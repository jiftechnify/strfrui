package ratelimit

import (
	"context"
	"fmt"
	"time"

	evsifter "github.com/jiftechnify/strfry-evsifter"
	"github.com/jiftechnify/strfry-evsifter/sifters"
	"github.com/throttled/throttled/v2"
	"github.com/throttled/throttled/v2/store/memstore"
)

type UserKey int

const (
	IPAddr UserKey = iota + 1
	PubKey
)

type selectRateLimiterFn func(*evsifter.Input) throttled.RateLimiterCtx
type rateLimitKeyDeriveFn func(*evsifter.Input) (shouldLimit bool, key string)

type sifterUnit struct {
	selectLimiter  selectRateLimiterFn
	deriveLimitKey rateLimitKeyDeriveFn
	exclude        func(*evsifter.Input) bool
	reject         sifters.RejectionFn
}

func (s *sifterUnit) Sift(input *evsifter.Input) (*evsifter.Result, error) {
	if s.exclude(input) {
		return input.Accept()
	}
	shouldLimit, limitKey := s.deriveLimitKey(input)
	if !shouldLimit {
		return input.Accept()
	}
	rateLimiter := s.selectLimiter(input)
	if rateLimiter == nil {
		return input.Accept()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	limited, _, err := rateLimiter.RateLimitCtx(ctx, limitKey, 1)
	if err != nil {
		return nil, err
	}
	if limited {
		return s.reject(input), nil
	}
	return input.Accept()
}

func (s *sifterUnit) Exclude(exclude func(*evsifter.Input) bool) *sifterUnit {
	s.exclude = exclude
	return s
}

func (s *sifterUnit) ShadowReject() *sifterUnit {
	s.reject = sifters.ShadowReject
	return s
}

func (s *sifterUnit) RejectWithMsg(msg string) *sifterUnit {
	s.reject = sifters.RejectWithMsg(msg)
	return s
}

func (s *sifterUnit) RejectWithMsgFromInput(getMsg func(*evsifter.Input) string) *sifterUnit {
	s.reject = sifters.RejectWithMsgFromInput(getMsg)
	return s
}

func newSifterUnit(selectLimiter selectRateLimiterFn, deriveLimitKey rateLimitKeyDeriveFn) *sifterUnit {
	return &sifterUnit{
		selectLimiter:  selectLimiter,
		deriveLimitKey: deriveLimitKey,
		exclude:        func(i *evsifter.Input) bool { return false },
		reject:         sifters.RejectWithMsg("rate-limited: rate limit exceeded"),
	}
}

func ByUser(quota Quota, userKey UserKey) *sifterUnit {
	store, _ := memstore.NewCtx(65536)
	rateLimiter, _ := throttled.NewGCRARateLimiterCtx(store, quota)

	selectLimiter := func(_ *evsifter.Input) throttled.RateLimiterCtx { return rateLimiter }
	deriveLimitKey := func(input *evsifter.Input) (bool, string) {
		if !input.SourceType.IsEndUser() {
			return false, ""
		}
		switch userKey {
		case IPAddr:
			return true, input.SourceInfo
		case PubKey:
			return true, input.Event.PubKey
		default:
			return false, ""
		}
	}
	return newSifterUnit(selectLimiter, deriveLimitKey)
}

type rateLimiterPerKind struct {
	matchKind   func(int) bool
	rateLimiter throttled.RateLimiterCtx
}

// rate-limiting event sifter with variable quotas per conditions
// if no quota matches, the event is accepted
func ByUserAndKind(quotas []QuotaForKind, userKey UserKey) *sifterUnit {
	store, _ := memstore.NewCtx(65536)
	limiters := make([]rateLimiterPerKind, 0, len(quotas))
	for _, kq := range quotas {
		rateLimiter, _ := throttled.NewGCRARateLimiterCtx(store, kq.quota)
		limiters = append(limiters, rateLimiterPerKind{
			matchKind:   kq.matchKind,
			rateLimiter: rateLimiter,
		})
	}

	selectRateLimiter := func(input *evsifter.Input) throttled.RateLimiterCtx {
		for _, limiter := range limiters {
			if limiter.matchKind(input.Event.Kind) {
				return limiter.rateLimiter
			}
		}
		return nil
	}
	deriveLimitKey := func(input *evsifter.Input) (bool, string) {
		if !input.SourceType.IsEndUser() {
			return false, ""
		}
		kind := input.Event.Kind
		switch userKey {
		case IPAddr:
			return true, fmt.Sprintf("%s/%d", input.SourceInfo, kind)
		case PubKey:
			return true, fmt.Sprintf("%s/%d", input.Event.PubKey, kind)
		default:
			return false, ""
		}
	}
	return newSifterUnit(selectRateLimiter, deriveLimitKey)
}
