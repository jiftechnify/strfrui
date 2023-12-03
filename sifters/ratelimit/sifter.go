package ratelimit

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"time"

	"github.com/jiftechnify/strfrui"
	"github.com/jiftechnify/strfrui/sifters"
	"github.com/throttled/throttled/v2"
	"github.com/throttled/throttled/v2/store/memstore"
)

type userKey int

const (
	IPAddr userKey = iota + 1
	PubKey
)

type selectRateLimiterFn func(*strfrui.Input) throttled.RateLimiterCtx
type rateLimitKeyDeriveFn func(*strfrui.Input) (shouldLimit bool, key string)

type sifterUnit struct {
	selectLimiter  selectRateLimiterFn
	deriveLimitKey rateLimitKeyDeriveFn
	exclude        func(*strfrui.Input) bool
	reject         sifters.RejectionFn
}

func (s *sifterUnit) Sift(input *strfrui.Input) (*strfrui.Result, error) {
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

func (s *sifterUnit) Exclude(exclude func(*strfrui.Input) bool) *sifterUnit {
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

func (s *sifterUnit) RejectWithMsgFromInput(getMsg func(*strfrui.Input) string) *sifterUnit {
	s.reject = sifters.RejectWithMsgFromInput(getMsg)
	return s
}

func newSifterUnit(selectLimiter selectRateLimiterFn, deriveLimitKey rateLimitKeyDeriveFn) *sifterUnit {
	return &sifterUnit{
		selectLimiter:  selectLimiter,
		deriveLimitKey: deriveLimitKey,
		exclude:        func(i *strfrui.Input) bool { return false },
		reject:         sifters.RejectWithMsg("rate-limited: rate limit exceeded"),
	}
}

func ByUser(quota Quota, uk userKey) *sifterUnit {
	store, _ := memstore.NewCtx(65536)
	rateLimiter, err := throttled.NewGCRARateLimiterCtx(store, quota)
	if err != nil {
		log.Fatalf("ratelimit.ByUser: failed to initialize rate-limiter: %v", err)
	}

	selectLimiter := func(_ *strfrui.Input) throttled.RateLimiterCtx { return rateLimiter }
	deriveLimitKey := func(input *strfrui.Input) (bool, string) {
		if !input.SourceType.IsEndUser() {
			return false, ""
		}
		switch uk {
		case IPAddr:
			if isValidIPAddr(input.SourceInfo) {
				return true, input.SourceInfo
			}
			return false, ""
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
func ByUserAndKind(quotas []KindQuota, uk userKey) *sifterUnit {
	store, _ := memstore.NewCtx(65536)
	limiters := make([]rateLimiterPerKind, 0, len(quotas))
	for _, kq := range quotas {
		rateLimiter, err := throttled.NewGCRARateLimiterCtx(store, kq.quota)
		if err != nil {
			log.Fatalf("ratelimit.ByUser: failed to initialize rate-limiter: %v", err)
		}
		limiters = append(limiters, rateLimiterPerKind{
			matchKind:   kq.matchKind,
			rateLimiter: rateLimiter,
		})
	}

	selectRateLimiter := func(input *strfrui.Input) throttled.RateLimiterCtx {
		for _, limiter := range limiters {
			if limiter.matchKind(input.Event.Kind) {
				return limiter.rateLimiter
			}
		}
		return nil
	}
	deriveLimitKey := func(input *strfrui.Input) (bool, string) {
		if !input.SourceType.IsEndUser() {
			return false, ""
		}
		kind := input.Event.Kind
		switch uk {
		case IPAddr:
			if isValidIPAddr(input.SourceInfo) {
				return true, fmt.Sprintf("%s/%d", input.SourceInfo, kind)
			}
			return false, ""
		case PubKey:
			return true, fmt.Sprintf("%s/%d", input.Event.PubKey, kind)
		default:
			return false, ""
		}
	}
	return newSifterUnit(selectRateLimiter, deriveLimitKey)
}

func isValidIPAddr(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}
