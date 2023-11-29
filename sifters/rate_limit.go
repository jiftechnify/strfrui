package sifters

import (
	"context"
	"fmt"
	"time"

	evsifter "github.com/jiftechnify/strfry-evsifter"
	"github.com/throttled/throttled/v2"
	"github.com/throttled/throttled/v2/store/memstore"
)

type rateLimitKeyDeriveFn func(*evsifter.Input) (shouldLimit bool, key string)

type rateLimitSifter struct {
	rateLimiter throttled.RateLimiterCtx
	getLimitKey rateLimitKeyDeriveFn
	reject      rejectionFn
}

func (s *rateLimitSifter) Sift(input *evsifter.Input) (*evsifter.Result, error) {
	shouldLimit, limitKey := s.getLimitKey(input)
	if !shouldLimit {
		return input.Accept()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	limited, _, err := s.rateLimiter.RateLimitCtx(ctx, limitKey, 1)
	if err != nil {
		return nil, err
	}
	if limited {
		return s.reject(input), nil
	}
	return input.Accept()
}

type rateLimitUserKey int

const (
	RateLimitByIPAddr rateLimitUserKey = iota + 1
	RateLimitByPubKey
)

func RateLimitPerUser(quota throttled.RateQuota, userKey rateLimitUserKey, exclude func(*evsifter.Input) bool, rejFn rejectionFn) *rateLimitSifter {
	store, _ := memstore.NewCtx(65536)
	rateLimiter, _ := throttled.NewGCRARateLimiterCtx(store, quota)

	s := &rateLimitSifter{
		rateLimiter: rateLimiter,
		getLimitKey: func(input *evsifter.Input) (bool, string) {
			if !input.SourceType.IsEndUser() {
				return false, ""
			}
			if exclude != nil && exclude(input) {
				return false, ""
			}

			switch userKey {
			case RateLimitByIPAddr:
				return true, input.SourceInfo
			case RateLimitByPubKey:
				return true, input.Event.PubKey
			default:
				return false, ""
			}
		},
		reject: orDefaultRejFn(rejFn, RejectWithMsg("rate-limited: rate limit exceeded")),
	}
	return s
}

// rate-limiting event sifter with variable quotas per conditions
// if no quota matches, the event is accepted
type multiRateLimitSifter struct {
	selectRateLimiter func(*evsifter.Input) throttled.RateLimiterCtx
	getLimitKey       rateLimitKeyDeriveFn
	reject            rejectionFn
}

func (s *multiRateLimitSifter) Sift(input *evsifter.Input) (*evsifter.Result, error) {
	shouldLimit, limitKey := s.getLimitKey(input)
	if !shouldLimit {
		return input.Accept()
	}
	rateLimiter := s.selectRateLimiter(input)
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

type RateLimitQuotaPerKind struct {
	MatchKind func(int) bool
	Quota     throttled.RateQuota
}

type rateLimiterPerKind struct {
	matchKind   func(int) bool
	rateLimiter throttled.RateLimiterCtx
}

func RateLimitPerUserAndKind(quotas []RateLimitQuotaPerKind, userKey rateLimitUserKey, exclude func(*evsifter.Input) bool, rejFn rejectionFn) *multiRateLimitSifter {
	store, _ := memstore.NewCtx(65536)
	limiters := make([]rateLimiterPerKind, 0, len(quotas))
	for _, quota := range quotas {
		rateLimiter, _ := throttled.NewGCRARateLimiterCtx(store, quota.Quota)
		limiters = append(limiters, rateLimiterPerKind{
			matchKind:   quota.MatchKind,
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
	s := &multiRateLimitSifter{
		selectRateLimiter: selectRateLimiter,
		getLimitKey: func(input *evsifter.Input) (bool, string) {
			if !input.SourceType.IsEndUser() {
				return false, ""
			}
			if exclude != nil && exclude(input) {
				return false, ""
			}

			kind := input.Event.Kind
			switch userKey {
			case RateLimitByIPAddr:
				return true, fmt.Sprintf("%s/%d", input.SourceInfo, kind)
			case RateLimitByPubKey:
				return true, fmt.Sprintf("%s/%d", input.Event.PubKey, kind)
			default:
				return false, ""
			}
		},
		reject: orDefaultRejFn(rejFn, RejectWithMsg("rate-limited: rate limit exceeded")),
	}
	return s
}
