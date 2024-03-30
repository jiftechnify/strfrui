package ratelimit

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"time"

	"github.com/jiftechnify/strfrui"
	"github.com/jiftechnify/strfrui/sifters/internal"
	"github.com/throttled/throttled/v2"
	"github.com/throttled/throttled/v2/store/memstore"
)

// UserKey specifies what key should we use to identify a user for per-user rate limiting.
type UserKey int

const (
	// Use the source IP address of an input as an user identifier.
	// In this mode, rate limit is not applied if the source of events can't be determined.
	IPAddr UserKey = iota + 1

	// Use the pubkey of an event as an user identifier.
	PubKey
)

type selectRateLimiterFn func(*strfrui.Input) throttled.RateLimiterCtx
type rateLimitKeyDeriveFn func(*strfrui.Input) (shouldLimit bool, key string)

// SifterUnit is base structure of rate-limiting event-sifter logic.
//
// If it comes to reject inputs, each built-in sifter responds to the client with its own predefined message.
// If you want to customize the rejection behavior,
// use [SifterUnit.RejectWithMsg], [SifterUnit.RejectWithMsgFromInput] or [SifterUnit.ShadowReject].
//
// This type is exposed only for document organization purpose. You shouldn't initialize this struct directly.
type SifterUnit struct {
	selectLimiter  selectRateLimiterFn
	deriveLimitKey rateLimitKeyDeriveFn
	exclude        func(*strfrui.Input) bool
	reject         internal.RejectionFn
}

func (s *SifterUnit) Sift(input *strfrui.Input) (*strfrui.Result, error) {
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

// Exclude makes the rate-limiting sifter exclude inputs that match given function from rate-limiting.
func (s *SifterUnit) Exclude(exclude func(*strfrui.Input) bool) *SifterUnit {
	s.exclude = exclude
	return s
}

// ShadowReject sets the sifter's rejection behavior to "shadow-reject",
// which pretend to accept the input but actually reject it.
func (s *SifterUnit) ShadowReject() *SifterUnit {
	s.reject = internal.ShadowReject
	return s
}

// RejectWithMsg makes the sifter reject the input with the given message.
func (s *SifterUnit) RejectWithMsg(msg string) *SifterUnit {
	s.reject = internal.RejectWithMsg(msg)
	return s
}

// RejectWithMsgFromInput makes the sifter reject the input with the message derived from the input by the given function.
func (s *SifterUnit) RejectWithMsgFromInput(getMsg func(*strfrui.Input) string) *SifterUnit {
	s.reject = internal.RejectWithMsgFromInput(getMsg)
	return s
}

func newSifterUnit(selectLimiter selectRateLimiterFn, deriveLimitKey rateLimitKeyDeriveFn) *SifterUnit {
	return &SifterUnit{
		selectLimiter:  selectLimiter,
		deriveLimitKey: deriveLimitKey,
		exclude:        func(i *strfrui.Input) bool { return false },
		reject:         internal.RejectWithMsg("rate-limited: rate limit exceeded"),
	}
}

// ByUser creates a event-sifter that imposes rate limit on event write request per user.
//
// "User" is identified by the source IP address or the pubkey of the event, depending on the given [UserKey].
//
// Note that this doesn't impose a rate limit to events not from end-users (i.e. events imported from other relays).
func ByUser(quota Quota, uk UserKey) *SifterUnit {
	store, _ := memstore.NewCtx(65536)
	rateLimiter, err := throttled.NewGCRARateLimiterCtx(store, throttled.RateQuota(quota))
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

// ByUserAndKind creates a event-sifter that imposes rate limit on event write request per user and event kind.
// The quota for each event kind is specified by the given list of [QuotaForKinds].
// For event kinds for which a quota is not defined, no rate limit is imposed.
//
// "User" is identified by the source IP address or the pubkey of the event, depending on the given [UserKey].
//
// Note that this doesn't impose a rate limit to events not from end-users (i.e. events imported from other relays).
func ByUserAndKind(quotas []QuotaForKinds, uk UserKey) *SifterUnit {
	store, _ := memstore.NewCtx(65536)
	limiters := make([]rateLimiterPerKind, 0, len(quotas))
	for _, kq := range quotas {
		rateLimiter, err := throttled.NewGCRARateLimiterCtx(store, throttled.RateQuota(kq.quota))
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
