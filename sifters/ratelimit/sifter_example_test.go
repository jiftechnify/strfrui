package ratelimit_test

import (
	"github.com/jiftechnify/strfrui"
	"github.com/jiftechnify/strfrui/sifters"
	"github.com/jiftechnify/strfrui/sifters/ratelimit"
)

func ExampleByUser() {
	rateLimiter := ratelimit.ByUser(
		// 500 events/h per user, allowing burst up to 50 events
		ratelimit.QuotaPerHour(500).WithBurst(50),
		// "users" are identified by the pubkey
		ratelimit.PubKey,
	).
		// exclude all ephemeral events from rate limiting
		Exclude(func(input *strfrui.Input) bool {
			return sifters.KindsAllEphemeral(input.Event.Kind)
		})

	strfrui.New(rateLimiter).Run()
}

func ExampleByUser_pipeline() {
	// Of course, rate limiters can be composed with other sifters!
	rateLimiter := ratelimit.ByUser(
		ratelimit.QuotaPerHour(500).WithBurst(50),
		ratelimit.PubKey,
	)
	shortKind1 := sifters.WithMod(
		sifters.ContentMatcher(func(s string) (bool, error) {
			return len(s) <= 140, nil
		}, sifters.Allow)).OnlyIf(sifters.KindList([]int{1}, sifters.Allow))

	strfrui.New(sifters.Pipeline(
		rateLimiter,
		shortKind1,
	)).Run()
}

func ExampleByUserAndKind() {
	limiter := ratelimit.ByUserAndKind([]ratelimit.QuotaForKinds{
		// 100 kind:1 events/h per user, allowing burst up to 10 events
		ratelimit.QuotaPerHour(100).WithBurst(10).ForKinds(1),
		// 200 kind:7 events/h per user, allowing burst up to 50 events
		ratelimit.QuotaPerHour(200).WithBurst(50).ForKinds(7),
	}, ratelimit.PubKey)

	strfrui.New(limiter).Run()
}
