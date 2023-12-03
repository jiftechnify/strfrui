package sifters

import (
	"fmt"
	"time"

	"github.com/jiftechnify/strfrui"
	"github.com/jiftechnify/strfrui/sifters/internal/utils"
	"github.com/nbd-wtf/go-nostr"
)

func MatchesFilters(filters []nostr.Filter, mode Mode) *sifterUnit {
	matchInput := func(input *strfrui.Input) (inputMatchResult, error) {
		return matchResultFromBool(nostr.Filters(filters).Match(input.Event)), nil
	}
	defaultRejFn := rejectWithMsgPerMode(
		mode,
		"blocked: event must match filters to be accepted",
		"blocked: event is denied by filters",
	)
	return newSifterUnit(matchInput, mode, defaultRejFn)
}

func AuthorMatcher(matcher func(string) bool, mode Mode) *sifterUnit {
	matchInput := func(input *strfrui.Input) (inputMatchResult, error) {
		return matchResultFromBool(matcher(input.Event.PubKey)), nil
	}
	defaultRejFn := rejectWithMsgPerMode(
		mode,
		"blocked: event author is not in the whitelist",
		"blocked: event author is in the blacklist",
	)
	return newSifterUnit(matchInput, mode, defaultRejFn)
}

func AuthorList(authors []string, mode Mode) *sifterUnit {
	authorSet := utils.SliceToSet(authors)
	matchInput := func(input *strfrui.Input) (inputMatchResult, error) {
		_, ok := authorSet[input.Event.PubKey]
		return matchResultFromBool(ok), nil
	}
	defaultRejFn := rejectWithMsgPerMode(
		mode,
		"blocked: event author is not in the whitelist",
		"blocked: event author is in the blacklist",
	)
	return newSifterUnit(matchInput, mode, defaultRejFn)
}

var (
	// Non-Parametarized Replaceable events: kind 0, 3, 41 and 10000 <= kind < 20000
	KindsAllNonParamReplaceable = func(k int) bool {
		return k == 0 || k == 3 || k == 41 || (10000 <= k && k < 20000)
	}
	// Parameterized replaceable events: kind 30000 <= kind < 40000
	KindsAllParamReplaceable = func(k int) bool {
		return 30000 <= k && k < 40000
	}
	// General replaceable events (including both parametarized and non-parameterized)
	KindsAllReplaceable = func(k int) bool {
		return KindsAllNonParamReplaceable(k) || KindsAllParamReplaceable(k)
	}
	// Ephemeral events: kind 20000 <= kind < 30000
	KindsAllEphemeral = func(k int) bool {
		return 20000 <= k && k < 30000
	}
	// Regular events
	KindsAllRegular = func(k int) bool {
		return !(KindsAllReplaceable(k) || KindsAllEphemeral(k))
	}
)

func KindMatcher(matcher func(int) bool, mode Mode) *sifterUnit {
	matchInput := func(input *strfrui.Input) (inputMatchResult, error) {
		return matchResultFromBool(matcher(input.Event.Kind)), nil
	}
	defaultRejFn := rejectWithMsgPerMode(
		mode,
		"blocked: the kind of the event is not in the whitelist",
		"blocked: the kind of the event is in the blacklist",
	)
	return newSifterUnit(matchInput, mode, defaultRejFn)
}

func KindList(kinds []int, mode Mode) *sifterUnit {
	kindSet := utils.SliceToSet(kinds)
	matchInput := func(input *strfrui.Input) (inputMatchResult, error) {
		_, ok := kindSet[input.Event.Kind]
		return matchResultFromBool(ok), nil
	}
	defaultRejFn := rejectWithMsgPerMode(
		mode,
		"blocked: the kind of the event is not in the whitelist",
		"blocked: the kind of the event is in the blacklist",
	)
	return newSifterUnit(matchInput, mode, defaultRejFn)
}

type fakeableClock struct {
	fakeNow time.Time
}

var (
	clock fakeableClock
)

func (c fakeableClock) now() time.Time {
	if c.fakeNow.IsZero() {
		return time.Now()
	}
	return c.fakeNow
}

func (c *fakeableClock) setFake(t time.Time) {
	c.fakeNow = t
}

func (c *fakeableClock) reset() {
	c.fakeNow = time.Time{}
}

type RelativeTimeRange struct {
	maxPastDelta   time.Duration
	maxFutureDelta time.Duration
}

func (r RelativeTimeRange) Contains(t time.Time) bool {
	now := clock.now()

	okPast := r.maxPastDelta == 0 || !t.Before(now.Add(-r.maxPastDelta))
	okFuture := r.maxFutureDelta == 0 || !t.After(now.Add(r.maxFutureDelta))

	return okPast && okFuture
}

func (r RelativeTimeRange) String() string {
	left := "-∞"
	if r.maxPastDelta != 0 {
		left = r.maxFutureDelta.String() + " ago"
	}
	right := "+∞"
	if r.maxFutureDelta != 0 {
		right = r.maxFutureDelta.String() + " after"
	}
	return fmt.Sprintf("[%s, %s]", left, right)
}

func CreatedAtRange(timeRange RelativeTimeRange, mode Mode) *sifterUnit {
	matchInput := func(input *strfrui.Input) (inputMatchResult, error) {
		createdAt := input.Event.CreatedAt.Time()
		return matchResultFromBool(timeRange.Contains(createdAt)), nil
	}
	defaultRejFn := rejectWithMsgPerMode(
		mode,
		fmt.Sprintf("invalid: event timestamp is out of the range: %v", timeRange),
		fmt.Sprintf("blocked: event timestamp must be out of the range: %v", timeRange),
	)
	return newSifterUnit(matchInput, mode, defaultRejFn)
}
