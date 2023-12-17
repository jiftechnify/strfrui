package sifters

import (
	"fmt"
	"time"

	"github.com/jiftechnify/strfrui"
	"github.com/jiftechnify/strfrui/sifters/internal/utils"
	"github.com/nbd-wtf/go-nostr"
)

// MatchesFilters makes an event-sifter that matches a Nostr event against the given Nostr filters.
func MatchesFilters(filters []nostr.Filter, mode Mode) *SifterUnit {
	matchInput := func(input *strfrui.Input) (inputMatchResult, error) {
		return matchResultFromBool(nostr.Filters(filters).Match(input.Event), nil)
	}
	defaultRejFn := rejectWithMsgPerMode(
		mode,
		"blocked: event must match filters to be accepted",
		"blocked: event is denied by filters",
	)
	return newSifterUnit(matchInput, mode, defaultRejFn)
}

// AuthorMatcher makes an event-sifter that matches the author (pubkey) of a Nostr event with the given matcher function.
//
// If the matcher returns non-nil error, this sifter always rejects the input.
func AuthorMatcher(matcher func(string) (bool, error), mode Mode) *SifterUnit {
	matchInput := func(input *strfrui.Input) (inputMatchResult, error) {
		return matchResultFromBool(matcher(input.Event.PubKey))
	}
	defaultRejFn := rejectWithMsgPerMode(
		mode,
		"blocked: event author is not in the whitelist",
		"blocked: event author is in the blacklist",
	)
	return newSifterUnit(matchInput, mode, defaultRejFn)
}

// AuthorList makes an event-sifter that checks if the author (pubkey) of a Nostr event is in the given list.
func AuthorList(authors []string, mode Mode) *SifterUnit {
	authorSet := utils.SliceToSet(authors)
	matchInput := func(input *strfrui.Input) (inputMatchResult, error) {
		_, ok := authorSet[input.Event.PubKey]
		return matchResultFromBool(ok, nil)
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

// KindMatcherFallible makes an event-sifter that matches the kind of a Nostr event with the given matcher function that is fallible (i.e. can return error).
//
// If the matcher returns non-nil error, this sifter always rejects the input.
func KindMatcherFallible(matcher func(int) (bool, error), mode Mode) *SifterUnit {
	matchInput := func(input *strfrui.Input) (inputMatchResult, error) {
		return matchResultFromBool(matcher(input.Event.Kind))
	}
	defaultRejFn := rejectWithMsgPerMode(
		mode,
		"blocked: the kind of the event is not in the whitelist",
		"blocked: the kind of the event is in the blacklist",
	)
	return newSifterUnit(matchInput, mode, defaultRejFn)
}

// KindMatcher makes an event-sifter that matches the kind of a Nostr event with the given matcher function.
//
// Note that the matcher function can't return any error unlike other XxxMatcher sifters.
// To use a fallible matcher, you may want to [KindMatcherFallible] instead.
func KindMatcher(matcher func(int) bool, mode Mode) *SifterUnit {
	matcherf := func(k int) (bool, error) {
		return matcher(k), nil
	}
	return KindMatcherFallible(matcherf, mode)
}

// KindList makes an event-sifter that checks if the kind of a Nostr event is in the given list.
func KindList(kinds []int, mode Mode) *SifterUnit {
	kindSet := utils.SliceToSet(kinds)
	matchInput := func(input *strfrui.Input) (inputMatchResult, error) {
		_, ok := kindSet[input.Event.Kind]
		return matchResultFromBool(ok, nil)
	}
	defaultRejFn := rejectWithMsgPerMode(
		mode,
		"blocked: the kind of the event is not in the whitelist",
		"blocked: the kind of the event is in the blacklist",
	)
	return newSifterUnit(matchInput, mode, defaultRejFn)
}

// TagsMatcher makes an event-sifter that matches the tag list of a Nostr event with the given matcher function.
// You can utilize various matching methods on [github.com/nbd-wtf/go-nostr.Tags] in the matcher.
//
// If the matcher returns non-nil error, this sifter always rejects the input.
func TagsMatcher(matcher func(nostr.Tags) (bool, error), mode Mode) *SifterUnit {
	matchInput := func(input *strfrui.Input) (inputMatchResult, error) {
		return matchResultFromBool(matcher(input.Event.Tags))
	}
	defaultRejFn := rejectWithMsgPerMode(
		mode,
		"blocked: event tags don't match required patterns",
		"blocked: event tags match forbidden patterns",
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

// RelativeTimeRange represents a time range defined as a pair of maximum allowed duration in the past and future.
//
// Either of the durations can be zero (or left unspecified), means the corresponding side of the range is unbounded.
type RelativeTimeRange struct {
	MaxPastDelta   time.Duration
	MaxFutureDelta time.Duration
}

// Contains checks if the given time is in the time range.
func (r RelativeTimeRange) Contains(t time.Time) bool {
	now := clock.now()

	okPast := r.MaxPastDelta == 0 || !t.Before(now.Add(-r.MaxPastDelta))
	okFuture := r.MaxFutureDelta == 0 || !t.After(now.Add(r.MaxFutureDelta))

	return okPast && okFuture
}

// String returns a string representation of the time range.
func (r RelativeTimeRange) String() string {
	left := "-∞"
	if r.MaxPastDelta != 0 {
		left = r.MaxFutureDelta.String() + " ago"
	}
	right := "+∞"
	if r.MaxFutureDelta != 0 {
		right = r.MaxFutureDelta.String() + " after"
	}
	return fmt.Sprintf("[%s, %s]", left, right)
}

// CreatedAtRange makes an event-sifter that checks if the creation timestamp (created_at) of a Nostr event is in the given time range.
func CreatedAtRange(timeRange RelativeTimeRange, mode Mode) *SifterUnit {
	matchInput := func(input *strfrui.Input) (inputMatchResult, error) {
		createdAt := input.Event.CreatedAt.Time()
		return matchResultFromBool(timeRange.Contains(createdAt), nil)
	}
	defaultRejFn := rejectWithMsgPerMode(
		mode,
		fmt.Sprintf("invalid: event timestamp is out of the range: %v", timeRange),
		fmt.Sprintf("blocked: event timestamp must be out of the range: %v", timeRange),
	)
	return newSifterUnit(matchInput, mode, defaultRejFn)
}
