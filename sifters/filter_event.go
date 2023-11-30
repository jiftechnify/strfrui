package sifters

import (
	"fmt"
	"time"

	evsifter "github.com/jiftechnify/strfry-evsifter"
	"github.com/nbd-wtf/go-nostr"
)

type filtersSifter struct {
	filters nostr.Filters
	mode    Mode
	reject  rejectionFn
}

func (s *filtersSifter) Sift(input *evsifter.Input) (*evsifter.Result, error) {
	matched := s.filters.Match(input.Event)
	if shouldAccept(matched, s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

func MatchesFilters(filters []nostr.Filter, mode Mode, rejFn rejectionFn) *filtersSifter {
	s := &filtersSifter{
		filters: nostr.Filters(filters),
		mode:    mode,
		reject: orDefaultRejFn(rejFn, rejectWithMsgPerMode(
			mode,
			"blocked: event must match filters to be accepted",
			"blocked: event doesn't match filters",
		)),
	}
	return s
}

type authorsSifter struct {
	matchAuthor func(string) bool
	mode        Mode
	reject      rejectionFn
}

func (s *authorsSifter) Sift(input *evsifter.Input) (*evsifter.Result, error) {
	if shouldAccept(s.matchAuthor(input.Event.PubKey), s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

func AuthorMatcher(matcher func(string) bool, mode Mode, rejFn rejectionFn) *authorsSifter {
	s := &authorsSifter{
		matchAuthor: matcher,
		mode:        mode,
		reject: orDefaultRejFn(rejFn, rejectWithMsgPerMode(
			mode,
			"blocked: the author of the event is not in the whitelist",
			"blocked: the author of the event is in the blacklist",
		)),
	}
	return s
}

func matchAuthorWithList(pubkeys []string) func(string) bool {
	m := sliceToSet(pubkeys)
	return func(pubkey string) bool {
		_, ok := m[pubkey]
		return ok
	}
}

func AuthorList(authors []string, mode Mode, rejFn rejectionFn) *authorsSifter {
	s := &authorsSifter{
		matchAuthor: matchAuthorWithList(authors),
		mode:        mode,
		reject: orDefaultRejFn(rejFn, rejectWithMsgPerMode(
			mode,
			"blocked: author is not int the whitelist",
			"blocked: author is in the blacklist",
		)),
	}
	return s
}

var (
	// Regular events: kind < 1000 (excluding 0, 3, 41)
	KindsAllRegular = func(k int) bool {
		return k == 1 || k == 2 || (3 < k && k < 41) || (41 < k && k < 10000)
	}
	// Replaceable events: kind 0, 3, 41 or 10000 <= kind < 20000
	KindsAllReplaceable = func(k int) bool {
		return k == 0 || k == 3 || k == 41 || (10000 <= k && k < 20000)
	}
	KindsAllEphemeral = func(k int) bool {
		return 20000 <= k && k < 30000
	}
	KindsAllParameterizedReplaceable = func(k int) bool {
		return 30000 <= k && k < 40000
	}
)

type kindsSifter struct {
	matchKind func(int) bool
	mode      Mode
	reject    rejectionFn
}

func (s *kindsSifter) Sift(input *evsifter.Input) (*evsifter.Result, error) {
	matched := s.matchKind(input.Event.Kind)
	if shouldAccept(matched, s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

func KindMatcher(matcher func(int) bool, mode Mode, rejFn rejectionFn) *kindsSifter {
	s := &kindsSifter{
		matchKind: matcher,
		mode:      mode,
		reject:    orDefaultRejFn(rejFn, RejectWithMsg("blocked: the kind of the event is not allowed")),
	}
	return s
}

func matchKindWithList(kinds []int) func(int) bool {
	m := sliceToSet(kinds)
	return func(kind int) bool {
		_, ok := m[kind]
		return ok
	}
}

func KindList(kinds []int, mode Mode, rejFn rejectionFn) *kindsSifter {
	s := &kindsSifter{
		matchKind: matchKindWithList(kinds),
		mode:      mode,
		reject:    orDefaultRejFn(rejFn, RejectWithMsg("blocked: the kind of the event is not allowed")),
	}
	return s
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

type createdAtRangeSifter struct {
	timeRange RelativeTimeRange
	mode      Mode
	reject    rejectionFn
}

func (s *createdAtRangeSifter) Sift(input *evsifter.Input) (*evsifter.Result, error) {
	createdAt := input.Event.CreatedAt.Time()

	if shouldAccept(s.timeRange.Contains(createdAt), s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

func CreatedAtRange(timeRange RelativeTimeRange, mode Mode, rejFn rejectionFn) *createdAtRangeSifter {
	s := &createdAtRangeSifter{
		timeRange: timeRange,
		mode:      mode,
		reject: orDefaultRejFn(rejFn, rejectWithMsgPerMode(mode,
			fmt.Sprintf("invalid: event timestamp is out of the range: %v", timeRange),
			fmt.Sprintf("blocked: event timestamp must be out of the range: %v", timeRange),
		)),
	}
	return s
}
