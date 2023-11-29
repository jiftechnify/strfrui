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

func Filters(filters []nostr.Filter, mode Mode, rejFn rejectionFn) *filtersSifter {
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

func matchAuthorWithList(pubkeys []string) func(string) bool {
	m := sliceToSet(pubkeys)
	return func(pubkey string) bool {
		_, ok := m[pubkey]
		return ok
	}
}

func Authors(authors []string, mode Mode, rejFn rejectionFn) *authorsSifter {
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

func matchKindWithList(kinds []int) func(int) bool {
	m := sliceToSet(kinds)
	return func(kind int) bool {
		_, ok := m[kind]
		return ok
	}
}

func Kinds(kinds []int, mode Mode, rejFn rejectionFn) *kindsSifter {
	s := &kindsSifter{
		matchKind: matchKindWithList(kinds),
		mode:      mode,
		reject:    orDefaultRejFn(rejFn, RejectWithMsg("blocked: the kind of the event is not allowed")),
	}
	return s
}

func KindMatcher(matcher func(int) bool, mode Mode, rejFn rejectionFn) *kindsSifter {
	s := &kindsSifter{
		matchKind: matcher,
		mode:      mode,
		reject:    orDefaultRejFn(rejFn, RejectWithMsg("blocked: the kind of the event is not allowed")),
	}
	return s
}

type createdAtLimitSifter struct {
	maxPastDelta   time.Duration
	maxFutureDelta time.Duration
	mode           Mode
	reject         rejectionFn
}

func (s *createdAtLimitSifter) Sift(input *evsifter.Input) (*evsifter.Result, error) {
	now := time.Now()
	createdAt := input.Event.CreatedAt.Time()

	matchPast := s.maxPastDelta == 0 || !createdAt.Before(now.Add(-s.maxPastDelta))
	matchFuture := s.maxFutureDelta == 0 || !createdAt.After(now.Add(s.maxFutureDelta))
	matched := matchPast && matchFuture

	if shouldAccept(matched, s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

func CreatedAtLimit(maxPastDelta, maxFutureDelta time.Duration, mode Mode, rejFn rejectionFn) *createdAtLimitSifter {
	s := &createdAtLimitSifter{
		maxPastDelta:   maxPastDelta,
		maxFutureDelta: maxFutureDelta,
		mode:           mode,
		reject: orDefaultRejFn(rejFn, rejectWithMsgPerMode(mode,
			fmt.Sprintf("invalid: event timestamp is out of the range: %s", stringCreatedAtRange(maxPastDelta, maxFutureDelta)),
			fmt.Sprintf("blocked: event timestamp must be out of the range: %s", stringCreatedAtRange(maxPastDelta, maxFutureDelta)),
		)),
	}
	return s
}

func stringCreatedAtRange(maxPastDelta, maxFutureDelta time.Duration) string {
	left := "-∞"
	if maxPastDelta != 0 {
		left = maxFutureDelta.String() + " ago"
	}
	right := "+∞"
	if maxFutureDelta != 0 {
		right = maxFutureDelta.String() + " after"
	}
	return fmt.Sprintf("[%s, %s]", left, right)
}
