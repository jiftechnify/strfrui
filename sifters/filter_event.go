package sifters

import (
	"time"

	evsifter "github.com/jiftechnify/strfry-evsifter"
	"github.com/nbd-wtf/go-nostr"
)

type filtersSifter struct {
	filters nostr.Filters
	mode    Mode
	rejectorSetterEmbed
}

func (s *filtersSifter) Sift(input *evsifter.Input) (*evsifter.Result, error) {
	matched := s.filters.Match(input.Event)
	if shouldAccept(matched, s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

func Filters(filters []nostr.Filter, mode Mode, rejOpts ...rejectionOption) *filtersSifter {
	s := &filtersSifter{
		filters: nostr.Filters(filters),
		mode:    mode,
	}
	s.reject = rejectWithMsg("blocked: event not allowed due to judgement by filters")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

type authorsSifter struct {
	matchAuthor func(string) bool
	mode        Mode
	rejectorSetterEmbed
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

func Authors(authors []string, mode Mode, rejOpts ...rejectionOption) *authorsSifter {
	s := &authorsSifter{
		matchAuthor: matchAuthorWithList(authors),
		mode:        mode,
	}
	s.reject = rejectWithMsg("blocked: author not allowed to send events")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

func AuthorMatcher(matcher func(string) bool, mode Mode, rejOpts ...rejectionOption) *authorsSifter {
	s := &authorsSifter{
		matchAuthor: matcher,
		mode:        mode,
	}
	s.reject = rejectWithMsg("blocked: author not allowed to send events")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

type kindsSifter struct {
	matchKind func(int) bool
	mode      Mode
	rejectorSetterEmbed
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

func Kinds(kinds []int, mode Mode, rejOpts ...rejectionOption) *kindsSifter {
	s := &kindsSifter{
		matchKind: matchKindWithList(kinds),
		mode:      mode,
	}
	s.reject = rejectWithMsg("blocked: event kind not allowed")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

func KindMatcher(matcher func(int) bool, mode Mode, rejOpts ...rejectionOption) *kindsSifter {
	s := &kindsSifter{
		matchKind: matcher,
		mode:      mode,
	}
	s.reject = rejectWithMsg("blocked: event kind not allowed")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

type createdAtLimitSifter struct {
	maxPastDelta   time.Duration
	maxFutureDelta time.Duration
	mode           Mode
	rejectorSetterEmbed
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

func CreatedAtLimit(maxPastDelta, maxFutureDelta time.Duration, mode Mode, rejOpts ...rejectionOption) *createdAtLimitSifter {
	s := &createdAtLimitSifter{
		maxPastDelta:   maxPastDelta,
		maxFutureDelta: maxFutureDelta,
		mode:           mode,
	}
	s.reject = rejectWithMsg("blocked: event created_at not allowed")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}
