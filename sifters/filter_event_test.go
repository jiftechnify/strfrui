package sifters

import (
	"strings"
	"testing"
	"time"

	"github.com/jiftechnify/strfrui"
	"github.com/nbd-wtf/go-nostr"
)

func inputWithEvent(event *nostr.Event) *strfrui.Input {
	return &strfrui.Input{
		Event: event,
	}
}

func TestMatchesFilters(t *testing.T) {
	filters := []nostr.Filter{
		{Kinds: []int{0}},
		{Tags: map[string][]string{
			"p": {"hoge", "fuga"},
		}},
	}

	t.Run("accepts if Nostr filter matches", func(t *testing.T) {
		s := MatchesFilters(filters, Allow)

		evs := []*nostr.Event{
			{Kind: 0, Tags: []nostr.Tag{}},
			{Kind: 1, Tags: []nostr.Tag{{"p", "hoge", ""}}},
			{Kind: 7, Tags: []nostr.Tag{{"p", "fuga", ""}}},
		}

		for _, ev := range evs {
			res, err := s.Sift(inputWithEvent(ev))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != strfrui.ActionAccept {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})

	t.Run("rejects if Nostr filter doesn't match", func(t *testing.T) {
		s := MatchesFilters(filters, Allow)

		evs := []*nostr.Event{
			{Kind: 1},
			{Kind: 3, Tags: []nostr.Tag{{"p", "foo", ""}, {"p", "bar", ""}, {"p", "baz", ""}}},
		}

		for _, ev := range evs {
			res, err := s.Sift(inputWithEvent(ev))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != strfrui.ActionReject {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})
}

func TestAuthorMatcher(t *testing.T) {
	matcher := func(author string) bool {
		return strings.HasPrefix(author, "white")
	}

	t.Run("accepts if author matches the matcher", func(t *testing.T) {
		s := AuthorMatcher(matcher, Allow)

		res, err := s.Sift(inputWithEvent(&nostr.Event{PubKey: "white snow"}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionAccept {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("rejects if author doesn't match the matcher", func(t *testing.T) {
		s := AuthorMatcher(matcher, Allow)

		res, err := s.Sift(inputWithEvent(&nostr.Event{PubKey: "nobody"}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionReject {
			t.Fatalf("unexpected result: %+v", res)
		}
	})
}

func TestAuthorList(t *testing.T) {
	whitelist := []string{"white snow", "ivory tower", "azure sky"}

	t.Run("accepts if author is in the whitelist", func(t *testing.T) {
		s := AuthorList(whitelist, Allow)

		evs := []*nostr.Event{
			{PubKey: "white snow"},
			{PubKey: "ivory tower"},
			{PubKey: "azure sky"},
		}

		for _, ev := range evs {
			res, err := s.Sift(inputWithEvent(ev))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != strfrui.ActionAccept {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})

	t.Run("rejects if author is not in the whitelist", func(t *testing.T) {
		s := AuthorList(whitelist, Allow)

		res, err := s.Sift(inputWithEvent(&nostr.Event{PubKey: "nobody"}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionReject {
			t.Fatalf("unexpected result: %+v", res)
		}
	})
}

func TestKindMatcher(t *testing.T) {
	t.Run("accepts if kind matches the matcher", func(t *testing.T) {
		s := KindMatcher(KindsAllRegular, Allow)

		evs := []*nostr.Event{
			{Kind: 1},
			{Kind: 4},
			{Kind: 7},
			{Kind: 40},
			{Kind: 9735},
		}

		for _, ev := range evs {
			res, err := s.Sift(inputWithEvent(ev))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != strfrui.ActionAccept {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})

	t.Run("rejects if kind doesn't match the matcher", func(t *testing.T) {
		s := KindMatcher(KindsAllRegular, Allow)

		evs := []*nostr.Event{
			{Kind: 0},
			{Kind: 3},
			{Kind: 41},
			{Kind: 10000},
			{Kind: 20000},
			{Kind: 30000},
		}

		for _, ev := range evs {
			res, err := s.Sift(inputWithEvent(ev))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != strfrui.ActionReject {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})
}

func TestKindList(t *testing.T) {
	whitelist := []int{0, 1, 3}

	t.Run("accepts if kind is in the whitelist", func(t *testing.T) {
		s := KindList(whitelist, Allow)

		evs := []*nostr.Event{
			{Kind: 0},
			{Kind: 1},
			{Kind: 3},
		}

		for _, ev := range evs {
			res, err := s.Sift(inputWithEvent(ev))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != strfrui.ActionAccept {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})

	t.Run("rejects if kind is not in the whitelist", func(t *testing.T) {
		s := KindList(whitelist, Allow)

		evs := []*nostr.Event{
			{Kind: 4},
			{Kind: 7},
			{Kind: 8},
		}

		for _, ev := range evs {
			res, err := s.Sift(inputWithEvent(ev))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != strfrui.ActionReject {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})
}

func TestCreatedAtRange(t *testing.T) {
	// fix "now" to unixtime 1000
	clock.setFake(time.Unix(1000, 0))
	t.Cleanup(func() {
		clock.reset()
	})

	t.Run("accepts if created_at is within the limit (closed interval)", func(t *testing.T) {
		s := CreatedAtRange(RelativeTimeRange{
			maxPastDelta:   10 * time.Minute,
			maxFutureDelta: 5 * time.Minute,
		}, Allow)

		evs := []*nostr.Event{
			{CreatedAt: 1000},
			{CreatedAt: 400},
			{CreatedAt: 1300},
		}

		for _, ev := range evs {
			res, err := s.Sift(inputWithEvent(ev))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != strfrui.ActionAccept {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})

	t.Run("accepts if created_at is within the limit (left-opened interval)", func(t *testing.T) {
		s := CreatedAtRange(RelativeTimeRange{
			maxFutureDelta: 5 * time.Minute,
		}, Allow)

		evs := []*nostr.Event{
			{CreatedAt: 1000},
			{CreatedAt: 400},
			{CreatedAt: 0},
			{CreatedAt: 1300},
		}

		for _, ev := range evs {
			res, err := s.Sift(inputWithEvent(ev))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != strfrui.ActionAccept {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})

	t.Run("accepts if created_at is within the limit (right-opened interval)", func(t *testing.T) {
		s := CreatedAtRange(RelativeTimeRange{
			maxPastDelta: 10 * time.Minute,
		}, Allow)

		evs := []*nostr.Event{
			{CreatedAt: 1000},
			{CreatedAt: 400},
			{CreatedAt: 1300},
			{CreatedAt: 1000000000},
		}

		for _, ev := range evs {
			res, err := s.Sift(inputWithEvent(ev))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != strfrui.ActionAccept {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})

	t.Run("rejects if created_at is not within the limit", func(t *testing.T) {
		s := CreatedAtRange(RelativeTimeRange{
			maxPastDelta:   10 * time.Minute,
			maxFutureDelta: 5 * time.Minute,
		}, Allow)

		evs := []*nostr.Event{
			{CreatedAt: 0},
			{CreatedAt: 10000},
		}

		for _, ev := range evs {
			res, err := s.Sift(inputWithEvent(ev))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != strfrui.ActionReject {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})
}
