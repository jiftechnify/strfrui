package sifters

import (
	"regexp"
	"strings"
	"testing"

	"github.com/jiftechnify/strfrui"
	"github.com/nbd-wtf/go-nostr"
)

func inputWithContent(content string) *strfrui.Input {
	return &strfrui.Input{
		Event: &nostr.Event{
			Content: content,
		},
	}
}

func TestContentMatcher(t *testing.T) {
	aToZ := func(content string) bool {
		return strings.HasPrefix(content, "a") && strings.HasSuffix(content, "z")
	}
	t.Run("accepts if content matches the matcher", func(t *testing.T) {
		s := ContentMatcher(aToZ, Allow)

		res, err := s.Sift(inputWithContent("angrez"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionAccept {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("rejects if content doesn't match the matcher", func(t *testing.T) {
		s := ContentMatcher(aToZ, Allow)

		res, err := s.Sift(inputWithContent("abracadabra"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionReject {
			t.Fatalf("unexpected result: %+v", res)
		}
	})
}

func TestContentHasAnyWord(t *testing.T) {
	words := []string{"nostr", "zap"}

	t.Run("accepts if content contains any of the words", func(t *testing.T) {
		s := ContentHasAnyWord(words, Allow)

		cs := []string{
			"pronounciation of nostr is 'nostr'",
			"zap me later",
		}

		for _, c := range cs {
			res, err := s.Sift(inputWithContent(c))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != strfrui.ActionAccept {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})

	t.Run("rejects if content doesn't contain any of the words", func(t *testing.T) {
		s := ContentHasAnyWord(words, Allow)

		res, err := s.Sift(inputWithContent("random post"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionReject {
			t.Fatalf("unexpected result: %+v", res)
		}
	})
}

func TestContentHasAllWords(t *testing.T) {
	words := []string{"nostr", "zap"}

	t.Run("accepts if content contains all of the words", func(t *testing.T) {
		s := ContentHasAllWords(words, Allow)

		res, err := s.Sift(inputWithContent("lighting zap is one of the most awesome feature of the nostr"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionAccept {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("rejects if content doesn't contain all of the words", func(t *testing.T) {
		s := ContentHasAllWords(words, Allow)

		cs := []string{
			"random post",
			"pronounciation of nostr is 'nostr'",
			"zap me later",
		}

		for _, c := range cs {
			res, err := s.Sift(inputWithContent(c))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != strfrui.ActionReject {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})
}

func TestContentMatchesAnyRegexp(t *testing.T) {
	regexps := []*regexp.Regexp{
		regexp.MustCompile("[ぁ-ゖ]"),
		regexp.MustCompile("[ァ-ヶ]"),
	}

	t.Run("accepts if content matches any of the regexps", func(t *testing.T) {
		s := ContentMatchesAnyRegexp(regexps, Allow)

		cs := []string{
			"こんにちは!",
			"ノストラジア",
		}

		for _, c := range cs {
			res, err := s.Sift(inputWithContent(c))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != strfrui.ActionAccept {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})

	t.Run("rejects if content doesn't match any of the regexps", func(t *testing.T) {
		s := ContentMatchesAnyRegexp(regexps, Allow)

		cs := []string{
			"Hello!",
			"Nostrasia",
		}

		for _, c := range cs {
			res, err := s.Sift(inputWithContent(c))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != strfrui.ActionReject {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})
}

func TestContentMatchesAllRegexps(t *testing.T) {
	regexps := []*regexp.Regexp{
		regexp.MustCompile("[ぁ-ゖ]"),
		regexp.MustCompile("[ァ-ヶ]"),
	}

	t.Run("accepts if content matches all of the regexps", func(t *testing.T) {
		s := ContentMatchesAllRegexps(regexps, Allow)

		res, err := s.Sift(inputWithContent("こんにちはノストラジア!"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionAccept {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("rejects if content doesn't match all of the regexps", func(t *testing.T) {
		s := ContentMatchesAllRegexps(regexps, Allow)

		cs := []string{
			"Hello!",
			"こんにちは!",
			"ノストラジア",
		}

		for _, c := range cs {
			res, err := s.Sift(inputWithContent(c))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != strfrui.ActionReject {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})
}
