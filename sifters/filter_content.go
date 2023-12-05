package sifters

import (
	"regexp"
	"strings"

	"github.com/jiftechnify/strfrui"
)

// ContentMatcher makes an event-sifter that matches a content of a Nostr event with the matcher function.
//
// If the matcher returns non-nil error, this sifter always rejects the input.
func ContentMatcher(matcher func(string) (bool, error), mode Mode) *SifterUnit {
	matchInput := func(i *strfrui.Input) (inputMatchResult, error) {
		return matchResultFromBool(matcher(i.Event.Content))
	}
	defaultRejFn := rejectWithMsgPerMode(
		mode,
		"blocked: content must obey some rules to be accepted",
		"blocked: content conflicts with some rules",
	)
	return newSifterUnit(matchInput, mode, defaultRejFn)
}

// ContentHasAnyWord makes an event-sifter that checks if a content of a Nostr event has any word in the given list.
//
// Note that it performs case-sensitive match.
func ContentHasAnyWord(words []string, mode Mode) *SifterUnit {
	matchInput := func(i *strfrui.Input) (inputMatchResult, error) {
		for _, word := range words {
			if strings.Contains(i.Event.Content, word) {
				return inputMatch, nil
			}
		}
		return inputMismatch, nil
	}
	defaultRejFn := rejectWithMsgPerMode(
		mode,
		"blocked: content must have one of keywords to be accepted",
		"blocked: content has one of forbidden words",
	)
	return newSifterUnit(matchInput, mode, defaultRejFn)
}

// ContentHasAllWords makes an event-sifter that checks if a content of a Nostr event has all words in the given list.
//
// Note that it performs case-sensitive match.
func ContentHasAllWords(words []string, mode Mode) *SifterUnit {
	matchInput := func(i *strfrui.Input) (inputMatchResult, error) {
		for _, word := range words {
			if !strings.Contains(i.Event.Content, word) {
				return inputMismatch, nil
			}
		}
		return inputMatch, nil
	}
	defaultRejFn := rejectWithMsgPerMode(mode,
		"blocked: content must have all keywords to be accepted",
		"blocked: content has all of forbidden words",
	)
	return newSifterUnit(matchInput, mode, defaultRejFn)
}

// ContentMatchesAnyRegexp makes an event-sifter that checks if a content of a Nostr event matches any of the given list of regular expressions.
func ContentMatchesAnyRegexp(regexps []*regexp.Regexp, mode Mode) *SifterUnit {
	matchInput := func(i *strfrui.Input) (inputMatchResult, error) {
		for _, r := range regexps {
			if r.MatchString(i.Event.Content) {
				return inputMatch, nil
			}
		}
		return inputMismatch, nil
	}
	defaultRejFn := rejectWithMsgPerMode(
		mode,
		"blocked: content must match one of key-patterns to be accepted",
		"blocked: content matches one of forbidden patterns",
	)
	return newSifterUnit(matchInput, mode, defaultRejFn)
}

// ContentMatchesAllRegexps makes an event-sifter that checks if a content of a Nostr event matches all of the given list of regular expressions.
func ContentMatchesAllRegexps(regexps []*regexp.Regexp, mode Mode) *SifterUnit {
	matchInput := func(i *strfrui.Input) (inputMatchResult, error) {
		for _, r := range regexps {
			if !r.MatchString(i.Event.Content) {
				return inputMismatch, nil
			}
		}
		return inputMatch, nil
	}
	defaultRejectFn := rejectWithMsgPerMode(
		mode,
		"blocked: content must match all of key-patterns to be accepted",
		"blocked: content matches all of forbidden patterns",
	)
	return newSifterUnit(matchInput, mode, defaultRejectFn)
}
