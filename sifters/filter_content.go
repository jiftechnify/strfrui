package sifters

import (
	"regexp"
	"strings"

	"github.com/jiftechnify/strfrui"
)

func ContentMatcher(matcher func(string) (bool, error), mode Mode) *sifterUnit {
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

func ContentHasAnyWord(words []string, mode Mode) *sifterUnit {
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

func ContentHasAllWords(words []string, mode Mode) *sifterUnit {
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

func ContentMatchesAnyRegexp(regexps []*regexp.Regexp, mode Mode) *sifterUnit {
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

func ContentMatchesAllRegexps(regexps []*regexp.Regexp, mode Mode) *sifterUnit {
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
