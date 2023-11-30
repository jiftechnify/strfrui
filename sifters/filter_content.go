package sifters

import (
	"regexp"
	"strings"

	evsifter "github.com/jiftechnify/strfry-evsifter"
)

type matchContentSifter struct {
	matchContent func(string) bool
	mode         Mode
	reject       rejectionFn
}

func (s *matchContentSifter) Sift(input *evsifter.Input) (*evsifter.Result, error) {
	if shouldAccept(s.matchContent(input.Event.Content), s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

func ContentMatcher(matcher func(string) bool, mode Mode, rejFn rejectionFn) *matchContentSifter {
	s := &matchContentSifter{
		matchContent: matcher,
		mode:         mode,
		reject: orDefaultRejFn(rejFn, rejectWithMsgPerMode(
			mode,
			"blocked: content must obey some rules to be accepted",
			"blocked: content conflicts with some rules",
		)),
	}
	return s
}

func matchContentWithWordsAny(words []string) func(string) bool {
	return func(pubkey string) bool {
		for _, word := range words {
			if strings.Contains(pubkey, word) {
				return true
			}
		}
		return false
	}
}

func ContentHasAnyWord(words []string, mode Mode, rejFn rejectionFn) *matchContentSifter {
	s := &matchContentSifter{
		matchContent: matchContentWithWordsAny(words),
		mode:         mode,
		reject: orDefaultRejFn(rejFn, rejectWithMsgPerMode(
			mode,
			"blocked: content must have one of keywords to be accepted",
			"blocked: content has one of forbidden words",
		)),
	}
	return s
}

func matchContentWithWordsAll(words []string) func(string) bool {
	return func(pubkey string) bool {
		for _, word := range words {
			if !strings.Contains(pubkey, word) {
				return false
			}
		}
		return true
	}
}

func ContentHasAllWords(words []string, mode Mode, rejFn rejectionFn) *matchContentSifter {
	s := &matchContentSifter{
		matchContent: matchContentWithWordsAll(words),
		mode:         mode,
		reject: orDefaultRejFn(rejFn, rejectWithMsgPerMode(
			mode,
			"blocked: content must have all keywords to be accepted",
			"blocked: content has all of forbidden words",
		)),
	}
	return s
}

func matchContentWithRegexpsAny(regexps []*regexp.Regexp) func(string) bool {
	return func(content string) bool {
		for _, r := range regexps {
			if r.MatchString(content) {
				return true
			}
		}
		return false
	}
}

func ContentMatchesAnyRegexp(regexps []*regexp.Regexp, mode Mode, rejFn rejectionFn) *matchContentSifter {
	s := &matchContentSifter{
		matchContent: matchContentWithRegexpsAny(regexps),
		mode:         mode,
		reject: orDefaultRejFn(rejFn, rejectWithMsgPerMode(
			mode,
			"blocked: content must match one of key-patterns to be accepted",
			"blocked: content matches one of forbidden patterns",
		)),
	}
	return s
}

func matchContentWithRegexpsAll(regexps []*regexp.Regexp) func(string) bool {
	return func(content string) bool {
		for _, r := range regexps {
			if !r.MatchString(content) {
				return false
			}
		}
		return true
	}
}

func ContentMatchesAllRegexps(regexps []*regexp.Regexp, mode Mode, rejFn rejectionFn) *matchContentSifter {
	s := &matchContentSifter{
		matchContent: matchContentWithRegexpsAll(regexps),
		mode:         mode,
		reject: orDefaultRejFn(rejFn, rejectWithMsgPerMode(
			mode,
			"blocked: content must match all of key-patterns to be accepted",
			"blocked: content matches all of forbidden patterns",
		)),
	}
	return s
}
