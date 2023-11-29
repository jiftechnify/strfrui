package sifters

import (
	"regexp"
	"strings"

	evsifter "github.com/jiftechnify/strfry-evsifter"
)

type wordsSifter struct {
	matchWithWords func(string) bool
	mode           Mode
	reject         rejectionFn
}

func (s *wordsSifter) Sift(input *evsifter.Input) (*evsifter.Result, error) {
	if shouldAccept(s.matchWithWords(input.Event.Content), s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

func matchContentWithWordList(words []string) func(string) bool {
	return func(pubkey string) bool {
		for _, word := range words {
			if strings.Contains(pubkey, word) {
				return true
			}
		}
		return false
	}
}

func WordList(words []string, mode Mode, rejFn rejectionFn) *wordsSifter {
	s := &wordsSifter{
		matchWithWords: matchContentWithWordList(words),
		mode:           mode,
		reject: orDefaultRejFn(rejFn, rejectWithMsgPerMode(
			mode,
			"blocked: content must have keywords to be accepted",
			"blocked: content has forbidden words",
		)),
	}
	return s
}

func WordMatcher(matcher func(string) bool, mode Mode, rejFn rejectionFn) *wordsSifter {
	s := &wordsSifter{
		matchWithWords: matcher,
		mode:           mode,
		reject: orDefaultRejFn(rejFn, rejectWithMsgPerMode(
			mode,
			"blocked: content must have keywords to be accepted",
			"blocked: content has forbidden words",
		)),
	}
	return s
}

type regexpsSifter struct {
	regexps []*regexp.Regexp
	mode    Mode
	reject  rejectionFn
}

func (s *regexpsSifter) Sift(input *evsifter.Input) (*evsifter.Result, error) {
	matched := false
	for _, r := range s.regexps {
		if r.MatchString(input.Event.Content) {
			matched = true
			break
		}
	}
	if shouldAccept(matched, s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

func Regexps(regexps []*regexp.Regexp, mode Mode, rejFn rejectionFn) *regexpsSifter {
	s := &regexpsSifter{
		regexps: regexps,
		mode:    mode,
		reject: orDefaultRejFn(rejFn, rejectWithMsgPerMode(
			mode,
			"blocked: content matches forbidden patterns",
			"blocked: content must match key-patterns to be accepted",
		)),
	}
	return s
}
