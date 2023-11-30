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

func WordList(words []string, mode Mode, rejFn rejectionFn) *matchContentSifter {
	s := &matchContentSifter{
		matchContent: matchContentWithWordList(words),
		mode:         mode,
		reject: orDefaultRejFn(rejFn, rejectWithMsgPerMode(
			mode,
			"blocked: content must have keywords to be accepted",
			"blocked: content has forbidden words",
		)),
	}
	return s
}

func matchContentWithRegexps(regexps []*regexp.Regexp) func(string) bool {
	return func(content string) bool {
		for _, r := range regexps {
			if r.MatchString(content) {
				return true
			}
		}
		return false
	}
}

func Regexps(regexps []*regexp.Regexp, mode Mode, rejFn rejectionFn) *matchContentSifter {
	s := &matchContentSifter{
		matchContent: matchContentWithRegexps(regexps),
		mode:         mode,
		reject: orDefaultRejFn(rejFn, rejectWithMsgPerMode(
			mode,
			"blocked: content matches forbidden patterns",
			"blocked: content must match key-patterns to be accepted",
		)),
	}
	return s
}
