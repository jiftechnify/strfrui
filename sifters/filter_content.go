package sifters

import (
	"regexp"
	"strings"

	evsifter "github.com/jiftechnify/strfry-evsifter"
)

type wordsSifter struct {
	matchWithWords func(string) bool
	mode           Mode
	rejectorSetterEmbed
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

func WordList(words []string, mode Mode, rejOpts ...rejectionOption) *wordsSifter {
	s := &wordsSifter{
		matchWithWords: matchContentWithWordList(words),
		mode:           mode,
	}
	s.reject = rejectWithMsg("blocked: content have a word not allowed")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

func WordMatcher(matcher func(string) bool, mode Mode, rejOpts ...rejectionOption) *wordsSifter {
	s := &wordsSifter{
		matchWithWords: matcher,
		mode:           mode,
	}
	s.reject = rejectWithMsg("blocked: content have a word not allowed")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

type regexpsSifter struct {
	regexps []*regexp.Regexp
	mode    Mode
	rejectorSetterEmbed
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

func Regexps(regexps []*regexp.Regexp, mode Mode, rejOpts ...rejectionOption) *regexpsSifter {
	s := &regexpsSifter{
		regexps: regexps,
		mode:    mode,
	}
	s.reject = rejectWithMsg("blocked: content not allowed")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}
