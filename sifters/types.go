package sifters

import (
	"log"

	evsifter "github.com/jiftechnify/strfry-evsifter"
)

type Mode int

const (
	Allow Mode = iota + 1
	Deny
)

type inputMatchResult int

const (
	inputMatch inputMatchResult = iota + 1
	inputMismatch
	inputAlwaysAccept
	inputAlwaysReject
)

func matchResultFromBool(b bool) inputMatchResult {
	if b {
		return inputMatch
	}
	return inputMismatch
}

func shouldAccept(matchRes inputMatchResult, mode Mode) bool {
	switch matchRes {
	case inputAlwaysAccept:
		return true

	case inputAlwaysReject:
		return false

	case inputMatch:
		switch mode {
		case Allow:
			return true
		case Deny:
			return false
		default:
			log.Printf("unreachable: unknown mode")
			return false
		}

	case inputMismatch:
		switch mode {
		case Allow:
			return false
		case Deny:
			return true
		default:
			log.Printf("unreachable: unknown mode")
			return false
		}

	default:
		log.Printf("unreachable: unknown match result")
		return false
	}
}

type RejectionFn func(*evsifter.Input) *evsifter.Result

var ShadowReject = func(input *evsifter.Input) *evsifter.Result {
	return &evsifter.Result{
		ID:     input.Event.ID,
		Action: evsifter.ActionShadowReject,
	}
}

func RejectWithMsg(msg string) RejectionFn {
	return func(input *evsifter.Input) *evsifter.Result {
		return &evsifter.Result{
			ID:     input.Event.ID,
			Action: evsifter.ActionReject,
			Msg:    msg,
		}
	}
}

func RejectWithMsgFromInput(getMsg func(*evsifter.Input) string) RejectionFn {
	return func(input *evsifter.Input) *evsifter.Result {
		return &evsifter.Result{
			ID:     input.Event.ID,
			Action: evsifter.ActionReject,
			Msg:    getMsg(input),
		}
	}
}

func selectMsgByMode(mode Mode, msgAllow, msgDeny string) string {
	var msg string
	switch mode {
	case Allow:
		msg = msgAllow
	case Deny:
		msg = msgDeny
	}
	return msg
}

func rejectWithMsgPerMode(mode Mode, msgAllow, msgDeny string) RejectionFn {
	msg := selectMsgByMode(mode, msgAllow, msgDeny)
	return RejectWithMsg(msg)
}

type inputMatcher func(*evsifter.Input) (inputMatchResult, error)

type sifterUnit struct {
	match  inputMatcher
	mode   Mode
	reject RejectionFn
}

func (s *sifterUnit) Sift(input *evsifter.Input) (*evsifter.Result, error) {
	matched, err := s.match(input)
	if err != nil {
		return nil, err
	}
	if shouldAccept(matched, s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

func (s *sifterUnit) ShadowReject() *sifterUnit {
	s.reject = ShadowReject
	return s
}

func (s *sifterUnit) RejectWithMsg(msg string) *sifterUnit {
	s.reject = RejectWithMsg(msg)
	return s
}

func (s *sifterUnit) RejectWithMsgFromInput(getMsg func(*evsifter.Input) string) *sifterUnit {
	s.reject = RejectWithMsgFromInput(getMsg)
	return s
}

func newSifterUnit(matchInput inputMatcher, mode Mode, defaultRejFn RejectionFn) *sifterUnit {
	return &sifterUnit{
		match:  matchInput,
		mode:   mode,
		reject: defaultRejFn,
	}
}
