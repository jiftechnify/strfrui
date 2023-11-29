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

func shouldAccept(matched bool, m Mode) bool {
	switch m {
	case Allow:
		return matched
	case Deny:
		return !matched
	default:
		log.Printf("unreachable: unknown strategy")
		return false
	}
}

type rejector func(*evsifter.Input) *evsifter.Result

var shadowReject = func(input *evsifter.Input) *evsifter.Result {
	return &evsifter.Result{
		ID:     input.Event.ID,
		Action: evsifter.ActionShadowReject,
	}
}

func rejectWithMsg(msg string) rejector {
	return func(input *evsifter.Input) *evsifter.Result {
		return &evsifter.Result{
			ID:     input.Event.ID,
			Action: evsifter.ActionReject,
			Msg:    msg,
		}
	}
}

type rejectorSetter interface {
	setRejector(rejector)
}

type rejectorSetterEmbed struct {
	reject rejector
}

func (s *rejectorSetterEmbed) setRejector(r rejector) {
	s.reject = r
}

type rejectionOption func(rejectorSetter)

var WithShadowReject rejectionOption = func(s rejectorSetter) {
	s.setRejector(shadowReject)
}

func WithRejectMessage(msg string) rejectionOption {
	return func(s rejectorSetter) {
		s.setRejector(rejectWithMsg(msg))
	}
}
