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

type rejectionFn func(*evsifter.Input) *evsifter.Result

var ShadowReject = func(input *evsifter.Input) *evsifter.Result {
	return &evsifter.Result{
		ID:     input.Event.ID,
		Action: evsifter.ActionShadowReject,
	}
}

func RejectWithMsg(msg string) rejectionFn {
	return func(input *evsifter.Input) *evsifter.Result {
		return &evsifter.Result{
			ID:     input.Event.ID,
			Action: evsifter.ActionReject,
			Msg:    msg,
		}
	}
}

func RejectWithMsgFromInput(getMsg func(*evsifter.Input) string) rejectionFn {
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

func rejectWithMsgPerMode(mode Mode, msgAllow, msgDeny string) rejectionFn {
	msg := selectMsgByMode(mode, msgAllow, msgDeny)
	return RejectWithMsg(msg)
}

func orDefaultRejFn(rej rejectionFn, defaultRej rejectionFn) rejectionFn {
	if rej == nil {
		return defaultRej
	}
	return rej
}
