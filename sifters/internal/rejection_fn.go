package internal

import "github.com/jiftechnify/strfrui"

type RejectionFn func(*strfrui.Input) *strfrui.Result

// ShadowReject is a RejectionFn that rejects the input without any message.
var ShadowReject RejectionFn = func(input *strfrui.Input) *strfrui.Result {
	return &strfrui.Result{
		ID:     input.Event.ID,
		Action: strfrui.ActionShadowReject,
	}
}

func RejectWithMsg(msg string) RejectionFn {
	return func(input *strfrui.Input) *strfrui.Result {
		return &strfrui.Result{
			ID:     input.Event.ID,
			Action: strfrui.ActionReject,
			Msg:    msg,
		}
	}
}

func RejectWithMsgFromInput(getMsg func(*strfrui.Input) string) RejectionFn {
	return func(input *strfrui.Input) *strfrui.Result {
		return &strfrui.Result{
			ID:     input.Event.ID,
			Action: strfrui.ActionReject,
			Msg:    getMsg(input),
		}
	}
}
