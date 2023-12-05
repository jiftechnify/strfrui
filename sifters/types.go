package sifters

import (
	"log"

	"github.com/jiftechnify/strfrui"
	"github.com/jiftechnify/strfrui/sifters/internal"
)

// Mode specifies the behavior of sifters when input matches the condition defined by the sifter:
//
//   - Allow: Accept the input if the input matches the condition (i.e. whitelist).
//   - Deny: Reject the input if the input matches the condition (i.e. blacklist).
type Mode int

const (
	Allow Mode = iota + 1
	Deny
)

type inputMatcher func(*strfrui.Input) (inputMatchResult, error)

// SifterUnit is base structure of composable event-sifter logic. All built-in sifters are instances of this struct.
//
// If it comes to reject inputs, each built-in sifter responds to the client with its own predefined message.
// If you want to customize the rejection behavior,
// use [SifterUnit.RejectWithMsg], [SifterUnit.RejectWithMsgFromInput] or [SifterUnit.ShadowReject].
//
// This type is exposed only for document organization purpose. You shouldn't initialize this struct directly.
type SifterUnit struct {
	match  inputMatcher
	mode   Mode
	reject internal.RejectionFn
}

func (s *SifterUnit) Sift(input *strfrui.Input) (*strfrui.Result, error) {
	matched, err := s.match(input)
	if err != nil {
		return nil, err
	}
	if shouldAccept(matched, s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

// ShadowReject sets the sifter's rejection behavior to "shadow-reject",
// which pretend to accept the input but actually reject it.
func (s *SifterUnit) ShadowReject() *SifterUnit {
	s.reject = internal.ShadowReject
	return s
}

// RejectWithMsg makes the sifter reject the input with the given message.
func (s *SifterUnit) RejectWithMsg(msg string) *SifterUnit {
	s.reject = internal.RejectWithMsg(msg)
	return s
}

// RejectWithMsgFromInput makes the sifter reject the input with the message derived from the input by the given function.
func (s *SifterUnit) RejectWithMsgFromInput(getMsg func(*strfrui.Input) string) *SifterUnit {
	s.reject = internal.RejectWithMsgFromInput(getMsg)
	return s
}

func newSifterUnit(matchInput inputMatcher, mode Mode, defaultRejFn internal.RejectionFn) *SifterUnit {
	return &SifterUnit{
		match:  matchInput,
		mode:   mode,
		reject: defaultRejFn,
	}
}

type inputMatchResult int

const (
	inputMatch inputMatchResult = iota + 1
	inputMismatch
	inputAlwaysAccept
	inputAlwaysReject
)

func matchResultFromBool(b bool, err error) (inputMatchResult, error) {
	if err != nil {
		return inputAlwaysReject, err
	}
	if b {
		return inputMatch, nil
	}
	return inputMismatch, nil
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

func rejectWithMsgPerMode(mode Mode, msgAllow, msgDeny string) internal.RejectionFn {
	msg := selectMsgByMode(mode, msgAllow, msgDeny)
	return internal.RejectWithMsg(msg)
}
