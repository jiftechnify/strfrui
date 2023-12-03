package sifters

import (
	"testing"

	"github.com/jiftechnify/strfrui"
	"github.com/nbd-wtf/go-nostr"
)

var (
	dummyInput = &strfrui.Input{Event: &nostr.Event{}}
)

var (
	acceptAll = strfrui.SifterFunc(func(input *strfrui.Input) (*strfrui.Result, error) {
		return input.Accept()
	})
	shadowRejectAll = strfrui.SifterFunc(func(input *strfrui.Input) (*strfrui.Result, error) {
		return input.ShadowReject()
	})
)

func rejectAll(msg string) strfrui.Sifter {
	return strfrui.SifterFunc(func(input *strfrui.Input) (*strfrui.Result, error) {
		return input.Reject(msg)
	})
}

func TestPipeline(t *testing.T) {
	t.Run("accepts if all children accept", func(t *testing.T) {
		s := Pipeline(acceptAll, acceptAll, acceptAll)

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionAccept {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("rejects if any child rejects, with", func(t *testing.T) {
		s := Pipeline(
			acceptAll,
			rejectAll("reject!"),
			acceptAll,
		)

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionReject {
			t.Fatalf("unexpected result: %+v", res)
		}
		if res.Msg != "reject!" {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("rejects with first rejection result", func(t *testing.T) {
		s := Pipeline(
			acceptAll,
			rejectAll("reject 1"),
			acceptAll,
			rejectAll("reject 2"),
		)

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionReject {
			t.Fatalf("unexpected result: %+v", res)
		}
		if res.Msg != "reject 1" {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("rejects with first rejection result (shadow)", func(t *testing.T) {
		s := Pipeline(
			acceptAll,
			shadowRejectAll,
			acceptAll,
			rejectAll("reject 1"),
		)

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionShadowReject {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("accepts and skips further evaluation if a child with AcceptEarly flag accepts", func(t *testing.T) {
		s := Pipeline(
			acceptAll,
			WithMod(acceptAll).AcceptEarly(),
			rejectAll("reject after accept early"),
		)

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionAccept {
			t.Fatalf("unexpected result: %+v", res)
		}
	})
}

func TestOneOf(t *testing.T) {
	t.Run("accepts if any child accepts", func(t *testing.T) {
		s := OneOf(
			rejectAll("reject 1"),
			acceptAll,
			rejectAll("reject 2"),
		)

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionAccept {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("rejects if all children reject", func(t *testing.T) {
		s := OneOf(
			rejectAll("reject 1"),
			rejectAll("reject 2"),
			rejectAll("reject 3"),
		)

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionReject {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("rejects with custom result specified by modifier (override message)", func(t *testing.T) {
		s := OneOf(
			rejectAll("reject 1"),
			rejectAll("reject 2"),
			rejectAll("reject 3"),
		).RejectWithMsg("no one accepted")

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionReject {
			t.Fatalf("unexpected result: %+v", res)
		}
		if res.Msg != "no one accepted" {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("rejects with result emitted by given rejection func (shadow)", func(t *testing.T) {
		s := OneOf(
			rejectAll("reject 1"),
			rejectAll("reject 2"),
			rejectAll("reject 3"),
		).ShadowReject()

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionShadowReject {
			t.Fatalf("unexpected result: %+v", res)
		}
	})
}

func TestIfThen(t *testing.T) {
	t.Run("accepts if both `cond` and `body` accepts", func(t *testing.T) {
		s := IfThen(
			acceptAll,
			acceptAll,
		)

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionAccept {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("rejects if `cond` accepts and `body` rejects", func(t *testing.T) {
		s := IfThen(
			acceptAll,
			rejectAll("body rejects"),
		)

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionReject {
			t.Fatalf("unexpected result: %+v", res)
		}
		if res.Msg != "body rejects" {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("accepts if `cond` rejects and `body` accepts", func(t *testing.T) {
		s := IfThen(
			rejectAll("cond rejects"),
			acceptAll,
		)

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionAccept {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("accepts if both `cond` and `body` rejects", func(t *testing.T) {
		s := IfThen(
			rejectAll("cond rejects"),
			rejectAll("body also rejects"),
		)

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionAccept {
			t.Fatalf("unexpected result: %+v", res)
		}
	})
}

func TestIfNotThen(t *testing.T) {
	t.Run("accepts if both `cond` and `body` accepts", func(t *testing.T) {
		s := IfNotThen(
			acceptAll,
			acceptAll,
		)

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionAccept {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("accepts if `cond` accepts and `body` rejects", func(t *testing.T) {
		s := IfNotThen(
			acceptAll,
			rejectAll("body rejects"),
		)

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionAccept {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("accepts if `cond` rejects and `body` accepts", func(t *testing.T) {
		s := IfNotThen(
			rejectAll("cond rejects"),
			acceptAll,
		)

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionAccept {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("rejects if both `cond` and `body` rejects", func(t *testing.T) {
		s := IfNotThen(
			rejectAll("cond rejects"),
			rejectAll("body also rejects"),
		)

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionReject {
			t.Fatalf("unexpected result: %+v", res)
		}
		if res.Msg != "body also rejects" {
			t.Fatalf("unexpected result: %+v", res)
		}
	})
}
