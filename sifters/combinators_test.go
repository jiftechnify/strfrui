package sifters

import (
	"testing"

	evsifter "github.com/jiftechnify/strfry-evsifter"
	"github.com/nbd-wtf/go-nostr"
)

var (
	dummyInput = &evsifter.Input{Event: &nostr.Event{}}
)

var (
	acceptAll = evsifter.SifterFunc(func(input *evsifter.Input) (*evsifter.Result, error) {
		return input.Accept()
	})
	shadowRejectAll = evsifter.SifterFunc(func(input *evsifter.Input) (*evsifter.Result, error) {
		return input.ShadowReject()
	})
)

func rejectAll(msg string) evsifter.Sifter {
	return evsifter.SifterFunc(func(input *evsifter.Input) (*evsifter.Result, error) {
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
		if res.Action != evsifter.ActionAccept {
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
		if res.Action != evsifter.ActionReject {
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
		if res.Action != evsifter.ActionReject {
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
		if res.Action != evsifter.ActionShadowReject {
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
		if res.Action != evsifter.ActionAccept {
			t.Fatalf("unexpected result: %+v", res)
		}
	})
}

func TestOneOf(t *testing.T) {
	t.Run("accepts if any child accepts", func(t *testing.T) {
		s := OneOf([]evsifter.Sifter{
			rejectAll("reject 1"),
			acceptAll,
			rejectAll("reject 2"),
		}, nil)

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != evsifter.ActionAccept {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("rejects if all children reject", func(t *testing.T) {
		s := OneOf([]evsifter.Sifter{
			rejectAll("reject 1"),
			rejectAll("reject 2"),
			rejectAll("reject 3"),
		}, nil)

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != evsifter.ActionReject {
			t.Fatalf("unexpected result: %+v", res)
		}
		if res.Msg != "no one accepted" {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("rejects with result emitted by given rejection func", func(t *testing.T) {
		s := OneOf([]evsifter.Sifter{
			rejectAll("reject 1"),
			rejectAll("reject 2"),
			rejectAll("reject 3"),
		}, RejectWithMsg("no one accepted"))

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != evsifter.ActionReject {
			t.Fatalf("unexpected result: %+v", res)
		}
		if res.Msg != "no one accepted" {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("rejects with result emitted by given rejection func (shadow)", func(t *testing.T) {
		s := OneOf([]evsifter.Sifter{
			rejectAll("reject 1"),
			rejectAll("reject 2"),
			rejectAll("reject 3"),
		}, ShadowReject)

		res, err := s.Sift(dummyInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != evsifter.ActionReject {
			t.Fatalf("unexpected result: %+v", res)
		}
		if res.Msg != "no one accepted" {
			t.Fatalf("unexpected result: %+v", res)
		}
	})
}
