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

	t.Run("OnlyIf modifier works as expected", func(t *testing.T) {
		// if kind == 1, first rejectAll should be evaluated, so rest of the sifters should be ignored according to the semantics of OneOf.
		// otherwise, evaluation of first acceptAll is expected to be skipped so second sifter should be evaluated.
		s := Pipeline(
			WithMod(rejectAll("rejected conditionally")).OnlyIf(KindList([]int{1}, Allow)),
			rejectAll("skipped conditional sifter"),
		)

		res, err := s.Sift(inputWithEvent(&nostr.Event{Kind: 1}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionReject || res.Msg != "rejected conditionally" {
			t.Fatalf("unexpected result: %+v", res)
		}

		res, err = s.Sift(inputWithEvent(&nostr.Event{Kind: 2}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionReject || res.Msg != "skipped conditional sifter" {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("OnlyIfNot modifier works as expected", func(t *testing.T) {
		// if kind != 1, first rejectAll should be evaluated, so rest of the sifters should be ignored according to the semantics of OneOf.
		// otherwise, evaluation of first acceptAll is expected to be skipped so second sifter should be evaluated.
		s := Pipeline(
			WithMod(rejectAll("rejected conditionally")).OnlyIfNot(KindList([]int{1}, Allow)),
			rejectAll("skipped conditional sifter"),
		)

		res, err := s.Sift(inputWithEvent(&nostr.Event{Kind: 2}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionReject || res.Msg != "rejected conditionally" {
			t.Fatalf("unexpected result: %+v", res)
		}

		res, err = s.Sift(inputWithEvent(&nostr.Event{Kind: 1}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionReject || res.Msg != "skipped conditional sifter" {
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

	t.Run("OnlyIf modifier works as expected", func(t *testing.T) {
		// if kind == 1, acceptAll should be evaluated, so rest of the sifters should be ignored according to the semantics of OneOf.
		// otherwise, evaluation of acceptAll is expected to be skipped so second sifter should be evaluated.
		s := OneOf(
			WithMod(acceptAll).OnlyIf(KindList([]int{1}, Allow)),
			rejectAll("skipped conditional sifter"),
		).RejectWithMsg("OnlyIf works!")

		res, err := s.Sift(inputWithEvent(&nostr.Event{Kind: 1}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionAccept {
			t.Fatalf("unexpected result: %+v", res)
		}

		res, err = s.Sift(inputWithEvent(&nostr.Event{Kind: 2}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionReject {
			t.Fatalf("unexpected result: %+v", res)
		}
		if res.Msg != "OnlyIf works!" {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("OnlyIfNot modifier works as expected", func(t *testing.T) {
		s := OneOf(
			// if kind != 1, acceptAll should be evaluated, so rest of the sifters should be ignored according to the semantics of OneOf.
			// otherwise, evaluation of acceptAll is expected to be skipped so second sifter should be evaluated.
			WithMod(acceptAll).OnlyIfNot(KindList([]int{1}, Allow)),
			rejectAll("skipped conditional sifter"),
		).RejectWithMsg("OnlyIfNot works!")

		res, err := s.Sift(inputWithEvent(&nostr.Event{Kind: 2}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionAccept {
			t.Fatalf("unexpected result: %+v", res)
		}

		res, err = s.Sift(inputWithEvent(&nostr.Event{Kind: 1}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != strfrui.ActionReject {
			t.Fatalf("unexpected result: %+v", res)
		}
		if res.Msg != "OnlyIfNot works!" {
			t.Fatalf("unexpected result: %+v", res)
		}
	})
}
