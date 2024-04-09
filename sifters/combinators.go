package sifters

import (
	"fmt"

	"github.com/jiftechnify/strfrui"
	"github.com/jiftechnify/strfrui/sifters/internal"
)

// PipelineSifter is an event-sifter combinator that combines multiple sifters into one.
// The resulting sifter accepts an input if all sub-sifters accept it.
// Otherwise, i.e. one of sub-sifter rejects, the resulting sifter rejects with the result from that sub-sifter.
//
// This type is exposed only for document organization purpose. You shouldn't initialize this struct directly.
// Instead, use [Pipeline] function to construct an instance of PipelineSifter.
type PipelineSifter struct {
	children []*ModdedSifter
}

func (s *PipelineSifter) Sift(input *strfrui.Input) (*strfrui.Result, error) {
	var (
		res *strfrui.Result
		err error
	)
	for _, child := range s.children {
		if child.onlyIfCond != nil {
			// if condition is specified and it isn't met, skip this child
			condMet, err := child.onlyIfCond.evalCond(input)
			if err != nil {
				return nil, err
			}
			if !condMet {
				// log.Printf("[pipeline %s] %q not applied because condition not met", s.name, child.label)
				continue
			}
		}

		res, err = child.Sift(input)

		if err != nil {
			// log.Printf("[pipeline %s] %q failed: %v", s.name, child.label, err)
			return nil, err
		}
		if child.acceptEarly && res.Action == strfrui.ActionAccept {
			// early return
			// log.Printf("[pipeline %s] %q accepted event (id: %v), so returning early", s.name, child.label, input.Event.ID)
			return res, nil
		}
		if res.Action != strfrui.ActionAccept {
			// fail-fast
			// log.Printf("[pipeline %s] %q rejected event (id: %v)", s.name, child.label, input.Event.ID)
			return res, nil
		}
	}
	// log.Printf("[pipeline %s] accepted event (id: %v)", s.name, input.Event.ID)
	return res, nil
}

// Pipeline combines the given sifters as a PipelineSifter.
//
// For more details about the behavior of a resulting combined sifter, see the doc of [PipelineSifter] type.
func Pipeline(ss ...strfrui.Sifter) *PipelineSifter {
	return &PipelineSifter{
		children: assignDefaultLabelsToSifters(ss...),
	}
}

// OneOfSifter is an event-sifter combinator that combines multiple sifters into one.
// The resulting sifter accepts an input if one of sub-sifters accept it.
// Otherwise, i.e. all sub-sifter rejects, the resulting sifter rejects.
//
// OneOfSifter rejects with message: "blocked: any of sub-sifters didn't accept the event" by default.
// If you want to customize rejection behavior,
// call [OneOfSifter.RejectWithMsg], [OneOfSifter.RejectWithMsgFromInput] or [OneOfSifter.ShadowReject] methods on it.
//
// This type is exposed only for document organization purpose. You shouldn't initialize this struct directly.
// Instead, use [OneOf] function to construct an instance of OneOfSifter.
type OneOfSifter struct {
	children []*ModdedSifter
	reject   internal.RejectionFn
}

func (s *OneOfSifter) Sift(input *strfrui.Input) (*strfrui.Result, error) {
	var (
		res *strfrui.Result
		err error
	)
	for _, child := range s.children {
		if child.onlyIfCond != nil {
			// if condition is specified and it isn't met, skip this child
			condMet, err := child.onlyIfCond.evalCond(input)
			if err != nil {
				return nil, err
			}
			if !condMet {
				// log.Printf("[oneOf %s] %q not applied because condition not met", s.name, child.label)
				continue
			}
		}

		res, err = child.Sift(input)

		if err != nil {
			return nil, err
		}
		if res.Action == strfrui.ActionAccept {
			// accept early if one of the children accepts the event
			return res, nil
		}
	}
	// reject if any children didn't accept the event
	return s.reject(input), nil
}

// ShadowReject sets the sifter's rejection behavior to "shadow-reject",
// which pretend to accept the input but actually reject it.
func (s *OneOfSifter) ShadowReject() *OneOfSifter {
	s.reject = internal.ShadowReject
	return s
}

// RejectWithMsg makes the sifter reject the input with the given message.
func (s *OneOfSifter) RejectWithMsg(msg string) *OneOfSifter {
	s.reject = internal.RejectWithMsg(msg)
	return s
}

// RejectWithMsgFromInput makes the sifter reject the input with the message derived from the input by the given function.
func (s *OneOfSifter) RejectWithMsgFromInput(getMsg func(*strfrui.Input) string) *OneOfSifter {
	s.reject = internal.RejectWithMsgFromInput(getMsg)
	return s
}

// OneOf combines the given sifters as a OneOfSifter.
//
// For more details about the behavior of a resulting combined sifter, see the doc of [OneOfSifter] type.
func OneOf(ss ...strfrui.Sifter) *OneOfSifter {
	return &OneOfSifter{
		children: assignDefaultLabelsToSifters(ss...),
		reject:   internal.RejectWithMsg("blocked: any of sub-sifters didn't accept the event"),
	}
}

// ModdedSifter is a sifter with modifiers, that change its behavior (especially in Pipeline / OneOf).
//
// This type is exposed only for document organization purpose. You shouldn't initialize this struct directly.
type ModdedSifter struct {
	s           strfrui.Sifter
	label       string      // label for the sifter (used in logs)
	acceptEarly bool        // if true and underlying sifter accepts, Pipeline returns early
	onlyIfCond  *onlyIfCond // if non-nil, the sifter is only applied if the condition is met
}

func (s *ModdedSifter) Sift(input *strfrui.Input) (*strfrui.Result, error) {
	// modifiers don't change the logic of the underlying sifter.
	return s.s.Sift(input)
}

// WithMod makes the sifter "modifiable" by sifter modifiers.
// You can chain modification methods to modify behavior of the sifter.
func WithMod(s strfrui.Sifter) *ModdedSifter {
	return &ModdedSifter{
		s: s,
	}
}

// Label labels the sifter.
func (s *ModdedSifter) Label(label string) *ModdedSifter {
	s.label = label
	return s
}

// AcceptEarly sets "accept early" flag to the sifter.
//
// If a sifter that is modified by this method is used in [PipelineSifter]s and it accept event,
// pipelines accept it immediately, and all sifters after the sifter are skipped.
func (s *ModdedSifter) AcceptEarly() *ModdedSifter {
	s.acceptEarly = true
	return s
}

type onlyIfCond struct {
	cond       strfrui.Sifter
	ifAccepted bool
}

func (s *onlyIfCond) evalCond(input *strfrui.Input) (bool, error) {
	res, err := s.cond.Sift(input)
	if err != nil {
		return false, err
	}
	if s.ifAccepted == (res.Action == strfrui.ActionAccept) {
		return true, nil
	}
	return false, nil
}

// OnlyIf makes the sifter is applied only if the given condition is met if it is used in [PipelineSifter]s or [OneOfSifter]s.
//
// When the evaluation of a combined sifter come across a sifter modified by this,
// it first applies cond to an input. Then:
//   - if cond accepts the input, the modified sifter is applied to the input normally.
//   - if cond rejects the input, the modified sifter is skipped and move to next.
func (s *ModdedSifter) OnlyIf(cond strfrui.Sifter) *ModdedSifter {
	s.onlyIfCond = &onlyIfCond{
		cond:       cond,
		ifAccepted: true,
	}
	return s
}

// OnlyIfNot makes the sifter is applied only if the given condition is not met if it is used in [PipelineSifter]s or [OneOfSifter]s.
//
// When the evaluation of a combined sifter come across a sifter modified by this,
// it first applies cond to an input. Then:
//   - if cond rejects the input, the modified sifter is applied to the input normally.
//   - if cond accepts the input, the modified sifter is skipped and move to next.
func (s *ModdedSifter) OnlyIfNot(cond strfrui.Sifter) *ModdedSifter {
	s.onlyIfCond = &onlyIfCond{
		cond:       cond,
		ifAccepted: false,
	}
	return s
}

func assignDefaultLabelsToSifters(ss ...strfrui.Sifter) []*ModdedSifter {
	modded := make([]*ModdedSifter, 0, len(ss))
	for i, s := range ss {
		mod, ok := s.(*ModdedSifter)
		if !ok {
			modded = append(modded, WithMod(s).Label(fmt.Sprintf("sifter #%d", i)))
			continue
		}
		if ok && mod.label == "" {
			modded = append(modded, mod.Label(fmt.Sprintf("sifter #%d", i)))
			continue
		}
		modded = append(modded, mod)
	}
	return modded
}
