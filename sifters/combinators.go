package sifters

import (
	"fmt"

	"github.com/jiftechnify/strfrui"
)

type pipelineSifter struct {
	children []*moddedSifter
}

func (s *pipelineSifter) Sift(input *strfrui.Input) (*strfrui.Result, error) {
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
			// log.Printf("[pipeline %s] %q accepted event (id: %v), so returning ealry", s.name, child.label, input.Event.ID)
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

func Pipeline(ss ...strfrui.Sifter) *pipelineSifter {
	return &pipelineSifter{
		children: assignDefaultLabelsToSifters(ss...),
	}
}

type oneOfSifter struct {
	children []*moddedSifter
	reject   RejectionFn
}

func (s *oneOfSifter) Sift(input *strfrui.Input) (*strfrui.Result, error) {
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
			// accept ealry if one of the children accepts the event
			return res, nil
		}
	}
	// reject if any children didn't accept the event
	return s.reject(input), nil
}

func (s *oneOfSifter) ShadowReject() *oneOfSifter {
	s.reject = ShadowReject
	return s
}

func (s *oneOfSifter) RejectWithMsg(msg string) *oneOfSifter {
	s.reject = RejectWithMsg(msg)
	return s
}

func (s *oneOfSifter) RejectWithMsgFromInput(getMsg func(*strfrui.Input) string) *oneOfSifter {
	s.reject = RejectWithMsgFromInput(getMsg)
	return s
}

func OneOf(ss ...strfrui.Sifter) *oneOfSifter {
	return &oneOfSifter{
		children: assignDefaultLabelsToSifters(ss...),
		reject:   RejectWithMsg("blocked: any of sub-sifters didn't accept the event"),
	}
}

// sifter with modifiers that change its behavior (especially in Pipeline)
type moddedSifter struct {
	s           strfrui.Sifter
	label       string      // label for the sifter (used in logs)
	acceptEarly bool        // if true and underlying sifter accepts, Pipeline returns early
	onlyIfCond  *onlyIfCond // if non-nil, the sifter is only applied if the condition is met
}

func (s *moddedSifter) Sift(input *strfrui.Input) (*strfrui.Result, error) {
	// modifiers don't change the logic of the underlying sifter.
	return s.s.Sift(input)
}

// WithMod makes the sifter "modifiable" by sifter modifiers.
// You can chain modification methods to modify behavior of the sifter.
func WithMod(s strfrui.Sifter) *moddedSifter {
	return &moddedSifter{
		s: s,
	}
}

// Label labels the sifter. This label is used in debug logs.
func (s *moddedSifter) Label(label string) *moddedSifter {
	s.label = label
	return s
}

// AccpetEarly sets "accept early" flag to the sifter.
//
// If sifters with "accept early" flag are used in Pipeline sifters and they accept event, pipelines return early (unconditionally accept the event without further judgements).
func (s *moddedSifter) AcceptEarly() *moddedSifter {
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

func (s *moddedSifter) OnlyIf(cond strfrui.Sifter) *moddedSifter {
	s.onlyIfCond = &onlyIfCond{
		cond:       cond,
		ifAccepted: true,
	}
	return s
}

func (s *moddedSifter) OnlyIfNot(cond strfrui.Sifter) *moddedSifter {
	s.onlyIfCond = &onlyIfCond{
		cond:       cond,
		ifAccepted: false,
	}
	return s
}

func assignDefaultLabelsToSifters(ss ...strfrui.Sifter) []*moddedSifter {
	modded := make([]*moddedSifter, 0, len(ss))
	for i, s := range ss {
		mod, ok := s.(*moddedSifter)
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
