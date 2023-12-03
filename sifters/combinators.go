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

func OneOf(ss []strfrui.Sifter) *oneOfSifter {
	return &oneOfSifter{
		children: assignDefaultLabelsToSifters(ss...),
		reject:   RejectWithMsg("blocked: any of sub-sifters didn't accept the evnt"),
	}
}

type ifThenSifter struct {
	ifAccepted bool
	cond       strfrui.Sifter
	body       strfrui.Sifter
}

func (s *ifThenSifter) Sift(input *strfrui.Input) (*strfrui.Result, error) {
	condRes, err := s.cond.Sift(input)
	if err != nil {
		return nil, err
	}

	shouldApplyBody := s.ifAccepted == (condRes.Action == strfrui.ActionAccept)
	if !shouldApplyBody {
		return input.Accept()
	}
	return s.body.Sift(input)
}

func IfThen(cond, body strfrui.Sifter) *ifThenSifter {
	return &ifThenSifter{
		ifAccepted: true,
		cond:       cond,
		body:       body,
	}
}

func IfNotThen(cond, body strfrui.Sifter) *ifThenSifter {
	return &ifThenSifter{
		ifAccepted: false,
		cond:       cond,
		body:       body,
	}
}

// sifter with modifiers that change its behavior (especially in Pipeline)
type moddedSifter struct {
	s           strfrui.Sifter
	label       string // label for the sifter (used in logs)
	acceptEarly bool   // if true and underlying sifter accepts, Pipeline returns early
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
