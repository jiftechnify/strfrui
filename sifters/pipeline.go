package sifters

import (
	"fmt"
	"log"

	evsifter "github.com/jiftechnify/strfry-evsifter"
)

// sifter with modifiers that change its behavior (especially in Pipeline)
type moddedSifter struct {
	s           evsifter.Sifter
	name        string // sifter's name in logs
	acceptEarly bool   // if true and underlying sifter accepts, pipelineSifter returns early
}

func (s *moddedSifter) Sift(input *evsifter.Input) (*evsifter.Result, error) {
	// modifiers don't change the logic of the underlying sifter.
	return s.s.Sift(input)
}

// WithMod makes the sifter "modifiable" by sifter modifiers.
// You can chain modification methods to modify behavior of the sifter.
func WithMod(s evsifter.Sifter) *moddedSifter {
	return &moddedSifter{
		s:           s,
		name:        "",
		acceptEarly: false,
	}
}

// Name sets the name of the sifter in logs.
func (s *moddedSifter) Name(name string) *moddedSifter {
	s.name = name
	return s
}

// AccpetEarly sets "accept early" flag to the sifter.
//
// If sifters with "accept early" flag are used in Pipeline sifters and they accept event, pipelines return early (unconditionally accept the event without further judgements).
func (s *moddedSifter) AcceptEarly() *moddedSifter {
	s.acceptEarly = true
	return s
}

type pipelineSifter struct {
	sifters []*moddedSifter
}

func (s *pipelineSifter) Sift(input *evsifter.Input) (*evsifter.Result, error) {
	var (
		res *evsifter.Result
		err error
	)
	for _, s := range s.sifters {
		res, err = s.Sift(input)

		if err != nil {
			log.Printf("pipelineSifter: %q failed: %v", s.name, err)
			return nil, err
		}
		if s.acceptEarly && res.Action == evsifter.ActionAccept {
			// early return
			log.Printf("pipelineSifter: %q accepted event (id: %v), so returning ealry", s.name, input.Event.ID)
			return res, nil
		}
		if res.Action != evsifter.ActionAccept {
			// fail-fast
			log.Printf("pipelineSifter: %q rejected event (id: %v)", s.name, input.Event.ID)
			return res, nil
		}
	}
	return res, nil
}

func Pipeline(ss ...evsifter.Sifter) *pipelineSifter {
	modded := make([]*moddedSifter, 0, len(ss))
	for i, s := range ss {
		mod, ok := s.(*moddedSifter)
		if !ok {
			modded = append(modded, WithMod(s).Name(fmt.Sprintf("sifter #%d", i)))
			continue
		}
		if ok && mod.name == "" {
			modded = append(modded, mod.Name(fmt.Sprintf("sifter #%d", i)))
			continue
		}
		modded = append(modded, mod)
	}
	return &pipelineSifter{
		sifters: modded,
	}
}
