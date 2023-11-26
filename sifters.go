package evsifter

import (
	"fmt"
	"log"

	"github.com/nbd-wtf/go-nostr"
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

// sifter with modifiers that change its behavior (especially in Pipeline)
type moddedSifter struct {
	s           Sifter
	name        string // sifter's name in logs
	acceptEarly bool   // if true and underlying sifter accepts, pipelineSifter returns early
}

func (s *moddedSifter) Sift(input *Input) (*Result, error) {
	// modifiers don't change the logic of the underlying sifter.
	return s.s.Sift(input)
}

// WithMod makes the sifter "modifiable" by sifter modifiers.
// You can chain modification methods to modify behavior of the sifter.
func WithMod(s Sifter) *moddedSifter {
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

type rejector func(*Input) *Result

var shadowReject = func(input *Input) *Result {
	return &Result{
		ID:     input.Event.ID,
		Action: ActionShadowReject,
	}
}

func rejectWithMsg(msg string) rejector {
	return func(input *Input) *Result {
		return &Result{
			ID:     input.Event.ID,
			Action: ActionReject,
			Msg:    msg,
		}
	}
}

type rejectorSetter interface {
	setRejector(rejector)
}

type rejectorSetterEmbed struct {
	reject rejector
}

func (s *rejectorSetterEmbed) setRejector(r rejector) {
	s.reject = r
}

type rejectionOption func(rejectorSetter)

var WithShadowReject rejectionOption = func(s rejectorSetter) {
	s.setRejector(shadowReject)
}

func WithRejectMessage(msg string) rejectionOption {
	return func(s rejectorSetter) {
		s.setRejector(rejectWithMsg(msg))
	}
}

type pipelineSifter struct {
	sifters []*moddedSifter
}

func (s *pipelineSifter) Sift(input *Input) (*Result, error) {
	var (
		res *Result
		err error
	)
	for _, s := range s.sifters {
		res, err = s.Sift(input)

		if err != nil {
			log.Printf("pipelineSifter: %q failed: %v", s.name, err)
			return nil, err
		}
		if s.acceptEarly && res.Action == ActionAccept {
			// early return
			log.Printf("pipelineSifter: %q accepted event (id: %v), so returning ealry", s.name, input.Event.ID)
			return res, nil
		}
		if res.Action != ActionAccept {
			// fail-fast
			log.Printf("pipelineSifter: %q rejected event (id: %v)", s.name, input.Event.ID)
			return res, nil
		}
	}
	return res, nil
}

func Pipeline(sifters ...Sifter) *pipelineSifter {
	modded := make([]*moddedSifter, 0, len(sifters))
	for i, s := range sifters {
		mod, ok := s.(*moddedSifter)
		if !ok {
			sifters = append(sifters, WithMod(s).Name(fmt.Sprintf("sifter #%d", i)))
			continue
		}
		if ok && mod.name == "" {
			sifters = append(sifters, mod.Name(fmt.Sprintf("sifter #%d", i)))
			continue
		}
		sifters = append(sifters, mod)
	}
	return &pipelineSifter{
		sifters: modded,
	}
}

type authorSifter struct {
	matchAuthor func(string) bool
	mode        Mode
	rejectorSetterEmbed
}

func (s *authorSifter) Sift(input *Input) (*Result, error) {
	if shouldAccept(s.matchAuthor(input.Event.PubKey), s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

func matchAuthorWithList(pubkeys []string) func(string) bool {
	m := sliceToSet(pubkeys)
	return func(pubkey string) bool {
		_, ok := m[pubkey]
		return ok
	}
}

func AuthorList(authors []string, mode Mode, rejOpts ...rejectionOption) *authorSifter {
	s := &authorSifter{
		matchAuthor: matchAuthorWithList(authors),
		mode:        mode,
	}
	s.reject = rejectWithMsg("blocked: author not allowed to send events")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

func AuthorMatcher(matcher func(string) bool, mode Mode, rejOpts ...rejectionOption) *authorSifter {
	s := &authorSifter{
		matchAuthor: matcher,
		mode:        mode,
	}
	s.reject = rejectWithMsg("blocked: author not allowed to send events")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

type kindSifter struct {
	kinds map[int]struct{}
	mode  Mode
	rejectorSetterEmbed
}

func (s *kindSifter) Sift(input *Input) (*Result, error) {
	_, matched := s.kinds[input.Event.Kind]
	if shouldAccept(matched, s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

func KindList(kinds []int, mode Mode, rejOpts ...rejectionOption) *kindSifter {
	s := &kindSifter{
		kinds: sliceToSet(kinds),
		mode:  mode,
	}
	s.reject = rejectWithMsg("blocked: event kind not allowed")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

type filtersSifter struct {
	filters nostr.Filters
	mode    Mode
	rejectorSetterEmbed
}

func (s *filtersSifter) Sift(input *Input) (*Result, error) {
	matched := s.filters.Match(input.Event)
	if shouldAccept(matched, s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

func Filters(filters []nostr.Filter, mode Mode, rejOpts ...rejectionOption) *filtersSifter {
	s := &filtersSifter{
		filters: nostr.Filters(filters),
		mode:    mode,
	}
	s.reject = rejectWithMsg("blocked: event not allowed due to judgement by filters")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

func sliceToSet[T comparable](s []T) map[T]struct{} {
	m := make(map[T]struct{})
	for _, v := range s {
		m[v] = struct{}{}
	}
	return m
}
