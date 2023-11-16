package evsifter

import "log"

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
	sifters []Sifter
}

func (s *pipelineSifter) Sift(input *Input) (*Result, error) {
	var (
		res *Result
		err error
	)
	for _, s := range s.sifters {
		res, err = s.Sift(input)

		if err != nil {
			return nil, err
		}
		if res.Action != ActionAccept {
			// fail-fast
			return res, nil
		}
	}
	return res, nil
}

func Pipeline(sifters ...Sifter) *pipelineSifter {
	return &pipelineSifter{
		sifters,
	}
}

type authorSifter struct {
	matchAuthor func(string) bool
	mode        Mode
	reject      rejector
}

func (s *authorSifter) Sift(input *Input) (*Result, error) {
	if shouldAccept(s.matchAuthor(input.Event.PubKey), s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

func (s *authorSifter) setRejector(r rejector) {
	s.reject = r
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
		reject:      rejectWithMsg("blocked: author not allowed to send events"),
	}
	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

func AuthorMatcher(matcher func(string) bool, mode Mode, rejOpts ...rejectionOption) *authorSifter {
	s := &authorSifter{
		matchAuthor: matcher,
		mode:        mode,
		reject:      rejectWithMsg("blocked: author not allowed to send events"),
	}
	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

type kindSifter struct {
	kinds  map[int]struct{}
	mode   Mode
	reject rejector
}

func (s *kindSifter) Sift(input *Input) (*Result, error) {
	_, matched := s.kinds[input.Event.Kind]
	if shouldAccept(matched, s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

func (s *kindSifter) setRejector(r rejector) {
	s.reject = r
}

func KindList(kinds []int, mode Mode, rejOpts ...rejectionOption) *kindSifter {
	s := &kindSifter{
		kinds:  sliceToSet(kinds),
		mode:   mode,
		reject: rejectWithMsg("blocked: event kind not allowed"),
	}
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
