package evsifter

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/throttled/throttled/v2"
	"github.com/throttled/throttled/v2/store/memstore"
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
	matchKind func(int) bool
	mode      Mode
	rejectorSetterEmbed
}

var (
	// Regular events: kind < 1000 (excluding 0, 3, 41)
	KindsAllRegular = func(k int) bool {
		return k == 1 || k == 2 || (3 < k && k < 41) || (41 < k && k < 10000)
	}
	// Replaceable events: kind 0, 3, 41 or 10000 <= kind < 20000
	KindsAllReplaceable = func(k int) bool {
		return k == 0 || k == 3 || k == 41 || (10000 <= k && k < 20000)
	}
	KindsAllEphemeral = func(k int) bool {
		return 20000 <= k && k < 30000
	}
	KindsAllParameterizedReplaceable = func(k int) bool {
		return 30000 <= k && k < 40000
	}
)

func (s *kindSifter) Sift(input *Input) (*Result, error) {
	matched := s.matchKind(input.Event.Kind)
	if shouldAccept(matched, s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

func matchKindWithList(kinds []int) func(int) bool {
	m := sliceToSet(kinds)
	return func(kind int) bool {
		_, ok := m[kind]
		return ok
	}
}

func KindList(kinds []int, mode Mode, rejOpts ...rejectionOption) *kindSifter {
	s := &kindSifter{
		matchKind: matchKindWithList(kinds),
		mode:      mode,
	}
	s.reject = rejectWithMsg("blocked: event kind not allowed")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

func KindMatcher(matcher func(int) bool, mode Mode, rejOpts ...rejectionOption) *kindSifter {
	s := &kindSifter{
		matchKind: matcher,
		mode:      mode,
	}
	s.reject = rejectWithMsg("blocked: event kind not allowed")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

type createdAtRangeSifter struct {
	maxPastDelta   time.Duration
	maxFutureDelta time.Duration
	mode           Mode
	rejectorSetterEmbed
}

func (s *createdAtRangeSifter) Sift(input *Input) (*Result, error) {
	now := time.Now()
	createdAt := input.Event.CreatedAt.Time()

	matchPast := s.maxPastDelta == 0 || !createdAt.Before(now.Add(-s.maxPastDelta))
	matchFuture := s.maxFutureDelta == 0 || !createdAt.After(now.Add(s.maxFutureDelta))
	matched := matchPast && matchFuture

	if shouldAccept(matched, s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

func CreatedAtRange(maxPastDelta, maxFutureDelta time.Duration, mode Mode, rejOpts ...rejectionOption) *createdAtRangeSifter {
	s := &createdAtRangeSifter{
		maxPastDelta:   maxPastDelta,
		maxFutureDelta: maxFutureDelta,
		mode:           mode,
	}
	s.reject = rejectWithMsg("blocked: event created_at not allowed")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

type sourceIPSifter struct {
	matchWithSourceIP    func(netip.Addr) bool
	mode                 Mode
	modeForUnknownSource Mode
	rejectorSetterEmbed
}

func (s *sourceIPSifter) Sift(input *Input) (*Result, error) {
	if input.SourceType.IsEndUser() {
		return input.Accept()
	}

	addr, err := netip.ParseAddr(input.SourceInfo)
	if err != nil {
		log.Printf("sourceIPSifter: failed to parse source IP addr (%s): %v", input.SourceInfo, err)
		if shouldAccept(true, s.modeForUnknownSource) {
			return input.Accept()
		}
		return input.Reject("blocked: this relay blocks events from unknown sources")
	}

	if shouldAccept(s.matchWithSourceIP(addr), s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

func matchWithIPPrefixList(prefixes []netip.Prefix) func(netip.Addr) bool {
	// sort prefixes by length of prefix, in ascending order
	// so that shorter prefixes (= broader range of addr) are matched first
	sort.Slice(prefixes, func(i, j int) bool {
		return prefixes[i].Bits() < prefixes[j].Bits()
	})
	return func(addr netip.Addr) bool {
		for _, prefix := range prefixes {
			if prefix.Contains(addr) {
				return true
			}
		}
		return false
	}
}

func ParseStringIPList(strIPs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(strIPs))
	for _, strIP := range strIPs {
		if strings.ContainsRune(strIP, '/') {
			// strIP contains '/' -> parse as prefix
			prefix, err := netip.ParsePrefix(strIP)
			if err != nil {
				return nil, fmt.Errorf("failed to parse IP prefix %q: %w", strIP, err)
			}
			prefixes = append(prefixes, prefix)
		} else {
			// parse as a single IP address, then convert to prefix
			addr, err := netip.ParseAddr(strIP)
			if err != nil {
				return nil, fmt.Errorf("failed to parse IP addr %q: %w", strIP, err)
			}
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return prefixes, nil
}

func SourceIPPrefixList(ipPrefixes []netip.Prefix, mode Mode, modeForUnknownSource Mode, rejOpts ...rejectionOption) *sourceIPSifter {
	s := &sourceIPSifter{
		matchWithSourceIP:    matchWithIPPrefixList(ipPrefixes),
		mode:                 mode,
		modeForUnknownSource: modeForUnknownSource,
	}
	s.reject = rejectWithMsg("blocked: source IP not allowed")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

func SourceIPMatcher(matcher func(netip.Addr) bool, mode Mode, modeForUnknownSource Mode, rejOpts ...rejectionOption) *sourceIPSifter {
	s := &sourceIPSifter{
		matchWithSourceIP:    matcher,
		mode:                 mode,
		modeForUnknownSource: modeForUnknownSource,
	}
	s.reject = rejectWithMsg("blocked: source IP not allowed")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

type wordsSifter struct {
	matchWithWords func(string) bool
	mode           Mode
	rejectorSetterEmbed
}

func (s *wordsSifter) Sift(input *Input) (*Result, error) {
	if shouldAccept(s.matchWithWords(input.Event.Content), s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

func matchContentWithWordList(words []string) func(string) bool {
	return func(pubkey string) bool {
		for _, word := range words {
			if strings.Contains(pubkey, word) {
				return true
			}
		}
		return false
	}
}

func WordList(words []string, mode Mode, rejOpts ...rejectionOption) *wordsSifter {
	s := &wordsSifter{
		matchWithWords: matchContentWithWordList(words),
		mode:           mode,
	}
	s.reject = rejectWithMsg("blocked: content have a word not allowed")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

func WordMatcher(matcher func(string) bool, mode Mode, rejOpts ...rejectionOption) *wordsSifter {
	s := &wordsSifter{
		matchWithWords: matcher,
		mode:           mode,
	}
	s.reject = rejectWithMsg("blocked: content have a word not allowed")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

type regexpsSifter struct {
	regexps []*regexp.Regexp
	mode    Mode
	rejectorSetterEmbed
}

func (s *regexpsSifter) Sift(input *Input) (*Result, error) {
	matched := false
	for _, r := range s.regexps {
		if r.MatchString(input.Event.Content) {
			matched = true
			break
		}
	}
	if shouldAccept(matched, s.mode) {
		return input.Accept()
	}
	return s.reject(input), nil
}

func Regexps(regexps []*regexp.Regexp, mode Mode, rejOpts ...rejectionOption) *regexpsSifter {
	s := &regexpsSifter{
		regexps: regexps,
		mode:    mode,
	}
	s.reject = rejectWithMsg("blocked: content not allowed")

	for _, opt := range rejOpts {
		opt(s)
	}
	return s
}

type rateLimitKeyDeriveFn func(*Input) (shouldLimit bool, key string)

type rateLimitSifter struct {
	rateLimiter throttled.RateLimiterCtx
	getLimitKey rateLimitKeyDeriveFn
	reject      rejector
}

func (s *rateLimitSifter) Sift(input *Input) (*Result, error) {
	shouldLimit, limitKey := s.getLimitKey(input)
	if !shouldLimit {
		return input.Accept()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	limited, _, err := s.rateLimiter.RateLimitCtx(ctx, limitKey, 1)
	if err != nil {
		return nil, err
	}
	if limited {
		return s.reject(input), nil
	}
	return input.Accept()
}

type rateLimitUserKey int

const (
	RateLimitByIPAddr rateLimitUserKey = iota + 1
	RateLimitByPubKey
)

func RateLimitPerUser(quota throttled.RateQuota, userKey rateLimitUserKey, exclude func(*Input) bool) *rateLimitSifter {
	store, _ := memstore.NewCtx(65536)
	rateLimiter, _ := throttled.NewGCRARateLimiterCtx(store, quota)

	s := &rateLimitSifter{
		rateLimiter: rateLimiter,
		getLimitKey: func(input *Input) (bool, string) {
			if !input.SourceType.IsEndUser() {
				return false, ""
			}
			if exclude != nil && exclude(input) {
				return false, ""
			}

			switch userKey {
			case RateLimitByIPAddr:
				return true, input.SourceInfo
			case RateLimitByPubKey:
				return true, input.Event.PubKey
			default:
				return false, ""
			}
		},
		reject: rejectWithMsg("blocked: rate limit exceeded"),
	}
	return s
}

// rate-limiting event sifter with variable quotas per conditions
// if no quota matches, the event is accepted
type multiRateLimitSifter struct {
	selectRateLimiter func(*Input) throttled.RateLimiterCtx
	getLimitKey       rateLimitKeyDeriveFn
	reject            rejector
}

func (s *multiRateLimitSifter) Sift(input *Input) (*Result, error) {
	shouldLimit, limitKey := s.getLimitKey(input)
	if !shouldLimit {
		return input.Accept()
	}
	rateLimiter := s.selectRateLimiter(input)
	if rateLimiter == nil {
		return input.Accept()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	limited, _, err := rateLimiter.RateLimitCtx(ctx, limitKey, 1)
	if err != nil {
		return nil, err
	}
	if limited {
		return s.reject(input), nil
	}
	return input.Accept()
}

type RateLimitQuotaPerKind struct {
	MatchKind func(int) bool
	Quota     throttled.RateQuota
}

type rateLimiterPerKind struct {
	matchKind   func(int) bool
	rateLimiter throttled.RateLimiterCtx
}

func RateLimitPerUserAndKind(quotas []RateLimitQuotaPerKind, userKey rateLimitUserKey, exclude func(*Input) bool) *multiRateLimitSifter {
	store, _ := memstore.NewCtx(65536)
	limiters := make([]rateLimiterPerKind, 0, len(quotas))
	for _, quota := range quotas {
		rateLimiter, _ := throttled.NewGCRARateLimiterCtx(store, quota.Quota)
		limiters = append(limiters, rateLimiterPerKind{
			matchKind:   quota.MatchKind,
			rateLimiter: rateLimiter,
		})
	}
	selectRateLimiter := func(input *Input) throttled.RateLimiterCtx {
		for _, limiter := range limiters {
			if limiter.matchKind(input.Event.Kind) {
				return limiter.rateLimiter
			}
		}
		return nil
	}
	s := &multiRateLimitSifter{
		selectRateLimiter: selectRateLimiter,
		getLimitKey: func(input *Input) (bool, string) {
			if !input.SourceType.IsEndUser() {
				return false, ""
			}
			if exclude != nil && exclude(input) {
				return false, ""
			}

			kind := input.Event.Kind
			switch userKey {
			case RateLimitByIPAddr:
				return true, fmt.Sprintf("%s/%d", input.SourceInfo, kind)
			case RateLimitByPubKey:
				return true, fmt.Sprintf("%s/%d", input.Event.PubKey, kind)
			default:
				return false, ""
			}
		},
		reject: rejectWithMsg("blocked: rate limit exceeded"),
	}
	return s
}
