package sifters

import (
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strings"

	evsifter "github.com/jiftechnify/strfry-evsifter"
)

type sourceIPSifter struct {
	matchWithSourceIP    func(netip.Addr) bool
	mode                 Mode
	modeForUnknownSource Mode
	rejectorSetterEmbed
}

func (s *sourceIPSifter) Sift(input *evsifter.Input) (*evsifter.Result, error) {
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
