package sifters

import (
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strings"

	evsifter "github.com/jiftechnify/strfry-evsifter"
)

func SourceIPMatcher(matcher func(netip.Addr) bool, mode Mode, modeForUnknownSource Mode) *sifterUnit {
	matchInput := func(i *evsifter.Input) (inputMatchResult, error) {
		if !i.SourceType.IsEndUser() {
			return inputAlwaysAccept, nil
		}
		addr, err := netip.ParseAddr(i.SourceInfo)
		if err != nil {
			log.Printf("sourceIPMatcher: failed to parse source IP addr (%s): %v", i.SourceInfo, err)
			if modeForUnknownSource == Allow {
				return inputAlwaysAccept, nil
			}
			return inputAlwaysReject, nil
		}

		return matchResultFromBool(matcher(addr)), nil
	}
	defaultRejFn := rejectWithMsgPerMode(
		mode,
		"blocked: source IP is not in the whitelist",
		"blocked: source IP is in the blacklist",
	)
	return newSifterUnit(matchInput, mode, defaultRejFn)
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

func SourceIPPrefixList(ipPrefixes []netip.Prefix, mode Mode, modeForUnknownSource Mode) *sifterUnit {
	return SourceIPMatcher(matchWithIPPrefixList(ipPrefixes), mode, modeForUnknownSource)
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
