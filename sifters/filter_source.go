package sifters

import (
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strings"

	"github.com/jiftechnify/strfrui"
)

// SourceIPMatcher makes an event-sifter that matches the source IP address of a Nostr event with the matcher function.
// modeForUnknownSource specifies the behavior when the source IP address can't be determied.
//
// Note that this sifter always accepts events not from end-users (i.e. events imported from other relays).
//
// If the matcher returns non-nil error, this sifter always rejects the input.
func SourceIPMatcher(matcher func(netip.Addr) (bool, error), mode Mode, modeForUnknownSource Mode) *SifterUnit {
	matchInput := func(i *strfrui.Input) (inputMatchResult, error) {
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

		return matchResultFromBool(matcher(addr))
	}
	defaultRejFn := rejectWithMsgPerMode(
		mode,
		"blocked: source IP is not in the whitelist",
		"blocked: source IP is in the blacklist",
	)
	return newSifterUnit(matchInput, mode, defaultRejFn)
}

func matchWithIPPrefixList(prefixes []netip.Prefix) func(netip.Addr) (bool, error) {
	// sort prefixes by length of prefix, in ascending order
	// so that shorter prefixes (= broader range of addr) are matched first
	sort.Slice(prefixes, func(i, j int) bool {
		return prefixes[i].Bits() < prefixes[j].Bits()
	})
	return func(addr netip.Addr) (bool, error) {
		for _, prefix := range prefixes {
			if prefix.Contains(addr) {
				return true, nil
			}
		}
		return false, nil
	}
}

// SourceIPPrefixList makes an event-sifter that checks the source IP address of a Nostr event with list of IP address prefixes (CIDRs).
// modeForUnknownSource specifies the behavior when the source IP address can't be determied.
//
// You can use [ParseStringIPList] to parse a list of string IP address and CIDRs.
//
// Note that this sifter always accepts events not from end-users (i.e. events imported from other relays).
func SourceIPPrefixList(ipPrefixes []netip.Prefix, mode Mode, modeForUnknownSource Mode) *SifterUnit {
	return SourceIPMatcher(matchWithIPPrefixList(ipPrefixes), mode, modeForUnknownSource)
}

// ParseStringIPList parses a list of IP address and CIDRs in string form as a list of [netip.Prefix].
//
// IP addresses (without "/") are treated as IP prefixes that only contain the very address (e.g. 192.168.1.1 → 192.168.1.1/32, 2001:db8::1 → 2001:db8::1/128).
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
