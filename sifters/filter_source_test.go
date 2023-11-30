package sifters

import (
	"log"
	"net/netip"
	"testing"

	evsifter "github.com/jiftechnify/strfry-evsifter"
	"github.com/nbd-wtf/go-nostr"
)

func inputWithSource(srcType evsifter.SourceType, srcInfo string) *evsifter.Input {
	return &evsifter.Input{
		SourceType: srcType,
		SourceInfo: srcInfo,
		Event:      &nostr.Event{},
	}
}

func TestSourceIPMatcher(t *testing.T) {
	isIPv4 := func(a netip.Addr) bool {
		return a.Is4()
	}

	t.Run("accepts if source IP matches the matcher", func(t *testing.T) {
		s := SourceIPMatcher(isIPv4, Allow, Allow, nil)

		addrs := []string{
			"127.0.0.1",
			"192.168.1.1",
		}

		for _, addr := range addrs {
			res, err := s.Sift(inputWithSource(evsifter.SourceTypeIP4, addr))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != evsifter.ActionAccept {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})

	t.Run("rejects if source IP doesn't match the matcher", func(t *testing.T) {
		s := SourceIPMatcher(isIPv4, Allow, Allow, nil)

		addrs := []string{
			"::1",
			"2001:db8::1",
		}

		for _, addr := range addrs {
			res, err := s.Sift(inputWithSource(evsifter.SourceTypeIP6, addr))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != evsifter.ActionReject {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})

	t.Run("always accept if source type is not IP4/IP6", func(t *testing.T) {
		s := SourceIPMatcher(isIPv4, Allow, Allow, nil)

		ins := []*evsifter.Input{
			inputWithSource(evsifter.SourceTypeImport, ""),
			inputWithSource(evsifter.SourceTypeStream, "wss://example.com"),
			inputWithSource(evsifter.SourceTypeSync, "wss://example.com"),
		}

		for _, in := range ins {
			res, err := s.Sift(in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != evsifter.ActionAccept {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})

	t.Run("respects specified mode for unknown source (Allow)", func(t *testing.T) {
		s := SourceIPMatcher(isIPv4, Allow, Allow, nil)

		res, err := s.Sift(inputWithSource(evsifter.SourceTypeIP4, "???"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != evsifter.ActionAccept {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("respects specified mode for unknown source (Deny)", func(t *testing.T) {
		s := SourceIPMatcher(isIPv4, Allow, Deny, nil)

		res, err := s.Sift(inputWithSource(evsifter.SourceTypeIP4, "???"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Action != evsifter.ActionReject {
			t.Fatalf("unexpected result: %+v", res)
		}
	})
}

func TestSourceIPPrefixList(t *testing.T) {
	prefixes, _ := ParseStringIPList([]string{
		"192.168.1.0/24",
		"127.0.0.1",
		"fd00::/8",
		"::1",
	})

	t.Run("accepts if source IP matches any of the prefixes", func(t *testing.T) {
		s := SourceIPPrefixList(prefixes, Allow, Allow, nil)
		log.Println(prefixes)

		addrs4 := []string{
			"127.0.0.1",
			"192.168.1.1",
			"192.168.1.100",
		}
		addrs6 := []string{
			"::1",
			"fd12:3456:789a:1::1",
		}

		for _, addr := range addrs4 {
			log.Println(addr)
			res, err := s.Sift(inputWithSource(evsifter.SourceTypeIP4, addr))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != evsifter.ActionAccept {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
		for _, addr := range addrs6 {
			res, err := s.Sift(inputWithSource(evsifter.SourceTypeIP6, addr))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != evsifter.ActionAccept {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})

	t.Run("rejects if source IP doesn't match any of the prefixes", func(t *testing.T) {
		s := SourceIPPrefixList(prefixes, Allow, Allow, nil)

		addrs4 := []string{
			"192.168.2.1",
			"10.1.2.3",
		}
		addrs6 := []string{
			"2001:db8:85a3::8a2e:370:7334",
			"1050::5:600:300c:326b",
		}

		for _, addr := range addrs4 {
			res, err := s.Sift(inputWithSource(evsifter.SourceTypeIP4, addr))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != evsifter.ActionReject {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
		for _, addr := range addrs6 {
			res, err := s.Sift(inputWithSource(evsifter.SourceTypeIP6, addr))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != evsifter.ActionReject {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})
}
