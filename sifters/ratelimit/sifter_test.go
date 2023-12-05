package ratelimit

import (
	"sync"
	"testing"
	"time"

	"github.com/jiftechnify/strfrui"
	"github.com/jiftechnify/strfrui/sifters"
	"github.com/nbd-wtf/go-nostr"
)

func inputWithEvent(ev *nostr.Event) *strfrui.Input {
	return &strfrui.Input{
		SourceType: strfrui.SourceTypeIP4,
		SourceInfo: "192.168.1.1",
		Event:      ev,
	}
}

func inputFromPubkey(pubkey string) *strfrui.Input {
	return inputWithEvent(&nostr.Event{PubKey: pubkey})
}

func inputFromIPAddr(addr string) *strfrui.Input {
	return &strfrui.Input{
		SourceType: strfrui.SourceTypeIP4,
		SourceInfo: addr,
		Event: &nostr.Event{
			PubKey: "pubkey",
		},
	}
}

func expectResult(t *testing.T, want strfrui.Action) func(got *strfrui.Result, err error) {
	return func(got *strfrui.Result, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Action != want {
			t.Fatalf("want: %v, got: %v", want, got)
		}
	}
}

func TestByUser(t *testing.T) {
	t.Parallel()

	t.Run("userKey: Pubkey, basic case", func(t *testing.T) {
		t.Parallel()

		s := ByUser(Quota{MaxRate: PerSec(1)}, PubKey)

		// first event from 2 users
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkey("1")))
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkey("2")))

		// second event from each of 2 users in the same second: should be rejected
		expectResult(t, strfrui.ActionReject)(s.Sift(inputFromPubkey("1")))
		expectResult(t, strfrui.ActionReject)(s.Sift(inputFromPubkey("2")))

		// more event: should be rejected too
		expectResult(t, strfrui.ActionReject)(s.Sift(inputFromPubkey("1")))
		expectResult(t, strfrui.ActionReject)(s.Sift(inputFromPubkey("2")))

		// wait for 1 second and try again
		time.Sleep(1 * time.Second)
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkey("1")))
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkey("2")))
	})

	t.Run("userKey: Pubkey, allowing burst", func(t *testing.T) {
		t.Parallel()

		s := ByUser(Quota{MaxRate: PerSec(1), MaxBurst: 1}, PubKey)

		// first event from 2 users
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkey("1")))
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkey("2")))

		// second event from each of 2 users in the same second: burst should be allowed
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkey("1")))
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkey("2")))

		// more event exceeds burst limit: should be rejected
		expectResult(t, strfrui.ActionReject)(s.Sift(inputFromPubkey("1")))
		expectResult(t, strfrui.ActionReject)(s.Sift(inputFromPubkey("2")))

		// wait for a second
		time.Sleep(1 * time.Second)
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkey("1")))
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkey("2")))

		// due to the burst, quota is not fully healed yet, so these event should be rejected
		expectResult(t, strfrui.ActionReject)(s.Sift(inputFromPubkey("1")))
		expectResult(t, strfrui.ActionReject)(s.Sift(inputFromPubkey("2")))

		// wait for 2 seconds to fully heal the quota
		time.Sleep(2 * time.Second)
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkey("1")))
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkey("2")))

		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkey("1")))
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkey("2")))
	})

	t.Run("userKey: Pubkey, exclude some users from rate-limit target", func(t *testing.T) {
		t.Parallel()

		fromAdmin := func(i *strfrui.Input) bool {
			return i.Event.PubKey == "admin"
		}
		s := ByUser(Quota{MaxRate: PerSec(1)}, PubKey).Exclude(fromAdmin)

		// rate-limit events from normal users
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkey("normal")))
		expectResult(t, strfrui.ActionReject)(s.Sift(inputFromPubkey("normal")))

		time.Sleep(1 * time.Second)
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkey("normal")))

		// don't rate-limit events from admin
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkey("admin")))
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkey("admin")))
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkey("admin")))
	})

	t.Run("userKey: IPAddr, basic case", func(t *testing.T) {
		t.Parallel()

		s := ByUser(Quota{MaxRate: PerSec(1)}, IPAddr)

		// first event from 2 users
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddr("192.168.1.1")))
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddr("192.168.1.2")))

		// second event from each of 2 users in the same second: should be rejected
		expectResult(t, strfrui.ActionReject)(s.Sift(inputFromIPAddr("192.168.1.1")))
		expectResult(t, strfrui.ActionReject)(s.Sift(inputFromIPAddr("192.168.1.2")))

		// more event: should be rejected too
		expectResult(t, strfrui.ActionReject)(s.Sift(inputFromIPAddr("192.168.1.1")))
		expectResult(t, strfrui.ActionReject)(s.Sift(inputFromIPAddr("192.168.1.2")))

		// wait for 1 second and try again
		time.Sleep(1 * time.Second)
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddr("192.168.1.1")))
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddr("192.168.1.2")))
	})

	t.Run("userKey: IPAddr, accept events from unknown source", func(t *testing.T) {
		t.Parallel()

		s := ByUser(Quota{MaxRate: PerSec(1)}, IPAddr)

		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddr("???")))
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddr("???")))
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddr("???")))
	})

	t.Run("userKey: IPAddr, exclude some users from rate-limit target", func(t *testing.T) {
		t.Parallel()

		fromLocal := func(i *strfrui.Input) bool {
			return i.SourceInfo == "127.0.0.1"
		}
		s := ByUser(Quota{MaxRate: PerSec(1)}, IPAddr).Exclude(fromLocal)

		// rate-limit events from normal addresses
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddr("192.168.1.1")))
		expectResult(t, strfrui.ActionReject)(s.Sift(inputFromIPAddr("192.168.1.1")))

		time.Sleep(1 * time.Second)
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddr("192.168.1.1")))

		// don't rate-limit events from local
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddr("127.0.0.1")))
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddr("127.0.0.1")))
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddr("127.0.0.1")))
	})
}

func inputFromPubkeyWithKind(pubkey string, kind int) *strfrui.Input {
	return inputWithEvent(&nostr.Event{PubKey: pubkey, Kind: kind})
}

func inputFromIPAddrWithKind(addr string, kind int) *strfrui.Input {
	return &strfrui.Input{
		SourceType: strfrui.SourceTypeIP4,
		SourceInfo: addr,
		Event: &nostr.Event{
			PubKey: "pubkey",
			Kind:   kind,
		},
	}
}

func TestByUserAndKind(t *testing.T) {
	t.Parallel()

	t.Run("userKey: Pubkey, basic case (QuotaForKindsFn)", func(t *testing.T) {
		t.Parallel()

		quotas := []KindQuota{
			QuotaForKindsFn(sifters.KindsAllRegular, Quota{MaxRate: PerMin(60)}),     // 1 ev/sec
			QuotaForKindsFn(sifters.KindsAllReplaceable, Quota{MaxRate: PerMin(30)}), // 0.5 ev/sec
		}
		s := ByUserAndKind(quotas, PubKey)

		runScenario := func(t *testing.T, wg *sync.WaitGroup, pubkey string) {
			wg.Add(1)

			go func() {
				defer wg.Done()

				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 1)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 7)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 10000)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 30000)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 20000)))

				// 0.5 seconds later: all events except ephemeral one should be rejected
				time.Sleep(500 * time.Millisecond)
				expectResult(t, strfrui.ActionReject)(s.Sift(inputFromPubkeyWithKind(pubkey, 1)))
				expectResult(t, strfrui.ActionReject)(s.Sift(inputFromPubkeyWithKind(pubkey, 7)))
				expectResult(t, strfrui.ActionReject)(s.Sift(inputFromPubkeyWithKind(pubkey, 10000)))
				expectResult(t, strfrui.ActionReject)(s.Sift(inputFromPubkeyWithKind(pubkey, 30000)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 20000)))

				// 1 second later: regular events should be accepted whereas replaceable ones should be rejected
				time.Sleep(500 * time.Millisecond)
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 1)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 7)))
				expectResult(t, strfrui.ActionReject)(s.Sift(inputFromPubkeyWithKind(pubkey, 10000)))
				expectResult(t, strfrui.ActionReject)(s.Sift(inputFromPubkeyWithKind(pubkey, 30000)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 20000)))

				// 2 seconds later: all events should be accepted
				time.Sleep(1 * time.Second)
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 1)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 7)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 10000)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 30000)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 20000)))
			}()
		}

		var wg sync.WaitGroup
		runScenario(t, &wg, "1")
		runScenario(t, &wg, "2")
		wg.Wait()
	})

	t.Run("userKey: Pubkey, basic case (QuotaForKinds)", func(t *testing.T) {
		t.Parallel()

		quotas := []KindQuota{
			QuotaForKinds([]int{1}, Quota{MaxRate: PerMin(30)}), // 0.5 ev/sec
			QuotaForKinds([]int{7}, Quota{MaxRate: PerMin(60)}), // 1 ev/sec
		}
		s := ByUserAndKind(quotas, PubKey)

		runScenario := func(t *testing.T, wg *sync.WaitGroup, pubkey string) {
			wg.Add(1)

			go func() {
				defer wg.Done()

				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 1)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 7)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 0)))

				// 0.5 seconds later: only events with unspecified kinds should be accepted
				time.Sleep(500 * time.Millisecond)
				expectResult(t, strfrui.ActionReject)(s.Sift(inputFromPubkeyWithKind(pubkey, 1)))
				expectResult(t, strfrui.ActionReject)(s.Sift(inputFromPubkeyWithKind(pubkey, 7)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 0)))

				// 1 second later: kind 7 events should be accepted, whereas kind 1 events should be rejected
				time.Sleep(500 * time.Millisecond)
				expectResult(t, strfrui.ActionReject)(s.Sift(inputFromPubkeyWithKind(pubkey, 1)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 7)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 0)))

				// 2 seconds later: all events should be accepted
				time.Sleep(1 * time.Second)
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 1)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 7)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 0)))
			}()
		}

		var wg sync.WaitGroup
		runScenario(t, &wg, "1")
		runScenario(t, &wg, "2")
		wg.Wait()
	})

	t.Run("userKey: Pubkey, exclude", func(t *testing.T) {
		t.Parallel()

		quotas := []KindQuota{
			QuotaForKindsFn(sifters.KindsAllRegular, Quota{MaxRate: PerMin(60)}), // 1 ev/sec
		}
		fromAdmin := func(i *strfrui.Input) bool {
			return i.Event.PubKey == "admin"
		}
		s := ByUserAndKind(quotas, PubKey).Exclude(fromAdmin)

		runScenarioNormal := func(t *testing.T, wg *sync.WaitGroup) {
			wg.Add(1)
			go func() {
				defer wg.Done()

				pubkey := "normal"

				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 1)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 7)))

				expectResult(t, strfrui.ActionReject)(s.Sift(inputFromPubkeyWithKind(pubkey, 1)))
				expectResult(t, strfrui.ActionReject)(s.Sift(inputFromPubkeyWithKind(pubkey, 7)))

				time.Sleep(1 * time.Second)
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 1)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 7)))
			}()
		}
		runScenarioAdmin := func(t *testing.T, wg *sync.WaitGroup) {
			wg.Add(1)
			go func() {
				defer wg.Done()

				pubkey := "admin"

				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 1)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 7)))

				// admin events should not be rate-limited
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 1)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 7)))

				time.Sleep(1 * time.Second)
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 1)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromPubkeyWithKind(pubkey, 7)))
			}()
		}

		var wg sync.WaitGroup
		runScenarioNormal(t, &wg)
		runScenarioAdmin(t, &wg)
		wg.Wait()
	})

	t.Run("userKey: IPAddr, basic case", func(t *testing.T) {
		t.Parallel()

		quotas := []KindQuota{
			QuotaForKindsFn(sifters.KindsAllRegular, Quota{MaxRate: PerMin(60)}),     // 1 ev/sec
			QuotaForKindsFn(sifters.KindsAllReplaceable, Quota{MaxRate: PerMin(30)}), // 0.5 ev/sec
		}
		s := ByUserAndKind(quotas, IPAddr)

		runScenario := func(t *testing.T, wg *sync.WaitGroup, addr string) {
			wg.Add(1)

			go func() {
				defer wg.Done()

				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 1)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 7)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 10000)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 30000)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 20000)))

				// 0.5 seconds later: all events except ephemeral one should be rejected
				time.Sleep(500 * time.Millisecond)
				expectResult(t, strfrui.ActionReject)(s.Sift(inputFromIPAddrWithKind(addr, 1)))
				expectResult(t, strfrui.ActionReject)(s.Sift(inputFromIPAddrWithKind(addr, 7)))
				expectResult(t, strfrui.ActionReject)(s.Sift(inputFromIPAddrWithKind(addr, 10000)))
				expectResult(t, strfrui.ActionReject)(s.Sift(inputFromIPAddrWithKind(addr, 30000)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 20000)))

				// 1 second later: regular events should be accepted whereas replaceable ones should be rejected
				time.Sleep(500 * time.Millisecond)
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 1)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 7)))
				expectResult(t, strfrui.ActionReject)(s.Sift(inputFromIPAddrWithKind(addr, 10000)))
				expectResult(t, strfrui.ActionReject)(s.Sift(inputFromIPAddrWithKind(addr, 30000)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 20000)))

				// 2 seconds later: all events should be accepted
				time.Sleep(1 * time.Second)
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 1)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 7)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 10000)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 30000)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 20000)))
			}()
		}

		var wg sync.WaitGroup
		runScenario(t, &wg, "192.168.1.1")
		runScenario(t, &wg, "192.168.1.2")
		wg.Wait()
	})

	t.Run("userKey: IPAddr, exclude", func(t *testing.T) {
		t.Parallel()

		quotas := []KindQuota{
			QuotaForKindsFn(sifters.KindsAllRegular, Quota{MaxRate: PerMin(60)}), // 1 ev/sec
		}
		fromLocal := func(i *strfrui.Input) bool {
			return i.SourceInfo == "127.0.0.1"
		}
		s := ByUserAndKind(quotas, PubKey).Exclude(fromLocal)

		runScenarioNormal := func(t *testing.T, wg *sync.WaitGroup) {
			wg.Add(1)
			go func() {
				defer wg.Done()

				addr := "192.168.1.1"

				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 1)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 7)))

				expectResult(t, strfrui.ActionReject)(s.Sift(inputFromIPAddrWithKind(addr, 1)))
				expectResult(t, strfrui.ActionReject)(s.Sift(inputFromIPAddrWithKind(addr, 7)))

				time.Sleep(1 * time.Second)
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 1)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 7)))
			}()
		}
		runScenarioLocal := func(t *testing.T, wg *sync.WaitGroup) {
			wg.Add(1)
			go func() {
				defer wg.Done()

				addr := "127.0.0.1"

				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 1)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 7)))

				// events from local should not be rate-limited
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 1)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 7)))

				time.Sleep(1 * time.Second)
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 1)))
				expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind(addr, 7)))

			}()
		}

		var wg sync.WaitGroup
		runScenarioNormal(t, &wg)
		runScenarioLocal(t, &wg)
		wg.Wait()
	})

	t.Run("userKey: IPAddr, accept events from unknown source", func(t *testing.T) {
		t.Parallel()

		quotas := []KindQuota{
			QuotaForKindsFn(sifters.KindsAllRegular, Quota{MaxRate: PerMin(60)}),
		}
		s := ByUserAndKind(quotas, IPAddr)

		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind("???", 1)))
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind("???", 7)))

		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind("???", 1)))
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind("???", 7)))

		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind("???", 1)))
		expectResult(t, strfrui.ActionAccept)(s.Sift(inputFromIPAddrWithKind("???", 7)))
	})
}
