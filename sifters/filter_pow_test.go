package sifters

import (
	"testing"

	evsifter "github.com/jiftechnify/strfry-evsifter"
	"github.com/nbd-wtf/go-nostr"
)

func TestPoWMinDifficulty(t *testing.T) {
	t.Run("accepts if PoW difficulty is greater than or equal to the threshold", func(t *testing.T) {
		s := PoWMinDifficulty(33, nil)

		evs := []*nostr.Event{
			{ID: "0000000048ba5812c644dac2f8d53d6ef9b7f143d809a141559e486328ec94af"}, // diff: 33
			{ID: "000000000004227ad7dfdb0bc956d534d4e8ab8a4c643fc72690bf3ed29af587"},
		}

		for _, ev := range evs {
			res, err := s.Sift(inputWithEvent(ev))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != evsifter.ActionAccept {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})

	t.Run("rejects if PoW difficulty is less than the threshold", func(t *testing.T) {
		s := PoWMinDifficulty(33, nil)

		evs := []*nostr.Event{
			{ID: "afd8949610b42451fb99675ace8fa222d436db48643b69241b00954c8a89f4c7"}, // diff: 0
			{ID: "0000000085884ec468245df4cc0e07657b2dccddd2245b318528bcb41b1d8f72"}, // diff: 32
		}

		for _, ev := range evs {
			res, err := s.Sift(inputWithEvent(ev))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Action != evsifter.ActionReject {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
	})
}
