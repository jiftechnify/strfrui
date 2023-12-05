package sifters

import (
	"fmt"

	"github.com/jiftechnify/strfrui"
	"github.com/jiftechnify/strfrui/sifters/internal"
)

var nibbleToLzs = map[rune]uint{
	'0': 4,
	'1': 3,
	'2': 2, '3': 2,
	'4': 1, '5': 1, '6': 1, '7': 1,
	'8': 0, '9': 0, 'a': 0, 'b': 0, 'c': 0, 'd': 0, 'e': 0, 'f': 0,
}

func leadingZerosOfEventID(id string) (uint, error) {
	var res uint = 0
	for _, r := range id {
		if r != '0' {
			lzs, ok := nibbleToLzs[r]
			if !ok {
				return 0, fmt.Errorf("leadingZerosOfEventID: unexpected character in event ID: %q", r)
			}
			return res + lzs, nil
		}
		res += 4
	}
	return res, nil
}

// PoWMinDifficulty makes an event-sifter that checks if the Proof of Work (PoW) difficulty of a Nostr event
// is higher than or equal to the given minimum difficulty.
//
// About PoW for Nostr events, see [NIP-13]. Note that this sifter doesn't check if the "target difficulty" declared by the nonce tag is achieved.
//
// [NIP-13]: https://github.com/nostr-protocol/nips/blob/master/13.md
func PoWMinDifficulty(minDifficulty uint) *SifterUnit {
	matchInput := func(input *strfrui.Input) (inputMatchResult, error) {
		difficulty, err := leadingZerosOfEventID(input.Event.ID)
		if err != nil {
			return inputAlwaysReject, err
		}
		return matchResultFromBool(difficulty >= minDifficulty, nil)
	}
	defaultRejFn := internal.RejectWithMsg(fmt.Sprintf("pow: difficulty is less than %d", minDifficulty))
	return newSifterUnit(matchInput, Allow, defaultRejFn)
}
