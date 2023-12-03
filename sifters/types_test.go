package sifters

import "testing"

func TestShouldAccept(t *testing.T) {
	tests := []struct {
		matchRes  inputMatchResult
		mode      Mode
		expAccept bool
	}{
		{matchRes: inputMatch, mode: Allow, expAccept: true},
		{matchRes: inputMismatch, mode: Allow, expAccept: false},
		{matchRes: inputAlwaysAccept, mode: Allow, expAccept: true},
		{matchRes: inputAlwaysReject, mode: Allow, expAccept: false},
		{matchRes: inputMatch, mode: Deny, expAccept: false},
		{matchRes: inputMismatch, mode: Deny, expAccept: true},
		{matchRes: inputAlwaysAccept, mode: Deny, expAccept: true},
		{matchRes: inputAlwaysReject, mode: Deny, expAccept: false},
	}

	for _, tt := range tests {
		if got := shouldAccept(tt.matchRes, tt.mode); got != tt.expAccept {
			t.Fatalf("shouldAccept(%v, %v) = %v, want %v", tt.matchRes, tt.mode, got, tt.expAccept)
		}
	}
}
