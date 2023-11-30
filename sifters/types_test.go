package sifters

import "testing"

func TestShouldAccept(t *testing.T) {
	tests := []struct {
		matched   bool
		mode      Mode
		expAccept bool
	}{
		{matched: true, mode: Allow, expAccept: true},
		{matched: false, mode: Allow, expAccept: false},
		{matched: true, mode: Deny, expAccept: false},
		{matched: false, mode: Deny, expAccept: true},
	}

	for _, tt := range tests {
		if got := shouldAccept(tt.matched, tt.mode); got != tt.expAccept {
			t.Fatalf("shouldAccept(%v, %v) = %v, want %v", tt.matched, tt.mode, got, tt.expAccept)
		}
	}
}
