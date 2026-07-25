package topology

import (
	"testing"
)

func TestDerivePosition_Deterministic(t *testing.T) {
	peerID := "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
	x1, y1, z1 := DerivePosition(peerID)
	x2, y2, z2 := DerivePosition(peerID)
	if x1 != x2 || y1 != y2 || z1 != z2 {
		t.Errorf("DerivePosition not deterministic for same ID: (%v,%v,%v) vs (%v,%v,%v)",
			x1, y1, z1, x2, y2, z2)
	}
}

func TestDerivePosition_DifferentIDsDifferentPositions(t *testing.T) {
	x1, y1, z1 := DerivePosition("aaaa")
	x2, y2, z2 := DerivePosition("bbbb")
	if x1 == x2 && y1 == y2 && z1 == z2 {
		t.Error("Expected different positions for different peer IDs")
	}
}

func TestDerivePosition_Range(t *testing.T) {
	// Positions should be in [-500, 500]
	peerID := "test-peer-id-12345"
	x, y, z := DerivePosition(peerID)
	if x < -500 || x > 500 {
		t.Errorf("X out of range: %f", x)
	}
	if y < -500 || y > 500 {
		t.Errorf("Y out of range: %f", y)
	}
	if z < -500 || z > 500 {
		t.Errorf("Z out of range: %f", z)
	}
}

func TestScaleToRange(t *testing.T) {
	tests := []struct {
		name string
		val  uint64
	}{
		{"zero", 0},
		{"max", ^uint64(0)},
		{"midpoint", 1 << 63},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scaleToRange(tt.val)
			if result < -500 || result > 500 {
				t.Errorf("scaleToRange(%d) = %f, want [-500, 500]", tt.val, result)
			}
		})
	}
}
