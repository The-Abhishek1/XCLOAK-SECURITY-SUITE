package services

import (
	"fmt"
	"testing"
)

// ── portScanScore ─────────────────────────────────────────────────────────────

func TestPortScanScoreBelowThreshold(t *testing.T) {
	if got := portScanScore(5, 10, 50, 100); got != 0 {
		t.Errorf("count below low threshold: want 0, got %d", got)
	}
	if got := portScanScore(0, 10, 50, 100); got != 0 {
		t.Errorf("zero count: want 0, got %d", got)
	}
}

func TestPortScanScoreAtSaturation(t *testing.T) {
	if got := portScanScore(100, 10, 50, 100); got != 100 {
		t.Errorf("count at saturation: want 100, got %d", got)
	}
	if got := portScanScore(9999, 10, 50, 100); got != 100 {
		t.Errorf("count far above saturation: want 100, got %d", got)
	}
}

func TestPortScanScoreAtLow(t *testing.T) {
	// At low boundary the score must be 50.
	got := portScanScore(10, 10, 50, 100)
	if got != 50 {
		t.Errorf("count == low: want 50, got %d", got)
	}
}

func TestPortScanScoreMonotone(t *testing.T) {
	// Score must be non-decreasing as count increases.
	prev := portScanScore(0, 10, 50, 100)
	for count := 1; count <= 150; count++ {
		cur := portScanScore(count, 10, 50, 100)
		if cur < prev {
			t.Errorf("score not monotone at count=%d: prev=%d cur=%d", count, prev, cur)
		}
		prev = cur
	}
}

func TestPortScanScoreBounded(t *testing.T) {
	for count := 0; count <= 200; count++ {
		s := portScanScore(count, 10, 50, 100)
		if s < 0 || s > 100 {
			t.Errorf("score %d out of [0,100] at count=%d", s, count)
		}
	}
}

// ── adminPortName ─────────────────────────────────────────────────────────────

func TestAdminPortNameKnown(t *testing.T) {
	known := map[int]string{
		445:  "SMB",
		3389: "RDP",
		135:  "WMI/DCOM",
		5985: "WinRM-HTTP",
		5986: "WinRM-HTTPS",
		22:   "", // not in the admin list — falls through to port-N
	}
	for port, name := range known {
		got := adminPortName(port)
		if name != "" && got != name {
			t.Errorf("adminPortName(%d) = %q, want %q", port, got, name)
		}
	}
}

func TestAdminPortNameUnknown(t *testing.T) {
	// Unknown ports should return a non-empty "port-N" style string.
	for _, port := range []int{12345, 0, 65535} {
		got := adminPortName(port)
		if got == "" {
			t.Errorf("adminPortName(%d) returned empty string", port)
		}
		want := fmt.Sprintf("port-%d", port)
		if got != want {
			t.Errorf("adminPortName(%d) = %q, want %q", port, got, want)
		}
	}
}
