package services

import (
	"math"
	"testing"
)

// ── computeIntervals ──────────────────────────────────────────────────────────

func TestComputeIntervalsEmpty(t *testing.T) {
	if got := computeIntervals(nil); len(got) != 0 {
		t.Fatalf("nil input: want empty, got %v", got)
	}
	if got := computeIntervals([]int64{100}); len(got) != 0 {
		t.Fatalf("single ts: want empty, got %v", got)
	}
}

func TestComputeIntervalsSorted(t *testing.T) {
	got := computeIntervals([]int64{0, 10, 30, 60})
	want := []float64{10, 20, 30}
	if len(got) != len(want) {
		t.Fatalf("len %d, want %d", len(got), len(want))
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("[%d] got %v, want %v", i, got[i], v)
		}
	}
}

func TestComputeIntervalsUnsorted(t *testing.T) {
	// Unsorted input must be sorted before differencing.
	got := computeIntervals([]int64{60, 0, 30, 10})
	if len(got) != 3 {
		t.Fatalf("unsorted: len %d, want 3", len(got))
	}
	// After sort: 0, 10, 30, 60 → intervals 10, 20, 30
	want := []float64{10, 20, 30}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("[%d] got %v, want %v", i, got[i], v)
		}
	}
}

func TestComputeIntervalsDuplicates(t *testing.T) {
	// Duplicate timestamps produce a zero diff and must be dropped.
	got := computeIntervals([]int64{0, 0, 10, 10})
	for _, v := range got {
		if v <= 0 {
			t.Errorf("interval %v should be > 0", v)
		}
	}
}

// ── meanF ─────────────────────────────────────────────────────────────────────

func TestMeanFEmpty(t *testing.T) {
	if meanF(nil) != 0 {
		t.Error("empty slice should return 0")
	}
}

func TestMeanF(t *testing.T) {
	cases := []struct {
		vals []float64
		want float64
	}{
		{[]float64{10, 20, 30}, 20},
		{[]float64{5}, 5},
		{[]float64{1, 1, 1, 1}, 1},
	}
	for _, tc := range cases {
		if got := meanF(tc.vals); got != tc.want {
			t.Errorf("meanF(%v) = %v, want %v", tc.vals, got, tc.want)
		}
	}
}

// ── stddevF ───────────────────────────────────────────────────────────────────

func TestStddevFSingle(t *testing.T) {
	if stddevF([]float64{5}) != 0 {
		t.Error("single element should return 0")
	}
}

func TestStddevFConstant(t *testing.T) {
	if stddevF([]float64{5, 5, 5, 5}) != 0 {
		t.Error("constant series should return 0")
	}
}

func TestStddevFKnown(t *testing.T) {
	// {2,4,4,4,5,5,7,9}: mean=5, sum-of-sq-dev=32
	// sample stddev = sqrt(32/7) ≈ 2.138
	got := stddevF([]float64{2, 4, 4, 4, 5, 5, 7, 9})
	want := math.Sqrt(32.0 / 7.0)
	if math.Abs(got-want) > 0.001 {
		t.Errorf("sample stddev: want ≈%.4f, got %.4f", want, got)
	}
}

// ── coefficientOfVariation ───────────────────────────────────────────────────

func TestCVZeroMean(t *testing.T) {
	if coefficientOfVariation([]float64{0, 0, 0}) != 999 {
		t.Error("zero-mean series should return sentinel 999")
	}
}

func TestCVRegularBeacon(t *testing.T) {
	// Intervals ≈ 300s ± 1s → CV should be very small (< 0.05).
	intervals := []float64{299, 300, 301, 300, 299, 300, 301}
	cv := coefficientOfVariation(intervals)
	if cv >= 0.05 {
		t.Errorf("regular beacon: CV=%v, want < 0.05", cv)
	}
}

func TestCVIrregularTraffic(t *testing.T) {
	// Wildly varying intervals — should flag as non-beacon (CV > 0.5).
	wild := []float64{10, 900, 5, 800, 15, 700}
	cv := coefficientOfVariation(wild)
	if cv <= 0.5 {
		t.Errorf("irregular traffic: CV=%v, want > 0.5", cv)
	}
}

// ── isBenignProcess ───────────────────────────────────────────────────────────

func TestIsBenignProcessKnown(t *testing.T) {
	benign := []string{"ntpd", "chronyd", "sshd", "crond", "collectd", "telegraf", "snapd"}
	for _, p := range benign {
		if !isBenignProcess(p) {
			t.Errorf("%q should be benign", p)
		}
	}
}

func TestIsBenignProcessCaseInsensitive(t *testing.T) {
	if !isBenignProcess("NTPd") {
		t.Error("NTPd should be recognised as benign (lowercased before check)")
	}
	if !isBenignProcess("  SSHD  ") {
		t.Error("padded SSHD should be recognised as benign (trimmed before check)")
	}
}

func TestIsBenignProcessMalicious(t *testing.T) {
	malicious := []string{"mimikatz", "meterpreter", "c2agent", "evil.sh", "nc"}
	for _, p := range malicious {
		if isBenignProcess(p) {
			t.Errorf("%q should not be in benign list", p)
		}
	}
}

// ── isSuspiciousPort ─────────────────────────────────────────────────────────

func TestIsSuspiciousPortKnown(t *testing.T) {
	want := []int{4444, 4445, 8888, 1337, 31337, 9001, 9002, 2222, 2323, 6666, 6667}
	for _, p := range want {
		if !isSuspiciousPort(p) {
			t.Errorf("port %d should be suspicious", p)
		}
	}
}

func TestIsSuspiciousPortNormal(t *testing.T) {
	normal := []int{80, 443, 22, 25, 53, 8080, 3306, 5432}
	for _, p := range normal {
		if isSuspiciousPort(p) {
			t.Errorf("port %d should not be suspicious", p)
		}
	}
}

// ── splitAddr ─────────────────────────────────────────────────────────────────

func TestSplitAddrValid(t *testing.T) {
	ip, port := splitAddr("192.168.1.1:4444")
	if ip != "192.168.1.1" || port != 4444 {
		t.Errorf("got (%s, %d), want (192.168.1.1, 4444)", ip, port)
	}
}

func TestSplitAddrIPv6(t *testing.T) {
	ip, port := splitAddr("[::1]:9001")
	if ip != "::1" || port != 9001 {
		t.Errorf("IPv6: got (%s, %d), want (::1, 9001)", ip, port)
	}
}

func TestSplitAddrMalformed(t *testing.T) {
	ip, port := splitAddr("not-an-addr")
	if ip != "" || port != 0 {
		t.Errorf("malformed: got (%s, %d), want (\"\", 0)", ip, port)
	}
}

// ── scoreBeacon edge cases (no DB dependency) ─────────────────────────────────

func TestScoreBeaconTooFewTimestamps(t *testing.T) {
	// < 5 timestamps must always score 0 regardless of spacing.
	for n := 0; n < 5; n++ {
		ts := make([]int64, n)
		for i := range ts {
			ts[i] = int64(i * 300)
		}
		score, tags := scoreBeacon(ts, "1.2.3.4", 80, "proc", 0, 0)
		if score != 0 || len(tags) != 0 {
			t.Errorf("n=%d: want score=0/no tags, got score=%d tags=%v", n, score, tags)
		}
	}
}

func TestScoreBeaconSubSecondMeanSuppressed(t *testing.T) {
	// Mean interval < 5s is suppressed as OS-level noise.
	ts := []int64{0, 1, 2, 3, 4, 5} // intervals = [1,1,1,1,1] → mean = 1
	score, _ := scoreBeacon(ts, "8.8.8.8", 53, "systemd", 0, 0)
	if score != 0 {
		t.Errorf("sub-5s mean: want score=0, got %d", score)
	}
}
