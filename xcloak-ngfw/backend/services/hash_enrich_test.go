package services

import (
	"testing"
)

func TestDetectHashType(t *testing.T) {
	cases := []struct {
		hash     string
		expected string
	}{
		{"d41d8cd98f00b204e9800998ecf8427e", "md5"},                                // 32 hex
		{"da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"},                       // 40 hex
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"}, // 64 hex
		{"DEADBEEF", ""},          // uppercase not accepted
		{"xyz", ""},               // invalid
		{"abcdef1234567890", ""},  // 16 chars — not a valid hash length
	}
	for _, c := range cases {
		got := detectHashType(c.hash)
		if got != c.expected {
			t.Errorf("detectHashType(%q) = %q, want %q", c.hash, got, c.expected)
		}
	}
}

func TestComputeHashVerdict_MalwareBazaarWins(t *testing.T) {
	r := &HashEnrichment{MBSeen: true}
	v, conf := computeHashVerdict(r)
	if v != "malicious" || conf != "high" {
		t.Errorf("expected malicious/high when MB seen, got %s/%s", v, conf)
	}
}

func TestComputeHashVerdict_VTHighCount(t *testing.T) {
	mal, susp, total := 15, 2, 70
	r := &HashEnrichment{VTMalicious: &mal, VTSuspicious: &susp, VTTotal: &total}
	v, conf := computeHashVerdict(r)
	if v != "malicious" || conf != "high" {
		t.Errorf("expected malicious/high for VT 15/70, got %s/%s", v, conf)
	}
}

func TestComputeHashVerdict_VTLowCount(t *testing.T) {
	mal, susp, total := 1, 0, 70
	r := &HashEnrichment{VTMalicious: &mal, VTSuspicious: &susp, VTTotal: &total}
	v, conf := computeHashVerdict(r)
	if v != "suspicious" || conf != "medium" {
		t.Errorf("expected suspicious/medium for VT 1/70, got %s/%s", v, conf)
	}
}

func TestComputeHashVerdict_VTClean(t *testing.T) {
	mal, susp, total := 0, 0, 65
	r := &HashEnrichment{VTMalicious: &mal, VTSuspicious: &susp, VTTotal: &total}
	v, conf := computeHashVerdict(r)
	if v != "clean" || conf != "high" {
		t.Errorf("expected clean/high for VT 0/65, got %s/%s", v, conf)
	}
}

func TestComputeHashVerdict_NoSources(t *testing.T) {
	r := &HashEnrichment{}
	v, conf := computeHashVerdict(r)
	if v != "unknown" || conf != "low" {
		t.Errorf("expected unknown/low with no sources, got %s/%s", v, conf)
	}
}

func TestEnrichHash_BadInput(t *testing.T) {
	cases := []struct{ hash, wantErr string }{
		{"", "empty hash"},
		{"NOTAHEX0000000000000000000000000", "unrecognised hash length"},
		{"tooshort", "unrecognised hash length"},
	}
	for _, c := range cases {
		_, err := EnrichHash(c.hash)
		if err == nil {
			t.Errorf("EnrichHash(%q): expected error, got nil", c.hash)
		}
	}
}

func TestEnrichHash_CachesResult(t *testing.T) {
	// Prime cache with a known MD5 (empty file hash — won't hit network since
	// no VIRUSTOTAL_KEY env is set in test).
	hash := "d41d8cd98f00b204e9800998ecf8427e"
	hashCache.Delete(hash) // start clean

	r1, err := EnrichHash(hash)
	if err != nil {
		t.Fatalf("EnrichHash returned unexpected error: %v", err)
	}
	if r1.HashType != "md5" {
		t.Errorf("expected md5 hash type, got %q", r1.HashType)
	}

	// Second call should return cached pointer.
	r2, _ := EnrichHash(hash)
	if r1 != r2 {
		t.Error("expected same pointer from cache on second call")
	}

	hashCache.Delete(hash) // clean up
}

func TestComputeThreatLevel_RiotIsNone(t *testing.T) {
	r := &IPEnrichment{GNRiot: true}
	if computeThreatLevel(r) != "none" {
		t.Error("RIOT IPs should always compute to none")
	}
}

func TestComputeThreatLevel_GNMaliciousIsHigh(t *testing.T) {
	r := &IPEnrichment{GNClassification: "malicious"}
	if computeThreatLevel(r) != "high" {
		t.Error("Greynoise malicious should return high")
	}
}

func TestComputeThreatLevel_GNNoiseIsLow(t *testing.T) {
	r := &IPEnrichment{GNNoise: true}
	if computeThreatLevel(r) != "low" {
		t.Error("Greynoise noise should return low")
	}
}

func TestComputeThreatLevel_IOCOverridesNoise(t *testing.T) {
	r := &IPEnrichment{IsIOC: true, IOCSeverity: "critical", GNNoise: true}
	// IsIOC takes precedence over noise because the IOC path is checked first.
	// This is correct: if an analyst explicitly marked an IP as critical IOC,
	// the noise classification doesn't override that verdict.
	got := computeThreatLevel(r)
	if got != "critical" {
		t.Errorf("critical IOC should override noise classification, got %s", got)
	}
}
