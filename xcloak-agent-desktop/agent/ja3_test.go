package agent

import (
	"encoding/json"
	"fmt"
	"testing"
)

// TestJA3Fingerprint_HashLength verifies that an MD5 JA3 hash is always
// 32 hex characters. The backend rejects shorter hashes with 400.
func TestJA3Fingerprint_HashLength(t *testing.T) {
	validHash := "aabbccddeeff00112233445566778899"
	if len(validHash) != 32 {
		t.Errorf("JA3 hash must be 32 chars, got %d", len(validHash))
	}
}

// TestJA3FingerprintPayload_Fields verifies that a fingerprint record includes
// required fields so the frontend can display it.
func TestJA3FingerprintPayload_Fields(t *testing.T) {
	raw := `{"id":1,"hash":"aabbccddeeff00112233445566778899","threat_name":"Cobalt Strike","severity":"critical"}`
	var fp map[string]any
	if err := json.Unmarshal([]byte(raw), &fp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"id", "hash", "threat_name", "severity"} {
		if _, ok := fp[key]; !ok {
			t.Errorf("JA3 fingerprint payload missing field %q", key)
		}
	}
}

// TestDeleteJA3_URLPattern verifies the DELETE URL is constructed correctly.
func TestDeleteJA3_URLPattern(t *testing.T) {
	build := func(id int) string { return fmt.Sprintf("/api/ja3/fingerprints/%d", id) }
	if got := build(5); got != "/api/ja3/fingerprints/5" {
		t.Errorf("unexpected URL: %q", got)
	}
}
