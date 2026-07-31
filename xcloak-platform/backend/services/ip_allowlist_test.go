package services

import "testing"

func TestParseIPAllowlist_Empty(t *testing.T) {
	nets, err := ParseIPAllowlist("")
	if err != nil || nets != nil {
		t.Errorf("empty input: got (%v, %v), want (nil, nil)", nets, err)
	}
}

func TestParseIPAllowlist_BareIPBecomesSingleHostBlock(t *testing.T) {
	nets, err := ParseIPAllowlist("203.0.113.5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 1 {
		t.Fatalf("got %d nets, want 1", len(nets))
	}
	if !IsIPAllowed("203.0.113.5", nets) {
		t.Error("the exact bare IP should be allowed")
	}
	if IsIPAllowed("203.0.113.6", nets) {
		t.Error("a different IP should not be allowed by a /32 block")
	}
}

func TestParseIPAllowlist_CIDRAndMultipleEntries(t *testing.T) {
	nets, err := ParseIPAllowlist("10.0.0.0/8, 192.168.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 2 {
		t.Fatalf("got %d nets, want 2", len(nets))
	}
	if !IsIPAllowed("10.5.5.5", nets) {
		t.Error("10.5.5.5 should be inside 10.0.0.0/8")
	}
	if !IsIPAllowed("192.168.1.42", nets) {
		t.Error("192.168.1.42 should be inside 192.168.1.0/24")
	}
	if IsIPAllowed("8.8.8.8", nets) {
		t.Error("8.8.8.8 should not be in either block")
	}
}

func TestParseIPAllowlist_InvalidEntry(t *testing.T) {
	if _, err := ParseIPAllowlist("not-an-ip"); err == nil {
		t.Error("expected an error for an invalid entry")
	}
}

func TestIsIPAllowed_EmptyAllowlistAllowsEverything(t *testing.T) {
	if !IsIPAllowed("1.2.3.4", nil) {
		t.Error("an empty/nil allowlist should allow any IP (feature off)")
	}
}
