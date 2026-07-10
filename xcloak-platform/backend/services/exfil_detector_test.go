package services

import "testing"

// ── ExtractBytesFromLogMessage ────────────────────────────────────────────────

func TestExtractBytesFromLogMessage(t *testing.T) {
	cases := []struct {
		msg  string
		want int64
	}{
		{"bytes=12345 dst=192.168.1.1", 12345},
		{"out:9999 other fields", 9999},
		{"bytes_sent=524288 some log", 524288},
		{"BYTES=100", 100},         // case-insensitive
		{"bytes-out:77", 77},
		{"no numeric bytes here", 0},
		{"", 0},
	}
	for _, tc := range cases {
		got := ExtractBytesFromLogMessage(tc.msg)
		if got != tc.want {
			t.Errorf("input %q: got %d, want %d", tc.msg, got, tc.want)
		}
	}
}

func TestExtractBytesNegativeLiteral(t *testing.T) {
	// Regex captures unsigned integers; negative values cannot match.
	got := ExtractBytesFromLogMessage("bytes=-500")
	if got != 0 {
		t.Errorf("negative literal: want 0, got %d", got)
	}
}

// ── isCloudStorageDomain ──────────────────────────────────────────────────────

func TestIsCloudStorageDomainHits(t *testing.T) {
	hits := []struct{ msg, ip string }{
		{"connection to s3.amazonaws.com established", ""},
		{"upload to dropbox.com complete", ""},
		{"mega.nz transfer started", ""},
		{"", "drive.google.com"},
		{"transfer.sh upload", ""},
		{"wetransfer.com 50MB", ""},
		{"onedrive.live.com sync", ""},
		{"sharepoint.com upload", ""},
		{"gofile.io response", ""},
	}
	for _, tc := range hits {
		if !isCloudStorageDomain(tc.msg, tc.ip) {
			t.Errorf("isCloudStorageDomain(%q, %q) = false, want true", tc.msg, tc.ip)
		}
	}
}

func TestIsCloudStorageDomainMisses(t *testing.T) {
	misses := []struct{ msg, ip string }{
		{"connection to corp-fileserver.internal", ""},
		{"GET /api/data HTTP/1.1 200", ""},
		{"ntp sync to pool.ntp.org", ""},
		{"", ""},
		{"ssh session opened", "10.0.0.1"},
	}
	for _, tc := range misses {
		if isCloudStorageDomain(tc.msg, tc.ip) {
			t.Errorf("isCloudStorageDomain(%q, %q) = true, want false", tc.msg, tc.ip)
		}
	}
}

func TestIsCloudStorageDomainCaseInsensitive(t *testing.T) {
	// Domain check is case-insensitive (combined string is lowercased).
	if !isCloudStorageDomain("Connected to S3.AMAZONAWS.COM", "") {
		t.Error("domain check should be case-insensitive")
	}
}

// ── cloudStorageDomains table integrity ──────────────────────────────────────

func TestCloudStorageDomainsNonEmpty(t *testing.T) {
	if len(cloudStorageDomains) == 0 {
		t.Fatal("cloudStorageDomains must not be empty")
	}
	for i, d := range cloudStorageDomains {
		if d == "" {
			t.Errorf("cloudStorageDomains[%d] is empty", i)
		}
	}
}

func TestCloudStorageDomainsKeyServices(t *testing.T) {
	// These cloud storage services must always be covered.
	must := []string{"s3.amazonaws.com", "dropbox.com", "drive.google.com", "mega.nz", "onedrive.live.com"}
	for _, want := range must {
		found := false
		for _, d := range cloudStorageDomains {
			if d == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("cloudStorageDomains missing %q", want)
		}
	}
}
