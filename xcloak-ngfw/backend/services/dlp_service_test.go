package services

import (
	"testing"
)

// ── PII pattern matching ───────────────────────────────────────────────────────

func TestCreditCardPattern(t *testing.T) {
	re := piiPatterns[0].re // credit_card
	hits := []string{
		"4111111111111111",    // Visa 16-digit
		"5500005555555559",    // Mastercard
		"378282246310005",     // Amex 15-digit
		"6011111111111117",    // Discover
	}
	for _, s := range hits {
		if !re.MatchString(s) {
			t.Errorf("credit_card should match %q", s)
		}
	}
	misses := []string{
		"1234567890123456", // random digits, not a valid CC prefix
		"hello world",
	}
	for _, s := range misses {
		if re.MatchString(s) {
			t.Errorf("credit_card should NOT match %q", s)
		}
	}
}

func TestSSNPattern(t *testing.T) {
	re := piiPatterns[1].re // us_ssn
	// The regex matches the format; ssnIsValid() filters out invalid values.
	hits := []string{
		"123-45-6789",
		"078-05-1120",
	}
	for _, s := range hits {
		if !re.MatchString(s) {
			t.Errorf("us_ssn regex should match %q", s)
		}
		if !ssnIsValid(s) {
			t.Errorf("ssnIsValid should accept %q", s)
		}
	}
	invalidSSNs := []string{
		"000-45-6789", // first group 000 is invalid
		"666-45-6789", // first group 666 is invalid
		"900-45-6789", // first group 900-999 is invalid
		"123-00-6789", // second group 00 is invalid
		"123-45-0000", // last group 0000 is invalid
	}
	for _, s := range invalidSSNs {
		if !re.MatchString(s) {
			t.Errorf("us_ssn regex should still match format of %q", s)
		}
		if ssnIsValid(s) {
			t.Errorf("ssnIsValid should reject %q", s)
		}
	}
}

func TestIBANPattern(t *testing.T) {
	re := piiPatterns[2].re // iban
	hits := []string{
		"GB82WEST12345698765432",
		"DE89370400440532013000",
	}
	for _, s := range hits {
		if !re.MatchString(s) {
			t.Errorf("iban should match %q", s)
		}
	}
}

func TestAWSKeyPattern(t *testing.T) {
	re := piiPatterns[6].re // aws_access_key (index 6)
	hits := []string{
		"AKIAIOSFODNN7EXAMPLE",     // AKIA + exactly 16 chars = 20 total
		"ASIAXXX1234567890123",     // ASIA + exactly 16 chars = 20 total
	}
	for _, s := range hits {
		if !re.MatchString(s) {
			t.Errorf("aws_access_key should match %q", s)
		}
	}
	if re.MatchString("BKIAIOSFODNN7EXAMPL") {
		t.Error("aws_access_key should not match non-AKIA prefix")
	}
}

func TestJWTPattern(t *testing.T) {
	re := piiPatterns[7].re // jwt_token
	validJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	if !re.MatchString(validJWT) {
		t.Errorf("jwt_token should match valid JWT, got no match for %q", validJWT[:40]+"...")
	}
	if re.MatchString("not.a.jwt") {
		t.Error("jwt_token should not match non-JWT dot-separated string")
	}
}

func TestPrivateKeyHeaderPattern(t *testing.T) {
	re := piiPatterns[5].re // private_key_header
	hits := []string{
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
	}
	for _, s := range hits {
		if !re.MatchString(s) {
			t.Errorf("private_key_header should match %q", s)
		}
	}
}

// ── redactMatches ─────────────────────────────────────────────────────────────

func TestRedactMatches_LongString(t *testing.T) {
	r := redactMatches([]string{"4111111111111111"})
	if len(r) == 0 {
		t.Fatal("redactMatches returned empty")
	}
	// First 2 and last 2 chars preserved; middle should be asterisks.
	if r[0] != '4' || r[1] != '1' {
		t.Errorf("redactMatches prefix wrong: %q", r)
	}
	// The middle should contain asterisks.
	found := false
	for _, ch := range r {
		if ch == '*' {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("redactMatches should contain asterisks, got %q", r)
	}
}

func TestRedactMatches_ShortString(t *testing.T) {
	r := redactMatches([]string{"abc"})
	if r != "****" {
		t.Errorf("redactMatches short string: got %q, want ****", r)
	}
}

func TestRedactMatches_Multiple(t *testing.T) {
	r := redactMatches([]string{"123-45-6789", "987-65-4321"})
	// Should be comma-separated
	if r == "" {
		t.Fatal("empty result")
	}
	// Should contain a comma between the two redacted values.
	commaFound := false
	for _, ch := range r {
		if ch == ',' {
			commaFound = true
			break
		}
	}
	if !commaFound {
		t.Errorf("multiple matches should be comma-separated, got %q", r)
	}
}

// ── matchSensitiveFile ────────────────────────────────────────────────────────

func TestMatchSensitiveFile_PrivateKey(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/home/alice/.ssh/id_rsa", "private_key"},
		{"/etc/ssl/private/server.pem", "private_key"},
		{"/home/bob/secrets.yml", "secrets_config"},
		{"/opt/app/.env", "secrets_config"},
		{"/backup/production.sql", "database_dump"},
		{"/data/customers.csv", "pii_data_file"},
		{"/reports/salary_2024.xlsx", "pii_data_file"},  // "salary" matches pii_data_file first
		{"/normal/file.txt", ""},
	}
	for _, c := range cases {
		fp := matchSensitiveFile(c.path)
		if c.want == "" {
			if fp != nil {
				t.Errorf("matchSensitiveFile(%q) = %q, want no match", c.path, fp.name)
			}
		} else {
			if fp == nil {
				t.Errorf("matchSensitiveFile(%q) = nil, want %q", c.path, c.want)
			} else if fp.name != c.want {
				t.Errorf("matchSensitiveFile(%q) = %q, want %q", c.path, fp.name, c.want)
			}
		}
	}
}

// ── isSensitiveDestination ────────────────────────────────────────────────────

func TestIsSensitiveDestination_CloudStorage(t *testing.T) {
	hits := []string{
		"mega.nz", "dropbox.com", "s3.amazonaws.com",
		"pastebin.com", "mediafire.com", "filebin.net",
	}
	for _, h := range hits {
		if !isSensitiveDestination(h) {
			t.Errorf("isSensitiveDestination(%q) should be true", h)
		}
	}
}

func TestIsSensitiveDestination_Normal(t *testing.T) {
	misses := []string{
		"google.com", "github.com", "example.com", "192.168.1.1",
	}
	for _, m := range misses {
		if isSensitiveDestination(m) {
			t.Errorf("isSensitiveDestination(%q) should be false", m)
		}
	}
}

// ── piiPattern invariants ─────────────────────────────────────────────────────

func TestPIIPatterns_AllHaveRequiredFields(t *testing.T) {
	for _, p := range piiPatterns {
		if p.name == "" {
			t.Errorf("pii pattern missing name")
		}
		if p.re == nil {
			t.Errorf("pii pattern %q has nil regexp", p.name)
		}
		if p.severity == "" {
			t.Errorf("pii pattern %q missing severity", p.name)
		}
		if p.mitre == "" {
			t.Errorf("pii pattern %q missing mitre", p.name)
		}
	}
}

func TestFilePatterns_AllHaveRequiredFields(t *testing.T) {
	for _, fp := range sensitiveFilePatterns {
		if fp.name == "" {
			t.Errorf("file pattern missing name")
		}
		if len(fp.patterns) == 0 {
			t.Errorf("file pattern %q has no patterns", fp.name)
		}
		if fp.severity == "" {
			t.Errorf("file pattern %q missing severity", fp.name)
		}
		if fp.mitre == "" {
			t.Errorf("file pattern %q missing mitre", fp.name)
		}
	}
}

func TestSensitiveDestinations_NotEmpty(t *testing.T) {
	if len(sensitiveDestinations) == 0 {
		t.Error("sensitiveDestinations list is empty")
	}
	// Should at least contain Dropbox (from cloudStorageDomains) and pastebin.
	hasDropbox := false
	hasPastebin := false
	for _, d := range sensitiveDestinations {
		if d == "dropbox.com" {
			hasDropbox = true
		}
		if d == "pastebin.com" {
			hasPastebin = true
		}
	}
	if !hasDropbox {
		t.Error("sensitiveDestinations missing dropbox.com")
	}
	if !hasPastebin {
		t.Error("sensitiveDestinations missing pastebin.com")
	}
}
