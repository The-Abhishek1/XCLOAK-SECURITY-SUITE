package services

import "testing"

func TestMapOTXType(t *testing.T) {
	cases := map[string]string{
		"IPv4":            "ip",
		"IPv6":            "ip",
		"CIDR":            "ip",
		"domain":          "domain",
		"hostName":        "domain",
		"URL":             "url",
		"URI":             "url",
		"FileHash-MD5":    "md5",
		"FileHash-SHA256": "sha256",
		"email":           "email",
		"CVE":             "",
		"YARA":            "",
		"Mutex":           "",
	}
	for in, want := range cases {
		if got := mapOTXType(in); got != want {
			t.Errorf("mapOTXType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMapMISPType(t *testing.T) {
	cases := map[string]string{
		"ip-dst":   "ip",
		"ip-src":   "ip",
		"domain":   "domain",
		"hostname": "domain",
		"url":      "url",
		"md5":      "md5",
		"sha256":   "sha256",
		"comment":  "",
		"text":     "",
	}
	for in, want := range cases {
		if got := mapMISPType(in); got != want {
			t.Errorf("mapMISPType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseSTIXPattern(t *testing.T) {
	cases := []struct {
		pattern       string
		wantIndicator string
		wantType      string
	}{
		{`[ipv4-addr:value = '203.0.113.5']`, "203.0.113.5", "ip"},
		{`[ipv6-addr:value = '2001:db8::1']`, "2001:db8::1", "ip"},
		{`[domain-name:value = 'evil.example.com']`, "evil.example.com", "domain"},
		{`[url:value = 'http://evil.example.com/payload']`, "http://evil.example.com/payload", "url"},
		{`[email-addr:value = 'phish@evil.example.com']`, "phish@evil.example.com", "email"},
		{`[file:hashes.'MD5' = 'd41d8cd98f00b204e9800998ecf8427e']`, "d41d8cd98f00b204e9800998ecf8427e", "md5"},
		{`[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']`, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"},
		{`[mutex:name = 'Global\\foo']`, "", ""},                                      // unsupported object type
		{`[ipv4-addr:value = '1.2.3.4'] AND [domain-name:value = 'x.com']`, "1.2.3.4", "ip"}, // only first comparison extracted
		{`not a stix pattern at all`, "", ""},
	}
	for _, c := range cases {
		gotIndicator, gotType := parseSTIXPattern(c.pattern)
		if gotIndicator != c.wantIndicator || gotType != c.wantType {
			t.Errorf("parseSTIXPattern(%q) = (%q, %q), want (%q, %q)",
				c.pattern, gotIndicator, gotType, c.wantIndicator, c.wantType)
		}
	}
}
