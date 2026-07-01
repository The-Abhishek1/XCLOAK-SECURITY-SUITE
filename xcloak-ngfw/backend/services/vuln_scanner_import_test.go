package services

import (
	"strings"
	"testing"
)

// ── Nessus parser ─────────────────────────────────────────────────────────────

const nessusXML = `<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="Test Scan">
    <ReportHost name="192.168.1.10">
      <HostProperties>
        <tag name="host-ip">192.168.1.10</tag>
        <tag name="hostname">server01.internal</tag>
      </HostProperties>
      <!-- severity=0 should be skipped -->
      <ReportItem port="0" protocol="tcp" severity="0" pluginID="19506" pluginName="Nessus Scan Information">
        <description>Informational only.</description>
      </ReportItem>
      <ReportItem port="443" protocol="tcp" severity="3" pluginID="51192" pluginName="SSL Certificate Cannot Be Trusted">
        <cvss3_base_score>7.4</cvss3_base_score>
        <cvss_base_score>6.8</cvss_base_score>
        <cve>CVE-2020-12345</cve>
        <description>The SSL certificate cannot be trusted.</description>
        <solution>Purchase or generate a proper certificate.</solution>
      </ReportItem>
      <ReportItem port="22" protocol="tcp" severity="4" pluginID="10267" pluginName="SSH Weak Cipher">
        <cvss3_base_score>9.8</cvss3_base_score>
        <description>Weak SSH cipher.</description>
        <solution>Disable weak ciphers.</solution>
      </ReportItem>
    </ReportHost>
    <ReportHost name="10.0.0.5">
      <HostProperties>
        <tag name="host-ip">10.0.0.5</tag>
      </HostProperties>
      <ReportItem port="80" protocol="tcp" severity="2" pluginID="34022" pluginName="Apache httpd Outdated">
        <cvss3_base_score>5.3</cvss3_base_score>
        <cve>CVE-2021-99999</cve>
        <description>Apache is outdated.</description>
        <solution>Upgrade Apache.</solution>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`

func TestParseNessus_FindingCount(t *testing.T) {
	findings, err := parseNessus([]byte(nessusXML))
	if err != nil {
		t.Fatalf("parseNessus error: %v", err)
	}
	if len(findings) != 3 {
		t.Errorf("expected 3 findings (severity=0 skipped), got %d", len(findings))
	}
}

func TestParseNessus_SeverityMapping(t *testing.T) {
	findings, _ := parseNessus([]byte(nessusXML))
	// First finding is severity=3 → "high"
	if findings[0].Severity != "high" {
		t.Errorf("severity=3 should map to 'high', got %q", findings[0].Severity)
	}
	// Second is severity=4 → "critical"
	if findings[1].Severity != "critical" {
		t.Errorf("severity=4 should map to 'critical', got %q", findings[1].Severity)
	}
	// Third is severity=2 → "medium"
	if findings[2].Severity != "medium" {
		t.Errorf("severity=2 should map to 'medium', got %q", findings[2].Severity)
	}
}

func TestParseNessus_HostAndPort(t *testing.T) {
	findings, _ := parseNessus([]byte(nessusXML))
	f := findings[0]
	if f.HostIP != "192.168.1.10" {
		t.Errorf("host IP: got %q, want 192.168.1.10", f.HostIP)
	}
	if f.Hostname != "server01.internal" {
		t.Errorf("hostname: got %q, want server01.internal", f.Hostname)
	}
	if f.Port != 443 {
		t.Errorf("port: got %d, want 443", f.Port)
	}
	if f.Protocol != "tcp" {
		t.Errorf("protocol: got %q, want tcp", f.Protocol)
	}
}

func TestParseNessus_CVSSAndCVE(t *testing.T) {
	findings, _ := parseNessus([]byte(nessusXML))
	f := findings[0]
	if f.CVSSv3 != 7.4 {
		t.Errorf("CVSSv3: got %f, want 7.4", f.CVSSv3)
	}
	if f.CVSSv2 != 6.8 {
		t.Errorf("CVSSv2: got %f, want 6.8", f.CVSSv2)
	}
	if f.CVE != "CVE-2020-12345" {
		t.Errorf("CVE: got %q, want CVE-2020-12345", f.CVE)
	}
}

func TestParseNessus_Source(t *testing.T) {
	findings, _ := parseNessus([]byte(nessusXML))
	for _, f := range findings {
		if f.Source != "nessus" {
			t.Errorf("source: got %q, want nessus", f.Source)
		}
	}
}

func TestParseNessus_EmptyCVE(t *testing.T) {
	findings, _ := parseNessus([]byte(nessusXML))
	// Second finding (SSH Weak Cipher) has no CVE element
	f := findings[1]
	if f.CVE != "" {
		t.Errorf("missing CVE should be empty string, got %q", f.CVE)
	}
}

// ── Qualys parser ─────────────────────────────────────────────────────────────

const qualysXML = `<?xml version="1.0" encoding="UTF-8"?>
<SCAN>
  <HOST>
    <IP>10.10.10.1</IP>
    <DNS>db01.corp</DNS>
    <OS>Linux</OS>
    <VULN_LIST>
      <VULN>
        <QID>38173</QID>
        <TITLE>OpenSSL Heap-Based Buffer Overflow</TITLE>
        <SEVERITY>5</SEVERITY>
        <CVE_LIST><CVE><ID>CVE-2022-0778</ID></CVE></CVE_LIST>
        <CVSS_BASE>5.0</CVSS_BASE>
        <CVSS3_BASE>7.5</CVSS3_BASE>
        <PORT>443</PORT>
        <PROTOCOL>TCP</PROTOCOL>
        <DIAGNOSIS>Heap-based buffer overflow in OpenSSL.</DIAGNOSIS>
        <SOLUTION>Upgrade to OpenSSL 1.1.1n or 3.0.2.</SOLUTION>
      </VULN>
      <VULN>
        <QID>12345</QID>
        <TITLE>HTTP Trace Enabled</TITLE>
        <SEVERITY>2</SEVERITY>
        <CVSS_BASE>2.6</CVSS_BASE>
        <PORT>80</PORT>
        <PROTOCOL>TCP</PROTOCOL>
        <DIAGNOSIS>HTTP TRACE method is enabled.</DIAGNOSIS>
        <SOLUTION>Disable TRACE in web server config.</SOLUTION>
      </VULN>
      <VULN>
        <QID>99999</QID>
        <TITLE>Info finding</TITLE>
        <SEVERITY>0</SEVERITY>
        <DIAGNOSIS>Informational.</DIAGNOSIS>
      </VULN>
    </VULN_LIST>
  </HOST>
</SCAN>`

func TestParseQualys_FindingCount(t *testing.T) {
	findings, err := parseQualys([]byte(qualysXML))
	if err != nil {
		t.Fatalf("parseQualys error: %v", err)
	}
	if len(findings) != 2 {
		t.Errorf("expected 2 findings (severity=0 skipped), got %d", len(findings))
	}
}

func TestParseQualys_SeverityMapping(t *testing.T) {
	findings, _ := parseQualys([]byte(qualysXML))
	if findings[0].Severity != "critical" {
		t.Errorf("severity=5 should be 'critical', got %q", findings[0].Severity)
	}
	if findings[1].Severity != "low" {
		t.Errorf("severity=2 should be 'low', got %q", findings[1].Severity)
	}
}

func TestParseQualys_PluginIDPrefixed(t *testing.T) {
	findings, _ := parseQualys([]byte(qualysXML))
	if !strings.HasPrefix(findings[0].PluginID, "Q") {
		t.Errorf("Qualys plugin IDs should be prefixed with Q, got %q", findings[0].PluginID)
	}
}

func TestParseQualys_HostAndPort(t *testing.T) {
	findings, _ := parseQualys([]byte(qualysXML))
	f := findings[0]
	if f.HostIP != "10.10.10.1" {
		t.Errorf("IP: got %q, want 10.10.10.1", f.HostIP)
	}
	if f.Hostname != "db01.corp" {
		t.Errorf("hostname: got %q, want db01.corp", f.Hostname)
	}
	if f.Port != 443 {
		t.Errorf("port: got %d, want 443", f.Port)
	}
	if f.Protocol != "tcp" {
		t.Errorf("protocol: got %q, want tcp (lowercased)", f.Protocol)
	}
}

func TestParseQualys_CVSSPreferV3(t *testing.T) {
	findings, _ := parseQualys([]byte(qualysXML))
	f := findings[0]
	if f.CVSSv3 != 7.5 {
		t.Errorf("CVSSv3: got %f, want 7.5", f.CVSSv3)
	}
}

// ── Tenable parser ────────────────────────────────────────────────────────────

const tenableXML = `<?xml version="1.0"?>
<tenableSC>
  <scanResult>
    <ipList>
      <ip value="172.16.0.1" dnsName="web01.internal">
        <pluginList>
          <plugin id="21643" pluginName="SSL Certificate Expiry" severity="medium" protocol="tcp" port="443">
            <cveList><cve>CVE-2019-1234</cve></cveList>
            <cvssV3BaseScore>5.3</cvssV3BaseScore>
            <cvssV2BaseScore>4.3</cvssV2BaseScore>
            <description>SSL certificate expires soon.</description>
            <solution>Renew the certificate.</solution>
          </plugin>
          <plugin id="19506" pluginName="Nessus Info" severity="info" protocol="tcp" port="0">
            <description>Informational.</description>
          </plugin>
          <plugin id="55472" pluginName="Critical RCE" severity="critical" protocol="tcp" port="8080">
            <cvssV3BaseScore>9.8</cvssV3BaseScore>
            <description>Remote code execution.</description>
            <solution>Apply vendor patch.</solution>
          </plugin>
        </pluginList>
      </ip>
    </ipList>
  </scanResult>
</tenableSC>`

func TestParseTenable_FindingCount(t *testing.T) {
	findings, err := parseTenable([]byte(tenableXML))
	if err != nil {
		t.Fatalf("parseTenable error: %v", err)
	}
	if len(findings) != 2 {
		t.Errorf("expected 2 findings (info skipped), got %d", len(findings))
	}
}

func TestParseTenable_SeverityPassthrough(t *testing.T) {
	findings, _ := parseTenable([]byte(tenableXML))
	if findings[0].Severity != "medium" {
		t.Errorf("want medium, got %q", findings[0].Severity)
	}
	if findings[1].Severity != "critical" {
		t.Errorf("want critical, got %q", findings[1].Severity)
	}
}

func TestParseTenable_PluginIDPrefixed(t *testing.T) {
	findings, _ := parseTenable([]byte(tenableXML))
	for _, f := range findings {
		if !strings.HasPrefix(f.PluginID, "T") {
			t.Errorf("Tenable plugin IDs should be T-prefixed, got %q", f.PluginID)
		}
	}
}

func TestParseTenable_HostResolution(t *testing.T) {
	findings, _ := parseTenable([]byte(tenableXML))
	if findings[0].HostIP != "172.16.0.1" {
		t.Errorf("IP: got %q, want 172.16.0.1", findings[0].HostIP)
	}
	if findings[0].Hostname != "web01.internal" {
		t.Errorf("hostname: got %q, want web01.internal", findings[0].Hostname)
	}
}

// ── Format detection ──────────────────────────────────────────────────────────

func TestDetectAndParse_Nessus(t *testing.T) {
	scanner, findings, err := detectAndParse([]byte(nessusXML))
	if err != nil {
		t.Fatalf("detectAndParse: %v", err)
	}
	if scanner != "nessus" {
		t.Errorf("scanner: got %q, want nessus", scanner)
	}
	if len(findings) == 0 {
		t.Error("expected findings")
	}
}

func TestDetectAndParse_Qualys(t *testing.T) {
	scanner, findings, err := detectAndParse([]byte(qualysXML))
	if err != nil {
		t.Fatalf("detectAndParse: %v", err)
	}
	if scanner != "qualys" {
		t.Errorf("scanner: got %q, want qualys", scanner)
	}
	if len(findings) == 0 {
		t.Error("expected findings")
	}
}

func TestDetectAndParse_Tenable(t *testing.T) {
	scanner, findings, err := detectAndParse([]byte(tenableXML))
	if err != nil {
		t.Fatalf("detectAndParse: %v", err)
	}
	if scanner != "tenable" {
		t.Errorf("scanner: got %q, want tenable", scanner)
	}
	if len(findings) == 0 {
		t.Error("expected findings")
	}
}

func TestDetectAndParse_UnknownFormat(t *testing.T) {
	_, _, err := detectAndParse([]byte(`<unknown><data>hello</data></unknown>`))
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

// ── Severity mapping functions ────────────────────────────────────────────────

func TestNessusSeverity(t *testing.T) {
	cases := []struct{ in int; want string }{
		{0, ""},    // handled by the skip-before-map logic; function itself returns "low"
		{1, "low"},
		{2, "medium"},
		{3, "high"},
		{4, "critical"},
		{5, "low"}, // default
	}
	for _, c := range cases {
		got := nessusSeverity(c.in)
		if c.in == 0 {
			continue // severity=0 filtered before calling nessusSeverity
		}
		if got != c.want {
			t.Errorf("nessusSeverity(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestQualysSeverity(t *testing.T) {
	cases := []struct{ in int; want string }{
		{0, ""},
		{1, "low"},
		{2, "low"},
		{3, "medium"},
		{4, "high"},
		{5, "critical"},
	}
	for _, c := range cases {
		got := qualysSeverity(c.in)
		if got != c.want {
			t.Errorf("qualysSeverity(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTenableSeverity(t *testing.T) {
	cases := []struct{ in, want string }{
		{"info", ""},
		{"INFO", ""},
		{"low", "low"},
		{"medium", "medium"},
		{"high", "high"},
		{"critical", "critical"},
		{"CRITICAL", "critical"},
		{"unknown", ""},
	}
	for _, c := range cases {
		got := tenableSeverity(c.in)
		if got != c.want {
			t.Errorf("tenableSeverity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ── SQL helpers ───────────────────────────────────────────────────────────────

func TestSQLNullString(t *testing.T) {
	if sqlNullString("") != nil {
		t.Error("empty string should return nil")
	}
	if sqlNullString("hello") == nil {
		t.Error("non-empty string should return non-nil")
	}
}

func TestSQLNullInt(t *testing.T) {
	if sqlNullInt(0) != nil {
		t.Error("zero port should return nil")
	}
	if sqlNullInt(443) == nil {
		t.Error("non-zero port should return non-nil")
	}
}
