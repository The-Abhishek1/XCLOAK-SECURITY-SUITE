package services

import (
	"testing"
)

func TestGetPortInfo_KnownPorts(t *testing.T) {
	tests := []struct {
		port            string
		wantService     string
		wantSensitivity string
	}{
		{"22", "SSH", "sensitive"},
		{"80", "HTTP", "neutral"},
		{"443", "HTTPS", "safe"},
		{"445", "SMB", "critical"},
		{"21", "FTP", "critical"},
		{"23", "Telnet", "critical"},
		{"3389", "RDP", "critical"},
		{"1433", "MSSQL", "critical"},
		{"53", "DNS", "neutral"},
	}

	for _, tc := range tests {
		info := GetPortInfo(tc.port)
		if info == nil {
			t.Errorf("GetPortInfo(%q) = nil, want %q", tc.port, tc.wantService)
			continue
		}
		if info.Service != tc.wantService {
			t.Errorf("GetPortInfo(%q).Service = %q, want %q", tc.port, info.Service, tc.wantService)
		}
		if info.Sensitivity != tc.wantSensitivity {
			t.Errorf("GetPortInfo(%q).Sensitivity = %q, want %q", tc.port, info.Sensitivity, tc.wantSensitivity)
		}
	}
}

func TestGetPortInfo_UnknownPort(t *testing.T) {
	if info := GetPortInfo("99999"); info != nil {
		t.Errorf("expected nil for unknown port, got %+v", info)
	}
	if info := GetPortInfo(""); info != nil {
		t.Errorf("expected nil for empty port, got %+v", info)
	}
}

func intPtr(i int) *int       { return &i }
func boolTrue() bool          { return true }

func TestComputeThreatLevel(t *testing.T) {
	abuseLow := 3
	abuseMed := 30
	abuseHigh := 60
	abuseCrit := 80
	vtMed := 2
	vtHigh := 6

	tests := []struct {
		name string
		r    *IPEnrichment
		want string
	}{
		{
			"greynoise RIOT = none regardless of other signals",
			&IPEnrichment{GNRiot: true, GNClassification: "malicious", IsIOC: true, IOCSeverity: "critical"},
			"none",
		},
		{
			"greynoise malicious + critical IOC = critical",
			&IPEnrichment{GNClassification: "malicious", IsIOC: true, IOCSeverity: "critical"},
			"critical",
		},
		{
			"greynoise malicious without IOC = high",
			&IPEnrichment{GNClassification: "malicious"},
			"high",
		},
		{
			"IOC critical",
			&IPEnrichment{IsIOC: true, IOCSeverity: "critical"},
			"critical",
		},
		{
			"IOC high",
			&IPEnrichment{IsIOC: true, IOCSeverity: "high"},
			"high",
		},
		{
			"IOC medium",
			&IPEnrichment{IsIOC: true, IOCSeverity: "medium"},
			"medium",
		},
		{
			"IOC low/other",
			&IPEnrichment{IsIOC: true, IOCSeverity: "info"},
			"low",
		},
		{
			"abuseipdb score critical",
			&IPEnrichment{AbuseScore: &abuseCrit},
			"critical",
		},
		{
			"abuseipdb score high",
			&IPEnrichment{AbuseScore: &abuseHigh},
			"high",
		},
		{
			"abuseipdb score medium",
			&IPEnrichment{AbuseScore: &abuseMed},
			"medium",
		},
		{
			// score 3 is below the >= 5 threshold — falls through to "none"
			"abuseipdb score below low threshold",
			&IPEnrichment{AbuseScore: &abuseLow},
			"none",
		},
		{
			"virustotal high",
			&IPEnrichment{VTMalicious: &vtHigh},
			"high",
		},
		{
			"virustotal medium",
			&IPEnrichment{VTMalicious: &vtMed},
			"medium",
		},
		{
			"greynoise noise = low",
			&IPEnrichment{GNNoise: true},
			"low",
		},
		{
			"proxy = low",
			&IPEnrichment{IsProxy: true},
			"low",
		},
		{
			"no signals = none",
			&IPEnrichment{},
			"none",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := computeThreatLevel(tc.r)
			if got != tc.want {
				t.Errorf("computeThreatLevel() = %q, want %q", got, tc.want)
			}
		})
	}
}
