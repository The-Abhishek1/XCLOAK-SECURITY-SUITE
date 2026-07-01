package services

import (
	"testing"
)

// ── ClassifyOS ────────────────────────────────────────────────────────────────

func TestClassifyOS_Windows(t *testing.T) {
	cases := []string{
		"Windows 10 Pro",
		"Windows Server 2019 Datacenter",
		"Microsoft Windows 11",
		"windows server 2022",
	}
	for _, s := range cases {
		if got := ClassifyOS(s); got != "windows" {
			t.Errorf("ClassifyOS(%q) = %q, want windows", s, got)
		}
	}
}

func TestClassifyOS_Linux(t *testing.T) {
	cases := []string{
		"Ubuntu 22.04.3 LTS",
		"Debian GNU/Linux 12 (bookworm)",
		"CentOS Linux 7 (Core)",
		"Red Hat Enterprise Linux 9",
		"Fedora Linux 38",
		"Kali GNU/Linux Rolling",
		"Amazon Linux 2023",
		"Alpine Linux v3.18",
		"openSUSE Leap 15.5",
		"Rocky Linux 9.2",
		"AlmaLinux 9.2",
		"Linux 5.15.0-generic",
	}
	for _, s := range cases {
		if got := ClassifyOS(s); got != "linux" {
			t.Errorf("ClassifyOS(%q) = %q, want linux", s, got)
		}
	}
}

func TestClassifyOS_macOS(t *testing.T) {
	cases := []string{
		"darwin 22.6.0",
		"macOS 14.0 Sonoma",
		"Mac OS X 10.15.7",
	}
	for _, s := range cases {
		if got := ClassifyOS(s); got != "macos" {
			t.Errorf("ClassifyOS(%q) = %q, want macos", s, got)
		}
	}
}

func TestClassifyOS_iOS(t *testing.T) {
	cases := []string{
		"iPhone OS 16.6",
		"iPad OS 17.0",
		"iPadOS 16.1",
	}
	for _, s := range cases {
		if got := ClassifyOS(s); got != "ios" {
			t.Errorf("ClassifyOS(%q) = %q, want ios", s, got)
		}
	}
}

func TestClassifyOS_Android(t *testing.T) {
	cases := []string{
		"Android 13",
		"android 12.0.0",
	}
	for _, s := range cases {
		if got := ClassifyOS(s); got != "android" {
			t.Errorf("ClassifyOS(%q) = %q, want android", s, got)
		}
	}
}

func TestClassifyOS_Network(t *testing.T) {
	cases := []string{
		"Cisco IOS 15.7",
		"JunOS 20.4R3",
		"Pan-OS 10.2",
		"FortiOS 7.4",
		"pfSense 2.7",
		"OPNsense 23.7",
		"VyOS 1.4",
		"MikroTik RouterOS 7.11",
	}
	for _, s := range cases {
		if got := ClassifyOS(s); got != "network" {
			t.Errorf("ClassifyOS(%q) = %q, want network", s, got)
		}
	}
}

func TestClassifyOS_Other(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"unknown",
		"custom firmware v1.2",
	}
	for _, s := range cases {
		if got := ClassifyOS(s); got != "other" {
			t.Errorf("ClassifyOS(%q) = %q, want other", s, got)
		}
	}
}

func TestClassifyOS_CaseInsensitive(t *testing.T) {
	if got := ClassifyOS("UBUNTU 20.04"); got != "linux" {
		t.Errorf("ClassifyOS is case-sensitive: got %q", got)
	}
	if got := ClassifyOS("WINDOWS SERVER 2019"); got != "windows" {
		t.Errorf("ClassifyOS is case-sensitive: got %q", got)
	}
}

func TestClassifyOS_IOSNotConfusedWithCiscoIOS(t *testing.T) {
	// "Cisco IOS" should be network, not ios
	got := ClassifyOS("Cisco IOS XE 17.9.4")
	if got != "network" {
		t.Errorf("Cisco IOS should classify as network, got %q", got)
	}
}

// ── ClassifyAssetType ─────────────────────────────────────────────────────────

func TestClassifyAssetType_Web(t *testing.T) {
	cases := []string{"web_server", "web_application", "web"}
	for _, s := range cases {
		if got := ClassifyAssetType(s); got != "web" {
			t.Errorf("ClassifyAssetType(%q) = %q, want web", s, got)
		}
	}
}

func TestClassifyAssetType_Network(t *testing.T) {
	cases := []string{"network_device", "firewall", "router", "switch", "load_balancer", "network"}
	for _, s := range cases {
		if got := ClassifyAssetType(s); got != "network" {
			t.Errorf("ClassifyAssetType(%q) = %q, want network", s, got)
		}
	}
}

func TestClassifyAssetType_Cloud(t *testing.T) {
	cases := []string{"cloud_instance", "cloud", "container", "serverless"}
	for _, s := range cases {
		if got := ClassifyAssetType(s); got != "cloud" {
			t.Errorf("ClassifyAssetType(%q) = %q, want cloud", s, got)
		}
	}
}

func TestClassifyAssetType_Mobile(t *testing.T) {
	if got := ClassifyAssetType("mobile_ios"); got != "ios" {
		t.Errorf("mobile_ios: got %q, want ios", got)
	}
	if got := ClassifyAssetType("mobile_android"); got != "android" {
		t.Errorf("mobile_android: got %q, want android", got)
	}
}

func TestClassifyAssetType_Unknown(t *testing.T) {
	cases := []string{"server", "workstation", "database", ""}
	for _, s := range cases {
		if got := ClassifyAssetType(s); got != "other" {
			t.Errorf("ClassifyAssetType(%q) = %q, want other", s, got)
		}
	}
}
