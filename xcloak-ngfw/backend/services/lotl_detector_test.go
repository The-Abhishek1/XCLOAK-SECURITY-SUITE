package services

import (
	"strings"
	"testing"
)

// ── exeName ───────────────────────────────────────────────────────────────────

func TestExeNameWindowsPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{`C:\Windows\System32\cmd.exe`, "cmd.exe"},
		{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "powershell.exe"},
		{`C:\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE`, "WINWORD.EXE"},
	}
	for _, tc := range cases {
		if got := exeName(tc.path); got != tc.want {
			t.Errorf("exeName(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestExeNameUnixPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/usr/bin/bash", "bash"},
		{"/bin/sh", "sh"},
		{"/usr/local/bin/python3", "python3"},
	}
	for _, tc := range cases {
		if got := exeName(tc.path); got != tc.want {
			t.Errorf("exeName(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestExeNameNoSeparator(t *testing.T) {
	// Bare filename with no path separator returns the input unchanged.
	for _, name := range []string{"notepad.exe", "bash", ""} {
		if got := exeName(name); got != name {
			t.Errorf("exeName(%q) = %q, want %q", name, got, name)
		}
	}
}

// ── suspiciousChains table integrity ──────────────────────────────────────────

func TestSuspiciousChainsNonEmpty(t *testing.T) {
	if len(suspiciousChains) == 0 {
		t.Fatal("suspiciousChains must not be empty")
	}
}

func TestSuspiciousChainsFieldsPopulated(t *testing.T) {
	for i, chain := range suspiciousChains {
		if chain.parent == "" {
			t.Errorf("suspiciousChains[%d].parent is empty", i)
		}
		if chain.child == "" {
			t.Errorf("suspiciousChains[%d].child is empty", i)
		}
		if chain.ruleName == "" {
			t.Errorf("suspiciousChains[%d].ruleName is empty", i)
		}
		if chain.severity == "" {
			t.Errorf("suspiciousChains[%d].severity is empty", i)
		}
		if chain.mitre == "" {
			t.Errorf("suspiciousChains[%d].mitre is empty", i)
		}
	}
}

func TestSuspiciousChainsKeyEntries(t *testing.T) {
	// These parent→child pairs represent the highest-value detections and
	// must always be present in the table.
	must := []procChain{
		{parent: "winword.exe", child: "powershell.exe"},
		{parent: "excel.exe", child: "cmd.exe"},
		{parent: "mshta.exe", child: "powershell.exe"},
		{parent: "svchost.exe", child: "powershell.exe"},
		{parent: "wscript.exe", child: "powershell.exe"},
	}
	for _, want := range must {
		found := false
		for _, chain := range suspiciousChains {
			if chain.parent == want.parent && chain.child == want.child {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("suspiciousChains missing %s → %s", want.parent, want.child)
		}
	}
}

func TestSuspiciousChainsLowercaseNames(t *testing.T) {
	// Parent/child must be lowercase so exeName comparisons work correctly.
	for i, chain := range suspiciousChains {
		if chain.parent != strings.ToLower(chain.parent) {
			t.Errorf("suspiciousChains[%d].parent %q is not lowercase", i, chain.parent)
		}
		if chain.child != strings.ToLower(chain.child) {
			t.Errorf("suspiciousChains[%d].child %q is not lowercase", i, chain.child)
		}
	}
}

// ── lolBinSigs table integrity ────────────────────────────────────────────────

func TestLolBinSigsNonEmpty(t *testing.T) {
	if len(lolBinSigs) == 0 {
		t.Fatal("lolBinSigs must not be empty")
	}
}

func TestLolBinSigsFieldsPopulated(t *testing.T) {
	for i, sig := range lolBinSigs {
		if sig.cmdFrag == "" {
			t.Errorf("lolBinSigs[%d].cmdFrag is empty", i)
		}
		if sig.ruleName == "" {
			t.Errorf("lolBinSigs[%d].ruleName is empty", i)
		}
		if sig.severity == "" {
			t.Errorf("lolBinSigs[%d].severity is empty", i)
		}
		if sig.mitre == "" {
			t.Errorf("lolBinSigs[%d].mitre is empty", i)
		}
	}
}

func TestLolBinSigsKeyEntries(t *testing.T) {
	type entry struct{ process, cmdFrag string }
	mustHave := []entry{
		{"certutil.exe", "-urlcache"},
		{"certutil.exe", "-decode"},
		{"regsvr32.exe", "/i:http"},
		{"mshta.exe", "http"},
		{"bitsadmin.exe", "/transfer"},
		{"wmic.exe", "process call create"},
		{"powershell.exe", "downloadstring"},
		{"powershell.exe", "frombase64string"},
	}
	for _, want := range mustHave {
		found := false
		for _, sig := range lolBinSigs {
			if sig.process == want.process && sig.cmdFrag == want.cmdFrag {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("lolBinSigs missing %s with cmdFrag %q", want.process, want.cmdFrag)
		}
	}
}

func TestLolBinSigsCmdFragLowercase(t *testing.T) {
	// cmdFrag strings must be lowercase because detection logic lowercases the
	// command line before matching.
	for i, sig := range lolBinSigs {
		if sig.cmdFrag != strings.ToLower(sig.cmdFrag) {
			t.Errorf("lolBinSigs[%d].cmdFrag %q is not lowercase", i, sig.cmdFrag)
		}
	}
}

// ── encodedPSFlags table integrity ───────────────────────────────────────────

func TestEncodedPSFlagsNonEmpty(t *testing.T) {
	if len(encodedPSFlags) == 0 {
		t.Fatal("encodedPSFlags must not be empty")
	}
}

func TestEncodedPSFlagsKeyEntries(t *testing.T) {
	must := []string{"-enc ", "-encodedcommand ", "-e "}
	for _, f := range must {
		found := false
		for _, flag := range encodedPSFlags {
			if flag == f {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("encodedPSFlags missing %q", f)
		}
	}
}
