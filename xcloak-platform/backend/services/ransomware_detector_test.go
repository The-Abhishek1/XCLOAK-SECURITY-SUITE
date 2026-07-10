package services

import (
	"strings"
	"testing"
)

// ── Kill-chain pattern matching ───────────────────────────────────────────────

func TestKillChainPatternMatching(t *testing.T) {
	tests := []struct {
		cmdLine     string
		wantMatch   bool
		wantNeedle  string
	}{
		{"vssadmin delete shadows /all /quiet", true, "vssadmin delete shadows"},
		{"VSSADMIN DELETE SHADOWS /ALL", true, "vssadmin delete shadows"},   // case-insensitive
		{"wmic shadowcopy delete", true, "wmic shadowcopy delete"},
		{"diskshadow /s c:\\script.txt", true, "diskshadow /s"},
		{"bcdedit /set recoveryenabled no", true, "bcdedit /set recoveryenabled no"},
		{"bcdedit /set bootstatuspolicy ignoreallfailures", true, "bcdedit /set bootstatuspolicy ignoreallfailures"},
		{"wbadmin delete catalog -quiet", true, "wbadmin delete catalog"},
		{"powershell.exe -enc SGVsbG8=", false, ""},
		{"explorer.exe", false, ""},
		{"cmd.exe /c dir", false, ""},
		{"notepad.exe shadow.txt", false, ""}, // contains "shadow" but not the full needle
	}

	for _, tc := range tests {
		t.Run(tc.cmdLine, func(t *testing.T) {
			searchText := strings.ToLower(tc.cmdLine)
			matched := false
			matchedNeedle := ""
			for _, pat := range ransomKillChainPatterns {
				if strings.Contains(searchText, pat.needle) {
					matched = true
					matchedNeedle = pat.needle
					break
				}
			}
			if matched != tc.wantMatch {
				t.Errorf("input %q: matched=%v, want %v", tc.cmdLine, matched, tc.wantMatch)
			}
			if tc.wantMatch && matchedNeedle != tc.wantNeedle {
				t.Errorf("input %q: matched needle %q, want %q", tc.cmdLine, matchedNeedle, tc.wantNeedle)
			}
		})
	}
}

func TestKillChainPatternsNonEmpty(t *testing.T) {
	if len(ransomKillChainPatterns) == 0 {
		t.Fatal("ransomKillChainPatterns is empty")
	}
	for i, p := range ransomKillChainPatterns {
		if p.needle == "" {
			t.Errorf("pattern[%d] has empty needle", i)
		}
		if p.ruleName == "" {
			t.Errorf("pattern[%d] has empty ruleName", i)
		}
		if p.severity == "" {
			t.Errorf("pattern[%d] has empty severity", i)
		}
		if p.mitre == "" {
			t.Errorf("pattern[%d] has empty mitre", i)
		}
	}
}

// ── Crypto extensions ─────────────────────────────────────────────────────────

func TestCryptoExtensionsPresent(t *testing.T) {
	must := []string{
		".encrypted", ".locked", ".ransom",
		".wncry",    // WannaCry
		".ryuk",     // Ryuk
		".conti",    // Conti
		".darkside", // DarkSide
	}
	extSet := make(map[string]bool, len(cryptoExtensions))
	for _, e := range cryptoExtensions {
		extSet[e] = true
	}
	for _, e := range must {
		if !extSet[e] {
			t.Errorf("cryptoExtensions missing %q", e)
		}
	}
}

func TestCryptoExtensionsHaveLeadingDot(t *testing.T) {
	for _, e := range cryptoExtensions {
		if !strings.HasPrefix(e, ".") {
			t.Errorf("extension %q missing leading dot", e)
		}
	}
}

// ── cryptoExtSQL ─────────────────────────────────────────────────────────────

func TestCryptoExtSQL(t *testing.T) {
	sql := cryptoExtSQL()

	if !strings.HasPrefix(sql, "(") {
		t.Error("cryptoExtSQL: expected opening parenthesis")
	}
	if !strings.HasSuffix(sql, ")") {
		t.Error("cryptoExtSQL: expected closing parenthesis")
	}
	if !strings.Contains(sql, "LIKE") {
		t.Error("cryptoExtSQL: expected LIKE keyword")
	}
	if strings.Contains(sql, "''") {
		t.Error("cryptoExtSQL: contains empty string literal — extension list may have empty entry")
	}
	// Each extension should appear once
	for _, ext := range cryptoExtensions {
		if !strings.Contains(sql, ext) {
			t.Errorf("cryptoExtSQL: missing extension %q", ext)
		}
	}
}

// ── FIM threshold constants ───────────────────────────────────────────────────

func TestRansomFIMConstants(t *testing.T) {
	if ransomFIMThreshold <= 0 {
		t.Errorf("ransomFIMThreshold=%d, must be positive", ransomFIMThreshold)
	}
	if ransomFIMWindow == "" {
		t.Error("ransomFIMWindow must not be empty")
	}
	if ransomDedupTTL <= 0 {
		t.Error("ransomDedupTTL must be positive")
	}
}
