package agent

import "testing"

// Fixtures are real `yara -s -m -w` output, captured against an actual
// yara 4.5.0 binary while building this parser — not hand-guessed.
const realYaraOutputFixture = `RuleA [severity="high",is_test=true,score =5] target.txt
0xe:$a: wget
RuleB [] target.txt
0x2:$x: /bin/sh
`

func TestParseYaraOutput_RealFixture(t *testing.T) {
	matches := parseYaraOutput(7, realYaraOutputFixture)
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d: %+v", len(matches), matches)
	}

	a := matches[0]
	if a.RuleName != "RuleA" || a.FilePath != "target.txt" {
		t.Errorf("match 0: unexpected rule/path: %+v", a)
	}
	if a.Severity != "high" {
		t.Errorf("match 0: expected severity from meta %q, got %q", "high", a.Severity)
	}
	if a.AgentID != 7 {
		t.Errorf("expected agent id 7, got %d", a.AgentID)
	}
	if a.MatchedStrings == "" || a.MatchedStrings == "[]" {
		t.Errorf("match 0: expected matched strings, got %q", a.MatchedStrings)
	}

	b := matches[1]
	if b.RuleName != "RuleB" {
		t.Errorf("match 1: expected RuleB, got %q", b.RuleName)
	}
	// RuleB has no meta at all ("[]") — must fall back to the default
	// severity rather than ending up empty.
	if b.Severity != "high" {
		t.Errorf("match 1: expected default severity \"high\" for rule with no meta, got %q", b.Severity)
	}
}

func TestParseMetaBlock_QuotedCommaAndSpacedEquals(t *testing.T) {
	meta := parseMetaBlock(`description="Detects suspicious shell command, or similar",severity="critical",score =5,is_test=true`)

	if meta["description"] != "Detects suspicious shell command, or similar" {
		t.Errorf("comma inside quoted value got split: %q", meta["description"])
	}
	if meta["severity"] != "critical" {
		t.Errorf("expected severity=critical, got %q", meta["severity"])
	}
	if meta["score"] != "5" {
		t.Errorf("expected score=5 (tolerating the space-before-= yara quirk), got %q", meta["score"])
	}
	if meta["is_test"] != "true" {
		t.Errorf("expected is_test=true, got %q", meta["is_test"])
	}
}

func TestParseMatchedStringLine(t *testing.T) {
	ms, ok := parseMatchedStringLine("0xe:$a: wget http")
	if !ok {
		t.Fatal("expected parse success")
	}
	if ms.Offset != "0xe" || ms.Identifier != "$a" || ms.Data != "wget http" {
		t.Errorf("unexpected parse: %+v", ms)
	}
}
