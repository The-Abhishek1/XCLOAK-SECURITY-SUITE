package services

import "testing"

func TestEvaluateCondition_Precedence(t *testing.T) {
	// "a or b and c" must mean "a or (b and c)" — NOT "(a or b) and c".
	results := map[string]bool{"a": true, "b": false, "c": false}
	if got := EvaluateCondition("a or b and c", results); !got {
		t.Fatalf("a or (b and c) with a=true should be true, got false")
	}

	results = map[string]bool{"a": false, "b": true, "c": false}
	if got := EvaluateCondition("a or b and c", results); got {
		t.Fatalf("a or (b and c) with a=false,b=true,c=false should be false (b and c is false), got true")
	}

	// Explicit parens should let you override default precedence.
	results = map[string]bool{"a": false, "b": true, "c": false}
	if got := EvaluateCondition("(a or b) and c", results); got {
		t.Fatalf("(a or b) and c with c=false should be false, got true")
	}
}

func TestEvaluateCondition_Not(t *testing.T) {
	results := map[string]bool{"a": true, "b": false}
	if got := EvaluateCondition("not a and b", results); got {
		t.Fatalf("not(a) and b with a=true should be false, got true")
	}
	if got := EvaluateCondition("not b and a", results); !got {
		t.Fatalf("not(b) and a with a=true,b=false should be true, got false")
	}
}

func TestEvaluateCondition_QuantifierThem(t *testing.T) {
	results := map[string]bool{"selection1": true, "selection2": false, "filter": false}

	if got := EvaluateCondition("1 of them", results); !got {
		t.Fatalf("1 of them should be true when any selection matched")
	}
	if got := EvaluateCondition("all of them", results); got {
		t.Fatalf("all of them should be false when not every selection matched")
	}

	results = map[string]bool{"selection1": true, "selection2": true}
	if got := EvaluateCondition("all of them", results); !got {
		t.Fatalf("all of them should be true when every selection matched")
	}
}

func TestEvaluateCondition_QuantifierWildcard(t *testing.T) {
	results := map[string]bool{
		"selection_login":  true,
		"selection_logout": false,
		"filter_admin":     false,
	}

	if got := EvaluateCondition("1 of selection_*", results); !got {
		t.Fatalf("1 of selection_* should be true (selection_login matched)")
	}
	if got := EvaluateCondition("all of selection_*", results); got {
		t.Fatalf("all of selection_* should be false (selection_logout didn't match)")
	}
	if got := EvaluateCondition("1 of filter_*", results); got {
		t.Fatalf("1 of filter_* should be false (filter_admin didn't match)")
	}
	// A wildcard matching nothing at all must be false, not vacuously true.
	if got := EvaluateCondition("1 of nonexistent_*", results); got {
		t.Fatalf("quantifier over zero selections should be false")
	}
}

func TestEvaluateCondition_QuantifierAndCombined(t *testing.T) {
	results := map[string]bool{"selection1": true, "selection2": true, "filter": true}
	// Real-world Sigma pattern: match any selection but exclude the filter.
	if got := EvaluateCondition("1 of selection* and not filter", results); got {
		t.Fatalf("1 of selection* and not filter should be false when filter matched")
	}

	results = map[string]bool{"selection1": true, "selection2": false, "filter": false}
	if got := EvaluateCondition("1 of selection* and not filter", results); !got {
		t.Fatalf("1 of selection* and not filter should be true when filter didn't match")
	}
}

func TestEvaluateCondition_LegacyBehaviorUnaffected(t *testing.T) {
	// Single-selection legacy rules (Condition == "selection1") must still work.
	results := map[string]bool{"selection1": true}
	if got := EvaluateCondition("selection1", results); !got {
		t.Fatalf("plain identifier condition should still work")
	}

	// Empty condition falls back to "any selection matched".
	results = map[string]bool{"selection1": false, "selection2": true}
	if got := EvaluateCondition("", results); !got {
		t.Fatalf("empty condition should fall back to OR-of-all-selections")
	}
}

func TestEvaluateCondition_Malformed(t *testing.T) {
	results := map[string]bool{"a": true}
	// Unbalanced parens should fail closed (false), not panic.
	if got := EvaluateCondition("(a and", results); got {
		t.Fatalf("malformed condition should fail closed to false")
	}
}

func TestMatchKeyword_Regex(t *testing.T) {
	pf := ParsedFields{Process: "powershell.exe", User: "Administrator"}

	if !matchKeyword("process|re:(?i)^powershell", "", pf) {
		t.Fatalf("regex should match process field with case-insensitive flag")
	}
	if matchKeyword("process|re:^cmd", "", pf) {
		t.Fatalf("regex should not match a different prefix")
	}
	// Case-sensitive by default (no inline flag) — Administrator vs admin.
	if matchKeyword("user|re:^admin$", "", pf) {
		t.Fatalf("regex without (?i) should be case-sensitive and not match 'Administrator' against '^admin$'")
	}
	if !matchKeyword("user|re:^Admin", "", pf) {
		t.Fatalf("case-sensitive regex should match the correctly-cased prefix")
	}
}

func TestMatchKeyword_RegexInvalidPattern(t *testing.T) {
	pf := ParsedFields{Process: "test"}
	// An invalid regex must fail closed, not panic.
	if matchKeyword("process|re:(unclosed", "", pf) {
		t.Fatalf("invalid regex should fail closed to false")
	}
}
