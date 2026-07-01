package services

import (
	"encoding/json"
	"sync"
	"testing"

	"xcloak-ngfw/models"
)

// ── buildStepNameIndex ────────────────────────────────────────────────────────

func TestBuildStepNameIndex_BasicMapping(t *testing.T) {
	groups := [][]models.PlaybookAction{
		{{StepName: "enrich", StepOrder: 1}},
		{{StepName: "branch1", StepOrder: 2}},
		{{StepName: "notify", StepOrder: 3}, {StepName: "block", StepOrder: 3}},
	}
	idx := buildStepNameIndex(groups)
	cases := []struct{ name string; want int }{
		{"enrich", 0},
		{"branch1", 1},
		{"notify", 2},
		{"block", 2},
	}
	for _, c := range cases {
		if got := idx[c.name]; got != c.want {
			t.Errorf("index[%q] = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestBuildStepNameIndex_CaseInsensitive(t *testing.T) {
	groups := [][]models.PlaybookAction{
		{{StepName: "MyStep", StepOrder: 1}},
	}
	idx := buildStepNameIndex(groups)
	if _, ok := idx["mystep"]; !ok {
		t.Error("expected lowercase key 'mystep' in index")
	}
	if _, ok := idx["MyStep"]; ok {
		t.Error("unexpected mixed-case key 'MyStep' — index should be lowercase")
	}
}

func TestBuildStepNameIndex_UnnamedStepsIgnored(t *testing.T) {
	groups := [][]models.PlaybookAction{
		{{StepName: "", StepOrder: 1}},
		{{StepName: "named", StepOrder: 2}},
	}
	idx := buildStepNameIndex(groups)
	if _, ok := idx[""]; ok {
		t.Error("empty step_name should not be indexed")
	}
	if len(idx) != 1 {
		t.Errorf("expected 1 entry, got %d", len(idx))
	}
}

// ── propagateStepOutput ───────────────────────────────────────────────────────

func TestPropagateStepOutput_JSONOutput(t *testing.T) {
	ctx := map[string]string{}
	var mu sync.Mutex

	action := models.PlaybookAction{StepName: "enrich"}
	results := []*models.PlaybookStepResult{
		{Status: "success", Output: `{"verdict":"malicious","score":"95"}`},
	}
	propagateStepOutput(action, results, ctx, &mu)

	if ctx["steps.enrich.verdict"] != "malicious" {
		t.Errorf("steps.enrich.verdict = %q, want %q", ctx["steps.enrich.verdict"], "malicious")
	}
	if ctx["steps.enrich.score"] != "95" {
		t.Errorf("steps.enrich.score = %q, want %q", ctx["steps.enrich.score"], "95")
	}
	if ctx["steps.enrich.status"] != "success" {
		t.Errorf("steps.enrich.status = %q, want %q", ctx["steps.enrich.status"], "success")
	}
}

func TestPropagateStepOutput_PlainStringOutput(t *testing.T) {
	ctx := map[string]string{}
	var mu sync.Mutex

	action := models.PlaybookAction{StepName: "notify"}
	results := []*models.PlaybookStepResult{
		{Status: "success", Output: "slack message sent"},
	}
	propagateStepOutput(action, results, ctx, &mu)

	if ctx["steps.notify.output"] != "slack message sent" {
		t.Errorf("plain output not stored, got %q", ctx["steps.notify.output"])
	}
}

func TestPropagateStepOutput_NoNameNoOp(t *testing.T) {
	ctx := map[string]string{}
	var mu sync.Mutex

	action := models.PlaybookAction{StepName: ""}
	results := []*models.PlaybookStepResult{{Status: "success", Output: `{"x":"y"}`}}
	propagateStepOutput(action, results, ctx, &mu)

	if len(ctx) != 0 {
		t.Error("unnamed step should not write to ctx")
	}
}

func TestPropagateStepOutput_UsesFirstSuccess(t *testing.T) {
	ctx := map[string]string{}
	var mu sync.Mutex

	action := models.PlaybookAction{StepName: "multi"}
	results := []*models.PlaybookStepResult{
		{Status: "failed", Output: `{"verdict":"unknown"}`},
		{Status: "success", Output: `{"verdict":"malicious"}`},
		{Status: "failed", Output: `{"verdict":"clean"}`},
	}
	propagateStepOutput(action, results, ctx, &mu)

	// Should use the first successful result.
	if ctx["steps.multi.verdict"] != "malicious" {
		t.Errorf("expected 'malicious' from first success, got %q", ctx["steps.multi.verdict"])
	}
}

// ── evalCondition with step output context ────────────────────────────────────

func TestEvalCondition_StepOutputContext(t *testing.T) {
	ctx := map[string]string{
		"severity":                 "high",
		"steps.enrich.verdict":     "malicious",
		"steps.enrich.score":       "95",
	}
	cases := []struct {
		expr string
		want bool
	}{
		{`steps.enrich.verdict == "malicious"`, true},
		{`steps.enrich.verdict == "clean"`, false},
		{`steps.enrich.score >= 90`, true},
		{`steps.enrich.score <= 50`, false},
		{`severity == "high" && steps.enrich.verdict == "malicious"`, true},
		{`severity == "low" || steps.enrich.verdict == "malicious"`, true},
		{`severity == "low" && steps.enrich.verdict == "malicious"`, false},
		{`steps.enrich.verdict in ["malicious","suspicious"]`, true},
		{`steps.enrich.verdict not in ["clean","unknown"]`, true},
	}
	for _, c := range cases {
		if got := evalCondition(c.expr, ctx); got != c.want {
			t.Errorf("evalCondition(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
}

// ── loop-over expansion ───────────────────────────────────────────────────────

func TestExecuteStepWithLoop_EmptyLoopOver(t *testing.T) {
	// action with no loop_over — should run once with no loop item
	action := models.PlaybookAction{
		StepOrder:  1,
		ActionType: "branch",
		ConditionExpr: `severity == "critical"`,
		GotoOnSuccess: "escalate",
		GotoOnFailure: "close",
	}
	alert := models.Alert{Severity: "critical"}
	ctx := buildAlertContext(alert)

	results := executeStepWithLoopAndContext(action, alert, ctx, 0)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].GotoTaken != "escalate" {
		t.Errorf("branch true: GotoTaken = %q, want %q", results[0].GotoTaken, "escalate")
	}
}

func TestExecuteStepWithLoop_LoopExpansion(t *testing.T) {
	// action with loop_over — should run once per item
	action := models.PlaybookAction{
		StepOrder:  1,
		ActionType: "branch",
		ConditionExpr: `item == "malicious"`,
		GotoOnSuccess: "block",
		GotoOnFailure: "",
		LoopOver:  "ioc_list",
	}
	alert := models.Alert{Severity: "high"}
	ctx := buildAlertContext(alert)
	ctx["ioc_list"] = "malicious,clean,malicious"

	results := executeStepWithLoopAndContext(action, alert, ctx, 0)
	if len(results) != 3 {
		t.Fatalf("expected 3 results for 3 items, got %d", len(results))
	}
	if results[0].GotoTaken != "block" {
		t.Errorf("item[0]=malicious: GotoTaken = %q, want %q", results[0].GotoTaken, "block")
	}
	if results[1].GotoTaken != "" {
		t.Errorf("item[1]=clean: GotoTaken = %q, want empty", results[1].GotoTaken)
	}
	if results[0].LoopItem != "malicious" {
		t.Errorf("LoopItem = %q, want %q", results[0].LoopItem, "malicious")
	}
}

// ── branch action type ────────────────────────────────────────────────────────

func TestBranchAction_ConditionTrue(t *testing.T) {
	action := models.PlaybookAction{
		StepOrder:     1,
		ActionType:    "branch",
		ConditionExpr: `severity == "critical"`,
		GotoOnSuccess: "escalate",
		GotoOnFailure: "log_only",
	}
	alert := models.Alert{Severity: "critical"}
	ctx := buildAlertContext(alert)

	r := executeStep(action, alert, ctx, 0, "")
	if r.Status != "success" {
		t.Errorf("branch status = %q, want success", r.Status)
	}
	if r.GotoTaken != "escalate" {
		t.Errorf("GotoTaken = %q, want escalate", r.GotoTaken)
	}
}

func TestBranchAction_ConditionFalse(t *testing.T) {
	action := models.PlaybookAction{
		StepOrder:     1,
		ActionType:    "branch",
		ConditionExpr: `severity == "critical"`,
		GotoOnSuccess: "escalate",
		GotoOnFailure: "log_only",
	}
	alert := models.Alert{Severity: "high"}
	ctx := buildAlertContext(alert)

	r := executeStep(action, alert, ctx, 0, "")
	if r.GotoTaken != "log_only" {
		t.Errorf("GotoTaken = %q, want log_only", r.GotoTaken)
	}
}

// ── condition evaluator — existing coverage ───────────────────────────────────

func TestEvalCondition_InList(t *testing.T) {
	ctx := map[string]string{"severity": "critical"}
	if !evalCondition(`severity in ["critical","high"]`, ctx) {
		t.Error("expected true for severity in list")
	}
	if evalCondition(`severity in ["low","medium"]`, ctx) {
		t.Error("expected false for severity not in list")
	}
}

func TestEvalCondition_NumericComparisons(t *testing.T) {
	ctx := map[string]string{"score": "87"}
	cases := []struct {
		expr string
		want bool
	}{
		{"score > 80", true},
		{"score >= 87", true},
		{"score < 90", true},
		{"score <= 87", true},
		{"score > 90", false},
		{"score != 100", true},
	}
	for _, c := range cases {
		if got := evalCondition(c.expr, ctx); got != c.want {
			t.Errorf("evalCondition(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
}

func TestEvalCondition_EmptyExpr(t *testing.T) {
	if !evalCondition("", map[string]string{}) {
		t.Error("empty expression should evaluate to true (no guard)")
	}
}

// ── groupByStepOrder ──────────────────────────────────────────────────────────

func TestGroupByStepOrder_Basic(t *testing.T) {
	actions := []models.PlaybookAction{
		{StepOrder: 1}, {StepOrder: 1},
		{StepOrder: 2},
		{StepOrder: 3}, {StepOrder: 3}, {StepOrder: 3},
	}
	groups := groupByStepOrder(actions)
	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(groups))
	}
	if len(groups[0]) != 2 || len(groups[1]) != 1 || len(groups[2]) != 3 {
		t.Error("group sizes wrong")
	}
}

func TestGroupByStepOrder_EmptyActions(t *testing.T) {
	if groups := groupByStepOrder(nil); groups != nil {
		t.Error("nil input should return nil groups")
	}
}

// ── renderTemplate ────────────────────────────────────────────────────────────

func TestRenderTemplate_SubstitutesFields(t *testing.T) {
	ctx := map[string]string{
		"severity":  "critical",
		"rule_name": "Mimikatz Detected",
		"item":      "10.0.0.1",
	}
	tmpl := "Alert: {{alert.rule_name}} ({{alert.severity}}) — IP: {{alert.item}}"
	got := renderTemplate(tmpl, ctx)
	want := "Alert: Mimikatz Detected (critical) — IP: 10.0.0.1"
	if got != want {
		t.Errorf("renderTemplate = %q, want %q", got, want)
	}
}

func TestRenderPayload_SubstitutesJSON(t *testing.T) {
	ctx := map[string]string{"agent_id": "42", "severity": "high"}
	payload := json.RawMessage(`{"text":"Agent {{alert.agent_id}} - {{alert.severity}}"}`)
	got := string(renderPayload(payload, ctx))
	want := `{"text":"Agent 42 - high"}`
	if got != want {
		t.Errorf("renderPayload = %q, want %q", got, want)
	}
}
