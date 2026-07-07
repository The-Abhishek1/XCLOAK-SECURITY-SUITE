package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// sentinel goto values that terminate execution
const (
	gotoEnd  = "end"
	gotoStop = "stop"
)

// TriggerTypes supported:
//
//	alert_critical        — fires on any alert with severity "critical"
//	alert_high            — fires on any alert with severity "high"
//	alert_medium          — fires on any alert with severity "medium"
//	alert_any             — fires on every alert regardless of severity
//	IOC Match             — fires when the triggering rule is "IOC Match"
//	YARA Match            — fires when the triggering rule is "YARA Match"
//	incident_created      — fires when a new incident is auto-created
//	<exact rule name>     — fires when alert.RuleName matches exactly
func ExecutePlaybooks(alert models.Alert) {
	slog.Debug("soar eval", "rule", alert.RuleName, "severity", alert.Severity, "agent", alert.AgentID)

	playbooks, err := repositories.GetEnabledPlaybooksForAgent(alert.AgentID)
	if err != nil {
		slog.Error("soar: load playbooks failed", "agent", alert.AgentID, "err", err)
		return
	}

	for _, playbook := range playbooks {
		if !matchesTrigger(playbook.TriggerType, alert) {
			continue
		}
		slog.Info("soar: playbook triggered", "playbook", playbook.Name, "trigger", playbook.TriggerType)
		runPlaybookActions(playbook, alert)
	}
}

// ExecutePlaybookByID runs a specific playbook's actions directly, bypassing
// trigger matching — used when a correlation rule names a playbook explicitly.
func ExecutePlaybookByID(playbookID, tenantID int, alert models.Alert) error {
	playbook, err := repositories.GetPlaybookByID(playbookID, tenantID)
	if err != nil {
		return nil
	}
	if !playbook.Enabled {
		return nil
	}
	runPlaybookActions(*playbook, alert)
	return nil
}

// matchesTrigger returns true if a playbook's TriggerType should fire for alert.
func matchesTrigger(triggerType string, alert models.Alert) bool {
	switch strings.ToLower(triggerType) {
	case "alert_critical":
		return strings.ToLower(alert.Severity) == "critical"
	case "alert_high":
		return strings.ToLower(alert.Severity) == "high"
	case "alert_medium":
		return strings.ToLower(alert.Severity) == "medium"
	case "alert_low":
		return strings.ToLower(alert.Severity) == "low"
	case "alert_any":
		return true
	case "ioc match":
		return strings.EqualFold(alert.RuleName, "IOC Match")
	case "yara match":
		return strings.EqualFold(alert.RuleName, "YARA Match")
	default:
		return strings.EqualFold(triggerType, alert.RuleName)
	}
}

// runPlaybookActions executes all steps for playbook against alert with full
// support for: condition guards, template variables, parallel step groups,
// per-step retry, step-level result capture, goto branching, loop-over, and
// stop-on-failure.
//
// Execution model:
//   - Steps are ordered by step_order; equal step_order values run in the same
//     "group" (parallel if run_parallel=true, sequential otherwise).
//   - After each group, if any step fired a goto target the executor jumps to
//     the first group that contains a step with matching step_name.
//   - "end" or "stop" as a goto target terminates the playbook immediately.
//   - step_name output context: after a named step executes, its JSON output is
//     parsed and merged into ctx as steps.STEP_NAME.KEY so downstream
//     conditions can reference it (e.g. steps.enrich.verdict == "malicious").
//   - loop_over: if set to a ctx key holding a comma-separated list, the step
//     runs once per item with {{item}} substituted in payload/condition.
func runPlaybookActions(playbook models.Playbook, alert models.Alert) {
	startTime := time.Now()

	execID, err := repositories.CreatePlaybookExecutionRecord(models.PlaybookExecution{
		PlaybookID:    playbook.ID,
		AgentID:       alert.AgentID,
		AlertRule:     alert.RuleName,
		ActionType:    "multi-step",
		Status:        "running",
		OverallStatus: "running",
	})
	if err != nil {
		slog.Error("soar: create execution record failed", "playbook", playbook.ID, "err", err)
		execID = 0
	}

	actions, err := repositories.GetPlaybookActions(playbook.ID)
	if err != nil {
		slog.Error("soar: load actions failed", "playbook", playbook.ID, "err", err)
		return
	}

	ctx := buildAlertContext(alert)
	groups := groupByStepOrder(actions)
	nameIndex := buildStepNameIndex(groups) // step_name → group index

	var mu sync.Mutex
	var totalSteps, okSteps, failedSteps, skippedSteps int
	aborted := false

	addResult := func(status string) {
		mu.Lock()
		defer mu.Unlock()
		totalSteps++
		switch status {
		case "success", "pending_approval":
			okSteps++
		case "failed":
			failedSteps++
		case "skipped":
			skippedSteps++
		}
	}

	groupIdx := 0
	for groupIdx < len(groups) {
		group := groups[groupIdx]
		gotoTarget := ""

		var parallel, sequential []models.PlaybookAction
		for _, a := range group {
			if a.RunParallel {
				parallel = append(parallel, a)
			} else {
				sequential = append(sequential, a)
			}
		}

		// Parallel steps — run concurrently, collect goto signals safely.
		if len(parallel) > 0 {
			var wg sync.WaitGroup
			var gotoMu sync.Mutex
			for _, a := range parallel {
				wg.Add(1)
				go func(action models.PlaybookAction) {
					defer wg.Done()
					rs := executeStepWithLoopAndContext(action, alert, ctx, execID)
					for _, r := range rs {
						addResult(r.Status)
						gotoMu.Lock()
						if r.GotoTaken != "" && gotoTarget == "" {
							gotoTarget = r.GotoTaken
						}
						gotoMu.Unlock()
						if action.StopOnFailure && r.Status == "failed" {
							gotoMu.Lock()
							aborted = true
							gotoMu.Unlock()
						}
					}
					propagateStepOutput(action, rs, ctx, &mu)
				}(a)
			}
			wg.Wait()
		}

		if aborted {
			break
		}

		// Sequential steps.
		for _, a := range sequential {
			rs := executeStepWithLoopAndContext(a, alert, ctx, execID)
			for _, r := range rs {
				addResult(r.Status)
				if r.GotoTaken != "" && gotoTarget == "" {
					gotoTarget = r.GotoTaken
				}
				if a.StopOnFailure && r.Status == "failed" {
					aborted = true
					break
				}
			}
			propagateStepOutput(a, rs, ctx, &mu)
			if aborted {
				break
			}
		}

		if aborted {
			break
		}

		// Resolve goto routing.
		switch strings.ToLower(gotoTarget) {
		case "end", "stop", "":
			if gotoTarget != "" {
				goto done
			}
			groupIdx++
		default:
			if idx, ok := nameIndex[strings.ToLower(gotoTarget)]; ok {
				slog.Debug("soar: goto", "target", gotoTarget, "group", idx)
				groupIdx = idx
			} else {
				slog.Warn("soar: goto target not found, stopping", "target", gotoTarget)
				goto done
			}
		}
	}

done:
	durationMs := int(time.Since(startTime).Milliseconds())
	overallStatus := "completed"
	if aborted {
		overallStatus = "aborted"
	} else if failedSteps > 0 && okSteps == 0 && skippedSteps == 0 {
		overallStatus = "failed"
	} else if failedSteps > 0 {
		overallStatus = "partial"
	}

	if execID > 0 {
		repositories.UpdatePlaybookExecutionSummary(
			execID, overallStatus, totalSteps, okSteps, failedSteps, skippedSteps, durationMs)
	}

	LogEvent("SOAR_PLAYBOOK_DONE",
		fmt.Sprintf("Playbook %q: %s (%d ok/%d failed/%d skipped, %dms)",
			playbook.Name, overallStatus, okSteps, failedSteps, skippedSteps, durationMs),
		"system",
	)
}

// executeStepWithLoopAndContext expands loop_over and runs executeStep for each
// item (or once if loop_over is empty). Returns one result per iteration.
func executeStepWithLoopAndContext(action models.PlaybookAction, alert models.Alert, ctx map[string]string, execID int) []*models.PlaybookStepResult {
	if action.LoopOver == "" {
		r := executeStep(action, alert, ctx, execID, "")
		return []*models.PlaybookStepResult{r}
	}

	// Expand the loop list from ctx.
	listVal := ctx[action.LoopOver]
	if listVal == "" {
		r := executeStep(action, alert, ctx, execID, "")
		r.LoopItem = "(empty)"
		return []*models.PlaybookStepResult{r}
	}

	items := strings.Split(listVal, ",")
	results := make([]*models.PlaybookStepResult, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		// Add {{item}} to a copy of ctx for this iteration.
		iterCtx := make(map[string]string, len(ctx)+1)
		for k, v := range ctx {
			iterCtx[k] = v
		}
		iterCtx["item"] = item
		r := executeStep(action, alert, iterCtx, execID, item)
		results = append(results, r)
	}
	return results
}

// propagateStepOutput merges a named step's JSON output into ctx so that
// downstream condition expressions can reference steps.STEP_NAME.KEY.
func propagateStepOutput(action models.PlaybookAction, results []*models.PlaybookStepResult, ctx map[string]string, mu *sync.Mutex) {
	if action.StepName == "" || len(results) == 0 {
		return
	}
	// Use the last result (or first success).
	r := results[len(results)-1]
	for _, res := range results {
		if res.Status == "success" {
			r = res
			break
		}
	}
	if r.Output == "" {
		return
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(r.Output), &parsed); err != nil {
		// Not JSON — store the raw string under steps.NAME.output
		mu.Lock()
		ctx["steps."+action.StepName+".output"] = r.Output
		ctx["steps."+action.StepName+".status"] = r.Status
		mu.Unlock()
		return
	}

	mu.Lock()
	defer mu.Unlock()
	prefix := "steps." + action.StepName + "."
	ctx[prefix+"status"] = r.Status
	for k, v := range parsed {
		ctx[prefix+k] = fmt.Sprintf("%v", v)
	}
}

// buildStepNameIndex builds a map from lowercase step_name → group index.
// Groups without any named step are not indexed.
func buildStepNameIndex(groups [][]models.PlaybookAction) map[string]int {
	m := make(map[string]int)
	for i, group := range groups {
		for _, a := range group {
			if a.StepName != "" {
				m[strings.ToLower(a.StepName)] = i
			}
		}
	}
	return m
}

// executeStep runs a single action, respecting its condition, retrying on
// failure, and recording the result to playbook_step_results.
// loopItem is the current loop value when called from a loop_over expansion
// (empty string for non-loop steps).
func executeStep(action models.PlaybookAction, alert models.Alert, ctx map[string]string, execID int, loopItem string) *models.PlaybookStepResult {
	startedAt := time.Now()
	result := &models.PlaybookStepResult{
		ExecutionID:   execID,
		StepOrder:     action.StepOrder,
		ActionType:    action.ActionType,
		ConditionExpr: action.ConditionExpr,
		StartedAt:     startedAt,
		StepName:      action.StepName,
		LoopItem:      loopItem,
	}

	// branch action type — pure routing node; no external dispatch.
	// Evaluates condition and signals a goto via GotoTaken.
	if action.ActionType == "branch" {
		finishedAt := time.Now()
		result.FinishedAt = &finishedAt
		if evalCondition(action.ConditionExpr, ctx) {
			result.Status = "success"
			result.Output = "branch condition true"
			result.GotoTaken = action.GotoOnSuccess
		} else {
			result.Status = "success"
			result.Output = "branch condition false"
			result.GotoTaken = action.GotoOnFailure
		}
		slog.Debug("soar: branch step", "order", action.StepOrder, "cond", action.ConditionExpr, "goto", result.GotoTaken)
		if execID > 0 {
			repositories.CreatePlaybookStepResult(*result)
		}
		return result
	}

	if action.ConditionExpr != "" && !evalCondition(action.ConditionExpr, ctx) {
		result.Status = "skipped"
		result.Output = "condition not met: " + action.ConditionExpr
		finishedAt := time.Now()
		result.FinishedAt = &finishedAt
		if execID > 0 {
			repositories.CreatePlaybookStepResult(*result)
		}
		slog.Debug("soar: step skipped", "order", action.StepOrder, "type", action.ActionType, "cond", action.ConditionExpr)
		return result
	}

	// Render {{alert.field}} and {{item}} templates in the payload before dispatch.
	rendered := action
	rendered.Payload = renderPayload(action.Payload, ctx)

	maxAttempts := action.MaxRetries + 1
	var lastErr error
	var output string

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			delay := time.Duration(action.RetryDelaySecs) * time.Second
			if delay <= 0 {
				delay = 5 * time.Second
			}
			time.Sleep(delay)
			slog.Debug("soar: retry", "attempt", attempt+1, "max", action.MaxRetries, "order", action.StepOrder, "type", action.ActionType)
		}
		output, lastErr = dispatchActionAdvanced(rendered, alert)
		result.RetriesUsed = attempt
		if lastErr == nil {
			break
		}
	}

	finishedAt := time.Now()
	result.FinishedAt = &finishedAt
	result.Output = output

	switch {
	case lastErr != nil:
		result.Status = "failed"
		result.ErrorDetail = lastErr.Error()
		result.GotoTaken = action.GotoOnFailure
		slog.Warn("soar: step failed", "order", action.StepOrder, "type", action.ActionType, "err", lastErr)
	case output == "pending_approval":
		result.Status = "pending_approval"
		result.GotoTaken = action.GotoOnSuccess
		slog.Info("soar: step pending approval", "order", action.StepOrder, "type", action.ActionType)
	default:
		result.Status = "success"
		result.GotoTaken = action.GotoOnSuccess
		slog.Debug("soar: step ok", "order", action.StepOrder, "type", action.ActionType, "output", truncate(output, 120))
	}

	if execID > 0 {
		repositories.CreatePlaybookStepResult(*result)
	}
	return result
}

// dispatchActionAdvanced routes an action to the appropriate handler and
// returns a human-readable output string plus any error.
func dispatchActionAdvanced(action models.PlaybookAction, alert models.Alert) (string, error) {
	ctx := buildAlertContext(alert)

	switch action.ActionType {
	case "webhook":
		return handleWebhook(action.Payload, ctx)
	case "slack_message":
		return handleSlackMessage(action.Payload, ctx)
	case "pagerduty_incident":
		return handlePagerDutyIncident(action.Payload, ctx)
	case "email_alert":
		return handleEmailAlertAction(action.Payload, alert)
	default:
		return dispatchAgentTask(action, alert)
	}
}

// dispatchAgentTask queues an agent task (or holds it for approval if destructive).
func dispatchAgentTask(action models.PlaybookAction, alert models.Alert) (string, error) {
	payload := mergePayload(action.Payload, alert)
	task := models.AgentTask{
		AgentID:  alert.AgentID,
		TaskType: action.ActionType,
		Payload:  payload,
	}
	if IsDestructiveTask(action.ActionType) {
		if err := repositories.CreateTaskPendingApproval(task); err != nil {
			return "", err
		}
		LogEvent(
			"SOAR_ACTION_PENDING_APPROVAL",
			fmt.Sprintf("Playbook → %s on agent #%d from alert %q, awaiting approval",
				action.ActionType, alert.AgentID, alert.RuleName),
			"system",
		)
		return "pending_approval", nil
	}
	if err := CreateTask(task); err != nil {
		return "", err
	}
	return fmt.Sprintf("task queued for agent #%d", alert.AgentID), nil
}

// ── External notification handlers ────────────────────────────────────────────

// handleWebhook POSTs (or uses the configured method) to an arbitrary URL.
// Payload fields: url, method (default POST), headers (map), body (string, templated).
func handleWebhook(payload json.RawMessage, ctx map[string]string) (string, error) {
	var cfg struct {
		URL     string            `json:"url"`
		Method  string            `json:"method"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	}
	json.Unmarshal(payload, &cfg)
	if cfg.URL == "" {
		return "", fmt.Errorf("webhook: url is required")
	}
	if err := CheckURL(cfg.URL); err != nil {
		return "", fmt.Errorf("webhook: %w", err)
	}
	if cfg.Method == "" {
		cfg.Method = "POST"
	}

	body := renderTemplate(cfg.Body, ctx)
	req, err := http.NewRequest(cfg.Method, cfg.URL, strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("webhook: %w", err)
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("Content-Type") == "" && body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("webhook: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode >= 400 {
		return string(respBody), fmt.Errorf("webhook: HTTP %d", resp.StatusCode)
	}
	return fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 200)), nil
}

// handleSlackMessage posts a formatted message to a Slack incoming webhook.
// Payload fields: webhook_url, message (templated).
func handleSlackMessage(payload json.RawMessage, ctx map[string]string) (string, error) {
	var cfg struct {
		WebhookURL string `json:"webhook_url"`
		Message    string `json:"message"`
	}
	json.Unmarshal(payload, &cfg)
	if cfg.WebhookURL == "" {
		return "", fmt.Errorf("slack_message: webhook_url is required")
	}
	if err := CheckURL(cfg.WebhookURL); err != nil {
		return "", fmt.Errorf("slack_message: %w", err)
	}

	msg := renderTemplate(cfg.Message, ctx)
	if msg == "" {
		msg = fmt.Sprintf("*XCLOAK Alert:* %s\nSeverity: %s | Agent: #%s",
			ctx["rule_name"], ctx["severity"], ctx["agent_id"])
	}

	body, _ := json.Marshal(map[string]string{"text": msg})
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(cfg.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("slack_message: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("slack_message: HTTP %d: %s", resp.StatusCode, b)
	}
	return "slack message sent", nil
}

// handlePagerDutyIncident creates a PagerDuty incident via Events API v2.
// Payload fields: integration_key, title (templated), source.
func handlePagerDutyIncident(payload json.RawMessage, ctx map[string]string) (string, error) {
	var cfg struct {
		IntegrationKey string `json:"integration_key"`
		Title          string `json:"title"`
		Source         string `json:"source"`
	}
	json.Unmarshal(payload, &cfg)
	if cfg.IntegrationKey == "" {
		return "", fmt.Errorf("pagerduty_incident: integration_key is required")
	}

	title := cfg.Title
	if title == "" {
		title = fmt.Sprintf("XCLOAK: %s", ctx["rule_name"])
	}
	title = renderTemplate(title, ctx)

	source := cfg.Source
	if source == "" {
		source = "xcloak-ngfw"
	}

	pdSevMap := map[string]string{
		"critical": "critical",
		"high":     "error",
		"medium":   "warning",
		"low":      "info",
		"info":     "info",
	}
	pdSev := pdSevMap[strings.ToLower(ctx["severity"])]
	if pdSev == "" {
		pdSev = "error"
	}

	body, _ := json.Marshal(map[string]interface{}{
		"routing_key":  cfg.IntegrationKey,
		"event_action": "trigger",
		"payload": map[string]interface{}{
			"summary":   title,
			"severity":  pdSev,
			"source":    source,
			"timestamp": time.Now().Format(time.RFC3339),
			"custom_details": map[string]string{
				"agent_id":   ctx["agent_id"],
				"rule_name":  ctx["rule_name"],
				"log_sample": ctx["log_sample"],
			},
		},
	})

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post("https://events.pagerduty.com/v2/enqueue",
		"application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("pagerduty_incident: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("pagerduty_incident: HTTP %d: %s", resp.StatusCode, respBody)
	}
	return "PagerDuty incident created: " + truncate(string(respBody), 200), nil
}

// handleEmailAlertAction sends an alert email to addresses from payload.to.
// Payload fields: to (string, comma-separated), subject (optional, templated).
func handleEmailAlertAction(payload json.RawMessage, alert models.Alert) (string, error) {
	var cfg struct {
		To      string `json:"to"`
		Subject string `json:"subject"`
	}
	json.Unmarshal(payload, &cfg)
	if cfg.To == "" {
		return "", fmt.Errorf("email_alert: to is required")
	}
	recipients := strings.Split(cfg.To, ",")
	for i, r := range recipients {
		recipients[i] = strings.TrimSpace(r)
	}
	if err := SendAlertEmail(alert, recipients); err != nil {
		return "", fmt.Errorf("email_alert: %w", err)
	}
	return fmt.Sprintf("email sent to %s", cfg.To), nil
}

// ── Condition evaluator ────────────────────────────────────────────────────────

// evalCondition evaluates a simple boolean expression against ctx.
// Supports: ==, !=, contains, not contains, in, not in, >, >=, <, <=
// Logic operators: && (AND) and || (OR), left-to-right without parentheses.
// Field names map to alert context keys: severity, rule_name, agent_id, etc.
//
// Examples:
//
//	severity == "critical"
//	severity in ["critical","high"]
//	rule_name contains "SSH" && severity != "low"
func evalCondition(expr string, ctx map[string]string) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return true
	}
	for _, clause := range splitLogic(expr, "||") {
		if evalAnd(strings.TrimSpace(clause), ctx) {
			return true
		}
	}
	return false
}

func evalAnd(expr string, ctx map[string]string) bool {
	for _, clause := range splitLogic(expr, "&&") {
		if !evalTerm(strings.TrimSpace(clause), ctx) {
			return false
		}
	}
	return true
}

// splitLogic splits on op (|| or &&), ignoring occurrences inside [...].
func splitLogic(expr, op string) []string {
	var parts []string
	depth, last := 0, 0
	for i := 0; i < len(expr); i++ {
		switch expr[i] {
		case '[':
			depth++
		case ']':
			depth--
		default:
			if depth == 0 && strings.HasPrefix(expr[i:], op) {
				parts = append(parts, strings.TrimSpace(expr[last:i]))
				last = i + len(op)
				i += len(op) - 1
			}
		}
	}
	return append(parts, strings.TrimSpace(expr[last:]))
}

func evalTerm(term string, ctx map[string]string) bool {
	type rule struct{ sym, op string }
	rules := []rule{
		{" not contains ", "not_contains"},
		{" not in ", "not_in"},
		{" contains ", "contains"},
		{" >= ", "gte"},
		{" <= ", "lte"},
		{" == ", "eq"},
		{" != ", "ne"},
		{" in ", "in"},
		{" > ", "gt"},
		{" < ", "lt"},
	}
	for _, r := range rules {
		idx := strings.Index(term, r.sym)
		if idx < 0 {
			continue
		}
		field := strings.TrimSpace(term[:idx])
		rawVal := strings.TrimSpace(term[idx+len(r.sym):])
		fieldVal := ctx[field]
		return applyCondOp(fieldVal, r.op, rawVal)
	}
	return false
}

func applyCondOp(fieldVal, op, rawVal string) bool {
	val := condStripQuotes(rawVal)
	fv := strings.ToLower(fieldVal)
	v := strings.ToLower(val)

	switch op {
	case "eq":
		return fv == v
	case "ne":
		return fv != v
	case "contains":
		return strings.Contains(fv, v)
	case "not_contains":
		return !strings.Contains(fv, v)
	case "in":
		return condInList(fv, rawVal)
	case "not_in":
		return !condInList(fv, rawVal)
	case "gt", "gte", "lt", "lte":
		f, err1 := strconv.ParseFloat(fieldVal, 64)
		c, err2 := strconv.ParseFloat(val, 64)
		if err1 != nil || err2 != nil {
			return false
		}
		switch op {
		case "gt":
			return f > c
		case "gte":
			return f >= c
		case "lt":
			return f < c
		case "lte":
			return f <= c
		}
	}
	return false
}

func condInList(val, raw string) bool {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	for _, item := range strings.Split(raw, ",") {
		item = strings.ToLower(condStripQuotes(strings.TrimSpace(item)))
		if val == item {
			return true
		}
	}
	return false
}

func condStripQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// ── Template rendering ─────────────────────────────────────────────────────────

// buildAlertContext returns a map of alert fields usable in conditions and templates.
func buildAlertContext(alert models.Alert) map[string]string {
	return map[string]string{
		"severity":    alert.Severity,
		"rule_name":   alert.RuleName,
		"agent_id":    strconv.Itoa(alert.AgentID),
		"tenant_id":   strconv.Itoa(alert.TenantID),
		"log_message": alert.LogMessage,
		"log_sample":  truncate(alert.LogMessage, 200),
	}
}

// renderTemplate replaces {{alert.key}} placeholders in s with ctx values.
func renderTemplate(s string, ctx map[string]string) string {
	for key, val := range ctx {
		s = strings.ReplaceAll(s, "{{alert."+key+"}}", val)
	}
	return s
}

// renderPayload applies template substitution to a raw JSON payload.
func renderPayload(payload json.RawMessage, ctx map[string]string) json.RawMessage {
	if len(payload) == 0 {
		return payload
	}
	return json.RawMessage(renderTemplate(string(payload), ctx))
}

// ── Helpers ────────────────────────────────────────────────────────────────────

// groupByStepOrder groups actions into ordered slices where each inner slice
// shares the same step_order. The outer slice is ordered by step_order.
func groupByStepOrder(actions []models.PlaybookAction) [][]models.PlaybookAction {
	if len(actions) == 0 {
		return nil
	}
	var groups [][]models.PlaybookAction
	var cur []models.PlaybookAction
	curOrder := -1
	for _, a := range actions {
		if a.StepOrder != curOrder {
			if len(cur) > 0 {
				groups = append(groups, cur)
			}
			cur = []models.PlaybookAction{a}
			curOrder = a.StepOrder
		} else {
			cur = append(cur, a)
		}
	}
	if len(cur) > 0 {
		groups = append(groups, cur)
	}
	return groups
}

// mergePayload enriches an action's stored JSON payload with alert context fields.
// The action payload wins on key conflicts so explicit overrides are respected.
func mergePayload(actionPayload json.RawMessage, alert models.Alert) json.RawMessage {
	base := map[string]interface{}{
		"agent_id":   alert.AgentID,
		"rule_name":  alert.RuleName,
		"severity":   alert.Severity,
		"log_sample": truncate(alert.LogMessage, 200),
	}
	if len(actionPayload) > 0 && string(actionPayload) != "null" {
		var extra map[string]interface{}
		if err := json.Unmarshal(actionPayload, &extra); err == nil {
			for k, v := range extra {
				base[k] = v
			}
		}
	}
	merged, _ := json.Marshal(base)
	return merged
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
