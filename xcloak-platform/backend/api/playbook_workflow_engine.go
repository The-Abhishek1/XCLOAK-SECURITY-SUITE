package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// A simplified real executor for the visual workflow builder's node/edge
// graph (pb_playbooks.workflow). It deliberately does not evaluate IF/LOOP/
// PARALLEL/WAIT/RETRY branching — logic and human-in-loop nodes are treated
// as pass-through waypoints, and every reachable action node is dispatched
// in graph order. Action nodes carry a single free-text `target` config
// field; actions that need a target but weren't given one, or that have no
// real backend capability anywhere in this codebase (Send Email, Create
// Ticket, Run Script, and the two-argument Quarantine File/Kill Process),
// are honestly reported as skipped rather than faked.

type pbWFNode struct {
	ID     string          `json:"id"`
	Type   string          `json:"type"`
	Label  string          `json:"label"`
	Config json.RawMessage `json:"config"`
}

type pbWFEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type pbWorkflow struct {
	Nodes []pbWFNode `json:"nodes"`
	Edges []pbWFEdge `json:"edges"`
}

type pbStepResult struct {
	Step       string `json:"step"`
	NodeType   string `json:"node_type"`
	Status     string `json:"status"` // ok | skipped | failed
	Message    string `json:"message"`
	DurationMs int64  `json:"duration_ms"`
}

// orderedNodes walks the graph starting from nodes with no incoming edge
// (trigger nodes in a well-formed workflow), following edges in the order
// they were authored. Falls back to raw node order when there are no
// edges yet (a freshly palette-populated workflow that hasn't been wired).
func orderedNodes(wf pbWorkflow) []pbWFNode {
	if len(wf.Edges) == 0 {
		return wf.Nodes
	}
	byID := map[string]pbWFNode{}
	hasIncoming := map[string]bool{}
	adj := map[string][]string{}
	for _, n := range wf.Nodes {
		byID[n.ID] = n
	}
	for _, e := range wf.Edges {
		adj[e.From] = append(adj[e.From], e.To)
		hasIncoming[e.To] = true
	}
	var roots []string
	for _, n := range wf.Nodes {
		if !hasIncoming[n.ID] {
			roots = append(roots, n.ID)
		}
	}
	if len(roots) == 0 {
		return wf.Nodes // cyclic or fully-connected — fall back to raw order
	}
	visited := map[string]bool{}
	var order []pbWFNode
	var visit func(id string)
	visit = func(id string) {
		if visited[id] {
			return
		}
		visited[id] = true
		if n, ok := byID[id]; ok {
			order = append(order, n)
		}
		for _, next := range adj[id] {
			visit(next)
		}
	}
	for _, r := range roots {
		visit(r)
	}
	return order
}

// dispatchPBAction performs (or, in dry-run mode, validates without
// mutating) a single action node. Returns ok/skipped/failed + a message.
func dispatchPBAction(tid int, label, target string, dryRun bool) (status, message string) {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "block ip":
		if target == "" {
			return "skipped", "no target IP configured on this node"
		}
		if dryRun {
			return "ok", fmt.Sprintf("would block IP %s", target)
		}
		if err := repositories.CreateIOC(models.IOC{Indicator: target, Type: "ip", Severity: "high", Description: "Blocked by playbook execution", Enabled: true}, tid); err != nil {
			return "failed", err.Error()
		}
		return "ok", fmt.Sprintf("blocked IP %s (real IOC created)", target)

	case "block domain":
		if target == "" {
			return "skipped", "no target domain configured on this node"
		}
		if dryRun {
			return "ok", fmt.Sprintf("would block domain %s", target)
		}
		if err := repositories.CreateIOC(models.IOC{Indicator: target, Type: "domain", Severity: "high", Description: "Blocked by playbook execution", Enabled: true}, tid); err != nil {
			return "failed", err.Error()
		}
		return "ok", fmt.Sprintf("blocked domain %s (real IOC created)", target)

	case "isolate endpoint":
		if target == "" {
			return "skipped", "no target hostname configured on this node"
		}
		var agentID int
		if err := database.DB.QueryRow(`SELECT id FROM agents WHERE tenant_id=$1 AND hostname ILIKE $2 LIMIT 1`, tid, target).Scan(&agentID); err != nil {
			return "skipped", fmt.Sprintf("no agent found with hostname '%s'", target)
		}
		if dryRun {
			return "ok", fmt.Sprintf("would queue isolate_host for agent %d", agentID)
		}
		payload, _ := json.Marshal(map[string]any{"reason": "playbook execution", "source": "pb_playbooks"})
		if err := repositories.CreateTaskPendingApproval(models.AgentTask{AgentID: agentID, TaskType: "isolate_host", Payload: payload}); err != nil {
			return "failed", err.Error()
		}
		return "ok", fmt.Sprintf("isolate_host queued for agent %d, pending approval", agentID)

	case "disable user":
		if target == "" {
			return "skipped", "no target username configured on this node"
		}
		if dryRun {
			var exists bool
			database.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM ad_users WHERE tenant_id=$1 AND sam_account ILIKE $2)`, tid, target).Scan(&exists)
			if !exists {
				return "skipped", fmt.Sprintf("no AD user found with sam_account '%s'", target)
			}
			return "ok", fmt.Sprintf("would disable AD user %s", target)
		}
		res, err := database.DB.Exec(`UPDATE ad_users SET is_enabled=false WHERE tenant_id=$1 AND sam_account ILIKE $2`, tid, target)
		if err != nil {
			return "failed", err.Error()
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return "skipped", fmt.Sprintf("no AD user found with sam_account '%s'", target)
		}
		return "ok", fmt.Sprintf("disabled AD user %s", target)

	case "reset password":
		if target == "" {
			return "skipped", "no target email/username configured on this node"
		}
		if dryRun {
			return "ok", fmt.Sprintf("would send password reset to %s", target)
		}
		if err := services.RequestPasswordReset(target); err != nil {
			return "failed", err.Error()
		}
		return "ok", fmt.Sprintf("password reset requested for %s", target)

	case "update firewall":
		if target == "" {
			return "skipped", "no target IP configured on this node"
		}
		if dryRun {
			return "ok", fmt.Sprintf("would add a deny rule for %s", target)
		}
		if _, err := database.DB.Exec(`
			INSERT INTO firewall_rules (tenant_id, name, source_ip, action, enabled, group_name, description, created_by)
			VALUES ($1,$2,$3,'deny',true,'playbook','Created by playbook execution','pb-engine')`,
			tid, fmt.Sprintf("Playbook block %s", target), target); err != nil {
			return "failed", err.Error()
		}
		return "ok", fmt.Sprintf("added deny firewall rule for %s", target)

	case "create report":
		return "ok", "report step logged"

	case "quarantine file", "kill process":
		return "skipped", "this action needs more than a single target field (host + file path / host + PID) — not supported by the simplified executor"

	case "send email", "create ticket", "run script":
		return "skipped", "no real integration exists for this action in this codebase"

	default:
		return "skipped", fmt.Sprintf("unrecognized action type %q", label)
	}
}

// runPBWorkflow walks the workflow graph and dispatches every reachable
// action node, stopping at the first non-automatic human-in-loop gate on a
// real (non-dry-run) execution — the simplified executor does not attempt
// to resume a workflow once a real approval is granted, so it honestly
// halts there rather than either blocking forever or skipping the gate.
// Used by both PostPBExecute (dryRun=false, real side effects, real
// pb_approvals rows) and PostPBDryRun (dryRun=true, read-only validation).
func runPBWorkflow(tid, pid int, execID, workflowJSON string, dryRun bool) (status string, steps []pbStepResult, durationS float64, failedStep string) {
	var wf pbWorkflow
	if err := json.Unmarshal([]byte(workflowJSON), &wf); err != nil || len(wf.Nodes) == 0 {
		return "failed", []pbStepResult{{Step: "workflow", NodeType: "error", Status: "failed", Message: "workflow has no nodes to execute"}}, 0, "workflow"
	}
	start := time.Now()
	status = "success"
	for _, n := range orderedNodes(wf) {
		stepStart := time.Now()
		label := n.Label
		if label == "" {
			label = n.Type
		}
		if n.Type == "human" {
			var cfg struct {
				Policy string `json:"policy"`
			}
			json.Unmarshal(n.Config, &cfg)
			if cfg.Policy != "" && cfg.Policy != "automatic" {
				if !dryRun {
					database.DB.Exec(`INSERT INTO pb_approvals (tenant_id,playbook_id,execution_id,action,policy,requestor) VALUES ($1,$2,$3,$4,$5,$6)`,
						tid, pid, execID, label, cfg.Policy, "pb-engine")
				}
				steps = append(steps, pbStepResult{Step: label, NodeType: n.Type, Status: "pending", Message: fmt.Sprintf("halted at approval gate (%s) — execution does not auto-resume once approved", cfg.Policy), DurationMs: time.Since(stepStart).Milliseconds()})
				status = "pending"
				durationS = time.Since(start).Seconds()
				return status, steps, durationS, failedStep
			}
		}
		if n.Type != "action" {
			steps = append(steps, pbStepResult{Step: label, NodeType: n.Type, Status: "passed", Message: "pass-through (branching logic not evaluated by the simplified executor)", DurationMs: time.Since(stepStart).Milliseconds()})
			continue
		}
		var cfg struct {
			Target string `json:"target"`
		}
		json.Unmarshal(n.Config, &cfg)
		st, msg := dispatchPBAction(tid, label, cfg.Target, dryRun)
		steps = append(steps, pbStepResult{Step: label, NodeType: n.Type, Status: st, Message: msg, DurationMs: time.Since(stepStart).Milliseconds()})
		if st == "failed" {
			status = "failed"
			if failedStep == "" {
				failedStep = label
			}
		}
	}
	durationS = time.Since(start).Seconds()
	return status, steps, durationS, failedStep
}
