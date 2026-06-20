package services

import (
	"encoding/json"
	"fmt"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// FirewallSyncRule is the wire format sent to the agent.
// Mirrors models.FirewallRule but serialised cleanly.
type FirewallSyncRule struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`
	SourceIP      string `json:"source_ip"`
	DestinationIP string `json:"destination_ip"`
	Protocol      string `json:"protocol"` // tcp | udp | icmp | any
	Port          int    `json:"port"`      // 0 = any
	Action        string `json:"action"`    // allow | deny
	Priority      int    `json:"priority"`  // lower = evaluated first
}

// FirewallSyncPayload is the full task payload dispatched to each agent.
type FirewallSyncPayload struct {
	Rules       []FirewallSyncRule `json:"rules"`
	Mode        string             `json:"mode"`        // "replace" | "append"
	AllowManage string             `json:"allow_manage"` // mgmt IP to always whitelist
	SyncID      int64              `json:"sync_id"`
}

type SyncResult struct {
	AgentID    int    `json:"agent_id"`
	Hostname   string `json:"hostname"`
	TaskID     int    `json:"task_id"`
	RuleCount  int    `json:"rule_count"`
	Dispatched bool   `json:"dispatched"`
	Error      string `json:"error,omitempty"`
}

// SyncFirewallToAgents fetches tenantID's enabled rules, serialises them
// into a task payload, and dispatches an apply_firewall_rules task to every
// target — constrained to tenantID's own agents (both the "all online
// agents" fallback and any explicit targetAgentIDs), so one tenant can
// never push their firewall config onto (or wipe, in "replace" mode)
// another tenant's agents.
// targetAgentIDs: nil or empty = all online agents in tenantID.
func SyncFirewallToAgents(
	targetAgentIDs []int,
	mode string,         // "replace" | "append"
	manageIP string,     // XCloak server IP — always whitelisted
	syncedBy string,
	tenantID int,
) ([]SyncResult, error) {

	if mode == "" {
		mode = "replace"
	}

	if len(targetAgentIDs) > 0 {
		targetAgentIDs = filterAgentIDsByTenant(targetAgentIDs, tenantID)
	}

	// Fetch this tenant's enabled firewall rules ordered by priority.
	dbRules, err := repositories.GetRulesForTenant(tenantID)
	if err != nil {
		return nil, fmt.Errorf("fetch rules: %w", err)
	}

	var syncRules []FirewallSyncRule
	for _, r := range dbRules {
		if !r.Enabled {
			continue
		}
		syncRules = append(syncRules, FirewallSyncRule{
			ID:            r.ID,
			Name:          r.Name,
			SourceIP:      r.SourceIP,
			DestinationIP: r.DestinationIP,
			Protocol:      r.Protocol,
			Port:          r.Port,
			Action:        r.Action,
			Priority:      r.Priority,
		})
	}

	syncID := time.Now().UnixMilli()

	payload := FirewallSyncPayload{
		Rules:       syncRules,
		Mode:        mode,
		AllowManage: manageIP,
		SyncID:      syncID,
	}
	payloadJSON, _ := json.Marshal(payload)

	// Determine target agents — scoped to this tenant only.
	agents, err := repositories.GetAgents(tenantID)
	if err != nil {
		return nil, fmt.Errorf("fetch agents: %w", err)
	}

	wantAgent := map[int]bool{}
	for _, id := range targetAgentIDs {
		wantAgent[id] = true
	}

	var results []SyncResult

	for _, agent := range agents {
		// Skip offline agents unless explicitly targeted.
		if len(targetAgentIDs) > 0 && !wantAgent[agent.ID] {
			continue
		}
		if len(targetAgentIDs) == 0 && agent.Status != "online" {
			continue
		}

		res := SyncResult{
			AgentID:   agent.ID,
			Hostname:  agent.Hostname,
			RuleCount: len(syncRules),
		}

		// Dispatch task.
		taskErr := repositories.CreateTask(models.AgentTask{
			AgentID:  agent.ID,
			TaskType: "apply_firewall_rules",
			Payload:  payloadJSON,
		})

		if taskErr != nil {
			res.Error = taskErr.Error()
			results = append(results, res)
			continue
		}

		res.Dispatched = true

		// Log sync attempt.
		var logID int
		database.DB.QueryRow(`
			INSERT INTO firewall_sync_log (agent_id, rule_count, status, synced_by)
			VALUES ($1,$2,'dispatched',$3) RETURNING id
		`, agent.ID, len(syncRules), syncedBy).Scan(&logID)

		res.TaskID = logID
		results = append(results, res)
	}

	// Stamp rules as synced.
	database.DB.Exec(`UPDATE firewall_rules SET synced_at = now() WHERE enabled = TRUE AND tenant_id = $1`, tenantID)

	LogEvent(
		"FIREWALL_SYNC",
		fmt.Sprintf("Dispatched %d rules to %d agents (mode=%s)", len(syncRules), len(results), mode),
		syncedBy,
	)

	return results, nil
}

// GetFirewallSyncLog returns recent sync history for tenantID, optionally
// filtered to a single agent (still constrained to that tenant).
func GetFirewallSyncLog(agentID int, tenantID int) ([]map[string]any, error) {
	query := `
		SELECT l.id, l.agent_id, a.hostname, l.rule_count,
		       l.status, l.result, l.synced_by, l.synced_at
		FROM firewall_sync_log l
		JOIN agents a ON a.id = l.agent_id
		WHERE ($1 = 0 OR l.agent_id = $1) AND a.tenant_id = $2
		ORDER BY l.synced_at DESC
		LIMIT 50
	`
	rows, err := database.DB.Query(query, agentID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []map[string]any
	for rows.Next() {
		var id, agentId, ruleCount int
		var hostname, status, result, syncedBy, syncedAt string
		if err := rows.Scan(&id, &agentId, &hostname, &ruleCount,
			&status, &result, &syncedBy, &syncedAt); err == nil {
			logs = append(logs, map[string]any{
				"id": id, "agent_id": agentId, "hostname": hostname,
				"rule_count": ruleCount, "status": status, "result": result,
				"synced_by": syncedBy, "synced_at": syncedAt,
			})
		}
	}
	if logs == nil {
		logs = []map[string]any{}
	}
	return logs, nil
}
