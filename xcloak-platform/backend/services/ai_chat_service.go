package services

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

// ChatWithAssistant sends a user message to the AI with full platform context
// and returns the assistant's response plus the updated history.
func ChatWithAssistant(username, userMessage string, history []models.ChatMessage, tenantID int) (string, []models.ChatMessage, error) {

	context := buildPlatformContext(tenantID)

	historyStr := ""
	for _, m := range history {
		role := "User"
		if m.Role == "assistant" {
			role = "Assistant"
		}
		historyStr += role + ": " + m.Content + "\n"
	}

	prompt := "You are XCloak AI — an expert security operations assistant built into the XCloak Security Suite.\n" +
		"You have real-time access to the platform's current state (provided below).\n" +
		"Answer questions about the platform's security posture, help triage alerts, explain CVEs, and suggest remediation steps.\n" +
		"Be concise, specific, and actionable. Do not make up data not provided in the context.\n\n" +
		"=== PLATFORM CONTEXT ===\n" + context + "\n\n" +
		"=== CONVERSATION HISTORY ===\n" + historyStr + "\n" +
		"=== CURRENT QUESTION ===\n" +
		"User: " + userMessage + "\n\n" +
		"Assistant:"

	response, err := CallLLM(prompt)
	if err != nil {
		return "", history, err
	}

	// Append to history.
	now := time.Now()
	updated := append(history,
		models.ChatMessage{Role: "user",      Content: userMessage, Timestamp: now},
		models.ChatMessage{Role: "assistant", Content: response,    Timestamp: now},
	)

	// Persist history (keep last 20 messages to avoid token bloat).
	if len(updated) > 20 {
		updated = updated[len(updated)-20:]
	}
	persistChatHistory(username, tenantID, updated)

	return response, updated, nil
}

// GetChatHistory loads the saved chat session for a user, scoped to
// tenantID — usernames aren't guaranteed unique across tenants, so without
// this a user in one tenant could load another tenant's chat transcript.
func GetChatHistory(username string, tenantID int) ([]models.ChatMessage, error) {

	var messagesJSON []byte

	err := database.DB.QueryRow(`
		SELECT messages FROM ai_chat_sessions
		WHERE username = $1 AND tenant_id = $2
		ORDER BY updated_at DESC
		LIMIT 1
	`, username, tenantID).Scan(&messagesJSON)

	if err != nil {
		return []models.ChatMessage{}, nil // No history yet.
	}

	var messages []models.ChatMessage
	json.Unmarshal(messagesJSON, &messages)

	return messages, nil
}

// ClearChatHistory wipes the session for a user, scoped to tenantID.
func ClearChatHistory(username string, tenantID int) error {
	_, err := database.DB.Exec(`DELETE FROM ai_chat_sessions WHERE username = $1 AND tenant_id = $2`, username, tenantID)
	return err
}

func persistChatHistory(username string, tenantID int, messages []models.ChatMessage) {

	data, _ := json.Marshal(messages)

	database.DB.Exec(`
		INSERT INTO ai_chat_sessions (username, tenant_id, messages)
		VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING
	`, username, tenantID, data)

	database.DB.Exec(`
		UPDATE ai_chat_sessions
		SET messages = $1, updated_at = now()
		WHERE username = $2 AND tenant_id = $3
	`, data, username, tenantID)
}

// buildPlatformContext creates a concise snapshot of tenantID's platform
// state for AI context — scoped, since this is shown back to a specific
// logged-in user via the chat assistant, not an internal background job.
func buildPlatformContext(tenantID int) string {

	var lines []string

	// Agents
	agents, _ := repositories.GetAgents(tenantID)
	online := 0
	for _, a := range agents {
		if a.Status == "online" {
			online++
		}
	}
	lines = append(lines, fmt.Sprintf("Agents: %d total, %d online", len(agents), online))

	// Alerts
	alerts, _ := repositories.GetAlerts(tenantID)
	critCount := 0
	highCount := 0
	for _, a := range alerts {
		if a.Severity == "critical" {
			critCount++
		} else if a.Severity == "high" {
			highCount++
		}
	}
	lines = append(lines, fmt.Sprintf("Alerts: %d total (%d critical, %d high)", len(alerts), critCount, highCount))

	// Recent alerts (last 5)
	limit := 5
	if len(alerts) < limit {
		limit = len(alerts)
	}
	recentAlertLines := []string{}
	for _, a := range alerts[:limit] {
		recentAlertLines = append(recentAlertLines, fmt.Sprintf("  [%s] %s on agent #%d", a.Severity, a.RuleName, a.AgentID))
	}
	if len(recentAlertLines) > 0 {
		lines = append(lines, "Recent alerts:\n"+strings.Join(recentAlertLines, "\n"))
	}

	// Incidents
	incidents, _ := repositories.GetIncidents(tenantID)
	openInc := 0
	for _, i := range incidents {
		if i.Status == "open" || i.Status == "investigating" {
			openInc++
		}
	}
	lines = append(lines, fmt.Sprintf("Incidents: %d total, %d open", len(incidents), openInc))

	// Vulnerabilities
	vulns, _ := repositories.GetVulnerabilities(tenantID)
	critVulns := 0
	for _, v := range vulns {
		if v.Severity == "critical" {
			critVulns++
		}
	}
	lines = append(lines, fmt.Sprintf("Vulnerabilities: %d total (%d critical)", len(vulns), critVulns))

	// IOCs
	iocs, _ := repositories.GetIOCs(tenantID)
	lines = append(lines, fmt.Sprintf("IOCs in database: %d", len(iocs)))

	// FIM violations
	var fimViolations int
	database.DB.QueryRow(`SELECT COUNT(*) FROM fim_alerts WHERE created_at > now() - INTERVAL '24 hours' AND tenant_id=$1`, tenantID).Scan(&fimViolations)
	if fimViolations > 0 {
		lines = append(lines, fmt.Sprintf("FIM violations (last 24h): %d", fimViolations))
	}

	// YARA matches
	var yaraMatches int
	database.DB.QueryRow(`SELECT COUNT(*) FROM yara_matches WHERE created_at > now() - INTERVAL '24 hours' AND tenant_id=$1`, tenantID).Scan(&yaraMatches)
	if yaraMatches > 0 {
		lines = append(lines, fmt.Sprintf("YARA matches (last 24h): %d", yaraMatches))
	}

	// Playbook executions
	var playbookFired, playbookFailed int
	database.DB.QueryRow(`SELECT COUNT(*) FROM playbook_executions WHERE status='success' AND created_at > now() - INTERVAL '24 hours' AND tenant_id=$1`, tenantID).Scan(&playbookFired)
	database.DB.QueryRow(`SELECT COUNT(*) FROM playbook_executions WHERE status='failed' AND created_at > now() - INTERVAL '24 hours' AND tenant_id=$1`, tenantID).Scan(&playbookFailed)
	if playbookFired+playbookFailed > 0 {
		lines = append(lines, fmt.Sprintf("SOAR actions (last 24h): %d succeeded, %d failed", playbookFired, playbookFailed))
	}

	// Suppression stats
	var suppressedCount int
	database.DB.QueryRow(`SELECT COALESCE(SUM(match_count),0) FROM suppression_rules WHERE enabled=TRUE AND tenant_id=$1`, tenantID).Scan(&suppressedCount)
	if suppressedCount > 0 {
		lines = append(lines, fmt.Sprintf("Alerts suppressed by rules: %d", suppressedCount))
	}

	// Quarantined files
	var quarantineCount int
	database.DB.QueryRow(`SELECT COUNT(*) FROM quarantined_files WHERE tenant_id=$1`, tenantID).Scan(&quarantineCount)
	if quarantineCount > 0 {
		lines = append(lines, fmt.Sprintf("Files in quarantine: %d", quarantineCount))
	}

	// Agent health
	var unhealthyAgents int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM agent_health ah
		JOIN agents a ON a.id = ah.agent_id
		WHERE ah.health_status != 'healthy' AND a.tenant_id=$1
	`, tenantID).Scan(&unhealthyAgents)
	if unhealthyAgents > 0 {
		lines = append(lines, fmt.Sprintf("Unhealthy agents: %d", unhealthyAgents))
	}

	// Report time
	lines = append(lines, "Report time: "+time.Now().Format("2006-01-02 15:04 UTC"))

	return strings.Join(lines, "\n")
}
