package services

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// ChatWithAssistant sends a user message to the AI with full platform context
// and returns the assistant's response plus the updated history.
func ChatWithAssistant(username, userMessage string, history []models.ChatMessage) (string, []models.ChatMessage, error) {

	context := buildPlatformContext()

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
	persistChatHistory(username, updated)

	return response, updated, nil
}

// GetChatHistory loads the saved chat session for a user.
func GetChatHistory(username string) ([]models.ChatMessage, error) {

	var messagesJSON []byte

	err := database.DB.QueryRow(`
		SELECT messages FROM ai_chat_sessions
		WHERE username = $1
		ORDER BY updated_at DESC
		LIMIT 1
	`, username).Scan(&messagesJSON)

	if err != nil {
		return []models.ChatMessage{}, nil // No history yet.
	}

	var messages []models.ChatMessage
	json.Unmarshal(messagesJSON, &messages)

	return messages, nil
}

// ClearChatHistory wipes the session for a user.
func ClearChatHistory(username string) error {
	_, err := database.DB.Exec(`DELETE FROM ai_chat_sessions WHERE username = $1`, username)
	return err
}

func persistChatHistory(username string, messages []models.ChatMessage) {

	data, _ := json.Marshal(messages)

	database.DB.Exec(`
		INSERT INTO ai_chat_sessions (username, messages)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING
	`, username, data)

	database.DB.Exec(`
		UPDATE ai_chat_sessions
		SET messages = $1, updated_at = now()
		WHERE username = $2
	`, data, username)
}

// buildPlatformContext creates a concise snapshot of platform state for AI context.
func buildPlatformContext() string {

	var lines []string

	// Agents
	agents, _ := repositories.GetAgents()
	online := 0
	for _, a := range agents {
		if a.Status == "online" {
			online++
		}
	}
	lines = append(lines, fmt.Sprintf("Agents: %d total, %d online", len(agents), online))

	// Alerts
	alerts, _ := repositories.GetAlerts()
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
	incidents, _ := repositories.GetIncidents()
	openInc := 0
	for _, i := range incidents {
		if i.Status == "open" || i.Status == "investigating" {
			openInc++
		}
	}
	lines = append(lines, fmt.Sprintf("Incidents: %d total, %d open", len(incidents), openInc))

	// Vulnerabilities
	vulns, _ := repositories.GetAllVulnerabilities()
	critVulns := 0
	for _, v := range vulns {
		if v.Severity == "critical" {
			critVulns++
		}
	}
	lines = append(lines, fmt.Sprintf("Vulnerabilities: %d total (%d critical)", len(vulns), critVulns))

	// IOCs
	iocs, _ := repositories.GetIOCs()
	lines = append(lines, fmt.Sprintf("IOCs in database: %d", len(iocs)))

	// Timestamp
	lines = append(lines, "Report time: "+time.Now().Format("2006-01-02 15:04 UTC"))

	return strings.Join(lines, "\n")
}
