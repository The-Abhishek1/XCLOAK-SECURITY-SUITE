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

// TriageAlert sends an alert to the LLM for analysis and stores the result.
// Non-blocking when called from CreateAlert — call as a goroutine.
func TriageAlert(alert models.Alert) {

	prompt := buildTriagePrompt(alert)

	response, err := CallLLM(prompt)
	if err != nil {
		fmt.Printf("AI triage failed for alert %d: %v\n", alert.ID, err)
		return
	}

	result := parseTriageJSON(response)

	database.DB.Exec(`
		UPDATE alerts
		SET ai_summary = $1, ai_action = $2, ai_triaged_at = $3
		WHERE id = $4
	`, result.Summary, result.RecommendedAction, time.Now(), alert.ID)

	fmt.Printf("AI triage complete for alert %d: %s\n", alert.ID, result.Summary)
}

// SummarizeIncident generates an AI narrative for an incident, scoped to
// tenantID so a caller can't summarize another tenant's incident by ID.
func SummarizeIncident(incidentID int, tenantID int) (*models.AIIncidentSummary, error) {

	incident, err := repositories.GetIncidentByID(fmt.Sprintf("%d", incidentID), tenantID)
	if err != nil {
		return nil, err
	}

	// FIX: GetIncidentEvents takes a string, not an int
	events, _ := repositories.GetIncidentEvents(fmt.Sprintf("%d", incidentID))
	alerts, _ := repositories.GetAllAlerts()

	var agentAlerts []models.Alert
	for _, a := range alerts {
		if a.AgentID == incident.AgentID {
			agentAlerts = append(agentAlerts, a)
			if len(agentAlerts) >= 10 {
				break
			}
		}
	}

	prompt := buildIncidentPrompt(*incident, events, agentAlerts)

	response, err := CallLLM(prompt)
	if err != nil {
		return nil, fmt.Errorf("LLM unavailable: %w", err)
	}

	summary := parseIncidentSummaryJSON(response)

	database.DB.Exec(`
		UPDATE incidents SET ai_summary = $1, ai_triaged_at = $2 WHERE id = $3
	`, summary.Summary, time.Now(), incidentID)

	return summary, nil
}

func buildTriagePrompt(alert models.Alert) string {

	return fmt.Sprintf(`You are an expert security analyst working with a SIEM platform called XCloak.

Analyze the following security alert and provide a structured triage assessment.

ALERT DETAILS:
- Rule Name: %s
- Severity: %s
- Agent ID: %d
- MITRE Tactic: %s
- MITRE Technique: %s
- Log Message: %s

Respond ONLY with a valid JSON object in exactly this format (no markdown, no backticks):
{
  "summary": "<2-3 sentence analyst assessment of what this alert means>",
  "severity": "<your severity assessment: critical|high|medium|low>",
  "recommended_action": "<specific concrete action the analyst should take>",
  "false_positive": <true or false>,
  "mitre_technique": "<MITRE technique ID if identifiable, e.g. T1078>",
  "tags": ["<tag1>", "<tag2>"]
}`,
		alert.RuleName,
		alert.Severity,
		alert.AgentID,
		alert.MitreTactic,
		alert.MitreTechnique,
		alert.LogMessage,
	)
}

func buildIncidentPrompt(incident models.Incident, events []models.IncidentEvent, alerts []models.Alert) string {

	eventLines := []string{}
	for _, e := range events {
		eventLines = append(eventLines, fmt.Sprintf("  [%s] %s: %s",
			e.EventType, e.CreatedAt.Format("15:04:05"), e.Details))
	}

	alertLines := []string{}
	for _, a := range alerts {
		alertLines = append(alertLines, fmt.Sprintf("  - [%s] %s: %s",
			a.Severity, a.RuleName, a.LogMessage))
	}

	return fmt.Sprintf(`You are an expert security analyst. Summarize the following security incident for an SOC team.

INCIDENT:
- Title: %s
- Severity: %s
- Status: %s
- Description: %s

TIMELINE EVENTS:
%s

RECENT AGENT ALERTS:
%s

Respond ONLY with valid JSON (no markdown, no backticks):
{
  "summary": "<3-4 sentence executive summary of the incident>",
  "timeline": ["<key event 1>", "<key event 2>", "<key event 3>"],
  "root_cause_hint": "<best hypothesis for root cause>",
  "recommended_steps": ["<step 1>", "<step 2>", "<step 3>"]
}`,
		incident.Title,
		incident.Severity,
		incident.Status,
		incident.Description,
		strings.Join(eventLines, "\n"),
		strings.Join(alertLines, "\n"),
	)
}

func parseTriageJSON(raw string) *models.AITriageResult {

	result := &models.AITriageResult{}

	cleaned := strings.TrimSpace(raw)
	cleaned = strings.TrimPrefix(cleaned, "```json")
	cleaned = strings.TrimPrefix(cleaned, "```")
	cleaned = strings.TrimSuffix(cleaned, "```")
	cleaned = strings.TrimSpace(cleaned)

	if err := json.Unmarshal([]byte(cleaned), result); err != nil {
		result.Summary = cleaned
		result.RecommendedAction = "Review alert manually"
	}

	return result
}

func parseIncidentSummaryJSON(raw string) *models.AIIncidentSummary {

	result := &models.AIIncidentSummary{}

	cleaned := strings.TrimSpace(raw)
	cleaned = strings.TrimPrefix(cleaned, "```json")
	cleaned = strings.TrimPrefix(cleaned, "```")
	cleaned = strings.TrimSuffix(cleaned, "```")
	cleaned = strings.TrimSpace(cleaned)

	if err := json.Unmarshal([]byte(cleaned), result); err != nil {
		result.Summary = cleaned
		result.RootCauseHint = "Unable to parse AI response"
	}

	return result
}
