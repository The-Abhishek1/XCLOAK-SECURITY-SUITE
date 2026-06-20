package services

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// RunAnomalyDetection analyses an agent's collected data for behavioural
// anomalies using the LLM. It checks processes, connections, and users,
// then persists any findings for review.
func RunAnomalyDetection(agentID int) ([]models.AnomalyFinding, error) {

	processes,   _ := repositories.GetProcessesByAgent(fmt.Sprintf("%d", agentID))
	connections, _ := repositories.GetConnectionsByAgent(fmt.Sprintf("%d", agentID))
	users,       _ := repositories.GetUsersByAgent(fmt.Sprintf("%d", agentID))

	prompt := buildAnomalyPrompt(agentID, processes, connections, users)

	response, err := CallLLM(prompt)
	if err != nil {
		return nil, fmt.Errorf("LLM unavailable for anomaly detection: %w", err)
	}

	findings := parseAnomalyJSON(agentID, response)

	// Persist findings.
	for _, f := range findings {
		saveAnomaly(f)
	}

	fmt.Printf("Anomaly detection: agent=%d findings=%d\n", agentID, len(findings))

	return findings, nil
}

// GetAnomalies returns recent anomaly findings for tenantID, optionally
// filtered to a single agent (still constrained to that tenant).
func GetAnomalies(agentID string, tenantID int) ([]models.AnomalyFinding, error) {

	var rows *sql.Rows
	var err error

	if agentID != "" {
		rows, err = database.DB.Query(`
			SELECT id, agent_id, finding_type, description, severity, raw_context, created_at
			FROM anomaly_findings
			WHERE agent_id = $1 AND tenant_id = $2
			ORDER BY created_at DESC
			LIMIT 50
		`, agentID, tenantID)
	} else {
		rows, err = database.DB.Query(`
			SELECT id, agent_id, finding_type, description, severity, raw_context, created_at
			FROM anomaly_findings
			WHERE tenant_id = $1
			ORDER BY created_at DESC
			LIMIT 100
		`, tenantID)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []models.AnomalyFinding
	for rows.Next() {
		var f models.AnomalyFinding
		if err := rows.Scan(&f.ID, &f.AgentID, &f.FindingType, &f.Description, &f.Severity, &f.RawContext, &f.CreatedAt); err == nil {
			findings = append(findings, f)
		}
	}

	return findings, nil
}

func buildAnomalyPrompt(agentID int, processes []models.Process, connections []models.Connection, users []models.Users) string {

	// Summarise to avoid huge prompts.
	procNames := make([]string, 0, len(processes))
	for _, p := range processes {
		procNames = append(procNames, p.ProcessName)
	}
	if len(procNames) > 30 {
		procNames = procNames[:30]
	}

	connSummary := make([]string, 0, len(connections))
	for _, c := range connections {
		if c.State == "ESTABLISHED" || c.State == "LISTEN" {
			connSummary = append(connSummary, fmt.Sprintf("%s %s->%s", c.Protocol, c.LocalAddress, c.RemoteAddress))
		}
		if len(connSummary) >= 20 {
			break
		}
	}

	userNames := make([]string, 0, len(users))
	for _, u := range users {
		userNames = append(userNames, fmt.Sprintf("%s (uid=%d, shell=%s)", u.Username, u.UID, u.Shell))
	}

	return fmt.Sprintf(`You are a security expert analyzing Linux endpoint data for behavioural anomalies.

AGENT ID: %d
TIMESTAMP: %s

RUNNING PROCESSES (sample):
%s

ACTIVE CONNECTIONS:
%s

SYSTEM USERS:
%s

Look for:
- Suspicious processes (crypto miners, reverse shells, password dumpers, recon tools)
- Unusual outbound connections (non-standard ports, TOR exits, known C2 patterns)
- Suspicious users (uid=0 shells, hidden accounts, unusual shells)
- Any combination suggesting lateral movement or persistence

Respond ONLY with valid JSON (no markdown, no backticks):
{
  "findings": [
    {
      "finding_type": "process|connection|user|volume",
      "description": "<clear description of the anomaly>",
      "severity": "critical|high|medium|low",
      "indicator": "<the specific process name, IP, or username that triggered this>"
    }
  ]
}

If no anomalies are found, return: {"findings": []}`,
		agentID,
		time.Now().Format("2006-01-02 15:04 UTC"),
		strings.Join(procNames, ", "),
		strings.Join(connSummary, "\n"),
		strings.Join(userNames, "\n"),
	)
}

func parseAnomalyJSON(agentID int, raw string) []models.AnomalyFinding {

	cleaned := strings.TrimSpace(raw)
	cleaned = strings.TrimPrefix(cleaned, "```json")
	cleaned = strings.TrimPrefix(cleaned, "```")
	cleaned = strings.TrimSuffix(cleaned, "```")
	cleaned = strings.TrimSpace(cleaned)

	var result struct {
		Findings []struct {
			FindingType string `json:"finding_type"`
			Description string `json:"description"`
			Severity    string `json:"severity"`
			Indicator   string `json:"indicator"`
		} `json:"findings"`
	}

	if err := json.Unmarshal([]byte(cleaned), &result); err != nil {
		return nil
	}

	var findings []models.AnomalyFinding
	for _, f := range result.Findings {
		ctx, _ := json.Marshal(map[string]string{"indicator": f.Indicator})
		findings = append(findings, models.AnomalyFinding{
			AgentID:     agentID,
			FindingType: f.FindingType,
			Description: f.Description,
			Severity:    f.Severity,
			RawContext:  ctx,
		})
	}

	return findings
}

func saveAnomaly(f models.AnomalyFinding) {

	database.DB.Exec(`
		INSERT INTO anomaly_findings (agent_id, finding_type, description, severity, raw_context, tenant_id)
		VALUES ($1,$2,$3,$4,$5, (SELECT tenant_id FROM agents WHERE id = $1))
	`, f.AgentID, f.FindingType, f.Description, f.Severity, f.RawContext)
}
