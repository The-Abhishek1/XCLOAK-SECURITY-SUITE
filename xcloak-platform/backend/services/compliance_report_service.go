package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

// GenerateComplianceReport builds a health snapshot scoped to tenantID,
// persists it to the DB, and returns the report with its ID.
func GenerateComplianceReport(reportType, generatedBy string, tenantID int) (*models.ComplianceReport, error) {

	summary, err := buildSummary(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to build report summary: %w", err)
	}

	summaryJSON, _ := json.Marshal(summary)

	title := reportTitle(reportType)

	var id int
	err = database.DB.QueryRow(`
		INSERT INTO compliance_reports (title, report_type, generated_by, summary, tenant_id)
		VALUES ($1,$2,$3,$4,$5) RETURNING id
	`, title, reportType, generatedBy, summaryJSON, tenantID).Scan(&id)

	if err != nil {
		return nil, err
	}

	LogEvent("GENERATE_REPORT", fmt.Sprintf("%s by %s", title, generatedBy), generatedBy)

	return &models.ComplianceReport{
		ID:          id,
		Title:       title,
		ReportType:  reportType,
		GeneratedBy: generatedBy,
		Summary:     summaryJSON,
		CreatedAt:   time.Now(),
	}, nil
}

// GetReports returns reports belonging to tenantID, newest first.
func GetReports(tenantID int) ([]models.ComplianceReport, error) {

	rows, err := database.DB.Query(`
		SELECT id, title, report_type, generated_by, summary, created_at
		FROM compliance_reports
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`, tenantID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []models.ComplianceReport
	for rows.Next() {
		var r models.ComplianceReport
		if err := rows.Scan(&r.ID, &r.Title, &r.ReportType, &r.GeneratedBy, &r.Summary, &r.CreatedAt); err == nil {
			reports = append(reports, r)
		}
	}

	return reports, nil
}

// GetReportByID fetches a single report, scoped to tenantID — a request
// for another tenant's report gets the same error as a nonexistent one.
func GetReportByID(id string, tenantID int) (*models.ComplianceReport, error) {

	var r models.ComplianceReport
	err := database.DB.QueryRow(`
		SELECT id, title, report_type, generated_by, summary, created_at
		FROM compliance_reports WHERE id=$1 AND tenant_id=$2
	`, id, tenantID).Scan(&r.ID, &r.Title, &r.ReportType, &r.GeneratedBy, &r.Summary, &r.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &r, nil
}

// DeleteReport removes a report by ID, scoped to tenantID.
func DeleteReport(id string, tenantID int) error {
	tag, err := database.DB.Exec(`DELETE FROM compliance_reports WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return errors.New("report not found")
	}
	return nil
}

// buildSummary collects metrics scoped to tenantID to build the report body.
func buildSummary(tenantID int) (*models.ComplianceSummary, error) {

	s := &models.ComplianceSummary{
		VulnsBySeverity:  make(map[string]int),
		AlertsBySeverity: make(map[string]int),
	}

	// Agents
	agents, _ := repositories.GetAgents(tenantID)
	s.TotalAgents = len(agents)
	for _, a := range agents {
		if a.Status == "online" {
			s.OnlineAgents++
		}
	}

	// Alerts
	alerts, _ := repositories.GetAlerts(tenantID)
	s.TotalAlerts = len(alerts)
	for _, a := range alerts {
		s.AlertsBySeverity[a.Severity]++
		if a.Severity == "critical" {
			s.CriticalAlerts++
		}
	}

	// Incidents
	incidents, _ := repositories.GetIncidents(tenantID)
	for _, i := range incidents {
		if i.Status == "open" || i.Status == "investigating" {
			s.OpenIncidents++
		}
	}
	// Recent incidents (top 5)
	limit := 5
	if len(incidents) < limit {
		limit = len(incidents)
	}
	for _, i := range incidents[:limit] {
		s.RecentIncidents = append(s.RecentIncidents, models.IncidentSummaryEntry{
			ID: i.ID, Title: i.Title, Severity: i.Severity, Status: i.Status,
		})
	}

	// Vulnerabilities
	vulns, _ := repositories.GetVulnerabilities(tenantID)
	s.TotalVulns = len(vulns)
	for _, v := range vulns {
		s.VulnsBySeverity[v.Severity]++
		if v.Severity == "critical" {
			s.CriticalVulns++
		}
	}

	// IOCs
	iocs, _ := repositories.GetIOCs(tenantID)
	s.TotalIOCs = len(iocs)

	// Rules
	sigmaRules, _ := repositories.GetRules(tenantID)
	s.SigmaRules = len(sigmaRules)
	yaraRules, _ := repositories.GetYaraRules(tenantID)
	s.YaraRules = len(yaraRules)

	// Top risk agents (up to 5)
	for _, a := range agents {
		score, err := repositories.GetRiskScore(fmt.Sprintf("%d", a.ID))
		if err != nil {
			continue
		}
		s.TopRiskAgents = append(s.TopRiskAgents, models.AgentRiskEntry{
			AgentID: a.ID, Hostname: a.Hostname,
			RiskScore: score.RiskScore, RiskLevel: score.RiskLevel,
		})
	}
	// Sort descending by risk score (simple bubble — small N).
	for i := 0; i < len(s.TopRiskAgents); i++ {
		for j := i + 1; j < len(s.TopRiskAgents); j++ {
			if s.TopRiskAgents[j].RiskScore > s.TopRiskAgents[i].RiskScore {
				s.TopRiskAgents[i], s.TopRiskAgents[j] = s.TopRiskAgents[j], s.TopRiskAgents[i]
			}
		}
	}
	if len(s.TopRiskAgents) > 5 {
		s.TopRiskAgents = s.TopRiskAgents[:5]
	}

	return s, nil
}

func reportTitle(reportType string) string {
	now := time.Now().Format("2006-01-02 15:04")
	switch reportType {
	case "vulnerability":
		return fmt.Sprintf("Vulnerability Assessment — %s", now)
	case "incident":
		return fmt.Sprintf("Incident Summary Report — %s", now)
	case "audit":
		return fmt.Sprintf("Audit Trail Export — %s", now)
	default:
		return fmt.Sprintf("Full Compliance Report — %s", now)
	}
}
