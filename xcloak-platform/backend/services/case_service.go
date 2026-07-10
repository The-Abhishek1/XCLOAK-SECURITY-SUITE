package services

import (
	"fmt"
	"time"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

func CreateCase(req models.Case, userID int, username string) (models.Case, error) {
	req.Status = "open"
	req.Phase = "identification"
	req.SLAHours = repositories.SLAHoursForSeverity(req.Severity)
	t := repositories.SLABreachTime(req.Severity)
	req.SLABreachAt = &t

	c, err := repositories.CreateCase(req)
	if err != nil {
		return c, err
	}

	repositories.AddCaseComment(models.CaseComment{
		CaseID:   c.ID,
		Username: "system",
		Body:     fmt.Sprintf("Case created by %s. SLA: %dh (breach at %s).", username, req.SLAHours, t.Format(time.RFC3339)),
		IsSystem: true,
	})
	return c, nil
}

func UpdateCase(req models.Case, username string) error {
	old, err := repositories.GetCaseByID(req.ID, req.TenantID)
	if err != nil {
		return err
	}

	if req.Status == "closed" && old.Status != "closed" && req.ClosedAt == nil {
		now := time.Now()
		req.ClosedAt = &now
	}

	if err := repositories.UpdateCase(req); err != nil {
		return err
	}

	// System comment on status/phase change
	if old.Status != req.Status || old.Phase != req.Phase {
		msg := fmt.Sprintf("%s changed status to %q (phase: %s).", username, req.Status, req.Phase)
		repositories.AddCaseComment(models.CaseComment{
			CaseID:   req.ID,
			Username: "system",
			Body:     msg,
			IsSystem: true,
		})
	}
	return nil
}

// StartSLAChecker runs every 5 minutes, marks breached cases and adds a system comment.
func StartSLAChecker() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cases, err := repositories.FindCasesBreachingSLA()
		if err != nil {
			continue
		}
		for _, c := range cases {
			repositories.MarkCaseSLABreached(c.ID)
			repositories.AddCaseComment(models.CaseComment{
				CaseID:   c.ID,
				Username: "system",
				Body:     fmt.Sprintf("⚠ SLA BREACH: %s case exceeded %dh SLA threshold.", c.Severity, repositories.SLAHoursForSeverity(c.Severity)),
				IsSystem: true,
			})
		}
	}
}

func BuildExecutiveMetrics(tenantID int) (models.ExecutiveMetrics, error) {
	var m models.ExecutiveMetrics

	open, critical, mttr, slaRate, err := repositories.GetCaseMetrics(tenantID)
	if err != nil {
		return m, err
	}
	m.OpenCases = open
	m.CriticalCases = critical
	m.MTTRHours = mttr
	m.SLAComplianceRate = slaRate

	m.MTTDHours, _ = repositories.GetMTTDHours(tenantID)
	m.AlertVolume, _ = repositories.GetAlertVolumeLast30Days(tenantID)
	m.CasesBySeverity, _ = repositories.GetCasesGrouped(tenantID, "severity")
	m.CasesByPhase, _ = repositories.GetCasesGrouped(tenantID, "phase")
	m.TopMITRETactics, _ = repositories.GetTopMITRETactics(tenantID)
	m.RiskTrend, _ = repositories.GetRiskTrend(tenantID)

	m.TotalAssets, m.CriticalAssets = repositories.GetAssetCounts(tenantID)

	// Online agents from agents table
	if agents, err := repositories.GetAgents(tenantID); err == nil {
		for _, a := range agents {
			if a.Status == "online" {
				m.OnlineAgents++
			}
		}
	}

	// Total alerts last 30 days
	for _, d := range m.AlertVolume {
		m.TotalAlerts += d.Count
	}
	if m.AlertVolume == nil {
		m.AlertVolume = []models.DailyCount{}
	}
	if m.CasesBySeverity == nil {
		m.CasesBySeverity = []models.LabelCount{}
	}
	if m.CasesByPhase == nil {
		m.CasesByPhase = []models.LabelCount{}
	}
	if m.TopMITRETactics == nil {
		m.TopMITRETactics = []models.LabelCount{}
	}
	if m.RiskTrend == nil {
		m.RiskTrend = []models.DailyScore{}
	}
	return m, nil
}
