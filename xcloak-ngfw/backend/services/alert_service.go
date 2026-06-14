package services

import (
	"strings"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// CreateAlert persists an alert then fires:
//  1. SOAR playbook matching
//  2. Incident correlation
//  3. Risk score recalculation
//  4. AI triage (async, critical/high only to save LLM cost)
func CreateAlert(alert models.Alert) error {

	err := repositories.CreateAlert(alert)
	if err != nil {
		return err
	}

	go ExecutePlaybooks(alert)
	go CorrelateAlert(alert)

	// Auto-triage high/critical alerts with AI if LLM is configured.
	sev := strings.ToLower(alert.Severity)
	if sev == "critical" || sev == "high" {
		go TriageAlert(alert)
	}

	CalculateRiskScore(alert.AgentID)

	return nil
}

func GetAlerts() ([]models.Alert, error) {
	return repositories.GetAlerts()
}
