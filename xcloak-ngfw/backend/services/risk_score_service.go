package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func CalculateRiskScore(
	agentID int,
) error {

	score := 0

	alerts, _ := repositories.GetAlertsByAgentID(agentID)

	for _, alert := range alerts {

		switch alert.Severity {

		case "critical":
			score += 20

		case "high":
			score += 10

		case "medium":
			score += 5

		case "low":
			score += 2
		}

		if alert.RuleName == "IOC Match" {
			score += 20
		}

		if alert.RuleName == "YARA Match" {
			score += 25
		}
	}

	vulns, _ := repositories.GetVulnerabilitiesByAgentID(agentID)

	for _, v := range vulns {
		// A vuln on CISA's confirmed-active-exploitation list is a far
		// bigger real-world risk than CVSS alone implies — weighted above
		// even the YARA/IOC match bonuses below.
		if v.IsKEV {
			score += 30
		} else if v.EPSSScore >= 0.5 {
			// EPSS >= 0.5 means FIRST.org predicts a coin-flip-or-better
			// chance of exploitation within 30 days — worth a smaller bump.
			score += 10
		}
	}

	incidents, _ := repositories.GetIncidentsByAgentID(agentID)

	for _, incident := range incidents {

		switch incident.Severity {

		case "critical":
			score += 30

		case "high":
			score += 15

		case "medium":
			score += 10
		}
	}

	level := "low"

	switch {

	case score >= 80:
		level = "critical"

	case score >= 50:
		level = "high"

	case score >= 20:
		level = "medium"
	}

	return repositories.UpsertRiskScore(
		models.AssetRiskScore{
			AgentID:   agentID,
			RiskScore: score,
			RiskLevel: level,
		},
	)
}
