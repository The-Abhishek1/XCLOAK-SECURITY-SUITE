package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func CalculateRiskScore(
	agentID int,
) error {

	score := 0

	alerts, _ := repositories.GetAlerts()

	for _, alert := range alerts {

		if alert.AgentID != agentID {
			continue
		}

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

	incidents, _ := repositories.GetIncidents()

	for _, incident := range incidents {

		if incident.AgentID != agentID {
			continue
		}

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
