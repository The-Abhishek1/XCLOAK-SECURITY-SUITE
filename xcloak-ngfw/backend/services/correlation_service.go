package services

import (
	"fmt"
	"strings"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// CorrelateAlert decides whether an alert should automatically open or update
// an incident. Rules:
//
//   - critical alerts  → always create/upsert an incident
//   - high alerts      → create/upsert an incident
//   - IOC/YARA matches → always create/upsert (regardless of severity)
//   - medium/low       → no automatic incident (analysts review alerts manually)
//
// Deduplication: we set a fingerprint on the incident so re-running the same
// rule on the same agent does not open duplicate incidents (the DB's unique
// constraint on incidents.fingerprint handles the upsert).
func CorrelateAlert(alert models.Alert) {

	if !shouldCreateIncident(alert) {
		return
	}

	title, description := incidentContext(alert)

	fingerprint := fmt.Sprintf("incident-%d-%s",
		alert.AgentID,
		strings.ReplaceAll(strings.ToLower(alert.RuleName), " ", "-"),
	)

	incidentID, err := CreateIncident(models.Incident{
		AgentID:     alert.AgentID,
		Title:       title,
		Severity:    alert.Severity,
		Description: description,
		Fingerprint: fingerprint,
	})

	if err != nil {
		// Unique constraint hit = incident already open. Add a timeline event
		// to the existing one so analysts can see the alert count grow.
		existingID, lookupErr := repositories.GetIncidentIDByFingerprint(fingerprint)
		if lookupErr == nil && existingID > 0 {
			CreateIncidentEvent(models.IncidentEvent{
				IncidentID: existingID,
				EventType:  "alert_correlated",
				Details: fmt.Sprintf("Alert re-fired: %s (severity=%s)",
					alert.RuleName, alert.Severity),
			})
		}
		return
	}

	// New incident — add opening event.
	CreateIncidentEvent(models.IncidentEvent{
		IncidentID: incidentID,
		EventType:  "incident_opened",
		Details:    fmt.Sprintf("Auto-created from alert: %s", alert.RuleName),
	})

	// Fire playbooks that listen for "incident_created".
	ExecutePlaybooks(models.Alert{
		AgentID:  alert.AgentID,
		RuleName: "incident_created",
		Severity: alert.Severity,
	})
}

func shouldCreateIncident(alert models.Alert) bool {
	switch strings.ToLower(alert.Severity) {
	case "critical", "high":
		return true
	}
	switch strings.ToLower(alert.RuleName) {
	case "ioc match", "yara match":
		return true
	}
	return false
}

func incidentContext(alert models.Alert) (title, description string) {

	switch strings.ToLower(alert.RuleName) {

	case "ioc match":
		title = fmt.Sprintf("IOC Detected on Agent #%d", alert.AgentID)
		description = "Threat intelligence IOC matched in network traffic or logs. " + alert.LogMessage

	case "yara match":
		title = fmt.Sprintf("YARA Rule Hit on Agent #%d", alert.AgentID)
		description = "YARA scan identified malicious pattern. " + alert.LogMessage

	default:
		title = fmt.Sprintf("%s — Agent #%d", alert.RuleName, alert.AgentID)
		description = fmt.Sprintf("Auto-created from %s alert (severity=%s). Log: %s",
			alert.RuleName, alert.Severity, truncate(alert.LogMessage, 300))
	}

	return title, description
}
