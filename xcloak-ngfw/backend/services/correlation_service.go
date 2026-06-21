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

	// Custom rules run regardless of whether the built-in dedup below opens
	// an incident — a rule's action (create_incident / notify) is
	// independent of the built-in severity/IOC/YARA heuristic.
	EvaluateCorrelationRules(alert)

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

// EvaluateCorrelationRules tests every enabled custom correlation rule (see
// api/correlation_rules.go) against an incoming alert. This is what gives
// the Correlation Rules UI teeth — until this existed, rules could be
// created/toggled/deleted but nothing ever read them; only the hardcoded
// built-in dedup above ever fired.
//
// Semantics match what the UI documents: every non-empty condition on a
// rule must match for it to fire (AND), and a blank condition matches any
// value.
func EvaluateCorrelationRules(alert models.Alert) {
	tenantID, err := repositories.GetTenantIDByAgentID(alert.AgentID)
	if err != nil {
		return
	}

	rules, err := repositories.GetEnabledCorrelationRules(tenantID)
	if err != nil {
		return
	}

	for _, rule := range rules {
		if !correlationRuleMatches(rule, alert) {
			continue
		}

		_ = repositories.IncrementCorrelationRuleMatchCount(rule.ID)

		switch rule.Action {
		case "create_incident":
			fireCorrelationIncident(rule, alert)
		case "notify":
			fireCorrelationNotification(rule, alert)
		}
	}
}

func correlationRuleMatches(rule repositories.EnabledCorrelationRule, alert models.Alert) bool {
	if rule.Severity != "" && !strings.EqualFold(rule.Severity, alert.Severity) {
		return false
	}
	if rule.RuleName != "" && !strings.Contains(strings.ToLower(alert.RuleName), strings.ToLower(rule.RuleName)) {
		return false
	}
	if rule.MitreTechnique != "" && !strings.EqualFold(rule.MitreTechnique, alert.MitreTechnique) {
		return false
	}
	if rule.AgentID != 0 && rule.AgentID != alert.AgentID {
		return false
	}
	return true
}

func fireCorrelationIncident(rule repositories.EnabledCorrelationRule, alert models.Alert) {
	fingerprint := fmt.Sprintf("corr-rule-%d-%d", rule.ID, alert.AgentID)

	incidentID, err := CreateIncident(models.Incident{
		AgentID:     alert.AgentID,
		Title:       fmt.Sprintf("Correlation Rule Matched — Agent #%d", alert.AgentID),
		Severity:    alert.Severity,
		Description: fmt.Sprintf("Custom correlation rule #%d matched alert %q. %s", rule.ID, alert.RuleName, truncate(alert.LogMessage, 300)),
		Fingerprint: fingerprint,
	})
	if err != nil {
		existingID, lookupErr := repositories.GetIncidentIDByFingerprint(fingerprint)
		if lookupErr == nil && existingID > 0 {
			CreateIncidentEvent(models.IncidentEvent{
				IncidentID: existingID,
				EventType:  "alert_correlated",
				Details:    fmt.Sprintf("Correlation rule #%d re-fired: %s (severity=%s)", rule.ID, alert.RuleName, alert.Severity),
			})
		}
		return
	}

	CreateIncidentEvent(models.IncidentEvent{
		IncidentID: incidentID,
		EventType:  "incident_opened",
		Details:    fmt.Sprintf("Auto-created by correlation rule #%d from alert: %s", rule.ID, alert.RuleName),
	})
}

func fireCorrelationNotification(rule repositories.EnabledCorrelationRule, alert models.Alert) {
	recipients := GetEmailRecipients(alert.Severity, alert.AgentID)
	if len(recipients) == 0 {
		return
	}
	go func() {
		defer func() { recover() }()
		_ = SendAlertEmail(alert, recipients)
	}()
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
