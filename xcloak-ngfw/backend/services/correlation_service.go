package services

import (
	"fmt"
	"strings"
	"time"

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
		switch rule.CorrelationType {
		case "event_count":
			evaluateEventCountRule(rule, alert)
		case "temporal":
			evaluateTemporalRule(rule, alert, false)
		case "temporal_ordered":
			evaluateTemporalRule(rule, alert, true)
		default: // "simple", or empty for rows created before correlation_type existed
			if correlationRuleMatches(rule, alert) {
				fireCorrelationRule(rule, alert, "")
			}
		}
	}
}

// evaluateEventCountRule fires when this rule's own conditions have matched
// at least Threshold times for alert.AgentID within WindowMinutes — a
// generalized brute-force/threshold detector (e.g. "5+ failed logins in
// 10 minutes", but for any rule shape, not just auth).
func evaluateEventCountRule(rule repositories.EnabledCorrelationRule, alert models.Alert) {
	// Cheap early exit: this specific alert must itself match the rule's
	// conditions before it's worth running the windowed count query.
	if !correlationRuleMatches(rule, alert) {
		return
	}

	count, err := repositories.CountRecentMatchingAlerts(alert.AgentID, rule.Severity, rule.RuleName, rule.MitreTechnique, rule.WindowMinutes)
	if err != nil || count < rule.Threshold {
		return
	}

	detail := fmt.Sprintf("%d matching alerts within %dmin (threshold %d)", count, rule.WindowMinutes, rule.Threshold)
	fireCorrelationRule(rule, alert, detail)
}

// evaluateTemporalRule fires when every stage pattern has at least one
// matching alert for alert.AgentID within WindowMinutes. When ordered is
// true, the earliest match for each stage must be in non-decreasing time
// order — a real multi-step attack chain (e.g. recon, then exploitation,
// then persistence), not just unrelated alerts that happened to co-occur.
func evaluateTemporalRule(rule repositories.EnabledCorrelationRule, alert models.Alert, ordered bool) {
	if len(rule.Stages) < 2 {
		return // a temporal rule with fewer than 2 stages can't express a chain
	}

	// Cheap early exit: this alert must match at least one stage, otherwise
	// it can't be the event that completes the chain.
	matchesAnyStage := false
	for _, pattern := range rule.Stages {
		if strings.Contains(strings.ToLower(alert.RuleName), strings.ToLower(pattern)) {
			matchesAnyStage = true
			break
		}
	}
	if !matchesAnyStage {
		return
	}

	firstSeen, err := repositories.RecentRuleFirstSeen(alert.AgentID, rule.WindowMinutes)
	if err != nil {
		return
	}

	stageTimes := make([]time.Time, len(rule.Stages))
	for i, pattern := range rule.Stages {
		patternLower := strings.ToLower(pattern)
		var earliest time.Time
		found := false
		for ruleName, t := range firstSeen {
			if !strings.Contains(strings.ToLower(ruleName), patternLower) {
				continue
			}
			if !found || t.Before(earliest) {
				earliest = t
				found = true
			}
		}
		if !found {
			return // this stage hasn't happened within the window — no chain yet
		}
		stageTimes[i] = earliest
	}

	if ordered {
		for i := 1; i < len(stageTimes); i++ {
			if stageTimes[i].Before(stageTimes[i-1]) {
				return // stages happened, but not in the required order
			}
		}
	}

	detail := fmt.Sprintf("%d-stage %s chain matched within %dmin", len(rule.Stages), map[bool]string{true: "ordered", false: "unordered"}[ordered], rule.WindowMinutes)
	fireCorrelationRule(rule, alert, detail)
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

// fireCorrelationRule executes a matched rule's action. For windowed rule
// types (event_count/temporal/temporal_ordered), the incident fingerprint
// is bucketed by the rule's own window so the chain re-fires into a fresh
// incident once the window has fully rolled over, rather than either
// spamming a new incident on every contributing alert or silently merging
// into one incident forever. "simple" rules (no window) keep the original
// per-agent-per-rule fingerprint.
func fireCorrelationRule(rule repositories.EnabledCorrelationRule, alert models.Alert, detail string) {
	_ = repositories.IncrementCorrelationRuleMatchCount(rule.ID)

	switch rule.Action {
	case "create_incident":
		fireCorrelationIncident(rule, alert, detail)
	case "notify":
		fireCorrelationNotification(rule, alert)
	}
}

func fireCorrelationIncident(rule repositories.EnabledCorrelationRule, alert models.Alert, detail string) {
	fingerprint := fmt.Sprintf("corr-rule-%d-%d", rule.ID, alert.AgentID)
	if rule.WindowMinutes > 0 {
		bucket := time.Now().UTC().Truncate(time.Duration(rule.WindowMinutes) * time.Minute)
		fingerprint = fmt.Sprintf("%s-%s", fingerprint, bucket.Format(time.RFC3339))
	}

	description := fmt.Sprintf("Custom correlation rule #%d (%s) matched alert %q.", rule.ID, rule.CorrelationType, alert.RuleName)
	if detail != "" {
		description += " " + detail
	}
	description += " " + truncate(alert.LogMessage, 300)

	incidentID, err := CreateIncident(models.Incident{
		AgentID:     alert.AgentID,
		Title:       fmt.Sprintf("Correlation Rule Matched — Agent #%d", alert.AgentID),
		Severity:    alert.Severity,
		Description: description,
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
