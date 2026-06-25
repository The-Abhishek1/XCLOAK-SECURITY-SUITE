package services

import (
	"fmt"
	"strconv"
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
			evaluateEventCountRule(rule, alert, tenantID)
		case "temporal":
			evaluateTemporalRule(rule, alert, false, tenantID)
		case "temporal_ordered":
			evaluateTemporalRule(rule, alert, true, tenantID)
		default: // "simple", or empty for rows created before correlation_type existed
			if correlationRuleMatches(rule, alert) {
				fireCorrelationRule(rule, alert, "", tenantID, 0)
			}
		}
	}
}

// evaluateEventCountRule fires when this rule's own conditions have matched
// at least Threshold times for alert.AgentID within WindowMinutes — a
// generalized brute-force/threshold detector (e.g. "5+ failed logins in
// 10 minutes", but for any rule shape, not just auth). Alerts-only by
// design — see validateCorrelationRule, which rejects a non-"alert"
// SourceType on event_count rules so this stays consistent with
// CountRecentMatchingAlerts, which only ever queries the alerts table.
func evaluateEventCountRule(rule repositories.EnabledCorrelationRule, alert models.Alert, tenantID int) {
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
	fireCorrelationRule(rule, alert, detail, tenantID, count-rule.Threshold)
}

// evaluateTemporalRule fires when every stage has at least one match for
// alert.AgentID within WindowMinutes. Stages can now reference data beyond
// the alerts table (see stageMatchTime) — a chain like "recon alert" →
// "connects to an external IP" → "has a KEV vulnerability" is a much
// stronger attack-chain signal than alert-rule-name matching alone. When
// ordered is true, the earliest match for each stage must be in
// non-decreasing time order — a real multi-step attack chain, not just
// unrelated signals that happened to co-occur.
func evaluateTemporalRule(rule repositories.EnabledCorrelationRule, alert models.Alert, ordered bool, tenantID int) {
	if len(rule.Stages) < 2 {
		return // a temporal rule with fewer than 2 stages can't express a chain
	}

	// Cheap early exit only applies when every stage is alert-sourced — a
	// non-alert stage (vulnerability/network_connect/risk_score) reflects
	// state that this particular alert's rule_name can't rule out.
	if allStagesAlertSourced(rule.Stages) {
		matchesAnyStage := false
		for _, stage := range rule.Stages {
			if strings.Contains(strings.ToLower(alert.RuleName), strings.ToLower(stage.Pattern)) {
				matchesAnyStage = true
				break
			}
		}
		if !matchesAnyStage {
			return
		}
	}

	stageTimes := make([]time.Time, len(rule.Stages))
	for i, stage := range rule.Stages {
		t, found := stageMatchTime(alert.AgentID, stage.SourceType, stage.Pattern, rule.WindowMinutes)
		if !found {
			return // this stage hasn't happened within the window — no chain yet
		}
		stageTimes[i] = t
	}

	if ordered {
		for i := 1; i < len(stageTimes); i++ {
			if stageTimes[i].Before(stageTimes[i-1]) {
				return // stages happened, but not in the required order
			}
		}
	}

	detail := fmt.Sprintf("%d-stage %s chain matched within %dmin", len(rule.Stages), map[bool]string{true: "ordered", false: "unordered"}[ordered], rule.WindowMinutes)
	fireCorrelationRule(rule, alert, detail, tenantID, len(rule.Stages))
}

func allStagesAlertSourced(stages []repositories.CorrelationStage) bool {
	for _, s := range stages {
		if s.SourceType != "" && s.SourceType != "alert" {
			return false
		}
	}
	return true
}

// simpleCrossSourceLookbackMinutes bounds how far back a "simple" rule's
// non-alert condition looks — simple rules have no WindowMinutes concept
// (they're meant to be a single-alert-shaped check), so a cross-source
// condition needs *some* bound to avoid a vulnerability discovered months
// ago, or a risk score nobody has recomputed since, matching forever.
const simpleCrossSourceLookbackMinutes = 24 * 60

// stageMatchTime resolves whether sourceType/pattern has a match for
// agentID within windowMinutes, returning the earliest matching time.
// "alert" (the default) checks alert rule_names, same as before this
// function existed; the other three source types reach into data the
// correlation engine couldn't see at all until now.
func stageMatchTime(agentID int, sourceType, pattern string, windowMinutes int) (time.Time, bool) {
	switch sourceType {
	case "vulnerability":
		return vulnerabilityStageMatch(agentID, pattern, windowMinutes)
	case "network_connect":
		return networkConnectStageMatch(agentID, pattern, windowMinutes)
	case "risk_score":
		return riskScoreStageMatch(agentID, pattern, windowMinutes)
	default: // "alert" or ""
		return alertStageMatch(agentID, pattern, windowMinutes)
	}
}

func alertStageMatch(agentID int, pattern string, windowMinutes int) (time.Time, bool) {
	firstSeen, err := repositories.RecentRuleFirstSeen(agentID, windowMinutes)
	if err != nil {
		return time.Time{}, false
	}
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
	return earliest, found
}

func vulnerabilityStageMatch(agentID int, pattern string, windowMinutes int) (time.Time, bool) {
	vulns, err := repositories.GetVulnerabilitiesByAgentID(agentID)
	if err != nil {
		return time.Time{}, false
	}
	cutoff := time.Now().Add(-time.Duration(windowMinutes) * time.Minute)
	patternLower := strings.ToLower(strings.TrimSpace(pattern))

	var earliest time.Time
	found := false
	for _, v := range vulns {
		if v.DetectedAt.Before(cutoff) {
			continue
		}
		if !vulnerabilityMatchesPattern(v, patternLower) {
			continue
		}
		if !found || v.DetectedAt.Before(earliest) {
			earliest = v.DetectedAt
			found = true
		}
	}
	return earliest, found
}

// vulnerabilityMatchesPattern: "kev" → KEV-listed; "epss>=N" → EPSS score at
// or above N; blank → any vulnerability counts; anything else → CVE ID or
// package name substring.
func vulnerabilityMatchesPattern(v models.Vulnerability, patternLower string) bool {
	switch {
	case patternLower == "":
		return true
	case patternLower == "kev":
		return v.IsKEV
	case strings.HasPrefix(patternLower, "epss>="):
		threshold, err := strconv.ParseFloat(strings.TrimPrefix(patternLower, "epss>="), 64)
		return err == nil && v.EPSSScore >= threshold
	default:
		return strings.Contains(strings.ToLower(v.CVEID), patternLower) ||
			strings.Contains(strings.ToLower(v.PackageName), patternLower)
	}
}

// networkConnectStageLookback bounds how many recent connect events get
// scanned per agent — same reasoning as the network map's edge cap, just
// applied to a single agent's stream instead of the whole fleet.
const networkConnectStageLookback = 1000

func networkConnectStageMatch(agentID int, pattern string, windowMinutes int) (time.Time, bool) {
	events, err := repositories.GetConnectEventsByAgent(agentID, networkConnectStageLookback)
	if err != nil {
		return time.Time{}, false
	}
	cutoff := time.Now().Add(-time.Duration(windowMinutes) * time.Minute)
	patternLower := strings.ToLower(strings.TrimSpace(pattern))

	var earliest time.Time
	found := false
	for _, ev := range events {
		if ev.CreatedAt.Before(cutoff) {
			continue
		}
		if !networkConnectMatchesPattern(ev, patternLower) {
			continue
		}
		if !found || ev.CreatedAt.Before(earliest) {
			earliest = ev.CreatedAt
			found = true
		}
	}
	return earliest, found
}

// networkConnectMatchesPattern: "external"/"internal" → zone classification
// via the same isPrivateIP used by the network map and attack-path graph;
// blank → any real (non-listen-placeholder) connection counts; anything
// else → substring on the raw remote address.
func networkConnectMatchesPattern(ev models.ConnectEvent, patternLower string) bool {
	host := hostFromAddress(ev.RemoteAddress)
	if isListenPlaceholder(host) {
		return false
	}
	switch patternLower {
	case "":
		return true
	case "external":
		return !isPrivateIP(host)
	case "internal":
		return isPrivateIP(host)
	default:
		return strings.Contains(strings.ToLower(ev.RemoteAddress), patternLower)
	}
}

func riskScoreStageMatch(agentID int, pattern string, windowMinutes int) (time.Time, bool) {
	threshold, err := strconv.Atoi(strings.TrimSpace(pattern))
	if err != nil {
		return time.Time{}, false
	}
	score, err := repositories.GetRiskScore(strconv.Itoa(agentID))
	if err != nil || score.RiskScore < threshold {
		return time.Time{}, false
	}
	cutoff := time.Now().Add(-time.Duration(windowMinutes) * time.Minute)
	if score.UpdatedAt.Before(cutoff) {
		return time.Time{}, false // risk score hasn't been (re)computed within the window
	}
	return score.UpdatedAt, true
}

func correlationRuleMatches(rule repositories.EnabledCorrelationRule, alert models.Alert) bool {
	if rule.SourceType != "" && rule.SourceType != "alert" {
		_, found := stageMatchTime(alert.AgentID, rule.SourceType, rule.ConditionValue, simpleCrossSourceLookbackMinutes)
		return found
	}
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

// computeConfidence is a deterministic heuristic for how strong a match's
// evidence is — same spirit as attack_path_service.go's CompromiseCost.
// More stages, ordering, and cross-source evidence all raise confidence;
// it's a relative signal for triage, not a statistical probability. signal
// is contextual: how far an event_count match exceeded its threshold, or
// how many stages a temporal match satisfied — ignored for "simple".
func computeConfidence(rule repositories.EnabledCorrelationRule, signal int) int {
	switch rule.CorrelationType {
	case "event_count":
		confidence := 40 + signal*5 // signal = count - threshold, i.e. how far past the bar
		if confidence > 80 {
			confidence = 80
		}
		return confidence
	case "temporal", "temporal_ordered":
		confidence := 30 + signal*12 // signal = number of stages matched
		if rule.CorrelationType == "temporal_ordered" {
			confidence += 15
		}
		for _, s := range rule.Stages {
			if s.SourceType != "" && s.SourceType != "alert" {
				confidence += 10
				break
			}
		}
		if confidence > 95 {
			confidence = 95
		}
		return confidence
	default: // "simple"
		confidence := 50
		if rule.SourceType != "" && rule.SourceType != "alert" {
			confidence += 20
		} else {
			if rule.Severity != "" {
				confidence += 10
			}
			if rule.RuleName != "" {
				confidence += 10
			}
			if rule.MitreTechnique != "" {
				confidence += 10
			}
			if rule.AgentID != 0 {
				confidence += 10
			}
		}
		if confidence > 90 {
			confidence = 90
		}
		return confidence
	}
}

// fireCorrelationRule executes a matched rule's action. For windowed rule
// types (event_count/temporal/temporal_ordered), the incident fingerprint
// is bucketed by the rule's own window so the chain re-fires into a fresh
// incident once the window has fully rolled over, rather than either
// spamming a new incident on every contributing alert or silently merging
// into one incident forever. "simple" rules (no window) keep the original
// per-agent-per-rule fingerprint.
//
// A rule's PlaybookID (if set) fires independently of Action — a rule can
// both create_incident AND run a playbook; previously PlaybookID was
// stored/returned by the API but never read here, so setting it from the
// UI/API silently did nothing.
func fireCorrelationRule(rule repositories.EnabledCorrelationRule, alert models.Alert, detail string, tenantID int, signal int) {
	_ = repositories.IncrementCorrelationRuleMatchCount(rule.ID)

	var incidentID int
	switch rule.Action {
	case "create_incident":
		incidentID = fireCorrelationIncident(rule, alert, detail)
	case "notify":
		fireCorrelationNotification(rule, alert)
	}

	if rule.PlaybookID > 0 {
		if err := ExecutePlaybookByID(rule.PlaybookID, tenantID, alert); err != nil {
			fmt.Printf("correlation: playbook %d failed for rule %d: %v\n", rule.PlaybookID, rule.ID, err)
		}
	}

	match := models.CorrelationMatch{
		RuleID:     rule.ID,
		TenantID:   tenantID,
		AgentID:    alert.AgentID,
		Confidence: computeConfidence(rule, signal),
		Detail:     detail,
	}
	if alert.ID != 0 {
		aid := alert.ID
		match.TriggerAlertID = &aid
	}
	if incidentID != 0 {
		iid := incidentID
		match.IncidentID = &iid
	}
	_ = repositories.CreateCorrelationMatch(match)
}

func fireCorrelationIncident(rule repositories.EnabledCorrelationRule, alert models.Alert, detail string) int {
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
			return existingID
		}
		return 0
	}

	CreateIncidentEvent(models.IncidentEvent{
		IncidentID: incidentID,
		EventType:  "incident_opened",
		Details:    fmt.Sprintf("Auto-created by correlation rule #%d from alert: %s", rule.ID, alert.RuleName),
	})
	return incidentID
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
