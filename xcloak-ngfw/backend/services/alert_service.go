package services

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// alertIPRE extracts IPv4 addresses from alert log messages for threat intel lookup.
var alertIPRE = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

// enrichAlertWithThreatIntel looks up any src_ip found in the alert message
// against the tenant's IOC table (and the platform IOC table, tenant_id=0).
// If a match is found it appends a "[TI: ...]" annotation to the log message.
func enrichAlertWithThreatIntel(alert *models.Alert) {
	if alert.LogMessage == "" {
		return
	}
	// Only run on messages that contain an IP to avoid noise
	matches := alertIPRE.FindAllString(alert.LogMessage, 5)
	if len(matches) == 0 {
		return
	}

	tid := alert.TenantID
	if tid == 0 {
		tid = resolveAlertTenant(alert.AgentID)
	}

	for _, ip := range matches {
		if net.ParseIP(ip) == nil {
			continue
		}
		if isPrivateAlertIP(ip) {
			continue
		}
		var severity, description string
		err := database.DB.QueryRow(`
			SELECT severity, coalesce(description,'')
			FROM iocs
			WHERE indicator = $1
			  AND type = 'ip'
			  AND enabled = true
			  AND (tenant_id = $2 OR tenant_id = 0)
			ORDER BY tenant_id DESC
			LIMIT 1
		`, ip, tid).Scan(&severity, &description)
		if err != nil {
			continue
		}
		note := fmt.Sprintf(" [TI: ip=%s severity=%s %s]", ip, severity, description)
		if !strings.Contains(alert.LogMessage, "[TI:") {
			alert.LogMessage += note
		}
		// Escalate alert severity if TI says critical/high and current is lower
		if severityRank(severity) > severityRank(alert.Severity) {
			alert.Severity = severity
		}
	}
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func isPrivateAlertIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true
	}
	private := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}
	for _, cidr := range private {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(parsed) {
			return true
		}
	}
	return false
}

// userRE extracts a username from common syslog / Windows event patterns.
var userRE = regexp.MustCompile(
	`(?i)(?:for user |for |user[=: ]+|username[=: ]+|sAMAccountName=|account[=: ]+)([a-zA-Z0-9._\-]{2,64})\b`,
)

func extractUsernameFromLog(msg string) string {
	m := userRE.FindStringSubmatch(msg)
	if len(m) < 2 {
		return ""
	}
	u := m[1]
	// Ignore common noise words that get matched accidentally
	noise := map[string]bool{"root": false, "system": true, "null": true, "none": true, "n/a": true, "unknown": true}
	if noise[strings.ToLower(u)] {
		return ""
	}
	return u
}

func resolveAlertTenant(agentID int) int {
	var tid int
	database.DB.QueryRow(`SELECT tenant_id FROM agents WHERE id=$1`, agentID).Scan(&tid)
	return tid
}

// CreateAlert persists an alert then fires the full pipeline:
//  1. Suppression check — drop silently if rule matches
//  2. Prometheus counter increment
//  3. Kafka event publish
//  4. Broadcast to browser WebSocket clients (real-time bell)
//  5. Fire webhook/Slack integrations for critical/high
//  6. SOAR playbook matching
//  7. Incident correlation
//  8. Risk score recalculation
//  9. AI triage (async, critical/high only)
func CreateAlert(alert models.Alert) error {

	// LDAP identity enrichment — runs synchronously before save so the
	// enriched message is persisted to the DB and appears in all UIs.
	if username := extractUsernameFromLog(alert.LogMessage); username != "" {
		tid := alert.TenantID
		if tid == 0 {
			tid = resolveAlertTenant(alert.AgentID)
		}
		if tid > 0 {
			alert.LogMessage = EnrichAlertMessage(alert.LogMessage, username, tid)
		}
	}

	// Threat intel enrichment — auto-annotate any public IP in the alert message
	// with IOC context from the iocs table. Also escalates severity on TI match.
	enrichAlertWithThreatIntel(&alert)

	err := repositories.CreateAlert(alert)
	if err != nil {
		return err
	}

	// Prometheus — increment severity counter + per-detector breakdown.
	IncrementAlertCounter(strings.ToLower(alert.Severity))
	RecordDetectorAlert(alert.RuleName, alert.Severity)

	// Kafka — publish to xcloak.alerts topic.
	go func() {
		defer func() { recover() }()
		PublishAlert(alert)
	}()

	// Real-time browser notification.
	if broadcastFn != nil {
		go broadcastFn(alert)
	}

	// IOC auto-block if IOC rule matched.
	if strings.Contains(strings.ToLower(alert.RuleName), "ioc") {
		go func() {
		defer func() { recover() }()
		autoBlockIOC(alert)
	}()
	}

	// Webhook / Slack integrations.
	go func() {
		defer func() { recover() }()
		FireAlertWebhook(alert)
	}()

	// Enterprise integrations: PagerDuty, Teams, Jira, ServiceNow.
	go func() {
		defer func() { recover() }()
		FireEnterpriseIntegrations(alert)
	}()

	go func() {
		defer func() { recover() }()
		ExecutePlaybooks(alert)
	}()
	go func() {
		defer func() { recover() }()
		CorrelateAlert(alert)
	}()

	sev := strings.ToLower(alert.Severity)
	if sev == "critical" || sev == "high" {
		go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("[TriageAlert] recovered panic: %v\n", r)
			}
		}()
		TriageAlert(alert)
	}()

	// Email notifications for critical/high
	if sev == "critical" || sev == "high" {
		go func() {
			defer func() { recover() }()
			recipients := GetEmailRecipients(alert.Severity, alert.AgentID)
			if len(recipients) > 0 {
				if err := SendAlertEmail(alert, recipients); err != nil {
					fmt.Printf("[Email] Failed to send alert email: %v\n", err)
				}
			}
		}()
	}
	}

	CalculateRiskScore(alert.AgentID)

	return nil
}

// broadcastFn injected from main.go to avoid import cycles.
var broadcastFn func(models.Alert)

// RegisterBroadcastFn injects the WS notification broadcaster.
func RegisterBroadcastFn(fn func(models.Alert)) {
	broadcastFn = fn
}

func GetAlerts(tenantID int) ([]models.Alert, error) {
	return repositories.GetAlerts(tenantID)
}
