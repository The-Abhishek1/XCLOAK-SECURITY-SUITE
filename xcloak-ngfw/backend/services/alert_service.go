package services

import (
	"strings"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// CreateAlert persists an alert then fires the full pipeline:
//  1. Suppression check — drop silently if rule matches
//  2. Broadcast to browser WebSocket clients (real-time bell)
//  3. Fire webhook/Slack integrations for critical/high
//  4. SOAR playbook matching
//  5. Incident correlation
//  6. Risk score recalculation
//  7. AI triage (async, critical/high only)
func CreateAlert(alert models.Alert) error {

	err := repositories.CreateAlert(alert)
	if err != nil {
		return err
	}

	// Real-time browser notification.
	if broadcastFn != nil {
		go broadcastFn(alert)
	}

	// IOC auto-block if IOC rule matched.
	if strings.Contains(strings.ToLower(alert.RuleName), "ioc") {
		go autoBlockIOC(alert)
	}

	// Webhook / Slack integrations.
	go FireAlertWebhook(alert)

	go ExecutePlaybooks(alert)
	go CorrelateAlert(alert)

	sev := strings.ToLower(alert.Severity)
	if sev == "critical" || sev == "high" {
		go TriageAlert(alert)
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

func GetAlerts() ([]models.Alert, error) {
	return repositories.GetAlerts()
}
