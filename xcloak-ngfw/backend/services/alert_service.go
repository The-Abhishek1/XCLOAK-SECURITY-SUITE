package services

import (
	"fmt"
	"strings"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

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

	err := repositories.CreateAlert(alert)
	if err != nil {
		return err
	}

	// Prometheus — increment severity counter.
	IncrementAlertCounter(strings.ToLower(alert.Severity))

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
