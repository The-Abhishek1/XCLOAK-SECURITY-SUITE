package services

import (
	"strings"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// CreateAlert persists an alert then:
//  1. Broadcasts to all connected browser WebSocket clients (real-time bell)
//  2. Fires SOAR playbook matching
//  3. Fires incident correlation
//  4. Recalculates agent risk score
//  5. AI-triages critical/high alerts (async)
func CreateAlert(alert models.Alert) error {

	err := repositories.CreateAlert(alert)
	if err != nil {
		return err
	}

	// Broadcast to browser notification WebSocket clients.
	// Import cycle avoided by calling through the api package interface.
	// We use a package-level function registered at startup.
	if broadcastFn != nil {
		go broadcastFn(alert)
	}

	go ExecutePlaybooks(alert)
	go CorrelateAlert(alert)

	sev := strings.ToLower(alert.Severity)
	if sev == "critical" || sev == "high" {
		go TriageAlert(alert)
	}

	CalculateRiskScore(alert.AgentID)

	return nil
}

// broadcastFn is set at startup by main.go to avoid import cycles
// between services and api packages.
var broadcastFn func(models.Alert)

// RegisterBroadcastFn is called from main.go to inject the WS broadcaster.
func RegisterBroadcastFn(fn func(models.Alert)) {
	broadcastFn = fn
}

func GetAlerts() ([]models.Alert, error) {
	return repositories.GetAlerts()
}
