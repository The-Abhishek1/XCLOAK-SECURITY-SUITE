package services

import (
	"fmt"
	"strings"

	"xcloak-ngfw/models"
)

// DetectThreats runs a log line through both the Sigma rule engine and
// the hardcoded detection heuristics. The Sigma engine covers user-defined
// rules; the heuristics catch common patterns even with no rules configured.
//
// Call order: Sigma first (user rules), then heuristics (built-in), then
// brute-force state machine (stateful across log lines).
func DetectThreats(log models.Log) {

	// 1. Sigma-lite engine (user-defined rules).
	EvaluateRules(log)

	message := strings.ToLower(log.LogMessage)

	// 2. Brute-force state machine — "failed password" increments the counter.
	if strings.Contains(message, "failed password") ||
		strings.Contains(message, "authentication failure") ||
		strings.Contains(message, "invalid user") {
		TrackFailedLogin(log.AgentID, log.LogMessage)
	}

	// Reset counter on successful authentication.
	if strings.Contains(message, "accepted password") ||
		strings.Contains(message, "accepted publickey") {
		ResetBruteForceState(log.AgentID)
	}

	// 3. Heuristic detections — complement Sigma for common cases.
	heuristics := []struct {
		trigger  string
		ruleName string
		severity string
	}{
		{"accepted password",    "Successful Login",      "low"},
		{"sudo:",                "Sudo Usage",            "medium"},
		{"useradd",              "New User Created",      "high"},
		{"/dev/tcp",             "Reverse Shell",         "critical"},
		{"bash -i",              "Reverse Shell",         "critical"},
		{"base64 -d",            "Base64 Encoded Command","high"},
		{"chmod 777",            "Suspicious Permission", "medium"},
		{"crontab -e",           "Cron Job Modified",     "medium"},
		{"authorized_keys",      "SSH Key Added",         "high"},
		{"wget http",            "Suspicious Download",   "medium"},
		{"curl http",            "Suspicious Download",   "medium"},
		{"rm -rf /",             "Destructive Command",   "critical"},
		{"passwd",               "Password Change",       "medium"},
		{"nmap",                 "Network Scan",          "high"},
		{"masscan",              "Network Scan",          "high"},
	}

	for _, h := range heuristics {

		if !strings.Contains(message, h.trigger) {
			continue
		}

		alert := models.Alert{
			AgentID:     log.AgentID,
			Severity:    h.severity,
			RuleName:    h.ruleName,
			LogMessage:  log.LogMessage,
			Fingerprint: fmt.Sprintf("%d-%s", log.AgentID, strings.ReplaceAll(h.ruleName, " ", "-")),
		}

		MapMITRE(&alert)
		CreateAlert(alert)
	}
}
