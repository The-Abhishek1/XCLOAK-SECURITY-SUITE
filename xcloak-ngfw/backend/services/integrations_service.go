package services

// Enterprise integrations — automatic alert/incident delivery to external
// ticketing, on-call, and communication systems.
//
// All integrations are configured per-tenant in the integrations table.
// Secret fields (API keys, tokens, URLs) are stored in Vault when available,
// falling back to the jsonb config column when Vault is not configured.
//
// Integration names (used as the `name` column in the integrations table):
//   pagerduty  — PagerDuty Events API v2
//   teams      — Microsoft Teams Incoming Webhook
//   jira       — Jira Cloud REST API (issue creation)
//   servicenow — ServiceNow REST API (incident creation)
//   opsgenie   — OpsGenie Alert API v2
//   datadog    — Datadog Events API v1
//   splunk     — Splunk HTTP Event Collector (HEC)

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
	"xcloak-ngfw/secrets"
)

func init() {
	// Register secret fields so Vault split/merge handles them automatically.
	integrationSecretFields["pagerduty"] = []string{"integration_key"}
	integrationSecretFields["teams"] = []string{"webhook_url"}
	integrationSecretFields["jira"] = []string{"api_token"}
	integrationSecretFields["servicenow"] = []string{"password"}
	integrationSecretFields["opsgenie"] = []string{"api_key"}
	integrationSecretFields["datadog"] = []string{"api_key"}
	integrationSecretFields["splunk"] = []string{"token"}
}

// FireEnterpriseIntegrations delivers alert notifications to all configured
// enterprise integrations for the tenant. Called from CreateAlert for
// critical and high severity events.
func FireEnterpriseIntegrations(alert models.Alert) {
	if alert.TenantID == 0 {
		// Resolve tenant from agent when not explicitly set.
		database.DB.QueryRow(`SELECT tenant_id FROM agents WHERE id=$1`, alert.AgentID).Scan(&alert.TenantID)
	}
	if alert.TenantID == 0 {
		return
	}

	go deliverPagerDuty(alert)
	go deliverTeams(alert)
	go deliverJira(alert)
	go deliverServiceNow(alert)
	go deliverOpsGenie(alert)
	go deliverDatadog(alert)
	go deliverSplunkHEC(alert)
}

// ── PagerDuty ─────────────────────────────────────────────────────────────────

func deliverPagerDuty(alert models.Alert) {
	cfg, ok := loadIntegrationConfig("pagerduty", alert.TenantID)
	if !ok {
		return
	}

	key, _ := cfg["integration_key"].(string)
	if secrets.Enabled() {
		if v, ok2 := secrets.GetKV(integrationVaultPath(alert.TenantID, "pagerduty"), "integration_key"); ok2 {
			key = v
		}
	}
	if key == "" {
		return
	}

	pdSev := map[string]string{
		"critical": "critical",
		"high":     "error",
		"medium":   "warning",
		"low":      "info",
	}[alert.Severity]
	if pdSev == "" {
		pdSev = "error"
	}

	body, _ := json.Marshal(map[string]any{
		"routing_key":  key,
		"event_action": "trigger",
		"dedup_key":    alert.Fingerprint,
		"payload": map[string]any{
			"summary":   fmt.Sprintf("[XCloak] %s — %s", alert.Severity, alert.RuleName),
			"severity":  pdSev,
			"source":    "xcloak-ngfw",
			"timestamp": time.Now().Format(time.RFC3339),
			"custom_details": map[string]any{
				"agent_id":        alert.AgentID,
				"rule_name":       alert.RuleName,
				"mitre_technique": alert.MitreTechnique,
				"message":         truncateStr(alert.LogMessage, 500),
			},
		},
	})

	deliverIntegration("pagerduty", "alert.created", "https://events.pagerduty.com/v2/enqueue",
		body, map[string]string{"Content-Type": "application/json"}, alert.TenantID)
}

// ── Microsoft Teams ───────────────────────────────────────────────────────────

func deliverTeams(alert models.Alert) {
	cfg, ok := loadIntegrationConfig("teams", alert.TenantID)
	if !ok {
		return
	}

	webhookURL, _ := cfg["webhook_url"].(string)
	if secrets.Enabled() {
		if v, ok2 := secrets.GetKV(integrationVaultPath(alert.TenantID, "teams"), "webhook_url"); ok2 {
			webhookURL = v
		}
	}
	if webhookURL == "" {
		return
	}

	color := map[string]string{
		"critical": "FF0000",
		"high":     "FF6600",
		"medium":   "FFAA00",
		"low":      "00AA00",
	}[alert.Severity]
	if color == "" {
		color = "999999"
	}

	// Adaptive Card format for Teams (modern format, replaces legacy connectors)
	card := map[string]any{
		"type":        "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content": map[string]any{
				"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
				"type":    "AdaptiveCard",
				"version": "1.4",
				"body": []map[string]any{
					{
						"type":   "TextBlock",
						"size":   "Medium",
						"weight": "Bolder",
						"text":   fmt.Sprintf("🚨 XCloak Alert — %s", strings.ToUpper(alert.Severity)),
						"color":  "Attention",
					},
					{
						"type": "FactSet",
						"facts": []map[string]string{
							{"title": "Rule", "value": alert.RuleName},
							{"title": "Severity", "value": alert.Severity},
							{"title": "Agent ID", "value": fmt.Sprintf("%d", alert.AgentID)},
							{"title": "MITRE", "value": alert.MitreTechnique},
						},
					},
					{
						"type":    "TextBlock",
						"text":    truncateStr(alert.LogMessage, 300),
						"wrap":    true,
						"spacing": "Small",
					},
				},
			},
		}},
	}
	_ = color // used in legacy connector format; kept for future

	body, _ := json.Marshal(card)
	deliverIntegration("teams", "alert.created", webhookURL,
		body, map[string]string{"Content-Type": "application/json"}, alert.TenantID)
}

// ── Jira ──────────────────────────────────────────────────────────────────────

func deliverJira(alert models.Alert) {
	cfg, ok := loadIntegrationConfig("jira", alert.TenantID)
	if !ok {
		return
	}

	baseURL, _ := cfg["base_url"].(string)   // e.g. "https://company.atlassian.net"
	email, _ := cfg["email"].(string)
	apiToken, _ := cfg["api_token"].(string)
	project, _ := cfg["project_key"].(string) // e.g. "SEC"
	issueType, _ := cfg["issue_type"].(string)

	if secrets.Enabled() {
		if v, ok2 := secrets.GetKV(integrationVaultPath(alert.TenantID, "jira"), "api_token"); ok2 {
			apiToken = v
		}
	}

	if baseURL == "" || email == "" || apiToken == "" || project == "" {
		return
	}
	if issueType == "" {
		issueType = "Bug"
	}

	// Map XCloak severity to Jira priority name
	priority := map[string]string{
		"critical": "Highest",
		"high":     "High",
		"medium":   "Medium",
		"low":      "Low",
	}[alert.Severity]
	if priority == "" {
		priority = "Medium"
	}

	description := fmt.Sprintf(
		"*XCloak Alert*\n\n"+
			"*Rule:* %s\n"+
			"*Severity:* %s\n"+
			"*Agent ID:* %d\n"+
			"*MITRE Technique:* %s\n\n"+
			"*Log Sample:*\n{code}%s{code}",
		alert.RuleName, alert.Severity, alert.AgentID,
		alert.MitreTechnique, truncateStr(alert.LogMessage, 1000),
	)

	payload := map[string]any{
		"fields": map[string]any{
			"project":     map[string]string{"key": project},
			"summary":     fmt.Sprintf("[XCloak] %s: %s (Agent #%d)", strings.ToUpper(alert.Severity), alert.RuleName, alert.AgentID),
			"issuetype":   map[string]string{"name": issueType},
			"priority":    map[string]string{"name": priority},
			"description": description,
			"labels":      []string{"xcloak", "security", alert.Severity},
		},
	}

	body, _ := json.Marshal(payload)
	url := strings.TrimRight(baseURL, "/") + "/rest/api/2/issue"

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		logDelivery("jira", "alert.created", body, 0, false, err.Error(), alert.TenantID)
		return
	}
	req.SetBasicAuth(email, apiToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logDelivery("jira", "alert.created", body, 0, false, err.Error(), alert.TenantID)
		return
	}
	defer resp.Body.Close()

	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	logDelivery("jira", "alert.created", body, resp.StatusCode, success, "", alert.TenantID)
}

// ── ServiceNow ────────────────────────────────────────────────────────────────

func deliverServiceNow(alert models.Alert) {
	cfg, ok := loadIntegrationConfig("servicenow", alert.TenantID)
	if !ok {
		return
	}

	instance, _ := cfg["instance"].(string)  // e.g. "company.service-now.com"
	username, _ := cfg["username"].(string)
	password, _ := cfg["password"].(string)

	if secrets.Enabled() {
		if v, ok2 := secrets.GetKV(integrationVaultPath(alert.TenantID, "servicenow"), "password"); ok2 {
			password = v
		}
	}

	if instance == "" || username == "" || password == "" {
		return
	}

	// ServiceNow impact/urgency → priority matrix (1=critical, 2=high, 3=medium, 4=low)
	impact := map[string]string{"critical": "1", "high": "2", "medium": "3", "low": "3"}[alert.Severity]
	urgency := map[string]string{"critical": "1", "high": "2", "medium": "2", "low": "3"}[alert.Severity]
	if impact == "" {
		impact = "3"
		urgency = "3"
	}

	payload := map[string]any{
		"short_description": fmt.Sprintf("[XCloak] %s: %s", strings.ToUpper(alert.Severity), alert.RuleName),
		"description": fmt.Sprintf(
			"XCloak Security Alert\n\nRule: %s\nSeverity: %s\nAgent ID: %d\nMITRE: %s\n\nLog Sample:\n%s",
			alert.RuleName, alert.Severity, alert.AgentID,
			alert.MitreTechnique, truncateStr(alert.LogMessage, 1000),
		),
		"impact":    impact,
		"urgency":   urgency,
		"category":  "Security",
		"subcategory": "Threat",
	}

	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://%s/api/now/table/incident", strings.TrimRight(instance, "/"))

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		logDelivery("servicenow", "alert.created", body, 0, false, err.Error(), alert.TenantID)
		return
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logDelivery("servicenow", "alert.created", body, 0, false, err.Error(), alert.TenantID)
		return
	}
	defer resp.Body.Close()

	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	logDelivery("servicenow", "alert.created", body, resp.StatusCode, success, "", alert.TenantID)
}

// ── OpsGenie ──────────────────────────────────────────────────────────────────

func deliverOpsGenie(alert models.Alert) {
	cfg, ok := loadIntegrationConfig("opsgenie", alert.TenantID)
	if !ok {
		return
	}

	apiKey, _ := cfg["api_key"].(string)
	if secrets.Enabled() {
		if v, ok2 := secrets.GetKV(integrationVaultPath(alert.TenantID, "opsgenie"), "api_key"); ok2 {
			apiKey = v
		}
	}
	if apiKey == "" {
		return
	}

	priority := map[string]string{
		"critical": "P1",
		"high":     "P2",
		"medium":   "P3",
		"low":      "P4",
	}[alert.Severity]
	if priority == "" {
		priority = "P3"
	}

	responders := []map[string]string{}
	if team, _ := cfg["team"].(string); team != "" {
		responders = []map[string]string{{"name": team, "type": "team"}}
	}

	body, _ := json.Marshal(map[string]any{
		"message": truncateStr(
			fmt.Sprintf("[XCloak] %s — %s", strings.ToUpper(alert.Severity), alert.RuleName), 130),
		"alias": alert.Fingerprint,
		"description": fmt.Sprintf(
			"Rule: %s\nSeverity: %s\nAgent ID: %d\nMITRE: %s\n\nLog:\n%s",
			alert.RuleName, alert.Severity, alert.AgentID,
			alert.MitreTechnique, truncateStr(alert.LogMessage, 1000)),
		"priority":   priority,
		"source":     "xcloak-ngfw",
		"tags":       []string{"xcloak", "security", alert.Severity},
		"responders": responders,
	})

	deliverIntegration("opsgenie", "alert.created", "https://api.opsgenie.com/v2/alerts",
		body, map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "GenieKey " + apiKey,
		}, alert.TenantID)
}

// ── Datadog ───────────────────────────────────────────────────────────────────

func deliverDatadog(alert models.Alert) {
	cfg, ok := loadIntegrationConfig("datadog", alert.TenantID)
	if !ok {
		return
	}

	apiKey, _ := cfg["api_key"].(string)
	if secrets.Enabled() {
		if v, ok2 := secrets.GetKV(integrationVaultPath(alert.TenantID, "datadog"), "api_key"); ok2 {
			apiKey = v
		}
	}
	if apiKey == "" {
		return
	}

	site, _ := cfg["site"].(string)
	if site == "" {
		site = "datadoghq.com"
	}

	alertType := map[string]string{
		"critical": "error",
		"high":     "error",
		"medium":   "warning",
		"low":      "info",
	}[alert.Severity]
	if alertType == "" {
		alertType = "warning"
	}

	body, _ := json.Marshal(map[string]any{
		"title": fmt.Sprintf("[XCloak] %s: %s", strings.ToUpper(alert.Severity), alert.RuleName),
		"text": "%%% \n**Rule:** " + alert.RuleName +
			"\n**Severity:** " + alert.Severity +
			"\n**Agent:** " + fmt.Sprintf("%d", alert.AgentID) +
			"\n**MITRE:** " + alert.MitreTechnique +
			"\n\n```\n" + truncateStr(alert.LogMessage, 500) + "\n```\n %%%",
		"priority":         "normal",
		"alert_type":       alertType,
		"source_type_name": "XCLOAK",
		"tags": []string{
			"platform:xcloak",
			"severity:" + alert.Severity,
			fmt.Sprintf("agent_id:%d", alert.AgentID),
		},
	})

	deliverIntegration("datadog", "alert.created",
		fmt.Sprintf("https://api.%s/api/v1/events", site),
		body, map[string]string{
			"Content-Type": "application/json",
			"DD-API-KEY":   apiKey,
		}, alert.TenantID)
}

// ── Splunk HEC ────────────────────────────────────────────────────────────────

func deliverSplunkHEC(alert models.Alert) {
	cfg, ok := loadIntegrationConfig("splunk", alert.TenantID)
	if !ok {
		return
	}

	hecURL, _ := cfg["url"].(string)
	token, _ := cfg["token"].(string)
	if secrets.Enabled() {
		if v, ok2 := secrets.GetKV(integrationVaultPath(alert.TenantID, "splunk"), "token"); ok2 {
			token = v
		}
	}
	if hecURL == "" || token == "" {
		return
	}

	payload := map[string]any{
		"time":       time.Now().Unix(),
		"source":     "xcloak",
		"sourcetype": "xcloak:alert",
		"event": map[string]any{
			"severity":        alert.Severity,
			"rule_name":       alert.RuleName,
			"agent_id":        alert.AgentID,
			"mitre_technique": alert.MitreTechnique,
			"mitre_tactic":    alert.MitreTactic,
			"fingerprint":     alert.Fingerprint,
			"message":         truncateStr(alert.LogMessage, 1000),
		},
	}
	if index, _ := cfg["index"].(string); index != "" {
		payload["index"] = index
	}

	body, _ := json.Marshal(payload)
	url := strings.TrimRight(hecURL, "/") + "/services/collector/event"
	deliverIntegration("splunk", "alert.created", url,
		body, map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Splunk " + token,
		}, alert.TenantID)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func loadIntegrationConfig(name string, tenantID int) (map[string]any, bool) {
	var configRaw []byte
	var enabled bool
	err := database.DB.QueryRow(
		`SELECT enabled, config FROM integrations WHERE name=$1 AND tenant_id=$2`, name, tenantID,
	).Scan(&enabled, &configRaw)
	if err != nil || !enabled {
		return nil, false
	}
	var cfg map[string]any
	if json.Unmarshal(configRaw, &cfg) != nil || cfg == nil {
		return map[string]any{}, true
	}
	mergeIntegrationSecrets(tenantID, name, cfg)
	return cfg, true
}

func deliverIntegration(name, eventType, url string, body []byte, headers map[string]string, tenantID int) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		logDelivery(name, eventType, body, 0, false, err.Error(), tenantID)
		return
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		logDelivery(name, eventType, body, 0, false, err.Error(), tenantID)
		return
	}
	defer resp.Body.Close()
	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	logDelivery(name, eventType, body, resp.StatusCode, success, "", tenantID)
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
