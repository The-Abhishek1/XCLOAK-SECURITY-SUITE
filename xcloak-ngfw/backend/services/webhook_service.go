package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
	"xcloak-ngfw/secrets"
)

// integrationSecretFields lists, per integration name, which config keys
// hold credential material that belongs in Vault (when configured) rather
// than the integrations.config jsonb column: OIDC's client_secret, the
// webhook signing secret, and Slack's webhook URL (itself bearer-style
// credential material, not just an endpoint).
//
// When Vault is disabled these fields simply stay in the jsonb column,
// exactly as before Vault support existed — see splitIntegrationSecrets/
// mergeIntegrationSecrets below.
var integrationSecretFields = map[string][]string{
	"oidc":    {"client_secret"},
	"webhook": {"secret"},
	"slack":   {"webhook_url"},
}

func integrationVaultPath(tenantID int, name string) string {
	return fmt.Sprintf("xcloak/tenants/%d/integrations/%s", tenantID, name)
}

// mergeIntegrationSecrets fills name's secret fields into cfg from Vault.
// No-op if Vault is disabled (the fields are already in cfg in that case,
// read straight out of Postgres) or if nothing's been stored yet.
func mergeIntegrationSecrets(tenantID int, name string, cfg map[string]any) {
	if !secrets.Enabled() || len(integrationSecretFields[name]) == 0 {
		return
	}
	vaultData, ok := secrets.GetKVMap(integrationVaultPath(tenantID, name))
	if !ok {
		return
	}
	for _, f := range integrationSecretFields[name] {
		if v, ok := vaultData[f]; ok {
			cfg[f] = v
		}
	}
}

// splitIntegrationSecrets removes name's secret fields from cfg and writes
// them to Vault instead, so they never reach Postgres. No-op (fields stay
// in cfg, headed for Postgres as before) if Vault is disabled.
func splitIntegrationSecrets(tenantID int, name string, cfg map[string]any) error {
	fields := integrationSecretFields[name]
	if len(fields) == 0 || !secrets.Enabled() {
		return nil
	}
	vaultData := make(map[string]string, len(fields))
	for _, f := range fields {
		v, ok := cfg[f]
		if !ok {
			continue
		}
		if s, ok := v.(string); ok && s != "" {
			vaultData[f] = s
		}
		delete(cfg, f)
	}
	if len(vaultData) == 0 {
		return nil
	}
	return secrets.PutKV(integrationVaultPath(tenantID, name), vaultData)
}

type WebhookPayload struct {
	Event     string         `json:"event"`
	Timestamp time.Time      `json:"timestamp"`
	Platform  string         `json:"platform"`
	Data      map[string]any `json:"data"`
}

// FireAlertWebhook sends a webhook for a new critical/high alert, using the
// webhook/Slack config belonging to the tenant that owns alert.AgentID —
// without this, a tenant configuring their own Slack channel would also
// receive (or send) deliveries for every other tenant's alerts, since
// 'webhook'/'slack' integration rows are now per-tenant (see migration
// 000005). Called asynchronously from CreateAlert.
func FireAlertWebhook(alert models.Alert) {
	if alert.Severity != "critical" && alert.Severity != "high" {
		return
	}

	payload := WebhookPayload{
		Event:     "alert.created",
		Timestamp: time.Now(),
		Platform:  "XCloak Security Suite",
		Data: map[string]any{
			"id":              alert.ID,
			"severity":        alert.Severity,
			"rule_name":       alert.RuleName,
			"agent_id":        alert.AgentID,
			"mitre_technique": alert.MitreTechnique,
			"message":         alert.LogMessage,
		},
	}

	go deliverToAll("critical_alert", payload, alert.AgentID)
}

// FireIncidentWebhook sends a webhook when a new incident is created.
func FireIncidentWebhook(incident models.Incident) {
	payload := WebhookPayload{
		Event:     "incident.created",
		Timestamp: time.Now(),
		Platform:  "XCloak Security Suite",
		Data: map[string]any{
			"id":       incident.ID,
			"title":    incident.Title,
			"severity": incident.Severity,
			"agent_id": incident.AgentID,
		},
	}
	go deliverToAll("incident_created", payload, incident.AgentID)
}

// deliverToAll resolves the tenant from agentID once and uses it for both
// delivery channels.
func deliverToAll(eventType string, payload WebhookPayload, agentID int) {
	var tenantID int
	if err := database.DB.QueryRow(`SELECT tenant_id FROM agents WHERE id=$1`, agentID).Scan(&tenantID); err != nil {
		return
	}
	deliverToAllForTenant(eventType, payload, tenantID)
}

// deliverToAllForTenant is the tenant-known variant — used directly by the
// "test integration" button, which has no real agentID to resolve from.
func deliverToAllForTenant(eventType string, payload WebhookPayload, tenantID int) {
	// Generic webhook
	deliverWebhook(eventType, payload, tenantID)
	// Slack
	deliverSlack(payload, tenantID)
}

// FireTestWebhook sends a synthetic test event for tenantID, used by the
// "Test" button on the integrations settings page.
func FireTestWebhook(name string, tenantID int) {
	payload := WebhookPayload{
		Event:     "test." + name,
		Timestamp: time.Now(),
		Platform:  "XCloak Security Suite",
		Data: map[string]any{
			"severity":  "critical",
			"rule_name": "XCloak Test — " + name,
			"agent_id":  0,
			"message":   "This is a test event from XCloak Security Suite",
		},
	}
	deliverToAllForTenant("critical_alert", payload, tenantID)

	// For enterprise integration tests, fire a synthetic alert so the
	// per-integration deliver* functions are exercised end-to-end.
	switch name {
	case "pagerduty", "teams", "jira", "servicenow", "opsgenie", "datadog", "splunk":
		testAlert := models.Alert{
			TenantID:       tenantID,
			AgentID:        0,
			RuleName:       "XCloak Integration Test",
			Severity:       "critical",
			LogMessage:     "This is a test alert from XCloak Security Suite",
			MitreTechnique: "T0000",
			Fingerprint:    "test-" + name,
		}
		FireEnterpriseIntegrations(testAlert)
	}
}

func deliverWebhook(eventType string, payload WebhookPayload, tenantID int) {
	var config struct {
		URL    string   `json:"url"`
		Secret string   `json:"secret"`
		Events []string `json:"events"`
	}

	var configRaw []byte
	var enabled bool

	err := database.DB.QueryRow(
		`SELECT enabled, config FROM integrations WHERE name='webhook' AND tenant_id=$1`, tenantID,
	).Scan(&enabled, &configRaw)

	if err != nil || !enabled {
		return
	}

	json.Unmarshal(configRaw, &config)

	if secrets.Enabled() {
		if v, ok := secrets.GetKV(integrationVaultPath(tenantID, "webhook"), "secret"); ok {
			config.Secret = v
		}
	}

	if config.URL == "" {
		return
	}

	// Check if this event type is in the events list.
	if len(config.Events) > 0 {
		found := false
		for _, e := range config.Events {
			if e == eventType {
				found = true
				break
			}
		}
		if !found {
			return
		}
	}

	body, _ := json.Marshal(payload)
	deliver("webhook", eventType, config.URL, body, map[string]string{
		"Content-Type":     "application/json",
		"X-XCloak-Event":   eventType,
		"X-XCloak-Version": "1.0",
	}, tenantID)
}

func deliverSlack(payload WebhookPayload, tenantID int) {
	var config struct {
		WebhookURL          string `json:"webhook_url"`
		Channel             string `json:"channel"`
		MentionOnCritical   bool   `json:"mention_on_critical"`
	}

	var configRaw []byte
	var enabled bool

	err := database.DB.QueryRow(
		`SELECT enabled, config FROM integrations WHERE name='slack' AND tenant_id=$1`, tenantID,
	).Scan(&enabled, &configRaw)

	if err != nil || !enabled {
		return
	}

	json.Unmarshal(configRaw, &config)

	if secrets.Enabled() {
		if v, ok := secrets.GetKV(integrationVaultPath(tenantID, "slack"), "webhook_url"); ok {
			config.WebhookURL = v
		}
	}

	if config.WebhookURL == "" {
		return
	}

	severity, _ := payload.Data["severity"].(string)
	ruleName, _ := payload.Data["rule_name"].(string)
	agentID := payload.Data["agent_id"]

	icon := ":rotating_light:"
	if severity == "high" {
		icon = ":warning:"
	}

	mention := ""
	if config.MentionOnCritical && severity == "critical" {
		mention = "<!here> "
	}

	slackBody := map[string]any{
		"channel": config.Channel,
		"text": fmt.Sprintf(
			"%s%s *[%s]* %s — Agent #%v",
			mention, icon, severity, ruleName, agentID,
		),
	}

	body, _ := json.Marshal(slackBody)
	deliver("slack", payload.Event, config.WebhookURL, body, map[string]string{
		"Content-Type": "application/json",
	}, tenantID)
}

func deliver(integration, eventType, url string, body []byte, headers map[string]string, tenantID int) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		logDelivery(integration, eventType, body, 0, false, err.Error(), tenantID)
		return
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		logDelivery(integration, eventType, body, 0, false, err.Error(), tenantID)
		return
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // drain body

	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	logDelivery(integration, eventType, body, resp.StatusCode, success, "", tenantID)
}

func logDelivery(integration, eventType string, payload []byte, code int, success bool, errMsg string, tenantID int) {
	database.DB.Exec(`
		INSERT INTO webhook_deliveries (integration, event_type, payload, status_code, success, error_msg, tenant_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, integration, eventType, payload, code, success, errMsg, tenantID)
}

// knownIntegrations is the canonical list of supported integrations in the
// order they appear in the Settings UI. GetIntegrations always returns all of
// them — DB rows are merged in; unconfigured integrations get empty defaults.
var knownIntegrations = []string{
	"slack", "webhook", "email",
	"pagerduty", "teams", "jira", "servicenow",
	"opsgenie", "datadog", "splunk",
	"ldap", "oidc",
}

// GetIntegrations returns tenantID's integrations config.
// Every integration in knownIntegrations is always present in the result,
// even if it has never been configured (no DB row yet).
func GetIntegrations(tenantID int) ([]map[string]any, error) {
	rows, err := database.DB.Query(`
		SELECT name, enabled, config, updated_at FROM integrations WHERE tenant_id=$1
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Build a map of what's in the DB.
	dbRows := map[string]map[string]any{}
	for rows.Next() {
		var name, updatedAt string
		var enabled bool
		var config []byte
		if err := rows.Scan(&name, &enabled, &config, &updatedAt); err == nil {
			var cfg map[string]any
			json.Unmarshal(config, &cfg)
			if cfg == nil {
				cfg = map[string]any{}
			}
			mergeIntegrationSecrets(tenantID, name, cfg)
			dbRows[name] = map[string]any{
				"name":       name,
				"enabled":    enabled,
				"config":     cfg,
				"updated_at": updatedAt,
			}
		}
	}

	// Return all known integrations in canonical order, filling defaults for
	// any that have no DB row yet so the UI always renders every card.
	result := make([]map[string]any, 0, len(knownIntegrations))
	for _, name := range knownIntegrations {
		if row, ok := dbRows[name]; ok {
			result = append(result, row)
		} else {
			result = append(result, map[string]any{
				"name":       name,
				"enabled":    false,
				"config":     map[string]any{},
				"updated_at": "",
			})
		}
	}
	// Append any DB rows for integrations not in knownIntegrations (future ones).
	for name, row := range dbRows {
		known := false
		for _, k := range knownIntegrations {
			if k == name {
				known = true
				break
			}
		}
		if !known {
			result = append(result, row)
		}
	}
	return result, nil
}

// SaveIntegration upserts an integration config, scoped to tenantID — the
// ON CONFLICT target is (name, tenant_id) per migration 000005, not just
// name, so each tenant gets its own row instead of overwriting everyone
// else's.
func SaveIntegration(name string, enabled bool, config map[string]any, updatedBy string, tenantID int) error {
	if err := splitIntegrationSecrets(tenantID, name, config); err != nil {
		return err
	}
	configJSON, _ := json.Marshal(config)
	_, err := database.DB.Exec(`
		INSERT INTO integrations (name, enabled, config, updated_by, updated_at, tenant_id)
		VALUES ($1,$2,$3,$4,now(),$5)
		ON CONFLICT (name, tenant_id) DO UPDATE SET
			enabled    = EXCLUDED.enabled,
			config     = EXCLUDED.config,
			updated_by = EXCLUDED.updated_by,
			updated_at = now()
	`, name, enabled, configJSON, updatedBy, tenantID)
	return err
}

// GetWebhookDeliveries returns recent webhook delivery history for tenantID.
func GetWebhookDeliveries(tenantID int) ([]map[string]any, error) {
	rows, err := database.DB.Query(`
		SELECT id, integration, event_type, status_code, success, error_msg, delivered_at
		FROM webhook_deliveries WHERE tenant_id=$1 ORDER BY delivered_at DESC LIMIT 50
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]any
	for rows.Next() {
		var id, code int
		var integration, eventType, errMsg, deliveredAt string
		var success bool
		if err := rows.Scan(&id, &integration, &eventType, &code, &success, &errMsg, &deliveredAt); err == nil {
			result = append(result, map[string]any{
				"id": id, "integration": integration, "event_type": eventType,
				"status_code": code, "success": success, "error_msg": errMsg,
				"delivered_at": deliveredAt,
			})
		}
	}
	return result, nil
}
