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
)

type WebhookPayload struct {
	Event     string         `json:"event"`
	Timestamp time.Time      `json:"timestamp"`
	Platform  string         `json:"platform"`
	Data      map[string]any `json:"data"`
}

// FireAlertWebhook sends a webhook for a new critical/high alert.
// Called asynchronously from CreateAlert.
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

	go deliverToAll("critical_alert", payload)
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
	go deliverToAll("incident_created", payload)
}

func deliverToAll(eventType string, payload WebhookPayload) {
	// Generic webhook
	deliverWebhook(eventType, payload)
	// Slack
	deliverSlack(payload)
}

func deliverWebhook(eventType string, payload WebhookPayload) {
	var config struct {
		URL    string   `json:"url"`
		Secret string   `json:"secret"`
		Events []string `json:"events"`
	}

	var configRaw []byte
	var enabled bool

	err := database.DB.QueryRow(
		`SELECT enabled, config FROM integrations WHERE name='webhook'`,
	).Scan(&enabled, &configRaw)

	if err != nil || !enabled {
		return
	}

	json.Unmarshal(configRaw, &config)

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
	})
}

func deliverSlack(payload WebhookPayload) {
	var config struct {
		WebhookURL          string `json:"webhook_url"`
		Channel             string `json:"channel"`
		MentionOnCritical   bool   `json:"mention_on_critical"`
	}

	var configRaw []byte
	var enabled bool

	err := database.DB.QueryRow(
		`SELECT enabled, config FROM integrations WHERE name='slack'`,
	).Scan(&enabled, &configRaw)

	if err != nil || !enabled {
		return
	}

	json.Unmarshal(configRaw, &config)

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
	})
}

func deliver(integration, eventType, url string, body []byte, headers map[string]string) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		logDelivery(integration, eventType, body, 0, false, err.Error())
		return
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		logDelivery(integration, eventType, body, 0, false, err.Error())
		return
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // drain body

	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	logDelivery(integration, eventType, body, resp.StatusCode, success, "")
}

func logDelivery(integration, eventType string, payload []byte, code int, success bool, errMsg string) {
	database.DB.Exec(`
		INSERT INTO webhook_deliveries (integration, event_type, payload, status_code, success, error_msg)
		VALUES ($1,$2,$3,$4,$5,$6)
	`, integration, eventType, payload, code, success, errMsg)
}

// GetIntegrations returns all integrations config.
func GetIntegrations() ([]map[string]any, error) {
	rows, err := database.DB.Query(`
		SELECT name, enabled, config, updated_at FROM integrations ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]any
	for rows.Next() {
		var name, updatedAt string
		var enabled bool
		var config []byte
		if err := rows.Scan(&name, &enabled, &config, &updatedAt); err == nil {
			var cfg map[string]any
			json.Unmarshal(config, &cfg)
			result = append(result, map[string]any{
				"name":       name,
				"enabled":    enabled,
				"config":     cfg,
				"updated_at": updatedAt,
			})
		}
	}
	return result, nil
}

// SaveIntegration upserts an integration config.
func SaveIntegration(name string, enabled bool, config map[string]any, updatedBy string) error {
	configJSON, _ := json.Marshal(config)
	_, err := database.DB.Exec(`
		INSERT INTO integrations (name, enabled, config, updated_by, updated_at)
		VALUES ($1,$2,$3,$4,now())
		ON CONFLICT (name) DO UPDATE SET
			enabled    = EXCLUDED.enabled,
			config     = EXCLUDED.config,
			updated_by = EXCLUDED.updated_by,
			updated_at = now()
	`, name, enabled, configJSON, updatedBy)
	return err
}

// GetWebhookDeliveries returns recent webhook delivery history.
func GetWebhookDeliveries() ([]map[string]any, error) {
	rows, err := database.DB.Query(`
		SELECT id, integration, event_type, status_code, success, error_msg, delivered_at
		FROM webhook_deliveries ORDER BY delivered_at DESC LIMIT 50
	`)
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
