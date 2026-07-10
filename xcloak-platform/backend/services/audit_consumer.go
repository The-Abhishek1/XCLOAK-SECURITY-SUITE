package services

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"

	"xcloak-platform/database"
	"xcloak-platform/secrets"
)

// splunkConfigCache caches per-tenant Splunk configs to avoid a DB round-trip
// on every high-risk event. TTL is 2 minutes — stale enough to be invisible
// under normal load, short enough that a newly-added Splunk integration is
// visible within one token rotation window.
var (
	splunkCacheMu      sync.Mutex
	splunkCacheEntries []splunkEntry
	splunkCacheAt      time.Time
)

const splunkCacheTTL = 2 * time.Minute

type splunkEntry struct {
	tenantID int
	url      string
	token    string
	index    string
}

func loadSplunkConfigs() []splunkEntry {
	splunkCacheMu.Lock()
	defer splunkCacheMu.Unlock()

	if time.Since(splunkCacheAt) < splunkCacheTTL {
		return splunkCacheEntries
	}

	rows, err := database.DB.Query(`SELECT tenant_id, config FROM integrations WHERE name='splunk' AND enabled=true`)
	if err != nil {
		return splunkCacheEntries // return stale rather than nothing
	}
	defer rows.Close()

	var entries []splunkEntry
	for rows.Next() {
		var tenantID int
		var cfgRaw []byte
		if err := rows.Scan(&tenantID, &cfgRaw); err != nil {
			continue
		}
		var cfg struct {
			URL   string `json:"url"`
			Token string `json:"token"`
			Index string `json:"index"`
		}
		json.Unmarshal(cfgRaw, &cfg)
		if secrets.Enabled() {
			if v, ok := secrets.GetKV(integrationVaultPath(tenantID, "splunk"), "token"); ok {
				cfg.Token = v
			}
		}
		if cfg.URL == "" || cfg.Token == "" {
			continue
		}
		entries = append(entries, splunkEntry{tenantID, cfg.URL, cfg.Token, cfg.Index})
	}

	splunkCacheEntries = entries
	splunkCacheAt = time.Now()
	return entries
}

// highRiskAuditActions lists audit action codes that warrant immediate
// external notification (Splunk HEC stream, SIEM webhook) due to their
// security significance. Credential changes and access grants are in scope;
// routine operational actions are not.
var highRiskAuditActions = map[string]bool{
	"ROLE_CHANGE":          true,
	"INVITE_USER":          true,
	"DELETE_USER":          true,
	"DISABLE_2FA":          true,
	"RESET_2FA":            true,
	"PASSWORD_RESET":       true,
	"API_KEY_REVOKE":       true,
	"AGENT_TOKEN_ROTATED":  true,
	"SIGMA_RULE_DELETE":    true,
	"IOC_DELETE":           true,
	"THREAT_FEED_DELETE":   true,
	"INTEGRATION_SAVE":     true,
	"PERMISSION_CHANGE":    true,
}

// StartAuditConsumer reads from xcloak.audit and, for each event:
//   - Streams high-risk actions to Splunk HEC (if configured) so the SIEM
//     receives privileged-action events in real time rather than via scheduled
//     export.
//   - Logs all events at debug level for pipeline visibility.
func StartAuditConsumer() {
	defer logRecover("StartAuditConsumer")
	if !kafkaEnabled {
		return
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: kafkaBrokers,
		Topic:   TopicAudit,
		GroupID: "xcloak-audit-consumer",
	})
	defer reader.Close()

	slog.Info("kafka: audit consumer started", "topic", TopicAudit)

	for {
		msg, err := reader.ReadMessage(context.Background())
		KafkaAuditConsumerLag.Set(float64(reader.Stats().Lag))
		if err != nil {
			slog.Error("kafka: audit consumer read error", "err", err)
			continue
		}
		processAuditEvent(msg.Value, msg.Time.Unix())
	}
}

func processAuditEvent(raw []byte, ts int64) {
	defer logRecover("processAuditEvent")

	var envelope KafkaEvent
	if err := json.Unmarshal(raw, &envelope); err != nil {
		slog.Error("kafka: audit consumer bad envelope", "err", err)
		return
	}
	if envelope.EventType != "audit.logged" {
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		slog.Error("kafka: audit consumer bad payload", "err", err)
		return
	}

	action, _ := payload["action"].(string)
	details, _ := payload["details"].(string)
	username, _ := payload["username"].(string)

	slog.Debug("kafka: audit event", "action", action, "username", username)

	if !highRiskAuditActions[action] {
		return
	}

	slog.Info("kafka: high-risk audit action detected", "action", action, "username", username, "details", details)
	streamAuditToSplunk(action, details, username, ts)
}

// streamAuditToSplunk sends high-risk audit events to every tenant's Splunk
// HEC endpoint. Runs synchronously inside the consumer goroutine (each
// delivery is already async from the Kafka read loop's perspective).
// Tenant configs are loaded from a 2-minute in-process cache to avoid
// a DB round-trip on every event.
func streamAuditToSplunk(action, details, username string, ts int64) {
	for _, e := range loadSplunkConfigs() {
		event := map[string]any{
			"time":       ts,
			"sourcetype": "xcloak:audit",
			"index":      e.index,
			"event": map[string]any{
				"action":   action,
				"details":  details,
				"username": username,
				"platform": "XCloak Security Suite",
			},
		}
		body, err := json.Marshal(event)
		if err != nil {
			continue
		}
		deliver("splunk_audit", "audit."+action, e.url+"/services/collector/event", body, map[string]string{
			"Authorization": "Splunk " + e.token,
			"Content-Type":  "application/json",
		}, e.tenantID)
	}
}
