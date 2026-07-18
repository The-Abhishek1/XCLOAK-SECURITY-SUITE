package repositories

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// In-memory routing caches so the hot syslog/HTTP paths don't hit Postgres
// on every packet. Invalidated on create/delete. TTL isn't needed — the
// worst case is a stale entry after a delete; that source simply gets
// dropped on the next packet if DB re-confirms it's gone.
var (
	sourceByIP  sync.Map // ip string → *models.LogSource
	sourceByKey sync.Map // sha256(apiKey) → *models.LogSource
)

// GetLogSourceByIP looks up a registered syslog source by device IP.
// Falls back to the first enabled wildcard source (ip_address IS NULL).
// Returns nil if no enabled source matches.
func GetLogSourceByIP(ip string) *models.LogSource {
	if v, ok := sourceByIP.Load(ip); ok {
		return v.(*models.LogSource)
	}
	src := queryLogSource(`WHERE ip_address = $1::inet AND source_type='syslog' AND enabled = true LIMIT 1`, ip)
	if src == nil {
		// Wildcard: sources with no IP match any sender.
		src = queryLogSource(`WHERE ip_address IS NULL AND source_type='syslog' AND enabled = true LIMIT 1`)
	}
	if src != nil {
		sourceByIP.Store(ip, src)
	}
	return src
}

// GetLogSourceByAPIKey looks up an HTTP log source by the SHA-256 hash of
// the submitted key. Returns nil if no enabled source matches.
func GetLogSourceByAPIKey(keyHash string) *models.LogSource {
	if v, ok := sourceByKey.Load(keyHash); ok {
		return v.(*models.LogSource)
	}
	src := queryLogSource(`WHERE api_key = $1 AND enabled = true LIMIT 1`, keyHash)
	if src != nil {
		sourceByKey.Store(keyHash, src)
	}
	return src
}

func queryLogSource(where string, args ...interface{}) *models.LogSource {
	var src models.LogSource
	var agentID *int
	var ipStr, deviceType, format, sourceType, apiKeyHint *string
	var lastEvent *time.Time

	q := `SELECT id, tenant_id, name, source_type, ip_address::text, format, device_type,
	             agent_id, enabled, last_event, event_count, api_key_hint, created_at
	      FROM log_sources ` + where
	err := database.DB.QueryRow(q, args...).Scan(
		&src.ID, &src.TenantID, &src.Name, &sourceType, &ipStr, &format, &deviceType,
		&agentID, &src.Enabled, &lastEvent, &src.EventCount, &apiKeyHint, &src.CreatedAt,
	)
	if err != nil {
		return nil
	}
	if ipStr != nil {
		src.IPAddress = *ipStr
	}
	if format != nil {
		src.Format = *format
	}
	if deviceType != nil {
		src.DeviceType = *deviceType
	}
	if sourceType != nil {
		src.SourceType = *sourceType
	}
	if apiKeyHint != nil {
		src.APIKeyHint = *apiKeyHint
	}
	src.AgentID = agentID
	src.LastEvent = lastEvent
	return &src
}

func InvalidateLogSourceCaches(ip, keyHash string) {
	if ip != "" {
		sourceByIP.Delete(ip)
	}
	if keyHash != "" {
		sourceByKey.Delete(keyHash)
	}
}

// GetLogSources returns all log sources for a tenant.
func GetLogSources(tenantID int) ([]models.LogSource, error) {
	rows, err := database.DB.Query(`
		SELECT id, tenant_id, name, source_type, ip_address::text, format, device_type,
		       agent_id, enabled, last_event, event_count, api_key_hint, created_at
		FROM log_sources
		WHERE tenant_id = $1
		ORDER BY id DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []models.LogSource{}
	for rows.Next() {
		var src models.LogSource
		var agentID *int
		var ipStr, deviceType, format, sourceType, apiKeyHint *string
		var lastEvent *time.Time
		if err := rows.Scan(
			&src.ID, &src.TenantID, &src.Name, &sourceType, &ipStr, &format, &deviceType,
			&agentID, &src.Enabled, &lastEvent, &src.EventCount, &apiKeyHint, &src.CreatedAt,
		); err != nil {
			return nil, err
		}
		if ipStr != nil {
			src.IPAddress = *ipStr
		}
		if format != nil {
			src.Format = *format
		}
		if deviceType != nil {
			src.DeviceType = *deviceType
		}
		if sourceType != nil {
			src.SourceType = *sourceType
		}
		if apiKeyHint != nil {
			src.APIKeyHint = *apiKeyHint
		}
		src.AgentID = agentID
		src.LastEvent = lastEvent
		out = append(out, src)
	}
	return out, rows.Err()
}

// CreateLogSource creates the log source and its backing virtual agent.
// Returns the new row ID, the plaintext API key (for HTTP sources; empty for
// syslog), and any error.
func CreateLogSource(src *models.LogSource) (id int, plaintextKey string, err error) {
	var keyHash, keyHint string

	if src.SourceType == "http" {
		plaintextKey, keyHash, err = generateAPIKey()
		if err != nil {
			return 0, "", fmt.Errorf("generating API key: %w", err)
		}
		if len(plaintextKey) >= 8 {
			keyHint = plaintextKey[:4] + "..." + plaintextKey[len(plaintextKey)-4:]
		}
	}

	// Each log source gets a synthetic agent row so existing detection,
	// correlation, and log-search queries can reference it via agent_id.
	machineID := fmt.Sprintf("logsource-%s-%d", src.Name, src.TenantID)
	osLabel := src.DeviceType
	if osLabel == "" {
		osLabel = "network"
	}
	ipVal := src.IPAddress
	var agentID int
	err = database.DB.QueryRow(`
		INSERT INTO agents (machine_id, hostname, os, ip_address, status, token, tenant_id)
		VALUES ($1, $2, $3, $4, 'online', '', $5)
		ON CONFLICT (machine_id) DO UPDATE
		    SET hostname = EXCLUDED.hostname, status = 'online', ip_address = EXCLUDED.ip_address
		RETURNING id
	`, machineID, src.Name, osLabel, ipVal, src.TenantID).Scan(&agentID)
	if err != nil {
		return 0, "", fmt.Errorf("creating virtual agent: %w", err)
	}

	var ipArg interface{}
	if src.IPAddress != "" {
		ipArg = src.IPAddress
	}

	var keyArg interface{}
	if keyHash != "" {
		keyArg = keyHash
	}

	err = database.DB.QueryRow(`
		INSERT INTO log_sources
		    (tenant_id, name, source_type, ip_address, api_key, api_key_hint,
		     format, device_type, agent_id)
		VALUES ($1, $2, $3, $4::inet, $5, $6, $7, $8, $9)
		RETURNING id
	`, src.TenantID, src.Name, src.SourceType, ipArg, keyArg, keyHint,
		src.Format, src.DeviceType, agentID).Scan(&id)
	if err != nil {
		return 0, "", fmt.Errorf("inserting log source: %w", err)
	}

	return id, plaintextKey, nil
}

// UpdateLogSource toggles enabled/name/device_type.
// Returns an error if no row matched (id+tenant_id mismatch).
func UpdateLogSource(id, tenantID int, name, deviceType string, enabled bool) error {
	res, err := database.DB.Exec(`
		UPDATE log_sources
		SET name = $3, device_type = $4, enabled = $5
		WHERE id = $1 AND tenant_id = $2
	`, id, tenantID, name, deviceType, enabled)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("not found")
	}
	return nil
}

// DeleteLogSource removes the log source and its virtual agent.
// Invalidates the IP and API-key routing caches.
func DeleteLogSource(id, tenantID int) error {
	var agentID *int
	var ipStr, apiKeyHash *string
	_ = database.DB.QueryRow(
		`SELECT agent_id, ip_address::text, api_key FROM log_sources WHERE id = $1 AND tenant_id = $2`,
		id, tenantID,
	).Scan(&agentID, &ipStr, &apiKeyHash)

	if _, err := database.DB.Exec(
		`DELETE FROM log_sources WHERE id = $1 AND tenant_id = $2`, id, tenantID,
	); err != nil {
		return err
	}

	ip := ""
	if ipStr != nil {
		ip = *ipStr
	}
	keyHash := ""
	if apiKeyHash != nil {
		keyHash = *apiKeyHash
	}
	InvalidateLogSourceCaches(ip, keyHash)

	if agentID != nil {
		database.DB.Exec(
			`DELETE FROM agents WHERE id = $1 AND machine_id LIKE 'logsource-%'`, *agentID,
		)
	}
	return nil
}

// BumpLogSourceEvent increments event_count and updates last_event for the
// given log source ID. Fire-and-forget — call asynchronously.
func BumpLogSourceEvent(id int) {
	database.DB.Exec(`
		UPDATE log_sources
		SET event_count = event_count + 1, last_event = NOW()
		WHERE id = $1
	`, id)
}

// HashAPIKey computes the SHA-256 hex digest of a plaintext API key.
func HashAPIKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func generateAPIKey() (plaintext, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	plaintext = hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(plaintext))
	hash = hex.EncodeToString(sum[:])
	return plaintext, hash, nil
}
