package repositories

import (
	"xcloak-platform/database"
	"xcloak-platform/models"
)

// PostSaveHook is called after a successful SaveLogs commit.
// Injected from main.go to avoid the repositories → services import cycle.
var PostSaveHook func(logs []models.Log)

// SaveLogs inserts log lines with their normalised parsed_fields JSON.
// The parsed_fields column is populated by the normalizer in log_service.go
// before this function is called.
func SaveLogs(logs []models.Log) error {

	if len(logs) == 0 {
		return nil
	}

	tx, err := database.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, log := range logs {
		pf := log.ParsedFields
		if pf == "" {
			pf = "{}"
		}
		_, err := tx.Exec(`
			INSERT INTO endpoint_logs
			  (agent_id, tenant_id, log_source, log_message, parsed_fields)
			VALUES ($1, $2, $3, $4, $5::jsonb)
		`,
			log.AgentID,
			log.TenantID,
			log.LogSource,
			log.LogMessage,
			pf,
		)
		if err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// Non-blocking ES indexing after the Postgres commit succeeds.
	if PostSaveHook != nil {
		go PostSaveHook(logs)
	}
	return nil
}

// SearchLogs does a field-level search against parsed_fields JSONB.
// fieldName is a ParsedFields field (e.g. "src_ip", "user", "event_id").
// value supports exact match or contains match depending on the operator.
func SearchLogs(agentID, fieldName, value string, limit int) ([]models.Log, error) {
	if limit <= 0 {
		limit = 200
	}
	// Use Postgres JSONB operator ->> to extract the field, then ILIKE match.
	rows, err := database.DB.Query(`
		SELECT id, agent_id, log_source, log_message,
		       parsed_fields::text, collected_at
		FROM endpoint_logs
		WHERE ($1 = '' OR agent_id = $1::int)
		  AND parsed_fields ->> $2 ILIKE $3
		ORDER BY collected_at DESC
		LIMIT $4
	`, agentID, fieldName, "%"+value+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.Log
	for rows.Next() {
		var l models.Log
		if err := rows.Scan(&l.ID, &l.AgentID, &l.LogSource, &l.LogMessage, &l.ParsedFields, &l.CollectedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
