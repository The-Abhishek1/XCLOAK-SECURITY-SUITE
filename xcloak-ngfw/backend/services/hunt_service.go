package services

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// Allowed query types and their underlying tables + searchable columns.
var huntTargets = map[string]struct {
	table     string
	cols      []string
	joinAgent string
}{
	"process": {
		table:     "endpoint_processes",
		cols:      []string{"process_name", "cmdline", "username", "exe_path"},
		joinAgent: "agent_id",
	},
	"command": {
		table:     "audit_events",
		cols:      []string{"cmdline", "exe", "comm", "username", "threat_tag"},
		joinAgent: "agent_id",
	},
	"connection": {
		table:     "endpoint_connections",
		cols:      []string{"local_address", "remote_address", "state", "protocol"},
		joinAgent: "agent_id",
	},
	"user": {
		table:     "endpoint_users",
		cols:      []string{"username", "shell"},
		joinAgent: "agent_id",
	},
	"package": {
		table:     "endpoint_packages",
		cols:      []string{"package_name", "version"},
		joinAgent: "agent_id",
	},
	"log": {
		table:     "endpoint_logs",
		cols:      []string{"log_message", "log_source"},
		joinAgent: "agent_id",
	},
	"alert": {
		table:     "alerts",
		cols:      []string{"rule_name", "log_message", "mitre_technique", "severity"},
		joinAgent: "agent_id",
	},
	"file_hash": {
		table:     "endpoint_file_hashes",
		cols:      []string{"file_path", "file_name", "sha256_hash", "md5_hash"},
		joinAgent: "agent_id",
	},
}

// RunHuntQuery executes a hunt query safely using parameterized ILIKE search.
// QueryText is treated as a search term, NOT raw SQL — fully injection-safe.
func RunHuntQuery(queryID int, queryType, queryText string) (*models.HuntRunResponse, error) {

	start := time.Now()

	target, ok := huntTargets[queryType]
	if !ok {
		return nil, fmt.Errorf("unsupported query type: %s", queryType)
	}

	// Build ILIKE conditions for each searchable column.
	conditions := make([]string, 0, len(target.cols))
	args := []interface{}{"%" + queryText + "%"}

	for _, col := range target.cols {
		conditions = append(conditions, fmt.Sprintf("CAST(%s AS TEXT) ILIKE $1", col))
	}

	whereClause := strings.Join(conditions, " OR ")

	query := fmt.Sprintf(`
		SELECT t.*, a.hostname
		FROM %s t
		JOIN agents a ON a.id = t.%s
		WHERE %s
		ORDER BY t.id DESC
		LIMIT 500
	`, target.table, target.joinAgent, whereClause)

	rows, err := database.DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("hunt query failed: %w", err)
	}
	defer rows.Close()

	cols, _ := rows.Columns()
	var results []models.HuntResult

	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}

		if err := rows.Scan(ptrs...); err != nil {
			continue
		}

		row := make(map[string]interface{})
		for i, col := range cols {
			row[col] = vals[i]
		}

		data, _ := json.Marshal(row)
		results = append(results, models.HuntResult{
			QueryID: queryID,
			Result:  data,
		})
	}

	// Update hit count and last_run_at.
	if queryID > 0 {
		database.DB.Exec(`
			UPDATE hunt_queries
			SET hit_count = hit_count + $1, last_run_at = now()
			WHERE id = $2
		`, len(results), queryID)
	}

	return &models.HuntRunResponse{
		QueryID:  queryID,
		Hits:     len(results),
		Duration: fmt.Sprintf("%d", time.Since(start).Milliseconds()),
		Results:  results,
	}, nil
}

// SaveHuntQuery persists a named hunt query for reuse.
func SaveHuntQuery(q models.HuntQuery) (*models.HuntQuery, error) {

	err := database.DB.QueryRow(`
		INSERT INTO hunt_queries (name, description, query_type, query_text, created_by)
		VALUES ($1,$2,$3,$4,$5) RETURNING id, created_at
	`, q.Name, q.Description, q.QueryType, q.QueryText, q.CreatedBy).
		Scan(&q.ID, &q.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &q, nil
}

// GetHuntQueries returns all saved hunt queries.
func GetHuntQueries() ([]models.HuntQuery, error) {

	rows, err := database.DB.Query(`
		SELECT id, name, description, query_type, query_text,
		       created_by, hit_count, last_run_at, created_at
		FROM hunt_queries ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var queries []models.HuntQuery
	for rows.Next() {
		var q models.HuntQuery
		if err := rows.Scan(&q.ID, &q.Name, &q.Description, &q.QueryType,
			&q.QueryText, &q.CreatedBy, &q.HitCount, &q.LastRunAt, &q.CreatedAt); err == nil {
			queries = append(queries, q)
		}
	}
	return queries, nil
}

// DeleteHuntQuery removes a saved query.
func DeleteHuntQuery(id string) error {
	_, err := database.DB.Exec(`DELETE FROM hunt_queries WHERE id=$1`, id)
	return err
}
