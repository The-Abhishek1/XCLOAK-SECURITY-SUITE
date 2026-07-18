package repositories

import (
	"xcloak-platform/database"
)

// GetActiveTenantIDs returns IDs of all active tenants. Used by per-tenant
// detection schedulers that need to iterate over the full fleet.
func GetActiveTenantIDs() ([]int, error) {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = true`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []int{}
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// FIMCandidate is one agent row from the ransomware FIM mass-modification query.
type FIMCandidate struct {
	AgentID      int
	TotalChanges int
	DirsHit      int
	CryptoCount  int
}

// GetFIMRansomwareCandidates returns agents with suspicious file-modification
// volume in the last window. cryptoExtSQL is the SQL fragment built by
// services.cryptoExtSQL() and passed in to avoid a cross-package import.
func GetFIMRansomwareCandidates(tenantID, threshold int, cryptoExtSQL string) ([]FIMCandidate, error) {
	rows, err := database.DB.Query(`
		SELECT fa.agent_id,
		       COUNT(*)                                              AS total_changes,
		       COUNT(DISTINCT REGEXP_REPLACE(fa.file_path, '[^/\\]+$', '')) AS dirs_hit,
		       SUM(CASE WHEN `+cryptoExtSQL+` THEN 1 ELSE 0 END) AS crypto_count
		FROM fim_alerts fa
		JOIN agents a ON a.id = fa.agent_id AND a.tenant_id = $1
		WHERE fa.created_at > NOW() - INTERVAL '10 minutes'
		GROUP BY fa.agent_id
		HAVING COUNT(*) >= $2 OR SUM(CASE WHEN `+cryptoExtSQL+` THEN 1 ELSE 0 END) >= 5
	`, tenantID, threshold)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []FIMCandidate{}
	for rows.Next() {
		var c FIMCandidate
		if err := rows.Scan(&c.AgentID, &c.TotalChanges, &c.DirsHit, &c.CryptoCount); err == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

// ProcessLogRow is one row from the kill-chain command scan.
type ProcessLogRow struct {
	AgentID    int
	LogMessage string
	CmdLine    string
}

// GetRecentProcessLogs fetches recent process-execution logs for kill-chain
// detection. Falls back to raw log scan if parsed EventID field isn't populated.
func GetRecentProcessLogs(tenantID int) ([]ProcessLogRow, error) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id, el.log_message, el.parsed_fields->>'command_line' AS cmdline
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.created_at > NOW() - INTERVAL '5 minutes'
		  AND el.parsed_fields->>'event_id' = '4688'
		LIMIT 2000
	`, tenantID)
	if err != nil {
		// Fallback: raw log scan when parsed EventID isn't available.
		rows, err = database.DB.Query(`
			SELECT el.agent_id, el.log_message, '' AS cmdline
			FROM endpoint_logs el
			JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
			WHERE el.created_at > NOW() - INTERVAL '5 minutes'
			LIMIT 5000
		`, tenantID)
		if err != nil {
			return nil, err
		}
	}
	defer rows.Close()

	out := []ProcessLogRow{}
	for rows.Next() {
		var r ProcessLogRow
		if err := rows.Scan(&r.AgentID, &r.LogMessage, &r.CmdLine); err == nil {
			out = append(out, r)
		}
	}
	return out, nil
}

// ServiceStopLogRow is one row from the security-service-kill scan.
type ServiceStopLogRow struct {
	AgentID    int
	LogMessage string
}

// GetRecentServiceStopLogs fetches logs matching service-stop patterns used
// by ransomware to disable EDR/AV before encryption.
func GetRecentServiceStopLogs(tenantID int) ([]ServiceStopLogRow, error) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id, el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.created_at > NOW() - INTERVAL '5 minutes'
		  AND (lower(el.log_message) LIKE '%net stop%'
		    OR lower(el.log_message) LIKE '%sc stop%'
		    OR lower(el.log_message) LIKE '%sc delete%'
		    OR lower(el.log_message) LIKE '%taskkill%')
		LIMIT 1000
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ServiceStopLogRow{}
	for rows.Next() {
		var r ServiceStopLogRow
		if err := rows.Scan(&r.AgentID, &r.LogMessage); err == nil {
			out = append(out, r)
		}
	}
	return out, nil
}
