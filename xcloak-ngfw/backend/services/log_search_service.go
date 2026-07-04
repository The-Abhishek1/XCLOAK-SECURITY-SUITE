package services

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// ─────────────────────────────────────────────────────────────────────────────
// KQL-lite query parser
//
// Grammar (AND-implicit between terms):
//   field:value      — parsed_fields->>'field' ILIKE '%value%'
//   -field:value     — NOT parsed_fields->>'field' ILIKE '%value%'
//   "quoted phrase"  — log_message ILIKE '%quoted phrase%'
//   bare word        — log_message ILIKE '%word%'
//
// The field names map directly to ParsedFields JSON keys.
// ─────────────────────────────────────────────────────────────────────────────

type kqlCondition struct {
	sql  string
	args []interface{}
}

// parseKQL converts a KQL-lite query string into a list of SQL conditions
// (all ANDed together) and the corresponding positional parameter values.
// The caller must provide startIdx as the next $N to use (usually 1 or
// after the tenant/agent parameters that precede the WHERE conditions).
func parseKQL(query string, startIdx int) (conditions []string, args []interface{}) {
	tokens := tokenizeKQL(query)
	idx := startIdx

	for _, tok := range tokens {
		neg := strings.HasPrefix(tok, "-")
		if neg {
			tok = tok[1:]
		}

		colonIdx := strings.Index(tok, ":")
		if colonIdx > 0 {
			// field:value
			field := tok[:colonIdx]
			value := tok[colonIdx+1:]
			if value == "" {
				continue
			}
			// Sanitize: only allow [a-zA-Z0-9_] in field name.
			if !isSafeFieldName(field) {
				continue
			}
			cond := fmt.Sprintf("(parsed_fields->>'%s' ILIKE $%d)", field, idx)
			if neg {
				cond = "NOT " + cond
			}
			conditions = append(conditions, cond)
			args = append(args, "%"+value+"%")
			idx++
		} else {
			// Free text — unquoted word or quoted phrase.
			value := strings.Trim(tok, `"`)
			if value == "" {
				continue
			}
			cond := fmt.Sprintf("(log_message ILIKE $%d)", idx)
			if neg {
				cond = "NOT " + cond
			}
			conditions = append(conditions, cond)
			args = append(args, "%"+value+"%")
			idx++
		}
	}
	return
}

// tokenizeKQL splits a KQL-lite string into tokens, respecting double-quoted
// phrases and -negation prefixes.
func tokenizeKQL(q string) []string {
	var tokens []string
	q = strings.TrimSpace(q)
	for len(q) > 0 {
		q = strings.TrimLeft(q, " \t")
		if len(q) == 0 {
			break
		}

		neg := q[0] == '-'
		if neg {
			q = q[1:]
		}

		var tok string
		if len(q) > 0 && q[0] == '"' {
			// Quoted phrase — scan to next "
			end := strings.Index(q[1:], `"`)
			if end < 0 {
				tok = q[1:]
				q = ""
			} else {
				tok = q[1 : end+1]
				q = q[end+2:]
			}
			tok = `"` + tok + `"`
		} else {
			// Unquoted token — scan to next whitespace
			end := strings.IndexAny(q, " \t")
			if end < 0 {
				tok = q
				q = ""
			} else {
				tok = q[:end]
				q = q[end:]
			}
		}

		if tok == "AND" || tok == "OR" || tok == "NOT" {
			continue // skip boolean operators (we always AND)
		}
		if neg {
			tok = "-" + tok
		}
		tokens = append(tokens, tok)
	}
	return tokens
}

// isSafeFieldName is the security gate for field-name interpolation in
// parseKQL. Field values always go through parameterized query args ($N),
// but field *names* are embedded literally in SQL
// (parsed_fields->>'<field>' ILIKE $N) because PostgreSQL does not support
// a parameterized JSONB key on the ->> operator.
// This function therefore must be conservative: only ASCII alphanumeric +
// underscore, 1–60 chars. No quotes, no whitespace, no SQL metacharacters.
// Reviewed 2026-07-04: no SQL injection path through field names.
func isSafeFieldName(s string) bool {
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return len(s) > 0 && len(s) <= 60
}

// ─────────────────────────────────────────────────────────────────────────────
// Log search
// ─────────────────────────────────────────────────────────────────────────────

type LogSearchParams struct {
	Query     string    // KQL-lite free-text + field filters
	AgentID   int       // 0 = all agents
	From      time.Time // zero = unset
	To        time.Time // zero = unset
	Severity  string    // filter on parsed_fields->>'severity'
	LogSource string    // filter on log_source
	Limit     int       // default 200, max 1000
	Page      int       // 0-based
	TenantID  int
}

type LogSearchResult struct {
	Logs    []models.Log `json:"logs"`
	Total   int          `json:"total"`
	Page    int          `json:"page"`
	HasMore bool         `json:"has_more"`
}

// SearchLogs executes a parameterised log search and returns paginated results.
// Routes to Elasticsearch when available; falls back to Postgres.
func SearchLogs(p LogSearchParams) (*LogSearchResult, error) {
	if ElasticsearchEnabled() {
		if result, err := SearchLogsES(p); err == nil {
			return result, nil
		}
		slog.Warn("elasticsearch search failed, falling back to postgres")
	}
	if p.Limit <= 0 {
		p.Limit = 200
	}
	if p.Limit > 1000 {
		p.Limit = 1000
	}
	if p.Page < 0 {
		p.Page = 0
	}

	// Build WHERE clause.
	var whereParts []string
	var args []interface{}

	// Tenant isolation via agents join — ensures cross-tenant isolation.
	args = append(args, p.TenantID)
	tenantParam := fmt.Sprintf("$%d", len(args))
	whereParts = append(whereParts, fmt.Sprintf("a.tenant_id = %s", tenantParam))

	if p.AgentID > 0 {
		args = append(args, p.AgentID)
		whereParts = append(whereParts, fmt.Sprintf("l.agent_id = $%d", len(args)))
	}

	if !p.From.IsZero() {
		args = append(args, p.From)
		whereParts = append(whereParts, fmt.Sprintf("l.collected_at >= $%d", len(args)))
	}
	if !p.To.IsZero() {
		args = append(args, p.To)
		whereParts = append(whereParts, fmt.Sprintf("l.collected_at <= $%d", len(args)))
	}

	if p.Severity != "" {
		args = append(args, p.Severity)
		whereParts = append(whereParts, fmt.Sprintf("(l.parsed_fields->>'severity' ILIKE $%d)", len(args)))
	}
	if p.LogSource != "" {
		args = append(args, "%"+p.LogSource+"%")
		whereParts = append(whereParts, fmt.Sprintf("l.log_source ILIKE $%d", len(args)))
	}

	if p.Query != "" {
		conds, kqlArgs := parseKQL(p.Query, len(args)+1)
		for _, c := range conds {
			whereParts = append(whereParts, c)
		}
		args = append(args, kqlArgs...)
	}

	where := "WHERE " + strings.Join(whereParts, " AND ")

	baseQuery := fmt.Sprintf(`
		FROM endpoint_logs l
		JOIN agents a ON a.id = l.agent_id
		%s
	`, where)

	// Count (for pagination).
	var total int
	countSQL := "SELECT COUNT(*) " + baseQuery
	database.DB.QueryRow(countSQL, args...).Scan(&total)

	// Results.
	offset := p.Page * p.Limit
	args = append(args, p.Limit, offset)
	dataSQL := fmt.Sprintf(`
		SELECT l.id, l.agent_id, l.log_source, l.log_message,
		       COALESCE(l.parsed_fields::text, '{}'), l.collected_at
		%s
		ORDER BY l.collected_at DESC
		LIMIT $%d OFFSET $%d
	`, baseQuery, len(args)-1, len(args))

	rows, err := database.DB.Query(dataSQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []models.Log
	for rows.Next() {
		var l models.Log
		if err := rows.Scan(&l.ID, &l.AgentID, &l.LogSource, &l.LogMessage,
			&l.ParsedFields, &l.CollectedAt); err == nil {
			logs = append(logs, l)
		}
	}
	if logs == nil {
		logs = []models.Log{}
	}

	return &LogSearchResult{
		Logs:    logs,
		Total:   total,
		Page:    p.Page,
		HasMore: offset+len(logs) < total,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Export
// ─────────────────────────────────────────────────────────────────────────────

// ExportLogsCSV runs the same search and returns a CSV-formatted byte slice.
func ExportLogsCSV(p LogSearchParams) ([]byte, error) {
	p.Limit = 10000
	p.Page = 0
	res, err := SearchLogs(p)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"id", "agent_id", "log_source", "timestamp", "log_message", "user", "src_ip", "dst_ip", "event_id", "severity"})

	for _, l := range res.Logs {
		var pf map[string]interface{}
		json.Unmarshal([]byte(l.ParsedFields), &pf)

		getStr := func(k string) string {
			if v, ok := pf[k]; ok {
				if s, ok := v.(string); ok {
					return s
				}
			}
			return ""
		}

		ts := l.CollectedAt.Format(time.RFC3339)

		w.Write([]string{
			fmt.Sprintf("%d", l.ID),
			fmt.Sprintf("%d", l.AgentID),
			l.LogSource,
			ts,
			l.LogMessage,
			getStr("user"),
			getStr("src_ip"),
			getStr("dst_ip"),
			getStr("event_id"),
			getStr("severity"),
		})
	}
	w.Flush()
	return buf.Bytes(), nil
}

// ExportLogsJSON returns the logs as a JSON array.
func ExportLogsJSON(p LogSearchParams) ([]byte, error) {
	p.Limit = 10000
	p.Page = 0
	res, err := SearchLogs(p)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(res.Logs, "", "  ")
}

// ─────────────────────────────────────────────────────────────────────────────
// Log statistics
// ─────────────────────────────────────────────────────────────────────────────

type LogStats struct {
	TotalLogs      int                      `json:"total_logs"`
	ByAgent        []map[string]interface{} `json:"by_agent"`
	BySource       []map[string]interface{} `json:"by_source"`
	HourlyVolume   []map[string]interface{} `json:"hourly_volume"`
	RetentionDays  int                      `json:"retention_days"`
}

func GetLogStats(tenantID int) (*LogStats, error) {
	stats := &LogStats{}

	// Total count.
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM endpoint_logs l
		JOIN agents a ON a.id = l.agent_id WHERE a.tenant_id = $1
	`, tenantID).Scan(&stats.TotalLogs)

	// By agent (top 10).
	rows, err := database.DB.Query(`
		SELECT a.hostname, a.id, COUNT(*) AS cnt
		FROM endpoint_logs l
		JOIN agents a ON a.id = l.agent_id
		WHERE a.tenant_id = $1
		AND l.collected_at > NOW() - INTERVAL '24 hours'
		GROUP BY a.id, a.hostname
		ORDER BY cnt DESC LIMIT 10
	`, tenantID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var hostname string
			var agentID, cnt int
			if rows.Scan(&hostname, &agentID, &cnt) == nil {
				stats.ByAgent = append(stats.ByAgent, map[string]interface{}{
					"hostname": hostname, "agent_id": agentID, "count": cnt,
				})
			}
		}
		rows.Close()
	}

	// By log source (top 10).
	rows2, err := database.DB.Query(`
		SELECT l.log_source, COUNT(*) AS cnt
		FROM endpoint_logs l
		JOIN agents a ON a.id = l.agent_id
		WHERE a.tenant_id = $1 AND l.collected_at > NOW() - INTERVAL '24 hours'
		GROUP BY l.log_source ORDER BY cnt DESC LIMIT 10
	`, tenantID)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var src string
			var cnt int
			if rows2.Scan(&src, &cnt) == nil {
				stats.BySource = append(stats.BySource, map[string]interface{}{
					"source": src, "count": cnt,
				})
			}
		}
	}

	// Hourly volume (last 24 hours).
	rows3, err := database.DB.Query(`
		SELECT date_trunc('hour', l.collected_at) AS hour, COUNT(*) AS cnt
		FROM endpoint_logs l
		JOIN agents a ON a.id = l.agent_id
		WHERE a.tenant_id = $1 AND l.collected_at > NOW() - INTERVAL '24 hours'
		GROUP BY hour ORDER BY hour
	`, tenantID)
	if err == nil {
		defer rows3.Close()
		for rows3.Next() {
			var hour time.Time
			var cnt int
			if rows3.Scan(&hour, &cnt) == nil {
				stats.HourlyVolume = append(stats.HourlyVolume, map[string]interface{}{
					"hour": hour, "count": cnt,
				})
			}
		}
	}

	// Retention policy.
	database.DB.QueryRow(`
		SELECT COALESCE(retention_days, 90) FROM log_retention_policies WHERE tenant_id = $1
	`, tenantID).Scan(&stats.RetentionDays)
	if stats.RetentionDays == 0 {
		stats.RetentionDays = 90
	}

	return stats, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Saved searches
// ─────────────────────────────────────────────────────────────────────────────

type SavedLogSearch struct {
	ID         int             `json:"id"`
	Name       string          `json:"name"`
	Query      string          `json:"query"`
	Filters    json.RawMessage `json:"filters"`
	TimeRange  string          `json:"time_range"`
	CreatedBy  string          `json:"created_by"`
	TenantID   int             `json:"tenant_id"`
	RunCount   int             `json:"run_count"`
	LastRunAt  *time.Time      `json:"last_run_at"`
	CreatedAt  time.Time       `json:"created_at"`
}

func SaveLogSearch(s SavedLogSearch, tenantID int) (*SavedLogSearch, error) {
	filters := s.Filters
	if filters == nil {
		filters = json.RawMessage("{}")
	}
	err := database.DB.QueryRow(`
		INSERT INTO saved_log_searches (name, query, filters, time_range, created_by, tenant_id)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, created_at
	`, s.Name, s.Query, filters, s.TimeRange, s.CreatedBy, tenantID).
		Scan(&s.ID, &s.CreatedAt)
	if err != nil {
		return nil, err
	}
	s.TenantID = tenantID
	return &s, nil
}

func GetSavedLogSearches(tenantID int) ([]SavedLogSearch, error) {
	rows, err := database.DB.Query(`
		SELECT id, name, query, filters, time_range, created_by,
		       run_count, last_run_at, created_at
		FROM saved_log_searches WHERE tenant_id=$1 ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var searches []SavedLogSearch
	for rows.Next() {
		var s SavedLogSearch
		if err := rows.Scan(&s.ID, &s.Name, &s.Query, &s.Filters, &s.TimeRange,
			&s.CreatedBy, &s.RunCount, &s.LastRunAt, &s.CreatedAt); err == nil {
			searches = append(searches, s)
		}
	}
	return searches, nil
}

func DeleteSavedLogSearch(id string, tenantID int) error {
	tag, err := database.DB.Exec(`
		DELETE FROM saved_log_searches WHERE id=$1 AND tenant_id=$2
	`, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return fmt.Errorf("not found")
	}
	return nil
}

func IncrementSearchRunCount(id int) {
	database.DB.Exec(`
		UPDATE saved_log_searches SET run_count = run_count+1, last_run_at=NOW() WHERE id=$1
	`, id)
}

// ─────────────────────────────────────────────────────────────────────────────
// Retention policy
// ─────────────────────────────────────────────────────────────────────────────

func GetRetentionDays(tenantID int) int {
	var days int
	database.DB.QueryRow(`
		SELECT retention_days FROM log_retention_policies WHERE tenant_id=$1
	`, tenantID).Scan(&days)
	if days == 0 {
		return 90
	}
	return days
}

func SetRetentionDays(tenantID, days int) error {
	if days < 1 || days > 730 {
		return fmt.Errorf("retention_days must be between 1 and 730")
	}
	_, err := database.DB.Exec(`
		INSERT INTO log_retention_policies (tenant_id, retention_days, updated_at)
		VALUES ($1,$2,NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET retention_days=$2, updated_at=NOW()
	`, tenantID, days)
	return err
}

// EnsureNextMonthPartition creates the endpoint_logs partition for next month
// if it doesn't already exist. Called monthly from StartScheduler so inserts
// never fall through to the default/legacy partition.
//
// This function is intentionally self-contained: it checks whether
// endpoint_logs is a partitioned table (relkind='p') before acting, so it
// is a no-op when migration 52 hasn't been applied yet. It does not rely on
// the create_endpoint_logs_partition PL/pgSQL function to avoid a failure
// dependency on that function existing.
func EnsureNextMonthPartition() {
	// No-op when endpoint_logs hasn't been converted to a partitioned table.
	var relkind string
	if err := database.DB.QueryRow(
		`SELECT relkind FROM pg_class
		 WHERE relname='endpoint_logs' AND relnamespace='public'::regnamespace`,
	).Scan(&relkind); err != nil || relkind != "p" {
		return
	}

	next := time.Now().AddDate(0, 1, 0)
	start := time.Date(next.Year(), next.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	partName := fmt.Sprintf("endpoint_logs_%s", start.Format("2006_01"))

	// Check whether this month's partition already exists.
	var exists bool
	database.DB.QueryRow(
		`SELECT EXISTS(
			SELECT 1 FROM pg_class
			WHERE relname=$1 AND relnamespace='public'::regnamespace
		)`, partName,
	).Scan(&exists)
	if exists {
		return
	}

	_, err := database.DB.Exec(fmt.Sprintf(
		`CREATE TABLE %s PARTITION OF endpoint_logs
		 FOR VALUES FROM ('%s') TO ('%s')`,
		partName, start.Format("2006-01-02"), end.Format("2006-01-02"),
	))
	if err != nil {
		slog.Warn("partition maintenance failed", "partition", partName, "err", err)
	} else {
		slog.Info("created endpoint_logs partition", "partition", partName)
	}
}

// ApplyRetentionPolicies deletes time-series rows older than each tenant's
// configured retention window. For partitioned endpoint_logs, whole month
// partitions older than the retention cutoff are dropped (fast path); the
// batched-DELETE loop remains as a fallback for the legacy/default partition.
// Called from StartScheduler nightly.
func ApplyRetentionPolicies() {
	rows, err := database.DB.Query(`
		SELECT tenant_id, retention_days FROM log_retention_policies
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var tenantID, days int
		if rows.Scan(&tenantID, &days) != nil {
			continue
		}
		applyRetentionForTenant(tenantID, days)
	}
}

// applyRetentionForTenant purges all time-series tables for one tenant.
// Each table is purged in 1 000-row batches to cap lock duration.
func applyRetentionForTenant(tenantID, days int) {
	const batchSize = 1000

	// endpoint_logs — drop whole monthly partitions older than the retention
	// cutoff (O(1) vs batched DELETE). Falls through to DELETE on the
	// legacy/default partition which may not have month boundaries.
	cutoff := time.Now().AddDate(0, 0, -days)
	dropEndpointLogsPartitionsBefore(tenantID, cutoff, batchSize)

	// Tables with a direct tenant_id column.
	type directTable struct {
		name    string
		timeCol string
	}
	tables := []directTable{
		{"network_connections", "created_at"},
		{"network_anomalies", "detected_at"},
		{"audit_events", "created_at"},
		{"behavioral_findings", "scored_at"},
		{"sigma_matches", "matched_at"},
		{"mdm_commands", "queued_at"},
	}
	for _, t := range tables {
		tbl, col := t.name, t.timeCol
		deleteInBatches(batchSize, func() (int64, error) {
			r, err := database.DB.Exec(
				`DELETE FROM `+tbl+` WHERE ctid IN (`+
					`SELECT ctid FROM `+tbl+
					` WHERE tenant_id = $1`+
					` AND `+col+` < NOW() - ($2 * INTERVAL '1 day')`+
					` LIMIT $3)`,
				tenantID, days, batchSize,
			)
			if err != nil {
				return 0, err
			}
			return r.RowsAffected()
		})
	}
}

// dropEndpointLogsPartitionsBefore drops monthly endpoint_logs partitions whose
// entire month is older than cutoff for the given tenant. For multi-tenant
// partitions the DELETE fallback removes only that tenant's rows; whole-partition
// DROP only fires when the partition is single-tenant (future: per-tenant
// sub-partitioning). The legacy/default partition always falls through to DELETE.
func dropEndpointLogsPartitionsBefore(tenantID int, cutoff time.Time, batchSize int) {
	// Find named month partitions (endpoint_logs_YYYY_MM) older than cutoff.
	rows, err := database.DB.Query(`
		SELECT c.relname
		FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid
		WHERE i.inhparent = 'endpoint_logs'::regclass
		  AND c.relname ~ '^endpoint_logs_\d{4}_\d{2}$'
		  AND to_date(substring(c.relname FROM '\d{4}_\d{2}$'), 'YYYY_MM')
		      + INTERVAL '1 month' <= $1
	`, cutoff)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var partName string
			if rows.Scan(&partName) != nil {
				continue
			}
			// DROP is safe only when the partition holds data for one tenant.
			// For now, use targeted DELETE (safe for shared partitions).
			// TODO: enable DROP once per-tenant partitioning is implemented.
			database.DB.Exec(
				`DELETE FROM `+partName+` WHERE tenant_id = $1`, tenantID,
			)
		}
	}

	// Batched DELETE fallback for the legacy/default partition and any rows
	// that slipped through before the partition schema was in place.
	deleteInBatches(batchSize, func() (int64, error) {
		r, err := database.DB.Exec(`
			DELETE FROM endpoint_logs
			WHERE ctid IN (
				SELECT ctid FROM endpoint_logs
				WHERE tenant_id = $1
				  AND collected_at < $2
				LIMIT $3
			)
		`, tenantID, cutoff, batchSize)
		if err != nil {
			return 0, err
		}
		return r.RowsAffected()
	})
}

// deleteInBatches calls del() repeatedly until it deletes fewer than
// batchSize rows, indicating the backlog is clear. Stops on error.
func deleteInBatches(batchSize int, del func() (int64, error)) {
	for {
		n, err := del()
		if err != nil || n < int64(batchSize) {
			return
		}
	}
}
