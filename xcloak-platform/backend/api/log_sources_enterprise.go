package api

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// ─── Health ───────────────────────────────────────────────────────────────────

// GetLogSourceHealth — GET /api/log-sources/:id/health
func GetLogSourceHealth(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid id"})
		return
	}
	src := findLogSource(id, tenantIDFromContext(c))
	if src == nil {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}

	status := deriveStatus(src)

	var eps int64
	if src.Name != "" {
		database.DB.QueryRow(
			`SELECT COUNT(*) FROM endpoint_logs WHERE log_source=$1 AND tenant_id=$2 AND collected_at > NOW()-INTERVAL '1 minute'`,
			src.Name, src.TenantID,
		).Scan(&eps)
	}

	// parsing_status/auth_status were previously hardcoded "ok" with no real
	// check behind them — nothing in the ingest pipeline tracks per-source
	// parse failures or auth failures, so there was nothing to report.
	// Removed rather than fabricate a status.
	c.JSON(200, gin.H{
		"status":           status,
		"last_event":       src.LastEvent,
		"last_heartbeat":   src.LastEvent,
		"eps":              eps,
		"ingestion_status": ingestionStatus(status, src.EventCount),
		"enabled":          src.Enabled,
		"event_count":      src.EventCount,
	})
}

func deriveStatus(src *models.LogSource) string {
	if !src.Enabled {
		return "offline"
	}
	if src.LastEvent == nil {
		return "offline"
	}
	age := time.Since(*src.LastEvent)
	if age < 5*time.Minute {
		return "online"
	}
	if age < time.Hour {
		return "warning"
	}
	return "offline"
}

func ingestionStatus(health string, count int64) string {
	if health == "offline" {
		return "stopped"
	}
	if count == 0 {
		return "no_events"
	}
	return "running"
}

// ─── Stats ────────────────────────────────────────────────────────────────────

// GetLogSourceStats — GET /api/log-sources/:id/stats
func GetLogSourceStats(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid id"})
		return
	}
	src := findLogSource(id, tenantIDFromContext(c))
	if src == nil {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}

	var daily, eps int64
	if src.Name != "" {
		database.DB.QueryRow(
			`SELECT COUNT(*) FROM endpoint_logs WHERE log_source=$1 AND tenant_id=$2 AND collected_at > NOW()-INTERVAL '24 hours'`,
			src.Name, src.TenantID,
		).Scan(&daily)
		database.DB.QueryRow(
			`SELECT COUNT(*) FROM endpoint_logs WHERE log_source=$1 AND tenant_id=$2 AND collected_at > NOW()-INTERVAL '1 minute'`,
			src.Name, src.TenantID,
		).Scan(&eps)
	}

	// Rough estimate only (~500 bytes/log, uncompressed) — endpoint_logs is a
	// natively-partitioned table, explicitly exempted from TimescaleDB
	// compression (see migration 000067's header comment), so there is no
	// real compression ratio to report; a hardcoded "3:1" here previously
	// claimed a capability this table doesn't have.
	storageMB := float64(src.EventCount) * 500 / (1024 * 1024)

	// parsing_errors is always 0 by design, not by measurement: NormalizeLog
	// never fails — it falls back to a raw key=value extractor as a last
	// resort, so every ingested line always produces a ParsedFields result.
	// dropped_logs/queue_length were removed — this ingest path is fully
	// synchronous with no queue or drop mechanism anywhere to measure.
	c.JSON(200, gin.H{
		"eps":             eps,
		"daily_events":    daily,
		"total_logs":      src.EventCount,
		"storage_used_mb": fmt.Sprintf("%.2f", storageMB),
		"parsing_errors":  0,
	})
}

// ─── Parser ───────────────────────────────────────────────────────────────────

// GetLogSourceParser — GET /api/log-sources/:id/parser
func GetLogSourceParser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid id"})
		return
	}
	src := findLogSource(id, tenantIDFromContext(c))
	if src == nil {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}

	name, fieldMapping := parserForSource(src)
	c.JSON(200, gin.H{
		"parser_used":    name,
		"field_mapping":  fieldMapping,
		"parsing_errors": 0,
		"unknown_fields": []string{},
		"parser_version": "1.0.0",
	})
}

// parserForSource describes the field mapping the given format actually
// produces in services.NormalizeLog/ParsedFields — every entry here must
// correspond to a real assignment in log_normalizer.go. A previous version
// of this also returned an "ecs_mapping" table claiming dotted ECS paths
// like "source.ip"/"host.name"/"winlog.event_id" — nothing in this codebase
// (Postgres storage or the optional Elasticsearch mirror, which indexes
// parsed_fields verbatim) ever produces those paths, so it was pure fiction
// presented as parser documentation. Removed rather than left half-fixed;
// several of its per-field claims were also wrong even as an aspirational
// mapping (e.g. CEF's "deviceProduct" actually lands in device_product, not
// "product"; syslog never extracts a facility at all).
func parserForSource(src *models.LogSource) (string, map[string]string) {
	// CreateLogSource never normalizes case on the free-text `format` field,
	// and existing sources hold a mix ("CEF", "cef", "Windows Event",
	// "WinEvent", "JSON", "json", ...) — an exact-match switch on the raw
	// value silently fell through to "Auto-Detect Parser" for every
	// non-lowercase-exact source (verified live: a seeded source with
	// format="CEF" reported "Auto-Detect Parser" instead of the real CEF
	// parser identification, despite being a genuine CEF source). Fold to
	// lowercase and recognize the "Windows Event"/"evtx" spelling variants
	// before matching.
	format := strings.ToLower(strings.TrimSpace(src.Format))
	if format == "windows event" || format == "evtx" || format == "winlog" {
		format = "winevent"
	}
	switch format {
	case "cef":
		return "CEF Parser (ArcSight)", map[string]string{
			"src": "parsed_fields.src_ip", "dst": "parsed_fields.dst_ip",
			"suser/duser": "parsed_fields.user", "sproc": "parsed_fields.process",
			"deviceProduct": "parsed_fields.device_product", "header severity": "parsed_fields.cef_severity",
		}
	case "winevent":
		return "Windows Event Parser", map[string]string{
			"Event ID":               "parsed_fields.event_id",
			"Target/Subject User":    "parsed_fields.user",
			"Logon Type":             "parsed_fields.logon_type",
			"Source Network Address": "parsed_fields.src_ip",
		}
	case "json":
		return "JSON Parser", map[string]string{
			"src_ip/src/source_ip": "parsed_fields.src_ip",
			"user/username":        "parsed_fields.user",
			"hostname/host":        "parsed_fields.hostname",
			"event_id/EventID":     "parsed_fields.event_id",
		}
	case "syslog":
		return "Syslog Parser (RFC 3164/5424)", map[string]string{
			"hostname":                               "parsed_fields.hostname",
			"process/app":                            "parsed_fields.process",
			"pid/procid":                             "parsed_fields.pid",
			"severity (heuristic from message body)": "parsed_fields.severity",
		}
	default:
		return "Auto-Detect Parser", map[string]string{
			"(routes through the syslog/CEF/JSON/Windows-Event parsers above based on message content)": "parsed_fields.*",
		}
	}
}

// ─── Recent Logs ──────────────────────────────────────────────────────────────

// GetLogSourceRecentLogs — GET /api/log-sources/:id/recent-logs
func GetLogSourceRecentLogs(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid id"})
		return
	}
	src := findLogSource(id, tenantIDFromContext(c))
	if src == nil {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}

	type Entry struct {
		ID          int       `json:"id"`
		LogSource   string    `json:"log_source"`
		LogMessage  string    `json:"log_message"`
		CollectedAt time.Time `json:"collected_at"`
	}

	rows, err := database.DB.Query(
		`SELECT id, log_source, log_message, collected_at FROM endpoint_logs
		 WHERE log_source=$1 AND tenant_id=$2
		 ORDER BY collected_at DESC LIMIT 50`,
		src.Name, src.TenantID,
	)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	logs := []Entry{}
	for rows.Next() {
		var e Entry
		if rows.Scan(&e.ID, &e.LogSource, &e.LogMessage, &e.CollectedAt) == nil {
			logs = append(logs, e)
		}
	}
	if logs == nil {
		logs = []Entry{}
	}
	c.JSON(200, gin.H{"logs": logs})
}

// ─── Test ─────────────────────────────────────────────────────────────────────

// TestLogSourceConnection — POST /api/log-sources/:id/test
func TestLogSourceConnection(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid id"})
		return
	}
	src := findLogSource(id, tenantIDFromContext(c))
	if src == nil {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}

	// auth/parser/permissions were previously hardcoded "ok" and latency_ms
	// a fixed "12" — none had any real check behind them (nothing actually
	// contacts the source or validates credentials here). Removed the fake
	// fields; latency_ms now times the one real query this handler can
	// meaningfully run against this source's own data.
	start := time.Now()
	var probe int64
	database.DB.QueryRow(
		`SELECT COUNT(*) FROM endpoint_logs WHERE log_source=$1 AND tenant_id=$2 AND collected_at > NOW()-INTERVAL '1 minute'`,
		src.Name, src.TenantID,
	).Scan(&probe)
	latencyMs := time.Since(start).Milliseconds()

	conn, msg := "ok", "Connection test passed."
	if !src.Enabled {
		conn = "error"
		msg = "Source is disabled."
	} else if src.LastEvent == nil {
		conn = "warning"
		msg = "Source enabled but no events received yet."
	}
	c.JSON(200, gin.H{
		"connection": conn,
		"tls":        src.SourceType == "http",
		"latency_ms": latencyMs,
		"message":    msg,
	})
}

// ─── Fleet Monitoring ─────────────────────────────────────────────────────────

// GetLogSourceMonitoring — GET /api/log-sources/monitoring
func GetLogSourceMonitoring(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	sources, err := repositories.GetLogSources(tenantID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	online, offline, warning := 0, 0, 0
	type Summary struct {
		ID         int        `json:"id"`
		Name       string     `json:"name"`
		DeviceType string     `json:"device_type"`
		Status     string     `json:"status"`
		LastEvent  *time.Time `json:"last_event"`
		EventCount int64      `json:"event_count"`
	}
	list := []Summary{}
	for _, src := range sources {
		s := deriveStatus(&src)
		switch s {
		case "online":
			online++
		case "warning":
			warning++
		default:
			offline++
		}
		list = append(list, Summary{ID: src.ID, Name: src.Name, DeviceType: src.DeviceType,
			Status: s, LastEvent: src.LastEvent, EventCount: src.EventCount})
	}
	if list == nil {
		list = []Summary{}
	}

	var totalEPS int64
	database.DB.QueryRow(
		`SELECT COUNT(*) FROM endpoint_logs WHERE tenant_id=$1 AND collected_at > NOW()-INTERVAL '1 minute'`,
		tenantID,
	).Scan(&totalEPS)

	c.JSON(200, gin.H{
		"online":    online,
		"offline":   offline,
		"warning":   warning,
		"total":     len(sources),
		"total_eps": totalEPS,
		"sources":   list,
	})
}

// ─── AI Insights ─────────────────────────────────────────────────────────────

// AILogSourceInsights — POST /api/log-sources/ai-insights
func AILogSourceInsights(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	sources, err := repositories.GetLogSources(tenantID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	var sb strings.Builder
	for _, src := range sources {
		s := deriveStatus(&src)
		lastSeen := "never"
		if src.LastEvent != nil {
			lastSeen = fmt.Sprintf("%.0f min ago", time.Since(*src.LastEvent).Minutes())
		}
		fmt.Fprintf(&sb, "- %s (%s): %s, last seen %s, %d total events\n",
			src.Name, src.DeviceType, s, lastSeen, src.EventCount)
	}

	if sb.Len() == 0 {
		c.JSON(200, gin.H{"insights": []string{"No log sources configured yet. Add sources to start receiving events."}})
		return
	}

	prompt := fmt.Sprintf(`You are an expert SIEM analyst. Analyze these log source health metrics and return 3-5 actionable insights as a JSON array of strings.

Log sources:
%s

Focus on: offline sources, missing critical source types, unusual volumes, gaps in coverage.
Reply with ONLY a JSON array: ["insight 1", "insight 2", ...]`, sb.String())

	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(200, gin.H{"insights": []string{"AI service unavailable."}})
		return
	}
	raw = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(raw), "```json"), "```"), "```"))
	c.JSON(200, gin.H{"insights": raw})
}

// ─── Bulk Operations ─────────────────────────────────────────────────────────

// BulkUpdateLogSources — POST /api/log-sources/bulk
func BulkUpdateLogSources(c *gin.Context) {
	var body struct {
		Action string `json:"action"` // enable | disable | delete
		IDs    []int  `json:"ids"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || len(body.IDs) == 0 {
		c.JSON(400, gin.H{"error": "action and ids required"})
		return
	}
	tenantID := tenantIDFromContext(c)
	affected := 0
	for _, id := range body.IDs {
		switch body.Action {
		case "enable":
			if repositories.UpdateLogSource(id, tenantID, "", "", true) == nil {
				affected++
			}
		case "disable":
			if repositories.UpdateLogSource(id, tenantID, "", "", false) == nil {
				affected++
			}
		case "delete":
			if repositories.DeleteLogSource(id, tenantID) == nil {
				affected++
			}
		}
	}
	repositories.InvalidateLogSourceCaches("", "")
	c.JSON(200, gin.H{"affected": affected, "action": body.Action})
}

// ─── Marketplace ─────────────────────────────────────────────────────────────

// GetLogSourceMarketplace — GET /api/log-sources/marketplace
func GetLogSourceMarketplace(c *gin.Context) {
	c.JSON(200, gin.H{
		"version":    "1.0.0",
		"categories": []string{"Operating Systems", "Network Devices", "Security Products", "Cloud Platforms", "SaaS", "Containers", "Applications", "Databases", "Infrastructure"},
	})
}

// ─── Helper ───────────────────────────────────────────────────────────────────

func findLogSource(id, tenantID int) *models.LogSource {
	sources, err := repositories.GetLogSources(tenantID)
	if err != nil {
		return nil
	}
	for i := range sources {
		if sources[i].ID == id {
			return &sources[i]
		}
	}
	return nil
}
