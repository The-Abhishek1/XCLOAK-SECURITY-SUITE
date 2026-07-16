package api

import (
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
	"xcloak-platform/services"
)

// ─────────────────────────────────────────────────────────────────────────────
// Field Explorer — GET /api/logs/fields
// ─────────────────────────────────────────────────────────────────────────────

type FieldMeta struct {
	Name        string         `json:"name"`
	Type        string         `json:"type"`
	Count       int64          `json:"count"`
	NullCount   int64          `json:"null_count"`
	UniqueCount int64          `json:"unique_count"`
	TopValues   []FieldTopVal  `json:"top_values"`
}

type FieldTopVal struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

func GetLogFields(c *gin.Context) {
	tenantID := tenantIDFromContext(c)

	// Total logs for null count calculation
	var totalLogs int64
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id WHERE a.tenant_id = $1
	`, tenantID).Scan(&totalLogs)

	// Enumerate keys from parsed_fields JSONB + count non-null
	type rawField struct {
		Name        string
		Count       int64
		UniqueCount int64
	}
	var rawFields []rawField
	rows, err := database.DB.Query(`
		SELECT kv.key,
		       COUNT(*) AS cnt,
		       COUNT(DISTINCT kv.value) AS unique_cnt
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id,
		LATERAL jsonb_each_text(el.parsed_fields) AS kv(key, value)
		WHERE a.tenant_id = $1 AND el.parsed_fields IS NOT NULL
		GROUP BY kv.key
		ORDER BY cnt DESC
		LIMIT 60
	`, tenantID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var f rawField
			if rows.Scan(&f.Name, &f.Count, &f.UniqueCount) == nil {
				rawFields = append(rawFields, f)
			}
		}
	}

	// Infer types from well-known field names
	typeOf := func(name string) string {
		n := strings.ToLower(name)
		switch {
		case strings.HasSuffix(n, "_ip") || n == "src" || n == "dst":
			return "ip"
		case strings.HasSuffix(n, "_port") || n == "pid" || n == "event_id":
			return "number"
		case strings.Contains(n, "time") || strings.Contains(n, "ts") || strings.Contains(n, "at"):
			return "date"
		case n == "user" || n == "username" || n == "target_user" || n == "subject_user":
			return "keyword"
		case n == "domain" || n == "url" || n == "hostname":
			return "keyword"
		default:
			return "text"
		}
	}

	result := make([]FieldMeta, 0, len(rawFields))
	for _, rf := range rawFields {
		fm := FieldMeta{
			Name:        rf.Name,
			Type:        typeOf(rf.Name),
			Count:       rf.Count,
			NullCount:   totalLogs - rf.Count,
			UniqueCount: rf.UniqueCount,
		}
		// Top 5 values per field
		tvRows, err2 := database.DB.Query(`
			SELECT COALESCE(parsed_fields->>$2, '') as val, COUNT(*) as cnt
			FROM endpoint_logs el
			JOIN agents a ON a.id = el.agent_id
			WHERE a.tenant_id = $1 AND parsed_fields->>$2 IS NOT NULL AND parsed_fields->>$2 != ''
			GROUP BY val ORDER BY cnt DESC LIMIT 5
		`, tenantID, rf.Name)
		if err2 == nil {
			defer tvRows.Close()
			for tvRows.Next() {
				var tv FieldTopVal
				if tvRows.Scan(&tv.Value, &tv.Count) == nil {
					fm.TopValues = append(fm.TopValues, tv)
				}
			}
		}
		result = append(result, fm)
	}

	// Always include built-in fields if not already present
	builtin := []string{"log_source", "log_message", "collected_at"}
	for _, b := range builtin {
		found := false
		for _, r := range result {
			if r.Name == b {
				found = true
				break
			}
		}
		if !found {
			result = append(result, FieldMeta{Name: b, Type: "keyword", Count: totalLogs})
		}
	}

	c.JSON(200, gin.H{"fields": result, "total_docs": totalLogs})
}

// ─────────────────────────────────────────────────────────────────────────────
// AI Query — POST /api/logs/ai-query
// Natural language → KQL
// ─────────────────────────────────────────────────────────────────────────────

func AIQuery(c *gin.Context) {
	var body struct {
		Question string `json:"question"`
		Language string `json:"language"` // kql | lucene | sql | dsl
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Question == "" {
		c.JSON(400, gin.H{"error": "question required"})
		return
	}
	lang := body.Language
	if lang == "" {
		lang = "kql"
	}

	langDesc := map[string]string{
		"kql":    "KQL (Kibana Query Language with field:value syntax, AND/OR/NOT, wildcards)",
		"lucene": "Lucene query syntax",
		"sql":    "SQL SELECT against a table named 'logs' with columns: log_message, log_source, collected_at, parsed_fields (jsonb)",
		"dsl":    "Elasticsearch Query DSL JSON",
	}[lang]
	if langDesc == "" {
		langDesc = "KQL (field:value syntax)"
	}

	prompt := fmt.Sprintf(`You are a SIEM query expert. Convert this natural language question into a %s query for a security log search system.

Available fields in parsed_fields: user, target_user, subject_user, src_ip, dst_ip, src_port, dst_port, hostname, process, pid, event_id, auth_result, auth_method, severity, domain, url, logon_type.
The main log table has: log_message (text), log_source (text), collected_at (timestamp).

Question: %s

Reply with ONLY the query string, no explanation, no markdown code blocks, no quotes wrapping it. Just the raw query.`,
		langDesc, body.Question)

	query, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": "AI service unavailable"})
		return
	}
	// Strip any accidental markdown fences
	query = strings.TrimSpace(query)
	query = strings.TrimPrefix(query, "```kql")
	query = strings.TrimPrefix(query, "```sql")
	query = strings.TrimPrefix(query, "```json")
	query = strings.TrimPrefix(query, "```")
	query = strings.TrimSuffix(query, "```")
	query = strings.TrimSpace(query)

	c.JSON(200, gin.H{"query": query, "language": lang})
}

// ─────────────────────────────────────────────────────────────────────────────
// AI Explain — POST /api/logs/ai-explain
// Explain search results or a single log
// ─────────────────────────────────────────────────────────────────────────────

func AIExplainResults(c *gin.Context) {
	var body struct {
		Query    string   `json:"query"`
		HitCount int      `json:"hit_count"`
		Samples  []string `json:"samples"` // up to 10 log messages
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}
	samples := body.Samples
	if len(samples) > 10 {
		samples = samples[:10]
	}
	sampleStr := strings.Join(samples, "\n")

	prompt := fmt.Sprintf(`You are a SOC analyst assistant. Explain these search results concisely.

Search query: %s
Total matches: %d
Sample log lines:
%s

Explain in 3-5 bullet points:
• What events these logs describe
• Why they may be security-relevant
• Patterns or anomalies you notice
• Recommended analyst actions

Be concise and direct.`, body.Query, body.HitCount, sampleStr)

	explanation, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": "AI service unavailable"})
		return
	}
	c.JSON(200, gin.H{"explanation": explanation})
}

// ─────────────────────────────────────────────────────────────────────────────
// Search Templates — GET /api/logs/templates
// ─────────────────────────────────────────────────────────────────────────────

type SearchTemplate struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Query       string `json:"query"`
	TimeRange   string `json:"time_range"`
	Tags        []string `json:"tags"`
}

var builtinTemplates = []SearchTemplate{
	{
		ID: "failed-logins", Name: "Failed Logins", Category: "Authentication",
		Description: "All authentication failures across all sources",
		Query: `auth_result:failure OR auth_result:failed OR "authentication failure" OR event_id:4625`,
		TimeRange: "24h", Tags: []string{"auth", "brute-force"},
	},
	{
		ID: "ransomware-hunt", Name: "Ransomware Hunt", Category: "Threat Hunting",
		Description: "Detect ransomware precursors: shadow copy deletion, encryption activity",
		Query: `"vssadmin delete shadows" OR "wmic shadowcopy delete" OR "bcdedit /set" OR ".encrypted" OR ".locky" OR "ransom"`,
		TimeRange: "7d", Tags: []string{"ransomware", "threat-hunting"},
	},
	{
		ID: "dns-tunneling", Name: "DNS Tunneling", Category: "Network",
		Description: "Unusually long DNS queries or high-frequency DNS to same domain (C2 indicators)",
		Query: `log_source:named OR log_source:dns AND ("IN A" OR "IN TXT" OR "IN NULL")`,
		TimeRange: "24h", Tags: []string{"dns", "c2", "exfiltration"},
	},
	{
		ID: "suspicious-powershell", Name: "Suspicious PowerShell", Category: "Endpoint",
		Description: "Encoded, obfuscated, or hidden PowerShell execution",
		Query: `("-EncodedCommand" OR "-enc " OR "-nop -w hidden" OR "IEX(" OR "Invoke-Expression" OR "DownloadString") AND process:powershell`,
		TimeRange: "24h", Tags: []string{"powershell", "lolbas"},
	},
	{
		ID: "kerberoasting", Name: "Kerberoasting", Category: "Authentication",
		Description: "Service ticket requests that may indicate Kerberoasting attacks",
		Query: `event_id:4769 OR "Kerberos Service Ticket Request" OR "etype:0x17"`,
		TimeRange: "24h", Tags: []string{"kerberos", "privilege-escalation"},
	},
	{
		ID: "beaconing", Name: "C2 Beaconing", Category: "Network",
		Description: "Regular outbound connections to external IPs (C2 beacon patterns)",
		Query: `"cobalt strike" OR "beacon" OR log_source:suricata AND "ET MALWARE"`,
		TimeRange: "24h", Tags: []string{"c2", "malware"},
	},
	{
		ID: "privilege-escalation", Name: "Privilege Escalation", Category: "Endpoint",
		Description: "Signs of privilege escalation: token impersonation, LSASS access, RunAs",
		Query: `event_id:4648 OR event_id:4672 OR "SeDebugPrivilege" OR "lsass.exe" OR "token impersonation"`,
		TimeRange: "24h", Tags: []string{"privilege-escalation", "credential-access"},
	},
	{
		ID: "lateral-movement", Name: "Lateral Movement", Category: "Endpoint",
		Description: "Detect lateral movement via PsExec, WMI, RDP, or pass-the-hash",
		Query: `"psexec" OR "wmiexec" OR logon_type:3 OR event_id:4648 OR "pass-the-hash"`,
		TimeRange: "24h", Tags: []string{"lateral-movement"},
	},
	{
		ID: "data-exfil", Name: "Data Exfiltration", Category: "Network",
		Description: "Large outbound transfers or uploads to cloud storage",
		Query: `"pastebin.com" OR "mega.nz" OR "dropbox.com" OR "PUT" OR "POST" AND dst_port:443 AND "bytes_out"`,
		TimeRange: "24h", Tags: []string{"exfiltration"},
	},
	{
		ID: "new-admin", Name: "New Admin Account", Category: "Authentication",
		Description: "New privileged user accounts or group membership changes",
		Query: `event_id:4720 OR event_id:4732 OR event_id:4728 OR "Administrators" OR "Domain Admins"`,
		TimeRange: "24h", Tags: []string{"persistence", "account"},
	},
}

func GetSearchTemplates(c *gin.Context) {
	c.JSON(200, gin.H{"templates": builtinTemplates})
}

// ─────────────────────────────────────────────────────────────────────────────
// Scheduled Searches — GET/POST /api/logs/scheduled
// ─────────────────────────────────────────────────────────────────────────────

type ScheduledSearch struct {
	ID        int       `json:"id"`
	TenantID  int       `json:"tenant_id,omitempty"`
	Name      string    `json:"name"`
	Query     string    `json:"query"`
	TimeRange string    `json:"time_range"`
	Schedule  string    `json:"schedule"` // hourly | daily | weekly
	Action    string    `json:"action"`   // alert | email | dashboard | playbook
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	LastRunAt *time.Time `json:"last_run_at,omitempty"`
}

func GetScheduledSearches(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	rows, err := database.DB.Query(`
		SELECT id, name, query, COALESCE(time_range,'24h'), COALESCE(schedule,'daily'),
		       COALESCE(action,'alert'), COALESCE(enabled, true), created_at, last_run_at
		FROM scheduled_log_searches WHERE tenant_id = $1 ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		c.JSON(200, gin.H{"searches": []any{}})
		return
	}
	defer rows.Close()
	var result []ScheduledSearch
	for rows.Next() {
		var s ScheduledSearch
		if rows.Scan(&s.ID, &s.Name, &s.Query, &s.TimeRange, &s.Schedule, &s.Action, &s.Enabled, &s.CreatedAt, &s.LastRunAt) == nil {
			result = append(result, s)
		}
	}
	if result == nil {
		result = []ScheduledSearch{}
	}
	c.JSON(200, gin.H{"searches": result})
}

func CreateScheduledSearch(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	var body ScheduledSearch
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(400, gin.H{"error": "name required"})
		return
	}
	if body.Schedule == "" {
		body.Schedule = "daily"
	}
	if body.Action == "" {
		body.Action = "alert"
	}
	if body.TimeRange == "" {
		body.TimeRange = "24h"
	}

	var id int
	err := database.DB.QueryRow(`
		INSERT INTO scheduled_log_searches (tenant_id, name, query, time_range, schedule, action, enabled, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,true,NOW())
		RETURNING id
	`, tenantID, body.Name, body.Query, body.TimeRange, body.Schedule, body.Action).Scan(&id)
	if err != nil {
		// Table might not exist in all deployments — return graceful 201
		c.JSON(201, gin.H{"id": 0, "name": body.Name, "message": "scheduled (persistence unavailable)"})
		return
	}
	body.ID = id
	body.TenantID = 0
	body.CreatedAt = time.Now()
	c.JSON(201, body)
}

func DeleteScheduledSearch(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	id := c.Param("id")
	_, err := database.DB.Exec(`DELETE FROM scheduled_log_searches WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}
	c.JSON(200, gin.H{"message": "deleted"})
}

// ─────────────────────────────────────────────────────────────────────────────
// Detection Builder — POST /api/logs/build-detection
// Generates a Sigma rule from a query + sample logs
// ─────────────────────────────────────────────────────────────────────────────

func BuildDetection(c *gin.Context) {
	var body struct {
		Type    string   `json:"type"`    // sigma | correlation | alert
		Query   string   `json:"query"`
		Name    string   `json:"name"`
		Samples []string `json:"samples"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}

	var prompt string
	switch body.Type {
	case "sigma":
		prompt = fmt.Sprintf(`You are a security detection engineer. Generate a Sigma rule for the following search query and sample logs.

Query: %s
Name: %s
Sample logs:
%s

Return ONLY valid Sigma YAML. No explanation. No markdown fences.`, body.Query, body.Name, strings.Join(body.Samples, "\n"))
	default:
		prompt = fmt.Sprintf(`Generate an alert rule definition in JSON for this query: %s (name: %s)`, body.Query, body.Name)
	}

	result, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": "AI service unavailable"})
		return
	}
	result = strings.TrimSpace(result)
	result = strings.TrimPrefix(result, "```yaml")
	result = strings.TrimPrefix(result, "```json")
	result = strings.TrimPrefix(result, "```")
	result = strings.TrimSuffix(result, "```")
	c.JSON(200, gin.H{"rule": strings.TrimSpace(result), "type": body.Type})
}
