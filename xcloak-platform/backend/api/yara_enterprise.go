package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/services"
)

// ── GetYaraDashboard ──────────────────────────────────────────────────────

func GetYaraDashboard(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB

	var total, enabled, disabled int
	var matchesToday, matchesWeek, matchesTotal int
	var filesDetected, agentsTriggered int

	db.QueryRow(`SELECT COUNT(*), SUM(CASE WHEN enabled THEN 1 ELSE 0 END), SUM(CASE WHEN NOT enabled THEN 1 ELSE 0 END) FROM yara_rules WHERE tenant_id=$1`, tid).
		Scan(&total, &enabled, &disabled)

	db.QueryRow(`SELECT COUNT(*) FROM yara_matches WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '24 hours'`, tid).Scan(&matchesToday)
	db.QueryRow(`SELECT COUNT(*) FROM yara_matches WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '7 days'`, tid).Scan(&matchesWeek)
	db.QueryRow(`SELECT COUNT(*) FROM yara_matches WHERE tenant_id=$1`, tid).Scan(&matchesTotal)
	db.QueryRow(`SELECT COUNT(DISTINCT file_path) FROM yara_matches WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '7 days'`, tid).Scan(&filesDetected)
	db.QueryRow(`SELECT COUNT(DISTINCT agent_id) FROM yara_matches WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '7 days'`, tid).Scan(&agentsTriggered)

	type SevCount struct {
		Severity string `json:"severity"`
		Count    int    `json:"count"`
	}
	sevBreakdown := []SevCount{}
	srows, err := db.Query(`SELECT severity, COUNT(*) FROM yara_matches WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '7 days' GROUP BY severity ORDER BY 2 DESC`, tid)
	if err == nil {
		defer srows.Close()
		for srows.Next() {
			var sc SevCount
			if srows.Scan(&sc.Severity, &sc.Count) == nil {
				sevBreakdown = append(sevBreakdown, sc)
			}
		}
	}
	if sevBreakdown == nil {
		sevBreakdown = []SevCount{}
	}

	type TopRule struct {
		RuleName string `json:"rule_name"`
		Matches  int    `json:"matches"`
		Matches24h int  `json:"matches_24h"`
		Severity string `json:"severity"`
	}
	topRules := []TopRule{}
	tr, err := db.Query(`
		SELECT rule_name, severity, COUNT(*) matches,
		       COUNT(*) FILTER (WHERE created_at>=NOW()-INTERVAL '24 hours') matches_24h
		FROM yara_matches WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '7 days'
		GROUP BY rule_name, severity ORDER BY matches DESC LIMIT 10`, tid)
	if err == nil {
		defer tr.Close()
		for tr.Next() {
			var r TopRule
			if tr.Scan(&r.RuleName, &r.Severity, &r.Matches, &r.Matches24h) == nil {
				topRules = append(topRules, r)
			}
		}
	}
	if topRules == nil {
		topRules = []TopRule{}
	}

	type DayMatch struct {
		Date  string `json:"date"`
		Count int    `json:"count"`
	}
	trend := []DayMatch{}
	trows, err := db.Query(`
		SELECT DATE(created_at AT TIME ZONE 'UTC'), COUNT(*)
		FROM yara_matches WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '14 days'
		GROUP BY 1 ORDER BY 1`, tid)
	if err == nil {
		defer trows.Close()
		for trows.Next() {
			var d DayMatch
			if trows.Scan(&d.Date, &d.Count) == nil {
				trend = append(trend, d)
			}
		}
	}
	if trend == nil {
		trend = []DayMatch{}
	}

	type RecentMatch struct {
		RuleName  string `json:"rule_name"`
		FilePath  string `json:"file_path"`
		Severity  string `json:"severity"`
		AgentID   int    `json:"agent_id"`
		CreatedAt string `json:"created_at"`
	}
	recent := []RecentMatch{}
	rrows, err := db.Query(`
		SELECT rule_name, file_path, severity, agent_id, created_at::TEXT
		FROM yara_matches WHERE tenant_id=$1 ORDER BY id DESC LIMIT 8`, tid)
	if err == nil {
		defer rrows.Close()
		for rrows.Next() {
			var rm RecentMatch
			if rrows.Scan(&rm.RuleName, &rm.FilePath, &rm.Severity, &rm.AgentID, &rm.CreatedAt) == nil {
				recent = append(recent, rm)
			}
		}
	}
	if recent == nil {
		recent = []RecentMatch{}
	}

	c.JSON(http.StatusOK, gin.H{
		"total":             total,
		"enabled":           enabled,
		"disabled":          disabled,
		"matches_today":     matchesToday,
		"matches_week":      matchesWeek,
		"matches_total":     matchesTotal,
		"files_detected":    filesDetected,
		"agents_triggered":  agentsTriggered,
		"sev_breakdown":     sevBreakdown,
		"top_rules":         topRules,
		"trend":             trend,
		"recent_matches":    recent,
	})
}

// ── GetYaraAnalytics ──────────────────────────────────────────────────────

func GetYaraAnalytics(c *gin.Context) {
	tid := tenantIDFromContext(c)

	type RuleStat struct {
		RuleName   string  `json:"rule_name"`
		Total      int     `json:"total"`
		Last7d     int     `json:"last_7d"`
		Last24h    int     `json:"last_24h"`
		LastMatch  *string `json:"last_match"`
		TopSev     string  `json:"top_severity"`
	}
	rows, err := database.DB.Query(`
		SELECT rule_name,
		       COUNT(*) total,
		       COUNT(*) FILTER (WHERE created_at>=NOW()-INTERVAL '7 days')  last_7d,
		       COUNT(*) FILTER (WHERE created_at>=NOW()-INTERVAL '24 hours') last_24h,
		       MAX(created_at)::TEXT last_match,
		       mode() WITHIN GROUP (ORDER BY severity) top_sev
		FROM yara_matches WHERE tenant_id=$1
		GROUP BY rule_name ORDER BY total DESC LIMIT 100`, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	stats := []RuleStat{}
	for rows.Next() {
		var rs RuleStat
		if rows.Scan(&rs.RuleName, &rs.Total, &rs.Last7d, &rs.Last24h, &rs.LastMatch, &rs.TopSev) == nil {
			stats = append(stats, rs)
		}
	}
	if stats == nil {
		stats = []RuleStat{}
	}

	type DayTotal struct {
		Date  string `json:"date"`
		Count int    `json:"count"`
	}
	daily := []DayTotal{}
	drows, err := database.DB.Query(`
		SELECT DATE(created_at AT TIME ZONE 'UTC'), COUNT(*)
		FROM yara_matches WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '30 days'
		GROUP BY 1 ORDER BY 1`, tid)
	if err == nil {
		defer drows.Close()
		for drows.Next() {
			var d DayTotal
			if drows.Scan(&d.Date, &d.Count) == nil {
				daily = append(daily, d)
			}
		}
	}
	if daily == nil {
		daily = []DayTotal{}
	}

	type AgentStat struct {
		AgentID   int    `json:"agent_id"`
		AgentName string `json:"agent_name"`
		Matches   int    `json:"matches"`
	}
	agentStats := []AgentStat{}
	arows, err := database.DB.Query(`
		SELECT m.agent_id, COALESCE(a.hostname, a.name, 'Agent '||m.agent_id::text), COUNT(m.id)
		FROM yara_matches m
		LEFT JOIN agents a ON a.id=m.agent_id
		WHERE m.tenant_id=$1 AND m.created_at>=NOW()-INTERVAL '7 days'
		GROUP BY m.agent_id, 2 ORDER BY 3 DESC LIMIT 10`, tid)
	if err == nil {
		defer arows.Close()
		for arows.Next() {
			var as AgentStat
			if arows.Scan(&as.AgentID, &as.AgentName, &as.Matches) == nil {
				agentStats = append(agentStats, as)
			}
		}
	}
	if agentStats == nil {
		agentStats = []AgentStat{}
	}

	c.JSON(http.StatusOK, gin.H{
		"rules":       stats,
		"daily":       daily,
		"top_agents":  agentStats,
	})
}

// ── GetYaraCategories ─────────────────────────────────────────────────────
// Extracts rule category from YARA rule_content meta block (e.g. meta: malware_type = "ransomware")
// Falls back to keyword-based classification.

var yaraMetaRe = regexp.MustCompile(`(?i)(?:malware_type|category|type)\s*=\s*"([^"]+)"`)
var yaraTagsRe = regexp.MustCompile(`(?i)tags\s*=\s*\[([^\]]+)\]`)

func classifyYaraRule(content string) string {
	if m := yaraMetaRe.FindStringSubmatch(content); len(m) > 1 {
		return strings.ToLower(strings.TrimSpace(m[1]))
	}
	lower := strings.ToLower(content)
	for _, kw := range []struct{ word, cat string }{
		{"ransomware", "ransomware"}, {"ransom", "ransomware"},
		{"trojan", "trojan"}, {"backdoor", "backdoor"},
		{"rootkit", "rootkit"}, {"webshell", "webshell"}, {"web_shell", "webshell"},
		{"loader", "loader"}, {"dropper", "loader"},
		{"cryptominer", "cryptominer"}, {"miner", "cryptominer"},
		{"spyware", "spyware"}, {"keylogger", "spyware"},
		{"worm", "worm"}, {"botnet", "botnet"},
		{"lsass", "credential"}, {"mimikatz", "credential"},
		{"shellcode", "shellcode"}, {"injec", "injection"},
		{"pdf", "document"}, {"office", "document"}, {"docx", "document"}, {"macro", "document"},
		{"script", "script"}, {"powershell", "script"}, {"vbs", "script"},
		{"packer", "packer"}, {"upx", "packer"},
		{"linux", "linux"}, {"macho", "macos"},
	} {
		if strings.Contains(lower, kw.word) {
			return kw.cat
		}
	}
	return "unknown"
}

func GetYaraCategories(c *gin.Context) {
	tid := tenantIDFromContext(c)

	rows, err := database.DB.Query(`SELECT id, name, rule_content, enabled FROM yara_rules WHERE tenant_id=$1`, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type CatItem struct {
		ID      int    `json:"id"`
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	catMap := map[string][]CatItem{}
	for rows.Next() {
		var id int
		var name, content string
		var enabled bool
		if rows.Scan(&id, &name, &content, &enabled) == nil {
			cat := classifyYaraRule(content)
			catMap[cat] = append(catMap[cat], CatItem{ID: id, Name: name, Enabled: enabled})
		}
	}

	type CatGroup struct {
		Category string    `json:"category"`
		Total    int       `json:"total"`
		Enabled  int       `json:"enabled"`
		Rules    []CatItem `json:"rules"`
	}
	cats := []CatGroup{}
	for cat, items := range catMap {
		enabled := 0
		for _, it := range items {
			if it.Enabled {
				enabled++
			}
		}
		cats = append(cats, CatGroup{Category: cat, Total: len(items), Enabled: enabled, Rules: items})
	}

	c.JSON(http.StatusOK, gin.H{"categories": cats})
}

// ── GetYaraPerformance ────────────────────────────────────────────────────

func GetYaraPerformance(c *gin.Context) {
	tid := tenantIDFromContext(c)

	var totalMatches, matchesHour, matchesDay, matchesWeek int
	database.DB.QueryRow(`SELECT COUNT(*) FROM yara_matches WHERE tenant_id=$1`, tid).Scan(&totalMatches)
	database.DB.QueryRow(`SELECT COUNT(*) FROM yara_matches WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '1 hour'`, tid).Scan(&matchesHour)
	database.DB.QueryRow(`SELECT COUNT(*) FROM yara_matches WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '24 hours'`, tid).Scan(&matchesDay)
	database.DB.QueryRow(`SELECT COUNT(*) FROM yara_matches WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '7 days'`, tid).Scan(&matchesWeek)

	type HourlyBucket struct {
		Hour  string `json:"hour"`
		Count int    `json:"count"`
	}
	hourly := []HourlyBucket{}
	hrows, err := database.DB.Query(`
		SELECT DATE_TRUNC('hour', created_at AT TIME ZONE 'UTC'), COUNT(*)
		FROM yara_matches WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '24 hours'
		GROUP BY 1 ORDER BY 1`, tid)
	if err == nil {
		defer hrows.Close()
		for hrows.Next() {
			var h HourlyBucket
			if hrows.Scan(&h.Hour, &h.Count) == nil {
				hourly = append(hourly, h)
			}
		}
	}
	if hourly == nil {
		hourly = []HourlyBucket{}
	}

	type FileHit struct {
		FilePath string `json:"file_path"`
		Matches  int    `json:"matches"`
		RuleNames string `json:"rule_names"`
	}
	topFiles := []FileHit{}
	frows, err := database.DB.Query(`
		SELECT file_path, COUNT(*), STRING_AGG(DISTINCT rule_name, ', ' ORDER BY rule_name) rule_names
		FROM yara_matches WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '7 days'
		GROUP BY file_path ORDER BY 2 DESC LIMIT 10`, tid)
	if err == nil {
		defer frows.Close()
		for frows.Next() {
			var fh FileHit
			if frows.Scan(&fh.FilePath, &fh.Matches, &fh.RuleNames) == nil {
				topFiles = append(topFiles, fh)
			}
		}
	}
	if topFiles == nil {
		topFiles = []FileHit{}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_matches":  totalMatches,
		"matches_hour":   matchesHour,
		"matches_day":    matchesDay,
		"matches_week":   matchesWeek,
		"hourly":         hourly,
		"top_files":      topFiles,
	})
}

// ── GetYaraRelationships ──────────────────────────────────────────────────

func GetYaraRelationships(c *gin.Context) {
	tid := tenantIDFromContext(c)

	type RelNode struct {
		ID    string `json:"id"`
		Label string `json:"label"`
		Type  string `json:"type"`
		Value int    `json:"value"`
	}
	type RelEdge struct {
		Source string `json:"source"`
		Target string `json:"target"`
		Weight int    `json:"weight"`
	}

	nodes := []RelNode{}
	edges := []RelEdge{}

	// Top rules by recent matches
	rows, err := database.DB.Query(`
		SELECT rule_name, COUNT(*) cnt
		FROM yara_matches WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '7 days'
		GROUP BY rule_name ORDER BY cnt DESC LIMIT 12`, tid)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name string
			var cnt int
			if rows.Scan(&name, &cnt) == nil {
				nodes = append(nodes, RelNode{ID: "rule_" + name, Label: name, Type: "rule", Value: cnt})
			}
		}
	}

	// Agents involved
	arows, err := database.DB.Query(`
		SELECT DISTINCT m.agent_id, COALESCE(a.hostname, a.name, 'Agent '||m.agent_id::text), COUNT(m.id)
		FROM yara_matches m
		LEFT JOIN agents a ON a.id=m.agent_id
		WHERE m.tenant_id=$1 AND m.created_at>=NOW()-INTERVAL '7 days'
		GROUP BY m.agent_id, 2 ORDER BY 3 DESC LIMIT 8`, tid)
	if err == nil {
		defer arows.Close()
		agentSeen := map[int]bool{}
		for arows.Next() {
			var agentID, cnt int
			var agentName string
			if arows.Scan(&agentID, &agentName, &cnt) == nil {
				if !agentSeen[agentID] {
					nodes = append(nodes, RelNode{ID: fmt.Sprintf("agent_%d", agentID), Label: agentName, Type: "agent", Value: cnt})
					agentSeen[agentID] = true
				}
			}
		}
	}

	// Rule → agent edges
	erows, err := database.DB.Query(`
		SELECT rule_name, agent_id, COUNT(*) cnt
		FROM yara_matches WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '7 days'
		GROUP BY rule_name, agent_id ORDER BY cnt DESC LIMIT 30`, tid)
	if err == nil {
		defer erows.Close()
		for erows.Next() {
			var ruleName string
			var agentID, cnt int
			if erows.Scan(&ruleName, &agentID, &cnt) == nil {
				edges = append(edges, RelEdge{
					Source: "rule_" + ruleName,
					Target: fmt.Sprintf("agent_%d", agentID),
					Weight: cnt,
				})
			}
		}
	}

	// File nodes (top matched files)
	frows, err := database.DB.Query(`
		SELECT DISTINCT file_path, COUNT(*) cnt
		FROM yara_matches WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '7 days'
		GROUP BY file_path ORDER BY cnt DESC LIMIT 6`, tid)
	if err == nil {
		defer frows.Close()
		for frows.Next() {
			var fp string
			var cnt int
			if frows.Scan(&fp, &cnt) == nil {
				short := fp
				if idx := strings.LastIndex(fp, "/"); idx >= 0 {
					short = fp[idx+1:]
				} else if idx = strings.LastIndex(fp, "\\"); idx >= 0 {
					short = fp[idx+1:]
				}
				nodes = append(nodes, RelNode{ID: "file_" + fp, Label: short, Type: "file", Value: cnt})
			}
		}
	}

	// Rule → file edges
	rfrows, err := database.DB.Query(`
		SELECT rule_name, file_path, COUNT(*) cnt
		FROM yara_matches WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '7 days'
		GROUP BY rule_name, file_path ORDER BY cnt DESC LIMIT 20`, tid)
	if err == nil {
		defer rfrows.Close()
		for rfrows.Next() {
			var ruleName, fp string
			var cnt int
			if rfrows.Scan(&ruleName, &fp, &cnt) == nil {
				edges = append(edges, RelEdge{
					Source: "rule_" + ruleName,
					Target: "file_" + fp,
					Weight: cnt,
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"nodes": nodes, "edges": edges})
}

// ── PostYaraAI ────────────────────────────────────────────────────────────

func PostYaraAI(c *gin.Context) {
	tid := tenantIDFromContext(c)

	var body struct {
		Action      string `json:"action"`
		RuleID      int    `json:"rule_id"`
		RuleContent string `json:"rule_content"`
		Prompt      string `json:"prompt"`
		Context     string `json:"context"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Fetch rule content if rule_id provided
	ruleContent := body.RuleContent
	ruleName := ""
	if ruleContent == "" && body.RuleID > 0 {
		database.DB.QueryRow(`SELECT name, rule_content FROM yara_rules WHERE id=$1 AND tenant_id=$2`, body.RuleID, tid).
			Scan(&ruleName, &ruleContent)
	}

	var prompt string
	switch body.Action {
	case "generate":
		prompt = fmt.Sprintf(`You are a YARA rule expert and malware analyst. Generate a complete, valid YARA rule for the following detection requirement:

%s

Additional context: %s

Requirements:
- Use valid YARA syntax
- Include a meta section with: description, author="XCloak AI", date (today), version="1.0"
- Include meaningful string definitions
- Use appropriate condition logic
- Add comments explaining key detections

Return ONLY the YARA rule text, no explanation.`, body.Prompt, body.Context)

	case "explain":
		prompt = fmt.Sprintf(`You are a YARA rule expert. Explain the following YARA rule in detail.

YARA Rule:
%s

Provide:
1. What malware or threat this rule detects
2. How the string definitions work (hex patterns, text strings, regex)
3. What the condition logic means
4. The confidence level and potential false positives
5. How to improve or extend this rule

Return JSON: {"summary": "...", "threat": "...", "strings_explained": "...", "condition_explained": "...", "false_positives": "...", "improvements": "..."}`, ruleContent)

	case "optimize":
		prompt = fmt.Sprintf(`You are a YARA rule expert. Analyze this YARA rule and suggest optimizations for better performance and accuracy.

YARA Rule:
%s

Context: %s

Return JSON: {"issues": ["..."], "performance_tips": ["..."], "accuracy_improvements": ["..."], "optimized_rule": "...", "fp_risk": "low|medium|high"}`, ruleContent, body.Context)

	case "suggest_strings":
		prompt = fmt.Sprintf(`You are a malware analyst. For the following YARA rule, suggest additional detection strings that could improve coverage.

YARA Rule:
%s

Suggest:
- Additional hex byte patterns
- Additional plaintext strings
- Regex patterns
- Encoded variants

Return JSON: {"suggested_strings": [{"name": "...", "value": "...", "type": "text|hex|regex", "rationale": "..."}], "coverage_notes": "..."}`, ruleContent)

	case "fp_analysis":
		prompt = fmt.Sprintf(`You are a YARA rule expert. Analyze this YARA rule for potential false positives.

YARA Rule:
%s

Context: %s

Return JSON: {"fp_scenarios": [{"scenario": "...", "likelihood": "low|medium|high", "mitigation": "..."}], "overall_fp_risk": "low|medium|high", "tuning_recommendations": ["..."]}`, ruleContent, body.Context)

	case "generate_metadata":
		prompt = fmt.Sprintf(`You are a YARA rule expert. Generate a complete metadata block for the following YARA rule based on its content.

YARA Rule:
%s

Return JSON: {"name": "...", "description": "...", "malware_family": "...", "malware_type": "...", "threat_actor": "...", "severity": "critical|high|medium|low", "confidence": "high|medium|low", "references": ["..."]}`, ruleContent)

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown action: " + body.Action})
		return
	}

	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Strip markdown fences
	if idx := strings.Index(raw, "```json"); idx != -1 {
		raw = raw[idx+7:]
	} else if idx := strings.Index(raw, "```yara"); idx != -1 {
		raw = raw[idx+7:]
	} else if idx := strings.Index(raw, "```"); idx != -1 {
		raw = raw[idx+3:]
	}
	if idx := strings.LastIndex(raw, "```"); idx != -1 {
		raw = raw[:idx]
	}
	raw = strings.TrimSpace(raw)

	if body.Action == "generate" {
		c.JSON(http.StatusOK, gin.H{"rule": raw, "action": "generate"})
		return
	}

	c.Data(http.StatusOK, "application/json", []byte(raw))
}

// ── PostYaraBulk ──────────────────────────────────────────────────────────

func PostYaraBulk(c *gin.Context) {
	tid := tenantIDFromContext(c)

	var body struct {
		Action  string `json:"action"` // enable, disable, delete
		RuleIDs []int  `json:"rule_ids"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(body.RuleIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no rule_ids provided"})
		return
	}

	args := []interface{}{tid}
	placeholders := make([]string, len(body.RuleIDs))
	for i, id := range body.RuleIDs {
		args = append(args, id)
		placeholders[i] = fmt.Sprintf("$%d", i+2)
	}
	inClause := strings.Join(placeholders, ",")

	var query string
	switch body.Action {
	case "enable":
		query = fmt.Sprintf(`UPDATE yara_rules SET enabled=true WHERE tenant_id=$1 AND id IN (%s)`, inClause)
	case "disable":
		query = fmt.Sprintf(`UPDATE yara_rules SET enabled=false WHERE tenant_id=$1 AND id IN (%s)`, inClause)
	case "delete":
		query = fmt.Sprintf(`DELETE FROM yara_rules WHERE tenant_id=$1 AND id IN (%s)`, inClause)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown action: " + body.Action})
		return
	}

	result, err := database.DB.Exec(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	affected, _ := result.RowsAffected()
	c.JSON(http.StatusOK, gin.H{"affected": affected, "action": body.Action})
}

// ── PostYaraExport ────────────────────────────────────────────────────────

func PostYaraExport(c *gin.Context) {
	tid := tenantIDFromContext(c)

	var body struct {
		Format  string `json:"format"`   // yar, json
		RuleIDs []int  `json:"rule_ids"` // empty = all enabled
		All     bool   `json:"all"`      // if true, export all (incl disabled)
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Format == "" {
		body.Format = "yar"
	}

	var rows interface {
		Close() error
		Next() bool
		Scan(...interface{}) error
	}
	var err error

	if len(body.RuleIDs) > 0 {
		args := []interface{}{tid}
		phs := make([]string, len(body.RuleIDs))
		for i, id := range body.RuleIDs {
			args = append(args, id)
			phs[i] = fmt.Sprintf("$%d", i+2)
		}
		rows, err = database.DB.Query(
			fmt.Sprintf(`SELECT id, name, description, rule_content, enabled, created_at FROM yara_rules WHERE tenant_id=$1 AND id IN (%s) ORDER BY id`, strings.Join(phs, ",")),
			args...)
	} else if body.All {
		rows, err = database.DB.Query(`SELECT id, name, description, rule_content, enabled, created_at FROM yara_rules WHERE tenant_id=$1 ORDER BY id`, tid)
	} else {
		rows, err = database.DB.Query(`SELECT id, name, description, rule_content, enabled, created_at FROM yara_rules WHERE tenant_id=$1 AND enabled=true ORDER BY id`, tid)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type ExportRule struct {
		ID          int       `json:"id"`
		Name        string    `json:"name"`
		Description string    `json:"description"`
		RuleContent string    `json:"rule_content"`
		Enabled     bool      `json:"enabled"`
		CreatedAt   time.Time `json:"created_at"`
	}
	rules := []ExportRule{}
	for rows.Next() {
		var r ExportRule
		if rows.Scan(&r.ID, &r.Name, &r.Description, &r.RuleContent, &r.Enabled, &r.CreatedAt) == nil {
			rules = append(rules, r)
		}
	}
	if rules == nil {
		rules = []ExportRule{}
	}

	fname := fmt.Sprintf("yara_rules_%s", time.Now().Format("20060102"))

	if body.Format == "yar" {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("// XCloak YARA Export — %s\n// Rules: %d\n\n", time.Now().Format(time.RFC3339), len(rules)))
		for _, r := range rules {
			if r.Description != "" {
				sb.WriteString(fmt.Sprintf("// %s\n", r.Description))
			}
			sb.WriteString(r.RuleContent)
			sb.WriteString("\n\n")
		}
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.yar"`, fname))
		c.Data(http.StatusOK, "text/plain", []byte(sb.String()))
		return
	}

	b, _ := json.Marshal(rules)
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, fname))
	c.Data(http.StatusOK, "application/json", b)
}

// ── GetYaraRuleDetail ─────────────────────────────────────────────────────

func GetYaraRuleDetail(c *gin.Context) {
	tid := tenantIDFromContext(c)
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	var name, description, content string
	var enabled bool
	var createdAt time.Time
	err = database.DB.QueryRow(`SELECT name, description, rule_content, enabled, created_at FROM yara_rules WHERE id=$1 AND tenant_id=$2`, id, tid).
		Scan(&name, &description, &content, &enabled, &createdAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	var matchCount, matchCount24h, matchCount7d int
	var lastMatch *string
	database.DB.QueryRow(`SELECT COUNT(*), COUNT(*) FILTER (WHERE created_at>=NOW()-INTERVAL '24 hours'), COUNT(*) FILTER (WHERE created_at>=NOW()-INTERVAL '7 days'), MAX(created_at)::TEXT FROM yara_matches WHERE rule_name=$1 AND tenant_id=$2`, name, tid).
		Scan(&matchCount, &matchCount24h, &matchCount7d, &lastMatch)

	type RecentHit struct {
		FilePath  string `json:"file_path"`
		Severity  string `json:"severity"`
		AgentID   int    `json:"agent_id"`
		FileHash  string `json:"file_hash"`
		CreatedAt string `json:"created_at"`
	}
	recentHits := []RecentHit{}
	rrows, err := database.DB.Query(`SELECT file_path, severity, agent_id, file_hash, created_at::TEXT FROM yara_matches WHERE rule_name=$1 AND tenant_id=$2 ORDER BY id DESC LIMIT 15`, name, tid)
	if err == nil {
		defer rrows.Close()
		for rrows.Next() {
			var rh RecentHit
			if rrows.Scan(&rh.FilePath, &rh.Severity, &rh.AgentID, &rh.FileHash, &rh.CreatedAt) == nil {
				recentHits = append(recentHits, rh)
			}
		}
	}
	if recentHits == nil {
		recentHits = []RecentHit{}
	}

	c.JSON(http.StatusOK, gin.H{
		"id": id, "name": name, "description": description,
		"rule_content": content, "enabled": enabled, "created_at": createdAt,
		"category":      classifyYaraRule(content),
		"match_count":   matchCount,
		"match_24h":     matchCount24h,
		"match_7d":      matchCount7d,
		"last_match":    lastMatch,
		"recent_hits":   recentHits,
	})
}
