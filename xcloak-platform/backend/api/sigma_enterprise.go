package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/services"
)

// ── GetSigmaDashboard ──────────────────────────────────────────────────────

func GetSigmaDashboard(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB

	var total, enabled, disabled int
	var critical, high, medium, low, info int
	var experimental, stable, testing int
	var triggeredToday, triggeredWeek, totalHitsToday int
	var tacticCount, techniqueCount int

	db.QueryRow(`SELECT COUNT(*), SUM(CASE WHEN enabled THEN 1 ELSE 0 END), SUM(CASE WHEN NOT enabled THEN 1 ELSE 0 END) FROM sigma_rules WHERE tenant_id=$1`, tid).Scan(&total, &enabled, &disabled)

	rows, err := db.Query(`SELECT severity, COUNT(*) FROM sigma_rules WHERE tenant_id=$1 GROUP BY severity`, tid)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sev string
			var cnt int
			if rows.Scan(&sev, &cnt) == nil {
				switch strings.ToLower(sev) {
				case "critical":
					critical = cnt
				case "high":
					high = cnt
				case "medium":
					medium = cnt
				case "low":
					low = cnt
				case "info", "informational":
					info = cnt
				}
			}
		}
	}

	srows, err := db.Query(`SELECT status, COUNT(*) FROM sigma_rules WHERE tenant_id=$1 GROUP BY status`, tid)
	if err == nil {
		defer srows.Close()
		for srows.Next() {
			var st string
			var cnt int
			if srows.Scan(&st, &cnt) == nil {
				switch strings.ToLower(st) {
				case "experimental":
					experimental = cnt
				case "stable":
					stable = cnt
				case "test", "testing":
					testing = cnt
				}
			}
		}
	}

	db.QueryRow(`SELECT COUNT(DISTINCT rule_id) FROM sigma_rule_hits WHERE tenant_id=$1 AND matched_at>=NOW()-INTERVAL '24 hours'`, tid).Scan(&triggeredToday)
	db.QueryRow(`SELECT COUNT(DISTINCT rule_id) FROM sigma_rule_hits WHERE tenant_id=$1 AND matched_at>=NOW()-INTERVAL '7 days'`, tid).Scan(&triggeredWeek)
	db.QueryRow(`SELECT COUNT(*) FROM sigma_rule_hits WHERE tenant_id=$1 AND matched_at>=NOW()-INTERVAL '24 hours'`, tid).Scan(&totalHitsToday)
	db.QueryRow(`SELECT COUNT(DISTINCT mitre_tactic) FROM sigma_rules WHERE tenant_id=$1 AND mitre_tactic!=''`, tid).Scan(&tacticCount)
	db.QueryRow(`SELECT COUNT(DISTINCT mitre_technique) FROM sigma_rules WHERE tenant_id=$1 AND mitre_technique!=''`, tid).Scan(&techniqueCount)

	type TopRule struct {
		ID       int    `json:"id"`
		Title    string `json:"title"`
		Severity string `json:"severity"`
		Hits7d   int    `json:"hits_7d"`
		Hits24h  int    `json:"hits_24h"`
	}
	var topRules []TopRule
	tr, err := db.Query(`
		SELECT sr.id, sr.title, sr.severity,
		       COUNT(h.id) hits_7d,
		       COUNT(h.id) FILTER (WHERE h.matched_at >= NOW()-INTERVAL '24 hours') hits_24h
		FROM sigma_rules sr
		LEFT JOIN sigma_rule_hits h ON h.rule_id=sr.id AND h.tenant_id=sr.tenant_id AND h.matched_at>=NOW()-INTERVAL '7 days'
		WHERE sr.tenant_id=$1
		GROUP BY sr.id, sr.title, sr.severity
		HAVING COUNT(h.id) > 0
		ORDER BY hits_7d DESC LIMIT 10`, tid)
	if err == nil {
		defer tr.Close()
		for tr.Next() {
			var r TopRule
			if tr.Scan(&r.ID, &r.Title, &r.Severity, &r.Hits7d, &r.Hits24h) == nil {
				topRules = append(topRules, r)
			}
		}
	}
	if topRules == nil {
		topRules = []TopRule{}
	}

	// Daily trend 14 days
	type DayHit struct {
		Date  string `json:"date"`
		Count int    `json:"count"`
	}
	var trend []DayHit
	trows, err := db.Query(`
		SELECT DATE(matched_at AT TIME ZONE 'UTC'), COUNT(*)
		FROM sigma_rule_hits
		WHERE tenant_id=$1 AND matched_at>=NOW()-INTERVAL '14 days'
		GROUP BY 1 ORDER BY 1`, tid)
	if err == nil {
		defer trows.Close()
		for trows.Next() {
			var d DayHit
			if trows.Scan(&d.Date, &d.Count) == nil {
				trend = append(trend, d)
			}
		}
	}
	if trend == nil {
		trend = []DayHit{}
	}

	// Category breakdown by logsource_prod
	type CatStat struct {
		Category string `json:"category"`
		Total    int    `json:"total"`
		Enabled  int    `json:"enabled"`
	}
	var categories []CatStat
	crows, err := db.Query(`
		SELECT COALESCE(NULLIF(logsource_prod,''),'unknown'), COUNT(*), SUM(CASE WHEN enabled THEN 1 ELSE 0 END)
		FROM sigma_rules WHERE tenant_id=$1 GROUP BY 1 ORDER BY 2 DESC LIMIT 12`, tid)
	if err == nil {
		defer crows.Close()
		for crows.Next() {
			var cs CatStat
			if crows.Scan(&cs.Category, &cs.Total, &cs.Enabled) == nil {
				categories = append(categories, cs)
			}
		}
	}
	if categories == nil {
		categories = []CatStat{}
	}

	c.JSON(http.StatusOK, gin.H{
		"total":         total,
		"enabled":       enabled,
		"disabled":      disabled,
		"severity":      gin.H{"critical": critical, "high": high, "medium": medium, "low": low, "info": info},
		"status":        gin.H{"experimental": experimental, "stable": stable, "testing": testing},
		"triggered_24h": triggeredToday,
		"triggered_7d":  triggeredWeek,
		"total_hits_24h": totalHitsToday,
		"mitre_tactics":   tacticCount,
		"mitre_techniques": techniqueCount,
		"top_rules":     topRules,
		"trend":         trend,
		"categories":    categories,
	})
}

// ── GetSigmaMITRECoverage ─────────────────────────────────────────────────

func GetSigmaMITRECoverage(c *gin.Context) {
	tid := tenantIDFromContext(c)

	type TechStat struct {
		Technique string `json:"technique"`
		Name      string `json:"name"`
		Rules     int    `json:"rules"`
		Enabled   int    `json:"enabled"`
	}
	type TacticGroup struct {
		Tactic     string     `json:"tactic"`
		Techniques []TechStat `json:"techniques"`
		TotalRules int        `json:"total_rules"`
	}

	rows, err := database.DB.Query(`
		SELECT mitre_tactic, mitre_technique, mitre_name,
		       COUNT(*) rules, SUM(CASE WHEN enabled THEN 1 ELSE 0 END) enabled_rules
		FROM sigma_rules
		WHERE tenant_id=$1 AND mitre_tactic != ''
		GROUP BY mitre_tactic, mitre_technique, mitre_name
		ORDER BY mitre_tactic, rules DESC`, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	tacticMap := map[string]*TacticGroup{}
	tacticOrder := []string{}

	for rows.Next() {
		var tactic, technique, name string
		var rules, enabled int
		if rows.Scan(&tactic, &technique, &name, &rules, &enabled) != nil {
			continue
		}
		if _, exists := tacticMap[tactic]; !exists {
			tacticMap[tactic] = &TacticGroup{Tactic: tactic, Techniques: []TechStat{}}
			tacticOrder = append(tacticOrder, tactic)
		}
		tacticMap[tactic].Techniques = append(tacticMap[tactic].Techniques, TechStat{
			Technique: technique, Name: name, Rules: rules, Enabled: enabled,
		})
		tacticMap[tactic].TotalRules += rules
	}

	result := make([]TacticGroup, 0, len(tacticOrder))
	for _, t := range tacticOrder {
		result = append(result, *tacticMap[t])
	}

	// Uncovered summary
	var uncoveredCount int
	database.DB.QueryRow(`SELECT COUNT(*) FROM sigma_rules WHERE tenant_id=$1 AND mitre_tactic=''`, tid).Scan(&uncoveredCount)

	c.JSON(http.StatusOK, gin.H{
		"coverage":  result,
		"uncovered": uncoveredCount,
	})
}

// ── GetSigmaAnalytics ─────────────────────────────────────────────────────

func GetSigmaAnalytics(c *gin.Context) {
	tid := tenantIDFromContext(c)

	type RuleAnalytic struct {
		ID          int     `json:"id"`
		Title       string  `json:"title"`
		Severity    string  `json:"severity"`
		MITRETactic string  `json:"mitre_tactic"`
		Enabled     bool    `json:"enabled"`
		HitCount    int     `json:"hit_count"`
		Hits24h     int     `json:"hits_24h"`
		Hits7d      int     `json:"hits_7d"`
		LastHit     *string `json:"last_hit"`
	}

	rows, err := database.DB.Query(`
		SELECT sr.id, sr.title, sr.severity, sr.mitre_tactic, sr.enabled,
		       COUNT(h.id)                                                            hit_count,
		       COUNT(h.id) FILTER (WHERE h.matched_at >= NOW()-INTERVAL '24 hours')  hits_24h,
		       COUNT(h.id) FILTER (WHERE h.matched_at >= NOW()-INTERVAL '7 days')    hits_7d,
		       MAX(h.matched_at)::TEXT
		FROM sigma_rules sr
		LEFT JOIN sigma_rule_hits h ON h.rule_id=sr.id AND h.tenant_id=sr.tenant_id
		WHERE sr.tenant_id=$1
		GROUP BY sr.id, sr.title, sr.severity, sr.mitre_tactic, sr.enabled
		ORDER BY hit_count DESC, sr.id
		LIMIT 200`, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	rules := []RuleAnalytic{}
	for rows.Next() {
		var r RuleAnalytic
		if rows.Scan(&r.ID, &r.Title, &r.Severity, &r.MITRETactic, &r.Enabled, &r.HitCount, &r.Hits24h, &r.Hits7d, &r.LastHit) == nil {
			rules = append(rules, r)
		}
	}

	// Daily totals last 30 days
	type DayTotal struct {
		Date  string `json:"date"`
		Hits  int    `json:"hits"`
		Rules int    `json:"rules"`
	}
	var daily []DayTotal
	drows, err := database.DB.Query(`
		SELECT DATE(matched_at AT TIME ZONE 'UTC'), COUNT(*), COUNT(DISTINCT rule_id)
		FROM sigma_rule_hits WHERE tenant_id=$1 AND matched_at>=NOW()-INTERVAL '30 days'
		GROUP BY 1 ORDER BY 1`, tid)
	if err == nil {
		defer drows.Close()
		for drows.Next() {
			var d DayTotal
			if drows.Scan(&d.Date, &d.Hits, &d.Rules) == nil {
				daily = append(daily, d)
			}
		}
	}
	if daily == nil {
		daily = []DayTotal{}
	}

	// Severity hit distribution
	type SevHit struct {
		Severity string `json:"severity"`
		Hits     int    `json:"hits"`
	}
	var sevHits []SevHit
	svrows, err := database.DB.Query(`
		SELECT sr.severity, COUNT(h.id)
		FROM sigma_rules sr
		JOIN sigma_rule_hits h ON h.rule_id=sr.id AND h.tenant_id=sr.tenant_id
		AND h.matched_at>=NOW()-INTERVAL '7 days'
		WHERE sr.tenant_id=$1
		GROUP BY sr.severity ORDER BY 2 DESC`, tid)
	if err == nil {
		defer svrows.Close()
		for svrows.Next() {
			var s SevHit
			if svrows.Scan(&s.Severity, &s.Hits) == nil {
				sevHits = append(sevHits, s)
			}
		}
	}
	if sevHits == nil {
		sevHits = []SevHit{}
	}

	c.JSON(http.StatusOK, gin.H{
		"rules":      rules,
		"daily":      daily,
		"sev_hits":   sevHits,
	})
}

// ── GetSigmaCategories ────────────────────────────────────────────────────

func GetSigmaCategories(c *gin.Context) {
	tid := tenantIDFromContext(c)

	type CatDetail struct {
		Platform string `json:"platform"`
		Category string `json:"category"`
		Total    int    `json:"total"`
		Enabled  int    `json:"enabled"`
		Hits7d   int    `json:"hits_7d"`
	}

	rows, err := database.DB.Query(`
		SELECT
		    COALESCE(NULLIF(sr.logsource_prod,''),'unknown') platform,
		    COALESCE(NULLIF(sr.logsource_cat,''),'general')  category,
		    COUNT(*),
		    SUM(CASE WHEN sr.enabled THEN 1 ELSE 0 END),
		    COALESCE(SUM(h.cnt),0)
		FROM sigma_rules sr
		LEFT JOIN (
		    SELECT rule_id, COUNT(*) cnt FROM sigma_rule_hits
		    WHERE tenant_id=$1 AND matched_at>=NOW()-INTERVAL '7 days'
		    GROUP BY rule_id
		) h ON h.rule_id=sr.id
		WHERE sr.tenant_id=$1
		GROUP BY 1,2
		ORDER BY 3 DESC`, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	cats := []CatDetail{}
	for rows.Next() {
		var cd CatDetail
		if rows.Scan(&cd.Platform, &cd.Category, &cd.Total, &cd.Enabled, &cd.Hits7d) == nil {
			cats = append(cats, cd)
		}
	}

	c.JSON(http.StatusOK, gin.H{"categories": cats})
}

// ── GetSigmaPerformance ───────────────────────────────────────────────────

func GetSigmaPerformance(c *gin.Context) {
	tid := tenantIDFromContext(c)

	var hitsLastHour, hitsLast24h, hitsLast7d int
	database.DB.QueryRow(`SELECT COUNT(*) FROM sigma_rule_hits WHERE tenant_id=$1 AND matched_at>=NOW()-INTERVAL '1 hour'`, tid).Scan(&hitsLastHour)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sigma_rule_hits WHERE tenant_id=$1 AND matched_at>=NOW()-INTERVAL '24 hours'`, tid).Scan(&hitsLast24h)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sigma_rule_hits WHERE tenant_id=$1 AND matched_at>=NOW()-INTERVAL '7 days'`, tid).Scan(&hitsLast7d)

	type HourlyHit struct {
		Hour  string `json:"hour"`
		Count int    `json:"count"`
	}
	var hourly []HourlyHit
	hrows, err := database.DB.Query(`
		SELECT DATE_TRUNC('hour', matched_at AT TIME ZONE 'UTC'), COUNT(*)
		FROM sigma_rule_hits WHERE tenant_id=$1 AND matched_at>=NOW()-INTERVAL '24 hours'
		GROUP BY 1 ORDER BY 1`, tid)
	if err == nil {
		defer hrows.Close()
		for hrows.Next() {
			var h HourlyHit
			if hrows.Scan(&h.Hour, &h.Count) == nil {
				hourly = append(hourly, h)
			}
		}
	}
	if hourly == nil {
		hourly = []HourlyHit{}
	}

	type AgentHit struct {
		AgentID   int    `json:"agent_id"`
		AgentName string `json:"agent_name"`
		Hits      int    `json:"hits"`
	}
	var topAgents []AgentHit
	arows, err := database.DB.Query(`
		SELECT h.agent_id, COALESCE(a.hostname, a.name, 'Agent '||h.agent_id::text), COUNT(h.id)
		FROM sigma_rule_hits h
		LEFT JOIN agents a ON a.id=h.agent_id
		WHERE h.tenant_id=$1 AND h.matched_at>=NOW()-INTERVAL '7 days'
		GROUP BY h.agent_id, 2 ORDER BY 3 DESC LIMIT 10`, tid)
	if err == nil {
		defer arows.Close()
		for arows.Next() {
			var ah AgentHit
			if arows.Scan(&ah.AgentID, &ah.AgentName, &ah.Hits) == nil {
				topAgents = append(topAgents, ah)
			}
		}
	}
	if topAgents == nil {
		topAgents = []AgentHit{}
	}

	c.JSON(http.StatusOK, gin.H{
		"hits_last_hour": hitsLastHour,
		"hits_last_24h":  hitsLast24h,
		"hits_last_7d":   hitsLast7d,
		"hourly":         hourly,
		"top_agents":     topAgents,
	})
}

// ── GetSigmaRelationships ─────────────────────────────────────────────────

func GetSigmaRelationships(c *gin.Context) {
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

	// Top sigma rules by hit count
	rows, err := database.DB.Query(`
		SELECT sr.id, sr.title, COUNT(h.id) hits
		FROM sigma_rules sr
		JOIN sigma_rule_hits h ON h.rule_id=sr.id AND h.tenant_id=sr.tenant_id
		WHERE sr.tenant_id=$1 AND h.matched_at>=NOW()-INTERVAL '7 days'
		GROUP BY sr.id, sr.title ORDER BY hits DESC LIMIT 15`, tid)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id int
			var title string
			var hits int
			if rows.Scan(&id, &title, &hits) == nil {
				nodes = append(nodes, RelNode{
					ID:    fmt.Sprintf("rule_%d", id),
					Label: title,
					Type:  "rule",
					Value: hits,
				})
			}
		}
	}

	// Agents that triggered these rules
	arows, err := database.DB.Query(`
		SELECT DISTINCT h.rule_id, h.agent_id, COALESCE(a.hostname, a.name, 'Agent '||h.agent_id::text), COUNT(h.id)
		FROM sigma_rule_hits h
		LEFT JOIN agents a ON a.id=h.agent_id
		WHERE h.tenant_id=$1 AND h.matched_at>=NOW()-INTERVAL '7 days'
		GROUP BY h.rule_id, h.agent_id, 3
		ORDER BY 4 DESC LIMIT 30`, tid)
	if err == nil {
		defer arows.Close()
		agentSeen := map[int]bool{}
		for arows.Next() {
			var ruleID, agentID, cnt int
			var agentName string
			if arows.Scan(&ruleID, &agentID, &agentName, &cnt) == nil {
				agentNodeID := fmt.Sprintf("agent_%d", agentID)
				if !agentSeen[agentID] {
					nodes = append(nodes, RelNode{
						ID:    agentNodeID,
						Label: agentName,
						Type:  "agent",
						Value: cnt,
					})
					agentSeen[agentID] = true
				}
				edges = append(edges, RelEdge{
					Source: fmt.Sprintf("rule_%d", ruleID),
					Target: agentNodeID,
					Weight: cnt,
				})
			}
		}
	}

	// MITRE technique nodes
	mrows, err := database.DB.Query(`
		SELECT DISTINCT mitre_technique, mitre_tactic
		FROM sigma_rules
		WHERE tenant_id=$1 AND mitre_technique != ''
		LIMIT 20`, tid)
	if err == nil {
		defer mrows.Close()
		for mrows.Next() {
			var tech, tactic string
			if mrows.Scan(&tech, &tactic) == nil {
				nodes = append(nodes, RelNode{
					ID:    "mitre_" + tech,
					Label: tech,
					Type:  "mitre",
					Value: 1,
				})
			}
		}
	}

	// Rule → MITRE edges
	rmrows, err := database.DB.Query(`
		SELECT id, mitre_technique FROM sigma_rules
		WHERE tenant_id=$1 AND mitre_technique != ''`, tid)
	if err == nil {
		defer rmrows.Close()
		for rmrows.Next() {
			var id int
			var tech string
			if rmrows.Scan(&id, &tech) == nil {
				edges = append(edges, RelEdge{
					Source: fmt.Sprintf("rule_%d", id),
					Target: "mitre_" + tech,
					Weight: 1,
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"nodes": nodes, "edges": edges})
}

// ── PostSigmaAI ───────────────────────────────────────────────────────────

func PostSigmaAI(c *gin.Context) {
	tid := tenantIDFromContext(c)

	var body struct {
		Action    string `json:"action"`
		RuleID    int    `json:"rule_id"`
		Target    string `json:"target"`
		Prompt    string `json:"prompt"`
		RuleYAML  string `json:"rule_yaml"`
		Context   string `json:"context"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Fetch rule YAML if rule_id provided and no explicit yaml
	ruleYAML := body.RuleYAML
	if ruleYAML == "" && body.RuleID > 0 {
		var r models.SigmaRule
		database.DB.QueryRow(`SELECT title, description, status, severity, mitre_tactic, mitre_technique, logsource_cat, logsource_prod, logsource_svc, condition, tags, enabled FROM sigma_rules WHERE id=$1 AND tenant_id=$2`, body.RuleID, tid).
			Scan(&r.Title, &r.Description, &r.Status, &r.Severity, &r.MitreTactic, &r.MitreTechnique, &r.LogsourceCategory, &r.LogsourceProduct, &r.LogsourceService, &r.Condition, &r.Tags, &r.Enabled)
		ruleYAML = fmt.Sprintf("title: %s\nstatus: %s\nseverity: %s\ntags:\n  - attack.%s\n  - attack.%s\nlogsource:\n  category: %s\n  product: %s\n  service: %s\ncondition: %s",
			r.Title, r.Status, r.Severity, r.MitreTactic, r.MitreTechnique,
			r.LogsourceCategory, r.LogsourceProduct, r.LogsourceService, r.Condition)
	}

	var llmPrompt string
	switch body.Action {
	case "generate":
		llmPrompt = fmt.Sprintf(`You are a Sigma rule expert. Generate a complete, valid Sigma rule in YAML format for the following detection requirement:

%s

Additional context: %s

Return ONLY the Sigma YAML rule without any explanation. The rule must be valid Sigma format with: title, status, description, references, logsource (category/product/service), detection (selection + condition), falsepositives, level.`, body.Prompt, body.Context)

	case "explain":
		llmPrompt = fmt.Sprintf(`You are a Sigma rule expert. Explain the following Sigma rule in detail. Cover:
1. What threat or attack technique this rule detects
2. How the detection logic works (selections, condition)
3. The MITRE ATT&CK mapping
4. What log source is required
5. Potential false positives
6. Recommendations for tuning

Sigma Rule YAML:
%s

Return a structured JSON response: {"summary": "...", "threat": "...", "logic": "...", "mitre": "...", "logsource": "...", "false_positives": "...", "tuning_tips": "..."}`, ruleYAML)

	case "optimize":
		llmPrompt = fmt.Sprintf(`You are a Sigma rule expert. Analyze this Sigma rule and provide optimization recommendations.

Sigma Rule YAML:
%s

Context: %s

Return a JSON response: {"issues": ["..."], "recommendations": ["..."], "optimized_yaml": "...", "performance_impact": "low|medium|high", "fp_risk": "low|medium|high"}`, ruleYAML, body.Context)

	case "test_cases":
		llmPrompt = fmt.Sprintf(`You are a Sigma rule expert. Generate realistic test log events that would trigger the following Sigma rule.

Sigma Rule YAML:
%s

Return a JSON response: {"match_cases": [{"description": "...", "log_event": "..."}], "non_match_cases": [{"description": "...", "log_event": "..."}], "edge_cases": [{"description": "...", "log_event": "..."}]}`, ruleYAML)

	case "fp_analysis":
		llmPrompt = fmt.Sprintf(`You are a Sigma rule expert. Analyze the potential false positives for this Sigma rule and provide tuning recommendations.

Sigma Rule YAML:
%s

Return a JSON response: {"fp_scenarios": [{"scenario": "...", "likelihood": "low|medium|high", "mitigation": "..."}], "tuning_recommendations": ["..."], "fp_rate_estimate": "low|medium|high"}`, ruleYAML)

	case "convert":
		target := body.Target
		if target == "" {
			target = "elasticsearch"
		}
		llmPrompt = fmt.Sprintf(`You are a Sigma rule expert. Convert the following Sigma rule to a %s query.

Sigma Rule YAML:
%s

Return a JSON response: {"query": "...", "notes": "...", "platform": "%s", "limitations": "..."}`, target, ruleYAML, target)

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown action: " + body.Action})
		return
	}

	raw, err := services.CallLLM(llmPrompt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Strip markdown fences
	if idx := strings.Index(raw, "```json"); idx != -1 {
		raw = raw[idx+7:]
	} else if idx := strings.Index(raw, "```yaml"); idx != -1 {
		raw = raw[idx+7:]
	} else if idx := strings.Index(raw, "```"); idx != -1 {
		raw = raw[idx+3:]
	}
	if idx := strings.LastIndex(raw, "```"); idx != -1 {
		raw = raw[:idx]
	}
	raw = strings.TrimSpace(raw)

	// For generate action, return as yaml string wrapper if not JSON
	if body.Action == "generate" {
		c.JSON(http.StatusOK, gin.H{"yaml": raw, "action": "generate"})
		return
	}

	c.Data(http.StatusOK, "application/json", []byte(raw))
}

// ── PostSigmaConvert ──────────────────────────────────────────────────────

func PostSigmaConvert(c *gin.Context) {
	tid := tenantIDFromContext(c)

	var body struct {
		RuleID   int    `json:"rule_id"`
		RuleYAML string `json:"rule_yaml"`
		Target   string `json:"target"` // elastic, splunk, kql, qradar, suricata, opensearch
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ruleYAML := body.RuleYAML
	if ruleYAML == "" && body.RuleID > 0 {
		var title, status, severity, tactic, tech, cat, prod, svc, cond string
		database.DB.QueryRow(`SELECT title, status, severity, mitre_tactic, mitre_technique, logsource_cat, logsource_prod, logsource_svc, condition FROM sigma_rules WHERE id=$1 AND tenant_id=$2`,
			body.RuleID, tid).Scan(&title, &status, &severity, &tactic, &tech, &cat, &prod, &svc, &cond)
		ruleYAML = fmt.Sprintf("title: %s\nstatus: %s\nseverity: %s\ntags:\n  - attack.%s\n  - attack.%s\nlogsource:\n  category: %s\n  product: %s\n  service: %s\ncondition: %s",
			title, status, severity, tactic, tech, cat, prod, svc, cond)
	}

	if ruleYAML == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no rule YAML provided"})
		return
	}

	target := body.Target
	if target == "" {
		target = "elasticsearch"
	}

	platformNames := map[string]string{
		"elastic":     "Elasticsearch/Kibana EQL/Lucene",
		"splunk":      "Splunk SPL",
		"kql":         "Microsoft Sentinel KQL",
		"qradar":      "IBM QRadar AQL",
		"suricata":    "Suricata IDS rule",
		"opensearch":  "OpenSearch/OpenSearch Dashboards query",
	}
	platformName, ok := platformNames[target]
	if !ok {
		platformName = target
	}

	llmPrompt := fmt.Sprintf(`You are a SIEM expert. Convert the following Sigma detection rule to a %s query/rule.

Sigma Rule YAML:
%s

Requirements:
- Produce a valid, production-ready query for %s
- Include field mappings appropriate for the platform
- Note any limitations or fields that cannot be mapped
- Include notes on how to deploy/use this query

Return JSON: {"query": "...", "platform": "%s", "notes": "...", "limitations": "...", "deployment_notes": "..."}`,
		platformName, ruleYAML, platformName, target)

	raw, err := services.CallLLM(llmPrompt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if idx := strings.Index(raw, "```json"); idx != -1 {
		raw = raw[idx+7:]
	} else if idx := strings.Index(raw, "```"); idx != -1 {
		raw = raw[idx+3:]
	}
	if idx := strings.LastIndex(raw, "```"); idx != -1 {
		raw = raw[:idx]
	}
	c.Data(http.StatusOK, "application/json", []byte(strings.TrimSpace(raw)))
}

// ── PostSigmaBulk ─────────────────────────────────────────────────────────

func PostSigmaBulk(c *gin.Context) {
	tid := tenantIDFromContext(c)

	var body struct {
		Action   string `json:"action"` // enable, disable, delete, set_severity, set_status
		RuleIDs  []int  `json:"rule_ids"`
		Value    string `json:"value"` // for set_severity / set_status
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(body.RuleIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no rule_ids provided"})
		return
	}

	// Build $1,$2,... placeholders
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
		query = fmt.Sprintf(`UPDATE sigma_rules SET enabled=true WHERE tenant_id=$1 AND id IN (%s)`, inClause)
	case "disable":
		query = fmt.Sprintf(`UPDATE sigma_rules SET enabled=false WHERE tenant_id=$1 AND id IN (%s)`, inClause)
	case "delete":
		query = fmt.Sprintf(`DELETE FROM sigma_rules WHERE tenant_id=$1 AND id IN (%s)`, inClause)
	case "set_severity":
		if body.Value == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "value required for set_severity"})
			return
		}
		args = append([]interface{}{tid, body.Value}, args[1:]...)
		query = fmt.Sprintf(`UPDATE sigma_rules SET severity=$2 WHERE tenant_id=$1 AND id IN (%s)`, inClause)
		// Rebuild args properly
		args = []interface{}{tid, body.Value}
		for _, id := range body.RuleIDs {
			args = append(args, id)
		}
		placeholders2 := make([]string, len(body.RuleIDs))
		for i := range body.RuleIDs {
			placeholders2[i] = fmt.Sprintf("$%d", i+3)
		}
		query = fmt.Sprintf(`UPDATE sigma_rules SET severity=$2 WHERE tenant_id=$1 AND id IN (%s)`, strings.Join(placeholders2, ","))
	case "set_status":
		if body.Value == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "value required for set_status"})
			return
		}
		args = []interface{}{tid, body.Value}
		for _, id := range body.RuleIDs {
			args = append(args, id)
		}
		placeholders2 := make([]string, len(body.RuleIDs))
		for i := range body.RuleIDs {
			placeholders2[i] = fmt.Sprintf("$%d", i+3)
		}
		query = fmt.Sprintf(`UPDATE sigma_rules SET status=$2 WHERE tenant_id=$1 AND id IN (%s)`, strings.Join(placeholders2, ","))
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

// ── PostSigmaExport ───────────────────────────────────────────────────────

func PostSigmaExport(c *gin.Context) {
	tid := tenantIDFromContext(c)

	var body struct {
		Format  string `json:"format"` // yaml, json
		RuleIDs []int  `json:"rule_ids"` // empty = all
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Format == "" {
		body.Format = "yaml"
	}

	var rows interface{ Close() error; Next() bool; Scan(...interface{}) error }
	var err error

	if len(body.RuleIDs) > 0 {
		args := []interface{}{tid}
		placeholders := make([]string, len(body.RuleIDs))
		for i, id := range body.RuleIDs {
			args = append(args, id)
			placeholders[i] = fmt.Sprintf("$%d", i+2)
		}
		rows, err = database.DB.Query(
			fmt.Sprintf(`SELECT id, title, description, status, severity, mitre_tactic, mitre_technique, mitre_name, logsource_cat, logsource_prod, logsource_svc, condition, enabled, created_at FROM sigma_rules WHERE tenant_id=$1 AND id IN (%s) ORDER BY id`, strings.Join(placeholders, ",")),
			args...)
	} else {
		rows, err = database.DB.Query(`SELECT id, title, description, status, severity, mitre_tactic, mitre_technique, mitre_name, logsource_cat, logsource_prod, logsource_svc, condition, enabled, created_at FROM sigma_rules WHERE tenant_id=$1 ORDER BY id`, tid)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type ExportRule struct {
		ID          int       `json:"id" yaml:"id"`
		Title       string    `json:"title" yaml:"title"`
		Description string    `json:"description,omitempty" yaml:"description,omitempty"`
		Status      string    `json:"status" yaml:"status"`
		Severity    string    `json:"level" yaml:"level"`
		MITRETactic string    `json:"mitre_tactic,omitempty" yaml:"mitre_tactic,omitempty"`
		MITREtech   string    `json:"mitre_technique,omitempty" yaml:"mitre_technique,omitempty"`
		MITREname   string    `json:"mitre_name,omitempty" yaml:"mitre_name,omitempty"`
		Category    string    `json:"logsource_category,omitempty" yaml:"logsource_category,omitempty"`
		Product     string    `json:"logsource_product,omitempty" yaml:"logsource_product,omitempty"`
		Service     string    `json:"logsource_service,omitempty" yaml:"logsource_service,omitempty"`
		Condition   string    `json:"condition" yaml:"condition"`
		Enabled     bool      `json:"enabled" yaml:"enabled"`
		CreatedAt   time.Time `json:"created_at" yaml:"created_at"`
	}

	var rules []ExportRule
	for rows.Next() {
		var r ExportRule
		if rows.Scan(&r.ID, &r.Title, &r.Description, &r.Status, &r.Severity, &r.MITRETactic, &r.MITREtech, &r.MITREname, &r.Category, &r.Product, &r.Service, &r.Condition, &r.Enabled, &r.CreatedAt) == nil {
			rules = append(rules, r)
		}
	}
	if rules == nil {
		rules = []ExportRule{}
	}

	if body.Format == "yaml" {
		var sb strings.Builder
		for _, r := range rules {
			sb.WriteString(fmt.Sprintf("---\ntitle: %s\nstatus: %s\nlevel: %s\n", r.Title, r.Status, r.Severity))
			if r.Description != "" {
				sb.WriteString(fmt.Sprintf("description: %s\n", r.Description))
			}
			if r.MITRETactic != "" {
				sb.WriteString(fmt.Sprintf("tags:\n  - attack.%s\n  - attack.%s\n", r.MITRETactic, r.MITREtech))
			}
			sb.WriteString("logsource:\n")
			if r.Category != "" {
				sb.WriteString(fmt.Sprintf("  category: %s\n", r.Category))
			}
			if r.Product != "" {
				sb.WriteString(fmt.Sprintf("  product: %s\n", r.Product))
			}
			if r.Service != "" {
				sb.WriteString(fmt.Sprintf("  service: %s\n", r.Service))
			}
			sb.WriteString(fmt.Sprintf("condition: %s\n\n", r.Condition))
		}
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=sigma_rules_%s.yaml", time.Now().Format("20060102")))
		c.Data(http.StatusOK, "application/x-yaml", []byte(sb.String()))
		return
	}

	b, _ := json.Marshal(rules)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=sigma_rules_%s.json", time.Now().Format("20060102")))
	c.Data(http.StatusOK, "application/json", b)
}

// ── GetSigmaRuleDetail ────────────────────────────────────────────────────

func GetSigmaRuleDetail(c *gin.Context) {
	tid := tenantIDFromContext(c)
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	type RuleDetail struct {
		ID          int     `json:"id"`
		Title       string  `json:"title"`
		Description string  `json:"description"`
		Status      string  `json:"status"`
		Severity    string  `json:"severity"`
		MITRETactic string  `json:"mitre_tactic"`
		MITREtech   string  `json:"mitre_technique"`
		MITREname   string  `json:"mitre_name"`
		Category    string  `json:"logsource_category"`
		Product     string  `json:"logsource_product"`
		Service     string  `json:"logsource_service"`
		Keywords    string  `json:"keywords"`
		Condition   string  `json:"condition"`
		Enabled     bool    `json:"enabled"`
		HitCount    int     `json:"hit_count"`
		LastHit     *string `json:"last_hit"`
		Hits24h     int     `json:"hits_24h"`
		Hits7d      int     `json:"hits_7d"`
	}

	var r RuleDetail
	err = database.DB.QueryRow(`
		SELECT sr.id, sr.title, sr.description, sr.status, sr.severity, sr.mitre_tactic, sr.mitre_technique, sr.mitre_name,
		       sr.logsource_cat, sr.logsource_prod, sr.logsource_svc, sr.keywords, sr.condition, sr.enabled,
		       COUNT(h.id) hit_count, MAX(h.matched_at)::TEXT last_hit,
		       COUNT(h.id) FILTER (WHERE h.matched_at >= NOW()-INTERVAL '24 hours') hits_24h,
		       COUNT(h.id) FILTER (WHERE h.matched_at >= NOW()-INTERVAL '7 days') hits_7d
		FROM sigma_rules sr
		LEFT JOIN sigma_rule_hits h ON h.rule_id=sr.id AND h.tenant_id=sr.tenant_id
		WHERE sr.id=$1 AND sr.tenant_id=$2
		GROUP BY sr.id, sr.title, sr.description, sr.status, sr.severity, sr.mitre_tactic, sr.mitre_technique, sr.mitre_name,
		         sr.logsource_cat, sr.logsource_prod, sr.logsource_svc, sr.keywords, sr.condition, sr.enabled`,
		id, tid).Scan(&r.ID, &r.Title, &r.Description, &r.Status, &r.Severity, &r.MITRETactic, &r.MITREtech,
		&r.MITREname, &r.Category, &r.Product, &r.Service, &r.Keywords, &r.Condition, &r.Enabled,
		&r.HitCount, &r.LastHit, &r.Hits24h, &r.Hits7d)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	// Recent hits
	type HitEvent struct {
		AgentName string `json:"agent_name"`
		MatchedAt string `json:"matched_at"`
	}
	var recentHits []HitEvent
	hrows, err := database.DB.Query(`
		SELECT COALESCE(a.hostname, a.name, 'Agent '||h.agent_id::text), h.matched_at::TEXT
		FROM sigma_rule_hits h
		LEFT JOIN agents a ON a.id=h.agent_id
		WHERE h.rule_id=$1 AND h.tenant_id=$2
		ORDER BY h.matched_at DESC LIMIT 20`, id, tid)
	if err == nil {
		defer hrows.Close()
		for hrows.Next() {
			var he HitEvent
			if hrows.Scan(&he.AgentName, &he.MatchedAt) == nil {
				recentHits = append(recentHits, he)
			}
		}
	}
	if recentHits == nil {
		recentHits = []HitEvent{}
	}

	c.JSON(http.StatusOK, gin.H{"rule": r, "recent_hits": recentHits})
}
