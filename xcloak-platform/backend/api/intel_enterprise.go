package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/services"
)

// ── GetIntelOverview ───────────────────────────────────────────────────────────

func GetIntelOverview(c *gin.Context) {
	tid := tenantIDFromContext(c)
	hours := parseHours(c, 24)

	var totalIOCs, enabledIOCs, newToday, iocMatches int
	var totalActors, totalFeeds, enabledFeeds, sigmaRules, yaraRules int
	var highConfidence int

	database.DB.QueryRow(`SELECT COUNT(*), COUNT(*) FILTER (WHERE enabled=true) FROM iocs WHERE tenant_id=$1`, tid).
		Scan(&totalIOCs, &enabledIOCs)
	database.DB.QueryRow(`SELECT COUNT(*) FROM iocs WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL'24 hours'`, tid).
		Scan(&newToday)
	database.DB.QueryRow(`SELECT COALESCE(SUM(hit_count),0) FROM iocs WHERE tenant_id=$1`, tid).
		Scan(&iocMatches)
	database.DB.QueryRow(`SELECT COUNT(*) FROM iocs WHERE tenant_id=$1 AND hit_count >= 3`, tid).
		Scan(&highConfidence)
	database.DB.QueryRow(`SELECT COUNT(*) FROM threat_actors WHERE tenant_id=$1`, tid).
		Scan(&totalActors)
	database.DB.QueryRow(`SELECT COUNT(*), COUNT(*) FILTER (WHERE enabled=true) FROM threat_feeds WHERE tenant_id=$1`, tid).
		Scan(&totalFeeds, &enabledFeeds)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sigma_rules WHERE tenant_id=$1 AND enabled=true`, tid).
		Scan(&sigmaRules)
	database.DB.QueryRow(`SELECT COUNT(*) FROM yara_rules WHERE tenant_id=$1 AND enabled=true`, tid).
		Scan(&yaraRules)

	// Trend: new IOCs per day for last 7 days
	trendRows, _ := database.DB.Query(`
		SELECT TO_CHAR(DATE_TRUNC('day', created_at),'YYYY-MM-DD'), COUNT(*)
		FROM iocs
		WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL'7 days'
		GROUP BY 1 ORDER BY 1`, tid)
	type DayBucket struct {
		Day   string `json:"day"`
		Count int    `json:"count"`
	}
	trend := []DayBucket{}
	if trendRows != nil {
		for trendRows.Next() {
			var b DayBucket
			trendRows.Scan(&b.Day, &b.Count)
			trend = append(trend, b)
		}
		trendRows.Close()
	}
	if trend == nil {
		trend = []DayBucket{}
	}

	// IOC matches in last N hours
	var recentMatches int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM alerts
		WHERE tenant_id=$1 AND created_at > NOW()-($2::int)*INTERVAL'1 hour'
		AND rule_name ILIKE '%IOC%'`, tid, hours).Scan(&recentMatches)

	// Feed health: count feeds with last_sync in past 25 hours
	var healthyFeeds int
	database.DB.QueryRow(`SELECT COUNT(*) FROM threat_feeds WHERE tenant_id=$1 AND enabled=true AND last_sync > NOW()-INTERVAL'25 hours'`, tid).
		Scan(&healthyFeeds)

	// IOC type breakdown
	typeRows, _ := database.DB.Query(`SELECT type, COUNT(*)::int FROM iocs WHERE tenant_id=$1 GROUP BY type ORDER BY 2 DESC`, tid)
	type TypeBucket struct {
		Type  string `json:"type"`
		Count int    `json:"count"`
	}
	typeBreakdown := []TypeBucket{}
	if typeRows != nil {
		for typeRows.Next() {
			var b TypeBucket
			typeRows.Scan(&b.Type, &b.Count)
			typeBreakdown = append(typeBreakdown, b)
		}
		typeRows.Close()
	}
	if typeBreakdown == nil {
		typeBreakdown = []TypeBucket{}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_iocs":       totalIOCs,
		"enabled_iocs":     enabledIOCs,
		"new_today":        newToday,
		"ioc_matches":      iocMatches,
		"recent_matches":   recentMatches,
		"high_confidence":  highConfidence,
		"total_actors":     totalActors,
		"total_feeds":      totalFeeds,
		"enabled_feeds":    enabledFeeds,
		"healthy_feeds":    healthyFeeds,
		"sigma_rules":      sigmaRules,
		"yara_rules":       yaraRules,
		"trend":            trend,
		"type_breakdown":   typeBreakdown,
	})
}

// ── GetIntelAnalytics ──────────────────────────────────────────────────────────

func GetIntelAnalytics(c *gin.Context) {
	tid := tenantIDFromContext(c)

	// Most matched IOCs
	matchRows, _ := database.DB.Query(`
		SELECT id, indicator, type, severity, hit_count, last_seen, description
		FROM iocs
		WHERE tenant_id=$1 AND hit_count > 0
		ORDER BY hit_count DESC LIMIT 10`, tid)
	type MatchedIOC struct {
		ID          int        `json:"id"`
		Indicator   string     `json:"indicator"`
		Type        string     `json:"type"`
		Severity    string     `json:"severity"`
		HitCount    int        `json:"hit_count"`
		LastSeen    *time.Time `json:"last_seen"`
		Description string     `json:"description"`
	}
	topIOCs := []MatchedIOC{}
	if matchRows != nil {
		for matchRows.Next() {
			var m MatchedIOC
			matchRows.Scan(&m.ID, &m.Indicator, &m.Type, &m.Severity, &m.HitCount, &m.LastSeen, &m.Description)
			topIOCs = append(topIOCs, m)
		}
		matchRows.Close()
	}
	if topIOCs == nil {
		topIOCs = []MatchedIOC{}
	}

	// Top threat actors (by alert tags)
	actorRows, _ := database.DB.Query(`
		SELECT ta.id, ta.name, ta.motivation, ta.sophistication,
		       COUNT(aat.id)::int AS alert_count
		FROM threat_actors ta
		LEFT JOIN actor_alert_tags aat ON aat.actor_id=ta.id AND aat.tenant_id=ta.tenant_id
		WHERE ta.tenant_id=$1
		GROUP BY ta.id, ta.name, ta.motivation, ta.sophistication
		ORDER BY alert_count DESC, ta.name
		LIMIT 10`, tid)
	type ActorStat struct {
		ID           int    `json:"id"`
		Name         string `json:"name"`
		Motivation   string `json:"motivation"`
		Sophistication string `json:"sophistication"`
		AlertCount   int    `json:"alert_count"`
	}
	topActors := []ActorStat{}
	if actorRows != nil {
		for actorRows.Next() {
			var a ActorStat
			actorRows.Scan(&a.ID, &a.Name, &a.Motivation, &a.Sophistication, &a.AlertCount)
			topActors = append(topActors, a)
		}
		actorRows.Close()
	}
	if topActors == nil {
		topActors = []ActorStat{}
	}

	// IOC growth: new IOCs per week for last 4 weeks
	growthRows, _ := database.DB.Query(`
		SELECT TO_CHAR(DATE_TRUNC('week', created_at),'YYYY-MM-DD'), COUNT(*)::int
		FROM iocs
		WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL'28 days'
		GROUP BY 1 ORDER BY 1`, tid)
	type WeekBucket struct {
		Week  string `json:"week"`
		Count int    `json:"count"`
	}
	growth := []WeekBucket{}
	if growthRows != nil {
		for growthRows.Next() {
			var b WeekBucket
			growthRows.Scan(&b.Week, &b.Count)
			growth = append(growth, b)
		}
		growthRows.Close()
	}
	if growth == nil {
		growth = []WeekBucket{}
	}

	// Feed reliability: feeds sorted by IOC count proxy (counts IOCs from feed description)
	feedRows, _ := database.DB.Query(`
		SELECT tf.name, tf.enabled, tf.last_sync, tf.feed_type,
		       COUNT(i.id)::int AS ioc_count
		FROM threat_feeds tf
		LEFT JOIN iocs i ON i.tenant_id=tf.tenant_id AND i.description ILIKE '%' || tf.name || '%'
		WHERE tf.tenant_id=$1
		GROUP BY tf.id, tf.name, tf.enabled, tf.last_sync, tf.feed_type
		ORDER BY ioc_count DESC`, tid)
	type FeedStat struct {
		Name      string     `json:"name"`
		Enabled   bool       `json:"enabled"`
		LastSync  *time.Time `json:"last_sync"`
		FeedType  string     `json:"feed_type"`
		IOCCount  int        `json:"ioc_count"`
		Healthy   bool       `json:"healthy"`
	}
	feedStats := []FeedStat{}
	if feedRows != nil {
		for feedRows.Next() {
			var f FeedStat
			feedRows.Scan(&f.Name, &f.Enabled, &f.LastSync, &f.FeedType, &f.IOCCount)
			f.Healthy = f.Enabled && f.LastSync != nil && time.Since(*f.LastSync) < 25*time.Hour
			feedStats = append(feedStats, f)
		}
		feedRows.Close()
	}
	if feedStats == nil {
		feedStats = []FeedStat{}
	}

	// Severity distribution
	sevRows, _ := database.DB.Query(`SELECT severity, COUNT(*)::int FROM iocs WHERE tenant_id=$1 GROUP BY severity ORDER BY 2 DESC`, tid)
	type SevBucket struct {
		Severity string `json:"severity"`
		Count    int    `json:"count"`
	}
	sevDist := []SevBucket{}
	if sevRows != nil {
		for sevRows.Next() {
			var s SevBucket
			sevRows.Scan(&s.Severity, &s.Count)
			sevDist = append(sevDist, s)
		}
		sevRows.Close()
	}
	if sevDist == nil {
		sevDist = []SevBucket{}
	}

	c.JSON(http.StatusOK, gin.H{
		"top_iocs":           topIOCs,
		"top_actors":         topActors,
		"ioc_growth":         growth,
		"feed_reliability":   feedStats,
		"severity_distribution": sevDist,
	})
}

// ── GetIntelCampaigns ──────────────────────────────────────────────────────────

func GetIntelCampaigns(c *gin.Context) {
	tid := tenantIDFromContext(c)

	// Synthesize campaigns from alert_clusters grouped by mitre_technique
	rows, err := database.DB.Query(`
		SELECT COALESCE(NULLIF(mitre_technique,''),'Unknown') AS technique,
		       COUNT(*)::int AS cluster_count,
		       SUM(alert_count)::int AS total_alerts,
		       MAX(last_seen) AS latest,
		       MIN(first_seen) AS earliest
		FROM alert_clusters
		WHERE tenant_id=$1
		GROUP BY technique
		ORDER BY total_alerts DESC
		LIMIT 20`, tid)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type Campaign struct {
		Technique    string    `json:"technique"`
		Name         string    `json:"name"`
		ClusterCount int       `json:"cluster_count"`
		TotalAlerts  int       `json:"total_alerts"`
		Latest       time.Time `json:"latest"`
		Earliest     time.Time `json:"earliest"`
		Status       string    `json:"status"`
	}
	out := []Campaign{}
	for rows.Next() {
		var cp Campaign
		rows.Scan(&cp.Technique, &cp.ClusterCount, &cp.TotalAlerts, &cp.Latest, &cp.Earliest)
		cp.Name = campaignFromTechnique(cp.Technique)
		if time.Since(cp.Latest) < 48*time.Hour {
			cp.Status = "active"
		} else {
			cp.Status = "dormant"
		}
		out = append(out, cp)
	}
	if out == nil {
		out = []Campaign{}
	}
	c.JSON(http.StatusOK, gin.H{"campaigns": out})
}

// ── GetIntelMITRECoverage ──────────────────────────────────────────────────────

func GetIntelMITRECoverage(c *gin.Context) {
	tid := tenantIDFromContext(c)

	// Sigma rule coverage per technique
	sigmaRows, _ := database.DB.Query(`
		SELECT COALESCE(NULLIF(mitre_technique,''),'Unknown'),
		       COUNT(*)::int,
		       COUNT(*) FILTER (WHERE enabled=true)::int
		FROM sigma_rules
		WHERE tenant_id=$1
		GROUP BY mitre_technique
		ORDER BY 2 DESC`, tid)
	type TechBucket struct {
		Technique string `json:"technique"`
		Total     int    `json:"total"`
		Enabled   int    `json:"enabled"`
		Source    string `json:"source"`
	}
	techniques := []TechBucket{}
	if sigmaRows != nil {
		for sigmaRows.Next() {
			var b TechBucket
			sigmaRows.Scan(&b.Technique, &b.Total, &b.Enabled)
			b.Source = "sigma"
			techniques = append(techniques, b)
		}
		sigmaRows.Close()
	}

	// IOC technique coverage from actor tags
	actorTechRows, _ := database.DB.Query(`
		SELECT UNNEST(mitre_techniques), COUNT(*)::int
		FROM threat_actors
		WHERE tenant_id=$1 AND array_length(mitre_techniques,1) > 0
		GROUP BY 1 ORDER BY 2 DESC LIMIT 20`, tid)
	if actorTechRows != nil {
		for actorTechRows.Next() {
			var tech string
			var cnt int
			actorTechRows.Scan(&tech, &cnt)
			techniques = append(techniques, TechBucket{Technique: tech, Total: cnt, Enabled: cnt, Source: "actor"})
		}
		actorTechRows.Close()
	}

	if techniques == nil {
		techniques = []TechBucket{}
	}

	// Tactic summary
	tacticMap := map[string]int{}
	tacticNames := []string{"Initial Access", "Execution", "Persistence", "Privilege Escalation",
		"Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
		"Collection", "C2", "Exfiltration", "Impact"}
	for _, t := range techniques {
		for _, tactic := range tacticNames {
			if strings.Contains(strings.ToLower(tactic), strings.ToLower(t.Technique[:min(len(t.Technique), 4)])) {
				tacticMap[tactic] += t.Total
				break
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"techniques":   techniques,
		"total":        len(techniques),
		"covered_tactics": len(tacticMap),
	})
}

// ── GetIntelRelationships ──────────────────────────────────────────────────────

func GetIntelRelationships(c *gin.Context) {
	tid := tenantIDFromContext(c)

	type GraphNode struct {
		ID    string `json:"id"`
		Label string `json:"label"`
		Type  string `json:"type"` // actor, campaign, ioc, alert, malware
		Count int    `json:"count"`
	}
	type GraphEdge struct {
		Source string `json:"source"`
		Target string `json:"target"`
		Label  string `json:"label"`
	}

	nodes := []GraphNode{}
	edges := []GraphEdge{}

	// Threat actor nodes
	actorRows, _ := database.DB.Query(`
		SELECT id, name, COALESCE(motivation,'unknown')
		FROM threat_actors WHERE tenant_id=$1 LIMIT 10`, tid)
	if actorRows != nil {
		for actorRows.Next() {
			var id int
			var name, mot string
			actorRows.Scan(&id, &name, &mot)
			nodeID := fmt.Sprintf("actor_%d", id)
			nodes = append(nodes, GraphNode{ID: nodeID, Label: name, Type: "actor", Count: 1})
		}
		actorRows.Close()
	}

	// Top IOC nodes
	iocRows, _ := database.DB.Query(`
		SELECT id, indicator, type, hit_count
		FROM iocs WHERE tenant_id=$1 AND hit_count > 0
		ORDER BY hit_count DESC LIMIT 12`, tid)
	if iocRows != nil {
		for iocRows.Next() {
			var id, hits int
			var indicator, iocType string
			iocRows.Scan(&id, &indicator, &iocType, &hits)
			nodeID := fmt.Sprintf("ioc_%d", id)
			label := indicator
			if len(label) > 20 {
				label = label[:20] + "…"
			}
			nodes = append(nodes, GraphNode{ID: nodeID, Label: label, Type: "ioc", Count: hits})
		}
		iocRows.Close()
	}

	// Campaign nodes (from clusters)
	campRows, _ := database.DB.Query(`
		SELECT COALESCE(NULLIF(mitre_technique,''),'Unknown'), COUNT(*)::int
		FROM alert_clusters WHERE tenant_id=$1
		GROUP BY 1 ORDER BY 2 DESC LIMIT 6`, tid)
	if campRows != nil {
		for campRows.Next() {
			var tech string
			var cnt int
			campRows.Scan(&tech, &cnt)
			nodeID := "camp_" + strings.ReplaceAll(tech, ".", "_")
			nodes = append(nodes, GraphNode{ID: nodeID, Label: campaignFromTechnique(tech) + " (" + tech + ")", Type: "campaign", Count: cnt})
		}
		campRows.Close()
	}

	// Actor → Campaign edges via mitre_techniques
	actorEdgeRows, _ := database.DB.Query(`
		SELECT ta.id, ta.name, UNNEST(ta.mitre_techniques)
		FROM threat_actors ta
		WHERE ta.tenant_id=$1 AND array_length(ta.mitre_techniques,1) > 0
		LIMIT 20`, tid)
	if actorEdgeRows != nil {
		for actorEdgeRows.Next() {
			var actorID int
			var actorName, tech string
			actorEdgeRows.Scan(&actorID, &actorName, &tech)
			campNodeID := "camp_" + strings.ReplaceAll(tech, ".", "_")
			actorNodeID := fmt.Sprintf("actor_%d", actorID)
			edges = append(edges, GraphEdge{Source: actorNodeID, Target: campNodeID, Label: "uses"})
		}
		actorEdgeRows.Close()
	}

	// Campaign → IOC edges (heuristic: IOC type = ip or domain, hit_count > 0)
	campToIOCRows, _ := database.DB.Query(`
		SELECT DISTINCT 'camp_' || REPLACE(COALESCE(NULLIF(ac.mitre_technique,''),'Unknown'),'.',  '_'),
		       'ioc_' || i.id::text
		FROM alert_clusters ac
		JOIN alerts a ON a.created_at BETWEEN ac.first_seen AND ac.last_seen
		JOIN ioc_blocks ib ON ib.alert_id=a.id
		JOIN iocs i ON i.id=ib.ioc_id
		WHERE ac.tenant_id=$1
		LIMIT 15`, tid)
	if campToIOCRows != nil {
		for campToIOCRows.Next() {
			var src, tgt string
			campToIOCRows.Scan(&src, &tgt)
			edges = append(edges, GraphEdge{Source: src, Target: tgt, Label: "matched"})
		}
		campToIOCRows.Close()
	}

	if nodes == nil {
		nodes = []GraphNode{}
	}
	if edges == nil {
		edges = []GraphEdge{}
	}
	c.JSON(http.StatusOK, gin.H{"nodes": nodes, "edges": edges})
}

// ── PostIntelSearch ────────────────────────────────────────────────────────────

func PostIntelSearch(c *gin.Context) {
	tid := tenantIDFromContext(c)
	var body struct {
		Query string `json:"query"`
		Type  string `json:"type"` // ip, domain, hash, actor, campaign, technique
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Query == "" {
		c.JSON(400, gin.H{"error": "query required"})
		return
	}

	q := "%" + strings.ToLower(body.Query) + "%"

	// IOC matches
	iocRows, _ := database.DB.Query(`
		SELECT id, indicator, type, severity, hit_count, last_seen, description, enabled
		FROM iocs
		WHERE tenant_id=$1 AND (LOWER(indicator) LIKE $2 OR LOWER(description) LIKE $2)
		ORDER BY hit_count DESC LIMIT 20`, tid, q)
	type IOCResult struct {
		ID          int        `json:"id"`
		Indicator   string     `json:"indicator"`
		Type        string     `json:"type"`
		Severity    string     `json:"severity"`
		HitCount    int        `json:"hit_count"`
		LastSeen    *time.Time `json:"last_seen"`
		Description string     `json:"description"`
		Enabled     bool       `json:"enabled"`
	}
	iocs := []IOCResult{}
	if iocRows != nil {
		for iocRows.Next() {
			var r IOCResult
			iocRows.Scan(&r.ID, &r.Indicator, &r.Type, &r.Severity, &r.HitCount, &r.LastSeen, &r.Description, &r.Enabled)
			iocs = append(iocs, r)
		}
		iocRows.Close()
	}
	if iocs == nil {
		iocs = []IOCResult{}
	}

	// Threat actor matches
	actorRows, _ := database.DB.Query(`
		SELECT id, name, motivation, sophistication, description
		FROM threat_actors
		WHERE tenant_id=$1 AND (LOWER(name) LIKE $2 OR LOWER(description) LIKE $2)
		LIMIT 5`, tid, q)
	type ActorResult struct {
		ID             int    `json:"id"`
		Name           string `json:"name"`
		Motivation     string `json:"motivation"`
		Sophistication string `json:"sophistication"`
		Description    string `json:"description"`
	}
	actors := []ActorResult{}
	if actorRows != nil {
		for actorRows.Next() {
			var a ActorResult
			actorRows.Scan(&a.ID, &a.Name, &a.Motivation, &a.Sophistication, &a.Description)
			actors = append(actors, a)
		}
		actorRows.Close()
	}
	if actors == nil {
		actors = []ActorResult{}
	}

	// Sigma rule matches
	sigmaRows, _ := database.DB.Query(`
		SELECT id, title, mitre_technique, severity
		FROM sigma_rules
		WHERE tenant_id=$1 AND (LOWER(title) LIKE $2 OR LOWER(mitre_technique) LIKE $2)
		LIMIT 10`, tid, q)
	type SigmaResult struct {
		ID             int    `json:"id"`
		Title          string `json:"title"`
		MitreTechnique string `json:"mitre_technique"`
		Severity       string `json:"severity"`
	}
	sigma := []SigmaResult{}
	if sigmaRows != nil {
		for sigmaRows.Next() {
			var s SigmaResult
			sigmaRows.Scan(&s.ID, &s.Title, &s.MitreTechnique, &s.Severity)
			sigma = append(sigma, s)
		}
		sigmaRows.Close()
	}
	if sigma == nil {
		sigma = []SigmaResult{}
	}

	// Alert matches
	alertRows, _ := database.DB.Query(`
		SELECT id, rule_name, severity, created_at, COALESCE(source_ip,'')
		FROM alerts
		WHERE tenant_id=$1 AND (LOWER(rule_name) LIKE $2 OR LOWER(source_ip) LIKE $2)
		ORDER BY created_at DESC LIMIT 10`, tid, q)
	type AlertResult struct {
		ID       int       `json:"id"`
		RuleName string    `json:"rule_name"`
		Severity string    `json:"severity"`
		Time     time.Time `json:"time"`
		SourceIP string    `json:"source_ip"`
	}
	alerts := []AlertResult{}
	if alertRows != nil {
		for alertRows.Next() {
			var a AlertResult
			alertRows.Scan(&a.ID, &a.RuleName, &a.Severity, &a.Time, &a.SourceIP)
			alerts = append(alerts, a)
		}
		alertRows.Close()
	}
	if alerts == nil {
		alerts = []AlertResult{}
	}

	c.JSON(http.StatusOK, gin.H{
		"query":  body.Query,
		"iocs":   iocs,
		"actors": actors,
		"sigma":  sigma,
		"alerts": alerts,
		"total":  len(iocs) + len(actors) + len(sigma) + len(alerts),
	})
}

// ── PostIntelAI ────────────────────────────────────────────────────────────────

func PostIntelAI(c *gin.Context) {
	tid := tenantIDFromContext(c)
	var body struct {
		Action    string `json:"action"` // summarize_ioc, actor_profile, campaign_brief, threat_hunt
		Indicator string `json:"indicator"`
		Context   string `json:"context"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}

	// Enrich with recent data
	contextLines := []string{}
	if body.Indicator != "" {
		// IOC context
		var iocDesc, iocType, iocSev string
		var iocHits int
		database.DB.QueryRow(`SELECT COALESCE(description,''), type, severity, hit_count FROM iocs WHERE tenant_id=$1 AND indicator=$2 LIMIT 1`,
			tid, body.Indicator).Scan(&iocDesc, &iocType, &iocSev, &iocHits)
		if iocDesc != "" {
			contextLines = append(contextLines, fmt.Sprintf("IOC: %s (type=%s, severity=%s, hits=%d, desc=%s)", body.Indicator, iocType, iocSev, iocHits, iocDesc))
		}
		// Alert context
		alertCtxRows, _ := database.DB.Query(`
			SELECT rule_name, severity, created_at FROM alerts
			WHERE tenant_id=$1 AND (source_ip=$2 OR rule_name ILIKE '%' || $2 || '%')
			ORDER BY created_at DESC LIMIT 5`, tid, body.Indicator)
		if alertCtxRows != nil {
			for alertCtxRows.Next() {
				var rname, sev string
				var t time.Time
				alertCtxRows.Scan(&rname, &sev, &t)
				contextLines = append(contextLines, fmt.Sprintf("Alert: %s (%s) at %s", rname, sev, t.Format("2006-01-02 15:04")))
			}
			alertCtxRows.Close()
		}
	}
	if body.Context != "" {
		contextLines = append(contextLines, "User context: "+body.Context)
	}
	enrichedContext := strings.Join(contextLines, "\n")

	var prompt string
	switch body.Action {
	case "summarize_ioc":
		prompt = fmt.Sprintf(`You are a threat intelligence analyst. Analyze this IOC and produce a concise intelligence summary. Include: what it is, historical associations, risk assessment, and recommended response. Output ONLY a JSON object: {"summary": "...", "risk": "critical|high|medium|low", "type": "...", "associations": ["..."], "recommendations": ["..."], "confidence": "high|medium|low"}

Indicator: %s
%s`, body.Indicator, enrichedContext)
	case "actor_profile":
		prompt = fmt.Sprintf(`You are a threat intelligence expert. Create a threat actor intelligence profile. Include: attribution confidence, motivation, capability assessment, known TTPs, and defensive recommendations. Output ONLY a JSON object: {"actor_name": "...", "confidence": "high|medium|low", "motivation": "...", "capability": "nation-state|advanced|intermediate|basic", "ttps": ["..."], "target_sectors": ["..."], "defensive_recommendations": ["..."]}

Context: %s`, enrichedContext)
	case "campaign_brief":
		prompt = fmt.Sprintf(`You are a SOC analyst. Write an intelligence brief on this campaign or threat activity. Include: campaign attribution, timeline, affected sectors, IOC summary, and detection guidance. Output ONLY a JSON object: {"campaign_name": "...", "threat_actor": "...", "timeline": "...", "affected_sectors": ["..."], "ioc_summary": "...", "detection_guidance": ["..."], "confidence": "high|medium|low"}

Context: %s`, enrichedContext)
	case "threat_hunt":
		prompt = fmt.Sprintf(`You are a threat hunter. Based on this IOC or context, propose a threat hunting plan. Suggest: hunt hypotheses, data sources to query, detection logic, and expected artifacts. Output ONLY a JSON object: {"hypothesis": "...", "data_sources": ["..."], "hunt_queries": ["..."], "expected_artifacts": ["..."], "priority": "high|medium|low"}

Indicator: %s
%s`, body.Indicator, enrichedContext)
	default:
		c.JSON(400, gin.H{"error": "unknown action"})
		return
	}

	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
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

// ── GetIntelWatchlist ──────────────────────────────────────────────────────────

func GetIntelWatchlist(c *gin.Context) {
	tid := tenantIDFromContext(c)
	// Return high-priority IOCs as watchlist proxy
	rows, err := database.DB.Query(`
		SELECT id, indicator, type, severity, hit_count, last_seen, description, created_at
		FROM iocs
		WHERE tenant_id=$1 AND severity IN ('critical','high') AND enabled=true
		ORDER BY hit_count DESC, created_at DESC
		LIMIT 50`, tid)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type WatchItem struct {
		ID          int        `json:"id"`
		Indicator   string     `json:"indicator"`
		Type        string     `json:"type"`
		Severity    string     `json:"severity"`
		HitCount    int        `json:"hit_count"`
		LastSeen    *time.Time `json:"last_seen"`
		Description string     `json:"description"`
		AddedAt     time.Time  `json:"added_at"`
	}
	out := []WatchItem{}
	for rows.Next() {
		var w WatchItem
		rows.Scan(&w.ID, &w.Indicator, &w.Type, &w.Severity, &w.HitCount, &w.LastSeen, &w.Description, &w.AddedAt)
		out = append(out, w)
	}
	if out == nil {
		out = []WatchItem{}
	}
	c.JSON(http.StatusOK, gin.H{"watchlist": out})
}

// ── GetIntelIOCTimeline ────────────────────────────────────────────────────────

func GetIntelIOCTimeline(c *gin.Context) {
	tid := tenantIDFromContext(c)
	hours := parseHours(c, 168) // default 7 days

	rows, err := database.DB.Query(`
		SELECT id, indicator, type, severity, hit_count, created_at, last_seen, expires_at
		FROM iocs
		WHERE tenant_id=$1
		  AND (created_at > NOW()-($2::int)*INTERVAL'1 hour'
		       OR (last_seen IS NOT NULL AND last_seen > NOW()-($2::int)*INTERVAL'1 hour'))
		ORDER BY GREATEST(created_at, COALESCE(last_seen, created_at)) DESC
		LIMIT 100`, tid, hours)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type TimelineIOC struct {
		ID        int        `json:"id"`
		Indicator string     `json:"indicator"`
		Type      string     `json:"type"`
		Severity  string     `json:"severity"`
		HitCount  int        `json:"hit_count"`
		CreatedAt time.Time  `json:"created_at"`
		LastSeen  *time.Time `json:"last_seen"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	out := []TimelineIOC{}
	for rows.Next() {
		var t TimelineIOC
		rows.Scan(&t.ID, &t.Indicator, &t.Type, &t.Severity, &t.HitCount, &t.CreatedAt, &t.LastSeen, &t.ExpiresAt)
		out = append(out, t)
	}
	if out == nil {
		out = []TimelineIOC{}
	}
	c.JSON(http.StatusOK, gin.H{"events": out, "total": len(out)})
}
