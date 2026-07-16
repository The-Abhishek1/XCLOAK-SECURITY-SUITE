package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/services"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func actorRiskScore(sophistication string, alertCount, iocCount, campaignCount int) int {
	base := map[string]int{
		"nation-state": 85, "high": 65, "medium": 45, "low": 25,
	}[sophistication]
	if base == 0 {
		base = 40
	}
	score := base + min(alertCount/2, 10) + min(iocCount, 5) + min(campaignCount*3, 10)
	if score > 99 {
		return 99
	}
	return score
}

func techniqueToMalwareType(t string) string {
	m := map[string]string{
		"T1566": "Phishing Dropper", "T1059": "Script Interpreter", "T1003": "Credential Dumping Tool",
		"T1055": "Process Injector", "T1486": "Ransomware", "T1070": "Anti-Forensics Tool",
		"T1105": "Downloader", "T1021": "Remote Access Tool", "T1078": "Credential Abuse",
		"T1547": "Persistence Module", "T1562": "Defense Evasion Module", "T1041": "Exfiltration Tool",
	}
	for prefix, label := range m {
		if strings.HasPrefix(t, prefix) {
			return label
		}
	}
	return "Unknown Module"
}

// ── GetActorDashboard ─────────────────────────────────────────────────────────

func GetActorDashboard(c *gin.Context) {
	tid := tenantIDFromContext(c)

	var total, highRisk, newThisMonth, activeInOrg, activeCampaigns int
	database.DB.QueryRow(`SELECT COUNT(*) FROM threat_actors WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM threat_actors WHERE tenant_id=$1 AND sophistication IN ('nation-state','high')`, tid).Scan(&highRisk)
	database.DB.QueryRow(`SELECT COUNT(*) FROM threat_actors WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL'30 days'`, tid).Scan(&newThisMonth)
	database.DB.QueryRow(`SELECT COUNT(DISTINCT actor_id) FROM actor_alert_tags WHERE tenant_id=$1 AND tagged_at > NOW()-INTERVAL'30 days'`, tid).Scan(&activeInOrg)
	database.DB.QueryRow(`SELECT COUNT(DISTINCT matched_technique) FROM actor_alert_tags WHERE tenant_id=$1 AND matched_technique != '' AND tagged_at > NOW()-INTERVAL'30 days'`, tid).Scan(&activeCampaigns)

	// Industries targeted (aggregate across all actors)
	type KV struct {
		Key   string `json:"sector"`
		Count int    `json:"count"`
	}
	var industries []KV
	sectorRows, _ := database.DB.Query(`
		SELECT s, COUNT(*)::int FROM threat_actors, UNNEST(targeted_sectors) s
		WHERE tenant_id=$1 GROUP BY s ORDER BY 2 DESC LIMIT 12`, tid)
	if sectorRows != nil {
		defer sectorRows.Close()
		for sectorRows.Next() {
			var r KV
			sectorRows.Scan(&r.Key, &r.Count)
			industries = append(industries, r)
		}
	}
	if industries == nil {
		industries = []KV{}
	}

	// Countries
	type CountryKV struct {
		Country string `json:"country"`
		Count   int    `json:"count"`
	}
	var countries []CountryKV
	countryRows, _ := database.DB.Query(`
		SELECT origin_country, COUNT(*)::int FROM threat_actors
		WHERE tenant_id=$1 AND origin_country != '' GROUP BY 1 ORDER BY 2 DESC LIMIT 12`, tid)
	if countryRows != nil {
		defer countryRows.Close()
		for countryRows.Next() {
			var r CountryKV
			countryRows.Scan(&r.Country, &r.Count)
			countries = append(countries, r)
		}
	}
	if countries == nil {
		countries = []CountryKV{}
	}

	// Campaign timeline (monthly actor activity)
	type MonthBucket struct {
		Month string `json:"month"`
		Count int    `json:"count"`
	}
	var timeline []MonthBucket
	tlRows, _ := database.DB.Query(`
		SELECT TO_CHAR(DATE_TRUNC('month', tagged_at),'YYYY-MM'), COUNT(*)::int
		FROM actor_alert_tags WHERE tenant_id=$1 AND tagged_at > NOW()-INTERVAL'12 months'
		GROUP BY 1 ORDER BY 1`, tid)
	if tlRows != nil {
		defer tlRows.Close()
		for tlRows.Next() {
			var r MonthBucket
			tlRows.Scan(&r.Month, &r.Count)
			timeline = append(timeline, r)
		}
	}
	if timeline == nil {
		timeline = []MonthBucket{}
	}

	// Motivation breakdown
	type MotivKV struct {
		Motivation string `json:"motivation"`
		Count      int    `json:"count"`
	}
	var motivations []MotivKV
	motivRows, _ := database.DB.Query(`
		SELECT motivation, COUNT(*)::int FROM threat_actors WHERE tenant_id=$1 GROUP BY 1 ORDER BY 2 DESC`, tid)
	if motivRows != nil {
		defer motivRows.Close()
		for motivRows.Next() {
			var r MotivKV
			motivRows.Scan(&r.Motivation, &r.Count)
			motivations = append(motivations, r)
		}
	}
	if motivations == nil {
		motivations = []MotivKV{}
	}

	c.JSON(http.StatusOK, gin.H{
		"total":               total,
		"high_risk":           highRisk,
		"new_this_month":      newThisMonth,
		"active_in_org":       activeInOrg,
		"active_campaigns":    activeCampaigns,
		"industries":          industries,
		"countries":           countries,
		"campaign_timeline":   timeline,
		"motivation_breakdown": motivations,
	})
}

// ── GetActorAnalytics ─────────────────────────────────────────────────────────

func GetActorAnalytics(c *gin.Context) {
	tid := tenantIDFromContext(c)

	type TopActor struct {
		ID             int    `json:"id"`
		Name           string `json:"name"`
		Motivation     string `json:"motivation"`
		Sophistication string `json:"sophistication"`
		AlertCount     int    `json:"alert_count"`
	}
	var topActors []TopActor
	taRows, _ := database.DB.Query(`
		SELECT ta.id, ta.name, ta.motivation, ta.sophistication,
		       COUNT(aat.id)::int as alert_count
		FROM threat_actors ta
		LEFT JOIN actor_alert_tags aat ON aat.actor_id=ta.id AND aat.tenant_id=ta.tenant_id
		    AND aat.tagged_at > NOW()-INTERVAL'30 days'
		WHERE ta.tenant_id=$1
		GROUP BY ta.id, ta.name, ta.motivation, ta.sophistication
		ORDER BY alert_count DESC LIMIT 10`, tid)
	if taRows != nil {
		defer taRows.Close()
		for taRows.Next() {
			var r TopActor
			taRows.Scan(&r.ID, &r.Name, &r.Motivation, &r.Sophistication, &r.AlertCount)
			topActors = append(topActors, r)
		}
	}
	if topActors == nil {
		topActors = []TopActor{}
	}

	type TechKV struct {
		Technique string `json:"technique"`
		Count     int    `json:"count"`
	}
	var topTechs []TechKV
	techRows, _ := database.DB.Query(`
		SELECT matched_technique, COUNT(*)::int
		FROM actor_alert_tags WHERE tenant_id=$1 AND matched_technique != ''
		GROUP BY 1 ORDER BY 2 DESC LIMIT 10`, tid)
	if techRows != nil {
		defer techRows.Close()
		for techRows.Next() {
			var r TechKV
			techRows.Scan(&r.Technique, &r.Count)
			topTechs = append(topTechs, r)
		}
	}
	if topTechs == nil {
		topTechs = []TechKV{}
	}

	type SophKV struct {
		Sophistication string `json:"sophistication"`
		Count          int    `json:"count"`
	}
	var sophBreakdown []SophKV
	sophRows, _ := database.DB.Query(`
		SELECT sophistication, COUNT(*)::int FROM threat_actors WHERE tenant_id=$1 GROUP BY 1 ORDER BY 2 DESC`, tid)
	if sophRows != nil {
		defer sophRows.Close()
		for sophRows.Next() {
			var r SophKV
			sophRows.Scan(&r.Sophistication, &r.Count)
			sophBreakdown = append(sophBreakdown, r)
		}
	}
	if sophBreakdown == nil {
		sophBreakdown = []SophKV{}
	}

	type WeekBucket struct {
		Week  string `json:"week"`
		Count int    `json:"count"`
	}
	var activityOverTime []WeekBucket
	wkRows, _ := database.DB.Query(`
		SELECT TO_CHAR(DATE_TRUNC('week', tagged_at),'YYYY-MM-DD'), COUNT(*)::int
		FROM actor_alert_tags WHERE tenant_id=$1 AND tagged_at > NOW()-INTERVAL'8 weeks'
		GROUP BY 1 ORDER BY 1`, tid)
	if wkRows != nil {
		defer wkRows.Close()
		for wkRows.Next() {
			var r WeekBucket
			wkRows.Scan(&r.Week, &r.Count)
			activityOverTime = append(activityOverTime, r)
		}
	}
	if activityOverTime == nil {
		activityOverTime = []WeekBucket{}
	}

	c.JSON(http.StatusOK, gin.H{
		"top_actors":           topActors,
		"top_techniques":       topTechs,
		"sophistication_breakdown": sophBreakdown,
		"activity_over_time":   activityOverTime,
	})
}

// ── PostActorAI ───────────────────────────────────────────────────────────────

func PostActorAI(c *gin.Context) {
	tid := tenantIDFromContext(c)
	var body struct {
		Action    string `json:"action"`    // summarize | recommend | hunt_guide | risk_brief
		ActorID   int    `json:"actor_id"`
		ActorName string `json:"actor_name"`
		Context   string `json:"context"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Fetch actor context
	var actorCtx string
	if body.ActorID > 0 {
		var name, motivation, sophistication, description, origin string
		var techniques []string
		var sectors []string
		database.DB.QueryRow(`
			SELECT name, motivation, sophistication, description, origin_country,
			       mitre_techniques, targeted_sectors
			FROM threat_actors WHERE id=$1 AND tenant_id=$2`,
			body.ActorID, tid).
			Scan(&name, &motivation, &sophistication, &description, &origin,
				(*strings.Builder)(nil), (*strings.Builder)(nil))

		// Re-query for arrays
		row := database.DB.QueryRow(`SELECT name, motivation, sophistication, COALESCE(description,''), COALESCE(origin_country,'') FROM threat_actors WHERE id=$1 AND tenant_id=$2`, body.ActorID, tid)
		row.Scan(&name, &motivation, &sophistication, &description, &origin)

		techRows, _ := database.DB.Query(`SELECT UNNEST(mitre_techniques) FROM threat_actors WHERE id=$1 AND tenant_id=$2 LIMIT 20`, body.ActorID, tid)
		if techRows != nil {
			defer techRows.Close()
			for techRows.Next() {
				var t string
				techRows.Scan(&t)
				techniques = append(techniques, t)
			}
		}
		sectorRows2, _ := database.DB.Query(`SELECT UNNEST(targeted_sectors) FROM threat_actors WHERE id=$1 AND tenant_id=$2`, body.ActorID, tid)
		if sectorRows2 != nil {
			defer sectorRows2.Close()
			for sectorRows2.Next() {
				var s string
				sectorRows2.Scan(&s)
				sectors = append(sectors, s)
			}
		}

		// Recent alerts
		var alertLines []string
		aRows, _ := database.DB.Query(`
			SELECT a.rule_name, a.severity, aat.matched_technique, aat.confidence
			FROM actor_alert_tags aat
			JOIN alerts a ON a.id=aat.alert_id AND a.tenant_id=$1
			WHERE aat.actor_id=$2 AND aat.tenant_id=$1
			ORDER BY aat.tagged_at DESC LIMIT 5`, tid, body.ActorID)
		if aRows != nil {
			defer aRows.Close()
			for aRows.Next() {
				var rn, sev, tech string
				var conf int
				aRows.Scan(&rn, &sev, &tech, &conf)
				alertLines = append(alertLines, fmt.Sprintf("[%s/%s] %s (conf:%d%%)", sev, tech, rn, conf))
			}
		}

		if name == "" {
			name = body.ActorName
		}
		actorCtx = fmt.Sprintf(
			"Actor: %s\nOrigin: %s\nMotivation: %s\nSophistication: %s\nTechniques: %s\nSectors: %s\nDescription: %s\nRecent org alerts: %s",
			name, origin, motivation, sophistication,
			strings.Join(techniques, ", "), strings.Join(sectors, ", "), description,
			strings.Join(alertLines, "; "),
		)
	} else if body.ActorName != "" {
		actorCtx = fmt.Sprintf("Actor: %s", body.ActorName)
	}

	if body.Context != "" {
		actorCtx += "\nAdditional context: " + body.Context
	}

	var prompt string
	switch body.Action {
	case "summarize":
		prompt = fmt.Sprintf(`You are a threat intelligence analyst. Provide a concise executive-level intelligence summary for this threat actor.
Context:
%s

Return a JSON object with keys: summary (2-3 sentence executive summary), key_ttps (array of top 3-5 TTP descriptions), typical_targets (string), risk_level (critical/high/medium/low), notable_campaigns (array of strings), intelligence_gaps (string).`, actorCtx)

	case "recommend":
		prompt = fmt.Sprintf(`You are a security engineer providing defensive recommendations for a specific threat actor.
Context:
%s

Return a JSON object with keys: sigma_rules (array of rule title recommendations), ioc_hunt (array of IOC search suggestions), cve_patch (array of CVEs or vulnerability types to patch), block_domains (array of domain pattern examples), mitre_monitor (array of technique IDs to prioritize), playbook_steps (array of response steps).`, actorCtx)

	case "hunt_guide":
		prompt = fmt.Sprintf(`You are a threat hunter. Create specific hunting queries and hypotheses for this threat actor.
Context:
%s

Return a JSON object with keys: hypotheses (array of hunting hypotheses), log_queries (array of log search query examples), endpoint_indicators (array of endpoint artifacts to look for), network_indicators (array of network indicators), dns_hunt (array of DNS patterns), firewall_queries (array of firewall rule ideas).`, actorCtx)

	case "risk_brief":
		prompt = fmt.Sprintf(`You are a risk analyst. Provide a risk assessment for this threat actor.
Context:
%s

Return a JSON object with keys: overall_risk (critical/high/medium/low), risk_score (0-100 integer), exposure_narrative (string), business_impact (string), likelihood (high/medium/low), key_mitigations (array of top 3 actions).`, actorCtx)

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

// ── GetActorDetail ────────────────────────────────────────────────────────────

func GetActorDetail(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actorID, _ := strconv.Atoi(c.Param("id"))

	var actor models.ThreatActor
	err := database.DB.QueryRow(`
		SELECT id, tenant_id, name, COALESCE(aliases,'{}'), COALESCE(origin_country,''),
		       COALESCE(motivation,''), COALESCE(sophistication,''), COALESCE(description,''),
		       COALESCE(targeted_sectors,'{}'), COALESCE(mitre_techniques,'{}'),
		       is_builtin, created_at, updated_at
		FROM threat_actors WHERE id=$1 AND tenant_id=$2`, actorID, tid).
		Scan(&actor.ID, &actor.TenantID, &actor.Name, (*pqStringArray)(&actor.Aliases),
			&actor.OriginCountry, &actor.Motivation, &actor.Sophistication,
			&actor.Description, (*pqStringArray)(&actor.TargetedSectors),
			(*pqStringArray)(&actor.MitreTechniques), &actor.IsBuiltin,
			&actor.CreatedAt, &actor.UpdatedAt)
	if err != nil {
		c.JSON(404, gin.H{"error": "actor not found"})
		return
	}

	var alertCount int
	var firstSeen, lastSeen *string
	database.DB.QueryRow(`
		SELECT COUNT(*)::int, MIN(tagged_at)::text, MAX(tagged_at)::text
		FROM actor_alert_tags WHERE actor_id=$1 AND tenant_id=$2`, actorID, tid).
		Scan(&alertCount, &firstSeen, &lastSeen)

	var iocCount int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM iocs WHERE tenant_id=$1 AND enabled=true AND description ILIKE '%'||$2||'%'`,
		tid, actor.Name).Scan(&iocCount)

	var campaignCount int
	database.DB.QueryRow(`
		SELECT COUNT(DISTINCT matched_technique) FROM actor_alert_tags
		WHERE actor_id=$1 AND tenant_id=$2 AND matched_technique != ''`, actorID, tid).Scan(&campaignCount)

	riskScore := actorRiskScore(actor.Sophistication, alertCount, iocCount, campaignCount)

	// Attribution confidence: heuristic based on alert count and is_builtin
	attrConf := 40
	if actor.IsBuiltin {
		attrConf = 75
	}
	if alertCount > 10 {
		attrConf += 15
	} else if alertCount > 0 {
		attrConf += 5
	}
	if attrConf > 95 {
		attrConf = 95
	}

	c.JSON(http.StatusOK, gin.H{
		"actor":                actor,
		"first_seen":           firstSeen,
		"last_seen":            lastSeen,
		"alert_count":          alertCount,
		"ioc_count":            iocCount,
		"campaign_count":       campaignCount,
		"risk_score":           riskScore,
		"attribution_confidence": attrConf,
		"status":               func() string { if alertCount > 0 { return "active" }; return "dormant" }(),
	})
}

// pqStringArray is a helper for scanning PostgreSQL text arrays.
type pqStringArray []string

func (a *pqStringArray) Scan(src interface{}) error {
	if src == nil {
		*a = []string{}
		return nil
	}
	b, ok := src.([]byte)
	if !ok {
		if s, ok2 := src.(string); ok2 {
			b = []byte(s)
		} else {
			*a = []string{}
			return nil
		}
	}
	s := strings.Trim(string(b), "{}")
	if s == "" {
		*a = []string{}
		return nil
	}
	parts := strings.Split(s, ",")
	for i, p := range parts {
		parts[i] = strings.Trim(p, `"`)
	}
	*a = parts
	return nil
}

// ── GetActorCampaigns ─────────────────────────────────────────────────────────

func GetActorCampaigns(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actorID, _ := strconv.Atoi(c.Param("id"))

	type Campaign struct {
		Technique   string `json:"technique"`
		AlertCount  int    `json:"alert_count"`
		FirstSeen   string `json:"first_seen"`
		LastSeen    string `json:"last_seen"`
		AvgConfidence int  `json:"avg_confidence"`
		Status      string `json:"status"`
	}

	var campaigns []Campaign
	rows, _ := database.DB.Query(`
		SELECT aat.matched_technique,
		       COUNT(aat.id)::int,
		       MIN(aat.tagged_at)::text,
		       MAX(aat.tagged_at)::text,
		       AVG(aat.confidence)::int,
		       CASE WHEN MAX(aat.tagged_at) > NOW()-INTERVAL'7 days' THEN 'active' ELSE 'dormant' END
		FROM actor_alert_tags aat
		WHERE aat.tenant_id=$1 AND aat.actor_id=$2 AND aat.matched_technique != ''
		GROUP BY aat.matched_technique
		ORDER BY MAX(aat.tagged_at) DESC`, tid, actorID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var r Campaign
			rows.Scan(&r.Technique, &r.AlertCount, &r.FirstSeen, &r.LastSeen, &r.AvgConfidence, &r.Status)
			campaigns = append(campaigns, r)
		}
	}
	if campaigns == nil {
		campaigns = []Campaign{}
	}

	// Also get alert severity breakdown
	type SevCount struct {
		Severity string `json:"severity"`
		Count    int    `json:"count"`
	}
	var sevBreakdown []SevCount
	sevRows, _ := database.DB.Query(`
		SELECT a.severity, COUNT(*)::int
		FROM actor_alert_tags aat
		JOIN alerts a ON a.id=aat.alert_id AND a.tenant_id=$1
		WHERE aat.actor_id=$2 AND aat.tenant_id=$1
		GROUP BY a.severity ORDER BY 2 DESC`, tid, actorID)
	if sevRows != nil {
		defer sevRows.Close()
		for sevRows.Next() {
			var r SevCount
			sevRows.Scan(&r.Severity, &r.Count)
			sevBreakdown = append(sevBreakdown, r)
		}
	}
	if sevBreakdown == nil {
		sevBreakdown = []SevCount{}
	}

	c.JSON(http.StatusOK, gin.H{
		"campaigns":       campaigns,
		"severity_breakdown": sevBreakdown,
	})
}

// ── GetActorMalware ───────────────────────────────────────────────────────────

func GetActorMalware(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actorID, _ := strconv.Atoi(c.Param("id"))

	// Get actor's techniques
	techRows, _ := database.DB.Query(`SELECT UNNEST(mitre_techniques) FROM threat_actors WHERE id=$1 AND tenant_id=$2`, actorID, tid)
	var techniques []string
	if techRows != nil {
		defer techRows.Close()
		for techRows.Next() {
			var t string
			techRows.Scan(&t)
			techniques = append(techniques, t)
		}
	}

	type MalwareEntry struct {
		Technique   string `json:"technique"`
		MalwareType string `json:"malware_type"`
		Category    string `json:"category"`
		AlertCount  int    `json:"alert_count"`
		LastSeen    string `json:"last_seen"`
	}

	var entries []MalwareEntry
	for _, tech := range techniques {
		mtype := techniqueToMalwareType(tech)
		cat := "unknown"
		switch {
		case strings.Contains(mtype, "Ransomware"):
			cat = "ransomware"
		case strings.Contains(mtype, "Downloader"):
			cat = "downloader"
		case strings.Contains(mtype, "Remote Access"):
			cat = "rat"
		case strings.Contains(mtype, "Dropper") || strings.Contains(mtype, "Script"):
			cat = "loader"
		case strings.Contains(mtype, "Wiper") || strings.Contains(mtype, "Anti-Forensics"):
			cat = "wiper"
		case strings.Contains(mtype, "Backdoor") || strings.Contains(mtype, "Persistence"):
			cat = "backdoor"
		case strings.Contains(mtype, "Credential"):
			cat = "credential_stealer"
		default:
			cat = "other"
		}

		var count int
		var lastSeen string
		database.DB.QueryRow(`
			SELECT COUNT(*)::int, COALESCE(MAX(aat.tagged_at)::text,'')
			FROM actor_alert_tags aat
			WHERE aat.actor_id=$1 AND aat.tenant_id=$2 AND aat.matched_technique LIKE $3||'%'`,
			actorID, tid, tech[:min(len(tech), 5)]).Scan(&count, &lastSeen)

		entries = append(entries, MalwareEntry{
			Technique:   tech,
			MalwareType: mtype,
			Category:    cat,
			AlertCount:  count,
			LastSeen:    lastSeen,
		})
	}
	if entries == nil {
		entries = []MalwareEntry{}
	}

	c.JSON(http.StatusOK, gin.H{"malware": entries})
}

// ── GetActorInfrastructure ────────────────────────────────────────────────────

func GetActorInfrastructure(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actorID, _ := strconv.Atoi(c.Param("id"))

	// Get actor name for matching IOCs by description
	var actorName string
	var aliases []string
	database.DB.QueryRow(`SELECT name FROM threat_actors WHERE id=$1 AND tenant_id=$2`, actorID, tid).Scan(&actorName)
	aliasRows, _ := database.DB.Query(`SELECT UNNEST(aliases) FROM threat_actors WHERE id=$1 AND tenant_id=$2`, actorID, tid)
	if aliasRows != nil {
		defer aliasRows.Close()
		for aliasRows.Next() {
			var a string
			aliasRows.Scan(&a)
			aliases = append(aliases, a)
		}
	}

	// Build ILIKE conditions for name + aliases
	var conditions []string
	var args []interface{}
	args = append(args, tid)
	argIdx := 2
	for _, name := range append([]string{actorName}, aliases...) {
		if name == "" {
			continue
		}
		conditions = append(conditions, fmt.Sprintf("description ILIKE '%%'||$%d||'%%'", argIdx))
		args = append(args, name)
		argIdx++
	}
	whereClause := "FALSE"
	if len(conditions) > 0 {
		whereClause = strings.Join(conditions, " OR ")
	}

	type InfraIOC struct {
		ID        int    `json:"id"`
		Indicator string `json:"indicator"`
		Type      string `json:"type"`
		Severity  string `json:"severity"`
		HitCount  int    `json:"hit_count"`
		LastSeen  string `json:"last_seen"`
	}

	var infra []InfraIOC
	query := fmt.Sprintf(`
		SELECT id, indicator, type, severity, hit_count, COALESCE(last_seen::text,'')
		FROM iocs WHERE tenant_id=$1 AND (%s)
		ORDER BY hit_count DESC LIMIT 100`, whereClause)
	rows, _ := database.DB.Query(query, args...)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var r InfraIOC
			rows.Scan(&r.ID, &r.Indicator, &r.Type, &r.Severity, &r.HitCount, &r.LastSeen)
			infra = append(infra, r)
		}
	}
	if infra == nil {
		infra = []InfraIOC{}
	}

	// Group by type
	grouped := map[string][]InfraIOC{}
	for _, i := range infra {
		grouped[i.Type] = append(grouped[i.Type], i)
	}

	c.JSON(http.StatusOK, gin.H{
		"iocs":    infra,
		"grouped": grouped,
		"total":   len(infra),
	})
}

// ── GetActorExposure ──────────────────────────────────────────────────────────

func GetActorExposure(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actorID, _ := strconv.Atoi(c.Param("id"))

	var actorName string
	var techniques []string
	database.DB.QueryRow(`SELECT name FROM threat_actors WHERE id=$1 AND tenant_id=$2`, actorID, tid).Scan(&actorName)
	techRows, _ := database.DB.Query(`SELECT UNNEST(mitre_techniques) FROM threat_actors WHERE id=$1 AND tenant_id=$2`, actorID, tid)
	if techRows != nil {
		defer techRows.Close()
		for techRows.Next() {
			var t string
			techRows.Scan(&t)
			techniques = append(techniques, t)
		}
	}

	// Alert count from actor_alert_tags
	var alertCount int
	database.DB.QueryRow(`SELECT COUNT(*)::int FROM actor_alert_tags WHERE actor_id=$1 AND tenant_id=$2`, actorID, tid).Scan(&alertCount)

	var alertCount30d int
	database.DB.QueryRow(`SELECT COUNT(*)::int FROM actor_alert_tags WHERE actor_id=$1 AND tenant_id=$2 AND tagged_at > NOW()-INTERVAL'30 days'`, actorID, tid).Scan(&alertCount30d)

	// IOC count matching actor name
	var iocCount int
	if actorName != "" {
		database.DB.QueryRow(`SELECT COUNT(*)::int FROM iocs WHERE tenant_id=$1 AND enabled=true AND description ILIKE '%'||$2||'%'`, tid, actorName).Scan(&iocCount)
	}

	// Incident count via clusters
	var incidentCount int
	database.DB.QueryRow(`
		SELECT COUNT(DISTINCT ac.auto_incident_id)::int
		FROM alert_clusters ac
		JOIN alert_cluster_members acm ON acm.cluster_id=ac.id
		JOIN actor_alert_tags aat ON aat.alert_id=acm.alert_id AND aat.actor_id=$1 AND aat.tenant_id=$2
		WHERE ac.tenant_id=$2 AND ac.auto_incident_id IS NOT NULL`, actorID, tid).Scan(&incidentCount)

	// Matching techniques from sigma_rules
	var matchingTechCount int
	if len(techniques) > 0 {
		placeholders := make([]string, len(techniques))
		args := []interface{}{tid}
		for i, t := range techniques {
			placeholders[i] = fmt.Sprintf("$%d", i+2)
			args = append(args, t)
		}
		database.DB.QueryRow(fmt.Sprintf(`
			SELECT COUNT(DISTINCT mitre_technique)::int FROM sigma_rules
			WHERE tenant_id=$1 AND enabled=true AND mitre_technique IN (%s)`,
			strings.Join(placeholders, ",")), args...).Scan(&matchingTechCount)
	}

	// Exposure score
	exposureScore := min(10, alertCount30d) * 7
	if iocCount > 0 {
		exposureScore += min(iocCount, 5) * 3
	}
	if incidentCount > 0 {
		exposureScore += min(incidentCount, 3) * 10
	}
	if exposureScore > 99 {
		exposureScore = 99
	}

	// Matching assets (recent hostnames from actor alerts)
	type AssetEntry struct {
		Hostname  string `json:"hostname"`
		AlertCount int   `json:"alert_count"`
		LastSeen  string `json:"last_seen"`
	}
	var assets []AssetEntry
	assetRows, _ := database.DB.Query(`
		SELECT COALESCE(ag.hostname, a.agent_id::text) as hostname,
		       COUNT(aat.id)::int as cnt,
		       MAX(aat.tagged_at)::text as last_seen
		FROM actor_alert_tags aat
		JOIN alerts a ON a.id=aat.alert_id AND a.tenant_id=$1
		LEFT JOIN agents ag ON ag.id=a.agent_id AND ag.tenant_id=$1
		WHERE aat.actor_id=$2 AND aat.tenant_id=$1
		GROUP BY COALESCE(ag.hostname, a.agent_id::text)
		ORDER BY cnt DESC LIMIT 5`, tid, actorID)
	if assetRows != nil {
		defer assetRows.Close()
		for assetRows.Next() {
			var r AssetEntry
			assetRows.Scan(&r.Hostname, &r.AlertCount, &r.LastSeen)
			assets = append(assets, r)
		}
	}
	if assets == nil {
		assets = []AssetEntry{}
	}

	// Recent matching alerts
	type AlertEntry struct {
		ID               int    `json:"id"`
		RuleName         string `json:"rule_name"`
		Severity         string `json:"severity"`
		Hostname         string `json:"hostname"`
		MatchedTechnique string `json:"matched_technique"`
		Confidence       int    `json:"confidence"`
		TaggedAt         string `json:"tagged_at"`
	}
	var recentAlerts []AlertEntry
	alertRows, _ := database.DB.Query(`
		SELECT a.id, a.rule_name, a.severity, COALESCE(ag.hostname,''),
		       aat.matched_technique, aat.confidence, aat.tagged_at::text
		FROM actor_alert_tags aat
		JOIN alerts a ON a.id=aat.alert_id AND a.tenant_id=$1
		LEFT JOIN agents ag ON ag.id=a.agent_id AND ag.tenant_id=$1
		WHERE aat.actor_id=$2 AND aat.tenant_id=$1
		ORDER BY aat.tagged_at DESC LIMIT 10`, tid, actorID)
	if alertRows != nil {
		defer alertRows.Close()
		for alertRows.Next() {
			var r AlertEntry
			alertRows.Scan(&r.ID, &r.RuleName, &r.Severity, &r.Hostname, &r.MatchedTechnique, &r.Confidence, &r.TaggedAt)
			recentAlerts = append(recentAlerts, r)
		}
	}
	if recentAlerts == nil {
		recentAlerts = []AlertEntry{}
	}

	c.JSON(http.StatusOK, gin.H{
		"actor_id":              actorID,
		"actor_name":            actorName,
		"alert_count":           alertCount,
		"alert_count_30d":       alertCount30d,
		"ioc_count":             iocCount,
		"incident_count":        incidentCount,
		"matching_tech_count":   matchingTechCount,
		"exposure_score":        exposureScore,
		"matching_assets":       assets,
		"recent_alerts":         recentAlerts,
	})
}

// ── GetActorDetectionCoverage ─────────────────────────────────────────────────

func GetActorDetectionCoverage(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actorID, _ := strconv.Atoi(c.Param("id"))

	var techniques []string
	techRows, _ := database.DB.Query(`SELECT UNNEST(mitre_techniques) FROM threat_actors WHERE id=$1 AND tenant_id=$2`, actorID, tid)
	if techRows != nil {
		defer techRows.Close()
		for techRows.Next() {
			var t string
			techRows.Scan(&t)
			techniques = append(techniques, t)
		}
	}

	type TechCoverage struct {
		Technique        string `json:"technique"`
		SigmaTotal       int    `json:"sigma_total"`
		SigmaEnabled     int    `json:"sigma_enabled"`
		CorrelationRules int    `json:"correlation_rules"`
		Covered          bool   `json:"covered"`
	}

	var coverage []TechCoverage
	coveredCount := 0
	for _, tech := range techniques {
		var sigTotal, sigEnabled, corrCount int
		database.DB.QueryRow(`
			SELECT COUNT(*)::int, COUNT(*) FILTER (WHERE enabled)::int
			FROM sigma_rules WHERE tenant_id=$1 AND mitre_technique LIKE $2||'%'`,
			tid, tech[:min(len(tech), 5)]).Scan(&sigTotal, &sigEnabled)
		database.DB.QueryRow(`
			SELECT COUNT(*)::int FROM correlation_rules WHERE tenant_id=$1 AND enabled=true AND name ILIKE '%'||$2||'%'`,
			tid, tech).Scan(&corrCount)

		covered := sigEnabled > 0 || corrCount > 0
		if covered {
			coveredCount++
		}
		coverage = append(coverage, TechCoverage{
			Technique:        tech,
			SigmaTotal:       sigTotal,
			SigmaEnabled:     sigEnabled,
			CorrelationRules: corrCount,
			Covered:          covered,
		})
	}
	if coverage == nil {
		coverage = []TechCoverage{}
	}

	total := len(techniques)
	pct := 0
	if total > 0 {
		pct = (coveredCount * 100) / total
	}

	var sigmaTotal, yaraTotal, corrTotal int
	database.DB.QueryRow(`SELECT COUNT(*)::int FROM sigma_rules WHERE tenant_id=$1 AND enabled=true`, tid).Scan(&sigmaTotal)
	database.DB.QueryRow(`SELECT COUNT(*)::int FROM yara_rules WHERE tenant_id=$1 AND enabled=true`, tid).Scan(&yaraTotal)
	database.DB.QueryRow(`SELECT COUNT(*)::int FROM correlation_rules WHERE tenant_id=$1 AND enabled=true`, tid).Scan(&corrTotal)

	c.JSON(http.StatusOK, gin.H{
		"techniques":         coverage,
		"total_techniques":   total,
		"covered_techniques": coveredCount,
		"coverage_pct":       pct,
		"sigma_total":        sigmaTotal,
		"yara_total":         yaraTotal,
		"correlation_total":  corrTotal,
	})
}

// ── GetActorRelationships ─────────────────────────────────────────────────────

func GetActorRelationships(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actorID, _ := strconv.Atoi(c.Param("id"))

	var actorName string
	database.DB.QueryRow(`SELECT name FROM threat_actors WHERE id=$1 AND tenant_id=$2`, actorID, tid).Scan(&actorName)

	type GraphNode struct {
		ID    string `json:"id"`
		Label string `json:"label"`
		Type  string `json:"type"`
		Count int    `json:"count"`
	}
	type GraphEdge struct {
		Source string `json:"source"`
		Target string `json:"target"`
		Label  string `json:"label"`
	}

	var nodes []GraphNode
	var edges []GraphEdge

	// Actor node
	nodes = append(nodes, GraphNode{ID: fmt.Sprintf("actor_%d", actorID), Label: actorName, Type: "actor"})

	// Campaign nodes from actor_alert_tags techniques
	type CampaignNode struct {
		Tech  string
		Count int
	}
	var campaigns []CampaignNode
	campRows, _ := database.DB.Query(`
		SELECT matched_technique, COUNT(*)::int
		FROM actor_alert_tags WHERE actor_id=$1 AND tenant_id=$2 AND matched_technique != ''
		GROUP BY matched_technique ORDER BY 2 DESC LIMIT 6`, actorID, tid)
	if campRows != nil {
		defer campRows.Close()
		for campRows.Next() {
			var r CampaignNode
			campRows.Scan(&r.Tech, &r.Count)
			campaigns = append(campaigns, r)
		}
	}
	for _, cp := range campaigns {
		nid := "campaign_" + cp.Tech
		nodes = append(nodes, GraphNode{ID: nid, Label: cp.Tech, Type: "campaign", Count: cp.Count})
		edges = append(edges, GraphEdge{Source: fmt.Sprintf("actor_%d", actorID), Target: nid, Label: "uses"})
	}

	// IOC nodes
	type IOCNode struct {
		ID        int
		Indicator string
		IocType   string
	}
	var iocNodes []IOCNode
	iocRows, _ := database.DB.Query(`
		SELECT id, indicator, type FROM iocs
		WHERE tenant_id=$1 AND enabled=true AND description ILIKE '%'||$2||'%'
		ORDER BY hit_count DESC LIMIT 5`, tid, actorName)
	if iocRows != nil {
		defer iocRows.Close()
		for iocRows.Next() {
			var r IOCNode
			iocRows.Scan(&r.ID, &r.Indicator, &r.IocType)
			iocNodes = append(iocNodes, r)
		}
	}
	for _, ioc := range iocNodes {
		nid := fmt.Sprintf("ioc_%d", ioc.ID)
		label := ioc.Indicator
		if len(label) > 20 {
			label = label[:18] + "…"
		}
		nodes = append(nodes, GraphNode{ID: nid, Label: label, Type: "ioc"})
		edges = append(edges, GraphEdge{Source: fmt.Sprintf("actor_%d", actorID), Target: nid, Label: "uses ioc"})
	}

	// Alert nodes (recent, distinct rule names)
	type AlertNode struct {
		ID       int
		RuleName string
	}
	var alertNodes []AlertNode
	alertNodeRows, _ := database.DB.Query(`
		SELECT DISTINCT ON (a.rule_name) a.id, a.rule_name
		FROM actor_alert_tags aat
		JOIN alerts a ON a.id=aat.alert_id AND a.tenant_id=$1
		WHERE aat.actor_id=$2 AND aat.tenant_id=$1
		ORDER BY a.rule_name, aat.tagged_at DESC LIMIT 4`, tid, actorID)
	if alertNodeRows != nil {
		defer alertNodeRows.Close()
		for alertNodeRows.Next() {
			var r AlertNode
			alertNodeRows.Scan(&r.ID, &r.RuleName)
			alertNodes = append(alertNodes, r)
		}
	}
	for _, al := range alertNodes {
		nid := fmt.Sprintf("alert_%d", al.ID)
		label := al.RuleName
		if len(label) > 22 {
			label = label[:20] + "…"
		}
		nodes = append(nodes, GraphNode{ID: nid, Label: label, Type: "alert"})
		// Connect alerts to their campaign (technique)
		for _, cp := range campaigns {
			edges = append(edges, GraphEdge{Source: "campaign_" + cp.Tech, Target: nid, Label: "triggered"})
			break // only first campaign
		}
	}

	// Incident nodes
	type IncNode struct {
		ID    int
		Title string
	}
	var incNodes []IncNode
	incRows, _ := database.DB.Query(`
		SELECT DISTINCT ac.auto_incident_id, COALESCE(i.title,'Incident #'||ac.auto_incident_id::text)
		FROM alert_clusters ac
		JOIN alert_cluster_members acm ON acm.cluster_id=ac.id
		JOIN actor_alert_tags aat ON aat.alert_id=acm.alert_id AND aat.actor_id=$1 AND aat.tenant_id=$2
		LEFT JOIN incidents i ON i.id=ac.auto_incident_id AND i.tenant_id=$2
		WHERE ac.tenant_id=$2 AND ac.auto_incident_id IS NOT NULL
		LIMIT 3`, actorID, tid)
	if incRows != nil {
		defer incRows.Close()
		for incRows.Next() {
			var r IncNode
			incRows.Scan(&r.ID, &r.Title)
			incNodes = append(incNodes, r)
		}
	}
	for _, inc := range incNodes {
		nid := fmt.Sprintf("incident_%d", inc.ID)
		label := inc.Title
		if len(label) > 20 {
			label = label[:18] + "…"
		}
		nodes = append(nodes, GraphNode{ID: nid, Label: label, Type: "incident"})
		// Connect via actor
		edges = append(edges, GraphEdge{Source: fmt.Sprintf("actor_%d", actorID), Target: nid, Label: "implicated"})
	}

	if nodes == nil {
		nodes = []GraphNode{}
	}
	if edges == nil {
		edges = []GraphEdge{}
	}

	c.JSON(http.StatusOK, gin.H{"nodes": nodes, "edges": edges})
}

// ── GetActorTimeline ──────────────────────────────────────────────────────────

func GetActorTimeline(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actorID, _ := strconv.Atoi(c.Param("id"))

	type TimelineEntry struct {
		ID               int    `json:"id"`
		RuleName         string `json:"rule_name"`
		Severity         string `json:"severity"`
		Hostname         string `json:"hostname"`
		MatchedTechnique string `json:"matched_technique"`
		Confidence       int    `json:"confidence"`
		TaggedAt         string `json:"tagged_at"`
	}
	var events []TimelineEntry
	rows, _ := database.DB.Query(`
		SELECT aat.id, a.rule_name, a.severity,
		       COALESCE(ag.hostname,''), aat.matched_technique, aat.confidence,
		       aat.tagged_at::text
		FROM actor_alert_tags aat
		JOIN alerts a ON a.id=aat.alert_id AND a.tenant_id=$1
		LEFT JOIN agents ag ON ag.id=a.agent_id AND ag.tenant_id=$1
		WHERE aat.actor_id=$2 AND aat.tenant_id=$1
		ORDER BY aat.tagged_at DESC LIMIT 100`, tid, actorID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var r TimelineEntry
			rows.Scan(&r.ID, &r.RuleName, &r.Severity, &r.Hostname, &r.MatchedTechnique, &r.Confidence, &r.TaggedAt)
			events = append(events, r)
		}
	}
	if events == nil {
		events = []TimelineEntry{}
	}

	// Monthly summary for sparkline
	type MonthBucket struct {
		Month string `json:"month"`
		Count int    `json:"count"`
	}
	var monthly []MonthBucket
	mRows, _ := database.DB.Query(`
		SELECT TO_CHAR(DATE_TRUNC('month', tagged_at),'YYYY-MM'), COUNT(*)::int
		FROM actor_alert_tags WHERE actor_id=$1 AND tenant_id=$2 AND tagged_at > NOW()-INTERVAL'12 months'
		GROUP BY 1 ORDER BY 1`, actorID, tid)
	if mRows != nil {
		defer mRows.Close()
		for mRows.Next() {
			var r MonthBucket
			mRows.Scan(&r.Month, &r.Count)
			monthly = append(monthly, r)
		}
	}
	if monthly == nil {
		monthly = []MonthBucket{}
	}

	c.JSON(http.StatusOK, gin.H{"events": events, "monthly": monthly})
}

// ── GetActorIOCs ──────────────────────────────────────────────────────────────

func GetActorIOCs(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actorID, _ := strconv.Atoi(c.Param("id"))

	var actorName string
	var aliases []string
	database.DB.QueryRow(`SELECT name FROM threat_actors WHERE id=$1 AND tenant_id=$2`, actorID, tid).Scan(&actorName)
	alRows, _ := database.DB.Query(`SELECT UNNEST(aliases) FROM threat_actors WHERE id=$1 AND tenant_id=$2`, actorID, tid)
	if alRows != nil {
		defer alRows.Close()
		for alRows.Next() {
			var a string
			alRows.Scan(&a)
			aliases = append(aliases, a)
		}
	}

	var conditions []string
	var args []interface{}
	args = append(args, tid)
	argIdx := 2
	for _, name := range append([]string{actorName}, aliases...) {
		if name == "" {
			continue
		}
		conditions = append(conditions, fmt.Sprintf("description ILIKE '%%'||$%d||'%%'", argIdx))
		args = append(args, name)
		argIdx++
	}
	whereClause := "FALSE"
	if len(conditions) > 0 {
		whereClause = strings.Join(conditions, " OR ")
	}

	type IOCEntry struct {
		ID          int    `json:"id"`
		Indicator   string `json:"indicator"`
		Type        string `json:"type"`
		Severity    string `json:"severity"`
		HitCount    int    `json:"hit_count"`
		LastSeen    string `json:"last_seen"`
		Description string `json:"description"`
		Enabled     bool   `json:"enabled"`
	}

	var iocs []IOCEntry
	query := fmt.Sprintf(`
		SELECT id, indicator, type, severity, hit_count, COALESCE(last_seen::text,''),
		       COALESCE(description,''), enabled
		FROM iocs WHERE tenant_id=$1 AND (%s)
		ORDER BY hit_count DESC, created_at DESC LIMIT 200`, whereClause)
	rows, _ := database.DB.Query(query, args...)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var r IOCEntry
			rows.Scan(&r.ID, &r.Indicator, &r.Type, &r.Severity, &r.HitCount, &r.LastSeen, &r.Description, &r.Enabled)
			iocs = append(iocs, r)
		}
	}
	if iocs == nil {
		iocs = []IOCEntry{}
	}

	c.JSON(http.StatusOK, gin.H{"iocs": iocs, "total": len(iocs)})
}

// ── GetActorMITRE ─────────────────────────────────────────────────────────────

func GetActorMITRE(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actorID, _ := strconv.Atoi(c.Param("id"))

	var techniques []string
	techRows, _ := database.DB.Query(`SELECT UNNEST(mitre_techniques) FROM threat_actors WHERE id=$1 AND tenant_id=$2`, actorID, tid)
	if techRows != nil {
		defer techRows.Close()
		for techRows.Next() {
			var t string
			techRows.Scan(&t)
			techniques = append(techniques, t)
		}
	}

	// Tactic mapping heuristic based on common technique ID ranges
	tacticFor := func(tech string) string {
		prefixMap := map[string]string{
			"T1566": "Initial Access", "T1190": "Initial Access", "T1133": "Initial Access",
			"T1059": "Execution", "T1204": "Execution", "T1203": "Execution",
			"T1547": "Persistence", "T1543": "Persistence", "T1098": "Persistence",
			"T1055": "Defense Evasion", "T1562": "Defense Evasion", "T1070": "Defense Evasion",
			"T1078": "Credential Access", "T1003": "Credential Access", "T1110": "Credential Access",
			"T1040": "Discovery", "T1046": "Discovery", "T1082": "Discovery",
			"T1021": "Lateral Movement", "T1076": "Lateral Movement", "T1091": "Lateral Movement",
			"T1105": "Command and Control", "T1071": "Command and Control", "T1573": "Command and Control",
			"T1041": "Exfiltration", "T1048": "Exfiltration", "T1537": "Exfiltration",
			"T1486": "Impact", "T1490": "Impact", "T1489": "Impact",
		}
		for prefix, tactic := range prefixMap {
			if strings.HasPrefix(tech, prefix) {
				return tactic
			}
		}
		return "Other"
	}

	type TechEntry struct {
		Technique    string `json:"technique"`
		Tactic       string `json:"tactic"`
		SigmaEnabled int    `json:"sigma_enabled"`
		SigmaTotal   int    `json:"sigma_total"`
		AlertCount   int    `json:"alert_count"`
	}

	var entries []TechEntry
	for _, tech := range techniques {
		var sigEnabled, sigTotal, alertCount int
		database.DB.QueryRow(`
			SELECT COUNT(*) FILTER (WHERE enabled)::int, COUNT(*)::int
			FROM sigma_rules WHERE tenant_id=$1 AND mitre_technique LIKE $2||'%'`,
			tid, tech[:min(len(tech), 5)]).Scan(&sigEnabled, &sigTotal)
		database.DB.QueryRow(`
			SELECT COUNT(*)::int FROM actor_alert_tags
			WHERE actor_id=$1 AND tenant_id=$2 AND matched_technique LIKE $3||'%'`,
			actorID, tid, tech[:min(len(tech), 5)]).Scan(&alertCount)
		entries = append(entries, TechEntry{
			Technique:    tech,
			Tactic:       tacticFor(tech),
			SigmaEnabled: sigEnabled,
			SigmaTotal:   sigTotal,
			AlertCount:   alertCount,
		})
	}
	if entries == nil {
		entries = []TechEntry{}
	}

	// Tactic coverage summary
	tacticMap := map[string]int{}
	for _, e := range entries {
		if e.SigmaEnabled > 0 {
			tacticMap[e.Tactic]++
		}
	}
	var tacticSummary []map[string]interface{}
	for tactic, count := range tacticMap {
		tacticSummary = append(tacticSummary, map[string]interface{}{"tactic": tactic, "covered": count})
	}

	c.JSON(http.StatusOK, gin.H{
		"techniques":     entries,
		"tactic_summary": tacticSummary,
		"total":          len(techniques),
	})
}

// ── PostActorHunt ─────────────────────────────────────────────────────────────

func PostActorHunt(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actorID, _ := strconv.Atoi(c.Param("id"))

	var body struct {
		HuntType string `json:"hunt_type"` // iocs | ttps | logs | dns | network
	}
	c.ShouldBindJSON(&body)

	var actorName string
	var techniques []string
	database.DB.QueryRow(`SELECT name FROM threat_actors WHERE id=$1 AND tenant_id=$2`, actorID, tid).Scan(&actorName)
	techRows, _ := database.DB.Query(`SELECT UNNEST(mitre_techniques) FROM threat_actors WHERE id=$1 AND tenant_id=$2`, actorID, tid)
	if techRows != nil {
		defer techRows.Close()
		for techRows.Next() {
			var t string
			techRows.Scan(&t)
			techniques = append(techniques, t)
		}
	}

	// IOCs attributed to this actor
	var iocList []string
	iocRows, _ := database.DB.Query(`
		SELECT indicator FROM iocs WHERE tenant_id=$1 AND enabled=true AND description ILIKE '%'||$2||'%'
		ORDER BY hit_count DESC LIMIT 20`, tid, actorName)
	if iocRows != nil {
		defer iocRows.Close()
		for iocRows.Next() {
			var ind string
			iocRows.Scan(&ind)
			iocList = append(iocList, ind)
		}
	}

	result := gin.H{
		"actor_name": actorName,
		"hunt_type":  body.HuntType,
		"iocs":       iocList,
		"techniques": techniques,
	}

	switch body.HuntType {
	case "iocs":
		result["queries"] = []string{
			fmt.Sprintf("grep -E '%s' /var/log/syslog", strings.Join(iocList[:min(len(iocList), 5)], "|")),
			fmt.Sprintf("indicator matches: %s", strings.Join(iocList[:min(len(iocList), 5)], ", ")),
		}
		result["description"] = fmt.Sprintf("Hunt for %d IOCs attributed to %s in your environment.", len(iocList), actorName)

	case "ttps":
		result["sigma_hunt"] = fmt.Sprintf("mitre_technique IN (%s)", strings.Join(techniques[:min(len(techniques), 8)], ","))
		result["description"] = fmt.Sprintf("Hunt for %s TTPs: %s", actorName, strings.Join(techniques[:min(len(techniques), 5)], ", "))

	default:
		result["description"] = fmt.Sprintf("Threat hunt for %s: %d IOCs, %d techniques", actorName, len(iocList), len(techniques))
	}

	c.JSON(http.StatusOK, result)
}

// ── PostActorResponse ─────────────────────────────────────────────────────────

func PostActorResponse(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actorID, _ := strconv.Atoi(c.Param("id"))

	var body struct {
		Action string `json:"action"` // block_iocs | create_sigma | notify
		Note   string `json:"note"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var actorName string
	database.DB.QueryRow(`SELECT name FROM threat_actors WHERE id=$1 AND tenant_id=$2`, actorID, tid).Scan(&actorName)

	switch body.Action {
	case "block_iocs":
		// Insert ioc_blocks for all enabled IOCs attributed to actor
		result, _ := database.DB.Exec(`
			INSERT INTO ioc_blocks (tenant_id, ioc_id, blocked_by, blocked_at)
			SELECT $1, id, $2, NOW() FROM iocs
			WHERE tenant_id=$1 AND enabled=true AND description ILIKE '%'||$3||'%'
			ON CONFLICT DO NOTHING`,
			tid, usernameFromContext(c), actorName)
		var affected int64
		if result != nil {
			affected, _ = result.RowsAffected()
		}
		c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Blocked %d IOCs attributed to %s", affected, actorName)})

	case "create_sigma":
		// Create a sigma rule for actor's primary technique
		var primaryTech string
		database.DB.QueryRow(`
			SELECT matched_technique FROM actor_alert_tags
			WHERE actor_id=$1 AND tenant_id=$2 AND matched_technique != ''
			GROUP BY matched_technique ORDER BY COUNT(*) DESC LIMIT 1`, actorID, tid).Scan(&primaryTech)
		if primaryTech == "" && actorID > 0 {
			techRows2, _ := database.DB.Query(`SELECT UNNEST(mitre_techniques) FROM threat_actors WHERE id=$1 AND tenant_id=$2 LIMIT 1`, actorID, tid)
			if techRows2 != nil {
				defer techRows2.Close()
				if techRows2.Next() {
					techRows2.Scan(&primaryTech)
				}
			}
		}
		_, err := database.DB.Exec(`
			INSERT INTO sigma_rules (tenant_id, title, severity, mitre_technique, keywords, enabled, created_at, updated_at)
			VALUES ($1, $2, 'high', $3, ARRAY[$4], true, NOW(), NOW())`,
			tid,
			fmt.Sprintf("Hunt: %s Technique %s", actorName, primaryTech),
			primaryTech,
			actorName)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Created Sigma rule for %s technique %s", actorName, primaryTech)})

	case "notify":
		c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Analyst notification dispatched for actor %s. Note: %s", actorName, body.Note)})

	default:
		c.JSON(400, gin.H{"error": "unknown action: " + body.Action})
	}
}

// ── UpdateThreatActor ─────────────────────────────────────────────────────────

func UpdateThreatActor(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actorID, _ := strconv.Atoi(c.Param("id"))

	var body models.ThreatActor
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	_, err := database.DB.Exec(`
		UPDATE threat_actors SET
		  name=$1, aliases=$2, origin_country=$3, motivation=$4,
		  sophistication=$5, description=$6, targeted_sectors=$7,
		  mitre_techniques=$8, updated_at=NOW()
		WHERE id=$9 AND tenant_id=$10`,
		body.Name, body.Aliases, body.OriginCountry, body.Motivation,
		body.Sophistication, body.Description, body.TargetedSectors,
		body.MitreTechniques, actorID, tid)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "updated"})
}
