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

// ── tables ────────────────────────────────────────────────────────────────────

func createEXETables() {
	db := database.DB
	queries := []string{
		// Daily snapshots of all key metrics for trending/forecasting
		`CREATE TABLE IF NOT EXISTS exe_snapshots (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			snapshot_date DATE NOT NULL,
			security_score INTEGER DEFAULT 0,
			risk_score INTEGER DEFAULT 0,
			compliance_score INTEGER DEFAULT 0,
			total_incidents INTEGER DEFAULT 0,
			critical_incidents INTEGER DEFAULT 0,
			total_vulns INTEGER DEFAULT 0,
			critical_vulns INTEGER DEFAULT 0,
			total_assets INTEGER DEFAULT 0,
			critical_assets INTEGER DEFAULT 0,
			mttd_hours NUMERIC(8,2) DEFAULT 0,
			mttr_hours NUMERIC(8,2) DEFAULT 0,
			sla_compliance INTEGER DEFAULT 0,
			patch_compliance INTEGER DEFAULT 0,
			detection_coverage INTEGER DEFAULT 0,
			automation_rate INTEGER DEFAULT 0,
			false_positive_rate NUMERIC(6,2) DEFAULT 0,
			financial_risk_usd BIGINT DEFAULT 0,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(tenant_id, snapshot_date)
		)`,
		// Forecasting projections
		`CREATE TABLE IF NOT EXISTS exe_forecasts (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			forecast_date DATE NOT NULL,
			metric TEXT NOT NULL,
			predicted_value NUMERIC(12,2) DEFAULT 0,
			confidence_low NUMERIC(12,2) DEFAULT 0,
			confidence_high NUMERIC(12,2) DEFAULT 0,
			model TEXT DEFAULT 'linear',
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(tenant_id, forecast_date, metric)
		)`,
		// Generated executive reports
		`CREATE TABLE IF NOT EXISTS exe_reports (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			report_id TEXT NOT NULL UNIQUE,
			title TEXT NOT NULL,
			report_type TEXT NOT NULL DEFAULT 'executive_summary',
			generated_by TEXT NOT NULL,
			security_score INTEGER DEFAULT 0,
			risk_score INTEGER DEFAULT 0,
			summary TEXT,
			key_findings TEXT DEFAULT '[]',
			recommendations TEXT DEFAULT '[]',
			format TEXT DEFAULT 'pdf',
			size_bytes BIGINT DEFAULT 0,
			shared_with TEXT DEFAULT '[]',
			created_at TIMESTAMP DEFAULT NOW()
		)`,
		// Executive notifications
		`CREATE TABLE IF NOT EXISTS exe_notifications (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			title TEXT NOT NULL, message TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT 'info',
			source TEXT,
			action_url TEXT,
			read BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT NOW()
		)`,
		// Integration status registry
		`CREATE TABLE IF NOT EXISTS exe_integrations (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			integration_id TEXT NOT NULL UNIQUE,
			name TEXT NOT NULL,
			category TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			last_sync_at TIMESTAMP,
			records_synced BIGINT DEFAULT 0,
			health_score INTEGER DEFAULT 100,
			error_count INTEGER DEFAULT 0,
			config_summary TEXT,
			created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW()
		)`,
		// Audit trail
		`CREATE TABLE IF NOT EXISTS exe_audit (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			action TEXT NOT NULL,
			object_type TEXT NOT NULL,
			object_id TEXT, object_name TEXT,
			actor TEXT NOT NULL,
			ip_address TEXT,
			details TEXT,
			created_at TIMESTAMP DEFAULT NOW()
		)`,
	}
	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			panic("exe table: " + err.Error())
		}
	}
}

func InitEXETables() { createEXETables() }

// ── helpers ───────────────────────────────────────────────────────────────────

func exeAudit(tid int, action, objType, objID, objName, actor, details string) {
	database.DB.Exec(
		`INSERT INTO exe_audit (tenant_id,action,object_type,object_id,object_name,actor,details)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		tid, action, objType, exeNullStr(objID), exeNullStr(objName), actor, exeNullStr(details),
	)
}

func exeNotify(tid int, eventType, title, message, severity, source string) {
	database.DB.Exec(
		`INSERT INTO exe_notifications (tenant_id,event_type,title,message,severity,source)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		tid, eventType, title, message, severity, exeNullStr(source),
	)
}

func exeNullStr(s string) interface{} {
	if s == "" { return nil }
	return s
}

// ── dashboard (comprehensive) ─────────────────────────────────────────────────

func GetEXEDashboard(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB

	// Latest snapshot
	var secScore, riskScore, compScore, totalInc, critInc int
	var totalVulns, critVulns, totalAssets, critAssets int
	var mttd, mttr float64
	var slaComp, patchComp, detCov, autoRate int
	var falsePos float64
	var financialRisk int64
	db.QueryRow(`SELECT security_score, risk_score, compliance_score, total_incidents, critical_incidents,
		total_vulns, critical_vulns, total_assets, critical_assets, mttd_hours, mttr_hours,
		sla_compliance, patch_compliance, detection_coverage, automation_rate, false_positive_rate, financial_risk_usd
		FROM exe_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).Scan(
		&secScore, &riskScore, &compScore, &totalInc, &critInc,
		&totalVulns, &critVulns, &totalAssets, &critAssets, &mttd, &mttr,
		&slaComp, &patchComp, &detCov, &autoRate, &falsePos, &financialRisk,
	)

	// 30-day trend series — one row per snapshot, matching what the frontend expects
	type trendPoint struct {
		Date            string `json:"date"`
		SecurityScore   int    `json:"security_score"`
		RiskScore       int    `json:"risk_score"`
		TotalIncidents  int    `json:"total_incidents"`
	}
	tRows, _ := db.Query(`SELECT snapshot_date, security_score, risk_score, total_incidents FROM exe_snapshots
		WHERE tenant_id=$1 ORDER BY snapshot_date ASC LIMIT 30`, tid)
	trend := []trendPoint{}
	if tRows != nil {
		defer tRows.Close()
		for tRows.Next() {
			var d time.Time
			var p trendPoint
			tRows.Scan(&d, &p.SecurityScore, &p.RiskScore, &p.TotalIncidents)
			p.Date = d.Format("Jan 2")
			trend = append(trend, p)
		}
	}

	// Unread notifications count
	var unreadNotifs int
	db.QueryRow(`SELECT COUNT(*) FROM exe_notifications WHERE tenant_id=$1 AND read=FALSE`, tid).Scan(&unreadNotifs)

	c.JSON(http.StatusOK, gin.H{
		"latest": gin.H{
			"security_score":      secScore,
			"risk_score":          riskScore,
			"compliance_score":    compScore,
			"total_incidents":     totalInc,
			"critical_incidents":  critInc,
			"total_vulns":         totalVulns,
			"critical_vulns":      critVulns,
			"total_assets":        totalAssets,
			"critical_assets":     critAssets,
			"mttd_hours":          mttd,
			"mttr_hours":          mttr,
			"sla_compliance":      slaComp,
			"patch_compliance":    patchComp,
			"detection_coverage":  detCov,
			"automation_rate":     autoRate,
			"false_positive_rate": falsePos,
			"financial_risk_usd":  financialRisk,
		},
		"unread_notifications": unreadNotifs,
		"trend":                trend,
	})
}

// ── risk overview ─────────────────────────────────────────────────────────────

func GetEXERisk(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB

	var riskScore, critVulns, highRiskAssets, highRiskUsers, internetExposed int
	db.QueryRow(`SELECT risk_score, critical_vulns FROM exe_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).Scan(&riskScore, &critVulns)

	// high-risk assets proxy
	db.QueryRow(`SELECT COUNT(*) FROM assets WHERE tenant_id=$1 AND criticality IN ('critical','high')`, tid).Scan(&highRiskAssets)
	db.QueryRow(`SELECT COUNT(*) FROM cloud_assets WHERE tenant_id=$1 AND internet_exposed=true`, tid).Scan(&internetExposed)
	db.QueryRow(`SELECT COUNT(*) FROM user_risk_profiles WHERE tenant_id=$1 AND risk_score>=60`, tid).Scan(&highRiskUsers)

	// 30-day risk trend
	type dp struct {
		Date  string `json:"date"`
		Value int    `json:"value"`
	}
	rows, _ := db.Query(`SELECT snapshot_date, risk_score FROM exe_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date ASC LIMIT 30`, tid)
	trend := []dp{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var d time.Time; var v int
			rows.Scan(&d, &v)
			trend = append(trend, dp{d.Format("Jan 2"), v})
		}
	}
	riskTrendDelta := 0
	if len(trend) >= 2 {
		riskTrendDelta = trend[len(trend)-1].Value - trend[0].Value
	}

	// Business risk table — derived from real per-tenant metrics, only
	// including a category when there's actually something to report.
	var compScore, compFailed int
	db.QueryRow(`SELECT ROUND(overall_score)::int, failed_controls FROM fce_frameworks
		WHERE tenant_id=$1 AND is_active=TRUE ORDER BY overall_score ASC LIMIT 1`, tid).Scan(&compScore, &compFailed)
	var activeActorCampaigns int
	db.QueryRow(`SELECT COUNT(*) FROM threat_actors WHERE tenant_id=$1 AND sophistication IN ('nation-state','high') AND created_at > NOW()-INTERVAL'90 days'`, tid).Scan(&activeActorCampaigns)
	var cloudCritFindings int
	db.QueryRow(`SELECT COUNT(*) FROM cloud_findings WHERE tenant_id=$1 AND severity='critical' AND status='open'`, tid).Scan(&cloudCritFindings)

	topRisks := []gin.H{}
	if activeActorCampaigns > 0 {
		topRisks = append(topRisks, gin.H{"name": fmt.Sprintf("%d Active Nation-State/High-Sophistication Threat Actor(s) Tracked", activeActorCampaigns), "severity": "high", "business_unit": "", "category": "Threat Intelligence", "risk_score": 60 + min(activeActorCampaigns*5, 35)})
	}
	if critVulns > 0 {
		topRisks = append(topRisks, gin.H{"name": fmt.Sprintf("%d Critical Vulnerabilities Open", critVulns), "severity": "critical", "business_unit": "", "category": "Vulnerability", "risk_score": 70 + min(critVulns*3, 29)})
	}
	if compFailed > 0 {
		topRisks = append(topRisks, gin.H{"name": fmt.Sprintf("%d Failed Compliance Controls (lowest-scoring framework at %d%%)", compFailed, compScore), "severity": "high", "business_unit": "", "category": "Compliance", "risk_score": 100 - compScore})
	}
	if highRiskUsers > 0 {
		topRisks = append(topRisks, gin.H{"name": fmt.Sprintf("%d High-Risk Users Flagged", highRiskUsers), "severity": "high", "business_unit": "", "category": "Identity", "risk_score": 50 + min(highRiskUsers*5, 40)})
	}
	if cloudCritFindings > 0 {
		topRisks = append(topRisks, gin.H{"name": fmt.Sprintf("%d Critical Cloud Misconfigurations Open", cloudCritFindings), "severity": "medium", "business_unit": "", "category": "Cloud Security", "risk_score": 45 + min(cloudCritFindings*5, 40)})
	}

	criticalCount, highCount := 0, 0
	for _, r := range topRisks {
		switch r["severity"] {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		}
	}

	type geoRow struct {
		Country     string `json:"country"`
		ThreatCount int    `json:"threat_count"`
	}
	geoThreats := []geoRow{}
	geoRows, _ := db.Query(`SELECT country, COUNT(*) FROM fwe_threats WHERE tenant_id=$1 AND country IS NOT NULL AND country != '' GROUP BY country ORDER BY COUNT(*) DESC LIMIT 10`, tid)
	if geoRows != nil {
		defer geoRows.Close()
		for geoRows.Next() {
			var g geoRow
			geoRows.Scan(&g.Country, &g.ThreatCount)
			geoThreats = append(geoThreats, g)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"risk_score":       riskScore,
		"critical_vulns":   critVulns,
		"high_risk_assets": highRiskAssets,
		"high_risk_users":  highRiskUsers,
		"internet_exposed": internetExposed,
		"risk_trend":       riskTrendDelta,
		"trend":            trend,
		"top_risks":        topRisks,
		"critical_count":   criticalCount,
		"high_count":       highCount,
		"geo_threats":      geoThreats,
	})
}

// ── KPIs ──────────────────────────────────────────────────────────────────────

func GetEXEKPIs(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB

	var totalInc, critInc, resolvedInc, detCov, autoRate, compScore int
	var mttd, mttr, falsePos float64
	db.QueryRow(`SELECT total_incidents, critical_incidents, compliance_score, detection_coverage, automation_rate, mttd_hours, mttr_hours, false_positive_rate
		FROM exe_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).Scan(
		&totalInc, &critInc, &compScore, &detCov, &autoRate, &mttd, &mttr, &falsePos,
	)
	// approximate resolved from incidents table
	db.QueryRow(`SELECT COUNT(*) FROM incidents WHERE tenant_id=$1 AND status='closed'`, tid).Scan(&resolvedInc)

	var openCases int
	db.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND status NOT IN ('closed','archived')`, tid).Scan(&openCases)

	// Month-over-month changes (compare last 2 snapshots)
	type snap struct{ Incidents, Compliance, DetCov int; MTTD, MTTR float64 }
	var prev snap
	db.QueryRow(`SELECT total_incidents, compliance_score, detection_coverage, mttd_hours, mttr_hours
		FROM exe_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC OFFSET 7 LIMIT 1`, tid).Scan(
		&prev.Incidents, &prev.Compliance, &prev.DetCov, &prev.MTTD, &prev.MTTR,
	)

	kpis := []gin.H{
		{"name": "Total Incidents", "value": totalInc, "display_value": fmt.Sprintf("%d", totalInc), "lower_is_better": true, "change": totalInc - prev.Incidents},
		{"name": "Critical Incidents", "value": critInc, "display_value": fmt.Sprintf("%d", critInc), "lower_is_better": true},
		{"name": "Resolved Incidents", "value": resolvedInc, "display_value": fmt.Sprintf("%d", resolvedInc), "lower_is_better": false},
		{"name": "Open Cases", "value": openCases, "display_value": fmt.Sprintf("%d", openCases), "lower_is_better": true},
		{"name": "MTTD", "value": mttd, "display_value": fmt.Sprintf("%.1fh", mttd), "unit": "h", "lower_is_better": true, "change": mttd - prev.MTTD},
		{"name": "MTTR", "value": mttr, "display_value": fmt.Sprintf("%.1fh", mttr), "unit": "h", "lower_is_better": true, "change": mttr - prev.MTTR},
		{"name": "Detection Coverage", "value": detCov, "display_value": fmt.Sprintf("%d%%", detCov), "unit": "%", "lower_is_better": false, "change": detCov - prev.DetCov},
		{"name": "Automation Rate", "value": autoRate, "display_value": fmt.Sprintf("%d%%", autoRate), "unit": "%", "lower_is_better": false},
		{"name": "Compliance", "value": compScore, "display_value": fmt.Sprintf("%d%%", compScore), "unit": "%", "lower_is_better": false, "change": compScore - prev.Compliance},
		{"name": "False Positive Rate", "value": falsePos, "display_value": fmt.Sprintf("%.1f%%", falsePos), "unit": "%", "lower_is_better": true},
	}

	c.JSON(http.StatusOK, gin.H{
		"kpis": kpis,
	})
}

// ── business impact ───────────────────────────────────────────────────────────

func GetEXEBusinessImpact(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB
	var financialRisk int64
	db.QueryRow(`SELECT financial_risk_usd FROM exe_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).Scan(&financialRisk)

	rows, _ := db.Query(`
		SELECT COALESCE(NULLIF(a.business_unit,''),'Unassigned') AS bu,
		       COUNT(DISTINCT i.id) FILTER (WHERE i.severity='critical' AND i.status NOT IN ('resolved','closed')) AS crit_inc,
		       COUNT(DISTINCT i.id) FILTER (WHERE i.status NOT IN ('resolved','closed')) AS open_inc
		FROM assets a
		LEFT JOIN agents ag ON ag.id = a.agent_id
		LEFT JOIN incidents i ON i.agent_id = ag.id AND i.tenant_id = a.tenant_id
		WHERE a.tenant_id=$1
		GROUP BY bu
		ORDER BY crit_inc DESC, open_inc DESC
		LIMIT 8`, tid)

	type buRaw struct {
		Name     string
		CritInc  int
		OpenInc  int
	}
	var raws []buRaw
	totalOpen := 0
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var r buRaw
			rows.Scan(&r.Name, &r.CritInc, &r.OpenInc)
			raws = append(raws, r)
			totalOpen += r.OpenInc
		}
	}

	businessUnits := []gin.H{}
	affectedBUs := 0
	for _, r := range raws {
		riskScore := 20 + min(r.OpenInc*10+r.CritInc*15, 80)
		if r.OpenInc > 0 {
			affectedBUs++
		}
		var financialExposure int64
		if totalOpen > 0 {
			financialExposure = financialRisk * int64(r.OpenInc) / int64(totalOpen)
		}
		topRisk := ""
		if r.CritInc > 0 {
			topRisk = fmt.Sprintf("%d critical incident(s) open", r.CritInc)
		}
		businessUnits = append(businessUnits, gin.H{
			"name":               r.Name,
			"risk_score":         riskScore,
			"critical_incidents": r.CritInc,
			"financial_exposure": financialExposure,
			"top_risk":           topRisk,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"financial_risk_usd":      financialRisk,
		"max_potential_loss":      0,
		"avg_recovery_cost":       0,
		"cyber_insurance_coverage": "",
		"revenue_impact_usd":      financialRisk,
		"affected_business_units": affectedBUs,
		"business_units":          businessUnits,
	})
}

// ── threat landscape ──────────────────────────────────────────────────────────

func GetEXEThreatLandscape(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB

	type actorRow struct {
		ID             int
		Name           string
		Motivation     string
		Sophistication string
	}
	var actors []actorRow
	arows, _ := db.Query(`SELECT id, name, motivation, sophistication FROM threat_actors WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 10`, tid)
	if arows != nil {
		defer arows.Close()
		for arows.Next() {
			var a actorRow
			arows.Scan(&a.ID, &a.Name, &a.Motivation, &a.Sophistication)
			actors = append(actors, a)
		}
	}

	campaigns := []gin.H{}
	for _, a := range actors {
		var affected int
		db.QueryRow(`SELECT COUNT(DISTINCT alert_id) FROM actor_alert_tags WHERE actor_id=$1`, a.ID).Scan(&affected)
		severity := "medium"
		switch a.Sophistication {
		case "nation-state":
			severity = "critical"
		case "high":
			severity = "high"
		case "low":
			severity = "low"
		}
		campaigns = append(campaigns, gin.H{
			"name":             a.Name,
			"actor":            a.Name,
			"category":         a.Motivation,
			"severity":         severity,
			"affected_systems": affected,
		})
	}

	var threatActorCount int
	db.QueryRow(`SELECT COUNT(*) FROM threat_actors WHERE tenant_id=$1`, tid).Scan(&threatActorCount)
	var iocCount int
	db.QueryRow(`SELECT COUNT(*) FROM feed_iocs WHERE tenant_id=$1`, tid).Scan(&iocCount)

	type geoRow struct {
		Country string `json:"country"`
		Count   int    `json:"count"`
	}
	geoThreats := []geoRow{}
	geoRows, _ := db.Query(`SELECT country, COUNT(*) FROM fwe_threats WHERE tenant_id=$1 AND country IS NOT NULL AND country != '' GROUP BY country ORDER BY COUNT(*) DESC LIMIT 10`, tid)
	if geoRows != nil {
		defer geoRows.Close()
		for geoRows.Next() {
			var g geoRow
			geoRows.Scan(&g.Country, &g.Count)
			geoThreats = append(geoThreats, g)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"active_campaign_count": len(campaigns),
		"ioc_count":             iocCount,
		"threat_actor_count":    threatActorCount,
		"industry_targeting":    "",
		"active_campaigns":      campaigns,
		"top_malware":           []gin.H{},
		"geo_distribution":      geoThreats,
	})
}

// ── compliance overview ───────────────────────────────────────────────────────

func GetEXECompliance(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB

	var compScore int
	db.QueryRow(`SELECT compliance_score FROM exe_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).Scan(&compScore)

	// Pull from fce_frameworks if available
	type fwRow struct {
		Name           string `json:"name"`
		ComplianceScore int   `json:"compliance_score"`
		ControlsPassed int    `json:"controls_passed"`
		TotalControls  int    `json:"total_controls"`
		Category       string `json:"category"`
		Status         string `json:"status"`
	}
	frows, _ := db.Query(`SELECT name, overall_score, passed_controls, total_controls, category, compliance_status
		FROM fce_frameworks WHERE tenant_id=$1 AND is_active=TRUE ORDER BY overall_score ASC LIMIT 8`, tid)
	frameworks := []fwRow{}
	if frows != nil {
		defer frows.Close()
		for frows.Next() {
			var r fwRow
			frows.Scan(&r.Name, &r.ComplianceScore, &r.ControlsPassed, &r.TotalControls, &r.Category, &r.Status)
			frameworks = append(frameworks, r)
		}
	}

	var activeFrameworks int
	db.QueryRow(`SELECT COUNT(*) FROM fce_frameworks WHERE tenant_id=$1 AND is_active=TRUE`, tid).Scan(&activeFrameworks)
	var passedControls, failedControls, openRemediations int
	db.QueryRow(`SELECT COUNT(*) FILTER (WHERE assessment_status='passed'), COUNT(*) FILTER (WHERE assessment_status='failed')
		FROM fce_controls WHERE tenant_id=$1`, tid).Scan(&passedControls, &failedControls)
	db.QueryRow(`SELECT COUNT(*) FROM fce_remediations WHERE tenant_id=$1 AND status NOT IN ('closed','cancelled')`, tid).Scan(&openRemediations)

	c.JSON(http.StatusOK, gin.H{
		"overall_score":     compScore,
		"active_frameworks": activeFrameworks,
		"passed_controls":   passedControls,
		"failed_controls":   failedControls,
		"open_remediations": openRemediations,
		"frameworks":        frameworks,
	})
}

// ── vulnerability overview ────────────────────────────────────────────────────

func GetEXEVulns(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB

	var totalVulns, critVulns, highVulns int
	var avgCvss float64
	db.QueryRow(`SELECT COUNT(*), COUNT(*) FILTER (WHERE severity='critical'), COUNT(*) FILTER (WHERE severity='high'), COALESCE(AVG(cvss_score),0)
		FROM vulnerabilities WHERE tenant_id=$1`, tid).Scan(&totalVulns, &critVulns, &highVulns, &avgCvss)

	var patchComp int
	db.QueryRow(`SELECT patch_compliance FROM exe_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).Scan(&patchComp)

	type topVulnRow struct {
		Severity        string  `json:"severity"`
		CveID           string  `json:"cve_id"`
		Cvss            float64 `json:"cvss"`
		Title           string  `json:"title"`
		AffectedSystems int     `json:"affected_systems"`
	}
	topVulns := []topVulnRow{}
	trows, _ := db.Query(`SELECT cve_id, severity, COALESCE(cvss_score,0), COALESCE(NULLIF(name,''), package_name), COUNT(DISTINCT agent_id)
		FROM vulnerabilities WHERE tenant_id=$1 AND severity IN ('critical','high')
		GROUP BY cve_id, severity, cvss_score, COALESCE(NULLIF(name,''), package_name)
		ORDER BY COALESCE(cvss_score,0) DESC LIMIT 5`, tid)
	if trows != nil {
		defer trows.Close()
		for trows.Next() {
			var r topVulnRow
			trows.Scan(&r.CveID, &r.Severity, &r.Cvss, &r.Title, &r.AffectedSystems)
			topVulns = append(topVulns, r)
		}
	}

	type buVulnRow struct {
		Name         string `json:"name"`
		CriticalVulns int   `json:"critical_vulns"`
	}
	byBU := []buVulnRow{}
	brows, _ := db.Query(`
		SELECT COALESCE(NULLIF(a.business_unit,''),'Unassigned'), COUNT(*) FILTER (WHERE v.severity='critical')
		FROM vulnerabilities v
		JOIN agents ag ON ag.id = v.agent_id
		LEFT JOIN assets a ON a.agent_id = ag.id
		WHERE v.tenant_id=$1
		GROUP BY 1 ORDER BY 2 DESC LIMIT 8`, tid)
	if brows != nil {
		defer brows.Close()
		for brows.Next() {
			var r buVulnRow
			brows.Scan(&r.Name, &r.CriticalVulns)
			byBU = append(byBU, r)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_vulns":      totalVulns,
		"critical":         critVulns,
		"high":             highVulns,
		"exploitable":      0,
		"patch_coverage":   patchComp,
		"avg_cvss":         avgCvss,
		"top_vulns":        topVulns,
		"by_business_unit": byBU,
	})
}

// ── incident overview ─────────────────────────────────────────────────────────

func GetEXEIncidents(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB
	var totalInc, critInc int
	var mttd, mttr float64
	var slaComp int
	db.QueryRow(`SELECT total_incidents, critical_incidents, mttd_hours, mttr_hours, sla_compliance
		FROM exe_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).Scan(&totalInc, &critInc, &mttd, &mttr, &slaComp)

	var open int
	db.QueryRow(`SELECT COUNT(*) FROM incidents WHERE tenant_id=$1 AND status NOT IN ('closed','resolved')`, tid).Scan(&open)

	var repeatIncidents int
	db.QueryRow(`SELECT COUNT(*) FROM (
		SELECT fingerprint FROM incidents WHERE tenant_id=$1 AND fingerprint IS NOT NULL AND fingerprint != ''
		GROUP BY fingerprint HAVING COUNT(*) > 1
	) x`, tid).Scan(&repeatIncidents)

	type sevRow struct {
		Severity string `json:"severity"`
		Count    int    `json:"count"`
	}
	bySev := []sevRow{}
	srows, _ := db.Query(`SELECT severity, COUNT(*) FROM incidents WHERE tenant_id=$1 GROUP BY severity ORDER BY COUNT(*) DESC`, tid)
	if srows != nil {
		defer srows.Close()
		for srows.Next() {
			var r sevRow
			srows.Scan(&r.Severity, &r.Count)
			bySev = append(bySev, r)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_incidents":  totalInc,
		"critical_incidents": critInc,
		"open":              open,
		"repeat_incidents":  repeatIncidents,
		"mttd_hours":        mttd,
		"mttr_hours":        mttr,
		"sla_compliance":    slaComp,
		"sla_breach_count":  0,
		"by_severity":       bySev,
		"by_category":       []gin.H{},
		"root_causes":       []gin.H{},
	})
}

// ── asset overview ────────────────────────────────────────────────────────────

func GetEXEAssets(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB

	var totalAssets, critAssets int
	db.QueryRow(`SELECT total_assets, critical_assets FROM exe_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).Scan(&totalAssets, &critAssets)

	type catRow struct {
		Name        string `json:"name"`
		Count       int    `json:"count"`
		HealthScore int    `json:"health_score"`
	}
	cats := []catRow{}
	crows, _ := db.Query(`SELECT asset_type, COUNT(*) FROM assets WHERE tenant_id=$1 GROUP BY asset_type ORDER BY COUNT(*) DESC`, tid)
	if crows != nil {
		defer crows.Close()
		for crows.Next() {
			var r catRow
			crows.Scan(&r.Name, &r.Count)
			cats = append(cats, r)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_assets":    totalAssets,
		"critical_assets": critAssets,
		"managed_pct":     0,
		"unmanaged_count": 0,
		"avg_health":      0,
		"categories":      cats,
	})
}

// ── forecasting ───────────────────────────────────────────────────────────────

var exeLowerIsBetterMetrics = map[string]bool{
	"risk_score": true, "mttr_hours": true, "mttd_hours": true,
	"total_incidents": true, "total_vulns": true, "false_positive_rate": true,
}

func GetEXEForecasting(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB

	rows, _ := db.Query(`SELECT forecast_date, metric, predicted_value
		FROM exe_forecasts WHERE tenant_id=$1 ORDER BY metric, forecast_date ASC`, tid)

	type point struct {
		Value float64 `json:"value"`
	}
	order := []string{}
	byMetric := map[string][]point{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var metric string
			var val float64
			var d time.Time
			rows.Scan(&d, &metric, &val)
			if _, ok := byMetric[metric]; !ok {
				order = append(order, metric)
			}
			byMetric[metric] = append(byMetric[metric], point{val})
		}
	}

	metrics := []gin.H{}
	for _, m := range order {
		metrics = append(metrics, gin.H{
			"name":            m,
			"points":          byMetric[m],
			"lower_is_better": exeLowerIsBetterMetrics[m],
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"metrics":  metrics,
		"insights": []gin.H{},
	})
}

// ── analytics ─────────────────────────────────────────────────────────────────

func GetEXEAnalytics(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB

	type snap struct {
		Date            string  `json:"date"`
		SecurityScore   int     `json:"security_score"`
		RiskScore       int     `json:"risk_score"`
		ComplianceScore int     `json:"compliance_score"`
		Incidents       int     `json:"incidents"`
		Vulns           int     `json:"total_vulns"`
		MTTD            float64 `json:"mttd_hours"`
		MTTR            float64 `json:"mttr_hours"`
		SLAComp         int     `json:"sla_compliance"`
		DetCov          int     `json:"detection_coverage"`
	}
	rows, _ := db.Query(`SELECT snapshot_date, security_score, risk_score, compliance_score,
		total_incidents, total_vulns, mttd_hours, mttr_hours, sla_compliance, detection_coverage
		FROM exe_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date ASC`, tid)
	series := []snap{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var s snap; var d time.Time
			rows.Scan(&d, &s.SecurityScore, &s.RiskScore, &s.ComplianceScore, &s.Incidents, &s.Vulns, &s.MTTD, &s.MTTR, &s.SLAComp, &s.DetCov)
			s.Date = d.Format("Jan 2")
			series = append(series, s)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"time_series":     series,
		"soc_performance": gin.H{},
		"business_units":  []gin.H{},
	})
}

// ── reports ───────────────────────────────────────────────────────────────────

func GetEXEReports(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(`SELECT id, report_id, title, report_type, generated_by,
		security_score, risk_score, format, size_bytes, created_at
		FROM exe_reports WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 50`, tid)
	if rows == nil { c.JSON(http.StatusOK, []interface{}{}); return }
	defer rows.Close()
	type Row struct {
		ID           int       `json:"id"`
		ReportID     string    `json:"report_id"`
		Title        string    `json:"title"`
		ReportType   string    `json:"report_type"`
		GeneratedBy  string    `json:"generated_by"`
		SecurityScore int      `json:"security_score"`
		RiskScore    int       `json:"risk_score"`
		Format       string    `json:"format"`
		SizeBytes    int64     `json:"size_bytes"`
		CreatedAt    time.Time `json:"created_at"`
	}
	result := []Row{}
	for rows.Next() {
		var r Row
		rows.Scan(&r.ID, &r.ReportID, &r.Title, &r.ReportType, &r.GeneratedBy,
			&r.SecurityScore, &r.RiskScore, &r.Format, &r.SizeBytes, &r.CreatedAt)
		result = append(result, r)
	}
	c.JSON(http.StatusOK, result)
}

func PostEXEReport(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	var body struct {
		ReportType string `json:"report_type"`
		Title      string `json:"title"`
		Format     string `json:"format"`
	}
	c.ShouldBindJSON(&body)
	if body.Title == "" { body.Title = "Executive Security Report — " + time.Now().Format("January 2006") }
	if body.Format == "" { body.Format = "pdf" }
	if body.ReportType == "" { body.ReportType = "executive_summary" }

	rid := fmt.Sprintf("EXE-RPT-%d", time.Now().Unix()%100000)
	var secScore, riskScore int
	database.DB.QueryRow(`SELECT security_score, risk_score FROM exe_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).Scan(&secScore, &riskScore)

	var id int
	database.DB.QueryRow(`INSERT INTO exe_reports (tenant_id,report_id,title,report_type,generated_by,security_score,risk_score,format,size_bytes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
		tid, rid, body.Title, body.ReportType, actor, secScore, riskScore, body.Format, 420000+time.Now().Unix()%200000,
	).Scan(&id)

	exeAudit(tid, "report_generated", "report", rid, body.Title, actor, fmt.Sprintf("Type: %s, Format: %s", body.ReportType, body.Format))
	exeNotify(tid, "report_available", fmt.Sprintf("New Report: %s", body.Title), "Your executive report has been generated and is ready for download.", "info", "Report Generator")
	c.JSON(http.StatusOK, gin.H{"id": id, "report_id": rid})
}

// ── notifications ─────────────────────────────────────────────────────────────

func GetEXENotifications(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(
		`SELECT id, event_type, title, message, severity, source, read, created_at
		 FROM exe_notifications WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 100`, tid)
	if rows == nil { c.JSON(http.StatusOK, []interface{}{}); return }
	defer rows.Close()
	type Row struct {
		ID        int       `json:"id"`
		EventType string    `json:"event_type"`
		Title     string    `json:"title"`
		Message   string    `json:"message"`
		Severity  string    `json:"severity"`
		Source    *string   `json:"source"`
		Read      bool      `json:"read"`
		CreatedAt time.Time `json:"created_at"`
	}
	result := []Row{}
	for rows.Next() {
		var r Row
		rows.Scan(&r.ID, &r.EventType, &r.Title, &r.Message, &r.Severity, &r.Source, &r.Read, &r.CreatedAt)
		result = append(result, r)
	}
	c.JSON(http.StatusOK, result)
}

func PatchEXENotificationsRead(c *gin.Context) {
	tid := tenantIDFromContext(c)
	database.DB.Exec(`UPDATE exe_notifications SET read=TRUE WHERE tenant_id=$1`, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── integrations ──────────────────────────────────────────────────────────────

func GetEXEIntegrations(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(`SELECT id, integration_id, name, category, status, last_sync_at, records_synced, health_score, error_count, config_summary
		FROM exe_integrations WHERE tenant_id=$1 ORDER BY category, name`, tid)
	if rows == nil { c.JSON(http.StatusOK, []interface{}{}); return }
	defer rows.Close()
	type Row struct {
		ID            int        `json:"id"`
		IntegrationID string     `json:"integration_id"`
		Name          string     `json:"name"`
		Category      string     `json:"category"`
		Status        string     `json:"status"`
		LastSyncAt    *time.Time `json:"last_sync_at"`
		RecordsSynced int64      `json:"records_synced"`
		HealthScore   int        `json:"health_score"`
		ErrorCount    int        `json:"error_count"`
		ConfigSummary *string    `json:"config_summary"`
	}
	result := []Row{}
	for rows.Next() {
		var r Row
		rows.Scan(&r.ID, &r.IntegrationID, &r.Name, &r.Category, &r.Status, &r.LastSyncAt, &r.RecordsSynced, &r.HealthScore, &r.ErrorCount, &r.ConfigSummary)
		result = append(result, r)
	}
	c.JSON(http.StatusOK, result)
}

// ── audit trail ───────────────────────────────────────────────────────────────

func GetEXEAudit(c *gin.Context) {
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)
	rows, _ := database.DB.Query(`SELECT id, action, object_type, object_id, object_name, actor, ip_address, details, created_at
		FROM exe_audit WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tid, limit)
	if rows == nil { c.JSON(http.StatusOK, []interface{}{}); return }
	defer rows.Close()
	type Row struct {
		ID         int       `json:"id"`
		Action     string    `json:"action"`
		ObjectType string    `json:"object_type"`
		ObjectID   *string   `json:"object_id"`
		ObjectName *string   `json:"object_name"`
		Actor      string    `json:"actor"`
		IP         *string   `json:"ip_address"`
		Details    *string   `json:"details"`
		CreatedAt  time.Time `json:"created_at"`
	}
	result := []Row{}
	for rows.Next() {
		var r Row
		rows.Scan(&r.ID, &r.Action, &r.ObjectType, &r.ObjectID, &r.ObjectName, &r.Actor, &r.IP, &r.Details, &r.CreatedAt)
		result = append(result, r)
	}
	c.JSON(http.StatusOK, result)
}

// ── AI assistant ──────────────────────────────────────────────────────────────

func PostEXEAI(c *gin.Context) {
	tid := tenantIDFromContext(c)
	var body struct {
		Action  string `json:"action"`
		Context string `json:"context"`
	}
	c.ShouldBindJSON(&body)

	db := database.DB

	// ── Gather real executive metrics for this tenant ───────────────────────
	var secScore, riskScore, compScore, totalInc, critInc int
	var totalVulns, critVulns, totalAssets, critAssets int
	var mttd, mttr float64
	var slaComp, patchComp, detCov, autoRate int
	var falsePos float64
	var financialRisk int64
	db.QueryRow(`SELECT security_score, risk_score, compliance_score, total_incidents, critical_incidents,
		total_vulns, critical_vulns, total_assets, critical_assets, mttd_hours, mttr_hours,
		sla_compliance, patch_compliance, detection_coverage, automation_rate, false_positive_rate, financial_risk_usd
		FROM exe_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).Scan(
		&secScore, &riskScore, &compScore, &totalInc, &critInc,
		&totalVulns, &critVulns, &totalAssets, &critAssets, &mttd, &mttr,
		&slaComp, &patchComp, &detCov, &autoRate, &falsePos, &financialRisk,
	)

	var secScorePrev, riskScorePrev, totalIncPrev int
	db.QueryRow(`SELECT security_score, risk_score, total_incidents FROM exe_snapshots
		WHERE tenant_id=$1 ORDER BY snapshot_date DESC OFFSET 7 LIMIT 1`, tid).Scan(&secScorePrev, &riskScorePrev, &totalIncPrev)

	var ctx strings.Builder
	fmt.Fprintf(&ctx, "Security score: %d/100 (was %d 7 snapshots ago)\n", secScore, secScorePrev)
	fmt.Fprintf(&ctx, "Risk score: %d/100 (was %d)\n", riskScore, riskScorePrev)
	fmt.Fprintf(&ctx, "Compliance score: %d%%\n", compScore)
	fmt.Fprintf(&ctx, "Incidents: %d open (%d critical), was %d\n", totalInc, critInc, totalIncPrev)
	fmt.Fprintf(&ctx, "Vulnerabilities: %d total (%d critical)\n", totalVulns, critVulns)
	fmt.Fprintf(&ctx, "Assets: %d total (%d critical)\n", totalAssets, critAssets)
	fmt.Fprintf(&ctx, "MTTD: %.1fh | MTTR: %.1fh | SLA compliance: %d%%\n", mttd, mttr, slaComp)
	fmt.Fprintf(&ctx, "Patch compliance: %d%% | Detection coverage: %d%% | Automation rate: %d%% | False positive rate: %.1f%%\n", patchComp, detCov, autoRate, falsePos)
	fmt.Fprintf(&ctx, "Estimated financial risk exposure: $%d\n", financialRisk)

	frows, _ := db.Query(`SELECT name, overall_score, compliance_status FROM fce_frameworks
		WHERE tenant_id=$1 AND is_active=TRUE ORDER BY overall_score ASC LIMIT 5`, tid)
	if frows != nil {
		ctx.WriteString("Lowest-scoring compliance frameworks:\n")
		for frows.Next() {
			var name, status string
			var score int
			frows.Scan(&name, &score, &status)
			fmt.Fprintf(&ctx, "- %s: %d%% (%s)\n", name, score, status)
		}
		frows.Close()
	}

	irows, _ := db.Query(`SELECT title, severity, status FROM incidents WHERE tenant_id=$1
		AND status NOT IN ('closed','resolved') ORDER BY severity DESC LIMIT 5`, tid)
	if irows != nil {
		ctx.WriteString("Open incidents:\n")
		for irows.Next() {
			var title, sev, status string
			irows.Scan(&title, &sev, &status)
			fmt.Fprintf(&ctx, "- [%s] %s (%s)\n", sev, title, status)
		}
		irows.Close()
	}

	if body.Context != "" {
		fmt.Fprintf(&ctx, "\nAdditional context: %s\n", body.Context)
	}
	execctx := ctx.String()

	var task string
	switch body.Action {
	case "executive_summary":
		task = "Write a concise executive security briefing: overall posture, key metrics, top 3 priorities, business impact, and recommended board actions."
	case "weekly_briefing":
		task = "Write this week's security briefing: summary, notable items, metrics vs. the prior period, and focus areas for next week."
	case "board_summary":
		task = "Write a board-level security report: executive summary, key risks for board awareness, any investment requests implied by the data, and a recommendation."
	case "risk_analysis":
		task = "Write a business risk analysis: enterprise risk score and the top business risks implied by the metrics, each with business impact and a mitigation."
	case "trend_analysis":
		task = "Write a trend analysis comparing current metrics to the prior snapshot, calling out what's improving, what's degrading, and a forecast."
	case "recommendations":
		task = "Write prioritized strategic security recommendations grouped into immediate/short-term/long-term, each with an owner and rationale grounded in the data."
	case "predictive_insights":
		task = "Write a predictive risk outlook: likely trajectory of the key metrics if current trends continue, and what would change that trajectory."
	default:
		c.JSON(400, gin.H{"error": "unknown action"})
		return
	}

	prompt := fmt.Sprintf(`You are a CISO's analyst preparing material from this organization's real security metrics.

%s

Task: %s

Base your answer strictly on the data above — do not invent specific CVE numbers, campaign names, or figures not present in the data. If a metric is zero or missing, say the posture is stable/no data rather than fabricating an issue. Respond in plain text (no markdown headers), suitable for direct display to the user.`, execctx, task)

	resp, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"response": strings.TrimSpace(resp), "action": body.Action})
}
