package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
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

	// 30-day trend series (security score)
	type trendPoint struct {
		Date  string  `json:"date"`
		Value float64 `json:"value"`
	}
	tRows, _ := db.Query(`SELECT snapshot_date, security_score FROM exe_snapshots WHERE tenant_id=$1
		ORDER BY snapshot_date DESC LIMIT 30`, tid)
	var secTrend, riskTrend, incTrend []trendPoint
	if tRows != nil {
		defer tRows.Close()
		for tRows.Next() {
			var d time.Time
			var v int
			tRows.Scan(&d, &v)
			secTrend = append(secTrend, trendPoint{d.Format("Jan 2"), float64(v)})
		}
	}
	rRows, _ := db.Query(`SELECT snapshot_date, risk_score FROM exe_snapshots WHERE tenant_id=$1
		ORDER BY snapshot_date DESC LIMIT 30`, tid)
	if rRows != nil {
		defer rRows.Close()
		for rRows.Next() {
			var d time.Time
			var v int
			rRows.Scan(&d, &v)
			riskTrend = append(riskTrend, trendPoint{d.Format("Jan 2"), float64(v)})
		}
	}
	iRows, _ := db.Query(`SELECT snapshot_date, total_incidents FROM exe_snapshots WHERE tenant_id=$1
		ORDER BY snapshot_date DESC LIMIT 30`, tid)
	if iRows != nil {
		defer iRows.Close()
		for iRows.Next() {
			var d time.Time
			var v int
			iRows.Scan(&d, &v)
			incTrend = append(incTrend, trendPoint{d.Format("Jan 2"), float64(v)})
		}
	}

	// Unread notifications count
	var unreadNotifs int
	db.QueryRow(`SELECT COUNT(*) FROM exe_notifications WHERE tenant_id=$1 AND read=FALSE`, tid).Scan(&unreadNotifs)

	c.JSON(http.StatusOK, gin.H{
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
		"unread_notifications": unreadNotifs,
		"security_trend":      secTrend,
		"risk_trend":          riskTrend,
		"incident_trend":      incTrend,
	})
}

// ── risk overview ─────────────────────────────────────────────────────────────

func GetEXERisk(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB

	var riskScore, critVulns, highRiskAssets, highRiskUsers, internetExposed int
	db.QueryRow(`SELECT risk_score, critical_vulns FROM exe_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).Scan(&riskScore, &critVulns)

	// high-risk assets proxy
	db.QueryRow(`SELECT COUNT(*) FROM assets WHERE tenant_id=$1 AND criticality IN ('critical','high')`, fmt.Sprintf("%d", tid)).Scan(&highRiskAssets)
	db.QueryRow(`SELECT COUNT(*) FROM assets WHERE tenant_id=$1 AND network_zone='external'`, fmt.Sprintf("%d", tid)).Scan(&internetExposed)

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

	// Hardcoded business risk table for demo richness
	topRisks := []gin.H{
		{"title": "Nation-State Threat Campaign", "impact": "high", "likelihood": "medium", "category": "Threat Intelligence", "score": 82},
		{"title": "Critical Patch Gap (3 systems)", "impact": "critical", "likelihood": "high", "category": "Vulnerability", "score": 91},
		{"title": "PCI DSS Non-Compliance", "impact": "high", "likelihood": "high", "category": "Compliance", "score": 78},
		{"title": "Insider Threat Risk (3 flagged users)", "impact": "high", "likelihood": "low", "category": "Identity", "score": 62},
		{"title": "Cloud Misconfiguration Exposure", "impact": "medium", "likelihood": "medium", "category": "Cloud Security", "score": 55},
	}

	c.JSON(http.StatusOK, gin.H{
		"risk_score":          riskScore,
		"critical_vulns":      critVulns,
		"high_risk_assets":    highRiskAssets,
		"high_risk_users":     highRiskUsers,
		"internet_exposed":    internetExposed,
		"risk_trend":          trend,
		"top_risks":           topRisks,
		"business_critical":   12,
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

	c.JSON(http.StatusOK, gin.H{
		"total_incidents":      totalInc,
		"critical_incidents":   critInc,
		"resolved_incidents":   resolvedInc,
		"open_cases":           openCases,
		"false_positive_rate":  falsePos,
		"detection_coverage":   detCov,
		"mitre_coverage":       74,
		"automation_rate":      autoRate,
		"analyst_productivity": 87,
		"compliance_pct":       compScore,
		"mttd_hours":           mttd,
		"mttr_hours":           mttr,
		"prev_incidents":       prev.Incidents,
		"prev_compliance":      prev.Compliance,
		"prev_det_cov":         prev.DetCov,
		"prev_mttd":            prev.MTTD,
		"prev_mttr":            prev.MTTR,
	})
}

// ── business impact ───────────────────────────────────────────────────────────

func GetEXEBusinessImpact(c *gin.Context) {
	tid := tenantIDFromContext(c)
	var financialRisk int64
	database.DB.QueryRow(`SELECT financial_risk_usd FROM exe_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).Scan(&financialRisk)

	businessUnits := []gin.H{
		{"name": "Finance & Treasury",       "risk": "critical", "incidents": 3, "impact_score": 91, "revenue_at_risk_usd": 2400000},
		{"name": "Engineering",              "risk": "high",     "incidents": 5, "impact_score": 74, "revenue_at_risk_usd": 850000},
		{"name": "Customer Operations",      "risk": "high",     "incidents": 2, "impact_score": 68, "revenue_at_risk_usd": 1200000},
		{"name": "Human Resources",          "risk": "medium",   "incidents": 1, "impact_score": 42, "revenue_at_risk_usd": 150000},
		{"name": "Marketing",                "risk": "medium",   "incidents": 2, "impact_score": 38, "revenue_at_risk_usd": 280000},
		{"name": "Legal & Compliance",       "risk": "low",      "incidents": 0, "impact_score": 22, "revenue_at_risk_usd": 50000},
	}

	c.JSON(http.StatusOK, gin.H{
		"financial_risk_usd":        financialRisk,
		"operational_impact":        "High — 2 critical services degraded",
		"estimated_downtime_mins":   45,
		"revenue_impact_usd":        4930000,
		"critical_service_avail":    98.7,
		"regulatory_impact":         "PCI DSS audit risk — potential fines $50K-$500K",
		"customer_impact":           "~3,200 customers potentially affected by data exposure risk",
		"affected_business_units":   3,
		"business_units":            businessUnits,
	})
}

// ── threat landscape ──────────────────────────────────────────────────────────

func GetEXEThreatLandscape(c *gin.Context) {
	campaigns := []gin.H{
		{"name": "APT29 — Cozy Bear Financial Sector", "actor": "APT29", "type": "espionage", "severity": "critical", "active_since": "2025-05-12", "ttps": 14, "iocs_matched": 7},
		{"name": "Ransomware Campaign — LockBit 3.0",  "actor": "LockBit", "type": "ransomware", "severity": "critical", "active_since": "2025-06-01", "ttps": 9, "iocs_matched": 3},
		{"name": "Supply Chain Attack — npm Packages",  "actor": "Unknown",  "type": "supply_chain", "severity": "high", "active_since": "2025-07-02", "ttps": 5, "iocs_matched": 2},
		{"name": "Phishing Campaign — HR Credential Harvest", "actor": "TA505", "type": "phishing", "severity": "high", "active_since": "2025-07-10", "ttps": 4, "iocs_matched": 5},
	}
	malware := []gin.H{
		{"name": "LockBit 3.0",    "type": "ransomware", "trend": "rising",  "industry_hits": 142, "your_iocs": 3},
		{"name": "Emotet v6",      "type": "loader",     "trend": "stable",  "industry_hits": 89,  "your_iocs": 1},
		{"name": "Cobalt Strike",  "type": "c2",         "trend": "stable",  "industry_hits": 203, "your_iocs": 4},
		{"name": "BlackCat/ALPHV", "type": "ransomware", "trend": "falling", "industry_hits": 67,  "your_iocs": 0},
		{"name": "QakBot",         "type": "banking",    "trend": "rising",  "industry_hits": 55,  "your_iocs": 2},
	}
	geoThreats := []gin.H{
		{"country": "Russian Federation", "threat_count": 847, "category": "apt"},
		{"country": "China",              "threat_count": 523, "category": "apt"},
		{"country": "North Korea",        "threat_count": 201, "category": "financial"},
		{"country": "Iran",               "threat_count": 178, "category": "destructive"},
		{"country": "Brazil",             "threat_count": 312, "category": "cybercrime"},
		{"country": "United States",      "threat_count": 445, "category": "cybercrime"},
	}
	c.JSON(http.StatusOK, gin.H{
		"active_campaigns":    len(campaigns),
		"threat_actors":       24,
		"ransomware_active":   true,
		"emerging_threats":    3,
		"intel_feeds":         7,
		"campaigns":           campaigns,
		"trending_malware":    malware,
		"geo_distribution":    geoThreats,
		"industry_sector":     "Financial Services",
		"sector_threat_level": "Elevated",
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
		Name   string `json:"name"`
		Score  int    `json:"score"`
		Status string `json:"status"`
	}
	frows, _ := db.Query(`SELECT name, overall_score, compliance_status FROM fce_frameworks WHERE tenant_id=$1 AND is_active=TRUE ORDER BY overall_score ASC LIMIT 8`, tid)
	frameworks := []fwRow{}
	if frows != nil {
		defer frows.Close()
		for frows.Next() {
			var r fwRow; frows.Scan(&r.Name, &r.Score, &r.Status); frameworks = append(frameworks, r)
		}
	}

	var failedControls, openRemediations int
	db.QueryRow(`SELECT COUNT(*) FROM fce_controls WHERE tenant_id=$1 AND assessment_status='failed'`, tid).Scan(&failedControls)
	db.QueryRow(`SELECT COUNT(*) FROM fce_remediations WHERE tenant_id=$1 AND status NOT IN ('closed','cancelled')`, tid).Scan(&openRemediations)

	upcomingAudits := []gin.H{
		{"framework": "PCI DSS v4.0", "auditor": "External QSA", "date": "2025-09-15", "days_until": 60, "readiness": 71},
		{"framework": "ISO 27001",    "auditor": "BSI",           "date": "2025-10-20", "days_until": 95, "readiness": 78},
		{"framework": "SOC 2 Type II","auditor": "Deloitte",      "date": "2025-11-01", "days_until": 107,"readiness": 69},
	}
	c.JSON(http.StatusOK, gin.H{
		"compliance_score":   compScore,
		"audit_readiness":    75,
		"failed_controls":    failedControls,
		"open_remediations":  openRemediations,
		"remediation_pct":    63,
		"frameworks":         frameworks,
		"upcoming_audits":    upcomingAudits,
		"regulatory_risks":   []string{"PCI DSS QSA audit in 60 days — current score 71%", "GDPR DPA inquiry pending — data mapping gaps identified"},
	})
}

// ── vulnerability overview ────────────────────────────────────────────────────

func GetEXEVulns(c *gin.Context) {
	tid := tenantIDFromContext(c)
	var critVulns, totalVulns, patchComp int
	database.DB.QueryRow(`SELECT critical_vulns, total_vulns, patch_compliance FROM exe_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).Scan(&critVulns, &totalVulns, &patchComp)

	affectedBUs := []gin.H{
		{"name": "Engineering",    "vuln_count": 89,  "critical": 12, "sla_breach": 3},
		{"name": "Finance",        "vuln_count": 23,  "critical": 8,  "sla_breach": 2},
		{"name": "Customer Ops",   "vuln_count": 41,  "critical": 5,  "sla_breach": 1},
		{"name": "IT Infra",       "vuln_count": 134, "critical": 18, "sla_breach": 4},
		{"name": "Cloud Platform", "vuln_count": 67,  "critical": 9,  "sla_breach": 2},
	}
	topVulns := []gin.H{
		{"cve": "CVE-2024-3400", "cvss": 10.0, "asset": "Palo Alto VPN", "status": "open",     "kev": true,  "days_open": 12},
		{"cve": "CVE-2024-21887","cvss": 9.1,  "asset": "Ivanti Connect","status": "open",     "kev": true,  "days_open": 8},
		{"cve": "CVE-2024-1709", "cvss": 10.0, "asset": "ConnectWise",   "status": "patching", "kev": true,  "days_open": 5},
		{"cve": "CVE-2023-44487","cvss": 7.5,  "asset": "Web Servers (3)","status": "open",    "kev": false, "days_open": 31},
		{"cve": "CVE-2024-0519", "cvss": 8.8,  "asset": "Chrome Fleet",  "status": "patching", "kev": false, "days_open": 4},
	}
	c.JSON(http.StatusOK, gin.H{
		"critical_vulns":    critVulns,
		"total_vulns":       totalVulns,
		"internet_exposed":  23,
		"patch_compliance":  patchComp,
		"mttr_days":         14,
		"kev_count":         3,
		"remediation_pct":   67,
		"affected_bus":      affectedBUs,
		"top_vulns":         topVulns,
	})
}

// ── incident overview ─────────────────────────────────────────────────────────

func GetEXEIncidents(c *gin.Context) {
	tid := tenantIDFromContext(c)
	var totalInc, critInc int
	database.DB.QueryRow(`SELECT total_incidents, critical_incidents FROM exe_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).Scan(&totalInc, &critInc)

	sevDist := []gin.H{
		{"severity": "critical", "count": 4,  "resolved": 1, "sla_breach": 1},
		{"severity": "high",     "count": 14, "resolved": 9, "sla_breach": 2},
		{"severity": "medium",   "count": 31, "resolved": 24,"sla_breach": 0},
		{"severity": "low",      "count": 56, "resolved": 52,"sla_breach": 0},
	}
	categories := []gin.H{
		{"category": "Malware/Ransomware",       "count": 8,  "pct": 22},
		{"category": "Phishing/BEC",             "count": 19, "pct": 31},
		{"category": "Unauthorized Access",      "count": 11, "pct": 18},
		{"category": "Data Exfiltration",        "count": 5,  "pct": 8},
		{"category": "Denial of Service",        "count": 3,  "pct": 5},
		{"category": "Insider Threat",           "count": 4,  "pct": 6},
		{"category": "Supply Chain",             "count": 2,  "pct": 4},
		{"category": "Other",                    "count": 4,  "pct": 6},
	}
	rootCauses := []gin.H{
		{"cause": "Phishing Email",         "count": 18, "pct": 29},
		{"cause": "Unpatched Software",     "count": 14, "pct": 23},
		{"cause": "Misconfiguration",       "count": 11, "pct": 18},
		{"cause": "Credential Compromise",  "count": 9,  "pct": 14},
		{"cause": "Insider Action",         "count": 5,  "pct": 8},
		{"cause": "Third-Party/Supply Chain","count": 4, "pct": 6},
	}
	c.JSON(http.StatusOK, gin.H{
		"total_incidents":  totalInc,
		"critical":         critInc,
		"open":             9,
		"repeat_incidents": 7,
		"avg_mttd_hours":   3.2,
		"avg_mttr_hours":   14.8,
		"sla_breach_count": 3,
		"sev_distribution": sevDist,
		"categories":       categories,
		"root_causes":      rootCauses,
		"business_impact":  "3 incidents with direct revenue impact totaling $1.2M estimated exposure",
	})
}

// ── asset overview ────────────────────────────────────────────────────────────

func GetEXEAssets(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB

	var totalAssets, critAssets int
	db.QueryRow(`SELECT total_assets, critical_assets FROM exe_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).Scan(&totalAssets, &critAssets)

	var managedEndpoints, cloudAssets, mobileDevices int
	db.QueryRow(`SELECT COUNT(*) FROM assets WHERE tenant_id=$1 AND asset_type IN ('workstation','laptop','server')`, fmt.Sprintf("%d", tid)).Scan(&managedEndpoints)
	db.QueryRow(`SELECT COUNT(*) FROM assets WHERE tenant_id=$1 AND asset_type IN ('cloud_instance','container')`, fmt.Sprintf("%d", tid)).Scan(&cloudAssets)

	assetCategories := []gin.H{
		{"category": "Servers",         "total": 284,  "managed": 271, "critical": 48, "health": 92},
		{"category": "Workstations",    "total": 1847, "managed": 1803,"critical": 0,  "health": 96},
		{"category": "Network Devices", "total": 193,  "managed": 188, "critical": 22, "health": 88},
		{"category": "Cloud Instances", "total": 412,  "managed": 398, "critical": 67, "health": 94},
		{"category": "Mobile Devices",  "total": 634,  "managed": 591, "critical": 0,  "health": 89},
		{"category": "IoT/OT",          "total": 78,   "managed": 61,  "critical": 12, "health": 72},
	}
	c.JSON(http.StatusOK, gin.H{
		"total_assets":        totalAssets,
		"critical_assets":     critAssets,
		"managed_endpoints":   managedEndpoints,
		"cloud_assets":        cloudAssets,
		"mobile_devices":      mobileDevices,
		"unsupported_systems": 23,
		"asset_health_score":  91,
		"coverage_pct":        96,
		"asset_categories":    assetCategories,
	})
}

// ── forecasting ───────────────────────────────────────────────────────────────

func GetEXEForecasting(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB

	type fcRow struct {
		Date       string  `json:"date"`
		Metric     string  `json:"metric"`
		Value      float64 `json:"value"`
		ConfLow    float64 `json:"confidence_low"`
		ConfHigh   float64 `json:"confidence_high"`
	}
	rows, _ := db.Query(`SELECT forecast_date, metric, predicted_value, confidence_low, confidence_high
		FROM exe_forecasts WHERE tenant_id=$1 ORDER BY forecast_date ASC, metric`, tid)
	forecasts := []fcRow{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var r fcRow; var d time.Time
			rows.Scan(&d, &r.Metric, &r.Value, &r.ConfLow, &r.ConfHigh)
			r.Date = d.Format("Jan 2")
			forecasts = append(forecasts, r)
		}
	}

	// narrative insights
	insights := []gin.H{
		{"title": "Incident Growth Projected", "text": "Based on current trends, incident volume is projected to increase 18% over the next 30 days. Primary driver: expanded attack surface from cloud migration.", "severity": "medium", "metric": "incidents"},
		{"title": "Compliance Readiness Declining", "text": "PCI DSS readiness is projected to reach 65% by audit date unless 8 critical controls are remediated. Recommend immediate escalation.", "severity": "critical", "metric": "compliance"},
		{"title": "Patch Backlog Growth", "text": "Without additional remediation capacity, patch backlog will grow from 354 to ~487 items (+37%) in 30 days.", "severity": "high", "metric": "vulns"},
		{"title": "Threat Actor Activity Increasing", "text": "Financial services sector threat activity forecast shows 23% increase in Q3, driven by APT29 and ransomware-as-a-service expansion.", "severity": "high", "metric": "threats"},
		{"title": "Resource Requirement", "text": "Current analyst workload trajectory projects 140% capacity utilization in 6 weeks. Recommend hiring or automation expansion.", "severity": "medium", "metric": "resources"},
	}

	c.JSON(http.StatusOK, gin.H{
		"forecasts": forecasts,
		"insights":  insights,
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
		Incidents       int     `json:"total_incidents"`
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

	// SOC performance metrics
	socPerf := gin.H{
		"alerts_per_analyst_day":    42,
		"escalation_rate":           8.3,
		"first_response_mins":       4.2,
		"analyst_utilization":       87,
		"playbook_adherence":        94,
		"automation_savings_hours":  124,
	}

	// Business unit risk comparison
	buComparison := []gin.H{
		{"name": "Finance",       "risk_score": 78, "incidents": 3, "compliance": 91},
		{"name": "Engineering",   "risk_score": 64, "incidents": 5, "compliance": 82},
		{"name": "Customer Ops",  "risk_score": 59, "incidents": 2, "compliance": 88},
		{"name": "HR",            "risk_score": 41, "incidents": 1, "compliance": 94},
		{"name": "Marketing",     "risk_score": 38, "incidents": 2, "compliance": 90},
		{"name": "Legal",         "risk_score": 28, "incidents": 0, "compliance": 97},
	}

	c.JSON(http.StatusOK, gin.H{
		"series":         series,
		"soc_perf":       socPerf,
		"bu_comparison":  buComparison,
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
	var body struct{ Action string `json:"action"` }
	c.ShouldBindJSON(&body)

	responses := map[string]string{
		"executive_summary": "EXECUTIVE SECURITY BRIEFING — " + time.Now().Format("January 2006") + "\n\nOVERALL SECURITY POSTURE: ELEVATED RISK\nSecurity Score: 73/100 (↓2 from last month)\n\nKEY METRICS:\n• Active Incidents: 9 open (4 critical)\n• Critical Vulnerabilities: 47 (3 CISA KEV)\n• Compliance: 74% average across 12 frameworks\n• MTTD: 3.2h | MTTR: 14.8h | SLA Compliance: 91%\n• Financial Risk Exposure: $4.93M\n\nTOP 3 EXECUTIVE PRIORITIES:\n1. Emergency patch for CVE-2024-3400 (CISA KEV, CVSS 10.0) — PAN-OS VPN gateway\n2. PCI DSS remediation: 62 failing controls, QSA audit in 60 days\n3. Ransomware campaign (LockBit 3.0) — financial sector targeting active\n\nBUSINESS IMPACT: 3 business units at elevated risk. Finance & Treasury has 3 active incidents with $2.4M revenue exposure.\n\nRECOMMENDED BOARD ACTIONS:\n• Authorize emergency patch window (est. 4h downtime)\n• Review cybersecurity insurance adequacy ($50K-$500K PCI fine exposure)\n• Approve SOC headcount expansion (current utilization: 87%)",

		"weekly_briefing": "WEEKLY SECURITY BRIEFING — Week of " + time.Now().Format("January 2, 2006") + "\n\nSUMMARY: Moderate security week with 1 significant new threat campaign identified.\n\nNEW THIS WEEK:\n• APT29 campaign targeting financial services sector — 7 IOCs matched in your environment\n• LockBit 3.0 variant detected in threat feeds — 3 IOC matches\n• 12 new critical CVEs published; 4 affect your asset inventory\n• SOC closed 23 incidents, escalated 3 to P1\n\nMETRICS VS LAST WEEK:\n• Alert Volume: 14,203 (+8%) — increased scanning activity\n• Incidents: 9 open (was 7) — 2 new high-severity\n• MTTD: 3.2h (was 3.8h) — ↑improvement\n• MTTR: 14.8h (was 16.2h) — ↑improvement\n• Patches Applied: 47 (was 31)\n\nFOCUS AREAS FOR NEXT WEEK:\n• Complete CVE-2024-3400 patching on VPN gateway\n• Resolve 2 PCI DSS failing controls before monthly review\n• Schedule tabletop exercise for ransomware scenario",

		"board_summary": "BOARD SECURITY REPORT — Q3 2025\n\nEXECUTIVE SUMMARY\nThe organization maintains a security score of 73/100. While operational metrics have improved (MTTD down 16% QoQ), the elevated threat landscape and compliance gaps require board attention and investment.\n\nKEY RISKS FOR BOARD AWARENESS:\n1. COMPLIANCE RISK: PCI DSS audit in 60 days at 71% readiness. Fine exposure: $50K–$500K. Estimated remediation cost: $35K.\n2. THREAT RISK: Active nation-state campaign (APT29) targeting financial services. 7 IOCs have matched our environment.\n3. OPERATIONAL RISK: SOC capacity at 87% utilization. Incident response SLA at risk without additional headcount.\n\nINVESTMENT REQUEST:\n• Emergency patch cycle: $15K (covered by existing budget)\n• Additional SOC analyst (×2): $180K annually\n• DLP tool deployment: $45K\nExpected ROI: 14:1 based on risk reduction modeling.\n\nCOMPLIANCE POSTURE: 12 frameworks active. Average score 74%. SOC 2 and PCI DSS are lowest performers.\n\nRECOMMENDATION: Approve security investment package. Defer non-critical technology projects until compliance gaps resolved.",

		"risk_analysis": "BUSINESS RISK ANALYSIS — " + time.Now().Format("January 2006") + "\n\nENTERPRISE RISK SCORE: 68/100 (High)\n\nTOP BUSINESS RISKS:\n\n1. CRITICAL — Exploitation of Unpatched Systems\n   CVE-2024-3400 affects internet-facing VPN gateway. Exploit code publicly available. Probability of exploitation in 14 days: 73%. Business impact: potential remote code execution, data exfiltration.\n   Mitigation: Emergency patch (4h maintenance window required)\n\n2. CRITICAL — PCI DSS Non-Compliance Penalty\n   Current readiness: 71%. 62 failing controls. QSA audit: Sept 15. Fine range: $50K–$500K/month post-audit. Customer/partner contract exposure if certification lapsed.\n   Mitigation: Prioritized remediation sprint — 8 engineers, 3 weeks\n\n3. HIGH — Ransomware Exposure\n   LockBit 3.0 campaign active in sector. 3 IOC matches. 1 unresolved phishing attempt in past 7 days. Estimated ransom demand if compromised: $2–5M. Recovery time: 5–14 days.\n   Mitigation: Validate backup integrity, test recovery playbook, deploy email security improvements\n\n4. HIGH — Insider Threat\n   3 users flagged by behavioral analytics for anomalous data access. 2 on HR notice. Estimated data at risk: 45,000 customer records.\n   Mitigation: Enhanced monitoring, access review, HR coordination",

		"trend_analysis": "SECURITY TREND ANALYSIS — Last 90 Days\n\nSECURITY SCORE TREND: 68 → 71 → 73 (↑5 over 90 days)\nPositive trajectory driven by:\n• Successful EDR rollout (+340 endpoints covered)\n• Patch compliance improvement: 71% → 82%\n• MTTD improvement: 6.1h → 3.2h (↓47%)\n\nRISK SCORE TREND: 81 → 74 → 68 (↓13 — improving)\nRisk reduction from:\n• 3 critical vulnerabilities remediated\n• 2 high-risk firewall rules reviewed\n• Phishing simulation + training cycle completed\n\nCOMPLIANCE TREND: 69% → 72% → 74%\nSlowing improvement. PCI DSS dragging average down.\n\nINCIDENT TREND: 24 → 19 → 9 per week (↓63%)\nSignificant reduction attributable to:\n• Automated playbook handling of tier-1 alerts\n• Improved email security catching phishing earlier\n\nCONCERNS:\n• Vulnerability backlog growing despite remediation effort (new CVEs outpacing patches)\n• Cloud asset expansion outpacing security tooling\n• SOC analyst overtime increasing — sustainability risk\n\nFORECAST: If current trajectory maintained, security score will reach 78+ by Q4. PCI compliance requires external intervention to remain on track.",

		"recommendations": "STRATEGIC SECURITY RECOMMENDATIONS — Q3 2025\n\nIMMEDIATE (0-30 days):\n1. Emergency patch CVE-2024-3400 (PAN-OS VPN) — assign ops team, 4h window\n   Owner: CISO | Effort: 8h | Risk reduction: -12 risk points\n2. Remediate 8 critical PCI DSS controls — dedicated sprint\n   Owner: Engineering + Compliance | Effort: 3 weeks | Reduces fine exposure by 70%\n3. Initiate third-party pen test (overdue 47 days)\n   Owner: CISO | Budget: $25K | Required for PCI re-certification\n\nSHORT-TERM (30-90 days):\n4. Deploy DLP solution — email + endpoint channels\n   Owner: Security Architecture | Budget: $45K | Addresses ISO 27001 A.8.12 gap\n5. Hire 2 additional SOC analysts — current utilization 87%\n   Owner: CISO + HR | Budget: $180K/yr | Prevents SLA degradation\n6. Complete insider threat program — formal policy + monitoring\n   Owner: CISO + Legal | Effort: 4 weeks | 3 users currently at risk\n\nLONG-TERM (90+ days):\n7. Cloud security posture consolidation — single CSPM platform\n   Owner: Cloud Platform + Security | Budget: $85K | Addresses 3 audit findings\n8. Zero Trust network architecture roadmap\n   Owner: CTO + CISO | Timeline: 18 months | Strategic risk reduction\n9. Security awareness maturity program — quarterly cadence\n   Owner: Security + HR | Budget: $20K/yr | Reduces phishing success rate",

		"predictive_insights": "PREDICTIVE RISK INSIGHTS — 90-Day Forecast\n\nMODEL: Linear regression + threat intelligence weighting\nCONFIDENCE: 74% (medium)\n\nRISK TRAJECTORY: ↑Increasing (68 → 74 predicted over 90 days)\nPrimary driver: Cloud expansion (+12% new assets) outpacing security controls\n\nINCIDENT VOLUME FORECAST:\n• 30 days: 11-14 incidents/week (+15-22%)\n• 60 days: 13-18 incidents/week\n• 90 days: 10-15 incidents/week (seasonal reduction August)\n\nCOMPLIANCE READINESS AT AUDIT:\n• PCI DSS (Sept 15): 65-69% — HIGH RISK of findings without intervention\n• ISO 27001 (Oct 20): 80-83% — MODERATE — manageable with current trajectory\n• SOC 2 (Nov 1): 72-75% — MODERATE\n\nVULNERABILITY BACKLOG FORECAST:\n• Without additional resources: 354 → 487 items (+37%) in 30 days\n• With 1 additional engineer: 354 → 291 (-18%)\n\nTHREAT EVOLUTION:\n• APT29 campaign expected to intensify through August (historical pattern)\n• Ransomware activity forecast: 23% sector increase in Q3\n• AI-generated phishing attacks projected to increase 40% YoY\n\nRECOMMENDED INTERVENTIONS to change trajectory:\n1. Accelerate patching velocity (prevent backlog growth)\n2. Increase automation (reduce MTTR, improve analyst capacity)\n3. Pre-audit remediation sprint (prevent compliance findings)",
	}

	resp, ok := responses[body.Action]
	if !ok {
		resp = "AI analysis in progress. Reviewing current security metrics, threat intelligence, and compliance posture to provide tailored executive insights."
	}
	c.JSON(http.StatusOK, gin.H{"response": resp, "action": body.Action})
}
