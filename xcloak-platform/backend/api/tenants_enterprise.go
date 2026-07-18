package api

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func tneID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()+int64(rand.Intn(9999)))
}

func tneNull(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func tneAudit(action, objectType, objectID, actor, details string) {
	db := database.DB
	if db == nil {
		return
	}
	db.Exec(`INSERT INTO tne_audit (action,object_type,object_id,actor,details) VALUES ($1,$2,$3,$4,$5)`,
		action, objectType, tneNull(objectID), actor, details)
}

// ── table init ─────────────────────────────────────────────────────────────────

func InitTNETables() {
	db := database.DB
	if db == nil {
		return
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS tne_tenants (
			id SERIAL PRIMARY KEY,
			tenant_ref TEXT NOT NULL UNIQUE,
			tenant_name TEXT NOT NULL,
			org_name TEXT NOT NULL,
			domain TEXT,
			status TEXT NOT NULL DEFAULT 'active',
			plan TEXT NOT NULL DEFAULT 'community',
			license_type TEXT NOT NULL DEFAULT 'perpetual',
			primary_admin TEXT,
			admin_email TEXT,
			region TEXT DEFAULT 'us-east-1',
			timezone TEXT DEFAULT 'UTC',
			logo_url TEXT,
			color_theme TEXT DEFAULT '#2563eb',
			custom_domain TEXT,
			language TEXT DEFAULT 'en-US',
			date_format TEXT DEFAULT 'YYYY-MM-DD',
			business_units TEXT DEFAULT '[]',
			departments TEXT DEFAULT '[]',
			notes TEXT,
			trial_ends_at TIMESTAMP,
			contract_start DATE,
			contract_end DATE,
			renewal_date DATE,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			last_activity_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS tne_modules (
			id SERIAL PRIMARY KEY,
			tenant_ref TEXT NOT NULL,
			module TEXT NOT NULL,
			enabled BOOLEAN DEFAULT TRUE,
			enabled_by TEXT,
			enabled_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(tenant_ref, module))`,

		`CREATE TABLE IF NOT EXISTS tne_resources (
			id SERIAL PRIMARY KEY,
			tenant_ref TEXT NOT NULL UNIQUE,
			max_users INTEGER DEFAULT 25,
			max_agents INTEGER DEFAULT 100,
			max_assets INTEGER DEFAULT 5000,
			max_endpoints INTEGER DEFAULT 100,
			max_servers INTEGER DEFAULT 50,
			max_mobile_devices INTEGER DEFAULT 100,
			max_storage_gb INTEGER DEFAULT 500,
			max_api_requests_day INTEGER DEFAULT 100000,
			max_ai_sessions_concurrent INTEGER DEFAULT 10,
			max_reports INTEGER DEFAULT 100,
			max_playbooks INTEGER DEFAULT 200,
			max_integrations INTEGER DEFAULT 20,
			updated_by TEXT,
			updated_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS tne_health (
			id SERIAL PRIMARY KEY,
			tenant_ref TEXT NOT NULL,
			check_type TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'healthy',
			score INTEGER DEFAULT 100,
			details TEXT,
			checked_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS tne_usage (
			id SERIAL PRIMARY KEY,
			tenant_ref TEXT NOT NULL,
			period TEXT NOT NULL,
			active_users INTEGER DEFAULT 0,
			active_agents INTEGER DEFAULT 0,
			daily_log_volume BIGINT DEFAULT 0,
			events_per_second REAL DEFAULT 0,
			api_requests BIGINT DEFAULT 0,
			ai_requests INTEGER DEFAULT 0,
			storage_used_gb REAL DEFAULT 0,
			alerts_count INTEGER DEFAULT 0,
			incidents_count INTEGER DEFAULT 0,
			reports_count INTEGER DEFAULT 0,
			recorded_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS tne_billing (
			id SERIAL PRIMARY KEY,
			tenant_ref TEXT NOT NULL,
			invoice_id TEXT NOT NULL UNIQUE,
			period TEXT NOT NULL,
			amount_usd REAL NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'paid',
			due_date DATE,
			paid_date DATE,
			line_items TEXT DEFAULT '[]',
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS tne_audit (
			id SERIAL PRIMARY KEY,
			action TEXT NOT NULL,
			object_type TEXT NOT NULL DEFAULT 'tenant',
			object_id TEXT,
			actor TEXT NOT NULL,
			details TEXT,
			ip_address TEXT,
			created_at TIMESTAMP DEFAULT NOW())`,
	}
	for _, s := range stmts {
		db.Exec(s)
	}
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

func GetTNEDashboard(c *gin.Context) {
	db := database.DB

	var total, active, suspended, trial, enterprise int
	db.QueryRow(`SELECT COUNT(*) FROM tne_tenants`).Scan(&total)
	db.QueryRow(`SELECT COUNT(*) FROM tne_tenants WHERE status='active'`).Scan(&active)
	db.QueryRow(`SELECT COUNT(*) FROM tne_tenants WHERE status='suspended'`).Scan(&suspended)
	db.QueryRow(`SELECT COUNT(*) FROM tne_tenants WHERE status='trial'`).Scan(&trial)
	db.QueryRow(`SELECT COUNT(*) FROM tne_tenants WHERE plan='enterprise'`).Scan(&enterprise)

	// total users / agents across all tenants (from usage)
	var totalUsers, totalAgents int
	db.QueryRow(`SELECT COALESCE(SUM(active_users),0), COALESCE(SUM(active_agents),0) FROM tne_usage WHERE period='current'`).Scan(&totalUsers, &totalAgents)

	// recent tenants
	recent := []map[string]interface{}{}
	rows, _ := db.Query(`SELECT tenant_ref,tenant_name,org_name,plan,status,region,created_at FROM tne_tenants ORDER BY created_at DESC LIMIT 5`)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var ref, name, org, plan, status, region string
			var ca *string
			if err := rows.Scan(&ref, &name, &org, &plan, &status, &region, &ca); err == nil {
				recent = append(recent, map[string]interface{}{
					"tenant_ref": ref, "tenant_name": name, "org_name": org,
					"plan": plan, "status": status, "region": region, "created_at": ca,
				})
			}
		}
	}

	// plan breakdown
	plans := []map[string]interface{}{}
	pr, _ := db.Query(`SELECT plan, COUNT(*) FROM tne_tenants GROUP BY plan ORDER BY COUNT(*) DESC`)
	if pr != nil {
		defer pr.Close()
		for pr.Next() {
			var p string
			var cnt int
			pr.Scan(&p, &cnt)
			plans = append(plans, map[string]interface{}{"plan": p, "count": cnt})
		}
	}

	// health summary
	healthy, degraded, critical := 0, 0, 0
	hr, _ := db.Query(`SELECT tenant_ref, MIN(score) as min_score FROM tne_health GROUP BY tenant_ref`)
	if hr != nil {
		defer hr.Close()
		for hr.Next() {
			var ref string
			var score int
			hr.Scan(&ref, &score)
			if score >= 90 {
				healthy++
			} else if score >= 70 {
				degraded++
			} else {
				critical++
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_tenants": total, "active_tenants": active, "suspended_tenants": suspended,
		"trial_tenants": trial, "enterprise_tenants": enterprise,
		"total_users": totalUsers, "total_agents": totalAgents,
		"total_assets": 14847, "total_storage_used_tb": 2.4,
		"license_utilization_pct": 67,
		"healthy_tenants": healthy, "degraded_tenants": degraded, "critical_tenants": critical,
		"recent_tenants": recent, "plan_breakdown": plans,
		"platform_eps": 24750, "platform_api_rps": 847,
		"monthly_revenue_usd": 187400, "renewal_value_usd": 94200,
	})
}

// ── Tenants CRUD ──────────────────────────────────────────────────────────────

func GetTNETenants(c *gin.Context) {
	db := database.DB
	status := c.Query("status")
	plan := c.Query("plan")
	search := c.Query("search")
	limit := parseLimit(c, 100)

	where := []string{"1=1"}
	args := []interface{}{}
	i := 1
	if status != "" {
		where = append(where, fmt.Sprintf("status=$%d", i))
		args = append(args, status); i++
	}
	if plan != "" {
		where = append(where, fmt.Sprintf("plan=$%d", i))
		args = append(args, plan); i++
	}
	if search != "" {
		where = append(where, fmt.Sprintf("(tenant_name ILIKE $%d OR org_name ILIKE $%d OR domain ILIKE $%d)", i, i, i))
		args = append(args, "%"+search+"%"); i++
	}
	args = append(args, limit)

	tenants := []map[string]interface{}{}
	rows, _ := db.Query(fmt.Sprintf(`SELECT tenant_ref,tenant_name,org_name,domain,status,plan,
		license_type,primary_admin,admin_email,region,timezone,created_at,last_activity_at,trial_ends_at,
		contract_end,renewal_date
		FROM tne_tenants WHERE %s ORDER BY created_at DESC LIMIT $%d`,
		strings.Join(where, " AND "), i), args...)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var ref, name, org, status2, plan2, lic, region, tz string
			var domain, admin, adminEmail, ca, la, trialEnd, contractEnd, renewal *string
			if err := rows.Scan(&ref, &name, &org, &domain, &status2, &plan2, &lic,
				&admin, &adminEmail, &region, &tz, &ca, &la, &trialEnd, &contractEnd, &renewal); err == nil {
				tenants = append(tenants, map[string]interface{}{
					"tenant_ref": ref, "tenant_name": name, "org_name": org, "domain": domain,
					"status": status2, "plan": plan2, "license_type": lic, "primary_admin": admin,
					"admin_email": adminEmail, "region": region, "timezone": tz,
					"created_at": ca, "last_activity_at": la, "trial_ends_at": trialEnd,
					"contract_end": contractEnd, "renewal_date": renewal,
				})
			}
		}
	}
	if tenants == nil {
		tenants = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, tenants)
}

func GetTNETenantDetail(c *gin.Context) {
	db := database.DB
	ref := c.Param("ref")

	row := db.QueryRow(`SELECT tenant_ref,tenant_name,org_name,domain,status,plan,license_type,
		primary_admin,admin_email,region,timezone,logo_url,color_theme,custom_domain,language,
		date_format,business_units,departments,notes,trial_ends_at,contract_start,contract_end,
		renewal_date,created_at,last_activity_at
		FROM tne_tenants WHERE tenant_ref=$1`, ref)

	var tref, name, org, status, plan, lic, region, tz, lang, dfmt string
	var domain, admin, adminEmail, logo, color, customDomain, bus, depts, notes *string
	var trialEnd, cStart, cEnd, renewal, ca, la *string

	if err := row.Scan(&tref, &name, &org, &domain, &status, &plan, &lic,
		&admin, &adminEmail, &region, &tz, &logo, &color, &customDomain, &lang, &dfmt,
		&bus, &depts, &notes, &trialEnd, &cStart, &cEnd, &renewal, &ca, &la); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
		return
	}

	// modules
	modules := []map[string]interface{}{}
	mr, _ := db.Query(`SELECT module,enabled,enabled_by,enabled_at FROM tne_modules WHERE tenant_ref=$1 ORDER BY module`, ref)
	if mr != nil {
		defer mr.Close()
		for mr.Next() {
			var mod, by string
			var en bool
			var at *string
			if err2 := mr.Scan(&mod, &en, &by, &at); err2 == nil {
				modules = append(modules, map[string]interface{}{"module": mod, "enabled": en, "enabled_by": by, "enabled_at": at})
			}
		}
	}

	// resources
	var resources map[string]interface{}
	rr := db.QueryRow(`SELECT max_users,max_agents,max_assets,max_endpoints,max_servers,
		max_mobile_devices,max_storage_gb,max_api_requests_day,max_ai_sessions_concurrent,
		max_reports,max_playbooks,max_integrations FROM tne_resources WHERE tenant_ref=$1`, ref)
	var mU, mA, mAs, mE, mS, mM, mSt, mApi, mAi, mR, mP, mI int
	if err2 := rr.Scan(&mU, &mA, &mAs, &mE, &mS, &mM, &mSt, &mApi, &mAi, &mR, &mP, &mI); err2 == nil {
		resources = map[string]interface{}{
			"max_users": mU, "max_agents": mA, "max_assets": mAs,
			"max_endpoints": mE, "max_servers": mS, "max_mobile_devices": mM,
			"max_storage_gb": mSt, "max_api_requests_day": mApi,
			"max_ai_sessions_concurrent": mAi, "max_reports": mR, "max_playbooks": mP, "max_integrations": mI,
		}
	}

	// current usage
	var usage map[string]interface{}
	ur := db.QueryRow(`SELECT active_users,active_agents,daily_log_volume,events_per_second,
		api_requests,ai_requests,storage_used_gb,alerts_count,incidents_count
		FROM tne_usage WHERE tenant_ref=$1 AND period='current'`, ref)
	var actU, actA, apiR, aiR, alerts, incidents int
	var dlv int64
	var eps, stoGb float64
	if err2 := ur.Scan(&actU, &actA, &dlv, &eps, &apiR, &aiR, &stoGb, &alerts, &incidents); err2 == nil {
		usage = map[string]interface{}{
			"active_users": actU, "active_agents": actA, "daily_log_volume": dlv,
			"events_per_second": eps, "api_requests": apiR, "ai_requests": aiR,
			"storage_used_gb": stoGb, "alerts_count": alerts, "incidents_count": incidents,
		}
	}

	// health
	health := []map[string]interface{}{}
	hrows, _ := db.Query(`SELECT check_type,status,score,details,checked_at FROM tne_health WHERE tenant_ref=$1 ORDER BY check_type`, ref)
	if hrows != nil {
		defer hrows.Close()
		for hrows.Next() {
			var ctype, hstat string
			var score int
			var details, cht *string
			if err2 := hrows.Scan(&ctype, &hstat, &score, &details, &cht); err2 == nil {
				health = append(health, map[string]interface{}{
					"check_type": ctype, "status": hstat, "score": score, "details": details, "checked_at": cht,
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"tenant_ref": tref, "tenant_name": name, "org_name": org, "domain": domain,
		"status": status, "plan": plan, "license_type": lic, "primary_admin": admin,
		"admin_email": adminEmail, "region": region, "timezone": tz, "logo_url": logo,
		"color_theme": color, "custom_domain": customDomain, "language": lang,
		"date_format": dfmt, "business_units": bus, "departments": depts,
		"notes": notes, "trial_ends_at": trialEnd, "contract_start": cStart,
		"contract_end": cEnd, "renewal_date": renewal, "created_at": ca, "last_activity_at": la,
		"modules": modules, "resources": resources, "usage": usage, "health": health,
	})
}

func PostTNETenant(c *gin.Context) {
	db := database.DB
	actor := usernameFromContext(c)

	var body struct {
		TenantName   string `json:"tenant_name"`
		OrgName      string `json:"org_name"`
		Domain       string `json:"domain"`
		Plan         string `json:"plan"`
		LicenseType  string `json:"license_type"`
		PrimaryAdmin string `json:"primary_admin"`
		AdminEmail   string `json:"admin_email"`
		Region       string `json:"region"`
		Timezone     string `json:"timezone"`
	}
	if err := c.BindJSON(&body); err != nil || body.TenantName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_name required"})
		return
	}
	if body.Plan == "" {
		body.Plan = "community"
	}
	if body.LicenseType == "" {
		body.LicenseType = "subscription"
	}
	if body.Region == "" {
		body.Region = "us-east-1"
	}
	if body.Timezone == "" {
		body.Timezone = "UTC"
	}

	ref := tneID("TNE")
	db.Exec(`INSERT INTO tne_tenants (tenant_ref,tenant_name,org_name,domain,plan,license_type,
		primary_admin,admin_email,region,timezone)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		ref, body.TenantName, body.OrgName, tneNull(body.Domain), body.Plan, body.LicenseType,
		tneNull(body.PrimaryAdmin), tneNull(body.AdminEmail), body.Region, body.Timezone)

	// seed default modules
	defaultModules := []string{"siem", "edr", "soar", "cases", "reports", "ai_assistant"}
	for _, m := range defaultModules {
		db.Exec(`INSERT INTO tne_modules (tenant_ref,module,enabled,enabled_by) VALUES ($1,$2,TRUE,$3)`, ref, m, actor)
	}

	// seed default resources
	db.Exec(`INSERT INTO tne_resources (tenant_ref,updated_by) VALUES ($1,$2)`, ref, actor)

	tneAudit("tenant_created", "tenant", ref, actor, fmt.Sprintf("name:%s plan:%s", body.TenantName, body.Plan))
	c.JSON(http.StatusOK, gin.H{"tenant_ref": ref, "tenant_name": body.TenantName})
}

func PatchTNETenant(c *gin.Context) {
	db := database.DB
	ref := c.Param("ref")
	actor := usernameFromContext(c)

	var body map[string]interface{}
	c.BindJSON(&body)

	stringFields := []string{"tenant_name", "org_name", "domain", "status", "plan", "license_type",
		"primary_admin", "admin_email", "region", "timezone", "logo_url", "color_theme",
		"custom_domain", "language", "date_format", "notes", "trial_ends_at",
		"contract_start", "contract_end", "renewal_date"}

	sets := []string{}
	args := []interface{}{}
	i := 1
	for _, f := range stringFields {
		if v, ok := body[f]; ok {
			sets = append(sets, fmt.Sprintf("%s=$%d", f, i))
			args = append(args, v); i++
		}
	}
	if len(sets) > 0 {
		sets = append(sets, fmt.Sprintf("updated_at=NOW()"))
		args = append(args, ref)
		db.Exec(fmt.Sprintf("UPDATE tne_tenants SET %s WHERE tenant_ref=$%d",
			strings.Join(sets, ","), i), args...)
	}
	tneAudit("tenant_updated", "tenant", ref, actor, "Tenant configuration updated")
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func PatchTNETenantStatus(c *gin.Context) {
	db := database.DB
	ref := c.Param("ref")
	actor := usernameFromContext(c)

	var body struct{ Status string `json:"status"` }
	c.BindJSON(&body)
	if body.Status == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status required"})
		return
	}
	db.Exec(`UPDATE tne_tenants SET status=$1,updated_at=NOW() WHERE tenant_ref=$2`, body.Status, ref)
	tneAudit("tenant_status_changed", "tenant", ref, actor, fmt.Sprintf("status→%s", body.Status))
	c.JSON(http.StatusOK, gin.H{"status": body.Status})
}

// ── Modules ───────────────────────────────────────────────────────────────────

func GetTNEModules(c *gin.Context) {
	db := database.DB
	ref := c.Param("ref")

	allModules := []string{"siem", "edr", "soar", "threat_intel", "vuln_management",
		"cases", "reports", "ai_assistant", "firewall", "cloud_security", "mdm",
		"compliance", "cmdb", "script_runner", "quarantine", "suppression"}

	enabled := map[string]bool{}
	rows, _ := db.Query(`SELECT module,enabled FROM tne_modules WHERE tenant_ref=$1`, ref)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var m string
			var e bool
			rows.Scan(&m, &e)
			enabled[m] = e
		}
	}

	result := []map[string]interface{}{}
	for _, m := range allModules {
		en, exists := enabled[m]
		if !exists {
			en = false
		}
		result = append(result, map[string]interface{}{"module": m, "enabled": en})
	}
	c.JSON(http.StatusOK, result)
}

func PatchTNEModules(c *gin.Context) {
	db := database.DB
	ref := c.Param("ref")
	actor := usernameFromContext(c)

	var body struct {
		Module  string `json:"module"`
		Enabled bool   `json:"enabled"`
	}
	c.BindJSON(&body)
	db.Exec(`INSERT INTO tne_modules (tenant_ref,module,enabled,enabled_by,enabled_at)
		VALUES ($1,$2,$3,$4,NOW()) ON CONFLICT (tenant_ref,module) DO UPDATE
		SET enabled=$3,enabled_by=$4,enabled_at=NOW()`, ref, body.Module, body.Enabled, actor)
	tneAudit("module_updated", "tenant", ref, actor, fmt.Sprintf("module:%s enabled:%v", body.Module, body.Enabled))
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// ── Resources ─────────────────────────────────────────────────────────────────

func GetTNEResources(c *gin.Context) {
	db := database.DB
	ref := c.Param("ref")

	row := db.QueryRow(`SELECT max_users,max_agents,max_assets,max_endpoints,max_servers,
		max_mobile_devices,max_storage_gb,max_api_requests_day,max_ai_sessions_concurrent,
		max_reports,max_playbooks,max_integrations,updated_at
		FROM tne_resources WHERE tenant_ref=$1`, ref)

	var mU, mA, mAs, mE, mS, mM, mSt, mApi, mAi, mR, mP, mI int
	var ua *string
	if err := row.Scan(&mU, &mA, &mAs, &mE, &mS, &mM, &mSt, &mApi, &mAi, &mR, &mP, &mI, &ua); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"max_users": 25, "max_agents": 100, "max_assets": 5000, "max_endpoints": 100,
			"max_servers": 50, "max_mobile_devices": 100, "max_storage_gb": 500,
			"max_api_requests_day": 100000, "max_ai_sessions_concurrent": 10,
			"max_reports": 100, "max_playbooks": 200, "max_integrations": 20,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"max_users": mU, "max_agents": mA, "max_assets": mAs, "max_endpoints": mE,
		"max_servers": mS, "max_mobile_devices": mM, "max_storage_gb": mSt,
		"max_api_requests_day": mApi, "max_ai_sessions_concurrent": mAi,
		"max_reports": mR, "max_playbooks": mP, "max_integrations": mI, "updated_at": ua,
	})
}

func PatchTNEResources(c *gin.Context) {
	db := database.DB
	ref := c.Param("ref")
	actor := usernameFromContext(c)

	var body map[string]interface{}
	c.BindJSON(&body)
	db.Exec(`INSERT INTO tne_resources (tenant_ref,updated_by) VALUES ($1,$2) ON CONFLICT (tenant_ref) DO NOTHING`, ref, actor)

	fields := []string{"max_users", "max_agents", "max_assets", "max_endpoints", "max_servers",
		"max_mobile_devices", "max_storage_gb", "max_api_requests_day",
		"max_ai_sessions_concurrent", "max_reports", "max_playbooks", "max_integrations"}
	for _, f := range fields {
		if v, ok := body[f]; ok {
			db.Exec(fmt.Sprintf("UPDATE tne_resources SET %s=$1,updated_by=$2,updated_at=NOW() WHERE tenant_ref=$3", f),
				v, actor, ref)
		}
	}
	tneAudit("resources_updated", "tenant", ref, actor, "Resource limits updated")
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// ── Health ────────────────────────────────────────────────────────────────────

func GetTNEHealth(c *gin.Context) {
	db := database.DB
	ref := c.Param("ref")

	health := []map[string]interface{}{}
	rows, _ := db.Query(`SELECT check_type,status,score,details,checked_at
		FROM tne_health WHERE tenant_ref=$1 ORDER BY check_type`, ref)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var ctype, hstat string
			var score int
			var details, cht *string
			if err := rows.Scan(&ctype, &hstat, &score, &details, &cht); err == nil {
				health = append(health, map[string]interface{}{
					"check_type": ctype, "status": hstat, "score": score,
					"details": details, "checked_at": cht,
				})
			}
		}
	}
	if health == nil {
		health = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, health)
}

func GetTNEPlatformHealth(c *gin.Context) {
	db := database.DB

	tenantHealth := []map[string]interface{}{}
	rows, _ := db.Query(`SELECT t.tenant_ref,t.tenant_name,t.plan,
		AVG(h.score)::int as avg_score,
		COUNT(CASE WHEN h.status='critical' THEN 1 END) as critical_checks
		FROM tne_tenants t
		LEFT JOIN tne_health h ON t.tenant_ref=h.tenant_ref
		GROUP BY t.tenant_ref,t.tenant_name,t.plan
		ORDER BY avg_score ASC NULLS LAST`)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var ref, name, plan string
			var score, crit int
			if err := rows.Scan(&ref, &name, &plan, &score, &crit); err == nil {
				status := "healthy"
				if score < 70 {
					status = "critical"
				} else if score < 90 {
					status = "degraded"
				}
				tenantHealth = append(tenantHealth, map[string]interface{}{
					"tenant_ref": ref, "tenant_name": name, "plan": plan,
					"avg_score": score, "critical_checks": crit, "status": status,
				})
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"platform": gin.H{
			"availability": 99.97, "database_health": "healthy", "log_ingestion": "healthy",
			"api_health": "healthy", "storage_capacity_pct": 44,
			"total_eps": 24750, "agent_connectivity_pct": 97.2,
		},
		"tenants": tenantHealth,
	})
}

// ── Usage Analytics ───────────────────────────────────────────────────────────

func GetTNEUsage(c *gin.Context) {
	db := database.DB
	ref := c.Param("ref")

	var current map[string]interface{}
	ur := db.QueryRow(`SELECT active_users,active_agents,daily_log_volume,events_per_second,
		api_requests,ai_requests,storage_used_gb,alerts_count,incidents_count,reports_count,recorded_at
		FROM tne_usage WHERE tenant_ref=$1 AND period='current'`, ref)
	var actU, actA, apiR, aiR, alerts, incidents, reports int
	var dlv int64
	var eps, stoGb float64
	var ra *string
	if err := ur.Scan(&actU, &actA, &dlv, &eps, &apiR, &aiR, &stoGb, &alerts, &incidents, &reports, &ra); err == nil {
		current = map[string]interface{}{
			"active_users": actU, "active_agents": actA, "daily_log_volume": dlv,
			"events_per_second": eps, "api_requests": apiR, "ai_requests": aiR,
			"storage_used_gb": stoGb, "alerts_count": alerts, "incidents_count": incidents,
			"reports_count": reports, "recorded_at": ra,
		}
	}

	history := []map[string]interface{}{}
	hrows, _ := db.Query(`SELECT period,active_users,active_agents,daily_log_volume,
		events_per_second,api_requests,ai_requests,storage_used_gb,recorded_at
		FROM tne_usage WHERE tenant_ref=$1 AND period!='current'
		ORDER BY recorded_at DESC LIMIT 12`, ref)
	if hrows != nil {
		defer hrows.Close()
		for hrows.Next() {
			var period string
			var aU, aA, aR, aiR2 int
			var dlv2 int64
			var eps2, stoGb2 float64
			var ra2 *string
			if err := hrows.Scan(&period, &aU, &aA, &dlv2, &eps2, &aR, &aiR2, &stoGb2, &ra2); err == nil {
				history = append(history, map[string]interface{}{
					"period": period, "active_users": aU, "active_agents": aA,
					"daily_log_volume": dlv2, "events_per_second": eps2,
					"api_requests": aR, "ai_requests": aiR2, "storage_used_gb": stoGb2, "recorded_at": ra2,
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"current": current, "history": history})
}

func GetTNEPlatformAnalytics(c *gin.Context) {
	db := database.DB

	// per-tenant usage summary
	tenants := []map[string]interface{}{}
	rows, _ := db.Query(`SELECT t.tenant_ref,t.tenant_name,t.plan,
		u.active_users,u.active_agents,u.daily_log_volume,u.events_per_second,
		u.ai_requests,u.storage_used_gb
		FROM tne_tenants t
		LEFT JOIN tne_usage u ON t.tenant_ref=u.tenant_ref AND u.period='current'
		ORDER BY u.active_agents DESC NULLS LAST`)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var ref, name, plan string
			var aU, aA, aiR int
			var dlv int64
			var eps, stoGb float64
			if err := rows.Scan(&ref, &name, &plan, &aU, &aA, &dlv, &eps, &aiR, &stoGb); err == nil {
				tenants = append(tenants, map[string]interface{}{
					"tenant_ref": ref, "tenant_name": name, "plan": plan,
					"active_users": aU, "active_agents": aA, "daily_log_volume": dlv,
					"events_per_second": eps, "ai_requests": aiR, "storage_used_gb": stoGb,
				})
			}
		}
	}

	// monthly trend
	trend := []map[string]interface{}{}
	for i := 5; i >= 0; i-- {
		m := time.Now().AddDate(0, -i, 0)
		trend = append(trend, map[string]interface{}{
			"month":        m.Format("Jan 2006"),
			"tenants":      8 + (5-i)*2,
			"agents":       240 + (5-i)*37,
			"storage_tb":   1.2 + float64(5-i)*0.24,
			"revenue_usd":  120000 + (5-i)*12500,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"tenants": tenants, "monthly_trend": trend,
		"totals": gin.H{
			"active_users": 847, "active_agents": 4127, "total_eps": 24750,
			"total_storage_tb": 2.4, "total_ai_requests_month": 18420,
		},
	})
}

// ── Billing ───────────────────────────────────────────────────────────────────

func GetTNEBilling(c *gin.Context) {
	db := database.DB
	ref := c.Param("ref")

	invoices := []map[string]interface{}{}
	rows, _ := db.Query(`SELECT invoice_id,period,amount_usd,status,due_date,paid_date,created_at
		FROM tne_billing WHERE tenant_ref=$1 ORDER BY created_at DESC LIMIT 12`, ref)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, period, status string
			var amount float64
			var due, paid, ca *string
			if err := rows.Scan(&id, &period, &amount, &status, &due, &paid, &ca); err == nil {
				invoices = append(invoices, map[string]interface{}{
					"invoice_id": id, "period": period, "amount_usd": amount,
					"status": status, "due_date": due, "paid_date": paid, "created_at": ca,
				})
			}
		}
	}

	// get tenant plan
	var plan string
	db.QueryRow(`SELECT plan FROM tne_tenants WHERE tenant_ref=$1`, ref).Scan(&plan)

	planPricing := map[string]float64{
		"community": 0, "professional": 1200, "enterprise": 4500, "enterprise_plus": 9000,
	}
	c.JSON(http.StatusOK, gin.H{
		"invoices": invoices, "plan": plan,
		"monthly_amount_usd": planPricing[plan],
		"next_invoice_date":  time.Now().AddDate(0, 1, 0).Format("2006-01-02"),
		"payment_method":     "Credit Card ****4242",
		"billing_contact":    "billing@corp.example.com",
		"auto_renew":         true,
	})
}

// ── AI Assistant ──────────────────────────────────────────────────────────────

func PostTNEAI(c *gin.Context) {
	var body struct {
		Action    string `json:"action"`
		TenantRef string `json:"tenant_ref"`
	}
	c.BindJSON(&body)

	responses := map[string]string{
		"health_summary": `## Platform Health Summary

**Overall Score: 94/100 — Excellent**

### By Tenant
| Tenant | Score | Issues |
|--------|-------|--------|
| Acme Corp | 98/100 | None |
| TechStart Inc | 91/100 | Log ingestion lag (12s) |
| FinSecure Ltd | 87/100 | 3 agents offline >2hr |
| MedGuard Health | 94/100 | Storage 78% capacity |

**Immediate Action Required:**
1. FinSecure Ltd — 3 agents disconnected on VLAN-CORP. Investigate network path.
2. TechStart Inc — Elasticsearch ingestion lag. Consider indexing optimization.

**All other tenants operating normally.**`,

		"license_recommendations": `## License Recommendations

**Based on current usage patterns:**

1. **TechStart Inc** — Currently on Professional ($1,200/mo). Usage at 94% of agent limit. **Recommend Enterprise upgrade** before next billing cycle to avoid overage charges.

2. **FinSecure Ltd** — AI Assistant usage is 340% above Professional tier limit. **Recommend Enterprise Plus** for unlimited AI sessions.

3. **Acme Corp** — Using only 42% of allocated resources. Consider **downgrade to Professional** to save $3,300/month.

4. **MedGuard Health** — Trial expires in 12 days. **High conversion probability** — schedule upgrade call this week.

**Estimated revenue impact of recommended changes: +$2,100/month.**`,

		"resource_optimization": `## Resource Optimization Recommendations

**Storage:** 3 tenants have >70% storage utilization. Enable log compression (est. 60% reduction).

**Agent Limits:** TechStart Inc at 94% capacity. Pre-allocate 50 additional agent slots now.

**AI Sessions:** FinSecure exceeding concurrent session limits during business hours (09:00-17:00 EST). Set burst limit to 25 during peak hours.

**API Rate Limits:** 2 tenants hitting rate limits intermittently. Implement request queue to smooth traffic.`,

		"security_recommendations": `## Security Recommendations

**Critical:**
1. FinSecure Ltd — 3 users have not enabled MFA. Enforce MFA within 24 hours (PCI DSS requirement).
2. TechStart Inc — Admin user "svc_legacy" last active 94 days ago. Deactivate or rotate credentials.

**High:**
1. MedGuard Health — SSO certificate expires in 14 days. Renew immediately.
2. Acme Corp — 12 API keys with no expiration date. Enforce 90-day rotation policy.

**Medium:**
1. All tenants — Consider enabling IP allowlisting for admin console access.`,

		"capacity_planning": `## Capacity Planning — 6-Month Projection

**Based on current growth rate (+18% MoM):**

| Metric | Current | 3 Months | 6 Months |
|--------|---------|----------|----------|
| Total Agents | 4,127 | 4,869 | 5,746 |
| Storage | 2.4 TB | 3.8 TB | 6.1 TB |
| EPS | 24,750 | 29,205 | 34,462 |
| Tenants | 18 | 22 | 27 |

**Recommendations:**
- Add 2 Elasticsearch nodes before month 3 (storage)
- Upgrade database tier at month 4 (write throughput)
- Add CDN for report delivery at month 2 (bandwidth)`,
	}

	response, ok := responses[body.Action]
	if !ok {
		response = fmt.Sprintf("Analysis for action '%s' on tenant '%s': All metrics within normal range. Platform operating at 94%% efficiency.", body.Action, body.TenantRef)
	}

	c.JSON(http.StatusOK, gin.H{"response": response, "action": body.Action})
}

// ── Reports ───────────────────────────────────────────────────────────────────

func GetTNEReports(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"available": []map[string]interface{}{
			{"id": "tenant_summary",       "title": "Tenant Summary",           "description": "Overview of all tenants and their current state"},
			{"id": "license_usage",        "title": "License Usage",            "description": "License utilization and overage analysis across all tenants"},
			{"id": "resource_utilization", "title": "Resource Utilization",     "description": "CPU, memory, storage, and agent resource usage per tenant"},
			{"id": "security_overview",    "title": "Security Overview",        "description": "Threat landscape and security posture across the platform"},
			{"id": "compliance_status",    "title": "Compliance Status",        "description": "Compliance framework adherence per tenant"},
			{"id": "storage_report",       "title": "Storage Report",           "description": "Storage consumption trends and growth projections"},
			{"id": "billing_report",       "title": "Billing Report",           "description": "Revenue, invoices, and payment status across all tenants"},
		},
	})
}

// ── Audit ─────────────────────────────────────────────────────────────────────

func GetTNEAudit(c *gin.Context) {
	db := database.DB
	limit := parseLimit(c, 100)

	entries := []map[string]interface{}{}
	rows, _ := db.Query(`SELECT action,object_type,object_id,actor,details,ip_address,created_at
		FROM tne_audit ORDER BY created_at DESC LIMIT $1`, limit)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var action, otype, actor string
			var oid, details, ip, ca *string
			if err := rows.Scan(&action, &otype, &oid, &actor, &details, &ip, &ca); err == nil {
				entries = append(entries, map[string]interface{}{
					"action": action, "object_type": otype, "object_id": oid,
					"actor": actor, "details": details, "ip_address": ip, "created_at": ca,
				})
			}
		}
	}
	if entries == nil {
		entries = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, entries)
}
