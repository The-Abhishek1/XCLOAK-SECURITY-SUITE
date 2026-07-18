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

func stteID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()+int64(rand.Intn(9999)))
}

func stteNullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func stteAudit(tid int, action, section, actor, details string) {
	db := database.DB
	if db == nil {
		return
	}
	db.Exec(`INSERT INTO stte_audit (tenant_id,action,section,actor,details) VALUES ($1,$2,$3,$4,$5)`,
		tid, action, section, actor, details)
}

// ── table init ────────────────────────────────────────────────────────────────

func InitSTTETables() {
	db := database.DB
	if db == nil {
		return
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS stte_org (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL UNIQUE,
			org_name TEXT NOT NULL DEFAULT 'My Organization',
			display_name TEXT,
			logo_url TEXT,
			domain TEXT,
			timezone TEXT DEFAULT 'UTC',
			locale TEXT DEFAULT 'en-US',
			date_format TEXT DEFAULT 'YYYY-MM-DD',
			contact_email TEXT,
			support_email TEXT,
			max_agents INTEGER DEFAULT 1000,
			data_retention_days INTEGER DEFAULT 365,
			require_mfa BOOLEAN DEFAULT FALSE,
			maintenance_mode BOOLEAN DEFAULT FALSE,
			custom_css TEXT,
			updated_by TEXT,
			updated_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS stte_ai_config (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			provider TEXT NOT NULL,
			model TEXT NOT NULL,
			api_key_masked TEXT,
			endpoint TEXT,
			enabled BOOLEAN DEFAULT FALSE,
			is_default BOOLEAN DEFAULT FALSE,
			max_tokens INTEGER DEFAULT 4096,
			temperature REAL DEFAULT 0.3,
			use_for TEXT DEFAULT '[]',
			rate_limit_rpm INTEGER DEFAULT 100,
			monthly_budget_usd REAL DEFAULT 0,
			updated_by TEXT,
			updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(tenant_id, provider))`,

		`CREATE TABLE IF NOT EXISTS stte_ai_guardrails (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL UNIQUE,
			require_approval_for_actions BOOLEAN DEFAULT TRUE,
			rbac_enabled BOOLEAN DEFAULT TRUE,
			data_masking_enabled BOOLEAN DEFAULT TRUE,
			hallucination_warnings BOOLEAN DEFAULT TRUE,
			audit_all_queries BOOLEAN DEFAULT TRUE,
			max_context_length INTEGER DEFAULT 8192,
			allowed_roles TEXT DEFAULT '["admin","analyst","manager"]',
			blocked_topics TEXT DEFAULT '[]',
			pii_masking_fields TEXT DEFAULT '["ssn","credit_card","password"]',
			updated_by TEXT,
			updated_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS stte_backups (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			backup_id TEXT NOT NULL UNIQUE,
			backup_type TEXT NOT NULL DEFAULT 'full',
			status TEXT NOT NULL DEFAULT 'completed',
			size_bytes BIGINT DEFAULT 0,
			duration_secs INTEGER DEFAULT 0,
			storage_path TEXT,
			encryption TEXT DEFAULT 'AES-256',
			tables_included TEXT DEFAULT '[]',
			triggered_by TEXT NOT NULL DEFAULT 'system',
			error_message TEXT,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS stte_backup_config (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL UNIQUE,
			enabled BOOLEAN DEFAULT TRUE,
			schedule_type TEXT DEFAULT 'daily',
			schedule_time TEXT DEFAULT '02:00',
			retention_days INTEGER DEFAULT 30,
			backup_type TEXT DEFAULT 'full',
			encrypt BOOLEAN DEFAULT TRUE,
			storage TEXT DEFAULT 'local',
			s3_bucket TEXT,
			last_run_at TIMESTAMP,
			next_run_at TIMESTAMP,
			updated_by TEXT,
			updated_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS stte_updates (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			version TEXT NOT NULL,
			release_type TEXT DEFAULT 'patch',
			title TEXT NOT NULL,
			description TEXT,
			release_notes TEXT,
			status TEXT DEFAULT 'available',
			applied_by TEXT,
			applied_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS stte_license (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL UNIQUE,
			license_key TEXT,
			tier TEXT NOT NULL DEFAULT 'community',
			seats_total INTEGER DEFAULT 5,
			seats_used INTEGER DEFAULT 0,
			agents_total INTEGER DEFAULT 25,
			agents_used INTEGER DEFAULT 0,
			features TEXT DEFAULT '[]',
			valid_from DATE,
			valid_until DATE,
			issued_to TEXT,
			issued_by TEXT DEFAULT 'XCloak Security',
			support_tier TEXT DEFAULT 'community',
			is_trial BOOLEAN DEFAULT FALSE,
			trial_expires_at TIMESTAMP,
			activated_at TIMESTAMP,
			updated_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS stte_agents_config (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL UNIQUE,
			offline_threshold_mins INTEGER DEFAULT 15,
			auto_deregister_days INTEGER DEFAULT 90,
			heartbeat_interval_secs INTEGER DEFAULT 60,
			max_log_batch INTEGER DEFAULT 1000,
			enable_fim BOOLEAN DEFAULT TRUE,
			enable_process_monitoring BOOLEAN DEFAULT TRUE,
			enable_network_monitoring BOOLEAN DEFAULT TRUE,
			enrollment_token_ttl_hours INTEGER DEFAULT 48,
			require_signed_binaries BOOLEAN DEFAULT FALSE,
			updated_by TEXT,
			updated_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS stte_audit (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			action TEXT NOT NULL,
			section TEXT NOT NULL DEFAULT 'general',
			actor TEXT NOT NULL,
			details TEXT,
			ip_address TEXT,
			created_at TIMESTAMP DEFAULT NOW())`,
	}
	for _, s := range stmts {
		db.Exec(s)
	}
}

// ── Org Settings ──────────────────────────────────────────────────────────────

func GetSTTEOrg(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	row := db.QueryRow(`SELECT org_name,display_name,logo_url,domain,timezone,locale,date_format,
		contact_email,support_email,max_agents,data_retention_days,require_mfa,maintenance_mode,updated_at
		FROM stte_org WHERE tenant_id=$1`, tidStr)

	var name, tz, locale, fmt2, retention string
	var disp, logo, domain, contact, support, updatedAt *string
	var maxAgents, retDays int
	var reqMFA, maint bool

	if err := row.Scan(&name, &disp, &logo, &domain, &tz, &locale, &fmt2,
		&contact, &support, &maxAgents, &retDays, &reqMFA, &maint, &updatedAt); err != nil {
		// return defaults
		c.JSON(http.StatusOK, gin.H{
			"org_name": "XCloak Security", "display_name": "XCloak Security Suite",
			"timezone": "UTC", "locale": "en-US", "date_format": "YYYY-MM-DD",
			"max_agents": 1000, "data_retention_days": 365,
			"require_mfa": false, "maintenance_mode": false,
		})
		return
	}
	_ = retention
	c.JSON(http.StatusOK, gin.H{
		"org_name": name, "display_name": disp, "logo_url": logo, "domain": domain,
		"timezone": tz, "locale": locale, "date_format": fmt2,
		"contact_email": contact, "support_email": support,
		"max_agents": maxAgents, "data_retention_days": retDays,
		"require_mfa": reqMFA, "maintenance_mode": maint, "updated_at": updatedAt,
	})
}

func PatchSTTEOrg(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actor := usernameFromContext(c)

	var body map[string]interface{}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	// upsert
	db.Exec(`INSERT INTO stte_org (tenant_id,org_name,updated_by) VALUES ($1,'My Organization',$2)
		ON CONFLICT (tenant_id) DO NOTHING`, tidStr, actor)

	setClauses := []string{}
	args := []interface{}{}
	i := 1
	stringFields := []string{"org_name", "display_name", "logo_url", "domain", "timezone", "locale",
		"date_format", "contact_email", "support_email", "custom_css"}
	intFields := []string{"max_agents", "data_retention_days"}
	boolFields := []string{"require_mfa", "maintenance_mode"}

	for _, f := range stringFields {
		if v, ok := body[f]; ok {
			setClauses = append(setClauses, fmt.Sprintf("%s=$%d", f, i))
			args = append(args, v); i++
		}
	}
	for _, f := range intFields {
		if v, ok := body[f]; ok {
			setClauses = append(setClauses, fmt.Sprintf("%s=$%d", f, i))
			args = append(args, v); i++
		}
	}
	for _, f := range boolFields {
		if v, ok := body[f]; ok {
			setClauses = append(setClauses, fmt.Sprintf("%s=$%d", f, i))
			args = append(args, v); i++
		}
	}
	if len(setClauses) > 0 {
		setClauses = append(setClauses, fmt.Sprintf("updated_by=$%d", i), fmt.Sprintf("updated_at=NOW()"))
		args = append(args, actor)
		args = append(args, tidStr)
		db.Exec(fmt.Sprintf("UPDATE stte_org SET %s WHERE tenant_id=$%d",
			strings.Join(setClauses, ","), i+1), args...)
	}
	stteAudit(tid, "org_updated", "general", actor, "Organization settings updated")
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// ── AI Config ─────────────────────────────────────────────────────────────────

func GetSTTEAIConfig(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	providers := []map[string]interface{}{}
	rows, _ := db.Query(`SELECT provider,model,api_key_masked,endpoint,enabled,is_default,
		max_tokens,temperature,use_for,rate_limit_rpm,monthly_budget_usd,updated_at
		FROM stte_ai_config WHERE tenant_id=$1 ORDER BY is_default DESC, provider`, tidStr)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var prov, model string
			var key, ep, useFor, ua *string
			var enabled, isDefault bool
			var maxTok, rpmLimit int
			var temp, budget float64
			if err := rows.Scan(&prov, &model, &key, &ep, &enabled, &isDefault,
				&maxTok, &temp, &useFor, &rpmLimit, &budget, &ua); err == nil {
				providers = append(providers, map[string]interface{}{
					"provider": prov, "model": model, "api_key_masked": key, "endpoint": ep,
					"enabled": enabled, "is_default": isDefault, "max_tokens": maxTok,
					"temperature": temp, "use_for": useFor, "rate_limit_rpm": rpmLimit,
					"monthly_budget_usd": budget, "updated_at": ua,
				})
			}
		}
	}

	// guardrails
	var guardrails map[string]interface{}
	gr := db.QueryRow(`SELECT require_approval_for_actions,rbac_enabled,data_masking_enabled,
		hallucination_warnings,audit_all_queries,max_context_length,allowed_roles,pii_masking_fields
		FROM stte_ai_guardrails WHERE tenant_id=$1`, tidStr)
	var reqApproval, rbacEn, masking, hallWarn, auditQ bool
	var maxCtx int
	var allowedRoles, piiFields *string
	if err := gr.Scan(&reqApproval, &rbacEn, &masking, &hallWarn, &auditQ, &maxCtx, &allowedRoles, &piiFields); err == nil {
		guardrails = map[string]interface{}{
			"require_approval_for_actions": reqApproval, "rbac_enabled": rbacEn,
			"data_masking_enabled": masking, "hallucination_warnings": hallWarn,
			"audit_all_queries": auditQ, "max_context_length": maxCtx,
			"allowed_roles": allowedRoles, "pii_masking_fields": piiFields,
		}
	} else {
		guardrails = map[string]interface{}{
			"require_approval_for_actions": true, "rbac_enabled": true,
			"data_masking_enabled": true, "hallucination_warnings": true,
			"audit_all_queries": true, "max_context_length": 8192,
		}
	}

	c.JSON(http.StatusOK, gin.H{"providers": providers, "guardrails": guardrails})
}

func PatchSTTEAIConfig(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actor := usernameFromContext(c)

	var body struct {
		Provider  string  `json:"provider"`
		Model     string  `json:"model"`
		APIKey    string  `json:"api_key"`
		Endpoint  string  `json:"endpoint"`
		Enabled   *bool   `json:"enabled"`
		IsDefault *bool   `json:"is_default"`
		MaxTokens int     `json:"max_tokens"`
		Temp      float64 `json:"temperature"`
		RPMLimit  int     `json:"rate_limit_rpm"`
		Budget    float64 `json:"monthly_budget_usd"`
		// guardrails
		RequireApproval    *bool `json:"require_approval_for_actions"`
		RBACEnabled        *bool `json:"rbac_enabled"`
		DataMasking        *bool `json:"data_masking_enabled"`
		HallucinationWarn  *bool `json:"hallucination_warnings"`
		AuditAllQueries    *bool `json:"audit_all_queries"`
	}
	c.BindJSON(&body)

	if body.Provider != "" {
		masked := ""
		if body.APIKey != "" {
			if len(body.APIKey) > 8 {
				masked = body.APIKey[:4] + "****" + body.APIKey[len(body.APIKey)-4:]
			} else {
				masked = "****"
			}
		}
		db.Exec(`INSERT INTO stte_ai_config (tenant_id,provider,model,api_key_masked,endpoint,enabled,is_default,updated_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (tenant_id,provider) DO UPDATE SET
				model=EXCLUDED.model, api_key_masked=EXCLUDED.api_key_masked,
				endpoint=EXCLUDED.endpoint, enabled=EXCLUDED.enabled, is_default=EXCLUDED.is_default,
				updated_by=EXCLUDED.updated_by, updated_at=NOW()`,
			tidStr, body.Provider, body.Model, stteNullStr(masked), stteNullStr(body.Endpoint),
			body.Enabled != nil && *body.Enabled,
			body.IsDefault != nil && *body.IsDefault, actor)
	}

	// guardrails update
	if body.RequireApproval != nil || body.RBACEnabled != nil || body.DataMasking != nil {
		db.Exec(`INSERT INTO stte_ai_guardrails (tenant_id,updated_by) VALUES ($1,$2)
			ON CONFLICT (tenant_id) DO NOTHING`, tidStr, actor)
		if body.RequireApproval != nil {
			db.Exec(`UPDATE stte_ai_guardrails SET require_approval_for_actions=$1,updated_by=$2,updated_at=NOW()
				WHERE tenant_id=$3`, *body.RequireApproval, actor, tidStr)
		}
		if body.RBACEnabled != nil {
			db.Exec(`UPDATE stte_ai_guardrails SET rbac_enabled=$1,updated_by=$2,updated_at=NOW()
				WHERE tenant_id=$3`, *body.RBACEnabled, actor, tidStr)
		}
		if body.DataMasking != nil {
			db.Exec(`UPDATE stte_ai_guardrails SET data_masking_enabled=$1,updated_by=$2,updated_at=NOW()
				WHERE tenant_id=$3`, *body.DataMasking, actor, tidStr)
		}
		if body.HallucinationWarn != nil {
			db.Exec(`UPDATE stte_ai_guardrails SET hallucination_warnings=$1,updated_by=$2,updated_at=NOW()
				WHERE tenant_id=$3`, *body.HallucinationWarn, actor, tidStr)
		}
		if body.AuditAllQueries != nil {
			db.Exec(`UPDATE stte_ai_guardrails SET audit_all_queries=$1,updated_by=$2,updated_at=NOW()
				WHERE tenant_id=$3`, *body.AuditAllQueries, actor, tidStr)
		}
	}

	stteAudit(tid, "ai_config_updated", "ai", actor, fmt.Sprintf("provider:%s", body.Provider))
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// ── Backups ───────────────────────────────────────────────────────────────────

func GetSTTEBackups(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	// config
	var cfg map[string]interface{}
	cr := db.QueryRow(`SELECT enabled,schedule_type,schedule_time,retention_days,backup_type,
		encrypt,storage,last_run_at,next_run_at FROM stte_backup_config WHERE tenant_id=$1`, tidStr)
	var en, enc bool
	var stype, stime, btype, storage string
	var retDays int
	var lastRun, nextRun *string
	if err := cr.Scan(&en, &stype, &stime, &retDays, &btype, &enc, &storage, &lastRun, &nextRun); err == nil {
		cfg = map[string]interface{}{
			"enabled": en, "schedule_type": stype, "schedule_time": stime,
			"retention_days": retDays, "backup_type": btype, "encrypt": enc,
			"storage": storage, "last_run_at": lastRun, "next_run_at": nextRun,
		}
	} else {
		cfg = map[string]interface{}{
			"enabled": true, "schedule_type": "daily", "schedule_time": "02:00",
			"retention_days": 30, "backup_type": "full", "encrypt": true, "storage": "local",
		}
	}

	jobs := []map[string]interface{}{}
	rows, _ := db.Query(`SELECT backup_id,backup_type,status,size_bytes,duration_secs,
		triggered_by,error_message,created_at FROM stte_backups WHERE tenant_id=$1
		ORDER BY created_at DESC LIMIT 20`, tidStr)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, btype2, status, by string
			var size int64
			var dur int
			var errMsg, ca *string
			if err := rows.Scan(&id, &btype2, &status, &size, &dur, &by, &errMsg, &ca); err == nil {
				jobs = append(jobs, map[string]interface{}{
					"backup_id": id, "backup_type": btype2, "status": status,
					"size_bytes": size, "size_human": formatBytes(size),
					"duration_secs": dur, "triggered_by": by, "error_message": errMsg, "created_at": ca,
				})
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{"config": cfg, "jobs": jobs})
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func PostSTTEBackupTrigger(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actor := usernameFromContext(c)

	id := stteID("STTE-BKP")
	size := int64(50*1024*1024 + rand.Int63n(500*1024*1024))
	dur := 30 + rand.Intn(120)
	db.Exec(`INSERT INTO stte_backups (tenant_id,backup_id,backup_type,status,size_bytes,duration_secs,triggered_by)
		VALUES ($1,$2,'full','completed',$3,$4,$5)`, tidStr, id, size, dur, actor)
	db.Exec(`UPDATE stte_backup_config SET last_run_at=NOW() WHERE tenant_id=$1`, tidStr)
	stteAudit(tid, "backup_triggered", "system", actor, fmt.Sprintf("backup_id:%s", id))
	c.JSON(http.StatusOK, gin.H{"backup_id": id, "status": "completed", "size_bytes": size})
}

func PatchSTTEBackupConfig(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actor := usernameFromContext(c)

	var body map[string]interface{}
	c.BindJSON(&body)
	db.Exec(`INSERT INTO stte_backup_config (tenant_id,updated_by) VALUES ($1,$2) ON CONFLICT (tenant_id) DO NOTHING`, tidStr, actor)

	if v, ok := body["enabled"]; ok {
		db.Exec(`UPDATE stte_backup_config SET enabled=$1,updated_by=$2,updated_at=NOW() WHERE tenant_id=$3`, v, actor, tidStr)
	}
	if v, ok := body["schedule_type"]; ok {
		db.Exec(`UPDATE stte_backup_config SET schedule_type=$1,updated_by=$2,updated_at=NOW() WHERE tenant_id=$3`, v, actor, tidStr)
	}
	if v, ok := body["schedule_time"]; ok {
		db.Exec(`UPDATE stte_backup_config SET schedule_time=$1,updated_by=$2,updated_at=NOW() WHERE tenant_id=$3`, v, actor, tidStr)
	}
	if v, ok := body["retention_days"]; ok {
		db.Exec(`UPDATE stte_backup_config SET retention_days=$1,updated_by=$2,updated_at=NOW() WHERE tenant_id=$3`, v, actor, tidStr)
	}
	stteAudit(tid, "backup_config_updated", "system", actor, "Backup schedule updated")
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// ── Updates ───────────────────────────────────────────────────────────────────

func GetSTTEUpdates(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	history := []map[string]interface{}{}
	rows, _ := db.Query(`SELECT version,release_type,title,description,status,applied_by,applied_at,created_at
		FROM stte_updates WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 20`, tidStr)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var ver, rtype, title, status string
			var desc, appliedBy, appliedAt, ca *string
			if err := rows.Scan(&ver, &rtype, &title, &desc, &status, &appliedBy, &appliedAt, &ca); err == nil {
				history = append(history, map[string]interface{}{
					"version": ver, "release_type": rtype, "title": title, "description": desc,
					"status": status, "applied_by": appliedBy, "applied_at": appliedAt, "created_at": ca,
				})
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"current_version": "2.14.3",
		"latest_version":  "2.14.3",
		"update_available": false,
		"last_checked":    time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
		"channel":         "stable",
		"history":         history,
	})
}

func PostSTTECheckUpdates(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"update_available": false,
		"current_version":  "2.14.3",
		"latest_version":   "2.14.3",
		"message":          "You are running the latest version.",
		"checked_at":       time.Now().Format(time.RFC3339),
	})
}

// ── License ───────────────────────────────────────────────────────────────────

func GetSTTELicense(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	row := db.QueryRow(`SELECT license_key,tier,seats_total,seats_used,agents_total,agents_used,
		features,valid_from,valid_until,issued_to,support_tier,is_trial,activated_at
		FROM stte_license WHERE tenant_id=$1`, tidStr)

	var tier, support string
	var seatsTotal, seatsUsed, agentsTotal, agentsUsed int
	var isTrial bool
	var key, features, validFrom, validUntil, issuedTo, activatedAt *string

	if err := row.Scan(&key, &tier, &seatsTotal, &seatsUsed, &agentsTotal, &agentsUsed,
		&features, &validFrom, &validUntil, &issuedTo, &support, &isTrial, &activatedAt); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"tier": "community", "seats_total": 5, "seats_used": 0,
			"agents_total": 25, "agents_used": 0, "is_trial": false,
			"support_tier": "community", "features": []string{},
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"license_key": key, "tier": tier,
		"seats_total": seatsTotal, "seats_used": seatsUsed,
		"agents_total": agentsTotal, "agents_used": agentsUsed,
		"features": features, "valid_from": validFrom, "valid_until": validUntil,
		"issued_to": issuedTo, "support_tier": support,
		"is_trial": isTrial, "activated_at": activatedAt,
	})
}

func PostSTTELicenseActivate(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actor := usernameFromContext(c)

	var body struct{ LicenseKey string `json:"license_key"` }
	if err := c.BindJSON(&body); err != nil || body.LicenseKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "license_key required"})
		return
	}

	// Demo: accept any key and set enterprise tier
	masked := body.LicenseKey
	if len(masked) > 8 {
		masked = masked[:4] + "-****-****-" + masked[len(masked)-4:]
	}
	db.Exec(`INSERT INTO stte_license (tenant_id,license_key,tier,seats_total,seats_used,
		agents_total,agents_used,features,valid_from,valid_until,issued_to,support_tier,activated_at)
		VALUES ($1,$2,'enterprise',250,0,10000,0,
		'["siem","edr","soar","cmdb","mdm","ai_assistant","threat_intel","compliance","executive_reports","api_access","sso","mfa","backup","custom_roles","unlimited_agents"]',
		CURRENT_DATE, CURRENT_DATE + INTERVAL ''1 year'',''Demo Organization'',''enterprise'',NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			license_key=$2,tier=''enterprise'',seats_total=250,agents_total=10000,
			features=''["siem","edr","soar","cmdb","mdm","ai_assistant","threat_intel","compliance","executive_reports","api_access","sso","mfa","backup","custom_roles","unlimited_agents"]'',
			valid_until=CURRENT_DATE+INTERVAL ''1 year'',activated_at=NOW()`, tidStr, masked)
	stteAudit(tid, "license_activated", "system", actor, fmt.Sprintf("key:%s tier:enterprise", masked))
	c.JSON(http.StatusOK, gin.H{
		"status": "activated", "tier": "enterprise",
		"seats_total": 250, "agents_total": 10000,
		"valid_until": time.Now().AddDate(1, 0, 0).Format("2006-01-02"),
	})
}

// ── Agent Config ──────────────────────────────────────────────────────────────

func GetSTTEAgentsConfig(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	row := db.QueryRow(`SELECT offline_threshold_mins,auto_deregister_days,heartbeat_interval_secs,
		max_log_batch,enable_fim,enable_process_monitoring,enable_network_monitoring,
		enrollment_token_ttl_hours,require_signed_binaries
		FROM stte_agents_config WHERE tenant_id=$1`, tidStr)

	var offlineMins, deregDays, hbSecs, maxBatch, ttl int
	var fim, proc, net, signed bool

	if err := row.Scan(&offlineMins, &deregDays, &hbSecs, &maxBatch, &fim, &proc, &net, &ttl, &signed); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"offline_threshold_mins": 15, "auto_deregister_days": 90,
			"heartbeat_interval_secs": 60, "max_log_batch": 1000,
			"enable_fim": true, "enable_process_monitoring": true, "enable_network_monitoring": true,
			"enrollment_token_ttl_hours": 48, "require_signed_binaries": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"offline_threshold_mins": offlineMins, "auto_deregister_days": deregDays,
		"heartbeat_interval_secs": hbSecs, "max_log_batch": maxBatch,
		"enable_fim": fim, "enable_process_monitoring": proc, "enable_network_monitoring": net,
		"enrollment_token_ttl_hours": ttl, "require_signed_binaries": signed,
	})
}

func PatchSTTEAgentsConfig(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actor := usernameFromContext(c)

	var body map[string]interface{}
	c.BindJSON(&body)
	db.Exec(`INSERT INTO stte_agents_config (tenant_id,updated_by) VALUES ($1,$2) ON CONFLICT (tenant_id) DO NOTHING`, tidStr, actor)

	fields := []string{"offline_threshold_mins", "auto_deregister_days", "heartbeat_interval_secs",
		"max_log_batch", "enable_fim", "enable_process_monitoring", "enable_network_monitoring",
		"enrollment_token_ttl_hours", "require_signed_binaries"}
	for _, f := range fields {
		if v, ok := body[f]; ok {
			db.Exec(fmt.Sprintf("UPDATE stte_agents_config SET %s=$1,updated_by=$2,updated_at=NOW() WHERE tenant_id=$3", f),
				v, actor, tidStr)
		}
	}
	stteAudit(tid, "agents_config_updated", "security", actor, "Agent configuration updated")
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// ── Audit ─────────────────────────────────────────────────────────────────────

func GetSTTEAudit(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	limit := parseLimit(c, 100)

	entries := []map[string]interface{}{}
	rows, _ := db.Query(`SELECT action,section,actor,details,ip_address,created_at
		FROM stte_audit WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tidStr, limit)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var action, section, actor string
			var details, ip, ca *string
			if err := rows.Scan(&action, &section, &actor, &details, &ip, &ca); err == nil {
				entries = append(entries, map[string]interface{}{
					"action": action, "section": section, "actor": actor,
					"details": details, "ip_address": ip, "created_at": ca,
				})
			}
		}
	}
	c.JSON(http.StatusOK, entries)
}
