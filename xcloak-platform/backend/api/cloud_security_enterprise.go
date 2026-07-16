package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/services"

	"github.com/gin-gonic/gin"
)

func createCloudSecurityTables() {
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS cloud_accounts (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		provider TEXT NOT NULL,
		account_id TEXT,
		region TEXT DEFAULT 'us-east-1',
		status TEXT DEFAULT 'connected',
		asset_count INTEGER DEFAULT 0,
		finding_count INTEGER DEFAULT 0,
		risk_score INTEGER DEFAULT 0,
		last_scan TIMESTAMPTZ,
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS cloud_assets (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		account_id INTEGER REFERENCES cloud_accounts(id) ON DELETE SET NULL,
		name TEXT NOT NULL,
		resource_type TEXT NOT NULL,
		provider TEXT NOT NULL,
		region TEXT,
		owner TEXT,
		tags TEXT,
		risk_score INTEGER DEFAULT 0,
		internet_exposed BOOLEAN DEFAULT false,
		status TEXT DEFAULT 'active',
		last_activity TIMESTAMPTZ,
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS cloud_findings (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		asset_id INTEGER,
		category TEXT NOT NULL,
		title TEXT NOT NULL,
		description TEXT,
		severity TEXT DEFAULT 'medium',
		provider TEXT,
		region TEXT,
		resource_type TEXT,
		resource_id TEXT,
		remediation TEXT,
		status TEXT DEFAULT 'open',
		framework TEXT,
		control_id TEXT,
		created_at TIMESTAMPTZ DEFAULT NOW(),
		resolved_at TIMESTAMPTZ
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS cloud_threats (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		threat_type TEXT NOT NULL,
		provider TEXT,
		region TEXT,
		source_ip TEXT,
		source_user TEXT,
		resource_id TEXT,
		resource_type TEXT,
		severity TEXT DEFAULT 'high',
		details JSONB DEFAULT '{}',
		status TEXT DEFAULT 'open',
		mitre_technique TEXT,
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS cloud_drift_events (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		resource_id TEXT,
		resource_type TEXT,
		change_type TEXT NOT NULL,
		previous_state TEXT,
		new_state TEXT,
		changed_by TEXT,
		provider TEXT,
		region TEXT,
		severity TEXT DEFAULT 'medium',
		acknowledged BOOLEAN DEFAULT false,
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS cloud_identities (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		identity_type TEXT NOT NULL,
		provider TEXT NOT NULL,
		account_id TEXT,
		permissions TEXT,
		last_used TIMESTAMPTZ,
		is_dormant BOOLEAN DEFAULT false,
		mfa_enabled BOOLEAN DEFAULT false,
		access_key_age_days INTEGER DEFAULT 0,
		risk_level TEXT DEFAULT 'low',
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

func GetCloudDashboard(c *gin.Context) {
	createCloudSecurityTables()
	tid := tenantIDFromContext(c)

	var awsAccounts, azureSubs, gcpProjects int
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_accounts WHERE tenant_id=$1 AND provider='aws'`, tid).Scan(&awsAccounts)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_accounts WHERE tenant_id=$1 AND provider='azure'`, tid).Scan(&azureSubs)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_accounts WHERE tenant_id=$1 AND provider='gcp'`, tid).Scan(&gcpProjects)

	var totalAssets, publicAssets, criticalFindings, iamRisks, activeThreats int
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_assets WHERE tenant_id=$1`, tid).Scan(&totalAssets)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_assets WHERE tenant_id=$1 AND internet_exposed=true`, tid).Scan(&publicAssets)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_findings WHERE tenant_id=$1 AND severity='critical' AND status='open'`, tid).Scan(&criticalFindings)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_identities WHERE tenant_id=$1 AND risk_level IN ('high','critical')`, tid).Scan(&iamRisks)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_threats WHERE tenant_id=$1 AND status='open'`, tid).Scan(&activeThreats)

	var avgRisk float64
	database.DB.QueryRow(`SELECT COALESCE(AVG(risk_score),0) FROM cloud_accounts WHERE tenant_id=$1`, tid).Scan(&avgRisk)

	// Compliance score (% passing controls)
	var totalFindings, openFindings int
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_findings WHERE tenant_id=$1`, tid).Scan(&totalFindings)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_findings WHERE tenant_id=$1 AND status='open'`, tid).Scan(&openFindings)
	complianceScore := 100
	if totalFindings > 0 { complianceScore = 100 - int(float64(openFindings)/float64(totalFindings)*100) }

	// Inventory by provider
	type ProvCount struct {
		Provider string `json:"provider"`
		Count    int    `json:"count"`
	}
	inventory := []ProvCount{}
	invRows, _ := database.DB.Query(`SELECT provider, COUNT(*) FROM cloud_assets WHERE tenant_id=$1 GROUP BY provider`, tid)
	defer invRows.Close()
	for invRows.Next() {
		var pc ProvCount; invRows.Scan(&pc.Provider, &pc.Count); inventory = append(inventory, pc)
	}

	// Recent threats
	type RecentThreat struct {
		ID          int    `json:"id"`
		ThreatType  string `json:"threat_type"`
		Provider    string `json:"provider"`
		ResourceID  string `json:"resource_id"`
		Severity    string `json:"severity"`
		SourceIP    string `json:"source_ip"`
		CreatedAt   string `json:"created_at"`
	}
	recentThreats := []RecentThreat{}
	trows, _ := database.DB.Query(`SELECT id,threat_type,provider,resource_id,severity,source_ip,created_at FROM cloud_threats WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 8`, tid)
	defer trows.Close()
	for trows.Next() {
		var r RecentThreat; trows.Scan(&r.ID, &r.ThreatType, &r.Provider, &r.ResourceID, &r.Severity, &r.SourceIP, &r.CreatedAt)
		recentThreats = append(recentThreats, r)
	}

	c.JSON(http.StatusOK, gin.H{
		"aws_accounts":     awsAccounts,
		"azure_subs":       azureSubs,
		"gcp_projects":     gcpProjects,
		"total_assets":     totalAssets,
		"public_assets":    publicAssets,
		"critical_findings": criticalFindings,
		"iam_risks":        iamRisks,
		"active_threats":   activeThreats,
		"multi_cloud_risk": int(avgRisk),
		"compliance_score": complianceScore,
		"inventory":        inventory,
		"recent_threats":   recentThreats,
	})
}

// ── Accounts ──────────────────────────────────────────────────────────────────

func GetCloudAccounts(c *gin.Context) {
	createCloudSecurityTables()
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(`SELECT id,name,provider,account_id,region,status,asset_count,finding_count,risk_score,last_scan,created_at FROM cloud_accounts WHERE tenant_id=$1 ORDER BY provider,name`, tid)
	defer rows.Close()
	type Acct struct {
		ID           int     `json:"id"`
		Name         string  `json:"name"`
		Provider     string  `json:"provider"`
		AccountID    string  `json:"account_id"`
		Region       string  `json:"region"`
		Status       string  `json:"status"`
		AssetCount   int     `json:"asset_count"`
		FindingCount int     `json:"finding_count"`
		RiskScore    int     `json:"risk_score"`
		LastScan     *string `json:"last_scan"`
		CreatedAt    string  `json:"created_at"`
	}
	out := []Acct{}
	for rows.Next() {
		var a Acct; rows.Scan(&a.ID, &a.Name, &a.Provider, &a.AccountID, &a.Region, &a.Status, &a.AssetCount, &a.FindingCount, &a.RiskScore, &a.LastScan, &a.CreatedAt)
		out = append(out, a)
	}
	c.JSON(http.StatusOK, out)
}

func PostCloudAccount(c *gin.Context) {
	createCloudSecurityTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Name      string `json:"name"`
		Provider  string `json:"provider"`
		AccountID string `json:"account_id"`
		Region    string `json:"region"`
	}
	c.ShouldBindJSON(&body)
	var id int
	database.DB.QueryRow(`INSERT INTO cloud_accounts (tenant_id,name,provider,account_id,region) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		tid, body.Name, body.Provider, body.AccountID, body.Region).Scan(&id)
	c.JSON(http.StatusOK, gin.H{"id": id, "ok": true})
}

func DeleteCloudAccount(c *gin.Context) {
	tid := tenantIDFromContext(c)
	aid, _ := strconv.Atoi(c.Param("id"))
	database.DB.Exec(`DELETE FROM cloud_accounts WHERE tenant_id=$1 AND id=$2`, tid, aid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── Inventory ─────────────────────────────────────────────────────────────────

func GetCloudInventory(c *gin.Context) {
	createCloudSecurityTables()
	tid := tenantIDFromContext(c)
	provider := c.Query("provider")
	rtype := c.Query("resource_type")
	limit := parseLimit(c, 200)

	where := "WHERE tenant_id=$1"
	args := []interface{}{tid}
	n := 2
	if provider != "" { where += fmt.Sprintf(" AND provider=$%d", n); args = append(args, provider); n++ }
	if rtype != "" { where += fmt.Sprintf(" AND resource_type=$%d", n); args = append(args, rtype); n++ }

	rows, _ := database.DB.Query(fmt.Sprintf(`
		SELECT id,name,resource_type,provider,region,owner,tags,risk_score,internet_exposed,status,last_activity,created_at
		FROM cloud_assets %s ORDER BY risk_score DESC,internet_exposed DESC LIMIT $%d`, where, n),
		append(args, limit)...)
	defer rows.Close()

	type Asset struct {
		ID             int     `json:"id"`
		Name           string  `json:"name"`
		ResourceType   string  `json:"resource_type"`
		Provider       string  `json:"provider"`
		Region         string  `json:"region"`
		Owner          string  `json:"owner"`
		Tags           string  `json:"tags"`
		RiskScore      int     `json:"risk_score"`
		InternetExposed bool   `json:"internet_exposed"`
		Status         string  `json:"status"`
		LastActivity   *string `json:"last_activity"`
		CreatedAt      string  `json:"created_at"`
	}
	out := []Asset{}
	for rows.Next() {
		var a Asset
		rows.Scan(&a.ID, &a.Name, &a.ResourceType, &a.Provider, &a.Region, &a.Owner, &a.Tags, &a.RiskScore, &a.InternetExposed, &a.Status, &a.LastActivity, &a.CreatedAt)
		out = append(out, a)
	}
	c.JSON(http.StatusOK, out)
}

// ── CSPM ──────────────────────────────────────────────────────────────────────

func GetCSPMFindings(c *gin.Context) {
	createCloudSecurityTables()
	tid := tenantIDFromContext(c)
	category := c.Query("category")
	severity := c.Query("severity")
	provider := c.Query("provider")
	limit := parseLimit(c, 200)

	where := "WHERE tenant_id=$1 AND status='open'"
	args := []interface{}{tid}
	n := 2
	if category != "" { where += fmt.Sprintf(" AND category=$%d", n); args = append(args, category); n++ }
	if severity != "" { where += fmt.Sprintf(" AND severity=$%d", n); args = append(args, severity); n++ }
	if provider != "" { where += fmt.Sprintf(" AND provider=$%d", n); args = append(args, provider); n++ }

	rows, _ := database.DB.Query(fmt.Sprintf(`
		SELECT id,category,title,description,severity,provider,region,resource_type,resource_id,remediation,framework,control_id,created_at
		FROM cloud_findings %s ORDER BY
		CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END LIMIT $%d`, where, n),
		append(args, limit)...)
	defer rows.Close()

	type Finding struct {
		ID           int    `json:"id"`
		Category     string `json:"category"`
		Title        string `json:"title"`
		Description  string `json:"description"`
		Severity     string `json:"severity"`
		Provider     string `json:"provider"`
		Region       string `json:"region"`
		ResourceType string `json:"resource_type"`
		ResourceID   string `json:"resource_id"`
		Remediation  string `json:"remediation"`
		Framework    string `json:"framework"`
		ControlID    string `json:"control_id"`
		CreatedAt    string `json:"created_at"`
	}
	out := []Finding{}
	for rows.Next() {
		var f Finding
		rows.Scan(&f.ID, &f.Category, &f.Title, &f.Description, &f.Severity, &f.Provider, &f.Region, &f.ResourceType, &f.ResourceID, &f.Remediation, &f.Framework, &f.ControlID, &f.CreatedAt)
		out = append(out, f)
	}
	c.JSON(http.StatusOK, out)
}

func GetCSPMSummary(c *gin.Context) {
	createCloudSecurityTables()
	tid := tenantIDFromContext(c)

	type CatCount struct {
		Category string `json:"category"`
		Critical int    `json:"critical"`
		High     int    `json:"high"`
		Medium   int    `json:"medium"`
		Total    int    `json:"total"`
	}
	out := []CatCount{}
	rows, _ := database.DB.Query(`
		SELECT category,
		  COUNT(*) FILTER (WHERE severity='critical') critical,
		  COUNT(*) FILTER (WHERE severity='high') high,
		  COUNT(*) FILTER (WHERE severity='medium') medium,
		  COUNT(*) total
		FROM cloud_findings WHERE tenant_id=$1 AND status='open'
		GROUP BY category ORDER BY total DESC`, tid)
	defer rows.Close()
	for rows.Next() {
		var cc CatCount; rows.Scan(&cc.Category, &cc.Critical, &cc.High, &cc.Medium, &cc.Total)
		out = append(out, cc)
	}
	c.JSON(http.StatusOK, out)
}

func PatchCloudFinding(c *gin.Context) {
	tid := tenantIDFromContext(c)
	fid, _ := strconv.Atoi(c.Param("id"))
	var body struct { Status string `json:"status"` }
	c.ShouldBindJSON(&body)
	database.DB.Exec(`UPDATE cloud_findings SET status=$1 WHERE tenant_id=$2 AND id=$3`, body.Status, tid, fid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── CIEM ──────────────────────────────────────────────────────────────────────

func GetCIEMIdentities(c *gin.Context) {
	createCloudSecurityTables()
	tid := tenantIDFromContext(c)
	itype := c.Query("type")
	risk := c.Query("risk_level")
	limit := parseLimit(c, 100)

	where := "WHERE tenant_id=$1"
	args := []interface{}{tid}
	n := 2
	if itype != "" { where += fmt.Sprintf(" AND identity_type=$%d", n); args = append(args, itype); n++ }
	if risk != "" { where += fmt.Sprintf(" AND risk_level=$%d", n); args = append(args, risk); n++ }

	rows, _ := database.DB.Query(fmt.Sprintf(`
		SELECT id,name,identity_type,provider,account_id,permissions,last_used,is_dormant,mfa_enabled,access_key_age_days,risk_level,created_at
		FROM cloud_identities %s ORDER BY
		CASE risk_level WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END LIMIT $%d`, where, n),
		append(args, limit)...)
	defer rows.Close()

	type Identity struct {
		ID              int     `json:"id"`
		Name            string  `json:"name"`
		IdentityType    string  `json:"identity_type"`
		Provider        string  `json:"provider"`
		AccountID       string  `json:"account_id"`
		Permissions     string  `json:"permissions"`
		LastUsed        *string `json:"last_used"`
		IsDormant       bool    `json:"is_dormant"`
		MFAEnabled      bool    `json:"mfa_enabled"`
		AccessKeyAgeDays int    `json:"access_key_age_days"`
		RiskLevel       string  `json:"risk_level"`
		CreatedAt       string  `json:"created_at"`
	}
	out := []Identity{}
	for rows.Next() {
		var id Identity
		rows.Scan(&id.ID, &id.Name, &id.IdentityType, &id.Provider, &id.AccountID, &id.Permissions, &id.LastUsed, &id.IsDormant, &id.MFAEnabled, &id.AccessKeyAgeDays, &id.RiskLevel, &id.CreatedAt)
		out = append(out, id)
	}
	c.JSON(http.StatusOK, out)
}

func GetCIEMRisks(c *gin.Context) {
	createCloudSecurityTables()
	tid := tenantIDFromContext(c)

	var dormant, noMFA, oldKeys, excessive, privEsc int
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_identities WHERE tenant_id=$1 AND is_dormant=true`, tid).Scan(&dormant)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_identities WHERE tenant_id=$1 AND mfa_enabled=false AND identity_type='iam_user'`, tid).Scan(&noMFA)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_identities WHERE tenant_id=$1 AND access_key_age_days > 90`, tid).Scan(&oldKeys)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_identities WHERE tenant_id=$1 AND risk_level IN ('high','critical')`, tid).Scan(&excessive)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_identities WHERE tenant_id=$1 AND permissions LIKE '%AdministratorAccess%'`, tid).Scan(&privEsc)

	c.JSON(http.StatusOK, gin.H{
		"dormant_accounts":      dormant,
		"no_mfa":                noMFA,
		"old_access_keys":       oldKeys,
		"excessive_permissions": excessive,
		"privilege_escalation":  privEsc,
	})
}

// ── Cloud Threats (Detection) ─────────────────────────────────────────────────

func GetCloudThreats(c *gin.Context) {
	createCloudSecurityTables()
	tid := tenantIDFromContext(c)
	ttype := c.Query("threat_type")
	provider := c.Query("provider")
	limit := parseLimit(c, 200)

	where := "WHERE tenant_id=$1"
	args := []interface{}{tid}
	n := 2
	if ttype != "" { where += fmt.Sprintf(" AND threat_type=$%d", n); args = append(args, ttype); n++ }
	if provider != "" { where += fmt.Sprintf(" AND provider=$%d", n); args = append(args, provider); n++ }

	rows, _ := database.DB.Query(fmt.Sprintf(`
		SELECT id,threat_type,provider,region,source_ip,source_user,resource_id,resource_type,severity,mitre_technique,status,created_at
		FROM cloud_threats %s ORDER BY created_at DESC LIMIT $%d`, where, n),
		append(args, limit)...)
	defer rows.Close()

	type Threat struct {
		ID             int    `json:"id"`
		ThreatType     string `json:"threat_type"`
		Provider       string `json:"provider"`
		Region         string `json:"region"`
		SourceIP       string `json:"source_ip"`
		SourceUser     string `json:"source_user"`
		ResourceID     string `json:"resource_id"`
		ResourceType   string `json:"resource_type"`
		Severity       string `json:"severity"`
		MitreTechnique string `json:"mitre_technique"`
		Status         string `json:"status"`
		CreatedAt      string `json:"created_at"`
	}
	out := []Threat{}
	for rows.Next() {
		var t Threat
		rows.Scan(&t.ID, &t.ThreatType, &t.Provider, &t.Region, &t.SourceIP, &t.SourceUser, &t.ResourceID, &t.ResourceType, &t.Severity, &t.MitreTechnique, &t.Status, &t.CreatedAt)
		out = append(out, t)
	}
	c.JSON(http.StatusOK, out)
}

// ── Exposure ──────────────────────────────────────────────────────────────────

func GetCloudExposure(c *gin.Context) {
	createCloudSecurityTables()
	tid := tenantIDFromContext(c)

	var publicBuckets, openDBs, publicAPIs, weakSGs int
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_findings WHERE tenant_id=$1 AND category='public_storage' AND status='open'`, tid).Scan(&publicBuckets)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_findings WHERE tenant_id=$1 AND category='public_database' AND status='open'`, tid).Scan(&openDBs)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_findings WHERE tenant_id=$1 AND category='public_endpoint' AND status='open'`, tid).Scan(&publicAPIs)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_findings WHERE tenant_id=$1 AND category='open_security_group' AND status='open'`, tid).Scan(&weakSGs)

	exposedAssets := []map[string]interface{}{}
	rows, _ := database.DB.Query(`SELECT name,resource_type,provider,region,risk_score FROM cloud_assets WHERE tenant_id=$1 AND internet_exposed=true ORDER BY risk_score DESC LIMIT 20`, tid)
	defer rows.Close()
	for rows.Next() {
		var name, rtype, provider, region string; var risk int
		rows.Scan(&name, &rtype, &provider, &region, &risk)
		exposedAssets = append(exposedAssets, map[string]interface{}{"name": name, "resource_type": rtype, "provider": provider, "region": region, "risk_score": risk})
	}

	c.JSON(http.StatusOK, gin.H{
		"public_buckets":    publicBuckets,
		"open_databases":    openDBs,
		"public_apis":       publicAPIs,
		"weak_security_groups": weakSGs,
		"exposed_assets":    exposedAssets,
	})
}

// ── Compliance ────────────────────────────────────────────────────────────────

func GetCloudCompliance(c *gin.Context) {
	createCloudSecurityTables()
	tid := tenantIDFromContext(c)
	framework := c.Query("framework")

	where := "WHERE tenant_id=$1 AND framework != ''"
	args := []interface{}{tid}
	if framework != "" { where += " AND framework=$2"; args = append(args, framework) }

	type FW struct {
		Framework  string  `json:"framework"`
		Total      int     `json:"total"`
		Passed     int     `json:"passed"`
		Failed     int     `json:"failed"`
		Score      float64 `json:"score"`
	}
	out := []FW{}
	rows, _ := database.DB.Query(fmt.Sprintf(`
		SELECT framework,
		  COUNT(*) total,
		  COUNT(*) FILTER (WHERE status='resolved') passed,
		  COUNT(*) FILTER (WHERE status='open') failed
		FROM cloud_findings %s
		GROUP BY framework ORDER BY framework`, where), args...)
	defer rows.Close()
	for rows.Next() {
		var fw FW; rows.Scan(&fw.Framework, &fw.Total, &fw.Passed, &fw.Failed)
		if fw.Total > 0 { fw.Score = float64(fw.Passed) / float64(fw.Total) * 100 }
		out = append(out, fw)
	}
	c.JSON(http.StatusOK, out)
}

// ── Timeline ──────────────────────────────────────────────────────────────────

func GetCloudTimeline(c *gin.Context) {
	createCloudSecurityTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 200)

	// Combine threats + findings + drift into a unified timeline
	rows, _ := database.DB.Query(`
		SELECT 'threat' as event_type, threat_type as title, provider, region, severity, created_at FROM cloud_threats WHERE tenant_id=$1
		UNION ALL
		SELECT 'finding' as event_type, title, provider, region, severity, created_at FROM cloud_findings WHERE tenant_id=$1
		UNION ALL
		SELECT 'drift' as event_type, change_type, provider, region, severity, created_at FROM cloud_drift_events WHERE tenant_id=$1
		ORDER BY created_at DESC LIMIT $2`, tid, limit)
	defer rows.Close()

	type TLEvent struct {
		EventType string `json:"event_type"`
		Title     string `json:"title"`
		Provider  string `json:"provider"`
		Region    string `json:"region"`
		Severity  string `json:"severity"`
		CreatedAt string `json:"created_at"`
	}
	out := []TLEvent{}
	for rows.Next() {
		var e TLEvent; rows.Scan(&e.EventType, &e.Title, &e.Provider, &e.Region, &e.Severity, &e.CreatedAt)
		out = append(out, e)
	}
	c.JSON(http.StatusOK, out)
}

// ── Attack Paths ──────────────────────────────────────────────────────────────

func GetCloudAttackPaths(c *gin.Context) {
	createCloudSecurityTables()
	tid := tenantIDFromContext(c)

	// Build paths from internet-exposed assets to high-value targets
	nodes := []map[string]interface{}{}
	edges := []map[string]interface{}{}

	nodes = append(nodes, map[string]interface{}{"id": "internet", "label": "Internet", "type": "source", "icon": "globe"})

	exposedRows, _ := database.DB.Query(`SELECT id,name,resource_type,provider,risk_score FROM cloud_assets WHERE tenant_id=$1 AND internet_exposed=true LIMIT 5`, tid)
	defer exposedRows.Close()
	for exposedRows.Next() {
		var id int; var name, rtype, provider string; var risk int
		exposedRows.Scan(&id, &name, &rtype, &provider, &risk)
		nodeID := fmt.Sprintf("asset-%d", id)
		nodes = append(nodes, map[string]interface{}{"id": nodeID, "label": name, "type": rtype, "provider": provider, "risk": risk})
		edges = append(edges, map[string]interface{}{"source": "internet", "target": nodeID, "label": "direct access", "risk": "high"})

		// Link to IAM roles
		iamRows, _ := database.DB.Query(`SELECT id,name,permissions FROM cloud_identities WHERE tenant_id=$1 AND permissions LIKE '%AdministratorAccess%' LIMIT 2`, tid)
		for iamRows.Next() {
			var iid int; var iname, perms string
			iamRows.Scan(&iid, &iname, &perms)
			iamNodeID := fmt.Sprintf("iam-%d", iid)
			exists := false
			for _, n := range nodes { if n["id"] == iamNodeID { exists = true; break } }
			if !exists { nodes = append(nodes, map[string]interface{}{"id": iamNodeID, "label": iname, "type": "iam_role", "permissions": perms}) }
			edges = append(edges, map[string]interface{}{"source": nodeID, "target": iamNodeID, "label": "assumes role", "risk": "critical"})
		}
		iamRows.Close()
	}

	// Add high-value data targets
	dbRows, _ := database.DB.Query(`SELECT id,name,resource_type,provider FROM cloud_assets WHERE tenant_id=$1 AND resource_type IN ('rds','s3','storage_account','cloud_storage','bigquery') LIMIT 4`, tid)
	defer dbRows.Close()
	for dbRows.Next() {
		var id int; var name, rtype, provider string
		dbRows.Scan(&id, &name, &rtype, &provider)
		nodeID := fmt.Sprintf("data-%d", id)
		nodes = append(nodes, map[string]interface{}{"id": nodeID, "label": name, "type": rtype, "provider": provider, "sensitive": true})
		// Link from IAM roles to data
		for _, n := range nodes {
			if n["type"] == "iam_role" {
				edges = append(edges, map[string]interface{}{"source": n["id"], "target": nodeID, "label": "can access", "risk": "critical"})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"nodes": nodes, "edges": edges})
}

// ── Drift Detection ───────────────────────────────────────────────────────────

func GetCloudDrift(c *gin.Context) {
	createCloudSecurityTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)

	rows, _ := database.DB.Query(`SELECT id,resource_id,resource_type,change_type,previous_state,new_state,changed_by,provider,region,severity,acknowledged,created_at FROM cloud_drift_events WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tid, limit)
	defer rows.Close()

	type Drift struct {
		ID            int    `json:"id"`
		ResourceID    string `json:"resource_id"`
		ResourceType  string `json:"resource_type"`
		ChangeType    string `json:"change_type"`
		PreviousState string `json:"previous_state"`
		NewState      string `json:"new_state"`
		ChangedBy     string `json:"changed_by"`
		Provider      string `json:"provider"`
		Region        string `json:"region"`
		Severity      string `json:"severity"`
		Acknowledged  bool   `json:"acknowledged"`
		CreatedAt     string `json:"created_at"`
	}
	out := []Drift{}
	for rows.Next() {
		var d Drift; rows.Scan(&d.ID, &d.ResourceID, &d.ResourceType, &d.ChangeType, &d.PreviousState, &d.NewState, &d.ChangedBy, &d.Provider, &d.Region, &d.Severity, &d.Acknowledged, &d.CreatedAt)
		out = append(out, d)
	}
	c.JSON(http.StatusOK, out)
}

func PatchCloudDrift(c *gin.Context) {
	tid := tenantIDFromContext(c)
	did, _ := strconv.Atoi(c.Param("id"))
	database.DB.Exec(`UPDATE cloud_drift_events SET acknowledged=true WHERE tenant_id=$1 AND id=$2`, tid, did)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── Vulnerabilities ───────────────────────────────────────────────────────────

func GetCloudVulnerabilities(c *gin.Context) {
	createCloudSecurityTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)

	rows, _ := database.DB.Query(`SELECT id,category,title,description,severity,provider,region,resource_type,resource_id,framework,created_at FROM cloud_findings WHERE tenant_id=$1 AND category IN ('cve','missing_patch','container_vulnerability','package_vulnerability') ORDER BY created_at DESC LIMIT $2`, tid, limit)
	defer rows.Close()

	type Vuln struct {
		ID           int    `json:"id"`
		Category     string `json:"category"`
		Title        string `json:"title"`
		Description  string `json:"description"`
		Severity     string `json:"severity"`
		Provider     string `json:"provider"`
		Region       string `json:"region"`
		ResourceType string `json:"resource_type"`
		ResourceID   string `json:"resource_id"`
		Framework    string `json:"framework"`
		CreatedAt    string `json:"created_at"`
	}
	out := []Vuln{}
	for rows.Next() {
		var v Vuln; rows.Scan(&v.ID, &v.Category, &v.Title, &v.Description, &v.Severity, &v.Provider, &v.Region, &v.ResourceType, &v.ResourceID, &v.Framework, &v.CreatedAt)
		out = append(out, v)
	}
	c.JSON(http.StatusOK, out)
}

// ── Threat Intelligence ───────────────────────────────────────────────────────

func GetCloudThreatIntel(c *gin.Context) {
	createCloudSecurityTables()
	tid := tenantIDFromContext(c)

	// Top threat actor IPs hitting cloud
	topIPs := []map[string]interface{}{}
	ipRows, _ := database.DB.Query(`SELECT source_ip, COUNT(*) hits, STRING_AGG(DISTINCT threat_type,', ') types FROM cloud_threats WHERE tenant_id=$1 AND source_ip!='' GROUP BY source_ip ORDER BY hits DESC LIMIT 10`, tid)
	defer ipRows.Close()
	for ipRows.Next() {
		var ip, types string; var hits int
		ipRows.Scan(&ip, &hits, &types)
		topIPs = append(topIPs, map[string]interface{}{"ip": ip, "hits": hits, "threat_types": types})
	}

	// Threat type distribution
	byType := []map[string]interface{}{}
	typeRows, _ := database.DB.Query(`SELECT threat_type, COUNT(*), COUNT(*) FILTER (WHERE severity='critical') FROM cloud_threats WHERE tenant_id=$1 GROUP BY threat_type ORDER BY COUNT(*) DESC`, tid)
	defer typeRows.Close()
	for typeRows.Next() {
		var ttype string; var cnt, crit int
		typeRows.Scan(&ttype, &cnt, &crit)
		byType = append(byType, map[string]interface{}{"threat_type": ttype, "count": cnt, "critical": crit})
	}

	// Provider breakdown
	byProvider := []map[string]interface{}{}
	prvRows, _ := database.DB.Query(`SELECT provider, COUNT(*) FROM cloud_threats WHERE tenant_id=$1 GROUP BY provider ORDER BY COUNT(*) DESC`, tid)
	defer prvRows.Close()
	for prvRows.Next() {
		var prov string; var cnt int
		prvRows.Scan(&prov, &cnt)
		byProvider = append(byProvider, map[string]interface{}{"provider": prov, "count": cnt})
	}

	c.JSON(http.StatusOK, gin.H{
		"top_source_ips": topIPs,
		"by_threat_type": byType,
		"by_provider":    byProvider,
	})
}

// ── AI Security Assistant ─────────────────────────────────────────────────────

func PostCloudAI(c *gin.Context) {
	createCloudSecurityTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Question   string `json:"question"`
		Mode       string `json:"mode"`
		ResourceID string `json:"resource_id"`
		FindingID  int    `json:"finding_id"`
	}
	c.ShouldBindJSON(&body)

	var critFindings, publicAssets, iamRisks int
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_findings WHERE tenant_id=$1 AND severity='critical' AND status='open'`, tid).Scan(&critFindings)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_assets WHERE tenant_id=$1 AND internet_exposed=true`, tid).Scan(&publicAssets)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_identities WHERE tenant_id=$1 AND risk_level IN ('high','critical')`, tid).Scan(&iamRisks)

	var prompt string
	switch body.Mode {
	case "explain":
		prompt = fmt.Sprintf(`You are a cloud security expert. Explain this finding and its risk to a SOC analyst: "%s". Context: %d critical open findings, %d public assets, %d high-risk identities. Return JSON: {explanation, business_impact, likelihood, steps_to_reproduce (array), remediation_steps (array), mitre_technique, priority}`, body.Question, critFindings, publicAssets, iamRisks)
	case "remediate":
		prompt = fmt.Sprintf(`You are a cloud security expert. Provide detailed remediation for: "%s". Return JSON: {summary, cli_commands (array of {provider,command,description}), terraform_snippet, estimated_effort, risk_if_ignored, automated_fix_available}`, body.Question)
	case "prioritize":
		prompt = fmt.Sprintf(`Prioritize cloud security remediation given: %d critical findings, %d public assets, %d high-risk IAM identities. Return JSON: {top_priority (string), rationale, prioritized_actions (array of {action,severity,effort,impact}), quick_wins (array), strategic_fixes (array)}`, critFindings, publicAssets, iamRisks)
	default:
		prompt = fmt.Sprintf(`You are XCloak Cloud Security AI. Answer: "%s". Context: %d critical findings, %d public assets, %d IAM risks. Return JSON: {answer, confidence, related_resources (array), recommended_actions (array), additional_context}`, body.Question, critFindings, publicAssets, iamRisks)
	}

	raw, err := services.CallLLM(prompt)
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
	if idx := strings.Index(raw, "```json"); idx != -1 { raw = raw[idx+7:] } else if idx := strings.Index(raw, "```"); idx != -1 { raw = raw[idx+3:] }
	if idx := strings.LastIndex(raw, "```"); idx != -1 { raw = raw[:idx] }
	c.Data(http.StatusOK, "application/json", []byte(strings.TrimSpace(raw)))
}

// ── Analytics ─────────────────────────────────────────────────────────────────

func GetCloudAnalytics(c *gin.Context) {
	createCloudSecurityTables()
	tid := tenantIDFromContext(c)

	// Top exposed resources
	topExposed := []map[string]interface{}{}
	expRows, _ := database.DB.Query(`SELECT name,resource_type,provider,risk_score FROM cloud_assets WHERE tenant_id=$1 AND internet_exposed=true ORDER BY risk_score DESC LIMIT 10`, tid)
	defer expRows.Close()
	for expRows.Next() {
		var name, rtype, prov string; var risk int
		expRows.Scan(&name, &rtype, &prov, &risk)
		topExposed = append(topExposed, map[string]interface{}{"name": name, "resource_type": rtype, "provider": prov, "risk_score": risk})
	}

	// Top misconfigurations
	topMisconfig := []map[string]interface{}{}
	mcRows, _ := database.DB.Query(`SELECT category, COUNT(*) total, COUNT(*) FILTER (WHERE severity='critical') crit FROM cloud_findings WHERE tenant_id=$1 AND status='open' GROUP BY category ORDER BY total DESC LIMIT 10`, tid)
	defer mcRows.Close()
	for mcRows.Next() {
		var cat string; var total, crit int
		mcRows.Scan(&cat, &total, &crit)
		topMisconfig = append(topMisconfig, map[string]interface{}{"category": cat, "total": total, "critical": crit})
	}

	// Risk by region
	byRegion := []map[string]interface{}{}
	regRows, _ := database.DB.Query(`SELECT region, COUNT(*) assets, COALESCE(AVG(risk_score),0) avg_risk FROM cloud_assets WHERE tenant_id=$1 AND region!='' GROUP BY region ORDER BY avg_risk DESC LIMIT 10`, tid)
	defer regRows.Close()
	for regRows.Next() {
		var region string; var assets int; var avgRisk float64
		regRows.Scan(&region, &assets, &avgRisk)
		byRegion = append(byRegion, map[string]interface{}{"region": region, "assets": assets, "avg_risk": int(avgRisk)})
	}

	// Threat trend (14 days)
	threatTrend := []map[string]interface{}{}
	ttRows, _ := database.DB.Query(`SELECT DATE(created_at), COUNT(*) FROM cloud_threats WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL '14 days' GROUP BY DATE(created_at) ORDER BY 1`, tid)
	defer ttRows.Close()
	for ttRows.Next() {
		var d string; var cnt int; ttRows.Scan(&d, &cnt)
		threatTrend = append(threatTrend, map[string]interface{}{"date": d, "count": cnt})
	}

	// Compliance trend
	complianceTrend := []map[string]interface{}{}
	ctRows, _ := database.DB.Query(`SELECT DATE(created_at), COUNT(*) FROM cloud_findings WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL '30 days' GROUP BY DATE(created_at) ORDER BY 1`, tid)
	defer ctRows.Close()
	for ctRows.Next() {
		var d string; var cnt int; ctRows.Scan(&d, &cnt)
		complianceTrend = append(complianceTrend, map[string]interface{}{"date": d, "count": cnt})
	}

	c.JSON(http.StatusOK, gin.H{
		"top_exposed":       topExposed,
		"top_misconfigs":    topMisconfig,
		"by_region":         byRegion,
		"threat_trend":      threatTrend,
		"compliance_trend":  complianceTrend,
	})
}

// ── Response Actions ──────────────────────────────────────────────────────────

func PostCloudResponse(c *gin.Context) {
	createCloudSecurityTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Action     string `json:"action"`
		ResourceID string `json:"resource_id"`
		Provider   string `json:"provider"`
		FindingID  int    `json:"finding_id"`
		IdentityID int    `json:"identity_id"`
	}
	c.ShouldBindJSON(&body)
	username := usernameFromContext(c)

	message := fmt.Sprintf("Action '%s' on %s (%s) by %s", body.Action, body.ResourceID, body.Provider, username)

	switch body.Action {
	case "disable_iam_user":
		if body.IdentityID > 0 {
			database.DB.Exec(`UPDATE cloud_identities SET is_dormant=true WHERE tenant_id=$1 AND id=$2`, tid, body.IdentityID)
		}
	case "resolve_finding":
		if body.FindingID > 0 {
			database.DB.Exec(`UPDATE cloud_findings SET status='resolved',resolved_at=$1 WHERE tenant_id=$2 AND id=$3`, time.Now(), tid, body.FindingID)
		}
	case "make_bucket_private", "close_security_group", "rotate_access_key", "stop_instance", "isolate_workload":
		// Record drift/remediation event
		database.DB.Exec(`INSERT INTO cloud_drift_events (tenant_id,resource_id,resource_type,change_type,changed_by,provider,severity,acknowledged) VALUES ($1,$2,'cloud_resource',$3,$4,$5,'low',true)`,
			tid, body.ResourceID, body.Action, username, body.Provider)
		if body.FindingID > 0 {
			database.DB.Exec(`UPDATE cloud_findings SET status='resolved',resolved_at=$1 WHERE tenant_id=$2 AND id=$3`, time.Now(), tid, body.FindingID)
		}
	}

	database.DB.Exec(`INSERT INTO alerts (tenant_id,title,severity,status,description) VALUES ($1,$2,'low','closed',$3)`,
		tid, "Cloud Response: "+body.Action, message)

	c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "message": message})
}

// ── Report ────────────────────────────────────────────────────────────────────

func PostCloudReport(c *gin.Context) {
	createCloudSecurityTables()
	tid := tenantIDFromContext(c)
	var body struct { ReportType string `json:"report_type"` }
	c.ShouldBindJSON(&body)

	var totalAssets, critFindings, publicAssets, iamRisks, activeThreats int
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_assets WHERE tenant_id=$1`, tid).Scan(&totalAssets)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_findings WHERE tenant_id=$1 AND severity='critical' AND status='open'`, tid).Scan(&critFindings)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_assets WHERE tenant_id=$1 AND internet_exposed=true`, tid).Scan(&publicAssets)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_identities WHERE tenant_id=$1 AND risk_level IN ('high','critical')`, tid).Scan(&iamRisks)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cloud_threats WHERE tenant_id=$1 AND status='open'`, tid).Scan(&activeThreats)

	prompt := fmt.Sprintf(`Generate a %s cloud security report. Stats: %d total assets, %d critical findings, %d public assets, %d high-risk identities, %d active threats. Return JSON: {title, executive_summary, key_findings (array), risk_breakdown:{critical,high,medium,low}, top_recommendations (array of {priority,action,estimated_effort}), metrics:{total_assets,critical_findings,public_assets,iam_risks,active_threats}, compliance_summary}`,
		body.ReportType, totalAssets, critFindings, publicAssets, iamRisks, activeThreats)

	raw, err := services.CallLLM(prompt)
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
	if idx := strings.Index(raw, "```json"); idx != -1 { raw = raw[idx+7:] } else if idx := strings.Index(raw, "```"); idx != -1 { raw = raw[idx+3:] }
	if idx := strings.LastIndex(raw, "```"); idx != -1 { raw = raw[:idx] }
	c.Data(http.StatusOK, "application/json", []byte(strings.TrimSpace(raw)))
}
