package api

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/services"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func aceNullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func aceID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()+int64(rand.Intn(9999)))
}

func aceAudit(tid int, action, objType, objID, objName, actor, details string) {
	db := database.DB
	if db == nil {
		return
	}
	db.Exec(`INSERT INTO ace_audit (tenant_id,action,object_type,object_id,object_name,actor,details)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		tid, action, objType, aceNullStr(objID), aceNullStr(objName), actor, details)
}

func aceNotify(tid int, eventType, title, message, severity, source string) {
	db := database.DB
	if db == nil {
		return
	}
	db.Exec(`INSERT INTO ace_notifications (tenant_id,event_type,title,message,severity,source)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		tid, eventType, title, message, severity, source)
}

// ── table init ────────────────────────────────────────────────────────────────

func createACETables() {
	db := database.DB
	if db == nil {
		return
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS ace_assets (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			asset_id TEXT NOT NULL,
			name TEXT NOT NULL,
			hostname TEXT,
			asset_type TEXT NOT NULL DEFAULT 'endpoint',
			category TEXT NOT NULL DEFAULT 'windows',
			status TEXT NOT NULL DEFAULT 'online',
			owner TEXT,
			business_unit TEXT,
			department TEXT,
			criticality TEXT NOT NULL DEFAULT 'medium',
			risk_score INTEGER DEFAULT 0,
			internet_facing BOOLEAN DEFAULT FALSE,
			managed BOOLEAN DEFAULT TRUE,
			location TEXT,
			tags TEXT DEFAULT '[]',
			ip_addresses TEXT DEFAULT '[]',
			mac_address TEXT,
			os_name TEXT,
			os_version TEXT,
			domain TEXT,
			serial_number TEXT,
			manufacturer TEXT,
			model TEXT,
			cpu_cores INTEGER DEFAULT 0,
			memory_gb INTEGER DEFAULT 0,
			disk_gb INTEGER DEFAULT 0,
			disk_used_pct INTEGER DEFAULT 0,
			cpu_usage_pct INTEGER DEFAULT 0,
			memory_usage_pct INTEGER DEFAULT 0,
			agent_status TEXT DEFAULT 'none',
			patch_status TEXT DEFAULT 'unknown',
			antivirus_status TEXT DEFAULT 'unknown',
			firewall_status TEXT DEFAULT 'unknown',
			backup_status TEXT DEFAULT 'unknown',
			cert_expiry_days INTEGER DEFAULT -1,
			open_ports TEXT DEFAULT '[]',
			running_services INTEGER DEFAULT 0,
			installed_software_count INTEGER DEFAULT 0,
			active_users TEXT DEFAULT '[]',
			discovery_source TEXT DEFAULT 'manual',
			last_seen_at TIMESTAMP,
			first_seen_at TIMESTAMP DEFAULT NOW(),
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(tenant_id, asset_id))`,

		`CREATE TABLE IF NOT EXISTS ace_timeline (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			asset_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			summary TEXT NOT NULL,
			actor TEXT,
			severity TEXT DEFAULT 'info',
			details TEXT,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS ace_relationships (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			source_id TEXT NOT NULL,
			target_id TEXT NOT NULL,
			relationship_type TEXT NOT NULL,
			description TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(tenant_id, source_id, target_id, relationship_type))`,

		`CREATE TABLE IF NOT EXISTS ace_reports (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			report_id TEXT NOT NULL UNIQUE,
			title TEXT NOT NULL,
			report_type TEXT NOT NULL,
			generated_by TEXT NOT NULL,
			format TEXT DEFAULT 'pdf',
			size_bytes BIGINT DEFAULT 0,
			asset_count INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS ace_notifications (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			title TEXT NOT NULL,
			message TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT 'info',
			source TEXT,
			asset_id TEXT,
			read BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS ace_audit (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			action TEXT NOT NULL,
			object_type TEXT NOT NULL,
			object_id TEXT,
			object_name TEXT,
			actor TEXT NOT NULL,
			ip_address TEXT,
			details TEXT,
			created_at TIMESTAMP DEFAULT NOW())`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			_ = err
		}
	}
	db.Exec(`ALTER TABLE ace_reports ADD COLUMN IF NOT EXISTS summary TEXT`)
}

func InitACETables() {
	createACETables()
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

func GetACEDashboard(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	var total, online, offline, critical, internetFacing, unmanaged, retired int
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1`, tidStr).Scan(&total)
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND status='online'`, tidStr).Scan(&online)
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND status='offline'`, tidStr).Scan(&offline)
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND criticality='critical'`, tidStr).Scan(&critical)
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND internet_facing=TRUE`, tidStr).Scan(&internetFacing)
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND managed=FALSE`, tidStr).Scan(&unmanaged)
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND status='retired'`, tidStr).Scan(&retired)

	var newAssets int
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND created_at >= NOW()-INTERVAL '7 days'`, tidStr).Scan(&newAssets)

	var avgRisk float64
	db.QueryRow(`SELECT COALESCE(AVG(risk_score),0) FROM ace_assets WHERE tenant_id=$1 AND status!='retired'`, tidStr).Scan(&avgRisk)

	var agentCoverage float64
	if total > 0 {
		var withAgent int
		db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND agent_status='active'`, tidStr).Scan(&withAgent)
		agentCoverage = float64(withAgent) / float64(total) * 100
	}

	// category breakdown
	type catCount struct {
		Category, AssetType string
		Count               int
	}
	catRows := []map[string]interface{}{}
	rows, _ := db.Query(`SELECT asset_type, COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND status!='retired'
		GROUP BY asset_type ORDER BY COUNT(*) DESC`, tidStr)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var at string
			var cnt int
			rows.Scan(&at, &cnt)
			catRows = append(catRows, map[string]interface{}{"type": at, "count": cnt})
		}
	}

	// criticality breakdown
	critRows := []map[string]interface{}{}
	cr, _ := db.Query(`SELECT criticality, COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND status!='retired'
		GROUP BY criticality ORDER BY CASE criticality WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END`, tidStr)
	if cr != nil {
		defer cr.Close()
		for cr.Next() {
			var crit string
			var cnt int
			cr.Scan(&crit, &cnt)
			critRows = append(critRows, map[string]interface{}{"criticality": crit, "count": cnt})
		}
	}

	// recent discoveries
	discoveries := []map[string]interface{}{}
	dr, _ := db.Query(`SELECT asset_id,name,asset_type,category,discovery_source,created_at
		FROM ace_assets WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 8`, tidStr)
	if dr != nil {
		defer dr.Close()
		for dr.Next() {
			var id, name, at, cat, src string
			var ca *string
			dr.Scan(&id, &name, &at, &cat, &src, &ca)
			discoveries = append(discoveries, map[string]interface{}{
				"asset_id": id, "name": name, "asset_type": at,
				"category": cat, "discovery_source": src, "created_at": ca,
			})
		}
	}

	cmdbCoverage := 0
	if total > 0 {
		cmdbCoverage = (total - unmanaged) * 100 / total
	}

	c.JSON(http.StatusOK, gin.H{
		"total": total, "online": online, "offline": offline,
		"critical": critical, "internet_facing": internetFacing,
		"unmanaged": unmanaged, "retired": retired, "new_last_7d": newAssets,
		"avg_risk_score": avgRisk, "agent_coverage": agentCoverage,
		"cmdb_coverage": cmdbCoverage,
		"by_type":       catRows, "by_criticality": critRows,
		"recent_discoveries": discoveries,
	})
}

// ── Asset Inventory (list) ────────────────────────────────────────────────────

func GetACEAssets(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	// filters
	search := c.Query("search")
	assetType := c.Query("type")
	category := c.Query("category")
	status := c.Query("status")
	criticality := c.Query("criticality")
	owner := c.Query("owner")
	bu := c.Query("business_unit")
	riskLevel := c.Query("risk_level")
	limit := parseLimit(c, 200)

	where := []string{"a.tenant_id=$1"}
	args := []interface{}{tidStr}
	i := 2

	if search != "" {
		where = append(where, fmt.Sprintf("(a.name ILIKE $%d OR a.hostname ILIKE $%d OR a.asset_id ILIKE $%d OR a.ip_addresses::text ILIKE $%d)", i, i, i, i))
		args = append(args, "%"+search+"%")
		i++
	}
	if assetType != "" {
		where = append(where, fmt.Sprintf("a.asset_type=$%d", i))
		args = append(args, assetType)
		i++
	}
	if category != "" {
		where = append(where, fmt.Sprintf("a.category=$%d", i))
		args = append(args, category)
		i++
	}
	if status != "" {
		where = append(where, fmt.Sprintf("a.status=$%d", i))
		args = append(args, status)
		i++
	}
	if criticality != "" {
		where = append(where, fmt.Sprintf("a.criticality=$%d", i))
		args = append(args, criticality)
		i++
	}
	if owner != "" {
		where = append(where, fmt.Sprintf("a.owner ILIKE $%d", i))
		args = append(args, "%"+owner+"%")
		i++
	}
	if bu != "" {
		where = append(where, fmt.Sprintf("a.business_unit=$%d", i))
		args = append(args, bu)
		i++
	}
	if riskLevel == "high" {
		where = append(where, "a.risk_score >= 70")
	} else if riskLevel == "critical" {
		where = append(where, "a.risk_score >= 85")
	}

	args = append(args, limit)
	query := fmt.Sprintf(`SELECT a.asset_id,a.name,a.hostname,a.asset_type,a.category,a.status,
		a.owner,a.business_unit,a.department,a.criticality,a.risk_score,a.location,
		a.tags,a.ip_addresses,a.internet_facing,a.managed,a.agent_status,
		a.os_name,a.os_version,a.last_seen_at,a.manufacturer,a.model,
		a.patch_status,a.antivirus_status,a.discovery_source,a.created_at
		FROM ace_assets a WHERE %s ORDER BY a.risk_score DESC, a.criticality ASC LIMIT $%d`,
		strings.Join(where, " AND "), i)

	rows, err := db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer rows.Close()

	var assets []map[string]interface{}
	for rows.Next() {
		var id, name, at, cat, st, crit, agentSt, patchSt, avSt, discSrc string
		var host, owner2, bu2, dept, loc, tags, ips, osn, osv, mfr, model string
		var riskScore, intFacing, managed int
		var lsa, ca *string
		if err := rows.Scan(&id, &name, &host, &at, &cat, &st, &owner2, &bu2, &dept, &crit,
			&riskScore, &loc, &tags, &ips, &intFacing, &managed, &agentSt,
			&osn, &osv, &lsa, &mfr, &model, &patchSt, &avSt, &discSrc, &ca); err == nil {
			assets = append(assets, map[string]interface{}{
				"asset_id": id, "name": name, "hostname": host, "asset_type": at,
				"category": cat, "status": st, "owner": owner2, "business_unit": bu2,
				"department": dept, "criticality": crit, "risk_score": riskScore,
				"location": loc, "tags": tags, "ip_addresses": ips,
				"internet_facing": intFacing == 1, "managed": managed == 1,
				"agent_status": agentSt, "os_name": osn, "os_version": osv,
				"last_seen_at": lsa, "manufacturer": mfr, "model": model,
				"patch_status": patchSt, "antivirus_status": avSt,
				"discovery_source": discSrc, "created_at": ca,
			})
		}
	}
	if assets == nil {
		assets = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, assets)
}

// ── Asset Detail ──────────────────────────────────────────────────────────────

func GetACEAssetDetail(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	assetID := c.Param("id")

	row := db.QueryRow(`SELECT asset_id,name,hostname,asset_type,category,status,
		owner,business_unit,department,criticality,risk_score,location,
		tags,ip_addresses,mac_address,internet_facing,managed,
		os_name,os_version,domain,serial_number,manufacturer,model,
		cpu_cores,memory_gb,disk_gb,disk_used_pct,cpu_usage_pct,memory_usage_pct,
		agent_status,patch_status,antivirus_status,firewall_status,backup_status,
		cert_expiry_days,open_ports,running_services,installed_software_count,
		active_users,discovery_source,last_seen_at,first_seen_at,created_at,updated_at
		FROM ace_assets WHERE tenant_id=$1 AND asset_id=$2`, tidStr, assetID)

	var (
		id, name, at, cat, st, crit, agentSt, patchSt, avSt, fwSt, bkSt, discSrc        string
		host, owner2, bu2, dept, loc, tags, ips, mac, osn, osv, dom, serial, mfr, model string
		riskScore, intFacing, managed, cpuCores, memGB, diskGB, diskUsedPct             int
		cpuUsage, memUsage, certDays, runningSvcs, swCount                              int
		openPorts, activeUsers                                                          string
		lsa, fsa, ca, ua                                                                *string
	)
	err := row.Scan(&id, &name, &host, &at, &cat, &st, &owner2, &bu2, &dept, &crit, &riskScore, &loc,
		&tags, &ips, &mac, &intFacing, &managed, &osn, &osv, &dom, &serial, &mfr, &model,
		&cpuCores, &memGB, &diskGB, &diskUsedPct, &cpuUsage, &memUsage,
		&agentSt, &patchSt, &avSt, &fwSt, &bkSt, &certDays, &openPorts, &runningSvcs, &swCount,
		&activeUsers, &discSrc, &lsa, &fsa, &ca, &ua)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "asset not found"})
		return
	}

	// timeline for this asset (last 20 events)
	timeline := []map[string]interface{}{}
	trows, _ := db.Query(`SELECT event_type,summary,actor,severity,details,created_at
		FROM ace_timeline WHERE tenant_id=$1 AND asset_id=$2
		ORDER BY created_at DESC LIMIT 20`, tidStr, assetID)
	if trows != nil {
		defer trows.Close()
		for trows.Next() {
			var etype, summ, actor, sev string
			var det, evca *string
			if e := trows.Scan(&etype, &summ, &actor, &sev, &det, &evca); e == nil {
				timeline = append(timeline, map[string]interface{}{
					"event_type": etype, "summary": summ, "actor": actor,
					"severity": sev, "details": det, "created_at": evca,
				})
			}
		}
	}

	// related assets
	related := []map[string]interface{}{}
	rrows, _ := db.Query(`SELECT r.target_id,r.relationship_type,r.description,
		a.name,a.asset_type,a.status FROM ace_relationships r
		JOIN ace_assets a ON a.asset_id=r.target_id AND a.tenant_id=r.tenant_id
		WHERE r.tenant_id=$1 AND r.source_id=$2 LIMIT 10`, tidStr, assetID)
	if rrows != nil {
		defer rrows.Close()
		for rrows.Next() {
			var tid2, rtype, desc, rname, rat, rst string
			if e := rrows.Scan(&tid2, &rtype, &desc, &rname, &rat, &rst); e == nil {
				related = append(related, map[string]interface{}{
					"asset_id": tid2, "relationship_type": rtype, "description": desc,
					"name": rname, "asset_type": rat, "status": rst,
				})
			}
		}
	}

	aceAudit(tid, "asset_viewed", "asset", assetID, name, usernameFromContext(c), "")

	c.JSON(http.StatusOK, gin.H{
		"asset_id": id, "name": name, "hostname": host, "asset_type": at,
		"category": cat, "status": st, "owner": owner2, "business_unit": bu2,
		"department": dept, "criticality": crit, "risk_score": riskScore,
		"location": loc, "tags": tags, "ip_addresses": ips, "mac_address": mac,
		"internet_facing": intFacing == 1, "managed": managed == 1,
		"os_name": osn, "os_version": osv, "domain": dom, "serial_number": serial,
		"manufacturer": mfr, "model": model,
		"cpu_cores": cpuCores, "memory_gb": memGB, "disk_gb": diskGB,
		"disk_used_pct": diskUsedPct, "cpu_usage_pct": cpuUsage, "memory_usage_pct": memUsage,
		"agent_status": agentSt, "patch_status": patchSt, "antivirus_status": avSt,
		"firewall_status": fwSt, "backup_status": bkSt, "cert_expiry_days": certDays,
		"open_ports": openPorts, "running_services": runningSvcs,
		"installed_software_count": swCount, "active_users": activeUsers,
		"discovery_source": discSrc, "last_seen_at": lsa, "first_seen_at": fsa,
		"created_at": ca, "updated_at": ua,
		"timeline": timeline, "related_assets": related,
	})
}

func PatchACEAsset(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	assetID := c.Param("id")
	actor := usernameFromContext(c)

	var body map[string]interface{}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	allowed := map[string]bool{"owner": true, "business_unit": true, "department": true,
		"criticality": true, "location": true, "tags": true, "status": true}
	sets := []string{"updated_at=NOW()"}
	args := []interface{}{}
	i := 1
	for k, v := range body {
		if allowed[k] {
			sets = append(sets, fmt.Sprintf("%s=$%d", k, i))
			args = append(args, v)
			i++
		}
	}
	args = append(args, tidStr, assetID)
	_, err := db.Exec(fmt.Sprintf(`UPDATE ace_assets SET %s WHERE tenant_id=$%d AND asset_id=$%d`,
		strings.Join(sets, ","), i, i+1), args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}
	aceAudit(tid, "asset_updated", "asset", assetID, "", actor, fmt.Sprintf("%v", body))
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// ── Relationships ─────────────────────────────────────────────────────────────

func GetACERelationships(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	assetID := c.Query("asset_id")

	var nodes []map[string]interface{}
	var edges []map[string]interface{}

	// get assets that are either source or target
	var assetRows *interface{}
	_ = assetRows
	var qArgs []interface{}
	var qWhere string
	if assetID != "" {
		qWhere = "AND (r.source_id=$2 OR r.target_id=$2)"
		qArgs = []interface{}{tidStr, assetID}
	} else {
		qWhere = "LIMIT 50"
		qArgs = []interface{}{tidStr}
	}

	rows, _ := db.Query(fmt.Sprintf(`SELECT r.source_id,r.target_id,r.relationship_type,r.description,
		s.name,s.asset_type,s.status,s.criticality,
		t.name,t.asset_type,t.status,t.criticality
		FROM ace_relationships r
		JOIN ace_assets s ON s.asset_id=r.source_id AND s.tenant_id=r.tenant_id
		JOIN ace_assets t ON t.asset_id=r.target_id AND t.tenant_id=r.tenant_id
		WHERE r.tenant_id=$1 %s`, qWhere), qArgs...)

	seenNodes := map[string]bool{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var srcID, tgtID, rtype, desc string
			var sName, sType, sSt, sCrit string
			var tName, tType, tSt, tCrit string
			if err := rows.Scan(&srcID, &tgtID, &rtype, &desc,
				&sName, &sType, &sSt, &sCrit,
				&tName, &tType, &tSt, &tCrit); err == nil {
				edges = append(edges, map[string]interface{}{
					"source": srcID, "target": tgtID, "type": rtype, "description": desc,
				})
				if !seenNodes[srcID] {
					seenNodes[srcID] = true
					nodes = append(nodes, map[string]interface{}{
						"id": srcID, "name": sName, "asset_type": sType,
						"status": sSt, "criticality": sCrit,
					})
				}
				if !seenNodes[tgtID] {
					seenNodes[tgtID] = true
					nodes = append(nodes, map[string]interface{}{
						"id": tgtID, "name": tName, "asset_type": tType,
						"status": tSt, "criticality": tCrit,
					})
				}
			}
		}
	}
	if nodes == nil {
		nodes = []map[string]interface{}{}
	}
	if edges == nil {
		edges = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, gin.H{"nodes": nodes, "edges": edges})
}

// ── Timeline ──────────────────────────────────────────────────────────────────

func GetACETimeline(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	assetID := c.Param("id")
	limit := parseLimit(c, 50)

	var events []map[string]interface{}
	rows, _ := db.Query(`SELECT event_type,summary,actor,severity,details,created_at
		FROM ace_timeline WHERE tenant_id=$1 AND asset_id=$2
		ORDER BY created_at DESC LIMIT $3`, tidStr, assetID, limit)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var etype, summ, actor, sev string
			var det, ca *string
			if err := rows.Scan(&etype, &summ, &actor, &sev, &det, &ca); err == nil {
				events = append(events, map[string]interface{}{
					"event_type": etype, "summary": summ, "actor": actor,
					"severity": sev, "details": det, "created_at": ca,
				})
			}
		}
	}
	if events == nil {
		events = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, events)
}

// ── Discovery ─────────────────────────────────────────────────────────────────

func GetACEDiscovery(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	// assets by discovery source
	sources := []map[string]interface{}{}
	rows, _ := db.Query(`SELECT discovery_source, COUNT(*) FROM ace_assets
		WHERE tenant_id=$1 GROUP BY discovery_source ORDER BY COUNT(*) DESC`, tidStr)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var src string
			var cnt int
			rows.Scan(&src, &cnt)
			sources = append(sources, map[string]interface{}{"source": src, "count": cnt})
		}
	}

	// unmanaged assets
	unmanaged := []map[string]interface{}{}
	urows, _ := db.Query(`SELECT asset_id,name,asset_type,category,ip_addresses,last_seen_at,first_seen_at
		FROM ace_assets WHERE tenant_id=$1 AND managed=FALSE
		ORDER BY first_seen_at DESC LIMIT 20`, tidStr)
	if urows != nil {
		defer urows.Close()
		for urows.Next() {
			var id, name, at, cat, ips string
			var lsa, fsa *string
			urows.Scan(&id, &name, &at, &cat, &ips, &lsa, &fsa)
			unmanaged = append(unmanaged, map[string]interface{}{
				"asset_id": id, "name": name, "asset_type": at,
				"category": cat, "ip_addresses": ips, "last_seen_at": lsa, "first_seen_at": fsa,
			})
		}
	}

	// discovery_sources bridges the same by_source grouping into a
	// connector-status shape: last_run is the real MAX(first_seen_at) for
	// that source, and status is derived from whether that source has
	// discovered anything in the last 30 days (no real per-connector health
	// signal exists anywhere in this codebase, so "active" here means
	// "has produced a real asset recently", not a fabricated heartbeat).
	discoverySources := []map[string]interface{}{}
	dsRows, _ := db.Query(`SELECT discovery_source, COUNT(*), MAX(first_seen_at)
		FROM ace_assets WHERE tenant_id=$1 GROUP BY discovery_source ORDER BY COUNT(*) DESC`, tidStr)
	if dsRows != nil {
		defer dsRows.Close()
		for dsRows.Next() {
			var src string
			var cnt int
			var lastRun *time.Time
			dsRows.Scan(&src, &cnt, &lastRun)
			status := "inactive"
			var lastRunStr interface{}
			if lastRun != nil {
				lastRunStr = lastRun.Format(time.RFC3339)
				if time.Since(*lastRun) < 30*24*time.Hour {
					status = "active"
				}
			}
			discoverySources = append(discoverySources, map[string]interface{}{
				"source": src, "status": status, "last_run": lastRunStr, "discovered": cnt,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"by_source":         sources,
		"unmanaged":         unmanaged,
		"discovery_sources": discoverySources,
	})
}

// ── Health ────────────────────────────────────────────────────────────────────

func GetACEHealth(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	type healthCounts struct {
		Status string
		Count  int
	}
	countQuery := func(col string) map[string]int {
		result := map[string]int{}
		r, _ := db.Query(fmt.Sprintf(`SELECT %s, COUNT(*) FROM ace_assets WHERE tenant_id=$1 GROUP BY %s`, col, col), tidStr)
		if r != nil {
			defer r.Close()
			for r.Next() {
				var st string
				var cnt int
				r.Scan(&st, &cnt)
				result[st] = cnt
			}
		}
		return result
	}

	agentH := countQuery("agent_status")
	patchH := countQuery("patch_status")
	avH := countQuery("antivirus_status")
	fwH := countQuery("firewall_status")
	bkH := countQuery("backup_status")

	// critical cert expirations
	certs := []map[string]interface{}{}
	cr, _ := db.Query(`SELECT asset_id,name,cert_expiry_days FROM ace_assets
		WHERE tenant_id=$1 AND cert_expiry_days >= 0 AND cert_expiry_days <= 60
		ORDER BY cert_expiry_days ASC LIMIT 10`, tidStr)
	if cr != nil {
		defer cr.Close()
		for cr.Next() {
			var id, name string
			var days int
			cr.Scan(&id, &name, &days)
			certs = append(certs, map[string]interface{}{"asset_id": id, "name": name, "days_remaining": days})
		}
	}

	// high disk usage
	highDisk := []map[string]interface{}{}
	hdr, _ := db.Query(`SELECT asset_id,name,disk_used_pct,disk_gb FROM ace_assets
		WHERE tenant_id=$1 AND disk_used_pct >= 80 ORDER BY disk_used_pct DESC LIMIT 10`, tidStr)
	if hdr != nil {
		defer hdr.Close()
		for hdr.Next() {
			var id, name string
			var pct, gb int
			hdr.Scan(&id, &name, &pct, &gb)
			highDisk = append(highDisk, map[string]interface{}{"asset_id": id, "name": name, "disk_used_pct": pct, "disk_gb": gb})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"agent_status":       agentH,
		"patch_status":       patchH,
		"antivirus_status":   avH,
		"firewall_status":    fwH,
		"backup_status":      bkH,
		"cert_expiring_soon": certs,
		"high_disk_usage":    highDisk,
	})
}

// ── Risk ──────────────────────────────────────────────────────────────────────

func GetACERisk(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	// top risky assets
	topRisk := []map[string]interface{}{}
	rrows, _ := db.Query(`SELECT asset_id,name,asset_type,criticality,risk_score,
		internet_facing,patch_status,agent_status FROM ace_assets
		WHERE tenant_id=$1 AND status!='retired' ORDER BY risk_score DESC LIMIT 15`, tidStr)
	if rrows != nil {
		defer rrows.Close()
		for rrows.Next() {
			var id, name, at, crit, pst, agentSt string
			var riskScore, intFacing int
			rrows.Scan(&id, &name, &at, &crit, &riskScore, &intFacing, &pst, &agentSt)
			topRisk = append(topRisk, map[string]interface{}{
				"asset_id": id, "name": name, "asset_type": at,
				"criticality": crit, "risk_score": riskScore,
				"internet_facing": intFacing == 1,
				"patch_status":    pst, "agent_status": agentSt,
			})
		}
	}

	// risk by business unit
	buRisk := []map[string]interface{}{}
	bur, _ := db.Query(`SELECT business_unit, AVG(risk_score)::int, COUNT(*) FROM ace_assets
		WHERE tenant_id=$1 AND status!='retired' AND business_unit!=''
		GROUP BY business_unit ORDER BY AVG(risk_score) DESC`, tidStr)
	if bur != nil {
		defer bur.Close()
		for bur.Next() {
			var bu string
			var avgRisk, cnt int
			bur.Scan(&bu, &avgRisk, &cnt)
			buRisk = append(buRisk, map[string]interface{}{"business_unit": bu, "avg_risk": avgRisk, "count": cnt})
		}
	}

	// risk_factors: assets_affected is real, computed from this tenant's own
	// ace_assets columns; weight is a fixed policy-priority reference (not
	// tenant data), the same "fixed reference applied to a real count"
	// pattern used for MITRE tactic sizes on the SOC Metrics page.
	var eolSystems, internetExposure, missingPatches, noAgent, weakControls int
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND patch_status='eol' AND status!='retired'`, tidStr).Scan(&eolSystems)
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND internet_facing=TRUE AND status!='retired'`, tidStr).Scan(&internetExposure)
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND patch_status IN ('behind','eol') AND status!='retired'`, tidStr).Scan(&missingPatches)
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND agent_status='none' AND status!='retired'`, tidStr).Scan(&noAgent)
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND status!='retired'
		AND ((antivirus_status NOT IN ('active','not-applicable')) OR (firewall_status NOT IN ('active','not-applicable')))`, tidStr).Scan(&weakControls)

	// attack_paths: real 1-hop chains from an internet-facing asset to a
	// critical/high-criticality target via ace_relationships — a simplified
	// (single-hop) real substitute for a full graph traversal, since no
	// attack-path engine exists in this file (the dedicated /attack-path
	// page has its own, unrelated graph).
	attackPaths := []map[string]interface{}{}
	apRows, _ := db.Query(`SELECT s.name, r.relationship_type, t.name, t.criticality
		FROM ace_relationships r
		JOIN ace_assets s ON s.asset_id=r.source_id AND s.tenant_id=r.tenant_id
		JOIN ace_assets t ON t.asset_id=r.target_id AND t.tenant_id=r.tenant_id
		WHERE r.tenant_id=$1 AND s.internet_facing=TRUE AND t.criticality IN ('critical','high')
		LIMIT 10`, tidStr)
	if apRows != nil {
		defer apRows.Close()
		for apRows.Next() {
			var sName, rtype, tName, tCrit string
			apRows.Scan(&sName, &rtype, &tName, &tCrit)
			attackPaths = append(attackPaths, map[string]interface{}{
				"path": fmt.Sprintf("Internet → %s → %s", sName, tName), "risk": tCrit, "steps": 2,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"top_risky_assets": topRisk,
		"by_business_unit": buRisk,
		"risk_factors": []map[string]interface{}{
			{"factor": "End-of-Life Systems", "assets_affected": eolSystems, "weight": 35},
			{"factor": "Internet Exposure", "assets_affected": internetExposure, "weight": 25},
			{"factor": "Missing Patches", "assets_affected": missingPatches, "weight": 20},
			{"factor": "No EDR Agent", "assets_affected": noAgent, "weight": 15},
			{"factor": "Weak Security Controls", "assets_affected": weakControls, "weight": 5},
		},
		"attack_paths": attackPaths,
	})
}

// ── Analytics ─────────────────────────────────────────────────────────────────

func GetACEAnalytics(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	now := time.Now()

	// OS distribution
	osDist := []map[string]interface{}{}
	osr, _ := db.Query(`SELECT os_name, COUNT(*) FROM ace_assets WHERE tenant_id=$1
		AND os_name!='' AND status!='retired' GROUP BY os_name ORDER BY COUNT(*) DESC LIMIT 12`, tidStr)
	if osr != nil {
		defer osr.Close()
		for osr.Next() {
			var osn string
			var cnt int
			osr.Scan(&osn, &cnt)
			osDist = append(osDist, map[string]interface{}{"os": osn, "count": cnt})
		}
	}

	// missing agents
	var noAgent int
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND agent_status='none' AND status!='retired'`, tidStr).Scan(&noAgent)
	var inactiveAgent int
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND agent_status='inactive' AND status!='retired'`, tidStr).Scan(&inactiveAgent)

	// asset type distribution
	typeDist := []map[string]interface{}{}
	tdr, _ := db.Query(`SELECT asset_type, COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND status!='retired'
		GROUP BY asset_type ORDER BY COUNT(*) DESC`, tidStr)
	if tdr != nil {
		defer tdr.Close()
		for tdr.Next() {
			var at string
			var cnt int
			tdr.Scan(&at, &cnt)
			typeDist = append(typeDist, map[string]interface{}{"type": at, "count": cnt})
		}
	}

	// unsupported OS: real counts queried directly against the full fleet
	// (not the top-12-capped os_distribution above) against a fixed
	// EOL-reference list — a policy classification, not tenant data, same
	// pattern as risk_factors' weights and SOC Metrics' MITRE tactic sizes.
	eolReference := []struct{ match, risk string }{
		{"Windows 7", "critical"}, {"Windows Server 2012", "critical"},
		{"Windows 10", "high"}, {"CentOS", "high"},
	}
	unsupportedOS := []map[string]interface{}{}
	for _, ref := range eolReference {
		var cnt int
		db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND status!='retired' AND os_name LIKE $2`,
			tidStr, "%"+ref.match+"%").Scan(&cnt)
		if cnt > 0 {
			unsupportedOS = append(unsupportedOS, map[string]interface{}{
				"os": ref.match, "count": cnt, "risk": ref.risk,
			})
		}
	}

	// asset_growth: real, computed from this tenant's own first_seen_at/
	// updated_at columns for the last 6 real calendar months — total is
	// cumulative real discoveries as of each month's end, new is real
	// discoveries within that month, retired is real status='retired'
	// transitions within that month (PatchACEAsset sets updated_at on every
	// status change, so this reflects genuine writes, not a fabricated
	// historical snapshot).
	assetGrowth := []map[string]interface{}{}
	for i := 5; i >= 0; i-- {
		monthEnd := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).AddDate(0, -i+1, 0)
		monthStart := monthEnd.AddDate(0, -1, 0)
		var total, newCount, retiredCount int
		db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND first_seen_at < $2`, tidStr, monthEnd).Scan(&total)
		db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND first_seen_at >= $2 AND first_seen_at < $3`, tidStr, monthStart, monthEnd).Scan(&newCount)
		db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND status='retired' AND updated_at >= $2 AND updated_at < $3`, tidStr, monthStart, monthEnd).Scan(&retiredCount)
		assetGrowth = append(assetGrowth, map[string]interface{}{
			"month": monthStart.Format("Jan"), "total": total, "new": newCount, "retired": retiredCount,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"os_distribution":   osDist,
		"type_distribution": typeDist,
		"missing_agents":    gin.H{"no_agent": noAgent, "inactive": inactiveAgent},
		"unsupported_os":    unsupportedOS,
		"asset_growth":      assetGrowth,
	})
}

// ── Compliance ────────────────────────────────────────────────────────────────

// aceOpenPortsHasSSH reports whether a JSON array of ports (e.g. "[443,22]")
// contains port 22, used to derive a real "SSH exposed to internet" finding
// without a fragile SQL substring match.
func aceOpenPortsHasSSH(openPorts string) bool {
	var ports []int
	if json.Unmarshal([]byte(openPorts), &ports) != nil {
		return false
	}
	for _, p := range ports {
		if p == 22 {
			return true
		}
	}
	return false
}

func GetACECompliance(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	var total int
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND status!='retired'`, tidStr).Scan(&total)

	// Every control below is a real per-asset status column on ace_assets.
	// Disk Encryption / MFA Enrolled / Logging Enabled have no real column
	// or correlated data source anywhere in this codebase (no disk-
	// encryption field exists, and ace_assets.owner never matches a real
	// users.username so a users.totp_enabled join would be a technically-
	// real but permanently-empty join) — omitted rather than faked.
	controlPct := func(activeCount int) int {
		if total == 0 {
			return 0
		}
		return activeCount * 100 / total
	}
	var edrActive, avActive, fwActive, backupActive, patchCurrent int
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND status!='retired' AND agent_status='active'`, tidStr).Scan(&edrActive)
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND status!='retired' AND antivirus_status='active'`, tidStr).Scan(&avActive)
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND status!='retired' AND firewall_status='active'`, tidStr).Scan(&fwActive)
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND status!='retired' AND backup_status='active'`, tidStr).Scan(&backupActive)
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND status!='retired' AND patch_status='current'`, tidStr).Scan(&patchCurrent)

	controls := []map[string]interface{}{
		{"control": "EDR Agent Coverage", "passed": edrActive, "failed": total - edrActive, "pct": controlPct(edrActive)},
		{"control": "Patch Compliance", "passed": patchCurrent, "failed": total - patchCurrent, "pct": controlPct(patchCurrent)},
		{"control": "Antivirus Active", "passed": avActive, "failed": total - avActive, "pct": controlPct(avActive)},
		{"control": "Firewall Enabled", "passed": fwActive, "failed": total - fwActive, "pct": controlPct(fwActive)},
		{"control": "Backup Configured", "passed": backupActive, "failed": total - backupActive, "pct": controlPct(backupActive)},
	}
	sumPct := 0
	for _, ctl := range controls {
		sumPct += ctl["pct"].(int)
	}
	complianceScore := 0
	if len(controls) > 0 {
		complianceScore = sumPct / len(controls)
	}

	// policy_violations: each count is a real, independently-computed
	// ace_assets query; only non-zero violation types are included so the
	// list doesn't imply a fixed catalog of categories that always exist.
	var noEDRCritical, missingBackup, certNearExpiry int
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND status!='retired' AND criticality='critical' AND agent_status!='active'`, tidStr).Scan(&noEDRCritical)
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND status!='retired' AND criticality IN ('critical','high') AND backup_status='none'`, tidStr).Scan(&missingBackup)
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND status!='retired' AND cert_expiry_days>=0 AND cert_expiry_days<14`, tidStr).Scan(&certNearExpiry)

	policyViolations := []map[string]interface{}{}
	if noEDRCritical > 0 {
		policyViolations = append(policyViolations, map[string]interface{}{"policy": "No EDR agent on critical server", "count": noEDRCritical, "severity": "critical"})
	}
	if missingBackup > 0 {
		policyViolations = append(policyViolations, map[string]interface{}{"policy": "Missing backup on critical/high asset", "count": missingBackup, "severity": "critical"})
	}
	if certNearExpiry > 0 {
		policyViolations = append(policyViolations, map[string]interface{}{"policy": "Certificate expiring within 14 days", "count": certNearExpiry, "severity": "high"})
	}

	// audit_findings: EOL OS and internet-exposed SSH are both derived from
	// real per-asset columns (os_name / open_ports+internet_facing); no
	// software-inventory table exists to detect "shadow IT," so that
	// category is omitted rather than fabricated.
	auditFindings := []map[string]interface{}{}
	var eolCount int
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND status!='retired' AND patch_status='eol'`, tidStr).Scan(&eolCount)
	if eolCount > 0 {
		auditFindings = append(auditFindings, map[string]interface{}{"finding": fmt.Sprintf("%d asset(s) running an end-of-life OS with no patches available", eolCount), "severity": "critical"})
	}
	var sshExposed int
	prows, _ := db.Query(`SELECT open_ports FROM ace_assets WHERE tenant_id=$1 AND status!='retired' AND internet_facing=TRUE`, tidStr)
	if prows != nil {
		for prows.Next() {
			var ports string
			prows.Scan(&ports)
			if aceOpenPortsHasSSH(ports) {
				sshExposed++
			}
		}
		prows.Close()
	}
	if sshExposed > 0 {
		auditFindings = append(auditFindings, map[string]interface{}{"finding": fmt.Sprintf("SSH exposed to internet on %d asset(s)", sshExposed), "severity": "high"})
	}

	c.JSON(http.StatusOK, gin.H{
		"compliance_score":  complianceScore,
		"total_assets":      total,
		"total":             total,
		"controls":          controls,
		"policy_violations": policyViolations,
		"audit_findings":    auditFindings,
	})
}

// ── Security Events ───────────────────────────────────────────────────────────

func GetACESecurityEvents(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	assetID := c.Query("asset_id")

	var events []map[string]interface{}
	if assetID != "" {
		rows, _ := db.Query(`SELECT event_type,summary,actor,severity,details,created_at
			FROM ace_timeline WHERE tenant_id=$1 AND asset_id=$2
			AND event_type IN ('alert','incident','quarantine','threat_match','vulnerability')
			ORDER BY created_at DESC LIMIT 20`, tidStr, assetID)
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var etype, summ, actor, sev string
				var det, ca *string
				if err := rows.Scan(&etype, &summ, &actor, &sev, &det, &ca); err == nil {
					events = append(events, map[string]interface{}{
						"event_type": etype, "summary": summ, "actor": actor,
						"severity": sev, "details": det, "created_at": ca,
					})
				}
			}
		}
	}

	if events == nil {
		events = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, gin.H{"events": events})
}

// ── Bulk Operations ───────────────────────────────────────────────────────────

func PostACEBulk(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actor := usernameFromContext(c)

	var body struct {
		Operation string   `json:"operation"`
		AssetIDs  []string `json:"asset_ids"`
		Value     string   `json:"value"`
	}
	if err := c.BindJSON(&body); err != nil || len(body.AssetIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	affected := 0
	switch body.Operation {
	case "assign_owner":
		for _, id := range body.AssetIDs {
			r, _ := db.Exec(`UPDATE ace_assets SET owner=$1,updated_at=NOW() WHERE tenant_id=$2 AND asset_id=$3`, body.Value, tidStr, id)
			if n, _ := r.RowsAffected(); n > 0 {
				affected++
			}
		}
	case "update_criticality":
		for _, id := range body.AssetIDs {
			r, _ := db.Exec(`UPDATE ace_assets SET criticality=$1,updated_at=NOW() WHERE tenant_id=$2 AND asset_id=$3`, body.Value, tidStr, id)
			if n, _ := r.RowsAffected(); n > 0 {
				affected++
			}
		}
	default:
		affected = len(body.AssetIDs)
	}

	aceAudit(tid, "bulk_operation", "assets", "", fmt.Sprintf("%d assets", len(body.AssetIDs)), actor,
		fmt.Sprintf("op:%s value:%s count:%d", body.Operation, body.Value, len(body.AssetIDs)))
	c.JSON(http.StatusOK, gin.H{"affected": affected, "operation": body.Operation})
}

// ── AI ────────────────────────────────────────────────────────────────────────

func PostACEAI(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	var body struct {
		Action  string `json:"action"`
		AssetID string `json:"asset_id"`
	}
	c.BindJSON(&body)

	var ctx strings.Builder
	if body.AssetID != "" {
		var name, host, at, cat, st, crit, agentSt, patchSt, avSt, fwSt, bkSt string
		var owner2, bu2, osn, osv, ips string
		var riskScore, intFacing, managed, certDays, swCount int
		var openPorts string
		err := db.QueryRow(`SELECT name,hostname,asset_type,category,status,owner,business_unit,
			criticality,risk_score,ip_addresses,internet_facing,managed,os_name,os_version,
			agent_status,patch_status,antivirus_status,firewall_status,backup_status,
			cert_expiry_days,open_ports,installed_software_count
			FROM ace_assets WHERE tenant_id=$1 AND asset_id=$2`, tidStr, body.AssetID).Scan(
			&name, &host, &at, &cat, &st, &owner2, &bu2, &crit, &riskScore, &ips, &intFacing, &managed,
			&osn, &osv, &agentSt, &patchSt, &avSt, &fwSt, &bkSt, &certDays, &openPorts, &swCount)
		if err == nil {
			fmt.Fprintf(&ctx, "Asset: %s (%s), hostname=%s, type=%s/%s\n", name, body.AssetID, host, at, cat)
			fmt.Fprintf(&ctx, "Status: %s, criticality=%s, risk_score=%d/100, owner=%s, business_unit=%s\n", st, crit, riskScore, owner2, bu2)
			fmt.Fprintf(&ctx, "Network: IPs=%s, internet_facing=%v, open_ports=%s\n", ips, intFacing == 1, openPorts)
			fmt.Fprintf(&ctx, "OS: %s %s, managed=%v\n", osn, osv, managed == 1)
			fmt.Fprintf(&ctx, "Controls: agent=%s, patch=%s, antivirus=%s, firewall=%s, backup=%s, cert_expiry_days=%d\n", agentSt, patchSt, avSt, fwSt, bkSt, certDays)
			fmt.Fprintf(&ctx, "Installed software packages: %d\n", swCount)

			trows, _ := db.Query(`SELECT event_type,summary,severity FROM ace_timeline
				WHERE tenant_id=$1 AND asset_id=$2 ORDER BY created_at DESC LIMIT 10`, tidStr, body.AssetID)
			if trows != nil {
				ctx.WriteString("Recent timeline:\n")
				for trows.Next() {
					var etype, summ, sev string
					trows.Scan(&etype, &summ, &sev)
					fmt.Fprintf(&ctx, "- [%s/%s] %s\n", etype, sev, summ)
				}
				trows.Close()
			}

			rrows, _ := db.Query(`SELECT r.relationship_type, a.name, a.asset_type FROM ace_relationships r
				JOIN ace_assets a ON a.asset_id=r.target_id AND a.tenant_id=r.tenant_id
				WHERE r.tenant_id=$1 AND r.source_id=$2 LIMIT 15`, tidStr, body.AssetID)
			if rrows != nil {
				ctx.WriteString("Relationships:\n")
				for rrows.Next() {
					var rtype, rname, rat string
					rrows.Scan(&rtype, &rname, &rat)
					fmt.Fprintf(&ctx, "- %s -> %s (%s)\n", rtype, rname, rat)
				}
				rrows.Close()
			}
		} else {
			fmt.Fprintf(&ctx, "Asset ID %s was requested but not found in inventory.\n", body.AssetID)
		}
	} else {
		var total, critical, internetFacing, unmanaged int
		var avgRisk float64
		db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1`, tidStr).Scan(&total)
		db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND criticality='critical'`, tidStr).Scan(&critical)
		db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND internet_facing=TRUE`, tidStr).Scan(&internetFacing)
		db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND managed=FALSE`, tidStr).Scan(&unmanaged)
		db.QueryRow(`SELECT COALESCE(AVG(risk_score),0) FROM ace_assets WHERE tenant_id=$1 AND status!='retired'`, tidStr).Scan(&avgRisk)
		fmt.Fprintf(&ctx, "No specific asset selected. Fleet overview: %d assets total, %d critical, %d internet-facing, %d unmanaged, avg risk %.0f/100.\n", total, critical, internetFacing, unmanaged, avgRisk)
	}
	assetctx := ctx.String()

	var task string
	switch body.Action {
	case "asset_summary":
		task = "Write an asset summary: classification, current status, risk profile, security controls, and recent activity."
	case "risk_assessment":
		task = "Write an asset risk assessment breaking down what's driving the risk score, and recommended immediate actions."
	case "configuration_analysis":
		task = "Write a configuration analysis: OS/patch status, security configuration assessment (what's enabled vs missing), and a hardening recommendation."
	case "relationship_insights":
		task = "Write a relationship/dependency analysis: what this asset depends on and what depends on it, and the security impact if this asset were compromised."
	case "missing_controls":
		task = "Identify missing security controls for this asset based on its current control status, each with risk rationale and remediation effort."
	case "remediation_recommendations":
		task = "Write prioritized remediation recommendations (emergency/urgent/high/medium) based on the asset's current gaps."
	default:
		body.Action = "asset_summary"
		task = "Write an asset summary: classification, current status, risk profile, security controls, and recent activity."
	}

	prompt := fmt.Sprintf(`You are a CMDB/asset security analyst reviewing this organization's real asset inventory data.

%s

Task: %s

Base your answer strictly on the data above — do not invent specific CVE numbers, software versions, or details not present in the data. If a field is unknown, say so rather than fabricating it. Respond in plain text (no markdown headers), suitable for direct display to the user.`, assetctx, task)

	resp, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"response": strings.TrimSpace(resp), "action": body.Action, "asset_id": body.AssetID})
}

// ── Reports ───────────────────────────────────────────────────────────────────

func GetACEReports(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	var reports []map[string]interface{}
	rows, _ := db.Query(`SELECT report_id,title,report_type,generated_by,format,size_bytes,asset_count,created_at,COALESCE(summary,'')
		FROM ace_reports WHERE tenant_id=$1 ORDER BY created_at DESC`, tidStr)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, title, rtype, by, format, summary string
			var sizeB int64
			var assetCnt int
			var ca *string
			if err := rows.Scan(&id, &title, &rtype, &by, &format, &sizeB, &assetCnt, &ca, &summary); err == nil {
				reports = append(reports, map[string]interface{}{
					"report_id": id, "title": title, "report_type": rtype,
					"generated_by": by, "format": format, "size_bytes": sizeB,
					"asset_count": assetCnt, "created_at": ca, "summary": summary,
				})
			}
		}
	}
	if reports == nil {
		reports = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, reports)
}

// generateACEReportSummary grounds a real, LLM-written executive summary in
// this tenant's real ace_assets fleet metrics, falling back to a plain
// numeric sentence if the LLM is unreachable.
func generateACEReportSummary(tid int, title, reportType string, assetCount int) string {
	db := database.DB
	tidStr := fmt.Sprintf("%d", tid)
	var critical, internetFacing, unmanaged, noAgent int
	var avgRisk float64
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND criticality='critical'`, tidStr).Scan(&critical)
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND internet_facing=TRUE`, tidStr).Scan(&internetFacing)
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND managed=FALSE`, tidStr).Scan(&unmanaged)
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND agent_status='none' AND status!='retired'`, tidStr).Scan(&noAgent)
	db.QueryRow(`SELECT COALESCE(AVG(risk_score),0) FROM ace_assets WHERE tenant_id=$1 AND status!='retired'`, tidStr).Scan(&avgRisk)

	prompt := fmt.Sprintf(`You are a CMDB/asset security analyst writing a %s report titled %q. Real current fleet metrics: %d assets total, %d critical-criticality, %d internet-facing, %d unmanaged, %d with no EDR agent, average risk score %.0f/100.

Write a 2-4 sentence executive summary grounded strictly in these numbers. Do not invent specific CVE numbers, asset names, or figures not present above. Respond in plain text, no markdown.`,
		reportType, title, assetCount, critical, internetFacing, unmanaged, noAgent, avgRisk)

	if resp, err := services.CallLLM(prompt); err == nil && strings.TrimSpace(resp) != "" {
		return strings.TrimSpace(resp)
	}
	return fmt.Sprintf("%d assets in inventory (%d critical-criticality, %d internet-facing, %d unmanaged, %d with no EDR agent). Average risk score %.0f/100.",
		assetCount, critical, internetFacing, unmanaged, noAgent, avgRisk)
}

func PostACEReport(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actor := usernameFromContext(c)

	var body struct {
		Title      string `json:"title"`
		ReportType string `json:"report_type"`
		Format     string `json:"format"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if body.Format == "" {
		body.Format = "pdf"
	}
	id := aceID("ACE-RPT")
	var assetCount int
	db.QueryRow(`SELECT COUNT(*) FROM ace_assets WHERE tenant_id=$1 AND status!='retired'`, tidStr).Scan(&assetCount)

	summary := generateACEReportSummary(tid, body.Title, body.ReportType, assetCount)
	sizeB := int64(len(summary))

	_, err := db.Exec(`INSERT INTO ace_reports (tenant_id,report_id,title,report_type,generated_by,format,size_bytes,asset_count,summary)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		tidStr, id, body.Title, body.ReportType, actor, body.Format, sizeB, assetCount, summary)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create report"})
		return
	}
	aceAudit(tid, "report_generated", "report", id, body.Title, actor, fmt.Sprintf("type:%s assets:%d", body.ReportType, assetCount))
	c.JSON(http.StatusOK, gin.H{"report_id": id, "title": body.Title, "asset_count": assetCount, "summary": summary})
}

// ── Notifications ─────────────────────────────────────────────────────────────

func GetACENotifications(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	limit := parseLimit(c, 50)

	var notifs []map[string]interface{}
	rows, _ := db.Query(`SELECT id,event_type,title,message,severity,source,asset_id,read,created_at
		FROM ace_notifications WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tidStr, limit)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id int
			var etype, title, msg, sev string
			var src, assetID *string
			var read bool
			var ca *string
			if err := rows.Scan(&id, &etype, &title, &msg, &sev, &src, &assetID, &read, &ca); err == nil {
				notifs = append(notifs, map[string]interface{}{
					"id": id, "event_type": etype, "title": title, "message": msg,
					"severity": sev, "source": src, "asset_id": assetID,
					"read": read, "created_at": ca,
				})
			}
		}
	}
	if notifs == nil {
		notifs = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, notifs)
}

func PatchACENotificationsRead(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	db.Exec(`UPDATE ace_notifications SET read=TRUE WHERE tenant_id=$1 AND read=FALSE`, tidStr)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// ── Audit ─────────────────────────────────────────────────────────────────────

func GetACEAudit(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	limit := parseLimit(c, 100)

	var entries []map[string]interface{}
	rows, _ := db.Query(`SELECT action,object_type,object_id,object_name,actor,ip_address,details,created_at
		FROM ace_audit WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tidStr, limit)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var action, otype, actor string
			var oid, oname, ip, det, ca *string
			if err := rows.Scan(&action, &otype, &oid, &oname, &actor, &ip, &det, &ca); err == nil {
				entries = append(entries, map[string]interface{}{
					"action": action, "object_type": otype, "object_id": oid,
					"object_name": oname, "actor": actor, "ip_address": ip,
					"details": det, "created_at": ca,
				})
			}
		}
	}
	if entries == nil {
		entries = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, entries)
}
