package api

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
	"xcloak-platform/services"
)

func InitFWETables() { createFWETables() }

func createFWETables() {
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS fwe_policies (
		id              SERIAL PRIMARY KEY,
		tenant_id       TEXT NOT NULL,
		policy_id       TEXT NOT NULL,
		name            TEXT NOT NULL,
		description     TEXT,
		status          TEXT NOT NULL DEFAULT 'active',
		priority        INTEGER NOT NULL DEFAULT 100,
		rule_count      INTEGER DEFAULT 0,
		owner           TEXT,
		version         TEXT DEFAULT '1.0',
		tags            TEXT DEFAULT '[]',
		created_by      TEXT NOT NULL DEFAULT 'system',
		created_at      TIMESTAMP DEFAULT NOW(),
		updated_at      TIMESTAMP DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS fwe_zones (
		id              SERIAL PRIMARY KEY,
		tenant_id       TEXT NOT NULL,
		name            TEXT NOT NULL,
		zone_type       TEXT NOT NULL DEFAULT 'custom',
		description     TEXT,
		interfaces      TEXT DEFAULT '[]',
		cidr_ranges     TEXT DEFAULT '[]',
		trust_level     TEXT NOT NULL DEFAULT 'medium',
		enabled         BOOLEAN DEFAULT TRUE,
		created_at      TIMESTAMP DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS fwe_nat (
		id              SERIAL PRIMARY KEY,
		tenant_id       TEXT NOT NULL,
		nat_id          TEXT NOT NULL,
		name            TEXT NOT NULL,
		nat_type        TEXT NOT NULL DEFAULT 'snat',
		description     TEXT,
		src_ip          TEXT,
		dst_ip          TEXT,
		translated_ip   TEXT,
		src_port        TEXT,
		dst_port        TEXT,
		translated_port TEXT,
		protocol        TEXT DEFAULT 'tcp',
		interface       TEXT,
		enabled         BOOLEAN DEFAULT TRUE,
		hit_count       INTEGER DEFAULT 0,
		created_by      TEXT NOT NULL DEFAULT 'system',
		created_at      TIMESTAMP DEFAULT NOW(),
		updated_at      TIMESTAMP DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS fwe_threats (
		id              SERIAL PRIMARY KEY,
		tenant_id       TEXT NOT NULL,
		threat_type     TEXT NOT NULL,
		src_ip          TEXT,
		dst_ip          TEXT,
		src_port        INTEGER,
		dst_port        INTEGER,
		protocol        TEXT,
		domain          TEXT,
		country         TEXT,
		description     TEXT,
		action_taken    TEXT NOT NULL DEFAULT 'blocked',
		severity        TEXT NOT NULL DEFAULT 'high',
		confidence      INTEGER DEFAULT 90,
		rule_triggered  TEXT,
		threat_intel    TEXT DEFAULT '{}',
		created_at      TIMESTAMP DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS fwe_connections (
		id              SERIAL PRIMARY KEY,
		tenant_id       TEXT NOT NULL,
		src_ip          TEXT NOT NULL,
		dst_ip          TEXT NOT NULL,
		src_port        INTEGER,
		dst_port        INTEGER,
		protocol        TEXT NOT NULL DEFAULT 'tcp',
		application     TEXT,
		state           TEXT NOT NULL DEFAULT 'established',
		bytes_sent      BIGINT DEFAULT 0,
		bytes_recv      BIGINT DEFAULT 0,
		duration        INTEGER DEFAULT 0,
		rule_id         TEXT,
		zone_src        TEXT,
		zone_dst        TEXT,
		started_at      TIMESTAMP DEFAULT NOW(),
		last_seen       TIMESTAMP DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS fwe_approvals (
		id              SERIAL PRIMARY KEY,
		tenant_id       TEXT NOT NULL,
		change_type     TEXT NOT NULL,
		description     TEXT NOT NULL,
		requester       TEXT NOT NULL,
		approver        TEXT,
		status          TEXT NOT NULL DEFAULT 'pending',
		priority        TEXT NOT NULL DEFAULT 'medium',
		policy          TEXT,
		decision_note   TEXT,
		payload         TEXT DEFAULT '{}',
		decided_at      TIMESTAMP,
		expires_at      TIMESTAMP,
		created_at      TIMESTAMP DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS fwe_notifications (
		id              SERIAL PRIMARY KEY,
		tenant_id       TEXT NOT NULL,
		event_type      TEXT NOT NULL,
		title           TEXT NOT NULL,
		message         TEXT NOT NULL,
		severity        TEXT NOT NULL DEFAULT 'info',
		rule_id         TEXT,
		src_ip          TEXT,
		read            BOOLEAN DEFAULT FALSE,
		created_at      TIMESTAMP DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS fwe_audit (
		id              SERIAL PRIMARY KEY,
		tenant_id       TEXT NOT NULL,
		action          TEXT NOT NULL,
		object_type     TEXT,
		object_id       TEXT,
		object_name     TEXT,
		actor           TEXT NOT NULL,
		details         TEXT,
		ip_address      TEXT,
		created_at      TIMESTAMP DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS fwe_blocked (
		id              SERIAL PRIMARY KEY,
		tenant_id       TEXT NOT NULL,
		block_type      TEXT NOT NULL,
		value           TEXT NOT NULL,
		reason          TEXT,
		blocked_by      TEXT NOT NULL DEFAULT 'system',
		expires_at      TIMESTAMP,
		active          BOOLEAN DEFAULT TRUE,
		created_at      TIMESTAMP DEFAULT NOW()
	)`)
}

func fweAudit(tid int, action, objType, objID, objName, actor, details string) {
	database.DB.Exec(`INSERT INTO fwe_audit (tenant_id,action,object_type,object_id,object_name,actor,details)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, tid, action, objType, objID, objName, actor, details)
}

func fweNotify(tid int, eventType, title, message, severity, ruleID, srcIP string) {
	database.DB.Exec(`INSERT INTO fwe_notifications (tenant_id,event_type,title,message,severity,rule_id,src_ip)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, tid, eventType, title, message, severity, ruleID, srcIP)
}

// GET /api/fwe/dashboard
func GetFWEDashboard(c *gin.Context) {
	tid := tenantIDFromContext(c)

	countRules := func(where string, args ...any) int {
		var n int
		database.DB.QueryRow(`SELECT COUNT(*) FROM firewall_rules WHERE tenant_id=$1`+where, append([]any{tid}, args...)...).Scan(&n)
		return n
	}
	countThreats := func(where string, args ...any) int {
		var n int
		database.DB.QueryRow(`SELECT COUNT(*) FROM fwe_threats WHERE tenant_id=$1`+where, append([]any{tid}, args...)...).Scan(&n)
		return n
	}
	var pendingApprovals, unreadNotif int
	database.DB.QueryRow(`SELECT COUNT(*) FROM fwe_approvals WHERE tenant_id=$1 AND status='pending'`, tid).Scan(&pendingApprovals)
	database.DB.QueryRow(`SELECT COUNT(*) FROM fwe_notifications WHERE tenant_id=$1 AND read=FALSE`, tid).Scan(&unreadNotif)

	// fwe_connections has no real writer — active_connections is computed
	// from endpoint_connections instead (see GetFWEConnections).
	var activeConns int
	database.DB.QueryRow(`SELECT COUNT(*) FROM endpoint_connections WHERE tenant_id=$1 AND state='ESTABLISHED'`, tid).Scan(&activeConns)

	type topIP struct {
		IP    string `json:"ip"`
		Count int    `json:"count"`
	}
	topSrc := []topIP{}
	topDst := []topIP{}
	srcRows, _ := database.DB.Query(`SELECT src_ip, COUNT(*) as c FROM fwe_threats WHERE tenant_id=$1 GROUP BY src_ip ORDER BY c DESC LIMIT 5`, tid)
	if srcRows != nil {
		for srcRows.Next() {
			var t topIP
			srcRows.Scan(&t.IP, &t.Count)
			topSrc = append(topSrc, t)
		}
		srcRows.Close()
	}
	dstRows, _ := database.DB.Query(`SELECT dst_ip, COUNT(*) as c FROM fwe_threats WHERE tenant_id=$1 AND dst_ip IS NOT NULL GROUP BY dst_ip ORDER BY c DESC LIMIT 5`, tid)
	if dstRows != nil {
		for dstRows.Next() {
			var t topIP
			dstRows.Scan(&t.IP, &t.Count)
			topDst = append(topDst, t)
		}
		dstRows.Close()
	}

	c.JSON(http.StatusOK, gin.H{
		"active_rules":         countRules(` AND enabled=TRUE`),
		"total_rules":          countRules(``),
		"disabled_rules":       countRules(` AND enabled=FALSE`),
		"threat_blocks":        countThreats(` AND action_taken='blocked'`),
		"threats_24h":          countThreats(` AND created_at > NOW()-INTERVAL '24 hours'`),
		"port_scan_blocks":     countThreats(` AND threat_type='port_scan'`),
		"brute_force_blocks":   countThreats(` AND threat_type='brute_force'`),
		"c2_blocks":            countThreats(` AND threat_type='c2_traffic'`),
		"active_connections":   activeConns,
		"pending_approvals":    pendingApprovals,
		"unread_notifications": unreadNotif,
		"top_source_ips":       topSrc,
		"top_dest_ips":         topDst,
	})
}

// ── Policies ──────────────────────────────────────────────────────────────

// GET /api/fwe/policies
func GetFWEPolicies(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT id,policy_id,name,description,status,priority,rule_count,owner,version,tags,created_by,created_at,updated_at
		FROM fwe_policies WHERE tenant_id=$1 ORDER BY priority ASC`, tid)
	if err != nil {
		c.JSON(http.StatusOK, []any{})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, priority, ruleCount int
		var polID, name, status, owner, version, tags, createdBy string
		var desc *string
		var createdAt, updatedAt time.Time
		rows.Scan(&id, &polID, &name, &desc, &status, &priority, &ruleCount, &owner, &version, &tags, &createdBy, &createdAt, &updatedAt)
		p := map[string]any{
			"id": id, "policy_id": polID, "name": name, "status": status,
			"priority": priority, "rule_count": ruleCount, "owner": owner,
			"version": version, "tags": tags, "created_by": createdBy,
			"created_at": createdAt.Format(time.RFC3339), "updated_at": updatedAt.Format(time.RFC3339),
		}
		if desc != nil {
			p["description"] = *desc
		}
		out = append(out, p)
	}
	c.JSON(http.StatusOK, out)
}

// POST /api/fwe/policies
func PostFWEPolicy(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	var b struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Priority    int    `json:"priority"`
		Owner       string `json:"owner"`
		Tags        string `json:"tags"`
	}
	c.ShouldBindJSON(&b)
	if b.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}
	if b.Priority == 0 {
		b.Priority = 100
	}
	if b.Tags == "" {
		b.Tags = "[]"
	}
	polID := fmt.Sprintf("POL-%06d", rand.Intn(999999))
	var id int
	err := database.DB.QueryRow(`INSERT INTO fwe_policies (tenant_id,policy_id,name,description,status,priority,owner,tags,created_by)
		VALUES ($1,$2,$3,$4,'active',$5,$6,$7,$8) RETURNING id`,
		tid, polID, b.Name, b.Description, b.Priority, b.Owner, b.Tags, actor).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	fweAudit(tid, "policy_created", "policy", polID, b.Name, actor, "")
	c.JSON(http.StatusCreated, gin.H{"id": id, "policy_id": polID})
}

// PATCH /api/fwe/policies/:id
func PatchFWEPolicy(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id := c.Param("id")
	var b map[string]any
	c.ShouldBindJSON(&b)
	database.DB.Exec(`UPDATE fwe_policies SET name=COALESCE(NULLIF($3,''),name),
		description=COALESCE(NULLIF($4,''),description),
		status=COALESCE(NULLIF($5,''),status),
		owner=COALESCE(NULLIF($6,''),owner),
		updated_at=NOW() WHERE tenant_id=$1 AND id=$2`,
		tid, id, b["name"], b["description"], b["status"], b["owner"])
	var polID, name string
	database.DB.QueryRow(`SELECT policy_id, name FROM fwe_policies WHERE id=$1`, id).Scan(&polID, &name)
	fweAudit(tid, "policy_modified", "policy", polID, name, actor, "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DELETE /api/fwe/policies/:id
func DeleteFWEPolicy(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id := c.Param("id")
	var polID, name string
	database.DB.QueryRow(`SELECT policy_id, name FROM fwe_policies WHERE id=$1`, id).Scan(&polID, &name)
	database.DB.Exec(`DELETE FROM fwe_policies WHERE tenant_id=$1 AND id=$2`, tid, id)
	fweAudit(tid, "policy_deleted", "policy", polID, name, actor, "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── Zones ─────────────────────────────────────────────────────────────────

// GET /api/fwe/zones
func GetFWEZones(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT id,name,zone_type,description,interfaces,cidr_ranges,trust_level,enabled,created_at
		FROM fwe_zones WHERE tenant_id=$1 ORDER BY name ASC`, tid)
	if err != nil {
		c.JSON(http.StatusOK, []any{})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int
		var name, zoneType, trustLevel, ifaces, cidrs string
		var desc *string
		var enabled bool
		var createdAt time.Time
		rows.Scan(&id, &name, &zoneType, &desc, &ifaces, &cidrs, &trustLevel, &enabled, &createdAt)
		z := map[string]any{
			"id": id, "name": name, "zone_type": zoneType, "interfaces": ifaces,
			"cidr_ranges": cidrs, "trust_level": trustLevel, "enabled": enabled,
			"created_at": createdAt.Format(time.RFC3339),
		}
		if desc != nil {
			z["description"] = *desc
		}
		out = append(out, z)
	}
	c.JSON(http.StatusOK, out)
}

// POST /api/fwe/zones
func PostFWEZone(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	var b struct {
		Name        string `json:"name"`
		ZoneType    string `json:"zone_type"`
		Description string `json:"description"`
		Interfaces  string `json:"interfaces"`
		CidrRanges  string `json:"cidr_ranges"`
		TrustLevel  string `json:"trust_level"`
	}
	c.ShouldBindJSON(&b)
	if b.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}
	if b.ZoneType == "" {
		b.ZoneType = "custom"
	}
	if b.TrustLevel == "" {
		b.TrustLevel = "medium"
	}
	if b.Interfaces == "" {
		b.Interfaces = "[]"
	}
	if b.CidrRanges == "" {
		b.CidrRanges = "[]"
	}
	var id int
	database.DB.QueryRow(`INSERT INTO fwe_zones (tenant_id,name,zone_type,description,interfaces,cidr_ranges,trust_level)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		tid, b.Name, b.ZoneType, b.Description, b.Interfaces, b.CidrRanges, b.TrustLevel).Scan(&id)
	fweAudit(tid, "zone_created", "zone", "", b.Name, actor, "")
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// ── NAT ───────────────────────────────────────────────────────────────────

// GET /api/fwe/nat
func GetFWENAT(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT id,nat_id,name,nat_type,description,src_ip,dst_ip,translated_ip,
		src_port,dst_port,translated_port,protocol,interface,enabled,hit_count,created_at
		FROM fwe_nat WHERE tenant_id=$1 ORDER BY created_at DESC`, tid)
	if err != nil {
		c.JSON(http.StatusOK, []any{})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, hitCount int
		var natID, name, natType, protocol string
		var desc, srcIP, dstIP, transIP, srcPort, dstPort, transPort, iface *string
		var enabled bool
		var createdAt time.Time
		rows.Scan(&id, &natID, &name, &natType, &desc, &srcIP, &dstIP, &transIP,
			&srcPort, &dstPort, &transPort, &protocol, &iface, &enabled, &hitCount, &createdAt)
		n := map[string]any{
			"id": id, "nat_id": natID, "name": name, "nat_type": natType,
			"protocol": protocol, "enabled": enabled, "hit_count": hitCount,
			"created_at": createdAt.Format(time.RFC3339),
		}
		for k, v := range map[string]*string{
			"description": desc, "src_ip": srcIP, "dst_ip": dstIP, "translated_ip": transIP,
			"src_port": srcPort, "dst_port": dstPort, "translated_port": transPort, "interface": iface,
		} {
			if v != nil {
				n[k] = *v
			}
		}
		out = append(out, n)
	}
	c.JSON(http.StatusOK, out)
}

// POST /api/fwe/nat
func PostFWENAT(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	var b struct {
		Name           string `json:"name"`
		NatType        string `json:"nat_type"`
		Description    string `json:"description"`
		SrcIP          string `json:"src_ip"`
		DstIP          string `json:"dst_ip"`
		TranslatedIP   string `json:"translated_ip"`
		SrcPort        string `json:"src_port"`
		DstPort        string `json:"dst_port"`
		TranslatedPort string `json:"translated_port"`
		Protocol       string `json:"protocol"`
		Interface      string `json:"interface"`
	}
	c.ShouldBindJSON(&b)
	if b.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}
	if b.NatType == "" {
		b.NatType = "snat"
	}
	if b.Protocol == "" {
		b.Protocol = "tcp"
	}
	natID := fmt.Sprintf("NAT-%06d", rand.Intn(999999))
	var id int
	database.DB.QueryRow(`INSERT INTO fwe_nat (tenant_id,nat_id,name,nat_type,description,src_ip,dst_ip,translated_ip,src_port,dst_port,translated_port,protocol,interface,created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id`,
		tid, natID, b.Name, b.NatType, b.Description, b.SrcIP, b.DstIP, b.TranslatedIP,
		b.SrcPort, b.DstPort, b.TranslatedPort, b.Protocol, b.Interface, actor).Scan(&id)
	fweAudit(tid, "nat_created", "nat", natID, b.Name, actor, fmt.Sprintf("Type: %s", b.NatType))
	c.JSON(http.StatusCreated, gin.H{"id": id, "nat_id": natID})
}

// DELETE /api/fwe/nat/:id
func DeleteFWENAT(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id := c.Param("id")
	var natID, name string
	database.DB.QueryRow(`SELECT nat_id, name FROM fwe_nat WHERE id=$1`, id).Scan(&natID, &name)
	database.DB.Exec(`DELETE FROM fwe_nat WHERE tenant_id=$1 AND id=$2`, tid, id)
	fweAudit(tid, "nat_deleted", "nat", natID, name, actor, "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── Threat Protection ─────────────────────────────────────────────────────

// GET /api/fwe/threats
func GetFWEThreats(c *gin.Context) {
	tid := tenantIDFromContext(c)
	threatType := c.Query("type")
	severity := c.Query("severity")
	limit := parseLimit(c, 100)

	q := `SELECT id,threat_type,src_ip,dst_ip,src_port,dst_port,protocol,domain,country,description,
		action_taken,severity,confidence,rule_triggered,created_at
		FROM fwe_threats WHERE tenant_id=$1`
	args := []any{tid}
	i := 2
	if threatType != "" {
		q += fmt.Sprintf(` AND threat_type=$%d`, i)
		args = append(args, threatType)
		i++
	}
	if severity != "" {
		q += fmt.Sprintf(` AND severity=$%d`, i)
		args = append(args, severity)
		i++
	}
	q += fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d`, i)
	args = append(args, limit)

	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusOK, []any{})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, confidence int
		var srcPort, dstPort *int
		var threatType2, actionTaken, severity2 string
		var srcIP, dstIP, protocol, domain, country, desc, rule *string
		var createdAt time.Time
		rows.Scan(&id, &threatType2, &srcIP, &dstIP, &srcPort, &dstPort, &protocol, &domain, &country, &desc,
			&actionTaken, &severity2, &confidence, &rule, &createdAt)
		t := map[string]any{
			"id": id, "threat_type": threatType2, "action_taken": actionTaken,
			"severity": severity2, "confidence": confidence,
			"created_at": createdAt.Format(time.RFC3339),
		}
		for k, v := range map[string]*string{"src_ip": srcIP, "dst_ip": dstIP, "protocol": protocol, "domain": domain, "country": country, "description": desc, "rule_triggered": rule} {
			if v != nil {
				t[k] = *v
			}
		}
		if srcPort != nil {
			t["src_port"] = *srcPort
		}
		if dstPort != nil {
			t["dst_port"] = *dstPort
		}
		out = append(out, t)
	}
	c.JSON(http.StatusOK, out)
}

// ── Live Connections ──────────────────────────────────────────────────────

// GET /api/fwe/connections
//
// fwe_connections has no real writer anywhere in this codebase — this tab
// used to show only seeded, static data regardless of what any real agent
// was actually doing. Backed by endpoint_connections instead, the real
// periodic connection-snapshot table agents report to via
// POST /api/agents/connections (see repositories.SaveConnections) —
// real src/dst/protocol/state/process data. bytes_sent/bytes_recv/duration/
// zone_src/zone_dst/rule_id have no equivalent real source anywhere in this
// codebase (no live packet/flow byte-counting or zone-correlation exists)
// and are intentionally omitted rather than fabricated.
func GetFWEConnections(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT ec.id, ec.local_address, ec.remote_address, ec.protocol, ec.state,
		COALESCE(ec.process_name,''), ec.collected_at, a.hostname
		FROM endpoint_connections ec
		JOIN agents a ON a.id = ec.agent_id
		WHERE ec.tenant_id=$1
		ORDER BY ec.collected_at DESC LIMIT 200`, tid)
	if err != nil {
		c.JSON(http.StatusOK, []any{})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int
		var localAddr, remoteAddr, protocol, state, procName, hostname string
		var collectedAt time.Time
		rows.Scan(&id, &localAddr, &remoteAddr, &protocol, &state, &procName, &collectedAt, &hostname)
		srcIP, srcPort := splitHostPortLoose(localAddr)
		dstIP, dstPort := splitHostPortLoose(remoteAddr)
		out = append(out, map[string]any{
			"id": id, "src_ip": srcIP, "src_port": srcPort, "dst_ip": dstIP, "dst_port": dstPort,
			"protocol": strings.ToLower(protocol), "state": strings.ToUpper(state), "application": procName,
			"agent_hostname": hostname, "last_seen": collectedAt.Format(time.RFC3339),
		})
	}
	c.JSON(http.StatusOK, out)
}

// splitHostPortLoose splits an "ip:port" string (as agents report for
// local/remote socket addresses) into ip and port, tolerating a missing or
// unparseable port rather than erroring — real /proc/net or netstat output
// occasionally lacks a port for some entry types.
func splitHostPortLoose(addr string) (string, int) {
	idx := strings.LastIndex(addr, ":")
	if idx == -1 {
		return addr, 0
	}
	port, _ := strconv.Atoi(addr[idx+1:])
	return addr[:idx], port
}

// ── Response Actions ──────────────────────────────────────────────────────

// POST /api/fwe/block
func PostFWEBlock(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	var b struct {
		BlockType string `json:"block_type"`
		Value     string `json:"value"`
		Reason    string `json:"reason"`
		ExpiresIn int    `json:"expires_in_hours"`
	}
	c.ShouldBindJSON(&b)
	if b.BlockType == "" || b.Value == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "block_type and value required"})
		return
	}
	var expiresAt *time.Time
	if b.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(b.ExpiresIn) * time.Hour)
		expiresAt = &t
	}
	var id int
	database.DB.QueryRow(`INSERT INTO fwe_blocked (tenant_id,block_type,value,reason,blocked_by,expires_at)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`, tid, b.BlockType, b.Value, b.Reason, actor, expiresAt).Scan(&id)
	fweAudit(tid, "block_added", b.BlockType, "", b.Value, actor, b.Reason)
	fweNotify(tid, "block_added", fmt.Sprintf("%s blocked", b.BlockType), fmt.Sprintf("%s '%s' blocked by %s", b.BlockType, b.Value, actor), "warning", "", b.Value)
	c.JSON(http.StatusCreated, gin.H{"id": id, "ok": true})
}

// GET /api/fwe/blocked
func GetFWEBlocked(c *gin.Context) {
	tid := tenantIDFromContext(c)
	out := []map[string]any{}
	rows, err := database.DB.Query(`SELECT id,block_type,value,reason,blocked_by,expires_at,active,created_at
		FROM fwe_blocked WHERE tenant_id=$1 AND active=TRUE ORDER BY created_at DESC`, tid)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id int
			var blockType, value, blockedBy string
			var reason *string
			var expiresAt *time.Time
			var active bool
			var createdAt time.Time
			rows.Scan(&id, &blockType, &value, &reason, &blockedBy, &expiresAt, &active, &createdAt)
			b := map[string]any{
				"id": fmt.Sprintf("fwe-%d", id), "block_type": blockType, "value": value,
				"blocked_by": blockedBy, "active": active, "created_at": createdAt.Format(time.RFC3339),
			}
			if reason != nil {
				b["reason"] = *reason
			}
			if expiresAt != nil {
				b["expires_at"] = expiresAt.Format(time.RFC3339)
			}
			out = append(out, b)
		}
	}

	// ioc_firewall_blocks is a second, genuinely real block source (see
	// services.autoBlockIOC) that fwe_blocked's manual-block-only view
	// never surfaced — real automatic blocks triggered by IOC matches,
	// distinct from the manual blocks added via PostFWEBlock above.
	iocRows, err := database.DB.Query(`SELECT b.id, i.type, b.indicator, i.severity, b.blocked_at
		FROM ioc_firewall_blocks b JOIN iocs i ON i.id = b.ioc_id
		WHERE b.tenant_id=$1 ORDER BY b.blocked_at DESC LIMIT 100`, tid)
	if err == nil {
		defer iocRows.Close()
		for iocRows.Next() {
			var id int
			var iocType, indicator, severity string
			var blockedAt time.Time
			iocRows.Scan(&id, &iocType, &indicator, &severity, &blockedAt)
			out = append(out, map[string]any{
				"id": fmt.Sprintf("ioc-%d", id), "block_type": iocType, "value": indicator,
				"reason":     fmt.Sprintf("Auto-blocked: IOC match (%s severity)", severity),
				"blocked_by": "ids-auto", "active": true, "created_at": blockedAt.Format(time.RFC3339),
			})
		}
	}
	c.JSON(http.StatusOK, out)
}

// ── Approvals ─────────────────────────────────────────────────────────────

// GET /api/fwe/approvals
func GetFWEApprovals(c *gin.Context) {
	tid := tenantIDFromContext(c)
	status := c.Query("status")
	q := `SELECT id,change_type,description,requester,approver,status,priority,policy,decision_note,decided_at,expires_at,created_at
		FROM fwe_approvals WHERE tenant_id=$1`
	args := []any{tid}
	if status != "" {
		q += ` AND status=$2`
		args = append(args, status)
	}
	q += ` ORDER BY created_at DESC LIMIT 100`
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusOK, []any{})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int
		var changeType, desc, requester, status2, priority string
		var approver, policy, decisionNote *string
		var decidedAt, expiresAt *time.Time
		var createdAt time.Time
		rows.Scan(&id, &changeType, &desc, &requester, &approver, &status2, &priority, &policy, &decisionNote, &decidedAt, &expiresAt, &createdAt)
		a := map[string]any{
			"id": id, "change_type": changeType, "description": desc,
			"requester": requester, "status": status2, "priority": priority,
			"created_at": createdAt.Format(time.RFC3339),
		}
		for k, v := range map[string]*string{"approver": approver, "policy": policy, "decision_note": decisionNote} {
			if v != nil {
				a[k] = *v
			}
		}
		if decidedAt != nil {
			a["decided_at"] = decidedAt.Format(time.RFC3339)
		}
		if expiresAt != nil {
			a["expires_at"] = expiresAt.Format(time.RFC3339)
		}
		out = append(out, a)
	}
	c.JSON(http.StatusOK, out)
}

// POST /api/fwe/approvals
func PostFWEApproval(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	var b struct {
		ChangeType  string `json:"change_type"`
		Description string `json:"description"`
		Priority    string `json:"priority"`
		Policy      string `json:"policy"`
		Payload     string `json:"payload"`
	}
	c.ShouldBindJSON(&b)
	if b.ChangeType == "" || b.Description == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "change_type and description required"})
		return
	}
	if b.Priority == "" {
		b.Priority = "medium"
	}
	var id int
	database.DB.QueryRow(`INSERT INTO fwe_approvals (tenant_id,change_type,description,requester,status,priority,policy,payload,expires_at)
		VALUES ($1,$2,$3,$4,'pending',$5,$6,$7,NOW()+INTERVAL '24 hours') RETURNING id`,
		tid, b.ChangeType, b.Description, actor, b.Priority, b.Policy, b.Payload).Scan(&id)
	fweAudit(tid, "approval_requested", "approval", "", b.Description, actor, fmt.Sprintf("Type: %s", b.ChangeType))
	fweNotify(tid, "approval_required", "Approval Required", fmt.Sprintf("Firewall change '%s' requires approval", b.Description), "warning", "", "")
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// POST /api/fwe/approvals/:id/decide
func PostFWEApprovalDecide(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id := c.Param("id")
	var b struct {
		Decision string `json:"decision"`
		Note     string `json:"note"`
	}
	c.ShouldBindJSON(&b)
	if b.Decision != "approved" && b.Decision != "rejected" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "decision must be approved or rejected"})
		return
	}
	database.DB.Exec(`UPDATE fwe_approvals SET status=$1,approver=$2,decision_note=$3,decided_at=NOW() WHERE tenant_id=$4 AND id=$5`,
		b.Decision, actor, b.Note, tid, id)
	var desc string
	database.DB.QueryRow(`SELECT description FROM fwe_approvals WHERE id=$1`, id).Scan(&desc)
	fweAudit(tid, "approval_"+b.Decision, "approval", id, desc, actor, b.Note)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── Notifications ─────────────────────────────────────────────────────────

// GET /api/fwe/notifications
func GetFWENotifications(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT id,event_type,title,message,severity,rule_id,src_ip,read,created_at
		FROM fwe_notifications WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 100`, tid)
	if err != nil {
		c.JSON(http.StatusOK, []any{})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int
		var eventType, title, message, severity string
		var ruleID, srcIP *string
		var read bool
		var createdAt time.Time
		rows.Scan(&id, &eventType, &title, &message, &severity, &ruleID, &srcIP, &read, &createdAt)
		n := map[string]any{
			"id": id, "event_type": eventType, "title": title, "message": message,
			"severity": severity, "read": read, "created_at": createdAt.Format(time.RFC3339),
		}
		if ruleID != nil {
			n["rule_id"] = *ruleID
		}
		if srcIP != nil {
			n["src_ip"] = *srcIP
		}
		out = append(out, n)
	}
	c.JSON(http.StatusOK, out)
}

// PATCH /api/fwe/notifications/read
func PatchFWENotificationsRead(c *gin.Context) {
	tid := tenantIDFromContext(c)
	database.DB.Exec(`UPDATE fwe_notifications SET read=TRUE WHERE tenant_id=$1`, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── Analytics ─────────────────────────────────────────────────────────────

// GET /api/fwe/analytics
func GetFWEAnalytics(c *gin.Context) {
	tid := tenantIDFromContext(c)

	type threatStat struct {
		ThreatType string `json:"threat_type"`
		Count      int    `json:"count"`
	}
	trows, _ := database.DB.Query(`SELECT threat_type, COUNT(*) as c FROM fwe_threats WHERE tenant_id=$1 GROUP BY threat_type ORDER BY c DESC`, tid)
	threatStats := []threatStat{}
	if trows != nil {
		for trows.Next() {
			var ts threatStat
			trows.Scan(&ts.ThreatType, &ts.Count)
			threatStats = append(threatStats, ts)
		}
		trows.Close()
	}

	type protoStat struct {
		Protocol string `json:"protocol"`
		Count    int    `json:"count"`
	}
	prows, _ := database.DB.Query(`SELECT protocol, COUNT(*) as c FROM endpoint_connections WHERE tenant_id=$1 AND protocol IS NOT NULL GROUP BY protocol ORDER BY c DESC LIMIT 8`, tid)
	protoStats := []protoStat{}
	if prows != nil {
		for prows.Next() {
			var ps protoStat
			prows.Scan(&ps.Protocol, &ps.Count)
			protoStats = append(protoStats, ps)
		}
		prows.Close()
	}

	type topIP struct {
		IP    string `json:"ip"`
		Count int    `json:"count"`
	}
	irows, _ := database.DB.Query(`SELECT src_ip, COUNT(*) as c FROM fwe_threats WHERE tenant_id=$1 AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY c DESC LIMIT 10`, tid)
	topBlockedIPs := []topIP{}
	if irows != nil {
		for irows.Next() {
			var ti topIP
			irows.Scan(&ti.IP, &ti.Count)
			topBlockedIPs = append(topBlockedIPs, ti)
		}
		irows.Close()
	}

	var totalThreats, last24h int
	database.DB.QueryRow(`SELECT COUNT(*), COUNT(*) FILTER (WHERE created_at > NOW()-INTERVAL '24 hours') FROM fwe_threats WHERE tenant_id=$1`, tid).Scan(&totalThreats, &last24h)

	c.JSON(http.StatusOK, gin.H{
		"total_threats":   totalThreats,
		"threats_24h":     last24h,
		"by_threat_type":  threatStats,
		"by_protocol":     protoStats,
		"top_blocked_ips": topBlockedIPs,
	})
}

// ── Audit ─────────────────────────────────────────────────────────────────

// GET /api/fwe/audit
func GetFWEAudit(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT id,action,object_type,object_id,object_name,actor,details,ip_address,created_at
		FROM fwe_audit WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 200`, tid)
	if err != nil {
		c.JSON(http.StatusOK, []any{})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int
		var action, actor string
		var objType, objID, objName, details, ipAddr *string
		var createdAt time.Time
		rows.Scan(&id, &action, &objType, &objID, &objName, &actor, &details, &ipAddr, &createdAt)
		a := map[string]any{
			"id": id, "action": action, "actor": actor, "created_at": createdAt.Format(time.RFC3339),
		}
		for k, v := range map[string]*string{"object_type": objType, "object_id": objID, "object_name": objName, "details": details, "ip_address": ipAddr} {
			if v != nil {
				a[k] = *v
			}
		}
		out = append(out, a)
	}
	c.JSON(http.StatusOK, out)
}

// ── AI ────────────────────────────────────────────────────────────────────

// POST /api/fwe/ai
func PostFWEAI(c *gin.Context) {
	tid := tenantIDFromContext(c)
	var b struct {
		Action  string `json:"action"`
		Context string `json:"context"`
	}
	c.ShouldBindJSON(&b)

	// ── Gather real firewall context for this tenant ────────────────────────
	var ctx strings.Builder
	ruleRows, _ := database.DB.Query(`SELECT id, name, source_ip, destination_ip, protocol, port_range, action, priority
		FROM firewall_rules WHERE tenant_id=$1 AND enabled=TRUE ORDER BY priority ASC LIMIT 30`, tid)
	if ruleRows != nil {
		ctx.WriteString("Active firewall rules (ordered by priority):\n")
		for ruleRows.Next() {
			var id, priority int
			var name, action string
			var srcIP, dstIP, protocol, portRange *string
			ruleRows.Scan(&id, &name, &srcIP, &dstIP, &protocol, &portRange, &action, &priority)
			fmt.Fprintf(&ctx, "- [P%d] #%d %s: %s %s→%s %s/%s\n", priority, id, name, action,
				strOrDefault(srcIP, "any"), strOrDefault(dstIP, "any"), strOrDefault(protocol, "any"), strOrDefault(portRange, "any"))
		}
		ruleRows.Close()
	}

	threatRows, _ := database.DB.Query(`SELECT threat_type, src_ip, dst_ip, protocol, dst_port, severity, action_taken, COUNT(*) as hits
		FROM fwe_threats WHERE tenant_id=$1 GROUP BY threat_type, src_ip, dst_ip, protocol, dst_port, severity, action_taken
		ORDER BY hits DESC LIMIT 15`, tid)
	if threatRows != nil {
		ctx.WriteString("\nRecent threat patterns (grouped, most frequent first):\n")
		for threatRows.Next() {
			var threatType, action string
			var srcIP, dstIP, protocol *string
			var dstPort *int
			var severity string
			var hits int
			threatRows.Scan(&threatType, &srcIP, &dstIP, &protocol, &dstPort, &severity, &action, &hits)
			port := "any"
			if dstPort != nil {
				port = fmt.Sprintf("%d", *dstPort)
			}
			fmt.Fprintf(&ctx, "- %s (%s): %s→%s %s/%s, %d hits, %s\n", threatType, severity,
				strOrDefault(srcIP, "unknown"), strOrDefault(dstIP, "unknown"), strOrDefault(protocol, "any"), port, hits, action)
		}
		threatRows.Close()
	}

	var activeConns, totalRules int
	database.DB.QueryRow(`SELECT COUNT(*) FROM endpoint_connections WHERE tenant_id=$1 AND state='ESTABLISHED'`, tid).Scan(&activeConns)
	database.DB.QueryRow(`SELECT COUNT(*) FROM firewall_rules WHERE tenant_id=$1`, tid).Scan(&totalRules)
	fmt.Fprintf(&ctx, "\nActive established connections: %d\nTotal configured rules: %d\n", activeConns, totalRules)

	if b.Context != "" {
		fmt.Fprintf(&ctx, "\nAnalyst-provided context: %s\n", b.Context)
	}
	firewallCtx := ctx.String()

	var task string
	switch b.Action {
	case "recommend_rules":
		task = "Based on the observed threat patterns and existing rules, recommend specific new firewall rules to add (source/destination/protocol/port/action)."
	case "detect_redundant":
		task = "Analyze the active rules and identify any that are redundant or duplicate each other, explaining why."
	case "identify_shadowed":
		task = "Analyze the active rules ordered by priority and identify any that are shadowed (never evaluated) by a higher-priority rule."
	case "optimize_rule_order":
		task = "Recommend a better priority ordering for the active rules to improve both security posture and evaluation efficiency."
	case "explain_traffic":
		task = "Using the threat and connection data, explain what traffic patterns are being seen and how the current ruleset is (or isn't) handling them."
	case "recommend_improvements":
		task = "Give a prioritized list of firewall policy improvements based on the current rules, threat activity, and connection volume."
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown action"})
		return
	}

	prompt := fmt.Sprintf(`You are a network security analyst reviewing this organization's real firewall configuration and traffic data.

%s

Task: %s

Base your answer strictly on the data above — do not invent specific rule names, IPs, or figures not present in the data. If data is sparse, say so rather than inventing specifics. Respond in plain text (no markdown headers), suitable for direct display to the user.`, firewallCtx, task)

	resp, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"response": strings.TrimSpace(resp), "action": b.Action})
}

func strOrDefault(s *string, def string) string {
	if s == nil || *s == "" {
		return def
	}
	return *s
}

// POST /api/fwe/validate
func PostFWEValidate(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rules, _ := database.DB.Query(`SELECT id,name,source_ip,destination_ip,protocol,port_range,action,enabled,priority
		FROM firewall_rules WHERE tenant_id=$1 AND enabled=TRUE ORDER BY priority ASC`, tid)

	type issue struct {
		Type    string `json:"type"`
		RuleID  int    `json:"rule_id"`
		Name    string `json:"name"`
		Message string `json:"message"`
	}
	issues := []issue{}

	type rule struct {
		id, priority        int
		name, srcIP, dstIP  string
		protocol, portRange string
		action              string
	}
	allRules := []rule{}
	if rules != nil {
		for rules.Next() {
			var r rule
			var srcIP, dstIP, portRange *string
			rules.Scan(&r.id, &r.name, &srcIP, &dstIP, &r.protocol, &portRange, &r.action, new(bool), &r.priority)
			if srcIP != nil {
				r.srcIP = *srcIP
			}
			if dstIP != nil {
				r.dstIP = *dstIP
			}
			if portRange != nil {
				r.portRange = *portRange
			}
			allRules = append(allRules, r)
		}
		rules.Close()
	}

	// Simple duplicate/shadow detection
	seen := map[string]int{}
	for _, r := range allRules {
		key := fmt.Sprintf("%s|%s|%s|%s", r.srcIP, r.dstIP, r.protocol, r.portRange)
		if prev, ok := seen[key]; ok {
			issues = append(issues, issue{"duplicate", r.id, r.name, fmt.Sprintf("Duplicate of rule ID %d — same source/dest/protocol/port", prev)})
		}
		seen[key] = r.id
		// Overly permissive
		if (r.srcIP == "" || r.srcIP == "any" || r.srcIP == "0.0.0.0/0") && r.action == "allow" && (r.portRange == "" || r.portRange == "0-65535") {
			issues = append(issues, issue{"overly_permissive", r.id, r.name, "Allows all traffic from any source — overly permissive"})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"issues":      issues,
		"total_rules": len(allRules),
		"issue_count": len(issues),
	})
}

// POST /api/fwe/report
func PostFWEReport(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	var b struct {
		ReportType string `json:"report_type"`
	}
	c.ShouldBindJSON(&b)

	titles := map[string]string{
		"firewall_activity": "Firewall Activity Report", "policy_compliance": "Policy Compliance Report",
		"threat_blocking": "Threat Blocking Report", "config_change": "Configuration Change Report",
		"executive_summary": "Executive Summary", "audit": "Audit Report",
	}
	title := titles[b.ReportType]
	if title == "" {
		title = "Firewall Report"
	}

	row := func(q string) int {
		var n int
		database.DB.QueryRow(q, tid).Scan(&n)
		return n
	}
	totalRules := row(`SELECT COUNT(*) FROM firewall_rules WHERE tenant_id=$1`)
	activeRules := row(`SELECT COUNT(*) FROM firewall_rules WHERE tenant_id=$1 AND enabled=TRUE`)
	totalThreats := row(`SELECT COUNT(*) FROM fwe_threats WHERE tenant_id=$1`)
	threats24h := row(`SELECT COUNT(*) FROM fwe_threats WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL '24 hours'`)
	pendingApprovals := row(`SELECT COUNT(*) FROM fwe_approvals WHERE tenant_id=$1 AND status='pending'`)
	iocBlocks := row(`SELECT COUNT(*) FROM ioc_firewall_blocks WHERE tenant_id=$1`)

	// This used to return zero real numbers at all — not even a fabricated
	// snapshot, just a generic "X report generated successfully" string,
	// with no key_metrics field for the frontend to render.
	prompt := fmt.Sprintf(`You are a network security reporting assistant writing a %s. Real metrics for this tenant: %d total firewall rules (%d enabled), %d total threat events blocked (%d in the last 24 hours), %d real IOC-triggered auto-blocks, %d change requests currently pending approval. Respond as a JSON object with fields: executive_summary (2-3 sentences grounded only in these numbers, no invented incidents), recommendations (a JSON array of up to 4 short actionable strings based only on the real data given — if there isn't enough data, say so instead of inventing findings).`,
		title, totalRules, activeRules, totalThreats, threats24h, iocBlocks, pendingApprovals)
	var summary string
	var recommendations []string
	if raw, err := services.CallLLM(prompt); err == nil {
		clean := raw
		if idx := strings.Index(clean, "```json"); idx != -1 {
			clean = clean[idx+7:]
		} else if idx := strings.Index(clean, "```"); idx != -1 {
			clean = clean[idx+3:]
		}
		if idx := strings.LastIndex(clean, "```"); idx != -1 {
			clean = clean[:idx]
		}
		var parsed struct {
			ExecutiveSummary string   `json:"executive_summary"`
			Recommendations  []string `json:"recommendations"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(clean)), &parsed) == nil {
			summary = parsed.ExecutiveSummary
			recommendations = parsed.Recommendations
		}
	}
	if summary == "" {
		if totalRules == 0 {
			summary = "No firewall rules have been configured for this tenant."
		} else {
			summary = fmt.Sprintf("%d firewall rules configured (%d enabled), %d threat events blocked (%d in the last 24 hours). %d change request(s) currently pending approval.", totalRules, activeRules, totalThreats, threats24h, pendingApprovals)
		}
		recommendations = []string{}
	}

	fweAudit(tid, "report_generated", "report", "", b.ReportType, actor, "")
	c.JSON(http.StatusOK, gin.H{
		"ok":                true,
		"title":             title,
		"report_type":       b.ReportType,
		"generated_at":      time.Now().Format(time.RFC3339),
		"generated_by":      actor,
		"classification":    "CONFIDENTIAL",
		"executive_summary": summary,
		"key_metrics": gin.H{
			"total_rules":       totalRules,
			"active_rules":      activeRules,
			"total_threats":     totalThreats,
			"threats_24h":       threats24h,
			"ioc_blocks":        iocBlocks,
			"pending_approvals": pendingApprovals,
		},
		"recommendations": recommendations,
	})
}
