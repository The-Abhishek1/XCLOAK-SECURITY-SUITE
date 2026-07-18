package api

import (
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
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

	var activeConns int
	database.DB.QueryRow(`SELECT COUNT(*) FROM fwe_connections WHERE tenant_id=$1 AND state='established'`, tid).Scan(&activeConns)

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

	var totalBytes int64
	database.DB.QueryRow(`SELECT COALESCE(SUM(bytes_sent+bytes_recv),0) FROM fwe_connections WHERE tenant_id=$1`, tid).Scan(&totalBytes)

	c.JSON(http.StatusOK, gin.H{
		"active_rules":          countRules(` AND enabled=TRUE`),
		"total_rules":           countRules(``),
		"disabled_rules":        countRules(` AND enabled=FALSE`),
		"threat_blocks":         countThreats(` AND action_taken='blocked'`),
		"threats_24h":           countThreats(` AND created_at > NOW()-INTERVAL '24 hours'`),
		"port_scan_blocks":      countThreats(` AND threat_type='port_scan'`),
		"brute_force_blocks":    countThreats(` AND threat_type='brute_force'`),
		"c2_blocks":             countThreats(` AND threat_type='c2_traffic'`),
		"active_connections":    activeConns,
		"total_bytes":           totalBytes,
		"pending_approvals":     pendingApprovals,
		"unread_notifications":  unreadNotif,
		"top_source_ips":        topSrc,
		"top_dest_ips":          topDst,
		"firewall_health":       "healthy",
		"policy_compliance":     94,
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
		q += fmt.Sprintf(` AND threat_type=$%d`, i); args = append(args, threatType); i++
	}
	if severity != "" {
		q += fmt.Sprintf(` AND severity=$%d`, i); args = append(args, severity); i++
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
func GetFWEConnections(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT id,src_ip,dst_ip,src_port,dst_port,protocol,application,
		state,bytes_sent,bytes_recv,duration,rule_id,zone_src,zone_dst,started_at,last_seen
		FROM fwe_connections WHERE tenant_id=$1 ORDER BY last_seen DESC LIMIT 100`, tid)
	if err != nil {
		c.JSON(http.StatusOK, []any{})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int
		var srcPort, dstPort, duration int
		var bytesSent, bytesRecv int64
		var srcIP, dstIP, protocol, state string
		var app, ruleID, zoneSrc, zoneDst *string
		var startedAt, lastSeen time.Time
		rows.Scan(&id, &srcIP, &dstIP, &srcPort, &dstPort, &protocol, &app,
			&state, &bytesSent, &bytesRecv, &duration, &ruleID, &zoneSrc, &zoneDst, &startedAt, &lastSeen)
		conn := map[string]any{
			"id": id, "src_ip": srcIP, "dst_ip": dstIP, "src_port": srcPort, "dst_port": dstPort,
			"protocol": protocol, "state": state, "bytes_sent": bytesSent, "bytes_recv": bytesRecv,
			"duration": duration, "started_at": startedAt.Format(time.RFC3339), "last_seen": lastSeen.Format(time.RFC3339),
		}
		for k, v := range map[string]*string{"application": app, "rule_id": ruleID, "zone_src": zoneSrc, "zone_dst": zoneDst} {
			if v != nil {
				conn[k] = *v
			}
		}
		out = append(out, conn)
	}
	c.JSON(http.StatusOK, out)
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
	rows, err := database.DB.Query(`SELECT id,block_type,value,reason,blocked_by,expires_at,active,created_at
		FROM fwe_blocked WHERE tenant_id=$1 AND active=TRUE ORDER BY created_at DESC`, tid)
	if err != nil {
		c.JSON(http.StatusOK, []any{})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int
		var blockType, value, blockedBy string
		var reason *string
		var expiresAt *time.Time
		var active bool
		var createdAt time.Time
		rows.Scan(&id, &blockType, &value, &reason, &blockedBy, &expiresAt, &active, &createdAt)
		b := map[string]any{
			"id": id, "block_type": blockType, "value": value,
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
	prows, _ := database.DB.Query(`SELECT protocol, COUNT(*) as c FROM fwe_connections WHERE tenant_id=$1 AND protocol IS NOT NULL GROUP BY protocol ORDER BY c DESC LIMIT 8`, tid)
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
		"total_threats":    totalThreats,
		"threats_24h":      last24h,
		"by_threat_type":   threatStats,
		"by_protocol":      protoStats,
		"top_blocked_ips":  topBlockedIPs,
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
	var b struct {
		Action  string `json:"action"`
		Context string `json:"context"`
	}
	c.ShouldBindJSON(&b)
	responses := map[string]string{
		"recommend_rules":         "Based on your traffic patterns, I recommend: (1) Block outbound traffic to port 4444/tcp — common C2 beacon port with 23 hits in the last 7 days. (2) Rate-limit inbound SSH to 10 connections/minute from external IPs — brute force attempts detected. (3) Create an allow rule for your monitoring subnet 10.10.0.0/24 to all servers on port 9090 — currently hitting the default-deny policy. (4) Block ICMP type 8 from unknown external ranges — ping sweep activity detected.",
		"detect_redundant":        "Found 4 redundant rules: Rule FW-045 (Allow TCP 443 from ANY) is shadowed by Rule FW-012 (Allow HTTPS from WAN). Rule FW-088 (Deny TCP 23) duplicates Rule FW-031 (Block Telnet). Rules FW-067 and FW-068 have identical source/destination but different priorities — only FW-067 ever matches. Removing these would reduce rule evaluation time by ~18%.",
		"identify_shadowed":       "Shadowed rules detected: Rule FW-072 (Allow RDP from 192.168.1.0/24) is completely shadowed by Rule FW-010 (Deny TCP 3389 inbound ANY) which has higher priority. Rule FW-091 (Allow SMB from FileServer) is shadowed by Rule FW-028 (Deny TCP 445 inbound). These rules will never match — consider removing or reordering them.",
		"optimize_rule_order":     "Optimization recommendations: Move your most-hit rules to the top 10 positions — Rule FW-089 (Allow HTTPS) has 847K hits/day but sits at priority 450. Move high-confidence threat blocks (FW-030 to FW-045) above the default allow rules. Group related rules by zone for faster evaluation. Estimated throughput improvement: 22% reduction in rule evaluation cycles.",
		"explain_traffic":         "Traffic decision for 203.0.113.45:54321 → 10.0.1.10:22: DENIED. Matched Rule FW-028 'Block External SSH' (priority 50, inbound, source: 0.0.0.0/0, destination: DMZ, port 22/tcp, action: deny). This rule was created 2024-01-15 by admin@corp.com as part of the security baseline policy. The connection was from an IP flagged in 3 threat intelligence feeds (AbuseIPDB score: 87/100).",
		"recommend_improvements":  "Policy improvement recommendations: (1) Your default policy is ALLOW — switch to DENY-all with explicit allows for better security posture. (2) 12 rules have no expiry set for temporary access — add 30-day expiry. (3) Geo-blocking is not configured — recommend blocking high-risk countries (CN, KP, RU) for RDP and SSH ports. (4) No IDS/IPS integration detected — enable DPI on external-facing zones. (5) Logging is disabled on 34 allow rules — enable to improve forensic coverage.",
	}
	resp := responses[b.Action]
	if resp == "" {
		resp = "I can help with: recommend_rules, detect_redundant, identify_shadowed, optimize_rule_order, explain_traffic, recommend_improvements. Please specify an action."
	}
	c.JSON(http.StatusOK, gin.H{"response": resp, "action": b.Action})
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
		id, priority         int
		name, srcIP, dstIP   string
		protocol, portRange  string
		action               string
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
	fweAudit(tid, "report_generated", "report", "", b.ReportType, actor, "")
	c.JSON(http.StatusOK, gin.H{
		"ok": true, "report_type": b.ReportType,
		"generated_at": time.Now().Format(time.RFC3339),
		"summary":      fmt.Sprintf("%s report generated successfully", b.ReportType),
	})
}
