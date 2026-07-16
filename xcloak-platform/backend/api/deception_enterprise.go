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

func createDeceptionTables() {
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS deception_decoys (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		subtype TEXT,
		protocol TEXT,
		platform TEXT,
		ip TEXT,
		port INTEGER,
		location TEXT,
		template TEXT,
		status TEXT DEFAULT 'active',
		health TEXT DEFAULT 'online',
		trigger_count INTEGER DEFAULT 0,
		last_triggered TIMESTAMPTZ,
		last_heartbeat TIMESTAMPTZ,
		version TEXT DEFAULT '1.0.0',
		integrity_ok BOOLEAN DEFAULT true,
		tags TEXT,
		notes TEXT,
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS deception_honeytokens (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		subtype TEXT,
		value TEXT,
		location TEXT,
		owner TEXT,
		watchlist_category TEXT,
		triggered BOOLEAN DEFAULT false,
		trigger_count INTEGER DEFAULT 0,
		last_triggered TIMESTAMPTZ,
		status TEXT DEFAULT 'active',
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS deception_triggers (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		decoy_id INTEGER,
		honeytoken_id INTEGER,
		event_type TEXT NOT NULL,
		attacker_ip TEXT,
		attacker_user TEXT,
		source_host TEXT,
		source_mac TEXT,
		details JSONB DEFAULT '{}',
		severity TEXT DEFAULT 'high',
		campaign_id INTEGER,
		responded BOOLEAN DEFAULT false,
		response_actions TEXT,
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS deception_campaigns (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		attacker_ip TEXT,
		attacker_user TEXT,
		decoys_hit INTEGER DEFAULT 0,
		tokens_triggered INTEGER DEFAULT 0,
		malware_family TEXT,
		infrastructure TEXT,
		status TEXT DEFAULT 'active',
		severity TEXT DEFAULT 'high',
		mitre_techniques TEXT,
		started_at TIMESTAMPTZ DEFAULT NOW(),
		ended_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS deception_policies (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		decoy_types TEXT,
		locations TEXT,
		lifetime_days INTEGER DEFAULT 30,
		rotation_days INTEGER DEFAULT 7,
		alert_threshold INTEGER DEFAULT 1,
		auto_cleanup BOOLEAN DEFAULT true,
		enabled BOOLEAN DEFAULT true,
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS deception_watchlists (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		category TEXT NOT NULL,
		item TEXT NOT NULL,
		item_type TEXT,
		priority TEXT DEFAULT 'high',
		notes TEXT,
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

func GetDeceptionDashboard(c *gin.Context) {
	createDeceptionTables()
	tid := tenantIDFromContext(c)

	var activeDecoys, triggeredDecoys, totalTriggers, activeCampaigns, highRisk, offlineDecoys int
	database.DB.QueryRow(`SELECT COUNT(*) FROM deception_decoys WHERE tenant_id=$1 AND status='active'`, tid).Scan(&activeDecoys)
	database.DB.QueryRow(`SELECT COUNT(*) FROM deception_decoys WHERE tenant_id=$1 AND trigger_count>0`, tid).Scan(&triggeredDecoys)
	database.DB.QueryRow(`SELECT COUNT(*) FROM deception_triggers WHERE tenant_id=$1`, tid).Scan(&totalTriggers)
	database.DB.QueryRow(`SELECT COUNT(*) FROM deception_campaigns WHERE tenant_id=$1 AND status='active'`, tid).Scan(&activeCampaigns)
	database.DB.QueryRow(`SELECT COUNT(*) FROM deception_triggers WHERE tenant_id=$1 AND severity='critical' AND created_at > NOW()-INTERVAL '24h'`, tid).Scan(&highRisk)
	database.DB.QueryRow(`SELECT COUNT(*) FROM deception_decoys WHERE tenant_id=$1 AND health='offline'`, tid).Scan(&offlineDecoys)

	var honeytokensTriggered, activeHoneytokens int
	database.DB.QueryRow(`SELECT COUNT(*) FROM deception_honeytokens WHERE tenant_id=$1 AND triggered=true`, tid).Scan(&honeytokensTriggered)
	database.DB.QueryRow(`SELECT COUNT(*) FROM deception_honeytokens WHERE tenant_id=$1 AND status='active'`, tid).Scan(&activeHoneytokens)

	// Recent triggers
	rows, _ := database.DB.Query(`
		SELECT t.id, t.event_type, t.attacker_ip, t.attacker_user, t.severity, t.created_at,
		       COALESCE(d.name,''), COALESCE(h.name,'')
		FROM deception_triggers t
		LEFT JOIN deception_decoys d ON d.id=t.decoy_id
		LEFT JOIN deception_honeytokens h ON h.id=t.honeytoken_id
		WHERE t.tenant_id=$1
		ORDER BY t.created_at DESC LIMIT 10`, tid)
	defer rows.Close()
	type TR struct {
		ID          int    `json:"id"`
		EventType   string `json:"event_type"`
		AttackerIP  string `json:"attacker_ip"`
		AttackerUser string `json:"attacker_user"`
		Severity    string `json:"severity"`
		CreatedAt   string `json:"created_at"`
		DecoyName   string `json:"decoy_name"`
		TokenName   string `json:"token_name"`
	}
	recent := []TR{}
	for rows.Next() {
		var r TR
		rows.Scan(&r.ID, &r.EventType, &r.AttackerIP, &r.AttackerUser, &r.Severity, &r.CreatedAt, &r.DecoyName, &r.TokenName)
		recent = append(recent, r)
	}

	// 14-day trend
	trend := []map[string]interface{}{}
	trows, _ := database.DB.Query(`
		SELECT DATE(created_at), COUNT(*) FROM deception_triggers
		WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL '14 days'
		GROUP BY DATE(created_at) ORDER BY 1`, tid)
	defer trows.Close()
	for trows.Next() {
		var d string; var cnt int
		trows.Scan(&d, &cnt)
		trend = append(trend, map[string]interface{}{"date": d, "count": cnt})
	}

	c.JSON(http.StatusOK, gin.H{
		"active_decoys":        activeDecoys,
		"triggered_decoys":     triggeredDecoys,
		"total_triggers":       totalTriggers,
		"active_campaigns":     activeCampaigns,
		"high_risk_24h":        highRisk,
		"offline_decoys":       offlineDecoys,
		"honeytokens_triggered": honeytokensTriggered,
		"active_honeytokens":   activeHoneytokens,
		"recent_triggers":      recent,
		"trend":                trend,
	})
}

// ── Decoys ────────────────────────────────────────────────────────────────────

func GetDeceptionDecoys(c *gin.Context) {
	createDeceptionTables()
	tid := tenantIDFromContext(c)
	dtype := c.Query("type")
	status := c.Query("status")
	limit := parseLimit(c, 100)

	where := "WHERE tenant_id=$1"
	args := []interface{}{tid}
	n := 2
	if dtype != "" {
		where += fmt.Sprintf(" AND type=$%d", n); args = append(args, dtype); n++
	}
	if status != "" {
		where += fmt.Sprintf(" AND status=$%d", n); args = append(args, status); n++
	}

	rows, _ := database.DB.Query(fmt.Sprintf(`
		SELECT id,name,type,subtype,protocol,platform,ip,port,location,template,
		       status,health,trigger_count,last_triggered,last_heartbeat,version,integrity_ok,tags,created_at
		FROM deception_decoys %s ORDER BY trigger_count DESC LIMIT $%d`, where, n),
		append(args, limit)...)
	defer rows.Close()

	type Decoy struct {
		ID           int     `json:"id"`
		Name         string  `json:"name"`
		Type         string  `json:"type"`
		Subtype      string  `json:"subtype"`
		Protocol     string  `json:"protocol"`
		Platform     string  `json:"platform"`
		IP           string  `json:"ip"`
		Port         int     `json:"port"`
		Location     string  `json:"location"`
		Template     string  `json:"template"`
		Status       string  `json:"status"`
		Health       string  `json:"health"`
		TriggerCount int     `json:"trigger_count"`
		LastTriggered *string `json:"last_triggered"`
		LastHeartbeat *string `json:"last_heartbeat"`
		Version      string  `json:"version"`
		IntegrityOK  bool    `json:"integrity_ok"`
		Tags         string  `json:"tags"`
		CreatedAt    string  `json:"created_at"`
	}
	out := []Decoy{}
	for rows.Next() {
		var d Decoy
		rows.Scan(&d.ID, &d.Name, &d.Type, &d.Subtype, &d.Protocol, &d.Platform,
			&d.IP, &d.Port, &d.Location, &d.Template, &d.Status, &d.Health,
			&d.TriggerCount, &d.LastTriggered, &d.LastHeartbeat, &d.Version,
			&d.IntegrityOK, &d.Tags, &d.CreatedAt)
		out = append(out, d)
	}
	c.JSON(http.StatusOK, out)
}

func PostDeceptionDecoy(c *gin.Context) {
	createDeceptionTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Subtype  string `json:"subtype"`
		Protocol string `json:"protocol"`
		Platform string `json:"platform"`
		IP       string `json:"ip"`
		Port     int    `json:"port"`
		Location string `json:"location"`
		Template string `json:"template"`
		Tags     string `json:"tags"`
		Notes    string `json:"notes"`
	}
	c.ShouldBindJSON(&body)
	var id int
	database.DB.QueryRow(`
		INSERT INTO deception_decoys (tenant_id,name,type,subtype,protocol,platform,ip,port,location,template,tags,notes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
		tid, body.Name, body.Type, body.Subtype, body.Protocol, body.Platform,
		body.IP, body.Port, body.Location, body.Template, body.Tags, body.Notes).Scan(&id)
	c.JSON(http.StatusOK, gin.H{"id": id, "ok": true})
}

func PatchDeceptionDecoy(c *gin.Context) {
	tid := tenantIDFromContext(c)
	did, _ := strconv.Atoi(c.Param("id"))
	var body map[string]interface{}
	c.ShouldBindJSON(&body)
	allowed := map[string]bool{"name":true,"status":true,"health":true,"ip":true,"port":true,"location":true,"tags":true,"notes":true,"platform":true}
	setClauses, args := []string{}, []interface{}{}
	n := 1
	for k, v := range body {
		if allowed[k] {
			setClauses = append(setClauses, fmt.Sprintf("%s=$%d", k, n))
			args = append(args, v); n++
		}
	}
	if len(setClauses) == 0 { c.JSON(http.StatusOK, gin.H{"ok": true}); return }
	setClauses = append(setClauses, fmt.Sprintf("updated_at=$%d", n)); args = append(args, time.Now()); n++
	args = append(args, tid, did)
	database.DB.Exec(fmt.Sprintf("UPDATE deception_decoys SET %s WHERE tenant_id=$%d AND id=$%d",
		strings.Join(setClauses, ","), n, n+1), args...)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func DeleteDeceptionDecoy(c *gin.Context) {
	tid := tenantIDFromContext(c)
	did, _ := strconv.Atoi(c.Param("id"))
	database.DB.Exec(`DELETE FROM deception_decoys WHERE tenant_id=$1 AND id=$2`, tid, did)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func PostDeceptionDeploy(c *gin.Context) {
	createDeceptionTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Template  string   `json:"template"`
		Locations []string `json:"locations"`
		Protocol  string   `json:"protocol"`
		Count     int      `json:"count"`
		Platform  string   `json:"platform"`
	}
	c.ShouldBindJSON(&body)
	if body.Count == 0 { body.Count = 1 }
	created := 0
	for i := 0; i < body.Count && i < len(body.Locations); i++ {
		loc := body.Locations[i]
		name := fmt.Sprintf("%s-%s-%d", body.Template, body.Protocol, time.Now().UnixMilli()%10000+int64(i))
		database.DB.Exec(`
			INSERT INTO deception_decoys (tenant_id,name,type,protocol,platform,location,template)
			VALUES ($1,$2,'honeypot',$3,$4,$5,$6)`,
			tid, name, body.Protocol, body.Platform, loc, body.Template)
		created++
	}
	c.JSON(http.StatusOK, gin.H{"created": created, "ok": true})
}

// ── Honeytokens ───────────────────────────────────────────────────────────────

func GetDeceptionHoneytokens(c *gin.Context) {
	createDeceptionTables()
	tid := tenantIDFromContext(c)
	htype := c.Query("type")
	limit := parseLimit(c, 100)

	where := "WHERE tenant_id=$1"
	args := []interface{}{tid}
	if htype != "" { where += " AND type=$2"; args = append(args, htype) }

	rows, _ := database.DB.Query(fmt.Sprintf(`
		SELECT id,name,type,subtype,value,location,owner,watchlist_category,
		       triggered,trigger_count,last_triggered,status,created_at
		FROM deception_honeytokens %s ORDER BY trigger_count DESC LIMIT $%d`,
		where, len(args)+1), append(args, limit)...)
	defer rows.Close()

	type HT struct {
		ID                int     `json:"id"`
		Name              string  `json:"name"`
		Type              string  `json:"type"`
		Subtype           string  `json:"subtype"`
		Value             string  `json:"value"`
		Location          string  `json:"location"`
		Owner             string  `json:"owner"`
		WatchlistCategory string  `json:"watchlist_category"`
		Triggered         bool    `json:"triggered"`
		TriggerCount      int     `json:"trigger_count"`
		LastTriggered     *string `json:"last_triggered"`
		Status            string  `json:"status"`
		CreatedAt         string  `json:"created_at"`
	}
	out := []HT{}
	for rows.Next() {
		var h HT
		rows.Scan(&h.ID, &h.Name, &h.Type, &h.Subtype, &h.Value, &h.Location, &h.Owner,
			&h.WatchlistCategory, &h.Triggered, &h.TriggerCount, &h.LastTriggered, &h.Status, &h.CreatedAt)
		out = append(out, h)
	}
	c.JSON(http.StatusOK, out)
}

func PostDeceptionHoneytoken(c *gin.Context) {
	createDeceptionTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Name              string `json:"name"`
		Type              string `json:"type"`
		Subtype           string `json:"subtype"`
		Value             string `json:"value"`
		Location          string `json:"location"`
		Owner             string `json:"owner"`
		WatchlistCategory string `json:"watchlist_category"`
	}
	c.ShouldBindJSON(&body)
	var id int
	database.DB.QueryRow(`
		INSERT INTO deception_honeytokens (tenant_id,name,type,subtype,value,location,owner,watchlist_category)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		tid, body.Name, body.Type, body.Subtype, body.Value, body.Location, body.Owner, body.WatchlistCategory).Scan(&id)
	c.JSON(http.StatusOK, gin.H{"id": id, "ok": true})
}

func DeleteDeceptionHoneytoken(c *gin.Context) {
	tid := tenantIDFromContext(c)
	hid, _ := strconv.Atoi(c.Param("id"))
	database.DB.Exec(`DELETE FROM deception_honeytokens WHERE tenant_id=$1 AND id=$2`, tid, hid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── Triggers ──────────────────────────────────────────────────────────────────

func GetDeceptionTriggers(c *gin.Context) {
	createDeceptionTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 200)
	etype := c.Query("event_type")
	severity := c.Query("severity")

	where := "WHERE t.tenant_id=$1"
	args := []interface{}{tid}
	n := 2
	if etype != "" { where += fmt.Sprintf(" AND t.event_type=$%d", n); args = append(args, etype); n++ }
	if severity != "" { where += fmt.Sprintf(" AND t.severity=$%d", n); args = append(args, severity); n++ }

	rows, _ := database.DB.Query(fmt.Sprintf(`
		SELECT t.id, t.event_type, t.attacker_ip, t.attacker_user, t.source_host,
		       t.severity, t.responded, t.campaign_id, t.created_at,
		       COALESCE(d.name,''), COALESCE(d.type,''),
		       COALESCE(h.name,''), COALESCE(h.type,'')
		FROM deception_triggers t
		LEFT JOIN deception_decoys d ON d.id=t.decoy_id
		LEFT JOIN deception_honeytokens h ON h.id=t.honeytoken_id
		%s ORDER BY t.created_at DESC LIMIT $%d`, where, n),
		append(args, limit)...)
	defer rows.Close()

	type Trig struct {
		ID          int     `json:"id"`
		EventType   string  `json:"event_type"`
		AttackerIP  string  `json:"attacker_ip"`
		AttackerUser string `json:"attacker_user"`
		SourceHost  string  `json:"source_host"`
		Severity    string  `json:"severity"`
		Responded   bool    `json:"responded"`
		CampaignID  *int    `json:"campaign_id"`
		CreatedAt   string  `json:"created_at"`
		DecoyName   string  `json:"decoy_name"`
		DecoyType   string  `json:"decoy_type"`
		TokenName   string  `json:"token_name"`
		TokenType   string  `json:"token_type"`
	}
	out := []Trig{}
	for rows.Next() {
		var r Trig
		rows.Scan(&r.ID, &r.EventType, &r.AttackerIP, &r.AttackerUser, &r.SourceHost,
			&r.Severity, &r.Responded, &r.CampaignID, &r.CreatedAt,
			&r.DecoyName, &r.DecoyType, &r.TokenName, &r.TokenType)
		out = append(out, r)
	}
	c.JSON(http.StatusOK, out)
}

// ── Campaigns ─────────────────────────────────────────────────────────────────

func GetDeceptionCampaigns(c *gin.Context) {
	createDeceptionTables()
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(`
		SELECT id,name,attacker_ip,attacker_user,decoys_hit,tokens_triggered,
		       malware_family,status,severity,mitre_techniques,started_at,ended_at
		FROM deception_campaigns WHERE tenant_id=$1 ORDER BY started_at DESC LIMIT 50`, tid)
	defer rows.Close()

	type Camp struct {
		ID              int     `json:"id"`
		Name            string  `json:"name"`
		AttackerIP      string  `json:"attacker_ip"`
		AttackerUser    string  `json:"attacker_user"`
		DecoysHit       int     `json:"decoys_hit"`
		TokensTriggered int     `json:"tokens_triggered"`
		MalwareFamily   string  `json:"malware_family"`
		Status          string  `json:"status"`
		Severity        string  `json:"severity"`
		MitreTechniques string  `json:"mitre_techniques"`
		StartedAt       string  `json:"started_at"`
		EndedAt         *string `json:"ended_at"`
	}
	out := []Camp{}
	for rows.Next() {
		var r Camp
		rows.Scan(&r.ID, &r.Name, &r.AttackerIP, &r.AttackerUser, &r.DecoysHit, &r.TokensTriggered,
			&r.MalwareFamily, &r.Status, &r.Severity, &r.MitreTechniques, &r.StartedAt, &r.EndedAt)
		out = append(out, r)
	}
	c.JSON(http.StatusOK, out)
}

// ── Timeline ──────────────────────────────────────────────────────────────────

func GetDeceptionTimeline(c *gin.Context) {
	createDeceptionTables()
	tid := tenantIDFromContext(c)
	campaignID := c.Query("campaign_id")
	limit := parseLimit(c, 200)

	where := "WHERE t.tenant_id=$1"
	args := []interface{}{tid}
	if campaignID != "" { where += " AND t.campaign_id=$2"; args = append(args, campaignID) }

	rows, _ := database.DB.Query(fmt.Sprintf(`
		SELECT t.id, t.event_type, t.attacker_ip, t.attacker_user, t.source_host,
		       t.severity, t.created_at,
		       COALESCE(d.name,''), COALESCE(h.name,''), COALESCE(c.name,'')
		FROM deception_triggers t
		LEFT JOIN deception_decoys d ON d.id=t.decoy_id
		LEFT JOIN deception_honeytokens h ON h.id=t.honeytoken_id
		LEFT JOIN deception_campaigns c ON c.id=t.campaign_id
		%s ORDER BY t.created_at ASC LIMIT $%d`, where, len(args)+1),
		append(args, limit)...)
	defer rows.Close()

	type TL struct {
		ID           int    `json:"id"`
		EventType    string `json:"event_type"`
		AttackerIP   string `json:"attacker_ip"`
		AttackerUser string `json:"attacker_user"`
		SourceHost   string `json:"source_host"`
		Severity     string `json:"severity"`
		CreatedAt    string `json:"created_at"`
		DecoyName    string `json:"decoy_name"`
		TokenName    string `json:"token_name"`
		CampaignName string `json:"campaign_name"`
	}
	out := []TL{}
	for rows.Next() {
		var r TL
		rows.Scan(&r.ID, &r.EventType, &r.AttackerIP, &r.AttackerUser, &r.SourceHost,
			&r.Severity, &r.CreatedAt, &r.DecoyName, &r.TokenName, &r.CampaignName)
		out = append(out, r)
	}
	c.JSON(http.StatusOK, out)
}

// ── Relationship Graph ────────────────────────────────────────────────────────

func GetDeceptionGraph(c *gin.Context) {
	createDeceptionTables()
	tid := tenantIDFromContext(c)

	nodes := []map[string]interface{}{}
	edges := []map[string]interface{}{}

	// Attacker nodes from unique IPs
	ipRows, _ := database.DB.Query(`
		SELECT DISTINCT attacker_ip, COUNT(*) as hits FROM deception_triggers
		WHERE tenant_id=$1 AND attacker_ip!='' GROUP BY attacker_ip LIMIT 20`, tid)
	defer ipRows.Close()
	attackerIDs := map[string]string{}
	for ipRows.Next() {
		var ip string; var hits int
		ipRows.Scan(&ip, &hits)
		nodeID := "atk-" + ip
		attackerIDs[ip] = nodeID
		nodes = append(nodes, map[string]interface{}{"id": nodeID, "label": ip, "type": "attacker", "hits": hits})
	}

	// Decoy nodes
	drows, _ := database.DB.Query(`
		SELECT id,name,type,trigger_count FROM deception_decoys
		WHERE tenant_id=$1 AND trigger_count>0 LIMIT 30`, tid)
	defer drows.Close()
	for drows.Next() {
		var id int; var name, dtype string; var tc int
		drows.Scan(&id, &name, &dtype, &tc)
		nodes = append(nodes, map[string]interface{}{"id": fmt.Sprintf("dec-%d", id), "label": name, "type": "decoy", "subtype": dtype, "trigger_count": tc})
	}

	// Token nodes
	trows2, _ := database.DB.Query(`
		SELECT id,name,type FROM deception_honeytokens
		WHERE tenant_id=$1 AND triggered=true LIMIT 20`, tid)
	defer trows2.Close()
	for trows2.Next() {
		var id int; var name, htype string
		trows2.Scan(&id, &name, &htype)
		nodes = append(nodes, map[string]interface{}{"id": fmt.Sprintf("tok-%d", id), "label": name, "type": "honeytoken", "subtype": htype})
	}

	// Edges from triggers
	erows, _ := database.DB.Query(`
		SELECT attacker_ip, decoy_id, honeytoken_id, event_type, severity
		FROM deception_triggers WHERE tenant_id=$1 LIMIT 50`, tid)
	defer erows.Close()
	for erows.Next() {
		var ip string; var decoyID, tokenID *int; var etype, sev string
		erows.Scan(&ip, &decoyID, &tokenID, &etype, &sev)
		src := attackerIDs[ip]
		if src == "" { continue }
		if decoyID != nil {
			edges = append(edges, map[string]interface{}{"source": src, "target": fmt.Sprintf("dec-%d", *decoyID), "label": etype, "severity": sev})
		}
		if tokenID != nil {
			edges = append(edges, map[string]interface{}{"source": src, "target": fmt.Sprintf("tok-%d", *tokenID), "label": etype, "severity": sev})
		}
	}

	c.JSON(http.StatusOK, gin.H{"nodes": nodes, "edges": edges})
}

// ── Threat Intelligence ───────────────────────────────────────────────────────

func GetDeceptionThreatIntel(c *gin.Context) {
	createDeceptionTables()
	tid := tenantIDFromContext(c)
	ip := c.Query("ip")

	// Gather attacker context
	var triggerCount, decoysHit int
	database.DB.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT decoy_id) FROM deception_triggers WHERE tenant_id=$1 AND attacker_ip=$2`, tid, ip).Scan(&triggerCount, &decoysHit)

	prompt := fmt.Sprintf(`You are a threat intelligence analyst. An IP address "%s" has triggered %d deception assets and hit %d decoys in an enterprise environment.

Provide threat intelligence enrichment in JSON with: ip_reputation (clean/suspicious/malicious), confidence (0-100), threat_actor, campaign, malware_families (array), ttps (array of MITRE technique IDs), ioc_matches (array of {type,value,source}), geo_country, geo_city, asn, org, first_seen, last_seen, risk_score (0-100), recommended_actions (array).`, ip, triggerCount, decoysHit)

	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"ip": ip, "error": "intel unavailable"})
		return
	}
	if idx := strings.Index(raw, "```json"); idx != -1 { raw = raw[idx+7:] } else if idx := strings.Index(raw, "```"); idx != -1 { raw = raw[idx+3:] }
	if idx := strings.LastIndex(raw, "```"); idx != -1 { raw = raw[:idx] }
	c.Data(http.StatusOK, "application/json", []byte(strings.TrimSpace(raw)))
}

// ── AI Analysis ───────────────────────────────────────────────────────────────

func PostDeceptionAI(c *gin.Context) {
	createDeceptionTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Mode       string `json:"mode"`
		CampaignID int    `json:"campaign_id"`
		TriggerID  int    `json:"trigger_id"`
		AttackerIP string `json:"attacker_ip"`
		Question   string `json:"question"`
	}
	c.ShouldBindJSON(&body)

	// Gather context
	var ctx string
	if body.AttackerIP != "" {
		var tc int
		database.DB.QueryRow(`SELECT COUNT(*) FROM deception_triggers WHERE tenant_id=$1 AND attacker_ip=$2`, tid, body.AttackerIP).Scan(&tc)
		ctx = fmt.Sprintf("Attacker IP: %s, Total triggers: %d", body.AttackerIP, tc)
	}

	var prompt string
	switch body.Mode {
	case "summarize":
		prompt = fmt.Sprintf(`Summarize this deception engagement in 3-4 sentences for a SOC analyst. Context: %s. Include attacker behavior, objectives, and confidence level. Return JSON: {summary, confidence, key_findings (array), attack_stage}`, ctx)
	case "attribution":
		prompt = fmt.Sprintf(`Analyze for threat actor attribution. Context: %s. Return JSON: {threat_actor, confidence, evidence (array), similar_campaigns (array), recommended_hunts (array)}`, ctx)
	case "recommend":
		prompt = fmt.Sprintf(`Recommend response actions for this deception trigger. Context: %s. Return JSON: {immediate_actions (array), investigation_steps (array), additional_decoys (array), soar_playbook}`, ctx)
	case "attack_path":
		prompt = fmt.Sprintf(`Reconstruct the attacker's path through deception assets. Context: %s. Return JSON: {steps (array of {step,asset,technique,time}), objective, next_likely_step, detection_confidence}`, ctx)
	default:
		prompt = fmt.Sprintf(`Question about deception engagement: %s. Context: %s. Return JSON: {answer, confidence, related_mitre (array)}`, body.Question, ctx)
	}

	raw, err := services.CallLLM(prompt)
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
	if idx := strings.Index(raw, "```json"); idx != -1 { raw = raw[idx+7:] } else if idx := strings.Index(raw, "```"); idx != -1 { raw = raw[idx+3:] }
	if idx := strings.LastIndex(raw, "```"); idx != -1 { raw = raw[:idx] }
	c.Data(http.StatusOK, "application/json", []byte(strings.TrimSpace(raw)))
}

// ── Health ────────────────────────────────────────────────────────────────────

func GetDeceptionHealth(c *gin.Context) {
	createDeceptionTables()
	tid := tenantIDFromContext(c)

	rows, _ := database.DB.Query(`
		SELECT id,name,type,status,health,trigger_count,last_triggered,last_heartbeat,version,integrity_ok,location
		FROM deception_decoys WHERE tenant_id=$1 ORDER BY health ASC, last_heartbeat ASC NULLS FIRST`, tid)
	defer rows.Close()

	type Health struct {
		ID            int     `json:"id"`
		Name          string  `json:"name"`
		Type          string  `json:"type"`
		Status        string  `json:"status"`
		Health        string  `json:"health"`
		TriggerCount  int     `json:"trigger_count"`
		LastTriggered *string `json:"last_triggered"`
		LastHeartbeat *string `json:"last_heartbeat"`
		Version       string  `json:"version"`
		IntegrityOK   bool    `json:"integrity_ok"`
		Location      string  `json:"location"`
	}
	out := []Health{}
	for rows.Next() {
		var h Health
		rows.Scan(&h.ID, &h.Name, &h.Type, &h.Status, &h.Health, &h.TriggerCount,
			&h.LastTriggered, &h.LastHeartbeat, &h.Version, &h.IntegrityOK, &h.Location)
		out = append(out, h)
	}

	var online, offline, degraded int
	for _, h := range out {
		switch h.Health {
		case "online": online++
		case "offline": offline++
		default: degraded++
		}
	}
	c.JSON(http.StatusOK, gin.H{"decoys": out, "online": online, "offline": offline, "degraded": degraded})
}

// ── Response Actions ──────────────────────────────────────────────────────────

func PostDeceptionResponse(c *gin.Context) {
	createDeceptionTables()
	tid := tenantIDFromContext(c)
	var body struct {
		TriggerID  int    `json:"trigger_id"`
		Action     string `json:"action"`
		AttackerIP string `json:"attacker_ip"`
		UserID     string `json:"user_id"`
		AgentID    int    `json:"agent_id"`
	}
	c.ShouldBindJSON(&body)
	username := usernameFromContext(c)

	switch body.Action {
	case "isolate_endpoint":
		if body.AgentID > 0 {
			database.DB.Exec(`INSERT INTO playbook_tasks (tenant_id,playbook_id,agent_id,action,status,requested_by,expires_at)
				VALUES ($1,0,$2,'isolate','pending',$3,NOW()+INTERVAL '15 min')`, tid, body.AgentID, username)
		}
	case "block_ip":
		database.DB.Exec(`INSERT INTO firewall_rules (tenant_id,name,direction,action,src_ip,enabled)
			VALUES ($1,$2,'in','drop',$3,true)`, tid, "deception-block-"+body.AttackerIP, body.AttackerIP)
	case "disable_user":
		database.DB.Exec(`UPDATE users SET is_active=false WHERE tenant_id=$1 AND username=$2`, tid, body.UserID)
	case "create_alert":
		database.DB.Exec(`INSERT INTO alerts (tenant_id,title,severity,status,description,mitre_technique)
			VALUES ($1,'Deception Asset Triggered','high','open',$2,'T1078')`,
			tid, fmt.Sprintf("Attacker %s triggered deception asset", body.AttackerIP))
	case "collect_memory":
		if body.AgentID > 0 {
			database.DB.Exec(`INSERT INTO playbook_tasks (tenant_id,playbook_id,agent_id,action,status,requested_by,expires_at)
				VALUES ($1,0,$2,'collect_memory','pending',$3,NOW()+INTERVAL '15 min')`, tid, body.AgentID, username)
		}
	}

	if body.TriggerID > 0 {
		database.DB.Exec(`UPDATE deception_triggers SET responded=true, response_actions=$1 WHERE tenant_id=$2 AND id=$3`,
			body.Action, tid, body.TriggerID)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action})
}

// ── Analytics ─────────────────────────────────────────────────────────────────

func GetDeceptionAnalytics(c *gin.Context) {
	createDeceptionTables()
	tid := tenantIDFromContext(c)

	// Most triggered decoys
	topDecoys := []map[string]interface{}{}
	dr, _ := database.DB.Query(`SELECT name,type,trigger_count FROM deception_decoys WHERE tenant_id=$1 ORDER BY trigger_count DESC LIMIT 10`, tid)
	defer dr.Close()
	for dr.Next() {
		var name, dtype string; var tc int
		dr.Scan(&name, &dtype, &tc)
		topDecoys = append(topDecoys, map[string]interface{}{"name": name, "type": dtype, "trigger_count": tc})
	}

	// Most targeted credentials
	topTokens := []map[string]interface{}{}
	tr, _ := database.DB.Query(`SELECT name,type,trigger_count FROM deception_honeytokens WHERE tenant_id=$1 ORDER BY trigger_count DESC LIMIT 10`, tid)
	defer tr.Close()
	for tr.Next() {
		var name, htype string; var tc int
		tr.Scan(&name, &htype, &tc)
		topTokens = append(topTokens, map[string]interface{}{"name": name, "type": htype, "trigger_count": tc})
	}

	// Top attack sources
	topSources := []map[string]interface{}{}
	sr, _ := database.DB.Query(`SELECT attacker_ip, COUNT(*) as hits FROM deception_triggers WHERE tenant_id=$1 AND attacker_ip!='' GROUP BY attacker_ip ORDER BY hits DESC LIMIT 10`, tid)
	defer sr.Close()
	for sr.Next() {
		var ip string; var hits int
		sr.Scan(&ip, &hits)
		topSources = append(topSources, map[string]interface{}{"ip": ip, "hits": hits})
	}

	// Event type breakdown
	byType := []map[string]interface{}{}
	etr, _ := database.DB.Query(`SELECT event_type, COUNT(*) FROM deception_triggers WHERE tenant_id=$1 GROUP BY event_type ORDER BY COUNT(*) DESC`, tid)
	defer etr.Close()
	for etr.Next() {
		var etype string; var cnt int
		etr.Scan(&etype, &cnt)
		byType = append(byType, map[string]interface{}{"event_type": etype, "count": cnt})
	}

	// Daily trend (30 days)
	daily := []map[string]interface{}{}
	dailyr, _ := database.DB.Query(`SELECT DATE(created_at), COUNT(*) FROM deception_triggers WHERE tenant_id=$1 AND created_at>NOW()-INTERVAL '30 days' GROUP BY DATE(created_at) ORDER BY 1`, tid)
	defer dailyr.Close()
	for dailyr.Next() {
		var d string; var cnt int
		dailyr.Scan(&d, &cnt)
		daily = append(daily, map[string]interface{}{"date": d, "count": cnt})
	}

	c.JSON(http.StatusOK, gin.H{
		"top_decoys":   topDecoys,
		"top_tokens":   topTokens,
		"top_sources":  topSources,
		"by_event_type": byType,
		"daily":        daily,
	})
}

// ── Watchlists ────────────────────────────────────────────────────────────────

func GetDeceptionWatchlists(c *gin.Context) {
	createDeceptionTables()
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(`SELECT id,category,item,item_type,priority,notes,created_at FROM deception_watchlists WHERE tenant_id=$1 ORDER BY category,priority`, tid)
	defer rows.Close()

	type WL struct {
		ID       int    `json:"id"`
		Category string `json:"category"`
		Item     string `json:"item"`
		ItemType string `json:"item_type"`
		Priority string `json:"priority"`
		Notes    string `json:"notes"`
		CreatedAt string `json:"created_at"`
	}
	out := []WL{}
	for rows.Next() {
		var w WL
		rows.Scan(&w.ID, &w.Category, &w.Item, &w.ItemType, &w.Priority, &w.Notes, &w.CreatedAt)
		out = append(out, w)
	}
	c.JSON(http.StatusOK, out)
}

func PostDeceptionWatchlist(c *gin.Context) {
	createDeceptionTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Category string `json:"category"`
		Item     string `json:"item"`
		ItemType string `json:"item_type"`
		Priority string `json:"priority"`
		Notes    string `json:"notes"`
	}
	c.ShouldBindJSON(&body)
	if body.Priority == "" { body.Priority = "high" }
	var id int
	database.DB.QueryRow(`INSERT INTO deception_watchlists (tenant_id,category,item,item_type,priority,notes) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		tid, body.Category, body.Item, body.ItemType, body.Priority, body.Notes).Scan(&id)
	c.JSON(http.StatusOK, gin.H{"id": id, "ok": true})
}

func DeleteDeceptionWatchlist(c *gin.Context) {
	tid := tenantIDFromContext(c)
	wid, _ := strconv.Atoi(c.Param("id"))
	database.DB.Exec(`DELETE FROM deception_watchlists WHERE tenant_id=$1 AND id=$2`, tid, wid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── Policies ──────────────────────────────────────────────────────────────────

func GetDeceptionPolicies(c *gin.Context) {
	createDeceptionTables()
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(`SELECT id,name,decoy_types,locations,lifetime_days,rotation_days,alert_threshold,auto_cleanup,enabled,created_at FROM deception_policies WHERE tenant_id=$1 ORDER BY name`, tid)
	defer rows.Close()

	type Pol struct {
		ID             int    `json:"id"`
		Name           string `json:"name"`
		DecoyTypes     string `json:"decoy_types"`
		Locations      string `json:"locations"`
		LifetimeDays   int    `json:"lifetime_days"`
		RotationDays   int    `json:"rotation_days"`
		AlertThreshold int    `json:"alert_threshold"`
		AutoCleanup    bool   `json:"auto_cleanup"`
		Enabled        bool   `json:"enabled"`
		CreatedAt      string `json:"created_at"`
	}
	out := []Pol{}
	for rows.Next() {
		var p Pol
		rows.Scan(&p.ID, &p.Name, &p.DecoyTypes, &p.Locations, &p.LifetimeDays, &p.RotationDays, &p.AlertThreshold, &p.AutoCleanup, &p.Enabled, &p.CreatedAt)
		out = append(out, p)
	}
	c.JSON(http.StatusOK, out)
}

func PostDeceptionPolicy(c *gin.Context) {
	createDeceptionTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Name           string `json:"name"`
		DecoyTypes     string `json:"decoy_types"`
		Locations      string `json:"locations"`
		LifetimeDays   int    `json:"lifetime_days"`
		RotationDays   int    `json:"rotation_days"`
		AlertThreshold int    `json:"alert_threshold"`
		AutoCleanup    bool   `json:"auto_cleanup"`
	}
	c.ShouldBindJSON(&body)
	if body.LifetimeDays == 0 { body.LifetimeDays = 30 }
	if body.RotationDays == 0 { body.RotationDays = 7 }
	if body.AlertThreshold == 0 { body.AlertThreshold = 1 }
	var id int
	database.DB.QueryRow(`INSERT INTO deception_policies (tenant_id,name,decoy_types,locations,lifetime_days,rotation_days,alert_threshold,auto_cleanup) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		tid, body.Name, body.DecoyTypes, body.Locations, body.LifetimeDays, body.RotationDays, body.AlertThreshold, body.AutoCleanup).Scan(&id)
	c.JSON(http.StatusOK, gin.H{"id": id, "ok": true})
}

func DeleteDeceptionPolicy(c *gin.Context) {
	tid := tenantIDFromContext(c)
	pid, _ := strconv.Atoi(c.Param("id"))
	database.DB.Exec(`DELETE FROM deception_policies WHERE tenant_id=$1 AND id=$2`, tid, pid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── Report ────────────────────────────────────────────────────────────────────

func PostDeceptionReport(c *gin.Context) {
	createDeceptionTables()
	tid := tenantIDFromContext(c)
	var body struct {
		ReportType string `json:"report_type"`
		DateFrom   string `json:"date_from"`
		DateTo     string `json:"date_to"`
	}
	c.ShouldBindJSON(&body)

	var totalTriggers, campaigns, decoysDeployed int
	database.DB.QueryRow(`SELECT COUNT(*) FROM deception_triggers WHERE tenant_id=$1`, tid).Scan(&totalTriggers)
	database.DB.QueryRow(`SELECT COUNT(*) FROM deception_campaigns WHERE tenant_id=$1`, tid).Scan(&campaigns)
	database.DB.QueryRow(`SELECT COUNT(*) FROM deception_decoys WHERE tenant_id=$1`, tid).Scan(&decoysDeployed)

	prompt := fmt.Sprintf(`Generate a %s deception report for an enterprise security team.
Context: %d total trigger events, %d attack campaigns detected, %d decoys deployed.
Return JSON: {title, executive_summary, key_findings (array), attack_timeline (array of {time,event}), mitre_coverage (array), recommendations (array), metrics:{total_triggers,campaigns,decoys_deployed,avg_dwell_time_hours}}`,
		body.ReportType, totalTriggers, campaigns, decoysDeployed)

	raw, err := services.CallLLM(prompt)
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
	if idx := strings.Index(raw, "```json"); idx != -1 { raw = raw[idx+7:] } else if idx := strings.Index(raw, "```"); idx != -1 { raw = raw[idx+3:] }
	if idx := strings.LastIndex(raw, "```"); idx != -1 { raw = raw[:idx] }
	c.Data(http.StatusOK, "application/json", []byte(strings.TrimSpace(raw)))
}

// ── Templates ─────────────────────────────────────────────────────────────────

func GetDeceptionTemplates(c *gin.Context) {
	templates := []map[string]interface{}{
		{"id": "windows-file-server",   "name": "Windows File Server",   "type": "server",      "protocol": "smb",            "platform": "windows", "description": "Mimics a Windows file server with enticing shares and documents"},
		{"id": "linux-ssh",             "name": "Linux SSH Server",       "type": "server",      "protocol": "ssh",            "platform": "linux",   "description": "Low-interaction SSH honeypot that logs all authentication attempts"},
		{"id": "ad-domain-controller",  "name": "Active Directory DC",    "type": "ad_object",   "protocol": "ldap",           "platform": "windows", "description": "Fake Domain Controller with enticing privileged accounts"},
		{"id": "sql-database",          "name": "SQL Database",           "type": "database",    "protocol": "sql",            "platform": "windows", "description": "Fake SQL server with realistic-looking database credentials"},
		{"id": "web-application",       "name": "Web Application",        "type": "application", "protocol": "http",           "platform": "linux",   "description": "Fake web application with enticing admin panels and API endpoints"},
		{"id": "kubernetes-cluster",    "name": "Kubernetes Cluster",     "type": "container",   "protocol": "kubernetes_api", "platform": "linux",   "description": "Fake Kubernetes API server to catch cloud-native attackers"},
		{"id": "aws-environment",       "name": "AWS Environment",        "type": "cloud",       "protocol": "api",            "platform": "cloud",   "description": "Fake AWS environment with enticing S3 buckets and IAM credentials"},
		{"id": "azure-environment",     "name": "Azure Environment",      "type": "cloud",       "protocol": "api",            "platform": "cloud",   "description": "Fake Azure environment with enticing storage accounts and secrets"},
	}
	c.JSON(http.StatusOK, templates)
}
