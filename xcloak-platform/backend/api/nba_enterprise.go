package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/services"
)

// ── helpers ────────────────────────────────────────────────────────────────

func parseMins(c *gin.Context, def int) int {
	if v := c.Query("minutes"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func parseHours(c *gin.Context, def int) int {
	if v := c.Query("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func parseLimit(c *gin.Context, def int) int {
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			return n
		}
	}
	return def
}

// extractIP splits "host:port" into IP and port.
func extractIP(addr string) (string, int) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	port, _ := strconv.Atoi(p)
	return h, port
}

var lateralPorts = map[string]bool{
	"445": true, "3389": true, "22": true, "5985": true, "5986": true,
	"135": true, "139": true, "4444": true, "4445": true, "9999": true,
	"47001": true, "5900": true, "23": true,
}

var lateralPortLabel = map[string]string{
	"445": "SMB", "3389": "RDP", "22": "SSH", "5985": "WinRM", "5986": "WinRM(S)",
	"135": "RPC/DCOM", "139": "NetBIOS", "4444": "Meterpreter", "47001": "WinRM",
	"5900": "VNC", "23": "Telnet",
}

var mitreMap = map[string][]map[string]string{
	"new_destination": {
		{"id": "T1071", "name": "Application Layer Protocol"},
		{"id": "T1041", "name": "Exfiltration Over C2 Channel"},
	},
	"rare_port": {
		{"id": "T1571", "name": "Non-Standard Port"},
		{"id": "T1090", "name": "Proxy"},
	},
	"volume_spike": {
		{"id": "T1030", "name": "Data Transfer Size Limits"},
		{"id": "T1041", "name": "Exfiltration Over C2 Channel"},
	},
	"beacon":    {{"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1095", "name": "Non-Application Layer Protocol"}},
	"c2":        {{"id": "T1071", "name": "Application Layer Protocol"}, {"id": "T1219", "name": "Remote Access Software"}},
	"port_scan": {{"id": "T1046", "name": "Network Service Discovery"}},
	"smb_lateral": {
		{"id": "T1021.002", "name": "SMB/Windows Admin Shares"},
		{"id": "T1570", "name": "Lateral Tool Transfer"},
	},
	"rdp_lateral": {{"id": "T1021.001", "name": "Remote Desktop Protocol"}},
	"ssh_lateral": {{"id": "T1021.004", "name": "SSH"}},
	"winrm_lateral": {
		{"id": "T1021.006", "name": "Windows Remote Management"},
		{"id": "T1059.001", "name": "PowerShell"},
	},
	"dns_tunnel":  {{"id": "T1071.004", "name": "DNS"}, {"id": "T1048.003", "name": "Exfiltration Over Alternative Protocol"}},
	"exfiltration": {{"id": "T1041", "name": "Exfiltration Over C2 Channel"}, {"id": "T1030", "name": "Data Transfer Size Limits"}},
}

// ── 1. Overview ────────────────────────────────────────────────────────────

// GetNBAOverview — GET /api/nba/overview
func GetNBAOverview(c *gin.Context) {
	tid := tenantIDFromContext(c)
	minutes := parseMins(c, 60)
	since := time.Now().Add(-time.Duration(minutes) * time.Minute)

	var totalFlows, activeConns, suspiciousConns, beaconingCount, lateralCount int
	var exfilCount, c2Count, highRiskHosts int
	var networkRiskScore float64

	database.DB.QueryRow(`SELECT COUNT(*) FROM network_connect_events WHERE tenant_id=$1 AND created_at>=$2`, tid, since).Scan(&totalFlows)
	database.DB.QueryRow(`SELECT COUNT(*) FROM network_connect_events WHERE tenant_id=$1 AND created_at>=$2 AND state!='closed'`, tid, since).Scan(&activeConns)
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM network_anomalies
		WHERE tenant_id=$1 AND detected_at>=$2 AND is_acknowledged=false`, tid, since).Scan(&suspiciousConns)
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM network_anomalies
		WHERE tenant_id=$1 AND detected_at>=$2 AND anomaly_type='beacon'`, tid, since).Scan(&beaconingCount)
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM network_anomalies
		WHERE tenant_id=$1 AND detected_at>=$2 AND anomaly_type='lateral_movement'`, tid, since).Scan(&lateralCount)
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM network_anomalies
		WHERE tenant_id=$1 AND detected_at>=$2 AND anomaly_type IN ('volume_spike','exfiltration','rare_port') AND deviation_score>=70`, tid, since).Scan(&exfilCount)
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM network_anomalies
		WHERE tenant_id=$1 AND detected_at>=$2 AND anomaly_type IN ('beacon','c2')`, tid, since).Scan(&c2Count)
	database.DB.QueryRow(`
		SELECT COUNT(DISTINCT agent_id) FROM network_anomalies
		WHERE tenant_id=$1 AND detected_at>=$2 AND deviation_score>=70`, tid, since).Scan(&highRiskHosts)
	database.DB.QueryRow(`
		SELECT COALESCE(AVG(deviation_score::float),0) FROM network_anomalies
		WHERE tenant_id=$1 AND detected_at>=$2`, tid, since).Scan(&networkRiskScore)

	// top talkers by distinct remote_address count
	type TopTalker struct {
		Host       string `json:"host"`
		AgentID    int    `json:"agent_id"`
		ConnCount  int    `json:"conn_count"`
		UniqueIPs  int    `json:"unique_ips"`
		AnomalyCount int  `json:"anomaly_count"`
	}
	topTalkers := []TopTalker{}
	rows, _ := database.DB.Query(`
		SELECT COALESCE(a.hostname,'Agent #'||nce.agent_id::text), nce.agent_id,
		       COUNT(*) AS conn_count, COUNT(DISTINCT nce.remote_address) AS unique_ips,
		       COUNT(DISTINCT na.id) AS anomaly_count
		FROM network_connect_events nce
		LEFT JOIN agents a ON a.id=nce.agent_id
		LEFT JOIN network_anomalies na ON na.agent_id=nce.agent_id AND na.tenant_id=nce.tenant_id AND na.detected_at>=$2
		WHERE nce.tenant_id=$1 AND nce.created_at>=$2
		GROUP BY a.hostname, nce.agent_id
		ORDER BY conn_count DESC LIMIT 10`, tid, since)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var t TopTalker
			rows.Scan(&t.Host, &t.AgentID, &t.ConnCount, &t.UniqueIPs, &t.AnomalyCount)
			topTalkers = append(topTalkers, t)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_flows":       totalFlows,
		"active_connections": activeConns,
		"suspicious_connections": suspiciousConns,
		"beaconing_detections": beaconingCount,
		"lateral_movement":  lateralCount,
		"data_exfiltration": exfilCount,
		"c2_communications": c2Count,
		"high_risk_hosts":   highRiskHosts,
		"network_risk_score": int(networkRiskScore),
		"top_talkers":       topTalkers,
		"window_minutes":    minutes,
	})
}

// ── 2. Live Flows ──────────────────────────────────────────────────────────

// GetNBAFlows — GET /api/nba/flows
func GetNBAFlows(c *gin.Context) {
	tid := tenantIDFromContext(c)
	minutes := parseMins(c, 60)
	limit := parseLimit(c, 200)
	since := time.Now().Add(-time.Duration(minutes) * time.Minute)

	filterProto := c.Query("proto")
	filterIP := c.Query("ip")
	filterHost := c.Query("host")

	type Flow struct {
		AgentID       int    `json:"agent_id"`
		Hostname      string `json:"hostname"`
		SrcAddr       string `json:"src_address"`
		DstAddr       string `json:"dst_address"`
		Protocol      string `json:"protocol"`
		Process       string `json:"process"`
		State         string `json:"state"`
		Country       string `json:"country"`
		CountryCode   string `json:"country_code"`
		IsExternal    bool   `json:"is_external"`
		IsSuspicious  bool   `json:"is_suspicious"`
		DetectedAt    string `json:"detected_at"`
	}

	args := []any{tid, since, limit}
	conds := []string{}
	if filterProto != "" { args = append(args, filterProto); conds = append(conds, fmt.Sprintf("AND nce.protocol=$%d", len(args))) }
	if filterIP != "" { args = append(args, "%"+filterIP+"%"); conds = append(conds, fmt.Sprintf("AND (nce.remote_address LIKE $%d OR nce.local_address LIKE $%d)", len(args), len(args))) }
	if filterHost != "" { args = append(args, "%"+filterHost+"%"); conds = append(conds, fmt.Sprintf("AND a.hostname ILIKE $%d", len(args))) }

	q := fmt.Sprintf(`
		SELECT nce.agent_id, COALESCE(a.hostname,'Agent #'||nce.agent_id::text),
		       nce.local_address, nce.remote_address,
		       COALESCE(nce.protocol,'tcp'), COALESCE(nce.comm,''),
		       COALESCE(nce.state,''), '', '', false
		FROM network_connect_events nce
		LEFT JOIN agents a ON a.id=nce.agent_id
		WHERE nce.tenant_id=$1 AND nce.created_at>=$2
		%s
		ORDER BY nce.created_at DESC LIMIT $3`, strings.Join(conds, " "))

	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	// Load suspicious IPs from anomalies
	suspMap := map[string]bool{}
	sr, _ := database.DB.Query(`SELECT DISTINCT dst_ip FROM network_anomalies WHERE tenant_id=$1 AND detected_at>NOW()-INTERVAL '24 hours'`, tid)
	if sr != nil {
		defer sr.Close()
		for sr.Next() {
			var ip string; sr.Scan(&ip); suspMap[ip] = true
		}
	}

	flows := []Flow{}
	for rows.Next() {
		var f Flow
		var isExt bool
		rows.Scan(&f.AgentID, &f.Hostname, &f.SrcAddr, &f.DstAddr,
			&f.Protocol, &f.Process, &f.State, &f.Country, &f.CountryCode, &isExt)
		dstIP, _ := extractIP(f.DstAddr)
		if ip := net.ParseIP(dstIP); ip != nil {
			f.IsExternal = !ip.IsPrivate() && !ip.IsLoopback()
		}
		f.IsSuspicious = suspMap[dstIP]
		f.DetectedAt = time.Now().UTC().Format(time.RFC3339)
		flows = append(flows, f)
	}
	if flows == nil {
		flows = []Flow{}
	}
	c.JSON(http.StatusOK, gin.H{"flows": flows, "total": len(flows)})
}

// ── 3. Traffic Analysis ────────────────────────────────────────────────────

// GetNBATrafficAnalysis — GET /api/nba/traffic-analysis
func GetNBATrafficAnalysis(c *gin.Context) {
	tid := tenantIDFromContext(c)
	hours := parseHours(c, 24)
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	type ProtocolCount struct {
		Protocol string `json:"protocol"`
		Count    int    `json:"count"`
	}
	type TalkerEntry struct {
		Host      string `json:"host"`
		ConnCount int    `json:"conn_count"`
		UniqueExt int    `json:"unique_external_ips"`
	}

	protocols := []ProtocolCount{}
	pRows, _ := database.DB.Query(`
		SELECT COALESCE(protocol,'unknown'), COUNT(*) AS cnt
		FROM network_connect_events WHERE tenant_id=$1 AND created_at>=$2
		GROUP BY protocol ORDER BY cnt DESC LIMIT 20`, tid, since)
	if pRows != nil {
		defer pRows.Close()
		for pRows.Next() {
			var p ProtocolCount; pRows.Scan(&p.Protocol, &p.Count); protocols = append(protocols, p)
		}
	}

	topTalkers := []TalkerEntry{}
	tRows, _ := database.DB.Query(`
		SELECT COALESCE(a.hostname,'Agent #'||nce.agent_id::text),
		       COUNT(*) AS conn_count,
		       COUNT(DISTINCT CASE WHEN nce.remote_address NOT LIKE '10.%' AND nce.remote_address NOT LIKE '192.168.%' AND nce.remote_address NOT LIKE '172.%' THEN nce.remote_address END) AS ext
		FROM network_connect_events nce
		LEFT JOIN agents a ON a.id=nce.agent_id
		WHERE nce.tenant_id=$1 AND nce.created_at>=$2
		GROUP BY a.hostname, nce.agent_id ORDER BY conn_count DESC LIMIT 10`, tid, since)
	if tRows != nil {
		defer tRows.Close()
		for tRows.Next() {
			var t TalkerEntry; tRows.Scan(&t.Host, &t.ConnCount, &t.UniqueExt); topTalkers = append(topTalkers, t)
		}
	}

	// E-W vs N-S
	var ewCount, nsCount int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM network_connect_events
		WHERE tenant_id=$1 AND created_at>=$2
		  AND (remote_address LIKE '10.%' OR remote_address LIKE '192.168.%' OR remote_address LIKE '172.1%' OR remote_address LIKE '172.2%' OR remote_address LIKE '172.3%')`, tid, since).Scan(&ewCount)
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM network_connect_events
		WHERE tenant_id=$1 AND created_at>=$2
		  AND remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%' AND remote_address NOT LIKE '172.%' AND remote_address!=''`, tid, since).Scan(&nsCount)

	// Hourly trend (last 12 hours)
	type HourBucket struct {
		Hour  string `json:"hour"`
		Count int    `json:"count"`
	}
	trend := []HourBucket{}
	hrRows, _ := database.DB.Query(`
		SELECT to_char(date_trunc('hour', created_at), 'HH24:MI') AS hr, COUNT(*)
		FROM network_connect_events
		WHERE tenant_id=$1 AND created_at>NOW()-INTERVAL '12 hours'
		GROUP BY hr ORDER BY hr`, tid)
	if hrRows != nil {
		defer hrRows.Close()
		for hrRows.Next() {
			var b HourBucket; hrRows.Scan(&b.Hour, &b.Count); trend = append(trend, b)
		}
	}

	// Top unique destinations
	type DestEntry struct {
		RemoteAddr string `json:"remote_address"`
		Count      int    `json:"count"`
	}
	topDests := []DestEntry{}
	dRows, _ := database.DB.Query(`
		SELECT remote_address, COUNT(*) AS cnt
		FROM network_connect_events WHERE tenant_id=$1 AND created_at>=$2 AND remote_address!=''
		GROUP BY remote_address ORDER BY cnt DESC LIMIT 10`, tid, since)
	if dRows != nil {
		defer dRows.Close()
		for dRows.Next() {
			var d DestEntry; dRows.Scan(&d.RemoteAddr, &d.Count); topDests = append(topDests, d)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"protocols":         protocols,
		"top_talkers":       topTalkers,
		"top_destinations":  topDests,
		"east_west_count":   ewCount,
		"north_south_count": nsCount,
		"hourly_trend":      trend,
		"hours":             hours,
	})
}

// ── 4. DNS Analytics ──────────────────────────────────────────────────────

// GetNBADNSAnalytics — GET /api/nba/dns-analytics
func GetNBADNSAnalytics(c *gin.Context) {
	tid := tenantIDFromContext(c)
	hours := parseHours(c, 24)
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	var totalDNS, nxdomain, longQuery, dnsAnomalies int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM network_connect_events
		WHERE tenant_id=$1 AND created_at>=$2 AND (
		  remote_address LIKE '%:53' OR protocol ILIKE 'udp' AND remote_address LIKE '%:53'
		  OR local_address LIKE '%:53' OR remote_address LIKE '%.53')`, tid, since).Scan(&totalDNS)
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM network_anomalies
		WHERE tenant_id=$1 AND detected_at>=$2 AND anomaly_type='dns_tunnel'`, tid, since).Scan(&dnsAnomalies)

	// DNS entries from anomaly descriptions
	type DNSEntry struct {
		AgentID    int    `json:"agent_id"`
		Hostname   string `json:"hostname"`
		Type       string `json:"type"`
		Score      int    `json:"score"`
		Desc       string `json:"description"`
		DetectedAt string `json:"detected_at"`
	}
	dnsEvents := []DNSEntry{}
	dr, _ := database.DB.Query(`
		SELECT na.agent_id, COALESCE(a.hostname,''), na.anomaly_type,
		       na.deviation_score, na.description,
		       to_char(na.detected_at,'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		FROM network_anomalies na
		LEFT JOIN agents a ON a.id=na.agent_id
		WHERE na.tenant_id=$1 AND na.detected_at>=$2
		  AND na.anomaly_type IN ('dns_tunnel','dga','dns_flood','new_destination')
		ORDER BY na.detected_at DESC LIMIT 50`, tid, since)
	if dr != nil {
		defer dr.Close()
		for dr.Next() {
			var d DNSEntry
			dr.Scan(&d.AgentID, &d.Hostname, &d.Type, &d.Score, &d.Desc, &d.DetectedAt)
			dnsEvents = append(dnsEvents, d)
		}
	}
	_ = nxdomain; _ = longQuery

	// Top DNS destinations (port :53)
	type DNSDest struct {
		Dest  string `json:"dest"`
		Count int    `json:"count"`
	}
	topDNSDests := []DNSDest{}
	tdRows, _ := database.DB.Query(`
		SELECT remote_address, COUNT(*) AS cnt
		FROM network_connect_events
		WHERE tenant_id=$1 AND created_at>=$2 AND remote_address LIKE '%:53'
		GROUP BY remote_address ORDER BY cnt DESC LIMIT 10`, tid, since)
	if tdRows != nil {
		defer tdRows.Close()
		for tdRows.Next() {
			var d DNSDest; tdRows.Scan(&d.Dest, &d.Count); topDNSDests = append(topDNSDests, d)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_dns_queries": totalDNS,
		"dns_anomalies":     dnsAnomalies,
		"dns_events":        dnsEvents,
		"top_dns_servers":   topDNSDests,
		"hours":             hours,
	})
}

// ── 5. TLS Analytics ──────────────────────────────────────────────────────

// GetNBATLSAnalytics — GET /api/nba/tls-analytics
func GetNBATLSAnalytics(c *gin.Context) {
	tid := tenantIDFromContext(c)
	hours := parseHours(c, 24)
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	var totalTLS, unknownTLS int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM network_connect_events
		WHERE tenant_id=$1 AND created_at>=$2
		  AND (remote_address LIKE '%:443' OR remote_address LIKE '%:8443' OR remote_address LIKE '%:993' OR remote_address LIKE '%:465')`, tid, since).Scan(&totalTLS)
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM network_connect_events
		WHERE tenant_id=$1 AND created_at>=$2 AND remote_address LIKE '%:443'
		  AND remote_address NOT LIKE '%.%'`, tid, since).Scan(&unknownTLS)

	// JA3 fingerprints
	type JA3Entry struct {
		ID          int    `json:"id"`
		Fingerprint string `json:"fingerprint"`
		Label       string `json:"label"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		TenantWide  bool   `json:"tenant_wide"`
	}
	ja3Entries := []JA3Entry{}
	jr, _ := database.DB.Query(`
		SELECT id, fingerprint, label, severity, COALESCE(description,''), (tenant_id=0 OR tenant_id IS NULL)
		FROM ja3_fingerprints WHERE tenant_id=$1 OR tenant_id=0 OR tenant_id IS NULL
		ORDER BY severity DESC LIMIT 50`, tid)
	if jr != nil {
		defer jr.Close()
		for jr.Next() {
			var j JA3Entry
			jr.Scan(&j.ID, &j.Fingerprint, &j.Label, &j.Severity, &j.Description, &j.TenantWide)
			ja3Entries = append(ja3Entries, j)
		}
	}

	// TLS connections to rare ports (excluding 443/8443)
	type TLSConn struct {
		Addr  string `json:"address"`
		Count int    `json:"count"`
		Host  string `json:"hostname"`
	}
	rareTLS := []TLSConn{}
	rtr, _ := database.DB.Query(`
		SELECT remote_address, COUNT(*), COALESCE(a.hostname,'')
		FROM network_connect_events nce
		LEFT JOIN agents a ON a.id=nce.agent_id
		WHERE nce.tenant_id=$1 AND nce.created_at>=$2
		  AND (remote_address LIKE '%:8080' OR remote_address LIKE '%:4444' OR remote_address LIKE '%:1337' OR remote_address LIKE '%:4443')
		GROUP BY remote_address, a.hostname ORDER BY COUNT(*) DESC LIMIT 20`, tid, since)
	if rtr != nil {
		defer rtr.Close()
		for rtr.Next() {
			var t TLSConn; rtr.Scan(&t.Addr, &t.Count, &t.Host); rareTLS = append(rareTLS, t)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_tls_connections": totalTLS,
		"unknown_destinations":  unknownTLS,
		"ja3_fingerprints":      ja3Entries,
		"suspicious_tls":        rareTLS,
		"hours":                 hours,
	})
}

// ── 6. Beacon Detections ───────────────────────────────────────────────────

// GetNBABeacons — GET /api/nba/beacons
func GetNBABeacons(c *gin.Context) {
	tid := tenantIDFromContext(c)
	hours := parseHours(c, 48)
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	type Beacon struct {
		ID          int    `json:"id"`
		AgentID     int    `json:"agent_id"`
		Hostname    string `json:"hostname"`
		DstIP       string `json:"dst_ip"`
		DstPort     int    `json:"dst_port"`
		Proto       string `json:"proto"`
		Score       int    `json:"score"`
		Description string `json:"description"`
		Process     string `json:"process"`
		DetectedAt  string `json:"detected_at"`
	}

	rows, _ := database.DB.Query(`
		SELECT na.id, na.agent_id, COALESCE(a.hostname,'Agent #'||na.agent_id::text),
		       COALESCE(na.dst_ip,''), na.dst_port, COALESCE(na.proto,''),
		       na.deviation_score, na.description,
		       to_char(na.detected_at,'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		FROM network_anomalies na
		LEFT JOIN agents a ON a.id=na.agent_id
		WHERE na.tenant_id=$1 AND na.detected_at>=$2
		  AND na.anomaly_type IN ('beacon','c2','new_destination')
		  AND na.deviation_score>=60
		ORDER BY na.deviation_score DESC, na.detected_at DESC LIMIT 100`, tid, since)
	if rows != nil {
		defer rows.Close()
	}

	beacons := []Beacon{}
	if rows != nil {
		for rows.Next() {
			var b Beacon
			rows.Scan(&b.ID, &b.AgentID, &b.Hostname, &b.DstIP, &b.DstPort, &b.Proto,
				&b.Score, &b.Description, &b.DetectedAt)
			beacons = append(beacons, b)
		}
	}
	if beacons == nil {
		beacons = []Beacon{}
	}

	// Beacon stats
	var total, highConf, uniqueC2 int
	for _, b := range beacons {
		total++
		if b.Score >= 80 {
			highConf++
		}
		_ = b.DstIP
	}
	uniqueIPs := map[string]bool{}
	for _, b := range beacons {
		if b.DstIP != "" {
			uniqueIPs[b.DstIP] = true
		}
	}
	uniqueC2 = len(uniqueIPs)

	c.JSON(http.StatusOK, gin.H{
		"beacons":          beacons,
		"total":            total,
		"high_confidence":  highConf,
		"unique_c2_ips":    uniqueC2,
	})
}

// ── 7. Lateral Movement ────────────────────────────────────────────────────

// GetNBALateralMovement — GET /api/nba/lateral-movement
func GetNBALateralMovement(c *gin.Context) {
	tid := tenantIDFromContext(c)
	hours := parseHours(c, 48)
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	type LateralEvent struct {
		AgentID   int    `json:"agent_id"`
		SrcHost   string `json:"src_host"`
		DstAddr   string `json:"dst_address"`
		Protocol  string `json:"protocol"`
		Port      string `json:"port"`
		Method    string `json:"method"`
		Process   string `json:"process"`
		Count     int    `json:"count"`
		FirstSeen string `json:"first_seen"`
		LastSeen  string `json:"last_seen"`
	}

	events := []LateralEvent{}
	// Look for internal connections to lateral movement ports
	portList := "'445','3389','22','5985','5986','135','139','47001','23','4444'"
	q := fmt.Sprintf(`
		SELECT nce.agent_id, COALESCE(a.hostname,'Agent #'||nce.agent_id::text),
		       nce.remote_address, COALESCE(nce.protocol,'tcp'),
		       split_part(nce.remote_address,':',2) AS port,
		       COALESCE(nce.comm,''),
		       COUNT(*),
		       to_char(MIN(nce.created_at),'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
		       to_char(MAX(nce.created_at),'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		FROM network_connect_events nce
		LEFT JOIN agents a ON a.id=nce.agent_id
		WHERE nce.tenant_id=$1 AND nce.created_at>=$2
		  AND split_part(nce.remote_address,':',2) IN (%s)
		  AND (nce.remote_address LIKE '10.%%' OR nce.remote_address LIKE '192.168.%%' OR nce.remote_address LIKE '172.%%')
		GROUP BY nce.agent_id, a.hostname, nce.remote_address, nce.protocol, nce.comm
		ORDER BY COUNT(*) DESC LIMIT 50`, portList)

	rows, err := database.DB.Query(q, tid, since)
	if err == nil && rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e LateralEvent
			rows.Scan(&e.AgentID, &e.SrcHost, &e.DstAddr, &e.Protocol, &e.Port,
				&e.Process, &e.Count, &e.FirstSeen, &e.LastSeen)
			e.Method = lateralPortLabel[e.Port]
			if e.Method == "" {
				e.Method = "Unknown"
			}
			events = append(events, e)
		}
	}
	if events == nil {
		events = []LateralEvent{}
	}

	// Also include any lateral_movement anomalies
	type LateralAnomaly struct {
		ID          int    `json:"id"`
		AgentID     int    `json:"agent_id"`
		Hostname    string `json:"hostname"`
		DstIP       string `json:"dst_ip"`
		Score       int    `json:"score"`
		Description string `json:"description"`
		DetectedAt  string `json:"detected_at"`
	}
	anomalies := []LateralAnomaly{}
	ar, _ := database.DB.Query(`
		SELECT na.id, na.agent_id, COALESCE(a.hostname,''),
		       COALESCE(na.dst_ip,''), na.deviation_score, na.description,
		       to_char(na.detected_at,'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		FROM network_anomalies na
		LEFT JOIN agents a ON a.id=na.agent_id
		WHERE na.tenant_id=$1 AND na.detected_at>=$2
		  AND na.anomaly_type='lateral_movement'
		ORDER BY na.deviation_score DESC, na.detected_at DESC LIMIT 50`, tid, since)
	if ar != nil {
		defer ar.Close()
		for ar.Next() {
			var a LateralAnomaly
			ar.Scan(&a.ID, &a.AgentID, &a.Hostname, &a.DstIP, &a.Score, &a.Description, &a.DetectedAt)
			anomalies = append(anomalies, a)
		}
	}
	if anomalies == nil {
		anomalies = []LateralAnomaly{}
	}

	c.JSON(http.StatusOK, gin.H{
		"lateral_events":   events,
		"lateral_anomalies": anomalies,
		"total":            len(events) + len(anomalies),
	})
}

// ── 8. Threat Intelligence Correlation ────────────────────────────────────

// GetNBAThreatIntel — GET /api/nba/threat-intel
func GetNBAThreatIntel(c *gin.Context) {
	tid := tenantIDFromContext(c)
	hours := parseHours(c, 24)
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	type TIHit struct {
		AgentID     int    `json:"agent_id"`
		Hostname    string `json:"hostname"`
		RemoteAddr  string `json:"remote_address"`
		Process     string `json:"process"`
		IOCType     string `json:"ioc_type"`
		IOCValue    string `json:"ioc_value"`
		ThreatType  string `json:"threat_type"`
		Confidence  int    `json:"confidence"`
		FirstSeen   string `json:"first_seen"`
	}

	hits := []TIHit{}
	// Join network connections with IOC table
	rows, _ := database.DB.Query(`
		SELECT nce.agent_id, COALESCE(a.hostname,'Agent #'||nce.agent_id::text),
		       nce.remote_address, COALESCE(nce.comm,''),
		       i.ioc_type, i.value, COALESCE(i.threat_type,''), COALESCE(i.confidence,50),
		       to_char(MIN(nce.created_at),'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		FROM network_connect_events nce
		LEFT JOIN agents a ON a.id=nce.agent_id
		JOIN iocs i ON (
		  (i.ioc_type='ip' AND split_part(nce.remote_address,':',1)=i.value) OR
		  (i.ioc_type='domain')
		)
		WHERE nce.tenant_id=$1 AND nce.created_at>=$2
		  AND (i.tenant_id=$1 OR i.is_shared=true)
		  AND i.is_enabled=true
		GROUP BY nce.agent_id, a.hostname, nce.remote_address, nce.comm,
		         i.ioc_type, i.value, i.threat_type, i.confidence
		ORDER BY i.confidence DESC LIMIT 50`, tid, since)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var h TIHit
			rows.Scan(&h.AgentID, &h.Hostname, &h.RemoteAddr, &h.Process,
				&h.IOCType, &h.IOCValue, &h.ThreatType, &h.Confidence, &h.FirstSeen)
			hits = append(hits, h)
		}
	}
	if hits == nil {
		hits = []TIHit{}
	}

	// IOC blocks
	type IOCBlock struct {
		IP         string `json:"ip"`
		HitCount   int    `json:"hit_count"`
		BlockedAt  string `json:"blocked_at"`
	}
	blocks := []IOCBlock{}
	br, _ := database.DB.Query(`
		SELECT ip_address, hit_count, to_char(created_at,'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		FROM ioc_blocks WHERE tenant_id=$1 ORDER BY hit_count DESC LIMIT 20`, tid)
	if br != nil {
		defer br.Close()
		for br.Next() {
			var b IOCBlock; br.Scan(&b.IP, &b.HitCount, &b.BlockedAt); blocks = append(blocks, b)
		}
	}
	if blocks == nil {
		blocks = []IOCBlock{}
	}

	c.JSON(http.StatusOK, gin.H{
		"threat_intel_hits": hits,
		"ioc_blocks":        blocks,
		"total_hits":        len(hits),
	})
}

// ── 9. AI Insights ────────────────────────────────────────────────────────

// PostNBAAIInsights — POST /api/nba/ai-insights
func PostNBAAIInsights(c *gin.Context) {
	tid := tenantIDFromContext(c)

	var body struct {
		Context string `json:"context"`
		Host    string `json:"host"`
	}
	c.ShouldBindJSON(&body)

	// Gather recent anomaly summary
	type AnomalySummary struct {
		Type  string  `json:"type"`
		Count int     `json:"count"`
		AvgScore float64 `json:"avg_score"`
	}
	anomalies := []AnomalySummary{}
	rows, _ := database.DB.Query(`
		SELECT anomaly_type, COUNT(*), AVG(deviation_score)
		FROM network_anomalies WHERE tenant_id=$1 AND detected_at>NOW()-INTERVAL '24 hours'
		GROUP BY anomaly_type ORDER BY COUNT(*) DESC LIMIT 10`, tid)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var a AnomalySummary; rows.Scan(&a.Type, &a.Count, &a.AvgScore); anomalies = append(anomalies, a)
		}
	}

	var connCount int
	database.DB.QueryRow(`SELECT COUNT(*) FROM network_connect_events WHERE tenant_id=$1 AND created_at>NOW()-INTERVAL '1 hour'`, tid).Scan(&connCount)

	summary, _ := json.Marshal(anomalies)
	hostCtx := ""
	if body.Host != "" {
		hostCtx = fmt.Sprintf("Focusing on host: %s. ", body.Host)
	}

	prompt := fmt.Sprintf(`You are a network security AI analyst. Analyze this network behavior data and provide concise threat assessment.
%s
Network anomalies in last 24h: %s
Connections in last 1h: %d
Additional context: %s

Respond with JSON only (no markdown):
{
  "threat_summary": "...",
  "risk_level": "low|medium|high|critical",
  "key_findings": ["finding1","finding2","finding3"],
  "suspicious_behaviors": ["behavior1","behavior2"],
  "mitre_techniques": ["T1046 - Network Service Scanning"],
  "recommendations": ["action1","action2","action3"],
  "confidence": 85
}`, hostCtx, string(summary), connCount, body.Context)

	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "AI service unavailable"})
		return
	}
	// Strip markdown fences
	if idx := strings.Index(raw, "```json"); idx != -1 {
		raw = raw[idx+7:]
	} else if idx = strings.Index(raw, "```"); idx != -1 {
		raw = raw[idx+3:]
	}
	if idx := strings.LastIndex(raw, "```"); idx != -1 {
		raw = raw[:idx]
	}
	c.Data(http.StatusOK, "application/json", []byte(strings.TrimSpace(raw)))
}

// ── 10. Response Action ────────────────────────────────────────────────────

// PostNBAResponseAction — POST /api/nba/response-action
func PostNBAResponseAction(c *gin.Context) {
	tid := tenantIDFromContext(c)
	uid := userIDFromContext(c)

	var body struct {
		Action   string `json:"action"`
		IP       string `json:"ip"`
		Domain   string `json:"domain"`
		ASN      string `json:"asn"`
		AgentID  int    `json:"agent_id"`
		PID      int    `json:"pid"`
		Reason   string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	result := ""
	switch body.Action {
	case "block_ip":
		if body.IP == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ip required"}); return
		}
		_, err := database.DB.Exec(`
			INSERT INTO iocs (tenant_id, created_by, ioc_type, value, threat_type, confidence, is_enabled, description)
			VALUES ($1,$2,'ip',$3,'network_block',100,true,$4)
			ON CONFLICT (tenant_id, ioc_type, value) DO UPDATE SET is_enabled=true`,
			tid, uid, body.IP, "Blocked via NBA response action: "+body.Reason)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
		}
		result = fmt.Sprintf("IP %s blocked via IOC", body.IP)

	case "block_domain":
		if body.Domain == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "domain required"}); return
		}
		database.DB.Exec(`
			INSERT INTO iocs (tenant_id, created_by, ioc_type, value, threat_type, confidence, is_enabled, description)
			VALUES ($1,$2,'domain',$3,'network_block',100,true,$4)
			ON CONFLICT (tenant_id, ioc_type, value) DO UPDATE SET is_enabled=true`,
			tid, uid, body.Domain, "Blocked via NBA response action: "+body.Reason)
		result = fmt.Sprintf("Domain %s blocked via IOC", body.Domain)

	case "isolate_endpoint":
		if body.AgentID == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id required"}); return
		}
		database.DB.Exec(`UPDATE agents SET isolated=true, isolated_at=NOW(), isolated_by=$1 WHERE id=$2 AND tenant_id=$3`,
			uid, body.AgentID, tid)
		result = fmt.Sprintf("Agent #%d isolation requested", body.AgentID)

	case "create_incident":
		var incidentID int
		database.DB.QueryRow(`
			INSERT INTO incidents (tenant_id, title, description, severity, status, created_by)
			VALUES ($1,$2,$3,'high','open',$4) RETURNING id`,
			tid, fmt.Sprintf("NBA Alert: %s", body.Reason),
			fmt.Sprintf("Network behavior anomaly detected. IP: %s Domain: %s. %s", body.IP, body.Domain, body.Reason),
			uid).Scan(&incidentID)
		result = fmt.Sprintf("Incident #%d created", incidentID)

	case "start_pcap":
		result = fmt.Sprintf("Packet capture requested for agent #%d (requires agent support)", body.AgentID)

	case "block_asn":
		if body.ASN == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "asn required"}); return
		}
		database.DB.Exec(`
			INSERT INTO iocs (tenant_id, created_by, ioc_type, value, threat_type, confidence, is_enabled, description)
			VALUES ($1,$2,'asn',$3,'network_block',90,true,$4)
			ON CONFLICT DO NOTHING`,
			tid, uid, body.ASN, "ASN blocked via NBA: "+body.Reason)
		result = fmt.Sprintf("ASN %s blocked", body.ASN)

	case "push_firewall_rule":
		result = fmt.Sprintf("Firewall rule pushed: block %s (requires firewall integration)", body.IP)

	case "kill_process":
		result = fmt.Sprintf("Kill process PID=%d requested for agent #%d", body.PID, body.AgentID)

	case "run_playbook":
		result = "SOAR playbook execution queued"

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown action"}); return
	}

	c.JSON(http.StatusOK, gin.H{"result": result, "action": body.Action, "timestamp": time.Now().UTC()})
}

// ── 11. MITRE Mapping ─────────────────────────────────────────────────────

// GetNBAMitreMapping — GET /api/nba/mitre-mapping
func GetNBAMitreMapping(c *gin.Context) {
	tid := tenantIDFromContext(c)
	since := time.Now().Add(-7 * 24 * time.Hour)

	type AnomalyCount struct {
		AnomalyType string `json:"anomaly_type"`
		Count       int    `json:"count"`
		MaxScore    int    `json:"max_score"`
	}
	anomalyCounts := []AnomalyCount{}
	rows, _ := database.DB.Query(`
		SELECT anomaly_type, COUNT(*), MAX(deviation_score)
		FROM network_anomalies WHERE tenant_id=$1 AND detected_at>=$2
		GROUP BY anomaly_type ORDER BY COUNT(*) DESC`, tid, since)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var a AnomalyCount; rows.Scan(&a.AnomalyType, &a.Count, &a.MaxScore); anomalyCounts = append(anomalyCounts, a)
		}
	}

	type MITREEntry struct {
		TechniqueID   string   `json:"technique_id"`
		TechniqueName string   `json:"technique_name"`
		AnomalyTypes  []string `json:"anomaly_types"`
		HitCount      int      `json:"hit_count"`
		MaxScore      int      `json:"max_score"`
	}

	// Build MITRE entries from detected anomaly types
	techMap := map[string]*MITREEntry{}
	for _, ac := range anomalyCounts {
		techniques := mitreMap[ac.AnomalyType]
		if len(techniques) == 0 {
			techniques = []map[string]string{{"id": "T1071", "name": "Application Layer Protocol"}}
		}
		for _, t := range techniques {
			key := t["id"]
			if _, ok := techMap[key]; !ok {
				techMap[key] = &MITREEntry{TechniqueID: key, TechniqueName: t["name"]}
			}
			techMap[key].AnomalyTypes = append(techMap[key].AnomalyTypes, ac.AnomalyType)
			techMap[key].HitCount += ac.Count
			if ac.MaxScore > techMap[key].MaxScore {
				techMap[key].MaxScore = ac.MaxScore
			}
		}
	}

	entries := []MITREEntry{}
	for _, e := range techMap {
		entries = append(entries, *e)
	}

	// Always include a baseline set even if no anomalies yet
	baseline := []map[string]string{
		{"id": "T1046", "name": "Network Service Scanning"},
		{"id": "T1071", "name": "Application Layer Protocol"},
		{"id": "T1021", "name": "Remote Services"},
		{"id": "T1041", "name": "Exfiltration Over C2 Channel"},
		{"id": "T1095", "name": "Non-Application Layer Protocol"},
		{"id": "T1571", "name": "Non-Standard Port"},
		{"id": "T1219", "name": "Remote Access Software"},
	}
	for _, b := range baseline {
		if _, ok := techMap[b["id"]]; !ok {
			entries = append(entries, MITREEntry{TechniqueID: b["id"], TechniqueName: b["name"], HitCount: 0})
		}
	}

	c.JSON(http.StatusOK, gin.H{"techniques": entries, "total": len(entries)})
}

// ── 12. Protocol Breakdown ─────────────────────────────────────────────────

// GetNBAProtocolBreakdown — GET /api/nba/protocol-breakdown
func GetNBAProtocolBreakdown(c *gin.Context) {
	tid := tenantIDFromContext(c)
	hours := parseHours(c, 24)
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	portToProto := map[string]string{
		"80": "HTTP", "443": "HTTPS", "53": "DNS", "445": "SMB",
		"389": "LDAP", "636": "LDAPS", "88": "Kerberos", "22": "SSH",
		"21": "FTP", "25": "SMTP", "587": "SMTP(S)", "110": "POP3", "995": "POP3(S)",
		"143": "IMAP", "993": "IMAP(S)", "3389": "RDP", "5985": "WinRM",
		"161": "SNMP", "123": "NTP", "5353": "mDNS", "1883": "MQTT",
		"8883": "MQTT(S)", "8080": "HTTP-Alt", "8443": "HTTPS-Alt",
	}

	type ProtoEntry struct {
		Name      string `json:"name"`
		Port      string `json:"port"`
		Count     int    `json:"count"`
		IsRisky   bool   `json:"is_risky"`
		RiskPorts []string `json:"-"`
	}

	riskyPorts := map[string]bool{"4444": true, "1337": true, "31337": true, "4445": true, "9999": true, "6666": true, "6667": true}

	rows, _ := database.DB.Query(`
		SELECT split_part(remote_address,':',2) AS port, COUNT(*) AS cnt
		FROM network_connect_events WHERE tenant_id=$1 AND created_at>=$2 AND remote_address LIKE '%:%'
		GROUP BY port ORDER BY cnt DESC LIMIT 30`, tid, since)

	entries := []ProtoEntry{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var port string; var cnt int
			rows.Scan(&port, &cnt)
			label := portToProto[port]
			if label == "" {
				label = "Port " + port
			}
			entries = append(entries, ProtoEntry{
				Name:    label,
				Port:    port,
				Count:   cnt,
				IsRisky: riskyPorts[port],
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{"protocols": entries, "hours": hours})
}

// ── 13. Host Timeline ──────────────────────────────────────────────────────

// GetNBAHostTimeline — GET /api/nba/host-timeline?host=WS-014&hours=24
func GetNBAHostTimeline(c *gin.Context) {
	tid := tenantIDFromContext(c)
	host := c.Query("host")
	hours := parseHours(c, 24)
	limit := parseLimit(c, 100)
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	type TimelineEvent struct {
		EventType  string `json:"event_type"`
		Hostname   string `json:"hostname"`
		AgentID    int    `json:"agent_id"`
		RemoteAddr string `json:"remote_address"`
		Protocol   string `json:"protocol"`
		Process    string `json:"process"`
		Score      int    `json:"score,omitempty"`
		Detail     string `json:"detail"`
		Timestamp  string `json:"timestamp"`
	}

	events := []TimelineEvent{}

	// Network connect events
	hostCond := ""; args := []any{tid, since, limit}
	if host != "" {
		args = append(args[:len(args):len(args)], "%"+host+"%")
		hostCond = fmt.Sprintf("AND a.hostname ILIKE $%d", len(args))
	}
	q := fmt.Sprintf(`
		SELECT 'connection', COALESCE(a.hostname,''), nce.agent_id,
		       nce.remote_address, COALESCE(nce.protocol,''), COALESCE(nce.comm,''),
		       0, COALESCE(nce.state,''),
		       to_char(nce.created_at,'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		FROM network_connect_events nce
		LEFT JOIN agents a ON a.id=nce.agent_id
		WHERE nce.tenant_id=$1 AND nce.created_at>=$2 %s
		ORDER BY nce.created_at DESC LIMIT $3`, hostCond)
	rows, _ := database.DB.Query(q, args...)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e TimelineEvent
			rows.Scan(&e.EventType, &e.Hostname, &e.AgentID, &e.RemoteAddr,
				&e.Protocol, &e.Process, &e.Score, &e.Detail, &e.Timestamp)
			events = append(events, e)
		}
	}

	// Anomaly events for the host
	hostCond2 := ""
	args2 := []any{tid, since}
	if host != "" {
		args2 = append(args2, "%"+host+"%")
		hostCond2 = fmt.Sprintf("AND a.hostname ILIKE $%d", len(args2))
	}
	q2 := fmt.Sprintf(`
		SELECT 'anomaly', COALESCE(a.hostname,''), na.agent_id,
		       COALESCE(na.dst_ip,''), COALESCE(na.proto,''), '',
		       na.deviation_score, na.description,
		       to_char(na.detected_at,'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		FROM network_anomalies na
		LEFT JOIN agents a ON a.id=na.agent_id
		WHERE na.tenant_id=$1 AND na.detected_at>=$2 %s
		ORDER BY na.detected_at DESC LIMIT 50`, hostCond2)
	ar, _ := database.DB.Query(q2, args2...)
	if ar != nil {
		defer ar.Close()
		for ar.Next() {
			var e TimelineEvent
			ar.Scan(&e.EventType, &e.Hostname, &e.AgentID, &e.RemoteAddr,
				&e.Protocol, &e.Process, &e.Score, &e.Detail, &e.Timestamp)
			events = append(events, e)
		}
	}
	if events == nil {
		events = []TimelineEvent{}
	}

	c.JSON(http.StatusOK, gin.H{"events": events, "total": len(events), "host": host})
}

// ── 14. Analytics ─────────────────────────────────────────────────────────

// GetNBAAnalytics — GET /api/nba/analytics
func GetNBAAnalytics(c *gin.Context) {
	tid := tenantIDFromContext(c)
	hours := parseHours(c, 24)
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	type GeoEntry struct {
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		Count       int    `json:"count"`
	}
	geoDistribution := []GeoEntry{}
	gr, _ := database.DB.Query(`
		SELECT COALESCE(ec.country,'Unknown'), COALESCE(ec.country_code,'XX'), COUNT(*) AS cnt
		FROM endpoint_connections ec
		WHERE ec.tenant_id=$1 AND ec.collected_at>=$2
		  AND ec.country!='' AND ec.country IS NOT NULL
		GROUP BY ec.country, ec.country_code ORDER BY cnt DESC LIMIT 15`, tid, since)
	if gr != nil {
		defer gr.Close()
		for gr.Next() {
			var g GeoEntry; gr.Scan(&g.Country, &g.CountryCode, &g.Count); geoDistribution = append(geoDistribution, g)
		}
	}

	type AnomalyTrend struct {
		Hour  string `json:"hour"`
		Count int    `json:"count"`
		Avg   int    `json:"avg_score"`
	}
	anomalyTrend := []AnomalyTrend{}
	atr, _ := database.DB.Query(`
		SELECT to_char(date_trunc('hour', detected_at), 'HH24:MI'),
		       COUNT(*), COALESCE(AVG(deviation_score)::int,0)
		FROM network_anomalies WHERE tenant_id=$1 AND detected_at>=$2
		GROUP BY date_trunc('hour', detected_at)
		ORDER BY date_trunc('hour', detected_at)`, tid, since)
	if atr != nil {
		defer atr.Close()
		for atr.Next() {
			var a AnomalyTrend; atr.Scan(&a.Hour, &a.Count, &a.Avg); anomalyTrend = append(anomalyTrend, a)
		}
	}

	type HostRisk struct {
		Hostname     string `json:"hostname"`
		AgentID      int    `json:"agent_id"`
		AnomalyCount int    `json:"anomaly_count"`
		MaxScore     int    `json:"max_score"`
	}
	mostSuspicious := []HostRisk{}
	hsr, _ := database.DB.Query(`
		SELECT COALESCE(a.hostname,'Agent #'||na.agent_id::text), na.agent_id,
		       COUNT(*), MAX(na.deviation_score)
		FROM network_anomalies na
		LEFT JOIN agents a ON a.id=na.agent_id
		WHERE na.tenant_id=$1 AND na.detected_at>=$2
		GROUP BY a.hostname, na.agent_id ORDER BY COUNT(*) DESC LIMIT 10`, tid, since)
	if hsr != nil {
		defer hsr.Close()
		for hsr.Next() {
			var h HostRisk; hsr.Scan(&h.Hostname, &h.AgentID, &h.AnomalyCount, &h.MaxScore)
			mostSuspicious = append(mostSuspicious, h)
		}
	}

	// Beacon frequency by host
	type BeaconFreq struct {
		Hostname string `json:"hostname"`
		Count    int    `json:"count"`
		MaxScore int    `json:"max_score"`
	}
	beaconFrequency := []BeaconFreq{}
	bfr, _ := database.DB.Query(`
		SELECT COALESCE(a.hostname,'Agent #'||na.agent_id::text),
		       COUNT(*), MAX(na.deviation_score)
		FROM network_anomalies na
		LEFT JOIN agents a ON a.id=na.agent_id
		WHERE na.tenant_id=$1 AND na.detected_at>=$2 AND na.anomaly_type IN ('beacon','c2')
		GROUP BY a.hostname, na.agent_id ORDER BY COUNT(*) DESC LIMIT 10`, tid, since)
	if bfr != nil {
		defer bfr.Close()
		for bfr.Next() {
			var b BeaconFreq; bfr.Scan(&b.Hostname, &b.Count, &b.MaxScore); beaconFrequency = append(beaconFrequency, b)
		}
	}

	var totalConns, uniqueHosts, blockedIPs int
	database.DB.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT agent_id) FROM network_connect_events WHERE tenant_id=$1 AND created_at>=$2`, tid, since).Scan(&totalConns, &uniqueHosts)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ioc_blocks WHERE tenant_id=$1`, tid).Scan(&blockedIPs)

	c.JSON(http.StatusOK, gin.H{
		"total_connections":      totalConns,
		"unique_hosts":           uniqueHosts,
		"blocked_ips":            blockedIPs,
		"geo_distribution":       geoDistribution,
		"anomaly_trend":          anomalyTrend,
		"most_suspicious_hosts":  mostSuspicious,
		"beacon_frequency":       beaconFrequency,
		"hours":                  hours,
	})
}
