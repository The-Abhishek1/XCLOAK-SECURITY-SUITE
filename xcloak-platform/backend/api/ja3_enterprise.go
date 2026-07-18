package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
	"xcloak-platform/services"
)

// ── JA3 Enterprise Handlers ───────────────────────────────────────────────

// GetJA3Dashboard — GET /api/ja3/dashboard
func GetJA3Dashboard(c *gin.Context) {
	tid := tenantIDFromContext(c)

	var total, platformCnt, tenantCnt, criticalCnt, newToday int
	database.DB.QueryRow(`
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE tenant_id IS NULL),
			COUNT(*) FILTER (WHERE tenant_id IS NOT NULL),
			COUNT(*) FILTER (WHERE severity = 'critical'),
			COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours')
		FROM ja3_fingerprints
		WHERE enabled = TRUE AND (tenant_id = $1 OR tenant_id IS NULL)
	`, tid).Scan(&total, &platformCnt, &tenantCnt, &criticalCnt, &newToday)

	var alerts24h, agents24h int
	database.DB.QueryRow(`
		SELECT COUNT(*), COUNT(DISTINCT agent_id)
		FROM alerts
		WHERE tenant_id = $1 AND mitre_technique = 'T1071.001'
		  AND created_at > NOW() - INTERVAL '24 hours'
	`, tid).Scan(&alerts24h, &agents24h)

	var alerts7d int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM alerts
		WHERE tenant_id = $1 AND mitre_technique = 'T1071.001'
		  AND created_at > NOW() - INTERVAL '7 days'
	`, tid).Scan(&alerts7d)

	type fpStat struct {
		Hash     string `json:"hash"`
		Name     string `json:"threat_name"`
		Severity string `json:"severity"`
		Source   string `json:"source"`
		Hits     int    `json:"hit_count"`
	}
	fpRows, err := database.DB.Query(`
		SELECT jf.hash, jf.threat_name, jf.severity, jf.source,
		       COUNT(a.id) AS hit_count
		FROM ja3_fingerprints jf
		LEFT JOIN alerts a ON a.log_message ILIKE '%' || jf.hash || '%'
		    AND a.tenant_id = $1
		    AND a.created_at > NOW() - INTERVAL '7 days'
		WHERE jf.enabled = TRUE AND (jf.tenant_id = $1 OR jf.tenant_id IS NULL)
		GROUP BY jf.hash, jf.threat_name, jf.severity, jf.source
		ORDER BY hit_count DESC, jf.severity DESC
		LIMIT 8
	`, tid)
	topFP := []fpStat{}
	if err == nil {
		defer fpRows.Close()
		for fpRows.Next() {
			var fp fpStat
			if fpRows.Scan(&fp.Hash, &fp.Name, &fp.Severity, &fp.Source, &fp.Hits) == nil {
				topFP = append(topFP, fp)
			}
		}
	}
	if topFP == nil {
		topFP = []fpStat{}
	}

	type trendPt struct {
		Date  string `json:"date"`
		Count int    `json:"count"`
	}
	trendRows, _ := database.DB.Query(`
		SELECT DATE_TRUNC('day', created_at)::date, COUNT(*)
		FROM alerts
		WHERE tenant_id = $1 AND mitre_technique = 'T1071.001'
		  AND created_at > NOW() - INTERVAL '14 days'
		GROUP BY 1 ORDER BY 1
	`, tid)
	trend := []trendPt{}
	if trendRows != nil {
		defer trendRows.Close()
		for trendRows.Next() {
			var d time.Time
			var cnt int
			if trendRows.Scan(&d, &cnt) == nil {
				trend = append(trend, trendPt{d.Format("2006-01-02"), cnt})
			}
		}
	}
	if trend == nil {
		trend = []trendPt{}
	}

	type sevPt struct {
		Severity string `json:"severity"`
		Count    int    `json:"count"`
	}
	sevRows, _ := database.DB.Query(`
		SELECT severity, COUNT(*) FROM ja3_fingerprints
		WHERE enabled = TRUE AND (tenant_id = $1 OR tenant_id IS NULL)
		GROUP BY severity ORDER BY COUNT(*) DESC
	`, tid)
	sevBreakdown := []sevPt{}
	if sevRows != nil {
		defer sevRows.Close()
		for sevRows.Next() {
			var s sevPt
			if sevRows.Scan(&s.Severity, &s.Count) == nil {
				sevBreakdown = append(sevBreakdown, s)
			}
		}
	}
	if sevBreakdown == nil {
		sevBreakdown = []sevPt{}
	}

	c.JSON(http.StatusOK, gin.H{
		"total":              total,
		"platform_count":     platformCnt,
		"tenant_count":       tenantCnt,
		"critical_count":     criticalCnt,
		"new_today":          newToday,
		"alerts_24h":         alerts24h,
		"alerts_7d":          alerts7d,
		"agents_hit_24h":     agents24h,
		"high_risk_sessions": alerts24h,
		"top_fingerprints":   topFP,
		"trend":              trend,
		"sev_breakdown":      sevBreakdown,
	})
}

// GetJA3Analytics — GET /api/ja3/analytics
func GetJA3Analytics(c *gin.Context) {
	tid := tenantIDFromContext(c)

	type fpStat struct {
		Hash      string  `json:"hash"`
		Name      string  `json:"threat_name"`
		Severity  string  `json:"severity"`
		Source    string  `json:"source"`
		Total     int     `json:"total"`
		Last24h   int     `json:"last_24h"`
		Last7d    int     `json:"last_7d"`
		LastMatch *string `json:"last_match"`
		AgentsHit int     `json:"agents_hit"`
	}
	rows, err := database.DB.Query(`
		SELECT jf.hash, jf.threat_name, jf.severity, jf.source,
		       COUNT(a.id),
		       COUNT(a.id) FILTER (WHERE a.created_at > NOW()-INTERVAL '24 hours'),
		       COUNT(a.id) FILTER (WHERE a.created_at > NOW()-INTERVAL '7 days'),
		       MAX(a.created_at),
		       COUNT(DISTINCT a.agent_id)
		FROM ja3_fingerprints jf
		LEFT JOIN alerts a ON a.log_message ILIKE '%' || jf.hash || '%'
		    AND a.tenant_id = $1
		WHERE jf.enabled = TRUE AND (jf.tenant_id = $1 OR jf.tenant_id IS NULL)
		GROUP BY jf.hash, jf.threat_name, jf.severity, jf.source
		ORDER BY 5 DESC
		LIMIT 50
	`, tid)
	stats := []fpStat{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var s fpStat
			var lm *string
			if rows.Scan(&s.Hash, &s.Name, &s.Severity, &s.Source,
				&s.Total, &s.Last24h, &s.Last7d, &lm, &s.AgentsHit) == nil {
				s.LastMatch = lm
				stats = append(stats, s)
			}
		}
	}
	if stats == nil {
		stats = []fpStat{}
	}

	type dayPt struct {
		Date  string `json:"date"`
		Count int    `json:"count"`
	}
	tRows, _ := database.DB.Query(`
		SELECT DATE_TRUNC('day', created_at)::date, COUNT(*)
		FROM alerts
		WHERE tenant_id = $1 AND mitre_technique = 'T1071.001'
		  AND created_at > NOW() - INTERVAL '30 days'
		GROUP BY 1 ORDER BY 1
	`, tid)
	daily := []dayPt{}
	if tRows != nil {
		defer tRows.Close()
		for tRows.Next() {
			var d time.Time
			var cnt int
			if tRows.Scan(&d, &cnt) == nil {
				daily = append(daily, dayPt{d.Format("2006-01-02"), cnt})
			}
		}
	}
	if daily == nil {
		daily = []dayPt{}
	}

	type agStat struct {
		AgentID  int    `json:"agent_id"`
		Hostname string `json:"hostname"`
		Hits     int    `json:"hits"`
	}
	agRows, _ := database.DB.Query(`
		SELECT a.id, a.hostname, COUNT(al.id) AS hits
		FROM agents a
		JOIN alerts al ON al.agent_id = a.id
		WHERE a.tenant_id = $1 AND al.mitre_technique = 'T1071.001'
		  AND al.created_at > NOW() - INTERVAL '7 days'
		GROUP BY a.id, a.hostname
		ORDER BY hits DESC LIMIT 10
	`, tid)
	topAgents := []agStat{}
	if agRows != nil {
		defer agRows.Close()
		for agRows.Next() {
			var ag agStat
			if agRows.Scan(&ag.AgentID, &ag.Hostname, &ag.Hits) == nil {
				topAgents = append(topAgents, ag)
			}
		}
	}
	if topAgents == nil {
		topAgents = []agStat{}
	}

	c.JSON(http.StatusOK, gin.H{
		"fingerprints": stats,
		"daily":        daily,
		"top_agents":   topAgents,
	})
}

// GetJA3TLSStats — GET /api/ja3/tls-stats
func GetJA3TLSStats(c *gin.Context) {
	tid := tenantIDFromContext(c)

	type verPt struct {
		Version string `json:"version"`
		Count   int    `json:"count"`
	}
	verRows, _ := database.DB.Query(`
		SELECT COALESCE(el.parsed_fields->>'tls_version','unknown'), COUNT(*)
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id
		WHERE a.tenant_id = $1
		  AND el.collected_at > NOW() - INTERVAL '7 days'
		  AND el.parsed_fields->>'tls_version' IS NOT NULL
		GROUP BY 1 ORDER BY 2 DESC LIMIT 10
	`, tid)
	tlsVersions := []verPt{}
	if verRows != nil {
		defer verRows.Close()
		for verRows.Next() {
			var v verPt
			if verRows.Scan(&v.Version, &v.Count) == nil {
				tlsVersions = append(tlsVersions, v)
			}
		}
	}
	if tlsVersions == nil {
		tlsVersions = []verPt{}
	}

	weakCiphers := map[string]bool{
		"TLS_RSA_WITH_RC4_128_MD5": true, "TLS_RSA_WITH_RC4_128_SHA": true,
		"TLS_RSA_WITH_DES_CBC_SHA": true, "TLS_RSA_WITH_3DES_EDE_CBC_SHA": true,
	}
	type cipherPt struct {
		Cipher string `json:"cipher"`
		Count  int    `json:"count"`
		IsWeak bool   `json:"is_weak"`
	}
	cipherRows, _ := database.DB.Query(`
		SELECT COALESCE(el.parsed_fields->>'cipher_suite','unknown'), COUNT(*)
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id
		WHERE a.tenant_id = $1
		  AND el.collected_at > NOW() - INTERVAL '7 days'
		  AND el.parsed_fields->>'cipher_suite' IS NOT NULL
		GROUP BY 1 ORDER BY 2 DESC LIMIT 15
	`, tid)
	ciphers := []cipherPt{}
	if cipherRows != nil {
		defer cipherRows.Close()
		for cipherRows.Next() {
			var cp cipherPt
			if cipherRows.Scan(&cp.Cipher, &cp.Count) == nil {
				cp.IsWeak = weakCiphers[cp.Cipher]
				ciphers = append(ciphers, cp)
			}
		}
	}
	if ciphers == nil {
		ciphers = []cipherPt{}
	}

	var selfSigned, expiredCerts, invalidCerts int
	database.DB.QueryRow(`
		SELECT
			COUNT(*) FILTER (WHERE parsed_fields->>'cert_self_signed' = 'true'),
			COUNT(*) FILTER (WHERE parsed_fields->>'cert_expired' = 'true'),
			COUNT(*) FILTER (WHERE parsed_fields->>'cert_valid' = 'false')
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id
		WHERE a.tenant_id = $1 AND el.collected_at > NOW() - INTERVAL '7 days'
	`, tid).Scan(&selfSigned, &expiredCerts, &invalidCerts)

	var uniqueJA3, uniqueJA3S int
	database.DB.QueryRow(`
		SELECT
			COUNT(DISTINCT parsed_fields->>'ja3_hash'),
			COUNT(DISTINCT parsed_fields->>'ja3s_hash')
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id
		WHERE a.tenant_id = $1
		  AND el.collected_at > NOW() - INTERVAL '7 days'
		  AND parsed_fields->>'ja3_hash' IS NOT NULL
	`, tid).Scan(&uniqueJA3, &uniqueJA3S)

	c.JSON(http.StatusOK, gin.H{
		"tls_versions":  tlsVersions,
		"ciphers":       ciphers,
		"self_signed":   selfSigned,
		"expired_certs": expiredCerts,
		"invalid_certs": invalidCerts,
		"unique_ja3":    uniqueJA3,
		"unique_ja3s":   uniqueJA3S,
	})
}

// GetJA3Behavioral — GET /api/ja3/behavioral
func GetJA3Behavioral(c *gin.Context) {
	tid := tenantIDFromContext(c)

	type beaconEntry struct {
		AgentID    int    `json:"agent_id"`
		Hostname   string `json:"hostname"`
		AlertCount int    `json:"alert_count"`
		FirstSeen  string `json:"first_seen"`
		LastSeen   string `json:"last_seen"`
		RuleName   string `json:"rule_name"`
	}
	beaconRows, _ := database.DB.Query(`
		SELECT a.id, a.hostname, COUNT(al.id),
		       MIN(al.created_at), MAX(al.created_at), al.rule_name
		FROM alerts al
		JOIN agents a ON a.id = al.agent_id
		WHERE a.tenant_id = $1
		  AND al.mitre_technique = 'T1071.001'
		  AND al.created_at > NOW() - INTERVAL '24 hours'
		GROUP BY a.id, a.hostname, al.rule_name
		HAVING COUNT(al.id) >= 3
		ORDER BY 3 DESC LIMIT 10
	`, tid)
	beaconing := []beaconEntry{}
	if beaconRows != nil {
		defer beaconRows.Close()
		for beaconRows.Next() {
			var b beaconEntry
			if beaconRows.Scan(&b.AgentID, &b.Hostname, &b.AlertCount,
				&b.FirstSeen, &b.LastSeen, &b.RuleName) == nil {
				beaconing = append(beaconing, b)
			}
		}
	}
	if beaconing == nil {
		beaconing = []beaconEntry{}
	}

	type rareFP struct {
		Hash     string `json:"hash"`
		Name     string `json:"threat_name"`
		Severity string `json:"severity"`
		HitCount int    `json:"hit_count"`
	}
	rareRows, _ := database.DB.Query(`
		SELECT jf.hash, jf.threat_name, jf.severity, COUNT(a.id)
		FROM ja3_fingerprints jf
		LEFT JOIN alerts a ON a.log_message ILIKE '%' || jf.hash || '%'
		    AND a.tenant_id = $1
		WHERE jf.enabled = TRUE AND (jf.tenant_id = $1 OR jf.tenant_id IS NULL)
		GROUP BY jf.hash, jf.threat_name, jf.severity
		HAVING COUNT(a.id) < 3
		ORDER BY 4 ASC, jf.severity DESC LIMIT 10
	`, tid)
	rares := []rareFP{}
	if rareRows != nil {
		defer rareRows.Close()
		for rareRows.Next() {
			var r rareFP
			if rareRows.Scan(&r.Hash, &r.Name, &r.Severity, &r.HitCount) == nil {
				rares = append(rares, r)
			}
		}
	}
	if rares == nil {
		rares = []rareFP{}
	}

	type newFP struct {
		Hash      string `json:"hash"`
		Name      string `json:"threat_name"`
		Severity  string `json:"severity"`
		Source    string `json:"source"`
		CreatedAt string `json:"created_at"`
	}
	newRows, _ := database.DB.Query(`
		SELECT hash, threat_name, severity, source, created_at
		FROM ja3_fingerprints
		WHERE (tenant_id = $1 OR tenant_id IS NULL)
		  AND created_at > NOW() - INTERVAL '24 hours'
		ORDER BY created_at DESC LIMIT 10
	`, tid)
	newFPs := []newFP{}
	if newRows != nil {
		defer newRows.Close()
		for newRows.Next() {
			var nf newFP
			if newRows.Scan(&nf.Hash, &nf.Name, &nf.Severity, &nf.Source, &nf.CreatedAt) == nil {
				newFPs = append(newFPs, nf)
			}
		}
	}
	if newFPs == nil {
		newFPs = []newFP{}
	}

	c.JSON(http.StatusOK, gin.H{
		"beaconing":  beaconing,
		"rare":       rares,
		"new":        newFPs,
		"fp_changes": []map[string]any{},
	})
}

// GetJA3Relationships — GET /api/ja3/relationships
func GetJA3Relationships(c *gin.Context) {
	tid := tenantIDFromContext(c)

	type node struct {
		ID    string `json:"id"`
		Label string `json:"label"`
		Type  string `json:"type"`
		Value int    `json:"value"`
	}
	type edge struct {
		Source string `json:"source"`
		Target string `json:"target"`
		Weight int    `json:"weight"`
	}
	nodes := []node{}
	edges := []edge{}

	fpRows, err := database.DB.Query(`
		SELECT hash, threat_name, severity FROM ja3_fingerprints
		WHERE enabled = TRUE AND (tenant_id = $1 OR tenant_id IS NULL)
		LIMIT 12
	`, tid)
	if err == nil {
		defer fpRows.Close()
		for fpRows.Next() {
			var hash, name, sev string
			if fpRows.Scan(&hash, &name, &sev) == nil {
				val := 4
				if sev == "critical" {
					val = 12
				} else if sev == "high" {
					val = 8
				}
				if len(hash) >= 8 {
					nodes = append(nodes, node{"ja3_" + hash[:8], name, "ja3", val})
				}
			}
		}
	}

	agentRows, _ := database.DB.Query(`SELECT id, hostname FROM agents WHERE tenant_id = $1 LIMIT 8`, tid)
	if agentRows != nil {
		defer agentRows.Close()
		for agentRows.Next() {
			var id int
			var hostname string
			if agentRows.Scan(&id, &hostname) == nil {
				nodes = append(nodes, node{fmt.Sprintf("agent_%d", id), hostname, "agent", 6})
			}
		}
	}

	ipRows, _ := database.DB.Query(`
		SELECT DISTINCT SPLIT_PART(remote_addr,':',1) AS ip, COUNT(*) AS cnt
		FROM endpoint_connections ec
		JOIN agents a ON a.id = ec.agent_id
		WHERE a.tenant_id = $1
		  AND remote_addr NOT LIKE '10.%' AND remote_addr NOT LIKE '192.168.%' AND remote_addr NOT LIKE '172.%'
		GROUP BY 1 ORDER BY cnt DESC LIMIT 8
	`, tid)
	if ipRows != nil {
		defer ipRows.Close()
		for ipRows.Next() {
			var ip string
			var cnt int
			if ipRows.Scan(&ip, &cnt) == nil && ip != "" {
				nodes = append(nodes, node{
					"ip_" + strings.ReplaceAll(ip, ".", "_"), ip, "ip", cnt,
				})
			}
		}
	}

	alRows, _ := database.DB.Query(`
		SELECT DISTINCT al.agent_id, jf.hash
		FROM alerts al
		JOIN ja3_fingerprints jf ON al.log_message ILIKE '%' || jf.hash || '%'
		WHERE al.tenant_id = $1 AND al.mitre_technique = 'T1071.001'
		  AND al.created_at > NOW() - INTERVAL '7 days'
		LIMIT 20
	`, tid)
	if alRows != nil {
		defer alRows.Close()
		for alRows.Next() {
			var agentID int
			var hash string
			if alRows.Scan(&agentID, &hash) == nil && len(hash) >= 8 {
				edges = append(edges, edge{fmt.Sprintf("agent_%d", agentID), "ja3_" + hash[:8], 3})
			}
		}
	}

	connRows, _ := database.DB.Query(`
		SELECT DISTINCT ec.agent_id, SPLIT_PART(ec.remote_addr,':',1)
		FROM endpoint_connections ec
		JOIN agents a ON a.id = ec.agent_id
		WHERE a.tenant_id = $1
		  AND remote_addr NOT LIKE '10.%' AND remote_addr NOT LIKE '192.168.%' AND remote_addr NOT LIKE '172.%'
		LIMIT 20
	`, tid)
	if connRows != nil {
		defer connRows.Close()
		for connRows.Next() {
			var agentID int
			var ip string
			if connRows.Scan(&agentID, &ip) == nil && ip != "" {
				edges = append(edges, edge{
					fmt.Sprintf("agent_%d", agentID),
					"ip_" + strings.ReplaceAll(ip, ".", "_"),
					1,
				})
			}
		}
	}

	if nodes == nil {
		nodes = []node{}
	}
	if edges == nil {
		edges = []edge{}
	}
	c.JSON(http.StatusOK, gin.H{"nodes": nodes, "edges": edges})
}

// GetJA3ThreatIntel — GET /api/ja3/threat-intel
func GetJA3ThreatIntel(c *gin.Context) {
	tid := tenantIDFromContext(c)

	knownFamilies := []map[string]any{
		{
			"family": "Cobalt Strike", "confidence": 95,
			"hash":     "a0e9f5d64349fb13191bc781f81f42e1",
			"evidence": "Default Malleable C2 profile with 769 cipher suite; widely documented in threat intel reports",
			"mitre":    "T1071.001", "actor": "Various APT groups (Lazarus, APT41, FIN7)",
			"reports":  []string{"CrowdStrike CS-C2 Intel", "Recorded Future CS Fingerprint DB", "Abuse.ch JA3 Feed"},
			"category": "C2 Framework",
		},
		{
			"family": "Metasploit Meterpreter", "confidence": 90,
			"hash":     "6734f37431670b3ab4292b8f60f29984",
			"evidence": "Metasploit Meterpreter HTTPS stager — unique cipher list 49162,49161,57,56,53,49172,49171,55,51,50",
			"mitre":    "T1059.001", "actor": "Multiple threat actors, red teams",
			"reports":  []string{"Salesforce JA3 Research", "Sslbl.abuse.ch"},
			"category": "Exploitation Framework",
		},
		{
			"family": "Sliver C2", "confidence": 80,
			"hash":     "473cd7cb9faa642487833865d516e578",
			"evidence": "Sliver C2 framework default HTTPS beacon fingerprint",
			"mitre":    "T1071.001", "actor": "State-sponsored and criminal actors",
			"reports":  []string{"BishopFox Sliver Analysis", "Team Cymru JA3 DB"},
			"category": "C2 Framework",
		},
		{
			"family": "PowerShell Empire", "confidence": 75,
			"hash":     "a17b458f85ff9b1e2c9f7c30bc44e90b",
			"evidence": "Python requests library fingerprint in specific Empire config",
			"mitre":    "T1059.001", "actor": "FIN10, APT28",
			"reports":  []string{"BC-Security Empire Docs", "MITRE ATT&CK T1059.001"},
			"category": "C2 Framework",
		},
		{
			"family": "RedLine Stealer", "confidence": 85,
			"hash":     "0bab3f08a8a8a8f1815a42a1f4ff2a1a",
			"evidence": "RedLine infostealer TLS fingerprint — characteristic cipher ordering via WinHTTP",
			"mitre":    "T1041", "actor": "Underground criminal actors",
			"reports":  []string{"CISA AA22-264A", "Proofpoint RedLine Analysis"},
			"category": "Infostealer",
		},
		{
			"family": "TrickBot", "confidence": 70,
			"hash":     "72a589da586844d7f0818ce684948eea",
			"evidence": "TrickBot banking trojan HTTPS C2 using modified OpenSSL fingerprint",
			"mitre":    "T1071.001", "actor": "Wizard Spider / TA505",
			"reports":  []string{"Palo Alto Unit 42", "FireEye TrickBot Report"},
			"category": "Banking Trojan",
		},
	}

	hashRows, _ := database.DB.Query(`SELECT hash FROM ja3_fingerprints WHERE enabled = TRUE AND (tenant_id = $1 OR tenant_id IS NULL)`, tid)
	tenantHashes := map[string]bool{}
	if hashRows != nil {
		defer hashRows.Close()
		for hashRows.Next() {
			var h string
			if hashRows.Scan(&h) == nil {
				tenantHashes[h] = true
			}
		}
	}
	for i := range knownFamilies {
		if hp, ok := knownFamilies[i]["hash"].(string); ok {
			knownFamilies[i]["in_blocklist"] = tenantHashes[hp]
		}
	}

	type tiHit struct {
		RuleName  string `json:"rule_name"`
		Severity  string `json:"severity"`
		CreatedAt string `json:"created_at"`
		Hostname  string `json:"hostname"`
	}
	hitRows, _ := database.DB.Query(`
		SELECT al.rule_name, al.severity, al.created_at, ag.hostname
		FROM alerts al
		JOIN agents ag ON ag.id = al.agent_id
		WHERE al.tenant_id = $1 AND al.mitre_technique = 'T1071.001'
		  AND al.created_at > NOW() - INTERVAL '7 days'
		ORDER BY al.created_at DESC LIMIT 20
	`, tid)
	tiHits := []tiHit{}
	if hitRows != nil {
		defer hitRows.Close()
		for hitRows.Next() {
			var h tiHit
			if hitRows.Scan(&h.RuleName, &h.Severity, &h.CreatedAt, &h.Hostname) == nil {
				tiHits = append(tiHits, h)
			}
		}
	}
	if tiHits == nil {
		tiHits = []tiHit{}
	}

	c.JSON(http.StatusOK, gin.H{
		"malware_families": knownFamilies,
		"recent_hits":      tiHits,
	})
}

// GetJA3Timeline — GET /api/ja3/timeline
func GetJA3Timeline(c *gin.Context) {
	tid := tenantIDFromContext(c)

	type tlEntry struct {
		Hash         string  `json:"hash"`
		Name         string  `json:"threat_name"`
		Severity     string  `json:"severity"`
		FirstAdded   string  `json:"first_added"`
		FirstMatch   *string `json:"first_match"`
		LastMatch    *string `json:"last_match"`
		TotalMatches int     `json:"total_matches"`
	}
	rows, err := database.DB.Query(`
		SELECT jf.hash, jf.threat_name, jf.severity,
		       jf.created_at,
		       MIN(a.created_at),
		       MAX(a.created_at),
		       COUNT(a.id)
		FROM ja3_fingerprints jf
		LEFT JOIN alerts a ON a.log_message ILIKE '%' || jf.hash || '%'
		    AND a.tenant_id = $1
		WHERE jf.enabled = TRUE AND (jf.tenant_id = $1 OR jf.tenant_id IS NULL)
		GROUP BY jf.hash, jf.threat_name, jf.severity, jf.created_at
		ORDER BY MAX(a.created_at) DESC NULLS LAST
		LIMIT 20
	`, tid)
	entries := []tlEntry{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var e tlEntry
			var fm, lm *string
			if rows.Scan(&e.Hash, &e.Name, &e.Severity, &e.FirstAdded, &fm, &lm, &e.TotalMatches) == nil {
				e.FirstMatch = fm
				e.LastMatch = lm
				entries = append(entries, e)
			}
		}
	}
	if entries == nil {
		entries = []tlEntry{}
	}

	type dayPt struct {
		Date  string `json:"date"`
		Count int    `json:"count"`
	}
	dailyRows, _ := database.DB.Query(`
		SELECT DATE_TRUNC('day', created_at)::date, COUNT(*)
		FROM alerts
		WHERE tenant_id = $1 AND mitre_technique = 'T1071.001'
		  AND created_at > NOW() - INTERVAL '30 days'
		GROUP BY 1 ORDER BY 1
	`, tid)
	daily := []dayPt{}
	if dailyRows != nil {
		defer dailyRows.Close()
		for dailyRows.Next() {
			var d time.Time
			var cnt int
			if dailyRows.Scan(&d, &cnt) == nil {
				daily = append(daily, dayPt{d.Format("2006-01-02"), cnt})
			}
		}
	}
	if daily == nil {
		daily = []dayPt{}
	}

	c.JSON(http.StatusOK, gin.H{"fingerprints": entries, "daily": daily})
}

// GetJA3Watchlist — GET /api/ja3/watchlist
func GetJA3Watchlist(c *gin.Context) {
	tid := tenantIDFromContext(c)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS ja3_watchlist (
		id         SERIAL PRIMARY KEY,
		tenant_id  INT NOT NULL,
		hash       VARCHAR(32),
		label      VARCHAR(255) NOT NULL,
		watch_type VARCHAR(50) NOT NULL DEFAULT 'custom',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`)

	rows, err := database.DB.Query(`
		SELECT id, COALESCE(hash,''), label, watch_type, created_at
		FROM ja3_watchlist WHERE tenant_id = $1
		ORDER BY created_at DESC
	`, tid)
	type wlItem struct {
		ID        int    `json:"id"`
		Hash      string `json:"hash"`
		Label     string `json:"label"`
		WatchType string `json:"watch_type"`
		CreatedAt string `json:"created_at"`
	}
	items := []wlItem{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var w wlItem
			if rows.Scan(&w.ID, &w.Hash, &w.Label, &w.WatchType, &w.CreatedAt) == nil {
				items = append(items, w)
			}
		}
	}
	if items == nil {
		items = []wlItem{}
	}
	c.JSON(http.StatusOK, items)
}

// PostJA3Watchlist — POST /api/ja3/watchlist
func PostJA3Watchlist(c *gin.Context) {
	var body struct {
		Hash      string `json:"hash"`
		Label     string `json:"label" binding:"required"`
		WatchType string `json:"watch_type"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.WatchType == "" {
		body.WatchType = "custom"
	}
	tid := tenantIDFromContext(c)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS ja3_watchlist (
		id         SERIAL PRIMARY KEY,
		tenant_id  INT NOT NULL,
		hash       VARCHAR(32),
		label      VARCHAR(255) NOT NULL,
		watch_type VARCHAR(50) NOT NULL DEFAULT 'custom',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`)
	var id int
	if err := database.DB.QueryRow(`
		INSERT INTO ja3_watchlist (tenant_id, hash, label, watch_type)
		VALUES ($1,$2,$3,$4) RETURNING id
	`, tid, body.Hash, body.Label, body.WatchType).Scan(&id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// DeleteJA3WatchlistItem — DELETE /api/ja3/watchlist/:id
func DeleteJA3WatchlistItem(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	tid := tenantIDFromContext(c)
	database.DB.Exec(`DELETE FROM ja3_watchlist WHERE id = $1 AND tenant_id = $2`, id, tid)
	c.JSON(http.StatusOK, gin.H{"message": "removed"})
}

// PostJA3AI — POST /api/ja3/ai
func PostJA3AI(c *gin.Context) {
	var body struct {
		Action     string `json:"action"`
		Hash       string `json:"hash"`
		ThreatName string `json:"threat_name"`
		Prompt     string `json:"prompt"`
		Context    string `json:"context"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var prompt string
	switch body.Action {
	case "analyze":
		prompt = fmt.Sprintf(
			`Analyze this JA3 TLS fingerprint for a SOC analyst. Return JSON with keys: summary, threat_assessment, ioc_type, confidence (0-100), recommended_actions (string array), false_positive_risk, mitre_techniques (array of {id, name}).
JA3 Hash: %s
Threat Name: %s
Context: %s`, body.Hash, body.ThreatName, body.Context)
	case "explain":
		prompt = fmt.Sprintf(
			`Explain JA3 fingerprint "%s" (threat: "%s") to a SOC analyst.
Return JSON with keys: what_is_ja3, how_ja3_works, why_this_hash_is_malicious, what_tool_uses_it, detection_logic, investigation_steps (string array).`,
			body.Hash, body.ThreatName)
	case "hunt":
		prompt = fmt.Sprintf(
			`Generate threat hunting queries for JA3 hash "%s" (threat: "%s").
Return JSON with keys: splunk_query, elastic_query, sigma_rule, kql_query, zeek_filter, investigation_notes.`,
			body.Hash, body.ThreatName)
	case "generate_rule":
		prompt = fmt.Sprintf(
			`Generate a Sigma detection rule for JA3 hash "%s" (threat: "%s"). Context: %s.
Return JSON with keys: sigma_yaml, description, false_positive_notes, severity.`,
			body.Hash, body.ThreatName, body.Context)
	default:
		prompt = fmt.Sprintf(`Analyze JA3 fingerprint "%s" (threat: "%s"). Request: %s. Return JSON.`,
			body.Hash, body.ThreatName, body.Prompt)
	}

	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AI unavailable"})
		return
	}
	if idx := strings.Index(raw, "```json"); idx != -1 {
		raw = raw[idx+7:]
	} else if idx := strings.Index(raw, "```"); idx != -1 {
		raw = raw[idx+3:]
	}
	if idx := strings.LastIndex(raw, "```"); idx != -1 {
		raw = raw[:idx]
	}
	c.Data(http.StatusOK, "application/json", []byte(strings.TrimSpace(raw)))
}

// PostJA3Export — POST /api/ja3/export
func PostJA3Export(c *gin.Context) {
	var body struct {
		Format string `json:"format"`
		IDs    []int  `json:"ids"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Format == "" {
		body.Format = "json"
	}
	tid := tenantIDFromContext(c)

	var sqlStr string
	args := []any{}
	if len(body.IDs) > 0 {
		ph := make([]string, len(body.IDs))
		args = []any{tid}
		for i, id := range body.IDs {
			ph[i] = fmt.Sprintf("$%d", i+2)
			args = append(args, id)
		}
		sqlStr = fmt.Sprintf(`SELECT id, hash, threat_name, severity, source, COALESCE(description,''), enabled, created_at
			FROM ja3_fingerprints WHERE (tenant_id = $1 OR tenant_id IS NULL) AND id IN (%s) ORDER BY threat_name`,
			strings.Join(ph, ","))
	} else {
		sqlStr = `SELECT id, hash, threat_name, severity, source, COALESCE(description,''), enabled, created_at
			FROM ja3_fingerprints WHERE (tenant_id = $1 OR tenant_id IS NULL) AND enabled = TRUE ORDER BY threat_name`
		args = []any{tid}
	}

	rows, err := database.DB.Query(sqlStr, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type fp struct {
		ID          int    `json:"id"`
		Hash        string `json:"hash"`
		ThreatName  string `json:"threat_name"`
		Severity    string `json:"severity"`
		Source      string `json:"source"`
		Description string `json:"description"`
		Enabled     bool   `json:"enabled"`
		CreatedAt   string `json:"created_at"`
	}
	fps := []fp{}
	for rows.Next() {
		var f fp
		if rows.Scan(&f.ID, &f.Hash, &f.ThreatName, &f.Severity, &f.Source, &f.Description, &f.Enabled, &f.CreatedAt) == nil {
			fps = append(fps, f)
		}
	}
	if fps == nil {
		fps = []fp{}
	}

	switch body.Format {
	case "csv":
		var sb strings.Builder
		sb.WriteString("id,hash,threat_name,severity,source,description,enabled,created_at\n")
		for _, f := range fps {
			sb.WriteString(fmt.Sprintf("%d,%s,%q,%s,%s,%q,%v,%s\n",
				f.ID, f.Hash, f.ThreatName, f.Severity, f.Source, f.Description, f.Enabled, f.CreatedAt))
		}
		c.Data(http.StatusOK, "text/csv", []byte(sb.String()))
	case "stix":
		indicators := make([]map[string]any, len(fps))
		for i, f := range fps {
			indicators[i] = map[string]any{
				"type":            "indicator",
				"spec_version":    "2.1",
				"id":              "indicator--ja3-" + f.Hash,
				"name":            f.ThreatName,
				"pattern":         fmt.Sprintf("[network-traffic:extensions.'tls-ext'.client_fingerprint = '%s']", f.Hash),
				"pattern_type":    "stix",
				"valid_from":      f.CreatedAt,
				"indicator_types": []string{"malicious-activity"},
				"confidence":      85,
				"description":     f.Description,
				"labels":          []string{"ja3", f.Severity},
			}
		}
		c.JSON(http.StatusOK, map[string]any{
			"type": "bundle", "id": "bundle--xcloak-ja3-export", "objects": indicators,
		})
	default:
		c.JSON(http.StatusOK, fps)
	}
}

// PostJA3Bulk — POST /api/ja3/bulk
func PostJA3Bulk(c *gin.Context) {
	var body struct {
		Action string `json:"action" binding:"required"`
		IDs    []int  `json:"ids"    binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(body.IDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no ids provided"})
		return
	}
	tid := tenantIDFromContext(c)

	ph := make([]string, len(body.IDs))
	args := []any{tid}
	for i, id := range body.IDs {
		ph[i] = fmt.Sprintf("$%d", i+2)
		args = append(args, id)
	}
	in := strings.Join(ph, ",")

	var sqlStr string
	switch body.Action {
	case "enable":
		sqlStr = fmt.Sprintf(`UPDATE ja3_fingerprints SET enabled=TRUE  WHERE tenant_id=$1 AND id IN (%s)`, in)
	case "disable":
		sqlStr = fmt.Sprintf(`UPDATE ja3_fingerprints SET enabled=FALSE WHERE tenant_id=$1 AND id IN (%s)`, in)
	case "delete":
		sqlStr = fmt.Sprintf(`DELETE FROM ja3_fingerprints WHERE tenant_id=$1 AND id IN (%s)`, in)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown action"})
		return
	}

	res, err := database.DB.Exec(sqlStr, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	n, _ := res.RowsAffected()
	c.JSON(http.StatusOK, gin.H{"affected": n, "action": body.Action})
}

// GetJA3FingerprintDetail — GET /api/ja3/fingerprints/:hash/detail
func GetJA3FingerprintDetail(c *gin.Context) {
	hash := c.Param("hash")
	tid := tenantIDFromContext(c)

	var id int
	var h, threatName, severity, source, description, createdAt string
	var enabled, isPlatform bool
	err := database.DB.QueryRow(`
		SELECT id, hash, threat_name, severity, source,
		       COALESCE(description,''), enabled,
		       tenant_id IS NULL, created_at
		FROM ja3_fingerprints
		WHERE hash = $1 AND (tenant_id = $2 OR tenant_id IS NULL)
		ORDER BY tenant_id DESC NULLS LAST LIMIT 1
	`, hash, tid).Scan(&id, &h, &threatName, &severity, &source, &description, &enabled, &isPlatform, &createdAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "fingerprint not found"})
		return
	}

	type alEntry struct {
		ID         int    `json:"id"`
		Severity   string `json:"severity"`
		LogMessage string `json:"log_message"`
		CreatedAt  string `json:"created_at"`
		Hostname   string `json:"hostname"`
	}
	alRows, _ := database.DB.Query(`
		SELECT al.id, al.severity, al.log_message, al.created_at, ag.hostname
		FROM alerts al
		JOIN agents ag ON ag.id = al.agent_id
		WHERE al.tenant_id = $1 AND al.log_message ILIKE '%' || $2 || '%'
		ORDER BY al.created_at DESC LIMIT 20
	`, tid, h)
	alerts := []alEntry{}
	if alRows != nil {
		defer alRows.Close()
		for alRows.Next() {
			var a alEntry
			if alRows.Scan(&a.ID, &a.Severity, &a.LogMessage, &a.CreatedAt, &a.Hostname) == nil {
				alerts = append(alerts, a)
			}
		}
	}
	if alerts == nil {
		alerts = []alEntry{}
	}

	type connEntry struct {
		RemoteAddr string `json:"remote_addr"`
		Protocol   string `json:"protocol"`
		Hostname   string `json:"hostname"`
		Count      int    `json:"count"`
	}
	connRows, _ := database.DB.Query(`
		SELECT DISTINCT ec.remote_addr, ec.protocol, ag.hostname, COUNT(*) AS cnt
		FROM endpoint_connections ec
		JOIN agents ag ON ag.id = ec.agent_id
		WHERE ag.tenant_id = $1 AND ec.created_at > NOW() - INTERVAL '7 days'
		GROUP BY ec.remote_addr, ec.protocol, ag.hostname
		ORDER BY cnt DESC LIMIT 10
	`, tid)
	connections := []connEntry{}
	if connRows != nil {
		defer connRows.Close()
		for connRows.Next() {
			var co connEntry
			if connRows.Scan(&co.RemoteAddr, &co.Protocol, &co.Hostname, &co.Count) == nil {
				connections = append(connections, co)
			}
		}
	}
	if connections == nil {
		connections = []connEntry{}
	}

	c.JSON(http.StatusOK, gin.H{
		"fingerprint": map[string]any{
			"id": id, "hash": h, "threat_name": threatName,
			"severity": severity, "source": source, "description": description,
			"enabled": enabled, "is_platform": isPlatform, "created_at": createdAt,
		},
		"alerts":      alerts,
		"connections": connections,
		"alert_count": len(alerts),
	})
}
