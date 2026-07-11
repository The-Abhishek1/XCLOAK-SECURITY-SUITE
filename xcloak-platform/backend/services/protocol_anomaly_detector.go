package services

// Protocol Anomaly Detector
//
// Detects protocols running on wrong ports (DNS tunneling, HTTP on 8080, SSH
// on 443, etc.) and common covert channel / tunneling patterns.
//
// Detection categories:
//   1. DNS tunneling — long TXT/NULL queries, high query rates, large responses
//   2. Protocol-on-wrong-port — SSH on 443, SMB on 80, FTP on random ports
//   3. ICMP tunneling — large ICMP payload size seen in connect events
//   4. HTTP CONNECT tunnel abuse — CONNECT to internal hosts via proxy
//   5. Non-HTTP on port 80/443 — binary payload entropy on clear-text ports
//   6. Excessive DNS over TCP — fallback to TCP hints at large payload tunneling
//   7. SMTP exfil — SMTP to non-standard ports, unauthenticated relays

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// StartProtocolAnomalyScheduler runs protocol checks every 10 minutes.
func StartProtocolAnomalyScheduler() {
	go func() {
		time.Sleep(3 * time.Minute)
		runProtoSweepAll()
		for {
			time.Sleep(10 * time.Minute)
			runProtoSweepAll()
		}
	}()
}

func runProtoSweepAll() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active=true`)
	if err != nil { return }
	defer rows.Close()
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			RunProtocolAnomalyForTenant(id)
		}
	}
}

// RunProtocolAnomalyForTenant runs all protocol sub-checks for one tenant.
func RunProtocolAnomalyForTenant(tenantID int) {
	detectDNSTunneling(tenantID)
	detectProtoOnWrongPort(tenantID)
	detectICMPTunnel(tenantID)
	detectHTTPConnectAbuse(tenantID)
	detectExcessiveDNSTCP(tenantID)
	detectSMTPExfil(tenantID)
}

// ── 1. DNS tunneling ──────────────────────────────────────────────────────────

func detectDNSTunneling(tenantID int) {
	// Agents with unusually long subdomain labels in NCE SNI/host fields
	// (DNS tunnel data is encoded in subdomain labels, so labels become very long)
	rows, err := database.DB.Query(`
		SELECT agent_id, sni, http_host
		FROM network_connect_events
		WHERE tenant_id = $1
		  AND created_at > NOW() - INTERVAL '10 minutes'
		  AND (LENGTH(sni) > 52 OR LENGTH(http_host) > 52)
		  AND (sni LIKE '%.%' OR http_host LIKE '%.%')
	`, tenantID)
	if err != nil { return }
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var sni, host string
		if rows.Scan(&agentID, &sni, &host) != nil { continue }

		candidate := sni
		if len(host) > len(sni) {
			candidate = host
		}
		parts := strings.Split(candidate, ".")
		if len(parts) < 3 { continue }

		// Check if the leftmost label is suspiciously long (> 40 chars)
		if len(parts[0]) < 40 { continue }

		recordProtoFinding(agentID, tenantID, "dns_tunnel", "high",
			fmt.Sprintf("Possible DNS tunnel: long subdomain label %q (%d chars) in %q", truncate(parts[0], 40), len(parts[0]), candidate),
			candidate, "T1071.004", map[string]interface{}{
				"domain": candidate, "label_len": len(parts[0]), "reason": "long_subdomain",
			}, 75)
	}

	// Agents with very high DNS query rate (event count) to many unique domains
	queryRows, err := database.DB.Query(`
		SELECT agent_id, COUNT(DISTINCT sni) AS unique_sni_count
		FROM network_connect_events
		WHERE tenant_id = $1
		  AND created_at > NOW() - INTERVAL '10 minutes'
		  AND sni != ''
		GROUP BY agent_id
		HAVING COUNT(DISTINCT sni) > 200
	`, tenantID)
	if err != nil { return }
	defer queryRows.Close()

	for queryRows.Next() {
		var agentID, count int
		if queryRows.Scan(&agentID, &count) != nil { continue }
		recordProtoFinding(agentID, tenantID, "dns_tunnel", "medium",
			fmt.Sprintf("High DNS query rate: %d unique domains contacted in 10 minutes (possible DNS tunnel exfil)", count),
			"high_query_rate", "T1071.004", map[string]interface{}{
				"unique_domains": count, "window": "10min", "reason": "query_rate",
			}, 65)
	}
}

// ── 2. Protocol on wrong port ─────────────────────────────────────────────────

// expectedPorts maps protocol names (as they appear in log parsed_fields) to
// their standard ports. Traffic on any other port is flagged.
var expectedPorts = map[string][]string{
	"ssh":  {"22"},
	"ftp":  {"20", "21"},
	"smtp": {"25", "465", "587"},
	"rdp":  {"3389"},
	"smb":  {"445", "139"},
	"dns":  {"53"},
	"ldap": {"389", "636"},
	"nfs":  {"2049"},
	"vnc":  {"5900", "5901", "5902"},
}

func detectProtoOnWrongPort(tenantID int) {
	// Query endpoint_logs for connections whose parsed protocol doesn't match port
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       lower(COALESCE(el.parsed_fields->>'protocol', el.parsed_fields->>'app_proto', '')) AS proto,
		       COALESCE(el.parsed_fields->>'dst_port', el.parsed_fields->>'port', '0') AS port,
		       COALESCE(el.parsed_fields->>'dst_ip', '') AS dst
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id
		WHERE a.tenant_id = $1
		  AND el.collected_at > NOW() - INTERVAL '10 minutes'
		  AND el.parsed_fields->>'protocol' IS NOT NULL
		  AND el.parsed_fields->>'dst_port' IS NOT NULL
	`, tenantID)
	if err != nil { return }
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var proto, port, dst string
		if rows.Scan(&agentID, &proto, &port, &dst) != nil { continue }
		if proto == "" || port == "" || port == "0" { continue }

		expected, ok := expectedPorts[proto]
		if !ok { continue }

		onExpected := false
		for _, p := range expected {
			if p == port { onExpected = true; break }
		}
		if onExpected { continue }

		severity := "medium"
		score := 65
		if proto == "ssh" && (port == "443" || port == "80") {
			severity = "high"
			score = 80
		}
		if proto == "smb" && port != "445" && port != "139" {
			severity = "high"
			score = 80
		}

		recordProtoFinding(agentID, tenantID, "proto_on_wrong_port", severity,
			fmt.Sprintf("Protocol %q running on non-standard port %s to %s (expected: %s)",
				proto, port, dst, strings.Join(expected, "/")),
			fmt.Sprintf("%s:%s", proto, port), "T1571", map[string]interface{}{
				"protocol": proto, "port": port, "dst": dst,
				"expected_ports": expected, "reason": "wrong_port",
			}, score)
	}
}

// ── 3. ICMP tunnel detection ──────────────────────────────────────────────────

func detectICMPTunnel(tenantID int) {
	// Very large ICMP payloads indicate data tunneling over ping
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       COALESCE(el.parsed_fields->>'bytes', '0')::int AS payload_bytes,
		       COALESCE(el.parsed_fields->>'dst_ip', '') AS dst
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id
		WHERE a.tenant_id = $1
		  AND el.collected_at > NOW() - INTERVAL '10 minutes'
		  AND lower(COALESCE(el.parsed_fields->>'protocol','')) = 'icmp'
		  AND (el.parsed_fields->>'bytes')::int > 1000
	`, tenantID)
	if err != nil { return }
	defer rows.Close()

	for rows.Next() {
		var agentID, payloadBytes int
		var dst string
		if rows.Scan(&agentID, &payloadBytes, &dst) != nil { continue }

		severity := "medium"
		score := 65
		if payloadBytes > 4096 {
			severity = "high"
			score = 80
		}

		recordProtoFinding(agentID, tenantID, "icmp_tunnel", severity,
			fmt.Sprintf("Large ICMP payload: %d bytes to %s — possible ICMP tunnel/exfil", payloadBytes, dst),
			fmt.Sprintf("icmp:%s", dst), "T1095", map[string]interface{}{
				"payload_bytes": payloadBytes, "dst": dst, "reason": "large_icmp",
			}, score)
	}
}

// ── 4. HTTP CONNECT tunnel abuse ──────────────────────────────────────────────

func detectHTTPConnectAbuse(tenantID int) {
	// CONNECT requests to internal addresses (RFC 1918) are suspicious
	rows, err := database.DB.Query(`
		SELECT agent_id, http_host, http_path, remote_address
		FROM network_connect_events
		WHERE tenant_id = $1
		  AND created_at > NOW() - INTERVAL '10 minutes'
		  AND http_method = 'CONNECT'
		  AND (
		    http_host LIKE '10.%' OR http_host LIKE '192.168.%'
		    OR http_host LIKE '172.16.%' OR http_host LIKE '172.17.%'
		    OR http_host LIKE '172.18.%' OR http_host LIKE '172.19.%'
		    OR http_host LIKE '172.2_.%' OR http_host LIKE '172.30.%'
		    OR http_host LIKE '172.31.%'
		  )
	`, tenantID)
	if err != nil { return }
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var host, path, remote string
		if rows.Scan(&agentID, &host, &path, &remote) != nil { continue }

		recordProtoFinding(agentID, tenantID, "http_connect_tunnel", "high",
			fmt.Sprintf("HTTP CONNECT to internal host %q from %s — possible proxy tunnel for lateral movement", host, remote),
			fmt.Sprintf("CONNECT:%s", host), "T1572", map[string]interface{}{
				"host": host, "path": path, "remote": remote, "reason": "connect_internal",
			}, 80)
	}
}

// ── 5. Excessive DNS over TCP ─────────────────────────────────────────────────

func detectExcessiveDNSTCP(tenantID int) {
	// DNS-over-TCP is normal for large responses but unusual in high volume
	// (> 30 TCP connections to port 53 in 10 minutes suggests tunneling)
	rows, err := database.DB.Query(`
		SELECT agent_id, COUNT(*) AS tcp53_count
		FROM network_connect_events
		WHERE tenant_id = $1
		  AND created_at > NOW() - INTERVAL '10 minutes'
		  AND proto = 'tcp'
		  AND (remote_address LIKE '%:53' OR remote_address LIKE '%:53/%')
		GROUP BY agent_id
		HAVING COUNT(*) > 30
	`, tenantID)
	if err != nil { return }
	defer rows.Close()

	for rows.Next() {
		var agentID, count int
		if rows.Scan(&agentID, &count) != nil { continue }

		recordProtoFinding(agentID, tenantID, "dns_tcp_tunnel", "high",
			fmt.Sprintf("%d DNS-over-TCP connections in 10 minutes — possible DNS tunnel using TCP for large payload exfil", count),
			"dns_tcp_volume", "T1071.004", map[string]interface{}{
				"tcp53_count": count, "window": "10min", "reason": "dns_tcp_flood",
			}, 75)
	}
}

// ── 6. SMTP exfiltration ──────────────────────────────────────────────────────

func detectSMTPExfil(tenantID int) {
	// SMTP connections to non-standard SMTP ports from non-mail servers
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       COALESCE(el.parsed_fields->>'dst_ip','') AS dst,
		       COALESCE(el.parsed_fields->>'dst_port','') AS port
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id
		WHERE a.tenant_id = $1
		  AND el.collected_at > NOW() - INTERVAL '10 minutes'
		  AND lower(COALESCE(el.parsed_fields->>'protocol','')) = 'smtp'
		  AND el.parsed_fields->>'dst_port' NOT IN ('25','465','587')
	`, tenantID)
	if err != nil { return }
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var dst, port string
		if rows.Scan(&agentID, &dst, &port) != nil { continue }

		recordProtoFinding(agentID, tenantID, "smtp_non_standard", "medium",
			fmt.Sprintf("SMTP traffic on non-standard port %s to %s — possible exfil or C2 via email channel", port, dst),
			fmt.Sprintf("smtp:%s", dst), "T1048.002", map[string]interface{}{
				"dst": dst, "port": port, "reason": "smtp_wrong_port",
			}, 65)
	}
}

// ── Shared helper ─────────────────────────────────────────────────────────────

func recordProtoFinding(agentID, tenantID int, findingType, severity, desc, indicator, mitre string, ctx map[string]interface{}, score int) {
	var existing int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM dpi_findings
		WHERE agent_id=$1 AND finding_type=$2 AND indicator=$3
		  AND detected_at > NOW() - INTERVAL '30 minutes'
	`, agentID, findingType, truncate(indicator, 255)).Scan(&existing)
	if existing > 0 { return }

	ctxJSON, _ := json.Marshal(ctx)
	alertFired := score >= 70
	database.DB.Exec(`
		INSERT INTO dpi_findings
		  (agent_id, tenant_id, finding_type, severity, score, indicator,
		   description, mitre_technique, raw_context, alert_fired)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`, agentID, tenantID, findingType, severity, score, truncate(indicator, 255),
		desc, mitre, ctxJSON, alertFired)

	if alertFired {
		log.Printf("[PROTO] agent=%d type=%s sev=%s: %s", agentID, findingType, severity, truncate(desc, 100))
		alert := models.Alert{
			AgentID:        agentID,
			TenantID:       tenantID,
			RuleName:       "Protocol Anomaly: " + findingType,
			Severity:       severity,
			LogMessage:     desc,
			MitreTechnique: mitre,
			Fingerprint:    fmt.Sprintf("%d-proto-%x", agentID, simpleHash(indicator+desc)),
		}
		CreateAlert(alert) //nolint:errcheck
	}
}
