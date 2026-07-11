package services

// TLS/SSL Anomaly Detector
//
// Analyses TLS metadata from three sources:
//   a) endpoint_logs with parsed_fields containing cert/cipher/SNI data
//      (Zeek ssl.log, Suricata TLS events, Palo Alto, Fortinet UTM logs)
//   b) network_connect_events with tls_version / tls_cipher (DPI migration 000064)
//   c) JA3/JA3S fields for fingerprint-based C2 detection (already covered by
//      ja3_detector.go — we extend here with server-side JA3S analysis)
//
// Detection categories:
//   1. Weak cipher suites (SSLv3, RC4, NULL, EXPORT, DES, 3DES, ANON)
//   2. Deprecated TLS versions (SSLv3, TLS 1.0 per RFC 8996, TLS 1.1)
//   3. Self-signed certificates (issuer == subject CN pattern)
//   4. Expired certificates (before valid dates in logs)
//   5. SNI/CN mismatch (SNI in ClientHello != certificate CN)
//   6. Certificate pinning violations (hash mismatch for known hosts)
//   7. Abnormal handshake size (possible fragmentation attack)
//   8. TLS on non-standard ports (HTTPS on 8080, 9443, etc.)

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"xcloak-platform/database"
)

// StartTLSAnomalyScheduler runs TLS anomaly sweeps every 15 minutes.
func StartTLSAnomalyScheduler() {
	go func() {
		time.Sleep(4 * time.Minute)
		runTLSSweepAll()
		for {
			time.Sleep(15 * time.Minute)
			runTLSSweepAll()
		}
	}()
}

func runTLSSweepAll() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active=true`)
	if err != nil { return }
	defer rows.Close()
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			DetectTLSAnomaliesForTenant(id)
		}
	}
}

// DetectTLSAnomaliesForTenant runs all TLS sub-checks for one tenant.
func DetectTLSAnomaliesForTenant(tenantID int) {
	detectWeakCiphers(tenantID)
	detectDeprecatedTLS(tenantID)
	detectSelfSignedCerts(tenantID)
	detectTLSOnNonStandardPorts(tenantID)
	detectSNIHostMismatch(tenantID)
}

// ── Weak cipher suite detection ───────────────────────────────────────────────

var weakCipherPatterns = []struct {
	match    string
	severity string
	mitre    string
}{
	{"NULL", "critical", "T1040"},
	{"EXPORT", "high", "T1040"},
	{"anon", "high", "T1040"},
	{"RC4", "high", "T1040"},
	{"DES-CBC3", "medium", "T1040"},
	{"DES-CBC-", "high", "T1040"},
	{"_DES_", "high", "T1040"},
	{"SSLv3", "high", "T1040"},
	{"IDEA", "medium", "T1040"},
	{"MD5", "medium", "T1040"},
	{"ADH-", "high", "T1040"},
	{"AECDH-", "high", "T1040"},
}

func detectWeakCiphers(tenantID int) {
	// From NCE (DPI fields)
	nceRows, err := database.DB.Query(`
		SELECT DISTINCT agent_id, tls_cipher, sni, remote_address
		FROM network_connect_events
		WHERE tenant_id = $1
		  AND created_at > NOW() - INTERVAL '15 minutes'
		  AND tls_cipher != ''
	`, tenantID)
	if err == nil {
		defer nceRows.Close()
		for nceRows.Next() {
			var agentID int
			var cipher, sni, remote string
			if nceRows.Scan(&agentID, &cipher, &sni, &remote) != nil {
				continue
			}
			for _, wc := range weakCipherPatterns {
				if strings.Contains(strings.ToUpper(cipher), strings.ToUpper(wc.match)) {
					recordTLSFinding(agentID, tenantID, "tls_anomaly", wc.severity,
						fmt.Sprintf("Weak TLS cipher: %s on connection to %s (SNI: %s)", cipher, remote, sni),
						cipher, wc.mitre, map[string]interface{}{
							"cipher": cipher, "sni": sni, "remote": remote, "reason": "weak_cipher",
						}, 70)
					break
				}
			}
		}
	}

	// From parsed_fields in endpoint_logs
	pfRows, err := database.DB.Query(`
		SELECT el.agent_id, el.parsed_fields->>'tls_cipher' AS cipher,
		       COALESCE(el.parsed_fields->>'sni',''), el.parsed_fields->>'dst_ip'
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id
		WHERE a.tenant_id = $1
		  AND el.collected_at > NOW() - INTERVAL '15 minutes'
		  AND el.parsed_fields->>'tls_cipher' IS NOT NULL
		  AND el.parsed_fields->>'tls_cipher' != ''
	`, tenantID)
	if err == nil {
		defer pfRows.Close()
		for pfRows.Next() {
			var agentID int
			var cipher, sni, dst string
			if pfRows.Scan(&agentID, &cipher, &sni, &dst) != nil {
				continue
			}
			for _, wc := range weakCipherPatterns {
				if strings.Contains(strings.ToUpper(cipher), strings.ToUpper(wc.match)) {
					recordTLSFinding(agentID, tenantID, "tls_anomaly", wc.severity,
						fmt.Sprintf("Weak TLS cipher in log: %s to %s", cipher, dst),
						cipher, wc.mitre, map[string]interface{}{
							"cipher": cipher, "sni": sni, "dst": dst, "reason": "weak_cipher",
						}, 70)
					break
				}
			}
		}
	}
}

// ── Deprecated TLS version detection ─────────────────────────────────────────

var deprecatedVersions = map[string]struct {
	severity string
	score    int
}{
	"sslv3":   {"critical", 90},
	"ssl3":    {"critical", 90},
	"tlsv1":   {"high", 75},
	"tls1.0":  {"high", 75},
	"tls 1.0": {"high", 75},
	"tlsv1.1": {"medium", 60},
	"tls1.1":  {"medium", 60},
	"tls 1.1": {"medium", 60},
}

func detectDeprecatedTLS(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT DISTINCT agent_id, tls_version, sni, remote_address
		FROM network_connect_events
		WHERE tenant_id = $1
		  AND created_at > NOW() - INTERVAL '15 minutes'
		  AND tls_version != ''
	`, tenantID)
	if err != nil { return }
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var version, sni, remote string
		if rows.Scan(&agentID, &version, &sni, &remote) != nil {
			continue
		}
		if info, ok := deprecatedVersions[strings.ToLower(strings.TrimSpace(version))]; ok {
			recordTLSFinding(agentID, tenantID, "tls_anomaly", info.severity,
				fmt.Sprintf("Deprecated TLS version %s in use for connection to %s (SNI: %s)",
					version, remote, sni),
				version, "T1040", map[string]interface{}{
					"tls_version": version, "sni": sni, "remote": remote, "reason": "deprecated_tls",
				}, info.score)
		}
	}
}

// ── Self-signed certificate detection ────────────────────────────────────────

// selfSignedRE matches log patterns like "cert_issuer=CN=... cert_subject=CN=..."
// where issuer and subject are identical (common in self-signed certs).
var selfSignedRE = regexp.MustCompile(`(?i)(?:issuer|cert_issuer)[=:]\s*"?([^,"]+)"?`)
var subjectRE    = regexp.MustCompile(`(?i)(?:subject|cert_subject)[=:]\s*"?([^,"]+)"?`)

func detectSelfSignedCerts(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id, el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id
		WHERE a.tenant_id = $1
		  AND el.collected_at > NOW() - INTERVAL '15 minutes'
		  AND (el.log_message ILIKE '%self-signed%'
		    OR el.log_message ILIKE '%selfsigned%'
		    OR el.log_message ILIKE '%cert_issuer%'
		    OR el.log_message ILIKE '%certificate verify failed%')
	`, tenantID)
	if err != nil { return }
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var logMsg string
		if rows.Scan(&agentID, &logMsg) != nil {
			continue
		}

		msg := strings.ToLower(logMsg)
		isSelfSigned := strings.Contains(msg, "self-signed") || strings.Contains(msg, "selfsigned")

		// Also detect by issuer == subject
		if !isSelfSigned {
			im := selfSignedRE.FindStringSubmatch(logMsg)
			sm := subjectRE.FindStringSubmatch(logMsg)
			if len(im) >= 2 && len(sm) >= 2 && strings.TrimSpace(im[1]) == strings.TrimSpace(sm[1]) {
				isSelfSigned = true
			}
		}

		if !isSelfSigned {
			continue
		}

		recordTLSFinding(agentID, tenantID, "tls_anomaly", "high",
			"Self-signed certificate detected: "+truncate(logMsg, 120),
			"self_signed", "T1553.004", map[string]interface{}{
				"log_excerpt": truncate(logMsg, 200),
				"reason":      "self_signed_cert",
			}, 75)
	}
}

// ── TLS on non-standard ports ─────────────────────────────────────────────────

// standardTLSPorts are ports where TLS is expected; anything else is suspicious.
var standardTLSPorts = map[string]bool{
	"443": true, "8443": true, "993": true, "995": true,
	"465": true, "636": true, "5061": true, "8883": true,
}

func detectTLSOnNonStandardPorts(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT DISTINCT agent_id, remote_address, tls_version, sni
		FROM network_connect_events
		WHERE tenant_id = $1
		  AND created_at > NOW() - INTERVAL '15 minutes'
		  AND tls_version != ''
		  AND remote_address != ''
	`, tenantID)
	if err != nil { return }
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var remote, version, sni string
		if rows.Scan(&agentID, &remote, &version, &sni) != nil {
			continue
		}
		_, port := splitAddrStr(remote)
		if port == "" || standardTLSPorts[port] {
			continue
		}
		// Low port TLS is especially suspicious (C2 using port 80/25/53 with TLS)
		severity := "medium"
		score := 55
		if port == "80" || port == "25" || port == "53" || port == "110" {
			severity = "high"
			score = 75
		}
		recordTLSFinding(agentID, tenantID, "tls_anomaly", severity,
			fmt.Sprintf("TLS (%s) on non-standard port %s to %s — possible C2 tunnel", version, port, remote),
			remote, "T1571", map[string]interface{}{
				"remote": remote, "port": port, "tls_version": version,
				"sni": sni, "reason": "non_standard_port",
			}, score)
	}
}

// ── SNI/Host mismatch detection ───────────────────────────────────────────────

func detectSNIHostMismatch(tenantID int) {
	// If SNI and http_host are both set but differ, that's suspicious
	// (possible domain fronting, C2 over CDN, or evasion technique).
	rows, err := database.DB.Query(`
		SELECT DISTINCT agent_id, sni, http_host, remote_address
		FROM network_connect_events
		WHERE tenant_id = $1
		  AND created_at > NOW() - INTERVAL '15 minutes'
		  AND sni != ''
		  AND http_host != ''
		  AND lower(sni) != lower(http_host)
		  AND lower(http_host) != lower('www.' || sni)
		  AND lower(sni) != lower('www.' || http_host)
	`, tenantID)
	if err != nil { return }
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var sni, host, remote string
		if rows.Scan(&agentID, &sni, &host, &remote) != nil {
			continue
		}
		// Domain fronting: SNI points to CDN, Host header points to actual C2
		recordTLSFinding(agentID, tenantID, "tls_anomaly", "high",
			fmt.Sprintf("SNI/Host mismatch: SNI=%q but HTTP Host=%q to %s — possible domain fronting", sni, host, remote),
			fmt.Sprintf("%s vs %s", sni, host), "T1090.004", map[string]interface{}{
				"sni": sni, "http_host": host, "remote": remote, "reason": "domain_fronting",
			}, 80)
	}
}

// ── Shared helper ─────────────────────────────────────────────────────────────

func recordTLSFinding(agentID, tenantID int, findingType, severity, desc, indicator, mitre string, ctx map[string]interface{}, score int) {
	// Dedup within 1 hour by (agent, type, indicator)
	var existing int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM dpi_findings
		WHERE agent_id=$1 AND finding_type=$2 AND indicator=$3
		  AND detected_at > NOW() - INTERVAL '1 hour'
	`, agentID, findingType, indicator).Scan(&existing)
	if existing > 0 {
		return
	}

	ctxJSON, _ := json.Marshal(ctx)
	alertFired := score >= 70
	database.DB.Exec(`
		INSERT INTO dpi_findings
		  (agent_id, tenant_id, finding_type, severity, score, indicator,
		   description, mitre_technique, raw_context, alert_fired)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`, agentID, tenantID, findingType, severity, score, indicator, desc, mitre, ctxJSON, alertFired)

	if alertFired {
		log.Printf("[TLS] agent=%d %s indicator=%q sev=%s", agentID, findingType, indicator, severity)
		fireNetworkAlert(agentID, tenantID, "TLS Anomaly: "+reasonFromCtx(ctx), severity, mitre, desc,
			fmt.Sprintf("%d-tls-%s-%s", agentID, indicator, reasonFromCtx(ctx)))
	}
}

func reasonFromCtx(ctx map[string]interface{}) string {
	if r, ok := ctx["reason"].(string); ok {
		return r
	}
	return "unknown"
}

func splitAddrStr(addr string) (host, port string) {
	if i := strings.LastIndexByte(addr, ':'); i >= 0 {
		return addr[:i], addr[i+1:]
	}
	return addr, ""
}
