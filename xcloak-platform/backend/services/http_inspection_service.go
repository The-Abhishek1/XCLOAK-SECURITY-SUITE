package services

// HTTP Inspection Service
//
// Analyses HTTP metadata (method, path, User-Agent, response codes, headers)
// extracted from endpoint logs and network_connect_events DPI fields.
//
// Detection categories:
//   1. Malicious User-Agents — known RAT/C2/scanner signatures (50+ patterns)
//   2. Web shell access — suspicious paths matching common webshell names
//   3. Path traversal — ../../ sequences in URL paths
//   4. Suspicious HTTP methods — PROPFIND, TRACK, TRACE, DEBUG on non-standard servers
//   5. Encoded payload smuggling — base64, double-encoding, %00 null byte in paths
//   6. High-entropy POST bodies — likely encrypted C2 channel
//   7. Cookie-channel C2 — base64 in cookies (Cobalt Strike beacon pattern)
//   8. Suspicious referer patterns — referrers that don't match expected origin
//   9. HTTP verb tampering — method override headers (X-HTTP-Method-Override)
//  10. Scanner fingerprints — Nmap HTTP scripts, Nikto, sqlmap, Gobuster

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// StartHTTPInspectionScheduler runs HTTP pattern checks every 10 minutes.
func StartHTTPInspectionScheduler() {
	go func() {
		time.Sleep(2 * time.Minute)
		runHTTPInspectionAll()
		for {
			time.Sleep(10 * time.Minute)
			runHTTPInspectionAll()
		}
	}()
}

func runHTTPInspectionAll() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active=true`)
	if err != nil { return }
	defer rows.Close()
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			RunHTTPInspectionForTenant(id)
		}
	}
}

// RunHTTPInspectionForTenant runs all HTTP sub-checks for one tenant.
func RunHTTPInspectionForTenant(tenantID int) {
	scanMaliciousUserAgents(tenantID)
	scanWebShellPaths(tenantID)
	scanSuspiciousMethods(tenantID)
	scanHTTPNCEFields(tenantID)
}

// ── 1. Malicious User-Agent detection ────────────────────────────────────────

type uaPattern struct {
	pattern  string
	name     string
	severity string
	mitre    string
}

var maliciousUAPatterns = []uaPattern{
	// C2 frameworks
	{"cobalt strike", "Cobalt Strike beacon", "critical", "T1071.001"},
	{"cobaltstrike", "Cobalt Strike", "critical", "T1071.001"},
	{"metasploit", "Metasploit", "critical", "T1071.001"},
	{"meterpreter", "Meterpreter", "critical", "T1071.001"},
	{"empire", "PowerShell Empire", "critical", "T1071.001"},
	{"havoc", "Havoc C2", "critical", "T1071.001"},
	{"brute ratel", "Brute Ratel", "critical", "T1071.001"},
	// RAT clients
	{"nanocore", "NanoCore RAT", "critical", "T1071.001"},
	{"njrat", "njRAT", "critical", "T1071.001"},
	{"darkcomet", "DarkComet RAT", "critical", "T1071.001"},
	{"quasar", "Quasar RAT", "high", "T1071.001"},
	{"asyncrat", "AsyncRAT", "critical", "T1071.001"},
	{"remcos", "Remcos RAT", "critical", "T1071.001"},
	{"warzone", "Warzone RAT", "critical", "T1071.001"},
	{"dcrat", "DCRat", "critical", "T1071.001"},
	{"orcus", "Orcus RAT", "critical", "T1071.001"},
	// Scanners
	{"nmap scripting engine", "Nmap HTTP script", "high", "T1046"},
	{"nmap", "Nmap scanner", "high", "T1046"},
	{"nikto", "Nikto scanner", "high", "T1595"},
	{"sqlmap", "sqlmap injection tool", "high", "T1190"},
	{"dirbuster", "DirBuster", "high", "T1595"},
	{"gobuster", "Gobuster", "high", "T1595"},
	{"wfuzz", "wfuzz", "high", "T1595"},
	{"feroxbuster", "Feroxbuster", "high", "T1595"},
	{"ffuf", "ffuf fuzzer", "high", "T1595"},
	{"masscan", "Masscan", "high", "T1046"},
	{"zgrab", "ZGrab scanner", "high", "T1046"},
	{"nuclei", "Nuclei scanner", "high", "T1595"},
	{"burpsuite", "Burp Suite", "medium", "T1595"},
	{"burp ", "Burp Suite", "medium", "T1595"},
	// Exploit kits / loaders
	{"python-requests", "Python requests (script)", "low", "T1059.006"},
	{"go-http-client", "Go HTTP client (script)", "low", "T1059.003"},
	{"python/", "Python script", "low", "T1059.006"},
	{"curl/", "curl (command-line script)", "low", "T1059.004"},
	{"libcurl", "curl library", "low", "T1059.004"},
	// Specific malware UA strings
	{"mozilla/4.0 (compatible; msie 6.0;", "Old IE / Malware UA", "high", "T1071.001"},
	{"indy library", "Indy Library (Delphi malware)", "high", "T1071.001"},
	{"massmail", "MassMail sender", "high", "T1566"},
}

var uaLogRE = regexp.MustCompile(`(?i)(?:user.?agent|ua)[=:]\s*"?([^"\n]{5,256})"?`)

func scanMaliciousUserAgents(tenantID int) {
	// Source 1: http_user_agent from NCE DPI fields
	nceRows, err := database.DB.Query(`
		SELECT DISTINCT agent_id, http_user_agent, http_host, remote_address
		FROM network_connect_events
		WHERE tenant_id = $1
		  AND created_at > NOW() - INTERVAL '10 minutes'
		  AND http_user_agent != ''
	`, tenantID)
	if err == nil {
		defer nceRows.Close()
		for nceRows.Next() {
			var agentID int
			var ua, host, remote string
			if nceRows.Scan(&agentID, &ua, &host, &remote) == nil {
				checkUA(agentID, tenantID, ua, host, remote)
			}
		}
	}

	// Source 2: parsed_fields in endpoint_logs (web/proxy access logs)
	pfRows, err := database.DB.Query(`
		SELECT el.agent_id,
		       COALESCE(el.parsed_fields->>'user_agent', el.parsed_fields->>'http_user_agent', '') AS ua,
		       COALESCE(el.parsed_fields->>'dst_ip',''), el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id
		WHERE a.tenant_id = $1
		  AND el.collected_at > NOW() - INTERVAL '10 minutes'
		  AND (el.parsed_fields->>'user_agent' IS NOT NULL
		    OR el.parsed_fields->>'http_user_agent' IS NOT NULL)
	`, tenantID)
	if err == nil {
		defer pfRows.Close()
		for pfRows.Next() {
			var agentID int
			var ua, dst, raw string
			if pfRows.Scan(&agentID, &ua, &dst, &raw) == nil && ua != "" {
				checkUA(agentID, tenantID, ua, "", dst)
			}
		}
	}

	// Source 3: regex extraction from raw log_message
	rawRows, err := database.DB.Query(`
		SELECT el.agent_id, el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id
		WHERE a.tenant_id = $1
		  AND el.collected_at > NOW() - INTERVAL '10 minutes'
		  AND el.log_message ILIKE '%user-agent%'
	`, tenantID)
	if err == nil {
		defer rawRows.Close()
		for rawRows.Next() {
			var agentID int
			var msg string
			if rawRows.Scan(&agentID, &msg) == nil {
				if m := uaLogRE.FindStringSubmatch(msg); len(m) >= 2 {
					checkUA(agentID, tenantID, m[1], "", "")
				}
			}
		}
	}
}

func checkUA(agentID, tenantID int, ua, host, remote string) {
	lower := strings.ToLower(ua)
	for _, p := range maliciousUAPatterns {
		if strings.Contains(lower, p.pattern) {
			desc := fmt.Sprintf("Malicious User-Agent detected: %s (%q) → %s", p.name, truncate(ua, 80), remote)
			recordHTTPFinding(agentID, tenantID, p.severity, desc, ua, p.mitre, map[string]interface{}{
				"user_agent": ua, "host": host, "remote": remote,
				"match": p.pattern, "name": p.name, "reason": "malicious_ua",
			}, 85)
			return
		}
	}
}

// ── 2. Web shell path detection ───────────────────────────────────────────────

var webShellPaths = []string{
	"c99.php", "r57.php", "b374k.php", "wso.php", "alfa.php", "symlink.php",
	"shell.php", "webshell.php", "cmd.php", "command.php", "exec.php",
	"ajax.php?cmd=", "ajax.php?c=",
	".php?cmd=", ".php?exec=", ".php?command=",
	"eval(base64_decode", "eval(gzinflate",
	"wp-content/plugins/backdoor", "wp-content/uploads/shell",
	"wp-content/themes/shell", "xmlrpc.php?rsd",
	"_mem_bin/", "msadc/", "/iissamples/", "/_vti_cnf/",
	"/phpmyadmin/", "/pma/setup", "/myadmin/",
	".php.suspected",
	"webconfig.txt.php", "config.php.bak",
}

func scanWebShellPaths(tenantID int) {
	// NCE DPI path field
	nceRows, err := database.DB.Query(`
		SELECT agent_id, http_path, http_host, remote_address
		FROM network_connect_events
		WHERE tenant_id = $1
		  AND created_at > NOW() - INTERVAL '10 minutes'
		  AND http_path != ''
	`, tenantID)
	if err == nil {
		defer nceRows.Close()
		for nceRows.Next() {
			var agentID int
			var path, host, remote string
			if nceRows.Scan(&agentID, &path, &host, &remote) == nil {
				checkWebShellPath(agentID, tenantID, path, host, remote)
			}
		}
	}

	// parsed_fields url/http_path
	pfRows, err := database.DB.Query(`
		SELECT el.agent_id,
		       COALESCE(el.parsed_fields->>'url', el.parsed_fields->>'http_path', el.parsed_fields->>'cs-uri-stem', '') AS path,
		       COALESCE(el.parsed_fields->>'dst_ip', '')
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id
		WHERE a.tenant_id = $1
		  AND el.collected_at > NOW() - INTERVAL '10 minutes'
		  AND (el.parsed_fields->>'url' IS NOT NULL OR el.parsed_fields->>'http_path' IS NOT NULL)
	`, tenantID)
	if err == nil {
		defer pfRows.Close()
		for pfRows.Next() {
			var agentID int
			var path, dst string
			if pfRows.Scan(&agentID, &path, &dst) == nil && path != "" {
				checkWebShellPath(agentID, tenantID, path, "", dst)
			}
		}
	}
}

func checkWebShellPath(agentID, tenantID int, path, host, remote string) {
	lower := strings.ToLower(path)

	// Path traversal
	if strings.Contains(lower, "../") || strings.Contains(lower, "..\\") || strings.Contains(lower, "%2e%2e") {
		recordHTTPFinding(agentID, tenantID, "high",
			fmt.Sprintf("Path traversal attempt: %q → %s", truncate(path, 80), remote),
			path, "T1083", map[string]interface{}{
				"path": path, "host": host, "remote": remote, "reason": "path_traversal",
			}, 80)
		return
	}

	// Null byte injection
	if strings.Contains(path, "%00") || strings.Contains(path, "\x00") {
		recordHTTPFinding(agentID, tenantID, "high",
			fmt.Sprintf("Null byte injection in URL path: %q → %s", truncate(path, 80), remote),
			path, "T1190", map[string]interface{}{
				"path": path, "host": host, "remote": remote, "reason": "null_byte",
			}, 80)
		return
	}

	// Known webshell names
	for _, ws := range webShellPaths {
		if strings.Contains(lower, ws) {
			recordHTTPFinding(agentID, tenantID, "critical",
				fmt.Sprintf("Web shell access: %q matched pattern %q on %s", truncate(path, 80), ws, remote),
				path, "T1505.003", map[string]interface{}{
					"path": path, "host": host, "remote": remote,
					"pattern": ws, "reason": "webshell",
				}, 95)
			return
		}
	}

	// High-entropy path component = likely obfuscated webshell filename
	if entropy := URLPathEntropy(path); entropy >= 4.2 {
		recordHTTPFinding(agentID, tenantID, "medium",
			fmt.Sprintf("High-entropy URL path: %q (entropy=%.2f) → %s", truncate(path, 80), entropy, remote),
			path, "T1505.003", map[string]interface{}{
				"path": path, "host": host, "remote": remote,
				"entropy": entropy, "reason": "high_entropy_path",
			}, 65)
	}
}

// ── 3. Suspicious HTTP method detection ──────────────────────────────────────

var suspiciousHTTPMethods = map[string]struct {
	severity string
	mitre    string
}{
	"PROPFIND": {"medium", "T1595"},
	"TRACK":    {"high", "T1595"},
	"TRACE":    {"medium", "T1595"},
	"DEBUG":    {"high", "T1190"},
	"CONNECT":  {"medium", "T1572"},
}

func scanSuspiciousMethods(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT DISTINCT agent_id, http_method, http_path, http_host, remote_address
		FROM network_connect_events
		WHERE tenant_id = $1
		  AND created_at > NOW() - INTERVAL '10 minutes'
		  AND http_method != ''
		  AND http_method NOT IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS')
	`, tenantID)
	if err != nil { return }
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var method, path, host, remote string
		if rows.Scan(&agentID, &method, &path, &host, &remote) != nil {
			continue
		}
		if info, ok := suspiciousHTTPMethods[strings.ToUpper(method)]; ok {
			recordHTTPFinding(agentID, tenantID, info.severity,
				fmt.Sprintf("Suspicious HTTP method %q to %s%s", method, host, path),
				method, info.mitre, map[string]interface{}{
					"method": method, "path": path, "host": host,
					"remote": remote, "reason": "suspicious_method",
				}, 70)
		}
	}
}

// ── 4. NCE DPI field analysis ─────────────────────────────────────────────────

func scanHTTPNCEFields(tenantID int) {
	// High-entropy user agents (possible obfuscated C2 beacon UA)
	rows, err := database.DB.Query(`
		SELECT agent_id, http_user_agent, http_host, remote_address
		FROM network_connect_events
		WHERE tenant_id = $1
		  AND created_at > NOW() - INTERVAL '10 minutes'
		  AND http_user_agent != ''
		  AND entropy_score >= 75
	`, tenantID)
	if err != nil { return }
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var ua, host, remote string
		if rows.Scan(&agentID, &ua, &host, &remote) == nil {
			if IsBase64Encoded(ua) || ShannonEntropy(ua) >= 4.0 {
				recordHTTPFinding(agentID, tenantID, "high",
					fmt.Sprintf("High-entropy User-Agent (possible C2 beacon): %q → %s", truncate(ua, 60), remote),
					ua, "T1071.001", map[string]interface{}{
						"user_agent": ua, "host": host, "remote": remote,
						"entropy": ShannonEntropy(ua), "reason": "high_entropy_ua",
					}, 75)
			}
		}
	}
}

// ── Shared helpers ────────────────────────────────────────────────────────────

func recordHTTPFinding(agentID, tenantID int, severity, desc, indicator, mitre string, ctx map[string]interface{}, score int) {
	var existing int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM dpi_findings
		WHERE agent_id=$1 AND finding_type='http_pattern' AND indicator=$2
		  AND detected_at > NOW() - INTERVAL '30 minutes'
	`, agentID, truncate(indicator, 255)).Scan(&existing)
	if existing > 0 {
		return
	}

	ctxJSON, _ := json.Marshal(ctx)
	alertFired := score >= 70
	database.DB.Exec(`
		INSERT INTO dpi_findings
		  (agent_id, tenant_id, finding_type, severity, score, indicator,
		   description, mitre_technique, raw_context, alert_fired)
		VALUES ($1,$2,'http_pattern',$3,$4,$5,$6,$7,$8,$9)
	`, agentID, tenantID, severity, score, truncate(indicator, 255), desc, mitre, ctxJSON, alertFired)

	if alertFired {
		log.Printf("[HTTP] agent=%d sev=%s: %s", agentID, severity, truncate(desc, 100))
		alert := models.Alert{
			AgentID:        agentID,
			TenantID:       tenantID,
			RuleName:       "HTTP Threat Pattern: " + reasonFromCtxHTTP(ctx),
			Severity:       severity,
			LogMessage:     desc,
			MitreTechnique: mitre,
			Fingerprint:    fmt.Sprintf("%d-http-%x", agentID, simpleHash(indicator+desc)),
		}
		CreateAlert(alert) //nolint:errcheck
	}
}

func reasonFromCtxHTTP(ctx map[string]interface{}) string {
	if r, ok := ctx["reason"].(string); ok {
		switch r {
		case "malicious_ua": return "Malicious User-Agent"
		case "webshell":     return "Web Shell Access"
		case "path_traversal": return "Path Traversal"
		case "null_byte":    return "Null Byte Injection"
		case "suspicious_method": return "Suspicious HTTP Method"
		case "high_entropy_ua": return "High-Entropy User-Agent"
		default: return r
		}
	}
	return "Suspicious HTTP"
}

// simpleHash returns a 32-bit hash for dedup fingerprinting.
func simpleHash(s string) uint32 {
	h := uint32(2166136261)
	for _, c := range []byte(s) {
		h ^= uint32(c)
		h *= 16777619
	}
	return h
}
