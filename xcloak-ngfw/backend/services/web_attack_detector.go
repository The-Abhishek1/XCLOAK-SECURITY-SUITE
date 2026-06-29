package services

// Web Application Attack Detector
//
// Detects application-layer attacks from HTTP access logs (Apache, Nginx,
// Caddy, HAProxy, load balancers) ingested via syslog or the HTTP ingest API.
// The log normalizer now parses HTTP access log format and populates
// parsed_fields with http_method, url_path, user_agent, http_status, src_ip.
//
// Detection categories:
//
//  1. SQL Injection (T1190)         — UNION SELECT, ' OR 1=1, comment injection, hex 0x
//  2. Cross-Site Scripting (T1059.007) — <script>, javascript:, onerror=, eval(
//  3. Path Traversal / LFI (T1083)  — ../, /etc/passwd, /windows/system32
//  4. Command Injection (T1059)     — ; id, | whoami, && wget, $()
//  5. Web Scanner / Recon (T1595)   — sqlmap, nikto, masscan, nessus, nmap UA strings
//  6. 4xx/5xx flood (T1499.002)     — DoS probing, error-rate spike per src_ip
//
// Runs every 5 minutes. Alert dedup TTL: 15 minutes per (agent, category, src_ip).

import (
	"fmt"
	"log"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

const webDedupTTL = 15 * time.Minute

var webDedup = newTTLMap(webDedupTTL)

// ── Attack signature tables ───────────────────────────────────────────────────

type webSig struct {
	fragment string
	ruleName string
	severity string
	mitre    string
	mitreNm  string
}

var sqliSigs = []webSig{
	{"union select",   "SQL Injection — UNION SELECT",    "critical", "T1190", "Exploit Public-Facing Application"},
	{"union all select","SQL Injection — UNION ALL SELECT","critical", "T1190", "Exploit Public-Facing Application"},
	{"' or '1'='1",   "SQL Injection — OR tautology",    "critical", "T1190", "Exploit Public-Facing Application"},
	{"or 1=1",        "SQL Injection — OR 1=1",           "high",     "T1190", "Exploit Public-Facing Application"},
	{"'; drop table", "SQL Injection — DROP TABLE",       "critical", "T1190", "Exploit Public-Facing Application"},
	{"insert into",   "SQL Injection — INSERT",           "high",     "T1190", "Exploit Public-Facing Application"},
	{"xp_cmdshell",   "SQL Injection — xp_cmdshell RCE", "critical", "T1190", "Exploit Public-Facing Application"},
	{"information_schema.tables", "SQL Injection — Schema Enum", "high", "T1190", "Exploit Public-Facing Application"},
	{"sleep(", "SQL Injection — Blind time-based",       "high",     "T1190", "Exploit Public-Facing Application"},
	{"benchmark(",    "SQL Injection — Blind benchmark",  "high",     "T1190", "Exploit Public-Facing Application"},
	{"0x3c736372",    "SQL Injection — Hex encoded",      "high",     "T1190", "Exploit Public-Facing Application"},
}

var xssSigs = []webSig{
	{"<script",       "XSS — Script tag injection",       "high",     "T1059.007", "JavaScript"},
	{"javascript:",   "XSS — javascript: URI",            "high",     "T1059.007", "JavaScript"},
	{"onerror=",      "XSS — onerror handler",            "high",     "T1059.007", "JavaScript"},
	{"onload=",       "XSS — onload handler",             "high",     "T1059.007", "JavaScript"},
	{"eval(",         "XSS — eval() injection",           "high",     "T1059.007", "JavaScript"},
	{"document.cookie","XSS — cookie theft attempt",      "high",     "T1059.007", "JavaScript"},
	{"alert(",        "XSS — alert() probe",              "medium",   "T1059.007", "JavaScript"},
	{"<img src=x",    "XSS — img onerror probe",          "high",     "T1059.007", "JavaScript"},
	{"</script>",     "XSS — Script close tag",           "medium",   "T1059.007", "JavaScript"},
}

var traversalSigs = []webSig{
	{"../",           "Path Traversal",                   "high",     "T1083", "File and Directory Discovery"},
	{"..%2f",         "Path Traversal — URL encoded",     "high",     "T1083", "File and Directory Discovery"},
	{"..%5c",         "Path Traversal — backslash",       "high",     "T1083", "File and Directory Discovery"},
	{"/etc/passwd",   "LFI — /etc/passwd",                "critical", "T1083", "File and Directory Discovery"},
	{"/etc/shadow",   "LFI — /etc/shadow",                "critical", "T1083", "File and Directory Discovery"},
	{"\\windows\\system32","LFI — Windows system32",      "critical", "T1083", "File and Directory Discovery"},
	{"c:\\windows",   "LFI — Windows drive traversal",    "critical", "T1083", "File and Directory Discovery"},
	{"php://",        "RFI — php:// wrapper",             "critical", "T1190", "Exploit Public-Facing Application"},
	{"data://",       "RFI — data:// wrapper",            "critical", "T1190", "Exploit Public-Facing Application"},
	{"expect://",     "RFI — expect:// RCE wrapper",      "critical", "T1190", "Exploit Public-Facing Application"},
}

var cmdInjSigs = []webSig{
	{"; ls ",         "Command Injection — ls",           "critical", "T1059", "Command and Scripting Interpreter"},
	{"| whoami",      "Command Injection — whoami",       "critical", "T1059", "Command and Scripting Interpreter"},
	{"| id",          "Command Injection — id",           "critical", "T1059", "Command and Scripting Interpreter"},
	{"&& wget",       "Command Injection — wget",         "critical", "T1059", "Command and Scripting Interpreter"},
	{"&& curl",       "Command Injection — curl",         "critical", "T1059", "Command and Scripting Interpreter"},
	{"$(", "Command Injection — subshell $(",             "critical", "T1059", "Command and Scripting Interpreter"},
	{"`",             "Command Injection — backtick",     "high",     "T1059", "Command and Scripting Interpreter"},
	{"/bin/bash",     "Command Injection — bash path",    "critical", "T1059.004", "Unix Shell"},
	{"/bin/sh",       "Command Injection — sh path",      "critical", "T1059.004", "Unix Shell"},
}

// Scanners identified by User-Agent substring
var scannerUAs = []webSig{
	{"sqlmap",        "Web Scanner — sqlmap",             "high",     "T1595.002", "Vulnerability Scanning"},
	{"nikto",         "Web Scanner — Nikto",              "high",     "T1595.002", "Vulnerability Scanning"},
	{"nessus",        "Web Scanner — Nessus",             "medium",   "T1595.002", "Vulnerability Scanning"},
	{"openvas",       "Web Scanner — OpenVAS",            "medium",   "T1595.002", "Vulnerability Scanning"},
	{"masscan",       "Web Scanner — Masscan",            "high",     "T1595.001", "Scanning IP Blocks"},
	{"nmap",          "Web Scanner — Nmap",               "high",     "T1595.001", "Scanning IP Blocks"},
	{"acunetix",      "Web Scanner — Acunetix",           "high",     "T1595.002", "Vulnerability Scanning"},
	{"zgrab",         "Web Scanner — zgrab",              "high",     "T1595.001", "Scanning IP Blocks"},
	{"python-requests","Automated HTTP Client (Python)",  "low",      "T1595",     "Active Scanning"},
	{"gobuster",      "Directory Brute-force — gobuster", "high",     "T1595.002", "Vulnerability Scanning"},
	{"dirbuster",     "Directory Brute-force — dirbuster","high",     "T1595.002", "Vulnerability Scanning"},
	{"wfuzz",         "Directory Brute-force — wfuzz",    "high",     "T1595.002", "Vulnerability Scanning"},
	{"hydra",         "Credential Brute-force — Hydra",   "critical", "T1110",     "Brute Force"},
}

const errorFloodThreshold = 50 // 4xx/5xx errors from one IP in 5 min = DoS probe

func StartWebAttackScheduler() {
	go func() {
		time.Sleep(3 * time.Minute)
		for {
			runWebAttackDetection()
			time.Sleep(5 * time.Minute)
		}
	}()
}

func runWebAttackDetection() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = true`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var tid int
		if rows.Scan(&tid) == nil {
			detectWebAttacks(tid)
			detectWebScannerUA(tid)
			detectErrorFlood(tid)
		}
	}
}

// ── URL-based attack signature matching ──────────────────────────────────────

func detectWebAttacks(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'src_ip'     AS src_ip,
		       el.parsed_fields->>'url_path'   AS url,
		       el.parsed_fields->>'http_method' AS method,
		       el.parsed_fields->>'http_status' AS status,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'url_path' IS NOT NULL
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		LIMIT 5000
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	allSigs := [][]webSig{sqliSigs, xssSigs, traversalSigs, cmdInjSigs}
	categories := []string{"sqli", "xss", "traversal", "cmdinj"}

	for rows.Next() {
		var agentID int
		var srcIP, urlPath, method, status, logMsg string
		if rows.Scan(&agentID, &srcIP, &urlPath, &method, &status, &logMsg) != nil {
			continue
		}
		lowerURL := strings.ToLower(urlPath)

		for ci, sigs := range allSigs {
			for _, sig := range sigs {
				if !strings.Contains(lowerURL, sig.fragment) {
					continue
				}
				key := fmt.Sprintf("%d:web-%s:%s:%s", tenantID, categories[ci], srcIP, sig.fragment[:8])
				if webDedup.touched(key) {
					break
				}
				webDedup.touch(key)
				msg := fmt.Sprintf("%s from %s: %s %s (status: %s)",
					sig.ruleName, srcIP, method, truncateLog(urlPath, 300), status)
				log.Printf("[WebAttack] %s", msg)
				CreateAlert(models.Alert{
					AgentID:        agentID,
					TenantID:       tenantID,
					Severity:       sig.severity,
					RuleName:       sig.ruleName,
					LogMessage:     msg,
					MitreTactic:    "Initial Access",
					MitreTechnique: sig.mitre,
					MitreName:      sig.mitreNm,
					Fingerprint:    fmt.Sprintf("web-%s-%s-%s", categories[ci], srcIP, agentID),
				})
				break
			}
		}
	}
}

// ── Scanner User-Agent detection ─────────────────────────────────────────────

func detectWebScannerUA(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'src_ip'    AS src_ip,
		       lower(el.parsed_fields->>'user_agent') AS ua
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'user_agent' IS NOT NULL
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		LIMIT 5000
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var srcIP, ua string
		if rows.Scan(&agentID, &srcIP, &ua) != nil {
			continue
		}
		for _, sig := range scannerUAs {
			if !strings.Contains(ua, sig.fragment) {
				continue
			}
			key := fmt.Sprintf("%d:web-scanner:%s:%s", tenantID, srcIP, sig.fragment)
			if webDedup.touched(key) {
				break
			}
			webDedup.touch(key)
			msg := fmt.Sprintf("%s detected from %s (User-Agent: %s)", sig.ruleName, srcIP, truncateLog(ua, 200))
			log.Printf("[WebAttack] %s", msg)
			CreateAlert(models.Alert{
				AgentID:        agentID,
				TenantID:       tenantID,
				Severity:       sig.severity,
				RuleName:       sig.ruleName,
				LogMessage:     msg,
				MitreTactic:    "Reconnaissance",
				MitreTechnique: sig.mitre,
				MitreName:      sig.mitreNm,
				Fingerprint:    fmt.Sprintf("web-scanner-%s-%s", srcIP, sig.fragment),
			})
			break
		}
	}
}

// ── 4xx/5xx error flood — DoS probe or scanner ───────────────────────────────

func detectErrorFlood(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'src_ip' AS src_ip,
		       COUNT(*) AS error_count
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'http_status' IS NOT NULL
		  AND (el.parsed_fields->>'http_status' LIKE '4%'
		    OR el.parsed_fields->>'http_status' LIKE '5%')
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		GROUP BY el.agent_id, src_ip
		HAVING COUNT(*) >= $2
	`, tenantID, errorFloodThreshold)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID, errorCount int
		var srcIP string
		if rows.Scan(&agentID, &srcIP, &errorCount) != nil {
			continue
		}
		key := fmt.Sprintf("%d:web-errflood:%s", tenantID, srcIP)
		if webDedup.touched(key) {
			continue
		}
		webDedup.touch(key)
		msg := fmt.Sprintf("HTTP error flood from %s: %d 4xx/5xx responses in 5 minutes (DoS probe or scanner)", srcIP, errorCount)
		log.Printf("[WebAttack] %s", msg)
		CreateAlert(models.Alert{
			AgentID:        agentID,
			TenantID:       tenantID,
			Severity:       "medium",
			RuleName:       "HTTP Error Flood — DoS Probe",
			LogMessage:     msg,
			MitreTactic:    "Reconnaissance",
			MitreTechnique: "T1595.002",
			MitreName:      "Vulnerability Scanning",
			Fingerprint:    fmt.Sprintf("web-errflood-%s", srcIP),
		})
	}
}
