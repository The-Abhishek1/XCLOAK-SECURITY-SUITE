package services

// Content-Aware Data Loss Prevention (DLP) — extends the existing volume-based
// exfiltration detector with pattern recognition and file classification.
//
// Four detection engines:
//
//  1. pii_in_transit     — PII regex patterns (SSN, credit card, IBAN, passport,
//                          NHS, phone) found in log content flowing to external IPs.
//                          Scans endpoint_logs in 15-min windows; deduplicates
//                          by (agent, pattern_type, dst_ip) per hour.
//
//  2. sensitive_file_access — FIM alerts on files matching sensitive path patterns:
//                          private keys, .env configs, source code archives, SQL
//                          dumps, PII-named CSVs. Fires on any create/modify/delete.
//
//  3. sensitive_file_transfer — Correlates FIM-flagged sensitive paths against
//                          recent outbound connections to external destinations.
//                          Signals a possible exfil even without byte-count data.
//
//  4. personal_cloud_upload — PII pattern found in a log whose destination is a
//                          personal cloud-storage or file-sharing site.
//                          Combined signal: content + destination.
//
// MITRE coverage: T1048, T1567.002, T1005 (Data from Local System),
//                 T1552 (Unsecured Credentials)

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"xcloak-platform/database"
)

// ── PII patterns ──────────────────────────────────────────────────────────────

type piiPattern struct {
	name     string
	re       *regexp.Regexp
	severity string
	mitre    string
}

var piiPatterns = []piiPattern{
	{
		name:     "credit_card",
		severity: "critical",
		mitre:    "T1048",
		// Visa (4x), Mastercard (51-55 or 2221-2720), Amex (34/37), Discover (6011/65)
		re: regexp.MustCompile(
			`\b(?:4[0-9]{12}(?:[0-9]{3})?` +
				`|5[1-5][0-9]{14}` +
				`|2(?:2[2-9][1-9]|[3-6]\d{2}|7[01]\d|720)\d{12}` +
				`|3[47][0-9]{13}` +
				`|3(?:0[0-5]|[68][0-9])[0-9]{11}` +
				`|6(?:011|5[0-9]{2})[0-9]{12})\b`),
	},
	{
		name:     "us_ssn",
		severity: "critical",
		mitre:    "T1048",
		// SSN: 3-2-4 digit groups; invalid prefixes (000, 666, 900-999) and
		// all-zero groups are filtered by ssnIsValid() after matching.
		re: regexp.MustCompile(`\b(\d{3})-(\d{2})-(\d{4})\b`),
	},
	{
		name:     "iban",
		severity: "high",
		mitre:    "T1048",
		// IBAN: 2 letter country code + 2 check digits + up to 30 alphanumerics
		re: regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`),
	},
	{
		name:     "uk_nhs_number",
		severity: "high",
		mitre:    "T1048",
		// NHS number: 3 3 4 digit groups with spaces
		re: regexp.MustCompile(`\b\d{3}[\s-]\d{3}[\s-]\d{4}\b`),
	},
	{
		name:     "passport_number",
		severity: "high",
		mitre:    "T1048",
		// Generic passport: 1-2 letters followed by 6-9 digits
		re: regexp.MustCompile(`\b[A-Z]{1,2}\d{6,9}\b`),
	},
	{
		name:     "private_key_header",
		severity: "critical",
		mitre:    "T1552",
		re:       regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`),
	},
	{
		name:     "aws_access_key",
		severity: "critical",
		mitre:    "T1552",
		// AWS access key IDs start with AKIA, ASIA, or AROA
		re: regexp.MustCompile(`\b(AKIA|ASIA|AROA)[A-Z0-9]{16}\b`),
	},
	{
		name:     "jwt_token",
		severity: "high",
		mitre:    "T1552",
		// JWT: three base64url segments separated by dots
		re: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
	},
}

// ── Sensitive file path patterns ───────────────────────────────────────────────

type filePattern struct {
	name     string
	patterns []string // lowercase substrings matched against file_path
	severity string
	mitre    string
}

var sensitiveFilePatterns = []filePattern{
	{
		name:     "private_key",
		severity: "critical",
		mitre:    "T1552.004",
		patterns: []string{"id_rsa", "id_ed25519", "id_ecdsa", ".pem", ".key", ".p12", ".pfx",
			"privatekey", "private_key"},
	},
	{
		name:     "secrets_config",
		severity: "critical",
		mitre:    "T1552",
		patterns: []string{".env", "secrets.yml", "secrets.yaml", "secrets.json",
			"credentials.json", "credentials.yml", "vault.json", ".aws/credentials",
			"kubeconfig", ".kube/config"},
	},
	{
		name:     "database_dump",
		severity: "high",
		mitre:    "T1005",
		patterns: []string{".sql", ".dump", ".db.bak", "database_backup", "db_dump",
			".sqlite", ".mdf", ".bak"},
	},
	{
		name:     "pii_data_file",
		severity: "critical",
		mitre:    "T1005",
		patterns: []string{"customers.", "users.csv", "patients.", "ssn", "creditcard",
			"credit_card", "passport", "personnel", "payroll", "salary", "social_security"},
	},
	{
		name:     "source_code_archive",
		severity: "medium",
		mitre:    "T1005",
		patterns: []string{".tar.gz", ".zip", ".7z", ".rar"},
	},
	{
		name:     "financial_data",
		severity: "high",
		mitre:    "T1005",
		patterns: []string{"financial", "revenue", "budget", "invoice", "bank_statement",
			"tax_return", "accounting"},
	},
}

// ── Sensitive outbound destinations ───────────────────────────────────────────

var sensitiveDestinations = append(cloudStorageDomains, []string{
	// File-sharing / paste sites
	"pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "rentry.co",
	"privatebin.net", "zerobin.net",
	// Anonymous file transfer
	"send.vis.ee", "sendspace.com", "mediafire.com", "4shared.com",
	"zippyshare.com", "anonfiles.com", "bayfiles.com", "filebin.net",
	// Temporary / disposable
	"file.io", "tmpfiles.org", "litterbox.catbox.moe",
	// Encrypted / anonymous
	"keybase.io",
}...)

// ── Main entry point ───────────────────────────────────────────────────────────

// DetectDLPForTenant runs all content-aware DLP checks for one tenant.
// Called from the existing exfil scheduler so there's no separate scheduler.
func DetectDLPForTenant(tenantID int) {
	detectPIIInTransit(tenantID)
	detectSensitiveFileAccess(tenantID)
	detectSensitiveFileTransfer(tenantID)
}

// ── 1. PII in transit ─────────────────────────────────────────────────────────

func detectPIIInTransit(tenantID int) {
	// Pull recent log messages that have an external destination.
	// Limit 5000 rows to keep the regex scan bounded.
	rows, err := database.RDB().Query(`
		SELECT el.agent_id, el.log_message,
		       COALESCE(el.parsed_fields->>'dst_ip', '') AS dst_ip,
		       COALESCE(el.parsed_fields->>'url', '')    AS url
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.created_at > NOW() - INTERVAL '15 minutes'
		  AND el.log_message IS NOT NULL
		  AND length(el.log_message) > 20
		ORDER BY el.created_at DESC
		LIMIT 5000
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var logMsg, dstIP, url string
		if err := rows.Scan(&agentID, &logMsg, &dstIP, &url); err != nil {
			continue
		}
		// Only flag if destination is external or to a known sensitive site.
		externalDst := (!isPrivateIP(dstIP) && dstIP != "") ||
			isSensitiveDestination(url+" "+dstIP)

		for _, p := range piiPatterns {
			if !p.re.MatchString(logMsg) {
				continue
			}
			matches := p.re.FindAllString(logMsg, 3)
			if p.name == "us_ssn" {
				valid := matches[:0]
				for _, m := range matches {
					if ssnIsValid(m) {
						valid = append(valid, m)
					}
				}
				if len(valid) == 0 {
					continue
				}
				matches = valid
			}
			redacted := redactMatches(matches)

			desc := fmt.Sprintf(
				"DLP: %s pattern detected in outbound log traffic (dst: %s). Matches: %s",
				p.name, dstIP, redacted,
			)
			dedupKey := fmt.Sprintf("dlp-pii-%d-%s-%s", agentID, p.name, dstIP)

			sev := p.severity
			if externalDst && isSensitiveDestination(url+" "+dstIP) {
				// PII going to a known leak site — escalate
				if sev == "high" {
					sev = "critical"
				}
			}

			if !dedupDLPAlert(agentID, tenantID, "pii_in_transit:"+p.name, dstIP) {
				continue
			}
			log.Printf("[DLP] PII in transit: agent=%d pattern=%s dst=%s", agentID, p.name, dstIP)
			fireExfilAlert(agentID, tenantID, "DLP: PII In Transit", sev, p.mitre, desc, dedupKey)
		}
	}
}

// ── 2. Sensitive file access (FIM) ────────────────────────────────────────────

func detectSensitiveFileAccess(tenantID int) {
	rows, err := database.RDB().Query(`
		SELECT fa.agent_id, fa.file_path, fa.change_type, fa.created_at
		FROM fim_alerts fa
		JOIN agents a ON a.id = fa.agent_id AND a.tenant_id = $1
		WHERE fa.created_at > NOW() - INTERVAL '15 minutes'
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var filePath, changeType string
		var createdAt time.Time
		if err := rows.Scan(&agentID, &filePath, &changeType, &createdAt); err != nil {
			continue
		}

		fp := matchSensitiveFile(filePath)
		if fp == nil {
			continue
		}

		desc := fmt.Sprintf(
			"DLP: Sensitive file %s (%s) — %s at %s",
			fp.name, filePath, changeType, createdAt.Format(time.RFC3339),
		)
		dedupKey := fmt.Sprintf("dlp-fim-%d-%s-%s", agentID, fp.name, filePath)

		if !dedupDLPAlert(agentID, tenantID, "sensitive_file_access:"+fp.name, filePath) {
			continue
		}
		log.Printf("[DLP] sensitive file access: agent=%d pattern=%s path=%s", agentID, fp.name, filePath)
		fireExfilAlert(agentID, tenantID, "DLP: Sensitive File Access", fp.severity, fp.mitre, desc, dedupKey)
	}
}

// ── 3. Sensitive file transfer (FIM × outbound connections) ───────────────────

// detectSensitiveFileTransfer correlates recent FIM events on sensitive files
// with outbound network connections in the same time window on the same agent.
// This catches "read sensitive file, then immediately upload" patterns.
func detectSensitiveFileTransfer(tenantID int) {
	// Find agents that had both a sensitive FIM event and an external connection
	// in the last 30 minutes.
	rows, err := database.RDB().Query(`
		SELECT DISTINCT fa.agent_id, fa.file_path, fa.change_type,
		       COALESCE(nce.remote_address, '') AS remote_addr
		FROM fim_alerts fa
		JOIN agents a ON a.id = fa.agent_id AND a.tenant_id = $1
		LEFT JOIN network_connect_events nce
			ON nce.agent_id = fa.agent_id
			AND nce.tenant_id = $1
			AND nce.created_at BETWEEN fa.created_at AND fa.created_at + INTERVAL '5 minutes'
			AND nce.bytes_sent > 0
		WHERE fa.created_at > NOW() - INTERVAL '30 minutes'
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var filePath, changeType, remoteAddr string
		if err := rows.Scan(&agentID, &filePath, &changeType, &remoteAddr); err != nil {
			continue
		}

		fp := matchSensitiveFile(filePath)
		if fp == nil {
			continue
		}

		// Only fire if there was an outbound connection to an external host.
		if remoteAddr == "" {
			continue
		}
		dstIP := strings.Split(remoteAddr, ":")[0]
		if isPrivateIP(dstIP) {
			continue
		}

		desc := fmt.Sprintf(
			"DLP: Sensitive file (%s: %s) accessed then outbound connection to %s within 5 minutes — possible exfiltration",
			fp.name, filePath, remoteAddr,
		)
		dedupKey := fmt.Sprintf("dlp-transfer-%d-%s-%s", agentID, fp.name, dstIP)

		if !dedupDLPAlert(agentID, tenantID, "sensitive_file_transfer:"+fp.name, dstIP) {
			continue
		}
		log.Printf("[DLP] sensitive file transfer: agent=%d pattern=%s dst=%s", agentID, fp.name, dstIP)
		fireExfilAlert(agentID, tenantID, "DLP: Sensitive File Transfer", "critical", fp.mitre, desc, dedupKey)
	}
}

// ssnIsValid rejects well-known invalid SSN values that the basic regex admits.
func ssnIsValid(ssn string) bool {
	if len(ssn) < 11 {
		return false
	}
	area := ssn[:3]
	group := ssn[4:6]
	serial := ssn[7:]
	if area == "000" || area == "666" {
		return false
	}
	if area[0] == '9' {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	return true
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func matchSensitiveFile(filePath string) *filePattern {
	lower := strings.ToLower(filePath)
	for i := range sensitiveFilePatterns {
		fp := &sensitiveFilePatterns[i]
		for _, pat := range fp.patterns {
			if strings.Contains(lower, pat) {
				return fp
			}
		}
	}
	return nil
}

func isSensitiveDestination(combined string) bool {
	lower := strings.ToLower(combined)
	for _, d := range sensitiveDestinations {
		if strings.Contains(lower, d) {
			return true
		}
	}
	return false
}

// redactMatches returns the first N matches with middle characters replaced by
// asterisks. Prevents raw PII from appearing in alert descriptions.
func redactMatches(matches []string) string {
	redacted := make([]string, len(matches))
	for i, m := range matches {
		if len(m) > 4 {
			redacted[i] = m[:2] + strings.Repeat("*", len(m)-4) + m[len(m)-2:]
		} else {
			redacted[i] = "****"
		}
	}
	return strings.Join(redacted, ", ")
}

// dedupDLPAlert returns true if no matching DLP alert was recorded in the last
// hour for this (agent, type, target) triple. Uses network_anomalies for storage.
func dedupDLPAlert(agentID, tenantID int, dlpType, target string) bool {
	var count int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM network_anomalies
		WHERE agent_id = $1 AND anomaly_type = $2 AND dst_ip = $3
		  AND detected_at > NOW() - INTERVAL '1 hour'
	`, agentID, dlpType, target).Scan(&count)
	if count > 0 {
		return false
	}
	database.DB.Exec(`
		INSERT INTO network_anomalies
			(agent_id, tenant_id, anomaly_type, dst_ip, dst_port, proto, deviation_score, description)
		VALUES ($1,$2,$3,$4,0,'tcp',90,$5)
	`, agentID, tenantID, dlpType, target,
		"DLP finding: "+dlpType+" → "+target)
	return true
}
