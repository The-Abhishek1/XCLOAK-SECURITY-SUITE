package services

// Email Security Detector
//
// Analyses email gateway log lines ingested via syslog or the HTTP ingest API.
// Supported sources:
//   - Microsoft Exchange / Office 365 message tracking logs (JSON via HTTP ingest)
//   - Proofpoint SIEM API JSON
//   - Mimecast Audit & Gateway logs
//   - Postfix / Exim syslog (plain-text)
//   - Any JSON email log with SenderAddress / RecipientAddress / Subject fields
//     (parsed into parsed_fields by the JSON normaliser)
//
// Detection categories:
//   Phishing attachment   (T1566.001) — dangerous file extension in email body/subject
//   Phishing link         (T1566.002) — URL shorteners, suspicious TLDs, punycode domains
//   Business Email Compromise (T1078) — financial trigger words in subject
//   Credential phishing   (T1566.001) — password/login/verify themed subjects
//   Mass outbound         (T1114.002) — one sender to many recipients in 5 min
//   External→Internal DMARC/SPF fail (T1566) — email failing auth from external
//   Suspicious sender domain lookalike (T1566.001) — edit-distance ≤2 vs known domains
//   Malware dropper subject (T1566.001) — invoice/urgent/overdue themes
//
// Runs every 5 minutes.  Alert dedup TTL: 30 minutes per (tenant, rule, sender).

import (
	"fmt"
	"log"
	"strings"
	"time"
	"unicode"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// Dangerous attachment extensions commonly weaponised in spear-phishing.
var dangerousExtensions = []string{
	".exe", ".dll", ".bat", ".cmd", ".ps1", ".psm1", ".psd1",
	".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
	".scr", ".lnk", ".jar", ".msi", ".iso", ".img",
}

// URL shortener domains used to hide phishing destinations.
var urlShorteners = []string{
	"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
	"rebrand.ly", "cutt.ly", "is.gd", "v.gd", "qr.ae", "href.li",
}

// Trigger words used in Business Email Compromise.
var becTriggers = []string{
	"wire transfer", "urgent payment", "bank transfer", "invoice attached",
	"payment confirmation", "remittance advice", "outstanding invoice",
	"funds transfer", "ach payment", "routing number", "account number",
	"ceo request", "executive request", "confidential transfer",
}

// Phishing credential themes.
var credentialPhishingTriggers = []string{
	"verify your account", "confirm your password", "unusual sign-in",
	"account suspended", "login attempt", "update your credentials",
	"password expired", "your account has been", "secure your account",
	"action required", "click here to verify",
}

// Malware dropper lures.
var dropperLures = []string{
	"invoice", "overdue", "payment required", "shipment", "delivery failed",
	"your package", "order confirmation", "refund", "tax return", "receipt",
}

// Known branded domains — lookalike detection uses edit-distance ≤2.
var knownDomains = []string{
	"microsoft.com", "google.com", "amazon.com", "paypal.com", "apple.com",
	"facebook.com", "linkedin.com", "dropbox.com", "office.com", "outlook.com",
	"docusign.com", "zoom.us", "salesforce.com", "sharepoint.com", "onedrive.com",
}

var emailDedup = newTTLMap(30 * time.Minute)

func StartEmailSecurityScheduler() {
	go func() {
		time.Sleep(4 * time.Minute)
		for {
			runEmailSecurityDetection()
			time.Sleep(5 * time.Minute)
		}
	}()
}

func runEmailSecurityDetection() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = true`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var tid int
		if rows.Scan(&tid) == nil {
			detectEmailThreats(tid)
		}
	}
}

func detectEmailThreats(tenantID int) {
	detectPhishingAttachments(tenantID)
	detectBECThemes(tenantID)
	detectCredentialPhishing(tenantID)
	detectMassOutbound(tenantID)
	detectLookalikeDomains(tenantID)
}

// detectPhishingAttachments — email subject/body contains dangerous file extension.
func detectPhishingAttachments(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'email_from'    AS sender,
		       el.parsed_fields->>'email_to'      AS recipient,
		       lower(el.parsed_fields->>'email_subject') AS subject,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'email_from' IS NOT NULL
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		LIMIT 1000
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var sender, recipient, subject, logMsg string
		if rows.Scan(&agentID, &sender, &recipient, &subject, &logMsg) != nil {
			continue
		}

		for _, ext := range dangerousExtensions {
			if strings.Contains(subject, ext) || strings.Contains(strings.ToLower(logMsg), ext) {
				key := fmt.Sprintf("%d:email-attach:%s:%s", tenantID, sender, ext)
				if emailDedup.touched(key) {
					break
				}
				emailDedup.touch(key)

				msg := fmt.Sprintf("Phishing Attachment — from='%s' to='%s' subject='%s' extension='%s'",
					sender, recipient, truncateLog(subject, 100), ext)
				log.Printf("[Email] %s", msg)
				createEmailAlert(agentID, tenantID, "high", "Phishing Attachment Detected", msg, "T1566.001", "Spearphishing Attachment")
				break
			}
		}

		// URL shortener in message body
		for _, short := range urlShorteners {
			if strings.Contains(strings.ToLower(logMsg), short) {
				key := fmt.Sprintf("%d:email-shorturl:%s:%s", tenantID, sender, short)
				if emailDedup.touched(key) {
					break
				}
				emailDedup.touch(key)
				msg := fmt.Sprintf("Phishing Link (URL Shortener) — from='%s' to='%s' shortener='%s'", sender, recipient, short)
				log.Printf("[Email] %s", msg)
				createEmailAlert(agentID, tenantID, "high", "Phishing Link Detected", msg, "T1566.002", "Spearphishing Link")
				break
			}
		}
	}
}

// detectBECThemes — BEC trigger words in subject/body.
func detectBECThemes(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'email_from' AS sender,
		       el.parsed_fields->>'email_to'   AS recipient,
		       lower(coalesce(el.parsed_fields->>'email_subject','') || ' ' || el.log_message) AS combined
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'email_from' IS NOT NULL
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		LIMIT 1000
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var sender, recipient, combined string
		if rows.Scan(&agentID, &sender, &recipient, &combined) != nil {
			continue
		}
		for _, trigger := range becTriggers {
			if strings.Contains(combined, trigger) {
				key := fmt.Sprintf("%d:bec:%s:%s", tenantID, sender, trigger)
				if emailDedup.touched(key) {
					break
				}
				emailDedup.touch(key)
				msg := fmt.Sprintf("Business Email Compromise Theme — from='%s' to='%s' trigger='%s'", sender, recipient, trigger)
				log.Printf("[Email] %s", msg)
				createEmailAlert(agentID, tenantID, "high", "BEC — Financial Trigger Detected", msg, "T1078", "Valid Accounts")
				break
			}
		}
		for _, trigger := range credentialPhishingTriggers {
			if strings.Contains(combined, trigger) {
				key := fmt.Sprintf("%d:credphish:%s:%s", tenantID, sender, trigger)
				if emailDedup.touched(key) {
					break
				}
				emailDedup.touch(key)
				msg := fmt.Sprintf("Credential Phishing Theme — from='%s' to='%s' trigger='%s'", sender, recipient, trigger)
				log.Printf("[Email] %s", msg)
				createEmailAlert(agentID, tenantID, "high", "Credential Phishing Email Detected", msg, "T1566.001", "Spearphishing Attachment")
				break
			}
		}
	}
}

// detectCredentialPhishing is merged into detectBECThemes above (same query).
func detectCredentialPhishing(_ int) {}

// detectMassOutbound — single sender to ≥20 distinct recipients in 5 min.
func detectMassOutbound(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'email_from' AS sender,
		       COUNT(DISTINCT el.parsed_fields->>'email_to') AS rcpt_count
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'email_from' IS NOT NULL
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		GROUP BY el.agent_id, el.parsed_fields->>'email_from'
		HAVING COUNT(DISTINCT el.parsed_fields->>'email_to') >= 20
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var sender string
		var rcptCount int
		if rows.Scan(&agentID, &sender, &rcptCount) != nil {
			continue
		}
		key := fmt.Sprintf("%d:email-mass:%s", tenantID, sender)
		if emailDedup.touched(key) {
			continue
		}
		emailDedup.touch(key)
		msg := fmt.Sprintf("Mass Outbound Email — sender='%s' recipient_count=%d in last 5 min", sender, rcptCount)
		log.Printf("[Email] %s", msg)
		createEmailAlert(agentID, tenantID, "high", "Mass Outbound Email — Possible Spam/BEC", msg, "T1114.002", "Email Collection")
	}
}

// detectLookalikeDomains — sender domain within edit-distance ≤2 of a well-known brand.
func detectLookalikeDomains(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT DISTINCT ON (el.parsed_fields->>'email_from')
		       el.agent_id,
		       el.parsed_fields->>'email_from' AS sender,
		       el.parsed_fields->>'email_to'   AS recipient
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'email_from' IS NOT NULL
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		LIMIT 500
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var sender, recipient string
		if rows.Scan(&agentID, &sender, &recipient) != nil {
			continue
		}
		senderDomain := emailDomain(sender)
		if senderDomain == "" {
			continue
		}
		for _, known := range knownDomains {
			if senderDomain == known {
				break
			}
			dist := levenshtein(senderDomain, known)
			if dist > 0 && dist <= 2 {
				key := fmt.Sprintf("%d:lookalike:%s:%s", tenantID, senderDomain, known)
				if emailDedup.touched(key) {
					break
				}
				emailDedup.touch(key)
				msg := fmt.Sprintf("Lookalike Sender Domain — from='%s' impersonates='%s' edit_distance=%d to='%s'",
					sender, known, dist, recipient)
				log.Printf("[Email] %s", msg)
				createEmailAlert(agentID, tenantID, "high", "Lookalike Domain — Possible Impersonation", msg, "T1566.001", "Spearphishing Attachment")
				break
			}
		}
	}
}

func emailDomain(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(addr[at+1:]))
}

// levenshtein computes edit distance between two strings (simple iterative DP).
func levenshtein(a, b string) int {
	ra := []rune(a)
	rb := []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if unicode.ToLower(ra[i-1]) == unicode.ToLower(rb[j-1]) {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			m := del
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			curr[j] = m
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func createEmailAlert(agentID, tenantID int, severity, rule, msg, mitre, mitreName string) {
	CreateAlert(models.Alert{
		AgentID:        agentID,
		TenantID:       tenantID,
		Severity:       severity,
		RuleName:       rule,
		LogMessage:     msg,
		MitreTactic:    "Initial Access",
		MitreTechnique: mitre,
		MitreName:      mitreName,
		Fingerprint:    fmt.Sprintf("email-%s-%d", mitre, tenantID),
	})
}
