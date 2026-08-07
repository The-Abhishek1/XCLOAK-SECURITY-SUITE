package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

func createEmailSecurityTables() {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS email_messages (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			message_id TEXT DEFAULT '', sender TEXT DEFAULT '', recipient TEXT DEFAULT '',
			subject TEXT DEFAULT '', timestamp TIMESTAMPTZ DEFAULT NOW(),
			status TEXT DEFAULT 'delivered', has_attachment BOOLEAN DEFAULT false,
			attachment_count INTEGER DEFAULT 0, url_count INTEGER DEFAULT 0,
			threat_score INTEGER DEFAULT 0, delivery_status TEXT DEFAULT 'delivered',
			threat_type TEXT DEFAULT '', direction TEXT DEFAULT 'inbound',
			size_bytes INTEGER DEFAULT 0, created_at TIMESTAMPTZ DEFAULT NOW(),
			spf_result TEXT DEFAULT 'none', dkim_result TEXT DEFAULT 'none',
			dmarc_result TEXT DEFAULT 'none', dmarc_policy TEXT DEFAULT 'none'
		)`,
		`CREATE TABLE IF NOT EXISTS email_attachments (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			message_id INTEGER DEFAULT 0, filename TEXT DEFAULT '',
			file_type TEXT DEFAULT '', file_size INTEGER DEFAULT 0,
			sha256 TEXT DEFAULT '', md5 TEXT DEFAULT '',
			verdict TEXT DEFAULT 'clean', has_macros BOOLEAN DEFAULT false,
			has_embedded BOOLEAN DEFAULT false, has_signature BOOLEAN DEFAULT false,
			sandbox_result TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS email_urls (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			message_id INTEGER DEFAULT 0, url TEXT DEFAULT '',
			domain TEXT DEFAULT '', reputation TEXT DEFAULT 'neutral',
			redirect_count INTEGER DEFAULT 0, is_shortened BOOLEAN DEFAULT false,
			is_newly_registered BOOLEAN DEFAULT false, has_login_form BOOLEAN DEFAULT false,
			is_typosquatting BOOLEAN DEFAULT false, verdict TEXT DEFAULT 'clean',
			click_count INTEGER DEFAULT 0, created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS email_campaigns (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			name TEXT DEFAULT '', campaign_type TEXT DEFAULT 'phishing',
			threat_actor TEXT DEFAULT '', email_count INTEGER DEFAULT 0,
			victim_count INTEGER DEFAULT 0, first_seen TIMESTAMPTZ DEFAULT NOW(),
			last_seen TIMESTAMPTZ DEFAULT NOW(), status TEXT DEFAULT 'active',
			common_subject TEXT DEFAULT '', common_sender TEXT DEFAULT '',
			common_domain TEXT DEFAULT '', malware_family TEXT DEFAULT '',
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS email_user_risk (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			email TEXT DEFAULT '', display_name TEXT DEFAULT '',
			department TEXT DEFAULT '', click_count INTEGER DEFAULT 0,
			phishing_failures INTEGER DEFAULT 0, is_repeated_victim BOOLEAN DEFAULT false,
			training_status TEXT DEFAULT 'pending', risk_score INTEGER DEFAULT 0,
			last_click_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS email_reported (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			reporter_email TEXT DEFAULT '', message_id TEXT DEFAULT '',
			subject TEXT DEFAULT '', original_sender TEXT DEFAULT '',
			reported_at TIMESTAMPTZ DEFAULT NOW(), triage_status TEXT DEFAULT 'pending',
			analyst_notes TEXT DEFAULT '', campaign_id INTEGER DEFAULT 0,
			auto_verdict TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS email_policies (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			name TEXT DEFAULT '', policy_type TEXT DEFAULT 'attachment',
			action TEXT DEFAULT 'quarantine', criteria TEXT DEFAULT '',
			enabled BOOLEAN DEFAULT true, priority INTEGER DEFAULT 100,
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
	}
	for _, s := range stmts {
		database.DB.Exec(s)
	}
	// Defensive ALTERs for spf_result/dkim_result/dmarc_result/dmarc_policy —
	// covers the case where email_messages already exists from before these
	// columns were added (the CREATE TABLE above is a no-op once the table
	// exists, IF NOT EXISTS or not).
	for _, col := range []string{"spf_result", "dkim_result", "dmarc_result", "dmarc_policy"} {
		database.DB.Exec(fmt.Sprintf(`ALTER TABLE email_messages ADD COLUMN IF NOT EXISTS %s TEXT DEFAULT 'none'`, col))
	}
}

// GetEmailDashboard — GET /api/email/dashboard
func GetEmailDashboard(c *gin.Context) {
	createEmailSecurityTables()
	tid := tenantIDFromContext(c)
	var processed, delivered, blocked, phishing, malware, bec, spam int
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1`, tid).Scan(&processed)
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND status='delivered'`, tid).Scan(&delivered)
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND status IN ('blocked','quarantined')`, tid).Scan(&blocked)
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND threat_type='phishing'`, tid).Scan(&phishing)
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND threat_type='malware'`, tid).Scan(&malware)
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND threat_type='bec'`, tid).Scan(&bec)
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND threat_type='spam'`, tid).Scan(&spam)
	var urlClicks int
	database.DB.QueryRow(`SELECT COALESCE(SUM(click_count),0) FROM email_urls WHERE tenant_id=$1`, tid).Scan(&urlClicks)
	var highRisk int
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_user_risk WHERE tenant_id=$1 AND risk_score>=70`, tid).Scan(&highRisk)
	spamRate := 0
	if processed > 0 {
		spamRate = spam * 100 / processed
	}
	score := 100 - (phishing+malware+bec)*2 - blocked
	if score < 0 {
		score = 0
	} else if score > 100 {
		score = 100
	}
	c.JSON(http.StatusOK, gin.H{
		"emails_processed":     processed,
		"emails_delivered":     delivered,
		"emails_blocked":       blocked,
		"phishing_attempts":    phishing,
		"malware_attachments":  malware,
		"bec_attempts":         bec,
		"spam_rate":            spamRate,
		"url_clicks":           urlClicks,
		"high_risk_users":      highRisk,
		"email_security_score": score,
	})
}

// GetEmailMailFlow — GET /api/email/mail-flow
func GetEmailMailFlow(c *gin.Context) {
	createEmailSecurityTables()
	tid := tenantIDFromContext(c)
	var total, blocked, quarantined, sandboxed int
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND status='blocked'`, tid).Scan(&blocked)
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND status='quarantined'`, tid).Scan(&quarantined)
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_attachments WHERE tenant_id=$1`, tid).Scan(&sandboxed)
	c.JSON(http.StatusOK, gin.H{
		"steps": []map[string]interface{}{
			{"label": "Internet", "count": total, "dropped": 0, "quarantined": 0},
			{"label": "Gateway", "count": total, "dropped": 0, "quarantined": 0},
			{"label": "Email Filters", "count": total - blocked, "dropped": blocked, "quarantined": 0},
			{"label": "Sandbox", "count": sandboxed, "dropped": 0, "quarantined": 0},
			{"label": "Threat Intelligence", "count": total - blocked, "dropped": 0, "quarantined": 0},
			{"label": "Mailbox", "count": total - blocked - quarantined, "dropped": 0, "quarantined": quarantined},
			{"label": "User", "count": total - blocked - quarantined, "dropped": 0, "quarantined": 0},
		},
		"total":       total,
		"blocked":     blocked,
		"quarantined": quarantined,
	})
}

// GetEmailMessages — GET /api/email/messages
func GetEmailMessages(c *gin.Context) {
	createEmailSecurityTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	q := `SELECT id, message_id, sender, recipient, subject, timestamp, status,
		has_attachment, attachment_count, url_count, threat_score, delivery_status,
		threat_type, direction, size_bytes, created_at
		FROM email_messages WHERE tenant_id=$1`
	args := []interface{}{tid}
	i := 2
	// q is a free-text search across subject OR sender (the mobile search box) —
	// kept separate from the sender/subject filters below, which AND together
	// and would otherwise only match messages where the same term appears in
	// both fields at once.
	if v := c.Query("q"); v != "" {
		q += fmt.Sprintf(" AND (subject ILIKE $%d OR sender ILIKE $%d)", i, i)
		args = append(args, "%"+v+"%")
		i++
	}
	if v := c.Query("sender"); v != "" {
		q += fmt.Sprintf(" AND sender ILIKE $%d", i)
		args = append(args, "%"+v+"%")
		i++
	}
	if v := c.Query("recipient"); v != "" {
		q += fmt.Sprintf(" AND recipient ILIKE $%d", i)
		args = append(args, "%"+v+"%")
		i++
	}
	if v := c.Query("subject"); v != "" {
		q += fmt.Sprintf(" AND subject ILIKE $%d", i)
		args = append(args, "%"+v+"%")
		i++
	}
	if v := c.Query("status"); v != "" {
		q += fmt.Sprintf(" AND status=$%d", i)
		args = append(args, v)
		i++
	}
	if v := c.Query("threat_type"); v != "" {
		q += fmt.Sprintf(" AND threat_type=$%d", i)
		args = append(args, v)
		i++
	}
	if v := c.Query("message_id"); v != "" {
		q += fmt.Sprintf(" AND message_id ILIKE $%d", i)
		args = append(args, "%"+v+"%")
		i++
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Msg struct {
		ID              int    `json:"id"`
		MessageID       string `json:"message_id"`
		Sender          string `json:"sender"`
		Recipient       string `json:"recipient"`
		Subject         string `json:"subject"`
		Timestamp       string `json:"timestamp"`
		Status          string `json:"status"`
		HasAttachment   bool   `json:"has_attachment"`
		AttachmentCount int    `json:"attachment_count"`
		URLCount        int    `json:"url_count"`
		ThreatScore     int    `json:"threat_score"`
		DeliveryStatus  string `json:"delivery_status"`
		ThreatType      string `json:"threat_type"`
		Direction       string `json:"direction"`
		SizeBytes       int    `json:"size_bytes"`
		CreatedAt       string `json:"created_at"`
	}
	msgs := []Msg{}
	for rows.Next() {
		var m Msg
		if rows.Scan(&m.ID, &m.MessageID, &m.Sender, &m.Recipient, &m.Subject,
			&m.Timestamp, &m.Status, &m.HasAttachment, &m.AttachmentCount, &m.URLCount,
			&m.ThreatScore, &m.DeliveryStatus, &m.ThreatType, &m.Direction,
			&m.SizeBytes, &m.CreatedAt) == nil {
			msgs = append(msgs, m)
		}
	}
	if msgs == nil {
		msgs = []Msg{}
	}
	c.JSON(http.StatusOK, msgs)
}

// GetEmailThreats — GET /api/email/threats?type=phishing|bec|malware
func GetEmailThreats(c *gin.Context) {
	createEmailSecurityTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	threatType := c.Query("type")
	q := `SELECT id, message_id, sender, recipient, subject, status, threat_type,
		threat_score, has_attachment, url_count, created_at
		FROM email_messages WHERE tenant_id=$1 AND threat_type != '' AND threat_type != 'clean'`
	args := []interface{}{tid}
	if threatType != "" {
		q += " AND threat_type=$2 ORDER BY threat_score DESC, created_at DESC LIMIT $3"
		args = append(args, threatType, limit)
	} else {
		q += " ORDER BY threat_score DESC, created_at DESC LIMIT $2"
		args = append(args, limit)
	}
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Threat struct {
		ID            int    `json:"id"`
		MessageID     string `json:"message_id"`
		Sender        string `json:"sender"`
		Recipient     string `json:"recipient"`
		Subject       string `json:"subject"`
		Status        string `json:"status"`
		ThreatType    string `json:"threat_type"`
		ThreatScore   int    `json:"threat_score"`
		HasAttachment bool   `json:"has_attachment"`
		URLCount      int    `json:"url_count"`
		CreatedAt     string `json:"created_at"`
	}
	threats := []Threat{}
	for rows.Next() {
		var t Threat
		if rows.Scan(&t.ID, &t.MessageID, &t.Sender, &t.Recipient, &t.Subject,
			&t.Status, &t.ThreatType, &t.ThreatScore, &t.HasAttachment,
			&t.URLCount, &t.CreatedAt) == nil {
			threats = append(threats, t)
		}
	}
	if threats == nil {
		threats = []Threat{}
	}
	c.JSON(http.StatusOK, threats)
}

// GetEmailAttachments — GET /api/email/attachments
func GetEmailAttachments(c *gin.Context) {
	createEmailSecurityTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	q := `SELECT id, message_id, filename, file_type, file_size, sha256, md5,
		verdict, has_macros, has_embedded, has_signature, sandbox_result, created_at
		FROM email_attachments WHERE tenant_id=$1`
	args := []interface{}{tid}
	i := 2
	if v := c.Query("verdict"); v != "" {
		q += fmt.Sprintf(" AND verdict=$%d", i)
		args = append(args, v)
		i++
	}
	if v := c.Query("file_type"); v != "" {
		q += fmt.Sprintf(" AND file_type=$%d", i)
		args = append(args, v)
		i++
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Att struct {
		ID            int    `json:"id"`
		MessageID     int    `json:"message_id"`
		Filename      string `json:"filename"`
		FileType      string `json:"file_type"`
		FileSize      int    `json:"file_size"`
		SHA256        string `json:"sha256"`
		MD5           string `json:"md5"`
		Verdict       string `json:"verdict"`
		HasMacros     bool   `json:"has_macros"`
		HasEmbedded   bool   `json:"has_embedded"`
		HasSignature  bool   `json:"has_signature"`
		SandboxResult string `json:"sandbox_result"`
		CreatedAt     string `json:"created_at"`
	}
	atts := []Att{}
	for rows.Next() {
		var a Att
		if rows.Scan(&a.ID, &a.MessageID, &a.Filename, &a.FileType, &a.FileSize,
			&a.SHA256, &a.MD5, &a.Verdict, &a.HasMacros, &a.HasEmbedded,
			&a.HasSignature, &a.SandboxResult, &a.CreatedAt) == nil {
			atts = append(atts, a)
		}
	}
	if atts == nil {
		atts = []Att{}
	}
	c.JSON(http.StatusOK, atts)
}

// GetEmailURLs — GET /api/email/urls
func GetEmailURLs(c *gin.Context) {
	createEmailSecurityTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	verdict := c.Query("verdict")
	q := `SELECT id, message_id, url, domain, reputation, redirect_count,
		is_shortened, is_newly_registered, has_login_form, is_typosquatting,
		verdict, click_count, created_at
		FROM email_urls WHERE tenant_id=$1`
	args := []interface{}{tid}
	if verdict != "" {
		q += " AND verdict=$2 ORDER BY click_count DESC, created_at DESC LIMIT $3"
		args = append(args, verdict, limit)
	} else {
		q += " ORDER BY click_count DESC, created_at DESC LIMIT $2"
		args = append(args, limit)
	}
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type URL struct {
		ID                int    `json:"id"`
		MessageID         int    `json:"message_id"`
		URL               string `json:"url"`
		Domain            string `json:"domain"`
		Reputation        string `json:"reputation"`
		RedirectCount     int    `json:"redirect_count"`
		IsShortened       bool   `json:"is_shortened"`
		IsNewlyRegistered bool   `json:"is_newly_registered"`
		HasLoginForm      bool   `json:"has_login_form"`
		IsTyposquatting   bool   `json:"is_typosquatting"`
		Verdict           string `json:"verdict"`
		ClickCount        int    `json:"click_count"`
		CreatedAt         string `json:"created_at"`
	}
	urls := []URL{}
	for rows.Next() {
		var u URL
		if rows.Scan(&u.ID, &u.MessageID, &u.URL, &u.Domain, &u.Reputation,
			&u.RedirectCount, &u.IsShortened, &u.IsNewlyRegistered, &u.HasLoginForm,
			&u.IsTyposquatting, &u.Verdict, &u.ClickCount, &u.CreatedAt) == nil {
			urls = append(urls, u)
		}
	}
	if urls == nil {
		urls = []URL{}
	}
	c.JSON(http.StatusOK, urls)
}

// GetEmailAuthResults — GET /api/email/auth-results
// GetEmailAuthResults previously computed spf_pass/dkim_pass/dmarc_pass as
// fixed percentages of total message count (78%/82%/71%, regardless of any
// real data) and returned a hardcoded list of 7 domains unrelated to any
// tenant's actual mail flow (microsoft.com, google.com, ... with fixed
// pass/fail verdicts) — fabricated in full, not derived from anything.
// Real per-message spf_result/dkim_result/dmarc_result/dmarc_policy columns
// were added to email_messages so this can aggregate genuine data instead.
// ARC and BIMI (both real protocols, but opt-in and far less universally
// deployed than SPF/DKIM/DMARC) have no per-message signal tracked here —
// rather than fake those two too, they're dropped from the response
// entirely instead of carried forward as more fabricated fields.
func GetEmailAuthResults(c *gin.Context) {
	createEmailSecurityTables()
	tid := tenantIDFromContext(c)
	var total int
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1`, tid).Scan(&total)
	if total == 0 {
		total = 1
	}
	var spfPass, dkimPass, dmarcPass int
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND spf_result='pass'`, tid).Scan(&spfPass)
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND dkim_result='pass'`, tid).Scan(&dkimPass)
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND dmarc_result='pass'`, tid).Scan(&dmarcPass)

	type AuthDomain struct {
		Domain  string `json:"domain"`
		SPF     string `json:"spf"`
		DKIM    string `json:"dkim"`
		DMARC   string `json:"dmarc"`
		Aligned bool   `json:"aligned"`
		Policy  string `json:"policy"`
		Count   int    `json:"count"`
	}
	domains := []AuthDomain{}
	rows, err := database.DB.Query(`
		SELECT split_part(sender, '@', 2) AS domain,
		       COUNT(*) FILTER (WHERE spf_result='pass') AS spf_ok,
		       COUNT(*) FILTER (WHERE dkim_result='pass') AS dkim_ok,
		       COUNT(*) FILTER (WHERE dmarc_result='pass') AS dmarc_ok,
		       COUNT(*) AS total,
		       MODE() WITHIN GROUP (ORDER BY dmarc_policy) AS policy
		FROM email_messages
		WHERE tenant_id=$1 AND sender LIKE '%@%'
		GROUP BY domain
		ORDER BY total DESC
		LIMIT 15`, tid)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var d AuthDomain
			var spfOK, dkimOK, dmarcOK, cnt int
			if rows.Scan(&d.Domain, &spfOK, &dkimOK, &dmarcOK, &cnt, &d.Policy) == nil {
				d.Count = cnt
				majority := func(ok int) string {
					if ok*2 >= cnt {
						return "pass"
					}
					return "fail"
				}
				d.SPF = majority(spfOK)
				d.DKIM = majority(dkimOK)
				d.DMARC = majority(dmarcOK)
				d.Aligned = (d.SPF == "pass" || d.DKIM == "pass") && d.DMARC == "pass"
				domains = append(domains, d)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"summary": gin.H{
			"total":      total,
			"spf_pass":   spfPass,
			"dkim_pass":  dkimPass,
			"dmarc_pass": dmarcPass,
			"spf_rate":   spfPass * 100 / total,
			"dkim_rate":  dkimPass * 100 / total,
			"dmarc_rate": dmarcPass * 100 / total,
		},
		"domains": domains,
	})
}

// GetSenderIntelligence — GET /api/email/sender-intel?domain=...
// GetSenderIntelligence previously classified a domain "malicious"/"trusted"
// via a crude substring match (`strings.Contains(domain, "xyz")`, etc.) and
// returned entirely invented WHOIS/geo/ASN enrichment (fixed registrar,
// city, ASN per bucket) — none of it a real lookup of any kind. This app
// has no WHOIS/GeoIP integration for domains anywhere (services/
// geoip_service.go works on IPs, and email has no source-IP data at all),
// so rather than keep fabricating those fields, this now checks the real
// `iocs` table for an actual match and derives real signal from this
// tenant's own real email/URL history — and simply omits the fields with
// no honest real source instead of inventing them.
func GetSenderIntelligence(c *gin.Context) {
	createEmailSecurityTables()
	tid := tenantIDFromContext(c)
	domain := c.Query("domain")
	email := c.Query("email")
	if domain == "" && email != "" {
		if parts := strings.Split(email, "@"); len(parts) == 2 {
			domain = parts[1]
		}
	}
	if domain == "" {
		domain = "unknown"
	}

	var iocHits int
	database.DB.QueryRow(`SELECT COUNT(*) FROM iocs WHERE tenant_id=$1 AND enabled=true AND type IN ('domain','email') AND indicator ILIKE $2`,
		tid, "%"+domain+"%").Scan(&iocHits)

	var maliciousURLs, totalURLs int
	database.DB.QueryRow(`SELECT COUNT(*) FILTER (WHERE verdict='malicious'), COUNT(*) FROM email_urls WHERE tenant_id=$1 AND domain=$2`, tid, domain).Scan(&maliciousURLs, &totalURLs)

	var volume int
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND sender ILIKE $2 AND created_at > NOW()-INTERVAL '7 days'`,
		tid, "%@"+domain).Scan(&volume)

	rep, score := "unknown", 50
	switch {
	case iocHits > 0 || maliciousURLs > 0:
		rep, score = "malicious", 10
	case totalURLs > 0:
		rep, score = "neutral", 50
	}

	c.JSON(http.StatusOK, gin.H{
		"domain":            domain,
		"reputation":        rep,
		"reputation_score":  score,
		"email_volume_7d":   volume,
		"threat_intel_hits": iocHits,
	})
}

// GetEmailThreatIntel — GET /api/email/threat-intel
// GetEmailThreatIntel previously returned 4 sections as fixed constants
// regardless of tenant/data — specific domains, IPs, malware families, and
// threat actors that never came from anywhere real. Replaced with real
// derivations: malicious_domains from email_urls (a category label is
// derived from that row's own real is_typosquatting/has_login_form flags,
// not invented), threat_actors from email_campaigns' own real
// threat_actor column (already a real field on real seeded campaigns,
// simply never aggregated into this view before). malicious_ips and
// malware_families are dropped entirely rather than faked — this schema
// has no source-IP data anywhere for email (unlike network-based
// telemetry) and no structured malware-family field on any email table
// (email_attachments.sandbox_result is freeform text), so there's no
// honest real source for either.
func GetEmailThreatIntel(c *gin.Context) {
	createEmailSecurityTables()
	tid := tenantIDFromContext(c)
	var phishing, malware, bec int
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND threat_type='phishing'`, tid).Scan(&phishing)
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND threat_type='malware'`, tid).Scan(&malware)
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND threat_type='bec'`, tid).Scan(&bec)

	maliciousDomains := []map[string]interface{}{}
	dRows, err := database.DB.Query(`
		SELECT domain, SUM(click_count) AS hits, MIN(created_at) AS first_seen,
		       bool_or(has_login_form) AS login_form, bool_or(is_typosquatting) AS typo
		FROM email_urls WHERE tenant_id=$1 AND verdict='malicious' AND domain != ''
		GROUP BY domain ORDER BY hits DESC LIMIT 10`, tid)
	if err == nil {
		defer dRows.Close()
		for dRows.Next() {
			var domain, firstSeen string
			var hits int
			var loginForm, typo bool
			if dRows.Scan(&domain, &hits, &firstSeen, &loginForm, &typo) == nil {
				category := "phishing"
				switch {
				case typo:
					category = "brand_impersonation"
				case loginForm:
					category = "credential_harvesting"
				}
				maliciousDomains = append(maliciousDomains, map[string]interface{}{
					"domain": domain, "category": category, "hits": hits, "first_seen": firstSeen[:10],
				})
			}
		}
	}

	threatActors := []map[string]interface{}{}
	aRows, err := database.DB.Query(`
		SELECT threat_actor, COUNT(*) AS campaigns, COALESCE(SUM(email_count),0) AS volume
		FROM email_campaigns WHERE tenant_id=$1 AND threat_actor != ''
		GROUP BY threat_actor ORDER BY volume DESC LIMIT 10`, tid)
	if err == nil {
		defer aRows.Close()
		for aRows.Next() {
			var actor string
			var campaigns, volume int
			if aRows.Scan(&actor, &campaigns, &volume) == nil {
				threatActors = append(threatActors, map[string]interface{}{
					"actor": actor, "campaigns": campaigns, "email_volume": volume,
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"malicious_domains": maliciousDomains,
		"threat_actors":     threatActors,
		"by_threat_type": []map[string]interface{}{
			{"type": "phishing", "count": phishing},
			{"type": "malware", "count": malware},
			{"type": "bec", "count": bec},
		},
	})
}

// GetEmailCampaigns — GET /api/email/campaigns
func GetEmailCampaigns(c *gin.Context) {
	createEmailSecurityTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 30)
	rows, err := database.DB.Query(`
		SELECT id, name, campaign_type, threat_actor, email_count, victim_count,
			first_seen, last_seen, status, common_subject, common_sender,
			common_domain, malware_family, created_at
		FROM email_campaigns WHERE tenant_id=$1 ORDER BY last_seen DESC LIMIT $2
	`, tid, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Camp struct {
		ID            int    `json:"id"`
		Name          string `json:"name"`
		CampaignType  string `json:"campaign_type"`
		ThreatActor   string `json:"threat_actor"`
		EmailCount    int    `json:"email_count"`
		VictimCount   int    `json:"victim_count"`
		FirstSeen     string `json:"first_seen"`
		LastSeen      string `json:"last_seen"`
		Status        string `json:"status"`
		CommonSubject string `json:"common_subject"`
		CommonSender  string `json:"common_sender"`
		CommonDomain  string `json:"common_domain"`
		MalwareFamily string `json:"malware_family"`
		CreatedAt     string `json:"created_at"`
	}
	camps := []Camp{}
	for rows.Next() {
		var ca Camp
		if rows.Scan(&ca.ID, &ca.Name, &ca.CampaignType, &ca.ThreatActor, &ca.EmailCount,
			&ca.VictimCount, &ca.FirstSeen, &ca.LastSeen, &ca.Status, &ca.CommonSubject,
			&ca.CommonSender, &ca.CommonDomain, &ca.MalwareFamily, &ca.CreatedAt) == nil {
			camps = append(camps, ca)
		}
	}
	if camps == nil {
		camps = []Camp{}
	}
	c.JSON(http.StatusOK, camps)
}

// GetEmailTimeline — GET /api/email/timeline
func GetEmailTimeline(c *gin.Context) {
	createEmailSecurityTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	rows, err := database.DB.Query(`
		SELECT id, message_id, sender, recipient, subject, threat_type,
			threat_score, status, created_at
		FROM email_messages WHERE tenant_id=$1 AND threat_type != '' AND threat_type != 'clean'
		ORDER BY created_at DESC LIMIT $2
	`, tid, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Event struct {
		ID          int    `json:"id"`
		MessageID   string `json:"message_id"`
		Sender      string `json:"sender"`
		Recipient   string `json:"recipient"`
		Subject     string `json:"subject"`
		ThreatType  string `json:"threat_type"`
		ThreatScore int    `json:"threat_score"`
		Status      string `json:"status"`
		CreatedAt   string `json:"created_at"`
	}
	events := []Event{}
	for rows.Next() {
		var e Event
		if rows.Scan(&e.ID, &e.MessageID, &e.Sender, &e.Recipient, &e.Subject,
			&e.ThreatType, &e.ThreatScore, &e.Status, &e.CreatedAt) == nil {
			events = append(events, e)
		}
	}
	if events == nil {
		events = []Event{}
	}
	c.JSON(http.StatusOK, events)
}

// GetEmailUserRisk — GET /api/email/user-risk
func GetEmailUserRisk(c *gin.Context) {
	createEmailSecurityTables()
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`
		SELECT id, email, display_name, department, click_count, phishing_failures,
			is_repeated_victim, training_status, risk_score, last_click_at, created_at
		FROM email_user_risk WHERE tenant_id=$1 ORDER BY risk_score DESC LIMIT 50
	`, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type User struct {
		ID               int     `json:"id"`
		Email            string  `json:"email"`
		DisplayName      string  `json:"display_name"`
		Department       string  `json:"department"`
		ClickCount       int     `json:"click_count"`
		PhishingFailures int     `json:"phishing_failures"`
		IsRepeatedVictim bool    `json:"is_repeated_victim"`
		TrainingStatus   string  `json:"training_status"`
		RiskScore        int     `json:"risk_score"`
		LastClickAt      *string `json:"last_click_at"`
		CreatedAt        string  `json:"created_at"`
	}
	users := []User{}
	for rows.Next() {
		var u User
		if rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Department, &u.ClickCount,
			&u.PhishingFailures, &u.IsRepeatedVictim, &u.TrainingStatus,
			&u.RiskScore, &u.LastClickAt, &u.CreatedAt) == nil {
			users = append(users, u)
		}
	}
	if users == nil {
		users = []User{}
	}
	c.JSON(http.StatusOK, users)
}

// GetEmailAnalytics — GET /api/email/analytics
func GetEmailAnalytics(c *gin.Context) {
	createEmailSecurityTables()
	tid := tenantIDFromContext(c)
	type SenderStat struct {
		Sender string `json:"sender"`
		Count  int    `json:"count"`
	}
	type URLStat struct {
		Domain string `json:"domain"`
		Count  int    `json:"count"`
	}
	type TrendPoint struct {
		Date  string `json:"date"`
		Count int    `json:"count"`
	}
	topSenders := []SenderStat{}
	sRows, _ := database.DB.Query(`SELECT sender, COUNT(*) as cnt FROM email_messages WHERE tenant_id=$1 GROUP BY sender ORDER BY cnt DESC LIMIT 10`, tid)
	if sRows != nil {
		defer sRows.Close()
		for sRows.Next() {
			var s SenderStat
			if sRows.Scan(&s.Sender, &s.Count) == nil {
				topSenders = append(topSenders, s)
			}
		}
	}
	if topSenders == nil {
		topSenders = []SenderStat{}
	}
	topURLs := []URLStat{}
	uRows, _ := database.DB.Query(`SELECT domain, COUNT(*) as cnt FROM email_urls WHERE tenant_id=$1 AND verdict='malicious' GROUP BY domain ORDER BY cnt DESC LIMIT 10`, tid)
	if uRows != nil {
		defer uRows.Close()
		for uRows.Next() {
			var u URLStat
			if uRows.Scan(&u.Domain, &u.Count) == nil {
				topURLs = append(topURLs, u)
			}
		}
	}
	if topURLs == nil {
		topURLs = []URLStat{}
	}
	var phishingTrend, becTrend []TrendPoint
	for i := 13; i >= 0; i-- {
		d := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		var p, b int
		database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND DATE(created_at)=$2 AND threat_type='phishing'`, tid, d).Scan(&p)
		database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND DATE(created_at)=$2 AND threat_type='bec'`, tid, d).Scan(&b)
		phishingTrend = append(phishingTrend, TrendPoint{Date: d, Count: p})
		becTrend = append(becTrend, TrendPoint{Date: d, Count: b})
	}
	c.JSON(http.StatusOK, gin.H{
		"top_senders":      topSenders,
		"top_blocked_urls": topURLs,
		"phishing_trend":   phishingTrend,
		"bec_trend":        becTrend,
	})
}

// GetEmailPolicies — GET /api/email/policies
func GetEmailPolicies(c *gin.Context) {
	createEmailSecurityTables()
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`
		SELECT id, name, policy_type, action, criteria, enabled, priority, created_at
		FROM email_policies WHERE tenant_id=$1 ORDER BY priority ASC, created_at DESC
	`, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Policy struct {
		ID         int    `json:"id"`
		Name       string `json:"name"`
		PolicyType string `json:"policy_type"`
		Action     string `json:"action"`
		Criteria   string `json:"criteria"`
		Enabled    bool   `json:"enabled"`
		Priority   int    `json:"priority"`
		CreatedAt  string `json:"created_at"`
	}
	policies := []Policy{}
	for rows.Next() {
		var p Policy
		if rows.Scan(&p.ID, &p.Name, &p.PolicyType, &p.Action, &p.Criteria, &p.Enabled, &p.Priority, &p.CreatedAt) == nil {
			policies = append(policies, p)
		}
	}
	if policies == nil {
		policies = []Policy{}
	}
	c.JSON(http.StatusOK, policies)
}

// PostEmailPolicy — POST /api/email/policies
func PostEmailPolicy(c *gin.Context) {
	createEmailSecurityTables()
	var body struct {
		Name       string `json:"name"`
		PolicyType string `json:"policy_type"`
		Action     string `json:"action"`
		Criteria   string `json:"criteria"`
		Priority   int    `json:"priority"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}
	if body.Action == "" {
		body.Action = "quarantine"
	}
	if body.Priority == 0 {
		body.Priority = 100
	}
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO email_policies (name, policy_type, action, criteria, priority, tenant_id)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING id
	`, body.Name, body.PolicyType, body.Action, body.Criteria, body.Priority, tenantIDFromContext(c)).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "ok": true})
}

// PatchEmailPolicy — PATCH /api/email/policies/:id
func PatchEmailPolicy(c *gin.Context) {
	createEmailSecurityTables()
	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	allowed := map[string]bool{"name": true, "action": true, "criteria": true, "enabled": true, "priority": true}
	setClauses, args := []string{}, []interface{}{}
	i := 1
	for k, v := range body {
		if allowed[k] {
			setClauses = append(setClauses, fmt.Sprintf("%s=$%d", k, i))
			args = append(args, v)
			i++
		}
	}
	if len(setClauses) == 0 {
		c.JSON(http.StatusOK, gin.H{"ok": true})
		return
	}
	args = append(args, c.Param("id"), tenantIDFromContext(c))
	_, err := database.DB.Exec(
		fmt.Sprintf("UPDATE email_policies SET %s WHERE id=$%d AND tenant_id=$%d", strings.Join(setClauses, ","), i, i+1),
		args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DeleteEmailPolicy — DELETE /api/email/policies/:id
func DeleteEmailPolicy(c *gin.Context) {
	createEmailSecurityTables()
	res, err := database.DB.Exec(`DELETE FROM email_policies WHERE id=$1 AND tenant_id=$2`,
		c.Param("id"), tenantIDFromContext(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// GetUserReported — GET /api/email/reported
func GetUserReported(c *gin.Context) {
	createEmailSecurityTables()
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`
		SELECT id, reporter_email, message_id, subject, original_sender,
			reported_at, triage_status, analyst_notes, campaign_id, auto_verdict
		FROM email_reported WHERE tenant_id=$1 ORDER BY reported_at DESC LIMIT 50
	`, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Report struct {
		ID             int    `json:"id"`
		ReporterEmail  string `json:"reporter_email"`
		MessageID      string `json:"message_id"`
		Subject        string `json:"subject"`
		OriginalSender string `json:"original_sender"`
		ReportedAt     string `json:"reported_at"`
		TriageStatus   string `json:"triage_status"`
		AnalystNotes   string `json:"analyst_notes"`
		CampaignID     int    `json:"campaign_id"`
		AutoVerdict    string `json:"auto_verdict"`
	}
	reports := []Report{}
	for rows.Next() {
		var r Report
		if rows.Scan(&r.ID, &r.ReporterEmail, &r.MessageID, &r.Subject, &r.OriginalSender,
			&r.ReportedAt, &r.TriageStatus, &r.AnalystNotes, &r.CampaignID, &r.AutoVerdict) == nil {
			reports = append(reports, r)
		}
	}
	if reports == nil {
		reports = []Report{}
	}
	c.JSON(http.StatusOK, reports)
}

// PatchUserReported — PATCH /api/email/reported/:id
// Partial update: only columns actually present in the JSON body are set —
// this used to unconditionally overwrite both columns from a Go struct with
// zero-value defaults, so a caller that only meant to change triage_status
// (like the mobile "Mark Reviewed" button, which never sends analyst_notes)
// silently wiped out any existing analyst_notes on every call.
func PatchUserReported(c *gin.Context) {
	createEmailSecurityTables()
	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	allowed := map[string]bool{"triage_status": true, "analyst_notes": true}
	setClauses, args := []string{}, []interface{}{}
	i := 1
	for k, v := range body {
		if allowed[k] {
			setClauses = append(setClauses, fmt.Sprintf("%s=$%d", k, i))
			args = append(args, v)
			i++
		}
	}
	if len(setClauses) == 0 {
		c.JSON(http.StatusOK, gin.H{"ok": true})
		return
	}
	args = append(args, c.Param("id"), tenantIDFromContext(c))
	_, err := database.DB.Exec(
		fmt.Sprintf("UPDATE email_reported SET %s WHERE id=$%d AND tenant_id=$%d", strings.Join(setClauses, ","), i, i+1),
		args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// PostEmailResponse — POST /api/email/response
// PostEmailResponse dispatches a response action against a real message,
// sender, domain, URL, attachment hash, or victim.
//
// Previously this was a pure canned-message lookup table with zero side
// effects of any kind — not even a broken DB write attempt, unlike most
// fake-response-action instances found this phase. No email was ever
// actually quarantined/deleted, no IOC was ever created, no password reset
// was ever issued.
func PostEmailResponse(c *gin.Context) {
	createEmailSecurityTables()
	tid := tenantIDFromContext(c)
	username := usernameFromContext(c)
	var body struct {
		Action    string `json:"action"`
		MessageID string `json:"message_id"`
		Sender    string `json:"sender"`
		Domain    string `json:"domain"`
		URL       string `json:"url"`
		Hash      string `json:"hash"`
		Email     string `json:"email"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Action == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action required"})
		return
	}

	var message string
	switch body.Action {
	case "quarantine_email", "delete_email":
		if body.MessageID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "message_id required"})
			return
		}
		status := "quarantined"
		if body.Action == "delete_email" {
			status = "deleted"
		}
		tag, err := database.DB.Exec(`UPDATE email_messages SET status=$1, delivery_status=$1 WHERE tenant_id=$2 AND message_id=$3`,
			status, tid, body.MessageID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if n, _ := tag.RowsAffected(); n == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "no message found with id '" + body.MessageID + "'"})
			return
		}
		message = fmt.Sprintf("Message %s: %s", body.MessageID, status)

	case "block_sender":
		if err := createEmailIOC(tid, "email", body.Sender, username); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		message = "Sender " + body.Sender + " blocked"

	case "block_domain":
		if err := createEmailIOC(tid, "domain", body.Domain, username); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		message = "Domain " + body.Domain + " blocked"

	case "block_url":
		if err := createEmailIOC(tid, "url", body.URL, username); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		message = "URL blocked"

	case "block_hash":
		if body.Hash == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "hash required"})
			return
		}
		if err := createEmailIOC(tid, services.GuessIOCType(body.Hash), body.Hash, username); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		message = "Attachment hash blocked"

	case "reset_password":
		if body.Email == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "email required"})
			return
		}
		// Same anti-enumeration design as the real /api/auth/forgot-password
		// flow this reuses — always reports success regardless of whether
		// the email matches a real account, so the response can't be used
		// to probe which addresses have platform logins.
		services.RequestPasswordReset(body.Email)
		message = "If " + body.Email + " has a platform account, a password reset was issued"

	case "create_incident":
		var incidentID int
		if err := database.DB.QueryRow(`
			INSERT INTO incidents (tenant_id, title, description, severity, status)
			VALUES ($1,$2,$3,'high','open') RETURNING id`,
			tid, "Email Security Escalation: "+body.Sender,
			fmt.Sprintf("Escalated from email security. Message: %s, Sender: %s", body.MessageID, body.Sender),
		).Scan(&incidentID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		message = fmt.Sprintf("Incident #%d created", incidentID)

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown action"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "message": message})
}

// createEmailIOC blocks an indicator via the same real, enabled-IOC
// mechanism every other page's block_* response action uses this phase.
func createEmailIOC(tid int, iocType, indicator, actor string) error {
	if indicator == "" {
		return fmt.Errorf("indicator required")
	}
	return repositories.CreateIOC(models.IOC{
		Indicator: indicator, Type: iocType, Severity: "high", Enabled: true,
		Description: "Blocked via Email Security by " + actor,
	}, tid)
}

// PostEmailAI — POST /api/email/ai
func PostEmailAI(c *gin.Context) {
	createEmailSecurityTables()
	var body struct {
		Mode    string `json:"mode"`
		Subject string `json:"subject"`
		Sender  string `json:"sender"`
		Content string `json:"content"`
		URL     string `json:"url"`
		Hash    string `json:"hash"`
	}
	c.ShouldBindJSON(&body)
	var prompt string
	switch body.Mode {
	case "analyze":
		prompt = fmt.Sprintf(`You are an email security analyst. Analyze this email for threats.
Subject: %s
From: %s
Content excerpt: %s
Provide compact JSON: {"verdict":"clean|suspicious|malicious","confidence":90,"threat_type":"phishing|bec|malware|spam|clean","explanation":"one sentence","indicators":["key ioc"],"mitre_techniques":["T1566.001"],"recommended_actions":["action"]}`,
			body.Subject, body.Sender, body.Content)
	case "url":
		prompt = fmt.Sprintf(`Analyze this URL for phishing/malware: %s
Provide compact JSON: {"verdict":"clean|suspicious|malicious","confidence":85,"threat_type":"phishing|malware|clean","explanation":"one sentence","redirect_analysis":"brief","recommended_actions":["action"]}`,
			body.URL)
	case "attachment":
		prompt = fmt.Sprintf(`Analyze this file hash for threats: %s
Provide compact JSON: {"verdict":"clean|suspicious|malicious","confidence":80,"malware_family":"","explanation":"one sentence","behavior_summary":"brief","recommended_actions":["action"]}`,
			body.Hash)
	default:
		prompt = fmt.Sprintf(`Email security question: %s
Provide compact JSON: {"answer":"concise answer","confidence":85,"recommended_actions":["action"]}`,
			body.Content)
	}
	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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

// PostEmailReport — POST /api/email/report
func PostEmailReport(c *gin.Context) {
	createEmailSecurityTables()
	tid := tenantIDFromContext(c)
	var body struct {
		ReportType string `json:"report_type"`
	}
	c.ShouldBindJSON(&body)
	var total, phishing, malware, bec, blocked int
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND threat_type='phishing'`, tid).Scan(&phishing)
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND threat_type='malware'`, tid).Scan(&malware)
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND threat_type='bec'`, tid).Scan(&bec)
	database.DB.QueryRow(`SELECT COUNT(*) FROM email_messages WHERE tenant_id=$1 AND status IN ('blocked','quarantined')`, tid).Scan(&blocked)
	var prompt string
	switch body.ReportType {
	case "phishing":
		prompt = fmt.Sprintf(`Email security phishing report. %d phishing emails, %d blocked. Compact JSON: {"title":"Phishing Threat Report","executive_summary":"2 sentence summary","key_findings":["finding"],"top_techniques":["technique"],"recommendations":["recommendation"]}`, phishing, blocked)
	case "bec":
		prompt = fmt.Sprintf(`BEC (Business Email Compromise) report. %d BEC attempts. Compact JSON: {"title":"BEC Threat Report","executive_summary":"2 sentence summary","key_findings":["finding"],"financial_risk":"estimate","recommendations":["recommendation"]}`, bec)
	case "malware":
		prompt = fmt.Sprintf(`Email malware report. %d malware emails. Compact JSON: {"title":"Email Malware Report","executive_summary":"2 sentence summary","key_findings":["finding"],"malware_families":["family"],"recommendations":["recommendation"]}`, malware)
	case "user_risk":
		prompt = `User email risk report for security awareness training. Compact JSON: {"title":"User Risk Report","executive_summary":"2 sentence summary","key_findings":["finding"],"high_risk_behaviors":["behavior"],"training_recommendations":["recommendation"]}`
	default:
		prompt = fmt.Sprintf(`Executive email security report. Stats: %d processed, %d phishing, %d malware, %d BEC, %d blocked. Compact JSON: {"title":"Executive Email Security Report","executive_summary":"3 sentence summary","key_findings":["finding"],"risk_breakdown":{"phishing":%d,"malware":%d,"bec":%d},"top_recommendations":[{"priority":1,"action":"action","estimated_effort":"time"}],"metrics":{"total_processed":%d,"blocked":%d,"threats":%d}}`,
			total, phishing, malware, bec, blocked, phishing, malware, bec, total, blocked, phishing+malware+bec)
	}
	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
