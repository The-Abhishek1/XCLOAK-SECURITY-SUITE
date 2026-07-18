package services

// DGA (Domain Generation Algorithm) Detector
//
// Malware families (Conficker, Necurs, Mirai, Emotet, TrickBot, DarkComet,
// Locky, Ramnit, CryptoLocker, Nymaim…) use DGAs to generate thousands of
// candidate C2 domain names daily. Only the operator registers a few; the rest
// NXDOMAIN. Key signatures:
//
//   - Random-looking second-level domain (high character entropy, uncommon bigrams)
//   - Mixed digits and letters without vowel structure
//   - Unusual TLDs (.top, .xyz, .tk, .pw, .cc, .ws, .info for cheap registration)
//   - NXDOMAIN storm (rapid failed lookups = DGA rotation in progress)
//   - Newly registered domain contacted shortly after first agent boot
//
// This detector runs on two data paths:
//   1. Real-time: AnalyzeDNSLogEntry() integrates it into the log pipeline.
//   2. Scheduled: StartDGAScheduler() sweeps NCE + DNS logs every 30 min.

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// suspiciousTLDs are cheap/abused TLDs commonly registered by DGA operators.
var suspiciousTLDs = map[string]int{
	".top": 20, ".xyz": 15, ".tk": 20, ".pw": 20, ".cc": 15,
	".ws":  15, ".info": 10, ".biz": 10, ".gq": 20, ".ml": 20,
	".cf":  20, ".ga": 20, ".click": 10, ".link": 10, ".live": 10,
	".online": 10, ".site": 10, ".win": 15, ".men": 15, ".loan": 15,
	".download": 15, ".racing": 20, ".review": 15, ".bid": 15, ".trade": 15,
}

// dgaKnownPatterns are regex-like prefix/suffix patterns seen in specific DGA families.
// We keep them as simple string matchers to avoid the regex dependency.
type dgaPattern struct {
	family   string
	check    func(label string) bool
	severity string
}

var dgaFamilyPatterns = []dgaPattern{
	{
		family:   "Conficker",
		severity: "critical",
		check: func(l string) bool {
			if len(l) < 8 || len(l) > 16 { return false }
			digits := 0
			for _, c := range l { if c >= '0' && c <= '9' { digits++ } }
			return float64(digits)/float64(len(l)) < 0.1 && DGAScore(l) >= 65
		},
	},
	{
		family:   "Necurs",
		severity: "critical",
		check: func(l string) bool {
			return len(l) >= 12 && len(l) <= 22 && DGAScore(l) >= 70
		},
	},
	{
		family:   "Mirai-variant",
		severity: "high",
		check: func(l string) bool {
			return len(l) >= 8 && len(l) <= 12 && DGAScore(l) >= 60
		},
	},
}

// StartDGAScheduler runs domain entropy sweeps every 30 minutes.
func StartDGAScheduler() {
	go func() {
		time.Sleep(5 * time.Minute)
		runDGASweepAll()
		for {
			time.Sleep(30 * time.Minute)
			runDGASweepAll()
		}
	}()
}

func runDGASweepAll() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active=true`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			RunDGASweepForTenant(id)
		}
	}
}

// RunDGASweepForTenant sweeps NCE remote_address and SNI fields for the past
// hour and scores each unique domain using the multi-factor DGA model.
func RunDGASweepForTenant(tenantID int) {
	// Collect unique domains from SNI field and remote_address hostname hints.
	type domainHit struct {
		agentID int
		domain  string
	}
	hits := []domainHit{}

	// SNI field (populated after migration 000064)
	sniRows, err := database.DB.Query(`
		SELECT DISTINCT agent_id, sni
		FROM network_connect_events
		WHERE tenant_id = $1
		  AND created_at > NOW() - INTERVAL '1 hour'
		  AND sni != ''
		  AND sni NOT LIKE '%.google.com'
		  AND sni NOT LIKE '%.microsoft.com'
		  AND sni NOT LIKE '%.apple.com'
		  AND sni NOT LIKE '%.cloudflare.com'
		  AND sni NOT LIKE '%.akamai%'
		  AND sni NOT LIKE '%.amazonaws.com'
	`, tenantID)
	if err == nil {
		defer sniRows.Close()
		for sniRows.Next() {
			var agentID int
			var sni string
			if sniRows.Scan(&agentID, &sni) == nil && sni != "" {
				hits = append(hits, domainHit{agentID, strings.ToLower(sni)})
			}
		}
	}

	// Also check HTTP host fields
	hostRows, err := database.DB.Query(`
		SELECT DISTINCT agent_id, http_host
		FROM network_connect_events
		WHERE tenant_id = $1
		  AND created_at > NOW() - INTERVAL '1 hour'
		  AND http_host != ''
	`, tenantID)
	if err == nil {
		defer hostRows.Close()
		for hostRows.Next() {
			var agentID int
			var host string
			if hostRows.Scan(&agentID, &host) == nil && host != "" {
				hits = append(hits, domainHit{agentID, strings.ToLower(strings.TrimPrefix(host, "www."))})
			}
		}
	}

	for _, h := range hits {
		scoreDomain(h.agentID, tenantID, h.domain, "network_flow")
	}
}

// ScoreDomainDGA is the public entry point called from the DNS log pipeline.
// Returns the DGA score (0-100) and fires alerts/DPI findings if above threshold.
func ScoreDomainDGA(agentID, tenantID int, domain string) int {
	return scoreDomain(agentID, tenantID, domain, "dns_log")
}

func scoreDomain(agentID, tenantID int, domain, source string) int {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" || isKnownGoodDomain(domain) {
		return 0
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return 0
	}

	// The second-level domain label is the primary analysis target.
	// For "sub.evil.xyz" we analyse "evil"; for "abc123.com" we analyse "abc123".
	sld := parts[len(parts)-2]
	tld  := "." + parts[len(parts)-1]

	totalScore := 0
	indicators := []string{}

	// 1. Label-level DGA scoring
	dgaS := DGAScore(sld)
	if dgaS >= 45 {
		totalScore += dgaS / 2 // map 45-100 to 22-50 contribution
		indicators = append(indicators, fmt.Sprintf("dga_score=%d", dgaS))
	}

	// 2. Suspicious TLD
	if bonus, ok := suspiciousTLDs[tld]; ok {
		totalScore += bonus
		indicators = append(indicators, fmt.Sprintf("suspicious_tld=%s", tld))
	}

	// 3. IOC match (cross-check against existing blocklist)
	var iocCount int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM iocs
		WHERE tenant_id=$1 AND (indicator=$2 OR indicator=$3) AND ioc_type IN ('domain','fqdn','c2')
	`, tenantID, domain, strings.Join(parts[len(parts)-2:], ".")).Scan(&iocCount)
	if iocCount > 0 {
		totalScore += 40
		indicators = append(indicators, "ioc_match")
	}

	// 4. DGA family pattern recognition
	for _, p := range dgaFamilyPatterns {
		if p.check(sld) {
			totalScore += 25
			indicators = append(indicators, "family:"+p.family)
			break
		}
	}

	// 5. NXDOMAIN storm: many NCE failed connect attempts to this SLD in last 5min
	var nxCount int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM network_connect_events
		WHERE agent_id=$1 AND tenant_id=$2
		  AND (sni LIKE $3 OR http_host LIKE $3)
		  AND created_at > NOW() - INTERVAL '5 minutes'
	`, agentID, tenantID, "%."+sld+".%").Scan(&nxCount)
	if nxCount >= 8 {
		totalScore += 20
		indicators = append(indicators, fmt.Sprintf("nxdomain_storm=%d", nxCount))
	}

	if totalScore > 100 {
		totalScore = 100
	}
	if totalScore < 40 || len(indicators) == 0 {
		return totalScore
	}

	// Deduplicate: skip if same domain already flagged for this agent in past hour
	var existing int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM dpi_findings
		WHERE agent_id=$1 AND tenant_id=$2 AND finding_type='dga'
		  AND indicator=$3 AND detected_at > NOW() - INTERVAL '1 hour'
	`, agentID, tenantID, domain).Scan(&existing)
	if existing > 0 {
		return totalScore
	}

	desc := fmt.Sprintf("Possible DGA domain: %q (score=%d). Indicators: %s",
		domain, totalScore, strings.Join(indicators, ", "))

	ctx, _ := json.Marshal(map[string]interface{}{
		"domain":     domain,
		"sld":        sld,
		"tld":        tld,
		"dga_score":  dgaS,
		"indicators": indicators,
		"source":     source,
	})

	severity := "medium"
	if totalScore >= 75 || iocCount > 0 {
		severity = "high"
	}
	if totalScore >= 90 {
		severity = "critical"
	}

	alertFired := totalScore >= 60

	database.DB.Exec(`
		INSERT INTO dpi_findings
		  (agent_id, tenant_id, finding_type, severity, score, indicator,
		   description, mitre_technique, raw_context, alert_fired)
		VALUES ($1,$2,'dga',$3,$4,$5,$6,'T1568.002',$7,$8)
	`, agentID, tenantID, severity, totalScore, domain, desc, ctx, alertFired)

	if alertFired {
		log.Printf("[DGA] agent=%d domain=%q score=%d sev=%s", agentID, domain, totalScore, severity)
		alert := models.Alert{
			AgentID:        agentID,
			TenantID:       tenantID,
			RuleName:       "DGA Domain Detected",
			Severity:       severity,
			LogMessage:     desc,
			MitreTechnique: "T1568.002",
			Fingerprint:    fmt.Sprintf("%d-dga-%s", agentID, domain),
		}
		CreateAlert(alert) //nolint:errcheck
	}

	return totalScore
}

// isKnownGoodDomain returns true for Alexa-style top-level domains to avoid
// false positives on short random-looking labels in legitimate CDN hostnames.
func isKnownGoodDomain(domain string) bool {
	goodSuffixes := []string{
		"google.com", "googleapis.com", "gstatic.com",
		"microsoft.com", "windows.com", "azure.com", "msftncsi.com",
		"apple.com", "icloud.com", "aaplimg.com",
		"cloudflare.com", "cloudflare.net", "cloudfront.net",
		"amazonaws.com", "awsstatic.com", "aws.amazon.com",
		"akamai.net", "akamaiedge.net", "akamaitechnologies.com",
		"fastly.net", "fastlylb.net",
		"facebook.com", "fbcdn.net", "instagram.com",
		"twitter.com", "twimg.com",
		"youtube.com", "ytimg.com", "googlevideo.com",
		"netflix.com", "nflxvideo.net",
		"github.com", "githubusercontent.com",
		"slack.com", "slackb.com",
		"zoom.us", "zoomgov.com",
		"dropbox.com", "dropboxapi.com",
		"office.com", "office365.com", "sharepoint.com", "skype.com",
	}
	for _, suffix := range goodSuffixes {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}
	return false
}
