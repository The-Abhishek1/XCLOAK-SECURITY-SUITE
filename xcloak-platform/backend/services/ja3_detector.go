package services

// TLS/JA3 Fingerprint Detector
//
// Detects C2 and malware traffic by matching TLS ClientHello fingerprints
// (JA3 hashes) against a blocklist of known-malicious fingerprints.
//
// JA3 is an MD5 of fields extracted from the TLS ClientHello:
//   SSLVersion, Ciphers, Extensions, EllipticCurves, EllipticCurvePointFormats
//
// Hash sources extracted from logs:
//   • Zeek/Bro:       ja3=<hash>  ja3s=<hash>
//   • Suricata:       JSON  {"ja3": {"hash": "..."}}
//   • Palo Alto NGFW: ja3hash=<hash>  in traffic/threat logs
//   • Fortinet:       ja3hash= field in UTM logs
//   • ParsedFields:   ja3_hash / ja3s_hash (set by log_normalizer)
//
// Runs every 5 minutes. Checks endpoint_logs collected in the past 10 minutes
// to keep alert latency low without hammering the DB.

import (
	"fmt"
	"log"
	"strings"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// StartJA3Scheduler runs TLS fingerprint detection every 5 minutes.
func StartJA3Scheduler() {
	go func() {
		time.Sleep(90 * time.Second)
		runJA3All()
		for {
			time.Sleep(5 * time.Minute)
			runJA3All()
		}
	}()
}

func runJA3All() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = true`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			DetectJA3ForTenant(id)
		}
	}
}

// DetectJA3ForTenant checks recent logs for JA3 hashes matching the blocklist.
func DetectJA3ForTenant(tenantID int) {
	// Pull JA3 hashes from parsed_fields (set by normalizer for CEF/JSON/LEEF).
	// Also regex-extract from raw log_message for Zeek/Palo Alto text logs.
	type hit struct {
		agentID    int
		ja3Hash    string
		logMessage string
	}

	hits := []hit{}

	// Query 1: parsed_fields->>'ja3_hash'
	pfRows, err := database.DB.Query(`
		SELECT el.agent_id, el.parsed_fields->>'ja3_hash' AS ja3, el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id
		WHERE a.tenant_id = $1
		  AND el.collected_at > NOW() - INTERVAL '10 minutes'
		  AND el.parsed_fields->>'ja3_hash' IS NOT NULL
		  AND el.parsed_fields->>'ja3_hash' != ''
	`, tenantID)
	if err == nil {
		defer pfRows.Close()
		for pfRows.Next() {
			var h hit
			if pfRows.Scan(&h.agentID, &h.ja3Hash, &h.logMessage) == nil {
				hits = append(hits, h)
			}
		}
	}

	// Query 2: Regex extraction from raw log_message (Zeek text, Palo Alto syslog).
	rawRows, err := database.DB.Query(`
		SELECT el.agent_id, el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id
		WHERE a.tenant_id = $1
		  AND el.collected_at > NOW() - INTERVAL '10 minutes'
		  AND (el.parsed_fields->>'ja3_hash' IS NULL OR el.parsed_fields->>'ja3_hash' = '')
		  AND el.log_message ~* 'ja3s?(?:hash)?[=:]'
	`, tenantID)
	if err == nil {
		defer rawRows.Close()
		for rawRows.Next() {
			var agentID int
			var logMsg string
			if rawRows.Scan(&agentID, &logMsg) == nil {
				if h := ExtractJA3FromMessage(logMsg); h != "" {
					hits = append(hits, hit{agentID: agentID, ja3Hash: h, logMessage: logMsg})
				}
			}
		}
	}

	if len(hits) == 0 {
		return
	}

	// Deduplicate by (agentID, hash) to avoid flooding the blocklist query.
	seen := map[string]bool{}
	unique := hits[:0]
	for _, h := range hits {
		k := fmt.Sprintf("%d:%s", h.agentID, h.ja3Hash)
		if !seen[k] {
			seen[k] = true
			unique = append(unique, h)
		}
	}

	for _, h := range unique {
		matchJA3Blocklist(h.agentID, tenantID, h.ja3Hash, h.logMessage)
	}
}

// matchJA3Blocklist checks a single hash against platform-wide + tenant rules.
func matchJA3Blocklist(agentID, tenantID int, hash, logMessage string) {
	var threatName, severity, description string
	err := database.DB.QueryRow(`
		SELECT threat_name, severity, COALESCE(description,'')
		FROM ja3_fingerprints
		WHERE hash = $1
		  AND enabled = TRUE
		  AND (tenant_id = $2 OR tenant_id IS NULL)
		ORDER BY tenant_id DESC NULLS LAST  -- tenant-specific rows take precedence
		LIMIT 1
	`, strings.ToLower(hash), tenantID).Scan(&threatName, &severity, &description)
	if err != nil {
		return // no match
	}

	fingerprint := fmt.Sprintf("%d-ja3-%s", agentID, hash)
	desc := fmt.Sprintf(
		"Malicious TLS fingerprint detected: %s (JA3: %s). %s",
		threatName, hash, description,
	)

	// Dedup: don't re-fire the same JA3 alert for the same agent within 1 hour.
	var existing int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM alerts
		WHERE agent_id = $1 AND fingerprint = $2
		  AND created_at > NOW() - INTERVAL '1 hour'
	`, agentID, fingerprint).Scan(&existing)
	if existing > 0 {
		return
	}

	log.Printf("[JA3] match agent=%d hash=%s threat=%s sev=%s", agentID, hash, threatName, severity)

	alert := models.Alert{
		AgentID:        agentID,
		TenantID:       tenantID,
		RuleName:       fmt.Sprintf("Malicious TLS Fingerprint: %s", threatName),
		Severity:       severity,
		LogMessage:     desc,
		MitreTechnique: "T1071.001",
		Fingerprint:    fingerprint,
	}
	CreateAlert(alert) //nolint:errcheck
}
