package services

// Data Exfiltration Detector
//
// Detection signals (all tenant-scoped, sliding windows):
//
//   1. Volume flood (1h)  — single agent sends >100 MB to one external IP.
//      Fires "high". Escalates to "critical" at >500 MB.
//
//   2. Session burst (10m) — >50 MB to one external IP in 10 minutes.
//      Rapid exfil pattern (ransomware upload, insider dump).
//
//   3. Cloud-storage drain (1h) — >50 MB to known cloud-storage domains
//      (S3, GDrive, OneDrive, Dropbox, Box, Mega). Lower threshold because
//      employees rarely bulk-upload during an incident window.
//
//   4. Off-hours transfer (1h, 22:00–06:00 local) — >25 MB to any external
//      IP. Unusual for production workloads and common in slow-leak attacks.
//
// Byte source priority:
//   a. endpoint_logs.parsed_fields->>'bytes_sent'   (CEF out=, LEEF bytesOut=, JSON bytes_sent)
//   b. network_connect_events.bytes_sent            (eBPF-reported, after migration 000036)
//   c. Regex fallback on endpoint_logs.log_message  (\bbytes[=:]\s*(\d+))

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

const (
	exfilThresholdHigh     = 100 * 1024 * 1024  // 100 MB
	exfilThresholdCritical = 500 * 1024 * 1024  // 500 MB
	exfilBurst10m          = 50 * 1024 * 1024   // 50 MB in 10 min
	exfilCloudThreshold    = 50 * 1024 * 1024   // 50 MB to cloud storage
	exfilOffHours          = 25 * 1024 * 1024   // 25 MB off-hours
)

var (
	cloudStorageDomains = []string{
		"s3.amazonaws.com", "s3-", ".s3.",
		"drive.google.com", "docs.google.com",
		"onedrive.live.com", "sharepoint.com",
		"dropbox.com", "dropboxapi.com",
		"box.com", "boxcdn.net",
		"mega.nz", "mega.io",
		"wetransfer.com", "we.tl",
		"gofile.io", "transfer.sh",
	}

	// Regex to extract bytes from raw log messages as fallback.
	// Matches: bytes=12345  bytes:12345  out=12345  sentbytes=12345
	logBytesRE = regexp.MustCompile(`(?i)\b(?:bytes[_-]?(?:sent|out)?|out)\s*[=:]\s*(\d+)`)
)

// StartExfilScheduler runs exfil detection every 10 minutes.
func StartExfilScheduler() {
	go func() {
		time.Sleep(3 * time.Minute)
		runExfilAll()
		for {
			time.Sleep(10 * time.Minute)
			runExfilAll()
		}
	}()
}

func runExfilAll() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = true`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			DetectExfilForTenant(id)
		}
	}
}

// DetectExfilForTenant runs all exfil heuristics for one tenant.
func DetectExfilForTenant(tenantID int) {
	detectVolumeFlood(tenantID, "1 hour",   exfilThresholdHigh,     exfilThresholdCritical)
	detectVolumeFlood(tenantID, "10 minutes", exfilBurst10m,         exfilBurst10m*2)
	detectCloudStorage(tenantID)
	detectOffHoursTransfer(tenantID)
	DetectDLPForTenant(tenantID)
}

// detectVolumeFlood finds agents sending large byte volumes to a single
// external IP within the given window. Uses bytes from parsed_fields first,
// falls back to NCE bytes_sent, then regex on log_message.
func detectVolumeFlood(tenantID int, window string, threshHigh, threshCrit int64) {
	// Query 1: parsed_fields-based bytes (CEF/LEEF/JSON logs)
	type row struct {
		agentID  int
		dstIP    string
		bytesSent int64
	}

	var candidates []row

	logRows, err := database.DB.Query(fmt.Sprintf(`
		SELECT el.agent_id,
		       el.parsed_fields->>'dst_ip'               AS dst_ip,
		       SUM((el.parsed_fields->>'bytes_sent')::bigint) AS total_bytes
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id
		WHERE a.tenant_id = $1
		  AND el.collected_at > NOW() - INTERVAL '%s'
		  AND el.parsed_fields->>'bytes_sent' IS NOT NULL
		  AND el.parsed_fields->>'dst_ip'     IS NOT NULL
		GROUP BY el.agent_id, dst_ip
		HAVING SUM((el.parsed_fields->>'bytes_sent')::bigint) > $2
		ORDER BY total_bytes DESC
	`, window), tenantID, threshHigh)
	if err == nil {
		defer logRows.Close()
		for logRows.Next() {
			var r row
			if logRows.Scan(&r.agentID, &r.dstIP, &r.bytesSent) == nil && !isPrivateIP(r.dstIP) {
				candidates = append(candidates, r)
			}
		}
	}

	// Query 2: NCE bytes_sent (eBPF-reported, available after migration 000036)
	nceRows, err := database.DB.Query(fmt.Sprintf(`
		SELECT agent_id,
		       split_part(remote_address, ':', 1) AS dst_ip,
		       SUM(bytes_sent)                    AS total_bytes
		FROM network_connect_events
		WHERE tenant_id  = $1
		  AND created_at > NOW() - INTERVAL '%s'
		  AND bytes_sent > 0
		GROUP BY agent_id, dst_ip
		HAVING SUM(bytes_sent) > $2
		ORDER BY total_bytes DESC
	`, window), tenantID, threshHigh)
	if err == nil {
		defer nceRows.Close()
		for nceRows.Next() {
			var r row
			if nceRows.Scan(&r.agentID, &r.dstIP, &r.bytesSent) == nil && !isPrivateIP(r.dstIP) {
				candidates = append(candidates, r)
			}
		}
	}

	// Dedup by (agentID, dstIP) — take highest bytes across both sources
	seen := map[string]row{}
	for _, c := range candidates {
		k := fmt.Sprintf("%d:%s", c.agentID, c.dstIP)
		if existing, ok := seen[k]; !ok || c.bytesSent > existing.bytesSent {
			seen[k] = c
		}
	}

	for _, c := range seen {
		sev := "high"
		if c.bytesSent >= threshCrit {
			sev = "critical"
		}
		desc := fmt.Sprintf(
			"Data exfiltration: %.1f MB sent to %s in the last %s",
			float64(c.bytesSent)/(1024*1024), c.dstIP, window,
		)
		dedupKey := fmt.Sprintf("%d-exfil-%s", c.agentID, c.dstIP)
		if !recordExfilAnomaly(c.agentID, tenantID, "volume_flood", c.dstIP, c.bytesSent, sev, desc, window) {
			continue
		}
		log.Printf("[Exfil] volume flood agent=%d dst=%s bytes=%.1fMB sev=%s",
			c.agentID, c.dstIP, float64(c.bytesSent)/(1024*1024), sev)
		fireExfilAlert(c.agentID, tenantID, "Data Exfiltration Detected", sev, "T1048", desc, dedupKey)
	}
}

// detectCloudStorage flags large transfers to known cloud-storage endpoints.
func detectCloudStorage(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'dst_ip'               AS dst_ip,
		       el.log_message,
		       SUM((el.parsed_fields->>'bytes_sent')::bigint) AS total_bytes
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id
		WHERE a.tenant_id = $1
		  AND el.collected_at > NOW() - INTERVAL '1 hour'
		  AND el.parsed_fields->>'bytes_sent' IS NOT NULL
		GROUP BY el.agent_id, dst_ip, el.log_message
		HAVING SUM((el.parsed_fields->>'bytes_sent')::bigint) > $2
	`, tenantID, exfilCloudThreshold)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var dstIP, logMsg string
		var totalBytes int64
		if rows.Scan(&agentID, &dstIP, &logMsg, &totalBytes) != nil {
			continue
		}

		if !isCloudStorageDomain(logMsg, dstIP) {
			continue
		}

		desc := fmt.Sprintf(
			"Cloud-storage exfiltration: %.1f MB uploaded to cloud storage endpoint (%s) in 1 hour",
			float64(totalBytes)/(1024*1024), dstIP,
		)
		dedupKey := fmt.Sprintf("%d-cloud-exfil-%s", agentID, dstIP)
		if !recordExfilAnomaly(agentID, tenantID, "cloud_storage_drain", dstIP, totalBytes, "high", desc, "1 hour") {
			continue
		}
		log.Printf("[Exfil] cloud storage agent=%d dst=%s bytes=%.1fMB", agentID, dstIP, float64(totalBytes)/(1024*1024))
		fireExfilAlert(agentID, tenantID, "Cloud Storage Exfiltration", "high", "T1567.002", desc, dedupKey)
	}
}

// detectOffHoursTransfer flags significant outbound transfers during off-hours
// (22:00–06:00 UTC). Large night-time transfers are common in slow-leak attacks.
func detectOffHoursTransfer(tenantID int) {
	now := time.Now().UTC()
	hour := now.Hour()
	if hour >= 6 && hour < 22 {
		return // business hours — skip
	}

	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'dst_ip'               AS dst_ip,
		       SUM((el.parsed_fields->>'bytes_sent')::bigint) AS total_bytes
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id
		WHERE a.tenant_id = $1
		  AND el.collected_at > NOW() - INTERVAL '1 hour'
		  AND el.parsed_fields->>'bytes_sent' IS NOT NULL
		  AND el.parsed_fields->>'dst_ip'     IS NOT NULL
		GROUP BY el.agent_id, dst_ip
		HAVING SUM((el.parsed_fields->>'bytes_sent')::bigint) > $2
	`, tenantID, exfilOffHours)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var dstIP string
		var totalBytes int64
		if rows.Scan(&agentID, &dstIP, &totalBytes) != nil || isPrivateIP(dstIP) {
			continue
		}

		desc := fmt.Sprintf(
			"Off-hours data transfer: %.1f MB sent to %s at %s UTC (outside business hours)",
			float64(totalBytes)/(1024*1024), dstIP, now.Format("15:04"),
		)
		dedupKey := fmt.Sprintf("%d-offhours-%s", agentID, dstIP)
		if !recordExfilAnomaly(agentID, tenantID, "off_hours_transfer", dstIP, totalBytes, "medium", desc, "1 hour") {
			continue
		}
		log.Printf("[Exfil] off-hours agent=%d dst=%s bytes=%.1fMB", agentID, dstIP, float64(totalBytes)/(1024*1024))
		fireExfilAlert(agentID, tenantID, "Off-Hours Data Transfer", "medium", "T1048.003", desc, dedupKey)
	}
}

// ExtractBytesFromLogMessage is a regex fallback for log sources that embed
// byte counts in the raw message but aren't CEF/LEEF/JSON.
// Called from detection service if parsed_fields has no bytes.
func ExtractBytesFromLogMessage(msg string) int64 {
	m := logBytesRE.FindStringSubmatch(msg)
	if len(m) < 2 {
		return 0
	}
	n, _ := strconv.ParseInt(m[1], 10, 64)
	return n
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func isCloudStorageDomain(logMsg, dstIP string) bool {
	combined := strings.ToLower(logMsg + " " + dstIP)
	for _, d := range cloudStorageDomains {
		if strings.Contains(combined, d) {
			return true
		}
	}
	return false
}

func recordExfilAnomaly(agentID, tenantID int, anomalyType, dstIP string, bytesSent int64, severity, desc, dedupWindow string) bool {
	var existing int
	database.DB.QueryRow(fmt.Sprintf(`
		SELECT COUNT(*) FROM network_anomalies
		WHERE agent_id=$1 AND anomaly_type=$2 AND dst_ip=$3
		  AND detected_at > NOW() - INTERVAL '%s'
	`, dedupWindow), agentID, anomalyType, dstIP).Scan(&existing)
	if existing > 0 {
		return false
	}

	database.DB.Exec(`
		INSERT INTO network_anomalies
		  (agent_id, tenant_id, anomaly_type, dst_ip, dst_port, proto, deviation_score, description)
		VALUES ($1,$2,$3,$4,0,'tcp',$5,$6)
	`, agentID, tenantID, anomalyType, dstIP,
		int(min64(100, bytesSent/(1024*1024))), desc)
	return true
}

func fireExfilAlert(agentID, tenantID int, ruleName, severity, technique, desc, fingerprint string) {
	alert := models.Alert{
		AgentID:        agentID,
		TenantID:       tenantID,
		RuleName:       ruleName,
		Severity:       severity,
		LogMessage:     desc,
		MitreTechnique: technique,
		Fingerprint:    fingerprint,
	}
	CreateAlert(alert) //nolint:errcheck
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
