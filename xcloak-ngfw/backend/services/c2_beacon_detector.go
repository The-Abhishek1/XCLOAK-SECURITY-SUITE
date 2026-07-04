package services

// C2 Beacon Detector — identifies command-and-control callback patterns in
// network connection events using statistical interval analysis.
//
// A beacon is a periodic outbound connection from malware to its C2 server.
// Key characteristics:
//   - Highly regular intervals (low coefficient of variation)
//   - External destination (not private RFC-1918 space)
//   - Consistent process name across connections
//   - Often short-lived sessions
//
// The detector scores each (agent, process, remote_addr) tuple across a 24h
// window and writes high-confidence hits to network_anomalies, firing an alert
// for scores >= 80.

import (
	"fmt"
	"log"
	"math"
	"net"
	"sort"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// StartBeaconScheduler runs C2 beacon analysis every hour across all tenants.
func StartBeaconScheduler() {
	go func() {
		// Initial run shortly after startup (give agents time to send events)
		time.Sleep(3 * time.Minute)
		runBeaconAnalysisAll()

		for {
			time.Sleep(1 * time.Hour)
			runBeaconAnalysisAll()
		}
	}()
}

// RunBeaconAnalysisForTenant runs immediately for a single tenant. Exposed so
// the scheduler and any on-demand trigger can share the same logic.
func RunBeaconAnalysisForTenant(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT agent_id, tenant_id, COALESCE(comm,''), remote_address,
		       array_agg(EXTRACT(EPOCH FROM created_at)::bigint ORDER BY created_at)
		FROM network_connect_events
		WHERE tenant_id = $1
		  AND created_at > NOW() - INTERVAL '24 hours'
		  AND remote_address != ''
		  AND state != 'closed'
		GROUP BY agent_id, tenant_id, comm, remote_address
		HAVING COUNT(*) >= 5
	`, tenantID)
	if err != nil {
		log.Printf("[Beacon] query error tenant %d: %v", tenantID, err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID, tid int
		var comm, remoteAddr string
		var tsList []int64

		if err := rows.Scan(&agentID, &tid, &comm, &remoteAddr, &tsList); err != nil {
			continue
		}

		dstIP, dstPort := splitAddr(remoteAddr)
		if dstIP == "" {
			continue
		}

		// Skip private/loopback — internal traffic is expected periodic
		if isPrivateIP(dstIP) {
			continue
		}

		// Skip known benign processes
		if isBenignProcess(comm) {
			continue
		}

		score, tags := scoreBeacon(tsList, dstIP, dstPort, comm, agentID, tenantID)
		if score < 50 {
			continue
		}

		meanSec := meanInterval(tsList)
		desc := fmt.Sprintf(
			"[C2 Beacon] %s → %s every ~%.0fs (score %d). Tags: %s",
			comm, remoteAddr, meanSec, score, strings.Join(tags, ", "),
		)

		// Deduplicate: skip if already flagged in last 6h
		var existing int
		database.DB.QueryRow(`
			SELECT COUNT(*) FROM network_anomalies
			WHERE agent_id=$1 AND dst_ip=$2 AND dst_port=$3
			  AND anomaly_type='c2_beacon'
			  AND detected_at > NOW() - INTERVAL '6 hours'
		`, agentID, dstIP, dstPort).Scan(&existing)
		if existing > 0 {
			continue
		}

		database.DB.Exec(`
			INSERT INTO network_anomalies
			  (agent_id, tenant_id, anomaly_type, dst_ip, dst_port, proto,
			   deviation_score, description)
			VALUES ($1,$2,'c2_beacon',$3,$4,'tcp',$5,$6)
		`, agentID, tenantID, dstIP, dstPort, score, desc)

		log.Printf("[Beacon] agent=%d %s → %s score=%d", agentID, comm, remoteAddr, score)

		// Fire alert for high-confidence beacons
		if score >= 75 {
			fireBeaconAlert(agentID, tenantID, remoteAddr, comm, score, desc)
		}
	}
}

// ── Scoring ──────────────────────────────────────────────────────────────────

func scoreBeacon(tsList []int64, dstIP string, dstPort int, comm string, agentID, tenantID int) (int, []string) {
	if len(tsList) < 5 {
		return 0, nil
	}

	intervals := computeIntervals(tsList)
	if len(intervals) < 4 {
		return 0, nil
	}

	mean := meanF(intervals)
	if mean < 5 {
		// Sub-5-second interval is normal OS-level activity
		return 0, nil
	}

	cv := coefficientOfVariation(intervals)

	score := 0
	var tags []string

	// CV thresholds — the lower the CV, the more clockwork-regular the beacon
	switch {
	case cv < 0.10:
		score += 55
		tags = append(tags, fmt.Sprintf("very_regular(CV=%.2f)", cv))
	case cv < 0.20:
		score += 40
		tags = append(tags, fmt.Sprintf("regular(CV=%.2f)", cv))
	case cv < 0.35:
		score += 20
		tags = append(tags, fmt.Sprintf("somewhat_regular(CV=%.2f)", cv))
	default:
		// Irregular — not a beacon
		return 0, nil
	}

	// Frequent check-ins (< 10 min) are more suspicious
	if mean < 600 {
		score += 15
		tags = append(tags, "high_frequency")
	} else if mean < 3600 {
		score += 8
		tags = append(tags, "hourly")
	}

	// Known-bad ports bump score
	if isSuspiciousPort(dstPort) {
		score += 10
		tags = append(tags, fmt.Sprintf("suspicious_port(%d)", dstPort))
	}

	// IOC match adds significant weight
	var iocMatch int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM iocs
		WHERE tenant_id=$1 AND indicator=$2 AND (ioc_type='ip' OR ioc_type='c2')
	`, tenantID, dstIP).Scan(&iocMatch)
	if iocMatch > 0 {
		score += 30
		tags = append(tags, "ioc_match")
	}

	// Proxy IPs are common C2 infrastructure (geoip_cache.is_proxy is populated)
	var isProxy bool
	database.DB.QueryRow(`SELECT is_proxy FROM geoip_cache WHERE ip=$1`, dstIP).Scan(&isProxy)
	if isProxy {
		score += 10
		tags = append(tags, "proxy_ip")
	}

	if score > 100 {
		score = 100
	}
	return score, tags
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func computeIntervals(tsList []int64) []float64 {
	if len(tsList) < 2 {
		return nil
	}
	sorted := make([]int64, len(tsList))
	copy(sorted, tsList)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	intervals := make([]float64, 0, len(sorted)-1)
	for i := 1; i < len(sorted); i++ {
		d := float64(sorted[i] - sorted[i-1])
		if d > 0 {
			intervals = append(intervals, d)
		}
	}
	return intervals
}

func meanF(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

func meanInterval(tsList []int64) float64 {
	return meanF(computeIntervals(tsList))
}

func stddevF(vals []float64) float64 {
	if len(vals) < 2 {
		return 0
	}
	m := meanF(vals)
	var sum float64
	for _, v := range vals {
		d := v - m
		sum += d * d
	}
	return math.Sqrt(sum / float64(len(vals)-1))
}

func coefficientOfVariation(vals []float64) float64 {
	m := meanF(vals)
	if m == 0 {
		return 999
	}
	return stddevF(vals) / m
}

func splitAddr(addr string) (ip string, port int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0
	}
	var p int
	fmt.Sscanf(portStr, "%d", &p)
	return host, p
}

// isBenignProcess returns true for system processes known to poll periodically
// but are not malicious — avoids flood of false positives.
func isBenignProcess(comm string) bool {
	comm = strings.ToLower(strings.TrimSpace(comm))
	benign := []string{
		"ntpd", "chrony", "chronyd", "systemd-timesyncd", "timesync",
		"packagekitd", "apt", "yum", "dnf", "unattended-upgrades",
		"update-notifier", "snapd", "steam", "spotify",
		"collectd", "prometheus", "node_exporter", "telegraf",
		"zabbix", "zabbix_agent", "ossec",
		"sshd",   // keepalives
		"crond", "cron", // scheduled tasks
	}
	for _, b := range benign {
		if comm == b || strings.HasPrefix(comm, b) {
			return true
		}
	}
	return false
}

// isSuspiciousPort flags ports commonly abused by C2 frameworks.
func isSuspiciousPort(port int) bool {
	suspicious := map[int]bool{
		4444: true, 4445: true, 8888: true, 8443: true,
		1337: true, 31337: true, 6666: true, 6667: true,
		9001: true, 9002: true, // Tor
		2222: true, 2323: true, // alt SSH
	}
	return suspicious[port]
}

func runBeaconAnalysisAll() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = true`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			RunBeaconAnalysisForTenant(id)
		}
	}
}

func fireBeaconAlert(agentID, tenantID int, remoteAddr, comm string, score int, desc string) {
	severity := "medium"
	if score >= 85 {
		severity = "high"
	}

	alert := models.Alert{
		AgentID:        agentID,
		TenantID:       tenantID,
		RuleName:       "C2 Beacon Detected",
		Severity:       severity,
		LogMessage:     desc,
		MitreTechnique: "T1071", // Application Layer Protocol (C2)
		Fingerprint:    fmt.Sprintf("%d-c2beacon-%s-%s", agentID, comm, remoteAddr),
	}
	CreateAlert(alert) //nolint:errcheck
}
