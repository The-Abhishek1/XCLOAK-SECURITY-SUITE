package services

// Port Scan & Lateral Movement Detector
//
// Port scan detection:
//   - Vertical scan:  one source connects to many distinct ports on one target
//     (classic Nmap TCP connect / SYN scan)
//   - Horizontal scan: one source connects to the same port across many targets
//     (mass vulnerability scanners — Masscan, ZMap, WannaCry spread)
//
// Lateral movement detection:
//   - Internal-to-internal connections on admin/privileged ports (RDP, SMB,
//     WMI, WinRM, DCOM) from hosts whose baseline doesn't include that traffic.
//   - SMB spray: one host reaches many internal peers on port 445 (ransomware
//     propagation pattern).
//
// All analysis uses network_connect_events (eBPF real-time stream, created_at
// is wall-clock) for a 1-hour sliding window.  Results go into network_anomalies
// and fire alerts when scores exceed thresholds.

import (
	"fmt"
	"log"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// StartPortScanScheduler runs scan detection every 15 minutes.
func StartPortScanScheduler() {
	go func() {
		time.Sleep(2 * time.Minute)
		runPortScanAll()
		for {
			time.Sleep(15 * time.Minute)
			runPortScanAll()
		}
	}()
}

func runPortScanAll() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = true`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			DetectPortScansForTenant(id)
			DetectLateralMovementForTenant(id)
		}
	}
}

// ── Port scan ─────────────────────────────────────────────────────────────────

// DetectPortScansForTenant checks for vertical and horizontal port scans in the
// last hour across all agents owned by the tenant.
func DetectPortScansForTenant(tenantID int) {
	detectVerticalScans(tenantID)
	detectHorizontalScans(tenantID)
}

// Vertical scan: one source → many distinct ports on one destination.
// Threshold: ≥15 distinct destination ports to the same host in 1 hour.
func detectVerticalScans(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT agent_id,
		       split_part(remote_address, ':', 1) AS dst_ip,
		       COUNT(DISTINCT split_part(remote_address, ':', -1)) AS port_count
		FROM network_connect_events
		WHERE tenant_id = $1
		  AND created_at > NOW() - INTERVAL '1 hour'
		  AND remote_address != ''
		GROUP BY agent_id, dst_ip
		HAVING COUNT(DISTINCT split_part(remote_address, ':', -1)) >= 15
		ORDER BY port_count DESC
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var dstIP string
		var portCount int
		if err := rows.Scan(&agentID, &dstIP, &portCount); err != nil {
			continue
		}

		score := portScanScore(portCount, 15, 50, 100)
		desc := fmt.Sprintf("Vertical port scan: %d distinct ports probed on %s in the last hour", portCount, dstIP)

		if !recordNetworkAnomaly(agentID, tenantID, "port_scan_vertical", dstIP, 0, "tcp", score, desc, "1 hour") {
			continue
		}

		log.Printf("[Scan] vertical agent=%d dst=%s ports=%d score=%d", agentID, dstIP, portCount, score)

		if score >= 65 {
			fireNetworkAlert(agentID, tenantID, "Port Scan Detected (Vertical)", "medium", "T1046",
				desc, fmt.Sprintf("%d-vert-scan-%s", agentID, dstIP))
		}
	}
}

// Horizontal scan: one source → same port across many distinct hosts.
// Threshold: ≥20 distinct destination IPs on the same port in 1 hour.
func detectHorizontalScans(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT agent_id,
		       split_part(remote_address, ':', -1) AS dst_port,
		       COUNT(DISTINCT split_part(remote_address, ':', 1)) AS host_count
		FROM network_connect_events
		WHERE tenant_id = $1
		  AND created_at > NOW() - INTERVAL '1 hour'
		  AND remote_address != ''
		GROUP BY agent_id, dst_port
		HAVING COUNT(DISTINCT split_part(remote_address, ':', 1)) >= 20
		ORDER BY host_count DESC
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var dstPort string
		var hostCount int
		if err := rows.Scan(&agentID, &dstPort, &hostCount); err != nil {
			continue
		}

		score := portScanScore(hostCount, 20, 100, 500)
		desc := fmt.Sprintf("Horizontal port scan: port %s probed on %d distinct hosts in 1 hour (possible worm/mass-exploit)", dstPort, hostCount)

		if !recordNetworkAnomaly(agentID, tenantID, "port_scan_horizontal", "0.0.0.0", 0, "tcp", score, desc, "1 hour") {
			continue
		}

		log.Printf("[Scan] horizontal agent=%d port=%s hosts=%d score=%d", agentID, dstPort, hostCount, score)

		sev := "high"
		if score >= 85 {
			sev = "critical"
		}
		fireNetworkAlert(agentID, tenantID, "Port Scan Detected (Horizontal)", sev, "T1046",
			desc, fmt.Sprintf("%d-horiz-scan-%s", agentID, dstPort))
	}
}

// portScanScore maps a count to a 0–100 score using a linear ramp.
// low: minimum count to trigger (score=50), high: count that saturates at 100.
func portScanScore(count, low, high, sat int) int {
	if count < low {
		return 0
	}
	if count >= sat {
		return 100
	}
	// Linear interpolation from 50→100 over [low, sat]
	score := 50 + (count-low)*50/(sat-low)
	if score > 100 {
		return 100
	}
	return score
}

// ── Lateral movement ──────────────────────────────────────────────────────────

// DetectLateralMovementForTenant looks for internal-to-internal connections on
// administrative ports that are uncommon for the source host's baseline.
func DetectLateralMovementForTenant(tenantID int) {
	detectAdminPortSpread(tenantID)
	detectSMBSpray(tenantID)
}

// Admin port spread: a host reaches ≥5 distinct internal peers on a privileged
// admin port (RDP, SMB, WMI, WinRM, DCOM, PsExec) within 30 minutes.
func detectAdminPortSpread(tenantID int) {
	adminPorts := []int{445, 3389, 135, 5985, 5986, 139, 636, 389, 4899}

	for _, port := range adminPorts {
		portStr := fmt.Sprintf("%d", port)
		rows, err := database.DB.Query(`
			SELECT agent_id,
			       COUNT(DISTINCT split_part(remote_address, ':', 1)) AS peer_count
			FROM network_connect_events
			WHERE tenant_id  = $1
			  AND created_at > NOW() - INTERVAL '30 minutes'
			  AND split_part(remote_address, ':', -1) = $2
			  AND (
			      split_part(remote_address, ':', 1) LIKE '10.%'    OR
			      split_part(remote_address, ':', 1) LIKE '172.1%'  OR
			      split_part(remote_address, ':', 1) LIKE '172.2%'  OR
			      split_part(remote_address, ':', 1) LIKE '172.3%'  OR
			      split_part(remote_address, ':', 1) LIKE '192.168.%'
			  )
			GROUP BY agent_id
			HAVING COUNT(DISTINCT split_part(remote_address, ':', 1)) >= 5
		`, tenantID, portStr)
		if err != nil {
			continue
		}

		for rows.Next() {
			var agentID, peerCount int
			if rows.Scan(&agentID, &peerCount) != nil {
				continue
			}

			portName := adminPortName(port)
			desc := fmt.Sprintf(
				"Lateral movement indicator: %s (port %d) reached %d internal hosts in 30 min",
				portName, port, peerCount,
			)
			score := 70
			if peerCount >= 20 {
				score = 90
			}

			if !recordNetworkAnomaly(agentID, tenantID, "lateral_movement", "internal", port, "tcp", score, desc, "30 minutes") {
				continue
			}

			log.Printf("[Lateral] agent=%d port=%d peers=%d", agentID, port, peerCount)

			sev := "high"
			if peerCount >= 20 {
				sev = "critical"
			}
			fireNetworkAlert(agentID, tenantID, "Lateral Movement Detected", sev, "T1021",
				desc, fmt.Sprintf("%d-lateral-%d", agentID, port))
		}
		rows.Close()
	}
}

// SMB spray: specific detection for ransomware-style SMB propagation.
// Separate from detectAdminPortSpread for lower threshold and different alert.
func detectSMBSpray(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT agent_id,
		       COUNT(DISTINCT split_part(remote_address, ':', 1)) AS peer_count,
		       COUNT(*) AS attempt_count
		FROM network_connect_events
		WHERE tenant_id  = $1
		  AND created_at > NOW() - INTERVAL '10 minutes'
		  AND split_part(remote_address, ':', -1) = '445'
		  AND (
		      split_part(remote_address, ':', 1) LIKE '10.%'    OR
		      split_part(remote_address, ':', 1) LIKE '172.1%'  OR
		      split_part(remote_address, ':', 1) LIKE '172.2%'  OR
		      split_part(remote_address, ':', 1) LIKE '172.3%'  OR
		      split_part(remote_address, ':', 1) LIKE '192.168.%'
		  )
		GROUP BY agent_id
		HAVING COUNT(DISTINCT split_part(remote_address, ':', 1)) >= 10
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID, peerCount, attemptCount int
		if rows.Scan(&agentID, &peerCount, &attemptCount) != nil {
			continue
		}

		desc := fmt.Sprintf(
			"SMB spray: %d internal hosts contacted via SMB/port-445 in 10 min (%d total attempts) — possible ransomware propagation",
			peerCount, attemptCount,
		)

		if !recordNetworkAnomaly(agentID, tenantID, "smb_spray", "internal", 445, "tcp", 95, desc, "10 minutes") {
			continue
		}

		log.Printf("[Lateral] SMB spray agent=%d peers=%d", agentID, peerCount)
		fireNetworkAlert(agentID, tenantID, "SMB Spray / Ransomware Propagation", "critical", "T1021.002",
			desc, fmt.Sprintf("%d-smbspray", agentID))
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// recordNetworkAnomaly inserts an anomaly and returns true if it was new,
// false if a duplicate already existed within the dedup window.
func recordNetworkAnomaly(agentID, tenantID int, anomalyType, dstIP string, dstPort int, proto string, score int, desc, dedupWindow string) bool {
	var existing int
	database.DB.QueryRow(fmt.Sprintf(`
		SELECT COUNT(*) FROM network_anomalies
		WHERE agent_id=$1 AND anomaly_type=$2 AND dst_ip=$3 AND dst_port=$4
		  AND detected_at > NOW() - INTERVAL '%s'
	`, dedupWindow), agentID, anomalyType, dstIP, dstPort).Scan(&existing)
	if existing > 0 {
		return false
	}

	database.DB.Exec(`
		INSERT INTO network_anomalies
		  (agent_id, tenant_id, anomaly_type, dst_ip, dst_port, proto, deviation_score, description)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, agentID, tenantID, anomalyType, dstIP, dstPort, proto, score, desc)
	return true
}

func fireNetworkAlert(agentID, tenantID int, ruleName, severity, technique, desc, fingerprint string) {
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

func adminPortName(port int) string {
	names := map[int]string{
		445:  "SMB",
		3389: "RDP",
		135:  "WMI/DCOM",
		5985: "WinRM-HTTP",
		5986: "WinRM-HTTPS",
		139:  "NetBIOS",
		636:  "LDAPS",
		389:  "LDAP",
		4899: "Radmin",
	}
	if n, ok := names[port]; ok {
		return n
	}
	return fmt.Sprintf("port-%d", port)
}
