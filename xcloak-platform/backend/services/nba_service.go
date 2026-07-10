package services

import (
	"fmt"
	"log"
	"net"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// ── Baseline update ────────────────────────────────────────────────────────

// UpdateNetworkBaseline records a connection into the per-agent baseline.
// Called by the connect-event ingestion path.
func UpdateNetworkBaseline(agentID, tenantID, dstPort int, dstIP, proto string) {
	database.DB.Exec(`
		INSERT INTO network_baselines (agent_id, tenant_id, dst_ip, dst_port, proto, hit_count, first_seen, last_seen)
		VALUES ($1,$2,$3,$4,$5,1,NOW(),NOW())
		ON CONFLICT (agent_id, dst_ip, dst_port, proto)
		DO UPDATE SET hit_count=network_baselines.hit_count+1, last_seen=NOW()`,
		agentID, tenantID, dstIP, dstPort, proto)
}

// ── Anomaly detection ──────────────────────────────────────────────────────

// AnalyzeAgentNetworkBehavior detects deviations from baseline for one agent.
func AnalyzeAgentNetworkBehavior(agentID, tenantID int) {
	// New destinations seen in last hour that have never appeared in baseline before last 24h
	rows, err := database.DB.Query(`
		SELECT DISTINCT ce.dst_ip, ce.dst_port, COALESCE(ce.proto,'tcp')
		FROM endpoint_connections ce
		WHERE ce.agent_id=$1
		  AND ce.event_ts > NOW()-INTERVAL '1 hour'
		  AND NOT EXISTS (
		      SELECT 1 FROM network_baselines nb
		      WHERE nb.agent_id=$1 AND nb.dst_ip=ce.dst_ip
		        AND nb.dst_port=ce.dst_port
		        AND nb.last_seen < NOW()-INTERVAL '1 hour'
		        AND nb.hit_count >= 3
		  )
		  AND ce.dst_ip != ''
		LIMIT 50`, agentID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var dstIP, proto string
		var dstPort int
		rows.Scan(&dstIP, &dstPort, &proto)

		if isPrivateIPStr(dstIP) {
			continue // internal traffic is expected
		}

		score := 60
		anomalyType := "new_destination"
		desc := fmt.Sprintf("New external destination %s:%d/%s not seen in baseline", dstIP, dstPort, proto)

		// Boost score for known bad ports
		if isRarePort(dstPort) {
			score = 80
			anomalyType = "rare_port"
			desc = fmt.Sprintf("Connection to unusual port %d at %s (not in baseline)", dstPort, dstIP)
		}

		// Insert if not already flagged in last 6h
		var existing int
		database.DB.QueryRow(`
			SELECT COUNT(*) FROM network_anomalies
			WHERE agent_id=$1 AND dst_ip=$2 AND dst_port=$3 AND detected_at>NOW()-INTERVAL '6 hours'`,
			agentID, dstIP, dstPort,
		).Scan(&existing)
		if existing > 0 {
			continue
		}

		database.DB.Exec(`
			INSERT INTO network_anomalies
			  (agent_id, tenant_id, anomaly_type, dst_ip, dst_port, proto, deviation_score, description)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			agentID, tenantID, anomalyType, dstIP, dstPort, proto, score, desc)

		log.Printf("[NBA] agent #%d anomaly: %s → %s:%d (score=%d)", agentID, anomalyType, dstIP, dstPort, score)
	}

	// Volume spike: connections in last hour vs 7d average
	checkVolumeSpike(agentID, tenantID)
}

func checkVolumeSpike(agentID, tenantID int) {
	var lastHour, avgPerHour float64
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM endpoint_connections
		WHERE agent_id=$1 AND event_ts>NOW()-INTERVAL '1 hour'`, agentID,
	).Scan(&lastHour)
	database.DB.QueryRow(`
		SELECT COUNT(*)::float / GREATEST(EXTRACT(EPOCH FROM (NOW() - MIN(event_ts)))/3600, 1)
		FROM endpoint_connections
		WHERE agent_id=$1 AND event_ts BETWEEN NOW()-INTERVAL '7 days' AND NOW()-INTERVAL '1 hour'`, agentID,
	).Scan(&avgPerHour)

	if avgPerHour <= 0 || lastHour < avgPerHour*3 {
		return
	}

	score := int(((lastHour / avgPerHour) - 1) * 20)
	if score > 100 {
		score = 100
	}
	desc := fmt.Sprintf("Network volume spike: %d connections/hr vs %.0f avg (%.1fx)", int(lastHour), avgPerHour, lastHour/avgPerHour)

	var existing int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM network_anomalies
		WHERE agent_id=$1 AND anomaly_type='volume_spike' AND detected_at>NOW()-INTERVAL '2 hours'`, agentID,
	).Scan(&existing)
	if existing > 0 {
		return
	}

	database.DB.Exec(`
		INSERT INTO network_anomalies (agent_id, tenant_id, anomaly_type, deviation_score, description)
		VALUES ($1,$2,'volume_spike',$3,$4)`, agentID, tenantID, score, desc)
}

// ── Query ──────────────────────────────────────────────────────────────────

func GetNetworkAnomalies(tenantID, limit int) ([]models.NetworkAnomaly, error) {
	rows, err := database.DB.Query(`
		SELECT na.id, na.agent_id, COALESCE(a.hostname,''), na.tenant_id,
		       na.anomaly_type, na.dst_ip, na.dst_port, na.proto,
		       na.deviation_score, na.description, na.is_acknowledged, na.detected_at
		FROM network_anomalies na
		LEFT JOIN agents a ON a.id=na.agent_id
		WHERE na.tenant_id=$1
		ORDER BY na.detected_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.NetworkAnomaly
	for rows.Next() {
		var n models.NetworkAnomaly
		rows.Scan(&n.ID, &n.AgentID, &n.Hostname, &n.TenantID,
			&n.AnomalyType, &n.DstIP, &n.DstPort, &n.Proto,
			&n.DeviationScore, &n.Description, &n.IsAcknowledged, &n.DetectedAt)
		out = append(out, n)
	}
	return out, nil
}

func AcknowledgeNetworkAnomaly(id, tenantID int) error {
	_, err := database.DB.Exec(`
		UPDATE network_anomalies SET is_acknowledged=true WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

func GetNetworkBaselineStats(agentID, tenantID int) (map[string]any, error) {
	var totalDests, totalPorts int
	var topPorts []map[string]any

	database.DB.QueryRow(`SELECT COUNT(DISTINCT dst_ip), COUNT(DISTINCT dst_port)
		FROM network_baselines WHERE agent_id=$1 AND tenant_id=$2`, agentID, tenantID,
	).Scan(&totalDests, &totalPorts)

	rows, _ := database.DB.Query(`
		SELECT dst_port, proto, SUM(hit_count) AS hits
		FROM network_baselines WHERE agent_id=$1 AND tenant_id=$2
		GROUP BY dst_port, proto ORDER BY hits DESC LIMIT 10`, agentID, tenantID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var port, hits int
			var proto string
			rows.Scan(&port, &proto, &hits)
			topPorts = append(topPorts, map[string]any{"port": port, "proto": proto, "hits": hits})
		}
	}

	return map[string]any{
		"agent_id":    agentID,
		"total_dests": totalDests,
		"total_ports": totalPorts,
		"top_ports":   topPorts,
	}, nil
}

// RunNBAForTenant runs analysis for all online agents in a tenant immediately.
func RunNBAForTenant(tenantID int) {
	rows, err := database.DB.Query(`SELECT id FROM agents WHERE tenant_id=$1 AND status='online'`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var agentID int
		rows.Scan(&agentID)
		AnalyzeAgentNetworkBehavior(agentID, tenantID)
	}
}

// StartNBAScheduler runs anomaly detection every 30 minutes across all agents.
func StartNBAScheduler() {
	go func() {
		// Initial delay so connect-events have time to populate
		time.Sleep(5 * time.Minute)
		for {
			rows, err := database.DB.Query(`SELECT id, tenant_id FROM agents WHERE status='online'`)
			if err == nil {
				for rows.Next() {
					var agentID, tenantID int
					rows.Scan(&agentID, &tenantID)
					AnalyzeAgentNetworkBehavior(agentID, tenantID)
				}
				rows.Close()
			}
			time.Sleep(30 * time.Minute)
		}
	}()
}

// ── helpers ────────────────────────────────────────────────────────────────

func isPrivateIPStr(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func isRarePort(port int) bool {
	common := map[int]bool{
		80: true, 443: true, 53: true, 22: true, 25: true, 587: true,
		465: true, 993: true, 143: true, 110: true, 995: true,
		8080: true, 8443: true, 3306: true, 5432: true, 6379: true,
		27017: true, 9200: true, 2181: true, 9092: true,
	}
	return !common[port]
}
