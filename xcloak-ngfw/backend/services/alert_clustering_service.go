package services

import (
	"fmt"
	"log"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// ClusterAlerts groups recent alerts by MITRE technique + rule name + agent,
// upserts cluster records, and auto-promotes clusters with ≥3 alerts.
func ClusterAlerts(tenantID int) error {
	// Fetch unprocessed or recent alerts (last 24h)
	rows, err := database.DB.Query(`
		SELECT a.id, a.rule_name, a.severity,
		       COALESCE(a.mitre_technique,''), COALESCE(a.mitre_tactic,''),
		       COALESCE(a.agent_id, 0), a.created_at
		FROM alerts a
		WHERE a.tenant_id=$1
		  AND a.created_at > NOW()-INTERVAL '24 hours'
		  AND a.status NOT IN ('resolved','false_positive')
		ORDER BY a.created_at`, tenantID)
	if err != nil {
		return err
	}
	defer rows.Close()

	type alertRow struct {
		id                    int
		ruleName, severity    string
		mitreTech, mitreTact string
		agentID               int
		createdAt             time.Time
	}

	var alerts []alertRow
	for rows.Next() {
		var a alertRow
		rows.Scan(&a.id, &a.ruleName, &a.severity, &a.mitreTech, &a.mitreTact, &a.agentID, &a.createdAt)
		alerts = append(alerts, a)
	}
	rows.Close()

	// Group by cluster key: {technique or rule_name}:{agent_id}
	type clusterMeta struct {
		key      string
		tech     string
		ruleName string
		alertIDs []int
		first    time.Time
		last     time.Time
	}

	clusters := map[string]*clusterMeta{}
	for _, a := range alerts {
		key := clusterKey(a.mitreTech, a.ruleName, a.agentID)
		if _, ok := clusters[key]; !ok {
			clusters[key] = &clusterMeta{key: key, tech: a.mitreTech, ruleName: a.ruleName, first: a.createdAt, last: a.createdAt}
		}
		c := clusters[key]
		c.alertIDs = append(c.alertIDs, a.id)
		if a.createdAt.Before(c.first) {
			c.first = a.createdAt
		}
		if a.createdAt.After(c.last) {
			c.last = a.createdAt
		}
	}

	for _, c := range clusters {
		if len(c.alertIDs) < 2 {
			continue // single alerts don't form a cluster
		}

		// Upsert cluster
		var clusterID int
		err := database.DB.QueryRow(`
			INSERT INTO alert_clusters (tenant_id, cluster_key, mitre_technique, rule_name, alert_count, first_seen, last_seen)
			VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (tenant_id, cluster_key) DO UPDATE SET
			  alert_count = EXCLUDED.alert_count,
			  last_seen   = EXCLUDED.last_seen
			RETURNING id`,
			tenantID, c.key, c.tech, c.ruleName, len(c.alertIDs), c.first, c.last,
		).Scan(&clusterID)
		if err != nil {
			log.Printf("[Cluster] upsert failed for %s: %v", c.key, err)
			continue
		}

		// Link alert members
		for _, alertID := range c.alertIDs {
			database.DB.Exec(`
				INSERT INTO alert_cluster_members (cluster_id, alert_id)
				VALUES ($1,$2) ON CONFLICT DO NOTHING`, clusterID, alertID)
		}

		// Auto-promote clusters with ≥ 3 alerts to an incident
		if len(c.alertIDs) >= 3 {
			promoteClusterToIncident(clusterID, tenantID, c)
		}
	}
	return nil
}

func clusterKey(mitreTech, ruleName string, agentID int) string {
	base := mitreTech
	if base == "" {
		// Normalize rule name: take first 3 words
		words := strings.Fields(ruleName)
		if len(words) > 3 {
			words = words[:3]
		}
		base = strings.Join(words, "_")
	}
	return fmt.Sprintf("%s:agent_%d", base, agentID)
}

type clusterMetaRef struct {
	key      string
	tech     string
	ruleName string
	alertIDs []int
	first    time.Time
	last     time.Time
}

func promoteClusterToIncident(clusterID, tenantID int, c interface{}) {
	// Re-check if already promoted
	var existing int
	database.DB.QueryRow(`SELECT COALESCE(auto_incident_id, 0) FROM alert_clusters WHERE id=$1`, clusterID).Scan(&existing)
	if existing > 0 {
		return
	}

	// Determine severity from cluster member alerts
	var maxSev string
	database.DB.QueryRow(`
		SELECT severity FROM alerts a
		JOIN alert_cluster_members acm ON acm.alert_id=a.id
		WHERE acm.cluster_id=$1
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END
		LIMIT 1`, clusterID,
	).Scan(&maxSev)
	if maxSev == "" {
		maxSev = "high"
	}

	// Build incident title from cluster
	var ruleName, tech string
	var alertCount int
	database.DB.QueryRow(`SELECT rule_name, mitre_technique, alert_count FROM alert_clusters WHERE id=$1`, clusterID).
		Scan(&ruleName, &tech, &alertCount)

	title := fmt.Sprintf("[Auto-Cluster] %s × %d alerts", ruleName, alertCount)
	if tech != "" {
		title = fmt.Sprintf("[Auto-Cluster] %s (%s) × %d alerts", ruleName, tech, alertCount)
	}

	var incidentID int
	err := database.DB.QueryRow(`
		INSERT INTO incidents (tenant_id, title, severity, status, created_by)
		VALUES ($1,$2,$3,'open','auto-cluster')
		RETURNING id`, tenantID, title, maxSev,
	).Scan(&incidentID)
	if err != nil {
		log.Printf("[Cluster] create incident for cluster %d: %v", clusterID, err)
		return
	}

	database.DB.Exec(`UPDATE alert_clusters SET auto_incident_id=$1, status='promoted' WHERE id=$2`, incidentID, clusterID)

	// Link all cluster alerts to the new incident
	database.DB.Exec(`
		UPDATE alerts SET incident_id=$1
		FROM alert_cluster_members
		WHERE alert_cluster_members.cluster_id=$2
		  AND alerts.id=alert_cluster_members.alert_id`, incidentID, clusterID)

	log.Printf("[Cluster] promoted cluster #%d to incident #%d (%s, %d alerts)", clusterID, incidentID, maxSev, alertCount)
}

// GetAlertClusters returns clusters for a tenant, most active first.
func GetAlertClusters(tenantID, limit int) ([]models.AlertCluster, error) {
	rows, err := database.DB.Query(`
		SELECT ac.id, ac.tenant_id, ac.cluster_key, ac.mitre_technique, ac.rule_name,
		       ac.alert_count, ac.first_seen, ac.last_seen, ac.auto_incident_id, ac.status
		FROM alert_clusters ac
		WHERE ac.tenant_id=$1
		ORDER BY ac.last_seen DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.AlertCluster
	for rows.Next() {
		var c models.AlertCluster
		rows.Scan(&c.ID, &c.TenantID, &c.ClusterKey, &c.MitreTechnique, &c.RuleName,
			&c.AlertCount, &c.FirstSeen, &c.LastSeen, &c.AutoIncidentID, &c.Status)
		out = append(out, c)
	}
	return out, nil
}

// GetClusterAlerts returns the alert IDs in a cluster.
func GetClusterAlerts(clusterID, tenantID int) ([]map[string]any, error) {
	rows, err := database.DB.Query(`
		SELECT a.id, a.rule_name, a.severity, a.status,
		       COALESCE(ag.hostname,''), a.created_at
		FROM alert_cluster_members acm
		JOIN alerts a ON a.id=acm.alert_id
		LEFT JOIN agents ag ON ag.id=a.agent_id
		WHERE acm.cluster_id=$1 AND a.tenant_id=$2
		ORDER BY a.created_at`, clusterID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id int
		var ruleName, severity, status, hostname string
		var createdAt time.Time
		rows.Scan(&id, &ruleName, &severity, &status, &hostname, &createdAt)
		out = append(out, map[string]any{
			"id": id, "rule_name": ruleName, "severity": severity,
			"status": status, "hostname": hostname, "created_at": createdAt,
		})
	}
	return out, nil
}

// SuppressCluster marks a cluster as suppressed (user decided it's noise).
func SuppressCluster(clusterID, tenantID int) error {
	_, err := database.DB.Exec(`UPDATE alert_clusters SET status='suppressed' WHERE id=$1 AND tenant_id=$2`, clusterID, tenantID)
	return err
}

// StartClusterScheduler runs alert clustering every 15 min.
func StartClusterScheduler() {
	go func() {
		time.Sleep(2 * time.Minute) // initial quiet period
		for {
			rows, _ := database.DB.Query(`SELECT id FROM tenants WHERE is_active=true`)
			if rows != nil {
				for rows.Next() {
					var tid int
					rows.Scan(&tid)
					if err := ClusterAlerts(tid); err != nil {
						log.Printf("[Cluster] tenant %d: %v", tid, err)
					}
				}
				rows.Close()
			}
			time.Sleep(15 * time.Minute)
		}
	}()
}
