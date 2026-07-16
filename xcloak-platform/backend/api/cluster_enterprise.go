package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/services"
)

// campaignFromTechnique maps a MITRE technique to a campaign type heuristic.
func campaignFromTechnique(tech string) string {
	switch {
	case tech == "T1566" || strings.HasPrefix(tech, "T1566"):
		return "Phishing"
	case tech == "T1486" || tech == "T1490":
		return "Ransomware"
	case tech == "T1003" || strings.HasPrefix(tech, "T1003"):
		return "Credential Theft"
	case tech == "T1078" || tech == "T1021":
		return "Lateral Movement"
	case tech == "T1041" || tech == "T1048":
		return "Data Exfiltration"
	case tech == "T1071" || tech == "T1090":
		return "C2 / Botnet"
	case tech == "T1059" || tech == "T1055":
		return "Execution"
	default:
		return "Unknown"
	}
}

func clusterRiskScore(severity string, alertCount, hostCount int) int {
	score := alertCount * 5
	switch severity {
	case "critical":
		score += 40
	case "high":
		score += 20
	case "medium":
		score += 10
	}
	if hostCount > 1 {
		score += hostCount * 5
	}
	if score > 100 {
		return 100
	}
	return score
}

func clusterConfidence(alertCount int) int {
	c := 40 + alertCount*8
	if c > 95 {
		return 95
	}
	return c
}

// ── GetClusterOverview ────────────────────────────────────────────────────────

func GetClusterOverview(c *gin.Context) {
	tid := tenantIDFromContext(c)
	hours := parseHours(c, 24)

	var total, active, newCount, highRisk, closed, incidents, campaigns int
	database.DB.QueryRow(`SELECT COUNT(*) FROM alert_clusters WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM alert_clusters WHERE tenant_id=$1 AND status='open'`, tid).Scan(&active)
	database.DB.QueryRow(`SELECT COUNT(*) FROM alert_clusters WHERE tenant_id=$1 AND first_seen > NOW()-($2::int)*INTERVAL'1 hour'`, tid, hours).Scan(&newCount)
	database.DB.QueryRow(`SELECT COUNT(*) FROM alert_clusters WHERE tenant_id=$1 AND alert_count>=5 AND status='open'`, tid).Scan(&highRisk)
	database.DB.QueryRow(`SELECT COUNT(*) FROM alert_clusters WHERE tenant_id=$1 AND status NOT IN ('open')`, tid).Scan(&closed)
	database.DB.QueryRow(`SELECT COUNT(*) FROM alert_clusters WHERE tenant_id=$1 AND auto_incident_id IS NOT NULL`, tid).Scan(&incidents)
	database.DB.QueryRow(`SELECT COUNT(DISTINCT COALESCE(NULLIF(mitre_technique,''),'unknown')) FROM alert_clusters WHERE tenant_id=$1 AND status='open'`, tid).Scan(&campaigns)

	var avgSizeRaw float64
	database.DB.QueryRow(`SELECT COALESCE(AVG(alert_count),0) FROM alert_clusters WHERE tenant_id=$1`, tid).Scan(&avgSizeRaw)

	var confHigh int
	database.DB.QueryRow(`SELECT COUNT(*) FROM alert_clusters WHERE tenant_id=$1 AND alert_count>=3`, tid).Scan(&confHigh)
	confidence := 0
	if total > 0 {
		confidence = confHigh * 100 / total
	}

	// 7-day daily trend
	trendRows, _ := database.DB.Query(`
		SELECT TO_CHAR(DATE_TRUNC('day', first_seen),'YYYY-MM-DD'), COUNT(*)
		FROM alert_clusters
		WHERE tenant_id=$1 AND first_seen > NOW()-INTERVAL'7 days'
		GROUP BY 1 ORDER BY 1`, tid)
	type dayBucket struct {
		Day   string `json:"day"`
		Count int    `json:"count"`
	}
	var trend []dayBucket
	if trendRows != nil {
		for trendRows.Next() {
			var b dayBucket
			trendRows.Scan(&b.Day, &b.Count)
			trend = append(trend, b)
		}
		trendRows.Close()
	}
	if trend == nil {
		trend = []dayBucket{}
	}

	// Status breakdown
	statusRows, _ := database.DB.Query(`
		SELECT status, COUNT(*) FROM alert_clusters WHERE tenant_id=$1 GROUP BY status`, tid)
	statusBreakdown := map[string]int{}
	if statusRows != nil {
		for statusRows.Next() {
			var s string
			var n int
			statusRows.Scan(&s, &n)
			statusBreakdown[s] = n
		}
		statusRows.Close()
	}

	c.JSON(http.StatusOK, gin.H{
		"total":              total,
		"active_clusters":    active,
		"new_clusters":       newCount,
		"high_risk":          highRisk,
		"closed":             closed,
		"campaigns":          campaigns,
		"related_incidents":  incidents,
		"avg_cluster_size":   fmt.Sprintf("%.1f", avgSizeRaw),
		"cluster_confidence": confidence,
		"trend":              trend,
		"status_breakdown":   statusBreakdown,
	})
}

// ── GetClusterList ─────────────────────────────────────────────────────────────

type clusterListRow struct {
	ID             int       `json:"id"`
	ClusterKey     string    `json:"cluster_key"`
	MitreTechnique string    `json:"mitre_technique"`
	RuleName       string    `json:"rule_name"`
	AlertCount     int       `json:"alert_count"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	IncidentID     int       `json:"incident_id"`
	Status         string    `json:"status"`
	Severity       string    `json:"severity"`
	HostCount      int       `json:"host_count"`
	RiskScore      int       `json:"risk_score"`
	Confidence     int       `json:"confidence"`
	Campaign       string    `json:"campaign"`
}

func GetClusterList(c *gin.Context) {
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)
	status := c.DefaultQuery("status", "")

	where := "WHERE ac.tenant_id=$1"
	args := []any{tid}
	if status != "" && status != "all" {
		args = append(args, status)
		where += fmt.Sprintf(" AND ac.status=$%d", len(args))
	}
	args = append(args, limit)

	q := fmt.Sprintf(`
		SELECT ac.id,
		       ac.cluster_key,
		       COALESCE(ac.mitre_technique,''),
		       ac.rule_name,
		       ac.alert_count,
		       ac.first_seen,
		       ac.last_seen,
		       COALESCE(ac.auto_incident_id,0),
		       ac.status,
		       COALESCE((
		           SELECT a.severity FROM alerts a
		           JOIN alert_cluster_members acm2 ON acm2.alert_id=a.id
		           WHERE acm2.cluster_id=ac.id
		           ORDER BY CASE a.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END
		           LIMIT 1
		       ),'medium'),
		       COALESCE((
		           SELECT COUNT(DISTINCT a.agent_id)::int
		           FROM alerts a
		           JOIN alert_cluster_members acm3 ON acm3.alert_id=a.id
		           WHERE acm3.cluster_id=ac.id AND a.agent_id IS NOT NULL
		       ),0)
		FROM alert_clusters ac
		%s
		ORDER BY ac.last_seen DESC
		LIMIT $%d`, where, len(args))

	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var out []clusterListRow
	for rows.Next() {
		var r clusterListRow
		rows.Scan(&r.ID, &r.ClusterKey, &r.MitreTechnique, &r.RuleName,
			&r.AlertCount, &r.FirstSeen, &r.LastSeen, &r.IncidentID,
			&r.Status, &r.Severity, &r.HostCount)
		r.RiskScore = clusterRiskScore(r.Severity, r.AlertCount, r.HostCount)
		r.Confidence = clusterConfidence(r.AlertCount)
		r.Campaign = campaignFromTechnique(r.MitreTechnique)
		out = append(out, r)
	}
	if out == nil {
		out = []clusterListRow{}
	}
	c.JSON(http.StatusOK, out)
}

// ── GetClusterDetail ───────────────────────────────────────────────────────────

func GetClusterDetail(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	tid := tenantIDFromContext(c)

	// Core cluster row
	var r clusterListRow
	err := database.DB.QueryRow(`
		SELECT ac.id, ac.cluster_key, COALESCE(ac.mitre_technique,''), ac.rule_name,
		       ac.alert_count, ac.first_seen, ac.last_seen,
		       COALESCE(ac.auto_incident_id,0), ac.status,
		       COALESCE((
		           SELECT a.severity FROM alerts a
		           JOIN alert_cluster_members acm2 ON acm2.alert_id=a.id
		           WHERE acm2.cluster_id=ac.id
		           ORDER BY CASE a.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END
		           LIMIT 1
		       ),'medium'),
		       COALESCE((
		           SELECT COUNT(DISTINCT a.agent_id)::int
		           FROM alerts a
		           JOIN alert_cluster_members acm3 ON acm3.alert_id=a.id
		           WHERE acm3.cluster_id=ac.id AND a.agent_id IS NOT NULL
		       ),0)
		FROM alert_clusters ac
		WHERE ac.id=$1 AND ac.tenant_id=$2`, id, tid).
		Scan(&r.ID, &r.ClusterKey, &r.MitreTechnique, &r.RuleName,
			&r.AlertCount, &r.FirstSeen, &r.LastSeen, &r.IncidentID,
			&r.Status, &r.Severity, &r.HostCount)
	if err != nil {
		c.JSON(404, gin.H{"error": "cluster not found"})
		return
	}
	r.RiskScore = clusterRiskScore(r.Severity, r.AlertCount, r.HostCount)
	r.Confidence = clusterConfidence(r.AlertCount)
	r.Campaign = campaignFromTechnique(r.MitreTechnique)

	// Member alerts
	alertRows, _ := database.DB.Query(`
		SELECT a.id, a.rule_name, a.severity, a.status,
		       COALESCE(ag.hostname,'unknown'), a.created_at,
		       COALESCE(a.mitre_technique,''), COALESCE(a.mitre_tactic,''),
		       COALESCE(a.source_ip,'')
		FROM alert_cluster_members acm
		JOIN alerts a ON a.id=acm.alert_id
		LEFT JOIN agents ag ON ag.id=a.agent_id
		WHERE acm.cluster_id=$1 AND a.tenant_id=$2
		ORDER BY a.created_at`, id, tid)

	type AlertMember struct {
		ID             int       `json:"id"`
		RuleName       string    `json:"rule_name"`
		Severity       string    `json:"severity"`
		Status         string    `json:"status"`
		Hostname       string    `json:"hostname"`
		CreatedAt      time.Time `json:"created_at"`
		MitreTechnique string    `json:"mitre_technique"`
		MitreTactic    string    `json:"mitre_tactic"`
		SourceIP       string    `json:"source_ip"`
	}
	var alerts []AlertMember
	if alertRows != nil {
		for alertRows.Next() {
			var a AlertMember
			alertRows.Scan(&a.ID, &a.RuleName, &a.Severity, &a.Status,
				&a.Hostname, &a.CreatedAt, &a.MitreTechnique, &a.MitreTactic, &a.SourceIP)
			alerts = append(alerts, a)
		}
		alertRows.Close()
	}
	if alerts == nil {
		alerts = []AlertMember{}
	}

	// Distinct hosts
	type HostEntry struct {
		Hostname string `json:"hostname"`
		AgentID  int    `json:"agent_id"`
		Count    int    `json:"count"`
	}
	hostRows, _ := database.DB.Query(`
		SELECT COALESCE(ag.hostname,'unknown'), COALESCE(a.agent_id,0), COUNT(*)::int
		FROM alert_cluster_members acm
		JOIN alerts a ON a.id=acm.alert_id
		LEFT JOIN agents ag ON ag.id=a.agent_id
		WHERE acm.cluster_id=$1 AND a.tenant_id=$2
		GROUP BY ag.hostname, a.agent_id
		ORDER BY 3 DESC`, id, tid)
	var hosts []HostEntry
	if hostRows != nil {
		for hostRows.Next() {
			var h HostEntry
			hostRows.Scan(&h.Hostname, &h.AgentID, &h.Count)
			hosts = append(hosts, h)
		}
		hostRows.Close()
	}
	if hosts == nil {
		hosts = []HostEntry{}
	}

	// Distinct source IPs
	ipRows, _ := database.DB.Query(`
		SELECT COALESCE(a.source_ip,''), COUNT(*)::int
		FROM alert_cluster_members acm
		JOIN alerts a ON a.id=acm.alert_id
		WHERE acm.cluster_id=$1 AND a.tenant_id=$2 AND a.source_ip IS NOT NULL AND a.source_ip!=''
		GROUP BY a.source_ip ORDER BY 2 DESC LIMIT 20`, id, tid)
	type IPEntry struct {
		IP    string `json:"ip"`
		Count int    `json:"count"`
	}
	var ips []IPEntry
	if ipRows != nil {
		for ipRows.Next() {
			var e IPEntry
			ipRows.Scan(&e.IP, &e.Count)
			ips = append(ips, e)
		}
		ipRows.Close()
	}
	if ips == nil {
		ips = []IPEntry{}
	}

	// MITRE breakdown
	mitreRows, _ := database.DB.Query(`
		SELECT COALESCE(a.mitre_technique,''), COALESCE(a.mitre_tactic,''), COUNT(*)::int
		FROM alert_cluster_members acm
		JOIN alerts a ON a.id=acm.alert_id
		WHERE acm.cluster_id=$1 AND a.tenant_id=$2
		GROUP BY a.mitre_technique, a.mitre_tactic
		ORDER BY 3 DESC`, id, tid)
	type MITREEntry struct {
		Technique string `json:"technique"`
		Tactic    string `json:"tactic"`
		Count     int    `json:"count"`
	}
	var mitre []MITREEntry
	if mitreRows != nil {
		for mitreRows.Next() {
			var e MITREEntry
			mitreRows.Scan(&e.Technique, &e.Tactic, &e.Count)
			mitre = append(mitre, e)
		}
		mitreRows.Close()
	}
	if mitre == nil {
		mitre = []MITREEntry{}
	}

	c.JSON(http.StatusOK, gin.H{
		"cluster":   r,
		"alerts":    alerts,
		"hosts":     hosts,
		"ips":       ips,
		"mitre":     mitre,
	})
}

// ── GetClusterTimeline ─────────────────────────────────────────────────────────

func GetClusterTimeline(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	tid := tenantIDFromContext(c)

	rows, err := database.DB.Query(`
		SELECT a.id, a.rule_name, a.severity, COALESCE(ag.hostname,'unknown'),
		       a.created_at, COALESCE(a.mitre_technique,''), COALESCE(a.mitre_tactic,''),
		       COALESCE(a.source_ip,''), a.status
		FROM alert_cluster_members acm
		JOIN alerts a ON a.id=acm.alert_id
		LEFT JOIN agents ag ON ag.id=a.agent_id
		WHERE acm.cluster_id=$1 AND a.tenant_id=$2
		ORDER BY a.created_at`, id, tid)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type TimelineEvent struct {
		ID             int       `json:"id"`
		RuleName       string    `json:"rule_name"`
		Severity       string    `json:"severity"`
		Hostname       string    `json:"hostname"`
		Time           time.Time `json:"time"`
		MitreTechnique string    `json:"mitre_technique"`
		MitreTactic    string    `json:"mitre_tactic"`
		SourceIP       string    `json:"source_ip"`
		Status         string    `json:"status"`
	}
	var events []TimelineEvent
	for rows.Next() {
		var e TimelineEvent
		rows.Scan(&e.ID, &e.RuleName, &e.Severity, &e.Hostname,
			&e.Time, &e.MitreTechnique, &e.MitreTactic, &e.SourceIP, &e.Status)
		events = append(events, e)
	}
	if events == nil {
		events = []TimelineEvent{}
	}
	c.JSON(http.StatusOK, gin.H{"events": events, "total": len(events)})
}

// ── GetClusterGraph ────────────────────────────────────────────────────────────

func GetClusterGraph(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	tid := tenantIDFromContext(c)

	type GraphNode struct {
		ID    string `json:"id"`
		Label string `json:"label"`
		Type  string `json:"type"` // host, rule, ip, incident
		Count int    `json:"count"`
	}
	type GraphEdge struct {
		Source string `json:"source"`
		Target string `json:"target"`
	}

	var nodes []GraphNode
	var edges []GraphEdge

	// Host nodes
	hostRows, _ := database.DB.Query(`
		SELECT COALESCE(ag.hostname,'unknown'), COALESCE(a.agent_id,0), COUNT(*)::int
		FROM alert_cluster_members acm
		JOIN alerts a ON a.id=acm.alert_id
		LEFT JOIN agents ag ON ag.id=a.agent_id
		WHERE acm.cluster_id=$1 AND a.tenant_id=$2
		GROUP BY ag.hostname, a.agent_id`, id, tid)
	if hostRows != nil {
		for hostRows.Next() {
			var hostname string
			var agentID, cnt int
			hostRows.Scan(&hostname, &agentID, &cnt)
			nodeID := fmt.Sprintf("host_%d", agentID)
			nodes = append(nodes, GraphNode{ID: nodeID, Label: hostname, Type: "host", Count: cnt})
		}
		hostRows.Close()
	}

	// Rule nodes + edges to hosts
	ruleRows, _ := database.DB.Query(`
		SELECT DISTINCT a.rule_name, COALESCE(a.mitre_technique,''), COALESCE(a.agent_id,0)
		FROM alert_cluster_members acm
		JOIN alerts a ON a.id=acm.alert_id
		WHERE acm.cluster_id=$1 AND a.tenant_id=$2`, id, tid)
	rulesSeen := map[string]bool{}
	if ruleRows != nil {
		for ruleRows.Next() {
			var ruleName, tech string
			var agentID int
			ruleRows.Scan(&ruleName, &tech, &agentID)
			ruleNodeID := "rule_" + strings.ReplaceAll(ruleName, " ", "_")
			if !rulesSeen[ruleNodeID] {
				rulesSeen[ruleNodeID] = true
				label := ruleName
				if tech != "" {
					label = fmt.Sprintf("%s (%s)", ruleName, tech)
				}
				nodes = append(nodes, GraphNode{ID: ruleNodeID, Label: label, Type: "rule", Count: 1})
			}
			if agentID > 0 {
				hostNodeID := fmt.Sprintf("host_%d", agentID)
				edges = append(edges, GraphEdge{Source: hostNodeID, Target: ruleNodeID})
			}
		}
		ruleRows.Close()
	}

	// IP nodes + edges to rules
	ipRows, _ := database.DB.Query(`
		SELECT DISTINCT a.source_ip, a.rule_name
		FROM alert_cluster_members acm
		JOIN alerts a ON a.id=acm.alert_id
		WHERE acm.cluster_id=$1 AND a.tenant_id=$2 AND a.source_ip IS NOT NULL AND a.source_ip!=''
		LIMIT 20`, id, tid)
	ipsSeen := map[string]bool{}
	if ipRows != nil {
		for ipRows.Next() {
			var ip, ruleName string
			ipRows.Scan(&ip, &ruleName)
			ipNodeID := "ip_" + strings.ReplaceAll(ip, ".", "_")
			if !ipsSeen[ipNodeID] {
				ipsSeen[ipNodeID] = true
				nodes = append(nodes, GraphNode{ID: ipNodeID, Label: ip, Type: "ip", Count: 1})
			}
			ruleNodeID := "rule_" + strings.ReplaceAll(ruleName, " ", "_")
			edges = append(edges, GraphEdge{Source: ipNodeID, Target: ruleNodeID})
		}
		ipRows.Close()
	}

	// Incident node if promoted
	var incidentID int
	var incidentTitle string
	database.DB.QueryRow(`
		SELECT COALESCE(ac.auto_incident_id,0), COALESCE(i.title,'')
		FROM alert_clusters ac
		LEFT JOIN incidents i ON i.id=ac.auto_incident_id
		WHERE ac.id=$1 AND ac.tenant_id=$2`, id, tid).Scan(&incidentID, &incidentTitle)
	if incidentID > 0 {
		incNodeID := fmt.Sprintf("incident_%d", incidentID)
		if incidentTitle == "" {
			incidentTitle = fmt.Sprintf("Incident #%d", incidentID)
		}
		nodes = append(nodes, GraphNode{ID: incNodeID, Label: incidentTitle, Type: "incident", Count: incidentID})
		// Edge from each rule to the incident
		for nodeID := range rulesSeen {
			edges = append(edges, GraphEdge{Source: nodeID, Target: incNodeID})
		}
	}

	if nodes == nil {
		nodes = []GraphNode{}
	}
	if edges == nil {
		edges = []GraphEdge{}
	}
	c.JSON(http.StatusOK, gin.H{"nodes": nodes, "edges": edges})
}

// ── GetClusterAnalytics ────────────────────────────────────────────────────────

func GetClusterAnalytics(c *gin.Context) {
	tid := tenantIDFromContext(c)

	// Size distribution
	sizeRows, _ := database.DB.Query(`
		SELECT
		  CASE
		    WHEN alert_count=1 THEN '1'
		    WHEN alert_count BETWEEN 2 AND 4 THEN '2-4'
		    WHEN alert_count BETWEEN 5 AND 9 THEN '5-9'
		    WHEN alert_count BETWEEN 10 AND 24 THEN '10-24'
		    ELSE '25+'
		  END AS bucket,
		  COUNT(*)::int
		FROM alert_clusters
		WHERE tenant_id=$1
		GROUP BY 1
		ORDER BY MIN(alert_count)`, tid)
	type SizeBucket struct {
		Bucket string `json:"bucket"`
		Count  int    `json:"count"`
	}
	var sizeDist []SizeBucket
	if sizeRows != nil {
		for sizeRows.Next() {
			var b SizeBucket
			sizeRows.Scan(&b.Bucket, &b.Count)
			sizeDist = append(sizeDist, b)
		}
		sizeRows.Close()
	}
	if sizeDist == nil {
		sizeDist = []SizeBucket{}
	}

	// Campaign breakdown
	campRows, _ := database.DB.Query(`
		SELECT COALESCE(mitre_technique,''), COUNT(*)::int, SUM(alert_count)::int
		FROM alert_clusters
		WHERE tenant_id=$1 AND status='open'
		GROUP BY mitre_technique
		ORDER BY 2 DESC LIMIT 15`, tid)
	type CampBucket struct {
		Technique string `json:"technique"`
		Campaign  string `json:"campaign"`
		Clusters  int    `json:"clusters"`
		Alerts    int    `json:"alerts"`
	}
	var campaigns []CampBucket
	if campRows != nil {
		for campRows.Next() {
			var tech string
			var clusters, alerts int
			campRows.Scan(&tech, &clusters, &alerts)
			campaigns = append(campaigns, CampBucket{
				Technique: tech,
				Campaign:  campaignFromTechnique(tech),
				Clusters:  clusters,
				Alerts:    alerts,
			})
		}
		campRows.Close()
	}
	if campaigns == nil {
		campaigns = []CampBucket{}
	}

	// MTTR: average age of closed/suppressed clusters in hours
	var mttrHours float64
	database.DB.QueryRow(`
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (last_seen - first_seen))/3600),0)
		FROM alert_clusters
		WHERE tenant_id=$1 AND status NOT IN ('open')`, tid).Scan(&mttrHours)

	// Top clusters by alert count
	topRows, _ := database.DB.Query(`
		SELECT id, rule_name, alert_count, status, COALESCE(mitre_technique,'')
		FROM alert_clusters WHERE tenant_id=$1
		ORDER BY alert_count DESC LIMIT 10`, tid)
	type TopCluster struct {
		ID         int    `json:"id"`
		RuleName   string `json:"rule_name"`
		AlertCount int    `json:"alert_count"`
		Status     string `json:"status"`
		Technique  string `json:"technique"`
	}
	var topClusters []TopCluster
	if topRows != nil {
		for topRows.Next() {
			var tc TopCluster
			topRows.Scan(&tc.ID, &tc.RuleName, &tc.AlertCount, &tc.Status, &tc.Technique)
			topClusters = append(topClusters, tc)
		}
		topRows.Close()
	}
	if topClusters == nil {
		topClusters = []TopCluster{}
	}

	c.JSON(http.StatusOK, gin.H{
		"size_distribution": sizeDist,
		"campaigns":         campaigns,
		"top_clusters":      topClusters,
		"mttr_hours":        fmt.Sprintf("%.1f", mttrHours),
	})
}

// ── GetClusterCampaigns ────────────────────────────────────────────────────────

func GetClusterCampaigns(c *gin.Context) {
	tid := tenantIDFromContext(c)

	rows, err := database.DB.Query(`
		SELECT COALESCE(NULLIF(mitre_technique,''),'Unknown'),
		       COUNT(*)::int AS cluster_count,
		       SUM(alert_count)::int AS total_alerts,
		       MAX(last_seen) AS latest,
		       MAX(
		           CASE status WHEN 'open' THEN 1 ELSE 0 END
		       )::int AS has_open
		FROM alert_clusters
		WHERE tenant_id=$1
		GROUP BY mitre_technique
		ORDER BY total_alerts DESC
		LIMIT 20`, tid)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type CampaignRow struct {
		Technique    string    `json:"technique"`
		Campaign     string    `json:"campaign"`
		ClusterCount int       `json:"cluster_count"`
		TotalAlerts  int       `json:"total_alerts"`
		Latest       time.Time `json:"latest"`
		HasOpen      bool      `json:"has_open"`
		RiskLevel    string    `json:"risk_level"`
	}
	var out []CampaignRow
	for rows.Next() {
		var r CampaignRow
		var hasOpen int
		rows.Scan(&r.Technique, &r.ClusterCount, &r.TotalAlerts, &r.Latest, &hasOpen)
		r.HasOpen = hasOpen == 1
		r.Campaign = campaignFromTechnique(r.Technique)
		switch {
		case r.TotalAlerts >= 20:
			r.RiskLevel = "critical"
		case r.TotalAlerts >= 10:
			r.RiskLevel = "high"
		case r.TotalAlerts >= 5:
			r.RiskLevel = "medium"
		default:
			r.RiskLevel = "low"
		}
		out = append(out, r)
	}
	if out == nil {
		out = []CampaignRow{}
	}
	c.JSON(http.StatusOK, gin.H{"campaigns": out})
}

// ── PostClusterAI ──────────────────────────────────────────────────────────────

func PostClusterAI(c *gin.Context) {
	tid := tenantIDFromContext(c)
	var body struct {
		Action    string `json:"action"`    // summarize, root_cause, chain, campaign_detect
		ClusterID int    `json:"cluster_id"`
		Context   string `json:"context"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}

	// Build context from cluster data
	var clusterContext string
	if body.ClusterID > 0 {
		rows, _ := database.DB.Query(`
			SELECT a.rule_name, a.severity, COALESCE(a.mitre_technique,''),
			       COALESCE(ag.hostname,'unknown'), a.created_at
			FROM alert_cluster_members acm
			JOIN alerts a ON a.id=acm.alert_id
			LEFT JOIN agents ag ON ag.id=a.agent_id
			WHERE acm.cluster_id=$1 AND a.tenant_id=$2
			ORDER BY a.created_at LIMIT 30`, body.ClusterID, tid)
		var lines []string
		if rows != nil {
			for rows.Next() {
				var rname, sev, tech, host string
				var t time.Time
				rows.Scan(&rname, &sev, &tech, &host, &t)
				lines = append(lines, fmt.Sprintf("[%s] %s | sev=%s tech=%s host=%s",
					t.Format("15:04:05"), rname, sev, tech, host))
			}
			rows.Close()
		}
		if len(lines) > 0 {
			clusterContext = "Cluster alerts (chronological):\n" + strings.Join(lines, "\n")
		}
	}

	if body.Context != "" {
		clusterContext = clusterContext + "\n\nAdditional context: " + body.Context
	}

	var prompt string
	switch body.Action {
	case "summarize":
		prompt = fmt.Sprintf(`You are a SOC analyst. Analyze this alert cluster and write a concise executive summary (2-3 sentences) explaining what happened, which systems were affected, and the likely impact. Be specific and actionable. Output ONLY a JSON object: {"summary": "...", "severity": "critical|high|medium|low", "affected_systems": ["..."], "recommendation": "..."}

%s`, clusterContext)
	case "root_cause":
		prompt = fmt.Sprintf(`You are a threat hunter. Identify the root cause and attack progression for this alert cluster. Explain: (1) initial access method, (2) entry point, (3) lateral movement technique, (4) final objective, (5) estimated business impact. Output ONLY a JSON object: {"initial_access": "...", "entry_point": "...", "lateral_movement": "...", "final_objective": "...", "impact": "...", "confidence": "high|medium|low"}

%s`, clusterContext)
	case "chain":
		prompt = fmt.Sprintf(`You are a MITRE ATT&CK expert. Map this alert sequence to an ATT&CK kill chain. Identify each stage and its technique. Output ONLY a JSON object: {"kill_chain": [{"stage": "...", "technique": "T1xxx", "evidence": "...", "tactic": "..."}], "campaign_type": "...", "threat_actor_profile": "..."}

%s`, clusterContext)
	case "campaign_detect":
		prompt = fmt.Sprintf(`You are a threat intelligence analyst. Based on these alerts, determine if this represents a known campaign. Identify: campaign type, likely threat actor, similar past campaigns, IOC patterns, and recommended response. Output ONLY a JSON object: {"campaign_name": "...", "threat_actor": "...", "confidence": "high|medium|low", "similar_campaigns": ["..."], "ioc_patterns": ["..."], "recommended_response": "..."}

%s`, clusterContext)
	default:
		c.JSON(400, gin.H{"error": "unknown action"})
		return
	}

	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// Strip markdown fences
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

// ── PostClusterBulkAction ──────────────────────────────────────────────────────

func PostClusterBulkAction(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	tid := tenantIDFromContext(c)
	var body struct {
		Action     string `json:"action"` // create_incident, close, reopen, promote
		PlaybookID int    `json:"playbook_id"`
		Note       string `json:"note"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}

	switch body.Action {
	case "close":
		database.DB.Exec(`UPDATE alert_clusters SET status='closed' WHERE id=$1 AND tenant_id=$2`, id, tid)
	case "reopen":
		database.DB.Exec(`UPDATE alert_clusters SET status='open' WHERE id=$1 AND tenant_id=$2`, id, tid)
	case "promote":
		// Force promote to incident (re-uses existing service)
		var alertCount int
		var ruleName, tech string
		database.DB.QueryRow(`SELECT alert_count, rule_name, COALESCE(mitre_technique,'') FROM alert_clusters WHERE id=$1 AND tenant_id=$2`, id, tid).
			Scan(&alertCount, &ruleName, &tech)
		title := fmt.Sprintf("[Cluster] %s × %d alerts", ruleName, alertCount)
		if tech != "" {
			title = fmt.Sprintf("[Cluster] %s (%s) × %d alerts", ruleName, tech, alertCount)
		}
		var maxSev string
		database.DB.QueryRow(`
			SELECT COALESCE(severity,'high') FROM alerts a
			JOIN alert_cluster_members acm ON acm.alert_id=a.id
			WHERE acm.cluster_id=$1
			ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END
			LIMIT 1`, id).Scan(&maxSev)
		if maxSev == "" {
			maxSev = "high"
		}
		var incidentID int
		database.DB.QueryRow(`INSERT INTO incidents (tenant_id, title, severity, status, created_by) VALUES ($1,$2,$3,'open','manual-promote') RETURNING id`,
			tid, title, maxSev).Scan(&incidentID)
		if incidentID > 0 {
			database.DB.Exec(`UPDATE alert_clusters SET auto_incident_id=$1, status='promoted' WHERE id=$2 AND tenant_id=$3`, incidentID, id, tid)
		}
	default:
		c.JSON(400, gin.H{"error": "unknown action"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "action completed", "action": body.Action})
}

// ── PostClusterMerge ───────────────────────────────────────────────────────────

func PostClusterMerge(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	tid := tenantIDFromContext(c)
	var body struct {
		MergeIntoID int    `json:"merge_into_id"`
		Note        string `json:"note"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.MergeIntoID == 0 {
		c.JSON(400, gin.H{"error": "merge_into_id required"})
		return
	}

	// Verify target cluster belongs to same tenant
	var targetCount int
	database.DB.QueryRow(`SELECT COUNT(*) FROM alert_clusters WHERE id=$1 AND tenant_id=$2`, body.MergeIntoID, tid).Scan(&targetCount)
	if targetCount == 0 {
		c.JSON(404, gin.H{"error": "target cluster not found"})
		return
	}

	// Move all members from source → target
	database.DB.Exec(`
		INSERT INTO alert_cluster_members (cluster_id, alert_id)
		SELECT $1, alert_id FROM alert_cluster_members WHERE cluster_id=$2
		ON CONFLICT DO NOTHING`, body.MergeIntoID, id)

	// Update target alert_count
	database.DB.Exec(`
		UPDATE alert_clusters SET
		  alert_count=(SELECT COUNT(*) FROM alert_cluster_members WHERE cluster_id=$1),
		  last_seen=GREATEST(last_seen,(SELECT MAX(a.created_at) FROM alert_cluster_members acm JOIN alerts a ON a.id=acm.alert_id WHERE acm.cluster_id=$1))
		WHERE id=$1`, body.MergeIntoID)

	// Mark source as suppressed (merged)
	database.DB.Exec(`UPDATE alert_clusters SET status='suppressed' WHERE id=$1 AND tenant_id=$2`, id, tid)

	c.JSON(http.StatusOK, gin.H{"message": "clusters merged", "merged_into": body.MergeIntoID})
}
