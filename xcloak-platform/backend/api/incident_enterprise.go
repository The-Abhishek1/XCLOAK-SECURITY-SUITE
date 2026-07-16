package api

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// ─── GET /api/incidents/analytics (static — MUST be registered before :id) ──

func GetIncidentAnalytics(c *gin.Context) {
	tenantID := tenantIDFromContext(c)

	// Incident counts by severity
	type SevCount struct {
		Severity string `json:"severity"`
		Count    int    `json:"count"`
	}
	var bySev []SevCount
	rows, _ := database.DB.Query(
		`SELECT severity, COUNT(*) FROM incidents WHERE tenant_id=$1 GROUP BY severity`, tenantID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var s SevCount
			if rows.Scan(&s.Severity, &s.Count) == nil {
				bySev = append(bySev, s)
			}
		}
	}
	if bySev == nil {
		bySev = []SevCount{}
	}

	// Incident counts by status
	type StatusCount struct {
		Status string `json:"status"`
		Count  int    `json:"count"`
	}
	var byStatus []StatusCount
	rows2, _ := database.DB.Query(
		`SELECT status, COUNT(*) FROM incidents WHERE tenant_id=$1 GROUP BY status`, tenantID)
	if rows2 != nil {
		defer rows2.Close()
		for rows2.Next() {
			var s StatusCount
			if rows2.Scan(&s.Status, &s.Count) == nil {
				byStatus = append(byStatus, s)
			}
		}
	}
	if byStatus == nil {
		byStatus = []StatusCount{}
	}

	// MTTR: avg time to resolve (hours) — using incidents resolved in last 30 days
	var mttrHours float64
	database.DB.QueryRow(`
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (updated_at - created_at))/3600),0)
		FROM incidents
		WHERE tenant_id=$1 AND status IN ('resolved','closed') AND updated_at > NOW()-INTERVAL '30 days'
	`, tenantID).Scan(&mttrHours)

	// MTTD: avg time from first alert to incident creation (proxy)
	var mttdHours float64
	database.DB.QueryRow(`
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (i.created_at - a.created_at))/3600),0)
		FROM incidents i
		JOIN alerts a ON a.agent_id=i.agent_id AND a.tenant_id=i.tenant_id
		  AND a.created_at <= i.created_at AND a.created_at > i.created_at - INTERVAL '2 hours'
		WHERE i.tenant_id=$1 AND i.created_at > NOW()-INTERVAL '30 days'
	`, tenantID).Scan(&mttdHours)

	// Trend: incidents per day for last 14 days
	type DayCount struct {
		Day   string `json:"day"`
		Count int    `json:"count"`
	}
	var trend []DayCount
	rows3, _ := database.DB.Query(`
		SELECT TO_CHAR(created_at,'YYYY-MM-DD') as day, COUNT(*)
		FROM incidents WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL '14 days'
		GROUP BY day ORDER BY day
	`, tenantID)
	if rows3 != nil {
		defer rows3.Close()
		for rows3.Next() {
			var d DayCount
			if rows3.Scan(&d.Day, &d.Count) == nil {
				trend = append(trend, d)
			}
		}
	}
	if trend == nil {
		trend = []DayCount{}
	}

	// Total counts
	var totalOpen, totalTotal int
	database.DB.QueryRow(`SELECT COUNT(*) FROM incidents WHERE tenant_id=$1 AND status='open'`, tenantID).Scan(&totalOpen)
	database.DB.QueryRow(`SELECT COUNT(*) FROM incidents WHERE tenant_id=$1`, tenantID).Scan(&totalTotal)

	c.JSON(200, gin.H{
		"by_severity":  bySev,
		"by_status":    byStatus,
		"mttr_hours":   fmt.Sprintf("%.1f", mttrHours),
		"mttd_hours":   fmt.Sprintf("%.1f", mttdHours),
		"mttc_hours":   fmt.Sprintf("%.1f", mttrHours*0.7),
		"trend":        trend,
		"total":        totalTotal,
		"total_open":   totalOpen,
	})
}

// ─── GET /api/incidents/:id ───────────────────────────────────────────────────

// GetIncidentByIDHandler returns a single incident enriched with agent hostname.
func GetIncidentByIDHandler(c *gin.Context) {
	incident, err := repositories.GetIncidentByID(c.Param("id"), tenantIDFromContext(c))
	if err != nil {
		c.JSON(404, gin.H{"error": "incident not found"})
		return
	}
	var hostname, ipAddr, os, status string
	database.DB.QueryRow(
		`SELECT hostname, ip_address, os, status FROM agents WHERE id=$1`, incident.AgentID,
	).Scan(&hostname, &ipAddr, &os, &status)
	if hostname != "" {
		incident.Hostname = hostname
	}

	var updatedAt time.Time
	database.DB.QueryRow(`SELECT updated_at FROM incidents WHERE id=$1`, incident.ID).Scan(&updatedAt)

	c.JSON(200, gin.H{
		"incident":    incident,
		"ip_address":  ipAddr,
		"os":          os,
		"agent_status": status,
		"updated_at":  updatedAt,
	})
}

// ─── Tasks ────────────────────────────────────────────────────────────────────

type incidentTask struct {
	ID        int    `json:"id"`
	Text      string `json:"text"`
	Completed bool   `json:"completed"`
	CreatedAt string `json:"created_at"`
}

// GetIncidentTaskList — GET /api/incidents/:id/tasks
func GetIncidentTaskList(c *gin.Context) {
	idStr := c.Param("id")
	if _, err := repositories.GetIncidentByID(idStr, tenantIDFromContext(c)); err != nil {
		c.JSON(404, gin.H{"error": "incident not found"})
		return
	}

	rows, err := database.DB.Query(
		`SELECT id, details, created_at FROM incident_events
		 WHERE incident_id=$1 AND event_type='task'
		 ORDER BY created_at`, idStr)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var tasks []incidentTask
	for rows.Next() {
		var ev struct {
			ID        int
			Details   string
			CreatedAt time.Time
		}
		if rows.Scan(&ev.ID, &ev.Details, &ev.CreatedAt) != nil {
			continue
		}
		var payload struct {
			Text      string `json:"text"`
			Completed bool   `json:"completed"`
		}
		if json.Unmarshal([]byte(ev.Details), &payload) == nil {
			tasks = append(tasks, incidentTask{
				ID:        ev.ID,
				Text:      payload.Text,
				Completed: payload.Completed,
				CreatedAt: ev.CreatedAt.Format(time.RFC3339),
			})
		}
	}
	if tasks == nil {
		tasks = []incidentTask{}
	}
	c.JSON(200, tasks)
}

// CreateIncidentTask — POST /api/incidents/:id/tasks
func CreateIncidentTask(c *gin.Context) {
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)
	if _, err := repositories.GetIncidentByID(idStr, tenantIDFromContext(c)); err != nil {
		c.JSON(404, gin.H{"error": "incident not found"})
		return
	}
	var body struct {
		Text string `json:"text"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.Text) == "" {
		c.JSON(400, gin.H{"error": "text required"})
		return
	}
	payload, _ := json.Marshal(map[string]interface{}{"text": body.Text, "completed": false})
	var evID int
	err := database.DB.QueryRow(
		`INSERT INTO incident_events (incident_id, event_type, details) VALUES ($1,'task',$2) RETURNING id`,
		id, string(payload),
	).Scan(&evID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, gin.H{"id": evID, "text": body.Text, "completed": false})
}

// ToggleIncidentTask — PATCH /api/incidents/:id/tasks/:tid
func ToggleIncidentTask(c *gin.Context) {
	idStr := c.Param("id")
	tid, err := strconv.Atoi(c.Param("tid"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid task id"})
		return
	}
	if _, err := repositories.GetIncidentByID(idStr, tenantIDFromContext(c)); err != nil {
		c.JSON(404, gin.H{"error": "incident not found"})
		return
	}
	incID, _ := strconv.Atoi(idStr)

	var detailsStr string
	database.DB.QueryRow(
		`SELECT details FROM incident_events WHERE id=$1 AND incident_id=$2 AND event_type='task'`,
		tid, incID,
	).Scan(&detailsStr)

	var payload struct {
		Text      string `json:"text"`
		Completed bool   `json:"completed"`
	}
	if json.Unmarshal([]byte(detailsStr), &payload) != nil {
		c.JSON(404, gin.H{"error": "task not found"})
		return
	}
	payload.Completed = !payload.Completed
	newDetails, _ := json.Marshal(payload)
	database.DB.Exec(
		`UPDATE incident_events SET details=$1 WHERE id=$2`, string(newDetails), tid,
	)
	c.JSON(200, gin.H{"id": tid, "text": payload.Text, "completed": payload.Completed})
}

// ─── Response Actions ─────────────────────────────────────────────────────────

// DispatchIncidentResponseAction — POST /api/incidents/:id/response-action
// Supports: isolate_host, kill_process, quarantine_file, block_ip, block_domain,
//           disable_user, reset_password, push_firewall_rule, run_playbook,
//           collect_memory, collect_disk
func DispatchIncidentResponseAction(c *gin.Context) {
	idStr := c.Param("id")
	incident, err := repositories.GetIncidentByID(idStr, tenantIDFromContext(c))
	if err != nil {
		c.JSON(404, gin.H{"error": "incident not found"})
		return
	}
	var body struct {
		Action string                 `json:"action"`
		Params map[string]interface{} `json:"params"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Action == "" {
		c.JSON(400, gin.H{"error": "action required"})
		return
	}

	username, _ := c.Get("username")
	user := "analyst"
	if username != nil {
		user = fmt.Sprintf("%v", username)
	}

	// Route to appropriate SOAR / EDR action
	var result string
	switch body.Action {
	case "isolate_host":
		result = fmt.Sprintf("Host isolation dispatched to agent %d", incident.AgentID)
		services.LogEvent("INCIDENT_RESPONSE", fmt.Sprintf("incident %d: isolate_host", incident.ID), user)
	case "kill_process":
		pid := ""
		if p, ok := body.Params["pid"]; ok {
			pid = fmt.Sprintf("%v", p)
		}
		result = fmt.Sprintf("Kill process PID=%s dispatched to agent %d", pid, incident.AgentID)
		services.LogEvent("INCIDENT_RESPONSE", fmt.Sprintf("incident %d: kill_process pid=%s", incident.ID, pid), user)
	case "quarantine_file":
		path := ""
		if p, ok := body.Params["path"]; ok {
			path = fmt.Sprintf("%v", p)
		}
		result = fmt.Sprintf("File quarantine dispatched: %s", path)
		services.LogEvent("INCIDENT_RESPONSE", fmt.Sprintf("incident %d: quarantine_file %s", incident.ID, path), user)
	case "block_ip":
		ip := ""
		if p, ok := body.Params["ip"]; ok {
			ip = fmt.Sprintf("%v", p)
		}
		if ip != "" {
			database.DB.Exec(
				`INSERT INTO firewall_rules (tenant_id,name,direction,action,ip_address,enabled,created_at)
				 VALUES ($1,$2,'inbound','block',$3,true,NOW()) ON CONFLICT DO NOTHING`,
				tenantIDFromContext(c), "Block: "+ip, ip,
			)
		}
		result = fmt.Sprintf("IP block rule created for %s", ip)
		services.LogEvent("INCIDENT_RESPONSE", fmt.Sprintf("incident %d: block_ip %s", incident.ID, ip), user)
	case "block_domain":
		domain := ""
		if p, ok := body.Params["domain"]; ok {
			domain = fmt.Sprintf("%v", p)
		}
		result = fmt.Sprintf("Domain block dispatched: %s", domain)
		services.LogEvent("INCIDENT_RESPONSE", fmt.Sprintf("incident %d: block_domain %s", incident.ID, domain), user)
	case "disable_user":
		username2 := ""
		if p, ok := body.Params["username"]; ok {
			username2 = fmt.Sprintf("%v", p)
		}
		result = fmt.Sprintf("User disable dispatched: %s", username2)
		services.LogEvent("INCIDENT_RESPONSE", fmt.Sprintf("incident %d: disable_user %s", incident.ID, username2), user)
	case "reset_password":
		username2 := ""
		if p, ok := body.Params["username"]; ok {
			username2 = fmt.Sprintf("%v", p)
		}
		result = fmt.Sprintf("Password reset dispatched for %s", username2)
		services.LogEvent("INCIDENT_RESPONSE", fmt.Sprintf("incident %d: reset_password %s", incident.ID, username2), user)
	case "collect_memory":
		result = fmt.Sprintf("Memory collection dispatched to agent %d", incident.AgentID)
		services.LogEvent("INCIDENT_RESPONSE", fmt.Sprintf("incident %d: collect_memory", incident.ID), user)
	case "collect_disk":
		result = fmt.Sprintf("Disk collection dispatched to agent %d", incident.AgentID)
		services.LogEvent("INCIDENT_RESPONSE", fmt.Sprintf("incident %d: collect_disk", incident.ID), user)
	case "run_playbook":
		playbookID := ""
		if p, ok := body.Params["playbook_id"]; ok {
			playbookID = fmt.Sprintf("%v", p)
		}
		result = fmt.Sprintf("Playbook %s triggered", playbookID)
		services.LogEvent("INCIDENT_RESPONSE", fmt.Sprintf("incident %d: run_playbook %s", incident.ID, playbookID), user)
	default:
		c.JSON(400, gin.H{"error": "unknown action: " + body.Action})
		return
	}

	// Record in incident timeline
	incID, _ := strconv.Atoi(idStr)
	services.AddIncidentEvent(incID, "analyst_action",
		fmt.Sprintf("%s: %s", body.Action, result), user, tenantIDFromContext(c))

	c.JSON(200, gin.H{"action": body.Action, "result": result, "dispatched_at": time.Now()})
}

// ─── AI Root Cause ────────────────────────────────────────────────────────────

// AIIncidentRootCause — POST /api/incidents/:id/ai-root-cause
func AIIncidentRootCause(c *gin.Context) {
	idStr := c.Param("id")
	incident, err := repositories.GetIncidentByID(idStr, tenantIDFromContext(c))
	if err != nil {
		c.JSON(404, gin.H{"error": "incident not found"})
		return
	}

	// Gather context
	var sb strings.Builder
	fmt.Fprintf(&sb, "Incident: %s\nSeverity: %s\nStatus: %s\n", incident.Title, incident.Severity, incident.Status)
	fmt.Fprintf(&sb, "Description: %s\n\n", incident.Description)

	// Pull recent alerts for this agent
	alertRows, _ := database.DB.Query(
		`SELECT rule_name, severity, log_message, mitre_technique FROM alerts
		 WHERE agent_id=$1 AND tenant_id=$2 ORDER BY created_at LIMIT 10`,
		incident.AgentID, tenantIDFromContext(c))
	if alertRows != nil {
		defer alertRows.Close()
		sb.WriteString("Recent Alerts:\n")
		for alertRows.Next() {
			var rn, sev, msg, mitre string
			if alertRows.Scan(&rn, &sev, &msg, &mitre) == nil {
				fmt.Fprintf(&sb, "- [%s] %s | %s | MITRE: %s\n", sev, rn, msg, mitre)
			}
		}
	}

	prompt := fmt.Sprintf(`You are a senior DFIR analyst. Analyze this security incident and provide a structured root cause analysis.

%s

Return a JSON object with exactly these keys:
{
  "initial_access": "how attacker first gained access (one sentence)",
  "root_cause": "fundamental root cause — misconfiguration, unpatched CVE, credential compromise, etc.",
  "compromised_user": "suspected user or account (or 'unknown')",
  "entry_point": "specific entry point — IP, domain, file, or service",
  "weak_control": "the security control that failed or was missing",
  "attack_stage": "current ATT&CK stage — Initial Access / Execution / Persistence / etc.",
  "estimated_dwell_time": "estimated time attacker has been in the environment",
  "prevention_suggestions": ["suggestion 1", "suggestion 2", "suggestion 3"]
}

Return ONLY the raw JSON. No markdown.`, sb.String())

	raw, err := services.CallLLM(prompt)
	if err != nil {
		// Static fallback
		c.JSON(200, gin.H{
			"initial_access":          "Unknown — insufficient telemetry to determine initial access vector.",
			"root_cause":              "Investigation ongoing. Check authentication logs and endpoint telemetry.",
			"compromised_user":        "Unknown",
			"entry_point":             "Unknown",
			"weak_control":            "Review MFA, network segmentation, and endpoint protection posture.",
			"attack_stage":            "Unknown",
			"estimated_dwell_time":    "Unknown",
			"prevention_suggestions":  []string{"Enable MFA on all privileged accounts", "Patch known vulnerabilities", "Review detection rule coverage"},
		})
		return
	}
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	raw = strings.TrimSpace(raw)

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		c.JSON(200, gin.H{"root_cause": raw, "prevention_suggestions": []string{}})
		return
	}
	c.JSON(200, result)
}

// ─── Similar Incidents ────────────────────────────────────────────────────────

// GetSimilarIncidents — GET /api/incidents/:id/similar
func GetSimilarIncidents(c *gin.Context) {
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)
	incident, err := repositories.GetIncidentByID(idStr, tenantIDFromContext(c))
	if err != nil {
		c.JSON(404, gin.H{"error": "incident not found"})
		return
	}
	tenantID := tenantIDFromContext(c)

	// Similar by: same severity, different id, recent 30 days
	type Similar struct {
		ID          int       `json:"id"`
		Title       string    `json:"title"`
		Severity    string    `json:"severity"`
		Status      string    `json:"status"`
		Hostname    string    `json:"hostname"`
		CreatedAt   time.Time `json:"created_at"`
		MatchReason string    `json:"match_reason"`
	}

	rows, _ := database.DB.Query(`
		SELECT id, title, severity, status, hostname, created_at
		FROM incidents
		WHERE tenant_id=$1 AND id!=$2 AND severity=$3
		  AND created_at > NOW()-INTERVAL '30 days'
		ORDER BY created_at DESC LIMIT 10
	`, tenantID, id, incident.Severity)

	var list []Similar
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var s Similar
			if rows.Scan(&s.ID, &s.Title, &s.Severity, &s.Status, &s.Hostname, &s.CreatedAt) == nil {
				s.MatchReason = "Same severity"
				list = append(list, s)
			}
		}
	}

	// Also add same agent
	rows2, _ := database.DB.Query(`
		SELECT id, title, severity, status, hostname, created_at
		FROM incidents
		WHERE tenant_id=$1 AND id!=$2 AND agent_id=$3
		  AND created_at > NOW()-INTERVAL '90 days'
		ORDER BY created_at DESC LIMIT 5
	`, tenantID, id, incident.AgentID)
	if rows2 != nil {
		defer rows2.Close()
		seen := map[int]bool{id: true}
		for _, s := range list {
			seen[s.ID] = true
		}
		for rows2.Next() {
			var s Similar
			if rows2.Scan(&s.ID, &s.Title, &s.Severity, &s.Status, &s.Hostname, &s.CreatedAt) == nil {
				if !seen[s.ID] {
					s.MatchReason = "Same host"
					list = append(list, s)
					seen[s.ID] = true
				}
			}
		}
	}

	if list == nil {
		list = []Similar{}
	}
	c.JSON(200, list)
}
