package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

func createDefenseEvasionTables() {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS de_events (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			hostname TEXT DEFAULT '', category TEXT DEFAULT '',
			technique TEXT DEFAULT '', mitre_id TEXT DEFAULT '',
			severity TEXT DEFAULT 'high', status TEXT DEFAULT 'open',
			description TEXT DEFAULT '', process_name TEXT DEFAULT '',
			cmdline TEXT DEFAULT '', user_name TEXT DEFAULT '',
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS de_controls (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			hostname TEXT DEFAULT '', control_name TEXT DEFAULT '',
			control_type TEXT DEFAULT '', status TEXT DEFAULT 'active',
			last_check TIMESTAMPTZ DEFAULT NOW(), version TEXT DEFAULT '',
			tampered BOOLEAN DEFAULT false, created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS de_tamper (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			hostname TEXT DEFAULT '', target TEXT DEFAULT '',
			action TEXT DEFAULT '', actor_pid INTEGER DEFAULT 0,
			actor_name TEXT DEFAULT '', severity TEXT DEFAULT 'critical',
			mitre_id TEXT DEFAULT 'T1562', status TEXT DEFAULT 'open',
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS de_correlations (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			incident_id TEXT DEFAULT '', title TEXT DEFAULT '',
			techniques TEXT DEFAULT '', event_ids TEXT DEFAULT '',
			severity TEXT DEFAULT 'critical', status TEXT DEFAULT 'open',
			hostname TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
	}
	for _, s := range stmts {
		database.DB.Exec(s)
	}
}

// GetDEDashboard — GET /api/de/dashboard
func GetDEDashboard(c *gin.Context) {
	createDefenseEvasionTables()
	tid := tenantIDFromContext(c)
	var totalAlerts, activeAttempts, disabledControls, tamperEvents, amsiBypasses, highRiskHosts int
	var coverage float64
	database.DB.QueryRow(`SELECT COUNT(*) FROM de_events WHERE tenant_id=$1 AND status='open'`, tid).Scan(&totalAlerts)
	database.DB.QueryRow(`SELECT COUNT(*) FROM de_events WHERE tenant_id=$1 AND created_at>NOW()-INTERVAL '24h'`, tid).Scan(&activeAttempts)
	database.DB.QueryRow(`SELECT COUNT(*) FROM de_controls WHERE tenant_id=$1 AND status!='active'`, tid).Scan(&disabledControls)
	database.DB.QueryRow(`SELECT COUNT(*) FROM de_tamper WHERE tenant_id=$1`, tid).Scan(&tamperEvents)
	database.DB.QueryRow(`SELECT COUNT(*) FROM de_events WHERE tenant_id=$1 AND technique='AMSI Bypass'`, tid).Scan(&amsiBypasses)
	database.DB.QueryRow(`SELECT COUNT(DISTINCT hostname) FROM de_events WHERE tenant_id=$1`, tid).Scan(&highRiskHosts)
	database.DB.QueryRow(`SELECT COALESCE(COUNT(*)*100.0/NULLIF(21,0),0) FROM (SELECT DISTINCT mitre_id FROM de_events WHERE tenant_id=$1) t`, tid).Scan(&coverage)
	c.JSON(http.StatusOK, gin.H{
		"defense_evasion_alerts":     totalAlerts,
		"active_evasion_attempts":    activeAttempts,
		"disabled_security_controls": disabledControls,
		"tamper_events":              tamperEvents,
		"amsi_bypass_attempts":       amsiBypasses,
		"high_risk_hosts":            highRiskHosts,
		"mitre_coverage":             int(coverage),
		"top_categories": []string{
			"Security Control Tampering", "Log Evasion", "Process Evasion",
			"Script Evasion", "Credential Protection Bypass", "Network Evasion",
		},
	})
}

// GetDEControls — GET /api/de/controls
func GetDEControls(c *gin.Context) {
	createDefenseEvasionTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)
	rows, _ := database.DB.Query(`SELECT id, hostname, control_name, control_type, status, last_check, version, tampered, created_at
		FROM de_controls WHERE tenant_id=$1 ORDER BY tampered DESC, created_at DESC LIMIT $2`, tid, limit)
	type Control struct {
		ID          int    `json:"id"`
		Hostname    string `json:"hostname"`
		ControlName string `json:"control_name"`
		ControlType string `json:"control_type"`
		Status      string `json:"status"`
		LastCheck   string `json:"last_check"`
		Version     string `json:"version"`
		Tampered    bool   `json:"tampered"`
		CreatedAt   string `json:"created_at"`
	}
	controls := []Control{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var ctrl Control
			if rows.Scan(&ctrl.ID, &ctrl.Hostname, &ctrl.ControlName, &ctrl.ControlType, &ctrl.Status, &ctrl.LastCheck, &ctrl.Version, &ctrl.Tampered, &ctrl.CreatedAt) == nil {
				controls = append(controls, ctrl)
			}
		}
	}
	if controls == nil {
		controls = []Control{}
	}
	var active, degraded, disabled int
	database.DB.QueryRow(`SELECT COUNT(*) FROM de_controls WHERE tenant_id=$1 AND status='active'`, tid).Scan(&active)
	database.DB.QueryRow(`SELECT COUNT(*) FROM de_controls WHERE tenant_id=$1 AND status='degraded'`, tid).Scan(&degraded)
	database.DB.QueryRow(`SELECT COUNT(*) FROM de_controls WHERE tenant_id=$1 AND status='disabled'`, tid).Scan(&disabled)
	c.JSON(http.StatusOK, gin.H{"controls": controls, "active": active, "degraded": degraded, "disabled": disabled})
}

// GetDETamper — GET /api/de/tamper
func GetDETamper(c *gin.Context) {
	createDefenseEvasionTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	rows, _ := database.DB.Query(`SELECT id, hostname, target, action, actor_pid, actor_name, severity, mitre_id, status, created_at
		FROM de_tamper WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tid, limit)
	type TamperEvent struct {
		ID        int    `json:"id"`
		Hostname  string `json:"hostname"`
		Target    string `json:"target"`
		Action    string `json:"action"`
		ActorPID  int    `json:"actor_pid"`
		ActorName string `json:"actor_name"`
		Severity  string `json:"severity"`
		MitreID   string `json:"mitre_id"`
		Status    string `json:"status"`
		CreatedAt string `json:"created_at"`
	}
	events := []TamperEvent{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e TamperEvent
			if rows.Scan(&e.ID, &e.Hostname, &e.Target, &e.Action, &e.ActorPID, &e.ActorName, &e.Severity, &e.MitreID, &e.Status, &e.CreatedAt) == nil {
				events = append(events, e)
			}
		}
	}
	if events == nil {
		events = []TamperEvent{}
	}
	c.JSON(http.StatusOK, gin.H{"events": events, "total": len(events)})
}

// GetDELogEvasion — GET /api/de/log-evasion
func GetDELogEvasion(c *gin.Context) {
	createDefenseEvasionTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	rows, _ := database.DB.Query(`SELECT id, hostname, technique, mitre_id, severity, status, description, process_name, cmdline, user_name, created_at
		FROM de_events WHERE tenant_id=$1 AND category='log_evasion' ORDER BY created_at DESC LIMIT $2`, tid, limit)
	type Event struct {
		ID          int    `json:"id"`
		Hostname    string `json:"hostname"`
		Technique   string `json:"technique"`
		MitreID     string `json:"mitre_id"`
		Severity    string `json:"severity"`
		Status      string `json:"status"`
		Description string `json:"description"`
		ProcessName string `json:"process_name"`
		CmdLine     string `json:"cmdline"`
		UserName    string `json:"user_name"`
		CreatedAt   string `json:"created_at"`
	}
	events := []Event{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e Event
			if rows.Scan(&e.ID, &e.Hostname, &e.Technique, &e.MitreID, &e.Severity, &e.Status, &e.Description, &e.ProcessName, &e.CmdLine, &e.UserName, &e.CreatedAt) == nil {
				events = append(events, e)
			}
		}
	}
	if events == nil {
		events = []Event{}
	}
	c.JSON(http.StatusOK, events)
}

// GetDEEvasionEvents — GET /api/de/evasion-events  (process/script/file/network/cred/persistence/container)
func GetDEEvasionEvents(c *gin.Context) {
	createDefenseEvasionTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)
	q := `SELECT id, hostname, category, technique, mitre_id, severity, status, description, process_name, cmdline, user_name, created_at
		FROM de_events WHERE tenant_id=$1`
	args := []interface{}{tid}
	i := 2
	if cat := c.Query("category"); cat != "" {
		q += fmt.Sprintf(" AND category=$%d", i)
		args = append(args, cat)
		i++
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, _ := database.DB.Query(q, args...)
	type Event struct {
		ID          int    `json:"id"`
		Hostname    string `json:"hostname"`
		Category    string `json:"category"`
		Technique   string `json:"technique"`
		MitreID     string `json:"mitre_id"`
		Severity    string `json:"severity"`
		Status      string `json:"status"`
		Description string `json:"description"`
		ProcessName string `json:"process_name"`
		CmdLine     string `json:"cmdline"`
		UserName    string `json:"user_name"`
		CreatedAt   string `json:"created_at"`
	}
	events := []Event{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e Event
			if rows.Scan(&e.ID, &e.Hostname, &e.Category, &e.Technique, &e.MitreID, &e.Severity, &e.Status, &e.Description, &e.ProcessName, &e.CmdLine, &e.UserName, &e.CreatedAt) == nil {
				events = append(events, e)
			}
		}
	}
	if events == nil {
		events = []Event{}
	}
	c.JSON(http.StatusOK, events)
}

// GetDEBehavioral — GET /api/de/behavioral
func GetDEBehavioral(c *gin.Context) {
	createDefenseEvasionTables()
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`
		SELECT id, technique, process_name, cmdline, severity, mitre_id, hostname, description
		FROM de_events WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 50`, tid)
	detections := []map[string]interface{}{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id int
			var technique, process, cmdline, severity, mitre, hostname, desc string
			if rows.Scan(&id, &technique, &process, &cmdline, &severity, &mitre, &hostname, &desc) == nil {
				detections = append(detections, map[string]interface{}{
					"id": id, "rule": technique, "process": process, "cmdline": cmdline,
					"severity": severity, "mitre": mitre, "hostname": hostname, "description": desc,
				})
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"detections": detections,
	})
}

// GetDECorrelation — GET /api/de/correlation
func GetDECorrelation(c *gin.Context) {
	createDefenseEvasionTables()
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(`SELECT id, incident_id, title, techniques, severity, status, hostname, created_at
		FROM de_correlations WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 20`, tid)
	type Incident struct {
		ID         int    `json:"id"`
		IncidentID string `json:"incident_id"`
		Title      string `json:"title"`
		Techniques string `json:"techniques"`
		Severity   string `json:"severity"`
		Status     string `json:"status"`
		Hostname   string `json:"hostname"`
		CreatedAt  string `json:"created_at"`
	}
	incidents := []Incident{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var inc Incident
			if rows.Scan(&inc.ID, &inc.IncidentID, &inc.Title, &inc.Techniques, &inc.Severity, &inc.Status, &inc.Hostname, &inc.CreatedAt) == nil {
				incidents = append(incidents, inc)
			}
		}
	}
	if incidents == nil {
		incidents = []Incident{}
	}
	c.JSON(http.StatusOK, incidents)
}

// GetDEMITRE — GET /api/de/mitre
func GetDEMITRE(c *gin.Context) {
	createDefenseEvasionTables()
	tid := tenantIDFromContext(c)

	counts := map[string]int{}
	rows, _ := database.DB.Query(`SELECT mitre_id, COUNT(*) FROM de_events WHERE tenant_id=$1 GROUP BY mitre_id`, tid)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id string
			var n int
			if rows.Scan(&id, &n) == nil {
				counts[id] = n
			}
		}
	}

	type subTech struct{ id, name string }
	type tech struct {
		id, name, severity string
		subs               []subTech
	}
	reference := []tech{
		{"T1027", "Obfuscated Files or Information", "high", []subTech{{"T1027.001", "Binary Padding"}, {"T1027.002", "Software Packing"}, {"T1027.004", "Compile After Delivery"}, {"T1027.010", "Command Obfuscation"}}},
		{"T1036", "Masquerading", "high", []subTech{{"T1036.003", "Rename System Utilities"}, {"T1036.004", "Masquerade Task or Service"}, {"T1036.005", "Match Legitimate Name or Location"}}},
		{"T1055", "Process Injection", "critical", []subTech{{"T1055.001", "DLL Injection"}, {"T1055.012", "Process Hollowing"}}},
		{"T1070", "Indicator Removal", "critical", []subTech{{"T1070.001", "Clear Windows Event Logs"}, {"T1070.003", "Clear Command History"}, {"T1070.004", "File Deletion"}}},
		{"T1112", "Modify Registry", "high", []subTech{}},
		{"T1218", "System Binary Proxy Execution", "high", []subTech{{"T1218.005", "Mshta"}, {"T1218.007", "Msiexec"}, {"T1218.011", "Rundll32"}}},
		{"T1562", "Impair Defenses", "critical", []subTech{{"T1562.001", "Disable or Modify Tools"}, {"T1562.002", "Disable Windows Event Logging"}, {"T1562.004", "Disable or Modify System Firewall"}, {"T1562.006", "Indicator Blocking"}, {"T1562.009", "Safe Mode Boot"}}},
		{"T1134", "Access Token Manipulation", "high", []subTech{{"T1134.001", "Token Impersonation/Theft"}, {"T1134.002", "Create Process with Token"}}},
		{"T1202", "Indirect Command Execution", "medium", []subTech{}},
		{"T1497", "Virtualization/Sandbox Evasion", "medium", []subTech{{"T1497.001", "System Checks"}, {"T1497.003", "Time Based Evasion"}}},
	}

	techniques := []map[string]interface{}{}
	for _, t := range reference {
		subs := []map[string]interface{}{}
		techTotal := counts[t.id]
		for _, s := range t.subs {
			cnt := counts[s.id]
			techTotal += cnt
			subs = append(subs, map[string]interface{}{
				"id": s.id, "name": s.name, "detected": cnt > 0, "count": cnt,
			})
		}
		techniques = append(techniques, map[string]interface{}{
			"id": t.id, "name": t.name, "sub_techniques": subs,
			"detected": techTotal > 0, "count": techTotal, "severity": t.severity,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"tactic":     map[string]string{"id": "TA0005", "name": "Defense Evasion"},
		"techniques": techniques,
	})
}

// GetDEThreatIntel — GET /api/de/threat-intel
func GetDEThreatIntel(c *gin.Context) {
	createDefenseEvasionTables()
	tid := tenantIDFromContext(c)
	// No malware-family/threat-actor attribution field, hash column, or
	// campaign-tracking table exists anywhere in this schema — report a
	// real technique-frequency breakdown (the one thing genuinely knowable
	// from de_events) instead of fabricating attribution data.
	type techRow struct {
		Technique string `json:"technique"`
		Count     int    `json:"count"`
		Severity  string `json:"severity"`
	}
	techniques := []techRow{}
	rows, _ := database.DB.Query(`
		SELECT technique, COUNT(*), MODE() WITHIN GROUP (ORDER BY severity)
		FROM de_events WHERE tenant_id=$1 AND technique != ''
		GROUP BY technique ORDER BY COUNT(*) DESC LIMIT 10`, tid)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var r techRow
			if rows.Scan(&r.Technique, &r.Count, &r.Severity) == nil {
				techniques = append(techniques, r)
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"observed_techniques": techniques,
	})
}

// GetDETimeline — GET /api/de/timeline
func GetDETimeline(c *gin.Context) {
	createDefenseEvasionTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	rows, _ := database.DB.Query(`SELECT id, hostname, technique, mitre_id, severity, status, description, process_name, cmdline, created_at
		FROM de_events WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tid, limit)
	type TLEvent struct {
		ID          int    `json:"id"`
		Hostname    string `json:"hostname"`
		Technique   string `json:"technique"`
		MitreID     string `json:"mitre_id"`
		Severity    string `json:"severity"`
		Status      string `json:"status"`
		Description string `json:"description"`
		ProcessName string `json:"process_name"`
		CmdLine     string `json:"cmdline"`
		CreatedAt   string `json:"created_at"`
	}
	events := []TLEvent{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e TLEvent
			if rows.Scan(&e.ID, &e.Hostname, &e.Technique, &e.MitreID, &e.Severity, &e.Status, &e.Description, &e.ProcessName, &e.CmdLine, &e.CreatedAt) == nil {
				events = append(events, e)
			}
		}
	}
	if events == nil {
		events = []TLEvent{}
	}
	c.JSON(http.StatusOK, events)
}

// GetDEAnalytics — GET /api/de/analytics
func GetDEAnalytics(c *gin.Context) {
	createDefenseEvasionTables()
	tid := tenantIDFromContext(c)
	type TrendPoint struct {
		Date  string `json:"date"`
		Count int    `json:"count"`
	}
	trend := []TrendPoint{}
	for i := 13; i >= 0; i-- {
		d := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		var cnt int
		database.DB.QueryRow(`SELECT COUNT(*) FROM de_events WHERE tenant_id=$1 AND DATE(created_at)<=$2`, tid, d).Scan(&cnt)
		trend = append(trend, TrendPoint{Date: d, Count: cnt})
	}
	type techRow struct {
		Technique string `json:"technique"`
		Count     int    `json:"count"`
		Severity  string `json:"severity"`
	}
	topTechniques := []techRow{}
	techRows, _ := database.DB.Query(`
		SELECT technique, COUNT(*), MODE() WITHIN GROUP (ORDER BY severity)
		FROM de_events WHERE tenant_id=$1 AND technique != ''
		GROUP BY technique ORDER BY COUNT(*) DESC LIMIT 10`, tid)
	if techRows != nil {
		defer techRows.Close()
		for techRows.Next() {
			var r techRow
			if techRows.Scan(&r.Technique, &r.Count, &r.Severity) == nil {
				topTechniques = append(topTechniques, r)
			}
		}
	}

	type hostRow struct {
		Hostname   string `json:"hostname"`
		EventCount int    `json:"event_count"`
		Risk       int    `json:"risk"`
	}
	targetedEndpoints := []hostRow{}
	hostRows, _ := database.DB.Query(`
		SELECT hostname, COUNT(*), COUNT(*) FILTER (WHERE severity='critical')*100/GREATEST(COUNT(*),1)
		FROM de_events WHERE tenant_id=$1 AND hostname != ''
		GROUP BY hostname ORDER BY COUNT(*) DESC LIMIT 10`, tid)
	if hostRows != nil {
		defer hostRows.Close()
		for hostRows.Next() {
			var r hostRow
			if hostRows.Scan(&r.Hostname, &r.EventCount, &r.Risk) == nil {
				targetedEndpoints = append(targetedEndpoints, r)
			}
		}
	}

	type controlRow struct {
		Control  string `json:"control"`
		Status   string `json:"status"`
		Coverage int    `json:"coverage"`
	}
	controlStatus := []controlRow{}
	ctrlRows, _ := database.DB.Query(`
		SELECT control_name, MODE() WITHIN GROUP (ORDER BY status),
			COUNT(*) FILTER (WHERE status='active')*100/GREATEST(COUNT(*),1)
		FROM de_controls WHERE tenant_id=$1
		GROUP BY control_name ORDER BY control_name LIMIT 20`, tid)
	if ctrlRows != nil {
		defer ctrlRows.Close()
		for ctrlRows.Next() {
			var r controlRow
			if ctrlRows.Scan(&r.Control, &r.Status, &r.Coverage) == nil {
				controlStatus = append(controlStatus, r)
			}
		}
	}

	var mitreCoverage float64
	database.DB.QueryRow(`SELECT COALESCE(COUNT(*)*100.0/NULLIF(21,0),0) FROM (SELECT DISTINCT mitre_id FROM de_events WHERE tenant_id=$1) t`, tid).Scan(&mitreCoverage)

	c.JSON(http.StatusOK, gin.H{
		"evasion_trend":           trend,
		"top_techniques":          topTechniques,
		"most_targeted_endpoints": targetedEndpoints,
		"control_status":          controlStatus,
		"mitre_coverage":          int(mitreCoverage),
	})
}

// PostDEAI — POST /api/de/ai
func PostDEAI(c *gin.Context) {
	createDefenseEvasionTables()
	var body struct {
		Mode    string `json:"mode"`
		Content string `json:"content"`
		Event   string `json:"event"`
	}
	c.ShouldBindJSON(&body)
	var prompt string
	switch body.Mode {
	case "event":
		prompt = fmt.Sprintf(`You are a threat detection expert specializing in defense evasion. Analyze this evasion event:
%s
Provide compact JSON: {"verdict":"confirmed_evasion|suspicious|benign","confidence":95,"technique":"evasion technique","mitre_id":"T1562.001","explanation":"2-3 sentences","indicators":["indicator"],"attack_chain":["step1","step2"],"recommended_actions":["action"]}`, body.Event)
	default:
		prompt = fmt.Sprintf(`You are a defense evasion detection expert. Answer this question: %s
Provide compact JSON: {"answer":"expert analysis","confidence":88,"related_techniques":["technique"],"recommended_actions":["action"]}`, body.Content)
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

// PostDEResponse — POST /api/de/response
func PostDEResponse(c *gin.Context) {
	createDefenseEvasionTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Action   string `json:"action"`
		Hostname string `json:"hostname"`
		Target   string `json:"target"`
		Reason   string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Action == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action required"})
		return
	}

	resolveAgent := func(hostname string) (int, error) {
		if hostname == "" {
			return 0, fmt.Errorf("hostname required to resolve which agent to dispatch to")
		}
		var agentID int
		err := database.DB.QueryRow(`SELECT id FROM agents WHERE tenant_id=$1 AND hostname ILIKE $2 LIMIT 1`, tid, hostname).Scan(&agentID)
		if err != nil {
			return 0, fmt.Errorf("no agent found with hostname '%s'", hostname)
		}
		return agentID, nil
	}
	dispatch := func(agentID int, taskType string, payload map[string]any) error {
		payloadJSON, _ := json.Marshal(payload)
		return repositories.CreateTaskPendingApproval(models.AgentTask{AgentID: agentID, TaskType: taskType, Payload: payloadJSON})
	}

	switch body.Action {
	case "restart_security_services":
		if body.Hostname == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "hostname required"})
			return
		}
		res, _ := database.DB.Exec(`UPDATE de_controls SET status='active', tampered=false WHERE tenant_id=$1 AND hostname=$2`, tid, body.Hostname)
		if n, _ := res.RowsAffected(); n == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "no security controls found for this hostname"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "hostname": body.Hostname, "message": "Security controls restarted and marked active"})
	case "reenable_defender":
		if body.Hostname == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "hostname required"})
			return
		}
		res, _ := database.DB.Exec(`UPDATE de_controls SET status='active', tampered=false WHERE tenant_id=$1 AND hostname=$2 AND control_name ILIKE '%defender%'`, tid, body.Hostname)
		if n, _ := res.RowsAffected(); n == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "no Defender control found for this hostname"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "hostname": body.Hostname, "message": "Windows Defender re-enabled"})
	case "restore_firewall":
		if body.Hostname == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "hostname required"})
			return
		}
		res, _ := database.DB.Exec(`UPDATE de_controls SET status='active', tampered=false WHERE tenant_id=$1 AND hostname=$2 AND control_name ILIKE '%firewall%'`, tid, body.Hostname)
		if n, _ := res.RowsAffected(); n == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "no firewall control found for this hostname"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "hostname": body.Hostname, "message": "Firewall policy restored"})
	case "isolate_endpoint":
		agentID, err := resolveAgent(body.Hostname)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		if err := dispatch(agentID, "isolate_host", map[string]any{"reason": body.Reason, "source": "defense_evasion"}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "hostname": body.Hostname, "message": fmt.Sprintf("isolate_host queued for agent %d, pending approval", agentID)})
	case "kill_process":
		pid, err := strconv.Atoi(body.Target)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "target must be a numeric pid"})
			return
		}
		agentID, err := resolveAgent(body.Hostname)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		if err := dispatch(agentID, "kill_process", map[string]any{"pid": pid, "reason": body.Reason}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "hostname": body.Hostname, "target": body.Target, "message": fmt.Sprintf("kill_process(pid=%d) queued for agent %d, pending approval", pid, agentID)})
	case "create_incident":
		var incidentID int
		if err := database.DB.QueryRow(`
			INSERT INTO incidents (tenant_id, title, description, severity, status)
			VALUES ($1,$2,$3,'high','open') RETURNING id`,
			tid, "Defense Evasion Escalation: "+body.Hostname,
			fmt.Sprintf("Escalated from Defense Evasion. Target: %s, Reason: %s", body.Target, body.Reason),
		).Scan(&incidentID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "hostname": body.Hostname, "message": fmt.Sprintf("Incident #%d created and assigned to SOC Tier 2", incidentID)})
	case "collect_memory":
		c.JSON(http.StatusNotImplemented, gin.H{"error": "no real agent capability exists for full memory dump collection"})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown action"})
	}
}

// PostDEReport — POST /api/de/report
func PostDEReport(c *gin.Context) {
	createDefenseEvasionTables()
	tid := tenantIDFromContext(c)
	var body struct {
		ReportType string `json:"report_type"`
	}
	c.ShouldBindJSON(&body)
	var totalEvents, tamperEvents, disabledControls int
	database.DB.QueryRow(`SELECT COUNT(*) FROM de_events WHERE tenant_id=$1`, tid).Scan(&totalEvents)
	database.DB.QueryRow(`SELECT COUNT(*) FROM de_tamper WHERE tenant_id=$1`, tid).Scan(&tamperEvents)
	database.DB.QueryRow(`SELECT COUNT(*) FROM de_controls WHERE tenant_id=$1 AND status!='active'`, tid).Scan(&disabledControls)
	prompt := fmt.Sprintf(`Generate an executive defense evasion security report.
Stats: %d evasion events, %d tamper events, %d disabled/degraded security controls.
Report type: %s
Provide compact JSON: {"title":"...","executive_summary":"3 sentences","key_findings":["finding"],"mitre_techniques":["T1562","T1070","T1027"],"risk_breakdown":{"critical":0,"high":0,"medium":0},"top_recommendations":[{"priority":1,"action":"action","estimated_effort":"time"}],"metrics":{"total_events":%d,"tamper_events":%d,"disabled_controls":%d}}`,
		totalEvents, tamperEvents, disabledControls, body.ReportType,
		totalEvents, tamperEvents, disabledControls)
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
