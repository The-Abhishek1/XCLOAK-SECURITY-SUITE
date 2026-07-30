package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

func createProcessInjectionTables() {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS pi_processes (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			agent_id TEXT DEFAULT '', hostname TEXT DEFAULT '',
			name TEXT DEFAULT '', pid INTEGER DEFAULT 0,
			ppid INTEGER DEFAULT 0, username TEXT DEFAULT '',
			cmdline TEXT DEFAULT '', path TEXT DEFAULT '',
			signature TEXT DEFAULT '', sha256 TEXT DEFAULT '',
			integrity_level TEXT DEFAULT '', start_time TIMESTAMPTZ DEFAULT NOW(),
			risk_score INTEGER DEFAULT 0, created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS pi_injections (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			src_pid INTEGER DEFAULT 0, src_name TEXT DEFAULT '',
			dst_pid INTEGER DEFAULT 0, dst_name TEXT DEFAULT '',
			technique TEXT DEFAULT '', api_call TEXT DEFAULT '',
			hostname TEXT DEFAULT '', sha256 TEXT DEFAULT '',
			severity TEXT DEFAULT 'high', status TEXT DEFAULT 'open',
			mitre_technique TEXT DEFAULT 'T1055', created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS pi_memory (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			pid INTEGER DEFAULT 0, process_name TEXT DEFAULT '',
			hostname TEXT DEFAULT '', region_type TEXT DEFAULT '',
			base_addr TEXT DEFAULT '', size_bytes BIGINT DEFAULT 0,
			protection TEXT DEFAULT 'RWX', is_executable BOOLEAN DEFAULT false,
			is_suspicious BOOLEAN DEFAULT false, entropy NUMERIC(5,2) DEFAULT 0,
			contains_shellcode BOOLEAN DEFAULT false, is_backed BOOLEAN DEFAULT true,
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS pi_api_calls (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			pid INTEGER DEFAULT 0, process_name TEXT DEFAULT '',
			target_pid INTEGER DEFAULT 0, api_name TEXT DEFAULT '',
			parameters TEXT DEFAULT '', hostname TEXT DEFAULT '',
			is_suspicious BOOLEAN DEFAULT false, created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS pi_alerts (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			injection_id INTEGER DEFAULT 0, title TEXT DEFAULT '',
			description TEXT DEFAULT '', technique TEXT DEFAULT '',
			severity TEXT DEFAULT 'high', mitre_technique TEXT DEFAULT '',
			hostname TEXT DEFAULT '', status TEXT DEFAULT 'open',
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
	}
	for _, s := range stmts {
		database.DB.Exec(s)
	}
}

// GetPIDashboard — GET /api/pi/dashboard
func GetPIDashboard(c *gin.Context) {
	createProcessInjectionTables()
	tid := tenantIDFromContext(c)
	var injAlerts, activeInjections, suspProcs, protProcs, memMods, highRiskHosts int
	var detectCoverage float64
	database.DB.QueryRow(`SELECT COUNT(*) FROM pi_alerts WHERE tenant_id=$1 AND status='open'`, tid).Scan(&injAlerts)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pi_injections WHERE tenant_id=$1`, tid).Scan(&activeInjections)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pi_processes WHERE tenant_id=$1 AND risk_score>60`, tid).Scan(&suspProcs)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pi_processes WHERE tenant_id=$1 AND signature!=''`, tid).Scan(&protProcs)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pi_memory WHERE tenant_id=$1 AND is_suspicious=true`, tid).Scan(&memMods)
	database.DB.QueryRow(`SELECT COUNT(DISTINCT hostname) FROM pi_injections WHERE tenant_id=$1`, tid).Scan(&highRiskHosts)
	database.DB.QueryRow(`SELECT COALESCE(COUNT(*)*100.0/NULLIF(13,0),0) FROM (SELECT DISTINCT technique FROM pi_injections WHERE tenant_id=$1) t`, tid).Scan(&detectCoverage)
	c.JSON(http.StatusOK, gin.H{
		"injection_alerts":     injAlerts,
		"active_injections":    activeInjections,
		"suspicious_processes": suspProcs,
		"protected_processes":  protProcs,
		"memory_modifications": memMods,
		"high_risk_hosts":      highRiskHosts,
		"detection_coverage":   int(detectCoverage),
		"injection_types": []string{
			"DLL Injection", "Process Hollowing", "APC Injection", "Thread Injection",
			"Reflective DLL Loading", "Manual Mapping", "AtomBombing", "Process Doppelgänging",
			"Process Ghosting", "Early Bird APC", "Thread Hijacking", "QueueUserAPC Abuse",
		},
	})
}

// GetPIProcesses — GET /api/pi/processes
func GetPIProcesses(c *gin.Context) {
	createProcessInjectionTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)
	q := `SELECT id, agent_id, hostname, name, pid, ppid, username, cmdline, path,
		signature, sha256, integrity_level, start_time, risk_score, created_at
		FROM pi_processes WHERE tenant_id=$1`
	args := []interface{}{tid}
	i := 2
	if v := c.Query("hostname"); v != "" {
		q += fmt.Sprintf(" AND hostname=$%d", i)
		args = append(args, v)
		i++
	}
	if v := c.Query("suspicious"); v == "true" {
		q += " AND risk_score>60"
	}
	q += fmt.Sprintf(" ORDER BY risk_score DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	type Process struct {
		ID             int    `json:"id"`
		AgentID        string `json:"agent_id"`
		Hostname       string `json:"hostname"`
		Name           string `json:"name"`
		PID            int    `json:"pid"`
		PPID           int    `json:"ppid"`
		Username       string `json:"username"`
		CmdLine        string `json:"cmdline"`
		Path           string `json:"path"`
		Signature      string `json:"signature"`
		SHA256         string `json:"sha256"`
		IntegrityLevel string `json:"integrity_level"`
		StartTime      string `json:"start_time"`
		RiskScore      int    `json:"risk_score"`
		CreatedAt      string `json:"created_at"`
	}
	procs := []Process{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var p Process
			if rows.Scan(&p.ID, &p.AgentID, &p.Hostname, &p.Name, &p.PID, &p.PPID, &p.Username,
				&p.CmdLine, &p.Path, &p.Signature, &p.SHA256, &p.IntegrityLevel, &p.StartTime, &p.RiskScore, &p.CreatedAt) == nil {
				procs = append(procs, p)
			}
		}
	}
	if procs == nil {
		procs = []Process{}
	}
	c.JSON(http.StatusOK, procs)
}

// GetPIProcessTree — GET /api/pi/process-tree
func GetPIProcessTree(c *gin.Context) {
	createProcessInjectionTables()
	tid := tenantIDFromContext(c)
	hostname := c.Query("hostname")
	q := `SELECT id, name, pid, ppid, username, cmdline, risk_score
		FROM pi_processes WHERE tenant_id=$1`
	args := []interface{}{tid}
	if hostname != "" {
		q += " AND hostname=$2"
		args = append(args, hostname)
	}
	q += " ORDER BY ppid, pid LIMIT 200"
	rows, _ := database.DB.Query(q, args...)
	type Node struct {
		ID        int    `json:"id"`
		Name      string `json:"name"`
		PID       int    `json:"pid"`
		PPID      int    `json:"ppid"`
		Username  string `json:"username"`
		CmdLine   string `json:"cmdline"`
		RiskScore int    `json:"risk_score"`
		Children  []int  `json:"children"`
	}
	nodes := []Node{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var n Node
			if rows.Scan(&n.ID, &n.Name, &n.PID, &n.PPID, &n.Username, &n.CmdLine, &n.RiskScore) == nil {
				n.Children = []int{}
				nodes = append(nodes, n)
			}
		}
	}
	if nodes == nil {
		nodes = []Node{}
	}
	c.JSON(http.StatusOK, nodes)
}

// GetPIInjections — GET /api/pi/injections
func GetPIInjections(c *gin.Context) {
	createProcessInjectionTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	q := `SELECT id, src_pid, src_name, dst_pid, dst_name, technique, api_call,
		hostname, sha256, severity, status, mitre_technique, created_at
		FROM pi_injections WHERE tenant_id=$1`
	args := []interface{}{tid}
	i := 2
	if v := c.Query("technique"); v != "" {
		q += fmt.Sprintf(" AND technique=$%d", i)
		args = append(args, v)
		i++
	}
	if v := c.Query("severity"); v != "" {
		q += fmt.Sprintf(" AND severity=$%d", i)
		args = append(args, v)
		i++
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	type Injection struct {
		ID             int    `json:"id"`
		SrcPID         int    `json:"src_pid"`
		SrcName        string `json:"src_name"`
		DstPID         int    `json:"dst_pid"`
		DstName        string `json:"dst_name"`
		Technique      string `json:"technique"`
		APICall        string `json:"api_call"`
		Hostname       string `json:"hostname"`
		SHA256         string `json:"sha256"`
		Severity       string `json:"severity"`
		Status         string `json:"status"`
		MITRETechnique string `json:"mitre_technique"`
		CreatedAt      string `json:"created_at"`
	}
	injections := []Injection{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var inj Injection
			if rows.Scan(&inj.ID, &inj.SrcPID, &inj.SrcName, &inj.DstPID, &inj.DstName, &inj.Technique,
				&inj.APICall, &inj.Hostname, &inj.SHA256, &inj.Severity, &inj.Status, &inj.MITRETechnique, &inj.CreatedAt) == nil {
				injections = append(injections, inj)
			}
		}
	}
	if injections == nil {
		injections = []Injection{}
	}
	var total, critical int
	database.DB.QueryRow(`SELECT COUNT(*) FROM pi_injections WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pi_injections WHERE tenant_id=$1 AND severity='critical'`, tid).Scan(&critical)
	c.JSON(http.StatusOK, gin.H{"injections": injections, "total": total, "critical": critical})
}

// GetPIMemory — GET /api/pi/memory
func GetPIMemory(c *gin.Context) {
	createProcessInjectionTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	rows, _ := database.DB.Query(`SELECT id, pid, process_name, hostname, region_type, base_addr,
		size_bytes, protection, is_executable, is_suspicious, entropy, contains_shellcode, is_backed, created_at
		FROM pi_memory WHERE tenant_id=$1 ORDER BY is_suspicious DESC, entropy DESC LIMIT $2`, tid, limit)
	type MemRegion struct {
		ID                int     `json:"id"`
		PID               int     `json:"pid"`
		ProcessName       string  `json:"process_name"`
		Hostname          string  `json:"hostname"`
		RegionType        string  `json:"region_type"`
		BaseAddr          string  `json:"base_addr"`
		SizeBytes         int64   `json:"size_bytes"`
		Protection        string  `json:"protection"`
		IsExecutable      bool    `json:"is_executable"`
		IsSuspicious      bool    `json:"is_suspicious"`
		Entropy           float64 `json:"entropy"`
		ContainsShellcode bool    `json:"contains_shellcode"`
		IsBacked          bool    `json:"is_backed"`
		CreatedAt         string  `json:"created_at"`
	}
	regions := []MemRegion{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var r MemRegion
			if rows.Scan(&r.ID, &r.PID, &r.ProcessName, &r.Hostname, &r.RegionType, &r.BaseAddr,
				&r.SizeBytes, &r.Protection, &r.IsExecutable, &r.IsSuspicious, &r.Entropy, &r.ContainsShellcode, &r.IsBacked, &r.CreatedAt) == nil {
				regions = append(regions, r)
			}
		}
	}
	if regions == nil {
		regions = []MemRegion{}
	}
	var rwxCount, shellcodeCount, unbacked int
	database.DB.QueryRow(`SELECT COUNT(*) FROM pi_memory WHERE tenant_id=$1 AND protection='RWX'`, tid).Scan(&rwxCount)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pi_memory WHERE tenant_id=$1 AND contains_shellcode=true`, tid).Scan(&shellcodeCount)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pi_memory WHERE tenant_id=$1 AND is_backed=false`, tid).Scan(&unbacked)
	c.JSON(http.StatusOK, gin.H{"regions": regions, "rwx_pages": rwxCount, "shellcode": shellcodeCount, "unbacked": unbacked})
}

// GetPIModules — GET /api/pi/modules
func GetPIModules(c *gin.Context) {
	createProcessInjectionTables()
	// No agent capability collects per-process loaded-module inventories
	// anywhere in this codebase — report an honest empty list rather than
	// fabricated module data.
	c.JSON(http.StatusOK, gin.H{
		"modules": []map[string]interface{}{},
	})
}

// GetPIHandles — GET /api/pi/handles
func GetPIHandles(c *gin.Context) {
	createProcessInjectionTables()
	// No agent capability collects per-process handle tables anywhere in
	// this codebase — report an honest empty list rather than fabricated
	// handle data.
	c.JSON(http.StatusOK, gin.H{
		"handles": []map[string]interface{}{},
	})
}

// GetPIAPICalls — GET /api/pi/api-calls
func GetPIAPICalls(c *gin.Context) {
	createProcessInjectionTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	rows, _ := database.DB.Query(`SELECT id, pid, process_name, target_pid, api_name, parameters, hostname, is_suspicious, created_at
		FROM pi_api_calls WHERE tenant_id=$1 ORDER BY is_suspicious DESC, created_at DESC LIMIT $2`, tid, limit)
	type APICall struct {
		ID           int    `json:"id"`
		PID          int    `json:"pid"`
		ProcessName  string `json:"process_name"`
		TargetPID    int    `json:"target_pid"`
		APIName      string `json:"api_name"`
		Parameters   string `json:"parameters"`
		Hostname     string `json:"hostname"`
		IsSuspicious bool   `json:"is_suspicious"`
		CreatedAt    string `json:"created_at"`
	}
	calls := []APICall{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var call APICall
			if rows.Scan(&call.ID, &call.PID, &call.ProcessName, &call.TargetPID, &call.APIName, &call.Parameters, &call.Hostname, &call.IsSuspicious, &call.CreatedAt) == nil {
				calls = append(calls, call)
			}
		}
	}
	if calls == nil {
		calls = []APICall{}
	}
	c.JSON(http.StatusOK, gin.H{
		"api_calls": calls,
		"monitored_apis": []string{
			"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
			"NtMapViewOfSection", "NtWriteVirtualMemory", "QueueUserAPC",
			"SetWindowsHookEx", "NtCreateThreadEx", "RtlCreateUserThread",
			"NtUnmapViewOfSection", "VirtualProtectEx", "LoadLibraryA",
		},
	})
}

// GetPIBehavioral — GET /api/pi/behavioral
func GetPIBehavioral(c *gin.Context) {
	createProcessInjectionTables()
	tid := tenantIDFromContext(c)
	// Real behavioral detections: an injection event's src->dst process
	// pair (already tracked, real) is itself the behavioral parent/child
	// signal — no separate detection table needed.
	rows, err := database.DB.Query(`
		SELECT id, src_name, dst_name, api_call, severity, mitre_technique, hostname
		FROM pi_injections WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 50`, tid)
	detections := []map[string]interface{}{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id int
			var src, dst, apiCall, severity, mitre, hostname string
			if rows.Scan(&id, &src, &dst, &apiCall, &severity, &mitre, &hostname) == nil {
				detections = append(detections, map[string]interface{}{
					"id": id, "rule": src + " → " + dst, "parent": src, "child": dst,
					"cmdline": apiCall, "severity": severity, "mitre": mitre, "hostname": hostname,
				})
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"detections": detections,
	})
}

// GetPIThreatIntel — GET /api/pi/threat-intel
func GetPIThreatIntel(c *gin.Context) {
	createProcessInjectionTables()
	tid := tenantIDFromContext(c)

	// Real per-tenant IOC matching: check this tenant's actual observed
	// process hashes against the real iocs table. Only emit a match when a
	// real row for this tenant exists — no placeholder rows.
	malwareMatches := []map[string]interface{}{}
	rows, err := database.DB.Query(`
		SELECT DISTINCT p.sha256, p.name, i.severity, i.hit_count
		FROM pi_processes p JOIN iocs i ON i.tenant_id=p.tenant_id AND i.indicator=p.sha256
		WHERE p.tenant_id=$1 AND p.sha256 != '' AND i.enabled=true AND i.type IN ('sha256','hash','md5')
		LIMIT 20`, tid)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sha256, name, severity string
			var hits int
			if rows.Scan(&sha256, &name, &severity, &hits) == nil {
				malwareMatches = append(malwareMatches, map[string]interface{}{
					"sha256": sha256, "process": name, "severity": severity, "hits": hits,
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"malware_matches": malwareMatches,
	})
}

// GetPITimeline — GET /api/pi/timeline
func GetPITimeline(c *gin.Context) {
	createProcessInjectionTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	rows, _ := database.DB.Query(`SELECT id, title, description, technique, severity, mitre_technique, hostname, status, created_at
		FROM pi_alerts WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tid, limit)
	type TLEvent struct {
		ID             int    `json:"id"`
		Title          string `json:"title"`
		Description    string `json:"description"`
		Technique      string `json:"technique"`
		Severity       string `json:"severity"`
		MITRETechnique string `json:"mitre_technique"`
		Hostname       string `json:"hostname"`
		Status         string `json:"status"`
		CreatedAt      string `json:"created_at"`
	}
	events := []TLEvent{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e TLEvent
			if rows.Scan(&e.ID, &e.Title, &e.Description, &e.Technique, &e.Severity, &e.MITRETechnique, &e.Hostname, &e.Status, &e.CreatedAt) == nil {
				events = append(events, e)
			}
		}
	}
	if events == nil {
		events = []TLEvent{}
	}
	c.JSON(http.StatusOK, events)
}

// GetPIMITREMap — GET /api/pi/mitre
func GetPIMITREMap(c *gin.Context) {
	createProcessInjectionTables()
	tid := tenantIDFromContext(c)

	counts := map[string]int{}
	rows, _ := database.DB.Query(`SELECT mitre_technique, COUNT(*) FROM pi_injections WHERE tenant_id=$1 GROUP BY mitre_technique`, tid)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var t string
			var n int
			if rows.Scan(&t, &n) == nil {
				counts[t] = n
			}
		}
	}

	subTechniqueNames := []struct{ id, name string }{
		{"T1055.001", "Dynamic-link Library Injection"},
		{"T1055.002", "Portable Executable Injection"},
		{"T1055.003", "Thread Execution Hijacking"},
		{"T1055.004", "Asynchronous Procedure Call"},
		{"T1055.005", "Thread Local Storage"},
		{"T1055.008", "Ptrace System Calls"},
		{"T1055.009", "Proc Memory"},
		{"T1055.011", "Extra Window Memory Injection"},
		{"T1055.012", "Process Hollowing"},
		{"T1055.013", "Process Doppelgänging"},
		{"T1055.014", "VDSO Hijacking"},
		{"T1055.015", "ListPlanting"},
	}
	subTechniques := []map[string]interface{}{}
	for _, st := range subTechniqueNames {
		cnt := counts[st.id]
		subTechniques = append(subTechniques, map[string]interface{}{
			"id": st.id, "name": st.name, "detected": cnt > 0, "count": cnt,
		})
	}

	relatedNames := []struct{ id, name, tactic string }{
		{"T1003.001", "LSASS Memory", "Credential Access"},
		{"T1059.001", "PowerShell", "Execution"},
		{"T1218.011", "Rundll32", "Defense Evasion"},
		{"T1134", "Access Token Manipulation", "Privilege Escalation"},
	}
	related := []map[string]interface{}{}
	for _, r := range relatedNames {
		related = append(related, map[string]interface{}{
			"id": r.id, "name": r.name, "tactic": r.tactic, "detected": counts[r.id] > 0,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"parent": map[string]interface{}{
			"technique_id": "T1055", "name": "Process Injection",
			"tactic": "Defense Evasion, Privilege Escalation",
			"url":    "https://attack.mitre.org/techniques/T1055/",
		},
		"sub_techniques": subTechniques,
		"related":        related,
	})
}

// GetPIAnalytics — GET /api/pi/analytics
func GetPIAnalytics(c *gin.Context) {
	createProcessInjectionTables()
	tid := tenantIDFromContext(c)
	type TrendPoint struct {
		Date  string `json:"date"`
		Count int    `json:"count"`
	}
	trend := []TrendPoint{}
	for i := 13; i >= 0; i-- {
		d := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		var cnt int
		database.DB.QueryRow(`SELECT COUNT(*) FROM pi_injections WHERE tenant_id=$1 AND DATE(created_at)<=$2`, tid, d).Scan(&cnt)
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
		FROM pi_injections WHERE tenant_id=$1 AND technique != ''
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

	type procRow struct {
		Process string `json:"process"`
		Count   int    `json:"count"`
		Risk    string `json:"risk"`
	}
	targetedProcesses := []procRow{}
	procRows, _ := database.DB.Query(`
		SELECT dst_name, COUNT(*), MODE() WITHIN GROUP (ORDER BY severity)
		FROM pi_injections WHERE tenant_id=$1 AND dst_name != ''
		GROUP BY dst_name ORDER BY COUNT(*) DESC LIMIT 10`, tid)
	if procRows != nil {
		defer procRows.Close()
		for procRows.Next() {
			var r procRow
			if procRows.Scan(&r.Process, &r.Count, &r.Risk) == nil {
				targetedProcesses = append(targetedProcesses, r)
			}
		}
	}

	type apiRow struct {
		API   string `json:"api"`
		Count int    `json:"count"`
	}
	usedAPIs := []apiRow{}
	apiRows, _ := database.DB.Query(`
		SELECT api_call, COUNT(*) FROM pi_injections WHERE tenant_id=$1 AND api_call != ''
		GROUP BY api_call ORDER BY COUNT(*) DESC LIMIT 10`, tid)
	if apiRows != nil {
		defer apiRows.Close()
		for apiRows.Next() {
			var r apiRow
			if apiRows.Scan(&r.API, &r.Count) == nil {
				usedAPIs = append(usedAPIs, r)
			}
		}
	}

	type hostRow struct {
		Hostname       string `json:"hostname"`
		InjectionCount int    `json:"injection_count"`
		Risk           int    `json:"risk"`
	}
	highRiskHosts := []hostRow{}
	hostRows, _ := database.DB.Query(`
		SELECT i.hostname, COUNT(*), COALESCE(AVG(p.risk_score),0)
		FROM pi_injections i LEFT JOIN pi_processes p ON p.tenant_id=i.tenant_id AND p.hostname=i.hostname
		WHERE i.tenant_id=$1 AND i.hostname != ''
		GROUP BY i.hostname ORDER BY COUNT(*) DESC LIMIT 10`, tid)
	if hostRows != nil {
		defer hostRows.Close()
		for hostRows.Next() {
			var r hostRow
			var risk float64
			if hostRows.Scan(&r.Hostname, &r.InjectionCount, &risk) == nil {
				r.Risk = int(risk)
				highRiskHosts = append(highRiskHosts, r)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"injection_trend":         trend,
		"top_techniques":          topTechniques,
		"most_targeted_processes": targetedProcesses,
		"most_used_apis":          usedAPIs,
		"high_risk_hosts":         highRiskHosts,
	})
}

// PostPIAI — POST /api/pi/ai
func PostPIAI(c *gin.Context) {
	createProcessInjectionTables()
	var body struct {
		Mode    string `json:"mode"`
		Content string `json:"content"`
		Process string `json:"process"`
	}
	c.ShouldBindJSON(&body)
	var prompt string
	switch body.Mode {
	case "process":
		prompt = fmt.Sprintf(`You are a malware analyst and memory forensics expert. Analyze this process injection event:
%s
Provide compact JSON: {"verdict":"malicious|suspicious|benign","confidence":95,"technique":"injection technique name","mitre_technique":"T1055.XXX","explanation":"2-3 sentences","indicators":["indicator"],"recommended_actions":["action"]}`, body.Process)
	default:
		prompt = fmt.Sprintf(`You are a malware analyst expert in process injection and memory forensics. Answer: %s
Provide compact JSON: {"answer":"expert answer","confidence":88,"technique":"relevant technique if applicable","recommended_actions":["action"]}`, body.Content)
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

// PostPIResponse — POST /api/pi/response
func PostPIResponse(c *gin.Context) {
	createProcessInjectionTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Action   string `json:"action"`
		Target   string `json:"target"`
		PID      int    `json:"pid"`
		Hostname string `json:"hostname"`
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
	case "kill_process":
		if body.PID == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "pid required"})
			return
		}
		agentID, err := resolveAgent(body.Hostname)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		if err := dispatch(agentID, "kill_process", map[string]any{"pid": body.PID, "reason": body.Reason}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "target": body.Target, "hostname": body.Hostname, "message": fmt.Sprintf("kill_process(pid=%d) queued for agent %d, pending approval", body.PID, agentID)})
	case "collect_process":
		agentID, err := resolveAgent(body.Hostname)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		if err := dispatch(agentID, "collect_processes", map[string]any{"reason": body.Reason}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "target": body.Target, "hostname": body.Hostname, "message": fmt.Sprintf("Process collection queued for agent %d, pending approval", agentID)})
	case "isolate_endpoint":
		agentID, err := resolveAgent(body.Hostname)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		if err := dispatch(agentID, "isolate_host", map[string]any{"reason": body.Reason, "source": "process_injection"}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "target": body.Target, "hostname": body.Hostname, "message": fmt.Sprintf("isolate_host queued for agent %d, pending approval", agentID)})
	case "suspend_process", "dump_memory":
		c.JSON(http.StatusNotImplemented, gin.H{"error": "no real agent capability exists for this action (only kill_process/collect_processes/isolate_host are implemented)"})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown action"})
	}
}

// PostPIReport — POST /api/pi/report
func PostPIReport(c *gin.Context) {
	createProcessInjectionTables()
	tid := tenantIDFromContext(c)
	var body struct {
		ReportType string `json:"report_type"`
	}
	c.ShouldBindJSON(&body)
	var totalInjections, criticalAlerts, affectedHosts int
	database.DB.QueryRow(`SELECT COUNT(*) FROM pi_injections WHERE tenant_id=$1`, tid).Scan(&totalInjections)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pi_alerts WHERE tenant_id=$1 AND severity='critical'`, tid).Scan(&criticalAlerts)
	database.DB.QueryRow(`SELECT COUNT(DISTINCT hostname) FROM pi_injections WHERE tenant_id=$1`, tid).Scan(&affectedHosts)
	prompt := fmt.Sprintf(`Generate an executive process injection and memory forensics security report.
Stats: %d injection events, %d critical alerts, %d affected hosts.
Report type: %s
Provide compact JSON: {"title":"...","executive_summary":"3 sentences","key_findings":["finding"],"techniques_detected":["technique"],"risk_breakdown":{"critical":0,"high":0,"medium":0},"top_recommendations":[{"priority":1,"action":"action","estimated_effort":"time"}],"metrics":{"total_injections":%d,"critical_alerts":%d,"affected_hosts":%d}}`,
		totalInjections, criticalAlerts, affectedHosts, body.ReportType,
		totalInjections, criticalAlerts, affectedHosts)
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
