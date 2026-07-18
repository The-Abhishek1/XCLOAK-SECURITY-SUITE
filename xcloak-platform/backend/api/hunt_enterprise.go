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

// GetHuntDashboard returns KPIs and overview metrics for the hunt workbench dashboard.
func GetHuntDashboard(c *gin.Context) {
	tid := tenantIDFromContext(c)

	var active, completed, failed, total int
	database.DB.QueryRow(`
		SELECT
			COUNT(*) FILTER (WHERE status = 'running'),
			COUNT(*) FILTER (WHERE status = 'completed'),
			COUNT(*) FILTER (WHERE status = 'failed'),
			COUNT(*)
		FROM hunt_runs WHERE tenant_id = $1`, tid).
		Scan(&active, &completed, &failed, &total)

	var saved int
	database.DB.QueryRow(`SELECT COUNT(*) FROM hunt_templates WHERE tenant_id = $1`, tid).Scan(&saved)

	var withHits int
	database.DB.QueryRow(`SELECT COUNT(*) FROM hunt_runs WHERE tenant_id = $1 AND status = 'completed' AND hit_count > 0`, tid).Scan(&withHits)
	successRate := 0.0
	if completed > 0 {
		successRate = float64(withHits) / float64(completed) * 100
	}

	var iocMatches int
	database.DB.QueryRow(`SELECT COALESCE(SUM(hit_count), 0) FROM hunt_runs WHERE tenant_id = $1`, tid).Scan(&iocMatches)

	type recentRun struct {
		ID        int    `json:"id"`
		Name      string `json:"name"`
		Status    string `json:"status"`
		HitCount  int    `json:"hit_count"`
		Analyst   string `json:"analyst"`
		Severity  string `json:"severity"`
		StartedAt string `json:"started_at"`
	}
	rows, _ := database.DB.Query(`
		SELECT id, name, status, hit_count, COALESCE(analyst,''), COALESCE(severity,''), started_at
		FROM hunt_runs WHERE tenant_id = $1
		ORDER BY started_at DESC LIMIT 10`, tid)
	recentRuns := []recentRun{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var r recentRun
			if rows.Scan(&r.ID, &r.Name, &r.Status, &r.HitCount, &r.Analyst, &r.Severity, &r.StartedAt) == nil {
				recentRuns = append(recentRuns, r)
			}
		}
	}
	if recentRuns == nil {
		recentRuns = []recentRun{}
	}

	type techStat struct {
		Technique string `json:"technique"`
		Count     int    `json:"count"`
	}
	techRows, _ := database.DB.Query(`
		SELECT mitre_technique, COUNT(*)
		FROM hunt_templates WHERE tenant_id = $1 AND mitre_technique != ''
		GROUP BY mitre_technique ORDER BY 2 DESC LIMIT 8`, tid)
	topTechs := []techStat{}
	if techRows != nil {
		defer techRows.Close()
		for techRows.Next() {
			var ts techStat
			if techRows.Scan(&ts.Technique, &ts.Count) == nil {
				topTechs = append(topTechs, ts)
			}
		}
	}
	if topTechs == nil {
		topTechs = []techStat{}
	}

	type trendPt struct {
		Date    string `json:"date"`
		Runs    int    `json:"runs"`
		Matches int    `json:"matches"`
	}
	trendRows, _ := database.DB.Query(`
		SELECT DATE_TRUNC('day', started_at)::date, COUNT(*), COALESCE(SUM(hit_count), 0)
		FROM hunt_runs WHERE tenant_id = $1 AND started_at > NOW() - INTERVAL '14 days'
		GROUP BY 1 ORDER BY 1`, tid)
	trend := []trendPt{}
	if trendRows != nil {
		defer trendRows.Close()
		for trendRows.Next() {
			var d time.Time
			var tp trendPt
			if trendRows.Scan(&d, &tp.Runs, &tp.Matches) == nil {
				tp.Date = d.Format("2006-01-02")
				trend = append(trend, tp)
			}
		}
	}
	if trend == nil {
		trend = []trendPt{}
	}

	c.JSON(http.StatusOK, gin.H{
		"active":         active,
		"completed":      completed,
		"failed":         failed,
		"total":          total,
		"saved":          saved,
		"success_rate":   successRate,
		"ioc_matches":    iocMatches,
		"recent_runs":    recentRuns,
		"top_techniques": topTechs,
		"trend":          trend,
	})
}

// GetHuntAnalytics returns per-analyst and daily hunt execution metrics.
func GetHuntAnalytics(c *gin.Context) {
	tid := tenantIDFromContext(c)

	type analystStat struct {
		Analyst     string  `json:"analyst"`
		Runs        int     `json:"runs"`
		TotalHits   int     `json:"total_hits"`
		SuccessRate float64 `json:"success_rate"`
	}
	aRows, _ := database.DB.Query(`
		SELECT COALESCE(analyst,'unknown'), COUNT(*),
		       COALESCE(SUM(hit_count),0),
		       COUNT(*) FILTER (WHERE hit_count > 0)
		FROM hunt_runs WHERE tenant_id = $1
		GROUP BY 1 ORDER BY 2 DESC LIMIT 10`, tid)
	analysts := []analystStat{}
	if aRows != nil {
		defer aRows.Close()
		for aRows.Next() {
			var as analystStat
			var withHits int
			if aRows.Scan(&as.Analyst, &as.Runs, &as.TotalHits, &withHits) == nil {
				if as.Runs > 0 {
					as.SuccessRate = float64(withHits) / float64(as.Runs) * 100
				}
				analysts = append(analysts, as)
			}
		}
	}
	if analysts == nil {
		analysts = []analystStat{}
	}

	type tplStat struct {
		Name  string `json:"name"`
		Runs  int    `json:"runs"`
		Hits  int    `json:"hits"`
	}
	tRows, _ := database.DB.Query(`
		SELECT ht.name, COUNT(hr.id), COALESCE(SUM(hr.hit_count),0)
		FROM hunt_runs hr
		JOIN hunt_templates ht ON ht.id = hr.template_id
		WHERE hr.tenant_id = $1 AND hr.template_id IS NOT NULL
		GROUP BY ht.name ORDER BY 2 DESC LIMIT 10`, tid)
	topTemplates := []tplStat{}
	if tRows != nil {
		defer tRows.Close()
		for tRows.Next() {
			var ts tplStat
			if tRows.Scan(&ts.Name, &ts.Runs, &ts.Hits) == nil {
				topTemplates = append(topTemplates, ts)
			}
		}
	}
	if topTemplates == nil {
		topTemplates = []tplStat{}
	}

	type dailyPt struct {
		Date    string `json:"date"`
		Runs    int    `json:"runs"`
		Matches int    `json:"matches"`
	}
	dRows, _ := database.DB.Query(`
		SELECT DATE_TRUNC('day', started_at)::date, COUNT(*), COALESCE(SUM(hit_count),0)
		FROM hunt_runs WHERE tenant_id = $1 AND started_at > NOW() - INTERVAL '30 days'
		GROUP BY 1 ORDER BY 1`, tid)
	daily := []dailyPt{}
	if dRows != nil {
		defer dRows.Close()
		for dRows.Next() {
			var d time.Time
			var dp dailyPt
			if dRows.Scan(&d, &dp.Runs, &dp.Matches) == nil {
				dp.Date = d.Format("2006-01-02")
				daily = append(daily, dp)
			}
		}
	}
	if daily == nil {
		daily = []dailyPt{}
	}

	var totalRuns, totalHits int
	database.DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(hit_count),0) FROM hunt_runs WHERE tenant_id = $1`, tid).
		Scan(&totalRuns, &totalHits)

	c.JSON(http.StatusOK, gin.H{
		"analysts":      analysts,
		"top_templates": topTemplates,
		"daily":         daily,
		"total_runs":    totalRuns,
		"total_hits":    totalHits,
	})
}

// GetHuntMITRECoverage maps hunt templates to the MITRE ATT&CK framework and returns coverage data.
func GetHuntMITRECoverage(c *gin.Context) {
	tid := tenantIDFromContext(c)

	// Collect covered techniques from saved templates and runs
	coveredSet := map[string]int{}
	rows, _ := database.DB.Query(`
		SELECT mitre_technique, COUNT(*)
		FROM hunt_templates
		WHERE tenant_id = $1 AND mitre_technique != '' AND mitre_technique IS NOT NULL
		GROUP BY mitre_technique`, tid)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var tech string
			var cnt int
			if rows.Scan(&tech, &cnt) == nil {
				coveredSet[tech] += cnt
			}
		}
	}

	runRows, _ := database.DB.Query(`
		SELECT ht.mitre_technique, COUNT(hr.id)
		FROM hunt_runs hr
		JOIN hunt_templates ht ON ht.id = hr.template_id
		WHERE hr.tenant_id = $1 AND ht.mitre_technique != '' AND ht.mitre_technique IS NOT NULL
		GROUP BY ht.mitre_technique`, tid)
	if runRows != nil {
		defer runRows.Close()
		for runRows.Next() {
			var tech string
			var cnt int
			if runRows.Scan(&tech, &cnt) == nil {
				coveredSet[tech] += cnt
			}
		}
	}

	type Technique struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Status   string `json:"status"` // covered | frequently_hunted | untested
		RunCount int    `json:"run_count"`
	}
	type Tactic struct {
		ID         string      `json:"id"`
		Name       string      `json:"name"`
		Techniques []Technique `json:"techniques"`
		Coverage   int         `json:"coverage"` // percentage
	}

	matrix := []struct {
		ID         string
		Name       string
		Techniques []struct{ ID, Name string }
	}{
		{"TA0001", "Initial Access", []struct{ ID, Name string }{
			{"T1566", "Phishing"}, {"T1190", "Exploit Public-Facing App"}, {"T1195", "Supply Chain Compromise"},
			{"T1078", "Valid Accounts"}, {"T1199", "Trusted Relationship"},
		}},
		{"TA0002", "Execution", []struct{ ID, Name string }{
			{"T1059", "Command & Scripting Interpreter"}, {"T1059.001", "PowerShell"}, {"T1204", "User Execution"},
			{"T1053", "Scheduled Task/Job"}, {"T1569", "System Services"},
		}},
		{"TA0003", "Persistence", []struct{ ID, Name string }{
			{"T1547", "Boot/Logon Autostart"}, {"T1098", "Account Manipulation"}, {"T1136", "Create Account"},
			{"T1505", "Server Software Component"}, {"T1053", "Scheduled Task/Job"},
		}},
		{"TA0004", "Privilege Escalation", []struct{ ID, Name string }{
			{"T1548", "Abuse Elevation Control"}, {"T1134", "Access Token Manipulation"}, {"T1068", "Exploit Vuln"},
			{"T1055", "Process Injection"}, {"T1078", "Valid Accounts"},
		}},
		{"TA0005", "Defense Evasion", []struct{ ID, Name string }{
			{"T1027", "Obfuscated Files/Info"}, {"T1055", "Process Injection"}, {"T1036", "Masquerading"},
			{"T1070", "Indicator Removal"}, {"T1562", "Impair Defenses"},
		}},
		{"TA0006", "Credential Access", []struct{ ID, Name string }{
			{"T1003", "OS Credential Dumping"}, {"T1003.001", "LSASS Memory"}, {"T1110", "Brute Force"},
			{"T1552", "Unsecured Credentials"}, {"T1558", "Steal/Forge Kerberos Tickets"},
		}},
		{"TA0007", "Discovery", []struct{ ID, Name string }{
			{"T1046", "Network Service Discovery"}, {"T1082", "System Info Discovery"}, {"T1083", "File Discovery"},
			{"T1057", "Process Discovery"}, {"T1016", "System Network Config"},
		}},
		{"TA0008", "Lateral Movement", []struct{ ID, Name string }{
			{"T1021", "Remote Services"}, {"T1021.001", "RDP"}, {"T1021.002", "SMB/Admin Shares"},
			{"T1550", "Use Alternate Auth"}, {"T1570", "Lateral Tool Transfer"},
		}},
		{"TA0009", "Collection", []struct{ ID, Name string }{
			{"T1560", "Archive Collected Data"}, {"T1115", "Clipboard Data"}, {"T1056", "Input Capture"},
			{"T1213", "Data from Info Repositories"}, {"T1039", "Data from Network Drive"},
		}},
		{"TA0011", "Command & Control", []struct{ ID, Name string }{
			{"T1071", "App Layer Protocol"}, {"T1071.001", "Web Protocols"}, {"T1573", "Encrypted Channel"},
			{"T1008", "Fallback Channels"}, {"T1095", "Non-App Layer Protocol"},
		}},
		{"TA0010", "Exfiltration", []struct{ ID, Name string }{
			{"T1048", "Exfiltration Over Alt Protocol"}, {"T1041", "Exfil Over C2"}, {"T1052", "Exfil Over Physical Medium"},
			{"T1011", "Exfil Over Other Network"}, {"T1030", "Data Transfer Size Limits"},
		}},
		{"TA0040", "Impact", []struct{ ID, Name string }{
			{"T1485", "Data Destruction"}, {"T1489", "Service Stop"}, {"T1486", "Data Encrypted for Impact"},
			{"T1490", "Inhibit System Recovery"}, {"T1495", "Firmware Corruption"},
		}},
	}

	tactics := make([]Tactic, 0, len(matrix))
	for _, tac := range matrix {
		techs := make([]Technique, 0, len(tac.Techniques))
		covered := 0
		for _, tech := range tac.Techniques {
			cnt := coveredSet[tech.ID]
			status := "untested"
			if cnt >= 5 {
				status = "frequently_hunted"
				covered++
			} else if cnt > 0 {
				status = "covered"
				covered++
			}
			techs = append(techs, Technique{ID: tech.ID, Name: tech.Name, Status: status, RunCount: cnt})
		}
		coverage := 0
		if len(tac.Techniques) > 0 {
			coverage = covered * 100 / len(tac.Techniques)
		}
		tactics = append(tactics, Tactic{ID: tac.ID, Name: tac.Name, Techniques: techs, Coverage: coverage})
	}

	total := len(matrix) * 5
	totalCovered := 0
	for _, id := range coveredSet {
		_ = id
		totalCovered++
	}
	overallPct := 0
	if total > 0 {
		overallPct = totalCovered * 100 / total
	}

	c.JSON(http.StatusOK, gin.H{
		"tactics":          tactics,
		"overall_coverage": overallPct,
		"covered_count":    totalCovered,
		"total_count":      total,
	})
}

// PostHuntAI handles AI-assisted query generation, explanation, rule creation, and recommendation.
func PostHuntAI(c *gin.Context) {
	tid := tenantIDFromContext(c)
	var body struct {
		Action  string `json:"action"`
		Query   string `json:"query"`
		Results string `json:"results"`
		Context string `json:"context"`
		Prompt  string `json:"prompt"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var sysPrompt, userPrompt string
	switch body.Action {
	case "generate_query":
		sysPrompt = `You are a threat hunting expert. Convert natural language descriptions to KQL (Kibana Query Language) queries for SIEM threat hunting. Return JSON with fields: kql (string), explanation (string), alternative_queries (array of strings).`
		userPrompt = fmt.Sprintf("Convert to KQL: %s\nContext: %s", body.Prompt, body.Context)
	case "explain_results":
		sysPrompt = `You are a threat hunting expert. Analyze hunt results and explain their security significance. Return JSON with fields: summary (string), risk_level (string), indicators (array), false_positive_likelihood (string), recommended_actions (array of strings).`
		userPrompt = fmt.Sprintf("Analyze these hunt results:\nQuery: %s\nResults: %s", body.Query, body.Results)
	case "generate_sigma":
		sysPrompt = `You are a detection engineering expert. Generate a Sigma rule for the described threat hunting scenario. Return JSON with fields: sigma_rule (string, YAML format), description (string), tags (array), logsource (object).`
		userPrompt = fmt.Sprintf("Generate Sigma rule for: %s\nQuery context: %s", body.Prompt, body.Query)
	case "generate_yara":
		sysPrompt = `You are a malware analysis expert. Generate a YARA rule for the described hunting scenario. Return JSON with fields: yara_rule (string), description (string), strings_explanation (array), condition_explanation (string).`
		userPrompt = fmt.Sprintf("Generate YARA rule for: %s\nContext: %s", body.Prompt, body.Context)
	case "summarize":
		sysPrompt = `You are a threat hunting analyst. Summarize the hunt findings and provide an executive summary. Return JSON with fields: executive_summary (string), key_findings (array), severity (string), affected_assets (array), next_steps (array).`
		userPrompt = fmt.Sprintf("Summarize hunt findings:\nTenant ID: %d\nQuery: %s\nResults: %s", tid, body.Query, body.Results)
	case "recommend":
		sysPrompt = `You are a threat hunting strategist. Based on the current hunt context, recommend the next hunting strategies. Return JSON with fields: recommendations (array of {title, description, query, mitre_technique}), priority_order (array of strings), threat_landscape (string).`
		userPrompt = fmt.Sprintf("Recommend next hunts based on: %s\nContext: %s", body.Prompt, body.Context)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown action"})
		return
	}

	raw, err := services.CallLLM(sysPrompt + "\n\nUser: " + userPrompt)
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

// PostHuntIOC hunts for a specific IOC value across all telemetry sources.
func PostHuntIOC(c *gin.Context) {
	tid := tenantIDFromContext(c)
	var body struct {
		IOCType   string `json:"ioc_type"`  // ip, domain, sha256, md5, ja3, email, url, cve
		Value     string `json:"value"`
		TimeRange string `json:"time_range"` // 24h, 7d, 30d
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Value == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "value is required"})
		return
	}

	interval := "24 hours"
	switch body.TimeRange {
	case "7d":
		interval = "7 days"
	case "30d":
		interval = "30 days"
	}

	type logHit struct {
		Source    string `json:"source"`
		Hostname  string `json:"hostname"`
		Message   string `json:"message"`
		Timestamp string `json:"timestamp"`
		AgentID   int    `json:"agent_id"`
	}
	type alertHit struct {
		RuleName  string `json:"rule_name"`
		Hostname  string `json:"hostname"`
		Severity  string `json:"severity"`
		Timestamp string `json:"timestamp"`
	}
	type connHit struct {
		Hostname   string `json:"hostname"`
		RemoteAddr string `json:"remote_addr"`
		State      string `json:"state"`
		Timestamp  string `json:"timestamp"`
	}

	logHits := []logHit{}
	alertHits := []alertHit{}
	connHits := []connHit{}

	// Search endpoint_logs
	lRows, _ := database.DB.Query(fmt.Sprintf(`
		SELECT el.source, COALESCE(ag.hostname,'unknown'), el.log_message, el.collected_at, el.agent_id
		FROM endpoint_logs el
		JOIN agents ag ON ag.id = el.agent_id
		WHERE ag.tenant_id = $1 AND el.log_message ILIKE $2
		  AND el.collected_at > NOW() - INTERVAL '%s'
		ORDER BY el.collected_at DESC LIMIT 50`, interval),
		tid, "%"+body.Value+"%")
	if lRows != nil {
		defer lRows.Close()
		for lRows.Next() {
			var h logHit
			if lRows.Scan(&h.Source, &h.Hostname, &h.Message, &h.Timestamp, &h.AgentID) == nil {
				logHits = append(logHits, h)
			}
		}
	}

	// Search alerts
	aRows, _ := database.DB.Query(fmt.Sprintf(`
		SELECT a.rule_name, COALESCE(ag.hostname,'unknown'), a.severity, a.created_at
		FROM alerts a
		JOIN agents ag ON ag.id = a.agent_id
		WHERE ag.tenant_id = $1 AND (a.rule_name ILIKE $2 OR a.log_message ILIKE $2)
		  AND a.created_at > NOW() - INTERVAL '%s'
		ORDER BY a.created_at DESC LIMIT 50`, interval),
		tid, "%"+body.Value+"%")
	if aRows != nil {
		defer aRows.Close()
		for aRows.Next() {
			var h alertHit
			if aRows.Scan(&h.RuleName, &h.Hostname, &h.Severity, &h.Timestamp) == nil {
				alertHits = append(alertHits, h)
			}
		}
	}

	// Search endpoint_connections for IP/domain IOC types
	if body.IOCType == "ip" || body.IOCType == "domain" {
		cRows, _ := database.DB.Query(fmt.Sprintf(`
			SELECT COALESCE(ag.hostname,'unknown'), ec.remote_addr, COALESCE(ec.state,''), ec.created_at
			FROM endpoint_connections ec
			JOIN agents ag ON ag.id = ec.agent_id
			WHERE ag.tenant_id = $1 AND ec.remote_addr ILIKE $2
			  AND ec.created_at > NOW() - INTERVAL '%s'
			ORDER BY ec.created_at DESC LIMIT 50`, interval),
			tid, "%"+body.Value+"%")
		if cRows != nil {
			defer cRows.Close()
			for cRows.Next() {
				var h connHit
				if cRows.Scan(&h.Hostname, &h.RemoteAddr, &h.State, &h.Timestamp) == nil {
					connHits = append(connHits, h)
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"ioc_type":    body.IOCType,
		"value":       body.Value,
		"time_range":  body.TimeRange,
		"log_hits":    logHits,
		"alert_hits":  alertHits,
		"conn_hits":   connHits,
		"total_hits":  len(logHits) + len(alertHits) + len(connHits),
	})
}

// ttpDef defines search keywords and MITRE mapping for a TTP.
type ttpDef struct {
	Name     string
	Mitre    string
	Tactic   string
	Keywords []string
}

var huntTTPMap = map[string]ttpDef{
	"powershell": {
		"PowerShell Execution", "T1059.001", "Execution",
		[]string{"powershell", "pwsh", "invoke-expression", "encoded command", "bypass", "downloadstring"},
	},
	"lsass": {
		"LSASS Memory Access", "T1003.001", "Credential Access",
		[]string{"lsass", "mimikatz", "sekurlsa", "procdump", "comsvcs", "minidump"},
	},
	"lolbins": {
		"Living-off-the-Land Binaries", "T1218", "Defense Evasion",
		[]string{"wmic.exe", "certutil.exe", "regsvr32.exe", "mshta.exe", "rundll32.exe", "msiexec.exe", "bitsadmin.exe", "csc.exe"},
	},
	"injection": {
		"Process Injection", "T1055", "Defense Evasion",
		[]string{"createremotethread", "virtualallocex", "writeprocessmemory", "setthreadcontext", "inject"},
	},
	"beaconing": {
		"C2 Beaconing", "T1071.001", "Command & Control",
		[]string{"beacon", "jitter", "sleep(", "checkin", "c2", "cobalt strike", "sliver", "empire"},
	},
	"lateral": {
		"Lateral Movement", "T1021", "Lateral Movement",
		[]string{"psexec", "wmiexec", "pass-the-hash", "pth", "lateral movement", "admin share", "\\\\ipc$"},
	},
	"ransomware": {
		"Ransomware", "T1486", "Impact",
		[]string{"vssadmin delete shadows", ".encrypted", ".locked", "ransom", "decrypt_instructions", "readme.txt"},
	},
	"persistence": {
		"Persistence Mechanism", "T1547", "Persistence",
		[]string{"currentversion\\run", "crontab -e", "autorun", "startup folder", "rc.local", "systemd service"},
	},
}

// PostHuntTTP hunts for specific TTPs across endpoint telemetry.
func PostHuntTTP(c *gin.Context) {
	tid := tenantIDFromContext(c)
	var body struct {
		TTP       string `json:"ttp"`
		TimeRange string `json:"time_range"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	def, ok := huntTTPMap[body.TTP]
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown ttp"})
		return
	}

	interval := "24 hours"
	switch body.TimeRange {
	case "7d":
		interval = "7 days"
	case "30d":
		interval = "30 days"
	}

	// Build OR conditions (using our own keyword list, not user input)
	conditions := make([]string, 0, len(def.Keywords))
	for _, kw := range def.Keywords {
		safe := strings.ReplaceAll(kw, "'", "''")
		conditions = append(conditions, fmt.Sprintf("log_message ILIKE '%%%s%%'", safe))
	}
	whereOR := strings.Join(conditions, " OR ")

	type logHit struct {
		Hostname  string `json:"hostname"`
		Source    string `json:"source"`
		Message   string `json:"message"`
		Timestamp string `json:"timestamp"`
		AgentID   int    `json:"agent_id"`
	}
	lRows, _ := database.DB.Query(fmt.Sprintf(`
		SELECT COALESCE(ag.hostname,'unknown'), el.source, el.log_message, el.collected_at, el.agent_id
		FROM endpoint_logs el
		JOIN agents ag ON ag.id = el.agent_id
		WHERE ag.tenant_id = $1 AND (%s)
		  AND el.collected_at > NOW() - INTERVAL '%s'
		ORDER BY el.collected_at DESC LIMIT 100`, whereOR, interval), tid)
	logHits := []logHit{}
	if lRows != nil {
		defer lRows.Close()
		for lRows.Next() {
			var h logHit
			if lRows.Scan(&h.Hostname, &h.Source, &h.Message, &h.Timestamp, &h.AgentID) == nil {
				logHits = append(logHits, h)
			}
		}
	}
	if logHits == nil {
		logHits = []logHit{}
	}

	// Alert hits
	alertConditions := make([]string, 0, len(def.Keywords))
	for _, kw := range def.Keywords {
		safe := strings.ReplaceAll(kw, "'", "''")
		alertConditions = append(alertConditions, fmt.Sprintf("a.log_message ILIKE '%%%s%%'", safe))
	}
	alertWhere := strings.Join(alertConditions, " OR ")

	type alertHit struct {
		RuleName  string `json:"rule_name"`
		Hostname  string `json:"hostname"`
		Severity  string `json:"severity"`
		Timestamp string `json:"timestamp"`
	}
	aRows, _ := database.DB.Query(fmt.Sprintf(`
		SELECT a.rule_name, COALESCE(ag.hostname,'unknown'), a.severity, a.created_at
		FROM alerts a
		JOIN agents ag ON ag.id = a.agent_id
		WHERE ag.tenant_id = $1 AND (%s)
		  AND a.created_at > NOW() - INTERVAL '%s'
		ORDER BY a.created_at DESC LIMIT 50`, alertWhere, interval), tid)
	alertHits := []alertHit{}
	if aRows != nil {
		defer aRows.Close()
		for aRows.Next() {
			var h alertHit
			if aRows.Scan(&h.RuleName, &h.Hostname, &h.Severity, &h.Timestamp) == nil {
				alertHits = append(alertHits, h)
			}
		}
	}
	if alertHits == nil {
		alertHits = []alertHit{}
	}

	c.JSON(http.StatusOK, gin.H{
		"ttp":         body.TTP,
		"name":        def.Name,
		"mitre":       def.Mitre,
		"tactic":      def.Tactic,
		"log_hits":    logHits,
		"alert_hits":  alertHits,
		"total_hits":  len(logHits) + len(alertHits),
		"time_range":  body.TimeRange,
	})
}

// PostHuntActor hunts for a threat actor by searching across IOCs and threat intelligence.
func PostHuntActor(c *gin.Context) {
	tid := tenantIDFromContext(c)
	var body struct {
		Actor     string `json:"actor"`      // e.g. "APT29", "Lazarus Group"
		TimeRange string `json:"time_range"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	interval := "7 days"
	if body.TimeRange == "30d" {
		interval = "30 days"
	}

	actorSearch := strings.ReplaceAll(body.Actor, "'", "''")

	// Search IOC table for actor-attributed indicators
	type iocHit struct {
		Indicator string `json:"indicator"`
		Type      string `json:"type"`
		Source    string `json:"source"`
	}
	iocHits := []iocHit{}
	iRows, _ := database.DB.Query(fmt.Sprintf(`
		SELECT COALESCE(indicator,''), COALESCE(indicator_type,''), COALESCE(source,'')
		FROM iocs
		WHERE tenant_id = $1 AND (source ILIKE '%%%s%%' OR description ILIKE '%%%s%%')
		ORDER BY created_at DESC LIMIT 50`, actorSearch, actorSearch), tid)
	if iRows != nil {
		defer iRows.Close()
		for iRows.Next() {
			var h iocHit
			if iRows.Scan(&h.Indicator, &h.Type, &h.Source) == nil {
				iocHits = append(iocHits, h)
			}
		}
	}
	if iocHits == nil {
		iocHits = []iocHit{}
	}

	// Search alerts for actor name
	type alertHit struct {
		RuleName  string `json:"rule_name"`
		Hostname  string `json:"hostname"`
		Severity  string `json:"severity"`
		Timestamp string `json:"timestamp"`
	}
	aRows, _ := database.DB.Query(fmt.Sprintf(`
		SELECT a.rule_name, COALESCE(ag.hostname,'unknown'), a.severity, a.created_at
		FROM alerts a
		JOIN agents ag ON ag.id = a.agent_id
		WHERE ag.tenant_id = $1 AND (a.rule_name ILIKE '%%%s%%' OR a.log_message ILIKE '%%%s%%')
		  AND a.created_at > NOW() - INTERVAL '%s'
		ORDER BY a.created_at DESC LIMIT 50`, actorSearch, actorSearch, interval), tid)
	alertHits := []alertHit{}
	if aRows != nil {
		defer aRows.Close()
		for aRows.Next() {
			var h alertHit
			if aRows.Scan(&h.RuleName, &h.Hostname, &h.Severity, &h.Timestamp) == nil {
				alertHits = append(alertHits, h)
			}
		}
	}
	if alertHits == nil {
		alertHits = []alertHit{}
	}

	c.JSON(http.StatusOK, gin.H{
		"actor":       body.Actor,
		"ioc_hits":    iocHits,
		"alert_hits":  alertHits,
		"total_hits":  len(iocHits) + len(alertHits),
		"time_range":  body.TimeRange,
	})
}

// PostHuntExport exports a hunt run as CSV, JSON, or Markdown.
func PostHuntExport(c *gin.Context) {
	tid := tenantIDFromContext(c)
	var body struct {
		RunID  int    `json:"run_id"`
		Format string `json:"format"` // csv, json, markdown
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var name, status, kqlQuery, analyst, severity, notes string
	var hitCount int
	var startedAt time.Time
	err := database.DB.QueryRow(`
		SELECT name, status, kql_query, COALESCE(analyst,''), hit_count, COALESCE(severity,''), COALESCE(notes,''), started_at
		FROM hunt_runs WHERE id = $1 AND tenant_id = $2`, body.RunID, tid).
		Scan(&name, &status, &kqlQuery, &analyst, &hitCount, &severity, &notes, &startedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "hunt run not found"})
		return
	}

	switch body.Format {
	case "csv":
		var sb strings.Builder
		sb.WriteString("hunt_name,status,analyst,hit_count,severity,started_at,query\n")
		sb.WriteString(fmt.Sprintf("%q,%s,%s,%d,%s,%s,%q\n",
			name, status, analyst, hitCount, severity, startedAt.Format(time.RFC3339), kqlQuery))
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="hunt_%d.csv"`, body.RunID))
		c.Data(http.StatusOK, "text/csv", []byte(sb.String()))
	case "markdown":
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("# Hunt Report: %s\n\n", name))
		sb.WriteString(fmt.Sprintf("**Status:** %s  \n**Analyst:** %s  \n**Severity:** %s  \n**Hits:** %d  \n**Started:** %s\n\n",
			status, analyst, severity, hitCount, startedAt.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("## Query\n```kql\n%s\n```\n\n", kqlQuery))
		if notes != "" {
			sb.WriteString(fmt.Sprintf("## Notes\n%s\n", notes))
		}
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="hunt_%d.md"`, body.RunID))
		c.Data(http.StatusOK, "text/markdown", []byte(sb.String()))
	default: // json
		c.JSON(http.StatusOK, gin.H{
			"id":         body.RunID,
			"name":       name,
			"status":     status,
			"kql_query":  kqlQuery,
			"analyst":    analyst,
			"hit_count":  hitCount,
			"severity":   severity,
			"notes":      notes,
			"started_at": startedAt.Format(time.RFC3339),
		})
	}
}

// GetHuntNotebook retrieves hunt notebook entries for the tenant.
func GetHuntNotebook(c *gin.Context) {
	tid := tenantIDFromContext(c)

	database.DB.Exec(`
		CREATE TABLE IF NOT EXISTS hunt_notebook (
			id SERIAL PRIMARY KEY,
			tenant_id INT NOT NULL,
			run_id INT,
			content TEXT NOT NULL,
			content_type VARCHAR(50) NOT NULL DEFAULT 'note',
			created_by VARCHAR(255) NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`)

	runIDFilter := c.Query("run_id")
	var rows interface{ Next() bool; Scan(...interface{}) error; Close() error }
	if runIDFilter != "" {
		rid, _ := strconv.Atoi(runIDFilter)
		rows, _ = database.DB.Query(`
			SELECT id, COALESCE(run_id,0), content, content_type, created_by, created_at
			FROM hunt_notebook WHERE tenant_id = $1 AND run_id = $2
			ORDER BY created_at DESC`, tid, rid)
	} else {
		rows, _ = database.DB.Query(`
			SELECT id, COALESCE(run_id,0), content, content_type, created_by, created_at
			FROM hunt_notebook WHERE tenant_id = $1
			ORDER BY created_at DESC LIMIT 100`, tid)
	}

	type entry struct {
		ID          int    `json:"id"`
		RunID       int    `json:"run_id"`
		Content     string `json:"content"`
		ContentType string `json:"content_type"`
		CreatedBy   string `json:"created_by"`
		CreatedAt   string `json:"created_at"`
	}
	entries := []entry{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e entry
			if rows.Scan(&e.ID, &e.RunID, &e.Content, &e.ContentType, &e.CreatedBy, &e.CreatedAt) == nil {
				entries = append(entries, e)
			}
		}
	}
	if entries == nil {
		entries = []entry{}
	}
	c.JSON(http.StatusOK, entries)
}

// PostHuntNotebook adds an entry to the hunt notebook.
func PostHuntNotebook(c *gin.Context) {
	tid := tenantIDFromContext(c)
	user := usernameFromContext(c)
	var body struct {
		RunID       int    `json:"run_id"`
		Content     string `json:"content"`
		ContentType string `json:"content_type"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.ContentType == "" {
		body.ContentType = "note"
	}

	database.DB.Exec(`
		CREATE TABLE IF NOT EXISTS hunt_notebook (
			id SERIAL PRIMARY KEY,
			tenant_id INT NOT NULL,
			run_id INT,
			content TEXT NOT NULL,
			content_type VARCHAR(50) NOT NULL DEFAULT 'note',
			created_by VARCHAR(255) NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`)

	var rid *int
	if body.RunID != 0 {
		rid = &body.RunID
	}
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO hunt_notebook (tenant_id, run_id, content, content_type, created_by)
		VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		tid, rid, body.Content, body.ContentType, user).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id})
}

// DeleteHuntNotebook removes a notebook entry.
func DeleteHuntNotebook(c *gin.Context) {
	tid := tenantIDFromContext(c)
	nid, _ := strconv.Atoi(c.Param("nid"))
	database.DB.Exec(`DELETE FROM hunt_notebook WHERE id = $1 AND tenant_id = $2`, nid, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// PostHuntResponse dispatches a response action from the hunt workbench.
func PostHuntResponse(c *gin.Context) {
	tid := tenantIDFromContext(c)
	user := usernameFromContext(c)
	var body struct {
		Action  string `json:"action"` // isolate_host, block_ip, kill_process, quarantine_file, create_incident
		AgentID int    `json:"agent_id"`
		Target  string `json:"target"` // IP, process name, file path, etc.
		RunID   int    `json:"run_id"`
		Reason  string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Log the response action as an audit event
	database.DB.Exec(`
		INSERT INTO audit_logs (tenant_id, user_id, action, resource_type, resource_id, details, created_at)
		VALUES ($1, 0, $2, 'hunt_response', $3, $4, NOW())
		ON CONFLICT DO NOTHING`,
		tid,
		fmt.Sprintf("hunt.response.%s", body.Action),
		strconv.Itoa(body.RunID),
		fmt.Sprintf(`{"action":"%s","target":"%s","agent_id":%d,"analyst":"%s","reason":"%s"}`,
			body.Action, body.Target, body.AgentID, user, body.Reason),
	)

	c.JSON(http.StatusOK, gin.H{
		"queued":  true,
		"action":  body.Action,
		"target":  body.Target,
		"message": fmt.Sprintf("Response action '%s' queued for target '%s'", body.Action, body.Target),
	})
}
