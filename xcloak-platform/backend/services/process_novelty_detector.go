package services

// Process novelty detection — tracks which process names have historically run
// on each agent and fires an anomaly finding the first time a new process
// appears. This catches attacker tools, unexpected interpreters, and lateral
// movement payloads that threshold-based detectors miss entirely.
//
// Detection logic:
//   1. Every 10 minutes scan endpoint_processes for recently-seen process names.
//   2. Upsert each (agent_id, process_name) into agent_known_processes.
//   3. On first sighting (seen_count was 0 before upsert) and the name is not
//      in the benign whitelist, emit an anomaly_findings row.
//
// Severity tiering:
//   critical — name matches a known attacker-tool signature
//   high     — first appearance of any executable not in the whitelist
//   low      — after 2–4 sightings (likely a new install, not an attack)

import (
	"fmt"
	"strings"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// StartProcessNoveltyDetector runs the novelty scan every 10 minutes.
// Call once from StartScheduler.
func StartProcessNoveltyDetector() {
	go func() {
		time.Sleep(3 * time.Minute) // let agents enroll before first scan
		for {
			runProcessNoveltyDetection()
			time.Sleep(10 * time.Minute)
		}
	}()
}

// knownAttackerTools is a list of process-name substrings that are always
// treated as critical regardless of whether the process was seen before.
var knownAttackerTools = []string{
	"mimikatz", "rubeus", "bloodhound", "sharphound",
	"cobalt strike", "cobaltstrike", "beacon",
	"meterpreter", "metasploit",
	"empire", "powerview",
	"lazagne", "secretsdump",
	"crackmapexec", "cme",
	"chisel", "ligolo",
	"kerbrute", "impacket",
	"ncrack", "hydra", "medusa",
	"xmrig", "minerd", "cpuminer", // crypto miners
	"printspoofer", "juicypotato", "roguepotato",
}

// benignProcesses is a substring whitelist of processes that should never
// generate novelty alerts — they appear on virtually every endpoint and
// their first-sighting would flood the findings queue with noise.
var benignProcesses = []string{
	// Linux core
	"bash", "sh", "dash", "zsh", "fish",
	"systemd", "init", "kernel", "kthread",
	"sshd", "rsyslog", "journald", "dbus",
	"cron", "at", "anacron",
	"udev", "udevd",
	"python", "python3", "perl", "ruby",
	"apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "zypper",
	"vim", "nano", "less", "more", "cat", "grep", "awk", "sed",
	"find", "ls", "ps", "top", "htop", "netstat", "ss", "ip",
	"curl", "wget",
	"docker", "containerd", "runc", "podman",
	"nginx", "apache2", "httpd", "caddy",
	"postgres", "mysqld", "redis-server", "mongod",
	// Windows core
	"svchost.exe", "lsass.exe", "winlogon.exe", "explorer.exe",
	"taskmgr.exe", "cmd.exe", "powershell.exe",
	"services.exe", "wininit.exe", "csrss.exe", "smss.exe",
	"spoolsv.exe", "searchindexer.exe",
	"msiexec.exe", "wuauclt.exe", "wusa.exe",
	"chrome.exe", "msedge.exe", "firefox.exe",
	"teams.exe", "outlook.exe", "winword.exe", "excel.exe",
}

func isBenign(name string) bool {
	lower := strings.ToLower(name)
	for _, b := range benignProcesses {
		if strings.Contains(lower, b) {
			return true
		}
	}
	return false
}

func isAttackerTool(name string) bool {
	lower := strings.ToLower(name)
	for _, tool := range knownAttackerTools {
		if strings.Contains(lower, tool) {
			return true
		}
	}
	return false
}

func runProcessNoveltyDetection() {
	// Collect distinct (agent_id, tenant_id, process_name) seen in the last
	// 10 minutes. We use endpoint_processes (agent-pushed snapshots) rather
	// than logs so we catch processes that don't emit syslog lines.
	rows, err := database.DB.Query(`
		SELECT ep.agent_id, a.tenant_id, ep.process_name
		FROM endpoint_processes ep
		JOIN agents a ON a.id = ep.agent_id AND a.is_active = true
		WHERE ep.collected_at > NOW() - INTERVAL '10 minutes'
		  AND ep.process_name IS NOT NULL
		  AND ep.process_name <> ''
		GROUP BY ep.agent_id, a.tenant_id, ep.process_name
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	type procRow struct {
		agentID     int
		tenantID    int
		processName string
	}

	var procs []procRow
	for rows.Next() {
		var p procRow
		if err := rows.Scan(&p.agentID, &p.tenantID, &p.processName); err == nil {
			procs = append(procs, p)
		}
	}
	rows.Close()

	for _, p := range procs {
		// Always flag attacker tools, even if previously seen.
		if isAttackerTool(p.processName) {
			emitProcessNoveltyFinding(p.agentID, p.tenantID, p.processName, "critical",
				fmt.Sprintf("Known attacker tool detected: %q", p.processName))
			// Fall through — still upsert so the catalog is complete.
		}

		if isBenign(p.processName) {
			// Upsert silently — still build the catalog, but never alert.
			database.DB.Exec(`
				INSERT INTO agent_known_processes (agent_id, process_name, tenant_id)
				VALUES ($1, $2, $3)
				ON CONFLICT (agent_id, process_name) DO UPDATE
				    SET last_seen  = NOW(),
				        seen_count = agent_known_processes.seen_count + 1
			`, p.agentID, p.processName, p.tenantID)
			continue
		}

		// For non-benign processes: upsert and act on whether it's new or rare.
		var seenCount int
		err := database.DB.QueryRow(`
			INSERT INTO agent_known_processes (agent_id, process_name, tenant_id)
			VALUES ($1, $2, $3)
			ON CONFLICT (agent_id, process_name) DO UPDATE
			    SET last_seen  = NOW(),
			        seen_count = agent_known_processes.seen_count + 1
			RETURNING seen_count
		`, p.agentID, p.processName, p.tenantID).Scan(&seenCount)
		if err != nil {
			continue
		}

		switch seenCount {
		case 1:
			// First appearance — high severity novelty.
			emitProcessNoveltyFinding(p.agentID, p.tenantID, p.processName, "high",
				fmt.Sprintf("First-time process observed on this agent: %q", p.processName))
		case 2, 3:
			// Second/third sighting — could be new software install; low severity.
			emitProcessNoveltyFinding(p.agentID, p.tenantID, p.processName, "low",
				fmt.Sprintf("Rarely-seen process observed again (seen %d times): %q", seenCount, p.processName))
		}
		// After 4+ sightings: process is considered known — no more alerts.
	}
}

func emitProcessNoveltyFinding(agentID, tenantID int, processName, severity, description string) {
	// Deduplicate: one finding per (agent, process, 1-hour window).
	var exists bool
	database.DB.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM anomaly_findings
			WHERE agent_id = $1
			  AND tenant_id = $2
			  AND finding_type = 'process_novelty'
			  AND description LIKE $3
			  AND created_at > NOW() - INTERVAL '1 hour'
		)
	`, agentID, tenantID, "%"+processName+"%").Scan(&exists)
	if exists {
		return
	}

	ctx, _ := jsonMarshalSimple(map[string]string{"process_name": processName})
	database.DB.Exec(`
		INSERT INTO anomaly_findings
		    (agent_id, finding_type, description, severity, score, source, raw_context,
		     tenant_id, acknowledged)
		VALUES ($1,'process_novelty',$2,$3,$4,'process_novelty',$5,$6,false)
	`, agentID, description, severity, noveltyScore(severity), ctx, tenantID)

	// Escalate attacker tools and first-sightings as standard alerts.
	if severity == "critical" || severity == "high" {
		CreateAlert(models.Alert{
			AgentID:        agentID,
			RuleName:       "Process Novelty — " + processName,
			Severity:       severity,
			LogMessage:     description,
			MitreTactic:    "Execution",
			MitreTechnique: "T1204",
			MitreName:      "User Execution",
			Fingerprint:    fmt.Sprintf("%d-procnovelty-%s", agentID, processName),
		})
	}
}

func noveltyScore(severity string) int {
	switch severity {
	case "critical":
		return 95
	case "high":
		return 70
	default:
		return 30
	}
}

func jsonMarshalSimple(m map[string]string) ([]byte, error) {
	b := []byte(`{`)
	first := true
	for k, v := range m {
		if !first {
			b = append(b, ',')
		}
		b = append(b, fmt.Sprintf(`%q:%q`, k, v)...)
		first = false
	}
	b = append(b, '}')
	return b, nil
}
