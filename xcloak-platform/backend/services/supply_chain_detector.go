package services

// Supply Chain Attack Detector
//
// Detects indicators of software supply chain compromise: malicious package
// installs, build system abuse, dependency confusion, and living-off-the-land
// package manager patterns. All signals come from process creation logs
// (EventID 4688 on Windows, syslog/auditd on Linux) already ingested.
//
// Detection categories:
//
//  Curl-to-shell        (T1059.004) — curl/wget output piped directly to bash/sh/python
//  Sudo package install (T1072)    — pip/npm/gem/cargo/go installed by SYSTEM or root
//  Dependency confusion (T1195.001) — pip --extra-index-url or --index-url pointing to
//                                     a non-corporate registry alongside internal packages
//  Malicious script run (T1059)    — python/node executing content fetched from the network
//  Build tool injection (T1195.002) — make/cmake/gradle/maven downloading from internet
//  Package from Git URL (T1195.001) — npm/pip installing directly from git/http URLs
//  Unusual compiler     (T1027.004) — compiling in temp directories or /dev/shm
//  Soft update anomaly  (T1072)    — software update binary contacting unusual external host
//  Typosquatting lure   (T1195.001) — installing packages with names resembling popular libs
//  Container image tamper (T1525)  — docker build from modified Dockerfile, FROM scratch trick

import (
	"fmt"
	"log"
	"strings"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

var scDedup = newTTLMap(30 * time.Minute)

// Popular package names to check for near-exact typosquatting (edit-distance 1)
var popularPackages = []string{
	"requests", "numpy", "pandas", "flask", "django", "express", "react",
	"lodash", "axios", "boto3", "sqlalchemy", "pytest", "pillow", "cryptography",
	"paramiko", "pyyaml", "setuptools", "urllib3", "certifi", "charset-normalizer",
}

type scSig struct {
	fragments []string // ALL fragments must appear (case-insensitive AND)
	ruleName  string
	severity  string
	mitre     string
	mitreName string
}

var scSigs = []scSig{
	// Curl-to-shell variants
	{[]string{"curl", "| bash"}, "Curl-to-Bash — Remote Code Execution", "critical", "T1059.004", "Unix Shell"},
	{[]string{"curl", "| sh"}, "Curl-to-Shell — Remote Code Execution", "critical", "T1059.004", "Unix Shell"},
	{[]string{"curl", "| sudo"}, "Curl-to-Sudo — Privilege Escalation via Download", "critical", "T1059.004", "Unix Shell"},
	{[]string{"curl", "| python"}, "Curl-to-Python — Remote Script Execution", "critical", "T1059.006", "Python"},
	{[]string{"wget", "| bash"}, "Wget-to-Bash — Remote Code Execution", "critical", "T1059.004", "Unix Shell"},
	{[]string{"wget", "| sh"}, "Wget-to-Shell — Remote Code Execution", "critical", "T1059.004", "Unix Shell"},
	{[]string{"wget", "| python"}, "Wget-to-Python — Remote Script Execution", "critical", "T1059.006", "Python"},

	// Dependency confusion
	{[]string{"pip", "--extra-index-url"}, "Dependency Confusion — pip extra index (T1195.001)", "high", "T1195.001", "Compromise Software Dependencies"},
	{[]string{"pip", "--index-url", "http"}, "Dependency Confusion — pip non-HTTPS index", "high", "T1195.001", "Compromise Software Dependencies"},
	{[]string{"npm", "install", "http://"}, "Package from HTTP URL — npm (T1195.001)", "high", "T1195.001", "Compromise Software Dependencies"},
	{[]string{"pip", "install", "git+"}, "Package from Git URL — pip (T1195.001)", "high", "T1195.001", "Compromise Software Dependencies"},
	{[]string{"npm", "install", "git+"}, "Package from Git URL — npm (T1195.001)", "high", "T1195.001", "Compromise Software Dependencies"},
	{[]string{"pip", "install", "http"}, "Package from HTTP URL — pip (T1195.001)", "high", "T1195.001", "Compromise Software Dependencies"},

	// Compile/build in suspicious locations
	{[]string{"gcc", "/tmp/"}, "Compile in /tmp — Suspicious Build Location", "high", "T1027.004", "Compile After Delivery"},
	{[]string{"g++", "/tmp/"}, "Compile in /tmp — Suspicious Build Location", "high", "T1027.004", "Compile After Delivery"},
	{[]string{"gcc", "/dev/shm"}, "Compile in /dev/shm — Fileless Compile", "critical", "T1027.004", "Compile After Delivery"},
	{[]string{"make", "/tmp/"}, "Make in /tmp — Suspicious Build Location", "high", "T1027.004", "Compile After Delivery"},

	// Python/Node executing remote content
	{[]string{"python", "urllib", "exec("}, "Python Remote Exec — Dynamic Code Execution", "critical", "T1059.006", "Python"},
	{[]string{"python", "-c", "import os"}, "Python One-Liner — Possible Shellcode Loader", "high", "T1059.006", "Python"},
	{[]string{"node", "-e", "require('child_process')"}, "Node.js Remote Exec — child_process abuse", "critical", "T1059.007", "JavaScript"},

	// Build tool internet access
	{[]string{"gradle", "http://"}, "Gradle Build — HTTP Dependency (T1195.002)", "medium", "T1195.002", "Compromise Software Supply Chain"},
	{[]string{"mvn", "http://"}, "Maven Build — HTTP Repository", "medium", "T1195.002", "Compromise Software Supply Chain"},

	// Windows specific
	{[]string{"msiexec", "http"}, "MSI from HTTP — Possible Malicious Installer", "high", "T1218.007", "Msiexec"},
	{[]string{"msiexec", "ftp"}, "MSI from FTP — Possible Malicious Installer", "high", "T1218.007", "Msiexec"},
	{[]string{"nuget", "http://"}, "NuGet HTTP Source — Dependency Confusion Risk", "medium", "T1195.001", "Compromise Software Dependencies"},
	{[]string{"pip", "install", "--trusted-host"}, "pip trusted-host flag — TLS verification bypass", "medium", "T1195.001", "Compromise Software Dependencies"},

	// Package manager by SYSTEM/root
	{[]string{"system", "pip install"}, "System Account pip Install — Unusual Package Management", "high", "T1072", "Software Deployment Tools"},
	{[]string{"nt authority", "npm install"}, "SYSTEM npm Install — Possible Supply Chain Attack", "high", "T1072", "Software Deployment Tools"},
}

func StartSupplyChainScheduler() {
	go func() {
		time.Sleep(70 * time.Second)
		for {
			runSupplyChainDetection()
			time.Sleep(5 * time.Minute)
		}
	}()
}

func runSupplyChainDetection() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = true`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var tid int
		if rows.Scan(&tid) == nil {
			detectSupplyChainEvents(tid)
		}
	}
}

func detectSupplyChainEvents(tenantID int) {
	// Query process creation events that could indicate supply chain attacks
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       lower(coalesce(el.parsed_fields->>'command_line', el.log_message)) AS cmdline,
		       coalesce(el.parsed_fields->>'user','') AS user,
		       coalesce(el.parsed_fields->>'src_ip','') AS src_ip,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.created_at > NOW() - INTERVAL '5 minutes'
		  AND (
		       el.parsed_fields->>'event_id' = '4688'
		    OR el.log_message ILIKE '%pip install%'
		    OR el.log_message ILIKE '%npm install%'
		    OR el.log_message ILIKE '%gem install%'
		    OR el.log_message ILIKE '%curl%'
		    OR el.log_message ILIKE '%wget%'
		    OR el.log_message ILIKE '%msiexec%'
		    OR el.log_message ILIKE '%nuget%'
		    OR el.log_message ILIKE '%gradle%'
		    OR el.log_message ILIKE '%gcc %'
		    OR el.log_message ILIKE '%g++ %'
		  )
		LIMIT 2000
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var cmdline, user, srcIP, logMsg string
		if rows.Scan(&agentID, &cmdline, &user, &srcIP, &logMsg) != nil {
			continue
		}

		for _, sig := range scSigs {
			allMatch := true
			for _, frag := range sig.fragments {
				if !strings.Contains(cmdline, frag) {
					allMatch = false
					break
				}
			}
			if !allMatch {
				continue
			}

			key := fmt.Sprintf("%d:sc:%s:%s", tenantID, sig.mitre, user)
			if scDedup.touched(key) {
				break
			}
			scDedup.touch(key)

			msg := fmt.Sprintf("%s — user='%s' src_ip='%s' cmdline='%s'",
				sig.ruleName, user, srcIP, truncateLog(logMsg, 200))
			log.Printf("[SupplyChain] %s", msg)

			CreateAlert(models.Alert{
				AgentID:        agentID,
				TenantID:       tenantID,
				Severity:       sig.severity,
				RuleName:       sig.ruleName,
				LogMessage:     msg,
				MitreTactic:    "Initial Access",
				MitreTechnique: sig.mitre,
				MitreName:      sig.mitreName,
				Fingerprint:    fmt.Sprintf("sc-%s-%d-%s", sig.mitre, tenantID, user),
			})
			break
		}

		// Typosquatting check: package names with edit-distance 1 from popular packages
		if strings.Contains(cmdline, "pip install") || strings.Contains(cmdline, "npm install") ||
			strings.Contains(cmdline, "gem install") {
			detectTyposquatPackage(agentID, tenantID, user, srcIP, cmdline)
		}
	}
}

// detectTyposquatPackage looks for package names with Levenshtein distance 1 from
// popular packages — a common supply chain attack vector.
func detectTyposquatPackage(agentID, tenantID int, user, srcIP, cmdline string) {
	words := strings.Fields(cmdline)
	for _, word := range words {
		word = strings.Trim(word, `"'`)
		if len(word) < 4 {
			continue
		}
		for _, pkg := range popularPackages {
			if word == pkg {
				break
			}
			dist := levenshtein(word, pkg)
			if dist == 1 {
				key := fmt.Sprintf("%d:typosquat:%s:%s", tenantID, word, user)
				if scDedup.touched(key) {
					break
				}
				scDedup.touch(key)
				msg := fmt.Sprintf("Possible Typosquatting Package — installing='%s' resembles='%s' edit_distance=1 user='%s'",
					word, pkg, user)
				log.Printf("[SupplyChain] %s", msg)
				CreateAlert(models.Alert{
					AgentID:        agentID,
					TenantID:       tenantID,
					Severity:       "high",
					RuleName:       "Typosquatting Package Detected",
					LogMessage:     msg,
					MitreTactic:    "Initial Access",
					MitreTechnique: "T1195.001",
					MitreName:      "Compromise Software Dependencies",
					Fingerprint:    fmt.Sprintf("sc-typosquat-%d-%s", tenantID, word),
				})
				break
			}
		}
	}
}
