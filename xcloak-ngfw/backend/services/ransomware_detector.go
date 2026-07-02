package services

// Ransomware Behavior Detector
//
// Detects ransomware at two layers:
//
// Layer 1 — FIM mass-modification (T1486):
//   ≥ 20 file changes on the same agent in 10 minutes where the new file
//   path ends in a known crypto extension OR the change_type is 'modified'
//   across many distinct directories (scatter pattern = encryption sweep).
//
// Layer 2 — Kill-chain command patterns (T1490, T1562.001):
//   Shadow copy deletion:  vssadmin delete shadows, wmic shadowcopy delete
//   Backup killers:        bcdedit /set recoveryenabled no, wbadmin delete
//   AV/EDR kill:           net stop, sc stop targeting security services
//   Recovery disable:      wmic shadowcopy delete, diskshadow /s
//
// Runs every 3 minutes. Alert dedup TTL: 20 minutes per (agent, pattern).

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

const (
	ransomFIMThreshold   = 20 // file changes per agent in window
	ransomFIMWindow      = "10 minutes"
	ransomDedupTTL       = 20 * time.Minute
)

var ransomDedup = newTTLMap(ransomDedupTTL)

// Crypto file extensions observed in ransomware campaigns
var cryptoExtensions = []string{
	".encrypted", ".enc", ".locked", ".crypto", ".crypt",
	".locky", ".zepto", ".cerber", ".wnry", ".wncry",
	".wannacry", ".petya", ".notpetya", ".ryuk",
	".revil", ".sodinokibi", ".darkside", ".conti",
	".maze", ".egregor", ".ransom", ".pay2decrypt",
	".crypz", ".micro", ".zzzzz",
}

// Kill-chain commands used by ransomware before/during encryption
var ransomKillChainPatterns = []struct {
	needle   string
	ruleName string
	severity string
	mitre    string
	mitreNm  string
}{
	{
		"vssadmin delete shadows",
		"Shadow Copy Deletion via VSSAdmin",
		"critical", "T1490", "Inhibit System Recovery",
	},
	{
		"wmic shadowcopy delete",
		"Shadow Copy Deletion via WMIC",
		"critical", "T1490", "Inhibit System Recovery",
	},
	{
		"diskshadow /s",
		"Shadow Copy Deletion via DiskShadow",
		"critical", "T1490", "Inhibit System Recovery",
	},
	{
		"bcdedit /set recoveryenabled no",
		"Boot Recovery Disabled",
		"critical", "T1490", "Inhibit System Recovery",
	},
	{
		"bcdedit /set bootstatuspolicy ignoreallfailures",
		"Boot Recovery Disabled",
		"critical", "T1490", "Inhibit System Recovery",
	},
	{
		"wbadmin delete catalog",
		"Windows Backup Catalog Deleted",
		"critical", "T1490", "Inhibit System Recovery",
	},
	{
		"wbadmin delete systemstatebackup",
		"System State Backup Deleted",
		"critical", "T1490", "Inhibit System Recovery",
	},
	{
		"schtasks /delete",
		"Scheduled Tasks Deleted (pre-ransomware)",
		"high", "T1562.001", "Disable or Modify Tools",
	},
}

// Security product names targeted by ransomware kill scripts
var securityServices = []string{
	"mssmpeng", "avp", "avgnt", "mbam", "malwarebytes",
	"bdagent", "vsserv", "ekrn", "egui", "sophos",
	"savservice", "mcshield", "mcafee", "symantec",
	"ccsvchst", "sav", "kavfs", "klnagent", "cbdefense",
	"csfalconservice", "falconservice", "cylance",
	"cyserver", "sentinelone", "s1agent",
}

func StartRansomwareScheduler() {
	go func() {
		time.Sleep(90 * time.Second)
		for {
			runRansomwareDetection()
			time.Sleep(3 * time.Minute)
		}
	}()
}

func runRansomwareDetection() {
	tenants, err := repositories.GetActiveTenantIDs()
	if err != nil {
		return
	}
	for _, tid := range tenants {
		detectFIMRansomware(tid)
		detectKillChainCommands(tid)
		detectSecurityServiceKill(tid)
	}
}

// ── Layer 1: FIM mass-modification sweep ─────────────────────────────────────

func detectFIMRansomware(tenantID int) {
	candidates, err := repositories.GetFIMRansomwareCandidates(tenantID, ransomFIMThreshold, cryptoExtSQL())
	if err != nil {
		return
	}

	for _, c := range candidates {
		key := fmt.Sprintf("%d:ransom-fim:%d", tenantID, c.AgentID)
		if ransomDedup.touched(key) {
			continue
		}
		ransomDedup.touch(key)

		severity := "high"
		if c.CryptoCount >= 5 || c.TotalChanges >= 50 {
			severity = "critical"
		}

		msg := fmt.Sprintf(
			"Ransomware behavior — mass file modification: agent %d modified %d files across %d directories in %s (crypto extensions: %d)",
			c.AgentID, c.TotalChanges, c.DirsHit, ransomFIMWindow, c.CryptoCount,
		)
		slog.Warn("ransomware detected", "msg", msg)
		CreateAlert(models.Alert{
			AgentID:        c.AgentID,
			TenantID:       tenantID,
			Severity:       severity,
			RuleName:       "Ransomware — Mass File Modification",
			LogMessage:     msg,
			MitreTactic:    "Impact",
			MitreTechnique: "T1486",
			MitreName:      "Data Encrypted for Impact",
			Fingerprint:    fmt.Sprintf("ransomware-fim-%d", c.AgentID),
		})
	}
}

// cryptoExtSQL builds a SQL CASE expression for crypto extension matching.
func cryptoExtSQL() string {
	parts := make([]string, len(cryptoExtensions))
	for i, ext := range cryptoExtensions {
		parts[i] = fmt.Sprintf("lower(fa.file_path) LIKE '%%%s'", ext)
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

// ── Layer 2: Kill-chain command detection ──────────────────────────────────────

func detectKillChainCommands(tenantID int) {
	logs, err := repositories.GetRecentProcessLogs(tenantID)
	if err != nil {
		return
	}

	for _, row := range logs {
		searchText := strings.ToLower(row.LogMessage + " " + row.CmdLine)

		for _, pat := range ransomKillChainPatterns {
			if !strings.Contains(searchText, pat.needle) {
				continue
			}
			key := fmt.Sprintf("%d:ransom-kc:%d:%s", tenantID, row.AgentID, pat.needle)
			if ransomDedup.touched(key) {
				continue
			}
			ransomDedup.touch(key)

			msg := fmt.Sprintf("Ransomware kill-chain — %s detected on agent %d: %s",
				pat.ruleName, row.AgentID, truncateLog(row.LogMessage, 300))
			slog.Warn("ransomware detected", "msg", msg)
			CreateAlert(models.Alert{
				AgentID:        row.AgentID,
				TenantID:       tenantID,
				Severity:       pat.severity,
				RuleName:       pat.ruleName,
				LogMessage:     msg,
				MitreTactic:    "Impact",
				MitreTechnique: pat.mitre,
				MitreName:      pat.mitreNm,
				Fingerprint:    fmt.Sprintf("ransomware-kc-%d-%s", row.AgentID, strings.ReplaceAll(pat.needle[:10], " ", "-")),
			})
			break
		}
	}
}

// ── Layer 3: Security service kill (ransomware EDR evasion) ──────────────────

func detectSecurityServiceKill(tenantID int) {
	logs, err := repositories.GetRecentServiceStopLogs(tenantID)
	if err != nil {
		return
	}

	for _, row := range logs {
		lower := strings.ToLower(row.LogMessage)
		for _, svc := range securityServices {
			if !strings.Contains(lower, svc) {
				continue
			}
			key := fmt.Sprintf("%d:ransom-svcstop:%d:%s", tenantID, row.AgentID, svc)
			if ransomDedup.touched(key) {
				continue
			}
			ransomDedup.touch(key)
			msg := fmt.Sprintf("Security service '%s' killed on agent %d (ransomware evasion pattern): %s",
				svc, row.AgentID, truncateLog(row.LogMessage, 300))
			slog.Warn("ransomware detected", "msg", msg)
			CreateAlert(models.Alert{
				AgentID:        row.AgentID,
				TenantID:       tenantID,
				Severity:       "critical",
				RuleName:       "Security Tool Disabled (Ransomware Pattern)",
				LogMessage:     msg,
				MitreTactic:    "Defense Evasion",
				MitreTechnique: "T1562.001",
				MitreName:      "Disable or Modify Tools",
				Fingerprint:    fmt.Sprintf("ransom-svcstop-%d-%s", row.AgentID, svc),
			})
			break
		}
	}
}
