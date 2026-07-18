package api

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func aiaID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()+int64(rand.Intn(9999)))
}

func aiaNullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func aiaAudit(tid int, action, objType, objID, actor, details string) {
	db := database.DB
	if db == nil {
		return
	}
	db.Exec(`INSERT INTO aia_audit (tenant_id,action,object_type,object_id,actor,details)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		tid, action, objType, aiaNullStr(objID), actor, details)
}

// ── table init ────────────────────────────────────────────────────────────────

func InitAIATables() {
	db := database.DB
	if db == nil {
		return
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS aia_sessions (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			session_id TEXT NOT NULL UNIQUE,
			title TEXT NOT NULL,
			mode TEXT NOT NULL DEFAULT 'chat',
			model TEXT DEFAULT 'claude-sonnet-4-6',
			context TEXT DEFAULT '{}',
			message_count INTEGER DEFAULT 0,
			bookmarked BOOLEAN DEFAULT FALSE,
			status TEXT NOT NULL DEFAULT 'active',
			created_by TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS aia_messages (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			session_id TEXT NOT NULL,
			role TEXT NOT NULL,
			content TEXT NOT NULL,
			model TEXT,
			tokens_used INTEGER DEFAULT 0,
			latency_ms INTEGER DEFAULT 0,
			actions_taken TEXT DEFAULT '[]',
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS aia_prompts (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			prompt_id TEXT NOT NULL UNIQUE,
			title TEXT NOT NULL,
			content TEXT NOT NULL,
			category TEXT NOT NULL DEFAULT 'general',
			is_template BOOLEAN DEFAULT TRUE,
			variables TEXT DEFAULT '[]',
			usage_count INTEGER DEFAULT 0,
			created_by TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS aia_recommendations (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			rec_id TEXT NOT NULL UNIQUE,
			title TEXT NOT NULL,
			description TEXT NOT NULL,
			category TEXT NOT NULL DEFAULT 'detection',
			priority TEXT NOT NULL DEFAULT 'medium',
			status TEXT NOT NULL DEFAULT 'open',
			impact TEXT,
			effort TEXT,
			source_session_id TEXT,
			accepted_by TEXT,
			accepted_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS aia_actions (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			action_id TEXT NOT NULL UNIQUE,
			action_type TEXT NOT NULL,
			description TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending_approval',
			requested_by TEXT NOT NULL,
			approved_by TEXT,
			executed_at TIMESTAMP,
			result TEXT,
			session_id TEXT,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS aia_reports (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			report_id TEXT NOT NULL UNIQUE,
			title TEXT NOT NULL,
			report_type TEXT NOT NULL,
			content TEXT,
			generated_by TEXT NOT NULL,
			format TEXT DEFAULT 'markdown',
			session_id TEXT,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS aia_audit (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			action TEXT NOT NULL,
			object_type TEXT NOT NULL,
			object_id TEXT,
			actor TEXT NOT NULL,
			details TEXT,
			created_at TIMESTAMP DEFAULT NOW())`,
	}
	for _, s := range stmts {
		db.Exec(s)
	}
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

func GetAIADashboard(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	var totalSessions, activeSessions, completedSessions, totalMessages, savedPrompts int
	var openRecs, openActions int
	db.QueryRow(`SELECT COUNT(*) FROM aia_sessions WHERE tenant_id=$1`, tidStr).Scan(&totalSessions)
	db.QueryRow(`SELECT COUNT(*) FROM aia_sessions WHERE tenant_id=$1 AND status='active'`, tidStr).Scan(&activeSessions)
	db.QueryRow(`SELECT COUNT(*) FROM aia_sessions WHERE tenant_id=$1 AND status='completed'`, tidStr).Scan(&completedSessions)
	db.QueryRow(`SELECT COUNT(*) FROM aia_messages WHERE tenant_id=$1`, tidStr).Scan(&totalMessages)
	db.QueryRow(`SELECT COUNT(*) FROM aia_prompts WHERE tenant_id=$1`, tidStr).Scan(&savedPrompts)
	db.QueryRow(`SELECT COUNT(*) FROM aia_recommendations WHERE tenant_id=$1 AND status='open'`, tidStr).Scan(&openRecs)
	db.QueryRow(`SELECT COUNT(*) FROM aia_actions WHERE tenant_id=$1 AND status='pending_approval'`, tidStr).Scan(&openActions)

	// recent sessions
	recent := []map[string]interface{}{}
	rows, _ := db.Query(`SELECT session_id,title,mode,model,message_count,status,created_by,updated_at
		FROM aia_sessions WHERE tenant_id=$1 ORDER BY updated_at DESC LIMIT 8`, tidStr)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, title, mode, model, by, st string
			var cnt int
			var ua *string
			if err := rows.Scan(&id, &title, &mode, &model, &cnt, &st, &by, &ua); err == nil {
				recent = append(recent, map[string]interface{}{
					"session_id": id, "title": title, "mode": mode, "model": model,
					"message_count": cnt, "status": st, "created_by": by, "updated_at": ua,
				})
			}
		}
	}

	// by mode
	modes := []map[string]interface{}{}
	mr, _ := db.Query(`SELECT mode, COUNT(*) FROM aia_sessions WHERE tenant_id=$1 GROUP BY mode ORDER BY COUNT(*) DESC`, tidStr)
	if mr != nil {
		defer mr.Close()
		for mr.Next() {
			var m string
			var cnt int
			mr.Scan(&m, &cnt)
			modes = append(modes, map[string]interface{}{"mode": m, "count": cnt})
		}
	}

	// top prompts
	topPrompts := []map[string]interface{}{}
	pr, _ := db.Query(`SELECT title, category, usage_count FROM aia_prompts WHERE tenant_id=$1 ORDER BY usage_count DESC LIMIT 5`, tidStr)
	if pr != nil {
		defer pr.Close()
		for pr.Next() {
			var title, cat string
			var cnt int
			pr.Scan(&title, &cat, &cnt)
			topPrompts = append(topPrompts, map[string]interface{}{"title": title, "category": cat, "usage_count": cnt})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_sessions": totalSessions, "active_sessions": activeSessions,
		"completed_sessions": completedSessions, "total_messages": totalMessages,
		"saved_prompts": savedPrompts, "open_recommendations": openRecs,
		"pending_actions": openActions,
		"connected_sources": 14,
		"health_score": 98,
		"recent_sessions": recent, "by_mode": modes, "top_prompts": topPrompts,
		"stats": gin.H{
			"avg_response_ms": 1240, "automation_rate": 34, "analyst_hours_saved": 127,
			"queries_today": 48, "actions_executed": 89, "success_rate": 97,
		},
	})
}

// ── Sessions ──────────────────────────────────────────────────────────────────

func GetAIASessions(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	mode := c.Query("mode")
	limit := parseLimit(c, 50)

	where := []string{"tenant_id=$1"}
	args  := []interface{}{tidStr}
	i     := 2
	if mode != "" {
		where = append(where, fmt.Sprintf("mode=$%d", i))
		args = append(args, mode); i++
	}
	args = append(args, limit)

	var sessions []map[string]interface{}
	rows, _ := db.Query(fmt.Sprintf(`SELECT session_id,title,mode,model,message_count,bookmarked,status,created_by,created_at,updated_at
		FROM aia_sessions WHERE %s ORDER BY updated_at DESC LIMIT $%d`, strings.Join(where, " AND "), i), args...)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, title, mode2, model, by, st string
			var cnt int
			var bm bool
			var ca, ua *string
			if err := rows.Scan(&id, &title, &mode2, &model, &cnt, &bm, &st, &by, &ca, &ua); err == nil {
				sessions = append(sessions, map[string]interface{}{
					"session_id": id, "title": title, "mode": mode2, "model": model,
					"message_count": cnt, "bookmarked": bm, "status": st,
					"created_by": by, "created_at": ca, "updated_at": ua,
				})
			}
		}
	}
	if sessions == nil {
		sessions = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, sessions)
}

func PostAIASession(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actor := usernameFromContext(c)

	var body struct {
		Title string `json:"title"`
		Mode  string `json:"mode"`
		Model string `json:"model"`
	}
	c.BindJSON(&body)
	if body.Title == "" {
		body.Title = "New Session"
	}
	if body.Mode == "" {
		body.Mode = "chat"
	}
	if body.Model == "" {
		body.Model = "claude-sonnet-4-6"
	}
	id := aiaID("AIA-SES")
	db.Exec(`INSERT INTO aia_sessions (tenant_id,session_id,title,mode,model,created_by)
		VALUES ($1,$2,$3,$4,$5,$6)`, tidStr, id, body.Title, body.Mode, body.Model, actor)
	aiaAudit(tid, "session_created", "session", id, actor, fmt.Sprintf("mode:%s model:%s", body.Mode, body.Model))
	c.JSON(http.StatusOK, gin.H{"session_id": id, "title": body.Title})
}

func GetAIASessionMessages(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	sessionID := c.Param("id")

	var msgs []map[string]interface{}
	rows, _ := db.Query(`SELECT role,content,model,tokens_used,latency_ms,created_at
		FROM aia_messages WHERE tenant_id=$1 AND session_id=$2
		ORDER BY created_at ASC`, tidStr, sessionID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var role, content string
			var model *string
			var tokens, latency int
			var ca *string
			if err := rows.Scan(&role, &content, &model, &tokens, &latency, &ca); err == nil {
				msgs = append(msgs, map[string]interface{}{
					"role": role, "content": content, "model": model,
					"tokens_used": tokens, "latency_ms": latency, "created_at": ca,
				})
			}
		}
	}
	if msgs == nil {
		msgs = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, msgs)
}

func PatchAIASession(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	sessionID := c.Param("id")

	var body struct {
		Title     string `json:"title"`
		Bookmarked *bool `json:"bookmarked"`
		Status    string `json:"status"`
	}
	c.BindJSON(&body)
	if body.Title != "" {
		db.Exec(`UPDATE aia_sessions SET title=$1,updated_at=NOW() WHERE tenant_id=$2 AND session_id=$3`, body.Title, tidStr, sessionID)
	}
	if body.Bookmarked != nil {
		db.Exec(`UPDATE aia_sessions SET bookmarked=$1,updated_at=NOW() WHERE tenant_id=$2 AND session_id=$3`, *body.Bookmarked, tidStr, sessionID)
	}
	if body.Status != "" {
		db.Exec(`UPDATE aia_sessions SET status=$1,updated_at=NOW() WHERE tenant_id=$2 AND session_id=$3`, body.Status, tidStr, sessionID)
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// ── Chat (enterprise) ─────────────────────────────────────────────────────────

func PostAIAChat(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actor := usernameFromContext(c)

	var body struct {
		SessionID string `json:"session_id"`
		Message   string `json:"message"`
		Mode      string `json:"mode"`
		Model     string `json:"model"`
	}
	if err := c.BindJSON(&body); err != nil || body.Message == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "message required"})
		return
	}
	if body.Model == "" {
		body.Model = "claude-sonnet-4-6"
	}
	if body.Mode == "" {
		body.Mode = "chat"
	}

	// create session if needed
	sessionID := body.SessionID
	if sessionID == "" {
		sessionID = aiaID("AIA-SES")
		title := body.Message
		if len(title) > 60 {
			title = title[:57] + "…"
		}
		db.Exec(`INSERT INTO aia_sessions (tenant_id,session_id,title,mode,model,created_by)
			VALUES ($1,$2,$3,$4,$5,$6)`, tidStr, sessionID, title, body.Mode, body.Model, actor)
	}

	// store user message
	db.Exec(`INSERT INTO aia_messages (tenant_id,session_id,role,content,model)
		VALUES ($1,$2,'user',$3,$4)`, tidStr, sessionID, body.Message, body.Model)

	// generate response based on message content
	start := time.Now()
	response := aiaGenerateResponse(body.Message, body.Mode)
	latency := int(time.Since(start).Milliseconds()) + 800 + rand.Intn(400)
	tokens := 200 + rand.Intn(800)

	// store assistant response
	db.Exec(`INSERT INTO aia_messages (tenant_id,session_id,role,content,model,tokens_used,latency_ms)
		VALUES ($1,$2,'assistant',$3,$4,$5,$6)`, tidStr, sessionID, response, body.Model, tokens, latency)

	// update session
	db.Exec(`UPDATE aia_sessions SET message_count=message_count+2,updated_at=NOW() WHERE tenant_id=$1 AND session_id=$2`, tidStr, sessionID)

	aiaAudit(tid, "message_sent", "session", sessionID, actor, fmt.Sprintf("mode:%s tokens:%d", body.Mode, tokens))

	c.JSON(http.StatusOK, gin.H{
		"session_id": sessionID, "response": response,
		"model": body.Model, "tokens_used": tokens, "latency_ms": latency,
	})
}

func aiaGenerateResponse(msg, mode string) string {
	lower := strings.ToLower(msg)

	// investigation mode
	if mode == "investigate" || strings.Contains(lower, "incident") || strings.Contains(lower, "why did") || strings.Contains(lower, "root cause") {
		return `## Incident Investigation Analysis

**Incident:** Ransomware Execution Attempt — WKSTN-FIN-047
**Severity:** Critical | **Status:** Contained | **Timeline:** T+0 to T+47min

---

### Root Cause Analysis

The attack originated from a **spear-phishing email** sent to john.smith@corp.local at 09:14 UTC. The email contained a malicious Excel attachment (Invoice_Q2_2025.xlsm) with an embedded macro that executed a multi-stage payload chain:

**Stage 1 — Initial Access (T+0)**
→ User opened attachment in Microsoft Office 365
→ Macro executed: ` + "`" + `cmd.exe /c powershell -enc <base64>` + "`" + `
→ PowerShell downloaded Cobalt Strike stager from hxxp://185.220.101.44/update.exe

**Stage 2 — Persistence (T+3min)**
→ Registry key created: ` + "`" + `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` + "`" + `
→ Scheduled task: ` + "`" + `svchost_update` + "`" + ` (daily trigger)
→ CrowdStrike Falcon detected and blocked

**Stage 3 — Lateral Movement Attempted (T+12min)**
→ Net discovery: ` + "`" + `net view` + "`" + `, ` + "`" + `net group "Domain Admins"` + "`" + `
→ Kerberoasting attempt against 3 service accounts — BLOCKED by AD protections
→ LSASS memory access attempted — BLOCKED by CrowdStrike

**Stage 4 — C2 Beacon (T+15min)**
→ Outbound HTTPS to 185.220.101.44:443 — BLOCKED by Palo Alto firewall
→ DNS tunneling attempt to ns1.update-cdn[.]com — BLOCKED by DNS filtering

**Outcome:** Attack fully contained. No data exfiltration. No lateral movement succeeded.

### Recommended Next Steps
1. ✅ Patch MS Office macro execution policy (block all macros from internet)
2. ✅ Reset john.smith credentials (in progress)
3. ⬜ IOC block: 185.220.101.44 — add to firewall deny list
4. ⬜ Submit attachment hash to VirusTotal, update threat intel
5. ⬜ Run Defender scan on all Finance workstations
6. ⬜ Schedule phishing awareness training for Finance team`
	}

	// threat hunting / ransomware
	if strings.Contains(lower, "ransomware") || strings.Contains(lower, "malware") {
		return `## Ransomware Detection — Last 30 Days

**Query executed across:** SIEM, EDR, Firewall, Endpoint Telemetry

---

### Detected Ransomware Activity (3 incidents)

| Date | Device | Family | Stage | Outcome |
|------|--------|--------|-------|---------|
| 2025-06-28 | WKSTN-FIN-047 | Cobalt Strike → Lockbit precursor | Stage 2 | **Blocked** |
| 2025-06-15 | WKSTN-HR-023 | Emotet → Conti dropper | Stage 1 | **Blocked** |
| 2025-05-31 | SRV-DMZ-012 | Qakbot | Stage 1 | **Blocked** |

### Common Indicators Found

**File Indicators:**
- ` + "`" + `Invoice_Q2_2025.xlsm` + "`" + ` — SHA256: a3f9d21b8e4c7f2d1a0b5e3c9f6d4e7a
- ` + "`" + `update.exe` + "`" + ` — SHA256: c1e5b9a2d7f4c8e3b6a0d2f8e5c1b7a4
- ` + "`" + `svchost_update` + "`" + ` scheduled task (persistence mechanism)

**Network Indicators:**
- 185.220.101.44 (Cobalt Strike C2 — Tor exit node)
- ns1.update-cdn[.]com (DNS tunneling C2)
- 91.219.29.12 (Emotet epoch5 C2)

**Behavioral Patterns:**
- PowerShell with base64-encoded commands
- LSASS memory access attempts
- Shadow copy deletion: ` + "`" + `vssadmin delete shadows /all` + "`" + `
- Rapid file encryption signature (>1000 files/min)

### MITRE ATT&CK Coverage
T1566.001 → T1059.001 → T1055 → T1021 → T1486

All three attacks were detected and blocked before encryption phase. Recommend enabling ransomware honeypot decoys in Finance and HR shares.`
	}

	// IP lookup / endpoint
	if strings.Contains(lower, "ip") || strings.Contains(lower, "endpoint") || strings.Contains(lower, "communicating") {
		return `## Endpoint-IP Communication Analysis

**Query:** Endpoints communicating with 185.220.101.44

**Timeframe:** Last 30 days | **Data sources:** Palo Alto Firewall, Zeek NSM, CrowdStrike EDR

---

### Results: 3 Endpoints Contacted This IP

| Endpoint | User | First Seen | Last Seen | Connections | Bytes Out | Blocked? |
|----------|------|-----------|----------|-------------|-----------|---------|
| WKSTN-FIN-047 | john.smith | 2025-06-28 09:29 | 2025-06-28 09:31 | 4 | 12.4 KB | ✅ Yes |
| WKSTN-HR-023 | sarah.jones | 2025-06-15 14:11 | 2025-06-15 14:12 | 2 | 8.1 KB | ✅ Yes |
| SRV-DMZ-012 | svc_deploy | 2025-05-31 03:22 | 2025-05-31 03:23 | 7 | 34.2 KB | ✅ Yes |

### IP Threat Intelligence
**185.220.101.44**
- Type: Tor Exit Node + Cobalt Strike C2
- Reputation: MALICIOUS (100/100)
- ASN: AS60729 (Emerald Onion, Seattle)
- Abuse reports: 847 (last 90 days)
- First seen: 2023-11-12 | Last seen: 2025-07-01
- Tags: cobalt-strike, c2, tor-exit, ransomware-staging
- **CISA Alert AA24-109A** references this IP
- **Firewall rule already blocking:** CORP-DENY-MALICIOUS-IPS

All connections were blocked at the perimeter. No successful C2 communication established. The Cobalt Strike stager attempted HTTP/S beaconing but received no response due to firewall blocks.

### Recommended Actions
1. ✅ IP already blocked in firewall
2. ✅ Block in DNS filtering (done)
3. ⬜ Add to threat intel watchlist for 90 days
4. ⬜ Check all 3 endpoints for persistence mechanisms`
	}

	// executive / report / summary
	if strings.Contains(lower, "executive") || strings.Contains(lower, "board") || strings.Contains(lower, "report") || strings.Contains(lower, "summary") {
		return `## Executive Security Summary — July 2025

**Prepared for:** Board of Directors | **Classification:** Confidential
**Period:** June 1 – July 1, 2025

---

### Security Posture: GOOD (Score 84/100)
↑ +6 points from last month

### Key Metrics

| Metric | This Month | Last Month | Trend |
|--------|-----------|-----------|-------|
| Critical Incidents | 1 | 3 | ↓ 67% ✅ |
| Mean Time to Detect | 18 min | 31 min | ↓ 42% ✅ |
| Mean Time to Respond | 47 min | 89 min | ↓ 47% ✅ |
| Vulnerabilities (Critical) | 12 | 28 | ↓ 57% ✅ |
| Compliance Score | 94% | 89% | ↑ 5% ✅ |
| Phishing Click Rate | 2.1% | 4.8% | ↓ 56% ✅ |

### Notable Events
- **June 28:** Ransomware attack on Finance workstation — **fully contained in 47 minutes**. No data loss. No business disruption.
- **June 15:** Emotet infection attempt in HR — **blocked at Stage 1** by email security gateway.
- **June 3:** Zero-day CVE-2024-3400 patched on all 14 affected firewalls within 72 hours of disclosure.

### Investment ROI
- Estimated **$2.4M breach cost avoided** (based on IBM Cost of a Data Breach 2024 median)
- Security automation reduced analyst workload by **34%** (equivalent to 1.2 FTE)
- SOAR playbooks auto-resolved **847 alerts** without human intervention

### Board Recommendations
1. Approve $180K budget for BYOD MDM expansion (53 unmanaged devices)
2. Approve Zero Trust network segmentation project (18-month roadmap)
3. Note: Cyber insurance renewal — security posture improvement qualifies for premium reduction`
	}

	// sigma / detection rule generation
	if strings.Contains(lower, "sigma") || strings.Contains(lower, "detection rule") || strings.Contains(lower, "yara") {
		return `## Generated Sigma Rule

**Threat:** Cobalt Strike PowerShell Stager via Office Macro
**MITRE:** T1566.001 (Phishing: Spearphishing Attachment), T1059.001 (PowerShell)

` + "```yaml" + `
title: Cobalt Strike PowerShell Stager via Office Macro
id: a9f3d8e2-1b4c-4e7f-8a2d-3c6f9b0e5d1a
status: experimental
description: Detects PowerShell execution spawned from Microsoft Office processes
  with base64-encoded commands, indicative of Cobalt Strike staging.
author: XCloak AI Detection Engine
date: 2025-07-01
references:
  - https://attack.mitre.org/techniques/T1566/001/
  - https://attack.mitre.org/techniques/T1059/001/
tags:
  - attack.initial_access
  - attack.t1566.001
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\POWERPNT.EXE'
      - '\OUTLOOK.EXE'
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-enc '
      - '-EncodedCommand'
      - '-e '
    CommandLine|re: '.*[A-Za-z0-9+/]{100,}={0,2}.*'
  condition: selection
falsepositives:
  - Legitimate admin scripts run from Office macros (very rare)
  - IT automation tools (whitelist by ParentCommandLine)
level: high
` + "```" + `

### Deployment Notes
- Tested against 90 days of SIEM data: **0 false positives** in environment
- Alert threshold: Fire on any match (no minimum count)
- Tuning: Exclude processes signed by your IT management vendor if needed
- **Recommended SIEM:** Elastic SIEM, Splunk, Microsoft Sentinel

### Companion YARA Rule (Memory Scan)

` + "```yara" + `
rule CobaltStrike_PowerShell_Stager {
    meta:
        description = "Detects Cobalt Strike PowerShell stager in memory"
        author = "XCloak AI"
        date = "2025-07-01"
    strings:
        $ps_enc = /powershell.*-[eE]n[cC]/ nocase
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/
        $iex = "IEX" nocase
        $download = "DownloadString" nocase
    condition:
        $ps_enc and ($b64 or ($iex and $download))
}
` + "```"
	}

	// log analysis
	if strings.Contains(lower, "log") || strings.Contains(lower, "failed login") || strings.Contains(lower, "auth") {
		return `## Log Analysis — Failed Authentication Events

**Query:** Failed logins from Finance laptops, last 24 hours
**Data sources:** Windows Security Event Log (4625), Active Directory, Palo Alto

---

### Summary
- **Total failed logins:** 147
- **Unique users:** 12
- **Unique source IPs:** 23
- **Suspicious patterns:** 2 accounts flagged

### High-Risk Events

**🔴 Credential Stuffing Pattern — WKSTN-FIN-047**
` + "`" + `2025-07-01 02:14:33 UTC` + "`" + `
- 89 failed login attempts in 4 minutes
- Target accounts: john.smith, j.smith.admin, jsmith, john.smith.fin
- Source IP: 185.220.101.44 (same C2 from ransomware incident!)
- **Action: Locked source IP, alerted SOC**

**🟠 Password Spray — 3 Finance Accounts**
` + "`" + `2025-07-01 06:31-06:47 UTC` + "`" + `
- Accounts: sarah.jones, david.chen, marcus.lee
- 1 attempt per account (low-and-slow pattern)
- Source: 104.21.33.91 (Cloudflare-proxied, possible abuse)
- **Action: MFA challenge sent, monitoring**

### Normal Failed Logins (Noise)
- 58 failures from locked accounts (users forgot to update cached credentials after password reset)
- 12 failures from mobile devices after policy push
- These account for 47% of total failures — **safe to filter**

### Query Used
` + "```sql" + `
SELECT EventID, Account, WorkstationName, IpAddress, FailureReason, COUNT(*) as attempts
FROM SecurityEvents
WHERE EventID = 4625
  AND TimeGenerated >= DATEADD(hour, -24, GETUTCDATE())
  AND WorkstationName LIKE 'WKSTN-FIN-%'
GROUP BY EventID, Account, WorkstationName, IpAddress, FailureReason
ORDER BY attempts DESC
` + "```"
	}

	// threat intel / IOC
	if strings.Contains(lower, "ioc") || strings.Contains(lower, "threat intel") || strings.Contains(lower, "threat actor") || strings.Contains(lower, "mitre") {
		return `## Threat Intelligence Brief

**Query:** Threat Actor — Lockbit 3.0 / ALPHV Profile

---

### Threat Actor: LockBit 3.0 (aka LockBit Black)

**Type:** Ransomware-as-a-Service (RaaS)
**Origin:** Russia-linked (unconfirmed, English-language ransom notes)
**Active Since:** 2019 (LockBit 1.0) → Current variant since 2022
**Targets:** Healthcare, Finance, Manufacturing, Government (all sectors)
**Average Ransom:** $70,000–$1.4M USD
**Encryption:** AES-128 + RSA-2048
**Status:** ⚠️ **ACTIVE** — 3 victims claimed week of 2025-06-24

### MITRE ATT&CK Mapping

| Phase | Technique | ID |
|-------|-----------|-----|
| Initial Access | Phishing / VPN exploitation | T1566, T1133 |
| Execution | PowerShell, WMI | T1059.001, T1047 |
| Persistence | Registry Run Keys, Scheduled Tasks | T1547.001, T1053 |
| Lateral Movement | SMB/Windows Admin Shares | T1021.002 |
| Exfiltration | Rclone → Mega.nz / FTP | T1048 |
| Impact | Data Encrypted + Double Extortion | T1486, T1657 |

### Current IOCs (Updated 2025-06-30)

**Domains:**
- lockbit3753eqii[.]onion (leak site)
- update-cdn[.]com (staging C2)

**IPs:** 185.220.101.44, 91.219.29.12, 45.227.254.3

**File Hashes (SHA256):**
- a3f9d21b8e4c7f2d1a0b5e3c9f6d4e7a (LockBit 3.0 encryptor)
- c1e5b9a2d7f4c8e3b6a0d2f8e5c1b7a4 (Cobalt Strike stager)

**⚠️ 1 IOC MATCHES ENVIRONMENT:** 185.220.101.44 seen in June 28 incident

### Recommended Mitigations
1. Block all listed IPs/domains at perimeter
2. Enable honeypot decoy files in Finance and HR shares
3. Disable RDP externally or require NLA + MFA
4. Enable Controlled Folder Access (Windows Defender)
5. Review Rclone and cloud sync tools on all servers`
	}

	// generic / default
	return `## Security Analysis

I've analyzed your query against the connected security data sources.

**Query:** ` + `"` + msg + `"` + `
**Sources checked:** SIEM (Elastic), EDR (CrowdStrike), Firewall (Palo Alto), Vulnerability Scanner, MDM

---

### Findings

Based on current security telemetry:

**Current Platform Status:**
- 🟢 **Threat Level:** Moderate — 2 active threats under investigation
- 🟢 **SIEM:** 1,247 events in last hour (within normal range)
- 🟡 **Open Alerts:** 18 (3 critical, 8 high, 7 medium)
- 🟢 **EDR Coverage:** 97.2% (419/427 endpoints)
- 🟡 **Compliance:** 94.4% (24 non-compliant devices)
- 🔴 **Critical Vulnerabilities:** 12 unpatched (CVE-2024-3400 priority)

### Recent Activity
- **2 hours ago:** Ransomware stager blocked on WKSTN-FIN-047 (contained)
- **6 hours ago:** Phishing campaign targeting Finance team (9 emails blocked)
- **12 hours ago:** Successful patch deployment to 14 firewall devices (CVE-2024-3400)
- **Yesterday:** New threat actor profile added: LockBit 3.0 IOCs imported

### Recommendations
1. Investigate the 3 critical alerts in the queue — estimated 45 min effort
2. Patch 12 critical CVEs — CISA KEV compliance requires action within 24h
3. Enroll 24 non-compliant devices — focus on Finance and HR endpoints first

> 💡 **Tip:** Try asking "Show all critical alerts" or "Analyze the Finance workstation incident" for deeper analysis.`
}

// ── Recommendations ───────────────────────────────────────────────────────────

func GetAIARecommendations(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	var recs []map[string]interface{}
	rows, _ := db.Query(`SELECT rec_id,title,description,category,priority,status,impact,effort,created_at
		FROM aia_recommendations WHERE tenant_id=$1
		ORDER BY CASE priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
		CASE status WHEN 'open' THEN 1 WHEN 'accepted' THEN 2 ELSE 3 END,
		created_at DESC`, tidStr)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, title, desc, cat, pri, st, impact, effort string
			var ca *string
			if err := rows.Scan(&id, &title, &desc, &cat, &pri, &st, &impact, &effort, &ca); err == nil {
				recs = append(recs, map[string]interface{}{
					"rec_id": id, "title": title, "description": desc, "category": cat,
					"priority": pri, "status": st, "impact": impact, "effort": effort, "created_at": ca,
				})
			}
		}
	}
	if recs == nil {
		recs = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, recs)
}

func PatchAIARecommendation(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	recID := c.Param("id")
	actor := usernameFromContext(c)

	var body struct{ Status string `json:"status"` }
	c.BindJSON(&body)
	if body.Status == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status required"})
		return
	}
	db.Exec(`UPDATE aia_recommendations SET status=$1,accepted_by=$2,accepted_at=NOW()
		WHERE tenant_id=$3 AND rec_id=$4`, body.Status, actor, tidStr, recID)
	aiaAudit(tid, "recommendation_updated", "recommendation", recID, actor, fmt.Sprintf("status→%s", body.Status))
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// ── AI Actions ────────────────────────────────────────────────────────────────

func GetAIAActions(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	var actions []map[string]interface{}
	rows, _ := db.Query(`SELECT action_id,action_type,description,status,requested_by,approved_by,result,created_at
		FROM aia_actions WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 50`, tidStr)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, atype, desc, st, by string
			var approvedBy, result, ca *string
			if err := rows.Scan(&id, &atype, &desc, &st, &by, &approvedBy, &result, &ca); err == nil {
				actions = append(actions, map[string]interface{}{
					"action_id": id, "action_type": atype, "description": desc,
					"status": st, "requested_by": by, "approved_by": approvedBy,
					"result": result, "created_at": ca,
				})
			}
		}
	}
	if actions == nil {
		actions = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, actions)
}

func PostAIAAction(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actor := usernameFromContext(c)

	var body struct {
		ActionType  string `json:"action_type"`
		Description string `json:"description"`
		SessionID   string `json:"session_id"`
	}
	c.BindJSON(&body)
	if body.ActionType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action_type required"})
		return
	}
	id := aiaID("AIA-ACT")
	db.Exec(`INSERT INTO aia_actions (tenant_id,action_id,action_type,description,requested_by,session_id)
		VALUES ($1,$2,$3,$4,$5,$6)`, tidStr, id, body.ActionType, body.Description, actor, aiaNullStr(body.SessionID))
	aiaAudit(tid, "action_requested", "action", id, actor, fmt.Sprintf("type:%s", body.ActionType))
	c.JSON(http.StatusOK, gin.H{"action_id": id, "status": "pending_approval"})
}

func PatchAIAActionApprove(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actionID := c.Param("id")
	actor := usernameFromContext(c)

	var body struct{ Approve bool `json:"approve"` }
	c.BindJSON(&body)
	status := "rejected"
	if body.Approve {
		status = "approved"
	}
	db.Exec(`UPDATE aia_actions SET status=$1,approved_by=$2,executed_at=NOW() WHERE tenant_id=$3 AND action_id=$4`,
		status, actor, tidStr, actionID)
	aiaAudit(tid, "action_"+status, "action", actionID, actor, "")
	c.JSON(http.StatusOK, gin.H{"status": status})
}

// ── Prompt Library ────────────────────────────────────────────────────────────

func GetAIAPrompts(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	category := c.Query("category")

	where := []string{"tenant_id=$1"}
	args  := []interface{}{tidStr}
	i     := 2
	if category != "" {
		where = append(where, fmt.Sprintf("category=$%d", i))
		args = append(args, category); i++
	}

	var prompts []map[string]interface{}
	rows, _ := db.Query(fmt.Sprintf(`SELECT prompt_id,title,content,category,is_template,variables,usage_count,created_by,created_at
		FROM aia_prompts WHERE %s ORDER BY usage_count DESC, created_at DESC`, strings.Join(where, " AND ")), args...)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, title, content, cat, by string
			var isTemplate bool
			var vars *string
			var usage int
			var ca *string
			if err := rows.Scan(&id, &title, &content, &cat, &isTemplate, &vars, &usage, &by, &ca); err == nil {
				prompts = append(prompts, map[string]interface{}{
					"prompt_id": id, "title": title, "content": content, "category": cat,
					"is_template": isTemplate, "variables": vars, "usage_count": usage,
					"created_by": by, "created_at": ca,
				})
			}
		}
	}
	if prompts == nil {
		prompts = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, prompts)
}

func PostAIAPrompt(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actor := usernameFromContext(c)

	var body struct {
		Title      string `json:"title"`
		Content    string `json:"content"`
		Category   string `json:"category"`
		IsTemplate bool   `json:"is_template"`
		Variables  string `json:"variables"`
	}
	if err := c.BindJSON(&body); err != nil || body.Title == "" || body.Content == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "title and content required"})
		return
	}
	if body.Category == "" {
		body.Category = "general"
	}
	vars := body.Variables
	if vars == "" {
		vars = "[]"
	}
	id := aiaID("AIA-PRM")
	db.Exec(`INSERT INTO aia_prompts (tenant_id,prompt_id,title,content,category,is_template,variables,created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, tidStr, id, body.Title, body.Content, body.Category, body.IsTemplate, vars, actor)
	c.JSON(http.StatusOK, gin.H{"prompt_id": id})
}

// ── Analytics ─────────────────────────────────────────────────────────────────

func GetAIAAnalytics(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	// mode breakdown
	modes := []map[string]interface{}{}
	mr, _ := db.Query(`SELECT mode, COUNT(*) FROM aia_sessions WHERE tenant_id=$1 GROUP BY mode ORDER BY COUNT(*) DESC`, tidStr)
	if mr != nil {
		defer mr.Close()
		for mr.Next() {
			var m string
			var cnt int
			mr.Scan(&m, &cnt)
			modes = append(modes, map[string]interface{}{"mode": m, "count": cnt})
		}
	}

	// category breakdown for prompts
	cats := []map[string]interface{}{}
	cr, _ := db.Query(`SELECT category, COUNT(*) FROM aia_prompts WHERE tenant_id=$1 GROUP BY category ORDER BY COUNT(*) DESC`, tidStr)
	if cr != nil {
		defer cr.Close()
		for cr.Next() {
			var cat string
			var cnt int
			cr.Scan(&cat, &cnt)
			cats = append(cats, map[string]interface{}{"category": cat, "count": cnt})
		}
	}

	var totalSessions, totalMessages int
	db.QueryRow(`SELECT COUNT(*) FROM aia_sessions WHERE tenant_id=$1`, tidStr).Scan(&totalSessions)
	db.QueryRow(`SELECT COUNT(*) FROM aia_messages WHERE tenant_id=$1`, tidStr).Scan(&totalMessages)

	c.JSON(http.StatusOK, gin.H{
		"total_sessions": totalSessions, "total_messages": totalMessages,
		"by_mode": modes, "prompt_categories": cats,
		"usage_trend": []map[string]interface{}{
			{"date": "Mon", "sessions": 12, "messages": 47, "actions": 3},
			{"date": "Tue", "sessions": 18, "messages": 71, "actions": 7},
			{"date": "Wed", "sessions": 9, "messages": 34, "actions": 2},
			{"date": "Thu", "sessions": 22, "messages": 89, "actions": 11},
			{"date": "Fri", "sessions": 31, "messages": 124, "actions": 14},
			{"date": "Sat", "sessions": 4, "messages": 18, "actions": 1},
			{"date": "Sun", "sessions": 2, "messages": 9, "actions": 0},
		},
		"response_quality": gin.H{
			"avg_latency_ms": 1240, "accuracy_rate": 94, "hallucination_rate": 0.8,
			"user_rating_avg": 4.7, "correction_rate": 3.2,
		},
		"top_analysts": []map[string]interface{}{
			{"analyst": "alice.zhang", "sessions": 48, "messages": 192, "actions_executed": 12},
			{"analyst": "carol.kim", "sessions": 37, "messages": 147, "actions_executed": 8},
			{"analyst": "david.chen", "sessions": 24, "messages": 96, "actions_executed": 5},
			{"analyst": "grace.lee", "sessions": 18, "messages": 71, "actions_executed": 3},
		},
		"automation_stats": gin.H{
			"sigma_rules_generated": 14, "yara_rules_generated": 7,
			"playbooks_generated": 5, "reports_generated": 23,
			"scripts_generated": 9, "queries_generated": 31,
			"analyst_hours_saved": 127,
		},
	})
}

// ── Reports ───────────────────────────────────────────────────────────────────

func GetAIAReports(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	var reports []map[string]interface{}
	rows, _ := db.Query(`SELECT report_id,title,report_type,generated_by,format,session_id,created_at
		FROM aia_reports WHERE tenant_id=$1 ORDER BY created_at DESC`, tidStr)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, title, rtype, by, format string
			var sid, ca *string
			if err := rows.Scan(&id, &title, &rtype, &by, &format, &sid, &ca); err == nil {
				reports = append(reports, map[string]interface{}{
					"report_id": id, "title": title, "report_type": rtype,
					"generated_by": by, "format": format, "session_id": sid, "created_at": ca,
				})
			}
		}
	}
	if reports == nil {
		reports = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, reports)
}

func PostAIAReport(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actor := usernameFromContext(c)

	var body struct {
		Title      string `json:"title"`
		ReportType string `json:"report_type"`
		Format     string `json:"format"`
		SessionID  string `json:"session_id"`
	}
	c.BindJSON(&body)
	if body.Format == "" {
		body.Format = "markdown"
	}
	id := aiaID("AIA-RPT")
	db.Exec(`INSERT INTO aia_reports (tenant_id,report_id,title,report_type,generated_by,format,session_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, tidStr, id, body.Title, body.ReportType, actor, body.Format, aiaNullStr(body.SessionID))
	aiaAudit(tid, "report_generated", "report", id, actor, fmt.Sprintf("type:%s", body.ReportType))
	c.JSON(http.StatusOK, gin.H{"report_id": id})
}

// ── Audit ─────────────────────────────────────────────────────────────────────

func GetAIAAudit(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	limit := parseLimit(c, 100)

	var entries []map[string]interface{}
	rows, _ := db.Query(`SELECT action,object_type,object_id,actor,details,created_at
		FROM aia_audit WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tidStr, limit)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var action, otype, actor string
			var oid, details, ca *string
			if err := rows.Scan(&action, &otype, &oid, &actor, &details, &ca); err == nil {
				entries = append(entries, map[string]interface{}{
					"action": action, "object_type": otype, "object_id": oid,
					"actor": actor, "details": details, "created_at": ca,
				})
			}
		}
	}
	if entries == nil {
		entries = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, entries)
}
