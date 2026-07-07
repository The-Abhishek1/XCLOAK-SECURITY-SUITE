# XCloak User Guide

For SOC analysts and security engineers using the XCloak platform day-to-day.

---

## Table of Contents

1. [Logging In](#logging-in)
2. [Dashboard](#dashboard)
3. [Alerts](#alerts)
4. [Incidents](#incidents)
5. [Cases](#cases)
6. [Threat Hunting](#threat-hunting)
7. [Log Search](#log-search)
8. [Agents & Endpoints](#agents--endpoints)
9. [Vulnerabilities](#vulnerabilities)
10. [Detection Rules](#detection-rules)
11. [UEBA & Insider Threat](#ueba--insider-threat)
12. [Deception Technology](#deception-technology)
13. [AI Tools](#ai-tools)
14. [Compliance & Reporting](#compliance--reporting)
15. [Mobile Device Management (MDM)](#mobile-device-management-mdm)
16. [Integrations & Notifications](#integrations--notifications)
17. [Account & Profile](#account--profile)

---

## Logging In

Navigate to your XCloak URL (e.g. `https://xcloak.yourdomain.com`).

**Standard login** — enter your email and password. If your admin has enabled TOTP 2FA on your account, you will be prompted for a 6-digit code from your authenticator app after entering your password.

**SSO login** — if your tenant is configured for single sign-on, click **Sign in with SSO**. You will be redirected to your identity provider (Okta, Azure AD, Google Workspace, etc.) and returned to XCloak after authentication.

**Forgot password** — click **Forgot password** on the login page and enter your email. A reset link is valid for 30 minutes.

### Setting up TOTP 2FA

Go to **Account → Security → Enable 2FA**. Scan the QR code with Google Authenticator, Authy, or any RFC 4226-compatible app. Enter the 6-digit code to confirm enrollment. Save your backup codes in a password manager — they are the only way to recover access if you lose your authenticator device.

---

## Dashboard

The dashboard gives you a real-time security posture overview for your environment.

**Risk Posture Score** — a 0–100 score updated continuously. Factors include open critical/high alerts, unpatched critical CVEs, detection coverage gaps, and alert trend over the last 7 days. Lower is better. Click the score to see the breakdown.

**Alert trend** — 7-day bar chart of alert volume by severity. Sudden spikes are worth investigating.

**Top MITRE techniques** — the ATT&CK techniques that appeared most in alerts this week. Use this to prioritise detection rule tuning.

**Agent health** — count of online, offline, and unhealthy agents. Click through to the Agents view.

**Recent alerts** — last 10 unacknowledged alerts across all severity levels.

**SOC metrics** — Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR) for the current month.

---

## Alerts

Alerts are the primary signal from all detection engines (Sigma rules, IOC matches, behavioral detectors, YARA, correlation engine).

### Alert list

Go to **Alerts**. By default you see unacknowledged alerts sorted by time, newest first.

**Filters available:**
- Severity: Critical / High / Medium / Low / Informational
- Status: New / Acknowledged / Resolved
- Agent / Source
- Date range

**Bulk operations** — select multiple alerts and use **Bulk Acknowledge** to clear noise at scale.

### Alert detail

Click any alert to open the detail panel.

**Header** — severity badge, MITRE technique, source agent, timestamp.

**Description** — what was detected and why it matters.

**Investigation context** (auto-populated):
- Matching IOCs from your intelligence database
- Similar historical alerts from the same agent or technique
- Suggested cases this alert could belong to
- Correlated Sigma rules that matched the same event

**AI Triage** — click **Run AI Triage** to get a Claude/Ollama-powered analysis: what the alert likely represents, false-positive likelihood, and recommended next steps. This requires `run_ai_analysis` permission.

**Threat actor tags** — if the technique or IOC maps to a tracked threat actor, the actor is shown here with a link to their profile.

**Playbook recommendations** — click **Get Recommendations** to have the AI suggest response playbooks based on the MITRE technique. Click **Execute** to run one.

### Responding to an alert

| Action | When to use |
|--------|-------------|
| **Acknowledge** | You are aware of the alert and handling it — removes it from the new queue |
| **Resolve** | Investigation complete, no further action needed |
| **Dispatch Response** | Triggers a response action (kill process, isolate host, etc.) directly from the alert |
| **Link to Case** | Adds this alert to an open incident case for tracking |

**Suppression** — if an alert is a known false positive, go to **Settings → Suppression** and create a suppression rule matching the same conditions so it doesn't alert again.

---

## Incidents

Incidents are created automatically by the correlation engine when multiple alerts match a correlation rule, or manually by an analyst. When a new incident is created, the platform immediately:
- Sends a webhook/Slack notification to all configured integrations
- Pushes a real-time notification to all connected dashboards (bell icon in the top bar)

### Incident list

Go to **Incidents**. Filter by status: Open / In Progress / Closed.

### Incident detail

- **Status** — update as investigation progresses (Open → In Progress → Closed)
- **Events** — all alerts and system events correlated into this incident, in timeline order
- **Notes** — add analyst notes to document your findings
- **AI Summary** — click **Summarize** for a structured incident summary: scope, timeline, likely root cause, affected assets, recommended containment steps
- **Deep Dive** — full AI-generated DFIR report with kill chain reconstruction
- **Remediation plans** — step-by-step containment and recovery plans you can execute directly from the UI (requires `manage_agents` permission; each destructive step prompts for confirmation)
- **DFIR Timeline** — forensic timeline pulled from agent artifacts for this incident's affected hosts

---

## Cases

Cases give you a full IR lifecycle for complex investigations that span multiple incidents or require extended tracking.

**Create a case** — go to **Cases → New Case**. Set title, severity, assignee, and status (Open / In Progress / Closed / Resolved).

**Link alerts** — from any alert detail page, click **Link to Case** and select the case. Alternatively, open the case and click **Link Alert**.

**Comments** — use the comments thread to document investigation steps, analyst handoffs, and findings.

**Evidence** — attach files, screenshots, or artifact references directly to the case record.

---

## Threat Hunting

Go to **Threat Hunt** to run ad-hoc queries across endpoint telemetry.

### Running a hunt

1. Select a **query type**: process events, network connections, file events, auth events, registry events, or raw endpoint logs.
2. Set filters: agent(s), date range, and field-level conditions.
3. Click **Run Hunt**.

Results are returned in a table you can sort and export. Click any row to see the full raw event.

**Saved hunts** — click **Save** after running a query to store it for future use. Saved hunts appear in **Hunt → Saved Queries**.

### Hunt Workbench

The Workbench is for structured hunting with hypothesis tracking.

1. Go to **Hunt → Workbench → New Run**.
2. Pick a **Hunt Template** (pre-built hypotheses for common techniques) or create a custom one.
3. Write your hypothesis, select the template, and click **Execute**.
4. Add notes to document what you found and whether the hypothesis was confirmed.

Past hunt runs with notes are saved in **Hunt → Runs** for audit and knowledge sharing.

---

## Log Search

Go to **Logs → Search** to search across all endpoint logs ingested by XCloak (from agents and agentless log sources).

### Basic search

| Field | What it does |
|-------|-------------|
| **Query** | Free-text search across log messages (supports wildcards: `fail*`) |
| **Agent** | Filter to a specific endpoint |
| **Log Source** | Filter by log type: `syslog`, `windows_event`, `auth`, `firewall`, `http`, etc. |
| **From / To** | Date range |

Results are returned in reverse-chronological order. The `parsed_fields` column shows structured fields extracted by the log normalizer (src_ip, user, event_id, bytes, etc.).

### Elasticsearch mode

If your deployment has Elasticsearch connected (`ELASTICSEARCH_URL` set), search routes through ES automatically for full-text and wildcard queries. Postgres is used as fallback if ES is unavailable.

### Saved searches

Click **Save Search** to store the current query. Saved searches appear in **Logs → Saved Searches**. You can run them on-demand or set up scheduled reports from them.

### Export

Click **Export** to download the current result set as CSV or NDJSON.

---

## Agents & Endpoints

Go to **Agents** to see all enrolled endpoints.

### Agent list

Agents are grouped by platform (Windows, Linux, macOS, Network, Cloud, etc.). The status badge shows:
- **Online** — heartbeat received within 90 seconds
- **Offline** — no heartbeat for > 5 minutes
- **Unhealthy** — agent is responding but reporting errors

The **Health Score** (0–100) is a composite of heartbeat latency, error rate, and task success rate. Click **Refresh** to recompute all scores on demand.

### Agent detail

Click any agent to open its detail view.

**Summary** — hostname, OS, IP, agent version, last seen, risk score. Heartbeat now also surfaces `load_avg_1m/5m/15m`, `logged_in_users`, and `open_fds` (Linux) or `cpu_load_pct` and `logged_in_users` (Windows).

**Risk Score & Breakdown** — per-agent risk score with contributing factors (open critical alerts, failed auth events, anomaly score, unpatched CVEs).

**Timeline** — unified chronological view of all events (alerts, process events, auth events, connections, FIM changes) for this agent.

**Tabs:**
| Tab | What you see |
|-----|-------------|
| Processes | Running processes — PID, PPID, name, cmdline, exe path |
| Connections | Active network connections with **PID and process name** per socket (Linux: /proc/net inode mapping; Windows: netstat + tasklist) |
| Auth Events | Login/logout events, sudo, privilege escalation |
| File Hashes | SHA-256 + MD5 inventory |
| Services | Running services and their status |
| Packages | Installed packages — tagged by source (dpkg/rpm/pip/snap/winget/etc.) |
| Users | Local accounts — includes groups, sudo access, SSH key presence, last login, enabled/locked status |
| Registry | Windows registry run/persistence keys (Windows agents only) |
| FIM | File integrity monitoring — hash, mode, owner, mtime per file |
| Vulnerabilities | CVEs matched against this agent's package inventory |
| Auth Logs | Raw auth log lines |
| Cron Jobs | Scheduled tasks from /etc/crontab + /etc/cron.d/* + user crontabs (Linux); Windows Scheduled Tasks (Windows) |
| Kernel Modules | Loaded kernel modules (Linux) / drivers (Windows) — use to detect rootkits and unexpected persistence |
| SUID Binaries | Files with SUID/SGID bit set — privilege escalation vector inventory (Linux only) |
| Disk Usage | Capacity, used, and free per mount point / drive letter |

### Remote actions

From the agent detail page, click **Actions** to dispatch remote tasks:

| Action | Permission required |
|--------|-------------------|
| Collect processes | Any authenticated user |
| Collect connections | Any authenticated user |
| Collect users | Any authenticated user |
| Collect packages | Any authenticated user |
| Collect cron jobs | Any authenticated user |
| Collect kernel modules | Any authenticated user |
| Collect SUID/SGID binaries | Any authenticated user |
| Collect disk usage | Any authenticated user |
| Kill process | `manage_agents` |
| Isolate host (block all traffic) | `manage_agents` |
| Quarantine file | `manage_agents` |
| Run script | `run_scripts` |
| Trigger vulnerability scan | `manage_agents` |
| Trigger CIS benchmark scan | `manage_agents` |
| Memory dump | `run_ai_analysis` |
| Kill process tree | `manage_agents` |

**Script runner** — go to **Scripts → Run**. Select the target agent(s), choose a template or write a custom bash/python3 script, and click **Run**. Output streams back in real time. All script runs are logged in the audit trail.

**Destructive actions** (isolate host, kill process, quarantine file, memory dump) require admin approval before the agent acts. Pending approvals appear in **Tasks → Pending Approval**. This applies to:

- Actions manually triggered by a playbook with a human-in-the-loop gate
- `quarantine_file` tasks **automatically created** by the platform when a FIM or YARA detection matches a critical file — see the sections below

Approve or reject tasks from **Tasks → Pending Approval** (`approve_soar_actions` permission). Unapproved destructive tasks expire after 15 minutes.

### File Integrity Monitoring (FIM)

The agent monitors a configured set of paths for file creates, modifies, deletes, and permission changes.

**Viewing FIM alerts** — go to the agent's **FIM** tab. Each alert shows the file path, change type, old/new hash, and the user that made the change.

**Auto-quarantine for critical paths** — when a FIM violation is detected on a critical system path (`/bin/*`, `/sbin/*`, `/usr/bin/*`, `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/*`, `/etc/cron*`), the platform automatically creates a `quarantine_file` task in **pending approval**. Review it at **Tasks → Pending Approval** and approve or reject. The agent only quarantines the file after explicit approval.

**Accepting a baseline** — after initial deployment, the agent scans monitored paths and reports them as the baseline. Go to **FIM → Baseline** on the agent and click **Accept Baseline** to mark the current state as trusted. Future changes generate alerts. Requires `manage_detection_rules` permission.

---

## Vulnerabilities

Go to **Vulnerabilities** to see the prioritised CVE queue across your fleet.

### Priority queue

Vulnerabilities are scored and ranked using three signals:
- **EPSS** — probability of exploitation in the next 30 days (FIRST.org)
- **CVSS** — severity score
- **KEV** — whether this CVE is in CISA's Known Exploited Vulnerabilities catalogue

The queue sorts by composite risk. Filter by severity, EPSS threshold, KEV status, or specific CVE IDs.

**Patch status** — mark CVEs as Patched / Accepted Risk / In Progress. These states are per-CVE per-agent.

### Importing scanner results

Go to **Vulnerabilities → Import**. Upload a Nessus XML (`.nessus`), Qualys XML, or Tenable.sc export. XCloak merges the results into the priority queue.

### Per-agent vulnerabilities

The agent's **Vulnerabilities** tab shows CVEs specific to that endpoint's package inventory.

---

## Detection Rules

### Sigma Rules

Go to **Detection → Sigma Rules**.

Sigma rules are the primary custom detection layer. Each rule matches against parsed log fields.

**Create a rule** — click **New Rule** and fill in:
- `title` and `description`
- `logsource` — the log category (`windows`, `linux`, `network`, etc.)
- `detection` — field-level conditions using Sigma syntax
- `severity` — Critical / High / Medium / Low / Informational
- `tags` — MITRE ATT&CK technique IDs (e.g. `attack.t1059.001`)
- `falsepositives` — known benign conditions to document

**Test a rule** — click **Test** to run the rule against recent logs and see how many events it would match before enabling it.

**Enable / Disable** — use the toggle to turn rules on or off without deleting them.

**Import** — click **Import YAML** to bulk-import Sigma rules from the community (e.g. SigmaHQ). Drag and drop one or more `.yml` files.

### IOC Rules

Go to **Detection → IOCs**.

An IOC (Indicator of Compromise) can be an IP address, CIDR range, domain, file hash (MD5/SHA256), URL, or email address.

**Add an IOC** — click **New IOC**. Set the type, value, severity, and optional expiry date.

**Import** — click **Import** to paste a list or upload a CSV with columns `type,value,severity`.

**Bulk import** — `POST /api/iocs/bulk` accepts a JSON array for programmatic ingestion from threat intel pipelines.

**IOC sharing** — go to **Settings → IOC Sharing** to share your anonymised IOC hits with other XCloak tenants (opt-in). You receive their shared IOCs in return.

### YARA Rules

Go to **Detection → YARA Rules**.

YARA rules scan files on endpoints for malware signatures. The agent fetches enabled rules on each startup and applies them during file scans.

**Create / import** — write rule text directly or click **Import** to upload `.yar` / `.yara` files.

**Matches** — go to **Detection → YARA Matches** to see files that triggered a match, with the path, agent, and matching rule.

**Auto-quarantine** — when a YARA match is reported, the platform automatically creates a `quarantine_file` task in **pending approval** for the matched file path. Review at **Tasks → Pending Approval**. Requires `approve_soar_actions` permission to approve or reject.

### Correlation Rules

Go to **Detection → Correlation Rules**.

Correlation rules combine multiple alerts into a higher-fidelity incident signal.

**Conditions:** one or more of:
- `severity` — minimum alert severity
- `rule_name` — Sigma/YARA/IOC rule name substring
- `mitre` — MITRE technique tag
- `agent_id` — specific agent

**Logic** — AND / OR across conditions. Temporal ordering option for kill-chain sequencing.

**Action** — when the rule fires, it creates an incident automatically.

### JA3 / TLS Fingerprints

Go to **Detection → JA3 Fingerprints** to manage the TLS Client Hello blocklist. Matches generate alerts tagged T1071.001.

### Alert Suppression

Go to **Detection → Suppression Rules** to suppress known false positives. A suppression rule matches on any combination of: rule name, agent, source IP, destination IP, or username. Matching alerts are dropped silently and not stored.

### Threat Feeds

Go to **Threat Intel → Feeds**.

XCloak supports four feed types:
- **STIX/TAXII** — connect to any TAXII 2.x server
- **MISP** — connect to a MISP instance via API key
- **AlienVault OTX** — connect with your OTX API key
- **Flat file** — a line-per-indicator text file served over HTTP

Click **Sync** to force an immediate pull. Synced IOCs are added to the IOC database and matched against live traffic.

**Sync log** — click the feed name → **Sync Log** to see past sync results, counts, and errors.

---

## UEBA & Insider Threat

### UEBA

Go to **UEBA** to see user-level behavioral scores.

XCloak scores each user across:
- Failed authentication attempts
- Off-hours activity (logins and file access outside business hours)
- Privilege escalation events
- Volume of data transferred

**Users** — list of all users observed, sorted by risk score. Click a user to see their event history.

**Trigger analysis** — click **Analyze** (requires `run_ai_analysis`) to run the behavioral scorer immediately for a specific user.

### Insider Threat

Go to **Insider Threat** for a summary dashboard and ranked list of high-risk users. Scores are recalculated by the background scorer every cycle.

---

## Deception Technology

### Canary Tokens

Go to **Deception → Canary Tokens**.

A canary token is a URL embedded in a document, spreadsheet, or email. When it is accessed, XCloak generates an alert (technique T1204).

**Create a token** — set a name, description, and type (URL/document/email). Copy the generated URL and embed it in the file or message you want to protect.

**Trips** — go to **Deception → Trips** to see all canary token accesses, with the accessing IP, user-agent, and timestamp.

### Honeyports

Go to **Deception → Honeyports** to define listening ports that should never receive legitimate traffic. Any connection to a honeyport generates an alert.

---

## AI Tools

XCloak integrates AI (Claude or Ollama, configured by your admin) in several places.

| Feature | Where | Permission |
|---------|-------|-----------|
| Alert AI Triage | Alert detail → Run AI Triage | `run_ai_analysis` |
| Incident Summary | Incident detail → Summarize | Any auth user |
| Incident Deep Dive | Incident detail → Deep Dive | Any auth user |
| Anomaly Detection | Agents → Actions → Run Anomaly Detection | `run_ai_analysis` |
| Playbook Recommendations | Alert detail → Get Recommendations | Any auth user |
| AI Chat | AI → Chat | Any auth user |
| NBA Analysis | Network → NBA → Analyze | `run_ai_analysis` |
| Risk Posture Refresh | Dashboard → Refresh | `run_ai_analysis` |
| UEBA Analysis | UEBA → Analyze | `run_ai_analysis` |

**AI Chat** — go to **AI → Chat** for a conversational interface. Ask about alerts, hunting queries, MITRE techniques, or incident context. Chat history is persisted per-user and can be cleared from **AI → Chat → Clear History**.

---

## Compliance & Reporting

### Framework Compliance

Go to **Compliance → Framework Compliance** to see your coverage score against:
- SOC 2 Type II
- NIST Cybersecurity Framework
- PCI-DSS
- ISO 27001

Each framework shows a percentage coverage score based on the detection rules and controls you have active. Click a framework for the control-by-control breakdown.

### Compliance Reports

Go to **Compliance → Reports → Generate** to produce a point-in-time compliance report.

Reports are saved and can be downloaded as PDF. Old reports can be deleted (requires `manage_compliance`).

### CIS Benchmark

Go to **Compliance → CIS** to see benchmark scores per agent. Trigger a CIS scan from the agent detail page (requires `manage_agents`). The scan checks configuration settings against the CIS benchmark for the agent's OS.

### SOC Metrics

Go to **Compliance → SOC Metrics** to track:
- Alert volume by severity
- Mean Time to Detect (MTTD)
- Mean Time to Respond (MTTR)
- Analyst performance (acknowledgement and resolution rates)

### Executive Report

Go to **Executive → Download Report** for a PDF-ready summary suitable for management and board-level reporting. Covers risk posture score, alert trends, top threats, compliance status, and recommended priorities.

### Scheduled Reports

Go to **Reports → Scheduled** to set up recurring email delivery of compliance or executive reports. Requires `manage_notifications` permission.

### Audit Log

Go to **Audit → Logs** to see all platform actions (logins, rule changes, user management, task dispatches, etc.).

Audit logs are immutable — they are batch-exported to MinIO under Object Lock (WORM) and cannot be altered or deleted even by an admin. To verify exports, go to **Audit → Export Status**.

---

## Mobile Device Management (MDM)

XCloak includes a built-in MDM layer for Android devices via the **XCloak Agent** Flutter app. It supports BYOD and managed corporate device scenarios.

### Enrolling a device

1. Go to **MDM → Enrollment Tokens** and click **Generate Token**. Set an expiry (default 24 h) and optional owner email.
2. On the target Android device, install the XCloak Agent APK and tap **Enroll Device**.
3. Enter the server URL and the enrollment token. Tap **Enroll**.

At enrollment the agent captures and sends a rich device snapshot to the backend:

| Field | Description |
|-------|-------------|
| UDID (Android ID) | Stable per-device per-signing-key identifier |
| Manufacturer / hardware | OEM and hardware board name |
| OS version / SDK int | Android release string and API level |
| Security patch level | Android monthly security patch date |
| Build fingerprint | Cryptographic build fingerprint for forensic tracing |
| Encryption status | Full-disk encryption (all Android 6+ devices) |
| Root status | Heuristic — su binary paths + test-keys build tag + Magisk socket |
| Developer options | `development_settings_enabled` system setting |
| USB debugging | `adb_enabled` system setting |
| Battery level | From `dumpsys battery` |
| Network type | wifi / mobile / ethernet / none |
| Storage (total / free) | From `df /data` |
| RAM total | From `/proc/meminfo` |

### Device list

Go to **MDM → Devices** to see all enrolled devices.

- **Status** — Online (check-in within 10 min) / Offline
- **Posture score** — composite of root status, developer options, USB debugging, unknown-sources flag, sideloaded app count, screen lock
- **Platform** — Android version and SDK

Click a device to open its detail view with tabs: Posture, App Inventory, Command History, Check-in Timeline.

### Device posture checks

The agent re-evaluates and ships posture every 5 minutes (check-in). The posture tab shows a **pass/fail** for each control:

| Check | Pass condition |
|-------|---------------|
| Root / Jailbreak | No su binary, no Magisk socket, no test-keys build |
| Developer Mode | `development_settings_enabled` == 0 |
| USB Debugging | `adb_enabled` == 0 |
| Unknown Sources (API < 26) | `install_non_market_apps` == 0 |
| Disk Encryption | Android 6+ enforces FBE — always pass |
| Screen Lock | Requires Device Owner (DPC) — reported as null in BYOD mode |
| Battery | ≥ 15% |
| Storage | ≥ 1 GB free |
| Network | Not offline |
| VPN | Active VPN interface detected (`tun*`, `ppp*`, `vpn*`) |

### App inventory

The agent scans installed apps every 30 minutes. Go to **MDM → Devices → [Device] → App Inventory** to see:

- All installed apps with package name, version, installer source, system app flag
- **Sideloaded** — apps not installed via the Play Store and not system apps are flagged
- **Sideloaded count** and **high-risk count** (sideloaded + sensitive permissions) are reported in each inventory submission

### MDM commands

Dispatch commands to a device from **MDM → Devices → [Device] → Actions**:

| Command | What it does |
|---------|-------------|
| `collect_posture` | Immediate posture refresh and upload |
| `collect_apps` | Immediate app inventory scan |
| `scan_threats` | Summarises total / sideloaded / system app counts and ships to backend |
| `collect_logs` | Forwards a fresh logcat batch (security-relevant tags) |
| `sync` | Full sync — posture + app inventory in one operation |
| `message` | Displays an in-app message to the device user on next app open |
| `rotate_token` | Issues a new agent bearer token (old token invalidated) |
| `update_agent` | Notifies the user of a new APK URL to install |
| `lock_screen` | Requires Device Owner profile (BYOD: returns error with explanation) |
| `wipe` | Requires Device Owner profile (intentionally rejected in BYOD mode) |

The agent acknowledges every command (status: `executed` or `failed`) with a result string. Failed commands include the error reason so operators understand exactly why a command did not execute.

### Log forwarding

Every 10 minutes the agent collects security-relevant `logcat` lines and ships them to `/api/logs/ingest` with `log_source: android_agent`. Each log line includes a `severity` field (critical / error / warning / info / debug) parsed from the logcat prefix.

Tags captured:

`AndroidRuntime`, `ActivityManager`, `PackageManager`, `PackageInstaller`, `KeyStore`, `SELinux`, `Binder`, `WifiService`, `NetworkService`, `AccessibilityService`, `DevicePolicyManager`

SELinux denials and AccessibilityService bind events are particularly useful for detecting privilege escalation and overlay-based malware.

### Unenrolling a device

- **User-initiated** — tap the menu (⋮) in the XCloak Agent app → **Unenroll Device**. Credentials are wiped from the device's encrypted storage.
- **Admin-initiated** — go to **MDM → Devices → [Device] → Unenroll**. The device is deprovisioned. On the next check-in, the agent receives a 403 response and automatically wipes its credentials.

---

Go to **Settings → Integrations** to configure outbound alerting.

| Integration | What it does |
|-------------|-------------|
| **Slack** | Posts alert cards to a Slack channel |
| **Email** | Sends alert emails (configure SMTP rules per severity in Notifications → Email) |
| **Webhook** | POSTs JSON alert payloads to any URL |
| **PagerDuty** | Creates PagerDuty incidents from critical/high alerts |
| **Microsoft Teams** | Posts adaptive cards to a Teams channel |
| **Jira** | Auto-creates Jira issues from alerts |
| **ServiceNow** | Creates ServiceNow incidents via Table API |

**Test** — after saving an integration, click **Test** to send a test payload and verify it works.

**Automatic retry** — all outbound deliveries (Slack, PagerDuty, Teams, Jira, ServiceNow, generic webhook) retry automatically on transient failures. The platform makes up to 3 attempts (immediate → 5 s → 30 s). HTTP 4xx responses are treated as permanent failures (configuration error — fix the URL/token, not a retry candidate). SSRF-blocked URLs fail immediately.

**Delivery log** — click **Delivery Log** to see the last 100 webhook deliveries with status codes, response bodies, and error messages. The outcome shown is the final attempt — if all 3 retries failed, the entry shows `failed` with the last error.

### Email notification rules

Go to **Notifications → Email Rules** to configure which alert severities trigger email, and to which addresses. Each rule can filter by severity and/or rule name pattern.

### Network Behavior Analytics (NBA)

Go to **Network → NBA** to see anomalies detected by the network behavioral detector:
- Baseline deviation from normal connection patterns
- Anomalous protocols or ports
- Unusual bandwidth volumes

Click **Acknowledge** to mark an anomaly as reviewed.

---

## Account & Profile

### Profile

Go to **Account → Profile** to update your display name and email. Click **Change Password** to set a new password (requires your current password).

### Sessions

Go to **Account → Sessions** to see all active sessions (browser, API, SSO). Click **Revoke** to force-logout any session — useful if you suspect a session was compromised.

### API Keys

Go to **Account → API Keys** (admin only to create). API keys let you integrate external scripts or tools with XCloak without using your user password. Keys are shown once at creation — store them in a secrets manager.

Each key is scoped to a role. Keys are prefixed `xck_` for easy identification in logs.

### 2FA

Go to **Account → Security → 2FA** to enable or disable TOTP. Disabling requires your current TOTP code.

### Custom Roles (admin only)

Go to **Settings → Roles** to define granular custom roles. Each role is a named set of permissions from the full permission set:

`manage_firewall`, `manage_agents`, `manage_detection_rules`, `manage_threat_intel`, `manage_playbooks`, `manage_suppression`, `manage_compliance`, `manage_notifications`, `manage_integrations`, `manage_scheduler`, `manage_incidents`, `manage_quarantine`, `manage_users`, `manage_api_keys`, `manage_correlation_rules`, `export_audit_logs`, `run_scripts`, `approve_soar_actions`, `run_ai_analysis`, `sync_firewall`

Assign custom roles to users from **Settings → Users**.
