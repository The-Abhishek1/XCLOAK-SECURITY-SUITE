# Changelog

All notable changes to XCloak are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
XCloak uses [semantic versioning](https://semver.org/).

---

## [0.2.0] — 2026-07-07

### Added

**Backend — Security Hardening (Phases 4–6)**
- httpOnly cookie session auth (`access_token` + `refresh_token`); refresh token issued on every login, revoked on each rotation
- Atomic Lua sliding-window rate limiter (TOCTOU race closed): `ZREMRANGEBYSCORE + ZCARD + ZADD` in one Redis `EVAL`
- PostgreSQL RLS now load-bearing for every query: migration `000057` grants `xcloak_app` DML on all tables; app pool connects as `xcloak_app`
- Kafka event bus wired end-to-end: 5 publish functions + 6 consumer groups + 7 new consumer files (`fim_consumer`, `yara_consumer`, `incident_consumer`, `audit_consumer`, `ws_broadcast_consumer`, `ioc_match_consumer`)
- `FireIncidentWebhook` wired into `incident_consumer` — webhooks now fire on every new incident
- Real-time WebSocket notifications for incidents and task completions via `PublishEventBroadcast`
- FIM critical-path violations auto-create `quarantine_file` tasks in pending-approval queue
- YARA matches auto-create `quarantine_file` tasks in pending-approval queue
- High-risk audit events streamed to Splunk HEC in real time (13 action codes)
- Splunk config cached in-process (2-min TTL) — removes per-event DB round-trip
- Webhook retry with exponential backoff (immediate → 5 s → 30 s) for all integrations
- `xcloak_webhook_deliveries_total` Prometheus counter (by integration + outcome)
- `APP_BASE_URL` env var replaces hardcoded localhost in password-reset/invite emails
- `logRecover()` replaces all silent `recover()` calls — panics now emit `slog.Error`
- Full structured slog migration: zero `fmt.Printf`/`fmt.Println` in any backend file
- Audit logging for `LOG_RETENTION_CHANGE` and `SECURITY_POLICY_UPDATE`

**Go Agent — Enterprise Upgrade (Phase 7)**
- `log/slog` migration: zero unstructured log lines; `LOG_FORMAT=json` / `LOG_LEVEL` env controls
- Connection enrichment: `/proc/net/tcp*` inode→PID mapping (Linux); `netstat -ano` + `tasklist` (Windows) — every socket now has PID, process name, process path
- User inventory expanded: groups (`/etc/group`), sudo access (sudoers + wheel/sudo/admin), SSH authorized_keys, last login (`last`), account locked status (`/etc/shadow`), home directory, GID
- Package collection: dpkg → rpm → pacman → snap → flatpak → pip3 simultaneously (Linux); WMIC → registry → winget (Windows); `source` field added
- FIM extended: `mode`, `uid`, `gid`, `mod_time` per file via `syscall.Stat_t` (Linux); extended watch paths (`/etc/ld.so.preload`, `/etc/pam.d`, `/etc/systemd/system`)
- New collectors: cron jobs (Linux: `/etc/crontab` + `/etc/cron.d/*` + user crontabs; Windows: `schtasks`), kernel modules (`lsmod`/`driverquery`), SUID/SGID binary scan, disk usage (`/proc/mounts` + `syscall.Statfs`)
- Heartbeat enriched: Linux adds `load_avg_1m/5m/15m`, `logged_in_users`, `open_fds`; Windows adds `logged_in_users`, `cpu_load_pct`
- 4 new server-dispatched task types: `collect_cron_jobs`, `collect_kernel_modules`, `collect_suid_binaries`, `collect_disk_usage`

**Mobile Agent (Android) — Enterprise Upgrade (Phase 8)**
- `DevicePosture` expanded from 8 → 24 fields: battery level/charging, storage total/free, RAM, VPN detection, USB debugging, unknown sources, security patch level, manufacturer, hardware, network type, WiFi SSID, Android SDK version
- `PostureCollector` rewrite: battery via `dumpsys battery`, storage via `df /data`, RAM from `/proc/meminfo`, VPN via `NetworkInterface.list()`, Magisk socket check, USB debugging + unknown sources via `settings get global`
- `EnrollmentService` sends full posture snapshot + build fingerprint on enrollment
- 5 staggered background timers with ≤30 s jitter: check-in (5 min), command poll (2 min), log forward (10 min), app inventory (30 min), threat scan (15 min)
- `ApiClient` retry with exponential backoff (×3; 500 ms → 1 s → 2 s + jitter) for 5xx/429/SocketException/Timeout; 30 s timeout per request
- New MDM commands: `collect_posture`, `scan_threats`, `rotate_token`, `update_agent` — all fully implemented with result strings and acknowledgment
- `CommandService` stubs replaced: `collect_logs` calls `LogForwarder.forwardBatch()`, `sync` calls posture + apps
- `LogForwarder`: 11 security-relevant logcat tags; severity field per line; 200-line batches
- Consecutive check-in failure tracking → notification degrades to "Agent degraded" after 5 failures
- Pending message delivery: `message` MDM command stores text; shown as `AlertDialog` on next app open
- `agent_shell` Posture tab: 10 checks (added USB debugging, unknown sources, battery, storage, network, VPN), Hardware sub-score, Device Status card with progress bars, build fingerprint in device accordion

**Docs**
- `docs/security-audit-prep.md` — Phase 5, 6, 7, 8 entries (53 closed items total)
- `docs/user-guide.md` — MDM section with posture table, command reference, log-tag list
- `docs/deployment-guide.md` — Mobile agent deployment playbook (build → enroll → dispatch commands → unenroll)
- `README.md` — Mobile agent enterprise capabilities documented

### Fixed
- `GenerateRefreshToken` defined but never called — refresh tokens now issued on every login
- WebSocket auth used `?token=` query param leaking tokens into logs — replaced with short-lived WS ticket
- Silent `recover()` in goroutines swallowed panics — all replaced with `logRecover()`
- `stringVal()` in sessions audit call referenced non-existent helper — fixed to `fmt.Sprintf`
- Partition `DROP` in `pruneEmptyEndpointLogsPartitions` validated against regex before DDL
- `atoiSafe()` in `processes_windows.go` used `fmt.Sscanf` instead of `strconv.Atoi`

---

## [0.1.0] — 2026-06-30

### Added

**Core Platform**
- Go 1.25 / Gin backend with 56 database migrations (PostgreSQL 16)
- Multi-tenant architecture with PostgreSQL Row-Level Security
- JWT access tokens (8h) + Redis-backed revocation list
- TOTP 2FA via HashiCorp Vault transit
- OIDC/SSO per-tenant single sign-on
- Fine-grained RBAC: 19 permissions, custom roles

**Detection**
- Sigma rule engine with 43 production-ready rules seeded on first run
- YARA rule malware scanning
- IOC engine (IP, domain, hash, URL, email)
- 12 behavioral detectors: C2 beacon, DNS security, port scan, exfiltration, TLS/JA3 fingerprinting, credential attacks, privilege escalation, ransomware, LotL, impossible travel, NBA, UEBA
- Kafka-backed async IOC matching off the request path
- AD/LDAP alert enrichment with 3-tier cache

**Go Agent (Linux / Windows)**
- Single binary, no runtime dependencies
- 15 autonomous collectors (processes, connections, users, packages, FIM, services, auth logs, auditd, file hashes, registry, cron jobs, kernel modules, SUID scan, disk usage, firewall stats)
- eBPF TCP event capture (Linux kernel 5.8+, optional)
- ed25519-signed self-update with SHA-256 integrity verification
- Server-dispatched tasks: kill process, isolate host, quarantine file, run script, FIM scan

**SOAR**
- Automated playbooks with human-in-the-loop approval gate
- AI playbook recommender (Claude/Ollama)
- FIM + YARA auto-quarantine with pending-approval workflow
- Webhook delivery with SSRF protection

**Mobile Agent (Android)**
- Flutter 3.24 Android app with dual mode: Agent + Admin Console
- 53-section SOC admin console
- Foreground service, MDM check-in, app inventory, command handling

**Integrations**
- Slack, Email, PagerDuty, Microsoft Teams, Jira, ServiceNow, Webhook
- Elasticsearch dual-write, Splunk HEC, MinIO Object Lock audit export
- Prometheus metrics, Grafana dashboards, Kafka event bus

**Infrastructure**
- Docker Compose for local development
- Helm chart for Kubernetes (v0.1.0)
- PostgreSQL, Redis bundled via Bitnami charts (Kafka + MinIO BYO)

---

## [Unreleased]

See [roadmap.md](roadmap.md) for planned features.
