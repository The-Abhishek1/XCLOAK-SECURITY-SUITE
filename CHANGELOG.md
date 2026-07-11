# Changelog

All notable changes to XCloak are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
XCloak uses [semantic versioning](https://semver.org/).

Technical release posts and deep-dives at [blog.xcloak.tech](https://blog.xcloak.tech).

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

### Added

**Enterprise Firewall (migration 000063)**
- 9 new rule fields: `direction` (in/out/both), `port_range` (e.g. `8000-9000`, `80,443`), `log_enabled`, `log_prefix`, `expires_at`, `tags`, `created_by`, `updated_by`, `updated_at`
- `firewall_policy` table: per-tenant default-action (allow/deny) + mode (enforcing/audit/disabled)
- 8 new API endpoints: `GET/PUT /api/firewall/policy`, `POST /api/firewall/rules/bulk`, `POST /api/firewall/rules/import`, `GET /api/firewall/templates`, `GET/DELETE /api/firewall/expired`, `GET /api/firewall/conflicts/v2`
- 12 built-in rule templates (SSH allowlist, HTTPS egress, DNS allow, SMB block, etc.)
- CIDR overlap conflict detection using `net.IPNet.Contains`; port-range interval overlap via `ParsePortRange`
- `StartExpiredRuleReaper()` goroutine prunes expired rules every hour
- Agent Linux: atomic `iptables-restore --noflush` apply; incremental fallback; LOG target for `log_enabled`
- Agent Windows: direction-aware `netsh` rules (`-in`/`-out` suffixes when `direction=both`); `localport=` for port ranges
- Frontend: direction badge, bulk select toolbar, template picker modal, default policy toggle, JSON import, per-rule expiry indicator, tags display, full enterprise form
- `firewall_validators.go` fully rewritten: 21 tests pass (CIDR, direction enum, port-range, action enum)

**Deep Packet Inspection / Advanced Detection (migration 000064)**
- `dpi_findings` table: `finding_type`, `severity`, `score`, `indicator`, `description`, `mitre_technique`, `raw_context` (JSONB), `alert_fired`, `detected_at`
- 9 DPI columns on `network_connect_events`: `sni`, `http_host`, `http_method`, `http_path`, `http_user_agent`, `tls_version`, `tls_cipher`, `dpi_proto`, `entropy_score`
- `services/payload_entropy.go`: `ShannonEntropy`, `EntropyScore` (0–100), multi-factor `DGAScore` (entropy + English bigrams + digit ratio + consonant clusters + label length), `URLPathEntropy`, `IsBase64Encoded`
- `services/dga_detector.go`: 25 suspicious TLD bonuses; 3 DGA family matchers (Conficker/Necurs/Mirai-variant); NXDOMAIN storm detection; 30+ domain allowlist; 30-min sweep + real-time DNS pipeline hook; T1568.002
- `services/tls_anomaly_detector.go`: 12 weak cipher patterns; deprecated TLS version detection (SSLv3/1.0/1.1); self-signed cert detection; TLS on non-standard ports; SNI/Host domain fronting; 1-hour dedup; 15-min sweep; T1040/T1553/T1571/T1090.004
- `services/http_inspection_service.go`: 35+ malicious User-Agent signatures (RATs, C2 frameworks, scanners); webshell path detection (20+ patterns); path traversal/null-byte injection; suspicious HTTP methods (PROPFIND, TRACK, TRACE, DEBUG); high-entropy UA detection; 10-min sweep; T1071.001/T1505.003/T1190/T1595
- `services/protocol_anomaly_detector.go`: DNS tunneling (long labels + query rate); protocol-on-wrong-port for 9 protocols; ICMP tunnel (large payload); HTTP CONNECT to RFC 1918 addresses; DNS-over-TCP volume; SMTP on non-standard ports; 10-min sweep; T1071.004/T1571/T1095/T1572/T1048.002
- `dns_security.go` `AnalyzeDNSLogEntry` now delegates DGA scoring to `ScoreDomainDGA()` instead of single-entropy threshold
- `GET /api/dpi/findings` — paginated, filterable by agent/type/severity/alert-only
- `GET /api/dpi/summary` — 24-hour breakdown by finding type + severity
- Agent: `ConnectEvent` model extended with 9 DPI fields; `passive_dpi_linux.go` extracts SNI from TLS ClientHello + HTTP headers from `/proc/<pid>/fd` sockets (80ms timeout goroutine); `passive_dpi_other.go` no-op stub
- Frontend: `/dpi` Deep Inspection page — summary cards, breakdown pills, filterable table with score bars, expand-to-raw-context, MITRE links; Sidebar entry added

See [roadmap.md](roadmap.md) for planned features.

---

*[xcloak.tech](https://xcloak.tech) · [blog.xcloak.tech](https://blog.xcloak.tech) · [docs.xcloak.tech](https://docs.xcloak.tech)*
