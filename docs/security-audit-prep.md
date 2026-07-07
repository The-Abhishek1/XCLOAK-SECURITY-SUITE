# XCloak Security Audit & Penetration Test Preparation

This document prepares for a third-party external security audit.
It covers controls already in place, known attack surface, recommended
scope, and test evidence to collect before the engagement.

---

## Controls Already Implemented

### Authentication & Session Management
| Control | Location | Notes |
|---------|----------|-------|
| JWT access tokens (8h) + refresh tokens (7d) | `backend/auth/jwt.go` | Separate token types, type claim enforced |
| httpOnly cookie session (no JS access) | `backend/api/cookie_helpers.go` | Secure + SameSite=Lax |
| Token revocation on logout (Redis set) | `backend/services/redis_client.go` | `IsRevoked()` checked on every request |
| `?token=` query param removed | `backend/middleware/auth.go` | Eliminated token leakage via Referer/logs |
| Refresh token rotation | `backend/api/auth.go` | Old refresh invalidated on each use |
| WebSocket auth via short-lived ticket | `backend/api/ws_ticket.go` | Ticket consumed after use, 30s TTL |
| TOTP 2FA (TOTP via HashiCorp Vault transit) | `backend/services/totp_service.go` | Secrets encrypted at rest |
| API key support (xck_ prefix, hashed in DB) | `backend/services/api_key_service.go` | SHA-256 stored, never plaintext |
| Session list / forced logout | `backend/api/sessions.go` | Users can revoke other sessions |

### Authorization
| Control | Location | Notes |
|---------|----------|-------|
| Tenant isolation via PostgreSQL RLS | `migrations/000050_rls_tenant_isolation.up.sql` | `SET LOCAL app.tenant_id` per transaction |
| Role-based access (admin/analyst/viewer) | `backend/middleware/auth.go` | Checked via `RequireRole()` |
| Platform-admin gate (cross-tenant ops) | `middleware/auth.go` | `is_platform_admin` JWT claim |
| Agent auth separate from user auth | `backend/middleware/auth.go` | `RequireAgentAuth()` — agent tokens only |
| API key scoped by role | `backend/api/api_keys.go` | Role set at creation, not elevatable |

### Transport & Infrastructure
| Control | Location | Notes |
|---------|----------|-------|
| TLS termination | `backend/main.go` (or ingress) | TLS_CERT_FILE/KEY_FILE or Ingress TLS |
| CORS allowlist | `backend/main.go` | CORS_ALLOWED_ORIGINS env var |
| PgBouncer connection pooling | `docker-compose.yml`, Helm chart | Transaction mode (safe for RLS) |
| Secrets via HashiCorp Vault | `backend/secrets/` | Optional; falls back to env |
| ed25519-signed agent releases | `backend/services/release_signing_service.go` | Agents verify before self-update |

### Logging & Observability
| Control | Location | Notes |
|---------|----------|-------|
| Structured audit log | `backend/services/audit_service.go` | Every sensitive action logged |
| Immutable audit export (MinIO Object Lock) | `backend/services/audit_export_service.go` | WORM semantics |
| Prometheus metrics | `backend/api/metrics_endpoint.go` | Static bearer token required |
| Structured slog (P2.5) | `backend/logger/logger.go` | JSON in production |

---

## Attack Surface (Pentest Scope)

### External Endpoints
All routes are defined in `backend/routes/routes.go`.

**Public (no auth):**
- `POST /api/auth/login` — credential stuffing; per-IP rate limiting (10 req/min) + per-username lockout (5 failures → 15-min lock) now enforced
- `POST /api/auth/register` — first user creates admin; subsequent users analyst
- `GET /api/agent-releases/:platform` — requires agent token, not user token
- `GET /api/auth/oidc/*` — OIDC callback (CSRF state param enforced)

**Authenticated (user JWT / cookie):**
- All `/api/*` routes — test for IDOR, privilege escalation, SSRF (webhook URLs), injection
- `GET /api/notifications/stream` — WebSocket; ticket auth
- `GET /api/logs/live/:agentID` — WebSocket; ticket auth

**Agent-only (agent token):**
- `POST /api/agents/heartbeat`
- `POST /api/logs/ingest`
- `POST /api/fim/alerts`
- `POST /api/mdm/commands/:id/acknowledge`

**Platform-admin only:**
- `POST /api/platform/agent-releases`
- `/api/platform/tenants/*`

### Gaps — Phase 1 (all closed)

- [x] **Per-IP rate limiting on login** — `RateLimitAuth()` (10 req/min sliding window, Redis) in `backend/middleware/rate_limiter.go`. Applied to /api/auth/login, /api/auth/register, /api/signup.
- [x] **Per-username lockout on login** — `services.IsUsernameLocked()` / `RecordLoginFailure()` / `ClearLoginFailures()` in `backend/services/login_guard.go`; 5 failures in 15 min → 15-min lockout (Redis `login:fail:{u}`, `login:locked:{u}`). Wired into `api/auth.go:Login()`.
- [x] **CSP + HSTS headers** — `SecurityHeaders()` Gin middleware in `backend/middleware/security_headers.go`, registered globally in `main.go`. Sets `Content-Security-Policy: default-src 'none'`, HSTS (TLS-conditional, 1 year), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`.
- [x] **Request size limit on log ingest** — `http.MaxBytesReader(10 MiB)` on `ReceiveLogs` in `api/log.go` (POST /api/agents/logs). Matches existing cap on POST /api/logs/ingest.
- [x] **Webhook SSRF** — `services.CheckURL()` in `backend/services/ssrf.go` denies loopback (127.0.0.0/8, ::1), RFC1918, link-local/metadata (169.254.0.0/16, fe80::/10), shared CGN (100.64.0.0/10), and known metadata hostnames. Wired into `webhook_service.go:deliver()`, `playbook_engine.go:handleWebhook()`, and `playbook_engine.go:handleSlackMessage()`.
- [x] **RLS bypass (superuser app pool)** — `APP_DB_USER=xcloak_app` added to `.env.example` and compose/Helm defaults. `database/db.go:Connect()` opens the app pool as APP_DB_USER (DML-only, subject to RLS) and a separate `MigrationDB` pool as DB_USER (DDL rights). `WithTenantTx` wired into `CreateAlert`, `CreateSigmaRule`, `UpdateSigmaRule`, `CreateIOC` so the RLS WITH CHECK policy validates every write at the DB layer.

### Gaps — Phase 2 (all closed)

- [x] **File upload size limits** — `io.LimitReader(f, 1 MiB+1)` added to `api/yara_import.go` and `api/sigma_import.go`; max 20 files per request; oversized files are rejected before parsing. Vuln import (`api/vuln_import.go`) already had a 200 MiB check. Global Gin `router.MaxMultipartMemory = 8 MiB` set in `main.go` as a secondary backstop.
- [x] **KQL injection** — `log_search_service.go:isSafeFieldName()` validated as the security gate: field names go through `[a-zA-Z0-9_]{1-60}` before SQL interpolation; all field values are parameterized (`$N` args). No injection path exists. Reviewed and commented 2026-07-04.
- [x] **JSONB injection** — `parsed_fields` data accessed exclusively via `->>` text extraction with hardcoded key names (behavioral_baseline_service, email_security_detector, ot_ics_detector) or through `isSafeFieldName`-validated user keys (KQL search). Data is never executed — only compared via ILIKE/= operators. No plv8 or eval path exists. Reviewed 2026-07-04.
- [x] **Script runner shell allowlist** — `api/script_runner.go:DispatchScript()` now validates `shell` against `{bash, sh, python3, pwsh}`. Script body capped at 512 KiB. Backend does not execute scripts (payload is queued for agent); cross-tenant execution was already blocked via `GetAgentByID(id, tenantID)`.

### Gaps — Phase 3 (all closed)

- [x] **Path traversal in file uploads** — Confirmed N/A: YARA and Sigma import store rule content in PostgreSQL only; no file is written to the filesystem. No path traversal attack surface today. Revisit if on-disk YARA scanning is added.
- [x] **Per-tenant partition DROP** — `pruneEmptyEndpointLogsPartitions()` added to `log_search_service.go`; runs after every `ApplyRetentionPolicies()` nightly pass. Validates partition name against `^endpoint_logs_\d{4}_\d{2}$` before DDL, checks `EXISTS` immediately before DROP (no TOCTOU gap). Old partitions are reclaimed once all tenant data has expired out of them.
- [x] **KQL OR/NOT operators** — `log_search_service.go` tokenizer and parser fully rewritten. OR is now a first-class separator producing `(groupA) OR (groupB)` SQL. NOT keyword equivalent to `-` prefix (combinable). AND remains implicit. No query silently ignores user intent.

### Gaps — Phase 4 (all closed)

- [x] **RLS not operationally active** — Migration `000057_xcloak_app_full_grants.up.sql` grants `xcloak_app` SELECT/INSERT/UPDATE/DELETE on ALL tables in the public schema (not just the 6 RLS-protected tables from migration 000050) and sets `ALTER DEFAULT PRIVILEGES` so future migrations inherit the same grants. With `APP_DB_USER=xcloak_app` in `.env`, the app pool now connects as the limited-privilege role end-to-end and RLS is load-bearing for every query.
- [x] **Default xcloak_app password warning** — `database/db.go:Connect()` emits `slog.Warn` when `APP_DB_PASSWORD` is the known default `change_me_in_production`. Visible in startup logs before any traffic is served.
- [x] **Unprotected high-cost endpoints** — Added `middleware.RateLimitAPI()` (120 req/min sliding window) to `GET /api/logs/search`, `GET /api/logs/export`, `GET /api/dashboard/overview`, `GET /api/dashboard/metrics`, `POST /api/alerts/bulk-acknowledge`, `POST /api/iocs/bulk`. These endpoints perform full-table scans or aggregations; without rate limiting they were a DoS vector for authenticated users.
- [x] **Audit logging gaps for DELETE/config operations** — Added `services.LogEvent()` calls to `DeleteIOC` (`IOC_DELETE`), `DeleteSigmaRule` (`SIGMA_RULE_DELETE`), and `DeleteThreatFeed` (`THREAT_FEED_DELETE`). Audit trail now covers all destructive detection-rule operations.
- [x] **Weak password policy** — `services.ValidatePasswordComplexity()` replaces all bare `len(password) < 8` checks. New policy: ≥8 chars, at least one uppercase, lowercase, digit, and special character. Applied at all four registration/reset paths: `api/auth.go:Register`, `services/user_service.go:ChangePassword`, `services/user_service.go:ResetPassword`, `services/tenant_service.go:SelfServeSignup`.
- [x] **Detection engine test coverage** — Added unit tests for pure helper functions across 4 detectors previously without any test file: `c2_beacon_detector_test.go` (computeIntervals, meanF, stddevF, coefficientOfVariation, isBenignProcess, isSuspiciousPort, splitAddr, scoreBeacon edge cases), `exfil_detector_test.go` (ExtractBytesFromLogMessage, isCloudStorageDomain, cloudStorageDomains integrity), `port_scan_detector_test.go` (portScanScore, adminPortName), `lotl_detector_test.go` (exeName, suspiciousChains table, lolBinSigs table, encodedPSFlags). Also fixed a latent panic in `computeIntervals` (negative capacity make when called with < 2 elements).

### Gaps — Phase 5 (all closed, 2026-07-07)

- [x] **Rate limiter TOCTOU race** — `middleware/rate_limiter.go` rewrote the sliding-window check from a two-pipeline approach (check cardinality, then add — vulnerable to concurrent requests both passing the limit) to a single atomic Lua script (`ZREMRANGEBYSCORE` + `ZCARD` + conditional `ZADD` in one `EVAL`). No gap between read and write — concurrent requests cannot both slip through a full window.

- [x] **Refresh token never issued** — `GenerateRefreshToken` was defined but never called. Now issued on every login as a 7-day `refresh_token` httpOnly cookie, path-scoped to `/api/auth/refresh` (inaccessible to JS on other paths). Old refresh token is revoked on each use (rotation). `POST /api/auth/refresh` validates type claim, checks revocation list, verifies user/tenant are still active, and issues a new pair. Mobile clients (Dart/OkHttp UA) additionally receive the token in the response body.

- [x] **No agent token revocation path** — `POST /api/agents/:id/rotate-token` generates a new token and atomically replaces the old one. Old token is immediately invalid. Requires `manage_agents` permission. Every rotation is audit-logged as `AGENT_TOKEN_ROTATED`.

- [x] **Kafka consumers — dead publish paths** — Five publish functions (`PublishIncident`, `PublishTaskDispatched`, `PublishTaskCompleted`, `PublishAuditEvent`, `PublishFIMAlert`, `PublishYARAMatch`) were defined but never called, so no events were flowing through the bus. All five are now wired into their respective service functions. Six new consumer files implement the downstream actions — see below.

- [x] **`FireIncidentWebhook` never called** — Defined in `webhook_service.go` but not invoked anywhere. Now called from `incident_consumer.go` for every `incident.created` Kafka event.

- [x] **No real-time incident/task WS notifications** — WS broadcast was alert-only. Added `PublishEventBroadcast` in `ws_broadcast_service.go` and updated `api.BroadcastRaw` to forward pre-typed events directly (detects `"type"` field; falls back to alert-wrapping for backward compatibility). Incident and task-completion events now push real-time WS notifications.

- [x] **FIM violations had no automated response** — `fim_consumer.go` auto-creates a `quarantine_file` task in `pending_approval` when a critical system path (`/bin/*`, `/etc/passwd`, `/etc/sudoers`, etc.) is modified or deleted. Goes through the human-approval queue — not dispatched without operator review.

- [x] **YARA matches had no automated response** — `yara_consumer.go` auto-creates a `quarantine_file` task in `pending_approval` for each YARA-matched file path. Same approval-queue gate as FIM.

- [x] **High-risk audit actions not forwarded to SIEM in real time** — `audit_consumer.go` streams 13 high-risk actions (ROLE_CHANGE, DELETE_USER, AGENT_TOKEN_ROTATED, SIGMA_RULE_DELETE, PERMISSION_CHANGE, etc.) to all configured Splunk HEC endpoints immediately. Previously, audit events only reached Splunk via the nightly MinIO export.

- [x] **`APP_BASE_URL` hardcoded in emails** — Password-reset and invite email links used a hardcoded `http://localhost:3000` prefix. Replaced with `appBaseURL()` helper reading `APP_BASE_URL` env var, falling back to localhost for dev.

- [x] **Unstructured goroutine panics** — `defer func() { recover() }()` in goroutines swallowed panics silently. Replaced with `defer logRecover("CallerName")` which logs via `slog.Error` with panic value and caller name, then resumes.

### Gaps — Phase 6 (all closed, 2026-07-07)

- [x] **Consumer panic isolation incomplete** — Three consumers (`fim_consumer.go`, `yara_consumer.go`, `ioc_match_consumer.go`) had no per-message recovery. All consumers now extract message processing into a dedicated `process*Event(raw []byte)` function with `defer logRecover("process*Event")` inside. A panic on one message is logged and discarded; the consumer loop continues without crashing. The outer `Start*Consumer` also defers `logRecover` for setup panics.

- [x] **Silent `recover()` swallowing panics** — `correlation_service.go:fireCorrelationNotification` goroutine and `prometheus_service.go:RunDetector` both had `defer func() { recover() }()` that silently absorbed panics. Both now log via `slog.Error` with the panic value before recovering, making failures visible in structured logs and alertable in Loki/CloudWatch.

- [x] **Webhook delivery with no retry** — All outbound deliveries (Slack, PagerDuty, Teams, Jira, ServiceNow, Splunk HEC, generic webhook) had no retry logic — a transient network error or 5xx caused permanent delivery failure silently. `webhook_service.go:deliver()` now retries with exponential backoff: immediate → 5s → 30s. Network errors and 5xx are retried; 4xx failures are treated as permanent. SSRF-blocked URLs fail immediately without retry.

- [x] **No Prometheus visibility into webhook delivery failures** — Added `xcloak_webhook_deliveries_total` CounterVec (labels: `integration`, `event_type`, `outcome`) to `prometheus_service.go`. Incremented in `logDelivery()` for every outbound delivery attempt. This allows SLO alerting on delivery failure rates per integration.

- [x] **Audit log gaps — LOG_RETENTION_CHANGE and SECURITY_POLICY_UPDATE** — `api/log_search.go:SetRetentionPolicy` and `api/sessions.go:UpdateSecurityPolicy` were modifying tenant-scoped security configuration without emitting audit log entries. Both now call `services.LogEvent()` immediately after a successful write. `LOG_RETENTION_CHANGE` and `SECURITY_POLICY_UPDATE` are now audited alongside the 13 existing high-risk action codes.

- [x] **Splunk HEC streaming — DB query per event** — `audit_consumer.go:streamAuditToSplunk` queried `integrations WHERE name='splunk' AND enabled=true` on every high-risk audit event — a synchronous DB round-trip inside a Kafka consumer loop. Replaced with `loadSplunkConfigs()`: a `sync.Mutex`-protected in-process cache with a 2-minute TTL. Stale enough to be invisible under normal load; short enough that a newly added Splunk integration is visible within one cache window.

- [x] **Unstructured logs throughout backend** — `fmt.Printf`/`fmt.Println` calls remained in 17+ files after the initial slog migration (partition manager, scheduler, MinIO client, syslog receiver, anomaly detection, vulnerability scanner, AI triage, IOC autoblock, KEV refresh, scheduled reports, audit export, correlation engine, api/live_logs, api/log_ingest, api/risk_score_breakdown, api/notifications_ws). All replaced with structured `slog.Info/Warn/Error/Debug` calls with typed key-value fields. The backend now emits zero unstructured log lines in production paths.

### Gaps — Phase 7 (all closed, 2026-07-07) — Agent enterprise upgrade

- [x] **Agent unstructured logging** — All `fmt.Printf`/`fmt.Println`/`println()` calls across every agent file replaced with `log/slog` structured calls. `InitLogger()` honours `LOG_FORMAT=json` (production) and `LOG_LEVEL` at runtime. Agent now emits zero unstructured log lines — output integrates cleanly with any log aggregator (Splunk, Elastic, CloudWatch, Datadog).

- [x] **Connection telemetry lacked process context** — `CollectConnections` reported raw socket tuples with no PID or process name. Linux: now uses `/proc/net/tcp*` + inode→PID mapping from `/proc/<pid>/fd/` + `/proc/<pid>/comm` — every connection carries `pid`, `process_name`, `process_path`. Windows: `netstat -ano` + `tasklist /fo csv` PID→name resolution. `Connection` model updated with three new fields.

- [x] **User inventory was minimal** — Only username, UID, shell collected. Linux now also gathers: supplementary groups (`/etc/group`), sudo access (sudoers + wheel/sudo/admin group membership), SSH authorized_keys presence (`~/.ssh/authorized_keys`), most-recent login timestamp (`last`), account locked/disabled status (`/etc/shadow`), home directory. Windows: Administrators group membership mapped to `SudoAccess=true`. `User` model updated with GID, HomeDir, Groups, SudoAccess, HasSSHKey, LastLogin, PasswordExpiry, Enabled fields.

- [x] **Package collection was dpkg-only on Linux** — Full fallback chain now: dpkg → rpm → pacman → snap → flatpak → pip3. All sources collected simultaneously (not first-wins). Windows: WMIC → registry (PowerShell) → winget. Every package tagged with a `source` field. `Package` model updated.

- [x] **FIM tracked only hash + size** — `fimFileEntry` now also records file `mode` (permission string), `uid`, `gid`, and `mod_time`. Platform split: `fim_stat_linux.go` reads UID/GID via `syscall.Stat_t`; `fim_stat_windows.go` is a no-op. Extended `DefaultWatchPaths` with `/etc/ld.so.preload`, `/etc/pam.d`, `/etc/systemd/system` — critical persistence paths.

- [x] **No cron job / scheduled task inventory** — New `cron_collector.go` (Linux) collects `/etc/crontab`, `/etc/cron.d/*`, and per-user crontabs from `/var/spool/cron/crontabs/*`. `cron_collector_windows.go` queries `schtasks /fo CSV`. Runs every hour autonomously; also dispatchable as `collect_cron_jobs` task.

- [x] **No kernel module / driver inventory** — New `kernel_modules.go` (Linux) collects `lsmod` output (name, size, used-by). `kernel_modules_windows.go` uses `driverquery /fo csv`. Unexpected modules are a key rootkit/persistence indicator. Runs every 30 min autonomously; dispatchable as `collect_kernel_modules` task.

- [x] **No SUID/SGID binary inventory** — New `suid_scan.go` walks `/usr`, `/bin`, `/sbin`, `/opt`, `/home` for files with SUID (04000) or SGID (02000) bit set. Reports file path, permission string, UID, GID. Runs every 6 h autonomously; dispatchable as `collect_suid_binaries` task. Windows stub (SUID is a UNIX concept).

- [x] **No disk capacity monitoring** — New `disk_collector.go` (Linux) reads `/proc/mounts` and calls `syscall.Statfs` per mount, filtering pseudo-filesystems (proc, sysfs, devtmpfs, squashfs). `disk_collector_windows.go` uses `wmic logicaldisk` with PowerShell `Get-PSDrive` fallback. Reports total/used/free GB and used% per mount. Runs every 5 min autonomously; dispatchable as `collect_disk_usage` task.

- [x] **Heartbeat telemetry was thin** — Previously reported only version, uptime, mem_alloc, goroutines. Linux heartbeat now also includes `load_avg_1m/5m/15m` (from `/proc/loadavg`), `logged_in_users` (via `who`), `open_fds` (from `/proc/sys/fs/file-nr`). Windows heartbeat adds `logged_in_users` (via `query user`) and `cpu_load_pct` (via `wmic cpu`). Platform split via `heartbeat_linux.go` / `heartbeat_windows.go`.

### Gaps — Phase 8 (all closed, 2026-07-07) — Mobile Agent enterprise upgrade

- [x] **Mobile heartbeat was hardcoded / thin** — Background worker now ships an enriched heartbeat on every check-in: `battery_level`, `battery_charging`, `network_type`, `is_rooted`, `developer_mode`, `storage_free_gb`, `storage_total_gb`, `vpn_active`, `os_version`, `security_patch`. Replaces the previous hardcoded `'version': '1.0.0'` payload.

- [x] **DevicePosture model was incomplete** — `DevicePosture` expanded from 8 to 24 fields: added `security_patch_level`, `android_sdk_version`, `manufacturer`, `hardware`, `usb_debugging_enabled`, `unknown_sources_enabled`, `vpn_active`, `battery_level`, `battery_charging`, `network_type`, `wifi_ssid`, `storage_total_gb`, `storage_free_gb`, `ram_total_mb`. All fields sent in check-in PUT and enrollment POST.

- [x] **PostureCollector collected only root + developer mode** — Full rewrite: `_checkRooted()` now also checks for Magisk socket (`/dev/.magisk/mirror`); `_checkUsbDebugging()` reads `adb_enabled` system setting; `_checkUnknownSources()` reads `install_non_market_apps` (API < 26); `_batteryInfo()` parses `dumpsys battery` for level and charge status; `_storageStats()` parses `df /data` for total/free GB; `_ramMb()` reads `/proc/meminfo:MemTotal`; `_networkInfo()` uses `NetworkInterface.list()` for VPN detection + `Connectivity().checkConnectivity()` for type.

- [x] **Enrollment sent minimal device metadata** — `EnrollmentService.enroll()` now sends all posture snapshot fields plus `security_patch_level`, `android_sdk_version`, `manufacturer`, `hardware`, `usb_debugging_enabled`, `unknown_sources_enabled`, `battery_level`, `network_type`, `storage_total_gb`, `storage_free_gb`, `ram_total_mb`, and `build_fingerprint`. Backend has complete device metadata from first check-in.

- [x] **CommandService stubs were no-ops** — `collect_logs` now calls `LogForwarder.forwardBatch()`; `sync` now calls both `collect_posture` and `collect_apps`; new `collect_posture` performs an immediate posture refresh; new `scan_threats` calls `ThreatDetector.threatSummary()` and POSTs to `/api/mdm/devices/$id/threat-scan`; new `rotate_token` calls `/api/mdm/devices/$id/rotate-token` and stores the returned token via `SecureStore.storeAgentToken()`; new `update_agent` stores a pending message with the APK URL; new `message` stores text via `SecureStore.storePendingMessage()`. Every command returns a descriptive result string to the acknowledgment endpoint. Unknown command types return an error string rather than silently succeeding.

- [x] **No retry / backoff in ApiClient** — `ApiClient` rewritten with per-request exponential backoff: up to 3 retries on `SocketException`, `TimeoutException`, HTTP 429, and HTTP 5xx. Each retry waits `500ms × 2^attempt + jitter`. HTTP 4xx are not retried. 30-second per-request timeout added. Response decoding now handles empty bodies and non-JSON responses without throwing.

- [x] **No jitter on background timers — thundering herd** — `_schedulePeriodic()` now adds 0–30 s random jitter before the first tick of each of the 5 timers (checkin, cmdPoll, logs, inventory, threatScan). Prevents all devices rebooting simultaneously (e.g. after an OS update) from hitting the backend in a synchronized burst.

- [x] **No consecutive-failure tracking** — `_consecutiveCheckinFailures` counter increments on each failed check-in. After `_maxConsecutiveFailures` (5), the foreground notification text changes to "Agent degraded — server unreachable". Counter resets on next successful check-in. 403/401 responses detect server-side unenroll and wipe credentials.

- [x] **Threat scanner ran only at inventory time** — Added a dedicated `_threatScanInterval` (15 min) timer that calls `ThreatDetector.threatSummary()` and POSTs it to `/api/mdm/devices/$id/threat-scan` independently of the full app inventory (30 min). The summary includes `total_apps`, `sideloaded_count`, `system_app_count`, and the top-20 sideloaded package names.

- [x] **Log forwarder had 4 tags and no severity parsing** — `LogForwarder` now captures 11 security-relevant tags (added `PackageInstaller`, `SELinux`, `Binder`, `WifiService`, `NetworkService`, `AccessibilityService`, `DevicePolicyManager`). Each log entry now includes a `severity` field parsed from the logcat line prefix (V/D/I/W/E/F → debug/info/warning/error/critical). Batch size increased to 200 lines.

- [x] **No pending-message delivery to device user** — `SecureStore` adds `storePendingMessage()` / `pendingMessage()` / `clearPendingMessage()`. The `message` MDM command stores text there. `AgentShell._checkPendingMessage()` is called on `initState` and shows an `AlertDialog` if a pending message is present, then clears it.

- [x] **Agent posture UI showed only root + developer mode + encryption** — `_PostureTab` now shows 10 posture checks: Root, Developer Mode, USB Debugging, Unknown Sources, Disk Encryption, Screen Lock, Battery, Storage, Network, VPN. Added a "Hardware & Environment" sub-score section. Device Information accordion expanded to show Security Patch, SDK, Manufacturer, Hardware, RAM, and Build Fingerprint. Overview tab adds a Device Status card showing battery progress bar, storage progress bar, and network type with VPN badge.

---

## Recommended Pentest Scope

### Priority 1 — Critical paths
1. Authentication bypass (JWT forgery, type confusion, `alg:none`)
2. Tenant isolation (can analyst from tenant A read tenant B's data?)
3. Privilege escalation (analyst → admin, user → platform-admin)
4. Webhook SSRF (send HTTP requests to internal services via integration callbacks)
5. Agent token theft (can a compromised agent register as a different tenant?)

### Priority 2 — Data paths  
6. SQL injection (KQL-lite parser in `log_search_service.go`) — reviewed clean: field names gated by `isSafeFieldName`, values parameterized
7. JSONB injection via `parsed_fields` — reviewed clean: data accessed via `->>`/`->` only, never executed
8. File upload security (YARA/Sigma import) — size-limited 1 MiB/file, 20 files max; content stored in DB only
9. Script runner (`POST /api/scripts/run`) — shell allowlisted, script capped at 512 KiB, tenant scoped

### Priority 3 — Resilience
10. DoS via large request bodies on log ingest
11. Redis poisoning (if attacker reaches internal network)
12. Kafka topic spoofing (if Kafka is accessible)

---

## Evidence to Collect Before Audit

```bash
# Export all routes
grep -rn 'router\.' backend/routes/routes.go | awk '{print $1}' | sort > routes.txt

# List all middleware applied
grep -rn 'RequireAuth\|RequireRole\|RequireAgentAuth' backend/routes/routes.go | wc -l

# Check for any TODO/FIXME security notes
grep -rn 'TODO\|FIXME\|HACK\|insecure\|unsafe' backend/ --include="*.go"

# Verify no hardcoded secrets
grep -rn 'password\s*=\s*"[^"]\+"\|secret\s*=\s*"[^"]\+"' backend/ --include="*.go"

# Confirm RLS is enabled
psql $DATABASE_URL -c "SELECT relname, relrowsecurity FROM pg_class WHERE relname IN ('agents','alerts','incidents','endpoint_logs','sigma_rules','iocs');"
```

---

## OWASP ASVS v4 Checklist (Selected)

| # | Requirement | Status |
|---|-------------|--------|
| 2.1.1 | Passwords ≥ 8 chars + complexity | ✅ `ValidatePasswordComplexity()` in `services/user_service.go`; requires uppercase, lowercase, digit, special char |
| 2.3.1 | Credentials not sent in URL | ✅ `?token=` removed (P1.6) |
| 3.2.1 | Refresh token rotation | ✅ `POST /api/auth/refresh`; old refresh revoked on each use; `GenerateRefreshToken` now called on every login |
| 3.3.1 | Session tokens invalidated on logout | ✅ Redis revocation list |
| 3.4.1 | Cookie secure + httpOnly | ✅ access token + refresh token both httpOnly; refresh scoped to `/api/auth/refresh` path |
| 4.1.1 | Access control on every resource | ✅ RequireAuth() on all routes |
| 4.3.1 | Administrative functions isolated | ✅ RequireRole("admin") + platform_admin; agent token rotation requires `manage_agents` |
| 2.5.2 | Account lockout after failed attempts | ✅ per-username 5-failure/15-min lock in `login_guard.go` |
| 5.2.1 | Input validation on all fields | ✅ KQL gated by `isSafeFieldName`; uploads 1 MiB/file; shell allowlisted |
| 7.1.1 | Sensitive data not logged | ⚠️ `parsed_fields` may contain PII (email, IP, username) — operators should define a data-handling policy |
| 7.2.1 | Audit log completeness | ✅ 15 high-risk action codes — 13 streamed to SIEM in real time + `LOG_RETENTION_CHANGE` and `SECURITY_POLICY_UPDATE` added (P6) |
| 8.1.1 | RLS / tenant isolation | ✅ PostgreSQL RLS + `WithTenantTx` on writes (P1); `xcloak_app` granted all tables so RLS is load-bearing for every query (P4 migration 000057) |
| 9.1.1 | TLS for all connections | ✅ configurable, enforced at ingress |
| 10.2.1 | No hardcoded credentials | ✅ all secrets via env/Vault; `APP_BASE_URL` replaces hardcoded localhost in emails |
| 11.1.4 | Rate limit correctness (no race) | ✅ atomic Lua script — TOCTOU race in sliding-window check closed (P5) |
| 12.1.1 | File upload size limits | ✅ 1 MiB/file (YARA/Sigma), 200 MiB (vuln scan), 10 MiB (log ingest) |
| 14.4.1 | Security headers on all responses | ✅ `SecurityHeaders()` middleware: CSP, HSTS, X-Content-Type-Options, X-Frame-Options |
