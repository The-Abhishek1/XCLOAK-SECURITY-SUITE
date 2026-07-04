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
| 2.1.1 | Passwords ≥ 8 chars | ✅ enforced in `POST /api/auth/register` |
| 2.3.1 | Credentials not sent in URL | ✅ `?token=` removed (P1.6) |
| 3.3.1 | Session tokens invalidated on logout | ✅ Redis revocation list |
| 3.4.1 | Cookie secure + httpOnly | ✅ P1.x cookie migration |
| 4.1.1 | Access control on every resource | ✅ RequireAuth() on all routes |
| 4.3.1 | Administrative functions isolated | ✅ RequireRole("admin") + platform_admin |
| 2.5.2 | Account lockout after failed attempts | ✅ per-username 5-failure/15-min lock in `login_guard.go` |
| 5.2.1 | Input validation on all fields | ✅ KQL gated by `isSafeFieldName`; uploads 1 MiB/file; shell allowlisted |
| 7.1.1 | Sensitive data not logged | ⚠️ `parsed_fields` may contain PII (email, IP, username) — operators should define a data-handling policy |
| 8.1.1 | RLS / tenant isolation | ✅ PostgreSQL RLS + `WithTenantTx` on all writes (Phase 1) |
| 9.1.1 | TLS for all connections | ✅ configurable, enforced at ingress |
| 10.2.1 | No hardcoded credentials | ✅ all secrets via env/Vault |
| 12.1.1 | File upload size limits | ✅ 1 MiB/file (YARA/Sigma), 200 MiB (vuln scan), 10 MiB (log ingest) |
| 14.4.1 | Security headers on all responses | ✅ `SecurityHeaders()` middleware: CSP, HSTS, X-Content-Type-Options, X-Frame-Options |
