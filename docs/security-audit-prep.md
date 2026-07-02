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
- `POST /api/auth/login` — credential stuffing, account lockout (not yet implemented — see gap)
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

### Known Gaps (Address Before Audit)
- [ ] **No rate limiting / account lockout** on `/api/auth/login` — add middleware (e.g. `golang.org/x/time/rate` per IP + per username)
- [ ] **No CSP header** — add `Content-Security-Policy` to API responses and Next.js middleware
- [ ] **No HSTS header** — set `Strict-Transport-Security` at ingress or in Gin middleware
- [ ] **No request size limit** on log ingest — add `c.Request.Body = http.MaxBytesReader(...)` 
- [ ] **Webhook SSRF** — `POST /api/integrations` accepts arbitrary URLs; add allowlist or SSRF filter
- [ ] **No account lockout** — brute-force on login is unthrottled at the app level

---

## Recommended Pentest Scope

### Priority 1 — Critical paths
1. Authentication bypass (JWT forgery, type confusion, `alg:none`)
2. Tenant isolation (can analyst from tenant A read tenant B's data?)
3. Privilege escalation (analyst → admin, user → platform-admin)
4. Webhook SSRF (send HTTP requests to internal services via integration callbacks)
5. Agent token theft (can a compromised agent register as a different tenant?)

### Priority 2 — Data paths  
6. SQL injection (KQL-lite parser in `log_search_service.go`, raw query construction)
7. JSONB injection via `parsed_fields` — ensure no eval/exec paths from log data
8. File upload security (`POST /api/files`, YARA/Sigma import — ZIP bomb, path traversal)
9. Script runner (`POST /api/agents/:id/script`) — command injection on agent side

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
| 5.2.1 | Input validation on all fields | ⚠️ Partial — KQL sanitized, file upload needs review |
| 7.1.1 | Sensitive data not logged | ⚠️ Review parsed_fields for PII |
| 8.1.1 | RLS / tenant isolation | ✅ PostgreSQL RLS migration 000050 |
| 9.1.1 | TLS for all connections | ✅ configurable, enforced at ingress |
| 10.2.1 | No hardcoded credentials | ✅ all secrets via env/Vault |
| 12.1.1 | File upload size limits | ❌ not yet implemented |
