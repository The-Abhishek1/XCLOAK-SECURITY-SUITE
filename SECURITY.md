# Security Policy

**[xcloak.tech](https://xcloak.tech)** · [docs.xcloak.tech](https://docs.xcloak.tech) · [GitHub](https://github.com/The-Abhishek1/XCLOAK-SECURITY-SUITE)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x (latest) | ✅ |
| 0.1.x | ⚠️ Security fixes only |
| < 0.1 | ❌ |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: **abhishekn1003@gmail.com**  
Subject line: `[XCloak Security] <brief description>`

Include:
- Component affected (backend, Go agent, mobile agent, Helm chart)
- Steps to reproduce
- Severity assessment (CVSS score if possible)
- Proof-of-concept (if available — please do not deploy exploits against systems you don't own)

**Response SLA:**
- Acknowledgement: within 48 hours
- Triage and severity assessment: within 5 business days
- Fix timeline communicated: within 10 business days

We credit reporters in the release notes unless you prefer to remain anonymous.

---

## Threat Model

### Trust Boundaries

```
[Internet / Untrusted]
        │
        ▼
[Ingress / TLS termination]
        │
        ▼
[Backend API — Port 8080]          ← Primary attack surface
        │
   ┌────┴────┐
   ▼         ▼
[PostgreSQL] [Redis]               ← Internal-only; never exposed to the internet
        │
   ┌────┴────┐
   ▼         ▼
[Kafka]  [MinIO]                   ← Internal-only; BYO in production

[Go Agent] → [Backend API]         ← Agent token auth (bearer), separate from user tokens
[Mobile Agent] → [Backend API]     ← Agent token auth; MDM endpoints scoped separately
```

### Assets

| Asset | Sensitivity | Protection |
|-------|-------------|------------|
| JWT secret | Critical | Env var / Vault; never logged |
| User passwords | Critical | bcrypt (cost 14); never stored plaintext |
| Agent tokens | High | SHA-256 hashed in DB; rotatable via API |
| Audit logs | High | MinIO Object Lock (WORM) — can't be deleted even by admin |
| Tenant data (alerts, rules, logs) | High | PostgreSQL Row-Level Security (RLS) per tenant |
| Admin API keys | High | SHA-256 hashed, `xck_` prefix for log detection |
| TOTP secrets | High | HashiCorp Vault transit encryption at rest |

### Attack Scenarios Considered

| Scenario | Mitigation |
|----------|------------|
| Credential stuffing on `/api/auth/login` | Per-username 5-failure/15-min lockout + per-IP rate limit (10 req/min) |
| JWT forgery / algorithm confusion | HMAC-SHA256 only; `alg:none` rejected; `type` claim validated to prevent access↔refresh swap |
| Cross-tenant data access | PostgreSQL RLS enforced on every query via `xcloak_app` role; `SET LOCAL app.tenant_id` per transaction |
| Privilege escalation (analyst → admin) | `RequireRole()` middleware on every admin route; JWT role claim read-only after issue |
| SSRF via webhook/integration callbacks | All outbound URLs validated against RFC 3986; private/loopback ranges blocked |
| SQL injection via KQL search | Field names gated by `isSafeFieldName()` regex `[a-zA-Z0-9_]{1,60}`; all values parameterized |
| Agent token theft | Short-lived tokens; `/rotate-token` endpoint; audit-logged rotations |
| Replay attacks via WebSocket | Short-lived WS ticket (30s TTL); consumed on use |
| Session fixation | New session ID on every login; old refresh token revoked on rotation |
| Syslog injection (log forging) | Log lines parsed and stored as structured data; no shell interpolation |
| Rate-limit race condition | Atomic Lua script in Redis (ZREMRANGEBYSCORE + ZCARD + ZADD in one EVAL) |
| Rooted Android device | Detected heuristically; posture score penalised; operator alerted via MDM |

### Known Limitations (Be Transparent)

- **PII in logs** — `parsed_fields` may contain email addresses, usernames, IPs from raw log lines. No automatic masking. Operators should define a data-handling policy and potentially add a log sanitisation middleware before ingestion.
- **No certificate pinning** on the Go agent or mobile agent in the default build. Custom builds can embed a public key via ldflags.
- **Single-process consumers** — Kafka consumer goroutines run in the same process as the API server. A consumer panic is recovered and logged, but a severe OOM will affect both layers simultaneously.
- **Screen lock detection** on mobile requires Device Owner / DPC profile. In BYOD mode, `has_passcode` is always `null`.
- **eBPF TCP events** require Linux kernel 5.8+ and CAP_BPF. The feature degrades gracefully on older kernels (skipped with a log warning).

---

## Audit Status

| Phase | Date | Scope | Outcome |
|-------|------|-------|---------|
| Internal — Auth & Session | 2026-07-01 | JWT, refresh tokens, 2FA, rate limiting | All critical issues resolved (see `docs/security-audit-prep.md` Phase 1–5) |
| Internal — Injection & Authorization | 2026-07-02 | KQL injection, JSONB, RLS enforcement, RBAC | All critical issues resolved |
| Internal — Agent security | 2026-07-04 | Go agent token handling, FIM auto-quarantine, task approval flow | All critical issues resolved |
| Internal — Backend hardening | 2026-07-07 | Kafka consumer panics, webhook retry, Prometheus metrics, slog migration | All issues resolved |
| Internal — Mobile agent | 2026-07-07 | Android posture collection, MDM commands, retry backoff, credential storage | All issues resolved |
| **Third-party pentest** | Planned | Full platform | Not yet scheduled — see `docs/security-audit-prep.md` for scope |

---

## Disclosure Policy

Full security documentation is available at [docs.xcloak.tech](https://docs.xcloak.tech).

XCloak follows **coordinated disclosure**:

1. Reporter contacts us privately
2. We confirm the vulnerability and agree on a timeline
3. We develop and test a fix
4. Reporter reviews the fix (optional)
5. We release the fix and publish a CVE if warranted
6. Reporter is credited in the release notes

We aim to release security patches within **30 days** of a confirmed critical vulnerability. Critical CVEs with active exploitation may be patched faster on an emergency timeline.
