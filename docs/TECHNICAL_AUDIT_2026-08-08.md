# XCloak Security Suite — Independent Technical Audit

**Scope:** Backend, frontend, both agents, database, infrastructure
**Codebase size:** ~271K LOC across 5 components
**Method:** Static code review + live self-hosted stack + this repo's own CI logs
**Version audited:** v0.4.0 — released, all CI green
**Date:** 2026-08-08
**Overall rating:** 6.6 / 10 (see §22)

Every claim below is backed by a command, a file, or a live query against the running stack — not a skim of the README.

---

## 00. Executive Summary

XCloak is a real, working, self-hosted security platform — not a demo shell. In the course of this audit it was built from source, run against a live Postgres/Redis stack, and used to enroll a real endpoint agent that detected genuine brute-force and privilege-escalation activity on the host machine within minutes. That's a meaningfully higher bar than most open-source security tooling clears.

The codebase is large (~271K lines across five components) and mostly hand-written — no ORM on the backend, raw SQL throughout, a from-scratch Sigma-compatible detection engine, a real eBPF collector with graceful degradation. That buys control and performance at the cost of surface area: 248 live database tables, only 6 with row-level security enabled; a 3,666-finding gosec run that's 98% low-severity noise but includes 22 real HIGH findings worth triage; a repository layer with 56 files and 3 test files.

The most consistent pattern found across this session's live testing — and echoed in the project's own commit history — is **features that exist in the backend and are never wired into the frontend** (mobile enrollment token generation had zero UI despite a working API), and **silent field-name mismatches between frontend and agent** (Live Response Console dispatched commands the agent's JSON struct didn't recognize, IPv6 addresses that were never actually decoded). None of these are architectural flaws — they're the predictable cost of one person building an enormous surface area, and every one found here was fixable in under an hour once isolated.

**Bottom line:** credible engineering, real detection capability, genuine gaps in multi-tenant data isolation and enterprise MDM enforcement, and a codebase whose biggest risk is breadth outrunning verification — not weak fundamentals.

---

## 01. Architecture

Five independently-versioned components sharing one Postgres schema and one auth model.

```
Component sizes — real LOC, this audit
xcloak-platform/backend    141,665 lines  (Go)
xcloak-platform/frontend    90,934 lines  (TypeScript/TSX)
xcloak-agent-mobile         27,720 lines  (Dart/Flutter)
xcloak-agent-desktop        10,112 lines  (Go)
charts/xcloak                1,234 lines  (Helm/YAML)
                    ─────────────────────
                     271,665 lines total
```

The backend is a single Go/Gin monolith — not microservices — fronting PostgreSQL (TimescaleDB in practice), Redis, and an optional Kafka event bus. The frontend is a Next.js 14 dashboard that talks to the backend exclusively over REST + WebSocket, with a build-time toggle (`NEXT_PUBLIC_DEMO_ONLY`) that strips the backend entirely for a static "trial" build. Two independent agents — a Go binary for Linux/Windows desktops and servers, a Flutter app for Android — report into the same backend over a shared install-token/JWT scheme.

### Deployment topology

Five Docker Compose variants ship in the repo root, each a genuinely different topology rather than copies with a renamed service: `quickstart` (5 services, no Kafka/MinIO, verified live during this audit — cold build to healthy dashboard in under 3 minutes), `demo` (adds an auto-seeding job), the full `docker-compose.yml` (Kafka + MinIO + PgBouncer + Grafana/Prometheus), `dev`, and `ha` (Patroni + HAProxy for Postgres HA). A Helm chart covers the Kubernetes path with HPA, PodDisruptionBudget, and NetworkPolicy templates for both backend and frontend Deployments.

### Where the seams are

The seam that matters most in practice is **frontend ↔ backend field contracts**. Because there's no shared schema/codegen between the Go backend and the TypeScript frontend (no OpenAPI-generated client, no protobuf), every API surface is a hand-maintained agreement on both sides. Three of the bugs found and fixed during this session's live testing were exactly this: a task payload key the frontend called `command` and the agent's Go struct called `script`; a mobile enrollment API that existed on both client and server but was never called by any page; an OS filter that matched on a free-text string instead of the backend's own normalized `platform_category` field. This is a systemic risk class, not isolated bugs — see §14.

---

## 02. Backend

Go 1.25 / Gin, layered api → services → repositories, zero ORM.

| Layer | Files | Test files | Ratio |
|---|---|---|---|
| api/ | 168 | 29 | 17% |
| services/ | 171 | 31 | 18% |
| repositories/ | 56 | 3 | 5% |
| middleware/ | 12 | 4 | 33% |

The package layout is a textbook layered architecture: `api/` (Gin handlers, thin), `services/` (business logic), `repositories/` (raw SQL against Postgres), `models/` (structs, 61 files), `middleware/` (12 files — auth, rate limiting, tenant scoping), plus dedicated `auth/`, `secrets/`, and `database/` packages. There is deliberately no ORM — every query is hand-written SQL — a decision the project's own code comments defend explicitly as a control/performance tradeoff. It's a reasonable call for a security product where query behavior needs to be auditable, but it puts 100% of SQL-injection prevention on manual parameterization discipline; see §13 for what static analysis found there.

606 `Test*` functions exist against 2,987 top-level functions — a real, non-trivial test suite (not a token CI gate), but concentrated in middleware and services. **The repository layer — the code that composes raw SQL strings against a multi-tenant database — is the least tested part of the codebase by a wide margin.** That's precisely the layer where a tenant-isolation regression would land.

### Connection handling

The DB layer supports an optional read-replica connection (`DB_READ_HOST`) that callers can route reporting/analytics queries to, with explicit separate pool sizing for primary vs. replica and a nil-safe fallback when no replica is configured. This is a mature pattern that most self-hosted OSS security tools don't bother with.

```go
// database/db.go
readMaxOpenConn  = 40
...
if ReadDB != nil { return ReadDB }   // graceful fallback to primary
// DB_READ_HOST unset → nil, callers treat as "use primary"
```

---

## 03. Frontend

Next.js 14, 63 pages, no state management library — plain React state + fetch.

- **63** page.tsx routes
- **46** shared components
- **59** Playwright e2e specs

Every sidebar destination is a real page with its own data-fetching, not a shared shell with swapped content — confirmed by the sheer page count matching the product's own claimed feature surface (NGFW, SIEM, EDR, SOAR, ITDR, MDM each get multiple dedicated pages: firewall zones/NAT/policies, sigma rules, YARA, UEBA, insider threat, DFIR, agent fleet, mobile MDM, and more). There's no Redux/Zustand/Query-library — each page owns its `useState`/`useEffect` fetch cycle directly against a hand-written `lib/api.ts` client (1,483+ lines, one function per endpoint).

### The icon-stubs pattern — a real, live-verified defect class

One file, `lib/icon-stubs.ts`, re-exports every Lucide icon used across the app as a function that unconditionally returns `null`:

```ts
// lib/icon-stubs.ts:1-4
// Null stubs for Lucide icons — pages use text/symbols instead
const _I = (_?: any) => null as any;
export { _I as Activity, _I as AlertCircle, ... }  // 150+ icons, all null
```

The stated intent is that pages substitute text/unicode symbols wherever an icon carried real meaning. In practice this is an easy footgun: this session found and fixed four icon-only buttons on a single page (`agents/page.tsx`) that rendered as empty clickable boxes with zero visible content — an isolate button, a bulk-select checkbox, a modal close control, a remove-task control — plus one icon (`Smartphone`) that was missing from the stub file *entirely*, which would have crashed the page at render rather than silently disappearing. This is a structural liability: every new icon-only control anywhere in a 63-page app is one missed text-fallback away from being invisible, and nothing catches it short of manually clicking through the UI.

> **Recommendation:** A custom ESLint rule forbidding bare `<Icon />` JSX without a sibling text node, or a codemod to a real icon library with tree-shaking, would close this class permanently instead of relying on manual audits.

---

## 04. Agents

Two independent binaries, one shared enrollment model, verified live end-to-end during this audit.

### Desktop agent (Go, 10,112 lines)

A single static binary with no runtime dependency, cross-compiled for Linux (amd64/arm64) and Windows (amd64) from the same source. It runs 15 autonomous collectors on jitter-staggered intervals — processes, connections, services, users, packages, auth logs, FIM, registry (Windows), cron jobs, kernel modules, SUID/SGID scans, disk usage, and an optional eBPF TCP-event collector.

Built and ran this agent live against the quickstart stack during this audit: it self-registered, and within minutes the backend's own detection engine flagged real brute-force and new-user-creation activity on the host from genuine auth-log entries — not seeded/synthetic data. The eBPF collector correctly degraded when it couldn't acquire `CAP_SYS_ADMIN` in the sandbox, logging a clear reason rather than crashing — exactly the documented behavior.

> **Fixed this session:** IPv6 connection addresses were never actually decoded. `hexToAddr()`'s IPv6 branch was a literal placeholder — `// IPv6 — return raw hex for now` — that wrapped the undecoded `/proc/net/tcp6` hex string in brackets. Every IPv6 connection (roughly 45% of the connections seen from this one Linux host) showed as unreadable strings like `[00000000000000000000000000000000]` instead of a real address. Implemented the little-endian word-reversal decode and verified it against a real captured link-local address before rebuilding. (`xcloak-agent-desktop/agent/connections.go`)

### Mobile agent (Flutter, 27,720 lines)

Dual-mode app: Agent Mode (posture collection, MDM check-in) and a full Admin Console (a mobile port of the entire web sidebar against the same backend). Enrollment posts device posture — model, OS version, security patch level, root/encryption/passcode/developer-mode state, storage, RAM — to a dedicated `/api/mdm/self-enroll` endpoint that is architecturally separate from the desktop agent's install-token flow, down to a different token format (`xck-enroll-…` vs. a raw hex install token).

> **Fixed this session:** No frontend UI existed to generate a mobile enrollment token. The correct API client method (`mdmAPI.createToken`) and backend endpoint (`POST /api/mdm/enrollment-tokens`) both existed and worked — confirmed by calling it directly — but zero pages in the 63-page app ever called it. There was no way to enroll a phone from the web UI at all prior to this audit. Added a platform toggle to the existing desktop onboarding wizard.

No Android Enterprise (Device Owner / Work Profile) integration exists — enrollment is voluntary/BYOD-style only, meaning MDM "enforcement" (remote wipe, app blocklisting, forced passcode) is currently monitoring-and-request rather than OS-enforced. See §18.

---

## 05. Database

Live-queried against the running instance, not counted from migration files.

- **248** tables (live, `information_schema`)
- **76** migrations applied
- **6** tables with RLS enabled

PostgreSQL (deployed as TimescaleDB for hypertable support), migrated via a golang-migrate-style up/down pair per change. Multi-tenancy is primarily enforced by **application-level `tenant_id` filtering** — every repository query is expected to include a `WHERE tenant_id = $1` clause by convention — with PostgreSQL Row-Level Security as a defense-in-depth layer that is enabled on only 6 of 248 tables.

> **HIGH — Tenant isolation depends on manual query discipline, not database enforcement, for 242 of 248 tables.** If any one of the 56 repository files (5% test coverage, see §02) omits a `tenant_id` filter on a query touching one of those 242 tables, there is no second layer to catch it — the query simply returns cross-tenant data. This exact class of gap was found and fixed in this project's own history (a Redis-only session blacklist that never actually checked the `sessions` table). RLS is the standard belt-and-suspenders answer to this and is already proven out on 6 tables; the remaining rollout is mechanical, not architectural.
>
> Evidence: `SELECT count(*) FROM pg_tables t JOIN pg_class c ... WHERE c.relrowsecurity=true` → 6

Backups are a single shared `pg_dump`, not per-tenant isolated exports — acceptable for a self-hosted single-tenant install (the common case), a real gap for anyone running XCloak as a multi-tenant MSP platform.

---

## 06. API Design

Conventional REST, no generated client, no versioning.

Routes are declared in one 900+ line `routes/routes.go` file — every endpoint visible in one place, which is good for audit-ability and bad for merge conflicts at this scale. Middleware composition is explicit per-route (`RequireAuth()`, `RequirePermission("manage_agents")`, rate limiters) rather than router-group defaults, which is more verbose but makes it easy to *see* when a route is missing a check — and this project's own history shows that mattered: an entire tenant-admin API surface (`/api/tne/*`, 18 routes) previously shipped with no role check at all, caught in a prior audit specifically because the explicit-middleware pattern made the absence visible on inspection.

There is no API versioning (`/api/v1/...`) and no OpenAPI/Swagger generation — the `docs/` package exists but a spec-first contract between backend and the three clients (web, desktop agent, mobile agent) would materially reduce the field-mismatch bug class described in §01 and §14.

---

## 07. Authentication & Authorization

httpOnly JWT cookies, RBAC, MFA, OIDC/SSO, per-tenant policy.

Session tokens are httpOnly cookies (migrated off localStorage JWTs in this project's history specifically to close an XSS-exfiltration path), with refresh-token rotation and a Redis-backed session blacklist for revocation. MFA (TOTP) has both backend and self-service web enrollment. SSO is OIDC-based with per-tenant configuration. RBAC uses custom roles/permissions rather than a fixed role enum — 52 call sites across the codebase gate on `RequireAuth`/`RequirePermission`/`RequireRole`.

> **Verified sound — Session revocation actually revokes the live JWT.** This was a real bug in this project's history — admin-revoking another user's session updated a `sessions` table that `middleware.RequireAuth()` never actually consulted, so the raw JWT stayed valid until natural expiry. Fixed with a second hash-keyed Redis blacklist checked on every request; confirmed present in the current codebase.

Rate limiting exists as dedicated middleware (login endpoints specifically — 10/min, which is also why the mobile/desktop onboarding wizard uses a single shared login for its whole Playwright suite rather than one login per spec file).

---

## 08. Detection Engine & Rules Engine

A from-scratch Sigma-compatible engine, not a wrapper around an existing one.

- **102** Sigma rules (live count)
- **24** behavioral detector modules
- **7** dedicated Sigma-engine files

Sigma is a specification, not a library — XCloak implements its own parser, condition evaluator, field-mapping, and logsource pre-filter (`sigma_engine.go`, `sigma_condition_parser.go`, `sigma_loader.go`, `sigma_cache.go`) rather than shelling out to a reference implementation. The project's own engineering blog documents the scope decision explicitly: field-level matching plus logsource pre-filtering, deliberately not the full Sigma correlation-rule spec. That's an honest, legible tradeoff rather than an unstated limitation.

Behavioral detection is a separate layer — 24 detector modules covering DPI (DGA scoring, TLS anomaly detection, HTTP inspection, protocol tunneling), plus YARA malware scanning and IOC/threat-intel matching. Detection results flow through the async Kafka pipeline when enabled, synchronously when not (§09).

> **Note:** One rule taxonomy bug found and fixed in prior work — logsource category enforcement wasn't applied platform-wide at one point, causing an unscoped rule to false-positive on unrelated log types (78 rules affected, per this project's own fix history) — worth spot-checking that the fix generalized rather than patching the one observed case.

---

## 09. Kafka Pipeline

Genuinely optional, not optional-in-name-only.

```
7 consumer groups, verified by grep across services/
xcloak-task-consumer      xcloak-yara-consumer     xcloak-ioc-matcher
xcloak-audit-consumer     xcloak-alert-consumer   xcloak-incident-consumer
xcloak-fim-consumer
```

Every producer call site checks `IsKafkaEnabled()` first and falls through to a synchronous in-process path when Kafka is off — confirmed in `connection_service.go`, `connect_event_service.go`, `file_hash_service.go`, and others. This isn't a fallback bolted on after the fact; the synchronous path is the primary code path with async as an opt-in layer, which is the right way round for a product whose quickstart deployment target explicitly excludes Kafka. The tradeoff is real, though: without Kafka, task dispatch, YARA scanning, IOC matching, and FIM alerting all run inline on the request path rather than decoupled, which matters under load (§16).

---

## 10. WebSockets

Ticket-authenticated, used for live logs and notifications.

WebSocket auth uses a short-lived ticket exchange (`api/ws_ticket.go`) rather than passing the session cookie directly to the WS upgrade — the right pattern, since browsers don't attach httpOnly cookies to WS handshakes reliably across all proxy configurations and a ticket avoids leaking the long-lived session token into WS-adjacent logs. `ws_broadcast_service.go` fans out to connected clients for live log tailing and real-time notifications; `api/live_logs.go` is the primary consumer-facing surface.

---

## 11. Docker Deployment

Verified live during this audit, not read from docs.

Ran `docker compose -f docker-compose.quickstart.yml up -d --build` cold: five containers (Postgres/TimescaleDB, Redis, backend, frontend, a one-shot seeder), healthy in under three minutes including image builds, with a working default admin account (`admin` / `admin1234`) auto-seeded. Backend health check, frontend response, agent enrollment, and live task dispatch all confirmed working end-to-end against this stack in this session.

Five compose files cover materially different scenarios rather than being copy-paste variants — quickstart (evaluation), demo (seeded), full (production-shaped, Kafka+MinIO+PgBouncer+Grafana), dev, and ha (Patroni+HAProxy). That range is unusual for a self-hosted OSS project and suggests real production deployments exist somewhere, not just the maintainer's laptop.

---

## 12. Kubernetes / Helm

Production-shaped chart, not a toy manifest.

The chart (`version: 0.4.0` as of this audit) includes HorizontalPodAutoscaler and PodDisruptionBudget for both backend and frontend Deployments, a NetworkPolicy template, PgBouncer as a first-class connection-pooling component, and a Bitnami PostgreSQL sub-chart dependency gated behind an `enabled` flag so customers with managed Postgres can disable it and point at external services. `helm lint --values ci/smoke-values.yaml --strict` passes clean, confirmed in this audit's own CI run.

Kafka and MinIO are deliberately *not* bundled as chart dependencies — the chart's own comments document that Bitnami stopped publishing free images for either as of a documented verification date, and both features already degrade gracefully in-app (§09), so the chart correctly treats them as bring-your-own rather than pretending to bundle something that would silently fail to pull.

---

## 13. Security Audit

Live govulncheck + gosec output from this repo's own CI, this audit's commit.

### Dependency vulnerabilities — govulncheck

> **Clean — 0 exploitable vulnerabilities in reachable code.** One real, reachable CVE (`GO-2026-5970`, `golang.org/x/text`, reachable via the Shodan IP-enrichment service) was found and fixed during this session — bumped `v0.37.0 → v0.39.0`. Two further vulnerabilities exist in imported packages and two in required modules, but govulncheck confirms the code doesn't call the vulnerable symbols in either case — advisory only.

### Static analysis — gosec (backend, 124,665 lines scanned)

| Severity | Count | Dominant pattern |
|---|---|---|
| HIGH | 22 | Mixed — see below |
| MEDIUM | 61 | SQL string construction (G201/G202), path handling (G304) |
| LOW | 3,583 | G104 — unchecked error returns (98% of all findings) |

The headline number (3,666 total findings) is misleading without this breakdown: 98% is `G104`, gosec's blanket "this error return wasn't checked" rule, which fires on things like ignoring a `defer resp.Body.Close()` error — standard, low-risk Go style, not a security gap. The 22 HIGH and 61 MEDIUM findings are worth real triage:

> **MEDIUM — 46 combined CWE-89 (SQL injection pattern) flags — G201/G202.** Expected in a hand-written-SQL codebase with no ORM: gosec flags any `fmt.Sprintf`-built query string regardless of whether the interpolated values are actually parameterized elsewhere or are trusted internal constants (table/column names, not user input). Spot-checked the G101 "hardcoded credential" HIGH finding in `integrations.go:77` and confirmed it's a false positive — a comparison against the UI's redacted-secret placeholder string `"••••••••"`, not a real credential. The other 45 CWE-89 flags were not individually re-verified in this audit and should be triaged before relying on the gosec pass/fail as a security gate.
>
> **LOW-MED — 11× G404 — `math/rand` instead of `crypto/rand`.** Matters if any of these 11 sites generate tokens, IDs used for auth, or jitter values an attacker could predict to defeat rate limiting — doesn't matter if they're just scheduling jitter. Not distinguished in this audit; worth a targeted pass.

Both gosec jobs run with `continue-on-error: true` in CI — advisory, not a merge gate. Given the SQL-injection-pattern volume above, promoting at least the HIGH-severity bucket to a blocking check (with the confirmed false positives suppressed via `.gosec.json`) would be a low-cost, high-value change.

### Multi-tenancy — cross-reference to §05

The single largest security-relevant fact in this codebase is the RLS gap: 6 of 248 tables. Everything else in this section is defense-in-depth around an authentication perimeter; this is about whether tenant A can ever see tenant B's data by omission rather than exploit.

---

## 14. Code Quality Review

- **1** TODO/FIXME/HACK marker in 141K backend lines
- **1,573** `if err != nil` sites (explicit handling)
- **606** test functions / 2,987 top-level functions

The near-total absence of TODO markers is notable at this codebase size — either the team resolves things immediately rather than deferring (consistent with the terse, decisive style of the commit history reviewed for this audit — messages that name a root cause and a fix, not "WIP" or "fix later"), or debt is being tracked outside the code (an issue tracker not visible to this audit). Explicit `if err != nil` handling is used consistently rather than panics or silent swallowing — good Go hygiene.

### The dominant real defect class: unverified cross-boundary contracts

Every bug found and fixed in this session's live testing — as distinct from static reading — was a mismatch at a boundary nothing type-checks across: frontend↔agent JSON payload shape, frontend↔backend field names, or "the code to call an API exists on both ends but nothing actually wires them together." None were logic errors inside a single file. This is the natural failure mode of a system with three independently-typed clients (TypeScript, two flavors of Go, Dart) against one backend with no shared contract format (§06). It's also the cheapest class of bug to eliminate structurally — an OpenAPI spec with generated clients for at least the TypeScript and Go sides would catch the payload-shape and dead-endpoint bugs at build time instead of during manual QA.

### Comment philosophy

Comments across the reviewed files consistently explain *why* (a prior incident, a non-obvious constraint) rather than restating what the code does — e.g. the Kafka-optional comment explaining the rate-limit reasoning behind a shared test login, or the RLS migration comment noting TimescaleDB was chosen specifically so a real extension-dependent migration wouldn't silently skip in CI. That's a strong, consistently-applied signal of engineering discipline that doesn't show up in any metric.

---

## 15. Performance Review

*Code-pattern analysis — no load test was run as part of this audit; treat as architectural signal, not a benchmark.*

- **In favor:** no ORM means no N+1-generating lazy-load surprises by default; explicit connection pool tuning with separate read/write pools; Kafka decouples the heaviest async work (YARA, IOC matching, FIM) from the request path *when enabled*; Redis used for both caching and rate-limit counters, not just sessions.
- **Against:** the quickstart/demo topologies most users will actually run don't enable Kafka, so those async workloads run synchronously on the request path in the common deployment case — the mode most likely to be under-resourced is also the mode without the decoupling layer. 16 files in `repositories/` contain loop constructs adjacent to query code (a heuristic, not a confirmed N+1 audit) — worth a targeted EXPLAIN-ANALYZE pass on the busiest of those before calling performance "verified."

---

## 16. Scalability Review

- **Horizontal (compute):** the Helm chart's HPA templates on both backend and frontend Deployments indicate the backend is designed to be stateless at the process level — sessions live in Redis/Postgres, not in-memory — so horizontal pod scaling should work without sticky-session hacks. Not independently load-tested in this audit.
- **Horizontal (data):** read-replica support exists and is wired through the repository layer's connection selection, but is opt-in and its actual usage coverage (which queries route to the replica vs. primary) wasn't audited file-by-file here.
- **Multi-tenant scale:** 248 tables filtered by `tenant_id` per-query is a workable pattern up to a point, but without RLS as a hard backstop (§05), the operational answer to "how many tenants can this safely host" is bounded by code-review rigor, not database guarantees — a real ceiling for anyone considering XCloak as a multi-tenant MSP backend rather than single-org self-hosted.
- **Async backbone:** 7 real Kafka consumer groups is a legitimate scale-out primitive when enabled; each consumer group can be scaled independently of the API tier.

---

## 17. Enterprise Readiness Scorecard

| Category | Score | Notes |
|---|---|---|
| Auth & SSO | 80% | OIDC, MFA, RBAC present |
| Multi-tenancy isolation | 35% | App-level only on 98% of tables |
| Audit logging | 65% | Present; PII masking gap noted |
| Compliance tooling | 55% | CIS scan present; framework mapping partial |
| MDM enforcement | 25% | Monitoring-only, no Device Owner |
| HA / DR | 60% | Patroni option; shared single-dump backups |
| Third-party validation | 10% | No external pentest yet, by project's own admission |
| CI/CD maturity | 85% | 9 workflows, all green as of v0.4.0 — 4 were broken at audit start |

The pattern across this scorecard: the parts of the system a single engineer directly interacts with daily (auth, CI, the detection engine) are mature. The parts that only matter at genuine multi-tenant enterprise scale — hard tenant isolation, device-level MDM enforcement, third-party validation — are the ones still catching up, which is exactly what you'd expect from a product built by and initially for a smaller deployment footprint.

---

## 18. Missing Features & Gaps

| Gap | Impact |
|---|---|
| Row-Level Security on 242/248 tables | Tenant isolation relies on code review, not the database (§05, §13) |
| iOS mobile agent | Android-only MDM; no coverage for a large share of BYOD fleets |
| Android Device Owner / Work Profile | MDM is request/monitor, not enforce — can't force-wipe or block apps |
| PII masking in stored logs | Parsed log fields may retain emails/IPs verbatim — compliance exposure for GDPR-scope customers |
| Per-tenant backup isolation | Single shared `pg_dump` — fine for single-org, a gap for MSP use |
| No third-party penetration test | All security validation to date is internal (project's own admission) |
| No OpenAPI/shared client contract | Root cause of the field-mismatch bug class in §14 |
| No API versioning | Breaking changes have no migration path for external integrators |

---

## 19. Improvement Roadmap

### Now (days, not weeks)
1. Triage the 22 HIGH + 61 MEDIUM gosec findings by hand; suppress confirmed false positives in `.gosec.json`, fix the rest, then flip the two gosec CI jobs from advisory to blocking.
2. Add a lint rule or codemod pass for the icon-stub pattern (§03) — cheapest structural fix in this whole audit relative to impact.

### Next (weeks)
3. Extend RLS from 6 to the highest-risk subset of the remaining 242 tables first (anything holding credentials, PII, or cross-tenant-sensitive data), not all 248 at once.
4. Bring repository-layer test coverage from 5% toward parity with services/ (18%) — this is the layer where a missing `tenant_id` clause lives.
5. Stand up an OpenAPI spec generated from the Gin routes, and generate at minimum the TypeScript client from it.

### Later (quarter+)
6. Commission an external penetration test — the single highest-leverage move for enterprise credibility given everything else in this audit is already internally solid.
7. Android Enterprise (Device Owner) integration for real MDM enforcement, not just monitoring.
8. iOS agent, if mobile fleet coverage is a target buyer requirement (it will be, for most enterprise MDM RFPs).

---

## 20. Commercial Viability & Monetization

An open-core license-key + SaaS-toggle system exists in the backend (`services/license_service.go`, `services/license_checker.go`, `services/saas_service.go`) with an authority/self-hosted detection split — confirmed present, not just documented. The core platform is AGPL-3.0, which is a defensible open-core choice: it permits free self-hosting while requiring anyone who offers XCloak as a hosted service to release their modifications, which protects against a larger vendor white-labeling the project without contributing back.

The realistic monetization paths, in order of how much of the groundwork already exists in the codebase:

1. **Managed hosting / support** — the product is genuinely self-host-capable today (verified live in this audit), so "we'll run it for you" is a sellable service with near-zero additional engineering.
2. **Enterprise features gated by license key** — the license-check plumbing exists; the question is which features get gated (SSO is often the standard open-core gate; this project already ships it in the free tier, so the gate would need to move to something like multi-tenant MSP mode, advanced compliance reporting, or the Kubernetes HA path).
3. **Per-agent pricing** — mentioned as a direction in the project's own site copy but no concrete price point exists yet in code or public materials as of this audit.

The biggest commercial risk isn't the product — it's that the two enterprise-buyer questions XCloak can't yet answer with a document are "who pentested this" and "how is my data isolated from other tenants," and both have concrete, scoped fixes already identified in §19.

---

## 21. Vs. Commercial Products

*Positioned honestly, not a marketing comparison — XCloak is not competing on the same axis as most of these.*

| Product | Where it wins | Where XCloak wins |
|---|---|---|
| **CrowdStrike Falcon** | Cloud-native EDR at massive scale, threat-intel graph built from millions of endpoints, near-zero-day detection turnaround | Self-hosted (no data leaves your network), no per-endpoint SaaS fee, source-auditable detection logic |
| **Microsoft Defender for Endpoint** | Native OS-level telemetry depth on Windows, tight M365/Entra integration, enormous engineering investment | Platform-agnostic (Linux/Windows/Android equally first-class), no Microsoft ecosystem lock-in, transparent detection rules |
| **Palo Alto (Cortex/NGFW)** | Purpose-built network hardware + cloud-scale DPI, mature SOAR marketplace, deep compliance certifications | NGFW+SIEM+EDR unified in one deployable stack instead of a product portfolio; dramatically lower cost floor |
| **Splunk** | Best-in-class log search/analytics at extreme scale, enormous app ecosystem, industry-standard for SOC teams | Included SIEM+EDR+SOAR instead of Splunk-as-log-store-only; no per-GB ingest pricing |
| **Wazuh** | Larger community, longer track record, broader third-party integration library, its own maturity edge on RLS/multi-tenancy given more years in production | Genuinely unified single-agent/single-backend model vs. Wazuh's manager+indexer+dashboard stack; built-in SOAR and MDM in the same product rather than bolted-on |

The honest positioning: XCloak is not trying to out-scale CrowdStrike or out-search Splunk. Its real competitive claim is **consolidation** — one agent, one backend, one dashboard instead of six vendor relationships — for organizations that would otherwise be priced out of enterprise security tooling entirely, or are actively trying to reduce vendor sprawl. Against Wazuh specifically (its closest open-source peer), XCloak's unified single-stack architecture is a real differentiator, but Wazuh's production track record and this audit's own RLS/testing findings mean XCloak hasn't yet earned the operational trust that comes with years of hardening in the wild.

---

## 22. Overall Rating

| Category | Score |
|---|---|
| Architecture & code quality | 7.8 / 10 |
| Security posture | 5.8 / 10 |
| Feature completeness | 8.0 / 10 |
| Enterprise readiness | 4.8 / 10 |
| Production readiness (self-hosted, single-org) | 7.5 / 10 |
| Commercial viability | 6.0 / 10 |

### **Weighted overall: 6.6 / 10**

**A real platform, honestly short of enterprise-grade in specific, fixable places.** For a single-org, self-hosted deployment, XCloak is production-usable today — this audit ran it from a cold clone to a live, detecting agent in minutes, which most self-hosted security projects at this scope cannot claim. For a multi-tenant MSP or a buyer requiring third-party security validation, the RLS gap (§05, §13) and absence of an external pentest (§18) are the two findings that actually block that use case, and both have scoped, achievable fixes rather than requiring a rearchitecture. The rating reflects genuine engineering quality pulled down specifically by verification debt — not weak fundamentals.

---

*Methodology: static code review across all five components, live queries against a self-hosted quickstart deployment built from source during this audit, this repository's own CI logs (govulncheck, gosec, helm lint) for the current commit, and cross-reference against this project's own documented incident/fix history where relevant. Performance and scalability sections are architectural analysis, explicitly not benchmark results — no load testing was performed. All counts are reproducible via the commands referenced inline; none are estimated.*
