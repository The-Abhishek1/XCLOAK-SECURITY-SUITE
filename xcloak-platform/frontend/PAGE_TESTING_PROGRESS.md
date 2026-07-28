# Page-by-Page Testing Progress

Tracks the live-stack Playwright testing phase (started 2026-07-27): one sidebar
page at a time — audit frontend + backend for hardcoded/fabricated/dead data
and broken routes, fix real bugs found, write `tests/e2e/<page>.spec.ts`
against the real backend + seeded DB, verify `go build`/`go vet`/`go test` +
`tsc`/`lint`, run the full accumulated suite, update this file and the
project memory (`project_page_testing_phase.md`).

**How to use this file**: read it at the start of a session to see what's
next; update the relevant checklist line(s) at the end of every page (move
from ⬜ to ✅ with a one-line summary + spec file name). Full detail for each
page lives in memory (`project_page_testing_phase.md`), not here — this file
is just the index/checklist.

Full suite status as of last page (Live Logs): **139/142 passing** (3
pre-existing/narrow flakes unrelated to Live Logs's own changes — the
Network Map canvas-click timing race, the agents.spec.ts/agents-onwards.spec.ts
cross-spec agent-count race, and an Insider Threat force-logout toast timing
flake under heavy parallel load — all reproduce clean standalone).

---

## ✅ Completed (16)

1. **Dashboard** (`/dashboard`) — `dashboard.spec.ts`. Fabricated compliance %, broken SQL (nonexistent `compliance_reports.framework`/`.details` columns).
2. **Agents** (`/agents`) — `agents.spec.ts`. Dead `is_isolated`/`tamper_protection` fields fixed; removed a duplicate in-page "Enroll Agent" onboarding modal in favor of the more complete `/agents/onwards` wizard. **Agent Detail (`/agents/:id`) has 2 known deferred bugs** — start there when it comes up (see memory).
3. **Alerts** (`/alerts`) — `alerts.spec.ts`. Removed a huge fake-investigation drawer (fake scores/identities/fake action buttons), fixed a stale-closure bug + a race condition. **Revisited during Correlation work**: found/fixed a severe bug where `GetAlertsPaginated` (and 4 sibling queries) silently dropped real alerts with NULL `agent_id`/MITRE fields from results while still counting them in `total`.
4. **Incidents** (`/incidents`) — `incidents.spec.ts`. Fake MTTC, a broken MTTR query (wrong column), fake SLA sub-milestones.
5. **UEBA** (`/ueba`) — `ueba.spec.ts`. 7 of 8 response actions were fully fake (canned success, no real effect); 5 components of dead detection UI removed. Session-revocation isn't actually enforced anywhere (flagged for Settings).
6. **Insider Threat** (`/insider-threat`) — `insider-threat.spec.ts`. Same fake-action bug as UEBA (copy-pasted code) + a demo-seeder contributor-key mismatch.
7. **NBA / Net Behavior** (`/nba`) — `nba.spec.ts`. 3/9 response actions rewired to real dispatch; fake domain-IOC cross-join in threat-intel; seed `anomaly_type` mismatch hid real data; a cross-page `firewall_rules` COALESCE bug; a window-selector race condition.
8. **DPI / Deep Inspection** (`/dpi`) — `dpi.spec.ts`. Built out a full 14-tab dashboard (12 real backend endpoints had zero UI). Found wrong-schema bugs in `iocs`/`ja3_fingerprints`/`incidents`/`alerts` that also affected NBA's already-"fixed" response actions — verify persistence with a live DB query, not just by reading the SQL.
9. **Behavioral / Threat Detection** (`/threat-detection`) — `threat-detection.spec.ts`. Nonexistent `ioc_blocks` table (again), a literal hardcoded `"triggered": 0`, `yara_matches` wrong-column bug in 3 places, IOC tab's `value`/`indicator` field mismatch, a misleading-affordance Library tab. Found+fixed a non-idempotent `cmd/seed/rules` duplicate-rule bug.
10. **Correlation** (`/correlation`) — `correlation.spec.ts`. Cleanest page yet. Simulation tab was permanently inert (wrong columns + zero seed data); "IOC/YARA match always creates an incident" was only true for 2 of 6 real rule-name variants. **Also fixed cross-cutting infra**: replaced per-file logins with a single shared `global-setup.ts`; found/fixed the Alerts pagination bug (see #3); found (but did not fully fix — flagged for later) an Alert Clusters `source_ip`-doesn't-exist bug in `cluster_enterprise.go`.
11. **Network Map** (`/network-map`) — `network-map.spec.ts`. A genuinely sophisticated real topology/enrichment engine underneath (real node/edge construction, real hostname/OS-based type inference, real CIDR cloud-IP detection, real IOC + ip-api.com threat intel). Bugs found: `alertCountsByAgent` queried nonexistent `alerts.acknowledged` instead of `status='open'`, silently zeroing every node's alert count and the "alerting_nodes" summary; the color/type Legend statically listed all 21 `INFRA_FILL` entries but the backend can only ever produce 9, so it implied detection of 12 fictional infra types (Kubernetes, Hypervisor, OT/ICS, etc.) — trimmed to the real 7 non-agent/non-external_ip types; the node detail drawer's Actions tab was the same 100%-fake-button pattern as UEBA/Insider Threat (11 buttons, zero API calls) — rewired the real subset (isolate_host/vulnerability_scan/collect_processes/collect_auth_logs task dispatch, plus block_ip/create_incident/add-to-IOC via the shared response-action dispatcher) and removed buttons with no real backend capability anywhere (Ping, Port Scan, Restart Agent — executor has no case for it, Whois Lookup); also removed the Actions tab for infra-type nodes (no agent_id to act on) and external_ip's dead "Traffic" tab (never showed distinct content).
12. **Attack Paths** (`/attack-path`) — `attack-path.spec.ts`. Another genuinely strong real engine (real Dijkstra shortest-compromise-path, real BFS blast radius, real MITRE technique mapping, real chokepoint detection). Bugs found: PATH_TYPE_TABS had 6 filter tabs (Cloud/Container/Identity/VPN/Hybrid/SaaS) that could never match a real path (backend's PathType is hard-limited to lateral/priv_esc) — always rendered "No paths match this filter"; the kill-chain model selector's Lockheed/Diamond options never highlighted anything (phase IDs never matched real backend values) and even the MITRE list itself had 3 dead phases + was missing the real "exploitation" phase — rebuilt to the 7 real phases, removed Lockheed/Diamond; the node detail drawer's Actions tab was the same 100%-fake-button pattern (10 buttons) — rewired 3 real ones (isolate_host/vulnerability_scan task dispatch, create_incident via the shared dispatcher), removed the rest, and hid Actions entirely for the internet node; removed a fully-fabricated "Est. impact ₹X.XM" business-impact figure with zero real backing data. **Also fixed a masked backend bug**: `CalculateRiskScore` had no upper-bound clamp (routinely exceeded 100 given this tenant's alert volume) — invisible until now because `asset_risk_scores` had zero rows for the demo tenant (no seeder ever populated it); added `seedRiskScores` to `cmd/seed/demo/main.go` and fixed the clamp, giving this page's central per-node metric real data for the first time.
13. **Risk Posture** (`/risk-posture`) — `risk-posture.spec.ts`. Mostly careful, honest backend code (explicit "don't fabricate a mapping that doesn't exist" comments throughout) undermined by one real backend bug and three frontend fabrications. **Backend**: `RefreshVulnPriorityScores` joined a nonexistent `agents.risk_score` column (real scores live in `asset_risk_scores`) — broke on every call (startup + every 6h tick, every tenant) since this scheduler's introduction, silently zeroing `priority_score` everywhere and permanently capping Risk Posture's VulnScore at 0/30. Fixed the join + added error logging. **Frontend**: the Compliance card invented its own CIS/NIST/ISO/SOC2 percentages (arbitrary decimal scaling + hardcoded fake control counts) instead of using the real `/api/compliance/scores/latest` endpoint the Dashboard already correctly uses — wired it in; a fabricated "Estimated Financial Exposure ₹X Cr/L" figure (same arbitrary-multiplier pattern as Attack Paths' "Est. impact") — removed; the Remediation Queue's status badge unconditionally claimed 'in_progress'/'blocked' for specific categories regardless of real state — normalized to the only honest value, 'open'; AI Recommendation buttons had no onClick/href at all (dead-end affordance) — wired 4 of 5 to real destination pages.
14. **Deploy Agent** (`/agents/onwards`) — `agents-onwards.spec.ts`. A small, mostly well-built onboarding wizard — backend token generation/redemption (`api/integrations.go` + `api/agents.go`'s `RegisterAgent`) is real and correctly built: single-use via an atomic `UPDATE ... WHERE used=false ... RETURNING`, tenant-scoped, expires via a genuine 24h DB column default. One real bug: Step 4's `checkForAgent` had `if (recent || agents.length > 0) setFound(true)` — the `|| agents.length > 0` fallback made the "did MY new agent register" check meaningless for any tenant with pre-existing agents (essentially all of them, including this demo tenant's 4 seeded agents), so clicking "Check Now" unconditionally showed "Agent detected!" on the very first click regardless of whether the just-onboarded agent ever actually ran. Fixed by removing the fallback.
15. **Timeline** (`/timeline`) — `timeline.spec.ts`. Arrived mostly already fixed from an earlier untracked pass (`timeline_service.go`'s SQL already COALESCEs every nullable column; the right-click "Filter by Host" menu item, previously a literal no-op, was already wired up — both verified live, not assumed from comments). Two new bugs found: selecting a specific agent routed through a separate `/agents/:id/timeline` endpoint that ignores severity/category/search/time-range filters entirely, silently dropping them while the toolbar kept showing them as active — fixed by routing agent selection through the general `/api/timeline` endpoint's existing `agent_id` param instead; and the evidence panel's Bookmark/Copy-JSON buttons plus the toolbar's Bookmarks-filter toggle were icon-only with the app's null-stubbed icon library, making two of them literally zero-size and unclickable (the same "icon-stubs null fallout" bug class fixed on 16 other files in an earlier pass, missed here) — fixed with the established symbol/text vocabulary.
16. **Live Logs** (`/live-logs`) — `live-logs.spec.ts`. Core streaming is real and solid: `/api/ws/ticket` + `LiveLogsWS` genuinely stream real `endpoint_logs` rows over a real WebSocket, and AI Explain/Summarize genuinely call the LLM. The `'demo-ws-ticket-noop'` fallback is not a bug — it's the frontend's separate, documented no-backend "static-demo" mode, confirmed the real backend never returns that value. Everything *around* that real core was dead analyst-workflow chrome: right-click "Create IOC"/"Create Alert Rule" and the 4-button "Analyst Actions" grid were pure no-ops with no onClick at all — wired "Create IOC" to the real `iocsAPI.create` (verified via curl: persists correctly), gave "Create Alert Rule" an honest coming-soon toast, and pointed the 4 grid buttons at their real destination pages (/sigma-rules, /hunt-workbench, /cases, /dfir). The Analyst Note textarea silently discarded whatever was typed the instant a different log was selected (state was keyed only to the open log, never lifted); made it session-scoped per log id. The Tags input+button had no onClick and no path back to parent state at all — broken end-to-end with no backend column to save to either — removed. Three static "AI" suggestion rows had no onClick; two now call the real Explain/Summarize handlers just above them, the third links to Sigma Rules. The "Columns" button in Table view was a literal `onClick={() => {}}` despite the column-visibility state already being fully wired through `TableView` — added the missing checkbox popover. **Deferred, cross-cutting finding, not fixed**: every seeded `endpoint_logs` row in this tenant has `parsed_fields = '{}'` — meaning the field-based search mode, field filters, FieldChips, and several real backend detectors that key off `parsed_fields->>'event_id'` etc. (`persistence_detector.go`, `behavioral_baseline_service.go`, and more) have never been exercised against real seed data in this demo tenant. This is a demo-seeder completeness gap spanning multiple detection services, not specific to this page — flagged for its own dedicated pass rather than attempted here.

---

## ⬜ Remaining (40), in sidebar order
- [ ] Log Search (`/log-search`)
- [ ] Log Search (`/log-search`)
- [ ] ES Query (`/elastic-query`)
- [ ] Log Sources (`/log-sources`)
- [ ] Alert Clusters (`/clusters`) — start from the known `source_ip` column bug in `cluster_enterprise.go` (see memory)
- [ ] Threat Intel (`/threat-intel`)
- [ ] Threat Actors (`/threat-actors`)
- [ ] Sigma Rules (`/sigma-rules`)
- [ ] YARA Rules (`/yara-rules`)
- [ ] JA3 Fingerprints (`/ja3-fingerprints`)
- [ ] Hunt Workbench (`/hunt-workbench`)
- [ ] Threat Hunt (`/hunt`)
- [ ] DFIR (`/dfir`)
- [ ] Deception (`/deception`)
- [ ] Cloud Security (`/cloud-security`)
- [ ] Email Security (`/email-security`)
- [ ] Containers / K8s (`/container-security`)
- [ ] AD Attacks (`/ad-attacks`)
- [ ] Supply Chain (`/supply-chain`)
- [ ] OT / ICS (`/ot-ics`)
- [ ] Process Injection (`/process-injection`)
- [ ] Defense Evasion (`/defense-evasion`)
- [ ] Cases (`/cases`)
- [ ] Playbooks (`/playbooks`)
- [ ] Approval Queue (`/soar-approvals`)
- [ ] Vulnerabilities (`/vulnerabilities`)
- [ ] Vuln Queue (`/vuln-queue`)
- [ ] Suppression (`/suppression`)
- [ ] Quarantine (`/quarantine`)
- [ ] Script Runner (`/script-runner`)
- [ ] Scheduled Tasks (`/scheduled-tasks`)
- [ ] Firewall (`/firewall`)
- [ ] Reports (`/compliance`)
- [ ] Frameworks (`/framework-compliance`)
- [ ] Executive (`/executive`)
- [ ] SOC Metrics (`/soc-metrics`)
- [ ] Assets / CMDB (`/assets`)
- [ ] Mobile / MDM (`/mdm`)
- [ ] AI Assistant (`/ai-assistant`)
- [ ] Settings (`/settings`) — start from the session-revocation-enforcement gap flagged during UEBA/Insider Threat
- [ ] Tenants (`/platform`, platform-admin only)
