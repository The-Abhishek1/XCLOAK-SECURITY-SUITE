# XCloak Roadmap

**[xcloak.tech](https://xcloak.tech)** · [docs.xcloak.tech](https://docs.xcloak.tech) · [blog.xcloak.tech](https://blog.xcloak.tech)

This is a living document. Items are not promises — they represent current priorities and intentions. As a solo-maintained project, timelines shift.

---

## Status Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Done — shipped in current release |
| 🔄 | In progress |
| 📋 | Planned — next milestone |
| 💡 | Idea — not yet committed |

---

## Shipped

**v0.4.0 — August 2026**
✅ 4 GitHub Actions workflows fixed (a job-level `if:` bug that broke every push and every prior release; missing test services; CI scoped to the right test suite)
✅ Helm chart published to GitHub Pages — `helm repo add xcloak https://the-abhishek1.github.io/XCLOAK-SECURITY-SUITE`
✅ GitHub Release binaries — Linux/Windows agent binaries + Android APK attached to the release tag
✅ Mobile enrollment token generation wired into the Deploy Agent UI (API existed, no page ever called it)
✅ Real IPv6 connection decoding in the desktop agent (was a raw-hex stub)
✅ `golang.org/x/text` CVE fix (GO-2026-5970)
✅ Independent technical audit published ([docs/TECHNICAL_AUDIT_2026-08-08.md](docs/TECHNICAL_AUDIT_2026-08-08.md))

**v0.3.0 / v0.3.1 — July 2026**
✅ Enterprise Firewall — direction-aware rules, port ranges, 12 built-in templates, CIDR conflict detection, atomic agent sync
✅ Deep Packet Inspection — DGA scoring, TLS anomaly detection, HTTP inspection, protocol anomaly detection (4 new detector services)
✅ CI stabilized across 5 workflows; `xcloak-agent` Docker image published to GHCR

**v0.2.0 — July 2026**
✅ Backend security hardening (Phases 4–6)
✅ Go agent enterprise upgrade — 15 collectors, slog, connection enrichment
✅ Mobile agent enterprise upgrade — enriched posture, retry backoff, 11 MDM commands
✅ Kafka event bus wired end-to-end (7 consumer groups)
✅ FIM + YARA auto-quarantine with approval queue
✅ Splunk HEC real-time streaming
✅ Atomic rate limiter (TOCTOU closed)
✅ httpOnly cookie auth + refresh token rotation
✅ Exponential retry on all webhook deliveries

See [CHANGELOG.md](CHANGELOG.md) for full per-release detail.

---

## Next — targeting v0.5.0

### High Priority

📋 **Row-Level Security rollout** — currently 6 of 248 tables have RLS; extend to the highest-sensitivity remainder (credentials, PII, cross-tenant data) first, not all at once. Flagged as the top finding in the [technical audit](docs/TECHNICAL_AUDIT_2026-08-08.md).
📋 **Agent token rotation UI** — one-click rotation from agent detail page with audit trail
📋 **PII masking** — configurable field-level masking on log ingest for email/IP/username fields
📋 **Alert suppression tuning** — false-positive rate tracking per rule + one-click suppress from alert
📋 **OpenAPI spec + generated TypeScript client** — closes the field-mismatch bug class found repeatedly during live testing (payload key mismatches, dead-code API endpoints with no caller)

### Medium Priority

📋 **Repository-layer test coverage** — currently 5% (3 of 56 files), vs. 18% for services/ — this is the layer where a missing `tenant_id` clause would land
📋 **gosec HIGH-severity findings promoted to a blocking CI gate** — currently advisory (`continue-on-error: true`); 22 HIGH findings identified in the technical audit need triage first
📋 **macOS agent** — port heartbeat, packages (`brew`), processes, connections, FIM to macOS
📋 **iOS mobile agent** — minimal posture + MDM check-in (Android feature-parity is the target)
📋 **Agent fleet health dashboard** — backend overview of agent version distribution, offline count, disk/battery critical

---

## Later

### Detection

💡 **Suricata integration** — ingest Suricata EVE JSON alerts as a log source  
💡 **PCAP capture on isolate** — when an agent isolates a host, optionally capture a PCAP for the forensics tab  
💡 **ML-based anomaly baseline** — replace heuristic NBA thresholds with per-tenant learned baselines  
💡 **Custom detection pipelines** — let operators chain field-extraction + enrichment + threshold logic without writing Go  

### Platform

💡 **Android Enterprise (Device Owner) support** — real MDM enforcement (force-wipe, app blocklisting) instead of the current monitor/request-only model
💡 **SOC shift handoff notes** — per-tenant case handoff screen with shift-change workflow  
💡 **Agent self-update via UI** — push new agent binaries to enrolled endpoints from the dashboard  
💡 **HashiCorp Vault auto-unseal** — automated Vault init + unseal for Kubernetes deployments  
💡 **External penetration test** — highest-leverage move for enterprise credibility per the technical audit; no third-party validation exists yet

### Integrations

💡 **Splunk app** — XCloak Splunk app for forwarding detections into existing Splunk deployments  
💡 **Microsoft Sentinel connector** — native Logic App connector  
💡 **CrowdStrike Falcon feed** — ingest CrowdStrike detections as XCloak alerts  
💡 **AWS Security Hub** — bidirectional sync  

---

## Longer Term / Ideas

💡 **Hosted SaaS launch** — SaaS/self-hosted mode toggle, subscription management, and license-authority detection already ship in the platform admin console; a publicly-signed-up hosted offering is the remaining step  
💡 **Agent for network devices** — SNMP + syslog collector on routers/switches with VLAN visibility  
💡 **Container/Kubernetes agent** — eBPF-based runtime threat detection in Kubernetes pods  
💡 **AI rule generation** — describe an attack, Claude generates a Sigma rule  
💡 **Community rule hub** — GitHub-hosted community Sigma rule library synced into XCloak on update  

---

## Known Limitations (Transparent)

These are the current honest limitations of the platform:

- **Single maintainer** — response times and release cadence reflect a one-person project
- **Row-Level Security covers 6 of 248 tables** — the rest rely on application-level `tenant_id` filtering with no database-level backstop; see the [technical audit](docs/TECHNICAL_AUDIT_2026-08-08.md) for detail
- **Android-only mobile** — iOS agent does not exist yet
- **No Android Enterprise (Device Owner) enforcement** — MDM today is monitor/request-based, not OS-enforced
- **No official production SLA** — this is not a commercial product; use at your own risk
- **Screen lock detection requires Device Owner (DPC)** — BYOD Android mode cannot programmatically detect screen lock status
- **eBPF requires Linux kernel 5.8+** — degrades gracefully on older kernels
- **PII in logs not masked** — `parsed_fields` may contain emails/IPs from raw log lines
- **No third-party pentest yet** — all security work is internal; external audit is planned but not yet scheduled
- **Certificate pinning not enabled by default** — can be built in via ldflags for production deployments

---

*Last updated: 2026-08-08*  
*Maintainer: Abhishek N — abhishekn1003@gmail.com · [xcloak.tech](https://xcloak.tech)*
