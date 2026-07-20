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

## v0.2.0 (Current) — July 2026

✅ Backend security hardening (Phases 4–6)  
✅ Go agent enterprise upgrade — 15 collectors, slog, connection enrichment  
✅ Mobile agent enterprise upgrade — enriched posture, retry backoff, 11 MDM commands  
✅ Kafka event bus wired end-to-end (7 consumer groups)  
✅ FIM + YARA auto-quarantine with approval queue  
✅ Splunk HEC real-time streaming  
✅ Atomic rate limiter (TOCTOU closed)  
✅ PostgreSQL RLS load-bearing for all queries  
✅ httpOnly cookie auth + refresh token rotation  
✅ Exponential retry on all webhook deliveries  

---

## v0.3.0 — Q3 2026

### High Priority

📋 **GitHub Release binaries** — pre-built Linux/Windows agent binaries + Android APK attached to each GitHub Release tag  
📋 **Helm chart v0.2** published to GitHub Pages OCI registry (installable via `helm install xcloak oci://ghcr.io/the-abhishek1/charts/xcloak`)  
📋 **CI/CD pipeline** — GitHub Actions: Go build + test, Flutter build, Docker push to GHCR, Helm release  
📋 **Agent token rotation UI** — one-click rotation from agent detail page with audit trail  
📋 **PII masking** — configurable field-level masking on log ingest for email/IP/username fields  
📋 **Alert suppression tuning** — false-positive rate tracking per rule + one-click suppress from alert  

### Medium Priority

📋 **macOS agent** — port heartbeat, packages (`brew`), processes, connections, FIM to macOS  
📋 **iOS mobile agent** — minimal posture + MDM check-in (Android feature-parity is the target)  
📋 **Live Demo instance** — self-hosted demo at `demo.xcloak.tech` on a cheap VPS with sample data  
📋 **OpenAPI docs** — expand [docs.xcloak.tech](https://docs.xcloak.tech) with full API reference, rule examples, interactive tutorials  
📋 **Agent fleet health dashboard** — backend overview of agent version distribution, offline count, disk/battery critical  

---

## v0.4.0 — Q4 2026

### Detection

💡 **Suricata integration** — ingest Suricata EVE JSON alerts as a log source  
💡 **PCAP capture on isolate** — when an agent isolates a host, optionally capture a PCAP for the forensics tab  
💡 **ML-based anomaly baseline** — replace heuristic NBA thresholds with per-tenant learned baselines  
💡 **Custom detection pipelines** — let operators chain field-extraction + enrichment + threshold logic without writing Go  

### Platform

💡 **SOC shift handoff notes** — per-tenant case handoff screen with shift-change workflow  
💡 **Mobile agent iOS port** — full parity with Android  
💡 **Agent self-update via UI** — push new agent binaries to enrolled endpoints from the dashboard  
💡 **HashiCorp Vault auto-unseal** — automated Vault init + unseal for Kubernetes deployments  

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
- **Android-only mobile** — iOS agent does not exist yet
- **No official production SLA** — this is not a commercial product; use at your own risk
- **Screen lock detection requires Device Owner (DPC)** — BYOD Android mode cannot programmatically detect screen lock status
- **eBPF requires Linux kernel 5.8+** — degrades gracefully on older kernels
- **PII in logs not masked** — `parsed_fields` may contain emails/IPs from raw log lines
- **No third-party pentest yet** — all security work is internal; external audit is planned but not yet scheduled
- **Certificate pinning not enabled by default** — can be built in via ldflags for production deployments

---

*Last updated: 2026-07-20*  
*Maintainer: Abhishek N — abhishekn1003@gmail.com · [xcloak.tech](https://xcloak.tech)*
