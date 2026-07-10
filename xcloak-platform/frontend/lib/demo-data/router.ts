// Static demo router — returns baked-in data for every API endpoint.
// Used by app/api/[...path]/route.ts when DEMO_ONLY=true.
// No backend or database required; deploys to Netlify free tier.

import RAW from './data.json';

const D = RAW as Record<string, any[]>;

// ── helpers ──────────────────────────────────────────────────────────────────

function paginate(arr: any[], sp: URLSearchParams) {
  const page    = Math.max(1, parseInt(sp.get('page')     || '1'));
  const perPage = Math.min(200, Math.max(1, parseInt(sp.get('per_page') || '50')));
  const total   = arr.length;
  const pages   = Math.ceil(total / perPage);
  const slice   = arr.slice((page - 1) * perPage, page * perPage);
  return { data: slice, page, per_page: perPage, total, pages };
}

function ok(data: unknown, status = 200) { return { data, status }; }
function notFound()  { return { data: { error: 'not found' }, status: 404 }; }
function demoBlock() { return { data: { error: 'Action disabled in demo mode' }, status: 403 }; }

// Seeded LCG — stable values without Math.random() non-determinism
function seededRand(seed: number) {
  return ((seed * 1664525 + 1013904223) & 0xffffffff) / 0x100000000 + 0.5;
}

// ── Pre-computed blobs (built once, reused on every request) ─────────────────

// SigmaRuleStat[] — one entry per rule (page does stats.map(s => [s.rule_id, s]))
const SIGMA_STATS = D.sigma_rules.map((r: any, i: number) => ({
  rule_id:         r.id,
  title:           r.title,
  hit_count:       r.match_count ?? Math.floor(seededRand(r.id) * 50),
  last_matched_at: i < 80 ? new Date(Date.now() - i * 3600000).toISOString() : null,
}));

// FleetAnomalySummary[] — one entry per agent
const FLEET_SUMMARIES = D.agents.map((a: any, i: number) => ({
  agent_id:    a.id,
  hostname:    a.hostname,
  peak_score:  [82, 67, 44, 31][i] ?? 40,
  avg_score:   [71, 55, 38, 28][i] ?? 35,
  readings:    120,
  last_scored: new Date(Date.now() - i * 900000).toISOString(),
}));

// IOCs with indicator/enabled fields (page reads .indicator and .enabled)
const IOCS_NORMALIZED = D.iocs.map((ioc: any) => ({
  ...ioc,
  indicator: ioc.indicator ?? ioc.value,
  enabled:   ioc.enabled   ?? ioc.active ?? true,
}));

// Insider threat with correct contributor keys
const INSIDER_NORMALIZED = D.insider_threat.map((s: any) => ({
  ...s,
  contributors: {
    off_hours_auth:     s.contributors?.off_hours_auth ?? s.contributors?.off_hours     ?? Math.floor(seededRand(s.id * 6)     * 12),
    failed_auth:        s.contributors?.failed_auth    ?? s.contributors?.failed_logins ?? Math.floor(seededRand(s.id * 6 + 1) * 10),
    data_exfil:         s.contributors?.data_exfil     ?? s.contributors?.data_access   ?? Math.floor(seededRand(s.id * 6 + 2) * 18),
    sensitive_access:   s.contributors?.sensitive_access                                ?? Math.floor(seededRand(s.id * 6 + 3) * 8),
    privesc_attempt:    s.contributors?.privesc_attempt                                 ?? Math.floor(seededRand(s.id * 6 + 4) * 5),
    anomalous_location: s.contributors?.anomalous_location                              ?? Math.floor(seededRand(s.id * 6 + 5) * 6),
  },
}));

// Threat actors with required display fields
const THREAT_ACTORS_NORMALIZED = D.threat_actors.map((a: any, i: number) => ({
  ...a,
  recent_alert_count: [3, 7, 1, 0, 2, 5, 0, 1, 4, 0][i] ?? 0,
  is_builtin:         i < 6,
}));

// JA3 fingerprints with is_platform
const JA3_NORMALIZED = D.ja3.map((j: any, i: number) => ({
  ...j,
  is_platform: i < 2,
}));

// Correlation rules mapped to the interface the page expects
const CORRELATION_RULES_NORMALIZED = D.correlation_rules.map((r: any) => ({
  ...r,
  rule_name:        r.rule_name   ?? r.name,
  action:           r.action      ?? 'create_incident',
  source_type:      r.source_type ?? 'alert',
  agent_id:         r.agent_id    ?? 0,
  condition_value:  r.condition_value ?? String(r.threshold ?? ''),
  playbook_id:      r.playbook_id ?? null,
  stages:           r.stages      ?? null,
}));

// Hunt templates with display fields
const HUNT_TEMPLATES_NORMALIZED = D.hunt_templates.map((t: any) => ({
  ...t,
  schedule:    t.schedule    ?? null,
  created_by:  t.created_by  ?? 'XCloak',
}));

// VulnQueueItem[] built from vulnerabilities
const VULN_QUEUE_ITEMS = D.vulnerabilities.map((v: any, i: number) => {
  const ag = D.agents.find((a: any) => a.id === v.agent_id);
  return {
    id:               v.id,
    agent_id:         v.agent_id,
    hostname:         ag?.hostname ?? `Agent #${v.agent_id}`,
    cve_id:           v.cve_id   ?? `CVE-2024-${10000 + i}`,
    name:             v.name     ?? v.title ?? 'Unknown Vulnerability',
    package_name:     v.package_name ?? v.affected_component ?? 'unknown-pkg',
    package_version:  v.package_version ?? '1.0.0',
    severity:         v.severity ?? 'medium',
    cvss_score:       v.cvss_score ?? 6.5,
    epss_score:       v.epss_score ?? 0.02,
    is_kev:           v.is_kev ?? false,
    kev_ransomware:   false,
    priority_score:   v.priority_score ?? Math.floor(seededRand(v.id) * 900),
    patch_status:     v.patch_status ?? (v.fix_available ? 'open' : 'accepted_risk'),
    patch_notes:      '',
    patch_sla_days:   v.cvss_score >= 9 ? 7 : v.cvss_score >= 7 ? 30 : 90,
    patched_at:       null,
    asset_criticality: ag ? 'high' : 'medium',
  };
}).sort((a: any, b: any) => b.priority_score - a.priority_score);

// Risk posture with asset_scores
function riskPostureSnap() {
  const base = D.risk_posture[0] ?? {};
  const asset_scores = D.agents.map((a: any, i: number) => ({
    asset_id:    a.id,
    hostname:    a.hostname,
    score:       [82, 67, 44, 31][i] ?? 50,
    top_reason:  ['C2 beacon detected', 'Lateral movement', 'Vuln exposure', 'Low risk'][i] ?? 'Normal activity',
    criticality: ['critical', 'high', 'medium', 'low'][i] ?? 'medium',
  }));
  return {
    score:        base.score        ?? 42,
    vuln_score:   base.vuln_score   ?? 35,
    ueba_score:   base.ueba_score   ?? 60,
    alert_score:  base.alert_score  ?? 55,
    ioc_score:    base.ioc_score    ?? 20,
    asset_scores,
  };
}

// DFIR collections with all required fields
const DFIR_COLLECTIONS = [
  {
    id:             1,
    label:          'IR-2026-001 — C2 Beacon Investigation',
    agent_hostname: D.agents[0]?.hostname ?? 'web-prod-01',
    agent_id:       D.agents[0]?.id ?? 1,
    status:         'completed',
    triggered_by:   'analyst@xcloak.tech',
    artifact_types: ['memory', 'processes', 'network', 'files'],
    started_at:     new Date(Date.now() - 86400000 * 2).toISOString(),
    completed_at:   new Date(Date.now() - 86400000 * 2 + 3600000).toISOString(),
    created_at:     new Date(Date.now() - 86400000 * 2).toISOString(),
    artifact_count: 12,
    incident_id:    1,
    tenant_id:      9999,
  },
  {
    id:             2,
    label:          'IR-2026-002 — Ransomware Containment',
    agent_hostname: D.agents[1]?.hostname ?? 'db-server-02',
    agent_id:       D.agents[1]?.id ?? 2,
    status:         'completed',
    triggered_by:   'analyst@xcloak.tech',
    artifact_types: ['memory', 'files', 'registry'],
    started_at:     new Date(Date.now() - 86400000).toISOString(),
    completed_at:   new Date(Date.now() - 86400000 + 1800000).toISOString(),
    created_at:     new Date(Date.now() - 86400000).toISOString(),
    artifact_count: 8,
    incident_id:    2,
    tenant_id:      9999,
  },
];

// Framework compliance — FrameworkAssessment[]
const FRAMEWORK_ASSESSMENTS = (() => {
  const frameworks = [...new Set(D.compliance_scores.map((s: any) => s.framework))];
  return frameworks.map((fw: any) => {
    const scores = D.compliance_scores.filter((s: any) => s.framework === fw);
    const score  = scores[0]?.score ?? 74;
    const total  = 80;
    const covered = Math.round(total * score / 100);
    const partial = Math.round(total * 0.08);
    const gaps    = total - covered - partial;
    return {
      framework:      fw,
      overall_score:  score,
      total_controls: total,
      covered,
      partial,
      gaps:           Math.max(0, gaps),
      controls:       [],
    };
  });
})();

// Network map with correct NetworkMapNode / NetworkMapEdge / NetworkMapSummary shapes
const NETWORK_MAP = (() => {
  // Agent nodes — id must be a string
  const agentNodes = D.agents.map((a: any, i: number) => ({
    id:          String(a.id),
    type:        'agent' as const,
    agent_id:    a.id,
    hostname:    a.hostname,
    ip:          a.ip_address ?? `10.0.0.${i + 10}`,
    zone:        (['dmz', 'internal', 'internal', 'internal'] as const)[i] ?? 'internal',
    risk_score:  [82, 67, 44, 31][i] ?? 40,
    risk_level:  ['critical', 'high', 'medium', 'low'][i] ?? 'medium',
    alert_count: D.alerts.filter((al: any) => al.agent_id === a.id).length,
    is_ioc:      i === 0,
    status:      (a.status ?? 'online') as 'online' | 'offline',
  }));

  // Build external_ip nodes from unique remote addresses
  // remote_addr format is "IP:PORT" — split on last colon to handle IPv4
  const agentIpSet = new Set(D.agents.map((a: any) => a.ip_address).filter(Boolean));
  const extIpMap   = new Map<string, any>();
  D.endpoint_connections.forEach((c: any) => {
    const raw = c.remote_addr ?? '';
    const lastColon = raw.lastIndexOf(':');
    const ip  = lastColon > 0 ? raw.slice(0, lastColon) : raw;
    if (!ip || agentIpSet.has(ip) || extIpMap.has(ip)) return;
    extIpMap.set(ip, {
      id:          `ext_${ip}`,
      type:        'external_ip' as const,
      ip,
      zone:        'external' as const,
      risk_score:  20,
      risk_level:  'low',
      alert_count: 0,
      is_ioc:      false,
    });
  });
  const extNodes = Array.from(extIpMap.values()).slice(0, 20);
  const nodes    = [...agentNodes, ...extNodes];

  // Build agent-IP→id lookup so internal remote addrs map to an agent node
  const ipToNodeId = new Map<string, string>();
  agentNodes.forEach((n: any) => { if (n.ip) ipToNodeId.set(n.ip, n.id); });

  const PORT_SENSITIVITY: Record<number, 'safe' | 'neutral' | 'sensitive' | 'critical'> = {
    80: 'safe', 443: 'safe', 8080: 'neutral', 8443: 'neutral',
    22: 'sensitive', 3306: 'critical', 5432: 'critical', 3389: 'critical',
  };

  const edges = D.endpoint_connections.slice(0, 25).map((c: any) => {
    const raw      = c.remote_addr ?? '';
    const lastColon = raw.lastIndexOf(':');
    const remoteIp  = lastColon > 0 ? raw.slice(0, lastColon) : raw;
    const portStr   = lastColon > 0 ? raw.slice(lastColon + 1) : '443';
    const portNum   = parseInt(portStr) || 443;
    const targetId  = ipToNodeId.get(remoteIp) ?? `ext_${remoteIp}`;
    const isExternal = !ipToNodeId.has(remoteIp);
    return {
      source:           String(c.agent_id),
      target:           targetId,
      protocol:         (c.protocol ?? 'TCP').toUpperCase(),
      port:             portStr,
      service:          portNum === 443 ? 'HTTPS' : portNum === 80 ? 'HTTP' : portNum === 22 ? 'SSH' : portNum === 3389 ? 'RDP' : 'unknown',
      port_sensitivity: PORT_SENSITIVITY[portNum] ?? 'neutral',
      process:          c.process_name ?? 'svchost.exe',
      count:            c.connection_count ?? 1,
      last_seen:        c.created_at ?? new Date(Date.now() - 3600000).toISOString(),
      edge_type:        (isExternal ? 'external' : 'internal') as 'internal' | 'external',
    };
  });

  const onlineAgents = D.agents.filter((a: any) => a.status === 'online').length;
  const alertingIds  = new Set(D.alerts.map((al: any) => String(al.agent_id)));
  const summary = {
    total_agents:   D.agents.length,
    online_agents:  onlineAgents,
    external_ips:   extNodes.length,
    total_edges:    edges.length,
    ioc_hits:       0,
    alerting_nodes: alertingIds.size,
  };
  return { nodes, edges, summary, generated_at: new Date().toISOString() };
})();

// Attack path — matches AttackPathNode / AttackPathEdge / RankedAttackPath types
const ATTACK_PATH = (() => {
  // nodes: id is a string, type is 'internet' | 'agent'
  const internetNode = { id: 'internet', type: 'internet' as const, risk_score: 100, risk_level: 'critical', max_epss: 0.9, has_kev: true, kev_count: 2, exposed: true, compromise_cost: 0 };
  const agentNodes = D.agents.map((a: any, i: number) => ({
    id:              String(a.id),
    type:            'agent' as const,
    agent_id:        a.id,
    hostname:        a.hostname,
    risk_score:      [82, 67, 44, 31][i] ?? 40,
    risk_level:      ['critical', 'high', 'medium', 'low'][i] ?? 'medium',
    max_epss:        [0.85, 0.62, 0.3, 0.1][i] ?? 0.2,
    has_kev:         i < 2,
    kev_count:       i < 2 ? 1 : 0,
    exposed:         i === 0,
    compromise_cost: [10, 25, 45, 80][i] ?? 50,
  }));
  const nodes = [internetNode, ...agentNodes];

  // edges: source/target are string IDs, kind is 'internet_exposure' | 'lateral'
  const edges = [
    { source: 'internet', target: String(D.agents[0]?.id ?? 1), kind: 'internet_exposure' as const },
    ...D.agents.slice(0, -1).map((a: any, i: number) => ({
      source: String(a.id),
      target: String(D.agents[i + 1]?.id ?? a.id),
      kind:   'lateral' as const,
    })),
  ];

  // top_paths: hops is string[], plus cost/score fields
  const top_paths = [{
    hops:               ['internet', ...D.agents.map((a: any) => String(a.id))],
    total_cost:         10,
    target_hostname:    D.agents[D.agents.length - 1]?.hostname ?? 'db-server-02',
    target_risk_level:  'low',
    score:              87,
  }];

  return { nodes, edges, top_paths, has_entry_point: true };
})();

// Fake MDM devices (mdm_devices table is empty in seed data)
const MDM_DEVICES = [
  {
    id: 1, tenant_id: 9999,
    device_name: 'iPhone-CEO', serial: 'F2LX8Q3MNPQ1',
    platform: 'ios', os_version: '17.4.1', model: 'iPhone 15 Pro',
    enrollment_status: 'enrolled', compliance_status: 'compliant',
    last_checkin: new Date(Date.now() - 3600000).toISOString(),
    owner_email: 'ceo@xcloak.tech', owner_name: 'John Smith',
    is_supervised: true, is_encrypted: true, is_jailbroken: false,
    mdm_profile_installed: true, passcode_compliant: true,
    storage_used_gb: 45, storage_total_gb: 256,
    battery_level: 82, created_at: '2026-01-15T10:00:00Z',
  },
  {
    id: 2, tenant_id: 9999,
    device_name: 'android-mobile-01', serial: 'R3CX9S4KPQT2',
    platform: 'android', os_version: '14.0', model: 'Pixel 8 Pro',
    enrollment_status: 'enrolled', compliance_status: 'non_compliant',
    last_checkin: new Date(Date.now() - 7200000).toISOString(),
    owner_email: 'analyst@xcloak.tech', owner_name: 'Jane Doe',
    is_supervised: false, is_encrypted: true, is_jailbroken: false,
    mdm_profile_installed: true, passcode_compliant: false,
    storage_used_gb: 28, storage_total_gb: 128,
    battery_level: 61, created_at: '2026-02-01T08:30:00Z',
  },
  {
    id: 3, tenant_id: 9999,
    device_name: 'MacBook-SOC', serial: 'C02XN5QXJHD3',
    platform: 'macos', os_version: '14.4.1', model: 'MacBook Pro 16',
    enrollment_status: 'enrolled', compliance_status: 'compliant',
    last_checkin: new Date(Date.now() - 1800000).toISOString(),
    owner_email: 'soc@xcloak.tech', owner_name: 'SOC Analyst',
    is_supervised: true, is_encrypted: true, is_jailbroken: false,
    mdm_profile_installed: true, passcode_compliant: true,
    storage_used_gb: 120, storage_total_gb: 512,
    battery_level: 95, created_at: '2026-01-20T09:00:00Z',
  },
];

// Live log lines
const LIVE_LOG_LINES = D.endpoint_logs.slice(0, 30).map((l: any) => ({
  id:        l.id,
  agent_id:  l.agent_id,
  source:    l.log_source,
  message:   l.log_message,
  timestamp: l.collected_at,
  severity:  'info',
}));

// Dashboard overview
function dashboardOverview() {
  const alerts    = D.alerts;
  const incidents = D.incidents;
  const agents    = D.agents;
  const critical  = alerts.filter((a: any) => a.severity === 'critical').length;
  const high      = alerts.filter((a: any) => a.severity === 'high').length;
  const online    = agents.filter((a: any) => a.status === 'online').length;
  const tacticMap: Record<string, number> = {};
  alerts.forEach((a: any) => { const t = a.mitre_tactic || 'Unknown'; tacticMap[t] = (tacticMap[t] || 0) + 1; });
  const now = Date.now();
  return {
    critical_alerts:    critical,
    high_alerts:        high,
    total_alerts:       alerts.length,
    open_incidents:     incidents.filter((i: any) => i.status !== 'resolved').length,
    total_incidents:    incidents.length,
    agents_online:      online,
    total_agents:       agents.length,
    soar_executed:      D.playbook_executions.length,
    mttd_minutes:       464,
    mttr_minutes:       0,
    ioc_hits:           0,
    alert_velocity:     96,
    threat_score:       100,
    sensor_coverage:    0,
    mitre_coverage:     tacticMap,
    severity_breakdown: {
      critical, high,
      medium: alerts.filter((a: any) => a.severity === 'medium').length,
      low:    alerts.filter((a: any) => a.severity === 'low').length,
    },
    alert_trend: Array.from({ length: 24 }, (_, i) => ({
      hour:     new Date(now - (23 - i) * 3600000).toISOString(),
      critical: Math.floor(seededRand(i * 4)     * 4),
      high:     Math.floor(seededRand(i * 4 + 1) * 6),
      medium:   Math.floor(seededRand(i * 4 + 2) * 9),
      low:      Math.floor(seededRand(i * 4 + 3) * 5),
    })),
  };
}

// Dashboard metrics
function dashboardMetrics(range: string) {
  const alerts    = D.alerts;
  const incidents = D.incidents;
  const agents    = D.agents;
  const online    = agents.filter((a: any) => a.status === 'online').length;
  const total     = agents.length;
  const critical  = alerts.filter((a: any) => a.severity === 'critical').length;
  const high      = alerts.filter((a: any) => a.severity === 'high').length;
  const now       = Date.now();
  const buckets   = range === '1h' ? 12 : range === '7d' ? 7 : range === '30d' ? 30 : 24;
  const bucketMs  = range === '7d' || range === '30d' ? 86400000 : range === '1h' ? 300000 : 3600000;
  const alert_trend = Array.from({ length: buckets }, (_, i) => ({
    label:    new Date(now - (buckets - 1 - i) * bucketMs).toISOString(),
    critical: Math.floor(seededRand(i * 4)     * 4),
    high:     Math.floor(seededRand(i * 4 + 1) * 6),
    medium:   Math.floor(seededRand(i * 4 + 2) * 9),
    low:      Math.floor(seededRand(i * 4 + 3) * 5),
  }));
  const tacticCounts: Record<string, number> = {};
  alerts.forEach((a: any) => { const t = a.mitre_tactic || 'Defense Evasion'; tacticCounts[t] = (tacticCounts[t] || 0) + 1; });
  const mitre_tactics = Object.entries(tacticCounts).map(([tactic, count]) => ({
    tactic, alert_count: count, severity: count > 20 ? 'critical' : count > 10 ? 'high' : 'medium',
  }));
  const ruleCounts: Record<string, { count: number; severity: string }> = {};
  alerts.forEach((a: any) => { const r = a.rule_name || 'Unknown'; if (!ruleCounts[r]) ruleCounts[r] = { count: 0, severity: a.severity || 'medium' }; ruleCounts[r].count++; });
  const top_rules = Object.entries(ruleCounts).sort((a, b) => b[1].count - a[1].count).slice(0, 8)
    .map(([rule_name, v]) => ({ rule_name, count: v.count, severity: v.severity }));
  const agentCounts: Record<number, number> = {};
  alerts.forEach((a: any) => { agentCounts[a.agent_id] = (agentCounts[a.agent_id] || 0) + 1; });
  const top_agents = Object.entries(agentCounts).sort((a, b) => Number(b[1]) - Number(a[1])).slice(0, 5)
    .map(([agent_id, count]) => { const ag = agents.find((a: any) => a.id === Number(agent_id)); return { agent_id: Number(agent_id), hostname: ag?.hostname || `Agent #${agent_id}`, count }; });
  const sigma_enabled = D.sigma_rules.filter((r: any) => r.enabled).length;
  const yara_enabled  = D.yara_rules.filter((r: any) => r.enabled !== false).length;
  return {
    alert_trend, alert_velocity_1h: 96, threat_score: critical > 30 ? 82 : high > 20 ? 65 : 48,
    anomaly_score: 24, ioc_hits: 0, compliance_score: D.compliance_scores[0]?.score ?? 74, range,
    mttr: { avg_seconds: 0, avg_formatted: '—', total_resolved: incidents.filter((i: any) => i.status === 'resolved').length, last_24h_seconds: 0 },
    mttd: { avg_seconds: 27840, avg_formatted: '7h 44m', sample_count: alerts.length },
    alert_deltas:    { current: alerts.length, previous: Math.floor(alerts.length * 0.85), delta: Math.floor(alerts.length * 0.15), delta_pct: 15 },
    incident_deltas: { current: incidents.filter((i: any) => i.status !== 'resolved').length, previous: 3, delta: incidents.filter((i: any) => i.status !== 'resolved').length - 3, delta_pct: 20 },
    agent_coverage:  { total, online, offline: total - online, pct_online: total > 0 ? Math.round((online / total) * 100) : 0 },
    mitre_tactics, rule_health: { sigma_enabled, sigma_disabled: D.sigma_rules.length - sigma_enabled, sigma_total: D.sigma_rules.length, yara_enabled, yara_total: D.yara_rules.length },
    top_rules, top_agents,
  };
}

// ── main router ───────────────────────────────────────────────────────────────

export function demoRoute(
  path:   string,
  method: string,
  sp:     URLSearchParams,
): { data: unknown; status: number } {
  const p = path.replace(/^\/api/, '');

  // WebSocket ticket — fake it so the WS flow doesn't show a 403 toast
  if (p === '/ws/ticket') return ok({ ticket: 'demo-ws-ticket-noop' });

  // All mutations → 403
  if (!['GET', 'HEAD'].includes(method.toUpperCase())) return demoBlock();

  // ── Auth ──────────────────────────────────────────────────────────────────
  if (p === '/auth/profile' || p === '/auth/me') {
    return ok({ id: 1, username: 'demo-viewer', email: 'demo@xcloak.tech', role: 'viewer', tenant_id: 9999, is_active: true, created_at: '2026-01-01T00:00:00Z' });
  }

  // ── Dashboard ─────────────────────────────────────────────────────────────
  if (p === '/dashboard/overview') return ok(dashboardOverview());
  if (p === '/dashboard/metrics')  return ok(dashboardMetrics(sp.get('range') || '24h'));

  // ── Alerts ────────────────────────────────────────────────────────────────
  if (p === '/alerts') return ok(D.alerts);
  if (p === '/alerts/paginated') {
    let arr = [...D.alerts];
    const sev  = sp.get('severity');
    const aid  = sp.get('agent_id');
    const stat = sp.get('status');
    if (sev  && sev  !== 'all') arr = arr.filter((a: any) => a.severity === sev);
    if (aid)                    arr = arr.filter((a: any) => String(a.agent_id) === aid);
    if (stat && stat !== 'all') arr = arr.filter((a: any) => a.status === stat);
    const pg = paginate(arr, sp);
    // alerts page reads result?.alerts; cloud/infra pages read r.data?.alerts
    return ok({ alerts: pg.data, page: pg.page, per_page: pg.per_page, total: pg.total, pages: pg.pages });
  }
  if (/^\/alerts\/\d+\/investigate$/.test(p)) {
    const id    = parseInt(p.split('/')[2]);
    const alert = D.alerts.find((a: any) => a.id === id);
    return ok({
      alert,
      threat_score:     45,
      correlated_rules: [],
      ioc_hits:         [],
      similar_alerts:   D.alerts.filter((a: any) => a.rule_name === alert?.rule_name && a.id !== id).slice(0, 3),
      suggested_cases:  [],
      related_alerts:   D.alerts.slice(0, 3),
      ioc_matches:      [],
      mitre:            {},
    });
  }

  // ── Incidents ─────────────────────────────────────────────────────────────
  if (p === '/incidents') return ok(D.incidents);
  if (p === '/incidents/paginated') {
    let arr = [...D.incidents];
    const st = sp.get('status');
    if (st && st !== 'all') arr = arr.filter((i: any) => i.status === st);
    const pg = paginate(arr, sp);
    // page reads data.data — use "data" key
    return ok({ data: pg.data, page: pg.page, per_page: pg.per_page, total: pg.total, pages: pg.pages });
  }
  if (/^\/incidents\/\d+$/.test(p)) {
    const id = parseInt(p.split('/')[2]);
    return ok(D.incidents.find((i: any) => i.id === id) ?? notFound().data);
  }
  if (/^\/incidents\/\d+\/events$/.test(p)) return ok([]);
  if (/^\/incidents\/\d+\/notes$/.test(p))  return ok([]);

  // ── Agents ────────────────────────────────────────────────────────────────
  if (p === '/agents') return ok(D.agents);
  if (/^\/agents\/\d+$/.test(p)) {
    const id = parseInt(p.split('/')[2]);
    return ok(D.agents.find((a: any) => a.id === id) ?? notFound().data);
  }
  if (/^\/agents\/\d+\/summary$/.test(p)) {
    const id = parseInt(p.split('/')[2]);
    const ag = D.agents.find((a: any) => a.id === id);
    return ok({
      agent:       ag,
      alert_count: D.alerts.filter((a: any) => a.agent_id === id).length,
      vuln_count:  D.vulnerabilities.filter((v: any) => v.agent_id === id).length,
      processes:   D.endpoint_processes.filter((e: any) => e.agent_id === id).length,
      connections: D.endpoint_connections.filter((e: any) => e.agent_id === id).length,
      fim_alerts:  D.fim_alerts.filter((f: any) => f.agent_id === id).length,
      services:    0,
      packages:    0,
      users:       0,
    });
  }
  if (/^\/agents\/\d+\/processes$/.test(p)) {
    const id = parseInt(p.split('/')[2]);
    return ok(D.endpoint_processes.filter((e: any) => e.agent_id === id));
  }
  if (/^\/agents\/\d+\/connections$/.test(p)) {
    const id = parseInt(p.split('/')[2]);
    return ok(D.endpoint_connections.filter((e: any) => e.agent_id === id));
  }
  if (/^\/agents\/\d+\/timeline$/.test(p)) {
    const id = parseInt(p.split('/')[2]);
    // page expects event_type, message, timestamp AND created_at
    return ok(D.alerts.filter((a: any) => a.agent_id === id).slice(0, 30).map((a: any) => ({
      id:           a.id,
      event_type:   a.rule_name   ?? 'alert',
      message:      a.log_message ?? a.rule_name ?? 'Security event',
      timestamp:    a.created_at,
      created_at:   a.created_at,
      severity:     a.severity,
      agent_id:     a.agent_id,
      mitre_tactic: a.mitre_tactic,
    })));
  }
  if (/^\/agents\/\d+\/vulnerabilities$/.test(p)) {
    const id = parseInt(p.split('/')[2]);
    return ok(D.vulnerabilities.filter((v: any) => v.agent_id === id));
  }
  if (/^\/agents\/\d+\/risk$/.test(p))      return ok({ score: 72, factors: [] });
  if (/^\/agents\/\d+\/services$/.test(p))  return ok([]);
  if (/^\/agents\/\d+\/users$/.test(p))     return ok([]);
  if (/^\/agents\/\d+\/packages$/.test(p))  return ok([]);
  if (/^\/agents\/\d+\/auth-logs$/.test(p)) return ok([]);
  if (/^\/agents\/\d+\/filehashes$/.test(p))return ok([]);
  if (/^\/agents\/\d+\/fim\/alerts$/.test(p)) {
    const id = parseInt(p.split('/')[2]);
    return ok(D.fim_alerts.filter((f: any) => f.agent_id === id));
  }
  if (/^\/agents\/\d+\/fim\/baseline$/.test(p)) return ok([]);

  // ── IOCs — indicator/enabled keys ─────────────────────────────────────────
  if (p === '/iocs') {
    let arr = [...IOCS_NORMALIZED];
    const search = sp.get('search');
    const type   = sp.get('type');
    if (search) arr = arr.filter((i: any) => i.indicator?.includes(search) || i.description?.includes(search));
    if (type)   arr = arr.filter((i: any) => i.type === type);
    const pg = paginate(arr, sp);
    return ok({ data: pg.data, total: pg.total, page: pg.page, limit: pg.per_page });
  }
  if (/^\/iocs\/\d+$/.test(p)) {
    const id = parseInt(p.split('/')[2]);
    return ok(IOCS_NORMALIZED.find((i: any) => i.id === id) ?? notFound().data);
  }

  // ── Threat Feeds ─────────────────────────────────────────────────────────
  if (p === '/threat-feeds') return ok(D.threat_feeds.slice(0, 8));
  if (/^\/threat-feeds\/\d+\/sync-log$/.test(p)) return ok([]);

  // ── Threat Actors — with recent_alert_count, is_builtin ──────────────────
  if (p === '/threat-actors') return ok(THREAT_ACTORS_NORMALIZED);

  // ── Threat Intelligence ───────────────────────────────────────────────────
  if (p === '/threat/scores') return ok([]);
  if (p === '/threat/fleet')  return ok(FLEET_SUMMARIES);  // array, not object
  if (p === '/ai/anomalies')  {
    const aid = sp.get('agent_id');
    return ok(aid ? D.network_anomalies.filter((n: any) => String(n.agent_id) === aid).slice(0, 10) : []);
  }

  // ── Sigma Rules — stats returns SigmaRuleStat[] ───────────────────────────
  if (p === '/sigma/rules') {
    let arr = [...D.sigma_rules];
    const search = sp.get('search');
    const sev    = sp.get('severity');
    if (search) arr = arr.filter((r: any) => r.title?.toLowerCase().includes(search.toLowerCase()));
    if (sev)    arr = arr.filter((r: any) => r.severity === sev);
    const pg = paginate(arr, sp);
    return ok({ data: pg.data, total: pg.total, page: pg.page, limit: pg.per_page });
  }
  if (p === '/sigma/stats') return ok(SIGMA_STATS);

  // ── YARA ──────────────────────────────────────────────────────────────────
  if (p === '/yara/rules')   return ok(D.yara_rules);
  if (p === '/yara/matches') {
    const aid = sp.get('agent_id');
    return ok(aid ? D.yara_matches.filter((m: any) => String(m.agent_id) === aid) : D.yara_matches);
  }

  // ── Firewall ──────────────────────────────────────────────────────────────
  if (p === '/firewall/rules')     return ok(D.firewall_rules);
  if (p === '/firewall/stats')     return ok({ total: D.firewall_rules.length, enabled: D.firewall_rules.filter((r: any) => r.enabled).length, total_hits_24h: D.firewall_rules.reduce((s: number, r: any) => s + (r.hit_count || 0), 0), total_hits: D.firewall_rules.reduce((s: number, r: any) => s + (r.hit_count || 0), 0) });
  if (p === '/firewall/groups')    return ok([...new Set(D.firewall_rules.map((r: any) => r.group_name).filter(Boolean))]);
  if (p === '/firewall/conflicts') return ok([]);
  if (p === '/firewall/sync/log')  return ok([]);

  // ── Vulnerabilities ───────────────────────────────────────────────────────
  if (p === '/vulns/priority-queue') {
    const pg = paginate(VULN_QUEUE_ITEMS, sp);
    return ok({ items: pg.data, total: VULN_QUEUE_ITEMS.length, page: pg.page, pages: pg.pages });
  }
  if (p === '/vulnerabilities') return ok(D.vulnerabilities);

  // ── Assets ────────────────────────────────────────────────────────────────
  if (p === '/assets') return ok(D.assets);
  if (/^\/assets\/\d+$/.test(p)) {
    const id = parseInt(p.split('/')[2]);
    return ok(D.assets.find((a: any) => a.id === id) ?? notFound().data);
  }

  // ── Cases — list returns {cases,total}; detail returns {case,comments,evidence,alerts} ─
  if (p === '/cases') {
    const st  = sp.get('status');
    const ph  = sp.get('phase');
    let arr   = [...D.cases];
    if (st) arr = arr.filter((c: any) => c.status === st);
    if (ph) arr = arr.filter((c: any) => c.phase === ph);
    const pg = paginate(arr, sp);
    return ok({ cases: pg.data, total: pg.total, page: pg.page, pages: pg.pages });
  }
  if (/^\/cases\/\d+$/.test(p)) {
    const id = parseInt(p.split('/')[2]);
    const c  = D.cases.find((c: any) => c.id === id);
    if (!c) return notFound();
    return ok({ case: c, comments: [], evidence: [], alerts: [] });
  }
  if (/^\/cases\/\d+\/comments$/.test(p)) return ok([]);
  if (/^\/cases\/\d+\/evidence$/.test(p))  return ok([]);
  if (/^\/cases\/\d+\/alerts$/.test(p))    return ok([]);

  // ── Suppression — {rules, stats} ─────────────────────────────────────────
  if (p === '/suppression/rules') {
    const active = D.suppression_rules.filter((r: any) => r.enabled !== false).length;
    return ok({
      rules: D.suppression_rules,
      stats: { active_rules: active, total_suppressed: 1842, suppressed_24h: 73 },
    });
  }

  // ── Quarantine ────────────────────────────────────────────────────────────
  if (p === '/quarantine') return ok(D.quarantine);

  // ── UEBA — events wrapped in {events:[]} ─────────────────────────────────
  if (p === '/ueba/users') {
    let arr = [...D.ueba_users];
    const min = sp.get('min_score');
    if (min) arr = arr.filter((u: any) => u.risk_score >= parseInt(min));
    return ok({ profiles: arr, total: arr.length });
  }
  if (p === '/ueba/events') {
    const user = sp.get('username');
    const arr  = user ? D.ueba_events.filter((e: any) => e.username === user) : D.ueba_events;
    return ok({ events: arr });
  }

  // ── Insider Threat — contributor keys fixed ───────────────────────────────
  if (p === '/insider-threat' || p === '/insider-threat/scores') {
    return ok(INSIDER_NORMALIZED);
  }
  if (p === '/insider-threat/summary') {
    return ok(INSIDER_NORMALIZED.filter((s: any) => s.score >= 30).slice(0, 5));
  }

  // ── Alert Clusters ────────────────────────────────────────────────────────
  if (p === '/clusters') {
    return ok(D.alert_clusters.slice(0, parseInt(sp.get('limit') || '200')));
  }

  // ── JA3 — is_platform field ───────────────────────────────────────────────
  if (p === '/ja3/fingerprints') return ok(JA3_NORMALIZED);

  // ── Canary / Deception ────────────────────────────────────────────────────
  if (p === '/canary/tokens') return ok(D.canary_tokens);
  if (p === '/canary/trips')  return ok([]);
  if (p === '/honeyports')    return ok(D.honeyports);

  // ── Hunt — templates with schedule/created_by ─────────────────────────────
  if (p === '/hunt/templates') return ok(HUNT_TEMPLATES_NORMALIZED);
  if (p === '/hunt/runs')      return ok(D.hunt_runs);
  if (p === '/hunt/queries')   return ok([]);

  // ── Global Search ─────────────────────────────────────────────────────────
  if (p === '/search') {
    const q = (sp.get('q') || '').toLowerCase();
    if (!q) return ok({ alerts: [], incidents: [], agents: [], sigma_rules: [] });
    return ok({
      alerts:      D.alerts.filter((a: any) => a.rule_name?.toLowerCase().includes(q)).slice(0, 5),
      incidents:   D.incidents.filter((i: any) => i.title?.toLowerCase().includes(q)).slice(0, 5),
      agents:      D.agents.filter((a: any) => a.hostname?.toLowerCase().includes(q)).slice(0, 5),
      sigma_rules: D.sigma_rules.filter((r: any) => r.title?.toLowerCase().includes(q)).slice(0, 5),
    });
  }

  // ── Log Sources ───────────────────────────────────────────────────────────
  if (p === '/log-sources') return ok(D.log_sources.slice(0, 10));

  // ── Log Search / Live Logs ────────────────────────────────────────────────
  if (p === '/logs/search') {
    const q   = sp.get('q') || '';
    const aid = sp.get('agent_id');
    let arr   = [...D.endpoint_logs];
    if (q)   arr = arr.filter((l: any) => l.log_message?.toLowerCase().includes(q.toLowerCase()));
    if (aid) arr = arr.filter((l: any) => String(l.agent_id) === aid);
    return ok({ logs: arr.slice(0, 50), total: arr.length });
  }
  if (p === '/logs/stats') {
    const now = Date.now();
    return ok({
      total_logs:     D.endpoint_logs.length * 1000,
      retention_days: 90,
      hourly_volume:  Array.from({ length: 24 }, (_, i) => ({ hour: new Date(now - (23 - i) * 3600000).toISOString(), count: Math.floor(seededRand(i * 7) * 800 + 200) })),
      by_source:      D.log_sources.slice(0, 5).map((s: any) => ({ source: s.name ?? `source-${s.id}`, count: s.event_count ?? Math.floor(seededRand(s.id) * 50000) })),
      by_agent:       D.agents.map((a: any) => ({ agent_id: a.id, hostname: a.hostname, count: D.endpoint_logs.filter((l: any) => l.agent_id === a.id).length })),
    });
  }
  if (p === '/logs/searches')  return ok([]);
  if (p === '/logs/retention') return ok({ retention_days: 90 });

  // ── Risk Posture — with asset_scores ─────────────────────────────────────
  if (p === '/risk-posture')         return ok(riskPostureSnap());
  if (p === '/risk-posture/history') return ok(D.risk_posture.slice(0, parseInt(sp.get('limit') || '30')));

  // ── ITDR / DFIR — collections with label/triggered_by/agent_hostname ─────
  if (p === '/itdr/findings')     return ok({ findings: D.itdr_findings, total: D.itdr_findings.length });
  if (p === '/dfir/collections')  return ok(DFIR_COLLECTIONS);
  if (/^\/dfir\/collections\/\d+\/timeline$/.test(p)) return ok([]);

  // ── MDM — getDevices() reads res.data?.devices ───────────────────────────
  if (p === '/mdm/devices')             return ok({ devices: MDM_DEVICES });
  if (p === '/mdm/enrollment-tokens')   return ok(D.mdm_enrollment_tokens ?? []);
  if (p === '/mdm/compliance/summary')  return ok({ total: MDM_DEVICES.length, compliant: 2, non_compliant: 1, unknown: 0 });
  if (/^\/mdm\/devices\/\d+\/compliance$/.test(p)) return ok({ results: [] });
  if (/^\/mdm\/devices\/\d+\/commands$/.test(p))   return ok({ commands: [] });

  // ── Correlation — rule_name/action/stages/source_type ────────────────────
  if (p === '/correlation/rules')   return ok(CORRELATION_RULES_NORMALIZED);
  if (p === '/correlation/matches') {
    const rid = sp.get('rule_id');
    return ok(rid ? D.correlation_matches.filter((m: any) => String(m.rule_id) === rid) : D.correlation_matches);
  }

  // ── Playbooks ─────────────────────────────────────────────────────────────
  if (p === '/playbooks') return ok(D.playbooks);
  if (/^\/playbooks\/\d+$/.test(p)) {
    const id = parseInt(p.split('/')[2]);
    return ok(D.playbooks.find((pb: any) => pb.id === id) ?? notFound().data);
  }
  if (/^\/playbooks\/\d+\/actions$/.test(p))          return ok([]);
  if (p === '/playbook-executions')                    return ok(D.playbook_executions);
  if (/^\/playbook-executions\/\d+\/steps$/.test(p))  return ok([]);
  if (p === '/tasks/pending-approval')                 return ok([]);

  // ── Compliance ────────────────────────────────────────────────────────────
  if (p === '/compliance/reports') return ok(D.compliance_reports);
  if (/^\/compliance\/reports\/\d+$/.test(p)) {
    const id     = parseInt(p.split('/')[3]);
    const rep    = D.compliance_reports.find((r: any) => r.id === id);
    const scores = D.compliance_scores.filter((s: any) => s.report_id === id);
    return ok({ ...rep, scores });
  }
  // Framework compliance — FrameworkAssessment[] with overall_score/covered/partial/gaps/controls
  if (p === '/framework-compliance') return ok(FRAMEWORK_ASSESSMENTS);

  // ── Network Behaviour / NBA ───────────────────────────────────────────────
  if (p === '/nba/anomalies') {
    return ok(D.network_anomalies.slice(0, parseInt(sp.get('limit') || '200')));
  }

  // ── Attack Path — source/target + top_paths ───────────────────────────────
  if (p === '/attack-path') return ok(ATTACK_PATH);

  // ── Network Map — full node/edge shape + summary ──────────────────────────
  if (p === '/network-map') return ok(NETWORK_MAP);
  if (p === '/network-map/ip-info') {
    const ip = sp.get('ip') ?? '';
    return ok({
      ip, is_private: false, is_proxy: false, is_hosting: false, is_ioc: false,
      threat_level: 'none', threat_tags: [], sources: [],
      country: 'Unknown', org: 'Demo Network', asn: 'AS0',
    });
  }

  // ── MITRE ─────────────────────────────────────────────────────────────────
  if (p === '/mitre/mappings') return ok([]);

  // ── Settings / Integrations (read-only stubs) ─────────────────────────────
  if (p === '/integrations')              return ok([]);
  if (p === '/integrations/deliveries')   return ok([]);
  if (p === '/integrations/install-tokens') return ok([]);
  if (p === '/custom-roles')              return ok([]);
  if (p === '/permissions')               return ok([]);
  if (p === '/api-keys')                  return ok([]);
  if (p === '/users')                     return ok([{ id: 1, username: 'demo-viewer', email: 'demo@xcloak.tech', role: 'viewer', is_active: true }]);
  if (p === '/audit/logs')                return ok([]);
  if (p === '/audit/logs/paginated')      return ok({ logs: [], total: 0, page: 1, per_page: 50, pages: 0 });
  if (p === '/security-policy')           return ok({ mfa_required: false, session_timeout_minutes: 60, password_min_length: 12 });
  if (p === '/auth/sessions')             return ok([]);
  if (p === '/sessions')                  return ok([]);
  if (p === '/scheduled-reports') return ok([]);
  if (p === '/scheduler/tasks') {
    return ok([
      { id: 1, name: 'Auth Log Collection',    task_type: 'collect_auth_logs',    cron_expr: '*/15 * * * *', enabled: true,  agent_id: D.agents[0]?.id, last_run: new Date(Date.now() - 900000).toISOString(),    last_status: 'success' },
      { id: 2, name: 'Vulnerability Scan',     task_type: 'vulnerability_scan',   cron_expr: '0 2 * * *',    enabled: true,  agent_id: D.agents[1]?.id, last_run: new Date(Date.now() - 86400000).toISOString(),  last_status: 'success' },
      { id: 3, name: 'FIM Baseline Snapshot',  task_type: 'fim_snapshot',         cron_expr: '0 0 * * 0',    enabled: true,  agent_id: D.agents[0]?.id, last_run: new Date(Date.now() - 604800000).toISOString(), last_status: 'success' },
      { id: 4, name: 'Process Inventory',      task_type: 'collect_processes',    cron_expr: '*/5 * * * *',  enabled: false, agent_id: D.agents[2]?.id, last_run: new Date(Date.now() - 300000).toISOString(),    last_status: 'success' },
    ]);
  }

  // ── Executive / SOC Metrics ───────────────────────────────────────────────
  if (p === '/executive/metrics') {
    const now = Date.now();
    const days30 = Array.from({ length: 30 }, (_, i) => ({ date: new Date(now - (29 - i) * 86400000).toISOString().slice(0, 10), count: Math.floor(seededRand(i * 11) * 15 + 2) }));
    const tacticCounts: Record<string, number> = {};
    D.alerts.forEach((a: any) => { const t = a.mitre_tactic || 'Unknown'; tacticCounts[t] = (tacticCounts[t] || 0) + 1; });
    return ok({
      mttr_hours: 0, mttd_hours: 7.7, sla_compliance_rate: 87.4,
      open_cases:      D.cases.filter((c: any) => c.status !== 'closed').length,
      critical_cases:  D.cases.filter((c: any) => c.severity === 'critical' && c.status !== 'closed').length,
      total_assets:    D.assets.length,
      critical_assets: D.assets.filter((a: any) => a.criticality === 'critical').length,
      online_agents:   D.agents.filter((a: any) => a.status === 'online').length,
      total_alerts:    D.alerts.length,
      alert_volume:    days30,
      risk_trend:      days30.map((d, i) => ({ date: d.date, count: Math.floor(seededRand(i * 13) * 80 + 30) })),
      cases_by_severity: [
        { label: 'critical', count: D.cases.filter((c: any) => c.severity === 'critical').length },
        { label: 'high',     count: D.cases.filter((c: any) => c.severity === 'high').length },
        { label: 'medium',   count: D.cases.filter((c: any) => c.severity === 'medium').length },
        { label: 'sla_breach', count: 2 },
      ],
      cases_by_phase: [
        { label: 'open',          count: D.cases.filter((c: any) => c.status === 'open').length },
        { label: 'investigating', count: D.cases.filter((c: any) => c.status === 'investigating').length },
        { label: 'closed',        count: D.cases.filter((c: any) => c.status === 'closed').length },
      ],
      top_mitre_tactics: Object.entries(tacticCounts).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([label, count]) => ({ label, count })),
    });
  }
  if (p === '/soc/metrics') {
    const now = Date.now();
    return ok({
      total_open:       D.alerts.filter((a: any) => a.status === 'open').length,
      total_acked:      D.alerts.filter((a: any) => a.status === 'acknowledged').length,
      total_resolved:   D.alerts.filter((a: any) => a.status === 'resolved').length,
      avg_mttr_minutes: 0,
      alerts_by_day:    Array.from({ length: 14 }, (_, i) => ({ date: new Date(now - (13 - i) * 86400000).toISOString().slice(0, 10), count: Math.floor(seededRand(i * 9) * 20 + 5) })),
      backlog_trend:    Array.from({ length: 14 }, (_, i) => ({ date: new Date(now - (13 - i) * 86400000).toISOString().slice(0, 10), count: Math.floor(seededRand(i * 17) * 10 + 2) })),
      analysts:         [],
    });
  }

  // ── Live log stream ───────────────────────────────────────────────────────
  if (p === '/live-logs' || p === '/logs/live') return ok(LIVE_LOG_LINES);

  // ── Fallback ─────────────────────────────────────────────────────────────
  return ok([]);
}
