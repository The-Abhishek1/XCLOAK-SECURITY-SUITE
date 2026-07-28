'use client';

import { Fragment, useState, useEffect, useCallback, useRef } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { dpiAPI, agentsAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import {
  Activity, AlertTriangle, Ban, BarChart2, Bell, BellOff, Bot, Check, ChevronDown, ChevronUp,
  Code2, Copy, Database, FileText, Filter, Gauge, Globe, HardDrive, Layers,
  Loader2, Lock, Network, Play, RefreshCw, Search, Server, Shield, ShieldAlert, TrendingUp,
  X, XCircle, Zap,
} from '@/lib/icon-stubs';

// ── Types ─────────────────────────────────────────────────────────────────────

interface DPIFinding {
  id: number;
  agent_id: number;
  finding_type: string;
  severity: string;
  score: number;
  indicator: string;
  description: string;
  mitre_technique: string;
  raw_context: Record<string, unknown>;
  alert_fired: boolean;
  detected_at: string;
}

interface DPISummary {
  total_24h: number;
  alerted_24h: number;
  breakdown: { finding_type: string; severity: string; count: number }[];
}

interface Overview {
  total_findings: number; alerted_findings: number; total_sessions: number;
  malware_detected: number; yara_matches: number; dlp_violations: number;
  protocol_anomalies: number; encrypted_traffic: number; http_sessions: number;
  dns_queries: number; tls_connections: number;
  protocol_dist: { proto: string; count: number }[];
  finding_breakdown: { type: string; count: number }[];
  packets_per_sec: number; engine_status: string; hours: number;
}

interface Session {
  agent_id: number; hostname: string; local_address: string; remote_address: string;
  protocol: string; app_proto: string; sni: string; http_host: string; tls_version: string;
  conn_count: number; first_seen: string; last_seen: string; entropy_avg: number;
  is_encrypted: boolean; is_suspicious: boolean;
}

interface HTTPSession {
  agent_id: number; hostname: string; remote_address: string; http_host: string;
  method: string; path: string; user_agent: string; sni: string; proto: string;
  entropy: number; timestamp: string; is_suspicious: boolean;
}
interface TopEntry { value: string; count: number }
interface HTTPData { sessions: HTTPSession[]; total: number; top_urls: TopEntry[]; top_hosts: TopEntry[]; top_uas: TopEntry[] }

interface DNSFinding {
  id: number; agent_id: number; hostname: string; type: string; severity: string;
  score: number; indicator: string; description: string; detected_at: string;
}
interface DNSData { findings: DNSFinding[]; dga_count: number; tunnel_count: number; top_dns_servers: { dest: string; count: number }[] }

interface TLSSession {
  agent_id: number; hostname: string; remote_address: string; sni: string; tls_version: string;
  cipher: string; proto: string; count: number; is_weak: boolean; timestamp: string;
}
interface JA3Entry { fingerprint: string; label: string; severity: string }
interface TLSData {
  sessions: TLSSession[]; tls_findings: { id: number; indicator: string; severity: string; score: number; description: string; detected_at: string }[];
  ja3_fingerprints: JA3Entry[]; version_breakdown: { version: string; count: number }[];
  cipher_breakdown: { cipher: string; count: number }[]; total: number;
}

interface FileEntry {
  id: number; agent_id: number; hostname: string; finding_type: string; severity: string;
  score: number; indicator: string; description: string; alert_fired: boolean; detected_at: string;
}
interface FilesData { files: FileEntry[]; total: number; yara_matches: number; hash_hits: number; high_entropy: number }

interface DLPFinding {
  id: number; agent_id: number; hostname: string; category: string; severity: string;
  score: number; indicator: string; description: string; detected_at: string;
}
interface DLPData { findings: DLPFinding[]; total: number; by_category: { category: string; count: number }[] }

interface PAFinding {
  id: number; agent_id: number; hostname: string; finding_type: string; severity: string;
  score: number; indicator: string; description: string; detected_at: string;
}
interface ProtocolAnomalyData { findings: PAFinding[]; total: number; by_type: { type: string; count: number }[] }

interface AnalyticsData {
  top_urls: TopEntry[]; top_domains: TopEntry[]; top_user_agents: TopEntry[]; top_ciphers: TopEntry[];
  top_snis: TopEntry[]; top_protocols: TopEntry[]; top_findings: TopEntry[]; high_entropy_conns: TopEntry[];
  hourly_trend: { hour: string; count: number }[];
}

interface PerformanceData {
  packets_per_second: number; connections_last_5m: number; connections_last_1h: number;
  findings_last_min: number; findings_last_1h: number; throughput_estimate: string;
  dropped_packets: number; queue_depth: number; inspection_latency: string; engine_status: string;
  hourly_trend: { hour: string; count: number }[];
}

interface SearchResult {
  source: string; id: number; agent_id: number; hostname: string; type: string;
  value: string; description: string; detected_at: string; score: number;
}

interface AIInsight {
  threat_summary: string; risk_level: string; payload_analysis: string;
  attack_indicators: string[]; mitre_techniques: string[]; data_at_risk: string;
  recommendations: string[]; confidence: number;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const TYPE_META: Record<string, { label: string; icon: React.ElementType; color: string; bg: string }> = {
  dga:                 { label: 'DGA Domain',       icon: Globe,          color: '#a78bfa', bg: 'rgba(167,139,250,0.12)' },
  tls_anomaly:         { label: 'TLS Anomaly',      icon: Lock,           color: '#fbbf24', bg: 'rgba(251,191,36,0.10)' },
  http_pattern:        { label: 'HTTP Pattern',     icon: Code2,          color: '#f87171', bg: 'rgba(248,113,113,0.12)' },
  dns_tunnel:          { label: 'DNS Tunnel',       icon: Network,        color: '#fb923c', bg: 'rgba(251,146,60,0.12)' },
  proto_on_wrong_port: { label: 'Protocol Anomaly', icon: Activity,       color: '#60a5fa', bg: 'rgba(96,165,250,0.12)' },
  icmp_tunnel:         { label: 'ICMP Tunnel',      icon: Network,        color: '#fb923c', bg: 'rgba(251,146,60,0.12)' },
  http_connect_tunnel: { label: 'CONNECT Tunnel',   icon: Network,        color: '#f87171', bg: 'rgba(248,113,113,0.12)' },
  dns_tcp_tunnel:      { label: 'DNS-TCP Tunnel',   icon: Network,        color: '#fb923c', bg: 'rgba(251,146,60,0.12)' },
  smtp_non_standard:   { label: 'SMTP Exfil',       icon: AlertTriangle,  color: '#f87171', bg: 'rgba(248,113,113,0.12)' },
};

const SEV_STYLE: Record<string, { color: string; bg: string }> = {
  critical: { color: 'var(--red)',   bg: 'rgba(248,81,73,0.15)'   },
  high:     { color: '#fb923c',      bg: 'rgba(251,146,60,0.12)'  },
  medium:   { color: '#fbbf24',      bg: 'rgba(251,191,36,0.10)'  },
  low:      { color: 'var(--accent)',bg: 'rgba(37,99,235,0.10)'   },
};

const ALL_TYPES = ['dga','tls_anomaly','http_pattern','dns_tunnel',
  'proto_on_wrong_port','icmp_tunnel','http_connect_tunnel','dns_tcp_tunnel','smtp_non_standard'];
const ALL_SEV = ['critical','high','medium','low'];
const WINDOW_OPTIONS: [number, string][] = [[1,'1h'],[6,'6h'],[24,'24h'],[168,'7d']];
const RISK_COLOR = (s: number) => s >= 80 ? 'var(--red)' : s >= 60 ? 'var(--orange)' : s >= 30 ? 'var(--yellow)' : 'var(--green)';

function typeMeta(t: string) {
  return TYPE_META[t] ?? { label: t, icon: ShieldAlert, color: 'var(--text-3)', bg: 'var(--glass-bg-2)' };
}

function sevStyle(s: string) {
  return SEV_STYLE[s] ?? { color: 'var(--text-2)', bg: 'var(--glass-bg-2)' };
}

// ── Shared sub-components ──────────────────────────────────────────────────────

function SectionHeader({ icon: Icon, title, action }: { icon: any; title: string; action?: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 px-4 py-2.5 shrink-0"
      style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
      <Icon className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--accent)' }} />
      <span className="text-[10px] font-bold uppercase tracking-wider flex-1" style={{ color: 'var(--text-3)' }}>{title}</span>
      {action}
    </div>
  );
}

function Spinner() {
  return <div className="flex justify-center py-6"><Loader2 className="h-5 w-5 animate-spin" style={{ color: 'var(--text-3)' }} /></div>;
}

function Empty({ icon: Icon, text }: { icon: any; text: string }) {
  return (
    <div className="py-8 text-center space-y-2">
      <Icon className="h-8 w-8 mx-auto opacity-15" style={{ color: 'var(--text-3)' }} />
      <p className="text-xs" style={{ color: 'var(--text-3)' }}>{text}</p>
    </div>
  );
}

function ScoreBadge({ score }: { score: number }) {
  const c = RISK_COLOR(score);
  return (
    <span className="text-[10px] px-2 py-0.5 rounded font-bold tabular-nums"
      style={{ background: `${c}18`, color: c, border: `1px solid ${c}44` }}>{score}</span>
  );
}

function Tag({ text, color = 'var(--accent)' }: { text: string; color?: string }) {
  return (
    <span className="text-[9px] px-1.5 py-0.5 rounded font-semibold"
      style={{ background: `${color}18`, color, border: `1px solid ${color}33` }}>{text}</span>
  );
}

function ScoreBar({ score }: { score: number }) {
  const color = score >= 80 ? 'var(--red)' : score >= 60 ? '#fb923c' : score >= 40 ? '#fbbf24' : 'var(--text-3)';
  return (
    <div className="flex items-center gap-2 min-w-[80px]">
      <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--glass-bg-2)' }}>
        <div className="h-full rounded-full transition-all" style={{ width: `${score}%`, background: color }} />
      </div>
      <span className="text-[11px] tabular-nums font-semibold w-6 text-right" style={{ color }}>{score}</span>
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <button onClick={copy} className="shrink-0 transition-colors" title="Copy"
      style={{ color: copied ? 'var(--accent)' : 'var(--text-3)' }}>
      {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  );
}

function TypeBreakdownBar({ breakdown }: { breakdown: DPISummary['breakdown'] }) {
  const totals: Record<string, number> = {};
  for (const b of breakdown) {
    totals[b.finding_type] = (totals[b.finding_type] || 0) + b.count;
  }
  const max = Math.max(...Object.values(totals), 1);
  const sorted = Object.entries(totals).sort((a, b) => b[1] - a[1]).slice(0, 6);

  return (
    <div className="g-card p-4 space-y-2">
      <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
        <Layers className="inline w-3.5 h-3.5 mr-1" />Findings by Type (24h)
      </p>
      {sorted.map(([t, count]) => {
        const m = typeMeta(t);
        const pct = Math.max(3, Math.round((count / max) * 100));
        return (
          <div key={t} className="flex items-center gap-2">
            <span className="text-[11px] w-32 shrink-0 truncate" style={{ color: 'var(--text-2)' }}>{m.label}</span>
            <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: 'var(--glass-bg-2)' }}>
              <div className="h-full rounded-full" style={{ width: `${pct}%`, background: m.color }} />
            </div>
            <span className="text-[11px] tabular-nums w-6 text-right" style={{ color: 'var(--text-3)' }}>{count}</span>
          </div>
        );
      })}
    </div>
  );
}

function TopList({ title, icon: Icon, entries }: { title: string; icon: any; entries: TopEntry[] }) {
  return (
    <div className="g-card flex flex-col overflow-hidden">
      <SectionHeader icon={Icon} title={title} />
      {entries.length === 0 ? <Empty icon={Icon} text="No data in this window." /> : (
        <div className="p-3 space-y-1">
          {entries.map((e, i) => (
            <div key={i} className="flex items-center gap-2 py-1" style={{ borderBottom: i < entries.length - 1 ? '1px solid var(--border)' : undefined }}>
              <span className="text-[11px] font-mono truncate flex-1" style={{ color: 'var(--text-2)' }} title={e.value}>{e.value || '—'}</span>
              <span className="text-[10px] tabular-nums shrink-0" style={{ color: 'var(--text-3)' }}>{e.count}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Findings Detail (raw context expansion) ────────────────────────────────────

function FindingDetail({ description, mitre_technique, raw_context }: { description: string; mitre_technique?: string; raw_context?: Record<string, unknown> }) {
  return (
    <div className="px-4 py-4 space-y-3" style={{ background: 'var(--glass-bg)', borderTop: '1px solid var(--border)' }}>
      <p className="text-xs" style={{ color: 'var(--text-2)' }}>{description}</p>
      {mitre_technique && (
        <a href={`https://attack.mitre.org/techniques/${mitre_technique.replace('.', '/')}/`}
          target="_blank" rel="noopener noreferrer"
          className="inline-flex items-center gap-1 text-xs px-2 py-1 rounded"
          style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
          MITRE {mitre_technique} ↗
        </a>
      )}
      {raw_context && Object.keys(raw_context).length > 0 && (
        <div>
          <p className="text-[10px] uppercase tracking-wider mb-1.5 font-semibold" style={{ color: 'var(--text-3)' }}>Raw Context</p>
          <pre className="text-[11px] rounded-lg p-3 overflow-x-auto leading-relaxed"
            style={{ background: 'var(--bg-0)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>
            {JSON.stringify(raw_context, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

// ── Findings Panel (all dpi_findings, filterable) ──────────────────────────────

function FindingsPanel({ agentMap }: { agentMap: Record<number, string> }) {
  const [findings, setFindings] = useState<DPIFinding[]>([]);
  const [loading,  setLoading]  = useState(true);
  const [search,   setSearch]   = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [sevFilter,  setSevFilter]  = useState('');
  const [alertOnly,  setAlertOnly]  = useState(false);
  const [expanded,   setExpanded]   = useState<Set<number>>(new Set());
  const [page,       setPage]       = useState(0);
  const [hasMore,    setHasMore]    = useState(false);
  const LIMIT = 100;

  const load = useCallback(async (pg = 0) => {
    setLoading(true);
    try {
      const r = await dpiAPI.getFindings({
        finding_type: typeFilter || undefined,
        severity:     sevFilter  || undefined,
        alert_only:   alertOnly  || undefined,
        limit: LIMIT,
        offset: pg * LIMIT,
      });
      const data = (r.data as { findings: DPIFinding[] });
      const newFindings = data.findings || [];
      setFindings(pg === 0 ? newFindings : prev => [...prev, ...newFindings]);
      setHasMore(newFindings.length === LIMIT);
    } finally {
      setLoading(false);
    }
  }, [typeFilter, sevFilter, alertOnly]);

  useEffect(() => { load(0); setPage(0); }, [load]);

  const filtered = findings.filter(f => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      f.description.toLowerCase().includes(q) ||
      f.indicator.toLowerCase().includes(q) ||
      f.finding_type.toLowerCase().includes(q) ||
      (f.mitre_technique || '').toLowerCase().includes(q) ||
      (agentMap[f.agent_id] || '').toLowerCase().includes(q)
    );
  });

  const toggle = (id: number) => setExpanded(prev => {
    const s = new Set(prev);
    s.has(id) ? s.delete(id) : s.add(id);
    return s;
  });

  const loadMore = () => { const next = page + 1; setPage(next); load(next); };

  return (
    <div>
      <div className="p-3 flex flex-wrap items-center gap-2" style={{ borderBottom: '1px solid var(--border)' }}>
        <div className="relative flex-1 min-w-40">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--text-3)' }} />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search indicator, description, agent…" className="g-input pl-8 py-1.5 text-xs w-full" />
        </div>
        <Filter className="w-3.5 h-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />
        <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)} className="g-select text-xs py-1">
          <option value="">All types</option>
          {ALL_TYPES.map(t => <option key={t} value={t}>{typeMeta(t).label}</option>)}
        </select>
        <select value={sevFilter} onChange={e => setSevFilter(e.target.value)} className="g-select text-xs py-1">
          <option value="">All severities</option>
          {ALL_SEV.map(s => <option key={s} value={s} className="capitalize">{s}</option>)}
        </select>
        <label className="flex items-center gap-1.5 text-xs cursor-pointer select-none" style={{ color: 'var(--text-2)' }}>
          <input type="checkbox" checked={alertOnly} onChange={e => setAlertOnly(e.target.checked)} className="accent-red-500" />
          Alerts only
        </label>
        <span className="text-xs ml-auto" style={{ color: 'var(--text-3)' }}>{filtered.length} findings</span>
      </div>

      {loading && findings.length === 0 ? (
        <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
      ) : filtered.length === 0 ? (
        <Empty icon={ShieldAlert} text="No DPI findings match the current filters" />
      ) : (
        <>
          <table className="w-full text-xs">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
                {['Type','Severity','Score','Indicator','Agent','Detected','Alert',''].map(h => (
                  <th key={h} className="px-4 py-2.5 text-left font-semibold" style={{ color: 'var(--text-3)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map(f => {
                const m = typeMeta(f.finding_type);
                const Icon = m.icon;
                const sev = sevStyle(f.severity);
                const isExp = expanded.has(f.id);
                const agentName = agentMap[f.agent_id] || `#${f.agent_id}`;
                return (
                  <Fragment key={f.id}>
                    <tr className="cursor-pointer transition-colors hover:bg-[var(--glass-hover)]"
                      style={{ borderBottom: '1px solid var(--border)' }} onClick={() => toggle(f.id)}>
                      <td className="px-4 py-3">
                        <span className="flex items-center gap-1.5 font-medium">
                          <span className="flex items-center justify-center w-5 h-5 rounded" style={{ background: m.bg }}>
                            <Icon className="w-3 h-3" style={{ color: m.color }} />
                          </span>
                          <span style={{ color: m.color }}>{m.label}</span>
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold capitalize" style={{ background: sev.bg, color: sev.color }}>
                          {f.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3 min-w-[96px]"><ScoreBar score={f.score} /></td>
                      <td className="px-4 py-3 max-w-[200px]">
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono text-[11px] truncate" title={f.indicator} style={{ color: 'var(--text-1)' }}>{f.indicator}</span>
                          <CopyButton text={f.indicator} />
                        </div>
                      </td>
                      <td className="px-4 py-3" style={{ color: 'var(--text-2)' }}>{agentName}</td>
                      <td className="px-4 py-3 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>{timeAgo(f.detected_at)}</td>
                      <td className="px-4 py-3">
                        {f.alert_fired ? (
                          <span className="flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded" style={{ background: 'rgba(248,81,73,0.15)', color: 'var(--red)' }}>
                            <Bell className="w-2.5 h-2.5" /> Alert
                          </span>
                        ) : <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>—</span>}
                      </td>
                      <td className="px-4 py-3" style={{ color: 'var(--text-3)' }}>
                        {isExp ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                      </td>
                    </tr>
                    {isExp && (
                      <tr>
                        <td colSpan={8} className="p-0">
                          <FindingDetail description={f.description} mitre_technique={f.mitre_technique} raw_context={f.raw_context} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
          {hasMore && (
            <div className="px-4 py-3 text-center" style={{ borderTop: '1px solid var(--border)' }}>
              <button onClick={loadMore} disabled={loading} className="g-btn g-btn-ghost text-xs">
                {loading ? 'Loading…' : `Load more (showing ${findings.length})`}
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── Sessions Panel ──────────────────────────────────────────────────────────────

function SessionsPanel({ data, loading }: { data: { sessions: Session[]; total: number } | null; loading: boolean }) {
  if (loading) return <Spinner />;
  if (!data || data.sessions.length === 0) return <Empty icon={Network} text="No active sessions in this window." />;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border)' }}>
            {['Host','Remote','App Proto','SNI / HTTP Host','TLS','Conns','Entropy','Flags'].map(h => (
              <th key={h} className="px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.sessions.slice(0, 200).map((s, i) => (
            <tr key={i} className="hover:bg-[var(--glass-hover)] transition-colors" style={{ borderBottom: '1px solid var(--border)' }}>
              <td className="px-3 py-2 text-[11px]" style={{ color: 'var(--text-2)' }}>{s.hostname}</td>
              <td className="px-3 py-2 font-mono text-[11px]" style={{ color: s.is_suspicious ? 'var(--red)' : 'var(--text-1)' }}>{s.remote_address}</td>
              <td className="px-3 py-2"><Tag text={(s.app_proto || s.protocol || 'tcp').toUpperCase()} /></td>
              <td className="px-3 py-2 font-mono text-[10px] max-w-[180px] truncate" style={{ color: 'var(--text-3)' }}>{s.sni || s.http_host || '—'}</td>
              <td className="px-3 py-2 text-[10px]" style={{ color: s.is_encrypted ? 'var(--green)' : 'var(--text-3)' }}>{s.tls_version || (s.is_encrypted ? 'yes' : '—')}</td>
              <td className="px-3 py-2 tabular-nums text-[11px]" style={{ color: 'var(--text-2)' }}>{s.conn_count}</td>
              <td className="px-3 py-2 tabular-nums text-[11px]" style={{ color: s.entropy_avg > 70 ? 'var(--orange)' : 'var(--text-3)' }}>{s.entropy_avg}</td>
              <td className="px-3 py-2">{s.is_suspicious && <AlertTriangle className="h-3.5 w-3.5" style={{ color: 'var(--red)' }} />}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── HTTP Panel ──────────────────────────────────────────────────────────────────

function HTTPPanel({ data, loading, q, onSearch }: { data: HTTPData | null; loading: boolean; q: string; onSearch: (v: string) => void }) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
      <div className="lg:col-span-2 g-card overflow-hidden">
        <div className="p-3 flex items-center gap-2" style={{ borderBottom: '1px solid var(--border)' }}>
          <Search className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
          <input value={q} onChange={e => onSearch(e.target.value)} placeholder="Filter by host, path, user-agent…" className="g-input flex-1 text-xs" />
        </div>
        {loading ? <Spinner /> : !data || data.sessions.length === 0 ? <Empty icon={Code2} text="No HTTP traffic in this window." /> : (
          <div className="overflow-x-auto" style={{ maxHeight: 460, overflowY: 'auto' }}>
            <table className="w-full text-xs">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['Host','Method','Path','User-Agent','Entropy','Detected',''].map(h => (
                    <th key={h} className="px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.sessions.map((s, i) => (
                  <tr key={i} className="hover:bg-[var(--glass-hover)]" style={{ borderBottom: '1px solid var(--border)' }}>
                    <td className="px-3 py-2 font-mono text-[11px]" style={{ color: 'var(--text-1)' }}>{s.http_host || s.sni || '—'}</td>
                    <td className="px-3 py-2"><Tag text={s.method || 'GET'} /></td>
                    <td className="px-3 py-2 font-mono text-[10px] max-w-[220px] truncate" style={{ color: s.is_suspicious ? 'var(--red)' : 'var(--text-2)' }} title={s.path}>{s.path}</td>
                    <td className="px-3 py-2 text-[10px] max-w-[160px] truncate" style={{ color: 'var(--text-3)' }} title={s.user_agent}>{s.user_agent || '—'}</td>
                    <td className="px-3 py-2 tabular-nums text-[11px]" style={{ color: s.entropy > 70 ? 'var(--orange)' : 'var(--text-3)' }}>{s.entropy}</td>
                    <td className="px-3 py-2 whitespace-nowrap text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(s.timestamp)}</td>
                    <td className="px-3 py-2">{s.is_suspicious && <AlertTriangle className="h-3.5 w-3.5" style={{ color: 'var(--red)' }} />}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <div className="space-y-3">
        <TopList title="Top Paths" icon={Code2} entries={data?.top_urls ?? []} />
        <TopList title="Top Hosts" icon={Globe} entries={data?.top_hosts ?? []} />
        <TopList title="Top User-Agents" icon={FileText} entries={data?.top_uas ?? []} />
      </div>
    </div>
  );
}

// ── DNS Panel ────────────────────────────────────────────────────────────────

function DNSPanel({ data, loading }: { data: DNSData | null; loading: boolean }) {
  if (loading) return <Spinner />;
  if (!data) return <Empty icon={Globe} text="No DNS data." />;
  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
      <div className="lg:col-span-2 g-card overflow-hidden">
        <SectionHeader icon={Globe} title={`DNS Findings (DGA: ${data.dga_count} · Tunnels: ${data.tunnel_count})`} />
        {data.findings.length === 0 ? <Empty icon={Globe} text="No DNS anomalies detected." /> : (
          <div className="p-3 space-y-1.5" style={{ maxHeight: 460, overflowY: 'auto' }}>
            {data.findings.map(f => {
              const sev = sevStyle(f.severity);
              return (
                <div key={f.id} className="rounded-lg px-3 py-2" style={{ background: 'var(--glass-bg)', border: `1px solid ${sev.color}33` }}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{f.hostname || `#${f.agent_id}`}</span>
                    <ScoreBadge score={f.score} />
                  </div>
                  <p className="text-[10px] mt-0.5 font-mono" style={{ color: sev.color }}>{f.indicator}</p>
                  <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{f.description}</p>
                </div>
              );
            })}
          </div>
        )}
      </div>
      <TopList title="Top DNS Servers" icon={Server} entries={data.top_dns_servers.map(d => ({ value: d.dest, count: d.count }))} />
    </div>
  );
}

// ── TLS Panel ────────────────────────────────────────────────────────────────

function TLSPanel({ data, loading }: { data: TLSData | null; loading: boolean }) {
  if (loading) return <Spinner />;
  if (!data) return <Empty icon={Lock} text="No TLS data." />;
  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
      <div className="lg:col-span-2 space-y-3">
        <div className="g-card overflow-hidden">
          <SectionHeader icon={AlertTriangle} title="TLS Anomaly Findings" />
          {data.tls_findings.length === 0 ? <Empty icon={AlertTriangle} text="No TLS anomalies detected." /> : (
            <div className="p-3 space-y-1.5">
              {data.tls_findings.map(f => {
                const sev = sevStyle(f.severity);
                return (
                  <div key={f.id} className="rounded-lg px-3 py-2" style={{ background: 'var(--glass-bg)', border: `1px solid ${sev.color}33` }}>
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-mono truncate" style={{ color: 'var(--text-1)' }}>{f.indicator}</span>
                      <ScoreBadge score={f.score} />
                    </div>
                    <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{f.description} · {timeAgo(f.detected_at)}</p>
                  </div>
                );
              })}
            </div>
          )}
        </div>
        <div className="g-card overflow-hidden">
          <SectionHeader icon={Lock} title="TLS Sessions" />
          {data.sessions.length === 0 ? <Empty icon={Lock} text="No TLS sessions in this window." /> : (
            <div className="overflow-x-auto" style={{ maxHeight: 320, overflowY: 'auto' }}>
              <table className="w-full text-xs">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    {['Host','SNI','Version','Cipher','Conns',''].map(h => (
                      <th key={h} className="px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.sessions.map((s, i) => (
                    <tr key={i} className="hover:bg-[var(--glass-hover)]" style={{ borderBottom: '1px solid var(--border)' }}>
                      <td className="px-3 py-2 text-[11px]" style={{ color: 'var(--text-2)' }}>{s.hostname}</td>
                      <td className="px-3 py-2 font-mono text-[10px] max-w-[180px] truncate" style={{ color: 'var(--text-1)' }}>{s.sni || '—'}</td>
                      <td className="px-3 py-2 text-[10px]" style={{ color: s.is_weak ? 'var(--red)' : 'var(--text-2)' }}>{s.tls_version || '—'}</td>
                      <td className="px-3 py-2 font-mono text-[10px] max-w-[140px] truncate" style={{ color: 'var(--text-3)' }} title={s.cipher}>{s.cipher || '—'}</td>
                      <td className="px-3 py-2 tabular-nums text-[11px]" style={{ color: 'var(--text-2)' }}>{s.count}</td>
                      <td className="px-3 py-2">{s.is_weak && <Tag text="WEAK" color="var(--red)" />}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
        <div className="g-card overflow-hidden">
          <SectionHeader icon={ShieldAlert} title="Known Malicious JA3 Fingerprints" />
          {data.ja3_fingerprints.length === 0 ? <Empty icon={ShieldAlert} text="No JA3 fingerprint entries." /> : (
            <div className="p-3 space-y-1.5">
              {data.ja3_fingerprints.map((j, i) => {
                const sev = sevStyle(j.severity);
                return (
                  <div key={i} className="flex items-center gap-2 py-1" style={{ borderBottom: '1px solid var(--border)' }}>
                    <span className="font-mono text-[10px] truncate flex-1" style={{ color: 'var(--text-2)' }} title={j.fingerprint}>{j.fingerprint}</span>
                    <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{j.label}</span>
                    <span className="px-1.5 py-0.5 rounded text-[9px] font-bold capitalize" style={{ background: sev.bg, color: sev.color }}>{j.severity}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
      <div className="space-y-3">
        <TopList title="TLS Version Breakdown" icon={Lock} entries={data.version_breakdown.map(v => ({ value: v.version, count: v.count }))} />
        <TopList title="Cipher Suite Breakdown" icon={Shield} entries={data.cipher_breakdown.map(c => ({ value: c.cipher, count: c.count }))} />
      </div>
    </div>
  );
}

// ── Files Panel ──────────────────────────────────────────────────────────────

function FilesPanel({ data, loading }: { data: FilesData | null; loading: boolean }) {
  if (loading) return <Spinner />;
  if (!data || data.files.length === 0) return <Empty icon={HardDrive} text="No file/malware findings in this window." />;
  return (
    <div className="p-3 space-y-3">
      <div className="grid grid-cols-3 gap-2">
        {[
          { l: 'YARA Matches', v: data.yara_matches, c: data.yara_matches > 0 ? 'var(--red)' : 'var(--text-3)' },
          { l: 'Hash Hits', v: data.hash_hits, c: data.hash_hits > 0 ? 'var(--red)' : 'var(--text-3)' },
          { l: 'High Entropy', v: data.high_entropy, c: data.high_entropy > 0 ? 'var(--orange)' : 'var(--text-3)' },
        ].map(s => (
          <div key={s.l} className="rounded-lg px-3 py-2" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
            <p className="text-[9px] uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>{s.l}</p>
            <p className="text-sm font-bold tabular-nums" style={{ color: s.c }}>{s.v}</p>
          </div>
        ))}
      </div>
      {data.files.map(f => {
        const sev = sevStyle(f.severity);
        return (
          <div key={f.id} className="rounded-lg px-3 py-2.5" style={{ background: 'var(--glass-bg)', border: `1px solid ${sev.color}33` }}>
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{f.hostname || `#${f.agent_id}`}</span>
                <span className="px-1.5 py-0.5 rounded text-[9px] font-bold capitalize" style={{ background: sev.bg, color: sev.color }}>{f.severity}</span>
                <Tag text={f.finding_type} />
                {f.alert_fired && <Tag text="ALERTED" color="var(--red)" />}
              </div>
              <ScoreBadge score={f.score} />
            </div>
            <p className="text-[10px] mt-1 font-mono" style={{ color: 'var(--text-2)' }}>{f.indicator}</p>
            <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{f.description} · {timeAgo(f.detected_at)}</p>
          </div>
        );
      })}
    </div>
  );
}

// ── DLP Panel ────────────────────────────────────────────────────────────────

function DLPPanel({ data, loading }: { data: DLPData | null; loading: boolean }) {
  if (loading) return <Spinner />;
  if (!data || data.findings.length === 0) return <Empty icon={Database} text="No DLP findings in this window." />;
  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
      <div className="lg:col-span-2 space-y-1.5 p-1">
        {data.findings.map(f => {
          const sev = sevStyle(f.severity);
          return (
            <div key={f.id} className="rounded-lg px-3 py-2.5" style={{ background: 'var(--glass-bg)', border: `1px solid ${sev.color}33` }}>
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{f.hostname || `#${f.agent_id}`}</span>
                <span className="px-1.5 py-0.5 rounded text-[9px] font-bold capitalize" style={{ background: sev.bg, color: sev.color }}>{f.category}</span>
              </div>
              <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{f.description} · {timeAgo(f.detected_at)}</p>
            </div>
          );
        })}
      </div>
      <TopList title="By Category" icon={Database} entries={data.by_category.map(c => ({ value: c.category, count: c.count }))} />
    </div>
  );
}

// ── Protocol Anomalies Panel ────────────────────────────────────────────────────

function ProtocolAnomaliesPanel({ data, loading }: { data: ProtocolAnomalyData | null; loading: boolean }) {
  if (loading) return <Spinner />;
  if (!data || data.findings.length === 0) return <Empty icon={Activity} text="No protocol anomalies in this window." />;
  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
      <div className="lg:col-span-2 space-y-1.5 p-1">
        {data.findings.map(f => {
          const m = typeMeta(f.finding_type);
          const sev = sevStyle(f.severity);
          return (
            <div key={f.id} className="rounded-lg px-3 py-2.5 flex items-start gap-2" style={{ background: 'var(--glass-bg)', border: `1px solid ${sev.color}33` }}>
              <span className="flex items-center justify-center w-5 h-5 rounded shrink-0" style={{ background: m.bg }}>
                <m.icon className="w-3 h-3" style={{ color: m.color }} />
              </span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{f.hostname || `#${f.agent_id}`} · {m.label}</span>
                  <ScoreBadge score={f.score} />
                </div>
                <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{f.description} · {timeAgo(f.detected_at)}</p>
              </div>
            </div>
          );
        })}
      </div>
      <TopList title="By Type" icon={Activity} entries={data.by_type.map(t => ({ value: typeMeta(t.type).label, count: t.count }))} />
    </div>
  );
}

// ── Analytics Panel ────────────────────────────────────────────────────────────

function AnalyticsPanel({ data, loading }: { data: AnalyticsData | null; loading: boolean }) {
  if (loading) return <Spinner />;
  if (!data) return <Empty icon={TrendingUp} text="No analytics data." />;
  const maxTrend = Math.max(...data.hourly_trend.map(h => h.count), 1);
  return (
    <div className="space-y-3">
      <div className="g-card p-4">
        <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>
          <TrendingUp className="inline w-3.5 h-3.5 mr-1" />Findings Trend
        </p>
        {data.hourly_trend.length === 0 ? <Empty icon={TrendingUp} text="No findings recorded yet." /> : (
          <div className="flex items-end gap-1 h-24">
            {data.hourly_trend.map((h, i) => (
              <div key={i} className="flex-1 flex flex-col items-center gap-1" title={`${h.hour}: ${h.count}`}>
                <div className="w-full rounded-t" style={{ height: `${Math.max(4, (h.count / maxTrend) * 80)}px`, background: 'var(--accent)' }} />
                <span className="text-[8px]" style={{ color: 'var(--text-3)' }}>{h.hour}</span>
              </div>
            ))}
          </div>
        )}
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
        <TopList title="Top URLs" icon={Code2} entries={data.top_urls} />
        <TopList title="Top Domains" icon={Globe} entries={data.top_domains} />
        <TopList title="Top User-Agents" icon={FileText} entries={data.top_user_agents} />
        <TopList title="Top SNIs" icon={Lock} entries={data.top_snis} />
        <TopList title="Top Ciphers" icon={Shield} entries={data.top_ciphers} />
        <TopList title="Top Protocols" icon={Layers} entries={data.top_protocols} />
        <TopList title="Top Finding Types" icon={ShieldAlert} entries={data.top_findings} />
        <TopList title="High-Entropy Destinations" icon={AlertTriangle} entries={data.high_entropy_conns} />
      </div>
    </div>
  );
}

// ── Performance Panel ───────────────────────────────────────────────────────────

function PerformancePanel({ data, loading }: { data: PerformanceData | null; loading: boolean }) {
  if (loading) return <Spinner />;
  if (!data) return <Empty icon={Gauge} text="No performance data." />;
  const maxTrend = Math.max(...data.hourly_trend.map(h => h.count), 1);
  return (
    <div className="space-y-3 p-1">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {[
          { l: 'Packets/sec (est)', v: data.packets_per_second, c: 'var(--accent)' },
          { l: 'Conns (5m)', v: data.connections_last_5m, c: 'var(--text-1)' },
          { l: 'Conns (1h)', v: data.connections_last_1h, c: 'var(--text-1)' },
          { l: 'Findings (1m)', v: data.findings_last_min, c: data.findings_last_min > 0 ? 'var(--red)' : 'var(--text-3)' },
          { l: 'Findings (1h)', v: data.findings_last_1h, c: data.findings_last_1h > 0 ? 'var(--orange)' : 'var(--text-3)' },
          { l: 'Inspection Latency', v: data.inspection_latency, c: 'var(--green)' },
          { l: 'Engine Status', v: data.engine_status, c: 'var(--green)' },
          { l: 'Queue Depth', v: data.queue_depth, c: 'var(--text-3)' },
        ].map(s => (
          <div key={s.l} className="g-card p-3">
            <p className="text-[9px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>{s.l}</p>
            <p className="text-lg font-bold tabular-nums capitalize" style={{ color: s.c }}>{s.v}</p>
          </div>
        ))}
      </div>
      <div className="g-card p-4">
        <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>
          <Activity className="inline w-3.5 h-3.5 mr-1" />Connection Volume (last 12h)
        </p>
        {data.hourly_trend.length === 0 ? <Empty icon={Activity} text="No connection data yet." /> : (
          <div className="flex items-end gap-1 h-24">
            {data.hourly_trend.map((h, i) => (
              <div key={i} className="flex-1 flex flex-col items-center gap-1" title={`${h.hour}: ${h.count}`}>
                <div className="w-full rounded-t" style={{ height: `${Math.max(4, (h.count / maxTrend) * 80)}px`, background: 'var(--green)' }} />
                <span className="text-[8px]" style={{ color: 'var(--text-3)' }}>{h.hour}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Search Panel ─────────────────────────────────────────────────────────────

function SearchPanel() {
  const [q, setQ] = useState('');
  const [results, setResults] = useState<SearchResult[] | null>(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    if (!q.trim()) return;
    setLoading(true);
    try {
      const r = await dpiAPI.search(q.trim());
      setResults((r.data as { results: SearchResult[] })?.results ?? []);
    } finally { setLoading(false); }
  };

  return (
    <div className="p-4 space-y-3">
      <div className="flex items-center gap-2">
        <Search className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
        <input value={q} onChange={e => setQ(e.target.value)} onKeyDown={e => e.key === 'Enter' && run()}
          placeholder="Search indicators, hosts, paths, SNIs across the last 7 days…" className="g-input flex-1 text-xs" />
        <button onClick={run} disabled={!q.trim() || loading} className="g-btn g-btn-primary text-xs px-3">
          {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : 'Search'}
        </button>
      </div>
      {results === null ? (
        <Empty icon={Search} text="Search DPI findings and network events by indicator, host, path, or SNI." />
      ) : results.length === 0 ? (
        <Empty icon={Search} text={`No results for "${q}"`} />
      ) : (
        <div className="space-y-1.5">
          {results.map((r, i) => (
            <div key={i} className="rounded-lg px-3 py-2" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
              <div className="flex items-center gap-2">
                <Tag text={r.source === 'dpi_finding' ? 'Finding' : 'Network Event'} color={r.source === 'dpi_finding' ? 'var(--red)' : 'var(--accent)'} />
                <span className="text-xs font-mono truncate" style={{ color: 'var(--text-1)' }}>{r.value}</span>
              </div>
              <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{r.hostname || `#${r.agent_id}`} · {r.type} · {timeAgo(r.detected_at)}</p>
              {r.description && <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-2)' }}>{r.description}</p>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── AI Insights Panel ──────────────────────────────────────────────────────────

function AIInsightsPanel() {
  const [ai, setAi] = useState<AIInsight | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [ctx, setCtx] = useState('');

  const run = async () => {
    setLoading(true); setError(''); setAi(null);
    try {
      const r = await dpiAPI.aiInspect({ context: ctx });
      setAi(r.data as AIInsight);
    } catch { setError('AI analysis unavailable'); }
    finally { setLoading(false); }
  };

  return (
    <div className="p-4 space-y-3">
      {!ai && !loading && (
        <div className="space-y-2">
          <textarea value={ctx} onChange={e => setCtx(e.target.value)}
            placeholder="Optional context: which hosts/sessions to focus on…" rows={2}
            className="g-input w-full text-xs resize-none" />
          <button onClick={run} className="g-btn g-btn-primary text-xs w-full justify-center">
            <Bot className="h-3.5 w-3.5" /> Run AI DPI Analysis
          </button>
        </div>
      )}
      {loading && <div className="text-center py-6 space-y-2">
        <Loader2 className="h-6 w-6 animate-spin mx-auto" style={{ color: 'var(--accent)' }} />
        <p className="text-xs" style={{ color: 'var(--text-3)' }}>Analyzing packet inspection findings…</p>
      </div>}
      {error && <Empty icon={AlertTriangle} text={error} />}
      {ai && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <ScoreBadge score={ai.confidence} />
            <Tag text={ai.risk_level?.toUpperCase()} color={RISK_COLOR(ai.risk_level === 'critical' ? 90 : ai.risk_level === 'high' ? 70 : ai.risk_level === 'medium' ? 40 : 10)} />
          </div>
          <p className="text-xs" style={{ color: 'var(--text-2)' }}>{ai.threat_summary}</p>
          {ai.payload_analysis && <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{ai.payload_analysis}</p>}
          {ai.data_at_risk && <p className="text-[11px]" style={{ color: 'var(--orange)' }}>Data at risk: {ai.data_at_risk}</p>}
          {ai.attack_indicators?.length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-wider mb-1 font-semibold" style={{ color: 'var(--text-3)' }}>Attack Indicators</p>
              <div className="flex flex-wrap gap-1.5">{ai.attack_indicators.map((x, i) => <Tag key={i} text={x} color="var(--red)" />)}</div>
            </div>
          )}
          {ai.mitre_techniques?.length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-wider mb-1 font-semibold" style={{ color: 'var(--text-3)' }}>MITRE Techniques</p>
              <div className="flex flex-wrap gap-1.5">{ai.mitre_techniques.map((x, i) => <Tag key={i} text={x} color="var(--accent)" />)}</div>
            </div>
          )}
          {ai.recommendations?.length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-wider mb-1 font-semibold" style={{ color: 'var(--text-3)' }}>Recommendations</p>
              <ul className="space-y-1">{ai.recommendations.map((x, i) => <li key={i} className="text-[11px]" style={{ color: 'var(--text-2)' }}>• {x}</li>)}</ul>
            </div>
          )}
          <button onClick={() => setAi(null)} className="g-btn g-btn-ghost text-xs">Run again</button>
        </div>
      )}
    </div>
  );
}

// ── Response Actions Panel ──────────────────────────────────────────────────────

const RESPONSE_ACTIONS = [
  { key: 'block_ip',          label: 'Block IP',           icon: Ban,        color: 'var(--red)',    needs: 'ip',          placeholder: 'IP address' },
  { key: 'block_domain',      label: 'Block Domain',       icon: Globe,      color: 'var(--red)',    needs: 'domain',      placeholder: 'domain.com' },
  { key: 'block_url',         label: 'Block URL',          icon: Ban,        color: 'var(--red)',    needs: 'url',         placeholder: 'https://…' },
  { key: 'block_ja3',         label: 'Block JA3',          icon: Lock,       color: 'var(--red)',    needs: 'ja3',         placeholder: 'JA3 fingerprint' },
  { key: 'push_firewall_rule',label: 'Push Firewall Rule', icon: Shield,     color: 'var(--orange)', needs: 'ip',          placeholder: 'Target IP' },
  { key: 'kill_session',      label: 'Kill Session',       icon: XCircle,    color: 'var(--orange)', needs: 'session_id',  placeholder: 'Session ID', needs2: 'agent_id', placeholder2: 'Agent ID' },
  { key: 'create_alert',      label: 'Create Alert',       icon: Bell,       color: 'var(--accent)', needs: 'reason',      placeholder: 'Description' },
  { key: 'create_incident',   label: 'Create Incident',    icon: ShieldAlert,color: 'var(--accent)', needs: 'reason',      placeholder: 'Description' },
  { key: 'run_playbook',      label: 'Run SOAR Playbook',  icon: Play,       color: 'var(--accent)', needs: 'playbook_id', placeholder: 'Playbook ID' },
] as const;

function ResponseActionsPanel({ onToast }: { onToast: (m: string) => void }) {
  const [active, setActive] = useState<string | null>(null);
  const [param, setParam] = useState('');
  const [param2, setParam2] = useState('');
  const [reason, setReason] = useState('');
  const [running, setRunning] = useState<string | null>(null);

  const dispatch = async (key: string, a: typeof RESPONSE_ACTIONS[number]) => {
    setRunning(key);
    try {
      const body: Record<string, unknown> = { reason };
      if (a.needs === 'ip') body.ip = param;
      else if (a.needs === 'domain') body.domain = param;
      else if (a.needs === 'url') body.url = param;
      else if (a.needs === 'ja3') body.ja3 = param;
      else if (a.needs === 'session_id') body.session_id = param;
      else if (a.needs === 'playbook_id') body.playbook_id = parseInt(param) || 0;
      else if (a.needs === 'reason') body.reason = param;
      if ('needs2' in a && a.needs2 === 'agent_id') body.agent_id = parseInt(param2) || 0;
      const r = await dpiAPI.responseAction(key, body);
      onToast((r.data as any)?.result ?? `${key} executed`);
      setActive(null); setParam(''); setParam2('');
    } catch (err) {
      const msg = (err as any)?.response?.data?.error;
      onToast(msg || 'Action failed');
    }
    finally { setRunning(null); }
  };

  return (
    <div className="p-3 space-y-3">
      {active && (() => {
        const a = RESPONSE_ACTIONS.find(x => x.key === active)!;
        const needs2 = 'needs2' in a ? a.needs2 : undefined;
        const placeholder2 = 'placeholder2' in a ? a.placeholder2 : undefined;
        return a.needs && (
          <div className="flex items-center gap-2 rounded-lg px-3 py-2.5"
            style={{ background: 'var(--glass-bg)', border: '1px solid var(--accent-border)' }}>
            <input value={param} onChange={e => setParam(e.target.value)}
              placeholder={a.placeholder} className="g-input flex-1 text-xs"
              onKeyDown={e => e.key === 'Enter' && param && (!needs2 || param2) && dispatch(active, a)} />
            {needs2 && (
              <input value={param2} onChange={e => setParam2(e.target.value)}
                placeholder={placeholder2} className="g-input flex-1 text-xs"
                onKeyDown={e => e.key === 'Enter' && param && param2 && dispatch(active, a)} />
            )}
            {a.needs !== 'reason' && (
              <input value={reason} onChange={e => setReason(e.target.value)}
                placeholder="Reason…" className="g-input flex-1 text-xs" />
            )}
            <button onClick={() => dispatch(active, a)} disabled={!param || (!!needs2 && !param2) || running !== null} className="g-btn g-btn-primary text-xs px-3">
              {running === active ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : 'Execute'}
            </button>
            <button onClick={() => { setActive(null); setParam(''); setParam2(''); }} className="g-btn g-btn-ghost text-xs px-2">
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        );
      })()}
      <div className="grid grid-cols-3 gap-1.5">
        {RESPONSE_ACTIONS.map(a => (
          <button key={a.key}
            onClick={() => { setActive(a.key); setParam(''); setParam2(''); setReason(''); }}
            disabled={running !== null}
            className="flex items-center gap-2 rounded-lg px-3 py-2 text-left hover:bg-[var(--glass-hover)] transition-colors"
            style={{ background: 'var(--glass-bg)', border: `1px solid ${a.color}33` }}>
            {running === a.key
              ? <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" style={{ color: a.color }} />
              : <a.icon className="h-3.5 w-3.5 shrink-0" style={{ color: a.color }} />}
            <span className="text-[10px] font-medium" style={{ color: 'var(--text-1)' }}>{a.label}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

type ViewTab = 'overview' | 'findings' | 'sessions' | 'http' | 'dns' | 'tls' | 'files' |
               'dlp' | 'protocols' | 'analytics' | 'performance' | 'search' | 'ai' | 'response';

export default function DPIPage() {
  const [summary,     setSummary]     = useState<DPISummary | null>(null);
  const [overview,    setOverview]    = useState<Overview | null>(null);
  const [sessions,    setSessions]    = useState<{ sessions: Session[]; total: number } | null>(null);
  const [http,        setHttp]        = useState<HTTPData | null>(null);
  const [httpQ,       setHttpQ]       = useState('');
  const [dns,         setDns]         = useState<DNSData | null>(null);
  const [tls,         setTls]         = useState<TLSData | null>(null);
  const [files,       setFiles]       = useState<FilesData | null>(null);
  const [dlp,         setDlp]         = useState<DLPData | null>(null);
  const [protocols,   setProtocols]   = useState<ProtocolAnomalyData | null>(null);
  const [analytics,   setAnalytics]   = useState<AnalyticsData | null>(null);
  const [performance, setPerformance] = useState<PerformanceData | null>(null);
  const [agentMap,    setAgentMap]    = useState<Record<number, string>>({});

  const [loadingO, setLoadingO] = useState(true);
  const [loadingS, setLoadingS] = useState(false);
  const [loadingH, setLoadingH] = useState(false);
  const [loadingD, setLoadingD] = useState(false);
  const [loadingT, setLoadingT] = useState(false);
  const [loadingF, setLoadingF] = useState(false);
  const [loadingL, setLoadingL] = useState(false);
  const [loadingP, setLoadingP] = useState(false);
  const [loadingA, setLoadingA] = useState(false);
  const [loadingPerf, setLoadingPerf] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const [view, setView] = useState<ViewTab>('overview');
  const [hours, setHours] = useState(24);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Guards against a stale in-flight request (for a previously-selected
  // window) resolving after a newer one and clobbering the UI.
  const hoursRef = useRef(hours);
  hoursRef.current = hours;

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 4000); };

  const loadAgents = useCallback(async () => {
    try {
      const r = await agentsAPI.getAll();
      const agents: { id: number; hostname: string }[] = r.data?.agents || r.data || [];
      const m: Record<number, string> = {};
      for (const a of agents) m[a.id] = a.hostname;
      setAgentMap(m);
    } catch {}
  }, []);

  const loadOverview = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    setLoadingO(true);
    const requestedFor = hours;
    const [sRes, oRes] = await Promise.all([dpiAPI.getSummary(), dpiAPI.getOverview(hours)]);
    if (requestedFor === hoursRef.current) {
      if (sRes.data) setSummary(sRes.data as DPISummary);
      if (oRes.data) setOverview(oRes.data as Overview);
      setLoadingO(false); setRefreshing(false);
    }
  }, [hours]);

  useEffect(() => { loadOverview(); loadAgents(); }, [loadOverview, loadAgents]);

  useEffect(() => {
    if (timerRef.current) clearInterval(timerRef.current);
    if (autoRefresh) timerRef.current = setInterval(() => loadOverview(), 30_000);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [autoRefresh, loadOverview]);

  // Lazy-load panels when the tab is first opened; reload when the window changes.
  useEffect(() => {
    if (view === 'sessions')  { setLoadingS(true);   dpiAPI.getSessions({ hours }).then(r => { setSessions(r.data as any); setLoadingS(false); }); }
    if (view === 'http')      { setLoadingH(true);   dpiAPI.getHTTPInspection({ hours, q: httpQ || undefined }).then(r => { setHttp(r.data as HTTPData); setLoadingH(false); }); }
    if (view === 'dns')       { setLoadingD(true);   dpiAPI.getDNSInspection(hours).then(r => { setDns(r.data as DNSData); setLoadingD(false); }); }
    if (view === 'tls')       { setLoadingT(true);   dpiAPI.getTLSInspection(hours).then(r => { setTls(r.data as TLSData); setLoadingT(false); }); }
    if (view === 'files')     { setLoadingF(true);   dpiAPI.getFiles(hours).then(r => { setFiles(r.data as FilesData); setLoadingF(false); }); }
    if (view === 'dlp')       { setLoadingL(true);   dpiAPI.getDLP(hours).then(r => { setDlp(r.data as DLPData); setLoadingL(false); }); }
    if (view === 'protocols') { setLoadingP(true);   dpiAPI.getProtocolAnomalies(hours).then(r => { setProtocols(r.data as ProtocolAnomalyData); setLoadingP(false); }); }
    if (view === 'analytics') { setLoadingA(true);   dpiAPI.getAnalytics(hours).then(r => { setAnalytics(r.data as AnalyticsData); setLoadingA(false); }); }
    if (view === 'performance') { setLoadingPerf(true); dpiAPI.getPerformance().then(r => { setPerformance(r.data as PerformanceData); setLoadingPerf(false); }); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view, hours]);

  // Debounced HTTP search
  useEffect(() => {
    if (view !== 'http') return;
    const t = setTimeout(() => {
      setLoadingH(true);
      dpiAPI.getHTTPInspection({ hours, q: httpQ || undefined }).then(r => { setHttp(r.data as HTTPData); setLoadingH(false); });
    }, 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [httpQ]);

  const TABS: { id: ViewTab; label: string; icon: any }[] = [
    { id: 'overview',    label: 'Overview',        icon: BarChart2 },
    { id: 'findings',    label: 'Findings',         icon: ShieldAlert },
    { id: 'sessions',    label: 'Sessions',         icon: Network },
    { id: 'http',        label: 'HTTP',             icon: Code2 },
    { id: 'dns',         label: 'DNS',              icon: Globe },
    { id: 'tls',         label: 'TLS',              icon: Lock },
    { id: 'files',       label: 'Files & Malware',  icon: HardDrive },
    { id: 'dlp',         label: 'DLP',              icon: Database },
    { id: 'protocols',   label: 'Protocol Anomalies', icon: Activity },
    { id: 'analytics',   label: 'Analytics',        icon: TrendingUp },
    { id: 'performance', label: 'Performance',      icon: Gauge },
    { id: 'search',      label: 'Search',           icon: Search },
    { id: 'ai',          label: 'AI Insights',      icon: Bot },
    { id: 'response',    label: 'Response',         icon: Zap },
  ];

  const CARD = 'g-card flex flex-col overflow-hidden';
  const critHigh = summary?.breakdown.filter(b => b.severity === 'critical' || b.severity === 'high')
    .reduce((a, b) => a + b.count, 0) ?? 0;

  const subtitleParts = [];
  if (summary) {
    subtitleParts.push(`${summary.total_24h} findings in 24h`);
    if (summary.alerted_24h > 0) subtitleParts.push(`${summary.alerted_24h} alerts fired`);
  }

  return (
    <RootLayout
      title="Deep Packet Inspection"
      subtitle={subtitleParts.join(' · ') || 'L7 threat findings'}
      actions={
        <div className="flex items-center gap-2">
          <button onClick={() => setAutoRefresh(r => !r)} title={autoRefresh ? 'Disable auto-refresh' : 'Auto-refresh every 30s'}
            className="g-btn g-btn-ghost text-xs" style={{ color: autoRefresh ? 'var(--accent)' : 'var(--text-3)' }}>
            {autoRefresh ? <Bell className="h-3.5 w-3.5" /> : <BellOff className="h-3.5 w-3.5" />}
          </button>
          <button onClick={() => loadOverview(true)} className="g-btn g-btn-ghost text-xs">
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
      }>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 px-4 py-2.5 rounded-lg text-sm font-medium shadow-xl"
          style={{ background: 'var(--accent)', color: '#000' }}>{toast}</div>
      )}

      <div className="space-y-4">
        {/* KPI Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: 'Findings (24h)', val: summary?.total_24h ?? '—', color: 'var(--text-1)' },
            { label: 'Alerts Fired',   val: summary?.alerted_24h ?? '—', color: 'var(--red)' },
            { label: 'Types Active',   val: summary ? new Set(summary.breakdown.map(b => b.finding_type)).size : '—', color: 'var(--accent)' },
            { label: 'Crit + High',    val: summary ? critHigh : '—', color: '#fb923c' },
          ].map(s => (
            <div key={s.label} className="g-card p-4">
              <p className="text-[10px] uppercase tracking-wider mb-1 font-medium" style={{ color: 'var(--text-3)' }}>{s.label}</p>
              <p className="text-2xl font-bold" style={{ color: s.color }}>{s.val}</p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex items-center gap-1 overflow-x-auto pb-1">
          {TABS.map(t => (
            <button key={t.id} onClick={() => setView(t.id)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors"
              style={{
                background: view === t.id ? 'var(--accent-glow)' : 'transparent',
                color: view === t.id ? 'var(--accent)' : 'var(--text-3)',
                border: view === t.id ? '1px solid var(--accent-border)' : '1px solid transparent',
              }}>
              <t.icon className="h-3.5 w-3.5" />{t.label}
            </button>
          ))}
          {view !== 'search' && view !== 'ai' && view !== 'response' && view !== 'findings' && (
            <select value={hours} onChange={e => setHours(+e.target.value)} className="g-select text-xs ml-auto shrink-0">
              {WINDOW_OPTIONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          )}
        </div>

        {/* Overview */}
        {view === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
            <div className="lg:col-span-2 space-y-3">
              {loadingO && !overview ? <Spinner /> : overview && (
                <>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                    {[
                      { l: 'Total Sessions', v: overview.total_sessions, c: 'var(--text-1)' },
                      { l: 'Malware Detected', v: overview.malware_detected, c: overview.malware_detected > 0 ? 'var(--red)' : 'var(--text-3)' },
                      { l: 'DLP Violations', v: overview.dlp_violations, c: overview.dlp_violations > 0 ? 'var(--orange)' : 'var(--text-3)' },
                      { l: 'Protocol Anomalies', v: overview.protocol_anomalies, c: overview.protocol_anomalies > 0 ? 'var(--orange)' : 'var(--text-3)' },
                      { l: 'Encrypted Traffic', v: overview.encrypted_traffic, c: 'var(--green)' },
                      { l: 'HTTP Sessions', v: overview.http_sessions, c: 'var(--text-2)' },
                      { l: 'DNS Queries', v: overview.dns_queries, c: 'var(--text-2)' },
                      { l: 'TLS Connections', v: overview.tls_connections, c: 'var(--text-2)' },
                    ].map(s => (
                      <div key={s.l} className="g-card p-3">
                        <p className="text-[9px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>{s.l}</p>
                        <p className="text-lg font-bold tabular-nums" style={{ color: s.c }}>{s.v}</p>
                      </div>
                    ))}
                  </div>
                  <TopList title="Protocol Distribution" icon={Layers} entries={overview.protocol_dist.map(p => ({ value: p.proto, count: p.count }))} />
                </>
              )}
            </div>
            {summary && summary.breakdown.length > 0 && <TypeBreakdownBar breakdown={summary.breakdown} />}
          </div>
        )}

        {/* Findings */}
        {view === 'findings' && (
          <div className={CARD}>
            <FindingsPanel agentMap={agentMap} />
          </div>
        )}

        {/* Sessions */}
        {view === 'sessions' && (
          <div className={CARD}>
            <SectionHeader icon={Network} title="Live Sessions" />
            <SessionsPanel data={sessions} loading={loadingS} />
          </div>
        )}

        {/* HTTP */}
        {view === 'http' && <HTTPPanel data={http} loading={loadingH} q={httpQ} onSearch={setHttpQ} />}

        {/* DNS */}
        {view === 'dns' && <DNSPanel data={dns} loading={loadingD} />}

        {/* TLS */}
        {view === 'tls' && <TLSPanel data={tls} loading={loadingT} />}

        {/* Files */}
        {view === 'files' && (
          <div className={CARD}>
            <SectionHeader icon={HardDrive} title="Files & Malware Findings" />
            <FilesPanel data={files} loading={loadingF} />
          </div>
        )}

        {/* DLP */}
        {view === 'dlp' && (
          <div className={CARD}>
            <SectionHeader icon={Database} title="Data Loss Prevention Findings" />
            <DLPPanel data={dlp} loading={loadingL} />
          </div>
        )}

        {/* Protocol Anomalies */}
        {view === 'protocols' && (
          <div className={CARD}>
            <SectionHeader icon={Activity} title="Protocol Anomalies" />
            <ProtocolAnomaliesPanel data={protocols} loading={loadingP} />
          </div>
        )}

        {/* Analytics */}
        {view === 'analytics' && <AnalyticsPanel data={analytics} loading={loadingA} />}

        {/* Performance */}
        {view === 'performance' && <PerformancePanel data={performance} loading={loadingPerf} />}

        {/* Search */}
        {view === 'search' && (
          <div className={CARD}>
            <SectionHeader icon={Search} title="Cross-Source Search" />
            <SearchPanel />
          </div>
        )}

        {/* AI Insights */}
        {view === 'ai' && (
          <div className={CARD}>
            <SectionHeader icon={Bot} title="AI DPI Analysis" />
            <AIInsightsPanel />
          </div>
        )}

        {/* Response Actions */}
        {view === 'response' && (
          <div className={CARD}>
            <SectionHeader icon={Zap} title="Response Actions" />
            <ResponseActionsPanel onToast={notify} />
          </div>
        )}
      </div>
    </RootLayout>
  );
}
