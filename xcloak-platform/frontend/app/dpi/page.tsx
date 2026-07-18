'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { dpiAPI, agentsAPI } from '@/lib/api';
import { Activity, AlertTriangle, Bell, BellOff, Check, ChevronDown, ChevronUp, Code2, Copy, Filter, Globe, Layers, Network, RefreshCw, Search, ShieldAlert, Lock } from '@/lib/icon-stubs';

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

function typeMeta(t: string) {
  return TYPE_META[t] ?? { label: t, icon: ShieldAlert, color: 'var(--text-3)', bg: 'var(--glass-bg-2)' };
}

function relativeTime(iso: string): string {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
  return new Date(iso).toLocaleDateString();
}

// ── Sub-components ────────────────────────────────────────────────────────────

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

// ── Detail Panel ──────────────────────────────────────────────────────────────

function FindingDetail({ f }: { f: DPIFinding }) {
  const m = typeMeta(f.finding_type);
  return (
    <div className="px-4 py-4 space-y-3" style={{ background: 'var(--glass-bg)', borderTop: '1px solid var(--border)' }}>
      <p className="text-xs" style={{ color: 'var(--text-2)' }}>{f.description}</p>
      {f.mitre_technique && (
        <a href={`https://attack.mitre.org/techniques/${f.mitre_technique.replace('.', '/')}/`}
          target="_blank" rel="noopener noreferrer"
          className="inline-flex items-center gap-1 text-xs px-2 py-1 rounded"
          style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
          MITRE {f.mitre_technique} ↗
        </a>
      )}
      {f.raw_context && Object.keys(f.raw_context).length > 0 && (
        <div>
          <p className="text-[10px] uppercase tracking-wider mb-1.5 font-semibold" style={{ color: 'var(--text-3)' }}>Raw Context</p>
          <pre className="text-[11px] rounded-lg p-3 overflow-x-auto leading-relaxed"
            style={{ background: 'var(--bg-0)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>
            {JSON.stringify(f.raw_context, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function DPIPage() {
  const [findings, setFindings] = useState<DPIFinding[]>([]);
  const [summary,  setSummary]  = useState<DPISummary | null>(null);
  const [agentMap, setAgentMap] = useState<Record<number, string>>({});
  const [loading,  setLoading]  = useState(true);
  const [search,   setSearch]   = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [sevFilter,  setSevFilter]  = useState('');
  const [alertOnly,  setAlertOnly]  = useState(false);
  const [expanded,   setExpanded]   = useState<Set<number>>(new Set());
  const [page,       setPage]       = useState(0);
  const [hasMore,    setHasMore]    = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const LIMIT = 100;

  const loadAgents = useCallback(async () => {
    try {
      const r = await agentsAPI.getAll();
      const agents: { id: number; hostname: string }[] = r.data?.agents || r.data || [];
      const m: Record<number, string> = {};
      for (const a of agents) m[a.id] = a.hostname;
      setAgentMap(m);
    } catch {}
  }, []);

  const load = useCallback(async (pg = 0) => {
    setLoading(true);
    try {
      const [fRes, sRes] = await Promise.all([
        dpiAPI.getFindings({
          finding_type: typeFilter || undefined,
          severity:     sevFilter  || undefined,
          alert_only:   alertOnly  || undefined,
          limit: LIMIT,
          offset: pg * LIMIT,
        }),
        pg === 0 ? dpiAPI.getSummary() : Promise.resolve(null),
      ]);
      const data = (fRes.data as { findings: DPIFinding[]; total?: number });
      const newFindings = data.findings || [];
      setFindings(pg === 0 ? newFindings : prev => [...prev, ...newFindings]);
      setHasMore(newFindings.length === LIMIT);
      if (sRes) setSummary(sRes.data as DPISummary);
    } finally {
      setLoading(false);
    }
  }, [typeFilter, sevFilter, alertOnly]);

  useEffect(() => { load(0); setPage(0); }, [load]);
  useEffect(() => { loadAgents(); }, [loadAgents]);

  useEffect(() => {
    if (timerRef.current) clearInterval(timerRef.current);
    if (autoRefresh) {
      timerRef.current = setInterval(() => load(0), 30_000);
    }
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [autoRefresh, load]);

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

  const loadMore = () => {
    const next = page + 1;
    setPage(next);
    load(next);
  };

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
          <button
            onClick={() => setAutoRefresh(r => !r)}
            title={autoRefresh ? 'Disable auto-refresh' : 'Auto-refresh every 30s'}
            className="g-btn g-btn-ghost text-xs"
            style={{ color: autoRefresh ? 'var(--accent)' : 'var(--text-3)' }}>
            {autoRefresh ? <Bell className="h-3.5 w-3.5" /> : <BellOff className="h-3.5 w-3.5" />}
          </button>
          <button onClick={() => { load(0); setPage(0); }} className="g-btn g-btn-ghost text-xs">
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      }>

      {/* Stats + breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
        <div className="lg:col-span-2 grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: 'Findings (24h)', val: summary?.total_24h ?? '—', color: 'var(--text-1)' },
            { label: 'Alerts Fired',   val: summary?.alerted_24h ?? '—', color: 'var(--red)' },
            { label: 'Types Active',   val: summary ? new Set(summary.breakdown.map(b => b.finding_type)).size : '—', color: 'var(--accent)' },
            { label: 'Crit + High',    val: critHigh || '—', color: '#fb923c' },
          ].map(s => (
            <div key={s.label} className="g-card p-4">
              <p className="text-[10px] uppercase tracking-wider mb-1 font-medium" style={{ color: 'var(--text-3)' }}>{s.label}</p>
              <p className="text-2xl font-bold" style={{ color: s.color }}>{s.val}</p>
            </div>
          ))}
        </div>
        {summary && summary.breakdown.length > 0 && (
          <TypeBreakdownBar breakdown={summary.breakdown} />
        )}
      </div>

      {/* Filters */}
      <div className="g-card p-3 mb-4 flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-40">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--text-3)' }} />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search indicator, description, agent…"
            className="g-input pl-8 py-1.5 text-xs w-full"
          />
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
        {autoRefresh && (
          <span className="text-[10px] px-2 py-0.5 rounded-full font-medium"
            style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
            Live 30s
          </span>
        )}
        <span className="text-xs ml-auto" style={{ color: 'var(--text-3)' }}>{filtered.length} findings</span>
      </div>

      {/* Table */}
      <div className="g-card overflow-hidden">
        {loading && findings.length === 0 ? (
          <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
        ) : filtered.length === 0 ? (
          <div className="py-16 text-center">
            <ShieldAlert className="mx-auto h-10 w-10 mb-3 opacity-20" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No DPI findings match the current filters</p>
          </div>
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
                  const sev = SEV_STYLE[f.severity] ?? { color: 'var(--text-2)', bg: 'var(--glass-bg-2)' };
                  const isExp = expanded.has(f.id);
                  const agentName = agentMap[f.agent_id] || `#${f.agent_id}`;

                  return (
                    <>
                      <tr key={f.id}
                        className="cursor-pointer transition-colors hover:bg-[var(--glass-hover)]"
                        style={{ borderBottom: '1px solid var(--border)' }}
                        onClick={() => toggle(f.id)}>
                        <td className="px-4 py-3">
                          <span className="flex items-center gap-1.5 font-medium">
                            <span className="flex items-center justify-center w-5 h-5 rounded"
                              style={{ background: m.bg }}>
                              <Icon className="w-3 h-3" style={{ color: m.color }} />
                            </span>
                            <span style={{ color: m.color }}>{m.label}</span>
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold capitalize"
                            style={{ background: sev.bg, color: sev.color }}>
                            {f.severity}
                          </span>
                        </td>
                        <td className="px-4 py-3 min-w-[96px]">
                          <ScoreBar score={f.score} />
                        </td>
                        <td className="px-4 py-3 max-w-[200px]">
                          <div className="flex items-center gap-1.5">
                            <span className="font-mono text-[11px] truncate" title={f.indicator}
                              style={{ color: 'var(--text-1)' }}>
                              {f.indicator}
                            </span>
                            <CopyButton text={f.indicator} />
                          </div>
                        </td>
                        <td className="px-4 py-3" style={{ color: 'var(--text-2)' }}>
                          {agentName}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>
                          {relativeTime(f.detected_at)}
                        </td>
                        <td className="px-4 py-3">
                          {f.alert_fired ? (
                            <span className="flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded"
                              style={{ background: 'rgba(248,81,73,0.15)', color: 'var(--red)' }}>
                              <Bell className="w-2.5 h-2.5" /> Alert
                            </span>
                          ) : (
                            <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>—</span>
                          )}
                        </td>
                        <td className="px-4 py-3" style={{ color: 'var(--text-3)' }}>
                          {isExp ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                        </td>
                      </tr>
                      {isExp && (
                        <tr key={`${f.id}-detail`}>
                          <td colSpan={8} className="p-0">
                            <FindingDetail f={f} />
                          </td>
                        </tr>
                      )}
                    </>
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
    </RootLayout>
  );
}
