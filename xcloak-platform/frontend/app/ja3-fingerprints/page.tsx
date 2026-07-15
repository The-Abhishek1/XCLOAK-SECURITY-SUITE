'use client';

import { useEffect, useState, useCallback, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { ja3API } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import {
  Fingerprint, Grid, Layers, Lock, Activity, Shield, Share2, Bot, Bookmark,
  Plus, Trash2, Search, Download, Zap, Copy, Globe, ChevronDown, ChevronUp,
  AlertTriangle, CheckSquare, X, Hash, BarChart3, BookmarkPlus,
} from 'lucide-react';

// ── Types ─────────────────────────────────────────────────────────────────

interface JA3Entry {
  id: number; hash: string; threat_name: string; severity: string;
  source: string; description: string; enabled: boolean; is_platform: boolean; created_at: string;
}

interface DashData {
  total: number; platform_count: number; tenant_count: number;
  critical_count: number; new_today: number;
  alerts_24h: number; alerts_7d: number; agents_hit_24h: number;
  top_fingerprints: { hash: string; threat_name: string; severity: string; source: string; hit_count: number }[];
  trend: { date: string; count: number }[];
  sev_breakdown: { severity: string; count: number }[];
}

interface TLSData {
  tls_versions: { version: string; count: number }[];
  ciphers: { cipher: string; count: number; is_weak: boolean }[];
  self_signed: number; expired_certs: number; invalid_certs: number;
  unique_ja3: number; unique_ja3s: number;
}

interface BehavData {
  beaconing: { agent_id: number; hostname: string; alert_count: number; first_seen: string; last_seen: string; rule_name: string }[];
  rare: { hash: string; threat_name: string; severity: string; hit_count: number }[];
  new: { hash: string; threat_name: string; severity: string; source: string; created_at: string }[];
}

interface ThreatFamily {
  family: string; confidence: number; hash: string;
  evidence: string; mitre: string; actor: string;
  reports: string[]; category: string; in_blocklist: boolean;
}

interface ThreatIntelData {
  malware_families: ThreatFamily[];
  recent_hits: { rule_name: string; severity: string; created_at: string; hostname: string }[];
}

interface RelNode { id: string; label: string; type: string; value: number; }
interface RelEdge { source: string; target: string; weight: number; }

interface WatchItem { id: number; hash: string; label: string; watch_type: string; created_at: string; }

// ── Constants ─────────────────────────────────────────────────────────────

const TABS = [
  { id: 'dashboard',    label: 'Dashboard',       icon: Grid },
  { id: 'library',      label: 'Library',          icon: Layers },
  { id: 'tls',          label: 'TLS Analytics',    icon: Lock },
  { id: 'behavioral',   label: 'Behavioral',       icon: Activity },
  { id: 'threat-intel', label: 'Threat Intel',     icon: Shield },
  { id: 'relationships',label: 'Relationships',    icon: Share2 },
  { id: 'ai',           label: 'AI Analysis',      icon: Bot },
  { id: 'watchlist',    label: 'Watchlists',       icon: Bookmark },
];

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)', high: 'var(--orange)',
  medium: 'var(--yellow)', low: 'var(--blue)', info: 'var(--text-3)',
};

const AI_ACTIONS = [
  { id: 'analyze',      label: 'Deep Analysis',   desc: 'Full threat assessment and recommended actions' },
  { id: 'explain',      label: 'Explain Hash',     desc: 'How JA3 works and why this hash is malicious' },
  { id: 'hunt',         label: 'Hunting Queries',  desc: 'Splunk, Elastic, KQL, Zeek hunting queries' },
  { id: 'generate_rule',label: 'Generate Rule',    desc: 'Auto-generate a Sigma detection rule' },
];

const emptyForm = { hash: '', threat_name: '', severity: 'high', source: 'manual', description: '' };

// ── Micro-components ──────────────────────────────────────────────────────

function KPICard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="g-card p-4 flex flex-col gap-1">
      <span className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>{label}</span>
      <span className="text-2xl font-bold font-mono" style={{ color: color ?? 'var(--text-1)' }}>{value}</span>
      {sub && <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{sub}</span>}
    </div>
  );
}

function SevBadge({ sev }: { sev: string }) {
  const color = SEV_COLOR[sev?.toLowerCase()] ?? 'var(--text-3)';
  return (
    <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded"
      style={{ color, background: color + '22', border: `1px solid ${color}55` }}>{sev || '—'}</span>
  );
}

function MiniBar({ value, max, color = 'var(--accent)' }: { value: number; max: number; color?: string }) {
  const pct = max > 0 ? Math.min(100, Math.round((value / max) * 100)) : 0;
  return (
    <div className="h-1.5 rounded-full w-full" style={{ background: 'var(--bg-0)' }}>
      <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: color }} />
    </div>
  );
}

function SparkTrend({ trend }: { trend: { date: string; count: number }[] }) {
  if (!trend.length) return <div className="text-xs" style={{ color: 'var(--text-3)' }}>No data</div>;
  const max = Math.max(...trend.map(t => t.count), 1);
  const W = 220, H = 36;
  const pts = trend.map((t, i) => {
    const x = (i / Math.max(trend.length - 1, 1)) * W;
    const y = H - (t.count / max) * (H - 4) - 2;
    return `${x},${y}`;
  }).join(' ');
  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ maxHeight: H }}>
      <polyline points={pts} fill="none" stroke="var(--accent)" strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

function RelGraph({ nodes, edges }: { nodes: RelNode[]; edges: RelEdge[] }) {
  const TYPE_ORDER = ['ja3', 'agent', 'ip'];
  const cols: Record<string, RelNode[]> = { ja3: [], agent: [], ip: [] };
  nodes.forEach(n => { if (cols[n.type]) cols[n.type].push(n); });
  const W = 640, H = 380;
  const COL_X = [90, 320, 560];
  const pos: Record<string, { x: number; y: number }> = {};
  TYPE_ORDER.forEach((t, ci) => {
    const count = cols[t].length;
    cols[t].forEach((n, i) => {
      pos[n.id] = { x: COL_X[ci], y: count > 0 ? (H / (count + 1)) * (i + 1) : H / 2 };
    });
  });
  const maxW = Math.max(...edges.map(e => e.weight), 1);
  const TYPE_COLOR: Record<string, string> = { ja3: 'var(--red)', agent: 'var(--blue)', ip: 'var(--yellow)' };
  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ maxHeight: 380 }}>
      {edges.map((e, i) => {
        const s = pos[e.source], t = pos[e.target];
        if (!s || !t) return null;
        return <line key={i} x1={s.x} y1={s.y} x2={t.x} y2={t.y}
          stroke="var(--accent)" strokeOpacity={0.12 + (e.weight / maxW) * 0.5}
          strokeWidth={1 + (e.weight / maxW) * 2.5} />;
      })}
      {nodes.map(n => {
        const p = pos[n.id];
        if (!p) return null;
        const color = TYPE_COLOR[n.type] ?? 'var(--text-3)';
        const r = 5 + Math.min(n.value / 4, 14);
        return (
          <g key={n.id}>
            <circle cx={p.x} cy={p.y} r={r} fill={color} fillOpacity={0.2} stroke={color} strokeWidth={1.5} />
            <text x={p.x} y={p.y - r - 3} textAnchor="middle" fill="var(--text-2)" fontSize={9}>{n.label.slice(0, 18)}</text>
          </g>
        );
      })}
      {TYPE_ORDER.map((t, i) => (
        <text key={t} x={COL_X[i]} y={14} textAnchor="middle" fill="var(--text-3)" fontSize={10} fontWeight={600}>
          {t.toUpperCase()}
        </text>
      ))}
    </svg>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────

export default function JA3FingerprintsPage() {
  const [tab, setTab]         = useState('dashboard');
  const [entries, setEntries] = useState<JA3Entry[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const [search,   setSearch]   = useState('');
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [showAdd,  setShowAdd]  = useState(false);
  const [form,     setForm]     = useState({ ...emptyForm });
  const [saving,   setSaving]   = useState(false);
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const [dash,        setDash]        = useState<DashData | null>(null);
  const [tlsData,     setTlsData]     = useState<TLSData | null>(null);
  const [behavData,   setBehavData]   = useState<BehavData | null>(null);
  const [tiData,      setTiData]      = useState<ThreatIntelData | null>(null);
  const [relData,     setRelData]     = useState<{ nodes: RelNode[]; edges: RelEdge[] } | null>(null);
  const [timelineData,setTimelineData]= useState<any>(null);
  const [analyticsData,setAnalyticsData]= useState<any>(null);

  const [watchlist,   setWatchlist]   = useState<WatchItem[]>([]);
  const [wlForm,      setWlForm]      = useState({ hash: '', label: '', watch_type: 'custom' });
  const [wlSaving,    setWlSaving]    = useState(false);

  const [aiAction,  setAiAction]  = useState('analyze');
  const [aiHash,    setAiHash]    = useState('');
  const [aiThreat,  setAiThreat]  = useState('');
  const [aiPrompt,  setAiPrompt]  = useState('');
  const [aiResult,  setAiResult]  = useState<any>(null);
  const [aiLoading, setAiLoading] = useState(false);

  const [bulkAction, setBulkAction] = useState('enable');
  const [bulkLoading,setBulkLoading]= useState(false);

  const [toast, setToast] = useState<string | null>(null);
  const loaded = useRef<Record<string, boolean>>({});

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3500); };

  // ── Load ────────────────────────────────────────────────────────────────

  const loadEntries = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const r = await ja3API.getAll();
      setEntries(Array.isArray(r.data) ? r.data : []);
    } catch { setEntries([]); }
    setLoading(false);
    setRefreshing(false);
  }, []);

  useEffect(() => { loadEntries(); }, [loadEntries]);

  useEffect(() => {
    if (loaded.current[tab]) return;
    loaded.current[tab] = true;
    if (tab === 'dashboard')     ja3API.dashboard().then(r => setDash(r.data));
    if (tab === 'tls')           ja3API.tlsStats().then(r => setTlsData(r.data));
    if (tab === 'behavioral')    ja3API.behavioral().then(r => setBehavData(r.data));
    if (tab === 'threat-intel')  ja3API.threatIntel().then(r => setTiData(r.data));
    if (tab === 'relationships') ja3API.relationships().then(r => setRelData(r.data));
    if (tab === 'watchlist')     ja3API.watchlist().then(r => setWatchlist(Array.isArray(r.data) ? r.data : []));
    if (tab === 'ai')            ja3API.analytics().then(r => setAnalyticsData(r.data));
    if (tab === 'library')       ja3API.timeline().then(r => setTimelineData(r.data));
  }, [tab]);

  // ── Derived ──────────────────────────────────────────────────────────────

  const filtered = useMemo(() =>
    entries.filter(e =>
      !search ||
      e.hash.includes(search.toLowerCase()) ||
      e.threat_name.toLowerCase().includes(search.toLowerCase()) ||
      e.source.toLowerCase().includes(search.toLowerCase())
    ), [entries, search]);

  // ── CRUD ─────────────────────────────────────────────────────────────────

  const createEntry = async (ev: React.FormEvent) => {
    ev.preventDefault();
    if (form.hash.length !== 32) { notify('Hash must be exactly 32 hex characters'); return; }
    setSaving(true);
    try {
      await ja3API.create(form);
      setShowAdd(false); setForm({ ...emptyForm });
      loaded.current = {};
      loadEntries();
      notify('Fingerprint added');
    } catch (err: any) { notify(err?.response?.data?.error || 'Failed'); }
    finally { setSaving(false); }
  };

  const removeEntry = async (e: JA3Entry) => {
    if (e.is_platform) { notify('Platform fingerprints cannot be deleted'); return; }
    try {
      await ja3API.remove(e.id);
      setEntries(p => p.filter(x => x.id !== e.id));
      setSelected(s => { const n = new Set(s); n.delete(e.id); return n; });
      notify('Deleted');
    } catch { notify('Delete failed'); }
  };

  // ── Bulk ─────────────────────────────────────────────────────────────────

  const runBulk = async () => {
    if (selected.size === 0) { notify('Select fingerprints first'); return; }
    setBulkLoading(true);
    try {
      const res = await ja3API.bulk(bulkAction, Array.from(selected));
      notify(`${res.data.affected} entries ${bulkAction}d`);
      setSelected(new Set()); loaded.current = {}; loadEntries();
    } catch { notify('Bulk action failed'); }
    finally { setBulkLoading(false); }
  };

  // ── Watchlist ─────────────────────────────────────────────────────────────

  const addToWatchlist = async () => {
    if (!wlForm.label.trim()) { notify('Label is required'); return; }
    setWlSaving(true);
    try {
      await ja3API.addWatchlist(wlForm);
      const r = await ja3API.watchlist();
      setWatchlist(Array.isArray(r.data) ? r.data : []);
      setWlForm({ hash: '', label: '', watch_type: 'custom' });
      notify('Added to watchlist');
    } catch { notify('Failed to add'); }
    finally { setWlSaving(false); }
  };

  const removeFromWatchlist = async (id: number) => {
    try {
      await ja3API.removeWatchlist(id);
      setWatchlist(p => p.filter(w => w.id !== id));
      notify('Removed from watchlist');
    } catch { notify('Failed'); }
  };

  // ── AI ───────────────────────────────────────────────────────────────────

  const runAI = async () => {
    setAiLoading(true); setAiResult(null);
    try {
      const res = await ja3API.ai({
        action: aiAction, hash: aiHash, threat_name: aiThreat, prompt: aiPrompt,
      });
      setAiResult(res.data);
    } catch { notify('AI request failed'); }
    finally { setAiLoading(false); }
  };

  // ── Export ────────────────────────────────────────────────────────────────

  const exportEntries = async (format: 'csv' | 'json' | 'stix') => {
    try {
      const res = await ja3API.export({ format, ids: selected.size > 0 ? Array.from(selected) : [] });
      const content = typeof res.data === 'string' ? res.data : JSON.stringify(res.data, null, 2);
      const ext = format === 'stix' ? 'json' : format;
      const blob = new Blob([content], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `ja3_fingerprints.${ext}`; a.click();
      URL.revokeObjectURL(url);
    } catch { notify('Export failed'); }
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // RENDER
  // ═══════════════════════════════════════════════════════════════════════════

  return (
    <RootLayout
      title="JA3 Fingerprints"
      subtitle={`${entries.length} fingerprints · ${entries.filter(e => e.severity === 'critical').length} critical · ${entries.filter(e => !e.is_platform).length} custom`}
      onRefresh={() => { loaded.current = {}; loadEntries(true); }}
      refreshing={refreshing}
      actions={
        <div className="flex items-center gap-2">
          {selected.size > 0 && (
            <span className="text-xs rounded-lg px-2 py-1" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>
              {selected.size} selected
            </span>
          )}
          <button onClick={() => setShowAdd(p => !p)} className="g-btn g-btn-primary text-xs">
            <Plus className="h-3.5 w-3.5" /> Add Hash
          </button>
        </div>
      }>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)', minWidth: 200 }}>{toast}</div>
      )}

      {/* ── Tabs ── */}
      <div className="flex items-center gap-1 flex-wrap mb-5 pb-3" style={{ borderBottom: '1px solid var(--border)' }}>
        {TABS.map(t => {
          const Icon = t.icon;
          const active = tab === t.id;
          return (
            <button key={t.id} onClick={() => setTab(t.id)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition-all"
              style={{
                background: active ? 'var(--accent-glow)' : 'transparent',
                border: `1px solid ${active ? 'var(--accent-border)' : 'transparent'}`,
                color: active ? 'var(--accent)' : 'var(--text-3)',
                fontWeight: active ? 600 : 400,
              }}>
              <Icon className="h-3.5 w-3.5" />{t.label}
            </button>
          );
        })}
      </div>

      {/* ═══ DASHBOARD ═══ */}
      {tab === 'dashboard' && (
        <div className="space-y-5">
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
            <KPICard label="Total Hashes" value={dash?.total ?? entries.length} />
            <KPICard label="Platform" value={dash?.platform_count ?? entries.filter(e => e.is_platform).length} color="var(--text-3)" sub="built-in" />
            <KPICard label="Custom" value={dash?.tenant_count ?? entries.filter(e => !e.is_platform).length} color="var(--accent)" sub="tenant" />
            <KPICard label="Critical" value={dash?.critical_count ?? entries.filter(e => e.severity === 'critical').length} color="var(--red)" />
            <KPICard label="New Today" value={dash?.new_today ?? 0} color="var(--green)" sub="last 24h" />
            <KPICard label="TLS Alerts 24h" value={dash?.alerts_24h ?? 0} color="var(--orange)" />
            <KPICard label="TLS Alerts 7d" value={dash?.alerts_7d ?? 0} color="var(--yellow)" />
            <KPICard label="Agents Hit" value={dash?.agents_hit_24h ?? 0} color="var(--blue)" sub="24h" />
          </div>

          {dash && (
            <div className="grid grid-cols-3 gap-4">
              <div className="g-card p-4">
                <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Severity Breakdown</p>
                {dash.sev_breakdown.length === 0
                  ? <p className="text-xs" style={{ color: 'var(--text-3)' }}>No fingerprints</p>
                  : <div className="space-y-2">
                    {dash.sev_breakdown.map(s => (
                      <div key={s.severity}>
                        <div className="flex justify-between text-[10px] mb-0.5">
                          <span className="capitalize" style={{ color: SEV_COLOR[s.severity] ?? 'var(--text-2)' }}>{s.severity}</span>
                          <span style={{ color: 'var(--text-2)' }}>{s.count}</span>
                        </div>
                        <MiniBar value={s.count} max={dash.sev_breakdown[0]?.count ?? 1} color={SEV_COLOR[s.severity] ?? 'var(--accent)'} />
                      </div>
                    ))}
                  </div>}
              </div>
              <div className="g-card p-4">
                <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Alert Trend (14d)</p>
                <SparkTrend trend={dash.trend} />
                <p className="text-[10px] mt-2" style={{ color: 'var(--text-3)' }}>{dash.alerts_24h} TLS alerts in last 24h</p>
              </div>
              <div className="g-card p-4">
                <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Top Firing Hashes (7d)</p>
                {dash.top_fingerprints.length === 0
                  ? <p className="text-xs" style={{ color: 'var(--text-3)' }}>No TLS matches yet</p>
                  : <div className="space-y-2">
                    {dash.top_fingerprints.slice(0, 6).map(fp => (
                      <div key={fp.hash} className="flex items-center gap-2">
                        <SevBadge sev={fp.severity} />
                        <span className="flex-1 text-[10px] font-mono truncate" style={{ color: 'var(--text-1)' }}>{fp.threat_name}</span>
                        <span className="text-[10px] font-mono shrink-0" style={{ color: 'var(--accent)' }}>{fp.hit_count}</span>
                      </div>
                    ))}
                  </div>}
              </div>
            </div>
          )}

          {/* How JA3 works */}
          <div className="g-card p-4">
            <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-2)' }}>How JA3 fits into XCloak</p>
            <div className="flex items-start gap-6">
              <div className="text-[10px] font-mono space-y-0.5" style={{ color: 'var(--text-3)' }}>
                {['TLS Traffic', '│', '▼', 'DPI (Extract TLS metadata)', '│', '▼', 'JA3 Fingerprint Engine', '│', '├──► Threat Intelligence', '├──► Network Behavior', '├──► Correlation Engine', '├──► Alerts', '└──► Threat Hunting'].map((l, i) => (
                  <p key={i}>{l}</p>
                ))}
              </div>
              <p className="text-[11px] leading-relaxed" style={{ color: 'var(--text-3)' }}>
                XCloak extracts JA3 hashes from Zeek (<code className="mono px-1 rounded" style={{ background: 'var(--glass-bg)' }}>ja3=</code>),
                Suricata (<code className="mono px-1 rounded" style={{ background: 'var(--glass-bg)' }}>ja3.hash</code>),
                CEF (<code className="mono px-1 rounded" style={{ background: 'var(--glass-bg)' }}>ja3hash=</code>), and
                Palo Alto NGFW logs. Matches fire MITRE T1071.001 alerts. Platform hashes cover known C2 frameworks and cannot be deleted.
              </p>
            </div>
          </div>

          {!dash && <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading dashboard…</div>}
        </div>
      )}

      {/* ═══ LIBRARY ═══ */}
      {tab === 'library' && (
        <div className="space-y-4">
          {/* Add form */}
          {showAdd && (
            <div className="g-card p-5 space-y-4">
              <div className="flex items-center justify-between">
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Add Custom JA3 Hash</p>
                <button onClick={() => setShowAdd(false)} style={{ color: 'var(--text-3)' }}><X className="h-4 w-4" /></button>
              </div>
              <form onSubmit={createEntry} className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>JA3 Hash (32 hex chars)</label>
                    <input required value={form.hash} onChange={e => setForm(f => ({ ...f, hash: e.target.value.toLowerCase() }))}
                      placeholder="a0e9f5d64349fb13191bc781f81f42e1" maxLength={32} className="g-input w-full text-xs mono" />
                  </div>
                  <div>
                    <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Threat Name</label>
                    <input required value={form.threat_name} onChange={e => setForm(f => ({ ...f, threat_name: e.target.value }))}
                      placeholder="e.g. Cobalt Strike" className="g-input w-full text-xs" />
                  </div>
                  <div>
                    <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Severity</label>
                    <select value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))} className="g-select w-full text-xs">
                      {['critical', 'high', 'medium', 'low', 'info'].map(s => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Source</label>
                    <input value={form.source} onChange={e => setForm(f => ({ ...f, source: e.target.value }))}
                      placeholder="manual / abuse.ch / internal" className="g-input w-full text-xs" />
                  </div>
                </div>
                <div>
                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Description</label>
                  <input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                    placeholder="Brief description of the threat" className="g-input w-full text-xs" />
                </div>
                <div className="flex gap-2">
                  <button type="submit" disabled={saving} className="g-btn g-btn-primary text-xs flex-1 justify-center">
                    {saving ? 'Adding…' : 'Add Fingerprint'}
                  </button>
                  <button type="button" onClick={() => setShowAdd(false)} className="g-btn g-btn-ghost text-xs">Cancel</button>
                </div>
              </form>
            </div>
          )}

          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 min-w-[200px] max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
              <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search hash, threat, source…" className="g-input pl-9" />
            </div>
            <div className="ml-auto flex gap-1 items-center">
              <input type="checkbox" checked={selected.size === entries.length && entries.length > 0}
                onChange={e => setSelected(e.target.checked ? new Set(entries.map(en => en.id)) : new Set())}
                className="h-3.5 w-3.5" title="Select all" />
              <span className="text-[10px] ml-1" style={{ color: 'var(--text-3)' }}>Select all</span>
            </div>
          </div>

          {loading ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          ) : filtered.length === 0 ? (
            <div className="py-16 text-center">
              <Fingerprint className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>No fingerprints found</p>
            </div>
          ) : (
            <div className="g-table">
              <div className="g-thead grid gap-2 px-4" style={{ gridTemplateColumns: '24px 300px 1fr 80px 90px 80px 24px' }}>
                <span /><span>Hash / Threat</span><span>Description</span><span>Severity</span><span>Source</span><span>Added</span><span />
              </div>
              {filtered.map(e => (
                <div key={e.id}>
                  <div className="g-tr grid gap-2 items-center px-4 cursor-pointer"
                    onClick={() => setExpandedId(expandedId === e.id ? null : e.id)}
                    style={{ gridTemplateColumns: '24px 300px 1fr 80px 90px 80px 24px' }}>
                    <input type="checkbox" checked={selected.has(e.id)}
                      onClick={ev => ev.stopPropagation()}
                      onChange={ev => setSelected(s => { const n = new Set(s); ev.target.checked ? n.add(e.id) : n.delete(e.id); return n; })}
                      className="h-3.5 w-3.5" />
                    <div>
                      <div className="flex items-center gap-1.5">
                        <p className="text-[10px] font-mono" style={{ color: 'var(--text-3)' }}>{e.hash}</p>
                        {e.is_platform && <Globe className="h-3 w-3 shrink-0" style={{ color: 'var(--text-3)' }} />}
                      </div>
                      <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{e.threat_name}</p>
                    </div>
                    <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>{e.description || '—'}</p>
                    <SevBadge sev={e.severity} />
                    <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{e.source}</span>
                    <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{e.created_at ? timeAgo(e.created_at) : '—'}</span>
                    {expandedId === e.id
                      ? <ChevronUp className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
                      : <ChevronDown className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />}
                  </div>
                  {expandedId === e.id && (
                    <div className="px-4 pb-3 pt-2 space-y-2" style={{ background: 'var(--bg-0)', borderBottom: '1px solid var(--border)' }}>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-[10px] font-mono rounded px-2 py-1 flex items-center gap-1"
                          style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                          <Hash className="h-3 w-3" />{e.hash}
                          <button onClick={() => navigator.clipboard.writeText(e.hash).catch(() => {})} className="ml-1 opacity-50 hover:opacity-100"><Copy className="h-3 w-3" /></button>
                        </span>
                        {e.is_platform
                          ? <span className="text-[10px]" style={{ color: 'var(--text-3)' }}><Globe className="h-3 w-3 inline" /> Platform-managed (cannot delete)</span>
                          : <button onClick={() => removeEntry(e)}
                              className="g-btn g-btn-ghost text-[10px]" style={{ padding: '2px 8px', color: 'var(--red)' }}>
                              <Trash2 className="h-3 w-3" /> Delete
                            </button>}
                        <button onClick={() => { setWlForm({ hash: e.hash, label: e.threat_name, watch_type: 'custom' }); setTab('watchlist'); }}
                          className="g-btn g-btn-ghost text-[10px]" style={{ padding: '2px 8px' }}>
                          <BookmarkPlus className="h-3 w-3" /> Add to Watchlist
                        </button>
                        <button onClick={() => { setAiHash(e.hash); setAiThreat(e.threat_name); setTab('ai'); }}
                          className="g-btn g-btn-ghost text-[10px]" style={{ padding: '2px 8px' }}>
                          <Bot className="h-3 w-3" /> AI Analyze
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ═══ TLS ANALYTICS ═══ */}
      {tab === 'tls' && (
        <div className="space-y-4">
          {!tlsData ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading TLS analytics…</div>
          ) : (
            <>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                <KPICard label="Unique JA3" value={tlsData.unique_ja3} color="var(--accent)" />
                <KPICard label="Unique JA3S" value={tlsData.unique_ja3s} color="var(--blue)" />
                <KPICard label="Self-Signed" value={tlsData.self_signed} color="var(--orange)" sub="7d" />
                <KPICard label="Expired Certs" value={tlsData.expired_certs} color="var(--red)" sub="7d" />
                <KPICard label="Invalid Certs" value={tlsData.invalid_certs} color="var(--yellow)" sub="7d" />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="g-card p-4">
                  <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>TLS Version Distribution (7d)</p>
                  {tlsData.tls_versions.length === 0
                    ? <p className="text-xs" style={{ color: 'var(--text-3)' }}>No TLS version data in logs — enable tls_version parsing in your log forwarder</p>
                    : <div className="space-y-2">
                      {tlsData.tls_versions.map(v => (
                        <div key={v.version}>
                          <div className="flex justify-between text-[10px] mb-0.5">
                            <span style={{ color: (v.version.includes('1.0') || v.version.includes('1.1')) ? 'var(--red)' : 'var(--green)' }}>{v.version}</span>
                            <span style={{ color: 'var(--text-2)' }}>{v.count}</span>
                          </div>
                          <MiniBar value={v.count} max={tlsData.tls_versions[0]?.count ?? 1}
                            color={(v.version.includes('1.0') || v.version.includes('1.1')) ? 'var(--red)' : 'var(--green)'} />
                        </div>
                      ))}
                    </div>}
                </div>

                <div className="g-card p-4">
                  <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Cipher Suite Analysis</p>
                  {tlsData.ciphers.length === 0
                    ? <p className="text-xs" style={{ color: 'var(--text-3)' }}>No cipher data in logs — enable cipher_suite parsing in your log forwarder</p>
                    : <div className="space-y-1.5">
                      {tlsData.ciphers.slice(0, 10).map(ci => (
                        <div key={ci.cipher} className="flex items-center gap-2">
                          {ci.is_weak && <AlertTriangle className="h-3 w-3 shrink-0" style={{ color: 'var(--red)' }} />}
                          <span className="flex-1 text-[10px] mono truncate" style={{ color: ci.is_weak ? 'var(--red)' : 'var(--text-2)' }}>{ci.cipher}</span>
                          <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{ci.count}</span>
                        </div>
                      ))}
                    </div>}
                </div>
              </div>

              <div className="g-card p-4">
                <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Certificate Risk Summary</p>
                <div className="grid grid-cols-3 gap-3">
                  {[
                    { label: 'Self-Signed Certificates', value: tlsData.self_signed, desc: 'Self-signed certs may indicate untrusted or malicious services', color: 'var(--orange)' },
                    { label: 'Expired Certificates', value: tlsData.expired_certs, desc: 'Expired certs may indicate abandoned C2 or poorly maintained services', color: 'var(--red)' },
                    { label: 'Invalid Certificates', value: tlsData.invalid_certs, desc: 'Chain validation failures — potential MITM or misconfigured services', color: 'var(--yellow)' },
                  ].map(item => (
                    <div key={item.label} className="rounded-xl p-3" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                      <p className="text-2xl font-bold font-mono mb-1" style={{ color: item.color }}>{item.value}</p>
                      <p className="text-xs font-medium mb-1" style={{ color: 'var(--text-1)' }}>{item.label}</p>
                      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{item.desc}</p>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {/* ═══ BEHAVIORAL ═══ */}
      {tab === 'behavioral' && (
        <div className="space-y-4">
          {!behavData ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading behavioral data…</div>
          ) : (
            <>
              <div className="g-card p-4">
                <div className="flex items-center gap-2 mb-3">
                  <Activity className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                  <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Beaconing Connections (24h)</p>
                  {behavData.beaconing.length > 0 && (
                    <span className="text-[10px] rounded px-1.5 py-0.5" style={{ background: 'var(--red)', color: '#fff' }}>{behavData.beaconing.length}</span>
                  )}
                </div>
                {behavData.beaconing.length === 0
                  ? <p className="text-xs" style={{ color: 'var(--text-3)' }}>No beaconing patterns detected in the last 24h</p>
                  : <div className="g-table">
                    <div className="g-thead grid gap-2 px-4" style={{ gridTemplateColumns: '1fr 1fr 60px 120px 120px' }}>
                      <span>Agent</span><span>Rule</span><span>Hits</span><span>First Seen</span><span>Last Seen</span>
                    </div>
                    {behavData.beaconing.map((b, i) => (
                      <div key={i} className="g-tr grid gap-2 items-center px-4" style={{ gridTemplateColumns: '1fr 1fr 60px 120px 120px' }}>
                        <span className="text-xs font-mono" style={{ color: 'var(--accent)' }}>{b.hostname}</span>
                        <span className="text-xs truncate" style={{ color: 'var(--text-2)' }}>{b.rule_name}</span>
                        <span className="text-xs font-mono text-center" style={{ color: 'var(--red)' }}>{b.alert_count}</span>
                        <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(b.first_seen)}</span>
                        <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(b.last_seen)}</span>
                      </div>
                    ))}
                  </div>}
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="g-card p-4">
                  <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Rare Fingerprints (&lt;3 matches)</p>
                  {behavData.rare.length === 0
                    ? <p className="text-xs" style={{ color: 'var(--text-3)' }}>No rare fingerprints</p>
                    : <div className="space-y-2">
                      {behavData.rare.map(r => (
                        <div key={r.hash} className="flex items-center gap-2">
                          <SevBadge sev={r.severity} />
                          <span className="flex-1 text-xs font-mono truncate" style={{ color: 'var(--text-1)' }}>{r.threat_name}</span>
                          <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{r.hit_count} hits</span>
                        </div>
                      ))}
                    </div>}
                </div>

                <div className="g-card p-4">
                  <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>New Fingerprints (24h)</p>
                  {behavData.new.length === 0
                    ? <p className="text-xs" style={{ color: 'var(--text-3)' }}>No new fingerprints added today</p>
                    : <div className="space-y-2">
                      {behavData.new.map(n => (
                        <div key={n.hash} className="flex items-center gap-2">
                          <SevBadge sev={n.severity} />
                          <div className="flex-1 min-w-0">
                            <p className="text-xs font-mono truncate" style={{ color: 'var(--text-1)' }}>{n.threat_name}</p>
                            <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Source: {n.source}</p>
                          </div>
                          <span className="text-[10px] shrink-0" style={{ color: 'var(--text-3)' }}>{timeAgo(n.created_at)}</span>
                        </div>
                      ))}
                    </div>}
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {/* ═══ THREAT INTEL ═══ */}
      {tab === 'threat-intel' && (
        <div className="space-y-4">
          {!tiData ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading threat intelligence…</div>
          ) : (
            <>
              <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                JA3 fingerprint matches are probabilistic — tools can alter TLS behavior. These are best-effort malware family mappings.
              </p>
              <div className="grid grid-cols-2 gap-4">
                {tiData.malware_families.map(fam => (
                  <div key={fam.family} className="g-card p-4">
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{fam.family}</p>
                        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{fam.category}</p>
                      </div>
                      <div className="flex flex-col items-end gap-1">
                        <span className="text-[10px] font-bold rounded px-1.5 py-0.5"
                          style={{ background: fam.in_blocklist ? 'rgba(52,211,153,0.1)' : 'var(--glass-bg)', color: fam.in_blocklist ? 'var(--green)' : 'var(--text-3)' }}>
                          {fam.in_blocklist ? '✓ In Blocklist' : 'Not in Blocklist'}
                        </span>
                        <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>Confidence: <span style={{ color: fam.confidence >= 85 ? 'var(--red)' : fam.confidence >= 70 ? 'var(--orange)' : 'var(--yellow)' }}>{fam.confidence}%</span></span>
                      </div>
                    </div>
                    <p className="text-[10px] mb-2" style={{ color: 'var(--text-2)' }}>{fam.evidence}</p>
                    <div className="flex flex-wrap gap-1 mb-2">
                      <span className="text-[9px] rounded px-1.5 py-0.5 font-mono" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>{fam.mitre}</span>
                      <span className="text-[9px] rounded px-1.5 py-0.5" style={{ background: 'var(--glass-bg)', color: 'var(--text-3)' }}>{fam.actor}</span>
                    </div>
                    <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>Sources: {fam.reports.join(' · ')}</p>
                    <p className="text-[9px] mono mt-1" style={{ color: 'var(--text-3)' }}>Hash: {fam.hash}</p>
                    {!fam.in_blocklist && (
                      <button onClick={async () => {
                        try {
                          await ja3API.create({ hash: fam.hash, threat_name: fam.family, severity: 'critical', source: 'threat-intel', description: fam.evidence });
                          loaded.current = {}; loadEntries();
                          notify(`${fam.family} added to blocklist`);
                        } catch { notify('Failed to add'); }
                      }} className="g-btn g-btn-ghost text-[10px] mt-2" style={{ padding: '2px 8px' }}>
                        <Plus className="h-3 w-3" /> Add to Blocklist
                      </button>
                    )}
                  </div>
                ))}
              </div>

              {tiData.recent_hits.length > 0 && (
                <div className="g-card p-4">
                  <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Recent TLS Threat Hits (7d)</p>
                  <div className="g-table">
                    <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 80px 120px 100px' }}>
                      <span>Rule Name</span><span>Severity</span><span>Agent</span><span>When</span>
                    </div>
                    {tiData.recent_hits.map((h, i) => (
                      <div key={i} className="g-tr grid gap-3 items-center px-4" style={{ gridTemplateColumns: '1fr 80px 120px 100px' }}>
                        <span className="text-xs" style={{ color: 'var(--text-1)' }}>{h.rule_name}</span>
                        <SevBadge sev={h.severity} />
                        <span className="text-xs font-mono" style={{ color: 'var(--accent)' }}>{h.hostname}</span>
                        <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(h.created_at)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* ═══ RELATIONSHIPS ═══ */}
      {tab === 'relationships' && (
        <div className="space-y-4">
          {!relData ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading relationships…</div>
          ) : relData.nodes.length === 0 ? (
            <div className="py-16 text-center">
              <Share2 className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>No relationship data yet — connections will appear after JA3 alerts fire</p>
            </div>
          ) : (
            <div className="g-card p-4">
              <div className="flex items-center gap-3 mb-4">
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>JA3 → Agent → IP Relationships</p>
                <div className="flex items-center gap-3 ml-auto">
                  {[
                    { color: 'var(--red)', label: 'JA3 Hash' },
                    { color: 'var(--blue)', label: 'Agent' },
                    { color: 'var(--yellow)', label: 'External IP' },
                  ].map(l => (
                    <div key={l.label} className="flex items-center gap-1">
                      <div className="h-2 w-2 rounded-full" style={{ background: l.color }} />
                      <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{l.label}</span>
                    </div>
                  ))}
                </div>
              </div>
              <RelGraph nodes={relData.nodes} edges={relData.edges} />
            </div>
          )}
        </div>
      )}

      {/* ═══ AI ANALYSIS ═══ */}
      {tab === 'ai' && (
        <div className="space-y-4">
          <div className="g-card p-5">
            <div className="flex items-center gap-2 mb-4">
              <Bot className="h-4 w-4" style={{ color: 'var(--accent)' }} />
              <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>AI JA3 Analysis</p>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Action</label>
                <select value={aiAction} onChange={e => setAiAction(e.target.value)} className="g-select">
                  {AI_ACTIONS.map(a => <option key={a.id} value={a.id}>{a.label}</option>)}
                </select>
                <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                  {AI_ACTIONS.find(a => a.id === aiAction)?.desc}
                </p>
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Select from blocklist (or type hash below)</label>
                <select className="g-select" value={aiHash} onChange={e => {
                  const entry = entries.find(en => en.hash === e.target.value);
                  setAiHash(e.target.value);
                  if (entry) setAiThreat(entry.threat_name);
                }}>
                  <option value="">— select fingerprint —</option>
                  {entries.map(e => <option key={e.id} value={e.hash}>{e.threat_name}</option>)}
                </select>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>JA3 Hash</label>
                <input value={aiHash} onChange={e => setAiHash(e.target.value)}
                  placeholder="a0e9f5d64349fb13191bc781f81f42e1" className="g-input mono" />
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Threat Name</label>
                <input value={aiThreat} onChange={e => setAiThreat(e.target.value)}
                  placeholder="e.g. Cobalt Strike" className="g-input" />
              </div>
            </div>

            {aiAction === 'generate_rule' && (
              <div className="mb-4">
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Additional Context</label>
                <textarea value={aiPrompt} onChange={e => setAiPrompt(e.target.value)} rows={2}
                  placeholder="Additional context about the threat or desired rule behavior…"
                  className="g-input w-full resize-none" />
              </div>
            )}

            <button onClick={runAI} disabled={aiLoading || !aiHash}
              className="g-btn g-btn-primary text-xs">
              <Zap className="h-3.5 w-3.5" />{aiLoading ? 'Analyzing…' : 'Run AI Analysis'}
            </button>
          </div>

          {aiResult && (
            <div className="g-card p-4">
              <div className="flex items-center justify-between mb-3">
                <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>AI Analysis Result</p>
                <button onClick={() => navigator.clipboard.writeText(JSON.stringify(aiResult, null, 2)).catch(() => {})}
                  className="g-btn g-btn-ghost text-[10px]" style={{ padding: '2px 8px' }}>
                  <Copy className="h-3 w-3" /> Copy
                </button>
              </div>

              {aiAction === 'analyze' && (
                <div className="space-y-3">
                  {(['summary', 'threat_assessment', 'ioc_type'] as const).map(k => {
                    const val = (aiResult as any)[k];
                    if (!val) return null;
                    return (
                      <div key={k} className="rounded-lg p-3" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                        <p className="text-[10px] uppercase tracking-wider font-semibold mb-1" style={{ color: 'var(--text-3)' }}>{k.replace(/_/g, ' ')}</p>
                        <p className="text-xs" style={{ color: 'var(--text-2)' }}>{val}</p>
                      </div>
                    );
                  })}
                  {(aiResult as any).recommended_actions?.length > 0 && (
                    <div className="rounded-lg p-3" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                      <p className="text-[10px] uppercase tracking-wider font-semibold mb-2" style={{ color: 'var(--text-3)' }}>Recommended Actions</p>
                      <ul className="space-y-1">
                        {((aiResult as any).recommended_actions as string[]).map((a, i) => (
                          <li key={i} className="text-xs flex items-start gap-1.5" style={{ color: 'var(--text-2)' }}>
                            <span style={{ color: 'var(--accent)' }}>→</span>{a}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {(aiResult as any).confidence !== undefined && (
                    <p className="text-xs" style={{ color: 'var(--text-3)' }}>Confidence: <span style={{ color: 'var(--accent)' }}>{(aiResult as any).confidence}%</span></p>
                  )}
                </div>
              )}

              {aiAction === 'hunt' && (
                <div className="space-y-3">
                  {(['splunk_query', 'elastic_query', 'kql_query', 'zeek_filter', 'sigma_rule'] as const).map(k => {
                    const val = (aiResult as any)[k];
                    if (!val) return null;
                    return (
                      <div key={k}>
                        <p className="text-[10px] uppercase tracking-wider font-semibold mb-1" style={{ color: 'var(--text-3)' }}>{k.replace(/_/g, ' ')}</p>
                        <pre className="text-[10px] font-mono rounded-lg p-3 overflow-auto"
                          style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-2)', maxHeight: 200 }}>{val}</pre>
                      </div>
                    );
                  })}
                </div>
              )}

              {(aiAction === 'explain' || aiAction === 'generate_rule') && (
                <pre className="p-3 text-[11px] font-mono rounded-xl overflow-auto"
                  style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-2)', maxHeight: 500 }}>
                  {JSON.stringify(aiResult, null, 2)}
                </pre>
              )}
            </div>
          )}
        </div>
      )}

      {/* ═══ WATCHLISTS ═══ */}
      {tab === 'watchlist' && (
        <div className="space-y-4">
          {/* Add to watchlist */}
          <div className="g-card p-5">
            <div className="flex items-center gap-2 mb-4">
              <BookmarkPlus className="h-4 w-4" style={{ color: 'var(--accent)' }} />
              <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Add to Watchlist</p>
            </div>
            <div className="grid grid-cols-3 gap-3 mb-3">
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>JA3 Hash (optional)</label>
                <input value={wlForm.hash} onChange={e => setWlForm(f => ({ ...f, hash: e.target.value }))}
                  placeholder="32-char hex or leave blank" className="g-input mono text-xs" />
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Label *</label>
                <input value={wlForm.label} onChange={e => setWlForm(f => ({ ...f, label: e.target.value }))}
                  placeholder="e.g. High-Risk JA3s" className="g-input text-xs" />
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Type</label>
                <select value={wlForm.watch_type} onChange={e => setWlForm(f => ({ ...f, watch_type: e.target.value }))} className="g-select text-xs">
                  <option value="custom">Custom</option>
                  <option value="high_risk">High Risk</option>
                  <option value="rare">Rare</option>
                  <option value="new">New</option>
                  <option value="malicious">Known Malicious</option>
                </select>
              </div>
            </div>
            <button onClick={addToWatchlist} disabled={wlSaving || !wlForm.label.trim()} className="g-btn g-btn-primary text-xs">
              {wlSaving ? 'Adding…' : 'Add to Watchlist'}
            </button>
          </div>

          {/* Watchlist */}
          {watchlist.length > 0 && (
            <div className="g-card p-4">
              <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Tracked Fingerprints</p>
              <div className="g-table">
                <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 200px 80px 100px 24px' }}>
                  <span>Label</span><span>Hash</span><span>Type</span><span>Added</span><span />
                </div>
                {watchlist.map(w => (
                  <div key={w.id} className="g-tr grid gap-3 items-center px-4" style={{ gridTemplateColumns: '1fr 200px 80px 100px 24px' }}>
                    <span className="text-xs" style={{ color: 'var(--text-1)' }}>{w.label}</span>
                    <span className="text-[10px] font-mono truncate" style={{ color: 'var(--text-3)' }}>{w.hash || '—'}</span>
                    <span className="text-[10px] capitalize" style={{ color: 'var(--text-3)' }}>{w.watch_type}</span>
                    <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(w.created_at)}</span>
                    <button onClick={() => removeFromWatchlist(w.id)} style={{ color: 'var(--text-3)' }}
                      onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--red)'}
                      onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Bulk ops */}
          <div className="g-card p-5">
            <div className="flex items-center gap-2 mb-4">
              <CheckSquare className="h-4 w-4" style={{ color: 'var(--accent)' }} />
              <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Bulk Operations</p>
              {selected.size > 0 && (
                <span className="text-[10px] rounded px-1.5 py-0.5" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>
                  {selected.size} selected in Library
                </span>
              )}
            </div>
            <div className="flex items-center gap-3 mb-3">
              <select value={bulkAction} onChange={e => setBulkAction(e.target.value)} className="g-select text-xs" style={{ width: 160 }}>
                <option value="enable">Enable selected</option>
                <option value="disable">Disable selected</option>
                <option value="delete">Delete selected</option>
              </select>
              <button onClick={runBulk} disabled={bulkLoading || selected.size === 0} className="g-btn g-btn-primary text-xs">
                <Zap className="h-3.5 w-3.5" />{bulkLoading ? 'Running…' : `Apply to ${selected.size || 0} entries`}
              </button>
            </div>
            <div className="flex flex-wrap gap-2">
              <p className="text-xs w-full" style={{ color: 'var(--text-3)' }}>Quick select (go to Library tab to review):</p>
              {[
                { label: 'All', fn: () => setSelected(new Set(entries.map(e => e.id))) },
                { label: 'Critical', fn: () => setSelected(new Set(entries.filter(e => e.severity === 'critical').map(e => e.id))) },
                { label: 'Custom only', fn: () => setSelected(new Set(entries.filter(e => !e.is_platform).map(e => e.id))) },
                { label: 'Clear', fn: () => setSelected(new Set()) },
              ].map(h => <button key={h.label} onClick={h.fn} className="g-btn g-btn-ghost text-xs">{h.label}</button>)}
            </div>
          </div>

          {/* Export */}
          <div className="g-card p-5">
            <div className="flex items-center gap-2 mb-3">
              <Download className="h-4 w-4" style={{ color: 'var(--accent)' }} />
              <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Export Fingerprints</p>
            </div>
            <p className="text-xs mb-4" style={{ color: 'var(--text-3)' }}>
              Export your JA3 blocklist. Select entries in Library to export a subset, or export all enabled fingerprints.
              {selected.size > 0 && <span style={{ color: 'var(--accent)' }}> {selected.size} selected.</span>}
            </p>
            <div className="flex flex-wrap gap-3">
              <button onClick={() => exportEntries('csv')} className="g-btn g-btn-primary text-xs">
                <Download className="h-3.5 w-3.5" /> Export CSV
              </button>
              <button onClick={() => exportEntries('json')} className="g-btn g-btn-ghost text-xs">
                <Download className="h-3.5 w-3.5" /> Export JSON
              </button>
              <button onClick={() => exportEntries('stix')} className="g-btn g-btn-ghost text-xs">
                <BarChart3 className="h-3.5 w-3.5" /> Export STIX 2.1
              </button>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
