'use client';

import {
  useState, useEffect, useCallback, useMemo, useRef,
} from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { threatActorsAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import { Activity, AlertCircle, AlertTriangle, ArrowRight, BarChart3, Brain, Check, CheckCircle2, Clock, Copy, Crosshair, Database, Edit2, Eye, Globe, Layers, Network, Play, Plus, RefreshCw, Search, Shield, Target, Trash2, Users, X, Zap, Lock } from '@/lib/icon-stubs';

// ── Types ─────────────────────────────────────────────────────────────────────

type ViewTab =
  | 'dashboard' | 'actors' | 'campaigns' | 'malware' | 'infrastructure'
  | 'mitre' | 'iocs' | 'timeline' | 'exposure' | 'detection'
  | 'hunt' | 'relationships' | 'analytics' | 'ai';

interface Actor {
  id: number; name: string; aliases: string[]; origin_country: string;
  motivation: string; sophistication: string; description: string;
  targeted_sectors: string[]; mitre_techniques: string[];
  is_builtin: boolean; recent_alert_count: number; created_at: string;
}

interface ActorDetail {
  actor: Actor; first_seen: string | null; last_seen: string | null;
  alert_count: number; ioc_count: number; campaign_count: number;
  risk_score: number; attribution_confidence: number; status: string;
}

interface Dashboard {
  total: number; high_risk: number; new_this_month: number;
  active_in_org: number; active_campaigns: number;
  industries: Array<{ sector: string; count: number }>;
  countries: Array<{ country: string; count: number }>;
  campaign_timeline: Array<{ month: string; count: number }>;
  motivation_breakdown: Array<{ motivation: string; count: number }>;
}

interface Campaign {
  technique: string; alert_count: number; first_seen: string;
  last_seen: string; avg_confidence: number; status: string;
}

interface MalwareEntry {
  technique: string; malware_type: string; category: string;
  alert_count: number; last_seen: string;
}

interface InfraEntry {
  id: number; indicator: string; type: string; severity: string;
  hit_count: number; last_seen: string;
}

interface MITREEntry {
  technique: string; tactic: string; sigma_enabled: number;
  sigma_total: number; alert_count: number;
}

interface IOCEntry {
  id: number; indicator: string; type: string; severity: string;
  hit_count: number; last_seen: string; description: string; enabled: boolean;
}

interface TimelineEvent {
  id: number; rule_name: string; severity: string; hostname: string;
  matched_technique: string; confidence: number; tagged_at: string;
}

interface ExposureData {
  actor_id: number; actor_name: string;
  alert_count: number; alert_count_30d: number;
  ioc_count: number; incident_count: number;
  matching_tech_count: number; exposure_score: number;
  matching_assets: Array<{ hostname: string; alert_count: number; last_seen: string }>;
  recent_alerts: Array<{ id: number; rule_name: string; severity: string; hostname: string; matched_technique: string; confidence: number; tagged_at: string }>;
}

interface DetectionCoverage {
  techniques: Array<{ technique: string; sigma_total: number; sigma_enabled: number; correlation_rules: number; covered: boolean }>;
  total_techniques: number; covered_techniques: number; coverage_pct: number;
  sigma_total: number; yara_total: number; correlation_total: number;
}

interface RelNode { id: string; label: string; type: string; count?: number; }
interface RelEdge { source: string; target: string; label: string; }

interface Analytics {
  top_actors: Array<{ id: number; name: string; motivation: string; sophistication: string; alert_count: number }>;
  top_techniques: Array<{ technique: string; count: number }>;
  sophistication_breakdown: Array<{ sophistication: string; count: number }>;
  activity_over_time: Array<{ week: string; count: number }>;
}

interface AIResult { raw: string; parsed: Record<string, unknown> | null; }

// ── Constants ─────────────────────────────────────────────────────────────────

const MOTIV_COLOR: Record<string, string> = {
  espionage: '#38bdf8', financial: '#22c55e', destructive: '#f85149',
  hacktivism: '#a855f7', unknown: 'var(--text-3)',
};
const SOPH_COLOR: Record<string, string> = {
  'nation-state': '#f85149', high: '#fb923c', medium: '#fbbf24', low: '#22c55e',
};
const SEV_COLOR: Record<string, string> = {
  critical: '#f85149', high: '#fb923c', medium: '#fbbf24',
  low: '#22c55e', informational: 'var(--text-3)',
};
const MALWARE_COLOR: Record<string, string> = {
  ransomware: '#f85149', rat: '#fb923c', loader: '#fbbf24',
  backdoor: '#a855f7', wiper: '#f85149', credential_stealer: '#38bdf8',
  downloader: '#22c55e', other: 'var(--text-3)',
};
const NODE_COLORS: Record<string, string> = {
  actor: '#f85149', campaign: '#fb923c', ioc: 'var(--accent)',
  alert: '#fbbf24', incident: '#a855f7',
};

const MOTIVATIONS  = ['espionage', 'financial', 'destructive', 'hacktivism', 'unknown'];
const SOPHISTICATION = ['low', 'medium', 'high', 'nation-state'];

const TABS: Array<{ id: ViewTab; label: string; icon: React.ElementType; needsActor?: boolean }> = [
  { id: 'dashboard',      label: 'Dashboard',    icon: BarChart3 },
  { id: 'actors',         label: 'Actors',        icon: Users },
  { id: 'campaigns',      label: 'Campaigns',     icon: Target,   needsActor: true },
  { id: 'malware',        label: 'Malware',       icon: AlertCircle, needsActor: true },
  { id: 'infrastructure', label: 'Infrastructure', icon: Database, needsActor: true },
  { id: 'mitre',          label: 'MITRE',         icon: Layers,   needsActor: true },
  { id: 'iocs',           label: 'IOC Library',   icon: Shield,   needsActor: true },
  { id: 'timeline',       label: 'Timeline',      icon: Clock,    needsActor: true },
  { id: 'exposure',       label: 'Exposure',      icon: Eye,      needsActor: true },
  { id: 'detection',      label: 'Detection',     icon: CheckCircle2, needsActor: true },
  { id: 'hunt',           label: 'Hunt',          icon: Crosshair, needsActor: true },
  { id: 'relationships',  label: 'Graph',         icon: Network,  needsActor: true },
  { id: 'analytics',      label: 'Analytics',     icon: Activity },
  { id: 'ai',             label: 'AI Intel',      icon: Brain,    needsActor: true },
];

const KILL_CHAIN_STAGES = [
  { stage: 'Initial Access',   techniques: ['T1566','T1190','T1133'] },
  { stage: 'Execution',        techniques: ['T1059','T1204','T1203'] },
  { stage: 'Persistence',      techniques: ['T1547','T1543','T1098'] },
  { stage: 'Defense Evasion',  techniques: ['T1055','T1562','T1070'] },
  { stage: 'Credential Access', techniques: ['T1078','T1003','T1110'] },
  { stage: 'Lateral Movement', techniques: ['T1021','T1076','T1091'] },
  { stage: 'C2',               techniques: ['T1105','T1071','T1573'] },
  { stage: 'Exfiltration',     techniques: ['T1041','T1048'] },
];

// ── Small helpers ─────────────────────────────────────────────────────────────

function sevBadge(sev: string) {
  const color = SEV_COLOR[sev] ?? 'var(--text-3)';
  return (
    <span className="px-2 py-0.5 rounded text-[10px] font-bold capitalize"
      style={{ background: `color-mix(in srgb, ${color} 15%, transparent)`, color }}>
      {sev || '—'}
    </span>
  );
}

function MiniBar({ value, max, color }: { value: number; max: number; color: string }) {
  const pct = max > 0 ? Math.max(2, (value / max) * 100) : 2;
  return (
    <div className="h-1.5 flex-1 rounded-full overflow-hidden" style={{ background: 'var(--glass-bg-2)' }}>
      <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: color }} />
    </div>
  );
}

function CopyBtn({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(text).catch(() => {}); setDone(true); setTimeout(() => setDone(false), 1500); }}
      style={{ color: done ? 'var(--accent)' : 'var(--text-3)' }}>
      {done ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  );
}

function KPICard({ label, value, sub, color, icon: Icon }: {
  label: string; value: number | string; sub?: string; color: string; icon: React.ElementType;
}) {
  return (
    <div className="g-card p-4 flex items-start gap-3">
      <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
        style={{ background: `color-mix(in srgb, ${color} 15%, transparent)` }}>
        <Icon className="w-4 h-4" style={{ color }} />
      </div>
      <div className="min-w-0">
        <p className="text-[10px] uppercase tracking-wider mb-0.5 font-medium" style={{ color: 'var(--text-3)' }}>{label}</p>
        <p className="text-2xl font-bold leading-none" style={{ color }}>{value}</p>
        {sub && <p className="text-[11px] mt-1" style={{ color: 'var(--text-3)' }}>{sub}</p>}
      </div>
    </div>
  );
}

function SparkBar({ data, keyName }: { data: Array<Record<string, unknown>>; keyName: string }) {
  const values = data.map(d => Number(d[keyName] ?? 0));
  const max = Math.max(...values, 1);
  if (!data.length) return <div className="h-10 text-xs flex items-center" style={{ color: 'var(--text-3)' }}>No data</div>;
  return (
    <div className="flex items-end gap-0.5 h-10">
      {data.map((d, i) => (
        <div key={i} className="flex-1 rounded-sm min-w-[4px]"
          style={{ height: `${Math.max(4, (values[i] / max) * 40)}px`, background: 'var(--accent)', opacity: 0.8 }} />
      ))}
    </div>
  );
}

function ConfidenceBar({ value }: { value: number }) {
  const color = value >= 70 ? '#22c55e' : value >= 40 ? '#fbbf24' : '#f85149';
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: 'var(--glass-bg-2)' }}>
        <div className="h-full rounded-full" style={{ width: `${value}%`, background: color }} />
      </div>
      <span className="text-xs font-bold tabular-nums" style={{ color }}>{value}%</span>
    </div>
  );
}

function RiskMeter({ score }: { score: number }) {
  const color = score >= 80 ? '#f85149' : score >= 60 ? '#fb923c' : score >= 40 ? '#fbbf24' : '#22c55e';
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2.5 rounded-full overflow-hidden" style={{ background: 'var(--glass-bg-2)' }}>
        <div className="h-full rounded-full" style={{ width: `${score}%`, background: color }} />
      </div>
      <span className="text-sm font-bold tabular-nums w-8 shrink-0" style={{ color }}>{score}</span>
    </div>
  );
}

// ── Relationship Graph ─────────────────────────────────────────────────────────

function RelGraph({ nodes, edges }: { nodes: RelNode[]; edges: RelEdge[] }) {
  const layout = useMemo(() => {
    const byType: Record<string, RelNode[]> = {};
    nodes.forEach(n => { byType[n.type] = [...(byType[n.type] ?? []), n]; });
    const W = 720, H = 420;
    const pos: Record<string, { x: number; y: number }> = {};
    const cols = ['actor', 'campaign', 'ioc', 'alert', 'incident'];
    cols.forEach((type, ci) => {
      const items = byType[type] ?? [];
      const x = 60 + ci * 155;
      items.forEach((n, i) => {
        pos[n.id] = { x, y: 50 + (i * Math.min(80, (H - 100) / Math.max(items.length, 1))) };
      });
    });
    return pos;
  }, [nodes]);

  if (!nodes.length) return (
    <div className="py-12 text-center text-xs" style={{ color: 'var(--text-3)' }}>
      No relationship data. Select an actor with alerts and IOCs to view the graph.
    </div>
  );

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-3 text-[10px]">
        {Object.entries(NODE_COLORS).map(([t, c]) => (
          <span key={t} className="flex items-center gap-1 capitalize">
            <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: c }} />{t}
          </span>
        ))}
      </div>
      <svg width="100%" viewBox="0 0 720 420" className="rounded-xl"
        style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
        {/* Column headers */}
        {['Actor','Campaign','IOC','Alert','Incident'].map((l, i) => (
          <text key={l} x={60 + i * 155} y={18} textAnchor="middle" fontSize={9} fill="var(--text-3)">{l}</text>
        ))}
        {edges.map((e, i) => {
          const s = layout[e.source]; const t = layout[e.target];
          if (!s || !t) return null;
          return <line key={i} x1={s.x} y1={s.y} x2={t.x} y2={t.y} stroke="var(--border)" strokeWidth={1.5} strokeOpacity={0.7} />;
        })}
        {nodes.map(n => {
          const p = layout[n.id];
          if (!p) return null;
          const color = NODE_COLORS[n.type] ?? 'var(--text-3)';
          const r = Math.min(18, 8 + (n.count ?? 1));
          return (
            <g key={n.id} transform={`translate(${p.x},${p.y})`}>
              <circle r={r} fill={`color-mix(in srgb, ${color} 20%, var(--glass-bg))`} stroke={color} strokeWidth={1.5} />
              <text y={r + 13} textAnchor="middle" fontSize={8.5} fill="var(--text-2)" className="select-none">
                {n.label.length > 16 ? n.label.slice(0, 15) + '…' : n.label}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// ── Kill Chain Visualizer ──────────────────────────────────────────────────────

function KillChainView({ techniques }: { techniques: string[] }) {
  const techSet = new Set(techniques);
  const active = KILL_CHAIN_STAGES.filter(s => s.techniques.some(t => techSet.has(t)));
  const stages = KILL_CHAIN_STAGES.map(s => ({
    ...s,
    covered: s.techniques.some(t => techSet.has(t)),
  }));

  return (
    <div className="space-y-2">
      <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
        Actor covers {active.length} of {KILL_CHAIN_STAGES.length} kill chain stages.
      </p>
      <div className="space-y-1.5">
        {stages.map((s, i) => (
          <div key={s.stage} className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 w-36 shrink-0">
              <span className="w-4 h-4 rounded-full flex items-center justify-center shrink-0 text-[8px] font-bold"
                style={{ background: s.covered ? 'rgba(248,81,73,0.2)' : 'var(--glass-bg-2)', color: s.covered ? '#f85149' : 'var(--text-3)', border: `1px solid ${s.covered ? 'rgba(248,81,73,0.5)' : 'var(--border)'}` }}>
                {i + 1}
              </span>
              <span className="text-[10px] font-medium" style={{ color: s.covered ? 'var(--text-1)' : 'var(--text-3)' }}>{s.stage}</span>
            </div>
            <div className="flex flex-wrap gap-1 flex-1">
              {s.techniques.map(t => {
                const hit = techSet.has(t);
                return (
                  <span key={t} className="font-mono text-[9px] px-1.5 py-0.5 rounded"
                    style={{
                      background: hit ? 'rgba(248,81,73,0.15)' : 'var(--glass-bg)',
                      color: hit ? '#f85149' : 'var(--text-3)',
                      border: `1px solid ${hit ? 'rgba(248,81,73,0.4)' : 'var(--border)'}`,
                    }}>
                    {t}
                  </span>
                );
              })}
            </div>
            {i < stages.length - 1 && s.covered && (
              <ArrowRight className="w-3 h-3 shrink-0" style={{ color: 'var(--text-3)' }} />
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Actor List + Profile ───────────────────────────────────────────────────────

function ActorListPanel({ actors, selected, onSelect, onDelete, onEdit }: {
  actors: Actor[]; selected: Actor | null;
  onSelect: (a: Actor) => void; onDelete: (id: number) => void; onEdit: (a: Actor) => void;
}) {
  const [search, setSearch] = useState('');
  const [motivFilter, setMotivFilter] = useState('all');

  const filtered = useMemo(() => {
    let list = actors;
    if (motivFilter !== 'all') list = list.filter(a => a.motivation === motivFilter);
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(a =>
        a.name.toLowerCase().includes(q) ||
        a.origin_country.toLowerCase().includes(q) ||
        (a.mitre_techniques ?? []).some(t => t.toLowerCase().includes(q)) ||
        (a.aliases ?? []).some(x => x.toLowerCase().includes(q))
      );
    }
    return list;
  }, [actors, search, motivFilter]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2 items-center">
        <div className="relative flex-1 min-w-[180px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--text-3)' }} />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search actors, techniques, country…" className="g-input pl-9 w-full text-xs" />
        </div>
        <select value={motivFilter} onChange={e => setMotivFilter(e.target.value)} className="g-select text-xs">
          <option value="all">All Motivations</option>
          {MOTIVATIONS.map(m => <option key={m} value={m}>{m}</option>)}
        </select>
        <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{filtered.length} actors</span>
      </div>

      <div className="space-y-1.5">
        {filtered.map(a => {
          const motivColor = MOTIV_COLOR[a.motivation] ?? 'var(--text-3)';
          const sophColor = SOPH_COLOR[a.sophistication] ?? 'var(--text-3)';
          const isSelected = selected?.id === a.id;
          return (
            <div key={a.id}
              className="g-card overflow-hidden cursor-pointer transition-colors"
              style={{ border: isSelected ? `1px solid ${motivColor}` : undefined }}
              onClick={() => onSelect(a)}>
              <div className="flex items-center gap-3 px-4 py-3">
                <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 text-xs font-bold"
                  style={{ background: `color-mix(in srgb, ${motivColor} 15%, transparent)`, color: motivColor, border: `1px solid color-mix(in srgb, ${motivColor} 30%, transparent)` }}>
                  {a.name.slice(0, 2).toUpperCase()}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{a.name}</span>
                    <span className="text-[9px] px-1.5 py-0.5 rounded font-bold uppercase"
                      style={{ background: `color-mix(in srgb, ${sophColor} 15%, transparent)`, color: sophColor, border: `1px solid color-mix(in srgb, ${sophColor} 30%, transparent)` }}>
                      {a.sophistication}
                    </span>
                    <span className="text-[9px] px-1.5 py-0.5 rounded capitalize"
                      style={{ background: `color-mix(in srgb, ${motivColor} 12%, transparent)`, color: motivColor }}>
                      {a.motivation}
                    </span>
                    {a.origin_country && (
                      <span className="text-[10px] flex items-center gap-0.5" style={{ color: 'var(--text-3)' }}>
                        <Globe className="w-2.5 h-2.5" />{a.origin_country}
                      </span>
                    )}
                    {a.recent_alert_count > 0 && (
                      <span className="text-[10px] flex items-center gap-0.5" style={{ color: '#f85149' }}>
                        <AlertTriangle className="w-3 h-3" />{a.recent_alert_count} alerts
                      </span>
                    )}
                    {a.is_builtin && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded" style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)', border: '1px solid var(--border)' }}>built-in</span>
                    )}
                  </div>
                  {(a.aliases ?? []).length > 0 && (
                    <p className="text-[10px] truncate mt-0.5" style={{ color: 'var(--text-3)' }}>
                      aka: {a.aliases.join(', ')}
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  <button onClick={e => { e.stopPropagation(); onEdit(a); }}
                    className="p-1 rounded hover:opacity-70" style={{ color: 'var(--text-3)' }}>
                    <Edit2 className="w-3.5 h-3.5" />
                  </button>
                  {!a.is_builtin && (
                    <button onClick={e => { e.stopPropagation(); onDelete(a.id); }}
                      className="p-1 rounded hover:opacity-70" style={{ color: 'var(--text-3)' }}>
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>
            </div>
          );
        })}
        {filtered.length === 0 && (
          <div className="py-12 text-center">
            <Users className="mx-auto w-10 h-10 mb-3 opacity-20" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-3)' }}>
              {search || motivFilter !== 'all' ? 'No actors match.' : 'No actors yet.'}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Profile Detail Panel ───────────────────────────────────────────────────────

function ActorProfilePanel({ actor, detail }: { actor: Actor; detail: ActorDetail | null }) {
  const motivColor = MOTIV_COLOR[actor.motivation] ?? 'var(--text-3)';
  const sophColor = SOPH_COLOR[actor.sophistication] ?? 'var(--text-3)';

  return (
    <div className="g-card p-5 space-y-4">
      {/* Header */}
      <div className="flex items-start gap-4">
        <div className="w-14 h-14 rounded-xl flex items-center justify-center text-xl font-bold shrink-0"
          style={{ background: `color-mix(in srgb, ${motivColor} 15%, transparent)`, color: motivColor, border: `1px solid color-mix(in srgb, ${motivColor} 30%, transparent)` }}>
          {actor.name.slice(0, 2).toUpperCase()}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <h2 className="text-base font-bold" style={{ color: 'var(--text-1)' }}>{actor.name}</h2>
            {detail?.status && (
              <span className="text-[10px] px-2 py-0.5 rounded capitalize font-semibold"
                style={{ background: detail.status === 'active' ? 'rgba(248,81,73,0.15)' : 'var(--glass-bg-2)', color: detail.status === 'active' ? '#f85149' : 'var(--text-3)', border: `1px solid ${detail.status === 'active' ? 'rgba(248,81,73,0.3)' : 'var(--border)'}` }}>
                {detail.status}
              </span>
            )}
          </div>
          {actor.description && (
            <p className="text-xs" style={{ color: 'var(--text-2)' }}>{actor.description}</p>
          )}
        </div>
      </div>

      {/* Stats row */}
      {detail && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="p-3 rounded-lg" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
            <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>Risk Score</p>
            <RiskMeter score={detail.risk_score} />
          </div>
          <div className="p-3 rounded-lg" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
            <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>Attribution</p>
            <ConfidenceBar value={detail.attribution_confidence} />
          </div>
          <div className="p-3 rounded-lg" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
            <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>Alerts</p>
            <p className="text-lg font-bold" style={{ color: detail.alert_count > 0 ? '#f85149' : 'var(--text-3)' }}>{detail.alert_count}</p>
          </div>
          <div className="p-3 rounded-lg" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
            <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>IOCs</p>
            <p className="text-lg font-bold" style={{ color: 'var(--accent)' }}>{detail.ioc_count}</p>
          </div>
        </div>
      )}

      {/* Profile fields grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
        <div>
          <p className="text-[10px] uppercase tracking-wider mb-0.5 font-semibold" style={{ color: 'var(--text-3)' }}>Sophistication</p>
          <span className="px-2 py-0.5 rounded font-bold uppercase text-[10px]"
            style={{ background: `color-mix(in srgb, ${sophColor} 15%, transparent)`, color: sophColor, border: `1px solid color-mix(in srgb, ${sophColor} 30%, transparent)` }}>
            {actor.sophistication}
          </span>
        </div>
        <div>
          <p className="text-[10px] uppercase tracking-wider mb-0.5 font-semibold" style={{ color: 'var(--text-3)' }}>Motivation</p>
          <span className="capitalize" style={{ color: motivColor }}>{actor.motivation}</span>
        </div>
        <div>
          <p className="text-[10px] uppercase tracking-wider mb-0.5 font-semibold" style={{ color: 'var(--text-3)' }}>Origin</p>
          <span style={{ color: 'var(--text-2)' }}>{actor.origin_country || '—'}</span>
        </div>
        {detail && (
          <>
            <div>
              <p className="text-[10px] uppercase tracking-wider mb-0.5 font-semibold" style={{ color: 'var(--text-3)' }}>First Observed</p>
              <span style={{ color: 'var(--text-2)' }}>{detail.first_seen ? timeAgo(detail.first_seen) : '—'}</span>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wider mb-0.5 font-semibold" style={{ color: 'var(--text-3)' }}>Last Activity</p>
              <span style={{ color: 'var(--text-2)' }}>{detail.last_seen ? timeAgo(detail.last_seen) : '—'}</span>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wider mb-0.5 font-semibold" style={{ color: 'var(--text-3)' }}>Campaigns</p>
              <span style={{ color: 'var(--text-2)' }}>{detail.campaign_count}</span>
            </div>
          </>
        )}
      </div>

      {(actor.aliases ?? []).length > 0 && (
        <div>
          <p className="text-[10px] uppercase tracking-wider mb-1.5 font-semibold" style={{ color: 'var(--text-3)' }}>Known Aliases</p>
          <div className="flex flex-wrap gap-1">
            {actor.aliases.map(al => (
              <span key={al} className="text-[10px] px-2 py-0.5 rounded"
                style={{ background: 'var(--glass-bg-2)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>
                {al}
              </span>
            ))}
          </div>
        </div>
      )}

      {(actor.targeted_sectors ?? []).length > 0 && (
        <div>
          <p className="text-[10px] uppercase tracking-wider mb-1.5 font-semibold" style={{ color: 'var(--text-3)' }}>Typical Targets</p>
          <div className="flex flex-wrap gap-1">
            {actor.targeted_sectors.map(s => (
              <span key={s} className="text-[10px] px-2 py-0.5 rounded capitalize"
                style={{ background: 'rgba(251,191,36,0.12)', color: '#fbbf24', border: '1px solid rgba(251,191,36,0.3)' }}>
                {s}
              </span>
            ))}
          </div>
        </div>
      )}

      {(actor.mitre_techniques ?? []).length > 0 && (
        <div>
          <p className="text-[10px] uppercase tracking-wider mb-1.5 font-semibold" style={{ color: 'var(--text-3)' }}>MITRE Techniques</p>
          <div className="flex flex-wrap gap-1">
            {actor.mitre_techniques.map(t => (
              <a key={t} href={`https://attack.mitre.org/techniques/${t.replace('.','/')}`} target="_blank" rel="noopener noreferrer"
                className="font-mono text-[10px] px-1.5 py-0.5 rounded hover:underline"
                style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                {t}
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Modal helper ───────────────────────────────────────────────────────────────

function ActorFormModal({
  title, initial, onClose, onSave,
}: {
  title: string;
  initial: Partial<{ name: string; origin_country: string; motivation: string; sophistication: string; description: string; aliases: string; targeted_sectors: string; mitre_techniques: string }>;
  onClose: () => void;
  onSave: (data: Record<string, unknown>) => Promise<void>;
}) {
  const [form, setForm] = useState({
    name: initial.name ?? '',
    origin_country: initial.origin_country ?? '',
    motivation: initial.motivation ?? 'espionage',
    sophistication: initial.sophistication ?? 'medium',
    description: initial.description ?? '',
    aliases: initial.aliases ?? '',
    targeted_sectors: initial.targeted_sectors ?? '',
    mitre_techniques: initial.mitre_techniques ?? '',
  });
  const [saving, setSaving] = useState(false);
  const f = (key: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) =>
    setForm(prev => ({ ...prev, [key]: e.target.value }));

  const save = async () => {
    if (!form.name) return;
    setSaving(true);
    try {
      await onSave({
        name: form.name, origin_country: form.origin_country,
        motivation: form.motivation, sophistication: form.sophistication,
        description: form.description,
        aliases: form.aliases.split(',').map(s => s.trim()).filter(Boolean),
        targeted_sectors: form.targeted_sectors.split(',').map(s => s.trim()).filter(Boolean),
        mitre_techniques: form.mitre_techniques.split(',').map(s => s.trim()).filter(Boolean),
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="g-modal" style={{ maxWidth: 540 }}>
        <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{title}</h2>
          <button onClick={onClose} style={{ color: 'var(--text-2)' }}><X className="w-4 h-4" /></button>
        </div>
        <div className="p-5 space-y-3 max-h-[65vh] overflow-y-auto">
          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2">
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Name *</label>
              <input value={form.name} onChange={f('name')} className="g-input w-full text-xs" placeholder="APT28, Lazarus Group…" />
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Origin Country</label>
              <input value={form.origin_country} onChange={f('origin_country')} className="g-input w-full text-xs" placeholder="Russia, China, DPRK…" />
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Motivation</label>
              <select value={form.motivation} onChange={f('motivation')} className="g-select w-full text-xs">
                {MOTIVATIONS.map(m => <option key={m} value={m}>{m}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Sophistication</label>
              <select value={form.sophistication} onChange={f('sophistication')} className="g-select w-full text-xs">
                {SOPHISTICATION.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Aliases (comma-sep)</label>
              <input value={form.aliases} onChange={f('aliases')} className="g-input w-full text-xs" placeholder="Fancy Bear, Sofacy…" />
            </div>
            <div className="col-span-2">
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>MITRE Techniques (comma-sep)</label>
              <input value={form.mitre_techniques} onChange={f('mitre_techniques')} className="g-input w-full text-xs font-mono" placeholder="T1566, T1059, T1003" />
            </div>
            <div className="col-span-2">
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Targeted Sectors (comma-sep)</label>
              <input value={form.targeted_sectors} onChange={f('targeted_sectors')} className="g-input w-full text-xs" placeholder="Government, Energy, Finance" />
            </div>
            <div className="col-span-2">
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Description</label>
              <textarea value={form.description} onChange={f('description')} className="g-input w-full text-xs resize-none" rows={3} />
            </div>
          </div>
        </div>
        <div className="flex gap-3 px-5 pb-5">
          <button onClick={onClose} className="g-btn g-btn-ghost flex-1 justify-center text-xs">Cancel</button>
          <button onClick={save} disabled={saving || !form.name} className="g-btn g-btn-primary flex-1 justify-center text-xs">
            {saving ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── AI Panel ──────────────────────────────────────────────────────────────────

function AIPanel({ actor }: { actor: Actor | null }) {
  const [action, setAction] = useState('summarize');
  const [context, setContext] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AIResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const ACTIONS = [
    { id: 'summarize',   label: 'Intelligence Summary', icon: Brain,    desc: 'Executive-level threat actor intelligence summary' },
    { id: 'recommend',   label: 'Recommendations',      icon: Shield,   desc: 'Sigma rules, IOCs, CVEs, and defensive steps' },
    { id: 'hunt_guide',  label: 'Hunt Guidance',        icon: Crosshair, desc: 'Hunting hypotheses, queries, and artifacts' },
    { id: 'risk_brief',  label: 'Risk Assessment',      icon: AlertTriangle, desc: 'Risk score, exposure narrative, and mitigations' },
  ];

  const run = async () => {
    setLoading(true); setError(null); setResult(null);
    try {
      const res = await threatActorsAPI.ai(action, actor?.id, actor?.name, context);
      const raw = typeof res.data === 'string' ? res.data : JSON.stringify(res.data, null, 2);
      let parsed: Record<string, unknown> | null = null;
      try { parsed = typeof res.data === 'object' ? res.data as Record<string, unknown> : JSON.parse(raw); } catch {}
      setResult({ raw, parsed });
    } catch {
      setError('AI analysis failed. Check that the LLM is configured.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      {!actor && (
        <div className="g-card p-4 text-xs" style={{ color: 'var(--text-3)', border: '1px solid var(--accent-border)' }}>
          Select a threat actor from the Actors tab to run actor-specific AI analysis.
          You can still run general analysis without a selection.
        </div>
      )}

      {actor && (
        <div className="g-card p-3 flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold shrink-0"
            style={{ background: `color-mix(in srgb, ${MOTIV_COLOR[actor.motivation] ?? 'var(--accent)'} 15%, transparent)`, color: MOTIV_COLOR[actor.motivation] ?? 'var(--accent)' }}>
            {actor.name.slice(0, 2).toUpperCase()}
          </div>
          <div>
            <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{actor.name}</p>
            <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{actor.sophistication} · {actor.motivation}</p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {ACTIONS.map(a => (
          <button key={a.id} onClick={() => setAction(a.id)}
            className={`p-3 rounded-xl text-left transition-colors ${action === a.id ? 'g-btn g-btn-primary' : 'g-card'}`}>
            <a.icon className="w-4 h-4 mb-2" style={{ color: action === a.id ? 'white' : 'var(--accent)' }} />
            <p className="text-xs font-medium">{a.label}</p>
            <p className="text-[10px] mt-0.5" style={{ color: action === a.id ? 'rgba(255,255,255,0.7)' : 'var(--text-3)' }}>{a.desc}</p>
          </button>
        ))}
      </div>

      <div className="g-card p-4 space-y-3">
        <div>
          <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Additional Context (optional)</label>
          <textarea value={context} onChange={e => setContext(e.target.value)}
            placeholder="Environment notes, specific concern, related incident…"
            className="g-input w-full text-xs resize-none" rows={2} />
        </div>
        <button onClick={run} disabled={loading} className="g-btn g-btn-primary text-xs">
          <Brain className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          {loading ? 'Analyzing…' : 'Run AI Analysis'}
        </button>
      </div>

      {error && <div className="g-card p-3 text-xs" style={{ color: 'var(--red)' }}>{error}</div>}

      {result && (
        <div className="g-card p-4 space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>
              {ACTIONS.find(a => a.id === action)?.label} — {actor?.name ?? 'General'}
            </p>
            <CopyBtn text={result.raw} />
          </div>
          {result.parsed ? (
            <div className="space-y-3">
              {Object.entries(result.parsed).map(([key, val]) => (
                <div key={key}>
                  <p className="text-[10px] uppercase tracking-wider mb-1 font-semibold" style={{ color: 'var(--text-3)' }}>{key.replace(/_/g, ' ')}</p>
                  {Array.isArray(val) ? (
                    <ul className="space-y-1">
                      {(val as unknown[]).map((item, i) => (
                        <li key={i} className="flex items-start gap-1.5 text-xs">
                          <span className="w-1.5 h-1.5 rounded-full mt-1 shrink-0" style={{ background: 'var(--accent)' }} />
                          <span style={{ color: 'var(--text-2)' }}>{String(item)}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-xs" style={{ color: 'var(--text-2)' }}>{String(val)}</p>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <pre className="text-[11px] p-3 rounded-lg overflow-x-auto leading-relaxed whitespace-pre-wrap"
              style={{ background: 'var(--bg-0)', color: 'var(--text-1)', border: '1px solid var(--border)' }}>
              {result.raw}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function ThreatActorsPage() {
  const [tab, setTab]             = useState<ViewTab>('dashboard');
  const [actors, setActors]       = useState<Actor[]>([]);
  const [selected, setSelected]   = useState<Actor | null>(null);
  const [loadingActors, setLoadingActors] = useState(true);
  const [toast, setToast]         = useState<string | null>(null);
  const loaded = useRef<Partial<Record<string, boolean>>>({});

  // Dashboard
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  // Analytics
  const [analytics, setAnalytics] = useState<Analytics | null>(null);
  // Per-actor data (keyed by actor id + tab)
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [sevBreakdown, setSevBreakdown] = useState<Array<{ severity: string; count: number }>>([]);
  const [malware, setMalware]     = useState<MalwareEntry[]>([]);
  const [infra, setInfra]         = useState<InfraEntry[]>([]);
  const [grouped, setGrouped]     = useState<Record<string, InfraEntry[]>>({});
  const [mitre, setMitre]         = useState<MITREEntry[]>([]);
  const [tacticSummary, setTacticSummary] = useState<Array<{ tactic: string; covered: number }>>([]);
  const [iocs, setIocs]           = useState<IOCEntry[]>([]);
  const [timelineEvents, setTimelineEvents] = useState<TimelineEvent[]>([]);
  const [timelineMonthly, setTimelineMonthly] = useState<Array<{ month: string; count: number }>>([]);
  const [exposure, setExposure]   = useState<ExposureData | null>(null);
  const [detection, setDetection] = useState<DetectionCoverage | null>(null);
  const [relNodes, setRelNodes]   = useState<RelNode[]>([]);
  const [relEdges, setRelEdges]   = useState<RelEdge[]>([]);
  const [actorDetail, setActorDetail] = useState<ActorDetail | null>(null);
  const [loadingTab, setLoadingTab] = useState(false);

  // Hunt
  const [huntType, setHuntType]   = useState('iocs');
  const [huntResult, setHuntResult] = useState<Record<string, unknown> | null>(null);
  const [hunting, setHunting]     = useState(false);

  // Response
  const [responseNote, setResponseNote] = useState('');
  const [responseMsg, setResponseMsg]   = useState<string | null>(null);
  const [responding, setResponding]     = useState(false);

  // Modals
  const [showCreate, setShowCreate] = useState(false);
  const [editActor, setEditActor]   = useState<Actor | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  // Load actor list
  const loadActors = useCallback(async () => {
    setLoadingActors(true);
    const r = await threatActorsAPI.getAll();
    setActors(r.data || []);
    setLoadingActors(false);
  }, []);

  useEffect(() => { loadActors(); }, [loadActors]);

  // Load tab data
  const loadTab = useCallback(async (t: ViewTab, actorId: number | null, force = false) => {
    const cacheKey = `${t}_${actorId ?? 'global'}`;
    if (loaded.current[cacheKey] && !force) return;
    loaded.current[cacheKey] = true;
    setLoadingTab(true);
    try {
      switch (t) {
        case 'dashboard': {
          const r = await threatActorsAPI.getDashboard();
          if (r.data) setDashboard(r.data as Dashboard);
          break;
        }
        case 'analytics': {
          const r = await threatActorsAPI.getAnalytics();
          if (r.data) setAnalytics(r.data as Analytics);
          break;
        }
        default:
          if (!actorId) break;
          switch (t) {
            case 'actors': {
              const [profR] = await Promise.all([threatActorsAPI.getProfile(actorId)]);
              if (profR.data) setActorDetail(profR.data as ActorDetail);
              break;
            }
            case 'campaigns': {
              const r = await threatActorsAPI.getCampaigns(actorId);
              const d = r.data as { campaigns?: Campaign[]; severity_breakdown?: Array<{ severity: string; count: number }> } | null;
              if (d?.campaigns) setCampaigns(d.campaigns);
              if (d?.severity_breakdown) setSevBreakdown(d.severity_breakdown);
              break;
            }
            case 'malware': {
              const r = await threatActorsAPI.getMalware(actorId);
              const d = r.data as { malware?: MalwareEntry[] } | null;
              if (d?.malware) setMalware(d.malware);
              break;
            }
            case 'infrastructure': {
              const r = await threatActorsAPI.getInfrastructure(actorId);
              const d = r.data as { iocs?: InfraEntry[]; grouped?: Record<string, InfraEntry[]> } | null;
              if (d?.iocs) setInfra(d.iocs);
              if (d?.grouped) setGrouped(d.grouped);
              break;
            }
            case 'mitre': {
              const r = await threatActorsAPI.getMITRE(actorId);
              const d = r.data as { techniques?: MITREEntry[]; tactic_summary?: Array<{ tactic: string; covered: number }> } | null;
              if (d?.techniques) setMitre(d.techniques);
              if (d?.tactic_summary) setTacticSummary(d.tactic_summary ?? []);
              break;
            }
            case 'iocs': {
              const r = await threatActorsAPI.getIOCs(actorId);
              const d = r.data as { iocs?: IOCEntry[] } | null;
              if (d?.iocs) setIocs(d.iocs);
              break;
            }
            case 'timeline': {
              const r = await threatActorsAPI.getTimeline(actorId);
              const d = r.data as { events?: TimelineEvent[]; monthly?: Array<{ month: string; count: number }> } | null;
              if (d?.events) setTimelineEvents(d.events);
              if (d?.monthly) setTimelineMonthly(d.monthly);
              break;
            }
            case 'exposure': {
              const r = await threatActorsAPI.getExposure(actorId);
              if (r.data) setExposure(r.data as ExposureData);
              break;
            }
            case 'detection': {
              const r = await threatActorsAPI.getDetectionCoverage(actorId);
              if (r.data) setDetection(r.data as DetectionCoverage);
              break;
            }
            case 'relationships': {
              const r = await threatActorsAPI.getRelationships(actorId);
              const d = r.data as { nodes?: RelNode[]; edges?: RelEdge[] } | null;
              if (d?.nodes) setRelNodes(d.nodes);
              if (d?.edges) setRelEdges(d.edges);
              break;
            }
            default: break;
          }
      }
    } finally {
      setLoadingTab(false);
    }
  }, []);

  useEffect(() => {
    const actorId = selected?.id ?? null;
    const needsActor = TABS.find(t => t.id === tab)?.needsActor;
    if (needsActor && !actorId) return;
    loadTab(tab, actorId);
  }, [tab, selected, loadTab]);

  // Reset per-actor cache when selected changes
  const selectActor = (a: Actor) => {
    setSelected(a);
    // Clear per-actor cached tabs
    const keys = Object.keys(loaded.current);
    keys.forEach(k => { if (!k.endsWith('_global')) delete loaded.current[k]; });
    if (tab === 'actors') {
      loadTab('actors', a.id);
    }
  };

  // CRUD
  const createActor = async (data: Record<string, unknown>) => {
    await threatActorsAPI.create(data);
    await loadActors();
    setShowCreate(false);
    notify('Actor added');
  };
  const updateActor = async (data: Record<string, unknown>) => {
    if (!editActor) return;
    await threatActorsAPI.update(editActor.id, data);
    await loadActors();
    setEditActor(null);
    notify('Actor updated');
    // Invalidate profile cache
    delete loaded.current[`actors_${editActor.id}`];
  };
  const deleteActor = async (id: number) => {
    await threatActorsAPI.remove(id);
    setActors(prev => prev.filter(a => a.id !== id));
    if (selected?.id === id) setSelected(null);
    notify('Actor deleted');
  };

  // Hunt
  const runHunt = async () => {
    if (!selected) return;
    setHunting(true); setHuntResult(null);
    try {
      const r = await threatActorsAPI.hunt(selected.id, huntType);
      setHuntResult(r.data as Record<string, unknown>);
    } finally { setHunting(false); }
  };

  // Response
  const runResponse = async (action: string) => {
    if (!selected) return;
    setResponding(true); setResponseMsg(null);
    try {
      const r = await threatActorsAPI.response(selected.id, action, responseNote);
      const d = r.data as { message?: string };
      setResponseMsg(d.message ?? 'Action completed');
    } catch {
      setResponseMsg('Action failed');
    } finally { setResponding(false); }
  };

  const needsActor = TABS.find(t => t.id === tab)?.needsActor;
  const activeActors = useMemo(() => actors.filter(a => a.recent_alert_count > 0).length, [actors]);
  const maxCountry = useMemo(() => Math.max(...(dashboard?.countries.map(c => c.count) ?? []), 1), [dashboard]);
  const maxSector  = useMemo(() => Math.max(...(dashboard?.industries.map(s => s.count) ?? []), 1), [dashboard]);
  const maxTech    = useMemo(() => Math.max(...(analytics?.top_techniques.map(t => t.count) ?? []), 1), [analytics]);
  const maxActor   = useMemo(() => Math.max(...(analytics?.top_actors.map(a => a.alert_count) ?? []), 1), [analytics]);

  return (
    <RootLayout title="Threat Actor Intelligence"
      subtitle={`${actors.length} actors · ${activeActors} active in env · ${selected ? `Viewing: ${selected.name}` : 'No actor selected'}`}
      actions={
        <div className="flex items-center gap-2">
          <button onClick={() => { loaded.current = {}; loadActors(); loadTab(tab, selected?.id ?? null, true); }} className="g-btn g-btn-ghost text-xs">
            <RefreshCw className={`w-3.5 h-3.5 ${loadingTab ? 'animate-spin' : ''}`} />
          </button>
          <button onClick={() => setShowCreate(true)} className="g-btn g-btn-primary text-xs">
            <Plus className="w-3.5 h-3.5" /> Add Actor
          </button>
        </div>
      }>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 g-card px-4 py-2.5 text-sm" style={{ color: 'var(--text-1)' }}>{toast}</div>
      )}

      {/* Tab bar */}
      <div className="flex gap-0.5 mb-4 overflow-x-auto pb-1">
        {TABS.map(t => {
          const disabled = t.needsActor && !selected;
          return (
            <button key={t.id} onClick={() => !disabled && setTab(t.id)}
              title={disabled ? 'Select an actor first' : undefined}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors
                ${tab === t.id ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'}
                ${disabled ? 'opacity-40 cursor-not-allowed' : ''}`}>
              <t.icon className="w-3.5 h-3.5" />
              {t.label}
            </button>
          );
        })}
      </div>

      {/* "Needs actor" guard */}
      {needsActor && !selected && (
        <div className="g-card p-8 text-center">
          <Users className="mx-auto w-12 h-12 mb-4 opacity-20" style={{ color: 'var(--text-3)' }} />
          <p className="text-sm font-medium mb-1" style={{ color: 'var(--text-1)' }}>No actor selected</p>
          <p className="text-xs mb-4" style={{ color: 'var(--text-3)' }}>Go to the Actors tab and click an actor to view its details.</p>
          <button onClick={() => setTab('actors')} className="g-btn g-btn-primary text-xs">
            <Users className="w-3.5 h-3.5" /> Browse Actors
          </button>
        </div>
      )}

      {/* ── Dashboard ── */}
      {tab === 'dashboard' && (
        <div className="space-y-4">
          {dashboard ? (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                <KPICard label="Total Actors"     value={dashboard.total}            color="var(--accent)"  icon={Users} />
                <KPICard label="High Risk"        value={dashboard.high_risk}         color="var(--red)"     icon={AlertTriangle} />
                <KPICard label="New This Month"   value={dashboard.new_this_month}    color="#fbbf24"        icon={Plus} />
                <KPICard label="Active in Org"    value={dashboard.active_in_org}     color="var(--red)"     icon={Eye}
                  sub={dashboard.active_in_org > 0 ? 'alerts last 30d' : 'no recent activity'} />
                <KPICard label="Active Campaigns" value={dashboard.active_campaigns}  color="#fb923c"        icon={Target} />
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Motivation breakdown */}
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Motivation Breakdown</p>
                  <div className="space-y-2">
                    {dashboard.motivation_breakdown.map(m => {
                      const color = MOTIV_COLOR[m.motivation] ?? 'var(--text-3)';
                      const max = Math.max(...dashboard.motivation_breakdown.map(x => x.count), 1);
                      return (
                        <div key={m.motivation} className="flex items-center gap-2">
                          <span className="w-20 shrink-0 text-xs capitalize" style={{ color }}>{m.motivation}</span>
                          <MiniBar value={m.count} max={max} color={color} />
                          <span className="text-[11px] font-bold tabular-nums w-5 shrink-0" style={{ color }}>{m.count}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Campaign timeline */}
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Activity Timeline (12 months)</p>
                  <SparkBar data={dashboard.campaign_timeline as Array<Record<string, unknown>>} keyName="count" />
                  {dashboard.campaign_timeline.length > 0 && (
                    <div className="flex justify-between mt-1 text-[9px]" style={{ color: 'var(--text-3)' }}>
                      <span>{dashboard.campaign_timeline[0]?.month}</span>
                      <span>{dashboard.campaign_timeline[dashboard.campaign_timeline.length - 1]?.month}</span>
                    </div>
                  )}
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Industries */}
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Industries Targeted</p>
                  <div className="space-y-2">
                    {dashboard.industries.map(s => (
                      <div key={s.sector} className="flex items-center gap-2">
                        <span className="text-xs w-28 shrink-0 truncate capitalize" style={{ color: 'var(--text-2)' }}>{s.sector}</span>
                        <MiniBar value={s.count} max={maxSector} color="#fbbf24" />
                        <span className="text-[11px] font-bold w-5 tabular-nums shrink-0 text-right" style={{ color: '#fbbf24' }}>{s.count}</span>
                      </div>
                    ))}
                    {dashboard.industries.length === 0 && <p className="text-xs" style={{ color: 'var(--text-3)' }}>No sector data</p>}
                  </div>
                </div>

                {/* Countries */}
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Countries of Origin</p>
                  <div className="space-y-2">
                    {dashboard.countries.map(c => (
                      <div key={c.country} className="flex items-center gap-2">
                        <span className="text-xs w-20 shrink-0 truncate" style={{ color: 'var(--text-2)' }}>{c.country}</span>
                        <MiniBar value={c.count} max={maxCountry} color="#38bdf8" />
                        <span className="text-[11px] font-bold w-5 tabular-nums shrink-0 text-right" style={{ color: '#38bdf8' }}>{c.count}</span>
                      </div>
                    ))}
                    {dashboard.countries.length === 0 && <p className="text-xs" style={{ color: 'var(--text-3)' }}>No country data</p>}
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          )}
        </div>
      )}

      {/* ── Actors Tab ── */}
      {tab === 'actors' && (
        <div className={`grid gap-4 ${selected ? 'grid-cols-1 lg:grid-cols-2' : 'grid-cols-1'}`}>
          <ActorListPanel actors={actors} selected={selected}
            onSelect={a => { selectActor(a); }}
            onDelete={deleteActor}
            onEdit={a => setEditActor(a)} />
          {selected && (
            <div className="space-y-3">
              <ActorProfilePanel actor={selected} detail={actorDetail} />
              <div className="flex flex-wrap gap-2">
                {(['campaigns','mitre','exposure','detection','ai'] as ViewTab[]).map(t => (
                  <button key={t} onClick={() => setTab(t)} className="g-btn g-btn-ghost text-xs capitalize">
                    {t}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Campaigns ── */}
      {tab === 'campaigns' && selected && (
        <div className="space-y-4">
          <p className="text-xs" style={{ color: 'var(--text-3)' }}>
            Campaigns attributed to <span className="font-semibold" style={{ color: 'var(--text-1)' }}>{selected.name}</span> — inferred from matched alert techniques.
          </p>
          {campaigns.length > 0 ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {campaigns.map(cp => (
                <div key={cp.technique} className="g-card p-4">
                  <div className="flex items-start justify-between mb-2">
                    <span className="font-mono text-sm font-bold" style={{ color: '#fbbf24' }}>{cp.technique}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded capitalize"
                      style={{ background: cp.status === 'active' ? 'rgba(248,81,73,0.15)' : 'var(--glass-bg-2)', color: cp.status === 'active' ? 'var(--red)' : 'var(--text-3)', border: `1px solid ${cp.status === 'active' ? 'rgba(248,81,73,0.3)' : 'var(--border)'}` }}>
                      {cp.status}
                    </span>
                  </div>
                  <div className="space-y-1 text-[11px]" style={{ color: 'var(--text-3)' }}>
                    <div className="flex justify-between">
                      <span>Alerts</span><span className="font-bold" style={{ color: '#fb923c' }}>{cp.alert_count}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Avg Confidence</span>
                      <span className="font-bold" style={{ color: cp.avg_confidence >= 70 ? '#22c55e' : '#fbbf24' }}>{cp.avg_confidence}%</span>
                    </div>
                    <div className="flex justify-between">
                      <span>First Seen</span><span>{cp.first_seen ? timeAgo(cp.first_seen) : '—'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Last Seen</span><span>{cp.last_seen ? timeAgo(cp.last_seen) : '—'}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="py-12 text-center text-sm" style={{ color: 'var(--text-3)' }}>
              {loadingTab ? 'Loading…' : 'No campaigns detected for this actor in your environment.'}
            </div>
          )}

          {sevBreakdown.length > 0 && (
            <div className="g-card p-4">
              <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Alert Severity Distribution</p>
              <div className="space-y-2">
                {sevBreakdown.map(s => {
                  const max = Math.max(...sevBreakdown.map(x => x.count), 1);
                  return (
                    <div key={s.severity} className="flex items-center gap-2">
                      <span className="w-20 shrink-0">{sevBadge(s.severity)}</span>
                      <MiniBar value={s.count} max={max} color={SEV_COLOR[s.severity] ?? 'var(--text-3)'} />
                      <span className="text-[11px] font-bold tabular-nums w-8 text-right" style={{ color: SEV_COLOR[s.severity] ?? 'var(--text-3)' }}>{s.count}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Malware ── */}
      {tab === 'malware' && selected && (
        <div className="space-y-4">
          {malware.length > 0 ? (
            <>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {malware.map(m => {
                  const color = MALWARE_COLOR[m.category] ?? 'var(--text-3)';
                  return (
                    <div key={m.technique} className="g-card p-4">
                      <div className="flex items-start gap-3 mb-3">
                        <div className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0"
                          style={{ background: `color-mix(in srgb, ${color} 15%, transparent)` }}>
                          <Lock className="w-3.5 h-3.5" style={{ color }} />
                        </div>
                        <div>
                          <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{m.malware_type}</p>
                          <p className="font-mono text-[10px]" style={{ color: '#fbbf24' }}>{m.technique}</p>
                        </div>
                      </div>
                      <div className="space-y-1 text-[11px]">
                        <div className="flex items-center justify-between">
                          <span style={{ color: 'var(--text-3)' }}>Category</span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded capitalize"
                            style={{ background: `color-mix(in srgb, ${color} 12%, transparent)`, color }}>
                            {m.category.replace('_', ' ')}
                          </span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span style={{ color: 'var(--text-3)' }}>Detections</span>
                          <span className="font-bold" style={{ color: m.alert_count > 0 ? 'var(--red)' : 'var(--text-3)' }}>{m.alert_count}</span>
                        </div>
                        {m.last_seen && (
                          <div className="flex items-center justify-between">
                            <span style={{ color: 'var(--text-3)' }}>Last Seen</span>
                            <span style={{ color: 'var(--text-2)' }}>{timeAgo(m.last_seen)}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Kill chain visualization */}
              <div className="g-card p-4">
                <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Kill Chain Coverage</p>
                <KillChainView techniques={selected.mitre_techniques ?? []} />
              </div>
            </>
          ) : (
            <div className="py-16 text-center">
              {loadingTab ? (
                <p className="text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</p>
              ) : (
                <p className="text-sm" style={{ color: 'var(--text-3)' }}>No MITRE technique data for this actor.</p>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Infrastructure ── */}
      {tab === 'infrastructure' && selected && (
        <div className="space-y-4">
          <p className="text-xs" style={{ color: 'var(--text-3)' }}>
            IOCs attributed to <span className="font-semibold" style={{ color: 'var(--text-1)' }}>{selected.name}</span> by name/alias match in descriptions.
          </p>

          {/* Type group cards */}
          {Object.keys(grouped).length > 0 && (
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
              {Object.entries(grouped).map(([type, items]) => (
                <div key={type} className="g-card p-3 text-center">
                  <p className="text-[10px] uppercase tracking-wider mb-1 font-mono" style={{ color: 'var(--accent)' }}>{type}</p>
                  <p className="text-xl font-bold" style={{ color: 'var(--text-1)' }}>{items.length}</p>
                </div>
              ))}
            </div>
          )}

          {infra.length > 0 ? (
            <div className="g-card overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
                    {['Indicator','Type','Severity','Hits','Last Seen'].map(h => (
                      <th key={h} className="px-3 py-2.5 text-left font-semibold" style={{ color: 'var(--text-3)' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {infra.map(i => (
                    <tr key={i.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td className="px-3 py-2 font-mono max-w-[200px] truncate">
                        <span style={{ color: 'var(--text-1)' }}>{i.indicator}</span>
                        <CopyBtn text={i.indicator} />
                      </td>
                      <td className="px-3 py-2">
                        <span className="text-[10px] px-1.5 py-0.5 rounded uppercase"
                          style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                          {i.type}
                        </span>
                      </td>
                      <td className="px-3 py-2">{sevBadge(i.severity)}</td>
                      <td className="px-3 py-2 font-bold tabular-nums" style={{ color: i.hit_count > 0 ? 'var(--red)' : 'var(--text-3)' }}>{i.hit_count}</td>
                      <td className="px-3 py-2" style={{ color: 'var(--text-3)' }}>{i.last_seen ? timeAgo(i.last_seen) : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="py-12 text-center">
              {loadingTab
                ? <p className="text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</p>
                : <p className="text-sm" style={{ color: 'var(--text-3)' }}>No infrastructure IOCs found. Add IOCs with this actor's name in the description.</p>
              }
            </div>
          )}
        </div>
      )}

      {/* ── MITRE ── */}
      {tab === 'mitre' && selected && (
        <div className="space-y-4">
          {mitre.length > 0 ? (
            <>
              {/* Tactic coverage pills */}
              {tacticSummary.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {tacticSummary.map(t => (
                    <span key={t.tactic} className="text-[10px] px-2 py-0.5 rounded"
                      style={{ background: 'rgba(248,81,73,0.12)', color: 'var(--red)', border: '1px solid rgba(248,81,73,0.3)' }}>
                      {t.tactic} ({t.covered})
                    </span>
                  ))}
                </div>
              )}

              <div className="g-card overflow-hidden">
                <table className="w-full text-xs">
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
                      {['Technique','Tactic','Sigma Rules','Alerts','Coverage'].map(h => (
                        <th key={h} className="px-3 py-2.5 text-left font-semibold" style={{ color: 'var(--text-3)' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {mitre.map(e => (
                      <tr key={e.technique} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td className="px-3 py-2.5 font-mono font-bold" style={{ color: '#fbbf24' }}>{e.technique}</td>
                        <td className="px-3 py-2.5" style={{ color: 'var(--text-2)' }}>{e.tactic}</td>
                        <td className="px-3 py-2.5">
                          <span style={{ color: 'var(--accent)' }}>{e.sigma_enabled}</span>
                          <span style={{ color: 'var(--text-3)' }}> / {e.sigma_total}</span>
                        </td>
                        <td className="px-3 py-2.5 font-bold tabular-nums" style={{ color: e.alert_count > 0 ? 'var(--red)' : 'var(--text-3)' }}>{e.alert_count}</td>
                        <td className="px-3 py-2.5">
                          {e.sigma_enabled > 0
                            ? <span className="flex items-center gap-1 text-[10px]" style={{ color: 'var(--green)' }}><Check className="w-3 h-3" /> Covered</span>
                            : <span className="text-[10px]" style={{ color: 'var(--red)' }}>Gap</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="g-card p-4">
                <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Kill Chain Visualization</p>
                <KillChainView techniques={selected.mitre_techniques ?? []} />
              </div>
            </>
          ) : (
            <div className="py-12 text-center text-sm" style={{ color: 'var(--text-3)' }}>
              {loadingTab ? 'Loading…' : 'No MITRE techniques mapped for this actor.'}
            </div>
          )}
        </div>
      )}

      {/* ── IOC Library ── */}
      {tab === 'iocs' && selected && (
        <div className="space-y-4">
          <p className="text-xs" style={{ color: 'var(--text-3)' }}>
            {iocs.length} IOCs associated with <span className="font-semibold" style={{ color: 'var(--text-1)' }}>{selected.name}</span>
          </p>
          {iocs.length > 0 ? (
            <div className="g-card overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
                    {['Indicator','Type','Severity','Hits','Last Seen','Description'].map(h => (
                      <th key={h} className="px-3 py-2.5 text-left font-semibold" style={{ color: 'var(--text-3)' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {iocs.map(ioc => (
                    <tr key={ioc.id} style={{ borderBottom: '1px solid var(--border)', opacity: ioc.enabled ? 1 : 0.4 }}>
                      <td className="px-3 py-2 font-mono max-w-[160px] truncate" style={{ color: 'var(--text-1)' }}>
                        <span className="flex items-center gap-1">{ioc.indicator}<CopyBtn text={ioc.indicator} /></span>
                      </td>
                      <td className="px-3 py-2">
                        <span className="text-[10px] uppercase px-1.5 py-0.5 rounded"
                          style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                          {ioc.type}
                        </span>
                      </td>
                      <td className="px-3 py-2">{sevBadge(ioc.severity)}</td>
                      <td className="px-3 py-2 font-bold tabular-nums" style={{ color: ioc.hit_count > 0 ? 'var(--red)' : 'var(--text-3)' }}>{ioc.hit_count}</td>
                      <td className="px-3 py-2 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>{ioc.last_seen ? timeAgo(ioc.last_seen) : '—'}</td>
                      <td className="px-3 py-2 max-w-xs truncate" style={{ color: 'var(--text-3)' }}>{ioc.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="py-12 text-center text-sm" style={{ color: 'var(--text-3)' }}>
              {loadingTab ? 'Loading…' : `No IOCs found for ${selected.name}. Add IOCs with this actor's name in the description.`}
            </div>
          )}
        </div>
      )}

      {/* ── Timeline ── */}
      {tab === 'timeline' && selected && (
        <div className="space-y-4">
          {timelineMonthly.length > 0 && (
            <div className="g-card p-4">
              <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Monthly Activity</p>
              <SparkBar data={timelineMonthly as Array<Record<string, unknown>>} keyName="count" />
            </div>
          )}
          {timelineEvents.length > 0 ? (
            <div className="g-card overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
                    {['When','Rule','Severity','Technique','Host','Confidence'].map(h => (
                      <th key={h} className="px-3 py-2.5 text-left font-semibold" style={{ color: 'var(--text-3)' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {timelineEvents.map(e => (
                    <tr key={e.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td className="px-3 py-2 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>{timeAgo(e.tagged_at)}</td>
                      <td className="px-3 py-2 max-w-[160px] truncate" style={{ color: 'var(--text-2)' }}>{e.rule_name}</td>
                      <td className="px-3 py-2">{sevBadge(e.severity)}</td>
                      <td className="px-3 py-2 font-mono" style={{ color: '#fbbf24' }}>{e.matched_technique || '—'}</td>
                      <td className="px-3 py-2" style={{ color: 'var(--text-3)' }}>{e.hostname || '—'}</td>
                      <td className="px-3 py-2" style={{ color: e.confidence >= 70 ? '#22c55e' : '#fbbf24' }}>{e.confidence}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="py-12 text-center text-sm" style={{ color: 'var(--text-3)' }}>
              {loadingTab ? 'Loading…' : `No alert history for ${selected.name} in your environment.`}
            </div>
          )}
        </div>
      )}

      {/* ── Exposure ── */}
      {tab === 'exposure' && selected && exposure && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <KPICard label="Total Alerts"    value={exposure.alert_count}        color="var(--red)"    icon={AlertTriangle} />
            <KPICard label="Alerts (30d)"    value={exposure.alert_count_30d}    color="#fb923c"       icon={Clock} />
            <KPICard label="Matched IOCs"    value={exposure.ioc_count}          color="var(--accent)" icon={Shield} />
            <KPICard label="Incidents"       value={exposure.incident_count}     color="#a855f7"       icon={Zap} />
          </div>

          {/* Exposure score */}
          <div className="g-card p-4">
            <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-1)' }}>Exposure Score</p>
            <RiskMeter score={exposure.exposure_score} />
            <p className="text-[11px] mt-2" style={{ color: 'var(--text-3)' }}>
              {exposure.exposure_score >= 70
                ? `High exposure — ${exposure.alert_count_30d} recent alerts, ${exposure.matching_tech_count} techniques detected in your environment.`
                : exposure.exposure_score >= 30
                ? `Moderate exposure — some activity detected. Monitor closely.`
                : 'Low exposure — minimal activity from this actor in your environment.'}
            </p>
            {exposure.matching_tech_count > 0 && (
              <p className="text-[11px] mt-1" style={{ color: '#fbbf24' }}>
                You currently have {exposure.matching_assets.length} asset{exposure.matching_assets.length !== 1 ? 's' : ''} exhibiting behaviors associated with this actor's techniques.
              </p>
            )}
          </div>

          {exposure.matching_assets.length > 0 && (
            <div className="g-card p-4">
              <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Matching Assets</p>
              <div className="space-y-2">
                {exposure.matching_assets.map((a, i) => (
                  <div key={i} className="flex items-center gap-3 text-xs">
                    <div className="w-2 h-2 rounded-full shrink-0" style={{ background: 'var(--red)' }} />
                    <span className="font-mono flex-1" style={{ color: 'var(--text-1)' }}>{a.hostname}</span>
                    <span style={{ color: 'var(--red)' }}>{a.alert_count} alerts</span>
                    <span style={{ color: 'var(--text-3)' }}>{timeAgo(a.last_seen)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {exposure.recent_alerts.length > 0 && (
            <div className="g-card overflow-hidden">
              <p className="text-xs font-semibold px-4 pt-3 pb-2" style={{ color: 'var(--text-1)' }}>Recent Matching Alerts</p>
              <table className="w-full text-xs">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
                    {['Rule','Severity','Host','Technique','Confidence','When'].map(h => (
                      <th key={h} className="px-3 py-2 text-left font-semibold" style={{ color: 'var(--text-3)' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {exposure.recent_alerts.map(a => (
                    <tr key={a.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td className="px-3 py-2 max-w-[160px] truncate" style={{ color: 'var(--text-2)' }}>{a.rule_name}</td>
                      <td className="px-3 py-2">{sevBadge(a.severity)}</td>
                      <td className="px-3 py-2" style={{ color: 'var(--text-3)' }}>{a.hostname || '—'}</td>
                      <td className="px-3 py-2 font-mono" style={{ color: '#fbbf24' }}>{a.matched_technique || '—'}</td>
                      <td className="px-3 py-2" style={{ color: a.confidence >= 70 ? '#22c55e' : '#fbbf24' }}>{a.confidence}%</td>
                      <td className="px-3 py-2 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>{timeAgo(a.tagged_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
      {tab === 'exposure' && selected && !exposure && (
        <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
      )}

      {/* ── Detection Coverage ── */}
      {tab === 'detection' && selected && (
        <div className="space-y-4">
          {detection ? (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <KPICard label="Coverage" value={`${detection.coverage_pct}%`} color={detection.coverage_pct >= 70 ? 'var(--green)' : detection.coverage_pct >= 40 ? '#fbbf24' : 'var(--red)'} icon={Shield} />
                <KPICard label="Sigma Rules"   value={detection.sigma_total}       color="var(--accent)"  icon={FileCodeIcon} />
                <KPICard label="YARA Rules"    value={detection.yara_total}        color="#fb923c"        icon={Lock} />
                <KPICard label="Uncovered"     value={detection.total_techniques - detection.covered_techniques} color="var(--red)" icon={AlertCircle} />
              </div>

              <div className="g-card p-4 mb-2">
                <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-1)' }}>Coverage Progress</p>
                <div className="flex items-center gap-3">
                  <div className="flex-1 h-3 rounded-full overflow-hidden" style={{ background: 'var(--glass-bg-2)' }}>
                    <div className="h-full rounded-full" style={{ width: `${detection.coverage_pct}%`, background: detection.coverage_pct >= 70 ? 'var(--green)' : detection.coverage_pct >= 40 ? '#fbbf24' : 'var(--red)' }} />
                  </div>
                  <span className="text-sm font-bold shrink-0" style={{ color: detection.coverage_pct >= 70 ? 'var(--green)' : detection.coverage_pct >= 40 ? '#fbbf24' : 'var(--red)' }}>
                    {detection.covered_techniques}/{detection.total_techniques} techniques
                  </span>
                </div>
              </div>

              <div className="g-card overflow-hidden">
                <table className="w-full text-xs">
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
                      {['Technique','Sigma (enabled/total)','Correlation Rules','Status'].map(h => (
                        <th key={h} className="px-3 py-2.5 text-left font-semibold" style={{ color: 'var(--text-3)' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {detection.techniques.map(t => (
                      <tr key={t.technique} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td className="px-3 py-2.5 font-mono font-bold" style={{ color: '#fbbf24' }}>{t.technique}</td>
                        <td className="px-3 py-2.5">
                          <span style={{ color: 'var(--accent)' }}>{t.sigma_enabled}</span>
                          <span style={{ color: 'var(--text-3)' }}> / {t.sigma_total}</span>
                        </td>
                        <td className="px-3 py-2.5" style={{ color: 'var(--text-2)' }}>{t.correlation_rules}</td>
                        <td className="px-3 py-2.5">
                          {t.covered
                            ? <span className="flex items-center gap-1 text-[10px]" style={{ color: 'var(--green)' }}><Check className="w-3 h-3" /> Covered</span>
                            : <span className="flex items-center gap-1 text-[10px]" style={{ color: 'var(--red)' }}><X className="w-3 h-3" /> Coverage Gap</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          )}
        </div>
      )}

      {/* ── Threat Hunt ── */}
      {tab === 'hunt' && selected && (
        <div className="space-y-4">
          <div className="g-card p-4">
            <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>
              Threat Hunt — {selected.name}
            </p>
            <p className="text-[11px] mb-4" style={{ color: 'var(--text-3)' }}>
              Generate hunt parameters for this actor's IOCs, TTPs, and common behaviors.
            </p>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 mb-4">
              {[
                { id: 'iocs',    label: 'Hunt IOCs',        icon: Shield },
                { id: 'ttps',    label: 'Hunt TTPs',        icon: Layers },
                { id: 'logs',    label: 'Search Logs',      icon: Database },
                { id: 'dns',     label: 'Search DNS',       icon: Globe },
                { id: 'network', label: 'Search Firewall',  icon: Network },
                { id: 'cloud',   label: 'Search Cloud',     icon: Activity },
              ].map(h => (
                <button key={h.id} onClick={() => setHuntType(h.id)}
                  className={`p-3 rounded-xl text-left flex items-center gap-2 text-xs transition-colors ${huntType === h.id ? 'g-btn g-btn-primary' : 'g-card'}`}>
                  <h.icon className="w-3.5 h-3.5 shrink-0" />
                  {h.label}
                </button>
              ))}
            </div>

            <button onClick={runHunt} disabled={hunting} className="g-btn g-btn-primary text-xs">
              <Play className={`w-3.5 h-3.5 ${hunting ? 'animate-spin' : ''}`} />
              {hunting ? 'Generating…' : 'Generate Hunt Parameters'}
            </button>
          </div>

          {huntResult && (
            <div className="g-card p-4 space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Hunt Parameters — {huntResult.actor_name as string}</p>
                <CopyBtn text={JSON.stringify(huntResult, null, 2)} />
              </div>
              {!!huntResult.description && (
                <p className="text-xs" style={{ color: 'var(--text-2)' }}>{String(huntResult.description)}</p>
              )}
              {Array.isArray(huntResult.iocs) && (huntResult.iocs as string[]).length > 0 && (
                <div>
                  <p className="text-[10px] uppercase tracking-wider mb-1.5 font-semibold" style={{ color: 'var(--text-3)' }}>IOCs to Hunt ({(huntResult.iocs as string[]).length})</p>
                  <div className="flex flex-wrap gap-1">
                    {(huntResult.iocs as string[]).map((ioc: string) => (
                      <span key={ioc} className="font-mono text-[10px] px-2 py-0.5 rounded flex items-center gap-1"
                        style={{ background: 'var(--glass-bg-2)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>
                        {ioc}<CopyBtn text={ioc} />
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {Array.isArray(huntResult.techniques) && (huntResult.techniques as string[]).length > 0 && (
                <div>
                  <p className="text-[10px] uppercase tracking-wider mb-1.5 font-semibold" style={{ color: 'var(--text-3)' }}>Techniques ({(huntResult.techniques as string[]).length})</p>
                  <div className="flex flex-wrap gap-1">
                    {(huntResult.techniques as string[]).map((t: string) => (
                      <span key={t} className="font-mono text-[10px] px-2 py-0.5 rounded"
                        style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {!!huntResult.sigma_hunt && (
                <div>
                  <p className="text-[10px] uppercase tracking-wider mb-1 font-semibold" style={{ color: 'var(--text-3)' }}>Sigma Hunt Query</p>
                  <code className="text-[11px] px-3 py-2 rounded block"
                    style={{ background: 'var(--bg-0)', color: 'var(--accent)', border: '1px solid var(--border)' }}>
                    {String(huntResult.sigma_hunt)}
                  </code>
                </div>
              )}
            </div>
          )}

          {/* Response Actions section */}
          <div className="g-card p-4">
            <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Response Actions</p>
            <div className="space-y-3">
              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Note (optional)</label>
                <input value={responseNote} onChange={e => setResponseNote(e.target.value)}
                  placeholder="Analyst note for the action log…" className="g-input w-full text-xs" />
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                {[
                  { action: 'block_iocs',    label: 'Block IOCs',         icon: Shield, desc: 'Add actor IOCs to block list' },
                  { action: 'create_sigma',  label: 'Create Sigma Rule',  icon: FileCodeIcon, desc: 'Auto-generate Sigma rule for primary technique' },
                  { action: 'notify',        label: 'Notify Analysts',    icon: AlertTriangle, desc: 'Send analyst notification' },
                ].map(act => (
                  <button key={act.action} onClick={() => runResponse(act.action)}
                    disabled={responding}
                    className="g-card p-3 text-left hover:opacity-80 transition-opacity">
                    <act.icon className="w-4 h-4 mb-1.5" style={{ color: 'var(--accent)' }} />
                    <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{act.label}</p>
                    <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{act.desc}</p>
                  </button>
                ))}
              </div>
              {responseMsg && (
                <div className="text-xs px-3 py-2 rounded-lg"
                  style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                  {responseMsg}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Relationships ── */}
      {tab === 'relationships' && selected && (
        <div className="space-y-4">
          <p className="text-xs" style={{ color: 'var(--text-3)' }}>
            Relationship graph for <span className="font-semibold" style={{ color: 'var(--text-1)' }}>{selected.name}</span>:
            actor → campaigns → IOCs → alerts → incidents.
          </p>
          {loadingTab
            ? <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
            : <RelGraph nodes={relNodes} edges={relEdges} />}
        </div>
      )}

      {/* ── Analytics ── */}
      {tab === 'analytics' && (
        <div className="space-y-4">
          {analytics ? (
            <>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Most Active Actors (30d)</p>
                  <div className="space-y-2">
                    {analytics.top_actors.map(a => {
                      const color = MOTIV_COLOR[a.motivation] ?? 'var(--text-3)';
                      return (
                        <div key={a.id} className="flex items-center gap-2">
                          <span className="text-xs flex-1 truncate" style={{ color: 'var(--text-2)' }}>{a.name}</span>
                          <span className="text-[10px] capitalize" style={{ color }}>{a.motivation}</span>
                          <MiniBar value={a.alert_count} max={maxActor} color={color} />
                          <span className="text-[11px] font-bold tabular-nums w-6 shrink-0 text-right" style={{ color }}>{a.alert_count}</span>
                        </div>
                      );
                    })}
                    {analytics.top_actors.length === 0 && <p className="text-xs" style={{ color: 'var(--text-3)' }}>No actor activity</p>}
                  </div>
                </div>

                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Top Matched Techniques</p>
                  <div className="space-y-2">
                    {analytics.top_techniques.map(t => (
                      <div key={t.technique} className="flex items-center gap-2">
                        <span className="font-mono text-[10px] w-16 shrink-0" style={{ color: '#fbbf24' }}>{t.technique}</span>
                        <MiniBar value={t.count} max={maxTech} color="#fbbf24" />
                        <span className="text-[11px] font-bold tabular-nums w-5 shrink-0 text-right" style={{ color: '#fbbf24' }}>{t.count}</span>
                      </div>
                    ))}
                    {analytics.top_techniques.length === 0 && <p className="text-xs" style={{ color: 'var(--text-3)' }}>No technique data</p>}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Sophistication Breakdown</p>
                  <div className="space-y-2">
                    {analytics.sophistication_breakdown.map(s => {
                      const max = Math.max(...analytics.sophistication_breakdown.map(x => x.count), 1);
                      const color = SOPH_COLOR[s.sophistication] ?? 'var(--text-3)';
                      return (
                        <div key={s.sophistication} className="flex items-center gap-2">
                          <span className="text-xs w-24 shrink-0 capitalize" style={{ color }}>{s.sophistication}</span>
                          <MiniBar value={s.count} max={max} color={color} />
                          <span className="text-[11px] font-bold tabular-nums w-5 shrink-0 text-right" style={{ color }}>{s.count}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>8-week Activity Trend</p>
                  <SparkBar data={analytics.activity_over_time as Array<Record<string, unknown>>} keyName="count" />
                </div>
              </div>
            </>
          ) : (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          )}
        </div>
      )}

      {/* ── AI Intel ── */}
      {tab === 'ai' && selected && <AIPanel actor={selected} />}

      {/* ── Modals ── */}
      {showCreate && (
        <ActorFormModal title="Add Threat Actor" initial={{}} onClose={() => setShowCreate(false)} onSave={createActor} />
      )}
      {editActor && (
        <ActorFormModal
          title={`Edit — ${editActor.name}`}
          initial={{
            name: editActor.name,
            origin_country: editActor.origin_country,
            motivation: editActor.motivation,
            sophistication: editActor.sophistication,
            description: editActor.description,
            aliases: (editActor.aliases ?? []).join(', '),
            targeted_sectors: (editActor.targeted_sectors ?? []).join(', '),
            mitre_techniques: (editActor.mitre_techniques ?? []).join(', '),
          }}
          onClose={() => setEditActor(null)}
          onSave={updateActor}
        />
      )}
    </RootLayout>
  );
}

// Small shim to avoid importing FileCode from lucide inside sevBadge scope
function FileCodeIcon({ className, style }: { className?: string; style?: React.CSSProperties }) {
  return (
    <svg className={className} style={style} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
      <polyline points="14 2 14 8 20 8" />
      <path d="m10 13-2 2 2 2" />
      <path d="m14 17 2-2-2-2" />
    </svg>
  );
}
