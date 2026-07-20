'use client';

import {
  useState, useEffect, useCallback, useMemo, useRef,
} from 'react';
import { createPortal } from 'react-dom';
import { RootLayout } from '@/components/layout/RootLayout';
import {
  iocsAPI, sigmaAPI, threatFeedsAPI, threatActorsAPI, intelAPI,
} from '@/lib/api';
import { IOC, SigmaRule, ThreatFeed } from '@/types';
import { sevClass, timeAgo } from '@/lib/utils';
import { Activity, AlertTriangle, BarChart3, Brain, Check, CheckCircle2, ChevronLeft, ChevronRight, Clock, Copy, Database, Edit2, Eye, FileCode, Layers, Network, Plus, RefreshCw, Rss, Search, Shield, Target, ToggleLeft, ToggleRight, Trash2, Upload, Users, X, Lock } from '@/lib/icon-stubs';

// ── Types ─────────────────────────────────────────────────────────────────────

type ViewTab =
  | 'overview' | 'iocs' | 'feeds' | 'actors' | 'campaigns'
  | 'relationships' | 'mitre' | 'timeline' | 'watchlist'
  | 'search' | 'analytics' | 'ai';

interface Overview {
  total_iocs: number;
  enabled_iocs: number;
  new_today: number;
  ioc_matches: number;
  recent_matches: number;
  high_confidence: number;
  total_actors: number;
  total_feeds: number;
  enabled_feeds: number;
  healthy_feeds: number;
  sigma_rules: number;
  yara_rules: number;
  trend: Array<{ day: string; count: number }>;
  type_breakdown: Array<{ type: string; count: number }>;
}

interface Analytics {
  top_iocs: Array<{
    id: number; indicator: string; type: string; severity: string;
    hit_count: number; last_seen: string | null; description: string;
  }>;
  top_actors: Array<{
    id: number; name: string; motivation: string; sophistication: string; alert_count: number;
  }>;
  ioc_growth: Array<{ week: string; count: number }>;
  feed_reliability: Array<{ name: string; enabled: boolean; last_sync: string | null; feed_type: string; ioc_count: number; healthy: boolean }>;
  severity_distribution: Array<{ severity: string; count: number }>;
}

interface Campaign {
  technique: string; name: string; cluster_count: number;
  total_alerts: number; latest: string; earliest: string; status: string;
}

interface MITREData {
  techniques: Array<{ technique: string; total: number; enabled: number; source: string }>;
  total: number;
  covered_tactics: number;
}

interface RelNode { id: string; label: string; type: string; count: number; }
interface RelEdge { source: string; target: string; label: string; }

interface WatchItem {
  id: number; indicator: string; type: string; severity: string;
  hit_count: number; last_seen: string | null; description: string; added_at: string;
}

interface TimelineIOC {
  id: number; indicator: string; type: string; severity: string;
  hit_count: number; created_at: string; last_seen: string | null; expires_at: string | null;
}

interface SearchResult {
  query: string;
  iocs: Array<{ id: number; indicator: string; type: string; severity: string; hit_count: number; description: string }>;
  actors: Array<{ id: number; name: string; motivation: string; sophistication: string; description: string }>;
  sigma: Array<{ id: number; title: string; mitre_technique: string; severity: string }>;
  alerts: Array<{ id: number; rule_name: string; severity: string; time: string; source_ip: string }>;
  total: number;
}

interface AIResult { raw: string; parsed: Record<string, unknown> | null; }

// ── Constants ─────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)', high: '#fb923c', medium: '#fbbf24',
  low: 'var(--accent)', informational: 'var(--text-3)',
};

const IOC_TYPES_EXT = [
  'ip', 'domain', 'url', 'fqdn', 'asn',
  'sha256', 'sha1', 'md5', 'filename', 'filetype',
  'email', 'sender', 'subject', 'attachment_hash',
  'ja3', 'ja3s', 'certificate', 'serial',
  'iam_user', 'access_key', 'bucket', 'resource_id',
];
const IOC_TYPES_SIMPLE = ['ip', 'sha256', 'md5', 'domain', 'url'];
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const FEED_TYPES = ['flatfile', 'otx', 'misp', 'taxii'] as const;
const PAGE_SIZE = 50;

const emptyIOC = { indicator: '', type: 'ip', severity: 'high', description: '', enabled: true, expires_at: '' };
const emptyFeed = { name: '', source: '', feed_type: 'flatfile', enabled: true, config: { api_key: '', collection_id: '', username: '', password: '' } };
const emptySigma = { title: '', severity: 'high', mitre_tactic: '', mitre_technique: '', mitre_name: '', keywords: '', enabled: true };

const TABS: Array<{ id: ViewTab; label: string; icon: React.ElementType }> = [
  { id: 'overview',       label: 'Overview',      icon: BarChart3 },
  { id: 'iocs',           label: 'IOCs',           icon: Shield },
  { id: 'feeds',          label: 'Feeds',          icon: Rss },
  { id: 'actors',         label: 'Threat Actors',  icon: Users },
  { id: 'campaigns',      label: 'Campaigns',      icon: Target },
  { id: 'relationships',  label: 'Relationships',  icon: Network },
  { id: 'mitre',          label: 'MITRE',          icon: Layers },
  { id: 'timeline',       label: 'Timeline',       icon: Clock },
  { id: 'watchlist',      label: 'Watchlist',      icon: Eye },
  { id: 'search',         label: 'Hunt/Search',    icon: Search },
  { id: 'analytics',      label: 'Analytics',      icon: Activity },
  { id: 'ai',             label: 'AI Intel',       icon: Brain },
];

const FEED_PROVIDERS = [
  { name: 'STIX/TAXII',    type: 'taxii',    desc: 'OASIS standard structured threat intel' },
  { name: 'MISP',          type: 'misp',     desc: 'Open Source Threat Sharing Platform' },
  { name: 'AlienVault OTX', type: 'otx',    desc: 'Open Threat Exchange by AT&T' },
  { name: 'AbuseIPDB',     type: 'flatfile', desc: 'Collaborative IP abuse database' },
  { name: 'URLHaus',       type: 'flatfile', desc: 'Malware distribution site database' },
  { name: 'PhishTank',     type: 'flatfile', desc: 'Crowdsourced phishing URL feed' },
  { name: 'MalwareBazaar', type: 'flatfile', desc: 'Hash-based malware sample database' },
];

const ACTOR_MOTIVATIONS = [
  'espionage', 'financial', 'hacktivism', 'destruction', 'unknown',
];

// ── Helpers ───────────────────────────────────────────────────────────────────

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
      <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
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

function SparkBar({ data, label }: { data: Array<{ day?: string; week?: string; count: number }>; label?: string }) {
  const max = Math.max(...data.map(d => d.count), 1);
  if (!data.length) return <div className="h-10 text-xs flex items-center" style={{ color: 'var(--text-3)' }}>No data</div>;
  return (
    <div>
      {label && <p className="text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>{label}</p>}
      <div className="flex items-end gap-0.5 h-10">
        {data.map((d, i) => (
          <div key={i} className="flex-1 rounded-sm min-w-[4px]"
            title={`${d.day || d.week}: ${d.count}`}
            style={{ height: `${Math.max(4, (d.count / max) * 40)}px`, background: 'var(--accent)', opacity: 0.8 }} />
        ))}
      </div>
    </div>
  );
}

// ── Feed status badge ──────────────────────────────────────────────────────────

function FeedHealthDot({ healthy }: { healthy?: boolean }) {
  return (
    <span className="flex items-center gap-1 text-[10px]" style={{ color: healthy ? 'var(--green)' : 'var(--red)' }}>
      <span className="w-2 h-2 rounded-full" style={{ background: healthy ? 'var(--green)' : 'var(--red)' }} />
      {healthy ? 'Healthy' : 'Stale'}
    </span>
  );
}

// ── Relationship Graph ─────────────────────────────────────────────────────────

function RelationshipGraph({ nodes, edges }: { nodes: RelNode[]; edges: RelEdge[] }) {
  const NODE_COLORS: Record<string, string> = {
    actor: 'var(--red)', campaign: '#fb923c', ioc: 'var(--accent)',
    alert: '#fbbf24', malware: '#a78bfa',
  };

  const layout = useMemo(() => {
    const actors   = nodes.filter(n => n.type === 'actor');
    const campaigns = nodes.filter(n => n.type === 'campaign');
    const iocNodes = nodes.filter(n => n.type === 'ioc');
    const others   = nodes.filter(n => !['actor','campaign','ioc'].includes(n.type));
    const W = 720, H = 380;
    const pos: Record<string, { x: number; y: number }> = {};
    const col = (arr: RelNode[], x: number) => arr.forEach((n, i) => {
      pos[n.id] = { x, y: 40 + (i * Math.min(70, (H - 80) / Math.max(arr.length, 1))) };
    });
    col(actors, 80);
    col(campaigns, 260);
    col(iocNodes, 460);
    col(others, 640);
    return pos;
  }, [nodes]);

  if (!nodes.length) return (
    <div className="py-12 text-center text-xs" style={{ color: 'var(--text-3)' }}>
      No relationship data. Add threat actors and IOCs to see the graph.
    </div>
  );

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-4 text-[10px] flex-wrap">
        {Object.entries(NODE_COLORS).map(([t, c]) => (
          <span key={t} className="flex items-center gap-1 capitalize">
            <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: c }} />{t}
          </span>
        ))}
      </div>
      <svg width="100%" viewBox="0 0 720 380" className="rounded-lg"
        style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
        {edges.map((e, i) => {
          const s = layout[e.source];
          const t = layout[e.target];
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
              <text y={r + 12} textAnchor="middle" fontSize={9} fill="var(--text-2)" className="select-none">
                {n.label.slice(0, 16)}{n.label.length > 16 ? '…' : ''}
              </text>
            </g>
          );
        })}
        {[{ x: 80, l: 'Threat Actors' }, { x: 260, l: 'Campaigns' }, { x: 460, l: 'IOCs' }, { x: 640, l: 'Alerts' }].map(s => (
          <text key={s.l} x={s.x} y={15} textAnchor="middle" fontSize={9} fill="var(--text-3)">{s.l}</text>
        ))}
      </svg>
    </div>
  );
}

// ── AI Intel Panel ─────────────────────────────────────────────────────────────

function AIIntelPanel() {
  const [action, setAction]     = useState('summarize_ioc');
  const [indicator, setIndicator] = useState('');
  const [context, setContext]   = useState('');
  const [loading, setLoading]   = useState(false);
  const [result, setResult]     = useState<AIResult | null>(null);
  const [error, setError]       = useState<string | null>(null);

  const ACTIONS = [
    { id: 'summarize_ioc',   label: 'IOC Summary',     icon: Shield,  desc: 'Risk assessment & associations for an indicator' },
    { id: 'actor_profile',   label: 'Actor Profile',   icon: Users,   desc: 'Intelligence profile for a threat actor' },
    { id: 'campaign_brief',  label: 'Campaign Brief',  icon: Target,  desc: 'Intelligence brief for a campaign or activity' },
    { id: 'threat_hunt',     label: 'Hunt Guidance',   icon: Search,  desc: 'Threat hunting queries and hypotheses' },
  ];

  const run = async () => {
    setLoading(true); setError(null); setResult(null);
    try {
      const res = await intelAPI.ai(action, indicator || undefined, context);
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
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>
              {action === 'summarize_ioc' || action === 'threat_hunt' ? 'Indicator (IP, domain, hash, etc.)' : 'Name or Keyword'}
            </label>
            <input value={indicator} onChange={e => setIndicator(e.target.value)}
              placeholder={action === 'actor_profile' ? 'e.g. APT28, Lazarus Group' : 'e.g. 185.220.101.1, evil.com, T1566'}
              className="g-input w-full text-xs" />
          </div>
          <div>
            <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Additional Context</label>
            <textarea value={context} onChange={e => setContext(e.target.value)}
              placeholder="Environment notes, related campaign, sector…"
              className="g-input w-full text-xs resize-none" rows={2} />
          </div>
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
              AI Result — {ACTIONS.find(a => a.id === action)?.label}
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

// ── IOC Search Panel ───────────────────────────────────────────────────────────

function SearchPanel() {
  const [query, setQuery]     = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult]   = useState<SearchResult | null>(null);

  const run = async () => {
    if (!query.trim()) return;
    setLoading(true);
    try {
      const res = await intelAPI.search(query);
      setResult(res.data as SearchResult);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="g-card p-4">
        <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Unified Threat Intelligence Search</p>
        <p className="text-[11px] mb-3" style={{ color: 'var(--text-3)' }}>
          Search across IOCs, threat actors, Sigma rules, and alerts simultaneously.
        </p>
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--text-3)' }} />
            <input value={query} onChange={e => setQuery(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && run()}
              placeholder="IP, domain, hash, CVE, actor name, technique ID…"
              className="g-input pl-8 w-full text-xs" />
          </div>
          <button onClick={run} disabled={loading || !query.trim()} className="g-btn g-btn-primary text-xs">
            <Search className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            {loading ? 'Searching…' : 'Search'}
          </button>
        </div>

        <div className="flex flex-wrap gap-2 mt-3">
          {['185.220.101.1', 'T1566', 'Lazarus', 'powershell -enc', 'ransomware'].map(hint => (
            <button key={hint} onClick={() => setQuery(hint)}
              className="px-2 py-0.5 rounded text-[10px]"
              style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)', border: '1px solid var(--border)' }}>
              {hint}
            </button>
          ))}
        </div>
      </div>

      {result && (
        <div className="space-y-3">
          <p className="text-xs" style={{ color: 'var(--text-3)' }}>
            Found {result.total} results for "<span style={{ color: 'var(--text-1)' }}>{result.query}</span>"
          </p>

          {result.iocs.length > 0 && (
            <div className="g-card overflow-hidden">
              <p className="text-[10px] uppercase tracking-wider font-semibold px-4 pt-3 pb-2" style={{ color: 'var(--text-3)' }}>
                IOCs ({result.iocs.length})
              </p>
              <table className="w-full text-xs">
                <tbody>
                  {result.iocs.map(ioc => (
                    <tr key={ioc.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td className="px-4 py-2.5">
                        <span className="font-mono font-medium" style={{ color: 'var(--text-1)' }}>{ioc.indicator}</span>
                      </td>
                      <td className="px-2 py-2.5">
                        <span className="text-[10px] px-1.5 py-0.5 rounded font-mono uppercase"
                          style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                          {ioc.type}
                        </span>
                      </td>
                      <td className="px-2 py-2.5">{sevBadge(ioc.severity)}</td>
                      <td className="px-2 py-2.5" style={{ color: ioc.hit_count > 0 ? 'var(--red)' : 'var(--text-3)' }}>
                        {ioc.hit_count} hits
                      </td>
                      <td className="px-2 py-2.5 max-w-xs truncate" style={{ color: 'var(--text-3)' }}>{ioc.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {result.actors.length > 0 && (
            <div className="g-card p-4">
              <p className="text-[10px] uppercase tracking-wider font-semibold mb-2" style={{ color: 'var(--text-3)' }}>Threat Actors ({result.actors.length})</p>
              <div className="space-y-2">
                {result.actors.map(a => (
                  <div key={a.id} className="flex items-center gap-3">
                    <Users className="w-4 h-4 shrink-0" style={{ color: 'var(--red)' }} />
                    <div className="flex-1">
                      <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{a.name}</p>
                      <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{a.motivation} · {a.sophistication}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.sigma.length > 0 && (
            <div className="g-card p-4">
              <p className="text-[10px] uppercase tracking-wider font-semibold mb-2" style={{ color: 'var(--text-3)' }}>Sigma Rules ({result.sigma.length})</p>
              <div className="space-y-1">
                {result.sigma.map(s => (
                  <div key={s.id} className="flex items-center gap-2 text-xs">
                    <FileCode className="w-3.5 h-3.5 shrink-0" style={{ color: 'var(--accent)' }} />
                    <span className="flex-1" style={{ color: 'var(--text-2)' }}>{s.title}</span>
                    {s.mitre_technique && <span className="font-mono text-[10px]" style={{ color: '#fbbf24' }}>{s.mitre_technique}</span>}
                    {sevBadge(s.severity)}
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.alerts.length > 0 && (
            <div className="g-card p-4">
              <p className="text-[10px] uppercase tracking-wider font-semibold mb-2" style={{ color: 'var(--text-3)' }}>Matching Alerts ({result.alerts.length})</p>
              <div className="space-y-1">
                {result.alerts.map(a => (
                  <div key={a.id} className="flex items-center gap-2 text-xs">
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0" style={{ color: SEV_COLOR[a.severity] ?? 'var(--text-3)' }} />
                    <span className="flex-1 truncate" style={{ color: 'var(--text-2)' }}>{a.rule_name}</span>
                    {a.source_ip && <span className="font-mono text-[10px]" style={{ color: 'var(--text-3)' }}>{a.source_ip}</span>}
                    {sevBadge(a.severity)}
                    <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(a.time)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.total === 0 && (
            <div className="g-card py-12 text-center">
              <p className="text-sm" style={{ color: 'var(--text-3)' }}>No results for "{result.query}"</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Threat Actors Panel ────────────────────────────────────────────────────────

interface ThreatActorData {
  id: number; name: string; aliases: string[]; origin_country: string;
  motivation: string; sophistication: string; description: string;
  targeted_sectors: string[]; mitre_techniques: string[];
  is_builtin: boolean; recent_alert_count: number;
}

function ActorsPanel() {
  const [actors, setActors]   = useState<ThreatActorData[]>([]);
  const [loading, setLoading] = useState(false);
  const [showAdd, setShowAdd] = useState(false);
  const [toast, setToast]     = useState<string | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [form, setForm] = useState({
    name: '', aliases: '', origin_country: '', motivation: 'espionage',
    sophistication: 'advanced', description: '', targeted_sectors: '', mitre_techniques: '',
  });
  const [saving, setSaving] = useState(false);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const load = async () => {
    setLoading(true);
    const r = await threatActorsAPI.getAll();
    setActors(r.data || []);
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const create = async () => {
    if (!form.name) return;
    setSaving(true);
    try {
      await threatActorsAPI.create({
        ...form,
        aliases: form.aliases.split(',').map(s => s.trim()).filter(Boolean),
        targeted_sectors: form.targeted_sectors.split(',').map(s => s.trim()).filter(Boolean),
        mitre_techniques: form.mitre_techniques.split(',').map(s => s.trim()).filter(Boolean),
      });
      await load();
      setShowAdd(false);
      notify('Threat actor added');
    } finally {
      setSaving(false);
    }
  };

  const remove = async (id: number) => {
    await threatActorsAPI.remove(id);
    setActors(prev => prev.filter(a => a.id !== id));
    notify('Actor removed');
  };

  const SOPs: Record<string, string> = {
    espionage: 'Nation-state or state-sponsored, long-dwell intelligence gathering',
    financial: 'Ransomware, banking trojans, BEC, crypto theft',
    hacktivism: 'DDoS, defacement, data leaks for political or ideological reasons',
    destruction: 'Wiper attacks, critical infrastructure disruption, sabotage',
    unknown: 'Motivation not yet attributed',
  };

  return (
    <div className="space-y-4">
      {toast && <div className="fixed bottom-5 right-5 z-50 g-card px-4 py-2.5 text-sm" style={{ color: 'var(--text-1)' }}>{toast}</div>}

      <div className="flex items-center justify-between">
        <p className="text-xs" style={{ color: 'var(--text-3)' }}>{actors.length} threat actors</p>
        <button onClick={() => setShowAdd(true)} className="g-btn g-btn-primary text-xs">
          <Plus className="w-3.5 h-3.5" /> Add Actor
        </button>
      </div>

      {loading ? (
        <div className="py-12 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
      ) : actors.length === 0 ? (
        <div className="g-card py-16 text-center">
          <Users className="mx-auto w-10 h-10 mb-3 opacity-20" style={{ color: 'var(--text-3)' }} />
          <p className="text-sm" style={{ color: 'var(--text-3)' }}>No threat actors yet. Add one to start tracking.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {actors.map(a => (
            <div key={a.id} className="g-card overflow-hidden">
              <div className="flex items-center gap-3 px-4 py-3 cursor-pointer"
                onClick={() => setExpanded(e => e === a.id ? null : a.id)}>
                <div className="w-7 h-7 rounded-full flex items-center justify-center text-[10px] font-bold shrink-0"
                  style={{ background: 'rgba(248,81,73,0.15)', color: 'var(--red)' }}>
                  {a.name.slice(0, 2).toUpperCase()}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{a.name}</span>
                    {a.is_builtin && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded" style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)', border: '1px solid var(--border)' }}>
                        built-in
                      </span>
                    )}
                    {a.origin_country && (
                      <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>🌍 {a.origin_country}</span>
                    )}
                    <span className="text-[10px] px-1.5 py-0.5 rounded capitalize"
                      style={{ background: 'rgba(248,81,73,0.12)', color: 'var(--red)', border: '1px solid rgba(248,81,73,0.3)' }}>
                      {a.motivation}
                    </span>
                    {a.recent_alert_count > 0 && (
                      <span className="text-[10px]" style={{ color: '#fbbf24' }}>{a.recent_alert_count} recent alerts</span>
                    )}
                  </div>
                  {a.description && (
                    <p className="text-[11px] truncate" style={{ color: 'var(--text-3)' }}>{a.description}</p>
                  )}
                </div>
                <button onClick={e => { e.stopPropagation(); remove(a.id); }}
                  className="p-1 hover:opacity-70" style={{ color: 'var(--text-3)' }}>
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>

              {expanded === a.id && (
                <div className="px-4 pb-4 pt-2 space-y-3" style={{ borderTop: '1px solid var(--border)' }}>
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div>
                      <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>Sophistication</p>
                      <p style={{ color: 'var(--text-1)' }}>{a.sophistication}</p>
                    </div>
                    <div>
                      <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>Motivation</p>
                      <p style={{ color: 'var(--text-1)' }}>{a.motivation} — {SOPs[a.motivation] ?? ''}</p>
                    </div>
                  </div>
                  {(a.aliases || []).length > 0 && (
                    <div>
                      <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>Aliases</p>
                      <div className="flex flex-wrap gap-1">
                        {a.aliases.map(alias => (
                          <span key={alias} className="text-[10px] px-2 py-0.5 rounded"
                            style={{ background: 'var(--glass-bg-2)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>
                            {alias}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {(a.targeted_sectors || []).length > 0 && (
                    <div>
                      <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>Target Sectors</p>
                      <div className="flex flex-wrap gap-1">
                        {a.targeted_sectors.map(s => (
                          <span key={s} className="text-[10px] px-2 py-0.5 rounded"
                            style={{ background: 'rgba(251,191,36,0.12)', color: '#fbbf24', border: '1px solid rgba(251,191,36,0.3)' }}>
                            {s}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {(a.mitre_techniques || []).length > 0 && (
                    <div>
                      <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>MITRE Techniques</p>
                      <div className="flex flex-wrap gap-1">
                        {a.mitre_techniques.map(t => (
                          <span key={t} className="font-mono text-[10px] px-1.5 py-0.5 rounded"
                            style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {showAdd && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setShowAdd(false)}>
          <div className="g-modal" style={{ maxWidth: 520 }}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Add Threat Actor</h2>
              <button onClick={() => setShowAdd(false)} style={{ color: 'var(--text-2)' }}><X className="w-4 h-4" /></button>
            </div>
            <div className="p-5 space-y-3 max-h-[60vh] overflow-y-auto">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Name *</label>
                  <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                    placeholder="e.g. APT28, Lazarus" className="g-input w-full text-xs" />
                </div>
                <div>
                  <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Aliases (comma-sep)</label>
                  <input value={form.aliases} onChange={e => setForm(f => ({ ...f, aliases: e.target.value }))}
                    placeholder="Fancy Bear, Sofacy" className="g-input w-full text-xs" />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Origin Country</label>
                  <input value={form.origin_country} onChange={e => setForm(f => ({ ...f, origin_country: e.target.value }))}
                    placeholder="Russia, China, DPRK…" className="g-input w-full text-xs" />
                </div>
                <div>
                  <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Motivation</label>
                  <select value={form.motivation} onChange={e => setForm(f => ({ ...f, motivation: e.target.value }))} className="g-select w-full text-xs">
                    {ACTOR_MOTIVATIONS.map(m => <option key={m} value={m}>{m}</option>)}
                  </select>
                </div>
              </div>
              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Description</label>
                <textarea value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  placeholder="Background, history, known operations…" className="g-input w-full text-xs resize-none" rows={2} />
              </div>
              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Target Sectors (comma-sep)</label>
                <input value={form.targeted_sectors} onChange={e => setForm(f => ({ ...f, targeted_sectors: e.target.value }))}
                  placeholder="Finance, Energy, Government" className="g-input w-full text-xs" />
              </div>
              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>MITRE Techniques (comma-sep)</label>
                <input value={form.mitre_techniques} onChange={e => setForm(f => ({ ...f, mitre_techniques: e.target.value }))}
                  placeholder="T1566, T1078, T1003" className="g-input w-full text-xs font-mono" />
              </div>
            </div>
            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => setShowAdd(false)} className="g-btn g-btn-ghost flex-1 justify-center text-xs">Cancel</button>
              <button onClick={create} disabled={saving || !form.name} className="g-btn g-btn-primary flex-1 justify-center text-xs">
                {saving ? 'Adding…' : 'Add Actor'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Shared modal helpers (from existing page, preserved) ──────────────────────

function Modal({ title, children, onClose, wide }: { title: string; children: React.ReactNode; onClose: () => void; wide?: boolean }) {
  return (
    <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="g-modal" style={{ maxWidth: wide ? 560 : 480 }}>
        <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{title}</h2>
          <button type="button" onClick={onClose} style={{ color: 'var(--text-2)', fontSize: 18, lineHeight: 1 }} title="Close">×</button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

function ModalActions({ onCancel, onConfirm, saving, disabled, label }: {
  onCancel: () => void; onConfirm: () => void; saving: boolean; disabled?: boolean; label: string;
}) {
  return (
    <div className="flex gap-3 mt-5">
      <button type="button" onClick={onCancel} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
      <button type="button" onClick={onConfirm} disabled={saving || disabled} className="g-btn g-btn-primary flex-1 justify-center">
        {saving ? 'Saving…' : label}
      </button>
    </div>
  );
}

function MInput({ label, value, onChange, placeholder, mono }: { label: string; value: string; onChange: (v: string) => void; placeholder?: string; mono?: boolean }) {
  return (
    <div>
      <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>{label}</label>
      <input value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
        className={`g-input ${mono ? 'font-mono' : ''}`} />
    </div>
  );
}

function MSelect({ label, value, onChange, options, capitalize }: { label: string; value: string; onChange: (v: string) => void; options: string[]; capitalize?: boolean }) {
  return (
    <div>
      <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>{label}</label>
      <select value={value} onChange={e => onChange(e.target.value)} className="g-select">
        {options.map(o => <option key={o} value={o}>{capitalize ? o.charAt(0).toUpperCase() + o.slice(1) : o.toUpperCase()}</option>)}
      </select>
    </div>
  );
}

function ActionBtn({ icon, onClick, danger }: { icon: React.ReactNode; onClick: () => void; danger?: boolean }) {
  return (
    <button type="button" onClick={onClick} className="p-1 rounded transition-colors"
      style={{ color: 'var(--text-3)' }}
      onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = danger ? 'var(--red)' : 'var(--accent)'}
      onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
      {icon}
    </button>
  );
}

function LoadingRow() {
  return <div className="py-12 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>;
}

function EmptyRow({ icon, msg }: { icon: React.ReactNode; msg: string }) {
  return (
    <div className="py-12 text-center">
      <div className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }}>{icon}</div>
      <p className="text-sm" style={{ color: 'var(--text-2)' }}>{msg}</p>
    </div>
  );
}

function FeedFields({ form, setForm }: { form: typeof emptyFeed; setForm: (fn: (f: typeof emptyFeed) => typeof emptyFeed) => void }) {
  return (
    <div className="space-y-3">
      <MInput label="Name *" value={form.name} onChange={v => setForm(f => ({ ...f, name: v }))} placeholder="Feed name" />
      <MSelect label="Feed Type" value={form.feed_type} onChange={v => setForm(f => ({ ...f, feed_type: v }))} options={['flatfile', 'otx', 'misp', 'taxii']} capitalize />
      {form.feed_type === 'flatfile' && (
        <MInput label="URL / Path" value={form.source} onChange={v => setForm(f => ({ ...f, source: v }))} placeholder="https://… or /path/to/feed.txt" mono />
      )}
      {(form.feed_type === 'otx' || form.feed_type === 'misp') && (
        <MInput label="API Key *" value={form.config.api_key} onChange={v => setForm(f => ({ ...f, config: { ...f.config, api_key: v } }))} placeholder={form.feed_type === 'otx' ? 'AlienVault OTX API key' : 'MISP API key'} mono />
      )}
      {form.feed_type === 'misp' && (
        <MInput label="MISP URL *" value={form.source} onChange={v => setForm(f => ({ ...f, source: v }))} placeholder="https://misp.example.com" mono />
      )}
      {form.feed_type === 'taxii' && (
        <>
          <MInput label="TAXII URL *" value={form.source} onChange={v => setForm(f => ({ ...f, source: v }))} placeholder="https://…/taxii2/" mono />
          <MInput label="Collection ID" value={form.config.collection_id} onChange={v => setForm(f => ({ ...f, config: { ...f.config, collection_id: v } }))} placeholder="collection-uuid" mono />
          <MInput label="Username" value={form.config.username} onChange={v => setForm(f => ({ ...f, config: { ...f.config, username: v } }))} placeholder="optional" />
          <MInput label="Password" value={form.config.password} onChange={v => setForm(f => ({ ...f, config: { ...f.config, password: v } }))} placeholder="optional" />
        </>
      )}
    </div>
  );
}

function Pager({ page, total, totalPages, onChange }: { page: number; total: number; totalPages: number; onChange: (p: number) => void }) {
  if (totalPages <= 1) return null;
  const pages: number[] = [];
  const start = Math.max(1, Math.min(page - 2, totalPages - 4));
  const end   = Math.min(totalPages, start + 4);
  for (let p = start; p <= end; p++) pages.push(p);
  return (
    <div className="flex items-center justify-between px-1 pt-1">
      <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
        {((page - 1) * 50 + 1).toLocaleString()}–{Math.min(page * 50, total).toLocaleString()} of {total.toLocaleString()}
      </p>
      <div className="flex items-center gap-1">
        <button type="button" disabled={page === 1} onClick={() => onChange(page - 1)}
          className="p-1.5 rounded-lg disabled:opacity-30" style={{ border: '1px solid var(--border)', color: 'var(--text-2)' }}>
          <ChevronLeft className="h-3.5 w-3.5" />
        </button>
        {pages.map(p => (
          <button type="button" key={p} onClick={() => onChange(p)}
            className="min-w-[28px] h-7 px-1.5 rounded-lg text-xs"
            style={{
              background: p === page ? 'var(--accent-glow)' : 'transparent',
              border: `1px solid ${p === page ? 'var(--accent-border)' : 'var(--border)'}`,
              color: p === page ? 'var(--accent)' : 'var(--text-2)',
              fontWeight: p === page ? 600 : 400,
            }}>
            {p}
          </button>
        ))}
        <button type="button" disabled={page === totalPages} onClick={() => onChange(page + 1)}
          className="p-1.5 rounded-lg disabled:opacity-30" style={{ border: '1px solid var(--border)', color: 'var(--text-2)' }}>
          <ChevronRight className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}

function ToastEl({ msg, isError }: { msg: string; isError?: boolean }) {
  if (typeof document === 'undefined') return null;
  return createPortal(
    <div className="fixed bottom-5 right-5 px-4 py-3 text-sm rounded-xl shadow-lg"
      style={{
        zIndex: 99999, minWidth: 260, maxWidth: 400,
        background: isError ? 'var(--red)' : 'var(--glass-bg)',
        color: isError ? '#fff' : 'var(--text-1)',
        border: '1px solid ' + (isError ? 'rgba(255,255,255,0.2)' : 'var(--border)'),
        backdropFilter: 'blur(12px)',
      }}>
      {msg}
    </div>,
    document.body
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function ThreatIntelPage() {
  const [tab, setTab] = useState<ViewTab>('overview');
  const [hours, setHours] = useState(24);
  const loaded = useRef<Partial<Record<ViewTab, boolean>>>({});

  // Overview / analytics / campaigns / mitre / relationships / watchlist / timeline
  const [overview,       setOverview]       = useState<Overview | null>(null);
  const [analytics,      setAnalytics]      = useState<Analytics | null>(null);
  const [campaigns,      setCampaigns]      = useState<Campaign[]>([]);
  const [mitreData,      setMitreData]      = useState<MITREData | null>(null);
  const [relData,        setRelData]        = useState<{ nodes: RelNode[]; edges: RelEdge[] } | null>(null);
  const [watchlist,      setWatchlist]      = useState<WatchItem[]>([]);
  const [timelineEvents, setTimelineEvents] = useState<TimelineIOC[]>([]);
  const [loadingTab,     setLoadingTab]     = useState(false);

  // IOC state (from existing page)
  const [iocs,     setIocs]     = useState<IOC[]>([]);
  const [iocTotal, setIocTotal] = useState(0);
  const [iocPage,  setIocPage]  = useState(1);
  const [typeFilter, setTypeFilter] = useState('all');
  const [iocSearch, setIocSearch]   = useState('');
  const [iocLoading, setIocLoading] = useState(false);
  const iocDebounce = useRef<ReturnType<typeof setTimeout>>();
  const [debouncedIocSearch, setDebouncedIocSearch] = useState('');

  // Sigma state
  const [sigma, setSigma]         = useState<SigmaRule[]>([]);
  const [sigmaTotal, setSigmaTotal] = useState(0);
  const [sigmaPage, setSigmaPage]   = useState(1);
  const [sigmaSearch, setSigmaSearch] = useState('');
  const [sigmaLoading, setSigmaLoading] = useState(false);
  const sigmaDebounce = useRef<ReturnType<typeof setTimeout>>();
  const [debouncedSigmaSearch, setDebouncedSigmaSearch] = useState('');

  // Feeds
  const [feeds, setFeeds]     = useState<ThreatFeed[]>([]);
  const [syncingId, setSyncingId] = useState<number | null>(null);

  // Toast
  const [toast, setToast] = useState<{ msg: string; isError?: boolean } | null>(null);

  // Modals
  const [showAddIOC, setShowAddIOC]   = useState(false);
  const [showEditIOC, setShowEditIOC] = useState<IOC | null>(null);
  const [showBulk, setShowBulk]       = useState(false);
  const [showAddSigma, setShowAddSigma]   = useState(false);
  const [showEditSigma, setShowEditSigma] = useState<SigmaRule | null>(null);
  const [showAddFeed, setShowAddFeed]   = useState(false);
  const [editFeed, setEditFeed]         = useState<ThreatFeed | null>(null);

  const [iocForm,   setIocForm]   = useState({ ...emptyIOC });
  const [sigmaForm, setSigmaForm] = useState({ ...emptySigma });
  const [feedForm,  setFeedForm]  = useState({ ...emptyFeed });
  const [editForm,  setEditForm]  = useState({ ...emptyFeed });
  const [bulkForm,  setBulkForm]  = useState({ type: 'ip', severity: 'high', description: '', indicators: '' });
  const [saving, setSaving] = useState(false);

  const notify = (m: string, isError = false) => {
    setToast({ msg: m, isError });
    setTimeout(() => setToast(null), isError ? 6000 : 3000);
  };

  // Debounce searches
  useEffect(() => {
    clearTimeout(iocDebounce.current);
    iocDebounce.current = setTimeout(() => { setDebouncedIocSearch(iocSearch); setIocPage(1); }, 350);
  }, [iocSearch]);

  useEffect(() => {
    clearTimeout(sigmaDebounce.current);
    sigmaDebounce.current = setTimeout(() => { setDebouncedSigmaSearch(sigmaSearch); setSigmaPage(1); }, 350);
  }, [sigmaSearch]);

  // Loaders for old tabs
  const loadIOCs = useCallback(async (page: number, search: string, type: string) => {
    setIocLoading(true);
    try {
      const r = await iocsAPI.getPaged({ page, limit: PAGE_SIZE, search: search || undefined, type: type === 'all' ? undefined : type });
      setIocs(r.data?.data ?? []);
      setIocTotal(r.data?.total ?? 0);
    } catch { setIocs([]); } finally { setIocLoading(false); }
  }, []);

  const loadSigma = useCallback(async (page: number, search: string) => {
    setSigmaLoading(true);
    try {
      const r = await sigmaAPI.getPaged({ page, limit: PAGE_SIZE, search: search || undefined });
      setSigma(r.data?.data ?? []);
      setSigmaTotal(r.data?.total ?? 0);
    } catch { setSigma([]); } finally { setSigmaLoading(false); }
  }, []);

  const loadFeeds = useCallback(async () => {
    const r = await threatFeedsAPI.getAll();
    setFeeds(r.data || []);
  }, []);

  useEffect(() => { if (tab === 'iocs') loadIOCs(iocPage, debouncedIocSearch, typeFilter); }, [loadIOCs, iocPage, debouncedIocSearch, typeFilter, tab]);
  useEffect(() => { if (tab === 'feeds') loadSigma(sigmaPage, debouncedSigmaSearch); }, [loadSigma, sigmaPage, debouncedSigmaSearch, tab]);
  useEffect(() => { if (tab === 'feeds') loadFeeds(); }, [loadFeeds, tab]);

  // Enterprise tab loading
  const loadTab = useCallback(async (t: ViewTab, force = false) => {
    if (loaded.current[t] && !force) return;
    loaded.current[t] = true;
    setLoadingTab(true);
    try {
      switch (t) {
        case 'overview': {
          const r = await intelAPI.getOverview(hours);
          if (r.data) setOverview(r.data as Overview);
          break;
        }
        case 'campaigns': {
          const r = await intelAPI.getCampaigns();
          const d = r.data as { campaigns?: Campaign[] } | null;
          if (d?.campaigns) setCampaigns(d.campaigns);
          break;
        }
        case 'mitre': {
          const r = await intelAPI.getMITRE();
          if (r.data) setMitreData(r.data as MITREData);
          break;
        }
        case 'relationships': {
          const r = await intelAPI.getRelationships();
          if (r.data) setRelData(r.data as { nodes: RelNode[]; edges: RelEdge[] });
          break;
        }
        case 'watchlist': {
          const r = await intelAPI.getWatchlist();
          const d = r.data as { watchlist?: WatchItem[] } | null;
          if (d?.watchlist) setWatchlist(d.watchlist);
          break;
        }
        case 'timeline': {
          const r = await intelAPI.getTimeline(hours);
          const d = r.data as { events?: TimelineIOC[] } | null;
          if (d?.events) setTimelineEvents(d.events);
          break;
        }
        case 'analytics': {
          const r = await intelAPI.getAnalytics();
          if (r.data) setAnalytics(r.data as Analytics);
          break;
        }
        default: break;
      }
    } finally {
      setLoadingTab(false);
    }
  }, [hours]);

  useEffect(() => {
    loaded.current = {};
    loadTab(tab);
  }, [tab, hours]);

  // IOC CRUD
  const serializeIocForm = (f: typeof iocForm) => ({ ...f, expires_at: f.expires_at || null });
  const addIOC = async () => {
    if (!iocForm.indicator.trim()) return;
    setSaving(true);
    try { await iocsAPI.create(serializeIocForm(iocForm)); loadIOCs(iocPage, debouncedIocSearch, typeFilter); setShowAddIOC(false); setIocForm({ ...emptyIOC }); notify('IOC added'); }
    finally { setSaving(false); }
  };
  const updateIOC = async () => {
    if (!showEditIOC) return;
    setSaving(true);
    try { await iocsAPI.update(showEditIOC.id, serializeIocForm(iocForm)); loadIOCs(iocPage, debouncedIocSearch, typeFilter); setShowEditIOC(null); notify('IOC updated'); }
    finally { setSaving(false); }
  };
  const deleteIOC = async (id: number) => { await iocsAPI.delete(id); setIocs(p => p.filter(i => i.id !== id)); setIocTotal(t => t - 1); notify('IOC deleted'); };
  const toggleIOC = async (ioc: IOC) => { ioc.enabled ? await iocsAPI.disable(ioc.id) : await iocsAPI.enable(ioc.id); setIocs(p => p.map(i => i.id === ioc.id ? { ...i, enabled: !i.enabled } : i)); };
  const openEditIOC = (ioc: IOC) => {
    setIocForm({ indicator: ioc.indicator, type: ioc.type, severity: ioc.severity, description: ioc.description, enabled: ioc.enabled, expires_at: ioc.expires_at ? String(ioc.expires_at).slice(0, 10) : '' });
    setShowEditIOC(ioc);
  };
  const bulkImport = async () => {
    setSaving(true);
    try {
      const r = await iocsAPI.bulkCreate({ indicators: bulkForm.indicators, severity: bulkForm.severity, description: bulkForm.description, source: 'manual' });
      notify(`Imported ${r.data.imported} IOCs (${r.data.dupes} dupes, ${r.data.skipped} skipped)`);
      loadIOCs(1, debouncedIocSearch, typeFilter); setIocPage(1); setShowBulk(false); setBulkForm({ type: 'ip', severity: 'high', description: '', indicators: '' });
    } catch { notify('Bulk import failed', true); } finally { setSaving(false); }
  };

  // Sigma CRUD
  const addSigma = async () => {
    if (!sigmaForm.title.trim()) return;
    setSaving(true);
    try { const kw = sigmaForm.keywords.split(',').map(s => s.trim()).filter(Boolean); await sigmaAPI.create({ ...sigmaForm, keywords: kw }); loadSigma(sigmaPage, debouncedSigmaSearch); setShowAddSigma(false); setSigmaForm({ ...emptySigma }); notify('Sigma rule created'); }
    finally { setSaving(false); }
  };
  const updateSigma = async () => {
    if (!showEditSigma) return;
    setSaving(true);
    try { const kw = sigmaForm.keywords.split(',').map(s => s.trim()).filter(Boolean); await sigmaAPI.update(showEditSigma.id, { ...sigmaForm, keywords: kw }); loadSigma(sigmaPage, debouncedSigmaSearch); setShowEditSigma(null); notify('Rule updated'); }
    finally { setSaving(false); }
  };
  const deleteSigma = async (id: number) => { await sigmaAPI.delete(id); setSigma(p => p.filter(r => r.id !== id)); setSigmaTotal(t => t - 1); notify('Rule deleted'); };
  const toggleSigma = async (r: SigmaRule) => { r.enabled ? await sigmaAPI.disable(r.id) : await sigmaAPI.enable(r.id); setSigma(p => p.map(x => x.id === r.id ? { ...x, enabled: !x.enabled } : x)); };
  const openEditSigma = (r: SigmaRule) => {
    setSigmaForm({ title: r.title, severity: r.severity, mitre_tactic: r.mitre_tactic, mitre_technique: r.mitre_technique, mitre_name: r.mitre_name, keywords: (r.keywords || []).join(', '), enabled: r.enabled });
    setShowEditSigma(r);
  };

  // Feed CRUD
  const syncFeed = async (feed: ThreatFeed) => {
    if (feed.id == null) return;
    setSyncingId(feed.id);
    try {
      const res = await threatFeedsAPI.sync(feed.id);
      const count = res.data?.count ?? 0;
      notify(res.data?.warning ? `Partial sync: ${count} imported. ${res.data.warning.split('then: ')[1] ?? ''}` : `Synced "${feed.name}" — ${count} indicators`);
      loadFeeds(); loadIOCs(1, debouncedIocSearch, typeFilter); setIocPage(1);
    } catch (e: unknown) {
      const err = e as { response?: { data?: { error?: string } } };
      notify(err?.response?.data?.error || `Failed to sync "${feed.name}"`, true);
    } finally { setSyncingId(null); }
  };
  const deleteFeed = async (feed: ThreatFeed) => {
    if (!confirm(`Delete feed "${feed.name}"?`)) return;
    try { await threatFeedsAPI.delete(feed.id!); loadFeeds(); notify(`Deleted "${feed.name}"`); }
    catch { notify('Failed to delete feed', true); }
  };
  const openEditFeed = (f: ThreatFeed) => {
    let cfg = { api_key: '', collection_id: '', username: '', password: '' };
    try { const raw = typeof f.config === 'string' ? JSON.parse(f.config) : f.config; cfg = { ...cfg, ...raw }; } catch {}
    setEditForm({ name: f.name, source: f.source || '', feed_type: f.feed_type || 'flatfile', enabled: f.enabled, config: cfg });
    setEditFeed(f);
  };
  const updateFeed = async () => {
    if (!editFeed) return;
    setSaving(true);
    try { await threatFeedsAPI.update(editFeed.id!, editForm); loadFeeds(); setEditFeed(null); notify('Feed updated'); }
    catch (e: unknown) { const err = e as { response?: { data?: { error?: string } } }; notify(err?.response?.data?.error || 'Failed to update feed', true); }
    finally { setSaving(false); }
  };
  const addFeed = async () => {
    if (!feedForm.name.trim()) return;
    setSaving(true);
    try { await threatFeedsAPI.create(feedForm); loadFeeds(); setShowAddFeed(false); setFeedForm({ ...emptyFeed }); notify('Feed added'); }
    finally { setSaving(false); }
  };

  const iocPages   = Math.max(1, Math.ceil(iocTotal / PAGE_SIZE));
  const sigmaPages = Math.max(1, Math.ceil(sigmaTotal / PAGE_SIZE));

  const maxTypeCount = useMemo(() => Math.max(...(overview?.type_breakdown.map(t => t.count) ?? []), 1), [overview]);
  const maxActorCount = useMemo(() => Math.max(...(analytics?.top_actors.map(a => a.alert_count) ?? []), 1), [analytics]);
  const maxHitCount = useMemo(() => Math.max(...(analytics?.top_iocs.map(i => i.hit_count) ?? []), 1), [analytics]);

  return (
    <RootLayout title="Threat Intelligence"
      subtitle={`${iocTotal.toLocaleString()} IOCs · ${feeds.filter(f => f.enabled).length} active feeds · ${sigma.length} Sigma rules`}
      actions={
        <div className="flex items-center gap-2">
          <select value={hours} onChange={e => { setHours(Number(e.target.value)); loaded.current = {}; }}
            className="g-select text-xs py-1">
            {[6, 12, 24, 48, 168].map(h => <option key={h} value={h}>{h < 24 ? `${h}h` : h === 168 ? '7d' : '24h'}</option>)}
          </select>
          <button onClick={() => { loaded.current = {}; loadTab(tab, true); loadFeeds(); loadIOCs(iocPage, debouncedIocSearch, typeFilter); }} className="g-btn g-btn-ghost text-xs">
            <RefreshCw className={`w-3.5 h-3.5 ${loadingTab ? 'animate-spin' : ''}`} />
          </button>
        </div>
      }>

      {toast && <ToastEl msg={toast.msg} isError={toast.isError} />}

      {/* Tab bar */}
      <div className="flex gap-0.5 mb-4 overflow-x-auto pb-1">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors ${tab === t.id ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'}`}>
            <t.icon className="w-3.5 h-3.5" />
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Overview ── */}
      {tab === 'overview' && (
        <div className="space-y-4">
          {overview ? (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <KPICard label="Total IOCs"       value={overview.total_iocs.toLocaleString()} color="var(--accent)"  icon={Shield} />
                <KPICard label="New Today"        value={overview.new_today}                   color="#fbbf24"        icon={Plus} />
                <KPICard label="IOC Matches"      value={overview.ioc_matches}                 color="var(--red)"     icon={AlertTriangle} />
                <KPICard label="High Confidence"  value={overview.high_confidence}             color="var(--green)"   icon={CheckCircle2} />
                <KPICard label="Active Feeds"     value={overview.enabled_feeds}               color="#a78bfa"        icon={Rss}
                  sub={`${overview.healthy_feeds} healthy`} />
                <KPICard label="Threat Actors"    value={overview.total_actors}                color="var(--red)"     icon={Users} />
                <KPICard label="Sigma Rules"      value={overview.sigma_rules}                 color="var(--accent)"  icon={FileCode} />
                <KPICard label="YARA Rules"       value={overview.yara_rules}                  color="#fb923c"        icon={Lock} />
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>7-day IOC Growth</p>
                  <SparkBar data={overview.trend} />
                </div>
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>IOC Type Breakdown</p>
                  <div className="space-y-2">
                    {overview.type_breakdown.slice(0, 8).map(t => (
                      <div key={t.type} className="flex items-center gap-2">
                        <span className="text-xs font-mono uppercase w-20 shrink-0" style={{ color: 'var(--text-3)' }}>{t.type}</span>
                        <MiniBar value={t.count} max={maxTypeCount} color="var(--accent)" />
                        <span className="text-[11px] tabular-nums w-10 text-right shrink-0 font-bold" style={{ color: 'var(--accent)' }}>
                          {t.count.toLocaleString()}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Feed health strip */}
              {feeds.length > 0 && (
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Feed Health</p>
                  <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
                    {feeds.map(f => {
                      const healthy = f.enabled && !!f.last_sync && (new Date().getTime() - new Date(f.last_sync).getTime() < 25 * 3600000);
                      return (
                        <div key={f.id} className="p-2.5 rounded-lg"
                          style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                          <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{f.name}</p>
                          <div className="flex items-center justify-between mt-1">
                            <FeedHealthDot healthy={healthy} />
                            <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                              {f.last_sync ? timeAgo(f.last_sync) : 'Never'}
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          )}
        </div>
      )}

      {/* ── IOCs ── */}
      {tab === 'iocs' && (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2 items-center">
            {['all', ...IOC_TYPES_SIMPLE].map(t => (
              <button type="button" key={t} onClick={() => { setTypeFilter(t); setIocPage(1); }}
                className="g-btn text-[11px] uppercase"
                style={{ background: typeFilter === t ? 'var(--accent-glow)' : 'var(--glass-bg)', color: typeFilter === t ? 'var(--accent)' : 'var(--text-2)', border: `1px solid ${typeFilter === t ? 'var(--accent-border)' : 'var(--border)'}`, padding: '4px 10px' }}>
                {t === 'all' ? `All (${iocTotal.toLocaleString()})` : t}
              </button>
            ))}
            <div className="relative ml-auto">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
              <input value={iocSearch} onChange={e => setIocSearch(e.target.value)}
                placeholder="Search indicator…" className="g-input pl-9" style={{ width: 220, height: 34 }} />
            </div>
            <button type="button" onClick={() => setShowBulk(true)} className="g-btn g-btn-ghost text-xs">
              <Upload className="h-3.5 w-3.5" /> Bulk Import
            </button>
            <button type="button" onClick={() => { setIocForm({ ...emptyIOC }); setShowAddIOC(true); }} className="g-btn g-btn-primary text-xs">
              <Plus className="h-3.5 w-3.5" /> Add IOC
            </button>
          </div>

          <div className="g-table">
            <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 70px 80px 1fr 90px 80px 80px 60px' }}>
              <span>Indicator</span><span>Type</span><span>Severity</span><span>Description</span>
              <span>Hits</span><span>Last Seen</span><span>Status</span><span className="text-right">Actions</span>
            </div>
            {iocLoading ? <LoadingRow /> : iocs.length === 0
              ? <EmptyRow icon={<Shield />} msg={iocSearch || typeFilter !== 'all' ? 'No IOCs match your filter.' : 'No IOCs yet.'} />
              : iocs.map(ioc => (
                <div key={ioc.id} className={`g-tr grid gap-3 items-center px-4 ${!ioc.enabled ? 'opacity-40' : ''}`}
                  style={{ gridTemplateColumns: '1fr 70px 80px 1fr 90px 80px 80px 60px' }}>
                  <span className="mono text-xs truncate" style={{ color: 'var(--text-1)' }}>{ioc.indicator}</span>
                  <span className="mono text-[10px] rounded px-1.5 py-0.5 uppercase inline-block w-fit"
                    style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                    {ioc.type}
                  </span>
                  <span className={sevClass(ioc.severity)}>{ioc.severity}</span>
                  <span className="text-xs truncate" style={{ color: 'var(--text-2)' }}>{ioc.description}</span>
                  <span className="text-xs font-mono" style={{ color: (ioc.hit_count ?? 0) > 0 ? 'var(--red)' : 'var(--text-3)' }}>
                    {(ioc.hit_count ?? 0).toLocaleString()}
                  </span>
                  <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{ioc.last_seen ? timeAgo(String(ioc.last_seen)) : '—'}</span>
                  <button type="button" onClick={() => toggleIOC(ioc)} className="flex items-center gap-1 text-[10px]"
                    style={{ color: ioc.enabled ? 'var(--green)' : 'var(--text-3)' }}>
                    {ioc.enabled ? <ToggleRight className="h-4 w-4" /> : <ToggleLeft className="h-4 w-4" />}
                    {ioc.enabled ? 'On' : 'Off'}
                  </button>
                  <div className="flex items-center justify-end gap-1">
                    <ActionBtn icon={<Edit2 className="h-3.5 w-3.5" />} onClick={() => openEditIOC(ioc)} />
                    <ActionBtn icon={<Trash2 className="h-3.5 w-3.5" />} onClick={() => deleteIOC(ioc.id)} danger />
                  </div>
                </div>
              ))
            }
          </div>
          <Pager page={iocPage} total={iocTotal} totalPages={iocPages} onChange={p => setIocPage(p)} />
        </div>
      )}

      {/* ── Feeds ── */}
      {tab === 'feeds' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-xs" style={{ color: 'var(--text-3)' }}>{feeds.length} feeds configured</p>
            <button type="button" onClick={() => setShowAddFeed(true)} className="g-btn g-btn-primary text-xs">
              <Plus className="h-3.5 w-3.5" /> Add Feed
            </button>
          </div>

          {/* Feed provider tiles */}
          <div className="g-card p-4">
            <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Supported Providers</p>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {FEED_PROVIDERS.map(fp => (
                <div key={fp.name} className="p-3 rounded-lg"
                  style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}>
                  <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{fp.name}</p>
                  <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{fp.desc}</p>
                  <span className="text-[9px] px-1.5 py-0.5 rounded mt-1 inline-block uppercase"
                    style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                    {fp.type}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="g-table">
            <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 1fr 80px 120px 80px 140px' }}>
              <span>Name</span><span>Source</span><span>Type</span><span>Health</span><span>Last Sync</span><span className="text-right">Actions</span>
            </div>
            {feeds.length === 0 ? <EmptyRow icon={<Rss />} msg="No threat feeds configured." /> :
              feeds.map((f, i) => {
                const healthy = f.enabled && !!f.last_sync && (new Date().getTime() - new Date(f.last_sync).getTime() < 25 * 3600000);
                return (
                  <div key={i} className="g-tr grid gap-3 items-center px-4"
                    style={{ gridTemplateColumns: '1fr 1fr 80px 120px 80px 140px' }}>
                    <span className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{f.name}</span>
                    <span className="mono text-xs truncate" style={{ color: 'var(--text-2)' }}>{f.source || f.feed_type}</span>
                    <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded"
                      style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)' }}>{f.feed_type}</span>
                    <FeedHealthDot healthy={healthy} />
                    <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{f.last_sync ? timeAgo(f.last_sync) : 'Never'}</span>
                    <div className="flex justify-end gap-1">
                      <button type="button" onClick={() => syncFeed(f)} disabled={syncingId === f.id} className="g-btn g-btn-ghost text-[11px]" style={{ padding: '3px 8px' }}>
                        <RefreshCw className={`h-3 w-3 ${syncingId === f.id ? 'animate-spin' : ''}`} /> Sync
                      </button>
                      <button type="button" onClick={() => openEditFeed(f)} className="g-btn g-btn-ghost text-[11px]" style={{ padding: '3px 8px' }}>
                        <Edit2 className="h-3 w-3" />
                      </button>
                      <button type="button" onClick={() => deleteFeed(f)} className="g-btn g-btn-ghost text-[11px]" style={{ padding: '3px 8px', color: 'var(--red)' }}>
                        <Trash2 className="h-3 w-3" />
                      </button>
                    </div>
                  </div>
                );
              })
            }
          </div>
        </div>
      )}

      {/* ── Threat Actors ── */}
      {tab === 'actors' && <ActorsPanel />}

      {/* ── Campaigns ── */}
      {tab === 'campaigns' && (
        <div className="space-y-4">
          {campaigns.length > 0 ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {campaigns.map(cp => (
                <div key={cp.technique} className="g-card p-4">
                  <div className="flex items-start justify-between mb-2">
                    <div>
                      <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{cp.name}</p>
                      <p className="font-mono text-[11px]" style={{ color: '#fbbf24' }}>{cp.technique}</p>
                    </div>
                    <span className="text-[10px] px-1.5 py-0.5 rounded capitalize"
                      style={{ background: cp.status === 'active' ? 'rgba(248,81,73,0.15)' : 'var(--glass-bg-2)', color: cp.status === 'active' ? 'var(--red)' : 'var(--text-3)', border: `1px solid ${cp.status === 'active' ? 'rgba(248,81,73,0.3)' : 'var(--border)'}` }}>
                      {cp.status}
                    </span>
                  </div>
                  <div className="space-y-1 text-[11px]" style={{ color: 'var(--text-3)' }}>
                    <div className="flex justify-between">
                      <span>Clusters</span>
                      <span className="font-bold" style={{ color: 'var(--text-2)' }}>{cp.cluster_count}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Total Alerts</span>
                      <span className="font-bold" style={{ color: '#fbbf24' }}>{cp.total_alerts}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Last Active</span>
                      <span>{timeAgo(cp.latest)}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="py-16 text-center text-sm" style={{ color: 'var(--text-3)' }}>
              No campaign data. Campaigns are synthesized from alert clusters.
            </div>
          )}
        </div>
      )}

      {/* ── Relationships ── */}
      {tab === 'relationships' && (
        <div className="space-y-4">
          <p className="text-xs" style={{ color: 'var(--text-3)' }}>
            Intelligence relationship graph: threat actors → campaigns → IOCs → alerts.
          </p>
          {relData ? (
            <RelationshipGraph nodes={relData.nodes} edges={relData.edges} />
          ) : (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          )}
        </div>
      )}

      {/* ── MITRE Coverage ── */}
      {tab === 'mitre' && (
        <div className="space-y-4">
          {mitreData ? (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                <KPICard label="Techniques Covered" value={mitreData.total}          color="var(--accent)"  icon={Shield} />
                <KPICard label="Tactics Mapped"      value={mitreData.covered_tactics} color="var(--green)" icon={Layers} />
                <KPICard label="Coverage Sources"    value="Sigma + Actors"          color="#a78bfa"        icon={Database} />
              </div>
              <div className="g-card overflow-hidden">
                <table className="w-full text-xs">
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
                      {['Technique','Source','Total Rules','Enabled','Coverage'].map(h => (
                        <th key={h} className="px-3 py-2.5 text-left font-semibold" style={{ color: 'var(--text-3)' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {mitreData.techniques.map((t, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td className="px-3 py-2.5 font-mono font-bold" style={{ color: '#fbbf24' }}>{t.technique}</td>
                        <td className="px-3 py-2.5">
                          <span className="text-[10px] px-1.5 py-0.5 rounded uppercase"
                            style={{ background: 'var(--glass-bg-2)', color: t.source === 'sigma' ? 'var(--accent)' : 'var(--red)' }}>
                            {t.source}
                          </span>
                        </td>
                        <td className="px-3 py-2.5 font-bold tabular-nums" style={{ color: 'var(--text-2)' }}>{t.total}</td>
                        <td className="px-3 py-2.5" style={{ color: 'var(--green)' }}>{t.enabled}</td>
                        <td className="px-3 py-2.5">
                          <div className="flex items-center gap-2">
                            <MiniBar value={t.enabled} max={t.total || 1} color="var(--accent)" />
                            <span className="text-[10px] tabular-nums" style={{ color: 'var(--text-3)' }}>
                              {t.total > 0 ? Math.round((t.enabled / t.total) * 100) : 0}%
                            </span>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {mitreData.techniques.length === 0 && <EmptyRow icon={<Layers />} msg="No MITRE technique data yet." />}
              </div>
            </>
          ) : (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          )}
        </div>
      )}

      {/* ── Timeline ── */}
      {tab === 'timeline' && (
        <div className="space-y-4">
          {timelineEvents.length > 0 ? (
            <div className="g-card overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
                    {['Indicator','Type','Severity','Hits','First Seen','Last Seen','Expires'].map(h => (
                      <th key={h} className="px-3 py-2.5 text-left font-semibold" style={{ color: 'var(--text-3)' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {timelineEvents.map(t => (
                    <tr key={t.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td className="px-3 py-2.5 font-mono max-w-[180px] truncate" style={{ color: 'var(--text-1)' }}>{t.indicator}</td>
                      <td className="px-3 py-2.5">
                        <span className="text-[10px] uppercase px-1.5 py-0.5 rounded"
                          style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                          {t.type}
                        </span>
                      </td>
                      <td className="px-3 py-2.5">{sevBadge(t.severity)}</td>
                      <td className="px-3 py-2.5 font-bold tabular-nums" style={{ color: t.hit_count > 0 ? 'var(--red)' : 'var(--text-3)' }}>{t.hit_count}</td>
                      <td className="px-3 py-2.5 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>{timeAgo(t.created_at)}</td>
                      <td className="px-3 py-2.5 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>{t.last_seen ? timeAgo(t.last_seen) : '—'}</td>
                      <td className="px-3 py-2.5 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>{t.expires_at ? timeAgo(t.expires_at) : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="py-16 text-center text-sm" style={{ color: 'var(--text-3)' }}>
              {loadingTab ? 'Loading…' : 'No IOC activity in the selected time range.'}
            </div>
          )}
        </div>
      )}

      {/* ── Watchlist ── */}
      {tab === 'watchlist' && (
        <div className="space-y-4">
          <div className="g-card p-4 text-xs" style={{ color: 'var(--text-3)' }}>
            <span className="font-semibold" style={{ color: 'var(--text-2)' }}>Watchlist: </span>
            Automatically populated with Critical and High severity IOCs that are currently enabled.
          </div>
          {watchlist.length > 0 ? (
            <div className="g-card overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
                    {['Indicator','Type','Severity','Hits','Description','Added'].map(h => (
                      <th key={h} className="px-3 py-2.5 text-left font-semibold" style={{ color: 'var(--text-3)' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {watchlist.map(w => (
                    <tr key={w.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td className="px-3 py-2.5 font-mono max-w-[180px] truncate" style={{ color: 'var(--text-1)' }}>{w.indicator}</td>
                      <td className="px-3 py-2.5">
                        <span className="text-[10px] uppercase px-1.5 py-0.5 rounded"
                          style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                          {w.type}
                        </span>
                      </td>
                      <td className="px-3 py-2.5">{sevBadge(w.severity)}</td>
                      <td className="px-3 py-2.5 font-bold tabular-nums" style={{ color: w.hit_count > 0 ? 'var(--red)' : 'var(--text-3)' }}>{w.hit_count}</td>
                      <td className="px-3 py-2.5 max-w-xs truncate" style={{ color: 'var(--text-3)' }}>{w.description}</td>
                      <td className="px-3 py-2.5 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>{timeAgo(w.added_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="py-16 text-center">
              <Eye className="mx-auto w-10 h-10 mb-3 opacity-20" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-3)' }}>Watchlist is empty. Add Critical or High severity IOCs to populate it.</p>
            </div>
          )}
        </div>
      )}

      {/* ── Search / Hunt ── */}
      {tab === 'search' && <SearchPanel />}

      {/* ── Analytics ── */}
      {tab === 'analytics' && (
        <div className="space-y-4">
          {analytics ? (
            <>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Top matched IOCs */}
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Most Matched IOCs</p>
                  <div className="space-y-2">
                    {analytics.top_iocs.map(ioc => (
                      <div key={ioc.id} className="flex items-center gap-2">
                        <span className="font-mono text-xs flex-1 truncate" style={{ color: 'var(--text-2)' }}>{ioc.indicator}</span>
                        {sevBadge(ioc.severity)}
                        <MiniBar value={ioc.hit_count} max={maxHitCount} color="var(--red)" />
                        <span className="text-[11px] font-bold tabular-nums w-8 text-right shrink-0" style={{ color: 'var(--red)' }}>{ioc.hit_count}</span>
                      </div>
                    ))}
                    {analytics.top_iocs.length === 0 && <p className="text-xs" style={{ color: 'var(--text-3)' }}>No IOC matches yet</p>}
                  </div>
                </div>

                {/* Top actors */}
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Top Threat Actors (by alert tags)</p>
                  <div className="space-y-2">
                    {analytics.top_actors.map(a => (
                      <div key={a.id} className="flex items-center gap-2">
                        <span className="text-xs flex-1 truncate" style={{ color: 'var(--text-2)' }}>{a.name}</span>
                        <span className="text-[10px] capitalize" style={{ color: 'var(--text-3)' }}>{a.motivation}</span>
                        <MiniBar value={a.alert_count} max={maxActorCount} color="var(--red)" />
                        <span className="text-[11px] font-bold tabular-nums w-6 text-right shrink-0" style={{ color: 'var(--text-3)' }}>{a.alert_count}</span>
                      </div>
                    ))}
                    {analytics.top_actors.length === 0 && <p className="text-xs" style={{ color: 'var(--text-3)' }}>No actor data</p>}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* IOC growth */}
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>IOC Growth (4-week)</p>
                  <SparkBar data={analytics.ioc_growth} label="New IOCs per week" />
                </div>

                {/* Severity distribution */}
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>IOC Severity Distribution</p>
                  <div className="space-y-2">
                    {analytics.severity_distribution.map(s => {
                      const max = Math.max(...analytics.severity_distribution.map(x => x.count), 1);
                      return (
                        <div key={s.severity} className="flex items-center gap-2">
                          <span className="w-20 shrink-0">{sevBadge(s.severity)}</span>
                          <MiniBar value={s.count} max={max} color={SEV_COLOR[s.severity] ?? 'var(--text-3)'} />
                          <span className="text-[11px] tabular-nums w-10 text-right shrink-0 font-bold"
                            style={{ color: SEV_COLOR[s.severity] ?? 'var(--text-3)' }}>
                            {s.count.toLocaleString()}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>

              {/* Feed reliability */}
              <div className="g-card p-4">
                <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Feed Reliability</p>
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
                  {analytics.feed_reliability.map((f, i) => (
                    <div key={i} className="p-3 rounded-lg"
                      style={{ background: 'var(--glass-bg)', border: `1px solid ${f.healthy ? 'rgba(52,211,153,0.3)' : 'var(--border)'}` }}>
                      <div className="flex items-center justify-between mb-1">
                        <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{f.name}</p>
                        <FeedHealthDot healthy={f.healthy} />
                      </div>
                      <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
                        {f.last_sync ? `Synced ${timeAgo(f.last_sync)}` : 'Never synced'}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          )}
        </div>
      )}

      {/* ── AI Intel ── */}
      {tab === 'ai' && <AIIntelPanel />}

      {/* ── Modals (IOC) ── */}
      {(showAddIOC || showEditIOC) && (
        <Modal title={showEditIOC ? 'Edit IOC' : 'Add IOC'} onClose={() => { setShowAddIOC(false); setShowEditIOC(null); }}>
          <div className="space-y-3">
            <MInput label="Indicator *" value={iocForm.indicator} onChange={v => setIocForm(f => ({ ...f, indicator: v }))} placeholder="IP, hash, domain, URL" mono />
            <div className="grid grid-cols-2 gap-3">
              <MSelect label="Type" value={iocForm.type} onChange={v => setIocForm(f => ({ ...f, type: v }))} options={IOC_TYPES_SIMPLE} />
              <MSelect label="Severity" value={iocForm.severity} onChange={v => setIocForm(f => ({ ...f, severity: v }))} options={SEVERITIES} capitalize />
            </div>
            <MInput label="Description" value={iocForm.description} onChange={v => setIocForm(f => ({ ...f, description: v }))} placeholder="Context, source, notes…" />
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Expires At</label>
              <input type="date" value={iocForm.expires_at} onChange={e => setIocForm(f => ({ ...f, expires_at: e.target.value }))} className="g-input" />
            </div>
          </div>
          <ModalActions onCancel={() => { setShowAddIOC(false); setShowEditIOC(null); }}
            onConfirm={showEditIOC ? updateIOC : addIOC} saving={saving}
            disabled={!iocForm.indicator.trim()} label={showEditIOC ? 'Update' : 'Add IOC'} />
        </Modal>
      )}

      {showBulk && (
        <Modal title="Bulk Import IOCs" onClose={() => setShowBulk(false)}>
          <div className="space-y-3">
            <div className="rounded-xl px-3 py-2 text-[10px]"
              style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)', color: 'var(--text-2)' }}>
              Type is auto-detected — IPv4, IPv6, CIDR, domain, URL, SHA256, MD5, SHA1, email. Supports defanged indicators.
            </div>
            <MSelect label="Severity" value={bulkForm.severity} onChange={v => setBulkForm(f => ({ ...f, severity: v }))} options={SEVERITIES} capitalize />
            <MInput label="Description / Source tag" value={bulkForm.description} onChange={v => setBulkForm(f => ({ ...f, description: v }))} placeholder="e.g. APT28 feed" />
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Indicators (one per line)</label>
              <textarea value={bulkForm.indicators} onChange={e => setBulkForm(f => ({ ...f, indicators: e.target.value }))}
                rows={8} placeholder={"1.2.3.4\nevil.com\nhxxps://malware[.]example/payload"}
                className="g-input resize-none font-mono text-xs" />
            </div>
          </div>
          <ModalActions onCancel={() => setShowBulk(false)} onConfirm={bulkImport} saving={saving}
            disabled={!bulkForm.indicators.trim()} label="Import & Auto-Classify" />
        </Modal>
      )}

      {(showAddSigma || showEditSigma) && (
        <Modal title={showEditSigma ? 'Edit Sigma Rule' : 'New Sigma Rule'} onClose={() => { setShowAddSigma(false); setShowEditSigma(null); }} wide>
          <div className="space-y-3">
            <MInput label="Title *" value={sigmaForm.title} onChange={v => setSigmaForm(f => ({ ...f, title: v }))} placeholder="Rule title" />
            <MSelect label="Severity" value={sigmaForm.severity} onChange={v => setSigmaForm(f => ({ ...f, severity: v }))} options={SEVERITIES} capitalize />
            <MInput label="MITRE Tactic" value={sigmaForm.mitre_tactic} onChange={v => setSigmaForm(f => ({ ...f, mitre_tactic: v }))} placeholder="e.g. Execution" />
            <div className="grid grid-cols-2 gap-3">
              <MInput label="MITRE Technique" value={sigmaForm.mitre_technique} onChange={v => setSigmaForm(f => ({ ...f, mitre_technique: v }))} placeholder="e.g. T1059" />
              <MInput label="MITRE Name" value={sigmaForm.mitre_name} onChange={v => setSigmaForm(f => ({ ...f, mitre_name: v }))} placeholder="e.g. Command Execution" />
            </div>
            <MInput label="Keywords (comma-separated)" value={sigmaForm.keywords} onChange={v => setSigmaForm(f => ({ ...f, keywords: v }))} placeholder="sudo, root, exec" />
          </div>
          <ModalActions onCancel={() => { setShowAddSigma(false); setShowEditSigma(null); }}
            onConfirm={showEditSigma ? updateSigma : addSigma} saving={saving}
            disabled={!sigmaForm.title.trim()} label={showEditSigma ? 'Update' : 'Create Rule'} />
        </Modal>
      )}

      {showAddFeed && (
        <Modal title="Add Threat Feed" onClose={() => setShowAddFeed(false)}>
          <FeedFields form={feedForm} setForm={setFeedForm} />
          <ModalActions onCancel={() => setShowAddFeed(false)} onConfirm={addFeed} saving={saving}
            disabled={!feedForm.name.trim()} label="Add Feed" />
        </Modal>
      )}

      {editFeed && (
        <Modal title={`Edit Feed — ${editFeed.name}`} onClose={() => setEditFeed(null)}>
          <FeedFields form={editForm} setForm={setEditForm} />
          <ModalActions onCancel={() => setEditFeed(null)} onConfirm={updateFeed} saving={saving}
            disabled={!editForm.name.trim()} label="Save Changes" />
        </Modal>
      )}
    </RootLayout>
  );
}
