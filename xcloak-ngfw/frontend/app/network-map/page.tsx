'use client';

import { useEffect, useMemo, useRef, useState, useCallback } from 'react';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { RootLayout } from '@/components/layout/RootLayout';
import { networkMapAPI } from '@/lib/api';
import { NetworkMapGraph, NetworkMapNode, NetworkMapEdge } from '@/types';
import { sevClass } from '@/lib/utils';
import {
  Network, Search, X, Globe, Cpu, ShieldAlert,
  ZoomIn, AlertTriangle, Wifi, WifiOff, Info,
} from 'lucide-react';

const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), { ssr: false });

// ── color maps ──────────────────────────────────────────────────────────────

const RISK_FILL: Record<string, string> = {
  critical: '#f85149',
  high:     '#fb923c',
  medium:   '#fbbf24',
  low:      '#38bdf8',
  unknown:  '#64748b',
};

const IOC_FILL: Record<string, string> = {
  critical: '#f85149',
  high:     '#fb923c',
  medium:   '#fbbf24',
  low:      '#38bdf8',
  unknown:  '#e879f9',
};

const ZONE_RING_VAR: Record<string, string> = {
  internal: '--border-md',
  dmz:      '--orange',
  external: '--text-3',
};

function resolveThemeColors(): Record<string, string> {
  const out: Record<string, string> = {};
  if (typeof window === 'undefined') return out;
  const styles = getComputedStyle(document.documentElement);
  for (const [zone, varName] of Object.entries(ZONE_RING_VAR)) {
    out[zone] = styles.getPropertyValue(varName).trim() || '#64748b';
  }
  return out;
}

// ── constants ────────────────────────────────────────────────────────────────

const TIME_WINDOWS = [
  { label: '15m', minutes: 15 },
  { label: '1h',  minutes: 60 },
  { label: '6h',  minutes: 360 },
  { label: '24h', minutes: 1440 },
];

interface GNode extends NetworkMapNode { val: number; }

// ── Legend component ─────────────────────────────────────────────────────────

function Legend() {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative">
      <button onClick={() => setOpen(o => !o)}
        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs transition-colors"
        style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
        <Info className="h-3.5 w-3.5" /> Legend
      </button>
      {open && (
        <div className="absolute right-0 top-9 z-20 rounded-xl p-4 shadow-xl w-64 space-y-3"
          style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>
          <p className="text-[10px] font-bold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Node colors (agent risk)</p>
          <div className="grid grid-cols-2 gap-1.5">
            {Object.entries(RISK_FILL).map(([k, v]) => (
              <div key={k} className="flex items-center gap-2 text-[11px]" style={{ color: 'var(--text-2)' }}>
                <span className="h-3 w-3 rounded-full shrink-0" style={{ background: v }} />
                {k}
              </div>
            ))}
          </div>
          <div className="border-t pt-2" style={{ borderColor: 'var(--border)' }}>
            <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Ring style (zone)</p>
            <div className="space-y-1 text-[11px]" style={{ color: 'var(--text-2)' }}>
              <div className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full shrink-0 border" style={{ borderColor: '#94a3b8' }} /> Internal
              </div>
              <div className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full shrink-0 border-2" style={{ borderColor: '#fb923c' }} /> DMZ / exposed
              </div>
              <div className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full shrink-0" style={{ background: '#94a3b8' }} /> External IP
              </div>
              <div className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full shrink-0" style={{ background: '#e879f9' }} /> IOC match
              </div>
            </div>
          </div>
          <div className="border-t pt-2" style={{ borderColor: 'var(--border)' }}>
            <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Edge color</p>
            <div className="space-y-1 text-[11px]" style={{ color: 'var(--text-2)' }}>
              <div className="flex items-center gap-2">
                <span className="h-0.5 w-6 shrink-0 rounded" style={{ background: 'rgba(99,179,237,0.5)' }} /> Internal (agent↔agent)
              </div>
              <div className="flex items-center gap-2">
                <span className="h-0.5 w-6 shrink-0 rounded" style={{ background: 'rgba(148,163,184,0.3)' }} /> External (agent→internet)
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── main page ────────────────────────────────────────────────────────────────

export default function NetworkMapPage() {
  const graphRef = useRef<any>(null);
  const [graph, setGraph]           = useState<NetworkMapGraph | null>(null);
  const [loading, setLoading]       = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [sinceMinutes, setSinceMinutes] = useState(60);
  const [zoneFilter, setZoneFilter] = useState('all');
  const [search, setSearch]         = useState('');
  const [selected, setSelected]     = useState<NetworkMapNode | null>(null);
  const [zoneColors, setZoneColors] = useState<Record<string, string>>({});
  const [showOffline, setShowOffline] = useState(true);

  useEffect(() => { setZoneColors(resolveThemeColors()); }, []);

  const load = useCallback(async (minutes: number, spin = false) => {
    if (spin) setRefreshing(true);
    setLoading(true);
    try {
      const r = await networkMapAPI.get(minutes);
      setGraph(r.data);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { load(sinceMinutes); }, [load, sinceMinutes]);

  const filteredNodeIds = useMemo(() => {
    if (!graph) return new Set<string>();
    const q = search.trim().toLowerCase();
    const ids = new Set<string>();
    for (const n of graph.nodes) {
      if (zoneFilter !== 'all' && n.zone !== zoneFilter) continue;
      if (!showOffline && n.type === 'agent' && n.status === 'offline') continue;
      if (q) {
        const haystack = `${n.hostname || ''} ${n.ip || ''}`.toLowerCase();
        if (!haystack.includes(q)) continue;
      }
      ids.add(n.id);
    }
    return ids;
  }, [graph, zoneFilter, search, showOffline]);

  const data = useMemo(() => {
    if (!graph) return { nodes: [], links: [] };
    const nodes: GNode[] = graph.nodes
      .filter(n => filteredNodeIds.has(n.id))
      .map(n => ({ ...n, val: n.type === 'agent' ? 6 + n.risk_score / 20 : 4 }));
    const nodeIdSet = new Set(nodes.map(n => n.id));
    const links = graph.edges
      .filter(e => nodeIdSet.has(e.source) && nodeIdSet.has(e.target))
      .map(e => ({ ...e }));
    return { nodes, links };
  }, [graph, filteredNodeIds]);

  const edgesForSelected = useMemo(() => {
    if (!graph || !selected) return [];
    return graph.edges.filter(e => e.source === selected.id || e.target === selected.id);
  }, [graph, selected]);

  const nodeColor = (n: any): string => {
    if (n.type === 'external_ip') {
      if (n.is_ioc) return IOC_FILL[n.ioc_severity] || IOC_FILL.unknown;
      return '#64748b';
    }
    const fill = RISK_FILL[n.risk_level] || RISK_FILL.unknown;
    if (n.status === 'offline') {
      // desaturate offline agents by blending toward grey
      return fill + '88';
    }
    return fill;
  };

  const linkColor = (l: any): string =>
    l.edge_type === 'internal' ? 'rgba(99,179,237,0.4)' : 'rgba(148,163,184,0.25)';

  const drawNode = (n: any, ctx: CanvasRenderingContext2D) => {
    const ring = zoneColors[n.zone] || '#64748b';
    const r = (n.val || 4) + 2;
    // zone ring
    ctx.beginPath();
    ctx.arc(n.x, n.y, r, 0, 2 * Math.PI, false);
    ctx.strokeStyle = n.status === 'offline' ? ring + '55' : ring;
    ctx.lineWidth = n.zone === 'dmz' ? 2.5 : 1.25;
    ctx.stroke();
    // alert indicator — small red dot at top-right
    if (n.alert_count > 0) {
      ctx.beginPath();
      ctx.arc(n.x + r * 0.7, n.y - r * 0.7, 3, 0, 2 * Math.PI);
      ctx.fillStyle = '#f85149';
      ctx.fill();
    }
    // IOC indicator — magenta diamond-ish spike
    if (n.is_ioc) {
      ctx.beginPath();
      ctx.arc(n.x - r * 0.7, n.y - r * 0.7, 3, 0, 2 * Math.PI);
      ctx.fillStyle = '#e879f9';
      ctx.fill();
    }
    // label: hostname for agents, truncated IP for externals
    if (n.type === 'agent' || n.is_ioc) {
      const label = n.hostname
        ? (n.hostname.length > 14 ? n.hostname.slice(0, 12) + '…' : n.hostname)
        : (n.ip || n.id);
      const fontSize = 3.5;
      ctx.font = `${fontSize}px sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillStyle = n.status === 'offline' ? 'rgba(148,163,184,0.5)' : 'rgba(226,232,240,0.9)';
      ctx.fillText(label, n.x, n.y + r + 1.5);
    }
  };

  const s = graph?.summary;

  return (
    <RootLayout title="Network Map" subtitle="Fleet-wide outbound connections, zoned and colored by asset risk"
      onRefresh={() => load(sinceMinutes, true)} refreshing={refreshing}>

      <div className="space-y-4">

        {/* ── toolbar ──────────────────────────────────────────── */}
        <div className="g-panel p-3 flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1">
            {TIME_WINDOWS.map(w => (
              <button key={w.minutes} onClick={() => setSinceMinutes(w.minutes)}
                className="px-2.5 py-1 rounded-lg text-xs font-medium transition-all"
                style={{
                  background: sinceMinutes === w.minutes ? 'var(--accent-glow)' : 'transparent',
                  border: `1px solid ${sinceMinutes === w.minutes ? 'var(--accent-border)' : 'var(--border)'}`,
                  color: sinceMinutes === w.minutes ? 'var(--text-1)' : 'var(--text-3)',
                }}>
                {w.label}
              </button>
            ))}
          </div>

          <select value={zoneFilter} onChange={e => setZoneFilter(e.target.value)}
            className="g-select" style={{ minWidth: 130 }}>
            <option value="all">All zones</option>
            <option value="internal">Internal</option>
            <option value="dmz">DMZ (exposed)</option>
            <option value="external">External</option>
          </select>

          <div className="relative flex-1 min-w-[180px] max-w-xs">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search hostname or IP…" className="g-input pl-8 text-xs" />
          </div>

          <button onClick={() => setShowOffline(o => !o)}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs transition-all"
            style={{
              background: showOffline ? 'var(--glass-bg)' : 'var(--accent-glow)',
              border: `1px solid ${showOffline ? 'var(--border)' : 'var(--accent-border)'}`,
              color: showOffline ? 'var(--text-2)' : 'var(--accent)',
            }}>
            {showOffline ? <Wifi className="h-3.5 w-3.5" /> : <WifiOff className="h-3.5 w-3.5" />}
            {showOffline ? 'All' : 'Online only'}
          </button>

          <button
            onClick={() => graphRef.current?.zoomToFit(400, 40)}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs"
            style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
            <ZoomIn className="h-3.5 w-3.5" /> Fit
          </button>

          <Legend />
        </div>

        {/* ── summary stats bar ───────────────────────────────────── */}
        {s && (
          <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
            {[
              { label: 'Agents',    val: s.total_agents,   sub: `${s.online_agents} online` },
              { label: 'External',  val: s.external_ips,   sub: 'unique IPs' },
              { label: 'Edges',     val: s.total_edges,    sub: 'connections' },
              { label: 'IOC Hits',  val: s.ioc_hits,       sub: 'known bad IPs',  warn: s.ioc_hits > 0 },
              { label: 'Alerting',  val: s.alerting_nodes, sub: 'agents w/ alerts', warn: s.alerting_nodes > 0 },
              { label: 'Visible',   val: data.nodes.length, sub: 'in filter' },
            ].map(({ label, val, sub, warn }) => (
              <div key={label} className="g-card p-3">
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{label}</p>
                <p className="text-lg font-semibold tabular-nums"
                  style={{ color: warn ? 'var(--red)' : 'var(--text-1)' }}>{val}</p>
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{sub}</p>
              </div>
            ))}
          </div>
        )}

        {/* ── IOC warning banner ──────────────────────────────────── */}
        {s && s.ioc_hits > 0 && (
          <div className="g-panel flex items-center gap-3 px-4 py-3"
            style={{ border: '1px solid var(--red-border)', background: 'var(--red-bg)' }}>
            <AlertTriangle className="h-4 w-4 shrink-0" style={{ color: 'var(--red)' }} />
            <p className="text-xs" style={{ color: 'var(--text-1)' }}>
              <strong>{s.ioc_hits}</strong> external IP{s.ioc_hits !== 1 ? 's' : ''} in this window match known IOC indicators.
              Nodes shown in <span style={{ color: '#e879f9' }}>magenta</span>.
            </p>
          </div>
        )}

        {/* ── graph canvas ────────────────────────────────────────── */}
        {loading ? (
          <div className="py-14 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
        ) : !graph || graph.nodes.length === 0 ? (
          <div className="g-panel py-14 text-center">
            <Network className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>
              No agents registered yet. Install the xcloak-agent on at least one host to see the network map.
            </p>
          </div>
        ) : (
          <div className="g-panel overflow-hidden" style={{ height: 580 }}>
            <ForceGraph2D
              ref={graphRef}
              graphData={data}
              nodeId="id"
              nodeVal="val"
              nodeLabel={(n: any) => {
                const parts = [n.hostname || n.ip || n.id];
                if (n.type === 'agent') parts.push(`risk: ${n.risk_level} (${n.risk_score})`);
                if (n.alert_count > 0) parts.push(`⚠ ${n.alert_count} alert${n.alert_count !== 1 ? 's' : ''}`);
                if (n.is_ioc) parts.push(`🚨 IOC match (${n.ioc_severity})`);
                if (n.country) parts.push(n.country);
                if (n.status) parts.push(n.status);
                return parts.join('\n');
              }}
              nodeColor={nodeColor}
              linkColor={linkColor}
              linkWidth={(l: any) => Math.min(4, 1 + Math.log2(1 + (l.count || 1)))}
              linkDirectionalParticles={(l: any) => l.edge_type === 'internal' ? 2 : 1}
              linkDirectionalParticleWidth={1.5}
              linkDirectionalParticleColor={linkColor}
              onNodeClick={(n: any) => setSelected(n)}
              nodeCanvasObjectMode={() => 'after'}
              nodeCanvasObject={drawNode}
              cooldownTicks={120}
              backgroundColor="transparent"
            />
          </div>
        )}
      </div>

      {/* ── node detail drawer ──────────────────────────────────── */}
      {selected && (
        <div className="fixed inset-0 z-50 flex">
          <div className="flex-1" onClick={() => setSelected(null)} />

          <div className="w-full max-w-md h-full overflow-y-auto shadow-2xl"
            style={{ background: 'var(--bg-1)', borderLeft: '1px solid var(--border)' }}>

            <div className="sticky top-0 flex items-center gap-3 px-5 py-4"
              style={{ background: 'var(--bg-1)', borderBottom: '1px solid var(--border)', zIndex: 10 }}>
              {selected.type === 'agent'
                ? <Cpu className="h-4 w-4 shrink-0" style={{ color: 'var(--text-2)' }} />
                : <Globe className="h-4 w-4 shrink-0" style={{ color: 'var(--text-2)' }} />}
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold truncate" style={{ color: 'var(--text-1)' }}>
                  {selected.hostname || selected.ip || selected.id}
                </p>
                <div className="flex items-center gap-2 mt-0.5">
                  {selected.type === 'agent' && (
                    <span className="text-[10px]" style={{ color: selected.status === 'online' ? 'var(--green)' : 'var(--text-3)' }}>
                      ● {selected.status || 'unknown'}
                    </span>
                  )}
                  {selected.is_ioc && (
                    <span className="text-[10px] font-semibold" style={{ color: '#e879f9' }}>IOC</span>
                  )}
                  {selected.alert_count > 0 && (
                    <span className="flex items-center gap-1 text-[10px]" style={{ color: 'var(--red)' }}>
                      <AlertTriangle className="h-3 w-3" /> {selected.alert_count} alert{selected.alert_count !== 1 ? 's' : ''}
                    </span>
                  )}
                </div>
              </div>
              <button onClick={() => setSelected(null)} style={{ color: 'var(--text-3)' }}>
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="p-5 space-y-4">
              {/* meta grid */}
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: 'Type',    val: selected.type === 'agent' ? 'Agent' : 'External IP' },
                  { label: 'Zone',    val: selected.zone },
                  { label: 'IP',      val: selected.ip || '—' },
                  { label: 'Country', val: selected.country || '—' },
                  ...(selected.type === 'agent' ? [
                    { label: 'Risk score', val: `${selected.risk_score}` },
                  ] : []),
                  ...(selected.is_ioc ? [
                    { label: 'IOC severity', val: selected.ioc_severity || 'unknown' },
                  ] : []),
                ].map(({ label, val }) => (
                  <div key={label} className="rounded-xl p-3"
                    style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <p className="text-[10px] mb-0.5" style={{ color: 'var(--text-3)' }}>{label}</p>
                    <p className="text-xs mono font-medium truncate" style={{ color: 'var(--text-1)' }}>{val}</p>
                  </div>
                ))}
              </div>

              {/* risk / zone badges */}
              {selected.type === 'agent' && (
                <div className="flex flex-wrap items-center gap-2">
                  <span className={sevClass(selected.risk_level)}>{selected.risk_level} risk</span>
                  {selected.zone === 'dmz' && (
                    <span className="flex items-center gap-1 text-xs" style={{ color: 'var(--orange)' }}>
                      <ShieldAlert className="h-3.5 w-3.5" /> internet-exposed
                    </span>
                  )}
                  {selected.agent_id && (
                    <Link href={`/agents/${selected.agent_id}`}
                      className="text-xs underline" style={{ color: 'var(--accent)' }}>
                      View agent →
                    </Link>
                  )}
                </div>
              )}

              {/* connections list */}
              <div>
                <p className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>
                  Connections ({edgesForSelected.length})
                </p>
                <div className="space-y-1.5">
                  {edgesForSelected.length === 0 ? (
                    <p className="text-xs" style={{ color: 'var(--text-3)' }}>No edges in the current filter.</p>
                  ) : edgesForSelected.map((e: NetworkMapEdge, i: number) => {
                    const portLabel = e.service ? `${e.port}/${e.service}` : e.port;
                    const dir = e.source === selected.id ? '→' : '←';
                    return (
                      <div key={i} className="rounded-lg p-2.5 text-xs"
                        style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                        <div className="flex items-center justify-between gap-2">
                          <span className="mono truncate" style={{ color: 'var(--text-1)' }}>
                            <span style={{ color: e.edge_type === 'internal' ? 'var(--blue)' : 'var(--text-3)' }}>{dir}</span>
                            {' '}{e.process || 'unknown'}
                          </span>
                          <div className="flex items-center gap-2 shrink-0">
                            <span className="rounded px-1.5 py-0.5 mono"
                              style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                              {portLabel}/{e.protocol.toUpperCase()}
                            </span>
                            <span style={{ color: 'var(--text-3)' }}>×{e.count}</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 mt-1">
                          <span className="text-[10px] rounded px-1 py-0.5"
                            style={{ background: e.edge_type === 'internal' ? 'rgba(99,179,237,0.15)' : 'var(--glass-bg)', color: 'var(--text-3)' }}>
                            {e.edge_type}
                          </span>
                          <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                            last {new Date(e.last_seen).toLocaleString()}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
