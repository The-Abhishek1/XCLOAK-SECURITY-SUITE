'use client';

import { useEffect, useMemo, useState, useCallback } from 'react';
import dynamic from 'next/dynamic';
import { RootLayout } from '@/components/layout/RootLayout';
import { networkMapAPI } from '@/lib/api';
import { NetworkMapGraph, NetworkMapNode, NetworkMapEdge } from '@/types';
import { sevClass, formatDate } from '@/lib/utils';
import { Network, Search, X, Globe, Cpu, ShieldAlert } from 'lucide-react';

// react-force-graph-2d touches `window` at import time — must be loaded
// client-side only or the Next.js build fails on the page's SSR pass.
const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), { ssr: false });

const RISK_FILL: Record<string, string> = {
  critical: '#f85149',
  high:     '#fb923c',
  medium:   '#fbbf24',
  low:      '#38bdf8',
  unknown:  '#64748b',
};

// Canvas strokeStyle can't resolve CSS custom properties the way SVG/DOM
// styles can (unlike attack-path's SVG renderer, which uses var(--x)
// directly) — these get resolved to literal colors at runtime via
// resolveThemeColors() instead.
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

const TIME_WINDOWS = [
  { label: '15m', minutes: 15 },
  { label: '1h',  minutes: 60 },
  { label: '6h',  minutes: 360 },
  { label: '24h', minutes: 1440 },
];

interface GNode extends NetworkMapNode {
  val: number;
}

export default function NetworkMapPage() {
  const [graph, setGraph]         = useState<NetworkMapGraph | null>(null);
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [sinceMinutes, setSinceMinutes] = useState(60);
  const [zoneFilter, setZoneFilter] = useState('all');
  const [search, setSearch]       = useState('');
  const [selected, setSelected]   = useState<NetworkMapNode | null>(null);
  const [zoneColors, setZoneColors] = useState<Record<string, string>>({});

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
      if (q) {
        const haystack = `${n.hostname || ''} ${n.ip || ''}`.toLowerCase();
        if (!haystack.includes(q)) continue;
      }
      ids.add(n.id);
    }
    return ids;
  }, [graph, zoneFilter, search]);

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

  const externalCount = graph ? graph.nodes.filter(n => n.type === 'external_ip').length : 0;
  const dmzCount = graph ? graph.nodes.filter(n => n.zone === 'dmz').length : 0;

  return (
    <RootLayout title="Network Map" subtitle="Fleet-wide outbound connections, zoned and colored by asset risk"
      onRefresh={() => load(sinceMinutes, true)} refreshing={refreshing}>

      <div className="space-y-4">
        <div className="g-panel p-3 flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1.5">
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

          <select value={zoneFilter} onChange={e => setZoneFilter(e.target.value)} className="g-select" style={{ minWidth: 130 }}>
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

          <div className="ml-auto flex items-center gap-3 text-[11px]" style={{ color: 'var(--text-3)' }}>
            <span>{data.nodes.length} nodes</span>
            <span>{data.links.length} edges</span>
            {dmzCount > 0 && <span style={{ color: 'var(--orange)' }}>{dmzCount} exposed</span>}
            <span>{externalCount} external</span>
          </div>
        </div>

        {loading ? (
          <div className="py-14 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
        ) : !graph || graph.nodes.length === 0 ? (
          <div className="g-panel py-14 text-center">
            <Network className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>
              No connections observed in this window — widen the time range or check that agents have the eBPF
              connect-event collector running.
            </p>
          </div>
        ) : (
          <div className="g-panel overflow-hidden" style={{ height: 560 }}>
            <ForceGraph2D
              graphData={data}
              nodeId="id"
              nodeVal="val"
              nodeLabel={(n: any) => n.hostname || n.ip || n.id}
              nodeColor={(n: any) => n.type === 'agent' ? (RISK_FILL[n.risk_level] || RISK_FILL.unknown) : '#94a3b8'}
              linkColor={() => 'rgba(148,163,184,0.25)'}
              linkWidth={(l: any) => Math.min(4, 1 + Math.log2(1 + (l.count || 1)))}
              linkDirectionalParticles={1}
              linkDirectionalParticleWidth={1.5}
              onNodeClick={(n: any) => setSelected(n)}
              nodeCanvasObjectMode={() => 'after'}
              nodeCanvasObject={(n: any, ctx: CanvasRenderingContext2D) => {
                const ring = zoneColors[n.zone] || zoneColors.internal || '#64748b';
                ctx.beginPath();
                ctx.arc(n.x, n.y, (n.val || 4) + 2, 0, 2 * Math.PI, false);
                ctx.strokeStyle = ring;
                ctx.lineWidth = n.zone === 'dmz' ? 2.5 : 1.25;
                ctx.stroke();
              }}
              cooldownTicks={100}
              backgroundColor="transparent"
            />
          </div>
        )}
      </div>

      {/* ── Node detail drawer ──────────────────────────────── */}
      {selected && (
        <div className="fixed inset-0 z-50 flex">
          <div className="flex-1" onClick={() => setSelected(null)} />

          <div className="w-full max-w-md h-full overflow-y-auto shadow-2xl"
            style={{ background: 'var(--bg-1)', borderLeft: '1px solid var(--border)' }}>

            <div className="sticky top-0 flex items-center gap-3 px-5 py-4"
              style={{ background: 'var(--bg-1)', borderBottom: '1px solid var(--border)', zIndex: 10 }}>
              {selected.type === 'agent' ? <Cpu className="h-4 w-4" style={{ color: 'var(--text-2)' }} /> : <Globe className="h-4 w-4" style={{ color: 'var(--text-2)' }} />}
              <p className="flex-1 text-sm font-semibold truncate" style={{ color: 'var(--text-1)' }}>
                {selected.hostname || selected.ip || selected.id}
              </p>
              <button onClick={() => setSelected(null)} style={{ color: 'var(--text-3)' }}>
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="p-5 space-y-4">
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: 'Type', val: selected.type === 'agent' ? 'Agent' : 'External IP' },
                  { label: 'Zone', val: selected.zone },
                  { label: 'IP', val: selected.ip || '—' },
                  { label: 'Country', val: selected.country || '—' },
                ].map(({ label, val }) => (
                  <div key={label} className="rounded-xl p-3"
                    style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <p className="text-[10px] mb-0.5" style={{ color: 'var(--text-3)' }}>{label}</p>
                    <p className="text-xs mono font-medium truncate" style={{ color: 'var(--text-1)' }}>{val}</p>
                  </div>
                ))}
              </div>

              {selected.type === 'agent' && (
                <div className="flex items-center gap-2">
                  <span className={sevClass(selected.risk_level)}>{selected.risk_level} risk</span>
                  <span className="text-xs" style={{ color: 'var(--text-3)' }}>score {selected.risk_score}</span>
                  {selected.zone === 'dmz' && (
                    <span className="flex items-center gap-1 text-xs" style={{ color: 'var(--orange)' }}>
                      <ShieldAlert className="h-3.5 w-3.5" /> internet-exposed
                    </span>
                  )}
                </div>
              )}

              <div>
                <p className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>
                  Connections ({edgesForSelected.length})
                </p>
                <div className="space-y-1.5">
                  {edgesForSelected.map((e: NetworkMapEdge, i: number) => (
                    <div key={i} className="rounded-lg p-2.5 text-xs"
                      style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                      <div className="flex items-center justify-between">
                        <span className="mono" style={{ color: 'var(--text-1)' }}>
                          {e.source === selected.id ? '→' : '←'} {e.process || 'unknown'}:{e.port}/{e.protocol}
                        </span>
                        <span style={{ color: 'var(--text-3)' }}>×{e.count}</span>
                      </div>
                      <p className="mt-1" style={{ color: 'var(--text-3)' }}>last seen {formatDate(e.last_seen)}</p>
                    </div>
                  ))}
                  {edgesForSelected.length === 0 && (
                    <p className="text-xs" style={{ color: 'var(--text-3)' }}>No edges in the current filter.</p>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
