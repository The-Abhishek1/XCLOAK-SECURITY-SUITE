'use client';

import { useEffect, useState, useCallback, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { attackPathAPI } from '@/lib/api';
import { AttackPathGraph, AttackPathNode } from '@/types';
import { sevClass } from '@/lib/utils';
import { Crosshair, Globe, Skull, ShieldAlert, Cpu } from 'lucide-react';

const COL_WIDTH  = 200;
const ROW_HEIGHT = 90;
const PAD        = 70;

const RISK_FILL: Record<string, string> = {
  critical: '#f85149',
  high:     '#fb923c',
  medium:   '#fbbf24',
  low:      '#38bdf8',
  unknown:  '#64748b',
};

interface Positioned extends AttackPathNode {
  x: number;
  y: number;
}

export default function AttackPathPage() {
  const [graph, setGraph]       = useState<AttackPathGraph | null>(null);
  const [loading, setLoading]   = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedPath, setSelectedPath] = useState(0);
  const [hovered, setHovered]   = useState<Positioned | null>(null);

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    setLoading(true);
    try {
      const r = await attackPathAPI.get();
      setGraph(r.data);
      setSelectedPath(0);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // ── Layout: BFS depth from "internet" assigns each node a column ────────
  const layout = useMemo(() => {
    if (!graph) return null;

    const adjacency = new Map<string, string[]>();
    const addAdj = (a: string, b: string) => {
      adjacency.set(a, [...(adjacency.get(a) || []), b]);
      adjacency.set(b, [...(adjacency.get(b) || []), a]);
    };
    graph.edges.forEach(e => addAdj(e.source, e.target));

    const depth = new Map<string, number>();
    depth.set('internet', 0);
    const queue = ['internet'];
    while (queue.length > 0) {
      const cur = queue.shift()!;
      for (const next of adjacency.get(cur) || []) {
        if (!depth.has(next)) {
          depth.set(next, (depth.get(cur) || 0) + 1);
          queue.push(next);
        }
      }
    }

    const maxDepth = Math.max(0, ...Array.from(depth.values()));
    const isolatedDepth = maxDepth + 1;

    const columns = new Map<number, AttackPathNode[]>();
    graph.nodes.forEach(n => {
      const d = depth.get(n.id) ?? isolatedDepth;
      columns.set(d, [...(columns.get(d) || []), n]);
    });

    const positioned: Positioned[] = [];
    columns.forEach((nodesInCol, col) => {
      nodesInCol.forEach((n, i) => {
        positioned.push({ ...n, x: PAD + col * COL_WIDTH, y: PAD + i * ROW_HEIGHT });
      });
    });

    const maxCol = Math.max(1, ...Array.from(columns.keys()));
    const maxRows = Math.max(1, ...Array.from(columns.values()).map(c => c.length));

    return {
      nodes: positioned,
      byId: new Map(positioned.map(n => [n.id, n])),
      width: PAD * 2 + (maxCol + 1) * COL_WIDTH,
      height: PAD * 2 + maxRows * ROW_HEIGHT,
      hasIsolated: Array.from(depth.keys()).length < graph.nodes.length,
    };
  }, [graph]);

  const highlightedEdgeKeys = useMemo(() => {
    if (!graph || !graph.top_paths[selectedPath]) return new Set<string>();
    const hops = graph.top_paths[selectedPath].hops;
    const keys = new Set<string>();
    for (let i = 0; i < hops.length - 1; i++) {
      keys.add(`${hops[i]}|${hops[i + 1]}`);
      keys.add(`${hops[i + 1]}|${hops[i]}`);
    }
    return keys;
  }, [graph, selectedPath]);

  const agentCount = graph ? graph.nodes.filter(n => n.type === 'agent').length : 0;

  return (
    <RootLayout title="Attack Paths" subtitle="How an attacker could pivot from the internet to your highest-value assets"
      onRefresh={() => load(true)} refreshing={refreshing}>

      <div className="space-y-4">
        {loading ? (
          <div className="py-14 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
        ) : !graph || agentCount === 0 ? (
          <div className="g-panel py-14 text-center">
            <Crosshair className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No agents in this tenant yet.</p>
          </div>
        ) : (
          <>
            {!graph.has_entry_point && (
              <div className="g-panel px-4 py-3 text-xs flex items-center gap-2" style={{ color: 'var(--text-2)' }}>
                <ShieldAlert className="h-4 w-4 shrink-0" style={{ color: 'var(--yellow)' }} />
                No internet-facing entry point detected in observed connections — the topology below has no ranked attack
                path yet. Run agent connection collection on internet-facing hosts to surface one.
              </div>
            )}

            <div className="flex gap-4 flex-wrap lg:flex-nowrap">
              {/* Graph */}
              <div className="g-panel flex-1 overflow-auto" style={{ minHeight: 420, maxHeight: 600 }}>
                {layout && (
                  <svg width={layout.width} height={layout.height} style={{ display: 'block' }}>
                    {graph.edges.map((e, i) => {
                      const a = layout.byId.get(e.source);
                      const b = layout.byId.get(e.target);
                      if (!a || !b) return null;
                      const highlighted = highlightedEdgeKeys.has(`${e.source}|${e.target}`);
                      return (
                        <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                          stroke={highlighted ? '#f85149' : e.kind === 'internet_exposure' ? 'var(--orange)' : 'var(--border-md)'}
                          strokeWidth={highlighted ? 2.5 : 1.25}
                          strokeOpacity={highlighted ? 1 : 0.6}
                          strokeDasharray={e.kind === 'internet_exposure' ? '4 3' : undefined}
                        />
                      );
                    })}

                    {layout.nodes.map(n => (
                      <g key={n.id} transform={`translate(${n.x},${n.y})`} style={{ cursor: 'pointer' }}
                        onMouseEnter={() => setHovered(n)} onMouseLeave={() => setHovered(null)}>
                        <circle r={n.type === 'internet' ? 18 : 16}
                          fill={n.type === 'internet' ? 'var(--bg-1)' : RISK_FILL[n.risk_level] || RISK_FILL.unknown}
                          stroke={n.exposed ? 'var(--orange)' : 'var(--border)'}
                          strokeWidth={n.exposed ? 2.5 : 1.5} />
                        {n.type === 'internet' ? (
                          <Globe x={-8} y={-8} width={16} height={16} color="var(--text-1)" />
                        ) : (
                          <Cpu x={-7} y={-7} width={14} height={14} color="#0b0f14" />
                        )}
                        {n.has_kev && (
                          <g transform="translate(11,-11)">
                            <circle r={7} fill="#f85149" />
                            <Skull x={-4.5} y={-4.5} width={9} height={9} color="#fff" />
                          </g>
                        )}
                        {n.open_alert_count > 0 && (
                          <g transform="translate(-13,-11)">
                            <circle r={6} fill="#fb923c" />
                            <text textAnchor="middle" dominantBaseline="central" fontSize={7} fill="#fff" fontWeight="bold">
                              {n.open_alert_count > 9 ? '9+' : n.open_alert_count}
                            </text>
                          </g>
                        )}
                        <text x={0} y={32} textAnchor="middle" fontSize={10.5} fill="var(--text-2)">
                          {n.type === 'internet' ? 'Internet' : (n.hostname || `agent-${n.agent_id}`)}
                        </text>
                      </g>
                    ))}
                  </svg>
                )}
              </div>

              {/* Top attack paths */}
              <div className="g-panel p-4 shrink-0" style={{ width: 320 }}>
                <p className="text-xs font-bold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>
                  Top Attack Paths
                </p>
                {graph.top_paths.length === 0 ? (
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                    No ranked paths yet — needs an internet-facing agent and at least one agent with a non-zero risk
                    score or KEV-listed vulnerability.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {graph.top_paths.map((p, i) => (
                      <button key={i} onClick={() => setSelectedPath(i)}
                        className="w-full text-left rounded-xl p-3 transition-all"
                        style={{
                          background: selectedPath === i ? 'var(--accent-glow)' : 'var(--glass-bg)',
                          border: `1px solid ${selectedPath === i ? 'var(--accent-border)' : 'var(--border)'}`,
                        }}>
                        <div className="flex items-center justify-between mb-1.5">
                          <span className="text-[10px] font-bold" style={{ color: 'var(--text-3)' }}>PATH {i + 1}</span>
                          <span className={sevClass(p.target_risk_level)} style={{ fontSize: 10 }}>{p.target_risk_level}</span>
                        </div>
                        <p className="text-xs leading-relaxed" style={{ color: 'var(--text-1)' }}>
                          {p.hops.map((h, hi) => (
                            <span key={h}>
                              {hi > 0 && <span style={{ color: 'var(--text-3)' }}> → </span>}
                              {h === 'internet' ? 'Internet' : (layout?.byId.get(h)?.hostname || h)}
                            </span>
                          ))}
                        </p>
                        <p className="text-[10px] mt-1.5" style={{ color: 'var(--text-3)' }}>
                          compromise cost {p.total_cost.toFixed(0)} · target value score {p.score.toFixed(2)}
                        </p>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {hovered && hovered.type === 'agent' && (
              <div className="g-panel p-3 text-xs flex items-center gap-4" style={{ color: 'var(--text-2)' }}>
                <span style={{ color: 'var(--text-1)' }} className="font-medium">{hovered.hostname}</span>
                <span className={sevClass(hovered.risk_level)}>{hovered.risk_level} risk</span>
                <span>EPSS {(hovered.max_epss * 100).toFixed(1)}%</span>
                {hovered.has_kev && <span style={{ color: '#f85149' }} className="font-bold">{hovered.kev_count} KEV vuln{hovered.kev_count > 1 ? 's' : ''}</span>}
                {hovered.exposed && <span style={{ color: 'var(--orange)' }}>internet-facing</span>}
                {hovered.open_alert_count > 0 && <span style={{ color: 'var(--orange)' }} className="font-semibold">{hovered.open_alert_count} open alert{hovered.open_alert_count !== 1 ? 's' : ''}</span>}
                <span>pivot cost {hovered.compromise_cost.toFixed(0)}</span>
              </div>
            )}
          </>
        )}
      </div>
    </RootLayout>
  );
}
