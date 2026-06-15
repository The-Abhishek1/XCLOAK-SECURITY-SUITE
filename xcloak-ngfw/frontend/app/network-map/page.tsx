'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { agentsAPI } from '@/lib/api';
import { Agent } from '@/types';
import { Network, Eye, EyeOff, Cpu, ZoomIn, ZoomOut, RefreshCw } from 'lucide-react';

interface Connection {
  id: number;
  agent_id: number;
  protocol: string;
  local_address: string;
  remote_address: string;
  state: string;
}

interface GraphNode {
  id: string;
  type: 'agent' | 'external' | 'local';
  label: string;
  agentId?: number;
  status?: string;
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  fx?: number | null;
  fy?: number | null;
}

interface GraphLink {
  source: string;
  target: string;
  protocol: string;
  state: string;
  count: number;
}

const STATE_COLOR: Record<string, string> = {
  ESTABLISHED: '#34d399',
  LISTEN:      '#38bdf8',
  TIME_WAIT:   '#fbbf24',
  CLOSE_WAIT:  '#fb923c',
  default:     '#64748b',
};

export default function NetworkMapPage() {
  const canvasRef              = useRef<HTMLCanvasElement>(null);
  const animRef                = useRef<number>(0);
  const nodesRef               = useRef<GraphNode[]>([]);
  const linksRef               = useRef<GraphLink[]>([]);
  const dragRef                = useRef<{ node: GraphNode | null; offsetX: number; offsetY: number }>({ node: null, offsetX: 0, offsetY: 0 });
  const transformRef           = useRef({ x: 0, y: 0, scale: 1 });
  const panRef                 = useRef<{ dragging: boolean; startX: number; startY: number; tx: number; ty: number }>({ dragging: false, startX: 0, startY: 0, tx: 0, ty: 0 });

  const [agents, setAgents]           = useState<Agent[]>([]);
  const [loading, setLoading]         = useState(true);
  const [showExternal, setShowExternal] = useState(true);
  const [showListening, setShowListening] = useState(true);
  const [selected, setSelected]       = useState<GraphNode | null>(null);
  const [nodeLinks, setNodeLinks]     = useState<GraphLink[]>([]);
  const [refreshing, setRefreshing]   = useState(false);

  const buildGraph = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    setLoading(true);

    const agRes = await agentsAPI.getAll();
    const agentList: Agent[] = agRes.data || [];
    setAgents(agentList);

    const nodes: Map<string, GraphNode> = new Map();
    const linkMap: Map<string, GraphLink> = new Map();

    // Add agent nodes
    agentList.forEach(a => {
      nodes.set(`agent-${a.id}`, {
        id: `agent-${a.id}`,
        type: 'agent',
        label: a.hostname,
        agentId: a.id,
        status: a.status,
        x: Math.random() * 600 + 100,
        y: Math.random() * 400 + 100,
        vx: 0, vy: 0,
      });
    });

    // Fetch connections for each agent
    await Promise.allSettled(agentList.map(async a => {
      try {
        const r = await agentsAPI.getConnections(a.id);
        const conns: Connection[] = r.data || [];

        conns.forEach(c => {
          if (!showListening && c.state === 'LISTEN') return;

          const remoteIP = c.remote_address?.split(':')[0] || c.remote_address;
          const localIP  = c.local_address?.split(':')[0] || c.local_address;

          // Determine if remote is another agent
          const remoteAgent = agentList.find(ag => ag.ip_address === remoteIP);
          let targetId: string;

          if (remoteAgent) {
            targetId = `agent-${remoteAgent.id}`;
          } else if (c.state === 'LISTEN' || remoteIP === '0.0.0.0' || remoteIP === '::' || remoteIP === '127.0.0.1') {
            targetId = `local-${a.id}-${c.local_address}`;
            if (!nodes.has(targetId)) {
              nodes.set(targetId, {
                id: targetId, type: 'local',
                label: c.local_address,
                x: (nodes.get(`agent-${a.id}`)?.x || 300) + (Math.random() - 0.5) * 100,
                y: (nodes.get(`agent-${a.id}`)?.y || 300) + (Math.random() - 0.5) * 100,
                vx: 0, vy: 0,
              });
            }
          } else {
            if (!showExternal) return;
            targetId = `ext-${remoteIP}`;
            if (!nodes.has(targetId)) {
              nodes.set(targetId, {
                id: targetId, type: 'external',
                label: remoteIP,
                x: Math.random() * 800 + 50,
                y: Math.random() * 600 + 50,
                vx: 0, vy: 0,
              });
            }
          }

          const linkKey = `${`agent-${a.id}`}-${targetId}-${c.protocol}`;
          const existing = linkMap.get(linkKey);
          if (existing) {
            existing.count++;
          } else {
            linkMap.set(linkKey, {
              source: `agent-${a.id}`,
              target: targetId,
              protocol: c.protocol,
              state: c.state,
              count: 1,
            });
          }
        });
      } catch {}
    }));

    nodesRef.current = [...nodes.values()];
    linksRef.current = [...linkMap.values()];
    setLoading(false);
    setRefreshing(false);
  }, [showExternal, showListening]);

  useEffect(() => {
    buildGraph();
  }, [showExternal, showListening]);

  // Force simulation
  useEffect(() => {
    if (loading) return;

    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d')!;

    const W = canvas.parentElement?.clientWidth || 900;
    const H = canvas.parentElement?.clientHeight || 600;
    canvas.width  = W;
    canvas.height = H;

    const REPULSION  = 8000;
    const ATTRACTION = 0.05;
    const DAMPING    = 0.88;
    const CENTER_X   = W / 2;
    const CENTER_Y   = H / 2;

    // Init positions for new nodes
    nodesRef.current.forEach(n => {
      if (!n.x) n.x = Math.random() * W;
      if (!n.y) n.y = Math.random() * H;
      if (!n.vx) n.vx = 0;
      if (!n.vy) n.vy = 0;
    });

    function tick() {
      const nodes = nodesRef.current;
      const links = linksRef.current;

      // Repulsion between all nodes
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = (nodes[j].x || 0) - (nodes[i].x || 0);
          const dy = (nodes[j].y || 0) - (nodes[i].y || 0);
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const force = REPULSION / (dist * dist);
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;
          nodes[i].vx = (nodes[i].vx || 0) - fx;
          nodes[i].vy = (nodes[i].vy || 0) - fy;
          nodes[j].vx = (nodes[j].vx || 0) + fx;
          nodes[j].vy = (nodes[j].vy || 0) + fy;
        }
      }

      // Attraction along links
      links.forEach(link => {
        const s = nodes.find(n => n.id === link.source);
        const t = nodes.find(n => n.id === (typeof link.target === 'string' ? link.target : (link.target as any).id));
        if (!s || !t) return;
        const dx = (t.x || 0) - (s.x || 0);
        const dy = (t.y || 0) - (s.y || 0);
        s.vx = (s.vx || 0) + dx * ATTRACTION;
        s.vy = (s.vy || 0) + dy * ATTRACTION;
        t.vx = (t.vx || 0) - dx * ATTRACTION;
        t.vy = (t.vy || 0) - dy * ATTRACTION;
      });

      // Center gravity
      nodes.forEach(n => {
        n.vx = (n.vx || 0) + (CENTER_X - (n.x || CENTER_X)) * 0.005;
        n.vy = (n.vy || 0) + (CENTER_Y - (n.y || CENTER_Y)) * 0.005;
        n.vx = (n.vx || 0) * DAMPING;
        n.vy = (n.vy || 0) * DAMPING;
        if (n.fx != null) n.x = n.fx;
        else n.x = (n.x || 0) + (n.vx || 0);
        if (n.fy != null) n.y = n.fy;
        else n.y = (n.y || 0) + (n.vy || 0);
      });

      // Draw
      ctx.clearRect(0, 0, W, H);
      ctx.save();
      const t = transformRef.current;
      ctx.translate(t.x, t.y);
      ctx.scale(t.scale, t.scale);

      // Draw links
      links.forEach(link => {
        const s = nodes.find(n => n.id === link.source);
        const tNode = nodes.find(n => n.id === (typeof link.target === 'string' ? link.target : (link.target as any).id));
        if (!s || !tNode) return;

        ctx.beginPath();
        ctx.moveTo(s.x || 0, s.y || 0);
        ctx.lineTo(tNode.x || 0, tNode.y || 0);
        ctx.strokeStyle = STATE_COLOR[link.state] || STATE_COLOR.default;
        ctx.globalAlpha = 0.35;
        ctx.lineWidth = Math.min(link.count * 0.4 + 0.5, 3);
        ctx.stroke();
        ctx.globalAlpha = 1;
      });

      // Draw nodes
      nodes.forEach(n => {
        const x = n.x || 0;
        const y = n.y || 0;
        const r = n.type === 'agent' ? 18 : n.type === 'local' ? 8 : 10;

        ctx.beginPath();
        ctx.arc(x, y, r, 0, Math.PI * 2);

        if (n.type === 'agent') {
          ctx.fillStyle = n.status === 'online' ? '#34d39922' : '#f8514922';
          ctx.fill();
          ctx.strokeStyle = n.status === 'online' ? '#34d399' : '#f85149';
          ctx.lineWidth = 2;
          ctx.stroke();
          // Label
          ctx.fillStyle = '#e2e8f0';
          ctx.font = 'bold 10px monospace';
          ctx.textAlign = 'center';
          ctx.fillText(n.label.slice(0, 12), x, y + r + 13);
        } else if (n.type === 'local') {
          ctx.fillStyle = '#38bdf822';
          ctx.fill();
          ctx.strokeStyle = '#38bdf8';
          ctx.lineWidth = 1;
          ctx.stroke();
        } else {
          ctx.fillStyle = '#fbbf2422';
          ctx.fill();
          ctx.strokeStyle = '#fbbf24';
          ctx.lineWidth = 1;
          ctx.stroke();
          ctx.fillStyle = '#94a3b8';
          ctx.font = '9px monospace';
          ctx.textAlign = 'center';
          ctx.fillText(n.label.slice(0, 15), x, y + r + 12);
        }
      });

      ctx.restore();
      animRef.current = requestAnimationFrame(tick);
    }

    animRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(animRef.current);
  }, [loading]);

  // Mouse events
  const screenToWorld = (sx: number, sy: number) => {
    const t = transformRef.current;
    return { x: (sx - t.x) / t.scale, y: (sy - t.y) / t.scale };
  };

  const findNodeAt = (wx: number, wy: number) => {
    return nodesRef.current.find(n => {
      const r = n.type === 'agent' ? 18 : 10;
      const dx = (n.x || 0) - wx;
      const dy = (n.y || 0) - wy;
      return dx * dx + dy * dy <= r * r;
    }) || null;
  };

  const onMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current!.getBoundingClientRect();
    const sx = e.clientX - rect.left;
    const sy = e.clientY - rect.top;
    const { x: wx, y: wy } = screenToWorld(sx, sy);
    const node = findNodeAt(wx, wy);

    if (node) {
      dragRef.current = { node, offsetX: wx - (node.x || 0), offsetY: wy - (node.y || 0) };
      node.fx = node.x;
      node.fy = node.y;
      setSelected(node);
      setNodeLinks(linksRef.current.filter(l => l.source === node.id || l.target === node.id));
    } else {
      panRef.current = { dragging: true, startX: sx, startY: sy, tx: transformRef.current.x, ty: transformRef.current.y };
    }
  };

  const onMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current!.getBoundingClientRect();
    const sx = e.clientX - rect.left;
    const sy = e.clientY - rect.top;
    const { x: wx, y: wy } = screenToWorld(sx, sy);

    if (dragRef.current.node) {
      dragRef.current.node.fx = wx - dragRef.current.offsetX;
      dragRef.current.node.fy = wy - dragRef.current.offsetY;
    } else if (panRef.current.dragging) {
      transformRef.current.x = panRef.current.tx + (sx - panRef.current.startX);
      transformRef.current.y = panRef.current.ty + (sy - panRef.current.startY);
    }
  };

  const onMouseUp = () => {
    if (dragRef.current.node) {
      dragRef.current.node.fx = null;
      dragRef.current.node.fy = null;
      dragRef.current.node = null;
    }
    panRef.current.dragging = false;
  };

  const onWheel = (e: React.WheelEvent<HTMLCanvasElement>) => {
    e.preventDefault();
    const factor = e.deltaY > 0 ? 0.9 : 1.1;
    transformRef.current.scale = Math.min(Math.max(transformRef.current.scale * factor, 0.2), 5);
  };

  const totalConns = linksRef.current.length;
  const established = linksRef.current.filter(l => l.state === 'ESTABLISHED').length;

  return (
    <RootLayout title="Network Map" subtitle="Live agent connection topology"
      onRefresh={() => buildGraph(true)} refreshing={refreshing}
      actions={
        <div className="flex items-center gap-2">
          <button onClick={() => setShowExternal(p => !p)}
            className={`g-btn text-xs ${showExternal ? 'g-btn-primary' : 'g-btn-ghost'}`}>
            {showExternal ? <Eye className="h-3.5 w-3.5" /> : <EyeOff className="h-3.5 w-3.5" />}
            External
          </button>
          <button onClick={() => setShowListening(p => !p)}
            className={`g-btn text-xs ${showListening ? 'g-btn-primary' : 'g-btn-ghost'}`}>
            {showListening ? <Eye className="h-3.5 w-3.5" /> : <EyeOff className="h-3.5 w-3.5" />}
            Listening
          </button>
        </div>
      }>

      <div className="flex gap-4" style={{ height: 'calc(100vh - 140px)' }}>
        {/* Canvas */}
        <div className="flex-1 rounded-2xl overflow-hidden relative"
          style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
          {loading ? (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <Network className="h-10 w-10 mx-auto mb-3 animate-pulse" style={{ color: 'var(--accent)' }} />
                <p className="text-sm" style={{ color: 'var(--text-3)' }}>Building network topology…</p>
              </div>
            </div>
          ) : (
            <canvas ref={canvasRef} className="w-full h-full cursor-grab"
              style={{ cursor: dragRef.current.node ? 'grabbing' : 'grab' }}
              onMouseDown={onMouseDown} onMouseMove={onMouseMove}
              onMouseUp={onMouseUp} onMouseLeave={onMouseUp}
              onWheel={onWheel} />
          )}

          {/* Legend */}
          <div className="absolute bottom-3 left-3 flex items-center gap-3 text-[10px] px-3 py-2 rounded-xl"
            style={{ background: 'var(--glass-modal)', border: '1px solid var(--border)' }}>
            {[
              { color: '#34d399', label: 'Agent Online' },
              { color: '#f85149', label: 'Agent Offline' },
              { color: '#38bdf8', label: 'Listening' },
              { color: '#fbbf24', label: 'External' },
              { color: '#34d399', label: 'Established', dashed: false, line: true },
            ].map(l => (
              <div key={l.label} className="flex items-center gap-1">
                {l.line
                  ? <div className="h-0.5 w-4 rounded" style={{ background: l.color }} />
                  : <div className="h-2 w-2 rounded-full" style={{ background: l.color }} />}
                <span style={{ color: 'var(--text-3)' }}>{l.label}</span>
              </div>
            ))}
          </div>

          {/* Stats overlay */}
          <div className="absolute top-3 left-3 flex items-center gap-3 text-[10px] px-3 py-2 rounded-xl"
            style={{ background: 'var(--glass-modal)', border: '1px solid var(--border)' }}>
            <span style={{ color: 'var(--text-3)' }}>{agents.length} agents</span>
            <span style={{ color: 'var(--text-3)' }}>{nodesRef.current.length} nodes</span>
            <span style={{ color: 'var(--text-3)' }}>{totalConns} links</span>
            <span style={{ color: '#34d399' }}>{established} established</span>
          </div>

          {/* Zoom hint */}
          <div className="absolute bottom-3 right-3 text-[10px] px-2 py-1 rounded-lg"
            style={{ color: 'var(--text-3)', background: 'var(--glass-modal)' }}>
            Scroll to zoom · Drag nodes · Click to inspect
          </div>
        </div>

        {/* Detail panel */}
        <div className="w-64 shrink-0 space-y-3 overflow-y-auto">
          {selected ? (
            <>
              <div className="g-card p-4">
                <div className="flex items-center gap-2 mb-3">
                  {selected.type === 'agent'
                    ? <Cpu className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                    : <Network className="h-4 w-4" style={{ color: 'var(--accent)' }} />}
                  <p className="text-xs font-semibold truncate" style={{ color: 'var(--text-1)' }}>
                    {selected.label}
                  </p>
                </div>
                <div className="space-y-2 text-[11px]">
                  <div className="flex justify-between">
                    <span style={{ color: 'var(--text-3)' }}>Type</span>
                    <span className="capitalize" style={{ color: 'var(--text-1)' }}>{selected.type}</span>
                  </div>
                  {selected.type === 'agent' && (
                    <div className="flex justify-between">
                      <span style={{ color: 'var(--text-3)' }}>Status</span>
                      <span style={{ color: selected.status === 'online' ? 'var(--green)' : 'var(--red)' }}>
                        {selected.status}
                      </span>
                    </div>
                  )}
                  <div className="flex justify-between">
                    <span style={{ color: 'var(--text-3)' }}>Connections</span>
                    <span style={{ color: 'var(--accent)' }}>{nodeLinks.length}</span>
                  </div>
                </div>
              </div>

              {nodeLinks.length > 0 && (
                <div className="g-card">
                  <p className="text-[10px] font-semibold uppercase tracking-wider px-4 pt-3 pb-2"
                    style={{ color: 'var(--text-3)' }}>
                    Connections ({nodeLinks.length})
                  </p>
                  <div className="divide-y max-h-80 overflow-y-auto" style={{ borderColor: 'var(--border)' }}>
                    {nodeLinks.map((l, i) => {
                      const other = l.source === selected.id ? l.target : l.source;
                      const otherNode = nodesRef.current.find(n => n.id === other);
                      return (
                        <div key={i} className="px-4 py-2">
                          <p className="text-[10px] mono truncate" style={{ color: 'var(--text-1)' }}>
                            {otherNode?.label || other}
                          </p>
                          <div className="flex items-center gap-2 mt-0.5">
                            <span className="text-[9px]" style={{ color: STATE_COLOR[l.state] || 'var(--text-3)' }}>
                              {l.state}
                            </span>
                            <span className="text-[9px] mono" style={{ color: 'var(--text-3)' }}>{l.protocol}</span>
                            {l.count > 1 && <span className="text-[9px]" style={{ color: 'var(--text-3)' }}>×{l.count}</span>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="g-card p-6 text-center">
              <Network className="h-8 w-8 mx-auto mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-xs" style={{ color: 'var(--text-2)' }}>Click any node to inspect</p>
              <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                {nodesRef.current.filter(n => n.type === 'agent').length} agents ·{' '}
                {nodesRef.current.filter(n => n.type === 'external').length} external IPs
              </p>
            </div>
          )}
        </div>
      </div>
    </RootLayout>
  );
}
