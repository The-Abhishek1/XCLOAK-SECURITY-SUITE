'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { RootLayout } from '@/components/layout/RootLayout';
import { agentsAPI, iocsAPI } from '@/lib/api';
import { Agent } from '@/types';
import {
  Network, Eye, EyeOff, Cpu, ZoomIn, ZoomOut, RefreshCw,
  AlertTriangle, ExternalLink, Shield, Filter, X, Search,
} from 'lucide-react';

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

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
  country?: string;
  countryCode?: string;
  isMalicious?: boolean;
  port?: string;           // for local/listening nodes
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
  port?: string;
}

// ─────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────

const STATE_COLOR: Record<string, string> = {
  ESTABLISHED: '#34d399',
  LISTEN:      '#38bdf8',
  TIME_WAIT:   '#fbbf24',
  CLOSE_WAIT:  '#fb923c',
  SYN_SENT:    '#a78bfa',
  SYN_RECV:    '#c084fc',
  default:     '#64748b',
};

// Known suspicious ports for highlighting
const SUSPICIOUS_PORTS = new Set([
  '22', '23', '3389', '4444', '5555', '6666', '7777', '8888',
  '9999', '1337', '31337', '12345', '54321',
]);

function getPortFromAddress(addr: string): string {
  const parts = addr.split(':');
  return parts[parts.length - 1] || '';
}

function isPrivateIP(ip: string): boolean {
  return (
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('172.') ||
    ip === '127.0.0.1' ||
    ip === '0.0.0.0' ||
    ip === '::' ||
    ip === '::1'
  );
}

function flagEmoji(code: string): string {
  return code.toUpperCase().replace(/./g,
    (c: string) => String.fromCodePoint(127397 + c.charCodeAt(0))
  );
}

// ─────────────────────────────────────────────────────────────
// Main component
// ─────────────────────────────────────────────────────────────

export default function NetworkMapPage() {
  const router = useRouter();

  const canvasRef    = useRef<HTMLCanvasElement>(null);
  const animRef      = useRef<number>(0);
  const nodesRef     = useRef<GraphNode[]>([]);
  const linksRef     = useRef<GraphLink[]>([]);
  const dragRef      = useRef<{ node: GraphNode | null; offsetX: number; offsetY: number }>({ node: null, offsetX: 0, offsetY: 0 });
  const transformRef = useRef({ x: 0, y: 0, scale: 1 });
  const panRef       = useRef<{ dragging: boolean; startX: number; startY: number; tx: number; ty: number }>({ dragging: false, startX: 0, startY: 0, tx: 0, ty: 0 });
  const hoveredRef   = useRef<GraphNode | null>(null);
  const maliciousIPs = useRef<Set<string>>(new Set());
  const geoCache     = useRef<Record<string, { country: string; countryCode: string }>>({});

  const [agents, setAgents]               = useState<Agent[]>([]);
  const [loading, setLoading]             = useState(true);
  const [showExternal, setShowExternal]   = useState(true);
  const [showListening, setShowListening] = useState(true);
  const [showLocal, setShowLocal]         = useState(false);
  const [selected, setSelected]           = useState<GraphNode | null>(null);
  const [nodeLinks, setNodeLinks]         = useState<GraphLink[]>([]);
  const [refreshing, setRefreshing]       = useState(false);
  const [search, setSearch]               = useState('');
  const [tooltip, setTooltip]             = useState<{ x: number; y: number; node: GraphNode } | null>(null);
  const [stats, setStats]                 = useState({ agents: 0, nodes: 0, links: 0, established: 0, malicious: 0 });

  // ── Build graph ──────────────────────────────────────────────
  const buildGraph = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    setLoading(true);

    // Fetch agents + IOCs in parallel
    const [agRes, iocRes] = await Promise.allSettled([
      agentsAPI.getAll(),
      iocsAPI.getAll(),
    ]);

    const agentList: Agent[] = agRes.status === 'fulfilled' ? (agRes.value.data || []) : [];
    setAgents(agentList);

    // Build malicious IP set from IOCs
    if (iocRes.status === 'fulfilled') {
      const iocs = iocRes.value.data || [];
      maliciousIPs.current = new Set(
        iocs
          .filter((i: any) => (i.type === 'ip' || i.type === 'domain') && i.enabled)
          .map((i: any) => i.indicator as string)
      );
    }

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
          const remoteIP   = c.remote_address?.split(':')[0] || '';
          const remotePort = getPortFromAddress(c.remote_address || '');
          const localPort  = getPortFromAddress(c.local_address || '');

          // ── Listening / local sockets ─────────────────────────
          if (c.state === 'LISTEN' || remoteIP === '0.0.0.0' || remoteIP === '::' || remoteIP === '127.0.0.1' || remoteIP === '') {
            if (!showListening) return;
            const targetId = `local-${a.id}-${localPort}`;
            if (!nodes.has(targetId)) {
              nodes.set(targetId, {
                id: targetId, type: 'local',
                label: c.local_address || `port ${localPort}`,
                port: localPort,
                x: (nodes.get(`agent-${a.id}`)?.x || 300) + (Math.random() - 0.5) * 120,
                y: (nodes.get(`agent-${a.id}`)?.y || 300) + (Math.random() - 0.5) * 120,
                vx: 0, vy: 0,
              });
            }
            const linkKey = `agent-${a.id}-${targetId}-${c.protocol}`;
            if (!linkMap.has(linkKey)) {
              linkMap.set(linkKey, { source: `agent-${a.id}`, target: targetId, protocol: c.protocol, state: 'LISTEN', count: 1, port: localPort });
            } else {
              linkMap.get(linkKey)!.count++;
            }
            return;
          }

          if (!showLocal && isPrivateIP(remoteIP) && !agentList.find(ag => ag.ip_address === remoteIP)) return;

          // ── Agent-to-agent ────────────────────────────────────
          const remoteAgent = agentList.find(ag => ag.ip_address === remoteIP);
          if (remoteAgent) {
            const linkKey = `agent-${a.id}-agent-${remoteAgent.id}-${c.protocol}`;
            if (!linkMap.has(linkKey)) {
              linkMap.set(linkKey, { source: `agent-${a.id}`, target: `agent-${remoteAgent.id}`, protocol: c.protocol, state: c.state, count: 1 });
            } else {
              linkMap.get(linkKey)!.count++;
            }
            return;
          }

          // ── External IPs ──────────────────────────────────────
          if (!showExternal) return;
          const targetId = `ext-${remoteIP}`;
          const isMalicious = maliciousIPs.current.has(remoteIP);
          if (!nodes.has(targetId)) {
            const geo = geoCache.current[remoteIP];
            nodes.set(targetId, {
              id: targetId, type: 'external',
              label: remoteIP,
              country:     geo?.country     || '',
              countryCode: geo?.countryCode || '',
              isMalicious,
              x: Math.random() * 800 + 50,
              y: Math.random() * 600 + 50,
              vx: 0, vy: 0,
            });
          } else if (isMalicious) {
            nodes.get(targetId)!.isMalicious = true;
          }

          const linkKey = `agent-${a.id}-${targetId}-${c.protocol}`;
          if (!linkMap.has(linkKey)) {
            linkMap.set(linkKey, { source: `agent-${a.id}`, target: targetId, protocol: c.protocol, state: c.state, count: 1, port: remotePort });
          } else {
            linkMap.get(linkKey)!.count++;
          }
        });
      } catch { /* ignore per-agent errors */ }
    }));

    nodesRef.current = [...nodes.values()];
    linksRef.current = [...linkMap.values()];

    const established = linksRef.current.filter(l => l.state === 'ESTABLISHED').length;
    const maliciousCount = [...nodes.values()].filter(n => n.isMalicious).length;
    setStats({ agents: agentList.length, nodes: nodes.size, links: linkMap.size, established, malicious: maliciousCount });

    setLoading(false);
    setRefreshing(false);
  }, [showExternal, showListening, showLocal]);

  useEffect(() => { buildGraph(); }, [showExternal, showListening, showLocal]);

  // ── Background GeoIP enrichment ──────────────────────────────
  useEffect(() => {
    if (loading) return;
    const externalNodes = nodesRef.current.filter(n => n.type === 'external' && !n.country);
    if (externalNodes.length === 0) return;

    externalNodes.slice(0, 30).forEach((node, i) => {
      const ip = node.label;
      if (geoCache.current[ip]) return;
      setTimeout(async () => {
        try {
          const token = localStorage.getItem('token') || '';
          const r = await fetch(`/api/geoip/${ip}`, { headers: { Authorization: `Bearer ${token}` } });
          if (!r.ok) return;
          const data = await r.json();
          if (data.country_code) {
            geoCache.current[ip] = { country: data.country || '', countryCode: data.country_code || '' };
            const n = nodesRef.current.find(x => x.id === `ext-${ip}`);
            if (n) { n.country = data.country; n.countryCode = data.country_code; }
          }
        } catch { /* ignore */ }
      }, i * 150);
    });
  }, [loading]);

  // ── Force simulation + canvas draw ─────────────────────────
  useEffect(() => {
    if (loading) return;

    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d')!;

    const W = canvas.parentElement?.clientWidth || 900;
    const H = canvas.parentElement?.clientHeight || 600;
    canvas.width  = W;
    canvas.height = H;

    const REPULSION  = 9000;
    const ATTRACTION = 0.04;
    const DAMPING    = 0.87;
    const CENTER_X   = W / 2;
    const CENTER_Y   = H / 2;

    nodesRef.current.forEach(n => {
      if (!n.x) n.x = Math.random() * W;
      if (!n.y) n.y = Math.random() * H;
      n.vx = n.vx || 0;
      n.vy = n.vy || 0;
    });

    function resolveTarget(link: GraphLink): GraphNode | undefined {
      const t = link.target;
      return nodesRef.current.find(n => n.id === (typeof t === 'string' ? t : (t as any).id));
    }

    function tick() {
      const nodes = nodesRef.current;
      const links = linksRef.current;

      // Repulsion
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = (nodes[j].x || 0) - (nodes[i].x || 0);
          const dy = (nodes[j].y || 0) - (nodes[i].y || 0);
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const force = REPULSION / (dist * dist);
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;
          nodes[i].vx! -= fx; nodes[i].vy! -= fy;
          nodes[j].vx! += fx; nodes[j].vy! += fy;
        }
      }

      // Attraction
      links.forEach(link => {
        const s = nodes.find(n => n.id === link.source);
        const t = resolveTarget(link);
        if (!s || !t) return;
        const dx = (t.x || 0) - (s.x || 0);
        const dy = (t.y || 0) - (s.y || 0);
        s.vx! += dx * ATTRACTION; s.vy! += dy * ATTRACTION;
        t.vx! -= dx * ATTRACTION; t.vy! -= dy * ATTRACTION;
      });

      // Gravity + integrate
      nodes.forEach(n => {
        n.vx! += (CENTER_X - (n.x || CENTER_X)) * 0.004;
        n.vy! += (CENTER_Y - (n.y || CENTER_Y)) * 0.004;
        n.vx! *= DAMPING; n.vy! *= DAMPING;
        if (n.fx != null) n.x = n.fx; else n.x = (n.x || 0) + n.vx!;
        if (n.fy != null) n.y = n.fy; else n.y = (n.y || 0) + n.vy!;
      });

      // Draw
      ctx.clearRect(0, 0, W, H);
      ctx.save();
      const tr = transformRef.current;
      ctx.translate(tr.x, tr.y);
      ctx.scale(tr.scale, tr.scale);

      // ── Draw links ───────────────────────────────────────────
      links.forEach(link => {
        const s = nodes.find(n => n.id === link.source);
        const t = resolveTarget(link);
        if (!s || !t) return;

        const sx = s.x || 0, sy = s.y || 0;
        const tx2 = t.x || 0, ty2 = t.y || 0;

        // Highlight links to malicious nodes in red
        const isThreat = t.isMalicious || s.isMalicious;
        ctx.beginPath();
        ctx.moveTo(sx, sy);
        ctx.lineTo(tx2, ty2);
        ctx.strokeStyle = isThreat ? '#f85149' : (STATE_COLOR[link.state] || STATE_COLOR.default);
        ctx.globalAlpha = isThreat ? 0.7 : 0.3;
        ctx.lineWidth = Math.min(link.count * 0.5 + 0.5, 3);

        if (isThreat) {
          ctx.setLineDash([4, 3]);
        } else {
          ctx.setLineDash([]);
        }
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.globalAlpha = 1;

        // Port label on link midpoint for suspicious ports
        if (link.port && SUSPICIOUS_PORTS.has(link.port)) {
          const mx = (sx + tx2) / 2;
          const my = (sy + ty2) / 2;
          ctx.font = '8px monospace';
          ctx.fillStyle = '#fbbf24';
          ctx.textAlign = 'center';
          ctx.fillText(`:${link.port}`, mx, my - 4);
        }
      });

      // ── Draw nodes ───────────────────────────────────────────
      nodes.forEach(n => {
        const x = n.x || 0;
        const y = n.y || 0;

        // Skip nodes not matching search
        const searchLower = search.toLowerCase();
        const dimmed = searchLower && !n.label.toLowerCase().includes(searchLower) && !n.country?.toLowerCase().includes(searchLower);

        ctx.globalAlpha = dimmed ? 0.15 : 1;

        if (n.type === 'agent') {
          const r = 18;
          const online = n.status === 'online';
          const color = online ? '#34d399' : '#f85149';

          // Outer glow for online agents
          if (online) {
            const grad = ctx.createRadialGradient(x, y, r * 0.5, x, y, r * 2);
            grad.addColorStop(0, '#34d39930');
            grad.addColorStop(1, 'transparent');
            ctx.beginPath(); ctx.arc(x, y, r * 2, 0, Math.PI * 2);
            ctx.fillStyle = grad; ctx.fill();
          }

          ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2);
          ctx.fillStyle = online ? '#34d39918' : '#f8514918';
          ctx.fill();
          ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.stroke();

          // CPU icon placeholder — draw X mark
          ctx.fillStyle = color;
          ctx.font = 'bold 10px monospace';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillText('⬡', x, y);

          // Hostname label
          ctx.fillStyle = '#e2e8f0';
          ctx.font = 'bold 10px monospace';
          ctx.textBaseline = 'alphabetic';
          ctx.fillText(n.label.slice(0, 14), x, y + r + 13);

          // Risk score badge
          if ((n as any).riskScore > 70) {
            ctx.beginPath(); ctx.arc(x + r - 4, y - r + 4, 5, 0, Math.PI * 2);
            ctx.fillStyle = '#f85149'; ctx.fill();
          }

        } else if (n.type === 'local') {
          const r = 7;
          const isSuspicious = n.port ? SUSPICIOUS_PORTS.has(n.port) : false;
          ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2);
          ctx.fillStyle = isSuspicious ? '#fbbf2430' : '#38bdf820';
          ctx.fill();
          ctx.strokeStyle = isSuspicious ? '#fbbf24' : '#38bdf8';
          ctx.lineWidth = 1; ctx.stroke();

          // Port number label
          if (n.port) {
            ctx.fillStyle = isSuspicious ? '#fbbf24' : '#64748b';
            ctx.font = '8px monospace';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'alphabetic';
            ctx.fillText(`:${n.port}`, x, y + r + 10);
          }

        } else {
          // External
          const r = 10;
          const threat = n.isMalicious;

          if (threat) {
            // Pulsing red ring for malicious
            ctx.beginPath(); ctx.arc(x, y, r + 4, 0, Math.PI * 2);
            ctx.strokeStyle = '#f8514960'; ctx.lineWidth = 2; ctx.stroke();
          }

          ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2);
          ctx.fillStyle = threat ? '#f8514922' : '#fbbf2418';
          ctx.fill();
          ctx.strokeStyle = threat ? '#f85149' : '#fbbf24';
          ctx.lineWidth = threat ? 2 : 1; ctx.stroke();

          // IP label
          ctx.fillStyle = threat ? '#f87171' : '#94a3b8';
          ctx.font = '9px monospace';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'alphabetic';
          ctx.fillText(n.label.slice(0, 15), x, y + r + 12);

          // Country flag
          if (n.countryCode) {
            ctx.font = '11px sans-serif';
            ctx.fillText(flagEmoji(n.countryCode), x, y + r + 23);
          }

          // Threat label
          if (threat) {
            ctx.fillStyle = '#f85149';
            ctx.font = 'bold 8px monospace';
            ctx.fillText('⚠ IOC', x, y - r - 4);
          }
        }

        ctx.globalAlpha = 1;
      });

      // ── Hover tooltip (drawn in screen space) ───────────────
      ctx.restore();
      const hov = hoveredRef.current;
      if (hov) {
        const sx = (hov.x || 0) * tr.scale + tr.x;
        const sy = (hov.y || 0) * tr.scale + tr.y;
        const lines: string[] = [hov.label];
        if (hov.type === 'external' && hov.country) lines.push(`${flagEmoji(hov.countryCode || '')} ${hov.country}`);
        if (hov.isMalicious) lines.push('⚠ Matched IOC');
        if (hov.port && SUSPICIOUS_PORTS.has(hov.port)) lines.push(`⚠ Suspicious port :${hov.port}`);
        if (hov.type === 'agent') lines.push(`Status: ${hov.status}`);

        const tw = Math.max(...lines.map(l => l.length)) * 6.2 + 16;
        const th = lines.length * 15 + 10;
        const tx3 = Math.min(sx + 14, W - tw - 4);
        const ty3 = Math.max(sy - th / 2, 4);

        ctx.fillStyle = 'rgba(15,23,42,0.92)';
        ctx.strokeStyle = hov.isMalicious ? '#f85149' : 'rgba(148,163,184,0.3)';
        ctx.lineWidth = 1;
        const rad = 6;
        ctx.beginPath();
        ctx.moveTo(tx3 + rad, ty3); ctx.lineTo(tx3 + tw - rad, ty3);
        ctx.quadraticCurveTo(tx3 + tw, ty3, tx3 + tw, ty3 + rad);
        ctx.lineTo(tx3 + tw, ty3 + th - rad);
        ctx.quadraticCurveTo(tx3 + tw, ty3 + th, tx3 + tw - rad, ty3 + th);
        ctx.lineTo(tx3 + rad, ty3 + th);
        ctx.quadraticCurveTo(tx3, ty3 + th, tx3, ty3 + th - rad);
        ctx.lineTo(tx3, ty3 + rad);
        ctx.quadraticCurveTo(tx3, ty3, tx3 + rad, ty3);
        ctx.closePath();
        ctx.fill(); ctx.stroke();

        ctx.textBaseline = 'top';
        lines.forEach((line, i) => {
          ctx.fillStyle = i === 0 ? '#f1f5f9' : (hov.isMalicious && i > 0 ? '#f87171' : '#94a3b8');
          ctx.font = i === 0 ? 'bold 10px monospace' : '9px monospace';
          ctx.textAlign = 'left';
          ctx.fillText(line, tx3 + 8, ty3 + 5 + i * 15);
        });
      }

      animRef.current = requestAnimationFrame(tick);
    }

    animRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(animRef.current);
  }, [loading, search]);

  // ── Mouse helpers ────────────────────────────────────────────
  const screenToWorld = (sx: number, sy: number) => {
    const t = transformRef.current;
    return { x: (sx - t.x) / t.scale, y: (sy - t.y) / t.scale };
  };

  const findNodeAt = (wx: number, wy: number) => {
    return nodesRef.current.find(n => {
      const r = n.type === 'agent' ? 20 : 12;
      const dx = (n.x || 0) - wx; const dy = (n.y || 0) - wy;
      return dx * dx + dy * dy <= r * r;
    }) || null;
  };

  const onMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current!.getBoundingClientRect();
    const sx = e.clientX - rect.left; const sy = e.clientY - rect.top;
    const { x: wx, y: wy } = screenToWorld(sx, sy);
    const node = findNodeAt(wx, wy);
    if (node) {
      dragRef.current = { node, offsetX: wx - (node.x || 0), offsetY: wy - (node.y || 0) };
      node.fx = node.x; node.fy = node.y;
      setSelected(node);
      setNodeLinks(linksRef.current.filter(l => {
        const src = l.source;
        const tgt = typeof l.target === 'string' ? l.target : (l.target as any).id;
        return src === node.id || tgt === node.id;
      }));
    } else {
      panRef.current = { dragging: true, startX: sx, startY: sy, tx: transformRef.current.x, ty: transformRef.current.y };
    }
  };

  const onMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current!.getBoundingClientRect();
    const sx = e.clientX - rect.left; const sy = e.clientY - rect.top;
    const { x: wx, y: wy } = screenToWorld(sx, sy);

    if (dragRef.current.node) {
      dragRef.current.node.fx = wx - dragRef.current.offsetX;
      dragRef.current.node.fy = wy - dragRef.current.offsetY;
    } else if (panRef.current.dragging) {
      transformRef.current.x = panRef.current.tx + (sx - panRef.current.startX);
      transformRef.current.y = panRef.current.ty + (sy - panRef.current.startY);
    } else {
      // Hover detection
      const hovered = findNodeAt(wx, wy);
      hoveredRef.current = hovered;
      if (canvasRef.current) {
        canvasRef.current.style.cursor = hovered ? 'pointer' : 'grab';
      }
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
    const rect = canvasRef.current!.getBoundingClientRect();
    const mx = e.clientX - rect.left; const my = e.clientY - rect.top;
    const factor = e.deltaY > 0 ? 0.9 : 1.1;
    const newScale = Math.min(Math.max(transformRef.current.scale * factor, 0.15), 6);
    // Zoom toward mouse position
    transformRef.current.x = mx - (mx - transformRef.current.x) * (newScale / transformRef.current.scale);
    transformRef.current.y = my - (my - transformRef.current.y) * (newScale / transformRef.current.scale);
    transformRef.current.scale = newScale;
  };

  const resetView = () => { transformRef.current = { x: 0, y: 0, scale: 1 }; };
  const zoomIn    = () => { transformRef.current.scale = Math.min(transformRef.current.scale * 1.3, 6); };
  const zoomOut   = () => { transformRef.current.scale = Math.max(transformRef.current.scale * 0.77, 0.15); };

  // ── Panel: detail view for selected node ────────────────────
  const peerNodes = nodeLinks.map(l => {
    const otherId = l.source === selected?.id
      ? (typeof l.target === 'string' ? l.target : (l.target as any).id)
      : l.source;
    return { link: l, node: nodesRef.current.find(n => n.id === otherId) };
  });

  return (
    <RootLayout
      title="Network Map"
      subtitle="Live agent connection topology"
      onRefresh={() => buildGraph(true)}
      refreshing={refreshing}
      actions={
        <div className="flex items-center gap-2">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 pointer-events-none" style={{ color: 'var(--text-3)' }} />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Filter nodes…"
              className="g-input text-xs pl-6 h-7 w-36"
            />
            {search && (
              <button onClick={() => setSearch('')} className="absolute right-2 top-1/2 -translate-y-1/2">
                <X className="h-3 w-3" style={{ color: 'var(--text-3)' }} />
              </button>
            )}
          </div>

          {/* Toggle buttons */}
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
          <button onClick={() => setShowLocal(p => !p)}
            className={`g-btn text-xs ${showLocal ? 'g-btn-primary' : 'g-btn-ghost'}`}>
            {showLocal ? <Eye className="h-3.5 w-3.5" /> : <EyeOff className="h-3.5 w-3.5" />}
            LAN
          </button>
        </div>
      }
    >
      <div className="flex gap-4" style={{ height: 'calc(100vh - 140px)' }}>

        {/* ── Canvas area ─────────────────────────────────────── */}
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
            <canvas
              ref={canvasRef}
              className="w-full h-full"
              onMouseDown={onMouseDown}
              onMouseMove={onMouseMove}
              onMouseUp={onMouseUp}
              onMouseLeave={onMouseUp}
              onWheel={onWheel}
            />
          )}

          {/* Stats bar */}
          <div className="absolute top-3 left-3 flex items-center gap-3 text-[10px] px-3 py-2 rounded-xl"
            style={{ background: 'var(--glass-modal)', border: '1px solid var(--border)' }}>
            <span style={{ color: 'var(--text-3)' }}>{stats.agents} agents</span>
            <span style={{ color: 'var(--text-3)' }}>{stats.nodes} nodes</span>
            <span style={{ color: 'var(--text-3)' }}>{stats.links} links</span>
            <span style={{ color: '#34d399' }}>{stats.established} established</span>
            {stats.malicious > 0 && (
              <span className="flex items-center gap-1" style={{ color: '#f85149' }}>
                <AlertTriangle className="h-3 w-3" />
                {stats.malicious} IOC match
              </span>
            )}
          </div>

          {/* Zoom controls */}
          <div className="absolute top-3 right-3 flex flex-col gap-1">
            <button onClick={zoomIn} className="g-btn g-btn-ghost p-1.5 rounded-lg" title="Zoom in">
              <ZoomIn className="h-3.5 w-3.5" />
            </button>
            <button onClick={zoomOut} className="g-btn g-btn-ghost p-1.5 rounded-lg" title="Zoom out">
              <ZoomOut className="h-3.5 w-3.5" />
            </button>
            <button onClick={resetView} className="g-btn g-btn-ghost p-1.5 rounded-lg" title="Reset view">
              <RefreshCw className="h-3.5 w-3.5" />
            </button>
          </div>

          {/* Legend */}
          <div className="absolute bottom-3 left-3 flex items-center gap-3 text-[10px] px-3 py-2 rounded-xl"
            style={{ background: 'var(--glass-modal)', border: '1px solid var(--border)' }}>
            {[
              { color: '#34d399', label: 'Agent Online' },
              { color: '#f85149', label: 'Agent Offline' },
              { color: '#38bdf8', label: 'Listening' },
              { color: '#fbbf24', label: 'External' },
              { color: '#f85149', label: 'IOC Match', dot: true },
            ].map(l => (
              <div key={l.label} className="flex items-center gap-1">
                <div className="h-2 w-2 rounded-full" style={{ background: l.color }} />
                <span style={{ color: 'var(--text-3)' }}>{l.label}</span>
              </div>
            ))}
          </div>

          {/* Hint */}
          <div className="absolute bottom-3 right-3 text-[10px] px-2 py-1 rounded-lg"
            style={{ color: 'var(--text-3)', background: 'var(--glass-modal)' }}>
            Scroll to zoom · Drag nodes · Click to inspect
          </div>
        </div>

        {/* ── Detail panel ─────────────────────────────────────── */}
        <div className="w-72 shrink-0 space-y-3 overflow-y-auto">
          {selected ? (
            <>
              {/* Node info card */}
              <div className="g-card p-4">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-2">
                    {selected.type === 'agent'
                      ? <Cpu className="h-4 w-4 shrink-0" style={{ color: 'var(--accent)' }} />
                      : selected.isMalicious
                        ? <AlertTriangle className="h-4 w-4 shrink-0 text-red-400" />
                        : <Network className="h-4 w-4 shrink-0" style={{ color: 'var(--accent)' }} />}
                    <p className="text-xs font-semibold truncate" style={{ color: 'var(--text-1)' }}>
                      {selected.label}
                    </p>
                  </div>
                  <button onClick={() => setSelected(null)} className="p-0.5 rounded hover:opacity-70">
                    <X className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
                  </button>
                </div>

                {selected.isMalicious && (
                  <div className="flex items-center gap-2 mb-3 px-2 py-1.5 rounded-lg text-[11px]"
                    style={{ background: '#f8514915', border: '1px solid #f8514940' }}>
                    <AlertTriangle className="h-3.5 w-3.5 shrink-0" style={{ color: '#f85149' }} />
                    <span style={{ color: '#f87171' }}>Matched active IOC — potential threat</span>
                  </div>
                )}

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
                  {selected.type === 'external' && selected.country && (
                    <div className="flex justify-between">
                      <span style={{ color: 'var(--text-3)' }}>Country</span>
                      <span style={{ color: 'var(--text-1)' }}>
                        {selected.countryCode && <span className="mr-1">{flagEmoji(selected.countryCode)}</span>}
                        {selected.country}
                      </span>
                    </div>
                  )}
                  {selected.port && (
                    <div className="flex justify-between">
                      <span style={{ color: 'var(--text-3)' }}>Port</span>
                      <span style={{ color: SUSPICIOUS_PORTS.has(selected.port) ? '#fbbf24' : 'var(--text-1)' }}>
                        :{selected.port}
                        {SUSPICIOUS_PORTS.has(selected.port) && ' ⚠'}
                      </span>
                    </div>
                  )}
                  <div className="flex justify-between">
                    <span style={{ color: 'var(--text-3)' }}>Connections</span>
                    <span style={{ color: 'var(--accent)' }}>{nodeLinks.length}</span>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex gap-2 mt-3 pt-3" style={{ borderTop: '1px solid var(--border)' }}>
                  {selected.type === 'agent' && selected.agentId && (
                    <button
                      onClick={() => router.push(`/agents/${selected.agentId}`)}
                      className="g-btn g-btn-primary text-[10px] flex-1 flex items-center justify-center gap-1">
                      <ExternalLink className="h-3 w-3" />
                      View Agent
                    </button>
                  )}
                  {selected.type === 'external' && (
                    <button
                      onClick={() => window.open(`https://www.virustotal.com/gui/ip-address/${selected.label}`, '_blank')}
                      className="g-btn g-btn-ghost text-[10px] flex-1 flex items-center justify-center gap-1">
                      <Shield className="h-3 w-3" />
                      VirusTotal
                    </button>
                  )}
                  {selected.type === 'external' && (
                    <button
                      onClick={() => window.open(`https://ipinfo.io/${selected.label}`, '_blank')}
                      className="g-btn g-btn-ghost text-[10px] flex-1 flex items-center justify-center gap-1">
                      <ExternalLink className="h-3 w-3" />
                      IPInfo
                    </button>
                  )}
                </div>
              </div>

              {/* Connections list */}
              {peerNodes.length > 0 && (
                <div className="g-card">
                  <p className="text-[10px] font-semibold uppercase tracking-wider px-4 pt-3 pb-2"
                    style={{ color: 'var(--text-3)' }}>
                    Connections ({peerNodes.length})
                  </p>
                  <div className="divide-y max-h-96 overflow-y-auto" style={{ borderColor: 'var(--border)' }}>
                    {peerNodes.map(({ link, node: peer }, i) => (
                      <div key={i}
                        className="px-4 py-2.5 cursor-pointer hover:opacity-80 transition-opacity"
                        onClick={() => peer && (() => {
                          setSelected(peer);
                          setNodeLinks(linksRef.current.filter(l => {
                            const src = l.source;
                            const tgt = typeof l.target === 'string' ? l.target : (l.target as any).id;
                            return src === peer.id || tgt === peer.id;
                          }));
                        })()}>
                        <div className="flex items-center justify-between">
                          <p className="text-[10px] font-mono truncate max-w-[140px]" style={{ color: peer?.isMalicious ? '#f87171' : 'var(--text-1)' }}>
                            {peer?.isMalicious && '⚠ '}
                            {peer?.label || 'unknown'}
                          </p>
                          <div className="flex items-center gap-1.5">
                            <span className="text-[9px] font-mono" style={{ color: STATE_COLOR[link.state] || 'var(--text-3)' }}>
                              {link.state}
                            </span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="text-[9px] mono uppercase" style={{ color: 'var(--text-3)' }}>{link.protocol}</span>
                          {link.port && (
                            <span className="text-[9px] mono" style={{ color: SUSPICIOUS_PORTS.has(link.port) ? '#fbbf24' : 'var(--text-3)' }}>
                              :{link.port}
                            </span>
                          )}
                          {link.count > 1 && <span className="text-[9px]" style={{ color: 'var(--text-3)' }}>×{link.count}</span>}
                          {peer?.countryCode && <span className="text-[9px]">{flagEmoji(peer.countryCode)}</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          ) : (
            /* Empty state */
            <div className="g-card p-6 text-center">
              <Network className="h-8 w-8 mx-auto mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-xs" style={{ color: 'var(--text-2)' }}>Click any node to inspect</p>
              <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                {nodesRef.current.filter(n => n.type === 'agent').length} agents ·{' '}
                {nodesRef.current.filter(n => n.type === 'external').length} external IPs
              </p>
              {stats.malicious > 0 && (
                <div className="mt-3 flex items-center justify-center gap-1.5 text-[10px]" style={{ color: '#f87171' }}>
                  <AlertTriangle className="h-3 w-3" />
                  {stats.malicious} IOC-matched {stats.malicious === 1 ? 'host' : 'hosts'} detected
                </div>
              )}
            </div>
          )}

          {/* Threat summary card (always visible if IOC matches exist) */}
          {stats.malicious > 0 && !selected && (
            <div className="g-card p-3" style={{ border: '1px solid #f8514940' }}>
              <p className="text-[10px] font-semibold mb-2 flex items-center gap-1.5" style={{ color: '#f87171' }}>
                <AlertTriangle className="h-3 w-3" />
                Active Threat Connections
              </p>
              <div className="space-y-1">
                {nodesRef.current.filter(n => n.isMalicious).map(n => (
                  <button key={n.id}
                    className="w-full text-left px-2 py-1.5 rounded-lg text-[10px] font-mono hover:opacity-80 transition-opacity"
                    style={{ background: '#f8514912', color: '#f87171' }}
                    onClick={() => {
                      setSelected(n);
                      setNodeLinks(linksRef.current.filter(l => {
                        const src = l.source;
                        const tgt = typeof l.target === 'string' ? l.target : (l.target as any).id;
                        return src === n.id || tgt === n.id;
                      }));
                    }}>
                    ⚠ {n.label}
                    {n.countryCode && <span className="ml-1.5">{flagEmoji(n.countryCode)}</span>}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </RootLayout>
  );
}
