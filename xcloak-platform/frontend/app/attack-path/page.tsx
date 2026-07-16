'use client';

import { createPortal } from 'react-dom';
import { useEffect, useState, useCallback, useMemo, useRef } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { attackPathAPI } from '@/lib/api';
import { AttackPathGraph, AttackPathNode, AttackPathEdge, RankedAttackPath } from '@/types';
import { sevClass } from '@/lib/utils';
import Link from 'next/link';
import {
  Crosshair, Globe, Skull, ShieldAlert, Cpu, Cloud, Box,
  Crown, Zap, Target, Shield, Activity, ArrowRight, ArrowDown,
  Filter, AlertTriangle, AlertCircle, Bug, Play, SkipBack,
  SkipForward, Flame, Eye, Wrench, Lock, Users, Database,
  Server, GitFork, Layers, Sliders, X, ChevronRight,
  CheckCircle, ScanLine, Power, Send, Hash, Building,
  TrendingUp, BarChart2, Crosshair as CrosshairIcon,
} from 'lucide-react';

// ── Layout constants ────────────────────────────────────────────────────────
const COL_WIDTH  = 220;
const ROW_HEIGHT = 115;
const PAD        = 80;
const NODE_R     = 20;

// ── Visual constants ────────────────────────────────────────────────────────
const RISK_FILL: Record<string, string> = {
  critical: '#f85149', high: '#fb923c', medium: '#fbbf24', low: '#38bdf8', unknown: '#64748b',
};
const EDGE_COLOR: Record<string, string> = {
  internet_exposure: '#fb923c',
  lateral:           '#38bdf8',
  priv_esc:          '#a78bfa',
  cloud_jump:        '#2dd4bf',
  container_escape:  '#f85149',
  identity:          '#e879f9',
  vpn:               '#059669',
  credential_access: '#fbbf24',
  kerberos:          '#c084fc',
};
const EDGE_LABEL: Record<string, string> = {
  internet_exposure: 'Internet Exposure',
  lateral:           'Lateral Movement',
  priv_esc:          'Privilege Escalation',
  cloud_jump:        'Cloud Jump',
  container_escape:  'Container Escape',
  identity:          'Identity Pivot',
  vpn:               'VPN Tunnel',
  credential_access: 'Credential Access',
  kerberos:          'Kerberos Abuse',
};

const LATERAL_METHODS = ['RDP', 'SMB', 'PsExec', 'WMI', 'WinRM', 'SSH', 'Remote PowerShell', 'VPN', 'K8s Exec', 'Cloud IAM'];
const PRIV_ESC_TYPES  = ['Local Admin', 'Domain Admin', 'Azure AD Admin', 'AWS IAM', 'K8s RBAC', 'Docker Socket', 'Sudo Misconfig', 'SUID Binaries', 'Windows Token Abuse', 'Kerberos Abuse'];

const KILL_CHAIN_MODELS = {
  mitre: [
    { id: 'reconnaissance',       label: 'Recon' },
    { id: 'initial_access',       label: 'Initial Access' },
    { id: 'execution',            label: 'Execution' },
    { id: 'persistence',          label: 'Persistence' },
    { id: 'privilege_escalation', label: 'Priv Esc' },
    { id: 'lateral_movement',     label: 'Lateral Move' },
    { id: 'collection',           label: 'Collection' },
    { id: 'credential_access',    label: 'Cred Access' },
    { id: 'impact',               label: 'Impact' },
  ],
  lockheed: [
    { id: 'reconnaissance', label: 'Recon' },
    { id: 'weaponization',  label: 'Weapon' },
    { id: 'delivery',       label: 'Delivery' },
    { id: 'exploitation',   label: 'Exploit' },
    { id: 'installation',   label: 'Install' },
    { id: 'c2',             label: 'C2' },
    { id: 'actions',        label: 'Actions' },
  ],
  diamond: [
    { id: 'adversary',       label: 'Adversary' },
    { id: 'capability',      label: 'Capability' },
    { id: 'infrastructure',  label: 'Infrastructure' },
    { id: 'victim',          label: 'Victim' },
  ],
};

const PATH_TYPE_TABS = [
  { key: 'all',       label: 'All Paths'   },
  { key: 'lateral',   label: 'Lateral'     },
  { key: 'priv_esc',  label: 'Priv Esc'    },
  { key: 'cloud',     label: 'Cloud'       },
  { key: 'container', label: 'Container'   },
  { key: 'identity',  label: 'Identity'    },
  { key: 'vpn',       label: 'VPN'         },
  { key: 'hybrid',    label: 'Hybrid'      },
  { key: 'saas',      label: 'SaaS'        },
] as const;

const SIDE_TABS = ['Paths', 'Chain', 'MITRE', 'Choke Points', 'Blast Radius', 'Remediation', 'Exposure', 'Simulation', 'AI'] as const;

type PathTypeFilter = typeof PATH_TYPE_TABS[number]['key'];
type SideTab = typeof SIDE_TABS[number];
type KillChainModel = keyof typeof KILL_CHAIN_MODELS;

interface Positioned extends AttackPathNode { x: number; y: number; }

// ── Geometry helpers ────────────────────────────────────────────────────────
function edgePoints(ax: number, ay: number, bx: number, by: number) {
  const dx = bx - ax; const dy = by - ay;
  const dist = Math.sqrt(dx * dx + dy * dy);
  if (dist < 1) return { x1: ax, y1: ay, x2: bx, y2: by };
  const ux = dx / dist; const uy = dy / dist;
  return { x1: ax + ux * (NODE_R + 2), y1: ay + uy * (NODE_R + 2), x2: bx - ux * (NODE_R + 9), y2: by - uy * (NODE_R + 9) };
}
function hexPts(r: number) {
  return Array.from({ length: 6 }, (_, i) => {
    const a = (i * 60 - 30) * Math.PI / 180;
    return `${(r * Math.cos(a)).toFixed(1)},${(r * Math.sin(a)).toFixed(1)}`;
  }).join(' ');
}
function labelY(n: Positioned) { return n.type === 'cloud' ? NODE_R * 0.85 + 14 : NODE_R + 14; }

// ── Node shape + icon (SVG) ─────────────────────────────────────────────────
function NodeShape({ n, sim }: { n: Positioned; sim?: boolean }) {
  const fill   = n.type === 'internet' ? 'var(--bg-1)' : (RISK_FILL[n.risk_level] || RISK_FILL.unknown);
  const stroke = n.is_chokepoint ? '#a78bfa' : n.exposed ? '#fb923c' : sim ? '#38bdf8' : 'var(--border)';
  const sw     = (n.is_chokepoint || n.exposed || sim) ? 2.5 : 1.5;
  if (n.type === 'internet')          return <circle r={NODE_R} fill="var(--bg-1)" stroke="#fb923c" strokeWidth={2} />;
  if (n.type === 'cloud')             return <rect x={-NODE_R * 1.4} y={-NODE_R * 0.85} width={NODE_R * 2.8} height={NODE_R * 1.7} rx={NODE_R * 0.55} fill={fill} stroke={stroke} strokeWidth={sw} />;
  if (n.type === 'container')         return <polygon points={hexPts(NODE_R)} fill={fill} stroke={stroke} strokeWidth={sw} />;
  if (n.type === 'domain_controller') return <rect x={-NODE_R} y={-NODE_R} width={NODE_R * 2} height={NODE_R * 2} rx={3} fill={fill} stroke={stroke} strokeWidth={sw} />;
  return <circle r={NODE_R} fill={fill} stroke={stroke} strokeWidth={sw} />;
}
function NodeIcon({ n }: { n: Positioned }) {
  const s = 14; const o = -s / 2;
  const c = n.type === 'internet' ? 'var(--text-1)' : '#0b0f14';
  if (n.type === 'internet')          return <Globe  x={o} y={o} width={s} height={s} color={c} />;
  if (n.type === 'cloud')             return <Cloud  x={o} y={o} width={s} height={s} color={c} />;
  if (n.type === 'container')         return <Box    x={o} y={o} width={s} height={s} color={c} />;
  if (n.type === 'domain_controller') return <Crown  x={o} y={o} width={s} height={s} color={c} />;
  return <Cpu x={o} y={o} width={s} height={s} color={c} />;
}

// ── Node detail drawer ──────────────────────────────────────────────────────
function NodeDetail({ node, edges, graph, onClose, onToast }: {
  node: Positioned;
  edges: AttackPathEdge[];
  graph: AttackPathGraph;
  onClose: () => void;
  onToast: (m: string) => void;
}) {
  const [tab, setTab] = useState<'host' | 'security' | 'identity' | 'actions'>('host');

  const inEdges  = edges.filter(e => e.target === node.id);
  const outEdges = edges.filter(e => e.source === node.id);

  const tabs = [
    { id: 'host',     label: 'Host',     icon: Server   },
    { id: 'security', label: 'Security', icon: Shield   },
    { id: 'identity', label: 'Identity', icon: Users    },
    { id: 'actions',  label: 'Actions',  icon: Zap      },
  ] as const;

  const actions = [
    { label: 'Isolate Host',     icon: Lock,        color: 'var(--red)',    fn: () => onToast('Isolation command sent') },
    { label: 'Scan Endpoint',    icon: ScanLine,    color: 'var(--accent)', fn: () => onToast('Scan queued') },
    { label: 'Disable User',     icon: Power,       color: 'var(--orange)', fn: () => onToast('User disable request sent') },
    { label: 'Block IP',         icon: Shield,      color: 'var(--red)',    fn: () => onToast('Firewall rule pushed') },
    { label: 'Push FW Rule',     icon: Server,      color: 'var(--orange)', fn: () => onToast('Firewall rule created') },
    { label: 'Run Playbook',     icon: Play,        color: 'var(--accent)', fn: () => onToast('Playbook triggered') },
    { label: 'Open Incident',    icon: AlertCircle, color: 'var(--red)',    fn: () => onToast('Incident created') },
    { label: 'Patch Host',       icon: Wrench,      color: 'var(--green)',  fn: () => onToast('Patch job scheduled') },
    { label: 'Remove Privilege', icon: Crown,       color: 'var(--orange)', fn: () => onToast('Privilege removal queued') },
    { label: 'Hunt IOC',         icon: Crosshair,   color: 'var(--accent)', fn: () => onToast('IOC hunt started') },
  ] as { label: string; icon: any; color: string; fn: () => void }[];

  return (
    <div className="fixed inset-0 z-50 flex" onClick={onClose}>
      <div className="flex-1" />
      <div className="w-full max-w-md h-full overflow-y-auto shadow-2xl"
        style={{ background: 'var(--bg-1)', borderLeft: '1px solid var(--border)' }}
        onClick={e => e.stopPropagation()}>

        <div className="sticky top-0 flex items-center gap-3 px-5 py-4 z-10"
          style={{ background: 'var(--bg-1)', borderBottom: '1px solid var(--border)' }}>
          <div className="h-8 w-8 rounded-xl flex items-center justify-center shrink-0"
            style={{ background: (RISK_FILL[node.risk_level] || '#64748b') + '22', border: `1px solid ${RISK_FILL[node.risk_level] || '#64748b'}55` }}>
            <NodeIcon n={node} />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-bold truncate" style={{ color: 'var(--text-1)' }}>
              {node.type === 'internet' ? 'Internet (Entry Point)' : (node.hostname || node.id)}
            </p>
            <div className="flex items-center gap-2 mt-0.5 flex-wrap">
              <span className={sevClass(node.risk_level)} style={{ fontSize: 10 }}>{node.risk_level}</span>
              {node.exposed && <span className="text-[10px]" style={{ color: 'var(--orange)' }}>internet-facing</span>}
              {node.is_chokepoint && <span className="text-[10px] font-bold" style={{ color: '#a78bfa' }}>⚡ Choke Point</span>}
              {node.has_kev && <span className="text-[10px] font-bold" style={{ color: 'var(--red)' }}>KEV</span>}
            </div>
          </div>
          <button onClick={onClose} style={{ color: 'var(--text-3)' }}><X className="h-4 w-4" /></button>
        </div>

        <div className="flex border-b overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
          {tabs.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className="flex items-center gap-1.5 px-3 py-2.5 text-[11px] font-medium whitespace-nowrap shrink-0 transition-colors"
              style={{ color: tab === t.id ? 'var(--accent)' : 'var(--text-3)', borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent' }}>
              <t.icon className="h-3 w-3" /> {t.label}
            </button>
          ))}
        </div>

        <div className="p-5 space-y-3">
          {/* Host tab */}
          {tab === 'host' && (
            <>
              <div className="grid grid-cols-2 gap-2">
                {[
                  { label: 'Hostname',      val: node.hostname || '—' },
                  { label: 'Type',          val: node.type.replace('_', ' ') },
                  { label: 'Risk Score',    val: `${node.risk_score}/100` },
                  { label: 'Priv Level',    val: node.priv_level || '—' },
                  { label: 'Blast Radius',  val: String(node.blast_radius ?? '—') },
                  { label: 'Pivot Cost',    val: String(node.compromise_cost) },
                  { label: 'Open Alerts',   val: String(node.open_alert_count) },
                  { label: 'Max EPSS',      val: node.max_epss > 0 ? `${(node.max_epss * 100).toFixed(1)}%` : '—' },
                ].map(({ label, val }) => (
                  <div key={label} className="rounded-xl p-3" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <p className="text-[10px] mb-0.5" style={{ color: 'var(--text-3)' }}>{label}</p>
                    <p className="text-xs mono font-medium" style={{ color: 'var(--text-1)' }}>{val}</p>
                  </div>
                ))}
              </div>
              <div>
                <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Inbound ({inEdges.length}) → Outbound ({outEdges.length})</p>
                <div className="space-y-1">
                  {[...inEdges.slice(0,4), ...outEdges.slice(0,4)].map((e, i) => {
                    const dir = e.target === node.id ? '←' : '→';
                    const color = EDGE_COLOR[e.kind] || 'var(--text-3)';
                    return (
                      <div key={i} className="flex items-center gap-2 px-3 py-2 rounded-lg text-[11px]"
                        style={{ background: 'var(--bg-0)', border: `1px solid ${color}33` }}>
                        <span style={{ color }}>{dir}</span>
                        <span className="mono flex-1 truncate" style={{ color: 'var(--text-1)' }}>{e.technique_name || EDGE_LABEL[e.kind]}</span>
                        {e.technique_id && <span className="mono text-[10px]" style={{ color: 'var(--text-3)' }}>{e.technique_id}</span>}
                      </div>
                    );
                  })}
                </div>
              </div>
              {node.agent_id && (
                <Link href={`/agents/${node.agent_id}`}
                  className="flex items-center gap-1.5 text-xs px-3 py-2 rounded-xl w-full justify-center"
                  style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)', color: 'var(--accent)' }}>
                  Full Agent Detail <ArrowRight className="h-3.5 w-3.5" />
                </Link>
              )}
            </>
          )}

          {/* Security tab */}
          {tab === 'security' && (
            <div className="space-y-2">
              <div className="rounded-xl p-3" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Risk Score</p>
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: 'var(--bg-0)' }}>
                    <div className="h-full rounded-full" style={{ width: `${node.risk_score}%`, background: RISK_FILL[node.risk_level] || 'var(--accent)' }} />
                  </div>
                  <span className="font-bold tabular-nums text-sm" style={{ color: RISK_FILL[node.risk_level] || 'var(--text-1)' }}>{node.risk_score}</span>
                </div>
              </div>
              {[
                { label: 'Has KEV CVE',       val: node.has_kev ? `Yes (${node.kev_count})` : 'No', bad: node.has_kev },
                { label: 'Max EPSS Score',    val: node.max_epss > 0 ? `${(node.max_epss * 100).toFixed(1)}%` : 'Low', bad: node.max_epss > 0.5 },
                { label: 'Internet Exposed',  val: node.exposed ? 'Yes' : 'No', bad: node.exposed },
                { label: 'Open Alerts',       val: String(node.open_alert_count), bad: node.open_alert_count > 0 },
                { label: 'Privilege Level',   val: node.priv_level || 'Standard', bad: node.priv_level === 'admin' },
                { label: 'Is Choke Point',    val: node.is_chokepoint ? 'Yes' : 'No', bad: node.is_chokepoint },
              ].map(({ label, val, bad }) => (
                <div key={label} className="flex items-center justify-between px-3 py-2 rounded-lg"
                  style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                  <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{label}</span>
                  <span className="text-[11px] font-medium" style={{ color: bad ? 'var(--red)' : 'var(--green)' }}>{val}</span>
                </div>
              ))}
              <p className="text-[10px] font-bold uppercase tracking-wider mt-3 mb-2" style={{ color: 'var(--text-3)' }}>
                Privilege Escalation Paths
              </p>
              <div className="flex flex-wrap gap-1.5">
                {PRIV_ESC_TYPES.slice(0, 6).map(p => (
                  <span key={p} className="px-2 py-1 rounded-lg text-[10px]"
                    style={{ background: 'rgba(167,139,250,0.1)', color: '#a78bfa', border: '1px solid rgba(167,139,250,0.3)' }}>
                    {p}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Identity tab */}
          {tab === 'identity' && (
            <div className="space-y-3">
              <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Identity relationships for this node (BloodHound-style).</p>
              {[
                { label: 'Logged-in Users',     val: '—', icon: Users },
                { label: 'Privileged Accounts', val: node.priv_level || '—', icon: Crown },
                { label: 'AD Groups',           val: '—', icon: GitFork },
                { label: 'Trust Relationships', val: inEdges.length + ' inbound', icon: Lock },
                { label: 'Service Accounts',    val: '—', icon: Server },
                { label: 'Cloud Roles',         val: node.type === 'cloud' ? 'IAM Role' : '—', icon: Cloud },
                { label: 'Shared Credentials',  val: '—', icon: Hash },
                { label: 'Certificates',        val: '—', icon: Shield },
              ].map(({ label, val, icon: Icon }) => (
                <div key={label} className="flex items-center gap-3 px-3 py-2 rounded-lg"
                  style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                  <Icon className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />
                  <span className="text-[11px] flex-1" style={{ color: 'var(--text-3)' }}>{label}</span>
                  <span className="mono text-[11px] font-medium" style={{ color: 'var(--text-1)' }}>{val}</span>
                </div>
              ))}
            </div>
          )}

          {/* Actions tab */}
          {tab === 'actions' && (
            <div className="grid grid-cols-2 gap-2">
              {actions.map(({ label, icon: Icon, color, fn }) => (
                <button key={label} onClick={fn}
                  className="flex flex-col items-center gap-2 p-3 rounded-xl text-[11px] font-medium transition-all hover:opacity-80"
                  style={{ background: 'var(--bg-0)', border: `1px solid ${color}44`, color }}>
                  <Icon className="h-4 w-4" />
                  {label}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Main page ───────────────────────────────────────────────────────────────
export default function AttackPathPage() {
  const [graph,          setGraph]          = useState<AttackPathGraph | null>(null);
  const [loading,        setLoading]        = useState(true);
  const [refreshing,     setRefreshing]     = useState(false);
  const [selectedPath,   setSelectedPath]   = useState(0);
  const [hovered,        setHovered]        = useState<Positioned | null>(null);
  const [hoveredEdge,    setHoveredEdge]    = useState<{ x: number; y: number; edge: AttackPathEdge } | null>(null);
  const [pathTypeFilter, setPathTypeFilter] = useState<PathTypeFilter>('all');
  const [sideTab,        setSideTab]        = useState<SideTab>('Paths');
  const [clickedNode,    setClickedNode]    = useState<Positioned | null>(null);
  const [kcModel,        setKcModel]        = useState<KillChainModel>('mitre');
  const [simMode,        setSimMode]        = useState(false);
  const [simStart,       setSimStart]       = useState<string | null>(null);
  const [simReachable,   setSimReachable]   = useState<Set<string>>(new Set());
  const [replayStep,     setReplayStep]     = useState(0);
  const [toast,          setToast]          = useState<string | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

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

  // BFS layout
  const layout = useMemo(() => {
    if (!graph) return null;
    const adj = new Map<string, string[]>();
    graph.edges.forEach(e => {
      adj.set(e.source, [...(adj.get(e.source) || []), e.target]);
      adj.set(e.target, [...(adj.get(e.target) || []), e.source]);
    });
    const depth = new Map<string, number>();
    depth.set('internet', 0);
    const q = ['internet'];
    while (q.length > 0) {
      const cur = q.shift()!;
      for (const nxt of adj.get(cur) || []) {
        if (!depth.has(nxt)) { depth.set(nxt, (depth.get(cur) || 0) + 1); q.push(nxt); }
      }
    }
    const maxD = Math.max(0, ...Array.from(depth.values()));
    const isoD = maxD + 1;
    const cols = new Map<number, AttackPathNode[]>();
    graph.nodes.forEach(n => {
      const d = depth.get(n.id) ?? isoD;
      cols.set(d, [...(cols.get(d) || []), n]);
    });
    const pos: Positioned[] = [];
    cols.forEach((nodesInCol, col) => {
      nodesInCol.forEach((n, i) => { pos.push({ ...n, x: PAD + col * COL_WIDTH, y: PAD + i * ROW_HEIGHT }); });
    });
    const maxCol  = Math.max(1, ...Array.from(cols.keys()));
    const maxRows = Math.max(1, ...Array.from(cols.values()).map(c => c.length));
    return { nodes: pos, byId: new Map(pos.map(n => [n.id, n])), width: PAD * 2 + (maxCol + 1) * COL_WIDTH, height: PAD * 2 + maxRows * ROW_HEIGHT };
  }, [graph]);

  // Highlighted edge keys for selected path
  const hlEdgeKeys = useMemo(() => {
    if (!graph || !graph.top_paths[selectedPath]) return new Set<string>();
    const hops = graph.top_paths[selectedPath].hops;
    const s = new Set<string>();
    for (let i = 0; i < hops.length - 1; i++) s.add(`${hops[i]}|${hops[i + 1]}`);
    return s;
  }, [graph, selectedPath]);

  // Highlighted nodes for replay
  const replayNodes = useMemo(() => {
    const p = graph?.top_paths[selectedPath];
    if (!p) return new Set<string>();
    return new Set(p.hops.slice(0, replayStep + 1));
  }, [graph, selectedPath, replayStep]);

  // Simulation BFS
  const runSimulation = useCallback((startId: string) => {
    if (!graph) return;
    const adj = new Map<string, string[]>();
    graph.edges.forEach(e => { adj.set(e.source, [...(adj.get(e.source) || []), e.target]); });
    const visited = new Set<string>([startId]);
    const q = [startId];
    while (q.length > 0) {
      const cur = q.shift()!;
      for (const nxt of adj.get(cur) || []) { if (!visited.has(nxt)) { visited.add(nxt); q.push(nxt); } }
    }
    setSimReachable(visited);
    notify(`Simulation: ${visited.size} assets reachable from ${layout?.byId.get(startId)?.hostname || startId}`);
  }, [graph, layout]);

  const filteredPaths  = useMemo(() => {
    if (!graph) return [];
    if (pathTypeFilter === 'all') return graph.top_paths;
    return graph.top_paths.filter(p => p.path_type === pathTypeFilter);
  }, [graph, pathTypeFilter]);

  const chokePoints  = useMemo(() => graph?.nodes.filter(n => n.is_chokepoint).sort((a, b) => (b.blast_radius ?? 0) - (a.blast_radius ?? 0)) ?? [], [graph]);
  const blastRanking = useMemo(() => [...(graph?.nodes ?? [])].filter(n => n.type !== 'internet').sort((a, b) => (b.blast_radius ?? 0) - (a.blast_radius ?? 0)), [graph]);

  const remediationSteps = useMemo(() => {
    if (!graph) return [];
    const steps: { priority: number; action: string; reduction: number; type: string }[] = [];
    chokePoints.slice(0, 4).forEach((n, i) => {
      const r = Math.min(95, Math.round(((n.blast_radius || 0) / Math.max(1, graph.edges.length)) * 180 + 15));
      steps.push({ priority: i + 1, action: `Harden ${n.hostname || n.id} (${n.type.replace('_', ' ')})`, reduction: r, type: 'harden' });
    });
    graph.nodes.filter(n => n.has_kev).slice(0, 3).forEach((n, i) => {
      steps.push({ priority: chokePoints.length + i + 1, action: `Patch ${n.kev_count} KEV CVE(s) on ${n.hostname || n.id}`, reduction: Math.min(60, 15 + n.kev_count * 8), type: 'patch' });
    });
    if (graph.nodes.some(n => n.exposed)) steps.push({ priority: steps.length + 1, action: 'Enable MFA for all internet-facing hosts', reduction: 35, type: 'mfa' });
    if (graph.nodes.some(n => n.priv_level === 'admin')) steps.push({ priority: steps.length + 1, action: 'Remove unnecessary Local Admin rights', reduction: 31, type: 'priv' });
    return steps.sort((a, b) => b.reduction - a.reduction).slice(0, 8);
  }, [graph, chokePoints]);

  const aiInsights = useMemo(() => {
    if (!graph || !layout) return [];
    const ins: { sev: string; text: string }[] = [];
    const dcPaths = graph.top_paths.filter(p => {
      const last = layout.byId.get(p.hops[p.hops.length - 1]);
      return last?.type === 'domain_controller';
    });
    if (dcPaths.length > 0) {
      const sh = dcPaths.reduce((m, p) => p.hops.length < m.hops.length ? p : m, dcPaths[0]);
      ins.push({ sev: 'critical', text: `Shortest path to Domain Admin is ${sh.hops.length - 1} hop${sh.hops.length !== 2 ? 's' : ''} — via ${sh.hops.slice(1, -1).map(h => layout.byId.get(h)?.hostname || h).join(' → ')}.` });
    }
    if (chokePoints.length > 0) {
      const top = chokePoints[0];
      ins.push({ sev: 'high', text: `Securing ${top.hostname || top.id} eliminates the most attack paths (blast radius: ${top.blast_radius} assets).` });
    }
    if (graph.nodes.some(n => n.has_kev))
      ins.push({ sev: 'high', text: `${graph.nodes.filter(n => n.has_kev).length} host(s) have Known Exploited Vulnerabilities (KEV) — these are actively exploited in the wild.` });
    if (graph.nodes.some(n => n.exposed))
      ins.push({ sev: 'medium', text: `${graph.nodes.filter(n => n.exposed).length} internet-facing asset(s) detected — the attack surface reduction should start here.` });
    if (remediationSteps.length > 0)
      ins.push({ sev: 'low', text: `Top remediation action "${remediationSteps[0].action}" would eliminate ~${remediationSteps[0].reduction}% of attack paths.` });
    if (ins.length === 0)
      ins.push({ sev: 'low', text: 'No critical attack paths detected. Maintain regular scanning cadence.' });
    return ins;
  }, [graph, layout, chokePoints, remediationSteps]);

  const exposureData = useMemo(() => ({
    internetFacing: graph?.nodes.filter(n => n.exposed) ?? [],
    kevNodes:       graph?.nodes.filter(n => n.has_kev) ?? [],
    alerting:       graph?.nodes.filter(n => n.open_alert_count > 0) ?? [],
    chokepoints:    graph?.nodes.filter(n => n.is_chokepoint) ?? [],
    highRisk:       graph?.nodes.filter(n => n.risk_level === 'critical' || n.risk_level === 'high') ?? [],
  }), [graph]);

  const selectedPathData = graph?.top_paths[selectedPath];
  const activeKCPhases   = new Set(selectedPathData?.kill_chain_phases || []);
  const totalNodes       = graph ? graph.nodes.filter(n => n.type !== 'internet').length : 0;
  const kcPhases         = KILL_CHAIN_MODELS[kcModel];

  const getBusinessImpact = (n: AttackPathNode) => {
    const mul = n.type === 'domain_controller' ? 5_000_000 : n.type === 'cloud' ? 3_000_000 : n.type === 'container' ? 1_500_000 : 750_000;
    return ((n.blast_radius || 0) * mul);
  };

  const sevColor: Record<string, string> = { critical: '#f85149', high: '#fb923c', medium: '#fbbf24', low: 'var(--green)' };

  if (loading) {
    return (
      <RootLayout title="Attack Paths" subtitle="Enterprise attack graph — BloodHound-style" onRefresh={() => load(true)} refreshing={refreshing}>
        <div className="py-14 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
      </RootLayout>
    );
  }

  if (!graph || totalNodes === 0) {
    return (
      <RootLayout title="Attack Paths" subtitle="Enterprise attack graph — BloodHound-style" onRefresh={() => load(true)} refreshing={refreshing}>
        <div className="g-panel py-14 text-center">
          <Crosshair className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
          <p className="text-sm" style={{ color: 'var(--text-2)' }}>No agents in this tenant yet.</p>
        </div>
      </RootLayout>
    );
  }

  return (
    <RootLayout title="Attack Paths"
      subtitle="BloodHound-style graph — lateral movement, privilege escalation, cloud pivots, identity paths"
      onRefresh={() => load(true)} refreshing={refreshing}>
      <div className="space-y-4">

        {/* Toast */}
        {toast && (
          <div className="fixed bottom-5 right-5 z-[9999] g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)' }}>
            {toast}
          </div>
        )}

        {/* Entry point warning */}
        {!graph.has_entry_point && (
          <div className="g-panel px-4 py-3 text-xs flex items-center gap-2" style={{ color: 'var(--text-2)' }}>
            <ShieldAlert className="h-4 w-4 shrink-0" style={{ color: 'var(--yellow)' }} />
            No internet-facing entry point detected — run agent connection collection on internet-facing hosts to surface attack paths.
          </div>
        )}

        {/* Kill chain strip + model selector */}
        <div className="g-panel px-4 py-3">
          <div className="flex items-center justify-between mb-2.5 gap-3 flex-wrap">
            <p className="text-[10px] font-bold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
              {kcModel === 'mitre' ? 'MITRE ATT&CK' : kcModel === 'lockheed' ? 'Lockheed Kill Chain' : 'Diamond Model'} —{' '}
              {selectedPathData ? `Path ${selectedPath + 1}: ${selectedPathData.target_hostname}` : 'No path selected'}
            </p>
            <div className="flex gap-1">
              {(['mitre', 'lockheed', 'diamond'] as KillChainModel[]).map(m => (
                <button key={m} onClick={() => setKcModel(m)}
                  className="px-2.5 py-1 rounded-lg text-[10px] font-medium capitalize"
                  style={{
                    background: kcModel === m ? 'var(--accent-glow)' : 'var(--glass-bg)',
                    border: `1px solid ${kcModel === m ? 'var(--accent-border)' : 'var(--border)'}`,
                    color: kcModel === m ? 'var(--accent)' : 'var(--text-3)',
                  }}>
                  {m === 'mitre' ? 'MITRE' : m === 'lockheed' ? 'Lockheed' : 'Diamond'}
                </button>
              ))}
            </div>
          </div>
          <div className="flex items-start gap-0 overflow-x-auto pb-1">
            {kcPhases.map((phase, i) => {
              const active = activeKCPhases.has(phase.id);
              return (
                <div key={phase.id} className="flex items-center shrink-0">
                  <div className="flex flex-col items-center gap-1.5">
                    <div className="w-3 h-3 rounded-full transition-all" style={{
                      background: active ? '#f85149' : 'var(--bg-1)',
                      border: `2px solid ${active ? '#f85149' : 'var(--border)'}`,
                      boxShadow: active ? '0 0 10px rgba(248,81,73,0.55)' : 'none',
                    }} />
                    <span className="text-[9px] whitespace-nowrap" style={{ color: active ? 'var(--text-1)' : 'var(--text-3)' }}>{phase.label}</span>
                  </div>
                  {i < kcPhases.length - 1 && <div className="w-8 h-px shrink-0 mx-1 mb-4" style={{ background: 'var(--border)' }} />}
                </div>
              );
            })}
          </div>
        </div>

        {/* Attack Replay slider */}
        {selectedPathData && selectedPathData.hops.length > 1 && (
          <div className="g-panel px-4 py-3">
            <div className="flex items-center gap-3 mb-2">
              <Activity className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--accent)' }} />
              <p className="text-[10px] font-bold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
                Attack Replay — Path {selectedPath + 1}
              </p>
              <div className="flex items-center gap-1 ml-auto">
                <button onClick={() => setReplayStep(0)} className="p-1 rounded" style={{ color: 'var(--text-3)' }}><SkipBack className="h-3.5 w-3.5" /></button>
                <button onClick={() => setReplayStep(s => Math.max(0, s - 1))} className="p-1 rounded" style={{ color: 'var(--text-3)' }}>‹</button>
                <button onClick={() => setReplayStep(s => Math.min(selectedPathData.hops.length - 1, s + 1))} className="p-1 rounded" style={{ color: 'var(--text-3)' }}>›</button>
                <button onClick={() => setReplayStep(selectedPathData.hops.length - 1)} className="p-1 rounded" style={{ color: 'var(--text-3)' }}><SkipForward className="h-3.5 w-3.5" /></button>
              </div>
            </div>
            <input type="range" min={0} max={selectedPathData.hops.length - 1} value={replayStep}
              onChange={e => setReplayStep(Number(e.target.value))}
              className="w-full accent-[color:var(--accent)]" />
            <div className="flex items-center justify-between mt-1.5 overflow-x-auto gap-2">
              {selectedPathData.hops.map((h, i) => {
                const node = layout?.byId.get(h);
                const active = i <= replayStep;
                return (
                  <div key={h} className="flex items-center gap-1 shrink-0">
                    <div className="flex flex-col items-center gap-0.5">
                      <div className="w-2 h-2 rounded-full" style={{ background: active ? '#f85149' : 'var(--border)' }} />
                      <span className="text-[9px] whitespace-nowrap" style={{ color: active ? 'var(--text-1)' : 'var(--text-3)' }}>
                        {h === 'internet' ? 'Internet' : (node?.hostname || h).slice(0, 10)}
                      </span>
                    </div>
                    {i < selectedPathData.hops.length - 1 && (
                      <div className="w-4 h-px mx-0.5" style={{ background: i < replayStep ? '#f85149' : 'var(--border)' }} />
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Path type filter + edge legend */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex gap-1 flex-wrap">
            {PATH_TYPE_TABS.map(tab => (
              <button key={tab.key} onClick={() => setPathTypeFilter(tab.key)}
                className="text-xs px-3 py-1.5 rounded-full transition-all"
                style={{
                  background: pathTypeFilter === tab.key ? 'var(--accent)' : 'var(--glass-bg)',
                  color:      pathTypeFilter === tab.key ? '#fff' : 'var(--text-2)',
                  border:     `1px solid ${pathTypeFilter === tab.key ? 'var(--accent)' : 'var(--border)'}`,
                }}>
                {tab.label}
              </button>
            ))}
          </div>
          <div className="ml-auto flex gap-3 items-center flex-wrap">
            <button onClick={() => { setSimMode(v => !v); setSimReachable(new Set()); setSimStart(null); }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition-all"
              style={{
                background: simMode ? 'rgba(248,81,73,0.12)' : 'var(--glass-bg)',
                border: `1px solid ${simMode ? 'rgba(248,81,73,0.4)' : 'var(--border)'}`,
                color: simMode ? '#f85149' : 'var(--text-2)',
              }}>
              <Play className="h-3.5 w-3.5" />
              {simMode ? 'Simulation ON — click start node' : 'Simulate'}
            </button>
          </div>
        </div>

        {/* Simulation banner */}
        {simMode && simReachable.size > 0 && (
          <div className="g-panel px-4 py-3 flex items-center gap-3"
            style={{ border: '1px solid rgba(248,81,73,0.4)', background: 'rgba(248,81,73,0.08)' }}>
            <AlertTriangle className="h-4 w-4 shrink-0" style={{ color: '#f85149' }} />
            <p className="text-xs" style={{ color: 'var(--text-1)' }}>
              Attacker starting from <strong>{layout?.byId.get(simStart!)?.hostname || simStart}</strong> can reach{' '}
              <strong>{simReachable.size}</strong> asset{simReachable.size !== 1 ? 's' : ''}.
              Highlighted nodes are compromisable.
            </p>
            <button onClick={() => { setSimReachable(new Set()); setSimStart(null); }} className="ml-auto" style={{ color: 'var(--text-3)' }}>
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        )}

        {/* Main row: graph + side panel */}
        <div className="flex gap-4 flex-wrap lg:flex-nowrap">

          {/* Graph */}
          <div className="g-panel flex-1 overflow-auto relative" style={{ minHeight: 440, maxHeight: 640 }}>
            {layout && (
              <svg width={layout.width} height={layout.height} style={{ display: 'block' }}>
                <defs>
                  {Object.entries(EDGE_COLOR).map(([kind, color]) => (
                    <marker key={kind} id={`arrow-${kind}`} markerWidth="7" markerHeight="7" refX="5.5" refY="3.5" orient="auto">
                      <path d="M0,0.5 L0,6.5 L7,3.5 z" fill={color} opacity={0.85} />
                    </marker>
                  ))}
                </defs>

                {/* Simulation reachable highlight area */}
                {simReachable.size > 0 && layout.nodes
                  .filter(n => simReachable.has(n.id) && n.id !== simStart)
                  .map(n => (
                    <circle key={`sim-${n.id}`} cx={n.x} cy={n.y} r={NODE_R + 10}
                      fill="rgba(248,81,73,0.08)" stroke="#f85149" strokeWidth={1} strokeDasharray="3 2" />
                  ))
                }

                {/* Edges */}
                {graph.edges.map((e, i) => {
                  const a = layout.byId.get(e.source);
                  const b = layout.byId.get(e.target);
                  if (!a || !b) return null;
                  const hl    = hlEdgeKeys.has(`${e.source}|${e.target}`);
                  const color = EDGE_COLOR[e.kind] || 'var(--border-md)';
                  const pts   = edgePoints(a.x, a.y, b.x, b.y);
                  const mx    = (a.x + b.x) / 2;
                  const my    = (a.y + b.y) / 2;
                  return (
                    <g key={i}>
                      <line x1={pts.x1} y1={pts.y1} x2={pts.x2} y2={pts.y2}
                        stroke={color} strokeWidth={hl ? 3 : 1.5} strokeOpacity={hl ? 1 : 0.45}
                        strokeDasharray={e.kind === 'internet_exposure' ? '5 3' : e.kind === 'container_escape' ? '2 2' : undefined}
                        markerEnd={`url(#arrow-${e.kind})`} />
                      <line x1={pts.x1} y1={pts.y1} x2={pts.x2} y2={pts.y2}
                        stroke="transparent" strokeWidth={14}
                        onMouseEnter={() => setHoveredEdge({ x: mx, y: my, edge: e })}
                        onMouseLeave={() => setHoveredEdge(null)}
                        style={{ cursor: 'crosshair' }} />
                    </g>
                  );
                })}

                {/* Nodes */}
                {layout.nodes.map(n => {
                  const inSim      = simReachable.has(n.id);
                  const isStart    = n.id === simStart;
                  const inReplay   = replayStep > 0 && replayNodes.has(n.id);
                  const dimForSim  = simReachable.size > 0 && !inSim;
                  return (
                    <g key={n.id} transform={`translate(${n.x},${n.y})`}
                      style={{ cursor: simMode ? 'crosshair' : 'pointer', opacity: dimForSim ? 0.25 : 1 }}
                      onClick={() => {
                        if (simMode) {
                          setSimStart(n.id);
                          runSimulation(n.id);
                        } else {
                          setClickedNode(n);
                        }
                      }}
                      onMouseEnter={() => setHovered(n)} onMouseLeave={() => setHovered(null)}>

                      {/* Chokepoint pulse */}
                      {n.is_chokepoint && (
                        <circle r={NODE_R + 4} fill="none" stroke="#a78bfa" strokeWidth={1.5}>
                          <animate attributeName="r"       from={NODE_R + 4} to={NODE_R + 16} dur="1.8s" repeatCount="indefinite" />
                          <animate attributeName="opacity" from="0.8"        to="0"           dur="1.8s" repeatCount="indefinite" />
                        </circle>
                      )}
                      {/* Replay ring */}
                      {inReplay && (
                        <circle r={NODE_R + 6} fill="none" stroke="#f85149" strokeWidth={2} opacity={0.6}>
                          <animate attributeName="opacity" values="0.6;0.1;0.6" dur="0.9s" repeatCount="indefinite" />
                        </circle>
                      )}
                      {/* Simulation start marker */}
                      {isStart && <circle r={NODE_R + 8} fill="none" stroke="#f85149" strokeWidth={2} />}

                      <NodeShape n={n} sim={inSim && !isStart} />
                      <NodeIcon  n={n} />

                      {n.has_kev && (
                        <g transform="translate(14,-14)">
                          <circle r={7} fill="#f85149" />
                          <Skull x={-4.5} y={-4.5} width={9} height={9} color="#fff" />
                        </g>
                      )}
                      {n.open_alert_count > 0 && (
                        <g transform="translate(-15,-14)">
                          <circle r={6} fill="#fb923c" />
                          <text textAnchor="middle" dominantBaseline="central" fontSize={7} fill="#fff" fontWeight="bold">
                            {n.open_alert_count > 9 ? '9+' : n.open_alert_count}
                          </text>
                        </g>
                      )}
                      {n.is_chokepoint && (
                        <g transform="translate(14,14)">
                          <circle r={6} fill="#a78bfa" />
                          <Zap x={-3.5} y={-3.5} width={7} height={7} color="#fff" />
                        </g>
                      )}
                      {isStart && (
                        <g transform="translate(0,-NODE_R - 12)">
                          <text textAnchor="middle" fontSize={9} fill="#f85149" fontWeight="bold">START</text>
                        </g>
                      )}

                      <text x={0} y={labelY(n)} textAnchor="middle" fontSize={10} fill="var(--text-2)">
                        {n.type === 'internet' ? 'Internet' : (n.hostname || `agent-${n.agent_id}`)}
                      </text>
                      {n.kill_chain_phase && n.type !== 'internet' && (
                        <text x={0} y={labelY(n) + 12} textAnchor="middle" fontSize={8.5} fill="var(--text-3)">
                          {n.kill_chain_phase.replace(/_/g, ' ')}
                        </text>
                      )}
                    </g>
                  );
                })}

                {/* Edge hover tooltip */}
                {hoveredEdge && (() => {
                  const e = hoveredEdge.edge;
                  return (
                    <g transform={`translate(${hoveredEdge.x},${hoveredEdge.y})`} style={{ pointerEvents: 'none' }}>
                      <rect x={-110} y={-42} width={220} height={68} rx={8}
                        fill="var(--bg-0)" stroke={EDGE_COLOR[e.kind] || 'var(--border)'} strokeWidth={1.2} />
                      {e.technique_id && (
                        <text x={0} y={-26} textAnchor="middle" fontSize={9} fill="var(--text-3)" fontFamily="monospace">
                          {e.technique_id}
                        </text>
                      )}
                      <text x={0} y={-11} textAnchor="middle" fontSize={10} fill="var(--text-1)" fontWeight="600">
                        {e.technique_name || EDGE_LABEL[e.kind]}
                      </text>
                      <text x={0} y={4} textAnchor="middle" fontSize={8.5} fill={EDGE_COLOR[e.kind] || 'var(--text-3)'}>
                        {EDGE_LABEL[e.kind]}
                      </text>
                      {e.description && (
                        <text x={0} y={18} textAnchor="middle" fontSize={8} fill="var(--text-3)">{e.description.slice(0, 32)}</text>
                      )}
                    </g>
                  );
                })()}
              </svg>
            )}
          </div>

          {/* Side panel */}
          <div className="g-panel shrink-0 flex flex-col" style={{ width: 340, minHeight: 440 }}>
            <div className="flex border-b shrink-0 overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
              {SIDE_TABS.map(t => (
                <button key={t} onClick={() => setSideTab(t)}
                  className="shrink-0 text-[9px] font-semibold uppercase tracking-wide px-2.5 py-3 transition-colors whitespace-nowrap"
                  style={{ color: sideTab === t ? 'var(--accent)' : 'var(--text-3)', borderBottom: sideTab === t ? '2px solid var(--accent)' : '2px solid transparent' }}>
                  {t}
                </button>
              ))}
            </div>

            <div className="flex-1 overflow-y-auto p-3 space-y-2">

              {/* Paths */}
              {sideTab === 'Paths' && (
                filteredPaths.length === 0
                  ? <p className="text-xs py-10 text-center" style={{ color: 'var(--text-3)' }}>No paths match this filter.</p>
                  : filteredPaths.map((p, i) => {
                      const globalIdx = graph.top_paths.indexOf(p);
                      const ptColor: Record<string, string> = { lateral: '#38bdf8', priv_esc: '#a78bfa', cloud: '#2dd4bf', container: '#f85149', identity: '#e879f9', vpn: '#059669' };
                      const c = p.path_type ? (ptColor[p.path_type] || 'var(--text-3)') : 'var(--text-3)';
                      return (
                        <button key={i} onClick={() => { setSelectedPath(globalIdx); setReplayStep(0); }}
                          className="w-full text-left rounded-xl p-3 transition-all"
                          style={{ background: selectedPath === globalIdx ? 'var(--accent-glow)' : 'var(--glass-bg)', border: `1px solid ${selectedPath === globalIdx ? 'var(--accent-border)' : 'var(--border)'}` }}>
                          <div className="flex items-center justify-between mb-1.5">
                            <div className="flex items-center gap-1.5">
                              <span className="text-[10px] font-bold" style={{ color: 'var(--text-3)' }}>PATH {globalIdx + 1}</span>
                              {p.path_type && (
                                <span className="text-[9px] px-1.5 py-0.5 rounded" style={{ background: `${c}22`, color: c }}>
                                  {p.path_type.replace('_', ' ')}
                                </span>
                              )}
                            </div>
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
                            score {p.score} · cost {p.total_cost} · {p.hops.length - 1} hop{p.hops.length !== 2 ? 's' : ''}
                          </p>
                        </button>
                      );
                    })
              )}

              {/* Attack Chain */}
              {sideTab === 'Chain' && (
                selectedPathData
                  ? (
                    <div className="space-y-0">
                      <p className="text-[10px] mb-3" style={{ color: 'var(--text-3)' }}>
                        Attack Chain — Path {selectedPath + 1} → {selectedPathData.target_hostname}
                      </p>
                      {selectedPathData.hops.map((h, i) => {
                        const node = layout?.byId.get(h);
                        const edge = i < selectedPathData.hops.length - 1
                          ? graph.edges.find(e => e.source === h && e.target === selectedPathData.hops[i + 1])
                          : null;
                        const edgeColor = edge ? (EDGE_COLOR[edge.kind] || 'var(--border)') : 'var(--border)';
                        return (
                          <div key={h}>
                            <button onClick={() => node && setClickedNode(node)}
                              className="w-full text-left flex items-center gap-3 p-2.5 rounded-xl transition-all hover:opacity-80"
                              style={{ background: 'var(--glass-bg)', border: `1px solid ${RISK_FILL[(node?.risk_level as string) || 'unknown']}44` }}>
                              <div className="h-8 w-8 rounded-xl flex items-center justify-center shrink-0"
                                style={{ background: (RISK_FILL[(node?.risk_level as string) || 'unknown']) + '22' }}>
                                <span className="text-[10px] font-bold" style={{ color: RISK_FILL[(node?.risk_level as string) || 'unknown'] }}>{i + 1}</span>
                              </div>
                              <div className="flex-1 min-w-0">
                                <p className="text-xs font-semibold truncate" style={{ color: 'var(--text-1)' }}>
                                  {h === 'internet' ? '🌐 Internet' : (node?.hostname || h)}
                                </p>
                                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                                  {node?.type?.replace('_', ' ') || ''}{node?.priv_level ? ` · ${node.priv_level}` : ''}
                                </p>
                              </div>
                              {node?.risk_level && node.risk_level !== 'unknown' && (
                                <span className={sevClass(node.risk_level)} style={{ fontSize: 9 }}>{node.risk_level}</span>
                              )}
                            </button>
                            {edge && (
                              <div className="flex items-center gap-2 py-1.5 pl-5">
                                <div className="w-px h-4" style={{ background: edgeColor }} />
                                <span className="text-[10px] px-2 py-0.5 rounded"
                                  style={{ background: edgeColor + '22', color: edgeColor }}>
                                  {edge.technique_id ? `${edge.technique_id} · ` : ''}{edge.technique_name || EDGE_LABEL[edge.kind]}
                                </span>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )
                  : <p className="text-xs py-10 text-center" style={{ color: 'var(--text-3)' }}>Select a path from the Paths tab.</p>
              )}

              {/* MITRE */}
              {sideTab === 'MITRE' && (
                selectedPathData?.techniques?.length
                  ? (
                    <div className="space-y-2">
                      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                        {selectedPathData.techniques.length} technique(s) in Path {selectedPath + 1}
                      </p>
                      {selectedPathData.techniques.map((t, i) => (
                        <div key={i} className="rounded-xl p-3" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                          <div className="flex items-start gap-2 mb-2">
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded shrink-0"
                              style={{ background: '#a78bfa22', color: '#a78bfa' }}>{t.id}</span>
                            <span className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{t.name}</span>
                          </div>
                          <div className="grid grid-cols-2 gap-1.5">
                            {[
                              { label: 'Tactic',   val: 'Unknown' },
                              { label: 'Sub-tech',  val: '—' },
                              { label: 'Detection', val: 'Partial', ok: true },
                              { label: 'Prevention',val: 'Partial', ok: true },
                            ].map(({ label, val, ok }) => (
                              <div key={label} className="rounded px-2 py-1" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                                <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>{label}</p>
                                <p className="text-[10px] font-medium" style={{ color: ok ? 'var(--green)' : 'var(--text-2)' }}>{val}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      ))}
                      <a href="https://attack.mitre.org" target="_blank" rel="noopener noreferrer"
                        className="text-[10px] underline block pt-1" style={{ color: 'var(--accent)' }}>
                        View on MITRE ATT&amp;CK →
                      </a>
                    </div>
                  )
                  : <p className="text-xs py-10 text-center" style={{ color: 'var(--text-3)' }}>No MITRE data for this path.</p>
              )}

              {/* Choke Points */}
              {sideTab === 'Choke Points' && (
                chokePoints.length === 0
                  ? <p className="text-xs py-10 text-center" style={{ color: 'var(--text-3)' }}>No choke points identified.</p>
                  : (
                    <div className="space-y-2">
                      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                        Securing these nodes eliminates the most attack paths.
                      </p>
                      {chokePoints.map(n => {
                        const pathsThrough = graph.top_paths.filter(p => p.hops.includes(n.id)).length;
                        return (
                          <div key={n.id} className="rounded-xl p-3 cursor-pointer transition-colors"
                            style={{ background: '#a78bfa11', border: '1px solid #a78bfa44' }}
                            onClick={() => { const pn = layout?.byId.get(n.id); if (pn) setClickedNode(pn); }}>
                            <div className="flex items-center justify-between mb-1.5">
                              <div className="flex items-center gap-2">
                                <Zap className="h-3.5 w-3.5 shrink-0" style={{ color: '#a78bfa' }} />
                                <span className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{n.hostname || n.id}</span>
                              </div>
                              <span className={sevClass(n.risk_level)} style={{ fontSize: 10 }}>{n.risk_level}</span>
                            </div>
                            <p className="text-[10px] font-medium mb-1" style={{ color: '#a78bfa' }}>
                              Securing this eliminates paths through {pathsThrough} route{pathsThrough !== 1 ? 's' : ''}.
                            </p>
                            <div className="flex gap-3 text-[10px]" style={{ color: 'var(--text-3)' }}>
                              <span>Blast radius <strong style={{ color: '#a78bfa' }}>{n.blast_radius}</strong></span>
                              <span className="capitalize">{n.type.replace('_', ' ')}</span>
                              {n.priv_level && <span>priv: {n.priv_level}</span>}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )
              )}

              {/* Blast Radius */}
              {sideTab === 'Blast Radius' && (
                <div className="space-y-2">
                  <p className="text-[10px] mb-2" style={{ color: 'var(--text-3)' }}>
                    Assets reachable if each host is compromised. Business impact estimated.
                  </p>
                  {blastRanking.map((n, i) => {
                    const pct    = Math.min(100, ((n.blast_radius ?? 0) / Math.max(1, blastRanking[0]?.blast_radius ?? 1)) * 100);
                    const impact = getBusinessImpact(n);
                    return (
                      <div key={n.id} className="rounded-xl p-3 cursor-pointer"
                        style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}
                        onClick={() => { const pn = layout?.byId.get(n.id); if (pn) setClickedNode(pn); }}>
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <span className="text-[9px] w-4 text-right shrink-0" style={{ color: 'var(--text-3)' }}>{i + 1}</span>
                            <span className="text-[11px] font-medium truncate" style={{ color: 'var(--text-1)' }}>{n.hostname || n.id}</span>
                          </div>
                          <span className="text-[10px] shrink-0" style={{ color: n.is_chokepoint ? '#a78bfa' : 'var(--text-3)' }}>
                            {n.blast_radius ?? 0}{n.is_chokepoint ? ' ⚡' : ''}
                          </span>
                        </div>
                        <div className="h-1 rounded-full mb-1.5" style={{ background: 'var(--bg-1)' }}>
                          <div className="h-1 rounded-full" style={{ width: `${pct}%`, background: RISK_FILL[n.risk_level] || RISK_FILL.unknown }} />
                        </div>
                        {impact > 0 && (
                          <div className="flex items-center justify-between text-[10px]">
                            <span style={{ color: 'var(--text-3)' }}>Est. impact</span>
                            <span style={{ color: 'var(--red)', fontWeight: 600 }}>
                              ₹{impact >= 1_000_000 ? `${(impact / 1_000_000).toFixed(1)}M` : `${(impact / 1000).toFixed(0)}K`}
                            </span>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Remediation */}
              {sideTab === 'Remediation' && (
                remediationSteps.length > 0
                  ? (
                    <div className="space-y-2">
                      <p className="text-[10px] mb-2" style={{ color: 'var(--text-3)' }}>
                        Prioritized by attack path reduction. Apply in order for maximum impact.
                      </p>
                      {remediationSteps.map((step, i) => (
                        <div key={i} className="rounded-xl p-3"
                          style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                          <div className="flex items-start gap-2.5 mb-2">
                            <span className="shrink-0 w-5 h-5 rounded-full text-[9px] font-bold flex items-center justify-center"
                              style={{ background: 'var(--green)', color: '#fff', minWidth: 20 }}>{i + 1}</span>
                            <p className="text-xs font-medium leading-snug" style={{ color: 'var(--text-1)' }}>{step.action}</p>
                          </div>
                          <div className="flex items-center gap-2">
                            <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--bg-0)' }}>
                              <div className="h-full rounded-full" style={{ width: `${step.reduction}%`, background: 'var(--green)' }} />
                            </div>
                            <span className="text-[10px] font-bold tabular-nums" style={{ color: 'var(--green)' }}>
                              −{step.reduction}% paths
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )
                  : <p className="text-xs py-10 text-center" style={{ color: 'var(--text-3)' }}>No remediation data available.</p>
              )}

              {/* Exposure */}
              {sideTab === 'Exposure' && (
                <div className="space-y-3">
                  <p className="text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Attack surface exposure analysis.</p>
                  {[
                    { label: 'Internet-Facing Assets',  items: exposureData.internetFacing, color: '#fb923c', icon: Globe },
                    { label: 'Known Exploited (KEV)',    items: exposureData.kevNodes,        color: '#f85149', icon: Skull },
                    { label: 'Actively Alerting',        items: exposureData.alerting,        color: '#fb923c', icon: AlertCircle },
                    { label: 'Choke Points',             items: exposureData.chokepoints,     color: '#a78bfa', icon: Zap },
                    { label: 'Critical / High Risk',     items: exposureData.highRisk,        color: '#f85149', icon: ShieldAlert },
                  ].map(({ label, items, color, icon: Icon }) => (
                    <div key={label} className="rounded-xl p-3" style={{ background: 'var(--bg-0)', border: `1px solid ${color}44` }}>
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-1.5">
                          <Icon className="h-3.5 w-3.5 shrink-0" style={{ color }} />
                          <span className="text-[11px] font-semibold" style={{ color: 'var(--text-1)' }}>{label}</span>
                        </div>
                        <span className="text-sm font-bold tabular-nums" style={{ color }}>{items.length}</span>
                      </div>
                      {items.slice(0, 3).map(n => (
                        <div key={n.id} className="flex items-center gap-2 text-[10px] mb-0.5" style={{ color: 'var(--text-3)' }}>
                          <span className="h-1.5 w-1.5 rounded-full shrink-0" style={{ background: color }} />
                          {n.hostname || n.id}
                        </div>
                      ))}
                      {items.length > 3 && (
                        <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>+{items.length - 3} more</p>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* Simulation */}
              {sideTab === 'Simulation' && (
                <div className="space-y-3">
                  <div className="rounded-xl p-3" style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
                    <p className="text-[11px] font-bold mb-1" style={{ color: 'var(--accent)' }}>Attack Simulation</p>
                    <p className="text-[11px]" style={{ color: 'var(--text-2)' }}>
                      {simMode
                        ? 'Click any node on the graph to set the attacker\'s starting position. All reachable assets will be highlighted.'
                        : 'Enable simulation to calculate every asset an attacker can reach from any starting point.'}
                    </p>
                  </div>
                  <button onClick={() => { setSimMode(v => !v); setSimReachable(new Set()); setSimStart(null); }}
                    className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-sm font-medium transition-all"
                    style={{
                      background: simMode ? 'rgba(248,81,73,0.12)' : 'var(--glass-bg)',
                      border: `1px solid ${simMode ? 'rgba(248,81,73,0.4)' : 'var(--border)'}`,
                      color: simMode ? '#f85149' : 'var(--text-1)',
                    }}>
                    <Play className="h-4 w-4" />
                    {simMode ? 'Simulation Active — click to disable' : 'Enable Simulation Mode'}
                  </button>
                  {simReachable.size > 0 && (
                    <div className="space-y-1.5">
                      <p className="text-[10px] font-bold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
                        Reachable from {layout?.byId.get(simStart!)?.hostname || simStart}
                      </p>
                      <div className="grid grid-cols-2 gap-2">
                        {[
                          { label: 'Total Reachable', val: simReachable.size, color: '#f85149' },
                          { label: 'Agents', val: graph.nodes.filter(n => n.type === 'agent' && simReachable.has(n.id)).length, color: 'var(--text-1)' },
                          { label: 'Cloud Resources', val: graph.nodes.filter(n => n.type === 'cloud' && simReachable.has(n.id)).length, color: '#2dd4bf' },
                          { label: 'DCs', val: graph.nodes.filter(n => n.type === 'domain_controller' && simReachable.has(n.id)).length, color: '#a78bfa' },
                        ].map(({ label, val, color }) => (
                          <div key={label} className="rounded-xl p-3 text-center" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                            <p className="text-xl font-bold tabular-nums" style={{ color }}>{val}</p>
                            <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{label}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* AI */}
              {sideTab === 'AI' && (
                <div className="space-y-2">
                  <div className="rounded-xl p-3 mb-1" style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
                    <div className="flex items-center gap-2 mb-1">
                      <Flame className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
                      <span className="text-[11px] font-bold" style={{ color: 'var(--accent)' }}>XCloak AI Attack Analysis</span>
                    </div>
                    <p className="text-[11px]" style={{ color: 'var(--text-2)' }}>
                      {graph.top_paths.length} path(s) · {graph.nodes.length} node(s) · {graph.edges.length} edge(s) analyzed.
                    </p>
                  </div>
                  {aiInsights.map((ins, i) => (
                    <div key={i} className="rounded-xl p-3" style={{ background: 'var(--bg-0)', border: `1px solid ${sevColor[ins.sev] || 'var(--border)'}44` }}>
                      <div className="flex items-center gap-1.5 mb-1">
                        <span className="h-1.5 w-1.5 rounded-full shrink-0" style={{ background: sevColor[ins.sev] || 'var(--text-3)' }} />
                        <span className="text-[10px] font-bold uppercase tracking-wider" style={{ color: sevColor[ins.sev] || 'var(--text-3)' }}>{ins.sev}</span>
                      </div>
                      <p className="text-[11px] leading-relaxed" style={{ color: 'var(--text-1)' }}>{ins.text}</p>
                    </div>
                  ))}
                </div>
              )}

            </div>
          </div>
        </div>

        {/* Node hover info bar */}
        {hovered && !clickedNode && (
          <div className="g-panel px-4 py-3 text-xs flex items-center gap-4 flex-wrap" style={{ color: 'var(--text-2)' }}>
            <span className="font-semibold" style={{ color: 'var(--text-1)' }}>
              {hovered.type === 'internet' ? 'Internet (Entry Point)' : hovered.hostname}
            </span>
            <span style={{ color: 'var(--text-3)', textTransform: 'capitalize' }}>{hovered.type.replace('_', ' ')}</span>
            {hovered.type !== 'internet' && <span className={sevClass(hovered.risk_level)}>{hovered.risk_level} risk</span>}
            {hovered.max_epss > 0 && <span>EPSS {(hovered.max_epss * 100).toFixed(1)}%</span>}
            {hovered.has_kev && <span style={{ color: '#f85149' }} className="font-bold">{hovered.kev_count} KEV</span>}
            {hovered.exposed && <span style={{ color: 'var(--orange)' }}>internet-facing</span>}
            {hovered.open_alert_count > 0 && <span style={{ color: 'var(--orange)' }}>{hovered.open_alert_count} alert{hovered.open_alert_count !== 1 ? 's' : ''}</span>}
            {hovered.priv_level && <span>priv: <strong>{hovered.priv_level}</strong></span>}
            {hovered.blast_radius !== undefined && <span>blast: <strong>{hovered.blast_radius}</strong></span>}
            {hovered.is_chokepoint && <span className="font-bold" style={{ color: '#a78bfa' }}>⚡ CHOKE POINT</span>}
            {simMode && <span style={{ color: '#f85149' }} className="font-bold">← Click to start simulation here</span>}
            {!simMode && <span style={{ color: 'var(--text-3)' }}>← Click for details</span>}
          </div>
        )}

      </div>

      {/* Node detail drawer */}
      {clickedNode && (
        <NodeDetail
          node={clickedNode}
          edges={graph.edges}
          graph={graph}
          onClose={() => setClickedNode(null)}
          onToast={notify}
        />
      )}
    </RootLayout>
  );
}
