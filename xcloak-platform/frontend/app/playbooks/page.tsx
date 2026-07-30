'use client';
import { useState, useEffect, useRef, useCallback } from 'react';
import type { ComponentType, CSSProperties } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { pbAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import { MetricCard, DataTable, SectionCard, TabBar, ActionButton, EmptyState } from '@/components/design-system';
import {
  LayoutDashboard, Library, Workflow, History as HistoryIcon, CheckCircle2, BarChart3, LayoutTemplate, Store, Sparkles, FileText,
  AlertTriangle, Flame, FolderOpen, Target, Radio, Unlock, Play, Clock, Webhook as WebhookIcon, Plug,
  GitBranch, CornerDownLeft, Shuffle, Repeat, ArrowLeftRight, Pause, Timer, RotateCw,
  ShieldBan, Ban, Package, Skull, Lock, UserX, KeyRound, Mail, Ticket, Terminal, Network, FileBarChart,
  UserCog, Megaphone, Trash2, Save, Rocket, Download, Zap, Check, X, Wrench, Star,
} from 'lucide-react';

type IconComponent = ComponentType<{ className?: string; style?: CSSProperties }>;

type Tab = 'overview' | 'library' | 'builder' | 'executions' | 'approvals' | 'analytics' | 'templates' | 'marketplace' | 'ai' | 'reports';
const TAB_LABELS: Record<Tab, string> = {
  overview: 'Dashboard', library: 'Library', builder: 'Builder', executions: 'Executions',
  approvals: 'Approvals', analytics: 'Analytics',
  templates: 'Templates', marketplace: 'Marketplace', ai: 'AI Assistant', reports: 'Reports',
};
const TAB_ICONS: Record<Tab, IconComponent> = {
  overview: LayoutDashboard, library: Library, builder: Workflow, executions: HistoryIcon,
  approvals: CheckCircle2, analytics: BarChart3,
  templates: LayoutTemplate, marketplace: Store, ai: Sparkles, reports: FileText,
};

type NodeType = 'trigger' | 'logic' | 'action' | 'human';
const NODE_COLORS: Record<NodeType, string> = {
  trigger: '#3b82f6', logic: '#eab308', action: '#22c55e', human: '#a855f7',
};
const NODE_W = 180;
const NODE_H = 72;

interface WFNode { id: string; type: NodeType; label: string; icon: string; x: number; y: number; config: Record<string, any>; }
interface WFEdge { id: string; from: string; to: string; label?: string; }
interface WFState { nodes: WFNode[]; edges: WFEdge[]; }

// Node/palette icons are persisted as emoji strings in workflow JSON (backend compatibility) — this maps
// each emoji glyph to a real Lucide icon purely for rendering, without touching the stored data shape.
const EMOJI_ICON: Record<string, IconComponent> = {
  '🚨': AlertTriangle, '🔥': Flame, '📁': FolderOpen, '🎯': Target, '📡': Radio,
  '🔓': Unlock, '▶': Play, '⏰': Clock, '🪝': WebhookIcon, '🔌': Plug,
  '❓': GitBranch, '↩': CornerDownLeft, '🔀': Shuffle, '🔄': Repeat, '⟺': ArrowLeftRight,
  '⏸': Pause, '⏱': Timer, '↻': RotateCw,
  '🛡': ShieldBan, '🚫': Ban, '📦': Package, '💀': Skull, '🔒': Lock, '👤': UserX,
  '🔑': KeyRound, '📧': Mail, '🎫': Ticket, '💻': Terminal, '📊': FileBarChart,
  '✅': CheckCircle2, '👨‍💻': UserCog, '📢': Megaphone,
};
function GlyphIcon({ glyph, style }: { glyph: string; style?: CSSProperties }) {
  const Icon = EMOJI_ICON[glyph];
  if (!Icon) return <span style={style}>{glyph}</span>;
  return <Icon style={style} />;
}

const PALETTE: { type: NodeType; label: string; color: string; items: { label: string; icon: string }[] }[] = [
  { type: 'trigger', label: 'Triggers', color: '#3b82f6', items: [
    { label: 'Alert Created', icon: '🚨' }, { label: 'Incident Created', icon: '🔥' },
    { label: 'Case Created', icon: '📁' }, { label: 'IOC Match', icon: '🎯' },
    { label: 'Threat Feed Update', icon: '📡' }, { label: 'Vulnerability Found', icon: '🔓' },
    { label: 'Manual Start', icon: '▶' }, { label: 'Scheduled', icon: '⏰' },
    { label: 'Webhook', icon: '🪝' }, { label: 'API Event', icon: '🔌' },
  ]},
  { type: 'logic', label: 'Logic', color: '#eab308', items: [
    { label: 'IF', icon: '❓' }, { label: 'ELSE', icon: '↩' }, { label: 'SWITCH', icon: '🔀' },
    { label: 'LOOP', icon: '🔄' }, { label: 'PARALLEL', icon: '⟺' },
    { label: 'WAIT', icon: '⏸' }, { label: 'DELAY', icon: '⏱' }, { label: 'RETRY', icon: '↻' },
  ]},
  { type: 'action', label: 'Actions', color: '#22c55e', items: [
    { label: 'Block IP', icon: '🛡' }, { label: 'Block Domain', icon: '🚫' },
    { label: 'Quarantine File', icon: '📦' }, { label: 'Kill Process', icon: '💀' },
    { label: 'Isolate Endpoint', icon: '🔒' }, { label: 'Disable User', icon: '👤' },
    { label: 'Reset Password', icon: '🔑' }, { label: 'Send Email', icon: '📧' },
    { label: 'Create Ticket', icon: '🎫' }, { label: 'Run Script', icon: '💻' },
    { label: 'Update Firewall', icon: '🔥' }, { label: 'Create Report', icon: '📊' },
  ]},
  { type: 'human', label: 'Human-in-Loop', color: '#a855f7', items: [
    { label: 'Approve Action', icon: '✅' }, { label: 'Analyst Input', icon: '👨‍💻' },
    { label: 'Pause Workflow', icon: '⏸' }, { label: 'Escalate', icon: '📢' },
    { label: 'Resume', icon: '▶' },
  ]},
];

const STATUS_COLOR: Record<string, string> = {
  active: '#22c55e', draft: '#eab308', archived: '#6b7280',
  success: '#22c55e', failed: '#ef4444', running: '#3b82f6',
  pending: '#eab308', approved: '#22c55e', rejected: '#ef4444',
};

// ── Workflow Canvas ────────────────────────────────────────────────────────────
function WorkflowCanvas({ workflow, onChange }: { workflow: WFState; onChange: (w: WFState) => void }) {
  const canvasRef = useRef<HTMLDivElement>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [connectingFrom, setConnectingFrom] = useState<string | null>(null);
  const [dragging, setDragging] = useState<{ id: string; ox: number; oy: number } | null>(null);

  const selectedNode = workflow.nodes.find(n => n.id === selectedId) ?? null;

  const updateNode = useCallback((id: string, patch: Partial<WFNode>) => {
    onChange({ ...workflow, nodes: workflow.nodes.map(n => n.id === id ? { ...n, ...patch } : n) });
  }, [workflow, onChange]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!dragging || !canvasRef.current) return;
    const rect = canvasRef.current.getBoundingClientRect();
    const x = Math.max(0, e.clientX - rect.left - dragging.ox);
    const y = Math.max(0, e.clientY - rect.top - dragging.oy);
    onChange({ ...workflow, nodes: workflow.nodes.map(n => n.id === dragging.id ? { ...n, x, y } : n) });
  }, [dragging, workflow, onChange]);

  const stopDrag = useCallback(() => setDragging(null), []);

  const handleNodeMouseDown = (e: React.MouseEvent, node: WFNode) => {
    e.stopPropagation();
    if (connectingFrom) return;
    setSelectedId(node.id);
    const rect = canvasRef.current!.getBoundingClientRect();
    setDragging({ id: node.id, ox: e.clientX - rect.left - node.x, oy: e.clientY - rect.top - node.y });
  };

  const handleOutputPort = (e: React.MouseEvent, nodeId: string) => {
    e.stopPropagation();
    setConnectingFrom(prev => prev === nodeId ? null : nodeId);
  };

  const handleInputPort = (e: React.MouseEvent, nodeId: string) => {
    e.stopPropagation();
    if (!connectingFrom || connectingFrom === nodeId) return;
    const exists = workflow.edges.some(ed => ed.from === connectingFrom && ed.to === nodeId);
    if (!exists) onChange({ ...workflow, edges: [...workflow.edges, { id: `e-${Date.now()}`, from: connectingFrom, to: nodeId }] });
    setConnectingFrom(null);
  };

  const handleCanvasKey = (e: React.KeyboardEvent) => {
    if ((e.key === 'Delete' || e.key === 'Backspace') && selectedId) {
      onChange({ nodes: workflow.nodes.filter(n => n.id !== selectedId), edges: workflow.edges.filter(ed => ed.from !== selectedId && ed.to !== selectedId) });
      setSelectedId(null);
    }
    if (e.key === 'Escape') { setConnectingFrom(null); setSelectedId(null); }
  };

  const addNode = (type: NodeType, label: string, icon: string) => {
    const n = workflow.nodes.length;
    const id = `n-${Date.now()}`;
    onChange({ ...workflow, nodes: [...workflow.nodes, { id, type, label, icon, x: 300, y: 40 + n * 120, config: {} }] });
    setSelectedId(id);
  };

  return (
    <div style={{ display: 'flex', height: '680px', gap: 0 }}>
      {/* Palette sidebar */}
      <div style={{ width: '176px', borderRight: '1px solid var(--border)', overflowY: 'auto', padding: '0.5rem', flexShrink: 0 }}>
        {PALETTE.map(group => (
          <div key={group.type} style={{ marginBottom: '0.75rem' }}>
            <div style={{ fontSize: '0.68rem', fontWeight: 700, color: group.color, textTransform: 'uppercase', letterSpacing: '0.05em', padding: '0.25rem 0.25rem 0.4rem', borderBottom: `1px solid ${group.color}30` }}>{group.label}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', marginTop: '4px' }}>
              {group.items.map(item => (
                <button key={item.label} onClick={() => addNode(group.type, item.label, item.icon)}
                  style={{ display: 'flex', alignItems: 'center', gap: '5px', padding: '4px 6px', background: 'none', border: `1px solid ${group.color}22`, borderRadius: '4px', cursor: 'pointer', fontSize: '0.72rem', color: 'var(--text-2)', textAlign: 'left', transition: 'all 0.1s' }}
                  onMouseEnter={e => (e.currentTarget.style.background = `${group.color}18`)}
                  onMouseLeave={e => (e.currentTarget.style.background = 'none')}>
                  <GlyphIcon glyph={item.icon} style={{ width: 13, height: 13, flexShrink: 0 }} />
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.label}</span>
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Canvas */}
      <div
        ref={canvasRef}
        tabIndex={0}
        onMouseMove={handleMouseMove}
        onMouseUp={stopDrag}
        onMouseLeave={stopDrag}
        onKeyDown={handleCanvasKey}
        onClick={() => { setSelectedId(null); }}
        style={{
          flex: 1, position: 'relative', overflow: 'auto',
          backgroundImage: 'radial-gradient(circle, rgba(255,255,255,0.06) 1px, transparent 1px)',
          backgroundSize: '24px 24px',
          cursor: dragging ? 'grabbing' : 'default',
          outline: 'none', minWidth: 0,
        }}
      >
        {/* SVG for edges */}
        <svg style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', pointerEvents: 'none', overflow: 'visible' }}>
          <defs>
            <marker id="pb-arrow" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
              <polygon points="0 0, 10 3.5, 0 7" fill="rgba(99,102,241,0.7)" />
            </marker>
          </defs>
          {workflow.edges.map(edge => {
            const fr = workflow.nodes.find(n => n.id === edge.from);
            const to = workflow.nodes.find(n => n.id === edge.to);
            if (!fr || !to) return null;
            const x1 = fr.x + NODE_W / 2, y1 = fr.y + NODE_H + 7;
            const x2 = to.x + NODE_W / 2, y2 = to.y - 7;
            const mid = (y1 + y2) / 2;
            return (
              <g key={edge.id}>
                <path d={`M ${x1} ${y1} C ${x1} ${mid} ${x2} ${mid} ${x2} ${y2}`} fill="none" stroke="rgba(99,102,241,0.65)" strokeWidth="2" markerEnd="url(#pb-arrow)" />
                {edge.label && <text x={(x1 + x2) / 2 + 8} y={mid} fill="var(--text-3)" fontSize="10" textAnchor="start">{edge.label}</text>}
              </g>
            );
          })}
        </svg>

        {/* Nodes */}
        {workflow.nodes.map(node => {
          const col = NODE_COLORS[node.type];
          const isSel = node.id === selectedId;
          const isConn = node.id === connectingFrom;
          return (
            <div key={node.id} onMouseDown={e => handleNodeMouseDown(e, node)} style={{
              position: 'absolute', left: node.x, top: node.y, width: NODE_W, height: NODE_H,
              borderRadius: '8px', border: `2px solid ${isSel ? '#fff' : isConn ? '#a855f7' : col}`,
              background: `${col}16`, cursor: 'grab', userSelect: 'none', zIndex: isSel ? 10 : 1,
              boxShadow: isSel ? `0 0 0 2px ${col}60, 0 4px 16px rgba(0,0,0,0.4)` : undefined,
            }}>
              {/* Input port */}
              <div onClick={e => handleInputPort(e, node.id)} onMouseDown={e => e.stopPropagation()} style={{
                position: 'absolute', top: -7, left: '50%', transform: 'translateX(-50%)',
                width: 14, height: 14, borderRadius: '50%', zIndex: 20, cursor: 'pointer',
                background: connectingFrom && connectingFrom !== node.id ? col : '#12121e',
                border: `2px solid ${col}`,
              }} />
              {/* Body */}
              <div style={{ padding: '8px 12px', height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: '2px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <GlyphIcon glyph={node.icon} style={{ width: 14, height: 14, flexShrink: 0, color: col }} />
                  <span style={{ fontSize: '0.76rem', fontWeight: 600, color: col, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{node.label}</span>
                </div>
                {node.config?.condition && <div style={{ fontSize: '0.62rem', color: 'var(--text-3)', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{node.config.condition}</div>}
                {node.config?.policy && <div style={{ fontSize: '0.62rem', color: '#a855f7', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>Policy: {node.config.policy}</div>}
              </div>
              {/* Output port */}
              <div onClick={e => handleOutputPort(e, node.id)} onMouseDown={e => e.stopPropagation()} style={{
                position: 'absolute', bottom: -7, left: '50%', transform: 'translateX(-50%)',
                width: 14, height: 14, borderRadius: '50%', zIndex: 20, cursor: 'pointer',
                background: isConn ? '#a855f7' : '#12121e',
                border: `2px solid ${isConn ? '#a855f7' : col}`,
              }} />
            </div>
          );
        })}

        {workflow.nodes.length === 0 && (
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: 'var(--text-3)', pointerEvents: 'none' }}>
            <Zap style={{ width: 40, height: 40, marginBottom: '0.5rem' }} />
            <div style={{ fontSize: '0.9rem', fontWeight: 600 }}>Click a node type on the left to add it</div>
            <div style={{ fontSize: '0.75rem', marginTop: '0.3rem', color: 'var(--text-3)' }}>Then click output port (bottom ●) → input port (top ●) to connect</div>
          </div>
        )}
        {connectingFrom && (
          <div style={{ position: 'absolute', top: 8, left: '50%', transform: 'translateX(-50%)', background: 'rgba(168,85,247,0.9)', color: '#fff', padding: '4px 14px', borderRadius: '20px', fontSize: '0.76rem', pointerEvents: 'none', whiteSpace: 'nowrap' }}>
            Click input port (●) on another node to connect — Esc to cancel
          </div>
        )}
      </div>

      {/* Config panel */}
      {selectedNode && (
        <div style={{ width: '230px', borderLeft: '1px solid var(--border)', padding: '0.85rem', overflowY: 'auto', flexShrink: 0, fontSize: '0.8rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontWeight: 700, color: NODE_COLORS[selectedNode.type], marginBottom: '0.75rem', fontSize: '0.85rem' }}>
            <GlyphIcon glyph={selectedNode.icon} style={{ width: 14, height: 14 }} /> {selectedNode.label}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.55rem' }}>
            <div>
              <div style={{ color: 'var(--text-3)', fontSize: '0.68rem', marginBottom: '2px' }}>Label</div>
              <input className="g-input" style={{ width: '100%', fontSize: '0.76rem' }} value={selectedNode.label} onChange={e => updateNode(selectedNode.id, { label: e.target.value })} />
            </div>
            {selectedNode.type === 'logic' && (
              <div>
                <div style={{ color: 'var(--text-3)', fontSize: '0.68rem', marginBottom: '2px' }}>Condition</div>
                <textarea className="g-input" style={{ width: '100%', height: '55px', fontFamily: 'monospace', fontSize: '0.72rem', resize: 'none' }}
                  placeholder="severity == 'critical'"
                  value={selectedNode.config.condition || ''}
                  onChange={e => updateNode(selectedNode.id, { config: { ...selectedNode.config, condition: e.target.value } })} />
              </div>
            )}
            {selectedNode.type === 'action' && (<>
              <div>
                <div style={{ color: 'var(--text-3)', fontSize: '0.68rem', marginBottom: '2px' }}>Target (IP / hostname / username)</div>
                <input className="g-input" style={{ width: '100%', fontSize: '0.76rem' }} placeholder="e.g. 10.0.0.5, win-workstation-05, jsmith"
                  value={selectedNode.config.target || ''}
                  onChange={e => updateNode(selectedNode.id, { config: { ...selectedNode.config, target: e.target.value } })} />
              </div>
              <div>
                <div style={{ color: 'var(--text-3)', fontSize: '0.68rem', marginBottom: '2px' }}>Timeout (s)</div>
                <input className="g-input" style={{ width: '100%', fontSize: '0.76rem' }} type="number" value={selectedNode.config.timeout ?? 30}
                  onChange={e => updateNode(selectedNode.id, { config: { ...selectedNode.config, timeout: +e.target.value } })} />
              </div>
              <div>
                <div style={{ color: 'var(--text-3)', fontSize: '0.68rem', marginBottom: '2px' }}>On failure</div>
                <select className="g-select" style={{ width: '100%', fontSize: '0.76rem' }} value={selectedNode.config.on_failure ?? 'stop'}
                  onChange={e => updateNode(selectedNode.id, { config: { ...selectedNode.config, on_failure: e.target.value } })}>
                  {['stop', 'retry', 'skip', 'rollback', 'alternate', 'notify'].map(v => <option key={v} value={v}>{v}</option>)}
                </select>
              </div>
            </>)}
            {selectedNode.type === 'human' && (
              <div>
                <div style={{ color: 'var(--text-3)', fontSize: '0.68rem', marginBottom: '2px' }}>Approval Policy</div>
                <select className="g-select" style={{ width: '100%', fontSize: '0.76rem' }} value={selectedNode.config.policy ?? 'manager_approval'}
                  onChange={e => updateNode(selectedNode.id, { config: { ...selectedNode.config, policy: e.target.value } })}>
                  {['automatic', 'manager_approval', 'security_approval', 'dual_approval', 'emergency_override'].map(v => (
                    <option key={v} value={v}>{v.replace(/_/g, ' ')}</option>
                  ))}
                </select>
              </div>
            )}
            {selectedNode.type === 'trigger' && (
              <div>
                <div style={{ color: 'var(--text-3)', fontSize: '0.68rem', marginBottom: '2px' }}>Conditions</div>
                <textarea className="g-input" style={{ width: '100%', height: '55px', fontFamily: 'monospace', fontSize: '0.72rem', resize: 'none' }}
                  placeholder="severity: critical&#10;confidence: > 80"
                  value={selectedNode.config.conditions || ''}
                  onChange={e => updateNode(selectedNode.id, { config: { ...selectedNode.config, conditions: e.target.value } })} />
              </div>
            )}
            <div>
              <div style={{ color: 'var(--text-3)', fontSize: '0.68rem', marginBottom: '2px' }}>Notes</div>
              <textarea className="g-input" style={{ width: '100%', height: '44px', fontSize: '0.72rem', resize: 'none' }} placeholder="Optional…"
                value={selectedNode.config.notes || ''}
                onChange={e => updateNode(selectedNode.id, { config: { ...selectedNode.config, notes: e.target.value } })} />
            </div>
            <div style={{ borderTop: '1px solid var(--border)', paddingTop: '0.5rem' }}>
              <button onClick={() => {
                onChange({ nodes: workflow.nodes.filter(n => n.id !== selectedNode.id), edges: workflow.edges.filter(e => e.from !== selectedNode.id && e.to !== selectedNode.id) });
                setSelectedId(null);
              }} style={{ width: '100%', padding: '4px', background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)', borderRadius: '4px', color: '#ef4444', fontSize: '0.75rem', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 5 }}>
                <Trash2 style={{ width: 12, height: 12 }} /> Delete Node
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Overview Tab ───────────────────────────────────────────────────────────────
function OverviewTab({ dash }: { dash: any }) {
  if (!dash) return <div style={{ color: 'var(--text-3)', padding: '2rem' }}>Loading…</div>;
  const cards = [
    { label: 'Total Playbooks', value: dash.total_playbooks, color: '#6366f1' },
    { label: 'Active', value: dash.active_playbooks, color: '#22c55e' },
    { label: 'Draft', value: dash.draft_playbooks, color: '#eab308' },
    { label: 'Running Now', value: dash.running_executions, color: '#3b82f6' },
    { label: 'Successful Runs', value: dash.successful_runs, color: '#22c55e' },
    { label: 'Failed Runs', value: dash.failed_runs, color: '#ef4444' },
    { label: 'Avg Exec Time', value: `${dash.avg_exec_time_s}s`, color: '#f97316' },
    { label: 'Automation Cov', value: `${dash.automation_coverage?.toFixed(1)}%`, color: '#6366f1' },
    { label: 'Pending Approvals', value: dash.pending_approvals, color: '#a855f7' },
    { label: 'Total Executions', value: dash.total_executions, color: '#6b7280' },
  ];
  return (
    <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
      {cards.map(c => <MetricCard key={c.label} label={c.label} value={c.value} color={c.color} />)}
    </div>
  );
}

// ── Library Tab ────────────────────────────────────────────────────────────────
function LibraryTab({ onEdit, onExecute }: { onEdit: (pb: any) => void; onExecute: (pb: any) => void }) {
  const [list, setList] = useState<any[]>([]);
  const [statusFilter, setStatusFilter] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', description: '', category: 'custom', trigger_type: 'manual', approval_policy: 'automatic' });
  const [creating, setCreating] = useState(false);

  const load = useCallback(() => {
    const params: any = {};
    if (statusFilter) params.status = statusFilter;
    pbAPI.getLibrary(params).then(r => setList(r.data || []));
  }, [statusFilter]);

  useEffect(() => { load(); }, [load]);

  const create = async () => {
    if (!form.name) return;
    setCreating(true);
    const r = await pbAPI.createPlaybook(form);
    if (r.data?.ok) { setShowCreate(false); setForm({ name: '', description: '', category: 'custom', trigger_type: 'manual', approval_policy: 'automatic' }); load(); }
    setCreating(false);
  };

  const del = async (id: number) => {
    await pbAPI.deletePlaybook(id);
    load();
  };

  const STATUSES = ['', 'active', 'draft', 'archived'];
  const successRate = (pb: any) => pb.execution_count > 0 ? ((pb.success_count / pb.execution_count) * 100).toFixed(0) + '%' : '—';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
        <select className="g-select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)} style={{ fontSize: '0.82rem', width: 160 }}>
          {STATUSES.map(s => <option key={s} value={s}>{s || 'All Statuses'}</option>)}
        </select>
        <ActionButton variant="primary" onClick={() => setShowCreate(!showCreate)} style={{ marginLeft: 'auto' }}>+ New Playbook</ActionButton>
      </div>

      {showCreate && (
        <div className="g-card" style={{ padding: '1.25rem', border: '1px solid rgba(99,102,241,0.3)' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.6rem' }}>
            <div style={{ gridColumn: '1/-1' }}><input className="g-input" style={{ width: '100%' }} placeholder="Name *" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} /></div>
            <div style={{ gridColumn: '1/-1' }}><textarea className="g-input" style={{ width: '100%', height: '50px', resize: 'none' }} placeholder="Description" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} /></div>
            <select className="g-select" value={form.category} onChange={e => setForm(f => ({ ...f, category: e.target.value }))}>
              {['custom', 'incident_response', 'email_security', 'endpoint', 'identity', 'cloud', 'ueba', 'threat_intel', 'web_security', 'dlp'].map(v => <option key={v} value={v}>{v.replace(/_/g, ' ')}</option>)}
            </select>
            <select className="g-select" value={form.trigger_type} onChange={e => setForm(f => ({ ...f, trigger_type: e.target.value }))}>
              {['manual', 'alert_critical', 'alert_high', 'alert_medium', 'ioc_match', 'scheduled', 'webhook'].map(v => <option key={v} value={v}>{v.replace(/_/g, ' ')}</option>)}
            </select>
            <select className="g-select" value={form.approval_policy} onChange={e => setForm(f => ({ ...f, approval_policy: e.target.value }))}>
              {['automatic', 'manager_approval', 'security_approval', 'dual_approval', 'emergency_override'].map(v => <option key={v} value={v}>{v.replace(/_/g, ' ')}</option>)}
            </select>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.75rem' }}>
            <ActionButton variant="primary" onClick={create} disabled={creating || !form.name}>{creating ? 'Creating…' : 'Create'}</ActionButton>
            <ActionButton variant="ghost" onClick={() => setShowCreate(false)}>Cancel</ActionButton>
          </div>
        </div>
      )}

      <DataTable<any>
        rows={list}
        rowKey={(pb: any) => pb.id}
        onRowClick={pb => onEdit(pb)}
        emptyState={<EmptyState icon={Library} title="No playbooks found" />}
        columns={[
          { key: 'name', header: 'Name', render: (pb: any) => (
            <div style={{ fontWeight: 600, fontSize: '0.85rem', maxWidth: '180px' }}>
              <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{pb.name}</div>
              {pb.tags && <div style={{ display: 'flex', gap: '2px', marginTop: '2px', flexWrap: 'wrap' }}>
                {pb.tags.split(',').slice(0, 2).map((t: string) => <span key={t} style={{ fontSize: '0.63rem', background: 'rgba(99,102,241,0.1)', color: '#818cf8', padding: '1px 4px', borderRadius: '2px' }}>{t.trim()}</span>)}
              </div>}
            </div>
          ) },
          { key: 'category', header: 'Category', render: (pb: any) => <span style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>{pb.category?.replace(/_/g, ' ')}</span> },
          { key: 'trigger_type', header: 'Trigger', render: (pb: any) => <code style={{ fontSize: '0.72rem', color: 'var(--text-3)' }}>{pb.trigger_type}</code> },
          { key: 'version', header: 'Version', render: (pb: any) => <code style={{ fontSize: '0.72rem' }}>v{pb.version}</code> },
          { key: 'status', header: 'Status', render: (pb: any) => (
            <span style={{ background: `${STATUS_COLOR[pb.status] || '#666'}18`, color: STATUS_COLOR[pb.status] || '#666', padding: '2px 7px', borderRadius: '3px', fontSize: '0.73rem', fontWeight: 600 }}>{pb.status}</span>
          ) },
          { key: 'author', header: 'Author', render: (pb: any) => <span style={{ fontSize: '0.78rem', fontFamily: 'monospace' }}>{pb.author}</span> },
          { key: 'execution_count', header: 'Runs', align: 'right', render: (pb: any) => <span style={{ fontSize: '0.82rem' }}>{pb.execution_count}</span> },
          { key: 'success', header: 'Success', align: 'right', render: (pb: any) => <span style={{ fontSize: '0.82rem', color: '#22c55e' }}>{successRate(pb)}</span> },
          { key: 'avg_runtime_s', header: 'Avg', align: 'right', render: (pb: any) => <span style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>{pb.avg_runtime_s > 0 ? `${pb.avg_runtime_s}s` : '—'}</span> },
          { key: 'updated_at', header: 'Updated', render: (pb: any) => <span style={{ fontSize: '0.75rem', color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(pb.updated_at)}</span> },
          { key: 'actions', header: '', render: (pb: any) => (
            <div style={{ display: 'flex', gap: '4px' }} onClick={e => e.stopPropagation()}>
              <ActionButton variant="ghost" onClick={() => onEdit(pb)} style={{ fontSize: '0.72rem', padding: '2px 6px' }}>Edit</ActionButton>
              <ActionButton variant="primary" icon={Play} onClick={() => onExecute(pb)} style={{ fontSize: '0.72rem', padding: '2px 6px' }}>Run</ActionButton>
              <ActionButton variant="ghost" icon={X} onClick={() => del(pb.id)} style={{ padding: '2px 4px', color: '#ef4444' }} />
            </div>
          ) },
        ]}
      />
    </div>
  );
}

// ── Builder Tab ────────────────────────────────────────────────────────────────
function BuilderTab({ playbook, onSelectPlaybook }: { playbook: any; onSelectPlaybook: () => void }) {
  const [workflow, setWorkflow] = useState<WFState>({ nodes: [], edges: [] });
  const [saving, setSaving] = useState(false);
  const [publishing, setPublishing] = useState(false);
  const [dryRunning, setDryRunning] = useState(false);
  const [dryResult, setDryResult] = useState<any>(null);
  const [versions, setVersions] = useState<any[]>([]);
  const [showVersions, setShowVersions] = useState(false);

  useEffect(() => {
    if (!playbook?.id) return;
    pbAPI.getWorkflow(playbook.id).then(r => {
      if (r.data && typeof r.data === 'object') setWorkflow(r.data as WFState);
    });
    pbAPI.getVersions(playbook.id).then(r => setVersions(r.data || []));
  }, [playbook?.id]);

  const save = async () => {
    if (!playbook?.id) return;
    setSaving(true);
    await pbAPI.saveWorkflow(playbook.id, workflow);
    setSaving(false);
  };

  const publish = async () => {
    if (!playbook?.id) return;
    setPublishing(true);
    const r = await pbAPI.publishPlaybook(playbook.id);
    if (r.data?.version) alert(`Published as v${r.data.version}`);
    setPublishing(false);
  };

  const runDry = async () => {
    if (!playbook?.id) return;
    setDryRunning(true);
    const r = await pbAPI.dryRun(playbook.id, { workflow });
    setDryResult(r.data);
    setDryRunning(false);
  };

  if (!playbook) return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '400px', color: 'var(--text-3)', gap: '1rem' }}>
      <Wrench style={{ width: 40, height: 40 }} />
      <div style={{ fontWeight: 600 }}>No playbook selected</div>
      <ActionButton variant="primary" onClick={onSelectPlaybook}>Go to Library →</ActionButton>
    </div>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      {/* Builder toolbar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.75rem 1rem', background: 'rgba(255,255,255,0.03)', borderRadius: '8px', border: '1px solid var(--border)' }}>
        <div>
          <div style={{ fontWeight: 600 }}>{playbook.name}</div>
          <div style={{ display: 'flex', gap: '0.4rem', marginTop: '2px', alignItems: 'center' }}>
            <code style={{ fontSize: '0.72rem', color: '#818cf8' }}>v{playbook.version}</code>
            <span style={{ background: `${STATUS_COLOR[playbook.status] || '#666'}18`, color: STATUS_COLOR[playbook.status] || '#666', padding: '1px 6px', borderRadius: '3px', fontSize: '0.7rem' }}>{playbook.status}</span>
          </div>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', marginLeft: 'auto' }}>
          <ActionButton variant="ghost" icon={HistoryIcon} onClick={() => setShowVersions(!showVersions)} style={{ fontSize: '0.78rem' }}>History</ActionButton>
          <ActionButton variant="ghost" icon={Play} onClick={runDry} disabled={dryRunning} style={{ fontSize: '0.78rem' }}>{dryRunning ? 'Testing…' : 'Dry Run'}</ActionButton>
          <ActionButton variant="ghost" icon={Save} onClick={save} disabled={saving} style={{ fontSize: '0.78rem' }}>{saving ? 'Saving…' : 'Save'}</ActionButton>
          <ActionButton variant="primary" icon={Rocket} onClick={publish} disabled={publishing} style={{ fontSize: '0.78rem' }}>{publishing ? 'Publishing…' : 'Publish'}</ActionButton>
        </div>
      </div>

      {showVersions && (
        <div className="g-card" style={{ padding: '1rem' }}>
          <div style={{ fontWeight: 600, marginBottom: '0.5rem', fontSize: '0.85rem' }}>Version History</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
            {versions.map((v: any) => (
              <div key={v.version} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.4rem 0.5rem', background: 'rgba(255,255,255,0.04)', borderRadius: '4px', fontSize: '0.78rem' }}>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <code style={{ color: '#818cf8' }}>v{v.version}</code>
                  <span style={{ color: 'var(--text-3)' }}>{v.author}</span>
                  <span style={{ color: 'var(--text-3)' }}>·</span>
                  <span style={{ color: 'var(--text-3)' }}>{v.changelog}</span>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <span style={{ background: `${STATUS_COLOR[v.status] || '#666'}18`, color: STATUS_COLOR[v.status] || '#666', padding: '1px 5px', borderRadius: '3px', fontSize: '0.7rem' }}>{v.status}</span>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-3)' }}>{timeAgo(v.published_at)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {dryResult && (
        <div className="g-card" style={{ padding: '1rem', border: `1px solid ${dryResult.steps_failed > 0 ? 'rgba(239,68,68,0.3)' : 'rgba(34,197,94,0.3)'}` }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontWeight: 600, color: dryResult.steps_failed > 0 ? '#ef4444' : '#22c55e' }}>
              {dryResult.steps_failed > 0 ? <AlertTriangle style={{ width: 14, height: 14 }} /> : <CheckCircle2 style={{ width: 14, height: 14 }} />}
              {dryResult.steps_failed > 0 ? 'Dry Run: Issues Found' : 'Dry Run: All Passed'}
            </span>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-3)' }}>Est. {dryResult.estimated_time_s}s</span>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
            {(dryResult.step_results || []).map((s: any, i: number) => {
              const color = s.status === 'ok' ? '#22c55e' : s.status === 'failed' ? '#ef4444' : '#6b7280';
              return (
                <span key={i} title={s.message} style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: '0.72rem', padding: '2px 7px', borderRadius: '3px', background: `${color}18`, color }}>
                  {s.status === 'ok' ? <Check style={{ width: 10, height: 10 }} /> : s.status === 'failed' ? <X style={{ width: 10, height: 10 }} /> : <span>—</span>}
                  {' '}{s.step} <span style={{ color: 'var(--text-3)' }}>({s.status}{s.duration_ms ? `, ${s.duration_ms}ms` : ''})</span>
                </span>
              );
            })}
          </div>
          <button onClick={() => setDryResult(null)} style={{ marginTop: '0.5rem', background: 'none', border: 'none', color: 'var(--text-3)', fontSize: '0.75rem', cursor: 'pointer' }}>dismiss</button>
        </div>
      )}

      <div className="g-card" style={{ padding: 0, overflow: 'hidden' }}>
        <WorkflowCanvas workflow={workflow} onChange={setWorkflow} />
      </div>
      <div style={{ fontSize: '0.72rem', color: 'var(--text-3)', textAlign: 'center' }}>
        Delete key removes selected node · Click palette item to add · Drag node to reposition · Click bottom ● then top ● to connect
      </div>
    </div>
  );
}

// ── Executions Tab ─────────────────────────────────────────────────────────────
function ExecutionsTab() {
  const [execs, setExecs] = useState<any[]>([]);
  useEffect(() => { pbAPI.getExecutions().then(r => setExecs(r.data || [])); }, []);

  return (
    <DataTable<any>
      rows={execs}
      rowKey={(e: any) => e.id}
      emptyState={<EmptyState icon={HistoryIcon} title="No executions yet" />}
      columns={[
        { key: 'execution_id', header: 'Execution ID', render: (e: any) => <code style={{ fontSize: '0.72rem', color: '#818cf8' }}>{e.execution_id}</code> },
        { key: 'playbook_name', header: 'Playbook', render: (e: any) => <span style={{ fontWeight: 600, fontSize: '0.83rem' }}>{e.playbook_name}</span> },
        { key: 'status', header: 'Status', render: (e: any) => (
          <span style={{ background: `${STATUS_COLOR[e.status] || '#666'}18`, color: STATUS_COLOR[e.status] || '#666', padding: '2px 7px', borderRadius: '3px', fontSize: '0.73rem', fontWeight: 600 }}>
            {e.status}
          </span>
        ) },
        { key: 'trigger_type', header: 'Trigger', render: (e: any) => <code style={{ fontSize: '0.72rem', color: 'var(--text-3)' }}>{e.trigger_type}</code> },
        { key: 'analyst', header: 'Analyst', render: (e: any) => <span style={{ fontSize: '0.78rem', fontFamily: 'monospace' }}>{e.analyst}</span> },
        { key: 'duration_s', header: 'Duration', align: 'right', render: (e: any) => <span style={{ fontSize: '0.82rem', color: 'var(--text-2)' }}>{e.duration_s > 0 ? `${e.duration_s}s` : '—'}</span> },
        { key: 'failed_step', header: 'Failed Step', render: (e: any) => <span style={{ fontSize: '0.75rem', color: '#ef4444' }}>{e.failed_step || '—'}</span> },
        { key: 'started_at', header: 'Started', render: (e: any) => <span style={{ fontSize: '0.75rem', color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(e.started_at)}</span> },
        { key: 'is_dry_run', header: 'Type', render: (e: any) => (
          e.is_dry_run ? <span style={{ fontSize: '0.68rem', background: 'rgba(99,102,241,0.1)', color: '#818cf8', padding: '1px 5px', borderRadius: '3px' }}>dry</span> : null
        ) },
      ]}
    />
  );
}

// ── Approvals Tab (HITL) ───────────────────────────────────────────────────────
function ApprovalsTab() {
  const [approvals, setApprovals] = useState<any[]>([]);
  const [deciding, setDeciding] = useState<number | null>(null);
  const [notes, setNotes] = useState('');

  const load = () => pbAPI.getApprovals().then(r => setApprovals(r.data || []));
  useEffect(() => { load(); }, []);

  const decide = async (id: number, decision: string) => {
    setDeciding(id);
    await pbAPI.approvalDecision(id, { decision, notes });
    setNotes('');
    setDeciding(null);
    load();
  };

  const POLICY_BADGE: Record<string, string> = {
    automatic: '#22c55e', manager_approval: '#3b82f6',
    security_approval: '#f97316', dual_approval: '#a855f7', emergency_override: '#ef4444',
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <div style={{ padding: '0.75rem 1rem', background: 'rgba(168,85,247,0.07)', border: '1px solid rgba(168,85,247,0.2)', borderRadius: '6px', fontSize: '0.82rem', color: 'var(--text-2)' }}>
        <strong style={{ color: '#a855f7' }}>Human-in-the-Loop:</strong> Review automated actions before execution. Approve, reject, or provide analyst input to continue the playbook.
      </div>
      {approvals.map((a: any) => (
        <div key={a.id} className="g-card" style={{ padding: '1.1rem', borderLeft: `3px solid ${a.status === 'pending' ? '#a855f7' : STATUS_COLOR[a.status] || '#666'}` }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', marginBottom: '0.5rem' }}>
            <div>
              <div style={{ fontWeight: 600, fontSize: '0.88rem' }}>{a.action}</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-3)', marginTop: '2px' }}>
                Playbook: <strong>{a.playbook_name}</strong> · Requestor: <strong>{a.requestor}</strong>
              </div>
            </div>
            <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center', flexShrink: 0 }}>
              <span style={{ background: `${POLICY_BADGE[a.policy] || '#666'}18`, color: POLICY_BADGE[a.policy] || '#666', padding: '2px 7px', borderRadius: '3px', fontSize: '0.72rem' }}>
                {a.policy?.replace(/_/g, ' ')}
              </span>
              <span style={{ background: `${STATUS_COLOR[a.status] || '#666'}18`, color: STATUS_COLOR[a.status] || '#666', padding: '2px 7px', borderRadius: '3px', fontSize: '0.72rem', fontWeight: 600 }}>{a.status}</span>
              <code style={{ fontSize: '0.7rem', color: '#818cf8' }}>{a.execution_id}</code>
            </div>
          </div>
          <div style={{ fontSize: '0.73rem', color: 'var(--text-3)', marginBottom: '0.5rem' }}>Requested {timeAgo(a.created_at)}</div>
          {a.status === 'pending' && (
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
              <input className="g-input" placeholder="Optional notes…" value={deciding === a.id ? notes : ''} style={{ flex: 1, fontSize: '0.78rem', minWidth: '200px' }} onChange={e => { setDeciding(a.id); setNotes(e.target.value); }} />
              <ActionButton variant="primary" icon={Check} disabled={deciding === a.id && !notes} onClick={() => decide(a.id, 'approved')} style={{ background: 'rgba(34,197,94,0.15)', color: '#22c55e', border: '1px solid rgba(34,197,94,0.3)' }}>Approve</ActionButton>
              <ActionButton variant="ghost" icon={X} onClick={() => decide(a.id, 'rejected')} style={{ color: '#ef4444', border: '1px solid rgba(239,68,68,0.3)' }}>Reject</ActionButton>
              <ActionButton variant="ghost" icon={Megaphone} onClick={() => decide(a.id, 'escalated')} style={{ fontSize: '0.75rem' }}>Escalate</ActionButton>
            </div>
          )}
          {a.status !== 'pending' && a.approver && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.73rem', color: 'var(--text-3)' }}>
              {a.status === 'approved' ? <Check style={{ width: 11, height: 11 }} /> : <X style={{ width: 11, height: 11 }} />} by {a.approver}{a.notes ? ` · "${a.notes}"` : ''}
            </div>
          )}
        </div>
      ))}
      {approvals.filter(a => a.status === 'pending').length === 0 && approvals.length > 0 && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, color: '#22c55e', padding: '1rem', fontSize: '0.85rem' }}>
          <CheckCircle2 style={{ width: 15, height: 15 }} /> All pending approvals resolved
        </div>
      )}
    </div>
  );
}

// ── Analytics Tab ──────────────────────────────────────────────────────────────
function AnalyticsTab() {
  const [data, setData] = useState<any>(null);
  useEffect(() => { pbAPI.getAnalytics().then(r => setData(r.data)); }, []);
  if (!data) return <div style={{ color: 'var(--text-3)', padding: '2rem' }}>Loading…</div>;

  const maxTrend = Math.max(...(data.trend?.map((p: any) => p.runs) || [1]), 1);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        {[
          { label: 'Success Rate', value: `${data.success_rate?.toFixed(1)}%`, color: '#22c55e' },
          { label: 'Total Runs', value: data.total_runs, color: '#6366f1' },
          { label: 'Avg Runtime', value: `${data.avg_runtime_s}s`, color: '#f97316' },
          { label: 'Time Saved', value: `${data.time_saved_h?.toFixed(0)}h`, color: '#3b82f6' },
          { label: 'Analyst Hours', value: `${data.analyst_hours_saved?.toFixed(0)}h`, color: '#a855f7' },
          { label: 'Auto Coverage', value: `${data.automation_coverage}%`, color: '#22c55e' },
        ].map(c => <MetricCard key={c.label} label={c.label} value={c.value} color={c.color} />)}
      </div>

      <SectionCard title="Execution Trend (8d)">
        <div style={{ display: 'flex', alignItems: 'flex-end', gap: '4px', height: '80px' }}>
          {data.trend?.map((p: any, i: number) => (
            <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '4px' }}>
              <div style={{ position: 'relative', width: '100%', display: 'flex', justifyContent: 'center', gap: '1px', alignItems: 'flex-end' }}>
                <div style={{ width: '40%', background: '#22c55e', height: `${Math.max((p.success / maxTrend) * 64, p.success > 0 ? 4 : 0)}px`, borderRadius: '2px 2px 0 0' }} title={`Success: ${p.success}`} />
                <div style={{ width: '40%', background: '#ef4444', height: `${Math.max(((p.runs - p.success) / maxTrend) * 64, (p.runs - p.success) > 0 ? 4 : 0)}px`, borderRadius: '2px 2px 0 0' }} title={`Failed: ${p.runs - p.success}`} />
              </div>
              <div style={{ fontSize: '0.6rem', color: 'var(--text-3)', transform: 'rotate(-25deg)', whiteSpace: 'nowrap' }}>{p.date}</div>
            </div>
          ))}
        </div>
        <div style={{ display: 'flex', gap: '1rem', marginTop: '0.5rem', fontSize: '0.72rem' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><span style={{ width: '10px', height: '10px', background: '#22c55e', borderRadius: '2px', display: 'inline-block' }} /> Success</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><span style={{ width: '10px', height: '10px', background: '#ef4444', borderRadius: '2px', display: 'inline-block' }} /> Failed</span>
        </div>
      </SectionCard>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <SectionCard title="Most Used Playbooks">
          {data.most_used?.map((pb: any) => (
            <div key={pb.name} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.55rem' }}>
              <span style={{ minWidth: '140px', fontSize: '0.8rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{pb.name}</span>
              <div style={{ flex: 1, height: '7px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
                <div style={{ width: `${(pb.runs / 128) * 100}%`, height: '100%', borderRadius: '4px', background: '#6366f1' }} />
              </div>
              <span style={{ fontSize: '0.78rem', minWidth: '28px', textAlign: 'right' }}>{pb.runs}</span>
              <span style={{ fontSize: '0.72rem', color: '#22c55e', minWidth: '40px', textAlign: 'right' }}>{pb.success_rate}%</span>
            </div>
          ))}
        </SectionCard>
        <SectionCard title="Failed Steps">
          {data.failed_steps?.map((s: any) => (
            <div key={s.step} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.55rem' }}>
              <span style={{ minWidth: '120px', fontSize: '0.8rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.step}</span>
              <div style={{ flex: 1, height: '7px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
                <div style={{ width: `${(s.count / 8) * 100}%`, height: '100%', borderRadius: '4px', background: '#ef4444' }} />
              </div>
              <span style={{ fontSize: '0.75rem', color: '#ef4444', minWidth: '20px' }}>{s.count}</span>
              <span style={{ fontSize: '0.68rem', color: 'var(--text-3)', maxWidth: '80px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.reason}</span>
            </div>
          ))}
          <div style={{ marginTop: '1rem', display: 'flex', gap: '2rem', fontSize: '0.8rem' }}>
            <div><div style={{ color: '#22c55e', fontWeight: 700 }}>{data.manual_vs_automated?.automated}%</div><div style={{ color: 'var(--text-3)', fontSize: '0.7rem' }}>Automated</div></div>
            <div><div style={{ color: '#eab308', fontWeight: 700 }}>{data.manual_vs_automated?.manual}%</div><div style={{ color: 'var(--text-3)', fontSize: '0.7rem' }}>Manual</div></div>
          </div>
        </SectionCard>
      </div>
    </div>
  );
}

// ── Templates Tab ──────────────────────────────────────────────────────────────
function TemplatesTab({ onInstall }: { onInstall: (t: any) => void }) {
  const [templates, setTemplates] = useState<any[]>([]);
  const [installing, setInstalling] = useState<string | null>(null);
  useEffect(() => { pbAPI.getTemplates().then(r => setTemplates(r.data || [])); }, []);

  const install = async (t: any) => {
    setInstalling(t.id);
    const r = await pbAPI.installTemplate(t.id);
    if (r.data?.ok) onInstall(t);
    setInstalling(null);
  };

  const APPROVAL_COLORS: Record<string, string> = { automatic: '#22c55e', manager_approval: '#3b82f6', security_approval: '#f97316', dual_approval: '#a855f7' };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(280px,1fr))', gap: '1rem' }}>
      {templates.map((t: any) => (
        <div key={t.id} className="g-card" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div style={{ fontSize: '1.6rem' }}>{t.icon}</div>
            <div style={{ display: 'flex', gap: '0.3rem' }}>
              <span style={{ fontSize: '0.68rem', background: 'rgba(99,102,241,0.1)', color: '#818cf8', padding: '1px 5px', borderRadius: '3px' }}>{t.node_count} nodes</span>
              <span style={{ fontSize: '0.68rem', background: 'rgba(255,255,255,0.06)', color: 'var(--text-3)', padding: '1px 5px', borderRadius: '3px' }}>~{t.estimated_time_s}s</span>
            </div>
          </div>
          <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>{t.name}</div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-3)', lineHeight: 1.5 }}>{t.description}</div>
          <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.68rem', background: `${APPROVAL_COLORS[t.approval_policy] || '#666'}18`, color: APPROVAL_COLORS[t.approval_policy] || '#666', padding: '1px 5px', borderRadius: '3px' }}>{t.approval_policy?.replace(/_/g, ' ')}</span>
            <code style={{ fontSize: '0.68rem', color: 'var(--text-3)', background: 'rgba(255,255,255,0.06)', padding: '1px 5px', borderRadius: '3px' }}>{t.trigger}</code>
          </div>
          <ActionButton variant="primary" disabled={installing === t.id} onClick={() => install(t)} style={{ marginTop: 'auto', fontSize: '0.78rem', justifyContent: 'center' }}>
            {installing === t.id ? 'Installing…' : '+ Use Template'}
          </ActionButton>
        </div>
      ))}
    </div>
  );
}

// ── Marketplace Tab ────────────────────────────────────────────────────────────
function MarketplaceTab({ onInstall }: { onInstall: (t: any) => void }) {
  const [items, setItems] = useState<any[]>([]);
  const [installing, setInstalling] = useState<string | null>(null);
  const [catFilter, setCatFilter] = useState('');
  useEffect(() => { pbAPI.getMarketplace().then(r => setItems(r.data || [])); }, []);

  const install = async (item: any) => {
    setInstalling(item.id);
    const r = await pbAPI.installTemplate(item.id);
    if (r.data?.ok) onInstall(item);
    setInstalling(null);
  };

  const cats = ['', ...Array.from(new Set(items.map((i: any) => i.category)))];
  const filtered = catFilter ? items.filter((i: any) => i.category === catFilter) : items;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
        <select className="g-select" value={catFilter} onChange={e => setCatFilter(e.target.value)} style={{ fontSize: '0.82rem', width: 200 }}>
          {cats.map(c => <option key={c} value={c}>{c || 'All Categories'}</option>)}
        </select>
        <span style={{ fontSize: '0.78rem', color: 'var(--text-3)', marginLeft: 'auto' }}>{filtered.length} integrations available</span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(280px,1fr))', gap: '1rem' }}>
        {filtered.map((item: any) => (
          <div key={item.id} className="g-card" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div style={{ fontSize: '1.6rem' }}>{item.icon}</div>
              <div style={{ textAlign: 'right', fontSize: '0.72rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 1, justifyContent: 'flex-end', color: '#eab308' }}>
                  {Array.from({ length: 5 }).map((_, i) => (
                    <Star key={i} style={{ width: 10, height: 10, fill: i < Math.round(item.rating) ? '#eab308' : 'none' }} />
                  ))}
                  <span style={{ color: 'var(--text-3)', marginLeft: 3 }}>{item.rating}</span>
                </div>
                <div style={{ color: 'var(--text-3)', marginTop: '1px' }}>{(item.downloads / 1000).toFixed(1)}k downloads</div>
              </div>
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: '0.88rem' }}>{item.name}</div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-3)' }}>by {item.vendor}</div>
            </div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-3)', lineHeight: 1.5 }}>{item.description}</div>
            <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
              {(item.actions || []).map((a: string) => <span key={a} style={{ fontSize: '0.65rem', background: 'rgba(34,197,94,0.1)', color: '#22c55e', padding: '1px 5px', borderRadius: '3px' }}>{a}</span>)}
            </div>
            <ActionButton variant="ghost" icon={Download} disabled={installing === item.id} onClick={() => install(item)} style={{ marginTop: 'auto', fontSize: '0.78rem', justifyContent: 'center' }}>
              {installing === item.id ? 'Installing…' : 'Install'}
            </ActionButton>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── AI Tab ─────────────────────────────────────────────────────────────────────
function AITab({ playbook }: { playbook: any }) {
  const [mode, setMode] = useState<'generate' | 'explain' | 'optimize' | 'redundancy' | 'suggest' | 'ask'>('generate');
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  const AI_MODES = [
    { id: 'generate' as const, label: 'Generate', placeholder: 'Describe the playbook you want…' },
    { id: 'explain' as const, label: 'Explain', placeholder: 'Ask about the current workflow…' },
    { id: 'optimize' as const, label: 'Optimize', placeholder: 'Describe your performance goal…' },
    { id: 'redundancy' as const, label: 'Detect Redundancy', placeholder: 'Describe what to check…' },
    { id: 'suggest' as const, label: 'Suggest Automations', placeholder: 'Current manual processes to automate…' },
    { id: 'ask' as const, label: 'Ask', placeholder: 'Any SOAR/playbook question…' },
  ];

  const run = async () => {
    setLoading(true);
    const r = await pbAPI.analyzeAI({ mode, content: query, context: playbook ? `Playbook: ${playbook.name}, trigger: ${playbook.trigger_type}, status: ${playbook.status}` : '' });
    setResult(r.data);
    setLoading(false);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <SectionCard title="AI Playbook Assistant">
        <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
          {AI_MODES.map(m => (
            <ActionButton key={m.id} variant={mode === m.id ? 'primary' : 'ghost'} onClick={() => setMode(m.id)} style={{ fontSize: '0.78rem' }}>{m.label}</ActionButton>
          ))}
        </div>
        <textarea className="g-input" style={{ width: '100%', height: '80px', resize: 'vertical', marginBottom: '0.5rem' }}
          placeholder={AI_MODES.find(m => m.id === mode)?.placeholder}
          value={query} onChange={e => setQuery(e.target.value)} />
        {!playbook && <div style={{ fontSize: '0.75rem', color: 'var(--text-3)', marginBottom: '0.4rem' }}>Select a playbook from Library for context-aware analysis.</div>}
        <ActionButton variant="primary" icon={Sparkles} onClick={run} disabled={loading}>{loading ? 'Analyzing…' : 'Analyze'}</ActionButton>
      </SectionCard>

      {result && (
        <div className="g-card" style={{ padding: '1.25rem', border: '1px solid rgba(99,102,241,0.2)' }}>
          {result.summary && (
            <>
              <div style={{ fontWeight: 600, color: 'var(--accent)', marginBottom: '0.5rem' }}>Summary</div>
              <div style={{ fontSize: '0.85rem', color: 'var(--text-2)', lineHeight: 1.6, marginBottom: '0.75rem' }}>{result.summary}</div>
            </>
          )}
          {result.workflow_suggestion && (
            <div style={{ marginBottom: '0.75rem' }}>
              <div style={{ fontWeight: 600, fontSize: '0.82rem', marginBottom: '0.35rem' }}>Suggested Workflow</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                {result.workflow_suggestion.map((step: string, i: number) => (
                  <span key={i} style={{ fontSize: '0.75rem', padding: '3px 9px', borderRadius: '12px', background: 'rgba(99,102,241,0.1)', color: '#818cf8', display: 'flex', alignItems: 'center', gap: '4px' }}>
                    {i > 0 && <span style={{ color: 'var(--text-3)', fontSize: '0.65rem' }}>→</span>}{step}
                  </span>
                ))}
              </div>
            </div>
          )}
          {result.optimizations?.length > 0 && (
            <div style={{ marginBottom: '0.75rem' }}>
              <div style={{ fontWeight: 600, fontSize: '0.82rem', marginBottom: '0.35rem' }}>Optimizations</div>
              {result.optimizations.map((o: string, i: number) => (
                <div key={i} style={{ fontSize: '0.8rem', color: '#22c55e', paddingLeft: '0.5rem', borderLeft: '2px solid #22c55e', marginBottom: '0.3rem' }}>→ {o}</div>
              ))}
            </div>
          )}
          {result.warnings?.length > 0 && (
            <div>
              <div style={{ fontWeight: 600, fontSize: '0.82rem', marginBottom: '0.35rem' }}>Warnings</div>
              {result.warnings.map((w: string, i: number) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: '0.8rem', color: '#eab308', paddingLeft: '0.5rem', borderLeft: '2px solid #eab308', marginBottom: '0.3rem' }}>
                  <AlertTriangle style={{ width: 11, height: 11, flexShrink: 0 }} /> {w}
                </div>
              ))}
            </div>
          )}
          {result.explanation && <div style={{ fontSize: '0.82rem', color: 'var(--text-2)', lineHeight: 1.6 }}>{result.explanation}</div>}
          {result.answer && <div style={{ fontSize: '0.85rem', color: 'var(--text-2)', lineHeight: 1.6 }}>{result.answer}</div>}
        </div>
      )}
    </div>
  );
}

// ── Reports Tab ────────────────────────────────────────────────────────────────
function ReportsTab() {
  const [type, setType] = useState('executive');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<any>(null);

  const gen = async () => {
    setLoading(true);
    const r = await pbAPI.generateReport({ report_type: type });
    setReport(r.data);
    setLoading(false);
  };

  const TYPES = ['executive', 'automation', 'performance', 'compliance', 'lessons_learned'];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <SectionCard title="Generate Report">
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <select className="g-select" value={type} onChange={e => setType(e.target.value)} style={{ width: 220 }}>
            {TYPES.map(t => <option key={t} value={t}>{t.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</option>)}
          </select>
          <ActionButton variant="primary" onClick={gen} disabled={loading}>{loading ? 'Generating…' : 'Generate Report'}</ActionButton>
        </div>
      </SectionCard>

      {report && (
        <div className="g-card" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
            <div style={{ fontWeight: 700, fontSize: '1.05rem' }}>{report.title}</div>
            <span style={{ fontSize: '0.72rem', background: 'rgba(239,68,68,0.1)', color: '#ef4444', padding: '2px 8px', borderRadius: '3px', flexShrink: 0 }}>{report.classification}</span>
          </div>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-2)', lineHeight: 1.7, marginBottom: '1rem' }}>{report.executive_summary}</div>
          {report.key_metrics && (
            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
              {Object.entries(report.key_metrics).map(([k, v]) => (
                <MetricCard key={k} label={k.replace(/_/g, ' ')} value={String(v)} />
              ))}
            </div>
          )}
          {report.top_playbooks && (
            <div style={{ marginBottom: '1rem' }}>
              <div style={{ fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.4rem' }}>Top Playbooks</div>
              {report.top_playbooks.map((pb: any) => (
                <div key={pb.name} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', padding: '0.25rem 0', borderBottom: '1px solid var(--border)' }}>
                  <span>{pb.name}</span>
                  <span style={{ color: 'var(--text-3)' }}>{pb.runs} runs · <span style={{ color: '#22c55e' }}>{pb.success_rate}%</span></span>
                </div>
              ))}
            </div>
          )}
          {report.recommendations && (
            <div>
              <div style={{ fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.4rem' }}>Recommendations</div>
              {report.recommendations.map((r: string, i: number) => (
                <div key={i} style={{ fontSize: '0.8rem', color: '#22c55e', paddingLeft: '0.5rem', borderLeft: '2px solid #22c55e', marginBottom: '0.25rem' }}>→ {r}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────────
export default function PlaybooksPage() {
  const [tab, setTab] = useState<Tab>('overview');
  const [dash, setDash] = useState<any>(null);
  const [selectedPlaybook, setSelectedPlaybook] = useState<any>(null);
  const loaded = useRef<Record<string, boolean>>({});

  useEffect(() => { pbAPI.getDashboard().then(r => setDash(r.data)); }, []);

  if (!loaded.current[tab]) loaded.current[tab] = true;

  const handleEdit = (pb: any) => { setSelectedPlaybook(pb); setTab('builder'); };
  const handleExecute = async (pb: any) => {
    const r = await pbAPI.executePlaybook(pb.id, { trigger_type: 'manual' });
    if (r.data?.execution_id) {
      const statusMsg = r.data.status === 'pending' ? 'paused at an approval gate' : r.data.status === 'failed' ? 'failed' : 'succeeded';
      alert(`Execution ${r.data.execution_id} ${statusMsg}`);
      setTab('executions');
    }
  };
  const handleInstall = (t: any) => { alert(`"${t.name}" installed. Go to Library to edit it.`); setTab('library'); };

  const tabs = Object.keys(TAB_LABELS) as Tab[];

  return (
    <RootLayout title="Playbooks & SOAR"
      subtitle="Visual workflow automation · Human-in-the-Loop approvals · AI-assisted response"
      actions={selectedPlaybook ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.3)', padding: '0.5rem 1rem', borderRadius: '6px' }}>
          <div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-3)' }}>Editing</div>
            <div style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--accent)' }}>{selectedPlaybook.name}</div>
          </div>
          <code style={{ fontSize: '0.72rem', color: '#818cf8' }}>v{selectedPlaybook.version}</code>
          <ActionButton variant="ghost" icon={X} onClick={() => setSelectedPlaybook(null)} style={{ padding: '3px 6px' }} />
        </div>
      ) : undefined}>
      <div style={{ padding: '1.5rem', maxWidth: '1400px', margin: '0 auto' }}>
        <div style={{ marginBottom: '1.5rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.75rem' }}>
          <TabBar
            tabs={tabs.map(t => ({
              key: t,
              label: TAB_LABELS[t],
              icon: TAB_ICONS[t],
              count: t === 'approvals' ? (dash?.pending_approvals > 0 ? dash.pending_approvals : undefined) : undefined,
            }))}
            active={tab}
            onChange={t => setTab(t as Tab)}
          />
        </div>

        <div style={{ display: loaded.current['overview'] && tab === 'overview' ? 'block' : 'none' }}>
          {loaded.current['overview'] && <OverviewTab dash={dash} />}
        </div>
        <div style={{ display: loaded.current['library'] && tab === 'library' ? 'block' : 'none' }}>
          {loaded.current['library'] && <LibraryTab onEdit={handleEdit} onExecute={handleExecute} />}
        </div>
        <div style={{ display: loaded.current['builder'] && tab === 'builder' ? 'block' : 'none' }}>
          {loaded.current['builder'] && <BuilderTab playbook={selectedPlaybook} onSelectPlaybook={() => setTab('library')} />}
        </div>
        <div style={{ display: loaded.current['executions'] && tab === 'executions' ? 'block' : 'none' }}>
          {loaded.current['executions'] && <ExecutionsTab />}
        </div>
        <div style={{ display: loaded.current['approvals'] && tab === 'approvals' ? 'block' : 'none' }}>
          {loaded.current['approvals'] && <ApprovalsTab />}
        </div>
        <div style={{ display: loaded.current['analytics'] && tab === 'analytics' ? 'block' : 'none' }}>
          {loaded.current['analytics'] && <AnalyticsTab />}
        </div>
        <div style={{ display: loaded.current['templates'] && tab === 'templates' ? 'block' : 'none' }}>
          {loaded.current['templates'] && <TemplatesTab onInstall={handleInstall} />}
        </div>
        <div style={{ display: loaded.current['marketplace'] && tab === 'marketplace' ? 'block' : 'none' }}>
          {loaded.current['marketplace'] && <MarketplaceTab onInstall={handleInstall} />}
        </div>
        <div style={{ display: loaded.current['ai'] && tab === 'ai' ? 'block' : 'none' }}>
          {loaded.current['ai'] && <AITab playbook={selectedPlaybook} />}
        </div>
        <div style={{ display: loaded.current['reports'] && tab === 'reports' ? 'block' : 'none' }}>
          {loaded.current['reports'] && <ReportsTab />}
        </div>
      </div>
    </RootLayout>
  );
}
