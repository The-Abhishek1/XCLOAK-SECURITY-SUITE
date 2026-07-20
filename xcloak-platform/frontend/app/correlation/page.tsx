'use client';

import {
  useState, useEffect, useCallback, useMemo, useRef,
} from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { correlationAPI, playbooksAPI } from '@/lib/api';
import { CorrelationMatch } from '@/types';
import { timeAgo } from '@/lib/utils';
import { Activity, AlertTriangle, ArrowRight, BarChart3, Brain, Check, CheckCircle2, ChevronDown, ChevronUp, Copy, Cpu, Database, Filter, GitBranch, GitMerge, Layers, Network, Play, Plus, Search, Shield, Target, ToggleLeft, ToggleRight, Trash2, Zap, Lock } from '@/lib/icon-stubs';

// ── Types ─────────────────────────────────────────────────────────────────────

type ViewTab =
  | 'overview' | 'rules' | 'builder' | 'chain' | 'graph'
  | 'analytics' | 'grouping' | 'ai' | 'testing' | 'performance';

interface Overview {
  total_rules: number;
  active_rules: number;
  disabled_rules: number;
  matches_24h: number;
  incidents_created_24h: number;
  suppression_rules: number;
  avg_confidence: string;
  high_conf_matches: number;
  fp_rate: string;
  rule_breakdown: Array<{ type: string; count: number; enabled: number }>;
  top_rules: Array<{ id: number; name: string; match_count: number; severity: string }>;
}

interface TrendBucket { hour: string; matches: number; incidents: number; }

interface RuleAnalytic {
  id: number; name: string; severity: string; correlation_type: string;
  enabled: boolean; match_count: number; mitre_technique: string;
  matches_24h: number; incidents_24h: number; last_triggered: string | null;
}

interface GraphNode {
  id: string; label: string; type: 'rule' | 'agent' | 'incident'; count: number;
}
interface GraphEdge { source: string; target: string; confidence: number; }

interface AlertGrouping {
  by_host: Array<{ host: string; agent_id: number; alert_count: number; max_severity: string }>;
  by_mitre: Array<{ technique: string; count: number }>;
  by_severity: Array<{ severity: string; count: number }>;
}

interface Performance {
  total_rules: number; active_rules: number; matches_last_hour: number;
  incidents_last_hour: number; total_matches_all: number;
  queue_depth: number; avg_latency_ms: number; uptime_pct: number;
  engines: Array<{ name: string; status: string; avg_ms: number; rules?: number }>;
}

interface SimResult {
  matches: Array<{
    rule_id: number; rule_name: string; severity: string;
    would_fire: boolean; matched_stages: string[]; missed_stages: string[];
    coverage_pct: number;
  }>;
  total_rules: number; fired: number; missed: number; summary: string;
}

interface AIResult { raw: string; parsed: Record<string, unknown> | null; }

// ── Rule form types (from existing page) ──────────────────────────────────────

interface Stage { pattern: string; source_type: string; }

interface Rule {
  id: number; name: string; description: string; severity: string;
  rule_name: string; mitre_technique: string; agent_id: number;
  action: string; playbook_id: number; enabled: boolean; match_count: number;
  created_by: string; created_at: string; correlation_type: string;
  window_minutes: number; threshold: number; source_type: string;
  condition_value: string; stages: Stage[] | null;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const ACTIONS = ['create_incident', 'notify'];
const SEVERITIES = ['', 'critical', 'high', 'medium', 'low'];
const CORRELATION_TYPES = [
  { id: 'simple',           label: 'Simple — single alert' },
  { id: 'event_count',      label: 'Event Count — N+ within time window' },
  { id: 'temporal',         label: 'Temporal — all stages within window (any order)' },
  { id: 'temporal_ordered', label: 'Temporal Ordered — stages in order (attack chain)' },
];
const SOURCE_TYPES = [
  { id: 'alert',           label: 'Alert' },
  { id: 'vulnerability',   label: 'Vulnerability (EPSS/KEV)' },
  { id: 'network_connect', label: 'Network Connection' },
  { id: 'risk_score',      label: 'Risk Score' },
];
const CONDITION_PLACEHOLDER: Record<string, string> = {
  vulnerability: 'kev  or  epss>=0.7  or  CVE-2024-…',
  network_connect: 'external  or  internal  or  10.0.0.',
  risk_score: '70',
};
const EMPTY_FORM = {
  name: '', description: '', severity: '', rule_name: '',
  mitre_technique: '', agent_id: 0, action: 'create_incident', playbook_id: 0,
  correlation_type: 'simple', window_minutes: 10, threshold: 3,
  source_type: 'alert', condition_value: '',
  stages: [{ pattern: '', source_type: 'alert' }, { pattern: '', source_type: 'alert' }] as Stage[],
};

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)', high: '#fb923c', medium: '#fbbf24',
  low: 'var(--accent)', informational: 'var(--text-3)',
};

const TABS: Array<{ id: ViewTab; label: string; icon: React.ElementType }> = [
  { id: 'overview',     label: 'Overview',     icon: BarChart3 },
  { id: 'rules',        label: 'Rules',        icon: GitMerge },
  { id: 'builder',      label: 'Builder',      icon: GitBranch },
  { id: 'chain',        label: 'Attack Chain', icon: Layers },
  { id: 'graph',        label: 'Graph',        icon: Network },
  { id: 'analytics',    label: 'Analytics',    icon: Activity },
  { id: 'grouping',     label: 'Grouping',     icon: Filter },
  { id: 'ai',           label: 'AI Analysis',  icon: Brain },
  { id: 'testing',      label: 'Simulation',   icon: Play },
  { id: 'performance',  label: 'Performance',  icon: Cpu },
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

function StatusDot({ ok }: { ok: boolean }) {
  return <span className="inline-block w-2 h-2 rounded-full" style={{ background: ok ? 'var(--green)' : 'var(--red)' }} />;
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

// ── KPI Card ──────────────────────────────────────────────────────────────────

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

// ── Trend Chart ────────────────────────────────────────────────────────────────

function TrendChart({ buckets }: { buckets: TrendBucket[] }) {
  const maxM = useMemo(() => Math.max(...buckets.map(b => b.matches), 1), [buckets]);
  const maxI = useMemo(() => Math.max(...buckets.map(b => b.incidents), 1), [buckets]);

  if (!buckets.length) return (
    <div className="h-16 flex items-center justify-center text-xs" style={{ color: 'var(--text-3)' }}>
      No trend data
    </div>
  );
  return (
    <div className="flex items-end gap-px h-16 w-full">
      {buckets.slice(-48).map((b, i) => (
        <div key={i} className="flex-1 flex flex-col items-center gap-px min-w-[2px]">
          <div className="w-full rounded-sm"
            title={`Matches: ${b.matches} · Incidents: ${b.incidents}`}
            style={{ height: `${Math.max(2, (b.matches / maxM) * 48)}px`, background: 'var(--accent)', opacity: 0.8 }} />
          {b.incidents > 0 && (
            <div className="w-full rounded-sm"
              style={{ height: `${Math.max(2, (b.incidents / maxI) * 12)}px`, background: 'var(--red)', opacity: 0.9 }} />
          )}
        </div>
      ))}
    </div>
  );
}

// ── Correlation Graph (SVG) ────────────────────────────────────────────────────

function CorrelationGraphView({ nodes, edges }: { nodes: GraphNode[]; edges: GraphEdge[] }) {
  const svgRef = useRef<SVGSVGElement>(null);

  const NODE_COLORS: Record<string, string> = {
    rule: 'var(--accent)', agent: 'var(--green)', incident: 'var(--red)',
  };

  // Simple layout: rules in center row, agents on left, incidents on right
  const layout = useMemo(() => {
    const rules    = nodes.filter(n => n.type === 'rule');
    const agents   = nodes.filter(n => n.type === 'agent');
    const incidents = nodes.filter(n => n.type === 'incident');

    const W = 720, H = 400;
    const pos: Record<string, { x: number; y: number }> = {};

    agents.forEach((n, i) => {
      pos[n.id] = { x: 80, y: 40 + (i * Math.min(80, (H - 80) / Math.max(agents.length, 1))) };
    });
    rules.forEach((n, i) => {
      pos[n.id] = { x: W / 2, y: 40 + (i * Math.min(80, (H - 80) / Math.max(rules.length, 1))) };
    });
    incidents.forEach((n, i) => {
      pos[n.id] = { x: W - 80, y: 40 + (i * Math.min(80, (H - 80) / Math.max(incidents.length, 1))) };
    });
    return pos;
  }, [nodes]);

  if (!nodes.length) return (
    <div className="py-16 text-center text-sm" style={{ color: 'var(--text-3)' }}>
      No correlation graph data in the selected time range.
    </div>
  );

  return (
    <div className="g-card p-4 overflow-x-auto">
      <div className="flex items-center gap-4 mb-4 text-xs">
        <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-full inline-block" style={{ background: 'var(--green)' }} />Agent</span>
        <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-full inline-block" style={{ background: 'var(--accent)' }} />Correlation Rule</span>
        <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-full inline-block" style={{ background: 'var(--red)' }} />Incident</span>
      </div>
      <svg ref={svgRef} width="100%" viewBox="0 0 720 400" className="rounded-lg"
        style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', minHeight: 200 }}>
        {/* Edges */}
        {edges.slice(0, 100).map((e, i) => {
          const s = layout[e.source];
          const t = layout[e.target];
          if (!s || !t) return null;
          const opacity = Math.max(0.1, e.confidence / 100);
          return (
            <line key={i} x1={s.x} y1={s.y} x2={t.x} y2={t.y}
              stroke="var(--border)" strokeWidth={1.5} strokeOpacity={opacity} />
          );
        })}
        {/* Nodes */}
        {nodes.map(n => {
          const p = layout[n.id];
          if (!p) return null;
          const color = NODE_COLORS[n.type] ?? 'var(--text-3)';
          const r = Math.min(18, 8 + n.count * 2);
          return (
            <g key={n.id} transform={`translate(${p.x},${p.y})`}>
              <circle r={r} fill={`color-mix(in srgb, ${color} 20%, var(--glass-bg))`}
                stroke={color} strokeWidth={1.5} />
              <text y={r + 12} textAnchor="middle" fontSize={9} fill="var(--text-2)"
                className="select-none">
                {n.label.slice(0, 16)}{n.label.length > 16 ? '…' : ''}
              </text>
              {n.count > 1 && (
                <text y={4} textAnchor="middle" fontSize={8} fontWeight="bold" fill={color}>
                  {n.count}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      <div className="flex justify-between mt-2 text-[10px]" style={{ color: 'var(--text-3)' }}>
        <span>{nodes.filter(n => n.type === 'agent').length} agents</span>
        <span>{nodes.filter(n => n.type === 'rule').length} rules</span>
        <span>{nodes.filter(n => n.type === 'incident').length} incidents</span>
        <span>{edges.length} edges</span>
      </div>
    </div>
  );
}

// ── Attack Chain Visualizer ────────────────────────────────────────────────────

const MITRE_CHAIN = [
  { tactic: 'Reconnaissance',     technique: 'T1595', example: 'Port Scan / Active Scanning' },
  { tactic: 'Initial Access',     technique: 'T1566', example: 'Phishing / Spear Phishing' },
  { tactic: 'Execution',          technique: 'T1059', example: 'PowerShell / WMI / Script' },
  { tactic: 'Persistence',        technique: 'T1053', example: 'Scheduled Task / Registry Run' },
  { tactic: 'Privilege Escalation',technique: 'T1068', example: 'LSASS Dump / Token Impersonation' },
  { tactic: 'Defense Evasion',    technique: 'T1027', example: 'Obfuscation / LOLBins / AV Bypass' },
  { tactic: 'Credential Access',  technique: 'T1003', example: 'LSASS Access / Kerberoasting' },
  { tactic: 'Discovery',          technique: 'T1082', example: 'System Info / AD Enumeration' },
  { tactic: 'Lateral Movement',   technique: 'T1021', example: 'RDP / SMB / WinRM / PsExec' },
  { tactic: 'Collection',         technique: 'T1005', example: 'Data Staging / Archive Creation' },
  { tactic: 'C2',                 technique: 'T1071', example: 'DNS Tunnel / HTTPS C2 / Beacon' },
  { tactic: 'Exfiltration',       technique: 'T1041', example: 'Exfil over C2 / HTTP POST' },
  { tactic: 'Impact',             technique: 'T1486', example: 'Ransomware / Wiper / Defacement' },
];

function AttackChainView({ rules }: { rules: Rule[] }) {
  const [hoveredTactic, setHoveredTactic] = useState<string | null>(null);

  // Map rules to tactics based on mitre_technique
  const techniqueToTactic = new Map<string, string>();
  for (const step of MITRE_CHAIN) {
    techniqueToTactic.set(step.technique, step.tactic);
  }

  const rulesByTactic = useMemo(() => {
    const m = new Map<string, Rule[]>();
    for (const r of rules) {
      if (!r.mitre_technique) continue;
      const tech = r.mitre_technique.substring(0, 5);
      for (const step of MITRE_CHAIN) {
        if (step.technique === tech || step.technique.startsWith(tech)) {
          const existing = m.get(step.tactic) || [];
          existing.push(r);
          m.set(step.tactic, existing);
          break;
        }
      }
    }
    return m;
  }, [rules]);

  return (
    <div className="space-y-4">
      <div className="g-card p-4">
        <p className="text-xs font-semibold mb-4" style={{ color: 'var(--text-1)' }}>
          MITRE ATT&CK Chain — Correlation Coverage
          <span className="ml-2 text-[10px] font-normal" style={{ color: 'var(--text-3)' }}>
            Stages covered by temporal_ordered rules are highlighted
          </span>
        </p>
        <div className="flex flex-col gap-0">
          {MITRE_CHAIN.map((step, i) => {
            const covered = rulesByTactic.get(step.tactic) || [];
            const isHovered = hoveredTactic === step.tactic;
            return (
              <div key={step.tactic}
                className="flex items-stretch cursor-pointer"
                onMouseEnter={() => setHoveredTactic(step.tactic)}
                onMouseLeave={() => setHoveredTactic(null)}>
                {/* Step number + connector line */}
                <div className="flex flex-col items-center w-8 shrink-0">
                  <div className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold z-10"
                    style={{
                      background: covered.length > 0 ? 'color-mix(in srgb, var(--accent) 25%, var(--glass-bg))' : 'var(--glass-bg)',
                      border: `1px solid ${covered.length > 0 ? 'var(--accent)' : 'var(--border)'}`,
                      color: covered.length > 0 ? 'var(--accent)' : 'var(--text-3)',
                    }}>
                    {i + 1}
                  </div>
                  {i < MITRE_CHAIN.length - 1 && (
                    <div className="w-px flex-1 mt-1"
                      style={{ background: covered.length > 0 ? 'var(--accent)' : 'var(--border)', opacity: 0.4 }} />
                  )}
                </div>
                {/* Content */}
                <div className="flex-1 ml-3 pb-4 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-medium" style={{ color: covered.length > 0 ? 'var(--text-1)' : 'var(--text-3)' }}>
                      {step.tactic}
                    </span>
                    <span className="font-mono text-[10px]" style={{ color: 'var(--text-3)' }}>{step.technique}</span>
                    {covered.length > 0 && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded"
                        style={{ background: 'color-mix(in srgb, var(--accent) 15%, transparent)', color: 'var(--accent)' }}>
                        {covered.length} rule{covered.length > 1 ? 's' : ''}
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] mt-0.5" style={{ color: 'var(--text-3)' }}>{step.example}</p>
                  {isHovered && covered.length > 0 && (
                    <div className="mt-2 space-y-1">
                      {covered.map(r => (
                        <div key={r.id} className="flex items-center gap-2 text-[11px]">
                          <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: 'var(--accent)' }} />
                          <span style={{ color: 'var(--text-2)' }}>{r.name}</span>
                          {sevBadge(r.severity)}
                        </div>
                      ))}
                    </div>
                  )}
                  {covered.length === 0 && (
                    <span className="text-[10px] mt-0.5" style={{ color: 'rgba(248,81,73,0.6)' }}>No coverage</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Example: VPN Lateral Movement chain */}
      <div className="g-card p-4">
        <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>
          Example: VPN Lateral Movement → Ransomware Chain
        </p>
        <div className="flex flex-col gap-0">
          {[
            { label: 'VPN Login',         detail: 'Off-hours access from new IP',     sev: 'medium' },
            { label: 'PowerShell Exec',   detail: 'Encoded command, spawned from Office', sev: 'high' },
            { label: 'LSASS Access',      detail: 'T1003.001 — credential dumping',   sev: 'critical' },
            { label: 'RDP Lateral',       detail: 'T1021.001 — pass-the-hash RDP',    sev: 'high' },
            { label: 'SMB Spread',        detail: 'T1021.002 — file share traversal', sev: 'high' },
            { label: 'Data Staging',      detail: 'T1074 — collection before exfil',  sev: 'medium' },
            { label: 'Ransomware Deploy', detail: 'T1486 — volume shadow delete',     sev: 'critical' },
            { label: '→ Incident',        detail: 'Correlation rule fires → IR',      sev: 'critical' },
          ].map((s, i, arr) => (
            <div key={i} className="flex items-stretch">
              <div className="flex flex-col items-center w-8 shrink-0">
                <div className="w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-bold"
                  style={{
                    background: i === arr.length - 1 ? 'rgba(248,81,73,0.2)' : 'var(--glass-bg-2)',
                    border: `1px solid ${i === arr.length - 1 ? 'var(--red)' : 'var(--border)'}`,
                    color: i === arr.length - 1 ? 'var(--red)' : 'var(--text-3)',
                  }}>
                  {i + 1}
                </div>
                {i < arr.length - 1 && <div className="w-px flex-1 mt-1 mb-1" style={{ background: 'var(--border)' }} />}
              </div>
              <div className="flex-1 ml-3 pb-3">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-medium" style={{ color: i === arr.length - 1 ? 'var(--red)' : 'var(--text-1)' }}>
                    {s.label}
                  </span>
                  {sevBadge(s.sev)}
                </div>
                <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{s.detail}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Visual Builder ─────────────────────────────────────────────────────────────

interface BuilderBlock {
  id: string; type: 'if' | 'and' | 'or' | 'not' | 'sequence' | 'threshold' | 'within';
  value: string; children?: BuilderBlock[];
}

function BlockEditor({ block, onUpdate, onRemove, depth = 0 }: {
  block: BuilderBlock;
  onUpdate: (b: BuilderBlock) => void;
  onRemove: () => void;
  depth?: number;
}) {
  const colors: Record<string, string> = {
    if: 'var(--accent)', and: 'var(--green)', or: '#a78bfa',
    not: 'var(--red)', sequence: '#fbbf24', threshold: '#fb923c', within: '#60a5fa',
  };
  const color = colors[block.type] ?? 'var(--text-3)';

  const addChild = (type: BuilderBlock['type']) => {
    const newBlock: BuilderBlock = { id: `${Date.now()}`, type, value: '' };
    onUpdate({ ...block, children: [...(block.children || []), newBlock] });
  };
  const updateChild = (id: string, updated: BuilderBlock) => {
    onUpdate({ ...block, children: block.children?.map(c => c.id === id ? updated : c) });
  };
  const removeChild = (id: string) => {
    onUpdate({ ...block, children: block.children?.filter(c => c.id !== id) });
  };

  return (
    <div className="rounded-lg overflow-hidden" style={{ border: `1px solid ${color}`, marginLeft: depth > 0 ? 16 : 0 }}>
      <div className="flex items-center gap-2 px-3 py-2" style={{ background: `color-mix(in srgb, ${color} 10%, var(--glass-bg))` }}>
        <span className="text-[11px] font-bold uppercase tracking-wide w-16 shrink-0" style={{ color }}>{block.type}</span>
        {['if', 'not', 'sequence', 'threshold', 'within'].includes(block.type) && (
          <input value={block.value} onChange={e => onUpdate({ ...block, value: e.target.value })}
            placeholder={block.type === 'within' ? 'e.g. 10 minutes' : block.type === 'threshold' ? 'e.g. 5 times' : 'condition or event…'}
            className="flex-1 text-xs bg-transparent border-none outline-none"
            style={{ color: 'var(--text-1)' }} />
        )}
        <div className="flex items-center gap-1 ml-auto">
          {['and', 'or', 'not', 'sequence'].includes(block.type) && (
            <>
              <button onClick={() => addChild('and')} className="text-[9px] px-1.5 py-0.5 rounded" style={{ background: 'var(--glass-bg-2)', color: 'var(--green)' }}>+AND</button>
              <button onClick={() => addChild('or')} className="text-[9px] px-1.5 py-0.5 rounded" style={{ background: 'var(--glass-bg-2)', color: '#a78bfa' }}>+OR</button>
              <button onClick={() => addChild('not')} className="text-[9px] px-1.5 py-0.5 rounded" style={{ background: 'var(--glass-bg-2)', color: 'var(--red)' }}>+NOT</button>
              <button onClick={() => addChild('if')} className="text-[9px] px-1.5 py-0.5 rounded" style={{ background: 'var(--glass-bg-2)', color: 'var(--accent)' }}>+IF</button>
            </>
          )}
          {depth > 0 && (
            <button onClick={onRemove} className="text-[10px]" style={{ color: 'var(--text-3)' }} title="Remove">
              ×
            </button>
          )}
        </div>
      </div>
      {block.children && block.children.length > 0 && (
        <div className="p-2 space-y-2" style={{ background: 'var(--glass-bg)' }}>
          {block.children.map(child => (
            <BlockEditor key={child.id} block={child} depth={depth + 1}
              onUpdate={u => updateChild(child.id, u)}
              onRemove={() => removeChild(child.id)} />
          ))}
        </div>
      )}
    </div>
  );
}

function VisualBuilderPanel({ onCreateRule }: { onCreateRule: (form: typeof EMPTY_FORM) => void }) {
  const [tree, setTree] = useState<BuilderBlock>({
    id: 'root', type: 'if', value: 'VPN Login',
    children: [
      { id: '1', type: 'and', value: '', children: [
        { id: '2', type: 'if', value: 'PowerShell Exec' },
        { id: '3', type: 'and', value: '', children: [
          { id: '4', type: 'if', value: 'LSASS Access' },
        ]},
      ]},
      { id: '5', type: 'within', value: '10 minutes' },
    ],
  });
  const [action, setAction] = useState('create_incident');
  const [ruleName, setRuleName] = useState('');

  const addTopLevel = (type: BuilderBlock['type']) => {
    const newBlock: BuilderBlock = { id: `${Date.now()}`, type, value: '' };
    setTree(t => ({ ...t, children: [...(t.children || []), newBlock] }));
  };

  const extractStages = (b: BuilderBlock): string[] => {
    const stages: string[] = [];
    if (b.type === 'if' && b.value) stages.push(b.value);
    for (const child of b.children || []) stages.push(...extractStages(child));
    return stages;
  };

  const handleCreate = () => {
    if (!ruleName) return;
    const stages = extractStages(tree);
    const form = {
      ...EMPTY_FORM,
      name: ruleName,
      correlation_type: 'temporal_ordered',
      action,
      stages: stages.map(s => ({ pattern: s, source_type: 'alert' })),
      window_minutes: 10,
    };
    onCreateRule(form);
  };

  return (
    <div className="space-y-4">
      <div className="g-card p-4">
        <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Visual Rule Builder</p>
        <p className="text-[11px] mb-4" style={{ color: 'var(--text-3)' }}>
          Drag-and-drop logic builder for multi-stage attack chain detection. IF blocks define events; AND/OR/NOT control logic; WITHIN sets the time window.
        </p>

        <div className="mb-4 space-y-2">
          <BlockEditor block={tree} onUpdate={setTree} onRemove={() => {}} depth={0} />
        </div>

        <div className="flex flex-wrap gap-2 mb-4">
          {(['and', 'or', 'not', 'if', 'sequence', 'within', 'threshold'] as BuilderBlock['type'][]).map(t => (
            <button key={t} onClick={() => addTopLevel(t)}
              className="text-[10px] px-2 py-1 rounded font-medium"
              style={{ background: 'var(--glass-bg-2)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>
              + {t.toUpperCase()}
            </button>
          ))}
        </div>

        <div className="grid grid-cols-2 gap-3 mb-3">
          <div>
            <label className="text-[10px] uppercase tracking-wider mb-1 block" style={{ color: 'var(--text-3)' }}>Rule Name</label>
            <input value={ruleName} onChange={e => setRuleName(e.target.value)}
              placeholder="e.g. VPN Lateral Movement Chain" className="g-input text-xs w-full" />
          </div>
          <div>
            <label className="text-[10px] uppercase tracking-wider mb-1 block" style={{ color: 'var(--text-3)' }}>Action</label>
            <select value={action} onChange={e => setAction(e.target.value)} className="g-select text-xs w-full">
              {ACTIONS.map(a => <option key={a} value={a}>{a}</option>)}
            </select>
          </div>
        </div>
        <button onClick={handleCreate} disabled={!ruleName} className="g-btn g-btn-primary text-xs">
          <Plus className="w-3.5 h-3.5" /> Create Rule from Builder
        </button>
      </div>

      {/* Architecture diagram */}
      <div className="g-card p-4">
        <p className="text-xs font-semibold mb-4" style={{ color: 'var(--text-1)' }}>How Correlation Fits in XCloak</p>
        <div className="flex flex-col gap-0 max-w-xs mx-auto">
          {[
            { label: 'Log Sources', sub: 'EDR · Firewall · DPI · Cloud · UEBA · MDM', icon: Database, color: '#60a5fa' },
            { label: 'Normalization', sub: 'Parser · Field extraction · Type casting', icon: Layers, color: '#a78bfa' },
            { label: 'Detection Engine', sub: 'Sigma · YARA · IOC · Behavioral', icon: Shield, color: 'var(--accent)' },
            { label: 'Correlation Engine', sub: 'Temporal · Event Count · Sequence', icon: GitBranch, color: '#34d399', highlight: true },
            { label: 'Risk Scoring', sub: 'Event · User · Asset · Business impact', icon: BarChart3, color: '#fbbf24' },
            { label: 'Alert', sub: 'Dedup · Suppression · Priority', icon: AlertTriangle, color: '#fb923c' },
            { label: 'Incident', sub: 'Auto-correlation · Case management', icon: Target, color: 'var(--red)' },
            { label: 'SOAR', sub: 'Playbook · Response automation', icon: Zap, color: '#f472b6' },
          ].map((s, i, arr) => (
            <div key={s.label} className="flex items-stretch">
              <div className="flex flex-col items-center w-10 shrink-0">
                <div className="w-8 h-8 rounded-lg flex items-center justify-center"
                  style={{
                    background: `color-mix(in srgb, ${s.color} ${(s as {highlight?: boolean}).highlight ? 30 : 15}%, var(--glass-bg))`,
                    border: `1px solid ${(s as {highlight?: boolean}).highlight ? s.color : 'var(--border)'}`,
                  }}>
                  <s.icon className="w-4 h-4" style={{ color: s.color }} />
                </div>
                {i < arr.length - 1 && (
                  <div className="w-px flex-1 my-1" style={{ background: 'var(--border)' }} />
                )}
              </div>
              <div className="flex-1 ml-3 pb-3">
                <p className="text-xs font-medium" style={{ color: (s as {highlight?: boolean}).highlight ? s.color : 'var(--text-1)' }}>
                  {s.label}
                </p>
                <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{s.sub}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── AI Analysis Panel ──────────────────────────────────────────────────────────

function AIAnalysisPanel() {
  const [action, setAction] = useState('analyze');
  const [context, setContext] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AIResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const AI_ACTIONS = [
    { id: 'analyze',  label: 'Analyze Matches',   icon: Brain,      desc: 'Analyze recent correlation matches for patterns and campaigns' },
    { id: 'suggest',  label: 'Suggest Rules',      icon: Plus,       desc: 'Suggest new correlation rules based on recent activity' },
    { id: 'chain',    label: 'Reconstruct Chain',  icon: GitBranch,  desc: 'Map recent matches to a MITRE ATT&CK attack chain' },
    { id: 'cluster',  label: 'Cluster Incidents',  icon: Layers,     desc: 'Group matches into distinct attack campaigns' },
  ];

  const run = async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await correlationAPI.aiAnalysis(action, context);
      const raw = typeof res.data === 'string' ? res.data : JSON.stringify(res.data, null, 2);
      let parsed: Record<string, unknown> | null = null;
      try { parsed = typeof res.data === 'object' ? res.data as Record<string, unknown> : JSON.parse(raw); } catch {}
      setResult({ raw, parsed });
    } catch {
      setError('AI analysis failed. Ensure there are recent correlation matches.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {AI_ACTIONS.map(a => (
          <button key={a.id} onClick={() => setAction(a.id)}
            className={`p-3 rounded-xl text-left transition-colors ${action === a.id ? 'g-btn g-btn-primary' : 'g-card'}`}>
            <a.icon className="w-4 h-4 mb-2" style={{ color: action === a.id ? 'white' : 'var(--accent)' }} />
            <p className="text-xs font-medium">{a.label}</p>
            <p className="text-[10px] mt-0.5" style={{ color: action === a.id ? 'rgba(255,255,255,0.7)' : 'var(--text-3)' }}>{a.desc}</p>
          </button>
        ))}
      </div>

      <div className="g-card p-4 space-y-3">
        <label className="text-xs font-medium" style={{ color: 'var(--text-2)' }}>Additional Context (optional)</label>
        <textarea value={context} onChange={e => setContext(e.target.value)}
          placeholder="Describe environment, active incidents, threat actor context, etc."
          className="g-input w-full text-xs resize-none" rows={3} />
        <button onClick={run} disabled={loading} className="g-btn g-btn-primary text-xs">
          <Brain className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          {loading ? 'Analyzing…' : 'Run AI Analysis'}
        </button>
      </div>

      {error && <div className="g-card p-3 text-xs" style={{ color: 'var(--red)' }}>{error}</div>}

      {result && (
        <div className="g-card p-4 space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>AI Result</p>
            <CopyBtn text={result.raw} />
          </div>
          {result.parsed ? (
            <div className="space-y-3">
              {Object.entries(result.parsed).map(([key, val]) => (
                <div key={key}>
                  <p className="text-[10px] uppercase tracking-wider mb-1 font-semibold" style={{ color: 'var(--text-3)' }}>{key.replace(/_/g, ' ')}</p>
                  {Array.isArray(val) ? (
                    <ul className="space-y-1.5">
                      {(val as unknown[]).map((item, i) => (
                        <li key={i} className="text-xs flex items-start gap-1.5">
                          <span className="w-1.5 h-1.5 rounded-full mt-1 shrink-0" style={{ background: 'var(--accent)' }} />
                          <span style={{ color: 'var(--text-2)' }}>{typeof item === 'object' ? JSON.stringify(item) : String(item)}</span>
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
            <pre className="text-[11px] p-3 rounded-lg overflow-x-auto leading-relaxed"
              style={{ background: 'var(--bg-0)', color: 'var(--text-1)', border: '1px solid var(--border)' }}>
              {result.raw}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

// ── Simulation Panel ───────────────────────────────────────────────────────────

function SimulationPanel() {
  const [chain, setChain] = useState(['VPN Login', 'PowerShell Exec', 'LSASS Access', 'RDP Lateral', 'SMB Spread']);
  const [newStage, setNewStage] = useState('');
  const [window, setWindow] = useState(10);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SimResult | null>(null);

  const addStage = () => {
    if (!newStage.trim()) return;
    setChain(c => [...c, newStage.trim()]);
    setNewStage('');
  };

  const run = async () => {
    if (!chain.length) return;
    setLoading(true);
    try {
      const res = await correlationAPI.simulate(chain, window);
      setResult(res.data as SimResult);
    } catch {
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="g-card p-4 space-y-3">
        <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Attack Chain Simulation</p>
        <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
          Define an attack sequence and see which correlation rules would fire. Tests against all enabled temporal rules.
        </p>

        {/* Chain builder */}
        <div className="space-y-2">
          {chain.map((s, i) => (
            <div key={i} className="flex items-center gap-2">
              <span className="text-[11px] w-5 text-right shrink-0 font-mono" style={{ color: 'var(--text-3)' }}>{i + 1}.</span>
              <span className="flex-1 text-xs px-3 py-1.5 rounded-lg"
                style={{ background: 'var(--glass-bg-2)', color: 'var(--text-1)', border: '1px solid var(--border)' }}>
                {s}
              </span>
              <button onClick={() => setChain(c => c.filter((_, j) => j !== i))}
                className="text-[10px]" style={{ color: 'var(--text-3)' }} title="Remove">
                ×
              </button>
            </div>
          ))}
          <div className="flex items-center gap-2">
            <span className="text-[11px] w-5 text-right shrink-0 font-mono" style={{ color: 'var(--text-3)' }}>{chain.length + 1}.</span>
            <input value={newStage} onChange={e => setNewStage(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && addStage()}
              placeholder="Add stage (e.g. DNS Tunnel)…"
              className="flex-1 g-input text-xs" />
            <button onClick={addStage} className="g-btn g-btn-ghost text-xs" title="Add stage">+</button>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <label className="text-xs shrink-0" style={{ color: 'var(--text-2)' }}>Window (min)</label>
          <input type="number" value={window} onChange={e => setWindow(Number(e.target.value))}
            className="g-input text-xs w-20" min={1} max={1440} />
          <button onClick={run} disabled={loading || !chain.length} className="g-btn g-btn-primary text-xs ml-auto">
            <Play className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            {loading ? 'Simulating…' : 'Simulate'}
          </button>
        </div>
      </div>

      {result && (
        <div className="space-y-3">
          <div className="g-card p-4">
            <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-1)' }}>{result.summary}</p>
            <div className="grid grid-cols-3 gap-3">
              {[
                { label: 'Total Rules', val: result.total_rules, color: 'var(--text-2)' },
                { label: 'Would Fire', val: result.fired, color: 'var(--red)' },
                { label: 'No Match', val: result.missed, color: 'var(--text-3)' },
              ].map(s => (
                <div key={s.label} className="g-card p-3 text-center">
                  <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>{s.label}</p>
                  <p className="text-xl font-bold" style={{ color: s.color }}>{s.val}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="g-card overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
                  {['Rule','Severity','Fires','Coverage','Matched','Missing'].map(h => (
                    <th key={h} className="px-3 py-2.5 text-left font-semibold" style={{ color: 'var(--text-3)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {result.matches.map(m => (
                  <tr key={m.rule_id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td className="px-3 py-3 max-w-[180px]">
                      <p className="font-medium truncate" style={{ color: 'var(--text-1)' }}>{m.rule_name}</p>
                    </td>
                    <td className="px-3 py-3">{sevBadge(m.severity)}</td>
                    <td className="px-3 py-3">
                      {m.would_fire
                        ? <span className="flex items-center gap-1 text-[11px]" style={{ color: 'var(--red)' }}><AlertTriangle className="w-3 h-3" />Yes</span>
                        : <span style={{ color: 'var(--text-3)' }}>No</span>}
                    </td>
                    <td className="px-3 py-3">
                      <div className="flex items-center gap-2">
                        <MiniBar value={m.coverage_pct} max={100}
                          color={m.coverage_pct >= 80 ? 'var(--red)' : m.coverage_pct >= 50 ? '#fbbf24' : 'var(--text-3)'} />
                        <span className="text-[11px] tabular-nums" style={{ color: 'var(--text-2)' }}>{m.coverage_pct.toFixed(0)}%</span>
                      </div>
                    </td>
                    <td className="px-3 py-3">
                      <div className="flex flex-wrap gap-1">
                        {(m.matched_stages || []).map((s, i) => (
                          <span key={i} className="text-[10px] px-1.5 py-0.5 rounded"
                            style={{ background: 'rgba(52,211,153,0.15)', color: 'var(--green)' }}>{s}</span>
                        ))}
                      </div>
                    </td>
                    <td className="px-3 py-3">
                      <div className="flex flex-wrap gap-1">
                        {(m.missed_stages || []).map((s, i) => (
                          <span key={i} className="text-[10px] px-1.5 py-0.5 rounded"
                            style={{ background: 'rgba(248,81,73,0.15)', color: 'var(--red)' }}>{s}</span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {result.matches.length === 0 && (
              <div className="py-8 text-center text-sm" style={{ color: 'var(--text-3)' }}>
                No temporal correlation rules found. Create a temporal_ordered rule first.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Rule list (from existing page, preserved) ─────────────────────────────────

function RulesTab({ rules, playbooks, onToggle, onDelete, onToggleMatches, expandedId, matches, matchesLoading }: {
  rules: Rule[];
  playbooks: { id: number; name: string }[];
  onToggle: (id: number, enabled: boolean) => void;
  onDelete: (id: number) => void;
  onToggleMatches: (id: number) => void;
  expandedId: number | null;
  matches: CorrelationMatch[];
  matchesLoading: boolean;
}) {
  const [search, setSearch] = useState('');
  const [typeF, setTypeF] = useState('');

  const filtered = useMemo(() => rules.filter(r => {
    if (typeF && r.correlation_type !== typeF) return false;
    if (!search) return true;
    const q = search.toLowerCase();
    return r.name.toLowerCase().includes(q) || r.description.toLowerCase().includes(q);
  }), [rules, search, typeF]);

  const playbookName = (id: number) => playbooks.find(p => p.id === id)?.name || `#${id}`;

  const describeRule = (r: Rule) => {
    if (r.correlation_type === 'event_count') return (
      <p className="font-mono text-[11px]" style={{ color: 'var(--text-3)' }}>
        <span style={{ color: '#fbbf24' }}>{r.threshold}+ matches</span> within{' '}
        <span style={{ color: '#60a5fa' }}>{r.window_minutes}min</span>
        {r.severity && <> · severity={r.severity}</>}
        {' → '}<span style={{ color: 'var(--green)' }}>{r.action}</span>
      </p>
    );
    if (r.correlation_type === 'temporal' || r.correlation_type === 'temporal_ordered') return (
      <p className="font-mono text-[11px] flex items-center gap-1 flex-wrap" style={{ color: 'var(--text-3)' }}>
        {(r.stages || []).map((s, i) => (
          <span key={i} className="flex items-center gap-1">
            <span style={{ color: 'var(--accent)' }}>&ldquo;{s.pattern}&rdquo;</span>
            {i < (r.stages?.length || 0) - 1 && (
              r.correlation_type === 'temporal_ordered' ? <ArrowRight className="h-2.5 w-2.5" /> : <span>+</span>
            )}
          </span>
        ))}
        <span>within {r.window_minutes}min → </span>
        <span style={{ color: 'var(--green)' }}>{r.action}</span>
      </p>
    );
    return (
      <p className="font-mono text-[11px]" style={{ color: 'var(--text-3)' }}>
        IF{r.severity && <span style={{ color: '#fb923c' }}> severity={r.severity}</span>}
        {r.rule_name && <span style={{ color: 'var(--accent)' }}> rule≈&ldquo;{r.rule_name}&rdquo;</span>}
        {r.mitre_technique && <span style={{ color: '#fbbf24' }}> mitre={r.mitre_technique}</span>}
        {' → '}<span style={{ color: 'var(--green)' }}>{r.action}</span>
        {r.playbook_id > 0 && <span style={{ color: 'var(--accent)' }}> + {playbookName(r.playbook_id)}</span>}
      </p>
    );
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-40">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--text-3)' }} />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search rules…"
            className="g-input pl-8 py-1.5 text-xs w-full" />
        </div>
        <select value={typeF} onChange={e => setTypeF(e.target.value)} className="g-select text-xs py-1">
          <option value="">All types</option>
          {CORRELATION_TYPES.map(t => <option key={t.id} value={t.id}>{t.id}</option>)}
        </select>
        <span className="text-xs ml-auto" style={{ color: 'var(--text-3)' }}>{filtered.length} rules</span>
      </div>

      {/* Built-in rules */}
      <div>
        <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Built-in Rules (always active)</p>
        {[
          { name: 'Critical Alert → Incident', condition: 'severity = critical', action: 'create_incident' },
          { name: 'High Alert → Incident',     condition: 'severity = high', action: 'create_incident' },
          { name: 'IOC Match → Incident',      condition: 'rule_name contains "IOC"', action: 'create_incident' },
          { name: 'YARA Match → Incident',     condition: 'rule_name contains "YARA"', action: 'create_incident' },
        ].map(r => (
          <div key={r.name} className="g-card flex items-center gap-3 px-4 py-3 mb-2 opacity-70">
            <ToggleRight className="h-5 w-5 shrink-0" style={{ color: 'var(--green)' }} />
            <div className="flex-1">
              <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{r.name}</p>
              <p className="text-[10px] font-mono" style={{ color: 'var(--text-3)' }}>IF {r.condition} → {r.action}</p>
            </div>
            <span className="text-[10px] px-2 py-0.5 rounded"
              style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-3)' }}>
              built-in
            </span>
          </div>
        ))}
      </div>

      {/* Custom rules */}
      <div>
        <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Custom Rules ({rules.length})</p>
        {filtered.length === 0 ? (
          <div className="g-card py-12 text-center">
            <GitMerge className="mx-auto h-8 w-8 mb-3" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No rules match filters</p>
          </div>
        ) : filtered.map(r => (
          <div key={r.id} className="g-card mb-2">
            <div className="flex items-start gap-3 px-4 py-3">
              <button onClick={() => onToggle(r.id, r.enabled)} className="mt-0.5 shrink-0">
                {r.enabled
                  ? <ToggleRight className="h-5 w-5" style={{ color: 'var(--accent)' }} />
                  : <ToggleLeft  className="h-5 w-5" style={{ color: 'var(--text-3)' }} />}
              </button>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{r.name}</p>
                  {r.correlation_type !== 'simple' && (
                    <span className="text-[9px] px-1.5 py-0.5 rounded uppercase tracking-wide"
                      style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                      {r.correlation_type.replace('_', ' ')}
                    </span>
                  )}
                  {r.mitre_technique && (
                    <span className="text-[10px] font-mono" style={{ color: '#fbbf24' }}>{r.mitre_technique}</span>
                  )}
                  {!r.enabled && <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>disabled</span>}
                </div>
                {r.description && <p className="text-[11px] mb-1" style={{ color: 'var(--text-3)' }}>{r.description}</p>}
                {describeRule(r)}
              </div>
              <div className="flex items-center gap-3 shrink-0 text-[10px]" style={{ color: 'var(--text-3)' }}>
                <button onClick={() => onToggleMatches(r.id)} className="flex items-center gap-1">
                  {r.match_count} matches
                  {expandedId === r.id ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                </button>
                <span>{timeAgo(r.created_at)}</span>
                <button onClick={() => onDelete(r.id)} style={{ color: 'var(--text-3)' }}>
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
            {expandedId === r.id && (
              <div className="px-4 pb-3 pt-1" style={{ borderTop: '1px solid var(--border)' }}>
                {matchesLoading ? (
                  <p className="text-[10px] py-2" style={{ color: 'var(--text-3)' }}>Loading…</p>
                ) : matches.length === 0 ? (
                  <p className="text-[10px] py-2" style={{ color: 'var(--text-3)' }}>No recorded matches yet.</p>
                ) : (
                  <div className="space-y-1.5 pt-1">
                    {matches.map(m => (
                      <div key={m.id} className="flex items-center gap-3 text-[10px] font-mono"
                        style={{ color: 'var(--text-3)' }}>
                        <span style={{ color: 'var(--text-1)' }}>{m.hostname || `agent#${m.agent_id}`}</span>
                        <span className="px-1.5 py-0.5 rounded"
                          style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: m.confidence >= 70 ? 'var(--red)' : '#fbbf24' }}>
                          conf {m.confidence}
                        </span>
                        {m.incident_id && <span style={{ color: 'var(--accent)' }}>incident #{m.incident_id}</span>}
                        <span className="flex-1 truncate">{m.detail}</span>
                        <span>{timeAgo(m.matched_at)}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Create Rule Modal ──────────────────────────────────────────────────────────

function CreateRuleModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({ ...EMPTY_FORM });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [playbooks, setPlaybooks] = useState<{ id: number; name: string }[]>([]);

  useEffect(() => {
    playbooksAPI.getAll().then(r => setPlaybooks(r.data || [])).catch(() => {});
  }, []);

  const isTemporal = form.correlation_type === 'temporal' || form.correlation_type === 'temporal_ordered';

  const create = async () => {
    if (!form.name || !form.action) return;
    setSaving(true);
    setError(null);
    try {
      const payload = { ...form, stages: isTemporal ? form.stages.filter(s => s.pattern) : [] };
      await correlationAPI.create(payload);
      onCreated();
      onClose();
    } catch (e: unknown) {
      const err = e as { response?: { data?: { error?: string } } };
      setError(err?.response?.data?.error || 'Failed to create rule');
    } finally {
      setSaving(false);
    }
  };

  const addStage = () => setForm(f => ({ ...f, stages: [...f.stages, { pattern: '', source_type: 'alert' }] }));
  const removeStage = (idx: number) => setForm(f => ({ ...f, stages: f.stages.filter((_, i) => i !== idx) }));
  const updateStage = (idx: number, val: string) => setForm(f => ({ ...f, stages: f.stages.map((s, i) => i === idx ? { ...s, pattern: val } : s) }));
  const updateStageSource = (idx: number, src: string) => setForm(f => ({ ...f, stages: f.stages.map((s, i) => i === idx ? { ...s, source_type: src } : s) }));

  return (
    <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="g-modal" style={{ maxWidth: 560 }}>
        <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>New Correlation Rule</h2>
          <button onClick={onClose} style={{ color: 'var(--text-2)', fontSize: 18, lineHeight: 1 }} title="Close">×</button>
        </div>
        <div className="p-5 space-y-4 max-h-[70vh] overflow-y-auto">
          {error && <p className="text-xs" style={{ color: 'var(--red)' }}>{error}</p>}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Rule Name *</label>
              <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                placeholder="e.g. T1078 Lateral Movement" className="g-input w-full" />
            </div>
            <div>
              <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Action *</label>
              <select value={form.action} onChange={e => setForm(f => ({ ...f, action: e.target.value }))} className="g-select w-full">
                {ACTIONS.map(a => <option key={a} value={a}>{a}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Description</label>
            <input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              placeholder="What does this rule detect?" className="g-input w-full" />
          </div>
          <div>
            <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Correlation Type *</label>
            <select value={form.correlation_type} onChange={e => setForm(f => ({ ...f, correlation_type: e.target.value }))} className="g-select w-full">
              {CORRELATION_TYPES.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
            </select>
          </div>
          {form.correlation_type === 'event_count' && (
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Window (minutes)</label>
                <input type="number" min={1} value={form.window_minutes}
                  onChange={e => setForm(f => ({ ...f, window_minutes: parseInt(e.target.value) || 1 }))} className="g-input w-full" />
              </div>
              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Threshold (min 2)</label>
                <input type="number" min={2} value={form.threshold}
                  onChange={e => setForm(f => ({ ...f, threshold: parseInt(e.target.value) || 2 }))} className="g-input w-full" />
              </div>
            </div>
          )}
          {isTemporal && (
            <div>
              <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Window (minutes)</label>
              <input type="number" min={1} value={form.window_minutes}
                onChange={e => setForm(f => ({ ...f, window_minutes: parseInt(e.target.value) || 1 }))}
                className="g-input w-full mb-3" style={{ maxWidth: 140 }} />
              <div className="flex items-center justify-between mb-2">
                <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
                  Stages ({form.correlation_type === 'temporal_ordered' ? 'in order' : 'any order'})
                </label>
                <button onClick={addStage} className="g-btn g-btn-ghost text-[10px]" style={{ padding: '3px 8px' }}>
                  <Plus className="h-3 w-3" /> Add Stage
                </button>
              </div>
              <div className="space-y-2">
                {form.stages.map((s, idx) => (
                  <div key={idx} className="flex gap-2 items-center">
                    <span className="text-[10px] w-5 shrink-0 font-mono" style={{ color: 'var(--text-3)' }}>{idx + 1}.</span>
                    <select value={s.source_type} onChange={e => updateStageSource(idx, e.target.value)}
                      className="g-select shrink-0 text-[10px]" style={{ width: 92 }}>
                      {SOURCE_TYPES.map(t => <option key={t.id} value={t.id}>{t.label.split(' ')[0]}</option>)}
                    </select>
                    <input value={s.pattern} onChange={e => updateStage(idx, e.target.value)}
                      placeholder={s.source_type === 'alert' ? 'e.g. Port Recon Scan' : CONDITION_PLACEHOLDER[s.source_type]}
                      className="g-input flex-1" />
                    {form.stages.length > 2 && (
                      <button onClick={() => removeStage(idx)} style={{ color: 'var(--text-3)' }}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
          {!isTemporal && form.correlation_type !== 'event_count' && (
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Severity</label>
                <select value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))} className="g-select w-full">
                  <option value="">Any</option>
                  {SEVERITIES.filter(Boolean).map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>MITRE Technique</label>
                <input value={form.mitre_technique} onChange={e => setForm(f => ({ ...f, mitre_technique: e.target.value }))}
                  placeholder="e.g. T1078" className="g-input w-full" />
              </div>
              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Rule Name Contains</label>
                <input value={form.rule_name} onChange={e => setForm(f => ({ ...f, rule_name: e.target.value }))}
                  placeholder="e.g. Brute Force" className="g-input w-full" />
              </div>
              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Also Run Playbook</label>
                <select value={form.playbook_id} onChange={e => setForm(f => ({ ...f, playbook_id: parseInt(e.target.value) || 0 }))} className="g-select w-full">
                  <option value={0}>None</option>
                  {playbooks.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                </select>
              </div>
            </div>
          )}
        </div>
        <div className="flex gap-3 px-5 pb-5">
          <button onClick={onClose} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
          <button onClick={create} disabled={saving || !form.name} className="g-btn g-btn-primary flex-1 justify-center">
            {saving ? 'Creating…' : 'Create Rule'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function CorrelationPage() {
  const [tab, setTab] = useState<ViewTab>('overview');
  const [hours, setHours] = useState(24);
  const loaded = useRef<Partial<Record<ViewTab, boolean>>>({});

  const [overview,    setOverview]    = useState<Overview | null>(null);
  const [trends,      setTrends]      = useState<TrendBucket[]>([]);
  const [analytics,   setAnalytics]   = useState<RuleAnalytic[]>([]);
  const [graphData,   setGraphData]   = useState<{ nodes: GraphNode[]; edges: GraphEdge[] }>({ nodes: [], edges: [] });
  const [grouping,    setGrouping]    = useState<AlertGrouping | null>(null);
  const [performance, setPerformance] = useState<Performance | null>(null);
  const [rules,       setRules]       = useState<Rule[]>([]);
  const [loadingTab,  setLoadingTab]  = useState(false);
  const [showCreate,  setShowCreate]  = useState(false);
  const [expandedId,  setExpandedId]  = useState<number | null>(null);
  const [matches,     setMatches]     = useState<CorrelationMatch[]>([]);
  const [matchesLoading, setMatchesLoading] = useState(false);
  const [playbooks,   setPlaybooks]   = useState<{ id: number; name: string }[]>([]);
  const [toast, setToast] = useState<string | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const loadTab = useCallback(async (t: ViewTab, force = false) => {
    if (loaded.current[t] && !force) return;
    loaded.current[t] = true;
    setLoadingTab(true);
    try {
      switch (t) {
        case 'overview': {
          const [ovRes, trRes] = await Promise.all([
            correlationAPI.getOverview(hours),
            correlationAPI.getTrends(hours),
          ]);
          if (ovRes.data) setOverview(ovRes.data as Overview);
          if (trRes.data) setTrends((trRes.data as { buckets: TrendBucket[] }).buckets || []);
          break;
        }
        case 'rules': {
          const r = await correlationAPI.getAll();
          setRules(r.data || []);
          break;
        }
        case 'analytics': {
          const r = await correlationAPI.getAnalytics();
          if (r.data) setAnalytics((r.data as { rules: RuleAnalytic[] }).rules || []);
          break;
        }
        case 'graph': {
          const r = await correlationAPI.getGraph(hours);
          if (r.data) setGraphData(r.data as { nodes: GraphNode[]; edges: GraphEdge[] });
          break;
        }
        case 'grouping': {
          const r = await correlationAPI.getAlertGrouping(hours);
          if (r.data) setGrouping(r.data as AlertGrouping);
          break;
        }
        case 'performance': {
          const r = await correlationAPI.getPerformance();
          if (r.data) setPerformance(r.data as Performance);
          break;
        }
        case 'chain':
        case 'builder': {
          if (!rules.length) {
            const r = await correlationAPI.getAll();
            setRules(r.data || []);
          }
          break;
        }
        default:
          break;
      }
    } finally {
      setLoadingTab(false);
    }
  }, [hours, rules.length]);

  useEffect(() => {
    loaded.current = {};
    loadTab(tab);
  }, [tab, hours]);

  useEffect(() => {
    playbooksAPI.getAll().then(r => setPlaybooks(r.data || [])).catch(() => {});
  }, []);

  const reloadRules = async () => {
    const r = await correlationAPI.getAll();
    setRules(r.data || []);
    loaded.current['analytics'] = false;
    loaded.current['overview'] = false;
  };

  const toggleRule = async (id: number, enabled: boolean) => {
    await correlationAPI.toggle(id, !enabled);
    setRules(rs => rs.map(r => r.id === id ? { ...r, enabled: !enabled } : r));
    notify(enabled ? 'Rule disabled' : 'Rule enabled');
  };

  const deleteRule = async (id: number) => {
    await correlationAPI.delete(id);
    setRules(rs => rs.filter(r => r.id !== id));
    notify('Rule deleted');
  };

  const toggleMatches = async (ruleId: number) => {
    if (expandedId === ruleId) { setExpandedId(null); return; }
    setExpandedId(ruleId);
    setMatchesLoading(true);
    try {
      const r = await correlationAPI.getMatches(ruleId);
      setMatches(r.data || []);
    } finally {
      setMatchesLoading(false);
    }
  };

  const maxMatchCount = useMemo(() => Math.max(...analytics.map(r => r.match_count), 1), [analytics]);
  const maxAlertCount = useMemo(() => Math.max(...(grouping?.by_host.map(h => h.alert_count) ?? []), 1), [grouping]);

  return (
    <RootLayout
      title="Correlation Engine"
      subtitle="Multi-stage attack detection · Temporal correlation · Alert grouping"
      actions={
        <div className="flex items-center gap-2">
          <select value={hours} onChange={e => { setHours(Number(e.target.value)); loaded.current = {}; }}
            className="g-select text-xs py-1">
            {[6, 12, 24, 48, 168].map(h => <option key={h} value={h}>{h < 24 ? `${h}h` : h === 168 ? '7d' : '24h'}</option>)}
          </select>
          <button onClick={() => { loaded.current = {}; loadTab(tab, true); }} className="g-btn g-btn-ghost text-xs" title="Refresh">
            <span className={loadingTab ? 'animate-spin' : ''} style={{ display: 'inline-block' }}>↻</span>
          </button>
          <button onClick={() => setShowCreate(true)} className="g-btn g-btn-primary text-xs">
            <Plus className="h-3.5 w-3.5" /> New Rule
          </button>
        </div>
      }>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 g-card px-4 py-2.5 text-sm shadow-lg"
          style={{ color: 'var(--text-1)' }}>{toast}</div>
      )}

      {showCreate && <CreateRuleModal onClose={() => setShowCreate(false)} onCreated={reloadRules} />}

      {/* Tab bar */}
      <div className="flex gap-0.5 mb-4 overflow-x-auto pb-1">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors ${
              tab === t.id ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'
            }`}>
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
                <KPICard label="Active Rules"       value={overview.active_rules}         color="var(--accent)"   icon={Shield} />
                <KPICard label="Matches (24h)"      value={overview.matches_24h}           color="#fbbf24"         icon={Activity} />
                <KPICard label="Incidents Created"  value={overview.incidents_created_24h} color="var(--red)"      icon={AlertTriangle} />
                <KPICard label="Avg Confidence"     value={`${overview.avg_confidence}%`}  color="var(--green)"    icon={Target} />
                <KPICard label="Total Rules"        value={overview.total_rules}           color="var(--text-2)"   icon={GitMerge} />
                <KPICard label="Suppression Rules"  value={overview.suppression_rules}     color="var(--text-3)"   icon={Lock} />
                <KPICard label="FP Rate (proxy)"    value={`${overview.fp_rate}%`}         color="#fb923c"         icon={Activity} />
                <KPICard label="High Conf Matches"  value={overview.high_conf_matches}     color="var(--accent)"   icon={CheckCircle2} />
              </div>

              {/* Trend */}
              <div className="g-card p-4">
                <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>
                  Match Trend
                  <span className="ml-2 text-[10px] font-normal" style={{ color: 'var(--text-3)' }}>Blue = matches · Red = incidents</span>
                </p>
                <TrendChart buckets={trends} />
                <div className="flex justify-between mt-1 text-[10px]" style={{ color: 'var(--text-3)' }}>
                  <span>{trends[0] ? new Date(trends[0].hour).toLocaleString([], { month:'short', day:'numeric', hour:'2-digit' }) : ''}</span>
                  <span>Total: {trends.reduce((a, b) => a + b.matches, 0)} matches</span>
                </div>
              </div>

              {/* Rule breakdown + top rules */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Rules by Type</p>
                  <div className="space-y-3">
                    {overview.rule_breakdown.map(rb => (
                      <div key={rb.type} className="flex items-center gap-3">
                        <span className="text-xs font-medium w-32 shrink-0 capitalize" style={{ color: 'var(--text-2)' }}>
                          {rb.type.replace(/_/g, ' ')}
                        </span>
                        <MiniBar value={rb.enabled} max={rb.count} color="var(--accent)" />
                        <span className="text-[11px] tabular-nums w-20 shrink-0" style={{ color: 'var(--text-3)' }}>
                          {rb.enabled}/{rb.count}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Top Rules (all time)</p>
                  <div className="space-y-2">
                    {overview.top_rules.map(r => (
                      <div key={r.id} className="flex items-center gap-2">
                        <span className="text-xs truncate flex-1" style={{ color: 'var(--text-2)' }}>{r.name}</span>
                        {sevBadge(r.severity)}
                        <span className="text-[11px] font-bold tabular-nums" style={{ color: '#fbbf24' }}>{r.match_count}</span>
                      </div>
                    ))}
                    {overview.top_rules.length === 0 && (
                      <p className="text-xs" style={{ color: 'var(--text-3)' }}>No matches yet</p>
                    )}
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          )}
        </div>
      )}

      {/* ── Rules ── */}
      {tab === 'rules' && (
        <RulesTab rules={rules} playbooks={playbooks}
          onToggle={toggleRule} onDelete={deleteRule}
          onToggleMatches={toggleMatches}
          expandedId={expandedId} matches={matches} matchesLoading={matchesLoading} />
      )}

      {/* ── Builder ── */}
      {tab === 'builder' && (
        <VisualBuilderPanel onCreateRule={async (form) => {
          try {
            await correlationAPI.create(form);
            notify('Rule created from builder');
            await reloadRules();
          } catch {
            notify('Failed to create rule');
          }
        }} />
      )}

      {/* ── Attack Chain ── */}
      {tab === 'chain' && <AttackChainView rules={rules} />}

      {/* ── Graph ── */}
      {tab === 'graph' && (
        <div className="space-y-4">
          <p className="text-xs" style={{ color: 'var(--text-3)' }}>
            Relationship graph of agents, correlation rules, and incidents from the last {hours}h.
          </p>
          <CorrelationGraphView nodes={graphData.nodes} edges={graphData.edges} />
        </div>
      )}

      {/* ── Analytics ── */}
      {tab === 'analytics' && (
        <div className="space-y-4">
          {analytics.length > 0 ? (
            <div className="g-card overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
                    {['Rule','Type','Severity','MITRE','Total Matches','24h Matches','Incidents 24h','Last Triggered','Status'].map(h => (
                      <th key={h} className="px-3 py-2.5 text-left font-semibold" style={{ color: 'var(--text-3)' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {analytics.map(r => (
                    <tr key={r.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td className="px-3 py-3 max-w-[180px]">
                        <p className="font-medium truncate" style={{ color: 'var(--text-1)' }}>{r.name}</p>
                      </td>
                      <td className="px-3 py-3">
                        <span className="text-[10px] px-1.5 py-0.5 rounded capitalize"
                          style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)', border: '1px solid var(--border)' }}>
                          {r.correlation_type.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="px-3 py-3">{sevBadge(r.severity)}</td>
                      <td className="px-3 py-3">
                        <span className="font-mono text-[11px]" style={{ color: '#fbbf24' }}>{r.mitre_technique || '—'}</span>
                      </td>
                      <td className="px-3 py-3">
                        <div className="flex items-center gap-2">
                          <MiniBar value={r.match_count} max={maxMatchCount} color="var(--accent)" />
                          <span className="font-bold tabular-nums" style={{ color: r.match_count > 0 ? '#fbbf24' : 'var(--text-3)' }}>{r.match_count}</span>
                        </div>
                      </td>
                      <td className="px-3 py-3">
                        <span style={{ color: r.matches_24h > 0 ? '#fbbf24' : 'var(--text-3)' }}>{r.matches_24h}</span>
                      </td>
                      <td className="px-3 py-3">
                        <span style={{ color: r.incidents_24h > 0 ? 'var(--red)' : 'var(--text-3)' }}>{r.incidents_24h}</span>
                      </td>
                      <td className="px-3 py-3 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>
                        {r.last_triggered ? timeAgo(r.last_triggered) : '—'}
                      </td>
                      <td className="px-3 py-3">
                        <div className="flex items-center gap-1.5">
                          <StatusDot ok={r.enabled} />
                          <span style={{ color: r.enabled ? 'var(--green)' : 'var(--text-3)' }}>{r.enabled ? 'On' : 'Off'}</span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading analytics…</div>
          )}
        </div>
      )}

      {/* ── Alert Grouping ── */}
      {tab === 'grouping' && (
        <div className="space-y-4">
          {grouping ? (
            <>
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                {/* By host */}
                <div className="g-card p-4 lg:col-span-2">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Alerts by Host (24h)</p>
                  <div className="space-y-2">
                    {grouping.by_host.slice(0, 10).map(h => (
                      <div key={h.host} className="flex items-center gap-3">
                        <span className="text-xs truncate w-36 shrink-0 font-mono" style={{ color: 'var(--text-2)' }}>{h.host}</span>
                        <MiniBar value={h.alert_count} max={maxAlertCount} color={SEV_COLOR[h.max_severity] ?? 'var(--accent)'} />
                        <span className="text-[11px] tabular-nums w-8 text-right shrink-0 font-bold"
                          style={{ color: SEV_COLOR[h.max_severity] ?? 'var(--text-2)' }}>
                          {h.alert_count}
                        </span>
                      </div>
                    ))}
                    {grouping.by_host.length === 0 && (
                      <p className="text-xs" style={{ color: 'var(--text-3)' }}>No alerts in this period</p>
                    )}
                  </div>
                </div>

                {/* By severity */}
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>By Severity</p>
                  <div className="space-y-2">
                    {grouping.by_severity.map(s => {
                      const max = Math.max(...grouping.by_severity.map(x => x.count), 1);
                      return (
                        <div key={s.severity} className="flex items-center gap-2">
                          <span className="w-16 shrink-0">{sevBadge(s.severity)}</span>
                          <MiniBar value={s.count} max={max} color={SEV_COLOR[s.severity] ?? 'var(--text-3)'} />
                          <span className="text-[11px] tabular-nums w-8 text-right shrink-0" style={{ color: 'var(--text-3)' }}>{s.count}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>

              {/* By MITRE technique */}
              {grouping.by_mitre.length > 0 && (
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Alerts by MITRE Technique (24h)</p>
                  <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
                    {grouping.by_mitre.map(m => {
                      const max = grouping.by_mitre[0]?.count || 1;
                      const pct = (m.count / max) * 100;
                      return (
                        <div key={m.technique} className="p-3 rounded-lg"
                          style={{ background: `color-mix(in srgb, var(--accent) ${Math.max(5, pct * 0.15)}%, var(--glass-bg))`, border: '1px solid var(--border)' }}>
                          <p className="font-mono text-xs font-bold" style={{ color: 'var(--accent)' }}>{m.technique}</p>
                          <p className="text-xl font-bold" style={{ color: 'var(--text-1)' }}>{m.count}</p>
                          <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>alerts</p>
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

      {/* ── AI Analysis ── */}
      {tab === 'ai' && <AIAnalysisPanel />}

      {/* ── Simulation ── */}
      {tab === 'testing' && <SimulationPanel />}

      {/* ── Performance ── */}
      {tab === 'performance' && (
        <div className="space-y-4">
          {performance ? (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                  { label: 'Active Rules',     val: performance.active_rules,      color: 'var(--accent)' },
                  { label: 'Matches / Hour',   val: performance.matches_last_hour, color: '#fbbf24' },
                  { label: 'Incidents / Hour', val: performance.incidents_last_hour, color: 'var(--red)' },
                  { label: 'Avg Latency',      val: `${performance.avg_latency_ms}ms`, color: 'var(--green)' },
                  { label: 'Total Matches',    val: performance.total_matches_all, color: 'var(--text-2)' },
                  { label: 'Queue Depth',      val: performance.queue_depth,       color: 'var(--text-3)' },
                  { label: 'Uptime',           val: `${performance.uptime_pct}%`,  color: 'var(--green)' },
                  { label: 'Engine Count',     val: performance.engines.length,    color: 'var(--accent)' },
                ].map(s => (
                  <div key={s.label} className="g-card p-4">
                    <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>{s.label}</p>
                    <p className="text-xl font-bold" style={{ color: s.color }}>{s.val}</p>
                  </div>
                ))}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {performance.engines.map(e => (
                  <div key={e.name} className="g-card p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{e.name}</span>
                      <span className="text-[10px] px-2 py-0.5 rounded-full"
                        style={{ background: e.status === 'healthy' ? 'rgba(52,211,153,0.15)' : 'rgba(248,81,73,0.15)', color: e.status === 'healthy' ? 'var(--green)' : 'var(--red)' }}>
                        {e.status}
                      </span>
                    </div>
                    <div className="space-y-1 text-[11px]">
                      <div className="flex justify-between">
                        <span style={{ color: 'var(--text-3)' }}>Avg Latency</span>
                        <span className="font-medium" style={{ color: e.avg_ms < 10 ? 'var(--green)' : e.avg_ms < 50 ? '#fbbf24' : 'var(--red)' }}>
                          {e.avg_ms}ms
                        </span>
                      </div>
                      {e.rules !== undefined && (
                        <div className="flex justify-between">
                          <span style={{ color: 'var(--text-3)' }}>Rules</span>
                          <span className="font-medium" style={{ color: 'var(--text-2)' }}>{e.rules}</span>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          )}
        </div>
      )}
    </RootLayout>
  );
}
