'use client';

import { useEffect, useState, useCallback, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { sigmaAPI } from '@/lib/api';
import { SigmaRule, SigmaRuleStat } from '@/types';
import { sevClass, timeAgo } from '@/lib/utils';
import { AlertTriangle, BarChart, BarChart2, Bot, CheckSquare, ChevronRight, Copy, Download, Edit2, Eye, FileCode, Grid, Layers, Plus, Repeat2, Search, Shield, TestTube, ToggleLeft, ToggleRight, Trash2, Upload, X, Zap } from '@/lib/icon-stubs';

// ── Types ─────────────────────────────────────────────────────────────────

interface DashData {
  total: number; enabled: number; disabled: number;
  severity: { critical: number; high: number; medium: number; low: number; info: number };
  status: { experimental: number; stable: number; testing: number };
  triggered_24h: number; triggered_7d: number; total_hits_24h: number;
  mitre_tactics: number; mitre_techniques: number;
  top_rules: { id: number; title: string; severity: string; hits_7d: number; hits_24h: number }[];
  trend: { date: string; count: number }[];
  categories: { category: string; total: number; enabled: number }[];
}

interface TacticGroup {
  tactic: string;
  techniques: { technique: string; name: string; rules: number; enabled: number }[];
  total_rules: number;
}

interface RuleAnalytic {
  id: number; title: string; severity: string; mitre_tactic: string;
  enabled: boolean; hit_count: number; hits_24h: number; hits_7d: number;
  last_hit: string | null;
}

interface CatDetail { platform: string; category: string; total: number; enabled: number; hits_7d: number; }
interface RelNode { id: string; label: string; type: string; value: number; }
interface RelEdge { source: string; target: string; weight: number; }

// ── Constants ─────────────────────────────────────────────────────────────

const TABS = [
  { id: 'dashboard',  label: 'Dashboard',   icon: Grid },
  { id: 'library',    label: 'Library',      icon: Layers },
  { id: 'editor',     label: 'Rule Editor',  icon: FileCode },
  { id: 'testing',    label: 'Testing',      icon: TestTube },
  { id: 'mitre',      label: 'MITRE',        icon: Shield },
  { id: 'analytics',  label: 'Analytics',    icon: BarChart },
  { id: 'categories', label: 'Categories',   icon: BarChart2 },
  { id: 'ai',         label: 'AI Assistant', icon: Bot },
  { id: 'convert',    label: 'Convert',      icon: Repeat2 },
  { id: 'bulk',       label: 'Bulk Ops',     icon: CheckSquare },
  { id: 'import',     label: 'Import/Export',icon: Download },
];

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const STATUSES   = ['stable', 'test', 'experimental', 'deprecated'];
const PLATFORMS  = ['elasticsearch', 'splunk', 'kql', 'qradar', 'suricata', 'opensearch'];

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--blue)', info: 'var(--text-3)',
};

const MITRE_14 = [
  'reconnaissance','resource-development','initial-access','execution','persistence',
  'privilege-escalation','defense-evasion','credential-access','discovery',
  'lateral-movement','collection','command-and-control','exfiltration','impact',
];

// ── Form types ────────────────────────────────────────────────────────────

interface SelectionForm { name: string; keywords: string; }

const emptyForm = {
  title: '', description: '', status: 'experimental', severity: 'high',
  mitre_tactic: '', mitre_technique: '', mitre_name: '',
  logsource_cat: '', logsource_prod: '', logsource_svc: '', tags: '',
  selections: [{ name: 'selection1', keywords: '' }] as SelectionForm[],
  condition: 'selection1', enabled: true,
};

// ── Shared micro-components ───────────────────────────────────────────────

function KPICard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="g-card p-4 flex flex-col gap-1">
      <span className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>{label}</span>
      <span className="text-2xl font-bold font-mono" style={{ color: color ?? 'var(--text-1)' }}>{value}</span>
      {sub && <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{sub}</span>}
    </div>
  );
}

function MiniBar({ value, max, color = 'var(--accent)' }: { value: number; max: number; color?: string }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div className="h-1.5 rounded-full w-full" style={{ background: 'var(--bg-0)' }}>
      <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: color }} />
    </div>
  );
}

function SevBadge({ sev }: { sev: string }) {
  const color = SEV_COLOR[sev] ?? 'var(--text-3)';
  return (
    <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded"
      style={{ color, background: color + '22', border: `1px solid ${color}55` }}>{sev}</span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const color = status === 'stable' ? 'var(--green)' : status === 'test' ? 'var(--yellow)' : status === 'deprecated' ? 'var(--red)' : 'var(--text-3)';
  return <span className="text-[10px] font-mono" style={{ color }}>{status || 'exp'}</span>;
}

function SparkTrend({ trend }: { trend: { date: string; count: number }[] }) {
  if (!trend.length) return null;
  const max = Math.max(...trend.map(t => t.count), 1);
  const w = 120, h = 30;
  const pts = trend.map((t, i) => {
    const x = (i / Math.max(trend.length - 1, 1)) * w;
    const y = h - (t.count / max) * (h - 4) - 2;
    return `${x},${y}`;
  }).join(' ');
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`}>
      <polyline points={pts} fill="none" stroke="var(--accent)" strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

// ── Rule form ─────────────────────────────────────────────────────────────

function RuleForm({
  form, setForm, onSave, onCancel, saving, mode,
}: {
  form: typeof emptyForm;
  setForm: React.Dispatch<React.SetStateAction<typeof emptyForm>>;
  onSave: () => void;
  onCancel: () => void;
  saving: boolean;
  mode: 'create' | 'edit';
}) {
  const addSel = () => setForm(f => ({ ...f, selections: [...f.selections, { name: `selection${f.selections.length + 1}`, keywords: '' }] }));
  const remSel = (i: number) => setForm(f => ({ ...f, selections: f.selections.filter((_, j) => j !== i) }));
  const updSel = (i: number, k: 'name' | 'keywords', v: string) =>
    setForm(f => ({ ...f, selections: f.selections.map((s, j) => j === i ? { ...s, [k]: v } : s) }));

  const yamlPreview = useMemo(() => {
    const sels = form.selections.map(s => `    ${s.name}:\n      keywords:\n${s.keywords.split(',').map(k => `        - ${k.trim()}`).join('\n')}`).join('\n');
    return `title: ${form.title || 'Untitled'}
status: ${form.status}
level: ${form.severity}
description: ${form.description || '(none)'}
logsource:
  product: ${form.logsource_prod || '(any)'}
  category: ${form.logsource_cat || '(any)'}
  service: ${form.logsource_svc || '(any)'}
tags:
  - attack.${form.mitre_tactic || 'unknown'}
  - attack.${form.mitre_technique || 'unknown'}
detection:
${sels}
  condition: ${form.condition}`;
  }, [form]);

  return (
    <div className="grid grid-cols-2 gap-5 h-full">
      {/* Left: form fields */}
      <div className="space-y-3 overflow-y-auto pr-2" style={{ maxHeight: 'calc(100vh - 200px)' }}>
        <div className="grid grid-cols-2 gap-3">
          <div className="col-span-2">
            <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Title *</label>
            <input value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
              placeholder="SSH Brute Force Detection" className="g-input" />
          </div>
          <div className="col-span-2">
            <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Description</label>
            <input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              placeholder="Detects repeated SSH login failures from single source…" className="g-input" />
          </div>
          <div>
            <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Status</label>
            <select value={form.status} onChange={e => setForm(f => ({ ...f, status: e.target.value }))} className="g-select">
              {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Severity</label>
            <select value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))} className="g-select">
              {SEVERITIES.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
            </select>
          </div>
        </div>

        <div className="pt-2" style={{ borderTop: '1px solid var(--border)' }}>
          <label className="block text-[10px] uppercase tracking-wider font-semibold mb-2" style={{ color: 'var(--text-3)' }}>Logsource</label>
          <div className="grid grid-cols-3 gap-2">
            {(['logsource_prod', 'logsource_cat', 'logsource_svc'] as const).map((k, i) => (
              <div key={k}>
                <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>{['Product', 'Category', 'Service'][i]}</label>
                <input value={form[k]} onChange={e => setForm(f => ({ ...f, [k]: e.target.value }))}
                  placeholder={['windows', 'process_creation', 'sshd'][i]} className="g-input mono text-xs" />
              </div>
            ))}
          </div>
        </div>

        <div className="pt-2" style={{ borderTop: '1px solid var(--border)' }}>
          <label className="block text-[10px] uppercase tracking-wider font-semibold mb-2" style={{ color: 'var(--text-3)' }}>MITRE ATT&CK</label>
          <div className="grid grid-cols-3 gap-2">
            <div>
              <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Tactic</label>
              <input value={form.mitre_tactic} onChange={e => setForm(f => ({ ...f, mitre_tactic: e.target.value }))}
                placeholder="Execution" className="g-input" />
            </div>
            <div>
              <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Technique</label>
              <input value={form.mitre_technique} onChange={e => setForm(f => ({ ...f, mitre_technique: e.target.value }))}
                placeholder="T1059" className="g-input mono" />
            </div>
            <div>
              <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Name</label>
              <input value={form.mitre_name} onChange={e => setForm(f => ({ ...f, mitre_name: e.target.value }))}
                placeholder="Command and Scripting" className="g-input" />
            </div>
          </div>
        </div>

        <div>
          <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Tags (comma-separated)</label>
          <input value={form.tags} onChange={e => setForm(f => ({ ...f, tags: e.target.value }))}
            placeholder="attack.t1059.001, attack.execution" className="g-input mono text-xs" />
        </div>

        <div className="pt-2" style={{ borderTop: '1px solid var(--border)' }}>
          <div className="flex items-center justify-between mb-2">
            <label className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-3)' }}>Detection Selections</label>
            <button onClick={addSel} className="g-btn g-btn-ghost text-[10px]" style={{ padding: '2px 8px' }}>
              <Plus className="h-3 w-3" /> Add
            </button>
          </div>
          <div className="space-y-2">
            {form.selections.map((sel, i) => (
              <div key={i} className="flex gap-2 items-center">
                <input value={sel.name} onChange={e => updSel(i, 'name', e.target.value)}
                  placeholder="selection1" className="g-input mono text-xs" style={{ width: 110, flexShrink: 0 }} />
                <input value={sel.keywords} onChange={e => updSel(i, 'keywords', e.target.value)}
                  placeholder="CommandLine|contains:powershell" className="g-input flex-1 mono text-xs" />
                {form.selections.length > 1 && (
                  <button onClick={() => remSel(i)} className="p-1.5 rounded" style={{ color: 'var(--text-3)' }}><Trash2 className="h-3.5 w-3.5" /></button>
                )}
              </div>
            ))}
          </div>
          <p className="text-[10px] mt-1.5" style={{ color: 'var(--text-3)' }}>
            Modifiers: <span className="mono">contains · startswith · endswith · re · cidr · base64 · windash</span>
          </p>
        </div>

        <div>
          <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Condition</label>
          <input value={form.condition} onChange={e => setForm(f => ({ ...f, condition: e.target.value }))}
            placeholder="selection1 and not filter" className="g-input mono" />
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
            Ops: <span className="mono">and · or · not · ( )</span> · <span className="mono">1 of selection*</span> · <span className="mono">all of them</span>
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button onClick={() => setForm(f => ({ ...f, enabled: !f.enabled }))}>
            {form.enabled
              ? <ToggleRight className="h-5 w-5" style={{ color: 'var(--green)' }} />
              : <ToggleLeft className="h-5 w-5" style={{ color: 'var(--text-3)' }} />}
          </button>
          <span className="text-xs" style={{ color: 'var(--text-2)' }}>{form.enabled ? 'Enabled' : 'Disabled'}</span>
        </div>

        <div className="flex gap-3 pt-2">
          <button onClick={onCancel} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
          <button onClick={onSave} disabled={saving || !form.title.trim()} className="g-btn g-btn-primary flex-1 justify-center">
            {saving ? 'Saving…' : mode === 'create' ? 'Create Rule' : 'Update Rule'}
          </button>
        </div>
      </div>

      {/* Right: YAML preview */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <span className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-3)' }}>YAML Preview</span>
          <button onClick={() => navigator.clipboard.writeText(yamlPreview).catch(() => {})}
            className="g-btn g-btn-ghost text-[10px]" style={{ padding: '2px 8px' }}>
            <Copy className="h-3 w-3" /> Copy
          </button>
        </div>
        <pre className="flex-1 p-3 text-[11px] font-mono rounded-xl overflow-auto"
          style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-2)', minHeight: 300, maxHeight: 'calc(100vh - 300px)' }}>
          {yamlPreview}
        </pre>
      </div>
    </div>
  );
}

// ── Relationship Graph ─────────────────────────────────────────────────────

function RelGraph({ nodes, edges }: { nodes: RelNode[]; edges: RelEdge[] }) {
  const COL_TYPES = ['rule', 'agent', 'mitre'];
  const cols: Record<string, RelNode[]> = { rule: [], agent: [], mitre: [] };
  nodes.forEach(n => { if (cols[n.type]) cols[n.type].push(n); });

  const W = 700, H = 400, COL_X = [80, 300, 560];
  const nodePos: Record<string, { x: number; y: number }> = {};
  COL_TYPES.forEach((t, ci) => {
    cols[t].forEach((n, i) => {
      const gap = H / (cols[t].length + 1);
      nodePos[n.id] = { x: COL_X[ci], y: gap * (i + 1) };
    });
  });

  const maxW = Math.max(...edges.map(e => e.weight), 1);

  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ maxHeight: 400 }}>
      {edges.map((e, i) => {
        const s = nodePos[e.source], t = nodePos[e.target];
        if (!s || !t) return null;
        const opacity = 0.15 + (e.weight / maxW) * 0.6;
        return (
          <line key={i} x1={s.x} y1={s.y} x2={t.x} y2={t.y}
            stroke="var(--accent)" strokeWidth={1 + (e.weight / maxW) * 2} strokeOpacity={opacity} />
        );
      })}
      {nodes.map(n => {
        const pos = nodePos[n.id];
        if (!pos) return null;
        const color = n.type === 'rule' ? 'var(--accent)' : n.type === 'agent' ? 'var(--blue)' : 'var(--orange)';
        const r = 5 + Math.min(n.value / 10, 10);
        return (
          <g key={n.id}>
            <circle cx={pos.x} cy={pos.y} r={r} fill={color} fillOpacity={0.3} stroke={color} strokeWidth={1.5} />
            <text x={pos.x} y={pos.y - r - 3} textAnchor="middle" fill="var(--text-2)"
              fontSize={9} className="font-mono">{n.label.slice(0, 18)}</text>
          </g>
        );
      })}
      {COL_TYPES.map((t, i) => (
        <text key={t} x={COL_X[i]} y={16} textAnchor="middle" fill="var(--text-3)" fontSize={10} fontWeight="600">
          {t.toUpperCase()}
        </text>
      ))}
    </svg>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────

export default function SigmaRulesPage() {
  const [tab, setTab]         = useState('dashboard');
  const [rules, setRules]     = useState<SigmaRule[]>([]);
  const [stats, setStats]     = useState<SigmaRuleStat[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Library state
  const [search,    setSearch]    = useState('');
  const [sevFilter, setSevFilter] = useState('');
  const [selected,  setSelected]  = useState<Set<number>>(new Set());

  // Editor state
  const [editMode, setEditMode] = useState<'create' | 'edit'>('create');
  const [editTarget, setEditTarget] = useState<SigmaRule | null>(null);
  const [form, setForm] = useState({ ...emptyForm, selections: [...emptyForm.selections] });
  const [saving, setSaving] = useState(false);

  // Modal for quick edit from library
  const [modalEdit, setModalEdit] = useState<SigmaRule | null>(null);
  const [modalForm, setModalForm] = useState({ ...emptyForm, selections: [...emptyForm.selections] });
  const [modalSaving, setModalSaving] = useState(false);

  // Test state
  const [testMsg,  setTestMsg]  = useState('');
  const [testRes,  setTestRes]  = useState<any>(null);
  const [testing,  setTesting]  = useState(false);

  // Import state
  const [importing,  setImporting]  = useState(false);
  const [importLog,  setImportLog]  = useState<string | null>(null);

  // Enterprise data
  const [dash,        setDash]        = useState<DashData | null>(null);
  const [mitreCov,    setMitreCov]    = useState<{ coverage: TacticGroup[]; uncovered: number } | null>(null);
  const [analytics,   setAnalytics]   = useState<{ rules: RuleAnalytic[]; daily: any[]; sev_hits: any[] } | null>(null);
  const [categories,  setCategories]  = useState<CatDetail[] | null>(null);
  const [performance, setPerformance] = useState<any>(null);
  const [relData,     setRelData]     = useState<{ nodes: RelNode[]; edges: RelEdge[] } | null>(null);

  // AI state
  const [aiAction,  setAiAction]  = useState('generate');
  const [aiPrompt,  setAiPrompt]  = useState('');
  const [aiTarget,  setAiTarget]  = useState('elasticsearch');
  const [aiRuleID,  setAiRuleID]  = useState<number | null>(null);
  const [aiResult,  setAiResult]  = useState<any>(null);
  const [aiLoading, setAiLoading] = useState(false);

  // Convert state
  const [convRuleID,  setConvRuleID]  = useState<number | null>(null);
  const [convTarget,  setConvTarget]  = useState('elasticsearch');
  const [convResult,  setConvResult]  = useState<any>(null);
  const [convLoading, setConvLoading] = useState(false);

  // Bulk state
  const [bulkAction, setBulkAction] = useState('enable');
  const [bulkValue,  setBulkValue]  = useState('');
  const [bulkLoading, setBulkLoading] = useState(false);

  const [toast, setToast] = useState<string | null>(null);
  const loaded = useRef<Record<string, boolean>>({});

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3500); };

  // ── Data loading ────────────────────────────────────────────────────────

  const loadBase = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const [rRes, sRes] = await Promise.all([sigmaAPI.getAll(), sigmaAPI.stats().catch(() => ({ data: [] }))]);
      setRules(rRes.data || []);
      setStats(sRes.data || []);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { loadBase(); }, [loadBase]);

  useEffect(() => {
    if (loaded.current[tab]) return;
    loaded.current[tab] = true;

    if (tab === 'dashboard')  sigmaAPI.dashboard().then(r => setDash(r.data));
    if (tab === 'mitre')      sigmaAPI.mitreCoverage().then(r => setMitreCov(r.data));
    if (tab === 'analytics')  sigmaAPI.analytics().then(r => setAnalytics(r.data));
    if (tab === 'categories') sigmaAPI.categories().then(r => setCategories(r.data?.categories ?? null));
    if (tab === 'relationships') sigmaAPI.relationships().then(r => setRelData(r.data));
  }, [tab]);

  // ── Derived data ────────────────────────────────────────────────────────

  const hitMap = useMemo(
    () => Object.fromEntries(stats.map(s => [s.rule_id, s])),
    [stats]
  );

  const filtered = useMemo(() => rules.filter(r => {
    if (sevFilter && r.severity !== sevFilter) return false;
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      r.title?.toLowerCase().includes(q) ||
      r.description?.toLowerCase().includes(q) ||
      r.mitre_technique?.toLowerCase().includes(q) ||
      r.mitre_tactic?.toLowerCase().includes(q) ||
      (r.tags || []).some(t => t.toLowerCase().includes(q)) ||
      r.logsource_prod?.toLowerCase().includes(q) ||
      (r.keywords || []).some(k => k.toLowerCase().includes(q))
    );
  }), [rules, search, sevFilter]);

  // ── Payload builder ─────────────────────────────────────────────────────

  const buildPayload = (f: typeof emptyForm) => {
    const selections: Record<string, string[]> = {};
    f.selections.forEach(s => {
      const name = s.name.trim();
      if (!name) return;
      selections[name] = s.keywords.split(',').map(k => k.trim()).filter(Boolean);
    });
    return {
      title: f.title, description: f.description, status: f.status, severity: f.severity,
      mitre_tactic: f.mitre_tactic, mitre_technique: f.mitre_technique, mitre_name: f.mitre_name,
      logsource_cat: f.logsource_cat, logsource_prod: f.logsource_prod, logsource_svc: f.logsource_svc,
      tags: f.tags.split(',').map(t => t.trim()).filter(Boolean),
      keywords: Object.values(selections).flat(),
      selections,
      condition: f.condition.trim() || Object.keys(selections).join(' or '),
      enabled: f.enabled,
    };
  };

  const ruleToForm = (r: SigmaRule): typeof emptyForm => {
    const selections = r.selections && Object.keys(r.selections).length > 0
      ? Object.entries(r.selections).map(([name, kws]) => ({ name, keywords: (kws || []).join(', ') }))
      : [{ name: 'selection1', keywords: (r.keywords || []).join(', ') }];
    return {
      title: r.title, description: r.description || '', status: r.status || 'experimental',
      severity: r.severity, mitre_tactic: r.mitre_tactic || '', mitre_technique: r.mitre_technique || '',
      mitre_name: r.mitre_name || '', logsource_cat: r.logsource_cat || '',
      logsource_prod: r.logsource_prod || '', logsource_svc: r.logsource_svc || '',
      tags: (r.tags || []).join(', '), selections, condition: r.condition || selections.map(s => s.name).join(' or '),
      enabled: r.enabled,
    };
  };

  const resetForm = () => setForm({ ...emptyForm, selections: [{ name: 'selection1', keywords: '' }] });

  // ── CRUD ────────────────────────────────────────────────────────────────

  const saveRule = async () => {
    setSaving(true);
    try {
      if (editMode === 'create') {
        await sigmaAPI.create(buildPayload(form));
        notify('Rule created');
        resetForm();
      } else {
        await sigmaAPI.update(editTarget!.id, buildPayload(form));
        notify('Rule updated');
        setEditMode('create');
        setEditTarget(null);
      }
      loaded.current = {};
      loadBase();
    } catch {
      notify('Save failed');
    } finally {
      setSaving(false);
    }
  };

  const saveModalEdit = async () => {
    if (!modalEdit) return;
    setModalSaving(true);
    try {
      await sigmaAPI.update(modalEdit.id, buildPayload(modalForm));
      notify('Rule updated');
      setModalEdit(null);
      loaded.current = {};
      loadBase();
    } catch { notify('Update failed'); }
    finally { setModalSaving(false); }
  };

  const delRule = async (id: number) => {
    await sigmaAPI.delete(id);
    setRules(p => p.filter(r => r.id !== id));
    setSelected(s => { const n = new Set(s); n.delete(id); return n; });
    notify('Rule deleted');
  };

  const duplicate = async (r: SigmaRule) => {
    try {
      await sigmaAPI.create({ ...buildPayload(ruleToForm(r)), title: `${r.title} (copy)`, enabled: false });
      loadBase(); notify('Duplicated (disabled)');
    } catch { notify('Duplication failed'); }
  };

  const toggleRule = async (r: SigmaRule) => {
    r.enabled ? await sigmaAPI.disable(r.id) : await sigmaAPI.enable(r.id);
    setRules(p => p.map(x => x.id === r.id ? { ...x, enabled: !x.enabled } : x));
  };

  // ── Import ───────────────────────────────────────────────────────────────

  const handleImport = async (files: FileList) => {
    if (!files.length) return;
    setImporting(true); setImportLog(null);
    const fd = new FormData();
    Array.from(files).forEach(f => fd.append('rules', f));
    try {
      const res = await sigmaAPI.import(fd);
      const { imported, skipped, errors: errs } = res.data;
      let msg = `Imported ${imported}`;
      if (skipped) msg += `, skipped ${skipped}`;
      if (errs?.length) msg += `\n${errs.slice(0, 5).join('\n')}`;
      setImportLog(msg);
      loaded.current = {};
      loadBase();
    } catch { setImportLog('Import failed'); }
    finally { setImporting(false); }
  };

  // ── Testing ──────────────────────────────────────────────────────────────

  const runTest = async () => {
    if (!testMsg.trim()) return;
    setTesting(true);
    try { const r = await sigmaAPI.test({ message: testMsg }); setTestRes(r.data); }
    finally { setTesting(false); }
  };

  // ── AI ───────────────────────────────────────────────────────────────────

  const runAI = async () => {
    setAiLoading(true); setAiResult(null);
    try {
      const res = await sigmaAPI.ai({
        action: aiAction,
        rule_id: aiRuleID ?? 0,
        prompt: aiPrompt,
        target: aiTarget,
      });
      setAiResult(res.data);
    } catch { notify('AI request failed'); }
    finally { setAiLoading(false); }
  };

  // ── Convert ──────────────────────────────────────────────────────────────

  const runConvert = async () => {
    if (!convRuleID) { notify('Select a rule first'); return; }
    setConvLoading(true); setConvResult(null);
    try {
      const res = await sigmaAPI.convert({ rule_id: convRuleID, target: convTarget });
      setConvResult(res.data);
    } catch { notify('Conversion failed'); }
    finally { setConvLoading(false); }
  };

  // ── Bulk ──────────────────────────────────────────────────────────────────

  const runBulk = async () => {
    if (selected.size === 0) { notify('Select rules first'); return; }
    setBulkLoading(true);
    try {
      const res = await sigmaAPI.bulk(bulkAction, Array.from(selected), bulkValue);
      notify(`${res.data.affected} rules ${bulkAction}d`);
      setSelected(new Set());
      loaded.current = {};
      loadBase();
    } catch { notify('Bulk action failed'); }
    finally { setBulkLoading(false); }
  };

  // ── Export ───────────────────────────────────────────────────────────────

  const exportRules = async (fmt: string) => {
    try {
      const res = await sigmaAPI.export(fmt, selected.size > 0 ? Array.from(selected) : []);
      const blob = new Blob([typeof res.data === 'string' ? res.data : JSON.stringify(res.data, null, 2)],
        { type: fmt === 'yaml' ? 'application/x-yaml' : 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `sigma_rules.${fmt}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch { notify('Export failed'); }
  };

  // ── Tab description from spec ─────────────────────────────────────────────

  const describeRule = (r: SigmaRule) =>
    r.condition || (r.selections && Object.keys(r.selections).length
      ? Object.keys(r.selections).join(' or ')
      : 'any keyword');

  // ═══════════════════════════════════════════════════════════════════════════
  // RENDER
  // ═══════════════════════════════════════════════════════════════════════════

  return (
    <RootLayout
      title="Sigma Rules"
      subtitle={`${rules.length} rules · ${rules.filter(r => r.enabled).length} active`}
      onRefresh={() => { loaded.current = {}; loadBase(true); }}
      refreshing={refreshing}
      actions={
        <div className="flex items-center gap-2">
          <label className={`g-btn g-btn-ghost text-xs cursor-pointer ${importing ? 'opacity-50 pointer-events-none' : ''}`}>
            <Upload className="h-3.5 w-3.5" />
            {importing ? 'Importing…' : 'Import YAML'}
            <input type="file" multiple accept=".yml,.yaml" className="hidden"
              onChange={e => { handleImport(e.target.files!); e.target.value = ''; }} />
          </label>
          <button onClick={() => { resetForm(); setEditMode('create'); setEditTarget(null); setTab('editor'); }}
            className="g-btn g-btn-primary text-xs">
            <Plus className="h-3.5 w-3.5" /> New Rule
          </button>
        </div>
      }>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm"
          style={{ color: 'var(--text-1)', minWidth: 200 }}>{toast}</div>
      )}

      {importLog && (
        <div className="g-panel px-4 py-3 text-xs mb-3 whitespace-pre-wrap" style={{ color: 'var(--text-2)' }}>
          <div className="flex justify-between items-start gap-3">
            <span>{importLog}</span>
            <button onClick={() => setImportLog(null)} style={{ color: 'var(--text-3)' }}><X className="h-3.5 w-3.5" /></button>
          </div>
        </div>
      )}

      {/* ── Tabs ── */}
      <div className="flex items-center gap-1 flex-wrap mb-5 pb-3" style={{ borderBottom: '1px solid var(--border)' }}>
        {TABS.map(t => {
          const Icon = t.icon;
          const active = tab === t.id;
          return (
            <button key={t.id} onClick={() => setTab(t.id)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition-all"
              style={{
                background: active ? 'var(--accent-glow)' : 'transparent',
                border: `1px solid ${active ? 'var(--accent-border)' : 'transparent'}`,
                color: active ? 'var(--accent)' : 'var(--text-3)',
                fontWeight: active ? 600 : 400,
              }}>
              <Icon className="h-3.5 w-3.5" />{t.label}
            </button>
          );
        })}
      </div>

      {/* ═══ DASHBOARD ═══ */}
      {tab === 'dashboard' && (
        <div className="space-y-5">
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
            <KPICard label="Total Rules" value={dash?.total ?? rules.length} />
            <KPICard label="Enabled" value={dash?.enabled ?? rules.filter(r => r.enabled).length} color="var(--green)" />
            <KPICard label="Disabled" value={dash?.disabled ?? rules.filter(r => !r.enabled).length} color="var(--text-3)" />
            <KPICard label="Triggered 24h" value={dash?.triggered_24h ?? '—'} color="var(--orange)" />
            <KPICard label="MITRE Tactics" value={dash?.mitre_tactics ?? '—'} color="var(--accent)" sub="covered" />
            <KPICard label="Techniques" value={dash?.mitre_techniques ?? '—'} color="var(--accent)" sub="mapped" />
          </div>

          {dash && (
            <div className="grid grid-cols-3 gap-4">
              {/* Severity breakdown */}
              <div className="g-card p-4">
                <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>By Severity</p>
                <div className="space-y-2">
                  {(['critical', 'high', 'medium', 'low', 'info'] as const).map(s => (
                    <div key={s}>
                      <div className="flex justify-between text-[10px] mb-0.5">
                        <span className="capitalize" style={{ color: SEV_COLOR[s] }}>{s}</span>
                        <span style={{ color: 'var(--text-2)' }}>{dash.severity[s]}</span>
                      </div>
                      <MiniBar value={dash.severity[s]} max={dash.total} color={SEV_COLOR[s]} />
                    </div>
                  ))}
                </div>
              </div>

              {/* Trend */}
              <div className="g-card p-4">
                <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Hit Trend (14d)</p>
                <SparkTrend trend={dash.trend} />
                <p className="text-[10px] mt-2" style={{ color: 'var(--text-3)' }}>{dash.total_hits_24h} hits in last 24h</p>
              </div>

              {/* Status */}
              <div className="g-card p-4">
                <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>By Status</p>
                <div className="space-y-2">
                  {(['stable', 'experimental', 'testing'] as const).map(s => (
                    <div key={s} className="flex items-center justify-between">
                      <StatusBadge status={s} />
                      <span className="text-xs font-mono" style={{ color: 'var(--text-2)' }}>{dash.status[s as keyof typeof dash.status]}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Top rules */}
          {dash?.top_rules?.length ? (
            <div className="g-card p-4">
              <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Top Firing Rules (7d)</p>
              <div className="space-y-2">
                {dash.top_rules.map(r => (
                  <div key={r.id} className="flex items-center gap-3">
                    <SevBadge sev={r.severity} />
                    <span className="flex-1 text-xs truncate" style={{ color: 'var(--text-1)' }}>{r.title}</span>
                    <span className="text-[10px] font-mono" style={{ color: 'var(--text-3)' }}>{r.hits_24h}h · {r.hits_7d}w</span>
                    <MiniBar value={r.hits_7d} max={dash.top_rules[0]?.hits_7d ?? 1} color="var(--accent)" />
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          {/* Categories */}
          {dash?.categories?.length ? (
            <div className="g-card p-4">
              <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>By Platform</p>
              <div className="flex flex-wrap gap-2">
                {dash.categories.map(c => (
                  <div key={c.category} className="flex items-center gap-2 rounded-lg px-3 py-2"
                    style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                    <span className="text-xs font-medium capitalize" style={{ color: 'var(--text-1)' }}>{c.category}</span>
                    <span className="text-[10px] font-mono rounded px-1.5"
                      style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>{c.total}</span>
                    <span className="text-[10px]" style={{ color: 'var(--green)' }}>{c.enabled} on</span>
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          {!dash && (
            <div className="py-12 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading dashboard…</div>
          )}
        </div>
      )}

      {/* ═══ LIBRARY ═══ */}
      {tab === 'library' && (
        <div className="space-y-4">
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 min-w-[200px] max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
              <input value={search} onChange={e => setSearch(e.target.value)}
                placeholder="Search title, MITRE, tags, product…" className="g-input pl-9" />
            </div>
            <div className="flex gap-1">
              {['', ...SEVERITIES].map(s => (
                <button key={s || 'all'} onClick={() => setSevFilter(s)}
                  className="px-3 py-1.5 text-xs rounded-lg capitalize transition-all"
                  style={{
                    background: sevFilter === s ? 'var(--accent-glow)' : 'var(--glass-bg)',
                    border: `1px solid ${sevFilter === s ? 'var(--accent-border)' : 'var(--border)'}`,
                    color: sevFilter === s ? 'var(--accent)' : 'var(--text-2)',
                  }}>
                  {s || 'all'}
                </button>
              ))}
            </div>
            {selected.size > 0 && (
              <span className="text-xs rounded-lg px-2 py-1" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>
                {selected.size} selected
              </span>
            )}
          </div>

          <div className="g-table">
            <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '24px 1fr 90px 90px 90px 70px 52px 68px' }}>
              <input type="checkbox" checked={selected.size === filtered.length && filtered.length > 0}
                onChange={e => setSelected(e.target.checked ? new Set(filtered.map(r => r.id)) : new Set())}
                className="h-3.5 w-3.5" />
              <span>Title / Description</span>
              <span>Logsource</span>
              <span>MITRE</span>
              <span>Severity</span>
              <span>Status</span>
              <span>Hits</span>
              <span className="text-right">Actions</span>
            </div>

            {loading ? (
              <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
            ) : filtered.length === 0 ? (
              <div className="py-16 text-center">
                <FileCode className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
                <p className="text-sm" style={{ color: 'var(--text-2)' }}>No rules found. Import or create one.</p>
              </div>
            ) : filtered.map(r => {
              const hit = hitMap[r.id];
              const logsrc = [r.logsource_prod, r.logsource_cat, r.logsource_svc].filter(Boolean).join('/') || '—';
              return (
                <div key={r.id} className={`g-tr grid gap-3 items-center px-4 ${!r.enabled ? 'opacity-50' : ''}`}
                  style={{ gridTemplateColumns: '24px 1fr 90px 90px 90px 70px 52px 68px' }}>
                  <input type="checkbox" checked={selected.has(r.id)}
                    onChange={e => setSelected(s => { const n = new Set(s); e.target.checked ? n.add(r.id) : n.delete(r.id); return n; })}
                    className="h-3.5 w-3.5" />
                  <div>
                    <div className="flex items-center gap-1.5">
                      <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{r.title}</p>
                      <button onClick={() => toggleRule(r)} title={r.enabled ? 'Disable' : 'Enable'}>
                        {r.enabled
                          ? <ToggleRight className="h-4 w-4 shrink-0" style={{ color: 'var(--green)' }} />
                          : <ToggleLeft className="h-4 w-4 shrink-0" style={{ color: 'var(--text-3)' }} />}
                      </button>
                    </div>
                    {r.description
                      ? <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>{r.description}</p>
                      : <p className="text-[10px] font-mono truncate" style={{ color: 'var(--text-3)' }}>{describeRule(r)}</p>}
                    {(r.tags || []).length > 0 && (
                      <div className="flex gap-1 flex-wrap mt-0.5">
                        {(r.tags || []).slice(0, 3).map(t => (
                          <span key={t} className="text-[9px] font-mono rounded px-1"
                            style={{ background: 'var(--bg-0)', color: 'var(--text-3)', border: '1px solid var(--border)' }}>{t}</span>
                        ))}
                      </div>
                    )}
                  </div>
                  <span className="text-[10px] font-mono truncate" style={{ color: 'var(--text-3)' }}>{logsrc}</span>
                  <span className="text-[10px] font-mono rounded px-1.5 py-0.5 w-fit"
                    style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                    {r.mitre_technique || '—'}
                  </span>
                  <SevBadge sev={r.severity} />
                  <StatusBadge status={r.status} />
                  <span className="text-[11px] font-mono" style={{ color: hit?.hit_count ? 'var(--accent)' : 'var(--text-3)' }}>
                    {hit?.hit_count ?? 0}
                  </span>
                  <div className="flex items-center justify-end gap-1">
                    <button onClick={() => duplicate(r)} title="Duplicate" className="p-1 rounded" style={{ color: 'var(--text-3)' }}><Copy className="h-3.5 w-3.5" /></button>
                    <button onClick={() => { const f = ruleToForm(r); setModalForm(f); setModalEdit(r); }} title="Edit" className="p-1 rounded" style={{ color: 'var(--text-3)' }}><Edit2 className="h-3.5 w-3.5" /></button>
                    <button onClick={() => delRule(r.id)} title="Delete" className="p-1 rounded" style={{ color: 'var(--text-3)' }}
                      onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--red)'}
                      onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}><Trash2 className="h-3.5 w-3.5" /></button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ═══ EDITOR ═══ */}
      {tab === 'editor' && (
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="flex gap-1">
              <button onClick={() => { resetForm(); setEditMode('create'); setEditTarget(null); }}
                className="px-3 py-1.5 text-xs rounded-lg transition-all"
                style={{
                  background: editMode === 'create' ? 'var(--accent-glow)' : 'var(--glass-bg)',
                  border: `1px solid ${editMode === 'create' ? 'var(--accent-border)' : 'var(--border)'}`,
                  color: editMode === 'create' ? 'var(--accent)' : 'var(--text-2)',
                }}>New Rule</button>
            </div>
            {editMode === 'edit' && editTarget && (
              <span className="text-xs" style={{ color: 'var(--text-3)' }}>Editing: {editTarget.title}</span>
            )}
            {rules.length > 0 && (
              <div className="ml-auto flex items-center gap-2">
                <span className="text-xs" style={{ color: 'var(--text-3)' }}>Load existing:</span>
                <select className="g-select text-xs" style={{ width: 200 }}
                  value={editTarget?.id ?? ''}
                  onChange={e => {
                    const r = rules.find(x => x.id === Number(e.target.value));
                    if (r) { setForm(ruleToForm(r)); setEditMode('edit'); setEditTarget(r); }
                  }}>
                  <option value="">— select rule —</option>
                  {rules.map(r => <option key={r.id} value={r.id}>{r.title}</option>)}
                </select>
              </div>
            )}
          </div>
          <RuleForm
            form={form} setForm={setForm}
            onSave={saveRule} onCancel={() => { resetForm(); setEditMode('create'); setEditTarget(null); }}
            saving={saving} mode={editMode}
          />
        </div>
      )}

      {/* ═══ TESTING ═══ */}
      {tab === 'testing' && (
        <div className="space-y-4">
          <div className="g-card p-4">
            <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Test Rules Against Log Event</p>
            <div className="flex gap-3">
              <input value={testMsg} onChange={e => setTestMsg(e.target.value)}
                placeholder="Paste a raw log line or JSON event to test against all enabled rules…"
                className="g-input flex-1" />
              <button onClick={runTest} disabled={testing || !testMsg.trim()} className="g-btn g-btn-primary text-xs shrink-0">
                <TestTube className="h-3.5 w-3.5" />{testing ? 'Testing…' : 'Run Test'}
              </button>
            </div>
            {testRes && (
              <div className="mt-4 rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                <div className="g-thead grid px-4 py-2.5" style={{ gridTemplateColumns: '80px 1fr' }}>
                  <span>Match</span><span>Rule</span>
                </div>
                {(Array.isArray(testRes) ? testRes : [testRes]).map((r: any, i: number) => (
                  <div key={i} className="g-tr grid px-4 items-center" style={{ gridTemplateColumns: '80px 1fr' }}>
                    <span className={r.matched ? 's-critical' : 's-online'}>{r.matched ? 'MATCH' : 'NO MATCH'}</span>
                    <span className="text-xs" style={{ color: 'var(--text-1)' }}>{r.rule_name}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="g-card p-4">
            <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Sample Test Payloads</p>
            <div className="space-y-2">
              {[
                { label: 'PowerShell execution', msg: '{"EventID":4688,"CommandLine":"powershell.exe -enc JABj...","ParentImage":"cmd.exe"}' },
                { label: 'SSH failed login', msg: 'Failed password for invalid user admin from 192.168.1.100 port 52841 ssh2' },
                { label: 'Mimikatz', msg: '{"EventID":4104,"ScriptBlockText":"Invoke-Mimikatz -DumpCreds","Computer":"WIN10-PC"}' },
                { label: 'Brute force', msg: '{"event_type":"failed_login","username":"admin","src_ip":"10.0.0.5","count":50}' },
              ].map(sample => (
                <div key={sample.label} className="flex items-center gap-3 p-2 rounded-lg cursor-pointer"
                  style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}
                  onClick={() => setTestMsg(sample.msg)}>
                  <ChevronRight className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />
                  <span className="text-xs font-medium" style={{ color: 'var(--text-2)' }}>{sample.label}</span>
                  <span className="text-[10px] font-mono truncate" style={{ color: 'var(--text-3)' }}>{sample.msg.slice(0, 60)}…</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ═══ MITRE ═══ */}
      {tab === 'mitre' && (
        <div className="space-y-4">
          {!mitreCov ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading MITRE coverage…</div>
          ) : (
            <>
              <div className="grid grid-cols-3 gap-3">
                <KPICard label="Tactics Covered" value={mitreCov.coverage.length} sub={`of 14 (${Math.round(mitreCov.coverage.length / 14 * 100)}%)`} color="var(--accent)" />
                <KPICard label="Techniques Mapped" value={mitreCov.coverage.reduce((s, t) => s + t.techniques.length, 0)} color="var(--green)" />
                <KPICard label="Rules w/o MITRE" value={mitreCov.uncovered} color="var(--text-3)" />
              </div>

              {/* Tactic heatmap */}
              <div className="g-card p-4">
                <p className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: 'var(--text-3)' }}>MITRE ATT&CK Technique Coverage</p>
                <div className="grid gap-4" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))' }}>
                  {mitreCov.coverage.map(tg => (
                    <div key={tg.tactic} className="rounded-xl p-3" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                      <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--accent)' }}>
                        {tg.tactic.replace(/-/g, ' ')}
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {tg.techniques.map(t => (
                          <div key={t.technique} title={`${t.technique}: ${t.name} — ${t.rules} rule(s)`}
                            className="text-[9px] font-mono rounded px-1.5 py-0.5 cursor-default"
                            style={{
                              background: t.enabled > 0 ? 'rgba(52,211,153,0.15)' : 'rgba(255,255,255,0.04)',
                              border: `1px solid ${t.enabled > 0 ? 'rgba(52,211,153,0.4)' : 'var(--border)'}`,
                              color: t.enabled > 0 ? 'var(--green)' : 'var(--text-3)',
                            }}>
                            {t.technique}
                            {t.rules > 1 && <span className="ml-0.5" style={{ color: 'var(--accent)' }}>×{t.rules}</span>}
                          </div>
                        ))}
                      </div>
                      <p className="text-[10px] mt-2" style={{ color: 'var(--text-3)' }}>{tg.total_rules} rule{tg.total_rules !== 1 ? 's' : ''}</p>
                    </div>
                  ))}
                </div>

                {/* Uncovered tactics */}
                {MITRE_14.filter(t => !mitreCov.coverage.find(c => c.tactic.toLowerCase().includes(t))).length > 0 && (
                  <div className="mt-4 pt-3" style={{ borderTop: '1px solid var(--border)' }}>
                    <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Uncovered Tactics</p>
                    <div className="flex flex-wrap gap-1.5">
                      {MITRE_14.filter(t => !mitreCov.coverage.find(c => c.tactic.toLowerCase().includes(t))).map(t => (
                        <span key={t} className="text-[10px] rounded px-2 py-0.5 capitalize"
                          style={{ background: 'rgba(239,68,68,0.08)', color: 'var(--red)', border: '1px solid rgba(239,68,68,0.2)' }}>
                          {t.replace(/-/g, ' ')}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      )}

      {/* ═══ ANALYTICS ═══ */}
      {tab === 'analytics' && (
        <div className="space-y-4">
          {!analytics ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading analytics…</div>
          ) : (
            <>
              <div className="grid grid-cols-2 gap-4">
                {/* Daily trend */}
                <div className="g-card p-4">
                  <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Daily Hits (30d)</p>
                  {analytics.daily.length > 0 ? (
                    <SparkTrend trend={analytics.daily.map(d => ({ date: d.date, count: d.hits }))} />
                  ) : <p className="text-xs" style={{ color: 'var(--text-3)' }}>No hits recorded yet</p>}
                </div>
                {/* Severity distribution */}
                <div className="g-card p-4">
                  <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Hits by Severity (7d)</p>
                  <div className="space-y-2">
                    {analytics.sev_hits.map((s: any) => (
                      <div key={s.severity}>
                        <div className="flex justify-between text-[10px] mb-0.5">
                          <span style={{ color: SEV_COLOR[s.severity] ?? 'var(--text-2)' }} className="capitalize">{s.severity}</span>
                          <span style={{ color: 'var(--text-2)' }}>{s.hits}</span>
                        </div>
                        <MiniBar value={s.hits} max={analytics.sev_hits[0]?.hits ?? 1} color={SEV_COLOR[s.severity] ?? 'var(--accent)'} />
                      </div>
                    ))}
                    {analytics.sev_hits.length === 0 && <p className="text-xs" style={{ color: 'var(--text-3)' }}>No hits in last 7 days</p>}
                  </div>
                </div>
              </div>

              {/* Per-rule table */}
              <div className="g-card p-4">
                <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Rule Performance</p>
                <div className="g-table">
                  <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 80px 60px 60px 60px 120px' }}>
                    <span>Rule</span><span>Tactic</span><span>24h</span><span>7d</span><span>Total</span><span>Last Hit</span>
                  </div>
                  {analytics.rules.slice(0, 50).map((r: RuleAnalytic) => (
                    <div key={r.id} className={`g-tr grid gap-3 items-center px-4 ${!r.enabled ? 'opacity-50' : ''}`}
                      style={{ gridTemplateColumns: '1fr 80px 60px 60px 60px 120px' }}>
                      <div>
                        <p className="text-xs truncate" style={{ color: 'var(--text-1)' }}>{r.title}</p>
                        <SevBadge sev={r.severity} />
                      </div>
                      <span className="text-[10px] font-mono truncate" style={{ color: 'var(--text-3)' }}>{r.mitre_tactic || '—'}</span>
                      <span className="text-xs font-mono text-center" style={{ color: r.hits_24h ? 'var(--orange)' : 'var(--text-3)' }}>{r.hits_24h}</span>
                      <span className="text-xs font-mono text-center" style={{ color: r.hits_7d ? 'var(--accent)' : 'var(--text-3)' }}>{r.hits_7d}</span>
                      <span className="text-xs font-mono text-center" style={{ color: r.hit_count ? 'var(--green)' : 'var(--text-3)' }}>{r.hit_count}</span>
                      <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{r.last_hit ? timeAgo(r.last_hit) : '—'}</span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {/* ═══ CATEGORIES ═══ */}
      {tab === 'categories' && (
        <div className="space-y-4">
          {!categories ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading categories…</div>
          ) : (
            <div className="g-card p-4">
              <p className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: 'var(--text-3)' }}>Rules by Platform / Category</p>
              <div className="g-table">
                <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 1fr 80px 80px 80px' }}>
                  <span>Platform</span><span>Category</span><span>Total</span><span>Enabled</span><span>Hits 7d</span>
                </div>
                {categories.map((c, i) => (
                  <div key={i} className="g-tr grid gap-3 items-center px-4" style={{ gridTemplateColumns: '1fr 1fr 80px 80px 80px' }}>
                    <span className="text-xs font-medium capitalize" style={{ color: 'var(--text-1)' }}>{c.platform}</span>
                    <span className="text-xs capitalize" style={{ color: 'var(--text-2)' }}>{c.category}</span>
                    <span className="text-xs font-mono" style={{ color: 'var(--text-2)' }}>{c.total}</span>
                    <span className="text-xs font-mono" style={{ color: 'var(--green)' }}>{c.enabled}</span>
                    <span className="text-xs font-mono" style={{ color: c.hits_7d > 0 ? 'var(--accent)' : 'var(--text-3)' }}>{c.hits_7d}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ═══ AI ASSISTANT ═══ */}
      {tab === 'ai' && (
        <div className="space-y-4">
          <div className="g-card p-5">
            <div className="flex items-center gap-2 mb-4">
              <Bot className="h-4 w-4" style={{ color: 'var(--accent)' }} />
              <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>AI Sigma Rule Assistant</p>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Action</label>
                <select value={aiAction} onChange={e => setAiAction(e.target.value)} className="g-select">
                  <option value="generate">Generate new rule from description</option>
                  <option value="explain">Explain an existing rule</option>
                  <option value="optimize">Optimize / improve a rule</option>
                  <option value="test_cases">Generate test cases</option>
                  <option value="fp_analysis">False positive analysis</option>
                  <option value="convert">Convert to target platform</option>
                </select>
              </div>
              {['explain', 'optimize', 'test_cases', 'fp_analysis', 'convert'].includes(aiAction) && (
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Select Rule</label>
                  <select className="g-select" value={aiRuleID ?? ''} onChange={e => setAiRuleID(Number(e.target.value) || null)}>
                    <option value="">— select rule —</option>
                    {rules.map(r => <option key={r.id} value={r.id}>{r.title}</option>)}
                  </select>
                </div>
              )}
              {aiAction === 'convert' && (
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Target Platform</label>
                  <select value={aiTarget} onChange={e => setAiTarget(e.target.value)} className="g-select">
                    {PLATFORMS.map(p => <option key={p} value={p}>{p}</option>)}
                  </select>
                </div>
              )}
            </div>

            {aiAction === 'generate' && (
              <div className="mb-4">
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Detection Requirement</label>
                <textarea value={aiPrompt} onChange={e => setAiPrompt(e.target.value)} rows={3}
                  placeholder="Detect PowerShell downloading files from the internet using WebClient or Invoke-WebRequest…"
                  className="g-input w-full resize-none font-mono text-xs" />
              </div>
            )}

            <button onClick={runAI} disabled={aiLoading} className="g-btn g-btn-primary text-xs">
              <Zap className="h-3.5 w-3.5" />{aiLoading ? 'Thinking…' : 'Run AI'}
            </button>
          </div>

          {aiResult && (
            <div className="g-card p-4">
              <div className="flex items-center justify-between mb-3">
                <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>AI Response</p>
                <button onClick={() => navigator.clipboard.writeText(typeof aiResult === 'string' ? aiResult : JSON.stringify(aiResult, null, 2)).catch(() => {})}
                  className="g-btn g-btn-ghost text-[10px]" style={{ padding: '2px 8px' }}>
                  <Copy className="h-3 w-3" /> Copy
                </button>
              </div>

              {aiAction === 'generate' && aiResult.yaml && (
                <div className="space-y-3">
                  <pre className="p-3 text-[11px] font-mono rounded-xl overflow-auto"
                    style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-2)', maxHeight: 400 }}>
                    {aiResult.yaml}
                  </pre>
                  <button onClick={() => {
                    const yaml = aiResult.yaml as string;
                    const titleMatch = yaml.match(/^title:\s*(.+)/m);
                    setForm(f => ({ ...f, title: titleMatch?.[1]?.trim() ?? 'AI Generated Rule' }));
                    setTab('editor');
                    notify('Loaded AI-generated rule into editor');
                  }} className="g-btn g-btn-primary text-xs">
                    <FileCode className="h-3.5 w-3.5" /> Load into Editor
                  </button>
                </div>
              )}

              {aiAction === 'explain' && (
                <div className="space-y-3">
                  {['summary', 'threat', 'logic', 'mitre', 'logsource', 'false_positives', 'tuning_tips'].map(k => {
                    const val = (aiResult as any)[k];
                    if (!val) return null;
                    return (
                      <div key={k} className="rounded-lg p-3" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                        <p className="text-[10px] uppercase tracking-wider font-semibold mb-1" style={{ color: 'var(--text-3)' }}>{k.replace(/_/g, ' ')}</p>
                        <p className="text-xs" style={{ color: 'var(--text-2)' }}>{val}</p>
                      </div>
                    );
                  })}
                </div>
              )}

              {(aiAction === 'optimize' || aiAction === 'fp_analysis' || aiAction === 'test_cases') && (
                <pre className="p-3 text-[11px] font-mono rounded-xl overflow-auto"
                  style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-2)', maxHeight: 500 }}>
                  {JSON.stringify(aiResult, null, 2)}
                </pre>
              )}

              {aiAction === 'convert' && (aiResult as any).query && (
                <div className="space-y-3">
                  <div>
                    <p className="text-[10px] uppercase tracking-wider font-semibold mb-1" style={{ color: 'var(--text-3)' }}>Query</p>
                    <pre className="p-3 text-[11px] font-mono rounded-xl overflow-auto"
                      style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-2)', maxHeight: 200 }}>
                      {(aiResult as any).query}
                    </pre>
                  </div>
                  {(aiResult as any).notes && (
                    <p className="text-xs" style={{ color: 'var(--text-2)' }}>{(aiResult as any).notes}</p>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ═══ CONVERT ═══ */}
      {tab === 'convert' && (
        <div className="space-y-4">
          <div className="g-card p-5">
            <div className="flex items-center gap-2 mb-4">
              <Repeat2 className="h-4 w-4" style={{ color: 'var(--accent)' }} />
              <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Sigma Rule Converter</p>
              <span className="text-[10px] rounded px-1.5 py-0.5" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>AI-Powered</span>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Source Rule</label>
                <select className="g-select" value={convRuleID ?? ''} onChange={e => setConvRuleID(Number(e.target.value) || null)}>
                  <option value="">— select a Sigma rule —</option>
                  {rules.map(r => <option key={r.id} value={r.id}>{r.title}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Target Platform</label>
                <select value={convTarget} onChange={e => setConvTarget(e.target.value)} className="g-select">
                  <option value="elasticsearch">Elasticsearch (EQL / Lucene)</option>
                  <option value="splunk">Splunk SPL</option>
                  <option value="kql">Microsoft Sentinel KQL</option>
                  <option value="qradar">IBM QRadar AQL</option>
                  <option value="suricata">Suricata IDS</option>
                  <option value="opensearch">OpenSearch DSL</option>
                </select>
              </div>
            </div>

            <button onClick={runConvert} disabled={convLoading || !convRuleID} className="g-btn g-btn-primary text-xs">
              <Repeat2 className="h-3.5 w-3.5" />{convLoading ? 'Converting…' : 'Convert Rule'}
            </button>
          </div>

          {convResult && (
            <div className="g-card p-4 space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Converted Query</p>
                <button onClick={() => navigator.clipboard.writeText((convResult as any).query ?? '').catch(() => {})}
                  className="g-btn g-btn-ghost text-[10px]" style={{ padding: '2px 8px' }}>
                  <Copy className="h-3 w-3" /> Copy
                </button>
              </div>
              <pre className="p-3 text-[11px] font-mono rounded-xl overflow-auto"
                style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-2)', maxHeight: 300 }}>
                {(convResult as any).query}
              </pre>
              {(convResult as any).notes && (
                <p className="text-xs" style={{ color: 'var(--text-2)' }}><span style={{ color: 'var(--text-3)' }}>Notes: </span>{(convResult as any).notes}</p>
              )}
              {(convResult as any).limitations && (
                <div className="flex items-start gap-2 p-2 rounded-lg" style={{ background: 'rgba(251,191,36,0.08)', border: '1px solid rgba(251,191,36,0.2)' }}>
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" style={{ color: 'var(--yellow)' }} />
                  <p className="text-xs" style={{ color: 'var(--text-2)' }}>{(convResult as any).limitations}</p>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ═══ BULK OPS ═══ */}
      {tab === 'bulk' && (
        <div className="space-y-4">
          <div className="g-card p-5">
            <div className="flex items-center gap-2 mb-4">
              <CheckSquare className="h-4 w-4" style={{ color: 'var(--accent)' }} />
              <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Bulk Operations</p>
              {selected.size > 0 && (
                <span className="text-[10px] rounded px-1.5 py-0.5" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>
                  {selected.size} rule{selected.size !== 1 ? 's' : ''} selected
                </span>
              )}
            </div>

            <div className="grid grid-cols-3 gap-4 mb-4">
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Action</label>
                <select value={bulkAction} onChange={e => setBulkAction(e.target.value)} className="g-select">
                  <option value="enable">Enable selected</option>
                  <option value="disable">Disable selected</option>
                  <option value="delete">Delete selected</option>
                  <option value="set_severity">Set severity</option>
                  <option value="set_status">Set status</option>
                </select>
              </div>
              {['set_severity', 'set_status'].includes(bulkAction) && (
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Value</label>
                  {bulkAction === 'set_severity' ? (
                    <select value={bulkValue} onChange={e => setBulkValue(e.target.value)} className="g-select">
                      {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
                    </select>
                  ) : (
                    <select value={bulkValue} onChange={e => setBulkValue(e.target.value)} className="g-select">
                      {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
                    </select>
                  )}
                </div>
              )}
            </div>

            <div className="flex items-center gap-3">
              <button onClick={runBulk} disabled={bulkLoading || selected.size === 0} className="g-btn g-btn-primary text-xs">
                <Zap className="h-3.5 w-3.5" />{bulkLoading ? 'Running…' : `Apply to ${selected.size || 0} rules`}
              </button>
              <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                Select rules in the Library tab, then return here to apply bulk actions.
              </p>
            </div>
          </div>

          {/* Quick select helpers */}
          <div className="g-card p-4">
            <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Quick Selection</p>
            <div className="flex flex-wrap gap-2">
              {[
                { label: 'All rules', fn: () => setSelected(new Set(rules.map(r => r.id))) },
                { label: 'All enabled', fn: () => setSelected(new Set(rules.filter(r => r.enabled).map(r => r.id))) },
                { label: 'All disabled', fn: () => setSelected(new Set(rules.filter(r => !r.enabled).map(r => r.id))) },
                { label: 'Critical severity', fn: () => setSelected(new Set(rules.filter(r => r.severity === 'critical').map(r => r.id))) },
                { label: 'Experimental status', fn: () => setSelected(new Set(rules.filter(r => r.status === 'experimental').map(r => r.id))) },
                { label: 'Clear selection', fn: () => setSelected(new Set()) },
              ].map(h => (
                <button key={h.label} onClick={h.fn} className="g-btn g-btn-ghost text-xs">{h.label}</button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ═══ IMPORT / EXPORT ═══ */}
      {tab === 'import' && (
        <div className="space-y-4">
          <div className="g-card p-5">
            <div className="flex items-center gap-2 mb-4">
              <Upload className="h-4 w-4" style={{ color: 'var(--accent)' }} />
              <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Import Sigma Rules</p>
            </div>
            <p className="text-xs mb-4" style={{ color: 'var(--text-3)' }}>
              Import one or more Sigma YAML files. Multi-document YAML files (--- separated) are supported.
              Rules will be parsed, MITRE mappings extracted, and selectively imported (duplicates skipped).
            </p>
            <label className={`g-btn g-btn-primary text-xs cursor-pointer ${importing ? 'opacity-50 pointer-events-none' : ''}`}>
              <Upload className="h-3.5 w-3.5" />
              {importing ? 'Importing…' : 'Choose YAML Files'}
              <input type="file" multiple accept=".yml,.yaml" className="hidden"
                onChange={e => { handleImport(e.target.files!); e.target.value = ''; }} />
            </label>
            {importLog && (
              <div className="mt-3 p-3 rounded-xl text-xs font-mono whitespace-pre-wrap"
                style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                {importLog}
              </div>
            )}
          </div>

          <div className="g-card p-5">
            <div className="flex items-center gap-2 mb-4">
              <Download className="h-4 w-4" style={{ color: 'var(--accent)' }} />
              <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Export Rules</p>
            </div>
            <p className="text-xs mb-4" style={{ color: 'var(--text-3)' }}>
              Export rules as YAML or JSON. Select rules in the Library tab to export a subset, or export all.
              {selected.size > 0 && <> <span style={{ color: 'var(--accent)' }}>{selected.size} rules selected</span>.</>}
            </p>
            <div className="flex gap-3">
              <button onClick={() => exportRules('yaml')} className="g-btn g-btn-primary text-xs">
                <Download className="h-3.5 w-3.5" /> Export as YAML
              </button>
              <button onClick={() => exportRules('json')} className="g-btn g-btn-ghost text-xs">
                <Download className="h-3.5 w-3.5" /> Export as JSON
              </button>
            </div>
          </div>

          <div className="g-card p-4">
            <div className="flex items-center gap-2 mb-3">
              <Eye className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
              <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Community Rule Sources</p>
            </div>
            <div className="space-y-2">
              {[
                { name: 'SigmaHQ / sigma', desc: 'Official Sigma rule repository — thousands of curated rules', url: 'https://github.com/SigmaHQ/sigma' },
                { name: 'MITRE CAR', desc: 'MITRE Cyber Analytics Repository — ATT&CK-mapped rules', url: 'https://car.mitre.org/' },
                { name: 'Neo23x0 / sigma-rules', desc: 'Florian Roth curated detection rules', url: 'https://github.com/Neo23x0/sigma' },
              ].map(src => (
                <div key={src.name} className="flex items-center gap-3 p-2.5 rounded-lg"
                  style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                  <div className="flex-1">
                    <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{src.name}</p>
                    <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{src.desc}</p>
                  </div>
                  <a href={src.url} target="_blank" rel="noreferrer"
                    className="g-btn g-btn-ghost text-[10px]" style={{ padding: '2px 8px' }}>
                    View <ChevronRight className="h-3 w-3" />
                  </a>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Quick Edit Modal (from library) ── */}
      {modalEdit && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setModalEdit(null)}>
          <div className="g-modal" style={{ maxWidth: 700 }}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Edit: {modalEdit.title}</h2>
              <button onClick={() => setModalEdit(null)} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>
            <div className="p-5 overflow-y-auto" style={{ maxHeight: '78vh' }}>
              <RuleForm
                form={modalForm} setForm={setModalForm}
                onSave={saveModalEdit}
                onCancel={() => setModalEdit(null)}
                saving={modalSaving} mode="edit"
              />
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
