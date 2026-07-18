'use client';

import { useEffect, useState, useCallback, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { yaraAPI, agentsAPI, schedulerAPI } from '@/lib/api';
import { YaraRule, YaraMatch } from '@/types';
import { timeAgo, sevClass } from '@/lib/utils';
import { Agent } from '@/types';
import { AlertTriangle, BarChart, Bot, CheckSquare, ChevronDown, ChevronRight, ChevronUp, Clock, Code2, Copy, Download, Edit2, FileWarning, Grid, Hash, Layers, Plus, Search, Shield, ToggleLeft, ToggleRight, Trash2, Upload, X, Zap } from '@/lib/icon-stubs';

// ── Types ─────────────────────────────────────────────────────────────────

interface MatchedString { identifier: string; offset: string; data: string; }

interface ScheduledTaskLite {
  id: number; name: string; task_type: string;
  enabled: boolean; last_run_at: string | null; next_run_at: string | null;
}

interface DashData {
  total: number; enabled: number; disabled: number;
  matches_today: number; matches_week: number; matches_total: number;
  files_detected: number; agents_triggered: number;
  sev_breakdown: { severity: string; count: number }[];
  top_rules: { rule_name: string; matches: number; matches_24h: number; severity: string }[];
  trend: { date: string; count: number }[];
  recent_matches: { rule_name: string; file_path: string; severity: string; agent_id: number; created_at: string }[];
}

interface RuleStat {
  rule_name: string; total: number; last_7d: number; last_24h: number;
  last_match: string | null; top_severity: string;
}

interface CatGroup {
  category: string; total: number; enabled: number;
  rules: { id: number; name: string; enabled: boolean }[];
}

interface RelNode { id: string; label: string; type: string; value: number; }
interface RelEdge { source: string; target: string; weight: number; }

// ── Constants ─────────────────────────────────────────────────────────────

const TABS = [
  { id: 'dashboard',  label: 'Dashboard',   icon: Grid },
  { id: 'library',    label: 'Library',     icon: Layers },
  { id: 'editor',     label: 'Rule Editor', icon: Code2 },
  { id: 'matches',    label: 'Matches',     icon: FileWarning },
  { id: 'analytics',  label: 'Analytics',   icon: BarChart },
  { id: 'categories', label: 'Categories',  icon: Shield },
  { id: 'ai',         label: 'AI Assistant',icon: Bot },
  { id: 'bulk',       label: 'Bulk / Export',icon: CheckSquare },
];

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)',
  low: 'var(--blue)', info: 'var(--text-3)',
};

const emptyRule = {
  name: '',
  description: '',
  rule_content: `rule MyRule
{
    meta:
        description = "Detects suspicious activity"
        author      = "XCloak"
        severity    = "high"

    strings:
        $a = "suspicious string"
        $b = { 4D 5A 90 00 }

    condition:
        any of them
}`,
  enabled: true,
};

const AI_ACTIONS = [
  { id: 'generate',         label: 'Generate Rule',       desc: 'Create a new YARA rule from a description' },
  { id: 'explain',          label: 'Explain Rule',         desc: 'Detailed breakdown of the rule logic' },
  { id: 'optimize',         label: 'Optimize Rule',        desc: 'Performance and accuracy improvements' },
  { id: 'suggest_strings',  label: 'Suggest Strings',      desc: 'Additional detection strings to add' },
  { id: 'fp_analysis',      label: 'FP Analysis',          desc: 'False positive risk assessment' },
  { id: 'generate_metadata',label: 'Generate Metadata',    desc: 'Auto-generate rule meta block' },
];

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
  const color = SEV_COLOR[sev?.toLowerCase()] ?? 'var(--text-3)';
  return (
    <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded"
      style={{ color, background: color + '22', border: `1px solid ${color}55` }}>{sev || '—'}</span>
  );
}

function SparkTrend({ trend }: { trend: { date: string; count: number }[] }) {
  if (!trend.length) return <div className="text-xs" style={{ color: 'var(--text-3)' }}>No data</div>;
  const max = Math.max(...trend.map(t => t.count), 1);
  const W = 200, H = 36;
  const pts = trend.map((t, i) => {
    const x = (i / Math.max(trend.length - 1, 1)) * W;
    const y = H - (t.count / max) * (H - 4) - 2;
    return `${x},${y}`;
  }).join(' ');
  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ maxHeight: H }}>
      <polyline points={pts} fill="none" stroke="var(--accent)" strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

function YaraHighlight({ content }: { content: string }) {
  const html = content
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/(\/\/[^\n]*)/g, '<span style="color:var(--text-3)">$1</span>')
    .replace(/\b(rule|meta|strings|condition|and|or|not|any|all|of|them|import|include|private|global|ascii|wide|nocase|fullword|base64|xor|at|in|for|filesize|entrypoint|uint8|uint16|uint32|uint64)\b/g,
      '<span style="color:var(--accent)">$1</span>')
    .replace(/("(?:[^"\\]|\\.)*")/g, '<span style="color:var(--green)">$1</span>')
    .replace(/(\{ *[0-9A-Fa-f ?]+ *\})/g, '<span style="color:var(--orange)">$1</span>')
    .replace(/(\$\w+)/g, '<span style="color:var(--yellow)">$1</span>');
  return (
    <pre className="text-[11px] font-mono p-3 rounded-xl overflow-auto"
      style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-2)', maxHeight: 320 }}
      dangerouslySetInnerHTML={{ __html: html }} />
  );
}

function RelGraph({ nodes, edges }: { nodes: RelNode[]; edges: RelEdge[] }) {
  const COL_TYPES = ['rule', 'agent', 'file'];
  const cols: Record<string, RelNode[]> = { rule: [], agent: [], file: [] };
  nodes.forEach(n => { if (cols[n.type]) cols[n.type].push(n); });

  const W = 640, H = 380, COL_X = [80, 300, 540];
  const pos: Record<string, { x: number; y: number }> = {};
  COL_TYPES.forEach((t, ci) => {
    const count = cols[t].length;
    cols[t].forEach((n, i) => {
      pos[n.id] = { x: COL_X[ci], y: (H / (count + 1)) * (i + 1) };
    });
  });

  const maxW = Math.max(...edges.map(e => e.weight), 1);
  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ maxHeight: 380 }}>
      {edges.map((e, i) => {
        const s = pos[e.source], t = pos[e.target];
        if (!s || !t) return null;
        return (
          <line key={i} x1={s.x} y1={s.y} x2={t.x} y2={t.y}
            stroke="var(--accent)" strokeOpacity={0.15 + (e.weight / maxW) * 0.55}
            strokeWidth={1 + (e.weight / maxW) * 2} />
        );
      })}
      {nodes.map(n => {
        const p = pos[n.id];
        if (!p) return null;
        const color = n.type === 'rule' ? 'var(--accent)' : n.type === 'agent' ? 'var(--blue)' : 'var(--orange)';
        const r = 5 + Math.min(n.value / 5, 12);
        return (
          <g key={n.id}>
            <circle cx={p.x} cy={p.y} r={r} fill={color} fillOpacity={0.25} stroke={color} strokeWidth={1.5} />
            <text x={p.x} y={p.y - r - 3} textAnchor="middle" fill="var(--text-2)" fontSize={9}>{n.label.slice(0, 16)}</text>
          </g>
        );
      })}
      {COL_TYPES.map((t, i) => (
        <text key={t} x={COL_X[i]} y={16} textAnchor="middle" fill="var(--text-3)" fontSize={10} fontWeight={600}>
          {t.toUpperCase()}S
        </text>
      ))}
    </svg>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────

export default function YaraRulesPage() {
  const [tab, setTab]             = useState('dashboard');
  const [rules, setRules]         = useState<YaraRule[]>([]);
  const [matches, setMatches]     = useState<YaraMatch[]>([]);
  const [agents, setAgents]       = useState<Agent[]>([]);
  const [scheduledScan, setScheduledScan] = useState<ScheduledTaskLite | null>(null);
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Library state
  const [search,     setSearch]     = useState('');
  const [selected,   setSelected]   = useState<Set<number>>(new Set());
  const [matchSevFilter, setMatchSevFilter] = useState('');
  const [expandedId, setExpandedId] = useState<number | null>(null);

  // Editor state
  const [editMode,   setEditMode]   = useState<'create' | 'edit'>('create');
  const [editTarget, setEditTarget] = useState<YaraRule | null>(null);
  const [form,       setForm]       = useState({ ...emptyRule });
  const [saving,     setSaving]     = useState(false);

  // Modal for quick edit from library
  const [modalEdit,   setModalEdit]   = useState<YaraRule | null>(null);
  const [modalForm,   setModalForm]   = useState({ ...emptyRule });
  const [modalSaving, setModalSaving] = useState(false);

  // Enterprise data
  const [dash,       setDash]       = useState<DashData | null>(null);
  const [analytics,  setAnalytics]  = useState<{ rules: RuleStat[]; daily: any[]; top_agents: any[] } | null>(null);
  const [categories, setCategories] = useState<CatGroup[] | null>(null);
  const [relData,    setRelData]    = useState<{ nodes: RelNode[]; edges: RelEdge[] } | null>(null);

  // AI state
  const [aiAction,  setAiAction]  = useState('generate');
  const [aiPrompt,  setAiPrompt]  = useState('');
  const [aiRuleID,  setAiRuleID]  = useState<number | null>(null);
  const [aiResult,  setAiResult]  = useState<any>(null);
  const [aiLoading, setAiLoading] = useState(false);

  // Bulk state
  const [bulkAction,  setBulkAction]  = useState('enable');
  const [bulkLoading, setBulkLoading] = useState(false);

  // Scheduling
  const [scheduling, setScheduling] = useState(false);

  const [toast, setToast] = useState<string | null>(null);
  const loaded = useRef<Record<string, boolean>>({});

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3500); };
  const agentName = (id: number) => agents.find(a => a.id === id)?.hostname || `Agent #${id}`;

  // ── Base load ────────────────────────────────────────────────────────────

  const loadBase = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    const [rr, mr, sr] = await Promise.allSettled([
      yaraAPI.getAll(), yaraAPI.getMatches(), schedulerAPI.getAll(),
    ]);
    if (rr.status === 'fulfilled') setRules(rr.value.data || []);
    if (mr.status === 'fulfilled') setMatches(mr.value.data || []);
    if (sr.status === 'fulfilled') {
      const found = (sr.value.data || []).find((t: ScheduledTaskLite) => t.task_type === 'scan_yara');
      setScheduledScan(found || null);
    }
    setLoading(false);
    setRefreshing(false);
  }, []);

  useEffect(() => { loadBase(); }, [loadBase]);
  useEffect(() => { agentsAPI.getAll().then(r => setAgents(r.data || [])).catch(() => {}); }, []);

  useEffect(() => {
    if (loaded.current[tab]) return;
    loaded.current[tab] = true;
    if (tab === 'dashboard')  yaraAPI.dashboard().then(r => setDash(r.data));
    if (tab === 'analytics')  yaraAPI.analytics().then(r => setAnalytics(r.data));
    if (tab === 'categories') yaraAPI.categories().then(r => setCategories(r.data?.categories ?? null));
    if (tab === 'relationships') yaraAPI.relationships().then(r => setRelData(r.data));
  }, [tab]);

  // ── Derived ──────────────────────────────────────────────────────────────

  const filteredRules = useMemo(() =>
    rules.filter(r =>
      !search ||
      r.name.toLowerCase().includes(search.toLowerCase()) ||
      r.description.toLowerCase().includes(search.toLowerCase())
    ), [rules, search]);

  const filteredMatches = useMemo(() =>
    matches.filter(m => !matchSevFilter || m.severity === matchSevFilter),
    [matches, matchSevFilter]);

  // ── CRUD ─────────────────────────────────────────────────────────────────

  const saveRule = async () => {
    if (!form.name.trim() || !form.rule_content.trim()) return;
    setSaving(true);
    try {
      if (editMode === 'create') {
        await yaraAPI.create(form);
        notify('YARA rule created');
        setForm({ ...emptyRule });
      } else {
        await yaraAPI.update(editTarget!.id, form);
        notify('Rule updated');
        setEditMode('create'); setEditTarget(null);
      }
      loaded.current = {};
      loadBase();
    } catch { notify('Save failed'); }
    finally { setSaving(false); }
  };

  const saveModalEdit = async () => {
    if (!modalEdit) return;
    setModalSaving(true);
    try {
      await yaraAPI.update(modalEdit.id, modalForm);
      notify('Rule updated');
      setModalEdit(null);
      loaded.current = {};
      loadBase();
    } catch { notify('Update failed'); }
    finally { setModalSaving(false); }
  };

  const delRule = async (id: number) => {
    try { await yaraAPI.delete(id); setRules(p => p.filter(r => r.id !== id)); setSelected(s => { const n = new Set(s); n.delete(id); return n; }); notify('Rule deleted'); }
    catch { notify('Delete failed'); }
  };

  const toggleRule = async (r: YaraRule) => {
    try {
      r.enabled ? await yaraAPI.disable(r.id) : await yaraAPI.enable(r.id);
      setRules(p => p.map(x => x.id === r.id ? { ...x, enabled: !x.enabled } : x));
    } catch { notify('Toggle failed'); }
  };

  // ── Import / export ──────────────────────────────────────────────────────

  const handleImport = async (files: FileList) => {
    const fd = new FormData();
    Array.from(files).forEach(f => fd.append('rules', f));
    try { const r = await yaraAPI.import(fd); notify(r.data?.message || 'Imported'); loaded.current = {}; loadBase(); }
    catch { notify('Import failed'); }
  };

  const exportRules = async (format: 'yar' | 'json', all = false) => {
    try {
      const res = await yaraAPI.export(format, selected.size > 0 ? Array.from(selected) : [], all);
      const content = typeof res.data === 'string' ? res.data : JSON.stringify(res.data, null, 2);
      const blob = new Blob([content], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `yara_rules.${format}`; a.click();
      URL.revokeObjectURL(url);
    } catch { notify('Export failed'); }
  };

  // ── Scheduling ───────────────────────────────────────────────────────────

  const enablePeriodicScan = async () => {
    setScheduling(true);
    try {
      const r = await schedulerAPI.create({ name: 'Periodic YARA Scan', task_type: 'scan_yara', cron_expr: '0 */6 * * *', payload: {} });
      setScheduledScan(r.data);
      notify('Periodic scan enabled — runs every 6 hours');
    } catch { notify('Failed to schedule'); }
    finally { setScheduling(false); }
  };

  // ── AI ───────────────────────────────────────────────────────────────────

  const runAI = async () => {
    setAiLoading(true); setAiResult(null);
    try {
      const rule = aiRuleID ? rules.find(r => r.id === aiRuleID) : null;
      const res = await yaraAPI.ai({
        action: aiAction,
        rule_id: aiRuleID ?? 0,
        rule_content: rule?.rule_content ?? '',
        prompt: aiPrompt,
      });
      setAiResult(res.data);
    } catch { notify('AI request failed'); }
    finally { setAiLoading(false); }
  };

  // ── Bulk ─────────────────────────────────────────────────────────────────

  const runBulk = async () => {
    if (selected.size === 0) { notify('Select rules first'); return; }
    setBulkLoading(true);
    try {
      const res = await yaraAPI.bulk(bulkAction, Array.from(selected));
      notify(`${res.data.affected} rules ${bulkAction}d`);
      setSelected(new Set());
      loaded.current = {};
      loadBase();
    } catch { notify('Bulk action failed'); }
    finally { setBulkLoading(false); }
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // RENDER
  // ═══════════════════════════════════════════════════════════════════════════

  return (
    <RootLayout
      title="YARA Rules"
      subtitle={`${rules.length} rules · ${rules.filter(r => r.enabled).length} active · ${matches.length} matches`}
      onRefresh={() => { loaded.current = {}; loadBase(true); }}
      refreshing={refreshing}
      actions={
        <div className="flex items-center gap-2">
          {scheduledScan ? (
            <a href="/scheduled-tasks" className="g-btn g-btn-ghost text-xs">
              <Clock className="h-3.5 w-3.5" style={{ color: scheduledScan.enabled ? 'var(--green)' : 'var(--text-3)' }} />
              Periodic scan {scheduledScan.enabled ? 'active' : 'paused'}
            </a>
          ) : (
            <button onClick={enablePeriodicScan} disabled={scheduling} className="g-btn g-btn-ghost text-xs">
              <Clock className="h-3.5 w-3.5" />{scheduling ? 'Enabling…' : 'Schedule Scan'}
            </button>
          )}
          <label className="g-btn g-btn-ghost text-xs cursor-pointer">
            <Upload className="h-3.5 w-3.5" /> Import .yar
            <input type="file" multiple accept=".yar,.yara" className="hidden"
              onChange={e => { handleImport(e.target.files!); e.target.value = ''; }} />
          </label>
          <button onClick={() => { setForm({ ...emptyRule }); setEditMode('create'); setEditTarget(null); setTab('editor'); }}
            className="g-btn g-btn-primary text-xs">
            <Plus className="h-3.5 w-3.5" /> New Rule
          </button>
        </div>
      }>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)', minWidth: 200 }}>{toast}</div>
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
              {t.id === 'matches' && matches.length > 0 && (
                <span className="text-[9px] rounded px-1" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>{matches.length}</span>
              )}
            </button>
          );
        })}
      </div>

      {/* ═══ DASHBOARD ═══ */}
      {tab === 'dashboard' && (
        <div className="space-y-5">
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
            <KPICard label="Total Rules" value={dash?.total ?? rules.length} />
            <KPICard label="Enabled" value={dash?.enabled ?? rules.filter(r => r.enabled).length} color="var(--green)" />
            <KPICard label="Disabled" value={dash?.disabled ?? rules.filter(r => !r.enabled).length} color="var(--text-3)" />
            <KPICard label="Matches Today" value={dash?.matches_today ?? '—'} color="var(--orange)" sub="24h" />
            <KPICard label="Matches 7d" value={dash?.matches_week ?? '—'} color="var(--accent)" />
            <KPICard label="Total Matches" value={dash?.matches_total ?? matches.length} color="var(--accent)" />
            <KPICard label="Files Detected" value={dash?.files_detected ?? '—'} color="var(--yellow)" sub="7d" />
            <KPICard label="Agents" value={dash?.agents_triggered ?? '—'} color="var(--blue)" sub="triggered 7d" />
          </div>

          {dash && (
            <div className="grid grid-cols-3 gap-4">
              {/* Severity breakdown */}
              <div className="g-card p-4">
                <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Severity (7d)</p>
                {dash.sev_breakdown.length === 0
                  ? <p className="text-xs" style={{ color: 'var(--text-3)' }}>No matches yet</p>
                  : <div className="space-y-2">
                    {dash.sev_breakdown.map(s => (
                      <div key={s.severity}>
                        <div className="flex justify-between text-[10px] mb-0.5">
                          <span style={{ color: SEV_COLOR[s.severity] ?? 'var(--text-2)' }} className="capitalize">{s.severity}</span>
                          <span style={{ color: 'var(--text-2)' }}>{s.count}</span>
                        </div>
                        <MiniBar value={s.count} max={dash.sev_breakdown[0]?.count ?? 1} color={SEV_COLOR[s.severity] ?? 'var(--accent)'} />
                      </div>
                    ))}
                  </div>}
              </div>

              {/* Trend */}
              <div className="g-card p-4">
                <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Match Trend (14d)</p>
                <SparkTrend trend={dash.trend} />
                <p className="text-[10px] mt-2" style={{ color: 'var(--text-3)' }}>{dash.matches_today} matches in last 24h</p>
              </div>

              {/* Top rules */}
              <div className="g-card p-4">
                <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Top Firing Rules (7d)</p>
                {dash.top_rules.length === 0
                  ? <p className="text-xs" style={{ color: 'var(--text-3)' }}>No matches yet</p>
                  : <div className="space-y-2">
                    {dash.top_rules.slice(0, 6).map(r => (
                      <div key={r.rule_name} className="flex items-center gap-2">
                        <SevBadge sev={r.severity} />
                        <span className="flex-1 text-[10px] font-mono truncate" style={{ color: 'var(--text-1)' }}>{r.rule_name}</span>
                        <span className="text-[10px] font-mono shrink-0" style={{ color: 'var(--accent)' }}>{r.matches}</span>
                      </div>
                    ))}
                  </div>}
              </div>
            </div>
          )}

          {/* Recent matches */}
          {dash?.recent_matches?.length ? (
            <div className="g-card p-4">
              <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Recent Detections</p>
              <div className="g-table">
                <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '90px 1fr 1fr 90px' }}>
                  <span>Severity</span><span>Rule</span><span>File</span><span>When</span>
                </div>
                {dash.recent_matches.map((m, i) => (
                  <div key={i} className="g-tr grid gap-3 items-center px-4" style={{ gridTemplateColumns: '90px 1fr 1fr 90px' }}>
                    <SevBadge sev={m.severity} />
                    <span className="text-xs font-mono" style={{ color: 'var(--accent)' }}>{m.rule_name}</span>
                    <span className="text-[10px] font-mono truncate" style={{ color: 'var(--text-2)' }}>{m.file_path}</span>
                    <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(m.created_at)}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          {!dash && <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading dashboard…</div>}
        </div>
      )}

      {/* ═══ LIBRARY ═══ */}
      {tab === 'library' && (
        <div className="space-y-4">
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 min-w-[200px] max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
              <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search rules…" className="g-input pl-9" />
            </div>
            {selected.size > 0 && (
              <span className="text-xs rounded-lg px-2 py-1" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>
                {selected.size} selected
              </span>
            )}
            <div className="ml-auto flex gap-1">
              <input type="checkbox" checked={selected.size === rules.length && rules.length > 0}
                onChange={e => setSelected(e.target.checked ? new Set(rules.map(r => r.id)) : new Set())}
                className="h-3.5 w-3.5" title="Select all" />
            </div>
          </div>

          {loading ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          ) : filteredRules.length === 0 ? (
            <div className="py-16 text-center">
              <Code2 className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>No YARA rules. Import a .yar file or create one.</p>
            </div>
          ) : (
            <div className="g-table">
              <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '24px 1fr 200px 80px 80px' }}>
                <span />
                <span>Name / Description</span>
                <span>Rule Preview</span>
                <span>Status</span>
                <span className="text-right">Actions</span>
              </div>
              {filteredRules.map(r => (
                <div key={r.id} className={`g-tr grid gap-3 items-center px-4 ${!r.enabled ? 'opacity-50' : ''}`}
                  style={{ gridTemplateColumns: '24px 1fr 200px 80px 80px' }}>
                  <input type="checkbox" checked={selected.has(r.id)}
                    onChange={e => setSelected(s => { const n = new Set(s); e.target.checked ? n.add(r.id) : n.delete(r.id); return n; })}
                    className="h-3.5 w-3.5" />
                  <div>
                    <div className="flex items-center gap-1.5">
                      <p className="text-xs font-semibold font-mono" style={{ color: 'var(--text-1)' }}>{r.name}</p>
                      <button onClick={() => toggleRule(r)}>
                        {r.enabled
                          ? <ToggleRight className="h-4 w-4 shrink-0" style={{ color: 'var(--green)' }} />
                          : <ToggleLeft className="h-4 w-4 shrink-0" style={{ color: 'var(--text-3)' }} />}
                      </button>
                    </div>
                    <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>{r.description || 'No description'}</p>
                    <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>Added {timeAgo(r.created_at)}</p>
                  </div>
                  <pre className="text-[9px] font-mono rounded p-1.5 truncate overflow-hidden"
                    style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-3)', maxHeight: 52 }}>
                    {r.rule_content.slice(0, 150)}
                  </pre>
                  <span className="text-[10px]" style={{ color: r.enabled ? 'var(--green)' : 'var(--text-3)' }}>
                    {r.enabled ? 'Active' : 'Disabled'}
                  </span>
                  <div className="flex items-center justify-end gap-1">
                    <button onClick={() => { setModalForm({ name: r.name, description: r.description, rule_content: r.rule_content, enabled: r.enabled }); setModalEdit(r); }}
                      title="Edit" className="p-1 rounded" style={{ color: 'var(--text-3)' }}><Edit2 className="h-3.5 w-3.5" /></button>
                    <button onClick={() => delRule(r.id)} title="Delete" className="p-1 rounded" style={{ color: 'var(--text-3)' }}
                      onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--red)'}
                      onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}><Trash2 className="h-3.5 w-3.5" /></button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ═══ EDITOR ═══ */}
      {tab === 'editor' && (
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="flex gap-1">
              <button onClick={() => { setForm({ ...emptyRule }); setEditMode('create'); setEditTarget(null); }}
                className="px-3 py-1.5 text-xs rounded-lg transition-all"
                style={{
                  background: editMode === 'create' ? 'var(--accent-glow)' : 'var(--glass-bg)',
                  border: `1px solid ${editMode === 'create' ? 'var(--accent-border)' : 'var(--border)'}`,
                  color: editMode === 'create' ? 'var(--accent)' : 'var(--text-2)',
                }}>New Rule</button>
            </div>
            {rules.length > 0 && (
              <div className="ml-auto flex items-center gap-2">
                <span className="text-xs" style={{ color: 'var(--text-3)' }}>Load rule:</span>
                <select className="g-select text-xs" style={{ width: 220 }} value={editTarget?.id ?? ''}
                  onChange={e => {
                    const r = rules.find(x => x.id === Number(e.target.value));
                    if (r) { setForm({ name: r.name, description: r.description, rule_content: r.rule_content, enabled: r.enabled }); setEditMode('edit'); setEditTarget(r); }
                  }}>
                  <option value="">— select rule to edit —</option>
                  {rules.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
                </select>
              </div>
            )}
          </div>

          <div className="grid grid-cols-2 gap-5">
            {/* Left: metadata + rule textarea */}
            <div className="space-y-3">
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Rule Name *</label>
                <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  placeholder="DetectMimikatz" className="g-input mono" />
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Description</label>
                <input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  placeholder="What this rule detects" className="g-input" />
              </div>
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-xs" style={{ color: 'var(--text-3)' }}>Rule Content (.yar syntax) *</label>
                  <button onClick={() => navigator.clipboard.writeText(form.rule_content).catch(() => {})}
                    className="g-btn g-btn-ghost text-[10px]" style={{ padding: '2px 8px' }}>
                    <Copy className="h-3 w-3" /> Copy
                  </button>
                </div>
                <textarea value={form.rule_content} onChange={e => setForm(f => ({ ...f, rule_content: e.target.value }))}
                  rows={18} className="g-input mono resize-none w-full"
                  style={{ fontSize: 11, lineHeight: 1.7, fontFamily: 'monospace' }} />
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => setForm(f => ({ ...f, enabled: !f.enabled }))}>
                  {form.enabled
                    ? <ToggleRight className="h-5 w-5" style={{ color: 'var(--green)' }} />
                    : <ToggleLeft className="h-5 w-5" style={{ color: 'var(--text-3)' }} />}
                </button>
                <span className="text-xs" style={{ color: 'var(--text-2)' }}>{form.enabled ? 'Enabled' : 'Disabled'}</span>
              </div>
              <div className="flex gap-3">
                <button onClick={() => { setForm({ ...emptyRule }); setEditMode('create'); setEditTarget(null); }} className="g-btn g-btn-ghost flex-1 justify-center">Reset</button>
                <button onClick={saveRule} disabled={saving || !form.name.trim() || !form.rule_content.trim()}
                  className="g-btn g-btn-primary flex-1 justify-center">
                  {saving ? 'Saving…' : editMode === 'create' ? 'Create Rule' : 'Update Rule'}
                </button>
              </div>
            </div>

            {/* Right: syntax-highlighted preview */}
            <div className="flex flex-col gap-3">
              <span className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-3)' }}>Syntax Preview</span>
              <YaraHighlight content={form.rule_content} />

              {/* Quick templates */}
              <div>
                <p className="text-[10px] uppercase tracking-wider font-semibold mb-2" style={{ color: 'var(--text-3)' }}>Quick Templates</p>
                <div className="grid grid-cols-2 gap-1.5">
                  {[
                    { label: 'Ransomware', content: `rule RansomwareTemplate\n{\n    meta:\n        description = "Detects ransomware patterns"\n        severity    = "critical"\n\n    strings:\n        $ext1 = ".locked" ascii\n        $ext2 = ".encrypted" ascii\n        $note = "README_DECRYPT" ascii nocase\n        $vss  = "vssadmin delete shadows" ascii nocase\n\n    condition:\n        2 of them\n}` },
                    { label: 'Webshell', content: `rule WebshellTemplate\n{\n    meta:\n        description = "Detects common web shells"\n        severity    = "high"\n\n    strings:\n        $php1 = "eval(base64_decode(" ascii nocase\n        $php2 = "eval(gzinflate(" ascii nocase\n        $php3 = "system($_GET" ascii nocase\n        $asp1 = "<%eval request(" ascii nocase\n\n    condition:\n        any of them\n}` },
                    { label: 'PE Packed', content: `rule PackedExecutable\n{\n    meta:\n        description = "Detects packed PE files"\n        severity    = "medium"\n\n    strings:\n        $upx  = { 55 50 58 21 }\n        $mz   = { 4D 5A }\n        $ep   = "EP0" ascii\n\n    condition:\n        $mz at 0 and ($upx or $ep)\n}` },
                    { label: 'Macro', content: `rule MaliciousMacro\n{\n    meta:\n        description = "Detects Office macro with suspicious calls"\n        severity    = "high"\n\n    strings:\n        $auto1 = "AutoOpen" ascii\n        $auto2 = "Document_Open" ascii\n        $shell = "Shell(" ascii\n        $wscr  = "WScript.Shell" ascii\n        $http  = "http" ascii nocase\n\n    condition:\n        ($auto1 or $auto2) and any of ($shell, $wscr, $http)\n}` },
                  ].map(tmpl => (
                    <button key={tmpl.label} onClick={() => setForm(f => ({ ...f, name: f.name || tmpl.label, rule_content: tmpl.content }))}
                      className="px-2 py-1.5 text-[10px] rounded-lg text-left transition-all"
                      style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                      {tmpl.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ═══ MATCHES ═══ */}
      {tab === 'matches' && (
        <div className="space-y-4">
          <div className="flex items-center gap-2 flex-wrap">
            {['', 'critical', 'high', 'medium', 'low'].map(s => (
              <button key={s || 'all'} onClick={() => setMatchSevFilter(s)}
                className="rounded-lg px-3 py-1.5 text-xs font-medium capitalize transition-all"
                style={{
                  background: matchSevFilter === s ? 'var(--accent-glow)' : 'var(--glass-bg)',
                  border: `1px solid ${matchSevFilter === s ? 'var(--accent-border)' : 'var(--border)'}`,
                  color: matchSevFilter === s ? 'var(--accent)' : 'var(--text-2)',
                }}>
                {s || 'All'} ({s ? matches.filter(m => m.severity === s).length : matches.length})
              </button>
            ))}
          </div>

          <div className="g-table">
            <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '90px 70px 1fr 1fr 100px 20px' }}>
              <span>Agent</span><span>Severity</span><span>Rule</span><span>File Path</span><span>Detected</span><span />
            </div>
            {loading ? (
              <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
            ) : filteredMatches.length === 0 ? (
              <div className="py-16 text-center">
                <FileWarning className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
                <p className="text-sm" style={{ color: 'var(--text-2)' }}>
                  {matches.length === 0
                    ? 'No YARA matches yet. Enable periodic scanning or dispatch a scan task from an agent.'
                    : 'No matches for current filter.'}
                </p>
              </div>
            ) : filteredMatches.map(m => {
              let parsedStrings: MatchedString[] = [];
              try { parsedStrings = JSON.parse(m.matched_strings || '[]'); } catch { }
              const expanded = expandedId === m.id;
              return (
                <div key={m.id}>
                  <div className="g-tr grid gap-3 items-center px-4 cursor-pointer"
                    onClick={() => setExpandedId(expanded ? null : m.id)}
                    style={{ gridTemplateColumns: '90px 70px 1fr 1fr 100px 20px' }}>
                    <span className="text-xs mono" style={{ color: 'var(--accent)' }}>{agentName(m.agent_id)}</span>
                    <span className={sevClass(m.severity)}>{m.severity}</span>
                    <span className="mono text-xs font-medium" style={{ color: 'var(--accent)' }}>{m.rule_name}</span>
                    <span className="mono text-xs truncate" style={{ color: 'var(--text-1)' }}>{m.file_path}</span>
                    <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{timeAgo(m.created_at)}</span>
                    {expanded ? <ChevronUp className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} /> : <ChevronDown className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />}
                  </div>
                  {expanded && (
                    <div className="px-4 pb-3 pt-2 space-y-2" style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-0)' }}>
                      {m.description && <p className="text-xs" style={{ color: 'var(--text-2)' }}>{m.description}</p>}
                      {m.file_hash && (
                        <p className="text-[10px] mono flex items-center gap-1.5" style={{ color: 'var(--text-3)' }}>
                          <Hash className="h-3 w-3" /> SHA256: {m.file_hash}
                          <button onClick={() => navigator.clipboard.writeText(m.file_hash).catch(() => {})} className="ml-1"><Copy className="h-3 w-3" /></button>
                        </p>
                      )}
                      {parsedStrings.length > 0 && (
                        <div>
                          <p className="text-[10px] font-bold uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>Matched Strings</p>
                          {parsedStrings.map((s, i) => (
                            <p key={i} className="text-[10px] mono" style={{ color: 'var(--text-2)' }}>
                              <span style={{ color: 'var(--accent)' }}>{s.identifier}</span>
                              {' @ '}<span style={{ color: 'var(--yellow)' }}>{s.offset}</span>
                              {': '}<span style={{ color: 'var(--text-1)' }}>{s.data}</span>
                            </p>
                          ))}
                        </div>
                      )}
                      <div className="flex gap-2 mt-2">
                        <button className="g-btn g-btn-ghost text-[10px]" style={{ padding: '2px 8px' }}>
                          <AlertTriangle className="h-3 w-3" /> Create Alert
                        </button>
                        <button className="g-btn g-btn-ghost text-[10px]" style={{ padding: '2px 8px' }}>
                          <Shield className="h-3 w-3" /> Quarantine File
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
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
                <div className="g-card p-4">
                  <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Daily Matches (30d)</p>
                  <SparkTrend trend={analytics.daily.map((d: any) => ({ date: d.date, count: d.count }))} />
                </div>
                <div className="g-card p-4">
                  <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Top Agents (7d)</p>
                  <div className="space-y-2">
                    {analytics.top_agents.slice(0, 6).map((a: any) => (
                      <div key={a.agent_id}>
                        <div className="flex justify-between text-[10px] mb-0.5">
                          <span style={{ color: 'var(--text-2)' }}>{a.agent_name}</span>
                          <span style={{ color: 'var(--accent)' }}>{a.matches}</span>
                        </div>
                        <MiniBar value={a.matches} max={analytics.top_agents[0]?.matches ?? 1} />
                      </div>
                    ))}
                    {analytics.top_agents.length === 0 && <p className="text-xs" style={{ color: 'var(--text-3)' }}>No matches in last 7 days</p>}
                  </div>
                </div>
              </div>
              <div className="g-card p-4">
                <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Rule Hit Statistics</p>
                <div className="g-table">
                  <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 70px 70px 70px 120px' }}>
                    <span>Rule Name</span><span>24h</span><span>7d</span><span>Total</span><span>Last Match</span>
                  </div>
                  {analytics.rules.slice(0, 50).map((r: RuleStat) => (
                    <div key={r.rule_name} className="g-tr grid gap-3 items-center px-4" style={{ gridTemplateColumns: '1fr 70px 70px 70px 120px' }}>
                      <span className="text-xs font-mono" style={{ color: 'var(--text-1)' }}>{r.rule_name}</span>
                      <span className="text-xs font-mono text-center" style={{ color: r.last_24h ? 'var(--orange)' : 'var(--text-3)' }}>{r.last_24h}</span>
                      <span className="text-xs font-mono text-center" style={{ color: r.last_7d ? 'var(--accent)' : 'var(--text-3)' }}>{r.last_7d}</span>
                      <span className="text-xs font-mono text-center" style={{ color: r.total ? 'var(--green)' : 'var(--text-3)' }}>{r.total}</span>
                      <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{r.last_match ? timeAgo(r.last_match) : '—'}</span>
                    </div>
                  ))}
                  {analytics.rules.length === 0 && (
                    <div className="py-8 text-center text-xs" style={{ color: 'var(--text-3)' }}>No match data yet</div>
                  )}
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
          ) : categories.length === 0 ? (
            <div className="py-16 text-center text-sm" style={{ color: 'var(--text-3)' }}>No rules to categorize</div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {categories.sort((a, b) => b.total - a.total).map(cat => (
                <div key={cat.category} className="g-card p-4">
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-sm font-semibold capitalize" style={{ color: 'var(--text-1)' }}>{cat.category}</p>
                    <div className="flex gap-1">
                      <span className="text-[10px] rounded px-1.5 py-0.5" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>{cat.total}</span>
                      <span className="text-[10px] rounded px-1.5 py-0.5" style={{ background: 'rgba(52,211,153,0.1)', color: 'var(--green)' }}>{cat.enabled} on</span>
                    </div>
                  </div>
                  <div className="space-y-1">
                    {cat.rules.slice(0, 5).map(r => (
                      <div key={r.id} className="flex items-center gap-2">
                        <div className="h-1.5 w-1.5 rounded-full shrink-0" style={{ background: r.enabled ? 'var(--green)' : 'var(--text-3)' }} />
                        <span className="text-[10px] font-mono truncate" style={{ color: 'var(--text-2)' }}>{r.name}</span>
                      </div>
                    ))}
                    {cat.rules.length > 5 && (
                      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>+{cat.rules.length - 5} more</p>
                    )}
                  </div>
                </div>
              ))}
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
              <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>AI YARA Rule Assistant</p>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Action</label>
                <select value={aiAction} onChange={e => setAiAction(e.target.value)} className="g-select">
                  {AI_ACTIONS.map(a => <option key={a.id} value={a.id}>{a.label}</option>)}
                </select>
                <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                  {AI_ACTIONS.find(a => a.id === aiAction)?.desc}
                </p>
              </div>
              {aiAction !== 'generate' && (
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Select Rule (optional)</label>
                  <select className="g-select" value={aiRuleID ?? ''} onChange={e => setAiRuleID(Number(e.target.value) || null)}>
                    <option value="">— select rule —</option>
                    {rules.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
                  </select>
                </div>
              )}
            </div>

            {aiAction === 'generate' && (
              <div className="mb-4">
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Detection Requirement</label>
                <textarea value={aiPrompt} onChange={e => setAiPrompt(e.target.value)} rows={3}
                  placeholder="Detect Mimikatz credential dumping tool by looking for its unique strings and process behaviors…"
                  className="g-input w-full resize-none" style={{ fontFamily: 'inherit' }} />
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
                <button onClick={() => navigator.clipboard.writeText(typeof aiResult === 'object' ? JSON.stringify(aiResult, null, 2) : String(aiResult)).catch(() => {})}
                  className="g-btn g-btn-ghost text-[10px]" style={{ padding: '2px 8px' }}>
                  <Copy className="h-3 w-3" /> Copy
                </button>
              </div>

              {aiAction === 'generate' && aiResult.rule && (
                <div className="space-y-3">
                  <YaraHighlight content={aiResult.rule} />
                  <div className="flex gap-2">
                    <button onClick={() => {
                      const nameMatch = (aiResult.rule as string).match(/^rule\s+(\w+)/m);
                      setForm({ ...emptyRule, name: nameMatch?.[1] ?? 'AIGeneratedRule', rule_content: aiResult.rule });
                      setEditMode('create'); setEditTarget(null); setTab('editor');
                      notify('Loaded into editor');
                    }} className="g-btn g-btn-primary text-xs">
                      <Code2 className="h-3.5 w-3.5" /> Load into Editor
                    </button>
                  </div>
                </div>
              )}

              {aiAction === 'explain' && (
                <div className="space-y-3">
                  {(['summary', 'threat', 'strings_explained', 'condition_explained', 'false_positives', 'improvements'] as const).map(k => {
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

              {['optimize', 'suggest_strings', 'fp_analysis', 'generate_metadata'].includes(aiAction) && (
                <pre className="p-3 text-[11px] font-mono rounded-xl overflow-auto"
                  style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-2)', maxHeight: 500 }}>
                  {JSON.stringify(aiResult, null, 2)}
                </pre>
              )}
            </div>
          )}
        </div>
      )}

      {/* ═══ BULK / EXPORT ═══ */}
      {tab === 'bulk' && (
        <div className="space-y-4">
          {/* Bulk ops */}
          <div className="g-card p-5">
            <div className="flex items-center gap-2 mb-4">
              <CheckSquare className="h-4 w-4" style={{ color: 'var(--accent)' }} />
              <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Bulk Operations</p>
              {selected.size > 0 && (
                <span className="text-[10px] rounded px-1.5 py-0.5" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>
                  {selected.size} selected
                </span>
              )}
            </div>

            <div className="grid grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Action</label>
                <select value={bulkAction} onChange={e => setBulkAction(e.target.value)} className="g-select">
                  <option value="enable">Enable selected</option>
                  <option value="disable">Disable selected</option>
                  <option value="delete">Delete selected</option>
                </select>
              </div>
            </div>

            <div className="flex items-center gap-3 mb-4">
              <button onClick={runBulk} disabled={bulkLoading || selected.size === 0} className="g-btn g-btn-primary text-xs">
                <Zap className="h-3.5 w-3.5" />{bulkLoading ? 'Running…' : `Apply to ${selected.size || 0} rules`}
              </button>
            </div>

            <div className="flex flex-wrap gap-2">
              <p className="text-xs w-full mb-1" style={{ color: 'var(--text-3)' }}>Quick selection:</p>
              {[
                { label: 'All rules', fn: () => setSelected(new Set(rules.map(r => r.id))) },
                { label: 'All enabled', fn: () => setSelected(new Set(rules.filter(r => r.enabled).map(r => r.id))) },
                { label: 'All disabled', fn: () => setSelected(new Set(rules.filter(r => !r.enabled).map(r => r.id))) },
                { label: 'Clear', fn: () => setSelected(new Set()) },
              ].map(h => <button key={h.label} onClick={h.fn} className="g-btn g-btn-ghost text-xs">{h.label}</button>)}
            </div>
          </div>

          {/* Export */}
          <div className="g-card p-5">
            <div className="flex items-center gap-2 mb-4">
              <Download className="h-4 w-4" style={{ color: 'var(--accent)' }} />
              <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Export Rules</p>
            </div>
            <p className="text-xs mb-4" style={{ color: 'var(--text-3)' }}>
              Export as a combined .yar file or JSON. Select rules in Library to export a subset.
              {selected.size > 0 && <> <span style={{ color: 'var(--accent)' }}>{selected.size} selected.</span></>}
            </p>
            <div className="flex flex-wrap gap-3">
              <button onClick={() => exportRules('yar')} className="g-btn g-btn-primary text-xs">
                <Download className="h-3.5 w-3.5" /> Export .yar {selected.size > 0 ? `(${selected.size} rules)` : '(all enabled)'}
              </button>
              <button onClick={() => exportRules('yar', true)} className="g-btn g-btn-ghost text-xs">
                <Download className="h-3.5 w-3.5" /> Export all rules .yar
              </button>
              <button onClick={() => exportRules('json')} className="g-btn g-btn-ghost text-xs">
                <Download className="h-3.5 w-3.5" /> Export JSON
              </button>
            </div>
          </div>

          {/* Import */}
          <div className="g-card p-5">
            <div className="flex items-center gap-2 mb-3">
              <Upload className="h-4 w-4" style={{ color: 'var(--accent)' }} />
              <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Import Rules</p>
            </div>
            <p className="text-xs mb-4" style={{ color: 'var(--text-3)' }}>
              Import .yar / .yara files. Multiple rules per file are supported.
            </p>
            <label className="g-btn g-btn-ghost text-xs cursor-pointer">
              <Upload className="h-3.5 w-3.5" /> Choose .yar Files
              <input type="file" multiple accept=".yar,.yara" className="hidden"
                onChange={e => { handleImport(e.target.files!); e.target.value = ''; }} />
            </label>

            <div className="mt-4 pt-3" style={{ borderTop: '1px solid var(--border)' }}>
              <p className="text-[10px] uppercase tracking-wider font-semibold mb-2" style={{ color: 'var(--text-3)' }}>Community Rule Sources</p>
              <div className="space-y-2">
                {[
                  { name: 'Awesome YARA', desc: 'Curated list of YARA rules from the community', url: 'https://github.com/InQuest/awesome-yara' },
                  { name: 'Yara-Rules / rules', desc: 'Repository of open-source YARA rules', url: 'https://github.com/Yara-Rules/rules' },
                  { name: 'Neo23x0 / signature-base', desc: 'Florian Roth generic IOC and YARA rules', url: 'https://github.com/Neo23x0/signature-base' },
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
        </div>
      )}

      {/* ── Quick Edit Modal (from library) ── */}
      {modalEdit && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setModalEdit(null)}>
          <div className="g-modal" style={{ maxWidth: 660 }}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Edit: {modalEdit.name}</h2>
              <button onClick={() => setModalEdit(null)} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>
            <div className="p-5 space-y-3 overflow-y-auto" style={{ maxHeight: '80vh' }}>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Name *</label>
                <input value={modalForm.name} onChange={e => setModalForm(f => ({ ...f, name: e.target.value }))} className="g-input mono" />
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Description</label>
                <input value={modalForm.description} onChange={e => setModalForm(f => ({ ...f, description: e.target.value }))} className="g-input" />
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Rule Content *</label>
                <textarea value={modalForm.rule_content} onChange={e => setModalForm(f => ({ ...f, rule_content: e.target.value }))}
                  rows={14} className="g-input mono resize-none w-full" style={{ fontSize: 11, lineHeight: 1.6 }} />
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => setModalForm(f => ({ ...f, enabled: !f.enabled }))}>
                  {modalForm.enabled
                    ? <ToggleRight className="h-5 w-5" style={{ color: 'var(--green)' }} />
                    : <ToggleLeft className="h-5 w-5" style={{ color: 'var(--text-3)' }} />}
                </button>
                <span className="text-xs" style={{ color: 'var(--text-2)' }}>{modalForm.enabled ? 'Enabled' : 'Disabled'}</span>
              </div>
            </div>
            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => setModalEdit(null)} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={saveModalEdit} disabled={modalSaving || !modalForm.name.trim()} className="g-btn g-btn-primary flex-1 justify-center">
                {modalSaving ? 'Saving…' : 'Update Rule'}
              </button>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
