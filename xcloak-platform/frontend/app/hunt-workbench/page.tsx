'use client';

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { huntWorkbenchAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import {
  Search, Plus, Play, Trash2, Clock, CheckCircle, AlertCircle,
  ChevronDown, ChevronRight, BookOpen, Target, Brain, Shield,
  Activity, Grid3X3, FileText, Database, Zap, Users, TrendingUp,
  X, Copy, Download, RefreshCw, Eye, AlertTriangle, Globe,
} from 'lucide-react';

// ── Types ────────────────────────────────────────────────────────────────────

interface HuntTemplate {
  id: number; name: string; description: string; mitre_tactic: string;
  mitre_technique: string; kql_query: string; schedule: string;
  is_active: boolean; created_by: string; created_at: string;
}
interface HuntFinding { log_id: number; agent_id: number; hostname: string; source: string; message: string; timestamp: string; }
interface HuntRun {
  id: number; template_id: number | null; name: string; kql_query: string;
  status: string; hit_count: number; findings: HuntFinding[];
  analyst: string; severity: string; notes: string;
  started_at: string; completed_at: string | null;
}
interface HuntSession {
  id: string; name: string; queryLang: 'kql' | 'nl' | 'sigma' | 'elastic';
  query: string; nlQuery: string; run: HuntRun | null; running: boolean;
}
interface NoteEntry { id: number; run_id: number; content: string; content_type: string; created_by: string; created_at: string; }

// ── Shared display components ─────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = { critical: '#f85149', high: '#fb923c', medium: '#fbbf24', low: '#22c55e', info: '#60a5fa' };

function KPICard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="g-card p-4">
      <p className="text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>{label}</p>
      <p className="text-2xl font-bold" style={{ color: color || 'var(--text-1)' }}>{value}</p>
      {sub && <p className="text-[11px] mt-0.5" style={{ color: 'var(--text-3)' }}>{sub}</p>}
    </div>
  );
}

function SevBadge({ sev }: { sev: string }) {
  return (
    <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-full" style={{ background: `${SEV_COLOR[sev] || '#60a5fa'}22`, color: SEV_COLOR[sev] || '#60a5fa' }}>
      {sev}
    </span>
  );
}

function SparkTrend({ data, key1, key2 }: { data: any[]; key1: string; key2?: string }) {
  if (!data?.length) return null;
  const vals = data.map(d => d[key1] || 0);
  const max = Math.max(...vals, 1);
  return (
    <svg width="100%" height="32" viewBox={`0 0 ${data.length * 12} 32`} preserveAspectRatio="none">
      <polyline
        points={vals.map((v, i) => `${i * 12 + 6},${32 - (v / max) * 28}`).join(' ')}
        fill="none" stroke="var(--accent)" strokeWidth="1.5" strokeLinejoin="round"
      />
    </svg>
  );
}

// ── Existing RunCard (preserved) ─────────────────────────────────────────────

function RunCard({ run, onExpand, expanded, onUpdateNotes }: {
  run: HuntRun; expanded: boolean; onExpand: () => void;
  onUpdateNotes: (id: number, notes: string, severity: string) => void;
}) {
  const [notes, setNotes] = useState(run.notes);
  const [severity, setSeverity] = useState(run.severity || 'medium');
  const [saving, setSaving] = useState(false);
  const save = async () => { setSaving(true); await onUpdateNotes(run.id, notes, severity); setSaving(false); };

  const statusIcon = run.status === 'running'
    ? <Clock className="h-3.5 w-3.5 animate-spin" style={{ color: '#fbbf24' }} />
    : run.status === 'completed'
    ? <CheckCircle className="h-3.5 w-3.5" style={{ color: '#22c55e' }} />
    : <AlertCircle className="h-3.5 w-3.5" style={{ color: '#f85149' }} />;

  return (
    <div className="g-card overflow-hidden">
      <div className="px-4 py-3 flex items-center gap-3 cursor-pointer hover:bg-[var(--glass-bg-2)] transition-colors" onClick={onExpand}>
        {expanded ? <ChevronDown className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} /> : <ChevronRight className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />}
        {statusIcon}
        <span className="text-sm font-medium flex-1 truncate" style={{ color: 'var(--text-1)' }}>{run.name}</span>
        {run.hit_count > 0 && (
          <span className="text-[11px] font-bold px-2 py-0.5 rounded-full" style={{ background: 'rgba(248,81,73,0.15)', color: '#f85149' }}>
            {run.hit_count} hit{run.hit_count > 1 ? 's' : ''}
          </span>
        )}
        <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{timeAgo(run.started_at)}</span>
        {run.analyst && <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)' }}>{run.analyst}</span>}
      </div>
      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t" style={{ borderColor: 'var(--border)' }}>
          <div className="mt-3">
            <p className="text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>Query</p>
            <div className="font-mono text-[11px] px-3 py-2 rounded-lg" style={{ background: 'var(--bg-0)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>{run.kql_query}</div>
          </div>
          {run.hit_count > 0 && (
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: '#f85149' }}>Findings ({run.findings?.length || 0})</p>
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {(run.findings || []).slice(0, 20).map((f, i) => (
                  <div key={i} className="rounded-lg px-3 py-2" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-[10px] font-mono" style={{ color: 'var(--accent)' }}>{f.source}</span>
                      <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{f.timestamp}</span>
                    </div>
                    <p className="text-[11px] truncate" style={{ color: 'var(--text-2)' }}>{f.message}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
          <div className="flex gap-2 items-end">
            <div>
              <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Severity</label>
              <select value={severity} onChange={e => setSeverity(e.target.value)} className="g-select text-xs">
                {['critical','high','medium','low'].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div className="flex-1">
              <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Notes</label>
              <input value={notes} onChange={e => setNotes(e.target.value)} className="g-input text-xs w-full" placeholder="False positive / confirmed / escalated…" />
            </div>
            <button onClick={save} disabled={saving} className="g-btn g-btn-primary text-xs">{saving ? 'Saving…' : 'Save'}</button>
          </div>
        </div>
      )}
    </div>
  );
}

// ── TTP catalog ───────────────────────────────────────────────────────────────

const TTP_CATALOG = [
  { key: 'powershell',  label: 'PowerShell',         mitre: 'T1059.001', tactic: 'Execution',         icon: '⚡', desc: 'Encoded commands, AMSI bypass, download cradles' },
  { key: 'lsass',       label: 'LSASS Dumping',      mitre: 'T1003.001', tactic: 'Credential Access', icon: '🔑', desc: 'Mimikatz, procdump, comsvcs MiniDump' },
  { key: 'lolbins',     label: 'LOLBins',            mitre: 'T1218',     tactic: 'Defense Evasion',   icon: '🦎', desc: 'certutil, mshta, regsvr32, rundll32, BITS' },
  { key: 'injection',   label: 'Process Injection',  mitre: 'T1055',     tactic: 'Defense Evasion',   icon: '💉', desc: 'CreateRemoteThread, VirtualAllocEx, SetThreadContext' },
  { key: 'beaconing',   label: 'C2 Beaconing',       mitre: 'T1071.001', tactic: 'Command & Control', icon: '📡', desc: 'Cobalt Strike, Sliver, Empire — periodic check-ins' },
  { key: 'lateral',     label: 'Lateral Movement',   mitre: 'T1021',     tactic: 'Lateral Movement',  icon: '↔️', desc: 'PsExec, WMIExec, Pass-the-Hash, SMB admin shares' },
  { key: 'ransomware',  label: 'Ransomware',         mitre: 'T1486',     tactic: 'Impact',            icon: '🔒', desc: 'VSS deletion, shadow copy inhibit, .locked extensions' },
  { key: 'persistence', label: 'Persistence',        mitre: 'T1547',     tactic: 'Persistence',       icon: '🪝', desc: 'Run keys, crontab, systemd services, startup folders' },
] as const;

type TTPKEY = typeof TTP_CATALOG[number]['key'];

// ── Builtin quick-launch templates ────────────────────────────────────────────

const BUILTIN_TEMPLATES = [
  { name: 'Suspicious Auth Failures', description: 'High rate of failed logins — potential brute force', mitre_tactic: 'credential_access', mitre_technique: 'T1110', kql_query: 'Failed password', schedule: '' },
  { name: 'Privilege Escalation via Sudo', description: 'Sudo usage outside expected patterns', mitre_tactic: 'privilege_escalation', mitre_technique: 'T1548', kql_query: 'sudo', schedule: '' },
  { name: 'Outbound to Rare Countries', description: 'Connections to unusual geo — possible C2', mitre_tactic: 'command_and_control', mitre_technique: 'T1071', kql_query: 'connection_established', schedule: '' },
  { name: 'Lateral Movement (SMB)', description: 'SMB auth on internal hosts', mitre_tactic: 'lateral_movement', mitre_technique: 'T1021', kql_query: 'smb', schedule: '' },
  { name: 'Process Execution from /tmp', description: 'Unusual process launch from temp dir', mitre_tactic: 'execution', mitre_technique: 'T1059', kql_query: '/tmp/', schedule: '' },
  { name: 'New Cron Jobs Added', description: 'Persistence via cron', mitre_tactic: 'persistence', mitre_technique: 'T1053', kql_query: 'crontab', schedule: '' },
];

// ── Main page ─────────────────────────────────────────────────────────────────

const TABS = [
  { key: 'dashboard',  label: 'Dashboard',    icon: Activity },
  { key: 'workspace',  label: 'Workspace',    icon: Search },
  { key: 'ioc-hunt',   label: 'IOC Hunt',     icon: Target },
  { key: 'ttp-hunt',   label: 'TTP Hunt',     icon: Shield },
  { key: 'templates',  label: 'Templates',    icon: BookOpen },
  { key: 'history',    label: 'History',      icon: Clock },
  { key: 'notebook',   label: 'Notebook',     icon: FileText },
  { key: 'mitre',      label: 'MITRE',        icon: Grid3X3 },
  { key: 'analytics',  label: 'Analytics',    icon: TrendingUp },
] as const;
type TabKey = typeof TABS[number]['key'];

export default function HuntWorkbenchPage() {
  const [tab, setTab] = useState<TabKey>('dashboard');
  const loaded = useRef<Partial<Record<TabKey, boolean>>>({});

  // dashboard / analytics / mitre data
  const [dash, setDash] = useState<any>(null);
  const [analytics, setAnalytics] = useState<any>(null);
  const [mitre, setMitre] = useState<any>(null);

  // templates + runs
  const [templates, setTemplates] = useState<HuntTemplate[]>([]);
  const [runs, setRuns] = useState<HuntRun[]>([]);
  const [expandedRun, setExpandedRun] = useState<number | null>(null);
  const [showCreateTpl, setShowCreateTpl] = useState(false);
  const [newTpl, setNewTpl] = useState({ name: '', description: '', mitre_tactic: '', mitre_technique: '', kql_query: '', schedule: '' });
  const [tplSearch, setTplSearch] = useState('');

  // workspace (multi-tab hunt sessions)
  const [sessions, setSessions] = useState<HuntSession[]>([
    { id: 's1', name: 'Hunt 1', queryLang: 'kql', query: '', nlQuery: '', run: null, running: false },
  ]);
  const [activeSession, setActiveSession] = useState('s1');
  const curSession = useMemo(() => sessions.find(s => s.id === activeSession) || sessions[0], [sessions, activeSession]);
  const [aiGenerating, setAiGenerating] = useState(false);

  // IOC hunt
  const [iocType, setIocType] = useState('ip');
  const [iocValue, setIocValue] = useState('');
  const [iocRange, setIocRange] = useState('24h');
  const [iocResults, setIocResults] = useState<any>(null);
  const [iocRunning, setIocRunning] = useState(false);

  // TTP hunt
  const [ttpResults, setTtpResults] = useState<Partial<Record<TTPKEY, any>>>({});
  const [ttpRunning, setTtpRunning] = useState<Partial<Record<TTPKEY, boolean>>>({});
  const [ttpRange, setTtpRange] = useState('24h');

  // notebook
  const [notebook, setNotebook] = useState<NoteEntry[]>([]);
  const [noteContent, setNoteContent] = useState('');
  const [noteType, setNoteType] = useState('note');
  const [noteSaving, setNoteSaving] = useState(false);

  // AI
  const [aiAction, setAiAction] = useState('generate_query');
  const [aiPrompt, setAiPrompt] = useState('');
  const [aiResult, setAiResult] = useState<any>(null);
  const [aiRunning, setAiRunning] = useState(false);

  const [toast, setToast] = useState<string | null>(null);
  const notify = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 3000); };

  // ── Data loading ─────────────────────────────────────────────────────────

  const loadBase = useCallback(async () => {
    const [t, r] = await Promise.all([huntWorkbenchAPI.getTemplates(), huntWorkbenchAPI.getRuns()]);
    setTemplates(t.data || []);
    setRuns(r.data || []);
  }, []);

  useEffect(() => { loadBase(); }, [loadBase]);

  useEffect(() => {
    const hasRunning = runs.some(r => r.status === 'running');
    if (!hasRunning) return;
    const t = setInterval(() => loadBase(), 4000);
    return () => clearInterval(t);
  }, [runs, loadBase]);

  useEffect(() => {
    if (loaded.current[tab]) return;
    loaded.current[tab] = true;
    switch (tab) {
      case 'dashboard':
        huntWorkbenchAPI.dashboard().then(r => setDash(r.data));
        break;
      case 'analytics':
        huntWorkbenchAPI.analytics().then(r => setAnalytics(r.data));
        break;
      case 'mitre':
        huntWorkbenchAPI.mitreCoverage().then(r => setMitre(r.data));
        break;
      case 'notebook':
        huntWorkbenchAPI.notebook().then(r => setNotebook(r.data || []));
        break;
    }
  }, [tab]);

  // ── Actions ───────────────────────────────────────────────────────────────

  const patchSession = (id: string, patch: Partial<HuntSession>) =>
    setSessions(prev => prev.map(s => s.id === id ? { ...s, ...patch } : s));

  const executeHuntInSession = async (sid: string) => {
    const sess = sessions.find(s => s.id === sid);
    if (!sess || !sess.query) return;
    patchSession(sid, { running: true, run: null });
    const r = await huntWorkbenchAPI.execute({ kql_query: sess.query, name: sess.name });
    if (r.data) {
      patchSession(sid, { running: false, run: r.data });
      setRuns(prev => [r.data, ...prev.filter(x => x.id !== r.data.id)]);
      notify(`Hunt "${sess.name}" started`);
    } else {
      patchSession(sid, { running: false });
    }
  };

  const generateKQL = async (sid: string) => {
    const sess = sessions.find(s => s.id === sid);
    if (!sess?.nlQuery) return;
    setAiGenerating(true);
    try {
      const r = await huntWorkbenchAPI.ai({ action: 'generate_query', prompt: sess.nlQuery, context: '' });
      const d = r.data;
      if (d?.kql) patchSession(sid, { query: d.kql, queryLang: 'kql' });
      notify('KQL generated from natural language');
    } catch { notify('AI unavailable'); }
    setAiGenerating(false);
  };

  const addSession = () => {
    const id = `s${Date.now()}`;
    const n = sessions.length + 1;
    setSessions(prev => [...prev, { id, name: `Hunt ${n}`, queryLang: 'kql', query: '', nlQuery: '', run: null, running: false }]);
    setActiveSession(id);
  };

  const removeSession = (id: string) => {
    setSessions(prev => {
      const next = prev.filter(s => s.id !== id);
      if (next.length === 0) return [{ id: 's1', name: 'Hunt 1', queryLang: 'kql', query: '', nlQuery: '', run: null, running: false }];
      return next;
    });
    setActiveSession(prev => prev === id ? (sessions.find(s => s.id !== id)?.id || 's1') : prev);
  };

  const loadTemplateIntoSession = (kql: string, name: string) => {
    patchSession(activeSession, { query: kql, name });
    setTab('workspace');
  };

  const executeHunt = async (kql: string, name: string, templateID?: number) => {
    const r = await huntWorkbenchAPI.execute({ kql_query: kql, name, ...(templateID ? { template_id: templateID } : {}) });
    if (r.data) { setRuns(prev => [r.data, ...prev]); setTab('history'); setExpandedRun(r.data.id); notify('Hunt started'); }
  };

  const createTemplate = async () => {
    if (!newTpl.name || !newTpl.kql_query) return;
    await huntWorkbenchAPI.createTemplate(newTpl);
    setShowCreateTpl(false);
    setNewTpl({ name: '', description: '', mitre_tactic: '', mitre_technique: '', kql_query: '', schedule: '' });
    loadBase();
    notify('Template saved');
  };

  const deleteTemplate = async (id: number) => {
    await huntWorkbenchAPI.deleteTemplate(id);
    setTemplates(prev => prev.filter(t => t.id !== id));
    notify('Template deleted');
  };

  const updateNotes = async (id: number, notes: string, severity: string) => {
    await huntWorkbenchAPI.updateNotes(id, notes, severity);
    setRuns(prev => prev.map(r => r.id === id ? { ...r, notes, severity } : r));
  };

  const runIOCHunt = async () => {
    if (!iocValue) return;
    setIocRunning(true);
    try {
      const r = await huntWorkbenchAPI.iocHunt({ ioc_type: iocType, value: iocValue, time_range: iocRange });
      setIocResults(r.data);
    } catch { notify('IOC hunt failed'); }
    setIocRunning(false);
  };

  const runTTPHunt = async (ttp: TTPKEY) => {
    setTtpRunning(prev => ({ ...prev, [ttp]: true }));
    try {
      const r = await huntWorkbenchAPI.ttpHunt({ ttp, time_range: ttpRange });
      setTtpResults(prev => ({ ...prev, [ttp]: r.data }));
    } catch { notify('TTP hunt failed'); }
    setTtpRunning(prev => ({ ...prev, [ttp]: false }));
  };

  const addNote = async () => {
    if (!noteContent) return;
    setNoteSaving(true);
    try {
      await huntWorkbenchAPI.addNote({ content: noteContent, content_type: noteType });
      setNoteContent('');
      huntWorkbenchAPI.notebook().then(r => setNotebook(r.data || []));
      notify('Note saved');
    } catch { notify('Failed to save note'); }
    setNoteSaving(false);
  };

  const deleteNote = async (id: number) => {
    await huntWorkbenchAPI.deleteNote(id);
    setNotebook(prev => prev.filter(n => n.id !== id));
  };

  const runAI = async () => {
    if (!aiPrompt) return;
    setAiRunning(true);
    setAiResult(null);
    try {
      const r = await huntWorkbenchAPI.ai({ action: aiAction, prompt: aiPrompt, context: '' });
      setAiResult(r.data);
    } catch { notify('AI unavailable'); }
    setAiRunning(false);
  };

  const filteredTemplates = useMemo(() =>
    templates.filter(t => !tplSearch || t.name.toLowerCase().includes(tplSearch.toLowerCase()) || t.mitre_technique?.toLowerCase().includes(tplSearch.toLowerCase())),
  [templates, tplSearch]);

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <RootLayout title="Hunt Workbench" subtitle="Threat hunting · IOC & TTP pivoting · Evidence collection · MITRE coverage">
      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)' }}>{toast}</div>}

      {/* Tab bar */}
      <div className="flex gap-1 mb-4 flex-wrap">
        {TABS.map(({ key, label, icon: Icon }) => (
          <button key={key} onClick={() => setTab(key as TabKey)}
            className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5"
            style={{
              background: tab === key ? 'var(--accent-glow)' : 'var(--glass-bg)',
              border: `1px solid ${tab === key ? 'var(--accent-border)' : 'var(--border)'}`,
              color: tab === key ? 'var(--accent)' : 'var(--text-2)',
            }}>
            <Icon className="h-3 w-3" />{label}
          </button>
        ))}
      </div>

      {/* ── Dashboard ──────────────────────────────────────────────────────── */}
      {tab === 'dashboard' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-4 gap-3">
            <KPICard label="Active Hunts"   value={dash?.active ?? '—'}       color="#fbbf24" />
            <KPICard label="Completed"      value={dash?.completed ?? '—'}     />
            <KPICard label="IOC Matches"    value={dash?.ioc_matches ?? '—'}   color="#f85149" />
            <KPICard label="Success Rate"   value={dash ? `${Math.round(dash.success_rate)}%` : '—'} color="#22c55e" />
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <KPICard label="Saved Templates" value={dash?.saved ?? '—'} />
            <KPICard label="Total Runs"      value={dash?.total ?? '—'} />
            <KPICard label="Failed"          value={dash?.failed ?? '—'} color="#f85149" />
            <KPICard label="Techniques Hunted" value={dash?.top_techniques?.length ?? '—'} color="var(--accent)" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Recent runs */}
            <div className="g-card p-4">
              <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-2)' }}>Recent Hunt Runs</p>
              {dash?.recent_runs?.length ? (
                <table className="g-table w-full text-xs">
                  <thead className="g-thead">
                    <tr><th className="g-tr">Name</th><th className="g-tr">Status</th><th className="g-tr">Hits</th><th className="g-tr">Analyst</th><th className="g-tr">When</th></tr>
                  </thead>
                  <tbody>
                    {dash.recent_runs.map((r: any) => (
                      <tr key={r.id} className="hover:bg-[var(--glass-bg)] cursor-pointer" onClick={() => { setTab('history'); setExpandedRun(r.id); }}>
                        <td className="g-tr font-medium truncate max-w-[120px]" style={{ color: 'var(--text-1)' }}>{r.name}</td>
                        <td className="g-tr"><SevBadge sev={r.status === 'completed' ? 'info' : r.status === 'running' ? 'medium' : 'critical'} /></td>
                        <td className="g-tr" style={{ color: r.hit_count > 0 ? '#f85149' : 'var(--text-3)' }}>{r.hit_count}</td>
                        <td className="g-tr" style={{ color: 'var(--text-3)' }}>{r.analyst || '—'}</td>
                        <td className="g-tr" style={{ color: 'var(--text-3)' }}>{timeAgo(r.started_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : <p className="text-xs py-4 text-center" style={{ color: 'var(--text-3)' }}>No runs yet</p>}
            </div>

            {/* Trend + techniques */}
            <div className="space-y-3">
              <div className="g-card p-4">
                <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-2)' }}>14-Day Hunt Activity</p>
                <SparkTrend data={dash?.trend || []} key1="runs" />
              </div>
              <div className="g-card p-4">
                <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-2)' }}>Top MITRE Techniques</p>
                <div className="space-y-1.5">
                  {(dash?.top_techniques || []).map((t: any) => (
                    <div key={t.technique} className="flex items-center gap-2">
                      <span className="text-[10px] font-mono w-20 shrink-0" style={{ color: 'var(--accent)' }}>{t.technique}</span>
                      <div className="flex-1 h-1.5 rounded-full" style={{ background: 'var(--glass-bg-2)' }}>
                        <div className="h-full rounded-full" style={{ background: 'var(--accent)', width: `${Math.min(100, t.count * 20)}%` }} />
                      </div>
                      <span className="text-[10px] w-4 text-right" style={{ color: 'var(--text-3)' }}>{t.count}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Workspace (multi-tab) ───────────────────────────────────────────── */}
      {tab === 'workspace' && (
        <div className="space-y-3">
          {/* Session tabs */}
          <div className="flex items-center gap-1 flex-wrap">
            {sessions.map(s => (
              <div key={s.id} className="flex items-center gap-0.5">
                <button
                  onClick={() => setActiveSession(s.id)}
                  className="px-3 py-1.5 text-xs rounded-l-lg transition-all"
                  style={{
                    background: activeSession === s.id ? 'var(--accent-glow)' : 'var(--glass-bg)',
                    border: `1px solid ${activeSession === s.id ? 'var(--accent-border)' : 'var(--border)'}`,
                    borderRight: 'none',
                    color: activeSession === s.id ? 'var(--accent)' : 'var(--text-3)',
                  }}>
                  {s.name}
                </button>
                <button onClick={() => removeSession(s.id)} className="px-1.5 py-1.5 text-xs rounded-r-lg"
                  style={{ background: 'var(--glass-bg)', border: `1px solid var(--border)`, color: 'var(--text-3)' }}>
                  <X className="h-2.5 w-2.5" />
                </button>
              </div>
            ))}
            <button onClick={addSession} className="g-btn g-btn-ghost text-xs px-2 py-1.5">
              <Plus className="h-3 w-3" />
            </button>
          </div>

          {curSession && (
            <div className="g-card p-4 space-y-3">
              {/* Session header */}
              <div className="flex items-center gap-3">
                <input
                  value={curSession.name}
                  onChange={e => patchSession(curSession.id, { name: e.target.value })}
                  className="g-input text-sm font-medium flex-1"
                  placeholder="Hunt name…"
                />
                <select value={curSession.queryLang} onChange={e => patchSession(curSession.id, { queryLang: e.target.value as any })} className="g-select text-xs">
                  <option value="kql">KQL</option>
                  <option value="nl">Natural Language</option>
                  <option value="sigma">Sigma</option>
                  <option value="elastic">Elastic DSL</option>
                </select>
              </div>

              {/* Natural language input */}
              {curSession.queryLang === 'nl' && (
                <div className="space-y-2">
                  <textarea
                    value={curSession.nlQuery}
                    onChange={e => patchSession(curSession.id, { nlQuery: e.target.value })}
                    className="g-input w-full text-sm resize-none"
                    rows={2}
                    placeholder="Describe what you're hunting: e.g. 'Find PowerShell commands that download files from the internet'"
                  />
                  <button onClick={() => generateKQL(curSession.id)} disabled={aiGenerating || !curSession.nlQuery}
                    className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
                    <Brain className="h-3.5 w-3.5" />
                    {aiGenerating ? 'Generating…' : 'Generate KQL'}
                  </button>
                </div>
              )}

              {/* Query editor */}
              <div>
                <label className="block text-[10px] mb-1 font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
                  {curSession.queryLang === 'nl' ? 'Generated KQL' : curSession.queryLang.toUpperCase() + ' Query'}
                </label>
                <textarea
                  value={curSession.query}
                  onChange={e => patchSession(curSession.id, { query: e.target.value })}
                  className="g-input w-full font-mono text-sm resize-none"
                  rows={5}
                  placeholder={curSession.queryLang === 'kql' ? 'Failed password\n\nOR: severity:high source:auth.log\n\nOR: sudo AND NOT tty' :
                    curSession.queryLang === 'sigma' ? 'title: Suspicious PowerShell\ndetection:\n  selection:\n    EventID: 4104\n  condition: selection' :
                    curSession.queryLang === 'elastic' ? '{ "query": { "match": { "log_message": "powershell" } } }' :
                    'KQL generated from natural language will appear here…'}
                />
              </div>

              {/* Action row */}
              <div className="flex items-center gap-2 flex-wrap">
                <button
                  onClick={() => executeHuntInSession(curSession.id)}
                  disabled={curSession.running || !curSession.query}
                  className="g-btn g-btn-primary flex items-center gap-2">
                  <Play className="h-3.5 w-3.5" />
                  {curSession.running ? 'Hunting…' : 'Execute Hunt'}
                </button>
                <button
                  onClick={() => { setNewTpl(prev => ({ ...prev, kql_query: curSession.query, name: curSession.name })); setTab('templates'); setShowCreateTpl(true); }}
                  className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
                  <Plus className="h-3 w-3" /> Save as Template
                </button>
                <button
                  onClick={() => { setAiPrompt(curSession.query); setAiAction('explain_results'); setTab('workspace'); }}
                  className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
                  <Brain className="h-3 w-3" /> AI Explain
                </button>
              </div>

              {/* Inline results */}
              {curSession.run && (
                <div className="border-t pt-3" style={{ borderColor: 'var(--border)' }}>
                  <div className="flex items-center gap-2 mb-2">
                    {curSession.run.status === 'completed' ? <CheckCircle className="h-4 w-4" style={{ color: '#22c55e' }} /> : <Clock className="h-4 w-4 animate-spin" style={{ color: '#fbbf24' }} />}
                    <span className="text-sm font-medium" style={{ color: 'var(--text-1)' }}>{curSession.run.status === 'completed' ? `${curSession.run.hit_count} hits found` : 'Hunt running…'}</span>
                    {curSession.run.hit_count > 0 && <SevBadge sev="critical" />}
                  </div>
                  {(curSession.run.findings || []).slice(0, 5).map((f, i) => (
                    <div key={i} className="rounded-lg px-3 py-2 mb-1 text-[11px] font-mono truncate" style={{ background: 'var(--bg-0)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>
                      [{f.source}] {f.hostname}: {f.message}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Quick launch templates in workspace */}
          <div>
            <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-3)' }}>Quick Launch</p>
            <div className="grid grid-cols-2 lg:grid-cols-3 gap-2">
              {BUILTIN_TEMPLATES.map(t => (
                <div key={t.name} className="g-card p-3 flex items-start gap-2">
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-semibold truncate" style={{ color: 'var(--text-1)' }}>{t.name}</p>
                    <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{t.mitre_technique}</p>
                  </div>
                  <button onClick={() => { patchSession(activeSession, { query: t.kql_query, name: t.name }); }}
                    className="g-btn g-btn-ghost text-[11px] shrink-0"><Target className="h-3 w-3" /></button>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── IOC Hunt ────────────────────────────────────────────────────────── */}
      {tab === 'ioc-hunt' && (
        <div className="space-y-4">
          <div className="g-card p-4 space-y-3">
            <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Hunt by Indicator of Compromise</p>
            <div className="flex gap-3 flex-wrap">
              <div>
                <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>IOC Type</label>
                <select value={iocType} onChange={e => setIocType(e.target.value)} className="g-select text-sm">
                  {['ip', 'domain', 'sha256', 'md5', 'ja3', 'email', 'url', 'cve'].map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
                </select>
              </div>
              <div className="flex-1 min-w-[200px]">
                <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Value</label>
                <input value={iocValue} onChange={e => setIocValue(e.target.value)} className="g-input w-full text-sm font-mono"
                  placeholder={iocType === 'ip' ? '185.220.101.47' : iocType === 'sha256' ? 'e3b0c44298fc1c149afb...' : iocType === 'domain' ? 'evil.example.com' : `Enter ${iocType.toUpperCase()} value`} />
              </div>
              <div>
                <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Time Range</label>
                <select value={iocRange} onChange={e => setIocRange(e.target.value)} className="g-select text-sm">
                  <option value="24h">Last 24h</option>
                  <option value="7d">Last 7 days</option>
                  <option value="30d">Last 30 days</option>
                </select>
              </div>
              <div className="flex items-end">
                <button onClick={runIOCHunt} disabled={iocRunning || !iocValue} className="g-btn g-btn-primary flex items-center gap-2">
                  <Search className="h-3.5 w-3.5" />{iocRunning ? 'Hunting…' : 'Hunt IOC'}
                </button>
              </div>
            </div>
          </div>

          {iocResults && (
            <div className="g-card p-4 space-y-4">
              <div className="flex items-center gap-3">
                <span className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Results for {iocResults.ioc_type?.toUpperCase()}: {iocResults.value}</span>
                <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: iocResults.total_hits > 0 ? 'rgba(248,81,73,0.15)' : 'var(--glass-bg-2)', color: iocResults.total_hits > 0 ? '#f85149' : 'var(--text-3)' }}>
                  {iocResults.total_hits} total hits
                </span>
              </div>
              {iocResults.alert_hits?.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: '#f85149' }}>Alerts ({iocResults.alert_hits.length})</p>
                  {iocResults.alert_hits.map((h: any, i: number) => (
                    <div key={i} className="flex items-center gap-2 py-2 border-b" style={{ borderColor: 'var(--border)' }}>
                      <AlertTriangle className="h-3.5 w-3.5 shrink-0" style={{ color: '#f85149' }} />
                      <span className="text-xs font-medium flex-1" style={{ color: 'var(--text-1)' }}>{h.rule_name}</span>
                      <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{h.hostname}</span>
                      <SevBadge sev={h.severity} />
                    </div>
                  ))}
                </div>
              )}
              {iocResults.log_hits?.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-2)' }}>Log Hits ({iocResults.log_hits.length})</p>
                  <div className="max-h-64 overflow-y-auto space-y-1">
                    {iocResults.log_hits.map((h: any, i: number) => (
                      <div key={i} className="px-3 py-2 rounded-lg text-[11px] font-mono" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                        <span style={{ color: 'var(--accent)' }}>[{h.source}] {h.hostname}:</span> {h.message}
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {iocResults.conn_hits?.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-2)' }}>Connections ({iocResults.conn_hits.length})</p>
                  {iocResults.conn_hits.map((h: any, i: number) => (
                    <div key={i} className="flex items-center gap-3 py-1.5 text-xs border-b" style={{ borderColor: 'var(--border)' }}>
                      <Globe className="h-3 w-3 shrink-0" style={{ color: 'var(--accent)' }} />
                      <span style={{ color: 'var(--text-1)' }}>{h.hostname}</span>
                      <span className="font-mono" style={{ color: 'var(--text-3)' }}>{h.remote_addr}</span>
                      <span style={{ color: 'var(--text-3)' }}>{h.state}</span>
                    </div>
                  ))}
                </div>
              )}
              {iocResults.total_hits === 0 && (
                <p className="text-sm text-center py-6" style={{ color: 'var(--text-3)' }}>No hits found in selected time range</p>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── TTP Hunt ────────────────────────────────────────────────────────── */}
      {tab === 'ttp-hunt' && (
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Hunt by Tactic, Technique & Procedure</p>
            <select value={ttpRange} onChange={e => setTtpRange(e.target.value)} className="g-select text-xs ml-auto">
              <option value="24h">Last 24h</option>
              <option value="7d">Last 7 days</option>
              <option value="30d">Last 30 days</option>
            </select>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {TTP_CATALOG.map(t => {
              const res = ttpResults[t.key];
              const running = ttpRunning[t.key];
              return (
                <div key={t.key} className="g-card p-4 space-y-2">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <p className="text-sm">{t.icon} {t.label}</p>
                      <p className="text-[10px] font-mono mt-0.5" style={{ color: 'var(--accent)' }}>{t.mitre}</p>
                      <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>{t.desc}</p>
                    </div>
                  </div>
                  <button onClick={() => runTTPHunt(t.key as TTPKEY)} disabled={!!running}
                    className="g-btn g-btn-ghost text-xs w-full flex items-center justify-center gap-1.5">
                    <Play className="h-3 w-3" />{running ? 'Hunting…' : `Hunt ${t.label}`}
                  </button>
                  {res && (
                    <div className="border-t pt-2" style={{ borderColor: 'var(--border)' }}>
                      <p className="text-[10px] font-semibold" style={{ color: res.total_hits > 0 ? '#f85149' : '#22c55e' }}>
                        {res.total_hits > 0 ? `⚠ ${res.total_hits} hits` : '✓ No hits'}
                      </p>
                      {res.log_hits?.slice(0, 2).map((h: any, i: number) => (
                        <p key={i} className="text-[10px] font-mono truncate mt-1" style={{ color: 'var(--text-3)' }}>{h.hostname}: {h.message?.slice(0, 50)}</p>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Templates ──────────────────────────────────────────────────────── */}
      {tab === 'templates' && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
              <input value={tplSearch} onChange={e => setTplSearch(e.target.value)} className="g-input w-full pl-8 text-sm" placeholder="Search templates…" />
            </div>
            <button onClick={() => setShowCreateTpl(!showCreateTpl)} className="g-btn g-btn-primary text-xs flex items-center gap-1.5">
              <Plus className="h-3.5 w-3.5" /> Save Template
            </button>
          </div>

          {showCreateTpl && (
            <div className="g-card p-4 space-y-3">
              <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>New Hunt Template</p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Name</label>
                  <input value={newTpl.name} onChange={e => setNewTpl(p => ({ ...p, name: e.target.value }))} className="g-input w-full text-xs" /></div>
                <div><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>MITRE Technique</label>
                  <input value={newTpl.mitre_technique} onChange={e => setNewTpl(p => ({ ...p, mitre_technique: e.target.value }))} className="g-input w-full text-xs font-mono" placeholder="T1059" /></div>
                <div className="sm:col-span-2"><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>KQL Query</label>
                  <textarea value={newTpl.kql_query} onChange={e => setNewTpl(p => ({ ...p, kql_query: e.target.value }))} className="g-input w-full text-xs font-mono resize-none" rows={3} /></div>
                <div><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Schedule (cron)</label>
                  <input value={newTpl.schedule} onChange={e => setNewTpl(p => ({ ...p, schedule: e.target.value }))} className="g-input w-full text-xs font-mono" placeholder="0 6 * * 1" /></div>
                <div><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Description</label>
                  <input value={newTpl.description} onChange={e => setNewTpl(p => ({ ...p, description: e.target.value }))} className="g-input w-full text-xs" /></div>
              </div>
              <div className="flex justify-end gap-2">
                <button onClick={() => setShowCreateTpl(false)} className="g-btn g-btn-ghost text-xs">Cancel</button>
                <button onClick={createTemplate} className="g-btn g-btn-primary text-xs">Save</button>
              </div>
            </div>
          )}

          {/* Builtin section */}
          <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Quick-Launch Templates</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {BUILTIN_TEMPLATES.map(t => (
              <div key={t.name} className="g-card p-3 flex items-start gap-2">
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-semibold truncate" style={{ color: 'var(--text-1)' }}>{t.name}</p>
                  <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{t.mitre_technique} · {t.mitre_tactic}</p>
                  <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{t.description}</p>
                </div>
                <button onClick={() => loadTemplateIntoSession(t.kql_query, t.name)}
                  className="g-btn g-btn-ghost text-[11px] shrink-0 flex items-center gap-1"><Target className="h-3 w-3" />Use</button>
              </div>
            ))}
          </div>

          {/* Saved templates */}
          {filteredTemplates.length > 0 && (
            <>
              <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Saved Templates ({filteredTemplates.length})</p>
              <div className="space-y-2">
                {filteredTemplates.map(t => (
                  <div key={t.id} className="g-card p-4 flex items-center gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <p className="text-sm font-medium" style={{ color: 'var(--text-1)' }}>{t.name}</p>
                        {t.mitre_technique && <span className="text-[10px] font-mono px-1.5 py-0.5 rounded" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>{t.mitre_technique}</span>}
                        {t.schedule && <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)' }}>⏰ {t.schedule}</span>}
                      </div>
                      <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{t.description}</p>
                      <p className="font-mono text-[10px] mt-1 truncate" style={{ color: 'var(--text-3)' }}>{t.kql_query}</p>
                    </div>
                    <button onClick={() => executeHunt(t.kql_query, t.name, t.id)} className="g-btn g-btn-ghost text-xs flex items-center gap-1.5 shrink-0">
                      <Play className="h-3 w-3" /> Run
                    </button>
                    <button onClick={() => loadTemplateIntoSession(t.kql_query, t.name)} className="g-btn g-btn-ghost text-xs flex items-center gap-1.5 shrink-0">
                      <Eye className="h-3 w-3" /> Edit
                    </button>
                    <button onClick={() => deleteTemplate(t.id)} className="p-1.5 rounded hover:bg-[var(--glass-bg-2)]">
                      <Trash2 className="h-3.5 w-3.5" style={{ color: '#f85149' }} />
                    </button>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}

      {/* ── History (runs) ──────────────────────────────────────────────────── */}
      {tab === 'history' && (
        <div className="space-y-2">
          <div className="flex items-center justify-between mb-2">
            <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Hunt History ({runs.length})</p>
            <button onClick={loadBase} className="g-btn g-btn-ghost text-xs flex items-center gap-1"><RefreshCw className="h-3 w-3" /> Refresh</button>
          </div>
          {runs.length === 0 ? (
            <div className="g-card p-10 text-center">
              <Search className="mx-auto h-10 w-10 mb-2 opacity-20" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-3)' }}>No hunts run yet. Start one from the Workspace tab.</p>
            </div>
          ) : runs.map(r => (
            <RunCard key={r.id} run={r}
              expanded={expandedRun === r.id}
              onExpand={() => setExpandedRun(prev => prev === r.id ? null : r.id)}
              onUpdateNotes={updateNotes} />
          ))}
        </div>
      )}

      {/* ── Notebook ────────────────────────────────────────────────────────── */}
      {tab === 'notebook' && (
        <div className="space-y-4">
          <div className="g-card p-4 space-y-3">
            <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Add Evidence / Note</p>
            <div className="flex gap-2">
              <select value={noteType} onChange={e => setNoteType(e.target.value)} className="g-select text-xs">
                <option value="note">Note</option>
                <option value="query">Query</option>
                <option value="evidence">Evidence</option>
                <option value="bookmark">Bookmark</option>
              </select>
            </div>
            <textarea value={noteContent} onChange={e => setNoteContent(e.target.value)}
              className="g-input w-full text-sm resize-none font-mono" rows={4}
              placeholder="Write notes, paste queries, record evidence…&#10;&#10;Markdown supported." />
            <div className="flex justify-between items-center">
              <button
                onClick={() => {
                  const md = notebook.map(n => `## ${n.content_type} — ${n.created_at}\n\n${n.content}`).join('\n\n---\n\n');
                  const blob = new Blob([md], { type: 'text/markdown' });
                  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
                  a.download = 'hunt-notebook.md'; a.click();
                }}
                className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
                <Download className="h-3 w-3" /> Export Markdown
              </button>
              <button onClick={addNote} disabled={noteSaving || !noteContent} className="g-btn g-btn-primary text-xs">
                {noteSaving ? 'Saving…' : 'Add Entry'}
              </button>
            </div>
          </div>

          <div className="space-y-2">
            {notebook.length === 0 ? (
              <div className="g-card p-8 text-center">
                <FileText className="mx-auto h-8 w-8 mb-2 opacity-20" style={{ color: 'var(--text-3)' }} />
                <p className="text-sm" style={{ color: 'var(--text-3)' }}>Notebook is empty. Add your first entry above.</p>
              </div>
            ) : notebook.map(n => (
              <div key={n.id} className="g-card p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>{n.content_type}</span>
                    <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{n.created_by} · {timeAgo(n.created_at)}</span>
                  </div>
                  <button onClick={() => deleteNote(n.id)} className="p-1 rounded hover:bg-[var(--glass-bg-2)]">
                    <Trash2 className="h-3 w-3" style={{ color: '#f85149' }} />
                  </button>
                </div>
                <pre className="text-xs whitespace-pre-wrap font-mono" style={{ color: 'var(--text-2)' }}>{n.content}</pre>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── MITRE Coverage Heatmap ──────────────────────────────────────────── */}
      {tab === 'mitre' && (
        <div className="space-y-4">
          <div className="flex items-center gap-4">
            <div className="g-card p-3 flex-1 text-center">
              <p className="text-2xl font-bold" style={{ color: 'var(--accent)' }}>{mitre?.overall_coverage ?? 0}%</p>
              <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Overall Coverage</p>
            </div>
            <div className="g-card p-3 flex-1 text-center">
              <p className="text-2xl font-bold" style={{ color: '#22c55e' }}>{mitre?.covered_count ?? 0}</p>
              <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Covered Techniques</p>
            </div>
            <div className="g-card p-3 flex-1 text-center">
              <p className="text-2xl font-bold" style={{ color: 'var(--text-3)' }}>{(mitre?.total_count ?? 0) - (mitre?.covered_count ?? 0)}</p>
              <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Untested</p>
            </div>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-sm" style={{ background: '#22c55e' }} /><span className="text-[10px]" style={{ color: 'var(--text-3)' }}>Frequently Hunted</span></div>
              <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-sm" style={{ background: '#fbbf24' }} /><span className="text-[10px]" style={{ color: 'var(--text-3)' }}>Covered</span></div>
              <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-sm" style={{ background: 'var(--glass-bg-2)' }} /><span className="text-[10px]" style={{ color: 'var(--text-3)' }}>Untested</span></div>
            </div>
          </div>

          <div className="space-y-2">
            {(mitre?.tactics || []).map((tac: any) => (
              <div key={tac.id} className="g-card p-3">
                <div className="flex items-center gap-3 mb-2">
                  <span className="text-[10px] font-mono" style={{ color: 'var(--text-3)' }}>{tac.id}</span>
                  <p className="text-xs font-semibold flex-1" style={{ color: 'var(--text-1)' }}>{tac.name}</p>
                  <div className="flex items-center gap-1">
                    <div className="w-16 h-1.5 rounded-full" style={{ background: 'var(--glass-bg-2)' }}>
                      <div className="h-full rounded-full" style={{ background: '#22c55e', width: `${tac.coverage}%` }} />
                    </div>
                    <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{tac.coverage}%</span>
                  </div>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {tac.techniques?.map((tech: any) => (
                    <div key={tech.id} className="px-2 py-1 rounded text-[10px] font-mono"
                      style={{
                        background: tech.status === 'frequently_hunted' ? 'rgba(34,197,94,0.15)'
                          : tech.status === 'covered' ? 'rgba(251,191,36,0.15)'
                          : 'var(--glass-bg)',
                        color: tech.status === 'frequently_hunted' ? '#22c55e'
                          : tech.status === 'covered' ? '#fbbf24'
                          : 'var(--text-3)',
                        border: `1px solid ${tech.status === 'frequently_hunted' ? 'rgba(34,197,94,0.3)'
                          : tech.status === 'covered' ? 'rgba(251,191,36,0.3)'
                          : 'var(--border)'}`,
                      }}
                      title={`${tech.id}: ${tech.name}${tech.run_count ? ` (${tech.run_count} runs)` : ''}`}>
                      {tech.id}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Analytics ───────────────────────────────────────────────────────── */}
      {tab === 'analytics' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <KPICard label="Total Runs"  value={analytics?.total_runs ?? '—'} />
            <KPICard label="Total Hits"  value={analytics?.total_hits ?? '—'} color="#f85149" />
            <KPICard label="Analysts"    value={analytics?.analysts?.length ?? '—'} />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Per analyst */}
            <div className="g-card p-4">
              <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-2)' }}>By Analyst</p>
              <table className="g-table w-full text-xs">
                <thead className="g-thead">
                  <tr><th className="g-tr">Analyst</th><th className="g-tr">Runs</th><th className="g-tr">Total Hits</th><th className="g-tr">Success Rate</th></tr>
                </thead>
                <tbody>
                  {(analytics?.analysts || []).map((a: any) => (
                    <tr key={a.analyst} className="hover:bg-[var(--glass-bg)]">
                      <td className="g-tr font-medium" style={{ color: 'var(--text-1)' }}>{a.analyst}</td>
                      <td className="g-tr" style={{ color: 'var(--text-2)' }}>{a.runs}</td>
                      <td className="g-tr" style={{ color: a.total_hits > 0 ? '#f85149' : 'var(--text-3)' }}>{a.total_hits}</td>
                      <td className="g-tr">
                        <div className="flex items-center gap-2">
                          <div className="w-12 h-1 rounded-full" style={{ background: 'var(--glass-bg-2)' }}>
                            <div className="h-full rounded-full" style={{ background: '#22c55e', width: `${a.success_rate}%` }} />
                          </div>
                          <span style={{ color: 'var(--text-3)' }}>{Math.round(a.success_rate)}%</span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Top templates + 30d trend */}
            <div className="space-y-3">
              <div className="g-card p-4">
                <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-2)' }}>30-Day Run Trend</p>
                <SparkTrend data={analytics?.daily || []} key1="runs" />
              </div>
              <div className="g-card p-4">
                <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-2)' }}>Top Templates Used</p>
                <div className="space-y-2">
                  {(analytics?.top_templates || []).map((t: any) => (
                    <div key={t.name} className="flex items-center gap-2">
                      <p className="text-xs flex-1 truncate" style={{ color: 'var(--text-2)' }}>{t.name}</p>
                      <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{t.runs} runs</span>
                      <span className="text-[10px]" style={{ color: t.hits > 0 ? '#f85149' : 'var(--text-3)' }}>{t.hits} hits</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
