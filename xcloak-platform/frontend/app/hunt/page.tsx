'use client';

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { threatHuntAPI, huntAPI, agentsAPI, huntWorkbenchAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import {
  Search, Plus, Play, Trash2, Clock, CheckCircle, AlertCircle, ChevronDown,
  ChevronRight, Brain, Shield, Activity, Grid3X3, FileText, Target, Zap, Save,
  Download, RefreshCw, Eye, AlertTriangle, Users, TrendingUp, X, Filter,
  BookOpen, Settings, ExternalLink,
} from 'lucide-react';

// ── Types ────────────────────────────────────────────────────────────────────

interface ThreatHunt {
  id: number; name: string; description: string;
  category: string; sub_category: string; author: string;
  priority: string; status: string; risk_level: string;
  mitre_techniques: string; hypothesis: string; objective: string;
  expected_findings: string; success_criteria: string; scope: string;
  query_type: string; query_text: string; schedule_type: string;
  cron_schedule: string; is_continuous: boolean; continuous_interval: string;
  assigned_analyst: string; review_status: string;
  hit_count: number; run_count: number; success_count: number;
  false_positive_count: number; success_rate: number;
  last_run_at: string; version: number; created_at: string;
}
interface Finding {
  id: number; hunt_id: number; hunt_name: string;
  severity: string; confidence: string; risk: string;
  title: string; description: string; mitre_technique: string;
  affected_host: string; affected_user: string; ioc_value: string;
  status: string; created_at: string;
}

// ── Shared display components ─────────────────────────────────────────────────

const SEV: Record<string, string> = { critical: '#f85149', high: '#fb923c', medium: '#fbbf24', low: '#22c55e', info: '#60a5fa' };

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
  const c = SEV[sev] || '#60a5fa';
  return <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-full" style={{ background: `${c}22`, color: c }}>{sev}</span>;
}
function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = { active: '#22c55e', completed: '#60a5fa', draft: '#fbbf24', archived: 'var(--text-3)', open: '#f85149', acknowledged: '#fbbf24', false_positive: 'var(--text-3)', confirmed: '#f85149' };
  const c = map[status] || 'var(--text-3)';
  return <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: `${c}22`, color: c }}>{status}</span>;
}
function SparkTrend({ data, key1 }: { data: any[]; key1: string }) {
  if (!data?.length) return null;
  const vals = data.map(d => d[key1] || 0);
  const max = Math.max(...vals, 1);
  return (
    <svg width="100%" height="32" viewBox={`0 0 ${data.length * 12} 32`} preserveAspectRatio="none">
      <polyline points={vals.map((v, i) => `${i * 12 + 6},${32 - (v / max) * 28}`).join(' ')}
        fill="none" stroke="var(--accent)" strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

// ── Constants ─────────────────────────────────────────────────────────────────

const TABS = [
  { key: 'dashboard',  label: 'Dashboard',   icon: Activity },
  { key: 'library',    label: 'Library',      icon: BookOpen },
  { key: 'categories', label: 'Categories',   icon: Grid3X3 },
  { key: 'workspace',  label: 'Workspace',    icon: Search },
  { key: 'findings',   label: 'Findings',     icon: AlertTriangle },
  { key: 'mitre',      label: 'MITRE',        icon: Shield },
  { key: 'analytics',  label: 'Analytics',    icon: TrendingUp },
  { key: 'automation', label: 'Automation',   icon: Zap },
  { key: 'templates',  label: 'Templates',    icon: FileText },
] as const;
type TabKey = typeof TABS[number]['key'];

const SCOPES = ['endpoints', 'servers', 'cloud', 'containers', 'network', 'vpn', 'active_directory', 'mdm'];

const QUERY_TYPES = [
  { id: 'log',       label: 'Log Search' },
  { id: 'process',   label: 'Processes' },
  { id: 'connection',label: 'Connections' },
  { id: 'alert',     label: 'Alerts' },
  { id: 'file_hash', label: 'File Hashes' },
  { id: 'user',      label: 'Users' },
  { id: 'command',   label: 'Commands' },
];

const BUILTIN_TEMPLATES = [
  { name: 'Ransomware Hunt',         category: 'malware', sub_category: 'ransomware_family', priority: 'critical', mitre_techniques: 'T1486,T1490,T1489', query_type: 'log', query_text: 'vssadmin', hypothesis: 'A ransomware operator may be staging for deployment. Shadow copy deletion and service termination are pre-ransomware indicators.', objective: 'Detect ransomware pre-staging activity', expected_findings: 'vssadmin delete shadows, net stop services', success_criteria: 'Alert on any VSS deletion event', scope: 'endpoints,servers' },
  { name: 'Insider Threat Hunt',     category: 'insider', sub_category: 'data_exfil',     priority: 'high',     mitre_techniques: 'T1048,T1052,T1567',    query_type: 'log', query_text: 'usb', hypothesis: 'A disgruntled insider may be copying sensitive data to external devices or cloud services before departing.', objective: 'Detect unusual data copy or upload activity', expected_findings: 'Large file transfers to removable media or personal cloud', success_criteria: 'Identify data movement >1GB to non-approved destinations', scope: 'endpoints,cloud' },
  { name: 'DNS Tunneling Hunt',      category: 'ttp',     sub_category: 'beaconing',      priority: 'high',     mitre_techniques: 'T1048.003',            query_type: 'log', query_text: 'dns', hypothesis: 'An attacker may be using DNS tunneling to exfiltrate data or maintain C2 comms while evading firewalls.', objective: 'Detect anomalous DNS query patterns indicative of tunneling', expected_findings: 'Long subdomain queries, high query volume to single domain', success_criteria: 'Find hosts with >500 DNS queries/hour or subdomain >50 chars', scope: 'endpoints,network' },
  { name: 'Kerberoasting Hunt',      category: 'ttp',     sub_category: 'lsass',          priority: 'high',     mitre_techniques: 'T1558.003',            query_type: 'alert', query_text: 'kerberos', hypothesis: 'An attacker with domain access may be requesting service tickets for offline cracking of service account passwords.', objective: 'Detect Kerberos TGS-REQ events for service accounts from unusual sources', expected_findings: 'EventID 4769 with RC4 encryption type from non-admin hosts', success_criteria: 'Identify TGS requests with RC4 cypher not from service hosts', scope: 'servers,active_directory' },
  { name: 'Lateral Movement Hunt',   category: 'ttp',     sub_category: 'lateral',        priority: 'high',     mitre_techniques: 'T1021,T1550',          query_type: 'connection', query_text: 'smb', hypothesis: 'Post-initial access, attackers may be traversing the network laterally using stolen credentials and remote services.', objective: 'Identify abnormal authentication patterns between internal hosts', expected_findings: 'Hosts accessing >3 unique admin shares, unusual WMI/DCOM activity', success_criteria: 'Flag any host accessing admin shares outside maintenance windows', scope: 'endpoints,servers,active_directory' },
  { name: 'Living Off The Land Hunt',category: 'ttp',     sub_category: 'lolbins',        priority: 'medium',   mitre_techniques: 'T1218,T1059',          query_type: 'process', query_text: 'certutil', hypothesis: 'Attackers may be leveraging trusted Windows utilities (LOLBins) to bypass application whitelisting and execute malicious payloads.', objective: 'Detect abuse of trusted Windows binaries for malicious purposes', expected_findings: 'certutil -decode, mshta http://, regsvr32 /i: events', success_criteria: 'Find LOLBin invocations with network/file-write activity', scope: 'endpoints,servers' },
  { name: 'Cloud Persistence Hunt',  category: 'cloud',   sub_category: 'aws_iam',        priority: 'high',     mitre_techniques: 'T1078,T1136',          query_type: 'log', query_text: 'iam', hypothesis: 'An attacker with cloud access may be creating backdoor IAM users, roles, or Lambda functions to maintain persistence.', objective: 'Detect unauthorized creation of cloud identities and access mechanisms', expected_findings: 'CreateUser, CreateRole, CreateFunction events from unexpected principals', success_criteria: 'Identify any new IAM entity created outside approved change management', scope: 'cloud' },
];

const EMPTY_HUNT: Partial<ThreatHunt> = {
  name: '', description: '', category: 'ttp', sub_category: '', priority: 'high', status: 'active',
  risk_level: 'high', mitre_techniques: '', hypothesis: '', objective: '', expected_findings: '',
  success_criteria: '', scope: 'endpoints,servers', query_type: 'log', query_text: '',
  schedule_type: 'manual', cron_schedule: '', is_continuous: false, continuous_interval: '',
  assigned_analyst: '',
};

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ThreatHuntPage() {
  const [tab, setTab] = useState<TabKey>('dashboard');
  const loaded = useRef<Partial<Record<TabKey, boolean>>>({});

  const [dash, setDash] = useState<any>(null);
  const [library, setLibrary] = useState<ThreatHunt[]>([]);
  const [categories, setCategories] = useState<any>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [metrics, setMetrics] = useState<any>(null);
  const [mitre, setMitre] = useState<any>(null);

  // Library filters
  const [libSearch, setLibSearch] = useState('');
  const [libCategory, setLibCategory] = useState('');
  const [libStatus, setLibStatus] = useState('');

  // Workspace (create / view-edit)
  const [form, setForm] = useState<Partial<ThreatHunt>>({ ...EMPTY_HUNT });
  const [isEdit, setIsEdit] = useState(false);
  const [saving, setSaving] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [executeResult, setExecuteResult] = useState<any>(null);
  const [comments, setComments] = useState<any[]>([]);
  const [newComment, setNewComment] = useState('');

  // AI assistant (workspace)
  const [aiAction, setAiAction] = useState<string>('improve_hypothesis');
  const [aiResult, setAiResult] = useState<any>(null);
  const [aiRunning, setAiRunning] = useState(false);

  // Findings filters
  const [findSev, setFindSev] = useState('');
  const [findStatus, setFindStatus] = useState('');

  // Response modal
  const [responseTarget, setResponseTarget] = useState('');
  const [responseAction, setResponseAction] = useState('open_incident');
  const [responseFindingId, setResponseFindingId] = useState(0);
  const [showResponseModal, setShowResponseModal] = useState(false);

  // Ad-hoc query runner (from existing hunt page)
  const [adHocType, setAdHocType] = useState('log');
  const [adHocText, setAdHocText] = useState('');
  const [adHocRunning, setAdHocRunning] = useState(false);
  const [adHocResult, setAdHocResult] = useState<any>(null);
  const [agents, setAgents] = useState<any[]>([]);

  const [toast, setToast] = useState<string | null>(null);
  const notify = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 3000); };

  // ── Data loading ─────────────────────────────────────────────────────────

  const loadLibrary = useCallback(async () => {
    const r = await threatHuntAPI.library({ category: libCategory || undefined, status: libStatus || undefined });
    setLibrary(r.data || []);
  }, [libCategory, libStatus]);

  useEffect(() => { loadLibrary(); }, [loadLibrary]);
  useEffect(() => { agentsAPI.getAll().then(r => setAgents(r.data || [])).catch(() => {}); }, []);

  useEffect(() => {
    if (loaded.current[tab]) return;
    loaded.current[tab] = true;
    switch (tab) {
      case 'dashboard':   threatHuntAPI.dashboard().then(r => setDash(r.data)); break;
      case 'categories':  threatHuntAPI.categories().then(r => setCategories(r.data)); break;
      case 'findings':    threatHuntAPI.findings().then(r => setFindings(r.data || [])); break;
      case 'analytics':   threatHuntAPI.metrics().then(r => setMetrics(r.data)); break;
      case 'mitre':       huntWorkbenchAPI.mitreCoverage().then(r => setMitre(r.data)); break;
    }
  }, [tab]);

  // ── Actions ───────────────────────────────────────────────────────────────

  const openHuntInWorkspace = async (hunt: ThreatHunt) => {
    setForm({ ...hunt });
    setIsEdit(true);
    setExecuteResult(null);
    setAiResult(null);
    setTab('workspace');
    const cr = await threatHuntAPI.comments(hunt.id);
    setComments(cr.data || []);
  };

  const createOrUpdateHunt = async () => {
    if (!form.name) { notify('Hunt name is required'); return; }
    setSaving(true);
    try {
      if (isEdit && form.id) {
        await threatHuntAPI.update(form.id, form);
        notify('Hunt updated');
      } else {
        const r = await threatHuntAPI.create(form);
        if (r.data?.id) setForm(prev => ({ ...prev, id: r.data.id }));
        setIsEdit(true);
        notify('Hunt saved');
      }
      loaded.current['library'] = false;
      loaded.current['dashboard'] = false;
      loadLibrary();
    } catch { notify('Save failed'); }
    setSaving(false);
  };

  const executeHunt = async () => {
    if (!form.id) { notify('Save the hunt first'); return; }
    setExecuting(true);
    setExecuteResult(null);
    try {
      const r = await threatHuntAPI.execute(form.id);
      setExecuteResult(r.data);
      loaded.current['findings'] = false;
      notify(`Hunt executed — ${r.data?.hits ?? 0} hits`);
    } catch { notify('Execution failed'); }
    setExecuting(false);
  };

  const runAdHoc = async () => {
    if (!adHocText.trim()) return;
    setAdHocRunning(true);
    setAdHocResult(null);
    try {
      const r = await huntAPI.run({ query_type: adHocType, query_text: adHocText });
      setAdHocResult(r.data);
    } catch { notify('Query failed'); }
    setAdHocRunning(false);
  };

  const runAI = async () => {
    if (!form.name && !form.hypothesis) { notify('Fill in hunt name/hypothesis first'); return; }
    setAiRunning(true);
    setAiResult(null);
    try {
      const r = await threatHuntAPI.ai({
        action: aiAction,
        hunt_id: form.id,
        hunt_name: form.name,
        hypothesis: form.hypothesis,
        category: form.category,
        prompt: form.hypothesis || form.name || '',
        context: form.objective || '',
      });
      setAiResult(r.data);
    } catch { notify('AI unavailable'); }
    setAiRunning(false);
  };

  const applyAIToForm = () => {
    if (!aiResult) return;
    if (aiResult.improved_hypothesis) setForm(p => ({ ...p, hypothesis: aiResult.improved_hypothesis }));
    if (aiResult.objective)           setForm(p => ({ ...p, objective: aiResult.objective }));
    if (aiResult.expected_findings)   setForm(p => ({ ...p, expected_findings: aiResult.expected_findings }));
    if (aiResult.success_criteria)    setForm(p => ({ ...p, success_criteria: aiResult.success_criteria }));
    if (aiResult.kql_query)           setForm(p => ({ ...p, query_text: aiResult.kql_query }));
    if (aiResult.mitre_techniques?.join) setForm(p => ({ ...p, mitre_techniques: aiResult.mitre_techniques.join(',') }));
    notify('AI suggestions applied to form');
    setAiResult(null);
  };

  const ackFinding = async (fid: number, status: string) => {
    await threatHuntAPI.ackFinding(fid, status);
    setFindings(prev => prev.map(f => f.id === fid ? { ...f, status } : f));
  };

  const submitResponse = async () => {
    await threatHuntAPI.response({ action: responseAction, finding_id: responseFindingId, target: responseTarget });
    notify(`${responseAction} queued for ${responseTarget}`);
    setShowResponseModal(false);
  };

  const addComment = async () => {
    if (!newComment || !form.id) return;
    await threatHuntAPI.comment(form.id, newComment);
    setComments(prev => [...prev, { id: Date.now(), author: 'you', content: newComment, created_at: new Date().toISOString() }]);
    setNewComment('');
  };

  const applyTemplate = (tpl: typeof BUILTIN_TEMPLATES[0]) => {
    setForm({ ...EMPTY_HUNT, ...tpl, status: 'active', is_continuous: false });
    setIsEdit(false);
    setExecuteResult(null);
    setTab('workspace');
  };

  const loadCategoryIntoWorkspace = (cat: string, sub: string) => {
    setForm({ ...EMPTY_HUNT, category: cat, sub_category: sub, status: 'active' });
    setIsEdit(false);
    setTab('workspace');
  };

  const filteredLibrary = useMemo(() =>
    library.filter(h =>
      (!libSearch || h.name.toLowerCase().includes(libSearch.toLowerCase()) || h.mitre_techniques?.toLowerCase().includes(libSearch.toLowerCase())) &&
      (!libCategory || h.category === libCategory) &&
      (!libStatus || h.status === libStatus)
    ),
  [library, libSearch, libCategory, libStatus]);

  const filteredFindings = useMemo(() =>
    findings.filter(f => (!findSev || f.severity === findSev) && (!findStatus || f.status === findStatus)),
  [findings, findSev, findStatus]);

  const scopeList = useMemo(() =>
    (form.scope || '').split(',').map(s => s.trim()).filter(Boolean),
  [form.scope]);

  const toggleScope = (s: string) => {
    const current = scopeList;
    const next = current.includes(s) ? current.filter(x => x !== s) : [...current, s];
    setForm(p => ({ ...p, scope: next.join(',') }));
  };

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <RootLayout title="Threat Hunt" subtitle="Structured threat hunting · Hunt library · Findings · MITRE ATT&CK coverage">
      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)' }}>{toast}</div>}

      {showResponseModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.6)' }} onClick={e => e.target === e.currentTarget && setShowResponseModal(false)}>
          <div className="g-card p-5 space-y-3 w-full max-w-sm">
            <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Response Action</p>
            <select value={responseAction} onChange={e => setResponseAction(e.target.value)} className="g-select w-full text-sm">
              <option value="open_incident">Open Incident</option>
              <option value="open_case">Open Case</option>
              <option value="isolate_host">Isolate Host</option>
              <option value="block_ip">Block IP</option>
              <option value="block_ioc">Block IOC</option>
              <option value="run_soar">Run SOAR Playbook</option>
              <option value="hunt_similar">Hunt Similar</option>
            </select>
            <input value={responseTarget} onChange={e => setResponseTarget(e.target.value)} className="g-input w-full text-sm" placeholder="Target (host, IP, IOC value…)" />
            <div className="flex gap-2 justify-end">
              <button onClick={() => setShowResponseModal(false)} className="g-btn g-btn-ghost text-xs">Cancel</button>
              <button onClick={submitResponse} className="g-btn g-btn-primary text-xs">Execute</button>
            </div>
          </div>
        </div>
      )}

      {/* Tab bar */}
      <div className="flex gap-1 mb-4 flex-wrap">
        {TABS.map(({ key, label, icon: Icon }) => (
          <button key={key} onClick={() => setTab(key as TabKey)}
            className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5"
            style={{ background: tab === key ? 'var(--accent-glow)' : 'var(--glass-bg)', border: `1px solid ${tab === key ? 'var(--accent-border)' : 'var(--border)'}`, color: tab === key ? 'var(--accent)' : 'var(--text-2)' }}>
            <Icon className="h-3 w-3" />{label}
          </button>
        ))}
        <button onClick={() => { setForm({ ...EMPTY_HUNT }); setIsEdit(false); setExecuteResult(null); setAiResult(null); setTab('workspace'); }}
          className="ml-auto g-btn g-btn-primary text-xs flex items-center gap-1.5">
          <Plus className="h-3 w-3" /> New Hunt
        </button>
      </div>

      {/* ── Dashboard ──────────────────────────────────────────────────────── */}
      {tab === 'dashboard' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <KPICard label="Active Hunts"     value={dash?.active ?? '—'}       color="#22c55e" />
            <KPICard label="Scheduled"        value={dash?.scheduled ?? '—'}    color="var(--accent)" />
            <KPICard label="Continuous"       value={dash?.continuous ?? '—'}   color="#a855f7" />
            <KPICard label="Total"            value={dash?.total ?? '—'} />
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <KPICard label="IOC Hunts"        value={dash?.ioc_hunts ?? '—'} />
            <KPICard label="TTP Hunts"        value={dash?.ttp_hunts ?? '—'} />
            <KPICard label="Open Findings"    value={dash?.open_findings ?? '—'} color="#f85149" />
            <KPICard label="Success Rate"     value={dash ? `${Math.round(dash.success_rate)}%` : '—'} color="#22c55e" />
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <KPICard label="Total Findings"   value={dash?.findings ?? '—'} />
            <KPICard label="New Findings 24h" value={dash?.new_findings ?? '—'} color="#fb923c" />
            <KPICard label="Critical"         value={dash?.critical_finds ?? '—'} color="#f85149" />
            <KPICard label="Completed"        value={dash?.completed ?? '—'} />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="g-card p-4">
              <div className="flex items-center justify-between mb-3">
                <p className="text-xs font-semibold" style={{ color: 'var(--text-2)' }}>Recent Hunt Activity</p>
                <button onClick={() => setTab('library')} className="text-[10px]" style={{ color: 'var(--accent)' }}>View all →</button>
              </div>
              <table className="g-table w-full text-xs">
                <thead className="g-thead"><tr><th className="g-tr">Hunt</th><th className="g-tr">Category</th><th className="g-tr">Hits</th><th className="g-tr">When</th></tr></thead>
                <tbody>
                  {(dash?.recent || []).map((r: any) => (
                    <tr key={r.id} className="hover:bg-[var(--glass-bg)] cursor-pointer" onClick={() => { const h = library.find(x => x.id === r.id); if (h) openHuntInWorkspace(h); }}>
                      <td className="g-tr font-medium truncate max-w-[130px]" style={{ color: 'var(--text-1)' }}>{r.name}</td>
                      <td className="g-tr" style={{ color: 'var(--text-3)' }}>{r.category}</td>
                      <td className="g-tr" style={{ color: r.hit_count > 0 ? '#f85149' : 'var(--text-3)' }}>{r.hit_count}</td>
                      <td className="g-tr" style={{ color: 'var(--text-3)' }}>{r.run_at ? timeAgo(r.run_at) : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="space-y-3">
              <div className="g-card p-4">
                <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-2)' }}>30-Day Hunt Activity</p>
                <SparkTrend data={dash?.trend || []} key1="hunts" />
              </div>
              <div className="g-card p-4">
                <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-2)' }}>Hunt Program Status</p>
                {[
                  { label: 'IOC Hunts',   val: dash?.ioc_hunts,   total: dash?.total },
                  { label: 'TTP Hunts',   val: dash?.ttp_hunts,   total: dash?.total },
                  { label: 'Actor Hunts', val: dash?.actor_hunts, total: dash?.total },
                ].map(({ label, val, total }) => (
                  <div key={label} className="flex items-center gap-2 mb-2">
                    <span className="text-[11px] w-20" style={{ color: 'var(--text-3)' }}>{label}</span>
                    <div className="flex-1 h-1.5 rounded-full" style={{ background: 'var(--glass-bg-2)' }}>
                      <div className="h-full rounded-full" style={{ background: 'var(--accent)', width: total ? `${Math.round((val || 0) / total * 100)}%` : '0%' }} />
                    </div>
                    <span className="text-[10px] w-4" style={{ color: 'var(--text-3)' }}>{val ?? 0}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Library ──────────────────────────────────────────────────────────── */}
      {tab === 'library' && (
        <div className="space-y-3">
          <div className="flex gap-2 flex-wrap">
            <div className="relative flex-1 min-w-[180px]">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
              <input value={libSearch} onChange={e => setLibSearch(e.target.value)} className="g-input w-full pl-8 text-sm" placeholder="Search hunts, MITRE techniques…" />
            </div>
            <select value={libCategory} onChange={e => { setLibCategory(e.target.value); loaded.current['library'] = false; }} className="g-select text-xs">
              <option value="">All Categories</option>
              <option value="ioc">IOC</option><option value="ttp">TTP</option><option value="actor">Actor</option>
              <option value="malware">Malware</option><option value="cloud">Cloud</option><option value="insider">Insider</option>
            </select>
            <select value={libStatus} onChange={e => { setLibStatus(e.target.value); loaded.current['library'] = false; }} className="g-select text-xs">
              <option value="">All Statuses</option>
              <option value="active">Active</option><option value="draft">Draft</option>
              <option value="completed">Completed</option><option value="archived">Archived</option>
            </select>
            <button onClick={loadLibrary} className="g-btn g-btn-ghost text-xs"><RefreshCw className="h-3 w-3" /></button>
          </div>

          <div className="g-card overflow-hidden">
            <table className="g-table w-full text-xs">
              <thead className="g-thead">
                <tr>
                  <th className="g-tr">Hunt Name</th><th className="g-tr">Category</th>
                  <th className="g-tr">Author</th><th className="g-tr">MITRE</th>
                  <th className="g-tr">Priority</th><th className="g-tr">Status</th>
                  <th className="g-tr">Success%</th><th className="g-tr">Last Run</th>
                  <th className="g-tr">Version</th><th className="g-tr"></th>
                </tr>
              </thead>
              <tbody>
                {filteredLibrary.length === 0 && (
                  <tr><td colSpan={10} className="g-tr text-center py-8" style={{ color: 'var(--text-3)' }}>No hunts found. Click "New Hunt" to create one.</td></tr>
                )}
                {filteredLibrary.map(h => (
                  <tr key={h.id} className="hover:bg-[var(--glass-bg)] cursor-pointer" onClick={() => openHuntInWorkspace(h)}>
                    <td className="g-tr max-w-[180px]">
                      <div>
                        <p className="font-medium truncate" style={{ color: 'var(--text-1)' }}>{h.name}</p>
                        {h.is_continuous && <span className="text-[9px] px-1 rounded" style={{ background: 'rgba(168,85,247,0.15)', color: '#a855f7' }}>⟳ continuous</span>}
                      </div>
                    </td>
                    <td className="g-tr" style={{ color: 'var(--text-2)' }}><span className="capitalize">{h.category}</span>{h.sub_category ? <span style={{ color: 'var(--text-3)' }}>/{h.sub_category}</span> : ''}</td>
                    <td className="g-tr" style={{ color: 'var(--text-3)' }}>{h.author}</td>
                    <td className="g-tr font-mono" style={{ color: 'var(--accent)', fontSize: 10 }}>{h.mitre_techniques?.split(',')[0] || '—'}</td>
                    <td className="g-tr"><SevBadge sev={h.priority} /></td>
                    <td className="g-tr"><StatusBadge status={h.status} /></td>
                    <td className="g-tr" style={{ color: h.success_rate >= 50 ? '#22c55e' : '#fbbf24' }}>
                      {h.run_count > 0 ? `${Math.round(h.success_rate)}%` : '—'}
                    </td>
                    <td className="g-tr" style={{ color: 'var(--text-3)' }}>{h.last_run_at ? timeAgo(h.last_run_at) : '—'}</td>
                    <td className="g-tr" style={{ color: 'var(--text-3)' }}>v{h.version}</td>
                    <td className="g-tr">
                      <div className="flex gap-1.5" onClick={e => e.stopPropagation()}>
                        <button onClick={() => openHuntInWorkspace(h)} className="g-btn g-btn-ghost text-[10px] px-1.5 py-0.5"><Eye className="h-3 w-3" /></button>
                        <button onClick={async () => { await threatHuntAPI.execute(h.id); notify('Hunt executed'); }} className="g-btn g-btn-ghost text-[10px] px-1.5 py-0.5"><Play className="h-3 w-3" /></button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Categories ──────────────────────────────────────────────────────── */}
      {tab === 'categories' && (
        <div className="space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {(categories?.categories || []).map((cat: any) => (
              <div key={cat.key} className="g-card p-4">
                <div className="flex items-center gap-2 mb-3">
                  <span className="text-lg">{cat.icon}</span>
                  <div>
                    <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{cat.label}</p>
                    <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{cat.total_count} hunts configured</p>
                  </div>
                </div>
                <div className="space-y-1">
                  {cat.sub_categories?.map((sub: any) => (
                    <div key={sub.key} className="flex items-center gap-2 py-1 border-b" style={{ borderColor: 'var(--border)' }}>
                      <span className="flex-1 text-xs" style={{ color: 'var(--text-2)' }}>{sub.label}</span>
                      {sub.count > 0 && <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>{sub.count}</span>}
                      <button onClick={() => loadCategoryIntoWorkspace(cat.key, sub.key)}
                        className="g-btn g-btn-ghost text-[10px] px-1.5 py-0.5">
                        <Plus className="h-2.5 w-2.5" />
                      </button>
                      {sub.count > 0 && (
                        <button onClick={() => { setLibCategory(cat.key); setTab('library'); }}
                          className="g-btn g-btn-ghost text-[10px] px-1.5 py-0.5">
                          <Eye className="h-2.5 w-2.5" />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Workspace (create / view-edit hunt) ──────────────────────────────── */}
      {tab === 'workspace' && (
        <div className="space-y-4">
          {/* Action bar */}
          <div className="flex items-center gap-2 flex-wrap">
            <p className="text-sm font-semibold flex-1 truncate" style={{ color: 'var(--text-1)' }}>
              {isEdit ? `Editing: ${form.name}` : 'New Threat Hunt'}
              {isEdit && form.version && <span className="ml-2 text-[10px]" style={{ color: 'var(--text-3)' }}>v{form.version} · {form.review_status}</span>}
            </p>
            <button onClick={createOrUpdateHunt} disabled={saving} className="g-btn g-btn-primary text-xs flex items-center gap-1.5">
              <Save className="h-3 w-3" />{saving ? 'Saving…' : isEdit ? 'Update Hunt' : 'Save Hunt'}
            </button>
            {isEdit && form.id && (
              <button onClick={executeHunt} disabled={executing} className="g-btn text-xs flex items-center gap-1.5" style={{ background: 'rgba(34,197,94,0.12)', color: '#22c55e', border: '1px solid rgba(34,197,94,0.3)' }}>
                <Play className="h-3 w-3" />{executing ? 'Running…' : 'Execute Now'}
              </button>
            )}
            {isEdit && form.id && (
              <button onClick={() => { setResponseFindingId(form.id!); setResponseTarget(form.name || ''); setShowResponseModal(true); }}
                className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
                <Zap className="h-3 w-3" /> Respond
              </button>
            )}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Left: Hunt Info */}
            <div className="space-y-3">
              {/* Basic info */}
              <div className="g-card p-4 space-y-3">
                <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Hunt Info</p>
                <div>
                  <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Name *</label>
                  <input value={form.name || ''} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} className="g-input w-full text-sm" placeholder="e.g. PowerShell Encoded Command Hunt" />
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Category</label>
                    <select value={form.category || 'ttp'} onChange={e => setForm(p => ({ ...p, category: e.target.value }))} className="g-select w-full text-xs">
                      <option value="ioc">IOC Hunt</option><option value="ttp">TTP Hunt</option>
                      <option value="actor">Actor Hunt</option><option value="malware">Malware Hunt</option>
                      <option value="cloud">Cloud Hunt</option><option value="insider">Insider Hunt</option>
                      <option value="custom">Custom</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Sub-Category</label>
                    <input value={form.sub_category || ''} onChange={e => setForm(p => ({ ...p, sub_category: e.target.value }))} className="g-input w-full text-xs" placeholder="powershell, apt29, lsass…" />
                  </div>
                  <div>
                    <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Priority</label>
                    <select value={form.priority || 'high'} onChange={e => setForm(p => ({ ...p, priority: e.target.value }))} className="g-select w-full text-xs">
                      {['critical','high','medium','low'].map(v => <option key={v} value={v}>{v}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Risk Level</label>
                    <select value={form.risk_level || 'high'} onChange={e => setForm(p => ({ ...p, risk_level: e.target.value }))} className="g-select w-full text-xs">
                      {['critical','high','medium','low'].map(v => <option key={v} value={v}>{v}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Status</label>
                    <select value={form.status || 'active'} onChange={e => setForm(p => ({ ...p, status: e.target.value }))} className="g-select w-full text-xs">
                      {['active','draft','completed','archived'].map(v => <option key={v} value={v}>{v}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Assigned Analyst</label>
                    <input value={form.assigned_analyst || ''} onChange={e => setForm(p => ({ ...p, assigned_analyst: e.target.value }))} className="g-input w-full text-xs" placeholder="analyst-1" />
                  </div>
                </div>
                <div>
                  <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>MITRE Techniques (comma-separated)</label>
                  <input value={form.mitre_techniques || ''} onChange={e => setForm(p => ({ ...p, mitre_techniques: e.target.value }))} className="g-input w-full text-xs font-mono" placeholder="T1059.001,T1071.001" />
                </div>
                <div>
                  <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Description</label>
                  <textarea value={form.description || ''} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} className="g-input w-full text-xs resize-none" rows={2} />
                </div>
              </div>

              {/* Hypothesis */}
              <div className="g-card p-4 space-y-3">
                <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Hunt Hypothesis</p>
                <div>
                  <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Hypothesis</label>
                  <textarea value={form.hypothesis || ''} onChange={e => setForm(p => ({ ...p, hypothesis: e.target.value }))} className="g-input w-full text-sm resize-none" rows={3}
                    placeholder="An attacker may have used PowerShell with encoded commands after phishing to establish persistence." />
                </div>
                <div>
                  <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Objective</label>
                  <textarea value={form.objective || ''} onChange={e => setForm(p => ({ ...p, objective: e.target.value }))} className="g-input w-full text-xs resize-none" rows={2} placeholder="What are you trying to find?" />
                </div>
                <div>
                  <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Expected Findings</label>
                  <textarea value={form.expected_findings || ''} onChange={e => setForm(p => ({ ...p, expected_findings: e.target.value }))} className="g-input w-full text-xs resize-none" rows={2} placeholder="What evidence would confirm the hypothesis?" />
                </div>
                <div>
                  <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Success Criteria</label>
                  <input value={form.success_criteria || ''} onChange={e => setForm(p => ({ ...p, success_criteria: e.target.value }))} className="g-input w-full text-xs" placeholder="Find >0 encoded PS invocations not tied to approved scripts" />
                </div>
              </div>

              {/* Scope */}
              <div className="g-card p-4 space-y-2">
                <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Hunt Scope</p>
                <div className="flex flex-wrap gap-2">
                  {SCOPES.map(s => (
                    <button key={s} onClick={() => toggleScope(s)}
                      className="text-xs px-2.5 py-1 rounded-lg transition-all capitalize"
                      style={{ background: scopeList.includes(s) ? 'var(--accent-glow)' : 'var(--glass-bg)', border: `1px solid ${scopeList.includes(s) ? 'var(--accent-border)' : 'var(--border)'}`, color: scopeList.includes(s) ? 'var(--accent)' : 'var(--text-3)' }}>
                      {s.replace('_', ' ')}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Right: Query + Execution + AI */}
            <div className="space-y-3">
              {/* Query */}
              <div className="g-card p-4 space-y-3">
                <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Query</p>
                <div className="flex gap-2">
                  <select value={form.query_type || 'log'} onChange={e => setForm(p => ({ ...p, query_type: e.target.value }))} className="g-select text-xs">
                    {QUERY_TYPES.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
                  </select>
                  <div className="flex gap-1.5 text-[10px]" style={{ color: 'var(--text-3)' }}>
                    <a href="/hunt-workbench" className="g-btn g-btn-ghost px-1.5 flex items-center gap-1"><ExternalLink className="h-2.5 w-2.5" />Workbench</a>
                    <a href="/log-search" className="g-btn g-btn-ghost px-1.5 flex items-center gap-1"><ExternalLink className="h-2.5 w-2.5" />Log Search</a>
                    <a href="/elastic-query" className="g-btn g-btn-ghost px-1.5 flex items-center gap-1"><ExternalLink className="h-2.5 w-2.5" />ES Query</a>
                  </div>
                </div>
                <textarea value={form.query_text || ''} onChange={e => setForm(p => ({ ...p, query_text: e.target.value }))} className="g-input w-full font-mono text-xs resize-none" rows={4}
                  placeholder="Enter search term, query string, or IOC value…" />
              </div>

              {/* Scheduling */}
              <div className="g-card p-4 space-y-3">
                <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Execution & Scheduling</p>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Schedule Type</label>
                    <select value={form.schedule_type || 'manual'} onChange={e => setForm(p => ({ ...p, schedule_type: e.target.value }))} className="g-select w-full text-xs">
                      <option value="manual">Manual</option><option value="immediate">Immediate</option>
                      <option value="daily">Daily</option><option value="weekly">Weekly</option>
                      <option value="monthly">Monthly</option><option value="on_ioc_update">On IOC Update</option>
                      <option value="after_incident">After Incident</option><option value="continuous">Continuous</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Cron Schedule</label>
                    <input value={form.cron_schedule || ''} onChange={e => setForm(p => ({ ...p, cron_schedule: e.target.value }))} className="g-input w-full text-xs font-mono" placeholder="0 6 * * 1" />
                  </div>
                </div>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" checked={!!form.is_continuous} onChange={e => setForm(p => ({ ...p, is_continuous: e.target.checked }))} className="rounded" />
                  <span className="text-xs" style={{ color: 'var(--text-2)' }}>Continuous Hunting</span>
                </label>
                {form.is_continuous && (
                  <div>
                    <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Interval</label>
                    <select value={form.continuous_interval || '1h'} onChange={e => setForm(p => ({ ...p, continuous_interval: e.target.value }))} className="g-select w-full text-xs">
                      <option value="30m">Every 30 minutes</option><option value="1h">Every hour</option>
                      <option value="4h">Every 4 hours</option><option value="8h">Every 8 hours</option>
                      <option value="24h">Every 24 hours</option>
                    </select>
                  </div>
                )}
              </div>

              {/* Execute result */}
              {executeResult && (
                <div className="g-card p-4" style={{ borderColor: executeResult.hits > 0 ? '#f8514944' : '#22c55e44', border: '1px solid' }}>
                  <div className="flex items-center gap-2 mb-2">
                    {executeResult.hits > 0 ? <AlertTriangle className="h-4 w-4" style={{ color: '#f85149' }} /> : <CheckCircle className="h-4 w-4" style={{ color: '#22c55e' }} />}
                    <span className="text-sm font-semibold" style={{ color: executeResult.hits > 0 ? '#f85149' : '#22c55e' }}>
                      {executeResult.hits} hit{executeResult.hits !== 1 ? 's' : ''} found
                    </span>
                  </div>
                  {executeResult.hits > 0 && (
                    <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
                      Findings created automatically. <button onClick={() => setTab('findings')} style={{ color: 'var(--accent)' }}>View findings →</button>
                    </p>
                  )}
                </div>
              )}

              {/* Ad-hoc query runner */}
              <div className="g-card p-4 space-y-2">
                <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Ad-hoc Query Runner</p>
                <div className="flex gap-2">
                  <select value={adHocType} onChange={e => setAdHocType(e.target.value)} className="g-select text-xs">
                    {QUERY_TYPES.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
                  </select>
                </div>
                <div className="flex gap-2">
                  <input value={adHocText} onChange={e => setAdHocText(e.target.value)} onKeyDown={e => e.key === 'Enter' && runAdHoc()} className="g-input flex-1 text-xs font-mono" placeholder="Search term…" />
                  <button onClick={runAdHoc} disabled={adHocRunning || !adHocText} className="g-btn g-btn-ghost text-xs flex items-center gap-1">
                    <Play className="h-3 w-3" />{adHocRunning ? '…' : 'Run'}
                  </button>
                </div>
                {adHocResult && (
                  <p className="text-[11px]" style={{ color: adHocResult.hits > 0 ? '#f85149' : '#22c55e' }}>
                    {adHocResult.hits} hits in {adHocResult.duration_ms}ms
                  </p>
                )}
              </div>

              {/* AI Assistant */}
              <div className="g-card p-4 space-y-3">
                <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>AI Hunt Assistant</p>
                <select value={aiAction} onChange={e => setAiAction(e.target.value)} className="g-select w-full text-xs">
                  <option value="suggest">Suggest Hunts</option>
                  <option value="improve_hypothesis">Improve Hypothesis</option>
                  <option value="generate_query">Generate Query</option>
                  <option value="summarize">Summarize Findings</option>
                  <option value="recommend">Recommend Next Hunt</option>
                  <option value="generate_sigma">Generate Sigma Rule</option>
                </select>
                <button onClick={runAI} disabled={aiRunning} className="g-btn g-btn-ghost text-xs w-full flex items-center justify-center gap-1.5">
                  <Brain className="h-3.5 w-3.5" />{aiRunning ? 'Thinking…' : 'Ask AI'}
                </button>
                {aiResult && (
                  <div className="rounded-lg p-3 space-y-2" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    {aiResult.improved_hypothesis && <p className="text-[11px]" style={{ color: 'var(--text-2)' }}><strong>Hypothesis:</strong> {aiResult.improved_hypothesis}</p>}
                    {aiResult.executive_summary && <p className="text-[11px]" style={{ color: 'var(--text-2)' }}>{aiResult.executive_summary}</p>}
                    {aiResult.kql_query && <p className="text-[10px] font-mono" style={{ color: 'var(--accent)' }}>{aiResult.kql_query}</p>}
                    {aiResult.sigma_rule && <p className="text-[10px] font-mono whitespace-pre-wrap" style={{ color: 'var(--text-2)' }}>{aiResult.sigma_rule.slice(0, 200)}…</p>}
                    {(aiResult.recommended_actions || []).slice(0, 3).map((a: string, i: number) => (
                      <p key={i} className="text-[11px]" style={{ color: 'var(--text-3)' }}>• {a}</p>
                    ))}
                    {(aiResult.next_hunts || []).slice(0, 2).map((h: any, i: number) => (
                      <p key={i} className="text-[11px]" style={{ color: 'var(--accent)' }}>↳ {h.name} [{h.mitre_technique}]</p>
                    ))}
                    <button onClick={applyAIToForm} className="g-btn g-btn-ghost text-[10px] w-full">Apply to Form</button>
                  </div>
                )}
              </div>

              {/* Comments */}
              {isEdit && (
                <div className="g-card p-4 space-y-2">
                  <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Comments ({comments.length})</p>
                  <div className="max-h-40 overflow-y-auto space-y-2">
                    {comments.map(co => (
                      <div key={co.id} className="rounded-lg px-3 py-2" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                        <div className="flex items-center gap-2 mb-0.5">
                          <span className="text-[10px] font-semibold" style={{ color: 'var(--accent)' }}>{co.author}</span>
                          <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(co.created_at)}</span>
                        </div>
                        <p className="text-[11px]" style={{ color: 'var(--text-2)' }}>{co.content}</p>
                      </div>
                    ))}
                  </div>
                  <div className="flex gap-2">
                    <input value={newComment} onChange={e => setNewComment(e.target.value)} onKeyDown={e => e.key === 'Enter' && addComment()} className="g-input flex-1 text-xs" placeholder="Add comment…" />
                    <button onClick={addComment} className="g-btn g-btn-ghost text-xs">Add</button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Findings ─────────────────────────────────────────────────────────── */}
      {tab === 'findings' && (
        <div className="space-y-3">
          <div className="flex gap-2 flex-wrap items-center">
            <select value={findSev} onChange={e => setFindSev(e.target.value)} className="g-select text-xs">
              <option value="">All Severities</option>
              {['critical','high','medium','low'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <select value={findStatus} onChange={e => setFindStatus(e.target.value)} className="g-select text-xs">
              <option value="">All Statuses</option>
              {['open','acknowledged','false_positive','confirmed'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <button onClick={() => { loaded.current['findings'] = false; threatHuntAPI.findings().then(r => setFindings(r.data || [])); }} className="g-btn g-btn-ghost text-xs"><RefreshCw className="h-3 w-3" /></button>
            <span className="text-xs ml-auto" style={{ color: 'var(--text-3)' }}>{filteredFindings.length} findings</span>
          </div>

          <div className="space-y-2">
            {filteredFindings.length === 0 && (
              <div className="g-card p-10 text-center">
                <CheckCircle className="mx-auto h-8 w-8 mb-2 opacity-20" style={{ color: '#22c55e' }} />
                <p className="text-sm" style={{ color: 'var(--text-3)' }}>No findings. Execute hunts to generate findings.</p>
              </div>
            )}
            {filteredFindings.map(f => (
              <div key={f.id} className="g-card p-4">
                <div className="flex items-start gap-3 mb-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                      <SevBadge sev={f.severity} />
                      <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)' }}>confidence: {f.confidence}</span>
                      {f.mitre_technique && <span className="text-[10px] font-mono" style={{ color: 'var(--accent)' }}>{f.mitre_technique}</span>}
                      <StatusBadge status={f.status} />
                    </div>
                    <p className="text-sm font-semibold mt-1" style={{ color: 'var(--text-1)' }}>{f.title}</p>
                    <p className="text-[11px] mt-0.5" style={{ color: 'var(--text-3)' }}>{f.description}</p>
                    <div className="flex items-center gap-3 mt-1 text-[10px]" style={{ color: 'var(--text-3)' }}>
                      <span>Host: <strong style={{ color: 'var(--text-2)' }}>{f.affected_host || '—'}</strong></span>
                      <span>User: <strong style={{ color: 'var(--text-2)' }}>{f.affected_user || '—'}</strong></span>
                      {f.ioc_value && <span>IOC: <strong className="font-mono" style={{ color: 'var(--accent)' }}>{f.ioc_value}</strong></span>}
                      <span>Hunt: <strong style={{ color: 'var(--text-2)' }}>{f.hunt_name}</strong></span>
                      <span>{timeAgo(f.created_at)}</span>
                    </div>
                  </div>
                  <div className="flex flex-col gap-1 shrink-0">
                    <button onClick={() => ackFinding(f.id, 'acknowledged')} className="g-btn g-btn-ghost text-[10px] px-1.5 py-0.5">Ack</button>
                    <button onClick={() => ackFinding(f.id, 'false_positive')} className="g-btn g-btn-ghost text-[10px] px-1.5 py-0.5">FP</button>
                    <button onClick={() => { setResponseFindingId(f.id); setResponseTarget(f.affected_host); setShowResponseModal(true); }}
                      className="g-btn text-[10px] px-1.5 py-0.5" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' }}>
                      Respond
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── MITRE Coverage ────────────────────────────────────────────────────── */}
      {tab === 'mitre' && (
        <div className="space-y-3">
          <div className="flex items-center gap-4 mb-2">
            <KPICard label="Coverage" value={mitre ? `${mitre.overall_coverage}%` : '—'} color="var(--accent)" />
            <KPICard label="Covered" value={mitre?.covered_count ?? '—'} color="#22c55e" />
            <KPICard label="Untested" value={mitre ? mitre.total_count - mitre.covered_count : '—'} />
            <div className="flex items-center gap-3 text-[10px]" style={{ color: 'var(--text-3)' }}>
              <span style={{ color: '#22c55e' }}>■ Frequent</span>
              <span style={{ color: '#fbbf24' }}>■ Covered</span>
              <span>■ Untested</span>
            </div>
          </div>
          {(mitre?.tactics || []).map((tac: any) => (
            <div key={tac.id} className="g-card p-3">
              <div className="flex items-center gap-3 mb-2">
                <span className="text-[10px] font-mono w-16 shrink-0" style={{ color: 'var(--text-3)' }}>{tac.id}</span>
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
                  <span key={tech.id} className="px-2 py-1 rounded text-[10px] font-mono"
                    style={{ background: tech.status === 'frequently_hunted' ? 'rgba(34,197,94,0.15)' : tech.status === 'covered' ? 'rgba(251,191,36,0.15)' : 'var(--glass-bg)', color: tech.status === 'frequently_hunted' ? '#22c55e' : tech.status === 'covered' ? '#fbbf24' : 'var(--text-3)', border: `1px solid ${tech.status === 'frequently_hunted' ? 'rgba(34,197,94,0.3)' : tech.status === 'covered' ? 'rgba(251,191,36,0.3)' : 'var(--border)'}` }}
                    title={`${tech.id}: ${tech.name}`}>
                    {tech.id}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── Analytics ─────────────────────────────────────────────────────────── */}
      {tab === 'analytics' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="g-card p-4">
              <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-2)' }}>Hunts by Category</p>
              <div className="space-y-2">
                {(metrics?.by_category || []).map((c: any) => (
                  <div key={c.category} className="flex items-center gap-2">
                    <span className="text-xs w-20 capitalize" style={{ color: 'var(--text-3)' }}>{c.category}</span>
                    <div className="flex-1 h-2 rounded-full" style={{ background: 'var(--glass-bg-2)' }}>
                      <div className="h-full rounded-full" style={{ background: 'var(--accent)', width: `${Math.min(100, c.total_hits * 4)}%` }} />
                    </div>
                    <span className="text-[10px] w-8 text-right" style={{ color: 'var(--text-3)' }}>{c.total_hits}</span>
                    <span className="text-[10px] w-10 text-right" style={{ color: c.success_rate >= 50 ? '#22c55e' : '#fbbf24' }}>{Math.round(c.success_rate)}%</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="g-card p-4">
              <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-2)' }}>Analyst Performance</p>
              <table className="g-table w-full text-xs">
                <thead className="g-thead"><tr><th className="g-tr">Analyst</th><th className="g-tr">Hunts</th><th className="g-tr">Total Hits</th><th className="g-tr">Success</th></tr></thead>
                <tbody>
                  {(metrics?.by_analyst || []).map((a: any) => (
                    <tr key={a.analyst} className="hover:bg-[var(--glass-bg)]">
                      <td className="g-tr font-medium" style={{ color: 'var(--text-1)' }}>{a.analyst}</td>
                      <td className="g-tr" style={{ color: 'var(--text-2)' }}>{a.hunt_count}</td>
                      <td className="g-tr" style={{ color: a.total_hits > 0 ? '#f85149' : 'var(--text-3)' }}>{a.total_hits}</td>
                      <td className="g-tr" style={{ color: a.success_rate >= 50 ? '#22c55e' : '#fbbf24' }}>{Math.round(a.success_rate)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <div className="g-card p-4">
            <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-2)' }}>14-Day Finding Trend</p>
            <SparkTrend data={metrics?.daily || []} key1="findings" />
          </div>
        </div>
      )}

      {/* ── Automation ────────────────────────────────────────────────────────── */}
      {tab === 'automation' && (
        <div className="space-y-4">
          <p className="text-xs" style={{ color: 'var(--text-3)' }}>Configure automatic actions when hunt findings are created.</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {[
              { trigger: 'Finding created (Critical)', action: 'Create Alert', status: 'active', desc: 'Automatically creates a critical alert in the alerts dashboard' },
              { trigger: 'Finding created (High/Critical)', action: 'Create Incident', status: 'active', desc: 'Opens an incident for analyst triage' },
              { trigger: 'IOC match found', action: 'Block IOC', status: 'active', desc: 'Adds the IOC to all active blocklists' },
              { trigger: '3+ findings same host', action: 'Isolate Host', status: 'inactive', desc: 'Sends isolation command to agent via SOAR' },
              { trigger: 'Hunt completed (any result)', action: 'Notify Team', status: 'active', desc: 'Sends Slack/email notification to the hunt team' },
              { trigger: 'Continuous hunt hit', action: 'Run SOAR Playbook', status: 'inactive', desc: 'Triggers the configured SOAR playbook for automated response' },
              { trigger: 'Finding confirmed', action: 'Create Case', status: 'inactive', desc: 'Creates a case in the case management system' },
              { trigger: 'Actor IOC found', action: 'Enrich Threat Intel', status: 'active', desc: 'Queries threat intel feeds for related IOCs and campaigns' },
            ].map(rule => (
              <div key={rule.trigger} className="g-card p-4 flex items-start gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)' }}>IF</span>
                    <span className="text-xs font-medium" style={{ color: 'var(--text-2)' }}>{rule.trigger}</span>
                  </div>
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>THEN</span>
                    <span className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{rule.action}</span>
                  </div>
                  <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{rule.desc}</p>
                </div>
                <div className="shrink-0">
                  <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: rule.status === 'active' ? 'rgba(34,197,94,0.15)' : 'var(--glass-bg-2)', color: rule.status === 'active' ? '#22c55e' : 'var(--text-3)' }}>{rule.status}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Templates ────────────────────────────────────────────────────────── */}
      {tab === 'templates' && (
        <div className="space-y-3">
          <p className="text-xs" style={{ color: 'var(--text-3)' }}>Built-in hunt templates. Click "Use" to pre-fill the workspace.</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {BUILTIN_TEMPLATES.map(tpl => (
              <div key={tpl.name} className="g-card p-4 space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{tpl.name}</p>
                  <SevBadge sev={tpl.priority} />
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[10px] capitalize px-1.5 py-0.5 rounded" style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)' }}>{tpl.category}</span>
                  <span className="text-[10px] font-mono" style={{ color: 'var(--accent)' }}>{tpl.mitre_techniques.split(',')[0]}</span>
                </div>
                <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{tpl.hypothesis.slice(0, 100)}…</p>
                <div className="flex gap-2">
                  <button onClick={() => applyTemplate(tpl)} className="g-btn g-btn-primary text-xs flex-1 justify-center flex items-center gap-1">
                    <Target className="h-3 w-3" /> Use Template
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </RootLayout>
  );
}
