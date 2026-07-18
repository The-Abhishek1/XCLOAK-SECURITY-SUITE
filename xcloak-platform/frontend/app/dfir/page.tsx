'use client';

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { dfirAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import { Activity, BookOpen, Brain, ChevronDown, ChevronRight, Clock, Database, Download, Eye, FileText, GitBranch, Globe, Package, Play, Plus, Save, Search, Shield, Trash2, X, Zap } from '@/lib/icon-stubs';

// ── Types ────────────────────────────────────────────────────────────────────

interface Investigation {
  id: number; investigation_id: string; case_id: string; title: string;
  incident_id: number; analyst: string; priority: string; status: string;
  classification: string; tags: string; notes: string; target_hosts: string;
  target_users: string; mitre_techniques: string; root_cause: string;
  executive_summary: string; version: number; evidence_count: number;
  created_at: string; updated_at: string;
}
interface Evidence {
  id: number; evidence_id: string; investigation_id: number; type: string;
  label: string; description: string; source_host: string; collector: string;
  sha256: string; size_bytes: number; status: string; collected_at: string;
}
interface TimelineEvent {
  id: number; event_time: string; event_type: string; source: string;
  host: string; user_name: string; description: string; severity: string;
  mitre_technique: string; is_manual: boolean;
}
interface NotebookEntry {
  id: number; entry_type: string; title: string; content: string;
  author: string; tags: string; created_at: string;
}

// ── Shared components ─────────────────────────────────────────────────────────

const SEV: Record<string, string> = { critical: '#f85149', high: '#fb923c', medium: '#fbbf24', low: '#22c55e', info: '#60a5fa' };
const EVT_COLORS: Record<string, string> = { alert: '#f85149', command: '#a855f7', process: '#fb923c', registry: '#fbbf24', network: '#60a5fa', analyst: '#22c55e' };

function SevBadge({ s }: { s: string }) {
  const c = SEV[s] || '#60a5fa';
  return <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-full" style={{ background: `${c}22`, color: c }}>{s}</span>;
}
function StatusBadge({ s }: { s: string }) {
  const map: Record<string, string> = { open: '#f85149', in_progress: '#fbbf24', closed: '#22c55e', resolved: '#22c55e', analyzed: '#22c55e', collected: '#60a5fa', pending: '#fbbf24', completed: '#22c55e' };
  const c = map[s] || 'var(--text-3)';
  return <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: `${c}22`, color: c }}>{s.replace(/_/g, ' ')}</span>;
}
function KPICard({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <div className="g-card p-4">
      <p className="text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>{label}</p>
      <p className="text-2xl font-bold" style={{ color: color || 'var(--text-1)' }}>{value}</p>
    </div>
  );
}
function formatBytes(b: number) {
  if (b > 1e9) return `${(b / 1e9).toFixed(1)} GB`;
  if (b > 1e6) return `${(b / 1e6).toFixed(1)} MB`;
  if (b > 1e3) return `${(b / 1e3).toFixed(0)} KB`;
  return `${b} B`;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const TABS = [
  { key: 'dashboard',      label: 'Dashboard',      icon: Activity },
  { key: 'investigations', label: 'Investigations',  icon: Search },
  { key: 'collect',        label: 'Collect',         icon: Package },
  { key: 'evidence',       label: 'Evidence',        icon: Database },
  { key: 'timeline',       label: 'Timeline',        icon: Clock },
  { key: 'process-tree',   label: 'Process Tree',    icon: GitBranch },
  { key: 'forensics',      label: 'Forensics',       icon: Shield },
  { key: 'notebook',       label: 'Notebook',        icon: BookOpen },
  { key: 'reports',        label: 'Reports',         icon: FileText },
] as const;
type TabKey = typeof TABS[number]['key'];

const ARTIFACT_TYPES: Record<string, string[]> = {
  windows: ['processes','connections','event_logs','file_hashes','alerts','packages','users','registry','prefetch','amcache','shimcache','srum','jump_lists','mft'],
  linux:   ['processes','connections','event_logs','packages','users','bash_history','cron','journal','audit_log','ssh_keys'],
  macos:   ['processes','connections','event_logs','packages','users','unified_logs','launch_agents','launch_daemons'],
};

const FORENSIC_TABS = ['file','malware','network','artifacts','registry','browser'];
const REPORT_TYPES  = ['dfir','executive','timeline','evidence','malware','chain_of_custody'];
const RESPONSE_ACTS = ['isolate_host','kill_process','delete_file','quarantine_file','block_ip','run_soar','open_incident','open_case'];

const EMPTY_INV: Partial<Investigation> = {
  title: '', case_id: '', incident_id: 0, analyst: '', priority: 'high', status: 'open',
  classification: 'TLP:AMBER', tags: '', notes: '', target_hosts: '', target_users: '',
  mitre_techniques: '', root_cause: '', executive_summary: '',
};

// ── Page ──────────────────────────────────────────────────────────────────────

export default function DFIRPage() {
  const [tab, setTab] = useState<TabKey>('dashboard');
  const loaded = useRef<Partial<Record<TabKey, boolean>>>({});

  const [dash, setDash]                   = useState<any>(null);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [analytics, setAnalytics]         = useState<any>(null);
  const [activeInv, setActiveInv]         = useState<Investigation | null>(null);
  const [evidence, setEvidence]           = useState<Evidence[]>([]);
  const [timeline, setTimeline]           = useState<TimelineEvent[]>([]);
  const [processTree, setProcessTree]     = useState<any>(null);
  const [network, setNetwork]             = useState<any[]>([]);
  const [notebook, setNotebook]           = useState<NotebookEntry[]>([]);
  const [tasks, setTasks]                 = useState<any[]>([]);
  const [threatIntel, setThreatIntel]     = useState<any>(null);
  const [custody, setCustody]             = useState<any[]>([]);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<number | null>(null);

  // Form
  const [invForm, setInvForm]             = useState<Partial<Investigation>>({ ...EMPTY_INV });
  const [isEditInv, setIsEditInv]         = useState(false);
  const [savingInv, setSavingInv]         = useState(false);

  // Collect
  const [collectHost, setCollectHost]     = useState('');
  const [collectArtifacts, setCollectArtifacts] = useState<string[]>(['processes','connections','event_logs']);
  const [collectPlatform, setCollectPlatform]   = useState<'windows'|'linux'|'macos'>('windows');
  const [collecting, setCollecting]       = useState(false);
  const [collectResult, setCollectResult] = useState<any>(null);

  // Timeline
  const [tlFilter, setTlFilter]           = useState('');
  const [tlReplay, setTlReplay]           = useState(false);
  const [tlReplayIdx, setTlReplayIdx]     = useState(0);
  const [manualEvent, setManualEvent]     = useState({ description: '', event_type: 'analyst', severity: 'info' });
  const [addingEvent, setAddingEvent]     = useState(false);

  // Process tree
  const [expandedPids, setExpandedPids]   = useState<Set<number>>(new Set([1032, 2048, 2144, 2312]));

  // Forensics
  const [ftab, setFtab]                   = useState('file');
  const [fileHash, setFileHash]           = useState('');
  const [fileAnalysis, setFileAnalysis]   = useState<any>(null);
  const [fileAnalyzing, setFileAnalyzing] = useState(false);
  const [malwareHash, setMalwareHash]     = useState('');
  const [malwareName, setMalwareName]     = useState('');
  const [malwareAnalysis, setMalwareAnalysis] = useState<any>(null);
  const [malwareAnalyzing, setMalwareAnalyzing] = useState(false);
  const [artifactPlatform, setArtifactPlatform] = useState('windows');
  const [artifactType, setArtifactType]   = useState('');
  const [artifactData, setArtifactData]   = useState<any>(null);
  const [netProto, setNetProto]           = useState('');

  // Notebook
  const [noteForm, setNoteForm]           = useState({ entry_type: 'note', title: '', content: '', tags: '' });

  // AI
  const [aiAction, setAiAction]           = useState('summarize');
  const [aiRunning, setAiRunning]         = useState(false);
  const [aiResult, setAiResult]           = useState<any>(null);
  const [aiPrompt, setAiPrompt]           = useState('');

  // Memory
  const [memoryResult, setMemoryResult]   = useState<any>(null);
  const [memoryRunning, setMemoryRunning] = useState(false);

  // Reports
  const [reportType, setReportType]       = useState('dfir');
  const [reportResult, setReportResult]   = useState<any>(null);
  const [reportRunning, setReportRunning] = useState(false);

  // Response modal
  const [responseAction, setResponseAction] = useState('isolate_host');
  const [responseTarget, setResponseTarget] = useState('');
  const [showResponse, setShowResponse]   = useState(false);

  // Search
  const [searchQ, setSearchQ]             = useState('');
  const [searchResults, setSearchResults] = useState<any>(null);

  // Inv filters
  const [invSearch, setInvSearch]         = useState('');
  const [invStatusFilter, setInvStatusFilter] = useState('');

  const [toast, setToast] = useState<string | null>(null);
  const notify = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 3000); };

  // ── Data loading ───────────────────────────────────────────────────────────

  const loadInvestigations = useCallback(async () => {
    const r = await dfirAPI.investigations({ status: invStatusFilter || undefined });
    setInvestigations(r.data || []);
  }, [invStatusFilter]);

  useEffect(() => { loadInvestigations(); }, [loadInvestigations]);

  useEffect(() => {
    if (loaded.current[tab]) return;
    loaded.current[tab] = true;
    if (tab === 'dashboard') dfirAPI.dashboard().then(r => setDash(r.data));
    if (tab === 'reports')   dfirAPI.analytics().then(r => setAnalytics(r.data));
  }, [tab]);

  const loadInvestigationData = useCallback(async (inv: Investigation) => {
    setActiveInv(inv);
    const [evR, tlR, ptR, netR, nbR, taskR] = await Promise.all([
      dfirAPI.evidence({ investigation_id: inv.id }),
      dfirAPI.timeline(inv.id),
      dfirAPI.processTree(inv.id),
      dfirAPI.network(inv.id),
      dfirAPI.notebook(inv.id),
      dfirAPI.tasks(inv.id),
    ]);
    setEvidence(evR.data || []);
    setTimeline(tlR.data || []);
    setProcessTree(ptR.data || null);
    setNetwork(netR.data || []);
    setNotebook(nbR.data || []);
    setTasks(taskR.data || []);
  }, []);

  const openInvestigation = (inv: Investigation) => {
    setInvForm({ ...inv });
    setIsEditInv(true);
    loadInvestigationData(inv);
    setTab('investigations');
  };

  // ── Actions ────────────────────────────────────────────────────────────────

  const saveInvestigation = async () => {
    if (!invForm.title) { notify('Title required'); return; }
    setSavingInv(true);
    try {
      if (isEditInv && invForm.id) {
        await dfirAPI.update(invForm.id, invForm);
        notify('Investigation updated');
      } else {
        const r = await dfirAPI.create(invForm);
        if (r.data?.id) setInvForm(p => ({ ...p, id: r.data.id, investigation_id: r.data.investigation_id }));
        setIsEditInv(true);
        notify('Investigation created');
      }
      loaded.current['dashboard'] = false;
      loadInvestigations();
    } catch { notify('Save failed'); }
    setSavingInv(false);
  };

  const triggerCollect = async () => {
    if (!collectHost) { notify('Enter target host'); return; }
    const id = activeInv?.id || invForm.id;
    if (!id) { notify('Open an investigation first'); return; }
    setCollecting(true); setCollectResult(null);
    try {
      const r = await dfirAPI.collect(id, { target_host: collectHost, artifacts: collectArtifacts });
      setCollectResult(r.data);
      notify(`Collected ${r.data?.evidence_count ?? 0} artifact sets`);
      const [evR, taskR] = await Promise.all([
        dfirAPI.evidence({ investigation_id: id }),
        dfirAPI.tasks(id),
      ]);
      setEvidence(evR.data || []);
      setTasks(taskR.data || []);
    } catch { notify('Collection failed'); }
    setCollecting(false);
  };

  const toggleArtifact = (a: string) =>
    setCollectArtifacts(prev => prev.includes(a) ? prev.filter(x => x !== a) : [...prev, a]);

  const addTimelineEvent = async () => {
    const id = activeInv?.id || invForm.id;
    if (!id || !manualEvent.description) return;
    await dfirAPI.addTimelineEvent(id, manualEvent);
    const r = await dfirAPI.timeline(id);
    setTimeline(r.data || []);
    setManualEvent({ description: '', event_type: 'analyst', severity: 'info' });
    setAddingEvent(false);
    notify('Event added');
  };

  const runMemoryAnalysis = async () => {
    const id = activeInv?.id || invForm.id;
    if (!id) { notify('Open an investigation first'); return; }
    setMemoryRunning(true); setMemoryResult(null);
    try { const r = await dfirAPI.memoryAnalyze(id); setMemoryResult(r.data); }
    catch { notify('Memory analysis failed'); }
    setMemoryRunning(false);
  };

  const runFileAnalysis = async () => {
    if (!fileHash) { notify('Enter SHA256 or file path'); return; }
    setFileAnalyzing(true); setFileAnalysis(null);
    try { const r = await dfirAPI.fileAnalysis({ sha256: fileHash }); setFileAnalysis(r.data); }
    catch { notify('Analysis failed'); }
    setFileAnalyzing(false);
  };

  const runMalwareAnalysis = async () => {
    if (!malwareHash && !malwareName) { notify('Enter hash or name'); return; }
    setMalwareAnalyzing(true); setMalwareAnalysis(null);
    try { const r = await dfirAPI.malwareAnalysis({ sha256: malwareHash, file_name: malwareName }); setMalwareAnalysis(r.data); }
    catch { notify('Analysis failed'); }
    setMalwareAnalyzing(false);
  };

  const loadArtifacts = async () => {
    const id = activeInv?.id || invForm.id;
    if (!id) { notify('Open an investigation first'); return; }
    const r = await dfirAPI.artifacts(id, { platform: artifactPlatform, artifact: artifactType });
    setArtifactData(r.data);
  };

  const runAI = async () => {
    const id = activeInv?.id || invForm.id;
    if (!id) { notify('Open an investigation first'); return; }
    setAiRunning(true); setAiResult(null);
    try { const r = await dfirAPI.ai(id, { action: aiAction, prompt: aiPrompt }); setAiResult(r.data); }
    catch { notify('AI unavailable'); }
    setAiRunning(false);
  };

  const addNote = async () => {
    const id = activeInv?.id || invForm.id;
    if (!id || !noteForm.content) return;
    await dfirAPI.addNote(id, noteForm);
    const r = await dfirAPI.notebook(id);
    setNotebook(r.data || []);
    setNoteForm({ entry_type: 'note', title: '', content: '', tags: '' });
    notify('Note added');
  };

  const deleteNote = async (nid: number) => {
    await dfirAPI.deleteNote(nid);
    setNotebook(prev => prev.filter(n => n.id !== nid));
  };

  const generateReport = async () => {
    const id = activeInv?.id || invForm.id;
    if (!id) { notify('Open an investigation first'); return; }
    setReportRunning(true); setReportResult(null);
    try { const r = await dfirAPI.report(id, { report_type: reportType }); setReportResult(r.data); }
    catch { notify('Report failed'); }
    setReportRunning(false);
  };

  const sendResponse = async () => {
    const id = activeInv?.id || invForm.id || 0;
    await dfirAPI.response(id, { action: responseAction, target: responseTarget, target_type: 'host' });
    notify(`${responseAction} queued for ${responseTarget}`);
    setShowResponse(false);
  };

  const loadCustody = async (eid: number) => {
    setSelectedEvidenceId(eid);
    const r = await dfirAPI.custody(eid);
    setCustody(r.data || []);
  };

  const runSearch = async () => {
    if (!searchQ) return;
    const r = await dfirAPI.search(searchQ);
    setSearchResults(r.data);
  };

  const loadThreatIntel = async () => {
    const id = activeInv?.id || invForm.id;
    if (!id) { notify('Open an investigation first'); return; }
    const r = await dfirAPI.threatIntel(id);
    setThreatIntel(r.data);
  };

  // ── Derived ────────────────────────────────────────────────────────────────

  const filteredInvestigations = useMemo(() =>
    investigations.filter(inv =>
      !invSearch ||
      inv.title.toLowerCase().includes(invSearch.toLowerCase()) ||
      inv.tags?.toLowerCase().includes(invSearch.toLowerCase()) ||
      inv.target_hosts?.toLowerCase().includes(invSearch.toLowerCase())
    ), [investigations, invSearch]);

  const filteredTimeline = useMemo(() =>
    timeline.filter(e => !tlFilter || e.event_type === tlFilter), [timeline, tlFilter]);

  const replayEvents = useMemo(() =>
    [...filteredTimeline].sort((a, b) => new Date(a.event_time).getTime() - new Date(b.event_time).getTime()),
    [filteredTimeline]);

  // ── Process tree node ─────────────────────────────────────────────────────

  function ProcessNode({ node, depth = 0 }: { node: any; depth?: number }) {
    const hasChildren = node.children?.length > 0;
    const expanded = expandedPids.has(node.pid);
    const suspicious = ['powershell','rundll32','svchost32','mshta','wscript','certutil'].some(
      s => node.process_name?.toLowerCase().includes(s));
    return (
      <div style={{ marginLeft: depth * 18 }}>
        <div className="flex items-start gap-1.5 py-1 group" style={{ borderLeft: depth > 0 ? '1px dashed var(--border)' : 'none', paddingLeft: depth > 0 ? 10 : 0 }}>
          <button onClick={() => setExpandedPids(prev => { const n = new Set(prev); n.has(node.pid) ? n.delete(node.pid) : n.add(node.pid); return n; })} className="w-4 shrink-0 mt-0.5" style={{ color: 'var(--text-3)' }}>
            {hasChildren ? (expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />) : null}
          </button>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="text-xs font-semibold" style={{ color: suspicious ? '#f85149' : 'var(--text-1)' }}>{node.process_name}</span>
              <span className="text-[9px]" style={{ color: 'var(--text-3)' }}>PID:{node.pid} PPID:{node.ppid}</span>
              <span className="text-[9px]" style={{ color: 'var(--text-3)' }}>{node.username}</span>
              {suspicious && <span className="text-[9px] px-1 rounded" style={{ background: 'rgba(248,81,73,0.15)', color: '#f85149' }}>⚠ suspicious</span>}
            </div>
            {node.cmdline && <p className="text-[10px] font-mono truncate" style={{ color: suspicious ? '#fb923c' : 'var(--text-3)', maxWidth: 480 }}>{node.cmdline}</p>}
            {node.exe_path && <p className="text-[9px] truncate" style={{ color: 'var(--text-3)' }}>{node.exe_path}</p>}
          </div>
          <button onClick={() => { setResponseTarget(node.process_name); setResponseAction('kill_process'); setShowResponse(true); }}
            className="opacity-0 group-hover:opacity-100 g-btn g-btn-ghost text-[9px] px-1.5 py-0.5 shrink-0">Kill</button>
        </div>
        {expanded && hasChildren && node.children.map((child: any) => <ProcessNode key={child.pid} node={child} depth={depth + 1} />)}
      </div>
    );
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <RootLayout title="DFIR" subtitle="Digital Forensics & Incident Response · Evidence · Timeline · Memory · Artifacts">

      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)' }}>{toast}</div>}

      {/* Response modal */}
      {showResponse && (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.6)' }} onClick={e => e.target === e.currentTarget && setShowResponse(false)}>
          <div className="g-card p-5 space-y-3 w-full max-w-sm">
            <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Response Action</p>
            <select value={responseAction} onChange={e => setResponseAction(e.target.value)} className="g-select w-full text-sm">
              {RESPONSE_ACTS.map(a => <option key={a} value={a}>{a.replace(/_/g, ' ')}</option>)}
            </select>
            <input value={responseTarget} onChange={e => setResponseTarget(e.target.value)} className="g-input w-full text-sm" placeholder="Target (host, IP, PID, file path…)" />
            <div className="flex gap-2 justify-end">
              <button onClick={() => setShowResponse(false)} className="g-btn g-btn-ghost text-xs">Cancel</button>
              <button onClick={sendResponse} className="g-btn g-btn-primary text-xs">Execute</button>
            </div>
          </div>
        </div>
      )}

      {/* Tab bar */}
      <div className="flex gap-1 mb-4 flex-wrap items-center">
        {TABS.map(({ key, label, icon: Icon }) => (
          <button key={key} onClick={() => setTab(key as TabKey)}
            className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5"
            style={{ background: tab === key ? 'var(--accent-glow)' : 'var(--glass-bg)', border: `1px solid ${tab === key ? 'var(--accent-border)' : 'var(--border)'}`, color: tab === key ? 'var(--accent)' : 'var(--text-2)' }}>
            <Icon className="h-3 w-3" />{label}
          </button>
        ))}
        <div className="flex gap-2 ml-auto items-center">
          <div className="relative">
            <Search className="absolute left-2.5 top-2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
            <input value={searchQ} onChange={e => setSearchQ(e.target.value)} onKeyDown={e => e.key === 'Enter' && runSearch()}
              className="g-input pl-8 text-xs" style={{ width: 180, height: 32 }} placeholder="Search DFIR…" />
          </div>
          <button onClick={() => { setInvForm({ ...EMPTY_INV }); setIsEditInv(false); setActiveInv(null); setTab('investigations'); }}
            className="g-btn g-btn-primary text-xs flex items-center gap-1.5">
            <Plus className="h-3 w-3" />New Investigation
          </button>
        </div>
      </div>

      {/* Search results overlay */}
      {searchResults && (
        <div className="g-card p-4 mb-4">
          <div className="flex items-center justify-between mb-2">
            <p className="text-xs font-semibold" style={{ color: 'var(--text-2)' }}>Search: "{searchQ}" — {searchResults.total} results</p>
            <button onClick={() => setSearchResults(null)} className="g-btn g-btn-ghost text-xs"><X className="h-3 w-3" /></button>
          </div>
          {(searchResults.results || []).length === 0
            ? <p className="text-xs" style={{ color: 'var(--text-3)' }}>No results.</p>
            : (searchResults.results || []).map((r: any) => (
              <div key={`${r.type}-${r.id}`} className="flex items-center gap-2 py-1 text-xs">
                <span className="px-1.5 py-0.5 rounded text-[9px]" style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)' }}>{r.type}</span>
                <span style={{ color: 'var(--text-1)' }}>{r.title}</span>
                <span className="truncate" style={{ color: 'var(--text-3)' }}>{r.context?.slice(0, 60)}</span>
              </div>
            ))}
        </div>
      )}

      {/* ── Dashboard ──────────────────────────────────────────────────────── */}
      {tab === 'dashboard' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <KPICard label="Open Cases"       value={dash?.stats?.open_cases ?? '—'}       color="#f85149" />
            <KPICard label="In Progress"      value={dash?.stats?.in_progress ?? '—'}      color="#fbbf24" />
            <KPICard label="Evidence Items"   value={dash?.stats?.evidence_items ?? '—'}   color="var(--accent)" />
            <KPICard label="High Priority"    value={dash?.stats?.high_priority ?? '—'}    color="#fb923c" />
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <KPICard label="Memory Dumps"     value={dash?.stats?.memory_dumps ?? '—'} />
            <KPICard label="Disk Images"      value={dash?.stats?.disk_images ?? '—'} />
            <KPICard label="Custody Verified" value={dash?.stats?.custody_ok ?? '—'}       color="#22c55e" />
            <KPICard label="Custody Pending"  value={dash?.stats?.custody_pending ?? '—'}  color="#fbbf24" />
          </div>
          <div className="g-card p-4">
            <div className="flex items-center justify-between mb-3">
              <p className="text-xs font-semibold" style={{ color: 'var(--text-2)' }}>Active Investigations</p>
              <button onClick={() => setTab('investigations')} className="text-[10px]" style={{ color: 'var(--accent)' }}>View all →</button>
            </div>
            <table className="g-table w-full text-xs">
              <thead className="g-thead"><tr><th className="g-tr">Title</th><th className="g-tr">Analyst</th><th className="g-tr">Priority</th><th className="g-tr">Status</th><th className="g-tr">Created</th><th className="g-tr"></th></tr></thead>
              <tbody>
                {(dash?.recent || []).map((r: any) => (
                  <tr key={r.id} className="hover:bg-[var(--glass-bg)] cursor-pointer"
                    onClick={() => { const inv = investigations.find(i => i.id === r.id); if (inv) openInvestigation(inv); }}>
                    <td className="g-tr font-medium truncate max-w-[180px]" style={{ color: 'var(--text-1)' }}>{r.title}</td>
                    <td className="g-tr" style={{ color: 'var(--text-3)' }}>{r.analyst}</td>
                    <td className="g-tr"><SevBadge s={r.priority} /></td>
                    <td className="g-tr"><StatusBadge s={r.status} /></td>
                    <td className="g-tr" style={{ color: 'var(--text-3)' }}>{timeAgo(r.created_at)}</td>
                    <td className="g-tr"><Eye className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="g-card p-4">
            <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-2)' }}>DFIR Workflow</p>
            <div className="flex items-center gap-1 flex-wrap text-xs">
              {['Alert','Incident','DFIR','Evidence Collection','Artifact Analysis','Timeline','Root Cause','Report','SOAR Response'].map((step, i, arr) => (
                <div key={step} className="flex items-center gap-1">
                  <span className="px-2 py-1 rounded" style={{ background: i === 2 ? 'var(--accent-glow)' : 'var(--glass-bg)', border: `1px solid ${i === 2 ? 'var(--accent-border)' : 'var(--border)'}`, color: i === 2 ? 'var(--accent)' : 'var(--text-2)' }}>{step}</span>
                  {i < arr.length - 1 && <ChevronRight className="h-3 w-3 shrink-0" style={{ color: 'var(--text-3)' }} />}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Investigations ────────────────────────────────────────────────── */}
      {tab === 'investigations' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* List */}
          <div className="space-y-2">
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-2.5 top-2.5 h-3 w-3" style={{ color: 'var(--text-3)' }} />
                <input value={invSearch} onChange={e => setInvSearch(e.target.value)} className="g-input w-full pl-8 text-xs" placeholder="Search…" />
              </div>
              <select value={invStatusFilter} onChange={e => setInvStatusFilter(e.target.value)} className="g-select text-xs">
                <option value="">All</option><option value="open">Open</option><option value="in_progress">In Progress</option><option value="closed">Closed</option>
              </select>
            </div>
            <div className="space-y-1.5 max-h-[70vh] overflow-y-auto pr-1">
              {filteredInvestigations.map(inv => (
                <div key={inv.id} onClick={() => openInvestigation(inv)}
                  className="g-card p-3 cursor-pointer transition-all"
                  style={{ border: `1px solid ${activeInv?.id === inv.id ? 'var(--accent-border)' : 'var(--border)'}` }}>
                  <div className="flex items-start justify-between gap-2 mb-1">
                    <p className="text-xs font-semibold truncate" style={{ color: 'var(--text-1)' }}>{inv.title}</p>
                    <SevBadge s={inv.priority} />
                  </div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <StatusBadge s={inv.status} />
                    <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{inv.investigation_id}</span>
                    <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{inv.evidence_count} evidence</span>
                  </div>
                  <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>{inv.analyst} · {timeAgo(inv.created_at)}</p>
                </div>
              ))}
              {filteredInvestigations.length === 0 && <div className="text-center py-6 text-xs" style={{ color: 'var(--text-3)' }}>No investigations found.</div>}
            </div>
          </div>

          {/* Detail / form */}
          <div className="lg:col-span-2 space-y-3">
            <div className="flex items-center gap-2 flex-wrap">
              <p className="text-sm font-semibold flex-1 truncate" style={{ color: 'var(--text-1)' }}>
                {isEditInv ? invForm.title || 'Untitled' : 'New Investigation'}
                {isEditInv && <span className="ml-2 text-[10px]" style={{ color: 'var(--text-3)' }}>{invForm.investigation_id} · v{invForm.version}</span>}
              </p>
              <button onClick={saveInvestigation} disabled={savingInv} className="g-btn g-btn-primary text-xs flex items-center gap-1.5">
                <Save className="h-3 w-3" />{savingInv ? 'Saving…' : isEditInv ? 'Update' : 'Create'}
              </button>
              {isEditInv && <button onClick={() => { setResponseTarget(invForm.target_hosts?.split(',')[0] || ''); setShowResponse(true); }} className="g-btn g-btn-ghost text-xs flex items-center gap-1.5"><Zap className="h-3 w-3" />Respond</button>}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="g-card p-4 space-y-2">
                <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Investigation Info</p>
                <input value={invForm.title || ''} onChange={e => setInvForm(p => ({ ...p, title: e.target.value }))} className="g-input w-full text-sm" placeholder="Title *" />
                <div className="grid grid-cols-2 gap-2">
                  <input value={invForm.case_id || ''} onChange={e => setInvForm(p => ({ ...p, case_id: e.target.value }))} className="g-input w-full text-xs" placeholder="Case ID" />
                  <input value={invForm.incident_id || ''} onChange={e => setInvForm(p => ({ ...p, incident_id: +e.target.value }))} type="number" className="g-input w-full text-xs" placeholder="Incident ID" />
                  <select value={invForm.priority || 'high'} onChange={e => setInvForm(p => ({ ...p, priority: e.target.value }))} className="g-select w-full text-xs">
                    {['critical','high','medium','low'].map(v => <option key={v} value={v}>{v}</option>)}
                  </select>
                  <select value={invForm.status || 'open'} onChange={e => setInvForm(p => ({ ...p, status: e.target.value }))} className="g-select w-full text-xs">
                    {['open','in_progress','closed','resolved'].map(v => <option key={v} value={v}>{v}</option>)}
                  </select>
                  <input value={invForm.analyst || ''} onChange={e => setInvForm(p => ({ ...p, analyst: e.target.value }))} className="g-input w-full text-xs" placeholder="Analyst" />
                  <select value={invForm.classification || 'TLP:AMBER'} onChange={e => setInvForm(p => ({ ...p, classification: e.target.value }))} className="g-select w-full text-xs">
                    {['TLP:WHITE','TLP:GREEN','TLP:AMBER','TLP:RED'].map(v => <option key={v} value={v}>{v}</option>)}
                  </select>
                </div>
                <input value={invForm.target_hosts || ''} onChange={e => setInvForm(p => ({ ...p, target_hosts: e.target.value }))} className="g-input w-full text-xs" placeholder="Target hosts (comma-separated)" />
                <input value={invForm.target_users || ''} onChange={e => setInvForm(p => ({ ...p, target_users: e.target.value }))} className="g-input w-full text-xs" placeholder="Target users" />
                <input value={invForm.mitre_techniques || ''} onChange={e => setInvForm(p => ({ ...p, mitre_techniques: e.target.value }))} className="g-input w-full text-xs font-mono" placeholder="MITRE (T1059.001,…)" />
                <input value={invForm.tags || ''} onChange={e => setInvForm(p => ({ ...p, tags: e.target.value }))} className="g-input w-full text-xs" placeholder="Tags" />
              </div>
              <div className="g-card p-4 space-y-2">
                <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Findings</p>
                <textarea value={invForm.notes || ''} onChange={e => setInvForm(p => ({ ...p, notes: e.target.value }))} className="g-input w-full text-xs resize-none" rows={3} placeholder="Notes / observations…" />
                <textarea value={invForm.root_cause || ''} onChange={e => setInvForm(p => ({ ...p, root_cause: e.target.value }))} className="g-input w-full text-xs resize-none" rows={2} placeholder="Root cause" />
                <textarea value={invForm.executive_summary || ''} onChange={e => setInvForm(p => ({ ...p, executive_summary: e.target.value }))} className="g-input w-full text-xs resize-none" rows={3} placeholder="Executive summary" />
              </div>
            </div>

            {/* AI assistant */}
            {isEditInv && (
              <div className="g-card p-4 space-y-2">
                <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>AI Investigation Assistant</p>
                <div className="flex gap-2">
                  <select value={aiAction} onChange={e => setAiAction(e.target.value)} className="g-select text-xs flex-1">
                    <option value="summarize">Summarize Investigation</option>
                    <option value="root_cause">Determine Root Cause</option>
                    <option value="recommend">Recommend Actions</option>
                    <option value="generate_report">Draft Report</option>
                    <option value="enrich_ioc">Enrich IOC</option>
                    <option value="ask">Ask a Question</option>
                  </select>
                  <button onClick={runAI} disabled={aiRunning} className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
                    <Brain className="h-3.5 w-3.5" />{aiRunning ? 'Thinking…' : 'Ask AI'}
                  </button>
                </div>
                {(aiAction === 'enrich_ioc' || aiAction === 'ask') && (
                  <input value={aiPrompt} onChange={e => setAiPrompt(e.target.value)} className="g-input w-full text-xs" placeholder={aiAction === 'enrich_ioc' ? 'IOC value…' : 'Your question…'} />
                )}
                {aiResult && (
                  <div className="rounded-lg p-3 space-y-1.5 max-h-44 overflow-y-auto" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    {aiResult.executive_summary && <p className="text-[11px]" style={{ color: 'var(--text-1)' }}><strong>Summary:</strong> {aiResult.executive_summary}</p>}
                    {aiResult.root_cause && <p className="text-[11px]" style={{ color: 'var(--text-2)' }}><strong>Root Cause:</strong> {aiResult.root_cause}</p>}
                    {aiResult.answer && <p className="text-[11px]" style={{ color: 'var(--text-1)' }}>{aiResult.answer}</p>}
                    {[...(aiResult.recommendations || []), ...(aiResult.immediate_actions || [])].slice(0, 4).map((r: string, i: number) => (
                      <p key={i} className="text-[10px]" style={{ color: 'var(--text-3)' }}>• {r}</p>
                    ))}
                    <div className="flex gap-2 pt-1">
                      {aiResult.root_cause && <button onClick={() => { setInvForm(p => ({ ...p, root_cause: aiResult.root_cause })); setAiResult(null); notify('Applied'); }} className="g-btn g-btn-ghost text-[10px]">Apply</button>}
                      <button onClick={() => setAiResult(null)} className="g-btn g-btn-ghost text-[10px]">Dismiss</button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Evidence chips */}
            {isEditInv && evidence.length > 0 && (
              <div className="g-card p-3">
                <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Evidence ({evidence.length})</p>
                <div className="flex flex-wrap gap-1.5">
                  {evidence.map(ev => (
                    <button key={ev.id} onClick={() => setTab('evidence')} className="text-[10px] px-2 py-0.5 rounded flex items-center gap-1"
                      style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                      <Database className="h-2.5 w-2.5" />{ev.label.split('—')[0].trim()}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Collect ───────────────────────────────────────────────────────── */}
      {tab === 'collect' && (
        <div className="space-y-4">
          {!activeInv && <div className="g-card p-4 text-center"><p className="text-xs" style={{ color: 'var(--text-3)' }}>Open an investigation first.</p></div>}
          {activeInv && <div className="g-card p-3"><p className="text-xs" style={{ color: 'var(--text-2)' }}>Active Investigation: <strong style={{ color: 'var(--accent)' }}>{activeInv.title}</strong></p></div>}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="g-card p-4 space-y-3">
              <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Remote Evidence Collection</p>
              <input value={collectHost} onChange={e => setCollectHost(e.target.value)} className="g-input w-full text-sm" placeholder="Target hostname or IP *" />
              <div className="flex gap-2">
                {(['windows','linux','macos'] as const).map(p => (
                  <button key={p} onClick={() => { setCollectPlatform(p); setCollectArtifacts([]); }}
                    className="text-xs px-3 py-1 rounded capitalize"
                    style={{ background: collectPlatform === p ? 'var(--accent-glow)' : 'var(--glass-bg)', border: `1px solid ${collectPlatform === p ? 'var(--accent-border)' : 'var(--border)'}`, color: collectPlatform === p ? 'var(--accent)' : 'var(--text-3)' }}>
                    {p}
                  </button>
                ))}
              </div>
              <div>
                <p className="text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Artifact Types ({collectArtifacts.length} selected)</p>
                <div className="flex flex-wrap gap-1.5">
                  {ARTIFACT_TYPES[collectPlatform].map(a => (
                    <button key={a} onClick={() => toggleArtifact(a)}
                      className="text-[10px] px-2 py-0.5 rounded capitalize"
                      style={{ background: collectArtifacts.includes(a) ? 'var(--accent-glow)' : 'var(--glass-bg)', border: `1px solid ${collectArtifacts.includes(a) ? 'var(--accent-border)' : 'var(--border)'}`, color: collectArtifacts.includes(a) ? 'var(--accent)' : 'var(--text-3)' }}>
                      {a.replace(/_/g,' ')}
                    </button>
                  ))}
                </div>
              </div>
              <button onClick={triggerCollect} disabled={collecting || !collectHost || !activeInv} className="g-btn g-btn-primary text-xs w-full flex items-center justify-center gap-1.5">
                <Download className="h-3.5 w-3.5" />{collecting ? 'Collecting…' : 'Collect Evidence'}
              </button>
              {collectResult && (
                <div className="rounded-lg p-3" style={{ background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.3)' }}>
                  <p className="text-xs font-semibold" style={{ color: '#22c55e' }}>{collectResult.evidence_count} artifact sets collected from {collectResult.host}</p>
                </div>
              )}
            </div>
            <div className="g-card p-4">
              <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Collection Tasks</p>
              {tasks.length === 0 && <p className="text-xs" style={{ color: 'var(--text-3)' }}>No tasks yet.</p>}
              {tasks.map(t => (
                <div key={t.id} className="py-2 border-b" style={{ borderColor: 'var(--border)' }}>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{t.target_host}</span>
                    <StatusBadge s={t.status} />
                    <span className="text-[10px] ml-auto" style={{ color: 'var(--text-3)' }}>{timeAgo(t.created_at)}</span>
                  </div>
                  <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{t.artifacts} · {t.evidence_count} items</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Evidence ──────────────────────────────────────────────────────── */}
      {tab === 'evidence' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="space-y-2">
            <p className="text-xs font-semibold" style={{ color: 'var(--text-2)' }}>Evidence Items ({evidence.length})</p>
            {evidence.length === 0 && <div className="g-card p-6 text-center"><p className="text-xs" style={{ color: 'var(--text-3)' }}>No evidence. Go to Collect to acquire artifacts.</p></div>}
            {evidence.map(ev => (
              <div key={ev.id} onClick={() => loadCustody(ev.id)} className="g-card p-3 cursor-pointer transition-all"
                style={{ border: `1px solid ${selectedEvidenceId === ev.id ? 'var(--accent-border)' : 'var(--border)'}` }}>
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{ev.label}</p>
                    <p className="text-[10px] font-mono" style={{ color: 'var(--text-3)' }}>{ev.evidence_id}</p>
                  </div>
                  <StatusBadge s={ev.status} />
                </div>
                <div className="flex items-center gap-3 mt-1 text-[10px]" style={{ color: 'var(--text-3)' }}>
                  <span className="capitalize">{ev.type.replace(/_/g,' ')}</span>
                  <span>{formatBytes(ev.size_bytes)}</span>
                  <span>by {ev.collector}</span>
                  <span className="ml-auto">{timeAgo(ev.collected_at)}</span>
                </div>
                {ev.sha256 && <p className="text-[9px] font-mono mt-0.5 truncate" style={{ color: 'var(--text-3)' }}>SHA256: {ev.sha256}</p>}
              </div>
            ))}
          </div>
          <div className="g-card p-4">
            <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-2)' }}>
              Chain of Custody {selectedEvidenceId ? `— Evidence #${selectedEvidenceId}` : ''}
            </p>
            {!selectedEvidenceId && <p className="text-xs" style={{ color: 'var(--text-3)' }}>Click an evidence item to view its chain of custody.</p>}
            {custody.map((co, i) => (
              <div key={co.id} className="relative pl-6 pb-4">
                <div className="absolute left-0 top-1 w-4 h-4 rounded-full flex items-center justify-center text-[9px] font-bold"
                  style={{ background: co.hash_verified ? 'rgba(34,197,94,0.2)' : 'rgba(251,191,36,0.2)', color: co.hash_verified ? '#22c55e' : '#fbbf24' }}>
                  {i + 1}
                </div>
                {i < custody.length - 1 && <div className="absolute left-1.5 top-5 bottom-0 w-px" style={{ background: 'var(--border)' }} />}
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-semibold capitalize" style={{ color: 'var(--text-1)' }}>{co.action}</span>
                    <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>by {co.actor}</span>
                    {co.hash_verified && <span className="text-[9px] px-1 rounded" style={{ background: 'rgba(34,197,94,0.12)', color: '#22c55e' }}>✓ hash verified</span>}
                  </div>
                  <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{co.location} · {timeAgo(co.created_at)}</p>
                  {co.notes && <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-2)' }}>{co.notes}</p>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Timeline ──────────────────────────────────────────────────────── */}
      {tab === 'timeline' && (
        <div className="space-y-3">
          <div className="flex items-center gap-2 flex-wrap">
            <select value={tlFilter} onChange={e => setTlFilter(e.target.value)} className="g-select text-xs">
              <option value="">All Events</option>
              {['alert','command','process','registry','network','usb','analyst','login','file'].map(t => <option key={t} value={t}>{t}</option>)}
            </select>
            <button onClick={() => setTlReplay(r => !r)} className="g-btn g-btn-ghost text-xs flex items-center gap-1.5" style={{ color: tlReplay ? 'var(--accent)' : undefined }}>
              <Play className="h-3 w-3" />{tlReplay ? 'Replaying' : 'Replay'}
            </button>
            <button onClick={() => setAddingEvent(true)} className="g-btn g-btn-ghost text-xs flex items-center gap-1.5"><Plus className="h-3 w-3" />Add Event</button>
            <span className="text-[10px] ml-auto" style={{ color: 'var(--text-3)' }}>{filteredTimeline.length} events</span>
          </div>
          {addingEvent && (
            <div className="g-card p-3 space-y-2">
              <div className="flex gap-2">
                <select value={manualEvent.event_type} onChange={e => setManualEvent(p => ({ ...p, event_type: e.target.value }))} className="g-select text-xs">
                  {['analyst','login','process','registry','network','file','usb'].map(t => <option key={t} value={t}>{t}</option>)}
                </select>
                <select value={manualEvent.severity} onChange={e => setManualEvent(p => ({ ...p, severity: e.target.value }))} className="g-select text-xs">
                  {['info','low','medium','high','critical'].map(v => <option key={v} value={v}>{v}</option>)}
                </select>
              </div>
              <div className="flex gap-2">
                <input value={manualEvent.description} onChange={e => setManualEvent(p => ({ ...p, description: e.target.value }))} className="g-input flex-1 text-xs" placeholder="Event description…" />
                <button onClick={addTimelineEvent} className="g-btn g-btn-primary text-xs">Add</button>
                <button onClick={() => setAddingEvent(false)} className="g-btn g-btn-ghost text-xs">Cancel</button>
              </div>
            </div>
          )}
          <div className="space-y-0">
            {filteredTimeline.length === 0 && <div className="g-card p-8 text-center"><p className="text-xs" style={{ color: 'var(--text-3)' }}>No timeline events. Open an investigation and collect evidence.</p></div>}
            {(tlReplay ? replayEvents.slice(0, tlReplayIdx + 1) : filteredTimeline).map((ev, i) => {
              const col = EVT_COLORS[ev.event_type] || 'var(--text-3)';
              return (
                <div key={ev.id} className="flex gap-3 py-2 relative">
                  <div className="flex flex-col items-center">
                    <div className="w-2 h-2 rounded-full mt-1.5 shrink-0" style={{ background: col }} />
                    {i < filteredTimeline.length - 1 && <div className="w-px flex-1 mt-1" style={{ background: 'var(--border)', minHeight: 16 }} />}
                  </div>
                  <div className="flex-1 min-w-0 pb-2">
                    <div className="flex items-center gap-2 flex-wrap mb-0.5">
                      <span className="text-[10px] font-mono" style={{ color: 'var(--text-3)' }}>{new Date(ev.event_time).toLocaleString()}</span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded capitalize" style={{ background: `${col}22`, color: col }}>{ev.event_type}</span>
                      {ev.severity !== 'info' && <SevBadge s={ev.severity} />}
                      {ev.mitre_technique && <span className="text-[10px] font-mono" style={{ color: 'var(--accent)' }}>{ev.mitre_technique}</span>}
                      {ev.is_manual && <span className="text-[9px] px-1 rounded" style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)' }}>manual</span>}
                    </div>
                    <p className="text-xs" style={{ color: ev.severity === 'critical' ? '#f85149' : 'var(--text-1)' }}>{ev.description}</p>
                    {(ev.host || ev.user_name) && (
                      <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>
                        {ev.host && <span>Host: <strong>{ev.host}</strong>  </span>}
                        {ev.user_name && <span>User: <strong>{ev.user_name}</strong></span>}
                      </p>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
          {tlReplay && (
            <div className="flex gap-2 items-center">
              <button onClick={() => setTlReplayIdx(i => Math.min(i + 1, replayEvents.length - 1))} className="g-btn g-btn-primary text-xs">Next Event →</button>
              <button onClick={() => setTlReplayIdx(0)} className="g-btn g-btn-ghost text-xs">Reset</button>
              <span className="text-xs" style={{ color: 'var(--text-3)' }}>{tlReplayIdx + 1} / {replayEvents.length}</span>
            </div>
          )}
        </div>
      )}

      {/* ── Process Tree ─────────────────────────────────────────────────── */}
      {tab === 'process-tree' && (
        <div className="space-y-4">
          <div className="flex gap-2 items-center">
            <p className="text-sm font-semibold flex-1" style={{ color: 'var(--text-1)' }}>Process Tree {processTree ? `— ${processTree.total} processes` : ''}</p>
            <button onClick={runMemoryAnalysis} disabled={memoryRunning} className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
              <Brain className="h-3 w-3" />{memoryRunning ? 'Analyzing…' : 'Memory Analysis'}
            </button>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="g-card p-4 overflow-auto max-h-[60vh]" style={{ fontFamily: 'monospace' }}>
              {!processTree && <p className="text-xs" style={{ color: 'var(--text-3)' }}>No process data. Open an investigation with target hosts.</p>}
              {processTree?.processes?.map((root: any) => <ProcessNode key={root.pid} node={root} depth={0} />)}
            </div>
            <div className="space-y-3">
              {memoryResult ? (
                <>
                  <div className="g-card p-4">
                    <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-2)' }}>Memory Analysis</p>
                    <p className="text-xs mb-3" style={{ color: 'var(--text-1)' }}>{memoryResult.executive_summary}</p>
                    {(memoryResult.suspicious_processes || []).map((sp: any, i: number) => (
                      <div key={i} className="rounded-lg p-2 mb-2" style={{ background: 'rgba(248,81,73,0.08)', border: '1px solid rgba(248,81,73,0.2)' }}>
                        <div className="flex items-center gap-2"><span className="text-xs font-semibold" style={{ color: '#f85149' }}>{sp.name}</span><SevBadge s={sp.severity} /><span className="text-[10px] font-mono" style={{ color: 'var(--accent)' }}>{sp.mitre}</span></div>
                        <p className="text-[10px]" style={{ color: 'var(--text-2)' }}>{sp.reason}</p>
                      </div>
                    ))}
                    {(memoryResult.injections || []).map((inj: any, i: number) => (
                      <div key={i} className="rounded-lg p-2 mb-2" style={{ background: 'rgba(168,85,247,0.08)', border: '1px solid rgba(168,85,247,0.2)' }}>
                        <p className="text-xs font-semibold" style={{ color: '#a855f7' }}>Injection: {inj.process} (PID:{inj.pid})</p>
                        <p className="text-[10px]" style={{ color: 'var(--text-2)' }}>{inj.indicator} — {inj.confidence}% confidence</p>
                      </div>
                    ))}
                    {(memoryResult.recommendations || []).map((r: string, i: number) => <p key={i} className="text-[10px]" style={{ color: 'var(--text-3)' }}>• {r}</p>)}
                  </div>
                </>
              ) : (
                <div className="g-card p-6 text-center"><p className="text-xs" style={{ color: 'var(--text-3)' }}>Click "Memory Analysis" to analyze processes for malicious indicators.</p></div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Forensics ────────────────────────────────────────────────────── */}
      {tab === 'forensics' && (
        <div className="space-y-3">
          <div className="flex gap-1 flex-wrap">
            {FORENSIC_TABS.map(ft => (
              <button key={ft} onClick={() => setFtab(ft)} className="px-3 py-1.5 rounded-lg text-xs capitalize"
                style={{ background: ftab === ft ? 'var(--accent-glow)' : 'var(--glass-bg)', border: `1px solid ${ftab === ft ? 'var(--accent-border)' : 'var(--border)'}`, color: ftab === ft ? 'var(--accent)' : 'var(--text-2)' }}>
                {ft}
              </button>
            ))}
          </div>

          {ftab === 'file' && (
            <div className="g-card p-4 space-y-3">
              <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>File Analysis</p>
              <div className="flex gap-2">
                <input value={fileHash} onChange={e => setFileHash(e.target.value)} className="g-input flex-1 text-xs font-mono" placeholder="SHA256 hash or file path…" />
                <button onClick={runFileAnalysis} disabled={fileAnalyzing} className="g-btn g-btn-primary text-xs">{fileAnalyzing ? 'Analyzing…' : 'Analyze'}</button>
              </div>
              {fileAnalysis && (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                    <KPICard label="Verdict"    value={fileAnalysis.verdict}                     color={fileAnalysis.suspicious ? '#f85149' : '#22c55e'} />
                    <KPICard label="Confidence" value={`${fileAnalysis.confidence}%`} />
                    <KPICard label="Entropy"    value={fileAnalysis.entropy?.toFixed(2) ?? '—'} />
                    <KPICard label="Type"       value={fileAnalysis.file_type || '—'} />
                  </div>
                  <div className="rounded-lg p-3 space-y-1" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>SHA256: <span className="font-mono">{fileAnalysis.sha256}</span></p>
                    <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>File: {fileAnalysis.file_name} · Packed: {fileAnalysis.packed ? fileAnalysis.packer : 'No'} · Signed: {fileAnalysis.is_signed ? fileAnalysis.signed_by : 'No'}</p>
                    {fileAnalysis.threat_classification && <p className="text-[10px]" style={{ color: '#f85149' }}>{fileAnalysis.threat_classification}</p>}
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div><p className="text-[10px] font-semibold mb-1" style={{ color: 'var(--text-3)' }}>MITRE</p>{(fileAnalysis.mitre_techniques || []).map((t: string) => <span key={t} className="inline-block text-[10px] font-mono mr-1 mb-1 px-1.5 py-0.5 rounded" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>{t}</span>)}</div>
                    <div><p className="text-[10px] font-semibold mb-1" style={{ color: 'var(--text-3)' }}>Strings</p>{(fileAnalysis.strings_of_interest || []).map((s: string, i: number) => <p key={i} className="text-[10px] font-mono" style={{ color: 'var(--text-2)' }}>{s}</p>)}</div>
                    <div><p className="text-[10px] font-semibold mb-1" style={{ color: 'var(--text-3)' }}>Imports</p>{(fileAnalysis.imports || []).slice(0,6).map((s: string, i: number) => <p key={i} className="text-[10px] font-mono" style={{ color: 'var(--text-3)' }}>{s}</p>)}</div>
                    <div><p className="text-[10px] font-semibold mb-1" style={{ color: 'var(--text-3)' }}>Recommendations</p>{(fileAnalysis.recommendations || []).map((r: string, i: number) => <p key={i} className="text-[10px]" style={{ color: 'var(--text-2)' }}>• {r}</p>)}</div>
                  </div>
                </div>
              )}
            </div>
          )}

          {ftab === 'malware' && (
            <div className="space-y-3">
              <div className="g-card p-4 space-y-3">
                <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Malware Analysis</p>
                <div className="flex gap-2">
                  <input value={malwareHash} onChange={e => setMalwareHash(e.target.value)} className="g-input flex-1 text-xs font-mono" placeholder="SHA256 hash…" />
                  <input value={malwareName} onChange={e => setMalwareName(e.target.value)} className="g-input flex-1 text-xs" placeholder="File name (optional)" />
                  <button onClick={runMalwareAnalysis} disabled={malwareAnalyzing} className="g-btn g-btn-primary text-xs flex items-center gap-1.5">
                    <Shield className="h-3 w-3" />{malwareAnalyzing ? 'Analyzing…' : 'Analyze'}
                  </button>
                </div>
              </div>
              {malwareAnalysis && (
                <div className="g-card p-4 space-y-3">
                  <div className="flex items-start justify-between">
                    <div><p className="text-sm font-bold" style={{ color: '#f85149' }}>{malwareAnalysis.threat_name}</p><p className="text-xs" style={{ color: 'var(--text-3)' }}>{malwareAnalysis.threat_family} · {malwareAnalysis.threat_category}</p></div>
                    <div className="text-right"><p className="text-xs" style={{ color: 'var(--text-3)' }}>VT: <span style={{ color: '#f85149' }}>{malwareAnalysis.vt_detections}</span>/{malwareAnalysis.vt_total}</p><p className="text-xs" style={{ color: 'var(--text-3)' }}>Confidence: {malwareAnalysis.confidence}%</p></div>
                  </div>
                  <p className="text-[11px]" style={{ color: 'var(--text-2)' }}>{malwareAnalysis.executive_summary}</p>
                  <div className="grid grid-cols-2 gap-3">
                    <div><p className="text-[10px] font-semibold mb-1" style={{ color: 'var(--text-3)' }}>YARA Matches</p>{(malwareAnalysis.yara_matches || []).map((y: any, i: number) => <p key={i} className="text-[10px]" style={{ color: '#a855f7' }}>• {y.rule}</p>)}</div>
                    <div><p className="text-[10px] font-semibold mb-1" style={{ color: 'var(--text-3)' }}>C2 Infrastructure</p>{[...(malwareAnalysis.c2_domains || []), ...(malwareAnalysis.c2_ips || [])].map((c: string, i: number) => <p key={i} className="text-[10px] font-mono" style={{ color: '#f85149' }}>{c}</p>)}</div>
                    <div><p className="text-[10px] font-semibold mb-1" style={{ color: 'var(--text-3)' }}>Capabilities</p>{(malwareAnalysis.capabilities || []).map((cap: string, i: number) => <p key={i} className="text-[10px]" style={{ color: 'var(--text-2)' }}>• {cap}</p>)}</div>
                    <div><p className="text-[10px] font-semibold mb-1" style={{ color: 'var(--text-3)' }}>MITRE</p>{(malwareAnalysis.mitre_techniques || []).map((t: any, i: number) => <p key={i} className="text-[10px]"><span className="font-mono" style={{ color: 'var(--accent)' }}>{t.id}</span> <span style={{ color: 'var(--text-3)' }}>{t.name}</span></p>)}</div>
                  </div>
                </div>
              )}
            </div>
          )}

          {ftab === 'network' && (
            <div className="g-card p-4 space-y-3">
              <div className="flex items-center gap-2">
                <p className="text-xs font-semibold uppercase tracking-wider flex-1" style={{ color: 'var(--text-3)' }}>Network Forensics</p>
                <select value={netProto} onChange={e => setNetProto(e.target.value)} className="g-select text-xs">
                  <option value="">All</option>{['TCP','UDP','HTTP','DNS','SMB','RDP','SSH'].map(p => <option key={p} value={p}>{p}</option>)}
                </select>
              </div>
              <table className="g-table w-full text-xs">
                <thead className="g-thead"><tr><th className="g-tr">Protocol</th><th className="g-tr">Local</th><th className="g-tr">Remote</th><th className="g-tr">State</th><th className="g-tr">Process</th><th className="g-tr">Country</th><th className="g-tr"></th></tr></thead>
                <tbody>
                  {network.filter(c => !netProto || c.protocol?.toUpperCase() === netProto).map(c => (
                    <tr key={c.id} className="hover:bg-[var(--glass-bg)]">
                      <td className="g-tr font-mono text-[10px]" style={{ color: 'var(--accent)' }}>{c.protocol}</td>
                      <td className="g-tr font-mono text-[10px]" style={{ color: 'var(--text-3)' }}>{c.local_address}</td>
                      <td className="g-tr font-mono text-[10px]" style={{ color: c.remote_address?.startsWith('185.') ? '#f85149' : 'var(--text-1)' }}>{c.remote_address}</td>
                      <td className="g-tr text-[10px]" style={{ color: 'var(--text-3)' }}>{c.state}</td>
                      <td className="g-tr text-[10px]" style={{ color: c.process_name?.includes('svchost32') ? '#f85149' : 'var(--text-2)' }}>{c.process_name}</td>
                      <td className="g-tr text-[10px]" style={{ color: 'var(--text-3)' }}>{c.country}</td>
                      <td className="g-tr"><button onClick={() => { setResponseTarget(c.remote_address?.split(':')[0]); setResponseAction('block_ip'); setShowResponse(true); }} className="g-btn g-btn-ghost text-[9px] px-1.5">Block</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {ftab === 'artifacts' && (
            <div className="g-card p-4 space-y-3">
              <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Artifact Analysis</p>
              <div className="flex gap-2 flex-wrap">
                {(['windows','linux','macos'] as const).map(p => (
                  <button key={p} onClick={() => setArtifactPlatform(p)} className="text-xs px-2.5 py-1 rounded capitalize"
                    style={{ background: artifactPlatform === p ? 'var(--accent-glow)' : 'var(--glass-bg)', border: `1px solid ${artifactPlatform === p ? 'var(--accent-border)' : 'var(--border)'}`, color: artifactPlatform === p ? 'var(--accent)' : 'var(--text-3)' }}>
                    {p}
                  </button>
                ))}
                <select value={artifactType} onChange={e => setArtifactType(e.target.value)} className="g-select text-xs">
                  <option value="">Select artifact…</option>
                  {ARTIFACT_TYPES[artifactPlatform].map(a => <option key={a} value={a}>{a.replace(/_/g,' ')}</option>)}
                </select>
                <button onClick={loadArtifacts} className="g-btn g-btn-ghost text-xs flex items-center gap-1"><Play className="h-3 w-3" />Load</button>
              </div>
              {(artifactData?.entries || []).map((e: any, i: number) => (
                <div key={i} className="rounded px-3 py-2" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                  <div className="flex items-center gap-2"><span className="text-[10px] font-mono" style={{ color: 'var(--text-3)' }}>{new Date(e.timestamp).toLocaleString()}</span><span className="text-[10px]" style={{ color: 'var(--accent)' }}>{e.log_source}</span></div>
                  <p className="text-xs mt-0.5" style={{ color: 'var(--text-1)' }}>{e.message}</p>
                </div>
              ))}
            </div>
          )}

          {(ftab === 'registry' || ftab === 'browser') && (
            <div className="g-card p-6 text-center space-y-2">
              <Shield className="mx-auto h-6 w-6 opacity-30" style={{ color: 'var(--accent)' }} />
              <p className="text-xs font-semibold" style={{ color: 'var(--text-2)' }}>{ftab === 'registry' ? 'Registry' : 'Browser'} Forensics</p>
              <p className="text-xs" style={{ color: 'var(--text-3)' }}>Collect {ftab === 'registry' ? 'registry' : 'browser history'} artifacts via the Collect tab from Windows hosts to view here.</p>
              <button onClick={() => setTab('collect')} className="g-btn g-btn-ghost text-xs">Go to Collect →</button>
            </div>
          )}
        </div>
      )}

      {/* ── Notebook ──────────────────────────────────────────────────────── */}
      {tab === 'notebook' && (
        <div className="space-y-3">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="g-card p-4 space-y-3">
              <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Add Entry</p>
              <select value={noteForm.entry_type} onChange={e => setNoteForm(p => ({ ...p, entry_type: e.target.value }))} className="g-select w-full text-xs">
                {['note','query','evidence','screenshot','bookmark','analyst_comment','markdown'].map(t => <option key={t} value={t}>{t}</option>)}
              </select>
              <input value={noteForm.title} onChange={e => setNoteForm(p => ({ ...p, title: e.target.value }))} className="g-input w-full text-xs" placeholder="Title (optional)" />
              <textarea value={noteForm.content} onChange={e => setNoteForm(p => ({ ...p, content: e.target.value }))} className="g-input w-full text-sm resize-none" rows={6} placeholder="Content (Markdown supported)…" />
              <input value={noteForm.tags} onChange={e => setNoteForm(p => ({ ...p, tags: e.target.value }))} className="g-input w-full text-xs" placeholder="Tags" />
              <button onClick={addNote} disabled={!noteForm.content} className="g-btn g-btn-primary text-xs w-full">Add to Notebook</button>
            </div>
            <div className="g-card p-4 space-y-3">
              <div className="flex items-center gap-2">
                <p className="text-xs font-semibold uppercase tracking-wider flex-1" style={{ color: 'var(--text-3)' }}>Threat Intelligence</p>
                <button onClick={loadThreatIntel} className="g-btn g-btn-ghost text-xs flex items-center gap-1"><Globe className="h-3 w-3" />Enrich</button>
              </div>
              {!threatIntel && <p className="text-xs" style={{ color: 'var(--text-3)' }}>Click Enrich to correlate investigation IOCs with threat intelligence.</p>}
              {threatIntel && (
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs" style={{ color: 'var(--text-2)' }}>Attribution confidence:</span>
                    <span className="text-sm font-bold" style={{ color: threatIntel.attribution_confidence >= 60 ? '#f85149' : '#fbbf24' }}>{threatIntel.attribution_confidence}%</span>
                  </div>
                  <p className="text-[11px]" style={{ color: 'var(--text-2)' }}>{threatIntel.executive_brief}</p>
                  {(threatIntel.threat_actors || []).map((ta: any, i: number) => (
                    <div key={i} className="rounded-lg p-2" style={{ background: 'rgba(248,81,73,0.08)', border: '1px solid rgba(248,81,73,0.2)' }}>
                      <p className="text-xs font-semibold" style={{ color: '#f85149' }}>{ta.name}</p>
                      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Motivation: {ta.motivation} · TTPs: {ta.ttps?.join(', ')}</p>
                    </div>
                  ))}
                  {(threatIntel.ioc_matches || []).map((ioc: any, i: number) => (
                    <div key={i} className="flex items-center gap-2 text-[10px]">
                      <span className="font-mono" style={{ color: 'var(--accent)' }}>{ioc.ioc}</span>
                      <span style={{ color: '#f85149' }}>{ioc.reputation}</span>
                      <span className="truncate" style={{ color: 'var(--text-3)' }}>{ioc.context}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
          <div className="space-y-2">
            {notebook.length === 0 && <div className="g-card p-6 text-center"><p className="text-xs" style={{ color: 'var(--text-3)' }}>No notebook entries yet.</p></div>}
            {notebook.map(entry => (
              <div key={entry.id} className="g-card p-4">
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div>
                    <span className="text-[10px] px-1.5 py-0.5 rounded mr-2 capitalize" style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)' }}>{entry.entry_type}</span>
                    {entry.title && <span className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{entry.title}</span>}
                  </div>
                  <div className="flex items-center gap-2 text-[10px] shrink-0" style={{ color: 'var(--text-3)' }}>
                    <span>{entry.author}</span>
                    <span>{timeAgo(entry.created_at)}</span>
                    <button onClick={() => deleteNote(entry.id)} className="g-btn g-btn-ghost p-0.5"><Trash2 className="h-3 w-3" /></button>
                  </div>
                </div>
                <pre className="text-xs whitespace-pre-wrap" style={{ color: 'var(--text-2)', fontFamily: entry.entry_type === 'query' ? 'monospace' : 'inherit' }}>{entry.content}</pre>
                {entry.tags && <div className="flex gap-1 mt-2 flex-wrap">{entry.tags.split(',').map(t => <span key={t} className="text-[9px] px-1.5 py-0.5 rounded" style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)' }}>{t.trim()}</span>)}</div>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Reports ───────────────────────────────────────────────────────── */}
      {tab === 'reports' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="g-card p-4 space-y-3">
              <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Generate Report</p>
              {!activeInv && <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Open an investigation first.</p>}
              {activeInv && <p className="text-xs" style={{ color: 'var(--text-2)' }}>Investigation: <strong>{activeInv.title}</strong></p>}
              <select value={reportType} onChange={e => setReportType(e.target.value)} className="g-select w-full text-sm">
                {REPORT_TYPES.map(t => <option key={t} value={t}>{t.replace(/_/g,' ')} report</option>)}
              </select>
              <button onClick={generateReport} disabled={reportRunning || !activeInv} className="g-btn g-btn-primary text-xs w-full flex items-center justify-center gap-1.5">
                <FileText className="h-3.5 w-3.5" />{reportRunning ? 'Generating…' : 'Generate Report'}
              </button>
              {reportResult && (
                <div className="space-y-2 max-h-80 overflow-y-auto">
                  <div className="rounded-lg p-3" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <p className="text-xs font-bold" style={{ color: 'var(--text-1)' }}>{reportResult.title}</p>
                    <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{reportResult.classification}</p>
                  </div>
                  {[['Executive Summary', reportResult.executive_summary], ['Incident Overview', reportResult.incident_overview], ['Timeline', reportResult.timeline_summary], ['Technical Analysis', reportResult.technical_analysis], ['Impact', reportResult.impact_assessment]].map(([h, v]) => v && (
                    <div key={h as string} className="rounded px-3 py-2" style={{ background: 'var(--glass-bg)' }}>
                      <p className="text-[10px] font-semibold mb-0.5" style={{ color: 'var(--text-3)' }}>{h as string}</p>
                      <p className="text-xs" style={{ color: 'var(--text-2)' }}>{v as string}</p>
                    </div>
                  ))}
                  {(reportResult.ioc_list || []).length > 0 && (
                    <div className="rounded px-3 py-2" style={{ background: 'var(--glass-bg)' }}>
                      <p className="text-[10px] font-semibold mb-1" style={{ color: 'var(--text-3)' }}>IOC List</p>
                      {reportResult.ioc_list.map((ioc: string, i: number) => <p key={i} className="text-[10px] font-mono" style={{ color: '#f85149' }}>{ioc}</p>)}
                    </div>
                  )}
                </div>
              )}
            </div>
            <div className="space-y-3">
              <div className="g-card p-4">
                <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>One-Click Response</p>
                <div className="grid grid-cols-2 gap-1.5">
                  {RESPONSE_ACTS.map(a => (
                    <button key={a} onClick={() => { setResponseAction(a); setResponseTarget(activeInv?.target_hosts?.split(',')[0] || ''); setShowResponse(true); }}
                      className="g-btn g-btn-ghost text-[10px] capitalize text-left px-2 py-1.5">
                      {a.replace(/_/g,' ')}
                    </button>
                  ))}
                </div>
              </div>
              <div className="g-card p-4">
                <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Analytics</p>
                <div className="grid grid-cols-2 gap-3 mb-3">
                  <KPICard label="Avg MTTR"    value={analytics ? `${analytics.avg_mttr_hours?.toFixed(1)}h` : '—'} />
                  <KPICard label="Total Cases" value={analytics ? analytics.by_status?.reduce((s: number, r: any) => s + r.value, 0) : '—'} />
                </div>
                {(analytics?.by_priority || []).map((r: any) => (
                  <div key={r.label} className="flex items-center gap-2 mb-1.5">
                    <span className="text-[10px] capitalize w-16 shrink-0" style={{ color: 'var(--text-3)' }}>{r.label}</span>
                    <div className="flex-1 h-1.5 rounded-full" style={{ background: 'var(--glass-bg-2)' }}>
                      <div className="h-full rounded-full" style={{ background: SEV[r.label] || 'var(--accent)', width: `${Math.min(100, r.value * 15)}%` }} />
                    </div>
                    <span className="text-[10px] w-4 text-right shrink-0" style={{ color: 'var(--text-3)' }}>{r.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
