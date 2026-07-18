'use client';

import { useEffect, useState, useCallback, useRef, useMemo } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { RootLayout } from '@/components/layout/RootLayout';
import { agentsAPI, alertsAPI, tasksAPI, fimAPI, aiAPI, agentGroupsAPI } from '@/lib/api';
import {
  Agent, AgentSummary, Vulnerability, TimelineEvent,
  Alert, FIMAlert, FIMBaseline, Connection, AgentAuditEntry, AgentGroup,
} from '@/types';
import { sevClass, formatDate, timeAgo, formatUptime } from '@/lib/utils';
import { Activity, AlertCircle, AlertTriangle, ArrowLeft, Bell, Bluetooth, BookOpen, Box, Brain, Bug, CalendarClock, Camera, Check, Clock, Copy, Cpu, Crosshair, Database, Download, Eye, FileCode, FileSearch, Fingerprint, FolderOpen, Gauge, GitBranch, Globe, HardDrive, Hash, Layers, ListChecks, LogIn, MemoryStick, Network, Package, Play, Power, Printer, Radio, RefreshCw, RotateCcw, Search, Settings, Shield, ShieldAlert, ShieldCheck, ShieldOff, Tablet, Terminal, Trash2, TrendingDown, TrendingUp, Upload, Usb, Users, Wifi, WifiOff, X, Zap, Lock } from '@/lib/icon-stubs';

// ── Tab definitions ────────────────────────────────────────────────────────────

const TAB_GROUPS = [
  {
    label: 'Detection',
    tabs: [
      { id: 'alerts',          label: 'Alerts',           icon: Bell },
      { id: 'timeline',        label: 'Timeline',         icon: Clock },
      { id: 'vulnerabilities', label: 'Vulnerabilities',  icon: Bug },
      { id: 'fim',             label: 'File Monitoring',  icon: FileSearch },
      { id: 'ai_analysis',     label: 'AI Analysis',      icon: Brain },
    ],
  },
  {
    label: 'Monitoring',
    tabs: [
      { id: 'processes',       label: 'Processes',        icon: Activity },
      { id: 'network',         label: 'Network',          icon: Network },
      { id: 'users',           label: 'User Activity',    icon: Users },
      { id: 'device_control',  label: 'Device Control',   icon: Usb },
      { id: 'performance',     label: 'Performance',      icon: Gauge },
    ],
  },
  {
    label: 'Inventory',
    tabs: [
      { id: 'software',        label: 'Software',         icon: Package },
      { id: 'registry',        label: 'Registry',         icon: Database },
      { id: 'security',        label: 'Security Status',  icon: Shield },
      { id: 'compliance',      label: 'Compliance',       icon: ShieldCheck },
    ],
  },
  {
    label: 'Response',
    tabs: [
      { id: 'live_response',   label: 'Live Response',    icon: Terminal },
      { id: 'remote_actions',  label: 'Remote Actions',   icon: Zap },
      { id: 'policies',        label: 'Policies',         icon: Settings },
      { id: 'tasks',           label: 'Task History',     icon: ListChecks },
      { id: 'audit_history',   label: 'Audit History',    icon: BookOpen },
    ],
  },
];

const ALL_TABS = TAB_GROUPS.flatMap(g => g.tabs);

// Remote action catalog
const REMOTE_ACTION_GROUPS = [
  {
    label: 'Endpoint',
    color: '#38bdf8',
    actions: [
      { task: 'wol',                label: 'Wake-on-LAN',       icon: Wifi,       danger: false, desc: 'Send WoL magic packet' },
      { task: 'lock_device',        label: 'Lock Device',        icon: Lock,       danger: false, desc: 'Lock screen immediately' },
      { task: 'logoff_user',        label: 'Log Off User',       icon: LogIn,      danger: false, desc: 'Force sign out active session' },
      { task: 'force_sync',         label: 'Force Sync',         icon: RefreshCw,  danger: false, desc: 'Push policy and config sync' },
      { task: 'restart_agent',      label: 'Restart Agent',      icon: RefreshCw,  danger: false, desc: 'Restart XCloak agent service' },
      { task: 'update_agent',       label: 'Update Agent',       icon: Upload,     danger: false, desc: 'Pull latest agent version' },
      { task: 'isolate_host',       label: 'Isolate Host',       icon: ShieldOff,  danger: true,  desc: 'Block all network traffic' },
      { task: 'de_isolate',         label: 'Remove Isolation',   icon: ShieldCheck,danger: false, desc: 'Restore network access' },
      { task: 'restart_host',       label: 'Restart',            icon: RotateCcw,  danger: true,  desc: 'Reboot the endpoint' },
      { task: 'shutdown_host',      label: 'Shutdown',           icon: Power,      danger: true,  desc: 'Power off the endpoint' },
    ],
  },
  {
    label: 'Processes',
    color: '#fb923c',
    actions: [
      { task: 'kill_process',        label: 'Kill Process',       icon: X,           danger: false, desc: 'Terminate by PID' },
      { task: 'suspend_process',     label: 'Suspend Process',    icon: GitBranch,   danger: false, desc: 'Pause a running process' },
      { task: 'resume_process',      label: 'Resume Process',     icon: Play,        danger: false, desc: 'Resume a suspended process' },
      { task: 'collect_memory',      label: 'Dump Process Memory',icon: Cpu,         danger: false, desc: 'Memory dump via agent' },
      { task: 'collect_processes',   label: 'Collect Processes',  icon: Activity,    danger: false, desc: 'Refresh process list' },
    ],
  },
  {
    label: 'Files',
    color: '#a78bfa',
    actions: [
      { task: 'collect_file',        label: 'Download File',      icon: Download,    danger: false, desc: 'Collect file from endpoint' },
      { task: 'upload_file',         label: 'Upload File',        icon: Upload,      danger: false, desc: 'Push file to endpoint' },
      { task: 'delete_file',         label: 'Delete File',        icon: Trash2,      danger: true,  desc: 'Permanently delete a file' },
      { task: 'quarantine_file',     label: 'Quarantine File',    icon: Shield,      danger: false, desc: 'Move file to quarantine' },
      { task: 'calculate_hash',      label: 'Calculate Hash',     icon: Hash,        danger: false, desc: 'Compute SHA256/MD5 of file' },
      { task: 'scan_file',           label: 'Scan File',          icon: Eye,         danger: false, desc: 'Run YARA + AV on file' },
    ],
  },
  {
    label: 'Collection',
    color: '#34d399',
    actions: [
      { task: 'collect_logs',        label: 'Collect Logs',       icon: BookOpen,    danger: false, desc: 'Pull system event logs' },
      { task: 'collect_forensics',   label: 'Forensics Bundle',   icon: Box,         danger: false, desc: 'Full forensic collection' },
      { task: 'collect_registry',    label: 'Collect Registry',   icon: Database,    danger: false, desc: 'Export registry hives' },
      { task: 'collect_browser_history', label: 'Browser History',icon: Globe,       danger: false, desc: 'Collect browsing history' },
      { task: 'collect_event_logs',  label: 'Event Logs',         icon: FileCode,    danger: false, desc: 'Windows Event Log export' },
      { task: 'collect_prefetch',    label: 'Collect Prefetch',   icon: Layers,      danger: false, desc: 'Windows prefetch files' },
      { task: 'collect_scheduled_tasks', label: 'Sched. Tasks',   icon: CalendarClock,danger: false,desc: 'Export task scheduler' },
      { task: 'collect_auth_logs',   label: 'Auth Logs',          icon: Radio,       danger: false, desc: 'Collect /var/log/auth.log' },
    ],
  },
  {
    label: 'Scanning',
    color: '#fbbf24',
    actions: [
      { task: 'scan_yara',           label: 'YARA Scan',          icon: FileSearch,  danger: false, desc: 'Run YARA rules on path' },
      { task: 'vulnerability_scan',  label: 'Vuln Scan',          icon: Bug,         danger: false, desc: 'Run vulnerability scan' },
      { task: 'fim_scan',            label: 'FIM Scan',           icon: Fingerprint, danger: false, desc: 'File integrity check' },
      { task: 'ioc_sweep',           label: 'IOC Sweep',          icon: Crosshair,   danger: false, desc: 'Sweep for IOC indicators' },
    ],
  },
  {
    label: 'Automation',
    color: '#f472b6',
    actions: [
      { task: 'execute_script',      label: 'Run Script',         icon: Terminal,    danger: false, desc: 'Execute shell / PowerShell' },
      { task: 'run_playbook',        label: 'Run SOAR Playbook',  icon: Zap,         danger: false, desc: 'Trigger SOAR automation' },
      { task: 'push_firewall_rule',  label: 'Push Firewall Rule', icon: Shield,      danger: false, desc: 'Deploy firewall policy' },
    ],
  },
];

// Timeline event icon + color map
const TL_ICONS: Record<string, { icon: React.FC<any>; color: string }> = {
  process_start:     { icon: Activity,   color: 'var(--accent)' },
  process_end:       { icon: X,          color: 'var(--text-3)' },
  file_create:       { icon: FileCode,   color: 'var(--green)' },
  registry_change:   { icon: Database,   color: 'var(--yellow)' },
  dns_query:         { icon: Globe,      color: '#38bdf8' },
  network:           { icon: Network,    color: '#38bdf8' },
  login:             { icon: LogIn,      color: 'var(--accent)' },
  usb:               { icon: Usb,        color: 'var(--orange)' },
  powershell:        { icon: Terminal,   color: '#a78bfa' },
  scheduled_task:    { icon: CalendarClock, color: 'var(--orange)' },
  alert:             { icon: Bell,       color: 'var(--red)' },
  response:          { icon: Zap,        color: 'var(--yellow)' },
  default:           { icon: Clock,      color: 'var(--text-3)' },
};

// ── Small helpers ─────────────────────────────────────────────────────────────

function EmptyState({ msg, action }: { msg: string; action?: React.ReactNode }) {
  return (
    <div className="py-12 text-center space-y-3">
      <p className="text-sm" style={{ color: 'var(--text-2)' }}>{msg}</p>
      {action && <div>{action}</div>}
    </div>
  );
}

function TabLoader() {
  return <div className="py-12 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>;
}

function SevDot({ sev }: { sev: string }) {
  const c: Record<string, string> = { critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--blue)' };
  return <span className="h-2 w-2 rounded-full shrink-0 mt-1" style={{ background: c[sev] ?? 'var(--text-3)' }} />;
}

function MitreBadge({ tactic, technique }: { tactic?: string; technique?: string }) {
  if (!tactic && !technique) return null;
  return (
    <span className="text-[9px] font-mono px-1.5 py-0.5 rounded" style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
      {technique || tactic}
    </span>
  );
}

function StatusPill({ ok, label, unknown }: { ok?: boolean | null; label: string; unknown?: boolean }) {
  if (unknown || ok == null) {
    return (
      <div className="flex items-center justify-between p-3 rounded-lg" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
        <span className="text-xs" style={{ color: 'var(--text-2)' }}>{label}</span>
        <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>Unknown</span>
      </div>
    );
  }
  return (
    <div className="flex items-center justify-between p-3 rounded-lg" style={{ background: ok ? 'rgba(34,197,94,.06)' : 'rgba(248,81,73,.06)', border: `1px solid ${ok ? 'rgba(34,197,94,.2)' : 'rgba(248,81,73,.2)'}` }}>
      <span className="text-xs" style={{ color: 'var(--text-2)' }}>{label}</span>
      <span className="text-[10px] font-semibold flex items-center gap-1" style={{ color: ok ? 'var(--green)' : 'var(--red)' }}>
        {ok ? <Check className="h-3 w-3" /> : <X className="h-3 w-3" />}
        {ok ? 'Enabled' : 'Disabled'}
      </span>
    </div>
  );
}

interface Column { key: string; label: string; width?: string; mono?: boolean; upper?: boolean; badge?: boolean; fmt?: (v: any, row: any) => React.ReactNode; }

function DataTable({ data, loading, search, setSearch, onCollect, dispatching, collectLabel, searchKeys, columns, rowStyle }: {
  data: any[] | null; loading: boolean; search: string; setSearch: (s: string) => void;
  onCollect?: () => void; dispatching?: boolean; collectLabel?: string;
  searchKeys: string[]; columns: Column[]; rowStyle?: (row: any) => React.CSSProperties;
}) {
  const rows = data || [];
  const filtered = search
    ? rows.filter(r => searchKeys.some(k => String(r[k] ?? '').toLowerCase().includes(search.toLowerCase())))
    : rows;
  const gridCols = columns.map(c => c.width || '1fr').join(' ');

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[180px] max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Filter…"
            className="g-input pl-8" style={{ height: 32, fontSize: 12 }} />
        </div>
        {onCollect && (
          <button onClick={onCollect} disabled={dispatching} className="g-btn g-btn-primary text-xs">
            <Play className="h-3 w-3" /> {dispatching ? 'Dispatching…' : collectLabel}
          </button>
        )}
      </div>
      {loading ? <TabLoader /> : rows.length === 0 ? (
        <EmptyState msg="No data yet. Dispatch the collect task above." />
      ) : (
        <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
          <div className="g-thead grid gap-3 px-3" style={{ gridTemplateColumns: gridCols }}>
            {columns.map(c => <span key={c.key}>{c.label}</span>)}
          </div>
          <div className="max-h-[480px] overflow-y-auto">
            {filtered.length === 0 ? (
              <div className="py-8 text-center text-xs" style={{ color: 'var(--text-3)' }}>No matches for &quot;{search}&quot;</div>
            ) : filtered.map((row, i) => (
              <div key={i} className="g-tr grid gap-3 items-center px-3 py-2"
                style={{ gridTemplateColumns: gridCols, ...(rowStyle?.(row) ?? {}) }}>
                {columns.map(c => {
                  if (c.fmt) return <span key={c.key}>{c.fmt(row[c.key], row)}</span>;
                  const val = row[c.key];
                  if (c.badge) return (
                    <span key={c.key} className={String(val).toLowerCase().includes('running') || String(val).toLowerCase().includes('active') ? 's-online' : 's-offline'}>{val}</span>
                  );
                  return (
                    <span key={c.key} className={`text-xs truncate ${c.mono ? 'mono' : ''} ${c.upper ? 'uppercase' : ''}`}
                      style={{ color: c.mono ? 'var(--text-2)' : 'var(--text-1)' }}>
                      {val ?? '—'}
                    </span>
                  );
                })}
              </div>
            ))}
          </div>
        </div>
      )}
      {rows.length > 0 && (
        <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>Showing {filtered.length} of {rows.length}</p>
      )}
    </div>
  );
}

// ── Main page component ────────────────────────────────────────────────────────

export default function AgentDetailPage() {
  const params  = useParams();
  const agentId = parseInt(params.id as string);

  const [agent, setAgent]       = useState<Agent | null>(null);
  const [summary, setSummary]   = useState<AgentSummary | null>(null);
  const [vulns, setVulns]       = useState<Vulnerability[]>([]);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [agentAlerts, setAgentAlerts] = useState<Alert[]>([]);
  const [riskScore, setRiskScore] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState('alerts');
  const [loading, setLoading]   = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [dispatching, setDispatching] = useState(false);
  const [toast, setToast]       = useState<string | null>(null);
  const [tabLoading, setTabLoading] = useState(false);
  const [search, setSearch]     = useState('');
  const [tlFilter, setTlFilter] = useState('');
  const [alertFilter, setAlertFilter] = useState<'all' | 'open' | 'resolved'>('all');

  // Tab data (lazy-loaded)
  const [processes,      setProcesses]      = useState<any[] | null>(null);
  const [auditEvents,    setAuditEvents]    = useState<any[] | null>(null);
  const [connections,    setConnections]    = useState<Connection[] | null>(null);
  const [services,       setServices]       = useState<any[] | null>(null);
  const [users,          setUsers]          = useState<any[] | null>(null);
  const [packages,       setPackages]       = useState<any[] | null>(null);
  const [fimAlerts,      setFimAlerts]      = useState<FIMAlert[] | null>(null);
  const [fimBaseline,    setFimBaseline]    = useState<FIMBaseline[] | null>(null);
  const [authLogs,       setAuthLogs]       = useState<any[] | null>(null);
  const [anomalies,      setAnomalies]      = useState<any[] | null>(null);
  const [runningAnomaly, setRunningAnomaly] = useState(false);
  const [taskHistory,    setTaskHistory]    = useState<any[] | null>(null);
  const [fileHashes,     setFileHashes]     = useState<any[] | null>(null);
  const [startupItems,   setStartupItems]   = useState<any[] | null>(null);
  const [usbHistory,     setUsbHistory]     = useState<any[] | null>(null);
  const [loginHistory,   setLoginHistory]   = useState<any[] | null>(null);
  const [scheduledTasks, setScheduledTasks] = useState<any[] | null>(null);
  const [drivers,        setDrivers]        = useState<any[] | null>(null);
  const [policies,       setPolicies]       = useState<any | null>(undefined);
  const [secStatus,      setSecStatus]      = useState<any | null>(null);
  const [cisFindings,    setCisFindings]    = useState<any[] | null>(null);
  const [cisScore,       setCisScore]       = useState<any | null>(null);
  const [auditHistory,   setAuditHistory]   = useState<AgentAuditEntry[] | null>(null);

  // Live Response state
  const [lrHistory, setLrHistory] = useState<{ cmd: string; output: string; ts: string }[]>([]);
  const [lrInput,   setLrInput]   = useState('');
  const [lrRunning, setLrRunning] = useState(false);
  const lrBottomRef = useRef<HTMLDivElement>(null);

  const showToast = useCallback((msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 4000);
  }, []);

  const load = useCallback(async () => {
    try {
      const agentRes = await agentsAPI.getById(agentId);
      setAgent(agentRes.data);
    } catch {
      setNotFound(true);
      setLoading(false);
      return;
    }
    const results = await Promise.allSettled([
      agentsAPI.getSummary(agentId),
      agentsAPI.getVulnerabilities(agentId),
      agentsAPI.getTimeline(agentId),
      alertsAPI.getByAgent(agentId),
      agentsAPI.getRisk(agentId),
    ]);
    if (results[0].status === 'fulfilled') setSummary(results[0].value.data);
    if (results[1].status === 'fulfilled') setVulns(results[1].value.data || []);
    if (results[2].status === 'fulfilled') setTimeline(results[2].value.data || []);
    if (results[3].status === 'fulfilled') setAgentAlerts(results[3].value.data || []);
    if (results[4].status === 'fulfilled' && results[4].value.data)
      setRiskScore(results[4].value.data.risk_score ?? null);
    setLoading(false);
  }, [agentId]);

  useEffect(() => { if (!isNaN(agentId)) load(); }, [agentId, load]);

  const loadTabData = useCallback(async (tab: string) => {
    setSearch('');
    setTabLoading(true);
    try {
      switch (tab) {
        case 'processes':
          if (!processes) { const r = await agentsAPI.getProcesses(agentId); setProcesses(r.data || []); }
          break;
        case 'network':
          if (!connections) { const r = await agentsAPI.getConnections(agentId); setConnections(r.data || []); }
          break;
        case 'users':
          if (!users) {
            const [u, lh] = await Promise.allSettled([agentsAPI.getUsers(agentId), agentsAPI.getLoginHistory(agentId)]);
            if (u.status === 'fulfilled') setUsers(u.value.data || []);
            if (lh.status === 'fulfilled') setLoginHistory(lh.value.data || []);
          }
          break;
        case 'software':
          if (!packages) {
            const [p, sv, st, d] = await Promise.allSettled([
              agentsAPI.getPackages(agentId), agentsAPI.getServices(agentId),
              agentsAPI.getStartup(agentId), agentsAPI.getDrivers(agentId),
            ]);
            if (p.status === 'fulfilled') setPackages(p.value.data || []);
            if (sv.status === 'fulfilled') setServices(sv.value.data || []);
            if (st.status === 'fulfilled') setStartupItems(st.value.data || []);
            if (d.status === 'fulfilled') setDrivers(d.value.data || []);
          }
          break;
        case 'fim':
          if (!fimAlerts) {
            const [fa, fb] = await Promise.allSettled([fimAPI.getAlerts(agentId), fimAPI.getBaseline(agentId)]);
            if (fa.status === 'fulfilled') setFimAlerts(fa.value.data || []);
            if (fb.status === 'fulfilled') setFimBaseline(fb.value.data || []);
          }
          if (!fileHashes) agentsAPI.getFileHashes(agentId).then(r => setFileHashes(Array.isArray(r.data) ? r.data : [])).catch(() => setFileHashes([]));
          break;
        case 'device_control':
          if (!usbHistory) { const r = await agentsAPI.getUsbHistory(agentId); setUsbHistory(r.data || []); }
          break;
        case 'ai_analysis':
          if (!anomalies) { const r = await aiAPI.getAnomalies(agentId).catch(() => ({ data: [] })); setAnomalies(r.data || []); }
          break;
        case 'tasks':
          if (!taskHistory) { const r = await agentsAPI.getTasks(agentId); setTaskHistory(r.data || []); }
          break;
        case 'security':
          if (!secStatus) { const r = await agentsAPI.getSecurityStatus(agentId); setSecStatus(r.data); }
          break;
        case 'compliance':
          if (!cisFindings) {
            const [f, s] = await Promise.allSettled([agentsAPI.getCISFindings(agentId), agentsAPI.getCISScore(agentId)]);
            if (f.status === 'fulfilled') setCisFindings(f.value.data || []);
            if (s.status === 'fulfilled') setCisScore(s.value.data);
          }
          break;
        case 'policies':
          if (policies === undefined) { const r = await agentsAPI.getPolicies(agentId); setPolicies(r.data || null); }
          break;
        case 'audit_history':
          if (!auditHistory) { const r = await agentsAPI.getAuditHistory(agentId); setAuditHistory(r.data || []); }
          break;
      }
    } finally {
      setTabLoading(false);
    }
  }, [agentId, processes, connections, users, packages, services, startupItems, drivers, fimAlerts, fileHashes, authLogs, anomalies, taskHistory, usbHistory, loginHistory, scheduledTasks, secStatus, cisFindings, policies, auditHistory]);

  const selectTab = (tab: string) => { setActiveTab(tab); loadTabData(tab); };

  const dispatch = async (taskType: string, refreshTab?: string) => {
    setDispatching(true);
    try {
      await tasksAPI.create({ agent_id: agentId, task_type: taskType, payload: {} });
      showToast('✓ Task dispatched — refresh in ~15s');
      if (refreshTab) setTimeout(async () => {
        switch (refreshTab) {
          case 'processes':   setProcesses(null);   if (activeTab === 'processes')   loadTabData('processes'); break;
          case 'network':     setConnections(null); if (activeTab === 'network')     loadTabData('network'); break;
          case 'users':       setUsers(null);       if (activeTab === 'users')       loadTabData('users'); break;
          case 'fim':         setFimAlerts(null); setFimBaseline(null); if (activeTab === 'fim') loadTabData('fim'); break;
          case 'software':    setPackages(null); setServices(null); setStartupItems(null); setDrivers(null); if (activeTab === 'software') loadTabData('software'); break;
        }
        load();
      }, 10000);
    } catch {
      showToast('Failed to dispatch task');
    } finally {
      setDispatching(false);
    }
  };

  const acceptFIMBaseline = async (filePath: string) => {
    try {
      await fimAPI.acceptBaseline(agentId, filePath);
      showToast('✓ Baseline accepted for ' + filePath);
      setFimAlerts(null); setFimBaseline(null);
      loadTabData('fim');
    } catch {
      showToast('Failed to accept baseline');
    }
  };

  // Live Response: dispatch shell task and poll for result
  const runLRCommand = async () => {
    const cmd = lrInput.trim();
    if (!cmd || lrRunning) return;
    setLrInput('');
    setLrRunning(true);
    const ts = new Date().toLocaleTimeString();
    try {
      const res = await tasksAPI.create({ agent_id: agentId, task_type: 'execute_script', payload: { command: cmd } });
      const taskId = res.data?.id;
      let output = 'Task dispatched, polling for result…';
      if (taskId) {
        await new Promise(r => setTimeout(r, 4000));
        try {
          const hist = await agentsAPI.getTasks(agentId);
          const t = (hist.data || []).find((x: any) => x.id === taskId);
          if (t?.result) output = t.result;
        } catch { /* silent */ }
      }
      setLrHistory(h => [...h, { cmd, output, ts }]);
    } catch {
      setLrHistory(h => [...h, { cmd, output: 'Error dispatching command', ts }]);
    } finally {
      setLrRunning(false);
      setTimeout(() => lrBottomRef.current?.scrollIntoView({ behavior: 'smooth' }), 100);
    }
  };

  // Derived stats
  const critAlerts  = agentAlerts.filter(a => a.severity === 'critical').length;
  const openAlerts  = agentAlerts.filter(a => a.status === 'open' || !a.status).length;
  const critVulns   = vulns.filter(v => v.severity === 'critical').length;

  const kpiCards = [
    { label: 'Processes',   val: summary?.processes   ?? '—', icon: Activity,   tab: 'processes' },
    { label: 'Connections', val: summary?.connections ?? '—', icon: Network,    tab: 'network' },
    { label: 'Alerts',      val: agentAlerts.length,          icon: Bell,        tab: 'alerts',  warn: critAlerts > 0 },
    { label: 'Vulns',       val: vulns.length,                icon: Bug,         tab: 'vulnerabilities', warn: critVulns > 0 },
    { label: 'Users',       val: summary?.users       ?? '—', icon: Users,       tab: 'users' },
    { label: 'Risk Score',  val: riskScore !== null ? riskScore : '—', icon: ShieldAlert, tab: 'security', warn: (riskScore ?? 0) > 70 },
  ];

  if (loading) return (
    <RootLayout title="Loading agent…">
      <div className="flex h-64 items-center justify-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading agent…</div>
    </RootLayout>
  );
  if (notFound || !agent) return (
    <RootLayout title="Agent Not Found">
      <div className="flex flex-col items-center justify-center h-64 gap-3">
        <ShieldAlert className="h-10 w-10" style={{ color: 'var(--text-3)' }} />
        <p className="text-sm" style={{ color: 'var(--text-2)' }}>Agent not found or unreachable.</p>
        <Link href="/agents" className="text-xs" style={{ color: 'var(--accent)' }}>← Back to agents</Link>
      </div>
    </RootLayout>
  );

  const isWindows = agent.os?.toLowerCase().includes('windows');
  const isLinux   = agent.os?.toLowerCase().includes('linux');
  const isMobile  = agent.os?.toLowerCase().includes('android') || agent.os?.toLowerCase().includes('ios');

  return (
    <RootLayout title={agent.hostname} subtitle={`${agent.os} · ${agent.ip_address}`} onRefresh={load}
      actions={
        <Link href="/agents" className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
          <ArrowLeft className="h-3.5 w-3.5" /> All Agents
        </Link>
      }>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)' }}>
          {toast}
        </div>
      )}

      <div className="space-y-4">

        {/* ── Status & breadcrumb ──────────────────────────────────── */}
        <div className="flex items-center justify-between flex-wrap gap-2">
          <Link href="/agents" className="flex items-center gap-1 text-xs" style={{ color: 'var(--text-2)' }}>
            <ArrowLeft className="h-3.5 w-3.5" /> All agents
          </Link>
          <div className="flex items-center gap-2 flex-wrap">
            {agent.is_isolated && (
              <span className="text-xs font-semibold px-2 py-0.5 rounded flex items-center gap-1"
                style={{ background: '#f8514918', color: '#f85149', border: '1px solid #f8514940' }}>
                <ShieldOff className="h-3.5 w-3.5" /> Network Isolated
              </span>
            )}
            {agent.tamper_protection && (
              <span className="text-xs font-semibold px-2 py-0.5 rounded flex items-center gap-1"
                style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                <Shield className="h-3.5 w-3.5" /> Tamper Protection ON
              </span>
            )}
            <span className={agent.status === 'online' ? 's-online' : 's-offline'}>{agent.status}</span>
          </div>
        </div>

        {/* ── 3-column info cards ──────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">

          {/* Basic Information */}
          <div className="g-card p-4 space-y-2">
            <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Basic Information</p>
            <div className="grid grid-cols-2 gap-2 text-xs">
              {[
                { l: 'Agent ID',       v: String(agent.id) },
                { l: 'Hostname',       v: agent.hostname },
                { l: 'Host UUID',      v: agent.machine_id ? agent.machine_id.slice(0, 20) + '…' : '—' },
                { l: 'IP Address',     v: agent.ip_address },
                { l: 'OS',             v: agent.os },
                { l: 'Platform',       v: agent.platform_category || '—' },
                { l: 'Agent Version',  v: agent.version || '—' },
                { l: 'Last Seen',      v: timeAgo(agent.last_seen) },
                { l: 'Installed',      v: agent.created_at ? formatDate(agent.created_at) : agent.created_At ? formatDate(agent.created_At) : '—' },
                { l: 'Uptime',         v: formatUptime(agent.uptime_seconds) },
              ].map(({ l, v }) => (
                <div key={l}>
                  <p style={{ color: 'var(--text-3)' }}>{l}</p>
                  <p className="mt-0.5 font-medium mono truncate" title={v} style={{ color: 'var(--text-1)' }}>{v}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Hardware Info */}
          <div className="g-card p-4 space-y-2">
            <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Hardware</p>
            <div className="grid grid-cols-2 gap-2 text-xs">
              {[
                { l: 'Agent Memory',   v: agent.mem_alloc_mb != null ? `${agent.mem_alloc_mb} MB` : '—' },
                { l: 'Goroutines',     v: agent.goroutines ?? '—' },
                { l: 'Load (1m)',      v: agent.load_avg_1m != null ? agent.load_avg_1m.toFixed(2) : '—' },
                { l: 'Load (5m)',      v: agent.load_avg_5m != null ? agent.load_avg_5m.toFixed(2) : '—' },
                { l: 'Load (15m)',     v: agent.load_avg_15m != null ? agent.load_avg_15m.toFixed(2) : '—' },
                { l: 'Open FDs',       v: agent.open_fds ?? '—' },
                { l: 'Storage Free',   v: agent.storage_free_gb != null ? `${agent.storage_free_gb.toFixed(1)} GB` : '—' },
                { l: 'Storage Total',  v: agent.storage_total_gb != null ? `${agent.storage_total_gb.toFixed(1)} GB` : '—' },
                ...(isMobile ? [
                  { l: 'Battery',      v: agent.battery_level != null ? `${agent.battery_level}% ${agent.battery_charging ? '⚡' : ''}` : '—' },
                  { l: 'Network Type', v: agent.network_type || '—' },
                ] : []),
              ].map(({ l, v }) => (
                <div key={l}>
                  <p style={{ color: 'var(--text-3)' }}>{l}</p>
                  <p className="mt-0.5 font-medium mono truncate" style={{ color: 'var(--text-1)' }}>{String(v)}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Security Quick Status */}
          <div className="g-card p-4 space-y-2">
            <div className="flex items-center justify-between">
              <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Security Status</p>
              <button onClick={() => selectTab('security')} className="text-[10px]" style={{ color: 'var(--accent)' }}>Details →</button>
            </div>
            <div className="space-y-1.5">
              <StatusPill ok={true} label="EDR Agent" />
              <StatusPill ok={agent.tamper_protection ?? null} label="Tamper Protection" unknown={agent.tamper_protection == null} />
              <StatusPill ok={agent.is_isolated ? false : true} label="Network Access" />
              {isMobile && <>
                <StatusPill ok={agent.is_rooted === false ? true : agent.is_rooted === true ? false : null} label="Root Status" unknown={agent.is_rooted == null} />
                <StatusPill ok={agent.vpn_active ?? null} label="VPN Active" unknown={agent.vpn_active == null} />
              </>}
              {[
                { label: 'Firewall', val: critAlerts === 0 },
                { label: 'Open Alerts', val: openAlerts === 0 },
                { label: 'Critical Vulns', val: critVulns === 0 },
              ].map(({ label, val }) => (
                <StatusPill key={label} ok={val} label={label} />
              ))}
            </div>
          </div>
        </div>

        {/* ── KPI stat cards ──────────────────────────────────────── */}
        <div className="grid grid-cols-3 gap-3 sm:grid-cols-6">
          {kpiCards.map(({ label, val, icon: Icon, tab, warn }) => (
            <button key={label} onClick={() => selectTab(tab)}
              className="g-card p-3 flex flex-col gap-1 text-left transition-all hover:opacity-90"
              style={{ border: warn ? '1px solid rgba(248,81,73,.3)' : undefined }}>
              <div className="flex items-center gap-1.5">
                <Icon className="h-3.5 w-3.5 shrink-0" style={{ color: warn ? 'var(--red)' : 'var(--accent)' }} />
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{label}</p>
              </div>
              <p className="text-xl font-semibold tabular-nums" style={{ color: warn ? 'var(--red)' : 'var(--text-1)' }}>{val}</p>
            </button>
          ))}
        </div>

        {/* ── Tab navigation ──────────────────────────────────────── */}
        <div className="g-card overflow-hidden">
          <div style={{ borderBottom: '1px solid var(--border)' }}>
            {TAB_GROUPS.map(group => (
              <div key={group.label}>
                <div className="px-4 pt-2 pb-0.5">
                  <p className="text-[9px] font-semibold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>{group.label}</p>
                </div>
                <div className="flex overflow-x-auto">
                  {group.tabs.map(tab => {
                    const Icon = tab.icon;
                    return (
                      <button key={tab.id} onClick={() => selectTab(tab.id)}
                        className="flex items-center gap-1.5 whitespace-nowrap px-3 py-2 text-[11px] font-medium transition-colors"
                        style={{
                          color: activeTab === tab.id ? 'var(--accent)' : 'var(--text-2)',
                          borderBottom: activeTab === tab.id ? '2px solid var(--accent)' : '2px solid transparent',
                        }}>
                        <Icon className="h-3.5 w-3.5 shrink-0" />
                        <span className="hidden sm:inline">{tab.label}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>

          {/* ── Tab Content ───────────────────────────────────────── */}
          <div className="p-4 overflow-y-auto" style={{ maxHeight: 'calc(100vh - 400px)', minHeight: 300 }}>

            {/* ── Alerts ──────────────────────────────────────────── */}
            {activeTab === 'alerts' && (
              <div className="space-y-3">
                <div className="flex items-center gap-2 flex-wrap">
                  {(['all', 'open', 'resolved'] as const).map(f => (
                    <button key={f} onClick={() => setAlertFilter(f)}
                      className="text-xs px-3 py-1 rounded-lg capitalize"
                      style={{ background: alertFilter === f ? 'var(--accent-glow)' : 'var(--bg-0)', color: alertFilter === f ? 'var(--accent)' : 'var(--text-2)', border: `1px solid ${alertFilter === f ? 'var(--accent-border)' : 'var(--border)'}` }}>
                      {f} {f === 'all' ? `(${agentAlerts.length})` : `(${agentAlerts.filter(a => f === 'open' ? (a.status === 'open' || !a.status) : a.status === f).length})`}
                    </button>
                  ))}
                </div>
                {agentAlerts.length === 0 ? <EmptyState msg="No alerts for this endpoint." /> :
                  agentAlerts
                    .filter(a => alertFilter === 'all' ? true : alertFilter === 'open' ? (a.status === 'open' || !a.status) : a.status === alertFilter)
                    .map(a => (
                      <div key={a.id} className="flex items-start gap-3 rounded-lg p-3" style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}>
                        <SevDot sev={a.severity} />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <p className="text-sm font-medium" style={{ color: 'var(--text-1)' }}>{a.rule_name}</p>
                            <MitreBadge tactic={a.mitre_tactic} technique={a.mitre_technique} />
                          </div>
                          <p className="text-xs mt-0.5 truncate" style={{ color: 'var(--text-2)' }}>{a.log_message}</p>
                          {a.ai_summary && <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>AI: {a.ai_summary}</p>}
                        </div>
                        <div className="shrink-0 text-right space-y-1">
                          <span className={sevClass(a.severity)}>{a.severity}</span>
                          <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(a.created_at)}</p>
                          <p className="text-[10px] capitalize" style={{ color: a.status === 'resolved' ? 'var(--green)' : a.status === 'acknowledged' ? 'var(--yellow)' : 'var(--text-3)' }}>
                            {a.status || 'open'}
                          </p>
                        </div>
                      </div>
                    ))}
              </div>
            )}

            {/* ── Timeline ────────────────────────────────────────── */}
            {activeTab === 'timeline' && (
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <Search className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
                  <input value={tlFilter} onChange={e => setTlFilter(e.target.value)} placeholder="Filter events…"
                    className="g-input flex-1" style={{ height: 30, fontSize: 11 }} />
                </div>
                {timeline.length === 0 ? <EmptyState msg="No timeline events." /> : (
                  <div className="relative pl-5 space-y-3">
                    <div className="absolute left-2 top-0 bottom-0 w-px" style={{ background: 'var(--border)' }} />
                    {timeline
                      .filter(ev => !tlFilter || ev.message?.toLowerCase().includes(tlFilter.toLowerCase()) || ev.event_type?.toLowerCase().includes(tlFilter.toLowerCase()))
                      .map((ev, i) => {
                        const { icon: Icon, color } = TL_ICONS[ev.event_type] ?? TL_ICONS.default;
                        return (
                          <div key={i} className="relative flex items-start gap-2">
                            <div className="absolute -left-3 top-1 h-5 w-5 rounded-full flex items-center justify-center" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                              <Icon className="h-3 w-3" style={{ color }} />
                            </div>
                            <div className="ml-1">
                              <p className="text-xs leading-relaxed" style={{ color: 'var(--text-1)' }}>{ev.message}</p>
                              <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{formatDate(ev.created_at)} · <span className="capitalize">{ev.event_type?.replace(/_/g, ' ')}</span></p>
                            </div>
                          </div>
                        );
                      })}
                  </div>
                )}
              </div>
            )}

            {/* ── Vulnerabilities ──────────────────────────────────── */}
            {activeTab === 'vulnerabilities' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <div className="flex gap-3 text-xs">
                    <span style={{ color: 'var(--red)' }}>{critVulns} critical</span>
                    <span style={{ color: 'var(--orange)' }}>{vulns.filter(v => v.severity === 'high').length} high</span>
                    <span style={{ color: 'var(--text-3)' }}>{vulns.length} total</span>
                  </div>
                  <button onClick={() => dispatch('vulnerability_scan')} disabled={dispatching} className="g-btn g-btn-primary text-xs">
                    <Play className="h-3 w-3" /> {dispatching ? 'Scanning…' : 'Run Scan'}
                  </button>
                </div>
                {vulns.length === 0 ? <EmptyState msg="No vulnerabilities found. Run a scan." /> :
                  (() => {
                    const seen = new Set<string>();
                    return vulns.filter(v => { const k = v.cve_id || `${v.package_name}-${v.package_version}`; if (seen.has(k)) return false; seen.add(k); return true; })
                      .map(v => (
                        <div key={v.id} className="rounded-lg p-3 space-y-1" style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}>
                          <div className="flex items-start gap-2">
                            <span className={sevClass(v.severity)}>{v.severity}</span>
                            <p className="text-xs font-medium flex-1" style={{ color: 'var(--text-1)' }}>{v.name}</p>
                            {v.cve_id && <span className="mono text-[10px]" style={{ color: 'var(--accent)' }}>{v.cve_id}</span>}
                          </div>
                          <p className="text-[11px]" style={{ color: 'var(--text-2)' }}>{v.description}</p>
                          {v.remediation && <p className="text-[10px]" style={{ color: 'var(--green)' }}>Fix: {v.remediation}</p>}
                          <div className="flex gap-3 text-[10px]" style={{ color: 'var(--text-3)' }}>
                            {(v as any).epss_score != null && <span>EPSS: {((v as any).epss_score * 100).toFixed(2)}%</span>}
                            {(v as any).kev && <span className="font-bold" style={{ color: 'var(--red)' }}>⚠ KEV</span>}
                            {(v as any).cvss_score != null && <span>CVSS: {(v as any).cvss_score}</span>}
                          </div>
                        </div>
                      ));
                  })()
                }
              </div>
            )}

            {/* ── File Monitoring ──────────────────────────────────── */}
            {activeTab === 'fim' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                    Baseline: {fimBaseline?.length || 0} · Violations: {fimAlerts?.length || 0} · Hashes: {fileHashes?.length || 0}
                  </p>
                  <div className="flex gap-2">
                    <button onClick={() => dispatch('collect_file_hashes', 'fim')} disabled={dispatching} className="g-btn g-btn-ghost text-xs">
                      <Hash className="h-3 w-3" /> Collect Hashes
                    </button>
                    <button onClick={() => dispatch('fim_scan', 'fim')} disabled={dispatching} className="g-btn g-btn-primary text-xs">
                      <Play className="h-3 w-3" /> {dispatching ? 'Scanning…' : 'Run FIM Scan'}
                    </button>
                  </div>
                </div>
                {tabLoading ? <TabLoader /> : (
                  <>
                    {(fimAlerts?.length || 0) > 0 && (
                      <div>
                        <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-2)' }}>FIM Violations</p>
                        <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                          <div className="g-thead grid gap-3 px-3" style={{ gridTemplateColumns: '100px 1fr 100px 80px 70px' }}>
                            <span>Change</span><span>File Path</span><span>Details</span><span>Time</span><span></span>
                          </div>
                          {fimAlerts!.map((a, i) => {
                            const colors: Record<string, string> = { modified: 'var(--orange)', deleted: 'var(--red)', created: 'var(--green)', permission_change: '#a78bfa' };
                            const c = colors[a.change_type] ?? 'var(--text-3)';
                            return (
                              <div key={i} className="g-tr grid gap-3 items-center px-3 py-2" style={{ gridTemplateColumns: '100px 1fr 100px 80px 70px' }}>
                                <span className="text-[10px] font-medium capitalize px-1.5 py-0.5 rounded w-fit" style={{ background: `${c}15`, color: c, border: `1px solid ${c}40` }}>
                                  {a.change_type.replace('_', ' ')}
                                </span>
                                <span className="mono text-[11px] truncate" style={{ color: 'var(--text-1)' }}>{a.file_path}</span>
                                <span className="mono text-[10px] truncate" style={{ color: 'var(--text-3)' }}>{a.new_hash?.slice(0, 12) || '—'}</span>
                                <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(a.created_at)}</span>
                                <button onClick={() => acceptFIMBaseline(a.file_path)} className="g-btn g-btn-ghost text-[10px]">Accept</button>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}
                    {(fileHashes?.length || 0) > 0 && (
                      <div>
                        <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-2)' }}>File Hashes ({fileHashes!.length})</p>
                        <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                          <div className="g-thead grid gap-3 px-3" style={{ gridTemplateColumns: '2fr 1fr 100px 70px' }}>
                            <span>Path</span><span>SHA256</span><span>MD5</span><span>Size</span>
                          </div>
                          {fileHashes!.slice(0, 100).map((h: any, i: number) => (
                            <div key={i} className="g-tr grid gap-3 items-center px-3 py-1.5" style={{ gridTemplateColumns: '2fr 1fr 100px 70px' }}>
                              <span className="mono text-[10px] truncate" style={{ color: 'var(--text-1)' }}>{h.file_path}</span>
                              <span className="mono text-[10px] truncate" style={{ color: 'var(--text-3)' }}>{h.sha256_hash?.slice(0, 16) || '—'}…</span>
                              <span className="mono text-[10px]" style={{ color: 'var(--text-3)' }}>{h.md5_hash?.slice(0, 12) || '—'}…</span>
                              <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{h.file_size ? (h.file_size / 1024).toFixed(1) + ' KB' : '—'}</span>
                            </div>
                          ))}
                        </div>
                        {fileHashes!.length > 100 && <p className="text-[11px] mt-1" style={{ color: 'var(--text-3)' }}>Showing 100 of {fileHashes!.length}</p>}
                      </div>
                    )}
                    {(fimAlerts?.length || 0) === 0 && (fileHashes?.length || 0) === 0 && (
                      <EmptyState msg="No file monitoring data. Run FIM Scan or Collect Hashes." />
                    )}
                  </>
                )}
              </div>
            )}

            {/* ── AI Analysis ──────────────────────────────────────── */}
            {activeTab === 'ai_analysis' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>AI Behavioral Analysis</p>
                    <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Detects anomalous process, connection, and user behavior patterns</p>
                  </div>
                  <button onClick={async () => {
                    setRunningAnomaly(true);
                    try {
                      const r = await aiAPI.runAnomaly(agentId);
                      setAnomalies(r.data?.findings || []);
                    } catch (e: any) {
                      showToast(e?.response?.data?.error || 'AI analysis failed');
                    } finally { setRunningAnomaly(false); }
                  }} disabled={runningAnomaly} className="g-btn g-btn-primary text-xs">
                    <Brain className="h-3 w-3" /> {runningAnomaly ? 'Analyzing…' : 'Run AI Detection'}
                  </button>
                </div>

                {tabLoading || runningAnomaly ? (
                  <div className="py-8 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>
                    {runningAnomaly ? 'AI analyzing endpoint behavioral data…' : 'Loading…'}
                  </div>
                ) : (anomalies?.length || 0) === 0 ? (
                  <div className="space-y-3">
                    <EmptyState msg="No anomalies detected. Run AI Detection to analyze processes, connections, and user behavior." />
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      {[
                        { icon: Terminal, title: 'Process Anomaly', desc: 'PowerShell spawned from WINWORD.EXE with an encoded command.' },
                        { icon: Network,  title: 'Network Beacon',  desc: 'This endpoint has communicated with 3 malicious IPs in 24h.' },
                        { icon: GitBranch,title: 'Unusual Lineage', desc: 'Unusual parent-child process relationship detected.' },
                        { icon: Shield,   title: 'Recommendation',  desc: 'Recommended action: isolate endpoint for forensic analysis.' },
                      ].map(({ icon: Icon, title, desc }) => (
                        <div key={title} className="rounded-lg p-3 flex gap-3" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                          <Icon className="h-4 w-4 shrink-0 mt-0.5" style={{ color: 'var(--text-3)' }} />
                          <div>
                            <p className="text-[11px] font-medium" style={{ color: 'var(--text-2)' }}>{title}</p>
                            <p className="text-[10px] mt-0.5 italic" style={{ color: 'var(--text-3)' }}>&quot;{desc}&quot;</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {anomalies!.map((a: any, i: number) => (
                      <div key={i} className="g-card p-4">
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                              <span className="text-[10px] capitalize px-2 py-0.5 rounded" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>{a.finding_type}</span>
                              <span className={sevClass(a.severity)}>{a.severity}</span>
                              {a.mitre_technique && <MitreBadge technique={a.mitre_technique} />}
                            </div>
                            <p className="text-xs leading-relaxed" style={{ color: 'var(--text-1)' }}>{a.description}</p>
                            {a.raw_context?.indicator && (
                              <p className="mono text-[10px] mt-1.5 px-2 py-1 rounded" style={{ background: 'var(--bg-0)', color: 'var(--accent)' }}>
                                {a.raw_context.indicator}
                              </p>
                            )}
                            {a.recommended_action && (
                              <p className="text-[10px] mt-1.5" style={{ color: 'var(--green)' }}>→ {a.recommended_action}</p>
                            )}
                          </div>
                          <span className="text-[10px] shrink-0" style={{ color: 'var(--text-3)' }}>{timeAgo(a.created_at)}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* ── Processes ────────────────────────────────────────── */}
            {activeTab === 'processes' && (
              <DataTable
                data={processes} loading={tabLoading} search={search} setSearch={setSearch}
                onCollect={() => dispatch('collect_processes', 'processes')} dispatching={dispatching}
                collectLabel="Collect Processes" searchKeys={['process_name', 'cmdline', 'username', 'exe_path']}
                rowStyle={r => r.threat_tag ? { background: '#f8514908' } : {}}
                columns={[
                  { key: 'pid',          label: 'PID',      width: '55px',  mono: true },
                  { key: 'ppid',         label: 'PPID',     width: '55px',  mono: true },
                  { key: 'username',     label: 'User',     width: '90px'  },
                  { key: 'process_name', label: 'Name',     width: '130px' },
                  { key: 'cmdline',      label: 'Cmdline',  mono: true },
                  { key: 'cpu_percent',  label: 'CPU%',     width: '55px', fmt: (v) => <span className="mono text-xs">{Number(v || 0).toFixed(1)}</span> },
                  { key: 'mem_percent',  label: 'MEM%',     width: '55px', fmt: (v) => <span className="mono text-xs">{Number(v || 0).toFixed(1)}</span> },
                  { key: 'signed',       label: 'Signed',   width: '55px', fmt: (v) => v != null ? <span style={{ color: v ? 'var(--green)' : 'var(--red)' }}>{v ? '✓' : '✗'}</span> : <span style={{ color: 'var(--text-3)' }}>—</span> },
                ]}
              />
            )}

            {/* ── Network ──────────────────────────────────────────── */}
            {activeTab === 'network' && (
              <div className="space-y-4">
                <DataTable
                  data={connections} loading={tabLoading} search={search} setSearch={setSearch}
                  onCollect={() => dispatch('collect_connections', 'network')} dispatching={dispatching}
                  collectLabel="Collect Connections" searchKeys={['local_address', 'remote_address', 'protocol', 'state', 'process_name']}
                  columns={[
                    { key: 'protocol',       label: 'Proto',   width: '65px', mono: true, upper: true },
                    { key: 'state',          label: 'State',   width: '100px' },
                    { key: 'local_address',  label: 'Local',   mono: true },
                    { key: 'remote_address', label: 'Remote',  mono: true },
                    { key: 'process_name',   label: 'Process', width: '120px', mono: true },
                    { key: 'country',        label: 'Country', width: '80px', fmt: (v) => <span className="text-xs" style={{ color: 'var(--text-3)' }}>{v || '—'}</span> },
                  ]}
                />
                {isMobile && agent.vpn_active != null && (
                  <div className="g-card p-3">
                    <div className="flex items-center gap-2">
                      {agent.vpn_active ? <Wifi className="h-4 w-4" style={{ color: 'var(--green)' }} /> : <WifiOff className="h-4 w-4" style={{ color: 'var(--text-3)' }} />}
                      <span className="text-xs" style={{ color: 'var(--text-1)' }}>VPN: <strong style={{ color: agent.vpn_active ? 'var(--green)' : 'var(--text-3)' }}>{agent.vpn_active ? 'Active' : 'Inactive'}</strong></span>
                      <span className="text-xs ml-2" style={{ color: 'var(--text-3)' }}>Network: {agent.network_type || '—'}</span>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ── User Activity ────────────────────────────────────── */}
            {activeTab === 'users' && (
              <div className="space-y-4">
                {tabLoading ? <TabLoader /> : (
                  <>
                    {/* Logged-in users */}
                    {(users?.length || 0) > 0 && (
                      <div>
                        <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-2)' }}>System Users</p>
                        <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                          <div className="g-thead grid gap-3 px-3" style={{ gridTemplateColumns: '120px 70px 1fr 70px' }}>
                            <span>Username</span><span>UID</span><span>Shell</span><span>Groups</span>
                          </div>
                          {users!.map((u: any, i: number) => (
                            <div key={i} className="g-tr grid gap-3 items-center px-3 py-2" style={{ gridTemplateColumns: '120px 70px 1fr 70px' }}>
                              <span className="text-xs mono font-medium" style={{ color: 'var(--text-1)' }}>{u.username}</span>
                              <span className="mono text-[10px]" style={{ color: 'var(--text-3)' }}>{u.uid}</span>
                              <span className="mono text-[10px] truncate" style={{ color: 'var(--text-2)' }}>{u.shell}</span>
                              <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{u.groups?.length || '—'}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Login history */}
                    {(loginHistory?.length || 0) > 0 && (
                      <div>
                        <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-2)' }}>Login History</p>
                        <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                          <div className="g-thead grid gap-3 px-3" style={{ gridTemplateColumns: '100px 80px 130px 80px 80px 90px' }}>
                            <span>User</span><span>TTY</span><span>Source IP</span><span>Method</span><span>Status</span><span>Time</span>
                          </div>
                          {loginHistory!.map((l: any, i: number) => (
                            <div key={i} className="g-tr grid gap-3 items-center px-3 py-2"
                              style={{ gridTemplateColumns: '100px 80px 130px 80px 80px 90px', background: l.risk === 'critical' ? '#f8514908' : undefined }}>
                              <span className="mono text-xs font-medium" style={{ color: 'var(--text-1)' }}>{l.username}</span>
                              <span className="mono text-[10px]" style={{ color: 'var(--text-3)' }}>{l.tty}</span>
                              <span className="mono text-[10px]" style={{ color: l.risk ? '#fb923c' : 'var(--text-2)' }}>{l.ip}</span>
                              <span className="text-[10px] uppercase" style={{ color: 'var(--text-3)' }}>{l.method}</span>
                              <span className="text-[10px] font-semibold" style={{ color: l.status === 'success' ? 'var(--green)' : '#f85149' }}>{l.status}</span>
                              <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(l.timestamp)}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {(users?.length || 0) === 0 && (loginHistory?.length || 0) === 0 && (
                      <EmptyState msg="No user activity data collected."
                        action={<button onClick={() => dispatch('collect_users', 'users')} className="g-btn g-btn-primary text-xs"><Play className="h-3 w-3" />Collect Users</button>} />
                    )}
                  </>
                )}
              </div>
            )}

            {/* ── Device Control ───────────────────────────────────── */}
            {activeTab === 'device_control' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>{usbHistory?.length ?? 0} device events</p>
                  <button onClick={() => dispatch('collect_usb_history', 'device_control')} disabled={dispatching} className="g-btn g-btn-primary text-xs">
                    <Play className="h-3 w-3" /> Collect Device History
                  </button>
                </div>
                {tabLoading ? <TabLoader /> : (usbHistory?.length ?? 0) === 0 ? (
                  <div className="space-y-3">
                    <EmptyState msg="No device events recorded." />
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      {[
                        { icon: Usb,      label: 'USB Storage' },
                        { icon: HardDrive, label: 'External HDD' },
                        { icon: Bluetooth,label: 'Bluetooth' },
                        { icon: Printer,  label: 'Printers' },
                        { icon: Camera,   label: 'Cameras' },
                        { icon: Tablet,   label: 'Mobile Phones' },
                      ].map(({ icon: Icon, label }) => (
                        <div key={label} className="flex flex-col items-center gap-2 p-3 rounded-lg" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                          <Icon className="h-5 w-5" style={{ color: 'var(--text-3)' }} />
                          <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{label}</span>
                          <span className="text-[10px] font-bold" style={{ color: 'var(--text-3)' }}>—</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {usbHistory!.map((u: any) => (
                      <div key={u.id} className="rounded-lg p-3 flex items-start gap-3"
                        style={{ background: u.risk && u.risk !== 'none' ? '#fb923c08' : 'var(--glass-bg)', border: `1px solid ${u.risk && u.risk !== 'none' ? '#fb923c40' : 'var(--border)'}` }}>
                        <Usb className="h-4 w-4 shrink-0 mt-0.5" style={{ color: u.risk && u.risk !== 'none' ? '#fb923c' : 'var(--text-3)' }} />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{u.device_name}</p>
                          <p className="mono text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>
                            VID:{u.vendor_id} PID:{u.product_id}{u.serial ? ` · S/N:${u.serial}` : ''}
                          </p>
                          {u.mount_point && <p className="mono text-[10px]" style={{ color: 'var(--text-3)' }}>Mounted: {u.mount_point}</p>}
                        </div>
                        <div className="text-right shrink-0">
                          <span className="text-[10px] font-medium capitalize px-1.5 py-0.5 rounded"
                            style={{ background: u.event === 'connected' ? 'var(--accent-glow)' : 'var(--bg-1)', color: u.event === 'connected' ? 'var(--accent)' : 'var(--text-3)' }}>
                            {u.event}
                          </span>
                          <p className="text-[9px] mt-1" style={{ color: 'var(--text-3)' }}>{timeAgo(u.first_seen)}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* ── Performance ──────────────────────────────────────── */}
            {activeTab === 'performance' && (
              <div className="space-y-4">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {[
                    { label: 'Load Avg (1m)',  val: agent.load_avg_1m != null ? agent.load_avg_1m.toFixed(2) : '—', icon: Gauge,    color: (agent.load_avg_1m ?? 0) > 2 ? 'var(--red)' : 'var(--green)' },
                    { label: 'Load Avg (5m)',  val: agent.load_avg_5m != null ? agent.load_avg_5m.toFixed(2) : '—', icon: TrendingUp, color: 'var(--text-2)' },
                    { label: 'Load Avg (15m)', val: agent.load_avg_15m != null ? agent.load_avg_15m.toFixed(2) : '—', icon: TrendingDown, color: 'var(--text-2)' },
                    { label: 'Agent Memory',   val: agent.mem_alloc_mb != null ? `${agent.mem_alloc_mb} MB` : '—', icon: MemoryStick, color: 'var(--accent)' },
                    { label: 'Open FDs',       val: agent.open_fds ?? '—', icon: FolderOpen, color: 'var(--text-2)' },
                    { label: 'Goroutines',     val: agent.goroutines ?? '—', icon: Layers,   color: 'var(--text-2)' },
                    { label: 'Uptime',         val: formatUptime(agent.uptime_seconds), icon: Clock, color: 'var(--green)' },
                    { label: 'Last Check-in',  val: timeAgo(agent.last_seen), icon: Radio,   color: agent.status === 'online' ? 'var(--green)' : 'var(--red)' },
                  ].map(({ label, val, icon: Icon, color }) => (
                    <div key={label} className="g-card p-3">
                      <div className="flex items-center gap-1.5 mb-1">
                        <Icon className="h-3.5 w-3.5" style={{ color }} />
                        <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{label}</span>
                      </div>
                      <p className="text-lg font-bold tabular-nums" style={{ color }}>{String(val)}</p>
                    </div>
                  ))}
                </div>
                {isMobile && (
                  <div className="g-card p-4">
                    <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-2)' }}>Mobile Storage</p>
                    {agent.storage_total_gb != null && agent.storage_free_gb != null ? (
                      <>
                        <div className="flex items-center justify-between text-xs mb-1.5">
                          <span style={{ color: 'var(--text-3)' }}>Used {(agent.storage_total_gb - agent.storage_free_gb).toFixed(1)} GB / {agent.storage_total_gb.toFixed(1)} GB</span>
                          <span style={{ color: 'var(--text-2)' }}>{((1 - agent.storage_free_gb / agent.storage_total_gb) * 100).toFixed(0)}%</span>
                        </div>
                        <div className="h-2 rounded-full overflow-hidden" style={{ background: 'var(--bg-0)' }}>
                          <div className="h-full rounded-full transition-all" style={{ width: `${((1 - agent.storage_free_gb / agent.storage_total_gb) * 100).toFixed(0)}%`, background: 'var(--accent)' }} />
                        </div>
                      </>
                    ) : <p className="text-xs" style={{ color: 'var(--text-3)' }}>No storage data available.</p>}
                  </div>
                )}
                <p className="text-xs" style={{ color: 'var(--text-3)' }}>Historical performance charts require TimescaleDB time-series collection. Real-time agent metrics update on every heartbeat.</p>
              </div>
            )}

            {/* ── Software Inventory ───────────────────────────────── */}
            {activeTab === 'software' && (
              <div className="space-y-4">
                {tabLoading ? <TabLoader /> : (
                  <>
                    {/* Packages */}
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <p className="text-xs font-semibold" style={{ color: 'var(--text-2)' }}>Installed Packages ({packages?.length ?? 0})</p>
                        <button onClick={() => dispatch('collect_packages', 'software')} disabled={dispatching} className="g-btn g-btn-ghost text-xs"><Play className="h-3 w-3" />Refresh</button>
                      </div>
                      <DataTable data={packages} loading={false} search={search} setSearch={setSearch} searchKeys={['package_name', 'version']}
                        columns={[
                          { key: 'package_name', label: 'Package', mono: true },
                          { key: 'version', label: 'Version', width: '140px', mono: true },
                        ]} />
                    </div>

                    {/* Services */}
                    {(services?.length || 0) > 0 && (
                      <div>
                        <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-2)' }}>Running Services ({services!.length})</p>
                        <DataTable data={services} loading={false} search="" setSearch={() => {}} searchKeys={['service_name', 'service_state']}
                          columns={[
                            { key: 'service_name', label: 'Service', mono: true },
                            { key: 'service_state', label: 'State', width: '100px', badge: true },
                          ]} />
                      </div>
                    )}

                    {/* Startup Items */}
                    {(startupItems?.length || 0) > 0 && (
                      <div>
                        <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-2)' }}>Startup Programs ({startupItems!.length})</p>
                        <DataTable data={startupItems} loading={false} search="" setSearch={() => {}} searchKeys={['name', 'path']}
                          rowStyle={r => r.risk && r.risk !== 'none' ? { background: '#f8514908' } : {}}
                          columns={[
                            { key: 'name', label: 'Name', width: '160px', mono: true },
                            { key: 'type', label: 'Type', width: '80px' },
                            { key: 'state', label: 'State', width: '80px' },
                            { key: 'path', label: 'Path', mono: true },
                            { key: 'risk', label: 'Risk', width: '70px', fmt: (v) => v && v !== 'none' ? <span className="text-[10px] font-bold capitalize" style={{ color: v === 'critical' ? 'var(--red)' : 'var(--orange)' }}>{v}</span> : <span style={{ color: 'var(--text-3)' }}>—</span> },
                          ]} />
                      </div>
                    )}

                    {/* Drivers */}
                    {(drivers?.length || 0) > 0 && (
                      <div>
                        <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-2)' }}>Drivers ({drivers!.length})</p>
                        <DataTable data={drivers} loading={false} search="" setSearch={() => {}} searchKeys={['name', 'description']}
                          columns={[
                            { key: 'name', label: 'Module', width: '130px', mono: true },
                            { key: 'description', label: 'Description', width: '200px' },
                            { key: 'version', label: 'Version', width: '80px', mono: true },
                            { key: 'signed', label: 'Signed', width: '60px', fmt: (v) => <span style={{ color: v ? 'var(--green)' : 'var(--red)' }}>{v ? '✓' : '✗'}</span> },
                            { key: 'path', label: 'Path', mono: true },
                          ]} />
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {/* ── Registry ─────────────────────────────────────────── */}
            {activeTab === 'registry' && (
              <div className="space-y-3">
                {!isWindows ? (
                  <EmptyState msg="Registry monitoring is only available on Windows endpoints." />
                ) : (
                  <>
                    <div className="flex items-center justify-between">
                      <p className="text-xs" style={{ color: 'var(--text-3)' }}>Registry changes, autoruns, run keys, and scheduled tasks</p>
                      <button onClick={() => dispatch('collect_registry')} disabled={dispatching} className="g-btn g-btn-primary text-xs">
                        <Play className="h-3 w-3" /> Collect Registry
                      </button>
                    </div>
                    <EmptyState msg="No registry data collected. Click 'Collect Registry' to export hives." />
                  </>
                )}
              </div>
            )}

            {/* ── Security Status ──────────────────────────────────── */}
            {activeTab === 'security' && (
              <div className="space-y-4">
                {tabLoading ? <TabLoader /> : (
                  <>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <StatusPill ok={true} label="EDR Agent Running" />
                      <StatusPill ok={secStatus?.tamper_protection ?? null} label="Tamper Protection" unknown={!secStatus?.tamper_protection} />
                      <StatusPill ok={secStatus?.is_isolated === false} label="Network Access" />
                      <StatusPill ok={secStatus?.edr_enabled !== false} label="EDR Enabled" />
                      <StatusPill ok={secStatus?.firewall_enabled ?? null} label="Firewall Enabled" unknown={secStatus?.firewall_enabled == null} />
                      <StatusPill ok={secStatus?.disk_encrypted ?? null} label="Disk Encryption" unknown={secStatus?.disk_encrypted == null} />
                      <StatusPill ok={secStatus?.secure_boot ?? null} label="Secure Boot" unknown={secStatus?.secure_boot == null} />
                      <StatusPill ok={secStatus?.tpm_present ?? null} label="TPM Present" unknown={secStatus?.tpm_present == null} />
                      <StatusPill ok={secStatus?.antivirus_running ?? null} label="Antivirus Running" unknown={secStatus?.antivirus_running == null} />
                      {isMobile && <>
                        <StatusPill ok={secStatus?.is_rooted === false} label="Not Rooted" unknown={secStatus?.is_rooted == null} />
                        <StatusPill ok={secStatus?.developer_mode === false} label="Dev Mode Off" unknown={secStatus?.developer_mode == null} />
                        <StatusPill ok={secStatus?.vpn_active ?? null} label="VPN Active" unknown={secStatus?.vpn_active == null} />
                      </>}
                    </div>

                    <div className="grid grid-cols-2 gap-3">
                      {[
                        { label: 'Defender Status',  val: secStatus?.defender_status || 'Unknown' },
                        { label: 'Patch Status',      val: secStatus?.patch_status || 'Unknown' },
                        { label: 'Sensor Health',     val: secStatus?.sensor_health || 'Unknown' },
                        { label: 'Security Patch',    val: secStatus?.security_patch || '—' },
                      ].map(({ label, val }) => (
                        <div key={label} className="g-card p-3">
                          <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{label}</p>
                          <p className="text-sm font-semibold mt-1 capitalize" style={{ color: val === 'healthy' || val === 'active' ? 'var(--green)' : val === 'Unknown' ? 'var(--text-3)' : 'var(--text-1)' }}>{val}</p>
                        </div>
                      ))}
                    </div>

                    <div className="rounded-lg p-3 text-xs" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-3)' }}>
                      ℹ Fields showing &quot;Unknown&quot; require an agent update to report hardware security posture (TPM, Secure Boot, disk encryption, firewall status).
                    </div>
                  </>
                )}
              </div>
            )}

            {/* ── Compliance ───────────────────────────────────────── */}
            {activeTab === 'compliance' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>CIS Benchmark Compliance</p>
                    {cisScore && <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>Score: <strong style={{ color: 'var(--accent)' }}>{cisScore.score ?? '—'}</strong></p>}
                  </div>
                  <button onClick={async () => { setCisFindings(null); setCisScore(null); await agentsAPI.triggerCISScan(agentId); showToast('CIS scan triggered'); loadTabData('compliance'); }} disabled={dispatching} className="g-btn g-btn-primary text-xs">
                    <Play className="h-3 w-3" /> Run CIS Scan
                  </button>
                </div>
                {tabLoading ? <TabLoader /> : (cisFindings?.length || 0) === 0 ? (
                  <EmptyState msg="No CIS findings. Run a CIS scan to assess benchmark compliance." />
                ) : (
                  <div className="space-y-2">
                    {(['fail', 'warn', 'pass'] as const).map(status => {
                      const items = cisFindings!.filter((f: any) => f.status === status);
                      if (!items.length) return null;
                      const color = status === 'fail' ? 'var(--red)' : status === 'warn' ? 'var(--yellow)' : 'var(--green)';
                      return (
                        <div key={status}>
                          <p className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color }}>{status} ({items.length})</p>
                          {items.map((f: any, i: number) => (
                            <div key={i} className="rounded-lg p-3 mb-1.5 flex gap-3"
                              style={{ background: status === 'fail' ? '#f8514908' : 'var(--glass-bg)', border: `1px solid ${status === 'fail' ? '#f8514930' : 'var(--border)'}` }}>
                              <div className="h-4 w-4 mt-0.5 shrink-0 flex items-center justify-center rounded-full" style={{ background: `${color}20` }}>
                                {status === 'fail' ? <X className="h-2.5 w-2.5" style={{ color }} /> : status === 'warn' ? <AlertCircle className="h-2.5 w-2.5" style={{ color }} /> : <Check className="h-2.5 w-2.5" style={{ color }} />}
                              </div>
                              <div className="flex-1 min-w-0">
                                <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{f.title || f.control_id}</p>
                                {f.description && <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-2)' }}>{f.description}</p>}
                                {f.remediation && <p className="text-[10px] mt-0.5" style={{ color: 'var(--green)' }}>→ {f.remediation}</p>}
                              </div>
                              <span className="mono text-[10px] shrink-0" style={{ color: 'var(--text-3)' }}>{f.control_id}</span>
                            </div>
                          ))}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* ── Policies ─────────────────────────────────────────── */}
            {activeTab === 'policies' && (
              <div className="space-y-4">
                {tabLoading || policies === undefined ? <TabLoader /> : !policies ? (
                  <EmptyState msg="No policy assigned to this agent." />
                ) : (
                  <>
                    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                      {[
                        { l: 'Tamper Protection',      v: policies.tamper_protection      ? 'Enabled' : 'Disabled',   c: policies.tamper_protection      ? 'var(--green)' : 'var(--text-3)' },
                        { l: 'Network Isolation',      v: policies.network_isolation      ? 'ISOLATED' : 'Off',        c: policies.network_isolation      ? '#f85149'       : 'var(--green)'  },
                        { l: 'FIM',                    v: policies.fim_enabled            ? 'Enabled' : 'Disabled',   c: policies.fim_enabled            ? 'var(--green)' : 'var(--text-3)' },
                        { l: 'YARA Scanning',          v: policies.yara_enabled           ? 'Enabled' : 'Disabled',   c: policies.yara_enabled           ? 'var(--green)' : 'var(--text-3)' },
                        { l: 'Auto-Update Agent',      v: policies.auto_update            ? 'Enabled' : 'Disabled',   c: policies.auto_update            ? 'var(--green)' : 'var(--text-3)' },
                        { l: 'Block Removable Media',  v: policies.block_removable_media  ? 'Blocked' : 'Allowed',    c: policies.block_removable_media  ? '#f85149'       : 'var(--text-3)' },
                        { l: 'Block Script Execution', v: policies.script_execution_blocked ? 'Blocked' : 'Allowed',  c: policies.script_execution_blocked ? '#f85149'    : 'var(--text-3)' },
                        { l: 'Max CPU %',              v: `${policies.max_cpu_percent}%`,  c: 'var(--text-2)' },
                        { l: 'Collection Interval',    v: `${policies.collection_interval_seconds}s`, c: 'var(--text-2)' },
                      ].map(({ l, v, c }) => (
                        <div key={l} className="g-card p-3">
                          <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{l}</p>
                          <p className="text-sm font-semibold mt-1" style={{ color: c }}>{v}</p>
                        </div>
                      ))}
                    </div>
                    {policies.fim_paths?.length > 0 && (
                      <div className="g-card p-4">
                        <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-2)' }}>FIM Monitored Paths</p>
                        <div className="flex flex-wrap gap-2">
                          {policies.fim_paths.map((path: string) => (
                            <span key={path} className="mono text-[10px] px-2 py-1 rounded"
                              style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>{path}</span>
                          ))}
                        </div>
                      </div>
                    )}
                    <div className="flex gap-2">
                      <button className="g-btn g-btn-ghost text-xs"><Settings className="h-3 w-3" />Edit Policy</button>
                      <button className="g-btn g-btn-ghost text-xs"><Copy className="h-3 w-3" />Clone Policy</button>
                    </div>
                  </>
                )}
              </div>
            )}

            {/* ── Live Response ─────────────────────────────────────── */}
            {activeTab === 'live_response' && (
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <Terminal className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                  <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Live Response Console</p>
                  <span className="text-[10px] px-2 py-0.5 rounded" style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                    {agent.status === 'online' ? 'Connected' : 'Agent Offline'}
                  </span>
                </div>

                {/* Quick commands */}
                <div className="flex gap-2 flex-wrap">
                  {['hostname', 'ps aux | head -20', 'netstat -an | head -20', 'whoami', 'uname -a', 'df -h', 'free -h', 'uptime'].map(cmd => (
                    <button key={cmd} onClick={() => { setLrInput(cmd); }}
                      className="mono text-[10px] px-2 py-1 rounded"
                      style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                      {cmd}
                    </button>
                  ))}
                </div>

                {/* Terminal output */}
                <div className="rounded-xl overflow-hidden" style={{ background: '#0d1117', border: '1px solid #30363d' }}>
                  <div className="flex items-center gap-2 px-4 py-2 border-b" style={{ borderColor: '#30363d' }}>
                    <span className="h-3 w-3 rounded-full" style={{ background: '#f85149' }} />
                    <span className="h-3 w-3 rounded-full" style={{ background: '#fb923c' }} />
                    <span className="h-3 w-3 rounded-full" style={{ background: '#22c55e' }} />
                    <span className="mono text-[10px] ml-2" style={{ color: '#8b949e' }}>{agent.hostname} — live response</span>
                  </div>
                  <div className="p-3 min-h-[200px] max-h-[350px] overflow-y-auto mono text-[11px] space-y-2" style={{ color: '#e6edf3' }}>
                    {lrHistory.length === 0 && (
                      <p style={{ color: '#8b949e' }}>Type a command or select a quick command above. Commands are dispatched as agent tasks and results appear here (~5s).</p>
                    )}
                    {lrHistory.map((entry, i) => (
                      <div key={i}>
                        <div className="flex items-center gap-2">
                          <span style={{ color: '#22c55e' }}>$</span>
                          <span style={{ color: '#58a6ff' }}>{entry.cmd}</span>
                          <span className="ml-auto text-[9px]" style={{ color: '#8b949e' }}>{entry.ts}</span>
                        </div>
                        <pre className="mt-1 text-[10px] whitespace-pre-wrap pl-3" style={{ color: '#e6edf3' }}>{entry.output}</pre>
                      </div>
                    ))}
                    {lrRunning && <p className="animate-pulse" style={{ color: '#8b949e' }}>Running…</p>}
                    <div ref={lrBottomRef} />
                  </div>
                  <div className="flex items-center gap-2 px-3 py-2 border-t" style={{ borderColor: '#30363d' }}>
                    <span className="mono text-[11px]" style={{ color: '#22c55e' }}>$</span>
                    <input
                      value={lrInput} onChange={e => setLrInput(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && runLRCommand()}
                      disabled={lrRunning || agent.status !== 'online'}
                      placeholder={agent.status !== 'online' ? 'Agent offline' : 'Enter command…'}
                      className="flex-1 bg-transparent mono text-[11px] outline-none"
                      style={{ color: '#e6edf3' }}
                    />
                    <button onClick={runLRCommand} disabled={lrRunning || !lrInput.trim() || agent.status !== 'online'}
                      className="g-btn g-btn-primary text-xs" style={{ padding: '4px 10px' }}>
                      {lrRunning ? '…' : '↵'}
                    </button>
                  </div>
                </div>
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                  Commands execute via the XCloak agent task queue. Response time depends on agent check-in interval (~15s). Destructive commands require confirmation on the endpoint.
                </p>
              </div>
            )}

            {/* ── Remote Actions ───────────────────────────────────── */}
            {activeTab === 'remote_actions' && (
              <div className="space-y-5">
                <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                  All actions are dispatched as agent tasks. Destructive actions require confirmation. View execution status in Task History.
                </p>
                {REMOTE_ACTION_GROUPS.map(group => (
                  <div key={group.label}>
                    <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>{group.label}</p>
                    <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-4 gap-2">
                      {group.actions.map(({ task, label, icon: Icon, danger, desc }) => (
                        <button key={`${group.label}-${task}-${label}`}
                          onClick={async () => {
                            if (danger && !confirm(`${label} on ${agent.hostname}?`)) return;
                            dispatch(task);
                          }}
                          disabled={dispatching}
                          className="flex flex-col gap-1.5 rounded-xl p-3 text-left transition-all hover:opacity-90"
                          style={{ background: `${group.color}10`, border: `1px solid ${group.color}25`, color: group.color }}>
                          <div className="flex items-center justify-between">
                            <Icon className="h-4 w-4" />
                            {danger && <AlertTriangle className="h-3 w-3 opacity-60" />}
                          </div>
                          <p className="text-[11px] font-semibold">{label}</p>
                          <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>{desc}</p>
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* ── Task History ─────────────────────────────────────── */}
            {activeTab === 'tasks' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>{taskHistory?.length || 0} tasks dispatched</p>
                  <button onClick={() => { setTaskHistory(null); loadTabData('tasks'); }} className="g-btn g-btn-ghost text-xs">
                    <RefreshCw className="h-3 w-3" /> Refresh
                  </button>
                </div>
                {tabLoading ? <TabLoader /> : (taskHistory?.length || 0) === 0 ? (
                  <EmptyState msg="No tasks dispatched to this agent yet." />
                ) : (
                  <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                    <div className="g-thead grid gap-3 px-3" style={{ gridTemplateColumns: '150px 80px 1fr 90px 60px' }}>
                      <span>Task Type</span><span>Status</span><span>Result</span><span>Completed</span><span>ID</span>
                    </div>
                    {taskHistory!.map((t: any) => {
                      const ok = t.status === 'completed' && !t.result?.toLowerCase().includes('fail') && !t.result?.toLowerCase().includes('error');
                      const color = t.status === 'completed' ? (ok ? 'var(--green)' : 'var(--orange)') : t.status === 'running' ? 'var(--accent)' : 'var(--text-3)';
                      return (
                        <div key={t.id} className="g-tr grid gap-3 items-start px-3 py-2.5" style={{ gridTemplateColumns: '150px 80px 1fr 90px 60px' }}>
                          <span className="mono text-[11px]" style={{ color: 'var(--accent)' }}>{t.task_type}</span>
                          <span className="text-[11px] font-medium capitalize" style={{ color }}>{t.status}</span>
                          <span className="text-[11px] truncate" style={{ color: 'var(--text-2)' }} title={t.result || '—'}>{t.result || '—'}</span>
                          <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{t.completed_at ? timeAgo(t.completed_at) : '—'}</span>
                          <span className="mono text-[10px]" style={{ color: 'var(--text-3)' }}>#{t.id}</span>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* ── Audit History ────────────────────────────────────── */}
            {activeTab === 'audit_history' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                    All administrative actions on this endpoint — task dispatches, isolations, and lifecycle events.
                  </p>
                  <button onClick={() => { setAuditHistory(null); loadTabData('audit_history'); }} className="g-btn g-btn-ghost text-xs">
                    <RefreshCw className="h-3 w-3" /> Refresh
                  </button>
                </div>
                {tabLoading ? <TabLoader /> : (auditHistory?.length || 0) === 0 ? (
                  <EmptyState msg="No audit events recorded for this agent yet." />
                ) : (
                  <div className="relative pl-5 space-y-2">
                    <div className="absolute left-2 top-0 bottom-0 w-px" style={{ background: 'var(--border)' }} />
                    {auditHistory!.map((ev, i) => {
                      const isLcEvent = ev.action === 'agent_installed';
                      const statusColor = ev.status === 'completed' ? 'var(--green)' : ev.status === 'pending' ? 'var(--accent)' : ev.status === 'running' ? 'var(--yellow)' : 'var(--text-3)';
                      const actionLabel = ev.action.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                      return (
                        <div key={i} className="relative flex items-start gap-3">
                          <div className="absolute -left-3 top-1 h-5 w-5 rounded-full flex items-center justify-center shrink-0"
                            style={{ background: isLcEvent ? 'var(--accent-glow)' : 'var(--bg-0)', border: `1px solid ${isLcEvent ? 'var(--accent-border)' : 'var(--border)'}` }}>
                            {isLcEvent
                              ? <Check className="h-3 w-3" style={{ color: 'var(--accent)' }} />
                              : <Zap className="h-3 w-3" style={{ color: statusColor }} />
                            }
                          </div>
                          <div className="flex-1 rounded-lg p-3 min-w-0" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                            <div className="flex items-center gap-2 flex-wrap">
                              <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{actionLabel}</p>
                              <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded capitalize" style={{ background: `${statusColor}18`, color: statusColor, border: `1px solid ${statusColor}35` }}>
                                {ev.status}
                              </span>
                              {ev.actor && (
                                <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>by {ev.actor}</span>
                              )}
                            </div>
                            {ev.detail && ev.detail !== '' && ev.detail !== '[]' && (
                              <p className="mono text-[10px] mt-1 truncate" style={{ color: 'var(--text-3)' }} title={ev.detail}>{ev.detail}</p>
                            )}
                            <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                              {formatDate(ev.timestamp)}
                              {ev.completed_at && ` → ${formatDate(ev.completed_at)}`}
                            </p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

          </div>{/* end tab content */}
        </div>{/* end tab card */}
      </div>{/* end space-y-4 */}
    </RootLayout>
  );
}
