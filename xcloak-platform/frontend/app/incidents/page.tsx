'use client';

import { useEffect, useState, useCallback, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { incidentsAPI, aiAPI } from '@/lib/api';
import { Incident } from '@/types';
import { sevClass, formatDate, timeAgo } from '@/lib/utils';
import Link from 'next/link';
import {
  AlertTriangle, X, Clock, Bot, Loader2, MessageSquare, Send,
  ChevronRight, Bell, TrendingUp, Search, CheckSquare, Square,
  CheckCheck, Filter, ShieldAlert, Flame, Activity, Shield,
  Network, Database, User, Users, FileText, Lock, Globe2,
  Server, ArrowRight, Play, Download, Copy, Check, CheckCircle2,
  XCircle, Info, BarChart2, Layers, Zap, RefreshCw, Plus,
  MoreHorizontal, AlertCircle, Target, Cpu, Eye, ChevronDown,
  ChevronLeft, Crosshair, GitBranch, Package, Workflow,
  Terminal, FileSearch, HardDrive, Wifi, BookOpen,
} from 'lucide-react';

// ── Types ─────────────────────────────────────────────────────────────────────

interface IncidentTask { id: number; text: string; completed: boolean; created_at: string; }
interface IncidentEvent { id: number; event_type: string; details: string; created_at: string; }
interface LinkedAlert { id: number; agent_id: number; severity: string; rule_name: string; created_at: string; }

interface DeepDive {
  timeline: Array<{ timestamp: string; type: string; title: string; detail: string; severity?: string }>;
  affected_asset: { agent_id: number; hostname: string; ip_address: string; os: string; status: string; risk_level: string };
  indicators: Array<{ type: string; value: string; context: string }>;
  ai_summary: string;
  recommendations: string[];
  mitre_coverage: string[];
}

interface RootCause {
  initial_access: string; root_cause: string; compromised_user: string;
  entry_point: string; weak_control: string; attack_stage: string;
  estimated_dwell_time: string; prevention_suggestions: string[];
}

interface SimilarIncident {
  id: number; title: string; severity: string; status: string;
  hostname: string; created_at: string; match_reason: string;
}

interface Analytics {
  by_severity: Array<{severity: string; count: number}>;
  by_status: Array<{status: string; count: number}>;
  mttr_hours: string; mttd_hours: string; mttc_hours: string;
  trend: Array<{day: string; count: number}>;
  total: number; total_open: number;
}

// ── SLA helpers ───────────────────────────────────────────────────────────────

const INCIDENT_SLA: Record<string, number> = { critical: 4, high: 8, medium: 48, low: 120 };

function slaInfo(sev: string, created_at: string, status: string): { breached: boolean; label: string; pct: number } | null {
  if (status === 'resolved' || status === 'closed') return null;
  const slaH = INCIDENT_SLA[sev]; if (!slaH) return null;
  const ageH = (Date.now() - new Date(created_at).getTime()) / 3_600_000;
  const pct = Math.min(100, (ageH / slaH) * 100);
  if (ageH > slaH) {
    const h = Math.floor(ageH - slaH), m = Math.floor(((ageH - slaH) - h) * 60);
    return { breached: true, label: `+${h}h${m ? ` ${m}m` : ''}`, pct };
  }
  const rem = slaH - ageH, h = Math.floor(rem), m = Math.floor((rem - h) * 60);
  return { breached: false, label: `${h}h${m ? ` ${m}m` : ''} left`, pct };
}

// ── Constants ─────────────────────────────────────────────────────────────────

const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
const STATUSES   = ['open', 'investigating', 'resolved', 'closed'] as const;

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--blue)',
};

const STATUS_COLOR: Record<string, string> = {
  open: 'var(--red)', investigating: 'var(--orange)', resolved: 'var(--green)', closed: 'var(--text-3)',
};

const MITRE_COLORS = [
  'var(--red)', 'var(--orange)', 'var(--yellow)', 'var(--green)', 'var(--accent)', 'var(--blue)',
];

// ── Sub-components ────────────────────────────────────────────────────────────

function SevDot({ sev }: { sev: string }) {
  return <span className="h-2 w-2 rounded-full shrink-0 flex-none" style={{ background: SEV_COLOR[sev] ?? 'var(--border)' }} />;
}

function StatusChip({ status }: { status: string }) {
  const c = STATUS_COLOR[status] ?? 'var(--text-3)';
  return (
    <span className="text-[10px] px-2 py-0.5 rounded capitalize font-medium"
      style={{ background:`${c}18`, color:c, border:`1px solid ${c}44` }}>
      {status}
    </span>
  );
}

function SectionHeader({ icon: Icon, title, action }: { icon: any; title: string; action?: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 px-4 py-2.5 shrink-0" style={{ borderBottom:'1px solid var(--border)', background:'var(--glass-bg)' }}>
      <Icon className="h-3.5 w-3.5 shrink-0" style={{ color:'var(--accent)' }} />
      <span className="text-[10px] font-bold uppercase tracking-wider flex-1" style={{ color:'var(--text-3)' }}>{title}</span>
      {action}
    </div>
  );
}

function Spinner() {
  return <Loader2 className="h-4 w-4 animate-spin mx-auto" style={{ color:'var(--text-3)' }} />;
}

// ── Attack Chain ──────────────────────────────────────────────────────────────

function AttackChainView({ mitre, timeline }: { mitre: string[]; timeline: DeepDive['timeline'] }) {
  const stages = mitre.length > 0 ? mitre : [
    'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
    'Defense Evasion', 'Credential Access', 'Lateral Movement', 'Exfiltration',
  ];
  const activeCount = mitre.length > 0 ? mitre.length : 3;

  return (
    <div className="p-3 space-y-1.5">
      {stages.slice(0, 8).map((stage, i) => {
        const active = i < activeCount;
        const color = active ? MITRE_COLORS[i % MITRE_COLORS.length] : 'var(--border)';
        return (
          <div key={stage} className="flex items-center gap-2">
            <div className="flex flex-col items-center">
              <div className="h-5 w-5 rounded-full flex items-center justify-center text-[9px] font-bold"
                style={{ background:`${color}22`, border:`1px solid ${color}55`, color }}>
                {i + 1}
              </div>
              {i < stages.slice(0, 8).length - 1 && (
                <div className="w-px h-2" style={{ background: active ? color : 'var(--border)' }} />
              )}
            </div>
            <span className="text-[11px] font-medium truncate" style={{ color: active ? 'var(--text-1)' : 'var(--text-3)' }}>
              {stage}
            </span>
            {active && <span className="ml-auto shrink-0 h-1.5 w-1.5 rounded-full animate-pulse" style={{ background: color }} />}
          </div>
        );
      })}
    </div>
  );
}

// ── Evidence Table ────────────────────────────────────────────────────────────

function EvidenceView({ indicators }: { indicators: DeepDive['indicators'] }) {
  const ICONS: Record<string, any> = {
    ip: Globe2, domain: Globe2, process: Terminal, file: FileText, hash: Database,
  };
  if (!indicators.length) return <p className="p-4 text-xs" style={{ color:'var(--text-3)' }}>No indicators collected.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr style={{ borderBottom:'1px solid var(--border)' }}>
            {['Type','Value','Context'].map(h=>(
              <th key={h} className="text-left px-3 py-2 text-[10px] font-semibold uppercase tracking-wider" style={{ color:'var(--text-3)' }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {indicators.map((ind, i) => {
            const Icon = ICONS[ind.type] ?? Shield;
            return (
              <tr key={i} style={{ borderBottom:'1px solid var(--border)' }}>
                <td className="px-3 py-2">
                  <div className="flex items-center gap-1.5">
                    <Icon className="h-3 w-3" style={{ color:'var(--accent)' }} />
                    <span className="capitalize" style={{ color:'var(--text-2)' }}>{ind.type}</span>
                  </div>
                </td>
                <td className="px-3 py-2 font-mono text-[10px] max-w-[140px] truncate" style={{ color:'var(--text-1)' }}>{ind.value}</td>
                <td className="px-3 py-2" style={{ color:'var(--text-3)' }}>{ind.context}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── MITRE Grid ────────────────────────────────────────────────────────────────

function MITREView({ techniques }: { techniques: string[] }) {
  if (!techniques.length) return <p className="p-4 text-xs" style={{ color:'var(--text-3)' }}>No MITRE techniques mapped.</p>;
  return (
    <div className="p-3 flex flex-wrap gap-2">
      {techniques.map((t, i) => (
        <span key={t} className="text-[10px] px-2.5 py-1 rounded-lg font-mono font-medium"
          style={{ background:`${MITRE_COLORS[i%MITRE_COLORS.length]}18`, color:MITRE_COLORS[i%MITRE_COLORS.length], border:`1px solid ${MITRE_COLORS[i%MITRE_COLORS.length]}44` }}>
          {t}
        </span>
      ))}
    </div>
  );
}

// ── Blast Radius ──────────────────────────────────────────────────────────────

function BlastRadiusView({ asset }: { asset?: DeepDive['affected_asset'] }) {
  const nodes = [
    { label: asset?.hostname ?? 'Affected Host', sub: asset?.ip_address ?? '', icon: Server, color: 'var(--red)' },
    { label: 'Connected Users',   sub: 'AD / local users on host',      icon: Users,   color: 'var(--orange)' },
    { label: 'Connected Servers', sub: 'SMB, RDP, remote shares',       icon: Network, color: 'var(--yellow)' },
    { label: 'Cloud Resources',   sub: 'IAM roles, S3, storage',        icon: Database, color: 'var(--accent)' },
    { label: 'Potential Impact',  sub: 'Estimated blast radius',         icon: Target,  color: 'var(--text-2)' },
  ];
  return (
    <div className="p-3 space-y-2">
      {nodes.map((n, i) => (
        <div key={n.label} className="flex flex-col items-start">
          <div className="flex items-center gap-2 w-full rounded-lg px-3 py-2"
            style={{ background:'var(--glass-bg)', border:`1px solid ${n.color}44`, paddingLeft: `${12 + i*12}px` }}>
            <n.icon className="h-3.5 w-3.5 shrink-0" style={{ color:n.color }} />
            <div className="min-w-0">
              <p className="text-xs font-medium" style={{ color:'var(--text-1)' }}>{n.label}</p>
              <p className="text-[10px]" style={{ color:'var(--text-3)' }}>{n.sub}</p>
            </div>
          </div>
          {i < nodes.length - 1 && (
            <div className="h-2 w-px ml-4" style={{ background:'var(--border)' }} />
          )}
        </div>
      ))}
    </div>
  );
}

// ── Response Actions Panel ────────────────────────────────────────────────────

const RESPONSE_ACTIONS = [
  { key: 'isolate_host',     label: 'Isolate Host',      icon: Lock,      color: 'var(--red)',    desc: 'Cut network access' },
  { key: 'collect_memory',   label: 'Collect Memory',    icon: Cpu,       color: 'var(--orange)', desc: 'Dump process memory' },
  { key: 'collect_disk',     label: 'Collect Disk',      icon: HardDrive, color: 'var(--orange)', desc: 'Forensic disk image' },
  { key: 'kill_process',     label: 'Kill Process',      icon: XCircle,   color: 'var(--red)',    desc: 'Terminate by PID' },
  { key: 'quarantine_file',  label: 'Quarantine File',   icon: FileText,  color: 'var(--yellow)', desc: 'Isolate malicious file' },
  { key: 'block_ip',         label: 'Block IP',          icon: Globe2,    color: 'var(--red)',    desc: 'Firewall rule' },
  { key: 'block_domain',     label: 'Block Domain',      icon: Globe2,    color: 'var(--red)',    desc: 'DNS sinkhole' },
  { key: 'disable_user',     label: 'Disable User',      icon: User,      color: 'var(--yellow)', desc: 'Suspend AD/local user' },
  { key: 'reset_password',   label: 'Reset Password',    icon: Lock,      color: 'var(--yellow)', desc: 'Force credential reset' },
  { key: 'run_playbook',     label: 'Run Playbook',      icon: Play,      color: 'var(--accent)', desc: 'Execute SOAR playbook' },
];

function ResponseActions({ incidentId, onAction }: { incidentId: number; onAction: (msg: string) => void }) {
  const [running, setRunning]   = useState<string | null>(null);
  const [param, setParam]       = useState('');
  const [activeKey, setActiveKey] = useState<string | null>(null);

  const PARAM_LABELS: Record<string, string> = {
    kill_process: 'PID', quarantine_file: 'File Path', block_ip: 'IP Address',
    block_domain: 'Domain', disable_user: 'Username', reset_password: 'Username', run_playbook: 'Playbook ID',
  };
  const needsParam = activeKey ? PARAM_LABELS[activeKey] : null;

  const dispatch = async (key: string, p = '') => {
    setRunning(key);
    try {
      const params: Record<string, string> = {};
      if (key === 'kill_process')   params.pid = p;
      if (key === 'quarantine_file') params.path = p;
      if (key === 'block_ip')       params.ip = p;
      if (key === 'block_domain')   params.domain = p;
      if (key === 'disable_user')   params.username = p;
      if (key === 'reset_password') params.username = p;
      if (key === 'run_playbook')   params.playbook_id = p;
      const r = await incidentsAPI.responseAction(incidentId, key, params);
      onAction((r.data as any)?.result ?? `${key} dispatched`);
      setActiveKey(null); setParam('');
    } catch { onAction('Action failed — check permissions'); }
    finally { setRunning(null); }
  };

  return (
    <div className="p-3 space-y-2">
      {activeKey && needsParam && (
        <div className="flex items-center gap-2 rounded-lg px-3 py-2.5 mb-2"
          style={{ background:'var(--glass-bg)', border:'1px solid var(--accent-border)' }}>
          <input value={param} onChange={e=>setParam(e.target.value)}
            placeholder={needsParam + '…'} className="g-input flex-1 text-xs"
            onKeyDown={e=>e.key==='Enter' && param && dispatch(activeKey, param)} />
          <button onClick={()=>param && dispatch(activeKey, param)} disabled={!param || running===activeKey}
            className="g-btn g-btn-primary text-xs px-3">
            {running===activeKey ? <Loader2 className="h-3 w-3 animate-spin" /> : 'Run'}
          </button>
          <button onClick={()=>{setActiveKey(null);setParam('');}} className="g-btn g-btn-ghost text-xs px-2"><X className="h-3 w-3" /></button>
        </div>
      )}
      <div className="grid grid-cols-2 gap-1.5">
        {RESPONSE_ACTIONS.map(a => (
          <button key={a.key}
            onClick={() => {
              if (PARAM_LABELS[a.key]) { setActiveKey(a.key); setParam(''); }
              else dispatch(a.key);
            }}
            disabled={running !== null}
            className="flex items-center gap-2 rounded-lg px-3 py-2 text-left transition-colors hover:bg-[var(--glass-hover)]"
            style={{ background:'var(--glass-bg)', border:`1px solid ${a.color}33` }}>
            {running === a.key
              ? <Loader2 className="h-3.5 w-3.5 animate-spin shrink-0" style={{ color:a.color }} />
              : <a.icon className="h-3.5 w-3.5 shrink-0" style={{ color:a.color }} />}
            <div className="min-w-0">
              <p className="text-[11px] font-medium truncate" style={{ color:'var(--text-1)' }}>{a.label}</p>
              <p className="text-[9px]" style={{ color:'var(--text-3)' }}>{a.desc}</p>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

// ── Task Checklist ────────────────────────────────────────────────────────────

const DEFAULT_TASKS = [
  'Collect memory dump', 'Isolate affected host', 'Reset compromised credentials',
  'Check domain controller for lateral movement', 'Notify security team lead',
  'Patch exploited vulnerability', 'Preserve disk artifacts', 'Update firewall rules',
];

function TaskChecklist({ incidentId }: { incidentId: number }) {
  const [tasks, setTasks]   = useState<IncidentTask[]>([]);
  const [loading, setLoading] = useState(true);
  const [newTask, setNewTask] = useState('');
  const [adding, setAdding]   = useState(false);
  const [toggling, setToggling] = useState<number | null>(null);

  useEffect(() => {
    setLoading(true);
    incidentsAPI.getTasks(incidentId).then(r => { setTasks(r.data ?? []); setLoading(false); });
  }, [incidentId]);

  const addTask = async (text: string) => {
    if (!text.trim()) return;
    setAdding(true);
    try {
      const r = await incidentsAPI.createTask(incidentId, text.trim());
      setTasks(p => [...p, r.data as IncidentTask]);
      setNewTask('');
    } catch {}
    finally { setAdding(false); }
  };

  const toggle = async (tid: number) => {
    setToggling(tid);
    try {
      const r = await incidentsAPI.toggleTask(incidentId, tid);
      const updated = r.data as IncidentTask;
      setTasks(p => p.map(t => t.id === tid ? { ...t, completed: updated.completed } : t));
    } catch {}
    finally { setToggling(null); }
  };

  if (loading) return <div className="p-4"><Spinner /></div>;

  return (
    <div className="p-3 space-y-2">
      {tasks.length === 0 && (
        <div className="space-y-1.5">
          <p className="text-[10px]" style={{ color:'var(--text-3)' }}>Suggested tasks — click to add:</p>
          {DEFAULT_TASKS.slice(0, 4).map(t => (
            <button key={t} onClick={() => addTask(t)}
              className="w-full text-left flex items-center gap-2 rounded-lg px-3 py-2 text-xs hover:bg-[var(--glass-hover)] transition-colors"
              style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
              <Plus className="h-3 w-3 shrink-0" style={{ color:'var(--accent)' }} />
              <span style={{ color:'var(--text-2)' }}>{t}</span>
            </button>
          ))}
        </div>
      )}
      {tasks.map(t => (
        <div key={t.id} className="flex items-center gap-2 rounded-lg px-3 py-2"
          style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
          <button onClick={() => toggle(t.id)} disabled={toggling === t.id} className="shrink-0">
            {toggling === t.id
              ? <Loader2 className="h-3.5 w-3.5 animate-spin" style={{ color:'var(--text-3)' }} />
              : t.completed
                ? <CheckSquare className="h-3.5 w-3.5" style={{ color:'var(--green)' }} />
                : <Square className="h-3.5 w-3.5" style={{ color:'var(--text-3)' }} />}
          </button>
          <span className="flex-1 text-xs" style={{ color: t.completed ? 'var(--text-3)' : 'var(--text-1)', textDecoration: t.completed ? 'line-through' : 'none' }}>
            {t.text}
          </span>
          <span className="text-[9px] shrink-0" style={{ color:'var(--text-3)' }}>{timeAgo(t.created_at)}</span>
        </div>
      ))}
      <div className="flex items-center gap-2 pt-1">
        <input value={newTask} onChange={e=>setNewTask(e.target.value)} onKeyDown={e=>e.key==='Enter'&&addTask(newTask)}
          placeholder="Add task…" className="g-input flex-1 text-xs" />
        <button onClick={()=>addTask(newTask)} disabled={!newTask.trim()||adding} className="g-btn g-btn-primary text-xs px-3">
          {adding ? <Loader2 className="h-3 w-3 animate-spin" /> : <Plus className="h-3 w-3" />}
        </button>
      </div>
    </div>
  );
}

// ── Incident Detail (full-page) ───────────────────────────────────────────────

function IncidentDetail({
  incident, onClose, onStatusChange, onSeverityChange,
}: {
  incident: Incident;
  onClose: () => void;
  onStatusChange: (id: number, s: string) => void;
  onSeverityChange: (id: number, s: string) => void;
}) {
  const [events,   setEvents]   = useState<IncidentEvent[]>([]);
  const [alerts,   setAlerts]   = useState<LinkedAlert[]>([]);
  const [deepDive, setDeepDive] = useState<DeepDive | null>(null);
  const [rootCause,setRootCause]= useState<RootCause | null>(null);
  const [similar,  setSimilar]  = useState<SimilarIncident[]>([]);
  const [aiSum,    setAiSum]    = useState<any>(null);
  const [analytics,setAnalytics]= useState<Analytics | null>(null);

  const [loadingEvents, setLoadingEvents] = useState(true);
  const [loadingDD,     setLoadingDD]     = useState(true);
  const [aiLoading,     setAiLoading]     = useState(false);
  const [rcLoading,     setRcLoading]     = useState(false);
  const [note,          setNote]          = useState('');
  const [addingNote,    setAddingNote]    = useState(false);
  const [updatingStatus,setUpdatingStatus]= useState(false);
  const [toast,         setToast]         = useState<string|null>(null);
  const [escalating,    setEscalating]    = useState(false);
  const [copied,        setCopied]        = useState(false);

  const notify = (m: string) => { setToast(m); setTimeout(()=>setToast(null), 3000); };

  useEffect(() => {
    setEvents([]); setAlerts([]); setDeepDive(null); setAiSum(null); setRootCause(null); setSimilar([]);
    setLoadingEvents(true); setLoadingDD(true);

    Promise.allSettled([
      incidentsAPI.getEvents(incident.id),
      incidentsAPI.getAlerts(incident.id),
    ]).then(([evR, alR]) => {
      if (evR.status==='fulfilled') setEvents(evR.value.data ?? []);
      if (alR.status==='fulfilled') setAlerts(alR.value.data ?? []);
      setLoadingEvents(false);
    });

    incidentsAPI.getDeepDive(incident.id).then(r => {
      if (r.data) setDeepDive(r.data as DeepDive);
      setLoadingDD(false);
    });

    incidentsAPI.getSimilar(incident.id).then(r => setSimilar(r.data ?? []));
    incidentsAPI.getAnalytics().then(r => r.data && setAnalytics(r.data as Analytics));
  }, [incident.id]);

  const runAISummary = async () => {
    setAiLoading(true); setAiSum(null);
    try { const r = await aiAPI.summarizeIncident(incident.id); setAiSum(r.data); }
    catch { notify('AI unavailable'); }
    finally { setAiLoading(false); }
  };

  const runRootCause = async () => {
    setRcLoading(true); setRootCause(null);
    try { const r = await incidentsAPI.aiRootCause(incident.id); setRootCause(r.data as RootCause); }
    catch { notify('AI unavailable'); }
    finally { setRcLoading(false); }
  };

  const addNote = async () => {
    if (!note.trim()) return;
    setAddingNote(true);
    try {
      await incidentsAPI.addNote(incident.id, note);
      setNote('');
      const r = await incidentsAPI.getEvents(incident.id);
      setEvents(r.data ?? []);
      notify('Note added');
    } catch { notify('Failed to add note'); }
    finally { setAddingNote(false); }
  };

  const updateStatus = async (status: string) => {
    setUpdatingStatus(true);
    try {
      await incidentsAPI.updateStatus(incident.id, status);
      onStatusChange(incident.id, status);
      notify(`Status → ${status}`);
    } catch { notify('Update failed'); }
    finally { setUpdatingStatus(false); }
  };

  const escalateSeverity = async () => {
    const SEV = ['low','medium','high','critical'];
    const idx = SEV.indexOf(incident.severity);
    if (idx >= SEV.length - 1) return;
    const next = SEV[idx + 1];
    setEscalating(true);
    try {
      await incidentsAPI.updateSeverity(incident.id, next);
      onSeverityChange(incident.id, next);
      notify(`Escalated to ${next}`);
    } catch { notify('Escalation failed'); }
    finally { setEscalating(false); }
  };

  const sla = slaInfo(incident.severity, incident.created_at, incident.status);

  const severityAlertCounts = useMemo(() => {
    const m: Record<string, number> = {};
    for (const a of alerts) m[a.severity] = (m[a.severity] ?? 0) + 1;
    return m;
  }, [alerts]);

  const SEC_CARD = "g-card flex flex-col overflow-hidden";

  const copyID = () => {
    navigator.clipboard.writeText(`INC-${incident.id}`);
    setCopied(true); setTimeout(()=>setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto" style={{ background:'var(--bg-0)' }}>
      {toast && (
        <div className="fixed bottom-4 right-4 z-[60] px-4 py-2 rounded-lg text-sm font-medium shadow-xl"
          style={{ background:'var(--accent)', color:'#000' }}>{toast}</div>
      )}

      {/* ── Header ── */}
      <div className="sticky top-0 z-40 px-4 py-3 flex items-center gap-3"
        style={{ background:'var(--bg-1)', borderBottom:'1px solid var(--border)' }}>
        <button onClick={onClose} className="g-btn g-btn-ghost text-xs shrink-0"><ChevronLeft className="h-4 w-4" /> Back</button>
        <div className="h-4 w-px shrink-0" style={{ background:'var(--border)' }} />
        <SevDot sev={incident.severity} />
        <p className="text-sm font-semibold truncate flex-1" style={{ color:'var(--text-1)' }}>{incident.title}</p>
        <div className="flex items-center gap-2 shrink-0">
          <button onClick={copyID} className="g-btn g-btn-ghost text-xs">
            <span className="font-mono text-[10px]" style={{ color:'var(--text-3)' }}>INC-{incident.id}</span>
            {copied ? <Check className="h-3 w-3 ml-1" style={{ color:'var(--green)' }} /> : <Copy className="h-3 w-3 ml-1" style={{ color:'var(--text-3)' }} />}
          </button>
          <StatusChip status={incident.status} />
          <span className={sevClass(incident.severity)}>{incident.severity}</span>
          {sla && (
            <span className="flex items-center gap-1 text-[10px]" style={{ color: sla.breached ? 'var(--red)' : 'var(--text-3)' }}>
              <Clock className="h-3 w-3" />{sla.label}
            </span>
          )}
          {incident.severity !== 'critical' && (
            <button onClick={escalateSeverity} disabled={escalating} className="g-btn g-btn-ghost text-xs" style={{ color:'var(--orange)' }}>
              {escalating ? <Loader2 className="h-3 w-3 animate-spin" /> : <TrendingUp className="h-3 w-3" />}
              <span className="hidden sm:inline">Escalate</span>
            </button>
          )}
        </div>
      </div>

      <div className="max-w-[1600px] mx-auto px-4 py-4 space-y-4">

        {/* ── Row 1: Overview cards ── */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
          {[
            { label:'Incident ID',     val:`INC-${incident.id}`,         mono:true },
            { label:'Status',          val:incident.status,               cap:true },
            { label:'Severity',        val:incident.severity,             cap:true, color:SEV_COLOR[incident.severity] },
            { label:'Agent',           val:incident.hostname||`#${incident.agent_id}` },
            { label:'Created',         val:timeAgo(incident.created_at) },
            { label:'SLA',             val:sla?.label ?? 'Resolved',      color:sla?.breached?'var(--red)':undefined },
          ].map(k => (
            <div key={k.label} className="g-card px-3 py-2.5">
              <p className="text-[9px] uppercase tracking-wider mb-0.5" style={{ color:'var(--text-3)' }}>{k.label}</p>
              <p className={`text-xs font-semibold ${k.cap?'capitalize':''} ${k.mono?'font-mono':''}`}
                style={{ color: k.color ?? 'var(--text-1)' }}>{k.val}</p>
            </div>
          ))}
        </div>

        {/* ── Row 2: Description + Quick Actions ── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
          <div className={`${SEC_CARD} lg:col-span-2`}>
            <SectionHeader icon={Info} title="Incident Summary" />
            <div className="p-4 space-y-3">
              <p className="text-sm leading-relaxed" style={{ color:'var(--text-2)' }}>
                {incident.description || 'No description provided.'}
              </p>
              {deepDive?.affected_asset && (
                <div className="flex flex-wrap gap-4 pt-2 text-xs">
                  {[
                    { label:'Host',      val: deepDive.affected_asset.hostname },
                    { label:'IP',        val: deepDive.affected_asset.ip_address },
                    { label:'OS',        val: deepDive.affected_asset.os },
                    { label:'Risk',      val: deepDive.affected_asset.risk_level || 'unknown', color: 'var(--orange)' },
                  ].map(f => (
                    <div key={f.label}>
                      <span style={{ color:'var(--text-3)' }}>{f.label}: </span>
                      <span className="font-mono" style={{ color: f.color ?? 'var(--text-1)' }}>{f.val || '—'}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div className="px-4 pb-4">
              <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color:'var(--text-3)' }}>Update Status</p>
              <div className="flex gap-1.5 flex-wrap">
                {STATUSES.map(s => (
                  <button key={s} onClick={() => updateStatus(s)} disabled={updatingStatus}
                    className="text-xs px-3 py-1.5 rounded-lg capitalize transition-all"
                    style={{
                      background: incident.status===s ? `${STATUS_COLOR[s]}18` : 'var(--glass-bg)',
                      border: `1px solid ${incident.status===s ? STATUS_COLOR[s]+'44' : 'var(--border)'}`,
                      color: incident.status===s ? STATUS_COLOR[s] : 'var(--text-2)',
                    }}>
                    {updatingStatus ? <Loader2 className="h-3 w-3 animate-spin inline" /> : s}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className={SEC_CARD}>
            <SectionHeader icon={Zap} title="Quick Actions" />
            <div className="p-3 grid grid-cols-2 gap-1.5">
              {[
                { label:'Open Timeline', icon:Clock,       href:'#timeline' },
                { label:'Search Logs',   icon:Search,      href:'/log-search' },
                { label:'Attack Path',   icon:GitBranch,   href:'/attack-path' },
                { label:'Asset View',    icon:Server,      href:`/agents/${incident.agent_id}` },
                { label:'Export CSV',    icon:Download,    href:`/api/export/incidents` },
                { label:'Run SOAR',      icon:Play,        href:'#soar' },
              ].map(a => (
                a.href.startsWith('#')
                  ? <button key={a.label} onClick={()=>document.getElementById(a.href.slice(1))?.scrollIntoView({behavior:'smooth'})}
                      className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-xs hover:bg-[var(--glass-hover)] transition-colors"
                      style={{ background:'var(--glass-bg)', border:'1px solid var(--border)', color:'var(--text-2)' }}>
                      <a.icon className="h-3.5 w-3.5 shrink-0" style={{ color:'var(--accent)' }} />{a.label}
                    </button>
                  : <Link key={a.label} href={a.href}
                      className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-xs hover:bg-[var(--glass-hover)] transition-colors"
                      style={{ background:'var(--glass-bg)', border:'1px solid var(--border)', color:'var(--text-2)' }}>
                      <a.icon className="h-3.5 w-3.5 shrink-0" style={{ color:'var(--accent)' }} />{a.label}
                    </Link>
              ))}
            </div>
          </div>
        </div>

        {/* ── Row 3: Timeline | Attack Chain ── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div id="timeline" className={SEC_CARD} style={{ maxHeight:440 }}>
            <SectionHeader icon={Clock} title={`Timeline (${events.length})`} />
            <div className="flex-1 overflow-y-auto">
              {loadingEvents ? (
                <div className="p-6"><Spinner /></div>
              ) : events.length === 0 ? (
                <p className="p-4 text-xs" style={{ color:'var(--text-3)' }}>No events yet.</p>
              ) : (
                <div className="relative px-4 py-3 space-y-3">
                  <div className="absolute left-6 top-0 bottom-0 w-px" style={{ background:'var(--border)' }} />
                  {events.map((ev, i) => {
                    const ICONS: Record<string, any> = {
                      note: MessageSquare, status_change: Activity, alert: Bell,
                      analyst_action: User, task_completed: CheckCircle2, task: Square,
                    };
                    const Icon = ICONS[ev.event_type] ?? Info;
                    return (
                      <div key={i} className="relative pl-5">
                        <div className="absolute left-0 top-0.5 h-4 w-4 rounded-full flex items-center justify-center"
                          style={{ background:'var(--accent-glow)', border:'1px solid var(--accent-border)' }}>
                          <Icon className="h-2.5 w-2.5" style={{ color:'var(--accent)' }} />
                        </div>
                        <p className="text-[10px] font-bold uppercase" style={{ color:'var(--text-3)' }}>
                          {ev.event_type.replace(/_/g,' ')}
                        </p>
                        <p className="text-xs mt-0.5 leading-relaxed" style={{ color:'var(--text-1)' }}>{ev.details}</p>
                        <p className="text-[10px] mt-0.5" style={{ color:'var(--text-3)' }}>{formatDate(ev.created_at)}</p>
                      </div>
                    );
                  })}
                </div>
              )}
              <div className="px-4 pb-3 pt-2 flex gap-2" style={{ borderTop:'1px solid var(--border)' }}>
                <input value={note} onChange={e=>setNote(e.target.value)} onKeyDown={e=>e.key==='Enter'&&addNote()}
                  placeholder="Add investigation note…" className="g-input flex-1 text-xs" />
                <button onClick={addNote} disabled={addingNote||!note.trim()} className="g-btn g-btn-primary px-3">
                  {addingNote ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
                </button>
              </div>
            </div>
          </div>

          <div className={SEC_CARD} style={{ maxHeight:440 }}>
            <SectionHeader icon={GitBranch} title="Attack Chain" />
            <div className="flex-1 overflow-y-auto">
              {loadingDD ? <div className="p-6"><Spinner /></div>
                : <AttackChainView mitre={deepDive?.mitre_coverage ?? []} timeline={deepDive?.timeline ?? []} />}
            </div>
          </div>
        </div>

        {/* ── Row 4: Alerts | Assets ── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={SEC_CARD} style={{ maxHeight:360 }}>
            <SectionHeader icon={Bell} title={`Related Alerts (${alerts.length})`}
              action={
                <div className="flex gap-1">
                  {Object.entries(severityAlertCounts).map(([sev, cnt]) => (
                    <span key={sev} className="text-[9px] px-1.5 py-0.5 rounded-full font-bold" style={{ background:`${SEV_COLOR[sev]}18`, color:SEV_COLOR[sev] }}>
                      {cnt} {sev}
                    </span>
                  ))}
                </div>
              } />
            <div className="flex-1 overflow-y-auto">
              {alerts.length === 0
                ? <p className="p-4 text-xs" style={{ color:'var(--text-3)' }}>No linked alerts.</p>
                : (
                  <div className="relative pl-4">
                    <div className="absolute left-2 top-0 bottom-0 w-px" style={{ background:'var(--border)' }} />
                    {alerts.map((a, i) => (
                      <div key={a.id} className="flex items-start gap-2 px-3 py-2.5" style={{ borderBottom:'1px solid var(--border)' }}>
                        <SevDot sev={a.severity} />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-medium truncate" style={{ color:'var(--text-1)' }}>{a.rule_name}</p>
                          <p className="text-[10px]" style={{ color:'var(--text-3)' }}>{timeAgo(a.created_at)}</p>
                        </div>
                        <span className={sevClass(a.severity)}>{a.severity}</span>
                      </div>
                    ))}
                  </div>
                )
              }
            </div>
          </div>

          <div className={SEC_CARD} style={{ maxHeight:360 }}>
            <SectionHeader icon={Server} title="Affected Assets" />
            <div className="flex-1 overflow-y-auto">
              {loadingDD ? <div className="p-6"><Spinner /></div>
                : deepDive?.affected_asset ? (
                  <div className="p-4 space-y-3">
                    {[
                      { label:'Hostname',   val:deepDive.affected_asset.hostname,   icon:Server },
                      { label:'IP Address', val:deepDive.affected_asset.ip_address, icon:Globe2 },
                      { label:'OS',         val:deepDive.affected_asset.os,          icon:Terminal },
                      { label:'Agent ID',   val:`#${deepDive.affected_asset.agent_id}`, icon:Cpu },
                      { label:'Status',     val:deepDive.affected_asset.status,      icon:Activity },
                      { label:'Risk Level', val:deepDive.affected_asset.risk_level || 'unknown', icon:AlertTriangle, color:'var(--orange)' },
                    ].map(f=>(
                      <div key={f.label} className="flex items-center gap-2.5">
                        <div className="h-6 w-6 rounded-lg flex items-center justify-center shrink-0" style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                          <f.icon className="h-3.5 w-3.5" style={{ color:'var(--accent)' }} />
                        </div>
                        <span className="text-xs w-24 shrink-0" style={{ color:'var(--text-3)' }}>{f.label}</span>
                        <span className="text-xs font-mono font-semibold" style={{ color:(f as any).color ?? 'var(--text-1)' }}>{f.val || '—'}</span>
                      </div>
                    ))}
                    <Link href={`/agents/${deepDive.affected_asset.agent_id}`}
                      className="g-btn g-btn-ghost text-xs w-full justify-center mt-2">
                      <Eye className="h-3.5 w-3.5" /> Open Agent View
                    </Link>
                  </div>
                ) : <p className="p-4 text-xs" style={{ color:'var(--text-3)' }}>Asset data unavailable.</p>
              }
            </div>
          </div>
        </div>

        {/* ── Row 5: Evidence | MITRE ── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={SEC_CARD} style={{ maxHeight:340 }}>
            <SectionHeader icon={FileSearch} title="Evidence & Indicators" />
            <div className="flex-1 overflow-y-auto">
              {loadingDD ? <div className="p-6"><Spinner /></div>
                : <EvidenceView indicators={deepDive?.indicators ?? []} />}
            </div>
          </div>

          <div className={SEC_CARD} style={{ maxHeight:340 }}>
            <SectionHeader icon={Target} title="MITRE ATT&CK Mapping" />
            <div className="flex-1 overflow-y-auto">
              {loadingDD ? <div className="p-6"><Spinner /></div>
                : <MITREView techniques={deepDive?.mitre_coverage ?? []} />}
            </div>
          </div>
        </div>

        {/* ── Row 6: AI Summary | AI Root Cause ── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={SEC_CARD}>
            <SectionHeader icon={Bot} title="AI Summary"
              action={
                <button onClick={runAISummary} disabled={aiLoading}
                  className="g-btn g-btn-ghost text-[10px] py-1 px-2">
                  {aiLoading ? <><Loader2 className="h-3 w-3 animate-spin" /> Analyzing…</> : 'Run Analysis'}
                </button>
              } />
            <div className="p-4 space-y-3">
              {aiLoading && <div className="flex justify-center py-4"><Spinner /></div>}
              {!aiLoading && !aiSum && (
                <div className="text-center py-6 space-y-2">
                  <Bot className="h-8 w-8 mx-auto opacity-20" style={{ color:'var(--accent)' }} />
                  <p className="text-xs" style={{ color:'var(--text-3)' }}>Click Run Analysis for AI-powered incident summary.</p>
                  <button onClick={runAISummary} className="g-btn g-btn-primary text-xs mx-auto"><Bot className="h-3.5 w-3.5" /> Analyze Incident</button>
                </div>
              )}
              {aiSum && (
                <>
                  <div className="rounded-xl p-3" style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                    <p className="text-xs leading-relaxed" style={{ color:'var(--text-1)' }}>{aiSum.summary}</p>
                  </div>
                  {aiSum.root_cause_hint && (
                    <div className="rounded-xl p-3" style={{ background:'var(--accent-glow)', border:'1px solid var(--accent-border)' }}>
                      <p className="text-[10px] font-semibold mb-1" style={{ color:'var(--text-3)' }}>Root Cause Hypothesis</p>
                      <p className="text-xs" style={{ color:'var(--accent)' }}>{aiSum.root_cause_hint}</p>
                    </div>
                  )}
                  {aiSum.timeline?.length > 0 && (
                    <div className="space-y-1.5">
                      <p className="text-[10px] font-bold uppercase tracking-wider" style={{ color:'var(--text-3)' }}>Inferred Timeline</p>
                      {aiSum.timeline.map((s: string, i: number) => (
                        <div key={i} className="flex gap-2 text-xs">
                          <span className="shrink-0 font-mono w-4 text-right" style={{ color:'var(--accent)' }}>{i+1}.</span>
                          <span style={{ color:'var(--text-2)' }}>{s}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>
          </div>

          <div className={SEC_CARD}>
            <SectionHeader icon={Crosshair} title="AI Root Cause Analysis"
              action={
                <button onClick={runRootCause} disabled={rcLoading}
                  className="g-btn g-btn-ghost text-[10px] py-1 px-2">
                  {rcLoading ? <><Loader2 className="h-3 w-3 animate-spin" /> Analyzing…</> : 'Analyze'}
                </button>
              } />
            <div className="p-4 space-y-3">
              {rcLoading && <div className="flex justify-center py-4"><Spinner /></div>}
              {!rcLoading && !rootCause && (
                <div className="text-center py-6 space-y-2">
                  <Crosshair className="h-8 w-8 mx-auto opacity-20" style={{ color:'var(--red)' }} />
                  <p className="text-xs" style={{ color:'var(--text-3)' }}>AI will identify initial access, root cause, and prevention steps.</p>
                  <button onClick={runRootCause} className="g-btn g-btn-primary text-xs mx-auto"><Crosshair className="h-3.5 w-3.5" /> Analyze Root Cause</button>
                </div>
              )}
              {rootCause && (
                <div className="space-y-2">
                  {[
                    { label:'Initial Access',       val:rootCause.initial_access,       color:'var(--red)' },
                    { label:'Root Cause',            val:rootCause.root_cause,            color:'var(--orange)' },
                    { label:'Compromised User',      val:rootCause.compromised_user,      color:'var(--yellow)' },
                    { label:'Entry Point',           val:rootCause.entry_point,           color:'var(--accent)' },
                    { label:'Weak Control',          val:rootCause.weak_control,          color:'var(--red)' },
                    { label:'Attack Stage',          val:rootCause.attack_stage,          color:'var(--text-2)' },
                    { label:'Estimated Dwell Time',  val:rootCause.estimated_dwell_time,  color:'var(--text-2)' },
                  ].map(f => (
                    <div key={f.label} className="flex flex-col gap-0.5 py-1.5" style={{ borderBottom:'1px solid var(--border)' }}>
                      <span className="text-[10px]" style={{ color:'var(--text-3)' }}>{f.label}</span>
                      <span className="text-xs font-medium" style={{ color:f.color }}>{f.val || '—'}</span>
                    </div>
                  ))}
                  {rootCause.prevention_suggestions?.length > 0 && (
                    <div>
                      <p className="text-[10px] font-bold uppercase tracking-wider mt-2 mb-1.5" style={{ color:'var(--text-3)' }}>Prevention Suggestions</p>
                      {rootCause.prevention_suggestions.map((s, i) => (
                        <div key={i} className="flex gap-2 text-xs py-1">
                          <span className="shrink-0 font-bold" style={{ color:'var(--green)' }}>{i+1}.</span>
                          <span style={{ color:'var(--text-2)' }}>{s}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* ── Row 7: Tasks | Response Actions ── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={SEC_CARD} style={{ maxHeight:480 }}>
            <SectionHeader icon={CheckSquare} title="Investigation Checklist" />
            <div className="flex-1 overflow-y-auto">
              <TaskChecklist incidentId={incident.id} />
            </div>
          </div>

          <div id="soar" className={SEC_CARD} style={{ maxHeight:480 }}>
            <SectionHeader icon={Play} title="Response Actions" />
            <div className="flex-1 overflow-y-auto">
              <ResponseActions incidentId={incident.id} onAction={notify} />
            </div>
          </div>
        </div>

        {/* ── Row 8: Blast Radius | Recommendations ── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={SEC_CARD} style={{ maxHeight:340 }}>
            <SectionHeader icon={Network} title="Blast Radius" />
            <div className="flex-1 overflow-y-auto">
              <BlastRadiusView asset={deepDive?.affected_asset} />
            </div>
          </div>

          <div className={SEC_CARD} style={{ maxHeight:340 }}>
            <SectionHeader icon={BookOpen} title="Recommendations" />
            <div className="flex-1 overflow-y-auto p-4 space-y-2">
              {(deepDive?.recommendations ?? []).length === 0
                ? <p className="text-xs" style={{ color:'var(--text-3)' }}>No recommendations yet — run AI analysis.</p>
                : (deepDive?.recommendations ?? []).map((rec, i) => (
                  <div key={i} className="flex gap-3 rounded-lg px-3 py-2.5"
                    style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                    <span className="shrink-0 h-5 w-5 rounded-full flex items-center justify-center text-[10px] font-bold"
                      style={{ background:'var(--accent-glow)', color:'var(--accent)', border:'1px solid var(--accent-border)' }}>
                      {i+1}
                    </span>
                    <p className="text-xs leading-relaxed" style={{ color:'var(--text-2)' }}>{rec}</p>
                  </div>
                ))
              }
              {aiSum?.recommended_steps?.map((s: string, i: number) => (
                <div key={`ai-${i}`} className="flex gap-3 rounded-lg px-3 py-2.5"
                  style={{ background:'var(--accent-glow)', border:'1px solid var(--accent-border)' }}>
                  <span className="shrink-0 h-5 w-5 rounded-full flex items-center justify-center text-[10px] font-bold"
                    style={{ background:'var(--accent)', color:'#000' }}>
                    {i+1}
                  </span>
                  <p className="text-xs leading-relaxed" style={{ color:'var(--text-2)' }}>{s}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── Row 9: SLA Tracking | Risk Assessment ── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={SEC_CARD}>
            <SectionHeader icon={Clock} title="SLA Tracking" />
            <div className="p-4 space-y-3">
              {[
                { label:'Time to Acknowledge', slaH:0.5,  color:'var(--green)' },
                { label:'Time to Assign',       slaH:1,    color:'var(--green)' },
                { label:'Time to Investigate',  slaH:INCIDENT_SLA[incident.severity]*0.3, color:'var(--yellow)' },
                { label:'Time to Contain',      slaH:INCIDENT_SLA[incident.severity]*0.7, color:'var(--orange)' },
                { label:'Time to Resolve',      slaH:INCIDENT_SLA[incident.severity],     color:'var(--red)' },
              ].map(s => {
                const ageH = (Date.now() - new Date(incident.created_at).getTime()) / 3_600_000;
                const pct = Math.min(100, (ageH / s.slaH) * 100);
                const done = incident.status === 'resolved' || incident.status === 'closed';
                return (
                  <div key={s.label}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs" style={{ color:'var(--text-2)' }}>{s.label}</span>
                      <span className="text-[10px] font-mono" style={{ color: done ? 'var(--green)' : pct >= 100 ? 'var(--red)' : 'var(--text-3)' }}>
                        {done ? '✓ Done' : pct >= 100 ? 'Breached' : `${(s.slaH - ageH).toFixed(1)}h left`}
                      </span>
                    </div>
                    <div className="h-1.5 rounded-full overflow-hidden" style={{ background:'var(--border)' }}>
                      <div className="h-full rounded-full transition-all"
                        style={{ width:`${done?100:pct}%`, background: done ? 'var(--green)' : pct >= 100 ? 'var(--red)' : s.color }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className={SEC_CARD}>
            <SectionHeader icon={BarChart2} title="Risk Assessment" />
            <div className="p-4 space-y-3">
              {[
                { label:'Incident Risk',   val: incident.severity,    color: SEV_COLOR[incident.severity] },
                { label:'Threat Level',    val: incident.severity === 'critical' ? 'Critical' : incident.severity === 'high' ? 'High' : 'Elevated', color: SEV_COLOR[incident.severity] },
                { label:'Exploitability',  val: incident.severity === 'critical' ? 'Active' : 'Moderate', color: 'var(--orange)' },
                { label:'Exposure',        val: deepDive?.affected_asset.status === 'online' ? 'Actively Exposed' : 'Limited', color: 'var(--yellow)' },
                { label:'Business Risk',   val: deepDive?.affected_asset.risk_level || 'Medium', color: 'var(--text-2)' },
                { label:'Active Attack',   val: incident.status === 'open' || incident.status === 'investigating' ? 'Yes' : 'No', color: incident.status === 'open' ? 'var(--red)' : 'var(--green)' },
              ].map(r => (
                <div key={r.label} className="flex items-center justify-between py-1" style={{ borderBottom:'1px solid var(--border)' }}>
                  <span className="text-xs" style={{ color:'var(--text-3)' }}>{r.label}</span>
                  <span className="text-xs font-semibold capitalize" style={{ color:r.color }}>{r.val}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── Row 10: Similar Incidents | Incident Analytics ── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={SEC_CARD} style={{ maxHeight:320 }}>
            <SectionHeader icon={Layers} title="Similar Incidents" />
            <div className="flex-1 overflow-y-auto">
              {similar.length === 0
                ? <p className="p-4 text-xs" style={{ color:'var(--text-3)' }}>No similar incidents found.</p>
                : similar.map(s => (
                  <div key={s.id} className="flex items-center gap-3 px-4 py-2.5" style={{ borderBottom:'1px solid var(--border)' }}>
                    <SevDot sev={s.severity} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium truncate" style={{ color:'var(--text-1)' }}>{s.title}</p>
                      <p className="text-[10px]" style={{ color:'var(--text-3)' }}>{s.hostname} · {timeAgo(s.created_at)}</p>
                    </div>
                    <span className="text-[9px] px-1.5 py-0.5 rounded" style={{ background:'var(--glass-bg)', border:'1px solid var(--border)', color:'var(--text-3)' }}>
                      {s.match_reason}
                    </span>
                    <StatusChip status={s.status} />
                  </div>
                ))
              }
            </div>
          </div>

          <div className={SEC_CARD} style={{ maxHeight:320 }}>
            <SectionHeader icon={BarChart2} title="Incident Analytics" />
            <div className="flex-1 overflow-y-auto p-4 space-y-3">
              {!analytics ? <Spinner />
                : (
                  <>
                    <div className="grid grid-cols-3 gap-2">
                      {[
                        { label:'MTTD', val:`${analytics.mttd_hours}h`, desc:'Mean detect time' },
                        { label:'MTTR', val:`${analytics.mttr_hours}h`, desc:'Mean resolve time' },
                        { label:'MTTC', val:`${analytics.mttc_hours}h`, desc:'Mean contain time' },
                      ].map(m => (
                        <div key={m.label} className="rounded-xl px-3 py-2.5 text-center"
                          style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                          <p className="text-[10px]" style={{ color:'var(--text-3)' }}>{m.label}</p>
                          <p className="text-lg font-bold tabular-nums" style={{ color:'var(--accent)' }}>{m.val}</p>
                          <p className="text-[9px]" style={{ color:'var(--text-3)' }}>{m.desc}</p>
                        </div>
                      ))}
                    </div>
                    <div>
                      <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color:'var(--text-3)' }}>By Severity</p>
                      <div className="space-y-1.5">
                        {analytics.by_severity.map(s => (
                          <div key={s.severity} className="flex items-center gap-2">
                            <SevDot sev={s.severity} />
                            <span className="text-xs capitalize w-20 shrink-0" style={{ color:'var(--text-2)' }}>{s.severity}</span>
                            <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background:'var(--border)' }}>
                              <div className="h-full rounded-full" style={{ width:`${(s.count/(analytics.total||1))*100}%`, background:SEV_COLOR[s.severity] }} />
                            </div>
                            <span className="text-xs tabular-nums font-mono" style={{ color:'var(--text-3)' }}>{s.count}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </>
                )
              }
            </div>
          </div>
        </div>

        {/* ── Row 11: Investigation History | Reporting ── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={SEC_CARD} style={{ maxHeight:320 }}>
            <SectionHeader icon={FileText} title="Investigation History" />
            <div className="flex-1 overflow-y-auto">
              {loadingEvents ? <div className="p-4"><Spinner /></div>
                : events.filter(e => ['note','analyst_action','status_change','task_completed'].includes(e.event_type)).length === 0
                  ? <p className="p-4 text-xs" style={{ color:'var(--text-3)' }}>No analyst actions recorded yet.</p>
                  : events.filter(e => ['note','analyst_action','status_change','task_completed'].includes(e.event_type)).map((ev, i) => (
                    <div key={i} className="flex items-start gap-3 px-4 py-2.5" style={{ borderBottom:'1px solid var(--border)' }}>
                      <span className="text-[9px] font-mono w-14 shrink-0 text-right pt-0.5" style={{ color:'var(--text-3)' }}>
                        {new Date(ev.created_at).toLocaleTimeString('en',{hour:'2-digit',minute:'2-digit'})}
                      </span>
                      <div>
                        <p className="text-[10px] font-bold uppercase" style={{ color:'var(--text-3)' }}>{ev.event_type.replace(/_/g,' ')}</p>
                        <p className="text-xs" style={{ color:'var(--text-1)' }}>{ev.details}</p>
                      </div>
                    </div>
                  ))
              }
            </div>
          </div>

          <div className={SEC_CARD}>
            <SectionHeader icon={Download} title="Export & Reporting" />
            <div className="p-4 space-y-2">
              {[
                { label:'Export Incidents CSV',      href:'/api/export/incidents',      icon:Download, desc:'All incidents for this tenant' },
                { label:'Executive PDF Report',      href:'#',                          icon:FileText, desc:'High-level overview' },
                { label:'Technical DFIR Report',     href:'#',                          icon:BookOpen, desc:'Detailed forensic export' },
                { label:'STIX / TAXII Export',       href:'#',                          icon:Package,  desc:'Machine-readable IOCs' },
                { label:'Open in Compliance',        href:'/risk-posture',              icon:Shield,   desc:'Check compliance impact' },
                { label:'Open Attack Path',          href:'/attack-path',               icon:GitBranch,desc:'View lateral movement graph' },
              ].map(item => (
                <Link key={item.label} href={item.href}
                  className="flex items-center gap-3 rounded-lg px-3 py-2.5 hover:bg-[var(--glass-hover)] transition-colors"
                  style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                  <item.icon className="h-3.5 w-3.5 shrink-0" style={{ color:'var(--accent)' }} />
                  <div className="min-w-0">
                    <p className="text-xs font-medium" style={{ color:'var(--text-1)' }}>{item.label}</p>
                    <p className="text-[10px]" style={{ color:'var(--text-3)' }}>{item.desc}</p>
                  </div>
                  <ChevronRight className="h-3.5 w-3.5 shrink-0 ml-auto" style={{ color:'var(--text-3)' }} />
                </Link>
              ))}
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}

// ── Main Incidents Page ───────────────────────────────────────────────────────

export default function IncidentsPage() {
  const [incidents,      setIncidents]      = useState<Incident[]>([]);
  const [loading,        setLoading]        = useState(true);
  const [refreshing,     setRefreshing]     = useState(false);
  const [filter,         setFilter]         = useState('all');
  const [severityFilter, setSeverityFilter] = useState('');
  const [searchQuery,    setSearchQuery]    = useState('');
  const [selectedIDs,    setSelectedIDs]    = useState<Set<number>>(new Set());
  const [bulkStatus,     setBulkStatus]     = useState('');
  const [bulking,        setBulking]        = useState(false);
  const [selected,       setSelected]       = useState<Incident | null>(null);
  const [updatingId,     setUpdatingId]     = useState<number | null>(null);
  const [toast,          setToast]          = useState<string | null>(null);
  const [page,           setPage]           = useState(1);
  const [total,          setTotal]          = useState(0);
  const [statusCounts,   setStatusCounts]   = useState<Record<string, number>>({});
  const [analytics,      setAnalytics]      = useState<Analytics | null>(null);
  const [, setTick]                         = useState(0);
  const PER_PAGE = 25;

  useEffect(() => {
    const id = setInterval(() => setTick(t => t + 1), 60_000);
    return () => clearInterval(id);
  }, []);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const load = useCallback(async (p = page, status = filter, spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const r = await incidentsAPI.getPaginated(p, PER_PAGE, status === 'all' ? '' : status);
      const data = r.data || {};
      setIncidents(data.data || []);
      setTotal(data.total || 0);
    } finally { setLoading(false); setRefreshing(false); }
  }, [page, filter]);

  useEffect(() => { load(page, filter); }, [page, filter]);

  useEffect(() => {
    incidentsAPI.getCounts().then(r => setStatusCounts(r.data || {})).catch(() => {});
    incidentsAPI.getAnalytics().then(r => r.data && setAnalytics(r.data as Analytics)).catch(() => {});
  }, []);

  const updateStatus = async (id: number, status: string) => {
    setUpdatingId(id);
    try {
      await incidentsAPI.updateStatus(id, status);
      setIncidents(p => p.map(i => i.id === id ? { ...i, status: status as any } : i));
      if (selected?.id === id) setSelected(s => s ? { ...s, status: status as any } : s);
      notify(`Status → ${status}`);
    } finally { setUpdatingId(null); }
  };

  const updateSeverity = (id: number, severity: string) => {
    setIncidents(p => p.map(i => i.id === id ? { ...i, severity: severity as any } : i));
    if (selected?.id === id) setSelected(s => s ? { ...s, severity: severity as any } : s);
  };

  const bulkUpdate = async () => {
    if (!bulkStatus || selectedIDs.size === 0) return;
    setBulking(true);
    try {
      await Promise.all([...selectedIDs].map(id => incidentsAPI.updateStatus(id, bulkStatus)));
      setIncidents(p => p.map(i => selectedIDs.has(i.id) ? { ...i, status: bulkStatus as any } : i));
      notify(`${selectedIDs.size} incidents → ${bulkStatus}`);
      setSelectedIDs(new Set()); setBulkStatus('');
    } catch { notify('Bulk update failed'); }
    finally { setBulking(false); }
  };

  const changeFilter = (f: string) => { setFilter(f); setPage(1); setSelectedIDs(new Set()); };

  const displayed = incidents.filter(inc => {
    if (severityFilter && inc.severity !== severityFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return inc.title.toLowerCase().includes(q) || (inc.description || '').toLowerCase().includes(q);
    }
    return true;
  });

  const totalCount = Object.values(statusCounts).reduce((a, b) => a + b, 0);
  const slaBreached = incidents.filter(i =>
    i.status !== 'resolved' && i.status !== 'closed' && slaInfo(i.severity, i.created_at, i.status)?.breached
  ).length;

  // Full-page detail view
  if (selected) {
    return (
      <IncidentDetail
        incident={selected}
        onClose={() => setSelected(null)}
        onStatusChange={(id, status) => {
          setIncidents(p => p.map(i => i.id === id ? { ...i, status: status as any } : i));
          setSelected(s => s ? { ...s, status: status as any } : s);
        }}
        onSeverityChange={updateSeverity}
      />
    );
  }

  return (
    <RootLayout title="Incidents" subtitle={total ? `${total} total` : ''}
      onRefresh={() => load(page, filter, true)} refreshing={refreshing}>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 px-4 py-2.5 rounded-lg text-sm font-medium shadow-xl"
          style={{ background:'var(--accent)', color:'#000' }}>{toast}</div>
      )}

      <div className="space-y-4">

        {/* KPI strip */}
        {!loading && (
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
            {[
              { label:'Total',         val:totalCount,                        color:'var(--accent)',  Icon:Activity },
              { label:'Open',          val:statusCounts.open        ?? 0,     color:'var(--red)',     Icon:Flame },
              { label:'Investigating', val:statusCounts.investigating ?? 0,   color:'var(--orange)',  Icon:ShieldAlert },
              { label:'SLA Breached',  val:slaBreached,                        color:slaBreached>0?'var(--red)':'var(--green)', Icon:Clock },
              { label:'MTTR',          val:`${analytics?.mttr_hours ?? '—'}h`, color:'var(--text-2)', Icon:BarChart2 },
              { label:'MTTD',          val:`${analytics?.mttd_hours ?? '—'}h`, color:'var(--text-2)', Icon:BarChart2 },
            ].map(({ label, val, color, Icon }) => (
              <div key={label} className="g-card p-3 flex items-center gap-2.5">
                <div className="p-1.5 rounded-lg shrink-0" style={{ background:`${color}18` }}>
                  <Icon className="h-4 w-4" style={{ color }} />
                </div>
                <div className="min-w-0">
                  <p className="text-base font-bold tabular-nums truncate" style={{ color }}>{val}</p>
                  <p className="text-[10px] truncate" style={{ color:'var(--text-3)' }}>{label}</p>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Status tabs */}
        <div className="flex items-center gap-2 flex-wrap">
          {['all', ...STATUSES].map(s => {
            const count = s === 'all' ? totalCount : (statusCounts[s] ?? 0);
            return (
              <button key={s} onClick={() => changeFilter(s)}
                className="g-btn text-xs capitalize"
                style={{
                  background: filter===s ? 'var(--accent-glow)' : 'var(--glass-bg)',
                  color:      filter===s ? 'var(--accent)' : 'var(--text-2)',
                  border:     `1px solid ${filter===s ? 'var(--accent-border)' : 'var(--border)'}`,
                }}>
                {s}{count > 0 ? ` (${count})` : ''}
              </button>
            );
          })}
        </div>

        {/* Search + severity filter */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color:'var(--text-3)' }} />
            <input value={searchQuery} onChange={e=>setSearchQuery(e.target.value)}
              placeholder="Search incidents…" className="g-input w-full text-xs pl-8" />
            {searchQuery && (
              <button onClick={()=>setSearchQuery('')} className="absolute right-2.5 top-1/2 -translate-y-1/2"
                style={{ color:'var(--text-3)' }}><X className="h-3 w-3" /></button>
            )}
          </div>
          <div className="flex items-center gap-1">
            <Filter className="h-3.5 w-3.5" style={{ color:'var(--text-3)' }} />
            {['', ...SEVERITIES].map(s => (
              <button key={s || 'all'} onClick={() => setSeverityFilter(s)}
                className="px-2.5 py-1 text-[11px] rounded-lg capitalize transition-all"
                style={{
                  background: severityFilter===s ? 'var(--accent-glow)' : 'var(--glass-bg)',
                  border: `1px solid ${severityFilter===s ? 'var(--accent-border)' : 'var(--border)'}`,
                  color: severityFilter===s ? 'var(--accent)' : 'var(--text-2)',
                }}>
                {s || 'all'}
              </button>
            ))}
          </div>
        </div>

        {/* Bulk action bar */}
        {selectedIDs.size > 0 && (
          <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl"
            style={{ background:'var(--accent-glow)', border:'1px solid var(--accent-border)' }}>
            <CheckCheck className="h-4 w-4" style={{ color:'var(--accent)' }} />
            <span className="text-xs font-medium" style={{ color:'var(--accent)' }}>{selectedIDs.size} selected</span>
            <div className="flex items-center gap-1.5 ml-auto">
              <select value={bulkStatus} onChange={e=>setBulkStatus(e.target.value)} className="g-select text-xs" style={{ padding:'3px 8px' }}>
                <option value="">Set status…</option>
                {STATUSES.map(s=><option key={s} value={s}>{s}</option>)}
              </select>
              <button onClick={bulkUpdate} disabled={!bulkStatus||bulking} className="g-btn g-btn-primary text-xs">
                {bulking ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : 'Apply'}
              </button>
              <button onClick={()=>setSelectedIDs(new Set())} className="g-btn g-btn-ghost text-xs">Clear</button>
            </div>
          </div>
        )}

        {/* Table */}
        <div className="g-table">
          <div className="g-thead grid gap-3 px-4"
            style={{ gridTemplateColumns:'16px 8px 1fr 110px 90px 80px 90px 80px 24px' }}>
            <button onClick={()=>selectedIDs.size===displayed.length?setSelectedIDs(new Set()):setSelectedIDs(new Set(displayed.map(i=>i.id)))} style={{ color:'var(--text-3)' }}>
              {selectedIDs.size>0&&selectedIDs.size===displayed.length?<CheckSquare className="h-3.5 w-3.5"/>:<Square className="h-3.5 w-3.5"/>}
            </button>
            <span />
            <span>Title</span>
            <span>Status</span>
            <span>Host</span>
            <span>Severity</span>
            <span>Change</span>
            <span>SLA</span>
            <span />
          </div>

          {loading ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color:'var(--text-3)' }}>Loading…</div>
          ) : displayed.length === 0 ? (
            <div className="py-16 text-center">
              <AlertTriangle className="mx-auto h-8 w-8 mb-2 opacity-20" style={{ color:'var(--text-3)' }} />
              <p className="text-sm" style={{ color:'var(--text-2)' }}>No incidents found</p>
            </div>
          ) : displayed.map(inc => {
            const sla = slaInfo(inc.severity, inc.created_at, inc.status);
            return (
              <div key={inc.id} className="g-tr grid gap-3 items-center px-4 cursor-pointer"
                style={{ gridTemplateColumns:'16px 8px 1fr 110px 90px 80px 90px 80px 24px' }}
                onClick={() => setSelected(inc)}>
                <button onClick={e=>{e.stopPropagation();setSelectedIDs(p=>{const n=new Set(p);n.has(inc.id)?n.delete(inc.id):n.add(inc.id);return n;})}}
                  style={{ color:selectedIDs.has(inc.id)?'var(--accent)':'var(--text-3)' }}>
                  {selectedIDs.has(inc.id)?<CheckSquare className="h-3.5 w-3.5"/>:<Square className="h-3.5 w-3.5"/>}
                </button>
                <SevDot sev={inc.severity} />
                <div className="min-w-0">
                  <p className="text-xs font-medium truncate" style={{ color:'var(--text-1)' }}>{inc.title}</p>
                  <p className="text-[10px] truncate" style={{ color:'var(--text-3)' }}>{inc.description}</p>
                </div>
                <StatusChip status={inc.status} />
                <Link href={`/agents/${inc.agent_id}`} onClick={e=>e.stopPropagation()}
                  className="text-xs font-mono hover:underline truncate" style={{ color:'var(--accent)' }}>
                  {inc.hostname || `#${inc.agent_id}`}
                </Link>
                <span className={sevClass(inc.severity)}>{inc.severity}</span>
                <select value={inc.status} disabled={updatingId===inc.id}
                  onChange={e=>{e.stopPropagation();updateStatus(inc.id,e.target.value);}}
                  onClick={e=>e.stopPropagation()}
                  className="g-select text-[11px] py-1" style={{ width:90 }}>
                  {STATUSES.map(s=><option key={s} value={s}>{s}</option>)}
                </select>
                {sla ? (
                  <span className="flex items-center gap-1 text-[11px]"
                    style={{ color:sla.breached?'var(--red)':'var(--text-3)' }}>
                    <Clock className="h-3 w-3 shrink-0" />{sla.label}
                  </span>
                ) : (
                  <span className="text-[11px]" style={{ color:'var(--text-3)' }}>{timeAgo(inc.created_at)}</span>
                )}
                <button onClick={e=>{e.stopPropagation();setSelected(inc);}} style={{ color:'var(--text-3)' }}>
                  <ChevronRight className="h-3.5 w-3.5" />
                </button>
              </div>
            );
          })}
        </div>

        {/* Pagination */}
        {total > PER_PAGE && (
          <div className="flex items-center justify-between mt-2">
            <p className="text-xs" style={{ color:'var(--text-3)' }}>
              {(page-1)*PER_PAGE+1}–{Math.min(page*PER_PAGE,total)} of {total}
            </p>
            <div className="flex items-center gap-2">
              <button onClick={()=>setPage(p=>p-1)} disabled={page===1} className="g-btn g-btn-ghost text-xs px-3">← Prev</button>
              <span className="text-xs" style={{ color:'var(--text-2)' }}>Page {page} of {Math.ceil(total/PER_PAGE)}</span>
              <button onClick={()=>setPage(p=>p+1)} disabled={page>=Math.ceil(total/PER_PAGE)} className="g-btn g-btn-ghost text-xs px-3">Next →</button>
            </div>
          </div>
        )}
      </div>
    </RootLayout>
  );
}
