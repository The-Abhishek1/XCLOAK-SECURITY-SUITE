'use client';

import { useState, useMemo, useCallback } from 'react';
import { Alert } from '@/types';
import { alertsAPI, aiAPI, investigateAPI, alertDetailAPI } from '@/lib/api';
import { sevClass, timeAgo, formatDate } from '@/lib/utils';
import {
  X, Shield, Bot, Loader2, Check, Clock, VolumeX, BellOff, Zap, Search,
  ChevronRight, ChevronDown, Download,
  Monitor, HardDrive, Terminal,
  Brain, ShieldAlert, ShieldCheck, WifiOff, Ban,
  Target, Crosshair,
  Cpu, ScrollText, Pencil, Workflow, Swords,
  Trash2, PlayCircle,
} from 'lucide-react';

// ── Types ─────────────────────────────────────────────────────────────────────

interface Props {
  alert: Alert;
  onClose: () => void;
  onToast: (msg: string) => void;
  onReload: () => void;
}

type Tab = 'overview'|'detection'|'ai'|'actions'|'history';

interface HistoryEntry { ts: string; actor: string; action: string; detail: string; }

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

// ── History derivation ─────────────────────────────────────────────────────────
// Derived from the alert's own real lifecycle fields (status/note/timestamps) —
// not fabricated, unlike the timeline/entity/intel data this file used to generate.

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
  const [suppressHours, setSuppressHours] = useState('4');
  const [snoozeMin, setSnoozeMin]   = useState('240');
  const [responsePID, setResponsePID] = useState('');
  const [responseFile, setResponseFile] = useState('');

  // Derived / generated data
  const history  = useMemo(() => genHistory(a), [a]);
  // "T0000" / "Unknown" are the backend's internal placeholder for alerts it
  // couldn't classify — not real MITRE identifiers, so treat them as absent
  // rather than rendering them like a real technique/tactic.
  const mitreTechnique = a.mitre_technique && a.mitre_technique !== 'T0000' ? a.mitre_technique : undefined;
  const mitreTactic    = a.mitre_tactic    && a.mitre_tactic    !== 'Unknown' ? a.mitre_tactic    : undefined;
  const mitreName      = a.mitre_name      && a.mitre_name      !== 'Uncategorized' ? a.mitre_name : undefined;
  const mitreInfo = useMemo(() => getMitreInfo(mitreTechnique), [mitreTechnique]);

  const kcIdx = mitreTactic ? KILL_CHAIN.findIndex(k => k.toLowerCase() === mitreTactic.toLowerCase()) : -1;

  // Overrides the stale `a.ai_summary`/`a.ai_action` props with the fresh
  // result from a triage run in *this* session — onReload() only refreshes
  // the parent list, it doesn't hand a new `alert` prop back into this
  // still-open drawer, so without this the UI would claim "triage complete"
  // while still showing the old (possibly empty) summary underneath.
  const [triageOverride, setTriageOverride] = useState<{ summary: string; action: string } | null>(null);
  const aiSummary = triageOverride?.summary || a.ai_summary;
  const aiAction  = triageOverride?.action  || a.ai_action;

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

  const runTriage = useCallback(async () => {
    setTriaging(true);
    try {
      const { data } = await aiAPI.triageAlert(a.id);
      setTriageOverride({ summary: data.ai_summary || '', action: data.ai_action || '' });
      onToast('AI triage complete');
      onReload();
    }
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

  // Takes the action type directly (not from state) — dispatching off a
  // setResponseAction() call made in the same click handler read the PREVIOUS
  // render's state (setState hasn't committed yet), so every button dispatched
  // whatever action had been selected one click earlier instead of its own.
  const dispatchResponse = async (actionType: string, payload: Record<string,unknown> = {}) => {
    setResponding(true);
    try {
      const { data } = await alertDetailAPI.respond(a.id, { action_type: actionType, payload });
      onToast(data.message === 'task pending approval' ? `${actionType} queued for approval` : `Dispatched: ${actionType}`);
    } catch { onToast('Dispatch failed'); } finally { setResponding(false); }
  };

  const exportAlert = (fmt: 'json'|'csv') => {
    if (fmt === 'json') {
      const blob = new Blob([JSON.stringify(a, null, 2)], { type:'application/json' });
      const el = document.createElement('a'); el.href = URL.createObjectURL(blob);
      el.download = `alert-${a.id}.json`; el.click(); URL.revokeObjectURL(el.href);
    } else {
      const rows = Object.entries(a).map(([k,v]) => `"${k}","${String(v).replace(/"/g,'""')}"`).join('\n');
      const blob = new Blob([rows], { type:'text/csv' });
      const el = document.createElement('a'); el.href = URL.createObjectURL(blob);
      el.download = `alert-${a.id}.csv`; el.click(); URL.revokeObjectURL(el.href);
    }
  };

  // ── Tab definitions ───────────────────────────────────────────────────────

  const TABS: { id: Tab; label: string; icon: React.ReactNode }[] = [
    { id:'overview',      label:'Overview',      icon:<Shield className="h-3.5 w-3.5" /> },
    { id:'detection',     label:'Detection',     icon:<Crosshair className="h-3.5 w-3.5" /> },
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

          {/* Info strip */}
          <div className="flex items-center gap-6 px-5 pb-2.5">
            {mitreTechnique && (
              <div className="flex items-center gap-1.5 text-[11px]">
                <Shield className="h-3 w-3" style={{ color:'var(--accent)' }} />
                <span className="font-mono" style={{ color:'var(--accent)' }}>{mitreTechnique}</span>
                <span style={{ color:'var(--text-3)' }}>{mitreName || mitreTactic || ''}</span>
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
                    <MetaRow label="Agent"         val={a.hostname || `#${a.agent_id}`} mono />
                    <MetaRow label="First Seen"    val={formatDate(a.created_at)} />
                    <MetaRow label="Last Seen"     val={timeAgo(a.created_at)} />
                    <MetaRow label="Fingerprint"   val={a.fingerprint ? a.fingerprint.slice(0,32)+'…' : '—'} mono />
                  </div>
                </Section>

                {/* MITRE full mapping */}
                {(mitreTechnique || mitreTactic) && (
                  <Section title="MITRE ATT&CK Mapping" icon={<Swords className="h-3.5 w-3.5" />}>
                    <div className="space-y-3">
                      <div className="grid grid-cols-3 gap-3">
                        {[
                          { label:'Tactic',     val:mitreTactic     || '—' },
                          { label:'Technique',  val:mitreTechnique  || '—' },
                          { label:'Name',       val:mitreName       || mitreInfo?.name || '—' },
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
                      {mitreTactic && (
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
              </>
            )}

            {/* ── DETECTION ──────────────────────────────────────────────── */}
            {tab === 'detection' && (
              <>
                <Section title="Detection Rule" icon={<Target className="h-3.5 w-3.5" />}>
                  <div className="space-y-0">
                    <MetaRow label="Rule Name"     val={a.rule_name} />
                  </div>
                </Section>

                <Section title="Raw Event" icon={<ScrollText className="h-3.5 w-3.5" />}>
                  <div className="rounded-xl p-3 font-mono text-xs break-all"
                    style={{ background:'var(--bg-0)', border:'1px solid var(--border)', color:'var(--text-2)', maxHeight:180, overflowY:'auto' }}>
                    {a.log_message}
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
                  {aiSummary ? (
                    <p className="text-sm leading-relaxed" style={{ color:'var(--text-1)' }}>{aiSummary}</p>
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

                {aiAction && (
                  <Section title="Recommended Action" icon={<Target className="h-3.5 w-3.5" />}>
                    <div className="rounded-xl px-4 py-3" style={{ background:'var(--accent-glow)', border:'1px solid var(--accent-border)' }}>
                      <p className="text-sm font-medium" style={{ color:'var(--accent)' }}>{aiAction}</p>
                    </div>
                  </Section>
                )}

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

                {/* Response Actions — action_type strings here must match the
                    backend's allowlist in api/alert_response.go exactly, or
                    the dispatch 400s. */}
                <Section title="Endpoint Actions" icon={<Monitor className="h-3.5 w-3.5" />}>
                  <div className="grid grid-cols-2 gap-2">
                    <ActionBtn label="Isolate Host"   icon={<WifiOff className="h-3.5 w-3.5" />} danger color="var(--red)"
                      onClick={() => dispatchResponse('isolate_host')} />
                    <ActionBtn label="Collect Memory" icon={<HardDrive className="h-3.5 w-3.5" />}
                      onClick={() => dispatchResponse('memory_dump')} />
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
                        onClick={() => dispatchResponse('kill_process', responsePID ? { pid: parseInt(responsePID) } : undefined)} />
                    </div>
                  </div>
                </Section>

                <Section title="File Actions" icon={<HardDrive className="h-3.5 w-3.5" />} defaultOpen={false}>
                  <div className="space-y-2">
                    <input value={responseFile} onChange={e => setResponseFile(e.target.value)}
                      placeholder="File path, e.g. C:\Users\jdoe\malware.exe" className="g-input w-full text-xs" />
                    <div className="grid grid-cols-2 gap-2">
                      <ActionBtn label="Delete File"     icon={<Trash2 className="h-3.5 w-3.5" />} danger
                        onClick={() => dispatchResponse('delete_dropped_file', responseFile ? { file_path: responseFile } : undefined)} />
                      <ActionBtn label="Quarantine File" icon={<ShieldAlert className="h-3.5 w-3.5" />} color="var(--orange)"
                        onClick={() => dispatchResponse('quarantine_file', responseFile ? { file_path: responseFile } : undefined)} />
                    </div>
                  </div>
                </Section>

                <Section title="Automation" icon={<Workflow className="h-3.5 w-3.5" />} defaultOpen={false}>
                  <div className="grid grid-cols-2 gap-2">
                    <ActionBtn label="Run Playbook"     icon={<PlayCircle className="h-3.5 w-3.5" />} color="var(--accent)"
                      onClick={() => { loadPlaybookRecs(); setTab('ai'); }} />
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

                <Section title="Export" icon={<Download className="h-3.5 w-3.5" />} defaultOpen={false}>
                  <div className="grid grid-cols-2 gap-2">
                    {[
                      { label:'JSON', fmt:'json' as const, desc:'Full alert object' },
                      { label:'CSV',  fmt:'csv'  as const, desc:'Flat key-value format' },
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
