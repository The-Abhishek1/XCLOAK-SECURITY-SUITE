'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { casesAPI } from '@/lib/api';
import { useUser } from '@/context/UserContext';
import { Case, CaseComment, CaseEvidence, Alert } from '@/types';
import {
  Plus, X, MessageSquare, AlertCircle, Clock, CheckCircle2,
  Shield, Target, RefreshCw, FileText, Search,
  Download, ChevronUp, ChevronDown, ChevronsUpDown,
  FileImage, Network, Bug, StickyNote, UserCheck,
  Bell,
} from 'lucide-react';

// ── Constants ─────────────────────────────────────────────────────────────────

const PHASE_ORDER = ['identification','containment','eradication','recovery','lessons_learned','closed'] as const;
const STATUSES    = ['open','investigating','contained','eradicated','recovered','closed'] as const;
const SEVERITIES  = ['critical','high','medium','low'] as const;

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)', high: '#fb923c', medium: '#fbbf24', low: 'var(--accent)',
};
const SEV_BG: Record<string, string> = {
  critical: 'rgba(248,81,73,0.12)', high: 'rgba(251,146,60,0.12)',
  medium:   'rgba(251,191,36,0.10)', low: 'rgba(37,99,235,0.10)',
};
const STATUS_ICON: Record<string, React.ReactNode> = {
  open:          <AlertCircle  className="h-3 w-3" />,
  investigating: <RefreshCw    className="h-3 w-3" />,
  contained:     <Shield       className="h-3 w-3" />,
  eradicated:    <Target       className="h-3 w-3" />,
  recovered:     <CheckCircle2 className="h-3 w-3" />,
  closed:        <CheckCircle2 className="h-3 w-3" />,
};
const EVIDENCE_ICON: Record<string, React.ElementType> = {
  note:            StickyNote,
  log:             FileText,
  file:            FileText,
  screenshot:      FileImage,
  network_capture: Network,
  artifact:        Bug,
};

type SortKey = 'created_at' | 'severity' | 'status' | 'sla_breach_at';
type SortDir = 'asc' | 'desc';
const SEV_ORDER: Record<string, number> = { critical:0, high:1, medium:2, low:3 };
const STATUS_ORDER: Record<string, number> = { open:0, investigating:1, contained:2, eradicated:3, recovered:4, closed:5 };

// ── SLA helpers ───────────────────────────────────────────────────────────────

function useSLATick() {
  const [, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick(t => t + 1), 60_000);
    return () => clearInterval(id);
  }, []);
}

function slaLabel(c: Case): { text: string; color: string; bg: string } | null {
  if (c.status === 'closed' || c.status === 'recovered') return null;
  if (c.sla_breached) return { text: 'SLA BREACH', color: 'var(--red)', bg: 'rgba(248,81,73,0.15)' };
  if (c.sla_breach_at) {
    const mins = Math.round((new Date(c.sla_breach_at).getTime() - Date.now()) / 60_000);
    if (mins <= 0)   return { text: 'Overdue',    color: 'var(--red)',   bg: 'rgba(248,81,73,0.15)' };
    if (mins < 60)   return { text: `${mins}m`,   color: '#fbbf24',      bg: 'rgba(251,191,36,0.12)' };
    if (mins < 240)  return { text: `${Math.round(mins/60)}h ${mins%60}m`, color: '#fbbf24', bg: 'rgba(251,191,36,0.10)' };
  }
  return null;
}

function SLABadge({ c }: { c: Case }) {
  const s = slaLabel(c);
  if (!s) return null;
  return (
    <span className="text-[10px] px-1.5 py-0.5 rounded font-bold"
      style={{ background: s.bg, color: s.color }}>{s.text}</span>
  );
}

function PhaseBar({ phase }: { phase: string }) {
  const idx = PHASE_ORDER.indexOf(phase as any);
  return (
    <div className="flex gap-0.5">
      {PHASE_ORDER.map((ph, i) => (
        <div key={ph} className="flex-1 h-1 rounded-sm transition-colors"
          title={ph}
          style={{ background: i <= idx ? 'var(--accent)' : 'var(--glass-bg-2)' }} />
      ))}
    </div>
  );
}

// ── Case Drawer ───────────────────────────────────────────────────────────────

function CaseDrawer({ caseID, onClose, onUpdated }: {
  caseID: number; onClose: () => void; onUpdated: () => void;
}) {
  const { profile } = useUser();
  const [tab, setTab] = useState<'overview'|'comments'|'evidence'|'alerts'>('overview');
  const [data, setData] = useState<{ case: Case; comments: CaseComment[]; evidence: CaseEvidence[]; alerts: Alert[] } | null>(null);
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState<Partial<Case>>({});
  const [commentBody, setCommentBody] = useState('');
  const [evidenceForm, setEvidenceForm] = useState({ title:'', evidence_type:'note', description:'' });
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    const r = await casesAPI.getByID(caseID);
    setData(r.data);
    setForm(r.data.case);
  }, [caseID]);

  useEffect(() => { load(); }, [load]);

  // Escape to close
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  if (!data) return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.5)' }}>
      <div className="g-card p-8 text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
    </div>
  );

  const c = data.case;

  const save = async () => {
    setSaving(true);
    await casesAPI.update(caseID, form);
    setSaving(false);
    setEditing(false);
    load();
    onUpdated();
  };

  const assignToMe = async () => {
    if (!profile) return;
    await casesAPI.update(caseID, { ...c, assigned_to: profile.id });
    load();
    onUpdated();
  };

  const submitComment = async () => {
    if (!commentBody.trim()) return;
    await casesAPI.addComment(caseID, commentBody);
    setCommentBody('');
    load();
  };

  const submitEvidence = async () => {
    if (!evidenceForm.title.trim()) return;
    await casesAPI.addEvidence(caseID, evidenceForm);
    setEvidenceForm({ title:'', evidence_type:'note', description:'' });
    load();
  };

  const sla = slaLabel(c);

  return (
    <div className="fixed inset-0 z-50 flex" onClick={onClose}>
      <div className="flex-1" />
      <div className="w-full max-w-2xl h-full overflow-y-auto shadow-2xl"
        style={{ background: 'var(--glass-modal)', borderLeft: '1px solid var(--border-md)', backdropFilter: 'var(--blur)' }}
        onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div className="sticky top-0 z-10 px-5 py-4"
          style={{ background: 'var(--glass-bg)', borderBottom: '1px solid var(--border)' }}>
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 flex-wrap mb-1.5">
                <span className="text-[10px] px-2 py-0.5 rounded font-bold capitalize"
                  style={{ background: SEV_BG[c.severity], color: SEV_COLOR[c.severity] }}>
                  {c.severity}
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded flex items-center gap-1"
                  style={{ background: 'var(--glass-bg-2)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>
                  {STATUS_ICON[c.status]} {c.status}
                </span>
                {sla && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded font-bold flex items-center gap-1"
                    style={{ background: sla.bg, color: sla.color }}>
                    <Clock className="h-2.5 w-2.5" />{sla.text}
                  </span>
                )}
              </div>
              <p className="text-sm font-semibold leading-snug" style={{ color: 'var(--text-1)' }}>{c.title}</p>
              <p className="text-[11px] mt-0.5" style={{ color: 'var(--text-3)' }}>
                #{c.id} · {c.phase} · {c.assigned_to_name || 'Unassigned'}
              </p>
            </div>
            <div className="flex items-center gap-1.5 shrink-0">
              {profile && c.assigned_to !== profile.id && c.status !== 'closed' && (
                <button onClick={assignToMe} title="Assign to me"
                  className="g-btn g-btn-ghost text-[10px] py-1 px-2">
                  <UserCheck className="h-3 w-3 mr-1" />Assign me
                </button>
              )}
              <button onClick={onClose} style={{ color: 'var(--text-3)' }}><X className="h-5 w-5" /></button>
            </div>
          </div>
          {/* Phase stepper */}
          <div className="mt-3 flex items-center gap-1">
            {PHASE_ORDER.map((ph, i) => {
              const phIdx = PHASE_ORDER.indexOf(c.phase as any);
              const done = i < phIdx;
              const active = i === phIdx;
              return (
                <div key={ph} className="flex items-center gap-1 flex-1">
                  <div className="flex flex-col items-center flex-1">
                    <div className="w-full h-1 rounded-full"
                      style={{ background: done || active ? 'var(--accent)' : 'var(--glass-bg-2)' }} />
                    {active && (
                      <span className="text-[9px] mt-0.5 capitalize whitespace-nowrap" style={{ color: 'var(--accent)' }}>
                        {ph.replace('_', ' ')}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Tabs */}
        <div className="flex" style={{ borderBottom: '1px solid var(--border)' }}>
          {(['overview','comments','evidence','alerts'] as const).map(t => (
            <button key={t} onClick={() => setTab(t)}
              className="px-4 py-2.5 text-xs font-medium capitalize transition-colors"
              style={{
                color: tab === t ? 'var(--accent)' : 'var(--text-3)',
                borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent',
              }}>
              {t}
              {t === 'comments' && data.comments.length > 0 && ` (${data.comments.length})`}
              {t === 'evidence' && data.evidence.length > 0 && ` (${data.evidence.length})`}
              {t === 'alerts'   && data.alerts.length   > 0 && ` (${data.alerts.length})`}
            </button>
          ))}
        </div>

        <div className="p-5 space-y-4">

          {/* ── Overview ─────────────────────────────── */}
          {tab === 'overview' && (
            editing ? (
              <div className="space-y-3">
                <input className="g-input w-full" value={form.title||''} onChange={e=>setForm(f=>({...f,title:e.target.value}))} placeholder="Title" />
                <textarea className="g-input w-full min-h-[72px]" value={form.description||''} onChange={e=>setForm(f=>({...f,description:e.target.value}))} placeholder="Description" />
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[10px] uppercase mb-1" style={{ color: 'var(--text-3)' }}>Severity</label>
                    <select className="g-select w-full" value={form.severity} onChange={e=>setForm(f=>({...f,severity:e.target.value as any}))}>
                      {SEVERITIES.map(s=><option key={s} value={s}>{s}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] uppercase mb-1" style={{ color: 'var(--text-3)' }}>Status</label>
                    <select className="g-select w-full" value={form.status} onChange={e=>setForm(f=>({...f,status:e.target.value as any}))}>
                      {STATUSES.map(s=><option key={s} value={s}>{s}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] uppercase mb-1" style={{ color: 'var(--text-3)' }}>Phase</label>
                    <select className="g-select w-full" value={form.phase} onChange={e=>setForm(f=>({...f,phase:e.target.value as any}))}>
                      {PHASE_ORDER.map(p=><option key={p} value={p}>{p.replace('_',' ')}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] uppercase mb-1" style={{ color: 'var(--text-3)' }}>MITRE Tactic</label>
                    <input className="g-input w-full" value={form.mitre_tactic||''} onChange={e=>setForm(f=>({...f,mitre_tactic:e.target.value}))} placeholder="e.g. Initial Access" />
                  </div>
                  <div className="col-span-2">
                    <label className="block text-[10px] uppercase mb-1" style={{ color: 'var(--text-3)' }}>MITRE Technique</label>
                    <input className="g-input w-full" value={form.mitre_technique||''} onChange={e=>setForm(f=>({...f,mitre_technique:e.target.value}))} placeholder="e.g. T1059.001" />
                  </div>
                </div>
                <div>
                  <label className="block text-[10px] uppercase mb-1" style={{ color: 'var(--text-3)' }}>Root Cause Analysis</label>
                  <textarea className="g-input w-full min-h-[80px]" value={form.rca||''} onChange={e=>setForm(f=>({...f,rca:e.target.value}))} placeholder="Document root cause and lessons learned…" />
                </div>
                <div className="flex gap-2">
                  <button onClick={save} disabled={saving} className="g-btn g-btn-primary flex-1 justify-center">
                    {saving ? 'Saving…' : 'Save Changes'}
                  </button>
                  <button onClick={()=>{setEditing(false);setForm(c);}} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
                </div>
              </div>
            ) : (
              <>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  {([
                    ['SLA',       `${c.sla_hours}h`],
                    ['MITRE',     c.mitre_tactic    || '—'],
                    ['Technique', c.mitre_technique  || '—'],
                    ['Alerts',    String(c.alert_count)],
                    ['Opened',    new Date(c.created_at).toLocaleString()],
                    ['Updated',   new Date(c.updated_at).toLocaleString()],
                    c.closed_at ? ['Closed', new Date(c.closed_at).toLocaleString()] : null,
                  ] as ([string,string]|null)[]).filter((x): x is [string,string] => x !== null).map(([k,v]) => (
                    <div key={k} className="rounded-lg p-3" style={{ background:'var(--glass-bg-2)', border:'1px solid var(--border)' }}>
                      <p className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color:'var(--text-3)' }}>{k}</p>
                      <p className="font-medium truncate" style={{ color:'var(--text-1)' }}>{v}</p>
                    </div>
                  ))}
                </div>
                {c.description && (
                  <div className="rounded-lg p-3" style={{ background:'var(--glass-bg-2)', border:'1px solid var(--border)' }}>
                    <p className="text-[10px] uppercase tracking-wider mb-1 font-semibold" style={{ color:'var(--text-3)' }}>Description</p>
                    <p className="text-xs whitespace-pre-wrap leading-relaxed" style={{ color:'var(--text-1)' }}>{c.description}</p>
                  </div>
                )}
                {c.rca && (
                  <div className="rounded-lg p-3" style={{ background:'var(--accent-glow)', border:'1px solid var(--accent-border)' }}>
                    <p className="text-[10px] uppercase tracking-wider mb-1 font-semibold" style={{ color:'var(--accent)' }}>Root Cause Analysis</p>
                    <p className="text-xs whitespace-pre-wrap leading-relaxed" style={{ color:'var(--text-1)' }}>{c.rca}</p>
                  </div>
                )}
                <button onClick={()=>setEditing(true)} className="g-btn g-btn-ghost w-full justify-center text-xs">
                  Edit Case
                </button>
              </>
            )
          )}

          {/* ── Comments ────────────────────────────── */}
          {tab === 'comments' && (
            <div className="space-y-3">
              <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                {data.comments.length === 0 && (
                  <p className="text-xs text-center py-6" style={{ color:'var(--text-3)' }}>No comments yet.</p>
                )}
                {data.comments.map(cm => (
                  <div key={cm.id} className="rounded-lg p-3"
                    style={{
                      background: cm.is_system ? 'var(--glass-bg)' : 'var(--glass-bg-2)',
                      border:'1px solid var(--border)',
                      opacity: cm.is_system ? 0.7 : 1,
                    }}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[11px] font-semibold"
                        style={{ color: cm.is_system ? 'var(--text-3)' : 'var(--accent)' }}>
                        {cm.is_system ? '⚙ system' : cm.username}
                      </span>
                      <span className="text-[10px]" style={{ color:'var(--text-3)' }}>
                        {new Date(cm.created_at).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-xs whitespace-pre-wrap leading-relaxed" style={{ color:'var(--text-1)' }}>{cm.body}</p>
                  </div>
                ))}
              </div>
              <div className="space-y-2">
                <textarea className="g-input w-full min-h-[64px] text-xs"
                  value={commentBody} onChange={e=>setCommentBody(e.target.value)}
                  placeholder="Add a comment…" />
                <button onClick={submitComment} disabled={!commentBody.trim()} className="g-btn g-btn-primary w-full justify-center text-xs">
                  <MessageSquare className="h-3.5 w-3.5" /> Post Comment
                </button>
              </div>
            </div>
          )}

          {/* ── Evidence ────────────────────────────── */}
          {tab === 'evidence' && (
            <div className="space-y-3">
              <div className="space-y-2">
                {data.evidence.length === 0 && (
                  <p className="text-xs text-center py-6" style={{ color:'var(--text-3)' }}>No evidence attached.</p>
                )}
                {data.evidence.map(e => {
                  const Icon = EVIDENCE_ICON[e.evidence_type] ?? FileText;
                  return (
                    <div key={e.id} className="rounded-lg p-3 flex gap-3"
                      style={{ background:'var(--glass-bg-2)', border:'1px solid var(--border)' }}>
                      <div className="shrink-0 mt-0.5 flex items-center justify-center w-7 h-7 rounded"
                        style={{ background:'var(--accent-glow)' }}>
                        <Icon className="w-3.5 h-3.5" style={{ color:'var(--accent)' }} />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 mb-0.5">
                          <span className="text-[10px] px-1.5 py-0.5 rounded uppercase font-semibold"
                            style={{ background:'var(--glass-bg)', color:'var(--text-2)', border:'1px solid var(--border)' }}>
                            {e.evidence_type}
                          </span>
                          <span className="text-xs font-medium truncate" style={{ color:'var(--text-1)' }}>{e.title}</span>
                        </div>
                        {e.description && <p className="text-xs" style={{ color:'var(--text-2)' }}>{e.description}</p>}
                        <p className="text-[10px] mt-1" style={{ color:'var(--text-3)' }}>
                          {e.added_by_name} · {new Date(e.created_at).toLocaleString()}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>
              <div className="space-y-2 rounded-lg p-3" style={{ background:'var(--glass-bg-2)', border:'1px solid var(--border)' }}>
                <p className="text-xs font-semibold" style={{ color:'var(--text-2)' }}>Attach Evidence</p>
                <select className="g-select w-full text-xs" value={evidenceForm.evidence_type}
                  onChange={e=>setEvidenceForm(f=>({...f,evidence_type:e.target.value}))}>
                  {['note','log','file','screenshot','network_capture','artifact'].map(t=>
                    <option key={t} value={t}>{t.replace('_',' ')}</option>
                  )}
                </select>
                <input className="g-input w-full text-xs" placeholder="Title *" value={evidenceForm.title}
                  onChange={e=>setEvidenceForm(f=>({...f,title:e.target.value}))} />
                <textarea className="g-input w-full text-xs" placeholder="Description" value={evidenceForm.description}
                  onChange={e=>setEvidenceForm(f=>({...f,description:e.target.value}))} />
                <button onClick={submitEvidence} disabled={!evidenceForm.title.trim()}
                  className="g-btn g-btn-primary w-full justify-center text-xs">
                  Attach
                </button>
              </div>
            </div>
          )}

          {/* ── Linked Alerts ────────────────────────── */}
          {tab === 'alerts' && (
            <div className="space-y-2">
              {data.alerts.length === 0 && (
                <p className="text-xs text-center py-6" style={{ color:'var(--text-3)' }}>No alerts linked to this case.</p>
              )}
              {data.alerts.map(a => (
                <div key={a.id} className="rounded-lg p-3"
                  style={{ background:'var(--glass-bg-2)', border:'1px solid var(--border)' }}>
                  <div className="flex items-center gap-2 mb-1">
                    <Bell className="h-3 w-3" style={{ color: SEV_COLOR[a.severity] }} />
                    <span className="text-[10px] px-1.5 py-0.5 rounded font-bold capitalize"
                      style={{ background:SEV_BG[a.severity], color:SEV_COLOR[a.severity] }}>
                      {a.severity}
                    </span>
                    <span className="text-xs font-medium" style={{ color:'var(--text-1)' }}>{a.rule_name}</span>
                  </div>
                  <p className="text-[11px] font-mono truncate" style={{ color:'var(--text-2)' }}>{a.log_message}</p>
                </div>
              ))}
            </div>
          )}

        </div>
      </div>
    </div>
  );
}

// ── Create Modal ──────────────────────────────────────────────────────────────

function CreateCaseModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({ title:'', description:'', severity:'medium', mitre_tactic:'', mitre_technique:'' });
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [onClose]);

  const SLA_HOURS: Record<string,number> = { critical:4, high:8, medium:24, low:72 };

  const submit = async () => {
    if (!form.title.trim()) return;
    setSaving(true);
    await casesAPI.create(form);
    setSaving(false);
    onCreated();
    onClose();
  };

  return (
    <div className="g-modal-backdrop" onClick={onClose}>
      <div className="g-modal" style={{ maxWidth:520 }} onClick={e=>e.stopPropagation()}>
        <div className="p-5" style={{ borderBottom:'1px solid var(--border)' }}>
          <h2 className="text-sm font-semibold" style={{ color:'var(--text-1)' }}>Open New Case</h2>
        </div>
        <div className="p-5 space-y-3">
          <input className="g-input w-full" placeholder="Case title *" value={form.title}
            onChange={e=>setForm(f=>({...f,title:e.target.value}))} autoFocus />
          <textarea className="g-input w-full min-h-[64px]" placeholder="Description (optional)"
            value={form.description} onChange={e=>setForm(f=>({...f,description:e.target.value}))} />
          <div className="grid grid-cols-3 gap-2">
            <div>
              <label className="block text-[10px] uppercase mb-1" style={{ color:'var(--text-3)' }}>Severity</label>
              <select className="g-select w-full text-xs" value={form.severity}
                onChange={e=>setForm(f=>({...f,severity:e.target.value}))}>
                {SEVERITIES.map(s=><option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-[10px] uppercase mb-1" style={{ color:'var(--text-3)' }}>MITRE Tactic</label>
              <input className="g-input w-full text-xs" value={form.mitre_tactic}
                onChange={e=>setForm(f=>({...f,mitre_tactic:e.target.value}))} placeholder="e.g. Execution" />
            </div>
            <div>
              <label className="block text-[10px] uppercase mb-1" style={{ color:'var(--text-3)' }}>Technique</label>
              <input className="g-input w-full text-xs" value={form.mitre_technique}
                onChange={e=>setForm(f=>({...f,mitre_technique:e.target.value}))} placeholder="e.g. T1059" />
            </div>
          </div>
          {form.severity && (
            <p className="text-[11px]" style={{ color:'var(--text-3)' }}>
              SLA: <strong style={{ color:'var(--text-2)' }}>{SLA_HOURS[form.severity]}h</strong> for {form.severity} severity
            </p>
          )}
        </div>
        <div className="flex gap-3 px-5 pb-5">
          <button onClick={onClose} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
          <button onClick={submit} disabled={!form.title.trim()||saving} className="g-btn g-btn-primary flex-1 justify-center">
            {saving ? 'Creating…' : 'Open Case'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Sort header button ────────────────────────────────────────────────────────

function SortTh({ label, sortKey, current, dir, onSort }: {
  label: string; sortKey: SortKey; current: SortKey; dir: SortDir;
  onSort: (k: SortKey) => void;
}) {
  const active = current === sortKey;
  return (
    <th className="px-4 py-2.5 text-left font-semibold cursor-pointer select-none group"
      style={{ color: active ? 'var(--accent)' : 'var(--text-3)' }}
      onClick={() => onSort(sortKey)}>
      <span className="flex items-center gap-1">
        {label}
        {active
          ? dir === 'asc' ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />
          : <ChevronsUpDown className="h-3 w-3 opacity-30 group-hover:opacity-70" />
        }
      </span>
    </th>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function CasesPage() {
  useSLATick();
  const [cases, setCases]           = useState<Case[]>([]);
  const [total, setTotal]           = useState(0);
  const [loading, setLoading]       = useState(true);
  const [statusFilter, setStatusFilter] = useState('');
  const [sevFilter, setSevFilter]   = useState('');
  const [search, setSearch]         = useState('');
  const [sortKey, setSortKey]       = useState<SortKey>('created_at');
  const [sortDir, setSortDir]       = useState<SortDir>('desc');
  const [selected, setSelected]     = useState<number | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    const p: Record<string,string> = {};
    if (statusFilter) p.status   = statusFilter;
    if (sevFilter)    p.severity = sevFilter;
    try {
      const r = await casesAPI.getAll(p);
      setCases(r.data.cases || []);
      setTotal(r.data.total || 0);
    } finally { setLoading(false); }
  }, [statusFilter, sevFilter]);

  useEffect(() => { load(); }, [load]);

  const onSort = (k: SortKey) => {
    if (k === sortKey) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortKey(k); setSortDir('desc'); }
  };

  const filtered = cases
    .filter(c => {
      if (!search) return true;
      const q = search.toLowerCase();
      return c.title.toLowerCase().includes(q) ||
        (c.description || '').toLowerCase().includes(q) ||
        (c.mitre_tactic || '').toLowerCase().includes(q) ||
        (c.assigned_to_name || '').toLowerCase().includes(q);
    })
    .sort((a, b) => {
      let cmp = 0;
      if (sortKey === 'severity')     cmp = SEV_ORDER[a.severity]  - SEV_ORDER[b.severity];
      else if (sortKey === 'status')  cmp = STATUS_ORDER[a.status] - STATUS_ORDER[b.status];
      else if (sortKey === 'sla_breach_at') {
        const aT = a.sla_breach_at ? new Date(a.sla_breach_at).getTime() : Infinity;
        const bT = b.sla_breach_at ? new Date(b.sla_breach_at).getTime() : Infinity;
        cmp = aT - bT;
      } else {
        cmp = new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });

  const openCount     = cases.filter(c => c.status !== 'closed' && c.status !== 'recovered').length;
  const critCount     = cases.filter(c => c.severity === 'critical' && c.status !== 'closed').length;
  const breachedCount = cases.filter(c => c.sla_breached).length;

  // MTTR: avg hours from open→close for closed cases
  const closedCases = cases.filter(c => c.closed_at);
  const mttrHours = closedCases.length === 0 ? null :
    Math.round(closedCases.reduce((sum, c) => {
      return sum + (new Date(c.closed_at!).getTime() - new Date(c.created_at).getTime()) / 3_600_000;
    }, 0) / closedCases.length);

  const exportCSV = () => {
    const headers = ['ID','Title','Severity','Status','Phase','Assigned','SLA Breached','Alerts','Created'];
    const rows = cases.map(c => [
      c.id, `"${c.title.replace(/"/g,'""')}"`, c.severity, c.status, c.phase,
      c.assigned_to_name || '', c.sla_breached ? 'yes' : 'no', c.alert_count, c.created_at,
    ]);
    const csv = [headers.join(','), ...rows.map(r=>r.join(','))].join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type:'text/csv' }));
    a.download = 'cases.csv';
    a.click();
  };

  return (
    <RootLayout
      title="Case Management"
      subtitle={`${total} total · ${openCount} open`}
      actions={
        <div className="flex items-center gap-2">
          {cases.length > 0 && (
            <button onClick={exportCSV} className="g-btn g-btn-ghost text-xs">
              <Download className="h-3.5 w-3.5" /> Export
            </button>
          )}
          <button onClick={() => setShowCreate(true)} className="g-btn g-btn-primary text-xs">
            <Plus className="h-3.5 w-3.5" /> Open Case
          </button>
        </div>
      }>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-4">
        {[
          { label: 'Total Cases',   val: total,        color: 'var(--text-1)', sub: 'all time' },
          { label: 'Open',          val: openCount,    color: openCount     ? 'var(--red)' : 'var(--text-1)', sub: 'active' },
          { label: 'Critical Open', val: critCount,    color: critCount     ? 'var(--red)' : 'var(--text-1)', sub: 'priority' },
          { label: 'SLA Breached',  val: breachedCount,color: breachedCount ? 'var(--red)' : 'var(--text-1)', sub: 'overdue' },
          { label: 'MTTR',          val: mttrHours != null ? `${mttrHours}h` : '—', color: 'var(--accent)', sub: `${closedCases.length} closed` },
        ].map(s => (
          <div key={s.label} className="g-card p-4">
            <p className="text-[10px] uppercase tracking-wider font-medium mb-1" style={{ color:'var(--text-3)' }}>{s.label}</p>
            <p className="text-xl font-bold" style={{ color: s.color }}>{s.val}</p>
            <p className="text-[10px]" style={{ color:'var(--text-3)' }}>{s.sub}</p>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="g-card p-3 mb-4 flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-40">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color:'var(--text-3)' }} />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search title, description, assignee…"
            className="g-input pl-8 py-1.5 text-xs w-full"
          />
        </div>
        <select className="g-select text-xs py-1" value={statusFilter} onChange={e=>setStatusFilter(e.target.value)}>
          <option value="">All statuses</option>
          {STATUSES.map(s=><option key={s} value={s}>{s}</option>)}
        </select>
        <select className="g-select text-xs py-1" value={sevFilter} onChange={e=>setSevFilter(e.target.value)}>
          <option value="">All severities</option>
          {SEVERITIES.map(s=><option key={s} value={s}>{s}</option>)}
        </select>
        {(statusFilter || sevFilter || search) && (
          <button onClick={()=>{setStatusFilter('');setSevFilter('');setSearch('');}}
            className="text-xs" style={{ color:'var(--text-3)' }}>
            <X className="h-3.5 w-3.5 inline mr-1" />Clear
          </button>
        )}
        <span className="text-xs ml-auto" style={{ color:'var(--text-3)' }}>{filtered.length} cases</span>
      </div>

      {/* Table */}
      <div className="g-card overflow-hidden">
        {loading ? (
          <div className="py-16 text-center text-sm animate-pulse" style={{ color:'var(--text-3)' }}>Loading…</div>
        ) : filtered.length === 0 ? (
          <div className="py-16 text-center">
            <Shield className="mx-auto h-10 w-10 mb-3 opacity-20" style={{ color:'var(--text-3)' }} />
            <p className="text-sm" style={{ color:'var(--text-2)' }}>No cases found</p>
            {!statusFilter && !sevFilter && !search && (
              <button onClick={()=>setShowCreate(true)} className="g-btn g-btn-primary mt-3 text-xs">
                Open First Case
              </button>
            )}
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr style={{ borderBottom:'1px solid var(--border)', background:'var(--glass-bg)' }}>
                <th className="px-4 py-2.5 text-left font-semibold" style={{ color:'var(--text-3)' }}>#</th>
                <th className="px-4 py-2.5 text-left font-semibold" style={{ color:'var(--text-3)' }}>Title</th>
                <SortTh label="Severity" sortKey="severity"    current={sortKey} dir={sortDir} onSort={onSort} />
                <SortTh label="Status"   sortKey="status"      current={sortKey} dir={sortDir} onSort={onSort} />
                <th className="px-4 py-2.5 text-left font-semibold" style={{ color:'var(--text-3)' }}>Phase</th>
                <th className="px-4 py-2.5 text-left font-semibold" style={{ color:'var(--text-3)' }}>Assigned</th>
                <SortTh label="SLA"     sortKey="sla_breach_at" current={sortKey} dir={sortDir} onSort={onSort} />
                <th className="px-4 py-2.5 text-left font-semibold" style={{ color:'var(--text-3)' }}>Alerts</th>
                <SortTh label="Created"  sortKey="created_at"  current={sortKey} dir={sortDir} onSort={onSort} />
              </tr>
            </thead>
            <tbody>
              {filtered.map(c => (
                <tr key={c.id}
                  className="cursor-pointer transition-colors hover:bg-[var(--glass-hover)]"
                  style={{ borderBottom:'1px solid var(--border)' }}
                  onClick={() => setSelected(c.id)}>
                  <td className="px-4 py-3 tabular-nums" style={{ color:'var(--text-3)' }}>{c.id}</td>
                  <td className="px-4 py-3 max-w-[200px]">
                    <p className="font-medium truncate" style={{ color:'var(--text-1)' }}>{c.title}</p>
                    {c.mitre_tactic && (
                      <p className="text-[10px] truncate" style={{ color:'var(--text-3)' }}>{c.mitre_tactic}</p>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold capitalize"
                      style={{ background:SEV_BG[c.severity], color:SEV_COLOR[c.severity] }}>
                      {c.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="flex items-center gap-1 capitalize" style={{ color:'var(--text-2)' }}>
                      {STATUS_ICON[c.status]} {c.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 min-w-[120px]">
                    <p className="text-[10px] capitalize mb-1" style={{ color:'var(--text-2)' }}>
                      {c.phase.replace('_',' ')}
                    </p>
                    <PhaseBar phase={c.phase} />
                  </td>
                  <td className="px-4 py-3" style={{ color:'var(--text-2)' }}>
                    {c.assigned_to_name || <span style={{ color:'var(--text-3)' }}>—</span>}
                  </td>
                  <td className="px-4 py-3"><SLABadge c={c} /></td>
                  <td className="px-4 py-3 tabular-nums" style={{ color:'var(--text-2)' }}>{c.alert_count}</td>
                  <td className="px-4 py-3 whitespace-nowrap" style={{ color:'var(--text-3)' }}>
                    {new Date(c.created_at).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {selected && <CaseDrawer caseID={selected} onClose={()=>setSelected(null)} onUpdated={load} />}
      {showCreate && <CreateCaseModal onClose={()=>setShowCreate(false)} onCreated={load} />}
    </RootLayout>
  );
}
