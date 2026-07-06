'use client';

import { useState, useEffect, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { casesAPI } from '@/lib/api';
import { Case, CaseComment, CaseEvidence, Alert } from '@/types';
import {
  Plus, X, ChevronDown, ChevronRight, MessageSquare, Paperclip,
  AlertCircle, Clock, CheckCircle2, Shield, Target, RefreshCw,
  User, Tag, FileText, Link2, Download,
} from 'lucide-react';

const PHASE_ORDER = ['identification','containment','eradication','recovery','lessons_learned','closed'];

// ─── Severity / Status / Phase helpers ───────────────────────────────────────
const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)', high: '#fb923c', medium: '#fbbf24', low: 'var(--accent)',
};
const SEV_BG: Record<string, string> = {
  critical: 'rgba(248,81,73,0.12)', high: 'rgba(251,146,60,0.12)',
  medium: 'rgba(251,191,36,0.10)', low: 'rgba(16,185,129,0.10)',
};
const STATUS_ICON: Record<string, React.ReactNode> = {
  open:         <AlertCircle className="h-3.5 w-3.5" />,
  investigating:<RefreshCw   className="h-3.5 w-3.5" />,
  contained:    <Shield      className="h-3.5 w-3.5" />,
  eradicated:   <Target      className="h-3.5 w-3.5" />,
  recovered:    <CheckCircle2 className="h-3.5 w-3.5" />,
  closed:       <CheckCircle2 className="h-3.5 w-3.5" />,
};
const PHASES = ['identification','containment','eradication','recovery','lessons_learned','closed'];
const STATUSES = ['open','investigating','contained','eradicated','recovered','closed'];
const SEVERITIES = ['critical','high','medium','low'];

function SLABadge({ c }: { c: Case }) {
  if (c.status === 'closed' || c.status === 'recovered') return null;
  if (c.sla_breached) return (
    <span className="text-[10px] px-1.5 py-0.5 rounded font-bold"
      style={{ background: 'rgba(248,81,73,0.2)', color: 'var(--red)' }}>SLA BREACH</span>
  );
  if (c.sla_breach_at) {
    const mins = Math.round((new Date(c.sla_breach_at).getTime() - Date.now()) / 60000);
    if (mins < 120) return (
      <span className="text-[10px] px-1.5 py-0.5 rounded font-bold"
        style={{ background: 'rgba(251,191,36,0.15)', color: '#fbbf24' }}>
        SLA {mins < 0 ? 'overdue' : `${mins}m`}
      </span>
    );
  }
  return null;
}

// ─── Case Detail Drawer ───────────────────────────────────────────────────────
function CaseDrawer({ caseID, onClose, onUpdated }: {
  caseID: number; onClose: () => void; onUpdated: () => void;
}) {
  const [tab, setTab] = useState<'overview'|'comments'|'evidence'|'alerts'>('overview');
  const [data, setData] = useState<{ case: Case; comments: CaseComment[]; evidence: CaseEvidence[]; alerts: Alert[] } | null>(null);
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState<Partial<Case>>({});
  const [commentBody, setCommentBody] = useState('');
  const [evidenceForm, setEvidenceForm] = useState({ title: '', evidence_type: 'note', description: '' });
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    const r = await casesAPI.getByID(caseID);
    setData(r.data);
    setForm(r.data.case);
  }, [caseID]);

  useEffect(() => { load(); }, [load]);

  if (!data) return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.6)' }}>
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

  const submitComment = async () => {
    if (!commentBody.trim()) return;
    await casesAPI.addComment(caseID, commentBody);
    setCommentBody('');
    load();
  };

  const submitEvidence = async () => {
    if (!evidenceForm.title.trim()) return;
    await casesAPI.addEvidence(caseID, evidenceForm);
    setEvidenceForm({ title: '', evidence_type: 'note', description: '' });
    load();
  };

  return (
    <div className="fixed inset-0 z-50 flex" onClick={onClose}>
      <div className="flex-1" />
      <div className="w-full max-w-2xl h-full overflow-y-auto shadow-2xl"
        style={{ background: 'var(--glass-modal)', borderLeft: '1px solid var(--border-md)', backdropFilter: 'var(--blur)' }}
        onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div className="sticky top-0 z-10 px-5 py-4 flex items-start justify-between"
          style={{ background: 'var(--glass-bg)', borderBottom: '1px solid var(--border)' }}>
          <div className="min-w-0 flex-1 pr-4">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <span className="text-[11px] px-2 py-0.5 rounded font-semibold"
                style={{ background: SEV_BG[c.severity], color: SEV_COLOR[c.severity] }}>
                {c.severity}
              </span>
              <span className="text-[11px] px-2 py-0.5 rounded flex items-center gap-1"
                style={{ background: 'var(--glass-bg-2)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>
                {STATUS_ICON[c.status]} {c.status}
              </span>
              <SLABadge c={c} />
            </div>
            <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{c.title}</p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-3)' }}>
              #{c.id} · Phase: {c.phase} · Assigned: {c.assigned_to_name || 'Unassigned'}
            </p>
          </div>
          <button onClick={onClose} style={{ color: 'var(--text-3)' }}><X className="h-5 w-5" /></button>
        </div>

        {/* Tabs */}
        <div className="flex border-b" style={{ borderColor: 'var(--border)' }}>
          {(['overview','comments','evidence','alerts'] as const).map(t => (
            <button key={t} onClick={() => setTab(t)}
              className="px-4 py-2.5 text-xs font-medium capitalize transition-colors"
              style={{
                color: tab === t ? 'var(--accent)' : 'var(--text-3)',
                borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent',
              }}>
              {t}{t === 'comments' && data.comments.length > 0 ? ` (${data.comments.length})` : ''}
              {t === 'evidence' && data.evidence.length > 0 ? ` (${data.evidence.length})` : ''}
              {t === 'alerts' && data.alerts.length > 0 ? ` (${data.alerts.length})` : ''}
            </button>
          ))}
        </div>

        <div className="p-5 space-y-4">
          {tab === 'overview' && (
            <>
              {editing ? (
                <div className="space-y-3">
                  <input className="g-input w-full" value={form.title||''} onChange={e=>setForm(f=>({...f,title:e.target.value}))} placeholder="Title" />
                  <textarea className="g-input w-full min-h-[80px]" value={form.description||''} onChange={e=>setForm(f=>({...f,description:e.target.value}))} placeholder="Description" />
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Severity</label>
                      <select className="g-select w-full" value={form.severity} onChange={e=>setForm(f=>({...f,severity:e.target.value as any}))}>
                        {SEVERITIES.map(s=><option key={s} value={s}>{s}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Status</label>
                      <select className="g-select w-full" value={form.status} onChange={e=>setForm(f=>({...f,status:e.target.value as any}))}>
                        {STATUSES.map(s=><option key={s} value={s}>{s}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Phase</label>
                      <select className="g-select w-full" value={form.phase} onChange={e=>setForm(f=>({...f,phase:e.target.value as any}))}>
                        {PHASES.map(p=><option key={p} value={p}>{p}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>MITRE Tactic</label>
                      <input className="g-input w-full" value={form.mitre_tactic||''} onChange={e=>setForm(f=>({...f,mitre_tactic:e.target.value}))} placeholder="e.g. Initial Access" />
                    </div>
                  </div>
                  <div>
                    <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Root Cause Analysis (RCA)</label>
                    <textarea className="g-input w-full min-h-[80px]" value={form.rca||''} onChange={e=>setForm(f=>({...f,rca:e.target.value}))} placeholder="Document root cause and lessons learned…" />
                  </div>
                  <div className="flex gap-2">
                    <button onClick={save} disabled={saving} className="g-btn g-btn-primary flex-1 justify-center">
                      {saving ? 'Saving…' : 'Save Changes'}
                    </button>
                    <button onClick={() => { setEditing(false); setForm(c); }} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
                  </div>
                </div>
              ) : (
                <>
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    {[
                      ['SLA', `${c.sla_hours}h`],
                      ['MITRE', c.mitre_tactic || '—'],
                      ['Technique', c.mitre_technique || '—'],
                      ['Opened', new Date(c.created_at).toLocaleString()],
                      ['Updated', new Date(c.updated_at).toLocaleString()],
                      c.closed_at ? ['Closed', new Date(c.closed_at).toLocaleString()] : null,
                    ].filter((x): x is [string, string] => x !== null).map(([k,v]) => (
                      <div key={k as string} className="rounded-lg p-3" style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}>
                        <p className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: 'var(--text-3)' }}>{k}</p>
                        <p className="font-medium truncate" style={{ color: 'var(--text-1)' }}>{v}</p>
                      </div>
                    ))}
                  </div>
                  {c.description && (
                    <div className="rounded-lg p-3" style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}>
                      <p className="text-xs font-semibold mb-1" style={{ color: 'var(--text-2)' }}>Description</p>
                      <p className="text-xs whitespace-pre-wrap" style={{ color: 'var(--text-1)' }}>{c.description}</p>
                    </div>
                  )}
                  {c.rca && (
                    <div className="rounded-lg p-3" style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}>
                      <p className="text-xs font-semibold mb-1" style={{ color: 'var(--accent)' }}>Root Cause Analysis</p>
                      <p className="text-xs whitespace-pre-wrap" style={{ color: 'var(--text-1)' }}>{c.rca}</p>
                    </div>
                  )}
                  <button onClick={() => setEditing(true)} className="g-btn g-btn-ghost w-full justify-center text-xs">
                    Edit Case
                  </button>
                </>
              )}
            </>
          )}

          {tab === 'comments' && (
            <div className="space-y-3">
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {data.comments.length === 0 && (
                  <p className="text-xs text-center py-6" style={{ color: 'var(--text-3)' }}>No comments yet.</p>
                )}
                {data.comments.map(cm => (
                  <div key={cm.id} className="rounded-lg p-3"
                    style={{
                      background: cm.is_system ? 'var(--glass-bg)' : 'var(--glass-bg-2)',
                      border: '1px solid var(--border)',
                      opacity: cm.is_system ? 0.75 : 1,
                    }}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[11px] font-semibold" style={{ color: cm.is_system ? 'var(--text-3)' : 'var(--accent)' }}>
                        {cm.is_system ? '⚙ system' : cm.username}
                      </span>
                      <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                        {new Date(cm.created_at).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-xs whitespace-pre-wrap" style={{ color: 'var(--text-1)' }}>{cm.body}</p>
                  </div>
                ))}
              </div>
              <div className="space-y-2">
                <textarea className="g-input w-full min-h-[72px]" value={commentBody}
                  onChange={e => setCommentBody(e.target.value)} placeholder="Add a comment…" />
                <button onClick={submitComment} disabled={!commentBody.trim()} className="g-btn g-btn-primary w-full justify-center">
                  Post Comment
                </button>
              </div>
            </div>
          )}

          {tab === 'evidence' && (
            <div className="space-y-3">
              <div className="space-y-2">
                {data.evidence.length === 0 && (
                  <p className="text-xs text-center py-6" style={{ color: 'var(--text-3)' }}>No evidence attached.</p>
                )}
                {data.evidence.map(e => (
                  <div key={e.id} className="rounded-lg p-3" style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-[10px] px-1.5 py-0.5 rounded uppercase" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>{e.evidence_type}</span>
                      <span className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{e.title}</span>
                    </div>
                    {e.description && <p className="text-xs" style={{ color: 'var(--text-2)' }}>{e.description}</p>}
                    <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                      {e.added_by_name} · {new Date(e.created_at).toLocaleString()}
                    </p>
                  </div>
                ))}
              </div>
              <div className="space-y-2 rounded-lg p-3" style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}>
                <p className="text-xs font-semibold" style={{ color: 'var(--text-2)' }}>Add Evidence</p>
                <select className="g-select w-full" value={evidenceForm.evidence_type}
                  onChange={e => setEvidenceForm(f => ({ ...f, evidence_type: e.target.value }))}>
                  {['note','log','file','screenshot','network_capture','artifact'].map(t =>
                    <option key={t} value={t}>{t}</option>
                  )}
                </select>
                <input className="g-input w-full" placeholder="Title" value={evidenceForm.title}
                  onChange={e => setEvidenceForm(f => ({ ...f, title: e.target.value }))} />
                <textarea className="g-input w-full" placeholder="Description" value={evidenceForm.description}
                  onChange={e => setEvidenceForm(f => ({ ...f, description: e.target.value }))} />
                <button onClick={submitEvidence} disabled={!evidenceForm.title.trim()} className="g-btn g-btn-primary w-full justify-center">
                  Attach Evidence
                </button>
              </div>
            </div>
          )}

          {tab === 'alerts' && (
            <div className="space-y-2">
              {data.alerts.length === 0 && (
                <p className="text-xs text-center py-6" style={{ color: 'var(--text-3)' }}>No alerts linked to this case.</p>
              )}
              {data.alerts.map(a => (
                <div key={a.id} className="rounded-lg p-3" style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[10px] px-1.5 py-0.5 rounded font-semibold"
                      style={{ background: SEV_BG[a.severity], color: SEV_COLOR[a.severity] }}>{a.severity}</span>
                    <span className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{a.rule_name}</span>
                  </div>
                  <p className="text-xs font-mono truncate" style={{ color: 'var(--text-2)' }}>{a.log_message}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Create Case Modal ────────────────────────────────────────────────────────
function CreateCaseModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({ title: '', description: '', severity: 'medium', mitre_tactic: '', mitre_technique: '' });
  const [saving, setSaving] = useState(false);

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
      <div className="g-modal" style={{ maxWidth: 520 }} onClick={e => e.stopPropagation()}>
        <div className="p-5" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Open New Case</h2>
        </div>
        <div className="p-5 space-y-3">
          <input className="g-input w-full" placeholder="Case title *" value={form.title}
            onChange={e => setForm(f => ({ ...f, title: e.target.value }))} />
          <textarea className="g-input w-full min-h-[72px]" placeholder="Description"
            value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
          <div className="grid grid-cols-3 gap-2">
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Severity</label>
              <select className="g-select w-full" value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}>
                {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>MITRE Tactic</label>
              <input className="g-input w-full" value={form.mitre_tactic}
                onChange={e => setForm(f => ({ ...f, mitre_tactic: e.target.value }))} placeholder="e.g. Execution" />
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Technique</label>
              <input className="g-input w-full" value={form.mitre_technique}
                onChange={e => setForm(f => ({ ...f, mitre_technique: e.target.value }))} placeholder="e.g. T1059" />
            </div>
          </div>
          <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
            SLA will be set automatically based on severity (Critical: 4h, High: 8h, Medium: 24h, Low: 72h).
          </p>
        </div>
        <div className="flex gap-3 px-5 pb-5">
          <button onClick={onClose} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
          <button onClick={submit} disabled={!form.title.trim() || saving} className="g-btn g-btn-primary flex-1 justify-center">
            {saving ? 'Creating…' : 'Open Case'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────
export default function CasesPage() {
  const [cases, setCases] = useState<Case[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('');
  const [sevFilter, setSevFilter] = useState('');
  const [selected, setSelected] = useState<number | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    const p: any = {};
    if (statusFilter) p.status = statusFilter;
    if (sevFilter) p.severity = sevFilter;
    try {
      const r = await casesAPI.getAll(p);
      setCases(r.data.cases || []);
      setTotal(r.data.total || 0);
    } finally { setLoading(false); }
  }, [statusFilter, sevFilter]);

  useEffect(() => { load(); }, [load]);

  const openCount = cases.filter(c => c.status !== 'closed' && c.status !== 'recovered').length;
  const criticalCount = cases.filter(c => c.severity === 'critical' && c.status !== 'closed').length;
  const breachedCount = cases.filter(c => c.sla_breached).length;

  const exportCSV = () => {
    const headers = ['ID','Title','Severity','Status','Phase','Assigned','SLA Breached','Alerts','Created'];
    const rows = cases.map(c => [
      c.id, c.title, c.severity, c.status, c.phase,
      c.assigned_to_name || '', c.sla_breached ? 'yes' : 'no',
      c.alert_count, c.created_at,
    ]);
    const csv = [headers, ...rows].map(r => r.map(v => `"${v}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'cases.csv'; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <RootLayout title="Case Management" subtitle="IR Lifecycle · SLA Tracking · Evidence Chain"
      actions={
        <div className="flex items-center gap-2">
          {cases.length > 0 && (
            <button onClick={exportCSV} className="g-btn g-btn-ghost text-xs">
              <Download className="h-3.5 w-3.5" /> Export CSV
            </button>
          )}
          <button onClick={() => setShowCreate(true)} className="g-btn g-btn-primary flex items-center gap-1.5 text-xs">
            <Plus className="h-3.5 w-3.5" /> Open Case
          </button>
        </div>
      }>

      {/* Stats bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
        {[
          { label: 'Total Cases', val: total, sub: 'all time' },
          { label: 'Open', val: openCount, sub: 'active cases', warn: openCount > 0 },
          { label: 'Critical Open', val: criticalCount, sub: 'need priority', warn: criticalCount > 0 },
          { label: 'SLA Breached', val: breachedCount, sub: 'overdue', warn: breachedCount > 0 },
        ].map(s => (
          <div key={s.label} className="g-card p-4">
            <p className="text-xl font-bold" style={{ color: s.warn ? 'var(--red)' : 'var(--text-1)' }}>{s.val}</p>
            <p className="text-xs font-medium" style={{ color: 'var(--text-2)' }}>{s.label}</p>
            <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{s.sub}</p>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="g-card p-3 mb-4 flex flex-wrap items-center gap-2">
        <select className="g-select text-xs py-1" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">All statuses</option>
          {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="g-select text-xs py-1" value={sevFilter} onChange={e => setSevFilter(e.target.value)}>
          <option value="">All severities</option>
          {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        {(statusFilter || sevFilter) && (
          <button onClick={() => { setStatusFilter(''); setSevFilter(''); }} className="text-xs" style={{ color: 'var(--text-3)' }}>
            <X className="h-3.5 w-3.5 inline mr-1" />Clear
          </button>
        )}
      </div>

      {/* Cases table */}
      <div className="g-card overflow-hidden">
        {loading ? (
          <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
        ) : cases.length === 0 ? (
          <div className="py-16 text-center">
            <Shield className="mx-auto h-10 w-10 mb-3 opacity-20" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No cases found</p>
            <button onClick={() => setShowCreate(true)} className="g-btn g-btn-primary mt-3 text-xs">
              Open First Case
            </button>
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
                {['#', 'Title', 'Severity', 'Status', 'Phase', 'Assigned', 'SLA', 'Alerts', 'Created'].map(h => (
                  <th key={h} className="px-4 py-2.5 text-left font-semibold" style={{ color: 'var(--text-3)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {cases.map(c => (
                <tr key={c.id}
                  className="cursor-pointer transition-colors hover:bg-[var(--glass-hover)]"
                  style={{ borderBottom: '1px solid var(--border)' }}
                  onClick={() => setSelected(c.id)}>
                  <td className="px-4 py-3 tabular-nums" style={{ color: 'var(--text-3)' }}>{c.id}</td>
                  <td className="px-4 py-3 max-w-[220px]">
                    <p className="font-medium truncate" style={{ color: 'var(--text-1)' }}>{c.title}</p>
                    {c.mitre_tactic && <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>{c.mitre_tactic}</p>}
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold"
                      style={{ background: SEV_BG[c.severity], color: SEV_COLOR[c.severity] }}>{c.severity}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="flex items-center gap-1" style={{ color: 'var(--text-2)' }}>
                      {STATUS_ICON[c.status]} {c.status}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <p className="text-[10px] capitalize mb-1" style={{ color: 'var(--text-2)' }}>{c.phase}</p>
                    <div className="flex gap-0.5">
                      {PHASE_ORDER.map((ph, i) => {
                        const done = PHASE_ORDER.indexOf(c.phase) >= i;
                        return <div key={ph} className="flex-1 h-1 rounded-sm" style={{ background: done ? 'var(--accent)' : 'var(--glass-bg-2)' }} />;
                      })}
                    </div>
                  </td>
                  <td className="px-4 py-3" style={{ color: 'var(--text-2)' }}>{c.assigned_to_name || '—'}</td>
                  <td className="px-4 py-3"><SLABadge c={c} /></td>
                  <td className="px-4 py-3 tabular-nums" style={{ color: 'var(--text-2)' }}>{c.alert_count}</td>
                  <td className="px-4 py-3 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>
                    {new Date(c.created_at).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {selected && <CaseDrawer caseID={selected} onClose={() => setSelected(null)} onUpdated={load} />}
      {showCreate && <CreateCaseModal onClose={() => setShowCreate(false)} onCreated={load} />}
    </RootLayout>
  );
}
