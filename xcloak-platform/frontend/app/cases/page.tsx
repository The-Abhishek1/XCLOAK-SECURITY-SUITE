'use client';
import { useState, useEffect, useRef, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { casesAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';

type Tab = 'overview' | 'cases' | 'tasks' | 'evidence' | 'notebook' | 'timeline' | 'analytics' | 'response';

const TAB_LABELS: Record<Tab, string> = {
  overview:  'Dashboard',
  cases:     'Cases',
  tasks:     'Tasks',
  evidence:  'Evidence',
  notebook:  'Notebook',
  timeline:  'Timeline',
  analytics: 'Analytics',
  response:  'Response & AI',
};

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
};
const STATUS_COLOR: Record<string, string> = {
  open: '#3b82f6', in_progress: '#f97316', waiting_approval: '#a855f7',
  escalated: '#ef4444', closed: '#22c55e',
};
const STATUS_LABEL: Record<string, string> = {
  open: 'Open', in_progress: 'In Progress', waiting_approval: 'Awaiting Approval',
  escalated: 'Escalated', closed: 'Closed',
};
const TASK_STATUS_COLOR: Record<string, string> = {
  pending: '#6b7280', in_progress: '#f97316', done: '#22c55e', blocked: '#ef4444',
};
const EV_TYPE_ICON: Record<string, string> = {
  memory_dump: '💾', log: '📋', pcap: '🌐', file: '📄',
  registry: '🗝', screenshot: '🖼', timeline: '📅',
};
const TL_TYPE_COLOR: Record<string, string> = {
  case_created: '#3b82f6', assigned: '#6366f1', evidence_added: '#22c55e',
  ioc_found: '#ef4444', response_action: '#f97316', escalated: '#ef4444',
  approval_requested: '#a855f7', comment: '#6b7280', task_completed: '#22c55e',
};

// ── Overview ──────────────────────────────────────────────────────────────────
function OverviewTab({ dash }: { dash: any }) {
  if (!dash) return <div style={{ color: 'var(--text-3)', padding: '2rem' }}>Loading…</div>;
  const cards = [
    { label: 'Open',              value: dash.open,             color: '#3b82f6' },
    { label: 'In Progress',       value: dash.in_progress,      color: '#f97316' },
    { label: 'Awaiting Approval', value: dash.waiting_approval, color: '#a855f7' },
    { label: 'Escalated',         value: dash.escalated,        color: '#ef4444' },
    { label: 'Closed',            value: dash.closed,           color: '#22c55e' },
    { label: 'SLA Breach',        value: dash.sla_breach,       color: '#ef4444' },
    { label: 'SLA Warning',       value: dash.sla_warning,      color: '#eab308' },
    { label: 'Avg Resolution',    value: `${dash.avg_resolution_h}h`, color: '#6366f1' },
  ];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(155px,1fr))', gap: '1rem' }}>
        {cards.map(c => (
          <div key={c.label} className="g-card" style={{ padding: '1.25rem', borderTop: `3px solid ${c.color}` }}>
            <div style={{ fontSize: '2rem', fontWeight: 700, color: c.color }}>{c.value}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-3)', marginTop: '0.25rem' }}>{c.label}</div>
          </div>
        ))}
      </div>
      <div className="g-card" style={{ padding: '1.25rem' }}>
        <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Analyst Workload</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
          {(dash.analyst_workload || []).map((a: any) => (
            <div key={a.analyst} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <span style={{ minWidth: '90px', fontSize: '0.85rem', fontFamily: 'monospace' }}>{a.analyst}</span>
              <div style={{ display: 'flex', gap: '4px', flex: 1 }}>
                {a.open > 0 && <div style={{ width: `${a.open * 24}px`, height: '20px', background: '#3b82f6', borderRadius: '3px', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.7rem', color: '#fff', fontWeight: 600 }}>{a.open}</div>}
                {a.in_progress > 0 && <div style={{ width: `${a.in_progress * 24}px`, height: '20px', background: '#f97316', borderRadius: '3px', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.7rem', color: '#fff', fontWeight: 600 }}>{a.in_progress}</div>}
                {a.closed > 0 && <div style={{ width: `${Math.min(a.closed * 12, 120)}px`, height: '20px', background: 'rgba(34,197,94,0.3)', borderRadius: '3px', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.7rem', color: '#22c55e', fontWeight: 600 }}>{a.closed}</div>}
              </div>
              <div style={{ display: 'flex', gap: '0.5rem', fontSize: '0.72rem', color: 'var(--text-3)' }}>
                <span style={{ color: '#3b82f6' }}>{a.open} open</span>
                <span style={{ color: '#f97316' }}>{a.in_progress} active</span>
                <span style={{ color: '#22c55e' }}>{a.closed} closed</span>
              </div>
            </div>
          ))}
        </div>
        <div style={{ display: 'flex', gap: '1rem', marginTop: '0.75rem', fontSize: '0.72rem', color: 'var(--text-3)' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><span style={{ width: '10px', height: '10px', background: '#3b82f6', borderRadius: '2px', display: 'inline-block' }} /> Open</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><span style={{ width: '10px', height: '10px', background: '#f97316', borderRadius: '2px', display: 'inline-block' }} /> In Progress</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><span style={{ width: '10px', height: '10px', background: '#22c55e', borderRadius: '2px', display: 'inline-block' }} /> Closed</span>
        </div>
      </div>
    </div>
  );
}

// ── Cases List ─────────────────────────────────────────────────────────────────
function CasesTab({ selectedId, onSelect, onRefresh }: { selectedId: number | null; onSelect: (c: any) => void; onRefresh: () => void }) {
  const [cases, setCases] = useState<any[]>([]);
  const [templates, setTemplates] = useState<any[]>([]);
  const [filter, setFilter] = useState('');
  const [sevFilter, setSevFilter] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [showTemplates, setShowTemplates] = useState(false);
  const [form, setForm] = useState({ title: '', description: '', severity: 'high', priority: 'high', owner: '', team: '', tags: '', template: '' });
  const [creating, setCreating] = useState(false);

  const load = useCallback(() => {
    const params: any = {};
    if (filter) params.status = filter;
    if (sevFilter) params.severity = sevFilter;
    casesAPI.getCases(params).then(r => setCases(r.data || []));
  }, [filter, sevFilter]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { casesAPI.getTemplates().then(r => setTemplates(r.data || [])); }, []);

  const create = async () => {
    if (!form.title) return;
    setCreating(true);
    const r = await casesAPI.createCase(form);
    if (r.data?.ok) { setShowCreate(false); setForm({ title: '', description: '', severity: 'high', priority: 'high', owner: '', team: '', tags: '', template: '' }); load(); onRefresh(); }
    setCreating(false);
  };

  const applyTemplate = (t: any) => {
    setForm(f => ({ ...f, title: t.name, description: t.description, template: t.id }));
    setShowTemplates(false);
    setShowCreate(true);
  };

  const STATUSES = ['', 'open', 'in_progress', 'waiting_approval', 'escalated', 'closed'];
  const SEVS = ['', 'critical', 'high', 'medium', 'low'];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
        <select className="g-select" value={filter} onChange={e => setFilter(e.target.value)} style={{ fontSize: '0.82rem' }}>
          {STATUSES.map(s => <option key={s} value={s}>{s ? STATUS_LABEL[s] : 'All Statuses'}</option>)}
        </select>
        <select className="g-select" value={sevFilter} onChange={e => setSevFilter(e.target.value)} style={{ fontSize: '0.82rem' }}>
          {SEVS.map(s => <option key={s} value={s}>{s ? s.charAt(0).toUpperCase() + s.slice(1) : 'All Severities'}</option>)}
        </select>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: '0.5rem' }}>
          <button className="g-btn g-btn-ghost" onClick={() => setShowTemplates(!showTemplates)}>Templates</button>
          <button className="g-btn g-btn-primary" onClick={() => setShowCreate(!showCreate)}>+ New Case</button>
        </div>
      </div>

      {showTemplates && (
        <div className="g-card" style={{ padding: '1.25rem' }}>
          <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Case Templates</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(220px,1fr))', gap: '0.75rem' }}>
            {templates.map((t: any) => (
              <div key={t.id} className="g-card" style={{ padding: '0.85rem', cursor: 'pointer', border: '1px solid var(--border)' }} onClick={() => applyTemplate(t)}>
                <div style={{ fontSize: '1.2rem', marginBottom: '0.25rem' }}>{t.icon} <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>{t.name}</span></div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-3)', marginBottom: '0.5rem' }}>{t.description}</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                  {t.tasks?.slice(0, 3).map((task: string) => (
                    <span key={task} style={{ fontSize: '0.68rem', color: 'var(--text-3)', background: 'rgba(255,255,255,0.06)', padding: '1px 5px', borderRadius: '3px' }}>✓ {task}</span>
                  ))}
                  {t.tasks?.length > 3 && <span style={{ fontSize: '0.68rem', color: 'var(--text-3)' }}>+{t.tasks.length - 3} more</span>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {showCreate && (
        <div className="g-card" style={{ padding: '1.25rem', border: '1px solid rgba(99,102,241,0.3)' }}>
          <div style={{ fontWeight: 600, marginBottom: '1rem', color: 'var(--accent)' }}>New Case</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginBottom: '0.75rem' }}>
            <div style={{ gridColumn: '1/-1' }}>
              <input className="g-input" style={{ width: '100%' }} placeholder="Case title *" value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))} />
            </div>
            <div style={{ gridColumn: '1/-1' }}>
              <textarea className="g-input" style={{ width: '100%', height: '60px', resize: 'vertical' }} placeholder="Description" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
            </div>
            <select className="g-select" value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}>
              {['critical','high','medium','low'].map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase()+s.slice(1)}</option>)}
            </select>
            <select className="g-select" value={form.priority} onChange={e => setForm(f => ({ ...f, priority: e.target.value }))}>
              {['critical','high','medium','low'].map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase()+s.slice(1)}</option>)}
            </select>
            <input className="g-input" placeholder="Owner" value={form.owner} onChange={e => setForm(f => ({ ...f, owner: e.target.value }))} />
            <input className="g-input" placeholder="Team" value={form.team} onChange={e => setForm(f => ({ ...f, team: e.target.value }))} />
            <div style={{ gridColumn: '1/-1' }}>
              <input className="g-input" style={{ width: '100%' }} placeholder="Tags (comma-separated)" value={form.tags} onChange={e => setForm(f => ({ ...f, tags: e.target.value }))} />
            </div>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button className="g-btn g-btn-primary" onClick={create} disabled={creating || !form.title}>{creating ? 'Creating…' : 'Create Case'}</button>
            <button className="g-btn g-btn-ghost" onClick={() => setShowCreate(false)}>Cancel</button>
          </div>
        </div>
      )}

      <div className="g-card" style={{ padding: 0, overflowX: 'auto' }}>
        <table className="g-table" style={{ width: '100%' }}>
          <thead className="g-thead">
            <tr>
              <th className="g-tr">Case ID</th><th className="g-tr">Title</th>
              <th className="g-tr">Severity</th><th className="g-tr">Status</th>
              <th className="g-tr">Owner</th><th className="g-tr">SLA</th>
              <th className="g-tr">Due</th><th className="g-tr">Updated</th>
            </tr>
          </thead>
          <tbody>
            {cases.map((c: any) => (
              <tr key={c.id} onClick={() => onSelect(c)} style={{ cursor: 'pointer', background: selectedId === c.id ? 'rgba(99,102,241,0.1)' : undefined }}>
                <td className="g-tr"><code style={{ fontSize: '0.78rem', color: 'var(--accent)' }}>{c.case_id}</code></td>
                <td className="g-tr" style={{ maxWidth: '280px' }}>
                  <div style={{ fontWeight: 600, fontSize: '0.85rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.title}</div>
                  {c.tags && <div style={{ display: 'flex', gap: '0.25rem', marginTop: '2px', flexWrap: 'wrap' }}>
                    {c.tags.split(',').slice(0, 3).map((t: string) => (
                      <span key={t} style={{ fontSize: '0.65rem', background: 'rgba(99,102,241,0.1)', color: '#818cf8', padding: '1px 4px', borderRadius: '2px' }}>{t.trim()}</span>
                    ))}
                  </div>}
                </td>
                <td className="g-tr">
                  <span style={{ background: `${SEV_COLOR[c.severity]}18`, color: SEV_COLOR[c.severity], padding: '2px 7px', borderRadius: '3px', fontSize: '0.75rem', fontWeight: 600 }}>{c.severity.toUpperCase()}</span>
                </td>
                <td className="g-tr">
                  <span style={{ background: `${STATUS_COLOR[c.status]}18`, color: STATUS_COLOR[c.status], padding: '2px 7px', borderRadius: '3px', fontSize: '0.75rem' }}>{STATUS_LABEL[c.status] || c.status}</span>
                </td>
                <td className="g-tr" style={{ fontSize: '0.82rem', fontFamily: 'monospace' }}>{c.owner}</td>
                <td className="g-tr">
                  <span style={{ fontSize: '0.75rem', fontWeight: 600, color: c.sla_status === 'breach' ? '#ef4444' : c.sla_status === 'warning' ? '#eab308' : '#22c55e' }}>
                    {c.sla_status === 'breach' ? '⚠ BREACH' : c.sla_status === 'warning' ? '⚡ Warning' : '✓ OK'}
                  </span>
                </td>
                <td className="g-tr" style={{ fontSize: '0.78rem', color: c.due_date && new Date(c.due_date) < new Date() ? '#ef4444' : 'var(--text-3)', whiteSpace: 'nowrap' }}>
                  {c.due_date ? timeAgo(c.due_date) : '—'}
                </td>
                <td className="g-tr" style={{ fontSize: '0.78rem', color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(c.updated_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Tasks ─────────────────────────────────────────────────────────────────────
function TasksTab({ caseId, caseTitle }: { caseId: number | null; caseTitle: string }) {
  const [tasks, setTasks] = useState<any[]>([]);
  const [showAdd, setShowAdd] = useState(false);
  const [newTask, setNewTask] = useState({ title: '', priority: 'medium', assignee: '' });

  const load = useCallback(() => {
    if (!caseId) return;
    casesAPI.getTasks(caseId).then(r => setTasks(r.data || []));
  }, [caseId]);

  useEffect(() => { load(); }, [load]);

  const addTask = async () => {
    if (!caseId || !newTask.title) return;
    await casesAPI.createTask(caseId, newTask);
    setNewTask({ title: '', priority: 'medium', assignee: '' });
    setShowAdd(false);
    load();
  };

  const toggleStatus = async (task: any) => {
    if (!caseId) return;
    const next = task.status === 'done' ? 'pending' : task.status === 'pending' ? 'in_progress' : 'done';
    await casesAPI.updateTask(caseId, task.id, { status: next });
    load();
  };

  const checklist = (raw: string) => {
    try { return JSON.parse(raw) as string[]; } catch { return []; }
  };

  if (!caseId) return (
    <div style={{ color: 'var(--text-3)', padding: '2rem', textAlign: 'center' }}>
      Select a case from the <strong>Cases</strong> tab to view tasks.
    </div>
  );

  const done = tasks.filter(t => t.status === 'done').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <div style={{ fontWeight: 600 }}>{caseTitle}</div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>{done}/{tasks.length} tasks completed</div>
        </div>
        <button className="g-btn g-btn-primary" onClick={() => setShowAdd(!showAdd)}>+ Add Task</button>
      </div>

      {tasks.length > 0 && (
        <div style={{ height: '6px', borderRadius: '3px', background: 'rgba(255,255,255,0.08)' }}>
          <div style={{ width: `${(done / tasks.length) * 100}%`, height: '100%', borderRadius: '3px', background: '#22c55e', transition: 'width 0.3s' }} />
        </div>
      )}

      {showAdd && (
        <div className="g-card" style={{ padding: '1rem', border: '1px solid rgba(99,102,241,0.3)' }}>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <input className="g-input" style={{ flex: 2, minWidth: '180px' }} placeholder="Task title *" value={newTask.title} onChange={e => setNewTask(f => ({ ...f, title: e.target.value }))} onKeyDown={e => e.key === 'Enter' && addTask()} />
            <select className="g-select" value={newTask.priority} onChange={e => setNewTask(f => ({ ...f, priority: e.target.value }))}>
              {['critical','high','medium','low'].map(p => <option key={p} value={p}>{p}</option>)}
            </select>
            <input className="g-input" placeholder="Assignee" value={newTask.assignee} onChange={e => setNewTask(f => ({ ...f, assignee: e.target.value }))} />
            <button className="g-btn g-btn-primary" onClick={addTask} disabled={!newTask.title}>Add</button>
            <button className="g-btn g-btn-ghost" onClick={() => setShowAdd(false)}>Cancel</button>
          </div>
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        {tasks.map((t: any) => {
          const checks = checklist(t.checklist);
          return (
            <div key={t.id} className="g-card" style={{ padding: '1rem', borderLeft: `3px solid ${TASK_STATUS_COLOR[t.status] || '#666'}`, opacity: t.status === 'done' ? 0.7 : 1 }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
                <button
                  onClick={() => toggleStatus(t)}
                  style={{
                    width: '20px', height: '20px', borderRadius: '50%', flexShrink: 0, marginTop: '2px',
                    background: t.status === 'done' ? '#22c55e' : 'transparent',
                    border: `2px solid ${TASK_STATUS_COLOR[t.status] || '#666'}`,
                    cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontSize: '0.7rem',
                  }}
                >
                  {t.status === 'done' ? '✓' : ''}
                </button>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '0.5rem' }}>
                    <span style={{ fontWeight: 600, fontSize: '0.88rem', textDecoration: t.status === 'done' ? 'line-through' : 'none' }}>{t.title}</span>
                    <div style={{ display: 'flex', gap: '0.4rem', fontSize: '0.72rem', flexShrink: 0 }}>
                      <span style={{ background: `${SEV_COLOR[t.priority] || '#666'}18`, color: SEV_COLOR[t.priority] || '#666', padding: '1px 5px', borderRadius: '3px' }}>{t.priority}</span>
                      <span style={{ background: `${TASK_STATUS_COLOR[t.status]}18`, color: TASK_STATUS_COLOR[t.status], padding: '1px 5px', borderRadius: '3px' }}>{t.status}</span>
                      {t.assignee && <span style={{ color: 'var(--text-3)' }}>{t.assignee}</span>}
                    </div>
                  </div>
                  {checks.length > 0 && (
                    <div style={{ marginTop: '0.5rem', display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                      {checks.map((item, i) => (
                        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.78rem', color: 'var(--text-3)' }}>
                          <span style={{ color: t.status === 'done' ? '#22c55e' : 'var(--text-3)' }}>{t.status === 'done' ? '☑' : '☐'}</span>
                          {item}
                        </div>
                      ))}
                    </div>
                  )}
                  {t.notes && <div style={{ marginTop: '0.4rem', fontSize: '0.78rem', color: '#22c55e', fontStyle: 'italic' }}>✓ {t.notes}</div>}
                  {t.due_date && <div style={{ marginTop: '0.25rem', fontSize: '0.72rem', color: 'var(--text-3)' }}>Due: {timeAgo(t.due_date)}</div>}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Evidence ──────────────────────────────────────────────────────────────────
function EvidenceTab({ caseId, caseTitle }: { caseId: number | null; caseTitle: string }) {
  const [items, setItems] = useState<any[]>([]);
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({ title: '', evidence_type: 'log', file_hash: '', collector: '', notes: '' });
  const [selected, setSelected] = useState<any>(null);

  const load = useCallback(() => {
    if (!caseId) return;
    casesAPI.getEvidence(caseId).then(r => setItems(r.data || []));
  }, [caseId]);

  useEffect(() => { load(); }, [load]);

  const add = async () => {
    if (!caseId || !form.title) return;
    await casesAPI.addEvidence(caseId, form);
    setShowAdd(false);
    setForm({ title: '', evidence_type: 'log', file_hash: '', collector: '', notes: '' });
    load();
  };

  const EV_TYPES = ['log', 'memory_dump', 'pcap', 'file', 'registry', 'screenshot', 'timeline'];

  if (!caseId) return (
    <div style={{ color: 'var(--text-3)', padding: '2rem', textAlign: 'center' }}>
      Select a case from the <strong>Cases</strong> tab to view evidence.
    </div>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{ fontWeight: 600 }}>{caseTitle}</div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>{items.length} evidence items · Chain of Custody Tracking</div>
        </div>
        <button className="g-btn g-btn-primary" onClick={() => setShowAdd(!showAdd)}>+ Add Evidence</button>
      </div>

      {showAdd && (
        <div className="g-card" style={{ padding: '1rem', border: '1px solid rgba(99,102,241,0.3)' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
            <div style={{ gridColumn: '1/-1' }}>
              <input className="g-input" style={{ width: '100%' }} placeholder="Title *" value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))} />
            </div>
            <select className="g-select" value={form.evidence_type} onChange={e => setForm(f => ({ ...f, evidence_type: e.target.value }))}>
              {EV_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
            <input className="g-input" placeholder="Collector" value={form.collector} onChange={e => setForm(f => ({ ...f, collector: e.target.value }))} />
            <div style={{ gridColumn: '1/-1' }}>
              <input className="g-input" style={{ width: '100%' }} placeholder="File hash (sha256:...)" value={form.file_hash} onChange={e => setForm(f => ({ ...f, file_hash: e.target.value }))} />
            </div>
            <div style={{ gridColumn: '1/-1' }}>
              <textarea className="g-input" style={{ width: '100%', height: '50px', resize: 'none' }} placeholder="Notes" value={form.notes} onChange={e => setForm(f => ({ ...f, notes: e.target.value }))} />
            </div>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
            <button className="g-btn g-btn-primary" onClick={add} disabled={!form.title}>Add Evidence</button>
            <button className="g-btn g-btn-ghost" onClick={() => setShowAdd(false)}>Cancel</button>
          </div>
        </div>
      )}

      <div style={{ display: 'flex', gap: '1rem' }}>
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {items.map((e: any) => (
            <div key={e.id} className="g-card" style={{ padding: '1rem', cursor: 'pointer', border: `1px solid ${selected?.id === e.id ? 'var(--accent)' : 'transparent'}` }} onClick={() => setSelected(selected?.id === e.id ? null : e)}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ fontSize: '1.1rem' }}>{EV_TYPE_ICON[e.evidence_type] || '📁'}</span>
                  <span style={{ fontWeight: 600, fontSize: '0.88rem' }}>{e.title}</span>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', fontSize: '0.75rem' }}>
                  <code style={{ color: '#818cf8' }}>{e.evidence_id}</code>
                  {e.verified
                    ? <span style={{ color: '#22c55e', fontWeight: 600 }}>✓ Verified</span>
                    : <span style={{ color: '#eab308' }}>Pending</span>}
                </div>
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>
                <span>Collector: {e.collector}</span>
                <span style={{ margin: '0 0.5rem' }}>·</span>
                <span>Owner: {e.current_owner}</span>
                <span style={{ margin: '0 0.5rem' }}>·</span>
                <span>{timeAgo(e.created_at)}</span>
              </div>
              {e.notes && <div style={{ marginTop: '0.25rem', fontSize: '0.78rem', color: 'var(--text-2)' }}>{e.notes}</div>}
              {e.file_hash && <code style={{ display: 'block', marginTop: '0.35rem', fontSize: '0.68rem', color: 'var(--text-3)' }}>{e.file_hash}</code>}
            </div>
          ))}
        </div>

        {selected && (
          <div className="g-card" style={{ width: '300px', padding: '1rem', flexShrink: 0, fontSize: '0.82rem' }}>
            <div style={{ fontWeight: 600, color: 'var(--accent)', marginBottom: '0.75rem' }}>Chain of Custody</div>
            <div style={{ marginBottom: '0.5rem' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-3)', marginBottom: '0.25rem' }}>Evidence ID</div>
              <code style={{ color: '#818cf8' }}>{selected.evidence_id}</code>
            </div>
            <div style={{ marginBottom: '0.5rem' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-3)', marginBottom: '0.25rem' }}>Hash</div>
              <code style={{ fontSize: '0.7rem', wordBreak: 'break-all', color: 'var(--text-2)' }}>{selected.file_hash || '—'}</code>
            </div>
            <div style={{ marginBottom: '0.75rem' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-3)', marginBottom: '0.25rem' }}>Verification</div>
              <span style={{ color: selected.verified ? '#22c55e' : '#eab308', fontWeight: 600 }}>{selected.verified ? '✓ Hash Verified' : '⏳ Pending Verification'}</span>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-3)', marginBottom: '0.5rem' }}>Custody Log</div>
              {(() => {
                try {
                  const chain = JSON.parse(selected.custody_chain || '[]');
                  return chain.map((e: any, i: number) => (
                    <div key={i} style={{ padding: '0.4rem 0.5rem', background: 'rgba(255,255,255,0.04)', borderRadius: '4px', marginBottom: '0.35rem', fontSize: '0.75rem' }}>
                      <div style={{ fontWeight: 600 }}>{e.action}</div>
                      <div style={{ color: 'var(--text-3)' }}>{e.from} → {e.to}</div>
                      <div style={{ color: 'var(--text-3)' }}>{timeAgo(e.timestamp)}</div>
                    </div>
                  ));
                } catch { return <div style={{ color: 'var(--text-3)' }}>No custody log</div>; }
              })()}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Notebook ──────────────────────────────────────────────────────────────────
function NotebookTab({ caseId, caseTitle }: { caseId: number | null; caseTitle: string }) {
  const [notes, setNotes] = useState<any[]>([]);
  const [draft, setDraft] = useState('');
  const [saving, setSaving] = useState(false);

  const load = useCallback(() => {
    if (!caseId) return;
    casesAPI.getNotes(caseId).then(r => setNotes(r.data || []));
  }, [caseId]);

  useEffect(() => { load(); }, [load]);

  const save = async () => {
    if (!caseId || !draft.trim()) return;
    setSaving(true);
    await casesAPI.addNote(caseId, { content: draft, author: 'analyst', note_type: 'markdown' });
    setDraft('');
    load();
    setSaving(false);
  };

  if (!caseId) return (
    <div style={{ color: 'var(--text-3)', padding: '2rem', textAlign: 'center' }}>
      Select a case from the <strong>Cases</strong> tab to view the notebook.
    </div>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ fontWeight: 600 }}>{caseTitle} — Investigation Notebook</div>

      <div className="g-card" style={{ padding: '1rem' }}>
        <div style={{ fontSize: '0.78rem', color: 'var(--text-3)', marginBottom: '0.5rem' }}>New Note (Markdown supported)</div>
        <textarea
          className="g-input"
          style={{ width: '100%', height: '160px', resize: 'vertical', fontFamily: 'monospace', fontSize: '0.82rem' }}
          placeholder={`## Finding\n\nDescribe what you found…\n\n### IOCs\n- IP: \n- Hash: \n\n### Next Steps\n1. `}
          value={draft}
          onChange={e => setDraft(e.target.value)}
        />
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.5rem' }}>
          <div style={{ display: 'flex', gap: '0.35rem' }}>
            {['## ', '**', '_', '`', '```\n\n```', '- [ ] ', '> '].map(s => (
              <button key={s} className="g-btn g-btn-ghost"
                style={{ fontSize: '0.7rem', padding: '2px 6px' }}
                onClick={() => setDraft(d => d + s)}>
                {s.trim() || '&nbsp;'}
              </button>
            ))}
          </div>
          <button className="g-btn g-btn-primary" onClick={save} disabled={saving || !draft.trim()}>
            {saving ? 'Saving…' : 'Save Note'}
          </button>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        {notes.map((n: any) => (
          <div key={n.id} className="g-card" style={{ padding: '1.25rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}><strong>{n.author}</strong> · {timeAgo(n.created_at)}</span>
              <code style={{ fontSize: '0.7rem', color: 'var(--text-3)' }}>{n.note_type}</code>
            </div>
            <div style={{
              fontFamily: 'monospace', fontSize: '0.82rem', lineHeight: 1.7,
              whiteSpace: 'pre-wrap', wordBreak: 'break-word',
            }}>
              {n.content.split('\n').map((line: string, i: number) => {
                if (line.startsWith('## ')) return <div key={i} style={{ fontWeight: 700, fontSize: '1rem', margin: '0.5rem 0 0.25rem', color: 'var(--accent)' }}>{line.slice(3)}</div>;
                if (line.startsWith('### ')) return <div key={i} style={{ fontWeight: 600, margin: '0.4rem 0 0.15rem', color: 'var(--text-2)' }}>{line.slice(4)}</div>;
                if (line.startsWith('```')) return <div key={i} style={{ background: 'rgba(0,0,0,0.3)', padding: '0.1rem 0.5rem', borderRadius: '3px', marginTop: '2px' }}>{line}</div>;
                if (line.startsWith('- ') || line.startsWith('• ')) return <div key={i} style={{ color: 'var(--text-2)', paddingLeft: '0.75rem' }}>• {line.slice(2)}</div>;
                if (/^\d+\. /.test(line)) return <div key={i} style={{ color: 'var(--text-2)', paddingLeft: '0.75rem' }}>{line}</div>;
                if (line.startsWith('**') && line.endsWith('**')) return <div key={i} style={{ fontWeight: 700 }}>{line.slice(2, -2)}</div>;
                if (line.trim() === '') return <div key={i} style={{ height: '0.4rem' }} />;
                return <div key={i} style={{ color: 'var(--text-2)' }}>{line}</div>;
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Timeline ──────────────────────────────────────────────────────────────────
function TimelineTab({ caseId, caseTitle }: { caseId: number | null; caseTitle: string }) {
  const [events, setEvents] = useState<any[]>([]);

  useEffect(() => {
    if (!caseId) return;
    casesAPI.getTimeline(caseId).then(r => setEvents(r.data || []));
  }, [caseId]);

  if (!caseId) return (
    <div style={{ color: 'var(--text-3)', padding: '2rem', textAlign: 'center' }}>
      Select a case from the <strong>Cases</strong> tab to view the timeline.
    </div>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ fontWeight: 600 }}>{caseTitle} — Case Timeline</div>
      <div className="g-card" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
          {events.map((e: any, i: number) => (
            <div key={e.id} style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0, width: '24px' }}>
                <div style={{ width: '14px', height: '14px', borderRadius: '50%', background: TL_TYPE_COLOR[e.event_type] || '#666', marginTop: '4px', flexShrink: 0, boxShadow: `0 0 0 3px ${TL_TYPE_COLOR[e.event_type] || '#666'}22` }} />
                {i < events.length - 1 && <div style={{ width: '2px', flex: 1, minHeight: '36px', background: 'var(--border)' }} />}
              </div>
              <div style={{ paddingBottom: '1.25rem', flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem', marginBottom: '0.2rem' }}>
                  <span style={{ fontWeight: 600, fontSize: '0.88rem' }}>{e.event}</span>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-3)', whiteSpace: 'nowrap', flexShrink: 0 }}>{timeAgo(e.created_at)}</span>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem', fontSize: '0.75rem', color: 'var(--text-3)' }}>
                  <span>{e.actor}</span>
                  <span style={{ background: `${TL_TYPE_COLOR[e.event_type] || '#666'}18`, color: TL_TYPE_COLOR[e.event_type] || '#666', padding: '1px 6px', borderRadius: '3px' }}>
                    {e.event_type?.replace(/_/g, ' ')}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Analytics ─────────────────────────────────────────────────────────────────
function AnalyticsTab() {
  const [data, setData] = useState<any>(null);
  useEffect(() => { casesAPI.getAnalytics().then(r => setData(r.data)); }, []);
  if (!data) return <div style={{ color: 'var(--text-3)', padding: '2rem' }}>Loading…</div>;

  const maxTrend = Math.max(...(data.case_trend?.map((p: any) => p.count) || [1]), 1);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div className="g-card" style={{ padding: '1.25rem' }}>
        <div style={{ fontWeight: 600, marginBottom: '1rem' }}>Case Volume Trend (8d)</div>
        <div style={{ display: 'flex', alignItems: 'flex-end', gap: '4px', height: '100px' }}>
          {data.case_trend?.map((p: any, i: number) => (
            <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '4px' }}>
              <div style={{ width: '100%', background: p.count > 3 ? '#ef4444' : p.count > 1 ? '#f97316' : '#3b82f6', height: `${Math.max((p.count / maxTrend) * 80, p.count > 0 ? 6 : 2)}px`, borderRadius: '3px 3px 0 0' }} title={`${p.date}: ${p.count}`} />
              <div style={{ fontSize: '0.6rem', color: 'var(--text-3)', transform: 'rotate(-25deg)', whiteSpace: 'nowrap' }}>{p.date.slice(5)}</div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div className="g-card" style={{ padding: '1.25rem' }}>
          <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Cases by Severity</div>
          {data.by_severity?.map((s: any) => (
            <div key={s.severity} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.6rem' }}>
              <span style={{ minWidth: '70px', fontSize: '0.82rem', color: SEV_COLOR[s.severity] }}>{s.severity}</span>
              <div style={{ flex: 1, height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
                <div style={{ width: `${(s.count / 8) * 100}%`, height: '100%', borderRadius: '4px', background: SEV_COLOR[s.severity] }} />
              </div>
              <span style={{ fontSize: '0.8rem', minWidth: '20px', textAlign: 'right' }}>{s.count}</span>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: '1.25rem' }}>
          <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Cases by Analyst</div>
          {data.by_analyst?.map((a: any) => (
            <div key={a.analyst} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.6rem' }}>
              <span style={{ minWidth: '80px', fontSize: '0.82rem', fontFamily: 'monospace' }}>{a.analyst}</span>
              <div style={{ flex: 1, height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
                <div style={{ width: `${(a.count / 14) * 100}%`, height: '100%', borderRadius: '4px', background: '#6366f1' }} />
              </div>
              <span style={{ fontSize: '0.8rem', minWidth: '20px', textAlign: 'right' }}>{a.count}</span>
            </div>
          ))}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div className="g-card" style={{ padding: '1.25rem' }}>
          <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Avg Resolution by Severity</div>
          {data.avg_resolution_hours?.map((r: any) => (
            <div key={r.severity} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.6rem' }}>
              <span style={{ minWidth: '70px', fontSize: '0.82rem', color: SEV_COLOR[r.severity] }}>{r.severity}</span>
              <div style={{ flex: 1, height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
                <div style={{ width: `${(r.hours / 48) * 100}%`, height: '100%', borderRadius: '4px', background: SEV_COLOR[r.severity] }} />
              </div>
              <span style={{ fontSize: '0.8rem', minWidth: '30px', textAlign: 'right', color: 'var(--text-3)' }}>{r.hours}h</span>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <span style={{ fontWeight: 600 }}>SLA Compliance</span>
          </div>
          <div style={{ textAlign: 'center', padding: '1rem 0' }}>
            <div style={{ fontSize: '3rem', fontWeight: 700, color: data.sla_compliance >= 80 ? '#22c55e' : data.sla_compliance >= 60 ? '#eab308' : '#ef4444' }}>
              {data.sla_compliance}%
            </div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-3)', marginTop: '0.25rem' }}>Overall SLA compliance rate</div>
            <div style={{ marginTop: '0.75rem', height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
              <div style={{ width: `${data.sla_compliance}%`, height: '100%', borderRadius: '4px', background: data.sla_compliance >= 80 ? '#22c55e' : '#eab308' }} />
            </div>
          </div>
          <div style={{ marginTop: '0.75rem', fontSize: '0.78rem', color: 'var(--text-3)', textAlign: 'center' }}>
            Recurring cases: <strong style={{ color: '#f97316' }}>{data.recurring_case_count}</strong>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Response & AI ─────────────────────────────────────────────────────────────
function ResponseTab({ selectedCase }: { selectedCase: any }) {
  const [comments, setComments] = useState<any[]>([]);
  const [comment, setComment] = useState('');
  const [aiMode, setAiMode] = useState<'summarize' | 'next_steps' | 'root_cause' | 'ask'>('summarize');
  const [aiResult, setAiResult] = useState<any>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [askQuery, setAskQuery] = useState('');
  const [reportType, setReportType] = useState('executive');
  const [report, setReport] = useState<any>(null);
  const [reportLoading, setReportLoading] = useState(false);

  const caseId = selectedCase?.id;

  useEffect(() => {
    if (!caseId) return;
    casesAPI.getComments(caseId).then(r => setComments(r.data || []));
  }, [caseId]);

  const addComment = async () => {
    if (!caseId || !comment.trim()) return;
    await casesAPI.addComment(caseId, { content: comment, author: 'analyst', is_internal: true });
    setComment('');
    casesAPI.getComments(caseId).then(r => setComments(r.data || []));
  };

  const runAI = async () => {
    setAiLoading(true);
    const payload: any = {
      mode: aiMode,
      case_id: selectedCase?.case_id || '',
      context: selectedCase ? `Case: ${selectedCase.title}\nSeverity: ${selectedCase.severity}\nStatus: ${selectedCase.status}\nTags: ${selectedCase.tags}` : '',
    };
    if (aiMode === 'ask') payload.content = askQuery;
    const r = await casesAPI.analyzeAI(payload);
    setAiResult(r.data);
    setAiLoading(false);
  };

  const genReport = async () => {
    setReportLoading(true);
    const r = await casesAPI.generateReport({
      report_type: reportType,
      case_id: selectedCase?.case_id || '',
      context: selectedCase ? `${selectedCase.title}\nSeverity: ${selectedCase.severity}\nTags: ${selectedCase.tags}` : '',
    });
    setReport(r.data);
    setReportLoading(false);
  };

  const AI_MODES = [
    { id: 'summarize' as const,  label: 'Summarize' },
    { id: 'next_steps' as const, label: 'Next Steps' },
    { id: 'root_cause' as const, label: 'Root Cause' },
    { id: 'ask' as const,        label: 'Ask' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* AI Investigation Assistant */}
      <div className="g-card" style={{ padding: '1.25rem' }}>
        <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>AI Investigation Assistant</div>
        {!selectedCase && <div style={{ fontSize: '0.82rem', color: 'var(--text-3)', marginBottom: '0.75rem' }}>Select a case from the <strong>Cases</strong> tab for case-specific analysis.</div>}
        <div style={{ display: 'flex', gap: '0.4rem', marginBottom: '0.75rem' }}>
          {AI_MODES.map(m => (
            <button key={m.id} className={`g-btn ${aiMode === m.id ? 'g-btn-primary' : 'g-btn-ghost'}`}
              style={{ fontSize: '0.8rem' }} onClick={() => setAiMode(m.id)}>{m.label}</button>
          ))}
        </div>
        {aiMode === 'ask' && (
          <input className="g-input" style={{ width: '100%', marginBottom: '0.5rem' }}
            placeholder="Ask anything about this case…"
            value={askQuery} onChange={e => setAskQuery(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') runAI(); }} />
        )}
        <button className="g-btn g-btn-primary" onClick={runAI} disabled={aiLoading || (aiMode === 'ask' && !askQuery.trim())}>
          {aiLoading ? 'Analyzing…' : 'Analyze'}
        </button>

        {aiResult && (
          <div style={{ marginTop: '1rem', background: 'rgba(99,102,241,0.07)', padding: '1rem', borderRadius: '6px', border: '1px solid rgba(99,102,241,0.2)' }}>
            {aiResult.summary && (
              <>
                <div style={{ fontWeight: 600, marginBottom: '0.4rem', color: 'var(--accent)' }}>Summary</div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-2)', marginBottom: '0.75rem', lineHeight: 1.6 }}>{aiResult.summary}</div>
              </>
            )}
            {aiResult.answer && <div style={{ fontSize: '0.85rem', color: 'var(--text-2)', marginBottom: '0.75rem' }}>{aiResult.answer}</div>}
            {aiResult.key_findings && (
              <div style={{ marginBottom: '0.75rem' }}>
                <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-3)', marginBottom: '0.35rem' }}>Key Findings</div>
                {aiResult.key_findings.map((f: string, i: number) => (
                  <div key={i} style={{ fontSize: '0.8rem', color: '#ef4444', paddingLeft: '0.5rem', borderLeft: '2px solid #ef4444', marginBottom: '0.2rem' }}>• {f}</div>
                ))}
              </div>
            )}
            {aiResult.next_steps && (
              <div style={{ marginBottom: '0.75rem' }}>
                <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-3)', marginBottom: '0.35rem' }}>Next Steps</div>
                {aiResult.next_steps.map((s: string, i: number) => (
                  <div key={i} style={{ fontSize: '0.8rem', color: '#22c55e', paddingLeft: '0.5rem', borderLeft: '2px solid #22c55e', marginBottom: '0.2rem' }}>→ {s}</div>
                ))}
              </div>
            )}
            {aiResult.missing_evidence && (
              <div style={{ marginBottom: '0.75rem' }}>
                <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-3)', marginBottom: '0.35rem' }}>Missing Evidence</div>
                {aiResult.missing_evidence.map((e: string, i: number) => (
                  <div key={i} style={{ fontSize: '0.8rem', color: '#eab308', paddingLeft: '0.5rem', borderLeft: '2px solid #eab308', marginBottom: '0.2rem' }}>⚠ {e}</div>
                ))}
              </div>
            )}
            {aiResult.root_cause && (
              <div style={{ marginBottom: '0.75rem' }}>
                <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-3)', marginBottom: '0.35rem' }}>Root Cause Analysis</div>
                {[['Initial Access', aiResult.initial_access], ['Persistence', aiResult.persistence], ['Lateral Movement', aiResult.lateral_movement], ['Impact', aiResult.impact], ['Root Cause', aiResult.root_cause]].filter(([, v]) => v).map(([k, v]) => (
                  <div key={k as string} style={{ marginBottom: '0.4rem' }}>
                    <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-3)' }}>{k}: </span>
                    <span style={{ fontSize: '0.8rem', color: 'var(--text-2)' }}>{v}</span>
                  </div>
                ))}
                {aiResult.lessons_learned && (
                  <div style={{ marginTop: '0.5rem' }}>
                    <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-3)', marginBottom: '0.25rem' }}>Lessons Learned</div>
                    {aiResult.lessons_learned.map((l: string, i: number) => (
                      <div key={i} style={{ fontSize: '0.8rem', color: '#a855f7', paddingLeft: '0.5rem', borderLeft: '2px solid #a855f7', marginBottom: '0.2rem' }}>• {l}</div>
                    ))}
                  </div>
                )}
              </div>
            )}
            {aiResult.current_status && (
              <div style={{ marginTop: '0.5rem', fontSize: '0.78rem', color: 'var(--text-3)', borderTop: '1px solid var(--border)', paddingTop: '0.5rem' }}>
                Status: <span style={{ color: 'var(--text-2)' }}>{aiResult.current_status}</span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Report Generator */}
      <div className="g-card" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
          <span style={{ fontWeight: 600 }}>Report Generator</span>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <select className="g-select" value={reportType} onChange={e => setReportType(e.target.value)} style={{ fontSize: '0.82rem' }}>
              {['executive', 'technical', 'incident', 'dfir', 'compliance', 'lessons_learned'].map(t => (
                <option key={t} value={t}>{t.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</option>
              ))}
            </select>
            <button className="g-btn g-btn-primary" onClick={genReport} disabled={reportLoading}>
              {reportLoading ? 'Generating…' : 'Generate'}
            </button>
          </div>
        </div>
        {report && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div style={{ fontWeight: 600, fontSize: '1rem' }}>{report.title}</div>
              <span style={{ fontSize: '0.72rem', background: 'rgba(239,68,68,0.1)', color: '#ef4444', padding: '2px 8px', borderRadius: '3px', flexShrink: 0, marginLeft: '0.5rem' }}>{report.classification}</span>
            </div>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-2)', lineHeight: 1.6 }}>{report.executive_summary}</div>
            {report.timeline && (
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.35rem' }}>Timeline</div>
                {report.timeline.map((e: string, i: number) => (
                  <div key={i} style={{ fontSize: '0.8rem', color: 'var(--text-3)', paddingLeft: '0.5rem', borderLeft: '2px solid var(--border)', marginBottom: '0.2rem' }}>{e}</div>
                ))}
              </div>
            )}
            {report.technical_findings && (
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.35rem' }}>Technical Findings</div>
                {report.technical_findings.map((f: string, i: number) => (
                  <div key={i} style={{ fontSize: '0.82rem', color: '#ef4444', paddingLeft: '0.5rem', borderLeft: '2px solid #ef4444', marginBottom: '0.25rem' }}>• {f}</div>
                ))}
              </div>
            )}
            {report.iocs && (
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.35rem' }}>IOCs</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                  {report.iocs.map((ioc: string, i: number) => (
                    <code key={i} style={{ background: 'rgba(239,68,68,0.1)', color: '#ef4444', padding: '2px 6px', borderRadius: '3px', fontSize: '0.72rem' }}>{ioc}</code>
                  ))}
                </div>
              </div>
            )}
            {report.recommendations && (
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.35rem' }}>Recommendations</div>
                {report.recommendations.map((r: string, i: number) => (
                  <div key={i} style={{ fontSize: '0.82rem', color: '#22c55e', paddingLeft: '0.5rem', borderLeft: '2px solid #22c55e', marginBottom: '0.25rem' }}>→ {r}</div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Collaboration / Comments */}
      <div className="g-card" style={{ padding: '1.25rem' }}>
        <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>
          Collaboration {selectedCase ? `— ${selectedCase.case_id}` : ''}
        </div>
        {!selectedCase
          ? <div style={{ fontSize: '0.82rem', color: 'var(--text-3)' }}>Select a case to view and add comments.</div>
          : (
            <>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginBottom: '0.75rem', maxHeight: '300px', overflowY: 'auto' }}>
                {comments.map((cm: any) => (
                  <div key={cm.id} style={{ padding: '0.75rem', background: 'rgba(255,255,255,0.04)', borderRadius: '6px', borderLeft: '3px solid rgba(99,102,241,0.4)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem', fontSize: '0.78rem' }}>
                      <span style={{ fontWeight: 600, color: 'var(--accent)' }}>{cm.author}</span>
                      <span style={{ color: 'var(--text-3)' }}>{timeAgo(cm.created_at)}</span>
                    </div>
                    <div style={{ fontSize: '0.83rem', color: 'var(--text-2)', lineHeight: 1.5 }}>{cm.content}</div>
                    {cm.is_internal && <span style={{ fontSize: '0.68rem', color: 'var(--text-3)', marginTop: '0.25rem', display: 'block' }}>🔒 Internal</span>}
                  </div>
                ))}
              </div>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <textarea className="g-input" style={{ flex: 1, height: '60px', resize: 'none' }}
                  placeholder="Add an internal comment…"
                  value={comment} onChange={e => setComment(e.target.value)} />
                <button className="g-btn g-btn-primary" onClick={addComment} disabled={!comment.trim()} style={{ alignSelf: 'flex-end' }}>Post</button>
              </div>
            </>
          )}
      </div>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────
export default function CasesPage() {
  const [tab, setTab] = useState<Tab>('overview');
  const [dash, setDash] = useState<any>(null);
  const [selectedCase, setSelectedCase] = useState<any>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const loaded = useRef<Record<string, boolean>>({});

  useEffect(() => { casesAPI.getDashboard().then(r => setDash(r.data)); }, [refreshKey]);

  if (!loaded.current[tab]) loaded.current[tab] = true;

  const handleSelectCase = (c: any) => {
    setSelectedCase(c);
    setTab('tasks');
  };

  const tabs = Object.keys(TAB_LABELS) as Tab[];

  return (
    <RootLayout>
      <div style={{ padding: '1.5rem', maxWidth: '1400px', margin: '0 auto' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem' }}>
          <div>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Case Management</h1>
            <p style={{ color: 'var(--text-3)', margin: '0.25rem 0 0', fontSize: '0.85rem' }}>
              Incident investigation, evidence tracking, chain of custody, and DFIR reporting
            </p>
          </div>
          {selectedCase && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.3)', padding: '0.5rem 1rem', borderRadius: '6px' }}>
              <div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-3)' }}>Active Case</div>
                <div style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--accent)' }}>{selectedCase.case_id}</div>
              </div>
              <span style={{ background: `${SEV_COLOR[selectedCase.severity]}18`, color: SEV_COLOR[selectedCase.severity], padding: '2px 7px', borderRadius: '3px', fontSize: '0.75rem', fontWeight: 600 }}>{selectedCase.severity.toUpperCase()}</span>
              <button className="g-btn g-btn-ghost" style={{ fontSize: '0.75rem', padding: '3px 8px' }} onClick={() => setSelectedCase(null)}>✕</button>
            </div>
          )}
        </div>

        <div style={{ display: 'flex', gap: '0.25rem', marginBottom: '1.5rem', borderBottom: '1px solid var(--border)', overflowX: 'auto' }}>
          {tabs.map(t => (
            <button key={t} onClick={() => setTab(t)} style={{
              background: 'none', border: 'none', cursor: 'pointer',
              padding: '0.6rem 1rem', fontSize: '0.85rem', whiteSpace: 'nowrap',
              color: tab === t ? 'var(--accent)' : 'var(--text-3)',
              borderBottom: `2px solid ${tab === t ? 'var(--accent)' : 'transparent'}`,
              marginBottom: '-1px', transition: 'all 0.15s',
            }}>{TAB_LABELS[t]}</button>
          ))}
        </div>

        <div style={{ display: loaded.current['overview'] && tab === 'overview' ? 'block' : 'none' }}>
          {loaded.current['overview'] && <OverviewTab dash={dash} />}
        </div>
        <div style={{ display: loaded.current['cases'] && tab === 'cases' ? 'block' : 'none' }}>
          {loaded.current['cases'] && <CasesTab selectedId={selectedCase?.id ?? null} onSelect={handleSelectCase} onRefresh={() => setRefreshKey(k => k + 1)} />}
        </div>
        <div style={{ display: loaded.current['tasks'] && tab === 'tasks' ? 'block' : 'none' }}>
          {loaded.current['tasks'] && <TasksTab caseId={selectedCase?.id ?? null} caseTitle={selectedCase?.title || ''} />}
        </div>
        <div style={{ display: loaded.current['evidence'] && tab === 'evidence' ? 'block' : 'none' }}>
          {loaded.current['evidence'] && <EvidenceTab caseId={selectedCase?.id ?? null} caseTitle={selectedCase?.title || ''} />}
        </div>
        <div style={{ display: loaded.current['notebook'] && tab === 'notebook' ? 'block' : 'none' }}>
          {loaded.current['notebook'] && <NotebookTab caseId={selectedCase?.id ?? null} caseTitle={selectedCase?.title || ''} />}
        </div>
        <div style={{ display: loaded.current['timeline'] && tab === 'timeline' ? 'block' : 'none' }}>
          {loaded.current['timeline'] && <TimelineTab caseId={selectedCase?.id ?? null} caseTitle={selectedCase?.title || ''} />}
        </div>
        <div style={{ display: loaded.current['analytics'] && tab === 'analytics' ? 'block' : 'none' }}>
          {loaded.current['analytics'] && <AnalyticsTab />}
        </div>
        <div style={{ display: loaded.current['response'] && tab === 'response' ? 'block' : 'none' }}>
          {loaded.current['response'] && <ResponseTab selectedCase={selectedCase} />}
        </div>
      </div>
    </RootLayout>
  );
}
