'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { steAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';

type Tab = 'dashboard' | 'tasks' | 'upcoming' | 'history' | 'approvals' | 'notifications' | 'analytics' | 'audit' | 'reports';
const TABS: { id: Tab; label: string }[] = [
  { id: 'dashboard',     label: 'Dashboard' },
  { id: 'tasks',         label: 'Task Library' },
  { id: 'upcoming',      label: 'Upcoming' },
  { id: 'history',       label: 'Exec History' },
  { id: 'approvals',     label: 'Approvals' },
  { id: 'notifications', label: 'Notifications' },
  { id: 'analytics',     label: 'Analytics' },
  { id: 'audit',         label: 'Audit Trail' },
  { id: 'reports',       label: 'Reports' },
];

const STATUS_COLOR: Record<string, string> = {
  active: '#22c55e', paused: '#6b7280', disabled: '#6b7280', deprecated: '#6b7280',
  running: '#3b82f6', completed: '#22c55e', failed: '#ef4444',
  pending: '#f97316', approved: '#22c55e', rejected: '#ef4444',
  scheduled: '#a855f7',
};
const PRIORITY_COLOR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
};
const ACTION_COLOR: Record<string, string> = {
  created: '#3b82f6', modified: '#eab308', deleted: '#ef4444',
  executed: '#22c55e', enabled: '#22c55e', disabled: '#6b7280',
  approved: '#22c55e', rejected: '#ef4444', report_generated: '#06b6d4',
  approval_requested: '#f97316',
};
const SEVERITY_COLOR: Record<string, string> = {
  info: '#3b82f6', warning: '#f97316', critical: '#ef4444', success: '#22c55e',
};
const TASK_TYPES = [
  { group: 'Script Execution', values: ['powershell', 'bash', 'python', 'cmd', 'go_binary'] },
  { group: 'Security Operations', values: ['threat_hunt', 'ioc_search', 'vulnerability_scan', 'compliance_scan', 'asset_discovery', 'log_cleanup'] },
  { group: 'Incident Response', values: ['collect_logs', 'memory_collection', 'endpoint_scan', 'file_collection', 'network_diagnostics'] },
  { group: 'System Maintenance', values: ['database_cleanup', 'cache_cleanup', 'index_optimization', 'backup', 'health_check'] },
  { group: 'Reporting', values: ['executive_report', 'compliance_report', 'soc_metrics', 'risk_report', 'vulnerability_report'] },
  { group: 'Custom', values: ['api_call', 'webhook', 'playbook_execution', 'external_integration'] },
];
const SCHEDULE_TYPES = ['one_time', 'hourly', 'daily', 'weekly', 'monthly', 'yearly', 'cron', 'event_based', 'maintenance_window'];
const CATEGORIES = ['security_operations', 'incident_response', 'system_maintenance', 'reporting', 'compliance', 'custom'];
const TARGET_TYPES = ['all', 'single_endpoint', 'multiple_endpoints', 'asset_group', 'department', 'cloud_account', 'kubernetes_cluster'];
const TRIGGER_CONDITIONS = ['time_schedule', 'alert_created', 'incident_created', 'case_created', 'vulnerability_detected', 'asset_added', 'user_login', 'agent_online', 'custom_event'];
const CRON_PRESETS = [
  { label: 'Every hour',   value: '0 * * * *' },
  { label: 'Every 6h',    value: '0 */6 * * *' },
  { label: 'Daily 2AM',   value: '0 2 * * *' },
  { label: 'Weekly Sun',  value: '0 3 * * 0' },
  { label: 'Monthly 1st', value: '0 0 1 * *' },
];
const APPROVAL_POLICIES = ['production_systems', 'critical_infrastructure', 'domain_controllers', 'bulk_operations', 'destructive_tasks', 'custom'];

function pill(label: string, color: string) {
  return (
    <span style={{ fontSize: 10, fontWeight: 600, padding: '2px 8px', borderRadius: 10, background: color + '22', color, border: `1px solid ${color}44`, textTransform: 'capitalize', whiteSpace: 'nowrap' }}>
      {label}
    </span>
  );
}
function StatCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="g-card" style={{ padding: '14px 18px', minWidth: 120 }}>
      <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 700, color: color || 'var(--text-1)', lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 3 }}>{sub}</div>}
    </div>
  );
}

// ─── Dashboard ─────────────────────────────────────────────────────────────
function DashboardTab({ dash, onTabChange }: { dash: any; onTabChange: (t: Tab) => void }) {
  if (!dash) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total Tasks"      value={dash.total_tasks}           color="var(--accent)" />
        <StatCard label="Active"           value={dash.active_tasks}          color="#22c55e" />
        <StatCard label="Paused"           value={dash.paused_tasks}          color="#6b7280" />
        <StatCard label="Running Now"      value={dash.running_tasks}         color="#3b82f6" sub="currently executing" />
        <StatCard label="Completed"        value={dash.completed_executions}  color="#22c55e" sub="total" />
        <StatCard label="Failed"           value={dash.failed_executions}     color="#ef4444" sub="total" />
        <StatCard label="Avg Duration"     value={`${((dash.avg_execution_time||0)/1000).toFixed(1)}s`} color="#f97316" />
        <StatCard label="Total Executions" value={dash.total_executions}      color="#a855f7" />
      </div>

      {dash.pending_approvals > 0 && (
        <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #f97316', background: '#f9731608', cursor: 'pointer' }} onClick={() => onTabChange('approvals')}>
          <span style={{ fontWeight: 700, color: '#f97316' }}>⚠ {dash.pending_approvals} task{dash.pending_approvals !== 1 ? 's' : ''} pending approval.</span>
          <span style={{ fontSize: 13, color: 'var(--text-2)', marginLeft: 8 }}>Click to review in Approvals tab.</span>
        </div>
      )}
      {dash.unread_notifications > 0 && (
        <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #3b82f6', background: '#3b82f608' }}>
          <span style={{ fontWeight: 700, color: '#3b82f6' }}>🔔 {dash.unread_notifications} unread notification{dash.unread_notifications !== 1 ? 's' : ''}.</span>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Upcoming Executions</div>
          {(!dash.upcoming_executions || dash.upcoming_executions.length === 0) && (
            <div style={{ fontSize: 13, color: 'var(--text-3)' }}>No upcoming executions scheduled</div>
          )}
          {(dash.upcoming_executions || []).map((u: any, i: number) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontSize: 12, fontWeight: 500 }}>{u.name}</span>
              <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{timeAgo(u.next_run_at)}</span>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Recent Failures</div>
          {(!dash.recent_failures || dash.recent_failures.length === 0) && (
            <div style={{ fontSize: 13, color: 'var(--text-3)' }}>No recent failures 🎉</div>
          )}
          {(dash.recent_failures || []).map((f: any, i: number) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontSize: 12, fontWeight: 500 }}>{f.task_name}</span>
              <span style={{ fontSize: 10, color: '#ef4444', background: '#ef444422', padding: '2px 7px', borderRadius: 8 }}>failed</span>
            </div>
          ))}
        </div>
      </div>

      <div className="g-card" style={{ padding: 16 }}>
        <div style={{ fontWeight: 600, marginBottom: 12 }}>Task Coverage</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 10 }}>
          {[
            ['Active Tasks', dash.active_tasks, dash.total_tasks, '#22c55e'],
            ['Completed Runs', dash.completed_executions, Math.max(dash.total_executions, 1), '#3b82f6'],
            ['Success Rate', Math.round(dash.total_executions > 0 ? (dash.completed_executions / dash.total_executions) * 100 : 0), 100, '#a855f7'],
          ].map(([label, val, max, color]: any) => (
            <div key={label}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 4 }}>
                <span style={{ color: 'var(--text-2)' }}>{label}</span>
                <span style={{ fontWeight: 700, color }}>{val}{label.includes('Rate') ? '%' : ''}</span>
              </div>
              <div style={{ background: 'var(--border)', borderRadius: 3, height: 5 }}>
                <div style={{ background: color, borderRadius: 3, height: 5, width: `${Math.min(100, Math.round((val / Math.max(max, 1)) * 100))}%` }} />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Task Library ───────────────────────────────────────────────────────────
function TasksTab({ tasks, onRefresh, onNew }: { tasks: any[]; onRefresh: () => void; onNew: () => void }) {
  const [search, setSearch] = useState('');
  const [filterCat, setFilterCat] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [filterType, setFilterType] = useState('');
  const [filterSched, setFilterSched] = useState('');
  const [deleting, setDeleting] = useState<number | null>(null);
  const [running, setRunning] = useState<number | null>(null);
  const [toast, setToast] = useState('');
  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(''), 3000); };

  const filtered = useMemo(() => tasks.filter(t => {
    if (filterCat && t.category !== filterCat) return false;
    if (filterStatus && t.status !== filterStatus) return false;
    if (filterType && t.task_type !== filterType) return false;
    if (filterSched && t.schedule_type !== filterSched) return false;
    if (search) {
      const q = search.toLowerCase();
      return t.name.toLowerCase().includes(q) || t.task_id.toLowerCase().includes(q) || (t.owner || '').toLowerCase().includes(q) || (t.description || '').toLowerCase().includes(q);
    }
    return true;
  }), [tasks, filterCat, filterStatus, filterType, filterSched, search]);

  const toggle = async (t: any) => {
    await steAPI.updateTask(t.id, { enabled: !t.enabled });
    onRefresh();
  };
  const runNow = async (t: any) => {
    setRunning(t.id);
    try {
      const r = await steAPI.runTask(t.id);
      if ((r.data as any)?.status === 'pending_approval') {
        notify('Approval required — request submitted');
      } else {
        notify(`Task '${t.name}' started`);
      }
      setTimeout(onRefresh, 1000);
    } catch { notify('Failed to run task'); }
    finally { setRunning(null); }
  };
  const del = async (t: any) => {
    setDeleting(t.id);
    await steAPI.deleteTask(t.id);
    onRefresh();
    setDeleting(null);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {toast && <div className="g-card" style={{ padding: '8px 14px', borderLeft: '3px solid var(--accent)', fontSize: 13 }}>{toast}</div>}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <input className="g-input" placeholder="Search tasks…" value={search} onChange={e => setSearch(e.target.value)} style={{ fontSize: 12, width: 220 }} />
        <select className="g-select" value={filterCat} onChange={e => setFilterCat(e.target.value)} style={{ fontSize: 11 }}>
          <option value="">All Categories</option>
          {CATEGORIES.map(c => <option key={c} value={c}>{c.replace(/_/g, ' ')}</option>)}
        </select>
        <select className="g-select" value={filterStatus} onChange={e => setFilterStatus(e.target.value)} style={{ fontSize: 11 }}>
          <option value="">All Status</option>
          {['active','disabled','deprecated'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="g-select" value={filterSched} onChange={e => setFilterSched(e.target.value)} style={{ fontSize: 11 }}>
          <option value="">All Schedules</option>
          {SCHEDULE_TYPES.map(s => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
        </select>
        <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={onRefresh}>↻</button>
        <button className="g-btn g-btn-primary" style={{ fontSize: 11, marginLeft: 'auto' }} onClick={onNew}>+ New Task</button>
      </div>
      <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{filtered.length} of {tasks.length} tasks</div>
      <div className="g-card" style={{ overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table className="g-table" style={{ width: '100%' }}>
            <thead className="g-thead">
              <tr>{['Task ID','Name','Category','Type','Schedule','Owner','Priority','Status','Last Run','Next Run','Runs',''].map(h => (
                <th key={h} className="g-tr" style={{ padding: '8px 12px', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
              ))}</tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr><td colSpan={12} style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)' }}>No tasks found</td></tr>
              )}
              {filtered.map(t => {
                let tags: string[] = [];
                try { tags = JSON.parse(t.tags || '[]'); } catch { tags = []; }
                return (
                  <tr key={t.id} style={{ borderBottom: '1px solid var(--border)', opacity: t.enabled ? 1 : 0.6 }}>
                    <td style={{ padding: '10px 12px', fontSize: 10, fontFamily: 'monospace', color: 'var(--accent)' }}>{t.task_id}</td>
                    <td style={{ padding: '10px 12px', maxWidth: 220 }}>
                      <div style={{ fontWeight: 600, fontSize: 13 }}>{t.name}</div>
                      {t.description && <div style={{ fontSize: 11, color: 'var(--text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 200 }}>{t.description}</div>}
                      {tags.length > 0 && <div style={{ display: 'flex', gap: 3, marginTop: 3, flexWrap: 'wrap' }}>
                        {tags.slice(0, 3).map(tg => <span key={tg} style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3, background: 'var(--border)', color: 'var(--text-3)' }}>{tg}</span>)}
                      </div>}
                    </td>
                    <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-2)', textTransform: 'capitalize' }}>{(t.category||'').replace(/_/g,' ')}</td>
                    <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-2)', textTransform: 'capitalize' }}>{(t.task_type||'').replace(/_/g,' ')}</td>
                    <td style={{ padding: '10px 12px' }}>
                      <div style={{ fontSize: 11, color: 'var(--text-2)', textTransform: 'capitalize' }}>{(t.schedule_type||'').replace(/_/g,' ')}</div>
                      {t.cron_expr && <div style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--text-3)' }}>{t.cron_expr}</div>}
                    </td>
                    <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-2)' }}>{t.owner || '—'}</td>
                    <td style={{ padding: '10px 12px' }}>{pill(t.priority || 'medium', PRIORITY_COLOR[t.priority] || '#6b7280')}</td>
                    <td style={{ padding: '10px 12px' }}>{pill(t.enabled ? 'enabled' : 'disabled', t.enabled ? '#22c55e' : '#6b7280')}</td>
                    <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{t.last_run_at ? timeAgo(t.last_run_at) : '—'}</td>
                    <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{t.next_run_at ? timeAgo(t.next_run_at) : '—'}</td>
                    <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-2)' }}>
                      <span style={{ color: '#22c55e' }}>{t.success_count}</span>
                      <span style={{ color: 'var(--text-3)' }}>/</span>
                      <span style={{ color: '#ef4444' }}>{t.failure_count}</span>
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        <button className="g-btn g-btn-ghost" style={{ fontSize: 10, padding: '3px 8px' }} onClick={() => toggle(t)}>
                          {t.enabled ? 'Pause' : 'Enable'}
                        </button>
                        <button className="g-btn g-btn-primary" style={{ fontSize: 10, padding: '3px 8px' }} onClick={() => runNow(t)} disabled={running === t.id}>
                          {running === t.id ? '…' : '▶ Run'}
                        </button>
                        <button style={{ color: 'var(--text-3)', fontSize: 13 }} onClick={() => del(t)} disabled={deleting === t.id}>🗑</button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ─── Upcoming ──────────────────────────────────────────────────────────────
function UpcomingTab({ items }: { items: any[] }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 4 }}>Upcoming Scheduled Executions</div>
      {items.length === 0 && <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>No upcoming executions</div>}
      {items.map((u, i) => (
        <div key={i} className="g-card" style={{ padding: '14px 18px', display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{ fontSize: 22 }}>⏰</div>
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600, fontSize: 13 }}>{u.name}</div>
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>
              <span style={{ marginRight: 12 }}>Category: {(u.category||'').replace(/_/g,' ')}</span>
              <span style={{ marginRight: 12 }}>Type: {(u.task_type||'').replace(/_/g,' ')}</span>
              {u.owner && <span>Owner: {u.owner}</span>}
            </div>
            {u.cron_expr && <div style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--text-3)', marginTop: 3 }}>{u.cron_expr}</div>}
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--accent)' }}>{timeAgo(u.next_run_at)}</div>
            <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{new Date(u.next_run_at).toLocaleString()}</div>
          </div>
          {pill(u.priority || 'medium', PRIORITY_COLOR[u.priority] || '#6b7280')}
        </div>
      ))}
    </div>
  );
}

// ─── Execution History ─────────────────────────────────────────────────────
function HistoryTab({ execs }: { execs: any[] }) {
  const [filterStatus, setFilterStatus] = useState('');
  const [filterTrigger, setFilterTrigger] = useState('');
  const [search, setSearch] = useState('');

  const filtered = useMemo(() => execs.filter(e => {
    if (filterStatus && e.status !== filterStatus) return false;
    if (filterTrigger && e.trigger !== filterTrigger) return false;
    if (search) {
      const q = search.toLowerCase();
      return e.task_name.toLowerCase().includes(q) || e.execution_id.toLowerCase().includes(q) || (e.executed_by||'').toLowerCase().includes(q);
    }
    return true;
  }), [execs, filterStatus, filterTrigger, search]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <input className="g-input" placeholder="Search executions…" value={search} onChange={e => setSearch(e.target.value)} style={{ fontSize: 12, width: 220 }} />
        <select className="g-select" value={filterStatus} onChange={e => setFilterStatus(e.target.value)} style={{ fontSize: 11 }}>
          <option value="">All Status</option>
          {['running','completed','failed','cancelled'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="g-select" value={filterTrigger} onChange={e => setFilterTrigger(e.target.value)} style={{ fontSize: 11 }}>
          <option value="">All Triggers</option>
          {['scheduled','manual','alert','incident','playbook'].map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <span style={{ fontSize: 11, color: 'var(--text-3)', marginLeft: 'auto' }}>{filtered.length} results</span>
      </div>
      <div className="g-card" style={{ overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table className="g-table" style={{ width: '100%' }}>
            <thead className="g-thead">
              <tr>{['Execution ID','Task Name','Start Time','End Time','Duration','Status','Trigger','Executed By','Targets',''].map(h => (
                <th key={h} className="g-tr" style={{ padding: '8px 12px', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
              ))}</tr>
            </thead>
            <tbody>
              {filtered.length === 0 && <tr><td colSpan={9} style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)' }}>No executions found</td></tr>}
              {filtered.map(e => (
                <tr key={e.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '10px 12px', fontSize: 10, fontFamily: 'monospace', color: 'var(--accent)' }}>{e.execution_id}</td>
                  <td style={{ padding: '10px 12px', fontSize: 13, fontWeight: 500 }}>{e.task_name}</td>
                  <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(e.start_time)}</td>
                  <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{e.end_time ? timeAgo(e.end_time) : '—'}</td>
                  <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-2)' }}>{e.duration ? `${(e.duration/1000).toFixed(1)}s` : '—'}</td>
                  <td style={{ padding: '10px 12px' }}>{pill(e.status, STATUS_COLOR[e.status] || '#6b7280')}</td>
                  <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-2)', textTransform: 'capitalize' }}>{e.trigger}</td>
                  <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-2)' }}>{e.executed_by}</td>
                  <td style={{ padding: '10px 12px', fontSize: 11 }}>
                    <span style={{ color: '#22c55e' }}>{e.success_count || 0}✓</span>
                    {' '}
                    <span style={{ color: '#ef4444' }}>{e.failure_count || 0}✗</span>
                  </td>
                  <td style={{ padding: '10px 12px', fontSize: 11 }}>
                    {e.exit_code !== undefined && e.exit_code !== null && (
                      <span style={{ fontFamily: 'monospace', fontSize: 10, color: e.exit_code === 0 ? '#22c55e' : '#ef4444' }}>exit:{e.exit_code}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ─── Approvals ─────────────────────────────────────────────────────────────
function ApprovalsTab({ approvals, onRefresh }: { approvals: any[]; onRefresh: () => void }) {
  const [deciding, setDeciding] = useState<number | null>(null);
  const [note, setNote] = useState('');
  const [toast, setToast] = useState('');
  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(''), 3000); };

  const decide = async (id: number, decision: string) => {
    setDeciding(id);
    try {
      await steAPI.decideApproval(id, { decision, note });
      notify(`Task ${decision}`);
      onRefresh();
    } catch { notify('Decision failed'); }
    finally { setDeciding(null); setNote(''); }
  };

  const pending = approvals.filter(a => a.status === 'pending');
  const past = approvals.filter(a => a.status !== 'pending');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {toast && <div className="g-card" style={{ padding: '8px 14px', borderLeft: '3px solid var(--accent)', fontSize: 13 }}>{toast}</div>}
      <div>
        <div style={{ fontWeight: 600, marginBottom: 12 }}>Pending Approval ({pending.length})</div>
        {pending.length === 0 && <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-3)', fontSize: 13 }}>No pending approvals</div>}
        {pending.map(a => (
          <div key={a.id} className="g-card" style={{ padding: 16, marginBottom: 10, borderLeft: '3px solid #f97316' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
              <div>
                <div style={{ fontWeight: 600, fontSize: 13 }}>{a.task_name}</div>
                <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>
                  Requested by <strong>{a.requester}</strong> · {timeAgo(a.created_at)}
                  {a.policy && <span> · Policy: {a.policy.replace(/_/g,' ')}</span>}
                </div>
              </div>
              {pill('pending', '#f97316')}
            </div>
            {a.reason && <div style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 10, fontStyle: 'italic' }}>"{a.reason}"</div>}
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <input className="g-input" placeholder="Decision note (optional)…" value={deciding === a.id ? note : ''} onChange={e => setNote(e.target.value)} style={{ fontSize: 11, flex: 1 }} />
              <button className="g-btn g-btn-primary" style={{ fontSize: 11, background: '#22c55e', border: '1px solid #16a34a' }} onClick={() => decide(a.id, 'approved')} disabled={deciding === a.id}>
                ✓ Approve
              </button>
              <button className="g-btn g-btn-ghost" style={{ fontSize: 11, color: '#ef4444' }} onClick={() => decide(a.id, 'rejected')} disabled={deciding === a.id}>
                ✗ Reject
              </button>
            </div>
          </div>
        ))}
      </div>
      {past.length > 0 && (
        <div>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Past Decisions</div>
          <div className="g-card" style={{ overflow: 'hidden' }}>
            <table className="g-table" style={{ width: '100%' }}>
              <thead className="g-thead">
                <tr>{['Task','Requester','Approver','Decision','Note','Date'].map(h => (
                  <th key={h} className="g-tr" style={{ padding: '8px 12px', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left' }}>{h}</th>
                ))}</tr>
              </thead>
              <tbody>
                {past.map(a => (
                  <tr key={a.id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '10px 12px', fontSize: 13, fontWeight: 500 }}>{a.task_name}</td>
                    <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-2)' }}>{a.requester}</td>
                    <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-2)' }}>{a.approver || '—'}</td>
                    <td style={{ padding: '10px 12px' }}>{pill(a.status, STATUS_COLOR[a.status] || '#6b7280')}</td>
                    <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', fontStyle: 'italic' }}>{a.decision_note || '—'}</td>
                    <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{a.decided_at ? timeAgo(a.decided_at) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Notifications ─────────────────────────────────────────────────────────
function NotificationsTab({ notifications, onMarkRead }: { notifications: any[]; onMarkRead: () => void }) {
  const EVENT_ICON: Record<string, string> = {
    task_started: '▶', task_completed: '✓', task_failed: '✗',
    task_missed: '⚠', approval_required: '🔔', approval_approved: '✓',
    approval_rejected: '✗', schedule_modified: '✏',
  };
  const unread = notifications.filter(n => !n.read).length;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontWeight: 600 }}>Notifications {unread > 0 && <span style={{ fontSize: 11, background: '#3b82f622', color: '#3b82f6', borderRadius: 10, padding: '1px 8px', marginLeft: 6 }}>{unread} unread</span>}</div>
        {unread > 0 && <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={onMarkRead}>Mark all read</button>}
      </div>
      {notifications.length === 0 && <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>No notifications</div>}
      {notifications.map(n => (
        <div key={n.id} className="g-card" style={{ padding: '12px 16px', display: 'flex', gap: 12, alignItems: 'flex-start', opacity: n.read ? 0.6 : 1, borderLeft: `3px solid ${SEVERITY_COLOR[n.severity] || '#6b7280'}` }}>
          <div style={{ fontSize: 18, width: 24, textAlign: 'center', flexShrink: 0 }}>{EVENT_ICON[n.event_type] || '•'}</div>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 13, fontWeight: n.read ? 400 : 600 }}>{n.message}</div>
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 3 }}>
              {n.task_name && <span>{n.task_name} · </span>}
              <span style={{ textTransform: 'capitalize' }}>{n.event_type?.replace(/_/g,' ')}</span>
              {' · '}{timeAgo(n.created_at)}
            </div>
          </div>
          {pill(n.severity, SEVERITY_COLOR[n.severity] || '#6b7280')}
        </div>
      ))}
    </div>
  );
}

// ─── Analytics ─────────────────────────────────────────────────────────────
function AnalyticsTab({ data }: { data: any }) {
  if (!data) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading analytics…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Completed Executions" value={data.total_completed}                         color="#22c55e" />
        <StatCard label="Failed Executions"     value={data.total_failed}                           color="#ef4444" />
        <StatCard label="Success Rate"          value={`${(data.success_rate||0).toFixed(1)}%`}     color="#a855f7" />
        <StatCard label="Avg Duration"          value={`${((data.avg_duration_ms||0)/1000).toFixed(1)}s`} color="#f97316" />
        <StatCard label="Automation Hours Saved" value={`${(data.automation_hours||0).toFixed(1)}h`} color="#06b6d4" />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Executions by Category</div>
          {(!data.by_category || data.by_category.length === 0) && <div style={{ fontSize: 13, color: 'var(--text-3)' }}>No execution data yet</div>}
          {(data.by_category || []).map((c: any) => (
            <div key={c.category} style={{ marginBottom: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 3 }}>
                <span style={{ color: 'var(--text-2)', textTransform: 'capitalize' }}>{(c.category||'').replace(/_/g,' ')}</span>
                <div style={{ display: 'flex', gap: 10 }}>
                  <span style={{ fontWeight: 700, color: '#3b82f6' }}>{c.total} runs</span>
                  <span style={{ color: '#22c55e' }}>{(c.success_rate||0).toFixed(0)}% success</span>
                </div>
              </div>
              <div style={{ background: 'var(--border)', borderRadius: 3, height: 5 }}>
                <div style={{ background: c.success_rate > 80 ? '#22c55e' : c.success_rate > 50 ? '#f97316' : '#ef4444', borderRadius: 3, height: 5, width: `${c.success_rate||0}%` }} />
              </div>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Most Executed Task Types</div>
          {(!data.by_task_type || data.by_task_type.length === 0) && <div style={{ fontSize: 13, color: 'var(--text-3)' }}>No execution data yet</div>}
          {(data.by_task_type || []).map((t: any, i: number) => (
            <div key={t.task_type} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontSize: 12, color: 'var(--text-2)', textTransform: 'capitalize' }}>
                <span style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--text-3)', marginRight: 6 }}>#{i+1}</span>
                {(t.task_type||'').replace(/_/g,' ')}
              </span>
              <span style={{ fontWeight: 700, color: 'var(--accent)' }}>{t.executions}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Audit Trail ───────────────────────────────────────────────────────────
function AuditTab({ items }: { items: any[] }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      {items.length === 0 && <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>No audit events</div>}
      <div className="g-card" style={{ overflow: 'hidden' }}>
        <table className="g-table" style={{ width: '100%' }}>
          <thead className="g-thead">
            <tr>{['Time','Task','Action','Actor','Details'].map(h => (
              <th key={h} className="g-tr" style={{ padding: '8px 12px', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left' }}>{h}</th>
            ))}</tr>
          </thead>
          <tbody>
            {items.map(a => (
              <tr key={a.id} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(a.created_at)}</td>
                <td style={{ padding: '10px 12px', fontSize: 12, fontWeight: 500 }}>{a.task_name || a.task_id || '—'}</td>
                <td style={{ padding: '10px 12px' }}>{pill(a.action, ACTION_COLOR[a.action] || '#6b7280')}</td>
                <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-2)' }}>{a.actor}</td>
                <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', fontStyle: 'italic' }}>{a.details || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Reports ───────────────────────────────────────────────────────────────
function ReportsTab({ onGenerate }: { onGenerate: (type: string) => void }) {
  const [generating, setGenerating] = useState('');
  const [toast, setToast] = useState('');
  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(''), 3000); };
  const gen = async (type: string) => {
    setGenerating(type);
    await onGenerate(type);
    notify(`${type.replace(/_/g,' ')} report generated`);
    setGenerating('');
  };
  const reports = [
    { id: 'scheduled_task', label: 'Scheduled Task Report', desc: 'Full inventory of all scheduled tasks with configs and status' },
    { id: 'execution', label: 'Execution Report', desc: 'Detailed execution history with success/failure breakdown' },
    { id: 'failure', label: 'Failure Report', desc: 'Failed executions analysis with root cause summary' },
    { id: 'automation', label: 'Automation Report', desc: 'Automation coverage and time-saved metrics' },
    { id: 'audit', label: 'Audit Report', desc: 'Complete audit trail for compliance review' },
    { id: 'compliance', label: 'Compliance Report', desc: 'Compliance-focused task execution evidence' },
  ];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {toast && <div className="g-card" style={{ padding: '8px 14px', borderLeft: '3px solid var(--accent)', fontSize: 13 }}>{toast}</div>}
      <div style={{ fontWeight: 600, fontSize: 14 }}>Generate Reports</div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        {reports.map(r => (
          <div key={r.id} className="g-card" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{ fontWeight: 600, fontSize: 13 }}>{r.label}</div>
            <div style={{ fontSize: 12, color: 'var(--text-3)', flex: 1 }}>{r.desc}</div>
            <button className="g-btn g-btn-primary" style={{ fontSize: 11, alignSelf: 'flex-start' }} onClick={() => gen(r.id)} disabled={generating === r.id}>
              {generating === r.id ? 'Generating…' : '⬇ Generate'}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── AI Assistant ──────────────────────────────────────────────────────────
function AIPanel({ onClose }: { onClose: () => void }) {
  const [input, setInput] = useState('');
  const [response, setResponse] = useState('');
  const [loading, setLoading] = useState(false);
  const actions = [
    { id: 'generate_schedule', label: 'Generate Schedule' },
    { id: 'optimize_schedule', label: 'Optimize Schedule' },
    { id: 'detect_conflicts', label: 'Detect Conflicts' },
    { id: 'recommend_windows', label: 'Recommend Windows' },
    { id: 'explain_purpose', label: 'Explain Task Purpose' },
  ];
  const ask = async (action: string) => {
    setLoading(true);
    try {
      const r = await steAPI.ai({ action, context: input });
      setResponse((r.data as any)?.response || '');
    } catch { setResponse('AI assistant unavailable.'); }
    finally { setLoading(false); }
  };
  return (
    <div style={{ position: 'fixed', top: 0, right: 0, bottom: 0, width: 420, background: 'var(--glass-bg)', borderLeft: '1px solid var(--border)', zIndex: 100, display: 'flex', flexDirection: 'column', boxShadow: '-4px 0 24px rgba(0,0,0,0.3)' }}>
      <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontWeight: 700, fontSize: 14 }}>⚡ AI Schedule Assistant</div>
        <button onClick={onClose} style={{ fontSize: 18, color: 'var(--text-3)', lineHeight: 1 }}>×</button>
      </div>
      <div style={{ padding: 16, flex: 1, display: 'flex', flexDirection: 'column', gap: 12, overflow: 'auto' }}>
        <textarea className="g-input" placeholder="Describe your task, environment, or paste a config…" value={input} onChange={e => setInput(e.target.value)} style={{ fontSize: 12, minHeight: 80, resize: 'vertical' }} />
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {actions.map(a => (
            <button key={a.id} className="g-btn g-btn-ghost" style={{ fontSize: 11, justifyContent: 'flex-start' }} onClick={() => ask(a.id)} disabled={loading}>
              {a.label}
            </button>
          ))}
        </div>
        {loading && <div style={{ fontSize: 12, color: 'var(--text-3)', textAlign: 'center', padding: 12 }}>Analyzing…</div>}
        {response && (
          <div className="g-card" style={{ padding: 14, fontSize: 13, color: 'var(--text-1)', lineHeight: 1.7, whiteSpace: 'pre-wrap' }}>
            {response}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── New Task Modal ─────────────────────────────────────────────────────────
function NewTaskModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({
    name: '', description: '', category: 'security_operations', task_type: 'threat_hunt',
    script_language: '', owner: '', priority: 'medium',
    schedule_type: 'cron', cron_expr: '', target_type: 'all',
    max_runtime: 3600, retry_attempts: 3, retry_delay: 60, timeout: 300,
    parallel: false, concurrency_limit: 5,
    requires_approval: false, approval_policy: '',
    tags: '', enabled: true,
  });
  const [selectedTriggers, setSelectedTriggers] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const set = (k: string, v: any) => setForm(f => ({ ...f, [k]: v }));

  const save = async () => {
    if (!form.name) return;
    setSaving(true);
    try {
      await steAPI.createTask({
        ...form,
        trigger_conditions: JSON.stringify(selectedTriggers),
        tags: form.tags ? JSON.stringify(form.tags.split(',').map(s => s.trim()).filter(Boolean)) : '[]',
      });
      onCreated();
      onClose();
    } catch { setSaving(false); }
  };

  const section = (title: string, children: React.ReactNode) => (
    <div>
      <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 10, paddingBottom: 6, borderBottom: '1px solid var(--border)' }}>{title}</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>{children}</div>
    </div>
  );
  const field = (label: string, children: React.ReactNode) => (
    <div>
      <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>{label}</label>
      {children}
    </div>
  );

  return (
    <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="g-modal" style={{ maxWidth: 680, maxHeight: '90vh', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between' }}>
          <div style={{ fontWeight: 700, fontSize: 14 }}>New Scheduled Task</div>
          <button onClick={onClose} style={{ fontSize: 18, color: 'var(--text-3)' }}>×</button>
        </div>
        <div style={{ padding: 20, overflow: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: 20 }}>
          {section('Basic Info', <>
            {field('Task Name *', <input className="g-input w-full" value={form.name} onChange={e => set('name', e.target.value)} placeholder="e.g. Daily Threat Hunt" />)}
            {field('Description', <textarea className="g-input w-full" value={form.description} onChange={e => set('description', e.target.value)} placeholder="What does this task do?" style={{ minHeight: 56, resize: 'vertical' }} />)}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
              {field('Category', <select className="g-select w-full" value={form.category} onChange={e => set('category', e.target.value)}>
                {CATEGORIES.map(c => <option key={c} value={c}>{c.replace(/_/g,' ')}</option>)}
              </select>)}
              {field('Priority', <select className="g-select w-full" value={form.priority} onChange={e => set('priority', e.target.value)}>
                {['critical','high','medium','low'].map(p => <option key={p} value={p}>{p}</option>)}
              </select>)}
              {field('Owner', <input className="g-input w-full" value={form.owner} onChange={e => set('owner', e.target.value)} placeholder="analyst@corp.com" />)}
            </div>
          </>)}

          {section('Task Type', <>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              {field('Task Type', <select className="g-select w-full" value={form.task_type} onChange={e => set('task_type', e.target.value)}>
                {TASK_TYPES.map(g => (
                  <optgroup key={g.group} label={g.group}>
                    {g.values.map(v => <option key={v} value={v}>{v.replace(/_/g,' ')}</option>)}
                  </optgroup>
                ))}
              </select>)}
              {['powershell','bash','python','cmd','go_binary'].includes(form.task_type) && field('Script Language', <select className="g-select w-full" value={form.script_language} onChange={e => set('script_language', e.target.value)}>
                <option value="">Select language</option>
                {['powershell','bash','python','cmd','go'].map(l => <option key={l} value={l}>{l}</option>)}
              </select>)}
            </div>
          </>)}

          {section('Schedule', <>
            {field('Schedule Type', <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {SCHEDULE_TYPES.map(s => (
                <button key={s} type="button" onClick={() => set('schedule_type', s)} style={{ fontSize: 10, padding: '3px 10px', borderRadius: 8, background: form.schedule_type === s ? 'var(--accent-glow)' : 'var(--glass-bg)', border: `1px solid ${form.schedule_type === s ? 'var(--accent-border)' : 'var(--border)'}`, color: form.schedule_type === s ? 'var(--accent)' : 'var(--text-2)' }}>
                  {s.replace(/_/g,' ')}
                </button>
              ))}
            </div>)}
            {form.schedule_type === 'cron' && field('Cron Expression', <>
              <div style={{ display: 'flex', gap: 6, marginBottom: 8, flexWrap: 'wrap' }}>
                {CRON_PRESETS.map(p => (
                  <button key={p.value} type="button" onClick={() => set('cron_expr', p.value)} style={{ fontSize: 10, padding: '3px 10px', borderRadius: 8, background: form.cron_expr === p.value ? 'var(--accent-glow)' : 'var(--glass-bg)', border: `1px solid ${form.cron_expr === p.value ? 'var(--accent-border)' : 'var(--border)'}`, color: form.cron_expr === p.value ? 'var(--accent)' : 'var(--text-2)' }}>
                    {p.label}
                  </button>
                ))}
              </div>
              <input className="g-input w-full" style={{ fontFamily: 'monospace', fontSize: 12 }} value={form.cron_expr} onChange={e => set('cron_expr', e.target.value)} placeholder="0 2 * * *" />
            </>)}
          </>)}

          {section('Execution Target', <>
            {field('Target Type', <select className="g-select w-full" value={form.target_type} onChange={e => set('target_type', e.target.value)}>
              {TARGET_TYPES.map(t => <option key={t} value={t}>{t.replace(/_/g,' ')}</option>)}
            </select>)}
          </>)}

          {section('Trigger Conditions', <>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {TRIGGER_CONDITIONS.map(t => {
                const active = selectedTriggers.includes(t);
                return (
                  <button key={t} type="button" onClick={() => setSelectedTriggers(prev => active ? prev.filter(x => x !== t) : [...prev, t])} style={{ fontSize: 10, padding: '3px 10px', borderRadius: 8, background: active ? 'var(--accent-glow)' : 'var(--glass-bg)', border: `1px solid ${active ? 'var(--accent-border)' : 'var(--border)'}`, color: active ? 'var(--accent)' : 'var(--text-2)' }}>
                    {t.replace(/_/g,' ')}
                  </button>
                );
              })}
            </div>
          </>)}

          {section('Execution Controls', <>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 10 }}>
              {field('Max Runtime (s)', <input className="g-input w-full" type="number" value={form.max_runtime} onChange={e => set('max_runtime', +e.target.value)} />)}
              {field('Retry Attempts', <input className="g-input w-full" type="number" value={form.retry_attempts} onChange={e => set('retry_attempts', +e.target.value)} />)}
              {field('Retry Delay (s)', <input className="g-input w-full" type="number" value={form.retry_delay} onChange={e => set('retry_delay', +e.target.value)} />)}
              {field('Timeout (s)', <input className="g-input w-full" type="number" value={form.timeout} onChange={e => set('timeout', +e.target.value)} />)}
            </div>
            <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: 'pointer' }}>
                <input type="checkbox" checked={form.parallel} onChange={e => set('parallel', e.target.checked)} />
                Parallel Execution
              </label>
              {form.parallel && field('Concurrency Limit', <input className="g-input" type="number" value={form.concurrency_limit} onChange={e => set('concurrency_limit', +e.target.value)} style={{ width: 80 }} />)}
            </div>
          </>)}

          {section('Approval Workflow', <>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: 'pointer' }}>
              <input type="checkbox" checked={form.requires_approval} onChange={e => set('requires_approval', e.target.checked)} />
              Require Approval Before Execution
            </label>
            {form.requires_approval && field('Approval Policy', <select className="g-select w-full" value={form.approval_policy} onChange={e => set('approval_policy', e.target.value)}>
              <option value="">Select policy</option>
              {APPROVAL_POLICIES.map(p => <option key={p} value={p}>{p.replace(/_/g,' ')}</option>)}
            </select>)}
          </>)}

          {section('Tags', <>
            {field('Tags (comma-separated)', <input className="g-input w-full" value={form.tags} onChange={e => set('tags', e.target.value)} placeholder="threat-hunt, critical, daily" />)}
          </>)}
        </div>
        <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)', display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <button className="g-btn g-btn-ghost" onClick={onClose}>Cancel</button>
          <button className="g-btn g-btn-primary" onClick={save} disabled={saving || !form.name}>
            {saving ? 'Creating…' : 'Create Task'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Page ───────────────────────────────────────────────────────────────────
export default function ScheduledTasksPage() {
  const [tab, setTab] = useState<Tab>('dashboard');
  const [dash, setDash] = useState<any>(null);
  const [tasks, setTasks] = useState<any[]>([]);
  const [execs, setExecs] = useState<any[]>([]);
  const [upcoming, setUpcoming] = useState<any[]>([]);
  const [approvals, setApprovals] = useState<any[]>([]);
  const [notifications, setNotifications] = useState<any[]>([]);
  const [analytics, setAnalytics] = useState<any>(null);
  const [audit, setAudit] = useState<any[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [showAI, setShowAI] = useState(false);
  const [toast, setToast] = useState('');
  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(''), 3000); };

  const loadAll = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const [d, t, e, u, a, n, an, au] = await Promise.all([
        steAPI.getDashboard(),
        steAPI.getTasks(),
        steAPI.getExecutions(),
        steAPI.getUpcoming(),
        steAPI.getApprovals(),
        steAPI.getNotifications(),
        steAPI.getAnalytics(),
        steAPI.getAudit(),
      ]);
      setDash(d.data);
      setTasks((t.data as any) || []);
      setExecs((e.data as any) || []);
      setUpcoming((u.data as any) || []);
      setApprovals((a.data as any) || []);
      setNotifications((n.data as any) || []);
      setAnalytics(an.data);
      setAudit((au.data as any) || []);
    } finally { setRefreshing(false); }
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  const markRead = async () => {
    await steAPI.markNotificationsRead();
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
  };

  const genReport = async (type: string) => {
    await steAPI.report({ report_type: type });
  };

  const unreadCount = notifications.filter(n => !n.read).length;
  const pendingApprovals = approvals.filter(a => a.status === 'pending').length;

  return (
    <RootLayout
      title="Scheduled Tasks"
      subtitle="Enterprise automation scheduling & orchestration platform"
      onRefresh={() => loadAll(true)}
      refreshing={refreshing}
      actions={
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={() => setShowAI(v => !v)}>⚡ AI</button>
          <button className="g-btn g-btn-primary" style={{ fontSize: 11 }} onClick={() => setShowNew(true)}>+ New Task</button>
        </div>
      }
    >
      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)' }}>{toast}</div>}

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', marginBottom: 20, overflowX: 'auto' }}>
        {TABS.map(t => {
          const badge = t.id === 'approvals' ? pendingApprovals : t.id === 'notifications' ? unreadCount : 0;
          return (
            <button key={t.id} onClick={() => setTab(t.id)} style={{
              padding: '10px 16px', fontSize: 12, fontWeight: tab === t.id ? 700 : 400,
              color: tab === t.id ? 'var(--accent)' : 'var(--text-2)',
              borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
              background: 'none', whiteSpace: 'nowrap', position: 'relative',
            }}>
              {t.label}
              {badge > 0 && (
                <span style={{ position: 'absolute', top: 6, right: 4, fontSize: 8, fontWeight: 700, background: '#ef4444', color: '#fff', borderRadius: 8, padding: '1px 4px', minWidth: 14, textAlign: 'center' }}>{badge}</span>
              )}
            </button>
          );
        })}
      </div>

      {tab === 'dashboard'     && <DashboardTab dash={dash} onTabChange={setTab} />}
      {tab === 'tasks'         && <TasksTab tasks={tasks} onRefresh={() => loadAll()} onNew={() => setShowNew(true)} />}
      {tab === 'upcoming'      && <UpcomingTab items={upcoming} />}
      {tab === 'history'       && <HistoryTab execs={execs} />}
      {tab === 'approvals'     && <ApprovalsTab approvals={approvals} onRefresh={() => loadAll()} />}
      {tab === 'notifications' && <NotificationsTab notifications={notifications} onMarkRead={markRead} />}
      {tab === 'analytics'     && <AnalyticsTab data={analytics} />}
      {tab === 'audit'         && <AuditTab items={audit} />}
      {tab === 'reports'       && <ReportsTab onGenerate={genReport} />}

      {showNew && <NewTaskModal onClose={() => setShowNew(false)} onCreated={() => { loadAll(); notify('Task created'); }} />}
      {showAI && <AIPanel onClose={() => setShowAI(false)} />}
    </RootLayout>
  );
}
