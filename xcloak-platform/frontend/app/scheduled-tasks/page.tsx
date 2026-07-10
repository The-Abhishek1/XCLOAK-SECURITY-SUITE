'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import api from '@/lib/api';
import { Plus, Play, Trash2, ToggleLeft, ToggleRight, Clock, X, Cpu, Check, Activity } from 'lucide-react';
import { Agent } from '@/types';
import { timeAgo } from '@/lib/utils';

const TASK_TYPES = [
  'collect_processes', 'collect_connections', 'collect_services',
  'collect_packages', 'collect_users', 'collect_auth_logs',
  'collect_file_hashes', 'fim_scan', 'vulnerability_scan',
];

const CRON_PRESETS = [
  { label: 'Every 5 min',  value: '*/5 * * * *' },
  { label: 'Every 15 min', value: '*/15 * * * *' },
  { label: 'Every hour',   value: '0 * * * *' },
  { label: 'Every 6h',     value: '0 */6 * * *' },
  { label: 'Daily',        value: '0 0 * * *' },
];

interface ScheduledTask {
  id: number;
  name: string;
  task_type: string;
  agent_ids: number[];
  cron_expr: string;
  enabled: boolean;
  last_run_at: string | null;
  next_run_at: string | null;
  run_count: number;
  created_by: string;
}

export default function ScheduledTasksPage() {
  const [tasks, setTasks]         = useState<ScheduledTask[]>([]);
  const [agents, setAgents]       = useState<Agent[]>([]);
  const [loading, setLoading]     = useState(true);
  const [showNew, setShowNew]     = useState(false);
  const [form, setForm]           = useState({ name: '', task_type: 'collect_auth_logs', cron_expr: '*/15 * * * *' });
  const [selectedAgents, setSelectedAgents] = useState<number[]>([]);
  const [saving, setSaving]       = useState(false);
  const [toast, setToast]         = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try { const r = await api.get('/scheduler/tasks'); setTasks(r.data || []); }
    finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    api.get('/agents').then(r => setAgents(r.data || [])).catch(() => {});
  }, []);

  const toggleAgent = (id: number) =>
    setSelectedAgents(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);

  const openNew = () => {
    setForm({ name: '', task_type: 'collect_auth_logs', cron_expr: '*/15 * * * *' });
    setSelectedAgents([]);
    setShowNew(true);
  };

  const create = async () => {
    if (!form.name || !form.cron_expr) return;
    setSaving(true);
    try {
      await api.post('/scheduler/tasks', {
        name: form.name, task_type: form.task_type,
        cron_expr: form.cron_expr, agent_ids: selectedAgents,
      });
      setShowNew(false);
      load();
      notify('Scheduled task created');
    } catch { notify('Failed to create task'); }
    finally { setSaving(false); }
  };

  const toggle = async (id: number, enabled: boolean) => {
    await api.patch(`/scheduler/tasks/${id}/toggle`, { enabled: !enabled });
    setTasks(t => t.map(x => x.id === id ? { ...x, enabled: !enabled } : x));
  };

  const runNow = async (id: number) => {
    await api.post(`/scheduler/tasks/${id}/run`, {});
    notify('Task dispatched to agents');
    setTimeout(() => load(), 1000);
  };

  const del = async (id: number) => {
    await api.delete(`/scheduler/tasks/${id}`);
    setTasks(t => t.filter(x => x.id !== id));
    notify('Deleted');
  };

  return (
    <RootLayout title="Scheduled Tasks" subtitle="Recurring automated agent data collection"
      onRefresh={() => load(true)} refreshing={refreshing}
      actions={
        <button onClick={openNew} className="g-btn g-btn-primary text-xs">
          <Plus className="h-3.5 w-3.5" /> New Schedule
        </button>
      }>

      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)' }}>{toast}</div>}

      {!loading && tasks.length > 0 && (
        <div className="grid grid-cols-3 gap-3 mb-4">
          {[
            { label: 'Total Schedules', value: tasks.length, icon: Clock, color: 'var(--accent)' },
            { label: 'Enabled',         value: tasks.filter(t => t.enabled).length, icon: Activity, color: 'var(--green)' },
            { label: 'Total Runs',      value: tasks.reduce((s, t) => s + t.run_count, 0), icon: Cpu, color: '#fbbf24' },
          ].map(({ label, value, icon: Icon, color }) => (
            <div key={label} className="g-card p-4 flex items-center gap-3">
              <div className="p-2 rounded-lg" style={{ background: `${color}18`, border: `1px solid ${color}30` }}>
                <Icon className="h-4 w-4" style={{ color }} />
              </div>
              <div>
                <p className="text-xl font-bold" style={{ color }}>{value}</p>
                <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{label}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="space-y-3">
        {loading ? (
          <div className="py-12 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
        ) : tasks.length === 0 ? (
          <div className="g-card py-16 text-center">
            <Clock className="mx-auto h-10 w-10 mb-3" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No scheduled tasks yet.</p>
            <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>Create a schedule to automatically collect data from all agents.</p>
          </div>
        ) : tasks.map(task => (
          <div key={task.id} className="g-card px-5 py-4 flex items-center gap-4">
            {/* Toggle */}
            <button onClick={() => toggle(task.id, task.enabled)}>
              {task.enabled
                ? <ToggleRight className="h-5 w-5" style={{ color: 'var(--accent)' }} />
                : <ToggleLeft  className="h-5 w-5" style={{ color: 'var(--text-3)' }} />}
            </button>

            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <p className="text-sm font-medium" style={{ color: 'var(--text-1)' }}>{task.name}</p>
                <span className="mono text-[10px] rounded px-2 py-0.5"
                  style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)', color: 'var(--accent)' }}>
                  {task.task_type}
                </span>
                {!task.enabled && (
                  <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>disabled</span>
                )}
              </div>
              <div className="flex items-center gap-4 mt-1 text-[11px]" style={{ color: 'var(--text-3)' }}>
                <span className="mono">{task.cron_expr}</span>
                {task.agent_ids?.length > 0
                  ? <span>Agents: {task.agent_ids.join(', ')}</span>
                  : <span>All agents</span>}
                {task.last_run_at && <span>Last: {timeAgo(task.last_run_at)}</span>}
                {task.next_run_at && <span>Next: {timeAgo(task.next_run_at)}</span>}
                <span>{task.run_count} runs</span>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <button onClick={() => runNow(task.id)}
                className="g-btn g-btn-ghost text-xs">
                <Play className="h-3.5 w-3.5" /> Run now
              </button>
              <button onClick={() => del(task.id)} style={{ color: 'var(--text-3)' }}
                onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--red)'}
                onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                <Trash2 className="h-4 w-4" />
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* New task modal */}
      {showNew && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setShowNew(false)}>
          <div className="g-modal" style={{ maxWidth: 500 }}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>New Scheduled Task</h2>
              <button onClick={() => setShowNew(false)} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>
            <div className="p-5 space-y-4">
              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Name</label>
                <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  placeholder="e.g. Hourly auth log collection" className="g-input w-full" />
              </div>

              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Task Type</label>
                <select value={form.task_type} onChange={e => setForm(f => ({ ...f, task_type: e.target.value }))}
                  className="g-select w-full">
                  {TASK_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>

              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Schedule (cron)</label>
                <div className="flex gap-2 mb-2 flex-wrap">
                  {CRON_PRESETS.map(p => (
                    <button key={p.value} onClick={() => setForm(f => ({ ...f, cron_expr: p.value }))}
                      className="text-[11px] px-2.5 py-1 rounded-lg"
                      style={{
                        background: form.cron_expr === p.value ? 'var(--accent-glow)' : 'var(--glass-bg)',
                        border: `1px solid ${form.cron_expr === p.value ? 'var(--accent-border)' : 'var(--border)'}`,
                        color: form.cron_expr === p.value ? 'var(--accent)' : 'var(--text-2)',
                      }}>
                      {p.label}
                    </button>
                  ))}
                </div>
                <input value={form.cron_expr} onChange={e => setForm(f => ({ ...f, cron_expr: e.target.value }))}
                  placeholder="*/15 * * * *" className="g-input w-full font-mono" />
              </div>

              <div>
                <label className="text-xs mb-1.5 block" style={{ color: 'var(--text-3)' }}>
                  Target Agents
                  <span className="ml-1.5" style={{ color: 'var(--text-3)', fontWeight: 400 }}>
                    ({selectedAgents.length === 0 ? 'all agents' : `${selectedAgents.length} selected`})
                  </span>
                </label>
                {agents.length === 0 ? (
                  <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>No agents registered yet.</p>
                ) : (
                  <div className="rounded-xl overflow-hidden max-h-40 overflow-y-auto"
                    style={{ border: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
                    {agents.map(a => {
                      const checked = selectedAgents.includes(a.id);
                      return (
                        <button key={a.id} type="button"
                          onClick={() => toggleAgent(a.id)}
                          className="flex items-center gap-3 w-full px-3 py-2 text-left transition-colors"
                          style={{ borderBottom: '1px solid var(--border)' }}
                          onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--glass-hover)'}
                          onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}>
                          <div className="h-4 w-4 rounded flex items-center justify-center shrink-0"
                            style={{
                              background: checked ? 'var(--accent-glow)' : 'transparent',
                              border: `1px solid ${checked ? 'var(--accent)' : 'var(--border-md)'}`,
                            }}>
                            {checked && <Check className="h-2.5 w-2.5" style={{ color: 'var(--accent)' }} />}
                          </div>
                          <Cpu className="h-3 w-3 shrink-0" style={{ color: 'var(--text-3)' }} />
                          <span className="text-[11px] flex-1 min-w-0 truncate" style={{ color: 'var(--text-1)' }}>
                            {a.hostname}
                          </span>
                          <span className="text-[9px] shrink-0 px-1.5 py-0.5 rounded-full"
                            style={{
                              background: a.status === 'online' ? 'var(--green-bg)' : 'var(--glass-bg-2)',
                              color: a.status === 'online' ? 'var(--green)' : 'var(--text-3)',
                            }}>
                            {a.status}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                )}
                {selectedAgents.length > 0 && (
                  <button type="button" onClick={() => setSelectedAgents([])}
                    className="mt-1 text-[10px]" style={{ color: 'var(--text-3)' }}>
                    Clear selection (run on all agents)
                  </button>
                )}
              </div>
            </div>
            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => setShowNew(false)} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={create} disabled={saving || !form.name}
                className="g-btn g-btn-primary flex-1 justify-center">
                {saving ? 'Creating…' : 'Create Schedule'}
              </button>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
