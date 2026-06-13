'use client';

import { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { RootLayout } from '@/components/layout/RootLayout';
import { agentsAPI, tasksAPI } from '@/lib/api';
import { Agent } from '@/types';
import { timeAgo } from '@/lib/utils';
import { Cpu, Search, Play, ChevronRight, Wifi, WifiOff, X, Plus, Minus } from 'lucide-react';

// Tasks with payload requirements
const TASK_DEFS = [
  { v: 'collect_processes',   l: 'Collect Processes',    payload: 'none' },
  { v: 'collect_connections', l: 'Collect Connections',  payload: 'none' },
  { v: 'collect_services',    l: 'Collect Services',     payload: 'none' },
  { v: 'collect_packages',    l: 'Collect Packages',     payload: 'none' },
  { v: 'collect_users',       l: 'Collect Users',        payload: 'none' },
  { v: 'collect_auth_logs',   l: 'Collect Auth Logs',    payload: 'none' },
  { v: 'collect_file_hashes', l: 'Scan File Hashes',     payload: 'none' },
  { v: 'collect_file',        l: 'Collect File',         payload: 'path', placeholder: '/tmp/suspicious.sh' },
  { v: 'scan_yara',           l: 'YARA Scan',            payload: 'path', placeholder: '/tmp/test.sh' },
  { v: 'kill_process',        l: 'Kill Process',         payload: 'pid',  placeholder: '1234' },
  { v: 'execute_script',      l: 'Execute Script',       payload: 'script', placeholder: 'hostname && whoami' },
  { v: 'isolate_host',        l: 'Isolate Host',         payload: 'none' },
  { v: 'vulnerability_scan',  l: 'Vulnerability Scan',   payload: 'none' },
];

interface TaskItem {
  id: string;
  task_type: string;
  payload_value: string;
}

export default function AgentsPage() {
  const [agents, setAgents]   = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch]   = useState('');
  const [modal, setModal]     = useState<Agent | null>(null);
  const [tasks, setTasks]     = useState<TaskItem[]>([{ id: '1', task_type: 'collect_processes', payload_value: '' }]);
  const [dispatching, setDispatching] = useState(false);
  const [toast, setToast]     = useState<string | null>(null);

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try { const r = await agentsAPI.getAll(); setAgents(r.data || []); }
    finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const addTask = () => setTasks(p => [...p, { id: String(Date.now()), task_type: 'collect_processes', payload_value: '' }]);
  const removeTask = (id: string) => setTasks(p => p.filter(t => t.id !== id));
  const updateTask = (id: string, field: 'task_type' | 'payload_value', val: string) => {
    setTasks(p => p.map(t => t.id === id ? { ...t, [field]: val } : t));
  };

  const buildPayload = (task: TaskItem): any => {
    const def = TASK_DEFS.find(d => d.v === task.task_type);
    if (!def || def.payload === 'none') return {};
    if (def.payload === 'path')   return { path: task.payload_value };
    if (def.payload === 'pid')    return { pid: parseInt(task.payload_value) || 0 };
    if (def.payload === 'script') return { script: task.payload_value };
    return {};
  };

  const dispatchAll = async () => {
    if (!modal) return;
    setDispatching(true);
    let ok = 0, fail = 0;
    for (const task of tasks) {
      try {
        await tasksAPI.create({ agent_id: modal.id, task_type: task.task_type, payload: buildPayload(task) });
        ok++;
      } catch { fail++; }
    }
    setToast(`✓ ${ok} task${ok !== 1 ? 's' : ''} dispatched${fail > 0 ? ` · ${fail} failed` : ''}`);
    setTimeout(() => setToast(null), 4000);
    setModal(null);
    setDispatching(false);
    setTasks([{ id: '1', task_type: 'collect_processes', payload_value: '' }]);
  };

  const filtered = agents.filter(a =>
    !search || a.hostname?.toLowerCase().includes(search.toLowerCase())
      || a.ip_address?.includes(search) || a.os?.toLowerCase().includes(search.toLowerCase())
  );

  const online = agents.filter(a => a.status === 'online').length;

  return (
    <RootLayout title="Agents" subtitle={`${online}/${agents.length} online`}
      onRefresh={() => load(true)} refreshing={refreshing}>

      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)', minWidth: 240 }}>{toast}</div>}

      <div className="space-y-4">
        <div className="relative max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search hostname, IP, OS…" className="g-input pl-9" />
        </div>

        {loading ? (
          <div className="py-20 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
        ) : filtered.length === 0 ? (
          <div className="py-20 text-center">
            <Cpu className="mx-auto h-10 w-10 mb-2" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No agents found</p>
          </div>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
            {filtered.map(agent => (
              <div key={agent.id} className="g-card overflow-hidden">
                <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <div className="flex h-9 w-9 items-center justify-center rounded-xl shrink-0"
                        style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
                        {agent.status === 'online'
                          ? <Wifi className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                          : <WifiOff className="h-4 w-4" style={{ color: 'var(--text-3)' }} />}
                      </div>
                      <div className="min-w-0">
                        <p className="text-sm font-semibold truncate" style={{ color: 'var(--text-1)' }}>{agent.hostname}</p>
                        <p className="text-xs" style={{ color: 'var(--text-3)' }}>{agent.ip_address}</p>
                      </div>
                    </div>
                    <span className={agent.status === 'online' ? 's-online' : 's-offline'}>{agent.status}</span>
                  </div>
                  <div className="space-y-1.5 text-xs">
                    {[['OS', agent.os || '—'], ['Last seen', timeAgo(agent.last_seen)]].map(([k, v]) => (
                      <div key={k} className="flex justify-between">
                        <span style={{ color: 'var(--text-3)' }}>{k}</span>
                        <span style={{ color: 'var(--text-2)' }}>{v}</span>
                      </div>
                    ))}
                  </div>
                </div>
                <div className="flex items-center px-4 py-2.5 gap-2">
                  <button onClick={() => { setModal(agent); setTasks([{ id: '1', task_type: 'collect_processes', payload_value: '' }]); }}
                    className="g-btn g-btn-ghost text-xs" style={{ fontSize: 11 }}>
                    <Play className="h-3 w-3" /> Tasks
                  </button>
                  <div className="flex-1" />
                  <Link href={`/agents/${agent.id}`}
                    className="g-btn text-xs"
                    style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)', fontSize: 11 }}>
                    Details <ChevronRight className="h-3 w-3" />
                  </Link>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Multi-task dispatch modal */}
      {modal && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setModal(null)}>
          <div className="g-modal" style={{ maxWidth: 520 }}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <div>
                <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Dispatch Tasks</h2>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-3)' }}>{modal.hostname} · {modal.ip_address}</p>
              </div>
              <button onClick={() => setModal(null)} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>

            <div className="p-5 space-y-3 max-h-[50vh] overflow-y-auto">
              {tasks.map((task, idx) => {
                const def = TASK_DEFS.find(d => d.v === task.task_type);
                return (
                  <div key={task.id} className="rounded-xl p-3 space-y-2"
                    style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-medium shrink-0" style={{ color: 'var(--text-3)' }}>#{idx + 1}</span>
                      <select value={task.task_type}
                        onChange={e => updateTask(task.id, 'task_type', e.target.value)}
                        className="g-select flex-1" style={{ height: 34 }}>
                        {TASK_DEFS.map(d => <option key={d.v} value={d.v}>{d.l}</option>)}
                      </select>
                      {tasks.length > 1 && (
                        <button onClick={() => removeTask(task.id)} className="shrink-0 p-1 rounded"
                          style={{ color: 'var(--text-3)' }}
                          onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--red)'}
                          onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                          <Minus className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </div>
                    {def && def.payload !== 'none' && (
                      <input value={task.payload_value}
                        onChange={e => updateTask(task.id, 'payload_value', e.target.value)}
                        placeholder={def.placeholder}
                        className="g-input mono text-xs"
                        style={{ height: 32 }} />
                    )}
                  </div>
                );
              })}

              <button onClick={addTask}
                className="w-full g-btn g-btn-ghost text-xs justify-center"
                style={{ border: '1px dashed var(--border)' }}>
                <Plus className="h-3.5 w-3.5" /> Add another task
              </button>
            </div>

            <div className="flex gap-3 p-5 pt-0">
              <button onClick={() => setModal(null)} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={dispatchAll} disabled={dispatching} className="g-btn g-btn-primary flex-1 justify-center">
                {dispatching ? 'Dispatching…' : `Dispatch ${tasks.length} Task${tasks.length !== 1 ? 's' : ''}`}
              </button>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
