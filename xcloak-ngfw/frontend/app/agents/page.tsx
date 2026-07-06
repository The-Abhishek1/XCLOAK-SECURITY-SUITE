'use client';

import { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { RootLayout } from '@/components/layout/RootLayout';
import { agentsAPI, tasksAPI } from '@/lib/api';
import api from '@/lib/api';
import { Agent } from '@/types';
import { timeAgo } from '@/lib/utils';
import { Cpu, Search, Play, ChevronRight, Wifi, WifiOff, X, Plus, Minus, Heart, Key, Copy, Check, Terminal, ShieldCheck, ArrowRight, RefreshCw, Activity, ShieldOff, Monitor } from 'lucide-react';

interface AgentHealth {
  agent_id: number;
  health_score: number;
  health_status: string;
  heartbeat_gap_s: number;
  alert_rate_1h: number;
}

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
  const [agents, setAgents]     = useState<Agent[]>([]);
  const [health, setHealth]     = useState<Map<number, AgentHealth>>(new Map());
  const [loading, setLoading]   = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch]     = useState('');
  const [modal, setModal]         = useState<Agent | null>(null);
  const [showOnboard, setShowOnboard] = useState(false);
  const [genToken, setGenToken]       = useState('');
  const [tokenLabel, setTokenLabel]   = useState('');
  const [genLoading, setGenLoading]   = useState(false);
  const [copied, setCopied]           = useState(false);
  const [onboardStep, setOnboardStep] = useState(1);
  const [tasks, setTasks]       = useState<TaskItem[]>([{ id: '1', task_type: 'collect_processes', payload_value: '' }]);
  const [dispatching, setDispatching] = useState(false);
  const [toast, setToast]       = useState<string | null>(null);
  const [statusTab, setStatusTab] = useState<'all' | 'online' | 'offline'>('all');
  const [isolating, setIsolating] = useState<number | null>(null);

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const [agentRes, healthRes] = await Promise.allSettled([
        agentsAPI.getAll(),
        api.get('/agents/health').catch(() => ({ data: [] })),
      ]);
      if (agentRes.status === 'fulfilled') setAgents(agentRes.value.data || []);
      if (healthRes.status === 'fulfilled') {
        const hMap = new Map<number, AgentHealth>();
        (healthRes.value.data || []).forEach((h: AgentHealth) => hMap.set(h.agent_id, h));
        setHealth(hMap);
      }
    }
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

  const isolateAgent = async (agent: Agent) => {
    if (!confirm(`Isolate ${agent.hostname}? This will block all network traffic except to the XCloak server.`)) return;
    setIsolating(agent.id);
    try {
      await tasksAPI.create({ agent_id: agent.id, task_type: 'isolate_host', payload: {} });
      notify(`Isolation task dispatched to ${agent.hostname}`);
    } catch { notify('Isolation dispatch failed'); }
    finally { setIsolating(null); }
  };

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 4000); };

  const filtered = agents
    .filter(a => statusTab === 'all' ? true : statusTab === 'online' ? a.status === 'online' : a.status !== 'online')
    .filter(a =>
      !search || a.hostname?.toLowerCase().includes(search.toLowerCase())
        || a.ip_address?.includes(search) || a.os?.toLowerCase().includes(search.toLowerCase())
    );

  const online = agents.filter(a => a.status === 'online').length;

  return (
    <RootLayout title="Agents" subtitle={`${online}/${agents.length} online`}
      actions={
        <a href="/agents/onwards"
          className="g-btn g-btn-primary text-xs flex items-center gap-1.5">
          <Plus className="h-3.5 w-3.5" /> Add Agent
        </a>
      }
      onRefresh={() => load(true)} refreshing={refreshing}>

      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)', minWidth: 240 }}>{toast}</div>}

      <div className="space-y-4">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search hostname, IP, OS…" className="g-input pl-9" />
          </div>

          {/* Status tabs */}
          <div className="flex rounded-lg overflow-hidden" style={{ border: '1px solid var(--border)' }}>
            {(['all', 'online', 'offline'] as const).map(tab => {
              const count = tab === 'all' ? agents.length : agents.filter(a => tab === 'online' ? a.status === 'online' : a.status !== 'online').length;
              return (
                <button key={tab} onClick={() => setStatusTab(tab)}
                  className="px-3 py-1.5 text-[11px] font-semibold capitalize transition-all flex items-center gap-1.5"
                  style={{
                    background: statusTab === tab ? 'var(--accent)' : 'transparent',
                    color: statusTab === tab ? '#fff' : 'var(--text-3)',
                  }}>
                  {tab === 'online' && <span className="h-1.5 w-1.5 rounded-full bg-green-400" />}
                  {tab === 'offline' && <span className="h-1.5 w-1.5 rounded-full bg-gray-500" />}
                  {tab} <span className="opacity-70">({count})</span>
                </button>
              );
            })}
          </div>
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
                    {/* Version + risk row */}
                    {(agent.version || (agent.risk_score !== undefined && agent.risk_score !== null)) && (
                      <div className="flex items-center justify-between gap-2 mt-1">
                        {agent.version ? (
                          <span className="mono text-[10px] px-1.5 py-0.5 rounded"
                            style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)', color: 'var(--text-3)' }}>
                            v{agent.version}
                          </span>
                        ) : <span />}
                        {agent.risk_score !== undefined && agent.risk_score !== null && (
                          <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded"
                            style={{
                              background: agent.risk_score >= 70 ? 'var(--red-bg)' : agent.risk_score >= 40 ? 'rgba(251,146,60,0.12)' : 'rgba(52,211,153,0.1)',
                              color: agent.risk_score >= 70 ? 'var(--red)' : agent.risk_score >= 40 ? 'var(--orange)' : 'var(--green)',
                              border: `1px solid ${agent.risk_score >= 70 ? 'var(--red-border)' : agent.risk_score >= 40 ? 'rgba(251,146,60,0.3)' : 'rgba(52,211,153,0.3)'}`,
                            }}>
                            Risk {agent.risk_score}
                          </span>
                        )}
                      </div>
                    )}
                    {/* Health score + alert rate */}
                    {health.has(agent.id) && (() => {
                      const h = health.get(agent.id)!;
                      const color = h.health_score >= 80 ? 'var(--green)' : h.health_score >= 50 ? 'var(--orange)' : 'var(--red)';
                      return (
                        <div className="space-y-1.5 mt-2 pt-2" style={{ borderTop: '1px solid var(--border)' }}>
                          <div className="flex justify-between items-center">
                            <div className="flex items-center gap-1">
                              <Heart className="h-3 w-3" style={{ color }} />
                              <span style={{ color: 'var(--text-3)' }}>Health</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <div className="w-16 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--border)' }}>
                                <div className="h-full rounded-full transition-all"
                                  style={{ width: `${h.health_score}%`, background: color }} />
                              </div>
                              <span className="font-bold tabular-nums text-[11px]" style={{ color }}>
                                {h.health_score}
                              </span>
                            </div>
                          </div>
                          {h.alert_rate_1h > 0 && (
                            <div className="flex justify-between items-center">
                              <div className="flex items-center gap-1">
                                <Activity className="h-3 w-3" style={{ color: 'var(--orange)' }} />
                                <span style={{ color: 'var(--text-3)' }}>Alert rate</span>
                              </div>
                              <span className="text-[11px] font-bold tabular-nums"
                                style={{ color: h.alert_rate_1h > 10 ? 'var(--red)' : 'var(--orange)' }}>
                                {h.alert_rate_1h}/h
                              </span>
                            </div>
                          )}
                        </div>
                      );
                    })()}
                  </div>
                </div>
                <div className="flex items-center px-4 py-2.5 gap-2">
                  <button onClick={() => { setModal(agent); setTasks([{ id: '1', task_type: 'collect_processes', payload_value: '' }]); }}
                    className="g-btn g-btn-ghost text-xs" style={{ fontSize: 11 }}>
                    <Play className="h-3 w-3" /> Tasks
                  </button>
                  {agent.status === 'online' && (
                    <button
                      onClick={() => isolateAgent(agent)}
                      disabled={isolating === agent.id}
                      title="Network isolate this agent"
                      className="g-btn text-xs"
                      style={{ background: 'rgba(248,81,73,0.08)', color: 'var(--red)', border: '1px solid rgba(248,81,73,0.25)', fontSize: 11 }}>
                      <ShieldOff className="h-3 w-3" />
                    </button>
                  )}
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

      {/* ── Add Agent Onboarding Modal ────────────────────── */}
      {showOnboard && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)' }}
          onClick={e => e.target === e.currentTarget && setShowOnboard(false)}>
          <div className="w-full max-w-lg rounded-2xl overflow-hidden"
            style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>

            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4"
              style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
                  Add New Agent
                </p>
              </div>
              <button onClick={() => setShowOnboard(false)} style={{ color: 'var(--text-2)' }}>
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Step indicators */}
            <div className="flex items-center gap-0 px-6 pt-4">
              {[1, 2, 3].map((s, i) => (
                <div key={s} className="flex items-center flex-1 last:flex-none">
                  <div className="flex items-center gap-2">
                    <div className="h-7 w-7 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
                      style={{
                        background: onboardStep >= s ? 'var(--accent)' : 'var(--glass-bg)',
                        color: onboardStep >= s ? 'white' : 'var(--text-3)',
                        border: `1px solid ${onboardStep >= s ? 'var(--accent)' : 'var(--border)'}`,
                      }}>
                      {onboardStep > s ? <Check className="h-3.5 w-3.5" /> : s}
                    </div>
                    <span className="text-xs hidden sm:block" style={{ color: onboardStep >= s ? 'var(--text-1)' : 'var(--text-3)' }}>
                      {s === 1 ? 'Generate Token' : s === 2 ? 'Install Agent' : 'Verify'}
                    </span>
                  </div>
                  {i < 2 && <div className="flex-1 h-px mx-2" style={{ background: onboardStep > s ? 'var(--accent)' : 'var(--border)' }} />}
                </div>
              ))}
            </div>

            <div className="p-6 space-y-4">

              {/* Step 1: Generate token */}
              {onboardStep === 1 && (
                <div className="space-y-4">
                  <p className="text-sm" style={{ color: 'var(--text-2)' }}>
                    First, generate a one-time install token. The agent uses this to securely register itself — it expires in 24 hours and can only be used once.
                  </p>
                  <div className="flex gap-2">
                    <input value={tokenLabel} onChange={e => setTokenLabel(e.target.value)}
                      placeholder="Label (e.g. prod-server-01)"
                      className="g-input flex-1 text-sm" />
                    <button
                      disabled={genLoading}
                      onClick={async () => {
                        setGenLoading(true);
                        try {
                          const r = await api.post('/integrations/install-tokens', { label: tokenLabel || 'agent' });
                          setGenToken(r.data.token);
                        } catch { setToast('Failed to generate token'); setTimeout(() => setToast(null), 3000); }
                        finally { setGenLoading(false); }
                      }}
                      className="g-btn g-btn-primary whitespace-nowrap">
                      {genLoading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <><Key className="h-4 w-4" /> Generate</>}
                    </button>
                  </div>

                  {genToken && (
                    <div>
                      <div className="rounded-xl p-4 space-y-2"
                        style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
                        <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--accent)' }}>
                          Install Token — copy now, shown only once
                        </p>
                        <div className="flex items-center gap-2">
                          <code className="flex-1 text-xs font-mono break-all" style={{ color: 'var(--text-1)' }}>
                            {genToken}
                          </code>
                          <button onClick={() => {
                            navigator.clipboard.writeText(genToken);
                            setCopied(true);
                            setTimeout(() => setCopied(false), 2000);
                          }} style={{ color: 'var(--accent)' }}>
                            {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                          </button>
                        </div>
                      </div>
                      <button onClick={() => setOnboardStep(2)}
                        className="g-btn g-btn-primary w-full justify-center mt-3">
                        I&apos;ve copied the token <ArrowRight className="h-4 w-4" />
                      </button>
                    </div>
                  )}
                </div>
              )}

              {/* Step 2: Install agent */}
              {onboardStep === 2 && (
                <div className="space-y-4">
                  <p className="text-sm" style={{ color: 'var(--text-2)' }}>
                    Build and run the agent. On first start it will show a prompt asking for the install token — paste the one you just generated.
                  </p>
                  <div className="rounded-xl p-3 flex items-start gap-2"
                    style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
                    <Key className="h-4 w-4 shrink-0 mt-0.5" style={{ color: 'var(--accent)' }} />
                    <div>
                      <p className="text-xs font-semibold" style={{ color: 'var(--accent)' }}>Your token:</p>
                      <code className="text-[11px] font-mono break-all" style={{ color: 'var(--text-1)' }}>
                        {genToken || '(generate in step 1)'}
                      </code>
                    </div>
                  </div>

                  {[
                    {
                      label: '1. Download and build the agent',
                      code: `git clone <your-repo>/xcloak-agent\ncd xcloak-agent\ngo build -o xcloak-agent ./main.go`,
                    },
                    {
                      label: '2. Run the agent — it will prompt for the install token',
                      code: `./xcloak-agent`,
                    },
                  ].map(({ label, code }) => (
                    <div key={label}>
                      <p className="text-xs mb-1.5 font-medium" style={{ color: 'var(--text-2)' }}>{label}</p>
                      <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                        <div className="flex items-center justify-between px-3 py-1.5"
                          style={{ background: 'var(--glass-bg)', borderBottom: '1px solid var(--border)' }}>
                          <Terminal className="h-3 w-3" style={{ color: 'var(--text-3)' }} />
                          <button onClick={() => { navigator.clipboard.writeText(code); setToast('Copied!'); setTimeout(() => setToast(null), 2000); }}
                            className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                            <Copy className="h-3 w-3" />
                          </button>
                        </div>
                        <pre className="px-3 py-2 text-xs font-mono overflow-x-auto"
                          style={{ color: 'var(--text-1)', background: 'var(--bg-0)' }}>
                          {code}
                        </pre>
                      </div>
                    </div>
                  ))}

                  <div className="flex gap-3">
                    <button onClick={() => setOnboardStep(1)} className="g-btn g-btn-ghost flex-1 justify-center">Back</button>
                    <button onClick={() => setOnboardStep(3)} className="g-btn g-btn-primary flex-1 justify-center">
                      I&apos;ve run the agent <ArrowRight className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              )}

              {/* Step 3: Verify */}
              {onboardStep === 3 && (
                <div className="space-y-4">
                  <p className="text-sm" style={{ color: 'var(--text-2)' }}>
                    The agent should appear below within 15 seconds of starting. Click Refresh to check.
                  </p>

                  <div className="rounded-xl p-4 space-y-2"
                    style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>What to expect:</p>
                    {[
                      'Agent starts and sends install token to server',
                      'Server validates token, marks it used, creates agent record',
                      'Agent receives its permanent token and begins heartbeating',
                      'Agent appears here with status Online',
                    ].map((step, i) => (
                      <div key={i} className="flex items-start gap-2">
                        <Check className="h-3.5 w-3.5 mt-0.5 shrink-0" style={{ color: 'var(--green)' }} />
                        <p className="text-xs" style={{ color: 'var(--text-2)' }}>{step}</p>
                      </div>
                    ))}
                  </div>

                  <div className="flex gap-3">
                    <button onClick={() => setOnboardStep(2)} className="g-btn g-btn-ghost flex-1 justify-center">Back</button>
                    <button
                      onClick={async () => {
                        await load(true);
                        setShowOnboard(false);
                        setToast('Refreshed — check for your new agent below'); setTimeout(() => setToast(null), 3000);
                      }}
                      className="g-btn g-btn-primary flex-1 justify-center">
                      <RefreshCw className="h-4 w-4" /> Refresh & Check
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
