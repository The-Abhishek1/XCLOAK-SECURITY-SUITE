'use client';

import { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { RootLayout } from '@/components/layout/RootLayout';
import { agentsAPI, tasksAPI, integrationsAPI, agentGroupsAPI } from '@/lib/api';
import { Agent, AgentGroup } from '@/types';
import { timeAgo } from '@/lib/utils';
import {
  Cpu, Search, Play, ChevronRight, Wifi, WifiOff, X, Plus, Minus, Heart, Key, Copy,
  Check, Terminal, ShieldCheck, ArrowRight, RefreshCw, Activity, ShieldOff, Monitor,
  Shield, AlertTriangle, Power, RotateCcw, Upload, MemoryStick, Filter, Users,
  Layers, CheckSquare, Square, ChevronDown, Zap, Bug, RotateCw, Trash2,
} from 'lucide-react';

interface AgentHealth {
  agent_id: number;
  health_score: number;
  health_status: string;
  heartbeat_gap_s: number;
  alert_rate_1h: number;
}

const COLLECTION_TASKS = [
  { v: 'collect_processes',       l: 'Collect Processes',       payload: 'none' },
  { v: 'collect_connections',     l: 'Collect Connections',     payload: 'none' },
  { v: 'collect_services',        l: 'Collect Services',        payload: 'none' },
  { v: 'collect_packages',        l: 'Collect Packages',        payload: 'none' },
  { v: 'collect_users',           l: 'Collect Users',           payload: 'none' },
  { v: 'collect_auth_logs',       l: 'Collect Auth Logs',       payload: 'none' },
  { v: 'collect_file_hashes',     l: 'Scan File Hashes',        payload: 'none' },
  { v: 'collect_startup',         l: 'Collect Startup Items',   payload: 'none' },
  { v: 'collect_usb_history',     l: 'Collect USB History',     payload: 'none' },
  { v: 'collect_scheduled_tasks', l: 'Collect Scheduled Tasks', payload: 'none' },
  { v: 'collect_drivers',         l: 'Collect Drivers',         payload: 'none' },
  { v: 'collect_memory',          l: 'Collect Memory Dump',     payload: 'none' },
  { v: 'collect_file',            l: 'Download File',           payload: 'path',   placeholder: '/tmp/suspicious.sh' },
  { v: 'upload_file',             l: 'Upload File',             payload: 'path',   placeholder: '/remote/destination' },
  { v: 'scan_yara',               l: 'YARA Scan',               payload: 'path',   placeholder: '/tmp/test.sh' },
  { v: 'vulnerability_scan',      l: 'Vulnerability Scan',      payload: 'none' },
] as const;

const REMOTE_ACTION_TASKS = [
  { v: 'kill_process',  l: 'Kill Process',     payload: 'pid',    placeholder: '1234',              icon: X,           color: '#fb923c', danger: false },
  { v: 'execute_script',l: 'Shell / Script',   payload: 'script', placeholder: 'hostname && whoami', icon: Terminal,    color: '#38bdf8', danger: false },
  { v: 'isolate_host',  l: 'Isolate',          payload: 'none',   placeholder: '',                  icon: ShieldOff,   color: '#f85149', danger: true  },
  { v: 'de_isolate',    l: 'Remove Isolation', payload: 'none',   placeholder: '',                  icon: ShieldCheck, color: '#22c55e', danger: false },
  { v: 'restart_host',  l: 'Restart',          payload: 'none',   placeholder: '',                  icon: RotateCcw,   color: '#fb923c', danger: true  },
  { v: 'shutdown_host', l: 'Shutdown',         payload: 'none',   placeholder: '',                  icon: Power,       color: '#f85149', danger: true  },
  { v: 'update_agent',  l: 'Update Agent',     payload: 'none',   placeholder: '',                  icon: Upload,      color: 'var(--accent)', danger: false },
] as const;

const TASK_DEFS = [...COLLECTION_TASKS, ...REMOTE_ACTION_TASKS.map(t => ({ v: t.v, l: t.l, payload: t.payload, placeholder: t.placeholder }))];

// Bulk actions available from the top bar
const BULK_ACTIONS = [
  { v: 'isolate_host',      l: 'Isolate',         icon: ShieldOff,  danger: true  },
  { v: 'vulnerability_scan',l: 'Scan Vulns',       icon: Bug,        danger: false },
  { v: 'update_agent',      l: 'Update Agents',    icon: Upload,     danger: false },
  { v: 'restart_host',      l: 'Restart',          icon: RotateCcw,  danger: true  },
  { v: 'collect_processes', l: 'Collect Procs',    icon: Activity,   danger: false },
  { v: 'shutdown_host',     l: 'Shutdown',         icon: Power,      danger: true  },
];

interface TaskItem {
  id: string;
  task_type: string;
  payload_value: string;
}

type StatusFilter = 'all' | 'online' | 'offline';
type OSFilter = 'all' | 'windows' | 'linux' | 'macos' | 'android';
type RiskFilter = 'all' | 'high' | 'medium' | 'low';

export default function AgentsPage() {
  const [agents, setAgents]       = useState<Agent[]>([]);
  const [health, setHealth]       = useState<Map<number, AgentHealth>>(new Map());
  const [groups, setGroups]       = useState<AgentGroup[]>([]);
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch]       = useState('');
  const [modal, setModal]         = useState<Agent | null>(null);
  const [showOnboard, setShowOnboard] = useState(false);
  const [genToken, setGenToken]   = useState('');
  const [tokenLabel, setTokenLabel] = useState('');
  const [genLoading, setGenLoading] = useState(false);
  const [copied, setCopied]       = useState(false);
  const [onboardStep, setOnboardStep] = useState(1);
  const [tasks, setTasks]         = useState<TaskItem[]>([{ id: '1', task_type: 'collect_processes', payload_value: '' }]);
  const [dispatching, setDispatching] = useState(false);
  const [toast, setToast]         = useState<string | null>(null);
  const [statusTab, setStatusTab] = useState<StatusFilter>('all');
  const [osFilter, setOsFilter]   = useState<OSFilter>('all');
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('all');
  const [isolating, setIsolating] = useState<number | null>(null);
  const [modalTab, setModalTab]   = useState<'collection' | 'remote'>('collection');

  // Bulk selection
  const [selected, setSelected]   = useState<Set<number>>(new Set());
  const [bulkMode, setBulkMode]   = useState(false);
  const [bulkDispatching, setBulkDispatching] = useState(false);
  const [showBulkMenu, setShowBulkMenu] = useState(false);

  // Group filter
  const [activeGroup, setActiveGroup] = useState<number | null>(null);

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const [agentRes, healthRes, groupRes] = await Promise.allSettled([
        agentsAPI.getAll(),
        agentsAPI.getHealth().catch(() => ({ data: [] })),
        agentGroupsAPI.getAll().catch(() => ({ data: [] })),
      ]);
      if (agentRes.status === 'fulfilled') setAgents(agentRes.value.data || []);
      if (healthRes.status === 'fulfilled') {
        const hMap = new Map<number, AgentHealth>();
        (healthRes.value.data || []).forEach((h: AgentHealth) => hMap.set(h.agent_id, h));
        setHealth(hMap);
      }
      if (groupRes.status === 'fulfilled') setGroups(groupRes.value.data || []);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Close bulk dropdown on outside click
  useEffect(() => {
    if (!showBulkMenu) return;
    const close = () => setShowBulkMenu(false);
    document.addEventListener('click', close);
    return () => document.removeEventListener('click', close);
  }, [showBulkMenu]);

  const addTask = () => setTasks(p => [...p, { id: String(Date.now()), task_type: 'collect_processes', payload_value: '' }]);
  const removeTask = (id: string) => setTasks(p => p.filter(t => t.id !== id));
  const updateTask = (id: string, field: 'task_type' | 'payload_value', val: string) =>
    setTasks(p => p.map(t => t.id === id ? { ...t, [field]: val } : t));

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

  const toggleSelect = (id: number) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const selectAll = () => setSelected(new Set(filtered.map(a => a.id)));
  const clearSelection = () => { setSelected(new Set()); setBulkMode(false); };

  const bulkDispatch = async (action: string, danger: boolean) => {
    if (selected.size === 0) return;
    if (danger && !confirm(`${action.replace(/_/g, ' ')} on ${selected.size} agents? This may disrupt endpoints.`)) return;
    setBulkDispatching(true);
    setShowBulkMenu(false);
    try {
      await agentsAPI.bulk({ agent_ids: Array.from(selected), action });
      notify(`✓ "${action}" dispatched to ${selected.size} agent${selected.size !== 1 ? 's' : ''}`);
      clearSelection();
    } catch { notify('Bulk action failed'); }
    finally { setBulkDispatching(false); }
  };

  // ── Filtering ────────────────────────────────────────────────────
  const filtered = agents
    .filter(a => {
      if (statusTab !== 'all') {
        if (statusTab === 'online' && a.status !== 'online') return false;
        if (statusTab === 'offline' && a.status === 'online') return false;
      }
      if (osFilter !== 'all') {
        const os = (a.os || '').toLowerCase();
        if (osFilter === 'windows' && !os.includes('windows')) return false;
        if (osFilter === 'linux' && !os.includes('linux')) return false;
        if (osFilter === 'macos' && !os.includes('mac')) return false;
        if (osFilter === 'android' && !os.includes('android')) return false;
      }
      if (riskFilter !== 'all') {
        const rs = a.risk_score ?? 0;
        if (riskFilter === 'high' && rs < 70) return false;
        if (riskFilter === 'medium' && (rs < 40 || rs >= 70)) return false;
        if (riskFilter === 'low' && rs >= 40) return false;
      }
      if (activeGroup !== null) {
        // For now group membership requires backend — skip client-side filter.
      }
      if (!search) return true;
      const q = search.toLowerCase();
      return (
        a.hostname?.toLowerCase().includes(q) ||
        a.ip_address?.includes(q) ||
        a.os?.toLowerCase().includes(q) ||
        String(a.id).includes(q) ||
        a.machine_id?.toLowerCase().includes(q)
      );
    });

  const online = agents.filter(a => a.status === 'online').length;

  return (
    <RootLayout
      title="Agents"
      subtitle={`${online}/${agents.length} online`}
      actions={
        <button
          onClick={() => setShowOnboard(true)}
          className="g-btn g-btn-primary text-xs flex items-center gap-1.5">
          <Plus className="h-3.5 w-3.5" /> Enroll Agent
        </button>
      }
      onRefresh={() => load(true)} refreshing={refreshing}>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)', minWidth: 240 }}>
          {toast}
        </div>
      )}

      <div className="space-y-4">

        {/* ── Agent Groups chips ───────────────────────────────────── */}
        {groups.length > 0 && (
          <div className="flex items-center gap-2 flex-wrap">
            <Layers className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />
            <button
              onClick={() => setActiveGroup(null)}
              className="text-[11px] px-2.5 py-1 rounded-lg font-medium transition-all"
              style={{
                background: activeGroup === null ? 'var(--accent-glow)' : 'transparent',
                color: activeGroup === null ? 'var(--accent)' : 'var(--text-3)',
                border: `1px solid ${activeGroup === null ? 'var(--accent-border)' : 'var(--border)'}`,
              }}>
              All Groups
            </button>
            {groups.map(g => (
              <button
                key={g.id}
                onClick={() => setActiveGroup(activeGroup === g.id ? null : g.id)}
                className="text-[11px] px-2.5 py-1 rounded-lg font-medium transition-all flex items-center gap-1.5"
                style={{
                  background: activeGroup === g.id ? 'var(--accent-glow)' : 'transparent',
                  color: activeGroup === g.id ? 'var(--accent)' : 'var(--text-2)',
                  border: `1px solid ${activeGroup === g.id ? 'var(--accent-border)' : 'var(--border)'}`,
                }}>
                {g.name}
                <span className="text-[10px] opacity-60">({g.agent_count})</span>
              </button>
            ))}
          </div>
        )}

        {/* ── Search + Filters + Bulk bar ───────────────────────────── */}
        <div className="flex items-center gap-3 flex-wrap">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Hostname, IP, OS, Agent ID…"
              className="g-input pl-9"
              style={{ minWidth: 220 }}
            />
          </div>

          {/* Status tabs */}
          <div className="flex rounded-lg overflow-hidden" style={{ border: '1px solid var(--border)' }}>
            {(['all', 'online', 'offline'] as const).map(tab => {
              const count = tab === 'all' ? agents.length
                : agents.filter(a => tab === 'online' ? a.status === 'online' : a.status !== 'online').length;
              return (
                <button key={tab} onClick={() => setStatusTab(tab)}
                  className="px-3 py-1.5 text-[11px] font-semibold capitalize transition-all flex items-center gap-1.5"
                  style={{ background: statusTab === tab ? 'var(--accent)' : 'transparent', color: statusTab === tab ? '#fff' : 'var(--text-3)' }}>
                  {tab === 'online' && <span className="h-1.5 w-1.5 rounded-full bg-green-400" />}
                  {tab === 'offline' && <span className="h-1.5 w-1.5 rounded-full bg-gray-500" />}
                  {tab} <span className="opacity-70">({count})</span>
                </button>
              );
            })}
          </div>

          {/* OS filter */}
          <div className="flex rounded-lg overflow-hidden" style={{ border: '1px solid var(--border)' }}>
            {([
              { v: 'all', l: 'All OS' },
              { v: 'windows', l: 'Win' },
              { v: 'linux', l: 'Linux' },
              { v: 'macos', l: 'macOS' },
              { v: 'android', l: 'Mobile' },
            ] as const).map(({ v, l }) => (
              <button key={v} onClick={() => setOsFilter(v)}
                className="px-3 py-1.5 text-[11px] font-medium transition-all"
                style={{ background: osFilter === v ? 'var(--accent)' : 'transparent', color: osFilter === v ? '#fff' : 'var(--text-3)' }}>
                {l}
              </button>
            ))}
          </div>

          {/* Risk filter */}
          <div className="flex rounded-lg overflow-hidden" style={{ border: '1px solid var(--border)' }}>
            {([
              { v: 'all', l: 'Any Risk' },
              { v: 'high', l: 'High' },
              { v: 'medium', l: 'Medium' },
              { v: 'low', l: 'Low' },
            ] as const).map(({ v, l }) => (
              <button key={v} onClick={() => setRiskFilter(v)}
                className="px-3 py-1.5 text-[11px] font-medium transition-all"
                style={{
                  background: riskFilter === v ? (v === 'high' ? '#f85149' : v === 'medium' ? '#fb923c' : v === 'low' ? '#22c55e' : 'var(--accent)') : 'transparent',
                  color: riskFilter === v ? '#fff' : 'var(--text-3)',
                }}>
                {l}
              </button>
            ))}
          </div>

          {/* Bulk mode toggle */}
          <button
            onClick={() => { setBulkMode(b => !b); if (bulkMode) clearSelection(); }}
            className="g-btn g-btn-ghost text-xs"
            style={{ color: bulkMode ? 'var(--accent)' : 'var(--text-2)' }}>
            <CheckSquare className="h-3.5 w-3.5" />
            {bulkMode ? 'Exit Bulk' : 'Bulk Select'}
          </button>
        </div>

        {/* ── Bulk action bar (appears when items are selected) ─────── */}
        {bulkMode && selected.size > 0 && (
          <div className="flex items-center gap-3 px-4 py-3 rounded-xl flex-wrap"
            style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
            <span className="text-xs font-semibold" style={{ color: 'var(--accent)' }}>
              {selected.size} agent{selected.size !== 1 ? 's' : ''} selected
            </span>
            <div className="flex items-center gap-2 flex-wrap flex-1">
              {BULK_ACTIONS.map(({ v, l, icon: Icon, danger }) => (
                <button
                  key={v}
                  onClick={() => bulkDispatch(v, danger)}
                  disabled={bulkDispatching}
                  className="g-btn text-xs flex items-center gap-1.5"
                  style={{
                    background: danger ? 'rgba(248,81,73,0.1)' : 'var(--glass-bg)',
                    color: danger ? 'var(--red)' : 'var(--text-1)',
                    border: `1px solid ${danger ? 'rgba(248,81,73,0.3)' : 'var(--border)'}`,
                  }}>
                  <Icon className="h-3.5 w-3.5" />
                  {l}
                  {danger && <AlertTriangle className="h-3 w-3 opacity-60" />}
                </button>
              ))}
            </div>
            <button onClick={clearSelection} className="g-btn g-btn-ghost text-xs">
              <X className="h-3.5 w-3.5" /> Clear
            </button>
          </div>
        )}

        {/* ── Bulk select all / count row ───────────────────────────── */}
        {bulkMode && (
          <div className="flex items-center gap-3 text-xs" style={{ color: 'var(--text-3)' }}>
            <button onClick={selectAll} className="hover:underline" style={{ color: 'var(--accent)' }}>
              Select all {filtered.length}
            </button>
            <span>·</span>
            <span>{filtered.length} shown</span>
          </div>
        )}

        {/* ── Agent cards grid ─────────────────────────────────────── */}
        {loading ? (
          <div className="py-20 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
        ) : filtered.length === 0 ? (
          <div className="py-20 text-center">
            <Cpu className="mx-auto h-10 w-10 mb-2" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No agents match the current filters</p>
          </div>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
            {filtered.map(agent => {
              const isSelected = selected.has(agent.id);
              return (
                <div key={agent.id}
                  className="g-card overflow-hidden transition-all"
                  style={{ outline: isSelected ? '2px solid var(--accent)' : undefined }}>
                  <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
                    <div className="flex items-start justify-between mb-3">
                      {/* Bulk checkbox */}
                      {bulkMode && (
                        <button onClick={() => toggleSelect(agent.id)} className="shrink-0 mr-2 mt-0.5">
                          {isSelected
                            ? <CheckSquare className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                            : <Square className="h-4 w-4" style={{ color: 'var(--text-3)' }} />}
                        </button>
                      )}
                      <div className="flex items-center gap-2.5 min-w-0 flex-1">
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
                      <div className="flex items-center gap-1.5 flex-wrap justify-end shrink-0">
                        {agent.is_isolated && (
                          <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded flex items-center gap-1"
                            style={{ background: 'rgba(248,81,73,0.12)', color: 'var(--red)', border: '1px solid rgba(248,81,73,0.3)' }}>
                            <ShieldOff className="h-3 w-3" /> Isolated
                          </span>
                        )}
                        {(agent.open_alert_count ?? 0) > 0 && (
                          <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded"
                            style={{ background: 'rgba(251,146,60,0.12)', color: 'var(--orange)', border: '1px solid rgba(251,146,60,0.3)' }}>
                            {agent.open_alert_count} alert{agent.open_alert_count !== 1 ? 's' : ''}
                          </span>
                        )}
                        <span className={agent.status === 'online' ? 's-online' : 's-offline'}>{agent.status}</span>
                      </div>
                    </div>

                    <div className="space-y-1.5 text-xs">
                      {[
                        ['OS',        agent.os || '—'],
                        ['Last seen', timeAgo(agent.last_seen)],
                      ].map(([k, v]) => (
                        <div key={k} className="flex justify-between">
                          <span style={{ color: 'var(--text-3)' }}>{k}</span>
                          <span style={{ color: 'var(--text-2)' }}>{v}</span>
                        </div>
                      ))}
                      <div className="flex justify-between items-center">
                        <span style={{ color: 'var(--text-3)' }}>Tamper protect</span>
                        <span style={{ color: agent.tamper_protection ? 'var(--green)' : 'var(--text-3)' }} className="flex items-center gap-1">
                          <Shield className="h-3 w-3" />
                          {agent.tamper_protection ? 'On' : 'Off'}
                        </span>
                      </div>
                      {(agent.policy_count ?? 0) > 0 && (
                        <div className="flex justify-between">
                          <span style={{ color: 'var(--text-3)' }}>Policies</span>
                          <span style={{ color: 'var(--text-2)' }}>{agent.policy_count} applied</span>
                        </div>
                      )}
                      {agent.load_avg_1m != null && (
                        <div className="flex justify-between items-center">
                          <span style={{ color: 'var(--text-3)' }}>Load avg</span>
                          <span className="mono tabular-nums" style={{ color: 'var(--text-2)' }}>
                            {agent.load_avg_1m.toFixed(2)} · {agent.load_avg_5m?.toFixed(2)} · {agent.load_avg_15m?.toFixed(2)}
                          </span>
                        </div>
                      )}
                      {agent.battery_level != null && (
                        <div className="flex justify-between items-center">
                          <span style={{ color: 'var(--text-3)' }}>Battery</span>
                          <span className="tabular-nums" style={{
                            color: agent.battery_level < 20 ? 'var(--red)' : agent.battery_level < 40 ? 'var(--orange)' : 'var(--green)'
                          }}>
                            {agent.battery_level}%{agent.battery_charging ? ' ⚡' : ''}
                          </span>
                        </div>
                      )}
                      {agent.network_type && (
                        <div className="flex justify-between items-center">
                          <span style={{ color: 'var(--text-3)' }}>Network</span>
                          <span style={{ color: 'var(--text-2)' }}>{agent.network_type}</span>
                        </div>
                      )}
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
                                  <div className="h-full rounded-full transition-all" style={{ width: `${h.health_score}%`, background: color }} />
                                </div>
                                <span className="font-bold tabular-nums text-[11px]" style={{ color }}>{h.health_score}</span>
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

                  {/* Card footer actions */}
                  <div className="flex items-center px-4 py-2.5 gap-2">
                    <button
                      onClick={() => {
                        setModal(agent);
                        setModalTab('collection');
                        setTasks([{ id: '1', task_type: 'collect_processes', payload_value: '' }]);
                      }}
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
                    <Link
                      href={`/agents/${agent.id}`}
                      className="g-btn text-xs"
                      style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)', fontSize: 11 }}>
                      Details <ChevronRight className="h-3 w-3" />
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ── Multi-task dispatch modal ─────────────────────────────────── */}
      {modal && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setModal(null)}>
          <div className="g-modal" style={{ maxWidth: 560 }}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <div>
                <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
                  {modal.hostname}
                  {modal.is_isolated && (
                    <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded" style={{ background: '#f8514920', color: '#f85149' }}>ISOLATED</span>
                  )}
                </h2>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-3)' }}>{modal.ip_address} · {modal.os}</p>
              </div>
              <button onClick={() => setModal(null)} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>

            <div className="flex border-b" style={{ borderColor: 'var(--border)' }}>
              {(['collection', 'remote'] as const).map(k => (
                <button key={k} onClick={() => setModalTab(k)}
                  className="flex-1 text-xs font-semibold py-3 transition-colors"
                  style={{
                    color: modalTab === k ? 'var(--accent)' : 'var(--text-3)',
                    borderBottom: modalTab === k ? '2px solid var(--accent)' : '2px solid transparent',
                  }}>
                  {k === 'collection' ? 'Data Collection' : 'Remote Actions'}
                </button>
              ))}
            </div>

            {modalTab === 'collection' && (
              <>
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
                            {COLLECTION_TASKS.map(d => <option key={d.v} value={d.v}>{d.l}</option>)}
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
                            placeholder={'placeholder' in def ? def.placeholder : ''}
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
              </>
            )}

            {modalTab === 'remote' && (
              <div className="p-5 space-y-3">
                <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                  Dispatches a single task immediately. Dangerous actions require confirmation.
                </p>
                <div className="grid grid-cols-2 gap-2">
                  {REMOTE_ACTION_TASKS.map(action => {
                    const Icon = action.icon;
                    return (
                      <button key={action.v}
                        onClick={async () => {
                          if (action.danger && !confirm(`${action.l} ${modal.hostname}? This action may disrupt the endpoint.`)) return;
                          setDispatching(true);
                          try {
                            await tasksAPI.create({ agent_id: modal.id, task_type: action.v, payload: {} });
                            notify(`✓ ${action.l} dispatched to ${modal.hostname}`);
                            setModal(null);
                          } catch { notify(`Failed to dispatch ${action.l}`); }
                          finally { setDispatching(false); }
                        }}
                        disabled={dispatching}
                        className="flex items-center gap-2.5 rounded-xl px-4 py-3 text-xs font-medium transition-all text-left"
                        style={{ background: `${action.color}12`, border: `1px solid ${action.color}35`, color: action.color }}>
                        <Icon className="h-4 w-4 shrink-0" />
                        <span>{action.l}</span>
                        {action.danger && <AlertTriangle className="h-3 w-3 ml-auto opacity-60" />}
                      </button>
                    );
                  })}
                </div>
                <button onClick={() => setModal(null)} className="g-btn g-btn-ghost w-full justify-center mt-2">Close</button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Add Agent Onboarding Modal ──────────────────────────────────── */}
      {showOnboard && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)' }}
          onClick={e => e.target === e.currentTarget && setShowOnboard(false)}>
          <div className="w-full max-w-lg rounded-2xl overflow-hidden"
            style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>

            <div className="flex items-center justify-between px-6 py-4"
              style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Enroll New Agent</p>
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
              {onboardStep === 1 && (
                <div className="space-y-4">
                  <p className="text-sm" style={{ color: 'var(--text-2)' }}>
                    Generate a one-time install token. The agent uses this to securely register — it expires in 24 hours and can only be used once.
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
                          const r = await integrationsAPI.createInstallToken(tokenLabel || 'agent');
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
                          <code className="flex-1 text-xs font-mono break-all" style={{ color: 'var(--text-1)' }}>{genToken}</code>
                          <button onClick={() => { navigator.clipboard.writeText(genToken); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
                            style={{ color: 'var(--accent)' }}>
                            {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                          </button>
                        </div>
                      </div>
                      <button onClick={() => setOnboardStep(2)} className="g-btn g-btn-primary w-full justify-center mt-3">
                        I&apos;ve copied the token <ArrowRight className="h-4 w-4" />
                      </button>
                    </div>
                  )}
                </div>
              )}

              {onboardStep === 2 && (
                <div className="space-y-4">
                  <p className="text-sm" style={{ color: 'var(--text-2)' }}>
                    Build and run the agent. On first start it will prompt for the install token — paste the one you just generated.
                  </p>
                  {[
                    { label: '1. Clone and build', code: `git clone <your-repo>/xcloak-agent-desktop\ncd xcloak-agent-desktop\ngo build -o xcloak-agent ./main.go` },
                    { label: '2. Run — it will prompt for the install token', code: `./xcloak-agent` },
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
                        <pre className="px-3 py-2 text-xs font-mono overflow-x-auto" style={{ color: 'var(--text-1)', background: 'var(--bg-0)' }}>{code}</pre>
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

              {onboardStep === 3 && (
                <div className="space-y-4">
                  <p className="text-sm" style={{ color: 'var(--text-2)' }}>
                    The agent should appear in the list within 15 seconds. Click Refresh to check.
                  </p>
                  <div className="rounded-xl p-4 space-y-2" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>What to expect:</p>
                    {[
                      'Agent starts and sends install token to server',
                      'Server validates token, creates agent record',
                      'Agent receives permanent token and begins heartbeating',
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
                        setToast('Refreshed — check for your new agent below');
                        setTimeout(() => setToast(null), 3000);
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
