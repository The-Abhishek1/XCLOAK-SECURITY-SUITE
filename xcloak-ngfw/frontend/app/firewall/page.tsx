'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { firewallAPI, agentsAPI } from '@/lib/api';
import { FirewallRule, FirewallGroup, FirewallConflict, FirewallStats, Agent } from '@/types';
import { timeAgo } from '@/lib/utils';
import {
  Network, Plus, Trash2, Edit2, X, Search,
  Upload, CheckCircle, XCircle, Loader2, RefreshCw,
  Shield, AlertTriangle, Zap, BarChart2, ChevronDown, ChevronRight,
  Layers,
} from 'lucide-react';

const PROTOS  = ['tcp', 'udp', 'icmp', 'any'];
const ACTIONS = ['allow', 'deny'];
const EMPTY: Omit<FirewallRule, 'id' | 'hit_count' | 'synced_at'> = {
  name: '', description: '', group_name: 'default',
  source_ip: '', destination_ip: '', protocol: 'tcp',
  port: 0, action: 'allow', enabled: true, priority: 100,
};

interface SyncResult {
  agent_id:   number;
  hostname:   string;
  task_id:    number;
  rule_count: number;
  dispatched: boolean;
  error?:     string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Conflict badge
// ─────────────────────────────────────────────────────────────────────────────
function ConflictsPanel({ conflicts }: { conflicts: FirewallConflict[] }) {
  const [open, setOpen] = useState(false);
  if (conflicts.length === 0) return null;

  const errorCount = conflicts.filter(c => c.severity === 'error').length;
  return (
    <div className="rounded-xl overflow-hidden" style={{ border: `1px solid ${errorCount > 0 ? 'var(--red)' : 'rgba(251,191,36,0.4)'}` }}>
      <button
        className="w-full flex items-center gap-3 px-4 py-3"
        style={{ background: errorCount > 0 ? 'var(--red-bg)' : 'rgba(251,191,36,0.08)' }}
        onClick={() => setOpen(o => !o)}>
        <AlertTriangle className="h-4 w-4 shrink-0" style={{ color: errorCount > 0 ? 'var(--red)' : 'var(--yellow)' }} />
        <span className="text-sm font-semibold flex-1 text-left"
          style={{ color: errorCount > 0 ? 'var(--red)' : 'var(--yellow)' }}>
          {conflicts.length} rule conflict{conflicts.length !== 1 ? 's' : ''} detected
          {errorCount > 0 && ` (${errorCount} shadow${errorCount !== 1 ? 's' : ''})`}
        </span>
        {open ? <ChevronDown className="h-4 w-4" style={{ color: 'var(--text-3)' }} />
               : <ChevronRight className="h-4 w-4" style={{ color: 'var(--text-3)' }} />}
      </button>
      {open && (
        <div className="divide-y" style={{ borderTop: '1px solid var(--border)', '--tw-divide-opacity': 1 } as React.CSSProperties}>
          {conflicts.map((c, i) => (
            <div key={i} className="px-4 py-2.5">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 rounded"
                  style={{
                    background: c.severity === 'error' ? 'var(--red-bg)' : 'rgba(251,191,36,0.15)',
                    color: c.severity === 'error' ? 'var(--red)' : 'var(--yellow)',
                  }}>
                  {c.type}
                </span>
                <span className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>
                  {c.rule_a_name} ↔ {c.rule_b_name}
                </span>
              </div>
              <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{c.description}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Stats bar
// ─────────────────────────────────────────────────────────────────────────────
function StatsBar({ stats }: { stats: FirewallStats | null }) {
  if (!stats) return null;
  const topRule = stats.top_rules?.[0];
  return (
    <div className="grid grid-cols-3 gap-3 mb-4">
      <div className="rounded-xl p-3" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
        <div className="flex items-center gap-2 mb-1">
          <Zap className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
          <span className="text-[10px] uppercase font-bold" style={{ color: 'var(--text-3)' }}>Hits (24h)</span>
        </div>
        <p className="text-2xl font-bold" style={{ color: 'var(--text-1)' }}>
          {(stats.total_hits_24h || 0).toLocaleString()}
        </p>
      </div>
      <div className="rounded-xl p-3" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
        <div className="flex items-center gap-2 mb-1">
          <BarChart2 className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
          <span className="text-[10px] uppercase font-bold" style={{ color: 'var(--text-3)' }}>Top Rule</span>
        </div>
        {topRule ? (
          <>
            <p className="text-sm font-semibold truncate" style={{ color: 'var(--text-1)' }}>{topRule.name}</p>
            <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{topRule.hit_count.toLocaleString()} hits · {topRule.action}</p>
          </>
        ) : <p className="text-sm" style={{ color: 'var(--text-3)' }}>No data yet</p>}
      </div>
      <div className="rounded-xl p-3" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
        <div className="flex items-center gap-2 mb-1">
          <Network className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
          <span className="text-[10px] uppercase font-bold" style={{ color: 'var(--text-3)' }}>Top Agent</span>
        </div>
        {stats.per_agent?.[0] ? (
          <>
            <p className="text-sm font-semibold truncate" style={{ color: 'var(--text-1)' }}>{stats.per_agent[0].hostname}</p>
            <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{stats.per_agent[0].hits.toLocaleString()} hits</p>
          </>
        ) : <p className="text-sm" style={{ color: 'var(--text-3)' }}>No data yet</p>}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main page
// ─────────────────────────────────────────────────────────────────────────────
export default function FirewallPage() {
  const [rules, setRules]         = useState<FirewallRule[]>([]);
  const [agents, setAgents]       = useState<Agent[]>([]);
  const [groups, setGroups]       = useState<FirewallGroup[]>([]);
  const [conflicts, setConflicts] = useState<FirewallConflict[]>([]);
  const [stats, setStats]         = useState<FirewallStats | null>(null);
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch]       = useState('');
  const [activeGroup, setActiveGroup] = useState('');
  const [showAdd, setShowAdd]     = useState(false);
  const [showEdit, setShowEdit]   = useState<FirewallRule | null>(null);
  const [form, setForm]           = useState<typeof EMPTY>({ ...EMPTY });
  const [saving, setSaving]       = useState(false);
  const [toast, setToast]         = useState<string | null>(null);

  // Sync state
  const [showSync, setShowSync]       = useState(false);
  const [syncing, setSyncing]         = useState(false);
  const [syncResults, setSyncResults] = useState<SyncResult[] | null>(null);
  const [syncMode, setSyncMode]       = useState<'replace' | 'append'>('replace');
  const [syncGroup, setSyncGroup]     = useState('');
  const [manageIP, setManageIP]       = useState('');
  const [syncAgents, setSyncAgents]   = useState<number[]>([]);
  const [syncLog, setSyncLog]         = useState<any[]>([]);
  const [loadingLog, setLoadingLog]   = useState(false);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3500); };

  const loadSideData = useCallback(async () => {
    const [gRes, cRes, sRes] = await Promise.allSettled([
      firewallAPI.getGroups(),
      firewallAPI.getConflicts(),
      firewallAPI.getStats(),
    ]);
    if (gRes.status === 'fulfilled') setGroups(gRes.value.data || []);
    if (cRes.status === 'fulfilled') setConflicts(cRes.value.data || []);
    if (sRes.status === 'fulfilled') setStats(sRes.value.data || null);
  }, []);

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const [rRes, aRes] = await Promise.allSettled([
        firewallAPI.getAll(activeGroup || undefined),
        agentsAPI.getAll(),
      ]);
      if (rRes.status === 'fulfilled') setRules(rRes.value.data || []);
      if (aRes.status === 'fulfilled') setAgents(aRes.value.data || []);
      await loadSideData();
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [activeGroup, loadSideData]);

  const loadSyncLog = useCallback(async () => {
    setLoadingLog(true);
    try {
      const r = await firewallAPI.getSyncLog();
      setSyncLog(r.data || []);
    } finally { setLoadingLog(false); }
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { if (showSync) loadSyncLog(); }, [showSync, loadSyncLog]);

  const add = async () => {
    setSaving(true);
    try { await firewallAPI.create(form); load(); setShowAdd(false); setForm({ ...EMPTY }); notify('Rule created'); }
    catch (e: any) { notify(e?.response?.data?.error || 'Create failed'); }
    finally { setSaving(false); }
  };

  const update = async () => {
    if (!showEdit) return;
    setSaving(true);
    try { await firewallAPI.update(showEdit.id, form); load(); setShowEdit(null); notify('Rule updated'); }
    finally { setSaving(false); }
  };

  const del = async (id: number) => {
    if (!confirm('Delete this rule?')) return;
    await firewallAPI.delete(id);
    setRules(p => p.filter(r => r.id !== id));
    notify('Rule deleted');
    loadSideData();
  };

  const toggleEnabled = async (rule: FirewallRule) => {
    await firewallAPI.update(rule.id, { ...rule, enabled: !rule.enabled });
    load();
  };

  const openEdit = (r: FirewallRule) => {
    setForm({
      name: r.name, description: r.description || '', group_name: r.group_name || 'default',
      source_ip: r.source_ip, destination_ip: r.destination_ip,
      protocol: r.protocol, port: r.port, action: r.action,
      enabled: r.enabled, priority: r.priority || 100,
    });
    setShowEdit(r);
  };

  const doSync = async () => {
    setSyncing(true);
    setSyncResults(null);
    try {
      const r = await firewallAPI.sync({
        agent_ids:  syncAgents,
        mode:       syncMode,
        manage_ip:  manageIP,
        group_name: syncGroup || undefined,
      });
      setSyncResults(r.data.results || []);
      notify(r.data.message || 'Sync dispatched');
      load();
      loadSyncLog();
    } catch (e: any) {
      notify(e?.response?.data?.error || 'Sync failed');
    } finally { setSyncing(false); }
  };

  const filtered = rules.filter(r =>
    !search
    || r.name?.toLowerCase().includes(search.toLowerCase())
    || r.source_ip?.includes(search)
    || r.destination_ip?.includes(search)
    || r.group_name?.toLowerCase().includes(search.toLowerCase())
  );

  const enabledCount  = rules.filter(r => r.enabled).length;
  const pendingSync   = rules.filter(r => r.enabled && !r.synced_at).length;
  const onlineAgents  = agents.filter(a => a.status === 'online');

  return (
    <RootLayout
      title="Firewall"
      subtitle={`${rules.length} rules · ${enabledCount} enabled`}
      onRefresh={() => load(true)} refreshing={refreshing}
      actions={
        <div className="flex items-center gap-2">
          {pendingSync > 0 && (
            <div className="flex items-center gap-1.5 text-[11px] px-2.5 py-1 rounded-lg"
              style={{ background: 'rgba(251,191,36,0.15)', border: '1px solid rgba(251,191,36,0.3)', color: 'var(--yellow)' }}>
              <AlertTriangle className="h-3 w-3" /> {pendingSync} unsynced
            </div>
          )}
          <button onClick={() => setShowSync(true)}
            className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
            <Upload className="h-3.5 w-3.5" /> Apply to Agents
          </button>
          <button onClick={() => { setForm({ ...EMPTY }); setShowAdd(true); }}
            className="g-btn g-btn-primary text-xs">
            <Plus className="h-3.5 w-3.5" /> Add Rule
          </button>
        </div>
      }>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm"
          style={{ color: 'var(--text-1)', minWidth: 200 }}>{toast}</div>
      )}

      <div className="space-y-4">
        {/* Stats row */}
        <StatsBar stats={stats} />

        {/* Conflicts */}
        <ConflictsPanel conflicts={conflicts} />

        {/* Groups filter tabs */}
        {groups.length > 1 && (
          <div className="flex items-center gap-2 overflow-x-auto pb-1">
            <Layers className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />
            <button
              onClick={() => { setActiveGroup(''); }}
              className="text-[11px] px-3 py-1 rounded-full shrink-0 transition-colors"
              style={{
                background: !activeGroup ? 'var(--accent)' : 'var(--glass-bg)',
                color:      !activeGroup ? '#000' : 'var(--text-2)',
                border: '1px solid var(--border)',
              }}>
              All groups
            </button>
            {groups.map(g => (
              <button key={g.name}
                onClick={() => setActiveGroup(activeGroup === g.name ? '' : g.name)}
                className="text-[11px] px-3 py-1 rounded-full shrink-0 transition-colors"
                style={{
                  background: activeGroup === g.name ? 'var(--accent)' : 'var(--glass-bg)',
                  color:      activeGroup === g.name ? '#000' : 'var(--text-2)',
                  border: '1px solid var(--border)',
                }}>
                {g.name}
                <span className="ml-1.5 opacity-60">
                  {g.enabled_rules}/{g.total_rules}
                  {g.total_hits > 0 && ` · ${g.total_hits.toLocaleString()} hits`}
                </span>
              </button>
            ))}
          </div>
        )}

        {/* Search */}
        <div className="relative max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search name, IP, group…" className="g-input pl-9" />
        </div>

        {/* Rules table */}
        <div className="g-table">
          <div className="g-thead grid gap-2 px-4"
            style={{ gridTemplateColumns: '40px 1fr 100px 100px 60px 50px 65px 60px 70px 60px' }}>
            <span>#</span><span>Name / Group</span><span>Source</span><span>Dest</span>
            <span>Proto</span><span>Port</span><span>Action</span>
            <span title="Packet hits">Hits</span>
            <span>Synced</span>
            <span className="text-right">Edit</span>
          </div>

          {loading ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          ) : filtered.length === 0 ? (
            <div className="py-16 text-center">
              <Network className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>No firewall rules.</p>
            </div>
          ) : filtered.map(r => (
            <div key={r.id}
              className="g-tr grid gap-2 items-center px-4"
              style={{
                gridTemplateColumns: '40px 1fr 100px 100px 60px 50px 65px 60px 70px 60px',
                opacity: r.enabled ? 1 : 0.5,
              }}>
              <span className="mono text-[11px]" style={{ color: 'var(--text-3)' }}>{r.id}</span>

              <div className="flex items-center gap-2 min-w-0">
                <button onClick={() => toggleEnabled(r)}
                  className="h-3.5 w-3.5 rounded shrink-0 border transition-all"
                  style={{
                    background: r.enabled ? 'var(--accent)' : 'transparent',
                    borderColor: r.enabled ? 'var(--accent)' : 'var(--border)',
                  }}
                  title={r.enabled ? 'Enabled' : 'Disabled'} />
                <div className="min-w-0">
                  <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{r.name}</p>
                  {r.group_name && r.group_name !== 'default' && (
                    <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{r.group_name}</p>
                  )}
                </div>
              </div>

              <span className="mono text-[11px] truncate" style={{ color: 'var(--text-2)' }}>
                {r.source_ip || 'any'}
              </span>
              <span className="mono text-[11px] truncate" style={{ color: 'var(--text-2)' }}>
                {r.destination_ip || 'any'}
              </span>
              <span className="mono text-[11px] uppercase" style={{ color: 'var(--text-2)' }}>{r.protocol}</span>
              <span className="mono text-[11px]" style={{ color: 'var(--text-2)' }}>{r.port || 'any'}</span>
              <span className={r.action === 'deny' ? 's-critical' : 's-online'}>{r.action}</span>

              <span className="text-[11px] font-mono" style={{ color: r.hit_count > 0 ? 'var(--accent)' : 'var(--text-3)' }}>
                {r.hit_count > 0 ? r.hit_count.toLocaleString() : '—'}
              </span>

              <span className="text-[10px]" style={{ color: r.synced_at ? 'var(--green)' : 'var(--text-3)' }}>
                {r.synced_at ? timeAgo(r.synced_at) : '—'}
              </span>

              <div className="flex items-center justify-end gap-1">
                <button onClick={() => openEdit(r)} className="p-1 rounded" style={{ color: 'var(--text-3)' }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--accent)'}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                  <Edit2 className="h-3.5 w-3.5" />
                </button>
                <button onClick={() => del(r.id)} className="p-1 rounded" style={{ color: 'var(--text-3)' }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--red)'}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Sync Drawer ──────────────────────────────────────── */}
      {showSync && (
        <div className="fixed inset-0 z-50 flex">
          <div className="flex-1" style={{ background: 'rgba(0,0,0,0.5)' }} onClick={() => setShowSync(false)} />
          <div className="w-full max-w-md h-full overflow-y-auto shadow-2xl flex flex-col"
            style={{ background: 'var(--bg-1)', borderLeft: '1px solid var(--border)' }}>
            <div className="sticky top-0 px-5 py-4 flex items-center justify-between shrink-0"
              style={{ background: 'var(--bg-1)', borderBottom: '1px solid var(--border)', zIndex: 10 }}>
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Apply Firewall Rules</p>
              </div>
              <button onClick={() => setShowSync(false)} style={{ color: 'var(--text-2)' }}>
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="flex-1 p-5 space-y-5">
              {/* Summary */}
              <div className="rounded-xl p-4 space-y-2"
                style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
                <p className="text-xs font-semibold" style={{ color: 'var(--accent)' }}>Ready to push</p>
                <div className="grid grid-cols-3 gap-3 text-center">
                  {[
                    ['Enabled Rules', enabledCount],
                    ['Online Agents', onlineAgents.length],
                    ['Unsynced',      pendingSync],
                  ].map(([label, val]) => (
                    <div key={String(label)}>
                      <p className="text-xl font-bold" style={{ color: 'var(--text-1)' }}>{val}</p>
                      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{label}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Group filter */}
              <div>
                <label className="text-xs mb-1.5 block font-medium" style={{ color: 'var(--text-2)' }}>
                  Rule group to sync (empty = all groups)
                </label>
                <select value={syncGroup} onChange={e => setSyncGroup(e.target.value)}
                  className="g-select w-full text-xs">
                  <option value="">All groups</option>
                  {groups.map(g => <option key={g.name} value={g.name}>{g.name} ({g.enabled_rules} enabled)</option>)}
                </select>
              </div>

              {/* Mode */}
              <div>
                <label className="text-xs mb-1.5 block font-medium" style={{ color: 'var(--text-2)' }}>Sync mode</label>
                <div className="flex gap-2">
                  {(['replace', 'append'] as const).map(m => (
                    <button key={m} onClick={() => setSyncMode(m)}
                      className="flex-1 py-2 rounded-xl text-xs font-medium capitalize transition-all"
                      style={{
                        background: syncMode === m ? 'var(--accent-glow)' : 'var(--glass-bg)',
                        border: `1px solid ${syncMode === m ? 'var(--accent-border)' : 'var(--border)'}`,
                        color: syncMode === m ? 'var(--accent)' : 'var(--text-2)',
                      }}>
                      {m}
                    </button>
                  ))}
                </div>
                <p className="text-[10px] mt-1.5" style={{ color: 'var(--text-3)' }}>
                  {syncMode === 'replace'
                    ? 'Flushes the XCLOAK iptables chain and repopulates it.'
                    : 'Appends new rules to existing chain without flushing.'}
                </p>
              </div>

              {/* Manage IP */}
              <div>
                <label className="text-xs mb-1.5 block font-medium" style={{ color: 'var(--text-2)' }}>
                  Management IP (always whitelisted)
                </label>
                <input value={manageIP} onChange={e => setManageIP(e.target.value)}
                  placeholder="10.0.0.1 (XCloak server IP)" className="g-input w-full mono text-xs" />
              </div>

              {/* Target agents */}
              <div>
                <label className="text-xs mb-1.5 block font-medium" style={{ color: 'var(--text-2)' }}>Target agents</label>
                <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                  <div className="flex items-center gap-3 px-3 py-2.5"
                    style={{ borderBottom: '1px solid var(--border)' }}>
                    <input type="checkbox" checked={syncAgents.length === 0}
                      onChange={e => e.target.checked && setSyncAgents([])} />
                    <div>
                      <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>All online agents</p>
                      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{onlineAgents.length} currently online</p>
                    </div>
                  </div>
                  {agents.map(a => (
                    <div key={a.id} className="flex items-center gap-3 px-3 py-2"
                      style={{ opacity: a.status === 'online' ? 1 : 0.4 }}>
                      <input type="checkbox" checked={syncAgents.includes(a.id)}
                        onChange={e => setSyncAgents(prev =>
                          e.target.checked ? [...prev, a.id] : prev.filter(id => id !== a.id)
                        )}
                        disabled={a.status !== 'online'} />
                      <div className="flex-1 min-w-0">
                        <p className="text-xs truncate" style={{ color: 'var(--text-1)' }}>{a.hostname}</p>
                        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{a.ip_address}</p>
                      </div>
                      <span className={a.status === 'online' ? 's-online' : 's-offline'} style={{ fontSize: 9 }}>
                        {a.status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <button onClick={doSync}
                disabled={syncing || enabledCount === 0 || (syncAgents.length === 0 && onlineAgents.length === 0)}
                className="g-btn g-btn-primary w-full justify-center">
                {syncing
                  ? <><Loader2 className="h-4 w-4 animate-spin" /> Dispatching…</>
                  : <><Upload className="h-4 w-4" /> Push{syncGroup ? ` "${syncGroup}"` : ''} to{' '}
                    {syncAgents.length || onlineAgents.length} Agent{(syncAgents.length || onlineAgents.length) !== 1 ? 's' : ''}</>}
              </button>

              {syncResults && (
                <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                  <p className="px-4 py-2.5 text-[10px] font-semibold uppercase" style={{ color: 'var(--text-3)', borderBottom: '1px solid var(--border)' }}>
                    Dispatch Results
                  </p>
                  {syncResults.map((r, i) => (
                    <div key={i} className="flex items-center gap-3 px-4 py-2.5"
                      style={{ borderBottom: i < syncResults.length - 1 ? '1px solid var(--border)' : undefined }}>
                      {r.dispatched
                        ? <CheckCircle className="h-4 w-4 shrink-0" style={{ color: 'var(--green)' }} />
                        : <XCircle className="h-4 w-4 shrink-0" style={{ color: 'var(--red)' }} />}
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{r.hostname}</p>
                        <p className="text-[10px]" style={{ color: r.error ? 'var(--red)' : 'var(--text-3)' }}>
                          {r.error || `${r.rule_count} rules · task #${r.task_id}`}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Sync history */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <p className="text-xs font-medium" style={{ color: 'var(--text-2)' }}>Sync History</p>
                  <button onClick={loadSyncLog} style={{ color: 'var(--text-3)' }}>
                    <RefreshCw className={`h-3.5 w-3.5 ${loadingLog ? 'animate-spin' : ''}`} />
                  </button>
                </div>
                {syncLog.length === 0 ? (
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>No syncs yet.</p>
                ) : (
                  <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                    {syncLog.slice(0, 15).map((l: any, i: number) => (
                      <div key={l.id} className="flex items-center gap-3 px-3 py-2"
                        style={{ borderBottom: i < Math.min(syncLog.length, 15) - 1 ? '1px solid var(--border)' : undefined }}>
                        <span className="text-[10px] font-medium"
                          style={{ color: l.status === 'dispatched' ? 'var(--accent)' : l.status === 'failed' ? 'var(--red)' : 'var(--green)' }}>
                          {l.status}
                        </span>
                        <span className="flex-1 text-[11px] truncate" style={{ color: 'var(--text-2)' }}>
                          {l.hostname} · {l.rule_count} rules
                        </span>
                        <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(l.synced_at)}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Add / Edit modal ─────────────────────────────────── */}
      {(showAdd || showEdit) && (
        <div className="g-modal-backdrop"
          onClick={e => e.target === e.currentTarget && (setShowAdd(false), setShowEdit(null))}>
          <div className="g-modal" style={{ maxWidth: 580 }}>
            <div className="flex items-center justify-between p-5"
              style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
                {showEdit ? 'Edit Firewall Rule' : 'New Firewall Rule'}
              </h2>
              <button onClick={() => { setShowAdd(false); setShowEdit(null); }} style={{ color: 'var(--text-2)' }}>
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="p-5 space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Name *</label>
                  <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                    placeholder="Block outbound 4444" className="g-input w-full" />
                </div>
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Group</label>
                  <input value={form.group_name} onChange={e => setForm(f => ({ ...f, group_name: e.target.value }))}
                    placeholder="default" className="g-input w-full"
                    list="group-list" />
                  <datalist id="group-list">
                    {groups.map(g => <option key={g.name} value={g.name} />)}
                  </datalist>
                </div>
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Description</label>
                <input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  placeholder="Optional description" className="g-input w-full" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Source IP / CIDR</label>
                  <input value={form.source_ip} onChange={e => setForm(f => ({ ...f, source_ip: e.target.value }))}
                    placeholder="any" className="g-input w-full mono" />
                </div>
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Destination IP / CIDR</label>
                  <input value={form.destination_ip} onChange={e => setForm(f => ({ ...f, destination_ip: e.target.value }))}
                    placeholder="any" className="g-input w-full mono" />
                </div>
              </div>
              <div className="grid grid-cols-4 gap-3">
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Protocol</label>
                  <select value={form.protocol} onChange={e => setForm(f => ({ ...f, protocol: e.target.value }))}
                    className="g-select w-full">
                    {PROTOS.map(p => <option key={p}>{p}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Port</label>
                  <input type="number" value={form.port || ''}
                    onChange={e => setForm(f => ({ ...f, port: parseInt(e.target.value) || 0 }))}
                    placeholder="any" className="g-input w-full mono" />
                </div>
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Action</label>
                  <select value={form.action} onChange={e => setForm(f => ({ ...f, action: e.target.value }))}
                    className="g-select w-full">
                    {ACTIONS.map(a => <option key={a}>{a}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Priority</label>
                  <input type="number" value={form.priority}
                    onChange={e => setForm(f => ({ ...f, priority: parseInt(e.target.value) || 100 }))}
                    placeholder="100" className="g-input w-full" />
                </div>
              </div>
              <div className="flex items-center gap-2">
                <input type="checkbox" id="enabled" checked={form.enabled}
                  onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))} />
                <label htmlFor="enabled" className="text-xs" style={{ color: 'var(--text-2)' }}>
                  Enabled (included in next sync)
                </label>
              </div>
            </div>
            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => { setShowAdd(false); setShowEdit(null); }}
                className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={showEdit ? update : add}
                disabled={saving || !form.name.trim()}
                className="g-btn g-btn-primary flex-1 justify-center">
                {saving ? 'Saving…' : showEdit ? 'Update Rule' : 'Create Rule'}
              </button>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
