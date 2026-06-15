'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { firewallAPI, agentsAPI } from '@/lib/api';
import api from '@/lib/api';
import { FirewallRule, Agent } from '@/types';
import { timeAgo } from '@/lib/utils';
import {
  Network, Plus, Trash2, Edit2, X, Search,
  Upload, CheckCircle, XCircle, Loader2, RefreshCw,
  Shield, AlertTriangle,
} from 'lucide-react';

const PROTOS  = ['tcp', 'udp', 'icmp', 'any'];
const ACTIONS = ['allow', 'deny'];
const EMPTY   = { name: '', source_ip: '', destination_ip: '', protocol: 'tcp', port: 0, action: 'allow', enabled: true, priority: 100 };

interface SyncResult {
  agent_id:   number;
  hostname:   string;
  task_id:    number;
  rule_count: number;
  dispatched: boolean;
  error?:     string;
}

export default function FirewallPage() {
  const [rules, setRules]         = useState<FirewallRule[]>([]);
  const [agents, setAgents]       = useState<Agent[]>([]);
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch]       = useState('');
  const [showAdd, setShowAdd]     = useState(false);
  const [showEdit, setShowEdit]   = useState<FirewallRule | null>(null);
  const [form, setForm]           = useState({ ...EMPTY });
  const [saving, setSaving]       = useState(false);
  const [toast, setToast]         = useState<string | null>(null);

  // Sync state
  const [showSync, setShowSync]       = useState(false);
  const [syncing, setSyncing]         = useState(false);
  const [syncResults, setSyncResults] = useState<SyncResult[] | null>(null);
  const [syncMode, setSyncMode]       = useState<'replace' | 'append'>('replace');
  const [manageIP, setManageIP]       = useState('');
  const [syncAgents, setSyncAgents]   = useState<number[]>([]); // empty = all
  const [syncLog, setSyncLog]         = useState<any[]>([]);
  const [loadingLog, setLoadingLog]   = useState(false);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3500); };

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const [rRes, aRes] = await Promise.allSettled([
        firewallAPI.getAll(),
        agentsAPI.getAll(),
      ]);
      if (rRes.status === 'fulfilled') setRules(rRes.value.data || []);
      if (aRes.status === 'fulfilled') setAgents(aRes.value.data || []);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  const loadSyncLog = useCallback(async () => {
    setLoadingLog(true);
    try {
      const r = await api.get('/firewall/sync/log');
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
  };

  const toggleEnabled = async (rule: FirewallRule) => {
    await firewallAPI.update(rule.id, { ...rule, enabled: !rule.enabled });
    load();
  };

  const openEdit = (r: FirewallRule) => {
    setForm({
      name: r.name, source_ip: r.source_ip, destination_ip: r.destination_ip,
      protocol: r.protocol, port: r.port, action: r.action,
      enabled: r.enabled, priority: (r as any).priority || 100,
    });
    setShowEdit(r);
  };

  const doSync = async () => {
    setSyncing(true);
    setSyncResults(null);
    try {
      const r = await api.post('/firewall/sync', {
        agent_ids:  syncAgents,
        mode:       syncMode,
        manage_ip:  manageIP,
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
  );

  const enabledCount  = rules.filter(r => r.enabled).length;
  const pendingSync   = rules.filter(r => r.enabled && !(r as any).synced_at).length;
  const allowCount    = rules.filter(r => r.action === 'allow').length;
  const denyCount     = rules.filter(r => r.action === 'deny').length;
  const onlineAgents  = agents.filter(a => a.status === 'online');

  return (
    <RootLayout
      title="Firewall"
      subtitle={`${rules.length} rules · ${allowCount} allow · ${denyCount} deny · ${enabledCount} enabled`}
      onRefresh={() => load(true)} refreshing={refreshing}
      actions={
        <div className="flex items-center gap-2">
          {pendingSync > 0 && (
            <div className="flex items-center gap-1.5 text-[11px] px-2.5 py-1 rounded-lg"
              style={{ background: 'rgba(251,191,36,0.15)', border: '1px solid rgba(251,191,36,0.3)', color: 'var(--yellow)' }}>
              <AlertTriangle className="h-3 w-3" />
              {pendingSync} unsynced
            </div>
          )}
          <button onClick={() => setShowSync(true)}
            className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
            <Upload className="h-3.5 w-3.5" />
            Apply to Agents
          </button>
          <button onClick={() => { setForm({ ...EMPTY }); setShowAdd(true); }}
            className="g-btn g-btn-primary text-xs">
            <Plus className="h-3.5 w-3.5" /> Add Rule
          </button>
        </div>
      }>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm"
          style={{ color: 'var(--text-1)', minWidth: 200 }}>
          {toast}
        </div>
      )}

      <div className="space-y-4">
        <div className="relative max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search rule, source, destination…" className="g-input pl-9" />
        </div>

        <div className="g-table">
          <div className="g-thead grid gap-2 px-4"
            style={{ gridTemplateColumns: '40px 1fr 120px 120px 65px 55px 70px 70px 60px' }}>
            <span>#</span><span>Name</span><span>Source</span><span>Dest</span>
            <span>Proto</span><span>Port</span><span>Action</span><span>Synced</span>
            <span className="text-right">Edit</span>
          </div>

          {loading ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          ) : filtered.length === 0 ? (
            <div className="py-16 text-center">
              <Network className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>No firewall rules.</p>
            </div>
          ) : filtered.map(r => {
            const syncedAt = (r as any).synced_at;
            return (
              <div key={r.id}
                className="g-tr grid gap-2 items-center px-4"
                style={{
                  gridTemplateColumns: '40px 1fr 120px 120px 65px 55px 70px 70px 60px',
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
                    title={r.enabled ? 'Enabled — click to disable' : 'Disabled — click to enable'} />
                  <span className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{r.name}</span>
                </div>
                <span className="mono text-[11px] truncate" style={{ color: 'var(--text-2)' }}>
                  {r.source_ip || 'any'}
                </span>
                <span className="mono text-[11px] truncate" style={{ color: 'var(--text-2)' }}>
                  {r.destination_ip || 'any'}
                </span>
                <span className="mono text-[11px] uppercase" style={{ color: 'var(--text-2)' }}>{r.protocol}</span>
                <span className="mono text-[11px]" style={{ color: 'var(--text-2)' }}>
                  {r.port || 'any'}
                </span>
                <span className={r.action === 'deny' ? 's-critical' : 's-online'}>{r.action}</span>
                <span className="text-[10px]" style={{ color: syncedAt ? 'var(--green)' : 'var(--text-3)' }}>
                  {syncedAt ? timeAgo(syncedAt) : '—'}
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
            );
          })}
        </div>
      </div>

      {/* ── Sync Drawer ──────────────────────────────────────── */}
      {showSync && (
        <div className="fixed inset-0 z-50 flex">
          <div className="flex-1" style={{ background: 'rgba(0,0,0,0.5)' }} onClick={() => setShowSync(false)} />
          <div className="w-full max-w-md h-full overflow-y-auto shadow-2xl flex flex-col"
            style={{ background: 'var(--bg-1)', borderLeft: '1px solid var(--border)' }}>

            {/* Header */}
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

              {/* Summary card */}
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

              {/* Options */}
              <div className="space-y-3">
                <div>
                  <label className="text-xs mb-1.5 block font-medium" style={{ color: 'var(--text-2)' }}>
                    Sync mode
                  </label>
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
                      ? 'Flushes the XCLOAK iptables chain and repopulates it. Safest.'
                      : 'Appends new rules to existing chain without flushing.'}
                  </p>
                </div>

                <div>
                  <label className="text-xs mb-1.5 block font-medium" style={{ color: 'var(--text-2)' }}>
                    Management IP (always whitelisted)
                  </label>
                  <input value={manageIP} onChange={e => setManageIP(e.target.value)}
                    placeholder="10.0.0.1 (XCloak server IP)"
                    className="g-input w-full mono text-xs" />
                  <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                    This IP stays accessible even if deny-all rules are present.
                  </p>
                </div>

                <div>
                  <label className="text-xs mb-1.5 block font-medium" style={{ color: 'var(--text-2)' }}>
                    Target agents
                  </label>
                  <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                    <div className="flex items-center gap-3 px-3 py-2.5"
                      style={{ borderBottom: '1px solid var(--border)' }}>
                      <input type="checkbox"
                        checked={syncAgents.length === 0}
                        onChange={e => e.target.checked && setSyncAgents([])}
                        className="rounded" />
                      <div>
                        <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>All online agents</p>
                        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                          {onlineAgents.length} currently online
                        </p>
                      </div>
                    </div>
                    {agents.map(a => (
                      <div key={a.id} className="flex items-center gap-3 px-3 py-2"
                        style={{ opacity: a.status === 'online' ? 1 : 0.4 }}>
                        <input type="checkbox"
                          checked={syncAgents.includes(a.id)}
                          onChange={e => {
                            setSyncAgents(prev =>
                              e.target.checked
                                ? [...prev, a.id]
                                : prev.filter(id => id !== a.id)
                            );
                          }}
                          disabled={a.status !== 'online'}
                          className="rounded" />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs truncate" style={{ color: 'var(--text-1)' }}>{a.hostname}</p>
                          <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{a.ip_address}</p>
                        </div>
                        <span className={a.status === 'online' ? 's-online' : 's-offline'}
                          style={{ fontSize: 9 }}>
                          {a.status}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Dispatch button */}
              <button
                onClick={doSync}
                disabled={syncing || enabledCount === 0 || (syncAgents.length === 0 && onlineAgents.length === 0)}
                className="g-btn g-btn-primary w-full justify-center">
                {syncing
                  ? <><Loader2 className="h-4 w-4 animate-spin" /> Dispatching…</>
                  : <><Upload className="h-4 w-4" /> Push {enabledCount} Rules to {syncAgents.length || onlineAgents.length} Agent{(syncAgents.length || onlineAgents.length) !== 1 ? 's' : ''}</>}
              </button>

              {/* Sync results */}
              {syncResults && (
                <div className="rounded-xl overflow-hidden"
                  style={{ border: '1px solid var(--border)' }}>
                  <p className="px-4 py-2.5 text-[10px] font-semibold uppercase tracking-wider"
                    style={{ color: 'var(--text-3)', borderBottom: '1px solid var(--border)' }}>
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
                        <span className={`text-[10px] font-medium ${l.status === 'success' ? 'text-green-400' : l.status === 'failed' ? 'text-red-400' : ''}`}
                          style={{ color: l.status === 'dispatched' ? 'var(--accent)' : undefined }}>
                          {l.status}
                        </span>
                        <span className="flex-1 text-[11px] truncate" style={{ color: 'var(--text-2)' }}>
                          {l.hostname} · {l.rule_count} rules
                        </span>
                        <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                          {timeAgo(l.synced_at)}
                        </span>
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
          <div className="g-modal" style={{ maxWidth: 560 }}>
            <div className="flex items-center justify-between p-5"
              style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
                {showEdit ? 'Edit Firewall Rule' : 'New Firewall Rule'}
              </h2>
              <button onClick={() => { setShowAdd(false); setShowEdit(null); }}
                style={{ color: 'var(--text-2)' }}>
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="p-5 space-y-3">
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Name *</label>
                <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  placeholder="Block outbound 4444" className="g-input w-full" />
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
