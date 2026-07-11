'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { firewallAPI, agentsAPI } from '@/lib/api';
import { FirewallRule, FirewallGroup, FirewallConflict, FirewallStats, Agent } from '@/types';
import { timeAgo } from '@/lib/utils';
import {
  Network, Plus, Trash2, Edit2, X, Search,
  Upload, CheckCircle, XCircle, Loader2, RefreshCw,
  Shield, AlertTriangle, Zap, BarChart2, ChevronDown, ChevronRight,
  Layers, Copy, Download, FileJson, BookOpen, Clock, Tag,
  ArrowDown, ArrowUp, ArrowLeftRight, ChevronUp,
} from 'lucide-react';

const PROTOS     = ['tcp', 'udp', 'icmp', 'any'];
const ACTIONS    = ['allow', 'deny', 'drop', 'reject', 'log'];
const DIRECTIONS = ['both', 'in', 'out'];

const EMPTY_FORM = {
  name: '', description: '', group_name: 'default',
  source_ip: '', destination_ip: '', protocol: 'tcp',
  port: 0, port_range: '', direction: 'both' as 'in' | 'out' | 'both',
  log_enabled: false, log_prefix: '',
  action: 'allow', enabled: true, priority: 100,
  tags: [] as string[], expires_at: null as string | null,
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
// Direction badge
// ─────────────────────────────────────────────────────────────────────────────
function DirBadge({ dir }: { dir: string }) {
  const Icon = dir === 'in' ? ArrowDown : dir === 'out' ? ArrowUp : ArrowLeftRight;
  return (
    <span className="inline-flex items-center gap-0.5 text-[9px] font-bold uppercase px-1.5 py-0.5 rounded"
      style={{
        background: dir === 'in' ? 'rgba(59,130,246,0.15)' : dir === 'out' ? 'rgba(168,85,247,0.15)' : 'var(--glass-bg)',
        color:      dir === 'in' ? '#3b82f6'               : dir === 'out' ? '#a855f7'               : 'var(--text-3)',
        border:     `1px solid ${dir === 'in' ? 'rgba(59,130,246,0.3)' : dir === 'out' ? 'rgba(168,85,247,0.3)' : 'var(--border)'}`,
      }}>
      <Icon className="h-2.5 w-2.5" /> {dir}
    </span>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Conflicts panel
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
          {conflicts.length} conflict{conflicts.length !== 1 ? 's' : ''} detected
          {errorCount > 0 && ` — ${errorCount} shadow${errorCount !== 1 ? 's' : ''}`}
        </span>
        {open ? <ChevronUp className="h-4 w-4" style={{ color: 'var(--text-3)' }} />
               : <ChevronDown className="h-4 w-4" style={{ color: 'var(--text-3)' }} />}
      </button>
      {open && (
        <div className="divide-y" style={{ borderTop: '1px solid var(--border)' }}>
          {conflicts.map((c, i) => (
            <div key={i} className="px-4 py-2.5">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 rounded"
                  style={{
                    background: c.severity === 'error' ? 'var(--red-bg)' : 'rgba(251,191,36,0.15)',
                    color:      c.severity === 'error' ? 'var(--red)'    : 'var(--yellow)',
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
function StatsBar({ stats, policy }: { stats: FirewallStats | null; policy: string }) {
  if (!stats) return null;
  const topRule = stats.top_rules?.[0];
  return (
    <div className="grid grid-cols-4 gap-3 mb-2">
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
          <Clock className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
          <span className="text-[10px] uppercase font-bold" style={{ color: 'var(--text-3)' }}>Expiring</span>
        </div>
        <p className="text-2xl font-bold" style={{ color: stats.expiring_soon > 0 ? 'var(--yellow)' : 'var(--text-1)' }}>
          {stats.expiring_soon || 0}
        </p>
        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>in next 7 days</p>
      </div>
      <div className="rounded-xl p-3" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
        <div className="flex items-center gap-2 mb-1">
          <Shield className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
          <span className="text-[10px] uppercase font-bold" style={{ color: 'var(--text-3)' }}>Default Policy</span>
        </div>
        <p className="text-sm font-bold capitalize"
          style={{ color: policy === 'deny' ? 'var(--red)' : 'var(--green)' }}>
          {policy}
        </p>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Templates picker modal
// ─────────────────────────────────────────────────────────────────────────────
function TemplatesPicker({ onSelect, onClose }: {
  onSelect: (t: any) => void;
  onClose: () => void;
}) {
  const [templates, setTemplates] = useState<any[]>([]);
  const [search, setSearch] = useState('');
  useEffect(() => {
    firewallAPI.getTemplates().then(r => setTemplates(r.data || [])).catch(() => {});
  }, []);

  const filtered = templates.filter(t =>
    !search || t.name.toLowerCase().includes(search.toLowerCase()) ||
    t.description?.toLowerCase().includes(search.toLowerCase()) ||
    (t.tags || []).some((tag: string) => tag.includes(search.toLowerCase()))
  );

  return (
    <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="g-modal" style={{ maxWidth: 600 }}>
        <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="flex items-center gap-2">
            <BookOpen className="h-4 w-4" style={{ color: 'var(--accent)' }} />
            <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Rule Templates</h2>
          </div>
          <button onClick={onClose} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
        </div>
        <div className="p-4">
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search templates…" className="g-input w-full mb-3" />
          <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
            {filtered.map((t, i) => (
              <div key={i} className="rounded-xl p-3 flex items-start gap-3 cursor-pointer transition-all"
                style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}
                onClick={() => { onSelect(t); onClose(); }}>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{t.name}</p>
                    <span className={t.action === 'allow' || t.action === 'log' ? 's-online' : 's-critical'}>
                      {t.action}
                    </span>
                    <DirBadge dir={t.direction || 'both'} />
                  </div>
                  <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{t.description}</p>
                  {(t.tags || []).length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {t.tags.map((tag: string) => (
                        <span key={tag} className="text-[9px] px-1.5 py-0.5 rounded"
                          style={{ background: 'rgba(99,102,241,0.15)', color: 'var(--accent)', border: '1px solid rgba(99,102,241,0.3)' }}>
                          {tag}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                <div className="text-[10px] shrink-0 font-mono" style={{ color: 'var(--text-3)' }}>
                  {t.port_range || (t.port ? String(t.port) : 'any')}
                </div>
              </div>
            ))}
            {filtered.length === 0 && (
              <p className="text-xs py-8 text-center" style={{ color: 'var(--text-3)' }}>No templates match your search.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main page
// ─────────────────────────────────────────────────────────────────────────────
export default function FirewallPage() {
  const [rules, setRules]           = useState<FirewallRule[]>([]);
  const [agents, setAgents]         = useState<Agent[]>([]);
  const [groups, setGroups]         = useState<FirewallGroup[]>([]);
  const [conflicts, setConflicts]   = useState<FirewallConflict[]>([]);
  const [stats, setStats]           = useState<FirewallStats | null>(null);
  const [policy, setPolicy]         = useState('allow');
  const [loading, setLoading]       = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch]         = useState('');
  const [activeGroup, setActiveGroup] = useState('');
  const [showAdd, setShowAdd]       = useState(false);
  const [showEdit, setShowEdit]     = useState<FirewallRule | null>(null);
  const [form, setForm]             = useState<typeof EMPTY_FORM>({ ...EMPTY_FORM });
  const [tagsInput, setTagsInput]   = useState('');
  const [saving, setSaving]         = useState(false);
  const [toast, setToast]           = useState<string | null>(null);
  const [actionFilter, setActionFilter] = useState('');
  const [protoFilter, setProtoFilter]   = useState('');
  const [dirFilter, setDirFilter]       = useState('');
  const [selected, setSelected]     = useState<Set<number>>(new Set());
  const [bulkBusy, setBulkBusy]     = useState(false);
  const [showTemplates, setShowTemplates] = useState(false);
  const [showPolicyModal, setShowPolicyModal] = useState(false);
  const importRef = useRef<HTMLInputElement>(null);

  // Sync drawer state
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
    const results = await Promise.allSettled([
      firewallAPI.getGroups(),
      firewallAPI.getConflicts(),
      firewallAPI.getStats(),
      firewallAPI.getPolicy(),
    ]);
    if (results[0].status === 'fulfilled') setGroups(results[0].value.data || []);
    if (results[1].status === 'fulfilled') setConflicts(results[1].value.data || []);
    if (results[2].status === 'fulfilled') setStats(results[2].value.data || null);
    if (results[3].status === 'fulfilled') setPolicy(results[3].value.data?.default_action || 'allow');
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
    try { const r = await firewallAPI.getSyncLog(); setSyncLog(r.data || []); }
    finally { setLoadingLog(false); }
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { if (showSync) loadSyncLog(); }, [showSync, loadSyncLog]);

  // ── CRUD ──
  const add = async () => {
    setSaving(true);
    try {
      await firewallAPI.create({ ...form, tags: parseTags(tagsInput) });
      load(); setShowAdd(false); setForm({ ...EMPTY_FORM }); setTagsInput('');
      notify('Rule created');
    } catch (e: any) { notify(e?.response?.data?.error || 'Create failed'); }
    finally { setSaving(false); }
  };

  const update = async () => {
    if (!showEdit) return;
    setSaving(true);
    try {
      await firewallAPI.update(showEdit.id, { ...form, tags: parseTags(tagsInput) });
      load(); setShowEdit(null); notify('Rule updated');
    } finally { setSaving(false); }
  };

  const del = async (id: number) => {
    if (!confirm('Delete this rule?')) return;
    await firewallAPI.delete(id);
    setRules(p => p.filter(r => r.id !== id));
    setSelected(s => { const n = new Set(s); n.delete(id); return n; });
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
      protocol: r.protocol, port: r.port, port_range: r.port_range || '',
      direction: r.direction || 'both',
      log_enabled: r.log_enabled || false, log_prefix: r.log_prefix || '',
      action: r.action, enabled: r.enabled, priority: r.priority || 100,
      tags: r.tags || [], expires_at: r.expires_at,
    });
    setTagsInput((r.tags || []).join(', '));
    setShowEdit(r);
  };

  const applyTemplate = (t: any) => {
    setForm(f => ({
      ...f,
      name: t.name, description: t.description || '',
      group_name: t.group_name || 'default',
      protocol: t.protocol || 'tcp',
      port: t.port || 0, port_range: t.port_range || '',
      direction: t.direction || 'both',
      action: t.action || 'allow',
      tags: t.tags || [],
    }));
    setTagsInput((t.tags || []).join(', '));
    setShowAdd(true);
  };

  // ── Bulk ──
  const toggleSelect = (id: number) => {
    setSelected(s => {
      const n = new Set(s);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  };

  const selectAll = () => {
    if (selected.size === filtered.length) { setSelected(new Set()); }
    else { setSelected(new Set(filtered.map(r => r.id))); }
  };

  const bulkAction = async (action: 'enable' | 'disable' | 'delete') => {
    if (selected.size === 0) return;
    if (action === 'delete' && !confirm(`Delete ${selected.size} rule(s)?`)) return;
    setBulkBusy(true);
    try {
      const r = await firewallAPI.bulk([...selected], action);
      notify(`${action}: ${r.data.affected} rule(s) affected`);
      setSelected(new Set());
      load();
    } catch { notify('Bulk action failed'); }
    finally { setBulkBusy(false); }
  };

  // ── Export / Import ──
  const exportRules = () => {
    const blob = new Blob([JSON.stringify(rules, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = `xcloak-firewall-${Date.now()}.json`;
    a.click(); URL.revokeObjectURL(url);
  };

  const importFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const importRules = Array.isArray(parsed) ? parsed : parsed.rules;
      if (!Array.isArray(importRules)) { notify('Invalid file format — expected an array of rules'); return; }
      const mode = confirm(`Import ${importRules.length} rules?\nOK = append to existing, Cancel = replace all`) ? 'append' : 'replace';
      const r = await firewallAPI.import(importRules, mode);
      notify(`Imported ${r.data.imported} rules (${r.data.failed} failed)`);
      load();
    } catch { notify('Import failed — invalid JSON'); }
    finally { if (importRef.current) importRef.current.value = ''; }
  };

  // ── Sync ──
  const doSync = async () => {
    setSyncing(true); setSyncResults(null);
    try {
      const r = await firewallAPI.sync({ agent_ids: syncAgents, mode: syncMode, manage_ip: manageIP, group_name: syncGroup || undefined });
      setSyncResults(r.data.results || []);
      notify(r.data.message || 'Sync dispatched');
      load(); loadSyncLog();
    } catch (e: any) { notify(e?.response?.data?.error || 'Sync failed'); }
    finally { setSyncing(false); }
  };

  const cloneRule = async (r: FirewallRule) => {
    try {
      await firewallAPI.create({ ...r, id: undefined, name: `${r.name} (copy)`, enabled: false });
      load(); notify('Rule cloned (disabled)');
    } catch { notify('Clone failed'); }
  };

  // ── Filtered list ──
  const filtered = rules.filter(r => {
    if (actionFilter && r.action !== actionFilter) return false;
    if (protoFilter  && r.protocol !== protoFilter) return false;
    if (dirFilter    && (r.direction || 'both') !== dirFilter) return false;
    if (!search) return true;
    return (
      r.name?.toLowerCase().includes(search.toLowerCase()) ||
      r.source_ip?.includes(search) ||
      r.destination_ip?.includes(search) ||
      r.group_name?.toLowerCase().includes(search.toLowerCase()) ||
      (r.tags || []).some(t => t.toLowerCase().includes(search.toLowerCase()))
    );
  });

  const enabledCount  = rules.filter(r => r.enabled).length;
  const pendingSync   = rules.filter(r => r.enabled && !r.synced_at).length;
  const onlineAgents  = agents.filter(a => a.status === 'online');

  return (
    <RootLayout
      title="Firewall"
      subtitle={`${rules.length} rules · ${enabledCount} enabled · policy: ${policy}`}
      onRefresh={() => load(true)} refreshing={refreshing}
      actions={
        <div className="flex items-center gap-2">
          {pendingSync > 0 && (
            <div className="flex items-center gap-1.5 text-[11px] px-2.5 py-1 rounded-lg"
              style={{ background: 'rgba(251,191,36,0.15)', border: '1px solid rgba(251,191,36,0.3)', color: 'var(--yellow)' }}>
              <AlertTriangle className="h-3 w-3" /> {pendingSync} unsynced
            </div>
          )}
          <button onClick={() => setShowPolicyModal(true)}
            className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
            <Shield className="h-3.5 w-3.5" />
            Policy: <span style={{ color: policy === 'deny' ? 'var(--red)' : 'var(--green)' }}>{policy}</span>
          </button>
          <button onClick={() => setShowTemplates(true)}
            className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
            <BookOpen className="h-3.5 w-3.5" /> Templates
          </button>
          <label className="g-btn g-btn-ghost text-xs flex items-center gap-1.5 cursor-pointer">
            <FileJson className="h-3.5 w-3.5" /> Import
            <input ref={importRef} type="file" accept=".json" className="hidden" onChange={importFile} />
          </label>
          <button onClick={() => setShowSync(true)}
            className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
            <Upload className="h-3.5 w-3.5" /> Apply to Agents
          </button>
          <button onClick={() => { setForm({ ...EMPTY_FORM }); setTagsInput(''); setShowAdd(true); }}
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
        <StatsBar stats={stats} policy={policy} />
        <ConflictsPanel conflicts={conflicts} />

        {/* Group tabs */}
        {groups.length > 1 && (
          <div className="flex items-center gap-2 overflow-x-auto pb-1">
            <Layers className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />
            <button
              onClick={() => setActiveGroup('')}
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

        {/* Search + filters */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search name, IP, tag, group…" className="g-input pl-9" />
          </div>
          <div className="flex rounded-lg overflow-hidden" style={{ border: '1px solid var(--border)' }}>
            {['', 'allow', 'deny'].map(a => (
              <button key={a || 'all'} onClick={() => setActionFilter(a)}
                className="px-2.5 py-1.5 text-xs font-medium capitalize transition-all"
                style={{
                  background: actionFilter === a ? 'var(--accent)' : 'transparent',
                  color: actionFilter === a ? '#fff' : 'var(--text-3)',
                }}>
                {a || 'all'}
              </button>
            ))}
          </div>
          <div className="flex rounded-lg overflow-hidden" style={{ border: '1px solid var(--border)' }}>
            {['', ...PROTOS].map(p => (
              <button key={p || 'all'} onClick={() => setProtoFilter(p)}
                className="px-2.5 py-1.5 text-xs font-medium uppercase transition-all"
                style={{
                  background: protoFilter === p ? 'var(--accent)' : 'transparent',
                  color: protoFilter === p ? '#fff' : 'var(--text-3)',
                }}>
                {p || 'all'}
              </button>
            ))}
          </div>
          <div className="flex rounded-lg overflow-hidden" style={{ border: '1px solid var(--border)' }}>
            {['', 'in', 'out', 'both'].map(d => (
              <button key={d || 'all'} onClick={() => setDirFilter(d)}
                className="px-2.5 py-1.5 text-xs font-medium capitalize transition-all"
                style={{
                  background: dirFilter === d ? 'var(--accent)' : 'transparent',
                  color: dirFilter === d ? '#fff' : 'var(--text-3)',
                }}>
                {d || 'dir'}
              </button>
            ))}
          </div>
          <button onClick={exportRules}
            className="ml-auto flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg transition-all"
            style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
            <Download className="h-3.5 w-3.5" /> Export
          </button>
        </div>

        {/* Bulk action bar */}
        {selected.size > 0 && (
          <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl"
            style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
            <span className="text-xs font-medium" style={{ color: 'var(--accent)' }}>
              {selected.size} rule{selected.size !== 1 ? 's' : ''} selected
            </span>
            <div className="flex items-center gap-2 ml-auto">
              <button onClick={() => bulkAction('enable')} disabled={bulkBusy}
                className="text-xs px-3 py-1.5 rounded-lg transition-all"
                style={{ background: 'rgba(34,197,94,0.15)', color: 'var(--green)', border: '1px solid rgba(34,197,94,0.3)' }}>
                Enable
              </button>
              <button onClick={() => bulkAction('disable')} disabled={bulkBusy}
                className="text-xs px-3 py-1.5 rounded-lg transition-all"
                style={{ background: 'var(--glass-bg)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>
                Disable
              </button>
              <button onClick={() => bulkAction('delete')} disabled={bulkBusy}
                className="text-xs px-3 py-1.5 rounded-lg transition-all"
                style={{ background: 'var(--red-bg)', color: 'var(--red)', border: '1px solid rgba(239,68,68,0.3)' }}>
                Delete
              </button>
              <button onClick={() => setSelected(new Set())} style={{ color: 'var(--text-3)' }}>
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        )}

        {/* Rules table */}
        <div className="g-table">
          <div className="g-thead grid gap-2 px-4"
            style={{ gridTemplateColumns: '32px 32px 1fr 90px 90px 60px 90px 70px 60px 60px 70px 60px' }}>
            <span>
              <input type="checkbox" checked={selected.size > 0 && selected.size === filtered.length}
                ref={el => { if (el) el.indeterminate = selected.size > 0 && selected.size < filtered.length; }}
                onChange={selectAll} />
            </span>
            <span>#</span><span>Name / Group</span><span>Source</span><span>Dest</span>
            <span>Proto</span><span>Port/Range</span><span>Dir</span>
            <span>Action</span><span title="Packet hits">Hits</span>
            <span>Tags</span><span>Synced</span>
          </div>

          {loading ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          ) : filtered.length === 0 ? (
            <div className="py-16 text-center">
              <Network className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>No firewall rules.</p>
              <button onClick={() => setShowTemplates(true)}
                className="mt-3 text-xs underline" style={{ color: 'var(--accent)' }}>
                Start with a template
              </button>
            </div>
          ) : filtered.map(r => (
            <div key={r.id}
              className="g-tr grid gap-2 items-center px-4"
              style={{
                gridTemplateColumns: '32px 32px 1fr 90px 90px 60px 90px 70px 60px 60px 70px 60px',
                opacity: r.enabled ? 1 : 0.5,
                background: selected.has(r.id) ? 'rgba(99,102,241,0.05)' : undefined,
              }}>
              <input type="checkbox" checked={selected.has(r.id)}
                onChange={() => toggleSelect(r.id)} />

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
                  {r.expires_at && (
                    <p className="text-[9px]" style={{ color: 'var(--yellow)' }}>
                      expires {timeAgo(r.expires_at)}
                    </p>
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
              <span className="mono text-[11px]" style={{ color: 'var(--text-2)' }}>
                {r.port_range || (r.port ? String(r.port) : 'any')}
              </span>
              <DirBadge dir={r.direction || 'both'} />
              <span className={r.action === 'deny' || r.action === 'drop' ? 's-critical' : r.action === 'log' ? 's-warning' : 's-online'}>
                {r.action}
              </span>
              <span className="text-[11px] font-mono" style={{ color: r.hit_count > 0 ? 'var(--accent)' : 'var(--text-3)' }}>
                {r.hit_count > 0 ? r.hit_count.toLocaleString() : '—'}
              </span>
              <div className="flex flex-wrap gap-0.5">
                {(r.tags || []).slice(0, 2).map(t => (
                  <span key={t} className="text-[8px] px-1 py-0.5 rounded"
                    style={{ background: 'rgba(99,102,241,0.15)', color: 'var(--accent)' }}>
                    {t}
                  </span>
                ))}
                {(r.tags || []).length > 2 && (
                  <span className="text-[8px]" style={{ color: 'var(--text-3)' }}>+{r.tags.length - 2}</span>
                )}
              </div>
              <div className="flex items-center justify-end gap-0.5">
                <span className="text-[10px]" style={{ color: r.synced_at ? 'var(--green)' : 'var(--text-3)' }}>
                  {r.synced_at ? timeAgo(r.synced_at) : '—'}
                </span>
                <button onClick={() => cloneRule(r)} title="Clone" className="p-1 rounded" style={{ color: 'var(--text-3)' }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--accent)'}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                  <Copy className="h-3 w-3" />
                </button>
                <button onClick={() => openEdit(r)} title="Edit" className="p-1 rounded" style={{ color: 'var(--text-3)' }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--accent)'}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                  <Edit2 className="h-3 w-3" />
                </button>
                <button onClick={() => del(r.id)} title="Delete" className="p-1 rounded" style={{ color: 'var(--text-3)' }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--red)'}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                  <Trash2 className="h-3 w-3" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Templates modal */}
      {showTemplates && <TemplatesPicker onSelect={applyTemplate} onClose={() => setShowTemplates(false)} />}

      {/* Default policy modal */}
      {showPolicyModal && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setShowPolicyModal(false)}>
          <div className="g-modal" style={{ maxWidth: 380 }}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Default Firewall Policy</h2>
              </div>
              <button onClick={() => setShowPolicyModal(false)} style={{ color: 'var(--text-2)' }}>
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="p-5 space-y-4">
              <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                The default policy determines what happens to traffic that does not match any explicit rule.
              </p>
              <div className="grid grid-cols-2 gap-3">
                {(['allow', 'deny'] as const).map(p => (
                  <button key={p} onClick={async () => {
                    try {
                      await firewallAPI.setPolicy(p);
                      setPolicy(p);
                      setShowPolicyModal(false);
                      notify(`Default policy set to "${p}"`);
                    } catch { notify('Failed to update policy'); }
                  }}
                    className="py-4 rounded-xl text-sm font-bold capitalize transition-all"
                    style={{
                      background: policy === p ? (p === 'deny' ? 'var(--red-bg)' : 'rgba(34,197,94,0.15)') : 'var(--glass-bg)',
                      border:     policy === p ? `2px solid ${p === 'deny' ? 'var(--red)' : 'var(--green)'}` : '2px solid var(--border)',
                      color:      p === 'deny' ? 'var(--red)' : 'var(--green)',
                    }}>
                    {p === 'deny' ? 'Default Deny' : 'Default Allow'}
                    {policy === p && <span className="block text-[10px] mt-1 font-normal opacity-70">current</span>}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Sync drawer */}
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
              <div className="rounded-xl p-4 space-y-2"
                style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
                <p className="text-xs font-semibold" style={{ color: 'var(--accent)' }}>Ready to push</p>
                <div className="grid grid-cols-3 gap-3 text-center">
                  {[['Enabled', enabledCount], ['Online Agents', onlineAgents.length], ['Unsynced', pendingSync]].map(([label, val]) => (
                    <div key={String(label)}>
                      <p className="text-xl font-bold" style={{ color: 'var(--text-1)' }}>{val}</p>
                      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{label}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <label className="text-xs mb-1.5 block font-medium" style={{ color: 'var(--text-2)' }}>
                  Rule group (empty = all)
                </label>
                <select value={syncGroup} onChange={e => setSyncGroup(e.target.value)} className="g-select w-full text-xs">
                  <option value="">All groups</option>
                  {groups.map(g => <option key={g.name} value={g.name}>{g.name} ({g.enabled_rules} enabled)</option>)}
                </select>
              </div>

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
                    ? 'Atomic iptables-restore — flushes XCLOAK chain and repopulates atomically.'
                    : 'Appends new rules without flushing existing chain.'}
                </p>
              </div>

              <div>
                <label className="text-xs mb-1.5 block font-medium" style={{ color: 'var(--text-2)' }}>
                  Management IP (always whitelisted)
                </label>
                <input value={manageIP} onChange={e => setManageIP(e.target.value)}
                  placeholder="10.0.0.1" className="g-input w-full mono text-xs" />
              </div>

              <div>
                <label className="text-xs mb-1.5 block font-medium" style={{ color: 'var(--text-2)' }}>Target agents</label>
                <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                  <div className="flex items-center gap-3 px-3 py-2.5" style={{ borderBottom: '1px solid var(--border)' }}>
                    <input type="checkbox" checked={syncAgents.length === 0} onChange={e => e.target.checked && setSyncAgents([])} />
                    <div>
                      <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>All online agents</p>
                      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{onlineAgents.length} currently online</p>
                    </div>
                  </div>
                  {agents.map(a => (
                    <div key={a.id} className="flex items-center gap-3 px-3 py-2"
                      style={{ opacity: a.status === 'online' ? 1 : 0.4 }}>
                      <input type="checkbox" checked={syncAgents.includes(a.id)}
                        onChange={e => setSyncAgents(p => e.target.checked ? [...p, a.id] : p.filter(id => id !== a.id))}
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
                  : <><Upload className="h-4 w-4" /> Push to {syncAgents.length || onlineAgents.length} Agent{(syncAgents.length || onlineAgents.length) !== 1 ? 's' : ''}</>}
              </button>

              {syncResults && (
                <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                  <p className="px-4 py-2.5 text-[10px] font-semibold uppercase" style={{ color: 'var(--text-3)', borderBottom: '1px solid var(--border)' }}>
                    Results
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

      {/* Add / Edit modal */}
      {(showAdd || showEdit) && (
        <div className="g-modal-backdrop"
          onClick={e => e.target === e.currentTarget && (setShowAdd(false), setShowEdit(null))}>
          <div className="g-modal" style={{ maxWidth: 620 }}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
                  {showEdit ? 'Edit Firewall Rule' : 'New Firewall Rule'}
                </h2>
                {!showEdit && (
                  <button onClick={() => setShowTemplates(true)}
                    className="text-[11px] px-2.5 py-1 rounded-lg flex items-center gap-1"
                    style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-3)' }}>
                    <BookOpen className="h-3 w-3" /> from template
                  </button>
                )}
              </div>
              <button onClick={() => { setShowAdd(false); setShowEdit(null); }} style={{ color: 'var(--text-2)' }}>
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="p-5 space-y-3 max-h-[70vh] overflow-y-auto">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Name *</label>
                  <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                    placeholder="Block outbound C2" className="g-input w-full" />
                </div>
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Group</label>
                  <input value={form.group_name} onChange={e => setForm(f => ({ ...f, group_name: e.target.value }))}
                    placeholder="default" className="g-input w-full" list="group-list" />
                  <datalist id="group-list">
                    {groups.map(g => <option key={g.name} value={g.name} />)}
                  </datalist>
                </div>
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Description</label>
                <input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  placeholder="Optional" className="g-input w-full" />
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
              <div className="grid grid-cols-5 gap-3">
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Protocol</label>
                  <select value={form.protocol} onChange={e => setForm(f => ({ ...f, protocol: e.target.value }))}
                    className="g-select w-full">
                    {PROTOS.map(p => <option key={p}>{p}</option>)}
                  </select>
                </div>
                <div className="col-span-2">
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>
                    Port / Range <span style={{ color: 'var(--text-3)', fontWeight: 400 }}>(80, 8000-9000, 80,443)</span>
                  </label>
                  <input value={form.port_range} onChange={e => setForm(f => ({ ...f, port_range: e.target.value }))}
                    placeholder="any" className="g-input w-full mono" />
                </div>
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Direction</label>
                  <select value={form.direction} onChange={e => setForm(f => ({ ...f, direction: e.target.value as any }))}
                    className="g-select w-full">
                    {DIRECTIONS.map(d => <option key={d}>{d}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Action</label>
                  <select value={form.action} onChange={e => setForm(f => ({ ...f, action: e.target.value }))}
                    className="g-select w-full">
                    {ACTIONS.map(a => <option key={a}>{a}</option>)}
                  </select>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Priority</label>
                  <input type="number" value={form.priority}
                    onChange={e => setForm(f => ({ ...f, priority: parseInt(e.target.value) || 100 }))}
                    className="g-input w-full" />
                </div>
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>
                    Tags <span style={{ color: 'var(--text-3)', fontWeight: 400 }}>(comma-separated)</span>
                  </label>
                  <div className="relative">
                    <Tag className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
                    <input value={tagsInput} onChange={e => setTagsInput(e.target.value)}
                      placeholder="baseline, web, rdp" className="g-input w-full pl-8 mono" />
                  </div>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>
                    Expires at <span style={{ fontWeight: 400 }}>(leave empty for permanent)</span>
                  </label>
                  <input type="datetime-local"
                    value={form.expires_at ? form.expires_at.slice(0, 16) : ''}
                    onChange={e => setForm(f => ({ ...f, expires_at: e.target.value ? e.target.value + ':00Z' : null }))}
                    className="g-input w-full" />
                </div>
                <div className="flex flex-col justify-end gap-2 pb-0.5">
                  <div className="flex items-center gap-2">
                    <input type="checkbox" id="enabled" checked={form.enabled}
                      onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))} />
                    <label htmlFor="enabled" className="text-xs" style={{ color: 'var(--text-2)' }}>
                      Enabled
                    </label>
                  </div>
                  <div className="flex items-center gap-2">
                    <input type="checkbox" id="log_enabled" checked={form.log_enabled}
                      onChange={e => setForm(f => ({ ...f, log_enabled: e.target.checked }))} />
                    <label htmlFor="log_enabled" className="text-xs" style={{ color: 'var(--text-2)' }}>
                      Log matches
                    </label>
                  </div>
                </div>
              </div>
              {form.log_enabled && (
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Log prefix</label>
                  <input value={form.log_prefix} onChange={e => setForm(f => ({ ...f, log_prefix: e.target.value }))}
                    placeholder="xcloak: " className="g-input w-full mono" />
                </div>
              )}
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

// helpers
function parseTags(s: string): string[] {
  return s.split(',').map(t => t.trim()).filter(Boolean);
}
