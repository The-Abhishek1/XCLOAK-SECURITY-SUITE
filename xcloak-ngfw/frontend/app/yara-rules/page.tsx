'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { yaraAPI } from '@/lib/api';
import api from '@/lib/api';
import { YaraRule, YaraMatch } from '@/types';
import { timeAgo, sevClass } from '@/lib/utils';
import {
  Bug, Plus, Trash2, Edit2, X, ToggleLeft, ToggleRight, Search, FileWarning, Code2, Upload, CheckCircle,
  ChevronDown, ChevronUp, Clock, Hash,
} from 'lucide-react';
import { agentsAPI } from '@/lib/api';
import { Agent } from '@/types';

interface MatchedString { identifier: string; offset: string; data: string; }

interface ScheduledTaskLite {
  id: number;
  name: string;
  task_type: string;
  enabled: boolean;
  last_run_at: string | null;
  next_run_at: string | null;
}

const emptyRule = {
  name: '',
  description: '',
  rule_content: `rule MyRule
{
    strings:
        $a = "suspicious string"

    condition:
        $a
}`,
  enabled: true,
};

const TABS = [
  { id: 'rules',   label: 'Rules',   icon: Code2 },
  { id: 'matches', label: 'Matches', icon: FileWarning },
] as const;
type Tab = typeof TABS[number]['id'];

export default function YaraRulesPage() {
  const [tab, setTab]         = useState<Tab>('rules');
  const [rules, setRules]     = useState<YaraRule[]>([]);
  const [matches, setMatches] = useState<YaraMatch[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch]   = useState('');
  const [toast, setToast]     = useState<string | null>(null);

  const [showAdd, setShowAdd] = useState(false);
  const [showEdit, setShowEdit] = useState<YaraRule | null>(null);
  const [form, setForm]       = useState({ ...emptyRule });
  const [saving, setSaving]   = useState(false);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [scheduledScan, setScheduledScan] = useState<ScheduledTaskLite | null>(null);
  const [scheduling, setScheduling] = useState(false);
  const [agents, setAgents] = useState<Agent[]>([]);
  const agentName = (id: number) => agents.find(a => a.id === id)?.hostname || `#${id}`;

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    const [rr, mr, sr] = await Promise.allSettled([
      yaraAPI.getAll(), yaraAPI.getMatches(), api.get('/scheduler/tasks'),
    ]);
    if (rr.status === 'fulfilled') setRules(rr.value.data || []);
    if (mr.status === 'fulfilled') setMatches(mr.value.data || []);
    if (sr.status === 'fulfilled') {
      const found = (sr.value.data || []).find((t: ScheduledTaskLite) => t.task_type === 'scan_yara');
      setScheduledScan(found || null);
    }
    setLoading(false);
    setRefreshing(false);
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    agentsAPI.getAll().then(r => setAgents(r.data || [])).catch(() => {});
  }, []);

  const enablePeriodicScan = async () => {
    setScheduling(true);
    try {
      const r = await api.post('/scheduler/tasks', {
        name: 'Periodic YARA Scan',
        task_type: 'scan_yara',
        cron_expr: '0 */6 * * *',
        payload: {},
      });
      setScheduledScan(r.data);
      notify('Periodic scan enabled — runs every 6 hours against default targets');
    } catch { notify('Failed to schedule periodic scan'); }
    finally { setScheduling(false); }
  };

  const add = async () => {
    if (!form.name.trim() || !form.rule_content.trim()) return;
    setSaving(true);
    try { await yaraAPI.create(form); load(); setShowAdd(false); setForm({ ...emptyRule }); notify('YARA rule created'); }
    catch { notify('Failed to create rule'); }
    finally { setSaving(false); }
  };

  const update = async () => {
    if (!showEdit) return;
    setSaving(true);
    try { await yaraAPI.update(showEdit.id, form); load(); setShowEdit(null); notify('Rule updated'); }
    catch { notify('Failed to update rule'); }
    finally { setSaving(false); }
  };

  const del = async (id: number) => {
    try { await yaraAPI.delete(id); setRules(p => p.filter(r => r.id !== id)); notify('Rule deleted'); }
    catch { notify('Failed to delete rule'); }
  };

  const toggle = async (r: YaraRule) => {
    try {
      r.enabled ? await yaraAPI.disable(r.id) : await yaraAPI.enable(r.id);
      setRules(p => p.map(x => x.id === r.id ? { ...x, enabled: !x.enabled } : x));
    } catch { notify('Failed to toggle rule'); }
  };

  const openEdit = (r: YaraRule) => {
    setForm({ name: r.name, description: r.description, rule_content: r.rule_content, enabled: r.enabled });
    setShowEdit(r);
  };

  const filteredRules = rules.filter(r =>
    !search || r.name.toLowerCase().includes(search.toLowerCase()) || r.description.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <RootLayout title="YARA Rules" subtitle={`${rules.length} rules · ${rules.filter(r => r.enabled).length} active · ${matches.length} matches`}
      onRefresh={() => load(true)} refreshing={refreshing}
      actions={
        tab === 'rules' ? (
          <div className="flex items-center gap-2">
            <label className="g-btn g-btn-ghost text-xs cursor-pointer">
              <Upload className="h-3.5 w-3.5" /> Import .yar
              <input type="file" multiple accept=".yar,.yara" className="hidden"
                onChange={async e => {
                  const files = [...e.target.files!];
                  if (!files.length) return;
                  const form = new FormData();
                  files.forEach(f => form.append('rules', f));
                  try {
                    const r = await api.post('/yara/import', form, {
                      headers: { 'Content-Type': 'multipart/form-data' },
                    });
                    notify(r.data?.message || 'Imported');
                    load();
                  } catch { notify('Import failed'); }
                  e.target.value = '';
                }} />
            </label>
            <button onClick={() => { setForm({ ...emptyRule }); setShowAdd(true); }} className="g-btn g-btn-primary text-xs">
              <Plus className="h-3.5 w-3.5" /> New Rule
            </button>
          </div>
        ) : (
          scheduledScan ? (
            <a href="/scheduled-tasks" className="g-btn g-btn-ghost text-xs">
              <Clock className="h-3.5 w-3.5" style={{ color: scheduledScan.enabled ? 'var(--green)' : 'var(--text-3)' }} />
              Periodic scan {scheduledScan.enabled ? 'active' : 'paused'}
              {scheduledScan.last_run_at && <span style={{ color: 'var(--text-3)' }}>· last run {timeAgo(scheduledScan.last_run_at)}</span>}
            </a>
          ) : (
            <button onClick={enablePeriodicScan} disabled={scheduling} className="g-btn g-btn-ghost text-xs">
              <Clock className="h-3.5 w-3.5" /> {scheduling ? 'Enabling…' : 'Enable Periodic Scan'}
            </button>
          )
        )
      }>

      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)', minWidth: 200 }}>{toast}</div>}

      <div className="space-y-4">
        {/* Tab bar */}
        <div className="flex gap-1 p-1 rounded-xl w-fit" style={{ background: 'var(--glass-bg)', backdropFilter: 'var(--blur-sm)', border: '1px solid var(--border)' }}>
          {TABS.map(t => {
            const Icon = t.icon;
            return (
              <button key={t.id} onClick={() => setTab(t.id)}
                className="flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-medium transition-all"
                style={{
                  background: tab === t.id ? 'var(--accent-glow)' : 'transparent',
                  color:      tab === t.id ? 'var(--accent)' : 'var(--text-2)',
                  border:     tab === t.id ? '1px solid var(--accent-border)' : '1px solid transparent',
                }}>
                <Icon className="h-3.5 w-3.5" /> {t.label} {t.id === 'matches' ? `(${matches.length})` : `(${rules.length})`}
              </button>
            );
          })}
        </div>

        {/* RULES TAB */}
        {tab === 'rules' && (
          <>
            <div className="relative max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
              <input value={search} onChange={e => setSearch(e.target.value)}
                placeholder="Search rules…" className="g-input pl-9" />
            </div>

            {loading ? (
              <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
            ) : filteredRules.length === 0 ? (
              <div className="py-16 text-center">
                <Code2 className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
                <p className="text-sm" style={{ color: 'var(--text-2)' }}>No YARA rules. Create one to start scanning.</p>
              </div>
            ) : (
              <div className="grid gap-3 sm:grid-cols-2">
                {filteredRules.map(r => (
                  <div key={r.id} className={`g-card p-4 ${!r.enabled ? 'opacity-50' : ''}`}>
                    <div className="flex items-start justify-between mb-2">
                      <div className="min-w-0">
                        <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{r.name}</p>
                        <p className="text-xs mt-0.5" style={{ color: 'var(--text-3)' }}>{r.description || 'No description'}</p>
                      </div>
                      <div className="flex items-center gap-1 shrink-0">
                        <button onClick={() => toggle(r)} style={{ color: r.enabled ? 'var(--green)' : 'var(--text-3)' }}>
                          {r.enabled ? <ToggleRight className="h-4 w-4" /> : <ToggleLeft className="h-4 w-4" />}
                        </button>
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
                    <pre className="mono text-[10px] rounded-lg p-2.5 overflow-x-auto"
                      style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-2)', maxHeight: 120 }}>
{r.rule_content}
                    </pre>
                    <p className="text-[10px] mt-2" style={{ color: 'var(--text-3)' }}>Added {timeAgo(r.created_at)}</p>
                  </div>
                ))}
              </div>
            )}
          </>
        )}

        {/* MATCHES TAB */}
        {tab === 'matches' && (
          <div className="g-table">
            <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '90px 70px 1fr 1fr 100px 20px' }}>
              <span>Agent</span><span>Severity</span><span>Rule</span><span>File Path</span><span>Detected</span><span />
            </div>
            {loading ? (
              <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
            ) : matches.length === 0 ? (
              <div className="py-16 text-center">
                <FileWarning className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
                <p className="text-sm" style={{ color: 'var(--text-2)' }}>No YARA matches yet. Dispatch a &quot;YARA Scan&quot; task from an agent&apos;s page, or enable periodic scanning above.</p>
              </div>
            ) : matches.map(m => {
              let parsedStrings: MatchedString[] = [];
              try { parsedStrings = JSON.parse(m.matched_strings || '[]'); } catch { /* old rows, malformed JSON */ }
              const expanded = expandedId === m.id;
              return (
                <div key={m.id}>
                  <div className="g-tr grid gap-3 items-center px-4 cursor-pointer"
                    onClick={() => setExpandedId(expanded ? null : m.id)}
                    style={{ gridTemplateColumns: '90px 70px 1fr 1fr 100px 20px' }}>
                    <span className="text-xs mono" style={{ color: 'var(--accent)' }}>{agentName(m.agent_id)}</span>
                    <span className={sevClass(m.severity)}>{m.severity}</span>
                    <span className="mono text-xs font-medium" style={{ color: 'var(--accent)' }}>{m.rule_name}</span>
                    <span className="mono text-xs truncate" style={{ color: 'var(--text-1)' }}>{m.file_path}</span>
                    <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{timeAgo(m.created_at)}</span>
                    {expanded ? <ChevronUp className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} /> : <ChevronDown className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />}
                  </div>
                  {expanded && (
                    <div className="px-4 pb-3 pt-1 space-y-2" style={{ borderBottom: '1px solid var(--border)' }}>
                      <p className="text-xs" style={{ color: 'var(--text-2)' }}>{m.description}</p>
                      {m.file_hash && (
                        <p className="text-[11px] mono flex items-center gap-1.5" style={{ color: 'var(--text-3)' }}>
                          <Hash className="h-3 w-3" /> {m.file_hash}
                        </p>
                      )}
                      {parsedStrings.length > 0 && (
                        <div className="space-y-1">
                          <p className="text-[10px] font-bold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Matched Strings</p>
                          {parsedStrings.map((s, i) => (
                            <p key={i} className="text-[11px] mono" style={{ color: 'var(--text-2)' }}>
                              <span style={{ color: 'var(--accent)' }}>{s.identifier}</span> @ {s.offset}: <span style={{ color: 'var(--text-1)' }}>{s.data}</span>
                            </p>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Add/Edit modal */}
      {(showAdd || showEdit) && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && (setShowAdd(false), setShowEdit(null))}>
          <div className="g-modal" style={{ maxWidth: 620 }}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{showEdit ? 'Edit YARA Rule' : 'New YARA Rule'}</h2>
              <button onClick={() => { setShowAdd(false); setShowEdit(null); }} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>
            <div className="p-5 space-y-3">
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Name *</label>
                <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g. SuspiciousShell" className="g-input mono" />
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Description</label>
                <input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} placeholder="What this rule detects" className="g-input" />
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Rule Content (.yar syntax) *</label>
                <textarea value={form.rule_content} onChange={e => setForm(f => ({ ...f, rule_content: e.target.value }))}
                  rows={12} className="g-input mono resize-none" style={{ fontSize: 11, lineHeight: 1.6 }} />
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => setForm(f => ({ ...f, enabled: !f.enabled }))}>
                  {form.enabled ? <ToggleRight className="h-5 w-5" style={{ color: 'var(--green)' }} /> : <ToggleLeft className="h-5 w-5" style={{ color: 'var(--text-3)' }} />}
                </button>
                <span className="text-xs" style={{ color: 'var(--text-2)' }}>{form.enabled ? 'Enabled — agents will scan with this rule' : 'Disabled'}</span>
              </div>
            </div>
            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => { setShowAdd(false); setShowEdit(null); }} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={showEdit ? update : add} disabled={saving || !form.name.trim() || !form.rule_content.trim()} className="g-btn g-btn-primary flex-1 justify-center">
                {saving ? 'Saving…' : (showEdit ? 'Update' : 'Create')}
              </button>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
