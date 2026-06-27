'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { sigmaAPI } from '@/lib/api';
import { SigmaRule, SigmaRuleStat } from '@/types';
import { sevClass } from '@/lib/utils';
import {
  FileCode, Plus, Trash2, Edit2, X, TestTube,
  ToggleLeft, ToggleRight, Search, Info, Upload, BarChart2
} from 'lucide-react';

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const STATUSES   = ['stable', 'test', 'experimental', 'deprecated'];

interface SelectionForm { name: string; keywords: string; }

const emptyForm = {
  title:            '',
  description:      '',
  status:           'experimental',
  severity:         'high',
  mitre_tactic:     '',
  mitre_technique:  '',
  mitre_name:       '',
  logsource_cat:    '',
  logsource_prod:   '',
  logsource_svc:    '',
  tags:             '',
  selections: [{ name: 'selection1', keywords: '' }] as SelectionForm[],
  condition: 'selection1',
  enabled: true,
};

export default function SigmaRulesPage() {
  const [rules,      setRules]      = useState<SigmaRule[]>([]);
  const [stats,      setStats]      = useState<SigmaRuleStat[]>([]);
  const [loading,    setLoading]    = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search,     setSearch]     = useState('');
  const [showAdd,    setShowAdd]    = useState(false);
  const [showEdit,   setShowEdit]   = useState<SigmaRule | null>(null);
  const [form,       setForm]       = useState({ ...emptyForm, selections: [...emptyForm.selections] });
  const [saving,     setSaving]     = useState(false);
  const [toast,      setToast]      = useState<string | null>(null);
  const [importing,  setImporting]  = useState(false);
  const [importLog,  setImportLog]  = useState<string | null>(null);

  const [testMsg,  setTestMsg]  = useState('');
  const [testRes,  setTestRes]  = useState<any>(null);
  const [testing,  setTesting]  = useState(false);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3500); };

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const [rRes, sRes] = await Promise.all([sigmaAPI.getAll(), sigmaAPI.stats().catch(() => ({ data: [] }))]);
      setRules(rRes.data || []);
      setStats(sRes.data || []);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // ── hit-count map for the table ──────────────────────────────────────────
  const hitMap = Object.fromEntries(stats.map(s => [s.rule_id, s]));

  // ── form helpers ─────────────────────────────────────────────────────────
  const buildPayload = () => {
    const selections: Record<string, string[]> = {};
    form.selections.forEach(s => {
      const name = s.name.trim();
      if (!name) return;
      selections[name] = s.keywords.split(',').map(k => k.trim()).filter(Boolean);
    });
    return {
      title:           form.title,
      description:     form.description,
      status:          form.status,
      severity:        form.severity,
      mitre_tactic:    form.mitre_tactic,
      mitre_technique: form.mitre_technique,
      mitre_name:      form.mitre_name,
      logsource_cat:   form.logsource_cat,
      logsource_prod:  form.logsource_prod,
      logsource_svc:   form.logsource_svc,
      tags:            form.tags.split(',').map(t => t.trim()).filter(Boolean),
      keywords:        Object.values(selections).flat(),
      selections,
      condition:       form.condition.trim() || Object.keys(selections).join(' or '),
      enabled:         form.enabled,
    };
  };

  const resetForm = () => setForm({ ...emptyForm, selections: [{ name: 'selection1', keywords: '' }] });

  const openEdit = (r: SigmaRule) => {
    const selections = r.selections && Object.keys(r.selections).length > 0
      ? Object.entries(r.selections).map(([name, kws]) => ({ name, keywords: (kws || []).join(', ') }))
      : [{ name: 'selection1', keywords: (r.keywords || []).join(', ') }];
    setForm({
      title:           r.title,
      description:     r.description || '',
      status:          r.status || 'experimental',
      severity:        r.severity,
      mitre_tactic:    r.mitre_tactic || '',
      mitre_technique: r.mitre_technique || '',
      mitre_name:      r.mitre_name || '',
      logsource_cat:   r.logsource_cat || '',
      logsource_prod:  r.logsource_prod || '',
      logsource_svc:   r.logsource_svc || '',
      tags:            (r.tags || []).join(', '),
      selections,
      condition:       r.condition || selections.map(s => s.name).join(' or '),
      enabled:         r.enabled,
    });
    setShowEdit(r);
  };

  // ── CRUD ─────────────────────────────────────────────────────────────────
  const add = async () => {
    setSaving(true);
    try { await sigmaAPI.create(buildPayload()); load(); setShowAdd(false); resetForm(); notify('Rule created'); }
    catch { notify('Failed to create rule'); }
    finally { setSaving(false); }
  };

  const update = async () => {
    if (!showEdit) return;
    setSaving(true);
    try { await sigmaAPI.update(showEdit.id, buildPayload()); load(); setShowEdit(null); notify('Rule updated'); }
    catch { notify('Failed to update rule'); }
    finally { setSaving(false); }
  };

  const del    = async (id: number) => { await sigmaAPI.delete(id); setRules(p => p.filter(r => r.id !== id)); notify('Rule deleted'); };
  const toggle = async (r: SigmaRule) => {
    r.enabled ? await sigmaAPI.disable(r.id) : await sigmaAPI.enable(r.id);
    setRules(p => p.map(x => x.id === r.id ? { ...x, enabled: !x.enabled } : x));
  };

  // ── YAML import ──────────────────────────────────────────────────────────
  const handleImport = async (files: FileList) => {
    if (!files.length) return;
    setImporting(true);
    setImportLog(null);
    const fd = new FormData();
    Array.from(files).forEach(f => fd.append('rules', f));
    try {
      const res = await sigmaAPI.import(fd);
      const { imported, skipped, errors: errs } = res.data;
      let msg = `Imported ${imported}`;
      if (skipped) msg += `, skipped ${skipped}`;
      if (errs?.length) msg += `\n${errs.slice(0, 5).join('\n')}`;
      setImportLog(msg);
      load();
    } catch {
      setImportLog('Import failed');
    } finally {
      setImporting(false);
    }
  };

  // ── test panel ───────────────────────────────────────────────────────────
  const runTest = async () => {
    if (!testMsg.trim()) return;
    setTesting(true);
    try { const r = await sigmaAPI.test({ message: testMsg }); setTestRes(r.data); }
    finally { setTesting(false); }
  };

  // ── filtering ─────────────────────────────────────────────────────────────
  const filtered = rules.filter(r => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      r.title?.toLowerCase().includes(q) ||
      r.description?.toLowerCase().includes(q) ||
      r.mitre_technique?.toLowerCase().includes(q) ||
      r.mitre_tactic?.toLowerCase().includes(q) ||
      (r.tags || []).some(t => t.toLowerCase().includes(q)) ||
      r.logsource_prod?.toLowerCase().includes(q) ||
      (r.keywords || []).some(k => k.toLowerCase().includes(q))
    );
  });

  const describeRule = (r: SigmaRule) =>
    r.condition || (r.selections && Object.keys(r.selections).length
      ? Object.keys(r.selections).join(' or ')
      : 'any keyword');

  const statusBadge = (status: string) => {
    const color =
      status === 'stable'       ? 'var(--green)'  :
      status === 'test'         ? 'var(--yellow)'  :
      status === 'deprecated'   ? 'var(--red)'    :
      'var(--text-3)'; // experimental
    return <span className="text-[10px] font-mono" style={{ color }}>{status || 'exp'}</span>;
  };

  const addSelection = () => {
    setForm(f => ({ ...f, selections: [...f.selections, { name: `selection${f.selections.length + 1}`, keywords: '' }] }));
  };
  const removeSelection = (idx: number) => setForm(f => ({ ...f, selections: f.selections.filter((_, i) => i !== idx) }));
  const updateSelection = (idx: number, field: 'name' | 'keywords', val: string) =>
    setForm(f => ({ ...f, selections: f.selections.map((s, i) => i === idx ? { ...s, [field]: val } : s) }));

  // ── top stats strip ──────────────────────────────────────────────────────
  const topHitters = stats.filter(s => s.hit_count > 0).slice(0, 5);

  return (
    <RootLayout
      title="Sigma Rules"
      subtitle={`${rules.length} rules · ${rules.filter(r => r.enabled).length} active`}
      onRefresh={() => load(true)} refreshing={refreshing}
      actions={
        <div className="flex items-center gap-2">
          <label className={`g-btn g-btn-ghost text-xs cursor-pointer ${importing ? 'opacity-50 pointer-events-none' : ''}`}>
            <Upload className="h-3.5 w-3.5" />
            {importing ? 'Importing…' : 'Import YAML'}
            <input type="file" multiple accept=".yml,.yaml" className="hidden"
              onChange={e => { handleImport(e.target.files!); e.target.value = ''; }} />
          </label>
          <button onClick={() => { resetForm(); setShowAdd(true); }} className="g-btn g-btn-primary text-xs">
            <Plus className="h-3.5 w-3.5" /> New Rule
          </button>
        </div>
      }>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm"
          style={{ color: 'var(--text-1)', minWidth: 200 }}>{toast}</div>
      )}

      {importLog && (
        <div className="g-panel px-4 py-3 text-xs mb-3 whitespace-pre-wrap"
          style={{ color: 'var(--text-2)', borderColor: 'var(--border)' }}>
          <div className="flex justify-between items-start gap-3">
            <span>{importLog}</span>
            <button onClick={() => setImportLog(null)} style={{ color: 'var(--text-3)' }}><X className="h-3.5 w-3.5" /></button>
          </div>
        </div>
      )}

      <div className="space-y-4">

        {/* Top-hitting rules strip */}
        {topHitters.length > 0 && (
          <div className="g-card p-4">
            <div className="flex items-center gap-2 mb-3">
              <BarChart2 className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
              <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Top Firing Rules</p>
            </div>
            <div className="flex flex-wrap gap-2">
              {topHitters.map(s => (
                <div key={s.rule_id} className="flex items-center gap-2 rounded-lg px-3 py-1.5"
                  style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                  <span className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{s.title}</span>
                  <span className="text-[10px] font-mono rounded px-1.5 py-0.5"
                    style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>{s.hit_count} hits</span>
                  {s.last_matched_at && (
                    <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                      {new Date(s.last_matched_at).toLocaleDateString()}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Test panel */}
        <div className="g-card p-4">
          <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Test Rules Against Log</p>
          <div className="flex gap-3">
            <input value={testMsg} onChange={e => setTestMsg(e.target.value)}
              placeholder="Paste a log line to test against all rules…" className="g-input flex-1" />
            <button onClick={runTest} disabled={testing || !testMsg.trim()} className="g-btn g-btn-primary text-xs shrink-0">
              <TestTube className="h-3.5 w-3.5" /> {testing ? 'Testing…' : 'Test'}
            </button>
          </div>
          {testRes && (
            <div className="mt-3 rounded-xl p-3" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
              {(Array.isArray(testRes) ? testRes : [testRes]).map((r: any, i: number) => (
                <div key={i} className="flex items-center gap-3 py-1.5"
                  style={{ borderBottom: i < (Array.isArray(testRes) ? testRes.length : 1) - 1 ? '1px solid var(--border)' : 'none' }}>
                  <span className={r.matched ? 's-critical' : 's-online'}>{r.matched ? 'MATCH' : 'NO MATCH'}</span>
                  <span className="text-xs" style={{ color: 'var(--text-1)' }}>{r.rule_name}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Search */}
        <div className="relative max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search title, description, MITRE, tags, product…" className="g-input pl-9" />
        </div>

        {/* Rules table */}
        <div className="g-table">
          <div className="g-thead grid gap-3 px-4"
            style={{ gridTemplateColumns: '1fr 90px 90px 90px 70px 56px 60px' }}>
            <span>Title / Description</span>
            <span>Logsource</span>
            <span>MITRE</span>
            <span>Severity</span>
            <span>Status</span>
            <span>Hits</span>
            <span className="text-right">Actions</span>
          </div>

          {loading ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          ) : filtered.length === 0 ? (
            <div className="py-16 text-center">
              <FileCode className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>No Sigma rules. Import a .yml pack or create one.</p>
            </div>
          ) : filtered.map(r => {
            const hit = hitMap[r.id];
            const logsrc = [r.logsource_prod, r.logsource_cat, r.logsource_svc].filter(Boolean).join('/') || '—';
            return (
              <div key={r.id}
                className={`g-tr grid gap-3 items-center px-4 ${!r.enabled ? 'opacity-40' : ''}`}
                style={{ gridTemplateColumns: '1fr 90px 90px 90px 70px 56px 60px' }}>

                {/* Title + description */}
                <div>
                  <div className="flex items-center gap-1.5">
                    <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{r.title}</p>
                    <button onClick={() => toggle(r)} title={r.enabled ? 'Disable' : 'Enable'}>
                      {r.enabled
                        ? <ToggleRight className="h-4 w-4 shrink-0" style={{ color: 'var(--green)' }} />
                        : <ToggleLeft  className="h-4 w-4 shrink-0" style={{ color: 'var(--text-3)' }} />}
                    </button>
                  </div>
                  {r.description
                    ? <p className="text-[10px] mt-0.5 truncate" style={{ color: 'var(--text-3)' }}>{r.description}</p>
                    : <p className="text-[10px] mt-0.5 font-mono truncate" style={{ color: 'var(--text-3)' }}>{describeRule(r)}</p>}
                  {(r.tags || []).length > 0 && (
                    <div className="flex gap-1 flex-wrap mt-0.5">
                      {(r.tags || []).slice(0, 3).map(t => (
                        <span key={t} className="text-[9px] font-mono rounded px-1 py-px"
                          style={{ background: 'var(--bg-0)', color: 'var(--text-3)', border: '1px solid var(--border)' }}>
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {/* Logsource */}
                <span className="text-[10px] mono truncate" style={{ color: 'var(--text-3)' }}>{logsrc}</span>

                {/* MITRE */}
                <span className="mono text-[10px] rounded px-1.5 py-0.5 inline-block w-fit"
                  style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                  {r.mitre_technique || '—'}
                </span>

                {/* Severity */}
                <span className={sevClass(r.severity)}>{r.severity}</span>

                {/* Status */}
                {statusBadge(r.status)}

                {/* Hits */}
                <span className="text-[11px] font-mono" style={{ color: hit?.hit_count ? 'var(--accent)' : 'var(--text-3)' }}>
                  {hit?.hit_count ?? 0}
                </span>

                {/* Actions */}
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

      {/* Create / Edit modal */}
      {(showAdd || showEdit) && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && (setShowAdd(false), setShowEdit(null))}>
          <div className="g-modal" style={{ maxWidth: 640 }}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
                {showEdit ? 'Edit Sigma Rule' : 'New Sigma Rule'}
              </h2>
              <button onClick={() => { setShowAdd(false); setShowEdit(null); }} style={{ color: 'var(--text-2)' }}>
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="p-5 space-y-3 max-h-[72vh] overflow-y-auto">

              {/* Title */}
              <div><label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Title *</label>
                <input value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
                  placeholder="SSH Brute Force" className="g-input" /></div>

              {/* Description */}
              <div><label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Description</label>
                <input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  placeholder="Detects repeated SSH login failures…" className="g-input" /></div>

              {/* Status + Severity */}
              <div className="grid grid-cols-2 gap-3">
                <div><label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Status</label>
                  <select value={form.status} onChange={e => setForm(f => ({ ...f, status: e.target.value }))} className="g-select">
                    {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
                  </select></div>
                <div><label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Severity</label>
                  <select value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))} className="g-select">
                    {SEVERITIES.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
                  </select></div>
              </div>

              {/* Logsource */}
              <div className="pt-2" style={{ borderTop: '1px solid var(--border)' }}>
                <label className="block text-xs font-semibold uppercase tracking-wider mb-2 mt-1" style={{ color: 'var(--text-3)' }}>Logsource</label>
                <div className="grid grid-cols-3 gap-2">
                  <div><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Product</label>
                    <input value={form.logsource_prod} onChange={e => setForm(f => ({ ...f, logsource_prod: e.target.value }))}
                      placeholder="windows" className="g-input mono text-xs" /></div>
                  <div><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Category</label>
                    <input value={form.logsource_cat} onChange={e => setForm(f => ({ ...f, logsource_cat: e.target.value }))}
                      placeholder="process_creation" className="g-input mono text-xs" /></div>
                  <div><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Service</label>
                    <input value={form.logsource_svc} onChange={e => setForm(f => ({ ...f, logsource_svc: e.target.value }))}
                      placeholder="sshd" className="g-input mono text-xs" /></div>
                </div>
              </div>

              {/* MITRE */}
              <div className="pt-2" style={{ borderTop: '1px solid var(--border)' }}>
                <label className="block text-xs font-semibold uppercase tracking-wider mb-2 mt-1" style={{ color: 'var(--text-3)' }}>MITRE ATT&CK</label>
                <div className="grid grid-cols-3 gap-2">
                  <div><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Tactic</label>
                    <input value={form.mitre_tactic} onChange={e => setForm(f => ({ ...f, mitre_tactic: e.target.value }))}
                      placeholder="Execution" className="g-input" /></div>
                  <div><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Technique ID</label>
                    <input value={form.mitre_technique} onChange={e => setForm(f => ({ ...f, mitre_technique: e.target.value }))}
                      placeholder="T1059" className="g-input mono" /></div>
                  <div><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Name</label>
                    <input value={form.mitre_name} onChange={e => setForm(f => ({ ...f, mitre_name: e.target.value }))}
                      placeholder="Command and Scripting" className="g-input" /></div>
                </div>
              </div>

              {/* Tags */}
              <div><label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Tags (comma-separated)</label>
                <input value={form.tags} onChange={e => setForm(f => ({ ...f, tags: e.target.value }))}
                  placeholder="attack.t1059.001, attack.execution" className="g-input mono text-xs" /></div>

              {/* Selections */}
              <div className="pt-2" style={{ borderTop: '1px solid var(--border)' }}>
                <div className="flex items-center justify-between mb-2 mt-1">
                  <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Selections</label>
                  <button onClick={addSelection} className="g-btn g-btn-ghost text-[10px]" style={{ padding: '3px 8px' }}>
                    <Plus className="h-3 w-3" /> Add Selection
                  </button>
                </div>
                <div className="space-y-2">
                  {form.selections.map((sel, idx) => (
                    <div key={idx} className="flex gap-2 items-start">
                      <input value={sel.name} onChange={e => updateSelection(idx, 'name', e.target.value)}
                        placeholder="selection1" className="g-input mono" style={{ width: 110, flexShrink: 0 }} />
                      <input value={sel.keywords} onChange={e => updateSelection(idx, 'keywords', e.target.value)}
                        placeholder="field|contains:value, other|re:^pattern" className="g-input flex-1 mono text-xs" />
                      {form.selections.length > 1 && (
                        <button onClick={() => removeSelection(idx)} className="p-2 rounded shrink-0" style={{ color: 'var(--text-3)' }}
                          onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--red)'}
                          onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
                <div className="flex items-start gap-1.5 mt-2">
                  <Info className="h-3 w-3 mt-0.5 shrink-0" style={{ color: 'var(--text-3)' }} />
                  <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                    Comma-separate keywords or field matchers.
                    Syntax: <span className="mono">CommandLine|contains:powershell</span> ·{' '}
                    <span className="mono">Image|endswith:.exe</span> ·{' '}
                    <span className="mono">Image|re:^C:\\Windows</span> ·{' '}
                    <span className="mono">dst_ip|cidr:10.0.0.0/8</span> ·{' '}
                    Modifiers: <span className="mono">contains startswith endswith re cidr base64 windash utf16le</span>
                  </p>
                </div>
              </div>

              {/* Condition */}
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Condition</label>
                <input value={form.condition} onChange={e => setForm(f => ({ ...f, condition: e.target.value }))}
                  placeholder="selection1 and not selection2" className="g-input mono" />
                <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                  Ops: <span className="mono">and · or · not · ( )</span> · Quantifiers:{' '}
                  <span className="mono">1 of selection*</span> · <span className="mono">all of them</span>
                </p>
              </div>

              {/* Enabled toggle */}
              <div className="flex items-center gap-2">
                <button onClick={() => setForm(f => ({ ...f, enabled: !f.enabled }))}>
                  {form.enabled
                    ? <ToggleRight className="h-5 w-5" style={{ color: 'var(--green)' }} />
                    : <ToggleLeft  className="h-5 w-5" style={{ color: 'var(--text-3)' }} />}
                </button>
                <span className="text-xs" style={{ color: 'var(--text-2)' }}>{form.enabled ? 'Enabled' : 'Disabled'}</span>
              </div>
            </div>

            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => { setShowAdd(false); setShowEdit(null); }} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={showEdit ? update : add} disabled={saving || !form.title.trim()} className="g-btn g-btn-primary flex-1 justify-center">
                {saving ? 'Saving…' : (showEdit ? 'Update' : 'Create Rule')}
              </button>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
