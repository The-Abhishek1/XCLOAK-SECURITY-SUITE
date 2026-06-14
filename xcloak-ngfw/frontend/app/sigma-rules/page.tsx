'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { sigmaAPI } from '@/lib/api';
import { SigmaRule } from '@/types';
import { sevClass } from '@/lib/utils';
import { FileCode, Plus, Trash2, Edit2, X, TestTube, ToggleLeft, ToggleRight, Search, Info, Upload } from 'lucide-react';
import { SigmaImportButton } from '@/components/SigmaImportButton';

const SEVERITIES = ['critical','high','medium','low'];

interface SelectionForm {
  name: string;
  keywords: string;
}

const emptyForm = {
  title: '',
  severity: 'high',
  mitre_tactic: '',
  mitre_technique: '',
  mitre_name: '',
  selections: [{ name: 'selection1', keywords: '' }] as SelectionForm[],
  condition: 'selection1',
  enabled: true,
};

export default function SigmaRulesPage() {
  const [rules, setRules]     = useState<SigmaRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch]   = useState('');
  const [showAdd, setShowAdd] = useState(false);
  const [showEdit, setShowEdit] = useState<SigmaRule | null>(null);
  const [form, setForm]       = useState({ ...emptyForm, selections: [...emptyForm.selections] });
  const [saving, setSaving]   = useState(false);
  const [toast, setToast]     = useState<string | null>(null);

  const [testMsg, setTestMsg] = useState('');
  const [testRes, setTestRes] = useState<any>(null);
  const [testing, setTesting] = useState(false);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try { const r = await sigmaAPI.getAll(); setRules(r.data || []); }
    finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const buildPayload = () => {
    const selections: Record<string, string[]> = {};
    form.selections.forEach(s => {
      const name = s.name.trim();
      if (!name) return;
      selections[name] = s.keywords.split(',').map(k => k.trim()).filter(Boolean);
    });
    const allKeywords = Object.values(selections).flat();
    return {
      title: form.title,
      severity: form.severity,
      mitre_tactic: form.mitre_tactic,
      mitre_technique: form.mitre_technique,
      mitre_name: form.mitre_name,
      keywords: allKeywords,
      selections,
      condition: form.condition.trim() || Object.keys(selections).join(' or '),
      enabled: form.enabled,
    };
  };

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
  const toggle = async (r: SigmaRule) => { r.enabled ? await sigmaAPI.disable(r.id) : await sigmaAPI.enable(r.id); setRules(p => p.map(x => x.id === r.id ? { ...x, enabled: !x.enabled } : x)); };

  const resetForm = () => setForm({ ...emptyForm, selections: [{ name: 'selection1', keywords: '' }] });

  const openEdit = (r: SigmaRule) => {
    const selections = r.selections && Object.keys(r.selections).length > 0
      ? Object.entries(r.selections).map(([name, kws]) => ({ name, keywords: (kws || []).join(', ') }))
      : [{ name: 'selection1', keywords: (r.keywords || []).join(', ') }];

    setForm({
      title: r.title,
      severity: r.severity,
      mitre_tactic: r.mitre_tactic,
      mitre_technique: r.mitre_technique,
      mitre_name: r.mitre_name,
      selections,
      condition: r.condition || selections.map(s => s.name).join(' or '),
      enabled: r.enabled,
    });
    setShowEdit(r);
  };

  const addSelection = () => {
    setForm(f => {
      const nextNum = f.selections.length + 1;
      return { ...f, selections: [...f.selections, { name: `selection${nextNum}`, keywords: '' }] };
    });
  };

  const removeSelection = (idx: number) => {
    setForm(f => ({ ...f, selections: f.selections.filter((_, i) => i !== idx) }));
  };

  const updateSelection = (idx: number, field: 'name' | 'keywords', val: string) => {
    setForm(f => ({ ...f, selections: f.selections.map((s, i) => i === idx ? { ...s, [field]: val } : s) }));
  };

  const runTest = async () => {
    if (!testMsg.trim()) return;
    setTesting(true);
    try { const r = await sigmaAPI.test({ message: testMsg }); setTestRes(r.data); }
    finally { setTesting(false); }
  };

  const filtered = rules.filter(r =>
    !search || r.title?.toLowerCase().includes(search.toLowerCase())
      || r.mitre_technique?.toLowerCase().includes(search.toLowerCase())
      || (r.keywords || []).some(k => k.toLowerCase().includes(search.toLowerCase()))
  );

  const describeRule = (r: SigmaRule) => {
    if (r.selections && Object.keys(r.selections).length > 0) {
      return r.condition || Object.keys(r.selections).join(' or ');
    }
    return 'any keyword';
  };

  return (
    <RootLayout title="Sigma Rules" subtitle={`${rules.length} rules · ${rules.filter(r => r.enabled).length} active`}
      onRefresh={() => load(true)} refreshing={refreshing}
      actions={
        <div className="flex items-center gap-2">
          <label className="g-btn g-btn-ghost text-xs cursor-pointer">
            <Upload className="h-3.5 w-3.5" />
            Import YAML
            <input type="file" multiple accept=".yml,.yaml" className="hidden"
              onChange={async e => {
                const files = [...e.target.files!];
                if (!files.length) return;
                const form = new FormData();
                files.forEach(f => form.append('rules', f));
                try {
                  const axios = (await import('@/lib/api')).default;
                  await axios.post('/sigma/import', form, { headers: { 'Content-Type': 'multipart/form-data' } });
                  load();
                } catch {}
                e.target.value = '';
              }} />
          </label>
          <button onClick={() => { resetForm(); setShowAdd(true); }} className="g-btn g-btn-primary text-xs">
            <Plus className="h-3.5 w-3.5" /> New Rule
          </button>
        </div>
      }>

      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)', minWidth: 200 }}>{toast}</div>}

      <div className="space-y-4">
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
                <div key={i} className="flex items-center gap-3 py-1.5" style={{ borderBottom: i < testRes.length - 1 ? '1px solid var(--border)' : 'none' }}>
                  <span className={r.matched ? 's-critical' : 's-online'}>{r.matched ? 'MATCH' : 'NO MATCH'}</span>
                  <span className="text-xs" style={{ color: 'var(--text-1)' }}>{r.rule_name}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="relative max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search title, MITRE technique, keyword…" className="g-input pl-9" />
        </div>

        <div className="g-table">
          <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 100px 80px 1fr 80px 60px' }}>
            <span>Title</span><span>MITRE</span><span>Severity</span><span>Condition</span><span>Status</span><span className="text-right">Actions</span>
          </div>

          {loading ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          ) : filtered.length === 0 ? (
            <div className="py-16 text-center">
              <FileCode className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>No Sigma rules. Create one.</p>
            </div>
          ) : filtered.map(r => (
            <div key={r.id} className={`g-tr grid gap-3 items-center px-4 ${!r.enabled ? 'opacity-40' : ''}`}
              style={{ gridTemplateColumns: '1fr 100px 80px 1fr 80px 60px' }}>
              <div>
                <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{r.title}</p>
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{r.mitre_tactic} · {r.mitre_name}</p>
              </div>
              <span className="mono text-[10px] rounded px-1.5 py-0.5 inline-block w-fit"
                style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                {r.mitre_technique || '—'}
              </span>
              <span className={sevClass(r.severity)}>{r.severity}</span>
              <span className="mono text-[11px] truncate" style={{ color: 'var(--text-2)' }}>{describeRule(r)}</span>
              <button onClick={() => toggle(r)} className="flex items-center gap-1 text-[10px]"
                style={{ color: r.enabled ? 'var(--green)' : 'var(--text-3)' }}>
                {r.enabled ? <ToggleRight className="h-4 w-4" /> : <ToggleLeft className="h-4 w-4" />}
                {r.enabled ? 'On' : 'Off'}
              </button>
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

      {(showAdd || showEdit) && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && (setShowAdd(false), setShowEdit(null))}>
          <div className="g-modal" style={{ maxWidth: 620 }}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{showEdit ? 'Edit Sigma Rule' : 'New Sigma Rule'}</h2>
              <button onClick={() => { setShowAdd(false); setShowEdit(null); }} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>
            <div className="p-5 space-y-3 max-h-[70vh] overflow-y-auto">
              <div><label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Title *</label>
                <input value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))} placeholder="SSH Login" className="g-input" /></div>

              <div><label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Severity</label>
                <select value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))} className="g-select">
                  {SEVERITIES.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}</select></div>

              <div className="grid grid-cols-2 gap-3">
                <div><label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>MITRE Tactic</label>
                  <input value={form.mitre_tactic} onChange={e => setForm(f => ({ ...f, mitre_tactic: e.target.value }))} placeholder="Initial Access" className="g-input" /></div>
                <div><label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>MITRE Technique</label>
                  <input value={form.mitre_technique} onChange={e => setForm(f => ({ ...f, mitre_technique: e.target.value }))} placeholder="T1078" className="g-input" /></div>
              </div>
              <div><label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>MITRE Name</label>
                <input value={form.mitre_name} onChange={e => setForm(f => ({ ...f, mitre_name: e.target.value }))} placeholder="Valid Accounts" className="g-input" /></div>

              <div className="pt-2" style={{ borderTop: '1px solid var(--border)' }}>
                <div className="flex items-center justify-between mb-2 mt-2">
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
                        placeholder="keyword one, keyword two, ..." className="g-input flex-1" />
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
                <p className="text-[10px] mt-1.5" style={{ color: 'var(--text-3)' }}>
                  Each selection matches if ANY of its comma-separated keywords appear in the log message.
                </p>
              </div>

              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Condition</label>
                <input value={form.condition} onChange={e => setForm(f => ({ ...f, condition: e.target.value }))}
                  placeholder="selection1 and selection2" className="g-input mono" />
                <div className="flex items-start gap-1.5 mt-1.5">
                  <Info className="h-3 w-3 mt-0.5 shrink-0" style={{ color: 'var(--text-3)' }} />
                  <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                    Combine selection names with <span className="mono">and</span> / <span className="mono">or</span> / <span className="mono">not</span> and parentheses.
                    Examples: <span className="mono">selection1 and selection2</span> · <span className="mono">selection1 and not selection2</span> · <span className="mono">(selection1 or selection2) and selection3</span>.
                    Leave blank for "any selection matches" (OR of all).
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button onClick={() => setForm(f => ({ ...f, enabled: !f.enabled }))}>
                  {form.enabled ? <ToggleRight className="h-5 w-5" style={{ color: 'var(--green)' }} /> : <ToggleLeft className="h-5 w-5" style={{ color: 'var(--text-3)' }} />}
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
