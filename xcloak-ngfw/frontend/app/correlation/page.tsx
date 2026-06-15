'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { correlationAPI } from '@/lib/api';
import { sevClass, timeAgo } from '@/lib/utils';
import { GitMerge, Plus, Trash2, ToggleLeft, ToggleRight, X, Info } from 'lucide-react';

const ACTIONS   = ['create_incident', 'notify'];
const SEVERITIES = ['', 'critical', 'high', 'medium', 'low'];

interface Rule {
  id: number;
  name: string;
  description: string;
  severity: string;
  rule_name: string;
  mitre_technique: string;
  agent_id: number;
  action: string;
  enabled: boolean;
  match_count: number;
  created_by: string;
  created_at: string;
}

const empty = {
  name: '', description: '', severity: '', rule_name: '',
  mitre_technique: '', agent_id: 0, action: 'create_incident',
};

export default function CorrelationPage() {
  const [rules, setRules]     = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [showNew, setShowNew] = useState(false);
  const [form, setForm]       = useState({ ...empty });
  const [saving, setSaving]   = useState(false);
  const [toast, setToast]     = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try { const r = await correlationAPI.getAll(); setRules(r.data || []); }
    finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const create = async () => {
    if (!form.name || !form.action) return;
    setSaving(true);
    try {
      await correlationAPI.create(form);
      load(); setShowNew(false); setForm({ ...empty });
      notify('Rule created');
    } catch { notify('Failed to create rule'); }
    finally { setSaving(false); }
  };

  const toggle = async (id: number, enabled: boolean) => {
    await correlationAPI.toggle(id, !enabled);
    setRules(r => r.map(x => x.id === id ? { ...x, enabled: !enabled } : x));
  };

  const del = async (id: number) => {
    await correlationAPI.delete(id);
    setRules(r => r.filter(x => x.id !== id));
    notify('Rule deleted');
  };

  return (
    <RootLayout title="Correlation Rules" subtitle="Custom alert-to-incident correlation logic"
      onRefresh={() => load(true)} refreshing={refreshing}
      actions={
        <button onClick={() => setShowNew(true)} className="g-btn g-btn-primary text-xs">
          <Plus className="h-3.5 w-3.5" /> New Rule
        </button>
      }>

      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)' }}>{toast}</div>}

      {/* Info banner */}
      <div className="g-card p-4 flex items-start gap-3 mb-5"
        style={{ border: '1px solid var(--accent-border)', background: 'var(--accent-glow)' }}>
        <Info className="h-4 w-4 shrink-0 mt-0.5" style={{ color: 'var(--accent)' }} />
        <p className="text-xs leading-relaxed" style={{ color: 'var(--text-2)' }}>
          Correlation rules define when alerts automatically create incidents. The built-in rules
          fire on critical/high alerts and IOC/YARA matches. Add custom rules here to trigger
          incidents on specific MITRE techniques, rule names, or agent/severity combinations.
          All conditions in a rule must match for it to fire.
        </p>
      </div>

      <div className="space-y-3">
        {/* Built-in rules (read-only display) */}
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>
            Built-in Rules (always active)
          </p>
          {[
            { name: 'Critical Alert → Incident', condition: 'severity = critical', action: 'create_incident' },
            { name: 'High Alert → Incident',     condition: 'severity = high',     action: 'create_incident' },
            { name: 'IOC Match → Incident',      condition: 'rule_name contains "IOC"', action: 'create_incident' },
            { name: 'YARA Match → Incident',     condition: 'rule_name contains "YARA"', action: 'create_incident' },
          ].map(r => (
            <div key={r.name} className="g-card flex items-center gap-4 px-4 py-3 mb-2 opacity-70">
              <ToggleRight className="h-5 w-5 shrink-0" style={{ color: 'var(--green)' }} />
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{r.name}</p>
                <p className="text-[10px] mono mt-0.5" style={{ color: 'var(--text-3)' }}>
                  IF {r.condition} → {r.action}
                </p>
              </div>
              <span className="text-[10px] px-2 py-0.5 rounded"
                style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-3)' }}>
                built-in
              </span>
            </div>
          ))}
        </div>

        {/* Custom rules */}
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>
            Custom Rules ({rules.length})
          </p>

          {loading ? (
            <div className="py-8 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          ) : rules.length === 0 ? (
            <div className="g-card py-12 text-center">
              <GitMerge className="mx-auto h-8 w-8 mb-3" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>No custom rules yet.</p>
              <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>
                Create rules to correlate specific MITRE techniques or rule patterns into incidents.
              </p>
            </div>
          ) : rules.map(r => (
            <div key={r.id} className="g-card flex items-start gap-4 px-4 py-3 mb-2">
              <button onClick={() => toggle(r.id, r.enabled)} className="mt-0.5 shrink-0">
                {r.enabled
                  ? <ToggleRight className="h-5 w-5" style={{ color: 'var(--accent)' }} />
                  : <ToggleLeft  className="h-5 w-5" style={{ color: 'var(--text-3)' }} />}
              </button>

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{r.name}</p>
                  {!r.enabled && (
                    <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>disabled</span>
                  )}
                </div>
                {r.description && (
                  <p className="text-[11px] mb-1" style={{ color: 'var(--text-3)' }}>{r.description}</p>
                )}
                <div className="mono text-[10px] space-y-0.5" style={{ color: 'var(--text-3)' }}>
                  <p>
                    IF
                    {r.severity        && <span style={{ color: 'var(--orange)' }}> severity={r.severity}</span>}
                    {r.rule_name       && <span style={{ color: 'var(--accent)' }}> rule_name≈"{r.rule_name}"</span>}
                    {r.mitre_technique && <span style={{ color: 'var(--yellow)' }}> mitre={r.mitre_technique}</span>}
                    {r.agent_id > 0    && <span style={{ color: 'var(--blue)' }}> agent=#{r.agent_id}</span>}
                    {(!r.severity && !r.rule_name && !r.mitre_technique && !r.agent_id) && <span> (any alert)</span>}
                    {' → '}
                    <span style={{ color: 'var(--green)' }}>{r.action}</span>
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-3 shrink-0 text-[10px]" style={{ color: 'var(--text-3)' }}>
                <span>{r.match_count} matches</span>
                <span>{timeAgo(r.created_at)}</span>
                <button onClick={() => del(r.id)}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--red)'}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* New rule modal */}
      {showNew && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setShowNew(false)}>
          <div className="g-modal" style={{ maxWidth: 520 }}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>New Correlation Rule</h2>
              <button onClick={() => setShowNew(false)} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>

            <div className="p-5 space-y-4">
              <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                All non-empty conditions must match for the rule to fire.
                Leave a field blank to match any value.
              </p>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Rule Name *</label>
                  <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                    placeholder="e.g. T1078 Lateral Movement" className="g-input w-full" />
                </div>
                <div>
                  <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Action *</label>
                  <select value={form.action} onChange={e => setForm(f => ({ ...f, action: e.target.value }))}
                    className="g-select w-full">
                    {ACTIONS.map(a => <option key={a} value={a}>{a}</option>)}
                  </select>
                </div>
              </div>

              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Description</label>
                <input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  placeholder="What does this rule detect?" className="g-input w-full" />
              </div>

              <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
                Conditions (leave blank to match any)
              </p>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Severity</label>
                  <select value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}
                    className="g-select w-full">
                    <option value="">Any</option>
                    {SEVERITIES.filter(Boolean).map(s => <option key={s} value={s} className="capitalize">{s}</option>)}
                  </select>
                </div>
                <div>
                  <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>MITRE Technique</label>
                  <input value={form.mitre_technique} onChange={e => setForm(f => ({ ...f, mitre_technique: e.target.value }))}
                    placeholder="e.g. T1078" className="g-input w-full mono" />
                </div>
                <div>
                  <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Rule Name Contains</label>
                  <input value={form.rule_name} onChange={e => setForm(f => ({ ...f, rule_name: e.target.value }))}
                    placeholder="e.g. Brute Force" className="g-input w-full" />
                </div>
                <div>
                  <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Agent ID (0 = any)</label>
                  <input type="number" min={0} value={form.agent_id}
                    onChange={e => setForm(f => ({ ...f, agent_id: parseInt(e.target.value) || 0 }))}
                    className="g-input w-full mono" />
                </div>
              </div>
            </div>

            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => setShowNew(false)} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={create} disabled={saving || !form.name}
                className="g-btn g-btn-primary flex-1 justify-center">
                {saving ? 'Creating…' : 'Create Rule'}
              </button>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
