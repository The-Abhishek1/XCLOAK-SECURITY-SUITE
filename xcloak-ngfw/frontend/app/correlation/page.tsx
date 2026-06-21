'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { correlationAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import { GitMerge, Plus, Trash2, ToggleLeft, ToggleRight, X, Info, ArrowRight } from 'lucide-react';

const ACTIONS = ['create_incident', 'notify'];
const SEVERITIES = ['', 'critical', 'high', 'medium', 'low'];
const CORRELATION_TYPES = [
  { id: 'simple',           label: 'Simple — single alert' },
  { id: 'event_count',      label: 'Event Count — N+ within a time window' },
  { id: 'temporal',         label: 'Temporal — all stages within a window (any order)' },
  { id: 'temporal_ordered', label: 'Temporal Ordered — stages within a window, in order (attack chain)' },
];

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
  correlation_type: string;
  window_minutes: number;
  threshold: number;
  stages: string[] | null;
}

const empty = {
  name: '', description: '', severity: '', rule_name: '',
  mitre_technique: '', agent_id: 0, action: 'create_incident',
  correlation_type: 'simple', window_minutes: 10, threshold: 3,
  stages: ['', ''] as string[],
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

  const isTemporal = form.correlation_type === 'temporal' || form.correlation_type === 'temporal_ordered';

  const create = async () => {
    if (!form.name || !form.action) return;
    setSaving(true);
    try {
      const payload = { ...form, stages: isTemporal ? form.stages.filter(Boolean) : [] };
      await correlationAPI.create(payload);
      load(); setShowNew(false); setForm({ ...empty, stages: ['', ''] });
      notify('Rule created');
    } catch (e: any) { notify(e?.response?.data?.error || 'Failed to create rule'); }
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

  const addStage = () => setForm(f => ({ ...f, stages: [...f.stages, ''] }));
  const removeStage = (idx: number) => setForm(f => ({ ...f, stages: f.stages.filter((_, i) => i !== idx) }));
  const updateStage = (idx: number, val: string) => setForm(f => ({ ...f, stages: f.stages.map((s, i) => i === idx ? val : s) }));

  const describeRule = (r: Rule) => {
    switch (r.correlation_type) {
      case 'event_count':
        return (
          <p className="mono text-[10px]" style={{ color: 'var(--text-3)' }}>
            <span style={{ color: 'var(--yellow)' }}>{r.threshold}+ matches</span> within{' '}
            <span style={{ color: 'var(--blue)' }}>{r.window_minutes}min</span>
            {r.severity && <> · severity={r.severity}</>}
            {r.rule_name && <> · rule_name≈&quot;{r.rule_name}&quot;</>}
            {' → '}<span style={{ color: 'var(--green)' }}>{r.action}</span>
          </p>
        );
      case 'temporal':
      case 'temporal_ordered':
        return (
          <p className="mono text-[10px] flex items-center gap-1 flex-wrap" style={{ color: 'var(--text-3)' }}>
            {(r.stages || []).map((s, i) => (
              <span key={i} className="flex items-center gap-1">
                <span style={{ color: 'var(--accent)' }}>&quot;{s}&quot;</span>
                {i < (r.stages?.length || 0) - 1 && (
                  r.correlation_type === 'temporal_ordered'
                    ? <ArrowRight className="h-2.5 w-2.5" />
                    : <span>+</span>
                )}
              </span>
            ))}
            <span>within {r.window_minutes}min {' → '}</span>
            <span style={{ color: 'var(--green)' }}>{r.action}</span>
          </p>
        );
      default:
        return (
          <p className="mono text-[10px]" style={{ color: 'var(--text-3)' }}>
            IF
            {r.severity        && <span style={{ color: 'var(--orange)' }}> severity={r.severity}</span>}
            {r.rule_name       && <span style={{ color: 'var(--accent)' }}> rule_name≈&quot;{r.rule_name}&quot;</span>}
            {r.mitre_technique && <span style={{ color: 'var(--yellow)' }}> mitre={r.mitre_technique}</span>}
            {r.agent_id > 0    && <span style={{ color: 'var(--blue)' }}> agent=#{r.agent_id}</span>}
            {(!r.severity && !r.rule_name && !r.mitre_technique && !r.agent_id) && <span> (any alert)</span>}
            {' → '}
            <span style={{ color: 'var(--green)' }}>{r.action}</span>
          </p>
        );
    }
  };

  return (
    <RootLayout title="Correlation Rules" subtitle="Time-windowed, multi-stage alert correlation"
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
          fire on critical/high alerts and IOC/YARA matches. Custom rules support four modes:{' '}
          <b>Simple</b> (single-alert conditions), <b>Event Count</b> (N+ matching alerts within a
          time window — a generalized brute-force detector), <b>Temporal</b> (every listed stage
          seen within a window, any order), and <b>Temporal Ordered</b> (the same, but stages must
          occur in that order — a real multi-step attack chain, e.g. recon → exploit → persist).
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
                Create rules to correlate specific MITRE techniques, thresholds, or multi-stage attack chains into incidents.
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
                  {r.correlation_type && r.correlation_type !== 'simple' && (
                    <span className="text-[9px] px-1.5 py-0.5 rounded uppercase tracking-wide"
                      style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                      {r.correlation_type.replace('_', ' ')}
                    </span>
                  )}
                  {!r.enabled && (
                    <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>disabled</span>
                  )}
                </div>
                {r.description && (
                  <p className="text-[11px] mb-1" style={{ color: 'var(--text-3)' }}>{r.description}</p>
                )}
                <div className="space-y-0.5">{describeRule(r)}</div>
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
          <div className="g-modal" style={{ maxWidth: 560 }}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>New Correlation Rule</h2>
              <button onClick={() => setShowNew(false)} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>

            <div className="p-5 space-y-4 max-h-[70vh] overflow-y-auto">
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

              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Correlation Type *</label>
                <select value={form.correlation_type} onChange={e => setForm(f => ({ ...f, correlation_type: e.target.value }))}
                  className="g-select w-full">
                  {CORRELATION_TYPES.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
                </select>
              </div>

              {form.correlation_type === 'event_count' && (
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Window (minutes) *</label>
                    <input type="number" min={1} value={form.window_minutes}
                      onChange={e => setForm(f => ({ ...f, window_minutes: parseInt(e.target.value) || 1 }))}
                      className="g-input w-full mono" />
                  </div>
                  <div>
                    <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Threshold (min 2) *</label>
                    <input type="number" min={2} value={form.threshold}
                      onChange={e => setForm(f => ({ ...f, threshold: parseInt(e.target.value) || 2 }))}
                      className="g-input w-full mono" />
                  </div>
                </div>
              )}

              {isTemporal && (
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-xs block" style={{ color: 'var(--text-3)' }}>
                      Window (minutes) *
                    </label>
                  </div>
                  <input type="number" min={1} value={form.window_minutes}
                    onChange={e => setForm(f => ({ ...f, window_minutes: parseInt(e.target.value) || 1 }))}
                    className="g-input w-full mono mb-3" style={{ maxWidth: 140 }} />

                  <div className="flex items-center justify-between mb-2">
                    <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
                      Stages (rule_name patterns, {form.correlation_type === 'temporal_ordered' ? 'in order' : 'any order'})
                    </label>
                    <button onClick={addStage} className="g-btn g-btn-ghost text-[10px]" style={{ padding: '3px 8px' }}>
                      <Plus className="h-3 w-3" /> Add Stage
                    </button>
                  </div>
                  <div className="space-y-2">
                    {form.stages.map((s, idx) => (
                      <div key={idx} className="flex gap-2 items-center">
                        <span className="text-[10px] mono w-5 shrink-0" style={{ color: 'var(--text-3)' }}>{idx + 1}.</span>
                        <input value={s} onChange={e => updateStage(idx, e.target.value)}
                          placeholder="e.g. Port Recon Scan" className="g-input flex-1 mono" />
                        {form.stages.length > 2 && (
                          <button onClick={() => removeStage(idx)} className="p-1.5 rounded shrink-0" style={{ color: 'var(--text-3)' }}>
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                  <p className="text-[10px] mt-1.5" style={{ color: 'var(--text-3)' }}>
                    Each stage matches if any alert&apos;s rule_name contains that text (case-insensitive). At least 2 stages required.
                  </p>
                </div>
              )}

              {!isTemporal && (
                <>
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
                </>
              )}
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
