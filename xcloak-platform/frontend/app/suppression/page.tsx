'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { suppressionAPI } from '@/lib/api';
import { VolumeX, Plus, Trash2, ToggleLeft, ToggleRight, X, Info, Clock } from 'lucide-react';
import { timeAgo } from '@/lib/utils';

interface SuppressionRule {
  id: number;
  name: string;
  description: string;
  rule_name: string;
  agent_id: number;
  severity: string;
  mitre_technique: string;
  window_minutes: number;
  expires_at: string | null;
  enabled: boolean;
  match_count: number;
  created_at: string;
}

interface Stats { active_rules: number; total_suppressed: number; }

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low'];
const WINDOWS = [
  { label: '10 min',  value: 10 },
  { label: '30 min',  value: 30 },
  { label: '1 hour',  value: 60 },
  { label: '4 hours', value: 240 },
  { label: '24 hours',value: 1440 },
  { label: '7 days',  value: 10080 },
];

const empty = {
  name: '', description: '', rule_name: '', agent_id: 0,
  severity: '', mitre_technique: '', window_minutes: 60, expires_at: '',
};

export default function SuppressionPage() {
  const [rules, setRules]   = useState<SuppressionRule[]>([]);
  const [stats, setStats]   = useState<Stats>({ active_rules: 0, total_suppressed: 0 });
  const [loading, setLoading] = useState(true);
  const [showNew, setShowNew] = useState(false);
  const [form, setForm]     = useState({ ...empty });
  const [saving, setSaving] = useState(false);
  const [toast, setToast]   = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const r = await suppressionAPI.getAll();
      setRules(r.data?.rules || []);
      setStats(r.data?.stats || { active_rules: 0, total_suppressed: 0 });
    } finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const create = async () => {
    if (!form.name) return;
    setSaving(true);
    try {
      await suppressionAPI.create({
        ...form,
        agent_id: form.agent_id || 0,
        window_minutes: form.window_minutes || 60,
        expires_at: form.expires_at || null,
      });
      load(); setShowNew(false); setForm({ ...empty });
      notify('Suppression rule created');
    } catch { notify('Failed to create rule'); }
    finally { setSaving(false); }
  };

  const toggle = async (id: number, enabled: boolean) => {
    await suppressionAPI.toggle(id, !enabled);
    setRules(r => r.map(x => x.id === id ? { ...x, enabled: !enabled } : x));
  };

  const del = async (id: number) => {
    await suppressionAPI.remove(id);
    setRules(r => r.filter(x => x.id !== id));
    notify('Rule deleted');
  };

  return (
    <RootLayout title="Alert Suppression" subtitle="Control alert noise with suppression rules"
      onRefresh={() => load(true)} refreshing={refreshing}
      actions={
        <button onClick={() => setShowNew(true)} className="g-btn g-btn-primary text-xs">
          <Plus className="h-3.5 w-3.5" /> New Rule
        </button>
      }>

      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)' }}>{toast}</div>}

      <div className="space-y-5">
        {/* Stats */}
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: 'Active Rules',      val: stats.active_rules,      color: 'var(--accent)' },
            { label: 'Total Suppressed',  val: stats.total_suppressed,  color: 'var(--green)' },
            { label: 'Total Rules',       val: rules.length,            color: 'var(--text-2)' },
          ].map(s => (
            <div key={s.label} className="g-card p-4 text-center">
              <p className="text-2xl font-bold tabular-nums" style={{ color: s.color }}>{s.val}</p>
              <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>{s.label}</p>
            </div>
          ))}
        </div>

        {/* Info */}
        <div className="g-card p-4 flex items-start gap-3"
          style={{ border: '1px solid var(--accent-border)', background: 'var(--accent-glow)' }}>
          <Info className="h-4 w-4 shrink-0 mt-0.5" style={{ color: 'var(--accent)' }} />
          <p className="text-xs leading-relaxed" style={{ color: 'var(--text-2)' }}>
            Suppression rules silently drop matching alerts after the first occurrence within the
            configured time window. Use them to reduce noise from known-benign detections or
            scheduled tasks that repeatedly trigger rules. The first alert always gets through —
            only subsequent matches within the window are suppressed.
          </p>
        </div>

        {/* Rules list */}
        {loading ? (
          <div className="py-12 text-center animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
        ) : rules.length === 0 ? (
          <div className="g-card py-14 text-center">
            <VolumeX className="mx-auto h-10 w-10 mb-3" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No suppression rules yet.</p>
            <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>
              Add rules to reduce alert noise from known benign detections.
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {rules.map(r => (
              <div key={r.id} className="g-card px-4 py-3 flex items-start gap-4">
                <button onClick={() => toggle(r.id, r.enabled)} className="mt-0.5 shrink-0">
                  {r.enabled
                    ? <ToggleRight className="h-5 w-5" style={{ color: 'var(--accent)' }} />
                    : <ToggleLeft  className="h-5 w-5" style={{ color: 'var(--text-3)' }} />}
                </button>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{r.name}</p>
                    <span className="flex items-center gap-1 text-[10px]"
                      style={{ color: 'var(--text-3)' }}>
                      <Clock className="h-3 w-3" /> {r.window_minutes}m window
                    </span>
                  </div>
                  <div className="mono text-[10px] space-y-0.5" style={{ color: 'var(--text-3)' }}>
                    <p>
                      IF
                      {r.severity       && <span style={{ color: 'var(--orange)' }}> severity={r.severity}</span>}
                      {r.rule_name      && <span style={{ color: 'var(--accent)' }}> rule≈&quot;{r.rule_name}&quot;</span>}
                      {r.mitre_technique && <span style={{ color: 'var(--yellow)' }}> mitre={r.mitre_technique}</span>}
                      {r.agent_id > 0   && <span style={{ color: 'var(--blue)' }}> agent=#{r.agent_id}</span>}
                      {(!r.severity && !r.rule_name && !r.mitre_technique && !r.agent_id)
                        && <span> (match any)</span>}
                      <span style={{ color: 'var(--green)' }}> → suppress for {r.window_minutes}m</span>
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0 text-[10px]" style={{ color: 'var(--text-3)' }}>
                  <span className="font-medium" style={{ color: 'var(--green)' }}>
                    {r.match_count} suppressed
                  </span>
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
        )}
      </div>

      {/* Modal */}
      {showNew && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setShowNew(false)}>
          <div className="g-modal" style={{ maxWidth: 520 }}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>New Suppression Rule</h2>
              <button onClick={() => setShowNew(false)} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>

            <div className="p-5 space-y-4">
              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Rule Name *</label>
                <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  placeholder="e.g. Suppress vulnerability scan alerts" className="g-input w-full" />
              </div>

              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Suppression Window</label>
                <div className="flex gap-2 flex-wrap">
                  {WINDOWS.map(w => (
                    <button key={w.value} onClick={() => setForm(f => ({ ...f, window_minutes: w.value }))}
                      className="text-[11px] px-2.5 py-1 rounded-lg transition-all"
                      style={{
                        background: form.window_minutes === w.value ? 'var(--accent-glow)' : 'var(--glass-bg)',
                        border: `1px solid ${form.window_minutes === w.value ? 'var(--accent-border)' : 'var(--border)'}`,
                        color: form.window_minutes === w.value ? 'var(--accent)' : 'var(--text-2)',
                      }}>
                      {w.label}
                    </button>
                  ))}
                </div>
              </div>

              <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
                Match Conditions (leave blank = match any)
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
                  <input value={form.mitre_technique}
                    onChange={e => setForm(f => ({ ...f, mitre_technique: e.target.value }))}
                    placeholder="e.g. T1046" className="g-input w-full mono" />
                </div>
                <div>
                  <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Rule Name Contains</label>
                  <input value={form.rule_name}
                    onChange={e => setForm(f => ({ ...f, rule_name: e.target.value }))}
                    placeholder="e.g. Network Scan" className="g-input w-full" />
                </div>
                <div>
                  <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Agent ID (0 = any)</label>
                  <input type="number" min={0} value={form.agent_id}
                    onChange={e => setForm(f => ({ ...f, agent_id: parseInt(e.target.value) || 0 }))}
                    className="g-input w-full mono" />
                </div>
              </div>

              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>
                  Auto-expire (leave blank = never)
                </label>
                <input type="datetime-local" value={form.expires_at || ''}
                  onChange={e => setForm(f => ({ ...f, expires_at: e.target.value }))}
                  className="g-input w-full" />
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
