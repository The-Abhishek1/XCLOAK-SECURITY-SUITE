'use client';

import { useState, useEffect } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { threatActorsAPI } from '@/lib/api';
import { Shield, Globe, Target, Plus, Trash2, ChevronDown, ChevronRight, AlertTriangle, Crosshair } from 'lucide-react';

interface ThreatActor {
  id: number; name: string; aliases: string[]; origin_country: string;
  motivation: string; sophistication: string; description: string;
  targeted_sectors: string[]; mitre_techniques: string[];
  is_builtin: boolean; recent_alert_count: number; created_at: string;
}
interface ActorAlert {
  id: number; rule_name: string; severity: string; status: string;
  hostname: string; created_at: string; confidence: number; matched_technique: string;
}

const MOTIVATION_COLOR: Record<string, string> = {
  espionage: '#38bdf8', financial: '#22c55e', destructive: '#f85149',
  hacktivism: '#a855f7',
};
const SOPHISTICATION_COLOR: Record<string, string> = {
  'nation-state': '#f85149', high: '#fb923c', medium: '#fbbf24', low: '#22c55e',
};
const SEV_COLOR: Record<string, string> = {
  critical: '#f85149', high: '#fb923c', medium: '#fbbf24', low: '#22c55e',
};

function ActorCard({ actor, expanded, onToggle, onDelete }: {
  actor: ThreatActor; expanded: boolean; onToggle: () => void; onDelete: () => void;
}) {
  const [alerts, setAlerts] = useState<ActorAlert[]>([]);
  const [loadingAlerts, setLoadingAlerts] = useState(false);

  const loadAlerts = async () => {
    if (alerts.length > 0) return;
    setLoadingAlerts(true);
    const r = await threatActorsAPI.getAlerts(actor.id, 10);
    setAlerts(r.data || []);
    setLoadingAlerts(false);
  };

  const handleToggle = () => {
    onToggle();
    if (!expanded) loadAlerts();
  };

  const motivColor = MOTIVATION_COLOR[actor.motivation] || 'var(--accent)';
  const sophColor = SOPHISTICATION_COLOR[actor.sophistication] || 'var(--text-3)';

  return (
    <div className="g-card overflow-hidden">
      <div className="px-4 py-3 flex items-center gap-3 cursor-pointer hover:bg-[var(--glass-bg-2)] transition-colors" onClick={handleToggle}>
        {expanded ? <ChevronDown className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />
                  : <ChevronRight className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />}

        <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
          style={{ background: `${motivColor}18`, border: `1px solid ${motivColor}40` }}>
          <Target className="h-4 w-4" style={{ color: motivColor }} />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{actor.name}</p>
            <span className="text-[10px] px-1.5 py-0.5 rounded font-bold uppercase"
              style={{ background: `${sophColor}18`, color: sophColor, border: `1px solid ${sophColor}40` }}>
              {actor.sophistication}
            </span>
            <span className="text-[10px] px-1.5 py-0.5 rounded capitalize"
              style={{ background: `${motivColor}12`, color: motivColor }}>
              {actor.motivation}
            </span>
            {actor.origin_country && (
              <span className="text-[10px] flex items-center gap-1" style={{ color: 'var(--text-3)' }}>
                <Globe className="h-3 w-3" /> {actor.origin_country}
              </span>
            )}
          </div>
          {actor.aliases?.length > 0 && (
            <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
              aka: {actor.aliases.join(', ')}
            </p>
          )}
        </div>

        {actor.recent_alert_count > 0 && (
          <span className="text-[11px] font-bold px-2 py-0.5 rounded-full flex items-center gap-1 shrink-0"
            style={{ background: 'rgba(248,81,73,0.15)', color: '#f85149' }}>
            <AlertTriangle className="h-3 w-3" /> {actor.recent_alert_count} alerts (30d)
          </span>
        )}
        {!actor.is_builtin && (
          <button onClick={e => { e.stopPropagation(); onDelete(); }} className="p-1.5 rounded hover:bg-[var(--glass-bg)]">
            <Trash2 className="h-3.5 w-3.5" style={{ color: '#f85149' }} />
          </button>
        )}
      </div>

      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t" style={{ borderColor: 'var(--border)' }}>
          <p className="text-xs mt-3" style={{ color: 'var(--text-2)' }}>{actor.description}</p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {actor.targeted_sectors?.length > 0 && (
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>Targeted Sectors</p>
                <div className="flex flex-wrap gap-1">
                  {actor.targeted_sectors.map(s => (
                    <span key={s} className="text-[10px] px-2 py-0.5 rounded-full capitalize"
                      style={{ background: 'var(--glass-bg-2)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>
                      {s}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {actor.mitre_techniques?.length > 0 && (
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>MITRE Techniques</p>
                <div className="flex flex-wrap gap-1">
                  {actor.mitre_techniques.map(t => (
                    <a key={t} href={`https://attack.mitre.org/techniques/${t}`} target="_blank" rel="noopener noreferrer"
                      className="text-[10px] px-2 py-0.5 rounded-full font-mono hover:underline"
                      style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                      {t}
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Recent alerts tagged to this actor */}
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>
              Recent Matched Alerts
            </p>
            {loadingAlerts ? (
              <p className="text-xs animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</p>
            ) : alerts.length === 0 ? (
              <p className="text-xs" style={{ color: 'var(--text-3)' }}>No alerts attributed to this actor in your environment.</p>
            ) : (
              <div className="space-y-1">
                {alerts.map(a => (
                  <div key={a.id} className="flex items-center justify-between rounded-lg px-3 py-2 text-[11px]"
                    style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <div className="flex items-center gap-2">
                      <span className="font-bold" style={{ color: SEV_COLOR[a.severity] || 'var(--text-3)' }}>
                        {a.severity?.toUpperCase()}
                      </span>
                      <span style={{ color: 'var(--text-2)' }}>{a.rule_name}</span>
                      {a.hostname && <span style={{ color: 'var(--text-3)' }}>@ {a.hostname}</span>}
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono" style={{ color: 'var(--accent)' }}>{a.matched_technique}</span>
                      <span style={{ color: 'var(--text-3)' }}>{a.confidence}%</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function CreateActorModal({ onClose, onCreate }: { onClose: () => void; onCreate: () => void }) {
  const [form, setForm] = useState({
    name: '', origin_country: '', motivation: 'espionage', sophistication: 'medium',
    description: '', aliases: '', targeted_sectors: '', mitre_techniques: '',
  });
  const [saving, setSaving] = useState(false);
  const save = async () => {
    if (!form.name) return;
    setSaving(true);
    await threatActorsAPI.create({
      ...form,
      aliases: form.aliases.split(',').map(s => s.trim()).filter(Boolean),
      targeted_sectors: form.targeted_sectors.split(',').map(s => s.trim()).filter(Boolean),
      mitre_techniques: form.mitre_techniques.split(',').map(s => s.trim()).filter(Boolean),
    });
    setSaving(false); onCreate(); onClose();
  };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}>
      <div className="g-card p-6 w-full max-w-lg space-y-3">
        <h3 className="text-base font-semibold" style={{ color: 'var(--text-1)' }}>Add Threat Actor</h3>
        <div className="grid grid-cols-2 gap-3">
          <div className="col-span-2"><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Name</label>
            <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} className="g-input w-full text-xs" /></div>
          <div><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Origin Country</label>
            <input value={form.origin_country} onChange={e => setForm(f => ({ ...f, origin_country: e.target.value }))} className="g-input w-full text-xs" /></div>
          <div><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Motivation</label>
            <select value={form.motivation} onChange={e => setForm(f => ({ ...f, motivation: e.target.value }))} className="g-select w-full text-xs">
              {['espionage','financial','destructive','hacktivism'].map(m => <option key={m} value={m}>{m}</option>)}
            </select></div>
          <div><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Sophistication</label>
            <select value={form.sophistication} onChange={e => setForm(f => ({ ...f, sophistication: e.target.value }))} className="g-select w-full text-xs">
              {['low','medium','high','nation-state'].map(s => <option key={s} value={s}>{s}</option>)}
            </select></div>
          <div><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Aliases (comma-separated)</label>
            <input value={form.aliases} onChange={e => setForm(f => ({ ...f, aliases: e.target.value }))} className="g-input w-full text-xs" placeholder="Fancy Bear, Sofacy" /></div>
          <div className="col-span-2"><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>MITRE Techniques (comma-separated)</label>
            <input value={form.mitre_techniques} onChange={e => setForm(f => ({ ...f, mitre_techniques: e.target.value }))} className="g-input w-full text-xs mono" placeholder="T1566, T1078, T1059" /></div>
          <div className="col-span-2"><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Targeted Sectors (comma-separated)</label>
            <input value={form.targeted_sectors} onChange={e => setForm(f => ({ ...f, targeted_sectors: e.target.value }))} className="g-input w-full text-xs" placeholder="government, energy, healthcare" /></div>
          <div className="col-span-2"><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Description</label>
            <textarea value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} className="g-input w-full text-xs resize-none" rows={2} /></div>
        </div>
        <div className="flex justify-end gap-2 pt-1">
          <button onClick={onClose} className="g-btn g-btn-ghost text-xs">Cancel</button>
          <button onClick={save} disabled={saving || !form.name} className="g-btn g-btn-primary text-xs">
            {saving ? 'Saving…' : 'Add Actor'}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function ThreatActorsPage() {
  const [actors, setActors] = useState<ThreatActor[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedID, setExpandedID] = useState<number | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [filter, setFilter] = useState('');

  const load = async () => {
    setLoading(true);
    const r = await threatActorsAPI.getAll();
    setActors(r.data || []);
    setLoading(false);
  };
  useEffect(() => { load(); }, []);

  const deleteActor = async (id: number) => {
    await threatActorsAPI.remove(id);
    setActors(prev => prev.filter(a => a.id !== id));
  };

  const filtered = filter
    ? actors.filter(a =>
        a.name.toLowerCase().includes(filter.toLowerCase()) ||
        a.motivation.toLowerCase().includes(filter.toLowerCase()) ||
        a.origin_country.toLowerCase().includes(filter.toLowerCase()) ||
        (a.mitre_techniques || []).some(t => t.toLowerCase().includes(filter.toLowerCase())))
    : actors;

  const activeActors = actors.filter(a => a.recent_alert_count > 0).length;

  return (
    <RootLayout title="Threat Actor Intelligence" subtitle="APT profiles · TTP mapping · Environment attribution"
      actions={
        <button onClick={() => setShowCreate(true)} className="g-btn g-btn-primary text-xs flex items-center gap-1.5">
          <Plus className="h-3.5 w-3.5" /> Add Actor
        </button>
      }>
      {showCreate && <CreateActorModal onClose={() => setShowCreate(false)} onCreate={load} />}

      {/* KPIs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
        {[
          { label: 'Known Actors', value: actors.length, color: 'var(--accent)' },
          { label: 'Active in Env (30d)', value: activeActors, color: activeActors > 0 ? '#f85149' : 'var(--text-3)' },
          { label: 'Nation-State', value: actors.filter(a => a.sophistication === 'nation-state').length, color: '#f85149' },
          { label: 'Financial', value: actors.filter(a => a.motivation === 'financial').length, color: '#22c55e' },
        ].map(({ label, value, color }) => (
          <div key={label} className="g-card p-4">
            <p className="text-2xl font-bold" style={{ color }}>{value}</p>
            <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{label}</p>
          </div>
        ))}
      </div>

      {/* Search */}
      <div className="relative mb-4 max-w-sm">
        <Crosshair className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
        <input value={filter} onChange={e => setFilter(e.target.value)}
          placeholder="Filter by name, country, technique…" className="g-input pl-9 w-full text-sm" />
      </div>

      {/* Actor list */}
      {loading ? (
        <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading threat actors…</div>
      ) : (
        <div className="space-y-2">
          {filtered.map(a => (
            <ActorCard key={a.id} actor={a}
              expanded={expandedID === a.id}
              onToggle={() => setExpandedID(prev => prev === a.id ? null : a.id)}
              onDelete={() => deleteActor(a.id)} />
          ))}
        </div>
      )}
    </RootLayout>
  );
}
