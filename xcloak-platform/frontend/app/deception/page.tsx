'use client';

import { useState, useEffect } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import api from '@/lib/api';
import { Eye, EyeOff, Trash2, AlertTriangle, Shield, Zap, Plus, Copy, Check, Wifi } from 'lucide-react';

interface CanaryToken {
  id: number; token_type: string; name: string; token_value: string;
  description: string; deployed_to: string; created_by: string;
  alert_on_trip: boolean; is_active: boolean; trip_count: number;
  last_tripped_at: string | null; created_at: string;
}
interface CanaryTrip {
  id: number; token_id: number; source_ip: string; user_agent: string;
  method: string; extra_data: Record<string, any>; tripped_at: string;
}
interface Honeyport {
  id: number; agent_id: number; port: number; protocol: string;
  description: string; alert_severity: string; is_active: boolean;
  created_at: string; hostname: string;
}
interface Agent { id: number; hostname: string; }

const TYPE_COLORS: Record<string, string> = {
  file: '#fbbf24', api_key: '#a855f7', url: '#22c55e', dns: '#38bdf8',
};

function TokenCard({ t, onDelete, onToggle }: { t: CanaryToken; onDelete: () => void; onToggle: () => void }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(t.token_value);
    setCopied(true); setTimeout(() => setCopied(false), 1500);
  };
  const color = TYPE_COLORS[t.token_type] || 'var(--accent)';
  return (
    <div className="g-card p-4" style={{ borderLeft: `3px solid ${t.trip_count > 0 ? '#f85149' : color}`, opacity: t.is_active ? 1 : 0.6 }}>
      <div className="flex items-start justify-between mb-2">
        <div>
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded uppercase"
              style={{ background: `${color}18`, color, border: `1px solid ${color}40` }}>
              {t.token_type}
            </span>
            {t.trip_count > 0 && (
              <span className="text-[10px] font-bold px-1.5 py-0.5 rounded flex items-center gap-1"
                style={{ background: 'rgba(248,81,73,0.15)', color: '#f85149' }}>
                <AlertTriangle className="h-2.5 w-2.5" /> {t.trip_count} trip{t.trip_count > 1 ? 's' : ''}
              </span>
            )}
          </div>
          <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{t.name}</p>
          {t.deployed_to && <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{t.deployed_to}</p>}
        </div>
        <div className="flex items-center gap-1.5 ml-2">
          <button onClick={copy} className="p-1.5 rounded-lg transition-colors hover:bg-[var(--glass-bg-2)]" title="Copy token value">
            {copied ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />}
          </button>
          <button onClick={onToggle} className="p-1.5 rounded-lg transition-colors hover:bg-[var(--glass-bg-2)]" title={t.is_active ? 'Deactivate' : 'Activate'}>
            {t.is_active ? <Eye className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} /> : <EyeOff className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />}
          </button>
          <button onClick={onDelete} className="p-1.5 rounded-lg transition-colors hover:bg-[var(--glass-bg-2)]">
            <Trash2 className="h-3.5 w-3.5" style={{ color: '#f85149' }} />
          </button>
        </div>
      </div>
      <div className="font-mono text-[10px] px-2 py-1.5 rounded-lg truncate"
        style={{ background: 'var(--bg-0)', color: 'var(--text-3)', border: '1px solid var(--border)' }}>
        {t.token_value}
      </div>
      {t.last_tripped_at && (
        <p className="text-[10px] mt-1.5" style={{ color: '#f85149' }}>
          Last tripped: {new Date(t.last_tripped_at).toLocaleString()}
        </p>
      )}
    </div>
  );
}

function CreateTokenModal({ onClose, onCreate }: { onClose: () => void; onCreate: () => void }) {
  const [form, setForm] = useState({ token_type: 'file', name: '', description: '', deployed_to: '' });
  const [saving, setSaving] = useState(false);
  const save = async () => {
    if (!form.name) return;
    setSaving(true);
    await api.post('/canary/tokens', form);
    setSaving(false);
    onCreate();
    onClose();
  };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}>
      <div className="g-card p-6 w-full max-w-md space-y-4">
        <h3 className="text-base font-semibold" style={{ color: 'var(--text-1)' }}>New Canary Token</h3>
        <div>
          <label className="block text-[11px] mb-1" style={{ color: 'var(--text-3)' }}>Type</label>
          <select value={form.token_type} onChange={e => setForm(f => ({ ...f, token_type: e.target.value }))} className="g-select w-full text-xs">
            <option value="file">File (embed in documents)</option>
            <option value="api_key">API Key (embed in code/configs)</option>
            <option value="url">URL (tracking pixel / link)</option>
            <option value="dns">DNS (canary hostname)</option>
          </select>
        </div>
        <div>
          <label className="block text-[11px] mb-1" style={{ color: 'var(--text-3)' }}>Name</label>
          <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} className="g-input w-full text-xs" placeholder="HR Database Backup.xlsx" />
        </div>
        <div>
          <label className="block text-[11px] mb-1" style={{ color: 'var(--text-3)' }}>Description</label>
          <input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} className="g-input w-full text-xs" placeholder="Placed on finance share drive" />
        </div>
        <div>
          <label className="block text-[11px] mb-1" style={{ color: 'var(--text-3)' }}>Deployed To (path/location)</label>
          <input value={form.deployed_to} onChange={e => setForm(f => ({ ...f, deployed_to: e.target.value }))} className="g-input w-full text-xs" placeholder="\\fileserver\Finance\Confidential\" />
        </div>
        <div className="flex justify-end gap-2 pt-1">
          <button onClick={onClose} className="g-btn g-btn-ghost text-xs">Cancel</button>
          <button onClick={save} disabled={saving || !form.name} className="g-btn g-btn-primary text-xs">
            {saving ? 'Generating…' : 'Generate Token'}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function DeceptionPage() {
  const [tokens, setTokens] = useState<CanaryToken[]>([]);
  const [trips, setTrips] = useState<CanaryTrip[]>([]);
  const [honeyports, setHoneyports] = useState<Honeyport[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<'tokens' | 'trips' | 'honeyports'>('tokens');
  const [showCreate, setShowCreate] = useState(false);
  const [newPort, setNewPort] = useState({ agent_id: 0, port: '', protocol: 'tcp', description: '', alert_severity: 'high' });
  const [toast, setToast] = useState<string | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const load = async () => {
    setLoading(true);
    const [t, tr, h, ag] = await Promise.all([
      api.get('/canary/tokens').catch(() => ({ data: [] })),
      api.get('/canary/trips?limit=50').catch(() => ({ data: [] })),
      api.get('/honeyports').catch(() => ({ data: [] })),
      api.get('/agents').catch(() => ({ data: [] })),
    ]);
    setTokens(t.data || []);
    setTrips(tr.data || []);
    setHoneyports(h.data || []);
    setAgents(ag.data || []);
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const deleteToken = async (id: number) => {
    await api.delete(`/canary/tokens/${id}`);
    setTokens(prev => prev.filter(t => t.id !== id));
    notify('Token deleted');
  };
  const toggleToken = async (t: CanaryToken) => {
    await api.patch(`/canary/tokens/${t.id}/toggle`, { is_active: !t.is_active });
    setTokens(prev => prev.map(x => x.id === t.id ? { ...x, is_active: !x.is_active } : x));
  };
  const createHoneyport = async () => {
    if (!newPort.port || !newPort.agent_id) return;
    await api.post('/honeyports', { ...newPort, port: parseInt(newPort.port) });
    setNewPort({ agent_id: 0, port: '', protocol: 'tcp', description: '', alert_severity: 'high' });
    load();
    notify('Honeyport created');
  };
  const deleteHoneyport = async (id: number) => {
    await api.delete(`/honeyports/${id}`);
    setHoneyports(prev => prev.filter(h => h.id !== id));
    notify('Honeyport removed');
  };

  const activeTrips = trips.length;
  const activeTokens = tokens.filter(t => t.is_active).length;
  const trippedTokens = tokens.filter(t => t.trip_count > 0).length;

  return (
    <RootLayout title="Deception Technology" subtitle="Canary tokens · Honeyports · Tripwire detection">
      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)' }}>{toast}</div>}
      {showCreate && <CreateTokenModal onClose={() => setShowCreate(false)} onCreate={load} />}

      {/* KPIs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
        {[
          { label: 'Active Tokens', value: activeTokens, color: 'var(--accent)', icon: Shield },
          { label: 'Tripped', value: trippedTokens, color: trippedTokens > 0 ? '#f85149' : 'var(--text-3)', icon: AlertTriangle },
          { label: 'Recent Trips', value: activeTrips, color: activeTrips > 0 ? '#f85149' : 'var(--text-3)', icon: Zap },
          { label: 'Honeyports', value: honeyports.filter(h => h.is_active).length, color: '#fbbf24', icon: Wifi },
        ].map(({ label, value, color, icon: Icon }) => (
          <div key={label} className="g-card p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg" style={{ background: `${color}18` }}>
              <Icon className="h-4 w-4" style={{ color }} />
            </div>
            <div>
              <p className="text-xl font-bold" style={{ color }}>{value}</p>
              <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1.5 mb-4">
        {(['tokens', 'trips', 'honeyports'] as const).map(t => (
          <button key={t} onClick={() => setTab(t)}
            className="px-3 py-1.5 rounded-lg text-xs font-medium capitalize transition-all"
            style={{
              background: tab === t ? 'var(--accent-glow)' : 'var(--glass-bg)',
              border: `1px solid ${tab === t ? 'var(--accent-border)' : 'var(--border)'}`,
              color: tab === t ? 'var(--accent)' : 'var(--text-2)',
            }}>
            {t === 'tokens' ? `Canary Tokens (${tokens.length})` : t === 'trips' ? `Trip Log (${trips.length})` : `Honeyports (${honeyports.length})`}
          </button>
        ))}
        {tab === 'tokens' && (
          <button onClick={() => setShowCreate(true)} className="g-btn g-btn-primary text-xs ml-auto flex items-center gap-1.5">
            <Plus className="h-3.5 w-3.5" /> New Token
          </button>
        )}
      </div>

      {/* Tokens tab */}
      {tab === 'tokens' && (
        loading ? <p className="text-sm py-10 text-center animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</p>
        : tokens.length === 0
          ? <div className="g-card p-10 text-center">
              <Shield className="mx-auto h-10 w-10 mb-2 opacity-20" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm mb-3" style={{ color: 'var(--text-3)' }}>No canary tokens yet. Plant your first tripwire.</p>
              <button onClick={() => setShowCreate(true)} className="g-btn g-btn-primary text-xs">
                <Plus className="h-3.5 w-3.5" /> Create Token
              </button>
            </div>
          : <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {tokens.map(t => (
                <TokenCard key={t.id} t={t} onDelete={() => deleteToken(t.id)} onToggle={() => toggleToken(t)} />
              ))}
            </div>
      )}

      {/* Trips tab */}
      {tab === 'trips' && (
        <div className="g-card overflow-hidden">
          <table className="w-full" style={{ borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Time', 'Token', 'Source IP', 'Method', 'User Agent'].map(h => (
                  <th key={h} className="px-3 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {trips.length === 0
                ? <tr><td colSpan={5} className="px-4 py-10 text-center text-sm" style={{ color: 'var(--text-3)' }}>No trips recorded yet.</td></tr>
                : trips.map(tr => {
                    const tok = tokens.find(t => t.id === tr.token_id);
                    return (
                      <tr key={tr.id} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td className="px-3 py-2.5 text-xs" style={{ color: 'var(--text-3)' }}>{new Date(tr.tripped_at).toLocaleString()}</td>
                        <td className="px-3 py-2.5 text-xs font-medium" style={{ color: '#f85149' }}>{tok?.name || `#${tr.token_id}`}</td>
                        <td className="px-3 py-2.5 font-mono text-xs" style={{ color: 'var(--text-2)' }}>{tr.source_ip}</td>
                        <td className="px-3 py-2.5 text-xs" style={{ color: 'var(--text-3)' }}>{tr.method}</td>
                        <td className="px-3 py-2.5 text-xs truncate max-w-[200px]" style={{ color: 'var(--text-3)' }}>{tr.user_agent}</td>
                      </tr>
                    );
                  })
              }
            </tbody>
          </table>
        </div>
      )}

      {/* Honeyports tab */}
      {tab === 'honeyports' && (
        <div className="space-y-4">
          {/* Add form */}
          <div className="g-card p-4">
            <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-2)' }}>Add Honeyport</p>
            <div className="flex flex-wrap gap-2 items-end">
              <div>
                <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Agent</label>
                <select value={newPort.agent_id} onChange={e => setNewPort(p => ({ ...p, agent_id: parseInt(e.target.value) }))} className="g-select text-xs">
                  <option value="0">Select agent…</option>
                  {agents.map(a => <option key={a.id} value={a.id}>{a.hostname}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Port</label>
                <input value={newPort.port} onChange={e => setNewPort(p => ({ ...p, port: e.target.value }))} className="g-input text-xs w-24 mono" placeholder="e.g. 4444" />
              </div>
              <div>
                <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Protocol</label>
                <select value={newPort.protocol} onChange={e => setNewPort(p => ({ ...p, protocol: e.target.value }))} className="g-select text-xs">
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                </select>
              </div>
              <div>
                <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Alert Severity</label>
                <select value={newPort.alert_severity} onChange={e => setNewPort(p => ({ ...p, alert_severity: e.target.value }))} className="g-select text-xs">
                  {['critical','high','medium','low'].map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
              <div className="flex-1 min-w-[140px]">
                <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Description</label>
                <input value={newPort.description} onChange={e => setNewPort(p => ({ ...p, description: e.target.value }))} className="g-input text-xs w-full" placeholder="Fake SSH, RDP, etc." />
              </div>
              <button onClick={createHoneyport} disabled={!newPort.port || !newPort.agent_id} className="g-btn g-btn-primary text-xs flex items-center gap-1.5">
                <Plus className="h-3.5 w-3.5" /> Add
              </button>
            </div>
          </div>
          {/* List */}
          <div className="g-card overflow-hidden">
            <table className="w-full" style={{ borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['Agent', 'Port', 'Protocol', 'Severity', 'Description', ''].map(h => (
                    <th key={h} className="px-3 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {honeyports.length === 0
                  ? <tr><td colSpan={6} className="px-4 py-10 text-center text-sm" style={{ color: 'var(--text-3)' }}>No honeyports configured. Add one above to detect port scans.</td></tr>
                  : honeyports.map(h => (
                      <tr key={h.id} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td className="px-3 py-2.5 text-xs font-medium" style={{ color: 'var(--text-1)' }}>{h.hostname || `Agent #${h.agent_id}`}</td>
                        <td className="px-3 py-2.5 font-mono text-xs" style={{ color: 'var(--accent)' }}>{h.port}</td>
                        <td className="px-3 py-2.5 text-xs uppercase" style={{ color: 'var(--text-3)' }}>{h.protocol}</td>
                        <td className="px-3 py-2.5 text-xs font-bold" style={{ color: h.alert_severity === 'critical' ? '#f85149' : h.alert_severity === 'high' ? '#fb923c' : '#fbbf24' }}>{h.alert_severity}</td>
                        <td className="px-3 py-2.5 text-xs" style={{ color: 'var(--text-2)' }}>{h.description || '—'}</td>
                        <td className="px-3 py-2.5">
                          <button onClick={() => deleteHoneyport(h.id)} className="p-1 rounded hover:bg-[var(--glass-bg-2)]">
                            <Trash2 className="h-3.5 w-3.5" style={{ color: '#f85149' }} />
                          </button>
                        </td>
                      </tr>
                    ))
                }
              </tbody>
            </table>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
