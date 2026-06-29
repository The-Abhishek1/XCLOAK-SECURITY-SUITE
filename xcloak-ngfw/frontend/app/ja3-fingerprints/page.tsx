'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import api from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import {
  Fingerprint, Plus, Trash2, RefreshCw, Loader2,
  ShieldAlert, Globe, Lock,
} from 'lucide-react';

interface JA3Entry {
  id: number;
  hash: string;
  threat_name: string;
  severity: string;
  source: string;
  description: string;
  enabled: boolean;
  is_platform: boolean;
  created_at: string;
}

const SEV_COLOR: Record<string, string> = {
  critical: '#f85149',
  high:     '#e3b341',
  medium:   '#d29922',
  low:      '#3fb950',
  info:     'var(--text-3)',
};

const empty = { hash: '', threat_name: '', severity: 'high', source: 'manual', description: '' };

export default function JA3FingerprintsPage() {
  const [entries, setEntries]   = useState<JA3Entry[]>([]);
  const [loading, setLoading]   = useState(true);
  const [showAdd, setShowAdd]   = useState(false);
  const [form, setForm]         = useState({ ...empty });
  const [saving, setSaving]     = useState(false);
  const [toast, setToast]       = useState<string | null>(null);
  const [search, setSearch]     = useState('');

  const notify = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 3000); };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.get('/ja3/fingerprints');
      setEntries(Array.isArray(r.data) ? r.data : []);
    } catch { setEntries([]); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    if (form.hash.length !== 32) { notify('Hash must be exactly 32 hex characters (MD5)'); return; }
    setSaving(true);
    try {
      await api.post('/ja3/fingerprints', form);
      setShowAdd(false);
      setForm({ ...empty });
      load();
      notify('Fingerprint added');
    } catch (err: any) {
      notify(err?.response?.data?.error || 'Failed to add fingerprint');
    } finally { setSaving(false); }
  };

  const remove = async (e: JA3Entry) => {
    if (e.is_platform) { notify('Platform-wide fingerprints cannot be deleted'); return; }
    if (!confirm(`Delete "${e.threat_name}"?`)) return;
    try {
      await api.delete(`/ja3/fingerprints/${e.id}`);
      setEntries(p => p.filter(x => x.id !== e.id));
      notify('Deleted');
    } catch { notify('Delete failed'); }
  };

  const filtered = entries.filter(e =>
    !search ||
    e.hash.includes(search.toLowerCase()) ||
    e.threat_name.toLowerCase().includes(search.toLowerCase()) ||
    e.source.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <RootLayout title="JA3 Fingerprints" subtitle="TLS ClientHello fingerprint blocklist — detects C2, RATs, and exploit frameworks by their TLS signature">
      {toast && (
        <div className="fixed bottom-4 right-4 z-50 px-4 py-2 rounded-lg text-sm font-medium shadow-lg"
          style={{ background: 'var(--accent)', color: '#fff' }}>{toast}</div>
      )}

      <div className="space-y-4">
        {/* Header */}
        <div className="flex items-center gap-3">
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search hash, threat name, source…"
            className="g-input flex-1 text-xs" />
          <button onClick={load} className="g-btn g-btn-ghost text-xs"><RefreshCw className="h-3.5 w-3.5" /></button>
          <button onClick={() => setShowAdd(true)} className="g-btn g-btn-primary text-xs">
            <Plus className="h-3.5 w-3.5" /> Add Hash
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Total', val: entries.length, icon: Fingerprint },
            { label: 'Critical', val: entries.filter(e => e.severity === 'critical').length, icon: ShieldAlert, color: '#f85149' },
            { label: 'Platform', val: entries.filter(e => e.is_platform).length, icon: Globe },
            { label: 'Custom', val: entries.filter(e => !e.is_platform).length, icon: Lock },
          ].map(s => (
            <div key={s.label} className="g-card p-4 flex items-center gap-3">
              <s.icon className="h-4 w-4 flex-shrink-0" style={{ color: s.color || 'var(--accent)' }} />
              <div>
                <p className="text-lg font-bold" style={{ color: 'var(--text-1)' }}>{s.val}</p>
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{s.label}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Add form */}
        {showAdd && (
          <div className="g-card p-5 space-y-4">
            <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Add Custom JA3 Hash</p>
            <form onSubmit={create} className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>JA3 Hash (MD5, 32 hex chars)</label>
                  <input required value={form.hash} onChange={e => setForm(f => ({ ...f, hash: e.target.value.toLowerCase() }))}
                    placeholder="a0e9f5d64349fb13191bc781f81f42e1" maxLength={32}
                    className="g-input w-full text-xs mono" />
                </div>
                <div>
                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Threat Name</label>
                  <input required value={form.threat_name} onChange={e => setForm(f => ({ ...f, threat_name: e.target.value }))}
                    placeholder="e.g. Cobalt Strike" className="g-input w-full text-xs" />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Severity</label>
                  <select value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}
                    className="g-input w-full text-xs">
                    {['critical','high','medium','low','info'].map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
                <div>
                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Source</label>
                  <input value={form.source} onChange={e => setForm(f => ({ ...f, source: e.target.value }))}
                    placeholder="manual / abuse.ch / internal" className="g-input w-full text-xs" />
                </div>
              </div>
              <div>
                <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Description (optional)</label>
                <input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  placeholder="Brief description of the threat" className="g-input w-full text-xs" />
              </div>
              <div className="flex gap-2 pt-1">
                <button type="submit" disabled={saving} className="g-btn g-btn-primary text-xs flex-1 justify-center">
                  {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : 'Add Fingerprint'}
                </button>
                <button type="button" onClick={() => setShowAdd(false)} className="g-btn g-btn-ghost text-xs">Cancel</button>
              </div>
            </form>
          </div>
        )}

        {/* Table */}
        {loading ? (
          <div className="flex justify-center py-12">
            <Loader2 className="h-5 w-5 animate-spin" style={{ color: 'var(--text-3)' }} />
          </div>
        ) : filtered.length === 0 ? (
          <div className="g-card p-12 text-center">
            <Fingerprint className="h-8 w-8 mx-auto mb-2" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No fingerprints found</p>
          </div>
        ) : (
          <div className="g-card overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['Hash', 'Threat', 'Severity', 'Source', 'Description', 'Scope', 'Added', ''].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 text-[10px] font-semibold uppercase tracking-wider"
                      style={{ color: 'var(--text-3)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map(e => (
                  <tr key={e.id} style={{ borderBottom: '1px solid var(--border)' }}
                    className="hover:bg-[rgba(255,255,255,0.02)] transition-colors">
                    <td className="px-4 py-3 mono text-[11px]" style={{ color: 'var(--text-2)' }}>{e.hash}</td>
                    <td className="px-4 py-3 font-medium" style={{ color: 'var(--text-1)' }}>{e.threat_name}</td>
                    <td className="px-4 py-3">
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase"
                        style={{ background: `${SEV_COLOR[e.severity] || 'var(--text-3)'}22`, color: SEV_COLOR[e.severity] || 'var(--text-3)' }}>
                        {e.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3" style={{ color: 'var(--text-3)' }}>{e.source}</td>
                    <td className="px-4 py-3 max-w-xs truncate" style={{ color: 'var(--text-2)' }}>{e.description || '—'}</td>
                    <td className="px-4 py-3">
                      {e.is_platform
                        ? <span className="flex items-center gap-1 text-[10px]" style={{ color: 'var(--text-3)' }}><Globe className="h-3 w-3" /> Platform</span>
                        : <span className="flex items-center gap-1 text-[10px]" style={{ color: 'var(--accent)' }}><Lock className="h-3 w-3" /> Tenant</span>}
                    </td>
                    <td className="px-4 py-3" style={{ color: 'var(--text-3)' }}>
                      {e.created_at ? timeAgo(e.created_at) : '—'}
                    </td>
                    <td className="px-4 py-3">
                      {!e.is_platform && (
                        <button onClick={() => remove(e)} className="p-1 rounded hover:bg-red-500/10 transition-colors"
                          style={{ color: 'var(--text-3)' }}>
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="g-card p-4 space-y-1.5">
          <p className="text-xs font-semibold" style={{ color: 'var(--text-2)' }}>How JA3 detection works</p>
          <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
            XCloak extracts JA3 hashes from CEF <code className="mono px-1 rounded" style={{ background: 'var(--glass-bg)' }}>ja3hash=</code>,
            Zeek <code className="mono px-1 rounded" style={{ background: 'var(--glass-bg)' }}>ja3=</code>, and
            Suricata JSON <code className="mono px-1 rounded" style={{ background: 'var(--glass-bg)' }}>{"ja3.hash"}</code> fields.
            Matches fire an alert with MITRE T1071.001. Platform hashes come from public threat intel (Cobalt Strike, TrickBot, Emotet, etc.)
            and cannot be deleted. Add tenant-specific hashes above.
          </p>
        </div>
      </div>
    </RootLayout>
  );
}
