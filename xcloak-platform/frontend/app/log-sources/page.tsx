'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { logSourcesAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import {
  PlugZap, Plus, Trash2, ToggleLeft, ToggleRight, Copy, Check,
  Loader2, RefreshCw, Server, Globe, Eye, EyeOff, Wifi,
} from 'lucide-react';

interface LogSource {
  id: number;
  name: string;
  source_type: 'syslog' | 'http';
  ip_address?: string;
  api_key_hint?: string;
  format: string;
  device_type?: string;
  enabled: boolean;
  last_event?: string;
  event_count: number;
  created_at: string;
  api_key?: string; // only present immediately after creation
}

const FORMATS = ['auto', 'syslog', 'cef', 'leef', 'json', 'ndjson', 'text'];
const DEVICE_TYPES = ['firewall', 'router', 'switch', 'ids', 'proxy', 'endpoint', 'cloud', 'other'];

const emptyForm = {
  name: '',
  source_type: 'syslog' as 'syslog' | 'http',
  ip_address: '',
  format: 'auto',
  device_type: 'firewall',
};

export default function LogSourcesPage() {
  const [sources, setSources]     = useState<LogSource[]>([]);
  const [loading, setLoading]     = useState(true);
  const [showAdd, setShowAdd]     = useState(false);
  const [form, setForm]           = useState({ ...emptyForm });
  const [saving, setSaving]       = useState(false);
  const [newKey, setNewKey]       = useState<{ id: number; key: string } | null>(null);
  const [showKey, setShowKey]     = useState(false);
  const [copied, setCopied]       = useState(false);
  const [toast, setToast]         = useState<string | null>(null);

  const notify = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3000);
  };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await logSourcesAPI.getAll();
      setSources(Array.isArray(r.data) ? r.data : []);
    } catch { setSources([]); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      const r = await logSourcesAPI.create(form);
      const src: LogSource = r.data;
      if (src.api_key) {
        setNewKey({ id: src.id, key: src.api_key });
        setShowKey(false);
        setCopied(false);
      }
      setShowAdd(false);
      setForm({ ...emptyForm });
      load();
      notify('Log source created');
    } catch (err: any) {
      notify(err?.response?.data?.error || 'Failed to create log source');
    } finally { setSaving(false); }
  };

  const toggle = async (src: LogSource) => {
    try {
      await logSourcesAPI.update(src.id, {
        name: src.name,
        device_type: src.device_type || '',
        enabled: !src.enabled,
      });
      setSources(p => p.map(s => s.id === src.id ? { ...s, enabled: !s.enabled } : s));
    } catch { notify('Update failed'); }
  };

  const remove = async (id: number) => {
    if (!confirm('Delete this log source? It will stop receiving events.')) return;
    try {
      await logSourcesAPI.remove(id);
      setSources(p => p.filter(s => s.id !== id));
      notify('Log source deleted');
    } catch { notify('Delete failed'); }
  };

  const copy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <RootLayout title="Log Sources" subtitle="Agentless syslog and HTTP ingest — route firewall, network and cloud logs without deploying an agent">
      {/* Toast */}
      {toast && (
        <div className="fixed bottom-4 right-4 z-50 px-4 py-2 rounded-lg text-sm font-medium shadow-lg"
          style={{ background: 'var(--accent)', color: '#fff' }}>
          {toast}
        </div>
      )}

      {/* API key reveal modal */}
      {newKey && (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.7)' }}>
          <div className="g-card p-6 w-full max-w-md space-y-4">
            <div className="flex items-center gap-2">
              <PlugZap className="h-5 w-5" style={{ color: 'var(--accent)' }} />
              <p className="font-semibold" style={{ color: 'var(--text-1)' }}>Save your API key</p>
            </div>
            <p className="text-xs" style={{ color: 'var(--text-3)' }}>
              This key is shown <strong>once</strong>. Copy it now — it cannot be recovered.
            </p>
            <div className="flex items-center gap-2 rounded-lg px-3 py-2" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
              <code className="flex-1 text-xs mono break-all" style={{ color: 'var(--text-1)' }}>
                {showKey ? newKey.key : '•'.repeat(48)}
              </code>
              <button onClick={() => setShowKey(v => !v)} style={{ color: 'var(--text-3)' }}>
                {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
              <button onClick={() => copy(newKey.key)} style={{ color: copied ? 'var(--accent)' : 'var(--text-3)' }}>
                {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
              </button>
            </div>
            <div className="rounded-lg p-3 text-xs space-y-1" style={{ background: 'rgba(var(--accent-rgb),0.08)', border: '1px solid rgba(var(--accent-rgb),0.2)' }}>
              <p style={{ color: 'var(--text-2)' }}>Send logs via HTTP POST:</p>
              <code className="block mono text-[11px]" style={{ color: 'var(--text-1)' }}>
                POST /api/ingest<br />
                X-Api-Key: {'<key>'}<br />
                Content-Type: application/json
              </code>
            </div>
            <button onClick={() => setNewKey(null)} className="g-btn g-btn-primary w-full justify-center text-sm">
              I&apos;ve saved the key
            </button>
          </div>
        </div>
      )}

      <div className="space-y-4">
        {/* Header row */}
        <div className="flex items-center justify-between">
          <p className="text-xs" style={{ color: 'var(--text-3)' }}>{sources.length} source{sources.length !== 1 ? 's' : ''} configured</p>
          <div className="flex gap-2">
            <button onClick={load} className="g-btn g-btn-ghost text-xs">
              <RefreshCw className="h-3.5 w-3.5" />
            </button>
            <button onClick={() => setShowAdd(true)} className="g-btn g-btn-primary text-xs">
              <Plus className="h-3.5 w-3.5" /> Add Source
            </button>
          </div>
        </div>

        {/* Add form */}
        {showAdd && (
          <div className="g-card p-5 space-y-4">
            <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>New Log Source</p>
            <form onSubmit={create} className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Name</label>
                  <input required value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                    placeholder="e.g. Palo Alto NGFW" className="g-input w-full text-xs" />
                </div>
                <div>
                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Type</label>
                  <select value={form.source_type} onChange={e => setForm(f => ({ ...f, source_type: e.target.value as any }))}
                    className="g-input w-full text-xs">
                    <option value="syslog">Syslog (UDP/TCP)</option>
                    <option value="http">HTTP (REST API)</option>
                  </select>
                </div>
              </div>

              {form.source_type === 'syslog' && (
                <div>
                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Source IP Address</label>
                  <input value={form.ip_address} onChange={e => setForm(f => ({ ...f, ip_address: e.target.value }))}
                    placeholder="10.0.0.1" className="g-input w-full text-xs mono" />
                  <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                    Syslog packets from this IP will be routed to this source. Leave blank to match any.
                  </p>
                </div>
              )}

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Log Format</label>
                  <select value={form.format} onChange={e => setForm(f => ({ ...f, format: e.target.value }))}
                    className="g-input w-full text-xs">
                    {FORMATS.map(f => <option key={f} value={f}>{f}</option>)}
                  </select>
                </div>
                <div>
                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Device Type</label>
                  <select value={form.device_type} onChange={e => setForm(f => ({ ...f, device_type: e.target.value }))}
                    className="g-input w-full text-xs">
                    {DEVICE_TYPES.map(d => <option key={d} value={d}>{d}</option>)}
                  </select>
                </div>
              </div>

              <div className="flex gap-2 pt-1">
                <button type="submit" disabled={saving} className="g-btn g-btn-primary text-xs flex-1 justify-center">
                  {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : 'Create'}
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
        ) : sources.length === 0 ? (
          <div className="g-card p-12 text-center space-y-2">
            <PlugZap className="h-8 w-8 mx-auto" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No log sources yet</p>
            <p className="text-xs" style={{ color: 'var(--text-3)' }}>Add a syslog or HTTP source to start receiving agentless logs</p>
          </div>
        ) : (
          <div className="g-card overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['Name', 'Type', 'Address / Key', 'Format', 'Device', 'Events', 'Last Event', 'Status', ''].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 text-[10px] font-semibold uppercase tracking-wider"
                      style={{ color: 'var(--text-3)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {sources.map(src => (
                  <tr key={src.id} style={{ borderBottom: '1px solid var(--border)' }}
                    className="hover:bg-[rgba(255,255,255,0.02)] transition-colors">
                    <td className="px-4 py-3 font-medium" style={{ color: 'var(--text-1)' }}>{src.name}</td>
                    <td className="px-4 py-3">
                      <span className="flex items-center gap-1.5" style={{ color: 'var(--text-2)' }}>
                        {src.source_type === 'syslog'
                          ? <><Server className="h-3 w-3" /> Syslog</>
                          : <><Globe className="h-3 w-3" /> HTTP</>}
                      </span>
                    </td>
                    <td className="px-4 py-3 mono" style={{ color: 'var(--text-3)' }}>
                      {src.source_type === 'syslog'
                        ? (src.ip_address || <span className="italic">any</span>)
                        : (src.api_key_hint ? `…${src.api_key_hint}` : '—')}
                    </td>
                    <td className="px-4 py-3" style={{ color: 'var(--text-2)' }}>{src.format}</td>
                    <td className="px-4 py-3" style={{ color: 'var(--text-2)' }}>{src.device_type || '—'}</td>
                    <td className="px-4 py-3 mono" style={{ color: 'var(--text-2)' }}>
                      {src.event_count.toLocaleString()}
                    </td>
                    <td className="px-4 py-3" style={{ color: 'var(--text-3)' }}>
                      {src.last_event ? timeAgo(src.last_event) : '—'}
                    </td>
                    <td className="px-4 py-3">
                      <button onClick={() => toggle(src)}>
                        {src.enabled
                          ? <span className="flex items-center gap-1" style={{ color: '#3fb950' }}><Wifi className="h-3.5 w-3.5" /> Active</span>
                          : <span className="flex items-center gap-1" style={{ color: 'var(--text-3)' }}><Wifi className="h-3.5 w-3.5" /> Paused</span>}
                      </button>
                    </td>
                    <td className="px-4 py-3">
                      <button onClick={() => remove(src.id)} className="p-1 rounded hover:bg-red-500/10 transition-colors"
                        style={{ color: 'var(--text-3)' }}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Syslog setup hint */}
        <div className="g-card p-4 space-y-2">
          <p className="text-xs font-semibold" style={{ color: 'var(--text-2)' }}>Syslog Setup</p>
          <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
            Point your device to forward syslog to <code className="mono px-1 rounded" style={{ background: 'var(--glass-bg)' }}>{'<xcloak-host>:514'}</code> (UDP or TCP).
            Supports RFC 3164, RFC 5424, CEF, LEEF, and JSON formats.
          </p>
          <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
            For HTTP ingest, <code className="mono px-1 rounded" style={{ background: 'var(--glass-bg)' }}>POST /api/ingest</code> with{' '}
            <code className="mono px-1 rounded" style={{ background: 'var(--glass-bg)' }}>X-Api-Key: {'<key>'}</code> header.
            Body can be JSON array, NDJSON, or plain text lines (up to 10 MB / 5,000 events per request).
          </p>
        </div>
      </div>
    </RootLayout>
  );
}
