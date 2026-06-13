'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { quarantineAPI, agentsAPI } from '@/lib/api';
import { Agent } from '@/types';
import { formatDate, timeAgo } from '@/lib/utils';
import { Archive, Search, Plus, X, ShieldOff } from 'lucide-react';

interface QFile {
  id: number;
  agent_id: number;
  original_path: string;
  quarantine_path: string;
  file_name: string;
  reason: string;
  quarantined_at: string;
}

const empty = { agent_id: 0, original_path: '', quarantine_path: '', file_name: '', reason: 'manual quarantine' };

export default function QuarantinePage() {
  const [files, setFiles]     = useState<QFile[]>([]);
  const [agents, setAgents]   = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch]   = useState('');
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm]       = useState({ ...empty });
  const [saving, setSaving]   = useState(false);
  const [toast, setToast]     = useState<string | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const [qr, ar] = await Promise.allSettled([quarantineAPI.getAll(), agentsAPI.getAll()]);
      if (qr.status === 'fulfilled') setFiles(qr.value.data || []);
      if (ar.status === 'fulfilled') setAgents(ar.value.data || []);
    } finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const submit = async () => {
    if (!form.agent_id || !form.original_path.trim() || !form.file_name.trim()) return;
    setSaving(true);
    try {
      await quarantineAPI.quarantine(form);
      load();
      setShowAdd(false);
      setForm({ ...empty });
      notify('File quarantined');
    } finally { setSaving(false); }
  };

  // Auto-derive file_name and quarantine_path from original_path
  const updatePath = (path: string) => {
    const name = path.split('/').pop() || '';
    setForm(f => ({
      ...f,
      original_path: path,
      file_name: name,
      quarantine_path: name ? `/tmp/xcloak-quarantine/${name}` : '',
    }));
  };

  const filtered = files.filter(f =>
    !search ||
    f.file_name?.toLowerCase().includes(search.toLowerCase()) ||
    f.original_path?.toLowerCase().includes(search.toLowerCase()) ||
    String(f.agent_id).includes(search)
  );

  const agentName = (id: number) => agents.find(a => a.id === id)?.hostname || `Agent #${id}`;

  return (
    <RootLayout title="Quarantine" subtitle={`${files.length} quarantined files`}
      onRefresh={() => load(true)} refreshing={refreshing}
      actions={
        <button onClick={() => setShowAdd(true)} className="g-btn g-btn-primary text-xs">
          <Plus className="h-3.5 w-3.5" /> Quarantine File
        </button>
      }>

      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)', minWidth: 200 }}>{toast}</div>}

      <div className="space-y-4">
        <div className="relative max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search file, path, agent…" className="g-input pl-9" />
        </div>

        <div className="g-table">
          <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 1fr 100px 1fr 100px' }}>
            <span>File Name</span><span>Original Path</span><span>Agent</span><span>Reason</span><span>Quarantined</span>
          </div>

          {loading ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          ) : filtered.length === 0 ? (
            <div className="py-16 text-center">
              <Archive className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>
                {files.length === 0 ? 'No quarantined files.' : 'No matches.'}
              </p>
            </div>
          ) : filtered.map(f => (
            <div key={f.id} className="g-tr grid gap-3 items-center px-4"
              style={{ gridTemplateColumns: '1fr 1fr 100px 1fr 100px' }}>
              <div className="flex items-center gap-2 min-w-0">
                <ShieldOff className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--red)' }} />
                <span className="mono text-xs truncate" style={{ color: 'var(--text-1)' }}>{f.file_name}</span>
              </div>
              <span className="mono text-[11px] truncate" style={{ color: 'var(--text-2)' }}>{f.original_path}</span>
              <span className="text-xs truncate" style={{ color: 'var(--text-2)' }}>{agentName(f.agent_id)}</span>
              <span className="text-xs truncate" style={{ color: 'var(--text-3)' }}>{f.reason || '—'}</span>
              <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{timeAgo(f.quarantined_at)}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Add modal */}
      {showAdd && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setShowAdd(false)}>
          <div className="g-modal">
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Manually Quarantine File</h2>
              <button onClick={() => setShowAdd(false)} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>
            <div className="p-5 space-y-3">
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Agent *</label>
                <select value={form.agent_id} onChange={e => setForm(f => ({ ...f, agent_id: parseInt(e.target.value) }))} className="g-select">
                  <option value={0}>Select agent…</option>
                  {agents.map(a => <option key={a.id} value={a.id}>{a.hostname} (#{a.id})</option>)}
                </select>
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Original Path *</label>
                <input value={form.original_path} onChange={e => updatePath(e.target.value)}
                  placeholder="/tmp/malware.bin" className="g-input mono" />
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Quarantine Path</label>
                <input value={form.quarantine_path} onChange={e => setForm(f => ({ ...f, quarantine_path: e.target.value }))}
                  placeholder="/tmp/xcloak-quarantine/malware.bin" className="g-input mono" />
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>File Name</label>
                <input value={form.file_name} onChange={e => setForm(f => ({ ...f, file_name: e.target.value }))}
                  placeholder="malware.bin" className="g-input mono" />
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Reason</label>
                <input value={form.reason} onChange={e => setForm(f => ({ ...f, reason: e.target.value }))}
                  placeholder="manual quarantine" className="g-input" />
              </div>
            </div>
            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => setShowAdd(false)} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={submit} disabled={saving || !form.agent_id || !form.original_path.trim()}
                className="g-btn g-btn-primary flex-1 justify-center">
                {saving ? 'Recording…' : 'Quarantine'}
              </button>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
