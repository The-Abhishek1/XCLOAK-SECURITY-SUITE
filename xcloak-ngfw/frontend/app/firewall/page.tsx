'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { firewallAPI } from '@/lib/api';
import { FirewallRule } from '@/types';
import { Network, Plus, Trash2, Edit2, X, Search } from 'lucide-react';

const PROTOS  = ['tcp','udp','icmp','any'];
const ACTIONS = ['allow','deny'];
const empty   = { name: '', source_ip: '', destination_ip: '', protocol: 'tcp', port: 0, action: 'allow', enabled: true };

export default function FirewallPage() {
  const [rules, setRules]     = useState<FirewallRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch]   = useState('');
  const [showAdd, setShowAdd] = useState(false);
  const [showEdit, setShowEdit] = useState<FirewallRule | null>(null);
  const [form, setForm]       = useState({ ...empty });
  const [saving, setSaving]   = useState(false);
  const [toast, setToast]     = useState<string | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try { const r = await firewallAPI.getAll(); setRules(r.data || []); }
    finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const add = async () => {
    setSaving(true);
    try { await firewallAPI.create(form); load(); setShowAdd(false); setForm({ ...empty }); notify('Rule created'); }
    finally { setSaving(false); }
  };

  const update = async () => {
    if (!showEdit) return;
    setSaving(true);
    try { await firewallAPI.update(showEdit.id, form); load(); setShowEdit(null); notify('Rule updated'); }
    finally { setSaving(false); }
  };

  const del = async (id: number) => { await firewallAPI.delete(id); setRules(p => p.filter(r => r.id !== id)); notify('Rule deleted'); };

  const openEdit = (r: FirewallRule) => {
    setForm({ name: r.name, source_ip: r.source_ip, destination_ip: r.destination_ip, protocol: r.protocol, port: r.port, action: r.action, enabled: r.enabled });
    setShowEdit(r);
  };

  const filtered = rules.filter(r =>
    !search || r.name?.toLowerCase().includes(search.toLowerCase())
      || r.source_ip?.includes(search) || r.destination_ip?.includes(search)
  );

  const allowCount = rules.filter(r => r.action === 'allow').length;
  const denyCount  = rules.filter(r => r.action === 'deny').length;

  return (
    <RootLayout title="Firewall" subtitle={`${rules.length} rules · ${allowCount} allow · ${denyCount} deny`}
      onRefresh={() => load(true)} refreshing={refreshing}
      actions={
        <button onClick={() => { setForm({ ...empty }); setShowAdd(true); }} className="g-btn g-btn-primary text-xs">
          <Plus className="h-3.5 w-3.5" /> Add Rule
        </button>
      }>

      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)', minWidth: 200 }}>{toast}</div>}

      <div className="space-y-4">
        <div className="relative max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search rule, source, destination…" className="g-input pl-9" />
        </div>

        <div className="g-table">
          <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 130px 130px 70px 60px 70px 60px' }}>
            <span>Name</span><span>Source IP</span><span>Dest IP</span><span>Proto</span><span>Port</span><span>Action</span><span className="text-right">Actions</span>
          </div>

          {loading ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          ) : filtered.length === 0 ? (
            <div className="py-16 text-center">
              <Network className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>No firewall rules. Add one to control traffic.</p>
            </div>
          ) : filtered.map(r => (
            <div key={r.id} className="g-tr grid gap-3 items-center px-4"
              style={{ gridTemplateColumns: '1fr 130px 130px 70px 60px 70px 60px' }}>
              <span className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{r.name}</span>
              <span className="mono text-[11px]" style={{ color: 'var(--text-2)' }}>{r.source_ip}</span>
              <span className="mono text-[11px]" style={{ color: 'var(--text-2)' }}>{r.destination_ip}</span>
              <span className="mono text-[11px] uppercase" style={{ color: 'var(--text-2)' }}>{r.protocol}</span>
              <span className="mono text-[11px]" style={{ color: 'var(--text-2)' }}>{r.port}</span>
              <span className={r.action === 'deny' ? 's-critical' : 's-online'}>{r.action}</span>
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

      {/* Add/Edit modal */}
      {(showAdd || showEdit) && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && (setShowAdd(false), setShowEdit(null))}>
          <div className="g-modal" style={{ maxWidth: 540 }}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{showEdit ? 'Edit Firewall Rule' : 'New Firewall Rule'}</h2>
              <button onClick={() => { setShowAdd(false); setShowEdit(null); }} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>
            <div className="p-5 space-y-3">
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Name *</label>
                <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="Allow HTTPS" className="g-input" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Source IP</label>
                  <input value={form.source_ip} onChange={e => setForm(f => ({ ...f, source_ip: e.target.value }))} placeholder="10.0.0.0/24" className="g-input mono" />
                </div>
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Destination IP</label>
                  <input value={form.destination_ip} onChange={e => setForm(f => ({ ...f, destination_ip: e.target.value }))} placeholder="0.0.0.0/0" className="g-input mono" />
                </div>
              </div>
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Protocol</label>
                  <select value={form.protocol} onChange={e => setForm(f => ({ ...f, protocol: e.target.value }))} className="g-select">
                    {PROTOS.map(p => <option key={p}>{p}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Port</label>
                  <input type="number" value={form.port} onChange={e => setForm(f => ({ ...f, port: parseInt(e.target.value) || 0 }))} placeholder="443" className="g-input" />
                </div>
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Action</label>
                  <select value={form.action} onChange={e => setForm(f => ({ ...f, action: e.target.value }))} className="g-select">
                    {ACTIONS.map(a => <option key={a}>{a}</option>)}
                  </select>
                </div>
              </div>
            </div>
            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => { setShowAdd(false); setShowEdit(null); }} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={showEdit ? update : add} disabled={saving || !form.name.trim()} className="g-btn g-btn-primary flex-1 justify-center">
                {saving ? 'Saving…' : (showEdit ? 'Update' : 'Create Rule')}
              </button>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
