'use client';

import { useState, useEffect, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { assetsAPI } from '@/lib/api';
import { Asset } from '@/types';
import { Plus, X, Edit2, Trash2, Server, Monitor, Network, Cloud, Cpu, HardDrive, Search } from 'lucide-react';

const CRIT_COLOR: Record<string, string> = {
  critical: 'var(--red)', high: '#fb923c', medium: '#fbbf24', low: 'var(--accent)',
};
const CRIT_BG: Record<string, string> = {
  critical: 'rgba(248,81,73,0.12)', high: 'rgba(251,146,60,0.12)',
  medium: 'rgba(251,191,36,0.10)', low: 'rgba(16,185,129,0.10)',
};
const CLASS_COLOR: Record<string, string> = {
  restricted: 'var(--red)', confidential: '#fb923c', internal: 'var(--accent)', public: 'var(--text-3)',
};
const ASSET_ICON: Record<string, React.ReactNode> = {
  server:     <Server className="h-4 w-4" />,
  workstation:<Monitor className="h-4 w-4" />,
  network:    <Network className="h-4 w-4" />,
  cloud:      <Cloud className="h-4 w-4" />,
  container:  <Cpu className="h-4 w-4" />,
  iot:        <HardDrive className="h-4 w-4" />,
};

const EMPTY: Partial<Asset> = {
  name: '', hostname: '', ip_address: '', asset_type: 'server',
  owner: '', business_unit: '', criticality: 'medium',
  data_classification: 'internal', environment: 'production',
  location: '', tags: [], notes: '',
};

function AssetModal({ asset, onClose, onSaved }: {
  asset?: Asset; onClose: () => void; onSaved: () => void;
}) {
  const [form, setForm] = useState<Partial<Asset>>(asset ?? EMPTY);
  const [tagInput, setTagInput] = useState('');
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!form.name?.trim()) return;
    setSaving(true);
    if (asset) {
      await assetsAPI.update(asset.id, form);
    } else {
      await assetsAPI.create(form);
    }
    setSaving(false);
    onSaved();
    onClose();
  };

  const addTag = () => {
    const t = tagInput.trim();
    if (!t) return;
    setForm(f => ({ ...f, tags: [...(f.tags || []), t] }));
    setTagInput('');
  };

  const removeTag = (tag: string) => setForm(f => ({ ...f, tags: (f.tags || []).filter(t => t !== tag) }));

  return (
    <div className="g-modal-backdrop" onClick={onClose}>
      <div className="g-modal" style={{ maxWidth: 580 }} onClick={e => e.stopPropagation()}>
        <div className="p-5" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
            {asset ? 'Edit Asset' : 'Register Asset'}
          </h2>
        </div>
        <div className="p-5 space-y-3 max-h-[70vh] overflow-y-auto">
          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2">
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Asset Name *</label>
              <input className="g-input w-full" value={form.name||''} onChange={e=>setForm(f=>({...f,name:e.target.value}))} placeholder="e.g. prod-db-01" />
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Hostname</label>
              <input className="g-input w-full" value={form.hostname||''} onChange={e=>setForm(f=>({...f,hostname:e.target.value}))} />
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>IP Address</label>
              <input className="g-input w-full" value={form.ip_address||''} onChange={e=>setForm(f=>({...f,ip_address:e.target.value}))} />
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Type</label>
              <select className="g-select w-full" value={form.asset_type} onChange={e=>setForm(f=>({...f,asset_type:e.target.value}))}>
                {['server','workstation','network','cloud','container','iot','other'].map(t=><option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Criticality</label>
              <select className="g-select w-full" value={form.criticality} onChange={e=>setForm(f=>({...f,criticality:e.target.value as any}))}>
                {['critical','high','medium','low'].map(c=><option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Data Classification</label>
              <select className="g-select w-full" value={form.data_classification} onChange={e=>setForm(f=>({...f,data_classification:e.target.value as any}))}>
                {['public','internal','confidential','restricted'].map(c=><option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Environment</label>
              <select className="g-select w-full" value={form.environment} onChange={e=>setForm(f=>({...f,environment:e.target.value as any}))}>
                {['production','staging','development','test'].map(e=><option key={e} value={e}>{e}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Owner</label>
              <input className="g-input w-full" value={form.owner||''} onChange={e=>setForm(f=>({...f,owner:e.target.value}))} placeholder="e.g. alice@company.com" />
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Business Unit</label>
              <input className="g-input w-full" value={form.business_unit||''} onChange={e=>setForm(f=>({...f,business_unit:e.target.value}))} placeholder="e.g. Finance" />
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Location</label>
              <input className="g-input w-full" value={form.location||''} onChange={e=>setForm(f=>({...f,location:e.target.value}))} placeholder="e.g. us-east-1 / Rack B4" />
            </div>
          </div>

          {/* Tags */}
          <div>
            <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Tags</label>
            <div className="flex gap-1 flex-wrap mb-2">
              {(form.tags||[]).map(t => (
                <span key={t} className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded"
                  style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                  {t}<button onClick={() => removeTag(t)}><X className="h-2.5 w-2.5" /></button>
                </span>
              ))}
            </div>
            <div className="flex gap-2">
              <input className="g-input flex-1 text-xs" value={tagInput}
                onChange={e => setTagInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && addTag()}
                placeholder="Add tag…" />
              <button onClick={addTag} className="g-btn g-btn-ghost text-xs px-3">Add</button>
            </div>
          </div>

          <div>
            <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Notes</label>
            <textarea className="g-input w-full min-h-[64px]" value={form.notes||''}
              onChange={e=>setForm(f=>({...f,notes:e.target.value}))} placeholder="Any additional notes…" />
          </div>
        </div>
        <div className="flex gap-3 px-5 pb-5">
          <button onClick={onClose} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
          <button onClick={save} disabled={!form.name?.trim() || saving} className="g-btn g-btn-primary flex-1 justify-center">
            {saving ? 'Saving…' : asset ? 'Save Changes' : 'Register Asset'}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [critFilter, setCritFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [editAsset, setEditAsset] = useState<Asset | 'new' | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const r = await assetsAPI.getAll();
    setAssets(r.data || []);
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const deleteAsset = async (id: number) => {
    if (!confirm('Delete this asset?')) return;
    await assetsAPI.delete(id);
    load();
  };

  const filtered = assets.filter(a => {
    if (critFilter && a.criticality !== critFilter) return false;
    if (typeFilter && a.asset_type !== typeFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      if (!`${a.name} ${a.hostname} ${a.ip_address} ${a.owner} ${a.business_unit}`.toLowerCase().includes(q)) return false;
    }
    return true;
  });

  const criticalCount = assets.filter(a => a.criticality === 'critical').length;
  const prodCount = assets.filter(a => a.environment === 'production').length;
  const restrictedCount = assets.filter(a => a.data_classification === 'restricted' || a.data_classification === 'confidential').length;

  return (
    <RootLayout title="Asset Management" subtitle="CMDB · Criticality · Data Classification"
      actions={
        <button onClick={() => setEditAsset('new')} className="g-btn g-btn-primary flex items-center gap-1.5 text-xs">
          <Plus className="h-3.5 w-3.5" /> Register Asset
        </button>
      }>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
        {[
          { label: 'Total Assets', val: assets.length, sub: 'registered' },
          { label: 'Critical', val: criticalCount, sub: 'highest tier', warn: criticalCount > 0 },
          { label: 'Production', val: prodCount, sub: 'live environment' },
          { label: 'Sensitive Data', val: restrictedCount, sub: 'confidential/restricted', warn: restrictedCount > 0 },
        ].map(s => (
          <div key={s.label} className="g-card p-4">
            <p className="text-xl font-bold" style={{ color: s.warn ? 'var(--red)' : 'var(--text-1)' }}>{s.val}</p>
            <p className="text-xs font-medium" style={{ color: 'var(--text-2)' }}>{s.label}</p>
            <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{s.sub}</p>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="g-card p-3 mb-4 flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[180px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
          <input className="g-input pl-9 text-xs w-full" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search assets…" />
        </div>
        <select className="g-select text-xs py-1" value={critFilter} onChange={e => setCritFilter(e.target.value)}>
          <option value="">All criticalities</option>
          {['critical','high','medium','low'].map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <select className="g-select text-xs py-1" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
          <option value="">All types</option>
          {['server','workstation','network','cloud','container','iot','other'].map(t => <option key={t} value={t}>{t}</option>)}
        </select>
      </div>

      {/* Asset cards */}
      {loading ? (
        <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
      ) : filtered.length === 0 ? (
        <div className="g-card py-16 text-center">
          <Server className="mx-auto h-10 w-10 mb-3 opacity-20" style={{ color: 'var(--text-3)' }} />
          <p className="text-sm" style={{ color: 'var(--text-2)' }}>
            {assets.length === 0 ? 'No assets registered yet. Assets are auto-created from agent heartbeats.' : 'No assets match filters.'}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
          {filtered.map(a => (
            <div key={a.id} className="g-card p-4 space-y-3">
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2 min-w-0">
                  <div className="shrink-0 h-8 w-8 rounded-lg flex items-center justify-center"
                    style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)', color: 'var(--accent)' }}>
                    {ASSET_ICON[a.asset_type] || <Server className="h-4 w-4" />}
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm font-semibold truncate" style={{ color: 'var(--text-1)' }}>{a.name}</p>
                    <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>
                      {a.hostname || a.ip_address || 'no hostname'}
                      {a.agent_id && <span style={{ color: 'var(--accent)' }}> · agent #{a.agent_id}</span>}
                    </p>
                  </div>
                </div>
                <div className="flex gap-1 shrink-0">
                  <button onClick={() => setEditAsset(a)}
                    className="p-1.5 rounded-lg transition-colors"
                    style={{ color: 'var(--text-3)' }}
                    onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--accent)'}
                    onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                    <Edit2 className="h-3.5 w-3.5" />
                  </button>
                  <button onClick={() => deleteAsset(a.id)}
                    className="p-1.5 rounded-lg transition-colors"
                    style={{ color: 'var(--text-3)' }}
                    onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--red)'}
                    onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>

              <div className="flex flex-wrap gap-1.5">
                <span className="text-[10px] px-2 py-0.5 rounded font-bold"
                  style={{ background: CRIT_BG[a.criticality], color: CRIT_COLOR[a.criticality] }}>
                  {a.criticality}
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded"
                  style={{ background: 'var(--glass-bg-2)', color: CLASS_COLOR[a.data_classification] || 'var(--text-3)', border: '1px solid var(--border)' }}>
                  {a.data_classification}
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded"
                  style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)', border: '1px solid var(--border)' }}>
                  {a.environment}
                </span>
                {a.agent_status && (
                  <span className="text-[10px] px-2 py-0.5 rounded"
                    style={{
                      background: a.agent_status === 'online' ? 'rgba(16,185,129,0.1)' : 'rgba(100,100,100,0.1)',
                      color: a.agent_status === 'online' ? 'var(--accent)' : 'var(--text-3)',
                      border: '1px solid var(--border)',
                    }}>
                    {a.agent_status}
                  </span>
                )}
              </div>

              <div className="grid grid-cols-2 gap-1.5 text-[11px]">
                {a.owner && (
                  <div className="flex items-center gap-1" style={{ color: 'var(--text-2)' }}>
                    <span style={{ color: 'var(--text-3)' }}>owner</span> {a.owner}
                  </div>
                )}
                {a.business_unit && (
                  <div className="flex items-center gap-1" style={{ color: 'var(--text-2)' }}>
                    <span style={{ color: 'var(--text-3)' }}>bu</span> {a.business_unit}
                  </div>
                )}
                {a.location && (
                  <div className="col-span-2 flex items-center gap-1" style={{ color: 'var(--text-2)' }}>
                    <span style={{ color: 'var(--text-3)' }}>location</span> {a.location}
                  </div>
                )}
                {a.risk_score !== undefined && a.risk_score > 0 && (
                  <div className="flex items-center gap-1" style={{ color: 'var(--text-2)' }}>
                    <span style={{ color: 'var(--text-3)' }}>risk</span>
                    <span style={{ color: a.risk_score > 70 ? 'var(--red)' : a.risk_score > 40 ? '#fb923c' : 'var(--accent)' }}>
                      {a.risk_score}
                    </span>
                  </div>
                )}
              </div>

              {(a.tags || []).length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {a.tags.map(t => (
                    <span key={t} className="text-[10px] px-1.5 py-0.5 rounded"
                      style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {editAsset && (
        <AssetModal
          asset={editAsset === 'new' ? undefined : editAsset}
          onClose={() => setEditAsset(null)}
          onSaved={load}
        />
      )}
    </RootLayout>
  );
}
