'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { iocsAPI, sigmaAPI, threatFeedsAPI } from '@/lib/api';
import api from '@/lib/api';
import { IOC, SigmaRule, ThreatFeed } from '@/types';
import { sevClass, timeAgo } from '@/lib/utils';
import {
  Shield, Plus, Trash2, ToggleLeft, ToggleRight, X, Edit2,
  Upload, Rss, FileCode, Search, ChevronDown, ChevronUp, RefreshCw,
} from 'lucide-react';

const TABS = [
  { id: 'iocs',   label: 'IOCs',         icon: Shield },
  { id: 'sigma',  label: 'Sigma Rules',  icon: FileCode },
  { id: 'feeds',  label: 'Threat Feeds', icon: Rss },
] as const;
type Tab = typeof TABS[number]['id'];

const IOC_TYPES  = ['ip', 'sha256', 'md5', 'domain', 'url'];
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const emptyIOC   = { indicator: '', type: 'ip', severity: 'high', description: '', enabled: true };
const emptyFeed  = { name: '', source: '', enabled: true };
const emptySigma = { title: '', severity: 'high', mitre_tactic: '', mitre_technique: '', mitre_name: '', keywords: '', enabled: true };

export default function ThreatIntelPage() {
  const [tab, setTab]       = useState<Tab>('iocs');
  const [iocs, setIocs]     = useState<IOC[]>([]);
  const [sigma, setSigma]   = useState<SigmaRule[]>([]);
  const [feeds, setFeeds]   = useState<ThreatFeed[]>([]);
  const [loading, setLoading] = useState(true);
  const [typeFilter, setTypeFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [toast, setToast]   = useState<string | null>(null);

  // Modals
  const [showAddIOC, setShowAddIOC] = useState(false);
  const [showEditIOC, setShowEditIOC] = useState<IOC | null>(null);
  const [showBulk, setShowBulk] = useState(false);
  const [showAddSigma, setShowAddSigma] = useState(false);
  const [showEditSigma, setShowEditSigma] = useState<SigmaRule | null>(null);
  const [showAddFeed, setShowAddFeed] = useState(false);
  const [iocForm, setIocForm] = useState({ ...emptyIOC });
  const [sigmaForm, setSigmaForm] = useState({ ...emptySigma });
  const [feedForm, setFeedForm] = useState({ ...emptyFeed });
  const [bulkForm, setBulkForm] = useState({ type: 'ip', severity: 'high', description: '', indicators: '' });
  const [saving, setSaving] = useState(false);
  const [syncingId, setSyncingId] = useState<number | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const syncFeed = async (feed: ThreatFeed) => {
    setSyncingId(feed.id);
    try {
      const res = await threatFeedsAPI.sync(feed.id);
      notify(`Synced "${feed.name}" — ${res.data?.count ?? 0} indicators processed`);
      await load();
    } catch {
      notify(`Failed to sync "${feed.name}"`);
    } finally {
      setSyncingId(null);
    }
  };

  const load = useCallback(async () => {
    const [ir, sr, fr] = await Promise.allSettled([iocsAPI.getAll(), sigmaAPI.getAll(), threatFeedsAPI.getAll()]);
    if (ir.status === 'fulfilled') setIocs(ir.value.data || []);
    if (sr.status === 'fulfilled') setSigma(sr.value.data || []);
    if (fr.status === 'fulfilled') setFeeds(fr.value.data || []);
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  // IOC CRUD
  const addIOC = async () => {
    if (!iocForm.indicator.trim()) return;
    setSaving(true);
    try { await iocsAPI.create(iocForm); load(); setShowAddIOC(false); setIocForm({ ...emptyIOC }); notify('IOC added'); }
    finally { setSaving(false); }
  };

  const updateIOC = async () => {
    if (!showEditIOC) return;
    setSaving(true);
    try {
      await iocsAPI.update(showEditIOC.id, iocForm);
      load(); setShowEditIOC(null); notify('IOC updated');
    } finally { setSaving(false); }
  };

  const deleteIOC   = async (id: number) => { await iocsAPI.delete(id); setIocs(p => p.filter(i => i.id !== id)); notify('IOC deleted'); };
  const toggleIOC   = async (ioc: IOC)   => { ioc.enabled ? await iocsAPI.disable(ioc.id) : await iocsAPI.enable(ioc.id); setIocs(p => p.map(i => i.id === ioc.id ? { ...i, enabled: !i.enabled } : i)); };

  const openEditIOC = (ioc: IOC) => {
    setIocForm({ indicator: ioc.indicator, type: ioc.type, severity: ioc.severity, description: ioc.description, enabled: ioc.enabled });
    setShowEditIOC(ioc);
  };

  const bulkImport = async () => {
    setSaving(true);
    try {
      const r = await api.post('/iocs/bulk', {
        indicators:  bulkForm.indicators,
        severity:    bulkForm.severity,
        description: bulkForm.description,
        source:      'manual',
      });
      const { imported, dupes, skipped } = r.data;
      notify(`Imported ${imported} IOCs (${dupes} already existed, ${skipped} skipped)`);
      load();
      setShowBulk(false);
      setBulkForm({ type: 'ip', severity: 'high', description: '', indicators: '' });
    } catch {
      notify('Bulk import failed');
    } finally {
      setSaving(false);
    }
  };

  // Sigma CRUD
  const addSigma = async () => {
    if (!sigmaForm.title.trim()) return;
    setSaving(true);
    try {
      const keywords = sigmaForm.keywords.split(',').map(s => s.trim()).filter(Boolean);
      await sigmaAPI.create({ ...sigmaForm, keywords });
      load(); setShowAddSigma(false); setSigmaForm({ ...emptySigma }); notify('Sigma rule created');
    } finally { setSaving(false); }
  };

  const updateSigma = async () => {
    if (!showEditSigma) return;
    setSaving(true);
    try {
      const keywords = sigmaForm.keywords.split(',').map(s => s.trim()).filter(Boolean);
      await sigmaAPI.update(showEditSigma.id, { ...sigmaForm, keywords });
      load(); setShowEditSigma(null); notify('Rule updated');
    } finally { setSaving(false); }
  };

  const deleteSigma  = async (id: number) => { await sigmaAPI.delete(id); setSigma(p => p.filter(r => r.id !== id)); notify('Rule deleted'); };
  const toggleSigma  = async (r: SigmaRule) => { r.enabled ? await sigmaAPI.disable(r.id) : await sigmaAPI.enable(r.id); setSigma(p => p.map(x => x.id === r.id ? { ...x, enabled: !x.enabled } : x)); };

  const openEditSigma = (r: SigmaRule) => {
    setSigmaForm({ title: r.title, severity: r.severity, mitre_tactic: r.mitre_tactic, mitre_technique: r.mitre_technique, mitre_name: r.mitre_name, keywords: (r.keywords || []).join(', '), enabled: r.enabled });
    setShowEditSigma(r);
  };

  // Feed CRUD
  const addFeed = async () => {
    if (!feedForm.name.trim()) return;
    setSaving(true);
    try { await threatFeedsAPI.create(feedForm); load(); setShowAddFeed(false); setFeedForm({ ...emptyFeed }); notify('Feed added'); }
    finally { setSaving(false); }
  };

  // Filter
  const filteredIOCs = iocs.filter(i => {
    const mf = typeFilter === 'all' || i.type === typeFilter;
    const ms = !search || i.indicator.toLowerCase().includes(search.toLowerCase()) || i.description.toLowerCase().includes(search.toLowerCase());
    return mf && ms;
  });

  const iocsCount = IOC_TYPES.reduce((a, t) => { a[t] = iocs.filter(i => i.type === t).length; return a; }, {} as Record<string, number>);

  return (
    <RootLayout title="Threat Intelligence"
      subtitle={`${iocs.filter(i => i.enabled).length} active IOCs · ${sigma.length} sigma rules`}
      onRefresh={load}>

      {toast && <Toast msg={toast} />}

      <div className="space-y-4">
        {/* Tab bar */}
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex gap-1 p-1 rounded-xl" style={{ background: 'var(--glass-bg)', backdropFilter: 'var(--blur-sm)', border: '1px solid var(--border)' }}>
            {TABS.map(t => {
              const Icon = t.icon;
              return (
                <button key={t.id} onClick={() => setTab(t.id)}
                  className="flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-medium transition-all"
                  style={{
                    background: tab === t.id ? 'var(--accent-glow)' : 'transparent',
                    color:      tab === t.id ? 'var(--accent)' : 'var(--text-2)',
                    border:     tab === t.id ? '1px solid var(--accent-border)' : '1px solid transparent',
                  }}>
                  <Icon className="h-3.5 w-3.5" /> {t.label}
                </button>
              );
            })}
          </div>

          {/* Tab actions */}
          {tab === 'iocs' && (
            <div className="flex gap-2">
              <button onClick={() => setShowBulk(true)} className="g-btn g-btn-ghost text-xs">
                <Upload className="h-3.5 w-3.5" /> Bulk Import
              </button>
              <button onClick={() => { setIocForm({ ...emptyIOC }); setShowAddIOC(true); }} className="g-btn g-btn-primary text-xs">
                <Plus className="h-3.5 w-3.5" /> Add IOC
              </button>
            </div>
          )}
          {tab === 'sigma' && (
            <button onClick={() => { setSigmaForm({ ...emptySigma }); setShowAddSigma(true); }} className="g-btn g-btn-primary text-xs">
              <Plus className="h-3.5 w-3.5" /> New Rule
            </button>
          )}
          {tab === 'feeds' && (
            <button onClick={() => setShowAddFeed(true)} className="g-btn g-btn-primary text-xs">
              <Plus className="h-3.5 w-3.5" /> Add Feed
            </button>
          )}
        </div>

        {/* ── IOCs TAB ── */}
        {tab === 'iocs' && (
          <>
            <div className="flex flex-wrap gap-2 items-center">
              {/* Type filter pills */}
              {['all', ...IOC_TYPES].map(t => (
                <button key={t} onClick={() => setTypeFilter(t)}
                  className="g-btn text-[11px] uppercase"
                  style={{
                    background: typeFilter === t ? 'var(--accent-glow)' : 'var(--glass-bg)',
                    color:      typeFilter === t ? 'var(--accent)' : 'var(--text-2)',
                    border:     `1px solid ${typeFilter === t ? 'var(--accent-border)' : 'var(--border)'}`,
                    backdropFilter: 'var(--blur-sm)',
                    padding: '4px 10px',
                  }}>
                  {t === 'all' ? `All (${iocs.length})` : `${t} (${iocsCount[t] || 0})`}
                </button>
              ))}
              <div className="relative ml-auto">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
                <input value={search} onChange={e => setSearch(e.target.value)}
                  placeholder="Search indicator, description…" className="g-input pl-9" style={{ width: 250, height: 34 }} />
              </div>
            </div>

            <div className="g-table">
              <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 70px 80px 1fr 80px 80px 60px' }}>
                <span>Indicator</span><span>Type</span><span>Severity</span><span>Description</span>
                <span>Added</span><span>Status</span><span className="text-right">Actions</span>
              </div>
              {loading ? <LoadingRow /> : filteredIOCs.length === 0 ? <EmptyRow icon={<Shield />} msg="No IOCs. Add one to start matching threats." /> :
                filteredIOCs.map(ioc => (
                  <div key={ioc.id} className={`g-tr grid gap-3 items-center px-4 ${!ioc.enabled ? 'opacity-40' : ''}`}
                    style={{ gridTemplateColumns: '1fr 70px 80px 1fr 80px 80px 60px' }}>
                    <span className="mono text-xs truncate" style={{ color: 'var(--text-1)' }}>{ioc.indicator}</span>
                    <span className="mono text-[10px] rounded px-1.5 py-0.5 uppercase inline-block w-fit"
                      style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>{ioc.type}</span>
                    <span className={sevClass(ioc.severity)}>{ioc.severity}</span>
                    <span className="text-xs truncate" style={{ color: 'var(--text-2)' }}>{ioc.description}</span>
                    <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{timeAgo(ioc.created_at)}</span>
                    <button onClick={() => toggleIOC(ioc)} className="flex items-center gap-1 text-[10px]"
                      style={{ color: ioc.enabled ? 'var(--green)' : 'var(--text-3)' }}>
                      {ioc.enabled ? <ToggleRight className="h-4 w-4" /> : <ToggleLeft className="h-4 w-4" />}
                      {ioc.enabled ? 'On' : 'Off'}
                    </button>
                    <div className="flex items-center justify-end gap-1">
                      <ActionBtn icon={<Edit2 className="h-3.5 w-3.5" />} onClick={() => openEditIOC(ioc)} />
                      <ActionBtn icon={<Trash2 className="h-3.5 w-3.5" />} onClick={() => deleteIOC(ioc.id)} danger />
                    </div>
                  </div>
                ))
              }
            </div>
          </>
        )}

        {/* ── SIGMA TAB ── */}
        {tab === 'sigma' && (
          <div className="g-table">
            <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 100px 80px 80px 80px 60px' }}>
              <span>Title</span><span>MITRE</span><span>Severity</span><span>Keywords</span><span>Status</span><span className="text-right">Actions</span>
            </div>
            {loading ? <LoadingRow /> : sigma.length === 0 ? <EmptyRow icon={<FileCode />} msg="No Sigma rules. Create one." /> :
              sigma.map(r => (
                <div key={r.id} className={`g-tr grid gap-3 items-center px-4 ${!r.enabled ? 'opacity-40' : ''}`}
                  style={{ gridTemplateColumns: '1fr 100px 80px 80px 80px 60px' }}>
                  <div>
                    <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{r.title}</p>
                    <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{r.mitre_name}</p>
                  </div>
                  <span className="mono text-[10px] rounded px-1.5 py-0.5"
                    style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                    {r.mitre_technique || '—'}
                  </span>
                  <span className={sevClass(r.severity)}>{r.severity}</span>
                  <span className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>
                    {(r.keywords || []).slice(0, 2).join(', ')}{(r.keywords || []).length > 2 ? '…' : ''}
                  </span>
                  <button onClick={() => toggleSigma(r)} className="flex items-center gap-1 text-[10px]"
                    style={{ color: r.enabled ? 'var(--green)' : 'var(--text-3)' }}>
                    {r.enabled ? <ToggleRight className="h-4 w-4" /> : <ToggleLeft className="h-4 w-4" />}
                    {r.enabled ? 'On' : 'Off'}
                  </button>
                  <div className="flex items-center justify-end gap-1">
                    <ActionBtn icon={<Edit2 className="h-3.5 w-3.5" />} onClick={() => openEditSigma(r)} />
                    <ActionBtn icon={<Trash2 className="h-3.5 w-3.5" />} onClick={() => deleteSigma(r.id)} danger />
                  </div>
                </div>
              ))
            }
          </div>
        )}

        {/* ── FEEDS TAB ── */}
        {tab === 'feeds' && (
          <div className="g-table">
            <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 1fr 80px 100px 100px' }}>
              <span>Name</span><span>Source</span><span>Status</span><span>Last Sync</span><span className="text-right">Actions</span>
            </div>
            {feeds.length === 0 ? <EmptyRow icon={<Rss />} msg="No threat feeds configured." /> :
              feeds.map((f, i) => (
                <div key={i} className="g-tr grid gap-3 items-center px-4"
                  style={{ gridTemplateColumns: '1fr 1fr 80px 100px 100px' }}>
                  <span className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{f.name}</span>
                  <span className="mono text-xs truncate" style={{ color: 'var(--text-2)' }}>{f.source}</span>
                  <span className={f.enabled ? 's-online' : 's-offline'}>{f.enabled ? 'Active' : 'Off'}</span>
                  <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{f.last_sync ? timeAgo(f.last_sync) : 'Never'}</span>
                  <div className="flex justify-end">
                    <button onClick={() => syncFeed(f)} disabled={syncingId === f.id} className="g-btn g-btn-ghost text-[11px]" style={{ padding: '3px 8px' }}>
                      <RefreshCw className={`h-3 w-3 ${syncingId === f.id ? 'animate-spin' : ''}`} /> Sync
                    </button>
                  </div>
                </div>
              ))
            }
          </div>
        )}
      </div>

      {/* ── MODALS ── */}

      {/* Add/Edit IOC */}
      {(showAddIOC || showEditIOC) && (
        <Modal title={showEditIOC ? 'Edit IOC' : 'Add IOC'} onClose={() => { setShowAddIOC(false); setShowEditIOC(null); }}>
          <div className="space-y-3">
            <MInput label="Indicator *" value={iocForm.indicator} onChange={v => setIocForm(f => ({ ...f, indicator: v }))} placeholder="IP, hash, domain, URL" mono />
            <div className="grid grid-cols-2 gap-3">
              <MSelect label="Type" value={iocForm.type} onChange={v => setIocForm(f => ({ ...f, type: v }))} options={IOC_TYPES} />
              <MSelect label="Severity" value={iocForm.severity} onChange={v => setIocForm(f => ({ ...f, severity: v }))} options={SEVERITIES} capitalize />
            </div>
            <MInput label="Description" value={iocForm.description} onChange={v => setIocForm(f => ({ ...f, description: v }))} placeholder="Context, source, notes…" />
          </div>
          <ModalActions onCancel={() => { setShowAddIOC(false); setShowEditIOC(null); }}
            onConfirm={showEditIOC ? updateIOC : addIOC} saving={saving}
            disabled={!iocForm.indicator.trim()} label={showEditIOC ? 'Update' : 'Add IOC'} />
        </Modal>
      )}

      {/* Bulk import */}
      {showBulk && (
        <Modal title="Bulk Import IOCs" onClose={() => setShowBulk(false)}>
          <div className="space-y-3">
            <div className="rounded-xl px-3 py-2 text-[10px]"
              style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)', color: 'var(--text-2)' }}>
              ✨ Type is auto-detected — IPv4, IPv6, CIDR, domain, URL, SHA256, MD5, SHA1, email.
              Supports defanged indicators (hxxp, [.]).
            </div>
            <MSelect label="Severity" value={bulkForm.severity} onChange={v => setBulkForm(f => ({ ...f, severity: v }))} options={SEVERITIES} capitalize />
            <MInput label="Description / Source tag" value={bulkForm.description} onChange={v => setBulkForm(f => ({ ...f, description: v }))} placeholder="e.g. Threat campaign APT-X, feed: abuse.ch" />
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>
                Indicators (one per line, or comma/semicolon separated)
              </label>
              <textarea value={bulkForm.indicators} onChange={e => setBulkForm(f => ({ ...f, indicators: e.target.value }))}
                rows={8} placeholder={"1.2.3.4\nevil.com\nhxxps://malware[.]example/payload\nabc123def456...64hexchars\n8.8.8.8/24"}
                className="g-input resize-none font-mono text-xs" />
              <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                {bulkForm.indicators.split(/[\n,;]+/).filter(s => s.trim()).length} indicators
              </p>
            </div>
          </div>
          <ModalActions onCancel={() => setShowBulk(false)} onConfirm={bulkImport} saving={saving}
            disabled={!bulkForm.indicators.trim()} label="Import & Auto-Classify" />
        </Modal>
      )}

      {/* Add/Edit Sigma Rule */}
      {(showAddSigma || showEditSigma) && (
        <Modal title={showEditSigma ? 'Edit Sigma Rule' : 'New Sigma Rule'} onClose={() => { setShowAddSigma(false); setShowEditSigma(null); }} wide>
          <div className="space-y-3">
            <MInput label="Title *" value={sigmaForm.title} onChange={v => setSigmaForm(f => ({ ...f, title: v }))} placeholder="Rule title" />
            <div className="grid grid-cols-2 gap-3">
              <MSelect label="Severity" value={sigmaForm.severity} onChange={v => setSigmaForm(f => ({ ...f, severity: v }))} options={SEVERITIES} capitalize />
            </div>
            <MInput label="MITRE Tactic" value={sigmaForm.mitre_tactic} onChange={v => setSigmaForm(f => ({ ...f, mitre_tactic: v }))} placeholder="e.g. Execution" />
            <div className="grid grid-cols-2 gap-3">
              <MInput label="MITRE Technique" value={sigmaForm.mitre_technique} onChange={v => setSigmaForm(f => ({ ...f, mitre_technique: v }))} placeholder="e.g. T1059" />
              <MInput label="MITRE Name" value={sigmaForm.mitre_name} onChange={v => setSigmaForm(f => ({ ...f, mitre_name: v }))} placeholder="e.g. Command Execution" />
            </div>
            <MInput label="Keywords (comma-separated)" value={sigmaForm.keywords} onChange={v => setSigmaForm(f => ({ ...f, keywords: v }))} placeholder="sudo, root, exec" />
          </div>
          <ModalActions onCancel={() => { setShowAddSigma(false); setShowEditSigma(null); }}
            onConfirm={showEditSigma ? updateSigma : addSigma} saving={saving}
            disabled={!sigmaForm.title.trim()} label={showEditSigma ? 'Update' : 'Create Rule'} />
        </Modal>
      )}

      {/* Add Feed */}
      {showAddFeed && (
        <Modal title="Add Threat Feed" onClose={() => setShowAddFeed(false)}>
          <div className="space-y-3">
            <MInput label="Name *" value={feedForm.name} onChange={v => setFeedForm(f => ({ ...f, name: v }))} placeholder="Feed name" />
            <MInput label="Source" value={feedForm.source} onChange={v => setFeedForm(f => ({ ...f, source: v }))} placeholder="manual / https://…" mono />
          </div>
          <ModalActions onCancel={() => setShowAddFeed(false)} onConfirm={addFeed} saving={saving}
            disabled={!feedForm.name.trim()} label="Add Feed" />
        </Modal>
      )}
    </RootLayout>
  );
}

// ── Shared components ─────────────────────────────────────
function Modal({ title, children, onClose, wide }: { title: string; children: React.ReactNode; onClose: () => void; wide?: boolean }) {
  return (
    <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="g-modal" style={{ maxWidth: wide ? 560 : 480 }}>
        <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{title}</h2>
          <button onClick={onClose} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

function ModalActions({ onCancel, onConfirm, saving, disabled, label }: any) {
  return (
    <div className="flex gap-3 mt-5">
      <button onClick={onCancel} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
      <button onClick={onConfirm} disabled={saving || disabled} className="g-btn g-btn-primary flex-1 justify-center">
        {saving ? 'Saving…' : label}
      </button>
    </div>
  );
}

function MInput({ label, value, onChange, placeholder, mono }: any) {
  return (
    <div>
      <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>{label}</label>
      <input value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
        className={`g-input ${mono ? 'font-mono' : ''}`} />
    </div>
  );
}

function MSelect({ label, value, onChange, options, capitalize }: any) {
  return (
    <div>
      <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>{label}</label>
      <select value={value} onChange={e => onChange(e.target.value)} className="g-select">
        {options.map((o: string) => <option key={o} value={o}>{capitalize ? o.charAt(0).toUpperCase() + o.slice(1) : o.toUpperCase()}</option>)}
      </select>
    </div>
  );
}

function ActionBtn({ icon, onClick, danger }: { icon: React.ReactNode; onClick: () => void; danger?: boolean }) {
  return (
    <button onClick={onClick} className="p-1 rounded transition-colors"
      style={{ color: 'var(--text-3)' }}
      onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = danger ? 'var(--red)' : 'var(--accent)'}
      onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
      {icon}
    </button>
  );
}

function LoadingRow() {
  return <div className="py-12 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>;
}

function EmptyRow({ icon, msg }: { icon: React.ReactNode; msg: string }) {
  return (
    <div className="py-12 text-center">
      <div className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }}>{icon}</div>
      <p className="text-sm" style={{ color: 'var(--text-2)' }}>{msg}</p>
    </div>
  );
}

function Toast({ msg }: { msg: string }) {
  return <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)', minWidth: 220 }}>{msg}</div>;
}
