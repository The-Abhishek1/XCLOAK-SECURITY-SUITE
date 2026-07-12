'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { createPortal } from 'react-dom';
import { RootLayout } from '@/components/layout/RootLayout';
import { iocsAPI, sigmaAPI, threatFeedsAPI } from '@/lib/api';
import { IOC, SigmaRule, ThreatFeed } from '@/types';
import { sevClass, timeAgo } from '@/lib/utils';
import {
  Shield, Plus, Trash2, ToggleLeft, ToggleRight, X, Edit2,
  Upload, Rss, FileCode, Search, RefreshCw, ChevronLeft, ChevronRight,
} from 'lucide-react';

const TABS = [
  { id: 'iocs',  label: 'IOCs',         icon: Shield },
  { id: 'sigma', label: 'Sigma Rules',  icon: FileCode },
  { id: 'feeds', label: 'Threat Feeds', icon: Rss },
] as const;
type Tab = typeof TABS[number]['id'];

const IOC_TYPES  = ['ip', 'sha256', 'md5', 'domain', 'url'];
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const FEED_TYPES = ['flatfile', 'otx', 'misp', 'taxii'] as const;
const PAGE_SIZE  = 50;

const emptyIOC   = { indicator: '', type: 'ip', severity: 'high', description: '', enabled: true, expires_at: '' };
const emptyFeed  = { name: '', source: '', feed_type: 'flatfile', enabled: true, config: { api_key: '', collection_id: '', username: '', password: '' } };
const emptySigma = { title: '', severity: 'high', mitre_tactic: '', mitre_technique: '', mitre_name: '', keywords: '', enabled: true };

export default function ThreatIntelPage() {
  const [tab, setTab] = useState<Tab>('iocs');

  // IOC state
  const [iocs, setIocs]         = useState<IOC[]>([]);
  const [iocTotal, setIocTotal] = useState(0);
  const [iocPage, setIocPage]   = useState(1);
  const [typeFilter, setTypeFilter] = useState('all');
  const [iocSearch, setIocSearch]   = useState('');
  const [iocLoading, setIocLoading] = useState(false);

  // Sigma state
  const [sigma, setSigma]           = useState<SigmaRule[]>([]);
  const [sigmaTotal, setSigmaTotal] = useState(0);
  const [sigmaPage, setSigmaPage]   = useState(1);
  const [sigmaSearch, setSigmaSearch] = useState('');
  const [sigmaLoading, setSigmaLoading] = useState(false);

  // Feeds (no pagination needed — few rows)
  const [feeds, setFeeds] = useState<ThreatFeed[]>([]);

  // Toast
  const [toast, setToast] = useState<{ msg: string; isError?: boolean } | null>(null);

  // Modals
  const [showAddIOC, setShowAddIOC]   = useState(false);
  const [showEditIOC, setShowEditIOC] = useState<IOC | null>(null);
  const [showBulk, setShowBulk]       = useState(false);
  const [showAddSigma, setShowAddSigma]   = useState(false);
  const [showEditSigma, setShowEditSigma] = useState<SigmaRule | null>(null);
  const [showAddFeed, setShowAddFeed] = useState(false);
  const [editFeed, setEditFeed]       = useState<ThreatFeed | null>(null);

  const [iocForm, setIocForm]   = useState({ ...emptyIOC });
  const [sigmaForm, setSigmaForm] = useState({ ...emptySigma });
  const [feedForm, setFeedForm]   = useState({ ...emptyFeed });
  const [editForm, setEditForm]   = useState({ ...emptyFeed });
  const [bulkForm, setBulkForm]   = useState({ type: 'ip', severity: 'high', description: '', indicators: '' });
  const [saving, setSaving]       = useState(false);
  const [syncingId, setSyncingId] = useState<number | null>(null);

  // debounce refs
  const iocDebounce   = useRef<ReturnType<typeof setTimeout>>();
  const sigmaDebounce = useRef<ReturnType<typeof setTimeout>>();
  const [debouncedIocSearch, setDebouncedIocSearch]     = useState('');
  const [debouncedSigmaSearch, setDebouncedSigmaSearch] = useState('');

  useEffect(() => {
    clearTimeout(iocDebounce.current);
    iocDebounce.current = setTimeout(() => { setDebouncedIocSearch(iocSearch); setIocPage(1); }, 350);
  }, [iocSearch]);

  useEffect(() => {
    clearTimeout(sigmaDebounce.current);
    sigmaDebounce.current = setTimeout(() => { setDebouncedSigmaSearch(sigmaSearch); setSigmaPage(1); }, 350);
  }, [sigmaSearch]);

  const notify = (m: string, isError = false) => {
    setToast({ msg: m, isError });
    setTimeout(() => setToast(null), isError ? 6000 : 3000);
  };

  // ── loaders ──────────────────────────────────────────────────────────────

  const loadIOCs = useCallback(async (page: number, search: string, type: string) => {
    setIocLoading(true);
    try {
      const r = await iocsAPI.getPaged({ page, limit: PAGE_SIZE, search: search || undefined, type: type === 'all' ? undefined : type });
      setIocs(r.data?.data ?? []);
      setIocTotal(r.data?.total ?? 0);
    } catch { setIocs([]); }
    finally { setIocLoading(false); }
  }, []);

  const loadSigma = useCallback(async (page: number, search: string) => {
    setSigmaLoading(true);
    try {
      const r = await sigmaAPI.getPaged({ page, limit: PAGE_SIZE, search: search || undefined });
      setSigma(r.data?.data ?? []);
      setSigmaTotal(r.data?.total ?? 0);
    } catch { setSigma([]); }
    finally { setSigmaLoading(false); }
  }, []);

  const loadFeeds = useCallback(async () => {
    const r = await threatFeedsAPI.getAll();
    setFeeds(r.data || []);
  }, []);

  useEffect(() => { loadIOCs(iocPage, debouncedIocSearch, typeFilter); }, [loadIOCs, iocPage, debouncedIocSearch, typeFilter]);
  useEffect(() => { loadSigma(sigmaPage, debouncedSigmaSearch); }, [loadSigma, sigmaPage, debouncedSigmaSearch]);
  useEffect(() => { loadFeeds(); }, [loadFeeds]);

  // ── IOC CRUD ──────────────────────────────────────────────────────────────

  const serializeIocForm = (f: typeof iocForm) => ({
    ...f,
    expires_at: f.expires_at ? f.expires_at : null,
  });

  const addIOC = async () => {
    if (!iocForm.indicator.trim()) return;
    setSaving(true);
    try {
      await iocsAPI.create(serializeIocForm(iocForm));
      loadIOCs(iocPage, debouncedIocSearch, typeFilter);
      setShowAddIOC(false); setIocForm({ ...emptyIOC }); notify('IOC added');
    } finally { setSaving(false); }
  };

  const updateIOC = async () => {
    if (!showEditIOC) return;
    setSaving(true);
    try {
      await iocsAPI.update(showEditIOC.id, serializeIocForm(iocForm));
      loadIOCs(iocPage, debouncedIocSearch, typeFilter);
      setShowEditIOC(null); notify('IOC updated');
    } finally { setSaving(false); }
  };

  const deleteIOC = async (id: number) => {
    await iocsAPI.delete(id);
    setIocs(p => p.filter(i => i.id !== id));
    setIocTotal(t => t - 1);
    notify('IOC deleted');
  };

  const toggleIOC = async (ioc: IOC) => {
    ioc.enabled ? await iocsAPI.disable(ioc.id) : await iocsAPI.enable(ioc.id);
    setIocs(p => p.map(i => i.id === ioc.id ? { ...i, enabled: !i.enabled } : i));
  };

  const openEditIOC = (ioc: IOC) => {
    setIocForm({
      indicator: ioc.indicator, type: ioc.type, severity: ioc.severity,
      description: ioc.description, enabled: ioc.enabled,
      expires_at: ioc.expires_at ? ioc.expires_at.slice(0, 10) : '',
    });
    setShowEditIOC(ioc);
  };

  const bulkImport = async () => {
    setSaving(true);
    try {
      const r = await iocsAPI.bulkCreate({ indicators: bulkForm.indicators, severity: bulkForm.severity, description: bulkForm.description, source: 'manual' });
      const { imported, dupes, skipped } = r.data;
      notify(`Imported ${imported} IOCs (${dupes} already existed, ${skipped} skipped)`);
      loadIOCs(1, debouncedIocSearch, typeFilter);
      setIocPage(1);
      setShowBulk(false);
      setBulkForm({ type: 'ip', severity: 'high', description: '', indicators: '' });
    } catch { notify('Bulk import failed', true); }
    finally { setSaving(false); }
  };

  // ── Sigma CRUD ────────────────────────────────────────────────────────────

  const addSigma = async () => {
    if (!sigmaForm.title.trim()) return;
    setSaving(true);
    try {
      const keywords = sigmaForm.keywords.split(',').map(s => s.trim()).filter(Boolean);
      await sigmaAPI.create({ ...sigmaForm, keywords });
      loadSigma(sigmaPage, debouncedSigmaSearch);
      setShowAddSigma(false); setSigmaForm({ ...emptySigma }); notify('Sigma rule created');
    } finally { setSaving(false); }
  };

  const updateSigma = async () => {
    if (!showEditSigma) return;
    setSaving(true);
    try {
      const keywords = sigmaForm.keywords.split(',').map(s => s.trim()).filter(Boolean);
      await sigmaAPI.update(showEditSigma.id, { ...sigmaForm, keywords });
      loadSigma(sigmaPage, debouncedSigmaSearch);
      setShowEditSigma(null); notify('Rule updated');
    } finally { setSaving(false); }
  };

  const deleteSigma = async (id: number) => {
    await sigmaAPI.delete(id);
    setSigma(p => p.filter(r => r.id !== id));
    setSigmaTotal(t => t - 1);
    notify('Rule deleted');
  };

  const toggleSigma = async (r: SigmaRule) => {
    r.enabled ? await sigmaAPI.disable(r.id) : await sigmaAPI.enable(r.id);
    setSigma(p => p.map(x => x.id === r.id ? { ...x, enabled: !x.enabled } : x));
  };

  const openEditSigma = (r: SigmaRule) => {
    setSigmaForm({ title: r.title, severity: r.severity, mitre_tactic: r.mitre_tactic, mitre_technique: r.mitre_technique, mitre_name: r.mitre_name, keywords: (r.keywords || []).join(', '), enabled: r.enabled });
    setShowEditSigma(r);
  };

  // ── Feed CRUD ─────────────────────────────────────────────────────────────

  const syncFeed = async (feed: ThreatFeed) => {
    if (feed.id == null) return;
    setSyncingId(feed.id);
    try {
      const res = await threatFeedsAPI.sync(feed.id);
      const count = res.data?.count ?? 0;
      if (res.data?.warning) {
        notify(`Partial sync: ${count} indicators imported. ${res.data.warning.split('then: ')[1] ?? ''}`, true);
      } else {
        notify(`Synced "${feed.name}" — ${count} indicators imported`);
      }
      loadFeeds();
      // refresh IOC list from cache (fast local DB read)
      loadIOCs(1, debouncedIocSearch, typeFilter);
      setIocPage(1);
    } catch (e: any) {
      notify(e?.response?.data?.error || `Failed to sync "${feed.name}"`, true);
    } finally { setSyncingId(null); }
  };

  const deleteFeed = async (feed: ThreatFeed) => {
    if (!confirm(`Delete feed "${feed.name}"?`)) return;
    try { await threatFeedsAPI.delete(feed.id!); loadFeeds(); notify(`Deleted "${feed.name}"`); }
    catch { notify('Failed to delete feed', true); }
  };

  const openEditFeed = (f: ThreatFeed) => {
    let cfg = { api_key: '', collection_id: '', username: '', password: '' };
    try { const raw = typeof f.config === 'string' ? JSON.parse(f.config) : f.config; cfg = { ...cfg, ...raw }; } catch {}
    setEditForm({ name: f.name, source: f.source || '', feed_type: f.feed_type || 'flatfile', enabled: f.enabled, config: cfg });
    setEditFeed(f);
  };

  const updateFeed = async () => {
    if (!editFeed) return;
    setSaving(true);
    try {
      await threatFeedsAPI.update(editFeed.id!, editForm);
      loadFeeds(); setEditFeed(null); notify('Feed updated');
    } catch (e: any) {
      notify(e?.response?.data?.error || 'Failed to update feed', true);
    } finally { setSaving(false); }
  };

  const addFeed = async () => {
    if (!feedForm.name.trim()) return;
    setSaving(true);
    try {
      await threatFeedsAPI.create(feedForm);
      loadFeeds(); setShowAddFeed(false); setFeedForm({ ...emptyFeed }); notify('Feed added');
    } finally { setSaving(false); }
  };

  // ── render ────────────────────────────────────────────────────────────────

  const iocPages   = Math.max(1, Math.ceil(iocTotal / PAGE_SIZE));
  const sigmaPages = Math.max(1, Math.ceil(sigmaTotal / PAGE_SIZE));

  return (
    <RootLayout title="Threat Intelligence"
      subtitle={`${iocTotal.toLocaleString()} IOCs cached · ${sigmaTotal} sigma rules`}
      onRefresh={() => { loadIOCs(iocPage, debouncedIocSearch, typeFilter); loadSigma(sigmaPage, debouncedSigmaSearch); loadFeeds(); }}>

      {toast && <Toast msg={toast.msg} isError={toast.isError} />}

      <div className="space-y-4">

        {/* Stats strip */}
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: 'Total IOCs', value: iocTotal.toLocaleString(), color: 'var(--accent)', icon: Shield },
            { label: 'Active Feeds', value: feeds.filter(f => f.enabled).length, color: 'var(--green)', icon: Rss },
            { label: 'Sigma Rules', value: sigmaTotal, color: 'var(--orange)', icon: FileCode },
          ].map(({ label, value, color, icon: Icon }) => (
            <div key={label} className="g-card p-4 flex items-center gap-3">
              <div className="p-2 rounded-lg" style={{ background: `${color}18`, border: `1px solid ${color}30` }}>
                <Icon className="h-4 w-4" style={{ color }} />
              </div>
              <div>
                <p className="text-xl font-bold" style={{ color }}>{value}</p>
                <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{label}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Tab bar + actions */}
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

          {tab === 'iocs' && (
            <div className="flex gap-2">
              <button type="button" onClick={() => setShowBulk(true)} className="g-btn g-btn-ghost text-xs">
                <Upload className="h-3.5 w-3.5" /> Bulk Import
              </button>
              <button type="button" onClick={() => { setIocForm({ ...emptyIOC }); setShowAddIOC(true); }} className="g-btn g-btn-primary text-xs">
                <Plus className="h-3.5 w-3.5" /> Add IOC
              </button>
            </div>
          )}
          {tab === 'sigma' && (
            <button type="button" onClick={() => { setSigmaForm({ ...emptySigma }); setShowAddSigma(true); }} className="g-btn g-btn-primary text-xs">
              <Plus className="h-3.5 w-3.5" /> New Rule
            </button>
          )}
          {tab === 'feeds' && (
            <button type="button" onClick={() => setShowAddFeed(true)} className="g-btn g-btn-primary text-xs">
              <Plus className="h-3.5 w-3.5" /> Add Feed
            </button>
          )}
        </div>

        {/* ── IOCs TAB ── */}
        {tab === 'iocs' && (
          <>
            <div className="flex flex-wrap gap-2 items-center">
              {['all', ...IOC_TYPES].map(t => (
                <button type="button" key={t}
                  onClick={() => { setTypeFilter(t); setIocPage(1); }}
                  className="g-btn text-[11px] uppercase"
                  style={{
                    background: typeFilter === t ? 'var(--accent-glow)' : 'var(--glass-bg)',
                    color:      typeFilter === t ? 'var(--accent)' : 'var(--text-2)',
                    border:     `1px solid ${typeFilter === t ? 'var(--accent-border)' : 'var(--border)'}`,
                    backdropFilter: 'var(--blur-sm)',
                    padding: '4px 10px',
                  }}>
                  {t === 'all' ? `All (${iocTotal.toLocaleString()})` : t}
                </button>
              ))}
              <div className="relative ml-auto">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
                <input value={iocSearch} onChange={e => setIocSearch(e.target.value)}
                  placeholder="Search indicator, description…" className="g-input pl-9" style={{ width: 250, height: 34 }} />
              </div>
            </div>

            <div className="g-table">
              <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 70px 80px 1fr 90px 80px 80px 60px' }}>
                <span>Indicator</span><span>Type</span><span>Severity</span><span>Description</span>
                <span>Hits</span><span>Last Seen</span><span>Status</span><span className="text-right">Actions</span>
              </div>
              {iocLoading
                ? <LoadingRow />
                : iocs.length === 0
                  ? <EmptyRow icon={<Shield />} msg={iocSearch || typeFilter !== 'all' ? 'No IOCs match your filter.' : 'No IOCs yet. Add one or sync a feed.'} />
                  : iocs.map(ioc => (
                    <div key={ioc.id} className={`g-tr grid gap-3 items-center px-4 ${!ioc.enabled ? 'opacity-40' : ''}`}
                      style={{ gridTemplateColumns: '1fr 70px 80px 1fr 90px 80px 80px 60px' }}>
                      <span className="mono text-xs truncate" style={{ color: 'var(--text-1)' }}>{ioc.indicator}</span>
                      <span className="mono text-[10px] rounded px-1.5 py-0.5 uppercase inline-block w-fit"
                        style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>{ioc.type}</span>
                      <span className={sevClass(ioc.severity)}>{ioc.severity}</span>
                      <span className="text-xs truncate" style={{ color: 'var(--text-2)' }}>{ioc.description}</span>
                      <span className="text-xs font-mono" style={{ color: (ioc.hit_count ?? 0) > 0 ? 'var(--red)' : 'var(--text-3)' }}>
                        {(ioc.hit_count ?? 0).toLocaleString()}
                      </span>
                      <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>
                        {ioc.last_seen ? timeAgo(ioc.last_seen) : '—'}
                      </span>
                      <button type="button" onClick={() => toggleIOC(ioc)} className="flex items-center gap-1 text-[10px]"
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

            <Pager page={iocPage} total={iocTotal} totalPages={iocPages} onChange={p => setIocPage(p)} />
          </>
        )}

        {/* ── SIGMA TAB ── */}
        {tab === 'sigma' && (
          <>
            <div className="flex items-center gap-3">
              <div className="relative flex-1 max-w-xs">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
                <input value={sigmaSearch} onChange={e => setSigmaSearch(e.target.value)}
                  placeholder="Search rules…" className="g-input pl-9" style={{ height: 34 }} />
              </div>
            </div>

            <div className="g-table">
              <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 100px 80px 80px 80px 60px' }}>
                <span>Title</span><span>MITRE</span><span>Severity</span><span>Keywords</span><span>Status</span><span className="text-right">Actions</span>
              </div>
              {sigmaLoading
                ? <LoadingRow />
                : sigma.length === 0
                  ? <EmptyRow icon={<FileCode />} msg={sigmaSearch ? 'No rules match your search.' : 'No Sigma rules. Create one.'} />
                  : sigma.map(r => (
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
                      <button type="button" onClick={() => toggleSigma(r)} className="flex items-center gap-1 text-[10px]"
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

            <Pager page={sigmaPage} total={sigmaTotal} totalPages={sigmaPages} onChange={p => setSigmaPage(p)} />
          </>
        )}

        {/* ── FEEDS TAB ── */}
        {tab === 'feeds' && (
          <div className="g-table">
            <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 1fr 80px 100px 140px' }}>
              <span>Name</span><span>Source</span><span>Status</span><span>Last Sync</span><span className="text-right">Actions</span>
            </div>
            {feeds.length === 0 ? <EmptyRow icon={<Rss />} msg="No threat feeds configured." /> :
              feeds.map((f, i) => (
                <div key={i} className="g-tr grid gap-3 items-center px-4"
                  style={{ gridTemplateColumns: '1fr 1fr 80px 100px 140px' }}>
                  <span className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{f.name}</span>
                  <span className="mono text-xs truncate" style={{ color: 'var(--text-2)' }}>{f.source || f.feed_type}</span>
                  <span className={f.enabled ? 's-online' : 's-offline'}>{f.enabled ? 'Active' : 'Off'}</span>
                  <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{f.last_sync ? timeAgo(f.last_sync) : 'Never'}</span>
                  <div className="flex justify-end gap-1">
                    <button type="button" onClick={() => syncFeed(f)} disabled={syncingId === f.id} className="g-btn g-btn-ghost text-[11px]" style={{ padding: '3px 8px' }}>
                      <RefreshCw className={`h-3 w-3 ${syncingId === f.id ? 'animate-spin' : ''}`} /> Sync
                    </button>
                    <button type="button" onClick={() => openEditFeed(f)} className="g-btn g-btn-ghost text-[11px]" style={{ padding: '3px 8px' }}>
                      <Edit2 className="h-3 w-3" />
                    </button>
                    <button type="button" onClick={() => deleteFeed(f)} className="g-btn g-btn-ghost text-[11px]" style={{ padding: '3px 8px', color: 'var(--danger)' }}>
                      <Trash2 className="h-3 w-3" />
                    </button>
                  </div>
                </div>
              ))
            }
          </div>
        )}
      </div>

      {/* ── MODALS ── */}

      {(showAddIOC || showEditIOC) && (
        <Modal title={showEditIOC ? 'Edit IOC' : 'Add IOC'} onClose={() => { setShowAddIOC(false); setShowEditIOC(null); }}>
          <div className="space-y-3">
            <MInput label="Indicator *" value={iocForm.indicator} onChange={v => setIocForm(f => ({ ...f, indicator: v }))} placeholder="IP, hash, domain, URL" mono />
            <div className="grid grid-cols-2 gap-3">
              <MSelect label="Type" value={iocForm.type} onChange={v => setIocForm(f => ({ ...f, type: v }))} options={IOC_TYPES} />
              <MSelect label="Severity" value={iocForm.severity} onChange={v => setIocForm(f => ({ ...f, severity: v }))} options={SEVERITIES} capitalize />
            </div>
            <MInput label="Description" value={iocForm.description} onChange={v => setIocForm(f => ({ ...f, description: v }))} placeholder="Context, source, notes…" />
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>
                Expires At <span style={{ color: 'var(--text-3)', fontWeight: 400 }}>(leave blank = auto-expire after 90 days if never matched)</span>
              </label>
              <input type="date" value={iocForm.expires_at} onChange={e => setIocForm(f => ({ ...f, expires_at: e.target.value }))}
                className="g-input" />
            </div>
          </div>
          <ModalActions onCancel={() => { setShowAddIOC(false); setShowEditIOC(null); }}
            onConfirm={showEditIOC ? updateIOC : addIOC} saving={saving}
            disabled={!iocForm.indicator.trim()} label={showEditIOC ? 'Update' : 'Add IOC'} />
        </Modal>
      )}

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
                rows={8} placeholder={"1.2.3.4\nevil.com\nhxxps://malware[.]example/payload"}
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

      {showAddFeed && (
        <Modal title="Add Threat Feed" onClose={() => setShowAddFeed(false)}>
          <FeedFields form={feedForm} setForm={setFeedForm} />
          <ModalActions onCancel={() => setShowAddFeed(false)} onConfirm={addFeed} saving={saving}
            disabled={!feedForm.name.trim()} label="Add Feed" />
        </Modal>
      )}

      {editFeed && (
        <Modal title={`Edit Feed — ${editFeed.name}`} onClose={() => setEditFeed(null)}>
          <FeedFields form={editForm} setForm={setEditForm} />
          <ModalActions onCancel={() => setEditFeed(null)} onConfirm={updateFeed} saving={saving}
            disabled={!editForm.name.trim()} label="Save Changes" />
        </Modal>
      )}
    </RootLayout>
  );
}

// ── Pagination control ────────────────────────────────────────────────────────

function Pager({ page, total, totalPages, onChange }: { page: number; total: number; totalPages: number; onChange: (p: number) => void }) {
  if (totalPages <= 1) return null;

  const pages: number[] = [];
  const start = Math.max(1, Math.min(page - 2, totalPages - 4));
  const end   = Math.min(totalPages, start + 4);
  for (let p = start; p <= end; p++) pages.push(p);

  return (
    <div className="flex items-center justify-between px-1 pt-1">
      <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
        {((page - 1) * 50 + 1).toLocaleString()}–{Math.min(page * 50, total).toLocaleString()} of {total.toLocaleString()}
      </p>
      <div className="flex items-center gap-1">
        <button type="button" disabled={page === 1} onClick={() => onChange(page - 1)}
          className="p-1.5 rounded-lg disabled:opacity-30 transition-colors"
          style={{ border: '1px solid var(--border)', color: 'var(--text-2)' }}>
          <ChevronLeft className="h-3.5 w-3.5" />
        </button>
        {pages.map(p => (
          <button type="button" key={p} onClick={() => onChange(p)}
            className="min-w-[28px] h-7 px-1.5 rounded-lg text-xs transition-colors"
            style={{
              background: p === page ? 'var(--accent-glow)' : 'transparent',
              border: `1px solid ${p === page ? 'var(--accent-border)' : 'var(--border)'}`,
              color: p === page ? 'var(--accent)' : 'var(--text-2)',
              fontWeight: p === page ? 600 : 400,
            }}>
            {p}
          </button>
        ))}
        {end < totalPages && (
          <>
            <span className="text-xs px-1" style={{ color: 'var(--text-3)' }}>…</span>
            <button type="button" onClick={() => onChange(totalPages)}
              className="min-w-[28px] h-7 px-1.5 rounded-lg text-xs"
              style={{ border: '1px solid var(--border)', color: 'var(--text-2)' }}>
              {totalPages}
            </button>
          </>
        )}
        <button type="button" disabled={page === totalPages} onClick={() => onChange(page + 1)}
          className="p-1.5 rounded-lg disabled:opacity-30 transition-colors"
          style={{ border: '1px solid var(--border)', color: 'var(--text-2)' }}>
          <ChevronRight className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}

// ── Feed form (shared between Add/Edit modals) ────────────────────────────────

function FeedFields({ form, setForm }: { form: any; setForm: (fn: (f: any) => any) => void }) {
  return (
    <div className="space-y-3">
      <MInput label="Name *" value={form.name} onChange={v => setForm(f => ({ ...f, name: v }))} placeholder="Feed name" />
      <MSelect label="Feed Type" value={form.feed_type} onChange={v => setForm(f => ({ ...f, feed_type: v }))} options={['flatfile', 'otx', 'misp', 'taxii']} capitalize />
      {form.feed_type === 'flatfile' && (
        <MInput label="URL / Path" value={form.source} onChange={v => setForm(f => ({ ...f, source: v }))} placeholder="https://… or /path/to/feed.txt" mono />
      )}
      {(form.feed_type === 'otx' || form.feed_type === 'misp') && (
        <MInput label="API Key *" value={form.config.api_key} onChange={v => setForm(f => ({ ...f, config: { ...f.config, api_key: v } }))} placeholder={form.feed_type === 'otx' ? 'AlienVault OTX API key' : 'MISP API key'} mono />
      )}
      {form.feed_type === 'misp' && (
        <MInput label="MISP URL *" value={form.source} onChange={v => setForm(f => ({ ...f, source: v }))} placeholder="https://misp.example.com" mono />
      )}
      {form.feed_type === 'taxii' && (
        <>
          <MInput label="TAXII URL *" value={form.source} onChange={v => setForm(f => ({ ...f, source: v }))} placeholder="https://…/taxii2/" mono />
          <MInput label="Collection ID" value={form.config.collection_id} onChange={v => setForm(f => ({ ...f, config: { ...f.config, collection_id: v } }))} placeholder="collection-uuid" mono />
          <MInput label="Username" value={form.config.username} onChange={v => setForm(f => ({ ...f, config: { ...f.config, username: v } }))} placeholder="optional" />
          <MInput label="Password" value={form.config.password} onChange={v => setForm(f => ({ ...f, config: { ...f.config, password: v } }))} placeholder="optional" />
        </>
      )}
    </div>
  );
}

// ── Shared components ─────────────────────────────────────────────────────────

function Modal({ title, children, onClose, wide }: { title: string; children: React.ReactNode; onClose: () => void; wide?: boolean }) {
  return (
    <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="g-modal" style={{ maxWidth: wide ? 560 : 480 }}>
        <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{title}</h2>
          <button type="button" onClick={onClose} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

function ModalActions({ onCancel, onConfirm, saving, disabled, label }: any) {
  return (
    <div className="flex gap-3 mt-5">
      <button type="button" onClick={onCancel} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
      <button type="button" onClick={onConfirm} disabled={saving || disabled} className="g-btn g-btn-primary flex-1 justify-center">
        {saving ? 'Saving…' : label}
      </button>
    </div>
  );
}

function MInput({ label, value, onChange, placeholder, mono }: { label: string; value: string; onChange: (v: string) => void; placeholder?: string; mono?: boolean }) {
  return (
    <div>
      <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>{label}</label>
      <input value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
        className={`g-input ${mono ? 'font-mono' : ''}`} />
    </div>
  );
}

function MSelect({ label, value, onChange, options, capitalize }: { label: string; value: string; onChange: (v: string) => void; options: string[]; capitalize?: boolean }) {
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
    <button type="button" onClick={onClick} className="p-1 rounded transition-colors"
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

function Toast({ msg, isError }: { msg: string; isError?: boolean }) {
  if (typeof document === 'undefined') return null;
  return createPortal(
    <div className="fixed bottom-5 right-5 px-4 py-3 text-sm rounded-xl shadow-lg"
      style={{
        zIndex: 99999, minWidth: 260, maxWidth: 400,
        background: isError ? 'var(--red, #ef4444)' : 'var(--glass-bg, rgba(30,30,40,0.95))',
        color: isError ? '#fff' : 'var(--text-1)',
        border: '1px solid ' + (isError ? 'rgba(255,255,255,0.2)' : 'var(--border)'),
        backdropFilter: 'blur(12px)', wordBreak: 'break-word',
      }}>
      {msg}
    </div>,
    document.body
  );
}
