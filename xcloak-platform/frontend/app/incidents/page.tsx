'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { incidentsAPI, aiAPI } from '@/lib/api';
import { Incident } from '@/types';
import { sevClass, formatDate, timeAgo } from '@/lib/utils';
import Link from 'next/link';
import {
  AlertTriangle, X, Clock, Bot, Loader2,
  MessageSquare, Send, ChevronRight, Bell, TrendingUp,
  Search, CheckSquare, Square, CheckCheck, Filter,
  ShieldAlert, Flame, Activity,
} from 'lucide-react';

const INCIDENT_SLA: Record<string, number> = { critical: 4, high: 8, medium: 48, low: 120 };
const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
const STATUSES   = ['open', 'investigating', 'resolved', 'closed'] as const;

function slaInfo(sev: string, created_at: string, status: string): { breached: boolean; label: string } | null {
  if (status === 'resolved' || status === 'closed') return null;
  const slaH = INCIDENT_SLA[sev];
  if (!slaH) return null;
  const ageH = (Date.now() - new Date(created_at).getTime()) / 3_600_000;
  const diffH = ageH - slaH;
  if (diffH > 0) {
    const h = Math.floor(diffH);
    const m = Math.floor((diffH - h) * 60);
    return { breached: true, label: `+${h}h${m ? ` ${m}m` : ''}` };
  }
  const rem = slaH - ageH;
  const h = Math.floor(rem);
  const m = Math.floor((rem - h) * 60);
  return { breached: false, label: `${h}h${m ? ` ${m}m` : ''} left` };
}

function slaBreachDetail(sev: string, created_at: string): string {
  const slaH = INCIDENT_SLA[sev] ?? 0;
  const ageH = (Date.now() - new Date(created_at).getTime()) / 3_600_000;
  return `SLA breached by ${Math.round(ageH - slaH)}h (${slaH}h target for ${sev})`;
}

interface AISummary {
  summary: string;
  timeline: string[];
  root_cause_hint: string;
  recommended_steps: string[];
}

export default function IncidentsPage() {
  const [incidents, setIncidents]     = useState<Incident[]>([]);
  const [loading, setLoading]         = useState(true);
  const [refreshing, setRefreshing]   = useState(false);
  const [filter, setFilter]           = useState('all');
  const [severityFilter, setSeverityFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIDs, setSelectedIDs] = useState<Set<number>>(new Set());
  const [bulkStatus, setBulkStatus]   = useState('');
  const [bulking, setBulking]         = useState(false);
  const [selected, setSelected]       = useState<Incident | null>(null);
  const [events, setEvents]           = useState<any[]>([]);
  const [evLoading, setEvLoading]     = useState(false);
  const [updatingId, setUpdatingId]   = useState<number | null>(null);
  const [toast, setToast]             = useState<string | null>(null);
  const [aiSummary, setAiSummary]     = useState<AISummary | null>(null);
  const [aiLoading, setAiLoading]     = useState(false);
  const [note, setNote]               = useState('');
  const [addingNote, setAddingNote]   = useState(false);
  const [page, setPage]               = useState(1);
  const [total, setTotal]             = useState(0);
  const [linkedAlerts, setLinkedAlerts]   = useState<any[]>([]);
  const [linkedLoading, setLinkedLoading] = useState(false);
  const [escalating, setEscalating]   = useState(false);
  const [statusCounts, setStatusCounts]   = useState<Record<string, number>>({});
  const [, setTick]                   = useState(0);
  const PER_PAGE = 25;

  // Force re-render every 60s for live SLA countdowns
  useEffect(() => {
    const id = setInterval(() => setTick(t => t + 1), 60_000);
    return () => clearInterval(id);
  }, []);

  // Escape to close drawer
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') setSelected(null); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  const load = useCallback(async (p = page, status = filter, spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const r = await incidentsAPI.getPaginated(p, PER_PAGE, status === 'all' ? '' : status);
      const data = r.data || {};
      setIncidents(data.data || []);
      setTotal(data.total || 0);
    } finally { setLoading(false); setRefreshing(false); }
  }, [page, filter]);

  useEffect(() => { load(page, filter); }, [page, filter]);

  useEffect(() => {
    incidentsAPI.getCounts().then(r => setStatusCounts(r.data || {})).catch(() => {});
  }, []);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const openDetail = async (inc: Incident) => {
    setSelected(inc);
    setAiSummary(null);
    setNote('');
    setLinkedAlerts([]);
    setEvLoading(true);
    setLinkedLoading(true);
    try {
      const [evR, alR] = await Promise.allSettled([
        incidentsAPI.getEvents(inc.id),
        incidentsAPI.getAlerts(inc.id),
      ]);
      if (evR.status === 'fulfilled') setEvents(evR.value.data || []);
      if (alR.status === 'fulfilled') setLinkedAlerts(alR.value.data || []);
    } finally { setEvLoading(false); setLinkedLoading(false); }
  };

  const escalateSeverity = async () => {
    if (!selected) return;
    const SEV = ['low', 'medium', 'high', 'critical'];
    const idx = SEV.indexOf(selected.severity);
    if (idx >= SEV.length - 1) return;
    const next = SEV[idx + 1] as 'low' | 'medium' | 'high' | 'critical';
    setEscalating(true);
    try {
      await incidentsAPI.updateSeverity(selected.id, next);
      setSelected({ ...selected, severity: next });
      setIncidents(p => p.map(i => i.id === selected.id ? { ...i, severity: next } : i));
      notify(`Escalated to ${next}`);
    } catch { notify('Escalation failed'); }
    finally { setEscalating(false); }
  };

  const updateStatus = async (id: number, status: string) => {
    setUpdatingId(id);
    try {
      await incidentsAPI.updateStatus(id, status);
      setIncidents(p => p.map(i => i.id === id ? { ...i, status: status as any } : i));
      if (selected?.id === id) setSelected(s => s ? { ...s, status: status as any } : s);
      notify(`Status → ${status}`);
    } finally { setUpdatingId(null); }
  };

  const bulkUpdate = async () => {
    if (!bulkStatus || selectedIDs.size === 0) return;
    setBulking(true);
    try {
      await Promise.all([...selectedIDs].map(id => incidentsAPI.updateStatus(id, bulkStatus)));
      setIncidents(p => p.map(i => selectedIDs.has(i.id) ? { ...i, status: bulkStatus as any } : i));
      notify(`${selectedIDs.size} incident${selectedIDs.size !== 1 ? 's' : ''} → ${bulkStatus}`);
      setSelectedIDs(new Set());
      setBulkStatus('');
    } catch { notify('Bulk update failed'); }
    finally { setBulking(false); }
  };

  const toggleSelect = (id: number) => setSelectedIDs(prev => {
    const next = new Set(prev);
    next.has(id) ? next.delete(id) : next.add(id);
    return next;
  });

  const toggleSelectAll = () => {
    if (selectedIDs.size === displayed.length) setSelectedIDs(new Set());
    else setSelectedIDs(new Set(displayed.map(i => i.id)));
  };

  const runAISummary = async () => {
    if (!selected) return;
    setAiLoading(true);
    setAiSummary(null);
    try {
      const r = await aiAPI.summarizeIncident(selected.id);
      setAiSummary(r.data);
    } catch { notify('AI unavailable — check LLM config'); }
    finally { setAiLoading(false); }
  };

  const addNote = async () => {
    if (!selected || !note.trim()) return;
    setAddingNote(true);
    try {
      await incidentsAPI.addNote(selected.id, note);
      setNote('');
      const r = await incidentsAPI.getEvents(selected.id);
      setEvents(r.data || []);
      notify('Note added');
    } catch { notify('Failed to add note'); }
    finally { setAddingNote(false); }
  };

  const changeFilter = (f: string) => { setFilter(f); setPage(1); setSelectedIDs(new Set()); };

  const displayed = incidents.filter(inc => {
    if (severityFilter && inc.severity !== severityFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return inc.title.toLowerCase().includes(q) || (inc.description || '').toLowerCase().includes(q);
    }
    return true;
  });

  const totalCount    = Object.values(statusCounts).reduce((a, b) => a + b, 0);
  const slaBreachedCount = incidents.filter(i =>
    i.status !== 'resolved' && i.status !== 'closed' &&
    slaInfo(i.severity, i.created_at, i.status)?.breached
  ).length;

  return (
    <RootLayout title="Incidents" subtitle={total ? `${total} total` : ''}
      onRefresh={() => load(page, filter, true)} refreshing={refreshing}>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)' }}>
          {toast}
        </div>
      )}

      <div className="space-y-4">
        {/* KPI strip */}
        {!loading && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: 'Total',        value: totalCount,                       color: 'var(--accent)',  icon: Activity },
              { label: 'Open',         value: statusCounts.open        || 0,    color: 'var(--red)',     icon: Flame },
              { label: 'Investigating',value: statusCounts.investigating || 0,  color: 'var(--orange)',  icon: ShieldAlert },
              { label: 'SLA Breached', value: slaBreachedCount,                 color: slaBreachedCount > 0 ? 'var(--red)' : 'var(--green)', icon: Clock },
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
        )}

        {/* Status filter tabs */}
        <div className="flex items-center gap-2 flex-wrap">
          {['all', ...STATUSES].map(s => {
            const count = s === 'all'
              ? totalCount
              : (statusCounts[s] || 0);
            return (
              <button key={s} onClick={() => changeFilter(s)}
                className="g-btn text-xs capitalize"
                style={{
                  background: filter === s ? 'var(--accent-glow)' : 'var(--glass-bg)',
                  color:      filter === s ? 'var(--accent)' : 'var(--text-2)',
                  border:     filter === s ? '1px solid var(--accent-border)' : '1px solid var(--border)',
                }}>
                {s}{count > 0 ? ` (${count})` : ''}
              </button>
            );
          })}
        </div>

        {/* Search + severity filter */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
            <input value={searchQuery} onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search incidents…"
              className="g-input w-full text-xs pl-8" />
            {searchQuery && (
              <button onClick={() => setSearchQuery('')} className="absolute right-2.5 top-1/2 -translate-y-1/2"
                style={{ color: 'var(--text-3)' }}>
                <X className="h-3 w-3" />
              </button>
            )}
          </div>
          <div className="flex items-center gap-1">
            <Filter className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />
            {['', ...SEVERITIES].map(s => (
              <button key={s || 'all'} onClick={() => setSeverityFilter(s)}
                className="px-2.5 py-1 text-[11px] rounded-lg capitalize transition-all"
                style={{
                  background: severityFilter === s ? 'var(--accent-glow)' : 'var(--glass-bg)',
                  border: `1px solid ${severityFilter === s ? 'var(--accent-border)' : 'var(--border)'}`,
                  color: severityFilter === s ? 'var(--accent)' : 'var(--text-2)',
                }}>
                {s || 'all'}
              </button>
            ))}
          </div>
        </div>

        {/* Bulk action bar */}
        {selectedIDs.size > 0 && (
          <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl"
            style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
            <CheckCheck className="h-4 w-4" style={{ color: 'var(--accent)' }} />
            <span className="text-xs font-medium" style={{ color: 'var(--accent)' }}>
              {selectedIDs.size} selected
            </span>
            <div className="flex items-center gap-1.5 ml-auto">
              <select value={bulkStatus} onChange={e => setBulkStatus(e.target.value)}
                className="g-select text-xs" style={{ padding: '3px 8px' }}>
                <option value="">Set status…</option>
                {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
              <button onClick={bulkUpdate} disabled={!bulkStatus || bulking}
                className="g-btn g-btn-primary text-xs">
                {bulking ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : 'Apply'}
              </button>
              <button onClick={() => setSelectedIDs(new Set())}
                className="g-btn g-btn-ghost text-xs">Clear</button>
            </div>
          </div>
        )}

        {/* Table */}
        <div className="g-table">
          <div className="g-thead grid gap-3 px-4"
            style={{ gridTemplateColumns: '16px 16px 1fr 110px 70px 80px 90px 80px 24px' }}>
            <button onClick={toggleSelectAll} style={{ color: 'var(--text-3)' }}>
              {selectedIDs.size > 0 && selectedIDs.size === displayed.length
                ? <CheckSquare className="h-3.5 w-3.5" />
                : <Square className="h-3.5 w-3.5" />}
            </button>
            <span />
            <span>Title</span>
            <span>Status</span>
            <span>Agent</span>
            <span>Severity</span>
            <span>Change</span>
            <span>SLA</span>
            <span />
          </div>

          {loading ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          ) : displayed.length === 0 ? (
            <div className="py-16 text-center">
              <AlertTriangle className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>No incidents</p>
            </div>
          ) : displayed.map(inc => {
            const sla = slaInfo(inc.severity, inc.created_at, inc.status);
            return (
              <div key={inc.id} className="g-tr grid gap-3 items-center px-4"
                style={{ gridTemplateColumns: '16px 16px 1fr 110px 70px 80px 90px 80px 24px' }}>

                <button onClick={e => { e.stopPropagation(); toggleSelect(inc.id); }}
                  style={{ color: selectedIDs.has(inc.id) ? 'var(--accent)' : 'var(--text-3)' }}>
                  {selectedIDs.has(inc.id)
                    ? <CheckSquare className="h-3.5 w-3.5" />
                    : <Square className="h-3.5 w-3.5" />}
                </button>

                <span className="h-1.5 w-1.5 rounded-full shrink-0"
                  style={{ background: inc.severity === 'critical' ? 'var(--red)' : inc.severity === 'high' ? 'var(--orange)' : inc.severity === 'medium' ? 'var(--yellow)' : 'var(--blue)' }} />

                <div className="min-w-0 cursor-pointer" onClick={() => openDetail(inc)}>
                  <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{inc.title}</p>
                  <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>{inc.description}</p>
                </div>

                <span className="text-[11px] rounded px-2 py-0.5 capitalize font-medium inline-block w-fit"
                  style={
                    inc.status === 'open'          ? { background: 'var(--red-bg)',    color: 'var(--red)',    border: '1px solid var(--red-border)' }
                    : inc.status === 'investigating' ? { background: 'var(--orange-bg)', color: 'var(--orange)', border: '1px solid var(--orange-border)' }
                    : inc.status === 'resolved'      ? { background: 'var(--green-bg)',  color: 'var(--green)',  border: '1px solid var(--green-border)' }
                    :                                  { background: 'rgba(74,90,117,0.15)', color: 'var(--text-3)', border: '1px solid rgba(74,90,117,0.2)' }
                  }>
                  {inc.status}
                </span>

                <Link href={`/agents/${inc.agent_id}`} onClick={e => e.stopPropagation()}
                  className="text-xs mono hover:underline" style={{ color: 'var(--accent)' }}>
                  {inc.hostname || `#${inc.agent_id}`}
                </Link>
                <span className={sevClass(inc.severity)}>{inc.severity}</span>

                <select value={inc.status} disabled={updatingId === inc.id}
                  onChange={e => updateStatus(inc.id, e.target.value)}
                  className="g-select text-[11px] py-1" style={{ width: 90 }}>
                  {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
                </select>

                {sla ? (
                  <span className="flex items-center gap-1 text-[11px]"
                    style={{ color: sla.breached ? 'var(--red)' : 'var(--text-3)' }}
                    title={sla.breached ? slaBreachDetail(inc.severity, inc.created_at) : undefined}>
                    <Clock className="h-3 w-3 shrink-0" />
                    {sla.label}
                  </span>
                ) : (
                  <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>
                    {timeAgo(inc.created_at)}
                  </span>
                )}

                <button onClick={() => openDetail(inc)} style={{ color: 'var(--text-3)' }}>
                  <ChevronRight className="h-3.5 w-3.5" />
                </button>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── Detail drawer ──────────────────────────────────────── */}
      {selected && (
        <div className="fixed inset-0 z-50 flex">
          <div className="flex-1" onClick={() => setSelected(null)} />
          <div className="w-full max-w-lg h-full overflow-y-auto"
            style={{ background: 'var(--bg-1)', borderLeft: '1px solid var(--border)' }}>

            <div className="sticky top-0 px-5 py-4 flex items-start justify-between"
              style={{ background: 'var(--bg-1)', borderBottom: '1px solid var(--border)', zIndex: 10 }}>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold truncate pr-4" style={{ color: 'var(--text-1)' }}>
                  {selected.title}
                </p>
                <div className="flex items-center gap-2 mt-1">
                  <span className={sevClass(selected.severity)}>{selected.severity}</span>
                  <span className="text-[10px] capitalize px-2 py-0.5 rounded"
                    style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                    {selected.status}
                  </span>
                  <Link href={`/agents/${selected.agent_id}`}
                    className="text-[10px] mono hover:underline" style={{ color: 'var(--accent)' }}>
                    {selected.hostname || `#${selected.agent_id}`}
                  </Link>
                </div>
              </div>
              <button onClick={() => setSelected(null)} style={{ color: 'var(--text-3)' }}>
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="p-5 space-y-5">
              <p className="text-xs leading-relaxed" style={{ color: 'var(--text-2)' }}>
                {selected.description}
              </p>

              {/* SLA breach banner */}
              {slaInfo(selected.severity, selected.created_at, selected.status)?.breached && (
                <div className="rounded-xl px-3 py-2.5 flex items-center gap-2"
                  style={{ background: 'rgba(248,81,73,0.1)', border: '1px solid rgba(248,81,73,0.3)' }}>
                  <Clock className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--red)' }} />
                  <p className="text-[11px]" style={{ color: 'var(--red)' }}>
                    {slaBreachDetail(selected.severity, selected.created_at)}
                  </p>
                  {selected.severity !== 'critical' && (
                    <button onClick={escalateSeverity} disabled={escalating}
                      className="ml-auto g-btn text-[10px] flex items-center gap-1 shrink-0"
                      style={{ background: 'rgba(248,81,73,0.15)', color: 'var(--red)', border: '1px solid rgba(248,81,73,0.4)' }}>
                      {escalating ? <Loader2 className="h-3 w-3 animate-spin" /> : <TrendingUp className="h-3 w-3" />}
                      Escalate
                    </button>
                  )}
                </div>
              )}

              {/* Linked Alerts */}
              {(linkedLoading || linkedAlerts.length > 0) && (
                <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                  <div className="px-4 py-3 flex items-center gap-2"
                    style={{ background: 'var(--glass-bg)', borderBottom: '1px solid var(--border)' }}>
                    <Bell className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
                    <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>
                      Linked Alerts {linkedAlerts.length > 0 ? `(${linkedAlerts.length})` : ''}
                    </p>
                  </div>
                  <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                    {linkedLoading ? (
                      <div className="px-4 py-3 text-xs animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
                    ) : linkedAlerts.slice(0, 6).map((a: any, i: number) => (
                      <div key={i} className="flex items-center gap-3 px-4 py-2">
                        <span className="h-1.5 w-1.5 rounded-full shrink-0"
                          style={{ background: a.severity === 'critical' ? 'var(--red)' : a.severity === 'high' ? 'var(--orange)' : 'var(--yellow)' }} />
                        <div className="flex-1 min-w-0">
                          <p className="text-[11px] truncate" style={{ color: 'var(--text-1)' }}>{a.rule_name}</p>
                          <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(a.created_at)}</p>
                        </div>
                        <span className="text-[9px] px-1.5 py-0.5 rounded font-bold uppercase"
                          style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                          {a.severity}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Status update */}
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>
                  Update Status
                </p>
                <div className="flex gap-1.5 flex-wrap">
                  {STATUSES.map(s => (
                    <button key={s} onClick={() => updateStatus(selected.id, s)}
                      disabled={updatingId === selected.id}
                      className="text-xs px-3 py-1.5 rounded-lg capitalize transition-all"
                      style={{
                        background: selected.status === s ? 'var(--accent-glow)' : 'var(--glass-bg)',
                        border: `1px solid ${selected.status === s ? 'var(--accent-border)' : 'var(--border)'}`,
                        color: selected.status === s ? 'var(--accent)' : 'var(--text-2)',
                      }}>
                      {s}
                    </button>
                  ))}
                </div>
              </div>

              {/* AI Summary */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Bot className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
                    <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
                      AI Summary
                    </p>
                  </div>
                  <button onClick={runAISummary} disabled={aiLoading}
                    className="g-btn g-btn-ghost text-[11px]" style={{ padding: '3px 10px' }}>
                    {aiLoading ? <><Loader2 className="h-3 w-3 animate-spin" /> Analyzing…</> : 'Summarize'}
                  </button>
                </div>

                {aiLoading && (
                  <div className="rounded-xl p-4 text-center"
                    style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <Loader2 className="h-5 w-5 animate-spin mx-auto mb-2" style={{ color: 'var(--accent)' }} />
                    <p className="text-xs" style={{ color: 'var(--text-3)' }}>AI analyzing incident…</p>
                  </div>
                )}

                {aiSummary && !aiLoading && (
                  <div className="space-y-3">
                    <div className="rounded-xl p-3" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                      <p className="text-xs leading-relaxed" style={{ color: 'var(--text-1)' }}>{aiSummary.summary}</p>
                    </div>
                    {aiSummary.root_cause_hint && (
                      <div className="rounded-xl p-3" style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
                        <p className="text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Root Cause Hypothesis</p>
                        <p className="text-xs" style={{ color: 'var(--accent)' }}>{aiSummary.root_cause_hint}</p>
                      </div>
                    )}
                    {aiSummary.timeline?.length > 0 && (
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>
                          AI-Inferred Attack Timeline
                        </p>
                        <div className="relative pl-4 space-y-2">
                          <div className="absolute left-1.5 top-0 bottom-0 w-px" style={{ background: 'var(--border)' }} />
                          {aiSummary.timeline.map((step, i) => (
                            <div key={i} className="relative">
                              <div className="absolute -left-3 top-1 h-2 w-2 rounded-full" style={{ background: 'var(--accent)' }} />
                              <p className="text-[11px]" style={{ color: 'var(--text-2)' }}>{step}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {aiSummary.recommended_steps?.length > 0 && (
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>
                          Recommended Steps
                        </p>
                        <div className="space-y-1.5">
                          {aiSummary.recommended_steps.map((step, i) => (
                            <div key={i} className="flex gap-2 text-xs">
                              <span className="shrink-0 font-bold" style={{ color: 'var(--accent)' }}>{i + 1}.</span>
                              <span style={{ color: 'var(--text-2)' }}>{step}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {!aiSummary && !aiLoading && (
                  <div className="rounded-xl p-3 text-center"
                    style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <p className="text-xs" style={{ color: 'var(--text-3)' }}>Click Summarize to generate AI analysis.</p>
                  </div>
                )}
              </div>

              {/* Timeline */}
              <div>
                <div className="flex items-center gap-2 mb-3">
                  <Clock className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
                  <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
                    Timeline ({events.length})
                  </p>
                </div>
                {evLoading ? (
                  <p className="text-xs animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</p>
                ) : events.length === 0 ? (
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>No events recorded yet.</p>
                ) : (
                  <div className="relative pl-4 space-y-3">
                    <div className="absolute left-1.5 top-0 bottom-0 w-px" style={{ background: 'var(--border)' }} />
                    {events.map((ev, i) => (
                      <div key={i} className="relative">
                        <div className="absolute -left-3 top-1 h-2 w-2 rounded-full" style={{ background: 'var(--accent)' }} />
                        <p className="text-xs font-medium capitalize" style={{ color: 'var(--text-2)' }}>{ev.event_type}</p>
                        <p className="text-[11px] mt-0.5" style={{ color: 'var(--text-1)' }}>{ev.details || ev.message}</p>
                        <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{formatDate(ev.created_at)}</p>
                      </div>
                    ))}
                  </div>
                )}
                <div className="flex gap-2 mt-3 pt-3" style={{ borderTop: '1px solid var(--border)' }}>
                  <input value={note} onChange={e => setNote(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && addNote()}
                    placeholder="Add investigation note…"
                    className="g-input flex-1 text-xs" />
                  <button onClick={addNote} disabled={addingNote || !note.trim()}
                    className="g-btn g-btn-primary" style={{ padding: '0 12px' }}>
                    {addingNote ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Pagination */}
      {total > PER_PAGE && (
        <div className="flex items-center justify-between mt-4">
          <p className="text-xs" style={{ color: 'var(--text-3)' }}>
            Showing {(page - 1) * PER_PAGE + 1}–{Math.min(page * PER_PAGE, total)} of {total}
          </p>
          <div className="flex items-center gap-2">
            <button onClick={() => setPage(p => p - 1)}
              disabled={page === 1} className="g-btn g-btn-ghost text-xs px-3">
              ← Prev
            </button>
            <span className="text-xs" style={{ color: 'var(--text-2)' }}>
              Page {page} of {Math.ceil(total / PER_PAGE)}
            </span>
            <button onClick={() => setPage(p => p + 1)}
              disabled={page >= Math.ceil(total / PER_PAGE)} className="g-btn g-btn-ghost text-xs px-3">
              Next →
            </button>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
