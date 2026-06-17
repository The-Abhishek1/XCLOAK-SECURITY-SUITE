'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { incidentsAPI, aiAPI } from '@/lib/api';
import api from '@/lib/api';
import { Incident } from '@/types';
import { sevClass, formatDate, timeAgo } from '@/lib/utils';
import {
  AlertTriangle, X, Clock, Bot, Loader2,
  MessageSquare, Send, ChevronRight,
} from 'lucide-react';

const STATUSES = ['open','investigating','resolved','closed'] as const;

interface AISummary {
  summary: string;
  timeline: string[];
  root_cause_hint: string;
  recommended_steps: string[];
}

export default function IncidentsPage() {
  const [incidents, setIncidents]   = useState<Incident[]>([]);
  const [loading, setLoading]       = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [filter, setFilter]         = useState('all');
  const [selected, setSelected]     = useState<Incident | null>(null);
  const [events, setEvents]         = useState<any[]>([]);
  const [evLoading, setEvLoading]   = useState(false);
  const [updatingId, setUpdatingId] = useState<number | null>(null);
  const [toast, setToast]           = useState<string | null>(null);
  const [aiSummary, setAiSummary]   = useState<AISummary | null>(null);
  const [aiLoading, setAiLoading]   = useState(false);
  const [note, setNote]             = useState('');
  const [addingNote, setAddingNote] = useState(false);
  const [page, setPage]             = useState(1);
  const [total, setTotal]           = useState(0);
  const PER_PAGE = 25;

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try { const r = await incidentsAPI.getAll(); setIncidents(r.data || []); }
    finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const openDetail = async (inc: Incident) => {
    setSelected(inc);
    setAiSummary(null);
    setNote('');
    setEvLoading(true);
    try { const r = await incidentsAPI.getEvents(inc.id); setEvents(r.data || []); }
    finally { setEvLoading(false); }
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

  const filtered = filter === 'all' ? incidents : incidents.filter(i => i.status === filter);
  const counts   = STATUSES.reduce((a, s) => {
    a[s] = incidents.filter(i => i.status === s).length;
    return a;
  }, {} as Record<string, number>);

  return (
    <RootLayout title="Incidents" subtitle={`${incidents.length} total`}
      onRefresh={() => load(true)} refreshing={refreshing}>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)' }}>
          {toast}
        </div>
      )}

      <div className="space-y-4">
        {/* Status filter tabs */}
        <div className="flex items-center gap-2 flex-wrap">
          {['all', ...STATUSES].map(s => (
            <button key={s} onClick={() => setFilter(s)}
              className="g-btn text-xs capitalize"
              style={{
                background: filter === s ? 'var(--accent-glow)' : 'var(--glass-bg)',
                color:      filter === s ? 'var(--accent)' : 'var(--text-2)',
                border:     filter === s ? '1px solid var(--accent-border)' : '1px solid var(--border)',
              }}>
              {s} ({s === 'all' ? incidents.length : counts[s as keyof typeof counts] || 0})
            </button>
          ))}
        </div>

        {/* Table */}
        <div className="g-table">
          <div className="g-thead grid gap-4 px-4"
            style={{ gridTemplateColumns: '16px 1fr 110px 70px 80px 100px 60px 24px' }}>
            <span /><span>Title</span><span>Status</span>
            <span>Agent</span><span>Severity</span><span>Change</span><span>Time</span><span />
          </div>

          {loading ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          ) : filtered.length === 0 ? (
            <div className="py-16 text-center">
              <AlertTriangle className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>No incidents</p>
            </div>
          ) : filtered.map(inc => (
            <div key={inc.id} className="g-tr grid gap-4 items-center px-4"
              style={{ gridTemplateColumns: '16px 1fr 110px 70px 80px 100px 60px 24px' }}>
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

              <span className="text-xs" style={{ color: 'var(--text-2)' }}>#{inc.agent_id}</span>
              <span className={sevClass(inc.severity)}>{inc.severity}</span>

              <select value={inc.status} disabled={updatingId === inc.id}
                onChange={e => updateStatus(inc.id, e.target.value)}
                className="g-select text-[11px] py-1" style={{ width: 110 }}>
                {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>

              <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{timeAgo(inc.created_at)}</span>

              <button onClick={() => openDetail(inc)} style={{ color: 'var(--text-3)' }}>
                <ChevronRight className="h-3.5 w-3.5" />
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* ── Detail drawer ──────────────────────────────────────── */}
      {selected && (
        <div className="fixed inset-0 z-50 flex">
          <div className="flex-1" onClick={() => setSelected(null)} />

          <div className="w-full max-w-lg h-full overflow-y-auto"
            style={{ background: 'var(--bg-1)', borderLeft: '1px solid var(--border)' }}>

            {/* Header */}
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
                  <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>Agent #{selected.agent_id}</span>
                </div>
              </div>
              <button onClick={() => setSelected(null)} style={{ color: 'var(--text-3)' }}>
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="p-5 space-y-5">
              {/* Description */}
              <p className="text-xs leading-relaxed" style={{ color: 'var(--text-2)' }}>
                {selected.description}
              </p>

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
                        <div className="absolute -left-3 top-1 h-2 w-2 rounded-full"
                          style={{ background: 'var(--accent)' }} />
                        <p className="text-xs font-medium capitalize" style={{ color: 'var(--text-2)' }}>
                          {ev.event_type}
                        </p>
                        <p className="text-[11px] mt-0.5" style={{ color: 'var(--text-1)' }}>
                          {ev.details || ev.message}
                        </p>
                        <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>
                          {formatDate(ev.created_at)}
                        </p>
                      </div>
                    ))}
                  </div>
                )}

                {/* Add note */}
                <div className="flex gap-2 mt-3 pt-3" style={{ borderTop: '1px solid var(--border)' }}>
                  <input value={note} onChange={e => setNote(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && addNote()}
                    placeholder="Add investigation note…"
                    className="g-input flex-1 text-xs" />
                  <button onClick={addNote} disabled={addingNote || !note.trim()}
                    className="g-btn g-btn-primary" style={{ padding: '0 12px' }}>
                    {addingNote
                      ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      : <Send className="h-3.5 w-3.5" />}
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
            <button onClick={() => { const p = page - 1; setPage(p); load(true); }}
              disabled={page === 1} className="g-btn g-btn-ghost text-xs px-3">
              ← Prev
            </button>
            <span className="text-xs" style={{ color: 'var(--text-2)' }}>
              Page {page} of {Math.ceil(total / PER_PAGE)}
            </span>
            <button onClick={() => { const p = page + 1; setPage(p); load(true); }}
              disabled={page >= Math.ceil(total / PER_PAGE)} className="g-btn g-btn-ghost text-xs px-3">
              Next →
            </button>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
