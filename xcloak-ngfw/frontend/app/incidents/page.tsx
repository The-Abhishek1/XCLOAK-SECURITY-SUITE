'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { incidentsAPI, aiAPI } from '@/lib/api';
import api from '@/lib/api';
import { Incident } from '@/types';
import { sevClass, formatDate, timeAgo } from '@/lib/utils';
import {
  AlertTriangle, X, Clock, Bot, Loader2,
  MessageSquare, Send, ChevronRight, FileSearch, CheckCircle,
  Shield, Activity,
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
  const [deepDive, setDeepDive]     = useState<any | null>(null);
  const [deepLoading, setDeepLoading] = useState(false);
  const [showDeepDive, setShowDeepDive] = useState(false);
  const [note, setNote]             = useState('');
  const [addingNote, setAddingNote] = useState(false);

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
                  <div className="flex items-center gap-2">
                    <button onClick={runAISummary} disabled={aiLoading}
                      className="g-btn g-btn-ghost text-[11px]" style={{ padding: '3px 10px' }}>
                      {aiLoading ? <><Loader2 className="h-3 w-3 animate-spin" /> Analyzing…</> : 'Summarize'}
                    </button>
                    <button
                      disabled={deepLoading}
                      onClick={async () => {
                        setDeepLoading(true);
                        try {
                          const r = await api.get(`/incidents/${selected.id}/deepdive`);
                          setDeepDive(r.data);
                          setShowDeepDive(true);
                        } catch { notify('Deep-dive failed'); }
                        finally { setDeepLoading(false); }
                      }}
                      className="g-btn g-btn-primary text-[11px]" style={{ padding: '3px 10px' }}>
                      {deepLoading
                        ? <><Loader2 className="h-3 w-3 animate-spin" /> Loading…</>
                        : <><FileSearch className="h-3 w-3" /> Deep-Dive</>}
                    </button>
                  </div>
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

      {/* ── Deep-Dive Report Modal ─────────────────────────── */}
      {showDeepDive && deepDive && (
        <div className="fixed inset-0 z-50 flex items-start justify-center pt-10 px-4"
          style={{ background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)' }}
          onClick={e => e.target === e.currentTarget && setShowDeepDive(false)}>
          <div className="w-full max-w-2xl max-h-[85vh] overflow-y-auto rounded-2xl"
            style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>

            {/* Header */}
            <div className="sticky top-0 flex items-center justify-between px-5 py-4"
              style={{ background: 'var(--bg-1)', borderBottom: '1px solid var(--border)', zIndex: 10 }}>
              <div className="flex items-center gap-2">
                <FileSearch className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
                  Incident Deep-Dive Report
                </p>
              </div>
              <button onClick={() => setShowDeepDive(false)} style={{ color: 'var(--text-2)' }}>
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="p-5 space-y-5">
              {/* Title + severity */}
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className={sevClass(deepDive.severity)}>{deepDive.severity}</span>
                  <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                    Generated {new Date(deepDive.generated_at).toLocaleString()}
                  </span>
                </div>
                <p className="text-base font-bold" style={{ color: 'var(--text-1)' }}>{deepDive.title}</p>
              </div>

              {/* Affected asset */}
              <div className="g-card p-4">
                <p className="text-[10px] font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>
                  Affected Asset
                </p>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  {[
                    ['Host', deepDive.affected_asset?.hostname || '—'],
                    ['IP', deepDive.affected_asset?.ip_address || '—'],
                    ['OS', deepDive.affected_asset?.os || '—'],
                    ['Status', deepDive.affected_asset?.status || '—'],
                    ['Risk Level', deepDive.affected_asset?.risk_level || '—'],
                    ['Agent ID', `#${deepDive.affected_asset?.agent_id}`],
                  ].map(([k, v]) => (
                    <div key={k} className="flex justify-between gap-2">
                      <span style={{ color: 'var(--text-3)' }}>{k}</span>
                      <span className="font-medium" style={{ color: 'var(--text-1)' }}>{v}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* AI Summary */}
              {deepDive.ai_summary && (
                <div className="rounded-xl p-4"
                  style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
                  <div className="flex items-center gap-2 mb-2">
                    <Bot className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
                    <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--accent)' }}>
                      AI Analysis
                    </p>
                  </div>
                  <p className="text-xs leading-relaxed" style={{ color: 'var(--text-2)' }}>{deepDive.ai_summary}</p>
                </div>
              )}

              {/* Recommendations */}
              {deepDive.recommendations?.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>
                    Recommendations
                  </p>
                  <div className="space-y-1.5">
                    {deepDive.recommendations.map((r: string, i: number) => (
                      <div key={i} className="flex items-start gap-2">
                        <CheckCircle className="h-3.5 w-3.5 shrink-0 mt-0.5" style={{ color: 'var(--green)' }} />
                        <p className="text-xs" style={{ color: 'var(--text-2)' }}>{r}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* MITRE Coverage */}
              {deepDive.mitre_coverage?.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>
                    MITRE ATT&CK Coverage
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {deepDive.mitre_coverage.map((t: string) => (
                      <span key={t} className="mono text-[10px] px-2 py-0.5 rounded"
                        style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--accent)' }}>
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Indicators */}
              {deepDive.indicators?.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>
                    Observed Indicators
                  </p>
                  <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                    {deepDive.indicators.map((ind: any, i: number) => (
                      <div key={i} className="flex items-center gap-3 px-3 py-2"
                        style={{ borderBottom: i < deepDive.indicators.length - 1 ? '1px solid var(--border)' : undefined }}>
                        <span className="text-[10px] px-1.5 py-0.5 rounded font-medium shrink-0"
                          style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-3)' }}>
                          {ind.type}
                        </span>
                        <span className="mono text-[11px] flex-1 truncate" style={{ color: 'var(--text-1)' }}>
                          {ind.value}
                        </span>
                        <span className="text-[10px] shrink-0" style={{ color: 'var(--text-3)' }}>
                          {ind.context}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Timeline */}
              {deepDive.timeline?.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>
                    Timeline ({deepDive.timeline.length} events)
                  </p>
                  <div className="space-y-1.5">
                    {deepDive.timeline.slice(0, 15).map((ev: any, i: number) => (
                      <div key={i} className="flex items-start gap-3">
                        <span className="h-1.5 w-1.5 rounded-full mt-1.5 shrink-0"
                          style={{ background: ev.severity === 'critical' ? 'var(--red)' : ev.severity === 'high' ? 'var(--orange)' : 'var(--text-3)' }} />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{ev.title}</p>
                          {ev.detail && <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>{ev.detail}</p>}
                        </div>
                        <span className="text-[10px] shrink-0" style={{ color: 'var(--text-3)' }}>
                          {timeAgo(ev.timestamp)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
