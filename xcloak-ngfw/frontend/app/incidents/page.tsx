'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { incidentsAPI } from '@/lib/api';
import { Incident } from '@/types';
import { sevClass, formatDate, timeAgo } from '@/lib/utils';
import { AlertTriangle, X, Clock, ChevronDown } from 'lucide-react';

const STATUSES = ['open','investigating','resolved','closed'] as const;
const STATUS_STYLE: Record<string, string> = {
  open:          'background:var(--red-bg);color:var(--red);border:1px solid var(--red-border)',
  investigating: 'background:var(--orange-bg);color:var(--orange);border:1px solid var(--orange-border)',
  resolved:      'background:var(--green-bg);color:var(--green);border:1px solid var(--green-border)',
  closed:        'background:rgba(74,90,117,0.15);color:var(--text-3);border:1px solid rgba(74,90,117,0.2)',
};

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [filter, setFilter]       = useState('all');
  const [selected, setSelected]   = useState<Incident | null>(null);
  const [events, setEvents]       = useState<any[]>([]);
  const [evLoading, setEvLoading] = useState(false);
  const [updatingId, setUpdatingId] = useState<number | null>(null);
  const [toast, setToast]         = useState<string | null>(null);

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try { const r = await incidentsAPI.getAll(); setIncidents(r.data || []); }
    finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const openTimeline = async (inc: Incident) => {
    setSelected(inc); setEvLoading(true);
    try { const r = await incidentsAPI.getEvents(inc.id); setEvents(r.data || []); }
    finally { setEvLoading(false); }
  };

  const updateStatus = async (id: number, status: string) => {
    setUpdatingId(id);
    try {
      await incidentsAPI.updateStatus(id, status);
      setIncidents(p => p.map(i => i.id === id ? { ...i, status: status as any } : i));
      if (selected?.id === id) setSelected(s => s ? { ...s, status: status as any } : s);
      notify(`Status updated to ${status}`);
    } finally { setUpdatingId(null); }
  };

  const filtered = filter === 'all' ? incidents : incidents.filter(i => i.status === filter);
  const counts   = STATUSES.reduce((a, s) => { a[s] = incidents.filter(i => i.status === s).length; return a; }, {} as Record<string, number>);

  return (
    <RootLayout title="Incidents" subtitle={`${incidents.length} total`}
      onRefresh={() => load(true)} refreshing={refreshing}>

      {toast && <Toast msg={toast} />}

      <div className="space-y-4">
        {/* Status tabs */}
        <div className="flex items-center gap-2 flex-wrap">
          {['all', ...STATUSES].map(s => (
            <button key={s} onClick={() => setFilter(s)}
              className="g-btn text-xs capitalize"
              style={{
                background: filter === s ? 'var(--accent-glow)' : 'var(--glass-bg)',
                color:      filter === s ? 'var(--accent)' : 'var(--text-2)',
                border:     filter === s ? '1px solid var(--accent-border)' : '1px solid var(--border)',
                backdropFilter: 'var(--blur-sm)',
              }}>
              {s} ({s === 'all' ? incidents.length : counts[s as keyof typeof counts] || 0})
            </button>
          ))}
        </div>

        {/* Table */}
        <div className="g-table">
          <div className="g-thead grid gap-4 px-4" style={{ gridTemplateColumns: '24px 1fr 120px 80px 80px 80px 70px' }}>
            <span /><span>Title</span><span>Status</span><span>Agent</span><span>Severity</span><span>Change Status</span><span>Time</span>
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
              style={{ gridTemplateColumns: '24px 1fr 120px 80px 80px 80px 70px' }}>
              <span className="h-2 w-2 rounded-full"
                style={{ background: inc.severity === 'critical' ? 'var(--red)' : inc.severity === 'high' ? 'var(--orange)' : inc.severity === 'medium' ? 'var(--yellow)' : 'var(--blue)' }} />
              <div className="min-w-0 cursor-pointer" onClick={() => openTimeline(inc)}>
                <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{inc.title}</p>
                <p className="text-[11px] truncate" style={{ color: 'var(--text-3)' }}>{inc.description}</p>
              </div>
              <span className="text-[11px] rounded px-2 py-0.5 capitalize font-medium inline-block w-fit"
                style={inc.status === 'open' ? { background: 'var(--red-bg)', color: 'var(--red)', border: '1px solid var(--red-border)' }
                  : inc.status === 'investigating' ? { background: 'var(--orange-bg)', color: 'var(--orange)', border: '1px solid var(--orange-border)' }
                  : inc.status === 'resolved' ? { background: 'var(--green-bg)', color: 'var(--green)', border: '1px solid var(--green-border)' }
                  : { background: 'rgba(74,90,117,0.15)', color: 'var(--text-3)', border: '1px solid rgba(74,90,117,0.2)' }
                }>
                {inc.status}
              </span>
              <span className="text-xs" style={{ color: 'var(--text-2)' }}>#{inc.agent_id}</span>
              <span className={sevClass(inc.severity)}>{inc.severity}</span>

              {/* Status dropdown */}
              <div className="relative">
                <select
                  value={inc.status}
                  disabled={updatingId === inc.id}
                  onChange={e => updateStatus(inc.id, e.target.value)}
                  className="g-select text-[11px] py-1"
                  style={{ width: 110 }}>
                  {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>

              <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{timeAgo(inc.created_at)}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Timeline modal */}
      {selected && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setSelected(null)}>
          <div className="g-modal">
            <div className="flex items-start justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <div>
                <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{selected.title}</h2>
                <div className="flex items-center gap-2 mt-1.5">
                  <span className={sevClass(selected.severity)}>{selected.severity}</span>
                  <span className="text-[11px] rounded px-2 py-0.5 capitalize"
                    style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                    {selected.status}
                  </span>
                  <span className="text-xs" style={{ color: 'var(--text-3)' }}>Agent #{selected.agent_id}</span>
                </div>
              </div>
              <button onClick={() => setSelected(null)} className="p-1" style={{ color: 'var(--text-2)' }}>
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="p-5">
              <div className="flex items-center gap-2 mb-4">
                <Clock className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-2)' }}>Incident Timeline</p>
              </div>

              {evLoading ? (
                <p className="text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading events…</p>
              ) : events.length === 0 ? (
                <p className="text-sm" style={{ color: 'var(--text-3)' }}>No events recorded.</p>
              ) : (
                <div className="relative pl-5 space-y-4">
                  <div className="absolute left-2 top-0 bottom-0 w-px" style={{ background: 'var(--border-md)' }} />
                  {events.map((ev, i) => (
                    <div key={i} className="relative">
                      <div className="absolute -left-3 top-1.5 h-2 w-2 rounded-full"
                        style={{ background: 'var(--accent)', boxShadow: '0 0 6px var(--accent-glow)' }} />
                      <p className="text-sm" style={{ color: 'var(--text-1)' }}>{ev.message || ev.event_type}</p>
                      <p className="text-[11px] mt-0.5" style={{ color: 'var(--text-3)' }}>{formatDate(ev.created_at)}</p>
                    </div>
                  ))}
                </div>
              )}

              {/* Status update in modal */}
              <div className="mt-5 pt-4" style={{ borderTop: '1px solid var(--border)' }}>
                <p className="text-xs mb-2" style={{ color: 'var(--text-2)' }}>Update status</p>
                <div className="flex gap-2 flex-wrap">
                  {STATUSES.map(s => (
                    <button key={s} onClick={() => updateStatus(selected.id, s)}
                      className="g-btn text-xs capitalize"
                      style={{
                        background: selected.status === s ? 'var(--accent-glow)' : 'var(--glass-bg)',
                        color:      selected.status === s ? 'var(--accent)' : 'var(--text-2)',
                        border:     `1px solid ${selected.status === s ? 'var(--accent-border)' : 'var(--border)'}`,
                        backdropFilter: 'var(--blur-sm)',
                      }}>
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}

function Toast({ msg }: { msg: string }) {
  return (
    <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ minWidth: 200, color: 'var(--text-1)' }}>
      {msg}
    </div>
  );
}
