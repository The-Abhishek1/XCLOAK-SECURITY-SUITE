'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { agentsAPI } from '@/lib/api';
import { TimelineEvent, Agent } from '@/types';
import { formatDate, timeAgo } from '@/lib/utils';
import { Clock, Search, AlertTriangle, Play, Shield, Activity, ChevronDown } from 'lucide-react';

const EVENT_ICONS: Record<string, any> = {
  alert:     AlertTriangle,
  playbook:  Play,
  detection: Shield,
  process:   Activity,
  default:   Clock,
};

const EVENT_COLORS: Record<string, string> = {
  alert:     'var(--red)',
  critical:  'var(--red)',
  high:      'var(--orange)',
  playbook:  'var(--accent)',
  detection: 'var(--yellow)',
  process:   'var(--blue)',
};

export default function TimelinePage() {
  const [agents, setAgents]       = useState<Agent[]>([]);
  const [selected, setSelected]   = useState<number | 'all'>('all');
  const [events, setEvents]       = useState<(TimelineEvent & { hostname?: string })[]>([]);
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch]       = useState('');
  const [typeFilter, setTypeFilter] = useState('all');

  const load = useCallback(async (agentId: number | 'all' = selected, spin = false) => {
    if (spin) setRefreshing(true);
    setLoading(true);
    try {
      const agRes = await agentsAPI.getAll();
      const agentList: Agent[] = agRes.data || [];
      setAgents(agentList);

      const targets = agentId === 'all' ? agentList : agentList.filter(a => a.id === agentId);

      const all: (TimelineEvent & { hostname?: string })[] = [];

      await Promise.allSettled(
        targets.map(async (a) => {
          const r = await agentsAPI.getTimeline(a.id);
          const evts = (r.data || []).map((e: TimelineEvent) => ({ ...e, hostname: a.hostname }));
          all.push(...evts);
        })
      );

      // Sort newest first
      all.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
      setEvents(all);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [selected]);

  useEffect(() => { load(); }, []);

  const changeAgent = (id: number | 'all') => {
    setSelected(id);
    load(id);
  };

  const allTypes = [...new Set(events.map(e => e.event_type))];

  const filtered = events.filter(e => {
    const matchType   = typeFilter === 'all' || e.event_type === typeFilter;
    const matchSearch = !search || e.message?.toLowerCase().includes(search.toLowerCase());
    return matchType && matchSearch;
  });

  return (
    <RootLayout title="Timeline" subtitle="Cross-agent security event chronology"
      onRefresh={() => load(selected, true)} refreshing={refreshing}>

      <div className="space-y-4">
        {/* Controls */}
        <div className="flex items-center gap-3 flex-wrap">
          <select value={selected} onChange={e => changeAgent(e.target.value === 'all' ? 'all' : Number(e.target.value))}
            className="g-select" style={{ minWidth: 180 }}>
            <option value="all">All Agents ({agents.length})</option>
            {agents.map(a => <option key={a.id} value={a.id}>{a.hostname} (#{a.id})</option>)}
          </select>

          <div className="relative flex-1 min-w-[160px] max-w-xs">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search events…" className="g-input pl-9" />
          </div>

          <div className="flex items-center gap-1 flex-wrap">
            {['all', ...allTypes].map(t => (
              <button key={t} onClick={() => setTypeFilter(t)}
                className="text-xs px-2.5 py-1.5 rounded-lg capitalize transition-all"
                style={{
                  background: typeFilter === t ? 'var(--accent-glow)' : 'var(--glass-bg)',
                  border:     `1px solid ${typeFilter === t ? 'var(--accent-border)' : 'var(--border)'}`,
                  color:      typeFilter === t ? 'var(--accent)' : 'var(--text-2)',
                }}>
                {t}
              </button>
            ))}
          </div>

          <span className="text-xs" style={{ color: 'var(--text-3)' }}>
            {filtered.length} events
          </span>
        </div>

        {/* Timeline */}
        {loading ? (
          <div className="py-16 text-center animate-pulse text-sm" style={{ color: 'var(--text-3)' }}>
            Loading timeline…
          </div>
        ) : filtered.length === 0 ? (
          <div className="g-card py-16 text-center">
            <Clock className="mx-auto h-10 w-10 mb-3" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No timeline events found.</p>
            <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>
              Dispatch collection tasks to agents to generate events.
            </p>
          </div>
        ) : (
          <div className="relative pl-6">
            {/* Vertical line */}
            <div className="absolute left-[11px] top-0 bottom-0 w-px"
              style={{ background: 'var(--border)' }} />

            <div className="space-y-3">
              {filtered.map((ev, i) => {
                const Icon  = EVENT_ICONS[ev.event_type] || EVENT_ICONS.default;
                const color = EVENT_COLORS[ev.event_type] || EVENT_COLORS[ev.severity as string] || 'var(--accent)';

                return (
                  <div key={ev.id || i} className="relative flex items-start gap-3">
                    {/* Node */}
                    <div className="absolute -left-6 flex h-5 w-5 items-center justify-center rounded-full shrink-0"
                      style={{ background: 'var(--bg-1)', border: `2px solid ${color}` }}>
                      <Icon className="h-2.5 w-2.5" style={{ color }} />
                    </div>

                    {/* Card */}
                    <div className="flex-1 ml-2 rounded-xl px-4 py-3 transition-all"
                      style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}
                      onMouseEnter={e => (e.currentTarget as HTMLElement).style.borderColor = 'var(--accent-border)'}
                      onMouseLeave={e => (e.currentTarget as HTMLElement).style.borderColor = 'var(--border)'}>
                      <div className="flex items-center justify-between gap-3">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="text-[10px] font-bold uppercase rounded px-1.5 py-0.5 shrink-0"
                            style={{ background: `${color}22`, color, border: `1px solid ${color}44` }}>
                            {ev.event_type}
                          </span>
                          {ev.hostname && (
                            <span className="mono text-[10px] shrink-0" style={{ color: 'var(--accent)' }}>
                              {ev.hostname}
                            </span>
                          )}
                        </div>
                        <span className="text-[10px] shrink-0" style={{ color: 'var(--text-3)' }}>
                          {timeAgo(ev.created_at)}
                        </span>
                      </div>
                      <p className="text-xs mt-1.5 leading-relaxed" style={{ color: 'var(--text-1)' }}>
                        {ev.message}
                      </p>
                      <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                        {formatDate(ev.created_at)}
                      </p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </RootLayout>
  );
}
