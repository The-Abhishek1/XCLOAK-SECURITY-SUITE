'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { alertsAPI } from '@/lib/api';
import { Alert } from '@/types';
import { sevClass, sevDot, formatDate, timeAgo } from '@/lib/utils';
import { Bell, Search, ChevronDown, ChevronUp, Copy, Check } from 'lucide-react';

const SEVS = ['critical','high','medium','low'] as const;

export default function AlertsPage() {
  const [alerts, setAlerts]   = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch]   = useState('');
  const [sevFilter, setSevFilter] = useState<string[]>([]);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [copied, setCopied]   = useState<number | null>(null);

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try { const r = await alertsAPI.getAll(); setAlerts(r.data || []); }
    finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const toggle = (s: string) => setSevFilter(p => p.includes(s) ? p.filter(x => x !== s) : [...p, s]);

  const copy = (id: number, text: string) => {
    navigator.clipboard.writeText(text).then(() => { setCopied(id); setTimeout(() => setCopied(null), 1500); });
  };

  const filtered = alerts.filter(a => {
    const q = search.toLowerCase();
    const ms = !q || a.rule_name?.toLowerCase().includes(q) || a.log_message?.toLowerCase().includes(q)
      || a.mitre_technique?.toLowerCase().includes(q) || String(a.agent_id).includes(q);
    const mv = sevFilter.length === 0 || sevFilter.includes(a.severity);
    return ms && mv;
  });

  const counts = SEVS.reduce((acc, s) => { acc[s] = alerts.filter(a => a.severity === s).length; return acc; }, {} as Record<string, number>);

  return (
    <RootLayout title="Alerts" subtitle={`${alerts.length} total · ${filtered.length} shown`}
      onRefresh={() => load(true)} refreshing={refreshing}>
      <div className="space-y-4">

        {/* Summary chips */}
        <div className="grid grid-cols-4 gap-3">
          {SEVS.map(s => (
            <button key={s} onClick={() => toggle(s)}
              className="g-card p-3 text-left transition-all"
              style={{
                borderColor: sevFilter.includes(s) ? `var(--${s === 'critical' ? 'red' : s === 'high' ? 'orange' : s === 'medium' ? 'yellow' : 'blue'}-border)` : undefined,
                boxShadow: sevFilter.includes(s) ? `0 0 12px var(--${s === 'critical' ? 'red' : s === 'high' ? 'orange' : s === 'medium' ? 'yellow' : 'blue'}-bg)` : undefined,
              }}>
              <p className="text-xl font-bold tabular-nums" style={{ color: 'var(--text-1)' }}>{counts[s]}</p>
              <p className={`inline-block mt-1 ${sevClass(s)}`}>{s}</p>
            </button>
          ))}
        </div>

        {/* Search + filter bar */}
        <div className="flex flex-wrap gap-3 items-center">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search rules, messages, MITRE, agent ID…"
              className="g-input pl-9" />
          </div>
          <div className="flex gap-2">
            {SEVS.map(s => (
              <button key={s} onClick={() => toggle(s)}
                className="g-btn text-xs capitalize"
                style={{
                  background: sevFilter.includes(s) ? `var(--${s === 'critical' ? 'red' : s === 'high' ? 'orange' : s === 'medium' ? 'yellow' : 'blue'}-bg)` : 'var(--glass-bg)',
                  color: sevFilter.includes(s) ? `var(--${s === 'critical' ? 'red' : s === 'high' ? 'orange' : s === 'medium' ? 'yellow' : 'blue'})` : 'var(--text-2)',
                  border: `1px solid var(--${s === 'critical' ? 'red' : s === 'high' ? 'orange' : s === 'medium' ? 'yellow' : 'blue'}-border)`,
                  backdropFilter: 'var(--blur-sm)',
                }}>
                {s}
              </button>
            ))}
            {sevFilter.length > 0 && (
              <button onClick={() => setSevFilter([])} className="g-btn g-btn-ghost text-xs">Clear</button>
            )}
          </div>
        </div>

        {/* Table */}
        <div className="g-table">
          <div className="g-thead grid gap-4 px-4" style={{ gridTemplateColumns: '24px 1fr 140px 80px 80px 70px' }}>
            <span /><span>Rule / Message</span><span>MITRE</span><span>Agent</span><span>Severity</span><span>Time</span>
          </div>

          {loading ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading alerts…</div>
          ) : filtered.length === 0 ? (
            <div className="py-16 text-center">
              <Bell className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>No alerts match your filters</p>
            </div>
          ) : filtered.map(a => (
            <div key={a.id}>
              <div className="g-tr grid gap-4 items-center px-4 cursor-pointer"
                style={{ gridTemplateColumns: '24px 1fr 140px 80px 80px 70px' }}
                onClick={() => setExpanded(expanded === a.id ? null : a.id)}>
                <span className="h-2 w-2 rounded-full"
                  style={{ background: a.severity === 'critical' ? 'var(--red)' : a.severity === 'high' ? 'var(--orange)' : a.severity === 'medium' ? 'var(--yellow)' : 'var(--blue)' }} />
                <div className="min-w-0">
                  <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{a.rule_name}</p>
                  <p className="text-[11px] truncate" style={{ color: 'var(--text-3)' }}>{a.log_message}</p>
                </div>
                <div>
                  {a.mitre_technique
                    ? <span className="mono rounded px-2 py-0.5" style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)', fontSize: 10 }}>{a.mitre_technique}</span>
                    : <span style={{ color: 'var(--text-3)' }}>—</span>}
                </div>
                <span className="text-xs" style={{ color: 'var(--text-2)' }}>#{a.agent_id}</span>
                <span className={sevClass(a.severity)}>{a.severity}</span>
                <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{timeAgo(a.created_at)}</span>
              </div>

              {/* Expanded detail */}
              {expanded === a.id && (
                <div className="px-4 pb-4 pt-3" style={{ background: 'var(--accent-glow)', borderBottom: '1px solid var(--border)' }}>
                  <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-xs sm:grid-cols-3">
                    {[
                      ['Alert ID', String(a.id)],
                      ['Agent ID', String(a.agent_id)],
                      ['MITRE Tactic', a.mitre_tactic || '—'],
                      ['MITRE Technique', a.mitre_technique || '—'],
                      ['MITRE Name', a.mitre_name || '—'],
                      ['Created', formatDate(a.created_at)],
                    ].map(([k, v]) => (
                      <div key={k}>
                        <p style={{ color: 'var(--text-3)' }}>{k}</p>
                        <p className="font-medium mt-0.5" style={{ color: 'var(--text-1)' }}>{v}</p>
                      </div>
                    ))}
                    <div className="col-span-2 sm:col-span-3">
                      <p style={{ color: 'var(--text-3)' }}>Fingerprint</p>
                      <div className="flex items-center gap-2 mt-0.5">
                        <p className="mono break-all" style={{ color: 'var(--text-2)' }}>{a.fingerprint || '—'}</p>
                        {a.fingerprint && (
                          <button onClick={() => copy(a.id, a.fingerprint!)} style={{ color: 'var(--text-3)', shrink: 0 }}>
                            {copied === a.id ? <Check className="h-3.5 w-3.5" style={{ color: 'var(--green)' }} /> : <Copy className="h-3.5 w-3.5" />}
                          </button>
                        )}
                      </div>
                    </div>
                    <div className="col-span-2 sm:col-span-3">
                      <p style={{ color: 'var(--text-3)' }}>Log message</p>
                      <p className="mt-0.5 break-all" style={{ color: 'var(--text-1)' }}>{a.log_message}</p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </RootLayout>
  );
}
