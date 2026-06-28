'use client';

import { useState, useEffect } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { socAPI } from '@/lib/api';
import { SOCMetrics, AnalystMetrics } from '@/types';
import { Users, Clock, CheckCircle, AlertTriangle, TrendingUp } from 'lucide-react';

function MiniBar({ data, color = 'var(--accent)' }: { data: Array<{ count: number; date: string }>; color?: string }) {
  const max = Math.max(...data.map(d => d.count), 1);
  return (
    <div className="flex items-end gap-px h-12">
      {data.map((d, i) => (
        <div key={i} className="flex-1 flex flex-col items-center" title={`${d.date}: ${d.count}`}>
          <div className="w-full rounded-t-sm" style={{
            height: `${Math.max(2, (d.count / max) * 44)}px`,
            background: color, opacity: 0.4 + (d.count / max) * 0.6,
          }} />
        </div>
      ))}
    </div>
  );
}

function AnalystCard({ a }: { a: AnalystMetrics }) {
  const mttrH = (a.avg_triage_minutes / 60).toFixed(1);
  const initials = a.username.slice(0, 2).toUpperCase();
  return (
    <div className="g-card p-4">
      <div className="flex items-center gap-3 mb-3">
        <div className="w-9 h-9 rounded-full flex items-center justify-center text-sm font-bold"
          style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>
          {initials}
        </div>
        <div>
          <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{a.username}</p>
          {a.last_active && (
            <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
              Last active {new Date(a.last_active).toLocaleDateString()}
            </p>
          )}
        </div>
        {a.open_backlog > 0 && (
          <span className="ml-auto text-[11px] px-2 py-0.5 rounded-full font-bold"
            style={{ background: 'rgba(248,81,73,0.15)', color: '#f85149' }}>
            {a.open_backlog} open
          </span>
        )}
      </div>
      <div className="grid grid-cols-3 gap-3">
        <div className="text-center">
          <p className="text-lg font-bold" style={{ color: 'var(--accent)' }}>{a.triaged}</p>
          <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Triaged</p>
        </div>
        <div className="text-center">
          <p className="text-lg font-bold" style={{ color: '#22c55e' }}>{a.resolved}</p>
          <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Resolved</p>
        </div>
        <div className="text-center">
          <p className="text-lg font-bold" style={{ color: '#fbbf24' }}>{mttrH}h</p>
          <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Avg MTTR</p>
        </div>
      </div>
      {/* Triage rate bar */}
      {a.triaged > 0 && (
        <div className="mt-3">
          <div className="flex justify-between text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>
            <span>Resolution rate</span>
            <span>{a.triaged > 0 ? Math.round((a.resolved / a.triaged) * 100) : 0}%</span>
          </div>
          <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--glass-bg-2)' }}>
            <div className="h-full rounded-full" style={{
              width: `${a.triaged > 0 ? (a.resolved / a.triaged) * 100 : 0}%`,
              background: 'var(--accent)',
            }} />
          </div>
        </div>
      )}
    </div>
  );
}

export default function SOCMetricsPage() {
  const [metrics, setMetrics] = useState<SOCMetrics | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    socAPI.getMetrics().then(r => { setMetrics(r.data); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  const m = metrics;

  return (
    <RootLayout title="SOC Performance" subtitle="Analyst metrics · MTTR · Alert backlog trends">
      {loading ? (
        <div className="py-24 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading SOC metrics…</div>
      ) : !m ? (
        <div className="py-24 text-center text-sm" style={{ color: 'var(--text-3)' }}>Failed to load metrics.</div>
      ) : (
        <div className="space-y-6">

          {/* Top KPIs */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: 'Open Backlog', value: m.total_open, icon: AlertTriangle, color: '#f85149', warn: m.total_open > 20 },
              { label: 'Acknowledged', value: m.total_acked, icon: CheckCircle, color: 'var(--accent)' },
              { label: 'Resolved', value: m.total_resolved, icon: CheckCircle, color: '#22c55e' },
              { label: 'Avg MTTR', value: `${(m.avg_mttr_minutes / 60).toFixed(1)}h`, icon: Clock, color: '#fbbf24', warn: m.avg_mttr_minutes > 240 },
            ].map(({ label, value, icon: Icon, color, warn }) => (
              <div key={label} className="g-card p-4 flex items-center gap-3">
                <div className="p-2 rounded-lg" style={{ background: `${color}18` }}>
                  <Icon className="h-4 w-4" style={{ color }} />
                </div>
                <div>
                  <p className="text-xl font-bold" style={{ color: warn ? '#f85149' : 'var(--text-1)' }}>{value}</p>
                  <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{label}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="g-card p-5">
              <div className="flex items-center gap-2 mb-3">
                <TrendingUp className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Alert Volume — Last 14 Days</p>
              </div>
              {(m.alerts_by_day ?? []).length > 0 ? (
                <>
                  <MiniBar data={m.alerts_by_day ?? []} />
                  <div className="flex justify-between text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                    <span>{m.alerts_by_day[0]?.date}</span>
                    <span>{m.alerts_by_day[m.alerts_by_day.length - 1]?.date}</span>
                  </div>
                </>
              ) : <p className="text-xs py-6 text-center" style={{ color: 'var(--text-3)' }}>No alert data yet.</p>}
            </div>

            <div className="g-card p-5">
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle className="h-4 w-4" style={{ color: '#f85149' }} />
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Open Backlog — Last 14 Days</p>
              </div>
              {(m.backlog_trend ?? []).length > 0 ? (
                <>
                  <MiniBar data={m.backlog_trend ?? []} color="#f85149" />
                  <div className="flex justify-between text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                    <span>{m.backlog_trend[0]?.date}</span>
                    <span>{m.backlog_trend[m.backlog_trend.length - 1]?.date}</span>
                  </div>
                </>
              ) : <p className="text-xs py-6 text-center" style={{ color: 'var(--text-3)' }}>No backlog data yet.</p>}
            </div>
          </div>

          {/* Analyst cards */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Users className="h-4 w-4" style={{ color: 'var(--accent)' }} />
              <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Analyst Leaderboard</p>
            </div>
            {(m.analysts ?? []).length === 0 ? (
              <div className="g-card p-8 text-center">
                <p className="text-sm" style={{ color: 'var(--text-3)' }}>
                  No analyst activity yet. Metrics populate as analysts acknowledge and resolve alerts.
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {(m.analysts ?? []).map(a => <AnalystCard key={a.username} a={a} />)}
              </div>
            )}
          </div>

        </div>
      )}
    </RootLayout>
  );
}
