'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { dashboardAPI, alertsAPI, incidentsAPI, agentsAPI, playbooksAPI } from '@/lib/api';
import api from '@/lib/api';
import { DashboardOverview, Alert, Incident, Agent, PlaybookExecution } from '@/types';
import { sevClass, timeAgo } from '@/lib/utils';
import { useNotifications } from '@/context/NotificationContext';
import {
  Cpu, Bell, AlertTriangle, Activity, Zap, Radio,
  TrendingUp, ShieldCheck, ShieldAlert, CircleDot,
  Clock, Target, Gauge, Trophy,
} from 'lucide-react';
import {
  PieChart, Pie, Cell, BarChart, Bar, AreaChart, Area,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';

const SEV_COLORS: Record<string, string> = {
  critical: '#f85149', high: '#fb923c', medium: '#fbbf24', low: '#38bdf8',
};

const TOOLTIP_STYLE = {
  contentStyle: {
    background: 'var(--glass-modal)',
    border: '1px solid var(--border)',
    borderRadius: 8, fontSize: 11,
    color: 'var(--text-1)',
  },
  labelStyle: { color: 'var(--text-3)', fontSize: 10 },
};

interface DashboardMetrics {
  alert_trend: Array<{ hour: string; critical: number; high: number; medium: number; low: number }>;
  mttr: { avg_seconds: number; avg_formatted: string; total_resolved: number; last_24h_seconds: number };
  alert_velocity_1h: number;
  threat_score: number;
  top_rules: Array<{ rule_name: string; count: number; severity: string }>;
  top_agents: Array<{ agent_id: number; hostname: string; count: number }>;
}

function StatCard({ label, value, sub, icon: Icon, accent, pulse }: any) {
  return (
    <div className="g-card p-5 flex flex-col gap-2 relative overflow-hidden">
      {pulse && (
        <span className="absolute top-3 right-3 h-2 w-2 rounded-full animate-pulse"
          style={{ background: accent || 'var(--accent)' }} />
      )}
      <div className="flex items-start justify-between">
        <div className="flex h-9 w-9 items-center justify-center rounded-xl"
          style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
          <Icon className="h-4 w-4" style={{ color: accent || 'var(--accent)' }} />
        </div>
      </div>
      <p className="text-2xl font-bold tabular-nums" style={{ color: 'var(--text-1)' }}>{value ?? '—'}</p>
      <p className="text-xs font-medium" style={{ color: 'var(--text-2)' }}>{label}</p>
      {sub && <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{sub}</p>}
    </div>
  );
}

// Threat score gauge — SVG arc
function ThreatGauge({ score }: { score: number }) {
  const pct   = Math.min(score, 100) / 100;
  const r     = 54;
  const circ  = Math.PI * r; // half circle
  const dash  = circ * pct;
  const color = score >= 70 ? '#f85149' : score >= 40 ? '#fb923c' : score >= 20 ? '#fbbf24' : '#34d399';
  const label = score >= 70 ? 'Critical' : score >= 40 ? 'High' : score >= 20 ? 'Medium' : 'Low';

  return (
    <div className="flex flex-col items-center">
      <svg width="140" height="80" viewBox="0 0 140 80">
        {/* Background arc */}
        <path d="M 16 74 A 54 54 0 0 1 124 74" fill="none" stroke="var(--border)" strokeWidth="10" strokeLinecap="round" />
        {/* Value arc */}
        <path d="M 16 74 A 54 54 0 0 1 124 74" fill="none" stroke={color}
          strokeWidth="10" strokeLinecap="round"
          strokeDasharray={`${dash} ${circ}`} />
        <text x="70" y="68" textAnchor="middle" fontSize="22" fontWeight="700" fill="var(--text-1)">{score}</text>
      </svg>
      <p className="text-xs font-semibold -mt-1" style={{ color }}>{label} Risk</p>
    </div>
  );
}

export default function DashboardPage() {
  const { liveAlerts } = useNotifications();
  const [overview, setOverview]     = useState<DashboardOverview | null>(null);
  const [metrics, setMetrics]       = useState<DashboardMetrics | null>(null);
  const [alerts, setAlerts]         = useState<Alert[]>([]);
  const [incidents, setIncidents]   = useState<Incident[]>([]);
  const [agents, setAgents]         = useState<Agent[]>([]);
  const [executions, setExecutions] = useState<PlaybookExecution[]>([]);
  const [loading, setLoading]       = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    const [ov, al, inc, ag, ex, mx] = await Promise.allSettled([
      dashboardAPI.getOverview(),
      alertsAPI.getAll(),
      incidentsAPI.getAll(),
      agentsAPI.getAll(),
      playbooksAPI.getExecutions(),
      api.get('/dashboard/metrics'),
    ]);
    if (ov.status  === 'fulfilled') setOverview(ov.value.data);
    if (al.status  === 'fulfilled') setAlerts((al.value.data || []).slice(0, 20));
    if (inc.status === 'fulfilled') setIncidents(inc.value.data || []);
    if (ag.status  === 'fulfilled') setAgents(ag.value.data || []);
    if (ex.status  === 'fulfilled') setExecutions((ex.value.data || []).slice(0, 12));
    if (mx.status  === 'fulfilled') setMetrics(mx.value.data);
    setLoading(false);
    setRefreshing(false);
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(() => load(), 30000);
    return () => clearInterval(t);
  }, [load]);

  const agentName = (id: number) => agents.find(a => a.id === id)?.hostname || `#${id}`;

  const onlineAgents   = agents.filter(a => a.status === 'online').length;
  const openIncidents  = incidents.filter(i => i.status === 'open' || i.status === 'investigating').length;
  const criticalAlerts = alerts.filter(a => a.severity === 'critical').length;
  const soarFired      = executions.filter(e => e.status === 'success').length;

  const sevData = ['critical','high','medium','low'].map(s => ({
    name: s, value: alerts.filter(a => a.severity === s).length,
  })).filter(d => d.value > 0);

  // Use backend trend data if available, else build from local alerts
  const trendData = metrics?.alert_trend?.length
    ? metrics.alert_trend
    : Array.from({ length: 12 }, (_, i) => {
        const h = new Date(Date.now() - (11 - i) * 3600000);
        return {
          hour: h.getHours().toString().padStart(2,'0') + ':00',
          critical: 0, high: 0, medium: 0, low: 0,
        };
      });

  return (
    <RootLayout title="Dashboard" subtitle="Security Operations Overview"
      onRefresh={() => load(true)} refreshing={refreshing}>

      <div className="space-y-5">
        {/* ── Row 1: KPI stat cards ──────────────────────────── */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <StatCard label="Online Agents"   value={onlineAgents}   sub={`${agents.length} total`}      icon={Cpu}           />
          <StatCard label="Critical Alerts" value={criticalAlerts} sub={`${alerts.length} total`}      icon={Bell}
            accent={criticalAlerts > 0 ? 'var(--red)' : undefined}
            pulse={criticalAlerts > 0} />
          <StatCard label="Open Incidents"  value={openIncidents}  sub={`${incidents.length} total`}   icon={AlertTriangle}
            accent={openIncidents > 0 ? 'var(--orange)' : undefined} />
          <StatCard label="SOAR Executed"   value={soarFired}      sub="auto-responses"                icon={Zap}
            accent={soarFired > 0 ? 'var(--green)' : undefined} />
        </div>

        {/* ── Row 2: Metrics strip (velocity, MTTR, threat score) */}
        {metrics && (
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div className="g-card p-4 flex items-center gap-3">
              <div className="h-9 w-9 rounded-xl flex items-center justify-center shrink-0"
                style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
                <Activity className="h-4 w-4" style={{ color: 'var(--accent)' }} />
              </div>
              <div>
                <p className="text-xl font-bold tabular-nums" style={{ color: 'var(--text-1)' }}>
                  {metrics.alert_velocity_1h}
                </p>
                <p className="text-xs" style={{ color: 'var(--text-3)' }}>Alerts / hour</p>
              </div>
            </div>

            <div className="g-card p-4 flex items-center gap-3">
              <div className="h-9 w-9 rounded-xl flex items-center justify-center shrink-0"
                style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
                <Clock className="h-4 w-4" style={{ color: 'var(--accent)' }} />
              </div>
              <div>
                <p className="text-xl font-bold tabular-nums" style={{ color: 'var(--text-1)' }}>
                  {metrics.mttr.avg_formatted}
                </p>
                <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                  MTTR · {metrics.mttr.total_resolved} resolved
                </p>
              </div>
            </div>

            {/* Threat Score gauge */}
            <div className="g-card p-3 flex flex-col items-center justify-center sm:col-span-2">
              <p className="text-[10px] font-semibold uppercase tracking-wider mb-1"
                style={{ color: 'var(--text-3)' }}>Platform Threat Score</p>
              <ThreatGauge score={metrics.threat_score} />
            </div>
          </div>
        )}

        {/* ── Row 3: Alert trend (stacked area) + severity pie ─ */}
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="g-card p-4">
            <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>
              Alert Trend (24h)
            </p>
            <ResponsiveContainer width="100%" height={190}>
              <AreaChart data={trendData}>
                <defs>
                  {['critical','high','medium','low'].map(s => (
                    <linearGradient key={s} id={`g-${s}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor={SEV_COLORS[s]} stopOpacity={0.3} />
                      <stop offset="95%" stopColor={SEV_COLORS[s]} stopOpacity={0} />
                    </linearGradient>
                  ))}
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                <XAxis dataKey="hour" tick={{ fontSize: 9, fill: 'var(--text-3)' }} tickLine={false} axisLine={false} interval={3} />
                <YAxis allowDecimals={false} tick={{ fontSize: 9, fill: 'var(--text-3)' }} tickLine={false} axisLine={false} />
                <Tooltip {...TOOLTIP_STYLE} />
                {['critical','high','medium','low'].map(s => (
                  <Area key={s} type="monotone" dataKey={s} stackId="1"
                    stroke={SEV_COLORS[s]} fill={`url(#g-${s})`} strokeWidth={1.5} />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="g-card p-4">
            <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>
              Alert Severity Breakdown
            </p>
            {sevData.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-40 gap-2">
                <ShieldCheck className="h-8 w-8" style={{ color: 'var(--text-3)' }} />
                <p className="text-xs" style={{ color: 'var(--text-3)' }}>No alerts yet</p>
              </div>
            ) : (
              <>
                <ResponsiveContainer width="100%" height={150}>
                  <PieChart>
                    <Pie data={sevData} cx="50%" cy="50%" innerRadius={40} outerRadius={65}
                      dataKey="value" paddingAngle={3}>
                      {sevData.map(entry => (
                        <Cell key={entry.name} fill={SEV_COLORS[entry.name] || '#64748b'} />
                      ))}
                    </Pie>
                    <Tooltip {...TOOLTIP_STYLE} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="flex flex-wrap gap-3 mt-1">
                  {sevData.map(d => (
                    <div key={d.name} className="flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-full" style={{ background: SEV_COLORS[d.name] }} />
                      <span className="text-[11px] capitalize" style={{ color: 'var(--text-2)' }}>
                        {d.name} ({d.value})
                      </span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>

        {/* ── Row 4: Top rules + Top agents (from metrics) ───── */}
        {metrics && (metrics.top_rules?.length > 0 || metrics.top_agents?.length > 0) && (
          <div className="grid gap-4 sm:grid-cols-2">
            {/* Top firing rules */}
            {metrics.top_rules?.length > 0 && (
              <div className="g-card">
                <div className="flex items-center gap-2 px-4 pt-4 pb-3"
                  style={{ borderBottom: '1px solid var(--border)' }}>
                  <Target className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                  <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Top Firing Rules (7d)</p>
                </div>
                <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                  {metrics.top_rules.slice(0, 6).map((r, i) => (
                    <div key={i} className="flex items-center gap-3 px-4 py-2.5">
                      <span className="text-[10px] font-bold w-4 tabular-nums" style={{ color: 'var(--text-3)' }}>
                        {i + 1}
                      </span>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs truncate" style={{ color: 'var(--text-1)' }}>{r.rule_name}</p>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className={sevClass(r.severity)}>{r.severity}</span>
                        <span className="text-xs font-bold tabular-nums" style={{ color: 'var(--accent)' }}>
                          {r.count}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Top noisy agents */}
            {metrics.top_agents?.length > 0 && (
              <div className="g-card">
                <div className="flex items-center gap-2 px-4 pt-4 pb-3"
                  style={{ borderBottom: '1px solid var(--border)' }}>
                  <Trophy className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                  <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Noisiest Agents (7d)</p>
                </div>
                <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                  {metrics.top_agents.map((a, i) => (
                    <div key={i} className="flex items-center gap-3 px-4 py-2.5">
                      <span className="text-[10px] font-bold w-4 tabular-nums" style={{ color: 'var(--text-3)' }}>
                        {i + 1}
                      </span>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{a.hostname}</p>
                        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Agent #{a.agent_id}</p>
                      </div>
                      <span className="text-xs font-bold tabular-nums" style={{ color: 'var(--orange)' }}>
                        {a.count} alerts
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Row 5: Live Alert Ticker ───────────────────────── */}
        <div className="g-card">
          <div className="flex items-center justify-between px-4 pt-4 pb-3"
            style={{ borderBottom: '1px solid var(--border)' }}>
            <div className="flex items-center gap-2">
              <Radio className="h-4 w-4" style={{ color: 'var(--accent)' }} />
              <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Live Alert Feed</p>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full animate-pulse" style={{ background: 'var(--green)' }} />
              <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                {liveAlerts.length > 0 ? `${liveAlerts.length} received` : 'Listening…'}
              </span>
            </div>
          </div>
          <div className="overflow-hidden" style={{ maxHeight: 220 }}>
            {liveAlerts.length === 0 ? (
              <div className="py-10 text-center">
                <Radio className="mx-auto h-7 w-7 mb-2" style={{ color: 'var(--text-3)' }} />
                <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                  Waiting for alerts via WebSocket…
                </p>
                <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                  New critical/high alerts appear here in real-time
                </p>
              </div>
            ) : (
              <div className="divide-y overflow-y-auto" style={{ borderColor: 'var(--border)', maxHeight: 220 }}>
                {liveAlerts.map((a, i) => (
                  <div key={`${a.id}-${i}`} className="flex items-center gap-3 px-4 py-2 transition-all"
                    style={{ animationDuration: '0.3s' }}>
                    <span className="h-2 w-2 rounded-full shrink-0" style={{
                      background: a.severity === 'critical' ? 'var(--red)'
                        : a.severity === 'high' ? 'var(--orange)'
                        : a.severity === 'medium' ? 'var(--yellow)'
                        : 'var(--blue)',
                      boxShadow: a.severity === 'critical' ? '0 0 6px var(--red)' : undefined,
                    }} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs truncate" style={{ color: 'var(--text-1)' }}>{a.rule_name}</p>
                      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                        {agentName(a.agent_id)}
                        {a.message && ` · ${a.message.slice(0, 40)}${a.message.length > 40 ? '…' : ''}`}
                      </p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase ${sevClass(a.severity)}`}>
                        {a.severity}
                      </span>
                      <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                        {timeAgo(a.timestamp)}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* ── Row 6: SOAR feed + Recent alerts ───────────────── */}
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="g-card">
            <div className="flex items-center justify-between px-4 pt-4 pb-3"
              style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="flex items-center gap-2">
                <Zap className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>SOAR Activity</p>
              </div>
              {executions.length > 0 && (
                <span className="text-[10px] px-2 py-0.5 rounded-full"
                  style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                  live
                </span>
              )}
            </div>
            <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {executions.length === 0 ? (
                <div className="py-10 text-center">
                  <Zap className="mx-auto h-7 w-7 mb-2" style={{ color: 'var(--text-3)' }} />
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>No SOAR executions yet.</p>
                </div>
              ) : executions.map(ex => (
                <div key={ex.id} className="flex items-center gap-3 px-4 py-2.5">
                  <span className="h-1.5 w-1.5 rounded-full shrink-0"
                    style={{ background: ex.status === 'success' ? 'var(--green)' : 'var(--red)' }} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs truncate" style={{ color: 'var(--text-1)' }}>
                      <span className="mono" style={{ color: 'var(--accent)' }}>{ex.action_type}</span>
                      <span style={{ color: 'var(--text-3)' }}> on </span>{agentName(ex.agent_id)}
                    </p>
                    <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>
                      Trigger: {ex.alert_rule}
                    </p>
                  </div>
                  <div className="shrink-0 text-right">
                    <span className={ex.status === 'success' ? 's-online' : 's-critical'}>{ex.status}</span>
                    <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{timeAgo(ex.created_at)}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="g-card">
            <div className="flex items-center gap-2 px-4 pt-4 pb-3"
              style={{ borderBottom: '1px solid var(--border)' }}>
              <Bell className="h-4 w-4" style={{ color: 'var(--accent)' }} />
              <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Recent Alerts</p>
            </div>
            <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {alerts.length === 0 ? (
                <div className="py-10 text-center">
                  <ShieldCheck className="mx-auto h-7 w-7 mb-2" style={{ color: 'var(--text-3)' }} />
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>No alerts. All clear.</p>
                </div>
              ) : alerts.slice(0, 8).map(a => (
                <div key={a.id} className="flex items-center gap-3 px-4 py-2.5">
                  <span className="h-1.5 w-1.5 rounded-full shrink-0"
                    style={{ background: SEV_COLORS[a.severity] || 'var(--text-3)' }} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs truncate" style={{ color: 'var(--text-1)' }}>{a.rule_name}</p>
                    <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>{agentName(a.agent_id)}</p>
                  </div>
                  <div className="shrink-0 text-right">
                    <span className={sevClass(a.severity)}>{a.severity}</span>
                    <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{timeAgo(a.created_at)}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── Row 6: Open incidents ───────────────────────────── */}
        {openIncidents > 0 && (
          <div className="g-card">
            <div className="flex items-center gap-2 px-4 pt-4 pb-3"
              style={{ borderBottom: '1px solid var(--border)' }}>
              <ShieldAlert className="h-4 w-4" style={{ color: 'var(--orange)' }} />
              <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>
                Open Incidents ({openIncidents})
              </p>
            </div>
            <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {incidents.filter(i => i.status === 'open' || i.status === 'investigating').slice(0, 5).map(inc => (
                <div key={inc.id} className="flex items-center gap-3 px-4 py-3">
                  <CircleDot className="h-3.5 w-3.5 shrink-0"
                    style={{ color: SEV_COLORS[inc.severity] || 'var(--text-3)' }} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{inc.title}</p>
                    <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>
                      {agentName(inc.agent_id)} · {inc.description?.slice(0, 60)}…
                    </p>
                  </div>
                  <div className="shrink-0 text-right">
                    <span className={sevClass(inc.severity)}>{inc.severity}</span>
                    <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{timeAgo(inc.created_at)}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </RootLayout>
  );
}
