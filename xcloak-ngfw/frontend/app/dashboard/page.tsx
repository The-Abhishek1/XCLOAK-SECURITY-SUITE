'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { dashboardAPI, alertsAPI, incidentsAPI, agentsAPI, playbooksAPI } from '@/lib/api';
import { DashboardOverview, Alert, Incident, Agent, PlaybookExecution } from '@/types';
import { sevClass, timeAgo } from '@/lib/utils';
import {
  Cpu, Bell, AlertTriangle, Activity, Zap,
  TrendingUp, ShieldCheck, ShieldAlert, CircleDot,
} from 'lucide-react';
import {
  PieChart, Pie, Cell, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts';

const SEV_COLORS: Record<string, string> = {
  critical: '#f85149', high: '#fb923c', medium: '#fbbf24', low: '#38bdf8',
};

const TOOLTIP_STYLE = {
  contentStyle: {
    background: 'var(--glass-modal)',
    border: '1px solid var(--border-md)',
    borderRadius: 8, fontSize: 12,
    color: 'var(--text-1)',
  },
};

function StatCard({ label, value, sub, icon: Icon, accent }: any) {
  return (
    <div className="g-card p-5 flex flex-col gap-2">
      <div className="flex items-start justify-between">
        <div className="flex h-9 w-9 items-center justify-center rounded-xl"
          style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
          <Icon className="h-4 w-4" style={{ color: accent || 'var(--accent)' }} />
        </div>
        <TrendingUp className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
      </div>
      <p className="text-2xl font-bold tabular-nums" style={{ color: 'var(--text-1)' }}>{value ?? '—'}</p>
      <p className="text-xs font-medium" style={{ color: 'var(--text-2)' }}>{label}</p>
      {sub && <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{sub}</p>}
    </div>
  );
}

export default function DashboardPage() {
  const [overview, setOverview]       = useState<DashboardOverview | null>(null);
  const [alerts, setAlerts]           = useState<Alert[]>([]);
  const [incidents, setIncidents]     = useState<Incident[]>([]);
  const [agents, setAgents]           = useState<Agent[]>([]);
  const [executions, setExecutions]   = useState<PlaybookExecution[]>([]);
  const [loading, setLoading]         = useState(true);
  const [refreshing, setRefreshing]   = useState(false);

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    const [ov, al, inc, ag, ex] = await Promise.allSettled([
      dashboardAPI.getOverview(),
      alertsAPI.getAll(),
      incidentsAPI.getAll(),
      agentsAPI.getAll(),
      playbooksAPI.getExecutions(),
    ]);
    if (ov.status  === 'fulfilled') setOverview(ov.value.data);
    if (al.status  === 'fulfilled') setAlerts((al.value.data || []).slice(0, 20));
    if (inc.status === 'fulfilled') setIncidents(inc.value.data || []);
    if (ag.status  === 'fulfilled') setAgents(ag.value.data || []);
    if (ex.status  === 'fulfilled') setExecutions((ex.value.data || []).slice(0, 12));
    setLoading(false);
    setRefreshing(false);
  }, []);

  useEffect(() => { load(); const t = setInterval(() => load(), 30000); return () => clearInterval(t); }, [load]);

  // Severity breakdown for pie chart
  const sevData = ['critical','high','medium','low'].map(s => ({
    name: s, value: alerts.filter(a => a.severity === s).length,
  })).filter(d => d.value > 0);

  // Alert timeline by hour (last 12h)
  const now = Date.now();
  const hourlyData = Array.from({ length: 12 }, (_, i) => {
    const h = new Date(now - (11 - i) * 3600000);
    const label = h.getHours().toString().padStart(2, '0') + ':00';
    const count = alerts.filter(a => {
      const t = new Date(a.created_at).getTime();
      return t >= h.getTime() && t < h.getTime() + 3600000;
    }).length;
    return { label, count };
  });

  const onlineAgents = agents.filter(a => a.status === 'online').length;
  const openIncidents = incidents.filter(i => i.status === 'open').length;
  const criticalAlerts = alerts.filter(a => a.severity === 'critical').length;
  const soarFired = executions.filter(e => e.status === 'success').length;

  return (
    <RootLayout title="Dashboard" subtitle="Security Operations Overview"
      onRefresh={() => load(true)} refreshing={refreshing}>

      <div className="space-y-5">
        {/* Stat cards */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <StatCard label="Online Agents" value={onlineAgents}
            sub={`${agents.length} total`} icon={Cpu} />
          <StatCard label="Critical Alerts" value={criticalAlerts}
            sub={`${alerts.length} total`} icon={Bell}
            accent={criticalAlerts > 0 ? 'var(--red)' : undefined} />
          <StatCard label="Open Incidents" value={openIncidents}
            sub={`${incidents.length} total`} icon={AlertTriangle}
            accent={openIncidents > 0 ? 'var(--orange)' : undefined} />
          <StatCard label="SOAR Executed" value={soarFired}
            sub="auto-responses" icon={Zap}
            accent={soarFired > 0 ? 'var(--green)' : undefined} />
        </div>

        {/* Charts row */}
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="g-card p-4">
            <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Alert Severity Breakdown</p>
            {sevData.length === 0 ? (
              <div className="flex items-center justify-center h-32">
                <p className="text-xs" style={{ color: 'var(--text-3)' }}>No alerts yet</p>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie data={sevData} cx="50%" cy="50%" innerRadius={45} outerRadius={70}
                    dataKey="value" paddingAngle={3}>
                    {sevData.map((entry) => (
                      <Cell key={entry.name} fill={SEV_COLORS[entry.name] || '#64748b'} />
                    ))}
                  </Pie>
                  <Tooltip {...TOOLTIP_STYLE} />
                </PieChart>
              </ResponsiveContainer>
            )}
            <div className="flex flex-wrap gap-3 mt-2">
              {sevData.map(d => (
                <div key={d.name} className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full" style={{ background: SEV_COLORS[d.name] }} />
                  <span className="text-[11px] capitalize" style={{ color: 'var(--text-2)' }}>{d.name} ({d.value})</span>
                </div>
              ))}
            </div>
          </div>

          <div className="g-card p-4">
            <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Alert Volume (Last 12h)</p>
            <ResponsiveContainer width="100%" height={190}>
              <BarChart data={hourlyData} barSize={14}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                <XAxis dataKey="label" tick={{ fontSize: 9, fill: 'var(--text-3)' }} tickLine={false} axisLine={false} interval={2} />
                <YAxis allowDecimals={false} tick={{ fontSize: 10, fill: 'var(--text-3)' }} tickLine={false} axisLine={false} />
                <Tooltip {...TOOLTIP_STYLE} />
                <Bar dataKey="count" fill="var(--accent)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* SOAR activity feed + recent alerts */}
        <div className="grid gap-4 sm:grid-cols-2">

          {/* SOAR live feed */}
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
                  <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>Create a playbook triggered by alert_critical to see auto-responses here.</p>
                </div>
              ) : executions.map(ex => (
                <div key={ex.id} className="flex items-center gap-3 px-4 py-2.5">
                  <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${ex.status === 'success' ? '' : ''}`}
                    style={{ background: ex.status === 'success' ? 'var(--green)' : 'var(--red)' }} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs truncate" style={{ color: 'var(--text-1)' }}>
                      <span className="mono" style={{ color: 'var(--accent)' }}>{ex.action_type}</span>
                      <span style={{ color: 'var(--text-3)' }}> on </span>
                      Agent #{ex.agent_id}
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

          {/* Recent alerts */}
          <div className="g-card">
            <div className="flex items-center gap-2 px-4 pt-4 pb-3" style={{ borderBottom: '1px solid var(--border)' }}>
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
                    <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>Agent #{a.agent_id}</p>
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

        {/* Open incidents */}
        {openIncidents > 0 && (
          <div className="g-card">
            <div className="flex items-center gap-2 px-4 pt-4 pb-3" style={{ borderBottom: '1px solid var(--border)' }}>
              <ShieldAlert className="h-4 w-4" style={{ color: 'var(--orange)' }} />
              <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Open Incidents ({openIncidents})</p>
            </div>
            <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {incidents.filter(i => i.status === 'open').slice(0, 5).map(inc => (
                <div key={inc.id} className="flex items-center gap-3 px-4 py-3">
                  <CircleDot className="h-3.5 w-3.5 shrink-0" style={{ color: SEV_COLORS[inc.severity] || 'var(--text-3)' }} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{inc.title}</p>
                    <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>Agent #{inc.agent_id} · {inc.description?.slice(0, 60)}…</p>
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
