'use client';

import { useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { RootLayout } from '@/components/layout/RootLayout';
import { dashboardAPI, alertsAPI, incidentsAPI, agentsAPI } from '@/lib/api';
import { DashboardOverview, Alert, Incident, Agent } from '@/types';
import { sevClass, sevDot, timeAgo } from '@/lib/utils';
import { Cpu, Bell, AlertTriangle, Activity, Server, Package, Users, Network, TrendingUp } from 'lucide-react';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const SEV_COLORS = { critical: '#f85149', high: '#fb923c', medium: '#fbbf24', low: '#38bdf8' };
const CUSTOM_TOOLTIP = {
  contentStyle: { background: 'var(--glass-modal)', border: '1px solid var(--border-md)', borderRadius: 8, fontSize: 12, color: 'var(--text-1)' },
  labelStyle: { color: 'var(--text-2)' },
};

function StatCard({ label, value, sub, icon: Icon, color }: any) {
  return (
    <div className="stat-glow">
      <div className="flex items-start justify-between mb-3">
        <div className="flex h-9 w-9 items-center justify-center rounded-xl"
          style={{ background: color || 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
          <Icon className="h-4 w-4" style={{ color: 'var(--accent)' }} />
        </div>
        <TrendingUp className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
      </div>
      <p className="text-2xl font-bold tabular-nums mt-1" style={{ color: 'var(--text-1)' }}>{value}</p>
      <p className="text-xs mt-0.5 font-medium" style={{ color: 'var(--text-2)' }}>{label}</p>
      {sub && <p className="text-[11px] mt-1" style={{ color: 'var(--text-3)' }}>{sub}</p>}
    </div>
  );
}

export default function DashboardPage() {
  const router = useRouter();
  const [overview, setOverview]   = useState<DashboardOverview | null>(null);
  const [alerts, setAlerts]       = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [agents, setAgents]       = useState<Agent[]>([]);
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const [ov, al, inc, ag] = await Promise.allSettled([
        dashboardAPI.getOverview(), alertsAPI.getAll(),
        incidentsAPI.getAll(), agentsAPI.getAll(),
      ]);
      if (ov.status  === 'fulfilled') setOverview(ov.value.data);
      if (al.status  === 'fulfilled') setAlerts(al.value.data || []);
      if (inc.status === 'fulfilled') setIncidents(inc.value.data || []);
      if (ag.status  === 'fulfilled') setAgents(ag.value.data || []);
    } finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => {
    if (!localStorage.getItem('token')) { router.push('/login'); return; }
    load();
    const t = setInterval(() => load(), 30000);
    return () => clearInterval(t);
  }, [router, load]);

  const sevCounts = alerts.reduce((a, x) => { a[x.severity] = (a[x.severity] || 0) + 1; return a; }, {} as Record<string, number>);
  const pieData   = Object.entries(sevCounts).map(([name, value]) => ({ name, value }));
  const mitreCounts = alerts.reduce((a, x) => { if (x.mitre_tactic) a[x.mitre_tactic] = (a[x.mitre_tactic] || 0) + 1; return a; }, {} as Record<string, number>);
  const mitreData = Object.entries(mitreCounts).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, count]) => ({ name: name.split(' ')[0], count }));

  const online = agents.filter(a => a.status === 'online').length;
  const critAlerts = alerts.filter(a => a.severity === 'critical').length;
  const openInc    = incidents.filter(i => i.status === 'open' || i.status === 'investigating').length;

  if (loading) return (
    <RootLayout title="Dashboard">
      <div className="flex h-64 items-center justify-center">
        <div className="text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
      </div>
    </RootLayout>
  );

  return (
    <RootLayout title="Security Operations Center" subtitle="Real-time threat visibility"
      onRefresh={() => load(true)} refreshing={refreshing}>
      <div className="space-y-5">

        {/* Stat grid */}
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatCard label="Total Agents"   value={overview?.agents ?? agents.length}
            sub={`${online} online`} icon={Cpu} />
          <StatCard label="Active Alerts"  value={overview?.alerts ?? alerts.length}
            sub={`${critAlerts} critical`} icon={Bell}
            color={critAlerts > 0 ? 'var(--red-bg)' : undefined} />
          <StatCard label="Open Incidents" value={openInc}
            sub={`${overview?.critical_incidents ?? 0} critical`} icon={AlertTriangle}
            color={openInc > 0 ? 'var(--orange-bg)' : undefined} />
          <StatCard label="Processes"      value={overview?.processes ?? 0}
            sub={`${overview?.connections ?? 0} connections`} icon={Activity} />
        </div>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatCard label="Services"  value={overview?.services  ?? 0} icon={Server} />
          <StatCard label="Packages"  value={overview?.packages  ?? 0} icon={Package} />
          <StatCard label="Users"     value={overview?.users     ?? 0} icon={Users} />
          <StatCard label="Network"   value={overview?.connections ?? 0} icon={Network} />
        </div>

        {/* Charts row */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">

          {/* Severity donut */}
          <div className="g-card p-5">
            <p className="text-sm font-semibold mb-4" style={{ color: 'var(--text-1)' }}>Alert Severity</p>
            {pieData.length > 0 ? (
              <>
                <ResponsiveContainer width="100%" height={180}>
                  <PieChart>
                    <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={75} dataKey="value" paddingAngle={3}>
                      {pieData.map(e => <Cell key={e.name} fill={SEV_COLORS[e.name as keyof typeof SEV_COLORS] || '#64748b'} />)}
                    </Pie>
                    <Tooltip {...CUSTOM_TOOLTIP} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="flex flex-wrap justify-center gap-3 mt-2">
                  {Object.entries(SEV_COLORS).map(([s, c]) => (
                    <div key={s} className="flex items-center gap-1.5 text-[11px]" style={{ color: 'var(--text-2)' }}>
                      <span className="h-2 w-2 rounded-full" style={{ background: c }} />
                      {s} ({sevCounts[s] || 0})
                    </div>
                  ))}
                </div>
              </>
            ) : <EmptyChart msg="No alert data" />}
          </div>

          {/* MITRE bar */}
          <div className="g-card p-5">
            <p className="text-sm font-semibold mb-4" style={{ color: 'var(--text-1)' }}>MITRE ATT&CK</p>
            {mitreData.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={mitreData} layout="vertical" margin={{ left: 0, right: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 10, fill: 'var(--text-3)' }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="name" tick={{ fontSize: 10, fill: 'var(--text-2)' }} width={80} axisLine={false} tickLine={false} />
                  <Tooltip {...CUSTOM_TOOLTIP} />
                  <Bar dataKey="count" fill="var(--accent)" radius={[0, 5, 5, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : <EmptyChart msg="No tactic data" />}
          </div>

          {/* Agent status */}
          <div className="g-card p-5">
            <p className="text-sm font-semibold mb-4" style={{ color: 'var(--text-1)' }}>Agents</p>
            <div className="space-y-2.5">
              {agents.length === 0 ? <EmptyChart msg="No agents" /> :
                agents.slice(0, 7).map(a => (
                  <div key={a.id} className="flex items-center gap-2.5">
                    <span className={a.status === 'online' ? 'dot-online' : 'dot-offline'} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{a.hostname}</p>
                    </div>
                    <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(a.last_seen)}</span>
                  </div>
                ))}
            </div>
          </div>
        </div>

        {/* Recent alerts + incidents */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">

          <FeedCard title="Recent Alerts" link="/alerts" linkLabel="View all">
            {alerts.length === 0 ? <FeedEmpty msg="No alerts" /> :
              alerts.slice(0, 5).map(a => (
                <div key={a.id} className="flex items-start gap-3 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
                  <span className={`h-2 w-2 rounded-full mt-1.5 shrink-0 ${a.severity === 'critical' ? 'dot-online' : ''}`}
                    style={{ background: SEV_COLORS[a.severity as keyof typeof SEV_COLORS] || 'var(--text-3)' }} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{a.rule_name}</p>
                    <p className="text-[11px] truncate mt-0.5" style={{ color: 'var(--text-3)' }}>{a.log_message}</p>
                  </div>
                  <div className="shrink-0 text-right">
                    <span className={`inline-block ${sevClass(a.severity)}`}>{a.severity}</span>
                    <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>{timeAgo(a.created_at)}</p>
                  </div>
                </div>
              ))}
          </FeedCard>

          <FeedCard title="Active Incidents" link="/incidents" linkLabel="View all">
            {incidents.length === 0 ? <FeedEmpty msg="No incidents" /> :
              incidents.filter(i => i.status !== 'closed').slice(0, 5).map(i => (
                <div key={i.id} className="flex items-start gap-3 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
                  <span className="h-2 w-2 rounded-full mt-1.5 shrink-0"
                    style={{ background: SEV_COLORS[i.severity as keyof typeof SEV_COLORS] || 'var(--text-3)' }} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{i.title}</p>
                    <p className="text-[11px] mt-0.5" style={{ color: 'var(--text-3)' }}>Agent {i.agent_id}</p>
                  </div>
                  <div className="shrink-0 text-right">
                    <span className={`inline-block ${sevClass(i.severity)}`}>{i.severity}</span>
                    <p className="text-[10px] mt-1 capitalize" style={{ color: 'var(--text-3)' }}>{i.status}</p>
                  </div>
                </div>
              ))}
          </FeedCard>
        </div>
      </div>
    </RootLayout>
  );
}

function FeedCard({ title, link, linkLabel, children }: any) {
  return (
    <div className="g-card p-5">
      <div className="flex items-center justify-between mb-1">
        <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{title}</p>
        <a href={link} className="text-xs font-medium" style={{ color: 'var(--accent)' }}>{linkLabel} →</a>
      </div>
      {children}
    </div>
  );
}

function EmptyChart({ msg }: { msg: string }) {
  return <div className="flex h-[180px] items-center justify-center text-sm" style={{ color: 'var(--text-3)' }}>{msg}</div>;
}

function FeedEmpty({ msg }: { msg: string }) {
  return <p className="py-8 text-center text-sm" style={{ color: 'var(--text-3)' }}>{msg}</p>;
}
