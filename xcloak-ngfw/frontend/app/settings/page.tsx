'use client';

import { useEffect, useState } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { agentsAPI, dashboardAPI, auditAPI, authAPI } from '@/lib/api';
import { Agent, DashboardOverview } from '@/types';
import { formatDate, timeAgo } from '@/lib/utils';
import {
  User, Cpu, Server, FileText, Key, Eye, EyeOff,
  Globe, Database, Activity, ShieldCheck, AlertCircle, Check,
} from 'lucide-react';

const TABS = [
  { id: 'profile', label: 'User Profile', icon: User },
  { id: 'agents',  label: 'Agent Config', icon: Cpu },
  { id: 'server',  label: 'Server Info',  icon: Server },
  { id: 'audit',   label: 'Audit Log',    icon: FileText },
] as const;
type Tab = typeof TABS[number]['id'];

export default function SettingsPage() {
  const [tab, setTab]       = useState<Tab>('profile');
  const [agents, setAgents] = useState<Agent[]>([]);
  const [overview, setOverview] = useState<DashboardOverview | null>(null);
  const [audit, setAudit]   = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  // Profile state
  const [username, setUsername] = useState('');
  const [showToken, setShowToken] = useState(false);
  const [token, setToken] = useState('');

  useEffect(() => {
    setUsername(localStorage.getItem('username') || 'admin');
    setToken(localStorage.getItem('token') || '');

    const load = async () => {
      const [ar, ov, al] = await Promise.allSettled([agentsAPI.getAll(), dashboardAPI.getOverview(), auditAPI.getLogs()]);
      if (ar.status === 'fulfilled') setAgents(ar.value.data || []);
      if (ov.status === 'fulfilled') setOverview(ov.value.data);
      if (al.status === 'fulfilled') setAudit(al.value.data || []);
      setLoading(false);
    };
    load();
  }, []);

  const online  = agents.filter(a => a.status === 'online').length;
  const offline = agents.length - online;
  const osBreakdown = agents.reduce((acc, a) => { const os = a.os || 'Unknown'; acc[os] = (acc[os] || 0) + 1; return acc; }, {} as Record<string, number>);

  return (
    <RootLayout title="Settings">
      <div className="space-y-5">
        {/* Tab bar */}
        <div className="flex gap-1 p-1 rounded-xl w-fit flex-wrap" style={{ background: 'var(--glass-bg)', backdropFilter: 'var(--blur-sm)', border: '1px solid var(--border)' }}>
          {TABS.map(t => {
            const Icon = t.icon;
            return (
              <button key={t.id} onClick={() => setTab(t.id)}
                className="flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-medium transition-all"
                style={{
                  background: tab === t.id ? 'var(--accent-glow)' : 'transparent',
                  color:      tab === t.id ? 'var(--accent)' : 'var(--text-2)',
                  border:     tab === t.id ? '1px solid var(--accent-border)' : '1px solid transparent',
                }}>
                <Icon className="h-3.5 w-3.5" /> {t.label}
              </button>
            );
          })}
        </div>

        {/* ── USER PROFILE ── */}
        {tab === 'profile' && (
          <div className="space-y-4 max-w-xl">
            <div className="g-card p-5">
              <div className="flex items-center gap-4 mb-5">
                <div className="flex h-14 w-14 items-center justify-center rounded-2xl text-xl font-bold"
                  style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)', color: 'var(--accent)' }}>
                  {username.charAt(0).toUpperCase()}
                </div>
                <div>
                  <p className="text-base font-semibold" style={{ color: 'var(--text-1)' }}>{username}</p>
                  <p className="text-xs mt-0.5" style={{ color: 'var(--text-3)' }}>Administrator</p>
                </div>
              </div>

              <div className="space-y-3">
                <div>
                  <label className="block text-xs mb-1.5" style={{ color: 'var(--text-3)' }}>Username</label>
                  <input value={username} disabled className="g-input opacity-60" />
                </div>
                <div>
                  <label className="block text-xs mb-1.5" style={{ color: 'var(--text-3)' }}>Role</label>
                  <input value="admin" disabled className="g-input opacity-60" />
                </div>
                <div>
                  <label className="block text-xs mb-1.5" style={{ color: 'var(--text-3)' }}>Session Token</label>
                  <div className="relative">
                    <Key className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
                    <input value={showToken ? token : '•'.repeat(40)} disabled className="g-input pl-9 pr-10 mono opacity-60" style={{ fontSize: 10 }} />
                    <button onClick={() => setShowToken(p => !p)} className="absolute right-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-3)' }}>
                      {showToken ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                  <p className="text-[10px] mt-1.5" style={{ color: 'var(--text-3)' }}>JWT bearer token used for API authentication.</p>
                </div>
              </div>
            </div>

            <div className="g-card p-4 flex items-start gap-3">
              <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" style={{ color: 'var(--accent)' }} />
              <p className="text-xs" style={{ color: 'var(--text-2)' }}>
                Account creation and role management require backend support for user listing/editing —
                currently the API only supports register and login. Once a user management endpoint exists,
                this page can manage all SOC users.
              </p>
            </div>
          </div>
        )}

        {/* ── AGENT CONFIG ── */}
        {tab === 'agents' && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <StatBox icon={Cpu} label="Total Agents" value={agents.length} />
              <StatBox icon={Activity} label="Online" value={online} good />
              <StatBox icon={Activity} label="Offline" value={offline} />
              <StatBox icon={ShieldCheck} label="Coverage" value={agents.length ? `${Math.round((online / agents.length) * 100)}%` : '0%'} />
            </div>

            <div className="g-card p-5">
              <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>OS Distribution</p>
              <div className="space-y-2">
                {Object.entries(osBreakdown).map(([os, count]) => (
                  <div key={os} className="flex items-center gap-3">
                    <span className="text-xs w-32 truncate" style={{ color: 'var(--text-2)' }}>{os}</span>
                    <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: 'var(--bg-0)' }}>
                      <div className="h-full rounded-full" style={{ width: `${(count / agents.length) * 100}%`, background: 'var(--accent)' }} />
                    </div>
                    <span className="text-xs w-8 text-right tabular-nums" style={{ color: 'var(--text-1)' }}>{count}</span>
                  </div>
                ))}
                {agents.length === 0 && <p className="text-xs" style={{ color: 'var(--text-3)' }}>No agents registered.</p>}
              </div>
            </div>

            <div className="g-table">
              <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 1fr 100px 100px' }}>
                <span>Hostname</span><span>IP Address</span><span>Status</span><span>Last Seen</span>
              </div>
              {agents.map(a => (
                <div key={a.id} className="g-tr grid gap-3 items-center px-4" style={{ gridTemplateColumns: '1fr 1fr 100px 100px' }}>
                  <span className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{a.hostname}</span>
                  <span className="mono text-xs" style={{ color: 'var(--text-2)' }}>{a.ip_address}</span>
                  <span className={a.status === 'online' ? 's-online' : 's-offline'}>{a.status}</span>
                  <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{timeAgo(a.last_seen)}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── SERVER INFO ── */}
        {tab === 'server' && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <StatBox icon={Database} label="Processes Tracked" value={overview?.processes ?? 0} />
              <StatBox icon={Globe} label="Connections" value={overview?.connections ?? 0} />
              <StatBox icon={Server} label="Services" value={overview?.services ?? 0} />
              <StatBox icon={ShieldCheck} label="Packages" value={overview?.packages ?? 0} />
            </div>

            <div className="g-card p-5">
              <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>System Status</p>
              <div className="space-y-3">
                {[
                  ['API Status', 'Healthy', 'green'],
                  ['Service', 'xcloak-ngfw', null],
                  ['Total Alerts', String(overview?.alerts ?? 0), null],
                  ['Critical Alerts', String(overview?.critical_alerts ?? 0), (overview?.critical_alerts ?? 0) > 0 ? 'red' : null],
                  ['Total Incidents', String(overview?.incidents ?? 0), null],
                  ['Critical Incidents', String(overview?.critical_incidents ?? 0), (overview?.critical_incidents ?? 0) > 0 ? 'red' : null],
                  ['Total Users Tracked', String(overview?.users ?? 0), null],
                ].map(([k, v, color]) => (
                  <div key={k} className="flex items-center justify-between text-xs" style={{ borderBottom: '1px solid var(--border)', paddingBottom: 8 }}>
                    <span style={{ color: 'var(--text-2)' }}>{k}</span>
                    <span className="flex items-center gap-1.5 font-medium" style={{ color: color === 'green' ? 'var(--green)' : color === 'red' ? 'var(--red)' : 'var(--text-1)' }}>
                      {color === 'green' && <Check className="h-3 w-3" />}
                      {v}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <div className="g-card p-4 flex items-start gap-3">
              <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" style={{ color: 'var(--accent)' }} />
              <p className="text-xs" style={{ color: 'var(--text-2)' }}>
                Server configuration (database connection, ports, retention policies) is managed via environment
                variables on the backend and isn't exposed through the API for security reasons.
              </p>
            </div>
          </div>
        )}

        {/* ── AUDIT LOG ── */}
        {tab === 'audit' && (
          <div className="g-table">
            <div className="g-thead grid gap-4 px-4" style={{ gridTemplateColumns: '140px 1fr 120px 120px' }}>
              <span>Action</span><span>Details</span><span>User</span><span>Time</span>
            </div>
            {loading ? (
              <div className="py-12 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
            ) : audit.length === 0 ? (
              <div className="py-12 text-center text-sm" style={{ color: 'var(--text-2)' }}>No audit events.</div>
            ) : audit.map((log: any, i: number) => (
              <div key={i} className="g-tr grid gap-4 items-center px-4" style={{ gridTemplateColumns: '140px 1fr 120px 120px' }}>
                <span className="mono text-[11px] rounded px-1.5 py-0.5 inline-block w-fit"
                  style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                  {log.action}
                </span>
                <span className="text-xs truncate" style={{ color: 'var(--text-2)' }}>{log.details || '—'}</span>
                <span className="text-xs" style={{ color: 'var(--text-2)' }}>{log.username || '—'}</span>
                <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{formatDate(log.created_at)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </RootLayout>
  );
}

function StatBox({ icon: Icon, label, value, good }: { icon: any; label: string; value: string | number; good?: boolean }) {
  return (
    <div className="stat-glow">
      <div className="flex h-9 w-9 items-center justify-center rounded-xl mb-3"
        style={{ background: good ? 'var(--green-bg)' : 'var(--accent-glow)', border: `1px solid ${good ? 'var(--green-border)' : 'var(--accent-border)'}` }}>
        <Icon className="h-4 w-4" style={{ color: good ? 'var(--green)' : 'var(--accent)' }} />
      </div>
      <p className="text-2xl font-bold tabular-nums" style={{ color: 'var(--text-1)' }}>{value}</p>
      <p className="text-xs mt-0.5" style={{ color: 'var(--text-2)' }}>{label}</p>
    </div>
  );
}
