'use client';

import { useState, useEffect, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { uebaAPI } from '@/lib/api';
import { UserRiskProfile, UEBAEvent } from '@/types';
import {
  User, AlertTriangle, ChevronDown, ChevronRight,
  RefreshCw, Shield, Clock, MapPin, Key,
} from 'lucide-react';

const SEV_COLOR: Record<string, string> = {
  critical: '#f85149', high: '#fb923c', medium: '#fbbf24',
  low: '#22c55e', info: 'var(--text-3)',
};

const TYPE_LABEL: Record<string, string> = {
  failed_login: 'Failed Login', login: 'Login', sudo: 'Sudo',
  off_hours_login: 'Off-Hours', priv_escalation: 'Priv Escalation',
  priv_change: 'Priv Change', brute_force: 'Brute Force',
};

function RiskBar({ score }: { score: number }) {
  const color = score >= 60 ? '#f85149' : score >= 30 ? '#fb923c' : score >= 10 ? '#fbbf24' : '#22c55e';
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--glass-bg-2)' }}>
        <div className="h-full rounded-full" style={{ width: `${score}%`, background: color }} />
      </div>
      <span className="text-xs tabular-nums font-semibold" style={{ color }}>{score}</span>
    </div>
  );
}

function FlagBadge({ flag }: { flag: string }) {
  const label = flag.replace(/_/g, ' ');
  return (
    <span className="text-[10px] px-1.5 py-0.5 rounded font-medium" style={{
      background: 'rgba(251,146,60,0.12)', color: '#fb923c', border: '1px solid rgba(251,146,60,0.3)',
    }}>{label}</span>
  );
}

function UserRow({ p, onSelect, selected }: {
  p: UserRiskProfile; onSelect: () => void; selected: boolean;
}) {
  const riskLabel = p.risk_score >= 60 ? 'HIGH' : p.risk_score >= 30 ? 'MED' : p.risk_score >= 10 ? 'LOW' : 'OK';
  const riskColor = p.risk_score >= 60 ? '#f85149' : p.risk_score >= 30 ? '#fb923c' : p.risk_score >= 10 ? '#fbbf24' : '#22c55e';

  return (
    <div className="border-b cursor-pointer transition-colors" style={{ borderColor: 'var(--border)' }}
      onClick={onSelect}>
      <div className="flex items-center gap-3 px-4 py-3 hover:bg-[var(--glass-bg-2)]">
        <div className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold"
          style={{ background: 'var(--glass-bg-2)', color: 'var(--text-2)' }}>
          {p.username.charAt(0).toUpperCase()}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{p.username}</p>
            <span className="text-[10px] px-1.5 py-px rounded" style={{
              background: 'var(--glass-bg-2)', color: 'var(--text-3)', border: '1px solid var(--border)',
            }}>{p.source}</span>
          </div>
          <div className="flex items-center gap-3 mt-0.5 flex-wrap">
            {p.flags.slice(0, 3).map(f => <FlagBadge key={f} flag={f} />)}
          </div>
        </div>
        <div className="hidden sm:flex items-center gap-5 text-[11px]" style={{ color: 'var(--text-3)' }}>
          <span title="Failed logins"><span className="text-red-400">{p.failed_logins}</span> fail</span>
          <span title="Off-hours events"><span className="text-orange-400">{p.off_hours_events}</span> off-hrs</span>
          <span title="Unique IPs"><span className="text-yellow-400">{p.unique_ips}</span> IPs</span>
          <span title="Privilege escalations"><span className="text-purple-400">{p.privilege_escalations}</span> priv</span>
        </div>
        <div className="flex items-center gap-2 ml-3">
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded" style={{
            background: `${riskColor}20`, color: riskColor, border: `1px solid ${riskColor}40`,
          }}>{riskLabel}</span>
          <RiskBar score={p.risk_score} />
          {selected ? <ChevronDown className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
                    : <ChevronRight className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />}
        </div>
      </div>
    </div>
  );
}

function EventRow({ e }: { e: UEBAEvent }) {
  const color = SEV_COLOR[e.severity] || 'var(--text-3)';
  return (
    <div className="flex items-start gap-3 px-4 py-2.5 border-b" style={{ borderColor: 'var(--border)' }}>
      <div className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0" style={{ background: color }} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-semibold px-1.5 py-px rounded" style={{
            background: `${color}20`, color, border: `1px solid ${color}40`,
          }}>{TYPE_LABEL[e.event_type] || e.event_type}</span>
          {e.source_ip && (
            <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
              from {e.source_ip}
            </span>
          )}
        </div>
        <p className="text-xs mt-0.5" style={{ color: 'var(--text-2)' }}>{e.description}</p>
      </div>
      <p className="text-[10px] shrink-0" style={{ color: 'var(--text-3)' }}>
        {new Date(e.detected_at).toLocaleString()}
      </p>
    </div>
  );
}

export default function UEBAPage() {
  const [profiles, setProfiles] = useState<UserRiskProfile[]>([]);
  const [events, setEvents] = useState<UEBAEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [selectedUser, setSelectedUser] = useState<string | null>(null);
  const [tab, setTab] = useState<'all' | 'high'>('all');

  const load = useCallback(async () => {
    setLoading(true);
    const [pRes, eRes] = await Promise.allSettled([uebaAPI.getUsers(), uebaAPI.getEvents({ limit: 200 })]);
    if (pRes.status === 'fulfilled') {
      setProfiles(pRes.value.data.profiles || []);
      setTotal(pRes.value.data.total || 0);
    }
    if (eRes.status === 'fulfilled') setEvents(eRes.value.data.events || []);
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const analyze = async () => {
    setAnalyzing(true);
    await uebaAPI.analyze();
    setTimeout(() => { load(); setAnalyzing(false); }, 3000);
  };

  const loadUserEvents = async (username: string) => {
    const r = await uebaAPI.getEvents({ username, limit: 50 });
    setEvents(r.data.events || []);
  };

  const selectUser = (username: string) => {
    if (selectedUser === username) {
      setSelectedUser(null);
      uebaAPI.getEvents({ limit: 200 }).then(r => setEvents(r.data.events || []));
    } else {
      setSelectedUser(username);
      loadUserEvents(username);
    }
  };

  const filtered = tab === 'high' ? profiles.filter(p => p.risk_score >= 30) : profiles;

  // Stats
  const highRisk = profiles.filter(p => p.risk_score >= 60).length;
  const medRisk = profiles.filter(p => p.risk_score >= 30 && p.risk_score < 60).length;
  const flaggedTotal = profiles.filter(p => p.flags.length > 0).length;

  return (
    <RootLayout title="UEBA" subtitle="User & Entity Behavior Analytics"
      actions={
        <button onClick={analyze} disabled={analyzing}
          className="g-btn g-btn-ghost flex items-center gap-1.5 text-xs">
          <RefreshCw className={`h-3.5 w-3.5 ${analyzing ? 'animate-spin' : ''}`} />
          {analyzing ? 'Analyzing…' : 'Re-analyze'}
        </button>
      }>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
        {[
          { label: 'Total Users', value: total, icon: User, color: 'var(--accent)' },
          { label: 'High Risk', value: highRisk, icon: AlertTriangle, color: '#f85149' },
          { label: 'Medium Risk', value: medRisk, icon: Shield, color: '#fb923c' },
          { label: 'Flagged', value: flaggedTotal, icon: Key, color: '#a855f7' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="g-card p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg" style={{ background: `${color}18` }}>
              <Icon className="h-4 w-4" style={{ color }} />
            </div>
            <div>
              <p className="text-lg font-bold" style={{ color: 'var(--text-1)' }}>{value}</p>
              <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{label}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* User risk table */}
        <div className="lg:col-span-2 g-card overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
            <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
              User Risk Profiles {selectedUser && <span className="text-[11px] ml-2 font-normal" style={{ color: 'var(--accent)' }}>• {selectedUser}</span>}
            </p>
            <div className="flex gap-1">
              {(['all', 'high'] as const).map(t => (
                <button key={t} onClick={() => setTab(t)}
                  className="text-[11px] px-2.5 py-1 rounded-lg transition-colors"
                  style={{
                    background: tab === t ? 'var(--accent)' : 'var(--glass-bg-2)',
                    color: tab === t ? '#000' : 'var(--text-3)',
                    border: '1px solid var(--border)',
                  }}>
                  {t === 'all' ? 'All' : 'Risky (≥30)'}
                </button>
              ))}
            </div>
          </div>
          {loading ? (
            <p className="p-8 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Analyzing user behavior…</p>
          ) : filtered.length === 0 ? (
            <div className="p-12 text-center">
              <User className="mx-auto h-10 w-10 mb-3 opacity-20" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-3)' }}>
                {total === 0 ? 'No user events yet. Click Re-analyze to scan logs.' : 'No users match this filter.'}
              </p>
            </div>
          ) : (
            <div className="overflow-auto max-h-[560px]">
              {filtered.map(p => (
                <UserRow key={`${p.username}-${p.source}`} p={p}
                  selected={selectedUser === p.username}
                  onSelect={() => selectUser(p.username)} />
              ))}
            </div>
          )}
        </div>

        {/* Event feed */}
        <div className="g-card overflow-hidden flex flex-col">
          <div className="px-4 py-3 shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
            <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
              {selectedUser ? `Events — ${selectedUser}` : 'Recent Events'}
            </p>
          </div>
          <div className="overflow-auto flex-1 max-h-[560px]">
            {events.length === 0 ? (
              <p className="p-8 text-center text-xs" style={{ color: 'var(--text-3)' }}>No events yet.</p>
            ) : (
              events.map(e => <EventRow key={e.id} e={e} />)
            )}
          </div>
        </div>
      </div>

      {/* Legend */}
      <div className="mt-4 g-card px-4 py-3">
        <p className="text-[11px] font-semibold mb-2" style={{ color: 'var(--text-3)' }}>RISK SCORE COMPONENTS</p>
        <div className="flex gap-6 flex-wrap text-[11px]" style={{ color: 'var(--text-3)' }}>
          <span className="flex items-center gap-1.5"><span className="text-red-400 font-semibold">×10</span> Failed login</span>
          <span className="flex items-center gap-1.5"><span className="text-orange-400 font-semibold">×5</span> Off-hours event</span>
          <span className="flex items-center gap-1.5"><span className="text-purple-400 font-semibold">×20</span> Privilege escalation</span>
          <span className="flex items-center gap-1.5"><span className="text-yellow-400 font-semibold">×15</span> Additional source IP</span>
          <span className="ml-auto">Score capped at 100 · Re-analyzed every 30 min · 7-day window</span>
        </div>
      </div>
    </RootLayout>
  );
}
