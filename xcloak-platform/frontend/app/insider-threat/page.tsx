'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { insiderThreatAPI } from '@/lib/api';
import {
  UserX, RefreshCw, Loader2, TrendingUp,
  Clock, ShieldAlert, MapPin, Lock, Database,
} from 'lucide-react';

interface InsiderScore {
  username: string;
  score_date: string;
  score: number;
  risk_level: string;
  contributors: {
    off_hours_auth?: number;
    failed_auth?: number;
    data_exfil?: number;
    sensitive_access?: number;
    privesc_attempt?: number;
    anomalous_location?: number;
  };
  alert_fired: boolean;
  updated_at: string;
}

const RISK_COLOR: Record<string, string> = {
  critical: '#f85149',
  high:     '#e3b341',
  medium:   '#d29922',
  low:      '#3fb950',
};

const CONTRIB_ICONS: Record<string, { icon: any; label: string; max: number }> = {
  off_hours_auth:     { icon: Clock,       label: 'Off-Hours Auth',    max: 20 },
  failed_auth:        { icon: Lock,        label: 'Failed Auth',       max: 15 },
  data_exfil:         { icon: Database,    label: 'Data Exfiltration', max: 25 },
  sensitive_access:   { icon: ShieldAlert, label: 'Sensitive Access',  max: 15 },
  privesc_attempt:    { icon: TrendingUp,  label: 'Privilege Escalation', max: 15 },
  anomalous_location: { icon: MapPin,      label: 'Anomalous Location',max: 10 },
};

export default function InsiderThreatPage() {
  const [scores, setScores]       = useState<InsiderScore[]>([]);
  const [loading, setLoading]     = useState(true);
  const [days, setDays]           = useState(7);
  const [minScore, setMinScore]   = useState(0);
  const [expanded, setExpanded]   = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await insiderThreatAPI.getScores(days, minScore);
      setScores(Array.isArray(r.data) ? r.data : []);
    } catch { setScores([]); }
    finally { setLoading(false); }
  }, [days, minScore]);

  useEffect(() => { load(); }, [load]);

  const riskCounts = {
    critical: scores.filter(s => s.risk_level === 'critical').length,
    high:     scores.filter(s => s.risk_level === 'high').length,
    medium:   scores.filter(s => s.risk_level === 'medium').length,
  };

  return (
    <RootLayout title="Insider Threat" subtitle="Daily per-user risk scoring across auth, exfiltration, privilege escalation, and anomalous behaviour">
      <div className="space-y-4">
        {/* Controls */}
        <div className="flex items-center gap-3">
          <select value={days} onChange={e => setDays(+e.target.value)} className="g-input text-xs w-32">
            {[1,7,14,30,90].map(d => <option key={d} value={d}>Last {d}d</option>)}
          </select>
          <select value={minScore} onChange={e => setMinScore(+e.target.value)} className="g-input text-xs w-36">
            <option value={0}>All scores</option>
            <option value={30}>Medium+ (30+)</option>
            <option value={60}>High+ (60+)</option>
            <option value={80}>Critical (80+)</option>
          </select>
          <button onClick={load} className="g-btn g-btn-ghost text-xs"><RefreshCw className="h-3.5 w-3.5" /></button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Total Users', val: scores.length, color: 'var(--accent)' },
            { label: 'Critical', val: riskCounts.critical, color: '#f85149' },
            { label: 'High', val: riskCounts.high, color: '#e3b341' },
            { label: 'Medium', val: riskCounts.medium, color: '#d29922' },
          ].map(s => (
            <div key={s.label} className="g-card p-4 flex items-center gap-3">
              <UserX className="h-4 w-4 flex-shrink-0" style={{ color: s.color }} />
              <div>
                <p className="text-lg font-bold" style={{ color: 'var(--text-1)' }}>{s.val}</p>
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{s.label}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Score list */}
        {loading ? (
          <div className="flex justify-center py-12">
            <Loader2 className="h-5 w-5 animate-spin" style={{ color: 'var(--text-3)' }} />
          </div>
        ) : scores.length === 0 ? (
          <div className="g-card p-12 text-center">
            <UserX className="h-8 w-8 mx-auto mb-2" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No insider threat scores for selected filters</p>
            <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>Scores are computed every 6 hours from auth, exfil, and privilege escalation signals</p>
          </div>
        ) : (
          <div className="space-y-2">
            {scores.map((s, i) => {
              const key = `${s.username}-${s.score_date}`;
              const isOpen = expanded === key;
              return (
                <div key={i} className="g-card overflow-hidden">
                  <button
                    className="w-full flex items-center gap-4 px-4 py-3 text-left transition-colors hover:bg-[rgba(255,255,255,0.02)]"
                    onClick={() => setExpanded(isOpen ? null : key)}>
                    {/* Risk badge */}
                    <span className="w-16 text-center px-2 py-0.5 rounded text-[10px] font-bold uppercase flex-shrink-0"
                      style={{
                        background: `${RISK_COLOR[s.risk_level] || 'var(--text-3)'}22`,
                        color: RISK_COLOR[s.risk_level] || 'var(--text-3)',
                      }}>
                      {s.risk_level}
                    </span>

                    {/* Username */}
                    <span className="font-medium text-sm flex-1 text-left mono" style={{ color: 'var(--text-1)' }}>
                      {s.username}
                    </span>

                    {/* Score bar */}
                    <div className="flex items-center gap-2 w-48 flex-shrink-0">
                      <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--border)' }}>
                        <div className="h-full rounded-full transition-all"
                          style={{ width: `${s.score}%`, background: RISK_COLOR[s.risk_level] || 'var(--text-3)' }} />
                      </div>
                      <span className="text-xs font-bold w-10 text-right" style={{ color: 'var(--text-1)' }}>{s.score}/100</span>
                    </div>

                    {/* Date */}
                    <span className="text-[11px] w-24 text-right flex-shrink-0" style={{ color: 'var(--text-3)' }}>{s.score_date}</span>

                    {/* Alert indicator */}
                    {s.alert_fired && (
                      <ShieldAlert className="h-3.5 w-3.5 flex-shrink-0" style={{ color: '#f85149' }} />
                    )}
                  </button>

                  {/* Expanded contributor breakdown */}
                  {isOpen && (
                    <div className="px-4 pb-4 pt-1 space-y-2 border-t" style={{ borderColor: 'var(--border)' }}>
                      <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Signal Breakdown</p>
                      <div className="grid grid-cols-2 gap-2">
                        {Object.entries(CONTRIB_ICONS).map(([key, meta]) => {
                          const val = (s.contributors as any)[key] ?? 0;
                          const Icon = meta.icon;
                          return (
                            <div key={key} className="flex items-center gap-2">
                              <Icon className="h-3 w-3 flex-shrink-0" style={{ color: val > 0 ? RISK_COLOR[s.risk_level] : 'var(--text-3)' }} />
                              <span className="text-[11px] flex-1" style={{ color: 'var(--text-2)' }}>{meta.label}</span>
                              <span className="text-[11px] mono font-bold w-10 text-right" style={{ color: val > 0 ? 'var(--text-1)' : 'var(--text-3)' }}>
                                {val}/{meta.max}
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        <div className="g-card p-4 space-y-1.5">
          <p className="text-xs font-semibold" style={{ color: 'var(--text-2)' }}>How insider threat scoring works</p>
          <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
            Scores are computed every 6 hours per user from six signal categories. Off-hours auth (max 20), failed auth (max 15), data exfiltration volume (max 25), sensitive file access (max 15), privilege escalation events (max 15), and anomalous login location (max 10). Alerts fire when a user crosses 60 (high risk).
          </p>
        </div>
      </div>
    </RootLayout>
  );
}
