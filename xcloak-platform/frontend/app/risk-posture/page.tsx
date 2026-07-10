'use client';

import { useState, useEffect } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import api from '@/lib/api';
import { RefreshCw, TrendingUp, TrendingDown, Shield, AlertTriangle, Users, Bug, Zap } from 'lucide-react';

interface AssetRisk { asset_id: number; hostname: string; score: number; top_reason: string; criticality: string; }
interface RiskSnapshot {
  id: number; score: number; vuln_score: number; ueba_score: number;
  alert_score: number; ioc_score: number; asset_scores: AssetRisk[];
  snapshot_at: string;
}

function ScoreGauge({ score }: { score: number }) {
  const color = score >= 70 ? '#f85149' : score >= 40 ? '#fb923c' : score >= 20 ? '#fbbf24' : '#22c55e';
  const label = score >= 70 ? 'Critical' : score >= 40 ? 'High' : score >= 20 ? 'Medium' : 'Low';
  const pct = score; // 0-100
  const r = 54;
  const circ = 2 * Math.PI * r;
  const dash = (pct / 100) * circ;
  return (
    <div className="flex flex-col items-center">
      <svg width="140" height="140" className="rotate-[-90deg]">
        <circle cx="70" cy="70" r={r} fill="none" strokeWidth="12" stroke="var(--glass-bg-2)" />
        <circle cx="70" cy="70" r={r} fill="none" strokeWidth="12" stroke={color}
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 0.8s ease' }} />
      </svg>
      <div className="text-center" style={{ marginTop: '-118px' }}>
        <p className="text-4xl font-black" style={{ color }}>{score}</p>
        <p className="text-xs font-semibold" style={{ color }}>{label} Risk</p>
      </div>
      <div style={{ marginTop: '70px' }} />
    </div>
  );
}

function SparkLine({ data, color = 'var(--accent)' }: { data: number[]; color?: string }) {
  if (!data.length) return null;
  const max = Math.max(...data, 1);
  const h = 32;
  const w = data.length * 8;
  const pts = data.map((v, i) => `${i * 8},${h - (v / max) * h}`).join(' ');
  return (
    <svg width={w} height={h}>
      <polyline points={pts} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export default function RiskPosturePage() {
  const [snap, setSnap] = useState<RiskSnapshot | null>(null);
  const [history, setHistory] = useState<RiskSnapshot[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const load = async () => {
    setLoading(true);
    const [s, h] = await Promise.all([
      api.get('/risk-posture').catch(() => ({ data: null })),
      api.get('/risk-posture/history?limit=30').catch(() => ({ data: [] })),
    ]);
    setSnap(s.data);
    setHistory((h.data || []).reverse()); // oldest first for chart
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const refresh = async () => {
    setRefreshing(true);
    const r = await api.post('/risk-posture/refresh').catch(() => ({ data: null }));
    if (r.data) setSnap(r.data);
    setRefreshing(false);
    load();
  };

  const historyScores = history.map(h => h.score);
  const prevScore = history.length >= 2 ? history[history.length - 2].score : null;
  const delta = snap && prevScore !== null ? snap.score - prevScore : null;

  const subScores = snap ? [
    { label: 'Vulnerabilities', value: snap.vuln_score, max: 30, icon: Bug, color: '#f85149' },
    { label: 'UEBA Behavior', value: snap.ueba_score, max: 20, icon: Users, color: '#a855f7' },
    { label: 'Open Alerts', value: snap.alert_score, max: 30, icon: AlertTriangle, color: '#fb923c' },
    { label: 'IOC Matches', value: snap.ioc_score, max: 20, icon: Zap, color: '#fbbf24' },
  ] : [];

  return (
    <RootLayout title="Risk Posture" subtitle="Composite security score · Real-time org-wide risk"
      actions={
        <button onClick={refresh} disabled={refreshing} className="g-btn g-btn-ghost flex items-center gap-1.5 text-xs">
          <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} />
          {refreshing ? 'Computing…' : 'Refresh'}
        </button>
      }>

      {loading ? (
        <div className="py-24 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Computing risk posture…</div>
      ) : !snap ? (
        <div className="py-24 text-center text-sm" style={{ color: 'var(--text-3)' }}>No data yet — click Refresh to compute.</div>
      ) : (
        <div className="space-y-5">

          {/* Main score + sub-scores */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Gauge */}
            <div className="g-card p-6 flex flex-col items-center justify-center lg:col-span-1">
              <ScoreGauge score={snap.score} />
              <p className="text-[11px] mt-2" style={{ color: 'var(--text-3)' }}>
                As of {new Date(snap.snapshot_at).toLocaleTimeString()}
              </p>
              {delta !== null && (
                <div className="flex items-center gap-1 mt-1 text-xs font-semibold"
                  style={{ color: delta > 0 ? '#f85149' : '#22c55e' }}>
                  {delta > 0 ? <TrendingUp className="h-3.5 w-3.5" /> : <TrendingDown className="h-3.5 w-3.5" />}
                  {delta > 0 ? '+' : ''}{delta} vs previous
                </div>
              )}
            </div>

            {/* Sub-scores */}
            <div className="lg:col-span-2 grid grid-cols-2 gap-3">
              {subScores.map(({ label, value, max, icon: Icon, color }) => (
                <div key={label} className="g-card p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <div className="p-1.5 rounded-lg" style={{ background: `${color}15` }}>
                      <Icon className="h-3.5 w-3.5" style={{ color }} />
                    </div>
                    <p className="text-xs font-medium" style={{ color: 'var(--text-2)' }}>{label}</p>
                    <span className="ml-auto text-sm font-bold" style={{ color: value > 0 ? color : 'var(--text-3)' }}>{value}/{max}</span>
                  </div>
                  <div className="h-2 rounded-full overflow-hidden" style={{ background: 'var(--glass-bg-2)' }}>
                    <div className="h-full rounded-full transition-all duration-700" style={{
                      width: `${(value / max) * 100}%`,
                      background: color,
                    }} />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Trend chart */}
          {historyScores.length > 1 && (
            <div className="g-card p-5">
              <div className="flex items-center gap-2 mb-3">
                <TrendingUp className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Risk Score Trend — Last {historyScores.length} snapshots</p>
              </div>
              <div className="flex items-end gap-px h-16">
                {historyScores.map((s, i) => {
                  const color = s >= 70 ? '#f85149' : s >= 40 ? '#fb923c' : s >= 20 ? '#fbbf24' : '#22c55e';
                  return (
                    <div key={i} className="flex-1 flex flex-col items-center" title={`Score: ${s}`}>
                      <div className="w-full rounded-t-sm" style={{
                        height: `${Math.max(2, (s / 100) * 60)}px`,
                        background: color, opacity: 0.5 + (s / 200),
                      }} />
                    </div>
                  );
                })}
              </div>
              <div className="flex justify-between text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                <span>Oldest</span><span>Latest</span>
              </div>
            </div>
          )}

          {/* Per-asset risk */}
          {snap.asset_scores && snap.asset_scores.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-3">
                <Shield className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Top Riskiest Assets</p>
              </div>
              <div className="g-card overflow-hidden">
                <table className="w-full" style={{ borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)' }}>
                      {['Asset', 'Criticality', 'Risk Score', 'Top Reason'].map(h => (
                        <th key={h} className="px-3 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {snap.asset_scores.map(a => {
                      const scoreColor = a.score >= 70 ? '#f85149' : a.score >= 40 ? '#fb923c' : '#fbbf24';
                      return (
                        <tr key={a.asset_id} style={{ borderBottom: '1px solid var(--border)' }}>
                          <td className="px-3 py-2.5 text-xs font-medium" style={{ color: 'var(--text-1)' }}>{a.hostname || `Asset #${a.asset_id}`}</td>
                          <td className="px-3 py-2.5 text-xs capitalize" style={{ color: 'var(--text-3)' }}>{a.criticality || '—'}</td>
                          <td className="px-3 py-2.5">
                            <div className="flex items-center gap-2">
                              <div className="w-20 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--glass-bg-2)' }}>
                                <div className="h-full rounded-full" style={{ width: `${a.score}%`, background: scoreColor }} />
                              </div>
                              <span className="text-xs font-bold tabular-nums" style={{ color: scoreColor }}>{a.score}</span>
                            </div>
                          </td>
                          <td className="px-3 py-2.5 text-xs" style={{ color: 'var(--text-3)' }}>{a.top_reason}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </RootLayout>
  );
}
