'use client';

import { useState, useEffect } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import api from '@/lib/api';
import { Activity, AlertTriangle, CheckCircle, RefreshCw, Wifi, TrendingUp } from 'lucide-react';

interface NetworkAnomaly {
  id: number; agent_id: number; hostname: string; tenant_id: number;
  anomaly_type: string; dst_ip: string; dst_port: number; proto: string;
  deviation_score: number; description: string;
  is_acknowledged: boolean; detected_at: string;
}

const ANOMALY_TYPE_LABELS: Record<string, { label: string; color: string }> = {
  new_destination: { label: 'New Destination', color: '#fb923c' },
  rare_port:       { label: 'Rare Port',        color: '#f85149' },
  volume_spike:    { label: 'Volume Spike',      color: '#a855f7' },
  new_proto:       { label: 'New Protocol',      color: '#38bdf8' },
};

function ScoreBar({ score }: { score: number }) {
  const color = score >= 80 ? '#f85149' : score >= 60 ? '#fb923c' : '#fbbf24';
  return (
    <div className="flex items-center gap-2">
      <div className="w-14 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--glass-bg-2)' }}>
        <div className="h-full rounded-full" style={{ width: `${score}%`, background: color }} />
      </div>
      <span className="text-xs font-bold tabular-nums" style={{ color }}>{score}</span>
    </div>
  );
}

export default function NBAPage() {
  const [anomalies, setAnomalies] = useState<NetworkAnomaly[]>([]);
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [filter, setFilter] = useState<'all' | 'open' | 'acked'>('open');

  const load = async () => {
    setLoading(true);
    const r = await api.get('/nba/anomalies?limit=200').catch(() => ({ data: [] }));
    setAnomalies(r.data || []);
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const acknowledge = async (id: number) => {
    await api.post(`/nba/anomalies/${id}/acknowledge`);
    setAnomalies(prev => prev.map(a => a.id === id ? { ...a, is_acknowledged: true } : a));
  };

  const triggerAnalysis = async () => {
    setAnalyzing(true);
    await api.post('/nba/analyze');
    setTimeout(() => { load(); setAnalyzing(false); }, 3000);
  };

  const filtered = anomalies.filter(a =>
    filter === 'all' ? true :
    filter === 'open' ? !a.is_acknowledged :
    a.is_acknowledged
  );

  const openCount = anomalies.filter(a => !a.is_acknowledged).length;
  const highScore = anomalies.filter(a => a.deviation_score >= 80).length;
  const uniqueAgents = new Set(anomalies.map(a => a.agent_id)).size;

  return (
    <RootLayout title="Network Behavior Analytics"
      subtitle="Baseline deviation detection · New destinations · Volume spikes"
      actions={
        <button onClick={triggerAnalysis} disabled={analyzing}
          className="g-btn g-btn-ghost flex items-center gap-1.5 text-xs">
          <RefreshCw className={`h-3.5 w-3.5 ${analyzing ? 'animate-spin' : ''}`} />
          {analyzing ? 'Analyzing…' : 'Run Analysis'}
        </button>
      }>

      {/* KPIs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
        {[
          { label: 'Open Anomalies', value: openCount, color: openCount > 0 ? '#f85149' : 'var(--text-3)', icon: AlertTriangle },
          { label: 'High Score (≥80)', value: highScore, color: highScore > 0 ? '#fb923c' : 'var(--text-3)', icon: TrendingUp },
          { label: 'Affected Agents', value: uniqueAgents, color: 'var(--accent)', icon: Wifi },
          { label: 'Total Detected', value: anomalies.length, color: 'var(--text-2)', icon: Activity },
        ].map(({ label, value, color, icon: Icon }) => (
          <div key={label} className="g-card p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg" style={{ background: `${color}18` }}>
              <Icon className="h-4 w-4" style={{ color }} />
            </div>
            <div>
              <p className="text-xl font-bold" style={{ color }}>{value}</p>
              <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* How it works note */}
      <div className="rounded-xl px-4 py-3 mb-4 text-xs" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-3)' }}>
        <span className="font-semibold" style={{ color: 'var(--text-2)' }}>How NBA works: </span>
        Baselines normal outbound connections per agent from eBPF connect events. Flags new external destinations, rare ports, and volume spikes (3×+ hourly average). Runs automatically every 30 minutes for online agents.
      </div>

      {/* Filter tabs */}
      <div className="flex gap-1.5 mb-4">
        {([['open', 'Open'], ['acked', 'Acknowledged'], ['all', 'All']] as const).map(([v, l]) => (
          <button key={v} onClick={() => setFilter(v)}
            className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
            style={{
              background: filter === v ? 'var(--accent-glow)' : 'var(--glass-bg)',
              border: `1px solid ${filter === v ? 'var(--accent-border)' : 'var(--border)'}`,
              color: filter === v ? 'var(--accent)' : 'var(--text-2)',
            }}>{l}</button>
        ))}
      </div>

      {/* Table */}
      <div className="g-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full" style={{ borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Score', 'Type', 'Agent', 'Destination', 'Port/Proto', 'Description', 'Detected', ''].map(h => (
                  <th key={h} className="px-3 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={8} className="px-4 py-12 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={8} className="px-4 py-12 text-center">
                  <Activity className="mx-auto h-10 w-10 mb-2 opacity-20" style={{ color: 'var(--text-3)' }} />
                  <p className="text-sm" style={{ color: 'var(--text-3)' }}>
                    {filter === 'open' ? 'No open anomalies — network behaviour looks normal.' : 'No anomalies in this view.'}
                  </p>
                  <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>
                    Anomalies populate after agents have been online and the first analysis run completes.
                  </p>
                </td></tr>
              ) : filtered.map(a => {
                const typeInfo = ANOMALY_TYPE_LABELS[a.anomaly_type] || { label: a.anomaly_type, color: 'var(--text-3)' };
                return (
                  <tr key={a.id} style={{
                    borderBottom: '1px solid var(--border)',
                    opacity: a.is_acknowledged ? 0.55 : 1,
                  }}>
                    <td className="px-3 py-2.5"><ScoreBar score={a.deviation_score} /></td>
                    <td className="px-3 py-2.5">
                      <span className="text-[10px] font-bold px-1.5 py-0.5 rounded"
                        style={{ background: `${typeInfo.color}18`, color: typeInfo.color, border: `1px solid ${typeInfo.color}40` }}>
                        {typeInfo.label}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 text-xs font-medium" style={{ color: 'var(--text-1)' }}>
                      {a.hostname || `Agent #${a.agent_id}`}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-xs" style={{ color: 'var(--accent)' }}>
                      {a.dst_ip || '—'}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-xs" style={{ color: 'var(--text-3)' }}>
                      {a.dst_port > 0 ? `${a.dst_port}/${a.proto}` : '—'}
                    </td>
                    <td className="px-3 py-2.5 text-xs max-w-[280px]" style={{ color: 'var(--text-2)' }}>
                      {a.description}
                    </td>
                    <td className="px-3 py-2.5 text-[11px] whitespace-nowrap" style={{ color: 'var(--text-3)' }}>
                      {new Date(a.detected_at).toLocaleString()}
                    </td>
                    <td className="px-3 py-2.5">
                      {!a.is_acknowledged ? (
                        <button onClick={() => acknowledge(a.id)}
                          className="g-btn g-btn-ghost text-[11px] flex items-center gap-1">
                          <CheckCircle className="h-3 w-3" /> Ack
                        </button>
                      ) : (
                        <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>✓ acked</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </RootLayout>
  );
}
