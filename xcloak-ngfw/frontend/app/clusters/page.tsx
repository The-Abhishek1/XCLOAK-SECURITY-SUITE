'use client';

import { useState, useEffect } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import api from '@/lib/api';
import { GitMerge, AlertTriangle, ChevronDown, ChevronRight, RefreshCw, VolumeX, ExternalLink } from 'lucide-react';
import Link from 'next/link';

interface AlertCluster {
  id: number; cluster_key: string; mitre_technique: string; rule_name: string;
  alert_count: number; first_seen: string; last_seen: string;
  auto_incident_id: number | null; status: string;
}
interface ClusterAlert {
  id: number; rule_name: string; severity: string; status: string;
  hostname: string; created_at: string;
}

const STATUS_COLOR: Record<string, string> = {
  open: '#fb923c', promoted: '#22c55e', suppressed: 'var(--text-3)',
};
const SEV_COLOR: Record<string, string> = {
  critical: '#f85149', high: '#fb923c', medium: '#fbbf24', low: '#22c55e',
};

function ClusterRow({ cluster, expanded, onToggle, onSuppress }: {
  cluster: AlertCluster; expanded: boolean; onToggle: () => void; onSuppress: () => void;
}) {
  const [alerts, setAlerts] = useState<ClusterAlert[]>([]);
  const [loading, setLoading] = useState(false);

  const load = async () => {
    if (alerts.length > 0) return;
    setLoading(true);
    const r = await api.get(`/clusters/${cluster.id}/alerts`).catch(() => ({ data: [] }));
    setAlerts(r.data || []);
    setLoading(false);
  };

  const handleToggle = () => { onToggle(); if (!expanded) load(); };
  const statusColor = STATUS_COLOR[cluster.status] || 'var(--text-3)';

  const age = Math.round((Date.now() - new Date(cluster.first_seen).getTime()) / 60000);
  const ageStr = age < 60 ? `${age}m` : `${Math.round(age / 60)}h`;

  return (
    <div style={{ borderBottom: '1px solid var(--border)', opacity: cluster.status === 'suppressed' ? 0.5 : 1 }}>
      <div className="flex items-center gap-3 px-3 py-2.5 cursor-pointer hover:bg-[var(--glass-bg-2)] transition-colors" onClick={handleToggle}>
        {expanded ? <ChevronDown className="h-3 w-3 shrink-0" style={{ color: 'var(--text-3)' }} />
                  : <ChevronRight className="h-3 w-3 shrink-0" style={{ color: 'var(--text-3)' }} />}

        {/* Count badge */}
        <span className="text-xs font-bold w-7 text-center tabular-nums rounded px-1"
          style={{ background: `${statusColor}18`, color: statusColor }}>
          {cluster.alert_count}
        </span>

        {/* Rule name */}
        <span className="flex-1 text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>
          {cluster.rule_name || cluster.cluster_key}
        </span>

        {/* MITRE */}
        {cluster.mitre_technique && (
          <a href={`https://attack.mitre.org/techniques/${cluster.mitre_technique}`}
            target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()}
            className="text-[10px] font-mono px-1.5 py-0.5 rounded hover:underline shrink-0"
            style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
            {cluster.mitre_technique}
          </a>
        )}

        {/* Status */}
        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded shrink-0"
          style={{ background: `${statusColor}15`, color: statusColor }}>
          {cluster.status}
        </span>

        {/* Auto incident link */}
        {cluster.auto_incident_id && (
          <Link href={`/incidents?id=${cluster.auto_incident_id}`} onClick={e => e.stopPropagation()}
            className="text-[10px] flex items-center gap-0.5 shrink-0 hover:underline"
            style={{ color: 'var(--accent)' }}>
            INC#{cluster.auto_incident_id} <ExternalLink className="h-2.5 w-2.5" />
          </Link>
        )}

        {/* Age */}
        <span className="text-[10px] shrink-0" style={{ color: 'var(--text-3)' }}>{ageStr} ago</span>

        {/* Suppress */}
        {cluster.status === 'open' && (
          <button onClick={e => { e.stopPropagation(); onSuppress(); }}
            className="p-1 rounded hover:bg-[var(--glass-bg)] shrink-0" title="Suppress cluster">
            <VolumeX className="h-3 w-3" style={{ color: 'var(--text-3)' }} />
          </button>
        )}
      </div>

      {expanded && (
        <div className="px-10 pb-3">
          {loading ? (
            <p className="text-xs animate-pulse py-1" style={{ color: 'var(--text-3)' }}>Loading alerts…</p>
          ) : alerts.map(a => (
            <div key={a.id} className="flex items-center gap-2 py-1 border-b" style={{ borderColor: 'var(--border)' }}>
              <span className="text-[10px] font-bold w-12 shrink-0" style={{ color: SEV_COLOR[a.severity] || 'var(--text-3)' }}>
                {a.severity?.toUpperCase()}
              </span>
              <span className="text-xs flex-1 truncate" style={{ color: 'var(--text-2)' }}>{a.rule_name}</span>
              {a.hostname && <span className="text-[10px] shrink-0" style={{ color: 'var(--text-3)' }}>@ {a.hostname}</span>}
              <span className="text-[10px] shrink-0" style={{ color: 'var(--text-3)' }}>
                {new Date(a.created_at).toLocaleTimeString()}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function ClustersPage() {
  const [clusters, setClusters] = useState<AlertCluster[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [expandedID, setExpandedID] = useState<number | null>(null);
  const [filter, setFilter] = useState<'all' | 'open' | 'promoted' | 'suppressed'>('open');

  const load = async () => {
    setLoading(true);
    const r = await api.get('/clusters?limit=200').catch(() => ({ data: [] }));
    setClusters(r.data || []);
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const runClustering = async () => {
    setRunning(true);
    await api.post('/clusters/analyze');
    setTimeout(() => { load(); setRunning(false); }, 3000);
  };

  const suppress = async (id: number) => {
    await api.post(`/clusters/${id}/suppress`);
    setClusters(prev => prev.map(c => c.id === id ? { ...c, status: 'suppressed' } : c));
  };

  const filtered = clusters.filter(c => filter === 'all' ? true : c.status === filter);
  const openCount = clusters.filter(c => c.status === 'open').length;
  const promotedCount = clusters.filter(c => c.status === 'promoted').length;
  const totalAlerts = clusters.reduce((s, c) => s + c.alert_count, 0);

  return (
    <RootLayout title="Alert Clustering"
      subtitle="MITRE technique + time-window grouping · Auto incident promotion"
      actions={
        <button onClick={runClustering} disabled={running}
          className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
          <RefreshCw className={`h-3.5 w-3.5 ${running ? 'animate-spin' : ''}`} />
          {running ? 'Clustering…' : 'Run Now'}
        </button>
      }>

      {/* KPIs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
        {[
          { label: 'Total Clusters', value: clusters.length, color: 'var(--accent)' },
          { label: 'Open', value: openCount, color: openCount > 0 ? '#fb923c' : 'var(--text-3)' },
          { label: 'Auto-Promoted', value: promotedCount, color: '#22c55e' },
          { label: 'Grouped Alerts', value: totalAlerts, color: 'var(--text-2)' },
        ].map(({ label, value, color }) => (
          <div key={label} className="g-card p-4">
            <p className="text-2xl font-bold" style={{ color }}>{value}</p>
            <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{label}</p>
          </div>
        ))}
      </div>

      <div className="rounded-xl px-4 py-3 mb-4 text-xs" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-3)' }}>
        <span className="font-semibold" style={{ color: 'var(--text-2)' }}>Auto-clustering: </span>
        Alerts sharing the same MITRE technique or rule name on the same agent within a 24h window are grouped. Clusters with ≥3 alerts are automatically promoted to incidents. Runs every 15 minutes.
      </div>

      {/* Tabs */}
      <div className="flex gap-1.5 mb-4">
        {(['all', 'open', 'promoted', 'suppressed'] as const).map(v => (
          <button key={v} onClick={() => setFilter(v)}
            className="px-3 py-1.5 rounded-lg text-xs font-medium capitalize transition-all"
            style={{
              background: filter === v ? 'var(--accent-glow)' : 'var(--glass-bg)',
              border: `1px solid ${filter === v ? 'var(--accent-border)' : 'var(--border)'}`,
              color: filter === v ? 'var(--accent)' : 'var(--text-2)',
            }}>{v}</button>
        ))}
      </div>

      <div className="g-card overflow-hidden">
        {loading ? (
          <div className="py-12 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading clusters…</div>
        ) : filtered.length === 0 ? (
          <div className="py-12 text-center">
            <GitMerge className="mx-auto h-10 w-10 mb-2 opacity-20" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-3)' }}>
              {filter === 'open' ? 'No open clusters — alerts are not forming patterns right now.' : 'No clusters in this view.'}
            </p>
            <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>
              Clustering runs automatically every 15 min or click "Run Now" above.
            </p>
          </div>
        ) : (
          filtered.map(c => (
            <ClusterRow key={c.id} cluster={c}
              expanded={expandedID === c.id}
              onToggle={() => setExpandedID(p => p === c.id ? null : c.id)}
              onSuppress={() => suppress(c.id)} />
          ))
        )}
      </div>
    </RootLayout>
  );
}
