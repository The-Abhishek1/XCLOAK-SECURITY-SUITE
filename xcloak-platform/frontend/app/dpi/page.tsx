'use client';

import { useState, useEffect, useCallback } from 'react';
import { dpiAPI } from '@/lib/api';
import {
  Search, RefreshCw, Filter, AlertTriangle, ShieldAlert,
  Globe, Lock, Code2, Network, Activity, ChevronDown, ChevronUp,
} from 'lucide-react';

// ── Types ─────────────────────────────────────────────────────────────────────

interface DPIFinding {
  id: number;
  agent_id: number;
  finding_type: string;
  severity: string;
  score: number;
  indicator: string;
  description: string;
  mitre_technique: string;
  raw_context: Record<string, unknown>;
  alert_fired: boolean;
  detected_at: string;
}

interface DPISummary {
  total_24h: number;
  alerted_24h: number;
  breakdown: { finding_type: string; severity: string; count: number }[];
}

// ── Constants ─────────────────────────────────────────────────────────────────

const FINDING_TYPE_META: Record<string, { label: string; icon: React.ElementType; color: string }> = {
  dga:                { label: 'DGA Domain',        icon: Globe,       color: 'text-purple-400' },
  tls_anomaly:        { label: 'TLS Anomaly',       icon: Lock,        color: 'text-yellow-400' },
  http_pattern:       { label: 'HTTP Pattern',      icon: Code2,       color: 'text-red-400'    },
  dns_tunnel:         { label: 'DNS Tunnel',        icon: Network,     color: 'text-orange-400' },
  proto_on_wrong_port:{ label: 'Protocol Anomaly',  icon: Activity,    color: 'text-blue-400'   },
  icmp_tunnel:        { label: 'ICMP Tunnel',       icon: Network,     color: 'text-orange-400' },
  http_connect_tunnel:{ label: 'CONNECT Tunnel',    icon: Network,     color: 'text-red-400'    },
  dns_tcp_tunnel:     { label: 'DNS-TCP Tunnel',    icon: Network,     color: 'text-orange-400' },
  smtp_non_standard:  { label: 'SMTP Exfil',        icon: AlertTriangle, color: 'text-red-400'  },
};

const SEV_COLOR: Record<string, string> = {
  critical: 'bg-red-900/60 text-red-300 border border-red-700',
  high:     'bg-orange-900/60 text-orange-300 border border-orange-700',
  medium:   'bg-yellow-900/60 text-yellow-300 border border-yellow-700',
  low:      'bg-blue-900/60 text-blue-300 border border-blue-700',
};

const ALL_TYPES = ['', 'dga', 'tls_anomaly', 'http_pattern', 'dns_tunnel',
  'proto_on_wrong_port', 'icmp_tunnel', 'http_connect_tunnel', 'dns_tcp_tunnel', 'smtp_non_standard'];
const ALL_SEV  = ['', 'critical', 'high', 'medium', 'low'];

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function DPIPage() {
  const [findings, setFindings] = useState<DPIFinding[]>([]);
  const [summary,  setSummary]  = useState<DPISummary | null>(null);
  const [loading,  setLoading]  = useState(true);
  const [search,   setSearch]   = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [sevFilter,  setSevFilter]  = useState('');
  const [alertOnly,  setAlertOnly]  = useState(false);
  const [expanded,   setExpanded]   = useState<Set<number>>(new Set());

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [fRes, sRes] = await Promise.all([
        dpiAPI.getFindings({
          finding_type: typeFilter || undefined,
          severity:     sevFilter  || undefined,
          alert_only:   alertOnly  || undefined,
          limit: 200,
        }),
        dpiAPI.getSummary(),
      ]);
      setFindings((fRes.data as { findings: DPIFinding[] }).findings || []);
      setSummary(sRes.data as DPISummary);
    } finally {
      setLoading(false);
    }
  }, [typeFilter, sevFilter, alertOnly]);

  useEffect(() => { load(); }, [load]);

  const filtered = findings.filter(f => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      f.description.toLowerCase().includes(q) ||
      f.indicator.toLowerCase().includes(q) ||
      f.finding_type.toLowerCase().includes(q) ||
      f.mitre_technique.toLowerCase().includes(q)
    );
  });

  const toggleExpand = (id: number) => {
    setExpanded(prev => {
      const s = new Set(prev);
      s.has(id) ? s.delete(id) : s.add(id);
      return s;
    });
  };

  const typeMeta = (t: string) =>
    FINDING_TYPE_META[t] ?? { label: t, icon: ShieldAlert, color: 'text-gray-400' };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Deep Packet Inspection</h1>
          <p className="text-gray-400 text-sm mt-1">
            L7 threat findings: DGA domains, TLS anomalies, HTTP threats, protocol tunneling
          </p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded-lg transition-colors text-sm">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard label="Findings (24h)"   value={summary.total_24h}   color="text-white" />
          <StatCard label="Alerts Fired"     value={summary.alerted_24h} color="text-red-400" />
          <StatCard label="Finding Types"    value={summary.breakdown.length} color="text-blue-400" />
          <StatCard label="Critical + High"  value={summary.breakdown.filter(b => b.severity === 'critical' || b.severity === 'high').reduce((a, b) => a + b.count, 0)} color="text-orange-400" />
        </div>
      )}

      {/* Breakdown pills */}
      {summary && summary.breakdown.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {summary.breakdown.slice(0, 10).map((b, i) => {
            const meta = typeMeta(b.finding_type);
            return (
              <span key={i} className="flex items-center gap-1 px-3 py-1 bg-gray-800 rounded-full text-xs">
                <span className={meta.color}>{meta.label}</span>
                <span className="text-gray-400">·</span>
                <span className={SEV_COLOR[b.severity]?.split(' ')[1] ?? 'text-gray-300'}>{b.severity}</span>
                <span className="font-semibold text-white ml-1">{b.count}</span>
              </span>
            );
          })}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search findings…"
            className="w-full pl-9 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-gray-400" />
          <select
            value={typeFilter}
            onChange={e => setTypeFilter(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none"
          >
            <option value="">All Types</option>
            {ALL_TYPES.slice(1).map(t => (
              <option key={t} value={t}>{typeMeta(t).label}</option>
            ))}
          </select>

          <select
            value={sevFilter}
            onChange={e => setSevFilter(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none"
          >
            <option value="">All Severities</option>
            {ALL_SEV.slice(1).map(s => (
              <option key={s} value={s} className="capitalize">{s}</option>
            ))}
          </select>
        </div>

        <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={alertOnly}
            onChange={e => setAlertOnly(e.target.checked)}
            className="accent-red-500"
          />
          Alerts only
        </label>

        <span className="text-xs text-gray-500 ml-auto">{filtered.length} findings</span>
      </div>

      {/* Findings Table */}
      <div className="rounded-xl border border-gray-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-800/50">
            <tr className="text-gray-400 text-xs uppercase tracking-wider">
              <th className="px-4 py-3 text-left">Type</th>
              <th className="px-4 py-3 text-left">Severity</th>
              <th className="px-4 py-3 text-left">Score</th>
              <th className="px-4 py-3 text-left">Indicator</th>
              <th className="px-4 py-3 text-left">MITRE</th>
              <th className="px-4 py-3 text-left">Agent</th>
              <th className="px-4 py-3 text-left">Detected</th>
              <th className="px-4 py-3 text-center">Alert</th>
              <th className="px-4 py-3" />
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/60">
            {loading && (
              <tr><td colSpan={9} className="px-4 py-10 text-center text-gray-500">Loading…</td></tr>
            )}
            {!loading && filtered.length === 0 && (
              <tr><td colSpan={9} className="px-4 py-10 text-center text-gray-500">No findings match the current filters.</td></tr>
            )}
            {!loading && filtered.map(f => {
              const meta = typeMeta(f.finding_type);
              const Icon = meta.icon;
              const isExp = expanded.has(f.id);
              return (
                <>
                  <tr key={f.id} className="bg-gray-900/40 hover:bg-gray-800/40 transition-colors">
                    <td className="px-4 py-3">
                      <span className={`flex items-center gap-1.5 font-medium ${meta.color}`}>
                        <Icon className="w-4 h-4 shrink-0" />
                        {meta.label}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEV_COLOR[f.severity] ?? ''} capitalize`}>
                        {f.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <ScoreBar score={f.score} />
                    </td>
                    <td className="px-4 py-3 max-w-48">
                      <span className="font-mono text-xs text-gray-300 truncate block" title={f.indicator}>
                        {f.indicator}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-mono text-xs text-blue-400">{f.mitre_technique}</span>
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-xs">{f.agent_id}</td>
                    <td className="px-4 py-3 text-gray-500 text-xs whitespace-nowrap">
                      {new Date(f.detected_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-center">
                      {f.alert_fired
                        ? <span className="w-2 h-2 rounded-full bg-red-500 inline-block" title="Alert fired" />
                        : <span className="w-2 h-2 rounded-full bg-gray-700 inline-block" />
                      }
                    </td>
                    <td className="px-4 py-3">
                      <button onClick={() => toggleExpand(f.id)} className="text-gray-500 hover:text-gray-300">
                        {isExp ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </button>
                    </td>
                  </tr>
                  {isExp && (
                    <tr key={`${f.id}-detail`} className="bg-gray-950">
                      <td colSpan={9} className="px-6 py-4">
                        <div className="space-y-2">
                          <p className="text-gray-300 text-sm">{f.description}</p>
                          {f.raw_context && (
                            <pre className="text-xs text-gray-400 bg-gray-800/50 rounded-lg p-3 overflow-x-auto">
                              {JSON.stringify(f.raw_context, null, 2)}
                            </pre>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="bg-gray-800/50 rounded-xl border border-gray-700 p-4">
      <p className="text-gray-400 text-xs uppercase tracking-wider">{label}</p>
      <p className={`text-3xl font-bold mt-1 ${color}`}>{value}</p>
    </div>
  );
}

function ScoreBar({ score }: { score: number }) {
  const color = score >= 80 ? 'bg-red-500' : score >= 60 ? 'bg-orange-500' : score >= 40 ? 'bg-yellow-500' : 'bg-gray-500';
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-gray-700 rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs text-gray-400">{score}</span>
    </div>
  );
}
