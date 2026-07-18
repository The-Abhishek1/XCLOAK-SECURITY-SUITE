'use client';

import {
  useState, useEffect, useCallback, useMemo, useRef,
} from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { clustersAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import Link from 'next/link';
import { Activity, AlertTriangle, ArrowRight, BarChart3, Brain, Check, CheckCircle2, Copy, Cpu, ExternalLink, GitMerge, Globe, Layers, Network, Play, Plus, RefreshCw, Search, Shield, Target, VolumeX, X, Zap } from '@/lib/icon-stubs';

// ── Types ─────────────────────────────────────────────────────────────────────

type ViewTab = 'overview' | 'clusters' | 'campaign' | 'chain' | 'graph' | 'analytics' | 'ai';

interface Overview {
  total: number;
  active_clusters: number;
  new_clusters: number;
  high_risk: number;
  closed: number;
  campaigns: number;
  related_incidents: number;
  avg_cluster_size: string;
  cluster_confidence: number;
  trend: Array<{ day: string; count: number }>;
  status_breakdown: Record<string, number>;
}

interface ClusterRow {
  id: number;
  cluster_key: string;
  mitre_technique: string;
  rule_name: string;
  alert_count: number;
  first_seen: string;
  last_seen: string;
  incident_id: number;
  status: string;
  severity: string;
  host_count: number;
  risk_score: number;
  confidence: number;
  campaign: string;
}

interface ClusterDetail {
  cluster: ClusterRow;
  alerts: Array<{
    id: number; rule_name: string; severity: string; status: string;
    hostname: string; created_at: string; mitre_technique: string; mitre_tactic: string; source_ip: string;
  }>;
  hosts: Array<{ hostname: string; agent_id: number; count: number }>;
  ips: Array<{ ip: string; count: number }>;
  mitre: Array<{ technique: string; tactic: string; count: number }>;
}

interface TimelineEvent {
  id: number; rule_name: string; severity: string; hostname: string;
  time: string; mitre_technique: string; mitre_tactic: string;
  source_ip: string; status: string;
}

interface GraphNode { id: string; label: string; type: 'host' | 'rule' | 'ip' | 'incident'; count: number; }
interface GraphEdge { source: string; target: string; }

interface Analytics {
  size_distribution: Array<{ bucket: string; count: number }>;
  campaigns: Array<{ technique: string; campaign: string; clusters: number; alerts: number }>;
  top_clusters: Array<{ id: number; rule_name: string; alert_count: number; status: string; technique: string }>;
  mttr_hours: string;
}

interface Campaign {
  technique: string; campaign: string; cluster_count: number;
  total_alerts: number; latest: string; has_open: boolean; risk_level: string;
}

interface AIResult { raw: string; parsed: Record<string, unknown> | null; }

// ── Constants ─────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)', high: '#fb923c', medium: '#fbbf24',
  low: 'var(--accent)', informational: 'var(--text-3)',
};

const STATUS_COLOR: Record<string, string> = {
  open: '#fb923c', promoted: 'var(--accent)',
  suppressed: 'var(--text-3)', closed: 'var(--text-3)',
};

const RISK_COLOR = (score: number) => {
  if (score >= 70) return 'var(--red)';
  if (score >= 40) return '#fb923c';
  if (score >= 20) return '#fbbf24';
  return 'var(--green)';
};

const TABS: Array<{ id: ViewTab; label: string; icon: React.ElementType }> = [
  { id: 'overview',  label: 'Overview',      icon: BarChart3 },
  { id: 'clusters',  label: 'Clusters',      icon: GitMerge },
  { id: 'campaign',  label: 'Campaigns',     icon: Target },
  { id: 'chain',     label: 'Attack Chain',  icon: Layers },
  { id: 'graph',     label: 'Graph',         icon: Network },
  { id: 'analytics', label: 'Analytics',     icon: Activity },
  { id: 'ai',        label: 'AI Analysis',   icon: Brain },
];

const CAMPAIGN_CHAIN: Record<string, Array<{ label: string; detail: string }>> = {
  Phishing: [
    { label: 'Email Delivery',    detail: 'Spear phishing with malicious attachment or link' },
    { label: 'User Opens',        detail: 'Office document / PDF / HTML lure opened' },
    { label: 'Macro Execution',   detail: 'VBA macro or JavaScript dropper runs' },
    { label: 'Payload Download',  detail: 'Stage-2 download via HTTP/S or DNS' },
    { label: 'Persistence',       detail: 'Scheduled task / registry run key' },
    { label: 'C2 Established',    detail: 'Beacon to attacker infrastructure' },
    { label: '→ Campaign Goal',   detail: 'Credential theft / ransomware / espionage' },
  ],
  Ransomware: [
    { label: 'Initial Access',    detail: 'Phishing / RDP brute force / vuln exploit' },
    { label: 'PowerShell Exec',   detail: 'Encoded downloader spawned from Office' },
    { label: 'Credential Dump',   detail: 'LSASS access / Kerberoasting / DCSync' },
    { label: 'Lateral Movement',  detail: 'RDP / WMI / SMB pass-the-hash' },
    { label: 'Domain Compromise', detail: 'Domain admin acquired, AD recon' },
    { label: 'Data Staging',      detail: 'Bulk copy to staging dir before encryption' },
    { label: 'Encryption',        detail: 'VSS deletion + file encryption + ransom note' },
  ],
  'Lateral Movement': [
    { label: 'Foothold',          detail: 'Initial compromise of endpoint or server' },
    { label: 'Privilege Escalation', detail: 'Token impersonation / UAC bypass' },
    { label: 'Credential Access', detail: 'LSASS dump / cached credentials' },
    { label: 'Internal Recon',    detail: 'Net user / nltest / AD enumeration' },
    { label: 'Pivot via RDP',     detail: 'RDP / WinRM / PsExec to adjacent host' },
    { label: 'SMB Traversal',     detail: 'Share access, file copy, service install' },
    { label: 'Goal Achieved',     detail: 'DC access / data access / ransomware' },
  ],
  'Credential Theft': [
    { label: 'Access Gained',     detail: 'Spear phish / VPN brute force / supply chain' },
    { label: 'LSASS Dump',        detail: 'Mimikatz / ProcDump / MiniDumpWriteDump' },
    { label: 'Kerberoasting',     detail: 'SPN discovery and TGS ticket request' },
    { label: 'Hash Captured',     detail: 'Pass-the-hash / PTT / NTLM relay' },
    { label: 'Domain Escalation', detail: 'DCSync / Golden ticket / silver ticket' },
    { label: 'Persistence',       detail: 'New admin account / backdoor / golden ticket' },
    { label: 'Exfil/Impact',      detail: 'Data theft / ransomware / sabotage' },
  ],
};

const DEFAULT_CHAIN = CAMPAIGN_CHAIN.Ransomware;

// ── Helpers ───────────────────────────────────────────────────────────────────

function sevBadge(sev: string) {
  const color = SEV_COLOR[sev] ?? 'var(--text-3)';
  return (
    <span className="px-2 py-0.5 rounded text-[10px] font-bold capitalize"
      style={{ background: `color-mix(in srgb, ${color} 15%, transparent)`, color }}>
      {sev || '—'}
    </span>
  );
}

function statusBadge(s: string) {
  const color = STATUS_COLOR[s] ?? 'var(--text-3)';
  return (
    <span className="px-2 py-0.5 rounded text-[10px] font-semibold capitalize"
      style={{ background: `color-mix(in srgb, ${color} 12%, transparent)`, color, border: `1px solid color-mix(in srgb, ${color} 30%, transparent)` }}>
      {s}
    </span>
  );
}

function MiniBar({ value, max, color }: { value: number; max: number; color: string }) {
  const pct = max > 0 ? Math.max(2, (value / max) * 100) : 2;
  return (
    <div className="h-1.5 flex-1 rounded-full overflow-hidden" style={{ background: 'var(--glass-bg-2)' }}>
      <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
    </div>
  );
}

function RiskMeter({ score }: { score: number }) {
  return (
    <div className="flex items-center gap-1.5">
      <div className="h-1.5 w-16 rounded-full overflow-hidden" style={{ background: 'var(--glass-bg-2)' }}>
        <div className="h-full rounded-full transition-all"
          style={{ width: `${score}%`, background: RISK_COLOR(score) }} />
      </div>
      <span className="text-[11px] font-bold tabular-nums" style={{ color: RISK_COLOR(score) }}>{score}</span>
    </div>
  );
}

function CopyBtn({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(text).catch(() => {}); setDone(true); setTimeout(() => setDone(false), 1500); }}
      style={{ color: done ? 'var(--accent)' : 'var(--text-3)' }}>
      {done ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  );
}

// ── KPI Card ──────────────────────────────────────────────────────────────────

function KPICard({ label, value, sub, color, icon: Icon }: {
  label: string; value: number | string; sub?: string; color: string; icon: React.ElementType;
}) {
  return (
    <div className="g-card p-4 flex items-start gap-3">
      <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
        style={{ background: `color-mix(in srgb, ${color} 15%, transparent)` }}>
        <Icon className="w-4 h-4" style={{ color }} />
      </div>
      <div className="min-w-0">
        <p className="text-[10px] uppercase tracking-wider mb-0.5 font-medium" style={{ color: 'var(--text-3)' }}>{label}</p>
        <p className="text-2xl font-bold leading-none" style={{ color }}>{value}</p>
        {sub && <p className="text-[11px] mt-1" style={{ color: 'var(--text-3)' }}>{sub}</p>}
      </div>
    </div>
  );
}

// ── Trend Sparkline ────────────────────────────────────────────────────────────

function TrendSparkline({ data }: { data: Array<{ day: string; count: number }> }) {
  const max = Math.max(...data.map(d => d.count), 1);
  if (!data.length) return <div className="h-12" />;
  return (
    <div className="flex items-end gap-1 h-12">
      {data.map((d, i) => (
        <div key={i} className="flex-1 flex flex-col items-center gap-0.5 min-w-[6px]">
          <div className="w-full rounded-sm"
            title={`${d.day}: ${d.count}`}
            style={{ height: `${Math.max(4, (d.count / max) * 44)}px`, background: 'var(--accent)', opacity: 0.8 }} />
          <span className="text-[8px] truncate w-full text-center hidden sm:block" style={{ color: 'var(--text-3)' }}>
            {new Date(d.day).getDate()}
          </span>
        </div>
      ))}
    </div>
  );
}

// ── Cluster Detail Panel ───────────────────────────────────────────────────────

function ClusterDetailPanel({ clusterId, onClose }: { clusterId: number; onClose: () => void }) {
  const [detail, setDetail]       = useState<ClusterDetail | null>(null);
  const [timeline, setTimeline]   = useState<TimelineEvent[]>([]);
  const [graphData, setGraphData] = useState<{ nodes: GraphNode[]; edges: GraphEdge[] } | null>(null);
  const [innerTab, setInnerTab]   = useState<'members' | 'timeline' | 'graph' | 'intel'>('members');
  const [actionLoading, setActionLoading] = useState('');
  const [toast, setToast] = useState<string | null>(null);
  const [mergeInput, setMergeInput] = useState('');
  const [showMerge, setShowMerge] = useState(false);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  useEffect(() => {
    clustersAPI.getDetail(clusterId).then(r => { if (r.data) setDetail(r.data as ClusterDetail); });
  }, [clusterId]);

  useEffect(() => {
    if (innerTab === 'timeline') {
      clustersAPI.getTimeline(clusterId).then(r => {
        const d = r.data as { events?: TimelineEvent[] } | null;
        if (d?.events) setTimeline(d.events);
      });
    }
    if (innerTab === 'graph') {
      clustersAPI.getGraph(clusterId).then(r => {
        if (r.data) setGraphData(r.data as { nodes: GraphNode[]; edges: GraphEdge[] });
      });
    }
  }, [innerTab, clusterId]);

  const doAction = async (action: string) => {
    setActionLoading(action);
    try {
      await clustersAPI.bulkAction(clusterId, action);
      notify(`Action "${action}" completed`);
      if (detail) setDetail({ ...detail, cluster: { ...detail.cluster, status: action === 'close' ? 'closed' : detail.cluster.status } });
    } finally {
      setActionLoading('');
    }
  };

  const doMerge = async () => {
    const tid = parseInt(mergeInput);
    if (!tid) return;
    await clustersAPI.merge(clusterId, tid);
    notify(`Merged into cluster #${tid}`);
    setShowMerge(false);
    onClose();
  };

  if (!detail) return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.7)' }}>
      <div className="g-card p-8 text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
    </div>
  );

  const { cluster, alerts, hosts, ips, mitre } = detail;
  const maxIPs = Math.max(...ips.map(i => i.count), 1);
  const maxHosts = Math.max(...hosts.map(h => h.count), 1);

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center p-0 sm:p-4"
      style={{ background: 'rgba(0,0,0,0.7)' }} onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="w-full sm:max-w-4xl max-h-[90vh] flex flex-col rounded-t-2xl sm:rounded-2xl overflow-hidden"
        style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>

        {/* Header */}
        <div className="flex items-start gap-3 p-5 shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <h2 className="text-sm font-semibold truncate" style={{ color: 'var(--text-1)' }}>{cluster.rule_name || cluster.cluster_key}</h2>
              {statusBadge(cluster.status)}
              {sevBadge(cluster.severity)}
            </div>
            <div className="flex items-center gap-3 text-[11px] flex-wrap" style={{ color: 'var(--text-3)' }}>
              <span>{cluster.alert_count} alerts</span>
              <span>{hosts.length} hosts</span>
              {cluster.mitre_technique && <span className="font-mono" style={{ color: '#fbbf24' }}>{cluster.mitre_technique}</span>}
              <span>{cluster.campaign}</span>
              <RiskMeter score={cluster.risk_score} />
            </div>
          </div>
          {toast && <span className="text-xs px-2 py-1 rounded" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>{toast}</span>}
          <button onClick={onClose} style={{ color: 'var(--text-3)' }}><X className="w-4 h-4" /></button>
        </div>

        {/* Inner tabs */}
        <div className="flex gap-1 px-5 pt-3 shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
          {(['members', 'timeline', 'graph', 'intel'] as const).map(t => (
            <button key={t} onClick={() => setInnerTab(t)}
              className={`px-3 py-1.5 text-xs font-medium rounded-t-lg capitalize transition-colors ${innerTab === t ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'}`}>
              {t}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-5">

          {innerTab === 'members' && (
            <div className="space-y-4">
              {/* Alert list */}
              <div>
                <p className="text-[10px] uppercase tracking-wider font-semibold mb-2" style={{ color: 'var(--text-3)' }}>
                  Alerts ({alerts.length})
                </p>
                <div className="space-y-1">
                  {alerts.map(a => (
                    <div key={a.id} className="flex items-center gap-2 text-xs px-3 py-2 rounded-lg"
                      style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                      {sevBadge(a.severity)}
                      <span className="flex-1 truncate font-medium" style={{ color: 'var(--text-1)' }}>{a.rule_name}</span>
                      <span className="shrink-0" style={{ color: 'var(--text-3)' }}>@{a.hostname}</span>
                      {a.mitre_technique && <span className="font-mono text-[10px]" style={{ color: '#fbbf24' }}>{a.mitre_technique}</span>}
                      <span className="shrink-0 text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(a.created_at)}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Hosts + IPs */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-[10px] uppercase tracking-wider font-semibold mb-2" style={{ color: 'var(--text-3)' }}>Hosts ({hosts.length})</p>
                  <div className="space-y-1.5">
                    {hosts.map(h => (
                      <div key={h.agent_id} className="flex items-center gap-2">
                        <Cpu className="w-3 h-3 shrink-0" style={{ color: 'var(--accent)' }} />
                        <span className="text-xs flex-1 truncate" style={{ color: 'var(--text-2)' }}>{h.hostname}</span>
                        <MiniBar value={h.count} max={maxHosts} color="var(--accent)" />
                        <span className="text-[11px] tabular-nums" style={{ color: 'var(--text-3)' }}>{h.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider font-semibold mb-2" style={{ color: 'var(--text-3)' }}>IPs ({ips.length})</p>
                  <div className="space-y-1.5">
                    {ips.map(ip => (
                      <div key={ip.ip} className="flex items-center gap-2">
                        <Globe className="w-3 h-3 shrink-0" style={{ color: '#60a5fa' }} />
                        <span className="text-xs flex-1 font-mono truncate" style={{ color: 'var(--text-2)' }}>{ip.ip}</span>
                        <MiniBar value={ip.count} max={maxIPs} color="#60a5fa" />
                        <span className="text-[11px] tabular-nums" style={{ color: 'var(--text-3)' }}>{ip.count}</span>
                      </div>
                    ))}
                    {ips.length === 0 && <p className="text-xs" style={{ color: 'var(--text-3)' }}>No IP data</p>}
                  </div>
                </div>
              </div>

              {/* MITRE coverage */}
              {mitre.length > 0 && (
                <div>
                  <p className="text-[10px] uppercase tracking-wider font-semibold mb-2" style={{ color: 'var(--text-3)' }}>MITRE Techniques</p>
                  <div className="flex flex-wrap gap-2">
                    {mitre.map(m => (
                      <div key={m.technique} className="px-3 py-1.5 rounded-lg text-xs"
                        style={{ background: 'color-mix(in srgb, #fbbf24 12%, var(--glass-bg))', border: '1px solid rgba(251,191,36,0.3)' }}>
                        <span className="font-mono font-bold" style={{ color: '#fbbf24' }}>{m.technique}</span>
                        {m.tactic && <span className="ml-1.5" style={{ color: 'var(--text-3)' }}>{m.tactic}</span>}
                        <span className="ml-2 text-[10px]" style={{ color: 'var(--text-3)' }}>×{m.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {innerTab === 'timeline' && (
            <div className="space-y-0">
              {timeline.length === 0 ? (
                <p className="text-xs py-8 text-center animate-pulse" style={{ color: 'var(--text-3)' }}>Loading timeline…</p>
              ) : timeline.map((e, i) => (
                <div key={e.id} className="flex items-stretch">
                  <div className="flex flex-col items-center w-8 shrink-0">
                    <div className="w-2 h-2 rounded-full mt-3 shrink-0"
                      style={{ background: SEV_COLOR[e.severity] ?? 'var(--text-3)' }} />
                    {i < timeline.length - 1 && (
                      <div className="w-px flex-1 mt-1" style={{ background: 'var(--border)' }} />
                    )}
                  </div>
                  <div className="flex-1 ml-3 pb-4 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[11px] font-mono shrink-0" style={{ color: 'var(--text-3)' }}>
                        {new Date(e.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </span>
                      {sevBadge(e.severity)}
                      {e.mitre_technique && <span className="font-mono text-[10px]" style={{ color: '#fbbf24' }}>{e.mitre_technique}</span>}
                    </div>
                    <p className="text-xs font-medium mt-0.5" style={{ color: 'var(--text-1)' }}>{e.rule_name}</p>
                    <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
                      @{e.hostname}{e.source_ip ? ` · ${e.source_ip}` : ''}{e.mitre_tactic ? ` · ${e.mitre_tactic}` : ''}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}

          {innerTab === 'graph' && (
            <div>
              {!graphData ? (
                <p className="text-xs py-8 text-center animate-pulse" style={{ color: 'var(--text-3)' }}>Loading graph…</p>
              ) : (
                <ClusterGraphSVG nodes={graphData.nodes} edges={graphData.edges} />
              )}
            </div>
          )}

          {innerTab === 'intel' && (
            <div className="space-y-4">
              <div className="g-card p-4">
                <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Threat Intelligence Context</p>
                <div className="space-y-2 text-xs">
                  {[
                    { label: 'Campaign Type',    val: cluster.campaign },
                    { label: 'Risk Score',       val: `${cluster.risk_score}/100` },
                    { label: 'Confidence',       val: `${cluster.confidence}%` },
                    { label: 'MITRE Technique',  val: cluster.mitre_technique || '—' },
                    { label: 'Affected Hosts',   val: hosts.length.toString() },
                    { label: 'Source IPs',       val: ips.length.toString() },
                    { label: 'First Seen',       val: new Date(cluster.first_seen).toLocaleString() },
                    { label: 'Last Seen',        val: new Date(cluster.last_seen).toLocaleString() },
                    { label: 'Duration',         val: (() => {
                      const ms = new Date(cluster.last_seen).getTime() - new Date(cluster.first_seen).getTime();
                      const h = Math.floor(ms / 3600000);
                      const m = Math.floor((ms % 3600000) / 60000);
                      return h > 0 ? `${h}h ${m}m` : `${m}m`;
                    })() },
                  ].map(row => (
                    <div key={row.label} className="flex justify-between items-center py-1" style={{ borderBottom: '1px solid var(--border)' }}>
                      <span style={{ color: 'var(--text-3)' }}>{row.label}</span>
                      <span className="font-medium" style={{ color: 'var(--text-1)' }}>{row.val}</span>
                    </div>
                  ))}
                </div>
              </div>

              {cluster.incident_id > 0 && (
                <Link href={`/incidents?id=${cluster.incident_id}`}
                  className="flex items-center justify-between g-card px-4 py-3 hover:opacity-80 transition-opacity">
                  <div>
                    <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Auto-Promoted Incident</p>
                    <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>INC #{cluster.incident_id}</p>
                  </div>
                  <ExternalLink className="w-4 h-4" style={{ color: 'var(--accent)' }} />
                </Link>
              )}
            </div>
          )}
        </div>

        {/* Actions footer */}
        <div className="px-5 py-4 shrink-0 flex flex-wrap items-center gap-2" style={{ borderTop: '1px solid var(--border)' }}>
          <button onClick={() => doAction('promote')} disabled={!!actionLoading || cluster.status === 'promoted'}
            className="g-btn g-btn-primary text-xs">
            <Zap className="w-3.5 h-3.5" />
            {actionLoading === 'promote' ? 'Promoting…' : 'Promote to Incident'}
          </button>
          <button onClick={() => doAction('close')} disabled={!!actionLoading || cluster.status === 'closed'}
            className="g-btn g-btn-ghost text-xs">
            <CheckCircle2 className="w-3.5 h-3.5" />
            {actionLoading === 'close' ? 'Closing…' : 'Close Cluster'}
          </button>
          {cluster.status === 'closed' && (
            <button onClick={() => doAction('reopen')} disabled={!!actionLoading} className="g-btn g-btn-ghost text-xs">
              <RefreshCw className="w-3.5 h-3.5" /> Reopen
            </button>
          )}
          {cluster.status === 'open' && (
            <button onClick={() => clustersAPI.suppress(clusterId).then(() => { notify('Suppressed'); })}
              className="g-btn g-btn-ghost text-xs" style={{ color: 'var(--text-3)' }}>
              <VolumeX className="w-3.5 h-3.5" /> Suppress
            </button>
          )}
          <button onClick={() => setShowMerge(!showMerge)} className="g-btn g-btn-ghost text-xs">
            <GitMerge className="w-3.5 h-3.5" /> Merge Into…
          </button>
          {showMerge && (
            <div className="flex items-center gap-2">
              <input value={mergeInput} onChange={e => setMergeInput(e.target.value)}
                placeholder="Cluster ID" className="g-input text-xs w-24" />
              <button onClick={doMerge} className="g-btn g-btn-primary text-xs">Merge</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Cluster Graph SVG ──────────────────────────────────────────────────────────

function ClusterGraphSVG({ nodes, edges }: { nodes: GraphNode[]; edges: GraphEdge[] }) {
  const NODE_COLORS: Record<string, string> = {
    host: 'var(--accent)', rule: '#a78bfa', ip: '#60a5fa', incident: 'var(--red)',
  };

  const layout = useMemo(() => {
    const hosts     = nodes.filter(n => n.type === 'host');
    const rules     = nodes.filter(n => n.type === 'rule');
    const ips       = nodes.filter(n => n.type === 'ip');
    const incidents = nodes.filter(n => n.type === 'incident');
    const W = 700, H = 360;
    const pos: Record<string, { x: number; y: number }> = {};
    const spacing = (items: GraphNode[], x: number) => {
      items.forEach((n, i) => {
        pos[n.id] = { x, y: 40 + (i * Math.min(70, (H - 80) / Math.max(items.length, 1))) };
      });
    };
    spacing(ips, 70);
    spacing(hosts, 220);
    spacing(rules, 450);
    spacing(incidents, W - 70);
    return pos;
  }, [nodes]);

  if (!nodes.length) return (
    <div className="py-12 text-center text-xs" style={{ color: 'var(--text-3)' }}>
      No graph data for this cluster yet.
    </div>
  );

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-4 text-[10px] flex-wrap">
        {Object.entries({ ip: '#60a5fa', host: 'var(--accent)', rule: '#a78bfa', incident: 'var(--red)' }).map(([t, c]) => (
          <span key={t} className="flex items-center gap-1 capitalize">
            <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: c }} />{t}
          </span>
        ))}
      </div>
      <svg width="100%" viewBox="0 0 700 360" className="rounded-lg"
        style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
        {edges.map((e, i) => {
          const s = layout[e.source];
          const t = layout[e.target];
          if (!s || !t) return null;
          return <line key={i} x1={s.x} y1={s.y} x2={t.x} y2={t.y} stroke="var(--border)" strokeWidth={1.5} strokeOpacity={0.6} />;
        })}
        {nodes.map(n => {
          const p = layout[n.id];
          if (!p) return null;
          const color = NODE_COLORS[n.type] ?? 'var(--text-3)';
          const r = Math.min(20, 8 + n.count);
          return (
            <g key={n.id} transform={`translate(${p.x},${p.y})`}>
              <circle r={r} fill={`color-mix(in srgb, ${color} 20%, var(--glass-bg))`} stroke={color} strokeWidth={1.5} />
              <text y={r + 11} textAnchor="middle" fontSize={9} fill="var(--text-2)" className="select-none">
                {n.label.slice(0, 14)}{n.label.length > 14 ? '…' : ''}
              </text>
            </g>
          );
        })}
        {/* Column labels */}
        {[{ x: 70, l: 'Source IPs' }, { x: 220, l: 'Hosts' }, { x: 450, l: 'Rules' }, { x: 630, l: 'Incidents' }].map(s => (
          <text key={s.l} x={s.x} y={16} textAnchor="middle" fontSize={9} fill="var(--text-3)" className="select-none">{s.l}</text>
        ))}
      </svg>
    </div>
  );
}

// ── Attack Chain View ──────────────────────────────────────────────────────────

function AttackChainView({ campaigns }: { campaigns: Campaign[] }) {
  const [selected, setSelected] = useState<string>('Ransomware');
  const chain = CAMPAIGN_CHAIN[selected] || DEFAULT_CHAIN;

  const CAMPAIGN_TYPES = ['Ransomware', 'Phishing', 'Lateral Movement', 'Credential Theft'];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        {CAMPAIGN_TYPES.map(t => (
          <button key={t} onClick={() => setSelected(t)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${selected === t ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'}`}>
            {t}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Chain */}
        <div className="g-card p-4">
          <p className="text-xs font-semibold mb-4" style={{ color: 'var(--text-1)' }}>{selected} Attack Chain</p>
          <div className="flex flex-col gap-0">
            {chain.map((step, i) => (
              <div key={i} className="flex items-stretch">
                <div className="flex flex-col items-center w-8 shrink-0">
                  <div className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold shrink-0"
                    style={{
                      background: i === chain.length - 1 ? 'rgba(248,81,73,0.2)' : 'var(--glass-bg-2)',
                      border: `1px solid ${i === chain.length - 1 ? 'var(--red)' : 'var(--border)'}`,
                      color: i === chain.length - 1 ? 'var(--red)' : 'var(--text-3)',
                    }}>
                    {i + 1}
                  </div>
                  {i < chain.length - 1 && <div className="w-px flex-1 my-1" style={{ background: 'var(--border)' }} />}
                </div>
                <div className="flex-1 ml-3 pb-4">
                  <p className="text-xs font-medium" style={{ color: i === chain.length - 1 ? 'var(--red)' : 'var(--text-1)' }}>
                    {step.label}
                  </p>
                  <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{step.detail}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Active campaigns matching this type */}
        <div className="g-card p-4">
          <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>
            Active {selected} Clusters
          </p>
          {campaigns.filter(cp => cp.campaign === selected).length === 0 ? (
            <div className="py-8 text-center">
              <CheckCircle2 className="mx-auto w-8 h-8 mb-2" style={{ color: 'var(--green)', opacity: 0.5 }} />
              <p className="text-xs" style={{ color: 'var(--text-3)' }}>No active {selected} campaigns detected</p>
            </div>
          ) : (
            campaigns.filter(cp => cp.campaign === selected).map(cp => (
              <div key={cp.technique} className="g-card p-3 mb-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold" style={{ color: '#fbbf24' }}>{cp.technique}</span>
                  {sevBadge(cp.risk_level)}
                </div>
                <div className="flex items-center gap-3 text-[11px] mt-1" style={{ color: 'var(--text-3)' }}>
                  <span>{cp.cluster_count} clusters</span>
                  <span>{cp.total_alerts} alerts</span>
                  <span>last {timeAgo(cp.latest)}</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Workflow diagram */}
      <div className="g-card p-4">
        <p className="text-xs font-semibold mb-4" style={{ color: 'var(--text-1)' }}>XCloak Alert → Incident Flow</p>
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-1 flex-wrap text-xs">
          {[
            { label: 'Detection Engine',  sub: 'Sigma · YARA · IOC',        color: 'var(--accent)' },
            { label: 'Alert',             sub: 'Single event',               color: '#fbbf24' },
            { label: 'Correlation',       sub: 'Temporal · Count',           color: '#a78bfa' },
            { label: 'Alert Cluster',     sub: 'Grouped events',             color: '#fb923c', highlight: true },
            { label: 'Incident',          sub: 'Validated threat',           color: 'var(--red)' },
            { label: 'Case',              sub: 'Analyst assignment',         color: '#60a5fa' },
            { label: 'SOAR',              sub: 'Automated response',         color: '#34d399' },
          ].map((s, i, arr) => (
            <div key={s.label} className="flex items-center gap-1 flex-wrap">
              <div className={`px-3 py-2 rounded-lg`}
                style={{
                  background: `color-mix(in srgb, ${s.color} 15%, var(--glass-bg))`,
                  border: `2px solid ${(s as { highlight?: boolean }).highlight ? s.color : 'var(--border)'}`,
                }}>
                <p className="font-semibold" style={{ color: s.color }}>{s.label}</p>
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{s.sub}</p>
              </div>
              {i < arr.length - 1 && <ArrowRight className="w-3 h-3 shrink-0" style={{ color: 'var(--text-3)' }} />}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── AI Analysis Panel ──────────────────────────────────────────────────────────

function AIPanel({ clusters }: { clusters: ClusterRow[] }) {
  const [action, setAction] = useState('summarize');
  const [clusterId, setClusterId] = useState(0);
  const [context, setContext] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AIResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const AI_ACTIONS = [
    { id: 'summarize',       label: 'AI Summary',        icon: Brain,      desc: 'Executive summary of what happened and impact' },
    { id: 'root_cause',      label: 'Root Cause',        icon: Search,     desc: 'Initial access, entry point, lateral movement, objective' },
    { id: 'chain',           label: 'ATT&CK Chain',      icon: Layers,     desc: 'Map alerts to MITRE kill chain stages' },
    { id: 'campaign_detect', label: 'Campaign Detect',   icon: Target,     desc: 'Identify threat actor and campaign type' },
  ];

  const run = async () => {
    setLoading(true); setError(null); setResult(null);
    try {
      const res = await clustersAPI.aiAnalysis(action, clusterId || undefined, context);
      const raw = typeof res.data === 'string' ? res.data : JSON.stringify(res.data, null, 2);
      let parsed: Record<string, unknown> | null = null;
      try { parsed = typeof res.data === 'object' ? res.data as Record<string, unknown> : JSON.parse(raw); } catch {}
      setResult({ raw, parsed });
    } catch {
      setError('AI analysis failed. Select a cluster with alerts and try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {AI_ACTIONS.map(a => (
          <button key={a.id} onClick={() => setAction(a.id)}
            className={`p-3 rounded-xl text-left transition-colors ${action === a.id ? 'g-btn g-btn-primary' : 'g-card'}`}>
            <a.icon className="w-4 h-4 mb-2" style={{ color: action === a.id ? 'white' : 'var(--accent)' }} />
            <p className="text-xs font-medium">{a.label}</p>
            <p className="text-[10px] mt-0.5" style={{ color: action === a.id ? 'rgba(255,255,255,0.7)' : 'var(--text-3)' }}>{a.desc}</p>
          </button>
        ))}
      </div>

      <div className="g-card p-4 space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Cluster (optional — uses most recent if blank)</label>
            <select value={clusterId} onChange={e => setClusterId(Number(e.target.value))} className="g-select w-full text-xs">
              <option value={0}>Most recent cluster</option>
              {clusters.slice(0, 20).map(c => (
                <option key={c.id} value={c.id}>#{c.id} — {c.rule_name.slice(0, 40)} ({c.alert_count} alerts)</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Additional Context</label>
            <textarea value={context} onChange={e => setContext(e.target.value)}
              placeholder="Environment notes, active incidents, threat intel context…"
              className="g-input w-full text-xs resize-none" rows={2} />
          </div>
        </div>
        <button onClick={run} disabled={loading} className="g-btn g-btn-primary text-xs">
          <Brain className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          {loading ? 'Analyzing…' : 'Run AI Analysis'}
        </button>
      </div>

      {error && <div className="g-card p-3 text-xs" style={{ color: 'var(--red)' }}>{error}</div>}

      {result && (
        <div className="g-card p-4 space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>AI Result — {AI_ACTIONS.find(a => a.id === action)?.label}</p>
            <CopyBtn text={result.raw} />
          </div>
          {result.parsed ? (
            <div className="space-y-3">
              {Object.entries(result.parsed).map(([key, val]) => (
                <div key={key}>
                  <p className="text-[10px] uppercase tracking-wider mb-1 font-semibold" style={{ color: 'var(--text-3)' }}>{key.replace(/_/g, ' ')}</p>
                  {Array.isArray(val) ? (
                    <ul className="space-y-1">
                      {(val as unknown[]).map((item, i) => (
                        <li key={i} className="flex items-start gap-1.5 text-xs">
                          <span className="w-1.5 h-1.5 rounded-full mt-1 shrink-0" style={{ background: 'var(--accent)' }} />
                          <span style={{ color: 'var(--text-2)' }}>{typeof item === 'object' ? JSON.stringify(item) : String(item)}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-xs" style={{ color: 'var(--text-2)' }}>{String(val)}</p>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <pre className="text-[11px] p-3 rounded-lg overflow-x-auto leading-relaxed whitespace-pre-wrap"
              style={{ background: 'var(--bg-0)', color: 'var(--text-1)', border: '1px solid var(--border)' }}>
              {result.raw}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

// ── Cluster Table ──────────────────────────────────────────────────────────────

function ClusterTable({ clusters, onSelect, onSuppress, onRunClustering, running }: {
  clusters: ClusterRow[];
  onSelect: (id: number) => void;
  onSuppress: (id: number) => void;
  onRunClustering: () => void;
  running: boolean;
}) {
  const [search, setSearch] = useState('');
  const [statusF, setStatusF] = useState('open');
  const [sortBy, setSortBy] = useState<'risk' | 'alerts' | 'time'>('risk');

  const filtered = useMemo(() => {
    let list = clusters;
    if (statusF && statusF !== 'all') list = list.filter(c => c.status === statusF);
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(c =>
        c.rule_name.toLowerCase().includes(q) ||
        c.mitre_technique.toLowerCase().includes(q) ||
        c.campaign.toLowerCase().includes(q) ||
        c.cluster_key.toLowerCase().includes(q)
      );
    }
    switch (sortBy) {
      case 'risk':   return [...list].sort((a, b) => b.risk_score - a.risk_score);
      case 'alerts': return [...list].sort((a, b) => b.alert_count - a.alert_count);
      case 'time':   return [...list].sort((a, b) => new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime());
      default: return list;
    }
  }, [clusters, statusF, search, sortBy]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-40">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--text-3)' }} />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search clusters…"
            className="g-input pl-8 py-1.5 text-xs w-full" />
        </div>
        <div className="flex gap-1">
          {(['all', 'open', 'promoted', 'suppressed', 'closed'] as const).map(s => (
            <button key={s} onClick={() => setStatusF(s)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium capitalize transition-colors ${statusF === s ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'}`}>
              {s}
            </button>
          ))}
        </div>
        <select value={sortBy} onChange={e => setSortBy(e.target.value as typeof sortBy)} className="g-select text-xs py-1">
          <option value="risk">Sort: Risk</option>
          <option value="alerts">Sort: Alerts</option>
          <option value="time">Sort: Recent</option>
        </select>
        <span className="text-xs ml-auto" style={{ color: 'var(--text-3)' }}>{filtered.length} clusters</span>
        <button onClick={onRunClustering} disabled={running} className="g-btn g-btn-ghost text-xs">
          <RefreshCw className={`w-3.5 h-3.5 ${running ? 'animate-spin' : ''}`} />
          {running ? 'Clustering…' : 'Run Now'}
        </button>
      </div>

      {filtered.length === 0 ? (
        <div className="g-card py-16 text-center">
          <GitMerge className="mx-auto h-10 w-10 mb-3 opacity-20" style={{ color: 'var(--text-3)' }} />
          <p className="text-sm" style={{ color: 'var(--text-3)' }}>
            {statusF === 'open' ? 'No open clusters — no active attack patterns detected.' : 'No clusters in this view.'}
          </p>
        </div>
      ) : (
        <div className="g-card overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
                {['Cluster','Campaign','MITRE','Alerts','Hosts','Risk','Confidence','Status','Last Seen',''].map(h => (
                  <th key={h} className="px-3 py-2.5 text-left font-semibold" style={{ color: 'var(--text-3)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map(c => (
                <tr key={c.id} className="cursor-pointer hover:opacity-80 transition-opacity"
                  onClick={() => onSelect(c.id)}
                  style={{ borderBottom: '1px solid var(--border)', opacity: c.status === 'suppressed' ? 0.5 : 1 }}>
                  <td className="px-3 py-3 max-w-[200px]">
                    <p className="font-medium truncate" style={{ color: 'var(--text-1)' }}>{c.rule_name || c.cluster_key}</p>
                    <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{sevBadge(c.severity)}</p>
                  </td>
                  <td className="px-3 py-3 whitespace-nowrap">
                    <span className="text-[10px] px-1.5 py-0.5 rounded"
                      style={{ background: 'var(--glass-bg-2)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>
                      {c.campaign}
                    </span>
                  </td>
                  <td className="px-3 py-3">
                    {c.mitre_technique
                      ? <span className="font-mono text-[10px]" style={{ color: '#fbbf24' }}>{c.mitre_technique}</span>
                      : <span style={{ color: 'var(--text-3)' }}>—</span>}
                  </td>
                  <td className="px-3 py-3 font-bold tabular-nums" style={{ color: '#fbbf24' }}>{c.alert_count}</td>
                  <td className="px-3 py-3 tabular-nums" style={{ color: 'var(--text-2)' }}>{c.host_count}</td>
                  <td className="px-3 py-3"><RiskMeter score={c.risk_score} /></td>
                  <td className="px-3 py-3 tabular-nums" style={{ color: 'var(--text-3)' }}>{c.confidence}%</td>
                  <td className="px-3 py-3">{statusBadge(c.status)}</td>
                  <td className="px-3 py-3 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>{timeAgo(c.last_seen)}</td>
                  <td className="px-3 py-3">
                    {c.status === 'open' && (
                      <button onClick={e => { e.stopPropagation(); onSuppress(c.id); }}
                        className="p-1 rounded hover:opacity-70" title="Suppress" style={{ color: 'var(--text-3)' }}>
                        <VolumeX className="w-3.5 h-3.5" />
                      </button>
                    )}
                    {c.incident_id > 0 && (
                      <Link href={`/incidents?id=${c.incident_id}`} onClick={e => e.stopPropagation()}
                        className="flex items-center gap-0.5 text-[10px]" style={{ color: 'var(--accent)' }}>
                        INC#{c.incident_id} <ExternalLink className="w-2.5 h-2.5" />
                      </Link>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function ClustersPage() {
  const [tab,          setTab]          = useState<ViewTab>('overview');
  const [hours,        setHours]        = useState(24);
  const loaded                          = useRef<Partial<Record<ViewTab, boolean>>>({});

  const [overview,    setOverview]    = useState<Overview | null>(null);
  const [clusters,    setClusters]    = useState<ClusterRow[]>([]);
  const [analytics,   setAnalytics]   = useState<Analytics | null>(null);
  const [campaigns,   setCampaigns]   = useState<Campaign[]>([]);
  const [loadingTab,  setLoadingTab]  = useState(false);
  const [running,     setRunning]     = useState(false);
  const [selectedId,  setSelectedId]  = useState<number | null>(null);
  const [toast,       setToast]       = useState<string | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const loadTab = useCallback(async (t: ViewTab, force = false) => {
    if (loaded.current[t] && !force) return;
    loaded.current[t] = true;
    setLoadingTab(true);
    try {
      switch (t) {
        case 'overview': {
          const [ov, cl] = await Promise.all([
            clustersAPI.getOverview(hours),
            clustersAPI.getList('', 200),
          ]);
          if (ov.data) setOverview(ov.data as Overview);
          if (cl.data) setClusters(cl.data as ClusterRow[]);
          break;
        }
        case 'clusters': {
          const r = await clustersAPI.getList('', 200);
          if (r.data) setClusters(r.data as ClusterRow[]);
          break;
        }
        case 'campaign':
        case 'chain': {
          const [cl, cp] = await Promise.all([
            clusters.length ? Promise.resolve({ data: clusters }) : clustersAPI.getList('', 200),
            clustersAPI.getCampaigns(),
          ]);
          if (cl.data) setClusters(cl.data as ClusterRow[]);
          const cpData = cp.data as { campaigns?: Campaign[] } | null;
          if (cpData?.campaigns) setCampaigns(cpData.campaigns);
          break;
        }
        case 'graph': {
          if (!clusters.length) {
            const r = await clustersAPI.getList('', 200);
            if (r.data) setClusters(r.data as ClusterRow[]);
          }
          break;
        }
        case 'analytics': {
          const r = await clustersAPI.getAnalytics();
          if (r.data) setAnalytics(r.data as Analytics);
          break;
        }
        case 'ai': {
          if (!clusters.length) {
            const r = await clustersAPI.getList('', 200);
            if (r.data) setClusters(r.data as ClusterRow[]);
          }
          break;
        }
      }
    } finally {
      setLoadingTab(false);
    }
  }, [hours, clusters.length]);

  useEffect(() => {
    loaded.current = {};
    loadTab(tab);
  }, [tab, hours]);

  const runClustering = async () => {
    setRunning(true);
    await clustersAPI.analyze();
    setTimeout(async () => {
      loaded.current = {};
      await loadTab(tab, true);
      setRunning(false);
      notify('Clustering complete');
    }, 3000);
  };

  const suppress = async (id: number) => {
    await clustersAPI.suppress(id);
    setClusters(prev => prev.map(c => c.id === id ? { ...c, status: 'suppressed' } : c));
    notify('Cluster suppressed');
  };

  // Overview derived values
  const openClusters    = useMemo(() => clusters.filter(c => c.status === 'open'), [clusters]);
  const highRiskClusters = useMemo(() => clusters.filter(c => c.risk_score >= 70), [clusters]);
  const maxAnalyticCount = useMemo(() => Math.max(...(analytics?.top_clusters.map(tc => tc.alert_count) ?? []), 1), [analytics]);
  const maxCampAlerts   = useMemo(() => Math.max(...campaigns.map(cp => cp.total_alerts), 1), [campaigns]);

  return (
    <RootLayout
      title="Alert Clusters"
      subtitle="AI-powered grouping · Campaign detection · Multi-stage attack chain analysis"
      actions={
        <div className="flex items-center gap-2">
          <select value={hours} onChange={e => { setHours(Number(e.target.value)); loaded.current = {}; }}
            className="g-select text-xs py-1">
            {[6, 12, 24, 48, 168].map(h => <option key={h} value={h}>{h < 24 ? `${h}h` : h === 168 ? '7d' : '24h'}</option>)}
          </select>
          <button onClick={() => { loaded.current = {}; loadTab(tab, true); }} className="g-btn g-btn-ghost text-xs">
            <RefreshCw className={`w-3.5 h-3.5 ${loadingTab ? 'animate-spin' : ''}`} />
          </button>
          <button onClick={runClustering} disabled={running} className="g-btn g-btn-primary text-xs">
            <Play className={`w-3.5 h-3.5 ${running ? 'animate-spin' : ''}`} />
            {running ? 'Clustering…' : 'Run Clustering'}
          </button>
        </div>
      }>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 g-card px-4 py-2.5 text-sm shadow-lg" style={{ color: 'var(--text-1)' }}>
          {toast}
        </div>
      )}

      {selectedId && (
        <ClusterDetailPanel clusterId={selectedId} onClose={() => setSelectedId(null)} />
      )}

      {/* Tab bar */}
      <div className="flex gap-0.5 mb-4 overflow-x-auto pb-1">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors ${tab === t.id ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'}`}>
            <t.icon className="w-3.5 h-3.5" />
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Overview ── */}
      {tab === 'overview' && (
        <div className="space-y-4">
          {overview ? (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <KPICard label="Active Clusters"   value={overview.active_clusters}    color="var(--accent)"   icon={GitMerge} />
                <KPICard label="New (24h)"         value={overview.new_clusters}        color="#fbbf24"         icon={Plus} />
                <KPICard label="High Risk"         value={overview.high_risk}           color="var(--red)"      icon={AlertTriangle} />
                <KPICard label="Campaigns"         value={overview.campaigns}           color="#a78bfa"         icon={Target} />
                <KPICard label="Related Incidents" value={overview.related_incidents}   color="#fb923c"         icon={Zap} />
                <KPICard label="Avg Cluster Size"  value={overview.avg_cluster_size}    color="var(--text-2)"   icon={Layers} />
                <KPICard label="Cluster Confidence" value={`${overview.cluster_confidence}%`} color="var(--green)" icon={Shield} />
                <KPICard label="Total"             value={overview.total}               color="var(--text-3)"   icon={Activity} />
              </div>

              {/* Trend */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>7-day Cluster Trend</p>
                  <TrendSparkline data={overview.trend} />
                </div>
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Status Breakdown</p>
                  <div className="space-y-2">
                    {Object.entries(overview.status_breakdown).map(([s, n]) => {
                      const max = Math.max(...Object.values(overview.status_breakdown), 1);
                      return (
                        <div key={s} className="flex items-center gap-3">
                          <span className="text-xs capitalize w-20 shrink-0">{statusBadge(s)}</span>
                          <MiniBar value={n} max={max} color={STATUS_COLOR[s] ?? 'var(--text-3)'} />
                          <span className="text-[11px] font-bold tabular-nums w-6 text-right shrink-0"
                            style={{ color: STATUS_COLOR[s] ?? 'var(--text-3)' }}>{n}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>

              {/* Top high-risk open clusters */}
              {highRiskClusters.length > 0 && (
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--red)' }}>
                    High-Risk Open Clusters (risk ≥ 70)
                  </p>
                  <div className="space-y-2">
                    {highRiskClusters.slice(0, 5).map(c => (
                      <div key={c.id} className="flex items-center gap-3 cursor-pointer hover:opacity-80 transition-opacity"
                        onClick={() => { setTab('clusters'); setSelectedId(c.id); }}>
                        <RiskMeter score={c.risk_score} />
                        <span className="flex-1 text-xs truncate font-medium" style={{ color: 'var(--text-1)' }}>{c.rule_name}</span>
                        {sevBadge(c.severity)}
                        <span className="text-[11px] tabular-nums" style={{ color: '#fbbf24' }}>{c.alert_count} alerts</span>
                        <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(c.last_seen)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Info box */}
              <div className="g-card p-4 text-xs" style={{ color: 'var(--text-3)' }}>
                <span className="font-semibold" style={{ color: 'var(--text-2)' }}>Auto-clustering: </span>
                Alerts sharing the same MITRE technique or rule on the same agent within a 24h window are grouped. Clusters with ≥3 alerts auto-promote to incidents. Runs every 15 min. Click "Run Clustering" to force immediately.
              </div>
            </>
          ) : (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          )}
        </div>
      )}

      {/* ── Clusters table ── */}
      {tab === 'clusters' && (
        <ClusterTable
          clusters={clusters}
          onSelect={setSelectedId}
          onSuppress={suppress}
          onRunClustering={runClustering}
          running={running} />
      )}

      {/* ── Campaigns ── */}
      {tab === 'campaign' && (
        <div className="space-y-4">
          {campaigns.length > 0 ? (
            <>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {campaigns.map(cp => (
                  <div key={cp.technique} className="g-card p-4 cursor-pointer hover:opacity-80 transition-opacity"
                    onClick={() => setTab('chain')}>
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{cp.campaign}</p>
                        <p className="font-mono text-[11px]" style={{ color: '#fbbf24' }}>{cp.technique}</p>
                      </div>
                      {sevBadge(cp.risk_level)}
                    </div>
                    <div className="space-y-1.5 mt-3">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] w-16 shrink-0" style={{ color: 'var(--text-3)' }}>Clusters</span>
                        <MiniBar value={cp.cluster_count} max={campaigns[0]?.cluster_count || 1} color="var(--accent)" />
                        <span className="text-[11px] tabular-nums font-bold" style={{ color: 'var(--accent)' }}>{cp.cluster_count}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] w-16 shrink-0" style={{ color: 'var(--text-3)' }}>Alerts</span>
                        <MiniBar value={cp.total_alerts} max={maxCampAlerts} color="#fbbf24" />
                        <span className="text-[11px] tabular-nums font-bold" style={{ color: '#fbbf24' }}>{cp.total_alerts}</span>
                      </div>
                    </div>
                    <div className="flex items-center justify-between mt-3 text-[10px]" style={{ color: 'var(--text-3)' }}>
                      <span>Last: {timeAgo(cp.latest)}</span>
                      {cp.has_open && <span style={{ color: '#fb923c' }}>● Active</span>}
                    </div>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="py-16 text-center text-sm" style={{ color: 'var(--text-3)' }}>
              No campaign data yet. Run clustering to detect campaigns.
            </div>
          )}
        </div>
      )}

      {/* ── Attack Chain ── */}
      {tab === 'chain' && <AttackChainView campaigns={campaigns} />}

      {/* ── Graph ── */}
      {tab === 'graph' && (
        <div className="space-y-4">
          <p className="text-xs" style={{ color: 'var(--text-3)' }}>
            Select a cluster from the Clusters tab to view its relationship graph. The graph shows IPs, hosts, detection rules, and incidents as connected nodes.
          </p>
          <div className="g-card p-4">
            <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Open Clusters — Select to View Graph</p>
            <div className="space-y-2">
              {openClusters.slice(0, 10).map(c => (
                <button key={c.id} onClick={() => setSelectedId(c.id)}
                  className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left hover:opacity-80 transition-opacity"
                  style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                  <Network className="w-4 h-4 shrink-0" style={{ color: 'var(--accent)' }} />
                  <span className="flex-1 text-xs truncate font-medium" style={{ color: 'var(--text-1)' }}>{c.rule_name}</span>
                  <span className="text-[11px]" style={{ color: '#fbbf24' }}>{c.alert_count} alerts</span>
                  <RiskMeter score={c.risk_score} />
                </button>
              ))}
              {openClusters.length === 0 && (
                <p className="text-xs py-4 text-center" style={{ color: 'var(--text-3)' }}>No open clusters</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Analytics ── */}
      {tab === 'analytics' && (
        <div className="space-y-4">
          {analytics ? (
            <>
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                {/* Size distribution */}
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Cluster Size Distribution</p>
                  <div className="space-y-2">
                    {analytics.size_distribution.map(s => {
                      const max = Math.max(...analytics.size_distribution.map(x => x.count), 1);
                      return (
                        <div key={s.bucket} className="flex items-center gap-3">
                          <span className="text-xs font-mono w-12 shrink-0" style={{ color: 'var(--text-3)' }}>{s.bucket}</span>
                          <MiniBar value={s.count} max={max} color="var(--accent)" />
                          <span className="text-[11px] tabular-nums w-6 text-right shrink-0 font-bold" style={{ color: 'var(--accent)' }}>{s.count}</span>
                        </div>
                      );
                    })}
                  </div>
                  <div className="mt-4 pt-3" style={{ borderTop: '1px solid var(--border)' }}>
                    <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>MTTR: <span className="font-semibold" style={{ color: 'var(--text-2)' }}>{analytics.mttr_hours}h avg</span></p>
                  </div>
                </div>

                {/* Campaign breakdown */}
                <div className="g-card p-4 lg:col-span-2">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Campaign Breakdown (open clusters)</p>
                  <div className="space-y-2">
                    {analytics.campaigns.map(cp => {
                      const max = Math.max(...analytics.campaigns.map(x => x.alerts), 1);
                      return (
                        <div key={cp.technique} className="flex items-center gap-3">
                          <span className="font-mono text-[10px] w-14 shrink-0" style={{ color: '#fbbf24' }}>{cp.technique || '—'}</span>
                          <span className="text-[10px] w-24 shrink-0 truncate" style={{ color: 'var(--text-3)' }}>{cp.campaign}</span>
                          <MiniBar value={cp.alerts} max={max} color={cp.campaign === 'Ransomware' ? 'var(--red)' : 'var(--accent)'} />
                          <span className="text-[11px] tabular-nums w-8 text-right shrink-0" style={{ color: 'var(--text-2)' }}>{cp.clusters}</span>
                          <span className="text-[11px] tabular-nums w-10 text-right shrink-0 font-bold" style={{ color: '#fbbf24' }}>{cp.alerts}</span>
                        </div>
                      );
                    })}
                    {analytics.campaigns.length === 0 && (
                      <p className="text-xs" style={{ color: 'var(--text-3)' }}>No open cluster campaigns</p>
                    )}
                  </div>
                </div>
              </div>

              {/* Top clusters */}
              <div className="g-card p-4">
                <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Top Clusters by Alert Count</p>
                <div className="space-y-2">
                  {analytics.top_clusters.map(tc => (
                    <div key={tc.id} className="flex items-center gap-3 cursor-pointer hover:opacity-80 transition-opacity"
                      onClick={() => { setSelectedId(tc.id); }}>
                      <span className="text-[11px] font-mono w-8 shrink-0" style={{ color: 'var(--text-3)' }}>#{tc.id}</span>
                      <span className="flex-1 text-xs truncate" style={{ color: 'var(--text-1)' }}>{tc.rule_name}</span>
                      {statusBadge(tc.status)}
                      {tc.technique && <span className="font-mono text-[10px]" style={{ color: '#fbbf24' }}>{tc.technique}</span>}
                      <MiniBar value={tc.alert_count} max={maxAnalyticCount} color={tc.status === 'open' ? 'var(--red)' : 'var(--accent)'} />
                      <span className="text-[11px] font-bold tabular-nums" style={{ color: '#fbbf24' }}>{tc.alert_count}</span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading analytics…</div>
          )}
        </div>
      )}

      {/* ── AI ── */}
      {tab === 'ai' && <AIPanel clusters={clusters} />}
    </RootLayout>
  );
}
