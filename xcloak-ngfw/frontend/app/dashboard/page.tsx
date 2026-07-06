'use client';

import { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { RootLayout } from '@/components/layout/RootLayout';
import { dashboardAPI, alertsAPI, incidentsAPI, agentsAPI, playbooksAPI } from '@/lib/api';
import api from '@/lib/api';
import { DashboardOverview, Alert, Incident, Agent, PlaybookExecution } from '@/types';
import { sevClass, timeAgo } from '@/lib/utils';
import { useNotifications } from '@/context/NotificationContext';
import {
  Cpu, Bell, AlertTriangle, Activity, Zap, Radio,
  ShieldCheck, ShieldAlert, CircleDot, Clock, Target,
  Trophy, TrendingUp, TrendingDown, Minus, Crosshair,
  BookOpen, Shield, AlertOctagon, CheckCircle2, BarChart3,
  Layers, FileCode, Code2, Wifi,
} from 'lucide-react';
import {
  PieChart, Pie, Cell, AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts';

// ── Constants ────────────────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  critical: '#f85149', high: '#fb923c', medium: '#fbbf24', low: '#38bdf8',
};

const TOOLTIP_STYLE = {
  contentStyle: {
    background: 'var(--glass-modal)', border: '1px solid var(--border)',
    borderRadius: 8, fontSize: 11, color: 'var(--text-1)',
  },
  labelStyle: { color: 'var(--text-3)', fontSize: 10 },
};

const MITRE_ORDER = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
];

const MITRE_SHORT: Record<string, string> = {
  'Reconnaissance': 'Recon', 'Resource Development': 'Res Dev',
  'Initial Access': 'Init Acc', 'Execution': 'Exec',
  'Persistence': 'Persist', 'Privilege Escalation': 'Priv Esc',
  'Defense Evasion': 'Def Eva', 'Credential Access': 'Cred Acc',
  'Discovery': 'Discov', 'Lateral Movement': 'Lat Mov',
  'Collection': 'Collect', 'Command and Control': 'C2',
  'Exfiltration': 'Exfil', 'Impact': 'Impact',
};

type RangeOption = '1h' | '24h' | '7d' | '30d';

// ── Types ────────────────────────────────────────────────────────────────────

interface TrendDelta { current: number; previous: number; delta: number; delta_pct: number }
interface MTTRStats { avg_seconds: number; avg_formatted: string; total_resolved: number; last_24h_seconds: number }
interface MTTDStats { avg_seconds: number; avg_formatted: string; sample_count: number }
interface AgentCoverage { total: number; online: number; offline: number; pct_online: number }
interface MitreTacticCount { tactic: string; alert_count: number; severity: string }
interface RuleHealth { sigma_enabled: number; sigma_disabled: number; sigma_total: number; yara_enabled: number; yara_total: number }

interface DashboardMetrics {
  alert_trend: Array<{ label: string; critical: number; high: number; medium: number; low: number }>;
  alert_velocity_1h: number;
  threat_score: number;
  mttr: MTTRStats;
  mttd: MTTDStats;
  alert_deltas: TrendDelta;
  incident_deltas: TrendDelta;
  agent_coverage: AgentCoverage;
  mitre_tactics: MitreTacticCount[];
  rule_health: RuleHealth;
  ioc_hits: number;
  anomaly_score: number;
  compliance_score: number;
  top_rules: Array<{ rule_name: string; count: number; severity: string }>;
  top_agents: Array<{ agent_id: number; hostname: string; count: number }>;
  range: string;
}

// ── Sub-components ────────────────────────────────────────────────────────────

function RangePicker({ value, onChange }: { value: RangeOption; onChange: (r: RangeOption) => void }) {
  const opts: { label: string; value: RangeOption }[] = [
    { label: '1H', value: '1h' }, { label: '24H', value: '24h' },
    { label: '7D', value: '7d' }, { label: '30D', value: '30d' },
  ];
  return (
    <div className="flex rounded-lg overflow-hidden" style={{ border: '1px solid var(--border)' }}>
      {opts.map(o => (
        <button key={o.value} onClick={() => onChange(o.value)}
          className="px-3 py-1 text-[11px] font-semibold transition-all"
          style={{
            background: value === o.value ? 'var(--accent)' : 'transparent',
            color: value === o.value ? '#fff' : 'var(--text-3)',
          }}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

function DeltaBadge({ delta, pct }: { delta: number; pct: number }) {
  if (delta === 0) return <span className="text-[10px] flex items-center gap-0.5" style={{ color: 'var(--text-3)' }}><Minus className="h-2.5 w-2.5" /> 0%</span>;
  const up = delta > 0;
  const Icon = up ? TrendingUp : TrendingDown;
  return (
    <span className="text-[10px] flex items-center gap-0.5 font-semibold"
      style={{ color: up ? 'var(--red)' : 'var(--green)' }}>
      <Icon className="h-2.5 w-2.5" />
      {Math.abs(pct)}%
    </span>
  );
}

function StatCard({ label, value, sub, icon: Icon, accent, pulse, delta, deltaPct, link }: {
  label: string; value: string | number; sub?: string;
  icon: any; accent?: string; pulse?: boolean;
  delta?: number; deltaPct?: number; link?: string;
}) {
  const content = (
    <div className="g-card p-5 flex flex-col gap-2 relative overflow-hidden transition-all hover:border-accent">
      {pulse && (
        <span className="absolute top-3 right-3 h-2 w-2 rounded-full animate-pulse"
          style={{ background: accent || 'var(--accent)' }} />
      )}
      <div className="flex items-start justify-between">
        <div className="flex h-9 w-9 items-center justify-center rounded-xl"
          style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
          <Icon className="h-4 w-4" style={{ color: accent || 'var(--accent)' }} />
        </div>
        {delta !== undefined && deltaPct !== undefined && <DeltaBadge delta={delta} pct={deltaPct} />}
      </div>
      <p className="text-2xl font-bold tabular-nums" style={{ color: 'var(--text-1)' }}>{value ?? '—'}</p>
      <p className="text-xs font-medium" style={{ color: 'var(--text-2)' }}>{label}</p>
      {sub && <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{sub}</p>}
    </div>
  );
  return link ? <Link href={link}>{content}</Link> : content;
}

// SVG semicircle gauge — threat score
function ThreatGauge({ score }: { score: number }) {
  const pct   = Math.min(score, 100) / 100;
  const r     = 54;
  const circ  = Math.PI * r;
  const dash  = circ * pct;
  const color = score >= 70 ? '#f85149' : score >= 40 ? '#fb923c' : score >= 20 ? '#fbbf24' : '#34d399';
  const label = score >= 70 ? 'Critical' : score >= 40 ? 'High' : score >= 20 ? 'Medium' : 'Healthy';
  return (
    <div className="flex flex-col items-center">
      <svg width="140" height="80" viewBox="0 0 140 80">
        <path d="M 16 74 A 54 54 0 0 1 124 74" fill="none" stroke="var(--border)" strokeWidth="10" strokeLinecap="round" />
        <path d="M 16 74 A 54 54 0 0 1 124 74" fill="none" stroke={color}
          strokeWidth="10" strokeLinecap="round"
          strokeDasharray={`${dash} ${circ}`} />
        <text x="70" y="68" textAnchor="middle" fontSize="22" fontWeight="700" fill="var(--text-1)">{score}</text>
      </svg>
      <p className="text-xs font-semibold -mt-1" style={{ color }}>{label} Risk</p>
    </div>
  );
}

// SVG donut ring — agent coverage (like CrowdStrike sensor coverage)
function CoverageRing({ pct, online, total }: { pct: number; online: number; total: number }) {
  const r = 38, circ = 2 * Math.PI * r;
  const fill = circ * (pct / 100);
  const color = pct >= 90 ? '#34d399' : pct >= 70 ? '#fbbf24' : '#f85149';
  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="100" height="100" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r={r} fill="none" stroke="var(--border)" strokeWidth="9" />
        <circle cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="9"
          strokeDasharray={`${fill} ${circ}`} strokeLinecap="round"
          transform="rotate(-90 50 50)" />
        <text x="50" y="52" textAnchor="middle" fontSize="14" fontWeight="700" fill="var(--text-1)">{pct}%</text>
        <text x="50" y="64" textAnchor="middle" fontSize="7" fill="var(--text-3)">covered</text>
      </svg>
      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
        {online} / {total} agents online
      </p>
    </div>
  );
}

// MITRE ATT&CK heatmap — 14 tactics in kill-chain order
function MitreHeatmap({ tactics }: { tactics: MitreTacticCount[] }) {
  const tacticMap = Object.fromEntries(tactics.map(t => [t.tactic, t]));
  const max = Math.max(...tactics.map(t => t.alert_count), 1);

  return (
    <div className="g-card p-4">
      <div className="flex items-center gap-2 mb-4">
        <Crosshair className="h-4 w-4" style={{ color: 'var(--accent)' }} />
        <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>MITRE ATT&CK Coverage</p>
        <span className="ml-auto text-[10px]" style={{ color: 'var(--text-3)' }}>
          alert counts by tactic
        </span>
      </div>
      <div className="grid gap-1.5" style={{ gridTemplateColumns: 'repeat(7, 1fr)' }}>
        {MITRE_ORDER.map(tactic => {
          const t = tacticMap[tactic];
          const cnt = t?.alert_count ?? 0;
          const intensity = cnt === 0 ? 0 : Math.max(0.12, cnt / max);
          const bg = cnt === 0
            ? 'var(--bg-0)'
            : `rgba(248, 81, 73, ${intensity})`;
          const border = cnt > 0
            ? (cnt / max > 0.6 ? '#f85149' : cnt / max > 0.3 ? '#fb923c' : '#fbbf24')
            : 'var(--border)';
          return (
            <div key={tactic} title={`${tactic}: ${cnt} alerts`}
              className="flex flex-col items-center justify-center rounded-lg p-1.5 cursor-default transition-all"
              style={{ background: bg, border: `1px solid ${cnt > 0 ? border : 'var(--border)'}`, minHeight: 56 }}>
              <p className="text-[9px] font-bold text-center leading-tight"
                style={{ color: cnt > 0 ? '#fff' : 'var(--text-3)' }}>
                {MITRE_SHORT[tactic] ?? tactic}
              </p>
              {cnt > 0 && (
                <p className="text-[11px] font-bold mt-0.5 tabular-nums"
                  style={{ color: cnt > 0 ? '#fff' : 'var(--text-3)' }}>
                  {cnt}
                </p>
              )}
            </div>
          );
        })}
      </div>
      <div className="flex items-center gap-2 mt-3 justify-end">
        <span className="text-[9px]" style={{ color: 'var(--text-3)' }}>0</span>
        <div className="h-2 w-24 rounded-full" style={{
          background: 'linear-gradient(to right, var(--bg-0), rgba(248,81,73,0.2), rgba(248,81,73,0.6), #f85149)',
          border: '1px solid var(--border)',
        }} />
        <span className="text-[9px]" style={{ color: 'var(--text-3)' }}>high</span>
      </div>
    </div>
  );
}

// Anomaly indicator — today's volume vs 7d average
function AnomalyBanner({ score }: { score: number }) {
  if (score === 0) return null;
  const pct = Math.round((score - 1) * 100);
  const elevated = score > 1.3;
  const suppressed = score < 0.5;
  if (!elevated && !suppressed) return null;

  return (
    <div className="rounded-xl px-4 py-3 flex items-center gap-3"
      style={{
        background: elevated ? 'rgba(248,81,73,0.08)' : 'rgba(56,189,248,0.08)',
        border: `1px solid ${elevated ? 'rgba(248,81,73,0.3)' : 'rgba(56,189,248,0.3)'}`,
      }}>
      <AlertOctagon className="h-4 w-4 shrink-0" style={{ color: elevated ? 'var(--red)' : 'var(--blue)' }} />
      <p className="text-xs" style={{ color: 'var(--text-1)' }}>
        {elevated
          ? `Alert volume is ${Math.abs(pct)}% above the 7-day average — possible attack surge or noisy rule.`
          : `Alert volume is ${Math.abs(pct)}% below the 7-day average — verify sensors are reporting.`}
      </p>
    </div>
  );
}

// Rule health strip — like Sentinel analytics health
function RuleHealthStrip({ rh }: { rh: RuleHealth }) {
  const sigmaRatio = rh.sigma_total > 0 ? Math.round((rh.sigma_enabled / rh.sigma_total) * 100) : 0;
  const yaraRatio  = rh.yara_total  > 0 ? Math.round((rh.yara_enabled  / rh.yara_total)  * 100) : 0;

  return (
    <div className="g-card p-4">
      <div className="flex items-center gap-2 mb-3">
        <Shield className="h-4 w-4" style={{ color: 'var(--accent)' }} />
        <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Detection Rule Health</p>
        <Link href="/sigma-rules" className="ml-auto text-[10px]" style={{ color: 'var(--accent)' }}>manage →</Link>
      </div>
      <div className="space-y-3">
        {[
          { label: 'Sigma Rules', enabled: rh.sigma_enabled, total: rh.sigma_total, ratio: sigmaRatio, icon: FileCode },
          { label: 'YARA Rules',  enabled: rh.yara_enabled,  total: rh.yara_total,  ratio: yaraRatio,  icon: Code2 },
        ].map(({ label, enabled, total, ratio, icon: Icon }) => (
          <div key={label}>
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-1.5">
                <Icon className="h-3 w-3" style={{ color: 'var(--text-3)' }} />
                <span className="text-[11px]" style={{ color: 'var(--text-2)' }}>{label}</span>
              </div>
              <span className="text-[11px] font-semibold tabular-nums" style={{ color: ratio >= 80 ? 'var(--green)' : ratio >= 50 ? 'var(--yellow)' : 'var(--red)' }}>
                {enabled}/{total} active
              </span>
            </div>
            <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--bg-0)' }}>
              <div className="h-full rounded-full transition-all"
                style={{ width: `${ratio}%`, background: ratio >= 80 ? 'var(--green)' : ratio >= 50 ? 'var(--yellow)' : 'var(--red)' }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// Compact compliance posture strip
function ComplianceStrip({ score }: { score: number }) {
  const color = score >= 80 ? 'var(--green)' : score >= 60 ? 'var(--yellow)' : 'var(--red)';
  return (
    <div className="g-card p-4 flex items-center gap-4">
      <div className="flex h-10 w-10 items-center justify-center rounded-xl shrink-0"
        style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
        <CheckCircle2 className="h-5 w-5" style={{ color: 'var(--accent)' }} />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium mb-1" style={{ color: 'var(--text-2)' }}>Compliance Posture</p>
        <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--bg-0)' }}>
          <div className="h-full rounded-full transition-all" style={{ width: `${score}%`, background: color }} />
        </div>
      </div>
      <div className="shrink-0 text-right">
        <p className="text-xl font-bold tabular-nums" style={{ color }}>{Math.round(score)}%</p>
        <Link href="/compliance" className="text-[10px]" style={{ color: 'var(--accent)' }}>reports →</Link>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const { liveAlerts } = useNotifications();
  const [range, setRange]           = useState<RangeOption>('24h');
  const [overview, setOverview]     = useState<DashboardOverview | null>(null);
  const [metrics, setMetrics]       = useState<DashboardMetrics | null>(null);
  const [alerts, setAlerts]         = useState<Alert[]>([]);
  const [incidents, setIncidents]   = useState<Incident[]>([]);
  const [agents, setAgents]         = useState<Agent[]>([]);
  const [executions, setExecutions] = useState<PlaybookExecution[]>([]);
  const [loading, setLoading]       = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    const [ov, al, inc, ag, ex, mx] = await Promise.allSettled([
      dashboardAPI.getOverview(),
      alertsAPI.getAll(),
      incidentsAPI.getAll(),
      agentsAPI.getAll(),
      playbooksAPI.getExecutions(),
      api.get('/dashboard/metrics', { params: { range } }),
    ]);
    if (ov.status  === 'fulfilled') setOverview(ov.value.data);
    if (al.status  === 'fulfilled') setAlerts((al.value.data || []).slice(0, 20));
    if (inc.status === 'fulfilled') setIncidents(inc.value.data || []);
    if (ag.status  === 'fulfilled') setAgents(ag.value.data || []);
    if (ex.status  === 'fulfilled') setExecutions((ex.value.data || []).slice(0, 12));
    if (mx.status  === 'fulfilled') setMetrics(mx.value.data);
    setLoading(false);
    setRefreshing(false);
  }, [range]);

  useEffect(() => {
    load();
    const t = setInterval(() => load(), 30_000);
    return () => clearInterval(t);
  }, [load]);

  const agentName = (id: number) => agents.find(a => a.id === id)?.hostname || `#${id}`;

  const criticalAlerts = alerts.filter(a => a.severity === 'critical').length;
  const openIncidents  = incidents.filter(i => i.status === 'open' || i.status === 'investigating').length;
  const soarFired      = executions.filter(e => e.status === 'success').length;

  const sevData = ['critical','high','medium','low'].map(s => ({
    name: s, value: alerts.filter(a => a.severity === s).length,
  })).filter(d => d.value > 0);

  const trendData = metrics?.alert_trend?.length
    ? metrics.alert_trend
    : Array.from({ length: 12 }, (_, i) => ({
        label: `${i * 2}:00`, critical: 0, high: 0, medium: 0, low: 0,
      }));

  return (
    <RootLayout title="Dashboard" subtitle="Security Operations Overview"
      onRefresh={() => load(true)} refreshing={refreshing}>
      <div className="space-y-5">

        {/* ── Time range picker ──────────────────────────────────── */}
        <div className="flex items-center justify-between">
          <p className="text-xs" style={{ color: 'var(--text-3)' }}>
            All widgets reflect the selected time window
          </p>
          <RangePicker value={range} onChange={r => setRange(r)} />
        </div>

        {/* ── Anomaly banner ────────────────────────────────────── */}
        {metrics && <AnomalyBanner score={metrics.anomaly_score} />}

        {/* ── Row 1: KPI cards ─────────────────────────────────── */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <StatCard
            label="Critical Alerts" value={criticalAlerts}
            sub={`${alerts.length} total in window`}
            icon={Bell}
            accent={criticalAlerts > 0 ? 'var(--red)' : undefined}
            pulse={criticalAlerts > 0}
            delta={metrics?.alert_deltas?.delta}
            deltaPct={metrics?.alert_deltas?.delta_pct}
            link="/alerts"
          />
          <StatCard
            label="Open Incidents" value={openIncidents}
            sub={`${metrics?.incident_deltas?.previous ?? 0} resolved last 7d`}
            icon={AlertTriangle}
            accent={openIncidents > 0 ? 'var(--orange)' : undefined}
            link="/incidents"
          />
          <StatCard
            label="SOAR Executed" value={soarFired}
            sub="auto-responses in window"
            icon={Zap}
            accent={soarFired > 0 ? 'var(--green)' : undefined}
            link="/playbooks"
          />
          <StatCard
            label="Alert Velocity" value={metrics?.alert_velocity_1h ?? 0}
            sub="alerts in last hour"
            icon={Activity}
            pulse={(metrics?.alert_velocity_1h ?? 0) > 20}
          />
        </div>

        {/* ── Row 2: Threat gauge + Coverage + MTTR/MTTD + IOC ─── */}
        {metrics && (
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {/* Platform Threat Score */}
            <div className="g-card p-4 flex flex-col items-center justify-center">
              <p className="text-[10px] font-semibold uppercase tracking-wider mb-1"
                style={{ color: 'var(--text-3)' }}>Threat Score</p>
              <ThreatGauge score={metrics.threat_score} />
            </div>

            {/* Agent Coverage (CrowdStrike-style sensor coverage) */}
            <div className="g-card p-4 flex flex-col items-center justify-center">
              <p className="text-[10px] font-semibold uppercase tracking-wider mb-1"
                style={{ color: 'var(--text-3)' }}>Sensor Coverage</p>
              <CoverageRing
                pct={metrics.agent_coverage.pct_online}
                online={metrics.agent_coverage.online}
                total={metrics.agent_coverage.total}
              />
            </div>

            {/* MTTR + MTTD (Sentinel / Splunk style KPI strip) */}
            <div className="g-card p-4 space-y-3">
              <div>
                <div className="flex items-center gap-1.5 mb-0.5">
                  <Clock className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
                  <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-3)' }}>MTTR</p>
                </div>
                <p className="text-xl font-bold tabular-nums" style={{ color: 'var(--text-1)' }}>
                  {metrics.mttr.avg_formatted}
                </p>
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                  {metrics.mttr.total_resolved} incidents resolved
                </p>
              </div>
              <div style={{ borderTop: '1px solid var(--border)', paddingTop: 10 }}>
                <div className="flex items-center gap-1.5 mb-0.5">
                  <Crosshair className="h-3.5 w-3.5" style={{ color: 'var(--orange)' }} />
                  <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-3)' }}>MTTD</p>
                </div>
                <p className="text-xl font-bold tabular-nums" style={{ color: 'var(--text-1)' }}>
                  {metrics.mttd.avg_formatted}
                </p>
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                  {metrics.mttd.sample_count} samples
                </p>
              </div>
            </div>

            {/* IOC Hits */}
            <div className="g-card p-4">
              <div className="flex items-center gap-1.5 mb-2">
                <Layers className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
                <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-3)' }}>IOC Hits</p>
              </div>
              <p className="text-2xl font-bold tabular-nums" style={{ color: metrics.ioc_hits > 0 ? 'var(--red)' : 'var(--text-1)' }}>
                {metrics.ioc_hits}
              </p>
              <p className="text-[11px] mt-1" style={{ color: 'var(--text-3)' }}>indicator matches in window</p>
              <Link href="/threat-intel" className="text-[10px] mt-2 block" style={{ color: 'var(--accent)' }}>view intel →</Link>
            </div>
          </div>
        )}

        {/* ── Row 3: MITRE ATT&CK heatmap ────────────────────────── */}
        {metrics && metrics.mitre_tactics && (
          <MitreHeatmap tactics={metrics.mitre_tactics} />
        )}

        {/* ── Row 4: Alert trend + Severity pie ──────────────────── */}
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="g-card p-4">
            <div className="flex items-center justify-between mb-3">
              <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
                Alert Trend
              </p>
              <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>stacked by severity</span>
            </div>
            <ResponsiveContainer width="100%" height={190}>
              <AreaChart data={trendData}>
                <defs>
                  {['critical','high','medium','low'].map(s => (
                    <linearGradient key={s} id={`g-${s}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor={SEV_COLORS[s]} stopOpacity={0.3} />
                      <stop offset="95%" stopColor={SEV_COLORS[s]} stopOpacity={0} />
                    </linearGradient>
                  ))}
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                <XAxis dataKey="label" tick={{ fontSize: 9, fill: 'var(--text-3)' }} tickLine={false} axisLine={false} interval={3} />
                <YAxis allowDecimals={false} tick={{ fontSize: 9, fill: 'var(--text-3)' }} tickLine={false} axisLine={false} />
                <Tooltip {...TOOLTIP_STYLE} />
                {['critical','high','medium','low'].map(s => (
                  <Area key={s} type="monotone" dataKey={s} stackId="1"
                    stroke={SEV_COLORS[s]} fill={`url(#g-${s})`} strokeWidth={1.5} />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="g-card p-4">
            <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>
              Severity Breakdown
            </p>
            {sevData.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-40 gap-2">
                <ShieldCheck className="h-8 w-8" style={{ color: 'var(--text-3)' }} />
                <p className="text-xs" style={{ color: 'var(--text-3)' }}>No alerts in window</p>
              </div>
            ) : (
              <>
                <ResponsiveContainer width="100%" height={150}>
                  <PieChart>
                    <Pie data={sevData} cx="50%" cy="50%" innerRadius={40} outerRadius={65}
                      dataKey="value" paddingAngle={3}>
                      {sevData.map(entry => (
                        <Cell key={entry.name} fill={SEV_COLORS[entry.name] || '#64748b'} />
                      ))}
                    </Pie>
                    <Tooltip {...TOOLTIP_STYLE} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="flex flex-wrap gap-3 mt-1">
                  {sevData.map(d => (
                    <div key={d.name} className="flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-full" style={{ background: SEV_COLORS[d.name] }} />
                      <span className="text-[11px] capitalize" style={{ color: 'var(--text-2)' }}>
                        {d.name} ({d.value})
                      </span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>

        {/* ── Row 5: Rule health + Compliance ──────────────────────── */}
        {metrics && (
          <div className="grid gap-4 sm:grid-cols-2">
            <RuleHealthStrip rh={metrics.rule_health} />
            {metrics.compliance_score > 0 && (
              <ComplianceStrip score={metrics.compliance_score} />
            )}
          </div>
        )}

        {/* ── Row 6: Top rules (bar chart) + Top noisy agents ──────── */}
        {metrics && (metrics.top_rules?.length > 0 || metrics.top_agents?.length > 0) && (
          <div className="grid gap-4 sm:grid-cols-2">
            {metrics.top_rules?.length > 0 && (
              <div className="g-card p-4">
                <div className="flex items-center gap-2 mb-3">
                  <Target className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                  <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Top Firing Rules</p>
                </div>
                <ResponsiveContainer width="100%" height={180}>
                  <BarChart data={metrics.top_rules.slice(0, 6)} layout="vertical" barSize={8}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
                    <XAxis type="number" tick={{ fontSize: 9, fill: 'var(--text-3)' }} tickLine={false} axisLine={false} />
                    <YAxis type="category" dataKey="rule_name" width={120}
                      tick={{ fontSize: 9, fill: 'var(--text-3)' }} tickLine={false} axisLine={false}
                      tickFormatter={(v: string) => v.length > 18 ? v.slice(0, 18) + '…' : v} />
                    <Tooltip {...TOOLTIP_STYLE} />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                      {metrics.top_rules.slice(0, 6).map((r, i) => (
                        <Cell key={i} fill={SEV_COLORS[r.severity] || 'var(--accent)'} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}

            {metrics.top_agents?.length > 0 && (
              <div className="g-card">
                <div className="flex items-center gap-2 px-4 pt-4 pb-3"
                  style={{ borderBottom: '1px solid var(--border)' }}>
                  <Trophy className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                  <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Noisiest Agents</p>
                </div>
                <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                  {metrics.top_agents.map((a, i) => (
                    <Link key={i} href="/agents"
                      className="flex items-center gap-3 px-4 py-2.5 transition-colors"
                      style={{ display: 'flex' }}
                      onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--glass-hover)'}
                      onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = ''}>
                      <span className="text-[10px] font-bold w-4 tabular-nums" style={{ color: 'var(--text-3)' }}>{i + 1}</span>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{a.hostname}</p>
                        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>id:{a.agent_id}</p>
                      </div>
                      <span className="text-xs font-bold tabular-nums" style={{ color: 'var(--orange)' }}>
                        {a.count} alerts
                      </span>
                    </Link>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Row 7: Live alert ticker ───────────────────────────── */}
        <div className="g-card">
          <div className="flex items-center justify-between px-4 pt-4 pb-3"
            style={{ borderBottom: '1px solid var(--border)' }}>
            <div className="flex items-center gap-2">
              <Radio className="h-4 w-4" style={{ color: 'var(--accent)' }} />
              <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Live Alert Feed</p>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full animate-pulse" style={{ background: 'var(--green)' }} />
              <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                {liveAlerts.length > 0 ? `${liveAlerts.length} received` : 'Listening…'}
              </span>
              <Link href="/live-logs" className="ml-2 text-[10px]" style={{ color: 'var(--accent)' }}>view all →</Link>
            </div>
          </div>
          <div className="overflow-hidden" style={{ maxHeight: 200 }}>
            {liveAlerts.length === 0 ? (
              <div className="py-8 text-center">
                <Radio className="mx-auto h-7 w-7 mb-2" style={{ color: 'var(--text-3)' }} />
                <p className="text-xs" style={{ color: 'var(--text-3)' }}>Waiting for WebSocket alerts…</p>
              </div>
            ) : (
              <div className="divide-y overflow-y-auto" style={{ borderColor: 'var(--border)', maxHeight: 200 }}>
                {liveAlerts.map((a, i) => (
                  <div key={`${a.id}-${i}`} className="flex items-center gap-3 px-4 py-2">
                    <span className="h-2 w-2 rounded-full shrink-0" style={{
                      background: a.severity === 'critical' ? 'var(--red)'
                        : a.severity === 'high' ? 'var(--orange)'
                        : a.severity === 'medium' ? 'var(--yellow)' : 'var(--blue)',
                      boxShadow: a.severity === 'critical' ? '0 0 6px var(--red)' : undefined,
                    }} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs truncate" style={{ color: 'var(--text-1)' }}>{a.rule_name}</p>
                      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{agentName(a.agent_id)}</p>
                    </div>
                    <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase ${sevClass(a.severity)}`}>
                      {a.severity}
                    </span>
                    <span className="text-[10px] shrink-0" style={{ color: 'var(--text-3)' }}>
                      {timeAgo(a.timestamp)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* ── Row 8: SOAR activity + Recent alerts ──────────────── */}
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="g-card">
            <div className="flex items-center justify-between px-4 pt-4 pb-3"
              style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="flex items-center gap-2">
                <Zap className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>SOAR Activity</p>
              </div>
              <Link href="/playbooks" className="text-[10px]" style={{ color: 'var(--accent)' }}>manage →</Link>
            </div>
            <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {executions.length === 0 ? (
                <div className="py-8 text-center">
                  <Zap className="mx-auto h-7 w-7 mb-2" style={{ color: 'var(--text-3)' }} />
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>No SOAR executions yet.</p>
                </div>
              ) : executions.map(ex => (
                <div key={ex.id} className="flex items-center gap-3 px-4 py-2.5">
                  <span className="h-1.5 w-1.5 rounded-full shrink-0"
                    style={{ background: ex.status === 'success' ? 'var(--green)' : 'var(--red)' }} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs truncate" style={{ color: 'var(--text-1)' }}>
                      <span className="mono" style={{ color: 'var(--accent)' }}>{ex.action_type}</span>
                      <span style={{ color: 'var(--text-3)' }}> on </span>{agentName(ex.agent_id)}
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

          <div className="g-card">
            <div className="flex items-center justify-between px-4 pt-4 pb-3"
              style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="flex items-center gap-2">
                <Bell className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Recent Alerts</p>
              </div>
              <Link href="/alerts" className="text-[10px]" style={{ color: 'var(--accent)' }}>view all →</Link>
            </div>
            <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {alerts.length === 0 ? (
                <div className="py-8 text-center">
                  <ShieldCheck className="mx-auto h-7 w-7 mb-2" style={{ color: 'var(--text-3)' }} />
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>No alerts in window. All clear.</p>
                </div>
              ) : alerts.slice(0, 8).map(a => (
                <Link key={a.id} href="/alerts"
                  className="flex items-center gap-3 px-4 py-2.5 transition-colors"
                  style={{ display: 'flex' }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--glass-hover)'}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = ''}>
                  <span className="h-1.5 w-1.5 rounded-full shrink-0"
                    style={{ background: SEV_COLORS[a.severity] || 'var(--text-3)' }} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs truncate" style={{ color: 'var(--text-1)' }}>{a.rule_name}</p>
                    <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>{agentName(a.agent_id)}</p>
                  </div>
                  <div className="shrink-0 text-right">
                    <span className={sevClass(a.severity)}>{a.severity}</span>
                    <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{timeAgo(a.created_at)}</p>
                  </div>
                </Link>
              ))}
            </div>
          </div>
        </div>

        {/* ── Row 9: Open incidents ──────────────────────────────── */}
        {openIncidents > 0 && (
          <div className="g-card">
            <div className="flex items-center justify-between px-4 pt-4 pb-3"
              style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4" style={{ color: 'var(--orange)' }} />
                <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>
                  Open Incidents ({openIncidents})
                </p>
              </div>
              <Link href="/incidents" className="text-[10px]" style={{ color: 'var(--accent)' }}>manage →</Link>
            </div>
            <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {incidents.filter(i => i.status === 'open' || i.status === 'investigating').slice(0, 5).map(inc => (
                <Link key={inc.id} href="/incidents"
                  className="flex items-center gap-3 px-4 py-3 transition-colors"
                  style={{ display: 'flex' }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--glass-hover)'}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = ''}>
                  <CircleDot className="h-3.5 w-3.5 shrink-0"
                    style={{ color: SEV_COLORS[inc.severity] || 'var(--text-3)' }} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{inc.title}</p>
                    <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>
                      {agentName(inc.agent_id)} · {inc.description?.slice(0, 60)}…
                    </p>
                  </div>
                  <div className="shrink-0 text-right">
                    <span className={sevClass(inc.severity)}>{inc.severity}</span>
                    <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{timeAgo(inc.created_at)}</p>
                  </div>
                </Link>
              ))}
            </div>
          </div>
        )}

      </div>
    </RootLayout>
  );
}
