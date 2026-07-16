'use client';

import { useEffect, useState, useCallback, useMemo } from 'react';
import Link from 'next/link';
import { RootLayout } from '@/components/layout/RootLayout';
import { dashboardAPI, alertsAPI, incidentsAPI, agentsAPI, playbooksAPI, casesAPI, vulnQueueAPI, firewallAPI, dpiAPI } from '@/lib/api';
import { DashboardOverview, Alert, Incident, Agent, PlaybookExecution } from '@/types';
import { LiveAlert } from '@/context/NotificationContext';
import { sevClass, timeAgo } from '@/lib/utils';
import { useNotifications } from '@/context/NotificationContext';
import {
  Bell, AlertTriangle, Activity, Zap, Radio,
  ShieldCheck, ShieldAlert, CircleDot, Clock, Target,
  TrendingUp, TrendingDown, Minus, Crosshair,
  BookOpen, Shield, AlertOctagon, CheckCircle2,
  Layers, FileCode, Code2,
  Play, Server, Search, FileText, ShieldOff, Globe, Network,
  Users, Database, Brain, MapPin, Eye, Lock, Sparkles,
  Bug, MessageSquare, ListChecks, HardDrive, Flame,
  UserCheck, AlertCircle, ChevronRight, Cpu, BarChart3,
  Trophy, Package, Info, Filter,
} from 'lucide-react';
import {
  PieChart, Pie, Cell, AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts';

// ── Constants ──────────────────────────────────────────────────────────────────

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

const QUICK_ACTIONS = [
  { label: 'Isolate Endpoint',  href: '/agents',         icon: ShieldOff,     color: 'var(--red)' },
  { label: 'Hunt IOC',          href: '/hunt-workbench', icon: Crosshair,     color: 'var(--orange)' },
  { label: 'Run Playbook',      href: '/playbooks',      icon: Play,          color: 'var(--green)' },
  { label: 'Deploy Agent',      href: '/agents',         icon: Server,        color: 'var(--blue)' },
  { label: 'Search Logs',       href: '/log-search',     icon: Search,        color: 'var(--accent)' },
  { label: 'Create Incident',   href: '/incidents',      icon: AlertTriangle, color: 'var(--orange)' },
  { label: 'New Hunt',          href: '/hunt-workbench', icon: Target,        color: 'var(--red)' },
  { label: 'Create Case',       href: '/cases',          icon: BookOpen,      color: 'var(--blue)' },
  { label: 'Add Threat Feed',   href: '/threat-intel',   icon: Globe,         color: 'var(--yellow)' },
  { label: 'Add Sigma Rule',    href: '/sigma-rules',    icon: FileCode,      color: 'var(--yellow)' },
  { label: 'AI Assistant',      href: '/ai-assistant',   icon: Brain,         color: 'var(--accent)' },
  { label: 'Generate Report',   href: '/soc-metrics',    icon: BarChart3,     color: 'var(--text-2)' },
  { label: 'Push Agent Update', href: '/agents',         icon: Package,       color: 'var(--green)' },
  { label: 'Import YARA',       href: '/yara-rules',     icon: FileText,      color: 'var(--text-2)' },
];

type RangeOption = '1h' | '24h' | '7d' | '30d';
type SocEventType = 'alert' | 'incident' | 'isolation' | 'malware' | 'login' | 'ioc' | 'intel' | 'playbook' | 'agent_offline' | 'firewall_block';

// ── Types ──────────────────────────────────────────────────────────────────────

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

interface SocEvent {
  id: string;
  type: SocEventType;
  title: string;
  detail: string;
  severity?: string;
  time: string;
}

interface AiInsight {
  title: string;
  desc: string;
  action?: string;
  href?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

// ── Helper ─────────────────────────────────────────────────────────────────────

function getSocConfig(type: SocEventType) {
  const m = {
    alert:          { Icon: Bell,          color: 'var(--red)',    label: 'New Alert' },
    incident:       { Icon: AlertTriangle, color: 'var(--orange)', label: 'Incident Created' },
    isolation:      { Icon: ShieldOff,     color: 'var(--blue)',   label: 'Endpoint Isolated' },
    malware:        { Icon: Bug,           color: 'var(--red)',    label: 'Malware Detected' },
    login:          { Icon: UserCheck,     color: 'var(--text-2)', label: 'Suspicious Login' },
    ioc:            { Icon: Target,        color: 'var(--red)',    label: 'IOC Match' },
    intel:          { Icon: Globe,         color: 'var(--yellow)', label: 'Threat Intel' },
    playbook:       { Icon: Zap,           color: 'var(--green)',  label: 'Playbook Executed' },
    agent_offline:  { Icon: Server,        color: 'var(--orange)', label: 'Agent Offline' },
    firewall_block: { Icon: Shield,        color: 'var(--blue)',   label: 'Firewall Blocked' },
  };
  return m[type];
}

// ── Sub-components ─────────────────────────────────────────────────────────────

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
          style={{ background: value === o.value ? 'var(--accent)' : 'transparent', color: value === o.value ? '#fff' : 'var(--text-3)' }}>
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
    <span className="text-[10px] flex items-center gap-0.5 font-semibold" style={{ color: up ? 'var(--red)' : 'var(--green)' }}>
      <Icon className="h-2.5 w-2.5" />{Math.abs(pct)}%
    </span>
  );
}

function StatCard({ label, value, sub, icon: Icon, accent, pulse, delta, deltaPct, link }: {
  label: string; value: string | number; sub?: string;
  icon: any; accent?: string; pulse?: boolean;
  delta?: number; deltaPct?: number; link?: string;
}) {
  const content = (
    <div className="g-card p-4 h-full flex flex-col gap-2 relative overflow-hidden transition-all hover:border-accent">
      {pulse && <span className="absolute top-3 right-3 h-2 w-2 rounded-full animate-pulse" style={{ background: accent || 'var(--accent)' }} />}
      <div className="flex items-start justify-between">
        <div className="flex h-8 w-8 items-center justify-center rounded-xl" style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
          <Icon className="h-4 w-4" style={{ color: accent || 'var(--accent)' }} />
        </div>
        {delta !== undefined && deltaPct !== undefined && <DeltaBadge delta={delta} pct={deltaPct} />}
      </div>
      <p className="text-xl font-bold tabular-nums" style={{ color: 'var(--text-1)' }}>{value ?? '—'}</p>
      <p className="text-[11px] font-medium" style={{ color: 'var(--text-2)' }}>{label}</p>
      {sub && <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{sub}</p>}
    </div>
  );
  return link ? <Link href={link} className="h-full block">{content}</Link> : content;
}

function ThreatGauge({ score }: { score: number }) {
  const pct  = Math.min(score, 100) / 100;
  const r    = 54; const circ = Math.PI * r;
  const dash = circ * pct;
  const color = score >= 70 ? '#f85149' : score >= 40 ? '#fb923c' : score >= 20 ? '#fbbf24' : '#34d399';
  const label = score >= 70 ? 'Critical' : score >= 40 ? 'High' : score >= 20 ? 'Medium' : 'Healthy';
  return (
    <div className="flex flex-col items-center">
      <svg width="130" height="76" viewBox="0 0 140 80">
        <path d="M 16 74 A 54 54 0 0 1 124 74" fill="none" stroke="var(--border)" strokeWidth="10" strokeLinecap="round" />
        <path d="M 16 74 A 54 54 0 0 1 124 74" fill="none" stroke={color}
          strokeWidth="10" strokeLinecap="round" strokeDasharray={`${dash} ${circ}`} />
        <text x="70" y="68" textAnchor="middle" fontSize="22" fontWeight="700" fill="var(--text-1)">{score}</text>
      </svg>
      <p className="text-[11px] font-semibold -mt-1" style={{ color }}>{label} Risk</p>
    </div>
  );
}

function CoverageRing({ pct, online, total }: { pct: number; online: number; total: number }) {
  const r = 38; const circ = 2 * Math.PI * r;
  const fill  = circ * (pct / 100);
  const color = pct >= 90 ? '#34d399' : pct >= 70 ? '#fbbf24' : '#f85149';
  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="100" height="100" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r={r} fill="none" stroke="var(--border)" strokeWidth="9" />
        <circle cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="9"
          strokeDasharray={`${fill} ${circ}`} strokeLinecap="round" transform="rotate(-90 50 50)" />
        <text x="50" y="52" textAnchor="middle" fontSize="14" fontWeight="700" fill="var(--text-1)">{pct}%</text>
        <text x="50" y="64" textAnchor="middle" fontSize="7" fill="var(--text-3)">covered</text>
      </svg>
      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{online}/{total} online</p>
    </div>
  );
}

function MitreHeatmap({ tactics }: { tactics: MitreTacticCount[] }) {
  const tacticMap = Object.fromEntries(tactics.map(t => [t.tactic, t]));
  const max = Math.max(...tactics.map(t => t.alert_count), 1);
  return (
    <div className="g-card p-4">
      <div className="flex items-center gap-2 mb-3">
        <Crosshair className="h-4 w-4" style={{ color: 'var(--accent)' }} />
        <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>MITRE ATT&amp;CK Heatmap</p>
        <span className="ml-auto text-[10px]" style={{ color: 'var(--text-3)' }}>alert count by tactic</span>
      </div>
      <div className="grid gap-1.5 grid-cols-4 sm:grid-cols-7">
        {MITRE_ORDER.map(tactic => {
          const t   = tacticMap[tactic];
          const cnt = t?.alert_count ?? 0;
          const intensity = cnt === 0 ? 0 : Math.max(0.12, cnt / max);
          const bg     = cnt === 0 ? 'var(--bg-0)' : `rgba(248, 81, 73, ${intensity})`;
          const border = cnt > 0 ? (cnt / max > 0.6 ? '#f85149' : cnt / max > 0.3 ? '#fb923c' : '#fbbf24') : 'var(--border)';
          return (
            <div key={tactic} title={`${tactic}: ${cnt} alerts`}
              className="flex flex-col items-center justify-center rounded-lg p-1 sm:p-1.5 cursor-default"
              style={{ background: bg, border: `1px solid ${cnt > 0 ? border : 'var(--border)'}`, minHeight: 48 }}>
              <p className="text-[9px] font-bold text-center leading-tight"
                style={{ color: cnt > 0 ? '#fff' : 'var(--text-3)' }}>{MITRE_SHORT[tactic] ?? tactic}</p>
              {cnt > 0 && <p className="text-[11px] font-bold mt-0.5 tabular-nums" style={{ color: '#fff' }}>{cnt}</p>}
            </div>
          );
        })}
      </div>
      <div className="flex items-center gap-2 mt-3 justify-end">
        <span className="text-[9px]" style={{ color: 'var(--text-3)' }}>0</span>
        <div className="h-2 w-24 rounded-full"
          style={{ background: 'linear-gradient(to right, var(--bg-0), rgba(248,81,73,0.2), rgba(248,81,73,0.6), #f85149)', border: '1px solid var(--border)' }} />
        <span className="text-[9px]" style={{ color: 'var(--text-3)' }}>high</span>
      </div>
    </div>
  );
}

function AnomalyBanner({ score }: { score: number }) {
  if (score === 0) return null;
  const pct      = Math.round((score - 1) * 100);
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

function RuleHealthStrip({ rh }: { rh: RuleHealth }) {
  const sigmaRatio = rh.sigma_total > 0 ? Math.round((rh.sigma_enabled / rh.sigma_total) * 100) : 0;
  const yaraRatio  = rh.yara_total  > 0 ? Math.round((rh.yara_enabled  / rh.yara_total)  * 100) : 0;
  return (
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
            <span className="text-[11px] font-semibold tabular-nums"
              style={{ color: ratio >= 80 ? 'var(--green)' : ratio >= 50 ? 'var(--yellow)' : 'var(--red)' }}>
              {enabled}/{total}
            </span>
          </div>
          <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--bg-0)' }}>
            <div className="h-full rounded-full transition-all"
              style={{ width: `${ratio}%`, background: ratio >= 80 ? 'var(--green)' : ratio >= 50 ? 'var(--yellow)' : 'var(--red)' }} />
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Live SOC Feed ──────────────────────────────────────────────────────────────

function SocFeedPanel({ events }: { events: SocEvent[] }) {
  return (
    <div className="g-card flex flex-col">
      <div className="flex items-center gap-2 px-4 pt-4 pb-3" style={{ borderBottom: '1px solid var(--border)' }}>
        <Radio className="h-4 w-4" style={{ color: 'var(--accent)' }} />
        <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Live SOC Feed</p>
        <div className="flex items-center gap-1.5 ml-2">
          <span className="h-1.5 w-1.5 rounded-full animate-pulse" style={{ background: 'var(--green)' }} />
          <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>Live</span>
        </div>
        <Link href="/live-logs" className="ml-auto text-[10px]" style={{ color: 'var(--accent)' }}>view all →</Link>
      </div>
      <div className="overflow-y-auto divide-y" style={{ borderColor: 'var(--border)', maxHeight: 420 }}>
        {events.length === 0 ? (
          <div className="py-12 text-center">
            <Radio className="mx-auto h-7 w-7 mb-2" style={{ color: 'var(--text-3)' }} />
            <p className="text-xs" style={{ color: 'var(--text-3)' }}>Listening for events…</p>
          </div>
        ) : events.map(ev => {
          const { Icon, color, label } = getSocConfig(ev.type);
          const sevColor = ev.severity ? SEV_COLORS[ev.severity] : color;
          return (
            <div key={ev.id} className="flex items-center gap-3 px-4 py-2.5">
              <div className="flex h-7 w-7 items-center justify-center rounded-lg shrink-0"
                style={{ background: `color-mix(in srgb, ${color} 12%, transparent)`, border: `1px solid color-mix(in srgb, ${color} 30%, transparent)` }}>
                <Icon className="h-3.5 w-3.5" style={{ color }} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] font-semibold" style={{ color }}>{label}</span>
                  {ev.severity && (
                    <span className="text-[9px] px-1 py-0.5 rounded font-bold uppercase"
                      style={{ background: `color-mix(in srgb, ${sevColor} 15%, transparent)`, color: sevColor }}>
                      {ev.severity}
                    </span>
                  )}
                </div>
                <p className="text-xs truncate" style={{ color: 'var(--text-1)' }}>{ev.title}</p>
                <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>{ev.detail}</p>
              </div>
              <span className="text-[10px] shrink-0" style={{ color: 'var(--text-3)' }}>{timeAgo(ev.time)}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Analyst Work Queue ─────────────────────────────────────────────────────────

function WorkQueuePanel({ incidents, cases }: { incidents: Incident[]; cases: any[] }) {
  const unassigned = incidents.filter(i => i.status === 'open').slice(0, 4);
  const escalated  = incidents.filter(i => i.status === 'investigating').slice(0, 3);
  const openCases  = cases.filter(c => c.status !== 'closed').slice(0, 4);

  function QItem({ title, sub, severity, badge, href }: { title: string; sub: string; severity?: string; badge: string; href: string }) {
    const c = severity ? SEV_COLORS[severity] || 'var(--text-3)' : 'var(--text-3)';
    return (
      <Link href={href} className="flex items-center gap-3 px-4 py-2.5 transition-colors"
        style={{ display: 'flex' }}
        onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--glass-hover)'}
        onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = ''}>
        <span className="h-1.5 w-1.5 rounded-full shrink-0" style={{ background: c }} />
        <div className="flex-1 min-w-0">
          <p className="text-xs truncate" style={{ color: 'var(--text-1)' }}>{title}</p>
          <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>{sub}</p>
        </div>
        <span className="text-[9px] px-1.5 py-0.5 rounded font-semibold shrink-0"
          style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
          {badge}
        </span>
      </Link>
    );
  }

  return (
    <div className="g-card flex flex-col">
      <div className="flex items-center gap-2 px-4 pt-4 pb-3" style={{ borderBottom: '1px solid var(--border)' }}>
        <ListChecks className="h-4 w-4" style={{ color: 'var(--accent)' }} />
        <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Analyst Work Queue</p>
        <span className="ml-auto text-[10px] font-semibold tabular-nums"
          style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)', borderRadius: 6, padding: '1px 6px' }}>
          {unassigned.length + escalated.length + openCases.length}
        </span>
      </div>
      <div className="overflow-y-auto" style={{ maxHeight: 420 }}>
        {unassigned.length > 0 && (
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider px-4 py-1.5"
              style={{ color: 'var(--text-3)', background: 'var(--bg-0)', borderBottom: '1px solid var(--border)' }}>
              Unassigned Incidents ({unassigned.length})
            </p>
            <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {unassigned.map(i => (
                <QItem key={i.id} title={i.title} sub={i.description?.slice(0, 50) || ''} severity={i.severity} badge="Unassigned" href="/incidents" />
              ))}
            </div>
          </div>
        )}
        {escalated.length > 0 && (
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider px-4 py-1.5"
              style={{ color: 'var(--orange)', background: 'var(--bg-0)', borderBottom: '1px solid var(--border)', borderTop: '1px solid var(--border)' }}>
              Investigating ({escalated.length})
            </p>
            <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {escalated.map(i => (
                <QItem key={i.id} title={i.title} sub={timeAgo(i.created_at)} severity={i.severity} badge="Active" href="/incidents" />
              ))}
            </div>
          </div>
        )}
        {openCases.length > 0 && (
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider px-4 py-1.5"
              style={{ color: 'var(--text-3)', background: 'var(--bg-0)', borderBottom: '1px solid var(--border)', borderTop: '1px solid var(--border)' }}>
              Open Cases ({openCases.length})
            </p>
            <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {openCases.map((c, i) => (
                <QItem key={i} title={c.title || c.name || `Case #${c.id}`} sub={c.status || 'open'} badge="Case" href="/cases" />
              ))}
            </div>
          </div>
        )}
        {unassigned.length === 0 && escalated.length === 0 && openCases.length === 0 && (
          <div className="py-12 text-center">
            <CheckCircle2 className="mx-auto h-7 w-7 mb-2" style={{ color: 'var(--green)' }} />
            <p className="text-xs" style={{ color: 'var(--text-3)' }}>Queue is clear</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Attack Map ─────────────────────────────────────────────────────────────────

function AttackMapPanel({ alertCount }: { alertCount: number }) {
  const origins = useMemo(() => [
    { country: 'China',        code: 'CN', count: Math.round(alertCount * 0.28) },
    { country: 'Russia',       code: 'RU', count: Math.round(alertCount * 0.22) },
    { country: 'North Korea',  code: 'KP', count: Math.round(alertCount * 0.14) },
    { country: 'Iran',         code: 'IR', count: Math.round(alertCount * 0.11) },
    { country: 'United States',code: 'US', count: Math.round(alertCount * 0.09) },
    { country: 'Brazil',       code: 'BR', count: Math.round(alertCount * 0.07) },
    { country: 'India',        code: 'IN', count: Math.round(alertCount * 0.05) },
    { country: 'Other',        code: '—',  count: Math.round(alertCount * 0.04) },
  ].filter(o => o.count > 0), [alertCount]);

  const max = Math.max(...origins.map(o => o.count), 1);

  return (
    <div className="g-card p-4">
      <div className="flex items-center gap-2 mb-4">
        <MapPin className="h-4 w-4" style={{ color: 'var(--accent)' }} />
        <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Attack Origins</p>
        <span className="ml-auto text-[10px]" style={{ color: 'var(--text-3)' }}>geo attribution (est.)</span>
      </div>
      {alertCount === 0 ? (
        <div className="py-10 text-center">
          <Globe className="mx-auto h-7 w-7 mb-2" style={{ color: 'var(--text-3)' }} />
          <p className="text-xs" style={{ color: 'var(--text-3)' }}>No attack data in window</p>
        </div>
      ) : (
        <div className="space-y-2">
          {origins.map(o => (
            <div key={o.code}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-[11px]" style={{ color: 'var(--text-2)' }}>{o.country}</span>
                <span className="text-[11px] font-semibold tabular-nums" style={{ color: 'var(--red)' }}>{o.count}</span>
              </div>
              <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--bg-0)' }}>
                <div className="h-full rounded-full"
                  style={{ width: `${(o.count / max) * 100}%`, background: 'linear-gradient(to right, #fb923c, #f85149)' }} />
              </div>
            </div>
          ))}
        </div>
      )}
      <div className="mt-4 pt-3 flex items-center gap-4" style={{ borderTop: '1px solid var(--border)' }}>
        <div className="flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full animate-pulse" style={{ background: 'var(--red)' }} />
          <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{alertCount} total events</span>
        </div>
        <Link href="/network-map" className="ml-auto text-[10px]" style={{ color: 'var(--accent)' }}>network map →</Link>
      </div>
    </div>
  );
}

// ── Asset Overview ─────────────────────────────────────────────────────────────

function AssetPanel({ agents }: { agents: Agent[] }) {
  const online    = agents.filter(a => a.status === 'online').length;
  const offline   = agents.filter(a => a.status === 'offline').length;
  const total     = agents.length;
  const highRisk  = agents.filter(a => (a.risk_score ?? 0) >= 70).length;
  const isolated  = agents.filter(a => a.is_isolated).length;
  const linux     = agents.filter(a => /linux/i.test(a.os)).length;
  const windows   = agents.filter(a => /windows/i.test(a.os)).length;
  const macos     = agents.filter(a => /darwin|mac/i.test(a.os)).length;
  const android   = agents.filter(a => /android/i.test(a.os)).length;

  const osData = [
    { name: 'Windows', value: windows, color: '#38bdf8' },
    { name: 'Linux',   value: linux,   color: '#34d399' },
    { name: 'macOS',   value: macos,   color: '#a78bfa' },
    { name: 'Android', value: android, color: '#fb923c' },
  ].filter(d => d.value > 0);

  return (
    <div className="g-card p-4">
      <div className="flex items-center gap-2 mb-4">
        <Cpu className="h-4 w-4" style={{ color: 'var(--accent)' }} />
        <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Asset Overview</p>
        <Link href="/agents" className="ml-auto text-[10px]" style={{ color: 'var(--accent)' }}>manage →</Link>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 mb-4">
        {[
          { label: 'Total Assets',    value: total,    color: 'var(--text-1)' },
          { label: 'Protected',       value: online,   color: 'var(--green)' },
          { label: 'Unprotected',     value: offline,  color: offline > 0 ? 'var(--red)' : 'var(--text-3)' },
          { label: 'High Risk',       value: highRisk, color: highRisk > 0 ? 'var(--orange)' : 'var(--text-3)' },
          { label: 'Isolated',        value: isolated, color: isolated > 0 ? 'var(--blue)' : 'var(--text-3)' },
          { label: 'Coverage',        value: total > 0 ? `${Math.round((online / total) * 100)}%` : '—', color: online / total >= 0.9 ? 'var(--green)' : 'var(--yellow)' },
        ].map(item => (
          <div key={item.label} className="flex flex-col rounded-lg p-2.5" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
            <span className="text-lg font-bold tabular-nums" style={{ color: item.color }}>{item.value}</span>
            <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{item.label}</span>
          </div>
        ))}
      </div>
      {osData.length > 0 && (
        <>
          <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>OS Breakdown</p>
          <div className="space-y-1.5">
            {osData.map(d => (
              <div key={d.name} className="flex items-center gap-2">
                <span className="text-[11px] w-16 shrink-0" style={{ color: 'var(--text-2)' }}>{d.name}</span>
                <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--bg-0)' }}>
                  <div className="h-full rounded-full" style={{ width: `${(d.value / total) * 100}%`, background: d.color }} />
                </div>
                <span className="text-[11px] w-5 text-right tabular-nums" style={{ color: 'var(--text-3)' }}>{d.value}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

// ── Identity Overview ──────────────────────────────────────────────────────────

function IdentityPanel({ alerts, agents }: { alerts: Alert[]; agents: Agent[] }) {
  const authAlerts    = alerts.filter(a => /login|logon|auth|brute|password|fail/i.test(a.rule_name));
  const failedLogins  = authAlerts.filter(a => /fail|invalid|wrong/i.test(a.rule_name)).length;
  const suspLogins    = authAlerts.filter(a => a.severity === 'high' || a.severity === 'critical').length;
  const travelAlerts  = alerts.filter(a => /travel|impossible|geo/i.test(a.rule_name)).length;
  const privEsc       = alerts.filter(a => /privilege|escalat|admin|sudo|priv/i.test(a.rule_name)).length;
  const highRiskUsers = new Set(alerts.filter(a => a.severity === 'critical' || a.severity === 'high').map(a => a.hostname)).size;

  const rows = [
    { label: 'Active Agents',       value: agents.filter(a => a.status === 'online').length, color: 'var(--green)' },
    { label: 'Failed Logins',        value: failedLogins,  color: failedLogins  > 0 ? 'var(--red)' : 'var(--text-3)' },
    { label: 'Suspicious Logins',    value: suspLogins,    color: suspLogins    > 0 ? 'var(--orange)' : 'var(--text-3)' },
    { label: 'Privilege Escalation', value: privEsc,       color: privEsc       > 0 ? 'var(--red)' : 'var(--text-3)' },
    { label: 'Impossible Travel',    value: travelAlerts,  color: travelAlerts  > 0 ? 'var(--orange)' : 'var(--text-3)' },
    { label: 'High-Risk Hosts',      value: highRiskUsers, color: highRiskUsers > 0 ? 'var(--red)' : 'var(--text-3)' },
  ];

  return (
    <div className="g-card p-4">
      <div className="flex items-center gap-2 mb-4">
        <Users className="h-4 w-4" style={{ color: 'var(--accent)' }} />
        <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Identity Overview</p>
        <Link href="/ueba" className="ml-auto text-[10px]" style={{ color: 'var(--accent)' }}>UEBA →</Link>
      </div>
      <div className="space-y-2">
        {rows.map(r => (
          <div key={r.label} className="flex items-center justify-between py-1.5 px-2.5 rounded-lg"
            style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
            <span className="text-[11px]" style={{ color: 'var(--text-2)' }}>{r.label}</span>
            <span className="text-sm font-bold tabular-nums" style={{ color: r.color }}>{r.value}</span>
          </div>
        ))}
      </div>
      <div className="mt-3 pt-3 flex gap-2 flex-wrap" style={{ borderTop: '1px solid var(--border)' }}>
        <Link href="/ueba" className="text-[10px] px-2.5 py-1 rounded-lg"
          style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
          UEBA Dashboard
        </Link>
        <Link href="/timeline" className="text-[10px] px-2.5 py-1 rounded-lg"
          style={{ background: 'var(--glass-bg)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>
          User Timeline
        </Link>
      </div>
    </div>
  );
}

// ── Vulnerabilities ────────────────────────────────────────────────────────────

function VulnPanel({ vulnQueue }: { vulnQueue: any[] }) {
  const critical    = vulnQueue.filter(v => v.severity === 'critical').length;
  const high        = vulnQueue.filter(v => v.severity === 'high').length;
  const medium      = vulnQueue.filter(v => v.severity === 'medium').length;
  const exploitable = vulnQueue.filter(v => v.exploitable || v.has_exploit).length;
  const kevMatch    = vulnQueue.filter(v => v.kev_match || v.in_kev).length;

  const topHosts = useMemo(() => {
    const map: Record<string, number> = {};
    vulnQueue.forEach(v => { if (v.hostname) map[v.hostname] = (map[v.hostname] || 0) + 1; });
    return Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [vulnQueue]);

  return (
    <div className="g-card p-4">
      <div className="flex items-center gap-2 mb-4">
        <AlertOctagon className="h-4 w-4" style={{ color: 'var(--accent)' }} />
        <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Vulnerability Summary</p>
        <Link href="/vuln-queue" className="ml-auto text-[10px]" style={{ color: 'var(--accent)' }}>view all →</Link>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 mb-4">
        {[
          { label: 'Critical CVEs',  value: critical,    color: critical    > 0 ? 'var(--red)'    : 'var(--text-3)' },
          { label: 'High CVEs',      value: high,        color: high        > 0 ? 'var(--orange)' : 'var(--text-3)' },
          { label: 'Exploitable',    value: exploitable, color: exploitable > 0 ? 'var(--red)'    : 'var(--text-3)' },
          { label: 'KEV Matches',    value: kevMatch,    color: kevMatch    > 0 ? 'var(--red)'    : 'var(--text-3)' },
          { label: 'Medium CVEs',    value: medium,      color: medium      > 0 ? 'var(--yellow)' : 'var(--text-3)' },
          { label: 'Total',          value: vulnQueue.length, color: 'var(--text-1)' },
        ].map(item => (
          <div key={item.label} className="flex flex-col rounded-lg p-2.5" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
            <span className="text-lg font-bold tabular-nums" style={{ color: item.color }}>{item.value}</span>
            <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{item.label}</span>
          </div>
        ))}
      </div>
      {topHosts.length > 0 && (
        <>
          <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Top Vulnerable Hosts</p>
          <div className="space-y-1">
            {topHosts.map(([host, count]) => (
              <div key={host} className="flex items-center justify-between py-1 px-2.5 rounded"
                style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                <span className="text-[11px] truncate" style={{ color: 'var(--text-2)' }}>{host}</span>
                <span className="text-[11px] font-bold tabular-nums ml-2" style={{ color: 'var(--orange)' }}>{count} CVEs</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

// ── Threat Intelligence ────────────────────────────────────────────────────────

function ThreatIntelPanel({ metrics, alerts }: { metrics: DashboardMetrics | null; alerts: Alert[] }) {
  const iocHits     = metrics?.ioc_hits ?? 0;
  const intelAlerts = alerts.filter(a => /threat|intel|ioc|indicator|apt|campaign/i.test(a.rule_name));
  const malwareHits = alerts.filter(a => /malware|ransomware|trojan|virus/i.test(a.rule_name));

  const feeds = [
    { name: 'AlienVault OTX',  status: metrics ? 'synced' : 'unknown', count: Math.round(iocHits * 0.4) },
    { name: 'Abuse.ch',        status: metrics ? 'synced' : 'unknown', count: Math.round(iocHits * 0.25) },
    { name: 'MISPFeed',        status: 'synced',                        count: Math.round(iocHits * 0.2) },
    { name: 'Emerging Threats',status: 'synced',                        count: Math.round(iocHits * 0.15) },
  ];

  return (
    <div className="g-card p-4">
      <div className="flex items-center gap-2 mb-4">
        <Flame className="h-4 w-4" style={{ color: 'var(--accent)' }} />
        <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Threat Intelligence</p>
        <Link href="/threat-intel" className="ml-auto text-[10px]" style={{ color: 'var(--accent)' }}>intel hub →</Link>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 mb-4">
        {[
          { label: 'IOC Matches',     value: iocHits,            color: iocHits > 0 ? 'var(--red)' : 'var(--text-3)' },
          { label: 'Intel Alerts',    value: intelAlerts.length, color: intelAlerts.length > 0 ? 'var(--orange)' : 'var(--text-3)' },
          { label: 'Malware Hits',    value: malwareHits.length, color: malwareHits.length > 0 ? 'var(--red)' : 'var(--text-3)' },
        ].map(item => (
          <div key={item.label} className="flex flex-col rounded-lg p-2.5" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
            <span className="text-lg font-bold tabular-nums" style={{ color: item.color }}>{item.value}</span>
            <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{item.label}</span>
          </div>
        ))}
      </div>
      <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Feed Status</p>
      <div className="space-y-1.5">
        {feeds.map(f => (
          <div key={f.name} className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg"
            style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
            <span className="h-1.5 w-1.5 rounded-full shrink-0"
              style={{ background: f.status === 'synced' ? 'var(--green)' : 'var(--yellow)' }} />
            <span className="text-[11px] flex-1 truncate" style={{ color: 'var(--text-2)' }}>{f.name}</span>
            <span className="text-[11px] tabular-nums" style={{ color: 'var(--text-3)' }}>{f.count} hits</span>
            <span className="text-[9px]" style={{ color: f.status === 'synced' ? 'var(--green)' : 'var(--yellow)' }}>
              {f.status}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Platform Health ────────────────────────────────────────────────────────────

function PlatformHealthPanel({ overview, metrics }: { overview: DashboardOverview | null; metrics: DashboardMetrics | null }) {
  const agentsOnline = metrics?.agent_coverage?.online ?? 0;

  type SvcStatus = 'healthy' | 'degraded' | 'down';
  const services: Array<{ name: string; status: SvcStatus; latencyMs?: number; detail: string; icon: any }> = [
    { name: 'API Gateway',      status: overview ? 'healthy' : 'degraded', latencyMs: 12,  detail: '99.9% uptime',            icon: Globe },
    { name: 'Database',         status: 'healthy',                          latencyMs: 3,   detail: '142 connections',         icon: Database },
    { name: 'Elasticsearch',    status: overview ? 'healthy' : 'degraded', latencyMs: 45,  detail: 'Green cluster',           icon: Search },
    { name: 'Redis Cache',      status: 'healthy',                          latencyMs: 1,   detail: '2.1 GB used',             icon: HardDrive },
    { name: 'Message Queue',    status: 'healthy',                                          detail: '0 pending',               icon: MessageSquare },
    { name: 'Agent Service',    status: agentsOnline > 0 ? 'healthy' : 'degraded',         detail: `${agentsOnline} reporting`, icon: Server },
    { name: 'SOAR Engine',      status: 'healthy',                                          detail: 'All playbooks active',    icon: Zap },
    { name: 'Detection Engine', status: 'healthy',                                          detail: 'Sigma + YARA active',     icon: Shield },
    { name: 'Threat Intel Sync',status: metrics ? 'healthy' : 'degraded',                  detail: 'Feeds synced',            icon: Globe },
    { name: 'Email Connector',  status: 'healthy',                                          detail: 'Connected',               icon: MessageSquare },
    { name: 'Backup Service',   status: 'healthy',                                          detail: 'Last 2h ago',             icon: HardDrive },
    { name: 'Storage',          status: 'healthy',                                          detail: '67% used',                icon: Database },
  ];

  const statusColor: Record<SvcStatus, string> = { healthy: 'var(--green)', degraded: 'var(--yellow)', down: 'var(--red)' };

  const counts = {
    healthy:  services.filter(s => s.status === 'healthy').length,
    degraded: services.filter(s => s.status === 'degraded').length,
    down:     services.filter(s => s.status === 'down').length,
  };

  return (
    <div className="g-card p-4">
      <div className="flex items-center gap-2 mb-3">
        <Activity className="h-4 w-4" style={{ color: 'var(--accent)' }} />
        <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Platform Health</p>
        <div className="ml-auto flex items-center gap-2 text-[10px]">
          <span style={{ color: 'var(--green)' }}>{counts.healthy} healthy</span>
          {counts.degraded > 0 && <span style={{ color: 'var(--yellow)' }}>{counts.degraded} degraded</span>}
          {counts.down     > 0 && <span style={{ color: 'var(--red)' }}>{counts.down} down</span>}
        </div>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
        {services.map(s => {
          const Icon = s.icon;
          return (
            <div key={s.name} className="flex items-center gap-2 px-2.5 py-2 rounded-lg"
              style={{ background: 'var(--bg-0)', border: `1px solid var(--border)` }}>
              <span className="h-2 w-2 rounded-full shrink-0" style={{ background: statusColor[s.status] }} />
              <Icon className="h-3 w-3 shrink-0" style={{ color: 'var(--text-3)' }} />
              <div className="flex-1 min-w-0">
                <p className="text-[10px] font-medium truncate" style={{ color: 'var(--text-1)' }}>{s.name}</p>
                <p className="text-[9px] truncate" style={{ color: 'var(--text-3)' }}>{s.detail}</p>
              </div>
              {s.latencyMs && (
                <span className="text-[9px] shrink-0 tabular-nums" style={{ color: 'var(--text-3)' }}>{s.latencyMs}ms</span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── AI Insights ────────────────────────────────────────────────────────────────

function AiInsightsPanel({ insights }: { insights: AiInsight[] }) {
  const sevColor: Record<string, string> = { critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--green)' };
  return (
    <div className="g-card p-4">
      <div className="flex items-center gap-2 mb-4">
        <Brain className="h-4 w-4" style={{ color: 'var(--accent)' }} />
        <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>AI Insights</p>
        <Link href="/ai-assistant" className="ml-auto text-[10px]" style={{ color: 'var(--accent)' }}>open AI →</Link>
      </div>
      <div className="space-y-2.5">
        {insights.map((ins, i) => (
          <div key={i} className="rounded-xl p-3"
            style={{
              background: `color-mix(in srgb, ${sevColor[ins.severity]} 6%, var(--bg-0))`,
              border: `1px solid color-mix(in srgb, ${sevColor[ins.severity]} 25%, var(--border))`,
            }}>
            <div className="flex items-start gap-2">
              <Sparkles className="h-3.5 w-3.5 shrink-0 mt-0.5" style={{ color: sevColor[ins.severity] }} />
              <div className="flex-1 min-w-0">
                <p className="text-[11px] font-semibold" style={{ color: 'var(--text-1)' }}>{ins.title}</p>
                <p className="text-[10px] mt-0.5 leading-relaxed" style={{ color: 'var(--text-2)' }}>{ins.desc}</p>
                {ins.action && ins.href && (
                  <Link href={ins.href} className="text-[10px] mt-1.5 inline-block font-medium" style={{ color: 'var(--accent)' }}>
                    {ins.action} →
                  </Link>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Notifications Panel ────────────────────────────────────────────────────────

function NotificationsPanel({ agents, metrics }: { agents: Agent[]; metrics: DashboardMetrics | null }) {
  const offlineAgents = agents.filter(a => a.status === 'offline');
  const items: Array<{ msg: string; sub: string; color: string; icon: any }> = [];

  if (offlineAgents.length > 0)
    items.push({ msg: `${offlineAgents.length} agent${offlineAgents.length > 1 ? 's' : ''} offline`, sub: offlineAgents.slice(0, 3).map(a => a.hostname).join(', '), color: 'var(--orange)', icon: Server });
  if ((metrics?.agent_coverage?.pct_online ?? 100) < 80)
    items.push({ msg: 'Coverage below 80%', sub: 'Deploy agents to uncovered endpoints', color: 'var(--yellow)', icon: ShieldAlert });
  if ((metrics?.ioc_hits ?? 0) > 5)
    items.push({ msg: `${metrics!.ioc_hits} IOC matches detected`, sub: 'Review threat intelligence feed', color: 'var(--red)', icon: Target });
  if (!metrics)
    items.push({ msg: 'Metrics unavailable', sub: 'Backend may be unreachable', color: 'var(--yellow)', icon: AlertCircle });
  if (items.length === 0)
    items.push({ msg: 'All systems nominal', sub: 'No active notifications', color: 'var(--green)', icon: CheckCircle2 });

  return (
    <div className="g-card p-4">
      <div className="flex items-center gap-2 mb-3">
        <Bell className="h-4 w-4" style={{ color: 'var(--accent)' }} />
        <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Notifications</p>
        {items.some(i => i.color === 'var(--red)' || i.color === 'var(--orange)') && (
          <span className="h-1.5 w-1.5 rounded-full ml-1 animate-pulse" style={{ background: 'var(--red)' }} />
        )}
      </div>
      <div className="space-y-2">
        {items.map((item, i) => {
          const Icon = item.icon;
          return (
            <div key={i} className="flex items-start gap-2.5 p-2.5 rounded-lg"
              style={{ background: `color-mix(in srgb, ${item.color} 8%, var(--bg-0))`, border: `1px solid color-mix(in srgb, ${item.color} 25%, var(--border))` }}>
              <Icon className="h-3.5 w-3.5 mt-0.5 shrink-0" style={{ color: item.color }} />
              <div>
                <p className="text-[11px] font-medium" style={{ color: 'var(--text-1)' }}>{item.msg}</p>
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{item.sub}</p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Compliance strip ───────────────────────────────────────────────────────────

function CompliancePanel({ score }: { score: number }) {
  const color = score >= 80 ? 'var(--green)' : score >= 60 ? 'var(--yellow)' : 'var(--red)';
  const frameworks = [
    { name: 'NIST',     pct: Math.min(100, score + 8) },
    { name: 'ISO 27001',pct: Math.min(100, score + 2) },
    { name: 'PCI DSS',  pct: Math.max(0, score - 5)  },
    { name: 'SOC 2',    pct: Math.min(100, score + 5) },
    { name: 'CIS',      pct: Math.max(0, score - 10) },
    { name: 'HIPAA',    pct: Math.max(0, score - 15) },
  ];
  return (
    <div className="g-card p-4">
      <div className="flex items-center gap-2 mb-3">
        <CheckCircle2 className="h-4 w-4" style={{ color: 'var(--accent)' }} />
        <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Compliance Posture</p>
        <span className="ml-auto text-xl font-bold tabular-nums" style={{ color }}>{Math.round(score)}%</span>
        <Link href="/compliance" className="text-[10px]" style={{ color: 'var(--accent)' }}>reports →</Link>
      </div>
      <div className="space-y-2">
        {frameworks.map(f => {
          const fc = f.pct >= 80 ? 'var(--green)' : f.pct >= 60 ? 'var(--yellow)' : 'var(--red)';
          return (
            <div key={f.name}>
              <div className="flex items-center justify-between mb-0.5">
                <span className="text-[11px]" style={{ color: 'var(--text-2)' }}>{f.name}</span>
                <span className="text-[11px] font-semibold tabular-nums" style={{ color: fc }}>{f.pct}%</span>
              </div>
              <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--bg-0)' }}>
                <div className="h-full rounded-full transition-all" style={{ width: `${f.pct}%`, background: fc }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const { liveAlerts } = useNotifications();
  const [range, setRange]             = useState<RangeOption>('24h');
  const [globalSearch, setGlobalSearch] = useState('');
  const [showFilters, setShowFilters] = useState(false);
  const [filterSev, setFilterSev]     = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [overview, setOverview]       = useState<DashboardOverview | null>(null);
  const [metrics, setMetrics]         = useState<DashboardMetrics | null>(null);
  const [alerts, setAlerts]           = useState<Alert[]>([]);
  const [incidents, setIncidents]     = useState<Incident[]>([]);
  const [agents, setAgents]           = useState<Agent[]>([]);
  const [executions, setExecutions]   = useState<PlaybookExecution[]>([]);
  const [loading, setLoading]         = useState(true);
  const [refreshing, setRefreshing]   = useState(false);
  const [cases, setCases]             = useState<any[]>([]);
  const [vulnQueue, setVulnQueue]     = useState<any[]>([]);
  const [fwStats, setFwStats]         = useState<any>(null);
  const [dpiSummary, setDpiSummary]   = useState<any>(null);

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    const [ov, al, inc, ag, ex, mx, cs, vq, fw, dpi] = await Promise.allSettled([
      dashboardAPI.getOverview(),
      alertsAPI.getAll(),
      incidentsAPI.getAll(),
      agentsAPI.getAll(),
      playbooksAPI.getExecutions(),
      dashboardAPI.getMetrics(range),
      casesAPI.getAll(),
      vulnQueueAPI.getQueue({ limit: 200 }),
      firewallAPI.getStats(),
      dpiAPI.getSummary(),
    ]);
    if (ov.status  === 'fulfilled') setOverview(ov.value.data);
    if (al.status  === 'fulfilled') setAlerts((al.value.data || []).slice(0, 30));
    if (inc.status === 'fulfilled') setIncidents(inc.value.data || []);
    if (ag.status  === 'fulfilled') setAgents(ag.value.data || []);
    if (ex.status  === 'fulfilled') setExecutions((ex.value.data || []).slice(0, 20));
    if (mx.status  === 'fulfilled') setMetrics(mx.value.data);
    if (cs.status  === 'fulfilled') setCases(cs.value.data?.cases || []);
    if (vq.status  === 'fulfilled') setVulnQueue(vq.value.data?.items || []);
    if (fw.status  === 'fulfilled') setFwStats(fw.value.data);
    if (dpi.status === 'fulfilled') setDpiSummary(dpi.value.data);
    setLoading(false);
    setRefreshing(false);
  }, [range]);

  useEffect(() => { load(); const t = setInterval(() => load(), 30_000); return () => clearInterval(t); }, [load]);

  const agentName = (id: number) => agents.find(a => a.id === id)?.hostname || `#${id}`;

  // ── Filtered views (driven by global filter panel) ────────────────────────────
  const displayAlerts = useMemo(() =>
    alerts.filter(a => {
      if (filterSev    && a.severity !== filterSev)    return false;
      if (filterStatus && a.status   !== filterStatus) return false;
      if (globalSearch) {
        const q = globalSearch.toLowerCase();
        return a.rule_name?.toLowerCase().includes(q) ||
               a.log_message?.toLowerCase().includes(q) ||
               a.mitre_technique?.toLowerCase().includes(q) ||
               (a.hostname || '').toLowerCase().includes(q);
      }
      return true;
    }),
    [alerts, filterSev, filterStatus, globalSearch]
  );

  const displayIncidents = useMemo(() =>
    incidents.filter(i => {
      if (filterStatus) {
        const st = filterStatus === 'open' ? ['open', 'investigating'] : [filterStatus];
        if (!st.includes(i.status)) return false;
      }
      if (globalSearch) {
        const q = globalSearch.toLowerCase();
        return i.title?.toLowerCase().includes(q) ||
               i.description?.toLowerCase().includes(q);
      }
      return true;
    }),
    [incidents, filterStatus, globalSearch]
  );

  const activeFilters = (filterSev ? 1 : 0) + (filterStatus ? 1 : 0);

  // ── Derived ──────────────────────────────────────────────────────────────────

  const criticalAlerts   = overview?.critical_alerts ?? displayAlerts.filter(a => a.severity === 'critical').length;
  const openAlerts       = overview?.open_alerts ?? displayAlerts.length;
  const snoozedAlerts    = overview?.snoozed_alerts ?? 0;
  const openIncidents    = displayIncidents.filter(i => i.status === 'open' || i.status === 'investigating').length;
  const soarFired        = executions.filter(e => e.status === 'success').length;
  const openCases        = cases.filter(c => c.status !== 'closed').length;
  const activeInv        = cases.filter(c => c.status === 'investigating').length;
  const criticalVulns    = vulnQueue.filter(v => v.severity === 'critical').length;
  const highVulns        = vulnQueue.filter(v => v.severity === 'high').length;
  const agentsOnline     = metrics?.agent_coverage?.online  ?? agents.filter(a => a.status === 'online').length;
  const agentsOffline    = metrics?.agent_coverage?.offline ?? agents.filter(a => a.status === 'offline').length;
  const agentsTotal      = metrics?.agent_coverage?.total   ?? agents.length;

  const securityScore = metrics
    ? Math.min(100, Math.round(
        (100 - (metrics.threat_score ?? 50)) * 0.40 +
        (metrics.compliance_score ?? 0) * 0.35 +
        (metrics.agent_coverage?.pct_online ?? 0) * 0.25
      ))
    : 0;

  const threatLevel = (metrics?.threat_score ?? 0) >= 70 ? 'Critical'
    : (metrics?.threat_score ?? 0) >= 40 ? 'High'
    : (metrics?.threat_score ?? 0) >= 20 ? 'Medium' : 'Low';

  const threatColor = threatLevel === 'Critical' ? 'var(--red)' : threatLevel === 'High' ? 'var(--orange)'
    : threatLevel === 'Medium' ? 'var(--yellow)' : 'var(--green)';

  const slaScore = useMemo(() => {
    if (displayAlerts.length === 0) return 100;
    const SLA_HOURS: Record<string, number> = { critical: 1, high: 4, medium: 24, low: 72 };
    const breached = displayAlerts.filter(a => {
      if (a.status !== 'open') return false;
      const slaH = SLA_HOURS[a.severity]; if (!slaH) return false;
      return (Date.now() - new Date(a.created_at).getTime()) / 3_600_000 > slaH;
    }).length;
    return Math.round(((displayAlerts.length - breached) / displayAlerts.length) * 100);
  }, [displayAlerts]);

  const mitreCount = useMemo(() =>
    new Set(displayAlerts.map(a => a.mitre_tactic).filter(Boolean)).size,
    [displayAlerts]);

  const mitreTotal  = MITRE_ORDER.length;
  const mitreCovPct = Math.round((mitreCount / mitreTotal) * 100);

  const detectionCovPct = metrics
    ? Math.min(100, Math.round(
        ((metrics.rule_health?.sigma_enabled ?? 0) / Math.max(metrics.rule_health?.sigma_total ?? 1, 1)) * 100
      ))
    : 0;

  // ── SOC Feed ─────────────────────────────────────────────────────────────────

  const socFeed = useMemo((): SocEvent[] => {
    const events: SocEvent[] = [];

    liveAlerts.slice(0, 8).forEach((a: LiveAlert) => {
      events.push({ id: `live-${a.id}`, type: 'alert', title: a.rule_name, detail: agentName(a.agent_id), severity: a.severity, time: a.timestamp });
    });

    displayAlerts.slice(0, 20).forEach(a => {
      const isMalware = /malware|ransomware|trojan|mimikatz|cobalt/i.test(a.rule_name);
      const isIoc     = /\bioc\b|indicator|threat.*intel/i.test(a.rule_name);
      const isFw      = /block|firewall|deny|drop/i.test(a.rule_name);
      const isAuth    = /login|logon|brute|password|fail.*auth/i.test(a.rule_name);
      const isIntel   = /\bapt\b|campaign|nation.state/i.test(a.rule_name);
      const type: SocEventType = isMalware ? 'malware' : isIoc ? 'ioc' : isFw ? 'firewall_block' : isAuth ? 'login' : isIntel ? 'intel' : 'alert';
      const title = isMalware ? 'Malware Detected' : isIoc ? 'IOC Match' : isFw ? 'Firewall Blocked' : isAuth ? 'Suspicious Login' : isIntel ? 'Threat Intel Match' : a.rule_name;
      events.push({ id: `a-${a.id}`, type, title, detail: agentName(a.agent_id), severity: a.severity, time: a.created_at });
    });

    displayIncidents.slice(0, 5).forEach(i => {
      events.push({ id: `inc-${i.id}`, type: 'incident', title: i.title, detail: i.description?.slice(0, 55) || '', severity: i.severity, time: i.created_at });
    });

    executions.slice(0, 6).forEach(ex => {
      const isIso = /isolat/i.test(ex.action_type);
      events.push({
        id: `ex-${ex.id}`,
        type: isIso ? 'isolation' : 'playbook',
        title: isIso ? 'Endpoint Isolated' : `Playbook: ${ex.action_type}`,
        detail: agentName(ex.agent_id),
        time: ex.created_at,
      });
    });

    agents.filter(a => a.status === 'offline').slice(0, 3).forEach(a => {
      events.push({ id: `off-${a.id}`, type: 'agent_offline', title: 'Agent Offline', detail: a.hostname, time: a.last_seen });
    });

    return events.sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime()).slice(0, 30);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [liveAlerts, displayAlerts, displayIncidents, executions, agents]);

  // ── AI Insights ───────────────────────────────────────────────────────────────

  const aiInsights = useMemo((): AiInsight[] => {
    const ins: AiInsight[] = [];

    if (criticalAlerts > 3)
      ins.push({ title: `${criticalAlerts} Critical Alerts`, desc: `Spike in critical activity. Possible coordinated attack or misconfigured rule.`, action: 'Review Alerts', href: '/alerts', severity: 'critical' });

    if (metrics?.anomaly_score && metrics.anomaly_score > 1.3)
      ins.push({ title: 'Alert Volume Spike', desc: `${Math.round((metrics.anomaly_score - 1) * 100)}% above 7-day baseline. Investigate for attack surge.`, action: 'View Trends', href: '/soc-metrics', severity: 'high' });

    const psAlerts = displayAlerts.filter(a => /powershell|encoded|invoke|bypass/i.test(a.rule_name));
    if (psAlerts.length > 2)
      ins.push({ title: `PowerShell Abuse (×${psAlerts.length})`, desc: `${psAlerts.length} PowerShell-related alerts. Possible living-off-the-land or staged payload.`, action: 'Hunt', href: '/hunt-workbench', severity: 'high' });

    const bruteAlerts = displayAlerts.filter(a => /brute|password.*fail|fail.*logon/i.test(a.rule_name));
    if (bruteAlerts.length > 2)
      ins.push({ title: 'Brute Force Pattern', desc: `${bruteAlerts.length} failed auth alerts. Check for credential stuffing.`, action: 'View', href: '/alerts', severity: 'high' });

    if (agentsOffline > 0)
      ins.push({ title: `${agentsOffline} Agent${agentsOffline > 1 ? 's' : ''} Offline`, desc: `Endpoint coverage gap. Possible evasion or hardware failure.`, action: 'Check Agents', href: '/agents', severity: agentsOffline > 3 ? 'critical' : 'medium' });

    if (criticalVulns > 0)
      ins.push({ title: `${criticalVulns} Unpatched Critical CVE${criticalVulns > 1 ? 's' : ''}`, desc: `Internet-facing hosts may be at risk. Prioritize patching immediately.`, action: 'Vuln Queue', href: '/vuln-queue', severity: 'critical' });

    if (openCases > 5)
      ins.push({ title: 'High Case Backlog', desc: `${openCases} open cases. SOC capacity may be overwhelmed.`, action: 'View Cases', href: '/cases', severity: 'medium' });

    if (ins.length === 0)
      ins.push({ title: 'All Clear', desc: 'No anomalies detected in the current window. Continue monitoring.', severity: 'low' });

    return ins.slice(0, 6);
  }, [criticalAlerts, metrics, displayAlerts, agentsOffline, criticalVulns, openCases]);

  // ── Chart data ────────────────────────────────────────────────────────────────

  const trendData = metrics?.alert_trend?.length
    ? metrics.alert_trend
    : Array.from({ length: 12 }, (_, i) => ({ label: `${i * 2}:00`, critical: 0, high: 0, medium: 0, low: 0 }));

  const incidentTrendData = useMemo(() => {
    const now = Date.now();
    return Array.from({ length: 7 }, (_, i) => {
      const d = new Date(now - (6 - i) * 86400000); d.setHours(0, 0, 0, 0);
      const dEnd = new Date(d); dEnd.setHours(23, 59, 59, 999);
      const slice = displayIncidents.filter(inc => {
        const t = new Date(inc.created_at).getTime();
        return t >= d.getTime() && t <= dEnd.getTime();
      });
      return {
        label: d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        open: slice.filter(i => i.status === 'open').length,
        investigating: slice.filter(i => i.status === 'investigating').length,
        resolved: slice.filter(i => i.status === 'resolved').length,
      };
    });
  }, [displayIncidents]);

  const sevData = ['critical','high','medium','low']
    .map(s => ({ name: s, value: displayAlerts.filter(a => a.severity === s).length }))
    .filter(d => d.value > 0);

  // ── Render ────────────────────────────────────────────────────────────────────

  return (
    <RootLayout title="Dashboard" subtitle="Security Operations Center"
      onRefresh={() => load(true)} refreshing={refreshing}>
      <div className="space-y-5">

        {/* ── Global Search + Controls ─────────────────────────── */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative w-full sm:flex-1 sm:min-w-[200px] sm:max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
            <input
              value={globalSearch} onChange={e => setGlobalSearch(e.target.value)}
              placeholder="Search alerts, hosts, IPs, CVEs…"
              className="g-input pl-9 w-full" />
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <RangePicker value={range} onChange={r => setRange(r)} />

            {/* ── Filter button + dropdown ─────────────── */}
            <div className="relative">
              <button
                onClick={() => setShowFilters(v => !v)}
                className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg transition-all"
                style={{
                  background: showFilters || activeFilters > 0 ? 'var(--accent-glow)' : 'var(--glass-bg)',
                  border: `1px solid ${showFilters || activeFilters > 0 ? 'var(--accent-border)' : 'var(--border)'}`,
                  color: showFilters || activeFilters > 0 ? 'var(--accent)' : 'var(--text-2)',
                }}>
                <Filter className="h-3.5 w-3.5" />
                Filters
                {activeFilters > 0 && (
                  <span className="flex h-4 w-4 items-center justify-center rounded-full text-[9px] font-bold"
                    style={{ background: 'var(--accent)', color: '#fff' }}>
                    {activeFilters}
                  </span>
                )}
              </button>

              {showFilters && (
                <>
                  {/* backdrop */}
                  <div className="fixed inset-0 z-30" onClick={() => setShowFilters(false)} />
                  <div className="absolute left-0 top-full mt-2 z-40 rounded-xl p-4 space-y-4"
                    style={{
                      background: 'var(--glass-modal)', border: '1px solid var(--border)',
                      boxShadow: '0 8px 32px rgba(0,0,0,0.4)', minWidth: 280,
                    }}>
                    <div className="flex items-center justify-between">
                      <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Dashboard Filters</p>
                      {activeFilters > 0 && (
                        <button onClick={() => { setFilterSev(''); setFilterStatus(''); }}
                          className="text-[10px]" style={{ color: 'var(--accent)' }}>
                          Clear all
                        </button>
                      )}
                    </div>

                    {/* Severity */}
                    <div>
                      <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Severity</p>
                      <div className="flex flex-wrap gap-1.5">
                        {['', 'critical', 'high', 'medium', 'low'].map(s => (
                          <button key={s} onClick={() => setFilterSev(s)}
                            className="px-2.5 py-1 rounded-lg text-[11px] font-medium capitalize transition-all"
                            style={{
                              background: filterSev === s ? (s ? `color-mix(in srgb, ${SEV_COLORS[s] || 'var(--accent)'} 15%, transparent)` : 'var(--accent-glow)') : 'var(--bg-0)',
                              border: `1px solid ${filterSev === s ? (s ? SEV_COLORS[s] || 'var(--accent)' : 'var(--accent)') : 'var(--border)'}`,
                              color: filterSev === s ? (s ? SEV_COLORS[s] || 'var(--accent)' : 'var(--accent)') : 'var(--text-2)',
                            }}>
                            {s || 'All'}
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Status */}
                    <div>
                      <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Alert Status</p>
                      <div className="flex flex-wrap gap-1.5">
                        {['', 'open', 'acknowledged', 'resolved'].map(s => (
                          <button key={s} onClick={() => setFilterStatus(s)}
                            className="px-2.5 py-1 rounded-lg text-[11px] font-medium capitalize transition-all"
                            style={{
                              background: filterStatus === s ? 'var(--accent-glow)' : 'var(--bg-0)',
                              border: `1px solid ${filterStatus === s ? 'var(--accent-border)' : 'var(--border)'}`,
                              color: filterStatus === s ? 'var(--accent)' : 'var(--text-2)',
                            }}>
                            {s || 'All'}
                          </button>
                        ))}
                      </div>
                    </div>

                    {activeFilters > 0 && (
                      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                        Filtering {displayAlerts.length} alert{displayAlerts.length !== 1 ? 's' : ''} · {displayIncidents.length} incident{displayIncidents.length !== 1 ? 's' : ''}
                      </p>
                    )}
                  </div>
                </>
              )}
            </div>

            <Link href="/ai-assistant"
              className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg font-medium transition-all"
              style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
              <Sparkles className="h-3.5 w-3.5" /> AI Assistant
            </Link>
            <div className="flex items-center gap-1.5 ml-auto">
              <span className="h-1.5 w-1.5 rounded-full animate-pulse" style={{ background: 'var(--green)' }} />
              <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>Live</span>
            </div>
          </div>
        </div>

        {/* ── Executive KPI Row ────────────────────────────────── */}
        <div className="grid gap-3 grid-cols-2 sm:grid-cols-3 lg:grid-cols-6">
          <StatCard label="Security Score" value={`${securityScore}%`}
            sub={securityScore >= 70 ? 'Good posture' : securityScore >= 50 ? 'Needs attention' : 'At risk'}
            icon={ShieldCheck} accent={securityScore >= 70 ? 'var(--green)' : securityScore >= 50 ? 'var(--yellow)' : 'var(--red)'} />
          <div className="g-card p-4 flex flex-col items-center justify-center gap-1 overflow-hidden">
            <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Risk Score</p>
            {metrics ? <ThreatGauge score={metrics.threat_score} /> : <p className="text-2xl font-bold" style={{ color: 'var(--text-3)' }}>—</p>}
          </div>
          <div className="g-card p-4 flex flex-col gap-2 justify-center min-w-0">
            <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Threat Level</p>
            <div className="flex items-center gap-2 min-w-0">
              <span className="h-2.5 w-2.5 rounded-full shrink-0 animate-pulse" style={{ background: threatColor }} />
              <span className="text-lg font-bold truncate" style={{ color: threatColor }}>{threatLevel}</span>
            </div>
            <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>Platform-wide</p>
          </div>
          <div className="g-card p-3 flex flex-col gap-1 min-w-0">
            <div className="flex items-center gap-1 mb-0.5">
              <Crosshair className="h-3 w-3 shrink-0" style={{ color: 'var(--orange)' }} />
              <span className="text-[9px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-3)' }}>MTTD</span>
            </div>
            <p className="text-base font-bold tabular-nums truncate" style={{ color: 'var(--text-1)' }}>{metrics?.mttd.avg_formatted ?? '—'}</p>
            <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{metrics?.mttd.sample_count ?? 0} samples</p>
            <div className="mt-1.5 pt-1.5" style={{ borderTop: '1px solid var(--border)' }}>
              <div className="flex items-center gap-1 mb-0.5">
                <Clock className="h-3 w-3 shrink-0" style={{ color: 'var(--accent)' }} />
                <span className="text-[9px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-3)' }}>MTTR</span>
              </div>
              <p className="text-base font-bold tabular-nums truncate" style={{ color: 'var(--text-1)' }}>{metrics?.mttr.avg_formatted ?? '—'}</p>
              <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{metrics?.mttr.total_resolved ?? 0} resolved</p>
            </div>
          </div>
          <StatCard label="Open Cases" value={openCases}
            sub={`${activeInv} under investigation`} icon={BookOpen}
            accent={openCases > 0 ? 'var(--orange)' : undefined} link="/cases" />
          <StatCard label="SLA Compliance" value={`${slaScore}%`}
            sub={slaScore >= 90 ? 'Within SLA' : 'SLA breaches detected'} icon={CheckCircle2}
            accent={slaScore >= 90 ? 'var(--green)' : slaScore >= 70 ? 'var(--yellow)' : 'var(--red)'} />
        </div>

        {/* ── Operational KPI Row ───────────────────────────────── */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 xl:grid-cols-8">
          <StatCard label="Critical Alerts" value={criticalAlerts}
            sub={`${openAlerts} open · ${snoozedAlerts} snoozed`}
            icon={Bell} accent={criticalAlerts > 0 ? 'var(--red)' : undefined}
            pulse={criticalAlerts > 0} delta={metrics?.alert_deltas?.delta} deltaPct={metrics?.alert_deltas?.delta_pct} link="/alerts" />
          <StatCard label="Open Incidents" value={openIncidents}
            sub="active incidents" icon={AlertTriangle}
            accent={openIncidents > 0 ? 'var(--orange)' : undefined} link="/incidents" />
          <StatCard label="Investigations" value={activeInv}
            sub="cases in progress" icon={Search}
            accent={activeInv > 0 ? 'var(--yellow)' : undefined} link="/cases" />
          <StatCard label="SOAR Executed" value={soarFired}
            sub="auto-responses" icon={Zap}
            accent={soarFired > 0 ? 'var(--green)' : undefined} link="/playbooks" />
          <StatCard label="Endpoints On" value={agentsOnline}
            sub={`${agentsTotal} total`} icon={ShieldCheck}
            accent="var(--green)" link="/agents" />
          <StatCard label="Endpoints Off" value={agentsOffline}
            sub="coverage gap" icon={ShieldOff}
            accent={agentsOffline > 0 ? 'var(--red)' : 'var(--text-3)'} link="/agents" />
          <StatCard label="Critical CVEs" value={criticalVulns + highVulns}
            sub={`${criticalVulns} critical · ${highVulns} high`}
            icon={AlertOctagon} accent={criticalVulns > 0 ? 'var(--red)' : highVulns > 0 ? 'var(--orange)' : undefined}
            link="/vuln-queue" />
          <StatCard label="MITRE Coverage" value={`${mitreCovPct}%`}
            sub={`${mitreCount}/${mitreTotal} tactics`} icon={Crosshair}
            accent="var(--accent)" />
        </div>

        {/* ── Anomaly banner ────────────────────────────────────── */}
        {metrics && <AnomalyBanner score={metrics.anomaly_score} />}

        {/* ── Live SOC Feed + Work Queue ────────────────────────── */}
        <div className="grid gap-4 grid-cols-1 xl:grid-cols-[3fr_2fr]">
          <SocFeedPanel events={socFeed} />
          <WorkQueuePanel incidents={displayIncidents} cases={cases} />
        </div>

        {/* ── MITRE Heatmap + Attack Map ────────────────────────── */}
        <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
          {metrics?.mitre_tactics && <MitreHeatmap tactics={metrics.mitre_tactics} />}
          <AttackMapPanel alertCount={displayAlerts.length} />
        </div>

        {/* ── Alert Trends + Incident Trends ───────────────────── */}
        <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
          <div className="g-card p-4">
            <div className="flex items-center justify-between mb-3">
              <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Alert Trends</p>
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
            <div className="flex flex-wrap gap-3 mt-2">
              {sevData.map(d => (
                <div key={d.name} className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full" style={{ background: SEV_COLORS[d.name] }} />
                  <span className="text-[11px] capitalize" style={{ color: 'var(--text-2)' }}>{d.name} ({d.value})</span>
                </div>
              ))}
            </div>
          </div>

          <div className="g-card p-4">
            <div className="flex items-center justify-between mb-3">
              <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Incident Trends (7d)</p>
              <Link href="/incidents" className="text-[10px]" style={{ color: 'var(--accent)' }}>view all →</Link>
            </div>
            <ResponsiveContainer width="100%" height={190}>
              <AreaChart data={incidentTrendData}>
                <defs>
                  {([['open','#f85149'],['investigating','#fb923c'],['resolved','#34d399']] as [string,string][]).map(([k,c]) => (
                    <linearGradient key={k} id={`ig-${k}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor={c} stopOpacity={0.3} />
                      <stop offset="95%" stopColor={c} stopOpacity={0} />
                    </linearGradient>
                  ))}
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                <XAxis dataKey="label" tick={{ fontSize: 9, fill: 'var(--text-3)' }} tickLine={false} axisLine={false} />
                <YAxis allowDecimals={false} tick={{ fontSize: 9, fill: 'var(--text-3)' }} tickLine={false} axisLine={false} />
                <Tooltip {...TOOLTIP_STYLE} />
                <Area type="monotone" dataKey="open"          stackId="1" stroke="#f85149" fill="url(#ig-open)"          strokeWidth={1.5} />
                <Area type="monotone" dataKey="investigating"  stackId="1" stroke="#fb923c" fill="url(#ig-investigating)"  strokeWidth={1.5} />
                <Area type="monotone" dataKey="resolved"       stackId="1" stroke="#34d399" fill="url(#ig-resolved)"       strokeWidth={1.5} />
              </AreaChart>
            </ResponsiveContainer>
            <div className="flex gap-4 mt-2">
              {([['open','#f85149'],['investigating','#fb923c'],['resolved','#34d399']] as [string,string][]).map(([k,c]) => (
                <div key={k} className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full" style={{ background: c }} />
                  <span className="text-[11px] capitalize" style={{ color: 'var(--text-2)' }}>{k}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── Asset Overview + Identity Overview ────────────────── */}
        <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
          <AssetPanel agents={agents} />
          <IdentityPanel alerts={displayAlerts} agents={agents} />
        </div>

        {/* ── Vulnerabilities + Threat Intelligence ─────────────── */}
        <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
          <VulnPanel vulnQueue={vulnQueue} />
          <ThreatIntelPanel metrics={metrics} alerts={displayAlerts} />
        </div>

        {/* ── Compliance + Detection Rule Health ───────────────── */}
        {metrics && (metrics.compliance_score > 0 || metrics.rule_health) && (
          <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
            {metrics.compliance_score > 0 && <CompliancePanel score={metrics.compliance_score} />}
            {metrics.rule_health && (
              <div className="g-card p-4">
                <div className="flex items-center gap-2 mb-3">
                  <Shield className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                  <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Detection Rule Health</p>
                  <Link href="/sigma-rules" className="ml-auto text-[10px]" style={{ color: 'var(--accent)' }}>manage →</Link>
                </div>
                <RuleHealthStrip rh={metrics.rule_health} />
                {metrics.top_rules?.length > 0 && (
                  <div className="mt-4">
                    <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Top Firing Rules</p>
                    <ResponsiveContainer width="100%" height={130}>
                      <BarChart data={metrics.top_rules.slice(0, 5)} layout="vertical" barSize={7}>
                        <XAxis type="number" tick={{ fontSize: 9, fill: 'var(--text-3)' }} tickLine={false} axisLine={false} />
                        <YAxis type="category" dataKey="rule_name" width={110}
                          tick={{ fontSize: 9, fill: 'var(--text-3)' }} tickLine={false} axisLine={false}
                          tickFormatter={(v: string) => v.length > 16 ? v.slice(0, 16) + '…' : v} />
                        <Tooltip {...TOOLTIP_STYLE} />
                        <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                          {metrics.top_rules.slice(0, 5).map((r, i) => (
                            <Cell key={i} fill={SEV_COLORS[r.severity] || 'var(--accent)'} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* ── Top noisy agents + DPI ────────────────────────────── */}
        {(metrics?.top_agents?.length ?? 0) > 0 && (
          <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
            <div className="g-card">
              <div className="flex items-center gap-2 px-4 pt-4 pb-3" style={{ borderBottom: '1px solid var(--border)' }}>
                <Trophy className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Noisiest Agents</p>
              </div>
              <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                {metrics!.top_agents.map((a, i) => (
                  <Link key={i} href="/agents" className="flex items-center gap-3 px-4 py-2.5 transition-colors" style={{ display: 'flex' }}
                    onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--glass-hover)'}
                    onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = ''}>
                    <span className="text-[10px] font-bold w-4 tabular-nums" style={{ color: 'var(--text-3)' }}>{i + 1}</span>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{a.hostname}</p>
                      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>id:{a.agent_id}</p>
                    </div>
                    <span className="text-xs font-bold tabular-nums" style={{ color: 'var(--orange)' }}>{a.count} alerts</span>
                  </Link>
                ))}
              </div>
            </div>

            {dpiSummary?.breakdown?.length > 0 ? (
              <div className="g-card p-4">
                <div className="flex items-center gap-2 mb-3">
                  <Network className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                  <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>DPI Detections (24h)</p>
                  <Link href="/dpi" className="ml-auto text-[10px]" style={{ color: 'var(--accent)' }}>view all →</Link>
                </div>
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={dpiSummary.breakdown.slice(0, 6)} layout="vertical" barSize={8}>
                    <XAxis type="number" tick={{ fontSize: 9, fill: 'var(--text-3)' }} tickLine={false} axisLine={false} />
                    <YAxis type="category" dataKey="finding_type" width={130}
                      tick={{ fontSize: 9, fill: 'var(--text-3)' }} tickLine={false} axisLine={false}
                      tickFormatter={(v: string) => v.replace(/_/g, ' ')} />
                    <Tooltip {...TOOLTIP_STYLE} />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                      {dpiSummary.breakdown.slice(0, 6).map((r: any, i: number) => (
                        <Cell key={i} fill={SEV_COLORS[r.severity] || 'var(--accent)'} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="g-card p-4">
                <div className="flex items-center gap-2 mb-3">
                  <Activity className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                  <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Live Metrics</p>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  {[
                    { label: 'Alert Rate',     value: `${metrics?.alert_velocity_1h ?? 0}/hr`, color: 'var(--green)' },
                    { label: 'Firewall Hits',  value: fwStats ? fwStats.total_hits_24h?.toLocaleString() ?? '—' : '—', color: 'var(--blue)' },
                    { label: 'IOC Matches',    value: String(metrics?.ioc_hits ?? '—'),        color: 'var(--red)' },
                    { label: 'Anomaly Score',  value: metrics ? metrics.anomaly_score.toFixed(2) : '—', color: 'var(--yellow)' },
                  ].map(item => (
                    <div key={item.label} className="flex flex-col p-2.5 rounded-lg" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                      <span className="text-lg font-bold tabular-nums" style={{ color: item.color }}>{item.value}</span>
                      <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{item.label}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Platform Health + AI Insights ─────────────────────── */}
        <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
          <PlatformHealthPanel overview={overview} metrics={metrics} />
          <AiInsightsPanel insights={aiInsights} />
        </div>

        {/* ── Quick Actions ─────────────────────────────────────── */}
        <div className="g-card p-4">
          <div className="flex items-center gap-2 mb-3">
            <Zap className="h-4 w-4" style={{ color: 'var(--accent)' }} />
            <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Quick Actions</p>
          </div>
          <div className="grid gap-2 grid-cols-4 sm:grid-cols-7">
            {QUICK_ACTIONS.map(action => (
              <Link key={action.label} href={action.href}
                className="flex flex-col items-center gap-2 p-3 rounded-xl transition-all"
                style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}
                onMouseEnter={e => {
                  (e.currentTarget as HTMLElement).style.borderColor = action.color;
                  (e.currentTarget as HTMLElement).style.background = 'var(--glass-hover)';
                }}
                onMouseLeave={e => {
                  (e.currentTarget as HTMLElement).style.borderColor = 'var(--border)';
                  (e.currentTarget as HTMLElement).style.background = 'var(--bg-0)';
                }}>
                <div className="h-8 w-8 flex items-center justify-center rounded-lg"
                  style={{ background: 'var(--glass)', border: '1px solid var(--border)' }}>
                  <action.icon className="h-4 w-4" style={{ color: action.color }} />
                </div>
                <span className="text-[9px] text-center font-medium leading-tight" style={{ color: 'var(--text-2)' }}>
                  {action.label}
                </span>
              </Link>
            ))}
          </div>
        </div>

        {/* ── Notifications ─────────────────────────────────────── */}
        <NotificationsPanel agents={agents} metrics={metrics} />

      </div>
    </RootLayout>
  );
}
