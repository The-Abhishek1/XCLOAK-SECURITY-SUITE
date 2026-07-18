'use client';

import { useState, useEffect, useCallback, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { riskPostureAPI } from '@/lib/api';
import { sevClass } from '@/lib/utils';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell, Legend,
} from 'recharts';
import { Activity, BarChart2, Bug, Building2, CheckCircle, ChevronRight, Cloud, Database, Flame, Globe, Layers, Network, Package, RefreshCw, Server, Shield, ShieldAlert, Target, TrendingDown, TrendingUp, UserX, Users, Wifi, Wrench, Lock } from '@/lib/icon-stubs';

// ── Types ───────────────────────────────────────────────────────────────────
interface AssetRisk {
  asset_id:    number;
  hostname:    string;
  score:       number;
  top_reason:  string;
  criticality: string;
  os?:         string;
}
interface ExposedHost {
  hostname:   string;
  ip:         string;
  open_ports: number[];
  services:   string[];
}
interface Misconfiguration {
  id:       number;
  title:    string;
  severity: string;
  asset:    string;
  category: string;
}
interface UserRisk {
  username:      string;
  risk_score:    number;
  flags:         string[];
  failed_logins: number;
  off_hours:     number;
  last_seen_ip:  string;
}
interface DeptRisk {
  name:       string;
  score:      number;
  users:      number;
  assets:     number;
  top_issue:  string;
}
interface HighRiskIdentity {
  identity:        string;
  identity_type:   string;
  finding_type:    string;
  severity:        string;
  mitre_technique: string;
  description:     string;
}
interface HighRiskApp {
  name:    string;
  version: string;
  risk:    string;
  reason:  string;
  assets:  number;
}
interface TrendPoint {
  date:        string;
  score:       number;
  vuln_score:  number;
  ueba_score:  number;
  alert_score: number;
  ioc_score:   number;
}
interface RiskSnapshot {
  score:                number;
  vuln_score:           number;
  ueba_score:           number;
  alert_score:          number;
  ioc_score:            number;
  snoozed_alert_count?: number;
  snapshot_at?:         string;
  asset_scores:         AssetRisk[];
  internet_exposure:    { exposed_count: number; exposed_hosts: ExposedHost[] };
  missing_patches:      { critical: number; high: number; medium: number; total: number; overdue: number };
  unsupported_os:       Array<{ hostname: string; os: string; eol: string; agent_id: number | null }>;
  misconfigurations:    Misconfiguration[];
  user_risk:            UserRisk[];
  department_risk:      DeptRisk[];
  high_risk_identities: HighRiskIdentity[];
  high_risk_apps:       HighRiskApp[];
  trend:                TrendPoint[];
}

// ── Helpers ─────────────────────────────────────────────────────────────────
function riskColor(score: number) {
  if (score >= 70) return '#f85149';
  if (score >= 45) return '#fb923c';
  if (score >= 25) return '#fbbf24';
  return '#22c55e';
}
function riskLabel(score: number) {
  if (score >= 70) return 'Critical';
  if (score >= 45) return 'High';
  if (score >= 25) return 'Medium';
  return 'Low';
}
function secLabel(sec: number) {
  if (sec >= 80) return 'Good';
  if (sec >= 60) return 'Fair';
  if (sec >= 40) return 'Poor';
  return 'Critical';
}
function sevColor(sev: string) {
  const m: Record<string, string> = { critical: '#f85149', high: '#fb923c', medium: '#fbbf24', low: '#38bdf8' };
  return m[sev.toLowerCase()] ?? 'var(--text-3)';
}
function heatmapColor(count: number) {
  if (count === 0)  return 'var(--bg-1)';
  if (count <= 2)   return 'rgba(251,191,36,0.25)';
  if (count <= 5)   return 'rgba(251,146,60,0.35)';
  if (count <= 10)  return 'rgba(248,81,73,0.45)';
  return 'rgba(248,81,73,0.75)';
}
function heatmapText(count: number) {
  if (count === 0)  return 'var(--text-3)';
  if (count <= 2)   return '#fbbf24';
  if (count <= 5)   return '#fb923c';
  return '#f85149';
}

// ── Custom tooltip ────────────────────────────────────────────────────────────
function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-xl p-3 text-xs space-y-1"
      style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', minWidth: 160 }}>
      <p className="font-bold mb-1" style={{ color: 'var(--text-1)' }}>{label}</p>
      {payload.map((p: any) => (
        <div key={p.dataKey} className="flex justify-between gap-3">
          <span style={{ color: p.color }}>{p.name}</span>
          <span className="font-mono" style={{ color: 'var(--text-1)' }}>{p.value}</span>
        </div>
      ))}
    </div>
  );
}

// ── Mini sparkline ────────────────────────────────────────────────────────────
function Sparkline({ data, color }: { data: number[]; color: string }) {
  if (data.length < 2) return null;
  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;
  const w = 80; const h = 32;
  const pts = data.map((v, i) => `${(i / (data.length - 1)) * w},${h - ((v - min) / range) * h}`).join(' ');
  return (
    <svg width={w} height={h} style={{ overflow: 'visible' }}>
      <polyline points={pts} fill="none" stroke={color} strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// ── Score ring (compact) ──────────────────────────────────────────────────────
function ScoreRing({ score, color, size = 64, strokeW = 7 }: { score: number; color: string; size?: number; strokeW?: number }) {
  const r    = (size - strokeW * 2) / 2;
  const circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;
  const c    = size / 2;
  return (
    <svg width={size} height={size} className="rotate-[-90deg]">
      <circle cx={c} cy={c} r={r} fill="none" strokeWidth={strokeW} stroke="var(--bg-1)" />
      <circle cx={c} cy={c} r={r} fill="none" strokeWidth={strokeW} stroke={color}
        strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
        style={{ transition: 'stroke-dasharray 0.8s ease' }} />
    </svg>
  );
}

// ── KPI card ─────────────────────────────────────────────────────────────────
function KpiCard({ label, value, sub, color, icon: Icon, trend, sparkData }: {
  label: string; value: string | number; sub?: string; color: string;
  icon: any; trend?: number | null; sparkData?: number[];
}) {
  return (
    <div className="g-card p-5 flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-xl" style={{ background: `${color}18` }}>
            <Icon className="h-4 w-4" style={{ color }} />
          </div>
          <span className="text-[11px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>{label}</span>
        </div>
        {sparkData && <Sparkline data={sparkData} color={color} />}
      </div>
      <div>
        <p className="text-4xl font-black tabular-nums leading-none" style={{ color }}>{value}</p>
        {sub && <p className="text-[11px] mt-1" style={{ color: 'var(--text-3)' }}>{sub}</p>}
      </div>
      {trend !== null && trend !== undefined && (
        <div className="flex items-center gap-1 text-[11px] font-semibold"
          style={{ color: trend > 0 ? '#f85149' : '#22c55e' }}>
          {trend > 0 ? <TrendingUp className="h-3.5 w-3.5" /> : <TrendingDown className="h-3.5 w-3.5" />}
          {trend > 0 ? '+' : ''}{trend} vs previous snapshot
        </div>
      )}
    </div>
  );
}

// ── Risk heatmap ──────────────────────────────────────────────────────────────
function RiskHeatmap({ data }: {
  data: Record<string, Record<string, number>>;
}) {
  const domains = Object.keys(data);
  const levels  = ['critical', 'high', 'medium', 'low'];
  return (
    <div>
      <div className="grid gap-1" style={{ gridTemplateColumns: '90px 1fr 1fr 1fr 1fr' }}>
        <div />
        {levels.map(l => (
          <div key={l} className="text-[9px] font-bold uppercase tracking-widest text-center pb-1 capitalize"
            style={{ color: sevColor(l) }}>{l}</div>
        ))}
        {domains.map(domain => (
          <>
            <div key={domain + '-label'} className="text-[10px] font-semibold capitalize flex items-center pr-2"
              style={{ color: 'var(--text-2)' }}>{domain}</div>
            {levels.map(level => {
              const count = data[domain]?.[level] ?? 0;
              return (
                <div key={domain + level} className="rounded-lg flex items-center justify-center py-3 text-[11px] font-bold tabular-nums"
                  style={{ background: heatmapColor(count), color: heatmapText(count), border: '1px solid var(--border)' }}>
                  {count || '—'}
                </div>
              );
            })}
          </>
        ))}
      </div>
    </div>
  );
}

// ── Domain card ───────────────────────────────────────────────────────────────
function DomainCard({ icon: Icon, label, score, items, color }: {
  icon: any; label: string; score: number; color: string;
  items: { text: string; value: string | number; bad?: boolean }[];
}) {
  const rc = riskColor(score);
  return (
    <div className="g-card p-4 flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-xl" style={{ background: `${color}18` }}>
            <Icon className="h-4 w-4" style={{ color }} />
          </div>
          <span className="text-xs font-bold" style={{ color: 'var(--text-1)' }}>{label}</span>
        </div>
        <div className="relative" style={{ width: 48, height: 48 }}>
          <ScoreRing score={score} color={rc} size={48} strokeW={5} />
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-[11px] font-black" style={{ color: rc }}>{score}</span>
          </div>
        </div>
      </div>
      <div className="space-y-2">
        {items.map(({ text, value, bad }) => (
          <div key={text} className="flex items-center justify-between">
            <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{text}</span>
            <span className="text-[10px] font-bold tabular-nums" style={{ color: bad ? '#f85149' : 'var(--text-2)' }}>{value}</span>
          </div>
        ))}
      </div>
      <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--bg-1)' }}>
        <div className="h-full rounded-full transition-all" style={{ width: `${score}%`, background: rc }} />
      </div>
    </div>
  );
}

// ── Compliance framework row ──────────────────────────────────────────────────
function ComplianceRow({ name, score, controls, color }: { name: string; score: number; controls: string; color: string }) {
  return (
    <div className="flex items-center gap-3">
      <span className="text-[10px] font-mono font-bold w-24 shrink-0" style={{ color: 'var(--text-2)' }}>{name}</span>
      <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: 'var(--bg-1)' }}>
        <div className="h-full rounded-full transition-all" style={{ width: `${score}%`, background: color }} />
      </div>
      <span className="text-[10px] font-bold tabular-nums w-8 text-right" style={{ color }}>{score}%</span>
      <span className="text-[9px] w-24 shrink-0" style={{ color: 'var(--text-3)' }}>{controls}</span>
    </div>
  );
}

// ── Remediation item ──────────────────────────────────────────────────────────
function RemItem({ rank, action, effort, impact, type, status }: {
  rank: number; action: string; effort: string; impact: string; type: string; status: 'open' | 'in_progress' | 'blocked';
}) {
  const statusColor = status === 'open' ? 'var(--text-3)' : status === 'in_progress' ? 'var(--accent)' : '#f85149';
  const statusLabel = status === 'open' ? 'Open' : status === 'in_progress' ? 'In Progress' : 'Blocked';
  const typeColor = type === 'patch' ? '#fb923c' : type === 'config' ? '#a855f7' : type === 'identity' ? '#e879f9' : '#38bdf8';
  return (
    <div className="flex items-start gap-3 px-4 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
      <div className="w-6 h-6 rounded-full flex items-center justify-center shrink-0 mt-0.5"
        style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>
        <span className="text-[9px] font-bold" style={{ color: 'var(--text-3)' }}>{rank}</span>
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium leading-snug" style={{ color: 'var(--text-1)' }}>{action}</p>
        <div className="flex items-center gap-3 mt-1 flex-wrap">
          <span className="text-[9px] px-1.5 py-0.5 rounded capitalize"
            style={{ background: `${typeColor}18`, color: typeColor }}>{type}</span>
          <span className="text-[9px]" style={{ color: 'var(--text-3)' }}>Effort: {effort}</span>
          <span className="text-[9px]" style={{ color: 'var(--green)' }}>Impact: {impact}</span>
        </div>
      </div>
      <span className="text-[9px] font-semibold shrink-0" style={{ color: statusColor }}>{statusLabel}</span>
    </div>
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────
export default function RiskPosturePage() {
  const [snap,       setSnap]       = useState<RiskSnapshot | null>(null);
  const [loading,    setLoading]    = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try { const r = await riskPostureAPI.get(); setSnap(r.data); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const doRefresh = async () => {
    setRefreshing(true);
    try {
      const r = await riskPostureAPI.refresh();
      if (r.data) setSnap(r.data); else await load();
    } finally { setRefreshing(false); }
  };

  // ── Derived metrics ─────────────────────────────────────────────────────────
  const trend      = snap?.trend ?? [];
  const prevScore  = trend.length >= 2 ? trend[trend.length - 2].score : null;
  const delta      = snap && prevScore !== null ? snap.score - prevScore : null;
  const secScore   = snap ? Math.max(0, 100 - snap.score) : 0;
  const trendSpark = trend.slice(-10).map(t => t.score);

  const compliance = useMemo(() => {
    if (!snap) return 0;
    const critC = snap.misconfigurations?.filter(m => m.severity === 'critical').length ?? 0;
    const highC = snap.misconfigurations?.filter(m => m.severity === 'high').length ?? 0;
    const medC  = snap.misconfigurations?.filter(m => m.severity === 'medium').length ?? 0;
    return Math.max(0, Math.min(100, Math.round(100 - critC * 9 - highC * 4 - medC * 1.5)));
  }, [snap]);

  const frameworks = useMemo(() => {
    const base = compliance;
    return [
      { name: 'CIS Level 1',  score: Math.min(100, base + 3),        controls: '153 controls', color: '#38bdf8' },
      { name: 'NIST CSF',     score: Math.min(100, Math.round(base * 0.97)), controls: '108 outcomes', color: '#a855f7' },
      { name: 'ISO 27001',    score: Math.min(100, Math.round(base * 0.94)), controls: '93 controls',  color: '#22c55e' },
      { name: 'SOC 2 Type II',score: Math.min(100, Math.round(base * 0.91)), controls: '64 criteria',  color: '#fb923c' },
    ];
  }, [compliance]);

  const heatmapData = useMemo(() => {
    if (!snap) return {} as Record<string, Record<string, number>>;
    const assetsByLevel: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    snap.asset_scores?.forEach(a => {
      const l = a.score >= 70 ? 'critical' : a.score >= 45 ? 'high' : a.score >= 25 ? 'medium' : 'low';
      assetsByLevel[l]++;
    });
    const identityBySev: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    snap.high_risk_identities?.forEach(i => { if (identityBySev[i.severity] !== undefined) identityBySev[i.severity]++; });
    snap.user_risk?.filter(u => u.risk_score >= 70).forEach(() => identityBySev['high']++);
    const networkBySev: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    const exp = snap.internet_exposure?.exposed_count ?? 0;
    if (exp > 0) networkBySev['high'] += exp;
    snap.misconfigurations?.filter(m => m.category === 'network').forEach(m => {
      if (networkBySev[m.severity] !== undefined) networkBySev[m.severity]++;
    });
    const cloudBySev: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    snap.misconfigurations?.filter(m => m.category === 'cloud').forEach(m => {
      if (cloudBySev[m.severity] !== undefined) cloudBySev[m.severity]++;
    });
    const appBySev: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    snap.high_risk_apps?.forEach(a => { if (appBySev[a.risk] !== undefined) appBySev[a.risk]++; });
    return { assets: assetsByLevel, identity: identityBySev, network: networkBySev, cloud: cloudBySev, apps: appBySev };
  }, [snap]);

  const topRisks = useMemo(() => {
    if (!snap) return [];
    const risks: { label: string; detail: string; sev: string; category: string }[] = [];
    snap.asset_scores?.filter(a => a.score >= 70).slice(0, 3).forEach(a =>
      risks.push({ label: `Critical asset: ${a.hostname}`, detail: a.top_reason, sev: 'critical', category: 'Asset' }));
    snap.high_risk_identities?.filter(i => i.severity === 'critical').slice(0, 2).forEach(i =>
      risks.push({ label: i.identity, detail: i.description, sev: 'critical', category: 'Identity' }));
    if ((snap.missing_patches?.critical ?? 0) > 0)
      risks.push({ label: `${snap.missing_patches.critical} critical patches missing`, detail: `${snap.missing_patches.overdue ?? 0} overdue`, sev: 'critical', category: 'Vuln' });
    snap.misconfigurations?.filter(m => m.severity === 'critical').slice(0, 2).forEach(m =>
      risks.push({ label: m.title, detail: m.asset, sev: 'critical', category: 'Config' }));
    snap.asset_scores?.filter(a => a.score >= 45 && a.score < 70).slice(0, 3).forEach(a =>
      risks.push({ label: `High-risk asset: ${a.hostname}`, detail: a.top_reason, sev: 'high', category: 'Asset' }));
    snap.high_risk_identities?.filter(i => i.severity === 'high').slice(0, 2).forEach(i =>
      risks.push({ label: i.identity, detail: i.description, sev: 'high', category: 'Identity' }));
    if ((snap.internet_exposure?.exposed_count ?? 0) > 0)
      risks.push({ label: `${snap.internet_exposure.exposed_count} internet-facing hosts`, detail: 'Direct attack surface', sev: 'high', category: 'Network' });
    const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    return risks.sort((a, b) => (order[a.sev] ?? 4) - (order[b.sev] ?? 4)).slice(0, 10);
  }, [snap]);

  const domainScores = useMemo(() => {
    if (!snap) return [];
    const critAssets = snap.asset_scores?.filter(a => a.score >= 70).length ?? 0;
    const highUsers  = snap.user_risk?.filter(u => u.risk_score >= 70).length ?? 0;
    const assetScore = Math.min(100, Math.round(((snap.vuln_score / 40) * 60) + ((snap.asset_scores?.length ? critAssets / snap.asset_scores.length : 0) * 40)));
    const identScore = Math.min(100, Math.round(snap.ueba_score * 3.5 + (snap.high_risk_identities?.filter(i => i.severity === 'critical').length ?? 0) * 8));
    const netScore   = Math.min(100, Math.round((snap.internet_exposure?.exposed_count ?? 0) * 15 + (snap.misconfigurations?.filter(m => m.category === 'network').length ?? 0) * 5));
    const cloudScore = Math.min(100, Math.round((snap.misconfigurations?.filter(m => m.category === 'cloud').length ?? 0) * 8 + snap.ioc_score * 2.5));
    return [
      {
        icon: Server, label: 'Assets', score: assetScore, color: '#fb923c',
        items: [
          { text: 'Total monitored',   value: snap.asset_scores?.length ?? 0 },
          { text: 'Critical risk',     value: critAssets, bad: critAssets > 0 },
          { text: 'Missing patches',   value: snap.missing_patches?.total ?? 0, bad: (snap.missing_patches?.critical ?? 0) > 0 },
          { text: 'Unsupported OS',    value: snap.unsupported_os?.length ?? 0, bad: (snap.unsupported_os?.length ?? 0) > 0 },
        ],
      },
      {
        icon: Users, label: 'Identities', score: identScore, color: '#a855f7',
        items: [
          { text: 'Users monitored',   value: snap.user_risk?.length ?? 0 },
          { text: 'High-risk users',   value: highUsers, bad: highUsers > 0 },
          { text: 'High-risk identities', value: snap.high_risk_identities?.length ?? 0, bad: (snap.high_risk_identities?.length ?? 0) > 0 },
          { text: 'Departments at risk', value: snap.department_risk?.filter(d => d.score >= 45).length ?? 0 },
        ],
      },
      {
        icon: Network, label: 'Network', score: netScore, color: '#38bdf8',
        items: [
          { text: 'Internet-facing',   value: snap.internet_exposure?.exposed_count ?? 0, bad: (snap.internet_exposure?.exposed_count ?? 0) > 0 },
          { text: 'Network misconfigs', value: snap.misconfigurations?.filter(m => m.category === 'network').length ?? 0 },
          { text: 'Open alert score',  value: `${snap.alert_score}/30` },
          { text: 'IOC matches',       value: snap.ioc_score, bad: snap.ioc_score > 5 },
        ],
      },
      {
        icon: Cloud, label: 'Cloud', score: cloudScore, color: '#2dd4bf',
        items: [
          { text: 'Cloud misconfigs',  value: snap.misconfigurations?.filter(m => m.category === 'cloud').length ?? 0 },
          { text: 'High-risk apps',    value: snap.high_risk_apps?.filter(a => a.risk === 'critical' || a.risk === 'high').length ?? 0, bad: true },
          { text: 'IOC score',         value: `${snap.ioc_score}/20` },
          { text: 'UEBA anomalies',    value: `${snap.ueba_score}/20` },
        ],
      },
    ];
  }, [snap]);

  const businessImpact = useMemo(() => {
    if (!snap) return null;
    const critAssets = snap.asset_scores?.filter(a => a.score >= 70).length ?? 0;
    const usersAffected = snap.user_risk?.length ?? 0;
    const systemsAtRisk = snap.asset_scores?.filter(a => a.score >= 45).length ?? 0;
    const financialBase = (critAssets * 2_500_000) + (systemsAtRisk * 750_000) + ((snap.missing_patches?.critical ?? 0) * 500_000);
    return { critAssets, usersAffected, systemsAtRisk, financialBase };
  }, [snap]);

  const aiRecs = useMemo(() => {
    if (!snap) return [];
    const recs: { sev: string; text: string; action: string }[] = [];
    if ((snap.missing_patches?.critical ?? 0) > 0)
      recs.push({ sev: 'critical', text: `${snap.missing_patches.critical} critical patches missing — immediate remediation required to close known exploit vectors.`, action: 'Start patching' });
    const critAssets = snap.asset_scores?.filter(a => a.score >= 70) ?? [];
    if (critAssets.length > 0)
      recs.push({ sev: 'critical', text: `${critAssets.length} asset(s) at critical risk: ${critAssets.slice(0, 2).map(a => a.hostname).join(', ')} — isolate or harden immediately.`, action: 'Harden assets' });
    if ((snap.internet_exposure?.exposed_count ?? 0) > 0)
      recs.push({ sev: 'high', text: `${snap.internet_exposure.exposed_count} internet-facing host(s) detected with ${snap.internet_exposure.exposed_hosts?.reduce((s, h) => s + (h.open_ports?.length ?? 0), 0) || 0} open ports — restrict attack surface.`, action: 'Review firewall' });
    if (snap.high_risk_identities?.filter(i => i.severity === 'critical').length)
      recs.push({ sev: 'high', text: `Critical identity risk detected — enforce MFA, rotate credentials and review privilege assignments.`, action: 'Secure identities' });
    if (compliance < 70)
      recs.push({ sev: 'medium', text: `Compliance score at ${compliance}% — resolve ${snap.misconfigurations?.filter(m => m.severity === 'critical').length ?? 0} critical misconfigurations to close the gap.`, action: 'Fix configs' });
    if (snap.unsupported_os?.length)
      recs.push({ sev: 'medium', text: `${snap.unsupported_os.length} host(s) running end-of-life OS. No security patches will be issued — upgrade or isolate.`, action: 'Upgrade OS' });
    if (recs.length === 0)
      recs.push({ sev: 'low', text: 'No critical gaps detected. Maintain scanning cadence and continue monitoring.', action: 'Keep monitoring' });
    return recs;
  }, [snap, compliance]);

  const remQueue = useMemo(() => {
    if (!snap) return [];
    const q: { rank: number; action: string; effort: string; impact: string; type: string; status: 'open' | 'in_progress' | 'blocked' }[] = [];
    snap.misconfigurations?.filter(m => m.severity === 'critical').slice(0, 2).forEach((m, i) => {
      q.push({ rank: i + 1, action: `Fix: ${m.title} on ${m.asset}`, effort: '1-2 hrs', impact: 'High — closes exploit path', type: 'config', status: 'open' });
    });
    if ((snap.missing_patches?.critical ?? 0) > 0)
      q.push({ rank: q.length + 1, action: `Apply ${snap.missing_patches.critical} critical OS patches`, effort: '2-4 hrs', impact: 'Critical — patch active exploits', type: 'patch', status: 'open' });
    if ((snap.missing_patches?.high ?? 0) > 0)
      q.push({ rank: q.length + 1, action: `Apply ${snap.missing_patches.high} high-severity patches`, effort: '4-8 hrs', impact: 'High — reduce attack surface', type: 'patch', status: 'in_progress' });
    snap.high_risk_identities?.filter(i => i.severity === 'critical').slice(0, 2).forEach((i) => {
      q.push({ rank: q.length + 1, action: `Remediate identity risk: ${i.identity}`, effort: '30 min', impact: 'High — close identity pivot', type: 'identity', status: 'open' });
    });
    if (snap.unsupported_os?.length)
      q.push({ rank: q.length + 1, action: `Upgrade ${snap.unsupported_os.length} end-of-life systems`, effort: '1-2 days', impact: 'Medium — restore patch coverage', type: 'patch', status: 'blocked' });
    snap.misconfigurations?.filter(m => m.severity === 'high').slice(0, 2).forEach((m) => {
      q.push({ rank: q.length + 1, action: `Resolve: ${m.title}`, effort: '1 hr', impact: 'Medium — improve posture', type: 'config', status: 'open' });
    });
    return q.slice(0, 10);
  }, [snap]);

  const trendData = trend.map(t => ({
    date:       t.date.slice(5),
    'Total':    t.score,
    'Vulns':    t.vuln_score,
    'Behavior': t.ueba_score,
    'Alerts':   t.alert_score,
    'IOC':      t.ioc_score,
  }));

  const vulnBarData = snap ? [
    { name: 'Critical', value: snap.missing_patches?.critical ?? 0, fill: '#f85149' },
    { name: 'High',     value: snap.missing_patches?.high ?? 0,     fill: '#fb923c' },
    { name: 'Medium',   value: snap.missing_patches?.medium ?? 0,   fill: '#fbbf24' },
    { name: 'Other',    value: Math.max(0, (snap.missing_patches?.total ?? 0) - (snap.missing_patches?.critical ?? 0) - (snap.missing_patches?.high ?? 0) - (snap.missing_patches?.medium ?? 0)), fill: '#38bdf8' },
  ] : [];

  const sevRec: Record<string, string> = { critical: '#f85149', high: '#fb923c', medium: '#fbbf24', low: '#38bdf8' };

  return (
    <RootLayout title="Risk Posture"
      subtitle="Enterprise-wide security risk — assets, identity, network, cloud, compliance"
      actions={
        <button onClick={doRefresh} disabled={refreshing}
          className="g-btn g-btn-ghost flex items-center gap-1.5 text-xs">
          <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} />
          {refreshing ? 'Computing…' : 'Refresh Score'}
        </button>
      }>

      {loading ? (
        <div className="py-24 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>
          Computing risk posture…
        </div>
      ) : !snap ? (
        <div className="py-24 text-center text-sm" style={{ color: 'var(--text-3)' }}>
          No data — click Refresh Score to compute.
        </div>
      ) : (
        <div className="space-y-5">

          {/* ── Row 1: KPI banner ────────────────────────────────────────── */}
          <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
            <KpiCard
              label="Enterprise Risk"
              value={snap.score}
              sub={riskLabel(snap.score) + ' — lower is better'}
              color={riskColor(snap.score)}
              icon={ShieldAlert}
              trend={delta}
              sparkData={trendSpark}
            />
            <KpiCard
              label="Security Score"
              value={secScore}
              sub={secLabel(secScore) + ' security posture'}
              color={secScore >= 60 ? '#22c55e' : secScore >= 40 ? '#fbbf24' : '#f85149'}
              icon={Shield}
              sparkData={trendSpark.map(s => 100 - s)}
            />
            <KpiCard
              label="Compliance"
              value={`${compliance}%`}
              sub={`${snap.misconfigurations?.filter(m => m.severity === 'critical').length ?? 0} critical gaps open`}
              color={compliance >= 80 ? '#22c55e' : compliance >= 60 ? '#fbbf24' : '#f85149'}
              icon={CheckCircle}
            />
            <KpiCard
              label="30-Day Trend"
              value={trend.length >= 2 ? (delta !== null && delta < 0 ? '↓ Improving' : delta !== null && delta > 0 ? '↑ Worsening' : '→ Stable') : '—'}
              sub={trend.length >= 2 ? `Avg ${Math.round(trend.reduce((s, t) => s + t.score, 0) / trend.length)} over ${trend.length} snapshots` : 'Not enough data'}
              color={delta !== null && delta < 0 ? '#22c55e' : delta !== null && delta > 0 ? '#f85149' : '#38bdf8'}
              icon={Activity}
              sparkData={trendSpark}
            />
          </div>

          {/* ── Row 2: Risk Heatmap + Top Risks ─────────────────────────── */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="g-card p-5">
              <div className="flex items-center gap-2 mb-4">
                <div className="p-1.5 rounded-xl" style={{ background: '#f8514918' }}>
                  <Layers className="h-4 w-4" style={{ color: '#f85149' }} />
                </div>
                <p className="text-sm font-bold" style={{ color: 'var(--text-1)' }}>Risk Heatmap</p>
                <span className="text-[10px] ml-auto" style={{ color: 'var(--text-3)' }}>Domain × Severity</span>
              </div>
              <RiskHeatmap data={heatmapData} />
            </div>

            <div className="g-card overflow-hidden">
              <div className="flex items-center gap-2 px-5 pt-5 pb-3">
                <div className="p-1.5 rounded-xl" style={{ background: '#fb923c18' }}>
                  <Target className="h-4 w-4" style={{ color: '#fb923c' }} />
                </div>
                <p className="text-sm font-bold" style={{ color: 'var(--text-1)' }}>Top Risks</p>
                <span className="text-[10px] ml-auto font-bold" style={{ color: '#fb923c' }}>{topRisks.length} findings</span>
              </div>
              <div className="overflow-y-auto" style={{ maxHeight: 280 }}>
                {topRisks.length === 0
                  ? <p className="px-5 pb-5 text-xs" style={{ color: 'var(--text-3)' }}>No high-risk findings.</p>
                  : topRisks.map((r, i) => (
                    <div key={i} className="flex items-start gap-3 px-5 py-3"
                      style={{ borderBottom: '1px solid var(--border)' }}>
                      <span className="h-1.5 w-1.5 rounded-full mt-1.5 shrink-0" style={{ background: sevRec[r.sev] || 'var(--text-3)' }} />
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium leading-tight" style={{ color: 'var(--text-1)' }}>{r.label}</p>
                        {r.detail && <p className="text-[10px] mt-0.5 truncate" style={{ color: 'var(--text-3)' }}>{r.detail}</p>}
                      </div>
                      <span className="text-[9px] px-1.5 py-0.5 rounded shrink-0"
                        style={{ background: `${sevRec[r.sev] || 'var(--text-3)'}18`, color: sevRec[r.sev] || 'var(--text-3)' }}>
                        {r.category}
                      </span>
                    </div>
                  ))
                }
              </div>
            </div>
          </div>

          {/* ── Row 3: Domain scorecards ─────────────────────────────────── */}
          <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
            {domainScores.map(d => (
              <DomainCard key={d.label} icon={d.icon} label={d.label} score={d.score} color={d.color} items={d.items} />
            ))}
          </div>

          {/* ── Row 4: Vulnerabilities + Exposure + Compliance ───────────── */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

            {/* Vulnerabilities */}
            <div className="g-card p-5">
              <div className="flex items-center gap-2 mb-4">
                <div className="p-1.5 rounded-xl" style={{ background: '#f8514918' }}>
                  <Bug className="h-4 w-4" style={{ color: '#f85149' }} />
                </div>
                <p className="text-sm font-bold" style={{ color: 'var(--text-1)' }}>Vulnerabilities</p>
                <span className="ml-auto text-lg font-black tabular-nums" style={{ color: '#f85149' }}>
                  {snap.missing_patches?.total ?? 0}
                </span>
              </div>
              <ResponsiveContainer width="100%" height={100}>
                <BarChart data={vulnBarData} barSize={24} margin={{ top: 0, right: 0, left: -28, bottom: 0 }}>
                  <XAxis dataKey="name" tick={{ fontSize: 9, fill: 'var(--text-3)' }} tickLine={false} axisLine={false} />
                  <YAxis tick={{ fontSize: 9, fill: 'var(--text-3)' }} tickLine={false} axisLine={false} />
                  <Tooltip content={<ChartTooltip />} />
                  <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                    {vulnBarData.map((d, i) => <Cell key={i} fill={d.fill} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
              <div className="space-y-2 mt-3">
                {[
                  { label: 'Overdue patches', value: snap.missing_patches?.overdue ?? 0, color: '#f85149' },
                  { label: 'High-risk apps',  value: snap.high_risk_apps?.length ?? 0, color: '#fb923c' },
                  { label: 'Unsupported OS',  value: snap.unsupported_os?.length ?? 0, color: '#fbbf24' },
                ].map(({ label, value, color }) => (
                  <div key={label} className="flex items-center justify-between text-[11px]">
                    <span style={{ color: 'var(--text-3)' }}>{label}</span>
                    <span className="font-bold tabular-nums" style={{ color: value > 0 ? color : 'var(--text-3)' }}>{value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Exposure */}
            <div className="g-card p-5">
              <div className="flex items-center gap-2 mb-4">
                <div className="p-1.5 rounded-xl" style={{ background: '#38bdf818' }}>
                  <Globe className="h-4 w-4" style={{ color: '#38bdf8' }} />
                </div>
                <p className="text-sm font-bold" style={{ color: 'var(--text-1)' }}>Exposure</p>
                <span className="ml-auto text-lg font-black tabular-nums" style={{ color: '#38bdf8' }}>
                  {snap.internet_exposure?.exposed_count ?? 0}
                </span>
              </div>
              <div className="space-y-3">
                {[
                  { label: 'Internet-facing hosts', value: snap.internet_exposure?.exposed_count ?? 0, color: '#f85149', bad: true },
                  { label: 'Open ports (total)', value: snap.internet_exposure?.exposed_hosts?.reduce((s, h) => s + (h.open_ports?.length ?? 0), 0) ?? 0, color: '#fb923c', bad: true },
                  { label: 'Exposed services', value: snap.internet_exposure?.exposed_hosts?.reduce((s, h) => s + (h.services?.length ?? 0), 0) ?? 0, color: '#fbbf24' },
                  { label: 'Network misconfigs', value: snap.misconfigurations?.filter(m => m.category === 'network').length ?? 0, color: '#a855f7' },
                ].map(({ label, value, color, bad }) => (
                  <div key={label}>
                    <div className="flex items-center justify-between text-[11px] mb-1">
                      <span style={{ color: 'var(--text-3)' }}>{label}</span>
                      <span className="font-bold tabular-nums" style={{ color: (bad && value > 0) ? color : 'var(--text-2)' }}>{value}</span>
                    </div>
                    <div className="h-1 rounded-full overflow-hidden" style={{ background: 'var(--bg-1)' }}>
                      <div className="h-full rounded-full" style={{ width: `${Math.min(100, value * 8)}%`, background: color }} />
                    </div>
                  </div>
                ))}
              </div>
              {(snap.internet_exposure?.exposed_hosts ?? []).slice(0, 2).map((h, i) => (
                <div key={i} className="flex items-center gap-2 mt-3 px-2 py-1.5 rounded-lg" style={{ background: 'var(--bg-0)' }}>
                  <Wifi className="h-3 w-3 shrink-0" style={{ color: '#fb923c' }} />
                  <span className="text-[10px] font-medium flex-1 truncate" style={{ color: 'var(--text-2)' }}>{h.hostname}</span>
                  <span className="text-[9px]" style={{ color: 'var(--text-3)' }}>{h.open_ports?.length ?? 0} ports</span>
                </div>
              ))}
            </div>

            {/* Compliance */}
            <div className="g-card p-5">
              <div className="flex items-center gap-2 mb-4">
                <div className="p-1.5 rounded-xl" style={{ background: '#22c55e18' }}>
                  <CheckCircle className="h-4 w-4" style={{ color: '#22c55e' }} />
                </div>
                <p className="text-sm font-bold" style={{ color: 'var(--text-1)' }}>Compliance</p>
                <span className="ml-auto text-lg font-black tabular-nums" style={{ color: compliance >= 80 ? '#22c55e' : compliance >= 60 ? '#fbbf24' : '#f85149' }}>
                  {compliance}%
                </span>
              </div>
              <div className="space-y-3">
                {frameworks.map(f => (
                  <ComplianceRow key={f.name} name={f.name} score={f.score} controls={f.controls} color={f.color} />
                ))}
              </div>
              <div className="mt-4 space-y-2">
                {[
                  { label: 'Open critical gaps', value: snap.misconfigurations?.filter(m => m.severity === 'critical').length ?? 0, color: '#f85149' },
                  { label: 'Open high gaps',     value: snap.misconfigurations?.filter(m => m.severity === 'high').length ?? 0,     color: '#fb923c' },
                ].map(({ label, value, color }) => (
                  <div key={label} className="flex items-center justify-between text-[11px]">
                    <span style={{ color: 'var(--text-3)' }}>{label}</span>
                    <span className="font-bold tabular-nums" style={{ color: value > 0 ? color : 'var(--green)' }}>{value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* ── Row 5: Business Impact + AI Recommendations ───────────────── */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

            {/* Business Impact */}
            <div className="g-card p-5">
              <div className="flex items-center gap-2 mb-4">
                <div className="p-1.5 rounded-xl" style={{ background: '#f8514918' }}>
                  <Database className="h-4 w-4" style={{ color: '#f85149' }} />
                </div>
                <p className="text-sm font-bold" style={{ color: 'var(--text-1)' }}>Business Impact</p>
              </div>
              {businessImpact && (
                <>
                  <div className="grid grid-cols-2 gap-3 mb-4">
                    {[
                      { label: 'Users Affected',    value: businessImpact.usersAffected, color: '#a855f7', icon: Users },
                      { label: 'Systems at Risk',   value: businessImpact.systemsAtRisk,  color: '#fb923c', icon: Server },
                      { label: 'Critical Assets',   value: businessImpact.critAssets,     color: '#f85149', icon: ShieldAlert },
                      { label: 'Departments',       value: snap.department_risk?.filter(d => d.score >= 45).length ?? 0, color: '#38bdf8', icon: Building2 },
                    ].map(({ label, value, color, icon: Icon }) => (
                      <div key={label} className="rounded-xl p-3 text-center" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                        <Icon className="h-4 w-4 mx-auto mb-1" style={{ color }} />
                        <p className="text-2xl font-black tabular-nums" style={{ color }}>{value}</p>
                        <p className="text-[9px] mt-0.5" style={{ color: 'var(--text-3)' }}>{label}</p>
                      </div>
                    ))}
                  </div>
                  <div className="rounded-xl p-4" style={{ background: '#f8514911', border: '1px solid #f8514933' }}>
                    <p className="text-[10px] font-bold uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>
                      Estimated Financial Exposure
                    </p>
                    <p className="text-3xl font-black" style={{ color: '#f85149' }}>
                      ₹{businessImpact.financialBase >= 10_000_000
                        ? `${(businessImpact.financialBase / 10_000_000).toFixed(1)}Cr`
                        : businessImpact.financialBase >= 100_000
                          ? `${(businessImpact.financialBase / 100_000).toFixed(1)}L`
                          : businessImpact.financialBase.toLocaleString()}
                    </p>
                    <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                      Worst-case estimate based on asset criticality and risk score
                    </p>
                  </div>
                </>
              )}
            </div>

            {/* AI Recommendations */}
            <div className="g-card p-5">
              <div className="flex items-center gap-2 mb-4">
                <div className="p-1.5 rounded-xl" style={{ background: 'var(--accent-glow)' }}>
                  <Flame className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                </div>
                <p className="text-sm font-bold" style={{ color: 'var(--text-1)' }}>AI Recommendations</p>
                <span className="text-[10px] ml-auto" style={{ color: 'var(--accent)' }}>XCloak AI</span>
              </div>
              <div className="space-y-2.5">
                {aiRecs.map((r, i) => (
                  <div key={i} className="rounded-xl p-3"
                    style={{ background: `${sevRec[r.sev] || 'var(--text-3)'}0d`, border: `1px solid ${sevRec[r.sev] || 'var(--border)'}33` }}>
                    <div className="flex items-center gap-2 mb-1.5">
                      <span className="h-1.5 w-1.5 rounded-full shrink-0" style={{ background: sevRec[r.sev] || 'var(--text-3)' }} />
                      <span className="text-[10px] font-bold uppercase tracking-wider" style={{ color: sevRec[r.sev] || 'var(--text-3)' }}>{r.sev}</span>
                      <button className="ml-auto flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-lg"
                        style={{ background: 'var(--glass-bg)', color: 'var(--text-3)' }}>
                        {r.action} <ChevronRight className="h-2.5 w-2.5" />
                      </button>
                    </div>
                    <p className="text-[11px] leading-relaxed" style={{ color: 'var(--text-1)' }}>{r.text}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* ── Row 6: Remediation Queue ─────────────────────────────────── */}
          <div className="g-card overflow-hidden">
            <div className="flex items-center gap-2 px-5 pt-5 pb-3">
              <div className="p-1.5 rounded-xl" style={{ background: '#22c55e18' }}>
                <Wrench className="h-4 w-4" style={{ color: '#22c55e' }} />
              </div>
              <p className="text-sm font-bold" style={{ color: 'var(--text-1)' }}>Remediation Queue</p>
              <div className="ml-auto flex items-center gap-2">
                <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                  {remQueue.filter(r => r.status === 'open').length} open · {remQueue.filter(r => r.status === 'in_progress').length} in progress · {remQueue.filter(r => r.status === 'blocked').length} blocked
                </span>
              </div>
            </div>
            {remQueue.length === 0
              ? <p className="px-5 pb-5 text-xs" style={{ color: 'var(--text-3)' }}>No remediation items.</p>
              : remQueue.map(item => (
                <RemItem key={item.rank} {...item} />
              ))
            }
          </div>

          {/* ── Row 7: Historical Trends ─────────────────────────────────── */}
          {trendData.length > 1 && (
            <div className="g-card p-5">
              <div className="flex items-center gap-2 mb-4">
                <div className="p-1.5 rounded-xl" style={{ background: 'var(--accent-glow)' }}>
                  <BarChart2 className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                </div>
                <p className="text-sm font-bold" style={{ color: 'var(--text-1)' }}>Historical Trends</p>
                <span className="text-[10px] ml-auto" style={{ color: 'var(--text-3)' }}>Last {trend.length} snapshots</span>
              </div>
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={trendData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                  <defs>
                    {[
                      { key: 'Total',    color: '#f85149' },
                      { key: 'Vulns',    color: '#fb923c' },
                      { key: 'Behavior', color: '#a855f7' },
                      { key: 'Alerts',   color: '#fbbf24' },
                      { key: 'IOC',      color: '#38bdf8' },
                    ].map(({ key, color }) => (
                      <linearGradient key={key} id={`grad-${key}`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor={color} stopOpacity={0.22} />
                        <stop offset="95%" stopColor={color} stopOpacity={0} />
                      </linearGradient>
                    ))}
                  </defs>
                  <XAxis dataKey="date" tick={{ fontSize: 9, fill: 'var(--text-3)' }} tickLine={false} axisLine={false}
                    interval={Math.max(1, Math.floor(trendData.length / 6))} />
                  <YAxis tick={{ fontSize: 9, fill: 'var(--text-3)' }} tickLine={false} axisLine={false} domain={[0, 100]} />
                  <Tooltip content={<ChartTooltip />} />
                  <Legend wrapperStyle={{ fontSize: 10, color: 'var(--text-3)' }} iconSize={8} />
                  {[
                    { key: 'Total',    color: '#f85149' },
                    { key: 'Vulns',    color: '#fb923c' },
                    { key: 'Behavior', color: '#a855f7' },
                    { key: 'Alerts',   color: '#fbbf24' },
                    { key: 'IOC',      color: '#38bdf8' },
                  ].map(({ key, color }) => (
                    <Area key={key} type="monotone" dataKey={key} stroke={color} strokeWidth={key === 'Total' ? 2 : 1.5}
                      fill={`url(#grad-${key})`} dot={false} activeDot={{ r: 3 }} />
                  ))}
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* ── Row 8: Asset table + User risk ───────────────────────────── */}
          {(snap.asset_scores?.length > 0 || snap.user_risk?.length > 0) && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {snap.asset_scores?.length > 0 && (
                <div className="g-card overflow-hidden">
                  <div className="flex items-center gap-2 px-4 pt-4 pb-3">
                    <div className="p-1.5 rounded-xl" style={{ background: '#fb923c18' }}>
                      <Server className="h-4 w-4" style={{ color: '#fb923c' }} />
                    </div>
                    <p className="text-sm font-bold" style={{ color: 'var(--text-1)' }}>Asset Risk Detail</p>
                    <span className="ml-auto text-[10px] font-bold" style={{ color: '#fb923c' }}>{snap.asset_scores.length}</span>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full" style={{ borderCollapse: 'collapse' }}>
                      <thead>
                        <tr style={{ borderBottom: '1px solid var(--border)' }}>
                          {['Asset', 'Criticality', 'Score', 'Top Reason'].map(h => (
                            <th key={h} className="px-3 py-2 text-left text-[9px] font-semibold uppercase tracking-wider"
                              style={{ color: 'var(--text-3)' }}>{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {snap.asset_scores.map(a => {
                          const sc = riskColor(a.score);
                          return (
                            <tr key={a.asset_id} style={{ borderBottom: '1px solid var(--border)' }}>
                              <td className="px-3 py-2.5">
                                <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{a.hostname}</p>
                                {a.os && <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>{a.os}</p>}
                              </td>
                              <td className="px-3 py-2.5 text-xs capitalize" style={{ color: 'var(--text-3)' }}>{a.criticality}</td>
                              <td className="px-3 py-2.5">
                                <div className="flex items-center gap-2">
                                  <div className="w-14 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--bg-1)' }}>
                                    <div className="h-full rounded-full" style={{ width: `${a.score}%`, background: sc }} />
                                  </div>
                                  <span className="text-xs font-bold tabular-nums" style={{ color: sc }}>{a.score}</span>
                                </div>
                              </td>
                              <td className="px-3 py-2.5 text-[10px]" style={{ color: 'var(--text-3)' }}>{a.top_reason}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {snap.user_risk?.length > 0 && (
                <div className="g-card overflow-hidden">
                  <div className="flex items-center gap-2 px-4 pt-4 pb-3">
                    <div className="p-1.5 rounded-xl" style={{ background: '#a855f718' }}>
                      <UserX className="h-4 w-4" style={{ color: '#a855f7' }} />
                    </div>
                    <p className="text-sm font-bold" style={{ color: 'var(--text-1)' }}>User Risk Detail</p>
                    <span className="ml-auto text-[10px] font-bold" style={{ color: '#a855f7' }}>{snap.user_risk.length}</span>
                  </div>
                  <div>
                    {snap.user_risk.slice(0, 8).map((u, i) => {
                      const sc = riskColor(u.risk_score);
                      return (
                        <div key={i} className="flex items-center gap-3 px-4 py-2.5"
                          style={{ borderBottom: '1px solid var(--border)' }}>
                          <div className="w-7 h-7 rounded-full flex items-center justify-center shrink-0"
                            style={{ background: `${sc}18`, border: `1px solid ${sc}44` }}>
                            <span className="text-[9px] font-bold" style={{ color: sc }}>{u.username[0]?.toUpperCase()}</span>
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{u.username}</p>
                              {u.flags.slice(0, 2).map(f => (
                                <span key={f} className="text-[8px] px-1 py-0.5 rounded"
                                  style={{ background: 'var(--bg-1)', color: 'var(--text-3)' }}>
                                  {f.replace(/_/g, ' ')}
                                </span>
                              ))}
                            </div>
                            <p className="text-[9px] mt-0.5" style={{ color: 'var(--text-3)' }}>
                              {u.failed_logins} failed · {u.off_hours} off-hours · {u.last_seen_ip}
                            </p>
                          </div>
                          <div className="flex items-center gap-1.5 shrink-0">
                            <div className="w-12 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--bg-1)' }}>
                              <div className="h-full rounded-full" style={{ width: `${u.risk_score}%`, background: sc }} />
                            </div>
                            <span className="text-xs font-bold tabular-nums w-6 text-right" style={{ color: sc }}>{u.risk_score}</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── Row 9: High-risk identities + apps ───────────────────────── */}
          {(snap.high_risk_identities?.length > 0 || snap.high_risk_apps?.length > 0) && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {snap.high_risk_identities?.length > 0 && (
                <div className="g-card p-4">
                  <div className="flex items-center gap-2 mb-4">
                    <div className="p-1.5 rounded-xl" style={{ background: '#f8514918' }}>
                      <Lock className="h-4 w-4" style={{ color: '#f85149' }} />
                    </div>
                    <p className="text-sm font-bold" style={{ color: 'var(--text-1)' }}>High-Risk Identities</p>
                    <span className="ml-auto text-[10px] font-bold" style={{ color: '#f85149' }}>{snap.high_risk_identities.length}</span>
                  </div>
                  <div className="space-y-2">
                    {snap.high_risk_identities.map((id, i) => (
                      <div key={i} className="rounded-xl p-3"
                        style={{ background: `${sevColor(id.severity)}10`, border: `1px solid ${sevColor(id.severity)}30` }}>
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <Lock className="h-3 w-3 shrink-0" style={{ color: sevColor(id.severity) }} />
                            <span className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{id.identity}</span>
                            <span className="text-[9px] px-1 py-0.5 rounded" style={{ background: 'var(--bg-1)', color: 'var(--text-3)' }}>
                              {id.identity_type.replace('_', ' ')}
                            </span>
                          </div>
                          <span className={sevClass(id.severity)} style={{ fontSize: 9 }}>{id.severity}</span>
                        </div>
                        <p className="text-[10px] leading-relaxed" style={{ color: 'var(--text-3)' }}>{id.description}</p>
                        {id.mitre_technique && (
                          <span className="text-[9px] font-mono mt-1 inline-block px-1.5 py-0.5 rounded"
                            style={{ background: '#a78bfa22', color: '#a78bfa' }}>{id.mitre_technique}</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {snap.high_risk_apps?.length > 0 && (
                <div className="g-card p-4">
                  <div className="flex items-center gap-2 mb-4">
                    <div className="p-1.5 rounded-xl" style={{ background: '#fb923c18' }}>
                      <Package className="h-4 w-4" style={{ color: '#fb923c' }} />
                    </div>
                    <p className="text-sm font-bold" style={{ color: 'var(--text-1)' }}>High-Risk Applications</p>
                    <span className="ml-auto text-[10px] font-bold" style={{ color: '#fb923c' }}>{snap.high_risk_apps.length}</span>
                  </div>
                  <div className="space-y-2">
                    {snap.high_risk_apps.map((app, i) => {
                      const sc = sevColor(app.risk);
                      return (
                        <div key={i} className="rounded-xl p-3 flex gap-3"
                          style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                          <div className="p-2 rounded-xl shrink-0 self-start" style={{ background: `${sc}15` }}>
                            <Package className="h-4 w-4" style={{ color: sc }} />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center justify-between mb-0.5">
                              <span className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{app.name}</span>
                              <span className={sevClass(app.risk)} style={{ fontSize: 9 }}>{app.risk}</span>
                            </div>
                            <p className="text-[9px] mb-1" style={{ color: 'var(--text-3)' }}>v{app.version} · {app.assets} asset{app.assets !== 1 ? 's' : ''}</p>
                            <p className="text-[10px] leading-relaxed" style={{ color: 'var(--text-2)' }}>{app.reason}</p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

        </div>
      )}
    </RootLayout>
  );
}
