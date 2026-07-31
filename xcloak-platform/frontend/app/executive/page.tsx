'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { executiveAPI } from '@/lib/api';
import { MetricCard, DataTable, EmptyState, SectionCard, TabBar, ActionButton, Modal } from '@/components/design-system';
import {
  LayoutDashboard, ShieldAlert, Gauge, DollarSign, Flame, ShieldCheck, Bug,
  AlertTriangle, Boxes, TrendingUp, BarChart3, FileBarChart2, Bell, Plug, ScrollText,
  X, FileText, Share2, Settings, ClipboardList, Sparkles,
} from 'lucide-react';

// ── types ─────────────────────────────────────────────────────────────────────

type Tab = 'dashboard'|'risk'|'kpis'|'impact'|'threats'|'compliance'|'vulns'|'incidents'|'assets'|'forecast'|'analytics'|'reports'|'notif'|'integrations'|'audit';

// ── colour helpers ────────────────────────────────────────────────────────────

const SEV_CLR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#3b82f6',
};
const NOTIF_CLR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', info: '#3b82f6',
};
const STATUS_CLR: Record<string, string> = {
  active: '#22c55e', degraded: '#eab308', inactive: '#6b7280', error: '#ef4444',
};
const RISK_CLR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
};

function pill(label: string, color: string) {
  return (
    <span style={{ fontSize: 10, fontWeight: 600, padding: '2px 8px', borderRadius: 10, background: color + '22', color, border: `1px solid ${color}44`, textTransform: 'capitalize', whiteSpace: 'nowrap' }}>
      {label}
    </span>
  );
}

function fmt(d?: string | null) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString();
}

function fmtNum(n: number) {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`;
  return `$${n}`;
}

function ScoreRing({ score, size = 72, label }: { score: number; size?: number; label?: string }) {
  const r = (size - 8) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ * (1 - score / 100);
  const color = score >= 80 ? '#22c55e' : score >= 60 ? '#eab308' : '#ef4444';
  return (
    <svg width={size} height={size} style={{ flexShrink: 0 }}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--border)" strokeWidth={8} />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={8}
        strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
        style={{ transformOrigin: `${size / 2}px ${size / 2}px`, transform: 'rotate(-90deg)' }} />
      <text x="50%" y={label ? '42%' : '50%'} dominantBaseline="middle" textAnchor="middle"
        fill={color} fontSize={size / 5} fontWeight="bold">{score}</text>
      {label && <text x="50%" y="64%" dominantBaseline="middle" textAnchor="middle"
        fill="var(--text-3)" fontSize={size / 7}>{label}</text>}
    </svg>
  );
}

function HorizBar({ label, pct, color, value }: { label: string; pct: number; color: string; value?: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <div style={{ width: 120, fontSize: 11, color: 'var(--text-2)', flexShrink: 0, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{label}</div>
      <div style={{ flex: 1, height: 6, borderRadius: 3, background: 'var(--border)', overflow: 'hidden' }}>
        <div style={{ width: `${Math.min(pct, 100)}%`, height: '100%', background: color, borderRadius: 3 }} />
      </div>
      <div style={{ width: 48, fontSize: 11, textAlign: 'right', color: 'var(--text-2)', fontVariantNumeric: 'tabular-nums' }}>{value ?? `${pct.toFixed(0)}%`}</div>
    </div>
  );
}

function SparkBars({ data, color = 'var(--accent)', height = 48 }: { data: number[]; color?: string; height?: number }) {
  const max = Math.max(...data, 1);
  return (
    <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height }}>
      {data.map((v, i) => (
        <div key={i} style={{ flex: 1, background: color, borderRadius: 2, height: `${Math.max(3, (v / max) * height)}px`, opacity: 0.35 + 0.65 * (v / max) }} />
      ))}
    </div>
  );
}

// ── AI panel ──────────────────────────────────────────────────────────────────

const AI_ACTIONS = [
  { id: 'executive_summary',   label: 'Executive Summary'    },
  { id: 'weekly_briefing',     label: 'Weekly Briefing'      },
  { id: 'board_summary',       label: 'Board Summary'        },
  { id: 'risk_analysis',       label: 'Risk Analysis'        },
  { id: 'trend_analysis',      label: 'Trend Analysis'       },
  { id: 'recommendations',     label: 'Recommendations'      },
  { id: 'predictive_insights', label: 'Predictive Insights'  },
];

function AIPanel({ onClose }: { onClose: () => void }) {
  const [action, setAction] = useState('executive_summary');
  const [resp, setResp] = useState('');
  const [loading, setLoading] = useState(false);

  async function run() {
    setLoading(true); setResp('');
    const r = await executiveAPI.ai({ action }).catch(() => null);
    setResp((r as any)?.data?.response || 'No response.');
    setLoading(false);
  }

  return (
    <div style={{ position: 'fixed', inset: '0 0 0 auto', width: 420, background: 'var(--bg-1)', borderLeft: '1px solid var(--border)', zIndex: 50, display: 'flex', flexDirection: 'column', boxShadow: '-4px 0 20px #0006' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 18px', borderBottom: '1px solid var(--border)' }}>
        <span className="flex items-center gap-2" style={{ fontWeight: 700, fontSize: 13 }}>
          <Sparkles className="h-4 w-4" style={{ color: 'var(--accent)' }} /> AI Executive Assistant
        </span>
        <ActionButton variant="ghost" icon={X} onClick={onClose} style={{ padding: '2px 8px' }} />
      </div>
      <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12, flex: 1, overflowY: 'auto' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
          {AI_ACTIONS.map(a => (
            <ActionButton key={a.id} variant={action === a.id ? 'primary' : 'ghost'} onClick={() => setAction(a.id)}
              style={{ fontSize: 11, textAlign: 'left' }}>
              {a.label}
            </ActionButton>
          ))}
        </div>
        <ActionButton variant="primary" onClick={run} disabled={loading} style={{ fontSize: 12 }}>
          {loading ? 'Generating…' : 'Generate'}
        </ActionButton>
        {resp && (
          <div className="g-card" style={{ padding: 14, fontSize: 12, whiteSpace: 'pre-wrap', lineHeight: 1.6, color: 'var(--text-1)' }}>
            {resp}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Dashboard tab ─────────────────────────────────────────────────────────────

function DashboardTab({ dash }: { dash: any }) {
  if (!dash) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const latest = dash.latest || {};
  const trend = dash.trend || [];
  const trendSec  = trend.map((t: any) => t.security_score   || 0);
  const trendRisk = trend.map((t: any) => t.risk_score        || 0);
  const trendInc  = trend.map((t: any) => t.total_incidents   || 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <SectionCard>
        <div style={{ display: 'flex', alignItems: 'center', gap: 32, flexWrap: 'wrap' }}>
          <ScoreRing score={latest.security_score || 0}              size={100} label="Security"    />
          <ScoreRing score={100 - (latest.risk_score || 0)}          size={100} label="Risk Posture"/>
          <ScoreRing score={latest.compliance_score || 0}            size={100} label="Compliance"  />
          <div style={{ marginLeft: 'auto', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            {[
              { label: 'Total Incidents', value: latest.total_incidents || 0,                   color: '#ef4444' },
              { label: 'Critical Vulns',  value: latest.critical_vulns || 0,                    color: '#f97316' },
              { label: 'MTTD',            value: `${(latest.mttd_hours||0).toFixed(1)}h`,       color: '#eab308' },
              { label: 'MTTR',            value: `${(latest.mttr_hours||0).toFixed(1)}h`,       color: '#eab308' },
            ].map(s => (
              <div key={s.label} style={{ textAlign: 'center', background: s.color + '18', borderRadius: 10, padding: '10px 14px' }}>
                <div style={{ fontSize: 22, fontWeight: 700, color: s.color }}>{s.value}</div>
                <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{s.label}</div>
              </div>
            ))}
          </div>
        </div>
      </SectionCard>

      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <MetricCard label="Total Assets"     value={(latest.total_assets    || 0).toLocaleString()} color="var(--accent)" />
        <MetricCard label="Patch Compliance" value={`${latest.patch_compliance    || 0}%`} color="#22c55e" />
        <MetricCard label="Detection Cov."   value={`${latest.detection_coverage || 0}%`} color="#3b82f6" />
        <MetricCard label="Automation Rate"  value={`${latest.automation_rate    || 0}%`} color="#a855f7" />
        <MetricCard label="SLA Compliance"   value={`${latest.sla_compliance     || 0}%`} color="#22c55e" />
        <MetricCard label="Financial Risk"   value={fmtNum(latest.financial_risk_usd || 0)} color="#ef4444" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
        {[
          { label: '30-Day Security Score Trend', data: trendSec,  color: '#22c55e' },
          { label: '30-Day Risk Score Trend',     data: trendRisk, color: '#ef4444' },
          { label: '30-Day Incident Volume',      data: trendInc,  color: '#f97316' },
        ].map(s => (
          <SectionCard key={s.label}>
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 10 }}>{s.label}</div>
            <SparkBars data={s.data} color={s.color} height={56} />
          </SectionCard>
        ))}
      </div>
    </div>
  );
}

// ── Risk tab ──────────────────────────────────────────────────────────────────

function RiskTab({ risk }: { risk: any }) {
  if (!risk) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const topRisks: any[] = risk.top_risks    || [];
  const geo:      any[] = risk.geo_threats  || [];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <MetricCard label="Current Risk Score" value={risk.risk_score    || 0}   sub="Lower is better" color="#ef4444" />
        <MetricCard label="Critical Risks"     value={risk.critical_count || 0}  color="#ef4444" />
        <MetricCard label="High Risks"         value={risk.high_count     || 0}  color="#f97316" />
        <MetricCard label="Risk Trend"         value={risk.risk_trend > 0 ? `▲ +${risk.risk_trend}` : `▼ ${risk.risk_trend}`}
          color={risk.risk_trend > 0 ? '#ef4444' : '#22c55e'} />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <SectionCard title="Top Business Risks">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {topRisks.map((r: any, i: number) => (
              <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                <div style={{ width: 28, height: 28, borderRadius: 8, background: (RISK_CLR[r.severity]||'#6b7280')+'22', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <span style={{ fontSize: 11, fontWeight: 700, color: RISK_CLR[r.severity]||'#6b7280' }}>{i + 1}</span>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 12, color: 'var(--text-1)', fontWeight: 500 }}>{r.name}</div>
                  <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>{r.category} · {r.business_unit}</div>
                  <div style={{ display: 'flex', gap: 6, marginTop: 4 }}>
                    {pill(r.severity, RISK_CLR[r.severity] || '#6b7280')}
                    <span style={{ fontSize: 10, color: 'var(--text-3)' }}>Score: {r.risk_score}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </SectionCard>
        <SectionCard title="Geographic Threat Distribution">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {geo.map((g: any, i: number) => (
              <HorizBar key={i} label={g.country} pct={(g.threat_count / (geo[0]?.threat_count || 1)) * 100} color="#ef4444" value={String(g.threat_count)} />
            ))}
          </div>
        </SectionCard>
      </div>
    </div>
  );
}

// ── KPIs tab ──────────────────────────────────────────────────────────────────

function KPIsTab({ kpis }: { kpis: any }) {
  if (!kpis) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const items: any[] = kpis.kpis || [];
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 12 }}>
      {items.map((k: any, i: number) => {
        const ok    = k.target ? (k.lower_is_better ? k.value <= k.target : k.value >= k.target) : true;
        const color = ok ? '#22c55e' : '#ef4444';
        const pct   = k.target ? Math.min((k.lower_is_better ? k.target / k.value : k.value / k.target) * 100, 100) : 0;
        return (
          <SectionCard key={i}>
            <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>{k.name}</div>
            <div style={{ fontSize: 28, fontWeight: 700, color, lineHeight: 1 }}>{k.display_value || k.value}</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
              {k.target && <span style={{ fontSize: 10, color: 'var(--text-3)' }}>Target: {k.target_display || k.target}</span>}
              {k.change !== undefined && (
                <span style={{ fontSize: 10, color: k.change > 0 ? (k.lower_is_better ? '#ef4444' : '#22c55e') : (k.lower_is_better ? '#22c55e' : '#ef4444') }}>
                  {k.change > 0 ? '▲' : '▼'} {Math.abs(k.change).toFixed(1)}{k.unit || ''}
                </span>
              )}
            </div>
            {k.target && (
              <div style={{ marginTop: 8, height: 4, borderRadius: 2, background: 'var(--border)', overflow: 'hidden' }}>
                <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 2 }} />
              </div>
            )}
          </SectionCard>
        );
      })}
    </div>
  );
}

// ── Business Impact tab ───────────────────────────────────────────────────────

function ImpactTab({ impact }: { impact: any }) {
  if (!impact) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const bus: any[] = impact.business_units || [];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <MetricCard label="Total Financial Risk" value={fmtNum(impact.financial_risk_usd  || 0)} color="#ef4444" />
      </div>
      <SectionCard title="Business Unit Risk Breakdown" padded={false}>
        <DataTable<any>
          rows={bus}
          rowKey={(b: any, i: number) => b.name ?? i}
          emptyState={<EmptyState title="No business unit data" />}
          columns={[
            { key: 'name', header: 'Business Unit', render: (b: any) => <span style={{ fontSize: 12, color: 'var(--text-1)', fontWeight: 500 }}>{b.name}</span> },
            { key: 'risk_score', header: 'Risk Score', render: (b: any) => pill(String(b.risk_score), b.risk_score >= 70 ? '#ef4444' : b.risk_score >= 50 ? '#eab308' : '#22c55e') },
            { key: 'critical_incidents', header: 'Critical Incidents', render: (b: any) => <span style={{ fontSize: 12, color: '#ef4444' }}>{b.critical_incidents}</span> },
            { key: 'financial_exposure', header: 'Financial Exposure', render: (b: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{fmtNum(b.financial_exposure)}</span> },
            { key: 'top_risk', header: 'Top Risk', render: (b: any) => <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{b.top_risk || '—'}</span> },
          ]}
        />
      </SectionCard>
    </div>
  );
}

// ── Threats tab ───────────────────────────────────────────────────────────────

function ThreatsTab({ threats }: { threats: any }) {
  if (!threats) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const campaigns: any[] = threats.active_campaigns   || [];
  const malware:   any[] = threats.top_malware         || [];
  const geo:       any[] = threats.geo_distribution    || [];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <MetricCard label="Active Campaigns"     value={threats.active_campaign_count || 0} color="#ef4444" />
        <MetricCard label="IOCs Tracked"         value={(threats.ioc_count || 0).toLocaleString()} color="#f97316" />
        <MetricCard label="Threat Actors"        value={threats.threat_actor_count || 0} color="#a855f7" />
        <MetricCard label="Industries Targeted"  value={threats.industry_targeting  || '—'} />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <SectionCard title="Active Threat Campaigns">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {campaigns.map((c: any, i: number) => (
              <div key={i} style={{ padding: '10px 12px', borderRadius: 8, background: 'var(--bg-2)', border: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  {pill(c.severity, SEV_CLR[c.severity] || '#6b7280')}
                  <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-1)' }}>{c.name}</span>
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{c.actor} · {c.category} · {c.affected_systems} systems</div>
              </div>
            ))}
          </div>
        </SectionCard>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <SectionCard title="Top Malware Families">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {malware.map((m: any, i: number) => (
                <HorizBar key={i} label={m.name} pct={(m.detections / (malware[0]?.detections || 1)) * 100} color="#f97316" value={String(m.detections)} />
              ))}
            </div>
          </SectionCard>
          <SectionCard title="Geographic Distribution">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {geo.slice(0, 6).map((g: any, i: number) => (
                <HorizBar key={i} label={g.country} pct={(g.count / (geo[0]?.count || 1)) * 100} color="#a855f7" value={String(g.count)} />
              ))}
            </div>
          </SectionCard>
        </div>
      </div>
    </div>
  );
}

// ── Compliance tab ────────────────────────────────────────────────────────────

function ComplianceTab({ compliance }: { compliance: any }) {
  if (!compliance) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const frameworks: any[] = compliance.frameworks || [];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <MetricCard label="Overall Compliance" value={`${compliance.overall_score   || 0}%`} color="#22c55e" />
        <MetricCard label="Active Frameworks"  value={compliance.active_frameworks   || 0}   color="var(--accent)" />
        <MetricCard label="Passed Controls"    value={compliance.passed_controls     || 0}   color="#22c55e" />
        <MetricCard label="Failed Controls"    value={compliance.failed_controls     || 0}   color="#ef4444" />
        <MetricCard label="Open Remediations"  value={compliance.open_remediations   || 0}   color="#eab308" />
      </div>
      <SectionCard title="Framework Compliance Status">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {frameworks.map((f: any, i: number) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <ScoreRing score={f.compliance_score || 0} size={48} />
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-1)' }}>{f.name}</div>
                <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>{f.controls_passed}/{f.total_controls} controls · {f.category}</div>
              </div>
              {pill(f.status?.replace('_', ' ') || 'unknown', f.compliance_score >= 80 ? '#22c55e' : f.compliance_score >= 60 ? '#eab308' : '#ef4444')}
            </div>
          ))}
        </div>
      </SectionCard>
    </div>
  );
}

// ── Vulns tab ─────────────────────────────────────────────────────────────────

function VulnsTab({ vulns }: { vulns: any }) {
  if (!vulns) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const top: any[] = vulns.top_vulns         || [];
  const bu:  any[] = vulns.by_business_unit  || [];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <MetricCard label="Total Vulns"    value={(vulns.total_vulns || 0).toLocaleString()} color="var(--text-1)" />
        <MetricCard label="Critical"       value={vulns.critical || 0}    color="#ef4444" />
        <MetricCard label="High"           value={vulns.high || 0}        color="#f97316" />
        <MetricCard label="Exploitable"    value={vulns.exploitable || 0} color="#ef4444" />
        <MetricCard label="Patch Coverage" value={`${vulns.patch_coverage || 0}%`} color="#22c55e" />
        <MetricCard label="Avg CVSS"       value={(vulns.avg_cvss || 0).toFixed(1)} color="#eab308" />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: 16 }}>
        <SectionCard title="Top Critical Vulnerabilities">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {top.map((v: any, i: number) => (
              <div key={i} style={{ padding: '10px 12px', borderRadius: 8, background: 'var(--bg-2)', border: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}>
                  {pill(v.severity, RISK_CLR[v.severity] || '#6b7280')}
                  <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-3)' }}>{v.cve_id}</span>
                  <span style={{ marginLeft: 'auto', fontSize: 11, fontWeight: 600, color: '#ef4444' }}>CVSS {v.cvss}</span>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-1)' }}>{v.title}</div>
                <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>{v.affected_systems} systems affected</div>
              </div>
            ))}
          </div>
        </SectionCard>
        <SectionCard title="Exposure by Business Unit">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {bu.map((b: any, i: number) => (
              <HorizBar key={i} label={b.name} pct={(b.critical_vulns / (bu[0]?.critical_vulns || 1)) * 100} color="#ef4444" value={String(b.critical_vulns)} />
            ))}
          </div>
        </SectionCard>
      </div>
    </div>
  );
}

// ── Incidents tab ─────────────────────────────────────────────────────────────

function IncidentsTab({ incidents }: { incidents: any }) {
  if (!incidents) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const sev: any[] = incidents.by_severity || [];
  const cat: any[] = incidents.by_category || [];
  const rc:  any[] = incidents.root_causes || [];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <MetricCard label="Total Incidents"  value={incidents.total_incidents    || 0} color="var(--text-1)" />
        <MetricCard label="Critical"         value={incidents.critical_incidents  || 0} color="#ef4444" />
        <MetricCard label="MTTD"             value={`${(incidents.mttd_hours||0).toFixed(1)}h`} color="#eab308" sub="Mean time to detect" />
        <MetricCard label="MTTR"             value={`${(incidents.mttr_hours||0).toFixed(1)}h`} color="#f97316" sub="Mean time to respond" />
        <MetricCard label="SLA Compliance"   value={`${incidents.sla_compliance || 0}%`} color="#22c55e" />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
        <SectionCard title="By Severity">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {sev.map((s: any, i: number) => (
              <HorizBar key={i} label={s.severity} pct={(s.count / (incidents.total_incidents || 1)) * 100} color={SEV_CLR[s.severity] || '#6b7280'} value={String(s.count)} />
            ))}
          </div>
        </SectionCard>
        <SectionCard title="By Category">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {cat.map((c: any, i: number) => (
              <HorizBar key={i} label={c.category} pct={(c.count / (incidents.total_incidents || 1)) * 100} color="#3b82f6" value={String(c.count)} />
            ))}
          </div>
        </SectionCard>
        <SectionCard title="Root Causes">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {rc.map((r: any, i: number) => (
              <HorizBar key={i} label={r.cause} pct={(r.count / (incidents.total_incidents || 1)) * 100} color="#a855f7" value={String(r.count)} />
            ))}
          </div>
        </SectionCard>
      </div>
    </div>
  );
}

// ── Assets tab ────────────────────────────────────────────────────────────────

function AssetsTab({ assets }: { assets: any }) {
  if (!assets) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const cats: any[] = assets.categories || [];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <MetricCard label="Total Assets"     value={(assets.total_assets || 0).toLocaleString()} color="var(--accent)" />
        <MetricCard label="Critical Assets"  value={assets.critical_assets  || 0} color="#ef4444" />
        <MetricCard label="Managed"          value={`${assets.managed_pct   || 0}%`} color="#22c55e" />
        <MetricCard label="Unmanaged"        value={assets.unmanaged_count   || 0} color="#eab308" />
        <MetricCard label="Avg Health Score" value={`${assets.avg_health     || 0}%`} color="#3b82f6" />
      </div>
      <SectionCard title="Asset Categories">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: 10 }}>
          {cats.map((c: any, i: number) => (
            <div key={i} style={{ padding: '14px 16px', borderRadius: 10, background: 'var(--bg-2)', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'capitalize', marginBottom: 6 }}>{c.name}</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-1)' }}>{(c.count||0).toLocaleString()}</div>
              <div style={{ marginTop: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-3)', marginBottom: 3 }}>
                  <span>Health</span><span>{c.health_score}%</span>
                </div>
                <div style={{ height: 4, borderRadius: 2, background: 'var(--border)', overflow: 'hidden' }}>
                  <div style={{ width: `${c.health_score}%`, height: '100%', borderRadius: 2, background: c.health_score >= 80 ? '#22c55e' : c.health_score >= 60 ? '#eab308' : '#ef4444' }} />
                </div>
              </div>
            </div>
          ))}
        </div>
      </SectionCard>
    </div>
  );
}

// ── Forecasting tab ───────────────────────────────────────────────────────────

function ForecastTab({ forecast }: { forecast: any }) {
  if (!forecast) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const metrics:  any[] = forecast.metrics  || [];
  const insights: any[] = forecast.insights || [];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 12 }}>
        {metrics.map((m: any, i: number) => {
          const vals  = (m.points || []).map((p: any) => Number(p.value) || 0);
          const trend = vals.length >= 2 ? vals[vals.length - 1] - vals[0] : 0;
          const color = m.lower_is_better ? (trend > 0 ? '#ef4444' : '#22c55e') : (trend > 0 ? '#22c55e' : '#ef4444');
          const last  = vals[vals.length - 1] ?? 0;
          return (
            <SectionCard key={i}>
              <div style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'capitalize', marginBottom: 8 }}>{m.name?.replace(/_/g, ' ')}</div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 10 }}>
                <span style={{ fontSize: 24, fontWeight: 700, color }}>{last.toFixed(1)}</span>
                <span style={{ fontSize: 11, color }}>30-day forecast</span>
              </div>
              <SparkBars data={vals} color={color} height={40} />
            </SectionCard>
          );
        })}
      </div>
      {insights.length > 0 && (
        <SectionCard title="Predictive Insights">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {insights.map((ins: any, i: number) => (
              <div key={i} style={{ padding: '10px 14px', borderRadius: 8, background: 'var(--bg-2)', border: `1px solid ${SEV_CLR[ins.severity] || 'var(--border)'}44` }}>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}>
                  {pill(ins.type || 'insight', SEV_CLR[ins.severity] || '#3b82f6')}
                  <span style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-1)' }}>{ins.title}</span>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{ins.description}</div>
              </div>
            ))}
          </div>
        </SectionCard>
      )}
    </div>
  );
}

// ── Analytics tab ─────────────────────────────────────────────────────────────

function AnalyticsTab({ analytics }: { analytics: any }) {
  if (!analytics) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const ts:  any[]  = analytics.time_series     || [];
  const soc: any    = analytics.soc_performance || {};
  const bu:  any[]  = analytics.business_units  || [];
  const secScores   = ts.map((t: any) => t.security_score || 0);
  const riskScores  = ts.map((t: any) => t.risk_score     || 0);
  const incVolume   = ts.map((t: any) => t.incidents      || 0);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
        {[
          { label: 'Security Score (90d)', data: secScores,  color: '#22c55e' },
          { label: 'Risk Score (90d)',     data: riskScores, color: '#ef4444' },
          { label: 'Incident Volume (90d)',data: incVolume,  color: '#f97316' },
        ].map(s => (
          <SectionCard key={s.label}>
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 10 }}>{s.label}</div>
            <SparkBars data={s.data} color={s.color} height={60} />
          </SectionCard>
        ))}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <SectionCard title="SOC Performance Metrics">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            {Object.entries(soc).map(([k, v]: [string, any]) => (
              <div key={k} style={{ background: 'var(--bg-2)', borderRadius: 8, padding: '10px 12px' }}>
                <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'capitalize' }}>{k.replace(/_/g, ' ')}</div>
                <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-1)', marginTop: 4 }}>{v}</div>
              </div>
            ))}
          </div>
        </SectionCard>
        <SectionCard title="Business Unit Security Score">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {bu.map((b: any, i: number) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{ width: 90, fontSize: 11, color: 'var(--text-2)', flexShrink: 0 }}>{b.name}</div>
                <div style={{ flex: 1, height: 6, borderRadius: 3, background: 'var(--border)', overflow: 'hidden' }}>
                  <div style={{ width: `${b.security_score}%`, height: '100%', borderRadius: 3, background: b.security_score >= 80 ? '#22c55e' : b.security_score >= 60 ? '#eab308' : '#ef4444' }} />
                </div>
                <div style={{ width: 32, fontSize: 11, textAlign: 'right', color: 'var(--text-2)', fontVariantNumeric: 'tabular-nums' }}>{b.security_score}</div>
              </div>
            ))}
          </div>
        </SectionCard>
      </div>
    </div>
  );
}

// ── Reports tab ───────────────────────────────────────────────────────────────

function ReportsTab({ reports, onRefresh }: { reports: any[]; onRefresh: () => void }) {
  const [generating, setGenerating] = useState(false);
  const [form, setForm] = useState({ title: '', report_type: 'executive_summary', format: 'pdf' });
  const [viewing, setViewing] = useState<any>(null);

  async function generate() {
    setGenerating(true);
    try {
      await executiveAPI.generateReport(form);
      onRefresh();
    } catch (err: any) {
      alert(err?.response?.data?.error || 'Failed to generate report');
    }
    setGenerating(false);
  }

  const typeColors: Record<string, string> = {
    executive_summary: '#3b82f6', board_report: '#a855f7', weekly_briefing: '#22c55e',
    risk_analysis: '#ef4444', quarterly_review: '#f97316', compliance_summary: '#eab308',
    annual_report: '#6b7280', kpi_dashboard: '#06b6d4',
  };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <SectionCard>
        <div style={{ display: 'flex', gap: 10, alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 200 }}>
            <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 4 }}>Report Title</div>
            <input className="g-input" style={{ width: '100%', fontSize: 12 }} placeholder="e.g. Monthly Executive Briefing"
              value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))} />
          </div>
          <div>
            <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 4 }}>Type</div>
            <select className="g-input" style={{ fontSize: 12 }} value={form.report_type} onChange={e => setForm(f => ({ ...f, report_type: e.target.value }))}>
              {['executive_summary','board_report','weekly_briefing','risk_analysis','quarterly_review','compliance_summary','kpi_dashboard','annual_report'].map(t => (
                <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>
              ))}
            </select>
          </div>
          <ActionButton variant="primary" onClick={generate} disabled={generating || !form.title} style={{ fontSize: 12 }}>
            {generating ? 'Generating…' : 'Generate Report'}
          </ActionButton>
        </div>
      </SectionCard>
      <SectionCard padded={false}>
        <DataTable<any>
          rows={reports}
          rowKey={(r: any, i: number) => r.id ?? i}
          emptyState={<EmptyState title="No reports yet" />}
          columns={[
            { key: 'title', header: 'Title', render: (r: any) => <span style={{ fontSize: 12, color: 'var(--text-1)', fontWeight: 500 }}>{r.title}</span> },
            { key: 'report_type', header: 'Type', render: (r: any) => pill(r.report_type?.replace(/_/g, ' '), typeColors[r.report_type] || '#6b7280') },
            { key: 'generated_by', header: 'Generated By', render: (r: any) => <span style={{ fontSize: 11, color: 'var(--text-2)' }}>{r.generated_by}</span> },
            { key: 'created_at', header: 'Date', render: (r: any) => <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{fmt(r.created_at)}</span> },
            { key: 'format', header: 'Format', render: (r: any) => <span style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase' }}>{r.format}</span> },
            { key: 'size_bytes', header: 'Size', render: (r: any) => <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{r.size_bytes ? (r.size_bytes >= 1024 ? `${(r.size_bytes / 1024).toFixed(1)} KB` : `${r.size_bytes} B`) : '—'}</span> },
            { key: 'view', header: '', render: (r: any) => (
              <ActionButton variant="ghost" style={{ fontSize: 10 }} onClick={() => setViewing(r)}>View</ActionButton>
            ) },
          ]}
        />
      </SectionCard>

      <Modal open={!!viewing} onClose={() => setViewing(null)} title={viewing?.title} maxWidth={560}>
        {viewing && (() => {
          let findings: string[] = [];
          let recs: string[] = [];
          try { findings = JSON.parse(viewing.key_findings || '[]'); } catch { findings = []; }
          try { recs = JSON.parse(viewing.recommendations || '[]'); } catch { recs = []; }
          return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 6 }}>Summary</div>
                <div style={{ fontSize: 13, color: 'var(--text-1)', lineHeight: 1.5 }}>{viewing.summary || 'No summary available.'}</div>
              </div>
              {findings.length > 0 && (
                <div>
                  <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 6 }}>Key Findings</div>
                  {findings.map((f, i) => (
                    <div key={i} style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 4 }}>• {f}</div>
                  ))}
                </div>
              )}
              {recs.length > 0 && (
                <div>
                  <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 6 }}>Recommendations</div>
                  {recs.map((r, i) => (
                    <div key={i} style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 4 }}>{i + 1}. {r}</div>
                  ))}
                </div>
              )}
            </div>
          );
        })()}
      </Modal>
    </div>
  );
}

// ── Notifications tab ─────────────────────────────────────────────────────────

function NotifTab({ notifs, onRefresh }: { notifs: any[]; onRefresh: () => void }) {
  async function markRead() {
    await executiveAPI.markNotificationsRead().catch(() => null);
    onRefresh();
  }
  const unread = notifs.filter(n => !n.read).length;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        {unread > 0 && (
          <ActionButton variant="ghost" onClick={markRead} style={{ fontSize: 11 }}>
            Mark all read ({unread})
          </ActionButton>
        )}
      </div>
      {!notifs.length && <EmptyState title="No notifications" />}
      {notifs.map((n: any, i: number) => (
        <div key={i} style={{ padding: '12px 16px', borderRadius: 10, background: 'var(--bg-2)', border: `1px solid ${n.read ? 'var(--border)' : (NOTIF_CLR[n.severity] || 'var(--border)') + '44'}`, opacity: n.read ? 0.7 : 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            {pill(n.severity, NOTIF_CLR[n.severity] || '#6b7280')}
            <span style={{ fontSize: 12, fontWeight: n.read ? 400 : 600, color: 'var(--text-1)' }}>{n.title}</span>
            {!n.read && <span style={{ marginLeft: 'auto', width: 6, height: 6, borderRadius: '50%', background: NOTIF_CLR[n.severity] || '#3b82f6', display: 'inline-block', flexShrink: 0 }} />}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-2)', marginBottom: 4 }}>{n.message}</div>
          <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{n.source} · {fmt(n.created_at)}</div>
        </div>
      ))}
    </div>
  );
}

// ── Integrations tab ──────────────────────────────────────────────────────────

function IntegrationsTab({ integrations }: { integrations: any[] }) {
  const catColors: Record<string, string> = {
    siem: '#3b82f6', edr: '#22c55e', soar: '#a855f7', threat_intel: '#ef4444',
    vulnerability: '#f97316', cmdb: '#06b6d4', firewall: '#eab308',
    cloud_security: '#ec4899', compliance: '#10b981', iam: '#6366f1',
    ticketing: '#64748b', email_security: '#f43f5e',
  };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <MetricCard label="Total"    value={integrations.length}                                     color="var(--accent)" />
        <MetricCard label="Active"   value={integrations.filter(i => i.status === 'active').length}   color="#22c55e" />
        <MetricCard label="Degraded" value={integrations.filter(i => i.status === 'degraded').length} color="#eab308" />
        <MetricCard label="Inactive" value={integrations.filter(i => i.status === 'inactive').length} color="#6b7280" />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 10 }}>
        {integrations.map((intg: any, i: number) => (
          <div key={i} className="g-card" style={{ padding: 16, borderLeft: `3px solid ${catColors[intg.category] || '#6b7280'}` }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-1)', flex: 1 }}>{intg.name}</span>
              {pill(intg.status, STATUS_CLR[intg.status] || '#6b7280')}
            </div>
            <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 8 }}>{intg.config_summary}</div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span style={{ fontSize: 10, color: 'var(--text-3)' }}>Health</span>
              <span style={{ fontSize: 10, fontWeight: 600, color: intg.health_score >= 90 ? '#22c55e' : intg.health_score >= 70 ? '#eab308' : '#ef4444' }}>{intg.health_score}%</span>
            </div>
            <div style={{ height: 4, borderRadius: 2, background: 'var(--border)', overflow: 'hidden', marginBottom: 8 }}>
              <div style={{ width: `${intg.health_score}%`, height: '100%', borderRadius: 2, background: intg.health_score >= 90 ? '#22c55e' : intg.health_score >= 70 ? '#eab308' : '#ef4444' }} />
            </div>
            <div style={{ display: 'flex', gap: 12, fontSize: 10, color: 'var(--text-3)' }}>
              <span>Records: {(intg.records_synced || 0).toLocaleString()}</span>
              {intg.error_count > 0 && <span style={{ color: '#ef4444' }}>Errors: {intg.error_count}</span>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Audit tab ─────────────────────────────────────────────────────────────────

function AuditTab({ audit }: { audit: any[] }) {
  const actionColor: Record<string, string> = {
    dashboard_accessed: '#3b82f6', report_generated: '#22c55e', report_shared: '#a855f7',
    notification_viewed: '#06b6d4', config_changed: '#eab308',
  };
  const actionIcon: Record<string, any> = {
    report_generated: FileText, dashboard_accessed: LayoutDashboard, report_shared: Share2,
    config_changed: Settings, notification_viewed: Bell,
  };
  if (!audit.length) return <EmptyState title="No audit entries" />;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {audit.map((a: any, i: number) => {
        const Icon = actionIcon[a.action] || ClipboardList;
        const color = actionColor[a.action] || '#6b7280';
        return (
          <div key={i} style={{ display: 'flex', gap: 12, alignItems: 'flex-start', padding: '12px 14px', borderRadius: 8, background: 'var(--bg-2)', border: '1px solid var(--border)' }}>
            <div style={{ width: 32, height: 32, borderRadius: 8, background: color + '22', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
              <Icon className="h-4 w-4" style={{ color }} />
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
                {pill(a.action?.replace(/_/g, ' '), color)}
                <span style={{ fontSize: 12, color: 'var(--text-1)', fontWeight: 500 }}>{a.object_name || a.object_type}</span>
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{a.actor} · {a.ip_address} · {fmt(a.created_at)}</div>
              {a.details && <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>{a.details}</div>}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────────

export default function ExecutivePage() {
  const [tab, setTab]               = useState<Tab>('dashboard');
  const [showAI, setShowAI]         = useState(false);
  const [loading, setLoading]       = useState(true);

  const [dash, setDash]             = useState<any>(null);
  const [risk, setRisk]             = useState<any>(null);
  const [kpis, setKpis]             = useState<any>(null);
  const [impact, setImpact]         = useState<any>(null);
  const [threats, setThreats]       = useState<any>(null);
  const [compliance, setCompliance] = useState<any>(null);
  const [vulns, setVulns]           = useState<any>(null);
  const [incidents, setIncidents]   = useState<any>(null);
  const [assets, setAssets]         = useState<any>(null);
  const [forecast, setForecast]     = useState<any>(null);
  const [analytics, setAnalytics]   = useState<any>(null);
  const [reports, setReports]       = useState<any[]>([]);
  const [notifs, setNotifs]         = useState<any[]>([]);
  const [integrations, setIntegrations] = useState<any[]>([]);
  const [audit, setAudit]           = useState<any[]>([]);

  const loadAll = useCallback(async () => {
    setLoading(true);
    const [d, r, k, imp, th, comp, v, inc, a, fc, an, rp, nt, intg, au] = await Promise.all([
      executiveAPI.getDashboard(),
      executiveAPI.getRisk(),
      executiveAPI.getKPIs(),
      executiveAPI.getBusinessImpact(),
      executiveAPI.getThreatLandscape(),
      executiveAPI.getCompliance(),
      executiveAPI.getVulns(),
      executiveAPI.getIncidents(),
      executiveAPI.getAssets(),
      executiveAPI.getForecasting(),
      executiveAPI.getAnalytics(),
      executiveAPI.getReports(),
      executiveAPI.getNotifications(),
      executiveAPI.getIntegrations(),
      executiveAPI.getAudit(),
    ]);
    setDash((d as any)?.data);
    setRisk((r as any)?.data);
    setKpis((k as any)?.data);
    setImpact((imp as any)?.data);
    setThreats((th as any)?.data);
    setCompliance((comp as any)?.data);
    setVulns((v as any)?.data);
    setIncidents((inc as any)?.data);
    setAssets((a as any)?.data);
    setForecast((fc as any)?.data);
    setAnalytics((an as any)?.data);
    setReports(Array.isArray((rp as any)?.data) ? (rp as any).data : []);
    setNotifs(Array.isArray((nt as any)?.data) ? (nt as any).data : []);
    setIntegrations(Array.isArray((intg as any)?.data) ? (intg as any).data : []);
    setAudit(Array.isArray((au as any)?.data) ? (au as any).data : []);
    setLoading(false);
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  const unreadCount = notifs.filter(n => !n.read).length;

  const TABS: { key: Tab; label: string; icon: any; count?: number }[] = [
    { key: 'dashboard',    label: 'Dashboard',       icon: LayoutDashboard },
    { key: 'risk',         label: 'Risk Overview',   icon: ShieldAlert },
    { key: 'kpis',         label: 'KPIs',            icon: Gauge },
    { key: 'impact',       label: 'Business Impact', icon: DollarSign },
    { key: 'threats',      label: 'Threats',         icon: Flame },
    { key: 'compliance',   label: 'Compliance',      icon: ShieldCheck },
    { key: 'vulns',        label: 'Vulnerabilities', icon: Bug },
    { key: 'incidents',    label: 'Incidents',       icon: AlertTriangle },
    { key: 'assets',       label: 'Assets',          icon: Boxes },
    { key: 'forecast',     label: 'Forecasting',     icon: TrendingUp },
    { key: 'analytics',    label: 'Analytics',       icon: BarChart3 },
    { key: 'reports',      label: 'Reports',         icon: FileBarChart2 },
    { key: 'notif',        label: 'Notifications',   icon: Bell, count: unreadCount || undefined },
    { key: 'integrations', label: 'Integrations',    icon: Plug },
    { key: 'audit',        label: 'Audit Trail',     icon: ScrollText },
  ];

  const actions = (
    <ActionButton variant="primary" icon={Sparkles} onClick={() => setShowAI(v => !v)}>AI Assistant</ActionButton>
  );

  function renderTab() {
    if (loading) return <div style={{ padding: 60, textAlign: 'center', color: 'var(--text-3)' }}>Loading executive data…</div>;
    switch (tab) {
      case 'dashboard':    return <DashboardTab    dash={dash} />;
      case 'risk':         return <RiskTab         risk={risk} />;
      case 'kpis':         return <KPIsTab         kpis={kpis} />;
      case 'impact':       return <ImpactTab       impact={impact} />;
      case 'threats':      return <ThreatsTab      threats={threats} />;
      case 'compliance':   return <ComplianceTab   compliance={compliance} />;
      case 'vulns':        return <VulnsTab        vulns={vulns} />;
      case 'incidents':    return <IncidentsTab    incidents={incidents} />;
      case 'assets':       return <AssetsTab       assets={assets} />;
      case 'forecast':     return <ForecastTab     forecast={forecast} />;
      case 'analytics':    return <AnalyticsTab    analytics={analytics} />;
      case 'reports':      return <ReportsTab      reports={reports} onRefresh={loadAll} />;
      case 'notif':        return <NotifTab        notifs={notifs} onRefresh={loadAll} />;
      case 'integrations': return <IntegrationsTab integrations={integrations} />;
      case 'audit':        return <AuditTab        audit={audit} />;
      default:             return null;
    }
  }

  return (
    <RootLayout title="Executive" subtitle="C-Suite Security Intelligence" onRefresh={loadAll} actions={actions}>
      <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: 2, overflowX: 'auto' }}>
        <TabBar tabs={TABS} active={tab} onChange={k => setTab(k as Tab)} />
      </div>
      <div style={{ flex: 1, overflowY: 'auto', padding: '20px 0 0' }}>
        {renderTab()}
      </div>
      {showAI && <AIPanel onClose={() => setShowAI(false)} />}
    </RootLayout>
  );
}
