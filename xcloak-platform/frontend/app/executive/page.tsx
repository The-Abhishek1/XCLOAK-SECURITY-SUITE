'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { executiveAPI } from '@/lib/api';

// ── types ─────────────────────────────────────────────────────────────────────

type Tab = 'dashboard'|'risk'|'kpis'|'impact'|'threats'|'compliance'|'vulns'|'incidents'|'assets'|'forecast'|'analytics'|'reports'|'notif'|'integrations'|'audit';

const TABS: { id: Tab; label: string }[] = [
  { id: 'dashboard',    label: 'Dashboard'       },
  { id: 'risk',         label: 'Risk Overview'   },
  { id: 'kpis',         label: 'KPIs'            },
  { id: 'impact',       label: 'Business Impact' },
  { id: 'threats',      label: 'Threats'         },
  { id: 'compliance',   label: 'Compliance'      },
  { id: 'vulns',        label: 'Vulnerabilities' },
  { id: 'incidents',    label: 'Incidents'       },
  { id: 'assets',       label: 'Assets'          },
  { id: 'forecast',     label: 'Forecasting'     },
  { id: 'analytics',    label: 'Analytics'       },
  { id: 'reports',      label: 'Reports'         },
  { id: 'notif',        label: 'Notifications'   },
  { id: 'integrations', label: 'Integrations'    },
  { id: 'audit',        label: 'Audit Trail'     },
];

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

function StatCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="g-card" style={{ padding: '14px 18px', minWidth: 120 }}>
      <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 700, color: color || 'var(--text-1)', lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 3 }}>{sub}</div>}
    </div>
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
        <span style={{ fontWeight: 700, fontSize: 13 }}>✦ AI Executive Assistant</span>
        <button className="g-btn g-btn-ghost" style={{ fontSize: 12, padding: '2px 8px' }} onClick={onClose}>✕</button>
      </div>
      <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12, flex: 1, overflowY: 'auto' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
          {AI_ACTIONS.map(a => (
            <button key={a.id} onClick={() => setAction(a.id)} className="g-btn g-btn-ghost"
              style={{ fontSize: 11, textAlign: 'left', fontWeight: action === a.id ? 700 : 400, color: action === a.id ? 'var(--accent)' : 'var(--text-2)', borderColor: action === a.id ? 'var(--accent)' : 'var(--border)' }}>
              {a.label}
            </button>
          ))}
        </div>
        <button className="g-btn" onClick={run} disabled={loading} style={{ fontSize: 12 }}>
          {loading ? 'Generating…' : 'Generate'}
        </button>
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
      <div className="g-card" style={{ padding: 24, display: 'flex', alignItems: 'center', gap: 32, flexWrap: 'wrap' }}>
        <ScoreRing score={latest.security_score || 0}              size={100} label="Security"    />
        <ScoreRing score={100 - (latest.risk_score || 0)}          size={100} label="Risk Posture"/>
        <ScoreRing score={latest.compliance_score || 0}            size={100} label="Compliance"  />
        <div style={{ marginLeft: 'auto', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          {[
            { label: 'Total Incidents', value: latest.total_incidents,                        color: '#ef4444' },
            { label: 'Critical Vulns',  value: latest.critical_vulns,                         color: '#f97316' },
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

      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total Assets"     value={(latest.total_assets    || 0).toLocaleString()} color="var(--accent)" />
        <StatCard label="Patch Compliance" value={`${latest.patch_compliance    || 0}%`} color="#22c55e" />
        <StatCard label="Detection Cov."   value={`${latest.detection_coverage || 0}%`} color="#3b82f6" />
        <StatCard label="Automation Rate"  value={`${latest.automation_rate    || 0}%`} color="#a855f7" />
        <StatCard label="SLA Compliance"   value={`${latest.sla_compliance     || 0}%`} color="#22c55e" />
        <StatCard label="Financial Risk"   value={fmtNum(latest.financial_risk_usd || 0)} color="#ef4444" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
        {[
          { label: '30-Day Security Score Trend', data: trendSec,  color: '#22c55e' },
          { label: '30-Day Risk Score Trend',     data: trendRisk, color: '#ef4444' },
          { label: '30-Day Incident Volume',      data: trendInc,  color: '#f97316' },
        ].map(s => (
          <div key={s.label} className="g-card" style={{ padding: 16 }}>
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 10 }}>{s.label}</div>
            <SparkBars data={s.data} color={s.color} height={56} />
          </div>
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
        <StatCard label="Current Risk Score" value={risk.risk_score    || 0}   sub="Lower is better" color="#ef4444" />
        <StatCard label="Critical Risks"     value={risk.critical_count || 0}  color="#ef4444" />
        <StatCard label="High Risks"         value={risk.high_count     || 0}  color="#f97316" />
        <StatCard label="Risk Trend"         value={risk.risk_trend > 0 ? `▲ +${risk.risk_trend}` : `▼ ${risk.risk_trend}`}
          color={risk.risk_trend > 0 ? '#ef4444' : '#22c55e'} />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 14 }}>Top Business Risks</div>
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
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 14 }}>Geographic Threat Distribution</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {geo.map((g: any, i: number) => (
              <HorizBar key={i} label={g.country} pct={(g.threat_count / (geo[0]?.threat_count || 1)) * 100} color="#ef4444" value={String(g.threat_count)} />
            ))}
          </div>
        </div>
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
          <div key={i} className="g-card" style={{ padding: 16 }}>
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
          </div>
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
        <StatCard label="Total Financial Risk" value={fmtNum(impact.financial_risk_usd  || 0)} color="#ef4444" />
        <StatCard label="Max Potential Loss"   value={fmtNum(impact.max_potential_loss  || 0)} color="#f97316" />
        <StatCard label="Avg Recovery Cost"    value={fmtNum(impact.avg_recovery_cost   || 0)} color="#eab308" />
        <StatCard label="Cyber Insurance"      value={impact.cyber_insurance_coverage || '—'}  />
      </div>
      <div className="g-card" style={{ padding: 16 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 14 }}>Business Unit Risk Breakdown</div>
        <table className="g-table" style={{ width: '100%' }}>
          <thead>
            <tr>
              {['Business Unit', 'Risk Score', 'Critical Incidents', 'Financial Exposure', 'Top Risk'].map(h => (
                <th key={h} style={{ textAlign: 'left', fontSize: 10, color: 'var(--text-3)', padding: '6px 10px' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {bus.map((b: any, i: number) => (
              <tr key={i}>
                <td style={{ fontSize: 12, color: 'var(--text-1)', padding: '8px 10px', fontWeight: 500 }}>{b.name}</td>
                <td style={{ padding: '8px 10px' }}>{pill(String(b.risk_score), b.risk_score >= 70 ? '#ef4444' : b.risk_score >= 50 ? '#eab308' : '#22c55e')}</td>
                <td style={{ fontSize: 12, color: '#ef4444', padding: '8px 10px', textAlign: 'center' }}>{b.critical_incidents}</td>
                <td style={{ fontSize: 12, color: 'var(--text-2)', padding: '8px 10px' }}>{fmtNum(b.financial_exposure)}</td>
                <td style={{ fontSize: 11, color: 'var(--text-3)', padding: '8px 10px' }}>{b.top_risk || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
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
        <StatCard label="Active Campaigns"     value={threats.active_campaign_count || 0} color="#ef4444" />
        <StatCard label="IOCs Tracked"         value={(threats.ioc_count || 0).toLocaleString()} color="#f97316" />
        <StatCard label="Threat Actors"        value={threats.threat_actor_count || 0} color="#a855f7" />
        <StatCard label="Industries Targeted"  value={threats.industry_targeting  || '—'} />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>Active Threat Campaigns</div>
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
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div className="g-card" style={{ padding: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>Top Malware Families</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {malware.map((m: any, i: number) => (
                <HorizBar key={i} label={m.name} pct={(m.detections / (malware[0]?.detections || 1)) * 100} color="#f97316" value={String(m.detections)} />
              ))}
            </div>
          </div>
          <div className="g-card" style={{ padding: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>Geographic Distribution</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {geo.slice(0, 6).map((g: any, i: number) => (
                <HorizBar key={i} label={g.country} pct={(g.count / (geo[0]?.count || 1)) * 100} color="#a855f7" value={String(g.count)} />
              ))}
            </div>
          </div>
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
        <StatCard label="Overall Compliance" value={`${compliance.overall_score   || 0}%`} color="#22c55e" />
        <StatCard label="Active Frameworks"  value={compliance.active_frameworks   || 0}   color="var(--accent)" />
        <StatCard label="Passed Controls"    value={compliance.passed_controls     || 0}   color="#22c55e" />
        <StatCard label="Failed Controls"    value={compliance.failed_controls     || 0}   color="#ef4444" />
        <StatCard label="Open Remediations"  value={compliance.open_remediations   || 0}   color="#eab308" />
      </div>
      <div className="g-card" style={{ padding: 16 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 14 }}>Framework Compliance Status</div>
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
      </div>
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
        <StatCard label="Total Vulns"    value={(vulns.total_vulns || 0).toLocaleString()} color="var(--text-1)" />
        <StatCard label="Critical"       value={vulns.critical || 0}    color="#ef4444" />
        <StatCard label="High"           value={vulns.high || 0}        color="#f97316" />
        <StatCard label="Exploitable"    value={vulns.exploitable || 0} color="#ef4444" />
        <StatCard label="Patch Coverage" value={`${vulns.patch_coverage || 0}%`} color="#22c55e" />
        <StatCard label="Avg CVSS"       value={(vulns.avg_cvss || 0).toFixed(1)} color="#eab308" />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>Top Critical Vulnerabilities</div>
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
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>Exposure by Business Unit</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {bu.map((b: any, i: number) => (
              <HorizBar key={i} label={b.name} pct={(b.critical_vulns / (bu[0]?.critical_vulns || 1)) * 100} color="#ef4444" value={String(b.critical_vulns)} />
            ))}
          </div>
        </div>
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
        <StatCard label="Total Incidents"  value={incidents.total_incidents    || 0} color="var(--text-1)" />
        <StatCard label="Critical"         value={incidents.critical_incidents  || 0} color="#ef4444" />
        <StatCard label="MTTD"             value={`${(incidents.mttd_hours||0).toFixed(1)}h`} color="#eab308" sub="Mean time to detect" />
        <StatCard label="MTTR"             value={`${(incidents.mttr_hours||0).toFixed(1)}h`} color="#f97316" sub="Mean time to respond" />
        <StatCard label="SLA Compliance"   value={`${incidents.sla_compliance || 0}%`} color="#22c55e" />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>By Severity</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {sev.map((s: any, i: number) => (
              <HorizBar key={i} label={s.severity} pct={(s.count / (incidents.total_incidents || 1)) * 100} color={SEV_CLR[s.severity] || '#6b7280'} value={String(s.count)} />
            ))}
          </div>
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>By Category</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {cat.map((c: any, i: number) => (
              <HorizBar key={i} label={c.category} pct={(c.count / (incidents.total_incidents || 1)) * 100} color="#3b82f6" value={String(c.count)} />
            ))}
          </div>
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>Root Causes</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {rc.map((r: any, i: number) => (
              <HorizBar key={i} label={r.cause} pct={(r.count / (incidents.total_incidents || 1)) * 100} color="#a855f7" value={String(r.count)} />
            ))}
          </div>
        </div>
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
        <StatCard label="Total Assets"     value={(assets.total_assets || 0).toLocaleString()} color="var(--accent)" />
        <StatCard label="Critical Assets"  value={assets.critical_assets  || 0} color="#ef4444" />
        <StatCard label="Managed"          value={`${assets.managed_pct   || 0}%`} color="#22c55e" />
        <StatCard label="Unmanaged"        value={assets.unmanaged_count   || 0} color="#eab308" />
        <StatCard label="Avg Health Score" value={`${assets.avg_health     || 0}%`} color="#3b82f6" />
      </div>
      <div className="g-card" style={{ padding: 16 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 14 }}>Asset Categories</div>
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
      </div>
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
            <div key={i} className="g-card" style={{ padding: 16 }}>
              <div style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'capitalize', marginBottom: 8 }}>{m.name?.replace(/_/g, ' ')}</div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 10 }}>
                <span style={{ fontSize: 24, fontWeight: 700, color }}>{last.toFixed(1)}</span>
                <span style={{ fontSize: 11, color }}>30-day forecast</span>
              </div>
              <SparkBars data={vals} color={color} height={40} />
            </div>
          );
        })}
      </div>
      {insights.length > 0 && (
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>Predictive Insights</div>
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
        </div>
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
          <div key={s.label} className="g-card" style={{ padding: 16 }}>
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 10 }}>{s.label}</div>
            <SparkBars data={s.data} color={s.color} height={60} />
          </div>
        ))}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>SOC Performance Metrics</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            {Object.entries(soc).map(([k, v]: [string, any]) => (
              <div key={k} style={{ background: 'var(--bg-2)', borderRadius: 8, padding: '10px 12px' }}>
                <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'capitalize' }}>{k.replace(/_/g, ' ')}</div>
                <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-1)', marginTop: 4 }}>{v}</div>
              </div>
            ))}
          </div>
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>Business Unit Security Score</div>
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
        </div>
      </div>
    </div>
  );
}

// ── Reports tab ───────────────────────────────────────────────────────────────

function ReportsTab({ reports, onRefresh }: { reports: any[]; onRefresh: () => void }) {
  const [generating, setGenerating] = useState(false);
  const [form, setForm] = useState({ title: '', report_type: 'executive_summary', format: 'pdf' });

  async function generate() {
    setGenerating(true);
    await executiveAPI.generateReport(form).catch(() => null);
    setGenerating(false);
    onRefresh();
  }

  const typeColors: Record<string, string> = {
    executive_summary: '#3b82f6', board_report: '#a855f7', weekly_briefing: '#22c55e',
    risk_analysis: '#ef4444', quarterly_review: '#f97316', compliance_summary: '#eab308',
    annual_report: '#6b7280', kpi_dashboard: '#06b6d4',
  };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="g-card" style={{ padding: 16, display: 'flex', gap: 10, alignItems: 'flex-end', flexWrap: 'wrap' }}>
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
        <button className="g-btn" onClick={generate} disabled={generating || !form.title} style={{ fontSize: 12 }}>
          {generating ? 'Generating…' : 'Generate Report'}
        </button>
      </div>
      <div className="g-card" style={{ padding: 0, overflow: 'hidden' }}>
        <table className="g-table" style={{ width: '100%' }}>
          <thead>
            <tr>
              {['Title', 'Type', 'Generated By', 'Date', 'Format', 'Size'].map(h => (
                <th key={h} style={{ textAlign: 'left', fontSize: 10, color: 'var(--text-3)', padding: '10px 14px' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {reports.map((r: any, i: number) => (
              <tr key={i}>
                <td style={{ fontSize: 12, color: 'var(--text-1)', padding: '10px 14px', fontWeight: 500 }}>{r.title}</td>
                <td style={{ padding: '10px 14px' }}>{pill(r.report_type?.replace(/_/g, ' '), typeColors[r.report_type] || '#6b7280')}</td>
                <td style={{ fontSize: 11, color: 'var(--text-2)', padding: '10px 14px' }}>{r.generated_by}</td>
                <td style={{ fontSize: 11, color: 'var(--text-3)', padding: '10px 14px' }}>{fmt(r.created_at)}</td>
                <td style={{ fontSize: 11, color: 'var(--text-3)', padding: '10px 14px', textTransform: 'uppercase' }}>{r.format}</td>
                <td style={{ fontSize: 11, color: 'var(--text-3)', padding: '10px 14px' }}>{r.size_bytes ? `${(r.size_bytes / 1024).toFixed(0)} KB` : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
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
          <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={markRead}>
            Mark all read ({unread})
          </button>
        )}
      </div>
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
        <StatCard label="Total"    value={integrations.length}                                     color="var(--accent)" />
        <StatCard label="Active"   value={integrations.filter(i => i.status === 'active').length}   color="#22c55e" />
        <StatCard label="Degraded" value={integrations.filter(i => i.status === 'degraded').length} color="#eab308" />
        <StatCard label="Inactive" value={integrations.filter(i => i.status === 'inactive').length} color="#6b7280" />
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
  const actionIcon: Record<string, string> = {
    report_generated: '📄', dashboard_accessed: '📊', report_shared: '📤',
    config_changed: '⚙️', notification_viewed: '🔔',
  };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {audit.map((a: any, i: number) => (
        <div key={i} style={{ display: 'flex', gap: 12, alignItems: 'flex-start', padding: '12px 14px', borderRadius: 8, background: 'var(--bg-2)', border: '1px solid var(--border)' }}>
          <div style={{ width: 32, height: 32, borderRadius: 8, background: (actionColor[a.action] || '#6b7280') + '22', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <span style={{ fontSize: 14 }}>{actionIcon[a.action] || '📋'}</span>
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
              {pill(a.action?.replace(/_/g, ' '), actionColor[a.action] || '#6b7280')}
              <span style={{ fontSize: 12, color: 'var(--text-1)', fontWeight: 500 }}>{a.object_name || a.object_type}</span>
            </div>
            <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{a.actor} · {a.ip_address} · {fmt(a.created_at)}</div>
            {a.details && <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>{a.details}</div>}
          </div>
        </div>
      ))}
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

  const tabBar = (
    <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', overflowX: 'auto', flexShrink: 0 }}>
      {TABS.map(t => (
        <button key={t.id} onClick={() => setTab(t.id)}
          style={{ position: 'relative', padding: '10px 16px', fontSize: 12, whiteSpace: 'nowrap', background: 'none', border: 'none', cursor: 'pointer', color: tab === t.id ? 'var(--accent)' : 'var(--text-2)', borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent', fontWeight: tab === t.id ? 600 : 400 }}>
          {t.label}
          {t.id === 'notif' && unreadCount > 0 && (
            <span style={{ position: 'absolute', top: 6, right: 6, width: 14, height: 14, borderRadius: '50%', background: '#ef4444', fontSize: 8, color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700 }}>{unreadCount}</span>
          )}
        </button>
      ))}
    </div>
  );

  const actions = (
    <button className="g-btn" style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }} onClick={() => setShowAI(v => !v)}>
      ✦ AI Assistant
    </button>
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
    <RootLayout title="Executive" subtitle="C-Suite Security Intelligence" actions={actions}>
      {tabBar}
      <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>
        {renderTab()}
      </div>
      {showAI && <AIPanel onClose={() => setShowAI(false)} />}
    </RootLayout>
  );
}
