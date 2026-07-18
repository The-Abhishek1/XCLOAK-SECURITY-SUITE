'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { socMetricsAPI } from '@/lib/api';

// ── types ─────────────────────────────────────────────────────────────────────

type Tab = 'dashboard'|'alerts'|'incidents'|'cases'|'analysts'|'detection'|'automation'|'threats'|'endpoints'|'vulns'|'compliance'|'infra'|'ai'|'reports'|'audit';

const TABS: { id: Tab; label: string }[] = [
  { id: 'dashboard',  label: 'Dashboard'      },
  { id: 'alerts',     label: 'Alerts'         },
  { id: 'incidents',  label: 'Incidents'      },
  { id: 'cases',      label: 'Cases'          },
  { id: 'analysts',   label: 'Analysts'       },
  { id: 'detection',  label: 'Detection'      },
  { id: 'automation', label: 'Automation'     },
  { id: 'threats',    label: 'Threats'        },
  { id: 'endpoints',  label: 'Endpoints'      },
  { id: 'vulns',      label: 'Vulnerabilities'},
  { id: 'compliance', label: 'Compliance'     },
  { id: 'infra',      label: 'Infrastructure' },
  { id: 'ai',         label: 'AI Insights'    },
  { id: 'reports',    label: 'Reports'        },
  { id: 'audit',      label: 'Audit Trail'    },
];

// ── colour helpers ────────────────────────────────────────────────────────────

const SEV_CLR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#3b82f6',
};
const STATUS_CLR: Record<string, string> = {
  healthy: '#22c55e', degraded: '#eab308', error: '#ef4444', inactive: '#6b7280', active: '#22c55e',
};
const RULE_CLR: Record<string, string> = {
  sigma: '#3b82f6', yara: '#a855f7', ml: '#06b6d4', custom: '#f97316',
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
    <div className="g-card" style={{ padding: '14px 18px', minWidth: 110 }}>
      <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 24, fontWeight: 700, color: color || 'var(--text-1)', lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 3 }}>{sub}</div>}
    </div>
  );
}

function fmt(d?: string | null) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString();
}

function fmtTime(d?: string | null) {
  if (!d) return '—';
  return new Date(d).toLocaleTimeString();
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
      <div style={{ width: 130, fontSize: 11, color: 'var(--text-2)', flexShrink: 0, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{label}</div>
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
  { id: 'daily_summary',           label: 'Daily SOC Summary'          },
  { id: 'analyst_bottlenecks',     label: 'Analyst Bottlenecks'        },
  { id: 'detection_gaps',          label: 'Detection Gaps'             },
  { id: 'alert_noise',             label: 'Alert Noise Analysis'       },
  { id: 'automation_opportunities',label: 'Automation Opportunities'   },
  { id: 'threat_trends',           label: 'Threat Trends'              },
  { id: 'recommendations',         label: 'Recommendations'            },
];

function AIPanel({ onClose }: { onClose: () => void }) {
  const [action, setAction] = useState('daily_summary');
  const [resp, setResp]     = useState('');
  const [loading, setLoading] = useState(false);

  async function run() {
    setLoading(true); setResp('');
    const r = await socMetricsAPI.ai({ action }).catch(() => null);
    setResp((r as any)?.data?.response || 'No response.');
    setLoading(false);
  }

  return (
    <div style={{ position: 'fixed', inset: '0 0 0 auto', width: 440, background: 'var(--bg-1)', borderLeft: '1px solid var(--border)', zIndex: 50, display: 'flex', flexDirection: 'column', boxShadow: '-4px 0 20px #0006' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 18px', borderBottom: '1px solid var(--border)' }}>
        <span style={{ fontWeight: 700, fontSize: 13 }}>✦ AI SOC Insights</span>
        <button className="g-btn g-btn-ghost" style={{ fontSize: 12, padding: '2px 8px' }} onClick={onClose}>✕</button>
      </div>
      <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 10, flex: 1, overflowY: 'auto' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
          {AI_ACTIONS.map(a => (
            <button key={a.id} onClick={() => setAction(a.id)} className="g-btn g-btn-ghost"
              style={{ fontSize: 11, textAlign: 'left', fontWeight: action === a.id ? 700 : 400, color: action === a.id ? 'var(--accent)' : 'var(--text-2)', borderColor: action === a.id ? 'var(--accent)' : 'var(--border)' }}>
              {a.label}
            </button>
          ))}
        </div>
        <button className="g-btn" onClick={run} disabled={loading} style={{ fontSize: 12 }}>
          {loading ? 'Analyzing…' : 'Generate Insight'}
        </button>
        {resp && (
          <div className="g-card" style={{ padding: 14, fontSize: 12, whiteSpace: 'pre-wrap', lineHeight: 1.65, color: 'var(--text-1)' }}>
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
  const lat = dash.latest || {};
  const trend: any[] = dash.trend || [];
  const healthTrend = trend.map((t: any) => t.health_score || 0);
  const alertTrend  = trend.map((t: any) => t.total_alerts || 0);
  const incTrend    = trend.map((t: any) => t.total_incidents || 0);

  const healthColor = (lat.soc_health_score || 0) >= 80 ? '#22c55e' : (lat.soc_health_score || 0) >= 60 ? '#eab308' : '#ef4444';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* SOC Health Hero */}
      <div className="g-card" style={{ padding: 24, display: 'flex', alignItems: 'center', gap: 28, flexWrap: 'wrap' }}>
        <ScoreRing score={lat.soc_health_score || 0} size={96} label="SOC Health" />
        <div>
          <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 2 }}>SOC Health Score</div>
          <div style={{ fontSize: 40, fontWeight: 800, color: healthColor, lineHeight: 1 }}>{lat.soc_health_score || 0}</div>
          <div style={{ display: 'flex', gap: 8, marginTop: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 10, background: 'var(--bg-2)', borderRadius: 6, padding: '3px 8px', color: 'var(--text-2)' }}>
              Shift: <strong style={{ color: 'var(--text-1)' }}>{lat.current_shift || 'day'}</strong>
            </span>
            <span style={{ fontSize: 10, background: 'var(--bg-2)', borderRadius: 6, padding: '3px 8px', color: 'var(--text-2)' }}>
              Analysts: <strong style={{ color: '#22c55e' }}>{lat.analysts_online || 0}/{lat.active_analysts || 0}</strong> online
            </span>
            <span style={{ fontSize: 10, background: 'var(--bg-2)', borderRadius: 6, padding: '3px 8px', color: 'var(--text-2)' }}>
              Automation: <strong style={{ color: 'var(--accent)' }}>{lat.automation_coverage || 0}%</strong>
            </span>
          </div>
        </div>
        <div style={{ marginLeft: 'auto', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          {[
            { label: 'Active Alerts',   value: lat.active_alerts,    color: '#ef4444' },
            { label: 'Active Incidents',value: lat.active_incidents,  color: '#f97316' },
            { label: 'Open Cases',      value: lat.open_cases,        color: '#eab308' },
            { label: 'SLA Compliance',  value: `${lat.sla_compliance || 0}%`, color: '#22c55e' },
          ].map(s => (
            <div key={s.label} style={{ textAlign: 'center', background: s.color + '18', borderRadius: 10, padding: '10px 14px' }}>
              <div style={{ fontSize: 22, fontWeight: 700, color: s.color }}>{s.value}</div>
              <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{s.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Key metrics */}
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Critical Alerts"    value={lat.critical_alerts || 0}  color="#ef4444" />
        <StatCard label="Alert Queue"        value={lat.alert_queue || 0}       color="#f97316" sub="items pending" />
        <StatCard label="Critical Incidents" value={lat.critical_incidents || 0} color="#ef4444" />
        <StatCard label="Case Backlog"       value={lat.case_backlog || 0}      color="#eab308" />
        <StatCard label="MTTD"               value={`${(lat.mttd_mins||0).toFixed(0)}m`} color="#eab308" sub="mean time to detect" />
        <StatCard label="MTTR"               value={`${((lat.mttr_mins||0)/60).toFixed(1)}h`} color="#f97316" sub="mean time to respond" />
        <StatCard label="Playbooks Today"    value={lat.playbook_executions || 0} color="#a855f7" />
      </div>

      {/* Trend sparklines */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
        {[
          { label: 'SOC Health Score (30d)', data: healthTrend, color: '#22c55e' },
          { label: 'Alert Volume (30d)',      data: alertTrend,  color: '#ef4444' },
          { label: 'Incident Volume (30d)',   data: incTrend,    color: '#f97316' },
        ].map(s => (
          <div key={s.label} className="g-card" style={{ padding: 16 }}>
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 10 }}>{s.label}</div>
            <SparkBars data={s.data} color={s.color} height={52} />
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Alerts tab ────────────────────────────────────────────────────────────────

function AlertsTab({ alerts }: { alerts: any }) {
  if (!alerts) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const bySev: any[]    = alerts.by_severity || [];
  const bySource: any[] = alerts.by_source   || [];
  const trend: any[]    = alerts.trend        || [];
  const totalTrend      = trend.map((t: any) => t.total || 0);
  const fpTrend         = trend.map((t: any) => t.false_positives || 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total Alerts"      value={(alerts.total_alerts || 0).toLocaleString()} color="var(--text-1)" />
        <StatCard label="Critical"          value={alerts.critical || 0} color="#ef4444" />
        <StatCard label="High"              value={alerts.high || 0}     color="#f97316" />
        <StatCard label="Queue Size"        value={alerts.queue_size || 0} color="#eab308" />
        <StatCard label="False Positives"   value={alerts.false_positives || 0} color="#6b7280" />
        <StatCard label="FP Rate"           value={`${(alerts.false_positive_rate || 0).toFixed(1)}%`} color={alerts.false_positive_rate > 15 ? '#ef4444' : '#22c55e'} />
        <StatCard label="Escalated"         value={alerts.escalated || 0} color="#a855f7" />
        <StatCard label="Suppressed"        value={alerts.suppressed || 0} color="#6b7280" />
        <StatCard label="Proc. Time"        value={`${(alerts.processing_mins || 0).toFixed(1)}m`} sub="avg per alert" />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.2fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>By Severity</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {bySev.map((s: any, i: number) => (
              <HorizBar key={i} label={s.severity} pct={(s.count / (alerts.total_alerts || 1)) * 100}
                color={SEV_CLR[s.severity] || '#6b7280'} value={s.count.toLocaleString()} />
            ))}
          </div>
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>By Source</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {bySource.map((s: any, i: number) => (
              <HorizBar key={i} label={s.source} pct={(s.count / (alerts.total_alerts || 1)) * 100}
                color="#3b82f6" value={s.count.toLocaleString()} />
            ))}
          </div>
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 10 }}>Alert Volume Trend (30d)</div>
          <SparkBars data={totalTrend} color="#ef4444" height={52} />
          <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 10, marginBottom: 6 }}>False Positives (30d)</div>
          <SparkBars data={fpTrend} color="#6b7280" height={32} />
        </div>
      </div>
    </div>
  );
}

// ── Incidents tab ─────────────────────────────────────────────────────────────

function IncidentsTab({ incidents }: { incidents: any }) {
  if (!incidents) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const bySev: any[] = incidents.by_severity || [];
  const byCat: any[] = incidents.by_category || [];
  const trend: any[] = incidents.trend || [];
  const mttdTrend = trend.map((t: any) => t.mttd_mins || 0);
  const mttrtTrend = trend.map((t: any) => t.mttr_mins || 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total"          value={incidents.total_incidents || 0}    color="var(--text-1)" />
        <StatCard label="Critical"       value={incidents.critical || 0}            color="#ef4444" />
        <StatCard label="Open"           value={incidents.open || 0}               color="#f97316" />
        <StatCard label="Closed"         value={incidents.closed || 0}             color="#22c55e" />
        <StatCard label="SLA Compliance" value={`${incidents.sla_compliance || 0}%`} color={incidents.sla_compliance >= 90 ? '#22c55e' : '#eab308'} />
      </div>
      {/* Response time cards */}
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        {[
          { label: 'MTTD', value: `${(incidents.mttd_mins || 0).toFixed(0)}m`,    sub: 'Mean Time to Detect',   color: '#eab308' },
          { label: 'MTTA', value: `${(incidents.mtta_mins || 0).toFixed(0)}m`,    sub: 'Mean Time to Acknowledge', color: '#f97316' },
          { label: 'MTTC', value: `${(incidents.mttc_mins || 0).toFixed(0)}m`,    sub: 'Mean Time to Contain',  color: '#f97316' },
          { label: 'MTTR', value: `${((incidents.mttr_mins || 0)/60).toFixed(1)}h`, sub: 'Mean Time to Respond', color: '#ef4444' },
          { label: 'MTTRec', value: `${((incidents.mttrec_mins || 0)/60).toFixed(1)}h`, sub: 'Mean Time to Recover', color: '#a855f7' },
        ].map(m => <StatCard key={m.label} label={m.label} value={m.value} sub={m.sub} color={m.color} />)}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.2fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>By Severity</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {bySev.map((s: any, i: number) => (
              <HorizBar key={i} label={s.severity} pct={(s.count / (incidents.total_incidents || 1)) * 100}
                color={SEV_CLR[s.severity] || '#6b7280'} value={String(s.count)} />
            ))}
          </div>
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>By Category</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {byCat.map((c: any, i: number) => (
              <HorizBar key={i} label={c.category} pct={(c.count / (incidents.total_incidents || 1)) * 100}
                color="#3b82f6" value={String(c.count)} />
            ))}
          </div>
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 8 }}>MTTD Trend (30d)</div>
          <SparkBars data={mttdTrend} color="#eab308" height={40} />
          <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 12, marginBottom: 8 }}>MTTR Trend (30d)</div>
          <SparkBars data={mttrtTrend} color="#ef4444" height={40} />
        </div>
      </div>
    </div>
  );
}

// ── Cases tab ─────────────────────────────────────────────────────────────────

function CasesTab({ cases }: { cases: any }) {
  if (!cases) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const byStatus: any[]  = cases.by_status   || [];
  const byTeam: any[]    = cases.by_team     || [];
  const byAnalyst: any[] = cases.by_analyst  || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total Cases"          value={cases.total_cases || 0}   color="var(--text-1)" />
        <StatCard label="Open"                 value={cases.open || 0}          color="#f97316" />
        <StatCard label="Closed"               value={cases.closed || 0}        color="#22c55e" />
        <StatCard label="Backlog"              value={cases.backlog || 0}       color="#eab308" />
        <StatCard label="Escalated"            value={cases.escalated || 0}     color="#ef4444" />
        <StatCard label="Reopened"             value={cases.reopened || 0}      color="#6b7280" />
        <StatCard label="Avg Investigation"    value={`${cases.avg_investigation_hrs || 0}h`} color="#3b82f6" />
        <StatCard label="Avg Resolution"       value={`${cases.avg_resolution_hrs || 0}h`}    color="#a855f7" />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>Cases by Team</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {byTeam.map((t: any, i: number) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{ width: 140, fontSize: 11, color: 'var(--text-2)', flexShrink: 0 }}>{t.team}</div>
                <div style={{ flex: 1, height: 6, borderRadius: 3, background: 'var(--border)', overflow: 'hidden' }}>
                  <div style={{ width: `${(t.count / (cases.total_cases || 1)) * 100}%`, height: '100%', background: '#3b82f6', borderRadius: 3 }} />
                </div>
                <span style={{ fontSize: 10, color: 'var(--text-3)', width: 32, textAlign: 'right' }}>{t.count}</span>
                <span style={{ fontSize: 10, color: 'var(--text-3)' }}>{t.avg_hrs}h avg</span>
              </div>
            ))}
          </div>
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>Analyst Case Load</div>
          <table className="g-table" style={{ width: '100%' }}>
            <thead><tr>
              {['Analyst', 'Open', 'Closed', 'Avg Hrs'].map(h => (
                <th key={h} style={{ textAlign: 'left', fontSize: 10, color: 'var(--text-3)', padding: '4px 8px' }}>{h}</th>
              ))}
            </tr></thead>
            <tbody>
              {byAnalyst.map((a: any, i: number) => (
                <tr key={i}>
                  <td style={{ fontSize: 11, color: 'var(--text-1)', padding: '6px 8px' }}>{a.analyst}</td>
                  <td style={{ fontSize: 11, color: '#f97316', padding: '6px 8px', textAlign: 'center' }}>{a.open}</td>
                  <td style={{ fontSize: 11, color: '#22c55e', padding: '6px 8px', textAlign: 'center' }}>{a.closed}</td>
                  <td style={{ fontSize: 11, color: 'var(--text-3)', padding: '6px 8px' }}>{a.avg_hrs}h</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <div className="g-card" style={{ padding: 16 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>Cases by Status</div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          {byStatus.map((s: any, i: number) => {
            const colors: Record<string, string> = { open: '#ef4444', in_progress: '#3b82f6', pending_review: '#eab308', closed: '#22c55e', escalated: '#a855f7' };
            const c = colors[s.status] || '#6b7280';
            return (
              <div key={i} style={{ background: c + '18', border: `1px solid ${c}44`, borderRadius: 10, padding: '10px 16px', textAlign: 'center' }}>
                <div style={{ fontSize: 22, fontWeight: 700, color: c }}>{s.count}</div>
                <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'capitalize', marginTop: 2 }}>{s.status?.replace('_', ' ')}</div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ── Analysts tab ──────────────────────────────────────────────────────────────

function AnalystsTab({ analysts }: { analysts: any }) {
  if (!analysts) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const list: any[]   = analysts.analysts      || [];
  const shifts: any[] = analysts.shift_coverage || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total Active"   value={analysts.total_active || 0} color="var(--accent)" />
        <StatCard label="Online Now"     value={analysts.online_now || 0}   color="#22c55e" />
        <StatCard label="Shift Coverage" value={shifts.length}              sub="shifts configured" />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>Shift Coverage</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {shifts.map((s: any, i: number) => (
              <div key={i} style={{ padding: '10px 12px', borderRadius: 8, background: 'var(--bg-2)', border: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-1)', textTransform: 'capitalize' }}>{s.shift} Shift</span>
                  <span style={{ fontSize: 11, color: '#22c55e' }}>{s.analysts} analysts</span>
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{s.coverage}</div>
              </div>
            ))}
          </div>
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>Analyst Performance (30d)</div>
          <table className="g-table" style={{ width: '100%' }}>
            <thead><tr>
              {['Analyst', 'Team', 'Alerts', 'Incidents', 'Cases', 'Avg Resp', 'Productivity', 'Burnout'].map(h => (
                <th key={h} style={{ textAlign: 'left', fontSize: 10, color: 'var(--text-3)', padding: '5px 8px' }}>{h}</th>
              ))}
            </tr></thead>
            <tbody>
              {list.map((a: any, i: number) => {
                const burnoutColor = a.burnout_index >= 75 ? '#ef4444' : a.burnout_index >= 60 ? '#eab308' : '#22c55e';
                return (
                  <tr key={i}>
                    <td style={{ fontSize: 11, color: 'var(--text-1)', padding: '7px 8px', fontWeight: 500 }}>{a.name}</td>
                    <td style={{ fontSize: 10, color: 'var(--text-3)', padding: '7px 8px' }}>{a.team}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-2)', padding: '7px 8px', textAlign: 'center' }}>{a.alerts_investigated}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-2)', padding: '7px 8px', textAlign: 'center' }}>{a.incidents_resolved}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-2)', padding: '7px 8px', textAlign: 'center' }}>{a.cases_closed}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-3)', padding: '7px 8px' }}>{Number(a.avg_response_mins || 0).toFixed(0)}m</td>
                    <td style={{ padding: '7px 8px' }}>{pill(`${Number(a.productivity_score || 0).toFixed(0)}%`, '#22c55e')}</td>
                    <td style={{ padding: '7px 8px' }}>{pill(`${Number(a.burnout_index || 0).toFixed(0)}`, burnoutColor)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ── Detection tab ─────────────────────────────────────────────────────────────

function DetectionTab({ detection }: { detection: any }) {
  if (!detection) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const rules: any[]   = detection.rules         || [];
  const mitre: any[]   = detection.mitre_coverage || [];
  const summary: any   = detection.summary        || {};
  const engine: any    = detection.engine_health  || {};

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total Rules"      value={summary.total_rules || 0}     color="var(--text-1)" />
        <StatCard label="Active"           value={summary.active_rules || 0}    color="#22c55e" />
        <StatCard label="Sigma"            value={summary.sigma_rules || 0}     color="#3b82f6" />
        <StatCard label="YARA"             value={summary.yara_rules || 0}      color="#a855f7" />
        <StatCard label="Coverage"         value={`${summary.detection_coverage || 0}%`} color="var(--accent)" sub="MITRE ATT&CK" />
        <StatCard label="Avg Accuracy"     value={`${summary.avg_accuracy || 0}%`}       color="#22c55e" />
        <StatCard label="FP Rate"          value={`${summary.false_positive_rate || 0}%`} color="#eab308" />
        <StatCard label="Success Rate"     value={`${summary.detection_success_rate || 0}%`} color="#22c55e" />
      </div>
      {/* Engine health */}
      <div className="g-card" style={{ padding: 14, display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        {Object.entries(engine).map(([k, v]: [string, any]) => (
          <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: v === 'healthy' ? '#22c55e' : '#eab308', display: 'inline-block' }} />
            <span style={{ fontSize: 11, color: 'var(--text-2)' }}>{k.replace(/_/g, ' ')}</span>
          </div>
        ))}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>Top Rules by Hits</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {rules.slice(0, 8).map((r: any, i: number) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {pill(r.type, RULE_CLR[r.type] || '#6b7280')}
                <span style={{ flex: 1, fontSize: 11, color: 'var(--text-1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.name}</span>
                <span style={{ fontSize: 11, color: r.accuracy >= 90 ? '#22c55e' : r.accuracy >= 70 ? '#eab308' : '#ef4444', fontWeight: 600 }}>{r.accuracy}%</span>
                <span style={{ fontSize: 10, color: 'var(--text-3)', width: 54, textAlign: 'right' }}>{(r.total_hits || 0).toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>MITRE ATT&CK Coverage</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
            {mitre.map((m: any, i: number) => (
              <HorizBar key={i} label={m.tactic} pct={m.pct} color={m.pct >= 75 ? '#22c55e' : m.pct >= 50 ? '#eab308' : '#ef4444'}
                value={`${m.covered}/${m.techniques}`} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Automation tab ────────────────────────────────────────────────────────────

function AutomationTab({ automation }: { automation: any }) {
  if (!automation) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const playbooks: any[] = automation.playbooks || [];
  const trend: any[]     = automation.trend      || [];
  const approval: any    = automation.approval_queue || {};
  const execTrend = trend.map((t: any) => t.executions || 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Playbook Executions" value={(automation.playbook_executions || 0).toLocaleString()} color="var(--accent)" />
        <StatCard label="Script Executions"   value={(automation.script_executions || 0).toLocaleString()} color="#a855f7" />
        <StatCard label="Success Rate"        value={`${automation.automation_success_rate || 0}%`} color="#22c55e" />
        <StatCard label="Hours Saved"         value={`${(automation.analyst_hours_saved || 0).toFixed(0)}h`} color="#22c55e" sub="analyst time saved" />
        <StatCard label="Automation Coverage" value={`${automation.automation_coverage || 0}%`} color="var(--accent)" />
      </div>
      {/* Approval queue */}
      <div className="g-card" style={{ padding: 14, display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'center' }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)' }}>Approval Queue</span>
        {[
          { label: 'Pending', value: approval.pending, color: '#eab308' },
          { label: 'Approved', value: approval.approved, color: '#22c55e' },
          { label: 'Rejected', value: approval.rejected, color: '#ef4444' },
          { label: 'Avg Wait', value: `${approval.avg_wait_mins}m`, color: '#3b82f6' },
        ].map(s => (
          <span key={s.label} style={{ fontSize: 10, background: s.color + '18', borderRadius: 6, padding: '4px 10px', color: s.color, fontWeight: 600 }}>
            {s.label}: {s.value}
          </span>
        ))}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>Playbook Performance</div>
          <table className="g-table" style={{ width: '100%' }}>
            <thead><tr>
              {['Playbook', 'Category', 'Executions', 'Success', 'Hrs Saved', 'Avg Runtime'].map(h => (
                <th key={h} style={{ textAlign: 'left', fontSize: 10, color: 'var(--text-3)', padding: '5px 8px' }}>{h}</th>
              ))}
            </tr></thead>
            <tbody>
              {playbooks.map((p: any, i: number) => (
                <tr key={i}>
                  <td style={{ fontSize: 11, color: 'var(--text-1)', padding: '7px 8px', fontWeight: 500 }}>{p.name}</td>
                  <td style={{ padding: '7px 8px' }}>{pill(p.category?.replace('_', ' '), '#3b82f6')}</td>
                  <td style={{ fontSize: 11, color: 'var(--text-2)', padding: '7px 8px' }}>{(p.total || 0).toLocaleString()}</td>
                  <td style={{ padding: '7px 8px' }}>{pill(`${p.success_rate}%`, p.success_rate >= 90 ? '#22c55e' : '#eab308')}</td>
                  <td style={{ fontSize: 11, color: '#22c55e', padding: '7px 8px' }}>{Number(p.hours_saved || 0).toFixed(0)}h</td>
                  <td style={{ fontSize: 11, color: 'var(--text-3)', padding: '7px 8px' }}>{p.avg_runtime_secs}s</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 10 }}>Execution Volume (30d)</div>
          <SparkBars data={execTrend} color="#a855f7" height={80} />
        </div>
      </div>
    </div>
  );
}

// ── Threats tab ───────────────────────────────────────────────────────────────

function ThreatsTab({ threats }: { threats: any }) {
  if (!threats) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const mitre: any[] = threats.mitre_techniques || [];
  const geo: any[]   = threats.geo_distribution  || [];
  const malware: any[] = threats.malware_families || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="IOC Hits"            value={(threats.ioc_hits || 0).toLocaleString()} color="#ef4444" />
        <StatCard label="Malware Detections"  value={threats.malware_detections || 0}           color="#f97316" />
        <StatCard label="Ransomware"          value={threats.ransomware_detections || 0}        color="#ef4444" />
        <StatCard label="Threat Actor Hits"   value={threats.threat_actor_hits || 0}            color="#a855f7" />
        <StatCard label="Active Campaigns"    value={threats.active_campaigns || 0}             color="#ef4444" />
        <StatCard label="TI Sources"          value={threats.ti_sources || 0}                   color="#3b82f6" />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>MITRE Technique Hits</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {mitre.map((m: any, i: number) => (
              <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                <span style={{ fontSize: 9, fontFamily: 'monospace', background: '#3b82f622', color: '#3b82f6', padding: '2px 5px', borderRadius: 4, flexShrink: 0 }}>{m.technique?.split(' ')[0]}</span>
                <span style={{ flex: 1, fontSize: 11, color: 'var(--text-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m.technique?.split(' ').slice(1).join(' ')}</span>
                <span style={{ fontSize: 11, fontWeight: 600, color: '#ef4444', flexShrink: 0 }}>{m.hits}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>Malware Families</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {malware.map((m: any, i: number) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {pill(m.severity, SEV_CLR[m.severity] || '#6b7280')}
                <span style={{ flex: 1, fontSize: 11, color: 'var(--text-1)' }}>{m.name}</span>
                <span style={{ fontSize: 11, color: '#f97316', fontWeight: 600 }}>{m.detections}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>Geographic Distribution</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {geo.map((g: any, i: number) => (
              <HorizBar key={i} label={g.country} pct={(g.count / (geo[0]?.count || 1)) * 100} color="#a855f7" value={(g.count||0).toLocaleString()} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Endpoints tab ─────────────────────────────────────────────────────────────

function EndpointsTab({ endpoints }: { endpoints: any }) {
  if (!endpoints) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const platforms: any[]  = endpoints.endpoint_platforms || [];
  const isolations: any[] = endpoints.recent_isolations  || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total Endpoints"  value={(endpoints.total_endpoints || 0).toLocaleString()} color="var(--text-1)" />
        <StatCard label="Healthy"          value={(endpoints.healthy || 0).toLocaleString()} color="#22c55e" />
        <StatCard label="Offline"          value={endpoints.offline || 0}            color="#eab308" />
        <StatCard label="Quarantined"      value={endpoints.quarantined || 0}        color="#ef4444" />
        <StatCard label="Isolated"         value={endpoints.isolated || 0}           color="#ef4444" />
        <StatCard label="Coverage"         value={`${endpoints.coverage_pct || 0}%`} color="#22c55e" />
        <StatCard label="Firewall Blocks"  value={(endpoints.firewall_blocks || 0).toLocaleString()} color="#f97316" />
        <StatCard label="Net Anomalies"    value={endpoints.network_anomalies || 0}  color="#eab308" />
        <StatCard label="DPI Events"       value={(endpoints.dpi_events || 0).toLocaleString()} color="#3b82f6" />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>Platform Coverage</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {platforms.map((p: any, i: number) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ width: 60, fontSize: 11, color: 'var(--text-2)' }}>{p.platform}</span>
                <div style={{ flex: 1, height: 6, borderRadius: 3, background: 'var(--border)', overflow: 'hidden' }}>
                  <div style={{ width: `${p.coverage}%`, height: '100%', background: '#22c55e', borderRadius: 3 }} />
                </div>
                <span style={{ fontSize: 10, color: 'var(--text-3)', width: 40, textAlign: 'right' }}>{(p.count || 0).toLocaleString()}</span>
                <span style={{ fontSize: 10, color: '#22c55e' }}>{p.coverage}%</span>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 14, padding: '10px 12px', borderRadius: 8, background: 'var(--bg-2)', display: 'flex', gap: 16 }}>
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-3)' }}>Network Throughput</div>
              <div style={{ fontSize: 16, fontWeight: 700, color: '#3b82f6' }}>{endpoints.network_throughput_gbps} Gbps</div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-3)' }}>Blocked Connections</div>
              <div style={{ fontSize: 16, fontWeight: 700, color: '#ef4444' }}>{(endpoints.blocked_connections || 0).toLocaleString()}</div>
            </div>
          </div>
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>Recent Endpoint Isolations</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {isolations.map((iso: any, i: number) => (
              <div key={i} style={{ padding: '10px 12px', borderRadius: 8, background: '#ef444418', border: '1px solid #ef444444' }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: '#ef4444', marginBottom: 3 }}>{iso.host}</div>
                <div style={{ fontSize: 11, color: 'var(--text-2)', marginBottom: 2 }}>{iso.reason}</div>
                <div style={{ fontSize: 10, color: 'var(--text-3)' }}>Isolated: {fmtTime(iso.isolated_at)}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Vulnerabilities tab ───────────────────────────────────────────────────────

function VulnsTab({ vulns }: { vulns: any }) {
  if (!vulns) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const top: any[]   = vulns.risk_prioritized || [];
  const trend: any[] = vulns.trend            || [];
  const critTrend = trend.map((t: any) => t.critical || 0);
  const patchTrend = trend.map((t: any) => t.patch_compliance || 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total"            value={(vulns.total || 0).toLocaleString()} color="var(--text-1)" />
        <StatCard label="Critical"         value={vulns.critical || 0}    color="#ef4444" />
        <StatCard label="High"             value={vulns.high || 0}        color="#f97316" />
        <StatCard label="Exploitable"      value={vulns.exploitable || 0} color="#ef4444" />
        <StatCard label="Patch Compliance" value={`${vulns.patch_compliance || 0}%`} color={vulns.patch_compliance >= 90 ? '#22c55e' : '#eab308'} />
        <StatCard label="Overdue"          value={vulns.overdue_remediations || 0} color="#ef4444" />
        <StatCard label="MTTR"             value={`${vulns.mttr_days || 0}d`} sub="mean time to remediate" />
        <StatCard label="Verification"     value={`${vulns.verification_success_rate || 0}%`} color="#22c55e" />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12 }}>Risk-Prioritized Vulnerabilities</div>
          <table className="g-table" style={{ width: '100%' }}>
            <thead><tr>
              {['CVE', 'CVSS', 'Affected', 'Status'].map(h => (
                <th key={h} style={{ textAlign: 'left', fontSize: 10, color: 'var(--text-3)', padding: '5px 8px' }}>{h}</th>
              ))}
            </tr></thead>
            <tbody>
              {top.map((v: any, i: number) => {
                const stCl: Record<string, string> = { open: '#ef4444', in_progress: '#3b82f6', overdue: '#f97316', patched: '#22c55e' };
                return (
                  <tr key={i}>
                    <td style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--accent)', padding: '7px 8px' }}>{v.cve}</td>
                    <td style={{ padding: '7px 8px' }}>{pill(String(v.cvss), v.cvss >= 9 ? '#ef4444' : v.cvss >= 7 ? '#f97316' : '#eab308')}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-2)', padding: '7px 8px' }}>{v.affected} systems</td>
                    <td style={{ padding: '7px 8px' }}>{pill(v.status?.replace('_', ' '), stCl[v.status] || '#6b7280')}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div className="g-card" style={{ padding: 16 }}>
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 8 }}>Critical Vulns Trend (30d)</div>
            <SparkBars data={critTrend} color="#ef4444" height={48} />
          </div>
          <div className="g-card" style={{ padding: 16 }}>
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 8 }}>Patch Compliance Trend (30d)</div>
            <SparkBars data={patchTrend} color="#22c55e" height={48} />
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
        <StatCard label="Compliance Score"    value={`${compliance.compliance_score || 0}%`} color="#22c55e" />
        <StatCard label="Passed Controls"     value={(compliance.passed_controls || 0).toLocaleString()} color="#22c55e" />
        <StatCard label="Failed Controls"     value={compliance.failed_controls || 0} color="#ef4444" />
        <StatCard label="Frameworks"          value={compliance.framework_count || 0} color="var(--accent)" />
        <StatCard label="Audit Readiness"     value={`${compliance.audit_readiness || 0}%`} color="#22c55e" />
        <StatCard label="Open Findings"       value={compliance.open_findings || 0}    color="#eab308" />
        <StatCard label="Policy Violations"   value={compliance.policy_violations || 0} color="#ef4444" />
        <StatCard label="Remediation Progress" value={`${compliance.remediation_progress || 0}%`} color="#3b82f6" />
      </div>
      {frameworks.length > 0 && (
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 14 }}>Framework Status</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {frameworks.map((f: any, i: number) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <ScoreRing score={f.score || 0} size={44} />
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-1)' }}>{f.name}</div>
                  <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>{f.passed}/{f.total} controls · {f.category}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Infrastructure tab ────────────────────────────────────────────────────────

function InfraTab({ infra }: { infra: any }) {
  if (!infra) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const components: any[] = infra.components || [];
  const agents: any        = infra.agent_connectivity || {};

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Log Ingestion Rate" value={`${((infra.log_ingestion_rate || 0)/1e6).toFixed(1)}M/day`} color="var(--accent)" />
        <StatCard label="Events Per Second"  value={(infra.eps || 0).toLocaleString()} color="#3b82f6" />
        <StatCard label="Storage Used"       value={`${infra.storage_utilization || 0}%`} color={infra.storage_utilization > 80 ? '#ef4444' : '#22c55e'} />
        <StatCard label="Agents Online"      value={`${agents.online || 0}/${agents.total || 0}`} color="#22c55e" />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 10 }}>
        {components.map((comp: any, i: number) => (
          <div key={i} className="g-card" style={{ padding: 14, borderLeft: `3px solid ${STATUS_CLR[comp.status] || '#6b7280'}` }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <span style={{ flex: 1, fontSize: 12, fontWeight: 600, color: 'var(--text-1)' }}>{comp.name}</span>
              {pill(comp.status, STATUS_CLR[comp.status] || '#6b7280')}
            </div>
            <div style={{ display: 'flex', gap: 16, marginBottom: 8 }}>
              <div>
                <div style={{ fontSize: 9, color: 'var(--text-3)' }}>HEALTH</div>
                <div style={{ fontSize: 16, fontWeight: 700, color: comp.health >= 95 ? '#22c55e' : comp.health >= 80 ? '#eab308' : '#ef4444' }}>{comp.health}%</div>
              </div>
              <div>
                <div style={{ fontSize: 9, color: 'var(--text-3)' }}>LATENCY</div>
                <div style={{ fontSize: 16, fontWeight: 700, color: comp.latency_ms > 100 ? '#ef4444' : '#22c55e' }}>{comp.latency_ms}ms</div>
              </div>
              <div>
                <div style={{ fontSize: 9, color: 'var(--text-3)' }}>UPTIME</div>
                <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)' }}>{comp.uptime}%</div>
              </div>
            </div>
            <div style={{ height: 4, borderRadius: 2, background: 'var(--border)', overflow: 'hidden' }}>
              <div style={{ width: `${comp.health}%`, height: '100%', background: comp.health >= 95 ? '#22c55e' : comp.health >= 80 ? '#eab308' : '#ef4444', borderRadius: 2 }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── AI Insights tab ───────────────────────────────────────────────────────────

function AIInsightsTab() {
  const [action, setAction] = useState<string | null>(null);
  const [resp, setResp]     = useState('');
  const [loading, setLoading] = useState(false);

  async function run(a: string) {
    setAction(a); setLoading(true); setResp('');
    const r = await socMetricsAPI.ai({ action: a }).catch(() => null);
    setResp((r as any)?.data?.response || 'No response.');
    setLoading(false);
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 10 }}>
        {AI_ACTIONS.map(a => (
          <button key={a.id} onClick={() => run(a.id)} className="g-btn g-btn-ghost"
            style={{ fontSize: 12, textAlign: 'left', fontWeight: action === a.id ? 700 : 400,
              color: action === a.id ? 'var(--accent)' : 'var(--text-2)',
              borderColor: action === a.id ? 'var(--accent)' : 'var(--border)',
              padding: '10px 14px' }}>
            {a.label}
          </button>
        ))}
      </div>
      {loading && <div style={{ padding: 20, textAlign: 'center', color: 'var(--text-3)' }}>Analyzing SOC data…</div>}
      {resp && (
        <div className="g-card" style={{ padding: 20, fontSize: 13, whiteSpace: 'pre-wrap', lineHeight: 1.7, color: 'var(--text-1)' }}>
          {resp}
        </div>
      )}
      {!resp && !loading && (
        <div className="g-card" style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)', fontSize: 13 }}>
          Select an insight type above to generate AI-powered SOC analysis
        </div>
      )}
    </div>
  );
}

// ── Reports tab ───────────────────────────────────────────────────────────────

function ReportsTab({ reports, onRefresh }: { reports: any[]; onRefresh: () => void }) {
  const [generating, setGenerating] = useState(false);
  const [form, setForm] = useState({ title: '', report_type: 'daily_operations', period_days: 1 });

  async function generate() {
    setGenerating(true);
    await socMetricsAPI.generateReport(form).catch(() => null);
    setGenerating(false);
    onRefresh();
  }

  const typeColors: Record<string, string> = {
    daily_operations: '#22c55e', weekly_performance: '#3b82f6', monthly_kpi: '#a855f7',
    analyst_performance: '#f97316', detection_performance: '#06b6d4',
    automation_effectiveness: '#eab308', sla_compliance: '#ef4444',
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="g-card" style={{ padding: 16, display: 'flex', gap: 10, alignItems: 'flex-end', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 200 }}>
          <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 4 }}>Report Title</div>
          <input className="g-input" style={{ width: '100%', fontSize: 12 }} placeholder="e.g. Daily SOC Operations Report"
            value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))} />
        </div>
        <div>
          <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 4 }}>Type</div>
          <select className="g-input" style={{ fontSize: 12 }} value={form.report_type}
            onChange={e => setForm(f => ({ ...f, report_type: e.target.value }))}>
            {[
              ['daily_operations', 'Daily SOC Operations'],
              ['weekly_performance', 'Weekly Performance'],
              ['monthly_kpi', 'Monthly KPI'],
              ['analyst_performance', 'Analyst Performance'],
              ['detection_performance', 'Detection Performance'],
              ['automation_effectiveness', 'Automation Effectiveness'],
              ['sla_compliance', 'SLA Compliance'],
            ].map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </div>
        <div>
          <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 4 }}>Period</div>
          <select className="g-input" style={{ fontSize: 12 }} value={form.period_days}
            onChange={e => setForm(f => ({ ...f, period_days: Number(e.target.value) }))}>
            <option value={1}>Daily</option>
            <option value={7}>Weekly</option>
            <option value={30}>Monthly</option>
            <option value={90}>Quarterly</option>
          </select>
        </div>
        <button className="g-btn" onClick={generate} disabled={generating || !form.title} style={{ fontSize: 12 }}>
          {generating ? 'Generating…' : 'Generate'}
        </button>
      </div>
      <div className="g-card" style={{ padding: 0, overflow: 'hidden' }}>
        <table className="g-table" style={{ width: '100%' }}>
          <thead><tr>
            {['Title', 'Type', 'Period', 'Generated By', 'Date', 'Size'].map(h => (
              <th key={h} style={{ textAlign: 'left', fontSize: 10, color: 'var(--text-3)', padding: '10px 14px' }}>{h}</th>
            ))}
          </tr></thead>
          <tbody>
            {reports.map((r: any, i: number) => (
              <tr key={i}>
                <td style={{ fontSize: 12, color: 'var(--text-1)', padding: '10px 14px', fontWeight: 500, maxWidth: 280 }}>{r.title}</td>
                <td style={{ padding: '10px 14px' }}>{pill(r.report_type?.replace(/_/g, ' '), typeColors[r.report_type] || '#6b7280')}</td>
                <td style={{ fontSize: 11, color: 'var(--text-3)', padding: '10px 14px', whiteSpace: 'nowrap' }}>{fmt(r.period_start)} – {fmt(r.period_end)}</td>
                <td style={{ fontSize: 11, color: 'var(--text-2)', padding: '10px 14px' }}>{r.generated_by}</td>
                <td style={{ fontSize: 11, color: 'var(--text-3)', padding: '10px 14px' }}>{fmt(r.created_at)}</td>
                <td style={{ fontSize: 11, color: 'var(--text-3)', padding: '10px 14px' }}>{r.size_bytes ? `${(r.size_bytes / 1024).toFixed(0)} KB` : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Audit tab ─────────────────────────────────────────────────────────────────

function AuditTab({ audit }: { audit: any[] }) {
  const actionColor: Record<string, string> = {
    dashboard_accessed: '#3b82f6', report_generated: '#22c55e',
    kpi_configured: '#eab308', dashboard_shared: '#a855f7',
    widget_configured: '#06b6d4',
  };
  const actionIcon: Record<string, string> = {
    report_generated: '📄', dashboard_accessed: '📊', kpi_configured: '🎯',
    dashboard_shared: '📤', widget_configured: '⚙️',
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

// ── Page ──────────────────────────────────────────────────────────────────────

export default function SOCMetricsPage() {
  const [tab, setTab]         = useState<Tab>('dashboard');
  const [showAI, setShowAI]   = useState(false);
  const [loading, setLoading] = useState(true);

  const [dash, setDash]           = useState<any>(null);
  const [alerts, setAlerts]       = useState<any>(null);
  const [incidents, setIncidents] = useState<any>(null);
  const [cases, setCases]         = useState<any>(null);
  const [analysts, setAnalysts]   = useState<any>(null);
  const [detection, setDetection] = useState<any>(null);
  const [automation, setAutomation] = useState<any>(null);
  const [threats, setThreats]     = useState<any>(null);
  const [endpoints, setEndpoints] = useState<any>(null);
  const [vulns, setVulns]         = useState<any>(null);
  const [compliance, setCompliance] = useState<any>(null);
  const [infra, setInfra]         = useState<any>(null);
  const [reports, setReports]     = useState<any[]>([]);
  const [notifs, setNotifs]       = useState<any[]>([]);
  const [audit, setAudit]         = useState<any[]>([]);

  const loadAll = useCallback(async () => {
    setLoading(true);
    const [d, al, inc, cs, an, det, aut, th, ep, vl, comp, inf, rp, nt, au] = await Promise.all([
      socMetricsAPI.getDashboard(),
      socMetricsAPI.getAlerts(),
      socMetricsAPI.getIncidents(),
      socMetricsAPI.getCases(),
      socMetricsAPI.getAnalysts(),
      socMetricsAPI.getDetection(),
      socMetricsAPI.getAutomation(),
      socMetricsAPI.getThreats(),
      socMetricsAPI.getEndpoints(),
      socMetricsAPI.getVulns(),
      socMetricsAPI.getCompliance(),
      socMetricsAPI.getInfrastructure(),
      socMetricsAPI.getReports(),
      socMetricsAPI.getNotifications(),
      socMetricsAPI.getAudit(),
    ]);
    setDash((d as any)?.data);
    setAlerts((al as any)?.data);
    setIncidents((inc as any)?.data);
    setCases((cs as any)?.data);
    setAnalysts((an as any)?.data);
    setDetection((det as any)?.data);
    setAutomation((aut as any)?.data);
    setThreats((th as any)?.data);
    setEndpoints((ep as any)?.data);
    setVulns((vl as any)?.data);
    setCompliance((comp as any)?.data);
    setInfra((inf as any)?.data);
    setReports(Array.isArray((rp as any)?.data) ? (rp as any).data : []);
    setNotifs(Array.isArray((nt as any)?.data) ? (nt as any).data : []);
    setAudit(Array.isArray((au as any)?.data) ? (au as any).data : []);
    setLoading(false);
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  const unreadCount = notifs.filter(n => !n.read).length;

  const tabBar = (
    <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', overflowX: 'auto', flexShrink: 0 }}>
      {TABS.map(t => (
        <button key={t.id} onClick={() => setTab(t.id)}
          style={{ position: 'relative', padding: '10px 14px', fontSize: 12, whiteSpace: 'nowrap', background: 'none', border: 'none', cursor: 'pointer', color: tab === t.id ? 'var(--accent)' : 'var(--text-2)', borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent', fontWeight: tab === t.id ? 600 : 400 }}>
          {t.label}
          {t.id === 'ai' && (
            <span style={{ position: 'absolute', top: 4, right: 2, fontSize: 8, color: 'var(--accent)' }}>✦</span>
          )}
        </button>
      ))}
    </div>
  );

  const actions = (
    <div style={{ display: 'flex', gap: 8 }}>
      {unreadCount > 0 && (
        <button className="g-btn g-btn-ghost" style={{ fontSize: 12, position: 'relative' }} onClick={() => setTab('audit')}>
          <span style={{ position: 'absolute', top: -4, right: -4, width: 16, height: 16, borderRadius: '50%', background: '#ef4444', fontSize: 9, color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700 }}>{unreadCount}</span>
          Alerts
        </button>
      )}
      <button className="g-btn" style={{ fontSize: 12 }} onClick={() => setShowAI(v => !v)}>
        ✦ AI Insights
      </button>
    </div>
  );

  function renderTab() {
    if (loading) return <div style={{ padding: 60, textAlign: 'center', color: 'var(--text-3)' }}>Loading SOC metrics…</div>;
    switch (tab) {
      case 'dashboard':  return <DashboardTab  dash={dash} />;
      case 'alerts':     return <AlertsTab     alerts={alerts} />;
      case 'incidents':  return <IncidentsTab  incidents={incidents} />;
      case 'cases':      return <CasesTab      cases={cases} />;
      case 'analysts':   return <AnalystsTab   analysts={analysts} />;
      case 'detection':  return <DetectionTab  detection={detection} />;
      case 'automation': return <AutomationTab automation={automation} />;
      case 'threats':    return <ThreatsTab    threats={threats} />;
      case 'endpoints':  return <EndpointsTab  endpoints={endpoints} />;
      case 'vulns':      return <VulnsTab      vulns={vulns} />;
      case 'compliance': return <ComplianceTab compliance={compliance} />;
      case 'infra':      return <InfraTab      infra={infra} />;
      case 'ai':         return <AIInsightsTab />;
      case 'reports':    return <ReportsTab    reports={reports} onRefresh={loadAll} />;
      case 'audit':      return <AuditTab      audit={audit} />;
      default:           return null;
    }
  }

  return (
    <RootLayout title="SOC Metrics" subtitle="Security Operations Center Intelligence" actions={actions}>
      {tabBar}
      <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>
        {renderTab()}
      </div>
      {showAI && <AIPanel onClose={() => setShowAI(false)} />}
    </RootLayout>
  );
}
