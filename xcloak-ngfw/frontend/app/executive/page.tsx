'use client';

import { useState, useEffect, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { executiveAPI, scheduledReportsAPI } from '@/lib/api';
import { ExecutiveMetrics, ScheduledReport } from '@/types';
import {
  Download, Plus, Trash2, Clock, Shield, Target,
  TrendingUp, TrendingDown, Minus, Mail, Calendar,
  BarChart2, AlertTriangle, CheckCircle2, X,
} from 'lucide-react';

// ─── Metric KPI card ─────────────────────────────────────────────────────────
function KPI({ label, value, sub, warn, good }: {
  label: string; value: string | number; sub: string; warn?: boolean; good?: boolean;
}) {
  const color = warn ? 'var(--red)' : good ? 'var(--accent)' : 'var(--text-1)';
  const Icon = warn ? TrendingUp : good ? TrendingDown : Minus;
  return (
    <div className="g-card p-5">
      <div className="flex items-start justify-between mb-3">
        <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>{label}</p>
        <Icon className="h-4 w-4 opacity-50" style={{ color }} />
      </div>
      <p className="text-2xl font-bold" style={{ color }}>{value}</p>
      <p className="text-[11px] mt-1" style={{ color: 'var(--text-3)' }}>{sub}</p>
    </div>
  );
}

// ─── Bar chart (CSS-only) ────────────────────────────────────────────────────
function MiniBarChart({ data, color = 'var(--accent)' }: {
  data: Array<{ label?: string; date?: string; count?: number; score?: number }>;
  color?: string;
}) {
  const values = data.map(d => d.count ?? d.score ?? 0);
  const max = Math.max(...values, 1);
  return (
    <div className="flex items-end gap-px h-16">
      {data.map((d, i) => (
        <div key={i} className="flex-1 flex flex-col items-center gap-0.5">
          <div className="w-full rounded-t-sm" title={`${d.date || d.label}: ${values[i]}`}
            style={{
              height: `${Math.max(4, (values[i] / max) * 56)}px`,
              background: color,
              opacity: 0.4 + (values[i] / max) * 0.6,
            }} />
        </div>
      ))}
    </div>
  );
}

// ─── Horizontal bar ──────────────────────────────────────────────────────────
function HorizBar({ label, count, max, color }: { label: string; count: number; max: number; color: string }) {
  const pct = max > 0 ? (count / max) * 100 : 0;
  return (
    <div className="flex items-center gap-3">
      <p className="w-28 shrink-0 text-xs capitalize truncate" style={{ color: 'var(--text-2)' }}>{label}</p>
      <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: 'var(--glass-bg-2)' }}>
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color, transition: 'width 0.5s' }} />
      </div>
      <p className="w-8 text-right text-xs tabular-nums" style={{ color: 'var(--text-2)' }}>{count}</p>
    </div>
  );
}

const SEV_COLOR: Record<string, string> = { critical: '#f85149', high: '#fb923c', medium: '#fbbf24', low: '#22c55e' };
const PHASE_COLOR: Record<string, string> = {
  identification: '#3b82f6', containment: '#a855f7', eradication: '#ec4899',
  recovery: '#10b981', lessons_learned: '#f59e0b', closed: '#6b7280',
};

// ─── Scheduled report row ────────────────────────────────────────────────────
function ReportRow({ r, onDelete }: { r: ScheduledReport; onDelete: () => void }) {
  return (
    <div className="flex items-center gap-3 px-4 py-3 rounded-lg"
      style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}>
      <div className="flex-1 min-w-0">
        <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{r.name}</p>
        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
          {r.schedule} · {r.recipients.join(', ')}
          {r.last_sent_at && ` · Last sent ${new Date(r.last_sent_at).toLocaleDateString()}`}
        </p>
      </div>
      <span className="text-[10px] px-2 py-0.5 rounded" style={{
        background: r.enabled ? 'rgba(16,185,129,0.12)' : 'var(--glass-bg)',
        color: r.enabled ? 'var(--accent)' : 'var(--text-3)',
        border: '1px solid var(--border)',
      }}>{r.enabled ? 'active' : 'disabled'}</span>
      <button onClick={onDelete} className="p-1.5 rounded" style={{ color: 'var(--text-3)' }}
        onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--red)'}
        onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
        <Trash2 className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}

// ─── Create report modal ─────────────────────────────────────────────────────
function CreateReportModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({
    name: '', schedule: '0 8 * * 1', recipients: '', enabled: true, report_type: 'executive',
  });
  const [saving, setSaving] = useState(false);

  const PRESETS = [
    { label: 'Weekly Mon 8am', value: '0 8 * * 1' },
    { label: 'Daily 8am', value: '0 8 * * *' },
    { label: 'Monthly 1st', value: '0 8 1 * *' },
  ];

  const submit = async () => {
    if (!form.name.trim() || !form.recipients.trim()) return;
    setSaving(true);
    await scheduledReportsAPI.create({
      ...form,
      recipients: form.recipients.split(',').map(s => s.trim()).filter(Boolean),
    });
    setSaving(false);
    onCreated();
    onClose();
  };

  return (
    <div className="g-modal-backdrop" onClick={onClose}>
      <div className="g-modal" style={{ maxWidth: 480 }} onClick={e => e.stopPropagation()}>
        <div className="p-5" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Schedule Report</h2>
        </div>
        <div className="p-5 space-y-3">
          <input className="g-input w-full" placeholder="Report name *" value={form.name}
            onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
          <div>
            <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Schedule (cron)</label>
            <div className="flex gap-1 mb-2 flex-wrap">
              {PRESETS.map(p => (
                <button key={p.value} onClick={() => setForm(f => ({ ...f, schedule: p.value }))}
                  className="text-[11px] px-2 py-1 rounded-lg transition-colors"
                  style={{
                    background: form.schedule === p.value ? 'var(--accent)' : 'var(--glass-bg-2)',
                    color: form.schedule === p.value ? '#000' : 'var(--text-2)',
                    border: '1px solid var(--border)',
                  }}>{p.label}</button>
              ))}
            </div>
            <input className="g-input w-full font-mono text-xs" value={form.schedule}
              onChange={e => setForm(f => ({ ...f, schedule: e.target.value }))} />
            <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>min hour day month weekday (0=Sun)</p>
          </div>
          <div>
            <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Recipients (comma-separated)</label>
            <input className="g-input w-full" placeholder="ciso@company.com, board@company.com"
              value={form.recipients} onChange={e => setForm(f => ({ ...f, recipients: e.target.value }))} />
          </div>
        </div>
        <div className="flex gap-3 px-5 pb-5">
          <button onClick={onClose} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
          <button onClick={submit} disabled={!form.name.trim() || !form.recipients.trim() || saving}
            className="g-btn g-btn-primary flex-1 justify-center">
            {saving ? 'Saving…' : 'Schedule'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────
export default function ExecutivePage() {
  const [metrics, setMetrics] = useState<ExecutiveMetrics | null>(null);
  const [reports, setReports] = useState<ScheduledReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [showCreate, setShowCreate] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    const [mRes, rRes] = await Promise.allSettled([executiveAPI.getMetrics(), scheduledReportsAPI.getAll()]);
    if (mRes.status === 'fulfilled') setMetrics(mRes.value.data);
    if (rRes.status === 'fulfilled') setReports(rRes.value.data || []);
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const downloadPDF = async () => {
    setDownloading(true);
    const r = await executiveAPI.downloadReport();
    const url = URL.createObjectURL(new Blob([r.data], { type: 'application/pdf' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `xcloak-executive-report-${new Date().toISOString().slice(0,10)}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
    setDownloading(false);
  };

  const deleteReport = async (id: number) => {
    await scheduledReportsAPI.delete(id);
    setReports(r => r.filter(x => x.id !== id));
  };

  const m = metrics;

  return (
    <RootLayout title="Executive Dashboard" subtitle="Security posture · MTTR/MTTD · SLA compliance"
      actions={
        <button onClick={downloadPDF} disabled={downloading}
          className="g-btn g-btn-primary flex items-center gap-1.5 text-xs">
          <Download className="h-3.5 w-3.5" />
          {downloading ? 'Generating…' : 'Download PDF'}
        </button>
      }>

      {loading ? (
        <div className="py-24 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading metrics…</div>
      ) : !m ? (
        <div className="py-24 text-center text-sm" style={{ color: 'var(--text-3)' }}>Failed to load metrics.</div>
      ) : (
        <div className="space-y-6">

          {/* KPI row */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <KPI label="MTTR" value={`${m.mttr_hours.toFixed(1)}h`} sub="Mean time to resolve" warn={m.mttr_hours > 24} good={m.mttr_hours > 0 && m.mttr_hours <= 4} />
            <KPI label="MTTD" value={`${m.mttd_hours.toFixed(1)}h`} sub="Mean time to detect" warn={m.mttd_hours > 12} good={m.mttd_hours <= 2} />
            <KPI label="SLA Compliance" value={`${m.sla_compliance_rate.toFixed(0)}%`} sub="Cases closed within SLA" warn={m.sla_compliance_rate < 80} good={m.sla_compliance_rate >= 95} />
            <KPI label="Open Cases" value={m.open_cases} sub={`${m.critical_cases} critical`} warn={m.critical_cases > 0} good={m.open_cases === 0} />
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <KPI label="Total Assets" value={m.total_assets} sub={`${m.critical_assets} critical`} warn={m.critical_assets > 0} />
            <KPI label="Online Agents" value={m.online_agents} sub="active endpoints" good={m.online_agents > 0} />
            <KPI label="30d Alerts" value={m.total_alerts.toLocaleString()} sub="last 30 days" warn={m.total_alerts > 10000} />
            <KPI label="SLA Breaches" value={m.cases_by_severity.reduce((n,c)=>n+(c.label==='sla_breach'?c.count:0),0)} sub="total breached" warn={false} />
          </div>

          {/* Alert volume + Risk trend */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="g-card p-5">
              <div className="flex items-center gap-2 mb-4">
                <BarChart2 className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Alert Volume — Last 30 Days</p>
              </div>
              {m.alert_volume.length > 0 ? (
                <>
                  <MiniBarChart data={m.alert_volume} />
                  <div className="flex justify-between mt-1 text-[10px]" style={{ color: 'var(--text-3)' }}>
                    <span>{m.alert_volume[0]?.date}</span>
                    <span>{m.alert_volume[m.alert_volume.length-1]?.date}</span>
                  </div>
                </>
              ) : (
                <p className="text-xs py-8 text-center" style={{ color: 'var(--text-3)' }}>No alert data yet.</p>
              )}
            </div>

            <div className="g-card p-5">
              <div className="flex items-center gap-2 mb-4">
                <TrendingUp className="h-4 w-4" style={{ color: '#fb923c' }} />
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Risk Score Trend — Last 30 Days</p>
              </div>
              {m.risk_trend.length > 0 ? (
                <>
                  <MiniBarChart data={m.risk_trend} color="#fb923c" />
                  <div className="flex justify-between mt-1 text-[10px]" style={{ color: 'var(--text-3)' }}>
                    <span>{m.risk_trend[0]?.date}</span>
                    <span>{m.risk_trend[m.risk_trend.length-1]?.date}</span>
                  </div>
                </>
              ) : (
                <p className="text-xs py-8 text-center" style={{ color: 'var(--text-3)' }}>No risk data yet.</p>
              )}
            </div>
          </div>

          {/* Cases by severity + phase + MITRE tactics */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="g-card p-5">
              <p className="text-sm font-semibold mb-4" style={{ color: 'var(--text-1)' }}>Cases by Severity</p>
              {m.cases_by_severity.length === 0 ? (
                <p className="text-xs py-4 text-center" style={{ color: 'var(--text-3)' }}>No cases yet.</p>
              ) : (
                <div className="space-y-2">
                  {m.cases_by_severity.map(c => (
                    <HorizBar key={c.label} label={c.label} count={c.count}
                      max={Math.max(...m.cases_by_severity.map(x => x.count))}
                      color={SEV_COLOR[c.label] || 'var(--accent)'} />
                  ))}
                </div>
              )}
            </div>

            <div className="g-card p-5">
              <p className="text-sm font-semibold mb-4" style={{ color: 'var(--text-1)' }}>IR Phase Distribution</p>
              {m.cases_by_phase.length === 0 ? (
                <p className="text-xs py-4 text-center" style={{ color: 'var(--text-3)' }}>No cases yet.</p>
              ) : (
                <div className="space-y-2">
                  {m.cases_by_phase.map(c => (
                    <HorizBar key={c.label} label={c.label} count={c.count}
                      max={Math.max(...m.cases_by_phase.map(x => x.count))}
                      color={PHASE_COLOR[c.label] || 'var(--accent)'} />
                  ))}
                </div>
              )}
            </div>

            <div className="g-card p-5">
              <p className="text-sm font-semibold mb-4" style={{ color: 'var(--text-1)' }}>Top MITRE ATT&CK Tactics</p>
              {m.top_mitre_tactics.length === 0 ? (
                <p className="text-xs py-4 text-center" style={{ color: 'var(--text-3)' }}>No MITRE data yet.</p>
              ) : (
                <div className="space-y-2">
                  {m.top_mitre_tactics.slice(0, 6).map(c => (
                    <HorizBar key={c.label} label={c.label} count={c.count}
                      max={Math.max(...m.top_mitre_tactics.map(x => x.count))}
                      color="#a855f7" />
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Scheduled reports */}
          <div className="g-card p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Calendar className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Scheduled Reports</p>
              </div>
              <button onClick={() => setShowCreate(true)}
                className="g-btn g-btn-ghost text-xs flex items-center gap-1">
                <Plus className="h-3.5 w-3.5" /> Schedule
              </button>
            </div>
            {reports.length === 0 ? (
              <div className="py-8 text-center">
                <Mail className="mx-auto h-8 w-8 mb-2 opacity-20" style={{ color: 'var(--text-3)' }} />
                <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                  No scheduled reports. Schedule a weekly PDF for your CISO or board.
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                {reports.map(r => <ReportRow key={r.id} r={r} onDelete={() => deleteReport(r.id)} />)}
              </div>
            )}
          </div>

        </div>
      )}

      {showCreate && <CreateReportModal onClose={() => setShowCreate(false)} onCreated={load} />}
    </RootLayout>
  );
}
