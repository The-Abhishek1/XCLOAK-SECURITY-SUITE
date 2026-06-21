'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { complianceAPI, exportAPI } from '@/lib/api';
import { timeAgo, formatDate, sevClass } from '@/lib/utils';
import {
  FileText, Plus, Trash2, Download, Shield, AlertTriangle,
  Bug, Activity, Users, Eye, ChevronDown, ChevronUp, X,
  CheckCircle, XCircle, Target, BarChart3,
} from 'lucide-react';
import api from '@/lib/api';

const REPORT_TYPES = [
  { id: 'full',          label: 'Full Compliance Report', icon: Shield },
  { id: 'vulnerability', label: 'Vulnerability Assessment', icon: Bug },
  { id: 'incident',      label: 'Incident Summary',        icon: AlertTriangle },
  { id: 'audit',         label: 'Audit Trail Export',      icon: Activity },
];

const EXPORTS = [
  { label: 'Alerts CSV',          icon: Download, url: exportAPI.alertsCSV },
  { label: 'Incidents CSV',       icon: Download, url: exportAPI.incidentsCSV },
  { label: 'Vulnerabilities CSV', icon: Download, url: exportAPI.vulnsCSV },
  { label: 'Audit Log JSON',      icon: Download, url: exportAPI.auditJSON },
];

interface Report {
  id: number;
  title: string;
  report_type: string;
  generated_by: string;
  summary: any;
  created_at: string;
}

interface ComplianceCheck {
  id: string;
  name: string;
  category: string;
  passed: boolean;
  detail: string;
  severity: string;
}

interface FrameworkScore {
  framework: string;
  score: number;
  passed: number;
  failed: number;
  checks: ComplianceCheck[];
}

const SCORE_COLOR = (score: number) =>
  score >= 80 ? 'var(--green)' : score >= 60 ? 'var(--yellow)' : 'var(--red)';

const SCORE_BG = (score: number) =>
  score >= 80 ? 'rgba(52,211,153,0.12)' : score >= 60 ? 'rgba(251,191,36,0.12)' : 'rgba(248,81,73,0.12)';

export default function CompliancePage() {
  const [reports, setReports]   = useState<Report[]>([]);
  const [loading, setLoading]   = useState(true);
  const [generating, setGenerating] = useState(false);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [selType, setSelType]   = useState('full');
  const [toast, setToast]       = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [frameworkScores, setFrameworkScores] = useState<Record<number, FrameworkScore[]>>({});
  const [loadingScores, setLoadingScores] = useState<number | null>(null);
  const [expandedFramework, setExpandedFramework] = useState<string | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try { const r = await complianceAPI.getAll(); setReports(r.data || []); }
    finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const generate = async () => {
    setGenerating(true);
    try {
      await complianceAPI.generate(selType);
      await load();
      setShowModal(false);
      notify('Report generated successfully');
    } catch {
      notify('Failed to generate report');
    } finally {
      setGenerating(false);
    }
  };

  const del = async (id: number) => {
    try { await complianceAPI.delete(id); setReports(r => r.filter(x => x.id !== id)); notify('Report deleted'); }
    catch { notify('Failed to delete report'); }
  };

  const downloadExport = (urlFn: () => string) => {
    const token = localStorage.getItem('token') || '';
    const a = document.createElement('a');
    a.href = urlFn() + (token ? `?token=${token}` : '');
    a.download = '';
    a.click();
  };

  const parseSummary = (r: Report): any => {
    if (typeof r.summary === 'object') return r.summary;
    try { return JSON.parse(r.summary); } catch { return {}; }
  };

  return (
    <RootLayout title="Compliance & Reports" subtitle="Platform health snapshots and audit exports"
      onRefresh={() => load(true)} refreshing={refreshing}
      actions={
        <button onClick={() => setShowModal(true)} className="g-btn g-btn-primary text-xs">
          <Plus className="h-3.5 w-3.5" /> Generate Report
        </button>
      }>

      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)', minWidth: 220 }}>{toast}</div>}

      <div className="space-y-5">
        {/* Quick exports */}
        <div className="g-card p-4">
          <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Quick Exports</p>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {EXPORTS.map(e => {
              const Icon = e.icon;
              return (
                <button key={e.label} onClick={() => downloadExport(e.url)}
                  className="flex items-center gap-2 rounded-xl px-3 py-2.5 text-xs font-medium transition-all"
                  style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)', color: 'var(--text-2)' }}
                  onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = 'var(--accent)'; (e.currentTarget as HTMLElement).style.borderColor = 'var(--accent-border)'; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = 'var(--text-2)'; (e.currentTarget as HTMLElement).style.borderColor = 'var(--border)'; }}>
                  <Icon className="h-3.5 w-3.5 shrink-0" />
                  {e.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Reports list */}
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>
            Generated Reports ({reports.length})
          </p>

          {loading ? (
            <div className="py-12 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          ) : reports.length === 0 ? (
            <div className="g-card py-14 text-center">
              <FileText className="mx-auto h-10 w-10 mb-3" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>No reports generated yet.</p>
              <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>Click &quot;Generate Report&quot; to create a compliance snapshot.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {reports.map(r => {
                const summary = parseSummary(r);
                const isOpen  = expanded === r.id;
                return (
                  <div key={r.id} className="g-card overflow-hidden">
                    <div className="flex items-center gap-3 p-4 cursor-pointer" onClick={async () => {
                      if (isOpen) { setExpanded(null); return; }
                      setExpanded(r.id);
                      if (!frameworkScores[r.id]) {
                        setLoadingScores(r.id);
                        try {
                          const res = await api.get(`/compliance/reports/${r.id}/scores`);
                          setFrameworkScores(s => ({ ...s, [r.id]: res.data }));
                        } finally { setLoadingScores(null); }
                      }
                    }}>
                      <div className="h-9 w-9 rounded-xl flex items-center justify-center shrink-0"
                        style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
                        <FileText className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate" style={{ color: 'var(--text-1)' }}>{r.title}</p>
                        <p className="text-[11px] mt-0.5" style={{ color: 'var(--text-3)' }}>
                          Generated by {r.generated_by} · {timeAgo(r.created_at)}
                        </p>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className="mono text-[10px] rounded px-2 py-0.5"
                          style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)', color: 'var(--text-3)' }}>
                          {r.report_type}
                        </span>
                        <button onClick={e => { e.stopPropagation(); downloadExport(() => complianceAPI.pdfUrl(r.id)); }}
                          title="Download PDF"
                          className="p-1.5 rounded" style={{ color: 'var(--text-3)' }}
                          onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--accent)'}
                          onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                          <FileText className="h-3.5 w-3.5" />
                        </button>
                        <button onClick={e => { e.stopPropagation(); del(r.id); }}
                          className="p-1.5 rounded" style={{ color: 'var(--text-3)' }}
                          onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--red)'}
                          onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                        {isOpen ? <ChevronUp className="h-4 w-4" style={{ color: 'var(--text-3)' }} />
                                : <ChevronDown className="h-4 w-4" style={{ color: 'var(--text-3)' }} />}
                      </div>
                    </div>

                    {isOpen && summary && (
                      <div className="px-4 pb-4 pt-1" style={{ borderTop: '1px solid var(--border)' }}>
                        {/* Stats grid */}
                        <div className="grid grid-cols-3 gap-3 mb-4 sm:grid-cols-6 mt-3">
                          {[
                            { label: 'Agents',      val: summary.total_agents },
                            { label: 'Online',       val: summary.online_agents },
                            { label: 'Alerts',       val: summary.total_alerts },
                            { label: 'Critical',     val: summary.critical_alerts },
                            { label: 'Incidents',    val: summary.open_incidents },
                            { label: 'Vulns',        val: summary.total_vulns },
                          ].map(({ label, val }) => (
                            <div key={label} className="rounded-xl p-3 text-center"
                              style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}>
                              <p className="text-xl font-bold tabular-nums" style={{ color: 'var(--text-1)' }}>{val ?? '—'}</p>
                              <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{label}</p>
                            </div>
                          ))}
                        </div>

                        {/* Top risk agents */}
                        {summary.top_risk_agents?.length > 0 && (
                          <div className="mb-3">
                            <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Top Risk Agents</p>
                            <div className="space-y-1.5">
                              {summary.top_risk_agents.map((a: any) => (
                                <div key={a.agent_id} className="flex items-center justify-between rounded-lg px-3 py-2"
                                  style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                                  <span className="text-xs" style={{ color: 'var(--text-1)' }}>{a.hostname} (#{a.agent_id})</span>
                                  <div className="flex items-center gap-2">
                                    <span className={sevClass(a.risk_level)}>{a.risk_level}</span>
                                    <span className="mono text-xs font-bold" style={{ color: 'var(--accent)' }}>{a.risk_score}</span>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Recent incidents */}
                        {summary.recent_incidents?.length > 0 && (
                          <div>
                            <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Recent Incidents</p>
                            <div className="space-y-1.5">
                              {summary.recent_incidents.map((i: any) => (
                                <div key={i.id} className="flex items-center justify-between rounded-lg px-3 py-2"
                                  style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                                  <span className="text-xs truncate flex-1" style={{ color: 'var(--text-1)' }}>{i.title}</span>
                                  <div className="flex items-center gap-2 shrink-0">
                                    <span className={sevClass(i.severity)}>{i.severity}</span>
                                    <span className="text-[10px] capitalize" style={{ color: 'var(--text-3)' }}>{i.status}</span>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* ── Framework Scores ─────────────────── */}
                        {(frameworkScores[r.id] || loadingScores === r.id) && (
                          <div className="mt-4">
                            <div className="flex items-center gap-2 mb-3">
                              <Target className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                              <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>
                                Compliance Framework Scores
                              </p>
                            </div>

                            {loadingScores === r.id ? (
                              <div className="py-4 text-center text-xs animate-pulse" style={{ color: 'var(--text-3)' }}>
                                Computing scores…
                              </div>
                            ) : (
                              <div className="space-y-3">
                                {frameworkScores[r.id]?.map(fs => {
                                  const color = SCORE_COLOR(fs.score);
                                  const bg    = SCORE_BG(fs.score);
                                  const fwOpen = expandedFramework === `${r.id}-${fs.framework}`;
                                  return (
                                    <div key={fs.framework} className="rounded-xl overflow-hidden"
                                      style={{ border: '1px solid var(--border)' }}>
                                      <div className="flex items-center gap-4 px-4 py-3 cursor-pointer"
                                        style={{ background: bg }}
                                        onClick={() => setExpandedFramework(fwOpen ? null : `${r.id}-${fs.framework}`)}>
                                        <div className="flex-1">
                                          <div className="flex items-center gap-3">
                                            <p className="text-xs font-bold" style={{ color: 'var(--text-1)' }}>{fs.framework}</p>
                                            <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--border)', maxWidth: 160 }}>
                                              <div className="h-full rounded-full transition-all"
                                                style={{ width: `${fs.score}%`, background: color }} />
                                            </div>
                                          </div>
                                          <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>
                                            {fs.passed} passed · {fs.failed} failed
                                          </p>
                                        </div>
                                        <p className="text-2xl font-bold tabular-nums" style={{ color }}>{fs.score}%</p>
                                        {fwOpen
                                          ? <ChevronUp className="h-4 w-4 shrink-0" style={{ color: 'var(--text-3)' }} />
                                          : <ChevronDown className="h-4 w-4 shrink-0" style={{ color: 'var(--text-3)' }} />}
                                      </div>

                                      {fwOpen && (
                                        <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                                          {fs.checks.map(check => (
                                            <div key={check.id} className="flex items-center gap-3 px-4 py-2.5">
                                              {check.passed
                                                ? <CheckCircle className="h-4 w-4 shrink-0" style={{ color: 'var(--green)' }} />
                                                : <XCircle    className="h-4 w-4 shrink-0" style={{ color: 'var(--red)' }} />}
                                              <div className="flex-1 min-w-0">
                                                <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{check.name}</p>
                                                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{check.detail}</p>
                                              </div>
                                              <span className="text-[10px] px-2 py-0.5 rounded shrink-0"
                                                style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-3)' }}>
                                                {check.category}
                                              </span>
                                            </div>
                                          ))}
                                        </div>
                                      )}
                                    </div>
                                  );
                                })}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Generate modal */}
      {showModal && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setShowModal(false)}>
          <div className="g-modal" style={{ maxWidth: 480 }}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Generate Compliance Report</h2>
              <button onClick={() => setShowModal(false)} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>
            <div className="p-5 space-y-2">
              <p className="text-xs mb-3" style={{ color: 'var(--text-3)' }}>Select the report type to generate a snapshot of your platform&apos;s current security posture.</p>
              {REPORT_TYPES.map(t => {
                const Icon = t.icon;
                return (
                  <button key={t.id} onClick={() => setSelType(t.id)}
                    className="w-full flex items-center gap-3 rounded-xl p-3 text-left transition-all"
                    style={{
                      background: selType === t.id ? 'var(--accent-glow)' : 'var(--glass-bg-2)',
                      border: `1px solid ${selType === t.id ? 'var(--accent-border)' : 'var(--border)'}`,
                    }}>
                    <Icon className="h-4 w-4 shrink-0" style={{ color: selType === t.id ? 'var(--accent)' : 'var(--text-3)' }} />
                    <span className="text-xs font-medium" style={{ color: selType === t.id ? 'var(--accent)' : 'var(--text-2)' }}>{t.label}</span>
                  </button>
                );
              })}
            </div>
            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => setShowModal(false)} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={generate} disabled={generating} className="g-btn g-btn-primary flex-1 justify-center">
                {generating ? 'Generating…' : 'Generate'}
              </button>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
