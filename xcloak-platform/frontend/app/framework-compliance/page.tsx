'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { fceAPI } from '@/lib/api';

// ── types ─────────────────────────────────────────────────────────────────────

type Tab = 'dashboard' | 'frameworks' | 'controls' | 'evidence' | 'gaps' | 'remediation' | 'analytics' | 'assessments' | 'audit' | 'notif';

const TABS: { id: Tab; label: string }[] = [
  { id: 'dashboard',   label: 'Dashboard'     },
  { id: 'frameworks',  label: 'Frameworks'    },
  { id: 'controls',    label: 'Controls'      },
  { id: 'evidence',    label: 'Evidence'      },
  { id: 'gaps',        label: 'Gap Analysis'  },
  { id: 'remediation', label: 'Remediation'   },
  { id: 'analytics',   label: 'Analytics'     },
  { id: 'assessments', label: 'Assessments'   },
  { id: 'audit',       label: 'Audit Trail'   },
  { id: 'notif',       label: 'Notifications' },
];

const FRAMEWORK_CATEGORIES = ['security', 'cloud', 'privacy', 'financial', 'healthcare', 'custom'];
const EVIDENCE_TYPES = ['document', 'screenshot', 'log', 'report', 'certificate', 'config', 'test_result', 'attestation'];
const REMEDIATION_STATUSES = ['open', 'in_progress', 'in_review', 'verified', 'closed', 'cancelled'];

// ── colour helpers ────────────────────────────────────────────────────────────

const STATUS_CLR: Record<string, string> = {
  compliant:           '#22c55e',
  non_compliant:       '#ef4444',
  partially_compliant: '#eab308',
  not_assessed:        '#6b7280',
  in_progress:         '#3b82f6',
};
const RISK_CLR: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
};
const REMED_CLR: Record<string, string> = {
  open:        '#ef4444',
  in_progress: '#3b82f6',
  in_review:   '#eab308',
  verified:    '#22c55e',
  closed:      '#6b7280',
  cancelled:   '#6b7280',
};
const AUDIT_CLR: Record<string, string> = {
  framework_added:      '#22c55e',
  framework_modified:   '#eab308',
  framework_deleted:    '#ef4444',
  control_modified:     '#eab308',
  evidence_uploaded:    '#22c55e',
  evidence_deleted:     '#ef4444',
  assessment_completed: '#a855f7',
  remediation_created:  '#3b82f6',
  remediation_updated:  '#eab308',
};
const NOTIF_CLR: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  info:     '#3b82f6',
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

function ScoreRing({ score, size = 72 }: { score: number; size?: number }) {
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
      <text x="50%" y="50%" dominantBaseline="middle" textAnchor="middle"
        fill={color} fontSize={size / 5} fontWeight="bold">{score}%</text>
    </svg>
  );
}

// ── AI panel ──────────────────────────────────────────────────────────────────

const AI_ACTIONS = [
  { id: 'compliance_summary',      label: 'Compliance Summary'       },
  { id: 'explain_failures',        label: 'Explain Failures'         },
  { id: 'recommend_remediation',   label: 'Recommend Remediation'    },
  { id: 'suggest_evidence',        label: 'Suggest Evidence'         },
  { id: 'predict_audit_readiness', label: 'Audit Readiness Forecast' },
  { id: 'executive_summary',       label: 'Executive Summary'        },
];

function AIPanel({ onClose }: { onClose: () => void }) {
  const [action, setAction] = useState('compliance_summary');
  const [resp, setResp] = useState('');
  const [loading, setLoading] = useState(false);

  async function run() {
    setLoading(true); setResp('');
    const r = await fceAPI.ai({ action }).catch(() => null);
    setResp(r?.data?.response || 'No response.');
    setLoading(false);
  }

  return (
    <div style={{ position: 'fixed', inset: '0 0 0 auto', width: 420, background: 'var(--bg-1)', borderLeft: '1px solid var(--border)', zIndex: 50, display: 'flex', flexDirection: 'column', boxShadow: '-4px 0 20px #0006' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 18px', borderBottom: '1px solid var(--border)' }}>
        <span style={{ fontWeight: 700, fontSize: 13 }}>✦ AI Compliance Assistant</span>
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
          {loading ? 'Analyzing…' : 'Run Analysis'}
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
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Score hero */}
      <div className="g-card" style={{ padding: 20, display: 'flex', alignItems: 'center', gap: 28 }}>
        <ScoreRing score={dash.overall_score ?? 0} size={96} />
        <div>
          <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 4 }}>Overall Compliance Score</div>
          <div style={{ fontSize: 36, fontWeight: 700, color: 'var(--text-1)', lineHeight: 1 }}>{dash.overall_score ?? 0}%</div>
          <div style={{ display: 'flex', gap: 8, marginTop: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 10, background: 'var(--bg-2)', borderRadius: 6, padding: '3px 8px', color: 'var(--text-2)' }}>
              Audit Readiness: <strong style={{ color: '#22c55e' }}>{dash.audit_readiness}%</strong>
            </span>
            <span style={{ fontSize: 10, background: 'var(--bg-2)', borderRadius: 6, padding: '3px 8px', color: 'var(--text-2)' }}>
              Active Frameworks: <strong>{dash.active_frameworks}</strong>
            </span>
          </div>
        </div>
        <div style={{ marginLeft: 'auto', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          {[
            { label: 'Passed',   value: dash.passed_controls,  color: '#22c55e' },
            { label: 'Failed',   value: dash.failed_controls,  color: '#ef4444' },
            { label: 'Unassessed', value: dash.not_assessed,   color: '#eab308' },
            { label: 'Critical', value: dash.critical_findings, color: '#ef4444' },
          ].map(s => (
            <div key={s.label} style={{ textAlign: 'center', background: s.color + '18', borderRadius: 10, padding: '10px 14px' }}>
              <div style={{ fontSize: 22, fontWeight: 700, color: s.color }}>{s.value}</div>
              <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{s.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Stat row */}
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total Frameworks"  value={dash.total_frameworks}   color="var(--accent)" />
        <StatCard label="Open Remediations" value={dash.open_remediations}  color="#eab308" />
        <StatCard label="Overdue Tasks"     value={dash.overdue_count}      color="#ef4444" />
        <StatCard label="Critical Findings" value={dash.critical_findings}  color="#ef4444" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Status breakdown */}
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 12 }}>Compliance Status Breakdown</div>
          {(!dash.status_breakdown?.length) && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No framework data yet.</div>}
          {(dash.status_breakdown || []).map((s: any) => (
            <div key={s.status} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              {pill(s.status.replace(/_/g, ' '), STATUS_CLR[s.status] || '#6b7280')}
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)' }}>{s.count}</span>
            </div>
          ))}
        </div>

        {/* Weakest frameworks */}
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 12 }}>Frameworks Needing Attention</div>
          {(!dash.bottom_frameworks?.length) && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No data.</div>}
          {(dash.bottom_frameworks || []).map((f: any) => (
            <div key={f.framework_id} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 12, color: 'var(--text-1)' }}>{f.name}</div>
                <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{f.failed_controls} failing controls</div>
              </div>
              <div style={{ width: 80, background: 'var(--bg-2)', borderRadius: 4, height: 4 }}>
                <div style={{ width: `${f.overall_score}%`, height: 4, borderRadius: 4, background: '#ef4444' }} />
              </div>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#ef4444', width: 32, textAlign: 'right' }}>{f.overall_score}%</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Frameworks tab ────────────────────────────────────────────────────────────

function FrameworksTab({ frameworks, onRefresh }: { frameworks: any[]; onRefresh: () => void }) {
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('');
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({ name: '', version: '1.0', category: 'security', description: '', owner: '' });

  const filtered = frameworks.filter(f => {
    if (category && f.category !== category) return false;
    if (search && !f.name.toLowerCase().includes(search.toLowerCase()) && !f.framework_id.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  async function add() {
    if (!form.name) return;
    await fceAPI.createFramework(form);
    setShowAdd(false);
    setForm({ name: '', version: '1.0', category: 'security', description: '', owner: '' });
    onRefresh();
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search frameworks…"
          className="g-input" style={{ width: 220, fontSize: 12 }} />
        <select value={category} onChange={e => setCategory(e.target.value)} className="g-input" style={{ fontSize: 12 }}>
          <option value="">All Categories</option>
          {FRAMEWORK_CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <span style={{ fontSize: 11, color: 'var(--text-3)', marginLeft: 'auto' }}>{filtered.length} frameworks</span>
        <button className="g-btn" style={{ fontSize: 12 }} onClick={() => setShowAdd(v => !v)}>+ Add Framework</button>
      </div>

      {showAdd && (
        <div className="g-card" style={{ padding: 16, borderColor: 'var(--accent)' }}>
          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 10 }}>Add Custom Framework</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <input placeholder="Name *" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} className="g-input" style={{ fontSize: 12 }} />
            <input placeholder="Version" value={form.version} onChange={e => setForm({ ...form, version: e.target.value })} className="g-input" style={{ fontSize: 12 }} />
            <select value={form.category} onChange={e => setForm({ ...form, category: e.target.value })} className="g-input" style={{ fontSize: 12 }}>
              {FRAMEWORK_CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
            <input placeholder="Owner" value={form.owner} onChange={e => setForm({ ...form, owner: e.target.value })} className="g-input" style={{ fontSize: 12 }} />
            <input placeholder="Description" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} className="g-input" style={{ fontSize: 12, gridColumn: '1 / -1' }} />
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
            <button className="g-btn" style={{ fontSize: 12 }} onClick={add}>Add</button>
            <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={() => setShowAdd(false)}>Cancel</button>
          </div>
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {filtered.map(fw => (
          <div key={fw.id} className="g-card" style={{ padding: 16, display: 'flex', alignItems: 'flex-start', gap: 16 }}>
            <ScoreRing score={fw.overall_score} size={64} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginBottom: 4 }}>
                <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-1)' }}>{fw.name}</span>
                <span style={{ fontSize: 10, color: 'var(--text-3)' }}>v{fw.version}</span>
                {pill(fw.category, '#3b82f6')}
                {pill(fw.compliance_status.replace(/_/g, ' '), STATUS_CLR[fw.compliance_status] || '#6b7280')}
                {!fw.is_active && pill('inactive', '#6b7280')}
                {fw.is_builtin && pill('built-in', '#8b5cf6')}
              </div>
              {fw.description && <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 6 }}>{fw.description}</div>}
              <div style={{ display: 'flex', gap: 16, fontSize: 11, color: 'var(--text-3)', flexWrap: 'wrap' }}>
                <span>Controls: <strong style={{ color: 'var(--text-1)' }}>{fw.total_controls}</strong></span>
                <span>Passed: <strong style={{ color: '#22c55e' }}>{fw.passed_controls}</strong></span>
                <span>Failed: <strong style={{ color: '#ef4444' }}>{fw.failed_controls}</strong></span>
                <span>N/A: <strong style={{ color: 'var(--text-2)' }}>{fw.not_applicable}</strong></span>
                {fw.owner && <span>Owner: <strong style={{ color: 'var(--text-2)' }}>{fw.owner}</strong></span>}
                {fw.last_assessment_at && <span>Last assessed: <strong style={{ color: 'var(--text-2)' }}>{fmt(fw.last_assessment_at)}</strong></span>}
              </div>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }}
                onClick={async () => { await fceAPI.updateFramework(fw.id, { is_active: !fw.is_active }); onRefresh(); }}>
                {fw.is_active ? 'Deactivate' : 'Activate'}
              </button>
              {!fw.is_builtin && (
                <button className="g-btn g-btn-ghost" style={{ fontSize: 11, color: '#ef4444' }}
                  onClick={async () => { await fceAPI.deleteFramework(fw.id); onRefresh(); }}>
                  Delete
                </button>
              )}
            </div>
          </div>
        ))}
        {!filtered.length && <div style={{ textAlign: 'center', padding: 60, color: 'var(--text-3)', fontSize: 13 }}>No frameworks found.</div>}
      </div>
    </div>
  );
}

// ── Controls tab ──────────────────────────────────────────────────────────────

function ControlsTab({ controls, frameworks, onRefresh }: { controls: any[]; frameworks: any[]; onRefresh: () => void }) {
  const [fwFilter, setFwFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [riskFilter, setRiskFilter] = useState('');
  const [search, setSearch] = useState('');
  const [noteTarget, setNoteTarget] = useState<any>(null);
  const [noteVal, setNoteVal] = useState('');

  const filtered = controls.filter(c => {
    if (fwFilter && c.framework_id !== fwFilter) return false;
    if (statusFilter && c.assessment_status !== statusFilter) return false;
    if (riskFilter && c.risk_level !== riskFilter) return false;
    if (search && !c.name.toLowerCase().includes(search.toLowerCase()) && !c.control_id.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const grouped: Record<string, any[]> = {};
  filtered.forEach(c => { if (!grouped[c.framework_id]) grouped[c.framework_id] = []; grouped[c.framework_id].push(c); });

  async function saveNote() {
    if (!noteTarget) return;
    await fceAPI.updateControl(noteTarget.id, { notes: noteVal });
    setNoteTarget(null);
    onRefresh();
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search controls…" className="g-input" style={{ width: 200, fontSize: 12 }} />
        <select value={fwFilter} onChange={e => setFwFilter(e.target.value)} className="g-input" style={{ fontSize: 12 }}>
          <option value="">All Frameworks</option>
          {frameworks.map(f => <option key={f.framework_id} value={f.framework_id}>{f.name}</option>)}
        </select>
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)} className="g-input" style={{ fontSize: 12 }}>
          <option value="">All Statuses</option>
          {['passed', 'failed', 'not_assessed', 'not_applicable'].map(s => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
        </select>
        <select value={riskFilter} onChange={e => setRiskFilter(e.target.value)} className="g-input" style={{ fontSize: 12 }}>
          <option value="">All Risk Levels</option>
          {['critical', 'high', 'medium', 'low'].map(r => <option key={r} value={r}>{r}</option>)}
        </select>
        <span style={{ fontSize: 11, color: 'var(--text-3)', marginLeft: 'auto' }}>{filtered.length} controls</span>
      </div>

      {noteTarget && (
        <div className="g-card" style={{ padding: 14, borderColor: 'var(--accent)' }}>
          <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8, color: 'var(--text-1)' }}>{noteTarget.control_id} — {noteTarget.name}</div>
          <textarea value={noteVal} onChange={e => setNoteVal(e.target.value)} rows={3} placeholder="Add notes…"
            className="g-input" style={{ width: '100%', fontSize: 12, resize: 'vertical' }} />
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <button className="g-btn" style={{ fontSize: 12 }} onClick={saveNote}>Save</button>
            <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={() => setNoteTarget(null)}>Cancel</button>
          </div>
        </div>
      )}

      {Object.entries(grouped).map(([fwId, ctrls]) => (
        <div key={fwId} className="g-card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--border)', fontWeight: 600, fontSize: 12, display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ color: 'var(--accent)' }}>{fwId}</span>
            <span style={{ color: 'var(--text-3)', fontWeight: 400 }}>({ctrls.length} controls)</span>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table className="g-table" style={{ width: '100%' }}>
              <thead>
                <tr>
                  <th>Control</th>
                  <th>Category</th>
                  <th>Risk</th>
                  <th>Priority</th>
                  <th>Status</th>
                  <th>Evidence</th>
                  <th>Owner</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {ctrls.map(c => (
                  <tr key={c.id}>
                    <td>
                      <div style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--accent)' }}>{c.control_id}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-1)' }}>{c.name}</div>
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{c.category}</td>
                    <td>{pill(c.risk_level, RISK_CLR[c.risk_level] || '#6b7280')}</td>
                    <td style={{ fontSize: 11, fontWeight: 600, color: RISK_CLR[c.priority] || 'var(--text-2)' }}>{c.priority}</td>
                    <td>
                      <select value={c.assessment_status}
                        onChange={async e => { await fceAPI.updateControl(c.id, { assessment_status: e.target.value }); onRefresh(); }}
                        className="g-input" style={{ fontSize: 11, padding: '2px 6px' }}>
                        {['passed', 'failed', 'not_assessed', 'not_applicable'].map(s => (
                          <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>
                        ))}
                      </select>
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{c.evidence_count}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{c.owner || '—'}</td>
                    <td>
                      <button className="g-btn g-btn-ghost" style={{ fontSize: 10, padding: '2px 8px' }}
                        onClick={() => { setNoteTarget(c); setNoteVal(c.notes || ''); }}>
                        Notes
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ))}
      {!filtered.length && <div style={{ textAlign: 'center', padding: 60, color: 'var(--text-3)', fontSize: 13 }}>No controls found.</div>}
    </div>
  );
}

// ── Evidence tab ──────────────────────────────────────────────────────────────

function EvidenceTab({ evidence, frameworks, onRefresh }: { evidence: any[]; frameworks: any[]; onRefresh: () => void }) {
  const [fwFilter, setFwFilter] = useState('');
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({ framework_id: '', control_id: '', name: '', description: '', evidence_type: 'document', file_name: '', source: '' });

  const filtered = fwFilter ? evidence.filter(e => e.framework_id === fwFilter) : evidence;

  async function add() {
    if (!form.name || !form.framework_id) return;
    await fceAPI.addEvidence(form);
    setShowAdd(false);
    setForm({ framework_id: '', control_id: '', name: '', description: '', evidence_type: 'document', file_name: '', source: '' });
    onRefresh();
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <select value={fwFilter} onChange={e => setFwFilter(e.target.value)} className="g-input" style={{ fontSize: 12 }}>
          <option value="">All Frameworks</option>
          {frameworks.map(f => <option key={f.framework_id} value={f.framework_id}>{f.name}</option>)}
        </select>
        <span style={{ fontSize: 11, color: 'var(--text-3)', marginLeft: 'auto' }}>{filtered.length} items</span>
        <button className="g-btn" style={{ fontSize: 12 }} onClick={() => setShowAdd(v => !v)}>+ Add Evidence</button>
      </div>

      {showAdd && (
        <div className="g-card" style={{ padding: 16, borderColor: 'var(--accent)' }}>
          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 10 }}>Add Evidence</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <select value={form.framework_id} onChange={e => setForm({ ...form, framework_id: e.target.value })} className="g-input" style={{ fontSize: 12 }}>
              <option value="">Select Framework *</option>
              {frameworks.map(f => <option key={f.framework_id} value={f.framework_id}>{f.name}</option>)}
            </select>
            <input placeholder="Control ID (optional)" value={form.control_id} onChange={e => setForm({ ...form, control_id: e.target.value })} className="g-input" style={{ fontSize: 12 }} />
            <input placeholder="Name *" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} className="g-input" style={{ fontSize: 12 }} />
            <select value={form.evidence_type} onChange={e => setForm({ ...form, evidence_type: e.target.value })} className="g-input" style={{ fontSize: 12 }}>
              {EVIDENCE_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
            <input placeholder="File name" value={form.file_name} onChange={e => setForm({ ...form, file_name: e.target.value })} className="g-input" style={{ fontSize: 12 }} />
            <input placeholder="Source URL / system" value={form.source} onChange={e => setForm({ ...form, source: e.target.value })} className="g-input" style={{ fontSize: 12 }} />
            <input placeholder="Description" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} className="g-input" style={{ fontSize: 12, gridColumn: '1 / -1' }} />
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
            <button className="g-btn" style={{ fontSize: 12 }} onClick={add}>Upload</button>
            <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={() => setShowAdd(false)}>Cancel</button>
          </div>
        </div>
      )}

      <div className="g-card" style={{ padding: 0, overflow: 'hidden' }}>
        <table className="g-table" style={{ width: '100%' }}>
          <thead>
            <tr>
              <th>Evidence</th>
              <th>Framework</th>
              <th>Control</th>
              <th>Type</th>
              <th>Verified</th>
              <th>Uploaded By</th>
              <th>Expires</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(e => (
              <tr key={e.id}>
                <td>
                  <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-1)' }}>{e.name}</div>
                  {e.file_name && <div style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--text-3)' }}>{e.file_name}</div>}
                </td>
                <td style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--accent)' }}>{e.framework_id}</td>
                <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{e.control_id || '—'}</td>
                <td>{pill(e.evidence_type, '#6b7280')}</td>
                <td style={{ fontSize: 11 }}>
                  {e.verified
                    ? <span style={{ color: '#22c55e' }}>✓ {e.verified_by}</span>
                    : <span style={{ color: '#eab308' }}>Pending</span>}
                </td>
                <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{e.uploaded_by}</td>
                <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{fmt(e.expires_at)}</td>
                <td>
                  <button className="g-btn g-btn-ghost" style={{ fontSize: 10, color: '#ef4444' }}
                    onClick={async () => { await fceAPI.deleteEvidence(e.id); onRefresh(); }}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!filtered.length && <div style={{ textAlign: 'center', padding: 48, color: 'var(--text-3)', fontSize: 13 }}>No evidence records.</div>}
      </div>
    </div>
  );
}

// ── Gap Analysis tab ──────────────────────────────────────────────────────────

function GapsTab({ gaps, frameworks, onRefresh }: { gaps: any; frameworks: any[]; onRefresh: () => void }) {
  const [fwFilter, setFwFilter] = useState('');
  const [modal, setModal] = useState<any>(null);
  const [form, setForm] = useState({ title: '', description: '', priority: 'high', assigned_to: '', due_date: '' });

  const gapList = gaps?.gaps || [];
  const filtered = fwFilter ? gapList.filter((g: any) => g.framework_id === fwFilter) : gapList;

  async function createRemediation() {
    if (!modal || !form.title) return;
    await fceAPI.createRemediation({ framework_id: modal.framework_id, control_id: modal.control_id, control_name: modal.name, ...form });
    setModal(null);
    setForm({ title: '', description: '', priority: 'high', assigned_to: '', due_date: '' });
    onRefresh();
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {modal && (
        <div style={{ position: 'fixed', inset: 0, background: '#0008', zIndex: 60, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div className="g-card" style={{ padding: 20, width: 460 }}>
            <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 10 }}>Create Remediation Task</div>
            <div style={{ fontSize: 11, color: 'var(--text-3)', background: 'var(--bg-2)', borderRadius: 6, padding: '6px 10px', marginBottom: 12 }}>
              Control: {modal.control_id} — {modal.name}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <input placeholder="Task title *" value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} className="g-input" style={{ fontSize: 12 }} />
              <textarea placeholder="Description" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })}
                rows={3} className="g-input" style={{ fontSize: 12, resize: 'vertical', width: '100%' }} />
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                <select value={form.priority} onChange={e => setForm({ ...form, priority: e.target.value })} className="g-input" style={{ fontSize: 12 }}>
                  {['critical', 'high', 'medium', 'low'].map(p => <option key={p} value={p}>{p}</option>)}
                </select>
                <input type="date" value={form.due_date} onChange={e => setForm({ ...form, due_date: e.target.value })} className="g-input" style={{ fontSize: 12 }} />
                <input placeholder="Assign to" value={form.assigned_to} onChange={e => setForm({ ...form, assigned_to: e.target.value })} className="g-input" style={{ fontSize: 12, gridColumn: '1 / -1' }} />
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
              <button className="g-btn" style={{ fontSize: 12 }} onClick={createRemediation}>Create</button>
              <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={() => setModal(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <select value={fwFilter} onChange={e => setFwFilter(e.target.value)} className="g-input" style={{ fontSize: 12 }}>
          <option value="">All Frameworks</option>
          {frameworks.map(f => <option key={f.framework_id} value={f.framework_id}>{f.name}</option>)}
        </select>
      </div>

      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total Gaps"       value={gaps?.total_gaps ?? 0}       color="#eab308" />
        <StatCard label="Critical Gaps"    value={gaps?.critical_count ?? 0}   color="#ef4444" />
        <StatCard label="High Gaps"        value={gaps?.high_count ?? 0}       color="#f97316" />
        <StatCard label="Missing Evidence" value={gaps?.missing_evidence ?? 0} color="#a855f7" />
      </div>

      <div className="g-card" style={{ padding: 0, overflow: 'hidden' }}>
        <table className="g-table" style={{ width: '100%' }}>
          <thead>
            <tr>
              <th>Framework</th>
              <th>Control</th>
              <th>Category</th>
              <th>Risk</th>
              <th>Status</th>
              <th>Score</th>
              <th>Evidence</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((g: any, i: number) => (
              <tr key={i}>
                <td style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--accent)' }}>{g.framework_id}</td>
                <td>
                  <div style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--text-2)' }}>{g.control_id}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-1)' }}>{g.name}</div>
                </td>
                <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{g.category}</td>
                <td>{pill(g.risk_level, RISK_CLR[g.risk_level] || '#6b7280')}</td>
                <td>{pill(g.status.replace(/_/g, ' '), STATUS_CLR[g.status] || '#6b7280')}</td>
                <td style={{ fontSize: 11, color: 'var(--text-2)' }}>{g.score}%</td>
                <td style={{ fontSize: 11 }}>
                  {g.evidence_count === 0
                    ? <span style={{ color: '#ef4444' }}>None</span>
                    : <span style={{ color: 'var(--text-2)' }}>{g.evidence_count}</span>}
                </td>
                <td>
                  <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={() => setModal(g)}>Remediate</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!filtered.length && <div style={{ textAlign: 'center', padding: 48, color: 'var(--text-3)', fontSize: 13 }}>No gaps found — great compliance posture!</div>}
      </div>
    </div>
  );
}

// ── Remediation tab ───────────────────────────────────────────────────────────

function RemediationTab({ remediations, frameworks, onRefresh }: { remediations: any[]; frameworks: any[]; onRefresh: () => void }) {
  const [statusFilter, setStatusFilter] = useState('');
  const [fwFilter, setFwFilter] = useState('');

  const filtered = remediations.filter(r => {
    if (statusFilter && r.status !== statusFilter) return false;
    if (fwFilter && r.framework_id !== fwFilter) return false;
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)} className="g-input" style={{ fontSize: 12 }}>
          <option value="">All Statuses</option>
          {REMEDIATION_STATUSES.map(s => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
        </select>
        <select value={fwFilter} onChange={e => setFwFilter(e.target.value)} className="g-input" style={{ fontSize: 12 }}>
          <option value="">All Frameworks</option>
          {frameworks.map(f => <option key={f.framework_id} value={f.framework_id}>{f.name}</option>)}
        </select>
        <span style={{ fontSize: 11, color: 'var(--text-3)', marginLeft: 'auto' }}>{filtered.length} tasks</span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {filtered.map(item => (
          <div key={item.id} className="g-card" style={{ padding: 14 }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginBottom: 4 }}>
                  <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-1)' }}>{item.title}</span>
                  {pill(item.priority, RISK_CLR[item.priority] || '#6b7280')}
                  {pill(item.status.replace(/_/g, ' '), REMED_CLR[item.status] || '#6b7280')}
                </div>
                {item.description && <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 6 }}>{item.description}</div>}
                <div style={{ display: 'flex', gap: 16, fontSize: 11, color: 'var(--text-3)', flexWrap: 'wrap' }}>
                  <span>Framework: <strong style={{ color: 'var(--text-2)' }}>{item.framework_id}</strong></span>
                  <span>Control: <strong style={{ color: 'var(--text-2)' }}>{item.control_id}</strong></span>
                  {item.assigned_to && <span>Assigned: <strong style={{ color: 'var(--text-2)' }}>{item.assigned_to}</strong></span>}
                  {item.assigned_team && <span>Team: <strong style={{ color: 'var(--text-2)' }}>{item.assigned_team}</strong></span>}
                  {item.due_date && (
                    <span>Due: <strong style={{ color: new Date(item.due_date) < new Date() && item.status !== 'closed' ? '#ef4444' : 'var(--text-2)' }}>{fmt(item.due_date)}</strong></span>
                  )}
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {REMEDIATION_STATUSES.filter(s => s !== item.status).slice(0, 3).map(s => (
                  <button key={s} className="g-btn g-btn-ghost" style={{ fontSize: 10, padding: '2px 8px' }}
                    onClick={async () => { await fceAPI.updateRemediation(item.id, { status: s }); onRefresh(); }}>
                    → {s.replace(/_/g, ' ')}
                  </button>
                ))}
              </div>
            </div>
          </div>
        ))}
        {!filtered.length && <div style={{ textAlign: 'center', padding: 60, color: 'var(--text-3)', fontSize: 13 }}>No remediation tasks. Create them from Gap Analysis.</div>}
      </div>
    </div>
  );
}

// ── Analytics tab ─────────────────────────────────────────────────────────────

function AnalyticsTab({ data }: { data: any }) {
  if (!data) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;

  const remPct = data.remediation_progress ?? 0;
  const evPct = data.total_evidence > 0 ? Math.round((data.verified_evidence / data.total_evidence) * 100) : 0;
  const maxFwScore = Math.max(...(data.by_framework || []).map((f: any) => f.score), 1);
  const maxCat = Math.max(...(data.failed_by_category || []).map((c: any) => c.count), 1);
  const maxRisk = Math.max(...(data.risk_distribution || []).map((r: any) => r.count), 1);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total Remediations"  value={data.total_remediations ?? 0} />
        <StatCard label="Closed"              value={data.closed_remediations ?? 0}  color="#22c55e" />
        <StatCard label="Overdue"             value={data.overdue_remediations ?? 0} color="#ef4444" />
        <StatCard label="Total Evidence"      value={data.total_evidence ?? 0}       color="#3b82f6" />
        <StatCard label="Evidence Verified"   value={data.verified_evidence ?? 0}    color="#22c55e" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 12 }}>Compliance Scores by Framework</div>
          {(data.by_framework || []).map((f: any) => (
            <div key={f.name} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
              <div style={{ fontSize: 11, color: 'var(--text-2)', width: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.name}</div>
              <div style={{ flex: 1, background: 'var(--bg-2)', borderRadius: 4, height: 6 }}>
                <div style={{ width: `${(f.score / maxFwScore) * 100}%`, height: 6, borderRadius: 4, background: f.score >= 80 ? '#22c55e' : f.score >= 60 ? '#eab308' : '#ef4444' }} />
              </div>
              <span style={{ fontSize: 11, fontWeight: 700, width: 36, textAlign: 'right', color: f.score >= 80 ? '#22c55e' : f.score >= 60 ? '#eab308' : '#ef4444' }}>{f.score}%</span>
            </div>
          ))}
          {!data.by_framework?.length && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No framework data.</div>}
        </div>

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 12 }}>Failed Controls by Category</div>
          {(data.failed_by_category || []).map((c: any, i: number) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
              <div style={{ fontSize: 11, color: 'var(--text-2)', width: 120, textTransform: 'capitalize', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.category}</div>
              <div style={{ flex: 1, background: 'var(--bg-2)', borderRadius: 4, height: 6 }}>
                <div style={{ width: `${(c.count / maxCat) * 100}%`, height: 6, borderRadius: 4, background: '#ef4444' }} />
              </div>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#ef4444', width: 24, textAlign: 'right' }}>{c.count}</span>
            </div>
          ))}
          {!data.failed_by_category?.length && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No failures.</div>}
        </div>

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 12 }}>Risk Distribution (Failed Controls)</div>
          {(data.risk_distribution || []).map((r: any) => (
            <div key={r.risk_level} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
              {pill(r.risk_level, RISK_CLR[r.risk_level] || '#6b7280')}
              <div style={{ flex: 1, background: 'var(--bg-2)', borderRadius: 4, height: 6 }}>
                <div style={{ width: `${(r.count / maxRisk) * 100}%`, height: 6, borderRadius: 4, background: RISK_CLR[r.risk_level] || '#6b7280' }} />
              </div>
              <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-2)', width: 24, textAlign: 'right' }}>{r.count}</span>
            </div>
          ))}
          {!data.risk_distribution?.length && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No risk data.</div>}
        </div>

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 16 }}>Progress Indicators</div>
          {[
            { label: 'Remediation Progress', pct: remPct, color: '#3b82f6' },
            { label: `Evidence Verified (${data.verified_evidence}/${data.total_evidence})`, pct: evPct, color: '#22c55e' },
          ].map(b => (
            <div key={b.label} style={{ marginBottom: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-3)', marginBottom: 4 }}>
                <span>{b.label}</span><span style={{ fontWeight: 700, color: 'var(--text-2)' }}>{b.pct}%</span>
              </div>
              <div style={{ background: 'var(--bg-2)', borderRadius: 4, height: 10 }}>
                <div style={{ width: `${b.pct}%`, height: 10, borderRadius: 4, background: b.color, transition: 'width 0.4s' }} />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Assessments tab ───────────────────────────────────────────────────────────

function AssessmentsTab({ assessments, frameworks, onRefresh }: { assessments: any[]; frameworks: any[]; onRefresh: () => void }) {
  const [showRun, setShowRun] = useState(false);
  const [form, setForm] = useState({ framework_id: '', notes: '' });
  const [running, setRunning] = useState(false);

  async function run() {
    if (!form.framework_id) return;
    setRunning(true);
    const fw = frameworks.find(f => f.framework_id === form.framework_id);
    await fceAPI.runAssessment({ ...form, framework_name: fw?.name || form.framework_id });
    setRunning(false); setShowRun(false); setForm({ framework_id: '', notes: '' });
    onRefresh();
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{assessments.length} assessments run</span>
        <button className="g-btn" style={{ fontSize: 12, marginLeft: 'auto' }} onClick={() => setShowRun(v => !v)}>Run Assessment</button>
      </div>

      {showRun && (
        <div className="g-card" style={{ padding: 16, borderColor: 'var(--accent)' }}>
          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 4 }}>Run Framework Assessment</div>
          <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 10 }}>Calculates scores from current control assessment statuses.</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <select value={form.framework_id} onChange={e => setForm({ ...form, framework_id: e.target.value })} className="g-input" style={{ fontSize: 12 }}>
              <option value="">Select Framework *</option>
              {frameworks.map(f => <option key={f.framework_id} value={f.framework_id}>{f.name}</option>)}
            </select>
            <textarea placeholder="Notes (optional)" value={form.notes} onChange={e => setForm({ ...form, notes: e.target.value })}
              rows={2} className="g-input" style={{ fontSize: 12, resize: 'vertical', width: '100%' }} />
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
            <button className="g-btn" style={{ fontSize: 12 }} onClick={run} disabled={running}>{running ? 'Running…' : 'Run'}</button>
            <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={() => setShowRun(false)}>Cancel</button>
          </div>
        </div>
      )}

      <div className="g-card" style={{ padding: 0, overflow: 'hidden' }}>
        <table className="g-table" style={{ width: '100%' }}>
          <thead>
            <tr>
              <th>Framework</th>
              <th>Type</th>
              <th>Score</th>
              <th>Passed</th>
              <th>Failed</th>
              <th>N/A</th>
              <th>Started By</th>
              <th>Date</th>
            </tr>
          </thead>
          <tbody>
            {assessments.map(a => (
              <tr key={a.id}>
                <td style={{ fontSize: 12, color: 'var(--text-1)', fontWeight: 500 }}>{a.framework_name}</td>
                <td>{pill(a.assessment_type, '#6b7280')}</td>
                <td style={{ fontSize: 13, fontWeight: 700, color: a.score >= 80 ? '#22c55e' : a.score >= 60 ? '#eab308' : '#ef4444' }}>{a.score}%</td>
                <td style={{ fontSize: 12, color: '#22c55e' }}>{a.passed}</td>
                <td style={{ fontSize: 12, color: '#ef4444' }}>{a.failed}</td>
                <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{a.not_applicable}</td>
                <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{a.started_by}</td>
                <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{fmt(a.started_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!assessments.length && <div style={{ textAlign: 'center', padding: 48, color: 'var(--text-3)', fontSize: 13 }}>No assessments run yet.</div>}
      </div>
    </div>
  );
}

// ── Audit tab ─────────────────────────────────────────────────────────────────

function AuditTab({ items }: { items: any[] }) {
  return (
    <div className="g-card" style={{ padding: 0, overflow: 'hidden' }}>
      <table className="g-table" style={{ width: '100%' }}>
        <thead>
          <tr>
            <th>Action</th>
            <th>Object</th>
            <th>Name</th>
            <th>Actor</th>
            <th>Details</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          {items.map(e => (
            <tr key={e.id}>
              <td>{pill(e.action.replace(/_/g, ' '), AUDIT_CLR[e.action] || '#6b7280')}</td>
              <td style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'capitalize' }}>{e.object_type}</td>
              <td style={{ fontSize: 11, color: 'var(--text-2)' }}>{e.object_name || e.object_id || '—'}</td>
              <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{e.actor}</td>
              <td style={{ fontSize: 11, color: 'var(--text-3)', maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.details || '—'}</td>
              <td style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{fmt(e.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!items.length && <div style={{ textAlign: 'center', padding: 48, color: 'var(--text-3)', fontSize: 13 }}>No audit entries.</div>}
    </div>
  );
}

// ── Notifications tab ─────────────────────────────────────────────────────────

function NotificationsTab({ items, onMarkRead }: { items: any[]; onMarkRead: () => void }) {
  const unread = items.filter(n => !n.read).length;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{ fontWeight: 600, fontSize: 13 }}>
          Notifications {unread > 0 && <span style={{ fontSize: 11, background: '#3b82f622', color: '#3b82f6', borderRadius: 10, padding: '1px 8px', marginLeft: 6 }}>{unread} unread</span>}
        </span>
        {unread > 0 && <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={onMarkRead}>Mark all read</button>}
      </div>
      {items.map(n => (
        <div key={n.id} className="g-card" style={{ padding: 14, borderLeft: `3px solid ${n.read ? 'var(--border)' : NOTIF_CLR[n.severity] || '#6b7280'}` }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            {!n.read && <span style={{ width: 6, height: 6, borderRadius: '50%', background: NOTIF_CLR[n.severity] || '#6b7280', flexShrink: 0 }} />}
            <span style={{ fontWeight: 600, fontSize: 12, color: 'var(--text-1)' }}>{n.title}</span>
            {pill(n.severity, NOTIF_CLR[n.severity] || '#6b7280')}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{n.message}</div>
          <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 4 }}>{fmt(n.created_at)}</div>
        </div>
      ))}
      {!items.length && <div style={{ textAlign: 'center', padding: 48, color: 'var(--text-3)', fontSize: 13 }}>No notifications.</div>}
    </div>
  );
}

// ── page ──────────────────────────────────────────────────────────────────────

export default function FrameworkCompliancePage() {
  const [tab, setTab] = useState<Tab>('dashboard');
  const [showAI, setShowAI] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const [dash, setDash] = useState<any>(null);
  const [frameworks, setFrameworks] = useState<any[]>([]);
  const [controls, setControls] = useState<any[]>([]);
  const [evidence, setEvidence] = useState<any[]>([]);
  const [gaps, setGaps] = useState<any>(null);
  const [remediations, setRemediations] = useState<any[]>([]);
  const [analytics, setAnalytics] = useState<any>(null);
  const [assessments, setAssessments] = useState<any[]>([]);
  const [audit, setAudit] = useState<any[]>([]);
  const [notifications, setNotifications] = useState<any[]>([]);

  const loadAll = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const [d, fw, ct, ev, gp, rm, an, as_, au, no] = await Promise.all([
        fceAPI.getDashboard(),
        fceAPI.getFrameworks(),
        fceAPI.getControls(),
        fceAPI.getEvidence(),
        fceAPI.getGaps(),
        fceAPI.getRemediations(),
        fceAPI.getAnalytics(),
        fceAPI.getAssessments(),
        fceAPI.getAudit(),
        fceAPI.getNotifications(),
      ]);
      setDash(d.data);
      setFrameworks((fw.data as any) || []);
      setControls((ct.data as any) || []);
      setEvidence((ev.data as any) || []);
      setGaps(gp.data);
      setRemediations((rm.data as any) || []);
      setAnalytics(an.data);
      setAssessments((as_.data as any) || []);
      setAudit((au.data as any) || []);
      setNotifications((no.data as any) || []);
    } finally { setRefreshing(false); }
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  const markRead = async () => {
    await fceAPI.markNotificationsRead();
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
  };

  const unreadCount = notifications.filter(n => !n.read).length;

  return (
    <RootLayout
      title="Framework & Compliance"
      subtitle="Enterprise compliance management across 30+ security frameworks"
      onRefresh={() => loadAll(true)}
      refreshing={refreshing}
      actions={
        <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={() => setShowAI(v => !v)}>
          ✦ AI Assistant
        </button>
      }
    >
      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', marginBottom: 20, overflowX: 'auto' }}>
        {TABS.map(t => {
          const badge = t.id === 'notif' ? unreadCount : 0;
          return (
            <button key={t.id} onClick={() => setTab(t.id)} style={{
              padding: '10px 14px', fontSize: 12, fontWeight: tab === t.id ? 700 : 400,
              color: tab === t.id ? 'var(--accent)' : 'var(--text-2)',
              borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
              background: 'none', whiteSpace: 'nowrap', position: 'relative',
            }}>
              {t.label}
              {badge > 0 && (
                <span style={{ position: 'absolute', top: 6, right: 2, fontSize: 8, fontWeight: 700, background: '#ef4444', color: '#fff', borderRadius: 8, padding: '1px 4px', minWidth: 14, textAlign: 'center' }}>{badge}</span>
              )}
            </button>
          );
        })}
      </div>

      {tab === 'dashboard'   && <DashboardTab dash={dash} />}
      {tab === 'frameworks'  && <FrameworksTab frameworks={frameworks} onRefresh={() => loadAll()} />}
      {tab === 'controls'    && <ControlsTab controls={controls} frameworks={frameworks} onRefresh={() => loadAll()} />}
      {tab === 'evidence'    && <EvidenceTab evidence={evidence} frameworks={frameworks} onRefresh={() => loadAll()} />}
      {tab === 'gaps'        && <GapsTab gaps={gaps} frameworks={frameworks} onRefresh={() => loadAll()} />}
      {tab === 'remediation' && <RemediationTab remediations={remediations} frameworks={frameworks} onRefresh={() => loadAll()} />}
      {tab === 'analytics'   && <AnalyticsTab data={analytics} />}
      {tab === 'assessments' && <AssessmentsTab assessments={assessments} frameworks={frameworks} onRefresh={() => loadAll()} />}
      {tab === 'audit'       && <AuditTab items={audit} />}
      {tab === 'notif'       && <NotificationsTab items={notifications} onMarkRead={markRead} />}

      {showAI && <AIPanel onClose={() => setShowAI(false)} />}
    </RootLayout>
  );
}
