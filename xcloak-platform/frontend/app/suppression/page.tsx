'use client';

import React, { useState, useEffect, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { supAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';

type Tab = 'dashboard' | 'rules' | 'builder' | 'analytics' | 'audit' | 'reports';
const TAB_LABELS: Record<Tab, string> = {
  dashboard: 'Dashboard', rules: 'Active Rules', builder: 'Rule Builder',
  analytics: 'Analytics', audit: 'Audit Trail', reports: 'Reports',
};

const SUP_TYPE_LABEL: Record<string, string> = {
  full_suppress: 'Full Suppress', hide_from_queue: 'Hide from Queue',
  lower_severity: 'Lower Severity', group_duplicates: 'Group Duplicates', rate_limit: 'Rate Limit',
};
const SUP_TYPE_COLOR: Record<string, string> = {
  full_suppress: '#ef4444', hide_from_queue: '#f97316', lower_severity: '#eab308',
  group_duplicates: '#3b82f6', rate_limit: '#a855f7',
};
const STATUS_COLOR: Record<string, string> = {
  active: '#22c55e', draft: '#6b7280', disabled: '#6b7280', expired: '#ef4444',
};
const APPROVAL_COLOR: Record<string, string> = {
  not_required: '#22c55e', pending: '#f97316', approved: '#22c55e', rejected: '#ef4444',
};

const CONDITION_FIELDS = [
  'alert_type', 'detection_name', 'severity', 'confidence', 'risk_score',
  'mitre_technique', 'hostname', 'asset_group', 'username', 'src_ip', 'domain',
  'process_name', 'file_hash', 'registry_key', 'cloud_account', 'k8s_namespace', 'custom_tag',
];
const CONDITION_OPS = ['equals', 'contains', 'matches', 'starts_with', 'in', 'in_range', 'in_group', 'not_equals', 'regex'];
const SCOPE_OPTIONS = ['single_asset', 'asset_group', 'department', 'business_unit', 'cloud_account', 'entire_environment'];
const EXCEPTION_OPTIONS = ['domain_controllers', 'critical_assets', 'threat_intel_match', 'high_user_risk'];
const TIME_TYPES = ['until_date', 'maintenance_window', 'business_hours', 'recurring_schedule', 'one_time'];
const SUP_TYPES = ['full_suppress', 'hide_from_queue', 'lower_severity', 'group_duplicates', 'rate_limit'];

function StatCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="g-card" style={{ padding: '14px 18px', minWidth: 130 }}>
      <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 700, color: color || 'var(--text-1)', lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 3 }}>{sub}</div>}
    </div>
  );
}

function StatusPill({ s }: { s: string }) {
  const c = STATUS_COLOR[s] || '#6b7280';
  return <span style={{ fontSize: 11, fontWeight: 600, padding: '2px 9px', borderRadius: 10, background: c + '22', color: c, border: `1px solid ${c}44`, textTransform: 'capitalize' }}>{s}</span>;
}

function supTypeDesc(t: string): string {
  switch (t) {
    case 'full_suppress': return 'Alert is never generated. No record in analyst queue.';
    case 'hide_from_queue': return 'Alert is generated and logged but hidden from analyst queue.';
    case 'lower_severity': return 'Alert severity is downgraded before appearing in queue.';
    case 'group_duplicates': return 'Repeated identical alerts are grouped into a single alert.';
    case 'rate_limit': return 'Alert is only generated once per time window, not on every occurrence.';
    default: return '';
  }
}

function exceptionLabel(ex: string): string {
  switch (ex) {
    case 'domain_controllers': return 'Domain Controllers';
    case 'critical_assets': return 'Critical Assets';
    case 'threat_intel_match': return 'Threat Intel Match';
    case 'high_user_risk': return 'High User Risk';
    default: return ex;
  }
}

// ─── Dashboard Tab ─────────────────────────────────────────────────────────
function DashboardTab({ dash }: { dash: any }) {
  if (!dash) return <div style={{ color: 'var(--text-3)', padding: 40, textAlign: 'center' }}>Loading…</div>;
  const maxBar = Math.max(...(dash.suppression_trend || []).map((d: any) => d.suppressed), 1);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Active Rules" value={dash.active_rules} color="var(--accent)" />
        <StatCard label="Suppressed Today" value={dash.suppressed_today?.toLocaleString()} color="#f97316" sub="alerts suppressed" />
        <StatCard label="Expiring Rules" value={dash.expiring_rules} color={dash.expiring_rules > 0 ? '#f97316' : 'var(--text-1)'} sub="within 7 days" />
        <StatCard label="Analyst Hours Saved" value={`${(dash.analyst_time_saved_h || 0).toFixed(0)}h`} color="#22c55e" sub="estimated" />
      </div>

      {dash.expiring_rules > 0 && (
        <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #f97316', background: '#f9731608' }}>
          <span style={{ fontWeight: 700, color: '#f97316' }}>⚠ {dash.expiring_rules} rule{dash.expiring_rules !== 1 ? 's' : ''} expiring within 7 days.</span>
          <span style={{ fontSize: 13, color: 'var(--text-2)', marginLeft: 8 }}>Review and renew or allow to expire.</span>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Suppression Trend (7d)</div>
          <div style={{ display: 'flex', gap: 4, alignItems: 'flex-end', height: 80 }}>
            {dash.suppression_trend?.map((d: any) => (
              <div key={d.date} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                <div style={{ width: '100%', background: 'var(--accent)', borderRadius: '2px 2px 0 0', height: `${Math.max(3, (d.suppressed / maxBar) * 64)}px` }} title={`${d.suppressed} suppressed`} />
                <div style={{ fontSize: 8, color: 'var(--text-3)', textAlign: 'center' }}>{d.date.slice(5)}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Top Suppressed Detections</div>
          {dash.top_suppressed?.slice(0, 4).map((t: any) => (
            <div key={t.detection} style={{ marginBottom: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 2 }}>
                <span style={{ color: 'var(--text-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '70%' }}>{t.detection}</span>
                <span style={{ fontWeight: 700, color: '#f97316', flexShrink: 0 }}>{t.count.toLocaleString()}</span>
              </div>
              <div style={{ background: 'var(--border)', borderRadius: 2, height: 5 }}>
                <div style={{ background: '#f97316', borderRadius: 2, height: 5, width: `${(t.count / (dash.top_suppressed[0].count || 1)) * 100}%` }} />
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="g-card" style={{ padding: 16 }}>
        <div style={{ fontWeight: 600, marginBottom: 12 }}>Analysts Creating Rules</div>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr>
              {['Analyst', 'Rules Created', 'Alerts Suppressed', 'Avg / Rule'].map(h => (
                <th key={h} style={{ textAlign: 'left', padding: '5px 10px', color: 'var(--text-3)', fontSize: 11, fontWeight: 600, textTransform: 'uppercase' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {dash.analysts_creating_rules?.map((a: any) => (
              <tr key={a.analyst} style={{ borderTop: '1px solid var(--border)' }}>
                <td style={{ padding: '8px 10px' }}>{a.analyst}</td>
                <td style={{ padding: '8px 10px', textAlign: 'center', fontWeight: 700 }}>{a.rules_created}</td>
                <td style={{ padding: '8px 10px', textAlign: 'center', color: '#f97316', fontWeight: 700 }}>{a.suppressed.toLocaleString()}</td>
                <td style={{ padding: '8px 10px', textAlign: 'center', color: 'var(--text-3)' }}>{Math.round(a.suppressed / a.rules_created).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Rules Tab ─────────────────────────────────────────────────────────────
function RulesTab({ rules, onRefresh }: { rules: any[]; onRefresh: () => void }) {
  const [search, setSearch] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [selected, setSelected] = useState<any>(null);
  const [showApprove, setShowApprove] = useState(false);
  const [approveNotes, setApproveNotes] = useState('');

  const filtered = useMemo(() => rules.filter(r => {
    if (filterStatus && r.status !== filterStatus) return false;
    if (search) {
      const q = search.toLowerCase();
      return r.rule_name.toLowerCase().includes(q) || (r.description || '').toLowerCase().includes(q);
    }
    return true;
  }), [rules, filterStatus, search]);

  const setStatus = async (rule: any, status: string) => {
    await supAPI.updateRule(rule.id, { status });
    onRefresh();
  };

  const deleteRule = async (rule: any) => {
    await supAPI.deleteRule(rule.id);
    if (selected?.id === rule.id) setSelected(null);
    onRefresh();
  };

  const approve = async (decision: string) => {
    if (!selected) return;
    await supAPI.approveRule(selected.id, { decision, notes: approveNotes });
    setShowApprove(false);
    onRefresh();
  };

  let conditions: any[] = [];
  let exceptions: string[] = [];
  if (selected) {
    try { conditions = JSON.parse(selected.conditions || '[]'); } catch { conditions = []; }
    try { exceptions = JSON.parse(selected.exceptions || '[]'); } catch { exceptions = []; }
  }

  return (
    <div style={{ display: 'flex', gap: 14, height: 'calc(100vh - 220px)', minHeight: 500 }}>
      {/* Left list */}
      <div className="g-card" style={{ width: 340, flexShrink: 0, display: 'flex', flexDirection: 'column', padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)', display: 'flex', flexDirection: 'column', gap: 6 }}>
          <input className="g-input" placeholder="Search rules…" value={search} onChange={e => setSearch(e.target.value)} style={{ fontSize: 12 }} />
          <div style={{ display: 'flex', gap: 4 }}>
            <select className="g-select" value={filterStatus} onChange={e => setFilterStatus(e.target.value)} style={{ fontSize: 11, flex: 1 }}>
              <option value="">All Status</option>
              {['active', 'draft', 'disabled', 'expired'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={onRefresh}>↻</button>
          </div>
        </div>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {filtered.length === 0 && <div style={{ padding: 20, color: 'var(--text-3)', fontSize: 13, textAlign: 'center' }}>No rules</div>}
          {filtered.map(r => {
            const isSelected = selected?.id === r.id;
            const expiring = r.expires_at && new Date(r.expires_at).getTime() - Date.now() < 7 * 86400000 && new Date(r.expires_at) > new Date();
            return (
              <div key={r.id} onClick={() => setSelected(r)}
                style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)', cursor: 'pointer', background: isSelected ? 'var(--accent)10' : 'transparent', borderLeft: isSelected ? '3px solid var(--accent)' : '3px solid transparent' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                  <span style={{ fontWeight: 600, fontSize: 12, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.rule_name}</span>
                  <StatusPill s={r.status} />
                </div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                  <span style={{ fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 3, background: (SUP_TYPE_COLOR[r.suppression_type] || '#6b7280') + '22', color: SUP_TYPE_COLOR[r.suppression_type] || '#6b7280', border: `1px solid ${(SUP_TYPE_COLOR[r.suppression_type] || '#6b7280')}44` }}>
                    {SUP_TYPE_LABEL[r.suppression_type] || r.suppression_type}
                  </span>
                  {expiring && <span style={{ fontSize: 9, background: '#f9731622', color: '#f97316', padding: '1px 5px', borderRadius: 3, fontWeight: 700 }}>EXPIRING</span>}
                  {r.approval_status === 'pending' && <span style={{ fontSize: 9, background: '#f9731622', color: '#f97316', padding: '1px 5px', borderRadius: 3, fontWeight: 700 }}>NEEDS APPROVAL</span>}
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4, fontSize: 10, color: 'var(--text-3)' }}>
                  <span>{r.owner?.split('@')[0]}</span>
                  <span>{r.total_suppressed?.toLocaleString()} suppressed</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Right detail */}
      {!selected ? (
        <div className="g-card" style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 10 }}>
          <div style={{ fontSize: 36 }}>🔇</div>
          <div style={{ color: 'var(--text-3)', fontSize: 14 }}>Select a rule to inspect</div>
        </div>
      ) : (
        <div className="g-card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: 0 }}>
          <div style={{ padding: '14px 16px', borderBottom: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
              <span style={{ fontWeight: 700, fontSize: 15 }}>{selected.rule_name}</span>
              <StatusPill s={selected.status} />
              <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 3, background: (SUP_TYPE_COLOR[selected.suppression_type] || '#6b7280') + '22', color: SUP_TYPE_COLOR[selected.suppression_type] || '#6b7280', border: `1px solid ${(SUP_TYPE_COLOR[selected.suppression_type] || '#6b7280')}44` }}>
                {SUP_TYPE_LABEL[selected.suppression_type]}
              </span>
              {selected.approval_status === 'pending' && (
                <span style={{ fontSize: 10, background: '#f9731622', color: '#f97316', padding: '2px 7px', borderRadius: 3, fontWeight: 700 }}>PENDING APPROVAL</span>
              )}
            </div>
            {selected.description && <div style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 8 }}>{selected.description}</div>}
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {selected.status === 'draft' && selected.approval_status !== 'pending' && (
                <button className="g-btn g-btn-primary" style={{ fontSize: 12 }} onClick={() => setStatus(selected, 'active')}>Activate</button>
              )}
              {selected.status === 'active' && (
                <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={() => setStatus(selected, 'disabled')}>Disable</button>
              )}
              {selected.status === 'disabled' && (
                <button className="g-btn g-btn-primary" style={{ fontSize: 12 }} onClick={() => setStatus(selected, 'active')}>Re-enable</button>
              )}
              {selected.approval_status === 'pending' && (
                <button className="g-btn g-btn-primary" style={{ fontSize: 12, background: '#22c55e' }} onClick={() => setShowApprove(true)}>Review &amp; Approve</button>
              )}
              <button className="g-btn g-btn-ghost" style={{ fontSize: 12, color: '#ef4444' }} onClick={() => deleteRule(selected)}>Delete</button>
            </div>
          </div>

          {showApprove && (
            <div style={{ padding: '14px 16px', borderBottom: '1px solid var(--border)', background: '#f9731608' }}>
              <div style={{ fontWeight: 600, marginBottom: 8 }}>Approval Workflow</div>
              <div style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 10 }}>
                This rule is <strong>critical priority</strong> and requires approval before activation. Suppressing critical detections carries significant risk — review conditions carefully.
              </div>
              <textarea className="g-input" rows={2} value={approveNotes} onChange={e => setApproveNotes(e.target.value)} placeholder="Approval notes…" style={{ width: '100%', resize: 'none', marginBottom: 8, fontSize: 12 }} />
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="g-btn g-btn-primary" style={{ fontSize: 12, background: '#22c55e' }} onClick={() => approve('approve')}>Approve &amp; Activate</button>
                <button className="g-btn g-btn-ghost" style={{ fontSize: 12, color: '#ef4444' }} onClick={() => approve('reject')}>Reject</button>
                <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={() => setShowApprove(false)}>Cancel</button>
              </div>
            </div>
          )}

          <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 14 }}>
              <div className="g-card" style={{ padding: 12 }}>
                <div style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 8 }}>Rule Details</div>
                {[
                  ['Priority', selected.priority],
                  ['Scope', selected.scope?.replace(/_/g, ' ')],
                  ['Scope Value', selected.scope_value || 'All'],
                  ['Time Type', selected.time_type?.replace(/_/g, ' ')],
                  ['Expires', selected.expires_at ? new Date(selected.expires_at).toLocaleDateString() : 'Never'],
                  ['Owner', selected.owner],
                  ['Created', timeAgo(selected.created_at)],
                  ['Total Suppressed', selected.total_suppressed?.toLocaleString()],
                  ['Last Triggered', selected.last_triggered_at ? timeAgo(selected.last_triggered_at) : 'Never'],
                ].map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
                    <span style={{ color: 'var(--text-3)' }}>{k}</span>
                    <span style={{ fontWeight: 500, textAlign: 'right', textTransform: 'capitalize' }}>{String(v || '—')}</span>
                  </div>
                ))}
              </div>
              <div className="g-card" style={{ padding: 12 }}>
                <div style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 8 }}>Approval</div>
                {[
                  ['Status', selected.approval_status?.replace(/_/g, ' ')],
                  ['Approved By', selected.approved_by || '—'],
                ].map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
                    <span style={{ color: 'var(--text-3)' }}>{k}</span>
                    <span style={{ fontWeight: 600, color: APPROVAL_COLOR[selected.approval_status] || 'var(--text-1)' }}>{String(v)}</span>
                  </div>
                ))}
                <div style={{ marginTop: 14 }}>
                  <div style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 8 }}>Suppression Type</div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: SUP_TYPE_COLOR[selected.suppression_type] }}>{SUP_TYPE_LABEL[selected.suppression_type]}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>{supTypeDesc(selected.suppression_type)}</div>
                </div>
              </div>
            </div>

            <div className="g-card" style={{ padding: 12, marginBottom: 14 }}>
              <div style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 10 }}>Conditions</div>
              {conditions.length === 0 && <div style={{ color: 'var(--text-3)', fontSize: 13 }}>No conditions defined</div>}
              {conditions.map((cond: any, i: number) => (
                <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6, padding: '7px 10px', background: 'var(--bg)', borderRadius: 6, border: '1px solid var(--border)' }}>
                  {i === 0 && <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-3)', width: 24 }}>IF</span>}
                  {i > 0 && <span style={{ fontSize: 10, fontWeight: 700, color: '#3b82f6', width: 24 }}>AND</span>}
                  <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--accent)', fontFamily: 'monospace' }}>{cond.field}</span>
                  <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{cond.op}</span>
                  <span style={{ fontSize: 11, fontFamily: 'monospace', background: 'var(--border)', padding: '1px 6px', borderRadius: 4, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cond.value}</span>
                </div>
              ))}
            </div>

            {exceptions.length > 0 && (
              <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #22c55e' }}>
                <div style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 8 }}>Exceptions (Do NOT suppress)</div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {exceptions.map((ex: string) => (
                    <span key={ex} style={{ fontSize: 11, padding: '3px 10px', borderRadius: 10, background: '#22c55e22', color: '#22c55e', border: '1px solid #22c55e44', fontWeight: 600 }}>
                      {exceptionLabel(ex)}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Rule Builder Tab ─────────────────────────────────────────────────────
type Condition = { id: number; field: string; op: string; value: string; logic: 'AND' | 'OR' };

function BuilderTab({ onRefresh }: { onRefresh: () => void }) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [priority, setPriority] = useState('medium');
  const [supType, setSupType] = useState('full_suppress');
  const [scope, setScope] = useState('asset_group');
  const [scopeValue, setScopeValue] = useState('');
  const [timeType, setTimeType] = useState('until_date');
  const [expiresAt, setExpiresAt] = useState('');
  const [conditions, setConditions] = useState<Condition[]>([{ id: 1, field: 'detection_name', op: 'contains', value: '', logic: 'AND' }]);
  const [exceptions, setExceptions] = useState<string[]>([]);
  const [nextId, setNextId] = useState(2);
  const [previewResult, setPreviewResult] = useState<any>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [aiResult, setAiResult] = useState<any>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [detectionName, setDetectionName] = useState('');
  const [alertCount, setAlertCount] = useState('');
  const [incidentCount, setIncidentCount] = useState('0');
  const [saved, setSaved] = useState(false);

  const addCondition = () => {
    setConditions(cs => [...cs, { id: nextId, field: 'hostname', op: 'equals', value: '', logic: 'AND' }]);
    setNextId(n => n + 1);
  };

  const removeCondition = (id: number) => setConditions(cs => cs.filter(c => c.id !== id));

  const updateCondition = (id: number, key: keyof Condition, val: string) =>
    setConditions(cs => cs.map(c => c.id === id ? { ...c, [key]: val } : c));

  const toggleException = (ex: string) =>
    setExceptions(exs => exs.includes(ex) ? exs.filter(e => e !== ex) : [...exs, ex]);

  const runPreview = async () => {
    setPreviewLoading(true);
    const r = await supAPI.preview({ conditions: JSON.stringify(conditions), scope, scope_value: scopeValue });
    setPreviewResult(r.data);
    setPreviewLoading(false);
  };

  const runAI = async () => {
    if (!detectionName) return;
    setAiLoading(true);
    const r = await supAPI.askAI({ detection_name: detectionName, alert_count: parseInt(alertCount) || 0, incident_count: parseInt(incidentCount) || 0, asset_type: scope, severity: priority });
    setAiResult(r.data);
    setAiLoading(false);
  };

  const save = async () => {
    if (!name) return;
    await supAPI.createRule({ rule_name: name, description, priority, suppression_type: supType, scope, scope_value: scopeValue, time_type: timeType, expires_at: expiresAt, conditions: JSON.stringify(conditions), exceptions: JSON.stringify(exceptions) });
    setSaved(true);
    onRefresh();
  };

  return (
    <div style={{ display: 'flex', gap: 16, minHeight: 600 }}>
      {/* Builder left */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Rule Information</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div style={{ gridColumn: '1 / -1' }}>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Rule Name</label>
              <input className="g-input" value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Backup Window Suppression" style={{ width: '100%' }} />
            </div>
            <div style={{ gridColumn: '1 / -1' }}>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Description</label>
              <textarea className="g-input" rows={2} value={description} onChange={e => setDescription(e.target.value)} placeholder="What does this rule suppress and why?" style={{ width: '100%', resize: 'none' }} />
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Priority</label>
              <select className="g-select" value={priority} onChange={e => setPriority(e.target.value)} style={{ width: '100%' }}>
                {['low', 'medium', 'high', 'critical'].map(p => <option key={p} value={p}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>)}
              </select>
              {priority === 'critical' && <div style={{ fontSize: 10, color: '#f97316', marginTop: 3 }}>⚠ Critical rules require approval before activation</div>}
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Suppression Type</label>
              <select className="g-select" value={supType} onChange={e => setSupType(e.target.value)} style={{ width: '100%' }}>
                {SUP_TYPES.map(t => <option key={t} value={t}>{SUP_TYPE_LABEL[t]}</option>)}
              </select>
              <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 3 }}>{supTypeDesc(supType)}</div>
            </div>
          </div>
        </div>

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Conditions (AND / OR Logic)</div>
          {conditions.map((cond, i) => (
            <div key={cond.id} style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 8 }}>
              {i === 0 && <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-3)', width: 50, textAlign: 'right' }}>WHERE</span>}
              {i > 0 && (
                <select value={cond.logic} onChange={e => updateCondition(cond.id, 'logic', e.target.value)}
                  style={{ padding: '4px 6px', borderRadius: 4, border: '1px solid var(--border)', background: 'var(--bg)', color: '#3b82f6', fontWeight: 700, fontSize: 11, width: 52 }}>
                  <option value="AND">AND</option>
                  <option value="OR">OR</option>
                </select>
              )}
              <select className="g-select" value={cond.field} onChange={e => updateCondition(cond.id, 'field', e.target.value)} style={{ fontSize: 11, flex: 1 }}>
                {CONDITION_FIELDS.map(f => <option key={f} value={f}>{f.replace(/_/g, ' ')}</option>)}
              </select>
              <select className="g-select" value={cond.op} onChange={e => updateCondition(cond.id, 'op', e.target.value)} style={{ fontSize: 11, width: 96 }}>
                {CONDITION_OPS.map(o => <option key={o} value={o}>{o}</option>)}
              </select>
              <input className="g-input" value={cond.value} onChange={e => updateCondition(cond.id, 'value', e.target.value)} placeholder="value / regex / wildcard*" style={{ fontSize: 11, flex: 1 }} />
              {conditions.length > 1 && (
                <button onClick={() => removeCondition(cond.id)} style={{ background: 'transparent', border: 'none', color: '#ef4444', cursor: 'pointer', fontSize: 16, padding: '0 4px' }}>×</button>
              )}
            </div>
          ))}
          <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={addCondition}>+ Add Condition</button>
        </div>

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Scope &amp; Time</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Apply To</label>
              <select className="g-select" value={scope} onChange={e => setScope(e.target.value)} style={{ width: '100%' }}>
                {SCOPE_OPTIONS.map(s => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
              </select>
            </div>
            {scope !== 'entire_environment' && (
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Scope Value</label>
                <input className="g-input" value={scopeValue} onChange={e => setScopeValue(e.target.value)}
                  placeholder={scope === 'single_asset' ? 'hostname' : scope === 'cloud_account' ? '123456789012' : 'name…'}
                  style={{ width: '100%', fontSize: 11 }} />
              </div>
            )}
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Duration</label>
              <select className="g-select" value={timeType} onChange={e => setTimeType(e.target.value)} style={{ width: '100%' }}>
                {TIME_TYPES.map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
              </select>
            </div>
            {(timeType === 'until_date' || timeType === 'one_time') && (
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Expires At</label>
                <input type="datetime-local" className="g-input" value={expiresAt} onChange={e => setExpiresAt(e.target.value)} style={{ fontSize: 11 }} />
              </div>
            )}
          </div>
        </div>

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 10 }}>Exceptions (Do NOT suppress when)</div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {EXCEPTION_OPTIONS.map(ex => (
              <button key={ex} onClick={() => toggleException(ex)}
                className={exceptions.includes(ex) ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'}
                style={{ fontSize: 12 }}>
                {exceptions.includes(ex) ? '✓ ' : ''}{exceptionLabel(ex)}
              </button>
            ))}
          </div>
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <button className="g-btn g-btn-ghost" style={{ fontSize: 13 }} onClick={runPreview} disabled={previewLoading}>
            {previewLoading ? 'Previewing…' : '🔍 Preview Impact'}
          </button>
          <button className="g-btn g-btn-primary" style={{ fontSize: 13 }} onClick={save} disabled={!name || saved}>
            {saved ? '✓ Saved' : 'Save Rule'}
          </button>
        </div>
      </div>

      {/* Right: Preview + AI */}
      <div style={{ width: 340, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 14 }}>
        {/* AI Recommendation */}
        <div className="g-card" style={{ padding: 14 }}>
          <div style={{ fontWeight: 600, marginBottom: 10 }}>AI Recommendation</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 10 }}>
            <input className="g-input" value={detectionName} onChange={e => setDetectionName(e.target.value)} placeholder="Detection name…" style={{ fontSize: 12 }} />
            <div style={{ display: 'flex', gap: 6 }}>
              <input className="g-input" type="number" value={alertCount} onChange={e => setAlertCount(e.target.value)} placeholder="Alert count (30d)" style={{ fontSize: 12, flex: 1 }} />
              <input className="g-input" type="number" value={incidentCount} onChange={e => setIncidentCount(e.target.value)} placeholder="Incidents" style={{ fontSize: 12, width: 80 }} />
            </div>
            <button className="g-btn g-btn-primary" style={{ fontSize: 12 }} onClick={runAI} disabled={aiLoading || !detectionName}>
              {aiLoading ? 'Analyzing…' : 'Get AI Advice'}
            </button>
          </div>
          {aiResult && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <div style={{ padding: '8px 12px', borderRadius: 6, background: (aiResult.recommendation === 'suppress' ? '#22c55e' : aiResult.recommendation === 'do_not_suppress' ? '#ef4444' : '#f97316') + '22', border: `1px solid ${(aiResult.recommendation === 'suppress' ? '#22c55e' : aiResult.recommendation === 'do_not_suppress' ? '#ef4444' : '#f97316')}44` }}>
                <div style={{ fontWeight: 700, fontSize: 12, textTransform: 'uppercase', color: aiResult.recommendation === 'suppress' ? '#22c55e' : aiResult.recommendation === 'do_not_suppress' ? '#ef4444' : '#f97316' }}>
                  {aiResult.recommendation?.replace(/_/g, ' ')} · {aiResult.confidence_pct}% confidence
                </div>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.5 }}>{aiResult.reasoning}</div>
              {aiResult.conditions_if_conditional && aiResult.recommendation === 'conditional_suppress' && (
                <div style={{ fontSize: 11, color: 'var(--text-3)', borderLeft: '2px solid var(--accent)', paddingLeft: 8, lineHeight: 1.5 }}>Suggested conditions: {aiResult.conditions_if_conditional}</div>
              )}
              {aiResult.risk_if_suppressed && (
                <div style={{ fontSize: 11, color: '#f97316' }}>Risk: {aiResult.risk_if_suppressed}</div>
              )}
              {aiResult.alternative && (
                <div style={{ fontSize: 11, color: 'var(--text-3)' }}>Alternative: {aiResult.alternative}</div>
              )}
            </div>
          )}
        </div>

        {/* Preview Results */}
        {previewResult ? (
          <div className="g-card" style={{ padding: 14 }}>
            <div style={{ fontWeight: 600, marginBottom: 10 }}>Preview Results</div>
            <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
              <StatCard label="Historical Matches" value={previewResult.historical_matches?.toLocaleString()} sub={`in ${previewResult.lookback_days}d`} color="#f97316" />
              <StatCard label="Alerts/Day" value={previewResult.simulated_outcome?.alerts_per_day_before || 0} />
            </div>
            <div style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 6 }}>Impacted Assets</div>
              {previewResult.impacted_assets?.map((a: any) => (
                <div key={a.hostname} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
                  <span style={{ fontFamily: 'monospace' }}>{a.hostname}</span>
                  <span style={{ color: '#f97316', fontWeight: 700 }}>{a.alert_count?.toLocaleString()}</span>
                </div>
              ))}
            </div>
            <div style={{ padding: '8px 10px', borderRadius: 6, background: previewResult.simulated_outcome?.risk_assessment === 'low' ? '#22c55e22' : '#f9731622', border: `1px solid ${previewResult.simulated_outcome?.risk_assessment === 'low' ? '#22c55e44' : '#f9731644'}` }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: previewResult.simulated_outcome?.risk_assessment === 'low' ? '#22c55e' : '#f97316', marginBottom: 3 }}>
                Risk: {previewResult.simulated_outcome?.risk_assessment?.toUpperCase()}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-2)' }}>{previewResult.simulated_outcome?.recommendation}</div>
              <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 4 }}>Analyst hours saved/day: {previewResult.simulated_outcome?.analyst_hours_saved}</div>
            </div>
            {previewResult.sample_matches?.length > 0 && (
              <div style={{ marginTop: 10 }}>
                <div style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 6 }}>Sample Matches</div>
                {previewResult.sample_matches.slice(0, 3).map((m: any) => (
                  <div key={m.alert_id} style={{ padding: '5px 0', borderBottom: '1px solid var(--border)', fontSize: 11 }}>
                    <div style={{ fontFamily: 'monospace', color: 'var(--text-3)' }}>{m.alert_id}</div>
                    <div style={{ color: 'var(--text-2)' }}>{m.detection} · {m.asset}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : (
          <div className="g-card" style={{ padding: 16, flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 8 }}>
            <div style={{ fontSize: 28 }}>🔍</div>
            <div style={{ fontSize: 13, color: 'var(--text-3)', textAlign: 'center' }}>Click "Preview Impact" to see historical match count, impacted assets, and simulated outcome before saving</div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Analytics Tab ────────────────────────────────────────────────────────
function AnalyticsTab({ analytics }: { analytics: any }) {
  if (!analytics) return <div style={{ color: 'var(--text-3)', padding: 40, textAlign: 'center' }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Active Rules" value={analytics.active_rules} color="var(--accent)" />
        <StatCard label="Total Suppressed" value={analytics.total_suppressed?.toLocaleString()} color="#f97316" sub="all time" />
        <StatCard label="Hours Saved" value={`${analytics.analyst_hours_saved?.toLocaleString()}h`} color="#22c55e" sub="analyst time" />
        <StatCard label="FP Rate" value={`${analytics.false_positive_rate}%`} color="#22c55e" sub="of suppressed" />
        <StatCard label="Flagged Rules" value={analytics.suppression_effectiveness?.rules_with_incidents || 0} color={(analytics.suppression_effectiveness?.rules_with_incidents || 0) > 0 ? '#ef4444' : 'var(--text-1)'} sub="incident correlation" />
      </div>

      {(analytics.suppression_effectiveness?.rules_with_incidents || 0) > 0 && (
        <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #ef4444', background: '#ef444408' }}>
          <span style={{ fontWeight: 700, color: '#ef4444' }}>⚠ {analytics.suppression_effectiveness.rules_with_incidents} suppression rule(s) have been associated with confirmed incidents.</span>
          <span style={{ fontSize: 13, color: 'var(--text-2)', marginLeft: 8 }}>Review and adjust these rules immediately.</span>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Most Suppressed Rules</div>
          {analytics.most_suppressed_rules?.map((r: any) => (
            <div key={r.rule_name} style={{ marginBottom: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 3 }}>
                <span style={{ fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '65%' }}>{r.rule_name}</span>
                <span style={{ color: '#f97316', fontWeight: 700 }}>{r.suppressed?.toLocaleString()}</span>
              </div>
              <div style={{ background: 'var(--border)', borderRadius: 2, height: 5 }}>
                <div style={{ background: '#f97316', borderRadius: 2, height: 5, width: `${(r.suppressed / (analytics.most_suppressed_rules[0]?.suppressed || 1)) * 100}%` }} />
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{r.scope} · {r.owner?.split('@')[0]}</div>
            </div>
          ))}
        </div>

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Top Noisy Detections</div>
          {analytics.top_noisy_detections?.map((d: any) => (
            <div key={d.detection} style={{ marginBottom: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 3 }}>
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '60%', color: 'var(--text-2)' }}>{d.detection}</span>
                <span style={{ color: d.rate_pct > 90 ? '#22c55e' : '#f97316', fontWeight: 700 }}>{d.rate_pct?.toFixed(0)}% suppressed</span>
              </div>
              <div style={{ background: 'var(--border)', borderRadius: 2, height: 5 }}>
                <div style={{ background: d.rate_pct > 90 ? '#22c55e' : '#f97316', borderRadius: 2, height: 5, width: `${d.rate_pct}%` }} />
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{d.total?.toLocaleString()} total · {d.suppressed?.toLocaleString()} suppressed</div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Suppression by Team</div>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr>
                {['Team', 'Rules', 'Suppressed'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '5px 8px', color: 'var(--text-3)', fontSize: 11, fontWeight: 600, textTransform: 'uppercase' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {analytics.suppression_by_team?.map((t: any) => (
                <tr key={t.team} style={{ borderTop: '1px solid var(--border)' }}>
                  <td style={{ padding: '7px 8px' }}>{t.team}</td>
                  <td style={{ padding: '7px 8px', textAlign: 'center', fontWeight: 600 }}>{t.rules_created}</td>
                  <td style={{ padding: '7px 8px', textAlign: 'right', color: '#f97316', fontWeight: 700 }}>{t.alerts_suppressed?.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>False Positive Trend</div>
          <div style={{ display: 'flex', gap: 4, alignItems: 'flex-end', height: 80 }}>
            {analytics.false_positive_trend?.map((d: any) => {
              const max = Math.max(...analytics.false_positive_trend.map((x: any) => Math.max(x.fps, x.suppressed)), 1);
              return (
                <div key={d.month} style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 2, alignItems: 'center' }}>
                  <div style={{ width: '100%', display: 'flex', gap: 2, alignItems: 'flex-end', height: 64 }}>
                    <div style={{ flex: 1, background: '#ef444444', height: `${(d.fps / max) * 64}px`, borderRadius: '2px 2px 0 0' }} title={`FPs: ${d.fps}`} />
                    <div style={{ flex: 1, background: '#22c55e66', height: `${(d.suppressed / max) * 64}px`, borderRadius: '2px 2px 0 0' }} title={`Suppressed: ${d.suppressed}`} />
                  </div>
                  <div style={{ fontSize: 9, color: 'var(--text-3)' }}>{d.month}</div>
                </div>
              );
            })}
          </div>
          <div style={{ display: 'flex', gap: 12, marginTop: 6, fontSize: 10, color: 'var(--text-3)' }}>
            <span><span style={{ width: 10, height: 10, background: '#ef444444', display: 'inline-block', borderRadius: 2, marginRight: 4 }} />False Positives</span>
            <span><span style={{ width: 10, height: 10, background: '#22c55e66', display: 'inline-block', borderRadius: 2, marginRight: 4 }} />Suppressed</span>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Audit Tab ────────────────────────────────────────────────────────────
function AuditTab({ entries }: { entries: any[] }) {
  const ACTION_COLOR: Record<string, string> = {
    created: '#3b82f6', modified: '#f97316', active: '#22c55e', disabled: '#6b7280',
    expired: '#ef4444', deleted: '#ef4444', approved: '#22c55e', rejected: '#ef4444',
  };
  return (
    <div className="g-card" style={{ overflow: 'hidden' }}>
      <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontWeight: 600 }}>Suppression Audit Trail</span>
        <span style={{ fontSize: 12, color: 'var(--text-3)' }}>Immutable — all changes recorded</span>
      </div>
      {entries.length === 0 && <div style={{ padding: 24, color: 'var(--text-3)', textAlign: 'center' }}>No audit entries</div>}
      <div style={{ overflowX: 'auto' }}>
        <table className="g-table" style={{ width: '100%' }}>
          <thead className="g-thead">
            <tr>
              {['Time', 'Rule', 'Action', 'Actor', 'Details'].map(h => (
                <th key={h} className="g-tr" style={{ padding: '8px 14px', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {entries.map(e => (
              <tr key={e.id} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '9px 14px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(e.created_at)}</td>
                <td style={{ padding: '9px 14px', fontSize: 12, fontWeight: 600, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.rule_name}</td>
                <td style={{ padding: '9px 14px' }}>
                  <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 10, background: (ACTION_COLOR[e.action] || '#6b7280') + '22', color: ACTION_COLOR[e.action] || '#6b7280', textTransform: 'capitalize' }}>{e.action}</span>
                </td>
                <td style={{ padding: '9px 14px', fontSize: 12, color: 'var(--text-2)' }}>{e.actor}</td>
                <td style={{ padding: '9px 14px', fontSize: 12, color: 'var(--text-2)', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Reports Tab ──────────────────────────────────────────────────────────
function ReportsTab() {
  const [reportType, setReportType] = useState('suppression');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const REPORT_TYPES: [string, string][] = [
    ['suppression', 'Suppression Report'], ['false_positive', 'False Positive Report'],
    ['effectiveness', 'Rule Effectiveness Report'], ['audit', 'Audit Report'], ['compliance', 'Compliance Report'],
  ];
  const generate = async () => {
    setLoading(true);
    const r = await supAPI.generateReport({ report_type: reportType });
    setResult(r.data);
    setLoading(false);
  };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 800 }}>
      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 14 }}>Generate Report</div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'flex-end' }}>
          <div style={{ flex: 1 }}>
            <label style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', display: 'block', marginBottom: 4 }}>Report Type</label>
            <select className="g-select" value={reportType} onChange={e => setReportType(e.target.value)} style={{ width: '100%' }}>
              {REPORT_TYPES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </div>
          <button className="g-btn g-btn-primary" onClick={generate} disabled={loading}>{loading ? 'Generating…' : 'Generate'}</button>
        </div>
      </div>
      {result && (
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: 15 }}>{result.title}</div>
              <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 2 }}>Generated {new Date(result.generated_at).toLocaleString()} · {result.classification}</div>
            </div>
            <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }}>⬇ Export PDF</button>
          </div>
          <div className="g-card" style={{ padding: 12, marginBottom: 16, borderLeft: '3px solid var(--accent)' }}>
            <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 6 }}>Executive Summary</div>
            <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.5 }}>{result.executive_summary}</div>
          </div>
          {result.key_metrics && (
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 16 }}>
              {Object.entries(result.key_metrics).map(([k, v]) => <StatCard key={k} label={k.replace(/_/g, ' ')} value={String(v)} />)}
            </div>
          )}
          {result.flagged_rules?.length > 0 && (
            <div className="g-card" style={{ padding: 12, marginBottom: 14, borderLeft: '3px solid #ef4444' }}>
              <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8, color: '#ef4444' }}>Flagged Rules — Incident Correlation</div>
              {result.flagged_rules.map((r: any) => (
                <div key={r.rule} style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 4 }}>
                  <strong>{r.rule}</strong> — {r.issue}
                </div>
              ))}
            </div>
          )}
          {result.recommendations?.length > 0 && (
            <div>
              <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8 }}>Recommendations</div>
              {result.recommendations.map((r: string, i: number) => (
                <div key={i} style={{ display: 'flex', gap: 8, fontSize: 12, color: 'var(--text-2)', marginBottom: 5 }}>
                  <span style={{ color: 'var(--accent)', fontWeight: 700 }}>{i + 1}.</span><span>{r}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────
export default function SuppressionPage() {
  const [tab, setTab] = useState<Tab>('dashboard');
  const loaded = useRef<Record<string, boolean>>({});

  const [dash, setDash] = useState<any>(null);
  const [rules, setRules] = useState<any[]>([]);
  const [audit, setAudit] = useState<any[]>([]);
  const [analytics, setAnalytics] = useState<any>(null);

  useEffect(() => {
    loaded.current['dashboard'] = true;
    loaded.current['rules'] = true;
    loaded.current['builder'] = true;
    supAPI.getDashboard().then(r => setDash(r.data));
    supAPI.getRules().then(r => setRules(r.data || []));
  }, []);

  const refreshRules = () => {
    supAPI.getRules().then(r => setRules(r.data || []));
    supAPI.getDashboard().then(r => setDash(r.data));
  };

  const switchTab = (t: Tab) => {
    setTab(t);
    if (!loaded.current[t]) {
      loaded.current[t] = true;
      if (t === 'audit') supAPI.getAudit().then(r => setAudit(r.data || []));
      if (t === 'analytics') supAPI.getAnalytics().then(r => setAnalytics(r.data));
    }
  };

  return (
    <RootLayout>
      <div style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 20, height: '100%' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>Alert Suppression</h1>
            <div style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 4 }}>
              Noise reduction · False positive management · Rule builder · AI recommendations · Preview mode
            </div>
          </div>
          {dash?.expiring_rules > 0 && (
            <div style={{ padding: '6px 14px', borderRadius: 6, background: '#f9731622', color: '#f97316', fontSize: 12, fontWeight: 700, border: '1px solid #f9731644' }}>
              {dash.expiring_rules} rule{dash.expiring_rules !== 1 ? 's' : ''} expiring soon
            </div>
          )}
        </div>

        <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', overflowX: 'auto' }}>
          {(Object.keys(TAB_LABELS) as Tab[]).map(t => (
            <button key={t} onClick={() => switchTab(t)}
              style={{ padding: '8px 16px', fontSize: 12, fontWeight: tab === t ? 600 : 400, color: tab === t ? 'var(--accent)' : 'var(--text-3)', background: 'transparent', border: 'none', borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent', cursor: 'pointer', whiteSpace: 'nowrap' }}>
              {TAB_LABELS[t]}
              {t === 'rules' && rules.length > 0 && (
                <span style={{ marginLeft: 5, fontSize: 10, background: 'var(--border)', padding: '1px 5px', borderRadius: 8, color: 'var(--text-3)' }}>{rules.length}</span>
              )}
            </button>
          ))}
        </div>

        <div style={{ display: tab === 'dashboard' ? 'block' : 'none' }}><DashboardTab dash={dash} /></div>
        <div style={{ display: tab === 'rules' ? 'block' : 'none' }}>
          {loaded.current['rules'] && <RulesTab rules={rules} onRefresh={refreshRules} />}
        </div>
        <div style={{ display: tab === 'builder' ? 'block' : 'none' }}>
          {loaded.current['builder'] && <BuilderTab onRefresh={refreshRules} />}
        </div>
        <div style={{ display: tab === 'analytics' ? 'block' : 'none' }}>
          {loaded.current['analytics'] && <AnalyticsTab analytics={analytics} />}
        </div>
        <div style={{ display: tab === 'audit' ? 'block' : 'none' }}>
          {loaded.current['audit'] && <AuditTab entries={audit} />}
        </div>
        <div style={{ display: tab === 'reports' ? 'block' : 'none' }}>
          {loaded.current['reports'] && <ReportsTab />}
        </div>
      </div>
    </RootLayout>
  );
}
