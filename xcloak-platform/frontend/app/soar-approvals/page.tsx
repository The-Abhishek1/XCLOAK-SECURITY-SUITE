'use client';

import React, { useState, useEffect, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { aqAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import { MetricCard, DataTable, SectionCard, TabBar, ActionButton } from '@/components/design-system';
import {
  LayoutDashboard, Inbox, Scale, BarChart3, ScrollText, FileText,
  Monitor, User, Globe, Mail, Cloud, Check, X, HelpCircle, CornerUpRight, ArrowUp, Pause, Flame,
  AlertTriangle, Square, Download, CornerDownRight,
} from 'lucide-react';

type Tab = 'overview' | 'queue' | 'policies' | 'analytics' | 'audit' | 'reports';
const TAB_LABELS: Record<Tab, string> = {
  overview: 'Dashboard',
  queue: 'Approval Queue',
  policies: 'Policies & Matrix',
  analytics: 'Analytics',
  audit: 'Audit Trail',
  reports: 'Reports',
};
const TAB_ICONS: Record<Tab, any> = {
  overview: LayoutDashboard, queue: Inbox, policies: Scale, analytics: BarChart3, audit: ScrollText, reports: FileText,
};

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
};
const STATUS_COLOR: Record<string, string> = {
  pending: '#3b82f6', approved: '#22c55e', rejected: '#ef4444',
  expired: '#6b7280', delegated: '#a855f7',
};
const POLICY_COLOR: Record<string, string> = {
  automatic: '#22c55e', soc_lead: '#3b82f6', manager_approval: '#f97316',
  dual_approval: '#a855f7', executive_approval: '#ef4444',
};
const POLICY_LABEL: Record<string, string> = {
  automatic: 'Auto-Approved', soc_lead: 'SOC Lead', manager_approval: 'Manager',
  dual_approval: 'Dual Approval', executive_approval: 'Executive',
};

function SevBadge({ sev }: { sev: string }) {
  return (
    <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 3, background: SEV_COLOR[sev] || '#6b7280', color: '#fff', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
      {sev}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const color = STATUS_COLOR[status] || '#6b7280';
  return (
    <span style={{ fontSize: 10, fontWeight: 600, padding: '2px 8px', borderRadius: 10, background: color + '22', color, border: `1px solid ${color}44`, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
      {status.replace('_', ' ')}
    </span>
  );
}

function RiskBadge({ score }: { score: number }) {
  const color = score >= 90 ? '#ef4444' : score >= 70 ? '#f97316' : score >= 50 ? '#eab308' : '#22c55e';
  return (
    <span style={{ fontSize: 12, fontWeight: 700, padding: '2px 8px', borderRadius: 4, background: color + '22', color, border: `1px solid ${color}44` }}>
      {score}
    </span>
  );
}

function DueTag({ dueAt, status }: { dueAt?: string; status: string }) {
  if (!dueAt || status !== 'pending') return null;
  const diff = new Date(dueAt).getTime() - Date.now();
  const mins = Math.floor(diff / 60000);
  const overdue = diff < 0;
  const urgent = !overdue && mins < 10;
  return (
    <span style={{ fontSize: 10, padding: '1px 6px', borderRadius: 3, background: overdue ? '#ef444422' : urgent ? '#f9731622' : '#22c55e22', color: overdue ? '#ef4444' : urgent ? '#f97316' : '#22c55e', border: `1px solid ${overdue ? '#ef444444' : urgent ? '#f9731644' : '#22c55e44'}`, fontWeight: 600 }}>
      {overdue ? `Overdue ${Math.abs(mins)}m` : `Due ${mins}m`}
    </span>
  );
}

// ─── Overview Tab ─────────────────────────────────────────────────────────────
const CATEGORY_ICON: Record<string, any> = {
  endpoint: Monitor, identity: User, network: Globe, email: Mail, cloud: Cloud,
};

function OverviewTab({ dash }: { dash: any }) {
  if (!dash) return <div style={{ color: 'var(--text-3)', padding: 40, textAlign: 'center' }}>Loading dashboard…</div>;
  const totalByCategory = (dash.by_category || []).reduce((sum: number, c: any) => sum + c.count, 0) || 1;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <MetricCard label="Pending" value={dash.pending} color="#f97316" />
        <MetricCard label="Approved" value={dash.approved} color="#22c55e" />
        <MetricCard label="Rejected" value={dash.rejected} color="#ef4444" />
        <MetricCard label="Expired" value={dash.expired} color="#6b7280" />
        <MetricCard label="High Risk" value={dash.high_risk} color="#ef4444" sub="critical + high severity" />
        <MetricCard label="Emergency" value={dash.emergency} color="#ef4444" sub="break-glass events" />
        <MetricCard label="Avg Approval" value={`${dash.avg_approval_time_min?.toFixed(1)}m`} color="var(--accent)" />
        <MetricCard label="SLA Compliance" value={`${dash.sla_compliance?.toFixed(1)}%`} color={dash.sla_compliance >= 95 ? '#22c55e' : '#f97316'} />
        <MetricCard label="Auto-Approved" value={dash.auto_approved} color="#22c55e" sub="no human required" />
        <MetricCard label="Total Requests" value={dash.total_requests} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <SectionCard title="Approval Flow" subtitle="Approved requests, by policy">
          {(dash.by_policy || []).length === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No approved requests yet.</div>
          ) : (dash.by_policy || []).map((item: any) => (
            <div key={item.policy} style={{ marginBottom: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 3 }}>
                <span style={{ color: 'var(--text-2)', textTransform: 'capitalize' }}>{item.policy.replace(/_/g, ' ')}</span>
                <span style={{ fontWeight: 600 }}>{item.count}</span>
              </div>
              <div style={{ background: 'var(--border)', borderRadius: 2, height: 6 }}>
                <div style={{ background: 'var(--accent)', borderRadius: 2, height: 6, width: `${Math.min(100, (item.count / (dash.approved || 1)) * 100)}%` }} />
              </div>
            </div>
          ))}
        </SectionCard>

        <SectionCard title="By Request Category">
          {(dash.by_category || []).length === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No requests yet.</div>
          ) : (dash.by_category || []).map((item: any) => {
            const Icon = CATEGORY_ICON[item.category] || Globe;
            const pct = Math.round((item.count / totalByCategory) * 100);
            return (
              <div key={item.category} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <Icon style={{ width: 14, height: 14, color: 'var(--text-3)' }} />
                <span style={{ fontSize: 12, color: 'var(--text-2)', flex: 1, textTransform: 'capitalize' }}>{item.category.replace(/_/g, ' ')}</span>
                <div style={{ width: 100, background: 'var(--border)', borderRadius: 2, height: 6 }}>
                  <div style={{ background: 'var(--accent)', borderRadius: 2, height: 6, width: `${pct}%` }} />
                </div>
                <span style={{ fontSize: 11, color: 'var(--text-3)', width: 30, textAlign: 'right' }}>{pct}%</span>
              </div>
            );
          })}
        </SectionCard>
      </div>

      {dash.pending > 0 && (
        <div className="g-card" style={{ padding: 14, borderLeft: '3px solid #f97316', background: '#f9731608' }}>
          <div style={{ fontWeight: 600, color: '#f97316', marginBottom: 4 }}>Action Required</div>
          <div style={{ fontSize: 13, color: 'var(--text-2)' }}>
            {dash.pending} approval request{dash.pending !== 1 ? 's' : ''} pending review.
            {dash.emergency > 0 && <span style={{ color: '#ef4444', fontWeight: 700 }}> {dash.emergency} emergency request requires immediate attention.</span>}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Queue Tab ────────────────────────────────────────────────────────────────
function QueueTab({
  requests, selectedId, onSelect, onRefresh,
  requestDetail, evidence, timeline, comments, aiResult, aiLoading, approvers,
  detailTab, setDetailTab, onDecide, onDelegate, onEmergency, onAddComment,
  queueFilter, setQueueFilter, searchQ, setSearchQ,
}: {
  requests: any[]; selectedId: number | null; onSelect: (id: number) => void; onRefresh: () => void;
  requestDetail: any; evidence: any; timeline: any[]; comments: any[]; aiResult: any; aiLoading: boolean; approvers: any[];
  detailTab: string; setDetailTab: (t: string) => void;
  onDecide: (type: string) => void; onDelegate: (delegatee: string, notes: string) => void;
  onEmergency: (justification: string) => void; onAddComment: (content: string, type: string) => void;
  queueFilter: string; setQueueFilter: (f: string) => void; searchQ: string; setSearchQ: (q: string) => void;
}) {
  const [newComment, setNewComment] = useState('');
  const [commentType, setCommentType] = useState('note');
  const [delegateeInput, setDelegateeInput] = useState('');
  const [delegateNotes, setDelegateNotes] = useState('');
  const [showDelegateForm, setShowDelegateForm] = useState(false);
  const [emergencyText, setEmergencyText] = useState('');
  const [showEmergencyForm, setShowEmergencyForm] = useState(false);
  const [decisionNotes, setDecisionNotes] = useState('');
  const [pendingDecision, setPendingDecision] = useState<string | null>(null);

  const filtered = useMemo(() => requests.filter(r => {
    if (queueFilter !== 'all' && r.status !== queueFilter) return false;
    if (searchQ) {
      const q = searchQ.toLowerCase();
      return (
        r.approval_id.toLowerCase().includes(q) ||
        r.requested_action.toLowerCase().includes(q) ||
        (r.target_asset || '').toLowerCase().includes(q) ||
        (r.target_user || '').toLowerCase().includes(q) ||
        (r.incident_id || '').toLowerCase().includes(q)
      );
    }
    return true;
  }), [requests, queueFilter, searchQ]);

  const DETAIL_TABS = ['overview', 'evidence', 'timeline', 'ai', 'comments'];

  return (
    <div style={{ display: 'flex', gap: 16, height: 'calc(100vh - 220px)', minHeight: 500 }}>
      {/* Left panel */}
      <div className="g-card" style={{ width: 340, flexShrink: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: 0 }}>
        <div style={{ padding: '12px 12px 8px', borderBottom: '1px solid var(--border)' }}>
          <input
            className="g-input"
            placeholder="Search ID, action, asset, user…"
            value={searchQ}
            onChange={e => setSearchQ(e.target.value)}
            style={{ width: '100%', marginBottom: 8, fontSize: 12 }}
          />
          <div style={{ display: 'flex', gap: 4 }}>
            {(['pending', 'approved', 'rejected', 'all'] as const).map(f => (
              <ActionButton key={f} variant={queueFilter === f ? 'primary' : 'ghost'} onClick={() => setQueueFilter(f)} style={{ fontSize: 10, padding: '3px 8px' }}>
                {f.charAt(0).toUpperCase() + f.slice(1)}
                {f !== 'all' && <span style={{ marginLeft: 3, opacity: 0.7 }}>({requests.filter(r => r.status === f).length})</span>}
              </ActionButton>
            ))}
            <ActionButton variant="ghost" onClick={onRefresh} style={{ fontSize: 10, padding: '3px 8px', marginLeft: 'auto' }}>↻</ActionButton>
          </div>
        </div>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {filtered.length === 0 && <div style={{ padding: 24, color: 'var(--text-3)', fontSize: 13, textAlign: 'center' }}>No requests</div>}
          {filtered.map(r => (
            <div key={r.id} onClick={() => onSelect(r.id)}
              style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)', cursor: 'pointer', background: selectedId === r.id ? 'var(--accent)12' : 'transparent', borderLeft: selectedId === r.id ? '3px solid var(--accent)' : '3px solid transparent' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-3)', fontFamily: 'monospace' }}>{r.approval_id}</span>
                {r.is_emergency && <span style={{ fontSize: 9, fontWeight: 700, padding: '1px 5px', borderRadius: 3, background: '#ef4444', color: '#fff' }}>EMERGENCY</span>}
                <span style={{ marginLeft: 'auto' }}><SevBadge sev={r.severity} /></span>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-1)', fontWeight: 500, marginBottom: 4, lineHeight: 1.3, display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
                {r.requested_action}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                <StatusBadge status={r.status} />
                <RiskBadge score={r.risk_score} />
                {r.due_at && <DueTag dueAt={r.due_at} status={r.status} />}
                <span style={{ fontSize: 10, color: 'var(--text-3)', marginLeft: 'auto' }}>{timeAgo(r.created_at)}</span>
              </div>
              {r.incident_id && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: 10, color: 'var(--text-3)', marginTop: 3 }}>
                  <CornerDownRight style={{ width: 10, height: 10 }} /> {r.incident_id}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Right panel */}
      {!requestDetail ? (
        <div className="g-card" style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 12 }}>
          <Inbox style={{ width: 32, height: 32, color: 'var(--text-3)' }} />
          <div style={{ color: 'var(--text-3)', fontSize: 14 }}>Select a request from the queue to review</div>
        </div>
      ) : (
        <div className="g-card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: 0 }}>
          {/* Header */}
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <span style={{ fontWeight: 700, fontFamily: 'monospace', fontSize: 14 }}>{requestDetail.approval_id}</span>
              {requestDetail.is_emergency && <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 3, background: '#ef4444', color: '#fff' }}>EMERGENCY</span>}
              <SevBadge sev={requestDetail.severity} />
              <StatusBadge status={requestDetail.status} />
              <RiskBadge score={requestDetail.risk_score} />
              {requestDetail.due_at && <DueTag dueAt={requestDetail.due_at} status={requestDetail.status} />}
              <span style={{ fontSize: 11, color: 'var(--text-3)', marginLeft: 'auto' }}>
                by <strong>{requestDetail.requester}</strong> · {timeAgo(requestDetail.created_at)}
              </span>
            </div>
            <div style={{ marginTop: 8, fontSize: 13, color: 'var(--text-2)', lineHeight: 1.4 }}>
              <strong>Action:</strong> {requestDetail.requested_action}
            </div>
            <div style={{ display: 'flex', gap: 16, marginTop: 6, fontSize: 12, color: 'var(--text-3)', flexWrap: 'wrap' }}>
              {requestDetail.target_asset && <span>Asset: <strong style={{ color: 'var(--text-2)' }}>{requestDetail.target_asset}</strong></span>}
              {requestDetail.target_user && <span>User: <strong style={{ color: 'var(--text-2)' }}>{requestDetail.target_user}</strong></span>}
              {requestDetail.current_approver && <span>Approver: <strong style={{ color: 'var(--text-2)' }}>{requestDetail.current_approver}</strong></span>}
              {requestDetail.incident_id && <span>Incident: <strong style={{ color: 'var(--accent)' }}>{requestDetail.incident_id}</strong></span>}
            </div>
          </div>

          {/* Detail sub-tabs */}
          <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', paddingLeft: 16 }}>
            {DETAIL_TABS.map(t => (
              <button key={t} onClick={() => setDetailTab(t)}
                style={{ padding: '8px 14px', fontSize: 12, fontWeight: detailTab === t ? 600 : 400, color: detailTab === t ? 'var(--accent)' : 'var(--text-3)', background: 'transparent', border: 'none', borderBottom: detailTab === t ? '2px solid var(--accent)' : '2px solid transparent', cursor: 'pointer', textTransform: 'capitalize' }}>
                {t === 'ai' ? 'AI Risk' : t}
                {t === 'comments' && comments.length > 0 && <span style={{ marginLeft: 4, fontSize: 10, background: 'var(--accent)', color: '#fff', borderRadius: 10, padding: '0 4px' }}>{comments.length}</span>}
              </button>
            ))}
          </div>

          {/* Detail body */}
          <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>

            {detailTab === 'overview' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                <div className="g-card" style={{ padding: 14 }}>
                  <div style={{ fontWeight: 600, marginBottom: 8 }}>Description</div>
                  <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.5 }}>{requestDetail.description || 'No description provided.'}</div>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  <div className="g-card" style={{ padding: 12 }}>
                    <div style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Request Details</div>
                    {[['Type', requestDetail.request_type], ['Category', requestDetail.action_category], ['Risk Level', requestDetail.risk_level], ['Policy', POLICY_LABEL[requestDetail.policy] || requestDetail.policy]].map(([k, v]) => (
                      <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 5 }}>
                        <span style={{ color: 'var(--text-3)' }}>{k}</span>
                        <span style={{ fontWeight: 500, color: 'var(--text-1)' }}>{v || '—'}</span>
                      </div>
                    ))}
                  </div>
                  <div className="g-card" style={{ padding: 12 }}>
                    <div style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Related Context</div>
                    {[['Incident', requestDetail.incident_id], ['Case', requestDetail.case_id], ['Alert', requestDetail.alert_id], ['MITRE', requestDetail.mitre_technique]].map(([k, v]) => (
                      <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 5 }}>
                        <span style={{ color: 'var(--text-3)' }}>{k}</span>
                        <span style={{ fontWeight: 500, color: v ? 'var(--accent)' : 'var(--text-3)', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v || '—'}</span>
                      </div>
                    ))}
                  </div>
                </div>
                {requestDetail.business_impact && (
                  <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #eab308', background: '#eab30808' }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: '#eab308', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Business Impact</div>
                    <div style={{ fontSize: 13, color: 'var(--text-2)' }}>{requestDetail.business_impact}</div>
                  </div>
                )}
                {requestDetail.mitre_technique && (
                  <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #ef4444', background: '#ef444408' }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: '#ef4444', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>MITRE ATT&CK</div>
                    <div style={{ fontSize: 13, color: 'var(--text-2)' }}>{requestDetail.mitre_technique}</div>
                  </div>
                )}
              </div>
            )}

            {detailTab === 'evidence' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {evidence?.incident && (
                  <div className="g-card" style={{ padding: 12 }}>
                    <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8 }}>Related Incident</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontFamily: 'monospace', color: 'var(--accent)', fontSize: 12 }}>{evidence.incident.id}</span>
                      <span style={{ fontSize: 12 }}>{evidence.incident.title}</span>
                      <span style={{ marginLeft: 'auto' }}><SevBadge sev={evidence.incident.severity} /></span>
                      <StatusBadge status={evidence.incident.status} />
                    </div>
                  </div>
                )}
                {evidence?.related_alerts && (
                  <div className="g-card" style={{ padding: 12 }}>
                    <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8 }}>Related Alerts ({evidence.related_alerts.length})</div>
                    {evidence.related_alerts.map((a: any) => (
                      <div key={a.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 8px', background: 'var(--bg)', borderRadius: 4, marginBottom: 4 }}>
                        <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-3)' }}>{a.id}</span>
                        <span style={{ fontSize: 12, flex: 1 }}>{a.title}</span>
                        <SevBadge sev={a.severity} />
                        <span style={{ fontSize: 10, color: 'var(--text-3)' }}>{timeAgo(a.created_at)}</span>
                      </div>
                    ))}
                  </div>
                )}
                {evidence?.threat_intel && (
                  <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #ef4444' }}>
                    <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8 }}>Threat Intelligence (matched IOC)</div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                      {[['Indicator', evidence.threat_intel.indicator], ['Type', evidence.threat_intel.type], ['Severity', evidence.threat_intel.severity], ['Description', evidence.threat_intel.description], ['Hit Count', evidence.threat_intel.hit_count], ['Last Seen', evidence.threat_intel.last_seen ? timeAgo(evidence.threat_intel.last_seen) : '—']].map(([k, v]) => (
                        <div key={k}>
                          <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{k}</div>
                          <div style={{ fontSize: 12, fontWeight: 600, color: k === 'Severity' && (v === 'critical' || v === 'high') ? '#ef4444' : 'var(--text-1)' }}>{v}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {!evidence?.incident && !evidence?.threat_intel && (
                  <div style={{ fontSize: 12, color: 'var(--text-3)', textAlign: 'center', padding: '1.5rem' }}>
                    No linked incident, alert, or matching IOC found for this request.
                  </div>
                )}
              </div>
            )}

            {detailTab === 'timeline' && (
              <div>
                {timeline.length === 0 && <div style={{ color: 'var(--text-3)', fontSize: 13 }}>No timeline events yet.</div>}
                {timeline.map((e: any, i: number) => (
                  <div key={e.id} style={{ display: 'flex', gap: 12, paddingBottom: 16 }}>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: 28 }}>
                      <div style={{ width: 10, height: 10, borderRadius: '50%', background: e.action === 'emergency_override' ? '#ef4444' : e.action === 'approved' ? '#22c55e' : e.action === 'rejected' ? '#ef4444' : 'var(--accent)', flexShrink: 0, marginTop: 2 }} />
                      {i < timeline.length - 1 && <div style={{ flex: 1, width: 2, background: 'var(--border)', marginTop: 4 }} />}
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontSize: 12, fontWeight: 600, textTransform: 'capitalize' }}>{e.action.replace('_', ' ')}</span>
                        <span style={{ fontSize: 11, color: 'var(--text-3)' }}>by <strong>{e.actor}</strong></span>
                        <span style={{ fontSize: 10, color: 'var(--text-3)', marginLeft: 'auto' }}>{timeAgo(e.created_at)}</span>
                      </div>
                      {e.details && <div style={{ fontSize: 12, color: 'var(--text-2)', marginTop: 3 }}>{e.details}</div>}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {detailTab === 'ai' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {aiLoading && <div style={{ color: 'var(--text-3)', fontSize: 13, textAlign: 'center', padding: 24 }}>AI is analyzing this request…</div>}
                {!aiLoading && !aiResult && <div style={{ color: 'var(--text-3)', fontSize: 13, textAlign: 'center', padding: 24 }}>AI analysis not available.</div>}
                {aiResult && (
                  <>
                    <div className="g-card" style={{ padding: 14, borderLeft: `3px solid ${aiResult.recommendation === 'approve' ? '#22c55e' : aiResult.recommendation === 'reject' ? '#ef4444' : '#f97316'}` }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                        <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-3)' }}>AI Recommendation</span>
                        <span style={{ fontSize: 14, fontWeight: 700, padding: '3px 12px', borderRadius: 4, background: (aiResult.recommendation === 'approve' ? '#22c55e' : aiResult.recommendation === 'reject' ? '#ef4444' : '#f97316') + '22', color: aiResult.recommendation === 'approve' ? '#22c55e' : aiResult.recommendation === 'reject' ? '#ef4444' : '#f97316', textTransform: 'uppercase' }}>
                          {aiResult.recommendation}
                        </span>
                        <span style={{ fontSize: 11, color: 'var(--text-3)', marginLeft: 'auto' }}>Confidence: <strong>{aiResult.confidence}%</strong></span>
                      </div>
                      <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.5, marginBottom: 8 }}>{aiResult.risk_summary}</div>
                      {aiResult.business_impact && <div style={{ fontSize: 12, color: 'var(--text-3)' }}><strong>Business Impact:</strong> {aiResult.business_impact}</div>}
                    </div>
                    {aiResult.reasons?.length > 0 && (
                      <div className="g-card" style={{ padding: 14 }}>
                        <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8 }}>Reasoning</div>
                        {aiResult.reasons.map((r: string, i: number) => (
                          <div key={i} style={{ display: 'flex', gap: 8, fontSize: 12, color: 'var(--text-2)', marginBottom: 5 }}>
                            <span style={{ color: 'var(--accent)' }}>•</span>
                            <span>{r}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    {aiResult.mitre_context && (
                      <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #ef4444' }}>
                        <div style={{ fontSize: 11, fontWeight: 700, color: '#ef4444', marginBottom: 4, textTransform: 'uppercase' }}>MITRE Context</div>
                        <div style={{ fontSize: 12, color: 'var(--text-2)' }}>{aiResult.mitre_context}</div>
                      </div>
                    )}
                    {aiResult.suggested_conditions?.length > 0 && (
                      <div className="g-card" style={{ padding: 14 }}>
                        <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8 }}>Suggested Conditions</div>
                        {aiResult.suggested_conditions.map((cond: string, i: number) => (
                          <div key={i} style={{ display: 'flex', gap: 8, fontSize: 12, color: 'var(--text-2)', marginBottom: 5 }}>
                            <Square style={{ width: 12, height: 12, color: '#eab308', flexShrink: 0, marginTop: 1 }} />
                            <span>{cond}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    <div style={{ fontSize: 11, color: 'var(--text-3)', fontStyle: 'italic' }}>
                      AI recommendations are advisory only. The approver is responsible for the final decision.
                    </div>
                  </>
                )}
              </div>
            )}

            {detailTab === 'comments' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {comments.map((cm: any) => (
                  <div key={cm.id} style={{ display: 'flex', gap: 10 }}>
                    <div style={{ width: 28, height: 28, borderRadius: '50%', background: 'var(--accent)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11, fontWeight: 700, color: '#fff', flexShrink: 0 }}>
                      {cm.author.charAt(0).toUpperCase()}
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                        <strong style={{ fontSize: 12 }}>{cm.author}</strong>
                        <span style={{ fontSize: 10, padding: '1px 6px', borderRadius: 10, background: cm.comment_type === 'evidence' ? '#3b82f622' : cm.comment_type === 'justification' ? '#22c55e22' : 'var(--border)', color: cm.comment_type === 'evidence' ? '#3b82f6' : cm.comment_type === 'justification' ? '#22c55e' : 'var(--text-3)' }}>
                          {cm.comment_type}
                        </span>
                        <span style={{ fontSize: 10, color: 'var(--text-3)', marginLeft: 'auto' }}>{timeAgo(cm.created_at)}</span>
                      </div>
                      <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.4 }}>{cm.content}</div>
                    </div>
                  </div>
                ))}
                <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div style={{ display: 'flex', gap: 6 }}>
                    {(['note', 'evidence', 'justification'] as const).map(t => (
                      <ActionButton key={t} variant={commentType === t ? 'primary' : 'ghost'} onClick={() => setCommentType(t)} style={{ fontSize: 10, padding: '3px 8px', textTransform: 'capitalize' }}>{t}</ActionButton>
                    ))}
                  </div>
                  <textarea className="g-input" rows={3} placeholder="Add a note, evidence link, or justification…" value={newComment} onChange={e => setNewComment(e.target.value)} style={{ resize: 'vertical', fontSize: 12 }} />
                  <ActionButton variant="primary" onClick={() => { onAddComment(newComment, commentType); setNewComment(''); }} style={{ alignSelf: 'flex-end', fontSize: 12 }}>
                    Add Comment
                  </ActionButton>
                </div>
              </div>
            )}
          </div>

          {/* Decision footer */}
          {requestDetail.status === 'pending' && (
            <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)', background: 'var(--bg)', display: 'flex', flexDirection: 'column', gap: 8 }}>
              {pendingDecision ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div style={{ fontSize: 12, fontWeight: 600, textTransform: 'capitalize', color: pendingDecision === 'approve' ? '#22c55e' : pendingDecision === 'reject' ? '#ef4444' : '#f97316' }}>
                    {pendingDecision.replace('_', ' ')} — notes (optional)
                  </div>
                  <textarea className="g-input" rows={2} placeholder="Decision notes / justification…" value={decisionNotes} onChange={e => setDecisionNotes(e.target.value)} style={{ fontSize: 12, resize: 'none' }} />
                  <div style={{ display: 'flex', gap: 8 }}>
                    <ActionButton variant="primary" onClick={() => { onDecide(pendingDecision); setPendingDecision(null); setDecisionNotes(''); }} style={{ fontSize: 12 }}>Confirm</ActionButton>
                    <ActionButton variant="ghost" onClick={() => { setPendingDecision(null); setDecisionNotes(''); }} style={{ fontSize: 12 }}>Cancel</ActionButton>
                  </div>
                </div>
              ) : showDelegateForm ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div style={{ fontSize: 12, fontWeight: 600 }}>Delegate to another approver</div>
                  <select className="g-select" value={delegateeInput} onChange={e => setDelegateeInput(e.target.value)} style={{ fontSize: 12 }}>
                    <option value="">Select approver…</option>
                    {approvers.map((a: any) => <option key={a.id} value={a.id}>{a.name} — {a.role}</option>)}
                  </select>
                  <input className="g-input" placeholder="Reason for delegation…" value={delegateNotes} onChange={e => setDelegateNotes(e.target.value)} style={{ fontSize: 12 }} />
                  <div style={{ display: 'flex', gap: 8 }}>
                    <ActionButton variant="primary" onClick={() => { onDelegate(delegateeInput, delegateNotes); setShowDelegateForm(false); setDelegateeInput(''); setDelegateNotes(''); }} style={{ fontSize: 12 }}>Delegate</ActionButton>
                    <ActionButton variant="ghost" onClick={() => setShowDelegateForm(false)} style={{ fontSize: 12 }}>Cancel</ActionButton>
                  </div>
                </div>
              ) : showEmergencyForm ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, fontWeight: 700, color: '#ef4444' }}>
                    <AlertTriangle style={{ width: 13, height: 13 }} /> BREAK GLASS — Emergency Override
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-3)' }}>Bypasses standard approval. Fully audited. Executive notification sent.</div>
                  <textarea className="g-input" rows={2} placeholder="Justification (required)…" value={emergencyText} onChange={e => setEmergencyText(e.target.value)} style={{ fontSize: 12, resize: 'none' }} />
                  <div style={{ display: 'flex', gap: 8 }}>
                    <ActionButton variant="primary" onClick={() => { onEmergency(emergencyText); setShowEmergencyForm(false); setEmergencyText(''); }} style={{ fontSize: 12, background: '#ef4444', color: '#fff' }}>Execute Emergency Override</ActionButton>
                    <ActionButton variant="ghost" onClick={() => setShowEmergencyForm(false)} style={{ fontSize: 12 }}>Cancel</ActionButton>
                  </div>
                </div>
              ) : (
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  <ActionButton variant="primary" icon={Check} onClick={() => setPendingDecision('approve')} style={{ fontSize: 12, background: '#22c55e', color: '#fff', fontWeight: 600 }}>Approve</ActionButton>
                  <ActionButton variant="primary" icon={X} onClick={() => setPendingDecision('reject')} style={{ fontSize: 12, background: '#ef4444', color: '#fff', fontWeight: 600 }}>Reject</ActionButton>
                  <ActionButton variant="ghost" icon={HelpCircle} onClick={() => setPendingDecision('more_info')} style={{ fontSize: 12 }}>Request Info</ActionButton>
                  <ActionButton variant="ghost" icon={CornerUpRight} onClick={() => setShowDelegateForm(true)} style={{ fontSize: 12 }}>Delegate</ActionButton>
                  <ActionButton variant="ghost" icon={ArrowUp} onClick={() => setPendingDecision('escalate')} style={{ fontSize: 12 }}>Escalate</ActionButton>
                  <ActionButton variant="ghost" icon={Pause} onClick={() => setPendingDecision('postpone')} style={{ fontSize: 12 }}>Postpone</ActionButton>
                  <ActionButton variant="primary" icon={Flame} onClick={() => setShowEmergencyForm(true)} style={{ fontSize: 12, background: '#7f1d1d', color: '#fca5a5', marginLeft: 'auto' }}>Break Glass</ActionButton>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Policies Tab ─────────────────────────────────────────────────────────────
function PoliciesTab({ policies, matrix }: { policies: any[]; matrix: any[] }) {
  const [activeSection, setActiveSection] = useState<'policies' | 'matrix'>('policies');
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 8 }}>
        <ActionButton variant={activeSection === 'policies' ? 'primary' : 'ghost'} onClick={() => setActiveSection('policies')} style={{ fontSize: 12 }}>Approval Policies</ActionButton>
        <ActionButton variant={activeSection === 'matrix' ? 'primary' : 'ghost'} onClick={() => setActiveSection('matrix')} style={{ fontSize: 12 }}>Approval Matrix</ActionButton>
      </div>

      {activeSection === 'policies' && (
        <SectionCard title="Approval Policies" actions={<ActionButton variant="primary" style={{ fontSize: 12 }}>+ Add Policy</ActionButton>} padded={false}>
          <DataTable<any>
            rows={policies}
            rowKey={(p: any) => p.id}
            columns={[
              { key: 'name', header: 'Name', render: (p: any) => <span style={{ fontSize: 13, fontWeight: 600 }}>{p.name}</span> },
              { key: 'action_type', header: 'Action Type', render: (p: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{p.action_type.replace(/_/g, ' ')}</span> },
              { key: 'asset_criticality', header: 'Asset Criticality', render: (p: any) => <span style={{ fontSize: 12, color: 'var(--text-2)', textTransform: 'capitalize' }}>{p.asset_criticality}</span> },
              { key: 'policy', header: 'Policy', render: (p: any) => (
                <span style={{ fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 10, background: (POLICY_COLOR[p.policy] || '#6b7280') + '22', color: POLICY_COLOR[p.policy] || '#6b7280', border: `1px solid ${(POLICY_COLOR[p.policy] || '#6b7280')}44` }}>
                  {POLICY_LABEL[p.policy] || p.policy}
                </span>
              ) },
              { key: 'auto_conditions', header: 'Auto-Approve Conditions', render: (p: any) => <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-3)' }}>{p.auto_conditions || '—'}</span> },
              { key: 'approvers', header: 'Approvers', render: (p: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{p.approvers}</span> },
              { key: 'enabled', header: 'Status', render: (p: any) => (
                <span style={{ fontSize: 11, padding: '2px 7px', borderRadius: 10, background: p.enabled ? '#22c55e22' : '#ef444422', color: p.enabled ? '#22c55e' : '#ef4444' }}>
                  {p.enabled ? 'Active' : 'Disabled'}
                </span>
              ) },
            ]}
          />
        </SectionCard>
      )}

      {activeSection === 'matrix' && (
        <SectionCard title="Approval Matrix" subtitle="Approval requirement per action type and asset criticality" padded={false}>
          <DataTable<any>
            rows={matrix}
            rowKey={(row: any, i: number) => row.action ?? i}
            columns={[
              { key: 'action', header: 'Action', render: (row: any) => <span style={{ fontSize: 12, fontWeight: 500 }}>{row.action}</span> },
              { key: 'category', header: 'Category', render: (row: any) => <span style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'capitalize' }}>{row.category.replace(/_/g, ' ')}</span> },
              { key: 'asset_criticality', header: 'Asset Criticality', render: (row: any) => <span style={{ fontSize: 11, textTransform: 'capitalize', color: row.asset_criticality === 'critical' ? '#ef4444' : row.asset_criticality === 'high' ? '#f97316' : row.asset_criticality === 'medium' ? '#eab308' : 'var(--text-2)' }}>{row.asset_criticality}</span> },
              { key: 'requirement', header: 'Approval Requirement', render: (row: any) => (
                <span style={{ fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 10, background: (POLICY_COLOR[row.requirement] || '#6b7280') + '22', color: POLICY_COLOR[row.requirement] || '#6b7280', border: `1px solid ${(POLICY_COLOR[row.requirement] || '#6b7280')}44`, whiteSpace: 'nowrap' }}>
                  {POLICY_LABEL[row.requirement] || row.requirement}
                </span>
              ) },
              { key: 'approvers', header: 'Approvers', render: (row: any) => <span style={{ fontSize: 11, color: 'var(--text-2)' }}>{row.approvers}</span> },
              { key: 'risk', header: 'Risk', render: (row: any) => <SevBadge sev={row.risk} /> },
            ]}
          />
        </SectionCard>
      )}
    </div>
  );
}

// ─── Analytics Tab ────────────────────────────────────────────────────────────
function AnalyticsTab({ analytics }: { analytics: any }) {
  if (!analytics) return <div style={{ color: 'var(--text-3)', padding: 40, textAlign: 'center' }}>Loading analytics…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <MetricCard label="Avg Approval Time" value={`${analytics.avg_approval_time_min?.toFixed(1)}m`} color="var(--accent)" />
        <MetricCard label="Total Requests" value={analytics.total} />
        <MetricCard label="Approved" value={analytics.approved} color="#22c55e" />
        <MetricCard label="Rejected" value={analytics.rejected} color="#ef4444" />
        <MetricCard label="SLA Violations" value={analytics.sla_violations} color="#f97316" />
        <MetricCard label="Emergency" value={analytics.emergency_requests} color="#ef4444" />
        <MetricCard label="Auto-Approved" value={analytics.auto_approved} color="#22c55e" sub="no human action" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <SectionCard title="By Category">
          {analytics.by_category?.map((cat: any) => (
            <div key={cat.category} style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
                <span style={{ textTransform: 'capitalize', fontWeight: 500 }}>{cat.category}</span>
                <div style={{ display: 'flex', gap: 8 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 2, color: '#22c55e', fontSize: 11 }}><Check style={{ width: 10, height: 10 }} /> {cat.approved}</span>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 2, color: '#ef4444', fontSize: 11 }}><X style={{ width: 10, height: 10 }} /> {cat.rejected}</span>
                  <span style={{ color: 'var(--text-3)', fontSize: 11 }}>auto {cat.auto}</span>
                </div>
              </div>
              <div style={{ background: 'var(--border)', borderRadius: 2, height: 8, overflow: 'hidden', display: 'flex' }}>
                <div style={{ background: '#22c55e', height: 8, width: `${(cat.approved / (cat.count || 1)) * 100}%` }} />
                <div style={{ background: '#ef4444', height: 8, width: `${(cat.rejected / (cat.count || 1)) * 100}%` }} />
              </div>
            </div>
          ))}
        </SectionCard>

        <SectionCard title="By Approver" padded={false}>
          <DataTable<any>
            rows={analytics.by_approver || []}
            rowKey={(t: any) => t.approver}
            columns={[
              { key: 'approver', header: 'Approver', render: (t: any) => <span style={{ fontSize: 12, fontFamily: 'monospace' }}>{t.approver}</span> },
              { key: 'approved', header: 'Approved', render: (t: any) => <span style={{ fontSize: 12, color: '#22c55e', fontWeight: 600 }}>{t.approved}</span> },
              { key: 'avg_time_min', header: 'Avg Time', render: (t: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{t.avg_time_min.toFixed(1)}m</span> },
            ]}
          />
        </SectionCard>
      </div>

      <SectionCard title="Daily Request Trend">
        <div style={{ display: 'flex', gap: 4, alignItems: 'flex-end', height: 100 }}>
          {analytics.trend?.map((d: any) => {
            const max = Math.max(...analytics.trend.map((x: any) => x.requests), 1);
            const h = (d.requests / max) * 80;
            const ah = (d.approved / max) * 80;
            return (
              <div key={d.date} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                <div style={{ position: 'relative', width: '100%', height: 80 }}>
                  <div style={{ background: 'var(--border)', borderRadius: '2px 2px 0 0', height: h, position: 'absolute', bottom: 0, left: 0, right: 0 }} />
                  <div style={{ background: 'var(--accent)', borderRadius: '2px 2px 0 0', height: ah, position: 'absolute', bottom: 0, left: 0, right: 0, opacity: 0.8 }} />
                </div>
                <div style={{ fontSize: 9, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{d.date}</div>
              </div>
            );
          })}
        </div>
        <div style={{ display: 'flex', gap: 12, marginTop: 8, fontSize: 11, color: 'var(--text-3)' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}><span style={{ width: 10, height: 10, background: 'var(--border)', borderRadius: 2, display: 'inline-block' }} /> Total</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}><span style={{ width: 10, height: 10, background: 'var(--accent)', borderRadius: 2, display: 'inline-block', opacity: 0.8 }} /> Approved</span>
        </div>
      </SectionCard>
    </div>
  );
}

// ─── Audit Tab ────────────────────────────────────────────────────────────────
function AuditTab({ audit }: { audit: any[] }) {
  return (
    <SectionCard title="Immutable Audit Trail" subtitle="All approval lifecycle events. Cryptographically signed and tamper-evident." padded={false}>
      <DataTable<any>
        rows={audit}
        rowKey={(e: any) => e.id}
        columns={[
          { key: 'created_at', header: 'Time', render: (e: any) => <span style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{new Date(e.created_at).toLocaleString()}</span> },
          { key: 'approval_id', header: 'Approval ID', render: (e: any) => <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--accent)' }}>{e.approval_id || '—'}</span> },
          { key: 'actor', header: 'Actor', render: (e: any) => <span style={{ fontSize: 12, fontWeight: 500 }}>{e.actor}</span> },
          { key: 'action', header: 'Action', render: (e: any) => (
            <span style={{ fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 10, background: e.action === 'approved' ? '#22c55e22' : e.action === 'rejected' ? '#ef444422' : e.action === 'emergency_override' ? '#ef444422' : e.action === 'created' ? '#3b82f622' : 'var(--border)', color: e.action === 'approved' ? '#22c55e' : e.action === 'rejected' || e.action === 'emergency_override' ? '#ef4444' : e.action === 'created' ? '#3b82f6' : 'var(--text-2)', textTransform: 'capitalize' }}>
              {e.action.replace(/_/g, ' ')}
            </span>
          ) },
          { key: 'details', header: 'Details', render: (e: any) => <span style={{ fontSize: 12, color: 'var(--text-2)', maxWidth: 320, display: 'block' }}>{e.details}</span> },
          { key: 'ip_address', header: 'IP', render: (e: any) => <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-3)' }}>{e.ip_address || '—'}</span> },
        ]}
      />
    </SectionCard>
  );
}

// ─── Reports Tab ──────────────────────────────────────────────────────────────
function ReportsTab() {
  const [reportType, setReportType] = useState('approval_history');
  const [period, setPeriod] = useState('30d');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  const generate = async () => {
    setLoading(true);
    const res = await aqAPI.generateReport({ report_type: reportType, period });
    setResult(res.data);
    setLoading(false);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 800 }}>
      <SectionCard title="Generate Report">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: 12, alignItems: 'end' }}>
          <div>
            <label style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: 4 }}>Report Type</label>
            <select className="g-select" value={reportType} onChange={e => setReportType(e.target.value)} style={{ width: '100%' }}>
              <option value="approval_history">Approval History</option>
              <option value="executive">Executive Summary</option>
              <option value="sla_compliance">SLA Compliance</option>
              <option value="audit">Audit Report</option>
              <option value="compliance">Compliance Report</option>
            </select>
          </div>
          <div>
            <label style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: 4 }}>Period</label>
            <select className="g-select" value={period} onChange={e => setPeriod(e.target.value)} style={{ width: '100%' }}>
              <option value="7d">Last 7 days</option>
              <option value="30d">Last 30 days</option>
              <option value="90d">Last 90 days</option>
              <option value="ytd">Year to Date</option>
            </select>
          </div>
          <ActionButton variant="primary" onClick={generate} disabled={loading}>
            {loading ? 'Generating…' : 'Generate'}
          </ActionButton>
        </div>
      </SectionCard>

      {result && (
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: 15 }}>{result.title}</div>
              <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 2 }}>
                Generated {new Date(result.generated_at).toLocaleString()} · {result.classification}
              </div>
            </div>
            <ActionButton variant="ghost" icon={Download} style={{ fontSize: 12 }}>Export PDF</ActionButton>
          </div>
          <div className="g-card" style={{ padding: 12, marginBottom: 16, borderLeft: '3px solid var(--accent)' }}>
            <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 6 }}>Executive Summary</div>
            <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.5 }}>{result.summary}</div>
          </div>
          {result.statistics && (
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 16 }}>
              {Object.entries(result.statistics).map(([k, v]) => (
                <MetricCard key={k} label={k.replace(/_/g, ' ')} value={String(v)} />
              ))}
            </div>
          )}
          {result.top_requestors && result.top_requestors.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8 }}>Top Requestors</div>
              {result.top_requestors.map((r: any) => (
                <div key={r.requestor} style={{ display: 'flex', gap: 8, fontSize: 12, color: 'var(--text-2)', marginBottom: 4 }}>
                  <span style={{ flex: 1, fontFamily: 'monospace' }}>{r.requestor}</span>
                  <span>{r.count} requests</span>
                  <span style={{ color: 'var(--text-3)' }}>({r.auto_approved} auto)</span>
                </div>
              ))}
            </div>
          )}
          {result.risk_breakdown && result.risk_breakdown.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8 }}>Risk Breakdown</div>
              {result.risk_breakdown.map((r: any) => (
                <div key={r.level} style={{ display: 'flex', gap: 8, fontSize: 12, color: 'var(--text-2)', marginBottom: 4 }}>
                  <span style={{ flex: 1, textTransform: 'capitalize' }}>{r.level}</span>
                  <span>{r.count} requests</span>
                  <span style={{ color: r.all_approved ? '#22c55e' : '#eab308' }}>{r.all_approved ? 'all approved' : 'mixed outcome'}</span>
                </div>
              ))}
            </div>
          )}
          {result.recommendations && (
            <div>
              <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8 }}>Recommendations</div>
              {result.recommendations.length === 0 ? (
                <div style={{ fontSize: 12, color: 'var(--text-3)' }}>Not enough data yet to make recommendations.</div>
              ) : result.recommendations.map((r: string, i: number) => (
                <div key={i} style={{ display: 'flex', gap: 8, fontSize: 12, color: 'var(--text-2)', marginBottom: 6 }}>
                  <span style={{ color: 'var(--accent)', fontWeight: 700 }}>{i + 1}.</span>
                  <span>{r}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────
export default function SoarApprovalsPage() {
  const [tab, setTab] = useState<Tab>('overview');
  const loaded = useRef<Record<string, boolean>>({});

  const [dash, setDash] = useState<any>(null);
  const [requests, setRequests] = useState<any[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [requestDetail, setRequestDetail] = useState<any>(null);
  const [comments, setComments] = useState<any[]>([]);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [evidence, setEvidence] = useState<any>(null);
  const [aiResult, setAiResult] = useState<any>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [policies, setPolicies] = useState<any[]>([]);
  const [matrix, setMatrix] = useState<any[]>([]);
  const [analytics, setAnalytics] = useState<any>(null);
  const [audit, setAudit] = useState<any[]>([]);
  const [approvers, setApprovers] = useState<any[]>([]);
  const [queueFilter, setQueueFilter] = useState('pending');
  const [searchQ, setSearchQ] = useState('');
  const [detailTab, setDetailTab] = useState('overview');

  const loadRequests = async () => {
    const res = await aqAPI.getQueue();
    setRequests(res.data || []);
  };

  useEffect(() => {
    loaded.current['overview'] = true;
    aqAPI.getDashboard().then(r => setDash(r.data));
    loadRequests();
    aqAPI.getApprovers().then(r => setApprovers(r.data || []));
  }, []);

  const selectRequest = async (id: number) => {
    setSelectedId(id);
    setDetailTab('overview');
    setAiResult(null);
    const [det, cmts, tl, ev] = await Promise.all([
      aqAPI.getRequest(id),
      aqAPI.getComments(id),
      aqAPI.getTimeline(id),
      aqAPI.getEvidence(id),
    ]);
    setRequestDetail(det.data);
    setComments(cmts.data || []);
    setTimeline(tl.data || []);
    setEvidence(ev.data);
    const r = det.data;
    if (r) {
      setAiLoading(true);
      aqAPI.askAI({ mode: 'risk_summary', action: r.requested_action, asset: r.target_asset, context: r.description }).then(aiRes => {
        setAiResult(aiRes.data);
        setAiLoading(false);
      }).catch(() => setAiLoading(false));
    }
  };

  const onDecide = async (type: string) => {
    if (!selectedId) return;
    try {
      await aqAPI.decide(selectedId, { decision: type });
      setRequestDetail((r: any) => r ? { ...r, status: type === 'approve' ? 'approved' : type === 'reject' ? 'rejected' : type } : r);
      loadRequests();
    } catch (err: any) {
      alert(err?.response?.data?.error || 'Failed to record decision');
    }
  };

  const onDelegate = async (delegatee: string, notes: string) => {
    if (!selectedId) return;
    try {
      await aqAPI.delegate(selectedId, { delegatee, notes });
      setRequestDetail((r: any) => r ? { ...r, status: 'delegated', current_approver: delegatee } : r);
      loadRequests();
    } catch (err: any) {
      alert(err?.response?.data?.error || 'Failed to delegate');
    }
  };

  const onEmergency = async (justification: string) => {
    if (!selectedId) return;
    try {
      await aqAPI.emergency(selectedId, { justification });
      setRequestDetail((r: any) => r ? { ...r, status: 'approved', is_emergency: true } : r);
      loadRequests();
    } catch (err: any) {
      alert(err?.response?.data?.error || 'Failed to submit emergency override');
    }
  };

  const onAddComment = async (content: string, type: string) => {
    if (!selectedId || !content.trim()) return;
    try {
      await aqAPI.addComment(selectedId, { content, comment_type: type });
      const res = await aqAPI.getComments(selectedId);
      setComments(res.data || []);
    } catch (err: any) {
      alert(err?.response?.data?.error || 'Failed to add comment');
    }
  };

  const switchTab = (t: Tab) => {
    setTab(t);
    if (!loaded.current[t]) loaded.current[t] = true;
    if (t === 'queue') { /* requests already loaded */ }
    if (t === 'policies' && policies.length === 0) {
      aqAPI.getPolicies().then(r => setPolicies(r.data || []));
      aqAPI.getMatrix().then(r => setMatrix(r.data || []));
    }
    if (t === 'analytics' && !analytics) {
      aqAPI.getAnalytics().then(r => setAnalytics(r.data));
    }
    if (t === 'audit' && audit.length === 0) {
      aqAPI.getAudit().then(r => setAudit(r.data || []));
    }
  };

  return (
    <RootLayout title="Approval Queue"
      subtitle="Human-in-the-loop approval for high-risk SOAR actions · AI-assisted risk assessment · Immutable audit trail"
      actions={dash?.pending > 0 ? (
        <div style={{ padding: '6px 14px', borderRadius: 6, background: '#f9731622', color: '#f97316', fontSize: 12, fontWeight: 700, border: '1px solid #f9731644' }}>
          {dash.pending} pending approval{dash.pending !== 1 ? 's' : ''}
        </div>
      ) : undefined}>
      <div style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 20, height: '100%' }}>
        <TabBar
          tabs={(Object.keys(TAB_LABELS) as Tab[]).map(t => ({
            key: t,
            label: TAB_LABELS[t],
            icon: TAB_ICONS[t],
            count: t === 'queue' ? (dash?.pending > 0 ? dash.pending : undefined) : undefined,
          }))}
          active={tab}
          onChange={t => switchTab(t as Tab)}
        />

        <div style={{ display: tab === 'overview' ? 'block' : 'none' }}>
          <OverviewTab dash={dash} />
        </div>
        <div style={{ display: tab === 'queue' ? 'block' : 'none' }}>
          {loaded.current['queue'] && (
            <QueueTab
              requests={requests} selectedId={selectedId} onSelect={selectRequest} onRefresh={loadRequests}
              requestDetail={requestDetail} evidence={evidence} timeline={timeline} comments={comments}
              aiResult={aiResult} aiLoading={aiLoading} approvers={approvers}
              detailTab={detailTab} setDetailTab={setDetailTab}
              onDecide={onDecide} onDelegate={onDelegate} onEmergency={onEmergency} onAddComment={onAddComment}
              queueFilter={queueFilter} setQueueFilter={setQueueFilter} searchQ={searchQ} setSearchQ={setSearchQ}
            />
          )}
        </div>
        <div style={{ display: tab === 'policies' ? 'block' : 'none' }}>
          {loaded.current['policies'] && <PoliciesTab policies={policies} matrix={matrix} />}
        </div>
        <div style={{ display: tab === 'analytics' ? 'block' : 'none' }}>
          {loaded.current['analytics'] && <AnalyticsTab analytics={analytics} />}
        </div>
        <div style={{ display: tab === 'audit' ? 'block' : 'none' }}>
          {loaded.current['audit'] && <AuditTab audit={audit} />}
        </div>
        <div style={{ display: tab === 'reports' ? 'block' : 'none' }}>
          {loaded.current['reports'] && <ReportsTab />}
        </div>
      </div>
    </RootLayout>
  );
}
