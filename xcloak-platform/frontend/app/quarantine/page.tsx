'use client';

import React, { useState, useEffect, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { qeAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';

type Tab = 'dashboard' | 'queue' | 'ai' | 'approvals' | 'analytics' | 'audit' | 'reports';
const TAB_LABELS: Record<Tab, string> = {
  dashboard: 'Dashboard', queue: 'Queue', ai: 'AI Analysis',
  approvals: 'Approvals', analytics: 'Analytics', audit: 'Audit Trail', reports: 'Reports',
};

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
};
const STATUS_COLOR: Record<string, string> = {
  active: '#ef4444', released: '#22c55e', escalated: '#a855f7', pending: '#3b82f6',
};
const ASSET_ICON: Record<string, string> = {
  endpoint: '💻', file: '📄', process: '⚙️', user: '👤', email: '✉️', network: '🌐',
};
const QTYPE_LABEL: Record<string, string> = {
  full_network_isolation: 'Full Network Isolation',
  internet_only: 'Internet-Only Access',
  management_network_only: 'Mgmt Network Only',
  custom_network_policy: 'Custom Network Policy',
  move_to_secure_storage: 'Move to Secure Storage',
  encrypt_file: 'Encrypt File',
  suspend_process: 'Suspend Process',
  kill_process: 'Kill Process',
  disable_account: 'Disable Account',
  force_password_reset: 'Force Password Reset',
  move_to_quarantine_mailbox: 'Move to Quarantine Mailbox',
  block_ip: 'Block IP',
  block_domain: 'Block Domain',
};
const APPROVAL_COLOR: Record<string, string> = {
  not_required: '#22c55e', pending: '#f97316', approved: '#22c55e', rejected: '#ef4444',
};

function StatCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="g-card" style={{ padding: '14px 18px', minWidth: 120 }}>
      <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 700, color: color || 'var(--text-1)', lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 3 }}>{sub}</div>}
    </div>
  );
}

function SevPill({ s }: { s: string }) {
  const c = SEV_COLOR[s] || '#6b7280';
  return <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 3, background: c + '22', color: c, border: `1px solid ${c}44`, textTransform: 'uppercase' }}>{s}</span>;
}

function StatusPill({ s }: { s: string }) {
  const c = STATUS_COLOR[s] || '#6b7280';
  return <span style={{ fontSize: 10, fontWeight: 600, padding: '2px 8px', borderRadius: 10, background: c + '22', color: c, border: `1px solid ${c}44`, textTransform: 'capitalize' }}>{s}</span>;
}

// ─── Dashboard ────────────────────────────────────────────────────────────
function DashboardTab({ dash }: { dash: any }) {
  if (!dash) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Endpoints" value={dash.quarantined_endpoints} color="#ef4444" sub="quarantined" />
        <StatCard label="Files" value={dash.quarantined_files} color="#f97316" sub="quarantined" />
        <StatCard label="Processes" value={dash.quarantined_processes} color="#a855f7" sub="quarantined" />
        <StatCard label="Users" value={dash.quarantined_users} color="#eab308" sub="quarantined" />
        <StatCard label="Emails" value={dash.quarantined_emails} color="#3b82f6" sub="quarantined" />
        <StatCard label="Network" value={dash.quarantined_network_connections} color="#06b6d4" sub="quarantined" />
        <StatCard label="Active Sessions" value={dash.active_quarantine_sessions} color="#ef4444" />
        <StatCard label="Released" value={dash.released_assets} color="#22c55e" sub="total" />
      </div>

      {dash.pending_approvals > 0 && (
        <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #f97316', background: '#f9731608' }}>
          <span style={{ fontWeight: 700, color: '#f97316' }}>⚠ {dash.pending_approvals} quarantine action{dash.pending_approvals !== 1 ? 's' : ''} pending approval.</span>
          <span style={{ fontSize: 13, color: 'var(--text-2)', marginLeft: 8 }}>Review in the Approvals tab.</span>
        </div>
      )}
      {dash.expiring_soon > 0 && (
        <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #eab308', background: '#eab30808' }}>
          <span style={{ fontWeight: 700, color: '#eab308' }}>⏰ {dash.expiring_soon} quarantine{dash.expiring_soon !== 1 ? 's' : ''} expiring within 24 hours.</span>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Quarantined by Asset Type</div>
          {[
            ['💻 Endpoint', dash.quarantined_endpoints, '#ef4444'],
            ['📄 File', dash.quarantined_files, '#f97316'],
            ['⚙️ Process', dash.quarantined_processes, '#a855f7'],
            ['👤 User', dash.quarantined_users, '#eab308'],
            ['✉️ Email', dash.quarantined_emails, '#3b82f6'],
            ['🌐 Network', dash.quarantined_network_connections, '#06b6d4'],
          ].map(([label, val, color]) => {
            const total = dash.active_quarantine_sessions || 1;
            return (
              <div key={label as string} style={{ marginBottom: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 3 }}>
                  <span style={{ color: 'var(--text-2)' }}>{label}</span>
                  <span style={{ fontWeight: 700, color: color as string }}>{val}</span>
                </div>
                <div style={{ background: 'var(--border)', borderRadius: 2, height: 5 }}>
                  <div style={{ background: color as string, borderRadius: 2, height: 5, width: `${Math.round((Number(val) / total) * 100)}%` }} />
                </div>
              </div>
            );
          })}
        </div>

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Quarantine Status</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {[
              ['Active Quarantines', dash.active_quarantine_sessions, '#ef4444'],
              ['Released Assets', dash.released_assets, '#22c55e'],
              ['Pending Approval', dash.pending_approvals, '#f97316'],
              ['Expiring Soon', dash.expiring_soon, '#eab308'],
            ].map(([label, val, color]) => (
              <div key={label as string} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', borderRadius: 8, background: 'var(--bg)', border: '1px solid var(--border)' }}>
                <span style={{ fontSize: 13, color: 'var(--text-2)' }}>{label}</span>
                <span style={{ fontSize: 20, fontWeight: 700, color: color as string }}>{val}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Queue Tab ────────────────────────────────────────────────────────────
function QueueTab({ items, onRefresh }: { items: any[]; onRefresh: () => void }) {
  const [search, setSearch] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [filterType, setFilterType] = useState('');
  const [selected, setSelected] = useState<any>(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [notes, setNotes] = useState('');
  const [activeDetail, setActiveDetail] = useState<'detail' | 'evidence' | 'timeline'>('detail');
  const [evidence, setEvidence] = useState<any[]>([]);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [collectingEvidence, setCollectingEvidence] = useState(false);

  const filtered = useMemo(() => items.filter(r => {
    if (filterStatus && r.status !== filterStatus) return false;
    if (filterType && r.asset_type !== filterType) return false;
    if (search) {
      const q = search.toLowerCase();
      return r.asset_name.toLowerCase().includes(q) || r.quarantine_id.toLowerCase().includes(q) || (r.source_detection || '').toLowerCase().includes(q);
    }
    return true;
  }), [items, filterStatus, filterType, search]);

  const pendingApprovals = items.filter(i => i.approval_status === 'pending');

  const loadEvidence = async (id: number) => {
    setEvidenceLoading(true);
    const r = await qeAPI.getEvidence(id);
    setEvidence(r.data || []);
    setEvidenceLoading(false);
  };

  const selectItem = (item: any) => {
    setSelected(item);
    setActiveDetail('detail');
    setEvidence([]);
  };

  const doAction = async (action: string) => {
    if (!selected) return;
    setActionLoading(true);
    await qeAPI.action(selected.id, { action, notes });
    onRefresh();
    setActionLoading(false);
  };

  const doCollectEvidence = async () => {
    if (!selected) return;
    setCollectingEvidence(true);
    await qeAPI.collectEvidence(selected.id);
    await loadEvidence(selected.id);
    setCollectingEvidence(false);
    setActiveDetail('evidence');
  };

  const approve = async (decision: string) => {
    if (!selected) return;
    setActionLoading(true);
    await qeAPI.approve(selected.id, { decision, notes });
    onRefresh();
    setActionLoading(false);
  };

  let mitreTech: string[] = [];
  let relatedAlerts: string[] = [];
  let evTypes: string[] = [];
  if (selected) {
    try { mitreTech = JSON.parse(selected.mitre_techniques || '[]'); } catch { mitreTech = []; }
    try { relatedAlerts = JSON.parse(selected.related_alerts || '[]'); } catch { relatedAlerts = []; }
    try { evTypes = JSON.parse(selected.evidence_types || '[]'); } catch { evTypes = []; }
  }

  return (
    <div style={{ display: 'flex', gap: 14, height: 'calc(100vh - 220px)', minHeight: 500 }}>
      {/* Left list */}
      <div className="g-card" style={{ width: 360, flexShrink: 0, display: 'flex', flexDirection: 'column', padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)', display: 'flex', flexDirection: 'column', gap: 6 }}>
          <input className="g-input" placeholder="Search asset, ID, detection…" value={search} onChange={e => setSearch(e.target.value)} style={{ fontSize: 12 }} />
          <div style={{ display: 'flex', gap: 4 }}>
            <select className="g-select" value={filterStatus} onChange={e => setFilterStatus(e.target.value)} style={{ fontSize: 11, flex: 1 }}>
              <option value="">All Status</option>
              {['active','released','escalated'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <select className="g-select" value={filterType} onChange={e => setFilterType(e.target.value)} style={{ fontSize: 11, flex: 1 }}>
              <option value="">All Types</option>
              {['endpoint','file','process','user','email','network'].map(t => <option key={t} value={t}>{t}</option>)}
            </select>
            <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={onRefresh}>↻</button>
          </div>
          {pendingApprovals.length > 0 && (
            <div style={{ fontSize: 11, color: '#f97316', background: '#f9731610', padding: '4px 8px', borderRadius: 4, border: '1px solid #f9731630' }}>
              ⚠ {pendingApprovals.length} pending approval{pendingApprovals.length !== 1 ? 's' : ''}
            </div>
          )}
        </div>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {filtered.length === 0 && <div style={{ padding: 20, color: 'var(--text-3)', fontSize: 13, textAlign: 'center' }}>No quarantine items</div>}
          {filtered.map(r => {
            const isSelected = selected?.id === r.id;
            return (
              <div key={r.id} onClick={() => selectItem(r)}
                style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)', cursor: 'pointer', background: isSelected ? 'var(--accent)10' : 'transparent', borderLeft: isSelected ? '3px solid var(--accent)' : '3px solid transparent' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                  <span style={{ fontSize: 14 }}>{ASSET_ICON[r.asset_type] || '🔒'}</span>
                  <span style={{ fontWeight: 600, fontSize: 12, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.asset_name}</span>
                  <SevPill s={r.severity} />
                </div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 4 }}>
                  <StatusPill s={r.status} />
                  {r.approval_status === 'pending' && <span style={{ fontSize: 9, background: '#f9731622', color: '#f97316', padding: '1px 5px', borderRadius: 3, fontWeight: 700 }}>NEEDS APPROVAL</span>}
                  {r.evidence_collected && <span style={{ fontSize: 9, background: '#22c55e22', color: '#22c55e', padding: '1px 5px', borderRadius: 3, fontWeight: 700 }}>EVIDENCE ✓</span>}
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-3)' }}>
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '55%' }}>{r.source_detection}</span>
                  <span>{timeAgo(r.created_at)}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Right detail */}
      {!selected ? (
        <div className="g-card" style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 10 }}>
          <div style={{ fontSize: 40 }}>🔒</div>
          <div style={{ color: 'var(--text-3)', fontSize: 14 }}>Select a quarantine item to inspect</div>
        </div>
      ) : (
        <div className="g-card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: 0 }}>
          {/* Header */}
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 18 }}>{ASSET_ICON[selected.asset_type]}</span>
              <span style={{ fontWeight: 700, fontSize: 15 }}>{selected.asset_name}</span>
              <SevPill s={selected.severity} />
              <StatusPill s={selected.status} />
              {selected.approval_status === 'pending' && <span style={{ fontSize: 10, background: '#f9731622', color: '#f97316', padding: '2px 7px', borderRadius: 3, fontWeight: 700 }}>PENDING APPROVAL</span>}
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 8 }}>
              {selected.quarantine_id} · {QTYPE_LABEL[selected.quarantine_type] || selected.quarantine_type} · {timeAgo(selected.created_at)}
            </div>
            {/* Actions */}
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {selected.status === 'active' && (
                <button className="g-btn g-btn-primary" style={{ fontSize: 11, background: '#22c55e' }} onClick={() => doAction('release')} disabled={actionLoading}>Release</button>
              )}
              {selected.status === 'active' && (
                <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={() => doAction('extend')} disabled={actionLoading}>Extend 24h</button>
              )}
              {!selected.evidence_collected && (
                <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={doCollectEvidence} disabled={collectingEvidence}>
                  {collectingEvidence ? 'Collecting…' : '📥 Collect Evidence'}
                </button>
              )}
              {selected.status === 'active' && (
                <button className="g-btn g-btn-ghost" style={{ fontSize: 11, color: '#a855f7' }} onClick={() => doAction('escalate')} disabled={actionLoading}>Escalate</button>
              )}
              {selected.approval_status === 'pending' && (
                <>
                  <button className="g-btn g-btn-primary" style={{ fontSize: 11 }} onClick={() => approve('approve')} disabled={actionLoading}>✓ Approve</button>
                  <button className="g-btn g-btn-ghost" style={{ fontSize: 11, color: '#ef4444' }} onClick={() => approve('reject')} disabled={actionLoading}>✗ Reject</button>
                </>
              )}
            </div>
          </div>

          {/* Sub-tabs */}
          <div style={{ display: 'flex', borderBottom: '1px solid var(--border)' }}>
            {(['detail', 'evidence', 'timeline'] as const).map(t => (
              <button key={t} onClick={() => { setActiveDetail(t); if (t === 'evidence' && evidence.length === 0) loadEvidence(selected.id); }}
                style={{ padding: '6px 14px', fontSize: 11, fontWeight: activeDetail === t ? 600 : 400, color: activeDetail === t ? 'var(--accent)' : 'var(--text-3)', background: 'transparent', border: 'none', borderBottom: activeDetail === t ? '2px solid var(--accent)' : '2px solid transparent', cursor: 'pointer', textTransform: 'capitalize' }}>
                {t}
              </button>
            ))}
          </div>

          <div style={{ flex: 1, overflowY: 'auto', padding: 14 }}>
            {activeDetail === 'detail' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  <div className="g-card" style={{ padding: 12 }}>
                    <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 8 }}>Quarantine Details</div>
                    {[
                      ['Type', QTYPE_LABEL[selected.quarantine_type] || selected.quarantine_type],
                      ['Asset Type', selected.asset_type],
                      ['Owner', selected.owner || '—'],
                      ['Source', selected.source_detection || '—'],
                      ['Detection Rule', selected.detection_rule || '—'],
                      ['Incident', selected.incident_id || '—'],
                      ['Case', selected.case_id || '—'],
                      ['Risk Score', selected.risk_score],
                      ['Expires', selected.expires_at ? new Date(selected.expires_at).toLocaleDateString() : 'No expiry'],
                    ].map(([k, v]) => (
                      <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
                        <span style={{ color: 'var(--text-3)' }}>{k}</span>
                        <span style={{ fontWeight: 500, textAlign: 'right', maxWidth: '55%', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{String(v)}</span>
                      </div>
                    ))}
                  </div>
                  <div className="g-card" style={{ padding: 12 }}>
                    <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 8 }}>Approval</div>
                    {[
                      ['Status', selected.approval_status?.replace(/_/g, ' ')],
                      ['Approved By', selected.approved_by || '—'],
                    ].map(([k, v]) => (
                      <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
                        <span style={{ color: 'var(--text-3)' }}>{k}</span>
                        <span style={{ fontWeight: 600, color: APPROVAL_COLOR[selected.approval_status] || 'var(--text-1)' }}>{String(v)}</span>
                      </div>
                    ))}
                    {mitreTech.length > 0 && (
                      <div style={{ marginTop: 12 }}>
                        <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 6 }}>MITRE ATT&amp;CK</div>
                        {mitreTech.map((t: string) => (
                          <div key={t} style={{ fontSize: 10, fontFamily: 'monospace', padding: '2px 0', color: '#f97316' }}>{t}</div>
                        ))}
                      </div>
                    )}
                    {relatedAlerts.length > 0 && (
                      <div style={{ marginTop: 12 }}>
                        <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 6 }}>Related Alerts</div>
                        {relatedAlerts.map((a: string) => (
                          <div key={a} style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--accent)', padding: '1px 0' }}>{a}</div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
                {selected.quarantine_reason && (
                  <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #ef4444' }}>
                    <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 6 }}>Quarantine Reason</div>
                    <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.5 }}>{selected.quarantine_reason}</div>
                  </div>
                )}
                {selected.business_impact && (
                  <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #eab308' }}>
                    <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 6 }}>Business Impact</div>
                    <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.5 }}>{selected.business_impact}</div>
                  </div>
                )}
                <div className="g-card" style={{ padding: 12 }}>
                  <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 6 }}>Analyst Notes</div>
                  <textarea className="g-input" rows={3} value={notes || selected.analyst_notes || ''} onChange={e => setNotes(e.target.value)} placeholder="Add analyst notes…" style={{ width: '100%', resize: 'none', fontSize: 12 }} />
                  {notes && <button className="g-btn g-btn-ghost" style={{ fontSize: 11, marginTop: 6 }} onClick={() => doAction('update_notes')}>Save Notes</button>}
                </div>
              </div>
            )}

            {activeDetail === 'evidence' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {evidenceLoading ? (
                  <div style={{ color: 'var(--text-3)', padding: 20, textAlign: 'center' }}>Loading evidence…</div>
                ) : evidence.length === 0 ? (
                  <div style={{ textAlign: 'center', padding: 30 }}>
                    <div style={{ fontSize: 28, marginBottom: 8 }}>📁</div>
                    <div style={{ color: 'var(--text-3)', marginBottom: 12 }}>No evidence collected yet</div>
                    <button className="g-btn g-btn-primary" style={{ fontSize: 12 }} onClick={doCollectEvidence} disabled={collectingEvidence}>
                      {collectingEvidence ? 'Collecting…' : 'Collect Evidence Now'}
                    </button>
                  </div>
                ) : evidence.map(ev => {
                  let parsed: any = {};
                  try { parsed = JSON.parse(ev.data); } catch { parsed = {}; }
                  return (
                    <div key={ev.id} className="g-card" style={{ padding: 12 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                        <span style={{ fontWeight: 600, fontSize: 12, textTransform: 'capitalize' }}>{ev.evidence_type.replace(/_/g, ' ')}</span>
                        <span style={{ fontSize: 10, color: 'var(--text-3)' }}>{timeAgo(ev.collected_at)}</span>
                      </div>
                      <pre style={{ fontSize: 10, color: 'var(--text-2)', background: 'var(--bg)', padding: 8, borderRadius: 4, overflow: 'auto', maxHeight: 120, margin: 0, fontFamily: 'monospace' }}>
                        {JSON.stringify(parsed, null, 2)}
                      </pre>
                    </div>
                  );
                })}
              </div>
            )}

            {activeDetail === 'timeline' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
                {[
                  { label: 'Detection', desc: selected.source_detection, time: selected.created_at, color: '#ef4444' },
                  { label: 'Quarantine Applied', desc: `${QTYPE_LABEL[selected.quarantine_type]} applied to ${selected.asset_name}`, time: selected.created_at, color: '#f97316' },
                  ...(selected.evidence_collected ? [{ label: 'Evidence Collected', desc: evTypes.join(', ') || 'Multiple evidence types', time: selected.created_at, color: '#3b82f6' }] : []),
                  ...(selected.approved_by ? [{ label: 'Approved', desc: `Approved by ${selected.approved_by}`, time: selected.created_at, color: '#22c55e' }] : []),
                  ...(selected.status === 'released' ? [{ label: 'Released', desc: 'Asset released from quarantine', time: selected.created_at, color: '#22c55e' }] : []),
                ].map((ev, i) => (
                  <div key={i} style={{ display: 'flex', gap: 12, paddingBottom: 16 }}>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                      <div style={{ width: 10, height: 10, borderRadius: '50%', background: ev.color, flexShrink: 0, marginTop: 3 }} />
                      {i < 4 && <div style={{ width: 1, flex: 1, background: 'var(--border)', marginTop: 4 }} />}
                    </div>
                    <div style={{ paddingBottom: 4 }}>
                      <div style={{ fontWeight: 600, fontSize: 12, color: ev.color }}>{ev.label}</div>
                      <div style={{ fontSize: 12, color: 'var(--text-2)', marginTop: 2 }}>{ev.desc}</div>
                      <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>{timeAgo(ev.time)}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── AI Analysis Tab ─────────────────────────────────────────────────────
function AITab({ items }: { items: any[] }) {
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const activeItems = items.filter(i => i.status === 'active');
  const selected = activeItems.find(i => i.id === selectedId);

  const analyze = async () => {
    if (!selected) return;
    setLoading(true);
    const r = await qeAPI.askAI({
      asset_name: selected.asset_name,
      asset_type: selected.asset_type,
      quarantine_type: selected.quarantine_type,
      severity: selected.severity,
      source_detection: selected.source_detection,
      mitre_techniques: selected.mitre_techniques,
    });
    if (r.data?.ai_analysis) {
      try { setResult(JSON.parse(r.data.ai_analysis)); } catch { setResult({ threat_summary: r.data.ai_analysis }); }
    }
    setLoading(false);
  };

  return (
    <div style={{ display: 'flex', gap: 16, minHeight: 500 }}>
      <div style={{ width: 300, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div className="g-card" style={{ padding: 14 }}>
          <div style={{ fontWeight: 600, marginBottom: 10 }}>Select Quarantine Item</div>
          <select className="g-select" value={selectedId || ''} onChange={e => setSelectedId(Number(e.target.value))} style={{ width: '100%', marginBottom: 10 }}>
            <option value="">Choose an active item…</option>
            {activeItems.map(i => <option key={i.id} value={i.id}>{ASSET_ICON[i.asset_type]} {i.asset_name} ({i.severity})</option>)}
          </select>
          <button className="g-btn g-btn-primary" style={{ width: '100%', fontSize: 13 }} onClick={analyze} disabled={!selectedId || loading}>
            {loading ? 'Analyzing…' : '🧠 Run AI Analysis'}
          </button>
        </div>
        {selected && (
          <div className="g-card" style={{ padding: 12 }}>
            <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 8 }}>Selected Item</div>
            <div style={{ fontWeight: 600, fontSize: 13 }}>{selected.asset_name}</div>
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 3 }}>{selected.source_detection}</div>
            <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              <SevPill s={selected.severity} />
              <StatusPill s={selected.status} />
            </div>
          </div>
        )}
      </div>

      <div style={{ flex: 1 }}>
        {!result ? (
          <div className="g-card" style={{ flex: 1, padding: 40, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 12, minHeight: 400 }}>
            <div style={{ fontSize: 36 }}>🧠</div>
            <div style={{ fontWeight: 600, fontSize: 14 }}>AI Quarantine Analysis</div>
            <div style={{ fontSize: 13, color: 'var(--text-3)', textAlign: 'center', maxWidth: 400, lineHeight: 1.5 }}>
              Select an active quarantine item and click "Run AI Analysis" to get threat summary, root cause, recommended actions, business impact, and similar historical cases.
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div className="g-card" style={{ padding: 14, borderLeft: '3px solid #ef4444' }}>
              <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 8 }}>Threat Summary</div>
              <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.6 }}>{result.threat_summary}</div>
            </div>
            {result.root_cause && (
              <div className="g-card" style={{ padding: 14, borderLeft: '3px solid #f97316' }}>
                <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 8 }}>Root Cause Analysis</div>
                <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.6 }}>{result.root_cause}</div>
              </div>
            )}
            {result.recommended_actions?.length > 0 && (
              <div className="g-card" style={{ padding: 14 }}>
                <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 10 }}>Recommended Actions</div>
                {result.recommended_actions.map((a: string, i: number) => (
                  <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 8, fontSize: 13 }}>
                    <span style={{ color: 'var(--accent)', fontWeight: 700, flexShrink: 0 }}>{i + 1}.</span>
                    <span style={{ color: 'var(--text-2)', lineHeight: 1.4 }}>{a}</span>
                  </div>
                ))}
              </div>
            )}
            {result.estimated_business_impact && (
              <div className="g-card" style={{ padding: 14, borderLeft: '3px solid #eab308' }}>
                <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 8 }}>Estimated Business Impact</div>
                <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.5 }}>{result.estimated_business_impact}</div>
              </div>
            )}
            {result.similar_historical_cases?.length > 0 && (
              <div className="g-card" style={{ padding: 14 }}>
                <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 8 }}>Similar Historical Cases</div>
                {result.similar_historical_cases.map((c: string, i: number) => (
                  <div key={i} style={{ fontSize: 12, color: 'var(--text-2)', padding: '6px 0', borderTop: i > 0 ? '1px solid var(--border)' : 'none' }}>{c}</div>
                ))}
              </div>
            )}
            {result.release_recommendation && (
              <div className="g-card" style={{ padding: 14, borderLeft: '3px solid #22c55e', background: '#22c55e08' }}>
                <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 8 }}>Release Recommendation</div>
                <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.5 }}>{result.release_recommendation}</div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Approvals Tab ───────────────────────────────────────────────────────
function ApprovalsTab({ items, onRefresh }: { items: any[]; onRefresh: () => void }) {
  const [notes, setNotes] = useState<Record<number, string>>({});
  const [loading, setLoading] = useState<number | null>(null);

  const pending = items.filter(i => i.approval_status === 'pending');

  const decide = async (id: number, decision: string) => {
    setLoading(id);
    await qeAPI.approve(id, { decision, notes: notes[id] || '' });
    onRefresh();
    setLoading(null);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 900 }}>
      {pending.length === 0 && (
        <div className="g-card" style={{ padding: 40, textAlign: 'center' }}>
          <div style={{ fontSize: 32, marginBottom: 8 }}>✅</div>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>No pending approvals</div>
          <div style={{ fontSize: 13, color: 'var(--text-3)' }}>All quarantine actions have been reviewed</div>
        </div>
      )}
      {pending.map(item => (
        <div key={item.id} className="g-card" style={{ padding: 16, borderLeft: '3px solid #f97316' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12, marginBottom: 12, flexWrap: 'wrap' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span style={{ fontSize: 16 }}>{ASSET_ICON[item.asset_type]}</span>
                <span style={{ fontWeight: 700, fontSize: 15 }}>{item.asset_name}</span>
                <SevPill s={item.severity} />
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-3)' }}>{item.quarantine_id} · {QTYPE_LABEL[item.quarantine_type] || item.quarantine_type} · {timeAgo(item.created_at)}</div>
            </div>
            <span style={{ fontSize: 12, fontWeight: 700, color: '#f97316', background: '#f9731622', padding: '4px 10px', borderRadius: 6, border: '1px solid #f9731644', flexShrink: 0 }}>PENDING APPROVAL</span>
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 10, padding: '8px 12px', background: 'var(--bg)', borderRadius: 6, border: '1px solid var(--border)', lineHeight: 1.5 }}>
            <strong>Reason:</strong> {item.quarantine_reason || '—'}
          </div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
              {[['Source', item.source_detection], ['Owner', item.owner], ['Risk Score', item.risk_score]].map(([k, v]) => (
                <span key={k} style={{ fontSize: 11, padding: '3px 8px', borderRadius: 4, background: 'var(--border)', color: 'var(--text-2)' }}><strong>{k}:</strong> {v || '—'}</span>
              ))}
            </div>
          </div>
          <textarea className="g-input" rows={2} placeholder="Approval notes (optional)…" value={notes[item.id] || ''} onChange={e => setNotes(n => ({ ...n, [item.id]: e.target.value }))} style={{ width: '100%', resize: 'none', marginBottom: 10, fontSize: 12 }} />
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="g-btn g-btn-primary" style={{ fontSize: 12, background: '#22c55e' }} onClick={() => decide(item.id, 'approve')} disabled={loading === item.id}>✓ Approve &amp; Activate</button>
            <button className="g-btn g-btn-ghost" style={{ fontSize: 12, color: '#ef4444' }} onClick={() => decide(item.id, 'reject')} disabled={loading === item.id}>✗ Reject</button>
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Analytics Tab ───────────────────────────────────────────────────────
function AnalyticsTab({ analytics }: { analytics: any }) {
  if (!analytics) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const maxTrend = Math.max(...(analytics.quarantine_trend || []).map((d: any) => d.count), 1);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total Quarantined" value={analytics.total_quarantined} color="var(--accent)" />
        <StatCard label="Active" value={analytics.active} color="#ef4444" />
        <StatCard label="Released" value={analytics.released} color="#22c55e" />
        <StatCard label="Release Success" value={`${analytics.release_success_rate}%`} color="#22c55e" sub="of all releases" />
        <StatCard label="Avg Duration" value={`${analytics.avg_duration_hours}h`} color="#f97316" sub="quarantine time" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Quarantine Trend (7d)</div>
          <div style={{ display: 'flex', gap: 4, alignItems: 'flex-end', height: 80 }}>
            {analytics.quarantine_trend?.map((d: any) => (
              <div key={d.date} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                <div style={{ width: '100%', background: '#ef4444', borderRadius: '2px 2px 0 0', height: `${Math.max(3, (d.count / maxTrend) * 64)}px` }} title={`${d.count}`} />
                <div style={{ fontSize: 8, color: 'var(--text-3)' }}>{d.date.slice(5)}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>By Asset Type</div>
          {analytics.by_type && Object.entries(analytics.by_type).map(([type, count]) => (
            <div key={type} style={{ marginBottom: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 2 }}>
                <span style={{ color: 'var(--text-2)' }}>{ASSET_ICON[type]} {type}</span>
                <span style={{ fontWeight: 700, color: '#ef4444' }}>{String(count)}</span>
              </div>
              <div style={{ background: 'var(--border)', borderRadius: 2, height: 5 }}>
                <div style={{ background: '#ef4444', borderRadius: 2, height: 5, width: `${Math.round((Number(count) / analytics.total_quarantined) * 100)}%` }} />
              </div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Top Detection Sources</div>
          {analytics.top_detection_sources?.map((d: any) => (
            <div key={d.source} style={{ marginBottom: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 2 }}>
                <span style={{ color: 'var(--text-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '70%' }}>{d.source}</span>
                <span style={{ fontWeight: 700, color: '#f97316' }}>{d.count}</span>
              </div>
              <div style={{ background: 'var(--border)', borderRadius: 2, height: 5 }}>
                <div style={{ background: '#f97316', borderRadius: 2, height: 5, width: `${Math.round((d.count / (analytics.top_detection_sources[0]?.count || 1)) * 100)}%` }} />
              </div>
            </div>
          ))}
        </div>

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Repeat Offenders</div>
          {analytics.repeat_offenders?.length === 0 && <div style={{ color: 'var(--text-3)', fontSize: 13 }}>No repeat offenders</div>}
          {analytics.repeat_offenders?.map((r: any) => (
            <div key={r.asset} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <div>
                <div style={{ fontWeight: 600, fontSize: 12 }}>{r.asset}</div>
                <div style={{ fontSize: 10, color: 'var(--text-3)' }}>Last: {timeAgo(r.last_at)}</div>
              </div>
              <span style={{ fontSize: 18, fontWeight: 700, color: '#ef4444' }}>{r.quarantine_count}×</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Audit Trail ─────────────────────────────────────────────────────────
function AuditTab({ entries }: { entries: any[] }) {
  const ACTION_COLOR: Record<string, string> = {
    created: '#3b82f6', released: '#22c55e', escalated: '#a855f7', rejected: '#ef4444',
    approved: '#22c55e', evidence_collected: '#06b6d4', notes_updated: '#6b7280',
    extended: '#f97316', approval_required: '#f97316',
  };
  return (
    <div className="g-card" style={{ overflow: 'hidden' }}>
      <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontWeight: 600 }}>Quarantine Audit Trail</span>
        <span style={{ fontSize: 12, color: 'var(--text-3)' }}>Immutable — all actions recorded</span>
      </div>
      {entries.length === 0 && <div style={{ padding: 24, color: 'var(--text-3)', textAlign: 'center' }}>No audit entries</div>}
      <div style={{ overflowX: 'auto' }}>
        <table className="g-table" style={{ width: '100%' }}>
          <thead className="g-thead">
            <tr>{['Time', 'ID', 'Asset', 'Action', 'Actor', 'Details'].map(h => (
              <th key={h} className="g-tr" style={{ padding: '8px 14px', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
            ))}</tr>
          </thead>
          <tbody>
            {entries.map(e => (
              <tr key={e.id} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '9px 14px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(e.created_at)}</td>
                <td style={{ padding: '9px 14px', fontSize: 10, fontFamily: 'monospace', color: 'var(--accent)' }}>{e.quarantine_id}</td>
                <td style={{ padding: '9px 14px', fontSize: 12, fontWeight: 600, maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.asset_name}</td>
                <td style={{ padding: '9px 14px' }}>
                  <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 10, background: (ACTION_COLOR[e.action] || '#6b7280') + '22', color: ACTION_COLOR[e.action] || '#6b7280', textTransform: 'capitalize' }}>{e.action?.replace(/_/g, ' ')}</span>
                </td>
                <td style={{ padding: '9px 14px', fontSize: 12, color: 'var(--text-2)' }}>{e.actor}</td>
                <td style={{ padding: '9px 14px', fontSize: 12, color: 'var(--text-2)', maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Reports Tab ─────────────────────────────────────────────────────────
function ReportsTab() {
  const [reportType, setReportType] = useState('quarantine_activity');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const REPORT_TYPES: [string, string][] = [
    ['quarantine_activity', 'Quarantine Activity Report'],
    ['endpoint_isolation', 'Endpoint Isolation Report'],
    ['malware_containment', 'Malware Containment Report'],
    ['executive_summary', 'Executive Summary'],
    ['audit_report', 'Audit Report'],
    ['compliance_report', 'Compliance Report'],
  ];
  const generate = async () => {
    setLoading(true);
    const r = await qeAPI.generateReport({ report_type: reportType });
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
          {result.by_type_summary && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8 }}>By Asset Type</div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {Object.entries(result.by_type_summary).map(([type, count]) => (
                  <span key={type} style={{ fontSize: 12, padding: '4px 10px', borderRadius: 6, background: 'var(--border)', color: 'var(--text-2)' }}>{ASSET_ICON[type]} {type}: <strong>{String(count)}</strong></span>
                ))}
              </div>
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
export default function QuarantinePage() {
  const [tab, setTab] = useState<Tab>('dashboard');
  const loaded = useRef<Record<string, boolean>>({});

  const [dash, setDash] = useState<any>(null);
  const [items, setItems] = useState<any[]>([]);
  const [audit, setAudit] = useState<any[]>([]);
  const [analytics, setAnalytics] = useState<any>(null);

  useEffect(() => {
    loaded.current['dashboard'] = true;
    loaded.current['queue'] = true;
    loaded.current['ai'] = true;
    loaded.current['approvals'] = true;
    qeAPI.getDashboard().then(r => setDash(r.data));
    qeAPI.getQueue().then(r => setItems(r.data || []));
  }, []);

  const refreshAll = () => {
    qeAPI.getDashboard().then(r => setDash(r.data));
    qeAPI.getQueue().then(r => setItems(r.data || []));
    if (loaded.current['audit']) qeAPI.getAudit().then(r => setAudit(r.data || []));
    if (loaded.current['analytics']) qeAPI.getAnalytics().then(r => setAnalytics(r.data));
  };

  const switchTab = (t: Tab) => {
    setTab(t);
    if (!loaded.current[t]) {
      loaded.current[t] = true;
      if (t === 'audit') qeAPI.getAudit().then(r => setAudit(r.data || []));
      if (t === 'analytics') qeAPI.getAnalytics().then(r => setAnalytics(r.data));
    }
  };

  const pendingCount = items.filter(i => i.approval_status === 'pending').length;

  return (
    <RootLayout>
      <div style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 20, height: '100%' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>Quarantine</h1>
            <div style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 4 }}>
              Endpoint isolation · File containment · User lockout · Network blocking · AI analysis · Release workflow
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {pendingCount > 0 && (
              <div style={{ padding: '6px 12px', borderRadius: 6, background: '#f9731622', color: '#f97316', fontSize: 12, fontWeight: 700, border: '1px solid #f9731644' }}>
                {pendingCount} pending approval{pendingCount !== 1 ? 's' : ''}
              </div>
            )}
            <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={refreshAll}>↻ Refresh</button>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', overflowX: 'auto' }}>
          {(Object.keys(TAB_LABELS) as Tab[]).map(t => (
            <button key={t} onClick={() => switchTab(t)}
              style={{ padding: '8px 16px', fontSize: 12, fontWeight: tab === t ? 600 : 400, color: tab === t ? 'var(--accent)' : 'var(--text-3)', background: 'transparent', border: 'none', borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent', cursor: 'pointer', whiteSpace: 'nowrap', position: 'relative' }}>
              {TAB_LABELS[t]}
              {t === 'queue' && items.length > 0 && <span style={{ marginLeft: 5, fontSize: 10, background: 'var(--border)', padding: '1px 5px', borderRadius: 8, color: 'var(--text-3)' }}>{items.length}</span>}
              {t === 'approvals' && pendingCount > 0 && <span style={{ marginLeft: 5, fontSize: 10, background: '#f9731622', color: '#f97316', padding: '1px 5px', borderRadius: 8, fontWeight: 700 }}>{pendingCount}</span>}
            </button>
          ))}
        </div>

        <div style={{ display: tab === 'dashboard' ? 'block' : 'none' }}><DashboardTab dash={dash} /></div>
        <div style={{ display: tab === 'queue' ? 'block' : 'none' }}>
          {loaded.current['queue'] && <QueueTab items={items} onRefresh={refreshAll} />}
        </div>
        <div style={{ display: tab === 'ai' ? 'block' : 'none' }}>
          {loaded.current['ai'] && <AITab items={items} />}
        </div>
        <div style={{ display: tab === 'approvals' ? 'block' : 'none' }}>
          {loaded.current['approvals'] && <ApprovalsTab items={items} onRefresh={refreshAll} />}
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
