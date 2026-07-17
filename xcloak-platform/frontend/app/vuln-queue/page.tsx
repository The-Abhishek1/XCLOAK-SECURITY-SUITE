'use client';

import React, { useState, useEffect, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { vqAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';

type Tab = 'dashboard' | 'queue' | 'exceptions' | 'analytics' | 'reports';
const TAB_LABELS: Record<Tab, string> = {
  dashboard: 'Dashboard', queue: 'Remediation Queue',
  exceptions: 'Exceptions', analytics: 'Analytics', reports: 'Reports',
};

const PRIORITY_COLOR: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };
const STATUS_COLOR: Record<string, string> = { unassigned: '#6b7280', assigned: '#3b82f6', in_progress: '#a855f7', awaiting_verification: '#f97316', verified: '#22c55e', closed: '#6b7280', overdue: '#ef4444', blocked: '#ef4444' };

const TEAMS = ['Network Team', 'Windows Team', 'Linux Team', 'Cloud Team', 'DevOps Team', 'Application Team', 'Third-Party Vendor'];
const ACTIONS = [
  { key: 'apply_patch', label: 'Apply Patch' }, { key: 'upgrade_software', label: 'Upgrade Software' },
  { key: 'change_configuration', label: 'Change Configuration' }, { key: 'disable_service', label: 'Disable Service' },
  { key: 'remove_software', label: 'Remove Software' }, { key: 'apply_waf_rule', label: 'Apply WAF Rule' },
  { key: 'block_exploit', label: 'Block Exploit (IPS)' }, { key: 'compensating_control', label: 'Compensating Control' },
];
const BLOCKERS = ['maintenance_window', 'vendor_patch_unavailable', 'business_approval_pending', 'system_offline', 'requires_reboot', 'change_request_pending'];
const EX_TYPES = ['risk_acceptance', 'temporary', 'permanent', 'false_positive', 'compensating_control'];

function StatCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="g-card" style={{ padding: '14px 18px', minWidth: 110 }}>
      <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 700, color: color || 'var(--text-1)', lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 3 }}>{sub}</div>}
    </div>
  );
}

function PriBadge({ p }: { p: string }) {
  return <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 3, background: PRIORITY_COLOR[p] || '#6b7280', color: '#fff', textTransform: 'uppercase' }}>{p}</span>;
}

function StatusPill({ s }: { s: string }) {
  const c = STATUS_COLOR[s] || '#6b7280';
  return <span style={{ fontSize: 11, fontWeight: 600, padding: '2px 9px', borderRadius: 10, background: c + '22', color: c, border: `1px solid ${c}44`, textTransform: 'capitalize', whiteSpace: 'nowrap' }}>{s.replace(/_/g, ' ')}</span>;
}

function SLADueTag({ dueDate, status }: { dueDate: string | null; status: string }) {
  if (!dueDate) return null;
  const d = new Date(dueDate);
  const now = new Date();
  const diff = d.getTime() - now.getTime();
  const days = Math.round(diff / 86400000);
  const isOverdue = diff < 0 && status !== 'closed' && status !== 'verified';
  return (
    <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 4, background: isOverdue ? '#ef444422' : days < 2 ? '#f9731622' : '#6b728022', color: isOverdue ? '#ef4444' : days < 2 ? '#f97316' : 'var(--text-3)', border: `1px solid ${isOverdue ? '#ef444444' : days < 2 ? '#f9731644' : 'var(--border)'}` }}>
      {isOverdue ? `${Math.abs(days)}d overdue` : days === 0 ? 'due today' : `${days}d left`}
    </span>
  );
}

// ─── Dashboard Tab ────────────────────────────────────────────────────────────
function DashboardTab({ dash }: { dash: any }) {
  if (!dash) return <div style={{ color: 'var(--text-3)', padding: 40, textAlign: 'center' }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total Active" value={dash.total} />
        <StatCard label="Unassigned" value={dash.unassigned} color={dash.unassigned > 0 ? '#ef4444' : 'var(--text-1)'} />
        <StatCard label="Assigned" value={dash.assigned} color="#3b82f6" />
        <StatCard label="In Progress" value={dash.in_progress} color="#a855f7" />
        <StatCard label="Awaiting Verify" value={dash.awaiting_verification} color="#f97316" />
        <StatCard label="Verified" value={dash.verified} color="#22c55e" />
        <StatCard label="Closed" value={dash.closed} color="var(--text-3)" />
        <StatCard label="Overdue" value={dash.overdue} color={dash.overdue > 0 ? '#ef4444' : 'var(--text-1)'} sub="beyond SLA" />
        <StatCard label="SLA Compliance" value={`${(dash.sla_compliance || 0).toFixed(1)}%`} color={dash.sla_compliance >= 90 ? '#22c55e' : '#f97316'} />
        <StatCard label="MTTR" value={`${dash.mttr_days}d`} color="var(--accent)" sub="mean time to remediate" />
      </div>

      {dash.overdue > 0 && (
        <div className="g-card" style={{ padding: 14, borderLeft: '3px solid #ef4444', background: '#ef444408' }}>
          <div style={{ fontWeight: 700, color: '#ef4444', marginBottom: 4 }}>⚠ SLA Breach — Action Required</div>
          <div style={{ fontSize: 13, color: 'var(--text-2)' }}>
            {dash.overdue} remediation task{dash.overdue !== 1 ? 's are' : ' is'} past due date. Escalate immediately — SLA breach may trigger compliance findings.
          </div>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Queue by Status</div>
          {[
            { label: 'Unassigned', count: dash.unassigned, color: '#6b7280' },
            { label: 'Assigned', count: dash.assigned, color: '#3b82f6' },
            { label: 'In Progress', count: dash.in_progress, color: '#a855f7' },
            { label: 'Awaiting Verify', count: dash.awaiting_verification, color: '#f97316' },
            { label: 'Verified', count: dash.verified, color: '#22c55e' },
          ].map(item => (
            <div key={item.label} style={{ marginBottom: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 3 }}>
                <span style={{ color: item.color, fontWeight: 500 }}>{item.label}</span>
                <span>{item.count}</span>
              </div>
              <div style={{ background: 'var(--border)', borderRadius: 2, height: 6 }}>
                <div style={{ background: item.color, borderRadius: 2, height: 6, width: `${Math.min(100, (item.count / (dash.total || 1)) * 100)}%` }} />
              </div>
            </div>
          ))}
        </div>

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Team Workload</div>
          {dash.team_breakdown?.map((t: any) => (
            <div key={t.team} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
              <span style={{ flex: 1, fontWeight: 500 }}>{t.team}</span>
              <span style={{ fontWeight: 700 }}>{t.total}</span>
              {t.overdue > 0 && <span style={{ fontSize: 11, color: '#ef4444', fontWeight: 700 }}>{t.overdue} overdue</span>}
            </div>
          ))}
        </div>
      </div>

      <div className="g-card" style={{ padding: 16 }}>
        <div style={{ fontWeight: 600, marginBottom: 8 }}>Workflow</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', fontSize: 12 }}>
          {[
            { label: 'Scanner', color: '#6b7280' }, { label: 'Vulnerability', color: '#ef4444' },
            { label: 'Risk Prioritization', color: '#f97316' }, { label: 'Vuln Queue', color: '#a855f7' },
            { label: 'Assignment', color: '#3b82f6' }, { label: 'Patch / Mitigation', color: '#22c55e' },
            { label: 'Verification Scan', color: '#22c55e' }, { label: 'Closed', color: '#6b7280' },
          ].map((step, i, arr) => (
            <React.Fragment key={step.label}>
              <span style={{ padding: '5px 12px', borderRadius: 6, background: step.color + '22', color: step.color, fontWeight: 600, border: `1px solid ${step.color}44` }}>{step.label}</span>
              {i < arr.length - 1 && <span style={{ color: 'var(--text-3)' }}>→</span>}
            </React.Fragment>
          ))}
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 10, fontStyle: 'italic' }}>
          Vuln Queue is the operational remediation work queue — separate from Vulnerability discovery and analysis.
        </div>
      </div>
    </div>
  );
}

// ─── Queue Tab ────────────────────────────────────────────────────────────────
type QueuePanel = 'detail' | 'assign' | 'ai' | 'dependencies' | 'timeline';

function QueueTab({ items, onRefresh, selected, onSelect }: {
  items: any[]; onRefresh: () => void;
  selected: any | null; onSelect: (item: any) => void;
}) {
  const [filterStatus, setFilterStatus] = useState('');
  const [filterPriority, setFilterPriority] = useState('');
  const [filterTeam, setFilterTeam] = useState('');
  const [searchQ, setSearchQ] = useState('');
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [panel, setPanel] = useState<QueuePanel>('detail');
  const [aiResult, setAiResult] = useState<any>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [deps, setDeps] = useState<any[]>([]);
  const [showAssignForm, setShowAssignForm] = useState(false);
  const [assignForm, setAssignForm] = useState({ assigned_team: '', assigned_to: '', notes: '' });
  const [showActionForm, setShowActionForm] = useState(false);
  const [actionForm, setActionForm] = useState({ action: '', notes: '' });
  const [showBlocker, setShowBlocker] = useState(false);
  const [blockerForm, setBlockerForm] = useState({ blocker_type: '', notes: '' });
  const [showBulk, setShowBulk] = useState(false);
  const [bulkForm, setBulkForm] = useState({ action: 'assign', assigned_team: '', priority: '' });

  const filtered = useMemo(() => items.filter(it => {
    if (filterStatus && filterStatus !== 'all' && it.status !== filterStatus) return false;
    if (filterPriority && it.priority !== filterPriority) return false;
    if (filterTeam && it.assigned_team !== filterTeam) return false;
    if (searchQ) {
      const q = searchQ.toLowerCase();
      return it.cve_id.toLowerCase().includes(q) || it.asset_name.toLowerCase().includes(q) || (it.asset_owner || '').toLowerCase().includes(q);
    }
    return true;
  }), [items, filterStatus, filterPriority, filterTeam, searchQ]);

  const toggleSelect = (id: number) => {
    setSelectedIds(s => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  };
  const toggleAll = () => setSelectedIds(s => s.size === filtered.length ? new Set() : new Set(filtered.map(i => i.id)));

  const loadDeps = async (id: number) => {
    const r = await vqAPI.getDependencies(id);
    setDeps(r.data || []);
  };

  const handleSelect = (item: any) => {
    onSelect(item);
    setPanel('detail');
    setAiResult(null);
    setShowAssignForm(false);
    setShowActionForm(false);
    setShowBlocker(false);
  };

  const loadAI = async () => {
    if (!selected) return;
    setAiLoading(true);
    const r = await vqAPI.askAI({ cve_id: selected.cve_id, asset_name: selected.asset_name, priority: selected.priority, risk_score: selected.risk_score, assigned_team: selected.assigned_team || 'Unassigned' });
    setAiResult(r.data);
    setAiLoading(false);
    setPanel('ai');
  };

  const doAssign = async () => {
    if (!selected) return;
    await vqAPI.assign(selected.id, assignForm);
    setShowAssignForm(false);
    onRefresh();
  };

  const doAction = async () => {
    if (!selected) return;
    await vqAPI.action(selected.id, actionForm);
    setShowActionForm(false);
    onRefresh();
  };

  const doVerify = async (pass: boolean) => {
    if (!selected) return;
    await vqAPI.verify(selected.id, { pass, notes: '' });
    onRefresh();
  };

  const doAddBlocker = async () => {
    if (!selected) return;
    await vqAPI.addDependency(selected.id, blockerForm);
    setShowBlocker(false);
    loadDeps(selected.id);
    onRefresh();
  };

  const doBulk = async () => {
    await vqAPI.bulk({ ids: [...selectedIds], ...bulkForm });
    setSelectedIds(new Set());
    setShowBulk(false);
    onRefresh();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Toolbar */}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <input className="g-input" placeholder="CVE, asset, owner…" value={searchQ} onChange={e => setSearchQ(e.target.value)} style={{ fontSize: 12, width: 180 }} />
        <select className="g-select" value={filterStatus} onChange={e => setFilterStatus(e.target.value)} style={{ fontSize: 11 }}>
          <option value="">All Status</option>
          {['unassigned','assigned','in_progress','awaiting_verification','verified','closed','overdue','blocked'].map(s => <option key={s} value={s}>{s.replace(/_/g,' ')}</option>)}
        </select>
        <select className="g-select" value={filterPriority} onChange={e => setFilterPriority(e.target.value)} style={{ fontSize: 11 }}>
          <option value="">All Priority</option>
          {['critical','high','medium','low'].map(p => <option key={p} value={p}>{p}</option>)}
        </select>
        <select className="g-select" value={filterTeam} onChange={e => setFilterTeam(e.target.value)} style={{ fontSize: 11 }}>
          <option value="">All Teams</option>
          {TEAMS.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={onRefresh}>↻</button>
        {selectedIds.size > 0 && (
          <button className="g-btn g-btn-primary" style={{ fontSize: 11, marginLeft: 'auto' }} onClick={() => setShowBulk(true)}>
            Bulk ({selectedIds.size})
          </button>
        )}
      </div>

      {/* Bulk form */}
      {showBulk && (
        <div className="g-card" style={{ padding: 14 }}>
          <div style={{ fontWeight: 600, marginBottom: 10 }}>Bulk Action — {selectedIds.size} items</div>
          <div style={{ display: 'flex', gap: 10, alignItems: 'end', flexWrap: 'wrap' }}>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 3 }}>Action</label>
              <select className="g-select" value={bulkForm.action} onChange={e => setBulkForm(f => ({ ...f, action: e.target.value }))} style={{ fontSize: 12 }}>
                <option value="assign">Assign Team</option>
                <option value="set_priority">Set Priority</option>
                <option value="trigger_patch">Trigger Patch Job</option>
                <option value="close">Close</option>
              </select>
            </div>
            {bulkForm.action === 'assign' && (
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 3 }}>Team</label>
                <select className="g-select" value={bulkForm.assigned_team} onChange={e => setBulkForm(f => ({ ...f, assigned_team: e.target.value }))} style={{ fontSize: 12 }}>
                  <option value="">Select team…</option>
                  {TEAMS.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>
            )}
            {bulkForm.action === 'set_priority' && (
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 3 }}>Priority</label>
                <select className="g-select" value={bulkForm.priority} onChange={e => setBulkForm(f => ({ ...f, priority: e.target.value }))} style={{ fontSize: 12 }}>
                  <option value="">Select…</option>
                  {['critical','high','medium','low'].map(p => <option key={p} value={p}>{p}</option>)}
                </select>
              </div>
            )}
            <button className="g-btn g-btn-primary" style={{ fontSize: 12 }} onClick={doBulk}>Apply</button>
            <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={() => setShowBulk(false)}>Cancel</button>
          </div>
        </div>
      )}

      {/* Main split panel */}
      <div style={{ display: 'flex', gap: 12, minHeight: 500, height: 'calc(100vh - 320px)' }}>
        {/* Left list */}
        <div className="g-card" style={{ width: 360, flexShrink: 0, overflow: 'hidden', display: 'flex', flexDirection: 'column', padding: 0 }}>
          <div style={{ padding: '8px 10px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <input type="checkbox" checked={selectedIds.size === filtered.length && filtered.length > 0} onChange={toggleAll} />
            <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{filtered.length} items</span>
            {selectedIds.size > 0 && <span style={{ fontSize: 11, color: 'var(--accent)' }}>{selectedIds.size} selected</span>}
          </div>
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {filtered.length === 0 && <div style={{ padding: 24, color: 'var(--text-3)', fontSize: 13, textAlign: 'center' }}>No items</div>}
            {filtered.map(item => {
              const isSelected = selected?.id === item.id;
              const isOverdue = item.due_date && new Date(item.due_date) < new Date() && !['closed','verified'].includes(item.status);
              return (
                <div key={item.id} onClick={() => handleSelect(item)}
                  style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)', cursor: 'pointer', background: isSelected ? 'var(--accent)10' : 'transparent', borderLeft: isSelected ? '3px solid var(--accent)' : '3px solid transparent' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                    <input type="checkbox" checked={selectedIds.has(item.id)} onClick={e => e.stopPropagation()} onChange={() => toggleSelect(item.id)} />
                    <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--text-3)', fontWeight: 600 }}>{item.queue_id}</span>
                    <span style={{ marginLeft: 'auto' }}><PriBadge p={item.priority} /></span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
                    <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: 13, color: PRIORITY_COLOR[item.priority] || 'var(--text-1)' }}>{item.cve_id}</span>
                    {isOverdue && <span style={{ fontSize: 9, background: '#ef4444', color: '#fff', padding: '1px 5px', borderRadius: 3, fontWeight: 700 }}>OVERDUE</span>}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-2)', marginBottom: 4 }}>{item.asset_name} · {item.business_unit}</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                    <StatusPill s={item.status} />
                    {item.assigned_team && <span style={{ fontSize: 10, color: 'var(--text-3)' }}>{item.assigned_team}</span>}
                    {item.due_date && <SLADueTag dueDate={item.due_date} status={item.status} />}
                  </div>
                  {item.blocker_type && (
                    <div style={{ marginTop: 4, fontSize: 10, color: '#ef4444', fontWeight: 600 }}>⛔ {item.blocker_type.replace(/_/g,' ')}</div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Right panel */}
        {!selected ? (
          <div className="g-card" style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 10 }}>
            <div style={{ fontSize: 36 }}>🔧</div>
            <div style={{ color: 'var(--text-3)', fontSize: 14 }}>Select a queue item to review</div>
          </div>
        ) : (
          <div className="g-card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: 0 }}>
            {/* Header */}
            <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 11, color: 'var(--text-3)', fontFamily: 'monospace' }}>{selected.queue_id}</span>
                <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: 15, color: PRIORITY_COLOR[selected.priority] }}>{selected.cve_id}</span>
                <PriBadge p={selected.priority} />
                <StatusPill s={selected.status} />
                {selected.due_date && <SLADueTag dueDate={selected.due_date} status={selected.status} />}
              </div>
              <div style={{ display: 'flex', gap: 12, fontSize: 12, flexWrap: 'wrap', color: 'var(--text-2)' }}>
                <span>Asset: <strong>{selected.asset_name}</strong></span>
                {selected.asset_ip && <span style={{ fontFamily: 'monospace', color: 'var(--text-3)', fontSize: 11 }}>{selected.asset_ip}</span>}
                <span>Owner: <strong>{selected.asset_owner || '—'}</strong></span>
                <span>BU: <strong>{selected.business_unit || '—'}</strong></span>
                {selected.assigned_team && <span>Team: <strong style={{ color: '#3b82f6' }}>{selected.assigned_team}</strong></span>}
                {selected.assigned_to && <span>Assignee: <strong>{selected.assigned_to}</strong></span>}
              </div>
            </div>

            {/* Panel tabs */}
            <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', paddingLeft: 16, overflowX: 'auto' }}>
              {([['detail','Detail'], ['assign','Assign'], ['ai','AI Guidance'], ['dependencies','Dependencies'], ['timeline','Timeline']] as [QueuePanel,string][]).map(([key, label]) => (
                <button key={key} onClick={() => { setPanel(key); if (key === 'dependencies') loadDeps(selected.id); if (key === 'ai' && !aiResult) loadAI(); }}
                  style={{ padding: '7px 12px', fontSize: 11, fontWeight: panel === key ? 600 : 400, color: panel === key ? 'var(--accent)' : 'var(--text-3)', background: 'transparent', border: 'none', borderBottom: panel === key ? '2px solid var(--accent)' : '2px solid transparent', cursor: 'pointer', whiteSpace: 'nowrap' }}>
                  {label}
                </button>
              ))}
            </div>

            {/* Panel body */}
            <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>
              {panel === 'detail' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                    <div className="g-card" style={{ padding: 12 }}>
                      <div style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 8 }}>Queue Details</div>
                      {[['Risk Score', selected.risk_score?.toFixed(1)], ['SLA', `${selected.sla_hours}h`], ['Status', selected.status.replace(/_/g,' ')], ['Remediation', selected.remediation_action?.replace(/_/g,' ') || '—'], ['Blocker', selected.blocker_type?.replace(/_/g,' ') || 'None'], ['Created', timeAgo(selected.created_at)], ['Updated', timeAgo(selected.updated_at)]].map(([k,v]) => (
                        <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 5 }}>
                          <span style={{ color: 'var(--text-3)' }}>{k}</span>
                          <span style={{ fontWeight: 500, textAlign: 'right', color: k === 'Blocker' && v !== 'None' ? '#ef4444' : 'var(--text-1)' }}>{String(v||'—')}</span>
                        </div>
                      ))}
                    </div>
                    <div className="g-card" style={{ padding: 12 }}>
                      <div style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 8 }}>Asset Context</div>
                      {[['Hostname', selected.asset_name], ['IP', selected.asset_ip || '—'], ['Owner', selected.asset_owner || '—'], ['Business Unit', selected.business_unit || '—'], ['Assigned Team', selected.assigned_team || 'Unassigned'], ['Assignee', selected.assigned_to || 'Unassigned'], ['Due Date', selected.due_date ? new Date(selected.due_date).toLocaleDateString() : '—']].map(([k,v]) => (
                        <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 5 }}>
                          <span style={{ color: 'var(--text-3)' }}>{k}</span>
                          <span style={{ fontWeight: 500, textAlign: 'right' }}>{String(v||'—')}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  {selected.notes && (
                    <div className="g-card" style={{ padding: 12, borderLeft: '3px solid var(--accent)' }}>
                      <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 4 }}>Notes</div>
                      <div style={{ fontSize: 13, color: 'var(--text-2)' }}>{selected.notes}</div>
                    </div>
                  )}
                  <div className="g-card" style={{ padding: 14 }}>
                    <div style={{ fontWeight: 600, marginBottom: 10, fontSize: 12 }}>Remediation Actions</div>
                    {!showActionForm ? (
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        {selected.status === 'unassigned' && <button className="g-btn g-btn-primary" style={{ fontSize: 12 }} onClick={() => { setShowAssignForm(true); setPanel('assign'); }}>Assign</button>}
                        {['assigned','in_progress','blocked'].includes(selected.status) && <button className="g-btn g-btn-primary" style={{ fontSize: 12 }} onClick={() => setShowActionForm(true)}>Start / Update</button>}
                        {selected.status === 'in_progress' && <button className="g-btn g-btn-primary" style={{ fontSize: 12, background: '#22c55e' }} onClick={() => vqAPI.action(selected.id, { action: 'complete' }).then(onRefresh)}>Mark Complete</button>}
                        {selected.status === 'awaiting_verification' && (
                          <>
                            <button className="g-btn g-btn-primary" style={{ fontSize: 12, background: '#22c55e' }} onClick={() => doVerify(true)}>✓ Verification Passed</button>
                            <button className="g-btn g-btn-ghost" style={{ fontSize: 12, color: '#ef4444' }} onClick={() => doVerify(false)}>✗ Verification Failed</button>
                          </>
                        )}
                        <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={loadAI}>AI Guidance</button>
                        <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={() => { setShowBlocker(true); setPanel('dependencies'); }}>Add Blocker</button>
                        <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }}>Create Ticket</button>
                        <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }}>Create Incident</button>
                        <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }}>Notify Owner</button>
                      </div>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'end' }}>
                          <div>
                            <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 3 }}>Action</label>
                            <select className="g-select" value={actionForm.action} onChange={e => setActionForm(f => ({ ...f, action: e.target.value }))} style={{ fontSize: 12 }}>
                              <option value="">Select action…</option>
                              {ACTIONS.map(a => <option key={a.key} value={a.key}>{a.label}</option>)}
                            </select>
                          </div>
                          <div style={{ flex: 1 }}>
                            <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 3 }}>Notes</label>
                            <input className="g-input" value={actionForm.notes} onChange={e => setActionForm(f => ({ ...f, notes: e.target.value }))} placeholder="Notes…" style={{ fontSize: 12, width: '100%' }} />
                          </div>
                          <button className="g-btn g-btn-primary" style={{ fontSize: 12 }} onClick={doAction}>Update</button>
                          <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={() => setShowActionForm(false)}>Cancel</button>
                        </div>
                      </div>
                    )}
                  </div>
                  <div className="g-card" style={{ padding: 14 }}>
                    <div style={{ fontWeight: 600, marginBottom: 8, fontSize: 12 }}>Integration Actions</div>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                      <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }}>Jira</button>
                      <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }}>ServiceNow</button>
                      <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }}>Azure DevOps</button>
                      <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }}>GitHub Issues</button>
                      <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }}>Email</button>
                      <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }}>Webhook</button>
                    </div>
                  </div>
                </div>
              )}

              {panel === 'assign' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                  <div className="g-card" style={{ padding: 16 }}>
                    <div style={{ fontWeight: 600, marginBottom: 12 }}>Assign Remediation Task</div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                      <div>
                        <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Assign to Team</label>
                        <select className="g-select" value={assignForm.assigned_team} onChange={e => setAssignForm(f => ({ ...f, assigned_team: e.target.value }))} style={{ width: '100%' }}>
                          <option value="">Select team…</option>
                          {TEAMS.map(t => <option key={t} value={t}>{t}</option>)}
                        </select>
                      </div>
                      <div>
                        <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Assign to Individual</label>
                        <input className="g-input" value={assignForm.assigned_to} onChange={e => setAssignForm(f => ({ ...f, assigned_to: e.target.value }))} placeholder="email@corp.com" style={{ width: '100%' }} />
                      </div>
                      <div>
                        <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Notes</label>
                        <textarea className="g-input" rows={2} value={assignForm.notes} onChange={e => setAssignForm(f => ({ ...f, notes: e.target.value }))} placeholder="Assignment notes…" style={{ width: '100%', resize: 'none' }} />
                      </div>
                      <div style={{ display: 'flex', gap: 8 }}>
                        <button className="g-btn g-btn-primary" style={{ fontSize: 13 }} onClick={doAssign}>Assign</button>
                        <button className="g-btn g-btn-ghost" style={{ fontSize: 13 }} onClick={() => setPanel('detail')}>Cancel</button>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {panel === 'ai' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                  {aiLoading && <div style={{ color: 'var(--text-3)', padding: 24, textAlign: 'center' }}>AI analyzing remediation…</div>}
                  {!aiLoading && !aiResult && (
                    <div style={{ textAlign: 'center', padding: 24 }}>
                      <button className="g-btn g-btn-primary" onClick={loadAI}>Get AI Remediation Guidance</button>
                    </div>
                  )}
                  {aiResult && (
                    <>
                      <div className="g-card" style={{ padding: 14, borderLeft: '3px solid #22c55e' }}>
                        <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 6 }}>Recommendation</div>
                        <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.5 }}>{aiResult.recommendation}</div>
                        <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 6 }}>Estimated effort: {aiResult.estimated_effort}</div>
                      </div>
                      <div className="g-card" style={{ padding: 14 }}>
                        <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8 }}>Remediation Steps</div>
                        {aiResult.steps?.map((step: string, i: number) => (
                          <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 8, fontSize: 13, color: 'var(--text-2)' }}>
                            <span style={{ width: 20, height: 20, borderRadius: '50%', background: 'var(--accent)', color: '#fff', fontSize: 10, fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>{i+1}</span>
                            <span style={{ lineHeight: 1.4 }}>{step}</span>
                          </div>
                        ))}
                      </div>
                      {aiResult.risks_if_delayed && (
                        <div className="g-card" style={{ padding: 14, borderLeft: '3px solid #ef4444' }}>
                          <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 6, color: '#ef4444' }}>Risk if Delayed</div>
                          <div style={{ fontSize: 13, color: 'var(--text-2)' }}>{aiResult.risks_if_delayed}</div>
                        </div>
                      )}
                      {aiResult.alternative_mitigations?.length > 0 && (
                        <div className="g-card" style={{ padding: 14 }}>
                          <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8 }}>Alternative Mitigations (if patch not immediately possible)</div>
                          {aiResult.alternative_mitigations.map((m: string, i: number) => (
                            <div key={i} style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 6 }}>• {m}</div>
                          ))}
                        </div>
                      )}
                      {aiResult.ai_analysis && (
                        <div className="g-card" style={{ padding: 14 }}>
                          <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 6 }}>AI Risk Context</div>
                          <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.5, fontStyle: 'italic' }}>{aiResult.ai_analysis}</div>
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}

              {panel === 'dependencies' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                  {!showBlocker ? (
                    <button className="g-btn g-btn-ghost" style={{ fontSize: 12, alignSelf: 'flex-start' }} onClick={() => setShowBlocker(true)}>+ Add Blocker</button>
                  ) : (
                    <div className="g-card" style={{ padding: 14 }}>
                      <div style={{ fontWeight: 600, marginBottom: 10 }}>Add Dependency / Blocker</div>
                      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'end' }}>
                        <div>
                          <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 3 }}>Blocker Type</label>
                          <select className="g-select" value={blockerForm.blocker_type} onChange={e => setBlockerForm(f => ({ ...f, blocker_type: e.target.value }))} style={{ fontSize: 12 }}>
                            <option value="">Select type…</option>
                            {BLOCKERS.map(b => <option key={b} value={b}>{b.replace(/_/g,' ')}</option>)}
                          </select>
                        </div>
                        <div style={{ flex: 1 }}>
                          <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 3 }}>Notes</label>
                          <input className="g-input" value={blockerForm.notes} onChange={e => setBlockerForm(f => ({ ...f, notes: e.target.value }))} placeholder="Details…" style={{ fontSize: 12, width: '100%' }} />
                        </div>
                        <button className="g-btn g-btn-primary" style={{ fontSize: 12 }} onClick={doAddBlocker}>Add</button>
                        <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={() => setShowBlocker(false)}>Cancel</button>
                      </div>
                    </div>
                  )}
                  {deps.length === 0 && <div style={{ color: 'var(--text-3)', fontSize: 13 }}>No dependencies / blockers</div>}
                  {deps.map(d => (
                    <div key={d.id} className="g-card" style={{ padding: 12, borderLeft: '3px solid #ef4444' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                        <span style={{ fontSize: 12, fontWeight: 700, color: '#ef4444' }}>⛔ {d.blocker_type.replace(/_/g,' ')}</span>
                        <span style={{ fontSize: 11, padding: '1px 7px', borderRadius: 10, background: '#6b728022', color: '#6b7280' }}>{d.status}</span>
                        <span style={{ fontSize: 10, color: 'var(--text-3)', marginLeft: 'auto' }}>{timeAgo(d.created_at)}</span>
                      </div>
                      {d.notes && <div style={{ fontSize: 13, color: 'var(--text-2)' }}>{d.notes}</div>}
                    </div>
                  ))}
                </div>
              )}

              {panel === 'timeline' && (
                <div>
                  {[
                    { label: 'Vulnerability Detected', date: selected.created_at, icon: '⚠', done: true },
                    { label: 'Added to Queue', date: selected.created_at, icon: '📋', done: true },
                    { label: 'Assigned', date: selected.assigned_team ? selected.updated_at : null, icon: '👤', done: !!selected.assigned_team },
                    { label: 'Patch Scheduled', date: null, icon: '📅', done: ['in_progress','awaiting_verification','verified','closed'].includes(selected.status) },
                    { label: 'Patched / Remediated', date: null, icon: '🔧', done: ['awaiting_verification','verified','closed'].includes(selected.status) },
                    { label: 'Verification Scan', date: null, icon: '🔍', done: ['verified','closed'].includes(selected.status) },
                    { label: 'Closed', date: selected.status === 'closed' ? selected.updated_at : null, icon: '✅', done: selected.status === 'closed' },
                  ].map((step, i, arr) => (
                    <div key={step.label} style={{ display: 'flex', gap: 12, paddingBottom: 16 }}>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: 32 }}>
                        <div style={{ width: 28, height: 28, borderRadius: '50%', background: step.done ? 'var(--accent)' : 'var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 13, flexShrink: 0 }}>{step.icon}</div>
                        {i < arr.length - 1 && <div style={{ flex: 1, width: 2, background: 'var(--border)', marginTop: 4 }} />}
                      </div>
                      <div style={{ paddingTop: 4 }}>
                        <div style={{ fontSize: 13, fontWeight: 600, color: step.done ? 'var(--text-1)' : 'var(--text-3)' }}>{step.label}</div>
                        <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{step.date ? `${new Date(step.date).toLocaleDateString()} · ${timeAgo(step.date)}` : step.done ? 'Completed' : 'Pending'}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Exceptions Tab ───────────────────────────────────────────────────────────
function ExceptionsTab({ exceptions, onApprove, onDelete }: {
  exceptions: any[]; onApprove: (id: number) => void; onDelete: (id: number) => void;
}) {
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ cve_id: '', exception_type: 'temporary', reason: '', compensating_control: '', review_schedule: 'monthly' });
  const EX_STATUS_COLOR: Record<string, string> = { approved: '#22c55e', pending: '#f97316', rejected: '#ef4444', expired: '#6b7280' };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', gap: 10 }}>
          {['approved','pending','expired'].map(s => (
            <StatCard key={s} label={s} value={exceptions.filter(e => e.status === s).length} color={EX_STATUS_COLOR[s]} />
          ))}
        </div>
        <button className="g-btn g-btn-primary" style={{ fontSize: 12 }} onClick={() => setShowForm(true)}>+ New Exception</button>
      </div>

      {showForm && (
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Exception Request</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>CVE ID</label>
              <input className="g-input" value={form.cve_id} onChange={e => setForm(f => ({ ...f, cve_id: e.target.value }))} placeholder="CVE-2024-XXXXX" />
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Type</label>
              <select className="g-select" value={form.exception_type} onChange={e => setForm(f => ({ ...f, exception_type: e.target.value }))}>
                {EX_TYPES.map(t => <option key={t} value={t}>{t.replace(/_/g,' ')}</option>)}
              </select>
            </div>
          </div>
          <div style={{ marginBottom: 10 }}>
            <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Business Justification</label>
            <textarea className="g-input" rows={2} value={form.reason} onChange={e => setForm(f => ({ ...f, reason: e.target.value }))} placeholder="Why this exception is needed…" style={{ width: '100%', resize: 'none' }} />
          </div>
          <div style={{ marginBottom: 10 }}>
            <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Compensating Control</label>
            <input className="g-input" value={form.compensating_control} onChange={e => setForm(f => ({ ...f, compensating_control: e.target.value }))} placeholder="Controls in place to reduce risk…" style={{ width: '100%' }} />
          </div>
          <div style={{ marginBottom: 12 }}>
            <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Review Schedule</label>
            <select className="g-select" value={form.review_schedule} onChange={e => setForm(f => ({ ...f, review_schedule: e.target.value }))}>
              {['weekly','monthly','quarterly','annually'].map(r => <option key={r} value={r}>{r}</option>)}
            </select>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="g-btn g-btn-primary" style={{ fontSize: 12 }} onClick={async () => { await vqAPI.createException(form); setShowForm(false); }}>Submit</button>
            <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={() => setShowForm(false)}>Cancel</button>
          </div>
        </div>
      )}

      <div className="g-card" style={{ overflow: 'hidden' }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', fontWeight: 600 }}>Exception Register</div>
        {exceptions.length === 0 && <div style={{ padding: 24, color: 'var(--text-3)', textAlign: 'center' }}>No exceptions</div>}
        {exceptions.map(e => (
          <div key={e.id} style={{ padding: '14px 16px', borderBottom: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
              <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: 13, color: 'var(--accent)' }}>{e.cve_id}</span>
              <span style={{ fontSize: 11, background: 'var(--border)', padding: '1px 7px', borderRadius: 10, color: 'var(--text-2)', textTransform: 'capitalize' }}>{e.exception_type.replace(/_/g,' ')}</span>
              <span style={{ fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 10, background: (EX_STATUS_COLOR[e.status]||'#6b7280')+'22', color: EX_STATUS_COLOR[e.status]||'#6b7280' }}>{e.status}</span>
              {e.expiration_date && <span style={{ fontSize: 10, color: 'var(--text-3)', marginLeft: 'auto' }}>Expires {new Date(e.expiration_date).toLocaleDateString()}</span>}
            </div>
            <div style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 4 }}>{e.reason}</div>
            {e.compensating_control && <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 4 }}>Control: {e.compensating_control}</div>}
            {e.review_schedule && <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 6 }}>Review: {e.review_schedule}</div>}
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ fontSize: 10, color: 'var(--text-3)' }}>By {e.created_by} · {timeAgo(e.created_at)}</span>
              {e.approver && <span style={{ fontSize: 10, color: '#22c55e' }}>Approved by {e.approver}</span>}
              {e.status === 'pending' && <button className="g-btn g-btn-primary" style={{ fontSize: 10, padding: '2px 8px', marginLeft: 'auto' }} onClick={() => onApprove(e.id)}>Approve</button>}
              <button className="g-btn g-btn-ghost" style={{ fontSize: 10, padding: '2px 8px', marginLeft: e.status !== 'pending' ? 'auto' : 0, color: '#ef4444' }} onClick={() => onDelete(e.id)}>Delete</button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Analytics Tab ────────────────────────────────────────────────────────────
function AnalyticsTab({ analytics, sla }: { analytics: any; sla: any }) {
  if (!analytics) return <div style={{ color: 'var(--text-3)', padding: 40, textAlign: 'center' }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="MTTR" value={`${analytics.mttr_days}d`} color="var(--accent)" sub="mean time to remediate" />
        <StatCard label="SLA Compliance" value={`${analytics.sla_compliance}%`} color={analytics.sla_compliance >= 90 ? '#22c55e' : '#f97316'} />
        <StatCard label="Overdue" value={analytics.overdue_count} color={analytics.overdue_count > 0 ? '#ef4444' : 'var(--text-1)'} />
        <StatCard label="Closed" value={analytics.closed_count} color="#22c55e" sub="all time" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Team Performance</div>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead><tr>{['Team', 'Assigned', 'Closed', 'Overdue', 'Avg Days'].map(h => <th key={h} style={{ textAlign: 'left', padding: '5px 8px', color: 'var(--text-3)', fontWeight: 600, fontSize: 11, textTransform: 'uppercase' }}>{h}</th>)}</tr></thead>
            <tbody>
              {analytics.team_performance?.map((t: any) => (
                <tr key={t.team} style={{ borderTop: '1px solid var(--border)' }}>
                  <td style={{ padding: '7px 8px', fontWeight: 500 }}>{t.team}</td>
                  <td style={{ padding: '7px 8px', textAlign: 'center' }}>{t.assigned}</td>
                  <td style={{ padding: '7px 8px', textAlign: 'center', color: '#22c55e', fontWeight: 700 }}>{t.closed}</td>
                  <td style={{ padding: '7px 8px', textAlign: 'center', color: t.overdue > 0 ? '#ef4444' : 'var(--text-3)', fontWeight: t.overdue > 0 ? 700 : 400 }}>{t.overdue}</td>
                  <td style={{ padding: '7px 8px', textAlign: 'center', color: t.avg_days > 14 ? '#ef4444' : t.avg_days > 7 ? '#f97316' : '#22c55e', fontWeight: 700 }}>{t.avg_days}d</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Remediation Trend (Weekly)</div>
          <div style={{ display: 'flex', gap: 4, alignItems: 'flex-end', height: 80 }}>
            {analytics.remediation_trend?.map((d: any) => {
              const max = Math.max(...analytics.remediation_trend.map((x: any) => Math.max(x.opened, x.closed)), 1);
              return (
                <div key={d.week} style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 2, alignItems: 'center' }}>
                  <div style={{ width: '100%', display: 'flex', gap: 2, alignItems: 'flex-end', height: 64 }}>
                    <div style={{ flex: 1, background: '#ef444466', height: `${(d.opened/max)*64}px`, borderRadius: '2px 2px 0 0' }} title={`Opened: ${d.opened}`} />
                    <div style={{ flex: 1, background: '#22c55e88', height: `${(d.closed/max)*64}px`, borderRadius: '2px 2px 0 0' }} title={`Closed: ${d.closed}`} />
                  </div>
                  <div style={{ fontSize: 9, color: 'var(--text-3)' }}>{d.week}</div>
                </div>
              );
            })}
          </div>
          <div style={{ display: 'flex', gap: 12, marginTop: 6, fontSize: 10, color: 'var(--text-3)' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}><span style={{ width: 10, height: 10, background: '#ef444466', display: 'inline-block', borderRadius: 2 }} /> Opened</span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}><span style={{ width: 10, height: 10, background: '#22c55e88', display: 'inline-block', borderRadius: 2 }} /> Closed</span>
          </div>
        </div>
      </div>

      {analytics.top_delayed_assets?.length > 0 && (
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 10 }}>Top Delayed Assets</div>
          {analytics.top_delayed_assets.map((a: any) => (
            <div key={a.asset} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '8px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
              <span style={{ fontFamily: 'monospace', fontWeight: 600, flex: 1 }}>{a.asset}</span>
              <span style={{ color: '#f97316' }}>{a.assigned_team}</span>
              <span style={{ color: '#ef4444', fontWeight: 700 }}>{a.overdue_days}d overdue</span>
            </div>
          ))}
        </div>
      )}

      {sla && (
        <div className="g-card" style={{ overflow: 'hidden' }}>
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', fontWeight: 600 }}>SLA Policy & Compliance</div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead><tr>{['Priority', 'Assign', 'Start', 'Patch', 'Verify', 'Close', 'Compliance'].map(h => <th key={h} style={{ padding: '8px 12px', textAlign: 'left', color: 'var(--text-3)', fontWeight: 600, fontSize: 11, textTransform: 'uppercase' }}>{h}</th>)}</tr></thead>
              <tbody>
                {sla.policies?.map((p: any) => {
                  const comp = sla.current_compliance?.[p.priority];
                  return (
                    <tr key={p.priority} style={{ borderTop: '1px solid var(--border)' }}>
                      <td style={{ padding: '9px 12px' }}><span style={{ fontSize: 11, fontWeight: 700, padding: '2px 7px', borderRadius: 3, background: PRIORITY_COLOR[p.priority]+'22', color: PRIORITY_COLOR[p.priority], textTransform: 'capitalize' }}>{p.priority}</span></td>
                      <td style={{ padding: '9px 12px', color: 'var(--text-2)' }}>{p.time_to_assign_h}h</td>
                      <td style={{ padding: '9px 12px', color: 'var(--text-2)' }}>{p.time_to_start_h}h</td>
                      <td style={{ padding: '9px 12px', fontWeight: 700 }}>{p.time_to_patch_h}h</td>
                      <td style={{ padding: '9px 12px', color: 'var(--text-2)' }}>{p.time_to_verify_h}h</td>
                      <td style={{ padding: '9px 12px', color: 'var(--text-2)' }}>{p.time_to_close_h}h</td>
                      <td style={{ padding: '9px 12px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <div style={{ width: 80, background: 'var(--border)', borderRadius: 2, height: 6 }}>
                            <div style={{ background: comp >= 95 ? '#22c55e' : comp >= 80 ? '#f97316' : '#ef4444', borderRadius: 2, height: 6, width: `${comp}%` }} />
                          </div>
                          <span style={{ fontWeight: 700, color: comp >= 95 ? '#22c55e' : comp >= 80 ? '#f97316' : '#ef4444' }}>{comp}%</span>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Reports Tab ──────────────────────────────────────────────────────────────
function ReportsTab() {
  const [reportType, setReportType] = useState('remediation_status');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const REPORT_TYPES = [
    ['remediation_status', 'Remediation Status'], ['sla', 'SLA Report'],
    ['overdue', 'Overdue Findings'], ['team', 'Team Performance'], ['executive', 'Executive Summary'],
  ];
  const generate = async () => {
    setLoading(true);
    const r = await vqAPI.generateReport({ report_type: reportType });
    setResult(r.data);
    setLoading(false);
  };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 800 }}>
      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 14 }}>Generate Report</div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'end' }}>
          <div style={{ flex: 1 }}>
            <label style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', display: 'block', marginBottom: 4 }}>Report Type</label>
            <select className="g-select" value={reportType} onChange={e => setReportType(e.target.value)} style={{ width: '100%' }}>
              {REPORT_TYPES.map(([v,l]) => <option key={v} value={v}>{l}</option>)}
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
              {Object.entries(result.key_metrics).map(([k,v]) => <StatCard key={k} label={k.replace(/_/g,' ')} value={String(v)} />)}
            </div>
          )}
          {result.overdue_items && result.overdue_items.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8, color: '#ef4444' }}>Overdue Items</div>
              {result.overdue_items.map((i: any) => (
                <div key={i.queue_id} style={{ display: 'flex', gap: 12, fontSize: 12, padding: '6px 0', borderBottom: '1px solid var(--border)', alignItems: 'center' }}>
                  <span style={{ fontFamily: 'monospace', color: 'var(--text-3)', fontSize: 11 }}>{i.queue_id}</span>
                  <span style={{ fontFamily: 'monospace', fontWeight: 700, color: '#ef4444' }}>{i.cve}</span>
                  <span>{i.asset}</span>
                  <span style={{ color: 'var(--text-3)' }}>{i.team}</span>
                  <span style={{ color: '#ef4444', fontWeight: 700, marginLeft: 'auto' }}>{i.days_overdue}d overdue</span>
                </div>
              ))}
            </div>
          )}
          {result.recommendations && (
            <div>
              <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8 }}>Recommendations</div>
              {result.recommendations.map((r: string, i: number) => (
                <div key={i} style={{ display: 'flex', gap: 8, fontSize: 12, color: 'var(--text-2)', marginBottom: 5 }}>
                  <span style={{ color: 'var(--accent)', fontWeight: 700 }}>{i+1}.</span><span>{r}</span>
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
export default function VulnQueuePage() {
  const [tab, setTab] = useState<Tab>('dashboard');
  const loaded = useRef<Record<string, boolean>>({});

  const [dash, setDash] = useState<any>(null);
  const [items, setItems] = useState<any[]>([]);
  const [selectedItem, setSelectedItem] = useState<any>(null);
  const [exceptions, setExceptions] = useState<any[]>([]);
  const [analytics, setAnalytics] = useState<any>(null);
  const [sla, setSLA] = useState<any>(null);

  useEffect(() => {
    loaded.current['dashboard'] = true;
    vqAPI.getDashboard().then(r => setDash(r.data));
    vqAPI.getQueue().then(r => setItems(r.data || []));
  }, []);

  const switchTab = (t: Tab) => {
    setTab(t);
    if (!loaded.current[t]) loaded.current[t] = true;
    if (t === 'exceptions' && exceptions.length === 0) vqAPI.getExceptions().then(r => setExceptions(r.data || []));
    if (t === 'analytics' && !analytics) {
      vqAPI.getAnalytics().then(r => setAnalytics(r.data));
      vqAPI.getSLA().then(r => setSLA(r.data));
    }
  };

  return (
    <RootLayout>
      <div style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 20, height: '100%' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>Vulnerability Remediation Queue</h1>
            <div style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 4 }}>
              Operational remediation tracking — assign, patch, verify, and close vulnerabilities across teams
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {dash?.overdue > 0 && (
              <div style={{ padding: '6px 14px', borderRadius: 6, background: '#ef444422', color: '#ef4444', fontSize: 12, fontWeight: 700, border: '1px solid #ef444444' }}>
                {dash.overdue} item{dash.overdue !== 1 ? 's' : ''} overdue
              </div>
            )}
          </div>
        </div>

        <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', overflowX: 'auto' }}>
          {(Object.keys(TAB_LABELS) as Tab[]).map(t => (
            <button key={t} onClick={() => switchTab(t)}
              style={{ padding: '8px 16px', fontSize: 12, fontWeight: tab === t ? 600 : 400, color: tab === t ? 'var(--accent)' : 'var(--text-3)', background: 'transparent', border: 'none', borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent', cursor: 'pointer', whiteSpace: 'nowrap' }}>
              {TAB_LABELS[t]}
              {t === 'queue' && items.length > 0 && <span style={{ marginLeft: 6, fontSize: 10, background: 'var(--border)', padding: '1px 5px', borderRadius: 8, color: 'var(--text-3)' }}>{items.length}</span>}
            </button>
          ))}
        </div>

        <div style={{ display: tab === 'dashboard' ? 'block' : 'none' }}><DashboardTab dash={dash} /></div>
        <div style={{ display: tab === 'queue' ? 'block' : 'none' }}>
          {loaded.current['queue'] && (
            <QueueTab items={items} onRefresh={() => { vqAPI.getQueue().then(r => setItems(r.data || [])); vqAPI.getDashboard().then(r => setDash(r.data)); }} selected={selectedItem} onSelect={setSelectedItem} />
          )}
        </div>
        <div style={{ display: tab === 'exceptions' ? 'block' : 'none' }}>
          {loaded.current['exceptions'] && (
            <ExceptionsTab exceptions={exceptions} onApprove={async id => { await vqAPI.updateException(id, { status: 'approved' }); vqAPI.getExceptions().then(r => setExceptions(r.data || [])); }} onDelete={async id => { await vqAPI.deleteException(id); setExceptions(ex => ex.filter(e => e.id !== id)); }} />
          )}
        </div>
        <div style={{ display: tab === 'analytics' ? 'block' : 'none' }}>
          {loaded.current['analytics'] && <AnalyticsTab analytics={analytics} sla={sla} />}
        </div>
        <div style={{ display: tab === 'reports' ? 'block' : 'none' }}>
          {loaded.current['reports'] && <ReportsTab />}
        </div>
      </div>
    </RootLayout>
  );
}
