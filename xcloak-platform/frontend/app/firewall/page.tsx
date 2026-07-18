'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { firewallAPI, fweAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';

type Tab = 'dashboard' | 'policies' | 'rules' | 'nat' | 'zones' | 'threats' | 'connections' | 'blocked' | 'analytics' | 'approvals' | 'notifications' | 'audit' | 'reports';
const TABS: { id: Tab; label: string }[] = [
  { id: 'dashboard',     label: 'Dashboard' },
  { id: 'policies',      label: 'Policies' },
  { id: 'rules',         label: 'Firewall Rules' },
  { id: 'nat',           label: 'NAT' },
  { id: 'zones',         label: 'Zones' },
  { id: 'threats',       label: 'Threat Protection' },
  { id: 'connections',   label: 'Live Connections' },
  { id: 'blocked',       label: 'Blocked List' },
  { id: 'analytics',     label: 'Analytics' },
  { id: 'approvals',     label: 'Approvals' },
  { id: 'notifications', label: 'Notifications' },
  { id: 'audit',         label: 'Audit Trail' },
  { id: 'reports',       label: 'Reports' },
];

const ACTION_COLOR: Record<string, string> = {
  allow: '#22c55e', deny: '#ef4444', drop: '#ef4444', reject: '#f97316', log: '#3b82f6',
};
const SEVERITY_COLOR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#3b82f6',
};
const STATUS_COLOR: Record<string, string> = {
  active: '#22c55e', inactive: '#6b7280', pending: '#f97316', approved: '#22c55e', rejected: '#ef4444',
  established: '#22c55e', syn_sent: '#3b82f6', time_wait: '#6b7280',
};
const THREAT_TYPE_COLOR: Record<string, string> = {
  port_scan: '#f97316', brute_force: '#ef4444', ddos: '#ef4444', c2_traffic: '#a855f7',
  exploit: '#ef4444', malicious_ip: '#f97316', malicious_domain: '#f97316', threat_intel: '#eab308',
};
const AUDIT_COLOR: Record<string, string> = {
  rule_added: '#22c55e', rule_modified: '#eab308', rule_deleted: '#ef4444', policy_created: '#3b82f6',
  policy_modified: '#eab308', policy_deleted: '#ef4444', nat_created: '#3b82f6', nat_deleted: '#ef4444',
  zone_created: '#3b82f6', block_added: '#f97316', approval_requested: '#f97316',
  approval_approved: '#22c55e', approval_rejected: '#ef4444', report_generated: '#06b6d4',
};
const ZONE_COLORS: Record<string, string> = {
  lan: '#22c55e', wan: '#ef4444', dmz: '#f97316', vpn: '#a855f7',
  guest: '#eab308', server: '#3b82f6', cloud: '#06b6d4', custom: '#6b7280',
};
const NAT_TYPES = ['snat', 'dnat', 'port_forwarding', 'static_nat', 'dynamic_nat'];
const PROTOS = ['tcp', 'udp', 'icmp', 'any', 'esp', 'gre'];
const APPROVAL_POLICIES = ['internet_facing', 'production_firewall', 'default_policy', 'rule_deletion', 'high_risk'];

function pill(label: string, color: string) {
  return <span style={{ fontSize: 10, fontWeight: 600, padding: '2px 8px', borderRadius: 10, background: color + '22', color, border: `1px solid ${color}44`, textTransform: 'capitalize', whiteSpace: 'nowrap' }}>{label}</span>;
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
function bytes(n: number) {
  if (n > 1e9) return `${(n / 1e9).toFixed(1)} GB`;
  if (n > 1e6) return `${(n / 1e6).toFixed(1)} MB`;
  if (n > 1e3) return `${(n / 1e3).toFixed(1)} KB`;
  return `${n} B`;
}

// ── Dashboard ──────────────────────────────────────────────────────────────
function DashboardTab({ dash, onTabChange }: { dash: any; onTabChange: (t: Tab) => void }) {
  if (!dash) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Active Rules"      value={dash.active_rules}       color="var(--accent)" />
        <StatCard label="Total Rules"       value={dash.total_rules}        color="var(--text-2)" />
        <StatCard label="Threat Blocks"     value={dash.threat_blocks}      color="#ef4444" />
        <StatCard label="Blocks (24h)"      value={dash.threats_24h}        color="#f97316" sub="last 24 hours" />
        <StatCard label="Active Conns"      value={dash.active_connections} color="#3b82f6" />
        <StatCard label="Total Traffic"     value={bytes(dash.total_bytes || 0)} color="#a855f7" />
        <StatCard label="Policy Compliance" value={`${dash.policy_compliance}%`} color="#22c55e" />
        <StatCard label="Firewall Health"   value={dash.firewall_health}    color="#22c55e" />
      </div>

      {dash.pending_approvals > 0 && (
        <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #f97316', background: '#f9731608', cursor: 'pointer' }} onClick={() => onTabChange('approvals')}>
          <span style={{ fontWeight: 700, color: '#f97316' }}>⚠ {dash.pending_approvals} change{dash.pending_approvals !== 1 ? 's' : ''} pending approval.</span>
          <span style={{ fontSize: 13, color: 'var(--text-2)', marginLeft: 8 }}>Click to review.</span>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 13 }}>Threat Breakdown</div>
          {[
            ['Port Scans', dash.port_scan_blocks, '#f97316'],
            ['Brute Force', dash.brute_force_blocks, '#ef4444'],
            ['C2 Traffic', dash.c2_blocks, '#a855f7'],
          ].map(([label, val, color]: any) => (
            <div key={label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{label}</span>
              <span style={{ fontWeight: 700, color }}>{val}</span>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 13 }}>Top Source IPs (Blocked)</div>
          {(!dash.top_source_ips || dash.top_source_ips.length === 0) && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No data</div>}
          {(dash.top_source_ips || []).slice(0, 5).map((ip: any, i: number) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-2)' }}>{ip.ip}</span>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#ef4444' }}>{ip.count}</span>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 13 }}>Top Destination IPs</div>
          {(!dash.top_dest_ips || dash.top_dest_ips.length === 0) && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No data</div>}
          {(dash.top_dest_ips || []).slice(0, 5).map((ip: any, i: number) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-2)' }}>{ip.ip}</span>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#3b82f6' }}>{ip.count}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Policies ───────────────────────────────────────────────────────────────
function PoliciesTab({ policies, onRefresh }: { policies: any[]; onRefresh: () => void }) {
  const [showNew, setShowNew] = useState(false);
  const [form, setForm] = useState({ name: '', description: '', priority: 100, owner: '', tags: '' });
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState('');
  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(''), 3000); };

  const save = async () => {
    if (!form.name) return;
    setSaving(true);
    try {
      await fweAPI.createPolicy({ ...form, tags: form.tags ? JSON.stringify(form.tags.split(',').map((s: string) => s.trim())) : '[]' });
      onRefresh(); setShowNew(false); notify('Policy created');
    } catch { notify('Failed'); } finally { setSaving(false); }
  };
  const del = async (id: number, name: string) => {
    await fweAPI.deletePolicy(id); onRefresh(); notify(`Policy '${name}' deleted`);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {toast && <div className="g-card" style={{ padding: '8px 14px', borderLeft: '3px solid var(--accent)', fontSize: 13 }}>{toast}</div>}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontSize: 13, color: 'var(--text-3)' }}>{policies.length} policies</div>
        <button className="g-btn g-btn-primary" style={{ fontSize: 11 }} onClick={() => setShowNew(true)}>+ New Policy</button>
      </div>
      <div className="g-card" style={{ overflow: 'hidden' }}>
        <table className="g-table" style={{ width: '100%' }}>
          <thead className="g-thead">
            <tr>{['Policy ID', 'Name', 'Status', 'Priority', 'Rules', 'Owner', 'Version', 'Last Modified', ''].map(h => (
              <th key={h} className="g-tr" style={{ padding: '8px 12px', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
            ))}</tr>
          </thead>
          <tbody>
            {policies.length === 0 && <tr><td colSpan={9} style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)' }}>No policies</td></tr>}
            {policies.map(p => {
              let tags: string[] = [];
              try { tags = JSON.parse(p.tags || '[]'); } catch {}
              return (
                <tr key={p.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '10px 12px', fontSize: 10, fontFamily: 'monospace', color: 'var(--accent)' }}>{p.policy_id}</td>
                  <td style={{ padding: '10px 12px' }}>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>{p.name}</div>
                    {p.description && <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{p.description}</div>}
                    {tags.length > 0 && <div style={{ display: 'flex', gap: 3, marginTop: 3 }}>{tags.slice(0, 3).map((t: string) => <span key={t} style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3, background: 'var(--border)', color: 'var(--text-3)' }}>{t}</span>)}</div>}
                  </td>
                  <td style={{ padding: '10px 12px' }}>{pill(p.status || 'active', STATUS_COLOR[p.status] || '#22c55e')}</td>
                  <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-2)' }}>{p.priority}</td>
                  <td style={{ padding: '10px 12px', fontSize: 12, fontWeight: 700, color: 'var(--accent)' }}>{p.rule_count}</td>
                  <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-2)' }}>{p.owner || '—'}</td>
                  <td style={{ padding: '10px 12px', fontSize: 11, fontFamily: 'monospace', color: 'var(--text-3)' }}>v{p.version}</td>
                  <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(p.updated_at)}</td>
                  <td style={{ padding: '10px 12px' }}>
                    <button style={{ fontSize: 13, color: 'var(--text-3)' }} onClick={() => del(p.id, p.name)}>🗑</button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {showNew && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setShowNew(false)}>
          <div className="g-modal" style={{ maxWidth: 480 }}>
            <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between' }}>
              <div style={{ fontWeight: 700 }}>New Firewall Policy</div>
              <button onClick={() => setShowNew(false)} style={{ fontSize: 18, color: 'var(--text-3)' }}>×</button>
            </div>
            <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 12 }}>
              {[['Policy Name *', 'name', 'text', 'e.g. Internet Perimeter Policy'],
                ['Description', 'description', 'text', 'What this policy covers'],
                ['Owner', 'owner', 'text', 'network-team@corp.com'],
                ['Tags', 'tags', 'text', 'perimeter, internet, production']].map(([label, key, type, ph]) => (
                <div key={key}>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>{label}</label>
                  <input className="g-input w-full" type={type} placeholder={ph as string}
                    value={(form as any)[key]} onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))} />
                </div>
              ))}
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Priority</label>
                <input className="g-input w-full" type="number" value={form.priority} onChange={e => setForm(f => ({ ...f, priority: +e.target.value }))} />
              </div>
            </div>
            <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)', display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="g-btn g-btn-ghost" onClick={() => setShowNew(false)}>Cancel</button>
              <button className="g-btn g-btn-primary" onClick={save} disabled={saving || !form.name}>{saving ? 'Creating…' : 'Create Policy'}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Firewall Rules ─────────────────────────────────────────────────────────
function RulesTab({ rules, onRefresh }: { rules: any[]; onRefresh: () => void }) {
  const [search, setSearch] = useState('');
  const [filterAction, setFilterAction] = useState('');
  const [filterProto, setFilterProto] = useState('');
  const [filterDir, setFilterDir] = useState('');
  const [validating, setValidating] = useState(false);
  const [validation, setValidation] = useState<any>(null);
  const [deleting, setDeleting] = useState<number | null>(null);
  const [showNew, setShowNew] = useState(false);
  const [form, setForm] = useState({ name: '', description: '', source_ip: '', destination_ip: '', protocol: 'tcp', port_range: '', direction: 'in', action: 'allow', priority: 100, group_name: 'default', log_enabled: false, enabled: true, tags: '' });
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState('');
  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(''), 3000); };

  const filtered = useMemo(() => rules.filter(r => {
    if (filterAction && r.action !== filterAction) return false;
    if (filterProto && r.protocol !== filterProto) return false;
    if (filterDir && r.direction !== filterDir) return false;
    if (search) {
      const q = search.toLowerCase();
      return r.name.toLowerCase().includes(q) || (r.source_ip || '').includes(q) || (r.destination_ip || '').includes(q) || (r.port_range || '').includes(q);
    }
    return true;
  }), [rules, filterAction, filterProto, filterDir, search]);

  const validate = async () => {
    setValidating(true);
    try { const r = await fweAPI.validate(); setValidation(r.data); } catch {}
    finally { setValidating(false); }
  };
  const del = async (id: number) => {
    setDeleting(id);
    await firewallAPI.delete(id);
    onRefresh(); setDeleting(null); notify('Rule deleted');
  };
  const toggle = async (r: any) => {
    await firewallAPI.update(r.id, { ...r, enabled: !r.enabled });
    onRefresh();
  };
  const saveRule = async () => {
    if (!form.name) return;
    setSaving(true);
    try {
      await firewallAPI.create({ ...form, tags: form.tags ? form.tags.split(',').map((s: string) => s.trim()) : [] });
      onRefresh(); setShowNew(false); notify('Rule created');
    } catch { notify('Failed to create rule'); } finally { setSaving(false); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {toast && <div className="g-card" style={{ padding: '8px 14px', borderLeft: '3px solid var(--accent)', fontSize: 13 }}>{toast}</div>}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <input className="g-input" placeholder="Search rules…" value={search} onChange={e => setSearch(e.target.value)} style={{ fontSize: 12, width: 200 }} />
        <select className="g-select" value={filterAction} onChange={e => setFilterAction(e.target.value)} style={{ fontSize: 11 }}>
          <option value="">All Actions</option>
          {['allow','deny','drop','reject','log'].map(a => <option key={a} value={a}>{a}</option>)}
        </select>
        <select className="g-select" value={filterProto} onChange={e => setFilterProto(e.target.value)} style={{ fontSize: 11 }}>
          <option value="">All Protocols</option>
          {PROTOS.map(p => <option key={p} value={p}>{p}</option>)}
        </select>
        <select className="g-select" value={filterDir} onChange={e => setFilterDir(e.target.value)} style={{ fontSize: 11 }}>
          <option value="">All Directions</option>
          {['in','out','both'].map(d => <option key={d} value={d}>{d}</option>)}
        </select>
        <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={onRefresh}>↻</button>
        <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={validate} disabled={validating}>{validating ? 'Validating…' : '✓ Validate'}</button>
        <button className="g-btn g-btn-primary" style={{ fontSize: 11, marginLeft: 'auto' }} onClick={() => setShowNew(true)}>+ New Rule</button>
      </div>

      {validation && (
        <div className="g-card" style={{ padding: 14, borderLeft: `3px solid ${validation.issue_count > 0 ? '#f97316' : '#22c55e'}` }}>
          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 8 }}>
            Validation: {validation.issue_count} issue{validation.issue_count !== 1 ? 's' : ''} in {validation.total_rules} rules
          </div>
          {validation.issues?.slice(0, 5).map((issue: any, i: number) => (
            <div key={i} style={{ fontSize: 12, color: 'var(--text-2)', padding: '4px 0' }}>
              <span style={{ color: '#f97316', marginRight: 6 }}>⚠</span>
              <strong>{issue.name}</strong>: {issue.message}
            </div>
          ))}
          <button style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 6 }} onClick={() => setValidation(null)}>Dismiss</button>
        </div>
      )}

      <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{filtered.length} of {rules.length} rules</div>
      <div className="g-card" style={{ overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table className="g-table" style={{ width: '100%' }}>
            <thead className="g-thead">
              <tr>{['#', 'Name', 'Action', 'Source', 'Destination', 'Protocol', 'Port(s)', 'Direction', 'Group', 'Log', 'Status', ''].map(h => (
                <th key={h} className="g-tr" style={{ padding: '8px 12px', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
              ))}</tr>
            </thead>
            <tbody>
              {filtered.length === 0 && <tr><td colSpan={12} style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)' }}>No rules found</td></tr>}
              {filtered.map(r => (
                <tr key={r.id} style={{ borderBottom: '1px solid var(--border)', opacity: r.enabled ? 1 : 0.55 }}>
                  <td style={{ padding: '10px 12px', fontSize: 11, fontWeight: 600, color: 'var(--text-3)' }}>{r.priority}</td>
                  <td style={{ padding: '10px 12px', maxWidth: 200 }}>
                    <div style={{ fontWeight: 600, fontSize: 12 }}>{r.name}</div>
                    {r.description && <div style={{ fontSize: 10, color: 'var(--text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 180 }}>{r.description}</div>}
                  </td>
                  <td style={{ padding: '10px 12px' }}>{pill(r.action, ACTION_COLOR[r.action] || '#6b7280')}</td>
                  <td style={{ padding: '10px 12px', fontSize: 11, fontFamily: 'monospace', color: 'var(--text-2)' }}>{r.source_ip || 'any'}</td>
                  <td style={{ padding: '10px 12px', fontSize: 11, fontFamily: 'monospace', color: 'var(--text-2)' }}>{r.destination_ip || 'any'}</td>
                  <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-2)', textTransform: 'uppercase' }}>{r.protocol}</td>
                  <td style={{ padding: '10px 12px', fontSize: 11, fontFamily: 'monospace', color: 'var(--text-3)' }}>{r.port_range || r.port || '—'}</td>
                  <td style={{ padding: '10px 12px' }}>
                    <span style={{ fontSize: 9, fontWeight: 700, padding: '2px 6px', borderRadius: 8, textTransform: 'uppercase',
                      background: r.direction === 'in' ? '#3b82f622' : r.direction === 'out' ? '#a855f722' : 'var(--border)',
                      color: r.direction === 'in' ? '#3b82f6' : r.direction === 'out' ? '#a855f7' : 'var(--text-3)',
                    }}>{r.direction || 'both'}</span>
                  </td>
                  <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)' }}>{r.group_name || '—'}</td>
                  <td style={{ padding: '10px 12px', fontSize: 11 }}>{r.log_enabled ? <span style={{ color: '#22c55e' }}>✓</span> : <span style={{ color: 'var(--text-3)' }}>—</span>}</td>
                  <td style={{ padding: '10px 12px' }}>{pill(r.enabled ? 'enabled' : 'disabled', r.enabled ? '#22c55e' : '#6b7280')}</td>
                  <td style={{ padding: '10px 12px' }}>
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                      <button className="g-btn g-btn-ghost" style={{ fontSize: 10, padding: '2px 8px' }} onClick={() => toggle(r)}>{r.enabled ? 'Disable' : 'Enable'}</button>
                      <button style={{ fontSize: 13, color: 'var(--text-3)' }} onClick={() => del(r.id)} disabled={deleting === r.id}>🗑</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {showNew && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setShowNew(false)}>
          <div className="g-modal" style={{ maxWidth: 560 }}>
            <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between' }}>
              <div style={{ fontWeight: 700 }}>New Firewall Rule</div>
              <button onClick={() => setShowNew(false)} style={{ fontSize: 18, color: 'var(--text-3)' }}>×</button>
            </div>
            <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 12, maxHeight: '70vh', overflow: 'auto' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                {[['Rule Name *', 'name', 'text'], ['Group', 'group_name', 'text'], ['Source IP/CIDR', 'source_ip', 'text'], ['Destination IP/CIDR', 'destination_ip', 'text'], ['Port / Range', 'port_range', 'text'], ['Tags', 'tags', 'text']].map(([label, key, type]) => (
                  <div key={key}>
                    <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>{label}</label>
                    <input className="g-input w-full" type={type} value={(form as any)[key]} onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))} />
                  </div>
                ))}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Action</label>
                  <select className="g-select w-full" value={form.action} onChange={e => setForm(f => ({ ...f, action: e.target.value }))}>
                    {['allow','deny','drop','reject','log'].map(a => <option key={a} value={a}>{a}</option>)}
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Protocol</label>
                  <select className="g-select w-full" value={form.protocol} onChange={e => setForm(f => ({ ...f, protocol: e.target.value }))}>
                    {PROTOS.map(p => <option key={p} value={p}>{p}</option>)}
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Direction</label>
                  <select className="g-select w-full" value={form.direction} onChange={e => setForm(f => ({ ...f, direction: e.target.value }))}>
                    {['in','out','both'].map(d => <option key={d} value={d}>{d}</option>)}
                  </select>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: 'pointer' }}>
                  <input type="checkbox" checked={form.log_enabled} onChange={e => setForm(f => ({ ...f, log_enabled: e.target.checked }))} />
                  Enable Logging
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: 'pointer' }}>
                  <input type="checkbox" checked={form.enabled} onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))} />
                  Enabled
                </label>
              </div>
            </div>
            <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)', display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="g-btn g-btn-ghost" onClick={() => setShowNew(false)}>Cancel</button>
              <button className="g-btn g-btn-primary" onClick={saveRule} disabled={saving || !form.name}>{saving ? 'Creating…' : 'Create Rule'}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── NAT ────────────────────────────────────────────────────────────────────
function NATTab({ items, onRefresh }: { items: any[]; onRefresh: () => void }) {
  const [showNew, setShowNew] = useState(false);
  const [form, setForm] = useState({ name: '', nat_type: 'snat', src_ip: '', dst_ip: '', translated_ip: '', src_port: '', dst_port: '', translated_port: '', protocol: 'tcp', interface: '' });
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState('');
  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(''), 3000); };
  const NAT_COLOR: Record<string, string> = { snat: '#3b82f6', dnat: '#a855f7', port_forwarding: '#f97316', static_nat: '#22c55e', dynamic_nat: '#eab308' };

  const save = async () => {
    if (!form.name) return;
    setSaving(true);
    try { await fweAPI.createNAT(form); onRefresh(); setShowNew(false); notify('NAT rule created'); }
    catch { notify('Failed'); } finally { setSaving(false); }
  };
  const del = async (id: number) => { await fweAPI.deleteNAT(id); onRefresh(); notify('NAT rule deleted'); };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {toast && <div className="g-card" style={{ padding: '8px 14px', borderLeft: '3px solid var(--accent)', fontSize: 13 }}>{toast}</div>}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontSize: 13, color: 'var(--text-3)' }}>{items.length} NAT rules</div>
        <button className="g-btn g-btn-primary" style={{ fontSize: 11 }} onClick={() => setShowNew(true)}>+ New NAT Rule</button>
      </div>
      <div className="g-card" style={{ overflow: 'hidden' }}>
        <table className="g-table" style={{ width: '100%' }}>
          <thead className="g-thead">
            <tr>{['NAT ID', 'Name', 'Type', 'Source', 'Destination', 'Translated IP', 'Protocol', 'Hits', 'Status', ''].map(h => (
              <th key={h} className="g-tr" style={{ padding: '8px 12px', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
            ))}</tr>
          </thead>
          <tbody>
            {items.length === 0 && <tr><td colSpan={10} style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)' }}>No NAT rules</td></tr>}
            {items.map(n => (
              <tr key={n.id} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '10px 12px', fontSize: 10, fontFamily: 'monospace', color: 'var(--accent)' }}>{n.nat_id}</td>
                <td style={{ padding: '10px 12px', fontWeight: 600, fontSize: 12 }}>{n.name}</td>
                <td style={{ padding: '10px 12px' }}>{pill((n.nat_type || '').replace(/_/g, ' '), NAT_COLOR[n.nat_type] || '#6b7280')}</td>
                <td style={{ padding: '10px 12px', fontSize: 11, fontFamily: 'monospace', color: 'var(--text-2)' }}>{n.src_ip || 'any'}{n.src_port ? `:${n.src_port}` : ''}</td>
                <td style={{ padding: '10px 12px', fontSize: 11, fontFamily: 'monospace', color: 'var(--text-2)' }}>{n.dst_ip || 'any'}{n.dst_port ? `:${n.dst_port}` : ''}</td>
                <td style={{ padding: '10px 12px', fontSize: 11, fontFamily: 'monospace', color: 'var(--accent)' }}>{n.translated_ip || '—'}{n.translated_port ? `:${n.translated_port}` : ''}</td>
                <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-2)', textTransform: 'uppercase' }}>{n.protocol}</td>
                <td style={{ padding: '10px 12px', fontSize: 12, fontWeight: 700, color: 'var(--accent)' }}>{(n.hit_count || 0).toLocaleString()}</td>
                <td style={{ padding: '10px 12px' }}>{pill(n.enabled ? 'enabled' : 'disabled', n.enabled ? '#22c55e' : '#6b7280')}</td>
                <td style={{ padding: '10px 12px' }}><button style={{ fontSize: 13, color: 'var(--text-3)' }} onClick={() => del(n.id)}>🗑</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {showNew && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setShowNew(false)}>
          <div className="g-modal" style={{ maxWidth: 560 }}>
            <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between' }}>
              <div style={{ fontWeight: 700 }}>New NAT Rule</div>
              <button onClick={() => setShowNew(false)} style={{ fontSize: 18, color: 'var(--text-3)' }}>×</button>
            </div>
            <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Name *</label>
                  <input className="g-input w-full" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g. Web Server DNAT" />
                </div>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>NAT Type</label>
                  <select className="g-select w-full" value={form.nat_type} onChange={e => setForm(f => ({ ...f, nat_type: e.target.value }))}>
                    {NAT_TYPES.map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
                  </select>
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
                {[['Source IP', 'src_ip'], ['Source Port', 'src_port'], ['Destination IP', 'dst_ip'],
                  ['Destination Port', 'dst_port'], ['Translated IP', 'translated_ip'], ['Translated Port', 'translated_port']].map(([label, key]) => (
                  <div key={key}>
                    <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>{label}</label>
                    <input className="g-input w-full" value={(form as any)[key]} onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))} placeholder={label.includes('IP') ? '10.0.0.1' : '80'} />
                  </div>
                ))}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Protocol</label>
                  <select className="g-select w-full" value={form.protocol} onChange={e => setForm(f => ({ ...f, protocol: e.target.value }))}>
                    {PROTOS.map(p => <option key={p} value={p}>{p}</option>)}
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Interface</label>
                  <input className="g-input w-full" value={form.interface} onChange={e => setForm(f => ({ ...f, interface: e.target.value }))} placeholder="eth0" />
                </div>
              </div>
            </div>
            <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)', display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="g-btn g-btn-ghost" onClick={() => setShowNew(false)}>Cancel</button>
              <button className="g-btn g-btn-primary" onClick={save} disabled={saving || !form.name}>{saving ? 'Creating…' : 'Create NAT Rule'}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Zones ──────────────────────────────────────────────────────────────────
function ZonesTab({ zones, onRefresh }: { zones: any[]; onRefresh: () => void }) {
  const [showNew, setShowNew] = useState(false);
  const [form, setForm] = useState({ name: '', zone_type: 'custom', description: '', cidr_ranges: '', trust_level: 'medium' });
  const [saving, setSaving] = useState(false);
  const TRUST_COLOR: Record<string, string> = { high: '#22c55e', medium: '#eab308', low: '#f97316', untrusted: '#ef4444' };
  const ZONE_TYPES = ['lan', 'wan', 'dmz', 'vpn', 'guest', 'server', 'cloud', 'custom'];

  const save = async () => {
    if (!form.name) return;
    setSaving(true);
    try { await fweAPI.createZone({ ...form, cidr_ranges: JSON.stringify(form.cidr_ranges.split(',').map((s: string) => s.trim()).filter(Boolean)) }); onRefresh(); setShowNew(false); }
    catch {} finally { setSaving(false); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontSize: 13, color: 'var(--text-3)' }}>{zones.length} zones</div>
        <button className="g-btn g-btn-primary" style={{ fontSize: 11 }} onClick={() => setShowNew(true)}>+ New Zone</button>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 14 }}>
        {zones.map(z => {
          const color = ZONE_COLORS[z.zone_type] || '#6b7280';
          let cidrs: string[] = [];
          try { cidrs = JSON.parse(z.cidr_ranges || '[]'); } catch {}
          return (
            <div key={z.id} className="g-card" style={{ padding: 16, borderLeft: `3px solid ${color}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                <div>
                  <div style={{ fontWeight: 700, fontSize: 14 }}>{z.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase' }}>{z.zone_type}</div>
                </div>
                <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 8, background: TRUST_COLOR[z.trust_level] + '22', color: TRUST_COLOR[z.trust_level] || '#6b7280', border: `1px solid ${TRUST_COLOR[z.trust_level]}44`, textTransform: 'capitalize' }}>{z.trust_level}</span>
              </div>
              {z.description && <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 8 }}>{z.description}</div>}
              {cidrs.length > 0 && (
                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                  {cidrs.map((c: string) => <span key={c} style={{ fontSize: 10, fontFamily: 'monospace', padding: '2px 6px', borderRadius: 4, background: 'var(--border)', color: 'var(--text-2)' }}>{c}</span>)}
                </div>
              )}
            </div>
          );
        })}
      </div>
      {showNew && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setShowNew(false)}>
          <div className="g-modal" style={{ maxWidth: 460 }}>
            <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between' }}>
              <div style={{ fontWeight: 700 }}>New Network Zone</div>
              <button onClick={() => setShowNew(false)} style={{ fontSize: 18, color: 'var(--text-3)' }}>×</button>
            </div>
            <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Zone Name *</label>
                <input className="g-input w-full" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g. Production DMZ" />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Zone Type</label>
                  <select className="g-select w-full" value={form.zone_type} onChange={e => setForm(f => ({ ...f, zone_type: e.target.value }))}>
                    {ZONE_TYPES.map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Trust Level</label>
                  <select className="g-select w-full" value={form.trust_level} onChange={e => setForm(f => ({ ...f, trust_level: e.target.value }))}>
                    {['high','medium','low','untrusted'].map(t => <option key={t} value={t}>{t}</option>)}
                  </select>
                </div>
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>CIDR Ranges (comma-separated)</label>
                <input className="g-input w-full" value={form.cidr_ranges} onChange={e => setForm(f => ({ ...f, cidr_ranges: e.target.value }))} placeholder="10.0.1.0/24, 10.0.2.0/24" />
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Description</label>
                <input className="g-input w-full" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
              </div>
            </div>
            <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)', display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="g-btn g-btn-ghost" onClick={() => setShowNew(false)}>Cancel</button>
              <button className="g-btn g-btn-primary" onClick={save} disabled={saving || !form.name}>{saving ? 'Creating…' : 'Create Zone'}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Threat Protection ──────────────────────────────────────────────────────
function ThreatsTab({ threats }: { threats: any[] }) {
  const [filterType, setFilterType] = useState('');
  const [filterSev, setFilterSev] = useState('');
  const THREAT_LABELS: Record<string, string> = {
    port_scan: '🔍 Port Scan', brute_force: '🔨 Brute Force', ddos: '💀 DDoS',
    c2_traffic: '☠ C2 Traffic', exploit: '💥 Exploit', malicious_ip: '🚫 Malicious IP',
    malicious_domain: '🌐 Bad Domain', threat_intel: '🎯 Threat Intel',
  };
  const filtered = useMemo(() => threats.filter(t => {
    if (filterType && t.threat_type !== filterType) return false;
    if (filterSev && t.severity !== filterSev) return false;
    return true;
  }), [threats, filterType, filterSev]);

  const types = [...new Set(threats.map(t => t.threat_type))];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <select className="g-select" value={filterType} onChange={e => setFilterType(e.target.value)} style={{ fontSize: 11 }}>
          <option value="">All Types</option>
          {types.map(t => <option key={t} value={t}>{(THREAT_LABELS[t] || t).replace(/[^a-zA-Z ]/g, '').trim()}</option>)}
        </select>
        <select className="g-select" value={filterSev} onChange={e => setFilterSev(e.target.value)} style={{ fontSize: 11 }}>
          <option value="">All Severities</option>
          {['critical','high','medium','low'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <span style={{ fontSize: 11, color: 'var(--text-3)', marginLeft: 'auto' }}>{filtered.length} events</span>
      </div>
      <div className="g-card" style={{ overflow: 'hidden' }}>
        <table className="g-table" style={{ width: '100%' }}>
          <thead className="g-thead">
            <tr>{['Time', 'Type', 'Source IP', 'Dest IP', 'Port', 'Protocol', 'Country', 'Action', 'Severity', 'Confidence', 'Rule'].map(h => (
              <th key={h} className="g-tr" style={{ padding: '8px 12px', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
            ))}</tr>
          </thead>
          <tbody>
            {filtered.length === 0 && <tr><td colSpan={11} style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)' }}>No threats</td></tr>}
            {filtered.map(t => (
              <tr key={t.id} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '8px 12px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(t.created_at)}</td>
                <td style={{ padding: '8px 12px' }}><span style={{ fontSize: 11, fontWeight: 600, color: THREAT_TYPE_COLOR[t.threat_type] || '#6b7280' }}>{THREAT_LABELS[t.threat_type] || t.threat_type}</span></td>
                <td style={{ padding: '8px 12px', fontSize: 11, fontFamily: 'monospace', color: 'var(--text-2)' }}>{t.src_ip || '—'}</td>
                <td style={{ padding: '8px 12px', fontSize: 11, fontFamily: 'monospace', color: 'var(--text-2)' }}>{t.dst_ip || '—'}</td>
                <td style={{ padding: '8px 12px', fontSize: 11, fontFamily: 'monospace', color: 'var(--text-3)' }}>{t.dst_port || '—'}</td>
                <td style={{ padding: '8px 12px', fontSize: 11, color: 'var(--text-2)', textTransform: 'uppercase' }}>{t.protocol || '—'}</td>
                <td style={{ padding: '8px 12px', fontSize: 11, color: 'var(--text-3)' }}>{t.country || '—'}</td>
                <td style={{ padding: '8px 12px' }}>{pill(t.action_taken, t.action_taken === 'blocked' ? '#ef4444' : '#22c55e')}</td>
                <td style={{ padding: '8px 12px' }}>{pill(t.severity, SEVERITY_COLOR[t.severity] || '#6b7280')}</td>
                <td style={{ padding: '8px 12px', fontSize: 11, color: 'var(--text-2)' }}>{t.confidence}%</td>
                <td style={{ padding: '8px 12px', fontSize: 10, fontFamily: 'monospace', color: 'var(--text-3)' }}>{t.rule_triggered || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Live Connections ───────────────────────────────────────────────────────
function ConnectionsTab({ conns }: { conns: any[] }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontSize: 13, color: 'var(--text-3)' }}>{conns.length} connections</div>
        <span style={{ fontSize: 11, padding: '3px 10px', borderRadius: 8, background: '#22c55e22', color: '#22c55e', border: '1px solid #22c55e44' }}>● Live</span>
      </div>
      <div className="g-card" style={{ overflow: 'hidden' }}>
        <table className="g-table" style={{ width: '100%' }}>
          <thead className="g-thead">
            <tr>{['Source', 'Destination', 'Protocol', 'Application', 'State', 'Duration', 'Bytes In', 'Bytes Out', 'Zone Src', 'Zone Dst', 'Rule'].map(h => (
              <th key={h} className="g-tr" style={{ padding: '8px 12px', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
            ))}</tr>
          </thead>
          <tbody>
            {conns.length === 0 && <tr><td colSpan={11} style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)' }}>No active connections</td></tr>}
            {conns.map(c => (
              <tr key={c.id} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '8px 12px', fontSize: 11, fontFamily: 'monospace', color: 'var(--text-2)' }}>{c.src_ip}:{c.src_port}</td>
                <td style={{ padding: '8px 12px', fontSize: 11, fontFamily: 'monospace', color: 'var(--text-2)' }}>{c.dst_ip}:{c.dst_port}</td>
                <td style={{ padding: '8px 12px', fontSize: 11, textTransform: 'uppercase', color: 'var(--text-3)' }}>{c.protocol}</td>
                <td style={{ padding: '8px 12px', fontSize: 11, color: 'var(--accent)' }}>{c.application || '—'}</td>
                <td style={{ padding: '8px 12px' }}>{pill(c.state, STATUS_COLOR[c.state] || '#6b7280')}</td>
                <td style={{ padding: '8px 12px', fontSize: 11, color: 'var(--text-3)' }}>{c.duration ? `${c.duration}s` : '—'}</td>
                <td style={{ padding: '8px 12px', fontSize: 11, color: 'var(--text-2)' }}>{bytes(c.bytes_recv || 0)}</td>
                <td style={{ padding: '8px 12px', fontSize: 11, color: 'var(--text-2)' }}>{bytes(c.bytes_sent || 0)}</td>
                <td style={{ padding: '8px 12px', fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase' }}>{c.zone_src || '—'}</td>
                <td style={{ padding: '8px 12px', fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase' }}>{c.zone_dst || '—'}</td>
                <td style={{ padding: '8px 12px', fontSize: 10, fontFamily: 'monospace', color: 'var(--text-3)' }}>{c.rule_id || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Blocked List ───────────────────────────────────────────────────────────
function BlockedTab({ items, onRefresh }: { items: any[]; onRefresh: () => void }) {
  const [showNew, setShowNew] = useState(false);
  const [form, setForm] = useState({ block_type: 'ip', value: '', reason: '', expires_in_hours: 0 });
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState('');
  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(''), 3000); };
  const BLOCK_COLOR: Record<string, string> = { ip: '#ef4444', domain: '#f97316', country: '#a855f7', application: '#eab308' };

  const save = async () => {
    if (!form.value) return;
    setSaving(true);
    try { await fweAPI.block(form); onRefresh(); setShowNew(false); notify(`${form.block_type} blocked`); }
    catch { notify('Failed'); } finally { setSaving(false); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {toast && <div className="g-card" style={{ padding: '8px 14px', borderLeft: '3px solid #ef4444', fontSize: 13 }}>{toast}</div>}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontSize: 13, color: 'var(--text-3)' }}>{items.length} active blocks</div>
        <button className="g-btn g-btn-primary" style={{ fontSize: 11, background: '#ef4444', border: '1px solid #dc2626' }} onClick={() => setShowNew(true)}>🚫 Block</button>
      </div>
      <div className="g-card" style={{ overflow: 'hidden' }}>
        <table className="g-table" style={{ width: '100%' }}>
          <thead className="g-thead">
            <tr>{['Type', 'Value', 'Reason', 'Blocked By', 'Expires', 'Added'].map(h => (
              <th key={h} className="g-tr" style={{ padding: '8px 12px', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
            ))}</tr>
          </thead>
          <tbody>
            {items.length === 0 && <tr><td colSpan={6} style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)' }}>No blocks</td></tr>}
            {items.map(b => (
              <tr key={b.id} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '10px 12px' }}>{pill(b.block_type, BLOCK_COLOR[b.block_type] || '#6b7280')}</td>
                <td style={{ padding: '10px 12px', fontSize: 12, fontFamily: 'monospace', fontWeight: 600, color: 'var(--text-1)' }}>{b.value}</td>
                <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-3)', fontStyle: 'italic' }}>{b.reason || '—'}</td>
                <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-2)' }}>{b.blocked_by}</td>
                <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)' }}>{b.expires_at ? timeAgo(b.expires_at) : 'Never'}</td>
                <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(b.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {showNew && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setShowNew(false)}>
          <div className="g-modal" style={{ maxWidth: 420 }}>
            <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between' }}>
              <div style={{ fontWeight: 700 }}>Block IP / Domain / Country</div>
              <button onClick={() => setShowNew(false)} style={{ fontSize: 18, color: 'var(--text-3)' }}>×</button>
            </div>
            <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Block Type</label>
                <div style={{ display: 'flex', gap: 6 }}>
                  {['ip','domain','country','application'].map(t => (
                    <button key={t} type="button" onClick={() => setForm(f => ({ ...f, block_type: t }))} style={{ fontSize: 11, padding: '4px 12px', borderRadius: 8, background: form.block_type === t ? BLOCK_COLOR[t] + '22' : 'var(--glass-bg)', border: `1px solid ${form.block_type === t ? BLOCK_COLOR[t] : 'var(--border)'}`, color: form.block_type === t ? BLOCK_COLOR[t] : 'var(--text-2)' }}>
                      {t}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Value *</label>
                <input className="g-input w-full" value={form.value} onChange={e => setForm(f => ({ ...f, value: e.target.value }))} placeholder={form.block_type === 'ip' ? '203.0.113.0/24' : form.block_type === 'domain' ? 'evil.example.com' : form.block_type === 'country' ? 'CN' : 'BitTorrent'} />
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Reason</label>
                <input className="g-input w-full" value={form.reason} onChange={e => setForm(f => ({ ...f, reason: e.target.value }))} placeholder="Threat intel match" />
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Expires in (hours, 0 = never)</label>
                <input className="g-input w-full" type="number" value={form.expires_in_hours} onChange={e => setForm(f => ({ ...f, expires_in_hours: +e.target.value }))} />
              </div>
            </div>
            <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)', display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="g-btn g-btn-ghost" onClick={() => setShowNew(false)}>Cancel</button>
              <button className="g-btn g-btn-primary" onClick={save} disabled={saving || !form.value} style={{ background: '#ef4444', border: '1px solid #dc2626' }}>{saving ? 'Blocking…' : '🚫 Block'}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Analytics ──────────────────────────────────────────────────────────────
function AnalyticsTab({ data }: { data: any }) {
  if (!data) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>No analytics data</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total Threats"   value={data.total_threats}  color="#ef4444" />
        <StatCard label="Threats (24h)"   value={data.threats_24h}    color="#f97316" sub="last 24 hours" />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 13 }}>Threats by Type</div>
          {(!data.by_threat_type || data.by_threat_type.length === 0) && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No data</div>}
          {(data.by_threat_type || []).map((t: any) => (
            <div key={t.threat_type} style={{ marginBottom: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 3 }}>
                <span style={{ color: 'var(--text-2)', textTransform: 'capitalize' }}>{(t.threat_type || '').replace(/_/g, ' ')}</span>
                <span style={{ fontWeight: 700, color: THREAT_TYPE_COLOR[t.threat_type] || '#6b7280' }}>{t.count}</span>
              </div>
              <div style={{ background: 'var(--border)', borderRadius: 3, height: 4 }}>
                <div style={{ background: THREAT_TYPE_COLOR[t.threat_type] || '#6b7280', borderRadius: 3, height: 4, width: `${Math.min(100, (t.count / Math.max(...(data.by_threat_type || []).map((x: any) => x.count))) * 100)}%` }} />
              </div>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 13 }}>Traffic by Protocol</div>
          {(!data.by_protocol || data.by_protocol.length === 0) && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No data</div>}
          {(data.by_protocol || []).map((p: any, i: number) => (
            <div key={p.protocol} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontSize: 12, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-2)' }}>{p.protocol}</span>
              <span style={{ fontWeight: 700, color: 'var(--accent)' }}>{p.count.toLocaleString()}</span>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 13 }}>Top Blocked IPs</div>
          {(!data.top_blocked_ips || data.top_blocked_ips.length === 0) && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No data</div>}
          {(data.top_blocked_ips || []).slice(0, 8).map((ip: any, i: number) => (
            <div key={ip.ip} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-2)' }}>
                <span style={{ fontSize: 10, color: 'var(--text-3)', marginRight: 6 }}>#{i + 1}</span>{ip.ip}
              </span>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#ef4444' }}>{ip.count}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Approvals ──────────────────────────────────────────────────────────────
function ApprovalsTab({ approvals, onRefresh }: { approvals: any[]; onRefresh: () => void }) {
  const [deciding, setDeciding] = useState<number | null>(null);
  const [note, setNote] = useState('');
  const [showNew, setShowNew] = useState(false);
  const [form, setForm] = useState({ change_type: 'internet_facing', description: '', priority: 'high', policy: '' });
  const [toast, setToast] = useState('');
  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(''), 3000); };

  const decide = async (id: number, decision: string) => {
    setDeciding(id);
    try { await fweAPI.decideApproval(id, { decision, note }); onRefresh(); notify(`${decision}`); }
    catch { notify('Failed'); } finally { setDeciding(null); setNote(''); }
  };
  const submit = async () => {
    try { await fweAPI.createApproval(form); onRefresh(); setShowNew(false); notify('Approval request submitted'); }
    catch { notify('Failed'); }
  };

  const pending = approvals.filter(a => a.status === 'pending');
  const past = approvals.filter(a => a.status !== 'pending');
  const CHANGE_LABELS: Record<string, string> = {
    internet_facing: 'Internet-Facing Rule', production_firewall: 'Production Firewall', default_policy: 'Default Policy', rule_deletion: 'Rule Deletion', high_risk: 'High-Risk Config',
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {toast && <div className="g-card" style={{ padding: '8px 14px', borderLeft: '3px solid var(--accent)', fontSize: 13 }}>{toast}</div>}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontWeight: 600 }}>Pending ({pending.length})</div>
        <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={() => setShowNew(true)}>+ Request Approval</button>
      </div>
      {pending.length === 0 && <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-3)', fontSize: 13 }}>No pending approvals</div>}
      {pending.map(a => (
        <div key={a.id} className="g-card" style={{ padding: 16, borderLeft: '3px solid #f97316' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
            <div>
              <div style={{ fontWeight: 600, fontSize: 13 }}>{a.description}</div>
              <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>
                {CHANGE_LABELS[a.change_type] || a.change_type} · Requested by <strong>{a.requester}</strong> · {timeAgo(a.created_at)}
              </div>
            </div>
            {pill(a.priority, SEVERITY_COLOR[a.priority] || '#6b7280')}
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <input className="g-input" placeholder="Decision note…" value={deciding === a.id ? note : ''} onChange={e => setNote(e.target.value)} style={{ fontSize: 11, flex: 1 }} />
            <button className="g-btn" style={{ fontSize: 11, background: '#22c55e22', color: '#22c55e', border: '1px solid #22c55e44' }} onClick={() => decide(a.id, 'approved')} disabled={deciding === a.id}>✓ Approve</button>
            <button className="g-btn g-btn-ghost" style={{ fontSize: 11, color: '#ef4444' }} onClick={() => decide(a.id, 'rejected')} disabled={deciding === a.id}>✗ Reject</button>
          </div>
        </div>
      ))}
      {past.length > 0 && (
        <div>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Past Decisions</div>
          <div className="g-card" style={{ overflow: 'hidden' }}>
            <table className="g-table" style={{ width: '100%' }}>
              <thead className="g-thead">
                <tr>{['Change', 'Type', 'Requester', 'Approver', 'Decision', 'Date'].map(h => (
                  <th key={h} className="g-tr" style={{ padding: '8px 12px', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left' }}>{h}</th>
                ))}</tr>
              </thead>
              <tbody>
                {past.map(a => (
                  <tr key={a.id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '10px 12px', fontSize: 12, fontWeight: 500, maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.description}</td>
                    <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)' }}>{CHANGE_LABELS[a.change_type] || a.change_type}</td>
                    <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-2)' }}>{a.requester}</td>
                    <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-2)' }}>{a.approver || '—'}</td>
                    <td style={{ padding: '10px 12px' }}>{pill(a.status, STATUS_COLOR[a.status] || '#6b7280')}</td>
                    <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{a.decided_at ? timeAgo(a.decided_at) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {showNew && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setShowNew(false)}>
          <div className="g-modal" style={{ maxWidth: 460 }}>
            <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between' }}>
              <div style={{ fontWeight: 700 }}>Request Approval</div>
              <button onClick={() => setShowNew(false)} style={{ fontSize: 18, color: 'var(--text-3)' }}>×</button>
            </div>
            <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Change Type</label>
                <select className="g-select w-full" value={form.change_type} onChange={e => setForm(f => ({ ...f, change_type: e.target.value }))}>
                  {APPROVAL_POLICIES.map(p => <option key={p} value={p}>{CHANGE_LABELS[p] || p}</option>)}
                </select>
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Description *</label>
                <textarea className="g-input w-full" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} placeholder="Describe the change you need approval for…" style={{ minHeight: 70, resize: 'vertical' }} />
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Priority</label>
                <select className="g-select w-full" value={form.priority} onChange={e => setForm(f => ({ ...f, priority: e.target.value }))}>
                  {['critical','high','medium','low'].map(p => <option key={p} value={p}>{p}</option>)}
                </select>
              </div>
            </div>
            <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)', display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="g-btn g-btn-ghost" onClick={() => setShowNew(false)}>Cancel</button>
              <button className="g-btn g-btn-primary" onClick={submit} disabled={!form.description}>Submit Request</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Notifications ──────────────────────────────────────────────────────────
function NotificationsTab({ items, onMarkRead }: { items: any[]; onMarkRead: () => void }) {
  const EVENT_ICON: Record<string, string> = {
    rule_added: '➕', rule_modified: '✏', rule_deleted: '🗑', threat_blocked: '🛡',
    firewall_offline: '⚠', config_changed: '⚙', approval_required: '🔔', block_added: '🚫', high_hit_count: '📈',
  };
  const unread = items.filter(n => !n.read).length;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontWeight: 600 }}>Notifications {unread > 0 && <span style={{ fontSize: 11, background: '#3b82f622', color: '#3b82f6', borderRadius: 10, padding: '1px 8px', marginLeft: 6 }}>{unread} unread</span>}</div>
        {unread > 0 && <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={onMarkRead}>Mark all read</button>}
      </div>
      {items.length === 0 && <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>No notifications</div>}
      {items.map(n => (
        <div key={n.id} className="g-card" style={{ padding: '12px 16px', display: 'flex', gap: 12, alignItems: 'flex-start', opacity: n.read ? 0.6 : 1, borderLeft: `3px solid ${SEVERITY_COLOR[n.severity] || '#6b7280'}` }}>
          <div style={{ fontSize: 18, width: 24, textAlign: 'center', flexShrink: 0 }}>{EVENT_ICON[n.event_type] || '•'}</div>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 13, fontWeight: n.read ? 400 : 600 }}>{n.title}</div>
            <div style={{ fontSize: 12, color: 'var(--text-2)', marginTop: 2 }}>{n.message}</div>
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 3 }}>
              {n.src_ip && <span style={{ fontFamily: 'monospace', marginRight: 8 }}>{n.src_ip}</span>}
              {timeAgo(n.created_at)}
            </div>
          </div>
          {pill(n.severity, SEVERITY_COLOR[n.severity] || '#6b7280')}
        </div>
      ))}
    </div>
  );
}

// ── Audit Trail ────────────────────────────────────────────────────────────
function AuditTab({ items }: { items: any[] }) {
  return (
    <div className="g-card" style={{ overflow: 'hidden' }}>
      <table className="g-table" style={{ width: '100%' }}>
        <thead className="g-thead">
          <tr>{['Time', 'Action', 'Object Type', 'Object Name', 'Actor', 'Details'].map(h => (
            <th key={h} className="g-tr" style={{ padding: '8px 12px', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
          ))}</tr>
        </thead>
        <tbody>
          {items.length === 0 && <tr><td colSpan={6} style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)' }}>No audit events</td></tr>}
          {items.map(a => (
            <tr key={a.id} style={{ borderBottom: '1px solid var(--border)' }}>
              <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(a.created_at)}</td>
              <td style={{ padding: '10px 12px' }}>{pill(a.action, AUDIT_COLOR[a.action] || '#6b7280')}</td>
              <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', textTransform: 'capitalize' }}>{(a.object_type || '').replace(/_/g, ' ')}</td>
              <td style={{ padding: '10px 12px', fontSize: 12, fontWeight: 500 }}>{a.object_name || a.object_id || '—'}</td>
              <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-2)' }}>{a.actor}</td>
              <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', fontStyle: 'italic', maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.details || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Reports ────────────────────────────────────────────────────────────────
function ReportsTab({ onGenerate }: { onGenerate: (t: string) => void }) {
  const [gen, setGen] = useState('');
  const [toast, setToast] = useState('');
  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(''), 3000); };
  const go = async (type: string) => { setGen(type); await onGenerate(type); notify(`${type.replace(/_/g, ' ')} report generated`); setGen(''); };
  const reports = [
    { id: 'firewall_activity', label: 'Firewall Activity Report', desc: 'Complete log of all rule hits, allows, and denies' },
    { id: 'policy_compliance', label: 'Policy Compliance Report', desc: 'Rule compliance against security baseline' },
    { id: 'threat_blocking',   label: 'Threat Blocking Report',   desc: 'Detailed breakdown of blocked threats by type and source' },
    { id: 'config_change',     label: 'Configuration Change Report', desc: 'Audit of all firewall config changes' },
    { id: 'executive_summary', label: 'Executive Summary',         desc: 'High-level security posture and risk overview' },
    { id: 'audit',             label: 'Audit Report',              desc: 'Complete audit trail for compliance and forensics' },
  ];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {toast && <div className="g-card" style={{ padding: '8px 14px', borderLeft: '3px solid var(--accent)', fontSize: 13 }}>{toast}</div>}
      <div style={{ fontWeight: 600, fontSize: 14 }}>Generate Reports</div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        {reports.map(r => (
          <div key={r.id} className="g-card" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{ fontWeight: 600, fontSize: 13 }}>{r.label}</div>
            <div style={{ fontSize: 12, color: 'var(--text-3)', flex: 1 }}>{r.desc}</div>
            <button className="g-btn g-btn-primary" style={{ fontSize: 11, alignSelf: 'flex-start' }} onClick={() => go(r.id)} disabled={gen === r.id}>
              {gen === r.id ? 'Generating…' : '⬇ Generate'}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── AI Panel ───────────────────────────────────────────────────────────────
function AIPanel({ onClose }: { onClose: () => void }) {
  const [input, setInput] = useState('');
  const [response, setResponse] = useState('');
  const [loading, setLoading] = useState(false);
  const actions = [
    { id: 'recommend_rules',        label: '📋 Recommend Rules' },
    { id: 'detect_redundant',       label: '🔍 Detect Redundant Rules' },
    { id: 'identify_shadowed',      label: '👥 Identify Shadowed Rules' },
    { id: 'optimize_rule_order',    label: '⚡ Optimize Rule Order' },
    { id: 'explain_traffic',        label: '🔎 Explain Traffic Decision' },
    { id: 'recommend_improvements', label: '🛡 Recommend Improvements' },
  ];
  const ask = async (action: string) => {
    setLoading(true);
    try { const r = await fweAPI.ai({ action, context: input }); setResponse((r.data as any)?.response || ''); }
    catch { setResponse('AI unavailable.'); } finally { setLoading(false); }
  };
  return (
    <div style={{ position: 'fixed', top: 0, right: 0, bottom: 0, width: 440, background: 'var(--glass-bg)', borderLeft: '1px solid var(--border)', zIndex: 100, display: 'flex', flexDirection: 'column', boxShadow: '-4px 0 24px rgba(0,0,0,0.3)' }}>
      <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontWeight: 700, fontSize: 14 }}>🛡 Firewall AI Assistant</div>
        <button onClick={onClose} style={{ fontSize: 18, color: 'var(--text-3)' }}>×</button>
      </div>
      <div style={{ padding: 16, flex: 1, display: 'flex', flexDirection: 'column', gap: 12, overflow: 'auto' }}>
        <textarea className="g-input" placeholder="Describe traffic, paste rule config, or ask about a connection…" value={input} onChange={e => setInput(e.target.value)} style={{ fontSize: 12, minHeight: 80, resize: 'vertical' }} />
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {actions.map(a => (
            <button key={a.id} className="g-btn g-btn-ghost" style={{ fontSize: 11, justifyContent: 'flex-start' }} onClick={() => ask(a.id)} disabled={loading}>{a.label}</button>
          ))}
        </div>
        {loading && <div style={{ fontSize: 12, color: 'var(--text-3)', textAlign: 'center', padding: 12 }}>Analyzing…</div>}
        {response && (
          <div className="g-card" style={{ padding: 14, fontSize: 13, color: 'var(--text-1)', lineHeight: 1.7, whiteSpace: 'pre-wrap' }}>{response}</div>
        )}
      </div>
    </div>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────
export default function FirewallPage() {
  const [tab, setTab] = useState<Tab>('dashboard');
  const [dash, setDash] = useState<any>(null);
  const [policies, setPolicies] = useState<any[]>([]);
  const [rules, setRules] = useState<any[]>([]);
  const [nat, setNat] = useState<any[]>([]);
  const [zones, setZones] = useState<any[]>([]);
  const [threats, setThreats] = useState<any[]>([]);
  const [conns, setConns] = useState<any[]>([]);
  const [blocked, setBlocked] = useState<any[]>([]);
  const [analytics, setAnalytics] = useState<any>(null);
  const [approvals, setApprovals] = useState<any[]>([]);
  const [notifications, setNotifications] = useState<any[]>([]);
  const [audit, setAudit] = useState<any[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [showAI, setShowAI] = useState(false);

  const loadAll = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const [d, pol, r, n, z, t, c, bl, an, ap, notif, au] = await Promise.all([
        fweAPI.getDashboard(),
        fweAPI.getPolicies(),
        firewallAPI.getAll(),
        fweAPI.getNAT(),
        fweAPI.getZones(),
        fweAPI.getThreats(),
        fweAPI.getConnections(),
        fweAPI.getBlocked(),
        fweAPI.getAnalytics(),
        fweAPI.getApprovals(),
        fweAPI.getNotifications(),
        fweAPI.getAudit(),
      ]);
      setDash(d.data);
      setPolicies((pol.data as any) || []);
      setRules((r.data as any) || []);
      setNat((n.data as any) || []);
      setZones((z.data as any) || []);
      setThreats((t.data as any) || []);
      setConns((c.data as any) || []);
      setBlocked((bl.data as any) || []);
      setAnalytics(an.data);
      setApprovals((ap.data as any) || []);
      setNotifications((notif.data as any) || []);
      setAudit((au.data as any) || []);
    } finally { setRefreshing(false); }
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  const markRead = async () => {
    await fweAPI.markNotificationsRead();
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
  };

  const pendingApprovals = approvals.filter(a => a.status === 'pending').length;
  const unreadCount = notifications.filter(n => !n.read).length;

  return (
    <RootLayout
      title="Firewall"
      subtitle="Enterprise firewall management, threat protection & policy enforcement"
      onRefresh={() => loadAll(true)}
      refreshing={refreshing}
      actions={
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={() => setShowAI(v => !v)}>🛡 AI</button>
        </div>
      }
    >
      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', marginBottom: 20, overflowX: 'auto' }}>
        {TABS.map(t => {
          const badge = t.id === 'approvals' ? pendingApprovals : t.id === 'notifications' ? unreadCount : 0;
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

      {tab === 'dashboard'     && <DashboardTab dash={dash} onTabChange={setTab} />}
      {tab === 'policies'      && <PoliciesTab policies={policies} onRefresh={() => loadAll()} />}
      {tab === 'rules'         && <RulesTab rules={rules} onRefresh={() => loadAll()} />}
      {tab === 'nat'           && <NATTab items={nat} onRefresh={() => loadAll()} />}
      {tab === 'zones'         && <ZonesTab zones={zones} onRefresh={() => loadAll()} />}
      {tab === 'threats'       && <ThreatsTab threats={threats} />}
      {tab === 'connections'   && <ConnectionsTab conns={conns} />}
      {tab === 'blocked'       && <BlockedTab items={blocked} onRefresh={() => loadAll()} />}
      {tab === 'analytics'     && <AnalyticsTab data={analytics} />}
      {tab === 'approvals'     && <ApprovalsTab approvals={approvals} onRefresh={() => loadAll()} />}
      {tab === 'notifications' && <NotificationsTab items={notifications} onMarkRead={markRead} />}
      {tab === 'audit'         && <AuditTab items={audit} />}
      {tab === 'reports'       && <ReportsTab onGenerate={async (t) => { await fweAPI.report({ report_type: t }); }} />}

      {showAI && <AIPanel onClose={() => setShowAI(false)} />}
    </RootLayout>
  );
}
