'use client';
import { useState, useEffect, useRef, useMemo } from 'react';
import { adSecurityAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';

const SEV_BG: Record<string, string> = {
  critical: 'background:rgba(220,38,38,0.15);color:#f87171;border:1px solid rgba(220,38,38,0.3)',
  high:     'background:rgba(234,88,12,0.15);color:#fb923c;border:1px solid rgba(234,88,12,0.3)',
  medium:   'background:rgba(202,138,4,0.15);color:#facc15;border:1px solid rgba(202,138,4,0.3)',
  low:      'background:rgba(34,197,94,0.15);color:#4ade80;border:1px solid rgba(34,197,94,0.3)',
  clean:    'background:rgba(34,197,94,0.15);color:#4ade80;border:1px solid rgba(34,197,94,0.3)',
  warn:     'background:rgba(202,138,4,0.15);color:#facc15;border:1px solid rgba(202,138,4,0.3)',
  fail:     'background:rgba(220,38,38,0.15);color:#f87171;border:1px solid rgba(220,38,38,0.3)',
};
type Tab = 'overview' | 'inventory' | 'identity' | 'auth' | 'attacks' | 'lateral' | 'intelligence' | 'analytics' | 'response';

function SevBadge({ v }: { v: string }) {
  const style = SEV_BG[v?.toLowerCase()] || SEV_BG.low;
  return <span style={{ ...Object.fromEntries(style.split(';').filter(Boolean).map(s => { const [k, val] = s.split(':'); return [k.trim().replace(/-([a-z])/g, (_: string, c: string) => c.toUpperCase()), val?.trim()]; })), padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600, textTransform: 'uppercase' as const, whiteSpace: 'nowrap' as const }}>{v}</span>;
}
function StatCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="g-card" style={{ flex: 1, minWidth: 130, padding: '16px 18px' }}>
      <div style={{ fontSize: 22, fontWeight: 700, color: color || 'var(--accent)' }}>{value}</div>
      <div style={{ fontSize: 11, color: 'var(--text-2)', marginTop: 2 }}>{label}</div>
      {sub && <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 3 }}>{sub}</div>}
    </div>
  );
}
function RiskBar({ score }: { score: number }) {
  const color = score >= 80 ? '#ef4444' : score >= 60 ? '#f97316' : score >= 40 ? '#eab308' : '#22c55e';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 5, background: 'rgba(255,255,255,0.08)', borderRadius: 3 }}>
        <div style={{ width: `${score}%`, height: '100%', background: color, borderRadius: 3 }} />
      </div>
      <span style={{ fontSize: 11, color, fontWeight: 600, minWidth: 24 }}>{score}</span>
    </div>
  );
}

const ATTACK_COLOR: Record<string, string> = {
  kerberoasting: '#a855f7', as_rep_roasting: '#a855f7', golden_ticket: '#ef4444',
  silver_ticket: '#f97316', pass_the_ticket: '#f97316', kerberos_delegation: '#8b5cf6',
  pass_the_hash: '#ef4444', credential_dumping: '#ef4444', lsass_access: '#ef4444',
  dcsync: '#ef4444', dcshadow: '#dc2626', skeleton_key: '#dc2626', sam_access: '#ef4444',
  domain_admin_creation: '#ef4444', admin_group_change: '#f97316', privilege_escalation: '#f97316',
  sid_history_abuse: '#ef4444', lateral_psexec: '#3b82f6', lateral_smb: '#3b82f6',
  lateral_rdp: '#3b82f6', lateral_winrm: '#3b82f6', lateral_wmi: '#3b82f6',
};

// ── OVERVIEW TAB ─────────────────────────────────────────────────────────────
function OverviewTab() {
  const [dash, setDash] = useState<any>(null);
  useEffect(() => { adSecurityAPI.getDashboard().then(r => setDash(r.data)); }, []);
  const d = dash || {};
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Forests" value={d.forests ?? '—'} />
        <StatCard label="Domains" value={d.domains ?? '—'} />
        <StatCard label="Domain Controllers" value={d.domain_controllers ?? '—'} />
        <StatCard label="Domain Trusts" value={d.domain_trusts ?? '—'} />
        <StatCard label="High-Risk Users" value={d.high_risk_users ?? '—'} color={d.high_risk_users > 0 ? '#ef4444' : undefined} />
        <StatCard label="Privileged Accounts" value={d.privileged_accounts ?? '—'} color="#f97316" />
        <StatCard label="Active AD Attacks" value={d.active_attacks ?? '—'} color={d.active_attacks > 0 ? '#ef4444' : undefined} />
        <StatCard label="Failed Logins 24h" value={d.failed_logins_24h ?? '—'} color={d.failed_logins_24h > 100 ? '#ef4444' : '#f97316'} />
      </div>
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        <div className="g-card" style={{ flex: 1, minWidth: 280, padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>AD Risk Posture</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <span style={{ fontSize: 12, color: 'var(--text-2)' }}>AD Risk Score</span>
                <span style={{ fontSize: 12, fontWeight: 600 }}>{d.ad_risk_score ?? 0}/100</span>
              </div>
              <RiskBar score={d.ad_risk_score ?? 0} />
            </div>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <span style={{ fontSize: 12, color: 'var(--text-2)' }}>Identity Exposure</span>
                <span style={{ fontSize: 12, fontWeight: 600 }}>{d.identity_exposure ?? 0}%</span>
              </div>
              <RiskBar score={d.identity_exposure ?? 0} />
            </div>
          </div>
        </div>
        <div className="g-card" style={{ flex: 1, minWidth: 280, padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Active Threats</div>
          {[
            { label: 'Kerberos Attacks', color: '#a855f7', count: 3 },
            { label: 'Credential Attacks', color: '#ef4444', count: 3 },
            { label: 'Lateral Movement', color: '#3b82f6', count: 1 },
            { label: 'Privilege Escalation', color: '#f97316', count: 1 },
          ].map(t => (
            <div key={t.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: t.color }} />
                <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{t.label}</span>
              </div>
              <span style={{ fontWeight: 700, color: t.color }}>{t.count}</span>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ flex: 1, minWidth: 280, padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Authentication Health</div>
          {[
            { label: 'Kerberos', status: 'active', note: 'RC4 downgrade detected' },
            { label: 'NTLM', status: 'warn', note: 'NTLMv1 still enabled' },
            { label: 'LDAP', status: 'warn', note: 'Signing not required' },
            { label: 'LDAPS', status: 'ok', note: 'Encrypted' },
            { label: 'SMB Signing', status: 'fail', note: 'Not enforced' },
            { label: 'WDigest', status: 'fail', note: 'Plaintext caching enabled' },
          ].map(r => (
            <div key={r.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <div>
                <span style={{ fontSize: 12, fontWeight: 600 }}>{r.label}</span>
                <span style={{ fontSize: 10, color: 'var(--text-3)', marginLeft: 8 }}>{r.note}</span>
              </div>
              <SevBadge v={r.status === 'ok' || r.status === 'active' ? 'clean' : r.status === 'warn' ? 'medium' : 'critical'} />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── INVENTORY TAB ────────────────────────────────────────────────────────────
function InventoryTab() {
  const [inv, setInv] = useState<any>(null);
  useEffect(() => { adSecurityAPI.getInventory().then(r => setInv(r.data)); }, []);
  const d = inv || {};
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Forests" value={d.forests ?? '—'} />
        <StatCard label="Domains" value={d.domains ?? '—'} />
        <StatCard label="Domain Controllers" value={d.domain_controllers ?? '—'} />
        <StatCard label="Users" value={d.users ?? '—'} />
        <StatCard label="Service Accounts" value={d.service_accounts ?? '—'} color="#f97316" />
        <StatCard label="Admin Accounts" value={d.admin_accounts ?? '—'} color="#ef4444" />
        <StatCard label="Computers" value={d.computers ?? '—'} />
        <StatCard label="Groups" value={d.groups ?? '—'} />
        <StatCard label="GPOs" value={d.gpos ?? '—'} />
      </div>
      {(d.domain_list || []).length > 0 && (
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Domain Inventory</div>
          <table className="g-table"><thead className="g-thead"><tr>
            <th>Domain</th><th>NetBIOS</th><th>Functional Level</th><th>DCs</th><th>Users</th><th>Computers</th><th>GPOs</th><th>Trusts</th><th>Risk</th>
          </tr></thead><tbody>
            {d.domain_list.map((dom: any) => (
              <tr key={dom.id} className="g-tr">
                <td style={{ fontFamily: 'monospace', fontWeight: 600, fontSize: 12 }}>{dom.name}</td>
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{dom.netbios}</td>
                <td style={{ fontSize: 11, color: 'var(--text-2)' }}>{dom.functional_level}</td>
                <td>{dom.dc_count}</td>
                <td>{dom.user_count?.toLocaleString()}</td>
                <td>{dom.computer_count}</td>
                <td>{dom.gpo_count}</td>
                <td>{dom.trust_count}</td>
                <td style={{ width: 120 }}><RiskBar score={dom.risk_score} /></td>
              </tr>
            ))}
          </tbody></table>
        </div>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 16 }}>
        {[
          { label: 'Forests', icon: '🌲', count: d.forests, desc: 'AD forest boundaries' },
          { label: 'OUs', icon: '📁', count: '—', desc: 'Organizational units' },
          { label: 'Sites', icon: '📍', count: '—', desc: 'AD sites and services' },
          { label: 'Trusts', icon: '🔗', count: '—', desc: 'Domain/forest trusts' },
        ].map(item => (
          <div key={item.label} className="g-card" style={{ padding: 16 }}>
            <div style={{ fontSize: 24, marginBottom: 6 }}>{item.icon}</div>
            <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--accent)' }}>{item.count}</div>
            <div style={{ fontSize: 12, fontWeight: 600, marginTop: 2 }}>{item.label}</div>
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>{item.desc}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── IDENTITY RISK TAB ────────────────────────────────────────────────────────
function IdentityTab() {
  const [data, setData] = useState<any>(null);
  const [filter, setFilter] = useState('all');
  const [selected, setSelected] = useState<any>(null);
  useEffect(() => {
    adSecurityAPI.getIdentityRisk({ filter: filter === 'all' ? undefined : filter }).then(r => setData(r.data));
  }, [filter]);
  const d = data || {};
  const FILTERS = ['all', 'high_risk', 'admin', 'service_accounts', 'dormant', 'password_never_expires'];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="High-Risk Users" value={d.high_risk ?? '—'} color="#ef4444" />
        <StatCard label="Dormant Accounts" value={d.dormant ?? '—'} color="#f97316" sub="> 90 days inactive" />
        <StatCard label="Pwd Never Expires" value={d.password_never_expires ?? '—'} color="#f97316" />
        <StatCard label="Admin Accounts" value={d.admin_accounts ?? '—'} color="#a855f7" />
        <StatCard label="Service Accounts" value={d.service_accounts ?? '—'} color="#3b82f6" />
      </div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {FILTERS.map(f => (
          <button key={f} className={filter === f ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setFilter(f)} style={{ fontSize: 11, textTransform: 'capitalize' }}>
            {f.replace(/_/g, ' ')}
          </button>
        ))}
      </div>
      <div style={{ display: 'flex', gap: 16 }}>
        <div style={{ flex: 2 }}>
          <table className="g-table"><thead className="g-thead"><tr>
            <th>Account</th><th>Display Name</th><th>Dept</th><th>Admin</th><th>Svc Acc</th><th>Pwd Never Expires</th><th>Last Logon</th><th>Last Pwd Change</th><th>Risk</th>
          </tr></thead><tbody>
            {(d.users || []).map((u: any) => (
              <tr key={u.id} className="g-tr" onClick={() => setSelected(u)} style={{ cursor: 'pointer', background: selected?.id === u.id ? 'rgba(100,200,255,0.04)' : undefined }}>
                <td style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 600 }}>{u.sam_account}</td>
                <td style={{ fontSize: 12 }}>{u.display_name}</td>
                <td style={{ fontSize: 11, color: 'var(--text-2)' }}>{u.department}</td>
                <td><span style={{ color: u.is_admin ? '#ef4444' : '#22c55e', fontWeight: 700 }}>{u.is_admin ? '✗ YES' : '✓ No'}</span></td>
                <td><span style={{ color: u.is_service_account ? '#3b82f6' : 'var(--text-3)', fontWeight: 600 }}>{u.is_service_account ? 'SVC' : '—'}</span></td>
                <td><span style={{ color: u.password_never_expires ? '#f97316' : '#22c55e', fontWeight: 700 }}>{u.password_never_expires ? '✗' : '✓'}</span></td>
                <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{timeAgo(u.last_logon)}</td>
                <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{timeAgo(u.last_password_change)}</td>
                <td style={{ width: 110 }}><RiskBar score={u.risk_score} /></td>
              </tr>
            ))}
          </tbody></table>
        </div>
        {selected && (
          <div className="g-card" style={{ flex: 1, minWidth: 260, padding: 18, position: 'sticky', top: 16, alignSelf: 'flex-start', maxWidth: 300 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 14 }}>
              <span style={{ fontSize: 14, fontWeight: 600 }}>User Details</span>
              <button className="g-btn g-btn-ghost" style={{ padding: '2px 8px', fontSize: 11 }} onClick={() => setSelected(null)}>✕</button>
            </div>
            <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--accent)', marginBottom: 4, fontFamily: 'monospace' }}>{selected.sam_account}</div>
            <div style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 16 }}>{selected.display_name} · {selected.department}</div>
            <RiskBar score={selected.risk_score} />
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', margin: '12px 0' }}>
              {selected.is_admin && <SevBadge v="critical" />}
              {selected.is_service_account && <SevBadge v="medium" />}
              {selected.password_never_expires && <SevBadge v="high" />}
              {!selected.is_enabled && <SevBadge v="warn" />}
            </div>
            {[
              { label: 'Email', val: selected.email },
              { label: 'Last Logon', val: timeAgo(selected.last_logon) },
              { label: 'Password Age', val: timeAgo(selected.last_password_change) },
            ].map(r => (
              <div key={r.label} style={{ marginBottom: 8 }}>
                <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase' as const }}>{r.label}</div>
                <div style={{ fontSize: 12, color: 'var(--text-1)', marginTop: 2 }}>{r.val}</div>
              </div>
            ))}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 12 }}>
              <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }}>View Timeline</button>
              <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }}>Open Incident</button>
              <button className="g-btn" style={{ fontSize: 11, background: 'rgba(220,38,38,0.1)', border: '1px solid rgba(220,38,38,0.3)', color: '#f87171' }}>Disable Account</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── AUTH MONITOR TAB ─────────────────────────────────────────────────────────
function AuthTab() {
  const [data, setData] = useState<any>(null);
  const [authFilter, setAuthFilter] = useState('all');
  useEffect(() => { adSecurityAPI.getAuthMonitor().then(r => setData(r.data)); }, []);
  const d = data || {};
  const events = useMemo(() => {
    const all = d.events || [];
    if (authFilter === 'all') return all;
    return all.filter((e: any) => e.event_type === authFilter || e.auth_type?.toLowerCase() === authFilter);
  }, [d.events, authFilter]);
  const AUTH_FILTERS = ['all', 'failed_login', 'password_spray', 'kerberos_ticket', 'suspicious_logon', 'ldap_recon', 'ntlm_relay'];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Failed Logins" value={d.failed_logins ?? '—'} color="#ef4444" />
        <StatCard label="Password Sprays" value={d.password_spray ?? '—'} color={d.password_spray > 0 ? '#ef4444' : undefined} />
        <StatCard label="Brute Force" value={d.brute_force ?? '—'} color={d.brute_force > 0 ? '#ef4444' : undefined} />
        <StatCard label="Suspicious Logons" value={d.suspicious_logons ?? '—'} color={d.suspicious_logons > 0 ? '#f97316' : undefined} />
      </div>
      <div className="g-card" style={{ padding: 16 }}>
        <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>Auth Protocol Status</div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          {[
            { label: 'NTLM', status: 'warn', note: 'v1 enabled' }, { label: 'Kerberos', status: 'active', note: 'RC4 downgrade' },
            { label: 'LDAP', status: 'warn', note: 'No signing' }, { label: 'LDAPS', status: 'ok', note: 'Encrypted' },
            { label: 'RDP', status: 'ok', note: 'NLA required' }, { label: 'SMB', status: 'fail', note: 'No signing' },
            { label: 'WinRM', status: 'ok', note: 'HTTPS' }, { label: 'VPN', status: 'ok', note: 'MFA enabled' },
          ].map(a => (
            <div key={a.label} style={{ padding: '8px 14px', borderRadius: 8, background: 'rgba(255,255,255,0.03)', border: `1px solid ${a.status === 'fail' ? 'rgba(220,38,38,0.3)' : a.status === 'warn' ? 'rgba(234,88,12,0.3)' : 'var(--border)'}` }}>
              <div style={{ fontSize: 12, fontWeight: 600 }}>{a.label}</div>
              <div style={{ fontSize: 10, color: a.status === 'fail' ? '#f87171' : a.status === 'warn' ? '#fb923c' : '#4ade80', marginTop: 2 }}>{a.note}</div>
            </div>
          ))}
        </div>
      </div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {AUTH_FILTERS.map(f => (
          <button key={f} className={authFilter === f ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setAuthFilter(f)} style={{ fontSize: 11, textTransform: 'capitalize' }}>
            {f.replace(/_/g, ' ')}
          </button>
        ))}
      </div>
      <table className="g-table"><thead className="g-thead"><tr>
        <th>Event Type</th><th>Severity</th><th>User</th><th>Source Computer</th><th>Source IP</th><th>Target</th><th>Auth</th><th>Status</th><th>Time</th>
      </tr></thead><tbody>
        {events.map((e: any) => (
          <tr key={e.id} className="g-tr">
            <td style={{ fontWeight: 600, fontSize: 11, color: e.event_type === 'failed_login' ? '#ef4444' : e.event_type === 'password_spray' ? '#a855f7' : 'var(--text-1)' }}>
              {e.event_type?.replace(/_/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase())}
            </td>
            <td><SevBadge v={e.severity} /></td>
            <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{e.source_user}</td>
            <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{e.source_computer}</td>
            <td style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-3)' }}>{e.source_ip}</td>
            <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{e.target}</td>
            <td><code style={{ fontSize: 10, background: 'rgba(255,255,255,0.05)', padding: '1px 5px', borderRadius: 3 }}>{e.auth_type}</code></td>
            <td><SevBadge v={e.status === 'open' ? 'high' : e.status === 'investigating' ? 'medium' : 'clean'} /></td>
            <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{timeAgo(e.created_at)}</td>
          </tr>
        ))}
      </tbody></table>
    </div>
  );
}

// ── ATTACKS TAB ──────────────────────────────────────────────────────────────
function AttacksTab() {
  const [data, setData] = useState<any>(null);
  const [category, setCategory] = useState('all');
  const [selected, setSelected] = useState<any>(null);
  useEffect(() => {
    adSecurityAPI.getAttacks({ category: category === 'all' ? undefined : category }).then(r => setData(r.data));
  }, [category]);
  const d = data || {};
  const CATEGORIES = [
    { id: 'all', label: 'All Attacks' },
    { id: 'kerberos', label: 'Kerberos' },
    { id: 'credential', label: 'Credentials' },
    { id: 'privilege', label: 'Privilege Escalation' },
    { id: 'lateral', label: 'Lateral Movement' },
  ];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Kerberoasting" value={d.kerberoasting ?? '—'} color="#a855f7" />
        <StatCard label="AS-REP Roasting" value={d.as_rep_roasting ?? '—'} color="#a855f7" />
        <StatCard label="Golden Ticket" value={d.golden_ticket ?? '—'} color="#ef4444" />
        <StatCard label="Pass-the-Hash" value={d.pass_the_hash ?? '—'} color="#ef4444" />
        <StatCard label="DCSync" value={d.dcsync ?? '—'} color="#ef4444" />
        <StatCard label="DCShadow" value={d.dcshadow ?? '—'} color="#dc2626" />
        <StatCard label="Lateral Movement" value={d.lateral_movement ?? '—'} color="#3b82f6" />
        <StatCard label="Priv Escalation" value={d.priv_escalation ?? '—'} color="#f97316" />
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        {CATEGORIES.map(cat => (
          <button key={cat.id} className={category === cat.id ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setCategory(cat.id)} style={{ fontSize: 11 }}>{cat.label}</button>
        ))}
      </div>
      <div style={{ display: 'flex', gap: 16 }}>
        <div style={{ flex: 2 }}>
          <table className="g-table"><thead className="g-thead"><tr>
            <th>Attack Type</th><th>Severity</th><th>Source User</th><th>Source Computer</th><th>Target</th><th>MITRE</th><th>Status</th><th>Time</th>
          </tr></thead><tbody>
            {(d.attacks || []).map((a: any) => (
              <tr key={a.id} className="g-tr" onClick={() => setSelected(a)} style={{ cursor: 'pointer', background: selected?.id === a.id ? 'rgba(100,200,255,0.04)' : undefined }}>
                <td>
                  <span style={{ color: ATTACK_COLOR[a.attack_type] || 'var(--text-1)', fontWeight: 700, fontSize: 11 }}>
                    {a.attack_type?.replace(/_/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase())}
                  </span>
                </td>
                <td><SevBadge v={a.severity} /></td>
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{a.source_user}</td>
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{a.source_computer}</td>
                <td style={{ fontSize: 11, maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.target}</td>
                <td><code style={{ fontSize: 10, background: 'rgba(255,255,255,0.05)', padding: '1px 5px', borderRadius: 3 }}>{a.mitre_technique}</code></td>
                <td><SevBadge v={a.status === 'open' ? 'critical' : a.status === 'investigating' ? 'medium' : 'clean'} /></td>
                <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{timeAgo(a.created_at)}</td>
              </tr>
            ))}
          </tbody></table>
        </div>
        {selected && (
          <div className="g-card" style={{ flex: 1, minWidth: 280, padding: 18, position: 'sticky', top: 16, alignSelf: 'flex-start' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 14 }}>
              <span style={{ fontSize: 14, fontWeight: 600 }}>Attack Details</span>
              <button className="g-btn g-btn-ghost" style={{ padding: '2px 8px', fontSize: 11 }} onClick={() => setSelected(null)}>✕</button>
            </div>
            <div style={{ fontWeight: 700, fontSize: 13, color: ATTACK_COLOR[selected.attack_type] || 'var(--accent)', marginBottom: 10, textTransform: 'capitalize' }}>
              {selected.attack_type?.replace(/_/g, ' ')}
            </div>
            <div style={{ display: 'flex', gap: 6, marginBottom: 12 }}>
              <SevBadge v={selected.severity} />
              <code style={{ fontSize: 10, background: 'rgba(255,255,255,0.05)', padding: '2px 8px', borderRadius: 3 }}>{selected.mitre_technique}</code>
            </div>
            {[
              { label: 'Source User', val: selected.source_user },
              { label: 'Source Computer', val: selected.source_computer },
              { label: 'Source IP', val: selected.source_ip || 'N/A' },
              { label: 'Target', val: selected.target },
              { label: 'Technique', val: selected.technique },
            ].map(r => (
              <div key={r.label} style={{ marginBottom: 8 }}>
                <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase' as const }}>{r.label}</div>
                <div style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-1)', marginTop: 2, wordBreak: 'break-all' as const }}>{r.val}</div>
              </div>
            ))}
            <div style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.5, borderTop: '1px solid var(--border)', paddingTop: 10, marginTop: 6 }}>{selected.description}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 12 }}>
              <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }}>View Timeline</button>
              <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }}>Open Hunt</button>
              <button className="g-btn" style={{ fontSize: 11, background: 'rgba(220,38,38,0.1)', border: '1px solid rgba(220,38,38,0.3)', color: '#f87171' }}>Disable User</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── LATERAL / GPO / CHANGES TAB ──────────────────────────────────────────────
function LateralTab() {
  const [gpoChanges, setGpoChanges] = useState<any[]>([]);
  const [adChanges, setAdChanges] = useState<any[]>([]);
  const [tiering, setTiering] = useState<any>(null);
  const [exposure, setExposure] = useState<any>(null);
  const [sub, setSub] = useState<'lateral' | 'gpo' | 'changes' | 'tiering' | 'exposure'>('lateral');
  useEffect(() => {
    adSecurityAPI.getGPOChanges().then(r => setGpoChanges(r.data || []));
    adSecurityAPI.getChanges().then(r => setAdChanges(r.data || []));
    adSecurityAPI.getTiering().then(r => setTiering(r.data));
    adSecurityAPI.getExposure().then(r => setExposure(r.data));
  }, []);
  const exp = exposure || {};
  const tier = tiering || {};
  const LATERAL_TECHNIQUES = [
    { tech: 'PsExec', mitre: 'T1021.002', detected: true, count: 1 },
    { tech: 'SMB', mitre: 'T1021.002', detected: true, count: 2 },
    { tech: 'RDP', mitre: 'T1021.001', detected: false, count: 0 },
    { tech: 'WinRM', mitre: 'T1021.006', detected: false, count: 0 },
    { tech: 'WMI', mitre: 'T1047', detected: false, count: 0 },
    { tech: 'DCOM', mitre: 'T1021.003', detected: false, count: 0 },
    { tech: 'Remote PowerShell', mitre: 'T1059.001', detected: false, count: 0 },
    { tech: 'Remote Scheduled Tasks', mitre: 'T1053.005', detected: false, count: 0 },
  ];
  return (
    <div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 20, flexWrap: 'wrap' }}>
        {(['lateral', 'gpo', 'changes', 'tiering', 'exposure'] as const).map(s => (
          <button key={s} className={sub === s ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setSub(s)} style={{ fontSize: 11, textTransform: 'capitalize' }}>
            {s === 'gpo' ? 'GPO Changes' : s === 'changes' ? 'AD Changes' : s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
      </div>
      {sub === 'lateral' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            {LATERAL_TECHNIQUES.map(t => (
              <div key={t.tech} className="g-card" style={{ minWidth: 140, padding: '12px 16px', borderLeft: `3px solid ${t.detected ? '#ef4444' : 'var(--border)'}` }}>
                <div style={{ fontWeight: 600, fontSize: 12, color: t.detected ? '#ef4444' : 'var(--text-1)' }}>{t.tech}</div>
                <code style={{ fontSize: 10, color: 'var(--text-3)', display: 'block', marginTop: 4 }}>{t.mitre}</code>
                <div style={{ fontSize: 11, marginTop: 6, color: t.detected ? '#ef4444' : '#22c55e', fontWeight: 700 }}>
                  {t.detected ? `✗ ${t.count} detected` : '✓ None detected'}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
      {sub === 'gpo' && (
        <table className="g-table"><thead className="g-thead"><tr>
          <th>GPO Name</th><th>Status</th><th>Linked OUs</th><th>Last Modified</th>
        </tr></thead><tbody>
          {gpoChanges.map((g: any) => (
            <tr key={g.id} className="g-tr">
              <td style={{ fontWeight: 600, fontSize: 12 }}>{g.name}</td>
              <td><SevBadge v={g.status === 'modified' ? 'high' : g.status === 'created' ? 'critical' : g.status === 'enabled' ? 'medium' : 'clean'} /></td>
              <td style={{ fontSize: 11, color: 'var(--text-2)' }}>{g.linked_ous}</td>
              <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{timeAgo(g.last_modified)}</td>
            </tr>
          ))}
        </tbody></table>
      )}
      {sub === 'changes' && (
        <table className="g-table"><thead className="g-thead"><tr>
          <th>Change Type</th><th>Severity</th><th>Actor</th><th>Target</th><th>Description</th><th>Status</th><th>Time</th>
        </tr></thead><tbody>
          {adChanges.map((ch: any) => (
            <tr key={ch.id} className="g-tr">
              <td style={{ fontWeight: 600, fontSize: 11 }}>{ch.event_type?.replace(/_/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase())}</td>
              <td><SevBadge v={ch.severity} /></td>
              <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{ch.source_user}</td>
              <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{ch.target}</td>
              <td style={{ fontSize: 11, color: 'var(--text-2)', maxWidth: 280 }}>{ch.description}</td>
              <td><SevBadge v={ch.status === 'open' ? 'critical' : ch.status === 'investigating' ? 'medium' : 'clean'} /></td>
              <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{timeAgo(ch.created_at)}</td>
            </tr>
          ))}
        </tbody></table>
      )}
      {sub === 'tiering' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {[
            { label: 'Tier 0 — Control Plane', assets: tier.tier0_assets || [], color: '#ef4444', desc: 'Domain Controllers, PAWs, Tier-0 Groups' },
            { label: 'Tier 1 — Server Administration', assets: tier.tier1_assets || [], color: '#f97316', desc: 'Server Admins, Member Servers' },
            { label: 'Tier 2 — Workstation / User', assets: tier.tier2_assets || [], color: '#22c55e', desc: 'Workstations, Standard Users' },
          ].map(tier => (
            <div key={tier.label} className="g-card" style={{ padding: 20, borderLeft: `4px solid ${tier.color}` }}>
              <div style={{ fontWeight: 700, fontSize: 14, color: tier.color, marginBottom: 4 }}>{tier.label}</div>
              <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 16 }}>{tier.desc}</div>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                {tier.assets.map((a: any) => (
                  <div key={a.name} style={{ padding: '8px 14px', background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid var(--border)' }}>
                    <div style={{ fontSize: 13, fontWeight: 700, color: tier.color }}>{a.count}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-2)' }}>{a.name}</div>
                  </div>
                ))}
              </div>
            </div>
          ))}
          {(tier.privileged_sessions || []).length > 0 && (
            <div className="g-card" style={{ padding: 20 }}>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Active Privileged Sessions</div>
              <table className="g-table"><thead className="g-thead"><tr><th>User</th><th>Computer</th><th>Started</th><th>Duration</th></tr></thead><tbody>
                {tier.privileged_sessions.map((s: any, i: number) => (
                  <tr key={i} className="g-tr">
                    <td style={{ fontFamily: 'monospace', fontWeight: 600 }}>{s.user}</td>
                    <td style={{ fontFamily: 'monospace' }}>{s.computer}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{timeAgo(s.start)}</td>
                    <td style={{ fontSize: 11 }}>{s.duration} min</td>
                  </tr>
                ))}
              </tbody></table>
            </div>
          )}
        </div>
      )}
      {sub === 'exposure' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {(exp.findings || []).map((f: any) => (
            <div key={f.type} className="g-card" style={{ padding: 18, borderLeft: `3px solid ${f.severity === 'critical' ? '#ef4444' : f.severity === 'high' ? '#f97316' : '#eab308'}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                <div>
                  <span style={{ fontWeight: 700, fontSize: 13 }}>{f.type?.replace(/_/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase())}</span>
                  <span style={{ fontSize: 12, color: 'var(--text-3)', marginLeft: 8 }}>({f.count} affected)</span>
                </div>
                <SevBadge v={f.severity} />
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 8 }}>{f.description}</div>
              {f.affected?.length > 0 && (
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {f.affected.map((a: string, i: number) => (
                    <code key={i} style={{ fontSize: 10, background: 'rgba(255,255,255,0.05)', padding: '2px 8px', borderRadius: 3 }}>{a}</code>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── INTELLIGENCE TAB ─────────────────────────────────────────────────────────
function IntelligenceTab() {
  const [intel, setIntel] = useState<any>(null);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [graph, setGraph] = useState<any>(null);
  const [aiMode, setAiMode] = useState<'event' | 'user' | 'ask'>('event');
  const [aiInput, setAiInput] = useState('');
  const [aiRes, setAiRes] = useState<any>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [sub, setSub] = useState<'intel' | 'timeline' | 'ai' | 'graph'>('intel');
  useEffect(() => {
    adSecurityAPI.getThreatIntel().then(r => setIntel(r.data));
    adSecurityAPI.getTimeline().then(r => setTimeline(r.data || []));
    adSecurityAPI.getGraph().then(r => setGraph(r.data));
  }, []);
  const ti = intel || {}; const g = graph || {};
  const NODE_COLOR: Record<string, string> = { domain_controller: '#ef4444', user: '#3b82f6', service_account: '#a855f7', group: '#f97316', computer: '#22c55e', gpo: '#eab308', technique: '#dc2626' };
  const doAI = async () => {
    setAiLoading(true);
    try {
      const payload: any = { mode: aiMode };
      if (aiMode === 'event') payload.event = aiInput;
      else if (aiMode === 'user') payload.user = aiInput;
      else payload.content = aiInput;
      const r = await adSecurityAPI.analyzeAI(payload);
      setAiRes(r.data);
    } catch { setAiRes({ error: 'Analysis failed' }); }
    setAiLoading(false);
  };
  return (
    <div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
        {(['intel', 'timeline', 'ai', 'graph'] as const).map(s => (
          <button key={s} className={sub === s ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setSub(s)} style={{ fontSize: 11, textTransform: 'capitalize' }}>
            {s === 'intel' ? 'Threat Intel' : s === 'ai' ? 'AI Analysis' : s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
      </div>
      {sub === 'intel' && (
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          <div className="g-card" style={{ flex: 1, minWidth: 280, padding: 20 }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Threat Actors</div>
            {(ti.threat_actors || []).map((a: any) => (
              <div key={a.actor} style={{ marginBottom: 14, paddingBottom: 14, borderBottom: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ fontWeight: 700, color: '#ef4444' }}>{a.actor}</span>
                  <SevBadge v={a.active ? 'critical' : 'medium'} />
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>{a.target} · {a.campaigns} campaigns</div>
                <code style={{ fontSize: 10, background: 'rgba(255,255,255,0.05)', padding: '2px 6px', borderRadius: 3, display: 'inline-block', marginTop: 6 }}>{a.ttps}</code>
              </div>
            ))}
          </div>
          <div className="g-card" style={{ flex: 1, minWidth: 280, padding: 20 }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>IOC Matches</div>
            {(ti.ioc_matches || []).map((ioc: any) => (
              <div key={ioc.value} style={{ marginBottom: 10, padding: '8px 10px', background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <code style={{ fontSize: 11 }}>{ioc.value}</code>
                  <span style={{ fontSize: 11, fontWeight: 700, color: '#ef4444' }}>{ioc.hits} hits</span>
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 3 }}>{ioc.type?.toUpperCase()} · {ioc.category?.replace(/_/g, ' ')} · {ioc.threat_actor}</div>
              </div>
            ))}
          </div>
          <div className="g-card" style={{ flex: 1, minWidth: 280, padding: 20 }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Malware & Tools</div>
            {(ti.malware || []).map((m: any) => (
              <div key={m.family} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12, paddingBottom: 12, borderBottom: '1px solid var(--border)' }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>{m.family}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>{m.category?.replace(/_/g, ' ')}</div>
                </div>
                <span style={{ fontWeight: 700, fontSize: 14, color: m.detections > 0 ? '#ef4444' : '#22c55e' }}>{m.detections} detections</span>
              </div>
            ))}
          </div>
        </div>
      )}
      {sub === 'timeline' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {timeline.map((ev: any) => (
            <div key={ev.id} style={{ display: 'flex', gap: 14, alignItems: 'flex-start', padding: '12px 16px', background: 'rgba(255,255,255,0.02)', borderRadius: 8, borderLeft: `3px solid ${ev.severity === 'critical' ? '#ef4444' : ev.severity === 'high' ? '#f97316' : '#eab308'}` }}>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <span style={{ fontSize: 12, fontWeight: 700, textTransform: 'capitalize', color: ATTACK_COLOR[ev.event_type] || 'var(--text-1)' }}>{ev.event_type?.replace(/_/g, ' ')}</span>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <SevBadge v={ev.severity} />
                    <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{timeAgo(ev.created_at)}</span>
                  </div>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 4 }}>{ev.description}</div>
                <div style={{ fontSize: 10, color: 'var(--text-3)' }}>
                  <span style={{ fontFamily: 'monospace' }}>{ev.source_user}</span>
                  {ev.source_computer && <> → <span style={{ fontFamily: 'monospace' }}>{ev.source_computer}</span></>}
                  {ev.target && <> → <span style={{ fontFamily: 'monospace' }}>{ev.target}</span></>}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
      {sub === 'ai' && (
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          <div className="g-card" style={{ flex: 1, minWidth: 340, padding: 20 }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>AI Analysis</div>
            <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
              {(['event', 'user', 'ask'] as const).map(m => (
                <button key={m} className={aiMode === m ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setAiMode(m)} style={{ fontSize: 11, padding: '4px 10px', textTransform: 'capitalize' }}>{m}</button>
              ))}
            </div>
            <textarea className="g-input" rows={4} style={{ width: '100%', resize: 'vertical' as const, fontFamily: 'monospace', fontSize: 12 }}
              placeholder={aiMode === 'event' ? 'Paste AD security event or alert details...' : aiMode === 'user' ? 'Describe the user behavior to analyze...' : 'Ask an Active Directory security question...'}
              value={aiInput} onChange={e => setAiInput(e.target.value)} />
            <button className="g-btn g-btn-primary" style={{ marginTop: 10, width: '100%' }} onClick={doAI} disabled={aiLoading || !aiInput.trim()}>
              {aiLoading ? 'Analyzing...' : 'Analyze with AI'}
            </button>
            {aiRes && (
              <div style={{ marginTop: 16, padding: 14, background: 'rgba(0,0,0,0.2)', borderRadius: 8, border: '1px solid var(--border)' }}>
                {aiRes.verdict && <div style={{ marginBottom: 10 }}><SevBadge v={aiRes.verdict === 'confirmed_attack' ? 'critical' : aiRes.verdict === 'suspicious' ? 'high' : 'clean'} /></div>}
                {aiRes.attack_technique && <div style={{ fontSize: 12, fontWeight: 600, color: '#ef4444', marginBottom: 8 }}>{aiRes.attack_technique}</div>}
                {aiRes.explanation && <p style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.6, marginBottom: 12 }}>{aiRes.explanation}</p>}
                {aiRes.mitre_technique && <code style={{ fontSize: 11, background: 'rgba(255,255,255,0.05)', padding: '2px 8px', borderRadius: 3, display: 'inline-block', marginBottom: 12 }}>{aiRes.mitre_technique}</code>}
                {aiRes.recommended_actions && (
                  <div>
                    <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase' as const, marginBottom: 6 }}>Recommended Actions</div>
                    {aiRes.recommended_actions.map((a: string, i: number) => (
                      <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 6 }}>
                        <span style={{ color: 'var(--accent)', fontWeight: 700 }}>{i + 1}.</span>
                        <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{a}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
          <div className="g-card" style={{ flex: 1, minWidth: 300, padding: 20 }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>AI Insights</div>
            {[
              { title: 'Kerberoasting Pattern Detected', insight: 'The service account svc_backup requested an unusually high number of Kerberos service tickets (23 in 4 minutes), consistent with automated Kerberoasting tooling (Rubeus).', severity: 'critical' },
              { title: 'Impossible Travel Alert', insight: 'jsmith authenticated from Chicago and New York City within 4 minutes — indicating credential theft and relay from a remote attacker.', severity: 'high' },
              { title: 'DCSync from Non-DC Host', insight: 'The Domain Admin account authenticated from WS-INFECTED01, a workstation it has never used before, then performed MS-DRSR replication requests.', severity: 'critical' },
            ].map((ins, i) => (
              <div key={i} style={{ marginBottom: 14, padding: '12px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: 8, borderLeft: `3px solid ${ins.severity === 'critical' ? '#ef4444' : '#f97316'}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                  <span style={{ fontWeight: 600, fontSize: 12 }}>{ins.title}</span>
                  <SevBadge v={ins.severity} />
                </div>
                <p style={{ fontSize: 11, color: 'var(--text-2)', lineHeight: 1.5, margin: 0 }}>{ins.insight}</p>
              </div>
            ))}
          </div>
        </div>
      )}
      {sub === 'graph' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="g-card" style={{ padding: 20 }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 4 }}>AD Relationship Graph</div>
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 16 }}>Nodes show risk level. Click a node to see relationships.</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'center' }}>
              {(g.nodes || []).map((node: any) => (
                <div key={node.id} style={{ textAlign: 'center' as const }}>
                  <div style={{ padding: '10px 14px', borderRadius: 10, background: `${NODE_COLOR[node.type] || 'var(--accent)'}22`, border: `2px solid ${NODE_COLOR[node.type] || 'var(--accent)'}44`, cursor: 'pointer', transition: 'all 0.2s' }}>
                    <div style={{ fontSize: 20 }}>
                      {node.type === 'domain_controller' ? '🖥️' : node.type === 'user' ? '👤' : node.type === 'service_account' ? '⚙️' : node.type === 'group' ? '👥' : node.type === 'computer' ? '💻' : node.type === 'gpo' ? '📋' : '⚡'}
                    </div>
                    <div style={{ fontSize: 11, fontWeight: 700, color: NODE_COLOR[node.type] || 'var(--accent)', marginTop: 4 }}>{node.label}</div>
                    <div style={{ fontSize: 9, color: 'var(--text-3)', marginTop: 2 }}>{node.type?.replace(/_/g, ' ')}</div>
                    <div style={{ fontSize: 10, fontWeight: 700, color: node.risk >= 80 ? '#ef4444' : node.risk >= 60 ? '#f97316' : '#22c55e', marginTop: 4 }}>Risk: {node.risk}</div>
                    {node.members && <div style={{ fontSize: 9, color: 'var(--text-3)' }}>{node.members} members</div>}
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="g-card" style={{ padding: 20 }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Attack Edges (Critical Paths)</div>
            <table className="g-table"><thead className="g-thead"><tr><th>Source</th><th>Relationship</th><th>Target</th><th>Risk</th></tr></thead><tbody>
              {(g.edges || []).map((e: any, i: number) => (
                <tr key={i} className="g-tr">
                  <td style={{ fontFamily: 'monospace', fontSize: 11, color: NODE_COLOR[(g.nodes || []).find((n: any) => n.id === e.source)?.type] || 'var(--text-1)', fontWeight: 600 }}>
                    {(g.nodes || []).find((n: any) => n.id === e.source)?.label}
                  </td>
                  <td><code style={{ fontSize: 10, background: 'rgba(255,255,255,0.05)', padding: '2px 8px', borderRadius: 3 }}>{e.label}</code></td>
                  <td style={{ fontFamily: 'monospace', fontSize: 11, color: NODE_COLOR[(g.nodes || []).find((n: any) => n.id === e.target)?.type] || 'var(--text-1)', fontWeight: 600 }}>
                    {(g.nodes || []).find((n: any) => n.id === e.target)?.label}
                  </td>
                  <td><SevBadge v={e.risk} /></td>
                </tr>
              ))}
            </tbody></table>
          </div>
        </div>
      )}
    </div>
  );
}

// ── ANALYTICS TAB ─────────────────────────────────────────────────────────────
function AnalyticsTab() {
  const [analytics, setAnalytics] = useState<any>(null);
  const [assessment, setAssessment] = useState<any>(null);
  const [sub, setSub] = useState<'analytics' | 'assessment'>('analytics');
  useEffect(() => {
    adSecurityAPI.getAnalytics().then(r => setAnalytics(r.data));
    adSecurityAPI.getAssessment().then(r => setAssessment(r.data));
  }, []);
  const a = analytics || {}; const ass = assessment || {};
  const maxAuth = useMemo(() => Math.max(1, ...(a.auth_trend || []).map((p: any) => p.count)), [a.auth_trend]);
  const maxAttack = useMemo(() => Math.max(1, ...(a.attack_breakdown || []).map((t: any) => t.count)), [a.attack_breakdown]);
  return (
    <div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
        <button className={sub === 'analytics' ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setSub('analytics')}>Analytics</button>
        <button className={sub === 'assessment' ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setSub('assessment')}>Security Assessment</button>
      </div>
      {sub === 'analytics' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <StatCard label="Total Attacks" value={a.total_attacks ?? '—'} color="#ef4444" />
            <StatCard label="Kerberoasting" value={a.kerberoasting ?? '—'} color="#a855f7" />
            <StatCard label="Pass-the-Hash" value={a.pass_the_hash ?? '—'} color="#ef4444" />
            <StatCard label="DCSync Attempts" value={a.dcsync_attempts ?? '—'} color="#ef4444" />
            <StatCard label="Priv Escalations" value={a.priv_escalations ?? '—'} color="#f97316" />
            <StatCard label="New Admins (7d)" value={a.new_admins_7d ?? '—'} color={a.new_admins_7d > 0 ? '#ef4444' : undefined} />
          </div>
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
            <div className="g-card" style={{ flex: 2, minWidth: 300, padding: 20 }}>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Authentication Events — 14 Day Trend</div>
              <div style={{ display: 'flex', alignItems: 'flex-end', gap: 3, height: 80, paddingBottom: 24 }}>
                {(a.auth_trend || []).map((p: any) => (
                  <div key={p.date} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, height: '100%', justifyContent: 'flex-end' }}>
                    <div style={{ width: '80%', background: 'var(--accent)', borderRadius: 2, height: `${(p.count / maxAuth) * 56 + 4}px`, minHeight: 4 }} />
                    <span style={{ fontSize: 9, color: 'var(--text-3)' }}>{p.date?.slice(5)}</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="g-card" style={{ flex: 1, minWidth: 260, padding: 20 }}>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Attack Breakdown</div>
              {(a.attack_breakdown || []).map((t: any) => (
                <div key={t.type} style={{ marginBottom: 10 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{t.type}</span>
                    <span style={{ fontSize: 12, fontWeight: 600 }}>{t.count}</span>
                  </div>
                  <div style={{ height: 4, background: 'rgba(255,255,255,0.05)', borderRadius: 2 }}>
                    <div style={{ width: `${(t.count / maxAttack) * 100}%`, height: '100%', background: '#ef4444', borderRadius: 2 }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="g-card" style={{ padding: 20 }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Top Failed Logins</div>
            <table className="g-table"><thead className="g-thead"><tr><th>User</th><th>Failed Count</th><th>Source IP</th></tr></thead><tbody>
              {(a.top_failed_logins || []).map((f: any, i: number) => (
                <tr key={i} className="g-tr">
                  <td style={{ fontFamily: 'monospace', fontWeight: 600 }}>{f.user}</td>
                  <td style={{ color: f.count > 30 ? '#ef4444' : f.count > 15 ? '#f97316' : 'var(--text-1)', fontWeight: 700, fontSize: 14 }}>{f.count}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-3)' }}>{f.source_ip}</td>
                </tr>
              ))}
            </tbody></table>
          </div>
        </div>
      )}
      {sub === 'assessment' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
            <StatCard label="AD Hygiene Score" value={`${ass.overall_score ?? '—'}%`} color={ass.overall_score >= 80 ? '#22c55e' : ass.overall_score >= 60 ? '#f97316' : '#ef4444'} />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {(ass.checks || []).map((check: any) => (
              <div key={check.id} className="g-card" style={{ padding: 18, borderLeft: `3px solid ${check.status === 'fail' ? '#ef4444' : check.status === 'warn' ? '#eab308' : '#22c55e'}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                  <div>
                    <span style={{ fontWeight: 700, fontSize: 13 }}>{check.title}</span>
                    <SevBadge v={check.severity} />
                  </div>
                  <SevBadge v={check.status} />
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 8 }}>{check.detail}</div>
                <div style={{ fontSize: 11, padding: '8px 12px', background: 'rgba(34,197,94,0.05)', border: '1px solid rgba(34,197,94,0.15)', borderRadius: 6, color: '#4ade80' }}>
                  💡 {check.remediation}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── RESPONSE TAB ──────────────────────────────────────────────────────────────
function ResponseTab() {
  const [attackPaths, setAttackPaths] = useState<any>(null);
  const [action, setAction] = useState('disable_user');
  const [target, setTarget] = useState('');
  const [reason, setReason] = useState('');
  const [msg, setMsg] = useState('');
  const [reportType, setReportType] = useState('executive');
  const [reportResult, setReportResult] = useState<any>(null);
  const [reportLoading, setReportLoading] = useState(false);
  useEffect(() => { adSecurityAPI.getAttackPaths().then(r => setAttackPaths(r.data)); }, []);
  const ap = attackPaths || {};
  const NODE_COLOR: Record<string, string> = { domain_controller: '#ef4444', user: '#3b82f6', service_account: '#a855f7', group: '#f97316', computer: '#22c55e', gpo: '#eab308', technique: '#dc2626' };
  const ACTIONS = [
    { id: 'disable_user', label: 'Disable User', desc: 'Disable AD account immediately', color: '#ef4444' },
    { id: 'reset_password', label: 'Reset Password', desc: 'Force password change on next login', color: '#f97316' },
    { id: 'force_ticket_renewal', label: 'Force Ticket Renewal', desc: 'Invalidate all Kerberos TGTs', color: '#a855f7' },
    { id: 'remove_group_membership', label: 'Remove Group Membership', desc: 'Remove from privileged group', color: '#f97316' },
    { id: 'disable_service_account', label: 'Disable Service Account', desc: 'Disable service account', color: '#ef4444' },
    { id: 'isolate_endpoint', label: 'Isolate Endpoint', desc: 'Send isolation to EDR', color: '#3b82f6' },
    { id: 'run_soar_playbook', label: 'Run SOAR Playbook', desc: 'Trigger identity response playbook', color: '#22c55e' },
  ];
  const doAction = async () => {
    const r = await adSecurityAPI.respond({ action, target, reason });
    setMsg(r.data?.message || 'Action executed');
    setTimeout(() => setMsg(''), 5000);
  };
  const doReport = async () => {
    setReportLoading(true);
    const r = await adSecurityAPI.generateReport({ report_type: reportType });
    setReportResult(r.data);
    setReportLoading(false);
  };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Attack Path</div>
        <div style={{ overflowX: 'auto' }}>
          <div style={{ display: 'flex', alignItems: 'center', minWidth: 500, padding: '8px 0' }}>
            {(ap.nodes || []).map((node: any, i: number) => (
              <div key={node.id} style={{ display: 'flex', alignItems: 'center' }}>
                <div style={{ textAlign: 'center' as const, minWidth: 110 }}>
                  <div style={{ padding: '8px 12px', borderRadius: 8, background: `${NODE_COLOR[node.type] || '#888'}22`, border: `1px solid ${NODE_COLOR[node.type] || '#888'}44`, color: NODE_COLOR[node.type] || 'var(--text-1)', fontSize: 11, fontWeight: 700 }}>
                    {node.label}
                  </div>
                  <div style={{ fontSize: 9, color: 'var(--text-3)', marginTop: 3 }}>{node.type?.replace(/_/g, ' ')}</div>
                  <div style={{ fontSize: 9, color: 'var(--text-3)', marginTop: 1 }}>{node.detail}</div>
                </div>
                {i < (ap.nodes || []).length - 1 && (
                  <div style={{ color: '#ef4444', fontSize: 18, padding: '0 4px', marginBottom: 18 }}>→</div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        <div className="g-card" style={{ flex: 1, minWidth: 340, padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Response Actions</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 16 }}>
            {ACTIONS.map(a => (
              <button key={a.id} onClick={() => setAction(a.id)} style={{ textAlign: 'left' as const, padding: '10px 12px', borderRadius: 8, border: `1px solid ${action === a.id ? a.color : 'var(--border)'}`, background: action === a.id ? `${a.color}22` : 'rgba(255,255,255,0.02)', cursor: 'pointer', transition: 'all 0.2s' }}>
                <div style={{ fontWeight: 600, fontSize: 12, color: action === a.id ? a.color : 'var(--text-1)' }}>{a.label}</div>
                <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>{a.desc}</div>
              </button>
            ))}
          </div>
          <input className="g-input" placeholder="Target (user/computer)" value={target} onChange={e => setTarget(e.target.value)} style={{ marginBottom: 8, width: '100%' }} />
          <input className="g-input" placeholder="Reason / ticket number" value={reason} onChange={e => setReason(e.target.value)} style={{ marginBottom: 12, width: '100%' }} />
          <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
            <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }}>Open Timeline</button>
            <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }}>Start Hunt</button>
            <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }}>Log Search</button>
          </div>
          <button className="g-btn g-btn-primary" style={{ width: '100%' }} onClick={doAction}>
            Execute: {ACTIONS.find(a => a.id === action)?.label}
          </button>
          {msg && <div style={{ marginTop: 12, padding: '10px 14px', background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.3)', borderRadius: 6, fontSize: 12, color: '#4ade80' }}>{msg}</div>}
        </div>
        <div className="g-card" style={{ flex: 1, minWidth: 320, padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Generate Report</div>
          <select className="g-select" value={reportType} onChange={e => setReportType(e.target.value)} style={{ width: '100%', marginBottom: 12 }}>
            <option value="executive">Executive Summary</option>
            <option value="technical">Technical Deep Dive</option>
            <option value="incident">Incident Report</option>
            <option value="compliance">Compliance Report</option>
          </select>
          <button className="g-btn g-btn-primary" style={{ width: '100%' }} onClick={doReport} disabled={reportLoading}>
            {reportLoading ? 'Generating...' : 'Generate with AI'}
          </button>
          {reportResult && (
            <div style={{ marginTop: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ fontWeight: 700, fontSize: 14, color: 'var(--accent)' }}>{reportResult.title}</div>
              {reportResult.executive_summary && <p style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.6 }}>{reportResult.executive_summary}</p>}
              {reportResult.key_findings && (
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6 }}>Key Findings</div>
                  {reportResult.key_findings.map((f: string, i: number) => (
                    <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 6 }}>
                      <span style={{ color: '#ef4444', fontWeight: 700 }}>•</span>
                      <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{f}</span>
                    </div>
                  ))}
                </div>
              )}
              {reportResult.top_recommendations && (
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6 }}>Top Recommendations</div>
                  {reportResult.top_recommendations.map((rec: any, i: number) => (
                    <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                      <span style={{ color: 'var(--accent)', fontWeight: 700 }}>{rec.priority}.</span>
                      <div>
                        <div style={{ fontSize: 12, color: 'var(--text-1)' }}>{rec.action}</div>
                        <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>Est: {rec.estimated_effort}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── ROOT PAGE ─────────────────────────────────────────────────────────────────
export default function ADAttacksPage() {
  const [tab, setTab] = useState<Tab>('overview');
  const loaded = useRef<Record<string, boolean>>({});
  if (!loaded.current[tab]) loaded.current[tab] = true;
  const TAB_LABELS: Record<Tab, string> = {
    overview: 'Overview', inventory: 'AD Inventory', identity: 'Identity Risk',
    auth: 'Authentication', attacks: 'Attack Detection', lateral: 'Lateral + GPO',
    intelligence: 'Intelligence', analytics: 'Analytics', response: 'Attack Paths + Response',
  };
  const visibleTabs: Tab[] = ['overview', 'inventory', 'identity', 'auth', 'attacks', 'lateral', 'intelligence', 'analytics', 'response'];
  return (
    <div style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 20, minHeight: '100vh', background: 'var(--bg)' }}>
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>Active Directory Security</h1>
        <p style={{ margin: '4px 0 0', color: 'var(--text-2)', fontSize: 13 }}>Identity attack detection, Kerberos analysis, credential attack monitoring, and AD hygiene assessment.</p>
      </div>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', borderBottom: '1px solid var(--border)', paddingBottom: 12 }}>
        {visibleTabs.map(t => (
          <button key={t} className={tab === t ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setTab(t)} style={{ fontSize: 12 }}>{TAB_LABELS[t]}</button>
        ))}
      </div>
      <div>
        {loaded.current['overview']      && <div style={{ display: tab === 'overview'      ? 'block' : 'none' }}><OverviewTab /></div>}
        {loaded.current['inventory']     && <div style={{ display: tab === 'inventory'     ? 'block' : 'none' }}><InventoryTab /></div>}
        {loaded.current['identity']      && <div style={{ display: tab === 'identity'      ? 'block' : 'none' }}><IdentityTab /></div>}
        {loaded.current['auth']          && <div style={{ display: tab === 'auth'          ? 'block' : 'none' }}><AuthTab /></div>}
        {loaded.current['attacks']       && <div style={{ display: tab === 'attacks'       ? 'block' : 'none' }}><AttacksTab /></div>}
        {loaded.current['lateral']       && <div style={{ display: tab === 'lateral'       ? 'block' : 'none' }}><LateralTab /></div>}
        {loaded.current['intelligence']  && <div style={{ display: tab === 'intelligence'  ? 'block' : 'none' }}><IntelligenceTab /></div>}
        {loaded.current['analytics']     && <div style={{ display: tab === 'analytics'     ? 'block' : 'none' }}><AnalyticsTab /></div>}
        {loaded.current['response']      && <div style={{ display: tab === 'response'      ? 'block' : 'none' }}><ResponseTab /></div>}
      </div>
    </div>
  );
}
