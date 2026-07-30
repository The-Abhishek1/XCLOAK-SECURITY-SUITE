'use client';
import { useState, useEffect, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { adSecurityAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import { MetricCard, SectionCard, DataTable, TabBar, ActionButton } from '@/components/design-system';
import {
  LayoutDashboard, Building2, UserCog, KeyRound, ShieldAlert, Network, Radar, BarChart3, Siren,
  TreePine, FolderTree, MapPin, Link2, Server, User, Settings, Users, Laptop, ClipboardList, Zap,
  Lightbulb, Check, X,
} from 'lucide-react';

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

const TAB_ICONS: Record<Tab, any> = {
  overview: LayoutDashboard, inventory: Building2, identity: UserCog, auth: KeyRound,
  attacks: ShieldAlert, lateral: Network, intelligence: Radar, analytics: BarChart3, response: Siren,
};

function SevBadge({ v }: { v: string }) {
  const style = SEV_BG[v?.toLowerCase()] || SEV_BG.low;
  return <span style={{ ...Object.fromEntries(style.split(';').filter(Boolean).map(s => { const [k, val] = s.split(':'); return [k.trim().replace(/-([a-z])/g, (_: string, c: string) => c.toUpperCase()), val?.trim()]; })), padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600, textTransform: 'uppercase' as const, whiteSpace: 'nowrap' as const }}>{v}</span>;
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

function YesNo({ bad }: { bad: boolean }) {
  return bad
    ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 2, color: '#ef4444', fontWeight: 700 }}><X style={{ width: 12, height: 12 }} /> YES</span>
    : <span style={{ display: 'inline-flex', alignItems: 'center', gap: 2, color: '#22c55e', fontWeight: 700 }}><Check style={{ width: 12, height: 12 }} /> No</span>;
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
        <MetricCard label="Forests" value={d.forests ?? '—'} color="var(--accent)" />
        <MetricCard label="Domains" value={d.domains ?? '—'} color="var(--accent)" />
        <MetricCard label="Domain Controllers" value={d.domain_controllers ?? '—'} color="var(--accent)" />
        <MetricCard label="Domain Trusts" value={d.domain_trusts ?? '—'} color="var(--accent)" />
        <MetricCard label="High-Risk Users" value={d.high_risk_users ?? '—'} color={d.high_risk_users > 0 ? '#ef4444' : undefined} />
        <MetricCard label="Privileged Accounts" value={d.privileged_accounts ?? '—'} color="#f97316" />
        <MetricCard label="Active AD Attacks" value={d.active_attacks ?? '—'} color={d.active_attacks > 0 ? '#ef4444' : undefined} />
        <MetricCard label="Failed Logins 24h" value={d.failed_logins_24h ?? '—'} color={d.failed_logins_24h > 100 ? '#ef4444' : '#f97316'} />
      </div>
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        <SectionCard title="AD Risk Posture" className="flex-1" padded>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14, minWidth: 260 }}>
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
        </SectionCard>
        <SectionCard title="Active Threats" className="flex-1">
          <div style={{ minWidth: 260 }}>
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
        </SectionCard>
        <SectionCard title="Authentication Health" className="flex-1">
          <div style={{ minWidth: 260 }}>
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
        </SectionCard>
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
        <MetricCard label="Forests" value={d.forests ?? '—'} color="var(--accent)" />
        <MetricCard label="Domains" value={d.domains ?? '—'} color="var(--accent)" />
        <MetricCard label="Domain Controllers" value={d.domain_controllers ?? '—'} color="var(--accent)" />
        <MetricCard label="Users" value={d.users ?? '—'} color="var(--accent)" />
        <MetricCard label="Service Accounts" value={d.service_accounts ?? '—'} color="#f97316" />
        <MetricCard label="Admin Accounts" value={d.admin_accounts ?? '—'} color="#ef4444" />
        <MetricCard label="Computers" value={d.computers ?? '—'} color="var(--accent)" />
        <MetricCard label="Groups" value={d.groups ?? '—'} color="var(--accent)" />
        <MetricCard label="GPOs" value={d.gpos ?? '—'} color="var(--accent)" />
      </div>
      {(d.domain_list || []).length > 0 && (
        <SectionCard title="Domain Inventory">
          <DataTable<any>
            rows={d.domain_list}
            rowKey={(dom: any) => dom.id}
            columns={[
              { key: 'name', header: 'Domain', render: (dom: any) => <span style={{ fontFamily: 'monospace', fontWeight: 600, fontSize: 12 }}>{dom.name}</span> },
              { key: 'netbios', header: 'NetBIOS', render: (dom: any) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{dom.netbios}</span> },
              { key: 'functional_level', header: 'Functional Level', render: (dom: any) => <span style={{ fontSize: 11, color: 'var(--text-2)' }}>{dom.functional_level}</span> },
              { key: 'dc_count', header: 'DCs', render: (dom: any) => <span>{dom.dc_count}</span> },
              { key: 'user_count', header: 'Users', render: (dom: any) => <span>{dom.user_count?.toLocaleString()}</span> },
              { key: 'computer_count', header: 'Computers', render: (dom: any) => <span>{dom.computer_count}</span> },
              { key: 'gpo_count', header: 'GPOs', render: (dom: any) => <span>{dom.gpo_count}</span> },
              { key: 'trust_count', header: 'Trusts', render: (dom: any) => <span>{dom.trust_count}</span> },
              { key: 'risk', header: 'Risk', width: '120px', render: (dom: any) => <RiskBar score={dom.risk_score} /> },
            ]}
          />
        </SectionCard>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 16 }}>
        {[
          { label: 'Forests', icon: TreePine, count: d.forests, desc: 'AD forest boundaries' },
          { label: 'OUs', icon: FolderTree, count: '—', desc: 'Organizational units' },
          { label: 'Sites', icon: MapPin, count: '—', desc: 'AD sites and services' },
          { label: 'Trusts', icon: Link2, count: '—', desc: 'Domain/forest trusts' },
        ].map(item => (
          <MetricCard key={item.label} label={item.label} value={item.count} icon={item.icon} sub={item.desc} layout="icon-chip" color="var(--accent)" />
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
        <MetricCard label="High-Risk Users" value={d.high_risk ?? '—'} color="#ef4444" />
        <MetricCard label="Dormant Accounts" value={d.dormant ?? '—'} color="#f97316" sub="> 90 days inactive" />
        <MetricCard label="Pwd Never Expires" value={d.password_never_expires ?? '—'} color="#f97316" />
        <MetricCard label="Admin Accounts" value={d.admin_accounts ?? '—'} color="#a855f7" />
        <MetricCard label="Service Accounts" value={d.service_accounts ?? '—'} color="#3b82f6" />
      </div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {FILTERS.map(f => (
          <ActionButton key={f} variant={filter === f ? 'primary' : 'ghost'} onClick={() => setFilter(f)} style={{ fontSize: 11, textTransform: 'capitalize' }}>
            {f.replace(/_/g, ' ')}
          </ActionButton>
        ))}
      </div>
      <div style={{ display: 'flex', gap: 16 }}>
        <div style={{ flex: 2 }}>
          <DataTable<any>
            rows={d.users || []}
            rowKey={(u: any) => u.id}
            onRowClick={u => setSelected(u)}
            rowStyle={(u: any) => selected?.id === u.id ? { background: 'rgba(100,200,255,0.04)' } : undefined}
            columns={[
              { key: 'sam_account', header: 'Account', render: (u: any) => <span style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 600 }}>{u.sam_account}</span> },
              { key: 'display_name', header: 'Display Name', render: (u: any) => <span style={{ fontSize: 12 }}>{u.display_name}</span> },
              { key: 'department', header: 'Dept', render: (u: any) => <span style={{ fontSize: 11, color: 'var(--text-2)' }}>{u.department}</span> },
              { key: 'is_admin', header: 'Admin', render: (u: any) => <YesNo bad={u.is_admin} /> },
              { key: 'is_service_account', header: 'Svc Acc', render: (u: any) => <span style={{ color: u.is_service_account ? '#3b82f6' : 'var(--text-3)', fontWeight: 600 }}>{u.is_service_account ? 'SVC' : '—'}</span> },
              { key: 'password_never_expires', header: 'Pwd Never Expires', render: (u: any) => u.password_never_expires
                ? <X style={{ width: 12, height: 12, color: '#f97316' }} />
                : <Check style={{ width: 12, height: 12, color: '#22c55e' }} /> },
              { key: 'last_logon', header: 'Last Logon', render: (u: any) => <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{timeAgo(u.last_logon)}</span> },
              { key: 'last_password_change', header: 'Last Pwd Change', render: (u: any) => <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{timeAgo(u.last_password_change)}</span> },
              { key: 'risk', header: 'Risk', width: '110px', render: (u: any) => <RiskBar score={u.risk_score} /> },
            ]}
          />
        </div>
        {selected && (
          <div className="g-card" style={{ flex: 1, minWidth: 260, padding: 18, position: 'sticky', top: 16, alignSelf: 'flex-start', maxWidth: 300 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 14 }}>
              <span style={{ fontSize: 14, fontWeight: 600 }}>User Details</span>
              <ActionButton variant="ghost" style={{ padding: '2px 8px', fontSize: 11 }} onClick={() => setSelected(null)}><X style={{ width: 12, height: 12 }} /></ActionButton>
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
              <ActionButton variant="ghost" style={{ fontSize: 11 }}>View Timeline</ActionButton>
              <ActionButton variant="ghost" style={{ fontSize: 11 }}>Open Incident</ActionButton>
              <ActionButton variant="danger" style={{ fontSize: 11 }}>Disable Account</ActionButton>
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
        <MetricCard label="Failed Logins" value={d.failed_logins ?? '—'} color="#ef4444" />
        <MetricCard label="Password Sprays" value={d.password_spray ?? '—'} color={d.password_spray > 0 ? '#ef4444' : undefined} />
        <MetricCard label="Brute Force" value={d.brute_force ?? '—'} color={d.brute_force > 0 ? '#ef4444' : undefined} />
        <MetricCard label="Suspicious Logons" value={d.suspicious_logons ?? '—'} color={d.suspicious_logons > 0 ? '#f97316' : undefined} />
      </div>
      <SectionCard title="Auth Protocol Status">
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
      </SectionCard>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {AUTH_FILTERS.map(f => (
          <ActionButton key={f} variant={authFilter === f ? 'primary' : 'ghost'} onClick={() => setAuthFilter(f)} style={{ fontSize: 11, textTransform: 'capitalize' }}>
            {f.replace(/_/g, ' ')}
          </ActionButton>
        ))}
      </div>
      <DataTable<any>
        rows={events}
        rowKey={(e: any) => e.id}
        columns={[
          { key: 'event_type', header: 'Event Type', render: (e: any) => (
            <span style={{ fontWeight: 600, fontSize: 11, color: e.event_type === 'failed_login' ? '#ef4444' : e.event_type === 'password_spray' ? '#a855f7' : 'var(--text-1)' }}>
              {e.event_type?.replace(/_/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase())}
            </span>
          ) },
          { key: 'severity', header: 'Severity', render: (e: any) => <SevBadge v={e.severity} /> },
          { key: 'source_user', header: 'User', render: (e: any) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{e.source_user}</span> },
          { key: 'source_computer', header: 'Source Computer', render: (e: any) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{e.source_computer}</span> },
          { key: 'source_ip', header: 'Source IP', render: (e: any) => <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-3)' }}>{e.source_ip}</span> },
          { key: 'target', header: 'Target', render: (e: any) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{e.target}</span> },
          { key: 'auth_type', header: 'Auth', render: (e: any) => <code style={{ fontSize: 10, background: 'rgba(255,255,255,0.05)', padding: '1px 5px', borderRadius: 3 }}>{e.auth_type}</code> },
          { key: 'status', header: 'Status', render: (e: any) => <SevBadge v={e.status === 'open' ? 'high' : e.status === 'investigating' ? 'medium' : 'clean'} /> },
          { key: 'time', header: 'Time', render: (e: any) => <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{timeAgo(e.created_at)}</span> },
        ]}
      />
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
        <MetricCard label="Kerberoasting" value={d.kerberoasting ?? '—'} color="#a855f7" />
        <MetricCard label="AS-REP Roasting" value={d.as_rep_roasting ?? '—'} color="#a855f7" />
        <MetricCard label="Golden Ticket" value={d.golden_ticket ?? '—'} color="#ef4444" />
        <MetricCard label="Pass-the-Hash" value={d.pass_the_hash ?? '—'} color="#ef4444" />
        <MetricCard label="DCSync" value={d.dcsync ?? '—'} color="#ef4444" />
        <MetricCard label="DCShadow" value={d.dcshadow ?? '—'} color="#dc2626" />
        <MetricCard label="Lateral Movement" value={d.lateral_movement ?? '—'} color="#3b82f6" />
        <MetricCard label="Priv Escalation" value={d.priv_escalation ?? '—'} color="#f97316" />
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        {CATEGORIES.map(cat => (
          <ActionButton key={cat.id} variant={category === cat.id ? 'primary' : 'ghost'} onClick={() => setCategory(cat.id)} style={{ fontSize: 11 }}>{cat.label}</ActionButton>
        ))}
      </div>
      <div style={{ display: 'flex', gap: 16 }}>
        <div style={{ flex: 2 }}>
          <DataTable<any>
            rows={d.attacks || []}
            rowKey={(a: any) => a.id}
            onRowClick={a => setSelected(a)}
            rowStyle={(a: any) => selected?.id === a.id ? { background: 'rgba(100,200,255,0.04)' } : undefined}
            columns={[
              { key: 'attack_type', header: 'Attack Type', render: (a: any) => (
                <span style={{ color: ATTACK_COLOR[a.attack_type] || 'var(--text-1)', fontWeight: 700, fontSize: 11 }}>
                  {a.attack_type?.replace(/_/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase())}
                </span>
              ) },
              { key: 'severity', header: 'Severity', render: (a: any) => <SevBadge v={a.severity} /> },
              { key: 'source_user', header: 'Source User', render: (a: any) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{a.source_user}</span> },
              { key: 'source_computer', header: 'Source Computer', render: (a: any) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{a.source_computer}</span> },
              { key: 'target', header: 'Target', render: (a: any) => <span style={{ fontSize: 11, maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>{a.target}</span> },
              { key: 'mitre', header: 'MITRE', render: (a: any) => <code style={{ fontSize: 10, background: 'rgba(255,255,255,0.05)', padding: '1px 5px', borderRadius: 3 }}>{a.mitre_technique}</code> },
              { key: 'status', header: 'Status', render: (a: any) => <SevBadge v={a.status === 'open' ? 'critical' : a.status === 'investigating' ? 'medium' : 'clean'} /> },
              { key: 'time', header: 'Time', render: (a: any) => <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{timeAgo(a.created_at)}</span> },
            ]}
          />
        </div>
        {selected && (
          <div className="g-card" style={{ flex: 1, minWidth: 280, padding: 18, position: 'sticky', top: 16, alignSelf: 'flex-start' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 14 }}>
              <span style={{ fontSize: 14, fontWeight: 600 }}>Attack Details</span>
              <ActionButton variant="ghost" style={{ padding: '2px 8px', fontSize: 11 }} onClick={() => setSelected(null)}><X style={{ width: 12, height: 12 }} /></ActionButton>
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
              <ActionButton variant="ghost" style={{ fontSize: 11 }}>View Timeline</ActionButton>
              <ActionButton variant="ghost" style={{ fontSize: 11 }}>Open Hunt</ActionButton>
              <ActionButton variant="danger" style={{ fontSize: 11 }}>Disable User</ActionButton>
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
          <ActionButton key={s} variant={sub === s ? 'primary' : 'ghost'} onClick={() => setSub(s)} style={{ fontSize: 11, textTransform: 'capitalize' }}>
            {s === 'gpo' ? 'GPO Changes' : s === 'changes' ? 'AD Changes' : s.charAt(0).toUpperCase() + s.slice(1)}
          </ActionButton>
        ))}
      </div>
      {sub === 'lateral' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            {LATERAL_TECHNIQUES.map(t => (
              <div key={t.tech} className="g-card" style={{ minWidth: 140, padding: '12px 16px', borderLeft: `3px solid ${t.detected ? '#ef4444' : 'var(--border)'}` }}>
                <div style={{ fontWeight: 600, fontSize: 12, color: t.detected ? '#ef4444' : 'var(--text-1)' }}>{t.tech}</div>
                <code style={{ fontSize: 10, color: 'var(--text-3)', display: 'block', marginTop: 4 }}>{t.mitre}</code>
                <div style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: 11, marginTop: 6, color: t.detected ? '#ef4444' : '#22c55e', fontWeight: 700 }}>
                  {t.detected
                    ? <><X style={{ width: 11, height: 11 }} /> {t.count} detected</>
                    : <><Check style={{ width: 11, height: 11 }} /> None detected</>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
      {sub === 'gpo' && (
        <DataTable<any>
          rows={gpoChanges}
          rowKey={(g: any) => g.id}
          columns={[
            { key: 'name', header: 'GPO Name', render: (g: any) => <span style={{ fontWeight: 600, fontSize: 12 }}>{g.name}</span> },
            { key: 'status', header: 'Status', render: (g: any) => <SevBadge v={g.status === 'modified' ? 'high' : g.status === 'created' ? 'critical' : g.status === 'enabled' ? 'medium' : 'clean'} /> },
            { key: 'linked_ous', header: 'Linked OUs', render: (g: any) => <span style={{ fontSize: 11, color: 'var(--text-2)' }}>{g.linked_ous}</span> },
            { key: 'last_modified', header: 'Last Modified', render: (g: any) => <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{timeAgo(g.last_modified)}</span> },
          ]}
        />
      )}
      {sub === 'changes' && (
        <DataTable<any>
          rows={adChanges}
          rowKey={(ch: any) => ch.id}
          columns={[
            { key: 'event_type', header: 'Change Type', render: (ch: any) => <span style={{ fontWeight: 600, fontSize: 11 }}>{ch.event_type?.replace(/_/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase())}</span> },
            { key: 'severity', header: 'Severity', render: (ch: any) => <SevBadge v={ch.severity} /> },
            { key: 'source_user', header: 'Actor', render: (ch: any) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{ch.source_user}</span> },
            { key: 'target', header: 'Target', render: (ch: any) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{ch.target}</span> },
            { key: 'description', header: 'Description', render: (ch: any) => <span style={{ fontSize: 11, color: 'var(--text-2)', maxWidth: 280, display: 'block' }}>{ch.description}</span> },
            { key: 'status', header: 'Status', render: (ch: any) => <SevBadge v={ch.status === 'open' ? 'critical' : ch.status === 'investigating' ? 'medium' : 'clean'} /> },
            { key: 'time', header: 'Time', render: (ch: any) => <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{timeAgo(ch.created_at)}</span> },
          ]}
        />
      )}
      {sub === 'tiering' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {[
            { label: 'Tier 0 — Control Plane', assets: tier.tier0_assets || [], color: '#ef4444', desc: 'Domain Controllers' },
            { label: 'Tier 1 — Server Administration', assets: tier.tier1_assets || [], color: '#f97316', desc: 'Server Admins' },
            { label: 'Tier 2 — Workstation / User', assets: tier.tier2_assets || [], color: '#22c55e', desc: 'Workstations, Standard Users' },
          ].map(tierRow => (
            <div key={tierRow.label} className="g-card" style={{ padding: 20, borderLeft: `4px solid ${tierRow.color}` }}>
              <div style={{ fontWeight: 700, fontSize: 14, color: tierRow.color, marginBottom: 4 }}>{tierRow.label}</div>
              <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 16 }}>{tierRow.desc}</div>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                {tierRow.assets.map((a: any) => (
                  <div key={a.name} style={{ padding: '8px 14px', background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid var(--border)' }}>
                    <div style={{ fontSize: 13, fontWeight: 700, color: tierRow.color }}>{a.count}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-2)' }}>{a.name}</div>
                  </div>
                ))}
              </div>
            </div>
          ))}
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
  const NODE_ICON: Record<string, any> = { domain_controller: Server, user: User, service_account: Settings, group: Users, computer: Laptop, gpo: ClipboardList };
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
          <ActionButton key={s} variant={sub === s ? 'primary' : 'ghost'} onClick={() => setSub(s)} style={{ fontSize: 11, textTransform: 'capitalize' }}>
            {s === 'intel' ? 'Threat Intel' : s === 'ai' ? 'AI Analysis' : s.charAt(0).toUpperCase() + s.slice(1)}
          </ActionButton>
        ))}
      </div>
      {sub === 'intel' && (
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          <SectionCard title="IOC Matches" className="flex-1">
            <div style={{ minWidth: 260 }}>
              {(ti.ioc_matches || []).map((ioc: any) => (
                <div key={ioc.value} style={{ marginBottom: 10, padding: '8px 10px', background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid var(--border)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <code style={{ fontSize: 11 }}>{ioc.value}</code>
                    <span style={{ fontSize: 11, fontWeight: 700, color: '#ef4444' }}>{ioc.hits} hits</span>
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 3 }}>{ioc.type?.toUpperCase()}</div>
                </div>
              ))}
              {(ti.ioc_matches || []).length === 0 && <div style={{ fontSize: 11, color: 'var(--text-3)' }}>No IOC matches yet.</div>}
            </div>
          </SectionCard>
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
          <SectionCard title="AI Analysis" className="flex-1">
            <div style={{ minWidth: 340 }}>
              <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
                {(['event', 'user', 'ask'] as const).map(m => (
                  <ActionButton key={m} variant={aiMode === m ? 'primary' : 'ghost'} onClick={() => setAiMode(m)} style={{ fontSize: 11, padding: '4px 10px', textTransform: 'capitalize' }}>{m}</ActionButton>
                ))}
              </div>
              <textarea className="g-input" rows={4} style={{ width: '100%', resize: 'vertical' as const, fontFamily: 'monospace', fontSize: 12 }}
                placeholder={aiMode === 'event' ? 'Paste AD security event or alert details...' : aiMode === 'user' ? 'Describe the user behavior to analyze...' : 'Ask an Active Directory security question...'}
                value={aiInput} onChange={e => setAiInput(e.target.value)} />
              <ActionButton variant="primary" style={{ marginTop: 10, width: '100%', justifyContent: 'center' }} onClick={doAI} loading={aiLoading} disabled={!aiInput.trim()}>
                {aiLoading ? 'Analyzing...' : 'Analyze with AI'}
              </ActionButton>
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
          </SectionCard>
        </div>
      )}
      {sub === 'graph' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <SectionCard title="AD Relationship Graph" subtitle="Nodes show risk level. Click a node to see relationships.">
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'center' }}>
              {(g.nodes || []).map((node: any) => {
                const NodeIcon = NODE_ICON[node.type] || Zap;
                return (
                  <div key={node.id} style={{ textAlign: 'center' as const }}>
                    <div style={{ padding: '10px 14px', borderRadius: 10, background: `${NODE_COLOR[node.type] || 'var(--accent)'}22`, border: `2px solid ${NODE_COLOR[node.type] || 'var(--accent)'}44`, cursor: 'pointer', transition: 'all 0.2s' }}>
                      <NodeIcon style={{ width: 20, height: 20, color: NODE_COLOR[node.type] || 'var(--accent)', margin: '0 auto' }} />
                      <div style={{ fontSize: 11, fontWeight: 700, color: NODE_COLOR[node.type] || 'var(--accent)', marginTop: 4 }}>{node.label}</div>
                      <div style={{ fontSize: 9, color: 'var(--text-3)', marginTop: 2 }}>{node.type?.replace(/_/g, ' ')}</div>
                      <div style={{ fontSize: 10, fontWeight: 700, color: node.risk >= 80 ? '#ef4444' : node.risk >= 60 ? '#f97316' : '#22c55e', marginTop: 4 }}>Risk: {node.risk}</div>
                      {node.members && <div style={{ fontSize: 9, color: 'var(--text-3)' }}>{node.members} members</div>}
                    </div>
                  </div>
                );
              })}
            </div>
          </SectionCard>
          <SectionCard title="Attack Edges (Critical Paths)">
            <DataTable<any>
              rows={g.edges || []}
              rowKey={(e: any, i: number) => i}
              columns={[
                { key: 'source', header: 'Source', render: (e: any) => (
                  <span style={{ fontFamily: 'monospace', fontSize: 11, color: NODE_COLOR[(g.nodes || []).find((n: any) => n.id === e.source)?.type] || 'var(--text-1)', fontWeight: 600 }}>
                    {(g.nodes || []).find((n: any) => n.id === e.source)?.label}
                  </span>
                ) },
                { key: 'label', header: 'Relationship', render: (e: any) => <code style={{ fontSize: 10, background: 'rgba(255,255,255,0.05)', padding: '2px 8px', borderRadius: 3 }}>{e.label}</code> },
                { key: 'target', header: 'Target', render: (e: any) => (
                  <span style={{ fontFamily: 'monospace', fontSize: 11, color: NODE_COLOR[(g.nodes || []).find((n: any) => n.id === e.target)?.type] || 'var(--text-1)', fontWeight: 600 }}>
                    {(g.nodes || []).find((n: any) => n.id === e.target)?.label}
                  </span>
                ) },
                { key: 'risk', header: 'Risk', render: (e: any) => <SevBadge v={e.risk} /> },
              ]}
            />
          </SectionCard>
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
        <ActionButton variant={sub === 'analytics' ? 'primary' : 'ghost'} onClick={() => setSub('analytics')}>Analytics</ActionButton>
        <ActionButton variant={sub === 'assessment' ? 'primary' : 'ghost'} onClick={() => setSub('assessment')}>Security Assessment</ActionButton>
      </div>
      {sub === 'analytics' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <MetricCard label="Total Attacks" value={a.total_attacks ?? '—'} color="#ef4444" />
            <MetricCard label="Kerberoasting" value={a.kerberoasting ?? '—'} color="#a855f7" />
            <MetricCard label="Pass-the-Hash" value={a.pass_the_hash ?? '—'} color="#ef4444" />
            <MetricCard label="DCSync Attempts" value={a.dcsync_attempts ?? '—'} color="#ef4444" />
            <MetricCard label="Priv Escalations" value={a.priv_escalations ?? '—'} color="#f97316" />
            <MetricCard label="New Admins (7d)" value={a.new_admins_7d ?? '—'} color={a.new_admins_7d > 0 ? '#ef4444' : undefined} />
          </div>
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
            <SectionCard title="Authentication Events — 14 Day Trend" className="flex-1">
              <div style={{ display: 'flex', alignItems: 'flex-end', gap: 3, height: 80, paddingBottom: 24, minWidth: 300 }}>
                {(a.auth_trend || []).map((p: any) => (
                  <div key={p.date} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, height: '100%', justifyContent: 'flex-end' }}>
                    <div style={{ width: '80%', background: 'var(--accent)', borderRadius: 2, height: `${(p.count / maxAuth) * 56 + 4}px`, minHeight: 4 }} />
                    <span style={{ fontSize: 9, color: 'var(--text-3)' }}>{p.date?.slice(5)}</span>
                  </div>
                ))}
              </div>
            </SectionCard>
            <SectionCard title="Attack Breakdown" className="flex-1">
              <div style={{ minWidth: 260 }}>
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
            </SectionCard>
          </div>
          <SectionCard title="Top Failed Logins">
            <DataTable<any>
              rows={a.top_failed_logins || []}
              rowKey={(f: any, i: number) => i}
              columns={[
                { key: 'user', header: 'User', render: (f: any) => <span style={{ fontFamily: 'monospace', fontWeight: 600 }}>{f.user}</span> },
                { key: 'count', header: 'Failed Count', render: (f: any) => <span style={{ color: f.count > 30 ? '#ef4444' : f.count > 15 ? '#f97316' : 'var(--text-1)', fontWeight: 700, fontSize: 14 }}>{f.count}</span> },
                { key: 'source_ip', header: 'Source IP', render: (f: any) => <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-3)' }}>{f.source_ip}</span> },
              ]}
            />
          </SectionCard>
        </div>
      )}
      {sub === 'assessment' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
            <MetricCard label="AD Hygiene Score" value={`${ass.overall_score ?? '—'}%`} color={ass.overall_score >= 80 ? '#22c55e' : ass.overall_score >= 60 ? '#f97316' : '#ef4444'} />
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
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6, fontSize: 11, padding: '8px 12px', background: 'rgba(34,197,94,0.05)', border: '1px solid rgba(34,197,94,0.15)', borderRadius: 6, color: '#4ade80' }}>
                  <Lightbulb style={{ width: 13, height: 13, flexShrink: 0, marginTop: 1 }} /> {check.remediation}
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
  const [msgErr, setMsgErr] = useState(false);
  const [reportType, setReportType] = useState('executive');
  const [reportResult, setReportResult] = useState<any>(null);
  const [reportLoading, setReportLoading] = useState(false);
  useEffect(() => { adSecurityAPI.getAttackPaths().then(r => setAttackPaths(r.data)); }, []);
  const ap = attackPaths || {};
  const ACTIONS = [
    { id: 'disable_user', label: 'Disable User', desc: 'Disable AD account immediately', color: '#ef4444' },
    { id: 'reset_password', label: 'Reset Password', desc: 'Force password change on next login', color: '#f97316' },
    { id: 'force_ticket_renewal', label: 'Force Ticket Renewal', desc: 'Invalidate all Kerberos TGTs', color: '#a855f7' },
    { id: 'remove_group_membership', label: 'Remove Group Membership', desc: 'Remove from privileged group', color: '#f97316' },
    { id: 'disable_service_account', label: 'Disable Service Account', desc: 'Disable service account', color: '#ef4444' },
    { id: 'isolate_endpoint', label: 'Isolate Endpoint', desc: 'Send isolation to EDR', color: '#3b82f6' },
  ];
  const doAction = async () => {
    try {
      const r = await adSecurityAPI.respond({ action, target, reason });
      setMsg(r.data?.message || 'Action executed');
      setMsgErr(false);
    } catch (err: any) {
      setMsg(err?.response?.data?.error || 'Action failed');
      setMsgErr(true);
    }
    setTimeout(() => setMsg(''), 5000);
  };
  const doReport = async () => {
    setReportLoading(true);
    const r = await adSecurityAPI.generateReport({ report_type: reportType });
    setReportResult(r.data);
    setReportLoading(false);
  };
  const riskIdentities = ap.risk_identities || [];
  const riskComputers = ap.risk_computers || [];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <SectionCard title="Top Risk Factors">
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 280 }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-3)', textTransform: 'uppercase' as const, marginBottom: 8 }}>Highest-Risk Privileged Identities</div>
            {riskIdentities.length === 0 && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No admin/service accounts found.</div>}
            {riskIdentities.map((u: any) => (
              <div key={u.sam_account} style={{ marginBottom: 8, padding: '8px 10px', background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <code style={{ fontSize: 11, fontWeight: 600 }}>{u.sam_account}</code>
                  <span style={{ fontSize: 11, fontWeight: 700, color: u.risk_score >= 80 ? '#ef4444' : u.risk_score >= 60 ? '#f97316' : '#22c55e' }}>{u.risk_score}</span>
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>{u.display_name} · {u.is_admin ? 'admin' : 'service account'}</div>
              </div>
            ))}
          </div>
          <div style={{ flex: 1, minWidth: 280 }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-3)', textTransform: 'uppercase' as const, marginBottom: 8 }}>Computers with Unconstrained Delegation</div>
            {riskComputers.length === 0 && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>None found.</div>}
            {riskComputers.map((cmp: any) => (
              <div key={cmp.name} style={{ marginBottom: 8, padding: '8px 10px', background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <code style={{ fontSize: 11, fontWeight: 600 }}>{cmp.name}</code>
                  <span style={{ fontSize: 11, fontWeight: 700, color: cmp.risk_score >= 80 ? '#ef4444' : cmp.risk_score >= 60 ? '#f97316' : '#22c55e' }}>{cmp.risk_score}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </SectionCard>
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        <SectionCard title="Response Actions" className="flex-1">
          <div style={{ minWidth: 340 }}>
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
              <a href="/timeline" className="g-btn g-btn-ghost" style={{ fontSize: 11 }}>Open Timeline</a>
              <a href="/hunt-workbench" className="g-btn g-btn-ghost" style={{ fontSize: 11 }}>Start Hunt</a>
              <a href="/log-search" className="g-btn g-btn-ghost" style={{ fontSize: 11 }}>Log Search</a>
            </div>
            <ActionButton variant="primary" style={{ width: '100%', justifyContent: 'center' }} onClick={doAction}>
              Execute: {ACTIONS.find(a => a.id === action)?.label}
            </ActionButton>
            <a href="/playbooks" className="g-btn g-btn-ghost" style={{ marginTop: 8, width: '100%', justifyContent: 'center', display: 'flex' }}>
              Run SOAR Playbook
            </a>
            {msg && (
              <div style={{ marginTop: 12, padding: '10px 14px', background: msgErr ? 'rgba(239,68,68,0.1)' : 'rgba(34,197,94,0.1)', border: `1px solid ${msgErr ? 'rgba(239,68,68,0.3)' : 'rgba(34,197,94,0.3)'}`, borderRadius: 6, fontSize: 12, color: msgErr ? '#f87171' : '#4ade80' }}>{msg}</div>
            )}
          </div>
        </SectionCard>
        <SectionCard title="Generate Report" className="flex-1">
          <div style={{ minWidth: 300 }}>
            <select className="g-select" value={reportType} onChange={e => setReportType(e.target.value)} style={{ width: '100%', marginBottom: 12 }}>
              <option value="executive">Executive Summary</option>
              <option value="technical">Technical Deep Dive</option>
              <option value="incident">Incident Report</option>
              <option value="compliance">Compliance Report</option>
            </select>
            <ActionButton variant="primary" style={{ width: '100%', justifyContent: 'center' }} onClick={doReport} loading={reportLoading}>
              {reportLoading ? 'Generating...' : 'Generate with AI'}
            </ActionButton>
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
        </SectionCard>
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
    <RootLayout title="Active Directory Security"
      subtitle="Identity attack detection, Kerberos analysis, credential attack monitoring, and AD hygiene assessment.">
    <div style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: 4 }}>
        <TabBar
          tabs={visibleTabs.map(t => ({ key: t, label: TAB_LABELS[t], icon: TAB_ICONS[t] }))}
          active={tab}
          onChange={t => setTab(t as Tab)}
        />
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
    </RootLayout>
  );
}
