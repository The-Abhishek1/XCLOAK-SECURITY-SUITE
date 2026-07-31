'use client';
import { useState, useEffect, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import {
  stteAPI, usersAPI, auditAPI, apiKeysAPI, customRolesAPI,
  sessionsAPI, securityPolicyAPI, integrationsAPI, notificationsAPI,
} from '@/lib/api';
import { useUser } from '@/context/UserContext';
import {
  DataTable, EmptyState, SectionCard, TabBar, ActionButton, MetricCard, LoadingSkeleton,
} from '@/components/design-system';
import {
  Building2, ShieldCheck, Plug, Sparkles, Server,
  Send, Plus, UserCheck, UserX, Trash2, KeyRound, Copy, Save,
  RefreshCw, Download, CheckCircle2, Zap, RotateCcw, Power, CheckCheck,
} from 'lucide-react';

/* ── helpers ─────────────────────────────────────────────────────────────── */
const PILL: Record<string, string> = {
  active: '#16a34a', inactive: '#6b7280', admin: '#7c3aed', analyst: '#2563eb',
  viewer: '#0891b2', manager: '#ea580c', completed: '#16a34a', failed: '#dc2626',
  running: '#d97706', enterprise: '#7c3aed', professional: '#2563eb',
  community: '#6b7280', trial: '#d97706', stable: '#16a34a', beta: '#d97706',
  enabled: '#16a34a', disabled: '#6b7280', connected: '#16a34a', error: '#dc2626',
};
function pill(label: string, color?: string) {
  const bg = color ?? PILL[label?.toLowerCase()] ?? '#6b7280';
  return (
    <span style={{
      background: bg + '22', color: bg, border: `1px solid ${bg}55`,
      borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600,
      textTransform: 'uppercase', letterSpacing: 0.5, whiteSpace: 'nowrap',
    }}>{label}</span>
  );
}

function Toggle({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) {
  return (
    <div onClick={() => onChange(!value)} style={{
      width: 44, height: 24, borderRadius: 12, cursor: 'pointer',
      background: value ? 'var(--accent)' : 'var(--border)',
      position: 'relative', transition: 'background 0.2s', flexShrink: 0,
    }}>
      <div style={{
        position: 'absolute', top: 2, width: 20, height: 20, borderRadius: '50%',
        background: '#fff', transition: 'left 0.2s',
        left: value ? 22 : 2,
        boxShadow: '0 1px 3px rgba(0,0,0,0.3)',
      }} />
    </div>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', padding: 'var(--space-3) 0', borderBottom: '1px solid var(--border)' }}>
      <div style={{ flex: 1, paddingRight: 24 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)' }}>{label}</div>
        {hint && <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 2 }}>{hint}</div>}
      </div>
      <div style={{ flexShrink: 0 }}>{children}</div>
    </div>
  );
}

function SaveBar({ onSave, saving, label = 'Save Changes' }: { onSave: () => void; saving: boolean; label?: string }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 'var(--space-5)' }}>
      <ActionButton variant="primary" icon={Save} onClick={onSave} disabled={saving} style={{ minWidth: 130 }}>
        {saving ? 'Saving…' : label}
      </ActionButton>
    </div>
  );
}

/* ── navigation structure ────────────────────────────────────────────────── */
const TOP_TABS = [
  { key: 'general',      label: 'General',      icon: Building2 },
  { key: 'security',     label: 'Security',     icon: ShieldCheck },
  { key: 'integrations', label: 'Integrations', icon: Plug },
  { key: 'ai',           label: 'AI',           icon: Sparkles },
  { key: 'system',       label: 'System',       icon: Server },
];

const SIDEBAR: Record<string, { key: string; label: string }[]> = {
  general: [
    { key: 'organization', label: 'Organization' }, { key: 'users', label: 'Users & RBAC' },
  ],
  security: [
    { key: 'authentication', label: 'Authentication' }, { key: 'agents', label: 'Agents' },
  ],
  integrations: [
    { key: 'integrations', label: 'Integrations' }, { key: 'notifications', label: 'Notifications' },
  ],
  ai: [
    { key: 'ai-models', label: 'Models' }, { key: 'ai-guardrails', label: 'Guardrails' }, { key: 'ai-usage', label: 'Usage Limits' },
  ],
  system: [
    { key: 'backup', label: 'Backup & Recovery' }, { key: 'api-management', label: 'API Management' },
    { key: 'updates', label: 'Updates' }, { key: 'licensing', label: 'Licensing' },
    { key: 'audit', label: 'Audit Trail' },
  ],
};

const DEFAULT_SECTION: Record<string, string> = {
  general: 'organization', security: 'authentication',
  integrations: 'integrations', ai: 'ai-models', system: 'backup',
};

/* ── main component ───────────────────────────────────────────────────────── */
export default function SettingsEnterprise() {
  const { profile: user } = useUser();
  const [topTab, setTopTab]   = useState('general');
  const [section, setSection] = useState('organization');
  const [data, setData]       = useState<any>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving]   = useState(false);
  const [msg, setMsg]         = useState('');

  // form state
  const [org, setOrg]                 = useState<any>({});
  const [secPolicy, setSecPolicy]     = useState<any>({});
  const [agentCfg, setAgentCfg]       = useState<any>({});
  const [aiGuard, setAiGuard]         = useState<any>({});
  const [backupCfg, setBackupCfg]     = useState<any>({});

  // invite form
  const [inviteUser, setInviteUser]   = useState('');
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole]   = useState('analyst');
  const [inviting, setInviting]       = useState(false);

  // api key form
  const [keyLabel, setKeyLabel] = useState('');
  const [keyRole, setKeyRole]   = useState('analyst');
  const [newKey, setNewKey]     = useState('');

  // custom role form
  const [roleName, setRoleName] = useState('');

  // license key
  const [licKey, setLicKey] = useState('');
  const [activating, setActivating] = useState(false);

  // integration test
  const [testingIntg, setTestingIntg] = useState('');

  function flash(m: string) { setMsg(m); setTimeout(() => setMsg(''), 3000); }

  const loadAll = useCallback(async () => {
    setLoading(true);
    const [orgRes, spRes, agCfgRes, liRes, intgRes, usersRes, rolesRes, keysRes,
      sessRes, auditRes, backupRes, updRes, aiRes, notifRes, stteAuditRes] = await Promise.all([
      stteAPI.getOrg(),
      securityPolicyAPI.get().catch(() => ({ data: null })),
      stteAPI.getAgentsConfig(),
      stteAPI.getLicense(),
      integrationsAPI.getAll(),
      usersAPI.getAll().catch(() => ({ data: [] })),
      customRolesAPI.getAll().catch(() => ({ data: [] })),
      apiKeysAPI.getAll().catch(() => ({ data: [] })),
      sessionsAPI.getAll().catch(() => ({ data: [] })),
      auditAPI.getPaginated(1, 50).catch(() => ({ data: { logs: [] } })),
      stteAPI.getBackups(),
      stteAPI.getUpdates(),
      stteAPI.getAIConfig(),
      notificationsAPI.getEmailRules().catch(() => ({ data: [] })),
      stteAPI.getAudit(),
    ]);
    const orgData = orgRes?.data ?? {};
    const spData  = spRes?.data ?? {};
    const agData  = agCfgRes?.data ?? {};
    const aiData  = aiRes?.data ?? {};
    setOrg(orgData);
    setSecPolicy(spData);
    setAgentCfg(agData);
    setAiGuard(aiData?.guardrails ?? {});
    setBackupCfg(backupRes?.data?.config ?? {});
    setData({
      license:    liRes?.data ?? null,
      integrations: Array.isArray(intgRes?.data) ? intgRes.data : [],
      users:      Array.isArray(usersRes?.data) ? usersRes.data : [],
      roles:      Array.isArray(rolesRes?.data) ? rolesRes.data : [],
      keys:       Array.isArray(keysRes?.data) ? keysRes.data : [],
      sessions:   Array.isArray(sessRes?.data) ? sessRes.data : [],
      auditLogs:  Array.isArray(auditRes?.data?.logs) ? auditRes.data.logs : (Array.isArray(auditRes?.data) ? auditRes.data : []),
      backups:    backupRes?.data?.jobs ?? [],
      updates:    updRes?.data ?? null,
      aiProviders:aiData?.providers ?? [],
      notifRules: Array.isArray(notifRes?.data) ? notifRes.data : [],
      stteAudit:  Array.isArray(stteAuditRes?.data) ? stteAuditRes.data : [],
    });
    setLoading(false);
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  function switchTop(t: string) {
    setTopTab(t);
    setSection(DEFAULT_SECTION[t] ?? t);
  }

  // ── savers ─────────────────────────────────────────────────────────────────
  function fail(err: any, fallback: string) {
    flash(err?.response?.data?.error || fallback);
  }

  async function saveOrg() {
    setSaving(true);
    try { await stteAPI.updateOrg(org); flash('Organization settings saved.'); }
    catch (err: any) { fail(err, 'Failed to save organization settings.'); }
    finally { setSaving(false); }
  }

  async function saveSecPolicy() {
    setSaving(true);
    try { await securityPolicyAPI.update(secPolicy); flash('Security policy saved.'); }
    catch (err: any) { fail(err, 'Failed to save security policy.'); }
    finally { setSaving(false); }
  }

  async function saveAgentCfg() {
    setSaving(true);
    try { await stteAPI.updateAgentsConfig(agentCfg); flash('Agent configuration saved.'); }
    catch (err: any) { fail(err, 'Failed to save agent configuration.'); }
    finally { setSaving(false); }
  }

  async function saveAIGuardrails() {
    setSaving(true);
    try { await stteAPI.updateAIConfig(aiGuard); flash('AI guardrails saved.'); }
    catch (err: any) { fail(err, 'Failed to save AI guardrails.'); }
    finally { setSaving(false); }
  }

  async function saveBackupCfg() {
    setSaving(true);
    try { await stteAPI.updateBackupConfig(backupCfg); flash('Backup configuration saved.'); }
    catch (err: any) { fail(err, 'Failed to save backup configuration.'); }
    finally { setSaving(false); }
  }

  async function doInvite() {
    if (!inviteUser || !inviteEmail) return;
    setInviting(true);
    try {
      await usersAPI.invite(inviteUser, inviteEmail, inviteRole);
      setInviteUser(''); setInviteEmail('');
      flash('Invitation sent.'); loadAll();
    } catch (err: any) { fail(err, 'Failed to send invitation.'); }
    finally { setInviting(false); }
  }

  async function createKey() {
    if (!keyLabel) return;
    try {
      const res = await apiKeysAPI.create(keyLabel, keyRole);
      setNewKey(res?.data?.key ?? res?.data?.raw_key ?? '');
      setKeyLabel(''); loadAll();
    } catch (err: any) { fail(err, 'Error creating API key.'); }
  }

  async function activateLicense() {
    if (!licKey) return;
    setActivating(true);
    try {
      const res = await stteAPI.activateLicense({ license_key: licKey });
      flash(`License activated — tier: ${res?.data?.tier ?? 'enterprise'}`);
      setLicKey(''); loadAll();
    } catch (err: any) { fail(err, 'License activation failed.'); }
    finally { setActivating(false); }
  }

  async function triggerBackup() {
    try {
      await stteAPI.triggerBackup();
      flash('Backup completed.'); loadAll();
    } catch (err: any) { fail(err, 'Backup failed.'); }
  }

  async function checkUpdates() {
    try {
      const res = await stteAPI.checkUpdates();
      flash(res?.data?.message ?? 'Update check complete.');
    } catch (err: any) { fail(err, 'Failed to check for updates.'); }
  }

  async function testIntegration(name: string) {
    setTestingIntg(name);
    try { await integrationsAPI.test(name); flash(`${name}: connection test passed.`); }
    catch { flash(`${name}: connection test failed.`); }
    finally { setTestingIntg(''); }
  }

  const d = data;
  const sidebarItems = SIDEBAR[topTab] ?? [];

  return (
    <RootLayout title="Settings" subtitle="Platform configuration and administration" onRefresh={loadAll}>
      <div className="space-y-4">
        {msg && (
          <div className="flex items-center gap-2" style={{ background: 'var(--green-bg)', color: 'var(--green)', border: '1px solid var(--green-border)', borderRadius: 'var(--radius-md)', padding: '8px 16px', fontSize: 13 }}>
            <CheckCheck className="h-3.5 w-3.5" />
            {msg}
          </div>
        )}

        {/* Top-level tabs */}
        <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: 2 }}>
          <TabBar tabs={TOP_TABS} active={topTab} onChange={switchTop} />
        </div>

        {/* Sub-section tabs */}
        {sidebarItems.length > 1 && (
          <TabBar tabs={sidebarItems} active={section} onChange={setSection} />
        )}

        {/* ── content ─────────────────────────────────────────────────── */}
        <div>
          {loading ? (
            <LoadingSkeleton variant="card" count={4} />
          ) : (
            <>
              {/* ════════════════════════ ORGANIZATION ══════════════════ */}
              {section === 'organization' && (
                <div style={{ maxWidth: 700 }}>
                  <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Organization</h2>
                  <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 'var(--space-6)' }}>Configure your organization profile and platform-wide defaults.</p>
                  <SectionCard padded={false}>
                    <div className="px-4">
                      <Field label="Organization Name" hint="Displayed in the top navigation and reports">
                        <input className="g-input" value={org.org_name ?? ''} onChange={e => setOrg({ ...org, org_name: e.target.value })} style={{ width: 220 }} />
                      </Field>
                      <Field label="Display Name" hint="Short name shown in notifications and emails">
                        <input className="g-input" value={org.display_name ?? ''} onChange={e => setOrg({ ...org, display_name: e.target.value })} style={{ width: 220 }} />
                      </Field>
                      <Field label="Primary Domain" hint="Your organization's email domain (e.g. corp.example.com)">
                        <input className="g-input" value={org.domain ?? ''} onChange={e => setOrg({ ...org, domain: e.target.value })} style={{ width: 220 }} />
                      </Field>
                      <Field label="Contact Email" hint="Security operations contact email">
                        <input className="g-input" type="email" value={org.contact_email ?? ''} onChange={e => setOrg({ ...org, contact_email: e.target.value })} style={{ width: 220 }} />
                      </Field>
                      <Field label="Support Email" hint="Escalation contact for platform issues">
                        <input className="g-input" type="email" value={org.support_email ?? ''} onChange={e => setOrg({ ...org, support_email: e.target.value })} style={{ width: 220 }} />
                      </Field>
                      <Field label="Timezone" hint="Default timezone for reports and alerts">
                        <select className="g-input" value={org.timezone ?? 'UTC'} onChange={e => setOrg({ ...org, timezone: e.target.value })} style={{ width: 200 }}>
                          {['UTC','America/New_York','America/Chicago','America/Denver','America/Los_Angeles',
                            'Europe/London','Europe/Paris','Europe/Berlin','Asia/Tokyo','Asia/Singapore','Australia/Sydney'].map(tz => (
                            <option key={tz} value={tz}>{tz}</option>
                          ))}
                        </select>
                      </Field>
                      <Field label="Locale" hint="Date/number formatting locale">
                        <select className="g-input" value={org.locale ?? 'en-US'} onChange={e => setOrg({ ...org, locale: e.target.value })} style={{ width: 200 }}>
                          {['en-US','en-GB','de-DE','fr-FR','ja-JP','zh-CN'].map(l => <option key={l} value={l}>{l}</option>)}
                        </select>
                      </Field>
                      <Field label="Data Retention" hint="How long raw event data is stored (days)">
                        <input className="g-input" type="number" min={30} max={3650} value={org.data_retention_days ?? 365} onChange={e => setOrg({ ...org, data_retention_days: parseInt(e.target.value) })} style={{ width: 100 }} />
                      </Field>
                      <Field label="Max Agents" hint="Maximum enrolled agents for this tenant">
                        <input className="g-input" type="number" min={1} value={org.max_agents ?? 1000} onChange={e => setOrg({ ...org, max_agents: parseInt(e.target.value) })} style={{ width: 100 }} />
                      </Field>
                      <div style={{ padding: 'var(--space-3) 0' }}>
                        <Field label="Maintenance Mode" hint="Show maintenance banner to all users">
                          <Toggle value={org.maintenance_mode ?? false} onChange={v => setOrg({ ...org, maintenance_mode: v })} />
                        </Field>
                      </div>
                    </div>
                  </SectionCard>
                  <SaveBar onSave={saveOrg} saving={saving} />
                </div>
              )}

              {/* ════════════════════════ USERS & RBAC ══════════════════ */}
              {section === 'users' && (
                <div>
                  <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Users & RBAC</h2>
                  <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 'var(--space-6)' }}>Manage users, roles, and access control.</p>

                  <SectionCard title="Invite User" className="mb-5">
                    <div className="flex gap-2.5 flex-wrap">
                      <input className="g-input" placeholder="Username" value={inviteUser} onChange={e => setInviteUser(e.target.value)} style={{ flex: 1, minWidth: 140 }} />
                      <input className="g-input" type="email" placeholder="Email" value={inviteEmail} onChange={e => setInviteEmail(e.target.value)} style={{ flex: 1, minWidth: 180 }} />
                      <select className="g-input" value={inviteRole} onChange={e => setInviteRole(e.target.value)} style={{ minWidth: 120 }}>
                        <option value="viewer">Viewer</option>
                        <option value="analyst">Analyst</option>
                        <option value="manager">Manager</option>
                        <option value="admin">Admin</option>
                      </select>
                      <ActionButton variant="primary" icon={Send} disabled={inviting || !inviteUser || !inviteEmail} onClick={doInvite}>
                        {inviting ? 'Inviting…' : 'Send Invite'}
                      </ActionButton>
                    </div>
                  </SectionCard>

                  <SectionCard title={`Users (${(d.users ?? []).length})`} className="mb-5" padded={false}>
                    <DataTable<any>
                      rows={d.users ?? []}
                      rowKey={(u: any, i: number) => u.id ?? i}
                      emptyState={<EmptyState title="No users" />}
                      columns={[
                        { key: 'username', header: 'Username', render: (u: any) => <span style={{ fontWeight: 600 }}>{u.username}</span> },
                        { key: 'email', header: 'Email', render: (u: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{u.email}</span> },
                        { key: 'role', header: 'Role', render: (u: any) => (
                          <select className="g-input" value={u.role} style={{ fontSize: 12, padding: '2px 6px' }}
                            onChange={e => usersAPI.updateRole(u.id, e.target.value).then(loadAll).catch((err: any) => fail(err, 'Failed to update role.'))}>
                            <option value="viewer">viewer</option>
                            <option value="analyst">analyst</option>
                            <option value="manager">manager</option>
                            <option value="admin">admin</option>
                          </select>
                        ) },
                        { key: 'is_active', header: 'Status', render: (u: any) => pill(u.is_active ? 'active' : 'inactive') },
                        { key: 'actions', header: 'Actions', render: (u: any) => (
                          <div style={{ display: 'flex', gap: 6 }}>
                            <ActionButton variant="ghost" icon={u.is_active ? UserX : UserCheck} style={{ fontSize: 11, padding: '4px 10px' }}
                              onClick={() => usersAPI.toggle(u.id, !u.is_active).then(loadAll).catch((err: any) => fail(err, 'Failed to update user status.'))}>
                              {u.is_active ? 'Deactivate' : 'Activate'}
                            </ActionButton>
                            {u.username !== user?.username && (
                              <ActionButton variant="danger" icon={Trash2} style={{ fontSize: 11, padding: '4px 10px' }}
                                onClick={() => { if (window.confirm(`Delete ${u.username}?`)) usersAPI.delete(u.id).then(loadAll).catch((err: any) => fail(err, 'Failed to delete user.')); }}>
                                Delete
                              </ActionButton>
                            )}
                          </div>
                        ) },
                      ]}
                    />
                  </SectionCard>

                  <SectionCard title="Custom Roles">
                    <div className="flex gap-2.5 mb-4">
                      <input className="g-input" placeholder="Role name" value={roleName} onChange={e => setRoleName(e.target.value)} style={{ flex: 1 }} />
                      <ActionButton variant="primary" icon={Plus} disabled={!roleName}
                        onClick={() => customRolesAPI.create(roleName, []).then(() => { setRoleName(''); loadAll(); })}>
                        Create Role
                      </ActionButton>
                    </div>
                    <DataTable<any>
                      rows={d.roles ?? []}
                      rowKey={(r: any, i: number) => r.id ?? i}
                      emptyState={<EmptyState title="No custom roles" />}
                      columns={[
                        { key: 'name', header: 'Role', render: (r: any) => <span style={{ fontWeight: 600 }}>{r.name}</span> },
                        { key: 'permissions', header: 'Permissions', render: (r: any) => (
                          <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{(r.permissions ?? []).slice(0, 3).join(', ')}{r.permissions?.length > 3 ? ` +${r.permissions.length - 3} more` : ''}</span>
                        ) },
                        { key: 'actions', header: 'Actions', render: (r: any) => (
                          <ActionButton variant="danger" icon={Trash2} style={{ fontSize: 11, padding: '4px 10px' }}
                            onClick={() => { if (window.confirm(`Delete role ${r.name}?`)) customRolesAPI.delete(r.id).then(loadAll).catch((err: any) => fail(err, 'Failed to delete role.')); }}>
                            Delete
                          </ActionButton>
                        ) },
                      ]}
                    />
                  </SectionCard>
                </div>
              )}

              {/* ════════════════════════ AUTHENTICATION ════════════════ */}
              {section === 'authentication' && (
                <div style={{ maxWidth: 700 }}>
                  <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Authentication</h2>
                  <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 'var(--space-6)' }}>Configure MFA, sessions, password policy, and SSO.</p>

                  <SectionCard title="MFA & Session" padded={false} className="mb-5">
                    <div className="px-4">
                      <Field label="Require MFA for All Users" hint="Enforce multi-factor authentication organization-wide">
                        <Toggle value={org.require_mfa ?? false} onChange={v => setOrg({ ...org, require_mfa: v })} />
                      </Field>
                      <Field label="Session Timeout (minutes)" hint="Idle sessions are terminated after this duration">
                        <input className="g-input" type="number" min={5} max={1440} value={secPolicy.session_timeout_mins ?? 480} onChange={e => setSecPolicy({ ...secPolicy, session_timeout_mins: parseInt(e.target.value) })} style={{ width: 100 }} />
                      </Field>
                      <div style={{ borderBottom: 'none' }}>
                        <Field label="Max Concurrent Sessions" hint="Maximum active sessions per user account">
                          <input className="g-input" type="number" min={1} max={20} value={secPolicy.max_concurrent_sessions ?? 10} onChange={e => setSecPolicy({ ...secPolicy, max_concurrent_sessions: parseInt(e.target.value) })} style={{ width: 100 }} />
                        </Field>
                      </div>
                    </div>
                  </SectionCard>

                  <SectionCard title="Password Policy" padded={false} className="mb-5">
                    <div className="px-4">
                      <Field label="Minimum Password Length">
                        <input className="g-input" type="number" min={8} max={128} value={secPolicy.min_password_length ?? 12} onChange={e => setSecPolicy({ ...secPolicy, min_password_length: parseInt(e.target.value) })} style={{ width: 100 }} />
                      </Field>
                      <Field label="Require Special Characters">
                        <Toggle value={secPolicy.require_special_chars ?? true} onChange={v => setSecPolicy({ ...secPolicy, require_special_chars: v })} />
                      </Field>
                      <Field label="Require Numbers">
                        <Toggle value={secPolicy.require_numbers ?? true} onChange={v => setSecPolicy({ ...secPolicy, require_numbers: v })} />
                      </Field>
                      <Field label="Password Expiry (days, 0 = never)" hint="Force password reset after this many days">
                        <input className="g-input" type="number" min={0} max={365} value={secPolicy.password_expiry_days ?? 90} onChange={e => setSecPolicy({ ...secPolicy, password_expiry_days: parseInt(e.target.value) })} style={{ width: 100 }} />
                      </Field>
                    </div>
                  </SectionCard>

                  <SectionCard title="Login Protection" padded={false} className="mb-5">
                    <div className="px-4">
                      <Field label="Max Failed Login Attempts" hint="Account locked after this many consecutive failures">
                        <input className="g-input" type="number" min={3} max={20} value={secPolicy.max_failed_logins ?? 5} onChange={e => setSecPolicy({ ...secPolicy, max_failed_logins: parseInt(e.target.value) })} style={{ width: 100 }} />
                      </Field>
                      <Field label="Lockout Duration (minutes)">
                        <input className="g-input" type="number" min={5} max={1440} value={secPolicy.lockout_duration_mins ?? 30} onChange={e => setSecPolicy({ ...secPolicy, lockout_duration_mins: parseInt(e.target.value) })} style={{ width: 100 }} />
                      </Field>
                      <Field label="IP Allowlist" hint="Comma-separated CIDR blocks (empty = allow all)">
                        <input className="g-input" placeholder="10.0.0.0/8, 192.168.0.0/16" value={secPolicy.ip_allowlist ?? ''} onChange={e => setSecPolicy({ ...secPolicy, ip_allowlist: e.target.value })} style={{ width: 280 }} />
                      </Field>
                    </div>
                  </SectionCard>

                  <SectionCard title={`Active Sessions (${(d.sessions ?? []).length})`} padded={false} className="mb-5">
                    <DataTable<any>
                      rows={(d.sessions ?? []).slice(0, 10)}
                      rowKey={(s: any, i: number) => s.id ?? i}
                      emptyState={<EmptyState title="No active sessions" />}
                      columns={[
                        { key: 'username', header: 'User', render: (s: any) => <span style={{ fontWeight: 600 }}>{s.username ?? s.user_id}</span> },
                        { key: 'ip_address', header: 'IP', render: (s: any) => <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{s.ip_address}</span> },
                        { key: 'user_agent', header: 'User Agent', render: (s: any) => <span style={{ fontSize: 11, color: 'var(--text-3)', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>{s.user_agent}</span> },
                        { key: 'created_at', header: 'Created', render: (s: any) => <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{s.created_at ? new Date(s.created_at).toLocaleString() : ''}</span> },
                        { key: 'actions', header: 'Actions', render: (s: any) => (
                          <ActionButton variant="danger" icon={Trash2} style={{ fontSize: 11, padding: '4px 10px' }}
                            onClick={() => sessionsAPI.revoke(s.id).then(loadAll).catch((err: any) => fail(err, 'Failed to revoke session.'))}>Revoke</ActionButton>
                        ) },
                      ]}
                    />
                  </SectionCard>

                  <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 'var(--space-5)' }}>
                    <ActionButton variant="ghost" icon={Save} onClick={saveOrg} disabled={saving}>Save MFA Setting</ActionButton>
                    <ActionButton variant="primary" icon={Save} onClick={saveSecPolicy} disabled={saving}>{saving ? 'Saving…' : 'Save Security Policy'}</ActionButton>
                  </div>
                </div>
              )}

              {/* ════════════════════════ AGENTS ════════════════════════ */}
              {section === 'agents' && (
                <div style={{ maxWidth: 700 }}>
                  <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Agents</h2>
                  <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 'var(--space-6)' }}>Configure global agent behavior and enrollment settings.</p>

                  <SectionCard title="Monitoring" padded={false} className="mb-5">
                    <div className="px-4">
                      <Field label="Offline Threshold (minutes)" hint="Agent marked offline after this many minutes without heartbeat">
                        <input className="g-input" type="number" min={5} max={120} value={agentCfg.offline_threshold_mins ?? 15} onChange={e => setAgentCfg({ ...agentCfg, offline_threshold_mins: parseInt(e.target.value) })} style={{ width: 100 }} />
                      </Field>
                      <Field label="Heartbeat Interval (seconds)">
                        <input className="g-input" type="number" min={10} max={300} value={agentCfg.heartbeat_interval_secs ?? 60} onChange={e => setAgentCfg({ ...agentCfg, heartbeat_interval_secs: parseInt(e.target.value) })} style={{ width: 100 }} />
                      </Field>
                      <Field label="Auto-deregister Offline Agents (days)" hint="Automatically remove agents offline for this many days (0 = disabled)">
                        <input className="g-input" type="number" min={0} max={365} value={agentCfg.auto_deregister_days ?? 90} onChange={e => setAgentCfg({ ...agentCfg, auto_deregister_days: parseInt(e.target.value) })} style={{ width: 100 }} />
                      </Field>
                      <Field label="Max Log Batch Size" hint="Maximum number of log lines per agent upload">
                        <input className="g-input" type="number" min={100} max={10000} value={agentCfg.max_log_batch ?? 1000} onChange={e => setAgentCfg({ ...agentCfg, max_log_batch: parseInt(e.target.value) })} style={{ width: 100 }} />
                      </Field>
                    </div>
                  </SectionCard>

                  <SectionCard title="Collection" padded={false} className="mb-5">
                    <div className="px-4">
                      <Field label="File Integrity Monitoring (FIM)">
                        <Toggle value={agentCfg.enable_fim ?? true} onChange={v => setAgentCfg({ ...agentCfg, enable_fim: v })} />
                      </Field>
                      <Field label="Process Monitoring">
                        <Toggle value={agentCfg.enable_process_monitoring ?? true} onChange={v => setAgentCfg({ ...agentCfg, enable_process_monitoring: v })} />
                      </Field>
                      <Field label="Network Connection Monitoring">
                        <Toggle value={agentCfg.enable_network_monitoring ?? true} onChange={v => setAgentCfg({ ...agentCfg, enable_network_monitoring: v })} />
                      </Field>
                      <Field label="Require Signed Agent Binaries" hint="Only accept agents with valid code signatures">
                        <Toggle value={agentCfg.require_signed_binaries ?? false} onChange={v => setAgentCfg({ ...agentCfg, require_signed_binaries: v })} />
                      </Field>
                    </div>
                  </SectionCard>

                  <SectionCard title="Enrollment" padded={false} className="mb-5">
                    <div className="px-4">
                      <div style={{ borderBottom: 'none' }}>
                        <Field label="Enrollment Token TTL (hours)" hint="How long enrollment tokens remain valid after generation">
                          <input className="g-input" type="number" min={1} max={720} value={agentCfg.enrollment_token_ttl_hours ?? 48} onChange={e => setAgentCfg({ ...agentCfg, enrollment_token_ttl_hours: parseInt(e.target.value) })} style={{ width: 100 }} />
                        </Field>
                      </div>
                    </div>
                  </SectionCard>

                  <SaveBar onSave={saveAgentCfg} saving={saving} />
                </div>
              )}

              {/* ════════════════════════ INTEGRATIONS ══════════════════ */}
              {section === 'integrations' && (
                <div>
                  <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Integrations</h2>
                  <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 'var(--space-6)' }}>Connect external security tools and data sources.</p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    {(d.integrations ?? []).map((intg: any, i: number) => (
                      <SectionCard key={i} title={intg.name ?? intg.integration_name} subtitle={intg.description ?? intg.integration_type}
                        actions={pill(intg.enabled ? 'enabled' : 'disabled')}>
                        {intg.url && <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 8, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{intg.url}</div>}
                        {intg.last_tested_at && (
                          <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 10 }}>
                            Last tested: {new Date(intg.last_tested_at).toLocaleString()}
                            {intg.last_test_success !== undefined && (
                              <span style={{ marginLeft: 8 }}>{intg.last_test_success ? '✓ Passed' : '✗ Failed'}</span>
                            )}
                          </div>
                        )}
                        <ActionButton variant="ghost" icon={Zap} style={{ fontSize: 12 }}
                          disabled={testingIntg === (intg.name ?? intg.integration_name)}
                          onClick={() => testIntegration(intg.name ?? intg.integration_name)}>
                          {testingIntg === (intg.name ?? intg.integration_name) ? 'Testing…' : 'Test Connection'}
                        </ActionButton>
                      </SectionCard>
                    ))}
                    {!d.integrations?.length && (
                      <div className="sm:col-span-2">
                        <EmptyState title="No integrations configured yet" />
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* ════════════════════════ NOTIFICATIONS ═════════════════ */}
              {section === 'notifications' && (
                <div>
                  <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Notifications</h2>
                  <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 'var(--space-6)' }}>Configure email alert rules and notification channels.</p>
                  <SectionCard title={`Email Alert Rules (${(d.notifRules ?? []).length})`} padded={false}>
                    <DataTable<any>
                      rows={d.notifRules ?? []}
                      rowKey={(r: any, i: number) => r.id ?? i}
                      emptyState={<EmptyState title="No email rules configured" />}
                      columns={[
                        { key: 'name', header: 'Rule Name', render: (r: any) => <span style={{ fontWeight: 600, color: 'var(--text-1)' }}>{r.name}</span> },
                        { key: 'event_type', header: 'Event', render: (r: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{r.event_type}</span> },
                        { key: 'recipients', header: 'Recipients', render: (r: any) => <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{Array.isArray(r.recipients) ? r.recipients.join(', ') : r.recipients}</span> },
                        { key: 'min_severity', header: 'Severity', render: (r: any) => r.min_severity ? pill(r.min_severity) : null },
                        { key: 'enabled', header: 'Status', render: (r: any) => (
                          <Toggle value={r.enabled ?? false}
                            onChange={(v) => notificationsAPI.toggleEmailRule(r.id, v).then(loadAll).catch((err: any) => fail(err, 'Failed to update rule.'))} />
                        ) },
                        { key: 'actions', header: 'Actions', render: (r: any) => (
                          <ActionButton variant="danger" icon={Trash2} style={{ fontSize: 11, padding: '4px 10px' }}
                            onClick={() => { if (window.confirm('Delete rule?')) notificationsAPI.deleteEmailRule(r.id).then(loadAll).catch((err: any) => fail(err, 'Failed to delete rule.')); }}>
                            Delete
                          </ActionButton>
                        ) },
                      ]}
                    />
                  </SectionCard>
                </div>
              )}

              {/* ════════════════════════ AI MODELS ════════════════════ */}
              {section === 'ai-models' && (
                <div>
                  <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>AI Models</h2>
                  <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 'var(--space-6)' }}>Configure LLM providers, models, and API credentials.</p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    {[
                      { provider: 'anthropic',  label: 'Anthropic Claude',   model: 'claude-sonnet-4-6',    badge: 'Default' },
                      { provider: 'openai',      label: 'OpenAI GPT-4o',      model: 'gpt-4o-mini',          badge: '' },
                      { provider: 'gemini',      label: 'Google Gemini',      model: 'gemini-1.5-pro',       badge: '' },
                      { provider: 'azure_openai',label: 'Azure OpenAI',       model: 'gpt-4-turbo',          badge: '' },
                      { provider: 'ollama',      label: 'Ollama (Local)',      model: 'llama3.1:70b',         badge: 'On-Premise' },
                      { provider: 'mcp',         label: 'MCP Server',          model: 'custom',               badge: 'Ext.' },
                    ].map((p) => {
                      const existing = (d.aiProviders ?? []).find((a: any) => a.provider === p.provider);
                      return (
                        <SectionCard key={p.provider} title={p.label} subtitle={existing?.model ?? p.model}
                          actions={<div className="flex items-center gap-1.5">{p.badge && pill(p.badge, '#7c3aed')}{pill(existing?.enabled ? 'enabled' : 'disabled')}</div>}>
                          {existing?.api_key_masked && (
                            <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 8, fontFamily: 'monospace' }}>
                              Key: {existing.api_key_masked}
                            </div>
                          )}
                          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                            <input className="g-input" placeholder="API Key" type="password" style={{ flex: 1, fontSize: 12 }}
                              onBlur={e => {
                                if (!e.target.value) return;
                                stteAPI.updateAIConfig({ provider: p.provider, model: p.model, api_key: e.target.value, enabled: true })
                                  .then(() => { flash(`${p.label} API key saved.`); loadAll(); })
                                  .catch((err: any) => fail(err, `Failed to save ${p.label} API key.`));
                              }} />
                            <ActionButton variant="ghost" icon={Power} style={{ fontSize: 11 }}
                              onClick={() => stteAPI.updateAIConfig({ provider: p.provider, model: p.model, enabled: !(existing?.enabled) }).then(loadAll).catch((err: any) => fail(err, 'Failed to update provider.'))}>
                              {existing?.enabled ? 'Disable' : 'Enable'}
                            </ActionButton>
                          </div>
                          {existing?.rate_limit_rpm && (
                            <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 8 }}>
                              Rate: {existing.rate_limit_rpm} RPM · Budget: ${existing.monthly_budget_usd ?? 0}/mo
                            </div>
                          )}
                        </SectionCard>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* ════════════════════════ AI GUARDRAILS ════════════════ */}
              {section === 'ai-guardrails' && (
                <div style={{ maxWidth: 700 }}>
                  <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>AI Guardrails</h2>
                  <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 'var(--space-6)' }}>Safety controls, approval workflows, and data protection for AI.</p>
                  <SectionCard title="Safety Controls" padded={false} className="mb-5">
                    <div className="px-4">
                      <Field label="Require Approval for AI Actions" hint="All AI-requested actions must be approved by a human operator">
                        <Toggle value={aiGuard.require_approval_for_actions ?? true} onChange={v => setAiGuard({ ...aiGuard, require_approval_for_actions: v })} />
                      </Field>
                      <Field label="RBAC Enforcement" hint="Restrict AI capabilities based on user role">
                        <Toggle value={aiGuard.rbac_enabled ?? true} onChange={v => setAiGuard({ ...aiGuard, rbac_enabled: v })} />
                      </Field>
                      <Field label="Data Masking" hint="Automatically mask PII in AI context (SSN, credit cards, passwords)">
                        <Toggle value={aiGuard.data_masking_enabled ?? true} onChange={v => setAiGuard({ ...aiGuard, data_masking_enabled: v })} />
                      </Field>
                      <Field label="Hallucination Warnings" hint="Show confidence warnings when AI uncertainty is high">
                        <Toggle value={aiGuard.hallucination_warnings ?? true} onChange={v => setAiGuard({ ...aiGuard, hallucination_warnings: v })} />
                      </Field>
                      <div style={{ borderBottom: 'none' }}>
                        <Field label="Audit All Queries" hint="Log every AI query and response to the audit trail">
                          <Toggle value={aiGuard.audit_all_queries ?? true} onChange={v => setAiGuard({ ...aiGuard, audit_all_queries: v })} />
                        </Field>
                      </div>
                    </div>
                  </SectionCard>
                  <SectionCard title="Context Limits" padded={false} className="mb-5">
                    <div className="px-4">
                      <Field label="Max Context Length (tokens)" hint="Maximum tokens of security data passed to AI per query">
                        <input className="g-input" type="number" min={1024} max={128000} value={aiGuard.max_context_length ?? 8192} onChange={e => setAiGuard({ ...aiGuard, max_context_length: parseInt(e.target.value) })} style={{ width: 120 }} />
                      </Field>
                      <div style={{ borderBottom: 'none' }}>
                        <Field label="Allowed Roles" hint="Comma-separated roles with AI access">
                          <input className="g-input" value={Array.isArray(aiGuard.allowed_roles) ? aiGuard.allowed_roles.join(',') : (aiGuard.allowed_roles ?? 'admin,analyst,manager')}
                            onChange={e => setAiGuard({ ...aiGuard, allowed_roles: e.target.value.split(',').map((s: string) => s.trim()) })} style={{ width: 220 }} />
                        </Field>
                      </div>
                    </div>
                  </SectionCard>
                  <SaveBar onSave={saveAIGuardrails} saving={saving} />
                </div>
              )}

              {/* ════════════════════════ AI USAGE ═════════════════════ */}
              {section === 'ai-usage' && (
                <div style={{ maxWidth: 700 }}>
                  <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Usage Limits</h2>
                  <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 'var(--space-6)' }}>Set per-role message limits and monthly token budgets.</p>
                  <p style={{ color: 'var(--text-3)', fontSize: 12, marginTop: -12, marginBottom: 'var(--space-4)', fontStyle: 'italic' }}>
                    Example values for illustration — no per-role usage metering exists yet, so these are not live-configured or enforced.
                  </p>
                  <SectionCard padded={false}>
                    <DataTable<any>
                      rows={[
                        { role: 'admin',    msgs: 'Unlimited', tokens: 'Unlimited', budget: '$0 (no limit)' },
                        { role: 'analyst',  msgs: '500',       tokens: '2,000,000',  budget: '$100' },
                        { role: 'manager',  msgs: '200',       tokens: '1,000,000',  budget: '$50' },
                        { role: 'viewer',   msgs: '50',        tokens: '100,000',    budget: '$10' },
                      ]}
                      rowKey={(r: any) => r.role}
                      columns={[
                        { key: 'role', header: 'Role', render: (r: any) => pill(r.role) },
                        { key: 'msgs', header: 'Daily Messages', render: (r: any) => <span style={{ fontWeight: 600 }}>{r.msgs}</span> },
                        { key: 'tokens', header: 'Monthly Tokens', render: (r: any) => <span style={{ color: 'var(--text-2)' }}>{r.tokens}</span> },
                        { key: 'budget', header: 'Monthly Budget (USD)', render: (r: any) => <span style={{ color: 'var(--text-2)' }}>{r.budget}</span> },
                      ]}
                    />
                  </SectionCard>
                  <SectionCard title="Model Routing by Mode" subtitle="Example values — no per-mode fallback routing exists yet" padded={false} className="mt-4">
                    <DataTable<any>
                      rows={[
                        { mode: 'General Chat',          primary: 'claude-sonnet-4-6',  fallback: 'gpt-4o-mini' },
                        { mode: 'Investigation',         primary: 'claude-sonnet-4-6',  fallback: 'gpt-4o' },
                        { mode: 'Automation',            primary: 'claude-sonnet-4-6',  fallback: 'gpt-4o' },
                        { mode: 'Executive Assistant',   primary: 'claude-sonnet-4-6',  fallback: 'gemini-1.5-pro' },
                        { mode: 'Threat Intelligence',   primary: 'claude-sonnet-4-6',  fallback: 'llama3.1:70b (local)' },
                      ]}
                      rowKey={(r: any) => r.mode}
                      columns={[
                        { key: 'mode', header: 'Mode', render: (r: any) => <span style={{ fontWeight: 600 }}>{r.mode}</span> },
                        { key: 'primary', header: 'Primary Model', render: (r: any) => <span style={{ color: 'var(--accent)', fontFamily: 'monospace', fontSize: 12 }}>{r.primary}</span> },
                        { key: 'fallback', header: 'Fallback', render: (r: any) => <span style={{ color: 'var(--text-3)', fontFamily: 'monospace', fontSize: 12 }}>{r.fallback}</span> },
                      ]}
                    />
                  </SectionCard>
                </div>
              )}

              {/* ════════════════════════ BACKUP & RECOVERY ════════════ */}
              {section === 'backup' && (
                <div>
                  <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Backup & Recovery</h2>
                  <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 'var(--space-6)' }}>Configure automated backups and view restore points.</p>
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-5">
                    <SectionCard title="Backup Configuration" padded={false}>
                      <div className="px-4">
                        <Field label="Automated Backups">
                          <Toggle value={backupCfg.enabled ?? true} onChange={v => setBackupCfg({ ...backupCfg, enabled: v })} />
                        </Field>
                        <Field label="Schedule">
                          <select className="g-input" value={backupCfg.schedule_type ?? 'daily'} onChange={e => setBackupCfg({ ...backupCfg, schedule_type: e.target.value })} style={{ width: 140 }}>
                            <option value="hourly">Hourly</option>
                            <option value="daily">Daily</option>
                            <option value="weekly">Weekly</option>
                          </select>
                        </Field>
                        <Field label="Backup Time (UTC)">
                          <input className="g-input" type="time" value={backupCfg.schedule_time ?? '02:00'} onChange={e => setBackupCfg({ ...backupCfg, schedule_time: e.target.value })} style={{ width: 120 }} />
                        </Field>
                        <Field label="Retention (days)">
                          <input className="g-input" type="number" min={1} max={365} value={backupCfg.retention_days ?? 30} onChange={e => setBackupCfg({ ...backupCfg, retention_days: parseInt(e.target.value) })} style={{ width: 100 }} />
                        </Field>
                        <Field label="Encryption">
                          <Toggle value={backupCfg.encrypt ?? true} onChange={v => setBackupCfg({ ...backupCfg, encrypt: v })} />
                        </Field>
                        <div style={{ borderBottom: 'none' }}>
                          <Field label="Storage">
                            <select className="g-input" value={backupCfg.storage ?? 'local'} onChange={e => setBackupCfg({ ...backupCfg, storage: e.target.value })} style={{ width: 120 }}>
                              <option value="local">Local</option>
                              <option value="s3">AWS S3</option>
                              <option value="gcs">Google Cloud</option>
                              <option value="azure">Azure Blob</option>
                            </select>
                          </Field>
                        </div>
                        <div className="flex gap-2.5 mt-4 pb-4">
                          <ActionButton variant="primary" icon={Save} onClick={saveBackupCfg} disabled={saving}>Save Config</ActionButton>
                          <ActionButton variant="ghost" icon={RefreshCw} onClick={triggerBackup}>Backup Now</ActionButton>
                        </div>
                      </div>
                    </SectionCard>

                    <SectionCard title="Restore Points">
                      {(d.backups ?? []).slice(0, 6).map((b: any, i: number) => (
                        <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
                          <div>
                            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)' }}>
                              {b.created_at ? new Date(b.created_at).toLocaleString() : ''}
                            </div>
                            <div style={{ fontSize: 11, color: 'var(--text-3)' }}>
                              {b.backup_type} · {b.size_human ?? b.size_bytes} · {b.duration_secs}s
                            </div>
                          </div>
                          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                            {pill(b.status)}
                            <ActionButton variant="ghost" icon={RotateCcw} style={{ fontSize: 11, padding: '4px 10px' }}
                              onClick={() => alert('Restore is not available: running pg_restore against the live shared database from this UI would be destructive and is not supported. Contact an operator to restore from a backup file directly.')}>
                              Restore
                            </ActionButton>
                          </div>
                        </div>
                      ))}
                      {!d.backups?.length && <EmptyState title="No backup history" />}
                    </SectionCard>
                  </div>

                  <SectionCard title="Backup History" padded={false}>
                    <DataTable<any>
                      rows={d.backups ?? []}
                      rowKey={(b: any, i: number) => b.backup_id ?? i}
                      emptyState={<EmptyState title="No backups yet" message={'Click "Backup Now" to create the first one'} />}
                      columns={[
                        { key: 'backup_id', header: 'Backup ID', render: (b: any) => <span style={{ fontFamily: 'monospace', fontSize: 12 }}>{b.backup_id}</span> },
                        { key: 'backup_type', header: 'Type', render: (b: any) => pill(b.backup_type) },
                        { key: 'size', header: 'Size', render: (b: any) => <span style={{ fontSize: 12 }}>{b.size_human ?? b.size_bytes}</span> },
                        { key: 'duration_secs', header: 'Duration', render: (b: any) => <span style={{ fontSize: 12 }}>{b.duration_secs}s</span> },
                        { key: 'status', header: 'Status', render: (b: any) => pill(b.status) },
                        { key: 'triggered_by', header: 'Triggered By', render: (b: any) => <span style={{ fontSize: 12 }}>{b.triggered_by}</span> },
                        { key: 'created_at', header: 'Time', render: (b: any) => <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{b.created_at ? new Date(b.created_at).toLocaleString() : ''}</span> },
                      ]}
                    />
                  </SectionCard>
                </div>
              )}

              {/* ════════════════════════ API MANAGEMENT ════════════════ */}
              {section === 'api-management' && (
                <div>
                  <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>API Management</h2>
                  <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 'var(--space-6)' }}>Manage API keys, rate limits, and integration access.</p>

                  <SectionCard title="Create API Key" className="mb-5">
                    <div className="flex gap-2.5 flex-wrap">
                      <input className="g-input" placeholder="Key label (e.g. SIEM integration)" value={keyLabel} onChange={e => setKeyLabel(e.target.value)} style={{ flex: 1, minWidth: 200 }} />
                      <select className="g-input" value={keyRole} onChange={e => setKeyRole(e.target.value)} style={{ minWidth: 120 }}>
                        <option value="viewer">viewer</option>
                        <option value="analyst">analyst</option>
                        <option value="admin">admin</option>
                      </select>
                      <ActionButton variant="primary" icon={KeyRound} disabled={!keyLabel} onClick={createKey}>Generate Key</ActionButton>
                    </div>
                    {newKey && (
                      <div style={{ marginTop: 14, background: 'var(--bg-2)', borderRadius: 'var(--radius-md)', padding: '12px 16px', border: '1px solid var(--accent-border)' }}>
                        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--accent)', marginBottom: 4 }}>API Key (copy now — won&apos;t be shown again):</div>
                        <div style={{ fontFamily: 'monospace', fontSize: 13, wordBreak: 'break-all', color: 'var(--text-1)' }}>{newKey}</div>
                        <ActionButton variant="ghost" icon={Copy} style={{ marginTop: 8, fontSize: 11 }} onClick={() => navigator.clipboard.writeText(newKey)}>Copy</ActionButton>
                      </div>
                    )}
                  </SectionCard>

                  <SectionCard title={`API Keys (${(d.keys ?? []).length})`} padded={false} className="mb-5">
                    <DataTable<any>
                      rows={d.keys ?? []}
                      rowKey={(k: any, i: number) => k.id ?? i}
                      emptyState={<EmptyState title="No API keys yet" />}
                      columns={[
                        { key: 'label', header: 'Label', render: (k: any) => <span style={{ fontWeight: 600 }}>{k.label}</span> },
                        { key: 'role', header: 'Role', render: (k: any) => pill(k.role) },
                        { key: 'key_prefix', header: 'Key (masked)', render: (k: any) => <span style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--text-3)' }}>{k.key_prefix ?? k.api_key_prefix}****</span> },
                        { key: 'last_used_at', header: 'Last Used', render: (k: any) => <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{k.last_used_at ? new Date(k.last_used_at).toLocaleString() : 'Never'}</span> },
                        { key: 'expires_at', header: 'Expires', render: (k: any) => <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{k.expires_at ? new Date(k.expires_at).toLocaleDateString() : 'Never'}</span> },
                        { key: 'actions', header: 'Actions', render: (k: any) => (
                          <ActionButton variant="danger" icon={Trash2} style={{ fontSize: 11, padding: '4px 10px' }}
                            onClick={() => { if (window.confirm('Revoke this API key?')) apiKeysAPI.revoke(k.id).then(loadAll).catch((err: any) => fail(err, 'Failed to revoke API key.')); }}>
                            Revoke
                          </ActionButton>
                        ) },
                      ]}
                    />
                  </SectionCard>

                  <SectionCard title="Rate Limits" subtitle="Example values — only Authentication (10/min) and a single general API tier (120/min) are actually enforced; the per-group breakdown below is illustrative" padded={false}>
                    <DataTable<any>
                      rows={[
                        { group: 'Authentication', limit: 10, burst: 20, auth: false },
                        { group: 'Alerts & Incidents', limit: 300, burst: 500, auth: true },
                        { group: 'Search & Query', limit: 100, burst: 200, auth: true },
                        { group: 'AI Assistant', limit: 60, burst: 100, auth: true },
                        { group: 'Reports & Export', limit: 20, burst: 30, auth: true },
                        { group: 'Agent Ingestion', limit: 2000, burst: 5000, auth: false },
                      ]}
                      rowKey={(r: any) => r.group}
                      columns={[
                        { key: 'group', header: 'Endpoint Group', render: (r: any) => <span style={{ fontWeight: 600 }}>{r.group}</span> },
                        { key: 'limit', header: 'Limit (req/min)', render: (r: any) => <span>{r.limit}</span> },
                        { key: 'burst', header: 'Burst', render: (r: any) => <span>{r.burst}</span> },
                        { key: 'auth', header: 'Auth', render: (r: any) => pill(r.auth ? 'required' : 'none', r.auth ? '#7c3aed' : '#6b7280') },
                      ]}
                    />
                  </SectionCard>
                </div>
              )}

              {/* ════════════════════════ UPDATES ════════════════════════ */}
              {section === 'updates' && (
                <div style={{ maxWidth: 700 }}>
                  <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Updates</h2>
                  <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 'var(--space-6)' }}>Version management and platform update history.</p>

                  <SectionCard className="mb-5">
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
                      <div>
                        <div style={{ fontWeight: 700, fontSize: 20, color: 'var(--text-1)' }}>v{d.updates?.current_version ?? '1.0.0'}</div>
                        <div style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 2 }}>Current Version — {pill(d.updates?.channel ?? 'stable')}</div>
                      </div>
                      <div style={{ textAlign: 'right' }}>
                        {d.updates?.update_available ? (
                          <ActionButton variant="primary" icon={Download}>Install Update v{d.updates?.latest_version}</ActionButton>
                        ) : (
                          <div className="flex items-center gap-1.5 justify-end" style={{ fontSize: 13, color: 'var(--green)', fontWeight: 600 }}>
                            <CheckCircle2 className="h-3.5 w-3.5" /> Up to date
                          </div>
                        )}
                        <ActionButton variant="ghost" icon={RefreshCw} onClick={checkUpdates} style={{ marginTop: 8, display: 'flex', width: '100%', justifyContent: 'center' }}>Check for Updates</ActionButton>
                      </div>
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-3)' }}>
                      Last checked: {d.updates?.last_checked ? new Date(d.updates.last_checked).toLocaleString() : '—'}
                    </div>
                  </SectionCard>

                  <SectionCard title="Release History" padded={false}>
                    <DataTable<any>
                      rows={d.updates?.history ?? []}
                      rowKey={(u: any, i: number) => i}
                      emptyState={<EmptyState title="No update history" />}
                      columns={[
                        { key: 'version', header: 'Version', render: (u: any) => <span style={{ fontFamily: 'monospace', fontWeight: 600, color: 'var(--accent)' }}>v{u.version}</span> },
                        { key: 'release_type', header: 'Type', render: (u: any) => pill(u.release_type) },
                        { key: 'title', header: 'Title', render: (u: any) => <span style={{ fontSize: 13 }}>{u.title}</span> },
                        { key: 'applied_by', header: 'Applied By', render: (u: any) => <span style={{ fontSize: 12 }}>{u.applied_by ?? '—'}</span> },
                        { key: 'created_at', header: 'Date', render: (u: any) => <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{u.created_at ? new Date(u.created_at).toLocaleDateString() : ''}</span> },
                      ]}
                    />
                  </SectionCard>
                </div>
              )}

              {/* ════════════════════════ LICENSING ═════════════════════ */}
              {section === 'licensing' && (
                <div style={{ maxWidth: 700 }}>
                  <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Licensing</h2>
                  <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 'var(--space-6)' }}>Manage your XCloak license, tier, and seat usage.</p>

                  <SectionCard className="mb-5">
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                      <div>
                        <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-1)', textTransform: 'capitalize' }}>
                          {d.license?.tier ?? 'Community'} Edition
                        </div>
                        <div style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 2 }}>
                          {d.license?.is_trial ? 'Trial' : 'Licensed'} · Support: {d.license?.support_tier ?? 'community'}
                        </div>
                      </div>
                      {pill(d.license?.tier ?? 'community')}
                    </div>

                    <div className="grid grid-cols-2 gap-3 mb-4">
                      {[
                        { label: 'Seats Used',     value: `${d.license?.seats_used ?? 0} / ${d.license?.seats_total ?? 5}` },
                        { label: 'Agents Used',    value: `${d.license?.agents_used ?? 0} / ${d.license?.agents_total ?? 25}` },
                        { label: 'Valid From',     value: d.license?.valid_from ?? '—' },
                        { label: 'Valid Until',    value: d.license?.valid_until ?? '—' },
                        { label: 'Issued To',      value: d.license?.issued_to ?? '—' },
                        { label: 'Activated At',   value: d.license?.activated_at ? new Date(d.license.activated_at).toLocaleDateString() : '—' },
                      ].map((item, i) => (
                        <MetricCard key={i} variant="compact" label={item.label} value={item.value} />
                      ))}
                    </div>

                    {d.license?.features && (
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 8 }}>Enabled Features</div>
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                          {(Array.isArray(d.license.features) ? d.license.features :
                            JSON.parse(d.license.features || '[]')).map((f: string, i: number) => (
                            <span key={i} style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)', borderRadius: 4, padding: '2px 8px', fontSize: 11 }}>{f}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </SectionCard>

                  <SectionCard title="Activate License Key">
                    <div className="flex gap-2.5">
                      <input className="g-input" placeholder="XXXX-XXXX-XXXX-XXXX-XXXX" value={licKey} onChange={e => setLicKey(e.target.value)} style={{ flex: 1, fontFamily: 'monospace' }} />
                      <ActionButton variant="primary" icon={CheckCircle2} disabled={activating || !licKey} onClick={activateLicense}>
                        {activating ? 'Activating…' : 'Activate'}
                      </ActionButton>
                    </div>
                    <p style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 10 }}>
                      Contact sales@xcloak.io to obtain an Enterprise license key or upgrade your current plan.
                    </p>
                  </SectionCard>
                </div>
              )}

              {/* ════════════════════════ AUDIT TRAIL ════════════════════ */}
              {section === 'audit' && (
                <div>
                  <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Audit Trail</h2>
                  <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 'var(--space-6)' }}>Complete history of all platform configuration changes and administrative actions.</p>

                  <SectionCard title="Settings Changes" padded={false} className="mb-5">
                    <DataTable<any>
                      rows={d.stteAudit ?? []}
                      rowKey={(e: any, i: number) => i}
                      emptyState={<EmptyState title="No settings changes recorded" />}
                      columns={[
                        { key: 'created_at', header: 'Time', render: (e: any) => <span style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{e.created_at ? new Date(e.created_at).toLocaleString() : ''}</span> },
                        { key: 'action', header: 'Action', render: (e: any) => pill((e.action ?? '').replace(/_/g, ' ')) },
                        { key: 'section', header: 'Section', render: (e: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{e.section}</span> },
                        { key: 'actor', header: 'Actor', render: (e: any) => <span style={{ fontSize: 12, fontWeight: 600 }}>{e.actor}</span> },
                        { key: 'details', header: 'Details', render: (e: any) => <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{e.details ?? '—'}</span> },
                      ]}
                    />
                  </SectionCard>

                  <SectionCard title="Platform Audit Log" padded={false}>
                    <DataTable<any>
                      rows={(d.auditLogs ?? []).slice(0, 50)}
                      rowKey={(e: any, i: number) => i}
                      emptyState={<EmptyState title="No audit logs" />}
                      columns={[
                        { key: 'created_at', header: 'Time', render: (e: any) => <span style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{e.created_at ? new Date(e.created_at).toLocaleString() : ''}</span> },
                        { key: 'action', header: 'Action', render: (e: any) => <span style={{ fontSize: 12 }}>{e.action}</span> },
                        { key: 'actor', header: 'Actor', render: (e: any) => <span style={{ fontSize: 12, fontWeight: 600 }}>{e.username ?? e.actor ?? e.performed_by}</span> },
                        { key: 'target', header: 'Target', render: (e: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{e.target ?? e.object_id ?? '—'}</span> },
                        { key: 'ip_address', header: 'IP', render: (e: any) => <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{e.ip_address ?? '—'}</span> },
                      ]}
                    />
                  </SectionCard>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </RootLayout>
  );
}
