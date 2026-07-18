'use client';
import { useState, useEffect, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import {
  stteAPI, usersAPI, auditAPI, apiKeysAPI, customRolesAPI,
  sessionsAPI, securityPolicyAPI, integrationsAPI, notificationsAPI,
  billingAPI,
} from '@/lib/api';
import { useUser } from '@/context/UserContext';

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
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', padding: '14px 0', borderBottom: '1px solid var(--border)' }}>
      <div style={{ flex: 1, paddingRight: 24 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)' }}>{label}</div>
        {hint && <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 2 }}>{hint}</div>}
      </div>
      <div style={{ flexShrink: 0 }}>{children}</div>
    </div>
  );
}

function SaveBar({ onSave, saving }: { onSave: () => void; saving: boolean }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 20 }}>
      <button className="g-btn" onClick={onSave} disabled={saving} style={{ minWidth: 100 }}>
        {saving ? 'Saving…' : 'Save Changes'}
      </button>
    </div>
  );
}

/* ── navigation structure ────────────────────────────────────────────────── */
const TOP_TABS = [
  { id: 'general',      label: 'General' },
  { id: 'security',     label: 'Security' },
  { id: 'integrations', label: 'Integrations' },
  { id: 'ai',           label: 'AI' },
  { id: 'system',       label: 'System' },
];

const SIDEBAR: Record<string, { id: string; label: string }[][]> = {
  general: [
    [{ id: 'organization', label: 'Organization' }, { id: 'users', label: 'Users & RBAC' }],
  ],
  security: [
    [{ id: 'authentication', label: 'Authentication' }, { id: 'agents', label: 'Agents' }],
  ],
  integrations: [
    [{ id: 'integrations', label: 'Integrations' }, { id: 'notifications', label: 'Notifications' }],
  ],
  ai: [
    [{ id: 'ai-models', label: 'Models' }, { id: 'ai-guardrails', label: 'Guardrails' }, { id: 'ai-usage', label: 'Usage Limits' }],
  ],
  system: [
    [{ id: 'backup', label: 'Backup & Recovery' }, { id: 'api-management', label: 'API Management' }],
    [{ id: 'updates', label: 'Updates' }, { id: 'licensing', label: 'Licensing' }],
    [{ id: 'audit', label: 'Audit Trail' }],
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
  async function saveOrg() {
    setSaving(true);
    try { await stteAPI.updateOrg(org); flash('Organization settings saved.'); } finally { setSaving(false); }
  }

  async function saveSecPolicy() {
    setSaving(true);
    try { await securityPolicyAPI.update(secPolicy); flash('Security policy saved.'); } finally { setSaving(false); }
  }

  async function saveAgentCfg() {
    setSaving(true);
    try { await stteAPI.updateAgentsConfig(agentCfg); flash('Agent configuration saved.'); } finally { setSaving(false); }
  }

  async function saveAIGuardrails() {
    setSaving(true);
    try { await stteAPI.updateAIConfig(aiGuard); flash('AI guardrails saved.'); } finally { setSaving(false); }
  }

  async function saveBackupCfg() {
    setSaving(true);
    try { await stteAPI.updateBackupConfig(backupCfg); flash('Backup configuration saved.'); } finally { setSaving(false); }
  }

  async function doInvite() {
    if (!inviteUser || !inviteEmail) return;
    setInviting(true);
    try {
      await usersAPI.invite(inviteUser, inviteEmail, inviteRole);
      setInviteUser(''); setInviteEmail('');
      flash('Invitation sent.'); loadAll();
    } finally { setInviting(false); }
  }

  async function createKey() {
    if (!keyLabel) return;
    try {
      const res = await apiKeysAPI.create(keyLabel, keyRole);
      setNewKey(res?.data?.key ?? res?.data?.raw_key ?? '');
      setKeyLabel(''); loadAll();
    } catch { flash('Error creating API key.'); }
  }

  async function activateLicense() {
    if (!licKey) return;
    setActivating(true);
    try {
      const res = await stteAPI.activateLicense({ license_key: licKey });
      flash(`License activated — tier: ${res?.data?.tier ?? 'enterprise'}`);
      setLicKey(''); loadAll();
    } finally { setActivating(false); }
  }

  async function triggerBackup() {
    try {
      await stteAPI.triggerBackup();
      flash('Backup started.'); loadAll();
    } catch { flash('Error starting backup.'); }
  }

  async function checkUpdates() {
    const res = await stteAPI.checkUpdates();
    flash(res?.data?.message ?? 'Update check complete.');
  }

  async function testIntegration(name: string) {
    setTestingIntg(name);
    try { await integrationsAPI.test(name); flash(`${name}: connection test passed.`); }
    catch { flash(`${name}: connection test failed.`); }
    finally { setTestingIntg(''); }
  }

  const d = data;

  return (
    <RootLayout>
      <div style={{ minHeight: '100vh', background: 'var(--bg-1)' }}>
        {/* ── top tabs ──────────────────────────────────────────────────── */}
        <div style={{ background: 'var(--bg-2)', borderBottom: '1px solid var(--border)', padding: '0 32px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: 20, paddingBottom: 0 }}>
            <div>
              <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-1)', margin: 0 }}>Settings</h1>
              <p style={{ fontSize: 12, color: 'var(--text-3)', margin: '2px 0 0' }}>Platform configuration and administration</p>
            </div>
            {msg && (
              <div style={{ background: '#16a34a22', color: '#16a34a', border: '1px solid #16a34a55', borderRadius: 6, padding: '8px 16px', fontSize: 13 }}>
                {msg}
              </div>
            )}
          </div>
          <div style={{ display: 'flex', marginTop: 16 }}>
            {TOP_TABS.map(t => (
              <button key={t.id} onClick={() => switchTop(t.id)} style={{
                background: 'none', border: 'none', padding: '10px 20px', cursor: 'pointer',
                fontSize: 13, fontWeight: topTab === t.id ? 600 : 400,
                color: topTab === t.id ? 'var(--accent)' : 'var(--text-2)',
                borderBottom: topTab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
                marginBottom: -1,
              }}>{t.label}</button>
            ))}
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr', minHeight: 'calc(100vh - 120px)' }}>
          {/* ── sidebar ─────────────────────────────────────────────────── */}
          <div style={{ background: 'var(--bg-2)', borderRight: '1px solid var(--border)', padding: '20px 0' }}>
            {(SIDEBAR[topTab] ?? []).map((group, gi) => (
              <div key={gi} style={{ marginBottom: gi < (SIDEBAR[topTab]?.length ?? 0) - 1 ? 8 : 0 }}>
                {group.map(s => (
                  <button key={s.id} onClick={() => setSection(s.id)} style={{
                    display: 'block', width: '100%', textAlign: 'left',
                    padding: '9px 20px', background: section === s.id ? 'var(--accent)22' : 'none',
                    borderLeft: `3px solid ${section === s.id ? 'var(--accent)' : 'transparent'}`,
                    border: 'none', cursor: 'pointer', fontSize: 13, fontWeight: section === s.id ? 600 : 400,
                    color: section === s.id ? 'var(--accent)' : 'var(--text-2)',
                  }}>{s.label}</button>
                ))}
                {gi < (SIDEBAR[topTab]?.length ?? 0) - 1 && (
                  <div style={{ height: 1, background: 'var(--border)', margin: '8px 0' }} />
                )}
              </div>
            ))}
          </div>

          {/* ── content ─────────────────────────────────────────────────── */}
          <div style={{ padding: '28px 36px', overflow: 'auto' }}>
            {loading ? (
              <div style={{ color: 'var(--text-3)', padding: 40, textAlign: 'center' }}>Loading…</div>
            ) : (
              <>
                {/* ════════════════════════ ORGANIZATION ══════════════════ */}
                {section === 'organization' && (
                  <div style={{ maxWidth: 700 }}>
                    <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Organization</h2>
                    <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 24 }}>Configure your organization profile and platform-wide defaults.</p>
                    <div className="g-card">
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
                      <Field label="Maintenance Mode" hint="Show maintenance banner to all users">
                        <Toggle value={org.maintenance_mode ?? false} onChange={v => setOrg({ ...org, maintenance_mode: v })} />
                      </Field>
                    </div>
                    <SaveBar onSave={saveOrg} saving={saving} />
                  </div>
                )}

                {/* ════════════════════════ USERS & RBAC ══════════════════ */}
                {section === 'users' && (
                  <div>
                    <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Users & RBAC</h2>
                    <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 24 }}>Manage users, roles, and access control.</p>

                    {/* invite */}
                    <div className="g-card" style={{ marginBottom: 20 }}>
                      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Invite User</div>
                      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                        <input className="g-input" placeholder="Username" value={inviteUser} onChange={e => setInviteUser(e.target.value)} style={{ flex: 1, minWidth: 140 }} />
                        <input className="g-input" type="email" placeholder="Email" value={inviteEmail} onChange={e => setInviteEmail(e.target.value)} style={{ flex: 1, minWidth: 180 }} />
                        <select className="g-input" value={inviteRole} onChange={e => setInviteRole(e.target.value)} style={{ minWidth: 120 }}>
                          <option value="viewer">Viewer</option>
                          <option value="analyst">Analyst</option>
                          <option value="manager">Manager</option>
                          <option value="admin">Admin</option>
                        </select>
                        <button className="g-btn" disabled={inviting || !inviteUser || !inviteEmail} onClick={doInvite}>
                          {inviting ? 'Inviting…' : 'Send Invite'}
                        </button>
                      </div>
                    </div>

                    {/* users table */}
                    <div className="g-card" style={{ marginBottom: 20 }}>
                      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>
                        Users ({(d.users ?? []).length})
                      </div>
                      <table className="g-table" style={{ width: '100%' }}>
                        <thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead>
                        <tbody>
                          {(d.users ?? []).map((u: any, i: number) => (
                            <tr key={i}>
                              <td style={{ fontWeight: 600 }}>{u.username}</td>
                              <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{u.email}</td>
                              <td>
                                <select className="g-input" value={u.role} style={{ fontSize: 12, padding: '2px 6px' }}
                                  onChange={e => usersAPI.updateRole(u.id, e.target.value).then(loadAll)}>
                                  <option value="viewer">viewer</option>
                                  <option value="analyst">analyst</option>
                                  <option value="manager">manager</option>
                                  <option value="admin">admin</option>
                                </select>
                              </td>
                              <td>{pill(u.is_active ? 'active' : 'inactive')}</td>
                              <td>
                                <div style={{ display: 'flex', gap: 6 }}>
                                  <button className="g-btn-ghost" style={{ fontSize: 11, padding: '4px 10px' }}
                                    onClick={() => usersAPI.toggle(u.id, !u.is_active).then(loadAll)}>
                                    {u.is_active ? 'Deactivate' : 'Activate'}
                                  </button>
                                  {u.username !== user?.username && (
                                    <button className="g-btn-ghost" style={{ fontSize: 11, padding: '4px 10px', color: '#dc2626' }}
                                      onClick={() => { if (window.confirm(`Delete ${u.username}?`)) usersAPI.delete(u.id).then(loadAll); }}>
                                      Delete
                                    </button>
                                  )}
                                </div>
                              </td>
                            </tr>
                          ))}
                          {!d.users?.length && <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-3)', padding: 24 }}>No users</td></tr>}
                        </tbody>
                      </table>
                    </div>

                    {/* custom roles */}
                    <div className="g-card">
                      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Custom Roles</div>
                      <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
                        <input className="g-input" placeholder="Role name" value={roleName} onChange={e => setRoleName(e.target.value)} style={{ flex: 1 }} />
                        <button className="g-btn" disabled={!roleName}
                          onClick={() => customRolesAPI.create(roleName, []).then(() => { setRoleName(''); loadAll(); })}>
                          Create Role
                        </button>
                      </div>
                      <table className="g-table" style={{ width: '100%' }}>
                        <thead><tr><th>Role</th><th>Permissions</th><th>Actions</th></tr></thead>
                        <tbody>
                          {(d.roles ?? []).map((r: any, i: number) => (
                            <tr key={i}>
                              <td style={{ fontWeight: 600 }}>{r.name}</td>
                              <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{(r.permissions ?? []).slice(0, 3).join(', ')}{r.permissions?.length > 3 ? ` +${r.permissions.length - 3} more` : ''}</td>
                              <td>
                                <button className="g-btn-ghost" style={{ fontSize: 11, padding: '4px 10px', color: '#dc2626' }}
                                  onClick={() => { if (window.confirm(`Delete role ${r.name}?`)) customRolesAPI.delete(r.id).then(loadAll); }}>
                                  Delete
                                </button>
                              </td>
                            </tr>
                          ))}
                          {!d.roles?.length && <tr><td colSpan={3} style={{ textAlign: 'center', color: 'var(--text-3)', padding: 16 }}>No custom roles</td></tr>}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* ════════════════════════ AUTHENTICATION ════════════════ */}
                {section === 'authentication' && (
                  <div style={{ maxWidth: 700 }}>
                    <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Authentication</h2>
                    <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 24 }}>Configure MFA, sessions, password policy, and SSO.</p>

                    <div className="g-card" style={{ marginBottom: 20 }}>
                      <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-2)', marginBottom: 12 }}>MFA & Session</div>
                      <Field label="Require MFA for All Users" hint="Enforce multi-factor authentication organization-wide">
                        <Toggle value={org.require_mfa ?? false} onChange={v => setOrg({ ...org, require_mfa: v })} />
                      </Field>
                      <Field label="Session Timeout (minutes)" hint="Idle sessions are terminated after this duration">
                        <input className="g-input" type="number" min={5} max={1440} value={secPolicy.session_timeout_mins ?? 480} onChange={e => setSecPolicy({ ...secPolicy, session_timeout_mins: parseInt(e.target.value) })} style={{ width: 100 }} />
                      </Field>
                      <Field label="Max Concurrent Sessions" hint="Maximum active sessions per user account">
                        <input className="g-input" type="number" min={1} max={20} value={secPolicy.max_sessions ?? 5} onChange={e => setSecPolicy({ ...secPolicy, max_sessions: parseInt(e.target.value) })} style={{ width: 100 }} />
                      </Field>
                    </div>

                    <div className="g-card" style={{ marginBottom: 20 }}>
                      <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-2)', marginBottom: 12 }}>Password Policy</div>
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

                    <div className="g-card" style={{ marginBottom: 20 }}>
                      <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-2)', marginBottom: 12 }}>Login Protection</div>
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

                    {/* active sessions */}
                    <div className="g-card" style={{ marginBottom: 20 }}>
                      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Active Sessions ({(d.sessions ?? []).length})</div>
                      <table className="g-table" style={{ width: '100%' }}>
                        <thead><tr><th>User</th><th>IP</th><th>User Agent</th><th>Created</th><th>Actions</th></tr></thead>
                        <tbody>
                          {(d.sessions ?? []).slice(0, 10).map((s: any, i: number) => (
                            <tr key={i}>
                              <td style={{ fontWeight: 600 }}>{s.username ?? s.user_id}</td>
                              <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{s.ip_address}</td>
                              <td style={{ fontSize: 11, color: 'var(--text-3)', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.user_agent}</td>
                              <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{s.created_at ? new Date(s.created_at).toLocaleString() : ''}</td>
                              <td>
                                <button className="g-btn-ghost" style={{ fontSize: 11, padding: '4px 10px', color: '#dc2626' }}
                                  onClick={() => sessionsAPI.revoke(s.id).then(loadAll)}>Revoke</button>
                              </td>
                            </tr>
                          ))}
                          {!d.sessions?.length && <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-3)', padding: 16 }}>No active sessions</td></tr>}
                        </tbody>
                      </table>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 20 }}>
                      <button className="g-btn-ghost" onClick={saveOrg} disabled={saving}>Save MFA Setting</button>
                      <button className="g-btn" onClick={saveSecPolicy} disabled={saving}>{saving ? 'Saving…' : 'Save Security Policy'}</button>
                    </div>
                  </div>
                )}

                {/* ════════════════════════ AGENTS ════════════════════════ */}
                {section === 'agents' && (
                  <div style={{ maxWidth: 700 }}>
                    <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Agents</h2>
                    <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 24 }}>Configure global agent behavior and enrollment settings.</p>

                    <div className="g-card" style={{ marginBottom: 20 }}>
                      <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-2)', marginBottom: 12 }}>Monitoring</div>
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

                    <div className="g-card" style={{ marginBottom: 20 }}>
                      <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-2)', marginBottom: 12 }}>Collection</div>
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

                    <div className="g-card" style={{ marginBottom: 20 }}>
                      <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-2)', marginBottom: 12 }}>Enrollment</div>
                      <Field label="Enrollment Token TTL (hours)" hint="How long enrollment tokens remain valid after generation">
                        <input className="g-input" type="number" min={1} max={720} value={agentCfg.enrollment_token_ttl_hours ?? 48} onChange={e => setAgentCfg({ ...agentCfg, enrollment_token_ttl_hours: parseInt(e.target.value) })} style={{ width: 100 }} />
                      </Field>
                    </div>

                    <SaveBar onSave={saveAgentCfg} saving={saving} />
                  </div>
                )}

                {/* ════════════════════════ INTEGRATIONS ══════════════════ */}
                {section === 'integrations' && (
                  <div>
                    <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Integrations</h2>
                    <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 24 }}>Connect external security tools and data sources.</p>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
                      {(d.integrations ?? []).map((intg: any, i: number) => (
                        <div key={i} className="g-card">
                          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 10 }}>
                            <div>
                              <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-1)' }}>{intg.name ?? intg.integration_name}</div>
                              <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 2 }}>{intg.description ?? intg.integration_type}</div>
                            </div>
                            {pill(intg.enabled ? 'enabled' : 'disabled')}
                          </div>
                          {intg.url && <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 8, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{intg.url}</div>}
                          {intg.last_tested_at && (
                            <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 10 }}>
                              Last tested: {new Date(intg.last_tested_at).toLocaleString()}
                              {intg.last_test_success !== undefined && (
                                <span style={{ marginLeft: 8 }}>{intg.last_test_success ? '✓ Passed' : '✗ Failed'}</span>
                              )}
                            </div>
                          )}
                          <button className="g-btn-ghost" style={{ fontSize: 12 }}
                            disabled={testingIntg === (intg.name ?? intg.integration_name)}
                            onClick={() => testIntegration(intg.name ?? intg.integration_name)}>
                            {testingIntg === (intg.name ?? intg.integration_name) ? 'Testing…' : 'Test Connection'}
                          </button>
                        </div>
                      ))}
                      {!d.integrations?.length && (
                        <div className="g-card" style={{ gridColumn: '1/-1', textAlign: 'center', color: 'var(--text-3)', padding: 40 }}>
                          No integrations configured yet
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* ════════════════════════ NOTIFICATIONS ═════════════════ */}
                {section === 'notifications' && (
                  <div>
                    <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Notifications</h2>
                    <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 24 }}>Configure email alert rules and notification channels.</p>
                    <div className="g-card">
                      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>
                        Email Alert Rules ({(d.notifRules ?? []).length})
                      </div>
                      <table className="g-table" style={{ width: '100%' }}>
                        <thead><tr><th>Rule Name</th><th>Event</th><th>Recipients</th><th>Severity</th><th>Status</th><th>Actions</th></tr></thead>
                        <tbody>
                          {(d.notifRules ?? []).map((r: any, i: number) => (
                            <tr key={i}>
                              <td style={{ fontWeight: 600, color: 'var(--text-1)' }}>{r.name}</td>
                              <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{r.event_type}</td>
                              <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{Array.isArray(r.recipients) ? r.recipients.join(', ') : r.recipients}</td>
                              <td>{r.min_severity && pill(r.min_severity)}</td>
                              <td>
                                <Toggle value={r.enabled ?? false}
                                  onChange={(v) => notificationsAPI.toggleEmailRule(r.id, v).then(loadAll)} />
                              </td>
                              <td>
                                <button className="g-btn-ghost" style={{ fontSize: 11, padding: '4px 10px', color: '#dc2626' }}
                                  onClick={() => { if (window.confirm('Delete rule?')) notificationsAPI.deleteEmailRule(r.id).then(loadAll); }}>
                                  Delete
                                </button>
                              </td>
                            </tr>
                          ))}
                          {!d.notifRules?.length && <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-3)', padding: 24 }}>No email rules configured</td></tr>}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* ════════════════════════ AI MODELS ════════════════════ */}
                {section === 'ai-models' && (
                  <div>
                    <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>AI Models</h2>
                    <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 24 }}>Configure LLM providers, models, and API credentials.</p>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
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
                          <div key={p.provider} className="g-card">
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
                              <div>
                                <div style={{ fontWeight: 700, fontSize: 14, color: 'var(--text-1)' }}>{p.label}</div>
                                <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 2 }}>{existing?.model ?? p.model}</div>
                              </div>
                              <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                                {p.badge && pill(p.badge, '#7c3aed')}
                                {pill(existing?.enabled ? 'enabled' : 'disabled')}
                              </div>
                            </div>
                            {existing?.api_key_masked && (
                              <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 8, fontFamily: 'monospace' }}>
                                Key: {existing.api_key_masked}
                              </div>
                            )}
                            <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                              <input className="g-input" placeholder="API Key" type="password" style={{ flex: 1, fontSize: 12 }}
                                onChange={e => stteAPI.updateAIConfig({ provider: p.provider, model: p.model, api_key: e.target.value, enabled: true })} />
                              <button className="g-btn-ghost" style={{ fontSize: 11 }}
                                onClick={() => stteAPI.updateAIConfig({ provider: p.provider, model: p.model, enabled: !(existing?.enabled) }).then(loadAll)}>
                                {existing?.enabled ? 'Disable' : 'Enable'}
                              </button>
                            </div>
                            {existing?.rate_limit_rpm && (
                              <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 8 }}>
                                Rate: {existing.rate_limit_rpm} RPM · Budget: ${existing.monthly_budget_usd ?? 0}/mo
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* ════════════════════════ AI GUARDRAILS ════════════════ */}
                {section === 'ai-guardrails' && (
                  <div style={{ maxWidth: 700 }}>
                    <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>AI Guardrails</h2>
                    <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 24 }}>Safety controls, approval workflows, and data protection for AI.</p>
                    <div className="g-card" style={{ marginBottom: 20 }}>
                      <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-2)', marginBottom: 12 }}>Safety Controls</div>
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
                      <Field label="Audit All Queries" hint="Log every AI query and response to the audit trail">
                        <Toggle value={aiGuard.audit_all_queries ?? true} onChange={v => setAiGuard({ ...aiGuard, audit_all_queries: v })} />
                      </Field>
                    </div>
                    <div className="g-card" style={{ marginBottom: 20 }}>
                      <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-2)', marginBottom: 12 }}>Context Limits</div>
                      <Field label="Max Context Length (tokens)" hint="Maximum tokens of security data passed to AI per query">
                        <input className="g-input" type="number" min={1024} max={128000} value={aiGuard.max_context_length ?? 8192} onChange={e => setAiGuard({ ...aiGuard, max_context_length: parseInt(e.target.value) })} style={{ width: 120 }} />
                      </Field>
                      <Field label="Allowed Roles" hint="Comma-separated roles with AI access">
                        <input className="g-input" value={Array.isArray(aiGuard.allowed_roles) ? aiGuard.allowed_roles.join(',') : (aiGuard.allowed_roles ?? 'admin,analyst,manager')}
                          onChange={e => setAiGuard({ ...aiGuard, allowed_roles: e.target.value.split(',').map((s: string) => s.trim()) })} style={{ width: 220 }} />
                      </Field>
                    </div>
                    <SaveBar onSave={saveAIGuardrails} saving={saving} />
                  </div>
                )}

                {/* ════════════════════════ AI USAGE ═════════════════════ */}
                {section === 'ai-usage' && (
                  <div style={{ maxWidth: 700 }}>
                    <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Usage Limits</h2>
                    <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 24 }}>Set per-role message limits and monthly token budgets.</p>
                    <div className="g-card">
                      <table className="g-table" style={{ width: '100%' }}>
                        <thead><tr><th>Role</th><th>Daily Messages</th><th>Monthly Tokens</th><th>Monthly Budget (USD)</th></tr></thead>
                        <tbody>
                          {[
                            { role: 'admin',    msgs: 'Unlimited', tokens: 'Unlimited', budget: '$0 (no limit)' },
                            { role: 'analyst',  msgs: '500',       tokens: '2,000,000',  budget: '$100' },
                            { role: 'manager',  msgs: '200',       tokens: '1,000,000',  budget: '$50' },
                            { role: 'viewer',   msgs: '50',        tokens: '100,000',    budget: '$10' },
                          ].map((r, i) => (
                            <tr key={i}>
                              <td>{pill(r.role)}</td>
                              <td style={{ fontWeight: 600 }}>{r.msgs}</td>
                              <td style={{ color: 'var(--text-2)' }}>{r.tokens}</td>
                              <td style={{ color: 'var(--text-2)' }}>{r.budget}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <div className="g-card" style={{ marginTop: 16 }}>
                      <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-2)', marginBottom: 12 }}>Model Routing by Mode</div>
                      <table className="g-table" style={{ width: '100%' }}>
                        <thead><tr><th>Mode</th><th>Primary Model</th><th>Fallback</th></tr></thead>
                        <tbody>
                          {[
                            { mode: 'General Chat',          primary: 'claude-sonnet-4-6',  fallback: 'gpt-4o-mini' },
                            { mode: 'Investigation',         primary: 'claude-sonnet-4-6',  fallback: 'gpt-4o' },
                            { mode: 'Automation',            primary: 'claude-sonnet-4-6',  fallback: 'gpt-4o' },
                            { mode: 'Executive Assistant',   primary: 'claude-sonnet-4-6',  fallback: 'gemini-1.5-pro' },
                            { mode: 'Threat Intelligence',   primary: 'claude-sonnet-4-6',  fallback: 'llama3.1:70b (local)' },
                          ].map((r, i) => (
                            <tr key={i}>
                              <td style={{ fontWeight: 600 }}>{r.mode}</td>
                              <td style={{ color: 'var(--accent)', fontFamily: 'monospace', fontSize: 12 }}>{r.primary}</td>
                              <td style={{ color: 'var(--text-3)', fontFamily: 'monospace', fontSize: 12 }}>{r.fallback}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* ════════════════════════ BACKUP & RECOVERY ════════════ */}
                {section === 'backup' && (
                  <div>
                    <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Backup & Recovery</h2>
                    <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 24 }}>Configure automated backups and view restore points.</p>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>
                      <div className="g-card">
                        <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Backup Configuration</div>
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
                        <Field label="Storage">
                          <select className="g-input" value={backupCfg.storage ?? 'local'} onChange={e => setBackupCfg({ ...backupCfg, storage: e.target.value })} style={{ width: 120 }}>
                            <option value="local">Local</option>
                            <option value="s3">AWS S3</option>
                            <option value="gcs">Google Cloud</option>
                            <option value="azure">Azure Blob</option>
                          </select>
                        </Field>
                        <div style={{ display: 'flex', gap: 10, marginTop: 16 }}>
                          <button className="g-btn" onClick={saveBackupCfg} disabled={saving}>Save Config</button>
                          <button className="g-btn-ghost" onClick={triggerBackup}>Backup Now</button>
                        </div>
                      </div>

                      <div className="g-card">
                        <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Restore Points</div>
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
                              <button className="g-btn-ghost" style={{ fontSize: 11, padding: '4px 10px' }}>Restore</button>
                            </div>
                          </div>
                        ))}
                        {!d.backups?.length && <div style={{ color: 'var(--text-3)', textAlign: 'center', padding: 20 }}>No backup history</div>}
                      </div>
                    </div>

                    <div className="g-card">
                      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Backup History</div>
                      <table className="g-table" style={{ width: '100%' }}>
                        <thead><tr><th>Backup ID</th><th>Type</th><th>Size</th><th>Duration</th><th>Status</th><th>Triggered By</th><th>Time</th></tr></thead>
                        <tbody>
                          {(d.backups ?? []).map((b: any, i: number) => (
                            <tr key={i}>
                              <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{b.backup_id}</td>
                              <td>{pill(b.backup_type)}</td>
                              <td style={{ fontSize: 12 }}>{b.size_human ?? b.size_bytes}</td>
                              <td style={{ fontSize: 12 }}>{b.duration_secs}s</td>
                              <td>{pill(b.status)}</td>
                              <td style={{ fontSize: 12 }}>{b.triggered_by}</td>
                              <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{b.created_at ? new Date(b.created_at).toLocaleString() : ''}</td>
                            </tr>
                          ))}
                          {!d.backups?.length && <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-3)', padding: 24 }}>No backups yet — click "Backup Now" to create the first one</td></tr>}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* ════════════════════════ API MANAGEMENT ════════════════ */}
                {section === 'api-management' && (
                  <div>
                    <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>API Management</h2>
                    <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 24 }}>Manage API keys, rate limits, and integration access.</p>

                    <div className="g-card" style={{ marginBottom: 20 }}>
                      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Create API Key</div>
                      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                        <input className="g-input" placeholder="Key label (e.g. SIEM integration)" value={keyLabel} onChange={e => setKeyLabel(e.target.value)} style={{ flex: 1, minWidth: 200 }} />
                        <select className="g-input" value={keyRole} onChange={e => setKeyRole(e.target.value)} style={{ minWidth: 120 }}>
                          <option value="viewer">viewer</option>
                          <option value="analyst">analyst</option>
                          <option value="admin">admin</option>
                        </select>
                        <button className="g-btn" disabled={!keyLabel} onClick={createKey}>Generate Key</button>
                      </div>
                      {newKey && (
                        <div style={{ marginTop: 14, background: 'var(--bg-2)', borderRadius: 6, padding: '12px 16px', border: '1px solid var(--accent)55' }}>
                          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--accent)', marginBottom: 4 }}>API Key (copy now — won't be shown again):</div>
                          <div style={{ fontFamily: 'monospace', fontSize: 13, wordBreak: 'break-all', color: 'var(--text-1)' }}>{newKey}</div>
                          <button className="g-btn-ghost" style={{ marginTop: 8, fontSize: 11 }} onClick={() => navigator.clipboard.writeText(newKey)}>Copy</button>
                        </div>
                      )}
                    </div>

                    <div className="g-card">
                      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>API Keys ({(d.keys ?? []).length})</div>
                      <table className="g-table" style={{ width: '100%' }}>
                        <thead><tr><th>Label</th><th>Role</th><th>Key (masked)</th><th>Last Used</th><th>Expires</th><th>Actions</th></tr></thead>
                        <tbody>
                          {(d.keys ?? []).map((k: any, i: number) => (
                            <tr key={i}>
                              <td style={{ fontWeight: 600 }}>{k.label}</td>
                              <td>{pill(k.role)}</td>
                              <td style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--text-3)' }}>{k.key_prefix ?? k.api_key_prefix}****</td>
                              <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{k.last_used_at ? new Date(k.last_used_at).toLocaleString() : 'Never'}</td>
                              <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{k.expires_at ? new Date(k.expires_at).toLocaleDateString() : 'Never'}</td>
                              <td>
                                <button className="g-btn-ghost" style={{ fontSize: 11, padding: '4px 10px', color: '#dc2626' }}
                                  onClick={() => { if (window.confirm('Revoke this API key?')) apiKeysAPI.revoke(k.id).then(loadAll); }}>
                                  Revoke
                                </button>
                              </td>
                            </tr>
                          ))}
                          {!d.keys?.length && <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-3)', padding: 24 }}>No API keys yet</td></tr>}
                        </tbody>
                      </table>
                    </div>

                    <div className="g-card" style={{ marginTop: 16 }}>
                      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Rate Limits</div>
                      <table className="g-table" style={{ width: '100%' }}>
                        <thead><tr><th>Endpoint Group</th><th>Limit (req/min)</th><th>Burst</th><th>Auth</th></tr></thead>
                        <tbody>
                          {[
                            { group: 'Authentication', limit: 10, burst: 20, auth: false },
                            { group: 'Alerts & Incidents', limit: 300, burst: 500, auth: true },
                            { group: 'Search & Query', limit: 100, burst: 200, auth: true },
                            { group: 'AI Assistant', limit: 60, burst: 100, auth: true },
                            { group: 'Reports & Export', limit: 20, burst: 30, auth: true },
                            { group: 'Agent Ingestion', limit: 2000, burst: 5000, auth: false },
                          ].map((r, i) => (
                            <tr key={i}>
                              <td style={{ fontWeight: 600 }}>{r.group}</td>
                              <td>{r.limit}</td>
                              <td>{r.burst}</td>
                              <td>{pill(r.auth ? 'required' : 'none', r.auth ? '#7c3aed' : '#6b7280')}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* ════════════════════════ UPDATES ════════════════════════ */}
                {section === 'updates' && (
                  <div style={{ maxWidth: 700 }}>
                    <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Updates</h2>
                    <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 24 }}>Version management and platform update history.</p>

                    <div className="g-card" style={{ marginBottom: 20 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
                        <div>
                          <div style={{ fontWeight: 700, fontSize: 20, color: 'var(--text-1)' }}>v{d.updates?.current_version ?? '2.14.3'}</div>
                          <div style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 2 }}>Current Version — {pill(d.updates?.channel ?? 'stable')}</div>
                        </div>
                        <div style={{ textAlign: 'right' }}>
                          {d.updates?.update_available ? (
                            <button className="g-btn">Install Update v{d.updates?.latest_version}</button>
                          ) : (
                            <div style={{ fontSize: 13, color: '#16a34a', fontWeight: 600 }}>✓ Up to date</div>
                          )}
                          <button className="g-btn-ghost" onClick={checkUpdates} style={{ marginTop: 8, display: 'block', width: '100%' }}>Check for Updates</button>
                        </div>
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text-3)' }}>
                        Last checked: {d.updates?.last_checked ? new Date(d.updates.last_checked).toLocaleString() : '—'}
                      </div>
                    </div>

                    <div className="g-card">
                      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Release History</div>
                      {(d.updates?.history ?? []).length === 0 ? (
                        <div style={{ color: 'var(--text-3)', textAlign: 'center', padding: 20 }}>No update history</div>
                      ) : (
                        <table className="g-table" style={{ width: '100%' }}>
                          <thead><tr><th>Version</th><th>Type</th><th>Title</th><th>Applied By</th><th>Date</th></tr></thead>
                          <tbody>
                            {(d.updates?.history ?? []).map((u: any, i: number) => (
                              <tr key={i}>
                                <td style={{ fontFamily: 'monospace', fontWeight: 600, color: 'var(--accent)' }}>v{u.version}</td>
                                <td>{pill(u.release_type)}</td>
                                <td style={{ fontSize: 13 }}>{u.title}</td>
                                <td style={{ fontSize: 12 }}>{u.applied_by ?? '—'}</td>
                                <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{u.created_at ? new Date(u.created_at).toLocaleDateString() : ''}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      )}
                    </div>
                  </div>
                )}

                {/* ════════════════════════ LICENSING ═════════════════════ */}
                {section === 'licensing' && (
                  <div style={{ maxWidth: 700 }}>
                    <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Licensing</h2>
                    <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 24 }}>Manage your XCloak license, tier, and seat usage.</p>

                    <div className="g-card" style={{ marginBottom: 20 }}>
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

                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12, marginBottom: 16 }}>
                        {[
                          { label: 'Seats Used',     value: `${d.license?.seats_used ?? 0} / ${d.license?.seats_total ?? 5}` },
                          { label: 'Agents Used',    value: `${d.license?.agents_used ?? 0} / ${d.license?.agents_total ?? 25}` },
                          { label: 'Valid From',     value: d.license?.valid_from ?? '—' },
                          { label: 'Valid Until',    value: d.license?.valid_until ?? '—' },
                          { label: 'Issued To',      value: d.license?.issued_to ?? '—' },
                          { label: 'Activated At',   value: d.license?.activated_at ? new Date(d.license.activated_at).toLocaleDateString() : '—' },
                        ].map((item, i) => (
                          <div key={i} style={{ background: 'var(--bg-2)', borderRadius: 6, padding: '12px 16px' }}>
                            <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 4 }}>{item.label}</div>
                            <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-1)' }}>{item.value}</div>
                          </div>
                        ))}
                      </div>

                      {d.license?.features && (
                        <div>
                          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 8 }}>Enabled Features</div>
                          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                            {(Array.isArray(d.license.features) ? d.license.features :
                              JSON.parse(d.license.features || '[]')).map((f: string, i: number) => (
                              <span key={i} style={{ background: 'var(--accent)22', color: 'var(--accent)', border: '1px solid var(--accent)55', borderRadius: 4, padding: '2px 8px', fontSize: 11 }}>{f}</span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>

                    <div className="g-card">
                      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Activate License Key</div>
                      <div style={{ display: 'flex', gap: 10 }}>
                        <input className="g-input" placeholder="XXXX-XXXX-XXXX-XXXX-XXXX" value={licKey} onChange={e => setLicKey(e.target.value)} style={{ flex: 1, fontFamily: 'monospace' }} />
                        <button className="g-btn" disabled={activating || !licKey} onClick={activateLicense}>
                          {activating ? 'Activating…' : 'Activate'}
                        </button>
                      </div>
                      <p style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 10 }}>
                        Contact sales@xcloak.io to obtain an Enterprise license key or upgrade your current plan.
                      </p>
                    </div>
                  </div>
                )}

                {/* ════════════════════════ AUDIT TRAIL ════════════════════ */}
                {section === 'audit' && (
                  <div>
                    <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 4 }}>Audit Trail</h2>
                    <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 24 }}>Complete history of all platform configuration changes and administrative actions.</p>

                    <div className="g-card" style={{ marginBottom: 20 }}>
                      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Settings Changes</div>
                      <table className="g-table" style={{ width: '100%' }}>
                        <thead><tr><th>Time</th><th>Action</th><th>Section</th><th>Actor</th><th>Details</th></tr></thead>
                        <tbody>
                          {(d.stteAudit ?? []).map((e: any, i: number) => (
                            <tr key={i}>
                              <td style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
                                {e.created_at ? new Date(e.created_at).toLocaleString() : ''}
                              </td>
                              <td>{pill((e.action ?? '').replace(/_/g, ' '))}</td>
                              <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{e.section}</td>
                              <td style={{ fontSize: 12, fontWeight: 600 }}>{e.actor}</td>
                              <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{e.details ?? '—'}</td>
                            </tr>
                          ))}
                          {!d.stteAudit?.length && <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-3)', padding: 24 }}>No settings changes recorded</td></tr>}
                        </tbody>
                      </table>
                    </div>

                    <div className="g-card">
                      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Platform Audit Log</div>
                      <table className="g-table" style={{ width: '100%' }}>
                        <thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Target</th><th>IP</th></tr></thead>
                        <tbody>
                          {(d.auditLogs ?? []).slice(0, 50).map((e: any, i: number) => (
                            <tr key={i}>
                              <td style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
                                {e.created_at ? new Date(e.created_at).toLocaleString() : ''}
                              </td>
                              <td style={{ fontSize: 12 }}>{e.action}</td>
                              <td style={{ fontSize: 12, fontWeight: 600 }}>{e.username ?? e.actor ?? e.performed_by}</td>
                              <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{e.target ?? e.object_id ?? '—'}</td>
                              <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{e.ip_address ?? '—'}</td>
                            </tr>
                          ))}
                          {!d.auditLogs?.length && <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-3)', padding: 24 }}>No audit logs</td></tr>}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </RootLayout>
  );
}
