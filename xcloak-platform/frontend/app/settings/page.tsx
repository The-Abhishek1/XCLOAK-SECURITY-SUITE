'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { Pagination } from '@/components/ui/Pagination';
import { usersAPI, auditAPI, apiKeysAPI, customRolesAPI, sessionsAPI, securityPolicyAPI, integrationsAPI, authAPI, notificationsAPI } from '@/lib/api';
import type { UserSession, TenantSecurityPolicy } from '@/types';
import { useUser } from '@/context/UserContext';
import { timeAgo } from '@/lib/utils';
import {
  Users, UserCog, Shield, Server, ScrollText,
  Trash2, ToggleLeft, ToggleRight, ChevronDown, Search,
  Webhook, CheckCircle, XCircle, Send, Plus, Key, Copy, Eye, EyeOff,
  Mail, Lock, Smartphone, QrCode, Building2,
} from 'lucide-react';

const TABS = [
  { id: 'users',        label: 'User Management', icon: Users      },
  { id: 'integrations', label: 'Integrations',    icon: Webhook    },
  { id: 'sso',          label: 'SSO',              icon: Building2 },
  { id: 'apikeys',      label: 'API Keys',         icon: Key       },
  { id: 'roles',        label: 'Roles',            icon: Shield    },
  { id: 'profile',      label: 'My Profile',       icon: UserCog   },
  { id: 'email',        label: 'Email Alerts',     icon: Mail      },
  { id: '2fa',          label: '2FA Security',     icon: Lock      },
  { id: 'server',       label: 'Server Info',      icon: Server    },
  { id: 'audit',        label: 'Audit Log',        icon: ScrollText },
  { id: 'sessions',     label: 'Sessions',         icon: Lock      },
  { id: 'security',     label: 'Security Policy',  icon: Shield    },
] as const;
type Tab = typeof TABS[number]['id'];

const ROLES = ['admin', 'analyst', 'viewer'];

interface UserRow {
  id: number; username: string; email: string;
  role: string; is_active: boolean;
  last_login: string | null; created_at: string | null;
}
interface AuditPage {
  logs: any[]; total: number; page: number;
  per_page: number; pages: number;
}

export default function SettingsPage() {
  const { profile: authProfile } = useUser();
  const currentUsername = authProfile?.username || '';
  const [tab, setTab]     = useState<Tab>('users');
  const [toast, setToast] = useState<string | null>(null);
  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  // ── Users ────────────────────────────────────────────────────
  const [users, setUsers]             = useState<UserRow[]>([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [roleEditing, setRoleEditing] = useState<number | null>(null);
  const [userSearch, setUserSearch]   = useState('');
  const [showInvite, setShowInvite]   = useState(false);
  const [inviteForm, setInviteForm]   = useState({ username: '', email: '', role: 'analyst' });
  const [inviting, setInviting]       = useState(false);

  // ── Sessions ──────────────────────────────────────────────────
  const [sessions, setSessions]         = useState<UserSession[]>([]);
  const [allSessions, setAllSessions]   = useState<UserSession[]>([]);
  const [secPolicy, setSecPolicy]       = useState<TenantSecurityPolicy | null>(null);
  const [policyForm, setPolicyForm]     = useState<Partial<TenantSecurityPolicy>>({});
  const [savingPolicy, setSavingPolicy] = useState(false);

  // ── Integrations ─────────────────────────────────────────────
  const [integrations, setIntegrations] = useState<any[]>([]);
  const [intLoading, setIntLoading]     = useState(false);
  const [intSaving, setIntSaving]       = useState<string | null>(null);
  const [intForms, setIntForms]         = useState<Record<string, any>>({});
  const [deliveries, setDeliveries]     = useState<any[]>([]);
  const [installTokens, setInstallTokens] = useState<any[]>([]);
  const [genToken, setGenToken]         = useState<string | null>(null);
  const [tokenLabel, setTokenLabel]     = useState('');
  const [showSecrets, setShowSecrets]   = useState<Record<string, boolean>>({});

  // ── SSO (OIDC) ───────────────────────────────────────────────
  const [ssoLoading, setSsoLoading] = useState(false);
  const [ssoSaving, setSsoSaving]   = useState(false);
  const [ssoForm, setSsoForm]       = useState({ enabled: false, issuer_url: '', client_id: '', client_secret: '', button_label: '', jit_provisioning: false, default_role: 'analyst' });
  const [showSsoSecret, setShowSsoSecret] = useState(false);
  const [ssoConfigured, setSsoConfigured] = useState(false);

  // ── API Keys ─────────────────────────────────────────────────
  const [apiKeys, setApiKeys]       = useState<any[]>([]);
  const [apiKeysLoading, setApiKeysLoading] = useState(false);
  const [newKeyForm, setNewKeyForm] = useState({ label: '', role: 'viewer', expiresInDays: '' });
  const [genApiKey, setGenApiKey]   = useState<string | null>(null);
  const [creatingKey, setCreatingKey] = useState(false);
  const [revokingKey, setRevokingKey] = useState<number | null>(null);

  // ── Custom Roles ─────────────────────────────────────────────
  const [customRoles, setCustomRoles]   = useState<any[]>([]);
  const [allPermissions, setAllPermissions] = useState<string[]>([]);
  const [rolesLoading, setRolesLoading] = useState(false);
  const [showNewRole, setShowNewRole]   = useState(false);
  const [editingRole, setEditingRole]   = useState<any | null>(null);
  const [roleForm, setRoleForm]         = useState({ name: '', permissions: [] as string[] });
  const [savingRole, setSavingRole]     = useState(false);

  // ── Profile ──────────────────────────────────────────────────
  const [profile, setProfile]       = useState<any>(null);
  const [profileEmail, setProfileEmail] = useState('');
  const [changePw, setChangePw]     = useState({ current: '', next: '', confirm: '' });
  const [pwLoading, setPwLoading]   = useState(false);
  const [pwMsg, setPwMsg]           = useState<{ ok: boolean; text: string } | null>(null);

  // ── Email rules ──────────────────────────────────────────────
  const [emailRules, setEmailRules] = useState<any[]>([]);
  const [emailLoading, setEmailLoading] = useState(false);
  const [newRule, setNewRule]       = useState({ name: '', severity: 'critical', recipient: '' });

  // ── 2FA ──────────────────────────────────────────────────────
  const [twoFAEnabled, setTwoFAEnabled] = useState(false);
  const [totpQR, setTotpQR]         = useState('');
  const [totpSecret, setTotpSecret] = useState('');
  const [totpCode, setTotpCode]     = useState('');
  const [tfaLoading, setTfaLoading] = useState(false);

  // ── Audit ────────────────────────────────────────────────────
  const [auditPage, setAuditPage]   = useState<AuditPage | null>(null);
  const [auditP, setAuditP]         = useState(1);
  const [auditSearch, setAuditSearch] = useState('');
  const [auditLoading, setAuditLoading] = useState(false);
  const [exportStatus, setExportStatus] = useState<any>(null);


  // ── Loaders ──────────────────────────────────────────────────
  const loadUsers = useCallback(async () => {
    setUsersLoading(true);
    try { const r = await usersAPI.getAll(); setUsers(r.data || []); }
    finally { setUsersLoading(false); }
  }, []);

  const loadIntegrations = useCallback(async () => {
    setIntLoading(true);
    try {
      const [intR, delR, tokR] = await Promise.all([
        integrationsAPI.getAll(),
        integrationsAPI.getDeliveries(),
        integrationsAPI.getInstallTokens(),
      ]);
      const list = intR.data || [];
      setIntegrations(list);
      const forms: Record<string, any> = {};
      list.forEach((i: any) => { forms[i.name] = { enabled: i.enabled, config: { ...i.config } }; });
      setIntForms(forms);
      setDeliveries(delR.data || []);
      setInstallTokens(tokR.data || []);
    } finally { setIntLoading(false); }
  }, []);

  const loadSSO = useCallback(async () => {
    setSsoLoading(true);
    try {
      const r = await integrationsAPI.getAll();
      const row = (r.data || []).find((i: any) => i.name === 'oidc');
      if (row) {
        const secret = row.config?.client_secret || '';
        setSsoForm({
          enabled: row.enabled,
          issuer_url: row.config?.issuer_url || '',
          client_id: row.config?.client_id || '',
          // client_secret is redacted by the API once saved — leave blank
          // rather than show the placeholder bullets as if they were real.
          client_secret: secret === '••••••••' ? '' : secret,
          button_label: row.config?.button_label || '',
          jit_provisioning: row.config?.jit_provisioning || false,
          default_role: row.config?.default_role || 'analyst',
        });
        setSsoConfigured(true);
      } else {
        setSsoConfigured(false);
      }
    } finally { setSsoLoading(false); }
  }, []);

  const saveSSO = async () => {
    setSsoSaving(true);
    try {
      await integrationsAPI.save('oidc', {
        enabled: ssoForm.enabled,
        config: {
          issuer_url: ssoForm.issuer_url,
          client_id: ssoForm.client_id,
          client_secret: ssoForm.client_secret,
          button_label: ssoForm.button_label,
          jit_provisioning: ssoForm.jit_provisioning,
          default_role: ssoForm.default_role,
        },
      });
      notify('SSO settings saved');
      loadSSO();
    } catch (e: any) {
      notify(e?.response?.data?.error || 'Failed to save SSO settings');
    } finally { setSsoSaving(false); }
  };

  const loadAPIKeys = useCallback(async () => {
    setApiKeysLoading(true);
    try { const r = await apiKeysAPI.getAll(); setApiKeys(r.data || []); }
    finally { setApiKeysLoading(false); }
  }, []);

  const createAPIKey = async () => {
    if (!newKeyForm.label) { notify('Label is required'); return; }
    setCreatingKey(true);
    try {
      const days = newKeyForm.expiresInDays ? parseInt(newKeyForm.expiresInDays, 10) : 0;
      const r = await apiKeysAPI.create(newKeyForm.label, newKeyForm.role, days);
      setGenApiKey(r.data.key);
      setNewKeyForm({ label: '', role: 'viewer', expiresInDays: '' });
      loadAPIKeys();
    } catch (e: any) {
      notify(e?.response?.data?.error || 'Failed to create API key');
    } finally { setCreatingKey(false); }
  };

  const revokeAPIKey = async (id: number) => {
    if (!confirm('Revoke this API key? Anything using it will stop working immediately.')) return;
    setRevokingKey(id);
    try {
      await apiKeysAPI.revoke(id);
      setApiKeys(ks => ks.map(k => k.id === id ? { ...k, revoked_at: new Date().toISOString() } : k));
      notify('API key revoked');
    } catch (e: any) {
      notify(e?.response?.data?.error || 'Failed to revoke key');
    } finally { setRevokingKey(null); }
  };

  const loadCustomRoles = useCallback(async () => {
    setRolesLoading(true);
    try {
      const [r1, r2] = await Promise.all([customRolesAPI.getAll(), customRolesAPI.getPermissions()]);
      setCustomRoles(r1.data || []);
      setAllPermissions(r2.data || []);
    } finally { setRolesLoading(false); }
  }, []);

  const saveCustomRole = async () => {
    if (!roleForm.name && !editingRole) { notify('Name is required'); return; }
    setSavingRole(true);
    try {
      if (editingRole) {
        await customRolesAPI.update(editingRole.id, roleForm.permissions);
        notify('Role updated');
      } else {
        await customRolesAPI.create(roleForm.name, roleForm.permissions);
        notify('Role created');
      }
      setShowNewRole(false); setEditingRole(null);
      setRoleForm({ name: '', permissions: [] });
      loadCustomRoles();
    } catch (e: any) {
      notify(e?.response?.data?.error || 'Failed to save role');
    } finally { setSavingRole(false); }
  };

  const deleteCustomRole = async (id: number) => {
    if (!confirm('Delete this role?')) return;
    try {
      await customRolesAPI.delete(id);
      notify('Role deleted');
      loadCustomRoles();
    } catch (e: any) {
      notify(e?.response?.data?.error || 'Failed to delete role');
    }
  };

  const togglePerm = (p: string) => setRoleForm(f => ({
    ...f,
    permissions: f.permissions.includes(p) ? f.permissions.filter(x => x !== p) : [...f.permissions, p],
  }));

  const loadProfile = useCallback(async () => {
    try {
      const r = await authAPI.getProfile();
      setProfile(r.data);
      setProfileEmail(r.data?.email || '');
      setTwoFAEnabled(r.data?.totp_enabled || false);
    } catch {}
  }, []);

  const loadEmailRules = useCallback(async () => {
    setEmailLoading(true);
    try {
      const r = await notificationsAPI.getEmailRules();
      setEmailRules(r.data || []);
    } catch { setEmailRules([]); }
    finally { setEmailLoading(false); }
  }, []);

  const loadSessions = useCallback(async () => {
    try {
      const [myR, allR] = await Promise.allSettled([sessionsAPI.getMy(), sessionsAPI.getAll()]);
      if (myR.status === 'fulfilled') setSessions(myR.value.data.sessions || []);
      if (allR.status === 'fulfilled') setAllSessions(allR.value.data.sessions || []);
    } catch {}
  }, []);

  const loadSecurityPolicy = useCallback(async () => {
    try {
      const r = await securityPolicyAPI.get();
      setSecPolicy(r.data);
      setPolicyForm(r.data);
    } catch {}
  }, []);

  const saveSecurityPolicy = async () => {
    setSavingPolicy(true);
    try { await securityPolicyAPI.update(policyForm); await loadSecurityPolicy(); } catch {}
    setSavingPolicy(false);
  };

  const revokeSession = async (id: number) => {
    await sessionsAPI.revoke(id);
    loadSessions();
  };

  const load2FAStatus = useCallback(async () => {
    try {
      const r = await authAPI.getProfile();
      setTwoFAEnabled(r.data?.totp_enabled || false);
    } catch {}
  }, []);

  const loadAudit = useCallback(async (p = 1, search = '') => {
    setAuditLoading(true);
    try { const r = await auditAPI.getPaginated(p, 50, search); setAuditPage(r.data); }
    catch { setAuditPage(null); }
    finally { setAuditLoading(false); }
  }, []);

  const loadExportStatus = useCallback(async () => {
    try { const r = await auditAPI.getExportStatus(); setExportStatus(r.data); }
    catch { setExportStatus(null); }
  }, []);

  // Load on tab switch
  useEffect(() => {
    if (tab === 'users')        { loadUsers(); loadCustomRoles(); }
    if (tab === 'integrations') loadIntegrations();
    if (tab === 'sso')          loadSSO();
    if (tab === 'apikeys')      { loadAPIKeys(); loadCustomRoles(); }
    if (tab === 'roles')        loadCustomRoles();
    if (tab === 'profile')      loadProfile();
    if (tab === 'email')        loadEmailRules();
    if (tab === '2fa')          load2FAStatus();
    if (tab === 'audit')        { loadAudit(1, ''); loadExportStatus(); }
    if (tab === 'sessions')     { loadSessions(); }
    if (tab === 'security')     { loadSecurityPolicy(); }
  }, [tab]);

  // ── User actions ─────────────────────────────────────────────
  const updateRole = async (id: number, role: string) => {
    try { await usersAPI.updateRole(id, role); setUsers(u => u.map(x => x.id === id ? { ...x, role } : x)); notify('Role updated'); }
    catch { notify('Failed to update role'); }
    setRoleEditing(null);
  };
  const toggleUser = async (u: UserRow) => {
    try { await usersAPI.toggle(u.id, !u.is_active); setUsers(list => list.map(x => x.id === u.id ? { ...x, is_active: !x.is_active } : x)); }
    catch { notify('Failed to toggle user'); }
  };
  const deleteUser = async (id: number) => {
    if (!confirm('Delete this user?')) return;
    try { await usersAPI.delete(id); setUsers(u => u.filter(x => x.id !== id)); notify('User deleted'); }
    catch { notify('Failed to delete user'); }
  };
  const inviteUser = async () => {
    if (!inviteForm.username || !inviteForm.email) {
      notify('Username and email are required');
      return;
    }
    setInviting(true);
    try {
      await usersAPI.invite(inviteForm.username, inviteForm.email, inviteForm.role);
      notify(`Invite sent to ${inviteForm.email}`);
      setShowInvite(false);
      setInviteForm({ username: '', email: '', role: 'analyst' });
      loadUsers();
    } catch (e: any) {
      notify(e?.response?.data?.error || 'Failed to send invite');
    } finally { setInviting(false); }
  };
  const filteredUsers = users.filter(u =>
    !userSearch || u.username.toLowerCase().includes(userSearch.toLowerCase())
      || (u.email || '').toLowerCase().includes(userSearch.toLowerCase())
  );

  return (
    <RootLayout title="Settings" subtitle="Platform configuration">
      {toast && (
        <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm"
          style={{ color: 'var(--text-1)', minWidth: 220 }}>
          {toast}
        </div>
      )}

      <div className="space-y-4">
        {/* Tab bar */}
        <div className="flex gap-1 flex-wrap p-1 rounded-xl w-fit"
          style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
          {TABS.map(t => {
            const Icon = t.icon;
            return (
              <button key={t.id} onClick={() => setTab(t.id)}
                className="flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-medium transition-all"
                style={{
                  background: tab === t.id ? 'var(--accent-glow)' : 'transparent',
                  color:      tab === t.id ? 'var(--accent)' : 'var(--text-2)',
                  border:     tab === t.id ? '1px solid var(--accent-border)' : '1px solid transparent',
                }}>
                <Icon className="h-3.5 w-3.5" />{t.label}
              </button>
            );
          })}
        </div>

        {/* ══════════ USER MANAGEMENT ══════════ */}
        {tab === 'users' && (
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-3">
              <div className="relative max-w-sm flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                <input value={userSearch} onChange={e => setUserSearch(e.target.value)}
                  placeholder="Search users…" className="g-input pl-9" />
              </div>
              <button onClick={() => setShowInvite(true)} className="g-btn g-btn-primary text-xs shrink-0">
                <Plus className="h-3.5 w-3.5" /> Invite User
              </button>
            </div>
            <div className="g-table">
              <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 1fr 120px 80px 120px 80px' }}>
                <span>Username</span><span>Email</span><span>Role</span>
                <span>Status</span><span>Last Login</span><span className="text-right">Actions</span>
              </div>
              {usersLoading ? (
                <div className="py-12 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
              ) : filteredUsers.map(u => (
                <div key={u.id} className="g-tr grid gap-3 items-center px-4"
                  style={{ gridTemplateColumns: '1fr 1fr 120px 80px 120px 80px' }}>
                  <div className="flex items-center gap-2 min-w-0">
                    <div className="h-7 w-7 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
                      style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                      {u.username[0].toUpperCase()}
                    </div>
                    <span className="text-xs truncate" style={{ color: 'var(--text-1)' }}>{u.username}</span>
                  </div>
                  <span className="text-xs truncate" style={{ color: 'var(--text-2)' }}>{u.email || '—'}</span>
                  {roleEditing === u.id ? (
                    <select defaultValue={u.role} onChange={e => updateRole(u.id, e.target.value)}
                      onBlur={() => setRoleEditing(null)} autoFocus
                      className="g-select text-xs" style={{ height: 28, padding: '0 6px' }}>
                      {[...ROLES, ...customRoles.map(cr => cr.name)].map(r => <option key={r} value={r}>{r}</option>)}
                    </select>
                  ) : (
                    <button onClick={() => setRoleEditing(u.id)}
                      className="flex items-center gap-1 text-xs rounded-lg px-2 py-1 w-fit transition-colors"
                      style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                      <Shield className="h-3 w-3" style={{ color: u.role === 'admin' ? 'var(--accent)' : 'var(--text-3)' }} />
                      {u.role}<ChevronDown className="h-3 w-3" style={{ color: 'var(--text-3)' }} />
                    </button>
                  )}
                  <button onClick={() => toggleUser(u)} className="flex items-center gap-1 text-[10px]"
                    style={{ color: u.is_active ? 'var(--green)' : 'var(--text-3)' }}>
                    {u.is_active ? <ToggleRight className="h-4 w-4" /> : <ToggleLeft className="h-4 w-4" />}
                    {u.is_active ? 'Active' : 'Off'}
                  </button>
                  <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>
                    {u.last_login ? timeAgo(u.last_login) : 'Never'}
                  </span>
                  <div className="flex justify-end">
                    {u.username !== currentUsername && (
                      <button onClick={() => deleteUser(u.id)} className="p-1.5 rounded"
                        style={{ color: 'var(--text-3)' }}
                        onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--red)'}
                        onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ══════════ INTEGRATIONS ══════════ */}
        {tab === 'integrations' && (
          <div className="space-y-5">
            {intLoading ? (
              <div className="py-12 text-center animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
            ) : (
              <>
                <div className="grid gap-4 sm:grid-cols-2">
                  {integrations.map(int => {
                    const form = intForms[int.name] || { enabled: false, config: {} };
                    const save = async () => {
                      setIntSaving(int.name);
                      try { await integrationsAPI.save(int.name, form); notify(`${int.name} saved`); }
                      catch { notify('Save failed'); }
                      finally { setIntSaving(null); }
                    };
                    const test = async () => {
                      try { await integrationsAPI.test(int.name); notify(`Test sent via ${int.name}`); }
                      catch { notify('Test failed'); }
                    };
                    const setForm = (patch: any) => setIntForms(f => ({ ...f, [int.name]: { ...form, ...patch } }));
                    const setConfig = (patch: any) => setForm({ config: { ...form.config, ...patch } });

                    return (
                      <div key={int.name} className="g-card p-5 space-y-4">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-semibold capitalize" style={{ color: 'var(--text-1)' }}>{int.name}</p>
                            <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                              {int.name === 'slack'       ? 'Slack webhook notifications'
                                : int.name === 'webhook'     ? 'Generic HTTP webhook'
                                : int.name === 'email'       ? 'SMTP email alerts'
                                : int.name === 'pagerduty'   ? 'PagerDuty incident routing'
                                : int.name === 'teams'       ? 'Microsoft Teams Adaptive Card alerts'
                                : int.name === 'jira'        ? 'Jira Cloud — auto-create security tickets'
                                : int.name === 'servicenow'  ? 'ServiceNow — create incidents via Table API'
                                : int.name === 'opsgenie'    ? 'OpsGenie — alert routing and on-call management'
                                : int.name === 'datadog'     ? 'Datadog — forward security events to your observability stack'
                                : int.name === 'splunk'      ? 'Splunk HEC — stream alerts into your Splunk SIEM'
                                : int.name === 'ldap'        ? 'Active Directory / LDAP identity enrichment'
                                : int.name}
                            </p>
                          </div>
                          <button onClick={() => setForm({ enabled: !form.enabled })}>
                            {form.enabled
                              ? <ToggleRight className="h-6 w-6" style={{ color: 'var(--accent)' }} />
                              : <ToggleLeft  className="h-6 w-6" style={{ color: 'var(--text-3)' }} />}
                          </button>
                        </div>
                        {form.enabled && (
                          <div className="space-y-3">
                            {int.name === 'slack' && (
                              <>
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Webhook URL</label>
                                  <div className="relative">
                                    <input type={showSecrets['slack'] ? 'text' : 'password'}
                                      value={form.config.webhook_url || ''}
                                      onChange={e => setConfig({ webhook_url: e.target.value })}
                                      placeholder="https://hooks.slack.com/…" className="g-input w-full pr-8 text-xs mono" />
                                    <button className="absolute right-2 top-1/2 -translate-y-1/2"
                                      onClick={() => setShowSecrets(s => ({ ...s, slack: !s.slack }))}
                                      style={{ color: 'var(--text-3)' }}>
                                      {showSecrets['slack'] ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                                    </button>
                                  </div>
                                </div>
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Channel</label>
                                  <input value={form.config.channel || ''} onChange={e => setConfig({ channel: e.target.value })}
                                    placeholder="#security" className="g-input w-full text-xs mono" />
                                </div>
                              </>
                            )}
                            {int.name === 'webhook' && (
                              <>
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Endpoint URL</label>
                                  <input value={form.config.url || ''} onChange={e => setConfig({ url: e.target.value })}
                                    placeholder="https://your-endpoint.com/hook" className="g-input w-full text-xs mono" />
                                </div>
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Secret</label>
                                  <div className="relative">
                                    <input type={showSecrets['webhook'] ? 'text' : 'password'}
                                      value={form.config.secret || ''} onChange={e => setConfig({ secret: e.target.value })}
                                      placeholder="Signing secret" className="g-input w-full pr-8 text-xs mono" />
                                    <button className="absolute right-2 top-1/2 -translate-y-1/2"
                                      onClick={() => setShowSecrets(s => ({ ...s, webhook: !s.webhook }))}
                                      style={{ color: 'var(--text-3)' }}>
                                      {showSecrets['webhook'] ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                                    </button>
                                  </div>
                                </div>
                              </>
                            )}
                            {int.name === 'pagerduty' && (
                              <div>
                                <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Integration Key</label>
                                <input value={form.config.integration_key || ''}
                                  onChange={e => setConfig({ integration_key: e.target.value })}
                                  placeholder="PagerDuty Events API v2 key" className="g-input w-full text-xs mono" />
                              </div>
                            )}
                            {int.name === 'teams' && (
                              <div>
                                <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Incoming Webhook URL</label>
                                <input value={form.config.webhook_url || ''}
                                  onChange={e => setConfig({ webhook_url: e.target.value })}
                                  placeholder="https://outlook.office.com/webhook/…" className="g-input w-full text-xs mono" />
                              </div>
                            )}
                            {int.name === 'jira' && (
                              <div className="space-y-3">
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Jira Base URL</label>
                                  <input value={form.config.url || ''}
                                    onChange={e => setConfig({ url: e.target.value })}
                                    placeholder="https://your-org.atlassian.net" className="g-input w-full text-xs mono" />
                                </div>
                                <div className="grid grid-cols-2 gap-2">
                                  <div>
                                    <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Email</label>
                                    <input value={form.config.email || ''}
                                      onChange={e => setConfig({ email: e.target.value })}
                                      placeholder="you@org.com" className="g-input w-full text-xs" />
                                  </div>
                                  <div>
                                    <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>API Token</label>
                                    <input type="password" value={form.config.api_token || ''}
                                      onChange={e => setConfig({ api_token: e.target.value })}
                                      placeholder="Jira API token" className="g-input w-full text-xs mono" />
                                  </div>
                                </div>
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Project Key</label>
                                  <input value={form.config.project_key || ''}
                                    onChange={e => setConfig({ project_key: e.target.value })}
                                    placeholder="SEC" className="g-input w-full text-xs mono" />
                                </div>
                              </div>
                            )}
                            {int.name === 'servicenow' && (
                              <div className="space-y-3">
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Instance URL</label>
                                  <input value={form.config.instance_url || ''}
                                    onChange={e => setConfig({ instance_url: e.target.value })}
                                    placeholder="https://your-instance.service-now.com" className="g-input w-full text-xs mono" />
                                </div>
                                <div className="grid grid-cols-2 gap-2">
                                  <div>
                                    <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Username</label>
                                    <input value={form.config.username || ''}
                                      onChange={e => setConfig({ username: e.target.value })}
                                      placeholder="admin" className="g-input w-full text-xs mono" />
                                  </div>
                                  <div>
                                    <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Password</label>
                                    <input type="password" value={form.config.password || ''}
                                      onChange={e => setConfig({ password: e.target.value })}
                                      placeholder="ServiceNow password" className="g-input w-full text-xs mono" />
                                  </div>
                                </div>
                              </div>
                            )}
                            {int.name === 'opsgenie' && (
                              <div className="space-y-3">
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>API Key</label>
                                  <input type="password" value={form.config.api_key || ''}
                                    onChange={e => setConfig({ api_key: e.target.value })}
                                    placeholder="OpsGenie API key" className="g-input w-full text-xs mono" />
                                </div>
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Responder Team <span style={{ color: 'var(--text-3)', fontWeight: 'normal' }}>(optional)</span></label>
                                  <input value={form.config.team || ''}
                                    onChange={e => setConfig({ team: e.target.value })}
                                    placeholder="noc-team" className="g-input w-full text-xs mono" />
                                </div>
                              </div>
                            )}
                            {int.name === 'datadog' && (
                              <div className="space-y-3">
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>API Key</label>
                                  <input type="password" value={form.config.api_key || ''}
                                    onChange={e => setConfig({ api_key: e.target.value })}
                                    placeholder="Datadog API key" className="g-input w-full text-xs mono" />
                                </div>
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Site</label>
                                  <select value={form.config.site || 'datadoghq.com'}
                                    onChange={e => setConfig({ site: e.target.value })}
                                    className="g-input w-full text-xs">
                                    <option value="datadoghq.com">US (datadoghq.com)</option>
                                    <option value="datadoghq.eu">EU (datadoghq.eu)</option>
                                    <option value="us3.datadoghq.com">US3 (us3.datadoghq.com)</option>
                                    <option value="us5.datadoghq.com">US5 (us5.datadoghq.com)</option>
                                  </select>
                                </div>
                              </div>
                            )}
                            {int.name === 'splunk' && (
                              <div className="space-y-3">
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>HEC URL</label>
                                  <input value={form.config.url || ''}
                                    onChange={e => setConfig({ url: e.target.value })}
                                    placeholder="https://splunk.example.com:8088" className="g-input w-full text-xs mono" />
                                </div>
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>HEC Token</label>
                                  <input type="password" value={form.config.token || ''}
                                    onChange={e => setConfig({ token: e.target.value })}
                                    placeholder="Splunk HEC token" className="g-input w-full text-xs mono" />
                                </div>
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Index <span style={{ color: 'var(--text-3)', fontWeight: 'normal' }}>(optional)</span></label>
                                  <input value={form.config.index || ''}
                                    onChange={e => setConfig({ index: e.target.value })}
                                    placeholder="security" className="g-input w-full text-xs mono" />
                                </div>
                              </div>
                            )}
                            {int.name === 'ldap' && (
                              <div className="space-y-3">
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>LDAP URL</label>
                                  <input value={form.config.url || ''}
                                    onChange={e => setConfig({ url: e.target.value })}
                                    placeholder="ldap://dc.corp.example.com:389" className="g-input w-full text-xs mono" />
                                </div>
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Bind DN</label>
                                  <input value={form.config.bind_dn || ''}
                                    onChange={e => setConfig({ bind_dn: e.target.value })}
                                    placeholder="CN=svc-xcloak,OU=Service,DC=corp,DC=com" className="g-input w-full text-xs mono" />
                                </div>
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Bind Password</label>
                                  <input type="password" value={form.config.bind_password || ''}
                                    onChange={e => setConfig({ bind_password: e.target.value })}
                                    placeholder="Service account password" className="g-input w-full text-xs mono" />
                                </div>
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Base DN</label>
                                  <input value={form.config.base_dn || ''}
                                    onChange={e => setConfig({ base_dn: e.target.value })}
                                    placeholder="DC=corp,DC=example,DC=com" className="g-input w-full text-xs mono" />
                                </div>
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>User Filter <span style={{ color: 'var(--text-3)', fontWeight: 'normal' }}>(optional)</span></label>
                                  <input value={form.config.user_filter || ''}
                                    onChange={e => setConfig({ user_filter: e.target.value })}
                                    placeholder="(sAMAccountName=%s)" className="g-input w-full text-xs mono" />
                                </div>
                              </div>
                            )}
                            <div className="flex gap-2">
                              <button onClick={save} disabled={intSaving === int.name}
                                className="g-btn g-btn-primary text-xs flex-1 justify-center">
                                {intSaving === int.name ? 'Saving…' : 'Save'}
                              </button>
                              <button onClick={test} className="g-btn g-btn-ghost text-xs">
                                <Send className="h-3.5 w-3.5" /> Test
                              </button>
                            </div>
                          </div>
                        )}
                        {!form.enabled && (
                          <button onClick={save} className="g-btn g-btn-ghost text-xs w-full justify-center">
                            Save disabled state
                          </button>
                        )}
                      </div>
                    );
                  })}
                </div>

                {/* Install tokens */}
                <div className="g-card">
                  <div className="flex items-center justify-between px-5 pt-4 pb-3"
                    style={{ borderBottom: '1px solid var(--border)' }}>
                    <div className="flex items-center gap-2">
                      <Key className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                      <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Agent Install Tokens</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <input value={tokenLabel} onChange={e => setTokenLabel(e.target.value)}
                        placeholder="Label (optional)" className="g-input text-xs" style={{ width: 150 }} />
                      <button onClick={async () => {
                        const r = await integrationsAPI.createInstallToken(tokenLabel);
                        setGenToken(r.data.token); setTokenLabel('');
                        const r2 = await integrationsAPI.getInstallTokens();
                        setInstallTokens(r2.data || []);
                      }} className="g-btn g-btn-primary text-xs">
                        <Plus className="h-3.5 w-3.5" /> Generate
                      </button>
                    </div>
                  </div>
                  {genToken && (
                    <div className="mx-4 my-3 p-3 rounded-xl"
                      style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
                      <p className="text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>New token — copy now (shown once):</p>
                      <div className="flex items-center gap-2">
                        <code className="flex-1 text-[11px] font-mono break-all" style={{ color: 'var(--accent)' }}>{genToken}</code>
                        <button onClick={() => { navigator.clipboard.writeText(genToken!); notify('Copied!'); }}
                          style={{ color: 'var(--accent)' }}><Copy className="h-4 w-4" /></button>
                      </div>
                    </div>
                  )}
                  <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                    {installTokens.length === 0 ? (
                      <p className="px-5 py-4 text-xs" style={{ color: 'var(--text-3)' }}>No tokens generated yet.</p>
                    ) : installTokens.map((t: any) => (
                      <div key={t.id} className="flex items-center gap-3 px-5 py-2.5">
                        <div className="flex-1 min-w-0">
                          <p className="text-xs" style={{ color: 'var(--text-1)' }}>{t.label || 'Unlabelled'}</p>
                          <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                            By {t.created_by} · Expires {new Date(t.expires_at).toLocaleDateString()}
                          </p>
                        </div>
                        <span className={`text-[10px] px-2 py-0.5 rounded font-medium ${t.used ? 's-offline' : 's-online'}`}>
                          {t.used ? 'used' : 'active'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {deliveries.length > 0 && (
                  <div className="g-card">
                    <p className="text-xs font-semibold px-5 pt-4 pb-3"
                      style={{ color: 'var(--text-1)', borderBottom: '1px solid var(--border)' }}>
                      Recent Webhook Deliveries
                    </p>
                    <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                      {deliveries.slice(0, 10).map((d: any) => (
                        <div key={d.id} className="flex items-center gap-3 px-5 py-2">
                          {d.success
                            ? <CheckCircle className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--green)' }} />
                            : <XCircle    className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--red)' }} />}
                          <span className="text-xs capitalize" style={{ color: 'var(--text-2)' }}>{d.integration}</span>
                          <span className="text-[10px] mono" style={{ color: 'var(--text-3)' }}>{d.event_type}</span>
                          <span className="ml-auto text-[10px]" style={{ color: d.success ? 'var(--green)' : 'var(--red)' }}>
                            {d.status_code || 'error'} · {timeAgo(d.delivered_at)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* ══════════ SSO ══════════ */}
        {tab === 'sso' && (
          <div className="space-y-4 max-w-lg">
            <div className="g-card p-5 space-y-4">
              {ssoLoading ? (
                <div className="py-12 text-center animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
              ) : (
                <>
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Single Sign-On (OIDC)</p>
                      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                        Okta, Azure AD, Google Workspace, Auth0, Keycloak, or any OIDC-compliant IdP.
                      </p>
                    </div>
                    <button onClick={() => setSsoForm(f => ({ ...f, enabled: !f.enabled }))}>
                      {ssoForm.enabled
                        ? <ToggleRight className="h-6 w-6" style={{ color: 'var(--accent)' }} />
                        : <ToggleLeft  className="h-6 w-6" style={{ color: 'var(--text-3)' }} />}
                    </button>
                  </div>

                  <div>
                    <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Issuer URL</label>
                    <input value={ssoForm.issuer_url} onChange={e => setSsoForm(f => ({ ...f, issuer_url: e.target.value }))}
                      placeholder="https://your-tenant.okta.com" className="g-input w-full text-xs mono" />
                  </div>
                  <div>
                    <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Client ID</label>
                    <input value={ssoForm.client_id} onChange={e => setSsoForm(f => ({ ...f, client_id: e.target.value }))}
                      placeholder="Client ID from your IdP app registration" className="g-input w-full text-xs mono" />
                  </div>
                  <div>
                    <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Client Secret</label>
                    <div className="relative">
                      <input type={showSsoSecret ? 'text' : 'password'}
                        value={ssoForm.client_secret} onChange={e => setSsoForm(f => ({ ...f, client_secret: e.target.value }))}
                        placeholder={ssoConfigured ? 'Leave blank to keep current secret' : 'Client secret from your IdP'}
                        className="g-input w-full pr-8 text-xs mono" />
                      <button className="absolute right-2 top-1/2 -translate-y-1/2"
                        onClick={() => setShowSsoSecret(s => !s)} style={{ color: 'var(--text-3)' }}>
                        {showSsoSecret ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                      </button>
                    </div>
                  </div>
                  <div>
                    <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Button Label (optional)</label>
                    <input value={ssoForm.button_label} onChange={e => setSsoForm(f => ({ ...f, button_label: e.target.value }))}
                      placeholder="Sign in with Acme Corp" className="g-input w-full text-xs" />
                  </div>

                  {/* JIT provisioning */}
                  <div className="rounded-xl p-3 space-y-2"
                    style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-[11px] font-semibold" style={{ color: 'var(--text-1)' }}>JIT Provisioning</p>
                        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                          Auto-create accounts on first SSO login (no pre-invite needed).
                        </p>
                      </div>
                      <button onClick={() => setSsoForm(f => ({ ...f, jit_provisioning: !f.jit_provisioning }))}>
                        {ssoForm.jit_provisioning
                          ? <ToggleRight className="h-5 w-5" style={{ color: 'var(--accent)' }} />
                          : <ToggleLeft  className="h-5 w-5" style={{ color: 'var(--text-3)' }} />}
                      </button>
                    </div>
                    {ssoForm.jit_provisioning && (
                      <div>
                        <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Default role for JIT users</label>
                        <select value={ssoForm.default_role}
                          onChange={e => setSsoForm(f => ({ ...f, default_role: e.target.value }))}
                          className="g-select w-full text-xs">
                          <option value="viewer">Viewer</option>
                          <option value="analyst">Analyst</option>
                          <option value="admin">Admin</option>
                        </select>
                      </div>
                    )}
                  </div>

                  {/* Callback URL */}
                  <div className="rounded-lg px-3 py-2.5 text-[11px]" style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                    Register this callback URL with your identity provider:
                    <div className="mono mt-1 break-all" style={{ color: 'var(--accent)' }}>
                      {(process.env.NEXT_PUBLIC_BACKEND_PUBLIC_URL || 'http://localhost:8080') + '/api/auth/oidc/callback'}
                    </div>
                  </div>

                  <div className="flex gap-2">
                    <button onClick={saveSSO} disabled={ssoSaving} className="g-btn g-btn-primary text-xs flex-1 justify-center">
                      {ssoSaving ? 'Saving…' : 'Save SSO Settings'}
                    </button>
                    {ssoConfigured && ssoForm.enabled && (
                      <a href="/login?sso_test=1" target="_blank" rel="noopener noreferrer"
                        className="g-btn g-btn-ghost text-xs px-4">
                        Test Login
                      </a>
                    )}
                  </div>
                </>
              )}
            </div>
          </div>
        )}

        {/* ══════════ API KEYS ══════════ */}
        {tab === 'apikeys' && (
          <div className="g-card max-w-2xl">
            <div className="flex items-center justify-between px-5 pt-4 pb-3"
              style={{ borderBottom: '1px solid var(--border)' }}>
              <div>
                <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>API Keys</p>
                <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>
                  Long-lived credentials for scripts and automation — each key acts like a user with the chosen role.
                </p>
              </div>
            </div>

            <div className="flex items-end gap-2 px-5 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="flex-1">
                <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Label</label>
                <input value={newKeyForm.label} onChange={e => setNewKeyForm(f => ({ ...f, label: e.target.value }))}
                  placeholder="ci-pipeline" className="g-input text-xs w-full" />
              </div>
              <div>
                <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Role</label>
                <select value={newKeyForm.role} onChange={e => setNewKeyForm(f => ({ ...f, role: e.target.value }))}
                  className="g-select text-xs" style={{ width: 110 }}>
                  {[...ROLES, ...customRoles.map(cr => cr.name)].map(r => <option key={r} value={r}>{r}</option>)}
                </select>
              </div>
              <div>
                <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Expires (days)</label>
                <input value={newKeyForm.expiresInDays} onChange={e => setNewKeyForm(f => ({ ...f, expiresInDays: e.target.value }))}
                  placeholder="never" className="g-input text-xs" style={{ width: 90 }} />
              </div>
              <button onClick={createAPIKey} disabled={creatingKey} className="g-btn g-btn-primary text-xs">
                <Plus className="h-3.5 w-3.5" /> Generate
              </button>
            </div>

            {genApiKey && (
              <div className="mx-4 my-3 p-3 rounded-xl"
                style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
                <p className="text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>New key — copy now (shown once, never displayed again):</p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 text-[11px] font-mono break-all" style={{ color: 'var(--accent)' }}>{genApiKey}</code>
                  <button onClick={() => { navigator.clipboard.writeText(genApiKey!); notify('Copied!'); }}
                    style={{ color: 'var(--accent)' }}><Copy className="h-4 w-4" /></button>
                </div>
              </div>
            )}

            <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {apiKeysLoading ? (
                <div className="py-12 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
              ) : apiKeys.length === 0 ? (
                <p className="px-5 py-4 text-xs" style={{ color: 'var(--text-3)' }}>No API keys yet.</p>
              ) : apiKeys.map((k: any) => (
                <div key={k.id} className="flex items-center gap-3 px-5 py-2.5">
                  <div className="flex-1 min-w-0">
                    <p className="text-xs flex items-center gap-2" style={{ color: 'var(--text-1)' }}>
                      {k.label}
                      <span className="mono text-[10px]" style={{ color: 'var(--text-3)' }}>{k.key_prefix}…</span>
                    </p>
                    <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                      {k.role} · by {k.created_by} · {k.last_used_at ? `last used ${timeAgo(k.last_used_at)}` : 'never used'}
                      {k.expires_at ? ` · expires ${new Date(k.expires_at).toLocaleDateString()}` : ' · never expires'}
                    </p>
                  </div>
                  {k.revoked_at ? (
                    <span className="text-[10px] px-2 py-0.5 rounded font-medium s-offline">revoked</span>
                  ) : (
                    <button onClick={() => revokeAPIKey(k.id)} disabled={revokingKey === k.id}
                      className="g-btn g-btn-ghost text-xs"
                      style={{ color: 'var(--red)' }}>
                      <Trash2 className="h-3.5 w-3.5" /> Revoke
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ══════════ ROLES ══════════ */}
        {tab === 'roles' && (
          <div className="g-card max-w-2xl">
            <div className="flex items-center justify-between px-5 pt-4 pb-3"
              style={{ borderBottom: '1px solid var(--border)' }}>
              <div>
                <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Custom Roles</p>
                <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>
                  Grant exactly the permissions a role needs — admin always has everything;
                  custom roles get only what&apos;s checked below.
                </p>
              </div>
              <button onClick={() => { setEditingRole(null); setRoleForm({ name: '', permissions: [] }); setShowNewRole(true); }}
                disabled={rolesLoading} className="g-btn g-btn-primary text-xs">
                <Plus className="h-3.5 w-3.5" /> New Role
              </button>
            </div>

            <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {rolesLoading ? (
                <div className="py-12 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
              ) : customRoles.length === 0 ? (
                <p className="px-5 py-4 text-xs" style={{ color: 'var(--text-3)' }}>No custom roles yet.</p>
              ) : customRoles.map((r: any) => (
                <div key={r.id} className="flex items-center gap-3 px-5 py-2.5">
                  <div className="flex-1 min-w-0">
                    <p className="text-xs" style={{ color: 'var(--text-1)' }}>{r.name}</p>
                    <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                      {r.permissions.length} permission{r.permissions.length === 1 ? '' : 's'} · by {r.created_by}
                    </p>
                  </div>
                  <button onClick={() => { setEditingRole(r); setRoleForm({ name: r.name, permissions: r.permissions }); setShowNewRole(true); }}
                    className="g-btn g-btn-ghost text-xs">Edit</button>
                  <button onClick={() => deleteCustomRole(r.id)} className="g-btn g-btn-ghost text-xs" style={{ color: 'var(--red)' }}>
                    <Trash2 className="h-3.5 w-3.5" /> Delete
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {showNewRole && (
          <div className="g-modal-backdrop" onClick={() => setShowNewRole(false)}>
            <div className="g-modal" style={{ maxWidth: 480 }} onClick={e => e.stopPropagation()}>
              <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
                <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
                  {editingRole ? `Edit "${editingRole.name}"` : 'New Role'}
                </h2>
                <button onClick={() => setShowNewRole(false)} style={{ color: 'var(--text-2)' }}><XCircle className="h-4 w-4" /></button>
              </div>
              <div className="p-5 space-y-3">
                {!editingRole && (
                  <div>
                    <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Role name</label>
                    <input value={roleForm.name} onChange={e => setRoleForm(f => ({ ...f, name: e.target.value }))}
                      placeholder="rule-editor" className="g-input w-full" />
                  </div>
                )}
                <div>
                  <label className="block text-xs mb-2" style={{ color: 'var(--text-3)' }}>Permissions</label>
                  <div className="space-y-1.5 max-h-64 overflow-y-auto">
                    {allPermissions.map(p => (
                      <label key={p} className="flex items-center gap-2 text-xs cursor-pointer" style={{ color: 'var(--text-1)' }}>
                        <input type="checkbox" checked={roleForm.permissions.includes(p)} onChange={() => togglePerm(p)} />
                        {p.replace(/_/g, ' ')}
                      </label>
                    ))}
                  </div>
                </div>
              </div>
              <div className="flex gap-3 px-5 pb-5">
                <button onClick={() => setShowNewRole(false)} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
                <button onClick={saveCustomRole} disabled={savingRole} className="g-btn g-btn-primary flex-1 justify-center">
                  {savingRole ? 'Saving…' : editingRole ? 'Save Changes' : 'Create Role'}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ══════════ MY PROFILE ══════════ */}
        {tab === 'profile' && (
          <div className="space-y-4 max-w-md">
            <div className="g-card p-5 space-y-4">
              <div className="flex items-center gap-4">
                <div className="h-14 w-14 rounded-2xl flex items-center justify-center text-2xl font-bold shrink-0"
                  style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '2px solid var(--accent-border)' }}>
                  {(profile?.username || currentUsername)[0]?.toUpperCase()}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
                    {profile?.username || currentUsername}
                  </p>
                  <p className="text-xs capitalize" style={{ color: 'var(--text-3)' }}>{profile?.role || '…'}</p>
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>{profile?.email || 'No email set'}</p>
                </div>
                <div className="text-right space-y-1">
                  <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                    Last login: {profile?.last_login ? new Date(profile.last_login).toLocaleDateString() : 'Never'}
                  </p>
                  <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                    Since: {profile?.created_at ? new Date(profile.created_at).toLocaleDateString() : '—'}
                  </p>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${profile?.totp_enabled ? 's-online' : 's-offline'}`}>
                    {profile?.totp_enabled ? '2FA On' : '2FA Off'}
                  </span>
                </div>
              </div>
            </div>

            <div className="g-card p-5 space-y-3">
              <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Update Email</p>
              <div className="flex gap-2">
                <input type="email" value={profileEmail}
                  onChange={e => setProfileEmail(e.target.value)}
                  placeholder="your@email.com" className="g-input flex-1 text-sm" />
                <button onClick={async () => {
                  try {
                    await authAPI.updateProfile({ email: profileEmail });
                    await loadProfile();
                    notify('Email updated');
                  } catch { notify('Failed to update email'); }
                }} className="g-btn g-btn-primary text-xs">Save</button>
              </div>
            </div>

            <div className="g-card p-5 space-y-3">
              <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Change Password</p>
              {pwMsg && (
                <div className="text-xs px-3 py-2 rounded-lg"
                  style={{
                    background: pwMsg.ok ? 'rgba(52,211,153,0.1)' : 'var(--red-bg)',
                    color: pwMsg.ok ? 'var(--green)' : 'var(--red)',
                    border: `1px solid ${pwMsg.ok ? 'var(--green)' : 'var(--red)'}`,
                  }}>
                  {pwMsg.text}
                </div>
              )}
              <input type="password" placeholder="Current password"
                value={changePw.current} onChange={e => setChangePw(f => ({ ...f, current: e.target.value }))}
                className="g-input w-full text-sm" />
              <input type="password" placeholder="New password (min 8 chars)"
                value={changePw.next} onChange={e => setChangePw(f => ({ ...f, next: e.target.value }))}
                className="g-input w-full text-sm" />
              <input type="password" placeholder="Confirm new password"
                value={changePw.confirm} onChange={e => setChangePw(f => ({ ...f, confirm: e.target.value }))}
                className="g-input w-full text-sm" />
              {changePw.next && changePw.confirm && changePw.next !== changePw.confirm && (
                <p className="text-[10px]" style={{ color: 'var(--red)' }}>Passwords do not match</p>
              )}
              <button
                disabled={pwLoading || !changePw.current || !changePw.next || changePw.next !== changePw.confirm}
                onClick={async () => {
                  setPwLoading(true); setPwMsg(null);
                  try {
                    await authAPI.changePassword({
                      current_password: changePw.current,
                      new_password: changePw.next,
                    });
                    setPwMsg({ ok: true, text: 'Password changed successfully' });
                    setChangePw({ current: '', next: '', confirm: '' });
                  } catch (e: any) {
                    setPwMsg({ ok: false, text: e?.response?.data?.error || 'Failed to change password' });
                  } finally { setPwLoading(false); }
                }}
                className="g-btn g-btn-primary w-full justify-center text-xs">
                {pwLoading ? 'Changing…' : 'Change Password'}
              </button>
            </div>
          </div>
        )}

        {/* ══════════ EMAIL ALERTS ══════════ */}
        {tab === 'email' && (
          <div className="space-y-4 max-w-2xl">
            <div className="g-card">
              <div className="px-5 pt-4 pb-3 flex items-center gap-2"
                style={{ borderBottom: '1px solid var(--border)' }}>
                <Mail className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Email Alert Rules</p>
              </div>

              <div className="mx-5 mt-4 p-3 rounded-xl text-xs"
                style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                <p className="font-semibold mb-1" style={{ color: 'var(--text-1)' }}>SMTP Configuration (backend .env)</p>
                <pre className="font-mono text-[10px]" style={{ color: 'var(--text-3)' }}>{
`SMTP_HOST=smtp.gmail.com   SMTP_PORT=587
SMTP_USER=your@email.com   SMTP_PASS=app_password`
                }</pre>
              </div>

              <div className="p-5 space-y-3">
                <div className="grid grid-cols-3 gap-3">
                  <div>
                    <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Rule name</label>
                    <input value={newRule.name} onChange={e => setNewRule(f => ({ ...f, name: e.target.value }))}
                      placeholder="On-call alerts" className="g-input w-full text-xs" />
                  </div>
                  <div>
                    <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Severity</label>
                    <select value={newRule.severity} onChange={e => setNewRule(f => ({ ...f, severity: e.target.value }))}
                      className="g-select w-full text-xs">
                      <option value="critical">Critical only</option>
                      <option value="high">High &amp; Critical</option>
                      <option value="any">All severities</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Recipient email</label>
                    <input value={newRule.recipient} onChange={e => setNewRule(f => ({ ...f, recipient: e.target.value }))}
                      placeholder="oncall@company.com" type="email" className="g-input w-full text-xs" />
                  </div>
                </div>
                <button onClick={async () => {
                  if (!newRule.recipient) return;
                  try {
                    await notificationsAPI.createEmailRule(newRule);
                    await loadEmailRules();
                    setNewRule({ name: '', severity: 'critical', recipient: '' });
                    notify('Email rule created');
                  } catch { notify('Failed to create rule'); }
                }} className="g-btn g-btn-primary text-xs">
                  <Plus className="h-3.5 w-3.5" /> Add Rule
                </button>
              </div>

              <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                {emailLoading ? (
                  <p className="px-5 py-4 text-xs animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</p>
                ) : emailRules.length === 0 ? (
                  <p className="px-5 py-4 text-xs" style={{ color: 'var(--text-3)' }}>
                    No email rules yet. Add one above to receive alert emails.
                  </p>
                ) : emailRules.map((r: any) => (
                  <div key={r.id} className="flex items-center gap-3 px-5 py-3">
                    <Mail className="h-3.5 w-3.5 shrink-0"
                      style={{ color: r.enabled ? 'var(--green)' : 'var(--text-3)' }} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{r.name || r.recipient}</p>
                      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{r.recipient} · {r.severity}</p>
                    </div>
                    <button onClick={async () => {
                      await notificationsAPI.toggleEmailRule(r.id, !r.enabled);
                      await loadEmailRules();
                    }} style={{ color: r.enabled ? 'var(--green)' : 'var(--text-3)' }}>
                      {r.enabled ? <ToggleRight className="h-5 w-5" /> : <ToggleLeft className="h-5 w-5" />}
                    </button>
                    <button onClick={async () => {
                      await notificationsAPI.deleteEmailRule(r.id);
                      await loadEmailRules();
                    }} style={{ color: 'var(--text-3)' }}>
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ══════════ 2FA SECURITY ══════════ */}
        {tab === '2fa' && (
          <div className="space-y-4 max-w-md">
            <div className="g-card p-5 space-y-4">
              <div className="flex items-center gap-2 mb-1">
                <Lock className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Two-Factor Authentication</p>
                <span className={`ml-auto text-[10px] px-2 py-0.5 rounded-full font-medium ${twoFAEnabled ? 's-online' : 's-offline'}`}>
                  {twoFAEnabled ? 'Enabled' : 'Disabled'}
                </span>
              </div>

              {!twoFAEnabled && !totpQR && (
                <div className="space-y-3">
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                    Add an extra layer of security. After enabling, every login requires a code from your authenticator app.
                  </p>
                  <button onClick={async () => {
                    setTfaLoading(true);
                    try {
                      const r = await authAPI.setup2FA();
                      setTotpSecret(r.data.secret);
                      setTotpQR(r.data.qr_url);
                    } catch { notify('Failed to setup 2FA'); }
                    finally { setTfaLoading(false); }
                  }} disabled={tfaLoading}
                    className="g-btn g-btn-primary w-full justify-center">
                    <Smartphone className="h-4 w-4" />
                    {tfaLoading ? 'Setting up…' : 'Set Up 2FA'}
                  </button>
                </div>
              )}

              {totpQR && !twoFAEnabled && (
                <div className="space-y-4">
                  <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>
                    1. Scan this QR code with your authenticator app
                  </p>
                  <div className="rounded-xl p-4 text-center space-y-3"
                    style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <img
                      src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(totpQR)}`}
                      alt="TOTP QR Code" width={200} height={200}
                      className="mx-auto rounded-lg"
                    />
                    <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                      Google Authenticator · Authy · 1Password · any TOTP app
                    </p>
                    <div className="rounded-lg p-2" style={{ background: 'var(--bg-0)' }}>
                      <p className="text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Manual entry:</p>
                      <div className="flex items-center gap-2 justify-center">
                        <code className="text-xs font-mono" style={{ color: 'var(--text-1)' }}>
                          {totpSecret.match(/.{1,4}/g)?.join(' ') || totpSecret}
                        </code>
                        <button onClick={() => { navigator.clipboard.writeText(totpSecret); notify('Copied!'); }}
                          style={{ color: 'var(--accent)' }}>
                          <Copy className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </div>
                  </div>

                  <div>
                    <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-1)' }}>
                      2. Enter the 6-digit code to verify
                    </p>
                    <div className="flex gap-2">
                      <input value={totpCode} onChange={e => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                        placeholder="000000" maxLength={6}
                        className="g-input flex-1 mono text-center text-lg tracking-widest font-bold" />
                      <button onClick={async () => {
                        try {
                          await authAPI.verify2FA(totpCode);
                          setTwoFAEnabled(true);
                          setTotpQR(''); setTotpCode('');
                          notify('2FA enabled successfully!');
                        } catch { notify('Invalid code — try again'); setTotpCode(''); }
                      }} disabled={totpCode.length !== 6}
                        className="g-btn g-btn-primary">Verify</button>
                    </div>
                  </div>
                </div>
              )}

              {twoFAEnabled && (
                <div className="space-y-3">
                  <div className="rounded-xl p-3 flex items-center gap-3"
                    style={{ background: 'rgba(52,211,153,0.08)', border: '1px solid var(--green)' }}>
                    <CheckCircle className="h-5 w-5 shrink-0" style={{ color: 'var(--green)' }} />
                    <div>
                      <p className="text-xs font-semibold" style={{ color: 'var(--green)' }}>2FA is active</p>
                      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                        Every login requires your authenticator code.
                      </p>
                    </div>
                  </div>
                  <div>
                    <p className="text-xs mb-2" style={{ color: 'var(--text-3)' }}>
                      To disable, enter your current authenticator code:
                    </p>
                    <div className="flex gap-2">
                      <input value={totpCode} onChange={e => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                        placeholder="000000" maxLength={6}
                        className="g-input flex-1 mono text-center text-lg tracking-widest font-bold" />
                      <button onClick={async () => {
                        try {
                          await authAPI.disable2FA(totpCode);
                          setTwoFAEnabled(false); setTotpCode('');
                          notify('2FA disabled');
                        } catch { notify('Invalid code'); setTotpCode(''); }
                      }} disabled={totpCode.length !== 6}
                        className="g-btn g-btn-ghost text-xs" style={{ color: 'var(--red)' }}>
                        Disable 2FA
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ══════════ SERVER INFO ══════════ */}
        {tab === 'server' && (
          <div className="g-card p-5 max-w-md space-y-3">
            {[
              { label: 'Platform',   value: 'XCloak Security Suite' },
              { label: 'Backend',    value: 'Go / Gin / PostgreSQL' },
              { label: 'Frontend',   value: 'Next.js 14 / TypeScript' },
              { label: 'Agent',      value: 'Go (Linux / macOS)' },
              { label: 'DB Pool',    value: '25 max / 5 idle' },
              { label: 'Rate Limit', value: '120 req/min (API) · 10/min (Auth)' },
              { label: 'Kafka',      value: '6 topics' },
              { label: 'Auth',       value: 'JWT HS256 · 8h expiry · TOTP 2FA' },
            ].map(({ label, value }) => (
              <div key={label} className="flex justify-between py-2" style={{ borderBottom: '1px solid var(--border)' }}>
                <span className="text-xs" style={{ color: 'var(--text-3)' }}>{label}</span>
                <span className="text-xs mono" style={{ color: 'var(--text-1)' }}>{value}</span>
              </div>
            ))}
          </div>
        )}

        {/* ══════════ AUDIT LOG ══════════ */}
        {tab === 'audit' && (
          <div className="space-y-3">
            <div className="g-card p-4">
              <p className="text-xs font-semibold mb-1" style={{ color: 'var(--text-1)' }}>Immutable Export (MinIO, GOVERNANCE retention)</p>
              {!exportStatus ? (
                <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>Export status unavailable.</p>
              ) : !exportStatus.last_exported_at ? (
                <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>No batches exported yet — runs every 5 minutes.</p>
              ) : (
                <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
                  Last batch: log #{exportStatus.last_exported_id} at {timeAgo(exportStatus.last_exported_at)}
                  {exportStatus.last_object_key && <> · <span className="mono">{exportStatus.last_object_key}</span></>}
                </p>
              )}
            </div>

            <div className="flex items-center gap-3">
              <div className="relative flex-1 max-w-xs">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                <input value={auditSearch}
                  onChange={e => setAuditSearch(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') { setAuditP(1); loadAudit(1, auditSearch); } }}
                  placeholder="Filter by action… (press Enter)" className="g-input pl-9" />
              </div>
              <button onClick={() => { setAuditP(1); loadAudit(1, auditSearch); }}
                className="g-btn g-btn-ghost text-xs">Search</button>
            </div>

            <div className="g-table">
              <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '60px 150px 100px 1fr 120px' }}>
                <span>ID</span><span>Action</span><span>User</span><span>Details</span><span>Time</span>
              </div>
              {auditLoading ? (
                <div className="py-12 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
              ) : !auditPage || !auditPage.logs || auditPage.logs.length === 0 ? (
                <div className="py-12 text-center text-sm" style={{ color: 'var(--text-3)' }}>No audit logs yet.</div>
              ) : auditPage.logs.map((log: any) => (
                <div key={log.id} className="g-tr grid gap-3 items-center px-4"
                  style={{ gridTemplateColumns: '60px 150px 100px 1fr 120px' }}>
                  <span className="mono text-[11px]" style={{ color: 'var(--text-3)' }}>#{log.id}</span>
                  <span className="mono text-xs" style={{ color: 'var(--accent)' }}>{log.action}</span>
                  <span className="text-xs truncate" style={{ color: 'var(--text-2)' }}>{log.performed_by || log.username || '—'}</span>
                  <span className="text-xs truncate" style={{ color: 'var(--text-2)' }}>{log.details}</span>
                  <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{timeAgo(log.created_at)}</span>
                </div>
              ))}
            </div>

            {auditPage && auditPage.pages > 1 && (
              <Pagination
                page={auditPage.page}
                totalPages={auditPage.pages}
                total={auditPage.total}
                perPage={auditPage.per_page}
                onPage={p => { setAuditP(p); loadAudit(p, auditSearch); }}
              />
            )}
          </div>
        )}

        {/* ── Sessions tab ─────────────────────────────────────── */}
        {tab === 'sessions' && (
          <div className="space-y-4">
            <div className="g-card overflow-hidden">
              <div className="px-4 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>My Active Sessions</p>
              </div>
              {sessions.length === 0 ? (
                <p className="p-6 text-xs text-center" style={{ color: 'var(--text-3)' }}>No active sessions tracked yet. Sessions are recorded on new logins.</p>
              ) : (
                <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                  {sessions.map(s => (
                    <div key={s.id} className="flex items-center gap-3 px-4 py-3">
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{s.ip_address || 'Unknown IP'}</p>
                        <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>{s.user_agent || 'Unknown client'}</p>
                        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                          Last active {new Date(s.last_active_at).toLocaleString()} · Created {new Date(s.created_at).toLocaleString()}
                        </p>
                      </div>
                      <button onClick={() => revokeSession(s.id)}
                        className="text-[11px] px-2 py-1 rounded-lg"
                        style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' }}>
                        Revoke
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div className="g-card overflow-hidden">
              <div className="px-4 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>All Tenant Sessions</p>
              </div>
              {allSessions.length === 0 ? (
                <p className="p-6 text-xs text-center" style={{ color: 'var(--text-3)' }}>No sessions found.</p>
              ) : (
                <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                  {allSessions.map(s => (
                    <div key={s.id} className="flex items-center gap-3 px-4 py-3">
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{s.username} <span className="font-normal text-[10px]">{s.ip_address}</span></p>
                        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                          Active {new Date(s.last_active_at).toLocaleString()}
                        </p>
                      </div>
                      <button onClick={() => revokeSession(s.id)}
                        className="text-[11px] px-2 py-1 rounded-lg"
                        style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' }}>
                        Revoke
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── Security Policy tab ─────────────────────────────────── */}
        {tab === 'security' && (
          <div className="max-w-lg space-y-4">
            <div className="g-card p-5 space-y-5">
              <div className="flex items-center gap-2 mb-1">
                <Shield className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Tenant Security Policy</p>
              </div>
              <div>
                <label className="block text-xs font-semibold mb-1" style={{ color: 'var(--text-2)' }}>
                  Session Timeout (minutes)
                </label>
                <input type="number" min={5} max={10080}
                  value={policyForm.session_timeout_mins ?? 480}
                  onChange={e => setPolicyForm(f => ({ ...f, session_timeout_mins: +e.target.value }))}
                  className="g-input w-full" />
                <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                  Sessions older than this with no activity are flagged expired. Default: 480 (8h).
                </p>
              </div>
              <div>
                <label className="block text-xs font-semibold mb-1" style={{ color: 'var(--text-2)' }}>
                  Max Concurrent Sessions per User
                </label>
                <input type="number" min={1} max={100}
                  value={policyForm.max_concurrent_sessions ?? 10}
                  onChange={e => setPolicyForm(f => ({ ...f, max_concurrent_sessions: +e.target.value }))}
                  className="g-input w-full" />
                <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                  Oldest sessions are revoked when this limit is exceeded. Default: 10.
                </p>
              </div>
              <div>
                <label className="flex items-center gap-3 cursor-pointer">
                  <input type="checkbox"
                    checked={policyForm.mfa_required ?? false}
                    onChange={e => setPolicyForm(f => ({ ...f, mfa_required: e.target.checked }))}
                    className="w-4 h-4 rounded" />
                  <div>
                    <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Require MFA for all users</p>
                    <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                      Users without TOTP enabled will be blocked from login until they set it up.
                    </p>
                  </div>
                </label>
              </div>
              <button onClick={saveSecurityPolicy} disabled={savingPolicy}
                className="g-btn g-btn-primary w-full justify-center">
                {savingPolicy ? 'Saving…' : 'Save Policy'}
              </button>
              {secPolicy && (
                <p className="text-[10px] text-center" style={{ color: 'var(--text-3)' }}>
                  Last updated {new Date(secPolicy.updated_at).toLocaleString()}
                </p>
              )}
            </div>
          </div>
        )}

      </div>

      {showInvite && (
        <div className="g-modal-backdrop" onClick={() => setShowInvite(false)}>
          <div className="g-modal" style={{ maxWidth: 420 }} onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Invite User</h2>
              <button onClick={() => setShowInvite(false)} style={{ color: 'var(--text-2)' }}><XCircle className="h-4 w-4" /></button>
            </div>
            <div className="p-5 space-y-3">
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Username</label>
                <input value={inviteForm.username} onChange={e => setInviteForm(f => ({ ...f, username: e.target.value }))}
                  placeholder="jsmith" className="g-input" />
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Email</label>
                <input value={inviteForm.email} onChange={e => setInviteForm(f => ({ ...f, email: e.target.value }))}
                  placeholder="jsmith@company.com" className="g-input" />
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Role</label>
                <select value={inviteForm.role} onChange={e => setInviteForm(f => ({ ...f, role: e.target.value }))}
                  className="g-select w-full">
                  {[...ROLES, ...customRoles.map(cr => cr.name)].map(r => <option key={r} value={r}>{r}</option>)}
                </select>
              </div>
              <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
                They&apos;ll get an email with a link to set their password.
              </p>
            </div>
            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => setShowInvite(false)} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={inviteUser} disabled={inviting} className="g-btn g-btn-primary flex-1 justify-center">
                {inviting ? 'Sending…' : 'Send Invite'}
              </button>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
