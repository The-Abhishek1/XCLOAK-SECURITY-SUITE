'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { Pagination } from '@/components/ui/Pagination';
import { usersAPI, auditAPI } from '@/lib/api';
import api from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import {
  Users, UserCog, Shield, Server, ScrollText,
  Trash2, ToggleLeft, ToggleRight, ChevronDown, Search,
  Webhook, CheckCircle, XCircle, Send, Plus, Key, Copy, Eye, EyeOff,
  Mail, Lock, Smartphone, QrCode,
} from 'lucide-react';

const TABS = [
  { id: 'users',        label: 'User Management', icon: Users      },
  { id: 'integrations', label: 'Integrations',    icon: Webhook    },
  { id: 'profile',      label: 'My Profile',       icon: UserCog   },
  { id: 'email',        label: 'Email Alerts',     icon: Mail      },
  { id: '2fa',          label: '2FA Security',     icon: Lock      },
  { id: 'server',       label: 'Server Info',      icon: Server    },
  { id: 'audit',        label: 'Audit Log',        icon: ScrollText },
] as const;
type Tab = typeof TABS[number]['id'];

const ROLES = ['admin', 'analyst', 'viewer'];

interface UserRow {
  id: number; username: string; email: string;
  role: string; is_active: boolean;
  last_login: string | null; created_at: string | null;
}
interface AuditPage {
  data: any[]; total: number; page: number;
  per_page: number; total_pages: number;
}

export default function SettingsPage() {
  const [tab, setTab]     = useState<Tab>('users');
  const [toast, setToast] = useState<string | null>(null);
  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  // ── Users ────────────────────────────────────────────────────
  const [users, setUsers]             = useState<UserRow[]>([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [roleEditing, setRoleEditing] = useState<number | null>(null);
  const [userSearch, setUserSearch]   = useState('');

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

  const currentUsername = typeof window !== 'undefined'
    ? localStorage.getItem('username') || 'admin' : 'admin';

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
        api.get('/integrations').catch(() => ({ data: [] })),
        api.get('/integrations/deliveries').catch(() => ({ data: [] })),
        api.get('/integrations/install-tokens').catch(() => ({ data: [] })),
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

  const loadProfile = useCallback(async () => {
    try {
      const r = await api.get('/auth/profile');
      setProfile(r.data);
      setProfileEmail(r.data?.email || '');
      setTwoFAEnabled(r.data?.totp_enabled || false);
    } catch {}
  }, []);

  const loadEmailRules = useCallback(async () => {
    setEmailLoading(true);
    try {
      const r = await api.get('/notifications/email');
      setEmailRules(r.data || []);
    } catch { setEmailRules([]); }
    finally { setEmailLoading(false); }
  }, []);

  const load2FAStatus = useCallback(async () => {
    try {
      const r = await api.get('/auth/profile');
      setTwoFAEnabled(r.data?.totp_enabled || false);
    } catch {}
  }, []);

  const loadAudit = useCallback(async (p = 1, search = '') => {
    setAuditLoading(true);
    try { const r = await auditAPI.getPaginated(p, 50, search); setAuditPage(r.data); }
    catch { setAuditPage(null); }
    finally { setAuditLoading(false); }
  }, []);

  // Load on tab switch
  useEffect(() => {
    if (tab === 'users')        loadUsers();
    if (tab === 'integrations') loadIntegrations();
    if (tab === 'profile')      loadProfile();
    if (tab === 'email')        loadEmailRules();
    if (tab === '2fa')          load2FAStatus();
    if (tab === 'audit')        loadAudit(1, '');
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
            <div className="relative max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
              <input value={userSearch} onChange={e => setUserSearch(e.target.value)}
                placeholder="Search users…" className="g-input pl-9" />
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
                      {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
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
                      try { await api.put(`/integrations/${int.name}`, form); notify(`${int.name} saved`); }
                      catch { notify('Save failed'); }
                      finally { setIntSaving(null); }
                    };
                    const test = async () => {
                      try { await api.post(`/integrations/${int.name}/test`, {}); notify(`Test sent via ${int.name}`); }
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
                              {int.name === 'slack' ? 'Slack webhook notifications'
                                : int.name === 'webhook' ? 'Generic HTTP webhook'
                                : int.name === 'email' ? 'SMTP email alerts'
                                : 'PagerDuty incident routing'}
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
                                  placeholder="PagerDuty key" className="g-input w-full text-xs mono" />
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
                        const r = await api.post('/integrations/install-tokens', { label: tokenLabel });
                        setGenToken(r.data.token); setTokenLabel('');
                        const r2 = await api.get('/integrations/install-tokens');
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
                    await api.patch('/auth/profile', { email: profileEmail });
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
                    await api.post('/auth/change-password', {
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
                    await api.post('/notifications/email', newRule);
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
                      await api.patch(`/notifications/email/${r.id}/toggle`, { enabled: !r.enabled });
                      await loadEmailRules();
                    }} style={{ color: r.enabled ? 'var(--green)' : 'var(--text-3)' }}>
                      {r.enabled ? <ToggleRight className="h-5 w-5" /> : <ToggleLeft className="h-5 w-5" />}
                    </button>
                    <button onClick={async () => {
                      await api.delete(`/notifications/email/${r.id}`);
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
                      const r = await api.post('/auth/2fa/setup');
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
                          await api.post('/auth/2fa/verify', { code: totpCode });
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
                          await api.delete('/auth/2fa', { data: { code: totpCode } });
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
              ) : !auditPage || !auditPage.data || auditPage.data.length === 0 ? (
                <div className="py-12 text-center text-sm" style={{ color: 'var(--text-3)' }}>No audit logs yet.</div>
              ) : auditPage.data.map((log: any) => (
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

            {auditPage && auditPage.total_pages > 1 && (
              <Pagination
                page={auditPage.page}
                totalPages={auditPage.total_pages}
                total={auditPage.total}
                perPage={auditPage.per_page}
                onPage={p => { setAuditP(p); loadAudit(p, auditSearch); }}
              />
            )}
          </div>
        )}
      </div>
    </RootLayout>
  );
}
