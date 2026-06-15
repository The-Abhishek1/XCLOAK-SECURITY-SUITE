'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { Pagination } from '@/components/ui/Pagination';
import { usersAPI, auditAPI } from '@/lib/api';
import api from '@/lib/api';
import { timeAgo, formatDate } from '@/lib/utils';
import {
  Users, UserCog, Shield, Server, ScrollText,
  Trash2, ToggleLeft, ToggleRight, ChevronDown, Search,
  Webhook, CheckCircle, XCircle, Send, Plus, Key, Copy, Eye, EyeOff,
} from 'lucide-react';

const TABS = [
  { id: 'users',        label: 'User Management', icon: Users },
  { id: 'integrations', label: 'Integrations',    icon: Webhook },
  { id: 'profile',      label: 'My Profile',       icon: UserCog },
  { id: 'server',       label: 'Server Info',      icon: Server },
  { id: 'audit',        label: 'Audit Log',        icon: ScrollText },
] as const;
type Tab = typeof TABS[number]['id'];

const ROLES = ['admin', 'analyst', 'viewer'];

interface UserRow {
  id: number;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  last_login: string | null;
  created_at: string | null;
}

interface AuditPage {
  data: any[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

export default function SettingsPage() {
  const [tab, setTab]       = useState<Tab>('users');
  const [toast, setToast]   = useState<string | null>(null);

  // Integrations
  const [integrations, setIntegrations] = useState<any[]>([]);
  const [intLoading, setIntLoading]     = useState(false);
  const [intSaving, setIntSaving]       = useState<string | null>(null);
  const [intForms, setIntForms]         = useState<Record<string, any>>({});
  const [deliveries, setDeliveries]     = useState<any[]>([]);
  const [installTokens, setInstallTokens] = useState<any[]>([]);
  const [genToken, setGenToken]         = useState<string | null>(null);
  const [tokenLabel, setTokenLabel]     = useState('');
  const [showSecrets, setShowSecrets]   = useState<Record<string, boolean>>({});

  // User management
  const [users, setUsers]   = useState<UserRow[]>([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [roleEditing, setRoleEditing] = useState<number | null>(null);
  const [userSearch, setUserSearch] = useState('');

  // Audit log
  const [auditPage, setAuditPage]   = useState<AuditPage | null>(null);
  const [auditP, setAuditP]         = useState(1);
  const [auditSearch, setAuditSearch] = useState('');
  const [auditLoading, setAuditLoading] = useState(false);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const loadUsers = useCallback(async () => {
    setUsersLoading(true);
    try { const r = await usersAPI.getAll(); setUsers(r.data || []); }
    finally { setUsersLoading(false); }
  }, []);

  const loadAudit = useCallback(async (p = 1, search = '') => {
    setAuditLoading(true);
    try { const r = await auditAPI.getPaginated(p, 50, search); setAuditPage(r.data); }
    finally { setAuditLoading(false); }
  }, []);

  useEffect(() => {
    if (tab === 'users') loadUsers();
    if (tab === 'audit') loadAudit(auditP, auditSearch);
    if (tab === 'integrations') {
      setIntLoading(true);
      Promise.allSettled([
        api.get('/integrations'),
        api.get('/integrations/deliveries'),
        api.get('/integrations/install-tokens'),
      ]).then(([intRes, delRes, tokRes]) => {
        if (intRes.status === 'fulfilled') {
          const list = intRes.value.data || [];
          setIntegrations(list);
          const forms: Record<string, any> = {};
          list.forEach((i: any) => { forms[i.name] = { enabled: i.enabled, config: { ...i.config } }; });
          setIntForms(forms);
        }
        if (delRes.status === 'fulfilled') setDeliveries(delRes.value.data || []);
        if (tokRes.status === 'fulfilled') setInstallTokens(tokRes.value.data || []);
      }).finally(() => setIntLoading(false));
    }
  }, [tab]);

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
    try { await usersAPI.delete(id); setUsers(u => u.filter(x => x.id !== id)); notify('User deleted'); }
    catch { notify('Failed to delete user'); }
  };

  const filteredUsers = users.filter(u =>
    !userSearch || u.username.toLowerCase().includes(userSearch.toLowerCase())
      || u.email.toLowerCase().includes(userSearch.toLowerCase())
  );

  // Get current user info from localStorage
  const currentUsername = typeof window !== 'undefined' ? localStorage.getItem('username') || 'admin' : 'admin';

  return (
    <RootLayout title="Settings" subtitle="Platform configuration">
      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)', minWidth: 220 }}>{toast}</div>}

      <div className="space-y-4">
        {/* Tab bar */}
        <div className="flex gap-1 flex-wrap p-1 rounded-xl w-fit"
          style={{ background: 'var(--glass-bg)', backdropFilter: 'var(--blur-sm)', border: '1px solid var(--border)' }}>
          {TABS.map(t => {
            const Icon = t.icon;
            return (
              <button key={t.id} onClick={() => setTab(t.id)}
                className="flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-medium transition-all"
                style={{
                  background: tab === t.id ? 'var(--accent-glow)' : 'transparent',
                  color: tab === t.id ? 'var(--accent)' : 'var(--text-2)',
                  border: tab === t.id ? '1px solid var(--accent-border)' : '1px solid transparent',
                }}>
                <Icon className="h-3.5 w-3.5" />{t.label}
              </button>
            );
          })}
        </div>

        {/* ── USER MANAGEMENT ── */}
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
                  <span className="text-xs truncate" style={{ color: 'var(--text-2)' }}>{u.email}</span>

                  {/* Role selector */}
                  {roleEditing === u.id ? (
                    <select defaultValue={u.role}
                      onChange={e => updateRole(u.id, e.target.value)}
                      onBlur={() => setRoleEditing(null)}
                      autoFocus className="g-select text-xs" style={{ height: 28, padding: '0 6px' }}>
                      {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                    </select>
                  ) : (
                    <button onClick={() => setRoleEditing(u.id)}
                      className="flex items-center gap-1 text-xs rounded-lg px-2 py-1 w-fit transition-colors"
                      style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                      <Shield className="h-3 w-3" style={{ color: u.role === 'admin' ? 'var(--accent)' : 'var(--text-3)' }} />
                      {u.role}
                      <ChevronDown className="h-3 w-3" style={{ color: 'var(--text-3)' }} />
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

        {/* ── INTEGRATIONS ── */}
        {tab === 'integrations' && (
          <div className="space-y-5">
            {intLoading ? (
              <div className="py-12 text-center animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
            ) : (
              <>
                {/* Integration cards */}
                <div className="grid gap-4 sm:grid-cols-2">
                  {integrations.map(int => {
                    const form = intForms[int.name] || { enabled: false, config: {} };
                    const isSlack   = int.name === 'slack';
                    const isWebhook = int.name === 'webhook';

                    const save = async () => {
                      setIntSaving(int.name);
                      try {
                        await api.put(`/integrations/${int.name}`, form);
                        notify(`${int.name} saved`);
                      } catch { notify('Save failed'); }
                      finally { setIntSaving(null); }
                    };

                    const test = async () => {
                      try {
                        await api.post(`/integrations/${int.name}/test`, {});
                        notify(`Test event sent via ${int.name}`);
                      } catch { notify('Test failed'); }
                    };

                    const setForm = (patch: any) => setIntForms(f => ({
                      ...f,
                      [int.name]: { ...form, ...patch },
                    }));

                    const setConfig = (patch: any) => setForm({
                      config: { ...form.config, ...patch },
                    });

                    return (
                      <div key={int.name} className="g-card p-5 space-y-4">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-semibold capitalize" style={{ color: 'var(--text-1)' }}>
                              {int.name}
                            </p>
                            <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                              {isSlack ? 'Slack webhook notifications'
                                : isWebhook ? 'Generic HTTP webhook'
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
                            {/* Slack */}
                            {isSlack && (
                              <>
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Webhook URL</label>
                                  <div className="relative">
                                    <input
                                      type={showSecrets['slack'] ? 'text' : 'password'}
                                      value={form.config.webhook_url || ''}
                                      onChange={e => setConfig({ webhook_url: e.target.value })}
                                      placeholder="https://hooks.slack.com/..."
                                      className="g-input w-full pr-8 text-xs mono" />
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

                            {/* Generic webhook */}
                            {isWebhook && (
                              <>
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Endpoint URL</label>
                                  <input value={form.config.url || ''} onChange={e => setConfig({ url: e.target.value })}
                                    placeholder="https://your-endpoint.com/hooks/xcloak"
                                    className="g-input w-full text-xs mono" />
                                </div>
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Secret (optional)</label>
                                  <div className="relative">
                                    <input
                                      type={showSecrets['webhook'] ? 'text' : 'password'}
                                      value={form.config.secret || ''}
                                      onChange={e => setConfig({ secret: e.target.value })}
                                      placeholder="Signing secret"
                                      className="g-input w-full pr-8 text-xs mono" />
                                    <button className="absolute right-2 top-1/2 -translate-y-1/2"
                                      onClick={() => setShowSecrets(s => ({ ...s, webhook: !s.webhook }))}
                                      style={{ color: 'var(--text-3)' }}>
                                      {showSecrets['webhook'] ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                                    </button>
                                  </div>
                                </div>
                              </>
                            )}

                            {/* PagerDuty */}
                            {int.name === 'pagerduty' && (
                              <div>
                                <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Integration Key</label>
                                <input value={form.config.integration_key || ''}
                                  onChange={e => setConfig({ integration_key: e.target.value })}
                                  placeholder="PagerDuty integration key"
                                  className="g-input w-full text-xs mono" />
                              </div>
                            )}

                            {/* Email */}
                            {int.name === 'email' && (
                              <div className="grid grid-cols-2 gap-2">
                                <div className="col-span-2">
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>SMTP Host</label>
                                  <input value={form.config.smtp_host || ''} onChange={e => setConfig({ smtp_host: e.target.value })}
                                    placeholder="smtp.gmail.com" className="g-input w-full text-xs" />
                                </div>
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Port</label>
                                  <input type="number" value={form.config.smtp_port || 587}
                                    onChange={e => setConfig({ smtp_port: parseInt(e.target.value) })}
                                    className="g-input w-full text-xs" />
                                </div>
                                <div>
                                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>From</label>
                                  <input value={form.config.from || ''} onChange={e => setConfig({ from: e.target.value })}
                                    placeholder="xcloak@company.com" className="g-input w-full text-xs" />
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

                {/* Agent install tokens */}
                <div className="g-card">
                  <div className="flex items-center justify-between px-5 pt-4 pb-3"
                    style={{ borderBottom: '1px solid var(--border)' }}>
                    <div className="flex items-center gap-2">
                      <Key className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                      <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>
                        Agent Install Tokens
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <input value={tokenLabel} onChange={e => setTokenLabel(e.target.value)}
                        placeholder="Label (optional)" className="g-input text-xs" style={{ width: 150 }} />
                      <button
                        onClick={async () => {
                          const r = await api.post('/integrations/install-tokens', { label: tokenLabel });
                          setGenToken(r.data.token);
                          setTokenLabel('');
                          const r2 = await api.get('/integrations/install-tokens');
                          setInstallTokens(r2.data || []);
                        }}
                        className="g-btn g-btn-primary text-xs">
                        <Plus className="h-3.5 w-3.5" /> Generate
                      </button>
                    </div>
                  </div>

                  {genToken && (
                    <div className="mx-4 my-3 p-3 rounded-xl"
                      style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
                      <p className="text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>
                        New token (copy now — shown once):
                      </p>
                      <div className="flex items-center gap-2">
                        <code className="flex-1 text-[11px] font-mono break-all" style={{ color: 'var(--accent)' }}>
                          {genToken}
                        </code>
                        <button onClick={() => { navigator.clipboard.writeText(genToken); notify('Copied!'); }}
                          style={{ color: 'var(--accent)' }}>
                          <Copy className="h-4 w-4" />
                        </button>
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

                {/* Delivery log */}
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

        {/* ── MY PROFILE ── */}
        {tab === 'profile' && (
          <div className="g-card p-6 max-w-sm space-y-4">
            <div className="flex items-center gap-4">
              <div className="h-14 w-14 rounded-2xl flex items-center justify-center text-xl font-bold"
                style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '2px solid var(--accent-border)' }}>
                {currentUsername[0].toUpperCase()}
              </div>
              <div>
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{currentUsername}</p>
                <p className="text-xs" style={{ color: 'var(--text-3)' }}>Administrator</p>
              </div>
            </div>
            <p className="text-xs" style={{ color: 'var(--text-2)' }}>
              Password change and email update will be available in the next release.
            </p>
          </div>
        )}

        {/* ── SERVER INFO ── */}
        {tab === 'server' && (
          <div className="g-card p-5 max-w-md space-y-3">
            {[
              { label: 'Platform',   value: 'XCloak Security Suite' },
              { label: 'Phase',      value: 'Phase 3 — Infrastructure' },
              { label: 'Backend',    value: 'Go / Gin / PostgreSQL' },
              { label: 'Frontend',   value: 'Next.js 14 / TypeScript' },
              { label: 'Agent',      value: 'Go 1.25 (Linux)' },
              { label: 'DB Pool',    value: '25 max open / 5 idle conns' },
              { label: 'Rate Limit', value: '120 req/min (API) · 10/min (Auth)' },
            ].map(({ label, value }) => (
              <div key={label} className="flex justify-between py-2" style={{ borderBottom: '1px solid var(--border)' }}>
                <span className="text-xs" style={{ color: 'var(--text-3)' }}>{label}</span>
                <span className="text-xs mono" style={{ color: 'var(--text-1)' }}>{value}</span>
              </div>
            ))}
          </div>
        )}

        {/* ── AUDIT LOG ── */}
        {tab === 'audit' && (
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <div className="relative flex-1 max-w-xs">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                <input value={auditSearch} onChange={e => { setAuditSearch(e.target.value); setAuditP(1); }}
                  placeholder="Filter by action…" className="g-input pl-9" />
              </div>
              <button onClick={() => loadAudit(auditP, auditSearch)} className="g-btn g-btn-ghost text-xs">Search</button>
            </div>

            <div className="g-table">
              <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '80px 150px 1fr 120px' }}>
                <span>ID</span><span>Action</span><span>Details</span><span>Time</span>
              </div>
              {auditLoading ? (
                <div className="py-12 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
              ) : (auditPage?.data || []).map((log: any) => (
                <div key={log.id} className="g-tr grid gap-3 items-center px-4"
                  style={{ gridTemplateColumns: '80px 150px 1fr 120px' }}>
                  <span className="mono text-[11px]" style={{ color: 'var(--text-3)' }}>#{log.id}</span>
                  <span className="mono text-xs" style={{ color: 'var(--accent)' }}>{log.action}</span>
                  <span className="text-xs truncate" style={{ color: 'var(--text-2)' }}>{log.details}</span>
                  <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{timeAgo(log.created_at)}</span>
                </div>
              ))}
            </div>

            {auditPage && (
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
