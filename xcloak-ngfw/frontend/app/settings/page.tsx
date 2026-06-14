'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { Pagination } from '@/components/ui/Pagination';
import { usersAPI, auditAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import {
  Users, UserCog, Shield, Server, ScrollText,
  Trash2, ToggleLeft, ToggleRight, ChevronDown, Search, Lock,
} from 'lucide-react';

// Decode JWT payload to get role without a library.
function getRoleFromToken(): string {
  try {
    const token = localStorage.getItem('token') || '';
    if (!token) return 'viewer';
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.role || 'viewer';
  } catch {
    return 'viewer';
  }
}

const ALL_TABS = [
  { id: 'users',   label: 'User Management', icon: Users,      adminOnly: true },
  { id: 'profile', label: 'My Profile',       icon: UserCog,   adminOnly: false },
  { id: 'server',  label: 'Server Info',      icon: Server,    adminOnly: false },
  { id: 'audit',   label: 'Audit Log',        icon: ScrollText, adminOnly: false },
] as const;
type Tab = typeof ALL_TABS[number]['id'];

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
  const [userRole, setUserRole] = useState('viewer');
  const [tab, setTab]       = useState<Tab>('profile');
  const [toast, setToast]   = useState<string | null>(null);

  // User management
  const [users, setUsers]   = useState<UserRow[]>([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [accessDenied, setAccessDenied] = useState(false);
  const [roleEditing, setRoleEditing] = useState<number | null>(null);
  const [userSearch, setUserSearch] = useState('');

  // Audit log
  const [auditPage, setAuditPage]   = useState<AuditPage | null>(null);
  const [auditP, setAuditP]         = useState(1);
  const [auditSearch, setAuditSearch] = useState('');
  const [auditLoading, setAuditLoading] = useState(false);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  // Detect role on mount and set default tab
  useEffect(() => {
    const role = getRoleFromToken();
    setUserRole(role);
    // Non-admins can't see User Management — start on Profile
    setTab(role === 'admin' ? 'users' : 'profile');
  }, []);

  const TABS = ALL_TABS.filter(t => !t.adminOnly || userRole === 'admin');

  const loadUsers = useCallback(async () => {
    setUsersLoading(true);
    setAccessDenied(false);
    try {
      const r = await usersAPI.getAll();
      setUsers(r.data || []);
    } catch (err: any) {
      if (err?.response?.status === 403) {
        setAccessDenied(true);
      }
    } finally {
      setUsersLoading(false);
    }
  }, []);

  const loadAudit = useCallback(async (p = 1, search = '') => {
    setAuditLoading(true);
    try { const r = await auditAPI.getPaginated(p, 50, search); setAuditPage(r.data); }
    finally { setAuditLoading(false); }
  }, []);

  useEffect(() => {
    if (tab === 'users') loadUsers();
    if (tab === 'audit') loadAudit(auditP, auditSearch);
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
            {accessDenied ? (
              <div className="g-card py-16 text-center">
                <Lock className="mx-auto h-10 w-10 mb-3" style={{ color: 'var(--text-3)' }} />
                <p className="text-sm font-medium" style={{ color: 'var(--text-1)' }}>Access Denied</p>
                <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>Only administrators can manage users.</p>
              </div>
            ) : (
            <>
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
