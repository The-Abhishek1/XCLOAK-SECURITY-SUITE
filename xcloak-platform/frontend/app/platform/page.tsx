'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { platformAPI } from '@/lib/api';
import { useUser } from '@/context/UserContext';
import { AgentRelease, TenantDomain } from '@/types';
import { timeAgo } from '@/lib/utils';
import { Plus, X, ShieldAlert, Building2, ToggleLeft, ToggleRight, Package, Upload, Globe, ChevronRight, ChevronDown, CreditCard, TrendingUp, Users, DollarSign, Activity, Edit2, Key, Copy, RefreshCw, Trash2, Server, Cloud } from 'lucide-react';

interface Tenant {
  id: number;
  name: string;
  slug: string;
  is_active: boolean;
  created_at: string;
  user_count?: number;
}

const PLATFORMS = [
  'linux_amd64', 'linux_arm64',
  'windows_amd64', 'windows_arm64',
  'darwin_amd64', 'darwin_arm64',
];

function DomainsPanel({ tenantID }: { tenantID: number }) {
  const [domains, setDomains]   = useState<TenantDomain[]>([]);
  const [loading, setLoading]   = useState(true);
  const [newDomain, setNewDomain] = useState('');
  const [adding, setAdding]     = useState(false);
  const [deleting, setDeleting] = useState<number | null>(null);
  const [err, setErr]           = useState('');

  useEffect(() => {
    platformAPI.getTenantDomains(tenantID)
      .then(r => setDomains(r.data || []))
      .finally(() => setLoading(false));
  }, [tenantID]);

  const add = async () => {
    if (!newDomain.trim()) return;
    setAdding(true); setErr('');
    try {
      await platformAPI.addTenantDomain(tenantID, newDomain.trim().toLowerCase());
      const r = await platformAPI.getTenantDomains(tenantID);
      setDomains(r.data || []);
      setNewDomain('');
    } catch (e: any) {
      setErr(e?.response?.data?.error || 'Failed to add domain');
    } finally { setAdding(false); }
  };

  const del = async (domainID: number) => {
    setDeleting(domainID);
    try {
      await platformAPI.deleteTenantDomain(tenantID, domainID);
      setDomains(d => d.filter(x => x.id !== domainID));
    } finally { setDeleting(null); }
  };

  if (loading) return <div className="px-4 py-2 text-[11px] animate-pulse" style={{ color: 'var(--text-3)' }}>Loading domains…</div>;

  return (
    <div className="px-4 pb-3 pt-1">
      <p className="text-[10px] font-semibold uppercase mb-2" style={{ color: 'var(--text-3)' }}>
        Email Domains → SSO Auto-Routing
      </p>
      <div className="flex gap-2 mb-2">
        <input value={newDomain} onChange={e => setNewDomain(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && add()}
          placeholder="acme.com" className="g-input text-xs mono flex-1"
          style={{ maxWidth: 200 }} />
        <button onClick={add} disabled={adding || !newDomain.trim()} className="g-btn g-btn-primary text-xs px-3">
          {adding ? '…' : <Plus className="h-3.5 w-3.5" />}
        </button>
      </div>
      {err && <p className="text-[10px] mb-1" style={{ color: 'var(--red)' }}>{err}</p>}
      {domains.length === 0 ? (
        <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
          No domains — users must enter the org slug to use SSO.
        </p>
      ) : (
        <div className="flex flex-wrap gap-2">
          {domains.map(d => (
            <div key={d.id} className="flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-[11px]"
              style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)', color: 'var(--accent)' }}>
              <Globe className="h-3 w-3" />
              <span className="mono">{d.domain}</span>
              <button onClick={() => del(d.id)} disabled={deleting === d.id}
                className="opacity-50 hover:opacity-100 transition-opacity">
                <X className="h-3 w-3" />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

type PTab = 'tenants' | 'deployment' | 'saas';

export default function PlatformPage() {
  const { profile } = useUser();
  const isPlatformAdmin = profile?.is_platform_admin ?? null;
  const [isAuthority, setIsAuthority] = useState<boolean | null>(null);
  const [ptab, setPtab]           = useState<PTab>('tenants');
  const [tenants, setTenants]     = useState<Tenant[]>([]);
  const [releases, setReleases]   = useState<AgentRelease[]>([]);
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [expandedTenant, setExpandedTenant] = useState<number | null>(null);
  const [showNew, setShowNew]     = useState(false);
  const [newTenantInviteLink, setNewTenantInviteLink] = useState<string | null>(null);
  const [newTenantAdminName, setNewTenantAdminName] = useState('');
  const [showRelease, setShowRelease] = useState(false);
  const [form, setForm]           = useState({ name: '', slug: '', admin_username: '', admin_email: '' });
  const [relForm, setRelForm]     = useState({ platform: 'linux_amd64', version: '', sha256: '', download_url: '' });
  const [creating, setCreating]   = useState(false);
  const [publishing, setPublishing] = useState(false);
  const [toast, setToast]         = useState<string | null>(null);
  const [toggling, setToggling]   = useState<number | null>(null);
  const [deletingTenant, setDeletingTenant] = useState<Tenant | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState('');
  const [deleteInProgress, setDeleteInProgress] = useState(false);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 4000); };

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const [tRes, rRes, capRes] = await Promise.allSettled([
        platformAPI.getTenants(),
        platformAPI.getReleases(),
        platformAPI.getCapabilities(),
      ]);
      if (tRes.status === 'fulfilled') setTenants(tRes.value.data || []);
      if (rRes.status === 'fulfilled') setReleases(rRes.value.data || []);
      if (capRes.status === 'fulfilled') setIsAuthority(capRes.value.data?.is_authority ?? false);
      else setIsAuthority(false);
    } finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => {
    if (isPlatformAdmin) load();
  }, [isPlatformAdmin, load]);

  const slugify = (s: string) => s.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');

  const createTenant = async () => {
    if (!form.name || !form.slug || !form.admin_username || !form.admin_email) {
      notify('Name, slug, admin username, and admin email are all required');
      return;
    }
    setCreating(true);
    try {
      const res = await platformAPI.createTenant(form.name, form.slug, form.admin_username, form.admin_email);
      load();
      if (res.data?.invite_link) {
        setNewTenantAdminName(form.admin_username);
        setNewTenantInviteLink(res.data.invite_link);
        setForm({ name: '', slug: '', admin_username: '', admin_email: '' });
      } else {
        notify(`Tenant created — invite sent to ${form.admin_email}`);
        setShowNew(false);
        setForm({ name: '', slug: '', admin_username: '', admin_email: '' });
      }
    } catch (e: any) {
      notify(e?.response?.data?.error || 'Failed to create tenant');
    } finally { setCreating(false); }
  };

  const toggleTenant = async (t: Tenant) => {
    setToggling(t.id);
    try {
      await platformAPI.toggleTenant(t.id, !t.is_active);
      setTenants(ts => ts.map(x => x.id === t.id ? { ...x, is_active: !x.is_active } : x));
      notify(t.is_active ? `${t.name} suspended` : `${t.name} reactivated`);
    } catch (e: any) {
      notify(e?.response?.data?.error || 'Failed to update tenant');
    } finally { setToggling(null); }
  };

  const confirmDeleteTenant = async () => {
    if (!deletingTenant) return;
    setDeleteInProgress(true);
    try {
      await platformAPI.deleteTenant(deletingTenant.id);
      setTenants(ts => ts.filter(x => x.id !== deletingTenant.id));
      notify(`Tenant "${deletingTenant.name}" permanently deleted`);
      setDeletingTenant(null);
      setDeleteConfirm('');
    } catch (e: any) {
      notify(e?.response?.data?.error || 'Failed to delete tenant');
    } finally { setDeleteInProgress(false); }
  };

  const publishRelease = async () => {
    if (!relForm.version || !relForm.sha256 || !relForm.download_url) {
      notify('Version, SHA256, and download URL are required');
      return;
    }
    setPublishing(true);
    try {
      await platformAPI.publishRelease(relForm);
      notify(`Published ${relForm.platform} v${relForm.version}`);
      setShowRelease(false);
      setRelForm({ platform: 'linux_amd64', version: '', sha256: '', download_url: '' });
      load();
    } catch (e: any) {
      notify(e?.response?.data?.error || 'Failed to publish release');
    } finally { setPublishing(false); }
  };

  if (isPlatformAdmin === null) {
    return (
      <RootLayout title="Platform" subtitle="Tenant provisioning">
        <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
      </RootLayout>
    );
  }

  if (!isPlatformAdmin) {
    return (
      <RootLayout title="Platform" subtitle="Tenant provisioning">
        <div className="g-card py-16 text-center">
          <ShieldAlert className="mx-auto h-10 w-10 mb-3" style={{ color: 'var(--text-3)' }} />
          <p className="text-sm" style={{ color: 'var(--text-2)' }}>Platform admin access required.</p>
          <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>
            This account doesn&apos;t have platform-operator privileges.
          </p>
        </div>
      </RootLayout>
    );
  }

  return (
    <RootLayout title="Platform" subtitle={`${tenants.length} tenant(s) · ${releases.length} release(s)`}
      onRefresh={() => load(true)} refreshing={refreshing}
      actions={
        <div className="flex items-center gap-2">
          <button onClick={() => setShowRelease(true)} className="g-btn g-btn-ghost text-xs">
            <Upload className="h-3.5 w-3.5" /> Publish Agent Release
          </button>
          <button onClick={() => setShowNew(true)} className="g-btn g-btn-primary text-xs">
            <Plus className="h-3.5 w-3.5" /> New Tenant
          </button>
        </div>
      }>

      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)' }}>{toast}</div>}

      {/* Tab bar */}
      <div className="flex gap-1 p-1 mb-5 rounded-xl w-fit" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
        {(
          [
            ['tenants',    Building2,  'Tenants']    as const,
            ...(isAuthority ? [
              ['deployment', Server,   'Deployment Mode'] as const,
              ['saas',       CreditCard, 'SaaS & Billing'] as const,
            ] : []),
          ]
        ).map(([id, Icon, label]) => (
          <button key={id} onClick={() => setPtab(id as PTab)}
            className="flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-medium transition-all"
            style={{
              background: ptab === id ? 'var(--accent-glow)' : 'transparent',
              color:      ptab === id ? 'var(--accent)' : 'var(--text-2)',
              border:     ptab === id ? '1px solid var(--accent-border)' : '1px solid transparent',
            }}>
            <Icon className="h-3.5 w-3.5" />{label}
          </button>
        ))}
      </div>

      {ptab === 'deployment' && <DeploymentModePanel notify={notify} />}
      {ptab === 'saas' && <SaasAdminPanel notify={notify} />}

      {ptab === 'tenants' && <>
      {/* ── Tenants ─────────────────────────────────────────── */}
      <div className="mb-6">
        <p className="text-xs font-semibold uppercase tracking-wide mb-3" style={{ color: 'var(--text-3)' }}>Tenants</p>
        <div className="g-table">
          <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '24px 1fr 160px 90px 90px 140px 1fr' }}>
            <span></span><span>Name</span><span>Slug</span><span>Users</span><span>Status</span><span>Created</span><span></span>
          </div>

          {loading ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          ) : tenants.length === 0 ? (
            <div className="py-16 text-center">
              <Building2 className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>No tenants yet.</p>
            </div>
          ) : tenants.map(t => (
            <div key={t.id}>
              <div className="g-tr grid gap-3 items-center px-4"
                style={{ gridTemplateColumns: '24px 1fr 160px 90px 90px 140px 1fr' }}>
                <button onClick={() => setExpandedTenant(expandedTenant === t.id ? null : t.id)}
                  style={{ color: 'var(--text-3)' }}>
                  {expandedTenant === t.id
                    ? <ChevronDown className="h-3.5 w-3.5" />
                    : <ChevronRight className="h-3.5 w-3.5" />}
                </button>
                <span className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{t.name}</span>
                <span className="mono text-[11px] truncate" style={{ color: 'var(--text-3)' }}>{t.slug}</span>
                <span className="text-xs" style={{ color: 'var(--text-2)' }}>{t.user_count ?? 0}</span>
                <span className="text-[11px] font-semibold" style={{ color: t.is_active ? 'var(--green)' : 'var(--red)' }}>
                  {t.is_active ? 'Active' : 'Suspended'}
                </span>
                <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{timeAgo(t.created_at)}</span>
                <div className="flex items-center gap-2">
                  <button
                    title={t.is_active ? 'Suspend tenant' : 'Reactivate tenant'}
                    onClick={() => toggleTenant(t)}
                    disabled={toggling === t.id}
                    className="g-btn text-xs"
                    style={{
                      background: t.is_active ? 'var(--red-bg)' : 'rgba(52,211,153,0.15)',
                      color: t.is_active ? 'var(--red)' : 'var(--green)',
                      border: t.is_active ? '1px solid var(--red-border)' : '1px solid rgba(52,211,153,0.3)',
                    }}>
                    {t.is_active ? <ToggleLeft className="h-3.5 w-3.5" /> : <ToggleRight className="h-3.5 w-3.5" />}
                    {t.is_active ? 'Suspend' : 'Reactivate'}
                  </button>
                  {t.id !== 1 && (
                    <button
                      title="Delete tenant permanently"
                      onClick={() => { setDeletingTenant(t); setDeleteConfirm(''); }}
                      className="g-btn text-xs"
                      style={{ background: 'var(--red-bg)', color: 'var(--red)', border: '1px solid var(--red-border)' }}>
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>
              </div>
              {expandedTenant === t.id && (
                <div style={{ borderTop: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
                  <DomainsPanel tenantID={t.id} />
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* ── Agent Releases ────────────────────────────────────── */}
      <div>
        <p className="text-xs font-semibold uppercase tracking-wide mb-3" style={{ color: 'var(--text-3)' }}>Agent Releases</p>
        <div className="g-table">
          <div className="g-thead grid gap-3 px-4"
            style={{ gridTemplateColumns: '140px 90px 1fr 80px 130px' }}>
            <span>Platform</span><span>Version</span><span>Download URL</span><span>By</span><span>Published</span>
          </div>

          {releases.length === 0 ? (
            <div className="py-12 text-center">
              <Package className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>No releases published yet.</p>
              <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>
                Agents poll for updates every 6 hours — publish a release to trigger self-update.
              </p>
            </div>
          ) : releases.map(r => (
            <div key={r.id} className="g-tr grid gap-3 items-center px-4"
              style={{ gridTemplateColumns: '140px 90px 1fr 80px 130px' }}>
              <span className="mono text-[11px] font-semibold" style={{ color: 'var(--accent)' }}>{r.platform}</span>
              <span className="mono text-[11px]" style={{ color: 'var(--text-1)' }}>v{r.version}</span>
              <a href={r.download_url} target="_blank" rel="noopener noreferrer"
                className="text-[11px] truncate hover:underline"
                style={{ color: 'var(--text-3)' }}
                title={r.download_url}>
                {r.download_url}
              </a>
              <span className="text-[11px]" style={{ color: 'var(--text-2)' }}>{r.created_by}</span>
              <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{timeAgo(r.created_at)}</span>
            </div>
          ))}
        </div>
      </div>

      </>}

      {/* ── Delete Tenant confirmation modal ──────────────────── */}
      {deletingTenant && (
        <div className="g-modal-backdrop" onClick={() => setDeletingTenant(null)}>
          <div className="g-modal" style={{ maxWidth: 420 }} onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--red)' }}>Delete Tenant</h2>
              <button onClick={() => setDeletingTenant(null)} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>
            <div className="p-5 space-y-4">
              <p className="text-sm" style={{ color: 'var(--text-1)' }}>
                This will permanently delete <strong>{deletingTenant.name}</strong> and all its users, agents, alerts, and data. This cannot be undone.
              </p>
              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>
                  Type <span className="mono font-semibold" style={{ color: 'var(--text-1)' }}>{deletingTenant.slug}</span> to confirm
                </label>
                <input
                  className="g-input w-full text-sm"
                  value={deleteConfirm}
                  onChange={e => setDeleteConfirm(e.target.value)}
                  placeholder={deletingTenant.slug}
                  autoFocus
                />
              </div>
              <div className="flex justify-end gap-2 pt-1">
                <button className="g-btn text-xs" onClick={() => setDeletingTenant(null)}>Cancel</button>
                <button
                  className="g-btn text-xs"
                  disabled={deleteConfirm !== deletingTenant.slug || deleteInProgress}
                  onClick={confirmDeleteTenant}
                  style={{
                    background: 'var(--red-bg)',
                    color: 'var(--red)',
                    border: '1px solid var(--red-border)',
                    opacity: deleteConfirm !== deletingTenant.slug ? 0.4 : 1,
                  }}>
                  <Trash2 className="h-3.5 w-3.5" />
                  {deleteInProgress ? 'Deleting…' : 'Delete Permanently'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── New Tenant modal ───────────────────────────────────── */}
      {showNew && (
        <div className="g-modal-backdrop" onClick={() => { setShowNew(false); setNewTenantInviteLink(null); }}>
          <div className="g-modal" style={{ maxWidth: 460 }} onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
                {newTenantInviteLink ? 'Share Invite Link' : 'New Tenant'}
              </h2>
              <button onClick={() => { setShowNew(false); setNewTenantInviteLink(null); }} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>
            {newTenantInviteLink ? (
              <div className="p-5 space-y-4">
                <div className="rounded-lg p-3 text-xs" style={{ background: 'rgba(251,191,36,0.08)', border: '1px solid rgba(251,191,36,0.25)', color: 'var(--text-2)' }}>
                  Tenant created. SMTP is not configured — share this link with <strong>{newTenantAdminName}</strong> so they can set their password. Expires in 7 days.
                </div>
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Set-password link</label>
                  <div className="flex gap-2">
                    <input readOnly value={newTenantInviteLink} className="g-input flex-1 text-[11px] mono" onClick={e => (e.target as HTMLInputElement).select()} />
                    <button className="g-btn text-xs shrink-0" onClick={() => { navigator.clipboard.writeText(newTenantInviteLink); notify('Link copied'); }}>
                      Copy
                    </button>
                  </div>
                </div>
                <button className="g-btn g-btn-primary w-full justify-center text-xs"
                  onClick={() => { setShowNew(false); setNewTenantInviteLink(null); }}>
                  Done
                </button>
              </div>
            ) : (
              <>
                <div className="p-5 space-y-3">
                  <div>
                    <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Organization name</label>
                    <input value={form.name}
                      onChange={e => setForm(f => ({ ...f, name: e.target.value, slug: f.slug || slugify(e.target.value) }))}
                      placeholder="Acme Corp" className="g-input" />
                  </div>
                  <div>
                    <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Slug</label>
                    <input value={form.slug} onChange={e => setForm(f => ({ ...f, slug: slugify(e.target.value) }))}
                      placeholder="acme-corp" className="g-input mono" />
                  </div>
                  <div>
                    <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>First admin — username</label>
                    <input value={form.admin_username} onChange={e => setForm(f => ({ ...f, admin_username: e.target.value }))}
                      placeholder="acme_admin" className="g-input" />
                  </div>
                  <div>
                    <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>First admin — email</label>
                    <input value={form.admin_email} onChange={e => setForm(f => ({ ...f, admin_email: e.target.value }))}
                      placeholder="admin@acme.com" className="g-input" />
                    <p className="text-[11px] mt-1" style={{ color: 'var(--text-3)' }}>
                      They&apos;ll get an email with a link to set their password.
                    </p>
                  </div>
                </div>
                <div className="flex gap-3 px-5 pb-5">
                  <button onClick={() => setShowNew(false)} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
                  <button onClick={createTenant} disabled={creating} className="g-btn g-btn-primary flex-1 justify-center">
                    {creating ? 'Creating…' : 'Create Tenant'}
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* ── Publish Release modal ──────────────────────────────── */}
      {showRelease && (
        <div className="g-modal-backdrop" onClick={() => setShowRelease(false)}>
          <div className="g-modal" style={{ maxWidth: 520 }} onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="flex items-center gap-2">
                <Package className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Publish Agent Release</h2>
              </div>
              <button onClick={() => setShowRelease(false)} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>
            <div className="p-5 space-y-3">
              <div className="rounded-xl p-3 text-[11px]"
                style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)', color: 'var(--text-2)' }}>
                Agents poll <span className="mono">/api/agent-releases/:platform</span> every 6 hours.
                When a newer version is available they download it, verify the SHA-256, and re-exec in place (Linux)
                or stage for manual apply (Windows/macOS). Publishing overwrites the current release for the platform.
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Platform</label>
                  <select value={relForm.platform}
                    onChange={e => setRelForm(f => ({ ...f, platform: e.target.value }))}
                    className="g-select w-full">
                    {PLATFORMS.map(p => <option key={p}>{p}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Version</label>
                  <input value={relForm.version}
                    onChange={e => setRelForm(f => ({ ...f, version: e.target.value }))}
                    placeholder="1.2.3" className="g-input w-full mono" />
                </div>
              </div>

              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Download URL</label>
                <input value={relForm.download_url}
                  onChange={e => setRelForm(f => ({ ...f, download_url: e.target.value }))}
                  placeholder="https://releases.example.com/xcloak-agent-linux-amd64-1.2.3"
                  className="g-input w-full mono text-[11px]" />
              </div>

              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>SHA-256 checksum</label>
                <input value={relForm.sha256}
                  onChange={e => setRelForm(f => ({ ...f, sha256: e.target.value }))}
                  placeholder="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                  className="g-input w-full mono text-[10px]" />
                <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                  Run <span className="mono">sha256sum ./xcloak-agent-desktop</span> to get this.
                </p>
              </div>
            </div>
            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => setShowRelease(false)} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={publishRelease}
                disabled={publishing || !relForm.version || !relForm.sha256 || !relForm.download_url}
                className="g-btn g-btn-primary flex-1 justify-center">
                {publishing ? 'Publishing…' : `Publish ${relForm.platform} v${relForm.version || '?'}`}
              </button>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}

// ── Deployment Mode Panel ─────────────────────────────────────────────────────

interface LicenseKey {
  id: number;
  key_id: string;
  customer_name: string;
  customer_email: string;
  tier: string;
  agent_limit: number;
  user_limit: number;
  expires_at: string;
  revoked_at: string | null;
  created_by: string;
  created_at: string;
  token?: string;
}

const TIER_COLOR: Record<string, string> = {
  community: 'var(--text-3)',
  pro: 'var(--accent)',
  enterprise: '#a855f7',
};

function DeploymentModePanel({ notify }: { notify: (m: string) => void }) {
  const [licenseOn, setLicenseOn]   = useState<boolean | null>(null);
  const [saasOn,    setSaasOnLocal] = useState<boolean | null>(null);
  const [togLic,    setTogLic]      = useState(false);
  const [togSaas,   setTogSaas]     = useState(false);
  const [keys,      setKeys]        = useState<LicenseKey[]>([]);
  const [loading,   setLoading]     = useState(true);
  const [showGen,   setShowGen]     = useState(false);
  const [genForm,   setGenForm]     = useState({
    customer_name: '', customer_email: '', tier: 'pro',
    agent_limit: 25, user_limit: 10, expires_at: '', notes: '',
  });
  const [generating, setGenerating] = useState(false);
  const [newToken,   setNewToken]   = useState<string | null>(null);
  const [revoking,   setRevoking]   = useState<string | null>(null);
  const [copied,     setCopied]     = useState(false);

  useEffect(() => {
    Promise.all([
      platformAPI.getLicenseMode(),
      platformAPI.getSaasMode(),
      platformAPI.getLicenseKeys(),
    ]).then(([lm, sm, keys]) => {
      setLicenseOn(lm.data?.license_mode ?? false);
      setSaasOnLocal(sm.data?.saas_mode ?? false);
      setKeys(keys.data || []);
    }).catch(() => { setLicenseOn(false); setSaasOnLocal(false); })
      .finally(() => setLoading(false));
  }, []);

  const toggleLicense = async () => {
    setTogLic(true);
    try {
      const next = !licenseOn;
      await platformAPI.setLicenseMode(next);
      setLicenseOn(next);
      notify(next
        ? 'License enforcement ON — self-hosted instances now require a key'
        : 'License enforcement OFF — full open-source access restored');
    } catch { notify('Failed to toggle license mode'); }
    finally { setTogLic(false); }
  };

  const toggleSaas = async () => {
    setTogSaas(true);
    try {
      const next = !saasOn;
      await platformAPI.setSaasMode(next);
      setSaasOnLocal(next);
      notify(next
        ? 'SaaS mode ON — subscription billing is now enforced'
        : 'SaaS mode OFF — running as open-source / self-hosted');
    } catch { notify('Failed to toggle SaaS mode'); }
    finally { setTogSaas(false); }
  };

  const generate = async () => {
    if (!genForm.customer_name || !genForm.customer_email) {
      notify('Customer name and email are required');
      return;
    }
    setGenerating(true);
    try {
      const res = await platformAPI.generateLicenseKey({
        ...genForm,
        expires_at: genForm.expires_at || new Date(Date.now() + 365 * 86400000).toISOString().slice(0, 10),
      });
      setKeys(k => [res.data, ...k]);
      setNewToken(res.data.token || null);
      setShowGen(false);
      setGenForm({ customer_name: '', customer_email: '', tier: 'pro', agent_limit: 25, user_limit: 10, expires_at: '', notes: '' });
    } catch (e: any) {
      notify(e?.response?.data?.error || 'Failed to generate license key');
    } finally { setGenerating(false); }
  };

  const revoke = async (keyID: string) => {
    if (!confirm('Revoke this license key? This cannot be undone.')) return;
    setRevoking(keyID);
    try {
      await platformAPI.revokeLicenseKey(keyID, 'revoked by platform admin');
      setKeys(k => k.map(x => x.key_id === keyID ? { ...x, revoked_at: new Date().toISOString() } : x));
      notify('License key revoked');
    } catch (e: any) {
      notify(e?.response?.data?.error || 'Failed to revoke');
    } finally { setRevoking(null); }
  };

  const copyToken = (token: string) => {
    navigator.clipboard.writeText(token).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  if (loading) return <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>;

  return (
    <div className="space-y-5">

      {/* Two master toggle cards */}
      <div className="grid grid-cols-2 gap-4">

        {/* Self-hosted License Mode */}
        <div className="g-card p-5">
          <div className="flex items-start justify-between gap-3">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <Server className="h-4 w-4 flex-shrink-0" style={{ color: licenseOn ? 'var(--orange)' : 'var(--text-3)' }} />
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Self-hosted License</p>
                <span className="text-[10px] px-2 py-0.5 rounded-full font-semibold flex-shrink-0"
                  style={{
                    background: licenseOn ? 'rgba(251,146,60,0.15)' : 'var(--glass-bg)',
                    color: licenseOn ? 'var(--orange)' : 'var(--text-3)',
                    border: `1px solid ${licenseOn ? 'rgba(251,146,60,0.4)' : 'var(--border)'}`,
                  }}>
                  {licenseOn ? 'ENFORCED' : 'FREE'}
                </span>
              </div>
              <p className="text-[11px] leading-relaxed" style={{ color: 'var(--text-3)' }}>
                {licenseOn
                  ? 'Self-hosted instances must present a valid license key. Instances without a key enter a 30-day grace period, then degrade to community limits.'
                  : 'OFF — users enjoy full product capabilities for free. Flip this when ready to monetize self-hosted deployments.'}
              </p>
            </div>
            <button onClick={toggleLicense} disabled={togLic}
              className="flex items-center gap-2 px-3 py-2 rounded-xl text-sm font-semibold transition-all flex-shrink-0"
              style={{
                background: licenseOn ? 'rgba(251,146,60,0.15)' : 'var(--glass-bg)',
                border: `1px solid ${licenseOn ? 'rgba(251,146,60,0.4)' : 'var(--border)'}`,
                color: licenseOn ? 'var(--orange)' : 'var(--text-2)',
              }}>
              {licenseOn ? <ToggleRight className="h-5 w-5" /> : <ToggleLeft className="h-5 w-5" />}
              {togLic ? '…' : licenseOn ? 'ON' : 'OFF'}
            </button>
          </div>
        </div>

        {/* SaaS Mode */}
        <div className="g-card p-5">
          <div className="flex items-start justify-between gap-3">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <Cloud className="h-4 w-4 flex-shrink-0" style={{ color: saasOn ? 'var(--green)' : 'var(--text-3)' }} />
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>SaaS Mode</p>
                <span className="text-[10px] px-2 py-0.5 rounded-full font-semibold flex-shrink-0"
                  style={{
                    background: saasOn ? 'rgba(52,211,153,0.15)' : 'var(--glass-bg)',
                    color: saasOn ? 'var(--green)' : 'var(--text-3)',
                    border: `1px solid ${saasOn ? 'rgba(52,211,153,0.4)' : 'var(--border)'}`,
                  }}>
                  {saasOn ? 'BILLING ON' : 'FREE'}
                </span>
              </div>
              <p className="text-[11px] leading-relaxed" style={{ color: 'var(--text-3)' }}>
                {saasOn
                  ? 'Subscription billing enforced. Suspended or expired tenants are blocked from accessing the platform.'
                  : 'OFF — your hosted instance runs without subscription enforcement. Flip this when you\'re ready to offer paid SaaS tiers.'}
              </p>
            </div>
            <button onClick={toggleSaas} disabled={togSaas}
              className="flex items-center gap-2 px-3 py-2 rounded-xl text-sm font-semibold transition-all flex-shrink-0"
              style={{
                background: saasOn ? 'rgba(52,211,153,0.15)' : 'var(--glass-bg)',
                border: `1px solid ${saasOn ? 'rgba(52,211,153,0.4)' : 'var(--border)'}`,
                color: saasOn ? 'var(--green)' : 'var(--text-2)',
              }}>
              {saasOn ? <ToggleRight className="h-5 w-5" /> : <ToggleLeft className="h-5 w-5" />}
              {togSaas ? '…' : saasOn ? 'ON' : 'OFF'}
            </button>
          </div>
        </div>
      </div>

      {/* Phase roadmap hint */}
      {!licenseOn && !saasOn && (
        <div className="rounded-xl p-4 text-[11px] leading-relaxed"
          style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)', color: 'var(--text-2)' }}>
          <span className="font-semibold" style={{ color: 'var(--accent)' }}>Phase 1 (now):</span> Both OFF — users get full product, no friction.
          Build adoption, get stars.{' '}
          <span className="font-semibold" style={{ color: 'var(--orange)' }}>Phase 2:</span> Flip Self-hosted ON — generate and sell license keys.{' '}
          <span className="font-semibold" style={{ color: 'var(--green)' }}>Phase 3:</span> Use license revenue to fund VPS, then flip SaaS ON.
        </div>
      )}

      {/* License Keys */}
      <div className="g-card">
        <div className="flex items-center justify-between px-5 py-4" style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="flex items-center gap-2">
            <Key className="h-4 w-4" style={{ color: 'var(--accent)' }} />
            <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>License Keys</p>
            <span className="text-[10px] px-1.5 py-0.5 rounded mono"
              style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-3)' }}>
              {keys.length}
            </span>
          </div>
          <button onClick={() => setShowGen(true)} className="g-btn g-btn-primary text-xs">
            <Plus className="h-3.5 w-3.5" /> Generate Key
          </button>
        </div>

        {keys.length === 0 ? (
          <div className="py-12 text-center">
            <Key className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No license keys yet.</p>
            <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>
              Generate keys for customers before enabling license enforcement.
            </p>
          </div>
        ) : (
          <div className="g-table">
            <div className="g-thead grid gap-3 px-4"
              style={{ gridTemplateColumns: '1fr 140px 70px 60px 60px 100px 80px 40px' }}>
              <span>Customer</span><span>Key ID</span><span>Tier</span><span>Agents</span><span>Users</span><span>Expires</span><span>Status</span><span></span>
            </div>
            {keys.map(k => (
              <div key={k.key_id} className="g-tr grid gap-3 items-center px-4"
                style={{ gridTemplateColumns: '1fr 140px 70px 60px 60px 100px 80px 40px' }}>
                <div className="min-w-0">
                  <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{k.customer_name}</p>
                  <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>{k.customer_email}</p>
                </div>
                <span className="mono text-[10px]" style={{ color: 'var(--text-3)' }}>{k.key_id}</span>
                <span className="text-[11px] font-semibold" style={{ color: TIER_COLOR[k.tier] ?? 'var(--accent)' }}>
                  {k.tier.charAt(0).toUpperCase() + k.tier.slice(1)}
                </span>
                <span className="text-xs" style={{ color: 'var(--text-2)' }}>{k.agent_limit === -1 ? '∞' : k.agent_limit}</span>
                <span className="text-xs" style={{ color: 'var(--text-2)' }}>{k.user_limit === -1 ? '∞' : k.user_limit}</span>
                <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>
                  {new Date(k.expires_at).toLocaleDateString()}
                </span>
                <span className="text-[11px] font-semibold"
                  style={{ color: k.revoked_at ? 'var(--red)' : new Date(k.expires_at) < new Date() ? 'var(--orange)' : 'var(--green)' }}>
                  {k.revoked_at ? 'Revoked' : new Date(k.expires_at) < new Date() ? 'Expired' : 'Active'}
                </span>
                <button onClick={() => revoke(k.key_id)} disabled={!!k.revoked_at || revoking === k.key_id}
                  title="Revoke key"
                  className="p-1 rounded transition-colors disabled:opacity-30"
                  style={{ color: 'var(--text-3)' }}
                  onMouseEnter={e => { if (!k.revoked_at) (e.currentTarget as HTMLElement).style.color = 'var(--red)'; }}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Generate key modal */}
      {showGen && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setShowGen(false)}>
          <div className="g-modal" style={{ maxWidth: 480 }} onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="flex items-center gap-2">
                <Key className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Generate License Key</h2>
              </div>
              <button onClick={() => setShowGen(false)} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>
            <div className="p-5 space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Customer name *</label>
                  <input value={genForm.customer_name}
                    onChange={e => setGenForm(f => ({ ...f, customer_name: e.target.value }))}
                    placeholder="Acme Corp" className="g-input w-full" />
                </div>
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Customer email *</label>
                  <input value={genForm.customer_email}
                    onChange={e => setGenForm(f => ({ ...f, customer_email: e.target.value }))}
                    placeholder="admin@acme.com" className="g-input w-full" />
                </div>
              </div>
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Tier</label>
                  <select value={genForm.tier} onChange={e => setGenForm(f => ({ ...f, tier: e.target.value }))} className="g-select w-full">
                    <option value="community">Community</option>
                    <option value="pro">Pro</option>
                    <option value="enterprise">Enterprise</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Agent limit</label>
                  <input type="number" min={1} value={genForm.agent_limit}
                    onChange={e => setGenForm(f => ({ ...f, agent_limit: +e.target.value }))}
                    className="g-input w-full mono" />
                </div>
                <div>
                  <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>User limit</label>
                  <input type="number" min={1} value={genForm.user_limit}
                    onChange={e => setGenForm(f => ({ ...f, user_limit: +e.target.value }))}
                    className="g-input w-full mono" />
                </div>
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Expires (leave blank = 1 year)</label>
                <input type="date" value={genForm.expires_at}
                  onChange={e => setGenForm(f => ({ ...f, expires_at: e.target.value }))}
                  className="g-input w-full mono" />
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Internal notes</label>
                <input value={genForm.notes}
                  onChange={e => setGenForm(f => ({ ...f, notes: e.target.value }))}
                  placeholder="e.g. Invoice #42, paid via Stripe" className="g-input w-full" />
              </div>
            </div>
            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => setShowGen(false)} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={generate} disabled={generating || !genForm.customer_name || !genForm.customer_email}
                className="g-btn g-btn-primary flex-1 justify-center">
                {generating ? 'Generating…' : 'Generate Key'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Show newly generated token */}
      {newToken && (
        <div className="g-modal-backdrop" onClick={() => setNewToken(null)}>
          <div className="g-modal" style={{ maxWidth: 560 }} onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="flex items-center gap-2">
                <Key className="h-4 w-4" style={{ color: 'var(--green)' }} />
                <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>License Key Generated</h2>
              </div>
              <button onClick={() => setNewToken(null)} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>
            <div className="p-5 space-y-4">
              <div className="rounded-xl p-3 text-[11px]"
                style={{ background: 'rgba(52,211,153,0.08)', border: '1px solid rgba(52,211,153,0.3)', color: 'var(--text-2)' }}>
                Copy this key now — it will not be shown again. Send it to the customer via email.
                They set it as <span className="mono font-semibold">XCLOAK_LICENSE_KEY</span> in their <span className="mono">.env</span>.
              </div>
              <div className="rounded-xl p-3 mono text-[10px] break-all select-all"
                style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--accent)' }}>
                {newToken}
              </div>
              <button onClick={() => copyToken(newToken)}
                className="g-btn g-btn-primary w-full justify-center">
                <Copy className="h-3.5 w-3.5" />
                {copied ? 'Copied!' : 'Copy to Clipboard'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── SaaS Admin Panel ──────────────────────────────────────────────────────────

const PLAN_COLORS: Record<string, string> = {
  trial: 'var(--text-3)', starter: 'var(--accent)',
  growth: 'var(--green)', pro: 'var(--orange)', enterprise: '#a855f7',
};
const STATUS_OPTS = ['trial', 'active', 'suspended', 'cancelled'];
const PLAN_OPTS   = ['trial', 'starter', 'growth', 'pro', 'enterprise'];

function SaasAdminPanel({ notify }: { notify: (m: string) => void }) {
  const [saasOn, setSaasOn]       = useState<boolean | null>(null);
  const [toggling, setToggling]   = useState(false);
  const [stats, setStats]         = useState<any>(null);
  const [subs, setSubs]           = useState<any[]>([]);
  const [loading, setLoading]     = useState(true);
  const [editSub, setEditSub]     = useState<any | null>(null);
  const [editForm, setEditForm]   = useState({ plan: '', status: '', notes: '' });
  const [saving, setSaving]       = useState(false);

  useEffect(() => {
    Promise.all([
      platformAPI.getSaasMode(),
      platformAPI.getSaasStats(),
      platformAPI.getAllSubscriptions(),
    ]).then(([m, st, sb]) => {
      setSaasOn(m.data?.saas_mode ?? false);
      setStats(st.data);
      setSubs(sb.data || []);
    }).catch(() => { setSaasOn(false); })
      .finally(() => setLoading(false));
  }, []);

  const toggleMode = async () => {
    setToggling(true);
    try {
      const next = !saasOn;
      await platformAPI.setSaasMode(next);
      setSaasOn(next);
      notify(next ? 'SaaS mode ENABLED — plan limits are now enforced' : 'SaaS mode DISABLED — running as self-hosted');
    } catch { notify('Failed to toggle SaaS mode'); }
    finally { setToggling(false); }
  };

  const openEdit = (sub: any) => {
    setEditForm({ plan: sub.plan_name, status: sub.status, notes: sub.notes || '' });
    setEditSub(sub);
  };

  const saveEdit = async () => {
    if (!editSub) return;
    setSaving(true);
    try {
      await platformAPI.updateSubscription(editSub.tenant_id, {
        plan: editForm.plan,
        status: editForm.status,
        notes: editForm.notes || undefined,
      });
      setSubs(s => s.map(x => x.tenant_id === editSub.tenant_id
        ? { ...x, plan_name: editForm.plan, status: editForm.status, notes: editForm.notes }
        : x));
      notify('Subscription updated');
      setEditSub(null);
    } catch { notify('Failed to update subscription'); }
    finally { setSaving(false); }
  };

  if (loading) return <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>;

  return (
    <div className="space-y-5">

      {/* SaaS Mode master toggle */}
      <div className="g-card p-5">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Activity className="h-4 w-4" style={{ color: saasOn ? 'var(--green)' : 'var(--text-3)' }} />
              <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>SaaS Mode</p>
            </div>
            <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
              {saasOn
                ? 'Plan limits are enforced. Suspended/expired tenants are blocked.'
                : 'Disabled — running as open-source self-hosted. No plan enforcement.'}
            </p>
          </div>
          <button onClick={toggleMode} disabled={toggling}
            className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold transition-all"
            style={{
              background: saasOn ? 'rgba(52,211,153,0.15)' : 'var(--glass-bg)',
              border: `1px solid ${saasOn ? 'rgba(52,211,153,0.4)' : 'var(--border)'}`,
              color: saasOn ? 'var(--green)' : 'var(--text-2)',
            }}>
            {saasOn ? <ToggleRight className="h-5 w-5" /> : <ToggleLeft className="h-5 w-5" />}
            {toggling ? '…' : saasOn ? 'ON' : 'OFF'}
          </button>
        </div>
      </div>

      {/* Stats strip */}
      {stats && (
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Total Tenants',    value: stats.total_tenants,     icon: Users,       color: 'var(--accent)' },
            { label: 'Active (Paying)',  value: stats.active_tenants,    icon: Activity,    color: 'var(--green)' },
            { label: 'On Trial',         value: stats.trial_tenants,     icon: TrendingUp,  color: 'var(--orange)' },
            { label: 'MRR',              value: `$${stats.mrr.toLocaleString()}`, icon: DollarSign, color: '#a855f7' },
          ].map(({ label, value, icon: Icon, color }) => (
            <div key={label} className="g-card p-4 flex items-center gap-3">
              <div className="p-2 rounded-lg" style={{ background: `${color}18`, border: `1px solid ${color}30` }}>
                <Icon className="h-4 w-4" style={{ color }} />
              </div>
              <div>
                <p className="text-lg font-bold" style={{ color }}>{value}</p>
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{label}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Subscriptions table */}
      <div className="g-card">
        <div className="px-5 py-4 border-b" style={{ borderColor: 'var(--border)' }}>
          <div className="flex items-center gap-2">
            <CreditCard className="h-4 w-4" style={{ color: 'var(--accent)' }} />
            <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>All Subscriptions</p>
          </div>
        </div>
        <div className="g-table">
          <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 100px 80px 90px 100px 80px 40px' }}>
            <span>Tenant</span><span>Plan</span><span>Price</span><span>Status</span><span>Agents</span><span>Updated</span><span></span>
          </div>
          {subs.length === 0 ? (
            <div className="py-12 text-center text-sm" style={{ color: 'var(--text-3)' }}>No subscriptions yet.</div>
          ) : subs.map(sub => {
            const color = PLAN_COLORS[sub.plan_name] ?? 'var(--accent)';
            return (
              <div key={sub.tenant_id} className="g-tr grid gap-3 items-center px-4"
                style={{ gridTemplateColumns: '1fr 100px 80px 90px 100px 80px 40px' }}>
                <span className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>Tenant #{sub.tenant_id}</span>
                <span className="text-xs font-semibold" style={{ color }}>{sub.plan_display_name}</span>
                <span className="text-xs" style={{ color: 'var(--text-3)' }}>
                  {sub.price_monthly > 0 ? `$${sub.price_monthly}` : 'Free'}
                </span>
                <span className="text-[11px]" style={{
                  color: sub.status === 'active' ? 'var(--green)' : sub.status === 'trial' ? 'var(--orange)' : 'var(--red)'
                }}>
                  {sub.status.charAt(0).toUpperCase() + sub.status.slice(1)}
                </span>
                <span className="text-xs" style={{ color: 'var(--text-2)' }}>
                  {sub.max_agents === -1 ? '∞' : sub.max_agents}
                </span>
                <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{timeAgo(sub.updated_at)}</span>
                <button onClick={() => openEdit(sub)} className="p-1 rounded transition-colors"
                  style={{ color: 'var(--text-3)' }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--accent)'}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                  <Edit2 className="h-3.5 w-3.5" />
                </button>
              </div>
            );
          })}
        </div>
      </div>

      {/* Edit subscription modal */}
      {editSub && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setEditSub(null)}>
          <div className="g-modal" style={{ maxWidth: 440 }}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
                Edit Subscription — Tenant #{editSub.tenant_id}
              </h2>
              <button onClick={() => setEditSub(null)} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>
            <div className="p-5 space-y-3">
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Plan</label>
                <select value={editForm.plan} onChange={e => setEditForm(f => ({ ...f, plan: e.target.value }))} className="g-select">
                  {PLAN_OPTS.map(p => <option key={p} value={p}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Status</label>
                <select value={editForm.status} onChange={e => setEditForm(f => ({ ...f, status: e.target.value }))} className="g-select">
                  {STATUS_OPTS.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Notes (internal)</label>
                <textarea value={editForm.notes} onChange={e => setEditForm(f => ({ ...f, notes: e.target.value }))}
                  rows={2} placeholder="e.g. Paid via wire transfer, invoice #123"
                  className="g-input resize-none text-xs" />
              </div>
            </div>
            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => setEditSub(null)} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={saveEdit} disabled={saving} className="g-btn g-btn-primary flex-1 justify-center">
                {saving ? 'Saving…' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
