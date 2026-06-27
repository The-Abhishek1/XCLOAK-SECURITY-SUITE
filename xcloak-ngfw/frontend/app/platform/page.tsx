'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { platformAPI } from '@/lib/api';
import { useUser } from '@/context/UserContext';
import { AgentRelease, TenantDomain } from '@/types';
import { timeAgo } from '@/lib/utils';
import { Plus, X, ShieldAlert, Building2, ToggleLeft, ToggleRight, Package, Upload, Globe, ChevronRight, ChevronDown } from 'lucide-react';

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

export default function PlatformPage() {
  const { profile } = useUser();
  const isPlatformAdmin = profile?.is_platform_admin ?? null;
  const [tenants, setTenants]     = useState<Tenant[]>([]);
  const [releases, setReleases]   = useState<AgentRelease[]>([]);
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [expandedTenant, setExpandedTenant] = useState<number | null>(null);
  const [showNew, setShowNew]     = useState(false);
  const [showRelease, setShowRelease] = useState(false);
  const [form, setForm]           = useState({ name: '', slug: '', admin_username: '', admin_email: '' });
  const [relForm, setRelForm]     = useState({ platform: 'linux_amd64', version: '', sha256: '', download_url: '' });
  const [creating, setCreating]   = useState(false);
  const [publishing, setPublishing] = useState(false);
  const [toast, setToast]         = useState<string | null>(null);
  const [toggling, setToggling]   = useState<number | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 4000); };

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const [tRes, rRes] = await Promise.allSettled([
        platformAPI.getTenants(),
        platformAPI.getReleases(),
      ]);
      if (tRes.status === 'fulfilled') setTenants(tRes.value.data || []);
      if (rRes.status === 'fulfilled') setReleases(rRes.value.data || []);
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
      await platformAPI.createTenant(form.name, form.slug, form.admin_username, form.admin_email);
      notify(`Tenant created — invite sent to ${form.admin_email}`);
      setShowNew(false);
      setForm({ name: '', slug: '', admin_username: '', admin_email: '' });
      load();
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

      {/* ── Tenants ─────────────────────────────────────────── */}
      <div className="mb-6">
        <p className="text-xs font-semibold uppercase tracking-wide mb-3" style={{ color: 'var(--text-3)' }}>Tenants</p>
        <div className="g-table">
          <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '24px 1fr 160px 90px 90px 140px 100px' }}>
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
                style={{ gridTemplateColumns: '24px 1fr 160px 90px 90px 140px 100px' }}>
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

      {/* ── New Tenant modal ───────────────────────────────────── */}
      {showNew && (
        <div className="g-modal-backdrop" onClick={() => setShowNew(false)}>
          <div className="g-modal" style={{ maxWidth: 460 }} onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>New Tenant</h2>
              <button onClick={() => setShowNew(false)} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>
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
                  Run <span className="mono">sha256sum ./xcloak-agent</span> to get this.
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
