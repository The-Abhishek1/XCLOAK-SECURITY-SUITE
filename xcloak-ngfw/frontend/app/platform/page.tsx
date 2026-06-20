'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import api, { platformAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import { Plus, X, ShieldAlert, Building2, ToggleLeft, ToggleRight } from 'lucide-react';

interface Tenant {
  id: number;
  name: string;
  slug: string;
  is_active: boolean;
  created_at: string;
  user_count?: number;
}

export default function PlatformPage() {
  const [tenants, setTenants]   = useState<Tenant[]>([]);
  const [loading, setLoading]   = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [isPlatformAdmin, setIsPlatformAdmin] = useState<boolean | null>(null);
  const [showNew, setShowNew]   = useState(false);
  const [form, setForm]         = useState({ name: '', slug: '', admin_username: '', admin_email: '' });
  const [creating, setCreating] = useState(false);
  const [toast, setToast]       = useState<string | null>(null);
  const [toggling, setToggling] = useState<number | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 4000); };

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const r = await platformAPI.getTenants();
      setTenants(r.data || []);
    } finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => {
    api.get('/auth/profile')
      .then(r => setIsPlatformAdmin(!!r.data?.is_platform_admin))
      .catch(() => setIsPlatformAdmin(false));
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
            This account doesn't have platform-operator privileges.
          </p>
        </div>
      </RootLayout>
    );
  }

  return (
    <RootLayout title="Platform" subtitle={`${tenants.length} tenant(s)`}
      onRefresh={() => load(true)} refreshing={refreshing}
      actions={
        <button onClick={() => setShowNew(true)} className="g-btn g-btn-primary text-xs">
          <Plus className="h-3.5 w-3.5" /> New Tenant
        </button>
      }>

      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)' }}>{toast}</div>}

      <div className="g-table">
        <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 160px 90px 90px 140px 100px' }}>
          <span>Name</span><span>Slug</span><span>Users</span><span>Status</span><span>Created</span><span></span>
        </div>

        {loading ? (
          <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
        ) : tenants.length === 0 ? (
          <div className="py-16 text-center">
            <Building2 className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No tenants yet.</p>
          </div>
        ) : tenants.map(t => (
          <div key={t.id} className="g-tr grid gap-3 items-center px-4"
            style={{ gridTemplateColumns: '1fr 160px 90px 90px 140px 100px' }}>
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
        ))}
      </div>

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
                  They'll get an email with a link to set their password.
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
    </RootLayout>
  );
}
