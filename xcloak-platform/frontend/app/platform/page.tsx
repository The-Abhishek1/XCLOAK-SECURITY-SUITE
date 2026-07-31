'use client';
import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { tneAPI, platformAPI } from '@/lib/api';
import { MetricCard, DataTable, EmptyState, SectionCard, TabBar, ActionButton } from '@/components/design-system';
import {
  LayoutDashboard, Building2, KeyRound, BarChart3, FileBarChart2,
  Plus, X, CheckCircle2, Ban, Pencil, Blocks, Gauge, CreditCard,
  Save, RotateCcw, Power, Wand2, Send, Trash2, Globe,
} from 'lucide-react';

// ── helpers ────────────────────────────────────────────────────────────────────

const PILL_COLORS: Record<string, string> = {
  active: '#16a34a', suspended: '#dc2626', trial: '#d97706', pending: '#d97706',
  healthy: '#16a34a', degraded: '#d97706', critical: '#dc2626',
  paid: '#16a34a', unpaid: '#dc2626', overdue: '#dc2626',
  enterprise_plus: '#7c3aed', enterprise: '#2563eb', professional: '#0891b2', community: '#6b7280',
};

function pill(label: string, color?: string) {
  const bg = color ? PILL_COLORS[color] ?? color : PILL_COLORS[label] ?? '#6b7280';
  return (
    <span style={{
      background: bg + '22', color: bg, border: `1px solid ${bg}44`,
      borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600,
      textTransform: 'uppercase', letterSpacing: '0.04em', whiteSpace: 'nowrap',
    }}>{label}</span>
  );
}

function SelectTenantPrompt({ onGo, label = 'to continue' }: { onGo: () => void; label?: string }) {
  return (
    <SectionCard>
      <div style={{ textAlign: 'center', padding: '12px 0', color: 'var(--text-3)', fontSize: 13 }}>
        Select a tenant from{' '}
        <ActionButton variant="ghost" icon={Building2} onClick={onGo} style={{ display: 'inline-flex' }}>Tenant Directory</ActionButton>
        {' '}{label}
      </div>
    </SectionCard>
  );
}

// ── sidebar / tab config ──────────────────────────────────────────────────────

const TABS = [
  { key: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { key: 'tenants',   label: 'Tenants',   icon: Building2 },
  { key: 'licenses',  label: 'Licenses',  icon: KeyRound },
  { key: 'usage',     label: 'Usage',     icon: BarChart3 },
  { key: 'reports',   label: 'Reports',   icon: FileBarChart2 },
];

const SIDEBAR: Record<string, { key: string; label: string }[]> = {
  dashboard: [{ key: 'overview',     label: 'Tenant Dashboard' }],
  tenants:   [{ key: 'directory',    label: 'Tenant Directory' }, { key: 'config', label: 'Tenant Configuration' },
              { key: 'live',         label: 'Live Tenants' },
              { key: 'isolation',    label: 'Data Isolation' }, { key: 'deployment', label: 'Deployment Mode' }],
  licenses:  [{ key: 'rbac',         label: 'Users & RBAC' }, { key: 'modules', label: 'Module Management' }],
  usage:     [{ key: 'resources',    label: 'Resource Allocation' },
              { key: 'subscription', label: 'Subscription & Licensing' }, { key: 'billing', label: 'Billing' }],
  reports:   [{ key: 'analytics',    label: 'Usage Analytics' }, { key: 'health', label: 'Tenant Health' },
              { key: 'ai',           label: 'AI Assistant' }, { key: 'audit', label: 'Audit Trail' }],
};

const DEFAULT_SECTION: Record<string, string> = {
  dashboard: 'overview', tenants: 'directory', licenses: 'rbac',
  usage: 'resources', reports: 'analytics',
};

// ── constants ─────────────────────────────────────────────────────────────────

const ALL_MODULES = [
  { id: 'siem',               label: 'SIEM',                    tier: 'community' },
  { id: 'edr',                label: 'EDR',                     tier: 'community' },
  { id: 'cases',              label: 'Case Management',          tier: 'community' },
  { id: 'reports',            label: 'Reports',                  tier: 'community' },
  { id: 'soar',               label: 'SOAR / Playbooks',         tier: 'professional' },
  { id: 'ai_assistant',       label: 'AI Assistant',             tier: 'professional' },
  { id: 'threat_intel',       label: 'Threat Intelligence',      tier: 'professional' },
  { id: 'vuln_management',    label: 'Vulnerability Management',  tier: 'enterprise' },
  { id: 'compliance',         label: 'Compliance',               tier: 'enterprise' },
  { id: 'cmdb',               label: 'CMDB',                     tier: 'enterprise' },
  { id: 'mdm',                label: 'MDM',                      tier: 'enterprise' },
  { id: 'cloud_security',     label: 'Cloud Security',           tier: 'enterprise' },
  { id: 'script_runner',      label: 'Script Runner',            tier: 'enterprise' },
  { id: 'quarantine',         label: 'Quarantine',               tier: 'enterprise' },
  { id: 'suppression',        label: 'Suppression',              tier: 'enterprise' },
  { id: 'firewall',           label: 'Firewall',                 tier: 'enterprise_plus' },
  { id: 'container_security', label: 'Container Security',       tier: 'enterprise_plus' },
  { id: 'ot_ics',             label: 'OT / ICS Security',        tier: 'enterprise_plus' },
  { id: 'executive_ai',       label: 'Executive AI Assistant',   tier: 'enterprise_plus' },
];

const RESOURCE_FIELDS = [
  { key: 'max_users',                  label: 'Max Users' },
  { key: 'max_agents',                 label: 'Max Agents' },
  { key: 'max_assets',                 label: 'Max Assets' },
  { key: 'max_endpoints',              label: 'Max Endpoints' },
  { key: 'max_servers',                label: 'Max Servers' },
  { key: 'max_mobile_devices',         label: 'Max Mobile Devices' },
  { key: 'max_storage_gb',             label: 'Max Storage (GB)' },
  { key: 'max_api_requests_day',       label: 'Max API Requests/Day' },
  { key: 'max_ai_sessions_concurrent', label: 'Max Concurrent AI Sessions' },
  { key: 'max_reports',                label: 'Max Reports' },
  { key: 'max_playbooks',              label: 'Max Playbooks' },
  { key: 'max_integrations',           label: 'Max Integrations' },
];

// Sections backed by the seeded tne_* reference dataset, not this deployment's
// real tenants — see the "Live Tenants" section for those.
const DEMO_SECTIONS = new Set([
  'overview', 'directory', 'config', 'rbac', 'modules', 'resources',
  'subscription', 'billing', 'analytics', 'health', 'ai', 'audit',
]);

const AI_PROMPTS = [
  { action: 'health_summary',           label: 'Platform Health Summary' },
  { action: 'license_recommendations',  label: 'License Recommendations' },
  { action: 'resource_optimization',    label: 'Resource Optimization' },
  { action: 'security_recommendations', label: 'Security Recommendations' },
  { action: 'capacity_planning',        label: 'Capacity Planning (6mo)' },
];

// ── component ─────────────────────────────────────────────────────────────────

export default function PlatformPage() {
  const [tab, setTab]             = useState('dashboard');
  const [section, setSection]     = useState('overview');
  const [dashboard, setDashboard] = useState<any>(null);
  const [tenants, setTenants]     = useState<any[]>([]);
  const [analytics, setAnalytics] = useState<any>(null);
  const [platformHealth, setPlatformHealth] = useState<any>(null);
  const [audit, setAudit]         = useState<any[]>([]);
  const [reports, setReports]     = useState<any>(null);

  const [selectedTenant, setSelectedTenant] = useState<any>(null);
  const [tenantDetail, setTenantDetail]     = useState<any>(null);
  const [tenantModules, setTenantModules]   = useState<any[]>([]);
  const [tenantResources, setTenantResources] = useState<any>({});
  const [tenantUsage, setTenantUsage]       = useState<any>(null);
  const [tenantBilling, setTenantBilling]   = useState<any>(null);

  const [configForm, setConfigForm]     = useState<any>({});
  const [resourceForm, setResourceForm] = useState<any>({});
  const [search, setSearch]         = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [planFilter, setPlanFilter]   = useState('');

  const [aiResponse, setAiResponse] = useState('');
  const [aiLoading, setAiLoading]   = useState(false);
  const [aiInput, setAiInput]       = useState('');

  const [showCreate, setShowCreate] = useState(false);
  const [newTenant, setNewTenant]   = useState({
    tenant_name: '', org_name: '', domain: '', admin_email: '',
    plan: 'professional', region: 'us-east-1',
  });

  const [saving, setSaving] = useState(false);
  const [msg, setMsg]       = useState('');

  const [capabilities, setCapabilities] = useState<any>(null);
  const [modeToggling, setModeToggling] = useState<'saas' | 'license' | null>(null);

  // Live tenants — this deployment's real tenants (distinct from the demo
  // Tenant Directory above, which runs on seeded reference data).
  const [realTenants, setRealTenants]     = useState<any[]>([]);
  const [showCreateReal, setShowCreateReal] = useState(false);
  const [newRealTenant, setNewRealTenant] = useState({ name: '', slug: '', admin_username: '', admin_email: '' });
  const [realMsg, setRealMsg]             = useState('');
  const [selectedRealTenant, setSelectedRealTenant] = useState<any>(null);
  const [realTenantDomains, setRealTenantDomains]   = useState<any[]>([]);
  const [newDomain, setNewDomain]         = useState('');

  const realFail = (err: any, fallback: string) => {
    setRealMsg(err?.response?.data?.error || fallback);
    setTimeout(() => setRealMsg(''), 4000);
  };

  const loadRealTenants = useCallback(() => {
    platformAPI.getTenants()
      .then(r => setRealTenants(Array.isArray(r.data) ? r.data : []))
      .catch((err: any) => realFail(err, 'Failed to load live tenants.'));
  }, []);

  useEffect(() => { if (section === 'live') loadRealTenants(); }, [section, loadRealTenants]);

  const createRealTenant = () => {
    platformAPI.createTenant(newRealTenant.name, newRealTenant.slug, newRealTenant.admin_username, newRealTenant.admin_email)
      .then(r => {
        setShowCreateReal(false);
        setNewRealTenant({ name: '', slug: '', admin_username: '', admin_email: '' });
        setRealMsg(r.data?.message ?? 'Tenant created.');
        setTimeout(() => setRealMsg(''), 5000);
        loadRealTenants();
      })
      .catch((err: any) => realFail(err, 'Failed to create tenant.'));
  };

  const toggleRealTenant = (t: any) => {
    platformAPI.toggleTenant(t.id, !t.is_active)
      .then(() => loadRealTenants())
      .catch((err: any) => realFail(err, 'Failed to update tenant status.'));
  };

  const deleteRealTenant = (t: any) => {
    if (!window.confirm(`Delete tenant "${t.name}"? This permanently removes all of its users, agents, and data.`)) return;
    platformAPI.deleteTenant(t.id)
      .then(() => { if (selectedRealTenant?.id === t.id) setSelectedRealTenant(null); loadRealTenants(); })
      .catch((err: any) => realFail(err, 'Failed to delete tenant.'));
  };

  const selectRealTenant = (t: any) => {
    setSelectedRealTenant(t);
    platformAPI.getTenantDomains(t.id)
      .then(r => setRealTenantDomains(Array.isArray(r.data) ? r.data : []))
      .catch((err: any) => realFail(err, 'Failed to load domains.'));
  };

  const addRealDomain = () => {
    if (!selectedRealTenant || !newDomain.trim()) return;
    platformAPI.addTenantDomain(selectedRealTenant.id, newDomain.trim())
      .then(() => { setNewDomain(''); return platformAPI.getTenantDomains(selectedRealTenant.id); })
      .then(r => setRealTenantDomains(Array.isArray(r.data) ? r.data : []))
      .catch((err: any) => realFail(err, 'Failed to add domain (it may already be mapped to a tenant).'));
  };

  const deleteRealDomain = (domainId: number) => {
    if (!selectedRealTenant) return;
    platformAPI.deleteTenantDomain(selectedRealTenant.id, domainId)
      .then(() => platformAPI.getTenantDomains(selectedRealTenant.id))
      .then(r => setRealTenantDomains(Array.isArray(r.data) ? r.data : []))
      .catch((err: any) => realFail(err, 'Failed to remove domain.'));
  };

  const loadAll = useCallback(async () => {
    const [dash, tList, anal, ph, aud, rpts, caps] = await Promise.all([
      tneAPI.getDashboard(),
      tneAPI.getTenants(),
      tneAPI.getAnalytics(),
      tneAPI.getPlatformHealth(),
      tneAPI.getAudit(),
      tneAPI.getReports(),
      platformAPI.getCapabilities().catch(() => ({ data: null })),
    ]);
    setDashboard(dash.data);
    setTenants(Array.isArray(tList.data) ? tList.data : []);
    setAnalytics(anal.data);
    setPlatformHealth(ph.data);
    setAudit(Array.isArray(aud.data) ? aud.data : []);
    setReports(rpts.data);
    setCapabilities(caps.data);
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  const loadTenantDetail = async (ref: string) => {
    const [detail, mods, res, usage, billing] = await Promise.all([
      tneAPI.getTenantDetail(ref),
      tneAPI.getModules(ref),
      tneAPI.getResources(ref),
      tneAPI.getTenantUsage(ref),
      tneAPI.getBilling(ref),
    ]);
    setTenantDetail(detail.data);
    setTenantModules(Array.isArray(mods.data) ? mods.data : []);
    const resData = res.data ?? {};
    setTenantResources(resData);
    setResourceForm(resData);
    setTenantUsage(usage.data);
    setTenantBilling(billing.data);
    if (detail.data) setConfigForm(detail.data);
  };

  const selectTenant = (t: any) => {
    setSelectedTenant(t);
    loadTenantDetail(t.tenant_ref);
  };

  const filteredTenants = tenants.filter(t => {
    const matchSearch = !search ||
      t.tenant_name?.toLowerCase().includes(search.toLowerCase()) ||
      t.domain?.toLowerCase().includes(search.toLowerCase());
    const matchStatus = !statusFilter || t.status === statusFilter;
    const matchPlan   = !planFilter   || t.plan   === planFilter;
    return matchSearch && matchStatus && matchPlan;
  });

  const saveConfig = async () => {
    if (!selectedTenant) return;
    setSaving(true);
    try {
      await tneAPI.updateTenant(selectedTenant.tenant_ref, configForm);
      setMsg('Tenant configuration saved.');
      loadAll();
    } finally { setSaving(false); setTimeout(() => setMsg(''), 3000); }
  };

  const saveResources = async () => {
    if (!selectedTenant) return;
    setSaving(true);
    try {
      await tneAPI.updateResources(selectedTenant.tenant_ref, resourceForm);
      setMsg('Resource limits saved.');
    } finally { setSaving(false); setTimeout(() => setMsg(''), 3000); }
  };

  const toggleModule = async (moduleId: string, enabled: boolean) => {
    if (!selectedTenant) return;
    await tneAPI.updateModule(selectedTenant.tenant_ref, { module: moduleId, enabled });
    const mods = await tneAPI.getModules(selectedTenant.tenant_ref);
    setTenantModules(Array.isArray(mods.data) ? mods.data : []);
  };

  const toggleSaasMode = async () => {
    if (!capabilities) return;
    setModeToggling('saas');
    try {
      const r = await platformAPI.setSaasMode(!capabilities.saas_mode);
      setCapabilities((p: any) => ({ ...p, saas_mode: r.data?.saas_mode ?? !p.saas_mode }));
      setMsg(r.data?.message ?? 'SaaS mode updated.');
    } finally { setModeToggling(null); setTimeout(() => setMsg(''), 3000); }
  };

  const toggleLicenseMode = async () => {
    if (!capabilities) return;
    setModeToggling('license');
    try {
      const r = await platformAPI.setLicenseMode(!capabilities.license_mode);
      setCapabilities((p: any) => ({ ...p, license_mode: r.data?.license_mode ?? !p.license_mode }));
      setMsg(r.data?.message ?? 'License mode updated.');
    } finally { setModeToggling(null); setTimeout(() => setMsg(''), 3000); }
  };

  const changeStatus = async (ref: string, status: string) => {
    await tneAPI.updateStatus(ref, status);
    loadAll();
    if (selectedTenant?.tenant_ref === ref) loadTenantDetail(ref);
  };

  const createTenant = async () => {
    await tneAPI.createTenant(newTenant);
    setShowCreate(false);
    setNewTenant({ tenant_name: '', org_name: '', domain: '', admin_email: '', plan: 'professional', region: 'us-east-1' });
    loadAll();
  };

  const askAI = async (action?: string) => {
    setAiLoading(true);
    setAiResponse('');
    try {
      const r = await tneAPI.askAI({
        action: action ?? 'health_summary',
        tenant_ref: selectedTenant?.tenant_ref,
        message: aiInput,
      });
      setAiResponse(r.data?.response ?? '');
    } finally { setAiLoading(false); }
  };

  const switchTab = (t: string) => {
    setTab(t);
    setSection(DEFAULT_SECTION[t]);
  };

  // ── section renderer ────────────────────────────────────────────────────────

  const renderSection = () => {
    switch (section) {

      // ── DASHBOARD ──────────────────────────────────────────────────────────
      case 'overview': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <MetricCard label="Total Tenants"   value={dashboard?.total_tenants ?? '—'} />
            <MetricCard label="Active"          value={dashboard?.active_tenants ?? '—'} />
            <MetricCard label="Enterprise"      value={dashboard?.enterprise_tenants ?? '—'} />
            <MetricCard label="Trial"           value={dashboard?.trial_tenants ?? '—'} />
            <MetricCard label="Suspended"       value={dashboard?.suspended_tenants ?? '—'} />
            <MetricCard label="Total Agents"    value={(dashboard?.total_agents ?? 0).toLocaleString()} />
            <MetricCard label="Platform EPS"    value={(dashboard?.platform_eps ?? 0).toLocaleString()} />
            <MetricCard label="Monthly Revenue" value={`$${((dashboard?.monthly_revenue_usd ?? 0) / 1000).toFixed(0)}k`} />
          </div>

          <div style={{ display: 'flex', gap: 16 }}>
            <div style={{ flex: 2 }}>
              <SectionCard title="Recent Tenants" padded={false}>
                <DataTable<any>
                  rows={dashboard?.recent_tenants ?? []}
                  rowKey={(t: any) => t.tenant_ref}
                  onRowClick={t => { switchTab('tenants'); selectTenant(t); }}
                  columns={[
                    { key: 'tenant_name', header: 'Tenant', render: (t: any) => (
                      <div>
                        <div style={{ fontWeight: 600 }}>{t.tenant_name}</div>
                        <div style={{ color: 'var(--text-3)', fontSize: 11 }}>{t.org_name}</div>
                      </div>
                    ) },
                    { key: 'plan', header: 'Plan', render: (t: any) => pill(t.plan, t.plan) },
                    { key: 'region', header: 'Region', render: (t: any) => <span style={{ color: 'var(--text-2)', fontSize: 12 }}>{t.region}</span> },
                    { key: 'status', header: 'Status', render: (t: any) => pill(t.status) },
                    { key: 'created_at', header: 'Created', render: (t: any) => <span style={{ color: 'var(--text-3)', fontSize: 12 }}>{t.created_at?.slice(0, 10)}</span> },
                  ]}
                />
              </SectionCard>
            </div>

            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <SectionCard title="Platform Health">
                <div style={{ display: 'flex', gap: 12 }}>
                  {([['Healthy', dashboard?.healthy_tenants ?? 0, '#16a34a'],
                     ['Degraded', dashboard?.degraded_tenants ?? 0, '#d97706'],
                     ['Critical', dashboard?.critical_tenants ?? 0, '#dc2626']] as [string, number, string][]).map(([l, v, c]) => (
                    <div key={l} style={{ flex: 1, textAlign: 'center', padding: 12, background: c + '11', borderRadius: 'var(--radius-md)' }}>
                      <div style={{ color: c, fontSize: 20, fontWeight: 700 }}>{v}</div>
                      <div style={{ color: 'var(--text-3)', fontSize: 11 }}>{l}</div>
                    </div>
                  ))}
                </div>
              </SectionCard>
              <SectionCard title="Plan Breakdown">
                {(dashboard?.plan_breakdown ?? []).map((p: any) => (
                  <div key={p.plan} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '4px 0' }}>
                    {pill(p.plan, p.plan)}
                    <span style={{ color: 'var(--text-2)', fontWeight: 600 }}>{p.count}</span>
                  </div>
                ))}
              </SectionCard>
            </div>
          </div>

          <SectionCard title="License Utilization">
            <div style={{ background: 'var(--bg-2)', borderRadius: 'var(--radius-md)', height: 14, overflow: 'hidden' }}>
              <div style={{
                background: 'var(--accent)', borderRadius: 'var(--radius-md)',
                width: `${dashboard?.license_utilization_pct ?? 0}%`,
                height: '100%', transition: 'width .4s',
              }} />
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-3)', fontSize: 11, marginTop: 4 }}>
              <span>Used: {dashboard?.license_utilization_pct ?? 0}%</span>
              <span>Remaining: {100 - (dashboard?.license_utilization_pct ?? 0)}%</span>
            </div>
          </SectionCard>
        </div>
      );

      // ── TENANT DIRECTORY ───────────────────────────────────────────────────
      case 'directory': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <input className="g-input" placeholder="Search tenants…" value={search}
              onChange={e => setSearch(e.target.value)} style={{ width: 200 }} />
            <select className="g-input" value={statusFilter} onChange={e => setStatusFilter(e.target.value)} style={{ width: 120 }}>
              <option value="">All Status</option>
              <option value="active">Active</option>
              <option value="trial">Trial</option>
              <option value="suspended">Suspended</option>
            </select>
            <select className="g-input" value={planFilter} onChange={e => setPlanFilter(e.target.value)} style={{ width: 160 }}>
              <option value="">All Plans</option>
              <option value="community">Community</option>
              <option value="professional">Professional</option>
              <option value="enterprise">Enterprise</option>
              <option value="enterprise_plus">Enterprise Plus</option>
            </select>
            <div style={{ flex: 1 }} />
            <ActionButton variant="primary" icon={Plus} onClick={() => setShowCreate(true)}>New Tenant</ActionButton>
          </div>

          {showCreate && (
            <SectionCard title="Create Tenant">
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                {([['tenant_name','Tenant Name'],['org_name','Organization Name'],['domain','Domain'],['admin_email','Admin Email']] as [string,string][]).map(([k, l]) => (
                  <div key={k}>
                    <label style={{ color: 'var(--text-2)', fontSize: 12 }}>{l}</label>
                    <input className="g-input" style={{ width: '100%', marginTop: 4 }}
                      value={(newTenant as any)[k] ?? ''}
                      onChange={e => setNewTenant(p => ({ ...p, [k]: e.target.value }))} />
                  </div>
                ))}
                <div>
                  <label style={{ color: 'var(--text-2)', fontSize: 12 }}>Plan</label>
                  <select className="g-input" style={{ width: '100%', marginTop: 4 }}
                    value={newTenant.plan} onChange={e => setNewTenant(p => ({ ...p, plan: e.target.value }))}>
                    <option value="community">Community</option>
                    <option value="professional">Professional</option>
                    <option value="enterprise">Enterprise</option>
                    <option value="enterprise_plus">Enterprise Plus</option>
                  </select>
                </div>
                <div>
                  <label style={{ color: 'var(--text-2)', fontSize: 12 }}>Region</label>
                  <select className="g-input" style={{ width: '100%', marginTop: 4 }}
                    value={newTenant.region} onChange={e => setNewTenant(p => ({ ...p, region: e.target.value }))}>
                    <option value="us-east-1">US East 1</option>
                    <option value="us-west-2">US West 2</option>
                    <option value="eu-west-1">EU West 1</option>
                    <option value="eu-central-1">EU Central 1</option>
                    <option value="ap-southeast-1">AP Southeast 1</option>
                    <option value="us-gov-east-1">US GovCloud East</option>
                  </select>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
                <ActionButton variant="primary" icon={Plus} onClick={createTenant}>Create Tenant</ActionButton>
                <ActionButton variant="ghost" icon={X} onClick={() => setShowCreate(false)}>Cancel</ActionButton>
              </div>
            </SectionCard>
          )}

          <DataTable<any>
            rows={filteredTenants}
            rowKey={(t: any) => t.tenant_ref}
            onRowClick={t => selectTenant(t)}
            rowStyle={(t: any) => selectedTenant?.tenant_ref === t.tenant_ref ? { background: 'var(--accent-glow)' } : undefined}
            emptyState={<EmptyState title="No tenants match filters" />}
            columns={[
              { key: 'tenant_name', header: 'Tenant', render: (t: any) => (
                <div>
                  <div style={{ fontWeight: 600, color: 'var(--text-1)' }}>{t.tenant_name}</div>
                  <div style={{ color: 'var(--text-3)', fontSize: 11 }}>{t.org_name}</div>
                  <div style={{ color: 'var(--text-3)', fontSize: 10, fontFamily: 'monospace' }}>{t.tenant_ref}</div>
                </div>
              ) },
              { key: 'domain', header: 'Domain', render: (t: any) => <span style={{ color: 'var(--text-2)', fontSize: 12 }}>{t.domain ?? '—'}</span> },
              { key: 'plan', header: 'Plan', render: (t: any) => pill(t.plan, t.plan) },
              { key: 'region', header: 'Region', render: (t: any) => <span style={{ color: 'var(--text-2)', fontSize: 12 }}>{t.region}</span> },
              { key: 'status', header: 'Status', render: (t: any) => pill(t.status) },
              { key: 'last_activity_at', header: 'Last Active', render: (t: any) => <span style={{ color: 'var(--text-3)', fontSize: 11 }}>{t.last_activity_at?.slice(0, 10) ?? '—'}</span> },
              { key: 'actions', header: 'Actions', render: (t: any) => (
                <div style={{ display: 'flex', gap: 6 }} onClick={e => e.stopPropagation()}>
                  {t.status !== 'active' && (
                    <ActionButton variant="ghost" icon={CheckCircle2} style={{ fontSize: 11, padding: '2px 8px' }}
                      onClick={() => changeStatus(t.tenant_ref, 'active')}>Activate</ActionButton>
                  )}
                  {t.status === 'active' && (
                    <ActionButton variant="danger" icon={Ban} style={{ fontSize: 11, padding: '2px 8px' }}
                      onClick={() => changeStatus(t.tenant_ref, 'suspended')}>Suspend</ActionButton>
                  )}
                </div>
              ) },
            ]}
          />

          {selectedTenant && (
            <div className="g-card" style={{ padding: 20, borderLeft: '3px solid var(--accent)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ fontWeight: 700, fontSize: 15, color: 'var(--text-1)' }}>{selectedTenant.tenant_name}</div>
                  <div style={{ color: 'var(--text-2)', fontSize: 12, marginTop: 2 }}>{selectedTenant.org_name} · {selectedTenant.domain}</div>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  {pill(selectedTenant.plan, selectedTenant.plan)}
                  {pill(selectedTenant.status)}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 24, marginTop: 12, flexWrap: 'wrap' }}>
                {([
                  ['Region', selectedTenant.region],
                  ['Admin', selectedTenant.primary_admin ?? '—'],
                  ['Email', selectedTenant.admin_email ?? '—'],
                  ['Contract End', selectedTenant.contract_end ?? '—'],
                  ['Renewal', selectedTenant.renewal_date ?? '—'],
                ] as [string, string][]).map(([l, v]) => (
                  <div key={l}>
                    <div style={{ color: 'var(--text-3)', fontSize: 10, textTransform: 'uppercase' }}>{l}</div>
                    <div style={{ color: 'var(--text-1)', fontSize: 13, marginTop: 1 }}>{v}</div>
                  </div>
                ))}
              </div>
              <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
                <ActionButton variant="ghost" icon={Pencil} style={{ fontSize: 12 }} onClick={() => setSection('config')}>Edit Config</ActionButton>
                <ActionButton variant="ghost" icon={Blocks} style={{ fontSize: 12 }} onClick={() => { switchTab('licenses'); setSection('modules'); }}>Modules</ActionButton>
                <ActionButton variant="ghost" icon={Gauge} style={{ fontSize: 12 }} onClick={() => { switchTab('usage'); setSection('resources'); }}>Resources</ActionButton>
                <ActionButton variant="ghost" icon={CreditCard} style={{ fontSize: 12 }} onClick={() => { switchTab('usage'); setSection('billing'); }}>Billing</ActionButton>
              </div>
            </div>
          )}
        </div>
      );

      // ── TENANT CONFIGURATION ───────────────────────────────────────────────
      case 'config': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {!selectedTenant ? (
            <SelectTenantPrompt onGo={() => setSection('directory')} />
          ) : (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Configure — {selectedTenant.tenant_name}</h2>
                {msg && <span style={{ color: 'var(--green)', fontSize: 13 }}>{msg}</span>}
              </div>

              {([
                { title: 'Identity', fields: [['tenant_name','Tenant Name'],['org_name','Organization Name'],['domain','Primary Domain'],['custom_domain','Custom Domain']] },
                { title: 'Administration', fields: [['primary_admin','Primary Admin'],['admin_email','Admin Email'],['region','Region'],['timezone','Timezone']] },
                { title: 'Branding', fields: [['logo_url','Logo URL'],['color_theme','Brand Color (#hex)'],['language','Language'],['date_format','Date Format']] },
                { title: 'Contract', fields: [['contract_start','Contract Start'],['contract_end','Contract End'],['renewal_date','Renewal Date'],['notes','Notes']] },
              ] as { title: string; fields: [string,string][] }[]).map(sec => (
                <SectionCard key={sec.title} title={sec.title}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                    {sec.fields.map(([k, l]) => (
                      <div key={k}>
                        <label style={{ color: 'var(--text-2)', fontSize: 12 }}>{l}</label>
                        <input className="g-input" style={{ width: '100%', marginTop: 4 }}
                          value={(configForm as any)[k] ?? ''}
                          onChange={e => setConfigForm((p: any) => ({ ...p, [k]: e.target.value }))} />
                      </div>
                    ))}
                  </div>
                </SectionCard>
              ))}

              <SectionCard title="Plan & Status">
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
                  <div>
                    <label style={{ color: 'var(--text-2)', fontSize: 12 }}>Plan</label>
                    <select className="g-input" style={{ width: '100%', marginTop: 4 }}
                      value={configForm.plan ?? ''} onChange={e => setConfigForm((p: any) => ({ ...p, plan: e.target.value }))}>
                      <option value="community">Community</option>
                      <option value="professional">Professional</option>
                      <option value="enterprise">Enterprise</option>
                      <option value="enterprise_plus">Enterprise Plus</option>
                    </select>
                  </div>
                  <div>
                    <label style={{ color: 'var(--text-2)', fontSize: 12 }}>Status</label>
                    <select className="g-input" style={{ width: '100%', marginTop: 4 }}
                      value={configForm.status ?? ''} onChange={e => setConfigForm((p: any) => ({ ...p, status: e.target.value }))}>
                      <option value="active">Active</option>
                      <option value="trial">Trial</option>
                      <option value="suspended">Suspended</option>
                    </select>
                  </div>
                  <div>
                    <label style={{ color: 'var(--text-2)', fontSize: 12 }}>License Type</label>
                    <select className="g-input" style={{ width: '100%', marginTop: 4 }}
                      value={configForm.license_type ?? ''} onChange={e => setConfigForm((p: any) => ({ ...p, license_type: e.target.value }))}>
                      <option value="subscription">Subscription</option>
                      <option value="perpetual">Perpetual</option>
                      <option value="trial">Trial</option>
                    </select>
                  </div>
                </div>
              </SectionCard>

              <div style={{ display: 'flex', gap: 8 }}>
                <ActionButton variant="primary" icon={Save} onClick={saveConfig} disabled={saving}>
                  {saving ? 'Saving…' : 'Save Configuration'}
                </ActionButton>
                <ActionButton variant="ghost" icon={RotateCcw} onClick={() => setConfigForm(tenantDetail ?? selectedTenant)}>Reset</ActionButton>
              </div>
            </>
          )}
        </div>
      );

      // ── LIVE TENANTS ────────────────────────────────────────────────────────
      case 'live': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Live Tenants</h2>
              <p style={{ margin: '2px 0 0', color: 'var(--text-3)', fontSize: 12 }}>
                This deployment&apos;s actual tenants — real accounts with real data, isolated by tenant_id.
                Suspending or deleting here takes effect immediately.
              </p>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              {realMsg && <span style={{ color: 'var(--text-2)', fontSize: 12 }}>{realMsg}</span>}
              <ActionButton variant="primary" icon={Plus} onClick={() => setShowCreateReal(true)}>New Tenant</ActionButton>
            </div>
          </div>

          {showCreateReal && (
            <SectionCard title="Create Tenant">
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                {([['name','Name'],['slug','Slug'],['admin_username','Admin Username'],['admin_email','Admin Email']] as [string,string][]).map(([k, l]) => (
                  <div key={k}>
                    <label style={{ color: 'var(--text-2)', fontSize: 12 }}>{l}</label>
                    <input className="g-input" style={{ width: '100%', marginTop: 4 }}
                      value={(newRealTenant as any)[k] ?? ''}
                      onChange={e => setNewRealTenant(p => ({ ...p, [k]: e.target.value }))} />
                  </div>
                ))}
              </div>
              <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
                <ActionButton variant="primary" icon={Plus}
                  disabled={!newRealTenant.name || !newRealTenant.slug || !newRealTenant.admin_username || !newRealTenant.admin_email}
                  onClick={createRealTenant}>Create Tenant</ActionButton>
                <ActionButton variant="ghost" icon={X} onClick={() => setShowCreateReal(false)}>Cancel</ActionButton>
              </div>
            </SectionCard>
          )}

          <SectionCard padded={false}>
            <DataTable<any>
              rows={realTenants}
              rowKey={(t: any) => t.id}
              onRowClick={t => selectRealTenant(t)}
              rowStyle={(t: any) => selectedRealTenant?.id === t.id ? { background: 'var(--accent-glow)' } : undefined}
              emptyState={<EmptyState title="No tenants" />}
              columns={[
                { key: 'name', header: 'Tenant', render: (t: any) => (
                  <div>
                    <div style={{ fontWeight: 600, color: 'var(--text-1)' }}>{t.name}</div>
                    <div style={{ color: 'var(--text-3)', fontSize: 11, fontFamily: 'monospace' }}>{t.slug}</div>
                  </div>
                ) },
                { key: 'user_count', header: 'Users', render: (t: any) => <span>{t.user_count ?? 0}</span> },
                { key: 'is_active', header: 'Status', render: (t: any) => t.is_active ? pill('active') : pill('suspended') },
                { key: 'created_at', header: 'Created', render: (t: any) => <span style={{ color: 'var(--text-3)', fontSize: 12 }}>{t.created_at?.slice(0, 10)}</span> },
                { key: 'actions', header: 'Actions', render: (t: any) => (
                  <div style={{ display: 'flex', gap: 6 }} onClick={e => e.stopPropagation()}>
                    {t.is_active ? (
                      <ActionButton variant="danger" icon={Ban} style={{ fontSize: 11, padding: '2px 8px' }}
                        onClick={() => toggleRealTenant(t)}>Suspend</ActionButton>
                    ) : (
                      <ActionButton variant="ghost" icon={CheckCircle2} style={{ fontSize: 11, padding: '2px 8px' }}
                        onClick={() => toggleRealTenant(t)}>Activate</ActionButton>
                    )}
                    {t.id !== 1 && (
                      <ActionButton variant="danger" icon={Trash2} style={{ fontSize: 11, padding: '2px 8px' }}
                        onClick={() => deleteRealTenant(t)}>Delete</ActionButton>
                    )}
                  </div>
                ) },
              ]}
            />
          </SectionCard>

          {selectedRealTenant && (
            <SectionCard title={`Domains — ${selectedRealTenant.name}`} subtitle="Mapping a domain routes logins from that domain to this tenant.">
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {realTenantDomains.length === 0 && (
                  <div style={{ color: 'var(--text-3)', fontSize: 12 }}>No domains mapped.</div>
                )}
                {realTenantDomains.map((d: any) => (
                  <div key={d.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '4px 0' }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}><Globe size={13} /> {d.domain}</span>
                    <ActionButton variant="ghost" icon={X} style={{ fontSize: 11, padding: '2px 8px' }}
                      onClick={() => deleteRealDomain(d.id)}>Remove</ActionButton>
                  </div>
                ))}
                <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                  <input className="g-input" placeholder="acme.com" style={{ flex: 1 }}
                    value={newDomain} onChange={e => setNewDomain(e.target.value)}
                    onKeyDown={e => { if (e.key === 'Enter') addRealDomain(); }} />
                  <ActionButton variant="primary" icon={Plus} onClick={addRealDomain}>Add Domain</ActionButton>
                </div>
              </div>
            </SectionCard>
          )}
        </div>
      );

      // ── DATA ISOLATION ─────────────────────────────────────────────────────
      case 'isolation': return (
        <SectionCard title="Data Isolation Policies" subtitle="What this deployment actually enforces today — not an aspirational architecture diagram.">
          {[
            ['Database Scoping',           'Application-level tenant_id filter on every query, across all 286 tenant-scoped tables'],
            ['Row-Level Security (RLS)',   'Enabled on 6 sensitive tables (alerts, incidents, iocs, sigma_rules, …); the rest rely on the app-level filter above, not DB-enforced RLS'],
            ['API Namespace Enforcement',  'JWT tenant_id claim set by RequireAuth/RequireAgentAuth and read on every handler via tenantIDFromContext'],
            ['Log Storage',                'Shared Elasticsearch index (xcloak-logs-*) — isolation is by tenant_id field filter, not a separate index per tenant'],
            ['Audit Log Storage',          'Written to MinIO object storage (shared bucket, not per-tenant)'],
            ['Backups',                    'Single pg_dump of the shared database — not a per-tenant snapshot; a restore affects every tenant'],
            ['Encryption at Rest',         'Not implemented — no per-tenant data key or KMS integration exists in this deployment'],
          ].map(([label, value]) => (
            <div key={label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
              <div style={{ color: 'var(--text-2)', fontSize: 13, width: '30%' }}>{label}</div>
              <div style={{ color: 'var(--text-1)', fontSize: 12, width: '67%', textAlign: 'right', lineHeight: 1.5 }}>{value}</div>
            </div>
          ))}
        </SectionCard>
      );

      // ── DEPLOYMENT MODE ────────────────────────────────────────────────────
      case 'deployment': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Deployment Mode</h2>
            {msg && <span style={{ color: 'var(--green)', fontSize: 13 }}>{msg}</span>}
          </div>

          {!capabilities ? (
            <SectionCard>
              <div style={{ textAlign: 'center', padding: 12, color: 'var(--text-3)' }}>Loading…</div>
            </SectionCard>
          ) : !capabilities.is_authority ? (
            <SectionCard>
              <p style={{ margin: 0, color: 'var(--text-2)', fontSize: 13, lineHeight: 1.6 }}>
                This is a self-hosted customer instance. Deployment mode — SaaS billing enforcement and
                license enforcement — is controlled centrally by the platform authority and can&apos;t be
                changed from here.
              </p>
            </SectionCard>
          ) : (
            <>
              <p style={{ margin: 0, color: 'var(--text-3)', fontSize: 13 }}>
                This instance holds the license signing key — it is the platform authority. These switches
                affect every tenant on this deployment.
              </p>

              <SectionCard>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 20 }}>
                  <div>
                    <h3 style={{ margin: '0 0 4px', color: 'var(--text-1)', fontSize: 14 }}>SaaS Mode</h3>
                    <p style={{ margin: 0, color: 'var(--text-3)', fontSize: 12, maxWidth: 460 }}>
                      When on, subscription billing is enforced on hosted tenants (plan limits, unpaid suspension).
                      When off, all tenants get full free access.
                    </p>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
                    {capabilities.saas_mode ? pill('enabled', '#16a34a') : pill('disabled', '#6b7280')}
                    <ActionButton
                      variant={capabilities.saas_mode ? 'primary' : 'ghost'}
                      icon={Power}
                      style={{ fontSize: 12, padding: '4px 14px', minWidth: 90 }}
                      disabled={modeToggling === 'saas'}
                      onClick={toggleSaasMode}>
                      {modeToggling === 'saas' ? '…' : capabilities.saas_mode ? 'Turn Off' : 'Turn On'}
                    </ActionButton>
                  </div>
                </div>
              </SectionCard>

              <SectionCard>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 20 }}>
                  <div>
                    <h3 style={{ margin: '0 0 4px', color: 'var(--text-1)', fontSize: 14 }}>Self-Hosted License Mode</h3>
                    <p style={{ margin: 0, color: 'var(--text-3)', fontSize: 12, maxWidth: 460 }}>
                      When on, self-hosted instances must present a valid license key to keep full functionality
                      (checked every 24h, 30-day grace period on failure). When off, self-hosted is fully open.
                    </p>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
                    {capabilities.license_mode ? pill('enabled', '#16a34a') : pill('disabled', '#6b7280')}
                    <ActionButton
                      variant={capabilities.license_mode ? 'primary' : 'ghost'}
                      icon={Power}
                      style={{ fontSize: 12, padding: '4px 14px', minWidth: 90 }}
                      disabled={modeToggling === 'license'}
                      onClick={toggleLicenseMode}>
                      {modeToggling === 'license' ? '…' : capabilities.license_mode ? 'Turn Off' : 'Turn On'}
                    </ActionButton>
                  </div>
                </div>
              </SectionCard>
            </>
          )}
        </div>
      );

      // ── USERS & RBAC ───────────────────────────────────────────────────────
      case 'rbac': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {!selectedTenant ? (
            <SelectTenantPrompt onGo={() => { switchTab('tenants'); setSection('directory'); }} label="to manage users" />
          ) : (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Users & RBAC — {selectedTenant.tenant_name}</h2>
                {pill(selectedTenant.plan, selectedTenant.plan)}
              </div>

              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                <MetricCard label="Active Users"   value={tenantUsage?.current?.active_users ?? '—'} />
                <MetricCard label="Max Users"      value={tenantResources?.max_users ?? '—'} sub="license limit" />
                <MetricCard label="MFA Coverage"   value="92%" />
                <MetricCard label="SSO"            value={selectedTenant.plan !== 'community' ? 'Configured' : 'Not Available'} />
              </div>

              <SectionCard title="Tenant Administrators">
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  <div>
                    <div style={{ color: 'var(--text-3)', fontSize: 11, textTransform: 'uppercase' }}>Primary Admin</div>
                    <div style={{ color: 'var(--text-1)', marginTop: 4, fontWeight: 500 }}>{selectedTenant.primary_admin ?? '—'}</div>
                  </div>
                  <div>
                    <div style={{ color: 'var(--text-3)', fontSize: 11, textTransform: 'uppercase' }}>Admin Email</div>
                    <div style={{ color: 'var(--text-1)', marginTop: 4 }}>{selectedTenant.admin_email ?? '—'}</div>
                  </div>
                </div>
              </SectionCard>

              <SectionCard title="RBAC Roles" padded={false}>
                <DataTable<any>
                  rows={[
                    { role: 'Platform Admin', users: 1, perms: 'Full platform access' },
                    { role: 'SOC Manager', users: 3, perms: 'All SIEM, cases, playbooks, reports' },
                    { role: 'SOC Analyst', users: 12, perms: 'SIEM, alerts, cases, threat intel' },
                    { role: 'Threat Hunter', users: 2, perms: 'SIEM, EDR, threat intel, scripts' },
                    { role: 'Compliance Auditor', users: 2, perms: 'Reports, compliance, read-only' },
                    { role: 'Read Only', users: 4, perms: 'Dashboards and reports only' },
                  ]}
                  rowKey={(r: any) => r.role}
                  columns={[
                    { key: 'role', header: 'Role', render: (r: any) => <span style={{ fontWeight: 500 }}>{r.role}</span> },
                    { key: 'users', header: 'Users', render: (r: any) => <span style={{ color: 'var(--text-2)' }}>{r.users}</span> },
                    { key: 'perms', header: 'Permissions', render: (r: any) => <span style={{ color: 'var(--text-3)', fontSize: 12 }}>{r.perms}</span> },
                  ]}
                />
              </SectionCard>
            </>
          )}
        </div>
      );

      // ── MODULE MANAGEMENT ──────────────────────────────────────────────────
      case 'modules': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {!selectedTenant ? (
            <SelectTenantPrompt onGo={() => { switchTab('tenants'); setSection('directory'); }} label="to manage modules" />
          ) : (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Module Management — {selectedTenant.tenant_name}</h2>
                {pill(selectedTenant.plan, selectedTenant.plan)}
              </div>
              <SectionCard padded={false}>
                <DataTable<any>
                  rows={ALL_MODULES}
                  rowKey={(m: any) => m.id}
                  columns={[
                    { key: 'label', header: 'Module', render: (m: any) => <span style={{ fontWeight: 500 }}>{m.label}</span> },
                    { key: 'tier', header: 'Min Tier', render: (m: any) => pill(m.tier, m.tier) },
                    { key: 'status', header: 'Status', render: (m: any) => {
                      const state = tenantModules.find((x: any) => x.module === m.id);
                      const enabled = state?.enabled ?? false;
                      return enabled ? pill('enabled', '#16a34a') : pill('disabled', '#6b7280');
                    } },
                    { key: 'toggle', header: 'Toggle', render: (m: any) => {
                      const state = tenantModules.find((x: any) => x.module === m.id);
                      const enabled = state?.enabled ?? false;
                      return (
                        <ActionButton
                          variant={enabled ? 'primary' : 'ghost'}
                          icon={Power}
                          style={{ fontSize: 11, padding: '3px 12px', minWidth: 70 }}
                          onClick={() => toggleModule(m.id, !enabled)}>
                          {enabled ? 'Disable' : 'Enable'}
                        </ActionButton>
                      );
                    } },
                  ]}
                />
              </SectionCard>
            </>
          )}
        </div>
      );

      // ── RESOURCE ALLOCATION ────────────────────────────────────────────────
      case 'resources': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {!selectedTenant ? (
            <SelectTenantPrompt onGo={() => { switchTab('tenants'); setSection('directory'); }} label="to configure resources" />
          ) : (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Resource Allocation — {selectedTenant.tenant_name}</h2>
                {msg && <span style={{ color: 'var(--green)', fontSize: 13 }}>{msg}</span>}
              </div>
              <SectionCard>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                  {RESOURCE_FIELDS.map(f => (
                    <div key={f.key}>
                      <label style={{ color: 'var(--text-2)', fontSize: 12 }}>{f.label}</label>
                      <input className="g-input" type="number" style={{ width: '100%', marginTop: 4 }}
                        value={(resourceForm as any)[f.key] ?? ''}
                        onChange={e => setResourceForm((p: any) => ({ ...p, [f.key]: parseInt(e.target.value) || 0 }))} />
                    </div>
                  ))}
                </div>
              </SectionCard>
              <div style={{ display: 'flex', gap: 8 }}>
                <ActionButton variant="primary" icon={Save} onClick={saveResources} disabled={saving}>
                  {saving ? 'Saving…' : 'Save Resource Limits'}
                </ActionButton>
                <ActionButton variant="ghost" icon={RotateCcw} onClick={() => setResourceForm(tenantResources)}>Reset</ActionButton>
              </div>
            </>
          )}
        </div>
      );

      // ── SUBSCRIPTION & LICENSING ───────────────────────────────────────────
      case 'subscription': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {!selectedTenant ? (
            <SelectTenantPrompt onGo={() => { switchTab('tenants'); setSection('directory'); }} />
          ) : (
            <>
              <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Subscription & Licensing — {selectedTenant.tenant_name}</h2>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                <MetricCard label="Plan"            value={selectedTenant.plan?.replace('_', ' ').toUpperCase() ?? '—'} />
                <MetricCard label="License Type"    value={selectedTenant.license_type ?? '—'} />
                <MetricCard label="Contract Start"  value={selectedTenant.contract_start ?? '—'} />
                <MetricCard label="Contract End"    value={selectedTenant.contract_end ?? '—'} />
                <MetricCard label="Renewal Date"    value={selectedTenant.renewal_date ?? '—'} />
                <MetricCard label="Trial Ends"      value={selectedTenant.trial_ends_at?.slice(0, 10) ?? 'N/A'} />
              </div>
              <SectionCard title="Change Plan">
                <div style={{ display: 'flex', gap: 12, alignItems: 'flex-end' }}>
                  <div style={{ flex: 1 }}>
                    <label style={{ color: 'var(--text-2)', fontSize: 12 }}>New Plan</label>
                    <select className="g-input" style={{ width: '100%', marginTop: 4 }}
                      value={configForm.plan ?? selectedTenant.plan}
                      onChange={e => setConfigForm((p: any) => ({ ...p, plan: e.target.value }))}>
                      <option value="community">Community — Free</option>
                      <option value="professional">Professional — $1,200/mo</option>
                      <option value="enterprise">Enterprise — $4,500/mo</option>
                      <option value="enterprise_plus">Enterprise Plus — $9,000/mo</option>
                    </select>
                  </div>
                  <ActionButton variant="primary" icon={CheckCircle2} onClick={saveConfig} disabled={saving}>Apply</ActionButton>
                </div>
              </SectionCard>
            </>
          )}
        </div>
      );

      // ── BILLING ────────────────────────────────────────────────────────────
      case 'billing': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {!selectedTenant ? (
            <SelectTenantPrompt onGo={() => { switchTab('tenants'); setSection('directory'); }} />
          ) : (
            <>
              <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Billing — {selectedTenant.tenant_name}</h2>
              {tenantBilling && (
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                  <MetricCard label="Monthly Amount"  value={`$${(tenantBilling.monthly_amount_usd ?? 0).toLocaleString()}`} />
                  <MetricCard label="Next Invoice"    value={tenantBilling.next_invoice_date ?? '—'} />
                  <MetricCard label="Payment Method"  value={tenantBilling.payment_method ?? '—'} />
                  <MetricCard label="Auto-Renew"      value={tenantBilling.auto_renew ? 'Enabled' : 'Disabled'} />
                </div>
              )}
              <SectionCard title="Invoice History" padded={false}>
                <DataTable<any>
                  rows={tenantBilling?.invoices ?? []}
                  rowKey={(inv: any) => inv.invoice_id}
                  emptyState={<EmptyState title="No invoices found" />}
                  columns={[
                    { key: 'invoice_id', header: 'Invoice ID', render: (inv: any) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{inv.invoice_id}</span> },
                    { key: 'period', header: 'Period', render: (inv: any) => <span style={{ color: 'var(--text-2)' }}>{inv.period}</span> },
                    { key: 'amount_usd', header: 'Amount', render: (inv: any) => <span style={{ fontWeight: 600 }}>${(inv.amount_usd ?? 0).toLocaleString()}</span> },
                    { key: 'status', header: 'Status', render: (inv: any) => pill(inv.status) },
                    { key: 'due_date', header: 'Due Date', render: (inv: any) => <span style={{ color: 'var(--text-3)', fontSize: 12 }}>{inv.due_date ?? '—'}</span> },
                    { key: 'paid_date', header: 'Paid Date', render: (inv: any) => <span style={{ color: 'var(--text-3)', fontSize: 12 }}>{inv.paid_date ?? '—'}</span> },
                  ]}
                />
              </SectionCard>
            </>
          )}
        </div>
      );

      // ── USAGE ANALYTICS ────────────────────────────────────────────────────
      case 'analytics': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Platform Usage Analytics</h2>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <MetricCard label="Active Users"       value={(analytics?.totals?.active_users ?? 0).toLocaleString()} />
            <MetricCard label="Active Agents"      value={(analytics?.totals?.active_agents ?? 0).toLocaleString()} />
            <MetricCard label="Platform EPS"       value={(analytics?.totals?.total_eps ?? 0).toLocaleString()} />
            <MetricCard label="Total Storage"      value={`${analytics?.totals?.total_storage_tb ?? '—'} TB`} />
            <MetricCard label="AI Req / Month"     value={(analytics?.totals?.total_ai_requests_month ?? 0).toLocaleString()} />
          </div>

          <SectionCard title="Agent Growth (6 months)">
            <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end', height: 120 }}>
              {(analytics?.monthly_trend ?? []).map((m: any) => {
                const maxA = Math.max(...(analytics?.monthly_trend ?? []).map((x: any) => x.agents ?? 0), 1);
                const h = Math.max(Math.round((m.agents / maxA) * 90), 4);
                return (
                  <div key={m.month} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
                    <div style={{ color: 'var(--text-3)', fontSize: 9 }}>{m.agents}</div>
                    <div style={{ width: '100%', height: h, background: 'var(--accent)', borderRadius: '3px 3px 0 0', opacity: 0.85 }} />
                    <div style={{ color: 'var(--text-3)', fontSize: 9, textAlign: 'center' }}>{m.month?.slice(0, 3)}</div>
                  </div>
                );
              })}
            </div>
          </SectionCard>

          <SectionCard title="Per-Tenant Usage" padded={false}>
            <DataTable<any>
              rows={analytics?.tenants ?? []}
              rowKey={(t: any) => t.tenant_ref}
              columns={[
                { key: 'tenant_name', header: 'Tenant', render: (t: any) => <span style={{ fontWeight: 600 }}>{t.tenant_name}</span> },
                { key: 'plan', header: 'Plan', render: (t: any) => pill(t.plan, t.plan) },
                { key: 'active_users', header: 'Users', render: (t: any) => <span>{(t.active_users ?? 0).toLocaleString()}</span> },
                { key: 'active_agents', header: 'Agents', render: (t: any) => <span>{(t.active_agents ?? 0).toLocaleString()}</span> },
                { key: 'daily_log_volume', header: 'Daily Logs', render: (t: any) => (
                  <span style={{ color: 'var(--text-2)' }}>{t.daily_log_volume ? `${(t.daily_log_volume / 1e6).toFixed(1)}M` : '—'}</span>
                ) },
                { key: 'events_per_second', header: 'EPS', render: (t: any) => (
                  <span style={{ color: 'var(--text-2)' }}>{t.events_per_second ? t.events_per_second.toFixed(0) : '—'}</span>
                ) },
                { key: 'ai_requests', header: 'AI Req', render: (t: any) => <span>{(t.ai_requests ?? 0).toLocaleString()}</span> },
                { key: 'storage_used_gb', header: 'Storage (GB)', render: (t: any) => <span>{t.storage_used_gb ? t.storage_used_gb.toFixed(1) : '—'}</span> },
              ]}
            />
          </SectionCard>
        </div>
      );

      // ── TENANT HEALTH ──────────────────────────────────────────────────────
      case 'health': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Tenant Health Monitoring</h2>
          {platformHealth?.platform && (
            <SectionCard title="Platform Infrastructure" subtitle="Live signals only — availability/log-ingestion/API-latency have no probe wired up on this deployment, so they're omitted rather than shown as invented numbers.">
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                <MetricCard label="Database"            value={platformHealth.platform.database_health} />
                <MetricCard label="Storage Used"        value={`${platformHealth.platform.storage_capacity_pct}%`} />
                <MetricCard label="Total EPS"           value={(platformHealth.platform.total_eps ?? 0).toLocaleString()} />
                <MetricCard label="Agent Connectivity"  value={`${(platformHealth.platform.agent_connectivity_pct ?? 0).toFixed(1)}%`} />
              </div>
            </SectionCard>
          )}
          <SectionCard title="Tenant Health Status" padded={false}>
            <DataTable<any>
              rows={platformHealth?.tenants ?? []}
              rowKey={(t: any) => t.tenant_ref}
              onRowClick={t => { switchTab('tenants'); setSection('directory'); selectTenant(t); }}
              columns={[
                { key: 'tenant_name', header: 'Tenant', render: (t: any) => <span style={{ fontWeight: 600 }}>{t.tenant_name}</span> },
                { key: 'plan', header: 'Plan', render: (t: any) => pill(t.plan, t.plan) },
                { key: 'avg_score', header: 'Health Score', render: (t: any) => (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div style={{ flex: 1, height: 6, background: 'var(--bg-2)', borderRadius: 3, overflow: 'hidden', minWidth: 60 }}>
                      <div style={{
                        width: `${t.avg_score ?? 0}%`, height: '100%', borderRadius: 3,
                        background: (t.avg_score ?? 0) >= 90 ? '#16a34a' : (t.avg_score ?? 0) >= 70 ? '#d97706' : '#dc2626',
                      }} />
                    </div>
                    <span style={{ color: 'var(--text-2)', fontSize: 12, minWidth: 40 }}>{t.avg_score ?? 0}/100</span>
                  </div>
                ) },
                { key: 'critical_checks', header: 'Critical Checks', render: (t: any) => (
                  <span style={{ color: (t.critical_checks ?? 0) > 0 ? 'var(--red)' : 'var(--text-2)' }}>{t.critical_checks ?? 0}</span>
                ) },
                { key: 'status', header: 'Status', render: (t: any) => pill(t.status) },
              ]}
            />
          </SectionCard>
        </div>
      );

      // ── AI ASSISTANT ───────────────────────────────────────────────────────
      case 'ai': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Platform AI Assistant</h2>
          <SectionCard title="Quick Analysis">
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {AI_PROMPTS.map(p => (
                <ActionButton key={p.action} variant="ghost" icon={Wand2} style={{ fontSize: 12 }}
                  onClick={() => askAI(p.action)}>
                  {p.label}
                </ActionButton>
              ))}
            </div>
          </SectionCard>
          <SectionCard title="Ask the Platform AI">
            <div style={{ display: 'flex', gap: 8 }}>
              <input className="g-input" style={{ flex: 1 }}
                placeholder="Ask about tenant health, license optimization, capacity planning…"
                value={aiInput}
                onChange={e => setAiInput(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') askAI(); }} />
              <ActionButton variant="primary" icon={Send} onClick={() => askAI()} disabled={aiLoading}>
                {aiLoading ? 'Analyzing…' : 'Ask'}
              </ActionButton>
            </div>
          </SectionCard>
          {(aiLoading || aiResponse) && (
            <SectionCard>
              {aiLoading ? (
                <div style={{ color: 'var(--text-3)', fontSize: 13 }}>Analyzing platform data…</div>
              ) : (
                <pre style={{ margin: 0, fontFamily: 'monospace', whiteSpace: 'pre-wrap', fontSize: 13, color: 'var(--text-1)', lineHeight: 1.7 }}>
                  {aiResponse}
                </pre>
              )}
            </SectionCard>
          )}
        </div>
      );

      // ── AUDIT TRAIL ────────────────────────────────────────────────────────
      case 'audit': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Platform Audit Trail</h2>
          <SectionCard padded={false}>
            <DataTable<any>
              rows={audit}
              rowKey={(e: any, i: number) => i}
              emptyState={<EmptyState title="No audit entries" />}
              columns={[
                { key: 'created_at', header: 'Time', render: (e: any) => (
                  <span style={{ color: 'var(--text-3)', fontSize: 11, whiteSpace: 'nowrap' }}>{e.created_at?.slice(0, 19)?.replace('T', ' ')}</span>
                ) },
                { key: 'action', header: 'Action', render: (e: any) => <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--accent)' }}>{e.action}</span> },
                { key: 'object_id', header: 'Tenant', render: (e: any) => <span style={{ color: 'var(--text-2)', fontSize: 12 }}>{e.object_id ?? '—'}</span> },
                { key: 'actor', header: 'Actor', render: (e: any) => <span style={{ fontWeight: 500, fontSize: 12 }}>{e.actor}</span> },
                { key: 'details', header: 'Details', render: (e: any) => <span style={{ color: 'var(--text-3)', fontSize: 12, maxWidth: 280, display: 'block' }}>{e.details}</span> },
                { key: 'ip_address', header: 'IP', render: (e: any) => <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-3)' }}>{e.ip_address ?? '—'}</span> },
              ]}
            />
          </SectionCard>
        </div>
      );

      default: return null;
    }
  };

  // ── layout ──────────────────────────────────────────────────────────────────

  const sidebarItems = SIDEBAR[tab] ?? [];

  return (
    <RootLayout title="Platform" subtitle="Multi-tenant administration" onRefresh={loadAll}>
      <div className="space-y-4">
        {/* Top-level tabs */}
        <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: 2 }}>
          <TabBar tabs={TABS} active={tab} onChange={switchTab} />
        </div>

        {/* Sub-section tabs */}
        {sidebarItems.length > 1 && (
          <TabBar tabs={sidebarItems} active={section} onChange={setSection} />
        )}

        {DEMO_SECTIONS.has(section) && (
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12,
            padding: '8px 14px', background: 'var(--bg-2)', borderRadius: 'var(--radius-md)',
            color: 'var(--text-3)', fontSize: 12, border: '1px solid var(--border)',
          }}>
            <span>Reference data — a seeded demo dataset showcasing a multi-tenant console, not this deployment&apos;s real tenants.</span>
            <ActionButton variant="ghost" icon={Building2} style={{ fontSize: 11, padding: '2px 8px', flexShrink: 0 }}
              onClick={() => { switchTab('tenants'); setSection('live'); }}>View Live Tenants</ActionButton>
          </div>
        )}

        {renderSection()}
      </div>
    </RootLayout>
  );
}
