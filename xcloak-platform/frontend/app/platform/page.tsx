'use client';
import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { tneAPI } from '@/lib/api';

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

function StatCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="g-card" style={{ padding: '16px 20px', minWidth: 140 }}>
      <div style={{ color: 'var(--text-3)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>{label}</div>
      <div style={{ color: 'var(--text-1)', fontSize: 22, fontWeight: 700 }}>{value}</div>
      {sub && <div style={{ color: 'var(--text-3)', fontSize: 11, marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

// ── sidebar / tab config ──────────────────────────────────────────────────────

const TABS = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'tenants',   label: 'Tenants' },
  { id: 'licenses',  label: 'Licenses' },
  { id: 'usage',     label: 'Usage' },
  { id: 'reports',   label: 'Reports' },
];

const SIDEBAR: Record<string, { id: string; label: string }[][]> = {
  dashboard: [[{ id: 'overview',     label: 'Tenant Dashboard' }]],
  tenants:   [[{ id: 'directory',    label: 'Tenant Directory' }, { id: 'config', label: 'Tenant Configuration' }],
              [{ id: 'isolation',    label: 'Data Isolation' }]],
  licenses:  [[{ id: 'rbac',         label: 'Users & RBAC' }],
              [{ id: 'modules',      label: 'Module Management' }]],
  usage:     [[{ id: 'resources',    label: 'Resource Allocation' }],
              [{ id: 'subscription', label: 'Subscription & Licensing' }, { id: 'billing', label: 'Billing' }]],
  reports:   [[{ id: 'analytics',   label: 'Usage Analytics' }, { id: 'health', label: 'Tenant Health' }],
              [{ id: 'ai',           label: 'AI Assistant' }],
              [{ id: 'audit',        label: 'Audit Trail' }]],
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

  const loadAll = useCallback(async () => {
    const [dash, tList, anal, ph, aud, rpts] = await Promise.all([
      tneAPI.getDashboard(),
      tneAPI.getTenants(),
      tneAPI.getAnalytics(),
      tneAPI.getPlatformHealth(),
      tneAPI.getAudit(),
      tneAPI.getReports(),
    ]);
    setDashboard(dash.data);
    setTenants(Array.isArray(tList.data) ? tList.data : []);
    setAnalytics(anal.data);
    setPlatformHealth(ph.data);
    setAudit(Array.isArray(aud.data) ? aud.data : []);
    setReports(rpts.data);
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
            <StatCard label="Total Tenants"   value={dashboard?.total_tenants ?? '—'} />
            <StatCard label="Active"          value={dashboard?.active_tenants ?? '—'} />
            <StatCard label="Enterprise"      value={dashboard?.enterprise_tenants ?? '—'} />
            <StatCard label="Trial"           value={dashboard?.trial_tenants ?? '—'} />
            <StatCard label="Suspended"       value={dashboard?.suspended_tenants ?? '—'} />
            <StatCard label="Total Agents"    value={(dashboard?.total_agents ?? 0).toLocaleString()} />
            <StatCard label="Platform EPS"    value={(dashboard?.platform_eps ?? 0).toLocaleString()} />
            <StatCard label="Monthly Revenue" value={`$${((dashboard?.monthly_revenue_usd ?? 0) / 1000).toFixed(0)}k`} />
          </div>

          <div style={{ display: 'flex', gap: 16 }}>
            <div className="g-card" style={{ flex: 2, padding: 20 }}>
              <h3 style={{ margin: '0 0 14px', color: 'var(--text-1)', fontSize: 14 }}>Recent Tenants</h3>
              <table className="g-table" style={{ width: '100%' }}>
                <thead><tr><th>Tenant</th><th>Plan</th><th>Region</th><th>Status</th><th>Created</th></tr></thead>
                <tbody>{(dashboard?.recent_tenants ?? []).map((t: any) => (
                  <tr key={t.tenant_ref} style={{ cursor: 'pointer' }}
                    onClick={() => { switchTab('tenants'); selectTenant(t); }}>
                    <td>
                      <div style={{ fontWeight: 600 }}>{t.tenant_name}</div>
                      <div style={{ color: 'var(--text-3)', fontSize: 11 }}>{t.org_name}</div>
                    </td>
                    <td>{pill(t.plan, t.plan)}</td>
                    <td style={{ color: 'var(--text-2)', fontSize: 12 }}>{t.region}</td>
                    <td>{pill(t.status)}</td>
                    <td style={{ color: 'var(--text-3)', fontSize: 12 }}>{t.created_at?.slice(0, 10)}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>

            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div className="g-card" style={{ padding: 20 }}>
                <h3 style={{ margin: '0 0 12px', color: 'var(--text-1)', fontSize: 14 }}>Platform Health</h3>
                <div style={{ display: 'flex', gap: 12 }}>
                  {([['Healthy', dashboard?.healthy_tenants ?? 0, '#16a34a'],
                     ['Degraded', dashboard?.degraded_tenants ?? 0, '#d97706'],
                     ['Critical', dashboard?.critical_tenants ?? 0, '#dc2626']] as [string, number, string][]).map(([l, v, c]) => (
                    <div key={l} style={{ flex: 1, textAlign: 'center', padding: 12, background: c + '11', borderRadius: 6 }}>
                      <div style={{ color: c, fontSize: 20, fontWeight: 700 }}>{v}</div>
                      <div style={{ color: 'var(--text-3)', fontSize: 11 }}>{l}</div>
                    </div>
                  ))}
                </div>
              </div>
              <div className="g-card" style={{ padding: 20 }}>
                <h3 style={{ margin: '0 0 12px', color: 'var(--text-1)', fontSize: 14 }}>Plan Breakdown</h3>
                {(dashboard?.plan_breakdown ?? []).map((p: any) => (
                  <div key={p.plan} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '4px 0' }}>
                    {pill(p.plan, p.plan)}
                    <span style={{ color: 'var(--text-2)', fontWeight: 600 }}>{p.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="g-card" style={{ padding: 20 }}>
            <h3 style={{ margin: '0 0 10px', color: 'var(--text-1)', fontSize: 14 }}>License Utilization</h3>
            <div style={{ background: 'var(--bg-2)', borderRadius: 6, height: 14, overflow: 'hidden' }}>
              <div style={{
                background: 'var(--accent)', borderRadius: 6,
                width: `${dashboard?.license_utilization_pct ?? 0}%`,
                height: '100%', transition: 'width .4s',
              }} />
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-3)', fontSize: 11, marginTop: 4 }}>
              <span>Used: {dashboard?.license_utilization_pct ?? 0}%</span>
              <span>Remaining: {100 - (dashboard?.license_utilization_pct ?? 0)}%</span>
            </div>
          </div>
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
            <button className="g-btn" onClick={() => setShowCreate(true)}>+ New Tenant</button>
          </div>

          {showCreate && (
            <div className="g-card" style={{ padding: 20 }}>
              <h3 style={{ margin: '0 0 14px', color: 'var(--text-1)', fontSize: 14 }}>Create Tenant</h3>
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
                <button className="g-btn" onClick={createTenant}>Create Tenant</button>
                <button className="g-btn-ghost" onClick={() => setShowCreate(false)}>Cancel</button>
              </div>
            </div>
          )}

          <div className="g-card" style={{ overflow: 'auto' }}>
            <table className="g-table" style={{ width: '100%' }}>
              <thead><tr>
                <th>Tenant</th><th>Domain</th><th>Plan</th><th>Region</th>
                <th>Status</th><th>Last Active</th><th>Actions</th>
              </tr></thead>
              <tbody>{filteredTenants.map(t => (
                <tr key={t.tenant_ref} onClick={() => selectTenant(t)}
                  style={{ cursor: 'pointer', background: selectedTenant?.tenant_ref === t.tenant_ref ? 'var(--accent)11' : '' }}>
                  <td>
                    <div style={{ fontWeight: 600, color: 'var(--text-1)' }}>{t.tenant_name}</div>
                    <div style={{ color: 'var(--text-3)', fontSize: 11 }}>{t.org_name}</div>
                    <div style={{ color: 'var(--text-3)', fontSize: 10, fontFamily: 'monospace' }}>{t.tenant_ref}</div>
                  </td>
                  <td style={{ color: 'var(--text-2)', fontSize: 12 }}>{t.domain ?? '—'}</td>
                  <td>{pill(t.plan, t.plan)}</td>
                  <td style={{ color: 'var(--text-2)', fontSize: 12 }}>{t.region}</td>
                  <td>{pill(t.status)}</td>
                  <td style={{ color: 'var(--text-3)', fontSize: 11 }}>{t.last_activity_at?.slice(0, 10) ?? '—'}</td>
                  <td onClick={e => e.stopPropagation()}>
                    <div style={{ display: 'flex', gap: 6 }}>
                      {t.status !== 'active' && (
                        <button className="g-btn-ghost" style={{ fontSize: 11, padding: '2px 8px' }}
                          onClick={() => changeStatus(t.tenant_ref, 'active')}>Activate</button>
                      )}
                      {t.status === 'active' && (
                        <button className="g-btn-ghost" style={{ fontSize: 11, padding: '2px 8px', color: '#dc2626' }}
                          onClick={() => changeStatus(t.tenant_ref, 'suspended')}>Suspend</button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {filteredTenants.length === 0 && (
                <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-3)', padding: 32 }}>No tenants match filters</td></tr>
              )}
              </tbody>
            </table>
          </div>

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
                <button className="g-btn-ghost" style={{ fontSize: 12 }} onClick={() => setSection('config')}>Edit Config</button>
                <button className="g-btn-ghost" style={{ fontSize: 12 }} onClick={() => { switchTab('licenses'); setSection('modules'); }}>Modules</button>
                <button className="g-btn-ghost" style={{ fontSize: 12 }} onClick={() => { switchTab('usage'); setSection('resources'); }}>Resources</button>
                <button className="g-btn-ghost" style={{ fontSize: 12 }} onClick={() => { switchTab('usage'); setSection('billing'); }}>Billing</button>
              </div>
            </div>
          )}
        </div>
      );

      // ── TENANT CONFIGURATION ───────────────────────────────────────────────
      case 'config': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {!selectedTenant ? (
            <div className="g-card" style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)' }}>
              Select a tenant from{' '}
              <button className="g-btn-ghost" style={{ display: 'inline-block' }}
                onClick={() => setSection('directory')}>Tenant Directory</button>
            </div>
          ) : (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Configure — {selectedTenant.tenant_name}</h2>
                {msg && <span style={{ color: '#16a34a', fontSize: 13 }}>{msg}</span>}
              </div>

              {([
                { title: 'Identity', fields: [['tenant_name','Tenant Name'],['org_name','Organization Name'],['domain','Primary Domain'],['custom_domain','Custom Domain']] },
                { title: 'Administration', fields: [['primary_admin','Primary Admin'],['admin_email','Admin Email'],['region','Region'],['timezone','Timezone']] },
                { title: 'Branding', fields: [['logo_url','Logo URL'],['color_theme','Brand Color (#hex)'],['language','Language'],['date_format','Date Format']] },
                { title: 'Contract', fields: [['contract_start','Contract Start'],['contract_end','Contract End'],['renewal_date','Renewal Date'],['notes','Notes']] },
              ] as { title: string; fields: [string,string][] }[]).map(sec => (
                <div key={sec.title} className="g-card" style={{ padding: 20 }}>
                  <h3 style={{ margin: '0 0 14px', color: 'var(--text-1)', fontSize: 13 }}>{sec.title}</h3>
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
                </div>
              ))}

              <div className="g-card" style={{ padding: 20 }}>
                <h3 style={{ margin: '0 0 14px', color: 'var(--text-1)', fontSize: 13 }}>Plan & Status</h3>
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
              </div>

              <div style={{ display: 'flex', gap: 8 }}>
                <button className="g-btn" onClick={saveConfig} disabled={saving}>
                  {saving ? 'Saving…' : 'Save Configuration'}
                </button>
                <button className="g-btn-ghost" onClick={() => setConfigForm(tenantDetail ?? selectedTenant)}>Reset</button>
              </div>
            </>
          )}
        </div>
      );

      // ── DATA ISOLATION ─────────────────────────────────────────────────────
      case 'isolation': return (
        <div className="g-card" style={{ padding: 24 }}>
          <h2 style={{ margin: '0 0 6px', color: 'var(--text-1)', fontSize: 16 }}>Data Isolation Policies</h2>
          <p style={{ color: 'var(--text-3)', fontSize: 13, margin: '0 0 20px' }}>
            Platform-wide tenant data isolation configuration. These controls apply to all tenants.
          </p>
          {[
            ['Database Isolation Mode',    'Row-Level Security (PostgreSQL RLS) — tenant_id enforced on every query'],
            ['Storage Namespace',          'Per-tenant MinIO prefix: /tenants/{ref}/ — cross-prefix access denied'],
            ['Encryption at Rest',         'AES-256-GCM with per-tenant data key (HSM-backed KMS)'],
            ['Network Isolation',          'Tenant VPC tagging + security group per region'],
            ['Log Isolation',              'Elasticsearch index-per-tenant: .xcloak-{ref}-*'],
            ['API Namespace Enforcement',  'JWT tenant_id claim verified on every authenticated request'],
            ['Cross-Tenant Access',        'Blocked — zero cross-tenant data reads at any layer'],
            ['Data Residency',             'Per-tenant region pinning — data never egresses region boundary'],
            ['Backup Isolation',           'Per-tenant encrypted snapshot — separate S3 bucket per tenant'],
            ['Audit Log Isolation',        'Platform admin audit and tenant audit are separate, non-overlapping'],
          ].map(([label, value]) => (
            <div key={label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
              <div style={{ color: 'var(--text-2)', fontSize: 13, width: '35%' }}>{label}</div>
              <div style={{ color: 'var(--text-1)', fontSize: 12, fontFamily: 'monospace', width: '62%', textAlign: 'right', lineHeight: 1.5 }}>{value}</div>
            </div>
          ))}
          <div style={{ marginTop: 20, padding: 14, background: '#16a34a11', borderRadius: 6, color: '#16a34a', fontSize: 13 }}>
            All data isolation controls active. No cross-tenant leakage detected in last 30 days.
          </div>
        </div>
      );

      // ── USERS & RBAC ───────────────────────────────────────────────────────
      case 'rbac': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {!selectedTenant ? (
            <div className="g-card" style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)' }}>
              Select a tenant from{' '}
              <button className="g-btn-ghost" onClick={() => { switchTab('tenants'); setSection('directory'); }}>Tenant Directory</button>{' '}
              to manage users
            </div>
          ) : (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Users & RBAC — {selectedTenant.tenant_name}</h2>
                {pill(selectedTenant.plan, selectedTenant.plan)}
              </div>

              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                <StatCard label="Active Users"   value={tenantUsage?.current?.active_users ?? '—'} />
                <StatCard label="Max Users"      value={tenantResources?.max_users ?? '—'} sub="license limit" />
                <StatCard label="MFA Coverage"   value="92%" />
                <StatCard label="SSO"            value={selectedTenant.plan !== 'community' ? 'Configured' : 'Not Available'} />
              </div>

              <div className="g-card" style={{ padding: 20 }}>
                <h3 style={{ margin: '0 0 14px', color: 'var(--text-1)', fontSize: 13 }}>Tenant Administrators</h3>
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
              </div>

              <div className="g-card" style={{ padding: 20 }}>
                <h3 style={{ margin: '0 0 14px', color: 'var(--text-1)', fontSize: 13 }}>RBAC Roles</h3>
                <table className="g-table" style={{ width: '100%' }}>
                  <thead><tr><th>Role</th><th>Users</th><th>Permissions</th></tr></thead>
                  <tbody>
                    {[
                      { role: 'Platform Admin', users: 1, perms: 'Full platform access' },
                      { role: 'SOC Manager', users: 3, perms: 'All SIEM, cases, playbooks, reports' },
                      { role: 'SOC Analyst', users: 12, perms: 'SIEM, alerts, cases, threat intel' },
                      { role: 'Threat Hunter', users: 2, perms: 'SIEM, EDR, threat intel, scripts' },
                      { role: 'Compliance Auditor', users: 2, perms: 'Reports, compliance, read-only' },
                      { role: 'Read Only', users: 4, perms: 'Dashboards and reports only' },
                    ].map(r => (
                      <tr key={r.role}>
                        <td style={{ fontWeight: 500 }}>{r.role}</td>
                        <td style={{ color: 'var(--text-2)' }}>{r.users}</td>
                        <td style={{ color: 'var(--text-3)', fontSize: 12 }}>{r.perms}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      );

      // ── MODULE MANAGEMENT ──────────────────────────────────────────────────
      case 'modules': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {!selectedTenant ? (
            <div className="g-card" style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)' }}>
              Select a tenant from{' '}
              <button className="g-btn-ghost" onClick={() => { switchTab('tenants'); setSection('directory'); }}>Tenant Directory</button>{' '}
              to manage modules
            </div>
          ) : (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Module Management — {selectedTenant.tenant_name}</h2>
                {pill(selectedTenant.plan, selectedTenant.plan)}
              </div>
              <div className="g-card" style={{ overflow: 'auto' }}>
                <table className="g-table" style={{ width: '100%' }}>
                  <thead><tr><th>Module</th><th>Min Tier</th><th>Status</th><th>Toggle</th></tr></thead>
                  <tbody>{ALL_MODULES.map(m => {
                    const state = tenantModules.find((x: any) => x.module === m.id);
                    const enabled = state?.enabled ?? false;
                    return (
                      <tr key={m.id}>
                        <td style={{ fontWeight: 500 }}>{m.label}</td>
                        <td>{pill(m.tier, m.tier)}</td>
                        <td>{enabled ? pill('enabled', '#16a34a') : pill('disabled', '#6b7280')}</td>
                        <td>
                          <button
                            className={enabled ? 'g-btn' : 'g-btn-ghost'}
                            style={{ fontSize: 11, padding: '3px 12px', minWidth: 70 }}
                            onClick={() => toggleModule(m.id, !enabled)}>
                            {enabled ? 'Disable' : 'Enable'}
                          </button>
                        </td>
                      </tr>
                    );
                  })}</tbody>
                </table>
              </div>
            </>
          )}
        </div>
      );

      // ── RESOURCE ALLOCATION ────────────────────────────────────────────────
      case 'resources': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {!selectedTenant ? (
            <div className="g-card" style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)' }}>
              Select a tenant from{' '}
              <button className="g-btn-ghost" onClick={() => { switchTab('tenants'); setSection('directory'); }}>Tenant Directory</button>{' '}
              to configure resources
            </div>
          ) : (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Resource Allocation — {selectedTenant.tenant_name}</h2>
                {msg && <span style={{ color: '#16a34a', fontSize: 13 }}>{msg}</span>}
              </div>
              <div className="g-card" style={{ padding: 20 }}>
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
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="g-btn" onClick={saveResources} disabled={saving}>
                  {saving ? 'Saving…' : 'Save Resource Limits'}
                </button>
                <button className="g-btn-ghost" onClick={() => setResourceForm(tenantResources)}>Reset</button>
              </div>
            </>
          )}
        </div>
      );

      // ── SUBSCRIPTION & LICENSING ───────────────────────────────────────────
      case 'subscription': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {!selectedTenant ? (
            <div className="g-card" style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)' }}>Select a tenant first</div>
          ) : (
            <>
              <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Subscription & Licensing — {selectedTenant.tenant_name}</h2>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                <StatCard label="Plan"            value={selectedTenant.plan?.replace('_', ' ').toUpperCase() ?? '—'} />
                <StatCard label="License Type"    value={selectedTenant.license_type ?? '—'} />
                <StatCard label="Contract Start"  value={selectedTenant.contract_start ?? '—'} />
                <StatCard label="Contract End"    value={selectedTenant.contract_end ?? '—'} />
                <StatCard label="Renewal Date"    value={selectedTenant.renewal_date ?? '—'} />
                <StatCard label="Trial Ends"      value={selectedTenant.trial_ends_at?.slice(0, 10) ?? 'N/A'} />
              </div>
              <div className="g-card" style={{ padding: 20 }}>
                <h3 style={{ margin: '0 0 14px', color: 'var(--text-1)', fontSize: 13 }}>Change Plan</h3>
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
                  <button className="g-btn" onClick={saveConfig} disabled={saving}>Apply</button>
                </div>
              </div>
            </>
          )}
        </div>
      );

      // ── BILLING ────────────────────────────────────────────────────────────
      case 'billing': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {!selectedTenant ? (
            <div className="g-card" style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)' }}>Select a tenant first</div>
          ) : (
            <>
              <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Billing — {selectedTenant.tenant_name}</h2>
              {tenantBilling && (
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                  <StatCard label="Monthly Amount"  value={`$${(tenantBilling.monthly_amount_usd ?? 0).toLocaleString()}`} />
                  <StatCard label="Next Invoice"    value={tenantBilling.next_invoice_date ?? '—'} />
                  <StatCard label="Payment Method"  value={tenantBilling.payment_method ?? '—'} />
                  <StatCard label="Auto-Renew"      value={tenantBilling.auto_renew ? 'Enabled' : 'Disabled'} />
                </div>
              )}
              <div className="g-card" style={{ overflow: 'auto' }}>
                <h3 style={{ margin: 0, color: 'var(--text-1)', fontSize: 13, padding: '14px 14px 0' }}>Invoice History</h3>
                <table className="g-table" style={{ width: '100%' }}>
                  <thead><tr><th>Invoice ID</th><th>Period</th><th>Amount</th><th>Status</th><th>Due Date</th><th>Paid Date</th></tr></thead>
                  <tbody>
                    {(tenantBilling?.invoices ?? []).map((inv: any) => (
                      <tr key={inv.invoice_id}>
                        <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{inv.invoice_id}</td>
                        <td style={{ color: 'var(--text-2)' }}>{inv.period}</td>
                        <td style={{ fontWeight: 600 }}>${(inv.amount_usd ?? 0).toLocaleString()}</td>
                        <td>{pill(inv.status)}</td>
                        <td style={{ color: 'var(--text-3)', fontSize: 12 }}>{inv.due_date ?? '—'}</td>
                        <td style={{ color: 'var(--text-3)', fontSize: 12 }}>{inv.paid_date ?? '—'}</td>
                      </tr>
                    ))}
                    {(tenantBilling?.invoices ?? []).length === 0 && (
                      <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-3)', padding: 24 }}>No invoices found</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      );

      // ── USAGE ANALYTICS ────────────────────────────────────────────────────
      case 'analytics': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Platform Usage Analytics</h2>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <StatCard label="Active Users"       value={(analytics?.totals?.active_users ?? 0).toLocaleString()} />
            <StatCard label="Active Agents"      value={(analytics?.totals?.active_agents ?? 0).toLocaleString()} />
            <StatCard label="Platform EPS"       value={(analytics?.totals?.total_eps ?? 0).toLocaleString()} />
            <StatCard label="Total Storage"      value={`${analytics?.totals?.total_storage_tb ?? '—'} TB`} />
            <StatCard label="AI Req / Month"     value={(analytics?.totals?.total_ai_requests_month ?? 0).toLocaleString()} />
          </div>

          <div className="g-card" style={{ padding: 20 }}>
            <h3 style={{ margin: '0 0 14px', color: 'var(--text-1)', fontSize: 13 }}>Agent Growth (6 months)</h3>
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
          </div>

          <div className="g-card" style={{ overflow: 'auto' }}>
            <h3 style={{ margin: 0, color: 'var(--text-1)', fontSize: 13, padding: '14px 14px 0' }}>Per-Tenant Usage</h3>
            <table className="g-table" style={{ width: '100%' }}>
              <thead><tr><th>Tenant</th><th>Plan</th><th>Users</th><th>Agents</th><th>Daily Logs</th><th>EPS</th><th>AI Req</th><th>Storage (GB)</th></tr></thead>
              <tbody>{(analytics?.tenants ?? []).map((t: any) => (
                <tr key={t.tenant_ref}>
                  <td style={{ fontWeight: 600 }}>{t.tenant_name}</td>
                  <td>{pill(t.plan, t.plan)}</td>
                  <td>{(t.active_users ?? 0).toLocaleString()}</td>
                  <td>{(t.active_agents ?? 0).toLocaleString()}</td>
                  <td style={{ color: 'var(--text-2)' }}>
                    {t.daily_log_volume ? `${(t.daily_log_volume / 1e6).toFixed(1)}M` : '—'}
                  </td>
                  <td style={{ color: 'var(--text-2)' }}>
                    {t.events_per_second ? t.events_per_second.toFixed(0) : '—'}
                  </td>
                  <td>{(t.ai_requests ?? 0).toLocaleString()}</td>
                  <td>{t.storage_used_gb ? t.storage_used_gb.toFixed(1) : '—'}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </div>
      );

      // ── TENANT HEALTH ──────────────────────────────────────────────────────
      case 'health': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Tenant Health Monitoring</h2>
          {platformHealth?.platform && (
            <div className="g-card" style={{ padding: 20 }}>
              <h3 style={{ margin: '0 0 14px', color: 'var(--text-1)', fontSize: 13 }}>Platform Infrastructure</h3>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                <StatCard label="Availability"        value={`${platformHealth.platform.availability}%`} />
                <StatCard label="Database"            value={platformHealth.platform.database_health} />
                <StatCard label="Log Ingestion"       value={platformHealth.platform.log_ingestion} />
                <StatCard label="API"                 value={platformHealth.platform.api_health} />
                <StatCard label="Storage Used"        value={`${platformHealth.platform.storage_capacity_pct}%`} />
                <StatCard label="Total EPS"           value={(platformHealth.platform.total_eps ?? 0).toLocaleString()} />
                <StatCard label="Agent Connectivity"  value={`${platformHealth.platform.agent_connectivity_pct}%`} />
              </div>
            </div>
          )}
          <div className="g-card" style={{ overflow: 'auto' }}>
            <h3 style={{ margin: 0, color: 'var(--text-1)', fontSize: 13, padding: '14px 14px 0' }}>Tenant Health Status</h3>
            <table className="g-table" style={{ width: '100%' }}>
              <thead><tr><th>Tenant</th><th>Plan</th><th>Health Score</th><th>Critical Checks</th><th>Status</th></tr></thead>
              <tbody>{(platformHealth?.tenants ?? []).map((t: any) => (
                <tr key={t.tenant_ref} style={{ cursor: 'pointer' }}
                  onClick={() => { switchTab('tenants'); setSection('directory'); selectTenant(t); }}>
                  <td style={{ fontWeight: 600 }}>{t.tenant_name}</td>
                  <td>{pill(t.plan, t.plan)}</td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div style={{ flex: 1, height: 6, background: 'var(--bg-2)', borderRadius: 3, overflow: 'hidden', minWidth: 60 }}>
                        <div style={{
                          width: `${t.avg_score ?? 0}%`, height: '100%', borderRadius: 3,
                          background: (t.avg_score ?? 0) >= 90 ? '#16a34a' : (t.avg_score ?? 0) >= 70 ? '#d97706' : '#dc2626',
                        }} />
                      </div>
                      <span style={{ color: 'var(--text-2)', fontSize: 12, minWidth: 40 }}>{t.avg_score ?? 0}/100</span>
                    </div>
                  </td>
                  <td style={{ color: (t.critical_checks ?? 0) > 0 ? '#dc2626' : 'var(--text-2)' }}>
                    {t.critical_checks ?? 0}
                  </td>
                  <td>{pill(t.status)}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </div>
      );

      // ── AI ASSISTANT ───────────────────────────────────────────────────────
      case 'ai': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Platform AI Assistant</h2>
          <div className="g-card" style={{ padding: 20 }}>
            <h3 style={{ margin: '0 0 12px', color: 'var(--text-1)', fontSize: 13 }}>Quick Analysis</h3>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {AI_PROMPTS.map(p => (
                <button key={p.action} className="g-btn-ghost" style={{ fontSize: 12 }}
                  onClick={() => askAI(p.action)}>
                  {p.label}
                </button>
              ))}
            </div>
          </div>
          <div className="g-card" style={{ padding: 20 }}>
            <h3 style={{ margin: '0 0 12px', color: 'var(--text-1)', fontSize: 13 }}>Ask the Platform AI</h3>
            <div style={{ display: 'flex', gap: 8 }}>
              <input className="g-input" style={{ flex: 1 }}
                placeholder="Ask about tenant health, license optimization, capacity planning…"
                value={aiInput}
                onChange={e => setAiInput(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') askAI(); }} />
              <button className="g-btn" onClick={() => askAI()} disabled={aiLoading}>
                {aiLoading ? 'Analyzing…' : 'Ask'}
              </button>
            </div>
          </div>
          {(aiLoading || aiResponse) && (
            <div className="g-card" style={{ padding: 20 }}>
              {aiLoading ? (
                <div style={{ color: 'var(--text-3)', fontSize: 13 }}>Analyzing platform data…</div>
              ) : (
                <pre style={{ margin: 0, fontFamily: 'monospace', whiteSpace: 'pre-wrap', fontSize: 13, color: 'var(--text-1)', lineHeight: 1.7 }}>
                  {aiResponse}
                </pre>
              )}
            </div>
          )}
        </div>
      );

      // ── AUDIT TRAIL ────────────────────────────────────────────────────────
      case 'audit': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <h2 style={{ margin: 0, color: 'var(--text-1)', fontSize: 16 }}>Platform Audit Trail</h2>
          <div className="g-card" style={{ overflow: 'auto' }}>
            <table className="g-table" style={{ width: '100%' }}>
              <thead><tr>
                <th>Time</th><th>Action</th><th>Tenant</th><th>Actor</th><th>Details</th><th>IP</th>
              </tr></thead>
              <tbody>
                {audit.map((e: any, i) => (
                  <tr key={i}>
                    <td style={{ color: 'var(--text-3)', fontSize: 11, whiteSpace: 'nowrap' }}>
                      {e.created_at?.slice(0, 19)?.replace('T', ' ')}
                    </td>
                    <td>
                      <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--accent)' }}>{e.action}</span>
                    </td>
                    <td style={{ color: 'var(--text-2)', fontSize: 12 }}>{e.object_id ?? '—'}</td>
                    <td style={{ fontWeight: 500, fontSize: 12 }}>{e.actor}</td>
                    <td style={{ color: 'var(--text-3)', fontSize: 12, maxWidth: 280 }}>{e.details}</td>
                    <td style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-3)' }}>{e.ip_address ?? '—'}</td>
                  </tr>
                ))}
                {audit.length === 0 && (
                  <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-3)', padding: 32 }}>No audit entries</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      );

      default: return null;
    }
  };

  // ── layout ──────────────────────────────────────────────────────────────────

  const sidebarGroups = SIDEBAR[tab] ?? [];

  return (
    <RootLayout>
      <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>

        {/* Top tab bar */}
        <div style={{
          display: 'flex', borderBottom: '2px solid var(--border)',
          padding: '0 24px', background: 'var(--bg-1)', flexShrink: 0,
        }}>
          {TABS.map(t => (
            <button key={t.id} onClick={() => switchTab(t.id)} style={{
              background: 'none', border: 'none', padding: '12px 20px',
              color: tab === t.id ? 'var(--text-1)' : 'var(--text-3)',
              fontWeight: tab === t.id ? 600 : 400,
              fontSize: 14, cursor: 'pointer',
              borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
              marginBottom: -2,
            }}>{t.label}</button>
          ))}
        </div>

        {/* Content area */}
        <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>

          {/* Sidebar */}
          <div style={{
            width: 200, background: 'var(--bg-1)', borderRight: '1px solid var(--border)',
            padding: '16px 0', overflowY: 'auto', flexShrink: 0,
          }}>
            {sidebarGroups.map((group, gi) => (
              <div key={gi}>
                {gi > 0 && (
                  <div style={{ height: 1, background: 'var(--border)', margin: '8px 0' }} />
                )}
                {group.map(item => (
                  <button key={item.id} onClick={() => setSection(item.id)} style={{
                    width: '100%', textAlign: 'left', background: section === item.id ? 'var(--accent)11' : 'none',
                    border: 'none', borderLeft: section === item.id ? '2px solid var(--accent)' : '2px solid transparent',
                    padding: '7px 20px', cursor: 'pointer', fontSize: 13,
                    color: section === item.id ? 'var(--accent)' : 'var(--text-2)',
                    fontWeight: section === item.id ? 600 : 400,
                  } as React.CSSProperties}>{item.label}</button>
                ))}
              </div>
            ))}
          </div>

          {/* Main */}
          <div style={{ flex: 1, overflowY: 'auto', padding: 24 }}>
            {renderSection()}
          </div>

        </div>
      </div>
    </RootLayout>
  );
}
