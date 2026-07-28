'use client';

import { useState, useEffect, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { cloudSecurityAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import { MetricCard, SectionCard, DataTable, TabBar, ActionButton } from '@/components/design-system';
import { Activity, AlertCircle, AlertTriangle, BarChart2, Brain, CheckCircle, ChevronRight, Cloud, Database, Eye, FileText, GitBranch, Globe, Key, Plus, RefreshCw, Server, Shield, XCircle, Zap, Lock } from 'lucide-react';

const TABS = [
  { id: 'overview',     label: 'Overview',     icon: Activity },
  { id: 'inventory',    label: 'Inventory',    icon: Cloud },
  { id: 'posture',      label: 'CSPM',         icon: Shield },
  { id: 'identity',     label: 'CIEM',         icon: Key },
  { id: 'detection',    label: 'Detection',    icon: AlertCircle },
  { id: 'compliance',   label: 'Compliance',   icon: CheckCircle },
  { id: 'attackpaths',  label: 'Attack Paths', icon: GitBranch },
  { id: 'intelligence', label: 'Intelligence', icon: Brain },
  { id: 'analytics',    label: 'Analytics',    icon: BarChart2 },
];

const SEV_STYLE: Record<string, React.CSSProperties> = {
  critical: { background: 'var(--red-bg)',    color: 'var(--red)',    border: '1px solid var(--red-border)' },
  high:     { background: 'var(--orange-bg)', color: 'var(--orange)', border: '1px solid var(--orange-border)' },
  medium:   { background: 'var(--yellow-bg)', color: 'var(--yellow)', border: '1px solid var(--yellow-border)' },
  low:      { background: 'var(--blue-bg)',   color: 'var(--blue)',   border: '1px solid var(--blue-border)' },
};
const PROV_STYLE: Record<string, React.CSSProperties> = {
  aws:   { color: 'var(--orange)' },
  azure: { color: 'var(--blue)' },
  gcp:   { color: 'var(--green)' },
};
const PROV_BG_STYLE: Record<string, React.CSSProperties> = {
  aws:   { background: 'var(--orange-bg)', border: '1px solid var(--orange-border)', color: 'var(--orange)' },
  azure: { background: 'var(--blue-bg)',   border: '1px solid var(--blue-border)',   color: 'var(--blue)' },
  gcp:   { background: 'var(--green-bg)',  border: '1px solid var(--green-border)',  color: 'var(--green)' },
};

const SELECTED_ROW_STYLE: React.CSSProperties = { background: 'var(--accent-glow)' };

function ProviderBadge({ provider }: { provider: string }) {
  const baseStyle: React.CSSProperties = PROV_BG_STYLE[provider] ?? { background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-3)' };
  return (
    <span className="text-[10px] px-1.5 py-0.5 rounded uppercase font-bold" style={baseStyle}>
      {provider}
    </span>
  );
}

// ── Overview Tab ──────────────────────────────────────────────────────────────

function OverviewTab() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    cloudSecurityAPI.getDashboard().then(r => { setData(r.data); setLoading(false); });
  }, []);

  if (loading) return <div className="text-[var(--text-3)] text-sm p-4">Loading...</div>;
  if (!data) return <div className="text-[var(--text-3)] p-4">No data</div>;

  const riskColor = data.multi_cloud_risk > 75 ? 'var(--red)' : data.multi_cloud_risk > 50 ? 'var(--orange)' : 'var(--yellow)';
  const compColor = data.compliance_score > 85 ? 'var(--green)' : data.compliance_score > 70 ? 'var(--yellow)' : 'var(--red)';

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <MetricCard label="AWS Accounts"     value={data.aws_accounts}     color="var(--orange)" />
        <MetricCard label="Azure Subs"       value={data.azure_subs}       color="var(--blue)" />
        <MetricCard label="GCP Projects"     value={data.gcp_projects}     color="var(--green)" />
        <MetricCard label="Multi-Cloud Risk" value={`${data.multi_cloud_risk}%`} color={riskColor} />
        <MetricCard label="Compliance Score" value={`${data.compliance_score}%`} color={compColor} />
      </div>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <MetricCard label="Total Assets"    value={data.total_assets} />
        <MetricCard label="Public Assets"  value={data.public_assets}   color={data.public_assets > 0 ? 'var(--red)' : 'var(--green)'} />
        <MetricCard label="Critical Findings" value={data.critical_findings} color="var(--red)" />
        <MetricCard label="IAM Risks"      value={data.iam_risks}       color="var(--orange)" />
        <MetricCard label="Active Threats" value={data.active_threats}  color={data.active_threats > 0 ? 'var(--red)' : 'var(--green)'} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <SectionCard title="Asset Inventory by Provider">
          <div className="space-y-2">
            {(data.inventory ?? []).map((inv: any) => {
              const total = data.total_assets || 1;
              return (
                <div key={inv.provider} className="space-y-1">
                  <div className="flex justify-between text-xs">
                    <span className="uppercase font-bold" style={PROV_STYLE[inv.provider] ?? { color: 'var(--text-2)' }}>{inv.provider}</span>
                    <span className="text-[var(--text-2)]">{inv.count} assets</span>
                  </div>
                  <div className="h-2 rounded-full bg-[var(--border)]">
                    <div className="h-full rounded-full"
                      style={{ width: `${Math.round(inv.count / total * 100)}%`, background: (PROV_STYLE[inv.provider] ?? { color: 'var(--accent)' }).color }} />
                  </div>
                </div>
              );
            })}
          </div>
        </SectionCard>

        <SectionCard title="Recent Cloud Threats">
          <div className="space-y-2 max-h-52 overflow-y-auto">
            {(data.recent_threats ?? []).map((t: any) => (
              <div key={t.id} className="flex items-start justify-between gap-3 py-1.5 border-b border-[var(--border)] last:border-0">
                <div className="space-y-0.5 min-w-0">
                  <div className="text-xs font-medium text-[var(--text-1)] capitalize">{t.threat_type.replace(/_/g, ' ')}</div>
                  <div className="text-[10px] text-[var(--text-3)] font-mono truncate">{t.resource_id}</div>
                </div>
                <div className="flex flex-col items-end gap-0.5 shrink-0">
                  <div className="flex items-center gap-1">
                    <ProviderBadge provider={t.provider} />
                    <span className="text-[10px] px-1.5 py-0.5 rounded" style={SEV_STYLE[t.severity] ?? SEV_STYLE.medium}>{t.severity}</span>
                  </div>
                  <span className="text-[10px] text-[var(--text-3)]">{timeAgo(t.created_at)}</span>
                </div>
              </div>
            ))}
          </div>
        </SectionCard>
      </div>
    </div>
  );
}

// ── Inventory Tab ─────────────────────────────────────────────────────────────

function InventoryTab() {
  const [assets, setAssets] = useState<any[]>([]);
  const [accounts, setAccounts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterProvider, setFilterProvider] = useState('');
  const [filterType, setFilterType] = useState('');
  const [showAddAccount, setShowAddAccount] = useState(false);
  const [form, setForm] = useState({ name: '', provider: 'aws', account_id: '', region: 'us-east-1' });

  const reload = () => {
    setLoading(true);
    const params: any = {};
    if (filterProvider) params.provider = filterProvider;
    if (filterType) params.resource_type = filterType;
    Promise.all([cloudSecurityAPI.getInventory(params), cloudSecurityAPI.getAccounts()])
      .then(([ar, acr]) => { setAssets(ar.data ?? []); setAccounts(acr.data ?? []); setLoading(false); });
  };
  useEffect(() => { reload(); }, [filterProvider, filterType]);

  const createAccount = async () => {
    await cloudSecurityAPI.createAccount(form);
    setShowAddAccount(false);
    reload();
  };

  const RESOURCE_ICONS: Record<string, React.ReactNode> = {
    ec2:             <Server   className="h-4 w-4" style={{ color: 'var(--orange)' }} />,
    s3:              <Database className="h-4 w-4" style={{ color: 'var(--orange)' }} />,
    rds:             <Database className="h-4 w-4" style={{ color: 'var(--blue)' }} />,
    eks:             <Cloud    className="h-4 w-4" style={{ color: 'var(--accent)' }} />,
    lambda:          <Zap      className="h-4 w-4" style={{ color: 'var(--yellow)' }} />,
    storage_account: <Database className="h-4 w-4" style={{ color: 'var(--blue)' }} />,
    bigquery:        <BarChart2 className="h-4 w-4" style={{ color: 'var(--green)' }} />,
    vpc:             <Globe    className="h-4 w-4" style={{ color: 'var(--blue)' }} />,
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2">
        {accounts.map((a: any) => (
          <div key={a.id} className="g-card p-3 space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase font-bold" style={PROV_STYLE[a.provider] ?? { color: 'var(--text-3)' }}>{a.provider}</span>
              <div className="h-1.5 w-1.5 rounded-full" style={{ background: a.status === 'connected' ? 'var(--green)' : 'var(--yellow)' }} />
            </div>
            <div className="text-xs font-medium text-[var(--text-1)] truncate">{a.name}</div>
            <div className="text-[10px] text-[var(--text-3)]">{a.asset_count} assets</div>
            <div className="text-[10px] font-bold" style={{ color: a.risk_score > 70 ? 'var(--red)' : a.risk_score > 50 ? 'var(--orange)' : 'var(--green)' }}>Risk: {a.risk_score}%</div>
          </div>
        ))}
        <button className="g-card p-3 flex flex-col items-center justify-center gap-1 text-[var(--text-3)] hover:text-[var(--accent)] hover:border-[var(--accent-border)] transition-colors cursor-pointer" onClick={() => setShowAddAccount(true)}>
          <Plus className="h-5 w-5" />
          <span className="text-[10px]">Add Account</span>
        </button>
      </div>

      {showAddAccount && (
        <SectionCard title="Connect Cloud Account" className="border border-[var(--accent-border)]">
          <div className="space-y-3">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {[
                { label: 'Name', key: 'name', placeholder: 'AWS Production' },
                { label: 'Provider', key: 'provider', options: ['aws', 'azure', 'gcp', 'digitalocean', 'oracle'] },
                { label: 'Account/Subscription ID', key: 'account_id', placeholder: '123456789012' },
                { label: 'Region', key: 'region', placeholder: 'us-east-1' },
              ].map(({ label, key, placeholder, options }) => (
                <div key={key}>
                  <label className="text-xs text-[var(--text-3)] mb-1 block">{label}</label>
                  {options ? (
                    <select className="g-select text-xs w-full" value={(form as any)[key]} onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}>
                      {options.map(o => <option key={o} value={o}>{o}</option>)}
                    </select>
                  ) : (
                    <input className="g-input text-xs w-full" placeholder={placeholder} value={(form as any)[key]} onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))} />
                  )}
                </div>
              ))}
            </div>
            <div className="flex gap-2">
              <ActionButton variant="primary" className="text-xs" onClick={createAccount}>Connect</ActionButton>
              <ActionButton variant="ghost" className="text-xs" onClick={() => setShowAddAccount(false)}>Cancel</ActionButton>
            </div>
          </div>
        </SectionCard>
      )}

      <div className="flex items-center gap-2 flex-wrap">
        <select className="g-select text-xs" value={filterProvider} onChange={e => setFilterProvider(e.target.value)}>
          <option value="">All Providers</option>
          <option value="aws">AWS</option>
          <option value="azure">Azure</option>
          <option value="gcp">GCP</option>
        </select>
        <select className="g-select text-xs" value={filterType} onChange={e => setFilterType(e.target.value)}>
          <option value="">All Resource Types</option>
          {['ec2','s3','rds','eks','lambda','vpc','storage_account','bigquery','cloud_function'].map(t => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <ActionButton variant="ghost" icon={RefreshCw} onClick={reload} className="text-xs" title="Refresh" />
      </div>

      <DataTable<any>
        loading={loading}
        rows={assets}
        rowKey={(a: any) => a.id}
        columns={[
          { key: 'name', header: 'Resource', render: (a: any) => (
            <div className="flex items-center gap-2">
              {RESOURCE_ICONS[a.resource_type] ?? <Cloud className="h-4 w-4 text-[var(--text-3)]" />}
              <span className="font-medium text-[var(--text-1)]">{a.name}</span>
            </div>
          ) },
          { key: 'type', header: 'Type', render: (a: any) => <span className="text-xs font-mono text-[var(--accent)]">{a.resource_type}</span> },
          { key: 'provider', header: 'Provider', render: (a: any) => <ProviderBadge provider={a.provider} /> },
          { key: 'region', header: 'Region', render: (a: any) => <span className="text-xs text-[var(--text-2)]">{a.region}</span> },
          { key: 'owner', header: 'Owner', render: (a: any) => <span className="text-xs text-[var(--text-3)]">{a.owner || '—'}</span> },
          { key: 'risk', header: 'Risk', render: (a: any) => (
            <div className="flex items-center gap-1">
              <div className="w-12 h-1.5 rounded-full bg-[var(--border)]">
                <div className="h-full rounded-full"
                  style={{ width: `${a.risk_score}%`, background: a.risk_score > 75 ? 'var(--red)' : a.risk_score > 50 ? 'var(--orange)' : 'var(--yellow)' }} />
              </div>
              <span className="text-xs font-bold" style={{ color: a.risk_score > 75 ? 'var(--red)' : a.risk_score > 50 ? 'var(--orange)' : 'var(--text-2)' }}>{a.risk_score}</span>
            </div>
          ) },
          { key: 'exposed', header: 'Exposed', render: (a: any) => a.internet_exposed ? <Eye className="h-3.5 w-3.5" style={{ color: 'var(--red)' }} /> : <Lock className="h-3.5 w-3.5" style={{ color: 'var(--green)' }} /> },
          { key: 'last_activity', header: 'Last Activity', render: (a: any) => <span className="text-xs text-[var(--text-3)]">{a.last_activity ? timeAgo(a.last_activity) : '—'}</span> },
        ]}
      />
    </div>
  );
}

// ── Posture (CSPM) Tab ────────────────────────────────────────────────────────

function PostureTab() {
  const [findings, setFindings] = useState<any[]>([]);
  const [summary, setSummary] = useState<any[]>([]);
  const [exposure, setExposure] = useState<any>(null);
  const [drift, setDrift] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterSev, setFilterSev] = useState('');
  const [filterCat, setFilterCat] = useState('');
  const [selected, setSelected] = useState<any>(null);
  const [responding, setResponding] = useState(false);

  const reload = () => {
    setLoading(true);
    const params: any = {};
    if (filterSev) params.severity = filterSev;
    if (filterCat) params.category = filterCat;
    Promise.all([cloudSecurityAPI.getCSPMFindings(params), cloudSecurityAPI.getCSPMSummary(), cloudSecurityAPI.getExposure(), cloudSecurityAPI.getDrift()])
      .then(([fr, sr, er, dr]) => { setFindings(fr.data ?? []); setSummary(sr.data ?? []); setExposure(er.data); setDrift(dr.data ?? []); setLoading(false); });
  };
  useEffect(() => { reload(); }, [filterSev, filterCat]);

  const doResolve = async (id: number) => {
    setResponding(true);
    await cloudSecurityAPI.patchFinding(id, { status: 'resolved' });
    setResponding(false);
    reload();
  };

  const doAckDrift = async (id: number) => {
    await cloudSecurityAPI.patchDrift(id);
    reload();
  };

  return (
    <div className="space-y-4">
      {exposure && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <MetricCard label="Public Buckets"  value={exposure.public_buckets}  color={exposure.public_buckets > 0 ? 'var(--red)' : 'var(--green)'} />
          <MetricCard label="Open Databases"  value={exposure.open_databases}  color={exposure.open_databases > 0 ? 'var(--red)' : 'var(--green)'} />
          <MetricCard label="Public APIs"     value={exposure.public_apis}     color={exposure.public_apis > 0 ? 'var(--orange)' : 'var(--green)'} />
          <MetricCard label="Weak Sec Groups" value={exposure.weak_security_groups} color="var(--orange)" />
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <SectionCard title="Finding Categories">
          <div className="space-y-3">
            {summary.map((s: any) => (
              <div key={s.category} className="space-y-1 cursor-pointer" onClick={() => setFilterCat(filterCat === s.category ? '' : s.category)}>
                <div className="flex justify-between text-xs">
                  <span className={`capitalize ${filterCat === s.category ? 'text-[var(--accent)]' : 'text-[var(--text-2)]'}`}>{s.category.replace(/_/g, ' ')}</span>
                  <div className="flex gap-1">
                    {s.critical > 0 && <span className="font-bold" style={{ color: 'var(--red)' }}>{s.critical}C</span>}
                    {s.high > 0 && <span className="font-bold" style={{ color: 'var(--orange)' }}>{s.high}H</span>}
                    <span className="text-[var(--text-3)]">{s.total}</span>
                  </div>
                </div>
                <div className="h-1 rounded-full bg-[var(--border)]">
                  <div className="h-full rounded-full bg-[var(--accent)]" style={{ width: `${Math.round(s.critical / (s.total || 1) * 100) + 10}%` }} />
                </div>
              </div>
            ))}
          </div>
        </SectionCard>

        <div className="lg:col-span-2 space-y-3">
          <div className="flex items-center gap-2">
            <select className="g-select text-xs" value={filterSev} onChange={e => setFilterSev(e.target.value)}>
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
            </select>
            <ActionButton variant="ghost" icon={RefreshCw} onClick={reload} className="text-xs" title="Refresh" />
          </div>

          {loading ? <div className="text-[var(--text-3)] text-sm">Loading...</div> : (
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {findings.map((f: any) => (
                <div
                  key={f.id}
                  className={`g-card p-3 space-y-2 cursor-pointer hover:border-[var(--accent-border)] transition-colors ${selected?.id === f.id ? 'border-[var(--accent-border)]' : ''}`}
                  onClick={() => setSelected(selected?.id === f.id ? null : f)}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="text-xs font-medium text-[var(--text-1)]">{f.title}</div>
                    <div className="flex items-center gap-1 shrink-0">
                      <ProviderBadge provider={f.provider} />
                      <span className="text-[10px] px-1.5 py-0.5 rounded" style={SEV_STYLE[f.severity] ?? SEV_STYLE.medium}>{f.severity}</span>
                    </div>
                  </div>
                  {selected?.id === f.id && (
                    <div className="space-y-2 pt-1">
                      <div className="text-xs text-[var(--text-2)]">{f.description}</div>
                      <div className="g-card p-2 text-xs text-[var(--text-2)]">
                        <span className="text-[var(--text-3)]">Remediation: </span>{f.remediation}
                      </div>
                      <div className="flex items-center gap-2 flex-wrap text-[10px] text-[var(--text-3)]">
                        <span>{f.resource_type} · {f.resource_id}</span>
                        <span>{f.region}</span>
                        {f.framework && <span className="px-1.5 py-0.5 rounded bg-[var(--glass-bg)] border border-[var(--border)]">{f.framework} {f.control_id}</span>}
                      </div>
                      <div className="flex gap-2">
                        <ActionButton variant="primary" className="text-xs" onClick={() => doResolve(f.id)} loading={responding}>Mark Resolved</ActionButton>
                        <ActionButton variant="ghost" className="text-xs" onClick={e => { e.stopPropagation(); setSelected(null); }}>Close</ActionButton>
                      </div>
                    </div>
                  )}
                </div>
              ))}
              {findings.length === 0 && <div className="text-xs text-[var(--text-3)] text-center py-8">No open findings</div>}
            </div>
          )}
        </div>
      </div>

      <SectionCard title="Infrastructure Drift">
        <DataTable<any>
          rows={drift}
          rowKey={(d: any) => d.id}
          rowStyle={(d: any) => d.acknowledged ? { opacity: 0.5 } : undefined}
          columns={[
            { key: 'resource', header: 'Resource', render: (d: any) => <span className="text-xs font-mono text-[var(--text-1)]">{d.resource_id}</span> },
            { key: 'change', header: 'Change', render: (d: any) => <span className="text-xs text-[var(--text-2)] capitalize">{d.change_type.replace(/_/g, ' ')}</span> },
            { key: 'previous', header: 'Previous', render: (d: any) => <span className="text-xs font-mono" style={{ color: 'var(--green)' }}>{d.previous_state || '—'}</span> },
            { key: 'new_state', header: 'New State', render: (d: any) => <span className="text-xs font-mono" style={{ color: 'var(--red)' }}>{d.new_state || '—'}</span> },
            { key: 'changed_by', header: 'Changed By', render: (d: any) => <span className="text-xs text-[var(--text-3)]">{d.changed_by || '—'}</span> },
            { key: 'provider', header: 'Provider', render: (d: any) => <ProviderBadge provider={d.provider} /> },
            { key: 'severity', header: 'Severity', render: (d: any) => <span className="text-[10px] px-1.5 py-0.5 rounded" style={SEV_STYLE[d.severity] ?? SEV_STYLE.medium}>{d.severity}</span> },
            { key: 'time', header: 'Time', render: (d: any) => <span className="text-xs text-[var(--text-3)]">{timeAgo(d.created_at)}</span> },
            { key: 'ack', header: '', render: (d: any) => !d.acknowledged && <button className="text-xs text-[var(--text-3)] hover:text-[var(--green)]" onClick={() => doAckDrift(d.id)}>Ack</button> },
          ]}
        />
      </SectionCard>
    </div>
  );
}

// ── Identity (CIEM) Tab ───────────────────────────────────────────────────────

function IdentityTab() {
  const [identities, setIdentities] = useState<any[]>([]);
  const [risks, setRisks] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [filterRisk, setFilterRisk] = useState('');
  const [filterType, setFilterType] = useState('');

  const reload = () => {
    setLoading(true);
    const params: any = {};
    if (filterRisk) params.risk_level = filterRisk;
    if (filterType) params.type = filterType;
    Promise.all([cloudSecurityAPI.getCIEMIdentities(params), cloudSecurityAPI.getCIEMRisks()])
      .then(([ir, rr]) => { setIdentities(ir.data ?? []); setRisks(rr.data); setLoading(false); });
  };
  useEffect(() => { reload(); }, [filterRisk, filterType]);

  return (
    <div className="space-y-4">
      {risks && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <MetricCard label="Dormant Accounts"      value={risks.dormant_accounts}      color="var(--orange)" />
          <MetricCard label="No MFA"                value={risks.no_mfa}                color="var(--red)" />
          <MetricCard label="Old Access Keys (90d)" value={risks.old_access_keys}       color="var(--orange)" />
          <MetricCard label="Excessive Permissions" value={risks.excessive_permissions} color="var(--red)" />
          <MetricCard label="Privilege Escalation"  value={risks.privilege_escalation}  color="var(--red)" />
        </div>
      )}

      <div className="flex items-center gap-2 flex-wrap">
        <select className="g-select text-xs" value={filterRisk} onChange={e => setFilterRisk(e.target.value)}>
          <option value="">All Risk Levels</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select className="g-select text-xs" value={filterType} onChange={e => setFilterType(e.target.value)}>
          <option value="">All Types</option>
          <option value="iam_user">IAM User</option>
          <option value="iam_role">IAM Role</option>
          <option value="service_account">Service Account</option>
          <option value="service_principal">Service Principal</option>
          <option value="oauth_app">OAuth App</option>
        </select>
        <ActionButton variant="ghost" icon={RefreshCw} onClick={reload} className="text-xs" title="Refresh" />
      </div>

      <DataTable<any>
        loading={loading}
        rows={identities}
        rowKey={(id: any) => id.id}
        columns={[
          { key: 'name', header: 'Identity', render: (id: any) => <span className="font-medium text-[var(--text-1)]">{id.name}</span> },
          { key: 'type', header: 'Type', render: (id: any) => <span className="text-xs text-[var(--text-2)] capitalize">{id.identity_type.replace(/_/g, ' ')}</span> },
          { key: 'provider', header: 'Provider', render: (id: any) => <ProviderBadge provider={id.provider} /> },
          { key: 'permissions', header: 'Permissions', render: (id: any) => <span className="text-xs font-mono text-[var(--text-3)] truncate max-w-[160px] block">{id.permissions || '—'}</span> },
          { key: 'mfa', header: 'MFA', render: (id: any) => id.mfa_enabled ? <CheckCircle className="h-3.5 w-3.5" style={{ color: 'var(--green)' }} /> : id.identity_type === 'iam_user' ? <XCircle className="h-3.5 w-3.5" style={{ color: 'var(--red)' }} /> : <span className="text-[10px] text-[var(--text-3)]">N/A</span> },
          { key: 'key_age', header: 'Key Age', render: (id: any) => <span className="text-xs" style={{ color: id.access_key_age_days > 90 ? 'var(--red)' : 'var(--text-2)', fontWeight: id.access_key_age_days > 90 ? 700 : undefined }}>{id.access_key_age_days > 0 ? `${id.access_key_age_days}d` : '—'}</span> },
          { key: 'dormant', header: 'Dormant', render: (id: any) => id.is_dormant ? <AlertTriangle className="h-3.5 w-3.5" style={{ color: 'var(--orange)' }} /> : <CheckCircle className="h-3.5 w-3.5" style={{ color: 'var(--green)' }} /> },
          { key: 'last_used', header: 'Last Used', render: (id: any) => <span className="text-xs text-[var(--text-3)]">{id.last_used ? timeAgo(id.last_used) : 'Never'}</span> },
          { key: 'risk', header: 'Risk', render: (id: any) => <span className="text-[10px] px-1.5 py-0.5 rounded" style={SEV_STYLE[id.risk_level] ?? SEV_STYLE.low}>{id.risk_level}</span> },
        ]}
      />
    </div>
  );
}

// ── Detection Tab ─────────────────────────────────────────────────────────────

function DetectionTab() {
  const [threats, setThreats] = useState<any[]>([]);
  const [vulns, setVulns] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterType, setFilterType] = useState('');
  const [filterProvider, setFilterProvider] = useState('');
  const [selected, setSelected] = useState<any>(null);
  const [subTab, setSubTab] = useState<'threats' | 'vulns'>('threats');
  const [responding, setResponding] = useState(false);

  const reload = () => {
    setLoading(true);
    const params: any = {};
    if (filterType) params.threat_type = filterType;
    if (filterProvider) params.provider = filterProvider;
    Promise.all([cloudSecurityAPI.getThreats(params), cloudSecurityAPI.getVulnerabilities()])
      .then(([tr, vr]) => { setThreats(tr.data ?? []); setVulns(vr.data ?? []); setLoading(false); });
  };
  useEffect(() => { reload(); }, [filterType, filterProvider]);

  const doRespond = async (action: string, t: any) => {
    setResponding(true);
    await cloudSecurityAPI.respond({ action, resource_id: t.resource_id, provider: t.provider });
    setResponding(false);
  };

  const THREAT_TYPES = ['crypto_mining', 'suspicious_api_calls', 'impossible_travel', 'new_iam_user', 'access_key_abuse', 'bucket_enumeration', 'data_exfiltration', 'malicious_lambda'];

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        {(['threats', 'vulns'] as const).map(s => (
          <ActionButton key={s} variant={subTab === s ? 'primary' : 'ghost'} onClick={() => setSubTab(s)} className="text-xs">
            {s === 'threats' ? `Cloud Threats (${threats.length})` : `Vulnerabilities (${vulns.length})`}
          </ActionButton>
        ))}
      </div>

      {subTab === 'threats' && (
        <>
          <div className="flex items-center gap-2 flex-wrap">
            <select className="g-select text-xs" value={filterType} onChange={e => setFilterType(e.target.value)}>
              <option value="">All Threat Types</option>
              {THREAT_TYPES.map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
            </select>
            <select className="g-select text-xs" value={filterProvider} onChange={e => setFilterProvider(e.target.value)}>
              <option value="">All Providers</option>
              <option value="aws">AWS</option>
              <option value="azure">Azure</option>
              <option value="gcp">GCP</option>
            </select>
            <ActionButton variant="ghost" icon={RefreshCw} onClick={reload} className="text-xs" title="Refresh" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2">
              <DataTable<any>
                loading={loading}
                rows={threats}
                rowKey={(t: any) => t.id}
                onRowClick={t => setSelected(selected?.id === t.id ? null : t)}
                rowStyle={(t: any) => selected?.id === t.id ? SELECTED_ROW_STYLE : undefined}
                columns={[
                  { key: 'type', header: 'Threat Type', render: (t: any) => <span className="text-xs text-[var(--text-1)] capitalize">{t.threat_type.replace(/_/g, ' ')}</span> },
                  { key: 'resource', header: 'Resource', render: (t: any) => <span className="text-xs font-mono text-[var(--text-2)] truncate max-w-[140px] block">{t.resource_id}</span> },
                  { key: 'source_ip', header: 'Source IP', render: (t: any) => <span className="text-xs font-mono" style={{ color: 'var(--red)' }}>{t.source_ip || '—'}</span> },
                  { key: 'user', header: 'User', render: (t: any) => <span className="text-xs text-[var(--text-3)]">{t.source_user || '—'}</span> },
                  { key: 'provider', header: 'Provider', render: (t: any) => <ProviderBadge provider={t.provider} /> },
                  { key: 'mitre', header: 'MITRE', render: (t: any) => <span className="text-[10px] px-1 py-0.5 rounded" style={{ background: 'var(--accent-bg, var(--blue-bg))', border: '1px solid var(--accent-border)', color: 'var(--accent)' }}>{t.mitre_technique || '—'}</span> },
                  { key: 'severity', header: 'Severity', render: (t: any) => <span className="text-[10px] px-1.5 py-0.5 rounded" style={SEV_STYLE[t.severity] ?? SEV_STYLE.medium}>{t.severity}</span> },
                  { key: 'time', header: 'Time', render: (t: any) => <span className="text-xs text-[var(--text-3)]">{timeAgo(t.created_at)}</span> },
                ]}
              />
            </div>

            <div>
              {selected ? (
                <div className="g-card p-4 space-y-3">
                  <div className="text-sm font-semibold text-[var(--text-1)]">Threat Detail</div>
                  <dl className="space-y-1.5 text-xs">
                    {([
                      ['Type', selected.threat_type?.replace(/_/g, ' ')],
                      ['Resource', selected.resource_id],
                      ['Resource Type', selected.resource_type],
                      ['Provider', selected.provider?.toUpperCase()],
                      ['Region', selected.region],
                      ['Source IP', selected.source_ip || '—'],
                      ['Source User', selected.source_user || '—'],
                      ['MITRE', selected.mitre_technique || '—'],
                      ['Status', selected.status],
                      ['Detected', new Date(selected.created_at).toLocaleString()],
                    ] as [string, string][]).map(([k, v]) => (
                      <div key={k} className="flex justify-between gap-2">
                        <dt className="text-[var(--text-3)]">{k}</dt>
                        <dd className="text-[var(--text-1)] text-right capitalize">{v}</dd>
                      </div>
                    ))}
                  </dl>
                  <div className="space-y-1.5">
                    <div className="text-xs text-[var(--text-3)] font-medium">Response Actions</div>
                    {(['block_ip', 'disable_iam_user', 'isolate_workload', 'rotate_access_key', 'stop_instance'] as string[]).map(action => (
                      <ActionButton key={action} variant="ghost" icon={Zap} className="text-xs w-full justify-start" onClick={() => doRespond(action, selected)} disabled={responding}>
                        {action.replace(/_/g, ' ')}
                      </ActionButton>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="g-card p-4 text-xs text-[var(--text-3)] text-center">Select a threat to respond</div>
              )}
            </div>
          </div>
        </>
      )}

      {subTab === 'vulns' && (
        <DataTable<any>
          rows={vulns}
          rowKey={(v: any) => v.id}
          columns={[
            { key: 'title', header: 'CVE / Finding', render: (v: any) => (
              <div>
                <div className="text-xs font-medium text-[var(--text-1)]">{v.title}</div>
                <div className="text-[10px] text-[var(--text-3)] line-clamp-1">{v.description}</div>
              </div>
            ) },
            { key: 'category', header: 'Category', render: (v: any) => <span className="text-xs text-[var(--text-2)] capitalize">{v.category.replace(/_/g, ' ')}</span> },
            { key: 'resource', header: 'Resource', render: (v: any) => <span className="text-xs font-mono text-[var(--text-3)]">{v.resource_id}</span> },
            { key: 'provider', header: 'Provider', render: (v: any) => <ProviderBadge provider={v.provider} /> },
            { key: 'severity', header: 'Severity', render: (v: any) => <span className="text-[10px] px-1.5 py-0.5 rounded" style={SEV_STYLE[v.severity] ?? SEV_STYLE.medium}>{v.severity}</span> },
            { key: 'scanner', header: 'Scanner', render: (v: any) => <span className="text-[10px] text-[var(--text-3)]">{v.framework}</span> },
            { key: 'time', header: 'Time', render: (v: any) => <span className="text-xs text-[var(--text-3)]">{timeAgo(v.created_at)}</span> },
          ]}
        />
      )}
    </div>
  );
}

// ── Compliance Tab ────────────────────────────────────────────────────────────

function ComplianceTab() {
  const [compliance, setCompliance] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    cloudSecurityAPI.getCompliance().then(r => { setCompliance(r.data ?? []); setLoading(false); });
  }, []);

  const FRAMEWORKS = ['CIS', 'NIST', 'ISO 27001', 'PCI DSS', 'SOC 2', 'HIPAA', 'GDPR'];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center text-xs text-[var(--text-3)]">
        {FRAMEWORKS.map(fw => {
          const comp = compliance.find(c => c.framework === fw);
          const score = comp ? Math.round(comp.score) : 0;
          const scoreColor = score > 85 ? 'var(--green)' : score > 70 ? 'var(--yellow)' : score > 0 ? 'var(--red)' : 'var(--text-3)';
          return (
            <div key={fw} className="g-card p-3 space-y-2">
              <div className="text-xs font-medium text-[var(--text-1)]">{fw}</div>
              <div className="text-2xl font-bold" style={{ color: scoreColor }}>{score > 0 ? `${score}%` : '—'}</div>
              {comp && (
                <div className="space-y-1">
                  <div className="h-1.5 rounded-full bg-[var(--border)]">
                    <div className="h-full rounded-full" style={{ width: `${score}%`, background: score > 85 ? 'var(--green)' : score > 70 ? 'var(--yellow)' : 'var(--red)' }} />
                  </div>
                  <div className="text-[10px] text-[var(--text-3)]">{comp.passed}/{comp.total} controls passed</div>
                </div>
              )}
              {!comp && <div className="text-[10px] text-[var(--text-3)]">Not evaluated</div>}
            </div>
          );
        })}
      </div>

      <DataTable<any>
        loading={loading}
        rows={compliance}
        rowKey={(c: any) => c.framework}
        columns={[
          { key: 'framework', header: 'Framework', render: (c: any) => <span className="font-medium text-[var(--text-1)]">{c.framework}</span> },
          { key: 'score', header: 'Score', render: (c: any) => <span className="text-sm font-bold" style={{ color: c.score > 85 ? 'var(--green)' : c.score > 70 ? 'var(--yellow)' : 'var(--red)' }}>{Math.round(c.score)}%</span> },
          { key: 'passed', header: 'Passed', render: (c: any) => <span className="text-xs" style={{ color: 'var(--green)' }}>{c.passed}</span> },
          { key: 'failed', header: 'Failed', render: (c: any) => <span className="text-xs" style={{ color: 'var(--red)' }}>{c.failed}</span> },
          { key: 'total', header: 'Total', render: (c: any) => <span className="text-xs text-[var(--text-2)]">{c.total}</span> },
          { key: 'progress', header: 'Progress', render: (c: any) => (
            <div className="w-24 h-1.5 rounded-full bg-[var(--border)]">
              <div className="h-full rounded-full" style={{ width: `${c.score}%`, background: c.score > 85 ? 'var(--green)' : c.score > 70 ? 'var(--yellow)' : 'var(--red)' }} />
            </div>
          ) },
        ]}
      />
    </div>
  );
}

// ── Attack Paths Tab ──────────────────────────────────────────────────────────

function AttackPathsTab() {
  const [graph, setGraph] = useState<{ nodes: any[]; edges: any[] }>({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);
  const [timeline, setTimeline] = useState<any[]>([]);

  useEffect(() => {
    Promise.all([cloudSecurityAPI.getAttackPaths(), cloudSecurityAPI.getTimeline()])
      .then(([gr, tr]) => { setGraph(gr.data ?? { nodes: [], edges: [] }); setTimeline(tr.data ?? []); setLoading(false); });
  }, []);

  const nodesByType = useMemo(() => {
    const groups: Record<string, any[]> = {};
    for (const n of graph.nodes) {
      const g = n.type === 'source' ? 'Source' : ['ec2', 'vm', 's3', 'storage_account', 'lambda'].includes(n.type) ? 'Public Assets' : ['iam_role', 'iam_user', 'service_account'].includes(n.type) ? 'Identity' : 'Data / Targets';
      if (!groups[g]) groups[g] = [];
      groups[g].push(n);
    }
    return groups;
  }, [graph]);

  const NODE_STYLE: Record<string, React.CSSProperties> = {
    'Source':        { background: 'var(--red-bg)',    border: '1px solid var(--red-border)',    color: 'var(--red)' },
    'Public Assets': { background: 'var(--orange-bg)', border: '1px solid var(--orange-border)', color: 'var(--orange)' },
    'Identity':      { background: 'var(--accent-bg, var(--blue-bg))', border: '1px solid var(--accent-border)', color: 'var(--accent)' },
    'Data / Targets':{ background: 'var(--blue-bg)',   border: '1px solid var(--blue-border)',   color: 'var(--blue)' },
  };

  return (
    <div className="space-y-4">
      {loading ? <div className="text-[var(--text-3)] text-sm">Loading...</div> : (
        <>
          <SectionCard title="Attack Path Visualization">
            <div className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {Object.entries(nodesByType).map(([groupName, nodes]) => (
                  <div key={groupName} className="space-y-2">
                    <div className="text-[10px] text-[var(--text-3)] font-medium uppercase tracking-wider">{groupName}</div>
                    {nodes.map(n => (
                      <div key={n.id} className="rounded-lg px-3 py-2 text-xs" style={NODE_STYLE[groupName] ?? { background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                        <div className="font-medium">{n.label}</div>
                        {n.permissions && <div className="text-[10px] opacity-70 truncate">{n.permissions}</div>}
                        {n.risk && <div className="text-[10px] opacity-70">Risk: {n.risk}%</div>}
                        {n.sensitive && <div className="text-[10px]" style={{ color: 'var(--yellow)' }}>Sensitive Data</div>}
                      </div>
                    ))}
                  </div>
                ))}
              </div>
              {graph.edges.length > 0 && (
                <div className="space-y-2">
                  <div className="text-xs text-[var(--text-3)] font-medium">Attack Edges ({graph.edges.length})</div>
                  <div className="space-y-1 max-h-40 overflow-y-auto">
                    {graph.edges.map((e: any, i: number) => (
                      <div key={i} className="flex items-center gap-2 text-xs text-[var(--text-2)]">
                        <span className="font-mono text-[10px]" style={{ color: 'var(--red)' }}>{e.source}</span>
                        <span className="text-[var(--text-3)]">→ {e.label} →</span>
                        <span className="text-[var(--accent)] font-mono text-[10px]">{e.target}</span>
                        <span className="ml-auto text-[10px] px-1 py-0.5 rounded" style={SEV_STYLE[e.risk] ?? SEV_STYLE.medium}>{e.risk}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </SectionCard>

          <SectionCard title="Cloud Security Timeline">
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {timeline.map((t: any, i: number) => (
                <div key={i} className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <div className="h-2.5 w-2.5 rounded-full mt-0.5 shrink-0" style={{ background: t.severity === 'critical' ? 'var(--red)' : t.severity === 'high' ? 'var(--orange)' : 'var(--yellow)' }} />
                    {i < timeline.length - 1 && <div className="w-px flex-1 bg-[var(--border)] mt-1" />}
                  </div>
                  <div className="pb-2 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] px-1 py-0.5 rounded" style={t.event_type === 'threat' ? SEV_STYLE.critical : t.event_type === 'drift' ? SEV_STYLE.high : SEV_STYLE.low}>{t.event_type}</span>
                      <ProviderBadge provider={t.provider} />
                    </div>
                    <div className="text-xs text-[var(--text-1)] mt-0.5 capitalize">{t.title.replace(/_/g, ' ')}</div>
                    <div className="text-[10px] text-[var(--text-3)]">{t.region} · {timeAgo(t.created_at)}</div>
                  </div>
                </div>
              ))}
            </div>
          </SectionCard>
        </>
      )}
    </div>
  );
}

// ── Intelligence Tab ──────────────────────────────────────────────────────────

function IntelligenceTab() {
  const [intel, setIntel] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [aiResult, setAiResult] = useState<any>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiMode, setAiMode] = useState('answer');
  const [question, setQuestion] = useState('');

  useEffect(() => {
    cloudSecurityAPI.getThreatIntel().then(r => { setIntel(r.data); setLoading(false); });
  }, []);

  const runAI = async () => {
    if (!question.trim() && aiMode === 'answer') return;
    setAiLoading(true); setAiResult(null);
    const r = await cloudSecurityAPI.analyzeAI({ mode: aiMode, question });
    setAiResult(r.data); setAiLoading(false);
  };

  const EXAMPLES = [
    'This S3 bucket became public three hours ago and contains sensitive documents.',
    'The IAM role has AdministratorAccess but has not been used in six months.',
    'This EC2 instance is communicating with infrastructure associated with known malicious activity.',
  ];

  const barMax = useMemo(() => Math.max(...(intel?.by_threat_type ?? []).map((t: any) => t.count), 1), [intel]);

  return (
    <div className="space-y-4">
      {loading ? <div className="text-[var(--text-3)] text-sm">Loading...</div> : intel && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <SectionCard title="Top Attack Sources">
            <div className="space-y-3">
              {(intel.top_source_ips ?? []).map((ip: any, i: number) => (
                <div key={i} className="space-y-1">
                  <div className="flex justify-between text-xs"><span className="font-mono" style={{ color: 'var(--red)' }}>{ip.ip}</span><span className="text-[var(--text-2)] font-bold">{ip.hits}</span></div>
                  <div className="text-[10px] text-[var(--text-3)] capitalize">{ip.threat_types}</div>
                </div>
              ))}
            </div>
          </SectionCard>

          <SectionCard title="Threat Type Distribution">
            <div className="space-y-3">
              {(intel.by_threat_type ?? []).map((t: any) => (
                <div key={t.threat_type} className="space-y-1">
                  <div className="flex justify-between text-xs"><span className="capitalize text-[var(--text-2)]">{t.threat_type.replace(/_/g, ' ')}</span><span className="text-[var(--accent)] font-bold">{t.count}</span></div>
                  <div className="h-1 rounded-full bg-[var(--border)]"><div className="h-full rounded-full bg-[var(--accent)]" style={{ width: `${Math.round(t.count / barMax * 100)}%` }} /></div>
                </div>
              ))}
            </div>
          </SectionCard>

          <SectionCard title="Threats by Cloud Provider">
            <div className="space-y-2">
              {(intel.by_provider ?? []).map((p: any) => (
                <div key={p.provider} className="flex items-center justify-between text-xs">
                  <ProviderBadge provider={p.provider} />
                  <span className="text-[var(--text-2)] font-bold">{p.count} threats</span>
                </div>
              ))}
            </div>
          </SectionCard>
        </div>
      )}

      <SectionCard title="AI Cloud Security Assistant">
        <div className="space-y-3">
          <div className="flex gap-2 flex-wrap">
            <select className="g-select text-xs" value={aiMode} onChange={e => setAiMode(e.target.value)}>
              <option value="answer">Ask a Question</option>
              <option value="explain">Explain Finding</option>
              <option value="remediate">Remediation Plan</option>
              <option value="prioritize">Prioritize Risks</option>
            </select>
          </div>
          <div className="space-y-2">
            <textarea
              className="g-input text-xs w-full resize-none"
              rows={3}
              placeholder={aiMode === 'answer' ? 'Ask anything about your cloud security posture...' : aiMode === 'explain' ? 'Describe the finding or paste the finding title...' : aiMode === 'remediate' ? 'Describe the misconfiguration to remediate...' : 'Describe your current environment context...'}
              value={question}
              onChange={e => setQuestion(e.target.value)}
            />
            <div className="flex flex-wrap gap-1.5">
              {EXAMPLES.map((ex, i) => (
                <button key={i} className="text-[10px] px-2 py-1 rounded bg-[var(--glass-bg)] border border-[var(--border)] text-[var(--text-3)] hover:text-[var(--text-1)] hover:border-[var(--accent-border)] transition-colors" onClick={() => setQuestion(ex)}>
                  {ex.slice(0, 50)}...
                </button>
              ))}
            </div>
            <ActionButton variant="primary" icon={Brain} onClick={runAI} loading={aiLoading} className="text-xs">
              Analyze
            </ActionButton>
          </div>

          {aiResult && (
            <div className="space-y-3 border-t border-[var(--border)] pt-3">
              {(aiResult.answer || aiResult.explanation || aiResult.summary) && (
                <div className="g-card p-3 text-sm text-[var(--text-2)] leading-relaxed">{aiResult.answer || aiResult.explanation || aiResult.summary}</div>
              )}
              {aiResult.confidence !== undefined && <div className="text-xs text-[var(--text-3)]">Confidence: <span className="text-[var(--accent)]">{aiResult.confidence}%</span></div>}
              {aiResult.cli_commands?.length > 0 && (
                <div>
                  <div className="text-xs text-[var(--text-3)] mb-1">CLI Commands</div>
                  {aiResult.cli_commands.map((cmd: any, i: number) => (
                    <div key={i} className="g-card p-2 mb-1 space-y-0.5">
                      <div className="text-[10px] text-[var(--accent)]">{cmd.provider?.toUpperCase()} · {cmd.description}</div>
                      <div className="text-xs font-mono text-[var(--text-1)] bg-black/20 px-2 py-1 rounded">{cmd.command}</div>
                    </div>
                  ))}
                </div>
              )}
              {aiResult.recommended_actions?.length > 0 && (
                <div>
                  <div className="text-xs text-[var(--text-3)] mb-1">Recommended Actions</div>
                  <ul className="space-y-1">{aiResult.recommended_actions.map((a: string, i: number) => (
                    <li key={i} className="text-xs text-[var(--text-2)] flex gap-1.5 items-start"><ChevronRight className="h-3 w-3 shrink-0 mt-0.5" style={{ color: 'var(--accent)' }} />{a}</li>
                  ))}</ul>
                </div>
              )}
              {aiResult.prioritized_actions?.length > 0 && (
                <DataTable<any>
                  rows={aiResult.prioritized_actions}
                  rowKey={(a: any, i: number) => i}
                  columns={[
                    { key: 'action', header: 'Action', render: (a: any) => <span className="text-xs text-[var(--text-1)]">{a.action}</span> },
                    { key: 'severity', header: 'Severity', render: (a: any) => <span className="text-[10px] px-1.5 py-0.5 rounded" style={SEV_STYLE[a.severity] ?? SEV_STYLE.medium}>{a.severity}</span> },
                    { key: 'effort', header: 'Effort', render: (a: any) => <span className="text-xs text-[var(--text-2)]">{a.effort}</span> },
                    { key: 'impact', header: 'Impact', render: (a: any) => <span className="text-xs text-[var(--text-2)]">{a.impact}</span> },
                  ]}
                />
              )}
            </div>
          )}
        </div>
      </SectionCard>
    </div>
  );
}

// ── Analytics Tab ─────────────────────────────────────────────────────────────

function AnalyticsTab() {
  const [analytics, setAnalytics] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [reportResult, setReportResult] = useState<any>(null);
  const [generating, setGenerating] = useState(false);
  const [reportType, setReportType] = useState('executive');

  useEffect(() => { cloudSecurityAPI.getAnalytics().then(r => { setAnalytics(r.data); setLoading(false); }); }, []);

  const generateReport = async () => {
    setGenerating(true);
    const r = await cloudSecurityAPI.generateReport({ report_type: reportType });
    setReportResult(r.data); setGenerating(false);
  };

  const threatBarMax = useMemo(() => Math.max(...(analytics?.threat_trend ?? []).map((d: any) => d.count), 1), [analytics]);

  if (loading) return <div className="text-[var(--text-3)] text-sm p-4">Loading...</div>;

  return (
    <div className="space-y-6">
      {analytics && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <SectionCard title="Most Exposed Resources">
              <div className="space-y-3">
                {(analytics.top_exposed ?? []).map((r: any, i: number) => (
                  <div key={i} className="flex items-center justify-between text-xs">
                    <div><div className="text-[var(--text-1)]">{r.name}</div><div className="text-[10px] text-[var(--text-3)]">{r.resource_type} · {r.provider}</div></div>
                    <span className="font-bold" style={{ color: r.risk_score > 75 ? 'var(--red)' : 'var(--orange)' }}>{r.risk_score}</span>
                  </div>
                ))}
              </div>
            </SectionCard>

            <SectionCard title="Top Misconfigurations">
              <div className="space-y-3">
                {(analytics.top_misconfigs ?? []).map((m: any, i: number) => (
                  <div key={i} className="flex items-center justify-between text-xs">
                    <span className="text-[var(--text-2)] capitalize">{m.category.replace(/_/g, ' ')}</span>
                    <div className="flex gap-1.5">
                      {m.critical > 0 && <span className="font-bold" style={{ color: 'var(--red)' }}>{m.critical}C</span>}
                      <span className="text-[var(--text-3)]">{m.total}</span>
                    </div>
                  </div>
                ))}
              </div>
            </SectionCard>

            <SectionCard title="Regions with Highest Risk">
              <div className="space-y-3">
                {(analytics.by_region ?? []).map((r: any, i: number) => (
                  <div key={i} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="text-[var(--text-2)]">{r.region}</span>
                      <span className="font-bold" style={{ color: r.avg_risk > 60 ? 'var(--orange)' : 'var(--text-2)' }}>{r.avg_risk}% risk</span>
                    </div>
                    <div className="h-1 rounded-full bg-[var(--border)]"><div className="h-full rounded-full" style={{ width: `${r.avg_risk}%`, background: r.avg_risk > 60 ? 'var(--orange)' : 'var(--accent)' }} /></div>
                  </div>
                ))}
              </div>
            </SectionCard>
          </div>

          <SectionCard title="14-Day Threat Trend">
            <div className="flex items-end gap-1 h-20">
              {(analytics.threat_trend ?? []).map((d: any, i: number) => (
                <div key={i} className="flex-1 flex flex-col items-center gap-0.5">
                  <div className="w-full rounded-sm opacity-70 hover:opacity-100" style={{ height: `${Math.round(d.count / threatBarMax * 72) + 2}px`, background: 'var(--red)' }} title={`${d.date}: ${d.count}`} />
                  {i % 3 === 0 && <div className="text-[9px] text-[var(--text-3)]">{d.date?.slice(5)}</div>}
                </div>
              ))}
            </div>
          </SectionCard>
        </>
      )}

      <SectionCard
        title="Security Reports"
        actions={
          <div className="flex items-center gap-2">
            <select className="g-select text-xs" value={reportType} onChange={e => setReportType(e.target.value)}>
              <option value="executive">Executive Summary</option>
              <option value="cspm">CSPM Report</option>
              <option value="iam">IAM Risk Report</option>
              <option value="compliance">Compliance Report</option>
              <option value="exposure">Exposure Report</option>
            </select>
            <ActionButton variant="primary" icon={FileText} onClick={generateReport} loading={generating} className="text-xs">Generate</ActionButton>
          </div>
        }
      >
        {reportResult && (
          <div className="space-y-4">
            <div className="text-base font-semibold text-[var(--text-1)]">{reportResult.title}</div>
            <div className="g-card p-3 text-sm text-[var(--text-2)] leading-relaxed">{reportResult.executive_summary}</div>
            {reportResult.risk_breakdown && (
              <div className="grid grid-cols-4 gap-3">
                <MetricCard label="Critical" value={reportResult.risk_breakdown.critical} color="var(--red)" />
                <MetricCard label="High"     value={reportResult.risk_breakdown.high}     color="var(--orange)" />
                <MetricCard label="Medium"   value={reportResult.risk_breakdown.medium}   color="var(--yellow)" />
                <MetricCard label="Low"      value={reportResult.risk_breakdown.low}      color="var(--blue)" />
              </div>
            )}
            {reportResult.key_findings?.length > 0 && (
              <div><div className="text-xs text-[var(--text-3)] mb-1">Key Findings</div>
                <ul className="space-y-1">{reportResult.key_findings.map((f: string, i: number) => <li key={i} className="text-xs text-[var(--text-2)] flex gap-1.5 items-start"><AlertTriangle className="h-3 w-3 shrink-0 mt-0.5" style={{ color: 'var(--red)' }} />{f}</li>)}</ul>
              </div>
            )}
            {reportResult.top_recommendations?.length > 0 && (
              <div><div className="text-xs text-[var(--text-3)] mb-1">Top Recommendations</div>
                <div className="space-y-1">{reportResult.top_recommendations.map((r: any, i: number) => (
                  <div key={i} className="flex items-start gap-2 text-xs"><span className="text-[var(--accent)] font-bold shrink-0">#{r.priority}</span><div><div className="text-[var(--text-1)]">{r.action}</div><div className="text-[10px] text-[var(--text-3)]">Effort: {r.estimated_effort}</div></div></div>
                ))}</div>
              </div>
            )}
            {reportResult.compliance_summary && (
              <div className="g-card p-3 text-xs text-[var(--text-2)]">{reportResult.compliance_summary}</div>
            )}
          </div>
        )}
      </SectionCard>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function CloudSecurityPage() {
  const [tab, setTab] = useState('overview');
  const loaded = useRef<Record<string, boolean>>({});

  if (!loaded.current[tab]) loaded.current[tab] = true;

  const TAB_CONTENT: Record<string, React.ReactNode> = {
    overview:     <OverviewTab />,
    inventory:    <InventoryTab />,
    posture:      <PostureTab />,
    identity:     <IdentityTab />,
    detection:    <DetectionTab />,
    compliance:   <ComplianceTab />,
    attackpaths:  <AttackPathsTab />,
    intelligence: <IntelligenceTab />,
    analytics:    <AnalyticsTab />,
  };

  return (
    <RootLayout title="Cloud Security" subtitle="CSPM · CIEM · CWPP · Multi-Cloud Asset Security">
      <div style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 20 }}>
        <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: 4 }}>
          <TabBar
            tabs={TABS.map(t => ({ key: t.id, label: t.label, icon: t.icon }))}
            active={tab}
            onChange={setTab}
          />
        </div>

        <div>
          {TABS.map(({ id }) => loaded.current[id] && (
            <div key={id} style={{ display: tab === id ? 'block' : 'none' }}>
              {TAB_CONTENT[id]}
            </div>
          ))}
        </div>
      </div>
    </RootLayout>
  );
}
