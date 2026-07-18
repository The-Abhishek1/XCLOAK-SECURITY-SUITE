'use client';

import { useState, useEffect, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { cloudSecurityAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import { Activity, AlertCircle, AlertTriangle, BarChart2, Brain, CheckCircle, Cloud, Database, Eye, FileText, GitBranch, Globe, Key, Plus, RefreshCw, Server, Shield, XCircle, Zap, Lock } from '@/lib/icon-stubs';

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

function StatCard({ label, value, sub, color = 'var(--text-1)' }: { label: string; value: number | string; sub?: string; color?: string }) {
  return (
    <div className="g-card p-4 space-y-1">
      <div className="text-xs text-[var(--text-3)]">{label}</div>
      <div className="text-2xl font-bold" style={{ color }}>{value}</div>
      {sub && <div className="text-xs text-[var(--text-3)]">{sub}</div>}
    </div>
  );
}

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
        <StatCard label="AWS Accounts"     value={data.aws_accounts}     color="var(--orange)" />
        <StatCard label="Azure Subs"       value={data.azure_subs}       color="var(--blue)" />
        <StatCard label="GCP Projects"     value={data.gcp_projects}     color="var(--green)" />
        <StatCard label="Multi-Cloud Risk" value={`${data.multi_cloud_risk}%`} color={riskColor} />
        <StatCard label="Compliance Score" value={`${data.compliance_score}%`} color={compColor} />
      </div>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <StatCard label="Total Assets"    value={data.total_assets} />
        <StatCard label="Public Assets"  value={data.public_assets}   color={data.public_assets > 0 ? 'var(--red)' : 'var(--green)'} />
        <StatCard label="Critical Findings" value={data.critical_findings} color="var(--red)" />
        <StatCard label="IAM Risks"      value={data.iam_risks}       color="var(--orange)" />
        <StatCard label="Active Threats" value={data.active_threats}  color={data.active_threats > 0 ? 'var(--red)' : 'var(--green)'} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="g-card p-4 space-y-3">
          <div className="text-sm font-medium text-[var(--text-1)]">Asset Inventory by Provider</div>
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
        </div>

        <div className="g-card p-4 space-y-3">
          <div className="text-sm font-medium text-[var(--text-1)]">Recent Cloud Threats</div>
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
        </div>
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
        <div className="g-card p-4 space-y-3 border border-[var(--accent-border)]">
          <div className="text-sm font-semibold text-[var(--text-1)]">Connect Cloud Account</div>
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
            <button className="g-btn-primary text-xs" onClick={createAccount}>Connect</button>
            <button className="g-btn text-xs" onClick={() => setShowAddAccount(false)}>Cancel</button>
          </div>
        </div>
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
        <button className="g-btn text-xs" onClick={reload}><RefreshCw className="h-3.5 w-3.5" /></button>
      </div>

      {loading ? <div className="text-[var(--text-3)] text-sm">Loading...</div> : (
        <div className="g-card overflow-hidden">
          <table className="g-table w-full">
            <thead className="g-thead"><tr>
              <th>Resource</th><th>Type</th><th>Provider</th><th>Region</th><th>Owner</th>
              <th>Risk</th><th>Exposed</th><th>Last Activity</th>
            </tr></thead>
            <tbody>
              {assets.map((a: any) => (
                <tr key={a.id} className="g-tr">
                  <td>
                    <div className="flex items-center gap-2">
                      {RESOURCE_ICONS[a.resource_type] ?? <Cloud className="h-4 w-4 text-[var(--text-3)]" />}
                      <span className="font-medium text-[var(--text-1)]">{a.name}</span>
                    </div>
                  </td>
                  <td><span className="text-xs font-mono text-[var(--accent)]">{a.resource_type}</span></td>
                  <td><ProviderBadge provider={a.provider} /></td>
                  <td><span className="text-xs text-[var(--text-2)]">{a.region}</span></td>
                  <td><span className="text-xs text-[var(--text-3)]">{a.owner || '—'}</span></td>
                  <td>
                    <div className="flex items-center gap-1">
                      <div className="w-12 h-1.5 rounded-full bg-[var(--border)]">
                        <div className="h-full rounded-full"
                          style={{ width: `${a.risk_score}%`, background: a.risk_score > 75 ? 'var(--red)' : a.risk_score > 50 ? 'var(--orange)' : 'var(--yellow)' }} />
                      </div>
                      <span className="text-xs font-bold" style={{ color: a.risk_score > 75 ? 'var(--red)' : a.risk_score > 50 ? 'var(--orange)' : 'var(--text-2)' }}>{a.risk_score}</span>
                    </div>
                  </td>
                  <td>{a.internet_exposed ? <Eye className="h-3.5 w-3.5" style={{ color: 'var(--red)' }} /> : <Lock className="h-3.5 w-3.5" style={{ color: 'var(--green)' }} />}</td>
                  <td><span className="text-xs text-[var(--text-3)]">{a.last_activity ? timeAgo(a.last_activity) : '—'}</span></td>
                </tr>
              ))}
              {assets.length === 0 && <tr><td colSpan={8} className="text-center text-[var(--text-3)] py-8">No assets found</td></tr>}
            </tbody>
          </table>
        </div>
      )}
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
          <StatCard label="Public Buckets"  value={exposure.public_buckets}  color={exposure.public_buckets > 0 ? 'var(--red)' : 'var(--green)'} />
          <StatCard label="Open Databases"  value={exposure.open_databases}  color={exposure.open_databases > 0 ? 'var(--red)' : 'var(--green)'} />
          <StatCard label="Public APIs"     value={exposure.public_apis}     color={exposure.public_apis > 0 ? 'var(--orange)' : 'var(--green)'} />
          <StatCard label="Weak Sec Groups" value={exposure.weak_security_groups} color="var(--orange)" />
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="g-card p-4 space-y-3">
          <div className="text-sm font-medium text-[var(--text-1)]">Finding Categories</div>
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

        <div className="lg:col-span-2 space-y-3">
          <div className="flex items-center gap-2">
            <select className="g-select text-xs" value={filterSev} onChange={e => setFilterSev(e.target.value)}>
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
            </select>
            <button className="g-btn text-xs" onClick={reload}><RefreshCw className="h-3.5 w-3.5" /></button>
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
                        <button className="g-btn-primary text-xs" onClick={() => doResolve(f.id)} disabled={responding}>Mark Resolved</button>
                        <button className="g-btn text-xs" onClick={e => { e.stopPropagation(); setSelected(null); }}>Close</button>
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

      <div className="g-card p-4 space-y-3">
        <div className="text-sm font-medium text-[var(--text-1)]">Infrastructure Drift</div>
        <div className="g-card overflow-hidden">
          <table className="g-table w-full">
            <thead className="g-thead"><tr>
              <th>Resource</th><th>Change</th><th>Previous</th><th>New State</th><th>Changed By</th><th>Provider</th><th>Severity</th><th>Time</th><th></th>
            </tr></thead>
            <tbody>
              {drift.map((d: any) => (
                <tr key={d.id} className={`g-tr ${d.acknowledged ? 'opacity-50' : ''}`}>
                  <td><span className="text-xs font-mono text-[var(--text-1)]">{d.resource_id}</span></td>
                  <td><span className="text-xs text-[var(--text-2)] capitalize">{d.change_type.replace(/_/g, ' ')}</span></td>
                  <td><span className="text-xs font-mono" style={{ color: 'var(--green)' }}>{d.previous_state || '—'}</span></td>
                  <td><span className="text-xs font-mono" style={{ color: 'var(--red)' }}>{d.new_state || '—'}</span></td>
                  <td><span className="text-xs text-[var(--text-3)]">{d.changed_by || '—'}</span></td>
                  <td><ProviderBadge provider={d.provider} /></td>
                  <td><span className="text-[10px] px-1.5 py-0.5 rounded" style={SEV_STYLE[d.severity] ?? SEV_STYLE.medium}>{d.severity}</span></td>
                  <td><span className="text-xs text-[var(--text-3)]">{timeAgo(d.created_at)}</span></td>
                  <td>{!d.acknowledged && <button className="text-xs text-[var(--text-3)] hover:text-[var(--green)]" onClick={() => doAckDrift(d.id)}>Ack</button>}</td>
                </tr>
              ))}
              {drift.length === 0 && <tr><td colSpan={9} className="text-center text-[var(--text-3)] py-6 text-xs">No drift detected</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
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
          <StatCard label="Dormant Accounts"      value={risks.dormant_accounts}      color="var(--orange)" />
          <StatCard label="No MFA"                value={risks.no_mfa}                color="var(--red)" />
          <StatCard label="Old Access Keys (90d)" value={risks.old_access_keys}       color="var(--orange)" />
          <StatCard label="Excessive Permissions" value={risks.excessive_permissions} color="var(--red)" />
          <StatCard label="Privilege Escalation"  value={risks.privilege_escalation}  color="var(--red)" />
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
        <button className="g-btn text-xs" onClick={reload}><RefreshCw className="h-3.5 w-3.5" /></button>
      </div>

      {loading ? <div className="text-[var(--text-3)] text-sm">Loading...</div> : (
        <div className="g-card overflow-hidden">
          <table className="g-table w-full">
            <thead className="g-thead"><tr>
              <th>Identity</th><th>Type</th><th>Provider</th><th>Permissions</th>
              <th>MFA</th><th>Key Age</th><th>Dormant</th><th>Last Used</th><th>Risk</th>
            </tr></thead>
            <tbody>
              {identities.map((id: any) => (
                <tr key={id.id} className="g-tr">
                  <td><span className="font-medium text-[var(--text-1)]">{id.name}</span></td>
                  <td><span className="text-xs text-[var(--text-2)] capitalize">{id.identity_type.replace(/_/g, ' ')}</span></td>
                  <td><ProviderBadge provider={id.provider} /></td>
                  <td><span className="text-xs font-mono text-[var(--text-3)] truncate max-w-[160px] block">{id.permissions || '—'}</span></td>
                  <td>{id.mfa_enabled ? <CheckCircle className="h-3.5 w-3.5" style={{ color: 'var(--green)' }} /> : id.identity_type === 'iam_user' ? <XCircle className="h-3.5 w-3.5" style={{ color: 'var(--red)' }} /> : <span className="text-[10px] text-[var(--text-3)]">N/A</span>}</td>
                  <td><span className="text-xs" style={{ color: id.access_key_age_days > 90 ? 'var(--red)' : 'var(--text-2)', fontWeight: id.access_key_age_days > 90 ? 700 : undefined }}>{id.access_key_age_days > 0 ? `${id.access_key_age_days}d` : '—'}</span></td>
                  <td>{id.is_dormant ? <AlertTriangle className="h-3.5 w-3.5" style={{ color: 'var(--orange)' }} /> : <CheckCircle className="h-3.5 w-3.5" style={{ color: 'var(--green)' }} />}</td>
                  <td><span className="text-xs text-[var(--text-3)]">{id.last_used ? timeAgo(id.last_used) : 'Never'}</span></td>
                  <td><span className="text-[10px] px-1.5 py-0.5 rounded" style={SEV_STYLE[id.risk_level] ?? SEV_STYLE.low}>{id.risk_level}</span></td>
                </tr>
              ))}
              {identities.length === 0 && <tr><td colSpan={9} className="text-center text-[var(--text-3)] py-8">No identities found</td></tr>}
            </tbody>
          </table>
        </div>
      )}
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
          <button key={s} onClick={() => setSubTab(s)}
            className={`text-xs px-3 py-1.5 rounded border transition-colors ${subTab === s ? 'border-[var(--accent)] text-[var(--accent)] bg-[var(--accent)]/5' : 'border-[var(--border)] text-[var(--text-3)] hover:text-[var(--text-1)]'}`}>
            {s === 'threats' ? `Cloud Threats (${threats.length})` : `Vulnerabilities (${vulns.length})`}
          </button>
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
            <button className="g-btn text-xs" onClick={reload}><RefreshCw className="h-3.5 w-3.5" /></button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2">
              {loading ? <div className="text-[var(--text-3)] text-sm">Loading...</div> : (
                <div className="g-card overflow-hidden">
                  <table className="g-table w-full">
                    <thead className="g-thead"><tr>
                      <th>Threat Type</th><th>Resource</th><th>Source IP</th><th>User</th><th>Provider</th><th>MITRE</th><th>Severity</th><th>Time</th>
                    </tr></thead>
                    <tbody>
                      {threats.map((t: any) => (
                        <tr key={t.id} className={`g-tr cursor-pointer ${selected?.id === t.id ? 'bg-[var(--accent)]/5' : ''}`} onClick={() => setSelected(selected?.id === t.id ? null : t)}>
                          <td><span className="text-xs text-[var(--text-1)] capitalize">{t.threat_type.replace(/_/g, ' ')}</span></td>
                          <td><span className="text-xs font-mono text-[var(--text-2)] truncate max-w-[140px] block">{t.resource_id}</span></td>
                          <td><span className="text-xs font-mono" style={{ color: 'var(--red)' }}>{t.source_ip || '—'}</span></td>
                          <td><span className="text-xs text-[var(--text-3)]">{t.source_user || '—'}</span></td>
                          <td><ProviderBadge provider={t.provider} /></td>
                          <td><span className="text-[10px] px-1 py-0.5 rounded" style={{ background: 'var(--accent-bg, var(--blue-bg))', border: '1px solid var(--accent-border)', color: 'var(--accent)' }}>{t.mitre_technique || '—'}</span></td>
                          <td><span className="text-[10px] px-1.5 py-0.5 rounded" style={SEV_STYLE[t.severity] ?? SEV_STYLE.medium}>{t.severity}</span></td>
                          <td><span className="text-xs text-[var(--text-3)]">{timeAgo(t.created_at)}</span></td>
                        </tr>
                      ))}
                      {threats.length === 0 && <tr><td colSpan={8} className="text-center text-[var(--text-3)] py-8">No threats detected</td></tr>}
                    </tbody>
                  </table>
                </div>
              )}
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
                      <button key={action} className="g-btn text-xs w-full text-left flex items-center gap-1.5" onClick={() => doRespond(action, selected)} disabled={responding}>
                        <Zap className="h-3 w-3" />{action.replace(/_/g, ' ')}
                      </button>
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
        <div className="g-card overflow-hidden">
          <table className="g-table w-full">
            <thead className="g-thead"><tr>
              <th>CVE / Finding</th><th>Category</th><th>Resource</th><th>Provider</th><th>Severity</th><th>Scanner</th><th>Time</th>
            </tr></thead>
            <tbody>
              {vulns.map((v: any) => (
                <tr key={v.id} className="g-tr">
                  <td><div className="text-xs font-medium text-[var(--text-1)]">{v.title}</div><div className="text-[10px] text-[var(--text-3)] line-clamp-1">{v.description}</div></td>
                  <td><span className="text-xs text-[var(--text-2)] capitalize">{v.category.replace(/_/g, ' ')}</span></td>
                  <td><span className="text-xs font-mono text-[var(--text-3)]">{v.resource_id}</span></td>
                  <td><ProviderBadge provider={v.provider} /></td>
                  <td><span className="text-[10px] px-1.5 py-0.5 rounded" style={SEV_STYLE[v.severity] ?? SEV_STYLE.medium}>{v.severity}</span></td>
                  <td><span className="text-[10px] text-[var(--text-3)]">{v.framework}</span></td>
                  <td><span className="text-xs text-[var(--text-3)]">{timeAgo(v.created_at)}</span></td>
                </tr>
              ))}
              {vulns.length === 0 && <tr><td colSpan={7} className="text-center text-[var(--text-3)] py-8">No vulnerabilities found</td></tr>}
            </tbody>
          </table>
        </div>
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

      {loading ? <div className="text-[var(--text-3)] text-sm">Loading...</div> : (
        <div className="g-card overflow-hidden">
          <table className="g-table w-full">
            <thead className="g-thead"><tr>
              <th>Framework</th><th>Score</th><th>Passed</th><th>Failed</th><th>Total</th><th>Progress</th>
            </tr></thead>
            <tbody>
              {compliance.map((c: any) => (
                <tr key={c.framework} className="g-tr">
                  <td><span className="font-medium text-[var(--text-1)]">{c.framework}</span></td>
                  <td><span className="text-sm font-bold" style={{ color: c.score > 85 ? 'var(--green)' : c.score > 70 ? 'var(--yellow)' : 'var(--red)' }}>{Math.round(c.score)}%</span></td>
                  <td><span className="text-xs" style={{ color: 'var(--green)' }}>{c.passed}</span></td>
                  <td><span className="text-xs" style={{ color: 'var(--red)' }}>{c.failed}</span></td>
                  <td><span className="text-xs text-[var(--text-2)]">{c.total}</span></td>
                  <td>
                    <div className="w-24 h-1.5 rounded-full bg-[var(--border)]">
                      <div className="h-full rounded-full" style={{ width: `${c.score}%`, background: c.score > 85 ? 'var(--green)' : c.score > 70 ? 'var(--yellow)' : 'var(--red)' }} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
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
          <div className="g-card p-4 space-y-4">
            <div className="text-sm font-medium text-[var(--text-1)]">Attack Path Visualization</div>
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

          <div className="g-card p-4 space-y-3">
            <div className="text-sm font-medium text-[var(--text-1)]">Cloud Security Timeline</div>
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
          </div>
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
          <div className="g-card p-4 space-y-3">
            <div className="text-sm font-medium text-[var(--text-1)]">Top Attack Sources</div>
            {(intel.top_source_ips ?? []).map((ip: any, i: number) => (
              <div key={i} className="space-y-1">
                <div className="flex justify-between text-xs"><span className="font-mono" style={{ color: 'var(--red)' }}>{ip.ip}</span><span className="text-[var(--text-2)] font-bold">{ip.hits}</span></div>
                <div className="text-[10px] text-[var(--text-3)] capitalize">{ip.threat_types}</div>
              </div>
            ))}
          </div>

          <div className="g-card p-4 space-y-3">
            <div className="text-sm font-medium text-[var(--text-1)]">Threat Type Distribution</div>
            {(intel.by_threat_type ?? []).map((t: any) => (
              <div key={t.threat_type} className="space-y-1">
                <div className="flex justify-between text-xs"><span className="capitalize text-[var(--text-2)]">{t.threat_type.replace(/_/g, ' ')}</span><span className="text-[var(--accent)] font-bold">{t.count}</span></div>
                <div className="h-1 rounded-full bg-[var(--border)]"><div className="h-full rounded-full bg-[var(--accent)]" style={{ width: `${Math.round(t.count / barMax * 100)}%` }} /></div>
              </div>
            ))}
          </div>

          <div className="g-card p-4 space-y-3">
            <div className="text-sm font-medium text-[var(--text-1)]">Threats by Cloud Provider</div>
            {(intel.by_provider ?? []).map((p: any) => (
              <div key={p.provider} className="flex items-center justify-between text-xs">
                <ProviderBadge provider={p.provider} />
                <span className="text-[var(--text-2)] font-bold">{p.count} threats</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="g-card p-4 space-y-3">
        <div className="text-sm font-medium text-[var(--text-1)]">AI Cloud Security Assistant</div>
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
          <button className="g-btn-primary text-xs flex items-center gap-1.5" onClick={runAI} disabled={aiLoading}>
            <Brain className="h-3.5 w-3.5" />{aiLoading ? 'Analyzing...' : 'Analyze'}
          </button>
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
                  <li key={i} className="text-xs text-[var(--text-2)] flex gap-1.5"><span className="text-[var(--accent)]">›</span>{a}</li>
                ))}</ul>
              </div>
            )}
            {aiResult.prioritized_actions?.length > 0 && (
              <div className="g-card overflow-hidden">
                <table className="g-table w-full">
                  <thead className="g-thead"><tr><th>Action</th><th>Severity</th><th>Effort</th><th>Impact</th></tr></thead>
                  <tbody>
                    {aiResult.prioritized_actions.map((a: any, i: number) => (
                      <tr key={i} className="g-tr">
                        <td><span className="text-xs text-[var(--text-1)]">{a.action}</span></td>
                        <td><span className="text-[10px] px-1.5 py-0.5 rounded" style={SEV_STYLE[a.severity] ?? SEV_STYLE.medium}>{a.severity}</span></td>
                        <td><span className="text-xs text-[var(--text-2)]">{a.effort}</span></td>
                        <td><span className="text-xs text-[var(--text-2)]">{a.impact}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
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
            <div className="g-card p-4 space-y-3">
              <div className="text-sm font-medium text-[var(--text-1)]">Most Exposed Resources</div>
              {(analytics.top_exposed ?? []).map((r: any, i: number) => (
                <div key={i} className="flex items-center justify-between text-xs">
                  <div><div className="text-[var(--text-1)]">{r.name}</div><div className="text-[10px] text-[var(--text-3)]">{r.resource_type} · {r.provider}</div></div>
                  <span className="font-bold" style={{ color: r.risk_score > 75 ? 'var(--red)' : 'var(--orange)' }}>{r.risk_score}</span>
                </div>
              ))}
            </div>

            <div className="g-card p-4 space-y-3">
              <div className="text-sm font-medium text-[var(--text-1)]">Top Misconfigurations</div>
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

            <div className="g-card p-4 space-y-3">
              <div className="text-sm font-medium text-[var(--text-1)]">Regions with Highest Risk</div>
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
          </div>

          <div className="g-card p-4 space-y-3">
            <div className="text-sm font-medium text-[var(--text-1)]">14-Day Threat Trend</div>
            <div className="flex items-end gap-1 h-20">
              {(analytics.threat_trend ?? []).map((d: any, i: number) => (
                <div key={i} className="flex-1 flex flex-col items-center gap-0.5">
                  <div className="w-full rounded-sm opacity-70 hover:opacity-100" style={{ height: `${Math.round(d.count / threatBarMax * 72) + 2}px`, background: 'var(--red)' }} title={`${d.date}: ${d.count}`} />
                  {i % 3 === 0 && <div className="text-[9px] text-[var(--text-3)]">{d.date?.slice(5)}</div>}
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      <div className="g-card p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="text-sm font-medium text-[var(--text-1)]">Security Reports</div>
          <div className="flex items-center gap-2">
            <select className="g-select text-xs" value={reportType} onChange={e => setReportType(e.target.value)}>
              <option value="executive">Executive Summary</option>
              <option value="cspm">CSPM Report</option>
              <option value="iam">IAM Risk Report</option>
              <option value="compliance">Compliance Report</option>
              <option value="exposure">Exposure Report</option>
            </select>
            <button className="g-btn-primary text-xs flex items-center gap-1.5" onClick={generateReport} disabled={generating}>
              <FileText className="h-3.5 w-3.5" />{generating ? 'Generating...' : 'Generate'}
            </button>
          </div>
        </div>

        {reportResult && (
          <div className="space-y-4">
            <div className="text-base font-semibold text-[var(--text-1)]">{reportResult.title}</div>
            <div className="g-card p-3 text-sm text-[var(--text-2)] leading-relaxed">{reportResult.executive_summary}</div>
            {reportResult.risk_breakdown && (
              <div className="grid grid-cols-4 gap-3">
                <StatCard label="Critical" value={reportResult.risk_breakdown.critical} color="var(--red)" />
                <StatCard label="High"     value={reportResult.risk_breakdown.high}     color="var(--orange)" />
                <StatCard label="Medium"   value={reportResult.risk_breakdown.medium}   color="var(--yellow)" />
                <StatCard label="Low"      value={reportResult.risk_breakdown.low}      color="var(--blue)" />
              </div>
            )}
            {reportResult.key_findings?.length > 0 && (
              <div><div className="text-xs text-[var(--text-3)] mb-1">Key Findings</div>
                <ul className="space-y-1">{reportResult.key_findings.map((f: string, i: number) => <li key={i} className="text-xs text-[var(--text-2)] flex gap-1.5"><span style={{ color: 'var(--red)' }}>!</span>{f}</li>)}</ul>
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
      </div>
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
    <RootLayout>
      <div style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 20 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>Cloud Security</h1>
          <div style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 4 }}>CSPM · CIEM · CWPP · Multi-Cloud Asset Security</div>
        </div>

        <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', overflowX: 'auto' }}>
          {TABS.map(({ id, label }) => (
            <button key={id} onClick={() => setTab(id)}
              style={{ padding: '8px 16px', fontSize: 12, fontWeight: tab === id ? 600 : 400, color: tab === id ? 'var(--accent)' : 'var(--text-3)', background: 'transparent', border: 'none', borderBottom: tab === id ? '2px solid var(--accent)' : '2px solid transparent', cursor: 'pointer', whiteSpace: 'nowrap' }}>
              {label}
            </button>
          ))}
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
