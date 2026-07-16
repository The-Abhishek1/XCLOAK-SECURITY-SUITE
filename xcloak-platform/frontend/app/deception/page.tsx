'use client';

import { useState, useEffect, useRef, useMemo } from 'react';
import { deceptionAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import {
  Shield, Bug, Key, Globe, Activity, GitBranch, Brain, Zap, BarChart2,
  Plus, RefreshCw, Trash2, CheckCircle, AlertTriangle, XCircle,
  Database, Server, Cloud, Lock, Play,
  FileText,
} from 'lucide-react';

const TABS = [
  { id: 'dashboard',    label: 'Dashboard',    icon: Activity },
  { id: 'decoys',       label: 'Decoys',       icon: Shield },
  { id: 'honeytokens',  label: 'Honeytokens',  icon: Key },
  { id: 'honeypots',    label: 'Honeypots',    icon: Bug },
  { id: 'triggers',     label: 'Triggers',     icon: Zap },
  { id: 'campaigns',    label: 'Campaigns',    icon: Globe },
  { id: 'graph',        label: 'Graph',        icon: GitBranch },
  { id: 'intelligence', label: 'Intelligence', icon: Brain },
  { id: 'analytics',    label: 'Analytics',    icon: BarChart2 },
];

const SEV_BG: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-400 border border-red-500/30',
  high:     'bg-orange-500/10 text-orange-400 border border-orange-500/30',
  medium:   'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30',
  low:      'bg-blue-500/10 text-blue-400 border border-blue-500/30',
};

const HEALTH_ICON: Record<string, React.ReactNode> = {
  online:   <CheckCircle className="h-3.5 w-3.5 text-green-400" />,
  degraded: <AlertTriangle className="h-3.5 w-3.5 text-yellow-400" />,
  offline:  <XCircle className="h-3.5 w-3.5 text-red-400" />,
};

const TYPE_ICON: Record<string, React.ReactNode> = {
  honeypot:         <Bug className="h-4 w-4 text-purple-400" />,
  ad_object:        <Server className="h-4 w-4 text-blue-400" />,
  database:         <Database className="h-4 w-4 text-cyan-400" />,
  container:        <Cloud className="h-4 w-4 text-indigo-400" />,
  cloud:            <Cloud className="h-4 w-4 text-sky-400" />,
  credential:       <Key className="h-4 w-4 text-yellow-400" />,
  file:             <FileText className="h-4 w-4 text-green-400" />,
  api_key:          <Lock className="h-4 w-4 text-red-400" />,
  cloud_credential: <Cloud className="h-4 w-4 text-indigo-400" />,
};

function StatCard({ label, value, sub, color = 'text-white' }: { label: string; value: number | string; sub?: string; color?: string }) {
  return (
    <div className="g-card p-4 space-y-1">
      <div className="text-xs text-[var(--text-3)]">{label}</div>
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      {sub && <div className="text-xs text-[var(--text-3)]">{sub}</div>}
    </div>
  );
}

// ── Dashboard Tab ─────────────────────────────────────────────────────────────

function DashboardTab() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    deceptionAPI.getDashboard().then(r => { setData(r.data); setLoading(false); });
  }, []);

  const barMax = useMemo(() => {
    const trend = data?.trend ?? [];
    return Math.max(...trend.map((t: any) => t.count), 1);
  }, [data]);

  if (loading) return <div className="text-[var(--text-3)] text-sm p-4">Loading...</div>;
  if (!data) return <div className="text-[var(--text-3)] p-4">No data</div>;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Active Decoys"      value={data.active_decoys}        color="text-[var(--accent)]" />
        <StatCard label="Triggered Decoys"   value={data.triggered_decoys}     color="text-orange-400" />
        <StatCard label="Active Campaigns"   value={data.active_campaigns}     color="text-red-400" />
        <StatCard label="High Risk (24h)"    value={data.high_risk_24h}        color="text-red-400" />
        <StatCard label="Total Triggers"     value={data.total_triggers} />
        <StatCard label="Offline Decoys"     value={data.offline_decoys}       color={data.offline_decoys > 0 ? 'text-yellow-400' : 'text-green-400'} />
        <StatCard label="Active Honeytokens" value={data.active_honeytokens} />
        <StatCard label="Tokens Triggered"   value={data.honeytokens_triggered} color={data.honeytokens_triggered > 0 ? 'text-red-400' : 'text-green-400'} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="g-card p-4 space-y-3">
          <div className="text-sm font-medium text-[var(--text-1)]">14-Day Trigger Trend</div>
          <div className="flex items-end gap-1 h-24">
            {(data.trend ?? []).map((t: any, i: number) => (
              <div key={i} className="flex-1 flex flex-col items-center gap-0.5">
                <div
                  className="w-full rounded-sm bg-[var(--accent)] opacity-70 hover:opacity-100 transition-opacity"
                  style={{ height: `${Math.round((t.count / barMax) * 88) + 2}px` }}
                  title={`${t.date}: ${t.count}`}
                />
                <div className="text-[9px] text-[var(--text-3)] hidden md:block">{t.date?.slice(5)}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="g-card p-4 space-y-3">
          <div className="text-sm font-medium text-[var(--text-1)]">Recent Triggers</div>
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {(data.recent_triggers ?? []).map((t: any) => (
              <div key={t.id} className="flex items-start justify-between gap-3 text-xs py-1.5 border-b border-[var(--border)] last:border-0">
                <div className="space-y-0.5">
                  <div className="font-medium text-[var(--text-1)] capitalize">{t.event_type.replace(/_/g, ' ')}</div>
                  <div className="text-[var(--text-3)]">
                    {t.attacker_ip}
                    {t.decoy_name ? ` → ${t.decoy_name}` : ''}
                    {t.token_name ? ` → ${t.token_name}` : ''}
                  </div>
                </div>
                <div className="flex flex-col items-end gap-0.5 shrink-0">
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${SEV_BG[t.severity] ?? SEV_BG.medium}`}>{t.severity}</span>
                  <span className="text-[var(--text-3)]">{timeAgo(t.created_at)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Decoys Tab ────────────────────────────────────────────────────────────────

function DecoysTab() {
  const [decoys, setDecoys] = useState<any[]>([]);
  const [templates, setTemplates] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterType, setFilterType] = useState('');
  const [showDeploy, setShowDeploy] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [form, setForm] = useState({ template: '', protocol: '', locations: '', count: 1, platform: 'linux' });

  const reload = () => {
    setLoading(true);
    Promise.all([
      deceptionAPI.getDecoys(filterType ? { type: filterType } : {}),
      deceptionAPI.getTemplates(),
    ]).then(([dr, tr]) => {
      setDecoys(dr.data ?? []);
      setTemplates(tr.data ?? []);
      setLoading(false);
    });
  };
  useEffect(() => { reload(); }, [filterType]);

  const doDeploy = async () => {
    if (!form.template || !form.locations) return;
    setDeploying(true);
    await deceptionAPI.deploy({
      template: form.template,
      protocol: form.protocol,
      locations: form.locations.split(',').map((s: string) => s.trim()),
      count: form.count,
      platform: form.platform,
    });
    setShowDeploy(false);
    setDeploying(false);
    reload();
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <select className="g-select text-xs" value={filterType} onChange={e => setFilterType(e.target.value)}>
            <option value="">All Types</option>
            <option value="honeypot">Honeypot</option>
            <option value="ad_object">AD Object</option>
            <option value="database">Database</option>
            <option value="container">Container</option>
            <option value="cloud">Cloud</option>
          </select>
          <button className="g-btn text-xs" onClick={reload}><RefreshCw className="h-3.5 w-3.5" /></button>
        </div>
        <button className="g-btn-primary text-xs flex items-center gap-1.5" onClick={() => setShowDeploy(true)}>
          <Plus className="h-3.5 w-3.5" /> Deploy Decoys
        </button>
      </div>

      {showDeploy && (
        <div className="g-card p-4 space-y-3 border border-[var(--accent-border)]">
          <div className="text-sm font-semibold text-[var(--text-1)]">Deploy from Template</div>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            <div>
              <label className="text-xs text-[var(--text-3)] mb-1 block">Template</label>
              <select className="g-select text-xs w-full" value={form.template} onChange={e => setForm(f => ({ ...f, template: e.target.value }))}>
                <option value="">Select template...</option>
                {templates.map((t: any) => <option key={t.id} value={t.id}>{t.name}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-[var(--text-3)] mb-1 block">Protocol</label>
              <input className="g-input text-xs w-full" placeholder="ssh / rdp / smb / http" value={form.protocol} onChange={e => setForm(f => ({ ...f, protocol: e.target.value }))} />
            </div>
            <div>
              <label className="text-xs text-[var(--text-3)] mb-1 block">Platform</label>
              <select className="g-select text-xs w-full" value={form.platform} onChange={e => setForm(f => ({ ...f, platform: e.target.value }))}>
                <option value="linux">Linux</option>
                <option value="windows">Windows</option>
                <option value="cloud">Cloud</option>
              </select>
            </div>
            <div className="col-span-2">
              <label className="text-xs text-[var(--text-3)] mb-1 block">Locations (comma-separated)</label>
              <input className="g-input text-xs w-full" placeholder="DMZ, Internal LAN, DB Segment" value={form.locations} onChange={e => setForm(f => ({ ...f, locations: e.target.value }))} />
            </div>
            <div>
              <label className="text-xs text-[var(--text-3)] mb-1 block">Count</label>
              <input className="g-input text-xs w-full" type="number" min={1} max={10} value={form.count} onChange={e => setForm(f => ({ ...f, count: Number(e.target.value) }))} />
            </div>
          </div>
          <div className="flex gap-2">
            <button className="g-btn-primary text-xs flex items-center gap-1.5" onClick={doDeploy} disabled={deploying}>
              <Play className="h-3.5 w-3.5" />{deploying ? 'Deploying...' : 'Deploy'}
            </button>
            <button className="g-btn text-xs" onClick={() => setShowDeploy(false)}>Cancel</button>
          </div>
        </div>
      )}

      {loading ? <div className="text-[var(--text-3)] text-sm">Loading...</div> : (
        <div className="g-card overflow-hidden">
          <table className="g-table w-full">
            <thead className="g-thead"><tr>
              <th>Name</th><th>Type</th><th>Protocol</th><th>IP:Port</th>
              <th>Location</th><th>Health</th><th>Triggers</th><th>Last Hit</th><th></th>
            </tr></thead>
            <tbody>
              {decoys.map((d: any) => (
                <tr key={d.id} className="g-tr">
                  <td>
                    <div className="flex items-center gap-2">
                      {TYPE_ICON[d.type] ?? <Shield className="h-4 w-4 text-[var(--text-3)]" />}
                      <span className="font-medium text-[var(--text-1)]">{d.name}</span>
                    </div>
                  </td>
                  <td><span className="text-xs text-[var(--text-2)] capitalize">{d.type}</span></td>
                  <td><span className="text-xs font-mono text-[var(--accent)]">{d.protocol || '—'}</span></td>
                  <td><span className="text-xs font-mono text-[var(--text-2)]">{d.ip || '—'}{d.port ? `:${d.port}` : ''}</span></td>
                  <td><span className="text-xs text-[var(--text-2)]">{d.location || '—'}</span></td>
                  <td>
                    <div className="flex items-center gap-1">
                      {HEALTH_ICON[d.health] ?? HEALTH_ICON.offline}
                      <span className="text-xs capitalize text-[var(--text-2)]">{d.health}</span>
                    </div>
                  </td>
                  <td><span className={`text-sm font-bold ${d.trigger_count > 0 ? 'text-orange-400' : 'text-[var(--text-3)]'}`}>{d.trigger_count}</span></td>
                  <td><span className="text-xs text-[var(--text-3)]">{d.last_triggered ? timeAgo(d.last_triggered) : 'Never'}</span></td>
                  <td>
                    <button className="p-1 hover:text-red-400 text-[var(--text-3)] transition-colors" onClick={() => deceptionAPI.deleteDecoy(d.id).then(reload)}>
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
              {decoys.length === 0 && (
                <tr><td colSpan={9} className="text-center text-[var(--text-3)] py-8">No decoys deployed</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      <div className="g-card p-4 space-y-3">
        <div className="text-sm font-medium text-[var(--text-1)]">Available Templates</div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {templates.map((t: any) => (
            <div
              key={t.id}
              className="g-card p-3 space-y-1 hover:border-[var(--accent-border)] transition-colors cursor-pointer"
              onClick={() => { setForm(f => ({ ...f, template: t.id, protocol: t.protocol })); setShowDeploy(true); }}
            >
              <div className="text-xs font-medium text-[var(--text-1)]">{t.name}</div>
              <div className="text-[10px] text-[var(--text-3)] line-clamp-2">{t.description}</div>
              <div className="text-[10px] font-mono text-[var(--accent)]">{t.protocol}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Honeytokens Tab ───────────────────────────────────────────────────────────

function HoneytokensTab() {
  const [tokens, setTokens] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', type: 'credential', subtype: '', value: '', location: '', owner: '', watchlist_category: '' });

  const reload = () => {
    setLoading(true);
    deceptionAPI.getHoneytokens().then(r => { setTokens(r.data ?? []); setLoading(false); });
  };
  useEffect(() => { reload(); }, []);

  const doCreate = async () => {
    if (!form.name) return;
    await deceptionAPI.createHoneytoken(form);
    setShowCreate(false);
    setForm({ name: '', type: 'credential', subtype: '', value: '', location: '', owner: '', watchlist_category: '' });
    reload();
  };

  const FIELDS = [
    { label: 'Name', key: 'name', placeholder: 'svc_backup_cred' },
    { label: 'Type', key: 'type', placeholder: '', options: ['credential', 'file', 'api_key', 'url', 'registry', 'cloud_credential'] },
    { label: 'Subtype', key: 'subtype', placeholder: 'domain_user / database_password' },
    { label: 'Value', key: 'value', placeholder: 'AKIAIOSFODNN7EXAMPLE' },
    { label: 'Location', key: 'location', placeholder: 'Share: \\\\FILESVR\\scripts\\' },
    { label: 'Owner', key: 'owner', placeholder: 'IT Operations' },
    { label: 'Watchlist Category', key: 'watchlist_category', placeholder: 'privileged_accounts' },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <button className="g-btn text-xs" onClick={reload}><RefreshCw className="h-3.5 w-3.5" /></button>
        <button className="g-btn-primary text-xs flex items-center gap-1.5" onClick={() => setShowCreate(true)}>
          <Plus className="h-3.5 w-3.5" /> Create Honeytoken
        </button>
      </div>

      {showCreate && (
        <div className="g-card p-4 space-y-3 border border-[var(--accent-border)]">
          <div className="text-sm font-semibold text-[var(--text-1)]">New Honeytoken</div>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            {FIELDS.map(({ label, key, placeholder, options }) => (
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
            <button className="g-btn-primary text-xs" onClick={doCreate}>Create</button>
            <button className="g-btn text-xs" onClick={() => setShowCreate(false)}>Cancel</button>
          </div>
        </div>
      )}

      {loading ? <div className="text-[var(--text-3)] text-sm">Loading...</div> : (
        <div className="g-card overflow-hidden">
          <table className="g-table w-full">
            <thead className="g-thead"><tr>
              <th>Name</th><th>Type</th><th>Location</th><th>Owner</th>
              <th>Category</th><th>Triggered</th><th>Last Hit</th><th></th>
            </tr></thead>
            <tbody>
              {tokens.map((t: any) => (
                <tr key={t.id} className="g-tr">
                  <td>
                    <div className="flex items-center gap-2">
                      {TYPE_ICON[t.type] ?? <Key className="h-4 w-4 text-[var(--text-3)]" />}
                      <span className="font-medium text-[var(--text-1)]">{t.name}</span>
                    </div>
                  </td>
                  <td><span className="text-xs text-[var(--text-2)] capitalize">{t.type}</span></td>
                  <td><span className="text-xs text-[var(--text-3)] font-mono truncate max-w-[180px] block">{t.location || '—'}</span></td>
                  <td><span className="text-xs text-[var(--text-2)]">{t.owner || '—'}</span></td>
                  <td><span className="text-xs text-[var(--text-3)]">{t.watchlist_category || '—'}</span></td>
                  <td>
                    {t.triggered ? (
                      <div className="flex items-center gap-1">
                        <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
                        <span className="text-xs text-red-400 font-medium">{t.trigger_count}x</span>
                      </div>
                    ) : (
                      <span className="text-xs text-green-400">Clean</span>
                    )}
                  </td>
                  <td><span className="text-xs text-[var(--text-3)]">{t.last_triggered ? timeAgo(t.last_triggered) : 'Never'}</span></td>
                  <td>
                    <button className="p-1 hover:text-red-400 text-[var(--text-3)]" onClick={() => deceptionAPI.deleteHoneytoken(t.id).then(reload)}>
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
              {tokens.length === 0 && <tr><td colSpan={8} className="text-center text-[var(--text-3)] py-8">No honeytokens deployed</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Honeypots Tab ─────────────────────────────────────────────────────────────

function HoneypotsTab() {
  const [decoys, setDecoys] = useState<any[]>([]);
  const [health, setHealth] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([deceptionAPI.getDecoys({ type: 'honeypot' }), deceptionAPI.getHealth()])
      .then(([dr, hr]) => { setDecoys(dr.data ?? []); setHealth(hr.data); setLoading(false); });
  }, []);

  const PROTOCOLS = ['SSH', 'RDP', 'SMB', 'HTTP', 'FTP', 'Telnet', 'MySQL', 'MSSQL', 'LDAP', 'Kubernetes API', 'AWS API'];

  return (
    <div className="space-y-4">
      {health && (
        <div className="grid grid-cols-3 gap-3">
          <StatCard label="Online"   value={health.online}   color="text-green-400" />
          <StatCard label="Degraded" value={health.degraded} color="text-yellow-400" />
          <StatCard label="Offline"  value={health.offline}  color="text-red-400" />
        </div>
      )}

      <div className="g-card p-4 space-y-3">
        <div className="text-sm font-medium text-[var(--text-1)]">Supported Protocols</div>
        <div className="flex flex-wrap gap-2">
          {PROTOCOLS.map(p => (
            <span key={p} className="px-2.5 py-1 rounded-full text-xs bg-[var(--glass-bg)] border border-[var(--border)] text-[var(--text-2)]">{p}</span>
          ))}
        </div>
      </div>

      {loading ? <div className="text-[var(--text-3)] text-sm">Loading...</div> : (
        <div className="g-card overflow-hidden">
          <table className="g-table w-full">
            <thead className="g-thead"><tr>
              <th>Name</th><th>Protocol</th><th>IP:Port</th><th>Platform</th>
              <th>Location</th><th>Health</th><th>Integrity</th><th>Version</th><th>Last Heartbeat</th>
            </tr></thead>
            <tbody>
              {decoys.map((d: any) => (
                <tr key={d.id} className="g-tr">
                  <td><span className="font-medium text-[var(--text-1)]">{d.name}</span></td>
                  <td><span className="text-xs font-mono text-[var(--accent)] uppercase">{d.protocol || '—'}</span></td>
                  <td><span className="text-xs font-mono text-[var(--text-2)]">{d.ip}{d.port ? `:${d.port}` : ''}</span></td>
                  <td><span className="text-xs text-[var(--text-2)] capitalize">{d.platform || '—'}</span></td>
                  <td><span className="text-xs text-[var(--text-3)]">{d.location}</span></td>
                  <td>
                    <div className="flex items-center gap-1">
                      {HEALTH_ICON[d.health] ?? HEALTH_ICON.offline}
                      <span className="text-xs capitalize">{d.health}</span>
                    </div>
                  </td>
                  <td>{d.integrity_ok ? <CheckCircle className="h-3.5 w-3.5 text-green-400" /> : <AlertTriangle className="h-3.5 w-3.5 text-yellow-400" />}</td>
                  <td><span className="text-xs font-mono text-[var(--text-3)]">{d.version}</span></td>
                  <td><span className="text-xs text-[var(--text-3)]">{d.last_heartbeat ? timeAgo(d.last_heartbeat) : 'Never'}</span></td>
                </tr>
              ))}
              {decoys.length === 0 && <tr><td colSpan={9} className="text-center text-[var(--text-3)] py-8">No honeypots active</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Triggers Tab ──────────────────────────────────────────────────────────────

function TriggersTab() {
  const [triggers, setTriggers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<any>(null);
  const [responding, setResponding] = useState(false);
  const [filterSev, setFilterSev] = useState('');

  const reload = () => {
    setLoading(true);
    deceptionAPI.getTriggers(filterSev ? { severity: filterSev } : {})
      .then(r => { setTriggers(r.data ?? []); setLoading(false); });
  };
  useEffect(() => { reload(); }, [filterSev]);

  const doRespond = async (action: string) => {
    if (!selected) return;
    setResponding(true);
    await deceptionAPI.respond({ trigger_id: selected.id, action, attacker_ip: selected.attacker_ip });
    setResponding(false);
    reload();
  };

  const RESPONSE_ACTIONS = ['block_ip', 'isolate_endpoint', 'create_alert', 'collect_memory', 'disable_user'];

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <select className="g-select text-xs" value={filterSev} onChange={e => setFilterSev(e.target.value)}>
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
        </select>
        <button className="g-btn text-xs" onClick={reload}><RefreshCw className="h-3.5 w-3.5" /></button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          {loading ? <div className="text-[var(--text-3)] text-sm">Loading...</div> : (
            <div className="g-card overflow-hidden">
              <table className="g-table w-full">
                <thead className="g-thead"><tr>
                  <th>Event</th><th>Attacker</th><th>Asset</th><th>Severity</th><th>Time</th><th>Status</th>
                </tr></thead>
                <tbody>
                  {triggers.map((t: any) => (
                    <tr
                      key={t.id}
                      className={`g-tr cursor-pointer ${selected?.id === t.id ? 'bg-[var(--accent)]/5' : ''}`}
                      onClick={() => setSelected(t)}
                    >
                      <td><span className="text-xs text-[var(--text-1)] capitalize">{t.event_type.replace(/_/g, ' ')}</span></td>
                      <td>
                        <div>
                          <div className="text-xs font-mono text-[var(--text-1)]">{t.attacker_ip}</div>
                          {t.attacker_user && <div className="text-[10px] text-[var(--text-3)]">{t.attacker_user}</div>}
                        </div>
                      </td>
                      <td><span className="text-xs text-[var(--text-2)]">{t.decoy_name || t.token_name || '—'}</span></td>
                      <td><span className={`text-[10px] px-1.5 py-0.5 rounded ${SEV_BG[t.severity] ?? SEV_BG.medium}`}>{t.severity}</span></td>
                      <td><span className="text-xs text-[var(--text-3)]">{timeAgo(t.created_at)}</span></td>
                      <td>{t.responded
                        ? <CheckCircle className="h-3.5 w-3.5 text-green-400" />
                        : <div className="h-1.5 w-1.5 rounded-full bg-red-400 animate-pulse" />}
                      </td>
                    </tr>
                  ))}
                  {triggers.length === 0 && <tr><td colSpan={6} className="text-center text-[var(--text-3)] py-8">No triggers</td></tr>}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div>
          {selected ? (
            <div className="g-card p-4 space-y-4">
              <div className="text-sm font-semibold text-[var(--text-1)]">Trigger Detail</div>
              <dl className="space-y-2 text-xs">
                {([
                  ['Event', selected.event_type?.replace(/_/g, ' ')],
                  ['Attacker IP', selected.attacker_ip],
                  ['Attacker User', selected.attacker_user || '—'],
                  ['Source Host', selected.source_host || '—'],
                  ['Asset', selected.decoy_name || selected.token_name || '—'],
                  ['Severity', selected.severity],
                  ['Time', new Date(selected.created_at).toLocaleString()],
                ] as [string, string][]).map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-2">
                    <dt className="text-[var(--text-3)]">{k}</dt>
                    <dd className="text-[var(--text-1)] text-right capitalize">{v}</dd>
                  </div>
                ))}
              </dl>
              <div className="space-y-2">
                <div className="text-xs text-[var(--text-3)] font-medium">Response Actions</div>
                {RESPONSE_ACTIONS.map(action => (
                  <button key={action} className="g-btn text-xs w-full text-left flex items-center gap-2" onClick={() => doRespond(action)} disabled={responding}>
                    <Zap className="h-3 w-3" />{action.replace(/_/g, ' ')}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div className="g-card p-4 text-xs text-[var(--text-3)] text-center">Select a trigger to see details and respond</div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Campaigns Tab ─────────────────────────────────────────────────────────────

function CampaignsTab() {
  const [campaigns, setCampaigns] = useState<any[]>([]);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [selected, setSelected] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([deceptionAPI.getCampaigns(), deceptionAPI.getTimeline()])
      .then(([cr, tr]) => { setCampaigns(cr.data ?? []); setTimeline(tr.data ?? []); setLoading(false); });
  }, []);

  const camTimeline = useMemo(
    () => selected ? timeline.filter((t: any) => t.campaign_name === selected.name) : timeline,
    [selected, timeline],
  );

  return (
    <div className="space-y-4">
      {loading ? <div className="text-[var(--text-3)] text-sm">Loading...</div> : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="space-y-3">
            <div className="text-sm font-medium text-[var(--text-1)]">Active Campaigns</div>
            {campaigns.map((c: any) => (
              <div
                key={c.id}
                className={`g-card p-4 space-y-3 cursor-pointer hover:border-[var(--accent-border)] transition-colors ${selected?.id === c.id ? 'border-[var(--accent-border)]' : ''}`}
                onClick={() => setSelected(selected?.id === c.id ? null : c)}
              >
                <div className="flex items-center justify-between">
                  <div className="font-medium text-[var(--text-1)]">{c.name}</div>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded ${SEV_BG[c.severity] ?? SEV_BG.medium}`}>{c.severity}</span>
                </div>
                <div className="grid grid-cols-3 gap-2 text-xs">
                  <div><div className="text-[var(--text-3)]">Attacker IP</div><div className="font-mono text-[var(--text-1)]">{c.attacker_ip || '—'}</div></div>
                  <div><div className="text-[var(--text-3)]">Decoys Hit</div><div className="text-orange-400 font-bold">{c.decoys_hit}</div></div>
                  <div><div className="text-[var(--text-3)]">Tokens Used</div><div className="text-red-400 font-bold">{c.tokens_triggered}</div></div>
                </div>
                {c.malware_family && (
                  <div className="text-xs"><span className="text-[var(--text-3)]">Malware: </span><span className="text-[var(--accent)]">{c.malware_family}</span></div>
                )}
                {c.mitre_techniques && (
                  <div className="flex flex-wrap gap-1">
                    {c.mitre_techniques.split(',').map((t: string) => (
                      <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--glass-bg)] border border-[var(--border)] text-[var(--text-3)]">{t.trim()}</span>
                    ))}
                  </div>
                )}
                <div className="text-[10px] text-[var(--text-3)]">
                  Started {timeAgo(c.started_at)}{c.ended_at ? ` · Ended ${timeAgo(c.ended_at)}` : ' · Active'}
                </div>
              </div>
            ))}
            {campaigns.length === 0 && <div className="g-card p-4 text-xs text-[var(--text-3)] text-center">No campaigns detected</div>}
          </div>

          <div>
            <div className="text-sm font-medium text-[var(--text-1)] mb-3">
              Attack Timeline {selected ? `— ${selected.name}` : '(all events)'}
            </div>
            <div className="space-y-2 max-h-[500px] overflow-y-auto">
              {camTimeline.map((t: any, i: number) => (
                <div key={t.id} className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <div className={`h-2.5 w-2.5 rounded-full mt-0.5 shrink-0 ${
                      t.severity === 'critical' ? 'bg-red-400' :
                      t.severity === 'high' ? 'bg-orange-400' : 'bg-yellow-400'
                    }`} />
                    {i < camTimeline.length - 1 && <div className="w-px flex-1 bg-[var(--border)] mt-1" />}
                  </div>
                  <div className="pb-3 flex-1">
                    <div className="text-xs text-[var(--text-1)] capitalize">{t.event_type.replace(/_/g, ' ')}</div>
                    <div className="text-[10px] text-[var(--text-3)]">{t.attacker_ip} · {t.decoy_name || t.token_name || '—'}</div>
                    <div className="text-[10px] text-[var(--text-3)]">{timeAgo(t.created_at)}</div>
                  </div>
                </div>
              ))}
              {camTimeline.length === 0 && <div className="text-xs text-[var(--text-3)]">No timeline events</div>}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Graph Tab ─────────────────────────────────────────────────────────────────

function GraphTab() {
  const [graph, setGraph] = useState<{ nodes: any[]; edges: any[] }>({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    deceptionAPI.getGraph().then(r => { setGraph(r.data ?? { nodes: [], edges: [] }); setLoading(false); });
  }, []);

  const attackers = graph.nodes.filter(n => n.type === 'attacker');
  const decoys    = graph.nodes.filter(n => n.type === 'decoy');
  const tokens    = graph.nodes.filter(n => n.type === 'honeytoken');

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        <StatCard label="Attacker IPs"     value={attackers.length} color="text-red-400" />
        <StatCard label="Triggered Decoys" value={decoys.length}    color="text-orange-400" />
        <StatCard label="Used Tokens"      value={tokens.length}    color="text-yellow-400" />
      </div>

      {loading ? <div className="text-[var(--text-3)] text-sm">Loading...</div> : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {([
              { label: 'Attackers', nodes: attackers, color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/30', icon: <Globe className="h-4 w-4 text-red-400" /> },
              { label: 'Decoys Hit', nodes: decoys, color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/30', icon: <Shield className="h-4 w-4 text-orange-400" /> },
              { label: 'Tokens Used', nodes: tokens, color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/30', icon: <Key className="h-4 w-4 text-yellow-400" /> },
            ] as { label: string; nodes: any[]; color: string; bg: string; icon: React.ReactNode }[]).map(({ label, nodes, color, bg, icon }) => (
              <div key={label} className="g-card p-4 space-y-3">
                <div className="flex items-center gap-2 text-sm font-medium text-[var(--text-1)]">{icon}{label}</div>
                <div className="space-y-2">
                  {nodes.map(n => (
                    <div key={n.id} className={`rounded-lg px-3 py-2 border text-xs ${bg}`}>
                      <div className={`font-mono font-medium ${color}`}>{n.label}</div>
                      {n.hits !== undefined && <div className="text-[var(--text-3)]">{n.hits} hits</div>}
                      {n.trigger_count !== undefined && <div className="text-[var(--text-3)]">{n.trigger_count} triggers</div>}
                      {n.subtype && <div className="text-[var(--text-3)] capitalize">{n.subtype}</div>}
                    </div>
                  ))}
                  {nodes.length === 0 && <div className="text-xs text-[var(--text-3)]">None</div>}
                </div>
              </div>
            ))}
          </div>

          {graph.edges.length > 0 && (
            <div className="g-card p-4 space-y-3">
              <div className="text-sm font-medium text-[var(--text-1)]">Attack Connections ({graph.edges.length})</div>
              <div className="g-card overflow-hidden">
                <table className="g-table w-full">
                  <thead className="g-thead"><tr><th>Source</th><th>Action</th><th>Target</th><th>Severity</th></tr></thead>
                  <tbody>
                    {graph.edges.map((e: any, i: number) => (
                      <tr key={i} className="g-tr">
                        <td><span className="text-xs font-mono text-red-400">{e.source?.replace('atk-', '')}</span></td>
                        <td><span className="text-xs text-[var(--text-2)] capitalize">{e.label?.replace(/_/g, ' ')}</span></td>
                        <td><span className="text-xs text-[var(--text-2)]">{e.target}</span></td>
                        <td><span className={`text-[10px] px-1.5 py-0.5 rounded ${SEV_BG[e.severity] ?? SEV_BG.medium}`}>{e.severity}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── Intelligence Tab ──────────────────────────────────────────────────────────

function IntelligenceTab() {
  const [triggers, setTriggers] = useState<any[]>([]);
  const [ip, setIp] = useState('');
  const [intel, setIntel] = useState<any>(null);
  const [aiResult, setAiResult] = useState<any>(null);
  const [aiMode, setAiMode] = useState('summarize');
  const [loading, setLoading] = useState(false);
  const [aiLoading, setAiLoading] = useState(false);

  useEffect(() => { deceptionAPI.getTriggers().then(r => setTriggers(r.data ?? [])); }, []);

  const attackerIPs = useMemo(
    () => [...new Set(triggers.map((t: any) => t.attacker_ip).filter(Boolean))],
    [triggers],
  );

  const fetchIntel = async () => {
    if (!ip) return;
    setLoading(true); setIntel(null);
    const r = await deceptionAPI.getThreatIntel(ip);
    setIntel(r.data); setLoading(false);
  };

  const runAI = async () => {
    setAiLoading(true); setAiResult(null);
    const r = await deceptionAPI.analyzeAI({ mode: aiMode, attacker_ip: ip });
    setAiResult(r.data); setAiLoading(false);
  };

  return (
    <div className="space-y-4">
      <div className="g-card p-4 space-y-3">
        <div className="text-sm font-medium text-[var(--text-1)]">Threat Intelligence Lookup</div>
        <div className="flex gap-2 flex-wrap">
          <select className="g-select text-xs flex-1 min-w-[160px]" value={ip} onChange={e => setIp(e.target.value)}>
            <option value="">Select attacker IP...</option>
            {attackerIPs.map(a => <option key={a} value={a}>{a}</option>)}
          </select>
          <input className="g-input text-xs w-36" placeholder="Or type IP..." value={ip} onChange={e => setIp(e.target.value)} />
          <button className="g-btn-primary text-xs" onClick={fetchIntel} disabled={!ip || loading}>{loading ? 'Loading...' : 'Enrich'}</button>
        </div>

        {intel && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-2">
            <StatCard label="Risk Score"  value={`${intel.risk_score}/100`} color={intel.risk_score > 80 ? 'text-red-400' : 'text-orange-400'} />
            <StatCard label="Reputation"  value={intel.ip_reputation} color={intel.ip_reputation === 'malicious' ? 'text-red-400' : 'text-yellow-400'} />
            <StatCard label="Confidence"  value={`${intel.confidence}%`} />
            <StatCard label="Location"    value={intel.geo_country || '—'} sub={intel.geo_city} />
            <div className="col-span-2 g-card p-3 space-y-1">
              <div className="text-xs text-[var(--text-3)]">Threat Actor</div>
              <div className="text-sm font-medium text-red-400">{intel.threat_actor || 'Unknown'}</div>
              <div className="text-xs text-[var(--text-3)]">{intel.campaign}</div>
            </div>
            <div className="col-span-2 g-card p-3 space-y-1">
              <div className="text-xs text-[var(--text-3)]">Malware Families</div>
              <div className="flex flex-wrap gap-1">
                {(intel.malware_families ?? []).map((m: string) => (
                  <span key={m} className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/30 text-red-400">{m}</span>
                ))}
              </div>
            </div>
            <div className="col-span-2 g-card p-3 space-y-1">
              <div className="text-xs text-[var(--text-3)]">MITRE TTPs</div>
              <div className="flex flex-wrap gap-1">
                {(intel.ttps ?? []).map((t: string) => (
                  <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--glass-bg)] border border-[var(--border)] text-[var(--text-3)]">{t}</span>
                ))}
              </div>
            </div>
            <div className="col-span-2 g-card p-3 space-y-1">
              <div className="text-xs text-[var(--text-3)]">Recommended Actions</div>
              <ul className="space-y-1">
                {(intel.recommended_actions ?? []).map((a: string, i: number) => (
                  <li key={i} className="text-xs text-[var(--text-2)] flex gap-1.5"><span className="text-[var(--accent)]">›</span>{a}</li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </div>

      <div className="g-card p-4 space-y-3">
        <div className="text-sm font-medium text-[var(--text-1)]">AI Deception Analysis</div>
        <div className="flex gap-2 flex-wrap">
          <select className="g-select text-xs" value={aiMode} onChange={e => setAiMode(e.target.value)}>
            <option value="summarize">Summarize Engagement</option>
            <option value="attribution">Threat Attribution</option>
            <option value="recommend">Response Recommendations</option>
            <option value="attack_path">Reconstruct Attack Path</option>
          </select>
          <button className="g-btn-primary text-xs" onClick={runAI} disabled={aiLoading}>{aiLoading ? 'Analyzing...' : 'Analyze'}</button>
        </div>

        {aiResult && (
          <div className="space-y-3 pt-2">
            {(aiResult.summary || aiResult.executive_summary) && (
              <div className="g-card p-3 text-sm text-[var(--text-2)] leading-relaxed">{aiResult.summary || aiResult.executive_summary}</div>
            )}
            {aiResult.confidence !== undefined && (
              <div className="text-xs text-[var(--text-3)]">Confidence: <span className="text-[var(--accent)]">{aiResult.confidence}%</span></div>
            )}
            {aiResult.key_findings?.length > 0 && (
              <div>
                <div className="text-xs text-[var(--text-3)] mb-1">Key Findings</div>
                <ul className="space-y-1">{aiResult.key_findings.map((f: string, i: number) => (
                  <li key={i} className="text-xs text-[var(--text-2)] flex gap-1.5"><span className="text-red-400">!</span>{f}</li>
                ))}</ul>
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
            {aiResult.steps?.length > 0 && (
              <div>
                <div className="text-xs text-[var(--text-3)] mb-1">Attack Path</div>
                <div className="space-y-2">{aiResult.steps.map((s: any, i: number) => (
                  <div key={i} className="flex gap-3 items-start">
                    <span className="text-xs text-[var(--accent)] font-bold w-4">{i + 1}</span>
                    <div>
                      <div className="text-xs text-[var(--text-1)]">{s.step || s.asset}</div>
                      <div className="text-[10px] text-[var(--text-3)]">{s.technique}</div>
                    </div>
                  </div>
                ))}</div>
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
  const [watchlists, setWatchlists] = useState<any[]>([]);
  const [policies, setPolicies] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [reportResult, setReportResult] = useState<any>(null);
  const [generating, setGenerating] = useState(false);
  const [showPolicy, setShowPolicy] = useState(false);
  const [policyForm, setPolicyForm] = useState({ name: '', decoy_types: '', locations: '', lifetime_days: 30, rotation_days: 7, alert_threshold: 1, auto_cleanup: true });

  const reload = () => {
    setLoading(true);
    Promise.all([deceptionAPI.getAnalytics(), deceptionAPI.getWatchlists(), deceptionAPI.getPolicies()])
      .then(([ar, wr, pr]) => { setAnalytics(ar.data); setWatchlists(wr.data ?? []); setPolicies(pr.data ?? []); setLoading(false); });
  };
  useEffect(() => { reload(); }, []);

  const generateReport = async () => {
    setGenerating(true);
    const r = await deceptionAPI.generateReport({ report_type: 'executive' });
    setReportResult(r.data);
    setGenerating(false);
  };

  const barMax = useMemo(
    () => Math.max(...(analytics?.daily ?? []).map((d: any) => d.count), 1),
    [analytics],
  );

  if (loading) return <div className="text-[var(--text-3)] text-sm p-4">Loading...</div>;

  return (
    <div className="space-y-6">
      {analytics && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="g-card p-4 space-y-3">
              <div className="text-sm font-medium text-[var(--text-1)]">Top Triggered Decoys</div>
              <div className="space-y-2">
                {(analytics.top_decoys ?? []).map((d: any, i: number) => (
                  <div key={i} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="text-[var(--text-2)]">{d.name}</span>
                      <span className="text-orange-400 font-bold">{d.trigger_count}</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-[var(--border)]">
                      <div className="h-full rounded-full bg-orange-500" style={{ width: `${Math.round(d.trigger_count / (analytics.top_decoys[0]?.trigger_count || 1) * 100)}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="g-card p-4 space-y-3">
              <div className="text-sm font-medium text-[var(--text-1)]">Event Type Breakdown</div>
              <div className="space-y-2">
                {(analytics.by_event_type ?? []).map((e: any, i: number) => (
                  <div key={i} className="flex items-center justify-between gap-2 text-xs">
                    <span className="text-[var(--text-2)] capitalize truncate">{e.event_type.replace(/_/g, ' ')}</span>
                    <span className="text-[var(--accent)] font-bold shrink-0">{e.count}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="g-card p-4 space-y-3">
              <div className="text-sm font-medium text-[var(--text-1)]">Top Attack Sources</div>
              <div className="space-y-2">
                {(analytics.top_sources ?? []).map((s: any, i: number) => (
                  <div key={i} className="flex items-center justify-between gap-2 text-xs">
                    <span className="font-mono text-red-400">{s.ip}</span>
                    <span className="text-[var(--text-2)] font-bold">{s.hits} hits</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {analytics.daily && (
            <div className="g-card p-4 space-y-3">
              <div className="text-sm font-medium text-[var(--text-1)]">30-Day Trigger Trend</div>
              <div className="flex items-end gap-0.5 h-28">
                {analytics.daily.map((d: any, i: number) => (
                  <div key={i} className="flex-1 flex flex-col items-center gap-0.5">
                    <div
                      className="w-full rounded-sm bg-[var(--accent)] opacity-70 hover:opacity-100"
                      style={{ height: `${Math.round((d.count / barMax) * 100) + 2}px` }}
                      title={`${d.date}: ${d.count}`}
                    />
                    {i % 7 === 0 && <div className="text-[9px] text-[var(--text-3)]">{d.date?.slice(5)}</div>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="text-sm font-medium text-[var(--text-1)]">Watchlists</div>
          </div>
          <div className="g-card overflow-hidden">
            <table className="g-table w-full">
              <thead className="g-thead"><tr><th>Category</th><th>Item</th><th>Priority</th><th></th></tr></thead>
              <tbody>
                {watchlists.map((w: any) => (
                  <tr key={w.id} className="g-tr">
                    <td><span className="text-xs text-[var(--text-2)] capitalize">{w.category.replace(/_/g, ' ')}</span></td>
                    <td><span className="text-xs font-mono text-[var(--text-1)]">{w.item}</span></td>
                    <td><span className={`text-[10px] px-1.5 py-0.5 rounded ${SEV_BG[w.priority] ?? SEV_BG.medium}`}>{w.priority}</span></td>
                    <td>
                      <button className="p-1 hover:text-red-400 text-[var(--text-3)]" onClick={() => deceptionAPI.deleteWatchlist(w.id).then(reload)}>
                        <Trash2 className="h-3 w-3" />
                      </button>
                    </td>
                  </tr>
                ))}
                {watchlists.length === 0 && <tr><td colSpan={4} className="text-center text-[var(--text-3)] py-4 text-xs">No watchlist items</td></tr>}
              </tbody>
            </table>
          </div>
        </div>

        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="text-sm font-medium text-[var(--text-1)]">Deployment Policies</div>
            <button className="g-btn text-xs flex items-center gap-1" onClick={() => setShowPolicy(true)}>
              <Plus className="h-3 w-3" /> New
            </button>
          </div>

          {showPolicy && (
            <div className="g-card p-3 space-y-3 border border-[var(--accent-border)]">
              <div className="grid grid-cols-2 gap-2">
                {([
                  { label: 'Name', key: 'name' },
                  { label: 'Decoy Types', key: 'decoy_types' },
                  { label: 'Locations', key: 'locations' },
                ] as { label: string; key: keyof typeof policyForm }[]).map(({ label, key }) => (
                  <div key={key}>
                    <label className="text-xs text-[var(--text-3)] mb-1 block">{label}</label>
                    <input className="g-input text-xs w-full" value={String(policyForm[key])} onChange={e => setPolicyForm(f => ({ ...f, [key]: e.target.value }))} />
                  </div>
                ))}
                <div>
                  <label className="text-xs text-[var(--text-3)] mb-1 block">Lifetime (days)</label>
                  <input className="g-input text-xs w-full" type="number" value={policyForm.lifetime_days} onChange={e => setPolicyForm(f => ({ ...f, lifetime_days: Number(e.target.value) }))} />
                </div>
              </div>
              <div className="flex gap-2">
                <button className="g-btn-primary text-xs" onClick={() => deceptionAPI.createPolicy(policyForm).then(() => { setShowPolicy(false); reload(); })}>Create</button>
                <button className="g-btn text-xs" onClick={() => setShowPolicy(false)}>Cancel</button>
              </div>
            </div>
          )}

          <div className="g-card overflow-hidden">
            <table className="g-table w-full">
              <thead className="g-thead"><tr><th>Name</th><th>Lifetime</th><th>Rotation</th><th>Enabled</th><th></th></tr></thead>
              <tbody>
                {policies.map((p: any) => (
                  <tr key={p.id} className="g-tr">
                    <td><span className="text-xs text-[var(--text-1)]">{p.name}</span></td>
                    <td><span className="text-xs text-[var(--text-2)]">{p.lifetime_days}d</span></td>
                    <td><span className="text-xs text-[var(--text-2)]">{p.rotation_days}d</span></td>
                    <td>{p.enabled ? <CheckCircle className="h-3.5 w-3.5 text-green-400" /> : <XCircle className="h-3.5 w-3.5 text-[var(--text-3)]" />}</td>
                    <td>
                      <button className="p-1 hover:text-red-400 text-[var(--text-3)]" onClick={() => deceptionAPI.deletePolicy(p.id).then(reload)}>
                        <Trash2 className="h-3 w-3" />
                      </button>
                    </td>
                  </tr>
                ))}
                {policies.length === 0 && <tr><td colSpan={5} className="text-center text-[var(--text-3)] py-4 text-xs">No policies</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="g-card p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="text-sm font-medium text-[var(--text-1)]">Executive Report</div>
          <button className="g-btn-primary text-xs flex items-center gap-1.5" onClick={generateReport} disabled={generating}>
            <FileText className="h-3.5 w-3.5" />{generating ? 'Generating...' : 'Generate Report'}
          </button>
        </div>
        {reportResult && (
          <div className="space-y-4">
            <div className="text-base font-semibold text-[var(--text-1)]">{reportResult.title}</div>
            <div className="g-card p-3 text-sm text-[var(--text-2)] leading-relaxed">{reportResult.executive_summary}</div>
            {reportResult.metrics && (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {Object.entries(reportResult.metrics).map(([k, v]) => (
                  <StatCard key={k} label={k.replace(/_/g, ' ')} value={String(v)} />
                ))}
              </div>
            )}
            {reportResult.key_findings?.length > 0 && (
              <div>
                <div className="text-xs text-[var(--text-3)] mb-2">Key Findings</div>
                <ul className="space-y-1">{reportResult.key_findings.map((f: string, i: number) => (
                  <li key={i} className="text-xs text-[var(--text-2)] flex gap-1.5"><span className="text-red-400">!</span>{f}</li>
                ))}</ul>
              </div>
            )}
            {reportResult.recommendations?.length > 0 && (
              <div>
                <div className="text-xs text-[var(--text-3)] mb-2">Recommendations</div>
                <ul className="space-y-1">{reportResult.recommendations.map((r: string, i: number) => (
                  <li key={i} className="text-xs text-[var(--text-2)] flex gap-1.5"><span className="text-[var(--accent)]">›</span>{r}</li>
                ))}</ul>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function DeceptionPage() {
  const [tab, setTab] = useState('dashboard');
  const loaded = useRef<Record<string, boolean>>({});

  if (!loaded.current[tab]) loaded.current[tab] = true;

  const TAB_CONTENT: Record<string, React.ReactNode> = {
    dashboard:    <DashboardTab />,
    decoys:       <DecoysTab />,
    honeytokens:  <HoneytokensTab />,
    honeypots:    <HoneypotsTab />,
    triggers:     <TriggersTab />,
    campaigns:    <CampaignsTab />,
    graph:        <GraphTab />,
    intelligence: <IntelligenceTab />,
    analytics:    <AnalyticsTab />,
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[var(--text-1)]">Deception Technology</h1>
        <p className="text-sm text-[var(--text-3)] mt-1">Decoys, honeytokens, honeypots and adversary engagement</p>
      </div>

      <div className="flex flex-wrap gap-1 border-b border-[var(--border)] pb-px">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-t transition-colors
              ${tab === id
                ? 'text-[var(--accent)] border-b-2 border-[var(--accent)] -mb-px bg-[var(--accent)]/5'
                : 'text-[var(--text-3)] hover:text-[var(--text-1)]'}`}
          >
            <Icon className="h-3.5 w-3.5" />
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
  );
}
