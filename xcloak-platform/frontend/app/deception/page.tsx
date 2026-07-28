'use client';

import { useState, useEffect, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { deceptionAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import { MetricCard, SectionCard, DataTable, TabBar, ActionButton } from '@/components/design-system';
import { Activity, AlertTriangle, BarChart2, Brain, Bug, CheckCircle, ChevronRight, Cloud, Database, FileText, GitBranch, Globe, Key, Play, Plus, RefreshCw, Server, Shield, Trash2, XCircle, Zap, Lock } from 'lucide-react';

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

const SEV_STYLE: Record<string, React.CSSProperties> = {
  critical: { background: 'var(--red-bg)',    color: 'var(--red)',    border: '1px solid var(--red-border)' },
  high:     { background: 'var(--orange-bg)', color: 'var(--orange)', border: '1px solid var(--orange-border)' },
  medium:   { background: 'var(--yellow-bg)', color: 'var(--yellow)', border: '1px solid var(--yellow-border)' },
  low:      { background: 'var(--blue-bg)',   color: 'var(--blue)',   border: '1px solid var(--blue-border)' },
};

const HEALTH_ICON: Record<string, React.ReactNode> = {
  online:   <CheckCircle className="h-3.5 w-3.5" style={{ color: 'var(--green)' }} />,
  degraded: <AlertTriangle className="h-3.5 w-3.5" style={{ color: 'var(--yellow)' }} />,
  offline:  <XCircle className="h-3.5 w-3.5" style={{ color: 'var(--red)' }} />,
};

const TYPE_ICON: Record<string, React.ReactNode> = {
  honeypot:         <Bug className="h-4 w-4" style={{ color: '#a78bfa' }} />,
  ad_object:        <Server className="h-4 w-4" style={{ color: 'var(--blue)' }} />,
  database:         <Database className="h-4 w-4" style={{ color: '#22d3ee' }} />,
  container:        <Cloud className="h-4 w-4" style={{ color: '#818cf8' }} />,
  cloud:            <Cloud className="h-4 w-4" style={{ color: '#38bdf8' }} />,
  credential:       <Key className="h-4 w-4" style={{ color: 'var(--yellow)' }} />,
  file:             <FileText className="h-4 w-4" style={{ color: 'var(--green)' }} />,
  api_key:          <Lock className="h-4 w-4" style={{ color: 'var(--red)' }} />,
  cloud_credential: <Cloud className="h-4 w-4" style={{ color: '#818cf8' }} />,
};

function DeleteButton({ onClick }: { onClick: () => void }) {
  return (
    <button className="p-1 transition-colors" style={{ color: 'var(--text-3)' }} onMouseEnter={e => (e.currentTarget.style.color = 'var(--red)')} onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-3)')} onClick={onClick}>
      <Trash2 className="h-3.5 w-3.5" />
    </button>
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
        <MetricCard label="Active Decoys"      value={data.active_decoys}        color={'var(--accent)'} />
        <MetricCard label="Triggered Decoys"   value={data.triggered_decoys}     color={'var(--orange)'} />
        <MetricCard label="Active Campaigns"   value={data.active_campaigns}     color={'var(--red)'} />
        <MetricCard label="High Risk (24h)"    value={data.high_risk_24h}        color={'var(--red)'} />
        <MetricCard label="Total Triggers"     value={data.total_triggers} />
        <MetricCard label="Offline Decoys"     value={data.offline_decoys}       color={data.offline_decoys > 0 ? 'var(--yellow)' : 'var(--green)'} />
        <MetricCard label="Active Honeytokens" value={data.active_honeytokens} />
        <MetricCard label="Tokens Triggered"   value={data.honeytokens_triggered} color={data.honeytokens_triggered > 0 ? 'var(--red)' : 'var(--green)'} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <SectionCard title="14-Day Trigger Trend">
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
        </SectionCard>

        <SectionCard title="Recent Triggers">
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
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-medium" style={SEV_STYLE[t.severity] ?? SEV_STYLE.medium}>{t.severity}</span>
                  <span className="text-[var(--text-3)]">{timeAgo(t.created_at)}</span>
                </div>
              </div>
            ))}
          </div>
        </SectionCard>
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
          <ActionButton variant="ghost" icon={RefreshCw} onClick={reload} className="text-xs" title="Refresh" />
        </div>
        <ActionButton variant="primary" icon={Plus} onClick={() => setShowDeploy(true)} className="text-xs">
          Deploy Decoys
        </ActionButton>
      </div>

      {showDeploy && (
        <SectionCard title="Deploy from Template" className="border border-[var(--accent-border)]">
          <div className="space-y-3">
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
              <ActionButton variant="primary" icon={Play} onClick={doDeploy} loading={deploying} className="text-xs">
                {deploying ? 'Deploying...' : 'Deploy'}
              </ActionButton>
              <ActionButton variant="ghost" onClick={() => setShowDeploy(false)} className="text-xs">Cancel</ActionButton>
            </div>
          </div>
        </SectionCard>
      )}

      <DataTable<any>
        loading={loading}
        rows={decoys}
        rowKey={(d: any) => d.id}
        columns={[
          { key: 'name', header: 'Name', render: (d: any) => (
            <div className="flex items-center gap-2">
              {TYPE_ICON[d.type] ?? <Shield className="h-4 w-4 text-[var(--text-3)]" />}
              <span className="font-medium text-[var(--text-1)]">{d.name}</span>
            </div>
          ) },
          { key: 'type', header: 'Type', render: (d: any) => <span className="text-xs text-[var(--text-2)] capitalize">{d.type}</span> },
          { key: 'protocol', header: 'Protocol', render: (d: any) => <span className="text-xs font-mono text-[var(--accent)]">{d.protocol || '—'}</span> },
          { key: 'ip', header: 'IP:Port', render: (d: any) => <span className="text-xs font-mono text-[var(--text-2)]">{d.ip || '—'}{d.port ? `:${d.port}` : ''}</span> },
          { key: 'location', header: 'Location', render: (d: any) => <span className="text-xs text-[var(--text-2)]">{d.location || '—'}</span> },
          { key: 'health', header: 'Health', render: (d: any) => (
            <div className="flex items-center gap-1">
              {HEALTH_ICON[d.health] ?? HEALTH_ICON.offline}
              <span className="text-xs capitalize text-[var(--text-2)]">{d.health}</span>
            </div>
          ) },
          { key: 'triggers', header: 'Triggers', render: (d: any) => <span className="text-sm font-bold" style={{ color: d.trigger_count > 0 ? 'var(--orange)' : 'var(--text-3)' }}>{d.trigger_count}</span> },
          { key: 'last_hit', header: 'Last Hit', render: (d: any) => <span className="text-xs text-[var(--text-3)]">{d.last_triggered ? timeAgo(d.last_triggered) : 'Never'}</span> },
          { key: 'actions', header: '', render: (d: any) => <DeleteButton onClick={() => deceptionAPI.deleteDecoy(d.id).then(reload)} /> },
        ]}
      />

      <SectionCard title="Available Templates">
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
      </SectionCard>
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
        <ActionButton variant="ghost" icon={RefreshCw} onClick={reload} className="text-xs" title="Refresh" />
        <ActionButton variant="primary" icon={Plus} onClick={() => setShowCreate(true)} className="text-xs">
          Create Honeytoken
        </ActionButton>
      </div>

      {showCreate && (
        <SectionCard title="New Honeytoken" className="border border-[var(--accent-border)]">
          <div className="space-y-3">
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
              <ActionButton variant="primary" onClick={doCreate} className="text-xs">Create</ActionButton>
              <ActionButton variant="ghost" onClick={() => setShowCreate(false)} className="text-xs">Cancel</ActionButton>
            </div>
          </div>
        </SectionCard>
      )}

      <DataTable<any>
        loading={loading}
        rows={tokens}
        rowKey={(t: any) => t.id}
        columns={[
          { key: 'name', header: 'Name', render: (t: any) => (
            <div className="flex items-center gap-2">
              {TYPE_ICON[t.type] ?? <Key className="h-4 w-4 text-[var(--text-3)]" />}
              <span className="font-medium text-[var(--text-1)]">{t.name}</span>
            </div>
          ) },
          { key: 'type', header: 'Type', render: (t: any) => <span className="text-xs text-[var(--text-2)] capitalize">{t.type}</span> },
          { key: 'location', header: 'Location', render: (t: any) => <span className="text-xs text-[var(--text-3)] font-mono truncate max-w-[180px] block">{t.location || '—'}</span> },
          { key: 'owner', header: 'Owner', render: (t: any) => <span className="text-xs text-[var(--text-2)]">{t.owner || '—'}</span> },
          { key: 'category', header: 'Category', render: (t: any) => <span className="text-xs text-[var(--text-3)]">{t.watchlist_category || '—'}</span> },
          { key: 'triggered', header: 'Triggered', render: (t: any) => t.triggered ? (
            <div className="flex items-center gap-1">
              <AlertTriangle className="h-3.5 w-3.5" style={{ color: 'var(--red)' }} />
              <span className="text-xs font-medium" style={{ color: 'var(--red)' }}>{t.trigger_count}x</span>
            </div>
          ) : <span className="text-xs" style={{ color: 'var(--green)' }}>Clean</span> },
          { key: 'last_hit', header: 'Last Hit', render: (t: any) => <span className="text-xs text-[var(--text-3)]">{t.last_triggered ? timeAgo(t.last_triggered) : 'Never'}</span> },
          { key: 'actions', header: '', render: (t: any) => <DeleteButton onClick={() => deceptionAPI.deleteHoneytoken(t.id).then(reload)} /> },
        ]}
      />
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
          <MetricCard label="Online"   value={health.online}   color={'var(--green)'} />
          <MetricCard label="Degraded" value={health.degraded} color={'var(--yellow)'} />
          <MetricCard label="Offline"  value={health.offline}  color={'var(--red)'} />
        </div>
      )}

      <SectionCard title="Supported Protocols">
        <div className="flex flex-wrap gap-2">
          {PROTOCOLS.map(p => (
            <span key={p} className="px-2.5 py-1 rounded-full text-xs bg-[var(--glass-bg)] border border-[var(--border)] text-[var(--text-2)]">{p}</span>
          ))}
        </div>
      </SectionCard>

      <DataTable<any>
        loading={loading}
        rows={decoys}
        rowKey={(d: any) => d.id}
        columns={[
          { key: 'name', header: 'Name', render: (d: any) => <span className="font-medium text-[var(--text-1)]">{d.name}</span> },
          { key: 'protocol', header: 'Protocol', render: (d: any) => <span className="text-xs font-mono text-[var(--accent)] uppercase">{d.protocol || '—'}</span> },
          { key: 'ip', header: 'IP:Port', render: (d: any) => <span className="text-xs font-mono text-[var(--text-2)]">{d.ip}{d.port ? `:${d.port}` : ''}</span> },
          { key: 'platform', header: 'Platform', render: (d: any) => <span className="text-xs text-[var(--text-2)] capitalize">{d.platform || '—'}</span> },
          { key: 'location', header: 'Location', render: (d: any) => <span className="text-xs text-[var(--text-3)]">{d.location}</span> },
          { key: 'health', header: 'Health', render: (d: any) => (
            <div className="flex items-center gap-1">
              {HEALTH_ICON[d.health] ?? HEALTH_ICON.offline}
              <span className="text-xs capitalize">{d.health}</span>
            </div>
          ) },
          { key: 'integrity', header: 'Integrity', render: (d: any) => d.integrity_ok ? <CheckCircle className="h-3.5 w-3.5" style={{ color: 'var(--green)' }} /> : <AlertTriangle className="h-3.5 w-3.5" style={{ color: 'var(--yellow)' }} /> },
          { key: 'version', header: 'Version', render: (d: any) => <span className="text-xs font-mono text-[var(--text-3)]">{d.version}</span> },
          { key: 'heartbeat', header: 'Last Heartbeat', render: (d: any) => <span className="text-xs text-[var(--text-3)]">{d.last_heartbeat ? timeAgo(d.last_heartbeat) : 'Never'}</span> },
        ]}
      />
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
        <ActionButton variant="ghost" icon={RefreshCw} onClick={reload} className="text-xs" title="Refresh" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          <DataTable<any>
            loading={loading}
            rows={triggers}
            rowKey={(t: any) => t.id}
            onRowClick={t => setSelected(t)}
            rowStyle={(t: any) => selected?.id === t.id ? { background: 'var(--accent-glow)' } : undefined}
            columns={[
              { key: 'event', header: 'Event', render: (t: any) => <span className="text-xs text-[var(--text-1)] capitalize">{t.event_type.replace(/_/g, ' ')}</span> },
              { key: 'attacker', header: 'Attacker', render: (t: any) => (
                <div>
                  <div className="text-xs font-mono text-[var(--text-1)]">{t.attacker_ip}</div>
                  {t.attacker_user && <div className="text-[10px] text-[var(--text-3)]">{t.attacker_user}</div>}
                </div>
              ) },
              { key: 'asset', header: 'Asset', render: (t: any) => <span className="text-xs text-[var(--text-2)]">{t.decoy_name || t.token_name || '—'}</span> },
              { key: 'severity', header: 'Severity', render: (t: any) => <span className="text-[10px] px-1.5 py-0.5 rounded" style={SEV_STYLE[t.severity] ?? SEV_STYLE.medium}>{t.severity}</span> },
              { key: 'time', header: 'Time', render: (t: any) => <span className="text-xs text-[var(--text-3)]">{timeAgo(t.created_at)}</span> },
              { key: 'status', header: 'Status', render: (t: any) => t.responded
                ? <CheckCircle className="h-3.5 w-3.5" style={{ color: 'var(--green)' }} />
                : <div className="h-1.5 w-1.5 rounded-full animate-pulse" style={{ background: 'var(--red)' }} /> },
            ]}
          />
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
                  <ActionButton key={action} variant="ghost" icon={Zap} className="text-xs w-full justify-start" onClick={() => doRespond(action)} disabled={responding}>
                    {action.replace(/_/g, ' ')}
                  </ActionButton>
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
                  <span className="text-[10px] px-1.5 py-0.5 rounded" style={SEV_STYLE[c.severity] ?? SEV_STYLE.medium}>{c.severity}</span>
                </div>
                <div className="grid grid-cols-3 gap-2 text-xs">
                  <div><div className="text-[var(--text-3)]">Attacker IP</div><div className="font-mono text-[var(--text-1)]">{c.attacker_ip || '—'}</div></div>
                  <div><div className="text-[var(--text-3)]">Decoys Hit</div><div className="font-bold" style={{ color: 'var(--orange)' }}>{c.decoys_hit}</div></div>
                  <div><div className="text-[var(--text-3)]">Tokens Used</div><div className="font-bold" style={{ color: 'var(--red)' }}>{c.tokens_triggered}</div></div>
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
                    <div
                      className="h-2.5 w-2.5 rounded-full mt-0.5 shrink-0"
                      style={{ background: t.severity === 'critical' ? 'var(--red)' : t.severity === 'high' ? 'var(--orange)' : 'var(--yellow)' }}
                    />
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
        <MetricCard label="Attacker IPs"     value={attackers.length} color={'var(--red)'} />
        <MetricCard label="Triggered Decoys" value={decoys.length}    color={'var(--orange)'} />
        <MetricCard label="Used Tokens"      value={tokens.length}    color={'var(--yellow)'} />
      </div>

      {loading ? <div className="text-[var(--text-3)] text-sm">Loading...</div> : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {([
              { label: 'Attackers',   nodes: attackers, labelStyle: { color: 'var(--red)' }    as React.CSSProperties, cardStyle: { background: 'var(--red-bg)',    border: '1px solid var(--red-border)' }    as React.CSSProperties, icon: <Globe  className="h-4 w-4" style={{ color: 'var(--red)' }} /> },
              { label: 'Decoys Hit',  nodes: decoys,    labelStyle: { color: 'var(--orange)' } as React.CSSProperties, cardStyle: { background: 'var(--orange-bg)', border: '1px solid var(--orange-border)' } as React.CSSProperties, icon: <Shield className="h-4 w-4" style={{ color: 'var(--orange)' }} /> },
              { label: 'Tokens Used', nodes: tokens,    labelStyle: { color: 'var(--yellow)' } as React.CSSProperties, cardStyle: { background: 'var(--yellow-bg)', border: '1px solid var(--yellow-border)' } as React.CSSProperties, icon: <Key    className="h-4 w-4" style={{ color: 'var(--yellow)' }} /> },
            ] as { label: string; nodes: any[]; labelStyle: React.CSSProperties; cardStyle: React.CSSProperties; icon: React.ReactNode }[]).map(({ label, nodes, labelStyle, cardStyle, icon }) => (
              <SectionCard key={label} title={<span className="flex items-center gap-2">{icon}{label}</span>}>
                <div className="space-y-2">
                  {nodes.map(n => (
                    <div key={n.id} className="rounded-lg px-3 py-2 text-xs" style={cardStyle}>
                      <div className="font-mono font-medium" style={labelStyle}>{n.label}</div>
                      {n.hits !== undefined && <div className="text-[var(--text-3)]">{n.hits} hits</div>}
                      {n.trigger_count !== undefined && <div className="text-[var(--text-3)]">{n.trigger_count} triggers</div>}
                      {n.subtype && <div className="text-[var(--text-3)] capitalize">{n.subtype}</div>}
                    </div>
                  ))}
                  {nodes.length === 0 && <div className="text-xs text-[var(--text-3)]">None</div>}
                </div>
              </SectionCard>
            ))}
          </div>

          {graph.edges.length > 0 && (
            <SectionCard title={`Attack Connections (${graph.edges.length})`}>
              <DataTable<any>
                rows={graph.edges}
                rowKey={(e: any, i: number) => i}
                columns={[
                  { key: 'source', header: 'Source', render: (e: any) => <span className="text-xs font-mono" style={{ color: 'var(--red)' }}>{e.source?.replace('atk-', '')}</span> },
                  { key: 'action', header: 'Action', render: (e: any) => <span className="text-xs text-[var(--text-2)] capitalize">{e.label?.replace(/_/g, ' ')}</span> },
                  { key: 'target', header: 'Target', render: (e: any) => <span className="text-xs text-[var(--text-2)]">{e.target}</span> },
                  { key: 'severity', header: 'Severity', render: (e: any) => <span className="text-[10px] px-1.5 py-0.5 rounded" style={SEV_STYLE[e.severity] ?? SEV_STYLE.medium}>{e.severity}</span> },
                ]}
              />
            </SectionCard>
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
      <SectionCard title="Threat Intelligence Lookup">
        <div className="space-y-3">
          <div className="flex gap-2 flex-wrap">
            <select className="g-select text-xs flex-1 min-w-[160px]" value={ip} onChange={e => setIp(e.target.value)}>
              <option value="">Select attacker IP...</option>
              {attackerIPs.map(a => <option key={a} value={a}>{a}</option>)}
            </select>
            <input className="g-input text-xs w-36" placeholder="Or type IP..." value={ip} onChange={e => setIp(e.target.value)} />
            <ActionButton variant="primary" onClick={fetchIntel} loading={loading} disabled={!ip} className="text-xs">Enrich</ActionButton>
          </div>

          {intel && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-2">
              <MetricCard label="Risk Score"  value={`${intel.risk_score}/100`} color={intel.risk_score > 80 ? 'var(--red)' : 'var(--orange)'} />
              <MetricCard label="Reputation"  value={intel.ip_reputation} color={intel.ip_reputation === 'malicious' ? 'var(--red)' : 'var(--yellow)'} />
              <MetricCard label="Confidence"  value={`${intel.confidence}%`} />
              <MetricCard label="Location"    value={intel.geo_country || '—'} sub={intel.geo_city} />
              <div className="col-span-2 g-card p-3 space-y-1">
                <div className="text-xs text-[var(--text-3)]">Threat Actor</div>
                <div className="text-sm font-medium" style={{ color: 'var(--red)' }}>{intel.threat_actor || 'Unknown'}</div>
                <div className="text-xs text-[var(--text-3)]">{intel.campaign}</div>
              </div>
              <div className="col-span-2 g-card p-3 space-y-1">
                <div className="text-xs text-[var(--text-3)]">Malware Families</div>
                <div className="flex flex-wrap gap-1">
                  {(intel.malware_families ?? []).map((m: string) => (
                    <span key={m} className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)', color: 'var(--red)' }}>{m}</span>
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
                    <li key={i} className="text-xs text-[var(--text-2)] flex gap-1.5 items-start"><ChevronRight className="h-3 w-3 shrink-0 mt-0.5" style={{ color: 'var(--accent)' }} />{a}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </div>
      </SectionCard>

      <SectionCard title="AI Deception Analysis">
        <div className="space-y-3">
          <div className="flex gap-2 flex-wrap">
            <select className="g-select text-xs" value={aiMode} onChange={e => setAiMode(e.target.value)}>
              <option value="summarize">Summarize Engagement</option>
              <option value="attribution">Threat Attribution</option>
              <option value="recommend">Response Recommendations</option>
              <option value="attack_path">Reconstruct Attack Path</option>
            </select>
            <ActionButton variant="primary" onClick={runAI} loading={aiLoading} className="text-xs">Analyze</ActionButton>
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
                    <li key={i} className="text-xs text-[var(--text-2)] flex gap-1.5 items-start"><AlertTriangle className="h-3 w-3 shrink-0 mt-0.5" style={{ color: 'var(--red)' }} />{f}</li>
                  ))}</ul>
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
      </SectionCard>
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
            <SectionCard title="Top Triggered Decoys">
              <div className="space-y-2">
                {(analytics.top_decoys ?? []).map((d: any, i: number) => (
                  <div key={i} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="text-[var(--text-2)]">{d.name}</span>
                      <span className="font-bold" style={{ color: 'var(--orange)' }}>{d.trigger_count}</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-[var(--border)]">
                      <div className="h-full rounded-full" style={{ width: `${Math.round(d.trigger_count / (analytics.top_decoys[0]?.trigger_count || 1) * 100)}%`, background: 'var(--orange)' }} />
                    </div>
                  </div>
                ))}
              </div>
            </SectionCard>

            <SectionCard title="Event Type Breakdown">
              <div className="space-y-2">
                {(analytics.by_event_type ?? []).map((e: any, i: number) => (
                  <div key={i} className="flex items-center justify-between gap-2 text-xs">
                    <span className="text-[var(--text-2)] capitalize truncate">{e.event_type.replace(/_/g, ' ')}</span>
                    <span className="text-[var(--accent)] font-bold shrink-0">{e.count}</span>
                  </div>
                ))}
              </div>
            </SectionCard>

            <SectionCard title="Top Attack Sources">
              <div className="space-y-2">
                {(analytics.top_sources ?? []).map((s: any, i: number) => (
                  <div key={i} className="flex items-center justify-between gap-2 text-xs">
                    <span className="font-mono" style={{ color: 'var(--red)' }}>{s.ip}</span>
                    <span className="text-[var(--text-2)] font-bold">{s.hits} hits</span>
                  </div>
                ))}
              </div>
            </SectionCard>
          </div>

          {analytics.daily && (
            <SectionCard title="30-Day Trigger Trend">
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
            </SectionCard>
          )}
        </>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <SectionCard title="Watchlists">
          <DataTable<any>
            rows={watchlists}
            rowKey={(w: any) => w.id}
            columns={[
              { key: 'category', header: 'Category', render: (w: any) => <span className="text-xs text-[var(--text-2)] capitalize">{w.category.replace(/_/g, ' ')}</span> },
              { key: 'item', header: 'Item', render: (w: any) => <span className="text-xs font-mono text-[var(--text-1)]">{w.item}</span> },
              { key: 'priority', header: 'Priority', render: (w: any) => <span className="text-[10px] px-1.5 py-0.5 rounded" style={SEV_STYLE[w.priority] ?? SEV_STYLE.medium}>{w.priority}</span> },
              { key: 'actions', header: '', render: (w: any) => <DeleteButton onClick={() => deceptionAPI.deleteWatchlist(w.id).then(reload)} /> },
            ]}
          />
        </SectionCard>

        <div className="space-y-3">
          <SectionCard
            title="Deployment Policies"
            actions={<ActionButton variant="ghost" icon={Plus} onClick={() => setShowPolicy(true)} className="text-xs">New</ActionButton>}
          >
            <div className="space-y-3">
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
                    <ActionButton variant="primary" onClick={() => deceptionAPI.createPolicy(policyForm).then(() => { setShowPolicy(false); reload(); })} className="text-xs">Create</ActionButton>
                    <ActionButton variant="ghost" onClick={() => setShowPolicy(false)} className="text-xs">Cancel</ActionButton>
                  </div>
                </div>
              )}

              <DataTable<any>
                rows={policies}
                rowKey={(p: any) => p.id}
                columns={[
                  { key: 'name', header: 'Name', render: (p: any) => <span className="text-xs text-[var(--text-1)]">{p.name}</span> },
                  { key: 'lifetime', header: 'Lifetime', render: (p: any) => <span className="text-xs text-[var(--text-2)]">{p.lifetime_days}d</span> },
                  { key: 'rotation', header: 'Rotation', render: (p: any) => <span className="text-xs text-[var(--text-2)]">{p.rotation_days}d</span> },
                  { key: 'enabled', header: 'Enabled', render: (p: any) => p.enabled ? <CheckCircle className="h-3.5 w-3.5" style={{ color: 'var(--green)' }} /> : <XCircle className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} /> },
                  { key: 'actions', header: '', render: (p: any) => <DeleteButton onClick={() => deceptionAPI.deletePolicy(p.id).then(reload)} /> },
                ]}
              />
            </div>
          </SectionCard>
        </div>
      </div>

      <SectionCard
        title="Executive Report"
        actions={<ActionButton variant="primary" icon={FileText} onClick={generateReport} loading={generating} className="text-xs">{generating ? 'Generating...' : 'Generate Report'}</ActionButton>}
      >
        {reportResult && (
          <div className="space-y-4">
            <div className="text-base font-semibold text-[var(--text-1)]">{reportResult.title}</div>
            <div className="g-card p-3 text-sm text-[var(--text-2)] leading-relaxed">{reportResult.executive_summary}</div>
            {reportResult.metrics && (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {Object.entries(reportResult.metrics).map(([k, v]) => (
                  <MetricCard key={k} label={k.replace(/_/g, ' ')} value={String(v)} />
                ))}
              </div>
            )}
            {reportResult.key_findings?.length > 0 && (
              <div>
                <div className="text-xs text-[var(--text-3)] mb-2">Key Findings</div>
                <ul className="space-y-1">{reportResult.key_findings.map((f: string, i: number) => (
                  <li key={i} className="text-xs text-[var(--text-2)] flex gap-1.5 items-start"><AlertTriangle className="h-3 w-3 shrink-0 mt-0.5" style={{ color: 'var(--red)' }} />{f}</li>
                ))}</ul>
              </div>
            )}
            {reportResult.recommendations?.length > 0 && (
              <div>
                <div className="text-xs text-[var(--text-3)] mb-2">Recommendations</div>
                <ul className="space-y-1">{reportResult.recommendations.map((r: string, i: number) => (
                  <li key={i} className="text-xs text-[var(--text-2)] flex gap-1.5 items-start"><ChevronRight className="h-3 w-3 shrink-0 mt-0.5" style={{ color: 'var(--accent)' }} />{r}</li>
                ))}</ul>
              </div>
            )}
          </div>
        )}
      </SectionCard>
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
    <RootLayout title="Deception Technology" subtitle="Decoys, honeytokens, honeypots and adversary engagement">
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
