'use client';

import { useState, useEffect, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { emailSecurityAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import { MetricCard, SectionCard, DataTable, TabBar, ActionButton } from '@/components/design-system';
import { Activity, AlertCircle, AlertTriangle, BarChart2, Brain, CheckCircle, ChevronRight, DollarSign, Eye, FileText, GitBranch, Link2, Mail, Paperclip, Plus, RefreshCw, Search, Shield, Trash2, User, XCircle, Zap } from 'lucide-react';

const TABS = [
  { id: 'dashboard',    label: 'Dashboard',    icon: Activity },
  { id: 'inbox',        label: 'Inbox',        icon: Mail },
  { id: 'threats',      label: 'Threats',      icon: AlertCircle },
  { id: 'auth',         label: 'Auth',         icon: Shield },
  { id: 'campaigns',    label: 'Campaigns',    icon: GitBranch },
  { id: 'intelligence', label: 'Intelligence', icon: Brain },
  { id: 'userrisk',     label: 'User Risk',    icon: User },
  { id: 'analytics',    label: 'Analytics',    icon: BarChart2 },
  { id: 'response',     label: 'Response',     icon: Zap },
];

const THREAT_COLOR: Record<string, React.CSSProperties> = {
  phishing: { background: 'var(--red-bg)', color: 'var(--red)', border: '1px solid var(--red-border)' },
  bec:      { background: 'var(--orange-bg)', color: 'var(--orange)', border: '1px solid var(--orange-border)' },
  malware:  { background: 'var(--blue-bg)', color: 'var(--blue)', border: '1px solid var(--blue-border)' },
  spam:     { background: 'var(--yellow-bg)', color: 'var(--yellow)', border: '1px solid var(--yellow-border)' },
  clean:    { background: 'var(--green-bg)', color: 'var(--green)', border: '1px solid var(--green-border)' },
};
const STATUS_COLOR: Record<string, React.CSSProperties> = {
  delivered:   { color: 'var(--green)' },
  quarantined: { color: 'var(--yellow)' },
  blocked:     { color: 'var(--red)' },
  rejected:    { color: 'var(--red)' },
};
const AUTH_COLOR: Record<string, React.CSSProperties> = {
  pass: { color: 'var(--green)' },
  fail: { color: 'var(--red)' },
  none: { color: 'var(--text-3)' },
};

const SELECTED_ROW_STYLE: React.CSSProperties = { background: 'var(--accent-glow)' };

function ThreatBadge({ type }: { type: string }) {
  return (
    <span className="text-[10px] px-1.5 py-0.5 rounded uppercase font-bold" style={THREAT_COLOR[type] ?? THREAT_COLOR.spam}>
      {type}
    </span>
  );
}

// ── Dashboard Tab ─────────────────────────────────────────────────────────────

function DashboardTab() {
  const [data, setData] = useState<any>(null);
  const [flow, setFlow] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([emailSecurityAPI.getDashboard(), emailSecurityAPI.getMailFlow()])
      .then(([dr, fr]) => { setData(dr.data); setFlow(fr.data); setLoading(false); });
  }, []);

  if (loading) return <div className="text-[var(--text-3)] text-sm p-4">Loading...</div>;

  const scoreColor: string = data?.email_security_score > 85 ? 'var(--green)' : data?.email_security_score > 70 ? 'var(--yellow)' : 'var(--red)';

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <MetricCard label="Processed"      value={(data?.emails_processed ?? 0).toLocaleString()} icon={Mail} />
        <MetricCard label="Delivered"      value={(data?.emails_delivered ?? 0).toLocaleString()} color="var(--green)" icon={CheckCircle} />
        <MetricCard label="Blocked"        value={(data?.emails_blocked ?? 0).toLocaleString()}   color="var(--red)" icon={XCircle} />
        <MetricCard label="Security Score" value={`${data?.email_security_score ?? 0}%`}          color={scoreColor} />
        <MetricCard label="High-Risk Users" value={data?.high_risk_users ?? 0}                    color="var(--orange)" icon={User} />
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <MetricCard label="Phishing Attempts"    value={data?.phishing_attempts ?? 0}   color="var(--red)" icon={AlertCircle} />
        <MetricCard label="Malware Attachments"  value={data?.malware_attachments ?? 0} color="var(--blue)" icon={Paperclip} />
        <MetricCard label="BEC Attempts"         value={data?.bec_attempts ?? 0}        color="var(--orange)" icon={DollarSign} />
        <MetricCard label="URL Clicks"           value={data?.url_clicks ?? 0}          color={data?.url_clicks > 0 ? 'var(--yellow)' : 'var(--green)'} icon={Link2} />
      </div>

      {flow && (
        <SectionCard title="Mail Flow Pipeline">
          <div className="space-y-3">
            <div className="grid grid-cols-3 md:grid-cols-7 gap-2">
              {(flow.steps ?? []).map((step: any, i: number) => (
                <div key={i} className="flex flex-col items-center gap-1 relative">
                  <div className="g-card px-2 py-2 text-center w-full space-y-0.5">
                    <div className="text-[10px] text-[var(--text-3)] font-medium">{step.label}</div>
                    <div className="text-sm font-bold text-[var(--text-1)]">{(step.count ?? 0).toLocaleString()}</div>
                    {step.dropped > 0 && <div className="text-[9px]" style={{ color: 'var(--red)' }}>-{step.dropped.toLocaleString()} blocked</div>}
                    {step.quarantined > 0 && <div className="text-[9px]" style={{ color: 'var(--yellow)' }}>-{step.quarantined.toLocaleString()} quarantined</div>}
                  </div>
                  {i < (flow.steps?.length ?? 0) - 1 && (
                    <div className="hidden md:flex absolute right-[-8px] top-1/2 -translate-y-1/2 text-[var(--text-3)] z-10">
                      <ChevronRight className="h-3.5 w-3.5" />
                    </div>
                  )}
                </div>
              ))}
            </div>
            <div className="flex gap-4 text-xs pt-1 border-t border-[var(--border)]">
              <span className="text-[var(--text-3)]">Total: <span className="text-[var(--text-1)] font-bold">{(flow.total ?? 0).toLocaleString()}</span></span>
              <span className="text-[var(--text-3)]">Blocked: <span className="font-bold" style={{ color: 'var(--red)' }}>{(flow.blocked ?? 0).toLocaleString()}</span></span>
              <span className="text-[var(--text-3)]">Quarantined: <span className="font-bold" style={{ color: 'var(--yellow)' }}>{(flow.quarantined ?? 0).toLocaleString()}</span></span>
            </div>
          </div>
        </SectionCard>
      )}
    </div>
  );
}

// ── Inbox Tab ─────────────────────────────────────────────────────────────────

function InboxTab() {
  const [messages, setMessages] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState({ sender: '', recipient: '', subject: '', status: '', threat_type: '' });
  const [selected, setSelected] = useState<any>(null);

  const reload = () => {
    setLoading(true);
    const params: any = {};
    if (search.sender)     params.sender     = search.sender;
    if (search.recipient)  params.recipient  = search.recipient;
    if (search.subject)    params.subject    = search.subject;
    if (search.status)     params.status     = search.status;
    if (search.threat_type) params.threat_type = search.threat_type;
    emailSecurityAPI.getMessages(params).then(r => { setMessages(r.data ?? []); setLoading(false); });
  };
  useEffect(() => { reload(); }, []);

  const [acting, setActing] = useState(false);
  const doRespond = async (action: string) => {
    if (!selected) return;
    setActing(true);
    await emailSecurityAPI.respond({ action, message_id: selected.message_id, sender: selected.sender });
    setActing(false);
  };

  return (
    <div className="space-y-4">
      <div className="g-card p-3 grid grid-cols-2 md:grid-cols-5 gap-2">
        {[
          { key: 'sender', placeholder: 'Sender...' },
          { key: 'recipient', placeholder: 'Recipient...' },
          { key: 'subject', placeholder: 'Subject...' },
          { key: 'status', placeholder: '', options: ['', 'delivered', 'quarantined', 'blocked'] },
          { key: 'threat_type', placeholder: '', options: ['', 'phishing', 'bec', 'malware', 'spam', 'clean'] },
        ].map(({ key, placeholder, options }) => (
          <div key={key}>
            {options ? (
              <select className="g-select text-xs w-full" value={(search as any)[key]} onChange={e => setSearch(s => ({ ...s, [key]: e.target.value }))}>
                {options.map(o => <option key={o} value={o}>{o || (key === 'status' ? 'All Statuses' : 'All Types')}</option>)}
              </select>
            ) : (
              <input className="g-input text-xs w-full" placeholder={placeholder} value={(search as any)[key]} onChange={e => setSearch(s => ({ ...s, [key]: e.target.value }))} onKeyDown={e => e.key === 'Enter' && reload()} />
            )}
          </div>
        ))}
      </div>
      <div className="flex gap-2">
        <ActionButton variant="primary" icon={Search} onClick={reload} className="text-xs">Search</ActionButton>
        <ActionButton variant="ghost" icon={RefreshCw} onClick={() => { setSearch({ sender: '', recipient: '', subject: '', status: '', threat_type: '' }); setTimeout(reload, 0); }} className="text-xs" title="Reset filters" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          <DataTable<any>
            loading={loading}
            rows={messages}
            rowKey={(m: any) => m.id}
            onRowClick={m => setSelected(selected?.id === m.id ? null : m)}
            rowStyle={(m: any) => selected?.id === m.id ? SELECTED_ROW_STYLE : undefined}
            columns={[
              { key: 'sender', header: 'From', render: (m: any) => <div className="text-xs text-[var(--text-1)] truncate max-w-[140px]">{m.sender}</div> },
              { key: 'subject', header: 'Subject', render: (m: any) => <div className="text-xs text-[var(--text-2)] truncate max-w-[180px]">{m.subject}</div> },
              { key: 'recipient', header: 'To', render: (m: any) => <div className="text-xs text-[var(--text-3)] truncate max-w-[120px]">{m.recipient}</div> },
              { key: 'threat', header: 'Threat', render: (m: any) => m.threat_type ? <ThreatBadge type={m.threat_type} /> : <span className="text-[10px] text-[var(--text-3)]">—</span> },
              { key: 'score', header: 'Score', render: (m: any) => (
                <div className="flex items-center gap-1">
                  <div className="w-8 h-1.5 rounded-full bg-[var(--border)]">
                    <div className="h-full rounded-full" style={{ width: `${m.threat_score}%`, background: m.threat_score > 80 ? 'var(--red)' : m.threat_score > 50 ? 'var(--orange)' : 'var(--green)' }} />
                  </div>
                  <span className="text-xs font-bold" style={{ color: m.threat_score > 80 ? 'var(--red)' : m.threat_score > 50 ? 'var(--orange)' : 'var(--green)' }}>{m.threat_score}</span>
                </div>
              ) },
              { key: 'attach', header: 'Attach', render: (m: any) => m.has_attachment ? <Paperclip className="h-3.5 w-3.5" style={{ color: 'var(--orange)' }} /> : <span className="text-[var(--text-3)]">—</span> },
              { key: 'urls', header: 'URLs', render: (m: any) => <span className="text-xs" style={{ color: m.url_count > 0 ? 'var(--blue)' : 'var(--text-3)' }}>{m.url_count}</span> },
              { key: 'status', header: 'Status', render: (m: any) => <span className="text-xs font-medium" style={STATUS_COLOR[m.status] ?? { color: 'var(--text-2)' }}>{m.status}</span> },
              { key: 'time', header: 'Time', render: (m: any) => <span className="text-xs text-[var(--text-3)]">{timeAgo(m.created_at)}</span> },
            ]}
          />
        </div>

        <div>
          {selected ? (
            <div className="g-card p-4 space-y-3">
              <div className="text-sm font-semibold text-[var(--text-1)]">Message Detail</div>
              <dl className="space-y-1.5 text-xs">
                {([
                  ['From', selected.sender],
                  ['To', selected.recipient],
                  ['Subject', selected.subject],
                  ['Message-ID', selected.message_id],
                  ['Direction', selected.direction],
                  ['Status', selected.status],
                  ['Delivery', selected.delivery_status],
                  ['Size', `${Math.round(selected.size_bytes / 1024)} KB`],
                  ['Received', new Date(selected.created_at).toLocaleString()],
                ] as [string, string][]).map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-2">
                    <dt className="text-[var(--text-3)] shrink-0">{k}</dt>
                    <dd className="text-[var(--text-1)] text-right text-[10px] font-mono truncate max-w-[160px]">{v}</dd>
                  </div>
                ))}
              </dl>
              <div className="space-y-1.5 pt-2 border-t border-[var(--border)]">
                <div className="text-xs text-[var(--text-3)] font-medium">Response Actions</div>
                {(['quarantine_email', 'delete_email', 'block_sender', 'block_domain', 'create_incident'] as string[]).map(action => (
                  <ActionButton key={action} variant="ghost" icon={Zap} className="text-xs w-full justify-start" onClick={() => doRespond(action)} disabled={acting}>
                    {action.replace(/_/g, ' ')}
                  </ActionButton>
                ))}
                <ActionButton variant="ghost" icon={Search} className="text-xs w-full justify-start" style={{ color: 'var(--blue)' }} onClick={() => {}}>
                  Pivot to SIEM
                </ActionButton>
              </div>
            </div>
          ) : (
            <div className="g-card p-4 text-xs text-[var(--text-3)] text-center">Select a message for details and actions</div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Threats Tab ───────────────────────────────────────────────────────────────

function ThreatsTab() {
  const [subTab, setSubTab] = useState<'all' | 'phishing' | 'bec' | 'attachments' | 'urls'>('all');
  const [threats, setThreats] = useState<any[]>([]);
  const [attachments, setAttachments] = useState<any[]>([]);
  const [urls, setURLs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<any>(null);

  const reload = () => {
    setLoading(true);
    const params: any = {};
    if (subTab === 'phishing') params.type = 'phishing';
    if (subTab === 'bec') params.type = 'bec';
    Promise.all([
      emailSecurityAPI.getThreats(subTab !== 'attachments' && subTab !== 'urls' ? params : {}),
      emailSecurityAPI.getAttachments(),
      emailSecurityAPI.getURLs(),
    ]).then(([tr, ar, ur]) => { setThreats(tr.data ?? []); setAttachments(ar.data ?? []); setURLs(ur.data ?? []); setLoading(false); });
  };
  useEffect(() => { reload(); }, [subTab]);

  const PHISHING_TYPES = [
    'Credential Harvesting', 'Fake Login Pages', 'Brand Impersonation', 'QR Code Phishing',
    'Homograph Domains', 'Look-alike Domains', 'Reply Chain Hijacking', 'Thread Hijacking',
  ];
  const BEC_TYPES = [
    'CEO Fraud', 'Invoice Fraud', 'Payroll Fraud', 'Display Name Spoofing',
    'Vendor Impersonation', 'Executive Impersonation', 'Gift Card Scams', 'Wire Transfer Fraud',
  ];

  return (
    <div className="space-y-4">
      <div className="flex gap-2 flex-wrap items-center">
        {(['all', 'phishing', 'bec', 'attachments', 'urls'] as const).map(s => (
          <ActionButton key={s} variant={subTab === s ? 'primary' : 'ghost'} onClick={() => setSubTab(s)} className="text-xs capitalize">
            {s === 'all' ? `All Threats (${threats.length})` : s === 'attachments' ? `Attachments (${attachments.length})` : s === 'urls' ? `URLs (${urls.length})` : s}
          </ActionButton>
        ))}
        <ActionButton variant="ghost" icon={RefreshCw} onClick={reload} className="text-xs ml-auto" title="Refresh" />
      </div>

      {(subTab === 'phishing' || subTab === 'bec') && (
        <SectionCard title={`${subTab === 'phishing' ? 'Phishing' : 'BEC'} Detection Capabilities`}>
          <div className="flex flex-wrap gap-1.5">
            {(subTab === 'phishing' ? PHISHING_TYPES : BEC_TYPES).map(t => (
              <span key={t} className="text-[10px] px-2 py-0.5 rounded bg-[var(--glass-bg)] border border-[var(--border)] text-[var(--text-2)]">{t}</span>
            ))}
          </div>
        </SectionCard>
      )}

      {(subTab === 'all' || subTab === 'phishing' || subTab === 'bec') && (
        <DataTable<any>
          loading={loading}
          rows={threats}
          rowKey={(t: any) => t.id}
          onRowClick={t => setSelected(selected?.id === t.id ? null : t)}
          rowStyle={(t: any) => selected?.id === t.id ? SELECTED_ROW_STYLE : undefined}
          columns={[
            { key: 'sender', header: 'Sender', render: (t: any) => <div className="text-xs text-[var(--text-1)] truncate max-w-[150px]">{t.sender}</div> },
            { key: 'subject', header: 'Subject', render: (t: any) => <div className="text-xs text-[var(--text-2)] truncate max-w-[200px]">{t.subject}</div> },
            { key: 'recipient', header: 'Recipient', render: (t: any) => <div className="text-xs text-[var(--text-3)] truncate max-w-[120px]">{t.recipient}</div> },
            { key: 'type', header: 'Type', render: (t: any) => <ThreatBadge type={t.threat_type} /> },
            { key: 'score', header: 'Score', render: (t: any) => <span className="text-sm font-bold" style={{ color: t.threat_score > 90 ? 'var(--red)' : t.threat_score > 70 ? 'var(--orange)' : 'var(--yellow)' }}>{t.threat_score}</span> },
            { key: 'attach', header: 'Attach', render: (t: any) => t.has_attachment ? <Paperclip className="h-3.5 w-3.5" style={{ color: 'var(--orange)' }} /> : <span className="text-[var(--text-3)]">—</span> },
            { key: 'urls', header: 'URLs', render: (t: any) => <span className="text-xs" style={{ color: t.url_count > 0 ? 'var(--blue)' : 'var(--text-3)' }}>{t.url_count}</span> },
            { key: 'status', header: 'Status', render: (t: any) => <span className="text-xs font-medium" style={STATUS_COLOR[t.status] ?? { color: 'var(--text-2)' }}>{t.status}</span> },
            { key: 'time', header: 'Time', render: (t: any) => <span className="text-xs text-[var(--text-3)]">{timeAgo(t.created_at)}</span> },
          ]}
        />
      )}

      {subTab === 'attachments' && (
        <div className="g-card overflow-hidden">
          <DataTable<any>
            rows={attachments}
            rowKey={(a: any) => a.id}
            onRowClick={a => setSelected(selected?.id === a.id ? null : a)}
            rowStyle={(a: any) => selected?.id === a.id ? SELECTED_ROW_STYLE : undefined}
            columns={[
              { key: 'filename', header: 'Filename', render: (a: any) => <div className="text-xs font-medium text-[var(--text-1)] truncate max-w-[180px]">{a.filename}</div> },
              { key: 'type', header: 'Type', render: (a: any) => <span className="text-[10px] font-mono text-[var(--accent)] uppercase">{a.file_type}</span> },
              { key: 'size', header: 'Size', render: (a: any) => <span className="text-xs text-[var(--text-2)]">{Math.round(a.file_size / 1024)} KB</span> },
              { key: 'verdict', header: 'Verdict', render: (a: any) => <span className="text-[10px] px-1.5 py-0.5 rounded" style={THREAT_COLOR[a.verdict === 'malicious' ? 'phishing' : a.verdict === 'suspicious' ? 'spam' : 'clean']}>{a.verdict}</span> },
              { key: 'macros', header: 'Macros', render: (a: any) => a.has_macros ? <AlertTriangle className="h-3.5 w-3.5" style={{ color: 'var(--red)' }} /> : <CheckCircle className="h-3.5 w-3.5" style={{ color: 'var(--green)' }} /> },
              { key: 'embedded', header: 'Embedded', render: (a: any) => a.has_embedded ? <AlertTriangle className="h-3.5 w-3.5" style={{ color: 'var(--orange)' }} /> : <CheckCircle className="h-3.5 w-3.5" style={{ color: 'var(--green)' }} /> },
              { key: 'sandbox', header: 'Sandbox', render: (a: any) => <div className="text-[10px] text-[var(--text-3)] truncate max-w-[200px]">{a.sandbox_result || '—'}</div> },
              { key: 'sha256', header: 'SHA256', render: (a: any) => <span className="text-[10px] font-mono text-[var(--text-3)] truncate max-w-[100px] block">{a.sha256?.slice(0, 16)}...</span> },
              { key: 'time', header: 'Time', render: (a: any) => <span className="text-xs text-[var(--text-3)]">{timeAgo(a.created_at)}</span> },
            ]}
          />
          {selected && selected.sandbox_result && (
            <div className="p-4 border-t border-[var(--border)] space-y-2">
              <div className="text-xs font-medium text-[var(--text-1)]">Sandbox Analysis — {selected.filename}</div>
              <div className="g-card p-3 text-xs font-mono text-[var(--text-2)] whitespace-pre-wrap">{selected.sandbox_result}</div>
              <div className="flex gap-2 text-[10px] text-[var(--text-3)]">
                <span>MD5: {selected.md5}</span>
                <span>SHA256: {selected.sha256}</span>
              </div>
            </div>
          )}
        </div>
      )}

      {subTab === 'urls' && (
        <DataTable<any>
          rows={urls}
          rowKey={(u: any) => u.id}
          columns={[
            { key: 'url', header: 'URL', render: (u: any) => <div className="text-xs font-mono text-[var(--text-1)] truncate max-w-[200px]">{u.url}</div> },
            { key: 'domain', header: 'Domain', render: (u: any) => <span className="text-xs text-[var(--accent)]">{u.domain}</span> },
            { key: 'verdict', header: 'Verdict', render: (u: any) => <span className="text-[10px] px-1.5 py-0.5 rounded" style={THREAT_COLOR[u.verdict === 'malicious' ? 'phishing' : u.verdict === 'suspicious' ? 'spam' : 'clean']}>{u.verdict}</span> },
            { key: 'reputation', header: 'Reputation', render: (u: any) => <span className="text-xs font-medium" style={{ color: u.reputation === 'malicious' ? 'var(--red)' : u.reputation === 'clean' ? 'var(--green)' : 'var(--yellow)' }}>{u.reputation}</span> },
            { key: 'redirects', header: 'Redirects', render: (u: any) => <span className="text-xs font-bold" style={{ color: u.redirect_count > 1 ? 'var(--orange)' : 'var(--text-2)' }}>{u.redirect_count}</span> },
            { key: 'shortened', header: 'Shortened', render: (u: any) => u.is_shortened ? <AlertTriangle className="h-3.5 w-3.5" style={{ color: 'var(--orange)' }} /> : <span className="text-[var(--text-3)]">—</span> },
            { key: 'new_domain', header: 'New Domain', render: (u: any) => u.is_newly_registered ? <AlertTriangle className="h-3.5 w-3.5" style={{ color: 'var(--red)' }} /> : <span className="text-[var(--text-3)]">—</span> },
            { key: 'login_form', header: 'Login Form', render: (u: any) => u.has_login_form ? <Eye className="h-3.5 w-3.5" style={{ color: 'var(--yellow)' }} /> : <span className="text-[var(--text-3)]">—</span> },
            { key: 'clicks', header: 'Clicks', render: (u: any) => <span className="text-xs font-bold" style={{ color: u.click_count > 0 ? 'var(--red)' : 'var(--text-3)' }}>{u.click_count}</span> },
            { key: 'time', header: 'Time', render: (u: any) => <span className="text-xs text-[var(--text-3)]">{timeAgo(u.created_at)}</span> },
          ]}
        />
      )}
    </div>
  );
}

// ── Auth Tab ──────────────────────────────────────────────────────────────────

function AuthTab() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    emailSecurityAPI.getAuthResults().then(r => { setData(r.data); setLoading(false); });
  }, []);

  if (loading) return <div className="text-[var(--text-3)] text-sm p-4">Loading...</div>;

  const s = data?.summary ?? {};
  const PROTOCOLS = ['SPF', 'DKIM', 'DMARC', 'ARC', 'BIMI'];
  const rates: Record<string, number> = { SPF: s.spf_rate ?? 0, DKIM: s.dkim_rate ?? 0, DMARC: s.dmarc_rate ?? 0, ARC: 42, BIMI: 31 };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {PROTOCOLS.map(proto => (
          <div key={proto} className="g-card p-4 text-center space-y-2">
            <div className="text-sm font-bold text-[var(--text-1)]">{proto}</div>
            <div className="text-2xl font-bold" style={{ color: rates[proto] > 80 ? 'var(--green)' : rates[proto] > 60 ? 'var(--yellow)' : 'var(--red)' }}>{rates[proto]}%</div>
            <div className="h-1.5 rounded-full bg-[var(--border)]">
              <div className="h-full rounded-full" style={{ width: `${rates[proto]}%`, background: rates[proto] > 80 ? 'var(--green)' : rates[proto] > 60 ? 'var(--yellow)' : 'var(--red)' }} />
            </div>
            <div className="text-[10px] text-[var(--text-3)]">pass rate</div>
          </div>
        ))}
      </div>

      <SectionCard title="Per-Domain Authentication Results">
        <div className="space-y-3">
          <DataTable<any>
            rows={data?.domains ?? []}
            rowKey={(d: any) => d.domain}
            columns={[
              { key: 'domain', header: 'Domain', render: (d: any) => <span className="text-xs font-mono text-[var(--text-1)]">{d.domain}</span> },
              { key: 'spf', header: 'SPF', render: (d: any) => <span className="text-xs font-bold" style={AUTH_COLOR[d.spf] ?? { color: 'var(--text-3)' }}>{d.spf}</span> },
              { key: 'dkim', header: 'DKIM', render: (d: any) => <span className="text-xs font-bold" style={AUTH_COLOR[d.dkim] ?? { color: 'var(--text-3)' }}>{d.dkim}</span> },
              { key: 'dmarc', header: 'DMARC', render: (d: any) => <span className="text-xs font-bold" style={AUTH_COLOR[d.dmarc] ?? { color: 'var(--text-3)' }}>{d.dmarc}</span> },
              { key: 'arc', header: 'ARC', render: (d: any) => <span className="text-xs font-bold" style={AUTH_COLOR[d.arc] ?? { color: 'var(--text-3)' }}>{d.arc}</span> },
              { key: 'bimi', header: 'BIMI', render: (d: any) => <span className="text-xs font-bold" style={AUTH_COLOR[d.bimi] ?? { color: 'var(--text-3)' }}>{d.bimi}</span> },
              { key: 'aligned', header: 'Aligned', render: (d: any) => d.aligned ? <CheckCircle className="h-3.5 w-3.5" style={{ color: 'var(--green)' }} /> : <XCircle className="h-3.5 w-3.5" style={{ color: 'var(--red)' }} /> },
              { key: 'policy', header: 'Policy', render: (d: any) => <span className="text-[10px] px-1.5 py-0.5 rounded" style={d.policy === 'reject' ? { background: 'var(--green-bg)', border: '1px solid var(--green-border)', color: 'var(--green)' } : d.policy === 'quarantine' ? { background: 'var(--yellow-bg)', border: '1px solid var(--yellow-border)', color: 'var(--yellow)' } : { background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-3)' }}>{d.policy}</span> },
            ]}
          />
          <div className="g-card p-3 text-xs text-[var(--text-2)] space-y-1">
            <div className="font-medium text-[var(--text-1)]">Recommendations</div>
            <div>• Set DMARC policy to <span className="font-bold" style={{ color: 'var(--green)' }}>reject</span> on all owned domains to prevent spoofing</div>
            <div>• 29% of inbound emails fail DMARC — consider enforcing strict alignment</div>
            <div>• Implement BIMI with VMC to enable brand logo display in supported email clients</div>
            <div>• Enable ARC sealing on your outbound email gateway</div>
          </div>
        </div>
      </SectionCard>
    </div>
  );
}

// ── Campaigns Tab ─────────────────────────────────────────────────────────────

function CampaignsTab() {
  const [campaigns, setCampaigns] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<any>(null);

  useEffect(() => {
    emailSecurityAPI.getCampaigns().then(r => { setCampaigns(r.data ?? []); setLoading(false); });
  }, []);

  const CAMPAIGN_COLOR: Record<string, React.CSSProperties> = {
    phishing: THREAT_COLOR.phishing,
    bec: THREAT_COLOR.bec,
    malware: THREAT_COLOR.malware,
    spam: THREAT_COLOR.spam,
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          <DataTable<any>
            loading={loading}
            rows={campaigns}
            rowKey={(c: any) => c.id}
            onRowClick={c => setSelected(selected?.id === c.id ? null : c)}
            rowStyle={(c: any) => selected?.id === c.id ? SELECTED_ROW_STYLE : undefined}
            columns={[
              { key: 'name', header: 'Campaign', render: (c: any) => <span className="text-xs font-medium text-[var(--text-1)]">{c.name}</span> },
              { key: 'type', header: 'Type', render: (c: any) => <span className="text-[10px] px-1.5 py-0.5 rounded" style={CAMPAIGN_COLOR[c.campaign_type] ?? THREAT_COLOR.spam}>{c.campaign_type}</span> },
              { key: 'actor', header: 'Actor', render: (c: any) => <span className="text-xs text-[var(--text-2)]">{c.threat_actor || '—'}</span> },
              { key: 'emails', header: 'Emails', render: (c: any) => <span className="text-xs font-bold text-[var(--text-1)]">{c.email_count}</span> },
              { key: 'victims', header: 'Victims', render: (c: any) => <span className="text-xs font-bold" style={{ color: c.victim_count > 0 ? 'var(--red)' : 'var(--green)' }}>{c.victim_count}</span> },
              { key: 'malware', header: 'Malware', render: (c: any) => <span className="text-xs" style={{ color: 'var(--blue)' }}>{c.malware_family || '—'}</span> },
              { key: 'status', header: 'Status', render: (c: any) => <span className="text-[10px] px-1.5 py-0.5 rounded" style={c.status === 'active' ? { background: 'var(--red-bg)', border: '1px solid var(--red-border)', color: 'var(--red)' } : { background: 'var(--green-bg)', border: '1px solid var(--green-border)', color: 'var(--green)' }}>{c.status}</span> },
              { key: 'last_seen', header: 'Last Seen', render: (c: any) => <span className="text-xs text-[var(--text-3)]">{timeAgo(c.last_seen)}</span> },
            ]}
          />
        </div>

        <div className="space-y-3">
          {selected ? (
            <div className="g-card p-4 space-y-3">
              <div className="text-sm font-semibold text-[var(--text-1)]">{selected.name}</div>
              <dl className="space-y-2 text-xs">
                {([
                  ['Type', selected.campaign_type],
                  ['Threat Actor', selected.threat_actor || 'Unknown'],
                  ['Emails', selected.email_count],
                  ['Victims', selected.victim_count],
                  ['Common Subject', selected.common_subject],
                  ['Common Sender', selected.common_sender],
                  ['Common Domain', selected.common_domain],
                  ['Malware Family', selected.malware_family || '—'],
                  ['First Seen', new Date(selected.first_seen).toLocaleString()],
                  ['Last Seen', new Date(selected.last_seen).toLocaleString()],
                ] as [string, any][]).map(([k, v]) => (
                  <div key={k}>
                    <dt className="text-[var(--text-3)] text-[10px]">{k}</dt>
                    <dd className="text-[var(--text-1)] font-mono text-[10px] truncate">{v}</dd>
                  </div>
                ))}
              </dl>
              <div className="flex gap-2 pt-2 border-t border-[var(--border)]">
                <ActionButton variant="primary" className="text-xs flex-1 justify-center" onClick={() => emailSecurityAPI.respond({ action: 'block_domain', domain: selected.common_domain })}>Block Domain</ActionButton>
                <ActionButton variant="ghost" className="text-xs flex-1 justify-center" onClick={() => emailSecurityAPI.respond({ action: 'create_incident' })}>Create Incident</ActionButton>
              </div>
            </div>
          ) : (
            <div className="g-card p-4 text-xs text-[var(--text-3)] text-center">Select a campaign for details</div>
          )}
          <div className="g-card p-3 space-y-2">
            <div className="text-xs font-medium text-[var(--text-1)]">Grouping Signals</div>
            {['Same Subject', 'Same Sender', 'Same Attachment Hash', 'Same URL/Domain', 'Same Threat Actor', 'Same IP/ASN'].map(s => (
              <div key={s} className="flex items-center gap-2 text-xs">
                <div className="h-1.5 w-1.5 rounded-full bg-[var(--accent)]" />
                <span className="text-[var(--text-2)]">{s}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Intelligence Tab ──────────────────────────────────────────────────────────

function IntelligenceTab() {
  const [intel, setIntel] = useState<any>(null);
  const [senderDomain, setSenderDomain] = useState('');
  const [senderData, setSenderData] = useState<any>(null);
  const [loadingSender, setLoadingSender] = useState(false);
  const [aiResult, setAiResult] = useState<any>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiMode, setAiMode] = useState('analyze');
  const [aiContent, setAiContent] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    emailSecurityAPI.getThreatIntel().then(r => { setIntel(r.data); setLoading(false); });
  }, []);

  const lookupSender = async () => {
    if (!senderDomain.trim()) return;
    setLoadingSender(true);
    const r = await emailSecurityAPI.getSenderIntel({ domain: senderDomain });
    setSenderData(r.data);
    setLoadingSender(false);
  };

  const runAI = async () => {
    if (!aiContent.trim()) return;
    setAiLoading(true); setAiResult(null);
    const payload: any = { mode: aiMode };
    if (aiMode === 'analyze') { payload.subject = aiContent.split('\n')[0]; payload.content = aiContent; }
    else if (aiMode === 'url') { payload.url = aiContent; }
    else if (aiMode === 'attachment') { payload.hash = aiContent; }
    else payload.content = aiContent;
    const r = await emailSecurityAPI.analyzeAI(payload);
    setAiResult(r.data); setAiLoading(false);
  };

  const barMax = useMemo(() => Math.max(...(intel?.by_threat_type ?? []).map((t: any) => t.count), 1), [intel]);

  return (
    <div className="space-y-4">
      {!loading && intel && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <SectionCard title="Malicious Domains">
            <div className="space-y-3">
              {(intel.malicious_domains ?? []).map((d: any) => (
                <div key={d.domain} className="space-y-0.5">
                  <div className="flex justify-between text-xs">
                    <span className="font-mono" style={{ color: 'var(--red)' }}>{d.domain}</span>
                    <span className="text-[var(--text-3)] font-bold">{d.hits} hits</span>
                  </div>
                  <div className="text-[10px] text-[var(--text-3)] capitalize">{d.category.replace(/_/g, ' ')} · since {d.first_seen}</div>
                </div>
              ))}
            </div>
          </SectionCard>

          <SectionCard title="Threat Distribution">
            <div className="space-y-3">
              {(intel.by_threat_type ?? []).map((t: any) => (
                <div key={t.type} className="space-y-1">
                  <div className="flex justify-between text-xs">
                    <span className="capitalize text-[var(--text-2)]">{t.type}</span>
                    <span className="text-[var(--accent)] font-bold">{t.count}</span>
                  </div>
                  <div className="h-1 rounded-full bg-[var(--border)]">
                    <div className="h-full rounded-full bg-[var(--accent)]" style={{ width: `${Math.round(t.count / barMax * 100)}%` }} />
                  </div>
                </div>
              ))}
              <div className="pt-2 border-t border-[var(--border)] space-y-2">
                <div className="text-xs font-medium text-[var(--text-1)]">Malware Families</div>
                {(intel.malware_families ?? []).map((m: any) => (
                  <div key={m.family} className="flex justify-between text-xs">
                    <span style={{ color: 'var(--blue)' }}>{m.family}</span>
                    <span className="text-[var(--text-3)]">{m.category} · {m.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </SectionCard>

          <SectionCard title="Threat Actors">
            <div className="space-y-3">
              {(intel.threat_actors ?? []).map((a: any) => (
                <div key={a.actor} className="space-y-0.5">
                  <div className="text-xs font-medium" style={{ color: 'var(--orange)' }}>{a.actor}</div>
                  <div className="text-[10px] text-[var(--text-3)]">{a.campaigns} campaigns · targeting {a.target_industry}</div>
                  <div className="text-[10px] text-[var(--text-3)]">{a.email_volume} emails</div>
                </div>
              ))}
              <div className="pt-2 border-t border-[var(--border)] space-y-2">
                <div className="text-xs font-medium text-[var(--text-1)]">Malicious IPs</div>
                {(intel.malicious_ips ?? []).map((ip: any) => (
                  <div key={ip.ip} className="flex justify-between text-xs">
                    <span className="font-mono" style={{ color: 'var(--red)' }}>{ip.ip}</span>
                    <span className="text-[var(--text-3)]">{ip.country} · {ip.hits}</span>
                  </div>
                ))}
              </div>
            </div>
          </SectionCard>
        </div>
      )}

      <SectionCard title="Sender Intelligence Lookup">
        <div className="space-y-3">
          <div className="flex gap-2">
            <input className="g-input text-xs flex-1" placeholder="e.g. suspicious-bank.xyz or noreply@example.com" value={senderDomain} onChange={e => setSenderDomain(e.target.value)} onKeyDown={e => e.key === 'Enter' && lookupSender()} />
            <ActionButton variant="primary" className="text-xs" onClick={lookupSender} loading={loadingSender}>Look Up</ActionButton>
          </div>
          {senderData && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="g-card p-3 text-center">
                <div className="text-xs text-[var(--text-3)]">Reputation</div>
                <div className="text-sm font-bold" style={{ color: senderData.reputation === 'malicious' ? 'var(--red)' : senderData.reputation === 'trusted' ? 'var(--green)' : 'var(--yellow)' }}>{senderData.reputation}</div>
              </div>
              <div className="g-card p-3 text-center">
                <div className="text-xs text-[var(--text-3)]">Score</div>
                <div className="text-sm font-bold" style={{ color: senderData.reputation_score < 30 ? 'var(--red)' : senderData.reputation_score > 70 ? 'var(--green)' : 'var(--yellow)' }}>{senderData.reputation_score}/100</div>
              </div>
              <div className="g-card p-3 text-center">
                <div className="text-xs text-[var(--text-3)]">Domain Age</div>
                <div className="text-sm font-bold" style={{ color: senderData.domain_age_days < 30 ? 'var(--red)' : 'var(--text-1)' }}>{senderData.domain_age_days}d</div>
              </div>
              <div className="g-card p-3 text-center">
                <div className="text-xs text-[var(--text-3)]">Threat Intel Hits</div>
                <div className="text-sm font-bold" style={{ color: senderData.threat_intel_hits > 0 ? 'var(--red)' : 'var(--green)' }}>{senderData.threat_intel_hits}</div>
              </div>
              <div className="g-card p-3 col-span-2">
                <div className="text-xs text-[var(--text-3)]">WHOIS</div>
                <div className="text-xs text-[var(--text-1)]">{senderData.whois_registrar} · created {senderData.whois_created}</div>
              </div>
              <div className="g-card p-3 col-span-2">
                <div className="text-xs text-[var(--text-3)]">GeoIP / ASN</div>
                <div className="text-xs text-[var(--text-1)]">{senderData.geo_city}, {senderData.geo_country} · {senderData.asn} ({senderData.asn_org})</div>
              </div>
            </div>
          )}
        </div>
      </SectionCard>

      <SectionCard title="AI Email Analysis">
        <div className="space-y-3">
          <div className="flex gap-2 flex-wrap">
            {[['analyze', 'Analyze Email'], ['url', 'Analyze URL'], ['attachment', 'Analyze Hash'], ['ask', 'Ask AI']].map(([mode, label]) => (
              <ActionButton key={mode} variant={aiMode === mode ? 'primary' : 'ghost'} onClick={() => setAiMode(mode)} className="text-xs">
                {label}
              </ActionButton>
            ))}
          </div>
          <textarea className="g-input text-xs w-full resize-none" rows={3}
            placeholder={aiMode === 'analyze' ? 'Paste email subject/content...' : aiMode === 'url' ? 'Paste suspicious URL...' : aiMode === 'attachment' ? 'Paste file hash (SHA256/MD5)...' : 'Ask about email security...'}
            value={aiContent} onChange={e => setAiContent(e.target.value)} />
          <div className="flex flex-wrap gap-1.5">
            {[
              'This message imitates your finance department and requests an urgent wire transfer.',
              'The attached Office document contains macros commonly used in phishing campaigns.',
              'The embedded link redirects through multiple domains before reaching a credential harvesting page.',
            ].map((ex, i) => (
              <button key={i} className="text-[10px] px-2 py-1 rounded bg-[var(--glass-bg)] border border-[var(--border)] text-[var(--text-3)] hover:text-[var(--text-1)] hover:border-[var(--accent-border)] transition-colors" onClick={() => setAiContent(ex)}>
                {ex.slice(0, 55)}...
              </button>
            ))}
          </div>
          <ActionButton variant="primary" icon={Brain} onClick={runAI} loading={aiLoading} className="text-xs">
            Analyze
          </ActionButton>

          {aiResult && (
            <div className="space-y-3 border-t border-[var(--border)] pt-3">
              {aiResult.verdict && (
                <div className="flex items-center gap-2">
                  <ThreatBadge type={aiResult.verdict === 'malicious' ? 'phishing' : aiResult.verdict === 'suspicious' ? 'spam' : 'clean'} />
                  <span className="text-sm font-bold text-[var(--text-1)] capitalize">{aiResult.verdict}</span>
                  {aiResult.confidence && <span className="text-xs text-[var(--text-3)]">Confidence: <span className="text-[var(--accent)]">{aiResult.confidence}%</span></span>}
                </div>
              )}
              {(aiResult.explanation || aiResult.answer) && (
                <div className="g-card p-3 text-sm text-[var(--text-2)] leading-relaxed">{aiResult.explanation || aiResult.answer}</div>
              )}
              {aiResult.indicators?.length > 0 && (
                <div>
                  <div className="text-xs text-[var(--text-3)] mb-1">Indicators</div>
                  <ul className="space-y-0.5">{aiResult.indicators.map((ind: string, i: number) => <li key={i} className="text-xs text-[var(--text-2)] flex gap-1.5 items-start"><AlertTriangle className="h-3 w-3 shrink-0 mt-0.5" style={{ color: 'var(--red)' }} />{ind}</li>)}</ul>
                </div>
              )}
              {aiResult.mitre_techniques?.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {aiResult.mitre_techniques.map((t: string) => (
                    <span key={t} className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'var(--blue-bg)', border: '1px solid var(--blue-border)', color: 'var(--blue)' }}>{t}</span>
                  ))}
                </div>
              )}
              {aiResult.recommended_actions?.length > 0 && (
                <div>
                  <div className="text-xs text-[var(--text-3)] mb-1">Recommended Actions</div>
                  <ul className="space-y-0.5">{aiResult.recommended_actions.map((a: string, i: number) => <li key={i} className="text-xs text-[var(--text-2)] flex gap-1.5 items-start"><ChevronRight className="h-3 w-3 shrink-0 mt-0.5" style={{ color: 'var(--accent)' }} />{a}</li>)}</ul>
                </div>
              )}
            </div>
          )}
        </div>
      </SectionCard>
    </div>
  );
}

// ── User Risk Tab ─────────────────────────────────────────────────────────────

function UserRiskTab() {
  const [users, setUsers] = useState<any[]>([]);
  const [reported, setReported] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [subTab, setSubTab] = useState<'risk' | 'reported'>('risk');
  const [triaging, setTriaging] = useState<number | null>(null);
  const [notes, setNotes] = useState('');

  const reload = () => {
    setLoading(true);
    Promise.all([emailSecurityAPI.getUserRisk(), emailSecurityAPI.getReported()])
      .then(([ur, rr]) => { setUsers(ur.data ?? []); setReported(rr.data ?? []); setLoading(false); });
  };
  useEffect(() => { reload(); }, []);

  const doTriage = async (id: number, status: string) => {
    await emailSecurityAPI.patchReported(id, { triage_status: status, analyst_notes: notes });
    setTriaging(null);
    reload();
  };

  const TRAINING_COLOR: Record<string, React.CSSProperties> = {
    completed:   { color: 'var(--green)' },
    in_progress: { color: 'var(--yellow)' },
    pending:     { color: 'var(--red)' },
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        {(['risk', 'reported'] as const).map(s => (
          <ActionButton key={s} variant={subTab === s ? 'primary' : 'ghost'} onClick={() => setSubTab(s)} className="text-xs">
            {s === 'risk' ? `User Risk (${users.length})` : `Reported Phishing (${reported.length})`}
          </ActionButton>
        ))}
      </div>

      {loading ? <div className="text-[var(--text-3)] text-sm">Loading...</div> : subTab === 'risk' ? (
        <DataTable<any>
          rows={users}
          rowKey={(u: any) => u.id}
          columns={[
            { key: 'user', header: 'User', render: (u: any) => (
              <div>
                <div className="text-xs font-medium text-[var(--text-1)]">{u.display_name}</div>
                <div className="text-[10px] text-[var(--text-3)]">{u.email}</div>
              </div>
            ) },
            { key: 'department', header: 'Department', render: (u: any) => <span className="text-xs text-[var(--text-2)]">{u.department}</span> },
            { key: 'clicks', header: 'Clicks', render: (u: any) => <span className="text-xs font-bold" style={{ color: u.click_count > 0 ? 'var(--red)' : 'var(--green)' }}>{u.click_count}</span> },
            { key: 'failures', header: 'Failures', render: (u: any) => <span className="text-xs font-bold" style={{ color: u.phishing_failures > 0 ? 'var(--red)' : 'var(--green)' }}>{u.phishing_failures}</span> },
            { key: 'repeated', header: 'Repeated', render: (u: any) => u.is_repeated_victim ? <AlertTriangle className="h-3.5 w-3.5" style={{ color: 'var(--orange)' }} /> : <CheckCircle className="h-3.5 w-3.5" style={{ color: 'var(--green)' }} /> },
            { key: 'training', header: 'Training', render: (u: any) => <span className="text-xs font-medium capitalize" style={TRAINING_COLOR[u.training_status] ?? { color: 'var(--text-2)' }}>{u.training_status.replace('_', ' ')}</span> },
            { key: 'risk_score', header: 'Risk Score', render: (u: any) => (
              <div className="flex items-center gap-1.5">
                <div className="w-12 h-1.5 rounded-full bg-[var(--border)]">
                  <div className="h-full rounded-full" style={{ width: `${u.risk_score}%`, background: u.risk_score > 75 ? 'var(--red)' : u.risk_score > 50 ? 'var(--orange)' : 'var(--yellow)' }} />
                </div>
                <span className="text-xs font-bold" style={{ color: u.risk_score > 75 ? 'var(--red)' : u.risk_score > 50 ? 'var(--orange)' : 'var(--text-2)' }}>{u.risk_score}</span>
              </div>
            ) },
            { key: 'last_click', header: 'Last Click', render: (u: any) => <span className="text-xs text-[var(--text-3)]">{u.last_click_at ? timeAgo(u.last_click_at) : 'Never'}</span> },
          ]}
        />
      ) : (
        <div className="space-y-3">
          {reported.map((r: any) => (
            <div key={r.id} className={`g-card p-4 space-y-3 ${triaging === r.id ? 'border-[var(--accent-border)]' : ''}`}>
              <div className="flex items-start justify-between gap-3">
                <div className="space-y-0.5 min-w-0">
                  <div className="text-xs font-medium text-[var(--text-1)] truncate">{r.subject}</div>
                  <div className="text-[10px] text-[var(--text-3)]">From: {r.original_sender} · Reported by: {r.reporter_email}</div>
                  <div className="text-[10px] text-[var(--text-3)]">{timeAgo(r.reported_at)}</div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-[10px] px-1.5 py-0.5 rounded" style={
                    r.auto_verdict === 'phishing' ? THREAT_COLOR.phishing :
                    r.auto_verdict === 'bec' ? THREAT_COLOR.bec :
                    r.auto_verdict === 'clean' ? THREAT_COLOR.clean : THREAT_COLOR.spam
                  }>{r.auto_verdict || 'unknown'}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded" style={
                    r.triage_status === 'confirmed_phishing' ? { background: 'var(--red-bg)', border: '1px solid var(--red-border)', color: 'var(--red)' } :
                    r.triage_status === 'false_positive' ? { background: 'var(--green-bg)', border: '1px solid var(--green-border)', color: 'var(--green)' } :
                    r.triage_status === 'escalated' ? { background: 'var(--orange-bg)', border: '1px solid var(--orange-border)', color: 'var(--orange)' } :
                    { background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-3)' }
                  }>{r.triage_status.replace('_', ' ')}</span>
                </div>
              </div>
              {r.analyst_notes && <div className="text-xs text-[var(--text-2)] italic">{r.analyst_notes}</div>}
              {triaging === r.id ? (
                <div className="space-y-2">
                  <textarea className="g-input text-xs w-full resize-none" rows={2} placeholder="Analyst notes..." value={notes} onChange={e => setNotes(e.target.value)} />
                  <div className="flex gap-1.5 flex-wrap">
                    {(['confirmed_phishing', 'false_positive', 'escalated'] as string[]).map(s => (
                      <ActionButton key={s} variant="ghost" onClick={() => doTriage(r.id, s)} className="text-xs capitalize">{s.replace('_', ' ')}</ActionButton>
                    ))}
                    <ActionButton variant="ghost" onClick={() => setTriaging(null)} className="text-xs">Cancel</ActionButton>
                  </div>
                </div>
              ) : (
                <ActionButton variant="ghost" onClick={() => { setTriaging(r.id); setNotes(r.analyst_notes); }} className="text-xs">
                  {r.triage_status === 'pending' ? 'Triage' : 'Edit Triage'}
                </ActionButton>
              )}
            </div>
          ))}
          {reported.length === 0 && <div className="g-card p-8 text-center text-[var(--text-3)] text-sm">No user-reported phishing</div>}
        </div>
      )}
    </div>
  );
}

// ── Analytics Tab ─────────────────────────────────────────────────────────────

function AnalyticsTab() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => { emailSecurityAPI.getAnalytics().then(r => { setData(r.data); setLoading(false); }); }, []);

  const phishingBarMax = useMemo(() => Math.max(...(data?.phishing_trend ?? []).map((d: any) => d.count), 1), [data]);
  const becBarMax = useMemo(() => Math.max(...(data?.bec_trend ?? []).map((d: any) => d.count), 1), [data]);

  if (loading) return <div className="text-[var(--text-3)] text-sm p-4">Loading...</div>;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <SectionCard title="Top Threat Senders">
          <div className="space-y-2">
            {(data?.top_senders ?? []).map((s: any, i: number) => (
              <div key={i} className="flex justify-between text-xs">
                <span className="font-mono truncate max-w-[160px]" style={{ color: 'var(--red)' }}>{s.sender}</span>
                <span className="text-[var(--text-2)] font-bold shrink-0 ml-2">{s.count}</span>
              </div>
            ))}
          </div>
        </SectionCard>

        <SectionCard title="Top Blocked URL Domains">
          <div className="space-y-2">
            {(data?.top_blocked_urls ?? []).map((u: any, i: number) => (
              <div key={i} className="flex justify-between text-xs">
                <span className="font-mono" style={{ color: 'var(--orange)' }}>{u.domain}</span>
                <span className="text-[var(--text-2)] font-bold">{u.count}</span>
              </div>
            ))}
          </div>
        </SectionCard>

        <SectionCard title="14-Day BEC Trend">
          <div className="flex items-end gap-0.5 h-20">
            {(data?.bec_trend ?? []).map((d: any, i: number) => (
              <div key={i} className="flex-1 flex flex-col items-center gap-0.5">
                <div className="w-full rounded-sm opacity-70 hover:opacity-100" style={{ height: `${Math.round(d.count / becBarMax * 72) + 2}px`, background: 'var(--orange)' }} title={`${d.date}: ${d.count}`} />
                {i % 3 === 0 && <div className="text-[9px] text-[var(--text-3)]">{d.date?.slice(5)}</div>}
              </div>
            ))}
          </div>
        </SectionCard>
      </div>

      <SectionCard title="14-Day Phishing Trend">
        <div className="flex items-end gap-0.5 h-24">
          {(data?.phishing_trend ?? []).map((d: any, i: number) => (
            <div key={i} className="flex-1 flex flex-col items-center gap-0.5">
              <div className="w-full rounded-sm opacity-70 hover:opacity-100" style={{ height: `${Math.round(d.count / phishingBarMax * 88) + 2}px`, background: 'var(--red)' }} title={`${d.date}: ${d.count}`} />
              {i % 2 === 0 && <div className="text-[9px] text-[var(--text-3)]">{d.date?.slice(5)}</div>}
            </div>
          ))}
        </div>
      </SectionCard>
    </div>
  );
}

// ── Response Tab ──────────────────────────────────────────────────────────────

function ResponseTab() {
  const [policies, setPolicies] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showNewPolicy, setShowNewPolicy] = useState(false);
  const [policyForm, setPolicyForm] = useState({ name: '', policy_type: 'attachment', action: 'quarantine', criteria: '', priority: 100 });
  const [reportResult, setReportResult] = useState<any>(null);
  const [reportType, setReportType] = useState('executive');
  const [generating, setGenerating] = useState(false);
  const [actionTarget, setActionTarget] = useState({ action: '', value: '' });
  const [actioning, setActioning] = useState(false);
  const [actionResult, setActionResult] = useState('');

  const reloadPolicies = () => {
    setLoading(true);
    emailSecurityAPI.getPolicies().then(r => { setPolicies(r.data ?? []); setLoading(false); });
  };
  useEffect(() => { reloadPolicies(); }, []);

  const doCreatePolicy = async () => {
    await emailSecurityAPI.createPolicy(policyForm);
    setShowNewPolicy(false);
    reloadPolicies();
  };
  const doDeletePolicy = async (id: number) => {
    await emailSecurityAPI.deletePolicy(id);
    reloadPolicies();
  };
  const doTogglePolicy = async (p: any) => {
    await emailSecurityAPI.patchPolicy(p.id, { enabled: !p.enabled });
    reloadPolicies();
  };

  const doAction = async () => {
    if (!actionTarget.action) return;
    setActioning(true);
    const r = await emailSecurityAPI.respond({ action: actionTarget.action, sender: actionTarget.value, domain: actionTarget.value, url: actionTarget.value, hash: actionTarget.value });
    setActionResult(r.data?.message ?? 'Done');
    setActioning(false);
  };

  const doGenerateReport = async () => {
    setGenerating(true);
    const r = await emailSecurityAPI.generateReport({ report_type: reportType });
    setReportResult(r.data);
    setGenerating(false);
  };

  const RESPONSE_ACTIONS = [
    ['quarantine_email', 'Quarantine Email', 'message_id'],
    ['delete_email',     'Delete from Mailboxes', 'message_id'],
    ['block_sender',     'Block Sender', 'sender email'],
    ['block_domain',     'Block Domain', 'domain'],
    ['block_url',        'Block URL', 'url'],
    ['block_hash',       'Block Attachment Hash', 'sha256'],
    ['reset_password',   'Reset User Password', 'email'],
    ['create_incident',  'Create Incident', ''],
    ['run_soar_playbook','Run SOAR Playbook', 'playbook name'],
  ] as [string, string, string][];

  const POLICY_TYPES = ['attachment', 'url', 'spam', 'bec', 'allowlist', 'blocklist', 'size_limit', 'file_type'];
  const ACTION_TYPES = ['allow', 'block', 'quarantine', 'tag', 'redirect'];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <SectionCard title="Response Actions">
          <div className="space-y-3">
            <div className="grid grid-cols-1 gap-2">
              {RESPONSE_ACTIONS.map(([action, label, target]) => (
                <div key={action} className="flex gap-2">
                  <ActionButton
                    variant={actionTarget.action === action ? 'primary' : 'ghost'}
                    icon={Zap}
                    className="text-xs whitespace-nowrap"
                    onClick={() => setActionTarget(t => ({ action: t.action === action ? '' : action, value: t.action === action ? t.value : '' }))}
                  >
                    {label}
                  </ActionButton>
                  {actionTarget.action === action && target && (
                    <input className="g-input text-xs flex-1" placeholder={target} value={actionTarget.value} onChange={e => setActionTarget(t => ({ ...t, value: e.target.value }))} />
                  )}
                  {actionTarget.action === action && (
                    <ActionButton variant="primary" className="text-xs whitespace-nowrap" onClick={doAction} loading={actioning}>Execute</ActionButton>
                  )}
                </div>
              ))}
            </div>
            {actionResult && <div className="g-card p-2 text-xs" style={{ color: 'var(--green)' }}>{actionResult}</div>}
          </div>
        </SectionCard>

        <div className="space-y-4">
          <SectionCard
            title="Email Policies"
            actions={<ActionButton variant="ghost" icon={Plus} onClick={() => setShowNewPolicy(s => !s)} className="text-xs">Add</ActionButton>}
          >
            <div className="space-y-3">
              {showNewPolicy && (
                <div className="space-y-2 p-3 rounded-lg border border-[var(--accent-border)] bg-[var(--accent)]/5">
                  <input className="g-input text-xs w-full" placeholder="Policy name" value={policyForm.name} onChange={e => setPolicyForm(f => ({ ...f, name: e.target.value }))} />
                  <div className="grid grid-cols-2 gap-2">
                    <select className="g-select text-xs" value={policyForm.policy_type} onChange={e => setPolicyForm(f => ({ ...f, policy_type: e.target.value }))}>
                      {POLICY_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                    </select>
                    <select className="g-select text-xs" value={policyForm.action} onChange={e => setPolicyForm(f => ({ ...f, action: e.target.value }))}>
                      {ACTION_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                    </select>
                  </div>
                  <input className="g-input text-xs w-full" placeholder="Criteria (e.g. file_type IN (exe,dll))" value={policyForm.criteria} onChange={e => setPolicyForm(f => ({ ...f, criteria: e.target.value }))} />
                  <div className="flex gap-2">
                    <ActionButton variant="primary" className="text-xs" onClick={doCreatePolicy}>Create</ActionButton>
                    <ActionButton variant="ghost" className="text-xs" onClick={() => setShowNewPolicy(false)}>Cancel</ActionButton>
                  </div>
                </div>
              )}
              {loading ? <div className="text-[var(--text-3)] text-xs">Loading...</div> : (
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {policies.map((p: any) => (
                    <div key={p.id} className={`flex items-start justify-between gap-2 p-2 rounded border ${p.enabled ? 'border-[var(--border)]' : 'border-[var(--border)] opacity-50'}`}>
                      <div className="min-w-0">
                        <div className="text-xs font-medium text-[var(--text-1)]">{p.name}</div>
                        <div className="text-[10px] text-[var(--text-3)]">{p.policy_type} · {p.action} · priority {p.priority}</div>
                        {p.criteria && <div className="text-[10px] font-mono text-[var(--text-3)] truncate max-w-[220px]">{p.criteria}</div>}
                      </div>
                      <div className="flex gap-1 shrink-0 items-center">
                        <button className="text-[10px] px-1.5 py-0.5 rounded border transition-colors" style={p.enabled ? { borderColor: 'var(--green-border)', color: 'var(--green)' } : { borderColor: 'var(--border)', color: 'var(--text-3)' }} onClick={() => doTogglePolicy(p)}>{p.enabled ? 'ON' : 'OFF'}</button>
                        <button className="text-[var(--text-3)] transition-colors p-0.5" onMouseEnter={e => (e.currentTarget.style.color = 'var(--red)')} onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-3)')} onClick={() => doDeletePolicy(p.id)}><Trash2 className="h-3 w-3" /></button>
                      </div>
                    </div>
                  ))}
                  {policies.length === 0 && <div className="text-xs text-[var(--text-3)] text-center py-4">No policies configured</div>}
                </div>
              )}
            </div>
          </SectionCard>
        </div>
      </div>

      <SectionCard
        title="Security Reports"
        actions={
          <div className="flex gap-2">
            <select className="g-select text-xs" value={reportType} onChange={e => setReportType(e.target.value)}>
              <option value="executive">Executive Summary</option>
              <option value="phishing">Phishing Report</option>
              <option value="bec">BEC Report</option>
              <option value="malware">Malware Report</option>
              <option value="user_risk">User Risk Report</option>
            </select>
            <ActionButton variant="primary" icon={FileText} onClick={doGenerateReport} loading={generating} className="text-xs">Generate</ActionButton>
          </div>
        }
      >
        {reportResult && (
          <div className="space-y-3">
            <div className="text-base font-semibold text-[var(--text-1)]">{reportResult.title}</div>
            <div className="g-card p-3 text-sm text-[var(--text-2)] leading-relaxed">{reportResult.executive_summary}</div>
            {reportResult.key_findings?.length > 0 && (
              <div><div className="text-xs text-[var(--text-3)] mb-1">Key Findings</div>
                <ul className="space-y-1">{reportResult.key_findings.map((f: string, i: number) => <li key={i} className="text-xs text-[var(--text-2)] flex gap-1.5 items-start"><AlertTriangle className="h-3 w-3 shrink-0 mt-0.5" style={{ color: 'var(--red)' }} />{f}</li>)}</ul>
              </div>
            )}
            {reportResult.risk_breakdown && (
              <div className="grid grid-cols-3 gap-3">
                <MetricCard label="Phishing"  value={reportResult.risk_breakdown.phishing ?? 0}  color="var(--red)" />
                <MetricCard label="Malware"   value={reportResult.risk_breakdown.malware ?? 0}   color="var(--blue)" />
                <MetricCard label="BEC"       value={reportResult.risk_breakdown.bec ?? 0}       color="var(--orange)" />
              </div>
            )}
            {reportResult.top_recommendations?.length > 0 && (
              <div><div className="text-xs text-[var(--text-3)] mb-1">Top Recommendations</div>
                <div className="space-y-1">{reportResult.top_recommendations.map((r: any, i: number) => (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    <span className="text-[var(--accent)] font-bold shrink-0">#{r.priority}</span>
                    <div><div className="text-[var(--text-1)]">{r.action}</div><div className="text-[10px] text-[var(--text-3)]">Effort: {r.estimated_effort}</div></div>
                  </div>
                ))}</div>
              </div>
            )}
          </div>
        )}
      </SectionCard>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function EmailSecurityPage() {
  const [tab, setTab] = useState('dashboard');
  const loaded = useRef<Record<string, boolean>>({});

  if (!loaded.current[tab]) loaded.current[tab] = true;

  const TAB_CONTENT: Record<string, React.ReactNode> = {
    dashboard:    <DashboardTab />,
    inbox:        <InboxTab />,
    threats:      <ThreatsTab />,
    auth:         <AuthTab />,
    campaigns:    <CampaignsTab />,
    intelligence: <IntelligenceTab />,
    userrisk:     <UserRiskTab />,
    analytics:    <AnalyticsTab />,
    response:     <ResponseTab />,
  };

  return (
    <RootLayout title="Email Security" subtitle="Phishing · BEC · Malware · URL Analysis · DMARC · Campaign Detection">
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
