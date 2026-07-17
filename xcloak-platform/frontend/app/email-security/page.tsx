'use client';

import { useState, useEffect, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { emailSecurityAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import {
  Mail, Shield, Key, Activity, GitBranch, Brain, BarChart2, Zap, Settings,
  AlertTriangle, CheckCircle, XCircle, Search, RefreshCw, Plus, Trash2,
  FileText, Lock, Eye, DollarSign, Link2, Paperclip, User, AlertCircle,
  TrendingUp, ChevronRight, Clock,
} from 'lucide-react';

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

const THREAT_COLOR: Record<string, string> = {
  phishing: 'bg-red-500/10 text-red-400 border border-red-500/30',
  bec:      'bg-orange-500/10 text-orange-400 border border-orange-500/30',
  malware:  'bg-purple-500/10 text-purple-400 border border-purple-500/30',
  spam:     'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30',
  clean:    'bg-green-500/10 text-green-400 border border-green-500/30',
};
const STATUS_COLOR: Record<string, string> = {
  delivered:   'text-green-400',
  quarantined: 'text-yellow-400',
  blocked:     'text-red-400',
  rejected:    'text-red-400',
};
const AUTH_COLOR: Record<string, string> = {
  pass: 'text-green-400',
  fail: 'text-red-400',
  none: 'text-[var(--text-3)]',
};

function StatCard({ label, value, sub, color = 'text-white', icon: Icon }: {
  label: string; value: number | string; sub?: string; color?: string; icon?: any;
}) {
  return (
    <div className="g-card p-4 space-y-1">
      <div className="flex items-center gap-1.5 text-xs text-[var(--text-3)]">
        {Icon && <Icon className="h-3.5 w-3.5" />}{label}
      </div>
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      {sub && <div className="text-xs text-[var(--text-3)]">{sub}</div>}
    </div>
  );
}

function ThreatBadge({ type }: { type: string }) {
  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded uppercase font-bold ${THREAT_COLOR[type] ?? THREAT_COLOR.spam}`}>
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

  const scoreColor = data?.email_security_score > 85 ? 'text-green-400' : data?.email_security_score > 70 ? 'text-yellow-400' : 'text-red-400';

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <StatCard label="Processed"      value={(data?.emails_processed ?? 0).toLocaleString()} icon={Mail} />
        <StatCard label="Delivered"      value={(data?.emails_delivered ?? 0).toLocaleString()} color="text-green-400" icon={CheckCircle} />
        <StatCard label="Blocked"        value={(data?.emails_blocked ?? 0).toLocaleString()}   color="text-red-400" icon={XCircle} />
        <StatCard label="Security Score" value={`${data?.email_security_score ?? 0}%`}          color={scoreColor} />
        <StatCard label="High-Risk Users" value={data?.high_risk_users ?? 0}                    color="text-orange-400" icon={User} />
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Phishing Attempts"    value={data?.phishing_attempts ?? 0}   color="text-red-400" icon={AlertCircle} />
        <StatCard label="Malware Attachments"  value={data?.malware_attachments ?? 0} color="text-purple-400" icon={Paperclip} />
        <StatCard label="BEC Attempts"         value={data?.bec_attempts ?? 0}        color="text-orange-400" icon={DollarSign} />
        <StatCard label="URL Clicks"           value={data?.url_clicks ?? 0}          color={data?.url_clicks > 0 ? 'text-yellow-400' : 'text-green-400'} icon={Link2} />
      </div>

      {flow && (
        <div className="g-card p-4 space-y-3">
          <div className="text-sm font-medium text-[var(--text-1)]">Mail Flow Pipeline</div>
          <div className="grid grid-cols-3 md:grid-cols-7 gap-2">
            {(flow.steps ?? []).map((step: any, i: number) => (
              <div key={i} className="flex flex-col items-center gap-1 relative">
                <div className="g-card px-2 py-2 text-center w-full space-y-0.5">
                  <div className="text-[10px] text-[var(--text-3)] font-medium">{step.label}</div>
                  <div className="text-sm font-bold text-[var(--text-1)]">{(step.count ?? 0).toLocaleString()}</div>
                  {step.dropped > 0 && <div className="text-[9px] text-red-400">-{step.dropped.toLocaleString()} blocked</div>}
                  {step.quarantined > 0 && <div className="text-[9px] text-yellow-400">-{step.quarantined.toLocaleString()} quarantined</div>}
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
            <span className="text-[var(--text-3)]">Blocked: <span className="text-red-400 font-bold">{(flow.blocked ?? 0).toLocaleString()}</span></span>
            <span className="text-[var(--text-3)]">Quarantined: <span className="text-yellow-400 font-bold">{(flow.quarantined ?? 0).toLocaleString()}</span></span>
          </div>
        </div>
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
        <button className="g-btn-primary text-xs flex items-center gap-1.5" onClick={reload}><Search className="h-3.5 w-3.5" />Search</button>
        <button className="g-btn text-xs" onClick={() => { setSearch({ sender: '', recipient: '', subject: '', status: '', threat_type: '' }); setTimeout(reload, 0); }}><RefreshCw className="h-3.5 w-3.5" /></button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          {loading ? <div className="text-[var(--text-3)] text-sm">Loading...</div> : (
            <div className="g-card overflow-hidden">
              <table className="g-table w-full">
                <thead className="g-thead"><tr>
                  <th>From</th><th>Subject</th><th>To</th><th>Threat</th>
                  <th>Score</th><th>Attach</th><th>URLs</th><th>Status</th><th>Time</th>
                </tr></thead>
                <tbody>
                  {messages.map((m: any) => (
                    <tr key={m.id} className={`g-tr cursor-pointer ${selected?.id === m.id ? 'bg-[var(--accent)]/5' : ''}`} onClick={() => setSelected(selected?.id === m.id ? null : m)}>
                      <td><div className="text-xs text-[var(--text-1)] truncate max-w-[140px]">{m.sender}</div></td>
                      <td><div className="text-xs text-[var(--text-2)] truncate max-w-[180px]">{m.subject}</div></td>
                      <td><div className="text-xs text-[var(--text-3)] truncate max-w-[120px]">{m.recipient}</div></td>
                      <td>{m.threat_type ? <ThreatBadge type={m.threat_type} /> : <span className="text-[10px] text-[var(--text-3)]">—</span>}</td>
                      <td>
                        <div className="flex items-center gap-1">
                          <div className="w-8 h-1.5 rounded-full bg-[var(--border)]">
                            <div className={`h-full rounded-full ${m.threat_score > 80 ? 'bg-red-500' : m.threat_score > 50 ? 'bg-orange-500' : 'bg-green-500'}`} style={{ width: `${m.threat_score}%` }} />
                          </div>
                          <span className={`text-xs font-bold ${m.threat_score > 80 ? 'text-red-400' : m.threat_score > 50 ? 'text-orange-400' : 'text-green-400'}`}>{m.threat_score}</span>
                        </div>
                      </td>
                      <td>{m.has_attachment ? <Paperclip className="h-3.5 w-3.5 text-orange-400" /> : <span className="text-[var(--text-3)]">—</span>}</td>
                      <td><span className={`text-xs ${m.url_count > 0 ? 'text-blue-400' : 'text-[var(--text-3)]'}`}>{m.url_count}</span></td>
                      <td><span className={`text-xs font-medium ${STATUS_COLOR[m.status] ?? 'text-[var(--text-2)]'}`}>{m.status}</span></td>
                      <td><span className="text-xs text-[var(--text-3)]">{timeAgo(m.created_at)}</span></td>
                    </tr>
                  ))}
                  {messages.length === 0 && <tr><td colSpan={9} className="text-center text-[var(--text-3)] py-8">No messages</td></tr>}
                </tbody>
              </table>
            </div>
          )}
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
                  <button key={action} className="g-btn text-xs w-full text-left flex items-center gap-1.5" onClick={() => doRespond(action)} disabled={acting}>
                    <Zap className="h-3 w-3" />{action.replace(/_/g, ' ')}
                  </button>
                ))}
                <button className="g-btn text-xs w-full text-left flex items-center gap-1.5 text-blue-400 hover:border-blue-500/30" onClick={() => {}}>
                  <Search className="h-3 w-3" />Pivot to SIEM
                </button>
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
      <div className="flex gap-2 flex-wrap">
        {(['all', 'phishing', 'bec', 'attachments', 'urls'] as const).map(s => (
          <button key={s} onClick={() => setSubTab(s)}
            className={`text-xs px-3 py-1.5 rounded border transition-colors capitalize ${subTab === s ? 'border-[var(--accent)] text-[var(--accent)] bg-[var(--accent)]/5' : 'border-[var(--border)] text-[var(--text-3)] hover:text-[var(--text-1)]'}`}>
            {s === 'all' ? `All Threats (${threats.length})` : s === 'attachments' ? `Attachments (${attachments.length})` : s === 'urls' ? `URLs (${urls.length})` : s}
          </button>
        ))}
        <button className="g-btn text-xs ml-auto" onClick={reload}><RefreshCw className="h-3.5 w-3.5" /></button>
      </div>

      {(subTab === 'phishing' || subTab === 'bec') && (
        <div className="g-card p-3">
          <div className="text-xs text-[var(--text-3)] font-medium mb-2">{subTab === 'phishing' ? 'Phishing' : 'BEC'} Detection Capabilities</div>
          <div className="flex flex-wrap gap-1.5">
            {(subTab === 'phishing' ? PHISHING_TYPES : BEC_TYPES).map(t => (
              <span key={t} className="text-[10px] px-2 py-0.5 rounded bg-[var(--glass-bg)] border border-[var(--border)] text-[var(--text-2)]">{t}</span>
            ))}
          </div>
        </div>
      )}

      {(subTab === 'all' || subTab === 'phishing' || subTab === 'bec') && (
        loading ? <div className="text-[var(--text-3)] text-sm">Loading...</div> : (
          <div className="g-card overflow-hidden">
            <table className="g-table w-full">
              <thead className="g-thead"><tr>
                <th>Sender</th><th>Subject</th><th>Recipient</th><th>Type</th>
                <th>Score</th><th>Attach</th><th>URLs</th><th>Status</th><th>Time</th>
              </tr></thead>
              <tbody>
                {threats.map((t: any) => (
                  <tr key={t.id} className={`g-tr cursor-pointer ${selected?.id === t.id ? 'bg-[var(--accent)]/5' : ''}`} onClick={() => setSelected(selected?.id === t.id ? null : t)}>
                    <td><div className="text-xs text-[var(--text-1)] truncate max-w-[150px]">{t.sender}</div></td>
                    <td><div className="text-xs text-[var(--text-2)] truncate max-w-[200px]">{t.subject}</div></td>
                    <td><div className="text-xs text-[var(--text-3)] truncate max-w-[120px]">{t.recipient}</div></td>
                    <td><ThreatBadge type={t.threat_type} /></td>
                    <td><span className={`text-sm font-bold ${t.threat_score > 90 ? 'text-red-400' : t.threat_score > 70 ? 'text-orange-400' : 'text-yellow-400'}`}>{t.threat_score}</span></td>
                    <td>{t.has_attachment ? <Paperclip className="h-3.5 w-3.5 text-orange-400" /> : <span className="text-[var(--text-3)]">—</span>}</td>
                    <td><span className={`text-xs ${t.url_count > 0 ? 'text-blue-400' : 'text-[var(--text-3)]'}`}>{t.url_count}</span></td>
                    <td><span className={`text-xs font-medium ${STATUS_COLOR[t.status] ?? 'text-[var(--text-2)]'}`}>{t.status}</span></td>
                    <td><span className="text-xs text-[var(--text-3)]">{timeAgo(t.created_at)}</span></td>
                  </tr>
                ))}
                {threats.length === 0 && <tr><td colSpan={9} className="text-center text-[var(--text-3)] py-8">No threats detected</td></tr>}
              </tbody>
            </table>
          </div>
        )
      )}

      {subTab === 'attachments' && (
        <div className="g-card overflow-hidden">
          <table className="g-table w-full">
            <thead className="g-thead"><tr>
              <th>Filename</th><th>Type</th><th>Size</th><th>Verdict</th>
              <th>Macros</th><th>Embedded</th><th>Sandbox</th><th>SHA256</th><th>Time</th>
            </tr></thead>
            <tbody>
              {attachments.map((a: any) => (
                <tr key={a.id} className={`g-tr cursor-pointer ${selected?.id === a.id ? 'bg-[var(--accent)]/5' : ''}`} onClick={() => setSelected(selected?.id === a.id ? null : a)}>
                  <td><div className="text-xs font-medium text-[var(--text-1)] truncate max-w-[180px]">{a.filename}</div></td>
                  <td><span className="text-[10px] font-mono text-[var(--accent)] uppercase">{a.file_type}</span></td>
                  <td><span className="text-xs text-[var(--text-2)]">{Math.round(a.file_size / 1024)} KB</span></td>
                  <td><span className={`text-[10px] px-1.5 py-0.5 rounded ${THREAT_COLOR[a.verdict === 'malicious' ? 'phishing' : a.verdict === 'suspicious' ? 'spam' : 'clean']}`}>{a.verdict}</span></td>
                  <td>{a.has_macros ? <AlertTriangle className="h-3.5 w-3.5 text-red-400" /> : <CheckCircle className="h-3.5 w-3.5 text-green-400" />}</td>
                  <td>{a.has_embedded ? <AlertTriangle className="h-3.5 w-3.5 text-orange-400" /> : <CheckCircle className="h-3.5 w-3.5 text-green-400" />}</td>
                  <td><div className="text-[10px] text-[var(--text-3)] truncate max-w-[200px]">{a.sandbox_result || '—'}</div></td>
                  <td><span className="text-[10px] font-mono text-[var(--text-3)] truncate max-w-[100px] block">{a.sha256?.slice(0, 16)}...</span></td>
                  <td><span className="text-xs text-[var(--text-3)]">{timeAgo(a.created_at)}</span></td>
                </tr>
              ))}
              {attachments.length === 0 && <tr><td colSpan={9} className="text-center text-[var(--text-3)] py-8">No attachments</td></tr>}
            </tbody>
          </table>
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
        <div className="g-card overflow-hidden">
          <table className="g-table w-full">
            <thead className="g-thead"><tr>
              <th>URL</th><th>Domain</th><th>Verdict</th><th>Reputation</th>
              <th>Redirects</th><th>Shortened</th><th>New Domain</th><th>Login Form</th><th>Clicks</th><th>Time</th>
            </tr></thead>
            <tbody>
              {urls.map((u: any) => (
                <tr key={u.id} className="g-tr">
                  <td><div className="text-xs font-mono text-[var(--text-1)] truncate max-w-[200px]">{u.url}</div></td>
                  <td><span className="text-xs text-[var(--accent)]">{u.domain}</span></td>
                  <td><span className={`text-[10px] px-1.5 py-0.5 rounded ${THREAT_COLOR[u.verdict === 'malicious' ? 'phishing' : u.verdict === 'suspicious' ? 'spam' : 'clean']}`}>{u.verdict}</span></td>
                  <td><span className={`text-xs font-medium ${u.reputation === 'malicious' ? 'text-red-400' : u.reputation === 'clean' ? 'text-green-400' : 'text-yellow-400'}`}>{u.reputation}</span></td>
                  <td><span className={`text-xs font-bold ${u.redirect_count > 1 ? 'text-orange-400' : 'text-[var(--text-2)]'}`}>{u.redirect_count}</span></td>
                  <td>{u.is_shortened ? <AlertTriangle className="h-3.5 w-3.5 text-orange-400" /> : <span className="text-[var(--text-3)]">—</span>}</td>
                  <td>{u.is_newly_registered ? <AlertTriangle className="h-3.5 w-3.5 text-red-400" /> : <span className="text-[var(--text-3)]">—</span>}</td>
                  <td>{u.has_login_form ? <Eye className="h-3.5 w-3.5 text-yellow-400" /> : <span className="text-[var(--text-3)]">—</span>}</td>
                  <td><span className={`text-xs font-bold ${u.click_count > 0 ? 'text-red-400' : 'text-[var(--text-3)]'}`}>{u.click_count}</span></td>
                  <td><span className="text-xs text-[var(--text-3)]">{timeAgo(u.created_at)}</span></td>
                </tr>
              ))}
              {urls.length === 0 && <tr><td colSpan={10} className="text-center text-[var(--text-3)] py-8">No URLs</td></tr>}
            </tbody>
          </table>
        </div>
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
            <div className={`text-2xl font-bold ${rates[proto] > 80 ? 'text-green-400' : rates[proto] > 60 ? 'text-yellow-400' : 'text-red-400'}`}>{rates[proto]}%</div>
            <div className="h-1.5 rounded-full bg-[var(--border)]">
              <div className={`h-full rounded-full ${rates[proto] > 80 ? 'bg-green-500' : rates[proto] > 60 ? 'bg-yellow-500' : 'bg-red-500'}`} style={{ width: `${rates[proto]}%` }} />
            </div>
            <div className="text-[10px] text-[var(--text-3)]">pass rate</div>
          </div>
        ))}
      </div>

      <div className="g-card p-4 space-y-3">
        <div className="text-sm font-medium text-[var(--text-1)]">Per-Domain Authentication Results</div>
        <div className="overflow-x-auto">
          <table className="g-table w-full">
            <thead className="g-thead"><tr>
              <th>Domain</th>
              {PROTOCOLS.map(p => <th key={p}>{p}</th>)}
              <th>Aligned</th><th>Policy</th>
            </tr></thead>
            <tbody>
              {(data?.domains ?? []).map((d: any) => (
                <tr key={d.domain} className="g-tr">
                  <td><span className="text-xs font-mono text-[var(--text-1)]">{d.domain}</span></td>
                  <td><span className={`text-xs font-bold ${AUTH_COLOR[d.spf] ?? 'text-[var(--text-3)]'}`}>{d.spf}</span></td>
                  <td><span className={`text-xs font-bold ${AUTH_COLOR[d.dkim] ?? 'text-[var(--text-3)]'}`}>{d.dkim}</span></td>
                  <td><span className={`text-xs font-bold ${AUTH_COLOR[d.dmarc] ?? 'text-[var(--text-3)]'}`}>{d.dmarc}</span></td>
                  <td><span className={`text-xs font-bold ${AUTH_COLOR[d.arc] ?? 'text-[var(--text-3)]'}`}>{d.arc}</span></td>
                  <td><span className={`text-xs font-bold ${AUTH_COLOR[d.bimi] ?? 'text-[var(--text-3)]'}`}>{d.bimi}</span></td>
                  <td>{d.aligned ? <CheckCircle className="h-3.5 w-3.5 text-green-400" /> : <XCircle className="h-3.5 w-3.5 text-red-400" />}</td>
                  <td><span className={`text-[10px] px-1.5 py-0.5 rounded ${d.policy === 'reject' ? 'bg-green-500/10 border border-green-500/30 text-green-400' : d.policy === 'quarantine' ? 'bg-yellow-500/10 border border-yellow-500/30 text-yellow-400' : 'bg-[var(--glass-bg)] border border-[var(--border)] text-[var(--text-3)]'}`}>{d.policy}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="g-card p-3 text-xs text-[var(--text-2)] space-y-1">
          <div className="font-medium text-[var(--text-1)]">Recommendations</div>
          <div>• Set DMARC policy to <span className="text-green-400 font-bold">reject</span> on all owned domains to prevent spoofing</div>
          <div>• 29% of inbound emails fail DMARC — consider enforcing strict alignment</div>
          <div>• Implement BIMI with VMC to enable brand logo display in supported email clients</div>
          <div>• Enable ARC sealing on your outbound email gateway</div>
        </div>
      </div>
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

  const CAMPAIGN_COLOR: Record<string, string> = {
    phishing: THREAT_COLOR.phishing,
    bec: THREAT_COLOR.bec,
    malware: THREAT_COLOR.malware,
    spam: THREAT_COLOR.spam,
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          {loading ? <div className="text-[var(--text-3)] text-sm">Loading...</div> : (
            <div className="g-card overflow-hidden">
              <table className="g-table w-full">
                <thead className="g-thead"><tr>
                  <th>Campaign</th><th>Type</th><th>Actor</th><th>Emails</th>
                  <th>Victims</th><th>Malware</th><th>Status</th><th>Last Seen</th>
                </tr></thead>
                <tbody>
                  {campaigns.map((c: any) => (
                    <tr key={c.id} className={`g-tr cursor-pointer ${selected?.id === c.id ? 'bg-[var(--accent)]/5' : ''}`} onClick={() => setSelected(selected?.id === c.id ? null : c)}>
                      <td><span className="text-xs font-medium text-[var(--text-1)]">{c.name}</span></td>
                      <td><span className={`text-[10px] px-1.5 py-0.5 rounded ${CAMPAIGN_COLOR[c.campaign_type] ?? THREAT_COLOR.spam}`}>{c.campaign_type}</span></td>
                      <td><span className="text-xs text-[var(--text-2)]">{c.threat_actor || '—'}</span></td>
                      <td><span className="text-xs font-bold text-[var(--text-1)]">{c.email_count}</span></td>
                      <td><span className={`text-xs font-bold ${c.victim_count > 0 ? 'text-red-400' : 'text-green-400'}`}>{c.victim_count}</span></td>
                      <td><span className="text-xs text-purple-400">{c.malware_family || '—'}</span></td>
                      <td><span className={`text-[10px] px-1.5 py-0.5 rounded ${c.status === 'active' ? 'bg-red-500/10 border border-red-500/30 text-red-400' : 'bg-green-500/10 border border-green-500/30 text-green-400'}`}>{c.status}</span></td>
                      <td><span className="text-xs text-[var(--text-3)]">{timeAgo(c.last_seen)}</span></td>
                    </tr>
                  ))}
                  {campaigns.length === 0 && <tr><td colSpan={8} className="text-center text-[var(--text-3)] py-8">No campaigns detected</td></tr>}
                </tbody>
              </table>
            </div>
          )}
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
                <button className="g-btn-primary text-xs flex-1" onClick={() => emailSecurityAPI.respond({ action: 'block_domain', domain: selected.common_domain })}>Block Domain</button>
                <button className="g-btn text-xs flex-1" onClick={() => emailSecurityAPI.respond({ action: 'create_incident' })}>Create Incident</button>
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
          <div className="g-card p-4 space-y-3">
            <div className="text-sm font-medium text-[var(--text-1)]">Malicious Domains</div>
            {(intel.malicious_domains ?? []).map((d: any) => (
              <div key={d.domain} className="space-y-0.5">
                <div className="flex justify-between text-xs">
                  <span className="font-mono text-red-400">{d.domain}</span>
                  <span className="text-[var(--text-3)] font-bold">{d.hits} hits</span>
                </div>
                <div className="text-[10px] text-[var(--text-3)] capitalize">{d.category.replace(/_/g, ' ')} · since {d.first_seen}</div>
              </div>
            ))}
          </div>

          <div className="g-card p-4 space-y-3">
            <div className="text-sm font-medium text-[var(--text-1)]">Threat Distribution</div>
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
                  <span className="text-purple-400">{m.family}</span>
                  <span className="text-[var(--text-3)]">{m.category} · {m.count}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="g-card p-4 space-y-3">
            <div className="text-sm font-medium text-[var(--text-1)]">Threat Actors</div>
            {(intel.threat_actors ?? []).map((a: any) => (
              <div key={a.actor} className="space-y-0.5">
                <div className="text-xs font-medium text-orange-400">{a.actor}</div>
                <div className="text-[10px] text-[var(--text-3)]">{a.campaigns} campaigns · targeting {a.target_industry}</div>
                <div className="text-[10px] text-[var(--text-3)]">{a.email_volume} emails</div>
              </div>
            ))}
            <div className="pt-2 border-t border-[var(--border)] space-y-2">
              <div className="text-xs font-medium text-[var(--text-1)]">Malicious IPs</div>
              {(intel.malicious_ips ?? []).map((ip: any) => (
                <div key={ip.ip} className="flex justify-between text-xs">
                  <span className="font-mono text-red-400">{ip.ip}</span>
                  <span className="text-[var(--text-3)]">{ip.country} · {ip.hits}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      <div className="g-card p-4 space-y-3">
        <div className="text-sm font-medium text-[var(--text-1)]">Sender Intelligence Lookup</div>
        <div className="flex gap-2">
          <input className="g-input text-xs flex-1" placeholder="e.g. suspicious-bank.xyz or noreply@example.com" value={senderDomain} onChange={e => setSenderDomain(e.target.value)} onKeyDown={e => e.key === 'Enter' && lookupSender()} />
          <button className="g-btn-primary text-xs" onClick={lookupSender} disabled={loadingSender}><Search className="h-3.5 w-3.5" /></button>
        </div>
        {senderData && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="g-card p-3 text-center">
              <div className="text-xs text-[var(--text-3)]">Reputation</div>
              <div className={`text-sm font-bold ${senderData.reputation === 'malicious' ? 'text-red-400' : senderData.reputation === 'trusted' ? 'text-green-400' : 'text-yellow-400'}`}>{senderData.reputation}</div>
            </div>
            <div className="g-card p-3 text-center">
              <div className="text-xs text-[var(--text-3)]">Score</div>
              <div className={`text-sm font-bold ${senderData.reputation_score < 30 ? 'text-red-400' : senderData.reputation_score > 70 ? 'text-green-400' : 'text-yellow-400'}`}>{senderData.reputation_score}/100</div>
            </div>
            <div className="g-card p-3 text-center">
              <div className="text-xs text-[var(--text-3)]">Domain Age</div>
              <div className={`text-sm font-bold ${senderData.domain_age_days < 30 ? 'text-red-400' : 'text-[var(--text-1)]'}`}>{senderData.domain_age_days}d</div>
            </div>
            <div className="g-card p-3 text-center">
              <div className="text-xs text-[var(--text-3)]">Threat Intel Hits</div>
              <div className={`text-sm font-bold ${senderData.threat_intel_hits > 0 ? 'text-red-400' : 'text-green-400'}`}>{senderData.threat_intel_hits}</div>
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

      <div className="g-card p-4 space-y-3">
        <div className="text-sm font-medium text-[var(--text-1)]">AI Email Analysis</div>
        <div className="flex gap-2 flex-wrap">
          {[['analyze', 'Analyze Email'], ['url', 'Analyze URL'], ['attachment', 'Analyze Hash'], ['ask', 'Ask AI']].map(([mode, label]) => (
            <button key={mode} onClick={() => setAiMode(mode)}
              className={`text-xs px-3 py-1.5 rounded border transition-colors ${aiMode === mode ? 'border-[var(--accent)] text-[var(--accent)] bg-[var(--accent)]/5' : 'border-[var(--border)] text-[var(--text-3)] hover:text-[var(--text-1)]'}`}>
              {label}
            </button>
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
        <button className="g-btn-primary text-xs flex items-center gap-1.5" onClick={runAI} disabled={aiLoading}>
          <Brain className="h-3.5 w-3.5" />{aiLoading ? 'Analyzing...' : 'Analyze'}
        </button>

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
                <ul className="space-y-0.5">{aiResult.indicators.map((ind: string, i: number) => <li key={i} className="text-xs text-[var(--text-2)] flex gap-1.5"><span className="text-red-400">!</span>{ind}</li>)}</ul>
              </div>
            )}
            {aiResult.mitre_techniques?.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {aiResult.mitre_techniques.map((t: string) => (
                  <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/30 text-purple-400">{t}</span>
                ))}
              </div>
            )}
            {aiResult.recommended_actions?.length > 0 && (
              <div>
                <div className="text-xs text-[var(--text-3)] mb-1">Recommended Actions</div>
                <ul className="space-y-0.5">{aiResult.recommended_actions.map((a: string, i: number) => <li key={i} className="text-xs text-[var(--text-2)] flex gap-1.5"><span className="text-[var(--accent)]">›</span>{a}</li>)}</ul>
              </div>
            )}
          </div>
        )}
      </div>
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

  const TRAINING_COLOR: Record<string, string> = {
    completed:   'text-green-400',
    in_progress: 'text-yellow-400',
    pending:     'text-red-400',
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        {(['risk', 'reported'] as const).map(s => (
          <button key={s} onClick={() => setSubTab(s)}
            className={`text-xs px-3 py-1.5 rounded border transition-colors ${subTab === s ? 'border-[var(--accent)] text-[var(--accent)] bg-[var(--accent)]/5' : 'border-[var(--border)] text-[var(--text-3)] hover:text-[var(--text-1)]'}`}>
            {s === 'risk' ? `User Risk (${users.length})` : `Reported Phishing (${reported.length})`}
          </button>
        ))}
      </div>

      {loading ? <div className="text-[var(--text-3)] text-sm">Loading...</div> : subTab === 'risk' ? (
        <div className="g-card overflow-hidden">
          <table className="g-table w-full">
            <thead className="g-thead"><tr>
              <th>User</th><th>Department</th><th>Clicks</th><th>Failures</th>
              <th>Repeated</th><th>Training</th><th>Risk Score</th><th>Last Click</th>
            </tr></thead>
            <tbody>
              {users.map((u: any) => (
                <tr key={u.id} className="g-tr">
                  <td>
                    <div className="text-xs font-medium text-[var(--text-1)]">{u.display_name}</div>
                    <div className="text-[10px] text-[var(--text-3)]">{u.email}</div>
                  </td>
                  <td><span className="text-xs text-[var(--text-2)]">{u.department}</span></td>
                  <td><span className={`text-xs font-bold ${u.click_count > 0 ? 'text-red-400' : 'text-green-400'}`}>{u.click_count}</span></td>
                  <td><span className={`text-xs font-bold ${u.phishing_failures > 0 ? 'text-red-400' : 'text-green-400'}`}>{u.phishing_failures}</span></td>
                  <td>{u.is_repeated_victim ? <AlertTriangle className="h-3.5 w-3.5 text-orange-400" /> : <CheckCircle className="h-3.5 w-3.5 text-green-400" />}</td>
                  <td><span className={`text-xs font-medium capitalize ${TRAINING_COLOR[u.training_status] ?? 'text-[var(--text-2)]'}`}>{u.training_status.replace('_', ' ')}</span></td>
                  <td>
                    <div className="flex items-center gap-1.5">
                      <div className="w-12 h-1.5 rounded-full bg-[var(--border)]">
                        <div className={`h-full rounded-full ${u.risk_score > 75 ? 'bg-red-500' : u.risk_score > 50 ? 'bg-orange-500' : 'bg-yellow-500'}`} style={{ width: `${u.risk_score}%` }} />
                      </div>
                      <span className={`text-xs font-bold ${u.risk_score > 75 ? 'text-red-400' : u.risk_score > 50 ? 'text-orange-400' : 'text-[var(--text-2)]'}`}>{u.risk_score}</span>
                    </div>
                  </td>
                  <td><span className="text-xs text-[var(--text-3)]">{u.last_click_at ? timeAgo(u.last_click_at) : 'Never'}</span></td>
                </tr>
              ))}
              {users.length === 0 && <tr><td colSpan={8} className="text-center text-[var(--text-3)] py-8">No user risk data</td></tr>}
            </tbody>
          </table>
        </div>
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
                  <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                    r.auto_verdict === 'phishing' ? THREAT_COLOR.phishing :
                    r.auto_verdict === 'bec' ? THREAT_COLOR.bec :
                    r.auto_verdict === 'clean' ? THREAT_COLOR.clean : THREAT_COLOR.spam
                  }`}>{r.auto_verdict || 'unknown'}</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                    r.triage_status === 'confirmed_phishing' ? 'bg-red-500/10 border-red-500/30 text-red-400' :
                    r.triage_status === 'false_positive' ? 'bg-green-500/10 border-green-500/30 text-green-400' :
                    r.triage_status === 'escalated' ? 'bg-orange-500/10 border-orange-500/30 text-orange-400' :
                    'bg-[var(--glass-bg)] border-[var(--border)] text-[var(--text-3)]'
                  }`}>{r.triage_status.replace('_', ' ')}</span>
                </div>
              </div>
              {r.analyst_notes && <div className="text-xs text-[var(--text-2)] italic">{r.analyst_notes}</div>}
              {triaging === r.id ? (
                <div className="space-y-2">
                  <textarea className="g-input text-xs w-full resize-none" rows={2} placeholder="Analyst notes..." value={notes} onChange={e => setNotes(e.target.value)} />
                  <div className="flex gap-1.5 flex-wrap">
                    {(['confirmed_phishing', 'false_positive', 'escalated'] as string[]).map(s => (
                      <button key={s} className="g-btn text-xs capitalize" onClick={() => doTriage(r.id, s)}>{s.replace('_', ' ')}</button>
                    ))}
                    <button className="g-btn text-xs" onClick={() => setTriaging(null)}>Cancel</button>
                  </div>
                </div>
              ) : (
                <button className="g-btn text-xs text-xs" onClick={() => { setTriaging(r.id); setNotes(r.analyst_notes); }}>
                  {r.triage_status === 'pending' ? 'Triage' : 'Edit Triage'}
                </button>
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
        <div className="g-card p-4 space-y-3">
          <div className="text-sm font-medium text-[var(--text-1)]">Top Threat Senders</div>
          {(data?.top_senders ?? []).map((s: any, i: number) => (
            <div key={i} className="space-y-1">
              <div className="flex justify-between text-xs">
                <span className="font-mono text-red-400 truncate max-w-[160px]">{s.sender}</span>
                <span className="text-[var(--text-2)] font-bold shrink-0 ml-2">{s.count}</span>
              </div>
            </div>
          ))}
        </div>

        <div className="g-card p-4 space-y-3">
          <div className="text-sm font-medium text-[var(--text-1)]">Top Blocked URL Domains</div>
          {(data?.top_blocked_urls ?? []).map((u: any, i: number) => (
            <div key={i} className="space-y-1">
              <div className="flex justify-between text-xs">
                <span className="font-mono text-orange-400">{u.domain}</span>
                <span className="text-[var(--text-2)] font-bold">{u.count}</span>
              </div>
            </div>
          ))}
        </div>

        <div className="g-card p-4 space-y-2">
          <div className="text-sm font-medium text-[var(--text-1)]">14-Day BEC Trend</div>
          <div className="flex items-end gap-0.5 h-20">
            {(data?.bec_trend ?? []).map((d: any, i: number) => (
              <div key={i} className="flex-1 flex flex-col items-center gap-0.5">
                <div className="w-full rounded-sm bg-orange-500 opacity-70 hover:opacity-100" style={{ height: `${Math.round(d.count / becBarMax * 72) + 2}px` }} title={`${d.date}: ${d.count}`} />
                {i % 3 === 0 && <div className="text-[9px] text-[var(--text-3)]">{d.date?.slice(5)}</div>}
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="g-card p-4 space-y-3">
        <div className="text-sm font-medium text-[var(--text-1)]">14-Day Phishing Trend</div>
        <div className="flex items-end gap-0.5 h-24">
          {(data?.phishing_trend ?? []).map((d: any, i: number) => (
            <div key={i} className="flex-1 flex flex-col items-center gap-0.5">
              <div className="w-full rounded-sm bg-red-500 opacity-70 hover:opacity-100" style={{ height: `${Math.round(d.count / phishingBarMax * 88) + 2}px` }} title={`${d.date}: ${d.count}`} />
              {i % 2 === 0 && <div className="text-[9px] text-[var(--text-3)]">{d.date?.slice(5)}</div>}
            </div>
          ))}
        </div>
      </div>
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
        <div className="g-card p-4 space-y-3">
          <div className="text-sm font-medium text-[var(--text-1)]">Response Actions</div>
          <div className="grid grid-cols-1 gap-2">
            {RESPONSE_ACTIONS.map(([action, label, target]) => (
              <div key={action} className="flex gap-2">
                <button
                  className={`g-btn text-xs whitespace-nowrap ${actionTarget.action === action ? 'border-[var(--accent)] text-[var(--accent)]' : ''}`}
                  onClick={() => setActionTarget(t => ({ action: t.action === action ? '' : action, value: t.action === action ? t.value : '' }))}
                >
                  <Zap className="h-3 w-3 shrink-0" />{label}
                </button>
                {actionTarget.action === action && target && (
                  <input className="g-input text-xs flex-1" placeholder={target} value={actionTarget.value} onChange={e => setActionTarget(t => ({ ...t, value: e.target.value }))} />
                )}
                {actionTarget.action === action && (
                  <button className="g-btn-primary text-xs whitespace-nowrap" onClick={doAction} disabled={actioning}>Execute</button>
                )}
              </div>
            ))}
          </div>
          {actionResult && <div className="g-card p-2 text-xs text-green-400">{actionResult}</div>}
        </div>

        <div className="space-y-4">
          <div className="g-card p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="text-sm font-medium text-[var(--text-1)]">Email Policies</div>
              <button className="g-btn text-xs flex items-center gap-1" onClick={() => setShowNewPolicy(s => !s)}><Plus className="h-3 w-3" />Add</button>
            </div>
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
                  <button className="g-btn-primary text-xs" onClick={doCreatePolicy}>Create</button>
                  <button className="g-btn text-xs" onClick={() => setShowNewPolicy(false)}>Cancel</button>
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
                    <div className="flex gap-1 shrink-0">
                      <button className={`text-[10px] px-1.5 py-0.5 rounded border ${p.enabled ? 'border-green-500/30 text-green-400' : 'border-[var(--border)] text-[var(--text-3)]'}`} onClick={() => doTogglePolicy(p)}>{p.enabled ? 'ON' : 'OFF'}</button>
                      <button className="text-[var(--text-3)] hover:text-red-400 transition-colors p-0.5" onClick={() => doDeletePolicy(p.id)}><Trash2 className="h-3 w-3" /></button>
                    </div>
                  </div>
                ))}
                {policies.length === 0 && <div className="text-xs text-[var(--text-3)] text-center py-4">No policies configured</div>}
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="g-card p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="text-sm font-medium text-[var(--text-1)]">Security Reports</div>
          <div className="flex gap-2">
            <select className="g-select text-xs" value={reportType} onChange={e => setReportType(e.target.value)}>
              <option value="executive">Executive Summary</option>
              <option value="phishing">Phishing Report</option>
              <option value="bec">BEC Report</option>
              <option value="malware">Malware Report</option>
              <option value="user_risk">User Risk Report</option>
            </select>
            <button className="g-btn-primary text-xs flex items-center gap-1.5" onClick={doGenerateReport} disabled={generating}>
              <FileText className="h-3.5 w-3.5" />{generating ? 'Generating...' : 'Generate'}
            </button>
          </div>
        </div>
        {reportResult && (
          <div className="space-y-3">
            <div className="text-base font-semibold text-[var(--text-1)]">{reportResult.title}</div>
            <div className="g-card p-3 text-sm text-[var(--text-2)] leading-relaxed">{reportResult.executive_summary}</div>
            {reportResult.key_findings?.length > 0 && (
              <div><div className="text-xs text-[var(--text-3)] mb-1">Key Findings</div>
                <ul className="space-y-1">{reportResult.key_findings.map((f: string, i: number) => <li key={i} className="text-xs text-[var(--text-2)] flex gap-1.5"><span className="text-red-400">!</span>{f}</li>)}</ul>
              </div>
            )}
            {reportResult.risk_breakdown && (
              <div className="grid grid-cols-3 gap-3">
                <StatCard label="Phishing"  value={reportResult.risk_breakdown.phishing ?? 0}  color="text-red-400" />
                <StatCard label="Malware"   value={reportResult.risk_breakdown.malware ?? 0}   color="text-purple-400" />
                <StatCard label="BEC"       value={reportResult.risk_breakdown.bec ?? 0}       color="text-orange-400" />
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
      </div>
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
    <RootLayout>
      <div style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 20 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>Email Security</h1>
          <div style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 4 }}>Phishing · BEC · Malware · URL Analysis · DMARC · Campaign Detection</div>
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
