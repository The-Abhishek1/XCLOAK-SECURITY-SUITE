'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { alertsAPI } from '@/lib/api';
import { Mail, RefreshCw, Loader2, ShieldAlert, Link2, DollarSign, AlertOctagon } from 'lucide-react';

interface Alert {
  id: number;
  rule_name: string;
  severity: string;
  log_message: string;
  mitre_technique: string;
  created_at: string;
}

const SEV_COLOR: Record<string, string> = {
  critical: '#f85149',
  high:     '#e3b341',
  medium:   '#d29922',
  low:      '#3fb950',
};

const CATEGORY_MAP: Record<string, { label: string; color: string; icon: any }> = {
  'Phishing Attachment':  { label: 'Attachment',  color: '#f85149', icon: AlertOctagon },
  'Phishing Link':        { label: 'Link',         color: '#e3b341', icon: Link2 },
  'BEC':                  { label: 'BEC',          color: '#d29922', icon: DollarSign },
  'Credential Phishing':  { label: 'Credential',   color: '#e3b341', icon: ShieldAlert },
  'Mass Outbound':        { label: 'Mass',         color: '#d29922', icon: Mail },
  'Lookalike Domain':     { label: 'Lookalike',    color: '#f85149', icon: AlertOctagon },
};

function categorise(ruleName: string) {
  for (const [key, val] of Object.entries(CATEGORY_MAP)) {
    if (ruleName.includes(key)) return val;
  }
  return { label: 'Email', color: 'var(--text-3)', icon: Mail };
}

export default function EmailSecurityPage() {
  const [alerts, setAlerts]   = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await alertsAPI.getFiltered({ page: 1, per_page: 200 });
      const data = r.data?.alerts ?? r.data ?? [];
      setAlerts(Array.isArray(data) ? data.filter((a: Alert) =>
        /phishing|bec|lookalike domain|mass outbound|credential phishing/i.test(a.rule_name)
      ) : []);
    } catch { setAlerts([]); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const countOf = (kw: string) => alerts.filter(a => a.rule_name.includes(kw)).length;

  return (
    <RootLayout title="Email Security" subtitle="Phishing, BEC, lookalike domains, credential theft lures — analysed from email gateway logs">
      <div className="space-y-4">
        <div className="flex justify-end">
          <button onClick={load} className="g-btn g-btn-ghost text-xs"><RefreshCw className="h-3.5 w-3.5" /></button>
        </div>

        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Phishing Attachments', val: countOf('Phishing Attachment'), color: '#f85149', icon: AlertOctagon },
            { label: 'Phishing Links',       val: countOf('Phishing Link'),        color: '#e3b341', icon: Link2 },
            { label: 'BEC / Financial',      val: countOf('BEC'),                  color: '#d29922', icon: DollarSign },
            { label: 'Lookalike Domains',    val: countOf('Lookalike'),            color: '#f85149', icon: ShieldAlert },
          ].map(s => (
            <div key={s.label} className="g-card p-4 flex items-center gap-3">
              <s.icon className="h-4 w-4 flex-shrink-0" style={{ color: s.color }} />
              <div>
                <p className="text-lg font-bold" style={{ color: 'var(--text-1)' }}>{s.val}</p>
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{s.label}</p>
              </div>
            </div>
          ))}
        </div>

        {loading ? (
          <div className="flex justify-center py-12">
            <Loader2 className="h-5 w-5 animate-spin" style={{ color: 'var(--text-3)' }} />
          </div>
        ) : alerts.length === 0 ? (
          <div className="g-card p-12 text-center">
            <Mail className="h-8 w-8 mx-auto mb-2" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No email security alerts</p>
            <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>
              Forward email gateway logs to XCloak via syslog (:514) or POST JSON to /api/ingest/logs.
              Supported: O365 Unified Audit, Proofpoint SIEM API, Mimecast, Postfix/Exim syslog.
            </p>
          </div>
        ) : (
          <div className="g-card overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['Category','Severity','Rule','Details','MITRE','Time'].map(h => (
                    <th key={h} className="px-4 py-2.5 text-left font-semibold uppercase tracking-wider"
                      style={{ color: 'var(--text-3)', fontSize: 10 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {alerts.map(a => {
                  const cat = categorise(a.rule_name);
                  const Icon = cat.icon;
                  return (
                    <tr key={a.id} style={{ borderBottom: '1px solid var(--border)' }}
                      className="hover:bg-[rgba(255,255,255,0.02)] transition-colors">
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-1.5">
                          <Icon className="h-3 w-3" style={{ color: cat.color }} />
                          <span className="text-[10px] font-bold" style={{ color: cat.color }}>{cat.label}</span>
                        </div>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase"
                          style={{ background: `${SEV_COLOR[a.severity] ?? '#888'}22`, color: SEV_COLOR[a.severity] ?? '#888' }}>
                          {a.severity}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 font-medium" style={{ color: 'var(--text-1)' }}>{a.rule_name}</td>
                      <td className="px-4 py-2.5 max-w-xs truncate" style={{ color: 'var(--text-2)' }}>{a.log_message}</td>
                      <td className="px-4 py-2.5">
                        <span className="mono text-[10px]" style={{ color: 'var(--accent)' }}>{a.mitre_technique}</span>
                      </td>
                      <td className="px-4 py-2.5 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>
                        {new Date(a.created_at).toLocaleString()}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        <div className="g-card p-4 space-y-1.5">
          <p className="text-xs font-semibold" style={{ color: 'var(--text-2)' }}>Email detection capabilities</p>
          <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
            Phishing attachments (13 dangerous extensions) · URL shortener links (12 domains) · BEC financial triggers (14 patterns) · Credential phishing themes (11 patterns) · Mass outbound detection (≥20 recipients) · Lookalike domain detection (edit-distance ≤2 vs 15 branded domains)
          </p>
        </div>
      </div>
    </RootLayout>
  );
}
