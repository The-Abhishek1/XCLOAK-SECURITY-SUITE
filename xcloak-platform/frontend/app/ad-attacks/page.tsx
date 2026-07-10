'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import api from '@/lib/api';
import { ShieldOff, RefreshCw, Loader2, Key, Users, AlertOctagon, Network } from 'lucide-react';

interface Alert {
  id: number;
  rule_name: string;
  severity: string;
  log_message: string;
  mitre_technique: string;
  mitre_name: string;
  created_at: string;
}

const SEV_COLOR: Record<string, string> = {
  critical: '#f85149',
  high:     '#e3b341',
  medium:   '#d29922',
  low:      '#3fb950',
};

const ATTACK_CATEGORY: { pattern: RegExp; label: string; color: string; icon: any }[] = [
  { pattern: /kerberoast/i,        label: 'Kerberoasting',   color: '#f85149', icon: Key },
  { pattern: /as-rep/i,            label: 'AS-REP Roast',    color: '#e3b341', icon: Key },
  { pattern: /dcsync/i,            label: 'DCSync',          color: '#f85149', icon: AlertOctagon },
  { pattern: /pass-the-hash/i,     label: 'Pass-the-Hash',   color: '#f85149', icon: Network },
  { pattern: /bloodhound|enum/i,   label: 'Enumeration',     color: '#d29922', icon: Users },
  { pattern: /sid history/i,       label: 'SID Injection',   color: '#f85149', icon: AlertOctagon },
  { pattern: /adminsdholder/i,     label: 'AdminSDHolder',   color: '#f85149', icon: AlertOctagon },
  { pattern: /kerberos brute|spray/i, label: 'Kerberos BF', color: '#e3b341', icon: Key },
  { pattern: /ldap enum/i,         label: 'LDAP Enum',       color: '#d29922', icon: Users },
];

function categorise(ruleName: string) {
  for (const c of ATTACK_CATEGORY) {
    if (c.pattern.test(ruleName)) return c;
  }
  return { label: 'AD Attack', color: 'var(--text-3)', icon: ShieldOff };
}

const AD_KEYWORDS = /kerberoast|as-rep|dcsync|pass-the-hash|bloodhound|sharphound|sid history|adminsdholder|kerberos brute|ldap enum|ad object enum|ad enum/i;

export default function ADAttacksPage() {
  const [alerts, setAlerts]   = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.get('/alerts/paginated', { params: { page: 1, per_page: 200 } });
      const data = r.data?.alerts ?? r.data ?? [];
      setAlerts(Array.isArray(data) ? data.filter((a: Alert) => AD_KEYWORDS.test(a.rule_name)) : []);
    } catch { setAlerts([]); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const count = (pat: RegExp) => alerts.filter(a => pat.test(a.rule_name)).length;

  return (
    <RootLayout title="Active Directory Attacks" subtitle="Kerberoasting · DCSync · Pass-the-Hash · BloodHound · SID History · AdminSDHolder — MITRE TA0006/TA0003/TA0008">
      <div className="space-y-4">
        <div className="flex justify-end">
          <button onClick={load} className="g-btn g-btn-ghost text-xs"><RefreshCw className="h-3.5 w-3.5" /></button>
        </div>

        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Credential Theft',  val: count(/kerberoast|as-rep|pass-the-hash|dcsync/i), color: '#f85149', icon: Key },
            { label: 'Enumeration',       val: count(/bloodhound|ldap enum|ad object/i),          color: '#d29922', icon: Users },
            { label: 'Privilege Abuse',   val: count(/sid history|adminsdholder/i),               color: '#f85149', icon: AlertOctagon },
            { label: 'Total',             val: alerts.length,                                      color: 'var(--accent)', icon: ShieldOff },
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
            <ShieldOff className="h-8 w-8 mx-auto mb-2" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No Active Directory attack alerts</p>
            <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>
              Forward Windows Security event logs (EventIDs 4769, 4768, 4662, 4624, 4765, 4688, 5136) to XCloak via syslog or agent
            </p>
          </div>
        ) : (
          <div className="g-card overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['Type','Severity','Rule','Details','MITRE','Time'].map(h => (
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
                      <td className="px-4 py-2.5 font-medium max-w-[180px]" style={{ color: 'var(--text-1)' }}>{a.rule_name}</td>
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
          <p className="text-xs font-semibold" style={{ color: 'var(--text-2)' }}>AD attack detection coverage</p>
          <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
            Kerberoasting (4769 + RC4) · AS-REP Roasting (4768 PreAuthType=0) · DCSync (4662 + replication GUIDs 1131f6aa/1131f6ad) · Pass-the-Hash (4624 LogonType=3 NTLM from ≥3 IPs) · BloodHound/SharpHound/ADFind/PowerView process detection (4688) · SID History injection (4765/4766) · AdminSDHolder abuse (5136) · Kerberos brute force / spray (4771 ≥20/5min) · LDAP enumeration burst (1644 / mass 4662)
          </p>
        </div>
      </div>
    </RootLayout>
  );
}
