'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { alertsAPI } from '@/lib/api';
import { Cpu, RefreshCw, Loader2, Key, AlertOctagon, Shield } from 'lucide-react';

interface Alert { id: number; rule_name: string; severity: string; log_message: string; mitre_technique: string; created_at: string; }

const SEV_COLOR: Record<string, string> = { critical: '#f85149', high: '#e3b341', medium: '#d29922', low: '#3fb950' };

function cat(rule: string) {
  const r = rule.toLowerCase();
  if (r.includes('lsass'))    return { label: 'LSASS Dump',    color: '#f85149', icon: Key };
  if (r.includes('remote thread') || r.includes('inject')) return { label: 'Code Inject', color: '#f85149', icon: Cpu };
  if (r.includes('hollow'))   return { label: 'Hollowing',    color: '#f85149', icon: AlertOctagon };
  if (r.includes('masquerad')) return { label: 'Masquerade',  color: '#e3b341', icon: Shield };
  if (r.includes('sam') || r.includes('ntds')) return { label: 'Cred Dump', color: '#f85149', icon: Key };
  if (r.includes('dll'))      return { label: 'DLL Inject',   color: '#e3b341', icon: Cpu };
  return { label: 'Injection', color: 'var(--text-3)', icon: Cpu };
}

const KEYWORDS = /lsass|createremotethread|process injection|process hollowing|process masquerad|reflective dll|sam credential|ntds.*dump|unsigned dll/i;

export default function ProcessInjectionPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await alertsAPI.getFiltered({ page: 1, per_page: 200 });
      const data = r.data?.alerts ?? r.data ?? [];
      setAlerts(Array.isArray(data) ? data.filter((a: Alert) => KEYWORDS.test(a.rule_name)) : []);
    } catch { setAlerts([]); } finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const count = (p: RegExp) => alerts.filter(a => p.test(a.rule_name)).length;

  return (
    <RootLayout title="Process Injection & Memory Attacks" subtitle="Sysmon EventID 8/10/25 — LSASS dump, code injection, process hollowing, reflective DLL, credential extraction">
      <div className="space-y-4">
        <div className="flex justify-end"><button onClick={load} className="g-btn g-btn-ghost text-xs"><RefreshCw className="h-3.5 w-3.5" /></button></div>
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'LSASS Cred Dump',  val: count(/lsass|sam cred|ntds/i),            color: '#f85149', icon: Key },
            { label: 'Code Injection',    val: count(/createremotethread|process inject/i), color: '#f85149', icon: Cpu },
            { label: 'Hollowing/Masq',   val: count(/hollow|masquerad/i),                 color: '#e3b341', icon: AlertOctagon },
            { label: 'Total',             val: alerts.length,                               color: 'var(--accent)', icon: Shield },
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
          <div className="flex justify-center py-12"><Loader2 className="h-5 w-5 animate-spin" style={{ color: 'var(--text-3)' }} /></div>
        ) : alerts.length === 0 ? (
          <div className="g-card p-12 text-center">
            <Cpu className="h-8 w-8 mx-auto mb-2" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No process injection alerts</p>
            <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>Requires Sysmon EventID 1, 7, 8, 10, 25. Install Sysmon with the SwiftOnSecurity or olafhartong config on monitored hosts.</p>
          </div>
        ) : (
          <div className="g-card overflow-hidden">
            <table className="w-full text-xs">
              <thead><tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Type','Severity','Rule','Details','MITRE','Time'].map(h => (
                  <th key={h} className="px-4 py-2.5 text-left font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)', fontSize: 10 }}>{h}</th>
                ))}
              </tr></thead>
              <tbody>{alerts.map(a => {
                const c = cat(a.rule_name); const Icon = c.icon;
                return (
                  <tr key={a.id} style={{ borderBottom: '1px solid var(--border)' }} className="hover:bg-[rgba(255,255,255,0.02)]">
                    <td className="px-4 py-2.5"><div className="flex items-center gap-1.5"><Icon className="h-3 w-3" style={{ color: c.color }}/><span className="text-[10px] font-bold" style={{ color: c.color }}>{c.label}</span></div></td>
                    <td className="px-4 py-2.5"><span className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase" style={{ background: `${SEV_COLOR[a.severity]??'#888'}22`, color: SEV_COLOR[a.severity]??'#888' }}>{a.severity}</span></td>
                    <td className="px-4 py-2.5 font-medium max-w-[180px]" style={{ color: 'var(--text-1)' }}>{a.rule_name}</td>
                    <td className="px-4 py-2.5 max-w-xs truncate" style={{ color: 'var(--text-2)' }}>{a.log_message}</td>
                    <td className="px-4 py-2.5"><span className="mono text-[10px]" style={{ color: 'var(--accent)' }}>{a.mitre_technique}</span></td>
                    <td className="px-4 py-2.5 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>{new Date(a.created_at).toLocaleString()}</td>
                  </tr>
                );
              })}</tbody>
            </table>
          </div>
        )}
        <div className="g-card p-4 space-y-1.5">
          <p className="text-xs font-semibold" style={{ color: 'var(--text-2)' }}>Detection coverage</p>
          <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
            Sysmon EventID 8 (CreateRemoteThread) · EventID 10 LSASS access with credential masks 0x1010/0x1410/0x143a/0x1fffff · EventID 25 (ProcessTampering/hollow) · EventID 7 unsigned DLL from user-writable paths · Process masquerading (svchost/lsass/csrss outside System32) · reg save SAM/SYSTEM hive · ntdsutil / NTDS.dit access
          </p>
        </div>
      </div>
    </RootLayout>
  );
}
