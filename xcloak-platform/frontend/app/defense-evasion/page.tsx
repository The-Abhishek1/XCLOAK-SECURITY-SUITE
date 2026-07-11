'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { alertsAPI } from '@/lib/api';
import { EyeOff, RefreshCw, Loader2, Trash2, ShieldOff, Zap, Clock } from 'lucide-react';

interface Alert { id: number; rule_name: string; severity: string; log_message: string; mitre_technique: string; created_at: string; }

const SEV_COLOR: Record<string, string> = { critical: '#f85149', high: '#e3b341', medium: '#d29922', low: '#3fb950' };

function cat(rule: string) {
  const r = rule.toLowerCase();
  if (r.includes('log cleared') || r.includes('event log')) return { label: 'Log Cleared', color: '#f85149', icon: Trash2 };
  if (r.includes('amsi'))       return { label: 'AMSI Bypass', color: '#f85149', icon: Zap };
  if (r.includes('uac'))        return { label: 'UAC Bypass',  color: '#e3b341', icon: ShieldOff };
  if (r.includes('defender') || r.includes('firewall')) return { label: 'AV/FW Kill', color: '#f85149', icon: ShieldOff };
  if (r.includes('timestamp') || r.includes('timestomp')) return { label: 'Timestomp', color: '#d29922', icon: Clock };
  if (r.includes('file delet') || r.includes('wipe') || r.includes('shred')) return { label: 'File Delete', color: '#d29922', icon: Trash2 };
  if (r.includes('safe mode'))  return { label: 'Safe Mode',  color: '#f85149', icon: EyeOff };
  if (r.includes('etw') || r.includes('audit policy')) return { label: 'Logging Off', color: '#e3b341', icon: EyeOff };
  return { label: 'Evasion', color: 'var(--text-3)', icon: EyeOff };
}

const KEYWORDS = /event log cleared|amsi bypass|uac bypass|windows defender disabled|firewall disabled|timestomp|file deletion|secure.*wipe|etw patch|audit policy disabled|safe mode boot|indicator removal|registry value modified/i;

export default function DefenseEvasionPage() {
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
    <RootLayout title="Defense Evasion" subtitle="MITRE TA0005 — Log clearing, AMSI bypass, UAC bypass, AV kill, timestomping, indicator removal">
      <div className="space-y-4">
        <div className="flex justify-end"><button onClick={load} className="g-btn g-btn-ghost text-xs"><RefreshCw className="h-3.5 w-3.5" /></button></div>
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Log Cleared',  val: count(/log cleared|event log/i),              color: '#f85149', icon: Trash2 },
            { label: 'AMSI/UAC',     val: count(/amsi|uac/i),                            color: '#f85149', icon: Zap },
            { label: 'AV/FW Kill',   val: count(/defender|firewall disable|safe mode/i), color: '#f85149', icon: ShieldOff },
            { label: 'Total',        val: alerts.length,                                  color: 'var(--accent)', icon: EyeOff },
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
            <EyeOff className="h-8 w-8 mx-auto mb-2" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No defense evasion alerts</p>
            <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>Forward Windows Security event logs (EventID 1102, 104, 4719) and process creation logs (EventID 4688/Sysmon 1) to detect log clearing, AMSI bypass, UAC bypass, and AV/firewall disablement</p>
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
          <p className="text-xs font-semibold" style={{ color: 'var(--text-2)' }}>Detection coverage (MITRE TA0005)</p>
          <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
            Log clearing (EventID 1102/104 + wevtutil cl/Clear-EventLog) · AMSI bypass (AmsiScanBuffer/AmsiUtils reflection, 4 patterns) · UAC bypass (eventvwr/fodhelper/sdclt/cmstp, 4 vectors) · Windows Defender/Firewall disable (Set-MpPreference, net stop windefend, registry, netsh) · Audit policy disable (auditpol, EventID 4719) · Timestomping (LastWriteTime/Invoke-TimeStomp) · Indicator removal (del /f *.log, cipher /w, shred, rm /var/log) · ETW disable (EtwEventWrite patch, NtSetInformationThread) · Safe mode boot (bcdedit safeboot)
          </p>
        </div>
      </div>
    </RootLayout>
  );
}
