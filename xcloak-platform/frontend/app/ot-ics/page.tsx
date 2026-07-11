'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { alertsAPI } from '@/lib/api';
import { Wrench, RefreshCw, Loader2, Radio, AlertOctagon, Network } from 'lucide-react';

interface Alert { id: number; rule_name: string; severity: string; log_message: string; mitre_technique: string; created_at: string; }

const SEV_COLOR: Record<string, string> = { critical: '#f85149', high: '#e3b341', medium: '#d29922', low: '#3fb950' };

function cat(rule: string) {
  const r = rule.toLowerCase();
  if (r.includes('it→ot') || r.includes('protocol access')) return { label: 'IT→OT',     color: '#f85149', icon: Network };
  if (r.includes('scan') || r.includes('enumerat'))         return { label: 'ICS Scan',   color: '#e3b341', icon: Radio };
  if (r.includes('firmware') || r.includes('plc') || r.includes('programming mode')) return { label: 'PLC/FW', color: '#f85149', icon: AlertOctagon };
  if (r.includes('safety') || r.includes('sis'))            return { label: 'Safety Sys', color: '#f85149', icon: AlertOctagon };
  if (r.includes('historian') || r.includes('scada'))       return { label: 'SCADA',      color: '#e3b341', icon: Wrench };
  return { label: 'OT/ICS', color: 'var(--text-3)', icon: Wrench };
}

const KEYWORDS = /it→ot|ics.*scan|ics port scan|industrial protocol|plc programming|firmware.*update|firmware.*write|scada|historian|safety.*bypass|ot engineering|modbus|dnp3|s7comm|opc-ua|engineering workstation/i;

export default function OTICSPage() {
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
    <RootLayout title="OT / ICS Security" subtitle="Industrial Control Systems — Modbus · DNP3 · IEC-104 · S7Comm · OPC-UA · SCADA · PLC monitoring">
      <div className="space-y-4">
        <div className="flex items-center gap-3 justify-between">
          <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
            OT network CIDR: set <span className="mono">OT_CIDR</span> env var (default 10.100.0.0/16).
            IT→OT alerts fire when a connection originates outside the OT CIDR range.
          </p>
          <button onClick={load} className="g-btn g-btn-ghost text-xs"><RefreshCw className="h-3.5 w-3.5" /></button>
        </div>
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'IT→OT Proto',   val: count(/it→ot|protocol access/i),          color: '#f85149', icon: Network },
            { label: 'ICS Scan',      val: count(/ics.*scan|ics port scan/i),          color: '#e3b341', icon: Radio },
            { label: 'PLC/Firmware',  val: count(/plc|firmware|programming mode/i),    color: '#f85149', icon: AlertOctagon },
            { label: 'Total',         val: alerts.length,                               color: 'var(--accent)', icon: Wrench },
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
            <Wrench className="h-8 w-8 mx-auto mb-2" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No OT/ICS alerts</p>
            <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>
              Forward network flow logs or IDS alerts to XCloak. Set <span className="mono">OT_CIDR</span> to your OT subnet. Supported protocols: Modbus (502), DNP3 (20000), IEC-104 (2404), EtherNet/IP (44818), S7Comm (102), OPC-UA (4840), BACnet (47808), IEC 61850 (61850).
            </p>
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
          <p className="text-xs font-semibold" style={{ color: 'var(--text-2)' }}>OT/ICS threat coverage</p>
          <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
            IT→OT unauthorized access (12 industrial protocol ports) · ICS network scan (≥3 ICS ports from 1 IP in 5 min) · SCADA/PLC software detection (Step7, TIA Portal, RSLogix, FactoryTalk, Studio 5000, Wonderware, Ignition, OSIsoft PI, AspenTech) · PLC programming mode / firmware write / Modbus force coil / Siemens CPU stop · Safety system bypass (IEC 61850/IEC-104) · Mass historian data export · RDP/VNC to OT hosts · Engineering workstation spawning cmd/PowerShell (T1059)
          </p>
        </div>
      </div>
    </RootLayout>
  );
}
