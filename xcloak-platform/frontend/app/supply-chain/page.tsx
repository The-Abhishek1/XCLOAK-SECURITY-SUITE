'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { alertsAPI } from '@/lib/api';
import { Package, RefreshCw, Loader2, Terminal, Link2, Wrench, AlertOctagon } from 'lucide-react';

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

function categoryOf(rule: string) {
  const r = rule.toLowerCase();
  if (r.includes('curl') || r.includes('wget') || r.includes('remote code')) return { label: 'Curl|Shell', color: '#f85149', icon: Terminal };
  if (r.includes('typosquat')) return { label: 'Typosquat', color: '#f85149', icon: AlertOctagon };
  if (r.includes('dependency confusion') || r.includes('git url') || r.includes('http url') || r.includes('extra-index')) return { label: 'Dep. Confusion', color: '#e3b341', icon: Link2 };
  if (r.includes('compile') || r.includes('make') || r.includes('build')) return { label: 'Build Abuse', color: '#d29922', icon: Wrench };
  return { label: 'Package', color: 'var(--text-3)', icon: Package };
}

const SC_KEYWORDS = /curl-to-bash|curl-to-shell|wget-to|dependency confusion|typosquat|package from git|package from http|compile in|build.*injection|system account.*pip|nt authority.*npm|trusted-host|extra-index-url/i;

export default function SupplyChainPage() {
  const [alerts, setAlerts]   = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await alertsAPI.getFiltered({ page: 1, per_page: 200 });
      const data = r.data?.alerts ?? r.data ?? [];
      setAlerts(Array.isArray(data) ? data.filter((a: Alert) => SC_KEYWORDS.test(a.rule_name)) : []);
    } catch { setAlerts([]); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const count = (pat: RegExp) => alerts.filter(a => pat.test(a.rule_name)).length;

  return (
    <RootLayout title="Supply Chain Security" subtitle="Curl-to-shell · Dependency confusion · Typosquatting · Build system abuse — MITRE T1195">
      <div className="space-y-4">
        <div className="flex justify-end">
          <button onClick={load} className="g-btn g-btn-ghost text-xs"><RefreshCw className="h-3.5 w-3.5" /></button>
        </div>

        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Curl|Shell RCE',    val: count(/curl-to|wget-to/i),                color: '#f85149', icon: Terminal },
            { label: 'Typosquatting',     val: count(/typosquat/i),                       color: '#f85149', icon: AlertOctagon },
            { label: 'Dep. Confusion',    val: count(/dependency confusion|git url|http url|extra-index/i), color: '#e3b341', icon: Link2 },
            { label: 'Total',             val: alerts.length,                              color: 'var(--accent)', icon: Package },
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
            <Package className="h-8 w-8 mx-auto mb-2" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No supply chain attack alerts</p>
            <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>
              XCloak monitors process creation logs for curl|bash, pip --extra-index-url, npm from git URLs, typosquatting packages (edit-distance 1 vs 20 popular libraries), and build tools downloading from the internet
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
                  const cat = categoryOf(a.rule_name);
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
          <p className="text-xs font-semibold" style={{ color: 'var(--text-2)' }}>Supply chain detection coverage</p>
          <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
            Curl/wget-to-bash/sh/python (7 patterns) · pip --extra-index-url / --index-url http (dependency confusion) · npm/pip install from git+/http URLs · gcc/g++/make in /tmp or /dev/shm (compile after delivery) · Python -c remote exec · Node.js child_process · MSI from HTTP/FTP · NuGet HTTP source · pip --trusted-host TLS bypass · System account pip/npm installs · Typosquatting detection (Levenshtein distance 1 vs 20 popular packages: requests, numpy, pandas, flask, django, express, react, lodash, axios, boto3…)
          </p>
        </div>
      </div>
    </RootLayout>
  );
}
