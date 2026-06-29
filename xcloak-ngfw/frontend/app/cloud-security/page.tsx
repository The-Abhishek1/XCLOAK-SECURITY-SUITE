'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import api from '@/lib/api';
import { Cloud, RefreshCw, Loader2, ShieldAlert, Lock, Database } from 'lucide-react';

interface Alert {
  id: number;
  rule_name: string;
  severity: string;
  log_message: string;
  mitre_technique: string;
  mitre_name: string;
  created_at: string;
  is_resolved: boolean;
}

const SEV_COLOR: Record<string, string> = {
  critical: '#f85149',
  high:     '#e3b341',
  medium:   '#d29922',
  low:      '#3fb950',
};

const PROVIDER_COLOR: Record<string, string> = {
  'AWS':   '#ff9900',
  'Azure': '#0078d4',
  'GCP':   '#4285f4',
};

function providerFromRule(rule: string) {
  if (rule.startsWith('AWS')) return 'AWS';
  if (rule.startsWith('Azure') || rule.startsWith('Azure AD')) return 'Azure';
  if (rule.startsWith('GCP')) return 'GCP';
  return 'Cloud';
}

export default function CloudSecurityPage() {
  const [alerts, setAlerts]     = useState<Alert[]>([]);
  const [loading, setLoading]   = useState(true);
  const [provider, setProvider] = useState('All');
  const [severity, setSeverity] = useState('All');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.get('/alerts/paginated', {
        params: { page: 1, per_page: 200, rule_prefix: 'AWS,Azure,GCP' },
      });
      const data = r.data?.alerts ?? r.data ?? [];
      setAlerts(Array.isArray(data) ? data.filter((a: Alert) =>
        /^(AWS|Azure|GCP)/i.test(a.rule_name)
      ) : []);
    } catch { setAlerts([]); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const filtered = alerts.filter(a => {
    const p = providerFromRule(a.rule_name);
    if (provider !== 'All' && p !== provider) return false;
    if (severity !== 'All' && a.severity !== severity) return false;
    return true;
  });

  const stats = {
    aws:      alerts.filter(a => providerFromRule(a.rule_name) === 'AWS').length,
    azure:    alerts.filter(a => providerFromRule(a.rule_name) === 'Azure').length,
    gcp:      alerts.filter(a => providerFromRule(a.rule_name) === 'GCP').length,
    critical: alerts.filter(a => a.severity === 'critical').length,
  };

  return (
    <RootLayout title="Cloud Security" subtitle="AWS CloudTrail · Azure Activity Log · GCP Audit Log — IAM, storage, logging and configuration events">
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <select value={provider} onChange={e => setProvider(e.target.value)} className="g-input text-xs w-28">
            <option>All</option>
            <option>AWS</option>
            <option>Azure</option>
            <option>GCP</option>
          </select>
          <select value={severity} onChange={e => setSeverity(e.target.value)} className="g-input text-xs w-28">
            <option>All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <button onClick={load} className="g-btn g-btn-ghost text-xs"><RefreshCw className="h-3.5 w-3.5" /></button>
        </div>

        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'AWS',      val: stats.aws,      color: '#ff9900', icon: Cloud },
            { label: 'Azure',    val: stats.azure,    color: '#0078d4', icon: Lock },
            { label: 'GCP',      val: stats.gcp,      color: '#4285f4', icon: Database },
            { label: 'Critical', val: stats.critical, color: '#f85149', icon: ShieldAlert },
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
        ) : filtered.length === 0 ? (
          <div className="g-card p-12 text-center">
            <Cloud className="h-8 w-8 mx-auto mb-2" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No cloud security events for current filters</p>
            <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>
              Ingest CloudTrail / Azure Activity / GCP Audit logs via syslog (:514) or the HTTP ingest API (/api/ingest/logs)
            </p>
          </div>
        ) : (
          <div className="g-card overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['Provider','Severity','Rule','Details','MITRE','Time'].map(h => (
                    <th key={h} className="px-4 py-2.5 text-left font-semibold uppercase tracking-wider"
                      style={{ color: 'var(--text-3)', fontSize: 10 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map(a => {
                  const prov = providerFromRule(a.rule_name);
                  return (
                    <tr key={a.id} style={{ borderBottom: '1px solid var(--border)' }}
                      className="hover:bg-[rgba(255,255,255,0.02)] transition-colors">
                      <td className="px-4 py-2.5">
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold"
                          style={{ background: `${PROVIDER_COLOR[prov] ?? 'var(--accent)'}22`, color: PROVIDER_COLOR[prov] ?? 'var(--accent)' }}>
                          {prov}
                        </span>
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
          <p className="text-xs font-semibold" style={{ color: 'var(--text-2)' }}>Supported cloud log sources</p>
          <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
            AWS CloudTrail (31 event signatures) · Azure Activity Log (7 signatures) · GCP Audit Log (6 signatures).
            Forward logs via syslog to port 514 or POST JSON to /api/ingest/logs. The normaliser auto-detects
            CloudTrail eventName, Azure operationName, and GCP protoPayload/methodName structures.
          </p>
        </div>
      </div>
    </RootLayout>
  );
}
