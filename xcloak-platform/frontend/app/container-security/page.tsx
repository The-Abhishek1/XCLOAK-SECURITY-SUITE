'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import api from '@/lib/api';
import { Container, RefreshCw, Loader2, ShieldAlert, Cpu, Zap } from 'lucide-react';

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

function categoryOf(ruleName: string) {
  const r = ruleName.toLowerCase();
  if (r.includes('privileged') || r.includes('escape') || r.includes('namespace') || r.includes('chroot') || r.includes('nsenter')) return { label: 'Escape', color: '#f85149', icon: ShieldAlert };
  if (r.includes('mining') || r.includes('xmrig') || r.includes('stratum')) return { label: 'Cryptomining', color: '#e3b341', icon: Cpu };
  if (r.includes('k8s') || r.includes('kubernetes') || r.includes('pod') || r.includes('clusterrole') || r.includes('secret')) return { label: 'K8s', color: '#0078d4', icon: Zap };
  if (r.includes('docker') || r.includes('socket') || r.includes('image') || r.includes('volume')) return { label: 'Docker', color: '#2496ed', icon: Container };
  if (r.includes('falco')) return { label: 'Falco', color: 'var(--accent)', icon: ShieldAlert };
  return { label: 'Container', color: 'var(--text-3)', icon: Container };
}

export default function ContainerSecurityPage() {
  const [alerts, setAlerts]   = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.get('/alerts/paginated', { params: { page: 1, per_page: 200 } });
      const data = r.data?.alerts ?? r.data ?? [];
      const containerKeywords = /privileged container|container escape|host pid|host network|docker socket|root filesystem|nsenter|chroot.*host|xmrig|minerd|stratum|mining pool|k8s|clusterrole|kubectl exec|secret.*accessed|secret.*listed|falco/i;
      setAlerts(Array.isArray(data) ? data.filter((a: Alert) =>
        containerKeywords.test(a.rule_name)
      ) : []);
    } catch { setAlerts([]); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const count = (kw: RegExp) => alerts.filter(a => kw.test(a.rule_name)).length;

  return (
    <RootLayout title="Container Security" subtitle="Docker · Kubernetes · Falco — container escape, cryptomining, K8s RBAC abuse, privileged containers">
      <div className="space-y-4">
        <div className="flex justify-end">
          <button onClick={load} className="g-btn g-btn-ghost text-xs"><RefreshCw className="h-3.5 w-3.5" /></button>
        </div>

        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Escape / Priv',  val: count(/privileged|escape|nsenter|chroot|socket/i),  color: '#f85149', icon: ShieldAlert },
            { label: 'Cryptomining',   val: count(/xmrig|minerd|stratum|mining/i),               color: '#e3b341', icon: Cpu },
            { label: 'K8s Audit',      val: count(/k8s|clusterrole|kubectl|secret.*access/i),    color: '#0078d4', icon: Zap },
            { label: 'Total',          val: alerts.length,                                        color: 'var(--accent)', icon: Container },
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
            <Container className="h-8 w-8 mx-auto mb-2" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No container security alerts</p>
            <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>
              Forward Docker daemon logs, K8s API server audit logs, or Falco JSON output to XCloak via syslog (:514) or /api/ingest/logs
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
          <p className="text-xs font-semibold" style={{ color: 'var(--text-2)' }}>Container detection signatures</p>
          <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
            Docker: privileged containers · host pid/network/ipc namespaces · docker.sock mount · root filesystem mount · nsenter/chroot escape · cryptominers (xmrig, minerd, stratum+tcp) · untagged :latest pulls.
            Kubernetes: ClusterRoleBinding/ClusterRole creation · kubectl exec · bulk secrets access · namespace/node/deployment deletion · PersistentVolume creation.
            Falco: passthrough of Falco rule alerts.
          </p>
        </div>
      </div>
    </RootLayout>
  );
}
