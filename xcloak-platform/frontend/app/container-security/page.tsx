'use client';
import { useState, useEffect, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { containerSecurityAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';

const SEV_BG: Record<string, string> = {
  critical: 'background:rgba(220,38,38,0.15);color:#f87171;border:1px solid rgba(220,38,38,0.3)',
  high:     'background:rgba(234,88,12,0.15);color:#fb923c;border:1px solid rgba(234,88,12,0.3)',
  medium:   'background:rgba(202,138,4,0.15);color:#facc15;border:1px solid rgba(202,138,4,0.3)',
  low:      'background:rgba(34,197,94,0.15);color:#4ade80;border:1px solid rgba(34,197,94,0.3)',
  clean:    'background:rgba(34,197,94,0.15);color:#4ade80;border:1px solid rgba(34,197,94,0.3)',
  warn:     'background:rgba(202,138,4,0.15);color:#facc15;border:1px solid rgba(202,138,4,0.3)',
};
type Tab = 'overview' | 'inventory' | 'images' | 'runtime' | 'rbac' | 'intelligence' | 'compliance' | 'analytics' | 'response';

function SevBadge({ v }: { v: string }) {
  const style = SEV_BG[v?.toLowerCase()] || SEV_BG.low;
  return <span style={{ ...Object.fromEntries(style.split(';').filter(Boolean).map(s => { const [k, val] = s.split(':'); return [k.trim().replace(/-([a-z])/g, (_: string, c: string) => c.toUpperCase()), val?.trim()]; })), padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600, textTransform: 'uppercase' as const, whiteSpace: 'nowrap' as const }}>{v}</span>;
}
function StatCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="g-card" style={{ flex: 1, minWidth: 140, padding: '18px 20px' }}>
      <div style={{ fontSize: 24, fontWeight: 700, color: color || 'var(--accent)' }}>{value}</div>
      <div style={{ fontSize: 12, color: 'var(--text-2)', marginTop: 2 }}>{label}</div>
      {sub && <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>{sub}</div>}
    </div>
  );
}
function RiskBar({ score }: { score: number }) {
  const color = score >= 80 ? '#ef4444' : score >= 60 ? '#f97316' : score >= 40 ? '#eab308' : '#22c55e';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 6, background: 'rgba(255,255,255,0.08)', borderRadius: 3 }}>
        <div style={{ width: `${score}%`, height: '100%', background: color, borderRadius: 3, transition: 'width 0.4s' }} />
      </div>
      <span style={{ fontSize: 12, color, fontWeight: 600, minWidth: 28 }}>{score}</span>
    </div>
  );
}

function OverviewTab() {
  const [dash, setDash] = useState<any>(null);
  useEffect(() => { containerSecurityAPI.getDashboard().then(r => setDash(r.data)); }, []);
  const d = dash || {};
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <StatCard label="Clusters" value={d.clusters ?? '—'} />
        <StatCard label="Nodes" value={d.nodes ?? '—'} />
        <StatCard label="Pods" value={d.pods ?? '—'} />
        <StatCard label="Namespaces" value={d.namespaces ?? '—'} />
        <StatCard label="Running Containers" value={d.running_containers ?? '—'} color="var(--accent)" />
        <StatCard label="Runtime Alerts" value={d.runtime_alerts ?? '—'} color={d.runtime_alerts > 0 ? '#ef4444' : undefined} />
        <StatCard label="Vulnerable Images" value={d.vulnerable_images ?? '—'} color={d.vulnerable_images > 0 ? '#f97316' : undefined} />
        <StatCard label="Critical Findings" value={d.critical_findings ?? '—'} color={d.critical_findings > 0 ? '#ef4444' : undefined} />
      </div>
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        <div className="g-card" style={{ flex: 1, minWidth: 300, padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Security Posture</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {[
              { label: 'Container Risk Score', val: d.container_risk_score ?? 0 },
              { label: 'Compliance Score', val: d.compliance_score ?? 0 },
            ].map(row => (
              <div key={row.label}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{row.label}</span>
                  <span style={{ fontSize: 12, fontWeight: 600 }}>{row.val}%</span>
                </div>
                <RiskBar score={row.val} />
              </div>
            ))}
          </div>
        </div>
        <div className="g-card" style={{ flex: 1, minWidth: 300, padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Security Concerns</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {[
              { label: 'Privileged Pods', val: d.privileged_pods, color: '#ef4444' },
              { label: 'Pods Without Resource Limits', val: d.pods_no_limits, color: '#f97316' },
              { label: 'Vulnerable Images', val: d.vulnerable_images, color: '#f97316' },
              { label: 'Open Runtime Alerts', val: d.runtime_alerts, color: '#ef4444' },
            ].map(row => (
              <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{row.label}</span>
                <span style={{ fontSize: 16, fontWeight: 700, color: (row.val ?? 0) > 0 ? row.color : '#22c55e' }}>{row.val ?? 0}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="g-card" style={{ flex: 1, minWidth: 300, padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Coverage</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {[
              { label: 'Runtime Protection', status: true },
              { label: 'Image Scanning', status: true },
              { label: 'RBAC Analysis', status: true },
              { label: 'Network Policies', status: false },
              { label: 'Admission Control', status: false },
              { label: 'Supply Chain Signing', status: false },
            ].map(row => (
              <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{row.label}</span>
                <span style={{ fontSize: 11, fontWeight: 600, color: row.status ? '#22c55e' : '#ef4444' }}>{row.status ? '✓ Active' : '✗ Missing'}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function InventoryTab() {
  const [sub, setSub] = useState<'clusters' | 'nodes' | 'namespaces' | 'pods'>('clusters');
  const [clusters, setClusters] = useState<any[]>([]);
  const [nodes, setNodes] = useState<any[]>([]);
  const [namespaces, setNamespaces] = useState<any[]>([]);
  const [pods, setPods] = useState<any[]>([]);
  useEffect(() => {
    containerSecurityAPI.getClusters().then(r => setClusters(r.data || []));
    containerSecurityAPI.getNodes().then(r => setNodes(r.data || []));
    containerSecurityAPI.getNamespaces().then(r => setNamespaces(r.data || []));
    containerSecurityAPI.getPods().then(r => setPods(r.data || []));
  }, []);
  const PROV_COLOR: Record<string, string> = { aws: '#f97316', gcp: '#3b82f6', azure: '#8b5cf6', kubernetes: '#22c55e' };
  return (
    <div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
        {(['clusters', 'nodes', 'namespaces', 'pods'] as const).map(s => (
          <button key={s} className={sub === s ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setSub(s)} style={{ textTransform: 'capitalize' }}>{s}</button>
        ))}
      </div>
      {sub === 'clusters' && (
        <table className="g-table"><thead className="g-thead"><tr>
          <th>Cluster</th><th>Provider</th><th>K8s Version</th><th>Nodes</th><th>Region</th><th>Risk</th><th>Compliance</th><th>Status</th>
        </tr></thead><tbody>
          {clusters.map((cl: any) => (
            <tr key={cl.id} className="g-tr">
              <td style={{ fontWeight: 600, fontFamily: 'monospace', fontSize: 12 }}>{cl.name}</td>
              <td><span style={{ color: PROV_COLOR[cl.provider] || 'var(--text-1)', fontWeight: 600, fontSize: 12, textTransform: 'uppercase' }}>{cl.provider}</span></td>
              <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{cl.k8s_version}</td>
              <td>{cl.node_count}</td>
              <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{cl.region}</td>
              <td><RiskBar score={cl.risk_score} /></td>
              <td><RiskBar score={cl.compliance_score} /></td>
              <td><SevBadge v={cl.status === 'healthy' ? 'clean' : cl.status === 'degraded' ? 'medium' : 'high'} /></td>
            </tr>
          ))}
        </tbody></table>
      )}
      {sub === 'nodes' && (
        <table className="g-table"><thead className="g-thead"><tr>
          <th>Node</th><th>OS</th><th>Runtime</th><th>CPU</th><th>Memory</th><th>Pods</th><th>CVEs</th><th>Risk</th><th>Status</th>
        </tr></thead><tbody>
          {nodes.map((n: any) => (
            <tr key={n.id} className="g-tr">
              <td style={{ fontFamily: 'monospace', fontSize: 11, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{n.name}</td>
              <td style={{ fontSize: 11 }}>{n.os}</td>
              <td style={{ fontSize: 11, fontFamily: 'monospace' }}>{n.runtime}</td>
              <td>{n.cpu_cores} vCPU</td>
              <td>{n.memory_gb} GB</td>
              <td>{n.pod_count}</td>
              <td style={{ color: n.vuln_count > 4 ? '#ef4444' : n.vuln_count > 2 ? '#f97316' : '#22c55e', fontWeight: 600 }}>{n.vuln_count}</td>
              <td><RiskBar score={n.risk_score} /></td>
              <td><SevBadge v={n.status === 'ready' ? 'clean' : 'high'} /></td>
            </tr>
          ))}
        </tbody></table>
      )}
      {sub === 'namespaces' && (
        <table className="g-table"><thead className="g-thead"><tr>
          <th>Namespace</th><th>Pods</th><th>Privileged Pods</th><th>Risk Score</th>
        </tr></thead><tbody>
          {namespaces.map((ns: any) => (
            <tr key={ns.namespace} className="g-tr">
              <td style={{ fontFamily: 'monospace', fontWeight: 600 }}>{ns.namespace}</td>
              <td>{ns.pod_count}</td>
              <td style={{ color: ns.privileged_pods > 0 ? '#ef4444' : '#22c55e', fontWeight: 600 }}>{ns.privileged_pods}</td>
              <td style={{ width: 200 }}><RiskBar score={Math.round(ns.risk_score)} /></td>
            </tr>
          ))}
        </tbody></table>
      )}
      {sub === 'pods' && (
        <table className="g-table"><thead className="g-thead"><tr>
          <th>Pod</th><th>Namespace</th><th>Image</th><th>Priv</th><th>Root</th><th>Host Net</th><th>Limits</th><th>Risk</th>
        </tr></thead><tbody>
          {pods.map((p: any) => (
            <tr key={p.id} className="g-tr">
              <td style={{ fontFamily: 'monospace', fontSize: 11, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.name}</td>
              <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{p.namespace}</td>
              <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{p.image}</td>
              <td><span style={{ color: p.is_privileged ? '#ef4444' : '#22c55e', fontWeight: 700 }}>{p.is_privileged ? '✗' : '✓'}</span></td>
              <td><span style={{ color: p.run_as_root ? '#ef4444' : '#22c55e', fontWeight: 700 }}>{p.run_as_root ? '✗' : '✓'}</span></td>
              <td><span style={{ color: p.host_network ? '#ef4444' : '#22c55e', fontWeight: 700 }}>{p.host_network ? '✗' : '✓'}</span></td>
              <td><span style={{ color: p.has_resource_limits ? '#22c55e' : '#ef4444', fontWeight: 700 }}>{p.has_resource_limits ? '✓' : '✗'}</span></td>
              <td style={{ width: 140 }}><RiskBar score={p.risk_score} /></td>
            </tr>
          ))}
        </tbody></table>
      )}
    </div>
  );
}

function ImagesTab() {
  const [images, setImages] = useState<any[]>([]);
  const [supply, setSupply] = useState<any>(null);
  const [sub, setSub] = useState<'scan' | 'supply'>('scan');
  useEffect(() => {
    containerSecurityAPI.getImages().then(r => setImages(r.data || []));
    containerSecurityAPI.getSupplyChain().then(r => setSupply(r.data));
  }, []);
  const sc = supply || {};
  return (
    <div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
        <button className={sub === 'scan' ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setSub('scan')}>Image Scan Results</button>
        <button className={sub === 'supply' ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setSub('supply')}>Supply Chain</button>
      </div>
      {sub === 'scan' && (
        <table className="g-table"><thead className="g-thead"><tr>
          <th>Image</th><th>Registry</th><th>OS</th><th>Age</th><th>Critical</th><th>High</th><th>Med</th><th>Low</th><th>Secrets</th><th>Signed</th><th>SBOM</th><th>Risk</th>
        </tr></thead><tbody>
          {images.map((img: any) => (
            <tr key={img.id} className="g-tr">
              <td style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 600 }}>{img.image}:{img.tag}</td>
              <td style={{ fontSize: 11 }}>{img.registry}</td>
              <td style={{ fontSize: 11 }}>{img.os}</td>
              <td style={{ fontSize: 11, color: img.age_days > 365 ? '#ef4444' : 'var(--text-2)' }}>{img.age_days}d</td>
              <td style={{ color: img.cve_critical > 0 ? '#ef4444' : 'var(--text-3)', fontWeight: img.cve_critical > 0 ? 700 : 400 }}>{img.cve_critical}</td>
              <td style={{ color: img.cve_high > 0 ? '#f97316' : 'var(--text-3)', fontWeight: img.cve_high > 0 ? 700 : 400 }}>{img.cve_high}</td>
              <td style={{ color: 'var(--text-2)' }}>{img.cve_medium}</td>
              <td style={{ color: 'var(--text-3)' }}>{img.cve_low}</td>
              <td><span style={{ color: img.has_secrets ? '#ef4444' : '#22c55e', fontWeight: 700 }}>{img.has_secrets ? '✗ YES' : '✓ No'}</span></td>
              <td><span style={{ color: img.signature_valid ? '#22c55e' : '#ef4444', fontWeight: 700 }}>{img.signature_valid ? '✓' : '✗'}</span></td>
              <td><span style={{ color: img.sbom_available ? '#22c55e' : '#ef4444', fontWeight: 700 }}>{img.sbom_available ? '✓' : '✗'}</span></td>
              <td style={{ width: 120 }}><RiskBar score={img.risk_score} /></td>
            </tr>
          ))}
        </tbody></table>
      )}
      {sub === 'supply' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <StatCard label="Total Images" value={sc.total_images ?? '—'} />
            <StatCard label="Signed Images" value={sc.signed_images ?? '—'} sub={`${sc.signature_rate ?? 0}% coverage`} color="#22c55e" />
            <StatCard label="SBOM Available" value={sc.sbom_available ?? '—'} sub={`${sc.sbom_rate ?? 0}% coverage`} color="#3b82f6" />
            <StatCard label="Old Base Images" value={sc.old_base_images ?? '—'} sub="> 180 days old" color={sc.old_base_images > 0 ? '#f97316' : undefined} />
          </div>
          <div className="g-card" style={{ padding: 20 }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Registry Trust</div>
            <table className="g-table"><thead className="g-thead"><tr><th>Registry</th><th>Trusted</th><th>Images</th></tr></thead><tbody>
              {(sc.trusted_registries || []).map((r: any) => (
                <tr key={r.registry} className="g-tr">
                  <td style={{ fontFamily: 'monospace', fontWeight: 600 }}>{r.registry}</td>
                  <td><span style={{ color: r.trusted ? '#22c55e' : '#ef4444', fontWeight: 700 }}>{r.trusted ? '✓ Trusted' : '✗ Untrusted'}</span></td>
                  <td>{r.images}</td>
                </tr>
              ))}
            </tbody></table>
          </div>
          <div className="g-card" style={{ padding: 20 }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Supply Chain Recommendations</div>
            {[
              'Enable Cosign image signing for all production images',
              'Generate and attach SBOMs to all container builds (syft/grype)',
              'Block unsigned images via admission controller policy (OPA Gatekeeper)',
              'Restrict allowed registries to gcr.io, ghcr.io, public.ecr.aws',
              'Update base images older than 90 days — use Renovate or Dependabot',
            ].map((rec, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginBottom: 10 }}>
                <span style={{ color: '#ef4444', fontWeight: 700, marginTop: 1 }}>✗</span>
                <span style={{ fontSize: 13, color: 'var(--text-2)' }}>{rec}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function RuntimeTab() {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [selected, setSelected] = useState<any>(null);
  useEffect(() => { containerSecurityAPI.getRuntimeAlerts().then(r => setAlerts(r.data || [])); }, []);
  const ALERT_COLOR: Record<string, string> = { reverse_shell: '#ef4444', crypto_mining: '#a855f7', container_escape: '#ef4444', privilege_escalation: '#f97316', file_tampering: '#eab308', unexpected_network: '#3b82f6' };
  return (
    <div style={{ display: 'flex', gap: 16 }}>
      <div style={{ flex: 2 }}>
        <table className="g-table"><thead className="g-thead"><tr>
          <th>Alert Type</th><th>Severity</th><th>Pod</th><th>Namespace</th><th>MITRE</th><th>Status</th><th>Time</th>
        </tr></thead><tbody>
          {alerts.map((a: any) => (
            <tr key={a.id} className="g-tr" onClick={() => setSelected(a)} style={{ cursor: 'pointer', background: selected?.id === a.id ? 'rgba(100,200,255,0.04)' : undefined }}>
              <td>
                <span style={{ color: ALERT_COLOR[a.alert_type] || 'var(--text-1)', fontWeight: 600, fontSize: 12 }}>
                  {a.alert_type?.replace(/_/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase())}
                </span>
              </td>
              <td><SevBadge v={a.severity} /></td>
              <td style={{ fontFamily: 'monospace', fontSize: 11, maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.pod_name}</td>
              <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{a.namespace}</td>
              <td><code style={{ fontSize: 10, background: 'rgba(255,255,255,0.05)', padding: '1px 5px', borderRadius: 3 }}>{a.mitre_technique}</code></td>
              <td><SevBadge v={a.status === 'open' ? 'critical' : a.status === 'investigating' ? 'medium' : 'clean'} /></td>
              <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{timeAgo(a.created_at)}</td>
            </tr>
          ))}
        </tbody></table>
      </div>
      {selected && (
        <div className="g-card" style={{ flex: 1, minWidth: 280, padding: 20, position: 'sticky', top: 16, alignSelf: 'flex-start' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
            <div style={{ fontSize: 14, fontWeight: 600 }}>Alert Details</div>
            <button className="g-btn g-btn-ghost" style={{ padding: '2px 8px', fontSize: 11 }} onClick={() => setSelected(null)}>✕</button>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {[
              { label: 'Type', val: selected.alert_type?.replace(/_/g, ' ') },
              { label: 'Pod', val: selected.pod_name },
              { label: 'Container', val: selected.container_name },
              { label: 'Namespace', val: selected.namespace },
              { label: 'MITRE', val: selected.mitre_technique },
              { label: 'Source IP', val: selected.source_ip || 'N/A' },
              { label: 'Process', val: selected.process || 'N/A' },
            ].map(row => (
              <div key={row.label}>
                <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase' as const, letterSpacing: '0.05em' }}>{row.label}</div>
                <div style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--text-1)', wordBreak: 'break-all' as const, marginTop: 2 }}>{row.val}</div>
              </div>
            ))}
            {selected.command && (
              <div>
                <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase' as const, marginBottom: 4 }}>Command</div>
                <code style={{ fontSize: 10, background: 'rgba(0,0,0,0.3)', padding: 8, borderRadius: 4, display: 'block', wordBreak: 'break-all' as const, color: '#ef4444' }}>{selected.command}</code>
              </div>
            )}
            <div style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.5, borderTop: '1px solid var(--border)', paddingTop: 8 }}>{selected.description}</div>
          </div>
        </div>
      )}
    </div>
  );
}

function RBACTab() {
  const [rbac, setRbac] = useState<any>(null);
  const [secrets, setSecrets] = useState<any>(null);
  const [netpols, setNetpols] = useState<any[]>([]);
  const [admission, setAdmission] = useState<any[]>([]);
  const [sub, setSub] = useState<'rbac' | 'secrets' | 'network' | 'admission'>('rbac');
  useEffect(() => {
    containerSecurityAPI.getRBAC().then(r => setRbac(r.data));
    containerSecurityAPI.getSecrets().then(r => setSecrets(r.data));
    containerSecurityAPI.getNetworkPolicies().then(r => setNetpols(r.data || []));
    containerSecurityAPI.getAdmission().then(r => setAdmission(r.data || []));
  }, []);
  const r = rbac || {}; const sc = secrets || {};
  return (
    <div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
        {(['rbac', 'secrets', 'network', 'admission'] as const).map(s => (
          <button key={s} className={sub === s ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setSub(s)}>
            {s === 'rbac' ? 'RBAC' : s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
      </div>
      {sub === 'rbac' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <StatCard label="Total Findings" value={r.total ?? '—'} color="#ef4444" />
            <StatCard label="Cluster Roles" value={r.cluster_roles ?? '—'} color="#f97316" />
            <StatCard label="Bindings" value={r.bindings ?? '—'} />
            <StatCard label="Excessive Perms" value={r.excessive ?? '—'} color="#f97316" />
            <StatCard label="Wildcard Perms" value={r.wildcard ?? '—'} color="#ef4444" />
          </div>
          <table className="g-table"><thead className="g-thead"><tr>
            <th>Kind</th><th>Name</th><th>Subject</th><th>Namespace</th><th>Finding</th><th>Severity</th><th>Description</th>
          </tr></thead><tbody>
            {(r.findings || []).map((f: any) => (
              <tr key={f.id} className="g-tr">
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{f.kind}</td>
                <td style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 600 }}>{f.name}</td>
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{f.subject}</td>
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{f.namespace}</td>
                <td style={{ fontSize: 11 }}>{f.finding_type?.replace(/_/g, ' ')}</td>
                <td><SevBadge v={f.severity} /></td>
                <td style={{ fontSize: 11, color: 'var(--text-2)', maxWidth: 280 }}>{f.description}</td>
              </tr>
            ))}
          </tbody></table>
        </div>
      )}
      {sub === 'secrets' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <StatCard label="Kubernetes Secrets" value={sc.total_secrets ?? '—'} />
            <StatCard label="Plaintext Secrets" value={sc.plaintext ?? '—'} color={sc.plaintext > 0 ? '#ef4444' : undefined} />
            <StatCard label="Expired Secrets" value={sc.expired ?? '—'} color={sc.expired > 0 ? '#f97316' : undefined} />
            <StatCard label="Exposed Secrets" value={sc.exposed ?? '—'} color={sc.exposed > 0 ? '#ef4444' : undefined} />
          </div>
          <div className="g-card" style={{ padding: 20 }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Secrets Providers</div>
            <table className="g-table"><thead className="g-thead"><tr><th>Provider</th><th>Count</th><th>Status</th></tr></thead><tbody>
              {(sc.providers || []).map((p: any) => (
                <tr key={p.name} className="g-tr">
                  <td style={{ fontWeight: 600 }}>{p.name}</td>
                  <td>{p.count}</td>
                  <td><SevBadge v={p.status === 'active' ? 'clean' : 'medium'} /></td>
                </tr>
              ))}
            </tbody></table>
          </div>
        </div>
      )}
      {sub === 'network' && (
        <table className="g-table"><thead className="g-thead"><tr>
          <th>Name</th><th>Namespace</th><th>Direction</th><th>Pod Selector</th><th>Peer</th><th>Port</th><th>Status</th>
        </tr></thead><tbody>
          {netpols.map((np: any) => (
            <tr key={np.id} className="g-tr">
              <td style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 600 }}>{np.name}</td>
              <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{np.namespace}</td>
              <td style={{ fontSize: 11 }}>{np.direction}</td>
              <td><code style={{ fontSize: 10, background: 'rgba(255,255,255,0.05)', padding: '1px 5px', borderRadius: 3 }}>{np.pod_selector}</code></td>
              <td style={{ fontSize: 11 }}>{np.peer}</td>
              <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{np.port}</td>
              <td><SevBadge v={np.status === 'active' ? 'clean' : np.status === 'warn' ? 'medium' : np.status === 'missing' ? 'high' : 'clean'} /></td>
            </tr>
          ))}
        </tbody></table>
      )}
      {sub === 'admission' && (
        <table className="g-table"><thead className="g-thead"><tr>
          <th>Workload</th><th>Kind</th><th>Namespace</th><th>Violation</th><th>Severity</th><th>Action</th><th>Time</th>
        </tr></thead><tbody>
          {admission.map((v: any) => (
            <tr key={v.id} className="g-tr">
              <td style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 600 }}>{v.workload}</td>
              <td style={{ fontSize: 11 }}>{v.kind}</td>
              <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{v.namespace}</td>
              <td style={{ fontSize: 11 }}>{v.violation_type?.replace(/_/g, ' ')}</td>
              <td><SevBadge v={v.severity} /></td>
              <td><SevBadge v={v.action === 'denied' ? 'clean' : v.action === 'allowed' ? 'high' : 'medium'} /></td>
              <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{v.created_at ? timeAgo(v.created_at) : '—'}</td>
            </tr>
          ))}
        </tbody></table>
      )}
    </div>
  );
}

function IntelligenceTab() {
  const [intel, setIntel] = useState<any>(null);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [aiMode, setAiMode] = useState<'alert' | 'image' | 'ask'>('alert');
  const [aiInput, setAiInput] = useState('');
  const [aiRes, setAiRes] = useState<any>(null);
  const [aiLoading, setAiLoading] = useState(false);
  useEffect(() => {
    containerSecurityAPI.getThreatIntel().then(r => setIntel(r.data));
    containerSecurityAPI.getTimeline().then(r => setTimeline(r.data || []));
  }, []);
  const ti = intel || {};
  const doAI = async () => {
    setAiLoading(true);
    try {
      const payload: any = { mode: aiMode };
      if (aiMode === 'image') payload.image = aiInput;
      else if (aiMode === 'alert') payload.alert = aiInput;
      else payload.content = aiInput;
      const r = await containerSecurityAPI.analyzeAI(payload);
      setAiRes(r.data);
    } catch { setAiRes({ error: 'Analysis failed' }); }
    setAiLoading(false);
  };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        <div className="g-card" style={{ flex: 1, minWidth: 280, padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Threat Actors</div>
          {(ti.threat_actors || []).map((a: any) => (
            <div key={a.actor} style={{ marginBottom: 12, paddingBottom: 12, borderBottom: '1px solid var(--border)' }}>
              <div style={{ fontWeight: 600, color: '#ef4444' }}>{a.actor}</div>
              <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>{a.target} · {a.campaigns} campaigns</div>
              <code style={{ fontSize: 10, background: 'rgba(255,255,255,0.05)', padding: '2px 6px', borderRadius: 3, display: 'inline-block', marginTop: 4 }}>{a.ttps}</code>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ flex: 1, minWidth: 280, padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Recent CVEs</div>
          {(ti.recent_cves || []).map((cv: any) => (
            <div key={cv.cve} style={{ marginBottom: 10, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <span style={{ fontFamily: 'monospace', fontWeight: 600, color: '#ef4444', fontSize: 13 }}>{cv.cve}</span>
                <span style={{ fontSize: 11, color: 'var(--text-3)', marginLeft: 8 }}>{cv.type?.replace(/_/g, ' ')}</span>
                <div style={{ fontSize: 11, color: 'var(--text-2)', marginTop: 2 }}>{cv.affected}</div>
              </div>
              <span style={{ fontWeight: 700, fontSize: 14, color: cv.score >= 9 ? '#ef4444' : cv.score >= 7 ? '#f97316' : '#eab308' }}>{cv.score}</span>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ flex: 1, minWidth: 280, padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>IOC Matches</div>
          {(ti.ioc_matches || []).map((ioc: any) => (
            <div key={ioc.value} style={{ marginBottom: 10, padding: '8px 10px', background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <code style={{ fontSize: 11 }}>{ioc.value}</code>
                <span style={{ fontSize: 11, fontWeight: 700, color: '#ef4444' }}>{ioc.hits} hits</span>
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>{ioc.type?.toUpperCase()} · {ioc.category?.replace(/_/g, ' ')}</div>
            </div>
          ))}
        </div>
      </div>
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        <div className="g-card" style={{ flex: 1, minWidth: 320, padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>AI Security Analysis</div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
            {(['alert', 'image', 'ask'] as const).map(m => (
              <button key={m} className={aiMode === m ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setAiMode(m)} style={{ fontSize: 11, padding: '4px 10px', textTransform: 'capitalize' }}>{m}</button>
            ))}
          </div>
          <textarea
            className="g-input"
            rows={3}
            style={{ width: '100%', resize: 'vertical' as const, fontFamily: 'monospace', fontSize: 12 }}
            placeholder={aiMode === 'alert' ? 'Paste runtime alert details...' : aiMode === 'image' ? 'Paste image scan results...' : 'Ask a Kubernetes security question...'}
            value={aiInput}
            onChange={e => setAiInput(e.target.value)}
          />
          <button className="g-btn g-btn-primary" style={{ marginTop: 10, width: '100%' }} onClick={doAI} disabled={aiLoading || !aiInput.trim()}>
            {aiLoading ? 'Analyzing...' : 'Analyze with AI'}
          </button>
          {aiRes && (
            <div style={{ marginTop: 16, padding: 14, background: 'rgba(0,0,0,0.2)', borderRadius: 8, border: '1px solid var(--border)' }}>
              {aiRes.verdict && <div style={{ marginBottom: 10 }}><SevBadge v={aiRes.verdict === 'confirmed_threat' ? 'critical' : aiRes.verdict === 'false_positive' ? 'clean' : 'medium'} /></div>}
              {aiRes.explanation && <p style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.6, marginBottom: 12 }}>{aiRes.explanation}</p>}
              {aiRes.mitre_techniques && (
                <div style={{ marginBottom: 10 }}>
                  <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase' as const, marginBottom: 4 }}>MITRE ATT&CK</div>
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    {aiRes.mitre_techniques.map((t: string) => <code key={t} style={{ fontSize: 10, background: 'rgba(255,255,255,0.05)', padding: '2px 6px', borderRadius: 3 }}>{t}</code>)}
                  </div>
                </div>
              )}
              {aiRes.recommended_actions && (
                <div>
                  <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase' as const, marginBottom: 6 }}>Recommended Actions</div>
                  {aiRes.recommended_actions.map((a: string, i: number) => (
                    <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 6 }}>
                      <span style={{ color: 'var(--accent)', fontWeight: 700 }}>{i + 1}.</span>
                      <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{a}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
        <div className="g-card" style={{ flex: 1, minWidth: 320, padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Security Timeline</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, maxHeight: 400, overflowY: 'auto' }}>
            {timeline.map((ev: any) => (
              <div key={ev.id} style={{ padding: '10px 12px', background: 'rgba(255,255,255,0.02)', borderRadius: 6, borderLeft: `3px solid ${ev.severity === 'critical' ? '#ef4444' : ev.severity === 'high' ? '#f97316' : ev.severity === 'medium' ? '#eab308' : '#22c55e'}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <span style={{ fontSize: 12, fontWeight: 600, textTransform: 'capitalize' }}>{ev.event_type?.replace(/_/g, ' ')}</span>
                  <SevBadge v={ev.severity} />
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-2)', marginBottom: 4 }}>{ev.description}</div>
                <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{ev.namespace}/{ev.pod_name} · {timeAgo(ev.created_at)}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function ComplianceTab() {
  const [comp, setComp] = useState<any>(null);
  useEffect(() => { containerSecurityAPI.getCompliance().then(r => setComp(r.data)); }, []);
  const c = comp || {};
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <StatCard label="Overall Compliance Score" value={`${c.overall_score ?? '—'}%`} color={c.overall_score >= 80 ? '#22c55e' : c.overall_score >= 60 ? '#f97316' : '#ef4444'} />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 16 }}>
        {(c.frameworks || []).map((fw: any) => (
          <div key={fw.name} className="g-card" style={{ padding: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
              <div>
                <div style={{ fontWeight: 600, fontSize: 13 }}>{fw.name}</div>
                <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>v{fw.version}</div>
              </div>
              <span style={{ fontSize: 22, fontWeight: 700, color: fw.score >= 80 ? '#22c55e' : fw.score >= 60 ? '#f97316' : '#ef4444' }}>{fw.score}%</span>
            </div>
            <RiskBar score={fw.score} />
            <div style={{ display: 'flex', gap: 16, marginTop: 12 }}>
              <div style={{ textAlign: 'center' as const }}><div style={{ fontSize: 16, fontWeight: 700, color: '#22c55e' }}>{fw.passed}</div><div style={{ fontSize: 10, color: 'var(--text-3)' }}>Passed</div></div>
              <div style={{ textAlign: 'center' as const }}><div style={{ fontSize: 16, fontWeight: 700, color: '#ef4444' }}>{fw.failed}</div><div style={{ fontSize: 10, color: 'var(--text-3)' }}>Failed</div></div>
              <div style={{ textAlign: 'center' as const }}><div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-2)' }}>{fw.total}</div><div style={{ fontSize: 10, color: 'var(--text-3)' }}>Total</div></div>
            </div>
          </div>
        ))}
      </div>
      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Failed Controls</div>
        <table className="g-table"><thead className="g-thead"><tr>
          <th>Control</th><th>Title</th><th>Framework</th><th>Severity</th>
        </tr></thead><tbody>
          {(c.failed_controls || []).map((fc: any, i: number) => (
            <tr key={i} className="g-tr">
              <td style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 600 }}>{fc.control}</td>
              <td style={{ fontSize: 12 }}>{fc.title}</td>
              <td style={{ fontSize: 11, color: 'var(--text-2)' }}>{fc.framework}</td>
              <td><SevBadge v={fc.severity} /></td>
            </tr>
          ))}
        </tbody></table>
      </div>
    </div>
  );
}

function AnalyticsTab() {
  const [analytics, setAnalytics] = useState<any>(null);
  useEffect(() => { containerSecurityAPI.getAnalytics().then(r => setAnalytics(r.data)); }, []);
  const a = analytics || {};
  const maxAlerts = useMemo(() => Math.max(1, ...(a.runtime_alert_trend || []).map((p: any) => p.count)), [a.runtime_alert_trend]);
  const maxAlertType = useMemo(() => Math.max(1, ...(a.alert_by_type || []).map((t: any) => t.count)), [a.alert_by_type]);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <StatCard label="Total Pods" value={a.total_pods ?? '—'} />
        <StatCard label="Privileged Pods" value={a.privileged_pods ?? '—'} color={a.privileged_pods > 0 ? '#ef4444' : undefined} />
      </div>
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        <div className="g-card" style={{ flex: 2, minWidth: 320, padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Runtime Alerts — 14 Day Trend</div>
          <div style={{ display: 'flex', alignItems: 'flex-end', gap: 3, height: 80, paddingBottom: 24 }}>
            {(a.runtime_alert_trend || []).map((p: any) => (
              <div key={p.date} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, height: '100%', justifyContent: 'flex-end' }}>
                <div style={{ width: '80%', background: p.count > 4 ? '#ef4444' : p.count > 2 ? '#f97316' : 'var(--accent)', borderRadius: 2, height: `${(p.count / maxAlerts) * 56 + 4}px`, minHeight: 4 }} />
                <span style={{ fontSize: 9, color: 'var(--text-3)' }}>{p.date?.slice(5)}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="g-card" style={{ flex: 1, minWidth: 260, padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Alerts by Type</div>
          {(a.alert_by_type || []).map((t: any) => (
            <div key={t.type} style={{ marginBottom: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <span style={{ fontSize: 12, color: 'var(--text-2)', textTransform: 'capitalize' }}>{t.type?.replace(/_/g, ' ')}</span>
                <span style={{ fontSize: 12, fontWeight: 600 }}>{t.count}</span>
              </div>
              <div style={{ height: 4, background: 'rgba(255,255,255,0.05)', borderRadius: 2 }}>
                <div style={{ width: `${(t.count / maxAlertType) * 100}%`, height: '100%', background: 'var(--accent)', borderRadius: 2 }} />
              </div>
            </div>
          ))}
        </div>
      </div>
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        <div className="g-card" style={{ flex: 1, minWidth: 300, padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Top Vulnerable Images</div>
          <table className="g-table"><thead className="g-thead"><tr><th>Image</th><th>Critical</th><th>High</th><th>Risk</th></tr></thead><tbody>
            {(a.top_vulnerable_images || []).map((img: any, i: number) => (
              <tr key={i} className="g-tr">
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{img.image}</td>
                <td style={{ color: '#ef4444', fontWeight: 700 }}>{img.cve_critical}</td>
                <td style={{ color: '#f97316', fontWeight: 700 }}>{img.cve_high}</td>
                <td style={{ width: 120 }}><RiskBar score={img.risk} /></td>
              </tr>
            ))}
          </tbody></table>
        </div>
        <div className="g-card" style={{ flex: 1, minWidth: 300, padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Namespace Risk</div>
          {(a.namespace_risk || []).map((ns: any) => (
            <div key={ns.namespace} style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <span style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 600 }}>{ns.namespace}</span>
                <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{ns.pods} pods</span>
              </div>
              <RiskBar score={ns.risk} />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ResponseTab() {
  const [attackPaths, setAttackPaths] = useState<any>(null);
  const [vulns, setVulns] = useState<any[]>([]);
  const [action, setAction] = useState('kill_container');
  const [target, setTarget] = useState('');
  const [ns, setNs] = useState('');
  const [msg, setMsg] = useState('');
  const [reportType, setReportType] = useState('executive');
  const [reportResult, setReportResult] = useState<any>(null);
  const [reportLoading, setReportLoading] = useState(false);
  useEffect(() => {
    containerSecurityAPI.getAttackPaths().then(r => setAttackPaths(r.data));
    containerSecurityAPI.getVulnerabilities().then(r => setVulns(r.data || []));
  }, []);
  const ap = attackPaths || {};
  const ACTIONS = [
    { id: 'kill_container', label: 'Kill Container', desc: 'Send SIGKILL to container process', color: '#ef4444' },
    { id: 'delete_pod', label: 'Delete Pod', desc: 'Delete pod (replacement will be scheduled)', color: '#f97316' },
    { id: 'scale_deployment', label: 'Scale to Zero', desc: 'Scale deployment to 0 replicas', color: '#f97316' },
    { id: 'quarantine_node', label: 'Quarantine Node', desc: 'Cordon node and evict all pods', color: '#ef4444' },
    { id: 'block_image', label: 'Block Image', desc: 'Add to admission controller blocklist', color: '#a855f7' },
    { id: 'revoke_service_account', label: 'Revoke SA Token', desc: 'Revoke service account token', color: '#3b82f6' },
    { id: 'run_soar_playbook', label: 'Run SOAR Playbook', desc: 'Trigger automated response playbook', color: '#22c55e' },
  ];
  const doAction = async () => {
    const r = await containerSecurityAPI.respond({ action, pod_name: target, namespace: ns });
    setMsg(r.data?.message || 'Action executed');
    setTimeout(() => setMsg(''), 5000);
  };
  const doReport = async () => {
    setReportLoading(true);
    const r = await containerSecurityAPI.generateReport({ report_type: reportType });
    setReportResult(r.data);
    setReportLoading(false);
  };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Attack Path Visualization</div>
        <div style={{ overflowX: 'auto' }}>
          <div style={{ display: 'flex', alignItems: 'center', minWidth: 600, padding: '8px 0', gap: 0 }}>
            {(ap.nodes || []).map((node: any, i: number) => (
              <div key={node.id} style={{ display: 'flex', alignItems: 'center' }}>
                <div style={{ textAlign: 'center' as const, minWidth: 100 }}>
                  <div style={{ padding: '8px 12px', borderRadius: 8, background: node.risk >= 90 ? 'rgba(220,38,38,0.15)' : node.risk >= 70 ? 'rgba(234,88,12,0.15)' : 'rgba(255,255,255,0.05)', border: `1px solid ${node.risk >= 90 ? 'rgba(220,38,38,0.4)' : node.risk >= 70 ? 'rgba(234,88,12,0.4)' : 'var(--border)'}`, color: node.risk >= 90 ? '#f87171' : node.risk >= 70 ? '#fb923c' : 'var(--text-1)', fontSize: 11, fontWeight: 600 }}>
                    {node.label}
                  </div>
                  <div style={{ fontSize: 9, color: 'var(--text-3)', marginTop: 4 }}>{node.type?.replace(/_/g, ' ')}</div>
                </div>
                {i < (ap.nodes || []).length - 1 && (
                  <div style={{ color: '#ef4444', fontSize: 18, padding: '0 4px', marginBottom: 14 }}>→</div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
      {vulns.length > 0 && (
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Vulnerability Summary</div>
          <table className="g-table"><thead className="g-thead"><tr><th>Image</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Risk</th></tr></thead><tbody>
            {vulns.map((v: any) => (
              <tr key={v.id} className="g-tr">
                <td style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 600 }}>{v.image}</td>
                <td style={{ color: '#ef4444', fontWeight: 700 }}>{v.cve_critical}</td>
                <td style={{ color: '#f97316', fontWeight: 700 }}>{v.cve_high}</td>
                <td style={{ color: '#eab308' }}>{v.cve_medium}</td>
                <td style={{ color: 'var(--text-3)' }}>{v.cve_low}</td>
                <td style={{ width: 120 }}><RiskBar score={v.risk_score} /></td>
              </tr>
            ))}
          </tbody></table>
        </div>
      )}
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        <div className="g-card" style={{ flex: 1, minWidth: 340, padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Response Actions</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 16 }}>
            {ACTIONS.map(a => (
              <button key={a.id} onClick={() => setAction(a.id)} style={{ textAlign: 'left' as const, padding: '10px 12px', borderRadius: 8, border: `1px solid ${action === a.id ? a.color : 'var(--border)'}`, background: action === a.id ? `${a.color}22` : 'rgba(255,255,255,0.02)', cursor: 'pointer', transition: 'all 0.2s' }}>
                <div style={{ fontWeight: 600, fontSize: 12, color: action === a.id ? a.color : 'var(--text-1)' }}>{a.label}</div>
                <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>{a.desc}</div>
              </button>
            ))}
          </div>
          <input className="g-input" placeholder="Pod name (optional)" value={target} onChange={e => setTarget(e.target.value)} style={{ marginBottom: 8, width: '100%' }} />
          <input className="g-input" placeholder="Namespace (optional)" value={ns} onChange={e => setNs(e.target.value)} style={{ marginBottom: 12, width: '100%' }} />
          <button className="g-btn g-btn-primary" style={{ width: '100%' }} onClick={doAction}>
            Execute: {ACTIONS.find(a => a.id === action)?.label}
          </button>
          {msg && <div style={{ marginTop: 12, padding: '10px 14px', background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.3)', borderRadius: 6, fontSize: 12, color: '#4ade80' }}>{msg}</div>}
        </div>
        <div className="g-card" style={{ flex: 1, minWidth: 320, padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Generate Report</div>
          <select className="g-select" value={reportType} onChange={e => setReportType(e.target.value)} style={{ width: '100%', marginBottom: 12 }}>
            <option value="executive">Executive Summary</option>
            <option value="technical">Technical Deep Dive</option>
            <option value="compliance">Compliance Report</option>
            <option value="incident">Incident Response Report</option>
          </select>
          <button className="g-btn g-btn-primary" style={{ width: '100%' }} onClick={doReport} disabled={reportLoading}>
            {reportLoading ? 'Generating...' : 'Generate with AI'}
          </button>
          {reportResult && (
            <div style={{ marginTop: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ fontWeight: 600, fontSize: 14, color: 'var(--accent)' }}>{reportResult.title}</div>
              {reportResult.executive_summary && <p style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.6 }}>{reportResult.executive_summary}</p>}
              {reportResult.key_findings && (
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6 }}>Key Findings</div>
                  {reportResult.key_findings.map((f: string, i: number) => (
                    <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 6 }}>
                      <span style={{ color: '#ef4444', fontWeight: 700 }}>•</span>
                      <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{f}</span>
                    </div>
                  ))}
                </div>
              )}
              {reportResult.top_recommendations && (
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6 }}>Top Recommendations</div>
                  {reportResult.top_recommendations.map((rec: any, i: number) => (
                    <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                      <span style={{ color: 'var(--accent)', fontWeight: 700 }}>{rec.priority}.</span>
                      <div>
                        <div style={{ fontSize: 12, color: 'var(--text-1)' }}>{rec.action}</div>
                        <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>Est. effort: {rec.estimated_effort}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function ContainerSecurityPage() {
  const [tab, setTab] = useState<Tab>('overview');
  const loaded = useRef<Record<string, boolean>>({});
  if (!loaded.current[tab]) loaded.current[tab] = true;
  const TAB_LABELS: Record<Tab, string> = {
    overview: 'Overview', inventory: 'Inventory', images: 'Images', runtime: 'Runtime',
    rbac: 'RBAC + Network', intelligence: 'Intelligence',
    compliance: 'Compliance', analytics: 'Analytics', response: 'Attack Paths + Response',
  };
  const visibleTabs: Tab[] = ['overview', 'inventory', 'images', 'runtime', 'rbac', 'intelligence', 'compliance', 'analytics', 'response'];
  return (
    <RootLayout>
    <div style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>Container &amp; Kubernetes Security</h1>
        <div style={{ marginTop: 4, color: 'var(--text-3)', fontSize: 13 }}>Runtime protection, image scanning, RBAC analysis, and compliance for containerized workloads.</div>
      </div>
      <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', overflowX: 'auto' }}>
        {visibleTabs.map(t => (
          <button key={t} onClick={() => setTab(t)}
            style={{ padding: '8px 16px', fontSize: 12, fontWeight: tab === t ? 600 : 400, color: tab === t ? 'var(--accent)' : 'var(--text-3)', background: 'transparent', border: 'none', borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent', cursor: 'pointer', whiteSpace: 'nowrap' }}>
            {TAB_LABELS[t]}
          </button>
        ))}
      </div>
      <div>
        {loaded.current['overview']      && <div style={{ display: tab === 'overview'      ? 'block' : 'none' }}><OverviewTab /></div>}
        {loaded.current['inventory']     && <div style={{ display: tab === 'inventory'     ? 'block' : 'none' }}><InventoryTab /></div>}
        {loaded.current['images']        && <div style={{ display: tab === 'images'        ? 'block' : 'none' }}><ImagesTab /></div>}
        {loaded.current['runtime']       && <div style={{ display: tab === 'runtime'       ? 'block' : 'none' }}><RuntimeTab /></div>}
        {loaded.current['rbac']          && <div style={{ display: tab === 'rbac'          ? 'block' : 'none' }}><RBACTab /></div>}
        {loaded.current['intelligence']  && <div style={{ display: tab === 'intelligence'  ? 'block' : 'none' }}><IntelligenceTab /></div>}
        {loaded.current['compliance']    && <div style={{ display: tab === 'compliance'    ? 'block' : 'none' }}><ComplianceTab /></div>}
        {loaded.current['analytics']     && <div style={{ display: tab === 'analytics'     ? 'block' : 'none' }}><AnalyticsTab /></div>}
        {loaded.current['response']      && <div style={{ display: tab === 'response'      ? 'block' : 'none' }}><ResponseTab /></div>}
      </div>
    </div>
    </RootLayout>
  );
}
