'use client';
import { useState, useEffect, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { containerSecurityAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import { MetricCard, SectionCard, DataTable, TabBar, ActionButton } from '@/components/design-system';
import {
  LayoutDashboard, Boxes, Package, Activity, Lock, Radar, ClipboardCheck, BarChart3, Siren, Check, X,
} from 'lucide-react';

const SEV_BG: Record<string, string> = {
  critical: 'background:rgba(220,38,38,0.15);color:#f87171;border:1px solid rgba(220,38,38,0.3)',
  high:     'background:rgba(234,88,12,0.15);color:#fb923c;border:1px solid rgba(234,88,12,0.3)',
  medium:   'background:rgba(202,138,4,0.15);color:#facc15;border:1px solid rgba(202,138,4,0.3)',
  low:      'background:rgba(34,197,94,0.15);color:#4ade80;border:1px solid rgba(34,197,94,0.3)',
  clean:    'background:rgba(34,197,94,0.15);color:#4ade80;border:1px solid rgba(34,197,94,0.3)',
  warn:     'background:rgba(202,138,4,0.15);color:#facc15;border:1px solid rgba(202,138,4,0.3)',
};
type Tab = 'overview' | 'inventory' | 'images' | 'runtime' | 'rbac' | 'intelligence' | 'compliance' | 'analytics' | 'response';

const TAB_ICONS: Record<Tab, any> = {
  overview: LayoutDashboard, inventory: Boxes, images: Package, runtime: Activity, rbac: Lock,
  intelligence: Radar, compliance: ClipboardCheck, analytics: BarChart3, response: Siren,
};

function SevBadge({ v }: { v: string }) {
  const style = SEV_BG[v?.toLowerCase()] || SEV_BG.low;
  return <span style={{ ...Object.fromEntries(style.split(';').filter(Boolean).map(s => { const [k, val] = s.split(':'); return [k.trim().replace(/-([a-z])/g, (_: string, c: string) => c.toUpperCase()), val?.trim()]; })), padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600, textTransform: 'uppercase' as const, whiteSpace: 'nowrap' as const }}>{v}</span>;
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

function OkBad({ ok }: { ok: boolean }) {
  return ok
    ? <Check style={{ width: 13, height: 13, color: '#22c55e' }} />
    : <X style={{ width: 13, height: 13, color: '#ef4444' }} />;
}

function OverviewTab() {
  const [dash, setDash] = useState<any>(null);
  useEffect(() => { containerSecurityAPI.getDashboard().then(r => setDash(r.data)); }, []);
  const d = dash || {};
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <MetricCard label="Clusters" value={d.clusters ?? '—'} color="var(--accent)" />
        <MetricCard label="Nodes" value={d.nodes ?? '—'} color="var(--accent)" />
        <MetricCard label="Pods" value={d.pods ?? '—'} color="var(--accent)" />
        <MetricCard label="Namespaces" value={d.namespaces ?? '—'} color="var(--accent)" />
        <MetricCard label="Running Containers" value={d.running_containers ?? '—'} color="var(--accent)" />
        <MetricCard label="Runtime Alerts" value={d.runtime_alerts ?? '—'} color={d.runtime_alerts > 0 ? '#ef4444' : undefined} />
        <MetricCard label="Vulnerable Images" value={d.vulnerable_images ?? '—'} color={d.vulnerable_images > 0 ? '#f97316' : undefined} />
        <MetricCard label="Critical Findings" value={d.critical_findings ?? '—'} color={d.critical_findings > 0 ? '#ef4444' : undefined} />
      </div>
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        <SectionCard title="Security Posture" className="flex-1">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14, minWidth: 280 }}>
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
        </SectionCard>
        <SectionCard title="Security Concerns" className="flex-1">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, minWidth: 280 }}>
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
        </SectionCard>
        <SectionCard title="Coverage" className="flex-1">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, minWidth: 280 }}>
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
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 11, fontWeight: 600, color: row.status ? '#22c55e' : '#ef4444' }}>
                  <OkBad ok={row.status} /> {row.status ? 'Active' : 'Missing'}
                </span>
              </div>
            ))}
          </div>
        </SectionCard>
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
          <ActionButton key={s} variant={sub === s ? 'primary' : 'ghost'} onClick={() => setSub(s)} style={{ textTransform: 'capitalize' }}>{s}</ActionButton>
        ))}
      </div>
      {sub === 'clusters' && (
        <DataTable<any>
          rows={clusters}
          rowKey={(cl: any) => cl.id}
          columns={[
            { key: 'name', header: 'Cluster', render: (cl: any) => <span style={{ fontWeight: 600, fontFamily: 'monospace', fontSize: 12 }}>{cl.name}</span> },
            { key: 'provider', header: 'Provider', render: (cl: any) => <span style={{ color: PROV_COLOR[cl.provider] || 'var(--text-1)', fontWeight: 600, fontSize: 12, textTransform: 'uppercase' }}>{cl.provider}</span> },
            { key: 'k8s_version', header: 'K8s Version', render: (cl: any) => <span style={{ fontFamily: 'monospace', fontSize: 12 }}>{cl.k8s_version}</span> },
            { key: 'node_count', header: 'Nodes', render: (cl: any) => <span>{cl.node_count}</span> },
            { key: 'region', header: 'Region', render: (cl: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{cl.region}</span> },
            { key: 'risk', header: 'Risk', render: (cl: any) => <RiskBar score={cl.risk_score} /> },
            { key: 'compliance', header: 'Compliance', render: (cl: any) => <RiskBar score={cl.compliance_score} /> },
            { key: 'status', header: 'Status', render: (cl: any) => <SevBadge v={cl.status === 'healthy' ? 'clean' : cl.status === 'degraded' ? 'medium' : 'high'} /> },
          ]}
        />
      )}
      {sub === 'nodes' && (
        <DataTable<any>
          rows={nodes}
          rowKey={(n: any) => n.id}
          columns={[
            { key: 'name', header: 'Node', render: (n: any) => <span style={{ fontFamily: 'monospace', fontSize: 11, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>{n.name}</span> },
            { key: 'os', header: 'OS', render: (n: any) => <span style={{ fontSize: 11 }}>{n.os}</span> },
            { key: 'runtime', header: 'Runtime', render: (n: any) => <span style={{ fontSize: 11, fontFamily: 'monospace' }}>{n.runtime}</span> },
            { key: 'cpu', header: 'CPU', render: (n: any) => <span>{n.cpu_cores} vCPU</span> },
            { key: 'memory', header: 'Memory', render: (n: any) => <span>{n.memory_gb} GB</span> },
            { key: 'pod_count', header: 'Pods', render: (n: any) => <span>{n.pod_count}</span> },
            { key: 'vuln_count', header: 'CVEs', render: (n: any) => <span style={{ color: n.vuln_count > 4 ? '#ef4444' : n.vuln_count > 2 ? '#f97316' : '#22c55e', fontWeight: 600 }}>{n.vuln_count}</span> },
            { key: 'risk', header: 'Risk', render: (n: any) => <RiskBar score={n.risk_score} /> },
            { key: 'status', header: 'Status', render: (n: any) => <SevBadge v={n.status === 'ready' ? 'clean' : 'high'} /> },
          ]}
        />
      )}
      {sub === 'namespaces' && (
        <DataTable<any>
          rows={namespaces}
          rowKey={(ns: any) => ns.namespace}
          columns={[
            { key: 'namespace', header: 'Namespace', render: (ns: any) => <span style={{ fontFamily: 'monospace', fontWeight: 600 }}>{ns.namespace}</span> },
            { key: 'pod_count', header: 'Pods', render: (ns: any) => <span>{ns.pod_count}</span> },
            { key: 'privileged_pods', header: 'Privileged Pods', render: (ns: any) => <span style={{ color: ns.privileged_pods > 0 ? '#ef4444' : '#22c55e', fontWeight: 600 }}>{ns.privileged_pods}</span> },
            { key: 'risk', header: 'Risk Score', width: '200px', render: (ns: any) => <RiskBar score={Math.round(ns.risk_score)} /> },
          ]}
        />
      )}
      {sub === 'pods' && (
        <DataTable<any>
          rows={pods}
          rowKey={(p: any) => p.id}
          columns={[
            { key: 'name', header: 'Pod', render: (p: any) => <span style={{ fontFamily: 'monospace', fontSize: 11, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>{p.name}</span> },
            { key: 'namespace', header: 'Namespace', render: (p: any) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{p.namespace}</span> },
            { key: 'image', header: 'Image', render: (p: any) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{p.image}</span> },
            { key: 'priv', header: 'Priv', render: (p: any) => <OkBad ok={!p.is_privileged} /> },
            { key: 'root', header: 'Root', render: (p: any) => <OkBad ok={!p.run_as_root} /> },
            { key: 'host_net', header: 'Host Net', render: (p: any) => <OkBad ok={!p.host_network} /> },
            { key: 'limits', header: 'Limits', render: (p: any) => <OkBad ok={p.has_resource_limits} /> },
            { key: 'risk', header: 'Risk', width: '140px', render: (p: any) => <RiskBar score={p.risk_score} /> },
          ]}
        />
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
        <ActionButton variant={sub === 'scan' ? 'primary' : 'ghost'} onClick={() => setSub('scan')}>Image Scan Results</ActionButton>
        <ActionButton variant={sub === 'supply' ? 'primary' : 'ghost'} onClick={() => setSub('supply')}>Supply Chain</ActionButton>
      </div>
      {sub === 'scan' && (
        <DataTable<any>
          rows={images}
          rowKey={(img: any) => img.id}
          columns={[
            { key: 'image', header: 'Image', render: (img: any) => <span style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 600 }}>{img.image}:{img.tag}</span> },
            { key: 'registry', header: 'Registry', render: (img: any) => <span style={{ fontSize: 11 }}>{img.registry}</span> },
            { key: 'os', header: 'OS', render: (img: any) => <span style={{ fontSize: 11 }}>{img.os}</span> },
            { key: 'age', header: 'Age', render: (img: any) => <span style={{ fontSize: 11, color: img.age_days > 365 ? '#ef4444' : 'var(--text-2)' }}>{img.age_days}d</span> },
            { key: 'critical', header: 'Critical', render: (img: any) => <span style={{ color: img.cve_critical > 0 ? '#ef4444' : 'var(--text-3)', fontWeight: img.cve_critical > 0 ? 700 : 400 }}>{img.cve_critical}</span> },
            { key: 'high', header: 'High', render: (img: any) => <span style={{ color: img.cve_high > 0 ? '#f97316' : 'var(--text-3)', fontWeight: img.cve_high > 0 ? 700 : 400 }}>{img.cve_high}</span> },
            { key: 'medium', header: 'Med', render: (img: any) => <span style={{ color: 'var(--text-2)' }}>{img.cve_medium}</span> },
            { key: 'low', header: 'Low', render: (img: any) => <span style={{ color: 'var(--text-3)' }}>{img.cve_low}</span> },
            { key: 'secrets', header: 'Secrets', render: (img: any) => img.has_secrets
              ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#ef4444', fontWeight: 700 }}><X style={{ width: 12, height: 12 }} /> YES</span>
              : <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#22c55e', fontWeight: 700 }}><Check style={{ width: 12, height: 12 }} /> No</span> },
            { key: 'signed', header: 'Signed', render: (img: any) => <OkBad ok={img.signature_valid} /> },
            { key: 'sbom', header: 'SBOM', render: (img: any) => <OkBad ok={img.sbom_available} /> },
            { key: 'risk', header: 'Risk', width: '120px', render: (img: any) => <RiskBar score={img.risk_score} /> },
          ]}
        />
      )}
      {sub === 'supply' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <MetricCard label="Total Images" value={sc.total_images ?? '—'} color="var(--accent)" />
            <MetricCard label="Signed Images" value={sc.signed_images ?? '—'} sub={`${sc.signature_rate ?? 0}% coverage`} color="#22c55e" />
            <MetricCard label="SBOM Available" value={sc.sbom_available ?? '—'} sub={`${sc.sbom_rate ?? 0}% coverage`} color="#3b82f6" />
            <MetricCard label="Old Base Images" value={sc.old_base_images ?? '—'} sub="> 180 days old" color={sc.old_base_images > 0 ? '#f97316' : undefined} />
          </div>
          <SectionCard title="Registry Trust">
            <DataTable<any>
              rows={sc.trusted_registries || []}
              rowKey={(r: any) => r.registry}
              columns={[
                { key: 'registry', header: 'Registry', render: (r: any) => <span style={{ fontFamily: 'monospace', fontWeight: 600 }}>{r.registry}</span> },
                { key: 'trusted', header: 'Trusted', render: (r: any) => r.trusted
                  ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#22c55e', fontWeight: 700 }}><Check style={{ width: 12, height: 12 }} /> Trusted</span>
                  : <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#ef4444', fontWeight: 700 }}><X style={{ width: 12, height: 12 }} /> Untrusted</span> },
                { key: 'images', header: 'Images', render: (r: any) => <span>{r.images}</span> },
              ]}
            />
          </SectionCard>
          <SectionCard title="Supply Chain Recommendations">
            {[
              'Enable Cosign image signing for all production images',
              'Generate and attach SBOMs to all container builds (syft/grype)',
              'Block unsigned images via admission controller policy (OPA Gatekeeper)',
              'Restrict allowed registries to gcr.io, ghcr.io, public.ecr.aws',
              'Update base images older than 90 days — use Renovate or Dependabot',
            ].map((rec, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginBottom: 10 }}>
                <X style={{ width: 13, height: 13, color: '#ef4444', flexShrink: 0, marginTop: 2 }} />
                <span style={{ fontSize: 13, color: 'var(--text-2)' }}>{rec}</span>
              </div>
            ))}
          </SectionCard>
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
        <DataTable<any>
          rows={alerts}
          rowKey={(a: any) => a.id}
          onRowClick={a => setSelected(a)}
          rowStyle={(a: any) => selected?.id === a.id ? { background: 'rgba(100,200,255,0.04)' } : undefined}
          columns={[
            { key: 'alert_type', header: 'Alert Type', render: (a: any) => (
              <span style={{ color: ALERT_COLOR[a.alert_type] || 'var(--text-1)', fontWeight: 600, fontSize: 12 }}>
                {a.alert_type?.replace(/_/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase())}
              </span>
            ) },
            { key: 'severity', header: 'Severity', render: (a: any) => <SevBadge v={a.severity} /> },
            { key: 'pod_name', header: 'Pod', render: (a: any) => <span style={{ fontFamily: 'monospace', fontSize: 11, maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>{a.pod_name}</span> },
            { key: 'namespace', header: 'Namespace', render: (a: any) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{a.namespace}</span> },
            { key: 'mitre', header: 'MITRE', render: (a: any) => <code style={{ fontSize: 10, background: 'rgba(255,255,255,0.05)', padding: '1px 5px', borderRadius: 3 }}>{a.mitre_technique}</code> },
            { key: 'status', header: 'Status', render: (a: any) => <SevBadge v={a.status === 'open' ? 'critical' : a.status === 'investigating' ? 'medium' : 'clean'} /> },
            { key: 'time', header: 'Time', render: (a: any) => <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{timeAgo(a.created_at)}</span> },
          ]}
        />
      </div>
      {selected && (
        <div className="g-card" style={{ flex: 1, minWidth: 280, padding: 20, position: 'sticky', top: 16, alignSelf: 'flex-start' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
            <div style={{ fontSize: 14, fontWeight: 600 }}>Alert Details</div>
            <ActionButton variant="ghost" style={{ padding: '2px 8px', fontSize: 11 }} onClick={() => setSelected(null)}><X style={{ width: 12, height: 12 }} /></ActionButton>
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
          <ActionButton key={s} variant={sub === s ? 'primary' : 'ghost'} onClick={() => setSub(s)}>
            {s === 'rbac' ? 'RBAC' : s.charAt(0).toUpperCase() + s.slice(1)}
          </ActionButton>
        ))}
      </div>
      {sub === 'rbac' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <MetricCard label="Total Findings" value={r.total ?? '—'} color="#ef4444" />
            <MetricCard label="Cluster Roles" value={r.cluster_roles ?? '—'} color="#f97316" />
            <MetricCard label="Bindings" value={r.bindings ?? '—'} color="var(--accent)" />
            <MetricCard label="Excessive Perms" value={r.excessive ?? '—'} color="#f97316" />
            <MetricCard label="Wildcard Perms" value={r.wildcard ?? '—'} color="#ef4444" />
          </div>
          <DataTable<any>
            rows={r.findings || []}
            rowKey={(f: any) => f.id}
            columns={[
              { key: 'kind', header: 'Kind', render: (f: any) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{f.kind}</span> },
              { key: 'name', header: 'Name', render: (f: any) => <span style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 600 }}>{f.name}</span> },
              { key: 'subject', header: 'Subject', render: (f: any) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{f.subject}</span> },
              { key: 'namespace', header: 'Namespace', render: (f: any) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{f.namespace}</span> },
              { key: 'finding_type', header: 'Finding', render: (f: any) => <span style={{ fontSize: 11 }}>{f.finding_type?.replace(/_/g, ' ')}</span> },
              { key: 'severity', header: 'Severity', render: (f: any) => <SevBadge v={f.severity} /> },
              { key: 'description', header: 'Description', render: (f: any) => <span style={{ fontSize: 11, color: 'var(--text-2)', maxWidth: 280, display: 'block' }}>{f.description}</span> },
            ]}
          />
        </div>
      )}
      {sub === 'secrets' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <MetricCard label="Kubernetes Secrets" value={sc.total_secrets ?? '—'} color="var(--accent)" />
            <MetricCard label="Plaintext Secrets" value={sc.plaintext ?? '—'} color={sc.plaintext > 0 ? '#ef4444' : undefined} />
            <MetricCard label="Expired Secrets" value={sc.expired ?? '—'} color={sc.expired > 0 ? '#f97316' : undefined} />
            <MetricCard label="Exposed Secrets" value={sc.exposed ?? '—'} color={sc.exposed > 0 ? '#ef4444' : undefined} />
          </div>
          <SectionCard title="Secrets Providers">
            <DataTable<any>
              rows={sc.providers || []}
              rowKey={(p: any) => p.name}
              columns={[
                { key: 'name', header: 'Provider', render: (p: any) => <span style={{ fontWeight: 600 }}>{p.name}</span> },
                { key: 'count', header: 'Count', render: (p: any) => <span>{p.count}</span> },
                { key: 'status', header: 'Status', render: (p: any) => <SevBadge v={p.status === 'active' ? 'clean' : 'medium'} /> },
              ]}
            />
          </SectionCard>
        </div>
      )}
      {sub === 'network' && (
        <DataTable<any>
          rows={netpols}
          rowKey={(np: any) => np.id}
          columns={[
            { key: 'name', header: 'Name', render: (np: any) => <span style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 600 }}>{np.name}</span> },
            { key: 'namespace', header: 'Namespace', render: (np: any) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{np.namespace}</span> },
            { key: 'direction', header: 'Direction', render: (np: any) => <span style={{ fontSize: 11 }}>{np.direction}</span> },
            { key: 'pod_selector', header: 'Pod Selector', render: (np: any) => <code style={{ fontSize: 10, background: 'rgba(255,255,255,0.05)', padding: '1px 5px', borderRadius: 3 }}>{np.pod_selector}</code> },
            { key: 'peer', header: 'Peer', render: (np: any) => <span style={{ fontSize: 11 }}>{np.peer}</span> },
            { key: 'port', header: 'Port', render: (np: any) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{np.port}</span> },
            { key: 'status', header: 'Status', render: (np: any) => <SevBadge v={np.status === 'active' ? 'clean' : np.status === 'warn' ? 'medium' : np.status === 'missing' ? 'high' : 'clean'} /> },
          ]}
        />
      )}
      {sub === 'admission' && (
        <DataTable<any>
          rows={admission}
          rowKey={(v: any) => v.id}
          columns={[
            { key: 'workload', header: 'Workload', render: (v: any) => <span style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 600 }}>{v.workload}</span> },
            { key: 'kind', header: 'Kind', render: (v: any) => <span style={{ fontSize: 11 }}>{v.kind}</span> },
            { key: 'namespace', header: 'Namespace', render: (v: any) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{v.namespace}</span> },
            { key: 'violation_type', header: 'Violation', render: (v: any) => <span style={{ fontSize: 11 }}>{v.violation_type?.replace(/_/g, ' ')}</span> },
            { key: 'severity', header: 'Severity', render: (v: any) => <SevBadge v={v.severity} /> },
            { key: 'action', header: 'Action', render: (v: any) => <SevBadge v={v.action === 'denied' ? 'clean' : v.action === 'allowed' ? 'high' : 'medium'} /> },
            { key: 'time', header: 'Time', render: (v: any) => <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{v.created_at ? timeAgo(v.created_at) : '—'}</span> },
          ]}
        />
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
        <SectionCard title="Threat Actors" className="flex-1">
          <div style={{ minWidth: 260 }}>
            {(ti.threat_actors || []).map((a: any) => (
              <div key={a.actor} style={{ marginBottom: 12, paddingBottom: 12, borderBottom: '1px solid var(--border)' }}>
                <div style={{ fontWeight: 600, color: '#ef4444' }}>{a.actor}</div>
                <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>{a.target} · {a.campaigns} campaigns</div>
                <code style={{ fontSize: 10, background: 'rgba(255,255,255,0.05)', padding: '2px 6px', borderRadius: 3, display: 'inline-block', marginTop: 4 }}>{a.ttps}</code>
              </div>
            ))}
          </div>
        </SectionCard>
        <SectionCard title="Recent CVEs" className="flex-1">
          <div style={{ minWidth: 260 }}>
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
        </SectionCard>
        <SectionCard title="IOC Matches" className="flex-1">
          <div style={{ minWidth: 260 }}>
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
        </SectionCard>
      </div>
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        <SectionCard title="AI Security Analysis" className="flex-1">
          <div style={{ minWidth: 320 }}>
            <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
              {(['alert', 'image', 'ask'] as const).map(m => (
                <ActionButton key={m} variant={aiMode === m ? 'primary' : 'ghost'} onClick={() => setAiMode(m)} style={{ fontSize: 11, padding: '4px 10px', textTransform: 'capitalize' }}>{m}</ActionButton>
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
            <ActionButton variant="primary" style={{ marginTop: 10, width: '100%', justifyContent: 'center' }} onClick={doAI} loading={aiLoading} disabled={!aiInput.trim()}>
              {aiLoading ? 'Analyzing...' : 'Analyze with AI'}
            </ActionButton>
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
        </SectionCard>
        <SectionCard title="Security Timeline" className="flex-1">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, maxHeight: 400, overflowY: 'auto', minWidth: 320 }}>
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
        </SectionCard>
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
        <MetricCard label="Overall Compliance Score" value={`${c.overall_score ?? '—'}%`} color={c.overall_score >= 80 ? '#22c55e' : c.overall_score >= 60 ? '#f97316' : '#ef4444'} />
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
      <SectionCard title="Failed Controls">
        <DataTable<any>
          rows={c.failed_controls || []}
          rowKey={(fc: any, i: number) => i}
          columns={[
            { key: 'control', header: 'Control', render: (fc: any) => <span style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 600 }}>{fc.control}</span> },
            { key: 'title', header: 'Title', render: (fc: any) => <span style={{ fontSize: 12 }}>{fc.title}</span> },
            { key: 'framework', header: 'Framework', render: (fc: any) => <span style={{ fontSize: 11, color: 'var(--text-2)' }}>{fc.framework}</span> },
            { key: 'severity', header: 'Severity', render: (fc: any) => <SevBadge v={fc.severity} /> },
          ]}
        />
      </SectionCard>
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
        <MetricCard label="Total Pods" value={a.total_pods ?? '—'} color="var(--accent)" />
        <MetricCard label="Privileged Pods" value={a.privileged_pods ?? '—'} color={a.privileged_pods > 0 ? '#ef4444' : undefined} />
      </div>
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        <SectionCard title="Runtime Alerts — 14 Day Trend" className="flex-[2]">
          <div style={{ display: 'flex', alignItems: 'flex-end', gap: 3, height: 80, paddingBottom: 24, minWidth: 320 }}>
            {(a.runtime_alert_trend || []).map((p: any) => (
              <div key={p.date} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, height: '100%', justifyContent: 'flex-end' }}>
                <div style={{ width: '80%', background: p.count > 4 ? '#ef4444' : p.count > 2 ? '#f97316' : 'var(--accent)', borderRadius: 2, height: `${(p.count / maxAlerts) * 56 + 4}px`, minHeight: 4 }} />
                <span style={{ fontSize: 9, color: 'var(--text-3)' }}>{p.date?.slice(5)}</span>
              </div>
            ))}
          </div>
        </SectionCard>
        <SectionCard title="Alerts by Type" className="flex-1">
          <div style={{ minWidth: 260 }}>
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
        </SectionCard>
      </div>
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        <SectionCard title="Top Vulnerable Images" className="flex-1">
          <div style={{ minWidth: 300 }}>
            <DataTable<any>
              rows={a.top_vulnerable_images || []}
              rowKey={(img: any, i: number) => i}
              columns={[
                { key: 'image', header: 'Image', render: (img: any) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{img.image}</span> },
                { key: 'critical', header: 'Critical', render: (img: any) => <span style={{ color: '#ef4444', fontWeight: 700 }}>{img.cve_critical}</span> },
                { key: 'high', header: 'High', render: (img: any) => <span style={{ color: '#f97316', fontWeight: 700 }}>{img.cve_high}</span> },
                { key: 'risk', header: 'Risk', width: '120px', render: (img: any) => <RiskBar score={img.risk} /> },
              ]}
            />
          </div>
        </SectionCard>
        <SectionCard title="Namespace Risk" className="flex-1">
          <div style={{ minWidth: 300 }}>
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
        </SectionCard>
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
      <SectionCard title="Attack Path Visualization">
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
      </SectionCard>
      {vulns.length > 0 && (
        <SectionCard title="Vulnerability Summary">
          <DataTable<any>
            rows={vulns}
            rowKey={(v: any) => v.id}
            columns={[
              { key: 'image', header: 'Image', render: (v: any) => <span style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 600 }}>{v.image}</span> },
              { key: 'critical', header: 'Critical', render: (v: any) => <span style={{ color: '#ef4444', fontWeight: 700 }}>{v.cve_critical}</span> },
              { key: 'high', header: 'High', render: (v: any) => <span style={{ color: '#f97316', fontWeight: 700 }}>{v.cve_high}</span> },
              { key: 'medium', header: 'Medium', render: (v: any) => <span style={{ color: '#eab308' }}>{v.cve_medium}</span> },
              { key: 'low', header: 'Low', render: (v: any) => <span style={{ color: 'var(--text-3)' }}>{v.cve_low}</span> },
              { key: 'risk', header: 'Risk', width: '120px', render: (v: any) => <RiskBar score={v.risk_score} /> },
            ]}
          />
        </SectionCard>
      )}
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        <SectionCard title="Response Actions" className="flex-1">
          <div style={{ minWidth: 340 }}>
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
            <ActionButton variant="primary" style={{ width: '100%', justifyContent: 'center' }} onClick={doAction}>
              Execute: {ACTIONS.find(a => a.id === action)?.label}
            </ActionButton>
            {msg && <div style={{ marginTop: 12, padding: '10px 14px', background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.3)', borderRadius: 6, fontSize: 12, color: '#4ade80' }}>{msg}</div>}
          </div>
        </SectionCard>
        <SectionCard title="Generate Report" className="flex-1">
          <div style={{ minWidth: 320 }}>
            <select className="g-select" value={reportType} onChange={e => setReportType(e.target.value)} style={{ width: '100%', marginBottom: 12 }}>
              <option value="executive">Executive Summary</option>
              <option value="technical">Technical Deep Dive</option>
              <option value="compliance">Compliance Report</option>
              <option value="incident">Incident Response Report</option>
            </select>
            <ActionButton variant="primary" style={{ width: '100%', justifyContent: 'center' }} onClick={doReport} loading={reportLoading}>
              {reportLoading ? 'Generating...' : 'Generate with AI'}
            </ActionButton>
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
        </SectionCard>
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
    <RootLayout title="Container & Kubernetes Security"
      subtitle="Runtime protection, image scanning, RBAC analysis, and compliance for containerized workloads.">
    <div style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: 4 }}>
        <TabBar
          tabs={visibleTabs.map(t => ({ key: t, label: TAB_LABELS[t], icon: TAB_ICONS[t] }))}
          active={tab}
          onChange={t => setTab(t as Tab)}
        />
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
