'use client';

import { useState, useEffect, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { supplyChainAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import { MetricCard, SectionCard, DataTable, TabBar, ActionButton } from '@/components/design-system';
import {
  LayoutDashboard, GitBranch, Workflow, Package, KeyRound, Radar,
  ClipboardCheck, BarChart3, Siren, Check, X, AlertTriangle,
} from 'lucide-react';

type Tab = 'overview' | 'repos' | 'pipelines' | 'sbom' | 'secrets' | 'intelligence' | 'compliance' | 'analytics' | 'response';

const TAB_LABELS: Record<Tab, string> = {
  overview:     'Overview',
  repos:        'Repositories',
  pipelines:    'Pipelines & Artifacts',
  sbom:         'SBOM & Vulnerabilities',
  secrets:      'Secrets & Integrity',
  intelligence: 'Threat Intelligence',
  compliance:   'Compliance & Policies',
  analytics:    'Analytics',
  response:     'Response & Reports',
};

const TAB_ICONS: Record<Tab, any> = {
  overview: LayoutDashboard, repos: GitBranch, pipelines: Workflow, sbom: Package,
  secrets: KeyRound, intelligence: Radar, compliance: ClipboardCheck, analytics: BarChart3, response: Siren,
};

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  info:     '#3b82f6',
};

const RISK_COLOR = (score: number) =>
  score >= 80 ? '#ef4444' : score >= 60 ? '#f97316' : score >= 40 ? '#eab308' : '#22c55e';

function ScoreBar({ score, color }: { score: number; color?: string }) {
  const c = color ?? RISK_COLOR(score);
  return (
    <div style={{ background: 'var(--border)', borderRadius: 4, height: 6, width: '100%', overflow: 'hidden' }}>
      <div style={{ width: `${Math.min(score, 100)}%`, height: '100%', background: c, borderRadius: 4 }} />
    </div>
  );
}

function Badge({ label, color }: { label: string; color?: string }) {
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 4,
      fontSize: 11, fontWeight: 600, background: (color ?? '#64748b') + '22',
      color: color ?? '#64748b', textTransform: 'uppercase', letterSpacing: '0.06em',
    }}>{label}</span>
  );
}

function YesNo({ ok, warn }: { ok: boolean; warn?: boolean }) {
  if (ok) return <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#22c55e' }}><Check style={{ width: 13, height: 13 }} /> Yes</span>;
  if (warn) return <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#ef4444' }}><AlertTriangle style={{ width: 12, height: 12 }} /> Yes</span>;
  return <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#f97316' }}><X style={{ width: 13, height: 13 }} /> No</span>;
}

function Dot({ on }: { on: boolean }) {
  return <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', marginRight: 6, background: on ? '#22c55e' : '#ef4444' }} />;
}

// ─── Overview Tab ────────────────────────────────────────────────────────────
function OverviewTab({ dash }: { dash: any }) {
  if (!dash) return <div style={{ color: 'var(--text-3)', padding: 32 }}>Loading dashboard…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>
        <MetricCard label="Repositories" value={dash.repositories} />
        <MetricCard label="Dependencies" value={dash.dependencies} />
        <MetricCard label="Critical CVEs" value={dash.critical_cves} color="#ef4444" />
        <MetricCard label="High-Risk Pkgs" value={dash.high_risk_packages} color="#f97316" />
        <MetricCard label="Risk Score" value={`${dash.risk_score}%`} color={RISK_COLOR(dash.risk_score)} />
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>
        <MetricCard label="SBOMs" value={dash.sboms} color="var(--accent)" sub="Generated" />
        <MetricCard label="Pipelines" value={dash.build_pipelines} sub="Monitored" />
        <MetricCard label="Signed Artifacts" value={`${dash.signed_artifacts}/${dash.total_artifacts}`} color="#22c55e" />
        <MetricCard label="Open Secrets" value={dash.secret_findings} color="#ef4444" sub="Detected in code" />
        <MetricCard label="SLSA Level" value="L1" color="#f97316" sub="Target: L3" />
      </div>
      <SectionCard title="Overall Risk Score">
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{ fontSize: 48, fontWeight: 800, color: RISK_COLOR(dash.risk_score) }}>{dash.risk_score}</div>
          <div style={{ flex: 1 }}>
            <ScoreBar score={dash.risk_score} />
            <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 8 }}>
              Score considers CVE severity, secret exposure, pipeline posture, artifact signing, and SBOM coverage.
            </div>
          </div>
        </div>
      </SectionCard>
    </div>
  );
}

// ─── Repositories Tab ────────────────────────────────────────────────────────
function ReposTab() {
  const [repos, setRepos] = useState<any[]>([]);
  const [deps, setDeps] = useState<any[]>([]);
  const [sub, setSub] = useState<'repos' | 'deps'>('repos');
  const [ecosystem, setEcosystem] = useState('');
  const [hasCVEs, setHasCVEs] = useState(false);

  useEffect(() => {
    supplyChainAPI.getRepositories().then(r => setRepos(r.data ?? []));
  }, []);

  useEffect(() => {
    if (sub === 'deps') {
      supplyChainAPI.getDependencies({ ecosystem: ecosystem || undefined, has_cves: hasCVEs || undefined })
        .then(r => setDeps(r.data ?? []));
    }
  }, [sub, ecosystem, hasCVEs]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 8 }}>
        {(['repos', 'deps'] as const).map(s => (
          <ActionButton key={s} variant={sub === s ? 'primary' : 'ghost'} onClick={() => setSub(s)}>
            {s === 'repos' ? 'Repository Inventory' : 'Dependency Management'}
          </ActionButton>
        ))}
      </div>

      {sub === 'repos' && (
        <DataTable<any>
          rows={repos}
          rowKey={(r: any) => r.id}
          columns={[
            { key: 'repo', header: 'Repository', render: (r: any) => <span style={{ fontWeight: 600 }}>{r.owner}/{r.name}</span> },
            { key: 'platform', header: 'Platform', render: (r: any) => <Badge label={r.platform} color="#3b82f6" /> },
            { key: 'language', header: 'Language', render: (r: any) => <Badge label={r.language} /> },
            { key: 'branch', header: 'Branch', render: (r: any) => <code style={{ fontSize: 12 }}>{r.default_branch}</code> },
            { key: 'contributors', header: 'Contributors', render: (r: any) => <span>{r.contributor_count}</span> },
            { key: 'deps', header: 'Dependencies', render: (r: any) => <span>{r.dep_count}</span> },
            { key: 'risk', header: 'Risk', render: (r: any) => (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ color: RISK_COLOR(r.risk_score), fontWeight: 700, fontSize: 13, width: 30 }}>{r.risk_score}</span>
                <div style={{ width: 60 }}><ScoreBar score={r.risk_score} /></div>
              </div>
            ) },
            { key: 'last_commit', header: 'Last Commit', render: (r: any) => <span style={{ color: 'var(--text-3)' }}>{timeAgo(r.last_commit)}</span> },
          ]}
        />
      )}

      {sub === 'deps' && (
        <>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <select className="g-select" style={{ width: 160, flexShrink: 0 }} value={ecosystem} onChange={e => setEcosystem(e.target.value)}>
              <option value="">All Ecosystems</option>
              {['npm', 'pip', 'maven', 'go', 'cargo', 'gradle', 'nuget', 'rubygems', 'composer'].map(e => (
                <option key={e} value={e}>{e}</option>
              ))}
            </select>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
              <input type="checkbox" checked={hasCVEs} onChange={e => setHasCVEs(e.target.checked)} />
              Has CVEs only
            </label>
          </div>
          <DataTable<any>
            rows={deps}
            rowKey={(d: any) => d.id}
            columns={[
              { key: 'package_name', header: 'Package', render: (d: any) => <span style={{ fontWeight: 600 }}>{d.package_name}</span> },
              { key: 'ecosystem', header: 'Ecosystem', render: (d: any) => <Badge label={d.ecosystem} color="#6366f1" /> },
              { key: 'version', header: 'Version', render: (d: any) => <code style={{ fontSize: 12 }}>{d.version}</code> },
              { key: 'latest', header: 'Latest', render: (d: any) => (
                <span>
                  <code style={{ fontSize: 12, color: d.is_outdated ? '#f97316' : 'var(--text-2)' }}>{d.latest_version}</code>
                  {d.is_outdated && <span style={{ fontSize: 10, color: '#f97316', marginLeft: 4 }}>outdated</span>}
                </span>
              ) },
              { key: 'license', header: 'License', render: (d: any) => <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{d.license}</span> },
              { key: 'cves', header: 'CVEs', render: (d: any) => d.cve_count > 0
                ? <span style={{ color: '#ef4444', fontWeight: 700 }}>{d.cve_count}</span>
                : <span style={{ color: 'var(--text-3)' }}>0</span> },
              { key: 'type', header: 'Type', render: (d: any) => <Badge label={d.is_direct ? 'direct' : 'transitive'} color={d.is_direct ? '#22c55e' : '#64748b'} /> },
              { key: 'risk', header: 'Risk', render: (d: any) => <span style={{ color: RISK_COLOR(d.risk_score), fontWeight: 700 }}>{d.risk_score}</span> },
            ]}
          />
        </>
      )}
    </div>
  );
}

// ─── Pipelines & Artifacts Tab ───────────────────────────────────────────────
function PipelinesTab() {
  const [pipelines, setPipelines] = useState<any[]>([]);
  const [artifacts, setArtifacts] = useState<any[]>([]);
  const [provenance, setProvenance] = useState<any>(null);
  const [sub, setSub] = useState<'pipelines' | 'artifacts' | 'provenance'>('pipelines');

  useEffect(() => {
    supplyChainAPI.getPipelines().then(r => setPipelines(r.data ?? []));
    supplyChainAPI.getArtifacts().then(r => setArtifacts(r.data ?? []));
    supplyChainAPI.getProvenance().then(r => setProvenance(r.data));
  }, []);

  const PLATFORM_COLORS: Record<string, string> = {
    github_actions: '#3b82f6', jenkins: '#f97316', gitlab_ci: '#f97316',
    azure_pipelines: '#0ea5e9', circleci: '#22c55e', argocd: '#a855f7',
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 8 }}>
        {(['pipelines', 'artifacts', 'provenance'] as const).map(s => (
          <ActionButton key={s} variant={sub === s ? 'primary' : 'ghost'} onClick={() => setSub(s)}>
            {s === 'pipelines' ? 'Build Pipelines' : s === 'artifacts' ? 'Artifact Security' : 'Build Provenance'}
          </ActionButton>
        ))}
      </div>

      {sub === 'pipelines' && (
        <DataTable<any>
          rows={pipelines}
          rowKey={(p: any) => p.id}
          columns={[
            { key: 'name', header: 'Pipeline', render: (p: any) => <span style={{ fontWeight: 600 }}>{p.name}</span> },
            { key: 'platform', header: 'Platform', render: (p: any) => <Badge label={p.platform} color={PLATFORM_COLORS[p.platform] ?? '#64748b'} /> },
            { key: 'status', header: 'Status', render: (p: any) => <Badge label={p.status} color={p.status === 'passing' ? '#22c55e' : '#ef4444'} /> },
            { key: 'secrets', header: 'Secrets in CI', render: (p: any) => p.has_secrets
              ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#ef4444' }}><AlertTriangle style={{ width: 12, height: 12 }} /> Yes</span>
              : <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#22c55e' }}><Check style={{ width: 13, height: 13 }} /> No</span> },
            { key: 'untrusted', header: 'Untrusted Actions', render: (p: any) => p.has_untrusted_actions
              ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#ef4444' }}><AlertTriangle style={{ width: 12, height: 12 }} /> Yes</span>
              : <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#22c55e' }}><Check style={{ width: 13, height: 13 }} /> No</span> },
            { key: 'pinned', header: 'Pinned Versions', render: (p: any) => <YesNo ok={p.has_pinned_versions} /> },
            { key: 'risk', header: 'Risk', render: (p: any) => <span style={{ color: RISK_COLOR(p.risk_score), fontWeight: 700 }}>{p.risk_score}</span> },
            { key: 'last_run', header: 'Last Run', render: (p: any) => <span style={{ color: 'var(--text-3)' }}>{timeAgo(p.last_run)}</span> },
          ]}
        />
      )}

      {sub === 'artifacts' && (
        <DataTable<any>
          rows={artifacts}
          rowKey={(a: any) => a.id}
          columns={[
            { key: 'name', header: 'Artifact', render: (a: any) => <span style={{ fontWeight: 600 }}>{a.name}</span> },
            { key: 'type', header: 'Type', render: (a: any) => <Badge label={a.artifact_type} color="#6366f1" /> },
            { key: 'version', header: 'Version', render: (a: any) => <code style={{ fontSize: 12 }}>{a.version}</code> },
            { key: 'signed', header: 'Signed', render: (a: any) => <YesNo ok={a.is_signed} /> },
            { key: 'sbom', header: 'SBOM', render: (a: any) => <YesNo ok={a.has_sbom} /> },
            { key: 'provenance', header: 'Provenance', render: (a: any) => <YesNo ok={a.provenance_available} /> },
            { key: 'hash', header: 'Hash', render: (a: any) => <code style={{ fontSize: 10, color: 'var(--text-3)' }}>{a.artifact_hash ? a.artifact_hash.slice(0, 20) + '…' : '—'}</code> },
            { key: 'risk', header: 'Risk', render: (a: any) => <span style={{ color: RISK_COLOR(a.risk_score), fontWeight: 700 }}>{a.risk_score}</span> },
          ]}
        />
      )}

      {sub === 'provenance' && provenance && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>
            <MetricCard label="SLSA Level" value={`L${provenance.slsa_level}`} color="#f97316" sub="Target: L3" />
            <MetricCard label="Provenance Coverage" value={`${provenance.provenance_rate}%`} color={provenance.provenance_rate > 70 ? '#22c55e' : '#f97316'} />
            <MetricCard label="Total Builds" value={provenance.builds?.length ?? 0} />
          </div>
          <DataTable<any>
            rows={provenance.builds ?? []}
            rowKey={(b: any, i: number) => i}
            columns={[
              { key: 'artifact', header: 'Artifact', render: (b: any) => <span style={{ fontWeight: 600 }}>{b.artifact}</span> },
              { key: 'builder', header: 'Builder', render: (b: any) => <Badge label={b.builder} color="#3b82f6" /> },
              { key: 'source_commit', header: 'Source Commit', render: (b: any) => <code style={{ fontSize: 12 }}>{b.source_commit}</code> },
              { key: 'signed', header: 'Signed', render: (b: any) => <YesNo ok={b.signed} /> },
              { key: 'slsa_level', header: 'SLSA Level', render: (b: any) => <Badge label={`L${b.slsa_level}`} color={b.slsa_level >= 2 ? '#22c55e' : '#ef4444'} /> },
              { key: 'attestation', header: 'Attestation', render: (b: any) => <span style={{ color: 'var(--text-3)' }}>{b.attestation || '—'}</span> },
              { key: 'built', header: 'Built', render: (b: any) => <span style={{ color: 'var(--text-3)' }}>{timeAgo(b.build_time)}</span> },
            ]}
          />
        </div>
      )}
    </div>
  );
}

// ─── SBOM & Vulnerabilities Tab ──────────────────────────────────────────────
function SBOMTab() {
  const [sboms, setSBOMs] = useState<any[]>([]);
  const [vulnData, setVulnData] = useState<any>(null);
  const [severity, setSeverity] = useState('');
  const [kevOnly, setKevOnly] = useState(false);
  const [sub, setSub] = useState<'sboms' | 'vulns'>('sboms');

  useEffect(() => {
    supplyChainAPI.getSBOMs().then(r => setSBOMs(r.data ?? []));
  }, []);

  useEffect(() => {
    if (sub === 'vulns') {
      supplyChainAPI.getVulnerabilities({ severity: severity || undefined, kev: kevOnly || undefined })
        .then(r => setVulnData(r.data));
    }
  }, [sub, severity, kevOnly]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 8 }}>
        {(['sboms', 'vulns'] as const).map(s => (
          <ActionButton key={s} variant={sub === s ? 'primary' : 'ghost'} onClick={() => setSub(s)}>
            {s === 'sboms' ? 'SBOM Management' : 'Vulnerability Management'}
          </ActionButton>
        ))}
      </div>

      {sub === 'sboms' && (
        <DataTable<any>
          rows={sboms}
          rowKey={(s: any) => s.id}
          columns={[
            { key: 'artifact_name', header: 'Artifact', render: (s: any) => <span style={{ fontWeight: 600 }}>{s.artifact_name}</span> },
            { key: 'format', header: 'Format', render: (s: any) => <Badge label={s.format} color="#6366f1" /> },
            { key: 'components', header: 'Components', render: (s: any) => <span>{s.component_count}</span> },
            { key: 'licenses', header: 'Licenses', render: (s: any) => <span>{s.license_count}</span> },
            { key: 'suppliers', header: 'Suppliers', render: (s: any) => <span>{s.supplier_count}</span> },
            { key: 'has_vulns', header: 'Has Vulns', render: (s: any) => s.has_vulnerabilities
              ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#ef4444' }}><AlertTriangle style={{ width: 12, height: 12 }} /> Yes</span>
              : <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#22c55e' }}><Check style={{ width: 13, height: 13 }} /> Clean</span> },
            { key: 'generated', header: 'Generated', render: (s: any) => <span style={{ color: 'var(--text-3)' }}>{timeAgo(s.generated_at)}</span> },
          ]}
        />
      )}

      {sub === 'vulns' && (
        <>
          {vulnData && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>
              <MetricCard label="Critical" value={vulnData.critical} color="#ef4444" />
              <MetricCard label="High" value={vulnData.high} color="#f97316" />
              <MetricCard label="KEV (CISA)" value={vulnData.kev} color="#dc2626" sub="Known exploited" />
              <MetricCard label="Exploited" value={vulnData.exploited} color="#f97316" sub="Active exploitation" />
            </div>
          )}
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <select className="g-select" style={{ width: 160, flexShrink: 0 }} value={severity} onChange={e => setSeverity(e.target.value)}>
              <option value="">All Severities</option>
              {['critical', 'high', 'medium', 'low'].map(s => (
                <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
              ))}
            </select>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
              <input type="checkbox" checked={kevOnly} onChange={e => setKevOnly(e.target.checked)} />
              KEV only
            </label>
          </div>
          <DataTable<any>
            rows={vulnData?.vulns ?? []}
            rowKey={(v: any) => v.id}
            columns={[
              { key: 'cve_id', header: 'CVE', render: (v: any) => <code style={{ fontSize: 12, color: 'var(--accent)' }}>{v.cve_id}</code> },
              { key: 'description', header: 'Description', render: (v: any) => <span style={{ fontSize: 12 }}>{v.description?.slice(0, 40)}…</span> },
              { key: 'cvss', header: 'CVSS', render: (v: any) => <span style={{ color: v.cvss >= 9 ? '#ef4444' : v.cvss >= 7 ? '#f97316' : '#eab308', fontWeight: 700 }}>{v.cvss.toFixed(1)}</span> },
              { key: 'epss', header: 'EPSS', render: (v: any) => <span style={{ fontSize: 12 }}>{(v.epss * 100).toFixed(1)}%</span> },
              { key: 'kev', header: 'KEV', render: (v: any) => v.is_kev ? <Badge label="KEV" color="#dc2626" /> : null },
              { key: 'exploit', header: 'Has Exploit', render: (v: any) => v.has_exploit
                ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#ef4444' }}><AlertTriangle style={{ width: 12, height: 12 }} /> Yes</span>
                : <span style={{ color: 'var(--text-3)' }}>—</span> },
              { key: 'fix', header: 'Fix', render: (v: any) => <code style={{ fontSize: 11 }}>{v.fix_version || '—'}</code> },
              { key: 'severity', header: 'Severity', render: (v: any) => <Badge label={v.severity} color={SEV_COLOR[v.severity]} /> },
              { key: 'affected', header: 'Affected', render: (v: any) => <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{v.affected_projects}</span> },
            ]}
          />
        </>
      )}
    </div>
  );
}

// ─── Secrets & Integrity Tab ─────────────────────────────────────────────────
function SecretsTab() {
  const [secretData, setSecretData] = useState<any>(null);
  const [integrity, setIntegrity] = useState<any>(null);
  const [sub, setSub] = useState<'secrets' | 'integrity'>('secrets');

  useEffect(() => {
    supplyChainAPI.getSecrets().then(r => setSecretData(r.data));
    supplyChainAPI.getCodeIntegrity().then(r => setIntegrity(r.data));
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 8 }}>
        {(['secrets', 'integrity'] as const).map(s => (
          <ActionButton key={s} variant={sub === s ? 'primary' : 'ghost'} onClick={() => setSub(s)}>
            {s === 'secrets' ? 'Secret Detection' : 'Code Integrity'}
          </ActionButton>
        ))}
      </div>

      {sub === 'secrets' && secretData && (
        <>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>
            <MetricCard label="Total Findings" value={secretData.total} />
            <MetricCard label="Open" value={secretData.open} color="#ef4444" />
            <MetricCard label="AWS Keys" value={secretData.aws_keys} color="#f97316" />
            <MetricCard label="API Keys" value={secretData.api_keys} color="#eab308" />
          </div>
          <DataTable<any>
            rows={secretData.secrets ?? []}
            rowKey={(s: any) => s.id}
            columns={[
              { key: 'type', header: 'Type', render: (s: any) => <Badge label={s.secret_type.replace(/_/g, ' ')} color="#ef4444" /> },
              { key: 'file_path', header: 'File Path', render: (s: any) => <code style={{ fontSize: 12 }}>{s.file_path}</code> },
              { key: 'commit', header: 'Commit', render: (s: any) => <code style={{ fontSize: 11, color: 'var(--text-3)' }}>{s.commit_hash}</code> },
              { key: 'severity', header: 'Severity', render: (s: any) => <Badge label={s.severity} color={SEV_COLOR[s.severity]} /> },
              { key: 'status', header: 'Status', render: (s: any) => <Badge label={s.status} color={s.status === 'open' ? '#ef4444' : '#22c55e'} /> },
              { key: 'found', header: 'Found', render: (s: any) => <span style={{ color: 'var(--text-3)' }}>{timeAgo(s.created_at)}</span> },
            ]}
          />
        </>
      )}

      {sub === 'integrity' && integrity && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>
            <MetricCard label="Signed Commits" value={`${integrity.signed_commits_rate}%`} color={integrity.signed_commits_rate >= 80 ? '#22c55e' : '#f97316'} />
            <MetricCard label="Signed Tags" value={`${integrity.signed_tags_rate}%`} color={integrity.signed_tags_rate >= 80 ? '#22c55e' : '#f97316'} />
            <MetricCard label="Protected Branches" value={integrity.protected_branches} color="#22c55e" />
            <MetricCard label="Force Push Incidents" value={integrity.force_push_incidents} color={integrity.force_push_incidents > 0 ? '#ef4444' : '#22c55e'} />
          </div>
          <DataTable<any>
            rows={integrity.findings ?? []}
            rowKey={(f: any, i: number) => i}
            columns={[
              { key: 'repo', header: 'Repository', render: (f: any) => <span style={{ fontWeight: 600 }}>{f.repo}</span> },
              { key: 'finding', header: 'Finding', render: (f: any) => <span>{f.finding}</span> },
              { key: 'severity', header: 'Severity', render: (f: any) => <Badge label={f.severity} color={SEV_COLOR[f.severity]} /> },
              { key: 'count', header: 'Count', render: (f: any) => <span>{f.count}</span> },
            ]}
          />
        </div>
      )}
    </div>
  );
}

// ─── Intelligence Tab ────────────────────────────────────────────────────────
function IntelligenceTab() {
  const [intel, setIntel] = useState<any>(null);
  const [thirdParty, setThirdParty] = useState<any>(null);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [sub, setSub] = useState<'intel' | 'third-party' | 'timeline' | 'ai'>('intel');
  const [aiMode, setAIMode] = useState<'dependency' | 'pipeline' | 'ask'>('ask');
  const [aiInput, setAIInput] = useState('');
  const [aiResult, setAIResult] = useState<any>(null);
  const [aiLoading, setAILoading] = useState(false);

  useEffect(() => {
    supplyChainAPI.getThreatIntel().then(r => setIntel(r.data));
    supplyChainAPI.getThirdParty().then(r => setThirdParty(r.data));
    supplyChainAPI.getTimeline().then(r => setTimeline(r.data ?? []));
  }, []);

  const runAI = async () => {
    if (!aiInput.trim()) return;
    setAILoading(true);
    try {
      const r = await supplyChainAPI.analyzeAI({ mode: aiMode, content: aiInput, dep: aiInput, build: aiInput });
      setAIResult(r.data);
    } catch { setAIResult({ error: 'AI analysis failed' }); }
    finally { setAILoading(false); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 8 }}>
        {(['intel', 'third-party', 'timeline', 'ai'] as const).map(s => (
          <ActionButton key={s} variant={sub === s ? 'primary' : 'ghost'} onClick={() => setSub(s)}>
            {s === 'intel' ? 'Threat Intelligence' : s === 'third-party' ? 'Third-Party Risk' : s === 'timeline' ? 'Timeline' : 'AI Analysis'}
          </ActionButton>
        ))}
      </div>

      {sub === 'intel' && intel && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <SectionCard title={<span style={{ color: '#ef4444' }}>Malicious Packages Detected</span>}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {(intel.malicious_packages ?? []).map((p: any, i: number) => (
                <div key={i} style={{ padding: 12, background: 'var(--border)', borderRadius: 6, borderLeft: '3px solid #ef4444' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontWeight: 700, color: '#ef4444' }}>{p.name}@{p.version}</span>
                    <Badge label={p.ecosystem} color="#6366f1" />
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text-2)' }}>{p.threat}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>Discovered: {p.discovered} · {p.downloads.toLocaleString()} downloads</div>
                </div>
              ))}
            </div>
          </SectionCard>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <SectionCard title="Active Campaigns">
              {(intel.campaigns ?? []).map((c: any, i: number) => (
                <div key={i} style={{ padding: 10, background: 'var(--border)', borderRadius: 6, marginBottom: 8 }}>
                  <div style={{ fontWeight: 600 }}>{c.name}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-3)' }}>{c.packages_affected} packages · {c.ecosystems} · Since {c.first_seen}</div>
                </div>
              ))}
            </SectionCard>
            <SectionCard title="IOC Matches in Dependencies">
              {(intel.ioc_matches ?? []).map((m: any, i: number) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
                  <div>
                    <Badge label={m.type} color="#f97316" />
                    <span style={{ marginLeft: 8, fontSize: 12, fontFamily: 'monospace' }}>{m.value}</span>
                  </div>
                  <span style={{ fontSize: 12, color: '#ef4444' }}>{m.hits} hits</span>
                </div>
              ))}
            </SectionCard>
          </div>
        </div>
      )}

      {sub === 'third-party' && thirdParty && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <SectionCard title="Third-Party Package Risk">
            <DataTable<any>
              rows={thirdParty.packages ?? []}
              rowKey={(p: any, i: number) => i}
              columns={[
                { key: 'name', header: 'Package', render: (p: any) => <span style={{ fontWeight: 600 }}>{p.name}</span> },
                { key: 'ecosystem', header: 'Ecosystem', render: (p: any) => <Badge label={p.ecosystem} color="#6366f1" /> },
                { key: 'version', header: 'Version', render: (p: any) => <code style={{ fontSize: 12 }}>{p.version}</code> },
                { key: 'trust', header: 'Trust Score', render: (p: any) => (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ color: RISK_COLOR(100 - p.trust_score), fontWeight: 700, width: 28 }}>{p.trust_score}</span>
                    <div style={{ width: 60 }}><ScoreBar score={p.trust_score} color={p.trust_score >= 70 ? '#22c55e' : p.trust_score >= 40 ? '#f97316' : '#ef4444'} /></div>
                  </div>
                ) },
                { key: 'maintenance', header: 'Maintenance', render: (p: any) => <Badge label={p.maintenance} color={p.maintenance === 'active' ? '#22c55e' : p.maintenance === 'abandoned' ? '#ef4444' : p.maintenance === 'compromised' || p.maintenance === 'malicious' ? '#dc2626' : '#f97316'} /> },
                { key: 'advisories', header: 'Advisories', render: (p: any) => p.advisories > 0 ? <span style={{ color: '#ef4444', fontWeight: 700 }}>{p.advisories}</span> : <span style={{ color: '#22c55e' }}>0</span> },
                { key: 'downloads', header: 'Weekly Downloads', render: (p: any) => <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{p.downloads_weekly.toLocaleString()}</span> },
              ]}
            />
          </SectionCard>
          <SectionCard title="CI/CD Plugin Assessment">
            <DataTable<any>
              rows={thirdParty.ci_plugins ?? []}
              rowKey={(p: any, i: number) => i}
              columns={[
                { key: 'name', header: 'Plugin', render: (p: any) => <span style={{ fontWeight: 600, fontFamily: 'monospace', fontSize: 13 }}>{p.name}</span> },
                { key: 'version', header: 'Version', render: (p: any) => <code>{p.version}</code> },
                { key: 'pinned', header: 'Pinned to SHA', render: (p: any) => <YesNo ok={p.is_pinned} /> },
                { key: 'trusted', header: 'Trusted', render: (p: any) => p.trusted
                  ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#22c55e' }}><Check style={{ width: 13, height: 13 }} /> Yes</span>
                  : <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#f97316' }}><AlertTriangle style={{ width: 12, height: 12 }} /> Unverified</span> },
                { key: 'sha', header: 'SHA', render: (p: any) => <code style={{ fontSize: 11, color: 'var(--text-3)' }}>{p.sha ? p.sha.slice(0, 16) + '…' : '—'}</code> },
              ]}
            />
          </SectionCard>
        </div>
      )}

      {sub === 'timeline' && (
        <DataTable<any>
          rows={timeline}
          rowKey={(e: any) => e.id}
          columns={[
            { key: 'event_type', header: 'Event', render: (e: any) => <Badge label={e.event_type.replace(/_/g, ' ')} color="#6366f1" /> },
            { key: 'target', header: 'Target', render: (e: any) => <code style={{ fontSize: 12 }}>{e.target}</code> },
            { key: 'severity', header: 'Severity', render: (e: any) => <Badge label={e.severity} color={SEV_COLOR[e.severity]} /> },
            { key: 'detail', header: 'Detail', render: (e: any) => <span style={{ fontSize: 12 }}>{e.detail}</span> },
            { key: 'time', header: 'Time', render: (e: any) => <span style={{ color: 'var(--text-3)' }}>{timeAgo(e.created_at)}</span> },
          ]}
        />
      )}

      {sub === 'ai' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', gap: 8 }}>
            {(['dependency', 'pipeline', 'ask'] as const).map(m => (
              <ActionButton key={m} variant={aiMode === m ? 'primary' : 'ghost'} onClick={() => setAIMode(m)}>
                {m === 'dependency' ? 'Analyze Dependency' : m === 'pipeline' ? 'Analyze Pipeline' : 'Ask AI'}
              </ActionButton>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <textarea
              className="g-input"
              rows={4}
              style={{ flex: 1, resize: 'vertical', fontFamily: 'monospace', fontSize: 13 }}
              placeholder={aiMode === 'dependency' ? 'Enter dependency name/version (e.g. log4j-core:2.14.1)' : aiMode === 'pipeline' ? 'Paste pipeline YAML configuration' : 'Ask about supply chain security…'}
              value={aiInput}
              onChange={e => setAIInput(e.target.value)}
            />
            <ActionButton variant="primary" onClick={runAI} loading={aiLoading} style={{ alignSelf: 'flex-start' }}>
              {aiLoading ? 'Analyzing…' : 'Analyze'}
            </ActionButton>
          </div>
          {aiResult && (
            <div className="g-card" style={{ padding: 20 }}>
              {aiResult.verdict && (
                <div style={{ marginBottom: 12 }}>
                  <span style={{ fontWeight: 700, color: aiResult.verdict === 'malicious' || aiResult.verdict === 'risky' ? '#ef4444' : '#22c55e', fontSize: 18 }}>
                    {aiResult.verdict?.toUpperCase()}
                  </span>
                  {aiResult.confidence && <span style={{ marginLeft: 8, color: 'var(--text-3)', fontSize: 13 }}>Confidence: {aiResult.confidence}%</span>}
                </div>
              )}
              {aiResult.explanation && <p style={{ fontSize: 14, lineHeight: 1.6, marginBottom: 12 }}>{aiResult.explanation}</p>}
              {aiResult.risk_factors && (
                <div style={{ marginBottom: 12 }}>
                  <div style={{ fontWeight: 600, marginBottom: 6, fontSize: 13 }}>Risk Factors</div>
                  <ul style={{ margin: 0, paddingLeft: 20 }}>
                    {aiResult.risk_factors.map((f: string, i: number) => <li key={i} style={{ fontSize: 13, color: '#ef4444', marginBottom: 4 }}>{f}</li>)}
                  </ul>
                </div>
              )}
              {aiResult.recommended_actions && (
                <div>
                  <div style={{ fontWeight: 600, marginBottom: 6, fontSize: 13 }}>Recommended Actions</div>
                  <ul style={{ margin: 0, paddingLeft: 20 }}>
                    {aiResult.recommended_actions.map((a: string, i: number) => <li key={i} style={{ fontSize: 13, color: '#22c55e', marginBottom: 4 }}>{a}</li>)}
                  </ul>
                </div>
              )}
              {aiResult.answer && <p style={{ fontSize: 14, lineHeight: 1.6 }}>{aiResult.answer}</p>}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Compliance & Policies Tab ───────────────────────────────────────────────
function ComplianceTab() {
  const [compliance, setCompliance] = useState<any>(null);
  const [policies, setPolicies] = useState<any[]>([]);
  const [sub, setSub] = useState<'compliance' | 'policies'>('compliance');
  const [policyForm, setPolicyForm] = useState({ name: '', rule_type: '', action: 'block', description: '' });
  const [saving, setSaving] = useState(false);

  const load = () => {
    supplyChainAPI.getCompliance().then(r => setCompliance(r.data));
    supplyChainAPI.getPolicies().then(r => setPolicies(r.data ?? []));
  };
  useEffect(load, []);

  const savePolicy = async () => {
    if (!policyForm.name.trim()) return;
    setSaving(true);
    try { await supplyChainAPI.createPolicy(policyForm); load(); setPolicyForm({ name: '', rule_type: '', action: 'block', description: '' }); }
    finally { setSaving(false); }
  };

  const togglePolicy = async (id: number, enabled: boolean) => {
    await supplyChainAPI.updatePolicy(id, { is_enabled: !enabled });
    load();
  };

  const deletePolicy = async (id: number) => {
    await supplyChainAPI.deletePolicy(id);
    load();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 8 }}>
        {(['compliance', 'policies'] as const).map(s => (
          <ActionButton key={s} variant={sub === s ? 'primary' : 'ghost'} onClick={() => setSub(s)}>
            {s === 'compliance' ? 'Compliance Frameworks' : 'Policy Engine'}
          </ActionButton>
        ))}
      </div>

      {sub === 'compliance' && compliance && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <MetricCard label="Overall Compliance Score" value={`${compliance.overall_score}%`} color={compliance.overall_score >= 70 ? '#22c55e' : compliance.overall_score >= 50 ? '#f97316' : '#ef4444'} />
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
            {(compliance.frameworks ?? []).map((f: any, i: number) => (
              <div key={i} className="g-card" style={{ padding: 16 }}>
                <div style={{ fontWeight: 600, marginBottom: 4 }}>{f.name}</div>
                {f.version && <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 8 }}>v{f.version}</div>}
                {f.level !== undefined && <div style={{ fontSize: 12, marginBottom: 6 }}>Level {f.level} / Target L{f.target_level}</div>}
                <div style={{ fontSize: 24, fontWeight: 700, color: f.score >= 70 ? '#22c55e' : f.score >= 50 ? '#f97316' : '#ef4444', marginBottom: 8 }}>{f.score}%</div>
                <ScoreBar score={f.score} color={f.score >= 70 ? '#22c55e' : f.score >= 50 ? '#f97316' : '#ef4444'} />
                <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 6 }}>{f.passed} passed · {f.failed} failed · {f.total} total</div>
              </div>
            ))}
          </div>
          <SectionCard title="Failed Controls">
            <DataTable<any>
              rows={compliance.failed_controls ?? []}
              rowKey={(c: any, i: number) => i}
              columns={[
                { key: 'control', header: 'Control', render: (c: any) => <code style={{ fontSize: 12 }}>{c.control}</code> },
                { key: 'title', header: 'Title', render: (c: any) => <span style={{ fontSize: 13 }}>{c.title}</span> },
                { key: 'framework', header: 'Framework', render: (c: any) => <Badge label={c.framework} color="#6366f1" /> },
                { key: 'severity', header: 'Severity', render: (c: any) => <Badge label={c.severity} color={SEV_COLOR[c.severity]} /> },
              ]}
            />
          </SectionCard>
        </div>
      )}

      {sub === 'policies' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <SectionCard title="New Policy">
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 12 }}>
              <input className="g-input" placeholder="Policy name*" value={policyForm.name} onChange={e => setPolicyForm({ ...policyForm, name: e.target.value })} />
              <select className="g-select" value={policyForm.rule_type} onChange={e => setPolicyForm({ ...policyForm, rule_type: e.target.value })}>
                <option value="">Rule Type</option>
                {['vulnerability', 'sbom', 'pipeline', 'secret', 'signing', 'license', 'dependency'].map(t => <option key={t} value={t}>{t}</option>)}
              </select>
              <select className="g-select" value={policyForm.action} onChange={e => setPolicyForm({ ...policyForm, action: e.target.value })}>
                <option value="block">Block</option>
                <option value="warn">Warn</option>
                <option value="audit">Audit Only</option>
              </select>
            </div>
            <div style={{ display: 'flex', gap: 12 }}>
              <input className="g-input" style={{ flex: 1 }} placeholder="Description" value={policyForm.description} onChange={e => setPolicyForm({ ...policyForm, description: e.target.value })} />
              <ActionButton variant="primary" onClick={savePolicy} loading={saving}>{saving ? 'Saving…' : 'Create Policy'}</ActionButton>
            </div>
          </SectionCard>
          <DataTable<any>
            rows={policies}
            rowKey={(p: any) => p.id}
            columns={[
              { key: 'name', header: 'Name', render: (p: any) => <span style={{ fontWeight: 600 }}>{p.name}</span> },
              { key: 'rule_type', header: 'Rule Type', render: (p: any) => <Badge label={p.rule_type || '—'} color="#6366f1" /> },
              { key: 'action', header: 'Action', render: (p: any) => <Badge label={p.action} color={p.action === 'block' ? '#ef4444' : p.action === 'warn' ? '#f97316' : '#64748b'} /> },
              { key: 'status', header: 'Status', render: (p: any) => (
                <button className="g-btn g-btn-ghost" onClick={() => togglePolicy(p.id, p.is_enabled)} style={{ fontSize: 11, padding: '2px 8px', color: p.is_enabled ? '#22c55e' : '#ef4444', display: 'inline-flex', alignItems: 'center' }}>
                  <Dot on={p.is_enabled} />{p.is_enabled ? 'Enabled' : 'Disabled'}
                </button>
              ) },
              { key: 'description', header: 'Description', render: (p: any) => <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{p.description}</span> },
              { key: 'actions', header: '', render: (p: any) => (
                <button className="g-btn g-btn-ghost" onClick={() => deletePolicy(p.id)} style={{ fontSize: 11, color: '#ef4444' }}>Delete</button>
              ) },
            ]}
          />
        </div>
      )}
    </div>
  );
}

// ─── Analytics Tab ────────────────────────────────────────────────────────────
function AnalyticsTab() {
  const [analytics, setAnalytics] = useState<any>(null);

  useEffect(() => { supplyChainAPI.getAnalytics().then(r => setAnalytics(r.data)); }, []);

  if (!analytics) return <div style={{ color: 'var(--text-3)', padding: 32 }}>Loading analytics…</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <SectionCard title="Most Vulnerable Projects">
          {(analytics.most_vulnerable_projects ?? []).map((p: any, i: number) => (
            <div key={i} style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <span style={{ fontWeight: 600 }}>{p.name}</span>
                <span style={{ color: RISK_COLOR(p.risk), fontWeight: 700 }}>{p.cve_count} CVEs ({p.critical} critical)</span>
              </div>
              <ScoreBar score={p.risk} />
            </div>
          ))}
        </SectionCard>
        <SectionCard title="Most Used Dependencies">
          {(analytics.most_used_dependencies ?? []).map((d: any, i: number) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontWeight: 600 }}>{d.package}</span>
                <Badge label={d.ecosystem} color="#6366f1" />
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{d.used_by} repos</span>
                {d.has_vuln && <Badge label="vulnerable" color="#ef4444" />}
              </div>
            </div>
          ))}
        </SectionCard>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <SectionCard title="Secret Findings by Type">
          {(analytics.secret_findings_by_type ?? []).map((s: any, i: number) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontSize: 13 }}>{s.type.replace(/_/g, ' ')}</span>
              <span style={{ fontWeight: 700, color: '#ef4444' }}>{s.count}</span>
            </div>
          ))}
        </SectionCard>
        <SectionCard title="Build Failure Summary">
          {(analytics.build_failures ?? []).map((b: any, i: number) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontWeight: 600 }}>{b.pipeline}</span>
              <div>
                <span style={{ color: '#ef4444', fontWeight: 700 }}>{b.failures} failures</span>
                <span style={{ fontSize: 11, color: 'var(--text-3)', marginLeft: 8 }}>last: {timeAgo(b.last_failure)}</span>
              </div>
            </div>
          ))}
        </SectionCard>
      </div>
      <SectionCard title="CVE Discovery Trend (14 days)">
        <div style={{ display: 'flex', alignItems: 'flex-end', gap: 4, height: 80 }}>
          {(analytics.compliance_trend ?? []).map((p: any, i: number) => {
            const max = Math.max(...(analytics.compliance_trend ?? []).map((x: any) => x.count), 1);
            return (
              <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
                <div style={{ width: '100%', background: 'var(--accent)', borderRadius: 2, height: `${(p.count / max) * 60}px`, opacity: 0.7 + (i / 14) * 0.3 }} />
                {i % 4 === 0 && <div style={{ fontSize: 9, color: 'var(--text-3)', transform: 'rotate(-30deg)' }}>{p.date?.slice(5)}</div>}
              </div>
            );
          })}
        </div>
      </SectionCard>
    </div>
  );
}

// ─── Response & Reports Tab ───────────────────────────────────────────────────
function ResponseTab() {
  const [action, setAction] = useState('block_build');
  const [target, setTarget] = useState('');
  const [reason, setReason] = useState('');
  const [result, setResult] = useState<any>(null);
  const [executing, setExecuting] = useState(false);
  const [reportType, setReportType] = useState('executive');
  const [report, setReport] = useState<any>(null);
  const [generating, setGenerating] = useState(false);

  const ACTIONS = [
    { value: 'block_build', label: 'Block Build', desc: 'Prevent pipeline from proceeding with current vulnerability or secret' },
    { value: 'quarantine_artifact', label: 'Quarantine Artifact', desc: 'Remove artifact from distribution registries' },
    { value: 'disable_pipeline', label: 'Disable Pipeline', desc: 'Shut down CI/CD pipeline until issue is resolved' },
    { value: 'create_issue', label: 'Create Issue', desc: 'File GitHub/GitLab issue and assign to repo owner' },
    { value: 'create_incident', label: 'Create Incident', desc: 'Open incident in incident management platform' },
    { value: 'trigger_soar', label: 'Trigger SOAR', desc: 'Execute supply chain SOAR playbook' },
  ];

  const execute = async () => {
    setExecuting(true);
    try { const r = await supplyChainAPI.respond({ action, target, reason }); setResult(r.data); }
    catch { setResult({ error: 'Action failed' }); }
    finally { setExecuting(false); }
  };

  const generateReport = async () => {
    setGenerating(true);
    try { const r = await supplyChainAPI.generateReport({ report_type: reportType }); setReport(r.data); }
    catch { setReport({ error: 'Report generation failed' }); }
    finally { setGenerating(false); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <SectionCard title="Response Actions">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10, marginBottom: 16 }}>
          {ACTIONS.map(a => (
            <div key={a.value}
              onClick={() => setAction(a.value)}
              style={{ padding: 12, border: `2px solid ${action === a.value ? 'var(--accent)' : 'var(--border)'}`, borderRadius: 8, cursor: 'pointer', background: action === a.value ? 'var(--accent)11' : undefined }}>
              <div style={{ fontWeight: 600, fontSize: 13 }}>{a.label}</div>
              <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>{a.desc}</div>
            </div>
          ))}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <input className="g-input" placeholder="Target (pipeline name, artifact, repo…)" value={target} onChange={e => setTarget(e.target.value)} />
          <div style={{ display: 'flex', gap: 10 }}>
            <input className="g-input" style={{ flex: 1 }} placeholder="Reason / justification" value={reason} onChange={e => setReason(e.target.value)} />
            <ActionButton variant="primary" onClick={execute} loading={executing} style={{ background: '#ef4444' }}>
              {executing ? 'Executing…' : 'Execute'}
            </ActionButton>
          </div>
        </div>
        {result && (
          <div style={{ marginTop: 16, padding: 12, background: result.error ? '#ef444422' : '#22c55e22', borderRadius: 6, borderLeft: `3px solid ${result.error ? '#ef4444' : '#22c55e'}` }}>
            {result.error ? result.error : result.message}
          </div>
        )}
      </SectionCard>

      <SectionCard
        title="Generate Report"
        actions={<ActionButton variant="primary" onClick={generateReport} loading={generating}>{generating ? 'Generating…' : 'Generate with AI'}</ActionButton>}
      >
        <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
          {['executive', 'technical', 'compliance', 'audit'].map(t => (
            <ActionButton key={t} variant={reportType === t ? 'primary' : 'ghost'} onClick={() => setReportType(t)}>
              {t.charAt(0).toUpperCase() + t.slice(1)}
            </ActionButton>
          ))}
        </div>
        {report && !report.error && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: 18, marginBottom: 8 }}>{report.title}</div>
              <p style={{ fontSize: 14, lineHeight: 1.6, color: 'var(--text-2)' }}>{report.executive_summary}</p>
            </div>
            {report.key_findings && (
              <div>
                <div style={{ fontWeight: 600, marginBottom: 8 }}>Key Findings</div>
                <ul style={{ margin: 0, paddingLeft: 20 }}>
                  {report.key_findings.map((f: string, i: number) => <li key={i} style={{ fontSize: 13, marginBottom: 4 }}>{f}</li>)}
                </ul>
              </div>
            )}
            {report.top_recommendations && (
              <div>
                <div style={{ fontWeight: 600, marginBottom: 8 }}>Top Recommendations</div>
                {report.top_recommendations.map((r: any, i: number) => (
                  <div key={i} style={{ padding: '10px 14px', background: 'var(--border)', borderRadius: 6, marginBottom: 8, display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                    <span style={{ background: 'var(--accent)', color: '#fff', borderRadius: '50%', width: 22, height: 22, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, flexShrink: 0, fontWeight: 700 }}>{r.priority}</span>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: 13 }}>{r.action}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-3)' }}>Effort: {r.estimated_effort}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </SectionCard>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────
export default function SupplyChainPage() {
  const [tab, setTab] = useState<Tab>('overview');
  const [dash, setDash] = useState<any>(null);
  const loaded = useRef<Record<string, boolean>>({});

  useEffect(() => { supplyChainAPI.getDashboard().then(r => setDash(r.data)); }, []);

  if (!loaded.current[tab]) loaded.current[tab] = true;

  const tabContent = useMemo(() => ({
    overview:     <OverviewTab dash={dash} />,
    repos:        <ReposTab />,
    pipelines:    <PipelinesTab />,
    sbom:         <SBOMTab />,
    secrets:      <SecretsTab />,
    intelligence: <IntelligenceTab />,
    compliance:   <ComplianceTab />,
    analytics:    <AnalyticsTab />,
    response:     <ResponseTab />,
  }), [dash]);

  return (
    <RootLayout title="Supply Chain Security"
      subtitle="Repository inventory · Dependency management · SBOM · Pipeline security · Artifact integrity · Vulnerability management"
      actions={dash ? (
        <div style={{ display: 'flex', gap: 16, fontSize: 13 }}>
          <span style={{ color: '#ef4444' }}>{dash.critical_cves} critical CVEs</span>
          <span style={{ color: '#f97316' }}>{dash.secret_findings} open secrets</span>
          <span style={{ color: RISK_COLOR(dash.risk_score), fontWeight: 700 }}>Risk: {dash.risk_score}</span>
        </div>
      ) : undefined}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 0, height: '100%' }}>
        <div style={{ padding: '20px 24px 0', borderBottom: '1px solid var(--border)' }}>
          <TabBar
            tabs={(Object.keys(TAB_LABELS) as Tab[]).map(t => ({ key: t, label: TAB_LABELS[t], icon: TAB_ICONS[t] }))}
            active={tab}
            onChange={t => setTab(t as Tab)}
          />
        </div>
        <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
          {(Object.keys(TAB_LABELS) as Tab[]).map(t => (
            <div key={t} style={{ display: loaded.current[t] ? 'block' : 'none' }}>
              {loaded.current[t] && tab === t && tabContent[t]}
            </div>
          ))}
        </div>
      </div>
    </RootLayout>
  );
}
