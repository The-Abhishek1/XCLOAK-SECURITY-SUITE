'use client';

import { useState, useEffect, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { supplyChainAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';

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

function StatCard({ label, value, color, sub }: { label: string; value: string | number; color?: string; sub?: string }) {
  return (
    <div className="g-card" style={{ padding: '16px 20px' }}>
      <div style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700, color: color ?? 'var(--text-1)', fontVariantNumeric: 'tabular-nums' }}>{value}</div>
      {sub && <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>{sub}</div>}
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

// ─── Overview Tab ────────────────────────────────────────────────────────────
function OverviewTab({ dash }: { dash: any }) {
  if (!dash) return <div style={{ color: 'var(--text-3)', padding: 32 }}>Loading dashboard…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
        <StatCard label="Repositories" value={dash.repositories} />
        <StatCard label="Dependencies" value={dash.dependencies} />
        <StatCard label="Critical CVEs" value={dash.critical_cves} color="#ef4444" />
        <StatCard label="High-Risk Pkgs" value={dash.high_risk_packages} color="#f97316" />
        <StatCard label="Risk Score" value={`${dash.risk_score}%`} color={RISK_COLOR(dash.risk_score)} />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
        <StatCard label="SBOMs" value={dash.sboms} color="var(--accent)" sub="Generated" />
        <StatCard label="Pipelines" value={dash.build_pipelines} sub="Monitored" />
        <StatCard label="Signed Artifacts" value={`${dash.signed_artifacts}/${dash.total_artifacts}`} color="#22c55e" />
        <StatCard label="Open Secrets" value={dash.secret_findings} color="#ef4444" sub="Detected in code" />
        <StatCard label="SLSA Level" value="L1" color="#f97316" sub="Target: L3" />
      </div>
      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 16 }}>Overall Risk Score</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{ fontSize: 48, fontWeight: 800, color: RISK_COLOR(dash.risk_score) }}>{dash.risk_score}</div>
          <div style={{ flex: 1 }}>
            <ScoreBar score={dash.risk_score} />
            <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 8 }}>
              Score considers CVE severity, secret exposure, pipeline posture, artifact signing, and SBOM coverage.
            </div>
          </div>
        </div>
      </div>
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
          <button key={s} className={sub === s ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setSub(s)}>
            {s === 'repos' ? 'Repository Inventory' : 'Dependency Management'}
          </button>
        ))}
      </div>

      {sub === 'repos' && (
        <div className="g-card" style={{ overflow: 'auto' }}>
          <table className="g-table">
            <thead className="g-thead">
              <tr><th>Repository</th><th>Platform</th><th>Language</th><th>Branch</th><th>Contributors</th><th>Dependencies</th><th>Risk</th><th>Last Commit</th></tr>
            </thead>
            <tbody>
              {repos.map(r => (
                <tr key={r.id} className="g-tr">
                  <td><span style={{ fontWeight: 600 }}>{r.owner}/{r.name}</span></td>
                  <td><Badge label={r.platform} color="#3b82f6" /></td>
                  <td><Badge label={r.language} /></td>
                  <td><code style={{ fontSize: 12 }}>{r.default_branch}</code></td>
                  <td>{r.contributor_count}</td>
                  <td>{r.dep_count}</td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ color: RISK_COLOR(r.risk_score), fontWeight: 700, fontSize: 13, width: 30 }}>{r.risk_score}</span>
                      <div style={{ width: 60 }}><ScoreBar score={r.risk_score} /></div>
                    </div>
                  </td>
                  <td style={{ color: 'var(--text-3)' }}>{timeAgo(r.last_commit)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {sub === 'deps' && (
        <>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <select className="g-select" style={{ width: 160 }} value={ecosystem} onChange={e => setEcosystem(e.target.value)}>
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
          <div className="g-card" style={{ overflow: 'auto' }}>
            <table className="g-table">
              <thead className="g-thead">
                <tr><th>Package</th><th>Ecosystem</th><th>Version</th><th>Latest</th><th>License</th><th>CVEs</th><th>Type</th><th>Risk</th></tr>
              </thead>
              <tbody>
                {deps.map(d => (
                  <tr key={d.id} className="g-tr">
                    <td style={{ fontWeight: 600 }}>{d.package_name}</td>
                    <td><Badge label={d.ecosystem} color="#6366f1" /></td>
                    <td><code style={{ fontSize: 12 }}>{d.version}</code></td>
                    <td>
                      <code style={{ fontSize: 12, color: d.is_outdated ? '#f97316' : 'var(--text-2)' }}>{d.latest_version}</code>
                      {d.is_outdated && <span style={{ fontSize: 10, color: '#f97316', marginLeft: 4 }}>outdated</span>}
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{d.license}</td>
                    <td>
                      {d.cve_count > 0
                        ? <span style={{ color: '#ef4444', fontWeight: 700 }}>{d.cve_count}</span>
                        : <span style={{ color: 'var(--text-3)' }}>0</span>}
                    </td>
                    <td><Badge label={d.is_direct ? 'direct' : 'transitive'} color={d.is_direct ? '#22c55e' : '#64748b'} /></td>
                    <td><span style={{ color: RISK_COLOR(d.risk_score), fontWeight: 700 }}>{d.risk_score}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
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
          <button key={s} className={sub === s ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setSub(s)}>
            {s === 'pipelines' ? 'Build Pipelines' : s === 'artifacts' ? 'Artifact Security' : 'Build Provenance'}
          </button>
        ))}
      </div>

      {sub === 'pipelines' && (
        <div className="g-card" style={{ overflow: 'auto' }}>
          <table className="g-table">
            <thead className="g-thead">
              <tr><th>Pipeline</th><th>Platform</th><th>Status</th><th>Secrets in CI</th><th>Untrusted Actions</th><th>Pinned Versions</th><th>Risk</th><th>Last Run</th></tr>
            </thead>
            <tbody>
              {pipelines.map(p => (
                <tr key={p.id} className="g-tr">
                  <td style={{ fontWeight: 600 }}>{p.name}</td>
                  <td><Badge label={p.platform} color={PLATFORM_COLORS[p.platform] ?? '#64748b'} /></td>
                  <td><Badge label={p.status} color={p.status === 'passing' ? '#22c55e' : '#ef4444'} /></td>
                  <td><span style={{ color: p.has_secrets ? '#ef4444' : '#22c55e' }}>{p.has_secrets ? '⚠ Yes' : '✓ No'}</span></td>
                  <td><span style={{ color: p.has_untrusted_actions ? '#ef4444' : '#22c55e' }}>{p.has_untrusted_actions ? '⚠ Yes' : '✓ No'}</span></td>
                  <td><span style={{ color: p.has_pinned_versions ? '#22c55e' : '#f97316' }}>{p.has_pinned_versions ? '✓ Yes' : '✗ No'}</span></td>
                  <td><span style={{ color: RISK_COLOR(p.risk_score), fontWeight: 700 }}>{p.risk_score}</span></td>
                  <td style={{ color: 'var(--text-3)' }}>{timeAgo(p.last_run)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {sub === 'artifacts' && (
        <div className="g-card" style={{ overflow: 'auto' }}>
          <table className="g-table">
            <thead className="g-thead">
              <tr><th>Artifact</th><th>Type</th><th>Version</th><th>Signed</th><th>SBOM</th><th>Provenance</th><th>Hash</th><th>Risk</th></tr>
            </thead>
            <tbody>
              {artifacts.map(a => (
                <tr key={a.id} className="g-tr">
                  <td style={{ fontWeight: 600 }}>{a.name}</td>
                  <td><Badge label={a.artifact_type} color="#6366f1" /></td>
                  <td><code style={{ fontSize: 12 }}>{a.version}</code></td>
                  <td><span style={{ color: a.is_signed ? '#22c55e' : '#ef4444' }}>{a.is_signed ? '✓ Yes' : '✗ No'}</span></td>
                  <td><span style={{ color: a.has_sbom ? '#22c55e' : '#f97316' }}>{a.has_sbom ? '✓ Yes' : '✗ No'}</span></td>
                  <td><span style={{ color: a.provenance_available ? '#22c55e' : '#ef4444' }}>{a.provenance_available ? '✓ Yes' : '✗ No'}</span></td>
                  <td><code style={{ fontSize: 10, color: 'var(--text-3)' }}>{a.artifact_hash ? a.artifact_hash.slice(0, 20) + '…' : '—'}</code></td>
                  <td><span style={{ color: RISK_COLOR(a.risk_score), fontWeight: 700 }}>{a.risk_score}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {sub === 'provenance' && provenance && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
            <StatCard label="SLSA Level" value={`L${provenance.slsa_level}`} color="#f97316" sub="Target: L3" />
            <StatCard label="Provenance Coverage" value={`${provenance.provenance_rate}%`} color={provenance.provenance_rate > 70 ? '#22c55e' : '#f97316'} />
            <StatCard label="Total Builds" value={provenance.builds?.length ?? 0} />
          </div>
          <div className="g-card" style={{ overflow: 'auto' }}>
            <table className="g-table">
              <thead className="g-thead">
                <tr><th>Artifact</th><th>Builder</th><th>Source Commit</th><th>Signed</th><th>SLSA Level</th><th>Attestation</th><th>Built</th></tr>
              </thead>
              <tbody>
                {(provenance.builds ?? []).map((b: any, i: number) => (
                  <tr key={i} className="g-tr">
                    <td style={{ fontWeight: 600 }}>{b.artifact}</td>
                    <td><Badge label={b.builder} color="#3b82f6" /></td>
                    <td><code style={{ fontSize: 12 }}>{b.source_commit}</code></td>
                    <td><span style={{ color: b.signed ? '#22c55e' : '#ef4444' }}>{b.signed ? '✓ Yes' : '✗ No'}</span></td>
                    <td><Badge label={`L${b.slsa_level}`} color={b.slsa_level >= 2 ? '#22c55e' : '#ef4444'} /></td>
                    <td style={{ color: 'var(--text-3)' }}>{b.attestation || '—'}</td>
                    <td style={{ color: 'var(--text-3)' }}>{timeAgo(b.build_time)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
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
          <button key={s} className={sub === s ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setSub(s)}>
            {s === 'sboms' ? 'SBOM Management' : 'Vulnerability Management'}
          </button>
        ))}
      </div>

      {sub === 'sboms' && (
        <div className="g-card" style={{ overflow: 'auto' }}>
          <table className="g-table">
            <thead className="g-thead">
              <tr><th>Artifact</th><th>Format</th><th>Components</th><th>Licenses</th><th>Suppliers</th><th>Has Vulns</th><th>Generated</th></tr>
            </thead>
            <tbody>
              {sboms.map(s => (
                <tr key={s.id} className="g-tr">
                  <td style={{ fontWeight: 600 }}>{s.artifact_name}</td>
                  <td><Badge label={s.format} color="#6366f1" /></td>
                  <td>{s.component_count}</td>
                  <td>{s.license_count}</td>
                  <td>{s.supplier_count}</td>
                  <td><span style={{ color: s.has_vulnerabilities ? '#ef4444' : '#22c55e' }}>{s.has_vulnerabilities ? '⚠ Yes' : '✓ Clean'}</span></td>
                  <td style={{ color: 'var(--text-3)' }}>{timeAgo(s.generated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {sub === 'vulns' && (
        <>
          {vulnData && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
              <StatCard label="Critical" value={vulnData.critical} color="#ef4444" />
              <StatCard label="High" value={vulnData.high} color="#f97316" />
              <StatCard label="KEV (CISA)" value={vulnData.kev} color="#dc2626" sub="Known exploited" />
              <StatCard label="Exploited" value={vulnData.exploited} color="#f97316" sub="Active exploitation" />
            </div>
          )}
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <select className="g-select" style={{ width: 160 }} value={severity} onChange={e => setSeverity(e.target.value)}>
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
          <div className="g-card" style={{ overflow: 'auto' }}>
            <table className="g-table">
              <thead className="g-thead">
                <tr><th>CVE</th><th>Description</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Has Exploit</th><th>Fix</th><th>Severity</th><th>Affected</th></tr>
              </thead>
              <tbody>
                {(vulnData?.vulns ?? []).map((v: any) => (
                  <tr key={v.id} className="g-tr">
                    <td><code style={{ fontSize: 12, color: 'var(--accent)' }}>{v.cve_id}</code></td>
                    <td style={{ fontSize: 12 }}>{v.description?.slice(0, 40)}…</td>
                    <td><span style={{ color: v.cvss >= 9 ? '#ef4444' : v.cvss >= 7 ? '#f97316' : '#eab308', fontWeight: 700 }}>{v.cvss.toFixed(1)}</span></td>
                    <td style={{ fontSize: 12 }}>{(v.epss * 100).toFixed(1)}%</td>
                    <td>{v.is_kev && <Badge label="KEV" color="#dc2626" />}</td>
                    <td><span style={{ color: v.has_exploit ? '#ef4444' : 'var(--text-3)' }}>{v.has_exploit ? '⚠ Yes' : '—'}</span></td>
                    <td><code style={{ fontSize: 11 }}>{v.fix_version || '—'}</code></td>
                    <td><Badge label={v.severity} color={SEV_COLOR[v.severity]} /></td>
                    <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{v.affected_projects}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
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
          <button key={s} className={sub === s ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setSub(s)}>
            {s === 'secrets' ? 'Secret Detection' : 'Code Integrity'}
          </button>
        ))}
      </div>

      {sub === 'secrets' && secretData && (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            <StatCard label="Total Findings" value={secretData.total} />
            <StatCard label="Open" value={secretData.open} color="#ef4444" />
            <StatCard label="AWS Keys" value={secretData.aws_keys} color="#f97316" />
            <StatCard label="API Keys" value={secretData.api_keys} color="#eab308" />
          </div>
          <div className="g-card" style={{ overflow: 'auto' }}>
            <table className="g-table">
              <thead className="g-thead">
                <tr><th>Type</th><th>File Path</th><th>Commit</th><th>Severity</th><th>Status</th><th>Found</th></tr>
              </thead>
              <tbody>
                {(secretData.secrets ?? []).map((s: any) => (
                  <tr key={s.id} className="g-tr">
                    <td><Badge label={s.secret_type.replace(/_/g, ' ')} color="#ef4444" /></td>
                    <td><code style={{ fontSize: 12 }}>{s.file_path}</code></td>
                    <td><code style={{ fontSize: 11, color: 'var(--text-3)' }}>{s.commit_hash}</code></td>
                    <td><Badge label={s.severity} color={SEV_COLOR[s.severity]} /></td>
                    <td><Badge label={s.status} color={s.status === 'open' ? '#ef4444' : '#22c55e'} /></td>
                    <td style={{ color: 'var(--text-3)' }}>{timeAgo(s.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {sub === 'integrity' && integrity && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            <StatCard label="Signed Commits" value={`${integrity.signed_commits_rate}%`} color={integrity.signed_commits_rate >= 80 ? '#22c55e' : '#f97316'} />
            <StatCard label="Signed Tags" value={`${integrity.signed_tags_rate}%`} color={integrity.signed_tags_rate >= 80 ? '#22c55e' : '#f97316'} />
            <StatCard label="Protected Branches" value={integrity.protected_branches} color="#22c55e" />
            <StatCard label="Force Push Incidents" value={integrity.force_push_incidents} color={integrity.force_push_incidents > 0 ? '#ef4444' : '#22c55e'} />
          </div>
          <div className="g-card" style={{ overflow: 'auto' }}>
            <table className="g-table">
              <thead className="g-thead">
                <tr><th>Repository</th><th>Finding</th><th>Severity</th><th>Count</th></tr>
              </thead>
              <tbody>
                {(integrity.findings ?? []).map((f: any, i: number) => (
                  <tr key={i} className="g-tr">
                    <td style={{ fontWeight: 600 }}>{f.repo}</td>
                    <td>{f.finding}</td>
                    <td><Badge label={f.severity} color={SEV_COLOR[f.severity]} /></td>
                    <td>{f.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
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
          <button key={s} className={sub === s ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setSub(s)}>
            {s === 'intel' ? 'Threat Intelligence' : s === 'third-party' ? 'Third-Party Risk' : s === 'timeline' ? 'Timeline' : 'AI Analysis'}
          </button>
        ))}
      </div>

      {sub === 'intel' && intel && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="g-card" style={{ padding: 20 }}>
            <div style={{ fontWeight: 600, marginBottom: 12, color: '#ef4444' }}>Malicious Packages Detected</div>
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
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div className="g-card" style={{ padding: 20 }}>
              <div style={{ fontWeight: 600, marginBottom: 12 }}>Active Campaigns</div>
              {(intel.campaigns ?? []).map((c: any, i: number) => (
                <div key={i} style={{ padding: 10, background: 'var(--border)', borderRadius: 6, marginBottom: 8 }}>
                  <div style={{ fontWeight: 600 }}>{c.name}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-3)' }}>{c.packages_affected} packages · {c.ecosystems} · Since {c.first_seen}</div>
                </div>
              ))}
            </div>
            <div className="g-card" style={{ padding: 20 }}>
              <div style={{ fontWeight: 600, marginBottom: 12 }}>IOC Matches in Dependencies</div>
              {(intel.ioc_matches ?? []).map((m: any, i: number) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
                  <div>
                    <Badge label={m.type} color="#f97316" />
                    <span style={{ marginLeft: 8, fontSize: 12, fontFamily: 'monospace' }}>{m.value}</span>
                  </div>
                  <span style={{ fontSize: 12, color: '#ef4444' }}>{m.hits} hits</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {sub === 'third-party' && thirdParty && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="g-card" style={{ overflow: 'auto' }}>
            <div style={{ padding: '12px 16px', fontWeight: 600, borderBottom: '1px solid var(--border)' }}>Third-Party Package Risk</div>
            <table className="g-table">
              <thead className="g-thead">
                <tr><th>Package</th><th>Ecosystem</th><th>Version</th><th>Trust Score</th><th>Maintenance</th><th>Advisories</th><th>Weekly Downloads</th></tr>
              </thead>
              <tbody>
                {(thirdParty.packages ?? []).map((p: any, i: number) => (
                  <tr key={i} className="g-tr">
                    <td style={{ fontWeight: 600 }}>{p.name}</td>
                    <td><Badge label={p.ecosystem} color="#6366f1" /></td>
                    <td><code style={{ fontSize: 12 }}>{p.version}</code></td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ color: RISK_COLOR(100 - p.trust_score), fontWeight: 700, width: 28 }}>{p.trust_score}</span>
                        <div style={{ width: 60 }}><ScoreBar score={p.trust_score} color={p.trust_score >= 70 ? '#22c55e' : p.trust_score >= 40 ? '#f97316' : '#ef4444'} /></div>
                      </div>
                    </td>
                    <td><Badge label={p.maintenance} color={p.maintenance === 'active' ? '#22c55e' : p.maintenance === 'abandoned' ? '#ef4444' : p.maintenance === 'compromised' || p.maintenance === 'malicious' ? '#dc2626' : '#f97316'} /></td>
                    <td>{p.advisories > 0 ? <span style={{ color: '#ef4444', fontWeight: 700 }}>{p.advisories}</span> : <span style={{ color: '#22c55e' }}>0</span>}</td>
                    <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{p.downloads_weekly.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="g-card" style={{ overflow: 'auto' }}>
            <div style={{ padding: '12px 16px', fontWeight: 600, borderBottom: '1px solid var(--border)' }}>CI/CD Plugin Assessment</div>
            <table className="g-table">
              <thead className="g-thead">
                <tr><th>Plugin</th><th>Version</th><th>Pinned to SHA</th><th>Trusted</th><th>SHA</th></tr>
              </thead>
              <tbody>
                {(thirdParty.ci_plugins ?? []).map((p: any, i: number) => (
                  <tr key={i} className="g-tr">
                    <td style={{ fontWeight: 600, fontFamily: 'monospace', fontSize: 13 }}>{p.name}</td>
                    <td><code>{p.version}</code></td>
                    <td><span style={{ color: p.is_pinned ? '#22c55e' : '#ef4444' }}>{p.is_pinned ? '✓ Yes' : '✗ No'}</span></td>
                    <td><span style={{ color: p.trusted ? '#22c55e' : '#f97316' }}>{p.trusted ? '✓ Yes' : '⚠ Unverified'}</span></td>
                    <td><code style={{ fontSize: 11, color: 'var(--text-3)' }}>{p.sha ? p.sha.slice(0, 16) + '…' : '—'}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {sub === 'timeline' && (
        <div className="g-card" style={{ overflow: 'auto' }}>
          <table className="g-table">
            <thead className="g-thead">
              <tr><th>Event</th><th>Target</th><th>Severity</th><th>Detail</th><th>Time</th></tr>
            </thead>
            <tbody>
              {timeline.map((e: any) => (
                <tr key={e.id} className="g-tr">
                  <td><Badge label={e.event_type.replace(/_/g, ' ')} color="#6366f1" /></td>
                  <td><code style={{ fontSize: 12 }}>{e.target}</code></td>
                  <td><Badge label={e.severity} color={SEV_COLOR[e.severity]} /></td>
                  <td style={{ fontSize: 12 }}>{e.detail}</td>
                  <td style={{ color: 'var(--text-3)' }}>{timeAgo(e.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {sub === 'ai' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', gap: 8 }}>
            {(['dependency', 'pipeline', 'ask'] as const).map(m => (
              <button key={m} className={aiMode === m ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setAIMode(m)}>
                {m === 'dependency' ? 'Analyze Dependency' : m === 'pipeline' ? 'Analyze Pipeline' : 'Ask AI'}
              </button>
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
            <button className="g-btn g-btn-primary" onClick={runAI} disabled={aiLoading} style={{ alignSelf: 'flex-start' }}>
              {aiLoading ? 'Analyzing…' : 'Analyze'}
            </button>
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
          <button key={s} className={sub === s ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setSub(s)}>
            {s === 'compliance' ? 'Compliance Frameworks' : 'Policy Engine'}
          </button>
        ))}
      </div>

      {sub === 'compliance' && compliance && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <StatCard label="Overall Compliance Score" value={`${compliance.overall_score}%`} color={compliance.overall_score >= 70 ? '#22c55e' : compliance.overall_score >= 50 ? '#f97316' : '#ef4444'} />
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
          <div className="g-card" style={{ overflow: 'auto' }}>
            <div style={{ padding: '12px 16px', fontWeight: 600, borderBottom: '1px solid var(--border)' }}>Failed Controls</div>
            <table className="g-table">
              <thead className="g-thead">
                <tr><th>Control</th><th>Title</th><th>Framework</th><th>Severity</th></tr>
              </thead>
              <tbody>
                {(compliance.failed_controls ?? []).map((c: any, i: number) => (
                  <tr key={i} className="g-tr">
                    <td><code style={{ fontSize: 12 }}>{c.control}</code></td>
                    <td style={{ fontSize: 13 }}>{c.title}</td>
                    <td><Badge label={c.framework} color="#6366f1" /></td>
                    <td><Badge label={c.severity} color={SEV_COLOR[c.severity]} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {sub === 'policies' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="g-card" style={{ padding: 20 }}>
            <div style={{ fontWeight: 600, marginBottom: 12 }}>New Policy</div>
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
              <button className="g-btn g-btn-primary" onClick={savePolicy} disabled={saving}>{saving ? 'Saving…' : 'Create Policy'}</button>
            </div>
          </div>
          <div className="g-card" style={{ overflow: 'auto' }}>
            <table className="g-table">
              <thead className="g-thead">
                <tr><th>Name</th><th>Rule Type</th><th>Action</th><th>Status</th><th>Description</th><th></th></tr>
              </thead>
              <tbody>
                {policies.map(p => (
                  <tr key={p.id} className="g-tr">
                    <td style={{ fontWeight: 600 }}>{p.name}</td>
                    <td><Badge label={p.rule_type || '—'} color="#6366f1" /></td>
                    <td><Badge label={p.action} color={p.action === 'block' ? '#ef4444' : p.action === 'warn' ? '#f97316' : '#64748b'} /></td>
                    <td>
                      <button className="g-btn g-btn-ghost" onClick={() => togglePolicy(p.id, p.is_enabled)} style={{ fontSize: 11, padding: '2px 8px', color: p.is_enabled ? '#22c55e' : '#ef4444' }}>
                        {p.is_enabled ? '● Enabled' : '○ Disabled'}
                      </button>
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{p.description}</td>
                    <td>
                      <button className="g-btn g-btn-ghost" onClick={() => deletePolicy(p.id)} style={{ fontSize: 11, color: '#ef4444' }}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
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
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Most Vulnerable Projects</div>
          {(analytics.most_vulnerable_projects ?? []).map((p: any, i: number) => (
            <div key={i} style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <span style={{ fontWeight: 600 }}>{p.name}</span>
                <span style={{ color: RISK_COLOR(p.risk), fontWeight: 700 }}>{p.cve_count} CVEs ({p.critical} critical)</span>
              </div>
              <ScoreBar score={p.risk} />
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Most Used Dependencies</div>
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
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Secret Findings by Type</div>
          {(analytics.secret_findings_by_type ?? []).map((s: any, i: number) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontSize: 13 }}>{s.type.replace(/_/g, ' ')}</span>
              <span style={{ fontWeight: 700, color: '#ef4444' }}>{s.count}</span>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Build Failure Summary</div>
          {(analytics.build_failures ?? []).map((b: any, i: number) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontWeight: 600 }}>{b.pipeline}</span>
              <div>
                <span style={{ color: '#ef4444', fontWeight: 700 }}>{b.failures} failures</span>
                <span style={{ fontSize: 11, color: 'var(--text-3)', marginLeft: 8 }}>last: {timeAgo(b.last_failure)}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 12 }}>CVE Discovery Trend (14 days)</div>
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
      </div>
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
      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 16 }}>Response Actions</div>
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
            <button className="g-btn g-btn-primary" onClick={execute} disabled={executing} style={{ background: '#ef4444' }}>
              {executing ? 'Executing…' : 'Execute'}
            </button>
          </div>
        </div>
        {result && (
          <div style={{ marginTop: 16, padding: 12, background: result.error ? '#ef444422' : '#22c55e22', borderRadius: 6, borderLeft: `3px solid ${result.error ? '#ef4444' : '#22c55e'}` }}>
            {result.error ? result.error : result.message}
          </div>
        )}
      </div>

      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 12 }}>Generate Report</div>
        <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
          {['executive', 'technical', 'compliance', 'audit'].map(t => (
            <button key={t} className={reportType === t ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setReportType(t)}>
              {t.charAt(0).toUpperCase() + t.slice(1)}
            </button>
          ))}
          <button className="g-btn g-btn-primary" onClick={generateReport} disabled={generating} style={{ marginLeft: 'auto' }}>
            {generating ? 'Generating…' : 'Generate with AI'}
          </button>
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
      </div>
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
    <RootLayout>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 0, height: '100%' }}>
        <div style={{ padding: '20px 24px 0', borderBottom: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
            <div>
              <h1 style={{ margin: 0, fontSize: 22, fontWeight: 700 }}>Supply Chain Security</h1>
              <p style={{ margin: '4px 0 0', fontSize: 13, color: 'var(--text-3)' }}>
                Repository inventory · Dependency management · SBOM · Pipeline security · Artifact integrity · Vulnerability management
              </p>
            </div>
            {dash && (
              <div style={{ display: 'flex', gap: 16, fontSize: 13 }}>
                <span style={{ color: '#ef4444' }}>{dash.critical_cves} critical CVEs</span>
                <span style={{ color: '#f97316' }}>{dash.secret_findings} open secrets</span>
                <span style={{ color: RISK_COLOR(dash.risk_score), fontWeight: 700 }}>Risk: {dash.risk_score}</span>
              </div>
            )}
          </div>
          <div style={{ display: 'flex', gap: 0, overflowX: 'auto' }}>
            {(Object.keys(TAB_LABELS) as Tab[]).map(t => (
              <button
                key={t}
                onClick={() => setTab(t)}
                style={{
                  padding: '8px 16px', background: 'none', border: 'none', cursor: 'pointer', fontSize: 13, fontWeight: 500,
                  color: tab === t ? 'var(--accent)' : 'var(--text-3)',
                  borderBottom: `2px solid ${tab === t ? 'var(--accent)' : 'transparent'}`,
                  whiteSpace: 'nowrap',
                }}
              >{TAB_LABELS[t]}</button>
            ))}
          </div>
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
