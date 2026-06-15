'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { agentsAPI, exportAPI, cveAPI } from '@/lib/api';
import { Vulnerability, Agent } from '@/types';
import { sevClass, timeAgo } from '@/lib/utils';
import {
  Bug, Search, Download, Play, ChevronDown,
  ExternalLink, Shield, AlertTriangle,
} from 'lucide-react';

interface CVEData {
  cve_id: string;
  cvss_score: number;
  severity: string;
  description: string;
  published_at: string | null;
}

export default function VulnerabilitiesPage() {
  const [agents, setAgents]       = useState<Agent[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<number | null>(null);
  const [vulns, setVulns]         = useState<Vulnerability[]>([]);
  const [loading, setLoading]     = useState(false);
  const [scanning, setScanning]   = useState(false);
  const [search, setSearch]       = useState('');
  const [sevFilter, setSevFilter] = useState('');
  const [cveDetail, setCveDetail] = useState<CVEData | null>(null);
  const [cveLoading, setCveLoading] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [toast, setToast]         = useState<string | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const loadAgents = useCallback(async () => {
    const r = await agentsAPI.getAll();
    const list = r.data || [];
    setAgents(list);
    if (list.length > 0 && !selectedAgent) setSelectedAgent(list[0].id);
  }, [selectedAgent]);

  useEffect(() => { loadAgents(); }, []);

  const loadVulns = useCallback(async (agentId: number, spin = false) => {
    if (spin) setRefreshing(true);
    setLoading(true);
    try {
      const r = await agentsAPI.getVulnerabilities(agentId);
      setVulns(r.data || []);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    if (selectedAgent) loadVulns(selectedAgent);
  }, [selectedAgent]);

  const scan = async () => {
    if (!selectedAgent) return;
    setScanning(true);
    try {
      await agentsAPI.vulnerabilityScan(selectedAgent);
      notify('Scan started — refresh in ~10s');
      setTimeout(() => loadVulns(selectedAgent), 10000);
    } catch {
      notify('Scan failed');
    } finally {
      setScanning(false);
    }
  };

  const lookupCVE = async (cveId: string) => {
    setCveLoading(cveId);
    try {
      const r = await cveAPI.lookup(cveId);
      setCveDetail(r.data);
    } catch {
      notify('CVE lookup failed — NVD may be unreachable');
    } finally {
      setCveLoading(null);
    }
  };

  const filtered = vulns.filter(v => {
    const matchSev  = !sevFilter || v.severity === sevFilter;
    const matchSearch = !search || v.cve_id?.toLowerCase().includes(search.toLowerCase())
      || v.package_name?.toLowerCase().includes(search.toLowerCase())
      || v.name?.toLowerCase().includes(search.toLowerCase());
    return matchSev && matchSearch;
  });

  const bySev = ['critical','high','medium','low'].reduce((acc, s) => {
    acc[s] = vulns.filter(v => v.severity === s).length;
    return acc;
  }, {} as Record<string, number>);

  const selectedAgentObj = agents.find(a => a.id === selectedAgent);

  return (
    <RootLayout title="Vulnerabilities" subtitle="CVE scan results across all agents"
      onRefresh={() => selectedAgent && loadVulns(selectedAgent, true)} refreshing={refreshing}
      actions={
        <div className="flex items-center gap-2">
          <a href={exportAPI.vulnsCSV()} download
            className="g-btn g-btn-ghost text-xs">
            <Download className="h-3.5 w-3.5" /> Export CSV
          </a>
          <button onClick={scan} disabled={scanning || !selectedAgent} className="g-btn g-btn-primary text-xs">
            <Play className="h-3.5 w-3.5" /> {scanning ? 'Scanning…' : 'Run Scan'}
          </button>
        </div>
      }>

      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)', minWidth: 220 }}>{toast}</div>}

      <div className="space-y-4">
        {/* Agent selector + severity summary */}
        <div className="flex items-start gap-4 flex-wrap">
          <div>
            <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Agent</label>
            <select value={selectedAgent || ''} onChange={e => setSelectedAgent(Number(e.target.value))}
              className="g-select" style={{ minWidth: 180 }}>
              {agents.map(a => (
                <option key={a.id} value={a.id}>{a.hostname} (#{a.id})</option>
              ))}
            </select>
          </div>

          {vulns.length > 0 && (
            <div className="flex items-center gap-2 flex-wrap mt-4">
              {['critical','high','medium','low'].map(s => (
                <button key={s} onClick={() => setSevFilter(sevFilter === s ? '' : s)}
                  className="flex items-center gap-1.5 rounded-xl px-3 py-1.5 text-xs font-medium capitalize transition-all"
                  style={{
                    background: sevFilter === s ? 'var(--accent-glow)' : 'var(--glass-bg)',
                    border: `1px solid ${sevFilter === s ? 'var(--accent-border)' : 'var(--border)'}`,
                    color: sevFilter === s ? 'var(--accent)' : 'var(--text-2)',
                  }}>
                  {s}
                  <span className="font-bold tabular-nums" style={{
                    color: s === 'critical' ? 'var(--red)' : s === 'high' ? 'var(--orange)' : s === 'medium' ? 'var(--yellow)' : 'var(--blue)',
                  }}>
                    {bySev[s] || 0}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="relative max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search CVE, package, or name…" className="g-input pl-9" />
        </div>

        {/* CVE detail panel */}
        {cveDetail && (
          <div className="fixed inset-0 z-50 flex">
            <div className="flex-1" onClick={() => setCveDetail(null)} />
            <div className="w-full max-w-sm h-full overflow-y-auto shadow-2xl"
              style={{ background: 'var(--bg-1)', borderLeft: '1px solid var(--border)' }}>

              {/* Header */}
              <div className="sticky top-0 px-5 py-4 flex items-center justify-between"
                style={{ background: 'var(--bg-1)', borderBottom: '1px solid var(--border)', zIndex: 10 }}>
                <div>
                  <p className="mono text-sm font-bold" style={{ color: 'var(--accent)' }}>{cveDetail.cve_id}</p>
                  <div className="flex items-center gap-2 mt-1">
                    <span className={sevClass(cveDetail.severity)}>{cveDetail.severity}</span>
                  </div>
                </div>
                <button onClick={() => setCveDetail(null)} style={{ color: 'var(--text-2)' }}>✕</button>
              </div>

              <div className="p-5 space-y-5">
                {/* CVSS Gauge */}
                {cveDetail.cvss_score > 0 && (() => {
                  const score = cveDetail.cvss_score;
                  const pct   = score / 10;
                  const r     = 48;
                  const circ  = Math.PI * r;
                  const dash  = circ * pct;
                  const color = score >= 9 ? '#f85149' : score >= 7 ? '#fb923c' : score >= 4 ? '#fbbf24' : '#34d399';
                  return (
                    <div className="flex items-center gap-5 rounded-xl p-4"
                      style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                      <svg width="110" height="65" viewBox="0 0 110 65">
                        <path d="M 7 60 A 48 48 0 0 1 103 60" fill="none" stroke="var(--border)" strokeWidth="9" strokeLinecap="round" />
                        <path d="M 7 60 A 48 48 0 0 1 103 60" fill="none" stroke={color}
                          strokeWidth="9" strokeLinecap="round"
                          strokeDasharray={`${dash} ${circ}`} />
                        <text x="55" y="55" textAnchor="middle" fontSize="18" fontWeight="700" fill="var(--text-1)">{score.toFixed(1)}</text>
                      </svg>
                      <div>
                        <p className="text-xs font-bold" style={{ color }}>
                          {score >= 9 ? 'Critical' : score >= 7 ? 'High' : score >= 4 ? 'Medium' : 'Low'}
                        </p>
                        <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>CVSS v3 Score</p>
                        {cveDetail.published_at && (
                          <p className="text-[10px] mt-2" style={{ color: 'var(--text-3)' }}>
                            Published {new Date(cveDetail.published_at).toLocaleDateString()}
                          </p>
                        )}
                      </div>
                    </div>
                  );
                })()}

                {/* Description */}
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>Description</p>
                  <p className="text-xs leading-relaxed" style={{ color: 'var(--text-2)' }}>{cveDetail.description}</p>
                </div>

                {/* Remediation */}
                {cveDetail.remediation && (
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>Remediation</p>
                    <div className="rounded-xl p-3 mono text-[11px]"
                      style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--green)' }}>
                      {cveDetail.remediation}
                    </div>
                  </div>
                )}

                {/* Links */}
                <div className="flex gap-2">
                  <a href={`https://nvd.nist.gov/vuln/detail/${cveDetail.cve_id}`}
                    target="_blank" rel="noopener"
                    className="g-btn g-btn-primary text-xs flex-1 justify-center">
                    <ExternalLink className="h-3.5 w-3.5" /> NVD Entry
                  </a>
                  <a href={`https://www.cvedetails.com/cve/${cveDetail.cve_id}/`}
                    target="_blank" rel="noopener"
                    className="g-btn g-btn-ghost text-xs flex-1 justify-center">
                    <ExternalLink className="h-3.5 w-3.5" /> CVE Details
                  </a>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Table */}
        <div className="g-table">
          <div className="g-thead grid gap-3 px-4"
            style={{ gridTemplateColumns: '100px 1fr 100px 70px 80px 1fr 80px' }}>
            <span>CVE ID</span><span>Package</span><span>Name</span>
            <span>CVSS</span><span>Severity</span><span>Remediation</span><span className="text-right">Lookup</span>
          </div>

          {loading ? (
            <div className="py-14 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          ) : filtered.length === 0 ? (
            <div className="py-14 text-center">
              <Shield className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>
                {vulns.length === 0 ? 'No vulnerabilities found. Run a scan.' : 'No matches for current filter.'}
              </p>
            </div>
          ) : filtered.map(v => (
            <div key={v.id} className="g-tr grid gap-3 items-center px-4"
              style={{ gridTemplateColumns: '100px 1fr 100px 70px 80px 1fr 80px' }}>
              <span className="mono text-[11px] font-medium" style={{ color: 'var(--accent)' }}>{v.cve_id}</span>
              <div className="min-w-0">
                <p className="text-xs truncate" style={{ color: 'var(--text-1)' }}>{v.package_name}</p>
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{v.package_version}</p>
              </div>
              <span className="text-xs truncate" style={{ color: 'var(--text-2)' }}>{v.name || '—'}</span>
              <span className="text-xs font-bold tabular-nums" style={{
                color: (v.cvss_score || 0) >= 9 ? 'var(--red)' : (v.cvss_score || 0) >= 7 ? 'var(--orange)' : 'var(--yellow)',
              }}>
                {(v.cvss_score || 0).toFixed(1)}
              </span>
              <span className={sevClass(v.severity)}>{v.severity}</span>
              <span className="text-[11px] truncate" style={{ color: 'var(--text-3)' }}>{v.remediation || '—'}</span>
              <div className="flex justify-end">
                <button onClick={() => lookupCVE(v.cve_id)} disabled={cveLoading === v.cve_id}
                  className="g-btn g-btn-ghost text-[11px]" style={{ padding: '3px 8px' }}>
                  {cveLoading === v.cve_id ? '…' : 'CVE'}
                </button>
              </div>
            </div>
          ))}
        </div>

        {filtered.length > 0 && (
          <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
            Showing {filtered.length} of {vulns.length} vulnerabilities
            {selectedAgentObj ? ` on ${selectedAgentObj.hostname}` : ''}
          </p>
        )}
      </div>
    </RootLayout>
  );
}
