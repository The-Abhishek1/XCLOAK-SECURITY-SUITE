'use client';

import React, { useState, useEffect, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { vmAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';

type Tab = 'overview' | 'inventory' | 'assets' | 'surface' | 'patches' | 'threat-intel' | 'compliance' | 'analytics' | 'scans' | 'exceptions' | 'reports';
const TAB_LABELS: Record<Tab, string> = {
  overview: 'Dashboard', inventory: 'Inventory', assets: 'Asset Exposure',
  surface: 'Attack Surface', patches: 'Patch Management', 'threat-intel': 'Threat Intel',
  compliance: 'Compliance', analytics: 'Analytics', scans: 'Scan Management',
  exceptions: 'Exceptions', reports: 'Reports',
};

const SEV_COLOR: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };
const RISK_COLOR = (s: number) => s >= 90 ? '#ef4444' : s >= 70 ? '#f97316' : s >= 50 ? '#eab308' : '#22c55e';
const PATCH_COLOR: Record<string, string> = { pending: '#f97316', installed: '#22c55e', failed: '#ef4444', deferred: '#6b7280' };

function StatCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="g-card" style={{ padding: '14px 18px', minWidth: 120 }}>
      <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 700, color: color || 'var(--text-1)', lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 3 }}>{sub}</div>}
    </div>
  );
}

function SevBadge({ sev }: { sev: string }) {
  return <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 3, background: SEV_COLOR[sev] || '#6b7280', color: '#fff', textTransform: 'uppercase', letterSpacing: '0.04em' }}>{sev}</span>;
}

function KEVBadge() {
  return <span style={{ fontSize: 9, fontWeight: 700, padding: '2px 6px', borderRadius: 3, background: '#ef4444', color: '#fff', letterSpacing: '0.04em' }}>KEV</span>;
}

function EPSSBar({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const color = pct >= 70 ? '#ef4444' : pct >= 40 ? '#f97316' : '#eab308';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <div style={{ width: 60, background: 'var(--border)', borderRadius: 2, height: 5 }}>
        <div style={{ background: color, height: 5, borderRadius: 2, width: `${pct}%` }} />
      </div>
      <span style={{ fontSize: 10, color, fontWeight: 600 }}>{(score * 100).toFixed(1)}%</span>
    </div>
  );
}

// ─── Overview Tab ─────────────────────────────────────────────────────────────
function OverviewTab({ dash }: { dash: any }) {
  if (!dash) return <div style={{ color: 'var(--text-3)', padding: 40, textAlign: 'center' }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total" value={dash.total} />
        <StatCard label="Critical" value={dash.critical} color="#ef4444" />
        <StatCard label="High" value={dash.high} color="#f97316" />
        <StatCard label="Medium" value={dash.medium} color="#eab308" />
        <StatCard label="Low" value={dash.low} color="#22c55e" />
        <StatCard label="Exploitable" value={dash.exploitable} color="#f97316" sub="exploit available" />
        <StatCard label="Actively Exploited" value={dash.actively_exploited} color="#ef4444" sub="confirmed in-the-wild" />
        <StatCard label="KEV Listed" value={dash.kev_findings} color="#ef4444" sub="CISA catalog" />
        <StatCard label="Patched" value={dash.patched} color="#22c55e" />
        <StatCard label="Overdue" value={dash.overdue} color="#ef4444" sub="beyond SLA" />
        <StatCard label="Risk Score" value={dash.risk_score} color={RISK_COLOR(dash.risk_score)} />
        <StatCard label="MTTR" value={`${dash.mttr_days}d`} color="var(--accent)" sub="mean time to remediate" />
        <StatCard label="Patch SLA" value={`${dash.patch_sla_compliance}%`} color={dash.patch_sla_compliance >= 90 ? '#22c55e' : '#f97316'} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Severity Breakdown</div>
          {[{ l: 'Critical', c: dash.critical, col: '#ef4444' }, { l: 'High', c: dash.high, col: '#f97316' }, { l: 'Medium', c: dash.medium, col: '#eab308' }, { l: 'Low', c: dash.low, col: '#22c55e' }].map(item => (
            <div key={item.l} style={{ marginBottom: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 3 }}>
                <span style={{ color: item.col, fontWeight: 600 }}>{item.l}</span>
                <span>{item.c}</span>
              </div>
              <div style={{ background: 'var(--border)', borderRadius: 2, height: 8 }}>
                <div style={{ background: item.col, borderRadius: 2, height: 8, width: `${Math.min(100, (item.c / (dash.total || 1)) * 100)}%` }} />
              </div>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Risk Prioritization Factors</div>
          {[
            { label: 'CISA KEV Listed', value: dash.kev_findings, color: '#ef4444', icon: '🔴' },
            { label: 'Actively Exploited', value: dash.actively_exploited, color: '#ef4444', icon: '⚡' },
            { label: 'Exploit Available', value: dash.exploitable, color: '#f97316', icon: '💣' },
            { label: 'Internet-Facing Asset', value: 4, color: '#f97316', icon: '🌐' },
            { label: 'Critical Asset', value: 2, color: '#eab308', icon: '⭐' },
          ].map(item => (
            <div key={item.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
              <span>{item.icon} {item.label}</span>
              <span style={{ fontWeight: 700, color: item.color }}>{item.value}</span>
            </div>
          ))}
          <div style={{ marginTop: 10, fontSize: 11, color: 'var(--text-3)', fontStyle: 'italic' }}>
            Risk prioritization uses CVSS + EPSS + KEV + Asset Exposure — not CVSS alone.
          </div>
        </div>
      </div>

      {dash.kev_findings > 0 && (
        <div className="g-card" style={{ padding: 14, borderLeft: '3px solid #ef4444', background: '#ef444408' }}>
          <div style={{ fontWeight: 700, color: '#ef4444', marginBottom: 4 }}>⚠ CISA KEV Alert</div>
          <div style={{ fontSize: 13, color: 'var(--text-2)' }}>
            {dash.kev_findings} vulnerabilities are listed in the CISA Known Exploited Vulnerabilities catalog. Federal agencies are required to remediate these immediately. Apply patches or implement mitigations now.
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Inventory Tab ────────────────────────────────────────────────────────────
type DetailSub = 'overview' | 'asset-context' | 'threat-intel' | 'attack-path' | 'ai' | 'remediation' | 'timeline';

function InventoryTab({
  findings, selectedId, onSelect, onRefresh,
  findingDetail, aiResult, aiLoading,
  detailSub, setDetailSub, onAction,
  filterSev, setFilterSev, filterKev, setFilterKev,
  filterExploit, setFilterExploit, searchQ, setSearchQ,
}: {
  findings: any[]; selectedId: number | null; onSelect: (id: number) => void; onRefresh: () => void;
  findingDetail: any; aiResult: any; aiLoading: boolean;
  detailSub: DetailSub; setDetailSub: (t: DetailSub) => void; onAction: (id: number, action: string) => void;
  filterSev: string; setFilterSev: (v: string) => void;
  filterKev: boolean; setFilterKev: (v: boolean) => void;
  filterExploit: boolean; setFilterExploit: (v: boolean) => void;
  searchQ: string; setSearchQ: (v: string) => void;
}) {
  const filtered = useMemo(() => findings.filter(f => {
    if (filterSev && f.severity !== filterSev) return false;
    if (filterKev && !f.kev_listed) return false;
    if (filterExploit && !f.exploit_available) return false;
    if (searchQ) {
      const q = searchQ.toLowerCase();
      return f.cve_id.toLowerCase().includes(q) || f.vendor.toLowerCase().includes(q) || f.product.toLowerCase().includes(q) || f.asset_name.toLowerCase().includes(q);
    }
    return true;
  }), [findings, filterSev, filterKev, filterExploit, searchQ]);

  const SUBS: { key: DetailSub; label: string }[] = [
    { key: 'overview', label: 'Overview' }, { key: 'asset-context', label: 'Asset Context' },
    { key: 'threat-intel', label: 'Threat Intel' }, { key: 'attack-path', label: 'Attack Path' },
    { key: 'ai', label: 'AI Risk' }, { key: 'remediation', label: 'Remediation' },
    { key: 'timeline', label: 'Timeline' },
  ];

  return (
    <div style={{ display: 'flex', gap: 14, height: 'calc(100vh - 220px)', minHeight: 500 }}>
      {/* Left panel */}
      <div className="g-card" style={{ width: 340, flexShrink: 0, display: 'flex', flexDirection: 'column', padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '10px 12px 8px', borderBottom: '1px solid var(--border)' }}>
          <input className="g-input" placeholder="CVE, vendor, product, asset…" value={searchQ} onChange={e => setSearchQ(e.target.value)} style={{ width: '100%', marginBottom: 6, fontSize: 12 }} />
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            <select className="g-select" value={filterSev} onChange={e => setFilterSev(e.target.value)} style={{ fontSize: 10, padding: '3px 6px', flex: 1 }}>
              <option value="">All Severity</option>
              {['critical','high','medium','low'].map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase()+s.slice(1)}</option>)}
            </select>
            <button onClick={() => setFilterKev(!filterKev)} className={filterKev ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} style={{ fontSize: 10, padding: '3px 8px' }}>KEV</button>
            <button onClick={() => setFilterExploit(!filterExploit)} className={filterExploit ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} style={{ fontSize: 10, padding: '3px 8px' }}>Exploit</button>
            <button onClick={onRefresh} className="g-btn g-btn-ghost" style={{ fontSize: 10, padding: '3px 6px' }}>↻</button>
          </div>
        </div>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {filtered.length === 0 && <div style={{ padding: 20, color: 'var(--text-3)', fontSize: 13, textAlign: 'center' }}>No findings</div>}
          {filtered.map(f => (
            <div key={f.id} onClick={() => onSelect(f.id)}
              style={{ padding: '9px 12px', borderBottom: '1px solid var(--border)', cursor: 'pointer', background: selectedId === f.id ? 'var(--accent)12' : 'transparent', borderLeft: selectedId === f.id ? '3px solid var(--accent)' : '3px solid transparent' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
                <span style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 700, color: SEV_COLOR[f.severity] }}>{f.cve_id}</span>
                {f.kev_listed && <KEVBadge />}
                {f.actively_exploited && <span style={{ fontSize: 9, background: '#f97316', color: '#fff', padding: '1px 5px', borderRadius: 3, fontWeight: 700 }}>EXPLOITED</span>}
                <span style={{ marginLeft: 'auto' }}><SevBadge sev={f.severity} /></span>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-2)', marginBottom: 3 }}>{f.vendor} · {f.product}</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: RISK_COLOR(f.cvss_score * 10) }}>CVSS {f.cvss_score.toFixed(1)}</span>
                <EPSSBar score={f.epss_score} />
                <span style={{ fontSize: 10, color: 'var(--text-3)', marginLeft: 'auto' }}>{f.asset_name}</span>
              </div>
              {f.internet_facing && <span style={{ fontSize: 9, color: '#3b82f6', fontWeight: 600 }}>🌐 Internet-facing</span>}
            </div>
          ))}
        </div>
      </div>

      {/* Right panel */}
      {!findingDetail ? (
        <div className="g-card" style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 10 }}>
          <div style={{ fontSize: 32 }}>🛡</div>
          <div style={{ color: 'var(--text-3)', fontSize: 14 }}>Select a finding to review</div>
        </div>
      ) : (
        <div className="g-card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: 0 }}>
          {/* Header */}
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 6 }}>
              <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: 16, color: SEV_COLOR[findingDetail.severity] }}>{findingDetail.cve_id}</span>
              {findingDetail.kev_listed && <KEVBadge />}
              {findingDetail.actively_exploited && <span style={{ fontSize: 10, background: '#f97316', color: '#fff', padding: '2px 7px', borderRadius: 3, fontWeight: 700 }}>ACTIVELY EXPLOITED</span>}
              <SevBadge sev={findingDetail.severity} />
              <span style={{ fontSize: 12, fontWeight: 700, color: RISK_COLOR(findingDetail.risk_score), background: RISK_COLOR(findingDetail.risk_score)+'22', padding: '2px 8px', borderRadius: 4, border: `1px solid ${RISK_COLOR(findingDetail.risk_score)}44` }}>Risk {findingDetail.risk_score}</span>
              <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-3)' }}>{findingDetail.status.replace('_',' ')} · {findingDetail.scan_type} scan</span>
            </div>
            <div style={{ display: 'flex', gap: 16, fontSize: 12, flexWrap: 'wrap' }}>
              <span>CVSS: <strong style={{ color: RISK_COLOR(findingDetail.cvss_score * 10) }}>{findingDetail.cvss_score.toFixed(1)}</strong></span>
              <span>EPSS: <strong style={{ color: findingDetail.epss_score > 0.5 ? '#ef4444' : '#f97316' }}>{(findingDetail.epss_score * 100).toFixed(1)}%</strong></span>
              <span>Vendor: <strong>{findingDetail.vendor}</strong></span>
              <span>Product: <strong>{findingDetail.product}</strong></span>
              <span>Asset: <strong style={{ color: 'var(--accent)' }}>{findingDetail.asset_name}</strong></span>
              {findingDetail.internet_facing && <span style={{ color: '#3b82f6', fontWeight: 600 }}>🌐 Internet-facing</span>}
            </div>
          </div>

          {/* Sub-tabs */}
          <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', paddingLeft: 16, overflowX: 'auto' }}>
            {SUBS.map(s => (
              <button key={s.key} onClick={() => setDetailSub(s.key)}
                style={{ padding: '7px 12px', fontSize: 11, fontWeight: detailSub === s.key ? 600 : 400, color: detailSub === s.key ? 'var(--accent)' : 'var(--text-3)', background: 'transparent', border: 'none', borderBottom: detailSub === s.key ? '2px solid var(--accent)' : '2px solid transparent', cursor: 'pointer', whiteSpace: 'nowrap' }}>
                {s.label}
              </button>
            ))}
          </div>

          {/* Sub-tab body */}
          <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>

            {detailSub === 'overview' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                <div className="g-card" style={{ padding: 14 }}>
                  <div style={{ fontWeight: 600, marginBottom: 8 }}>Description</div>
                  <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.5 }}>{findingDetail.description}</div>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  <div className="g-card" style={{ padding: 12 }}>
                    <div style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 8 }}>CVE Details</div>
                    {[['CVSS Score', findingDetail.cvss_score.toFixed(1)], ['CVSS Vector', findingDetail.cvss_vector], ['EPSS Score', `${(findingDetail.epss_score*100).toFixed(1)}% (${findingDetail.epss_percentile.toFixed(0)}th percentile)`], ['KEV Listed', findingDetail.kev_listed ? `Yes (added ${findingDetail.kev_date_added})` : 'No'], ['Exploit Maturity', findingDetail.exploit_maturity], ['Published', findingDetail.published_at ? new Date(findingDetail.published_at).toLocaleDateString() : '—']].map(([k,v]) => (
                      <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 5, gap: 8 }}>
                        <span style={{ color: 'var(--text-3)', flexShrink: 0 }}>{k}</span>
                        <span style={{ fontWeight: 500, textAlign: 'right', color: k === 'KEV Listed' && findingDetail.kev_listed ? '#ef4444' : 'var(--text-1)', wordBreak: 'break-all' }}>{String(v) || '—'}</span>
                      </div>
                    ))}
                  </div>
                  <div className="g-card" style={{ padding: 12 }}>
                    <div style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 8 }}>Affected Software</div>
                    {[['Vendor', findingDetail.vendor], ['Product', findingDetail.product], ['Affected Versions', findingDetail.affected_versions], ['Fixed Version', findingDetail.fixed_version], ['Patch Available', findingDetail.patch_available ? 'Yes' : 'No']].map(([k,v]) => (
                      <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 5, gap: 8 }}>
                        <span style={{ color: 'var(--text-3)', flexShrink: 0 }}>{k}</span>
                        <span style={{ fontWeight: 500, textAlign: 'right', color: k === 'Patch Available' ? (v === 'Yes' ? '#22c55e' : '#ef4444') : 'var(--text-1)', wordBreak: 'break-all' }}>{String(v) || '—'}</span>
                      </div>
                    ))}
                  </div>
                </div>
                {findingDetail.cisa_advisory && (
                  <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #ef4444' }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: '#ef4444', marginBottom: 4 }}>CISA Advisory</div>
                    <div style={{ fontSize: 13, color: 'var(--text-2)' }}>{findingDetail.cisa_advisory}</div>
                  </div>
                )}
              </div>
            )}

            {detailSub === 'asset-context' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                <div className="g-card" style={{ padding: 14 }}>
                  <div style={{ fontWeight: 600, marginBottom: 10 }}>Asset: {findingDetail.asset_name}</div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                    {[['IP Address', findingDetail.asset_ip], ['Criticality', findingDetail.asset_criticality], ['Internet Facing', findingDetail.internet_facing ? 'YES' : 'No'], ['Risk Score', findingDetail.risk_score]].map(([k,v]) => (
                      <div key={k}>
                        <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{k}</div>
                        <div style={{ fontSize: 13, fontWeight: 600, color: k === 'Internet Facing' && v === 'YES' ? '#ef4444' : k === 'Criticality' && v === 'critical' ? '#ef4444' : 'var(--text-1)' }}>{String(v)}</div>
                      </div>
                    ))}
                  </div>
                </div>
                <div className="g-card" style={{ padding: 14 }}>
                  <div style={{ fontWeight: 600, marginBottom: 8, fontSize: 12 }}>Why This Vulnerability Matters Here</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {findingDetail.internet_facing && <div style={{ fontSize: 12, color: '#ef4444' }}>• Asset is internet-facing — attackers can reach this vulnerability directly without network access</div>}
                    {findingDetail.asset_criticality === 'critical' && <div style={{ fontSize: 12, color: '#ef4444' }}>• Asset is rated critical — compromise has significant business impact</div>}
                    {findingDetail.kev_listed && <div style={{ fontSize: 12, color: '#f97316' }}>• CVE is in CISA KEV — confirmed exploitation in the wild, not theoretical</div>}
                    {findingDetail.actively_exploited && <div style={{ fontSize: 12, color: '#f97316' }}>• Actively exploited by threat actors as of scan date</div>}
                  </div>
                </div>
                <div className="g-card" style={{ padding: 14 }}>
                  <div style={{ fontWeight: 600, marginBottom: 8, fontSize: 12 }}>Asset Context</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12 }}>
                    <div><span style={{ color: 'var(--text-3)' }}>Business Application: </span><span>Corporate VPN gateway — primary remote access for 2,400 employees</span></div>
                    <div><span style={{ color: 'var(--text-3)' }}>Network Zone: </span><span>DMZ</span></div>
                    <div><span style={{ color: 'var(--text-3)' }}>Owner: </span><span>network-ops@corp.com</span></div>
                    <div><span style={{ color: 'var(--text-3)' }}>Related Incidents: </span><span style={{ color: 'var(--accent)' }}>None open</span></div>
                    <div><span style={{ color: 'var(--text-3)' }}>Running Services: </span><span style={{ fontFamily: 'monospace', fontSize: 11 }}>GlobalProtect (4443), HTTPS (443), SSH (22)</span></div>
                  </div>
                </div>
              </div>
            )}

            {detailSub === 'threat-intel' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                <div className="g-card" style={{ padding: 14, borderLeft: '3px solid #ef4444' }}>
                  <div style={{ fontWeight: 600, marginBottom: 8 }}>Exploitation Status</div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
                    <div style={{ textAlign: 'center', padding: 10, background: findingDetail.actively_exploited ? '#ef444422' : 'var(--bg)', borderRadius: 6, border: `1px solid ${findingDetail.actively_exploited ? '#ef4444' : 'var(--border)'}` }}>
                      <div style={{ fontSize: 20 }}>{findingDetail.actively_exploited ? '⚡' : '—'}</div>
                      <div style={{ fontSize: 11, fontWeight: 600, color: findingDetail.actively_exploited ? '#ef4444' : 'var(--text-3)' }}>In-the-Wild</div>
                    </div>
                    <div style={{ textAlign: 'center', padding: 10, background: findingDetail.exploit_available ? '#f9731622' : 'var(--bg)', borderRadius: 6, border: `1px solid ${findingDetail.exploit_available ? '#f97316' : 'var(--border)'}` }}>
                      <div style={{ fontSize: 20 }}>{findingDetail.exploit_available ? '💣' : '—'}</div>
                      <div style={{ fontSize: 11, fontWeight: 600, color: findingDetail.exploit_available ? '#f97316' : 'var(--text-3)' }}>Public Exploit</div>
                    </div>
                    <div style={{ textAlign: 'center', padding: 10, background: findingDetail.kev_listed ? '#ef444422' : 'var(--bg)', borderRadius: 6, border: `1px solid ${findingDetail.kev_listed ? '#ef4444' : 'var(--border)'}` }}>
                      <div style={{ fontSize: 20 }}>{findingDetail.kev_listed ? '📋' : '—'}</div>
                      <div style={{ fontSize: 11, fontWeight: 600, color: findingDetail.kev_listed ? '#ef4444' : 'var(--text-3)' }}>CISA KEV</div>
                    </div>
                  </div>
                </div>
                {findingDetail.malware_families && (
                  <div className="g-card" style={{ padding: 14 }}>
                    <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 6 }}>Associated Malware</div>
                    <div style={{ fontSize: 13, color: '#ef4444', fontWeight: 600 }}>{findingDetail.malware_families}</div>
                  </div>
                )}
                {findingDetail.threat_actors && (
                  <div className="g-card" style={{ padding: 14 }}>
                    <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 6 }}>Associated Threat Actors</div>
                    <div style={{ fontSize: 13, color: 'var(--text-1)' }}>{findingDetail.threat_actors}</div>
                  </div>
                )}
                <div className="g-card" style={{ padding: 14 }}>
                  <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 6 }}>EPSS Context</div>
                  <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.5 }}>
                    EPSS score of <strong style={{ color: '#ef4444' }}>{(findingDetail.epss_score*100).toFixed(1)}%</strong> means this CVE is in the top {(100-findingDetail.epss_percentile).toFixed(0)}% most likely to be exploited among all published CVEs. This is significantly higher than the CVSS score alone would suggest.
                  </div>
                </div>
              </div>
            )}

            {detailSub === 'attack-path' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                <div className="g-card" style={{ padding: 14 }}>
                  <div style={{ fontWeight: 600, marginBottom: 12 }}>Attack Path: Internet → {findingDetail.asset_name} → Internal</div>
                  {[
                    { node: 'Internet', type: 'source', icon: '🌐', desc: 'Attacker on public internet' },
                    { node: findingDetail.asset_name, type: 'entry', icon: '🎯', desc: `Exploit ${findingDetail.cve_id} — CVSS ${findingDetail.cvss_score.toFixed(1)}, ${findingDetail.exploit_maturity} exploit available` },
                    { node: 'Internal Network', type: 'pivot', icon: '↔', desc: 'Lateral movement across network segments' },
                    { node: 'Domain Admin / Data', type: 'objective', icon: '👑', desc: 'Credential theft, data exfiltration, or ransomware deployment' },
                  ].map((step, i, arr) => (
                    <div key={step.node} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: i < arr.length - 1 ? 0 : 0 }}>
                      <div style={{ padding: '10px 16px', border: `2px solid ${step.type === 'source' ? '#6b7280' : step.type === 'entry' ? '#ef4444' : step.type === 'pivot' ? '#f97316' : '#a855f7'}`, borderRadius: 8, background: step.type === 'entry' ? '#ef444408' : step.type === 'objective' ? '#a855f708' : 'var(--bg)', width: '100%', maxWidth: 440, textAlign: 'center' }}>
                        <div style={{ fontSize: 18, marginBottom: 4 }}>{step.icon}</div>
                        <div style={{ fontWeight: 700, fontSize: 13 }}>{step.node}</div>
                        <div style={{ fontSize: 12, color: 'var(--text-2)', marginTop: 3 }}>{step.desc}</div>
                      </div>
                      {i < arr.length - 1 && <div style={{ fontSize: 20, color: 'var(--text-3)', margin: '4px 0' }}>↓</div>}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {detailSub === 'ai' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {aiLoading && <div style={{ color: 'var(--text-3)', padding: 24, textAlign: 'center' }}>AI analyzing risk…</div>}
                {!aiLoading && !aiResult && <div style={{ color: 'var(--text-3)', padding: 24, textAlign: 'center' }}>No AI result.</div>}
                {aiResult && (
                  <>
                    <div className="g-card" style={{ padding: 14, borderLeft: `3px solid ${aiResult.priority === 'immediate' ? '#ef4444' : aiResult.priority === 'high' ? '#f97316' : '#eab308'}` }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                        <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-3)' }}>AI Priority</span>
                        <span style={{ fontSize: 13, fontWeight: 700, padding: '2px 10px', borderRadius: 4, background: (aiResult.priority === 'immediate' ? '#ef4444' : aiResult.priority === 'high' ? '#f97316' : '#eab308') + '22', color: aiResult.priority === 'immediate' ? '#ef4444' : aiResult.priority === 'high' ? '#f97316' : '#eab308', textTransform: 'uppercase' }}>{aiResult.priority}</span>
                      </div>
                      <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.5, marginBottom: 8 }}>{aiResult.risk_summary}</div>
                      <div style={{ fontSize: 12, color: 'var(--text-3)' }}>{aiResult.priority_reason}</div>
                    </div>
                    {aiResult.attack_scenario && (
                      <div className="g-card" style={{ padding: 14, borderLeft: '3px solid #ef4444' }}>
                        <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 6 }}>Attack Scenario</div>
                        <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.5 }}>{aiResult.attack_scenario}</div>
                      </div>
                    )}
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                      {aiResult.risk_factors?.length > 0 && (
                        <div className="g-card" style={{ padding: 12 }}>
                          <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 6 }}>Risk Factors</div>
                          {aiResult.risk_factors.map((r: string, i: number) => <div key={i} style={{ fontSize: 12, color: '#ef4444', marginBottom: 4 }}>• {r}</div>)}
                        </div>
                      )}
                      {aiResult.mitigating_factors?.length > 0 && (
                        <div className="g-card" style={{ padding: 12 }}>
                          <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 6 }}>Mitigating Factors</div>
                          {aiResult.mitigating_factors.map((r: string, i: number) => <div key={i} style={{ fontSize: 12, color: '#22c55e', marginBottom: 4 }}>• {r}</div>)}
                        </div>
                      )}
                    </div>
                    {aiResult.recommended_action && (
                      <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #22c55e' }}>
                        <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 6 }}>Recommended Action</div>
                        <div style={{ fontSize: 13, color: 'var(--text-2)' }}>{aiResult.recommended_action}</div>
                        {aiResult.estimated_effort && <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>Estimated effort: {aiResult.estimated_effort}</div>}
                      </div>
                    )}
                    <div style={{ fontSize: 11, color: 'var(--text-3)', fontStyle: 'italic' }}>AI risk analysis considers CVSS + EPSS + KEV + asset exposure — not CVSS score alone.</div>
                  </>
                )}
              </div>
            )}

            {detailSub === 'remediation' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                <div className="g-card" style={{ padding: 14, borderLeft: '3px solid #22c55e' }}>
                  <div style={{ fontWeight: 600, marginBottom: 8 }}>Patch Remediation</div>
                  <div style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 8 }}>
                    <strong>Fixed in:</strong> {findingDetail.fixed_version || 'Contact vendor'}<br />
                    {findingDetail.patch_url && <><strong>Patch URL:</strong> <span style={{ color: 'var(--accent)' }}>{findingDetail.patch_url}</span></>}
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button className="g-btn g-btn-primary" style={{ fontSize: 12 }} onClick={() => onAction(findingDetail.id, 'mark_patched')}>Mark as Patched</button>
                    <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }}>Launch Patch Job</button>
                    <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }}>Create Ticket</button>
                  </div>
                </div>
                <div className="g-card" style={{ padding: 14 }}>
                  <div style={{ fontWeight: 600, marginBottom: 8 }}>Response Actions</div>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }}>📋 Create Incident</button>
                    <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }}>▶ Run SOAR Playbook</button>
                    <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }}>📧 Notify Asset Owner</button>
                    <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }}>✓ Verify Remediation</button>
                    <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={() => onAction(findingDetail.id, 'accept_risk')}>Accept Risk</button>
                    <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={() => onAction(findingDetail.id, 'defer')}>Defer</button>
                  </div>
                </div>
                {findingDetail.cisa_advisory && (
                  <div className="g-card" style={{ padding: 14 }}>
                    <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 6 }}>Vendor Advisory</div>
                    <div style={{ fontSize: 13, color: 'var(--text-2)' }}>{findingDetail.cisa_advisory}</div>
                    <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 6 }}>Restart Required: Check vendor advisory · Estimated Downtime: 30 min maintenance window</div>
                  </div>
                )}
              </div>
            )}

            {detailSub === 'timeline' && (
              <div>
                {[
                  { label: 'CVE Published', date: findingDetail.published_at, icon: '📄', done: !!findingDetail.published_at },
                  { label: 'Asset Scanned', date: findingDetail.detected_at, icon: '🔍', done: true },
                  { label: 'Detected', date: findingDetail.detected_at, icon: '⚠', done: true },
                  { label: 'Patch Released', date: findingDetail.patch_released_at, icon: '📦', done: !!findingDetail.patch_released_at },
                  { label: 'Patched', date: findingDetail.patched_at, icon: '✅', done: !!findingDetail.patched_at },
                  { label: 'Verified', date: findingDetail.verified_at, icon: '☑', done: !!findingDetail.verified_at },
                ].map((step, i, arr) => (
                  <div key={step.label} style={{ display: 'flex', gap: 12, paddingBottom: 16 }}>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: 32 }}>
                      <div style={{ width: 28, height: 28, borderRadius: '50%', background: step.done ? 'var(--accent)' : 'var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 13, flexShrink: 0 }}>{step.icon}</div>
                      {i < arr.length - 1 && <div style={{ flex: 1, width: 2, background: 'var(--border)', marginTop: 4 }} />}
                    </div>
                    <div style={{ paddingTop: 4 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, color: step.done ? 'var(--text-1)' : 'var(--text-3)' }}>{step.label}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{step.date ? new Date(step.date).toLocaleDateString() + ' · ' + timeAgo(step.date) : 'Pending'}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Assets Tab ───────────────────────────────────────────────────────────────
function AssetsTab({ assets }: { assets: any[] }) {
  const [selectedAsset, setSelectedAsset] = useState<any>(null);
  return (
    <div className="g-card" style={{ overflow: 'hidden' }}>
      <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontWeight: 600 }}>Asset Exposure ({assets.length} assets)</span>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table className="g-table" style={{ width: '100%' }}>
          <thead className="g-thead">
            <tr>
              {['Host', 'IP', 'OS', 'Owner', 'Business Unit', 'Internet', 'Risk', 'Criticality', 'Vulns', 'Critical', 'Last Scanned'].map(h => (
                <th key={h} className="g-tr" style={{ padding: '8px 12px', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-3)', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {assets.map(a => (
              <tr key={a.id} onClick={() => setSelectedAsset(selectedAsset?.id === a.id ? null : a)} style={{ borderBottom: '1px solid var(--border)', cursor: 'pointer', background: selectedAsset?.id === a.id ? 'var(--accent)08' : 'transparent' }}>
                <td style={{ padding: '9px 12px', fontSize: 13, fontWeight: 600, whiteSpace: 'nowrap' }}>{a.hostname}</td>
                <td style={{ padding: '9px 12px', fontSize: 11, fontFamily: 'monospace', color: 'var(--text-3)' }}>{a.ip_address}</td>
                <td style={{ padding: '9px 12px', fontSize: 11, color: 'var(--text-2)' }}>{a.os} {a.os_version}</td>
                <td style={{ padding: '9px 12px', fontSize: 11, color: 'var(--text-2)' }}>{a.owner?.split('@')[0]}</td>
                <td style={{ padding: '9px 12px', fontSize: 11, color: 'var(--text-2)' }}>{a.business_unit}</td>
                <td style={{ padding: '9px 12px', textAlign: 'center' }}>{a.internet_facing ? <span style={{ color: '#ef4444', fontWeight: 700, fontSize: 12 }}>YES</span> : <span style={{ color: 'var(--text-3)', fontSize: 12 }}>No</span>}</td>
                <td style={{ padding: '9px 12px' }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: RISK_COLOR(a.risk_score) }}>{a.risk_score.toFixed(0)}</span>
                </td>
                <td style={{ padding: '9px 12px' }}><SevBadge sev={a.criticality} /></td>
                <td style={{ padding: '9px 12px', fontSize: 13, fontWeight: 600, textAlign: 'center' }}>{a.vuln_count}</td>
                <td style={{ padding: '9px 12px', fontSize: 13, fontWeight: 700, color: a.critical_count > 0 ? '#ef4444' : 'var(--text-2)', textAlign: 'center' }}>{a.critical_count}</td>
                <td style={{ padding: '9px 12px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{a.last_scanned_at ? timeAgo(a.last_scanned_at) : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {selectedAsset && (
        <div style={{ padding: '16px', borderTop: '1px solid var(--border)', background: 'var(--bg)' }}>
          <div style={{ fontWeight: 600, marginBottom: 10 }}>Asset Context: {selectedAsset.hostname}</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, fontSize: 12 }}>
            <div><div style={{ color: 'var(--text-3)', marginBottom: 2 }}>Network Zone</div><div style={{ fontWeight: 600 }}>{selectedAsset.network_zone}</div></div>
            <div><div style={{ color: 'var(--text-3)', marginBottom: 2 }}>Asset Value</div><div style={{ fontWeight: 600, textTransform: 'capitalize' }}>{selectedAsset.asset_value}</div></div>
            <div><div style={{ color: 'var(--text-3)', marginBottom: 2 }}>Open Vulnerabilities</div><div style={{ fontWeight: 700, color: '#ef4444' }}>{selectedAsset.critical_count} critical, {selectedAsset.high_count} high</div></div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Attack Surface Tab ───────────────────────────────────────────────────────
function SurfaceTab({ surface }: { surface: any }) {
  if (!surface) return <div style={{ color: 'var(--text-3)', padding: 40, textAlign: 'center' }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <StatCard label="Internet Exposed" value={surface.internet_exposed_assets} color="#ef4444" sub="assets" />
        <StatCard label="Open Ports" value={surface.open_ports_total} />
        <StatCard label="Expired Certs" value={surface.certificates?.filter((c: any) => c.expired).length || 0} color="#ef4444" />
        <StatCard label="Critical FW Rules" value={surface.firewall_exposure?.filter((r: any) => r.risk === 'critical').length || 0} color="#ef4444" />
      </div>

      <div className="g-card" style={{ overflow: 'hidden' }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', fontWeight: 600 }}>Exposed Services</div>
        <table className="g-table" style={{ width: '100%' }}>
          <thead className="g-thead"><tr>
            {['Service', 'Port', 'Assets', 'Risk', 'Notes'].map(h => <th key={h} className="g-tr" style={{ padding: '8px 14px', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left' }}>{h}</th>)}
          </tr></thead>
          <tbody>
            {surface.exposed_services?.map((s: any, i: number) => (
              <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '9px 14px', fontSize: 12, fontWeight: 600 }}>{s.service}</td>
                <td style={{ padding: '9px 14px', fontSize: 11, fontFamily: 'monospace', color: 'var(--text-3)' }}>{s.port}</td>
                <td style={{ padding: '9px 14px', fontSize: 12 }}>{s.assets}</td>
                <td style={{ padding: '9px 14px' }}>
                  {s.vulnerable_version && <span style={{ fontSize: 10, background: '#ef4444', color: '#fff', padding: '2px 6px', borderRadius: 3, fontWeight: 700 }}>VULNERABLE</span>}
                  {s.risk && !s.vulnerable_version && <SevBadge sev={s.risk} />}
                </td>
                <td style={{ padding: '9px 14px', fontSize: 12, color: 'var(--text-2)' }}>{s.notes || (s.cve ? `CVE: ${s.cve}` : '—')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 14 }}>
          <div style={{ fontWeight: 600, marginBottom: 10 }}>TLS Certificates</div>
          {surface.certificates?.map((cert: any, i: number) => (
            <div key={i} style={{ padding: '8px 0', borderBottom: i < surface.certificates.length - 1 ? '1px solid var(--border)' : 'none' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 12, fontFamily: 'monospace', flex: 1 }}>{cert.domain}</span>
                <span style={{ fontSize: 11, fontWeight: 700, color: cert.expired ? '#ef4444' : cert.days_remaining < 30 ? '#f97316' : '#22c55e' }}>
                  {cert.expired ? `EXPIRED ${Math.abs(cert.days_remaining)}d ago` : `${cert.days_remaining}d left`}
                </span>
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{cert.issuer} · {cert.strength}</div>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: 14 }}>
          <div style={{ fontWeight: 600, marginBottom: 10 }}>Firewall Exposure</div>
          {surface.firewall_exposure?.map((r: any, i: number) => (
            <div key={i} style={{ padding: '8px 0', borderBottom: i < surface.firewall_exposure.length - 1 ? '1px solid var(--border)' : 'none' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
                <span style={{ fontSize: 10, fontFamily: 'monospace', flex: 1, color: 'var(--text-2)' }}>{r.rule}</span>
                <SevBadge sev={r.risk} />
              </div>
              <div style={{ fontSize: 11, color: '#22c55e' }}>→ {r.recommendation}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Patches Tab ──────────────────────────────────────────────────────────────
function PatchesTab({ patches, onPatchAction }: { patches: any[]; onPatchAction: (id: number, action: string) => void }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        {['pending', 'installed', 'failed', 'deferred'].map(s => (
          <StatCard key={s} label={s.charAt(0).toUpperCase()+s.slice(1)} value={patches.filter(p => p.patch_status === s).length} color={PATCH_COLOR[s]} />
        ))}
      </div>
      <div className="g-card" style={{ overflow: 'hidden' }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', fontWeight: 600 }}>Patch Tracking</div>
        <div style={{ overflowX: 'auto' }}>
          <table className="g-table" style={{ width: '100%' }}>
            <thead className="g-thead"><tr>
              {['CVE', 'Asset', 'Patch', 'Status', 'Restart', 'Downtime', 'Assigned To', 'Scheduled', 'Actions'].map(h => (
                <th key={h} className="g-tr" style={{ padding: '8px 12px', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
              ))}
            </tr></thead>
            <tbody>
              {patches.map(p => (
                <tr key={p.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '9px 12px', fontSize: 12, fontWeight: 700, fontFamily: 'monospace', color: 'var(--accent)' }}>{p.cve_id}</td>
                  <td style={{ padding: '9px 12px', fontSize: 12 }}>{p.asset_name}</td>
                  <td style={{ padding: '9px 12px', fontSize: 11, color: 'var(--text-2)' }}>{p.patch_version || '—'}</td>
                  <td style={{ padding: '9px 12px' }}>
                    <span style={{ fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 10, background: (PATCH_COLOR[p.patch_status] || '#6b7280') + '22', color: PATCH_COLOR[p.patch_status] || '#6b7280', border: `1px solid ${(PATCH_COLOR[p.patch_status]||'#6b7280')}44`, textTransform: 'capitalize' }}>
                      {p.patch_status}
                    </span>
                  </td>
                  <td style={{ padding: '9px 12px', fontSize: 12, textAlign: 'center' }}>{p.restart_required ? '⚠ Yes' : 'No'}</td>
                  <td style={{ padding: '9px 12px', fontSize: 12, color: 'var(--text-2)' }}>{p.estimated_downtime ? `${p.estimated_downtime}m` : '—'}</td>
                  <td style={{ padding: '9px 12px', fontSize: 11, color: 'var(--text-2)' }}>{p.assigned_to?.split('@')[0] || '—'}</td>
                  <td style={{ padding: '9px 12px', fontSize: 11, color: 'var(--text-3)' }}>{p.scheduled_at ? new Date(p.scheduled_at).toLocaleDateString() : '—'}</td>
                  <td style={{ padding: '9px 12px' }}>
                    <div style={{ display: 'flex', gap: 4 }}>
                      {p.patch_status === 'pending' && <button className="g-btn g-btn-primary" style={{ fontSize: 10, padding: '2px 7px' }} onClick={() => onPatchAction(p.id, 'install')}>Install</button>}
                      {p.patch_status === 'pending' && <button className="g-btn g-btn-ghost" style={{ fontSize: 10, padding: '2px 7px' }} onClick={() => onPatchAction(p.id, 'defer')}>Defer</button>}
                      {p.patch_status === 'failed' && <button className="g-btn g-btn-ghost" style={{ fontSize: 10, padding: '2px 7px' }} onClick={() => onPatchAction(p.id, 'install')}>Retry</button>}
                      {p.rollback_available && <button className="g-btn g-btn-ghost" style={{ fontSize: 10, padding: '2px 7px' }} onClick={() => onPatchAction(p.id, 'rollback')}>Rollback</button>}
                    </div>
                    {p.failure_reason && <div style={{ fontSize: 10, color: '#ef4444', marginTop: 3 }}>{p.failure_reason.substring(0, 40)}…</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ─── Threat Intel Tab ─────────────────────────────────────────────────────────
function ThreatIntelTab({ ti }: { ti: any }) {
  if (!ti) return <div style={{ color: 'var(--text-3)', padding: 40, textAlign: 'center' }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="g-card" style={{ padding: 14 }}>
        <div style={{ fontWeight: 600, marginBottom: 10 }}>CISA KEV Catalog — Matched Findings</div>
        {ti.kev_catalog?.map((k: any) => (
          <div key={k.cve} style={{ padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: 13, color: '#ef4444' }}>{k.cve}</span>
              <KEVBadge />
              <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{k.vendor} · {k.product}</span>
              <span style={{ fontSize: 11, color: 'var(--text-3)', marginLeft: 'auto' }}>Added {k.date_added} · Due {k.due_date}</span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-2)' }}>{k.notes}</div>
          </div>
        ))}
      </div>
      <div className="g-card" style={{ padding: 14 }}>
        <div style={{ fontWeight: 600, marginBottom: 10 }}>Active Exploitation — Confirmed Threat Actor Activity</div>
        {ti.active_exploitation?.map((e: any) => (
          <div key={e.cve} style={{ padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 4 }}>
              <span style={{ fontFamily: 'monospace', fontWeight: 700, color: '#ef4444' }}>{e.cve}</span>
              <span style={{ fontSize: 12, color: 'var(--text-2)' }}>Threat Actor: <strong>{e.threat_actor}</strong></span>
              <span style={{ fontSize: 12, color: 'var(--text-2)' }}>Malware: <strong style={{ color: '#ef4444' }}>{e.malware}</strong></span>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-3)' }}>Campaign: {e.campaign} · First observed: {e.first_observed}</div>
          </div>
        ))}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 14 }}>
          <div style={{ fontWeight: 600, marginBottom: 10 }}>Exploit Availability</div>
          {ti.exploit_availability?.map((e: any) => (
            <div key={e.cve} style={{ padding: '8px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
                <span style={{ fontFamily: 'monospace', fontWeight: 700, color: 'var(--accent)' }}>{e.cve}</span>
                <span style={{ fontSize: 10, padding: '1px 6px', borderRadius: 3, background: e.maturity === 'weaponized' ? '#ef444422' : '#f9731622', color: e.maturity === 'weaponized' ? '#ef4444' : '#f97316', fontWeight: 600, textTransform: 'capitalize' }}>{e.maturity}</span>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                {e.public_poc && <span style={{ fontSize: 10, color: '#22c55e' }}>✓ Public PoC</span>}
                {e.metasploit && <span style={{ fontSize: 10, color: '#ef4444' }}>✓ Metasploit</span>}
                {e.exploit_db && <span style={{ fontSize: 10, color: '#f97316' }}>✓ Exploit-DB</span>}
              </div>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: 14 }}>
          <div style={{ fontWeight: 600, marginBottom: 10 }}>Threat Actors</div>
          {ti.threat_actors?.map((a: any) => (
            <div key={a.name} style={{ padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 3 }}>
                <span style={{ fontSize: 12, fontWeight: 700 }}>{a.name}</span>
                {a.aliases && <span style={{ fontSize: 10, color: 'var(--text-3)' }}>({a.aliases})</span>}
                <span style={{ fontSize: 10, color: 'var(--text-3)', marginLeft: 'auto' }}>{a.country} · {a.motivation}</span>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-2)' }}>Targets: {a.target_sectors}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Compliance Tab ───────────────────────────────────────────────────────────
function ComplianceTab({ compliance }: { compliance: any }) {
  const [activeFramework, setActiveFramework] = useState(0);
  if (!compliance) return <div style={{ color: 'var(--text-3)', padding: 40, textAlign: 'center' }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Overall Score" value={`${compliance.overall_score}%`} color={compliance.overall_score >= 80 ? '#22c55e' : '#f97316'} />
        <StatCard label="Failed Controls" value={compliance.failed_controls} color="#ef4444" />
        <StatCard label="Missing Patches" value={compliance.missing_patches} color="#f97316" />
        <StatCard label="SLA Violations" value={compliance.sla_violations} color="#f97316" />
      </div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {compliance.frameworks?.map((fw: any, i: number) => (
          <button key={fw.name} onClick={() => setActiveFramework(i)} className={activeFramework === i ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} style={{ fontSize: 12 }}>
            {fw.name}
            <span style={{ marginLeft: 6, fontSize: 11, color: activeFramework === i ? 'inherit' : fw.status === 'failing' ? '#ef4444' : '#f97316' }}>{fw.score.toFixed(0)}%</span>
          </button>
        ))}
      </div>
      {compliance.frameworks?.[activeFramework] && (
        <div className="g-card" style={{ overflow: 'hidden' }}>
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontWeight: 600 }}>{compliance.frameworks[activeFramework].name}</span>
            <span style={{ fontSize: 12, color: compliance.frameworks[activeFramework].status === 'failing' ? '#ef4444' : '#f97316', fontWeight: 700 }}>{compliance.frameworks[activeFramework].score.toFixed(0)}% · {compliance.frameworks[activeFramework].status}</span>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table className="g-table" style={{ width: '100%' }}>
              <thead className="g-thead"><tr>
                {['Control ID', 'Title', 'Status', 'Finding'].map(h => <th key={h} className="g-tr" style={{ padding: '8px 14px', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left' }}>{h}</th>)}
              </tr></thead>
              <tbody>
                {compliance.frameworks[activeFramework].controls?.map((ctrl: any) => (
                  <tr key={ctrl.id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '9px 14px', fontSize: 12, fontWeight: 700, fontFamily: 'monospace' }}>{ctrl.id}</td>
                    <td style={{ padding: '9px 14px', fontSize: 12, color: 'var(--text-2)', maxWidth: 280 }}>{ctrl.title}</td>
                    <td style={{ padding: '9px 14px' }}>
                      <span style={{ fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 10, background: ctrl.status === 'passing' ? '#22c55e22' : ctrl.status === 'failing' ? '#ef444422' : '#f9731622', color: ctrl.status === 'passing' ? '#22c55e' : ctrl.status === 'failing' ? '#ef4444' : '#f97316', border: `1px solid ${ctrl.status === 'passing' ? '#22c55e44' : ctrl.status === 'failing' ? '#ef444444' : '#f9731644'}` }}>
                        {ctrl.status}
                      </span>
                    </td>
                    <td style={{ padding: '9px 14px', fontSize: 12, color: 'var(--text-2)' }}>{ctrl.finding || ctrl.last_scan ? `Last scan: ${ctrl.last_scan}` : '—'}</td>
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
function AnalyticsTab({ analytics }: { analytics: any }) {
  if (!analytics) return <div style={{ color: 'var(--text-3)', padding: 40, textAlign: 'center' }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total" value={analytics.total} />
        <StatCard label="Critical" value={analytics.critical} color="#ef4444" />
        <StatCard label="High" value={analytics.high} color="#f97316" />
        <StatCard label="Patched" value={analytics.patched} color="#22c55e" />
        <StatCard label="KEV" value={analytics.kev} color="#ef4444" />
        <StatCard label="MTTR" value={`${analytics.mttr_days}d`} color="var(--accent)" />
        <StatCard label="Patch SLA" value={`${analytics.patch_sla}%`} color={analytics.patch_sla >= 90 ? '#22c55e' : '#f97316'} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Top Vulnerable Assets</div>
          {analytics.top_vulnerable_assets?.map((a: any) => (
            <div key={a.asset} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <span style={{ fontSize: 12, flex: 1, fontFamily: 'monospace' }}>{a.asset}</span>
              <span style={{ fontSize: 11, color: '#ef4444', fontWeight: 700 }}>{a.critical} crit</span>
              <div style={{ width: 80, background: 'var(--border)', borderRadius: 2, height: 6 }}>
                <div style={{ background: RISK_COLOR(a.risk_score), borderRadius: 2, height: 6, width: `${Math.min(100, a.risk_score)}%` }} />
              </div>
              <span style={{ fontSize: 11, color: 'var(--text-3)', width: 32 }}>{a.risk_score.toFixed(0)}</span>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Top CVEs by Risk</div>
          {analytics.top_cves?.map((c: any) => (
            <div key={c.cve} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8, fontSize: 12 }}>
              <span style={{ fontFamily: 'monospace', color: 'var(--accent)', width: 120 }}>{c.cve}</span>
              {c.kev && <KEVBadge />}
              <span style={{ color: 'var(--text-3)', fontSize: 11 }}>CVSS {c.cvss}</span>
              <span style={{ color: c.epss > 0.7 ? '#ef4444' : '#f97316', fontSize: 11 }}>EPSS {(c.epss*100).toFixed(0)}%</span>
              <span style={{ color: 'var(--text-3)', fontSize: 11, marginLeft: 'auto' }}>{c.affected_assets} assets</span>
            </div>
          ))}
        </div>
      </div>

      <div className="g-card" style={{ padding: 16 }}>
        <div style={{ fontWeight: 600, marginBottom: 12 }}>Risk Trend (Weekly)</div>
        <div style={{ display: 'flex', gap: 4, alignItems: 'flex-end', height: 80 }}>
          {analytics.risk_trend?.map((d: any) => {
            const max = Math.max(...analytics.risk_trend.map((x: any) => x.critical + x.high + x.medium), 1);
            const total = d.critical + d.high + d.medium;
            return (
              <div key={d.week} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                <div style={{ position: 'relative', width: '100%', height: 64, display: 'flex', flexDirection: 'column', justifyContent: 'flex-end' }}>
                  <div style={{ background: '#22c55e', height: `${(d.medium/max)*64}%`, borderRadius: '2px 2px 0 0' }} />
                  <div style={{ background: '#f97316', height: `${(d.high/max)*64}%` }} />
                  <div style={{ background: '#ef4444', height: `${(d.critical/max)*64}%` }} />
                </div>
                <div style={{ fontSize: 9, color: 'var(--text-3)' }}>{d.week}</div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="g-card" style={{ padding: 16 }}>
        <div style={{ fontWeight: 600, marginBottom: 12 }}>Patch SLA Compliance by Severity</div>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead><tr>{['Severity', 'SLA (days)', 'Avg Days', 'On-Time %', 'Progress'].map(h => <th key={h} style={{ textAlign: 'left', padding: '6px 10px', color: 'var(--text-3)', fontWeight: 600, fontSize: 11, textTransform: 'uppercase' }}>{h}</th>)}</tr></thead>
            <tbody>
              {analytics.patch_sla_breakdown?.map((s: any) => (
                <tr key={s.severity} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '8px 10px' }}><SevBadge sev={s.severity} /></td>
                  <td style={{ padding: '8px 10px' }}>{s.sla_days}</td>
                  <td style={{ padding: '8px 10px', color: s.avg_days > s.sla_days ? '#ef4444' : '#22c55e', fontWeight: 700 }}>{s.avg_days}</td>
                  <td style={{ padding: '8px 10px', color: s.on_time_pct >= 90 ? '#22c55e' : '#f97316', fontWeight: 700 }}>{s.on_time_pct}%</td>
                  <td style={{ padding: '8px 10px' }}>
                    <div style={{ width: 100, background: 'var(--border)', borderRadius: 2, height: 6 }}>
                      <div style={{ background: s.on_time_pct >= 90 ? '#22c55e' : '#f97316', borderRadius: 2, height: 6, width: `${s.on_time_pct}%` }} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ─── Scans Tab ────────────────────────────────────────────────────────────────
function ScansTab({ scans, onLaunchScan }: { scans: any[]; onLaunchScan: (data: any) => void }) {
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: '', scan_type: 'network', target: '', profile: 'full' });
  const SCAN_TYPES = ['network', 'agent', 'cloud', 'container', 'web', 'database', 'kubernetes'];
  const STATUS_COLOR: Record<string, string> = { running: '#3b82f6', completed: '#22c55e', failed: '#ef4444', pending: '#f97316' };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {SCAN_TYPES.map(t => (
          <button key={t} className="g-btn g-btn-ghost" style={{ fontSize: 11, textTransform: 'capitalize' }} onClick={() => { setForm(f => ({ ...f, scan_type: t })); setShowForm(true); }}>
            + {t.charAt(0).toUpperCase()+t.slice(1)} Scan
          </button>
        ))}
      </div>
      {showForm && (
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Launch Scan</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: 10, alignItems: 'end' }}>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Name</label>
              <input className="g-input" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="Scan name…" style={{ fontSize: 12 }} />
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Type</label>
              <select className="g-select" value={form.scan_type} onChange={e => setForm(f => ({ ...f, scan_type: e.target.value }))} style={{ fontSize: 12 }}>
                {SCAN_TYPES.map(t => <option key={t} value={t}>{t.charAt(0).toUpperCase()+t.slice(1)}</option>)}
              </select>
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Target</label>
              <input className="g-input" value={form.target} onChange={e => setForm(f => ({ ...f, target: e.target.value }))} placeholder="IP/CIDR/host…" style={{ fontSize: 12 }} />
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              <button className="g-btn g-btn-primary" style={{ fontSize: 12 }} onClick={() => { onLaunchScan(form); setShowForm(false); setForm({ name: '', scan_type: 'network', target: '', profile: 'full' }); }}>Launch</button>
              <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={() => setShowForm(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
      <div className="g-card" style={{ overflow: 'hidden' }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', fontWeight: 600 }}>Scan History</div>
        <div style={{ overflowX: 'auto' }}>
          <table className="g-table" style={{ width: '100%' }}>
            <thead className="g-thead"><tr>
              {['Name', 'Type', 'Target', 'Profile', 'Status', 'Findings', 'Duration', 'Created By', 'Started'].map(h => (
                <th key={h} className="g-tr" style={{ padding: '8px 12px', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
              ))}
            </tr></thead>
            <tbody>
              {scans.map(s => {
                const dur = s.started_at && s.finished_at ? Math.round((new Date(s.finished_at).getTime() - new Date(s.started_at).getTime()) / 60000) : null;
                return (
                  <tr key={s.id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '9px 12px', fontSize: 12, fontWeight: 600 }}>{s.name}</td>
                    <td style={{ padding: '9px 12px', fontSize: 11, color: 'var(--text-2)', textTransform: 'capitalize' }}>{s.scan_type}</td>
                    <td style={{ padding: '9px 12px', fontSize: 11, fontFamily: 'monospace', color: 'var(--text-3)', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.target}</td>
                    <td style={{ padding: '9px 12px', fontSize: 11, color: 'var(--text-2)', textTransform: 'capitalize' }}>{s.profile}</td>
                    <td style={{ padding: '9px 12px' }}>
                      <span style={{ fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 10, background: (STATUS_COLOR[s.status]||'#6b7280')+'22', color: STATUS_COLOR[s.status]||'#6b7280', textTransform: 'capitalize' }}>{s.status}</span>
                    </td>
                    <td style={{ padding: '9px 12px', fontSize: 12, fontWeight: 700, color: s.findings_count > 0 ? '#f97316' : 'var(--text-3)', textAlign: 'center' }}>{s.findings_count || '—'}</td>
                    <td style={{ padding: '9px 12px', fontSize: 11, color: 'var(--text-3)' }}>{dur ? `${dur}m` : s.status === 'running' ? 'Running…' : '—'}</td>
                    <td style={{ padding: '9px 12px', fontSize: 11, color: 'var(--text-2)' }}>{s.created_by}</td>
                    <td style={{ padding: '9px 12px', fontSize: 11, color: 'var(--text-3)' }}>{s.started_at ? timeAgo(s.started_at) : '—'}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ─── Exceptions Tab ───────────────────────────────────────────────────────────
function ExceptionsTab({ exceptions, onApprove, onDelete }: { exceptions: any[]; onApprove: (id: number) => void; onDelete: (id: number) => void }) {
  const [showForm, setShowForm] = useState(false);
  const EX_TYPES = ['risk_acceptance', 'temporary', 'permanent', 'compensating_control'];
  const STATUS_COLOR: Record<string, string> = { approved: '#22c55e', pending: '#f97316', expired: '#6b7280', rejected: '#ef4444' };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', gap: 10 }}>
          <StatCard label="Total" value={exceptions.length} />
          <StatCard label="Approved" value={exceptions.filter(e => e.status === 'approved').length} color="#22c55e" />
          <StatCard label="Pending" value={exceptions.filter(e => e.status === 'pending').length} color="#f97316" />
        </div>
        <button className="g-btn g-btn-primary" style={{ fontSize: 12 }} onClick={() => setShowForm(true)}>+ Add Exception</button>
      </div>

      {showForm && (
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>New Exception Request</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>CVE ID</label>
              <input className="g-input" placeholder="CVE-2024-XXXXX" style={{ fontSize: 12 }} />
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Exception Type</label>
              <select className="g-select" style={{ fontSize: 12 }}>
                {EX_TYPES.map(t => <option key={t} value={t}>{t.replace(/_/g,' ')}</option>)}
              </select>
            </div>
          </div>
          <div style={{ marginBottom: 10 }}>
            <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Business Justification</label>
            <textarea className="g-input" rows={2} placeholder="Reason for exception…" style={{ fontSize: 12, resize: 'none', width: '100%' }} />
          </div>
          <div style={{ marginBottom: 10 }}>
            <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Compensating Control</label>
            <input className="g-input" placeholder="What controls reduce the risk…" style={{ fontSize: 12 }} />
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="g-btn g-btn-primary" style={{ fontSize: 12 }} onClick={() => setShowForm(false)}>Submit</button>
            <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={() => setShowForm(false)}>Cancel</button>
          </div>
        </div>
      )}

      <div className="g-card" style={{ overflow: 'hidden' }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', fontWeight: 600 }}>Exception Register</div>
        {exceptions.length === 0 && <div style={{ padding: 24, color: 'var(--text-3)', textAlign: 'center' }}>No exceptions</div>}
        {exceptions.map(e => (
          <div key={e.id} style={{ padding: '14px 16px', borderBottom: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: 13, color: 'var(--accent)' }}>{e.cve_id}</span>
              <span style={{ fontSize: 11, background: 'var(--border)', padding: '1px 7px', borderRadius: 10, color: 'var(--text-2)', textTransform: 'capitalize' }}>{e.exception_type.replace(/_/g,' ')}</span>
              <span style={{ fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 10, background: (STATUS_COLOR[e.status]||'#6b7280')+'22', color: STATUS_COLOR[e.status]||'#6b7280', textTransform: 'capitalize' }}>{e.status}</span>
              {e.expires_at && <span style={{ fontSize: 10, color: 'var(--text-3)', marginLeft: 'auto' }}>Expires: {new Date(e.expires_at).toLocaleDateString()}</span>}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 4 }}>{e.reason}</div>
            {e.compensating_control && <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 6 }}>Compensating: {e.compensating_control}</div>}
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ fontSize: 10, color: 'var(--text-3)' }}>By {e.created_by} · {timeAgo(e.created_at)}</span>
              {e.approved_by && <span style={{ fontSize: 10, color: '#22c55e' }}>Approved by {e.approved_by}</span>}
              {e.status === 'pending' && <button className="g-btn g-btn-primary" style={{ fontSize: 10, padding: '2px 8px', marginLeft: 'auto' }} onClick={() => onApprove(e.id)}>Approve</button>}
              <button className="g-btn g-btn-ghost" style={{ fontSize: 10, padding: '2px 8px', marginLeft: e.status !== 'pending' ? 'auto' : 0 }} onClick={() => onDelete(e.id)}>Delete</button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Reports Tab ──────────────────────────────────────────────────────────────
function ReportsTab() {
  const [reportType, setReportType] = useState('executive');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const REPORT_TYPES = [['executive', 'Executive Report'], ['patch', 'Patch Report'], ['exposure', 'Exposure Report'], ['compliance', 'Compliance Report'], ['sla', 'SLA Report']];
  const generate = async () => { setLoading(true); const r = await vmAPI.generateReport({ report_type: reportType }); setResult(r.data); setLoading(false); };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 800 }}>
      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 14 }}>Generate Report</div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'end' }}>
          <div style={{ flex: 1 }}>
            <label style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: 4 }}>Report Type</label>
            <select className="g-select" value={reportType} onChange={e => setReportType(e.target.value)} style={{ width: '100%' }}>
              {REPORT_TYPES.map(([v,l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </div>
          <button className="g-btn g-btn-primary" onClick={generate} disabled={loading}>{loading ? 'Generating…' : 'Generate'}</button>
        </div>
      </div>
      {result && (
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: 15 }}>{result.title}</div>
              <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 2 }}>Generated {new Date(result.generated_at).toLocaleString()} · {result.classification}</div>
            </div>
            <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }}>⬇ Export PDF</button>
          </div>
          <div className="g-card" style={{ padding: 12, marginBottom: 16, borderLeft: '3px solid var(--accent)' }}>
            <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 6 }}>Executive Summary</div>
            <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.5 }}>{result.executive_summary}</div>
          </div>
          {result.key_metrics && (
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 16 }}>
              {Object.entries(result.key_metrics).map(([k,v]) => <StatCard key={k} label={k.replace(/_/g,' ')} value={String(v)} />)}
            </div>
          )}
          {result.top_risks && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8 }}>Top Risks</div>
              {result.top_risks.map((r: any) => (
                <div key={r.rank} style={{ display: 'flex', gap: 12, alignItems: 'center', padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
                  <span style={{ color: 'var(--text-3)', width: 16, fontWeight: 600 }}>#{r.rank}</span>
                  <span style={{ fontFamily: 'monospace', fontWeight: 700, color: '#ef4444' }}>{r.cve}</span>
                  {r.kev && <KEVBadge />}
                  <span style={{ color: 'var(--text-2)' }}>{r.asset}</span>
                  <span style={{ color: 'var(--text-3)' }}>CVSS {r.cvss}</span>
                  <span style={{ color: r.days_open > 7 ? '#ef4444' : 'var(--text-3)', marginLeft: 'auto' }}>{r.days_open}d open</span>
                </div>
              ))}
            </div>
          )}
          {result.recommendations && (
            <div>
              <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8 }}>Recommendations</div>
              {result.recommendations.map((r: string, i: number) => (
                <div key={i} style={{ display: 'flex', gap: 8, fontSize: 12, color: 'var(--text-2)', marginBottom: 5 }}>
                  <span style={{ color: 'var(--accent)', fontWeight: 700 }}>{i+1}.</span><span>{r}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────
export default function VulnerabilitiesPage() {
  const [tab, setTab] = useState<Tab>('overview');
  const loaded = useRef<Record<string, boolean>>({});

  const [dash, setDash] = useState<any>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [findingDetail, setFindingDetail] = useState<any>(null);
  const [aiResult, setAiResult] = useState<any>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [detailSub, setDetailSub] = useState<DetailSub>('overview');
  const [filterSev, setFilterSev] = useState('');
  const [filterKev, setFilterKev] = useState(false);
  const [filterExploit, setFilterExploit] = useState(false);
  const [searchQ, setSearchQ] = useState('');
  const [assets, setAssets] = useState<any[]>([]);
  const [surface, setSurface] = useState<any>(null);
  const [patches, setPatches] = useState<any[]>([]);
  const [threatIntel, setThreatIntel] = useState<any>(null);
  const [compliance, setCompliance] = useState<any>(null);
  const [analytics, setAnalytics] = useState<any>(null);
  const [scans, setScans] = useState<any[]>([]);
  const [exceptions, setExceptions] = useState<any[]>([]);

  useEffect(() => {
    loaded.current['overview'] = true;
    vmAPI.getDashboard().then(r => setDash(r.data));
    vmAPI.getInventory().then(r => setFindings(r.data || []));
  }, []);

  const selectFinding = async (id: number) => {
    setSelectedId(id);
    setDetailSub('overview');
    setAiResult(null);
    const det = await vmAPI.getFinding(id);
    setFindingDetail(det.data);
    if (det.data) {
      setAiLoading(true);
      vmAPI.askAI({ cve_id: det.data.cve_id, cvss_score: det.data.cvss_score, epss_score: det.data.epss_score, kev_listed: det.data.kev_listed, asset_name: det.data.asset_name, internet_facing: det.data.internet_facing, asset_criticality: det.data.asset_criticality, description: det.data.description }).then(r => { setAiResult(r.data); setAiLoading(false); }).catch(() => setAiLoading(false));
    }
  };

  const onAction = async (id: number, action: string) => {
    await vmAPI.findingAction(id, { action });
    const det = await vmAPI.getFinding(id);
    setFindingDetail(det.data);
    vmAPI.getInventory().then(r => setFindings(r.data || []));
  };

  const switchTab = (t: Tab) => {
    setTab(t);
    if (!loaded.current[t]) loaded.current[t] = true;
    if (t === 'assets' && assets.length === 0) vmAPI.getAssets().then(r => setAssets(r.data || []));
    if (t === 'surface' && !surface) vmAPI.getAttackSurface().then(r => setSurface(r.data));
    if (t === 'patches' && patches.length === 0) vmAPI.getPatches().then(r => setPatches(r.data || []));
    if (t === 'threat-intel' && !threatIntel) vmAPI.getThreatIntel().then(r => setThreatIntel(r.data));
    if (t === 'compliance' && !compliance) vmAPI.getCompliance().then(r => setCompliance(r.data));
    if (t === 'analytics' && !analytics) vmAPI.getAnalytics().then(r => setAnalytics(r.data));
    if (t === 'scans' && scans.length === 0) vmAPI.getScans().then(r => setScans(r.data || []));
    if (t === 'exceptions' && exceptions.length === 0) vmAPI.getExceptions().then(r => setExceptions(r.data || []));
  };

  return (
    <RootLayout>
      <div style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 20, height: '100%' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>Vulnerability Management</h1>
            <div style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 4 }}>
              CVSS · EPSS · KEV · Asset Exposure · Attack Path — enterprise risk prioritization
            </div>
          </div>
          {dash?.kev_findings > 0 && (
            <div style={{ padding: '6px 14px', borderRadius: 6, background: '#ef444422', color: '#ef4444', fontSize: 12, fontWeight: 700, border: '1px solid #ef444444' }}>
              {dash.kev_findings} KEV finding{dash.kev_findings !== 1 ? 's' : ''} require immediate action
            </div>
          )}
        </div>

        <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', overflowX: 'auto' }}>
          {(Object.keys(TAB_LABELS) as Tab[]).map(t => (
            <button key={t} onClick={() => switchTab(t)}
              style={{ padding: '8px 14px', fontSize: 12, fontWeight: tab === t ? 600 : 400, color: tab === t ? 'var(--accent)' : 'var(--text-3)', background: 'transparent', border: 'none', borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent', cursor: 'pointer', whiteSpace: 'nowrap' }}>
              {TAB_LABELS[t]}
            </button>
          ))}
        </div>

        <div style={{ display: tab === 'overview' ? 'block' : 'none' }}><OverviewTab dash={dash} /></div>
        <div style={{ display: tab === 'inventory' ? 'block' : 'none' }}>
          {loaded.current['inventory'] && (
            <InventoryTab findings={findings} selectedId={selectedId} onSelect={selectFinding} onRefresh={() => vmAPI.getInventory().then(r => setFindings(r.data||[]))}
              findingDetail={findingDetail} aiResult={aiResult} aiLoading={aiLoading}
              detailSub={detailSub} setDetailSub={setDetailSub} onAction={onAction}
              filterSev={filterSev} setFilterSev={setFilterSev} filterKev={filterKev} setFilterKev={setFilterKev}
              filterExploit={filterExploit} setFilterExploit={setFilterExploit} searchQ={searchQ} setSearchQ={setSearchQ}
            />
          )}
        </div>
        <div style={{ display: tab === 'assets' ? 'block' : 'none' }}>
          {loaded.current['assets'] && <AssetsTab assets={assets} />}
        </div>
        <div style={{ display: tab === 'surface' ? 'block' : 'none' }}>
          {loaded.current['surface'] && <SurfaceTab surface={surface} />}
        </div>
        <div style={{ display: tab === 'patches' ? 'block' : 'none' }}>
          {loaded.current['patches'] && <PatchesTab patches={patches} onPatchAction={async (id, action) => { await vmAPI.patchAction(id, { action }); vmAPI.getPatches().then(r => setPatches(r.data||[])); }} />}
        </div>
        <div style={{ display: tab === 'threat-intel' ? 'block' : 'none' }}>
          {loaded.current['threat-intel'] && <ThreatIntelTab ti={threatIntel} />}
        </div>
        <div style={{ display: tab === 'compliance' ? 'block' : 'none' }}>
          {loaded.current['compliance'] && <ComplianceTab compliance={compliance} />}
        </div>
        <div style={{ display: tab === 'analytics' ? 'block' : 'none' }}>
          {loaded.current['analytics'] && <AnalyticsTab analytics={analytics} />}
        </div>
        <div style={{ display: tab === 'scans' ? 'block' : 'none' }}>
          {loaded.current['scans'] && <ScansTab scans={scans} onLaunchScan={async data => { await vmAPI.launchScan(data); vmAPI.getScans().then(r => setScans(r.data||[])); }} />}
        </div>
        <div style={{ display: tab === 'exceptions' ? 'block' : 'none' }}>
          {loaded.current['exceptions'] && <ExceptionsTab exceptions={exceptions} onApprove={async id => { await vmAPI.updateException(id, { status: 'approved', approved_by: 'current_user' }); vmAPI.getExceptions().then(r => setExceptions(r.data||[])); }} onDelete={async id => { await vmAPI.deleteException(id); setExceptions(ex => ex.filter(e => e.id !== id)); }} />}
        </div>
        <div style={{ display: tab === 'reports' ? 'block' : 'none' }}>
          {loaded.current['reports'] && <ReportsTab />}
        </div>
      </div>
    </RootLayout>
  );
}
