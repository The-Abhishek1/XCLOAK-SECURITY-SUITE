'use client';
import React, { useState, useEffect, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { cmdbAPI } from '@/lib/api';

type Tab = 'dashboard' | 'inventory' | 'categories' | 'relationships' | 'discovery' | 'health' | 'risk' | 'compliance' | 'analytics' | 'ai' | 'reports' | 'audit';

// ── helpers ───────────────────────────────────────────────────────────────────

function pill(label: string, color: string) {
  const map: Record<string, string> = {
    critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
    info: '#3b82f6', active: '#22c55e', inactive: '#f97316', none: '#6b7280',
    online: '#22c55e', offline: '#6b7280', retired: '#6b7280', quarantine: '#ef4444',
    'in-maintenance': '#eab308', endpoint: '#6366f1', server: '#3b82f6',
    network: '#14b8a6', cloud: '#8b5cf6', application: '#f59e0b', 'ot-iot': '#ef4444',
    windows: '#0078d4', linux: '#f97316', macos: '#555', managed: '#22c55e',
    unmanaged: '#ef4444', passed: '#22c55e', failed: '#ef4444', 'not-applicable': '#6b7280',
    compliant: '#22c55e', 'non-compliant': '#ef4444',
  };
  const bg = map[label?.toLowerCase()] ?? '#6b7280';
  return (
    <span style={{
      background: bg + '22', color: bg, border: `1px solid ${bg}44`,
      borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600,
      display: 'inline-block', whiteSpace: 'nowrap',
    }}>{label}</span>
  );
}

function StatCard({ label, value, sub, color }: { label: string; value: any; sub?: string; color?: string }) {
  return (
    <div className="g-card" style={{ padding: '16px 20px', minWidth: 140 }}>
      <div style={{ fontSize: 24, fontWeight: 700, color: color ?? 'var(--text-1)' }}>{value}</div>
      <div style={{ fontSize: 13, color: 'var(--text-2)', marginTop: 2 }}>{label}</div>
      {sub && <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

function ScoreRing({ score, size = 80, label }: { score: number; size?: number; label?: string }) {
  const r = size * 0.38;
  const circ = 2 * Math.PI * r;
  const color = score >= 80 ? '#22c55e' : score >= 60 ? '#eab308' : score >= 40 ? '#f97316' : '#ef4444';
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--border)" strokeWidth={size * 0.1} />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={size * 0.1}
          strokeDasharray={circ} strokeDashoffset={circ * (1 - score / 100)} strokeLinecap="round"
          style={{ transformOrigin: `${size / 2}px ${size / 2}px`, transform: 'rotate(-90deg)' }} />
        <text x={size / 2} y={size / 2 + 5} textAnchor="middle" fill="var(--text-1)"
          fontSize={size * 0.22} fontWeight={700}>{score}</text>
      </svg>
      {label && <div style={{ fontSize: 11, color: 'var(--text-2)' }}>{label}</div>}
    </div>
  );
}

function HorizBar({ label, value, max, color = '#6366f1' }: { label: string; value: number; max: number; color?: string }) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0;
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: 'var(--text-2)', marginBottom: 4 }}>
        <span>{label}</span><span style={{ fontWeight: 600, color: 'var(--text-1)' }}>{value.toLocaleString()}</span>
      </div>
      <div style={{ background: 'var(--border)', borderRadius: 4, height: 6 }}>
        <div style={{ width: `${pct}%`, height: 6, background: color, borderRadius: 4, transition: 'width .4s' }} />
      </div>
    </div>
  );
}

function ProgressBar({ pct, color }: { pct: number; color?: string }) {
  const c = color ?? (pct >= 80 ? '#22c55e' : pct >= 60 ? '#eab308' : '#ef4444');
  return (
    <div style={{ background: 'var(--border)', borderRadius: 4, height: 6, width: '100%' }}>
      <div style={{ width: `${pct}%`, height: 6, background: c, borderRadius: 4, transition: 'width .4s' }} />
    </div>
  );
}

const TYPE_COLORS: Record<string, string> = {
  endpoint: '#6366f1', server: '#3b82f6', network: '#14b8a6',
  cloud: '#8b5cf6', application: '#f59e0b', 'ot-iot': '#ef4444',
};

const AI_ACTIONS = [
  { id: 'asset_summary',               label: 'Asset Summary' },
  { id: 'risk_assessment',             label: 'Risk Assessment' },
  { id: 'configuration_analysis',      label: 'Configuration Analysis' },
  { id: 'relationship_insights',       label: 'Relationship Insights' },
  { id: 'missing_controls',            label: 'Missing Controls' },
  { id: 'remediation_recommendations', label: 'Remediation Plan' },
];

// ── AI Panel ──────────────────────────────────────────────────────────────────

function AIPanel({ onClose, selectedAsset }: { onClose: () => void; selectedAsset: any }) {
  const [action, setAction] = useState('asset_summary');
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState('');

  const run = useCallback(async (a: string) => {
    setAction(a);
    setLoading(true);
    setResponse('');
    try {
      const res = await cmdbAPI.ai({ action: a, asset_id: selectedAsset?.asset_id ?? '' });
      setResponse(res.data?.response ?? '');
    } catch { setResponse('AI analysis unavailable.'); }
    finally { setLoading(false); }
  }, [selectedAsset]);

  return (
    <div style={{ position: 'fixed', inset: '0 0 0 auto', width: 420, background: 'var(--bg-1)', borderLeft: '1px solid var(--border)', zIndex: 200, display: 'flex', flexDirection: 'column' }}>
      <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 16 }}>✦ AI Asset Advisor</div>
          {selectedAsset && <div style={{ fontSize: 12, color: 'var(--text-2)', marginTop: 2 }}>{selectedAsset.name}</div>}
        </div>
        <button className="g-btn-ghost" onClick={onClose} style={{ fontSize: 18, padding: '4px 8px' }}>✕</button>
      </div>
      <div style={{ padding: '16px 24px', borderBottom: '1px solid var(--border)', display: 'flex', flexWrap: 'wrap', gap: 8 }}>
        {AI_ACTIONS.map(a => (
          <button key={a.id} className={action === a.id ? 'g-btn' : 'g-btn-ghost'}
            onClick={() => run(a.id)} style={{ fontSize: 12, padding: '6px 12px' }}>
            {a.label}
          </button>
        ))}
      </div>
      <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>
        {loading && <div style={{ color: 'var(--text-2)', fontStyle: 'italic' }}>Analyzing…</div>}
        {!loading && response && (
          <div style={{ fontSize: 13, lineHeight: 1.7, color: 'var(--text-1)', whiteSpace: 'pre-wrap' }}>{response}</div>
        )}
        {!loading && !response && (
          <div style={{ color: 'var(--text-3)', fontSize: 13 }}>Select an analysis type above to get AI insights about {selectedAsset?.name ?? 'the selected asset'}.</div>
        )}
      </div>
    </div>
  );
}

// ── Asset Detail Panel ────────────────────────────────────────────────────────

function AssetDetailPanel({ assetId, onClose }: { assetId: string; onClose: () => void }) {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [tlTab, setTlTab] = useState<'overview' | 'timeline' | 'security'>('overview');

  useEffect(() => {
    setLoading(true);
    cmdbAPI.getAssetDetail(assetId).then(r => { setData(r.data); setLoading(false); });
  }, [assetId]);

  return (
    <div style={{ position: 'fixed', inset: '0 0 0 auto', width: 520, background: 'var(--bg-1)', borderLeft: '1px solid var(--border)', zIndex: 150, display: 'flex', flexDirection: 'column', overflowY: 'auto' }}>
      <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', position: 'sticky', top: 0, background: 'var(--bg-1)', zIndex: 10 }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 15 }}>{loading ? '…' : data?.name}</div>
          {data && <div style={{ fontSize: 12, color: 'var(--text-2)', marginTop: 2 }}>{data.hostname} · {data.asset_type} · {data.category}</div>}
        </div>
        <button className="g-btn-ghost" onClick={onClose} style={{ fontSize: 18, padding: '4px 8px' }}>✕</button>
      </div>

      {loading && <div style={{ padding: 32, color: 'var(--text-2)', textAlign: 'center' }}>Loading…</div>}
      {!loading && data && (
        <div style={{ padding: 24 }}>
          {/* status row */}
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 20 }}>
            {pill(data.status, data.status)}
            {pill(data.criticality, data.criticality)}
            {pill(data.agent_status, data.agent_status)}
            {data.internet_facing && pill('internet-facing', 'critical')}
            {!data.managed && pill('unmanaged', 'failed')}
          </div>

          {/* score + resource */}
          <div style={{ display: 'flex', gap: 16, marginBottom: 20 }}>
            <ScoreRing score={data.risk_score ?? 0} size={72} label="Risk" />
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 6 }}>CPU</div>
              <ProgressBar pct={data.cpu_usage_pct} color="#6366f1" />
              <div style={{ fontSize: 12, color: 'var(--text-2)', margin: '8px 0 6px' }}>Memory</div>
              <ProgressBar pct={data.memory_usage_pct} color="#8b5cf6" />
              <div style={{ fontSize: 12, color: 'var(--text-2)', margin: '8px 0 6px' }}>Disk</div>
              <ProgressBar pct={data.disk_used_pct} color={data.disk_used_pct > 80 ? '#ef4444' : '#14b8a6'} />
            </div>
          </div>

          {/* info grid */}
          <div className="g-card" style={{ padding: 16, marginBottom: 16 }}>
            <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>Asset Information</div>
            {[
              ['Asset ID', data.asset_id],
              ['Owner', data.owner],
              ['Business Unit', data.business_unit],
              ['Department', data.department],
              ['Location', data.location],
              ['OS', `${data.os_name} ${data.os_version}`],
              ['Domain', data.domain],
              ['Manufacturer', `${data.manufacturer} ${data.model}`],
              ['Serial', data.serial_number],
              ['CPU Cores', data.cpu_cores],
              ['Memory', `${data.memory_gb} GB`],
              ['Disk', `${data.disk_gb} GB`],
              ['Discovery', data.discovery_source],
              ['First Seen', data.first_seen_at ? new Date(data.first_seen_at).toLocaleDateString() : '—'],
              ['Last Seen', data.last_seen_at ? new Date(data.last_seen_at).toLocaleString() : '—'],
            ].map(([k, v]) => v ? (
              <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
                <span style={{ color: 'var(--text-2)' }}>{k}</span>
                <span style={{ color: 'var(--text-1)', maxWidth: 220, textAlign: 'right' }}>{v}</span>
              </div>
            ) : null)}
          </div>

          {/* security controls */}
          <div className="g-card" style={{ padding: 16, marginBottom: 16 }}>
            <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>Security Controls</div>
            {[
              ['Patch Status', data.patch_status],
              ['Antivirus', data.antivirus_status],
              ['Firewall', data.firewall_status],
              ['Backup', data.backup_status],
              ['Agent', data.agent_status],
              ['Cert Expiry', data.cert_expiry_days >= 0 ? `${data.cert_expiry_days} days` : 'N/A'],
            ].map(([k, v]) => (
              <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
                <span style={{ color: 'var(--text-2)' }}>{k}</span>
                <span>{pill(String(v), String(v).toLowerCase())}</span>
              </div>
            ))}
          </div>

          {/* IP addresses */}
          {data.ip_addresses && data.ip_addresses !== '[]' && (
            <div className="g-card" style={{ padding: 16, marginBottom: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>IP Addresses</div>
              <div style={{ fontSize: 13, color: 'var(--text-1)', fontFamily: 'monospace' }}>
                {(() => { try { return (JSON.parse(data.ip_addresses) as string[]).join(', ') || '—'; } catch { return data.ip_addresses; } })()}
              </div>
              {data.mac_address && <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 6 }}>MAC: {data.mac_address}</div>}
            </div>
          )}

          {/* related assets */}
          {data.related_assets?.length > 0 && (
            <div className="g-card" style={{ padding: 16, marginBottom: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 10 }}>Related Assets</div>
              {data.related_assets.map((r: any) => (
                <div key={r.asset_id} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
                  <div>
                    <div style={{ fontWeight: 500 }}>{r.name}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{r.relationship_type} · {r.description}</div>
                  </div>
                  {pill(r.status, r.status)}
                </div>
              ))}
            </div>
          )}

          {/* timeline */}
          {data.timeline?.length > 0 && (
            <div className="g-card" style={{ padding: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 10 }}>Recent Timeline</div>
              {data.timeline.slice(0, 10).map((t: any, i: number) => (
                <div key={i} style={{ display: 'flex', gap: 10, padding: '7px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
                  <div style={{ width: 6, height: 6, borderRadius: '50%', background: t.severity === 'critical' ? '#ef4444' : t.severity === 'high' ? '#f97316' : t.severity === 'medium' ? '#eab308' : '#22c55e', marginTop: 5, flexShrink: 0 }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ color: 'var(--text-1)', fontWeight: 500 }}>{t.summary}</div>
                    <div style={{ color: 'var(--text-3)', marginTop: 2 }}>{t.actor} · {t.created_at ? new Date(t.created_at).toLocaleString() : ''}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Tab: Dashboard ────────────────────────────────────────────────────────────

function DashboardTab({ d }: { d: any }) {
  if (!d) return <div style={{ color: 'var(--text-3)' }}>Loading dashboard…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>
        <StatCard label="Total Assets" value={d.total?.toLocaleString() ?? 0} />
        <StatCard label="Online" value={d.online?.toLocaleString() ?? 0} color="#22c55e" />
        <StatCard label="Offline" value={d.offline?.toLocaleString() ?? 0} color="#6b7280" />
        <StatCard label="Critical Assets" value={d.critical?.toLocaleString() ?? 0} color="#ef4444" />
        <StatCard label="Internet Facing" value={d.internet_facing?.toLocaleString() ?? 0} color="#f97316" />
        <StatCard label="Unmanaged" value={d.unmanaged?.toLocaleString() ?? 0} color="#f97316" />
        <StatCard label="Retired" value={d.retired?.toLocaleString() ?? 0} color="#6b7280" />
        <StatCard label="New (7d)" value={d.new_last_7d?.toLocaleString() ?? 0} color="#6366f1" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>CMDB Coverage</div>
          <div style={{ fontSize: 32, fontWeight: 700, color: '#22c55e' }}>{d.cmdb_coverage ?? 0}%</div>
          <ProgressBar pct={d.cmdb_coverage ?? 0} color="#22c55e" />
        </div>
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>Agent Coverage</div>
          <div style={{ fontSize: 32, fontWeight: 700, color: '#6366f1' }}>{Math.round(d.agent_coverage ?? 0)}%</div>
          <ProgressBar pct={d.agent_coverage ?? 0} color="#6366f1" />
        </div>
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>Avg Risk Score</div>
          <div style={{ fontSize: 32, fontWeight: 700, color: '#f97316' }}>{Math.round(d.avg_risk_score ?? 0)}</div>
          <ProgressBar pct={d.avg_risk_score ?? 0} color="#f97316" />
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 14 }}>By Asset Type</div>
          {(d.by_type ?? []).map((t: any) => (
            <HorizBar key={t.type} label={t.type} value={t.count} max={d.total}
              color={TYPE_COLORS[t.type] ?? '#6b7280'} />
          ))}
        </div>
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 14 }}>By Criticality</div>
          {(d.by_criticality ?? []).map((c: any) => (
            <HorizBar key={c.criticality} label={c.criticality} value={c.count} max={d.total}
              color={c.criticality === 'critical' ? '#ef4444' : c.criticality === 'high' ? '#f97316' : c.criticality === 'medium' ? '#eab308' : '#22c55e'} />
          ))}
        </div>
      </div>

      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 14 }}>Recent Discoveries</div>
        <table className="g-table" style={{ width: '100%' }}>
          <thead><tr>
            <th>Name</th><th>Type</th><th>Source</th><th>Discovered</th>
          </tr></thead>
          <tbody>
            {(d.recent_discoveries ?? []).map((r: any) => (
              <tr key={r.asset_id}>
                <td style={{ fontWeight: 500 }}>{r.name}</td>
                <td>{pill(r.asset_type, r.asset_type)}</td>
                <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{r.discovery_source}</td>
                <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{r.created_at ? new Date(r.created_at).toLocaleDateString() : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Tab: Asset Inventory ──────────────────────────────────────────────────────

function InventoryTab({ assets, onSelect }: { assets: any[]; onSelect: (a: any) => void }) {
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [critFilter, setCritFilter] = useState('');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkOp, setBulkOp] = useState('assign_owner');
  const [bulkVal, setBulkVal] = useState('');
  const [bulkDone, setBulkDone] = useState('');

  const filtered = (assets ?? []).filter(a => {
    if (search && !`${a.name}${a.hostname}${a.asset_id}`.toLowerCase().includes(search.toLowerCase())) return false;
    if (typeFilter && a.asset_type !== typeFilter) return false;
    if (statusFilter && a.status !== statusFilter) return false;
    if (critFilter && a.criticality !== critFilter) return false;
    return true;
  });

  const toggleSelect = (id: string) => {
    const n = new Set(selected);
    if (n.has(id)) n.delete(id); else n.add(id);
    setSelected(n);
  };
  const toggleAll = () => setSelected(selected.size === filtered.length ? new Set() : new Set(filtered.map(a => a.asset_id)));

  const doBulk = async () => {
    if (!selected.size || !bulkVal) return;
    await cmdbAPI.bulkOperation({ operation: bulkOp, asset_ids: Array.from(selected), value: bulkVal });
    setBulkDone(`Applied "${bulkOp}" to ${selected.size} assets.`);
    setSelected(new Set());
    setBulkVal('');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* filters */}
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
        <input className="g-input" value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search name, hostname, IP…" style={{ minWidth: 240 }} />
        <select className="g-input" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
          <option value="">All Types</option>
          {['endpoint','server','network','cloud','application','ot-iot'].map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <select className="g-input" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">All Status</option>
          {['online','offline','in-maintenance','quarantine','retired'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="g-input" value={critFilter} onChange={e => setCritFilter(e.target.value)}>
          <option value="">All Criticality</option>
          {['critical','high','medium','low'].map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <span style={{ fontSize: 12, color: 'var(--text-3)', marginLeft: 'auto' }}>{filtered.length.toLocaleString()} assets</span>
      </div>

      {/* bulk bar */}
      {selected.size > 0 && (
        <div className="g-card" style={{ padding: '12px 16px', display: 'flex', gap: 10, alignItems: 'center' }}>
          <span style={{ fontSize: 13, color: 'var(--accent)', fontWeight: 600 }}>{selected.size} selected</span>
          <select className="g-input" value={bulkOp} onChange={e => setBulkOp(e.target.value)} style={{ width: 180 }}>
            <option value="assign_owner">Assign Owner</option>
            <option value="update_criticality">Update Criticality</option>
          </select>
          <input className="g-input" value={bulkVal} onChange={e => setBulkVal(e.target.value)}
            placeholder="New value…" style={{ width: 160 }} />
          <button className="g-btn" onClick={doBulk} style={{ fontSize: 13 }}>Apply</button>
          <button className="g-btn-ghost" onClick={() => setSelected(new Set())} style={{ fontSize: 13 }}>Clear</button>
          {bulkDone && <span style={{ fontSize: 12, color: '#22c55e' }}>{bulkDone}</span>}
        </div>
      )}

      <div className="g-card" style={{ padding: 0, overflow: 'auto', maxHeight: '62vh' }}>
        <table className="g-table" style={{ width: '100%' }}>
          <thead><tr>
            <th><input type="checkbox" checked={selected.size === filtered.length && filtered.length > 0}
              onChange={toggleAll} /></th>
            <th>Name</th><th>Type</th><th>Status</th><th>Criticality</th>
            <th>Risk</th><th>Owner</th><th>OS</th><th>Agent</th><th>Patch</th><th>Last Seen</th>
          </tr></thead>
          <tbody>
            {filtered.map(a => (
              <tr key={a.asset_id} onClick={() => onSelect(a)} style={{ cursor: 'pointer' }}>
                <td onClick={e => { e.stopPropagation(); toggleSelect(a.asset_id); }}>
                  <input type="checkbox" checked={selected.has(a.asset_id)} onChange={() => {}} />
                </td>
                <td>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>{a.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{a.hostname}</div>
                </td>
                <td>{pill(a.asset_type, a.asset_type)}</td>
                <td>{pill(a.status, a.status)}</td>
                <td>{pill(a.criticality, a.criticality)}</td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <div style={{ width: 36, height: 6, background: 'var(--border)', borderRadius: 3 }}>
                      <div style={{ width: `${a.risk_score}%`, height: '100%', borderRadius: 3, background: a.risk_score >= 70 ? '#ef4444' : a.risk_score >= 40 ? '#f97316' : '#22c55e' }} />
                    </div>
                    <span style={{ fontSize: 12 }}>{a.risk_score}</span>
                  </div>
                </td>
                <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{a.owner || '—'}</td>
                <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{a.os_name}</td>
                <td>{pill(a.agent_status, a.agent_status)}</td>
                <td>{pill(a.patch_status, a.patch_status)}</td>
                <td style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
                  {a.last_seen_at ? new Date(a.last_seen_at).toLocaleDateString() : '—'}
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr><td colSpan={11} style={{ textAlign: 'center', color: 'var(--text-3)', padding: 32 }}>No assets match filters</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Tab: Categories ────────────────────────────────────────────────────────────

function CategoriesTab({ assets }: { assets: any[] }) {
  const [activeType, setActiveType] = useState<string | null>(null);
  const types = ['endpoint', 'server', 'network', 'cloud', 'application', 'ot-iot'];

  const byType = types.map(t => ({
    type: t,
    items: (assets ?? []).filter(a => a.asset_type === t),
  }));

  const shown = activeType ? byType.filter(b => b.type === activeType) : byType;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button className={activeType === null ? 'g-btn' : 'g-btn-ghost'} onClick={() => setActiveType(null)} style={{ fontSize: 12 }}>All</button>
        {types.map(t => (
          <button key={t} className={activeType === t ? 'g-btn' : 'g-btn-ghost'} onClick={() => setActiveType(t)} style={{ fontSize: 12 }}>
            {t} ({(assets ?? []).filter(a => a.asset_type === t).length})
          </button>
        ))}
      </div>

      {shown.map(b => b.items.length === 0 ? null : (
        <div key={b.type} className="g-card" style={{ padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <div style={{ fontWeight: 700, display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ width: 10, height: 10, borderRadius: '50%', background: TYPE_COLORS[b.type] ?? '#6b7280', display: 'inline-block' }} />
              {b.type.charAt(0).toUpperCase() + b.type.slice(1).replace('-', ' / ')}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-3)' }}>{b.items.length} assets</div>
          </div>

          {/* summary stats */}
          <div style={{ display: 'flex', gap: 16, marginBottom: 14, flexWrap: 'wrap' }}>
            {(['online', 'offline', 'critical', 'in-maintenance'] as const).map(st => {
              const cnt = st === 'critical'
                ? b.items.filter(a => a.criticality === 'critical').length
                : b.items.filter(a => a.status === st).length;
              if (!cnt) return null;
              return <div key={st} style={{ fontSize: 12, color: 'var(--text-2)' }}>
                <span style={{ fontWeight: 600, color: st === 'online' ? '#22c55e' : st === 'critical' ? '#ef4444' : 'var(--text-1)' }}>{cnt}</span> {st}
              </div>;
            })}
            <div style={{ fontSize: 12, color: 'var(--text-2)' }}>
              <span style={{ fontWeight: 600, color: 'var(--text-1)' }}>
                {Math.round(b.items.reduce((s, a) => s + (a.risk_score ?? 0), 0) / b.items.length)}
              </span> avg risk
            </div>
          </div>

          <table className="g-table" style={{ width: '100%' }}>
            <thead><tr><th>Name</th><th>Status</th><th>Criticality</th><th>Risk</th><th>Patch</th><th>Owner</th></tr></thead>
            <tbody>
              {b.items.slice(0, 10).map(a => (
                <tr key={a.asset_id}>
                  <td>
                    <div style={{ fontWeight: 500, fontSize: 13 }}>{a.name}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{a.os_name}</div>
                  </td>
                  <td>{pill(a.status, a.status)}</td>
                  <td>{pill(a.criticality, a.criticality)}</td>
                  <td style={{ fontSize: 13 }}>{a.risk_score}</td>
                  <td>{pill(a.patch_status, a.patch_status)}</td>
                  <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{a.owner || '—'}</td>
                </tr>
              ))}
              {b.items.length > 10 && (
                <tr><td colSpan={6} style={{ textAlign: 'center', fontSize: 12, color: 'var(--text-3)', padding: 10 }}>
                  +{b.items.length - 10} more in Inventory tab
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      ))}
    </div>
  );
}

// ── Tab: Relationships ────────────────────────────────────────────────────────

function RelationshipsTab({ rel }: { rel: any }) {
  if (!rel) return <div style={{ color: 'var(--text-3)' }}>Loading…</div>;
  const nodes: any[] = rel.nodes ?? [];
  const edges: any[] = rel.edges ?? [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <StatCard label="Nodes" value={nodes.length} />
        <StatCard label="Relationships" value={edges.length} />
        <StatCard label="Unique Types" value={new Set(edges.map(e => e.type)).size} />
      </div>

      {/* relationship type breakdown */}
      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 14 }}>Relationship Types</div>
        {Array.from(new Set(edges.map(e => e.type))).map(t => {
          const cnt = edges.filter(e => e.type === t).length;
          return <HorizBar key={t} label={t} value={cnt} max={edges.length} color="#6366f1" />;
        })}
        {edges.length === 0 && <div style={{ color: 'var(--text-3)', fontSize: 13 }}>No relationships mapped yet</div>}
      </div>

      {/* edge list */}
      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 14 }}>Asset Relationships</div>
        <table className="g-table" style={{ width: '100%' }}>
          <thead><tr><th>Source</th><th>Type</th><th>Target</th><th>Description</th></tr></thead>
          <tbody>
            {edges.map((e, i) => {
              const src = nodes.find(n => n.id === e.source);
              const tgt = nodes.find(n => n.id === e.target);
              return (
                <tr key={i}>
                  <td>
                    <div style={{ fontWeight: 500, fontSize: 13 }}>{src?.name ?? e.source}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{src?.asset_type}</div>
                  </td>
                  <td><span style={{ fontSize: 12, color: 'var(--text-2)', fontStyle: 'italic' }}>{e.type}</span></td>
                  <td>
                    <div style={{ fontWeight: 500, fontSize: 13 }}>{tgt?.name ?? e.target}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{tgt?.asset_type}</div>
                  </td>
                  <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{e.description ?? '—'}</td>
                </tr>
              );
            })}
            {edges.length === 0 && <tr><td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-3)', padding: 24 }}>No relationship data</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Tab: Discovery ────────────────────────────────────────────────────────────

function DiscoveryTab({ d }: { d: any }) {
  if (!d) return <div style={{ color: 'var(--text-3)' }}>Loading…</div>;
  const sources: any[] = d.discovery_sources ?? [];
  const bySource: any[] = d.by_source ?? [];
  const unmanaged: any[] = d.unmanaged ?? [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 14 }}>Discovery Sources</div>
        <table className="g-table" style={{ width: '100%' }}>
          <thead><tr><th>Source</th><th>Status</th><th>Assets Found</th><th>Last Run</th></tr></thead>
          <tbody>
            {sources.map(s => (
              <tr key={s.source}>
                <td style={{ fontWeight: 500, fontSize: 13 }}>{s.source}</td>
                <td>{pill(s.status, s.status)}</td>
                <td style={{ fontWeight: 600 }}>{s.discovered?.toLocaleString()}</td>
                <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{s.last_run ? new Date(s.last_run).toLocaleString() : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 14 }}>Assets by Source</div>
          {bySource.map(s => (
            <HorizBar key={s.source} label={s.source} value={s.count}
              max={Math.max(...bySource.map(x => x.count))} color="#6366f1" />
          ))}
        </div>
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 14 }}>Unmanaged Assets <span style={{ color: '#ef4444', fontWeight: 700 }}>({unmanaged.length})</span></div>
          {unmanaged.slice(0, 8).map(a => (
            <div key={a.asset_id} style={{ padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
              <div style={{ fontWeight: 500 }}>{a.name}</div>
              <div style={{ color: 'var(--text-3)', marginTop: 2 }}>{a.asset_type} · First seen: {a.first_seen_at ? new Date(a.first_seen_at).toLocaleDateString() : '—'}</div>
            </div>
          ))}
          {unmanaged.length === 0 && <div style={{ color: 'var(--text-3)', fontSize: 13 }}>No unmanaged assets detected</div>}
        </div>
      </div>
    </div>
  );
}

// ── Tab: Health ───────────────────────────────────────────────────────────────

function HealthTab({ d }: { d: any }) {
  if (!d) return <div style={{ color: 'var(--text-3)' }}>Loading…</div>;

  const renderHealth = (title: string, data: Record<string, number>, positiveKey: string) => {
    const total = Object.values(data).reduce((s, n) => s + n, 0);
    const pos = data[positiveKey] ?? 0;
    const pct = total > 0 ? Math.round(pos / total * 100) : 0;
    return (
      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
          <span style={{ fontWeight: 600 }}>{title}</span>
          <span style={{ fontSize: 20, fontWeight: 700, color: pct >= 80 ? '#22c55e' : pct >= 60 ? '#eab308' : '#ef4444' }}>{pct}%</span>
        </div>
        <ProgressBar pct={pct} />
        <div style={{ display: 'flex', gap: 12, marginTop: 10, flexWrap: 'wrap' }}>
          {Object.entries(data).map(([k, v]) => (
            <div key={k} style={{ fontSize: 12, color: 'var(--text-2)' }}>
              <span style={{ fontWeight: 600, color: 'var(--text-1)' }}>{v}</span> {k}
            </div>
          ))}
        </div>
      </div>
    );
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 14 }}>
        {renderHealth('EDR Agent Coverage', d.agent_status ?? {}, 'active')}
        {renderHealth('Patch Compliance', d.patch_status ?? {}, 'current')}
        {renderHealth('Antivirus Coverage', d.antivirus_status ?? {}, 'active')}
        {renderHealth('Firewall Status', d.firewall_status ?? {}, 'active')}
        {renderHealth('Backup Status', d.backup_status ?? {}, 'active')}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Certificate Expiring Soon</div>
          {(d.cert_expiring_soon ?? []).map((c: any) => (
            <div key={c.asset_id} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
              <span>{c.name}</span>
              <span style={{ color: c.days_remaining <= 14 ? '#ef4444' : '#f97316', fontWeight: 600 }}>{c.days_remaining}d</span>
            </div>
          ))}
          {(d.cert_expiring_soon ?? []).length === 0 && <div style={{ color: '#22c55e', fontSize: 13 }}>No certs expiring soon</div>}
        </div>

        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>High Disk Usage</div>
          {(d.high_disk_usage ?? []).map((a: any) => (
            <div key={a.asset_id} style={{ padding: '8px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <span>{a.name}</span>
                <span style={{ color: '#ef4444', fontWeight: 600 }}>{a.disk_used_pct}%</span>
              </div>
              <ProgressBar pct={a.disk_used_pct} color="#ef4444" />
            </div>
          ))}
          {(d.high_disk_usage ?? []).length === 0 && <div style={{ color: '#22c55e', fontSize: 13 }}>No high disk usage</div>}
        </div>
      </div>
    </div>
  );
}

// ── Tab: Risk ─────────────────────────────────────────────────────────────────

function RiskTab({ d }: { d: any }) {
  if (!d) return <div style={{ color: 'var(--text-3)' }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 14 }}>Top Risky Assets</div>
          <table className="g-table" style={{ width: '100%' }}>
            <thead><tr><th>Asset</th><th>Criticality</th><th>Risk</th><th>Internet</th><th>Patch</th></tr></thead>
            <tbody>
              {(d.top_risky_assets ?? []).map((a: any) => (
                <tr key={a.asset_id}>
                  <td>
                    <div style={{ fontWeight: 500 }}>{a.name}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{a.asset_type}</div>
                  </td>
                  <td>{pill(a.criticality, a.criticality)}</td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <div style={{ width: 36, height: 6, background: 'var(--border)', borderRadius: 3 }}>
                        <div style={{ width: `${a.risk_score}%`, height: '100%', borderRadius: 3, background: a.risk_score >= 70 ? '#ef4444' : '#f97316' }} />
                      </div>
                      <span style={{ fontWeight: 700, color: '#ef4444' }}>{a.risk_score}</span>
                    </div>
                  </td>
                  <td>{a.internet_facing ? pill('yes', 'critical') : pill('no', 'low')}</td>
                  <td>{pill(a.patch_status, a.patch_status)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div className="g-card" style={{ padding: 20 }}>
            <div style={{ fontWeight: 600, marginBottom: 12 }}>Risk Factors</div>
            {(d.risk_factors ?? []).map((f: any) => (
              <div key={f.factor} style={{ marginBottom: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 4 }}>
                  <span>{f.factor}</span>
                  <span style={{ fontWeight: 600, color: '#ef4444' }}>{f.assets_affected} assets</span>
                </div>
                <ProgressBar pct={f.weight} color="#ef4444" />
              </div>
            ))}
          </div>

          <div className="g-card" style={{ padding: 20 }}>
            <div style={{ fontWeight: 600, marginBottom: 12 }}>Risk by Business Unit</div>
            {(d.by_business_unit ?? []).slice(0, 6).map((b: any) => (
              <div key={b.business_unit} style={{ marginBottom: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 3 }}>
                  <span>{b.business_unit}</span>
                  <span style={{ fontWeight: 600 }}>{b.avg_risk}</span>
                </div>
                <ProgressBar pct={b.avg_risk} color={b.avg_risk >= 70 ? '#ef4444' : b.avg_risk >= 40 ? '#f97316' : '#22c55e'} />
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 14 }}>Attack Paths</div>
        {(d.attack_paths ?? []).map((p: any, i: number) => (
          <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
            <div style={{ fontSize: 13, fontFamily: 'monospace', color: 'var(--text-1)' }}>{p.path}</div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{p.steps} steps</span>
              {pill(p.risk, p.risk)}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Tab: Compliance ───────────────────────────────────────────────────────────

function ComplianceTab({ d }: { d: any }) {
  if (!d) return <div style={{ color: 'var(--text-3)' }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'center' }}>
        <div className="g-card" style={{ padding: 20, display: 'flex', gap: 20, alignItems: 'center' }}>
          <ScoreRing score={d.compliance_score ?? 0} size={80} label="Compliance" />
          <div>
            <div style={{ fontWeight: 700, fontSize: 20 }}>{d.compliance_score ?? 0}/100</div>
            <div style={{ fontSize: 13, color: 'var(--text-2)' }}>Overall Score</div>
            <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 4 }}>{(d.total ?? 0).toLocaleString()} assets assessed</div>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 14 }}>Security Controls</div>
          {(d.controls ?? []).map((c: any) => (
            <div key={c.control} style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 4 }}>
                <span>{c.control}</span>
                <span style={{ fontWeight: 700, color: c.pct >= 80 ? '#22c55e' : c.pct >= 60 ? '#eab308' : '#ef4444' }}>{c.pct}%</span>
              </div>
              <ProgressBar pct={c.pct} color={c.pct >= 80 ? '#22c55e' : c.pct >= 60 ? '#eab308' : '#ef4444'} />
              <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 3 }}>
                {c.passed?.toLocaleString()} passed · {c.failed?.toLocaleString()} failed
              </div>
            </div>
          ))}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div className="g-card" style={{ padding: 20 }}>
            <div style={{ fontWeight: 600, marginBottom: 12 }}>Policy Violations</div>
            {(d.policy_violations ?? []).map((v: any, i: number) => (
              <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '7px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
                <span>{v.policy}</span>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <span style={{ fontWeight: 600 }}>{v.count}</span>
                  {pill(v.severity, v.severity)}
                </div>
              </div>
            ))}
          </div>

          <div className="g-card" style={{ padding: 20 }}>
            <div style={{ fontWeight: 600, marginBottom: 12 }}>Audit Findings</div>
            {(d.audit_findings ?? []).map((f: any, i: number) => (
              <div key={i} style={{ padding: '8px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
                <div style={{ display: 'flex', gap: 8, marginBottom: 4 }}>{pill(f.severity, f.severity)}</div>
                <div style={{ color: 'var(--text-1)' }}>{f.finding}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Tab: Analytics ────────────────────────────────────────────────────────────

function AnalyticsTab({ d }: { d: any }) {
  if (!d) return <div style={{ color: 'var(--text-3)' }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 14 }}>
        <StatCard label="No Agent" value={d.missing_agents?.no_agent ?? 0} color="#ef4444" sub="immediate action" />
        <StatCard label="Inactive Agent" value={d.missing_agents?.inactive ?? 0} color="#f97316" sub="needs investigation" />
        <StatCard label="Unsupported OS Types" value={(d.unsupported_os ?? []).length} color="#f97316" sub="end-of-life" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 14 }}>OS Distribution</div>
          {(d.os_distribution ?? []).map((o: any) => (
            <HorizBar key={o.os} label={o.os} value={o.count}
              max={Math.max(...(d.os_distribution ?? [{ count: 1 }]).map((x: any) => x.count))} color="#6366f1" />
          ))}
        </div>
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 14 }}>Asset Type Distribution</div>
          {(d.type_distribution ?? []).map((t: any) => (
            <HorizBar key={t.type} label={t.type} value={t.count}
              max={Math.max(...(d.type_distribution ?? [{ count: 1 }]).map((x: any) => x.count))}
              color={TYPE_COLORS[t.type] ?? '#6b7280'} />
          ))}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 14 }}>Asset Growth (6 months)</div>
          <div style={{ display: 'flex', gap: 2, alignItems: 'flex-end', height: 80 }}>
            {(d.asset_growth ?? []).map((g: any) => {
              const maxTotal = Math.max(...(d.asset_growth ?? []).map((x: any) => x.total));
              const h = maxTotal > 0 ? Math.round(g.total / maxTotal * 72) : 0;
              return (
                <div key={g.month} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
                  <div style={{ width: '100%', height: h, background: '#6366f1', borderRadius: '3px 3px 0 0', minHeight: 4 }} />
                  <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{g.month}</div>
                </div>
              );
            })}
          </div>
          <div style={{ display: 'flex', gap: 16, marginTop: 12 }}>
            {(d.asset_growth ?? []).slice(-1).map((g: any) => (
              <React.Fragment key="last">
                <div style={{ fontSize: 12, color: 'var(--text-2)' }}><span style={{ fontWeight: 600, color: '#22c55e' }}>+{g.new}</span> new</div>
                <div style={{ fontSize: 12, color: 'var(--text-2)' }}><span style={{ fontWeight: 600, color: '#6b7280' }}>-{g.retired}</span> retired</div>
                <div style={{ fontSize: 12, color: 'var(--text-2)' }}><span style={{ fontWeight: 600, color: 'var(--text-1)' }}>{g.total?.toLocaleString()}</span> total</div>
              </React.Fragment>
            ))}
          </div>
        </div>

        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 14 }}>Unsupported OS (EOL)</div>
          <table className="g-table" style={{ width: '100%' }}>
            <thead><tr><th>OS Version</th><th>Count</th><th>Risk</th></tr></thead>
            <tbody>
              {(d.unsupported_os ?? []).map((u: any) => (
                <tr key={u.os}>
                  <td style={{ fontSize: 13 }}>{u.os}</td>
                  <td style={{ fontWeight: 600 }}>{u.count}</td>
                  <td>{pill(u.risk, u.risk)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ── Tab: AI Insights ──────────────────────────────────────────────────────────

function AIInsightsTab({ selectedAsset }: { selectedAsset: any }) {
  const [action, setAction] = useState('asset_summary');
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState('');

  const run = useCallback(async (a: string) => {
    setAction(a);
    setLoading(true);
    setResponse('');
    try {
      const res = await cmdbAPI.ai({ action: a, asset_id: selectedAsset?.asset_id ?? '' });
      setResponse(res.data?.response ?? '');
    } catch { setResponse('AI analysis unavailable.'); }
    finally { setLoading(false); }
  }, [selectedAsset]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {selectedAsset && (
        <div className="g-card" style={{ padding: '12px 16px', background: 'var(--accent)1a', display: 'flex', gap: 12, alignItems: 'center' }}>
          <span style={{ fontSize: 13 }}>Context asset:</span>
          <strong>{selectedAsset.name}</strong>
          {pill(selectedAsset.criticality, selectedAsset.criticality)}
          <span style={{ fontSize: 12, color: 'var(--text-3)', marginLeft: 4 }}>Risk: {selectedAsset.risk_score}</span>
        </div>
      )}
      {!selectedAsset && (
        <div className="g-card" style={{ padding: 14 }}>
          <span style={{ fontSize: 13, color: 'var(--text-3)' }}>Select an asset in the Inventory tab to get context-aware AI analysis.</span>
        </div>
      )}

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {AI_ACTIONS.map(a => (
          <button key={a.id} className={action === a.id ? 'g-btn' : 'g-btn-ghost'}
            onClick={() => run(a.id)} style={{ fontSize: 13 }}>
            {a.label}
          </button>
        ))}
      </div>

      {loading && (
        <div className="g-card" style={{ padding: 32, textAlign: 'center', color: 'var(--text-2)', fontStyle: 'italic' }}>
          Analyzing…
        </div>
      )}
      {!loading && response && (
        <div className="g-card" style={{ padding: 24 }}>
          <pre style={{ fontFamily: 'inherit', whiteSpace: 'pre-wrap', fontSize: 13, lineHeight: 1.7, color: 'var(--text-1)', margin: 0 }}>{response}</pre>
        </div>
      )}
      {!loading && !response && (
        <div className="g-card" style={{ padding: 24, color: 'var(--text-3)', fontSize: 13 }}>
          Select an analysis type above to generate AI insights.
        </div>
      )}
    </div>
  );
}

// ── Tab: Reports ──────────────────────────────────────────────────────────────

function ReportsTab({ reports, onRefresh }: { reports: any[]; onRefresh: () => void }) {
  const [title, setTitle] = useState('');
  const [rtype, setRtype] = useState('asset_inventory');
  const [format, setFormat] = useState('pdf');
  const [gen, setGen] = useState(false);

  const generate = async () => {
    if (!title) return;
    setGen(true);
    await cmdbAPI.generateReport({ title, report_type: rtype, format });
    setTitle('');
    onRefresh();
    setGen(false);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 14 }}>Generate Report</div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <input className="g-input" value={title} onChange={e => setTitle(e.target.value)}
            placeholder="Report title…" style={{ minWidth: 240 }} />
          <select className="g-input" value={rtype} onChange={e => setRtype(e.target.value)}>
            <option value="asset_inventory">Asset Inventory</option>
            <option value="risk_report">Risk Report</option>
            <option value="compliance_report">Compliance Report</option>
            <option value="health_report">Health Report</option>
            <option value="discovery_report">Discovery Report</option>
            <option value="vulnerability_report">Vulnerability Report</option>
            <option value="executive_summary">Executive Summary</option>
          </select>
          <select className="g-input" value={format} onChange={e => setFormat(e.target.value)}>
            <option value="pdf">PDF</option>
            <option value="csv">CSV</option>
            <option value="json">JSON</option>
            <option value="xlsx">XLSX</option>
          </select>
          <button className="g-btn" onClick={generate} disabled={!title || gen}>
            {gen ? 'Generating…' : 'Generate'}
          </button>
        </div>
      </div>

      <div className="g-card" style={{ padding: 0, overflow: 'auto' }}>
        <table className="g-table" style={{ width: '100%' }}>
          <thead><tr>
            <th>Title</th><th>Type</th><th>Generated By</th><th>Assets</th><th>Format</th><th>Size</th><th>Date</th>
          </tr></thead>
          <tbody>
            {(reports ?? []).map(r => (
              <tr key={r.report_id}>
                <td style={{ fontWeight: 500 }}>{r.title}</td>
                <td><span style={{ fontSize: 12, color: 'var(--text-2)' }}>{r.report_type}</span></td>
                <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{r.generated_by}</td>
                <td style={{ fontWeight: 600 }}>{r.asset_count?.toLocaleString()}</td>
                <td>{pill(r.format, 'info')}</td>
                <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{r.size_bytes ? `${(r.size_bytes / 1024).toFixed(0)} KB` : '—'}</td>
                <td style={{ fontSize: 12, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
                  {r.created_at ? new Date(r.created_at).toLocaleDateString() : '—'}
                </td>
              </tr>
            ))}
            {(reports ?? []).length === 0 && (
              <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-3)', padding: 32 }}>No reports yet</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Tab: Audit ────────────────────────────────────────────────────────────────

function AuditTab({ entries }: { entries: any[] }) {
  return (
    <div className="g-card" style={{ padding: 0, overflow: 'auto' }}>
      <table className="g-table" style={{ width: '100%' }}>
        <thead><tr>
          <th>Time</th><th>Action</th><th>Object</th><th>Name</th><th>Actor</th><th>Details</th>
        </tr></thead>
        <tbody>
          {(entries ?? []).map((e, i) => (
            <tr key={i}>
              <td style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
                {e.created_at ? new Date(e.created_at).toLocaleString() : '—'}
              </td>
              <td>{pill(e.action?.replace(/_/g, ' '), 'info')}</td>
              <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{e.object_type}</td>
              <td style={{ fontSize: 12 }}>{e.object_name ?? e.object_id ?? '—'}</td>
              <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{e.actor}</td>
              <td style={{ fontSize: 11, color: 'var(--text-3)', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.details ?? '—'}</td>
            </tr>
          ))}
          {(entries ?? []).length === 0 && (
            <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-3)', padding: 32 }}>No audit entries</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

const TABS: { id: Tab; label: string }[] = [
  { id: 'dashboard',     label: 'Dashboard' },
  { id: 'inventory',     label: 'Inventory' },
  { id: 'categories',    label: 'Categories' },
  { id: 'relationships', label: 'Relationships' },
  { id: 'discovery',     label: 'Discovery' },
  { id: 'health',        label: 'Health' },
  { id: 'risk',          label: 'Risk' },
  { id: 'compliance',    label: 'Compliance' },
  { id: 'analytics',     label: 'Analytics' },
  { id: 'ai',            label: '✦ AI Advisor' },
  { id: 'reports',       label: 'Reports' },
  { id: 'audit',         label: 'Audit Trail' },
];

export default function AssetsPage() {
  const [tab, setTab]           = useState<Tab>('dashboard');
  const [showAI, setShowAI]     = useState(false);
  const [selectedAsset, setSelectedAsset] = useState<any>(null);
  const [showDetail, setShowDetail]       = useState(false);
  const [unread, setUnread]     = useState(0);

  const [dashboard, setDashboard]       = useState<any>(null);
  const [assets, setAssets]             = useState<any[]>([]);
  const [relationships, setRelationships] = useState<any>(null);
  const [discovery, setDiscovery]       = useState<any>(null);
  const [health, setHealth]             = useState<any>(null);
  const [risk, setRisk]                 = useState<any>(null);
  const [analytics, setAnalytics]       = useState<any>(null);
  const [compliance, setCompliance]     = useState<any>(null);
  const [reports, setReports]           = useState<any[]>([]);
  const [notifications, setNotifications] = useState<any[]>([]);
  const [audit, setAudit]               = useState<any[]>([]);

  const loadAll = useCallback(async () => {
    const [dash, asst, rel, disc, hlth, rsk, anal, comp, rpts, notifs, aud] = await Promise.all([
      cmdbAPI.getDashboard(),
      cmdbAPI.getAssets(),
      cmdbAPI.getRelationships(),
      cmdbAPI.getDiscovery(),
      cmdbAPI.getHealth(),
      cmdbAPI.getRisk(),
      cmdbAPI.getAnalytics(),
      cmdbAPI.getCompliance(),
      cmdbAPI.getReports(),
      cmdbAPI.getNotifications(),
      cmdbAPI.getAudit(),
    ]);
    setDashboard(dash.data);
    setAssets(Array.isArray(asst.data) ? asst.data : []);
    setRelationships(rel.data);
    setDiscovery(disc.data);
    setHealth(hlth.data);
    setRisk(rsk.data);
    setAnalytics(anal.data);
    setCompliance(comp.data);
    setReports(Array.isArray(rpts.data) ? rpts.data : []);
    const notifArr = Array.isArray(notifs.data) ? notifs.data : [];
    setNotifications(notifArr);
    setUnread(notifArr.filter((n: any) => !n.read).length);
    setAudit(Array.isArray(aud.data) ? aud.data : []);
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  const handleAssetSelect = (a: any) => {
    setSelectedAsset(a);
    setShowDetail(true);
  };

  const markRead = async () => {
    await cmdbAPI.markNotificationsRead();
    setUnread(0);
  };

  return (
    <RootLayout
      title="Assets & CMDB"
      actions={
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button className="g-btn-ghost" style={{ position: 'relative' }}
            onClick={() => { setTab('audit'); markRead(); }}>
            🔔{unread > 0 && (
              <span style={{ position: 'absolute', top: -4, right: -4, background: '#ef4444', color: '#fff', borderRadius: '50%', width: 16, height: 16, fontSize: 10, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                {unread}
              </span>
            )}
          </button>
          <button className="g-btn-ghost" onClick={() => { setShowAI(v => !v); }}>✦ AI Advisor</button>
          <button className="g-btn" onClick={loadAll}>Refresh</button>
        </div>
      }
    >
      {/* tab bar */}
      <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', marginBottom: 24, overflowX: 'auto' }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            padding: '10px 18px', fontSize: 13, fontWeight: tab === t.id ? 700 : 400,
            color: tab === t.id ? 'var(--accent)' : 'var(--text-2)',
            background: 'none', border: 'none', cursor: 'pointer', whiteSpace: 'nowrap',
            borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
          }}>{t.label}</button>
        ))}
      </div>

      {tab === 'dashboard'     && <DashboardTab d={dashboard} />}
      {tab === 'inventory'     && <InventoryTab assets={assets} onSelect={handleAssetSelect} />}
      {tab === 'categories'    && <CategoriesTab assets={assets} />}
      {tab === 'relationships' && <RelationshipsTab rel={relationships} />}
      {tab === 'discovery'     && <DiscoveryTab d={discovery} />}
      {tab === 'health'        && <HealthTab d={health} />}
      {tab === 'risk'          && <RiskTab d={risk} />}
      {tab === 'compliance'    && <ComplianceTab d={compliance} />}
      {tab === 'analytics'     && <AnalyticsTab d={analytics} />}
      {tab === 'ai'            && <AIInsightsTab selectedAsset={selectedAsset} />}
      {tab === 'reports'       && <ReportsTab reports={reports} onRefresh={() => cmdbAPI.getReports().then(r => setReports(r.data ?? []))} />}
      {tab === 'audit'         && <AuditTab entries={audit} />}

      {showDetail && selectedAsset && (
        <AssetDetailPanel assetId={selectedAsset.asset_id} onClose={() => setShowDetail(false)} />
      )}
      {showAI && (
        <AIPanel onClose={() => setShowAI(false)} selectedAsset={selectedAsset} />
      )}
    </RootLayout>
  );
}
