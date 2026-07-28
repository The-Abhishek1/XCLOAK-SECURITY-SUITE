'use client';
import React, { useState, useEffect, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { cmdbAPI } from '@/lib/api';
import { MetricCard, DataTable, EmptyState, SectionCard, TabBar, ActionButton } from '@/components/design-system';
import {
  LayoutDashboard, Boxes, LayoutGrid, Share2, Radar, HeartPulse, ShieldAlert,
  ShieldCheck, BarChart3, Sparkles, FileBarChart2, ScrollText, X, Check, FilePlus2, Bell,
} from 'lucide-react';

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
        <div className="flex items-center gap-2">
          <Sparkles className="h-4 w-4" style={{ color: 'var(--accent)' }} />
          <div>
            <div style={{ fontWeight: 700, fontSize: 16 }}>AI Asset Advisor</div>
            {selectedAsset && <div style={{ fontSize: 12, color: 'var(--text-2)', marginTop: 2 }}>{selectedAsset.name}</div>}
          </div>
        </div>
        <ActionButton variant="ghost" icon={X} onClick={onClose} style={{ padding: '4px 8px' }} />
      </div>
      <div style={{ padding: '16px 24px', borderBottom: '1px solid var(--border)', display: 'flex', flexWrap: 'wrap', gap: 8 }}>
        {AI_ACTIONS.map(a => (
          <ActionButton key={a.id} variant={action === a.id ? 'primary' : 'ghost'}
            onClick={() => run(a.id)} style={{ fontSize: 12, padding: '6px 12px' }}>
            {a.label}
          </ActionButton>
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
        <ActionButton variant="ghost" icon={X} onClick={onClose} style={{ padding: '4px 8px' }} />
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
          <SectionCard title="Asset Information" className="mb-4">
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
          </SectionCard>

          {/* security controls */}
          <SectionCard title="Security Controls" className="mb-4">
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
          </SectionCard>

          {/* IP addresses */}
          {data.ip_addresses && data.ip_addresses !== '[]' && (
            <SectionCard title="IP Addresses" className="mb-4">
              <div style={{ fontSize: 13, color: 'var(--text-1)', fontFamily: 'monospace' }}>
                {(() => { try { return (JSON.parse(data.ip_addresses) as string[]).join(', ') || '—'; } catch { return data.ip_addresses; } })()}
              </div>
              {data.mac_address && <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 6 }}>MAC: {data.mac_address}</div>}
            </SectionCard>
          )}

          {/* related assets */}
          {data.related_assets?.length > 0 && (
            <SectionCard title="Related Assets" className="mb-4">
              {data.related_assets.map((r: any) => (
                <div key={r.asset_id} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
                  <div>
                    <div style={{ fontWeight: 500 }}>{r.name}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{r.relationship_type} · {r.description}</div>
                  </div>
                  {pill(r.status, r.status)}
                </div>
              ))}
            </SectionCard>
          )}

          {/* timeline */}
          {data.timeline?.length > 0 && (
            <SectionCard title="Recent Timeline">
              {data.timeline.slice(0, 10).map((t: any, i: number) => (
                <div key={i} style={{ display: 'flex', gap: 10, padding: '7px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
                  <div style={{ width: 6, height: 6, borderRadius: '50%', background: t.severity === 'critical' ? '#ef4444' : t.severity === 'high' ? '#f97316' : t.severity === 'medium' ? '#eab308' : '#22c55e', marginTop: 5, flexShrink: 0 }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ color: 'var(--text-1)', fontWeight: 500 }}>{t.summary}</div>
                    <div style={{ color: 'var(--text-3)', marginTop: 2 }}>{t.actor} · {t.created_at ? new Date(t.created_at).toLocaleString() : ''}</div>
                  </div>
                </div>
              ))}
            </SectionCard>
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
        <MetricCard label="Total Assets" value={d.total?.toLocaleString() ?? 0} />
        <MetricCard label="Online" value={d.online?.toLocaleString() ?? 0} color="#22c55e" />
        <MetricCard label="Offline" value={d.offline?.toLocaleString() ?? 0} color="#6b7280" />
        <MetricCard label="Critical Assets" value={d.critical?.toLocaleString() ?? 0} color="#ef4444" />
        <MetricCard label="Internet Facing" value={d.internet_facing?.toLocaleString() ?? 0} color="#f97316" />
        <MetricCard label="Unmanaged" value={d.unmanaged?.toLocaleString() ?? 0} color="#f97316" />
        <MetricCard label="Retired" value={d.retired?.toLocaleString() ?? 0} color="#6b7280" />
        <MetricCard label="New (7d)" value={d.new_last_7d?.toLocaleString() ?? 0} color="#6366f1" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
        <SectionCard>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>CMDB Coverage</div>
          <div style={{ fontSize: 32, fontWeight: 700, color: '#22c55e' }}>{d.cmdb_coverage ?? 0}%</div>
          <ProgressBar pct={d.cmdb_coverage ?? 0} color="#22c55e" />
        </SectionCard>
        <SectionCard>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>Agent Coverage</div>
          <div style={{ fontSize: 32, fontWeight: 700, color: '#6366f1' }}>{Math.round(d.agent_coverage ?? 0)}%</div>
          <ProgressBar pct={d.agent_coverage ?? 0} color="#6366f1" />
        </SectionCard>
        <SectionCard>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>Avg Risk Score</div>
          <div style={{ fontSize: 32, fontWeight: 700, color: '#f97316' }}>{Math.round(d.avg_risk_score ?? 0)}</div>
          <ProgressBar pct={d.avg_risk_score ?? 0} color="#f97316" />
        </SectionCard>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <SectionCard title="By Asset Type">
          {(d.by_type ?? []).map((t: any) => (
            <HorizBar key={t.type} label={t.type} value={t.count} max={d.total}
              color={TYPE_COLORS[t.type] ?? '#6b7280'} />
          ))}
        </SectionCard>
        <SectionCard title="By Criticality">
          {(d.by_criticality ?? []).map((c: any) => (
            <HorizBar key={c.criticality} label={c.criticality} value={c.count} max={d.total}
              color={c.criticality === 'critical' ? '#ef4444' : c.criticality === 'high' ? '#f97316' : c.criticality === 'medium' ? '#eab308' : '#22c55e'} />
          ))}
        </SectionCard>
      </div>

      <SectionCard title="Recent Discoveries" padded={false}>
        <DataTable<any>
          columns={[
            { key: 'name', header: 'Name', render: (r: any) => <span style={{ fontWeight: 500 }}>{r.name}</span> },
            { key: 'asset_type', header: 'Type', render: (r: any) => pill(r.asset_type, r.asset_type) },
            { key: 'discovery_source', header: 'Source', render: (r: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{r.discovery_source}</span> },
            { key: 'created_at', header: 'Discovered', render: (r: any) => <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{r.created_at ? new Date(r.created_at).toLocaleDateString() : '—'}</span> },
          ]}
          rows={d.recent_discoveries ?? []}
          rowKey={(r: any) => r.asset_id}
          emptyState={<EmptyState title="No recent discoveries" />}
        />
      </SectionCard>
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
        <SectionCard>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{ fontSize: 13, color: 'var(--accent)', fontWeight: 600 }}>{selected.size} selected</span>
            <select className="g-input" value={bulkOp} onChange={e => setBulkOp(e.target.value)} style={{ width: 180 }}>
              <option value="assign_owner">Assign Owner</option>
              <option value="update_criticality">Update Criticality</option>
            </select>
            <input className="g-input" value={bulkVal} onChange={e => setBulkVal(e.target.value)}
              placeholder="New value…" style={{ width: 160 }} />
            <ActionButton variant="primary" icon={Check} onClick={doBulk} style={{ fontSize: 13 }}>Apply</ActionButton>
            <ActionButton variant="ghost" icon={X} onClick={() => setSelected(new Set())} style={{ fontSize: 13 }}>Clear</ActionButton>
            {bulkDone && <span style={{ fontSize: 12, color: 'var(--green)' }}>{bulkDone}</span>}
          </div>
        </SectionCard>
      )}

      <SectionCard padded={false} className="max-h-[62vh] overflow-auto">
        <DataTable<any>
          rows={filtered}
          rowKey={(a: any) => a.asset_id}
          onRowClick={a => onSelect(a)}
          rowStyle={(a: any) => selected.has(a.asset_id) ? { background: 'var(--accent-glow)' } : undefined}
          emptyState={<EmptyState title="No assets match filters" />}
          columns={[
            { key: 'select', header: (
              <input type="checkbox" checked={selected.size === filtered.length && filtered.length > 0} onChange={toggleAll} />
            ), render: (a: any) => (
              <span onClick={e => { e.stopPropagation(); toggleSelect(a.asset_id); }}>
                <input type="checkbox" checked={selected.has(a.asset_id)} onChange={() => {}} />
              </span>
            ) },
            { key: 'name', header: 'Name', render: (a: any) => (
              <div>
                <div style={{ fontWeight: 600, fontSize: 13 }}>{a.name}</div>
                <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{a.hostname}</div>
              </div>
            ) },
            { key: 'asset_type', header: 'Type', render: (a: any) => pill(a.asset_type, a.asset_type) },
            { key: 'status', header: 'Status', render: (a: any) => pill(a.status, a.status) },
            { key: 'criticality', header: 'Criticality', render: (a: any) => pill(a.criticality, a.criticality) },
            { key: 'risk_score', header: 'Risk', render: (a: any) => (
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <div style={{ width: 36, height: 6, background: 'var(--border)', borderRadius: 3 }}>
                  <div style={{ width: `${a.risk_score}%`, height: '100%', borderRadius: 3, background: a.risk_score >= 70 ? '#ef4444' : a.risk_score >= 40 ? '#f97316' : '#22c55e' }} />
                </div>
                <span style={{ fontSize: 12 }}>{a.risk_score}</span>
              </div>
            ) },
            { key: 'owner', header: 'Owner', render: (a: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{a.owner || '—'}</span> },
            { key: 'os_name', header: 'OS', render: (a: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{a.os_name}</span> },
            { key: 'agent_status', header: 'Agent', render: (a: any) => pill(a.agent_status, a.agent_status) },
            { key: 'patch_status', header: 'Patch', render: (a: any) => pill(a.patch_status, a.patch_status) },
            { key: 'last_seen_at', header: 'Last Seen', render: (a: any) => (
              <span style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
                {a.last_seen_at ? new Date(a.last_seen_at).toLocaleDateString() : '—'}
              </span>
            ) },
          ]}
        />
      </SectionCard>
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
        <ActionButton variant={activeType === null ? 'primary' : 'ghost'} onClick={() => setActiveType(null)} style={{ fontSize: 12 }}>All</ActionButton>
        {types.map(t => (
          <ActionButton key={t} variant={activeType === t ? 'primary' : 'ghost'} onClick={() => setActiveType(t)} style={{ fontSize: 12 }}>
            {t} ({(assets ?? []).filter(a => a.asset_type === t).length})
          </ActionButton>
        ))}
      </div>

      {shown.map(b => b.items.length === 0 ? null : (
        <SectionCard key={b.type}
          title={
            <span className="inline-flex items-center gap-2">
              <span style={{ width: 10, height: 10, borderRadius: '50%', background: TYPE_COLORS[b.type] ?? '#6b7280', display: 'inline-block' }} />
              {b.type.charAt(0).toUpperCase() + b.type.slice(1).replace('-', ' / ')}
            </span>
          }
          subtitle={`${b.items.length} assets`}
          padded={false}>
          <div style={{ display: 'flex', gap: 16, padding: '14px 16px 0', flexWrap: 'wrap' }}>
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

          <DataTable<any>
            rows={b.items.slice(0, 10)}
            rowKey={(a: any) => a.asset_id}
            columns={[
              { key: 'name', header: 'Name', render: (a: any) => (
                <div>
                  <div style={{ fontWeight: 500, fontSize: 13 }}>{a.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{a.os_name}</div>
                </div>
              ) },
              { key: 'status', header: 'Status', render: (a: any) => pill(a.status, a.status) },
              { key: 'criticality', header: 'Criticality', render: (a: any) => pill(a.criticality, a.criticality) },
              { key: 'risk_score', header: 'Risk', render: (a: any) => <span style={{ fontSize: 13 }}>{a.risk_score}</span> },
              { key: 'patch_status', header: 'Patch', render: (a: any) => pill(a.patch_status, a.patch_status) },
              { key: 'owner', header: 'Owner', render: (a: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{a.owner || '—'}</span> },
            ]}
            footer={b.items.length > 10 ? (
              <div style={{ textAlign: 'center', fontSize: 12, color: 'var(--text-3)' }}>+{b.items.length - 10} more in Inventory tab</div>
            ) : undefined}
          />
        </SectionCard>
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
        <MetricCard label="Nodes" value={nodes.length} />
        <MetricCard label="Relationships" value={edges.length} />
        <MetricCard label="Unique Types" value={new Set(edges.map(e => e.type)).size} />
      </div>

      {/* relationship type breakdown */}
      <SectionCard title="Relationship Types">
        {Array.from(new Set(edges.map(e => e.type))).map(t => {
          const cnt = edges.filter(e => e.type === t).length;
          return <HorizBar key={t} label={t} value={cnt} max={edges.length} color="#6366f1" />;
        })}
        {edges.length === 0 && <div style={{ color: 'var(--text-3)', fontSize: 13 }}>No relationships mapped yet</div>}
      </SectionCard>

      {/* edge list */}
      <SectionCard title="Asset Relationships" padded={false}>
        <DataTable<any>
          rows={edges}
          rowKey={(_e: any, i: number) => i}
          emptyState={<EmptyState title="No relationship data" />}
          columns={[
            { key: 'source', header: 'Source', render: (e: any) => {
              const src = nodes.find(n => n.id === e.source);
              return (
                <div>
                  <div style={{ fontWeight: 500, fontSize: 13 }}>{src?.name ?? e.source}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{src?.asset_type}</div>
                </div>
              );
            } },
            { key: 'type', header: 'Type', render: (e: any) => <span style={{ fontSize: 12, color: 'var(--text-2)', fontStyle: 'italic' }}>{e.type}</span> },
            { key: 'target', header: 'Target', render: (e: any) => {
              const tgt = nodes.find(n => n.id === e.target);
              return (
                <div>
                  <div style={{ fontWeight: 500, fontSize: 13 }}>{tgt?.name ?? e.target}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{tgt?.asset_type}</div>
                </div>
              );
            } },
            { key: 'description', header: 'Description', render: (e: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{e.description ?? '—'}</span> },
          ]}
        />
      </SectionCard>
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
      <SectionCard title="Discovery Sources" padded={false}>
        <DataTable<any>
          rows={sources}
          rowKey={(s: any) => s.source}
          emptyState={<EmptyState title="No discovery sources configured" />}
          columns={[
            { key: 'source', header: 'Source', render: (s: any) => <span style={{ fontWeight: 500, fontSize: 13 }}>{s.source}</span> },
            { key: 'status', header: 'Status', render: (s: any) => pill(s.status, s.status) },
            { key: 'discovered', header: 'Assets Found', render: (s: any) => <span style={{ fontWeight: 600 }}>{s.discovered?.toLocaleString()}</span> },
            { key: 'last_run', header: 'Last Run', render: (s: any) => <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{s.last_run ? new Date(s.last_run).toLocaleString() : '—'}</span> },
          ]}
        />
      </SectionCard>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <SectionCard title="Assets by Source">
          {bySource.map(s => (
            <HorizBar key={s.source} label={s.source} value={s.count}
              max={Math.max(...bySource.map(x => x.count))} color="#6366f1" />
          ))}
        </SectionCard>
        <SectionCard title={<>Unmanaged Assets <span style={{ color: '#ef4444', fontWeight: 700 }}>({unmanaged.length})</span></>}>
          {unmanaged.slice(0, 8).map(a => (
            <div key={a.asset_id} style={{ padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
              <div style={{ fontWeight: 500 }}>{a.name}</div>
              <div style={{ color: 'var(--text-3)', marginTop: 2 }}>{a.asset_type} · First seen: {a.first_seen_at ? new Date(a.first_seen_at).toLocaleDateString() : '—'}</div>
            </div>
          ))}
          {unmanaged.length === 0 && <div style={{ color: 'var(--text-3)', fontSize: 13 }}>No unmanaged assets detected</div>}
        </SectionCard>
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
      <SectionCard key={title}>
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
      </SectionCard>
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
        <SectionCard title="Certificate Expiring Soon">
          {(d.cert_expiring_soon ?? []).map((c: any) => (
            <div key={c.asset_id} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
              <span>{c.name}</span>
              <span style={{ color: c.days_remaining <= 14 ? '#ef4444' : '#f97316', fontWeight: 600 }}>{c.days_remaining}d</span>
            </div>
          ))}
          {(d.cert_expiring_soon ?? []).length === 0 && <div style={{ color: 'var(--green)', fontSize: 13 }}>No certs expiring soon</div>}
        </SectionCard>

        <SectionCard title="High Disk Usage">
          {(d.high_disk_usage ?? []).map((a: any) => (
            <div key={a.asset_id} style={{ padding: '8px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <span>{a.name}</span>
                <span style={{ color: '#ef4444', fontWeight: 600 }}>{a.disk_used_pct}%</span>
              </div>
              <ProgressBar pct={a.disk_used_pct} color="#ef4444" />
            </div>
          ))}
          {(d.high_disk_usage ?? []).length === 0 && <div style={{ color: 'var(--green)', fontSize: 13 }}>No high disk usage</div>}
        </SectionCard>
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
        <SectionCard title="Top Risky Assets" padded={false}>
          <DataTable<any>
            rows={d.top_risky_assets ?? []}
            rowKey={(a: any) => a.asset_id}
            columns={[
              { key: 'name', header: 'Asset', render: (a: any) => (
                <div>
                  <div style={{ fontWeight: 500 }}>{a.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{a.asset_type}</div>
                </div>
              ) },
              { key: 'criticality', header: 'Criticality', render: (a: any) => pill(a.criticality, a.criticality) },
              { key: 'risk_score', header: 'Risk', render: (a: any) => (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <div style={{ width: 36, height: 6, background: 'var(--border)', borderRadius: 3 }}>
                    <div style={{ width: `${a.risk_score}%`, height: '100%', borderRadius: 3, background: a.risk_score >= 70 ? '#ef4444' : '#f97316' }} />
                  </div>
                  <span style={{ fontWeight: 700, color: '#ef4444' }}>{a.risk_score}</span>
                </div>
              ) },
              { key: 'internet_facing', header: 'Internet', render: (a: any) => a.internet_facing ? pill('yes', 'critical') : pill('no', 'low') },
              { key: 'patch_status', header: 'Patch', render: (a: any) => pill(a.patch_status, a.patch_status) },
            ]}
          />
        </SectionCard>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <SectionCard title="Risk Factors">
            {(d.risk_factors ?? []).map((f: any) => (
              <div key={f.factor} style={{ marginBottom: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 4 }}>
                  <span>{f.factor}</span>
                  <span style={{ fontWeight: 600, color: '#ef4444' }}>{f.assets_affected} assets</span>
                </div>
                <ProgressBar pct={f.weight} color="#ef4444" />
              </div>
            ))}
          </SectionCard>

          <SectionCard title="Risk by Business Unit">
            {(d.by_business_unit ?? []).slice(0, 6).map((b: any) => (
              <div key={b.business_unit} style={{ marginBottom: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 3 }}>
                  <span>{b.business_unit}</span>
                  <span style={{ fontWeight: 600 }}>{b.avg_risk}</span>
                </div>
                <ProgressBar pct={b.avg_risk} color={b.avg_risk >= 70 ? '#ef4444' : b.avg_risk >= 40 ? '#f97316' : '#22c55e'} />
              </div>
            ))}
          </SectionCard>
        </div>
      </div>

      <SectionCard title="Attack Paths">
        {(d.attack_paths ?? []).map((p: any, i: number) => (
          <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
            <div style={{ fontSize: 13, fontFamily: 'monospace', color: 'var(--text-1)' }}>{p.path}</div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{p.steps} steps</span>
              {pill(p.risk, p.risk)}
            </div>
          </div>
        ))}
      </SectionCard>
    </div>
  );
}

// ── Tab: Compliance ───────────────────────────────────────────────────────────

function ComplianceTab({ d }: { d: any }) {
  if (!d) return <div style={{ color: 'var(--text-3)' }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <SectionCard>
        <div style={{ display: 'flex', gap: 20, alignItems: 'center' }}>
          <ScoreRing score={d.compliance_score ?? 0} size={80} label="Compliance" />
          <div>
            <div style={{ fontWeight: 700, fontSize: 20 }}>{d.compliance_score ?? 0}/100</div>
            <div style={{ fontSize: 13, color: 'var(--text-2)' }}>Overall Score</div>
            <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 4 }}>{(d.total ?? 0).toLocaleString()} assets assessed</div>
          </div>
        </div>
      </SectionCard>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <SectionCard title="Security Controls">
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
        </SectionCard>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <SectionCard title="Policy Violations">
            {(d.policy_violations ?? []).map((v: any, i: number) => (
              <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '7px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
                <span>{v.policy}</span>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <span style={{ fontWeight: 600 }}>{v.count}</span>
                  {pill(v.severity, v.severity)}
                </div>
              </div>
            ))}
          </SectionCard>

          <SectionCard title="Audit Findings">
            {(d.audit_findings ?? []).map((f: any, i: number) => (
              <div key={i} style={{ padding: '8px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
                <div style={{ display: 'flex', gap: 8, marginBottom: 4 }}>{pill(f.severity, f.severity)}</div>
                <div style={{ color: 'var(--text-1)' }}>{f.finding}</div>
              </div>
            ))}
          </SectionCard>
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
        <MetricCard label="No Agent" value={d.missing_agents?.no_agent ?? 0} color="#ef4444" sub="immediate action" />
        <MetricCard label="Inactive Agent" value={d.missing_agents?.inactive ?? 0} color="#f97316" sub="needs investigation" />
        <MetricCard label="Unsupported OS Types" value={(d.unsupported_os ?? []).length} color="#f97316" sub="end-of-life" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <SectionCard title="OS Distribution">
          {(d.os_distribution ?? []).map((o: any) => (
            <HorizBar key={o.os} label={o.os} value={o.count}
              max={Math.max(...(d.os_distribution ?? [{ count: 1 }]).map((x: any) => x.count))} color="#6366f1" />
          ))}
        </SectionCard>
        <SectionCard title="Asset Type Distribution">
          {(d.type_distribution ?? []).map((t: any) => (
            <HorizBar key={t.type} label={t.type} value={t.count}
              max={Math.max(...(d.type_distribution ?? [{ count: 1 }]).map((x: any) => x.count))}
              color={TYPE_COLORS[t.type] ?? '#6b7280'} />
          ))}
        </SectionCard>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <SectionCard title="Asset Growth (6 months)">
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
        </SectionCard>

        <SectionCard title="Unsupported OS (EOL)" padded={false}>
          <DataTable<any>
            rows={d.unsupported_os ?? []}
            rowKey={(u: any) => u.os}
            emptyState={<EmptyState title="No unsupported OS versions" />}
            columns={[
              { key: 'os', header: 'OS Version', render: (u: any) => <span style={{ fontSize: 13 }}>{u.os}</span> },
              { key: 'count', header: 'Count', render: (u: any) => <span style={{ fontWeight: 600 }}>{u.count}</span> },
              { key: 'risk', header: 'Risk', render: (u: any) => pill(u.risk, u.risk) },
            ]}
          />
        </SectionCard>
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
        <div className="g-card" style={{ padding: '12px 16px', background: 'var(--accent-glow)', display: 'flex', gap: 12, alignItems: 'center' }}>
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
          <ActionButton key={a.id} variant={action === a.id ? 'primary' : 'ghost'}
            onClick={() => run(a.id)} style={{ fontSize: 13 }}>
            {a.label}
          </ActionButton>
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
      <SectionCard title="Generate Report">
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
          <ActionButton variant="primary" icon={FilePlus2} onClick={generate} disabled={!title || gen}>
            {gen ? 'Generating…' : 'Generate'}
          </ActionButton>
        </div>
      </SectionCard>

      <SectionCard padded={false}>
        <DataTable<any>
          rows={reports ?? []}
          rowKey={(r: any) => r.report_id}
          emptyState={<EmptyState title="No reports yet" />}
          columns={[
            { key: 'title', header: 'Title', render: (r: any) => <span style={{ fontWeight: 500 }}>{r.title}</span> },
            { key: 'report_type', header: 'Type', render: (r: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{r.report_type}</span> },
            { key: 'generated_by', header: 'Generated By', render: (r: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{r.generated_by}</span> },
            { key: 'asset_count', header: 'Assets', render: (r: any) => <span style={{ fontWeight: 600 }}>{r.asset_count?.toLocaleString()}</span> },
            { key: 'format', header: 'Format', render: (r: any) => pill(r.format, 'info') },
            { key: 'size_bytes', header: 'Size', render: (r: any) => <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{r.size_bytes ? `${(r.size_bytes / 1024).toFixed(0)} KB` : '—'}</span> },
            { key: 'created_at', header: 'Date', render: (r: any) => <span style={{ fontSize: 12, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{r.created_at ? new Date(r.created_at).toLocaleDateString() : '—'}</span> },
          ]}
        />
      </SectionCard>
    </div>
  );
}

// ── Tab: Audit ────────────────────────────────────────────────────────────────

function AuditTab({ entries }: { entries: any[] }) {
  return (
    <SectionCard padded={false}>
      <DataTable<any>
        rows={entries ?? []}
        rowKey={(_e: any, i: number) => i}
        emptyState={<EmptyState title="No audit entries" />}
        columns={[
          { key: 'created_at', header: 'Time', render: (e: any) => <span style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{e.created_at ? new Date(e.created_at).toLocaleString() : '—'}</span> },
          { key: 'action', header: 'Action', render: (e: any) => pill(e.action?.replace(/_/g, ' '), 'info') },
          { key: 'object_type', header: 'Object', render: (e: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{e.object_type}</span> },
          { key: 'object_name', header: 'Name', render: (e: any) => <span style={{ fontSize: 12 }}>{e.object_name ?? e.object_id ?? '—'}</span> },
          { key: 'actor', header: 'Actor', render: (e: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{e.actor}</span> },
          { key: 'details', header: 'Details', render: (e: any) => <span style={{ fontSize: 11, color: 'var(--text-3)', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>{e.details ?? '—'}</span> },
        ]}
      />
    </SectionCard>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

const TABS: { key: Tab; label: string; icon: any }[] = [
  { key: 'dashboard',     label: 'Dashboard',     icon: LayoutDashboard },
  { key: 'inventory',     label: 'Inventory',     icon: Boxes },
  { key: 'categories',    label: 'Categories',    icon: LayoutGrid },
  { key: 'relationships', label: 'Relationships', icon: Share2 },
  { key: 'discovery',     label: 'Discovery',     icon: Radar },
  { key: 'health',        label: 'Health',        icon: HeartPulse },
  { key: 'risk',          label: 'Risk',          icon: ShieldAlert },
  { key: 'compliance',    label: 'Compliance',    icon: ShieldCheck },
  { key: 'analytics',     label: 'Analytics',     icon: BarChart3 },
  { key: 'ai',            label: 'AI Advisor',    icon: Sparkles },
  { key: 'reports',       label: 'Reports',       icon: FileBarChart2 },
  { key: 'audit',         label: 'Audit Trail',   icon: ScrollText },
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
      onRefresh={loadAll}
      actions={
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <div style={{ position: 'relative' }}>
            <ActionButton variant="ghost" icon={Bell} onClick={() => { setTab('audit'); markRead(); }} />
            {unread > 0 && (
              <span style={{ position: 'absolute', top: -4, right: -4, background: '#ef4444', color: '#fff', borderRadius: '50%', width: 16, height: 16, fontSize: 10, display: 'flex', alignItems: 'center', justifyContent: 'center', pointerEvents: 'none' }}>
                {unread}
              </span>
            )}
          </div>
          <ActionButton variant="ghost" icon={Sparkles} onClick={() => setShowAI(v => !v)}>AI Advisor</ActionButton>
        </div>
      }
    >
      {/* tab bar */}
      <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: 2, marginBottom: 24, overflowX: 'auto' }}>
        <TabBar tabs={TABS} active={tab} onChange={k => setTab(k as Tab)} />
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
