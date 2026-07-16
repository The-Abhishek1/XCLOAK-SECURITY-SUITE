'use client';

import { useState, useEffect, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { otICSAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';

type Tab = 'overview' | 'inventory' | 'topology' | 'protocols' | 'monitoring' | 'threats' | 'risk' | 'intelligence' | 'compliance' | 'analytics' | 'response';

const TAB_LABELS: Record<Tab, string> = {
  overview:     'Overview',
  inventory:    'Asset Inventory',
  topology:     'Network Topology',
  protocols:    'Protocol Analysis',
  monitoring:   'Device Monitoring',
  threats:      'Threat Detection',
  risk:         'Risk Assessment',
  intelligence: 'Threat Intelligence',
  compliance:   'Compliance',
  analytics:    'Analytics',
  response:     'Response',
};

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#3b82f6',
};

const RISK_COLOR = (s: number) => s >= 80 ? '#ef4444' : s >= 60 ? '#f97316' : s >= 40 ? '#eab308' : '#22c55e';

const ASSET_ICON: Record<string, string> = {
  plc: '⚙', hmi: '🖥', rtu: '📡', scada_server: '🖧', historian: '🗃',
  engineering_workstation: '💻', opc_server: '🔌', sensor: '📊', actuator: '🔧', industrial_switch: '🔀',
};

const PURDUE_COLOR: Record<number, string> = {
  0: '#22c55e', 1: '#3b82f6', 2: '#6366f1', 3: '#a855f7', 4: '#f97316',
};

function ScoreBar({ score, color }: { score: number; color?: string }) {
  return (
    <div style={{ background: 'var(--border)', borderRadius: 4, height: 6, width: '100%', overflow: 'hidden' }}>
      <div style={{ width: `${Math.min(score, 100)}%`, height: '100%', background: color ?? RISK_COLOR(score), borderRadius: 4 }} />
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
      display: 'inline-block', padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
      background: (color ?? '#64748b') + '22', color: color ?? '#64748b',
      textTransform: 'uppercase', letterSpacing: '0.06em',
    }}>{label}</span>
  );
}

// ─── Overview Tab ─────────────────────────────────────────────────────────────
function OverviewTab({ dash }: { dash: any }) {
  if (!dash) return <div style={{ color: 'var(--text-3)', padding: 32 }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 10 }}>
        <StatCard label="Sites" value={dash.sites} />
        <StatCard label="Industrial Zones" value={dash.industrial_zones} />
        <StatCard label="PLCs" value={dash.plcs} color="#3b82f6" />
        <StatCard label="HMIs" value={dash.hmis} color="#6366f1" />
        <StatCard label="RTUs" value={dash.rtus} color="#a855f7" />
        <StatCard label="Eng. Workstations" value={dash.engineering_workstations} color="#f97316" />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
        <StatCard label="OT Risk Score" value={`${dash.ot_risk_score}%`} color={RISK_COLOR(dash.ot_risk_score)} />
        <StatCard label="Critical Alerts" value={dash.critical_alerts} color="#ef4444" />
        <StatCard label="Active Incidents" value={dash.active_incidents} color="#f97316" />
        <StatCard label="Network Health" value={`${dash.network_health}%`} color={dash.network_health >= 85 ? '#22c55e' : '#f97316'} />
      </div>
      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 12 }}>OT Risk Score</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{ fontSize: 48, fontWeight: 800, color: RISK_COLOR(dash.ot_risk_score) }}>{dash.ot_risk_score}</div>
          <div style={{ flex: 1 }}>
            <ScoreBar score={dash.ot_risk_score} />
            <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 8 }}>
              Score considers internet exposure, firmware age, authentication posture, segmentation, and active threats.
            </div>
          </div>
        </div>
      </div>
      <div className="g-card" style={{ padding: 16, borderLeft: '3px solid #f97316' }}>
        <div style={{ fontWeight: 600, color: '#f97316', marginBottom: 6, fontSize: 13 }}>⚠ Safety-Aware Response Mode</div>
        <div style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.6 }}>
          All automated responses that may affect physical operations require explicit operator approval. Automated actions that could reboot PLCs, stop processes, or block critical control paths are disabled. Available modes: Alert Only · Operator Approval Required · Maintenance Window Actions · Emergency Escalation.
        </div>
      </div>
    </div>
  );
}

// ─── Asset Inventory Tab ──────────────────────────────────────────────────────
function InventoryTab() {
  const [assets, setAssets] = useState<any[]>([]);
  const [typeFilter, setTypeFilter] = useState('');
  const [zoneFilter, setZoneFilter] = useState('');

  const load = () => {
    otICSAPI.getAssets({ type: typeFilter || undefined, zone: zoneFilter || undefined })
      .then(r => setAssets(r.data ?? []));
  };
  useEffect(load, [typeFilter, zoneFilter]);

  const zones = useMemo(() => [...new Set(assets.map((a: any) => a.zone))], [assets]);

  const ASSET_TYPES = ['plc', 'hmi', 'rtu', 'scada_server', 'historian', 'engineering_workstation', 'opc_server', 'sensor', 'actuator', 'industrial_switch'];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 12 }}>
        <select className="g-select" style={{ width: 180 }} value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
          <option value="">All Asset Types</option>
          {ASSET_TYPES.map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
        </select>
        <select className="g-select" style={{ width: 180 }} value={zoneFilter} onChange={e => setZoneFilter(e.target.value)}>
          <option value="">All Zones</option>
          {zones.map(z => <option key={z} value={z}>{z}</option>)}
        </select>
        <div style={{ marginLeft: 'auto', fontSize: 13, color: 'var(--text-3)', alignSelf: 'center' }}>{assets.length} assets</div>
      </div>
      <div className="g-card" style={{ overflow: 'auto' }}>
        <table className="g-table">
          <thead className="g-thead">
            <tr><th></th><th>Name</th><th>Type</th><th>Vendor / Model</th><th>Firmware</th><th>IP</th><th>Zone</th><th>Purdue</th><th>Criticality</th><th>Status</th><th>Risk</th><th>Last Seen</th></tr>
          </thead>
          <tbody>
            {assets.map(a => (
              <tr key={a.id} className="g-tr">
                <td style={{ fontSize: 16 }}>{ASSET_ICON[a.asset_type] ?? '📦'}</td>
                <td style={{ fontWeight: 600 }}>{a.name}</td>
                <td><Badge label={a.asset_type.replace(/_/g, ' ')} color="#6366f1" /></td>
                <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{a.vendor} {a.model}</td>
                <td><code style={{ fontSize: 11 }}>{a.firmware}</code></td>
                <td><code style={{ fontSize: 12 }}>{a.ip}</code></td>
                <td style={{ fontSize: 12 }}>{a.zone}</td>
                <td>
                  <span style={{ background: (PURDUE_COLOR[a.purdue_level] ?? '#64748b') + '22', color: PURDUE_COLOR[a.purdue_level] ?? '#64748b', padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600 }}>
                    L{a.purdue_level}
                  </span>
                </td>
                <td><Badge label={a.criticality} color={a.criticality === 'critical' ? '#ef4444' : a.criticality === 'high' ? '#f97316' : '#64748b'} /></td>
                <td><span style={{ color: a.is_online ? '#22c55e' : '#ef4444', fontSize: 12 }}>{a.is_online ? '● Online' : '○ Offline'}</span></td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ color: RISK_COLOR(a.risk_score), fontWeight: 700, fontSize: 13, width: 28 }}>{a.risk_score}</span>
                    <div style={{ width: 50 }}><ScoreBar score={a.risk_score} /></div>
                  </div>
                </td>
                <td style={{ color: 'var(--text-3)', fontSize: 12 }}>{timeAgo(a.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Network Topology Tab ─────────────────────────────────────────────────────
function TopologyTab() {
  const [topo, setTopo] = useState<any>(null);

  useEffect(() => { otICSAPI.getTopology().then(r => setTopo(r.data)); }, []);

  if (!topo) return <div style={{ color: 'var(--text-3)', padding: 32 }}>Loading topology…</div>;

  const byLevel: Record<number, any[]> = {};
  for (const n of (topo.nodes ?? [])) {
    if (!byLevel[n.purdue_level]) byLevel[n.purdue_level] = [];
    byLevel[n.purdue_level].push(n);
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="g-card" style={{ padding: 24 }}>
        <div style={{ fontWeight: 600, marginBottom: 20 }}>Purdue Model — Live Network Map</div>
        {[4, 3, 2, 1, 0].map(level => (
          <div key={level} style={{ marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
              <span style={{ background: (PURDUE_COLOR[level] ?? '#64748b') + '33', color: PURDUE_COLOR[level] ?? '#64748b', padding: '3px 12px', borderRadius: 20, fontSize: 12, fontWeight: 700 }}>
                Level {level}
              </span>
              <span style={{ fontSize: 12, color: 'var(--text-3)' }}>
                {level === 4 ? 'Enterprise IT' : level === 3 ? 'Operations & Logistics' : level === 2 ? 'Supervisory Control' : level === 1 ? 'Control Devices' : 'Process / Field'}
              </span>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, paddingLeft: 16, borderLeft: `2px solid ${PURDUE_COLOR[level] ?? '#64748b'}44` }}>
              {(byLevel[level] ?? []).map((n: any) => (
                <div key={n.id} style={{
                  padding: '8px 14px', border: `1px solid ${n.risk_score > 70 ? '#ef4444' : 'var(--border)'}`, borderRadius: 8,
                  background: 'var(--bg)', cursor: 'pointer', minWidth: 130,
                }}>
                  <div style={{ fontSize: 16, marginBottom: 2 }}>{ASSET_ICON[n.asset_type] ?? '📦'}</div>
                  <div style={{ fontSize: 12, fontWeight: 600 }}>{n.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{n.ip}</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
                    <span style={{ color: n.is_online ? '#22c55e' : '#ef4444', fontSize: 10 }}>{n.is_online ? '●' : '○'}</span>
                    <span style={{ color: RISK_COLOR(n.risk_score), fontWeight: 700, fontSize: 11 }}>{n.risk_score}</span>
                  </div>
                </div>
              ))}
              {(byLevel[level] ?? []).length === 0 && (
                <div style={{ fontSize: 12, color: 'var(--text-3)', padding: '6px 0' }}>No assets discovered at this level</div>
              )}
            </div>
          </div>
        ))}
      </div>
      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 12 }}>Live Communication Paths</div>
        <table className="g-table">
          <thead className="g-thead">
            <tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Status</th><th>Anomaly</th></tr>
          </thead>
          <tbody>
            {(topo.links ?? []).map((l: any, i: number) => (
              <tr key={i} className="g-tr">
                <td><code style={{ fontSize: 12 }}>{l.src}</code></td>
                <td><code style={{ fontSize: 12 }}>{l.dst}</code></td>
                <td><Badge label={l.protocol} color="#3b82f6" /></td>
                <td><span style={{ color: l.active ? '#22c55e' : '#ef4444', fontSize: 12 }}>{l.active ? '● Active' : '○ Inactive'}</span></td>
                <td>{l.anomaly ? <Badge label={l.anomaly.replace(/_/g, ' ')} color="#ef4444" /> : <span style={{ color: 'var(--text-3)', fontSize: 12 }}>—</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Protocol Analysis Tab ────────────────────────────────────────────────────
function ProtocolsTab() {
  const [protos, setProtos] = useState<any>(null);
  const [traffic, setTraffic] = useState<any[]>([]);
  const [sub, setSub] = useState<'overview' | 'traffic' | 'dpi'>('overview');
  const [protFilter, setProtFilter] = useState('');
  const [unauthorizedOnly, setUnauthorizedOnly] = useState(false);
  const [dpi, setDPI] = useState<any>(null);

  useEffect(() => {
    otICSAPI.getProtocols().then(r => setProtos(r.data));
    otICSAPI.getDPI().then(r => setDPI(r.data));
  }, []);

  useEffect(() => {
    if (sub === 'traffic') {
      otICSAPI.getTraffic({ protocol: protFilter || undefined, unauthorized: unauthorizedOnly || undefined })
        .then(r => setTraffic(r.data ?? []));
    }
  }, [sub, protFilter, unauthorizedOnly]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 8 }}>
        {(['overview', 'traffic', 'dpi'] as const).map(s => (
          <button key={s} className={sub === s ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setSub(s)}>
            {s === 'overview' ? 'Protocol Overview' : s === 'traffic' ? 'Traffic Monitor' : 'Industrial DPI'}
          </button>
        ))}
      </div>

      {sub === 'overview' && protos && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
            <div className="g-card" style={{ padding: 20 }}>
              <div style={{ fontWeight: 600, marginBottom: 12 }}>Protocol Distribution</div>
              {(protos.protocol_stats ?? []).map((p: any, i: number) => {
                const total = (protos.protocol_stats ?? []).reduce((s: number, x: any) => s + x.count, 0) || 1;
                const pct = Math.round((p.count / total) * 100);
                return (
                  <div key={i} style={{ marginBottom: 10 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <span style={{ fontSize: 13 }}>{p.protocol}</span>
                      <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{pct}%</span>
                    </div>
                    <ScoreBar score={pct} color="var(--accent)" />
                  </div>
                );
              })}
            </div>
            <div className="g-card" style={{ padding: 20 }}>
              <div style={{ fontWeight: 600, marginBottom: 12 }}>Supported Protocols</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {(protos.supported_protocols ?? []).map((p: string) => (
                  <Badge key={p} label={p} color="#3b82f6" />
                ))}
              </div>
            </div>
          </div>
          <div className="g-card" style={{ overflow: 'auto' }}>
            <div style={{ padding: '12px 16px', fontWeight: 600, borderBottom: '1px solid var(--border)' }}>Active Sessions</div>
            <table className="g-table">
              <thead className="g-thead">
                <tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>Anomaly</th><th>Last Seen</th></tr>
              </thead>
              <tbody>
                {(protos.sessions ?? []).map((s: any, i: number) => (
                  <tr key={i} className="g-tr">
                    <td><code style={{ fontSize: 12 }}>{s.src}</code></td>
                    <td><code style={{ fontSize: 12 }}>{s.dst}</code></td>
                    <td><Badge label={s.protocol} color="#3b82f6" /></td>
                    <td>{s.packets.toLocaleString()}</td>
                    <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{(s.bytes / 1024).toFixed(1)} KB</td>
                    <td>{s.anomaly ? <Badge label={s.anomaly.replace(/_/g, ' ')} color="#ef4444" /> : <span style={{ color: 'var(--text-3)' }}>—</span>}</td>
                    <td style={{ color: 'var(--text-3)', fontSize: 12 }}>{timeAgo(s.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {sub === 'traffic' && (
        <>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <select className="g-select" style={{ width: 180 }} value={protFilter} onChange={e => setProtFilter(e.target.value)}>
              <option value="">All Protocols</option>
              {['Modbus TCP', 'DNP3', 'OPC UA', 'EtherNet/IP', 'S7', 'IEC 60870-5-104', 'BACnet', 'CIP', 'MQTT'].map(p => <option key={p} value={p}>{p}</option>)}
            </select>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
              <input type="checkbox" checked={unauthorizedOnly} onChange={e => setUnauthorizedOnly(e.target.checked)} />
              Unauthorized only
            </label>
          </div>
          <div className="g-card" style={{ overflow: 'auto' }}>
            <table className="g-table">
              <thead className="g-thead">
                <tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Function Code</th><th>Operation</th><th>Register</th><th>Value</th><th>Auth</th><th>Severity</th><th>Time</th></tr>
              </thead>
              <tbody>
                {traffic.map(t => (
                  <tr key={t.id} className="g-tr">
                    <td><code style={{ fontSize: 11 }}>{t.src_ip}</code></td>
                    <td><code style={{ fontSize: 11 }}>{t.dst_ip}</code></td>
                    <td><Badge label={t.protocol} color="#3b82f6" /></td>
                    <td><code style={{ fontSize: 11 }}>{t.function_code}</code></td>
                    <td style={{ fontSize: 12 }}>{t.operation}</td>
                    <td><code style={{ fontSize: 11, color: 'var(--text-3)' }}>{t.register_addr || '—'}</code></td>
                    <td><code style={{ fontSize: 11 }}>{t.value || '—'}</code></td>
                    <td><span style={{ color: t.is_authorized ? '#22c55e' : '#ef4444', fontSize: 12 }}>{t.is_authorized ? '✓' : '✗ Unauth'}</span></td>
                    <td><Badge label={t.severity} color={SEV_COLOR[t.severity]} /></td>
                    <td style={{ color: 'var(--text-3)', fontSize: 11 }}>{timeAgo(t.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {sub === 'dpi' && dpi && (
        <div className="g-card" style={{ overflow: 'auto' }}>
          <div style={{ padding: '12px 16px', fontWeight: 600, borderBottom: '1px solid var(--border)' }}>Decoded Industrial Protocol Frames</div>
          <table className="g-table">
            <thead className="g-thead">
              <tr><th>Source</th><th>Destination</th><th>Protocol</th><th>FC / Request</th><th>Operation</th><th>Register / Tag</th><th>Value</th><th>Auth</th><th>Time</th></tr>
            </thead>
            <tbody>
              {(dpi.decoded_frames ?? []).map((f: any) => (
                <tr key={f.id} className="g-tr">
                  <td><code style={{ fontSize: 11 }}>{f.src_ip}</code></td>
                  <td><code style={{ fontSize: 11 }}>{f.dst_ip}</code></td>
                  <td><Badge label={f.protocol} color="#6366f1" /></td>
                  <td><code style={{ fontSize: 11, color: 'var(--accent)' }}>{f.function_code}</code></td>
                  <td style={{ fontSize: 12 }}>{f.operation}</td>
                  <td><code style={{ fontSize: 11, color: 'var(--text-3)' }}>{f.register_addr || '—'}</code></td>
                  <td><code style={{ fontSize: 11 }}>{f.value || '—'}</code></td>
                  <td><span style={{ color: f.is_authorized ? '#22c55e' : '#ef4444', fontSize: 12 }}>{f.is_authorized ? '✓' : '✗'}</span></td>
                  <td style={{ color: 'var(--text-3)', fontSize: 11 }}>{timeAgo(f.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─── Device Monitoring Tab ────────────────────────────────────────────────────
function MonitoringTab() {
  const [devData, setDevData] = useState<any>(null);
  const [baseline, setBaseline] = useState<any>(null);
  const [sub, setSub] = useState<'devices' | 'firmware' | 'baseline'>('devices');

  useEffect(() => {
    otICSAPI.getDevices().then(r => setDevData(r.data));
    otICSAPI.getBaseline().then(r => setBaseline(r.data));
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 8 }}>
        {(['devices', 'firmware', 'baseline'] as const).map(s => (
          <button key={s} className={sub === s ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setSub(s)}>
            {s === 'devices' ? 'Device Health' : s === 'firmware' ? 'Firmware Changes' : 'Baseline Learning'}
          </button>
        ))}
      </div>

      {sub === 'devices' && devData && (
        <div className="g-card" style={{ overflow: 'auto' }}>
          <table className="g-table">
            <thead className="g-thead">
              <tr><th></th><th>Name</th><th>Type</th><th>Firmware</th><th>IP</th><th>Zone</th><th>Status</th><th>Uptime</th><th>Last Seen</th></tr>
            </thead>
            <tbody>
              {(devData.devices ?? []).map((d: any) => (
                <tr key={d.id} className="g-tr">
                  <td style={{ fontSize: 16 }}>{ASSET_ICON[d.asset_type] ?? '📦'}</td>
                  <td style={{ fontWeight: 600 }}>{d.name}</td>
                  <td><Badge label={d.asset_type.replace(/_/g, ' ')} color="#6366f1" /></td>
                  <td><code style={{ fontSize: 11 }}>{d.firmware}</code></td>
                  <td><code style={{ fontSize: 12 }}>{d.ip}</code></td>
                  <td style={{ fontSize: 12 }}>{d.zone}</td>
                  <td><span style={{ color: d.is_online ? '#22c55e' : '#ef4444', fontSize: 12 }}>{d.is_online ? '● Online' : '○ Offline'}</span></td>
                  <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{d.uptime_hours.toLocaleString()}h</td>
                  <td style={{ color: 'var(--text-3)', fontSize: 12 }}>{timeAgo(d.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {sub === 'firmware' && devData && (
        <div className="g-card" style={{ overflow: 'auto' }}>
          <table className="g-table">
            <thead className="g-thead">
              <tr><th>Asset ID</th><th>New Firmware</th><th>Previous</th><th>Changed By</th><th>Authorized</th><th>Changed</th></tr>
            </thead>
            <tbody>
              {(devData.firmware_changes ?? []).map((f: any) => (
                <tr key={f.id} className="g-tr">
                  <td style={{ fontWeight: 600 }}>Asset #{f.asset_id}</td>
                  <td><code style={{ fontSize: 12, color: '#22c55e' }}>{f.firmware_version}</code></td>
                  <td><code style={{ fontSize: 12, color: 'var(--text-3)' }}>{f.previous_version}</code></td>
                  <td><code style={{ fontSize: 12 }}>{f.changed_by}</code></td>
                  <td><span style={{ color: f.is_authorized ? '#22c55e' : '#ef4444', fontWeight: 700 }}>{f.is_authorized ? '✓ Authorized' : '✗ Unauthorized'}</span></td>
                  <td style={{ color: 'var(--text-3)', fontSize: 12 }}>{timeAgo(f.changed_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {sub === 'baseline' && baseline && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
            {(baseline.categories ?? []).map((c: any, i: number) => (
              <div key={i} className="g-card" style={{ padding: 16 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                  <span style={{ fontWeight: 600, fontSize: 13 }}>{c.type.replace(/_/g, ' ')}</span>
                  <span style={{ color: c.learned ? '#22c55e' : '#ef4444', fontSize: 12 }}>{c.learned ? '✓ Learned' : '○ Learning'}</span>
                </div>
                <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--accent)' }}>{c.items}</div>
                <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>{c.description}</div>
              </div>
            ))}
          </div>
          <div className="g-card" style={{ padding: 20 }}>
            <div style={{ fontWeight: 600, marginBottom: 12, color: '#f97316' }}>Baseline Deviations Detected</div>
            {(baseline.deviations ?? []).map((d: any) => (
              <div key={d.id} style={{ padding: 12, background: 'var(--border)', borderRadius: 6, marginBottom: 8, borderLeft: `3px solid ${SEV_COLOR[d.severity] ?? '#64748b'}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Badge label={d.type.replace(/_/g, ' ')} color={SEV_COLOR[d.severity]} />
                  <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{timeAgo(d.time)}</span>
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-2)', marginTop: 4 }}>{d.detail}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Threat Detection Tab ─────────────────────────────────────────────────────
function ThreatsTab() {
  const [threatData, setThreatData] = useState<any>(null);
  const [alertData, setAlertData] = useState<any>(null);
  const [sub, setSub] = useState<'threats' | 'alerts'>('threats');

  useEffect(() => {
    otICSAPI.getThreats().then(r => setThreatData(r.data));
    otICSAPI.getAlerts().then(r => setAlertData(r.data));
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 8 }}>
        {(['threats', 'alerts'] as const).map(s => (
          <button key={s} className={sub === s ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setSub(s)}>
            {s === 'threats' ? 'Threat Detections' : 'Alert Management'}
          </button>
        ))}
      </div>

      {sub === 'threats' && threatData && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="g-card" style={{ padding: 16 }}>
            <div style={{ fontWeight: 600, marginBottom: 10 }}>OT Threat Detection Categories</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {(threatData.detection_categories ?? []).map((c: string) => (
                <Badge key={c} label={c.replace(/_/g, ' ')} color="#6366f1" />
              ))}
            </div>
          </div>
          <div className="g-card" style={{ overflow: 'auto' }}>
            <table className="g-table">
              <thead className="g-thead">
                <tr><th>Type</th><th>Title</th><th>Description</th><th>Protocol</th><th>Source IP</th><th>Severity</th><th>Status</th><th>Time</th></tr>
              </thead>
              <tbody>
                {(threatData.threats ?? []).map((t: any) => (
                  <tr key={t.id} className="g-tr">
                    <td><Badge label={t.alert_type.replace(/_/g, ' ')} color="#6366f1" /></td>
                    <td style={{ fontWeight: 600, maxWidth: 200, fontSize: 13 }}>{t.title}</td>
                    <td style={{ fontSize: 12, color: 'var(--text-2)', maxWidth: 280 }}>{t.description}</td>
                    <td><Badge label={t.protocol} color="#3b82f6" /></td>
                    <td><code style={{ fontSize: 11 }}>{t.src_ip}</code></td>
                    <td><Badge label={t.severity} color={SEV_COLOR[t.severity]} /></td>
                    <td><Badge label={t.status} color={t.status === 'open' ? '#ef4444' : t.status === 'investigating' ? '#f97316' : '#22c55e'} /></td>
                    <td style={{ color: 'var(--text-3)', fontSize: 12 }}>{timeAgo(t.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {sub === 'alerts' && alertData && (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
            <StatCard label="Total Alerts" value={alertData.total ?? 0} />
            <StatCard label="Open" value={alertData.open ?? 0} color="#f97316" />
            <StatCard label="Critical" value={alertData.critical ?? 0} color="#ef4444" />
          </div>
          <div className="g-card" style={{ overflow: 'auto' }}>
            <table className="g-table">
              <thead className="g-thead">
                <tr><th>Type</th><th>Title</th><th>Protocol</th><th>Source</th><th>Severity</th><th>Status</th><th>Time</th></tr>
              </thead>
              <tbody>
                {(alertData.alerts ?? []).map((a: any) => (
                  <tr key={a.id} className="g-tr">
                    <td><Badge label={a.alert_type.replace(/_/g, ' ')} color="#6366f1" /></td>
                    <td style={{ fontWeight: 600, fontSize: 13, maxWidth: 220 }}>{a.title}</td>
                    <td><Badge label={a.protocol} color="#3b82f6" /></td>
                    <td><code style={{ fontSize: 11 }}>{a.src_ip}</code></td>
                    <td><Badge label={a.severity} color={SEV_COLOR[a.severity]} /></td>
                    <td><Badge label={a.status} color={a.status === 'open' ? '#ef4444' : a.status === 'investigating' ? '#f97316' : '#22c55e'} /></td>
                    <td style={{ color: 'var(--text-3)', fontSize: 12 }}>{timeAgo(a.created_at)}</td>
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

// ─── Risk Assessment Tab ──────────────────────────────────────────────────────
function RiskTab() {
  const [risk, setRisk] = useState<any>(null);
  const [vulns, setVulns] = useState<any>(null);
  const [zones, setZones] = useState<any>(null);
  const [attackPaths, setAttackPaths] = useState<any>(null);
  const [sub, setSub] = useState<'risk' | 'vulns' | 'zones' | 'paths'>('risk');

  useEffect(() => {
    otICSAPI.getRisk().then(r => setRisk(r.data));
    otICSAPI.getVulnerabilities().then(r => setVulns(r.data));
    otICSAPI.getZones().then(r => setZones(r.data));
    otICSAPI.getAttackPaths().then(r => setAttackPaths(r.data));
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {(['risk', 'vulns', 'zones', 'paths'] as const).map(s => (
          <button key={s} className={sub === s ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setSub(s)}>
            {s === 'risk' ? 'Risk Overview' : s === 'vulns' ? 'Vulnerabilities' : s === 'zones' ? 'Zone Segmentation' : 'Attack Paths'}
          </button>
        ))}
      </div>

      {sub === 'risk' && risk && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
            <StatCard label="Internet Exposed" value={risk.internet_exposed} color="#ef4444" sub="Critical — direct internet path" />
            <StatCard label="Unsupported Firmware" value={risk.unsupported_firmware} color="#f97316" sub="EOL / no security patches" />
            <StatCard label="Weak Authentication" value={risk.weak_auth} color="#f97316" sub="Default creds / no auth" />
            <StatCard label="Open Services" value={risk.open_services} color="#eab308" sub="Unnecessary exposed ports" />
            <StatCard label="Missing Segmentation" value={risk.missing_segmentation} color="#f97316" sub="Zones without firewall" />
            <StatCard label="Total OT Assets" value={risk.total_assets} />
          </div>
          <div className="g-card" style={{ padding: 20 }}>
            <div style={{ fontWeight: 600, marginBottom: 12 }}>Critical Assets</div>
            {(risk.critical_assets ?? []).map((a: any, i: number) => (
              <div key={i} style={{ padding: 12, background: 'var(--border)', borderRadius: 6, marginBottom: 8, borderLeft: `3px solid ${RISK_COLOR(a.risk)}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 16 }}>{ASSET_ICON[a.type] ?? '📦'}</span>
                    <span style={{ fontWeight: 700 }}>{a.name}</span>
                    <code style={{ fontSize: 11, color: 'var(--text-3)' }}>{a.ip}</code>
                  </div>
                  <span style={{ color: RISK_COLOR(a.risk), fontWeight: 700 }}>{a.risk}</span>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-2)' }}>{a.reason}</div>
              </div>
            ))}
          </div>
          <div className="g-card" style={{ overflow: 'auto' }}>
            <div style={{ padding: '12px 16px', fontWeight: 600, borderBottom: '1px solid var(--border)' }}>Risk Findings</div>
            <table className="g-table">
              <thead className="g-thead">
                <tr><th>Category</th><th>Count</th><th>Severity</th><th>Detail</th></tr>
              </thead>
              <tbody>
                {(risk.findings ?? []).map((f: any, i: number) => (
                  <tr key={i} className="g-tr">
                    <td style={{ fontWeight: 600 }}>{f.category}</td>
                    <td style={{ color: SEV_COLOR[f.severity], fontWeight: 700 }}>{f.count}</td>
                    <td><Badge label={f.severity} color={SEV_COLOR[f.severity]} /></td>
                    <td style={{ fontSize: 12 }}>{f.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {sub === 'vulns' && vulns && (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
            <StatCard label="Critical CVEs" value={vulns.critical} color="#ef4444" />
            <StatCard label="High CVEs" value={vulns.high} color="#f97316" />
            <StatCard label="Patch Available" value={vulns.patchable} color="#22c55e" sub="⚠ Requires maintenance window" />
          </div>
          <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #f97316' }}>
            <div style={{ fontSize: 12, color: '#f97316', fontWeight: 600, marginBottom: 4 }}>OT Patch Consideration</div>
            <div style={{ fontSize: 12, color: 'var(--text-2)' }}>Patching ICS/OT devices typically requires a planned maintenance window and process shutdown. Coordinate with operations and safety teams before applying any firmware updates.</div>
          </div>
          <div className="g-card" style={{ overflow: 'auto' }}>
            <table className="g-table">
              <thead className="g-thead">
                <tr><th>CVE</th><th>CVSS</th><th>Title</th><th>Advisory</th><th>Patch</th><th>Maint. Window</th><th>Severity</th></tr>
              </thead>
              <tbody>
                {(vulns.vulns ?? []).map((v: any) => (
                  <tr key={v.id} className="g-tr">
                    <td><code style={{ fontSize: 12, color: 'var(--accent)' }}>{v.cve_id}</code></td>
                    <td><span style={{ color: v.cvss >= 9 ? '#ef4444' : v.cvss >= 7 ? '#f97316' : '#eab308', fontWeight: 700 }}>{v.cvss.toFixed(1)}</span></td>
                    <td style={{ fontSize: 12, maxWidth: 240 }}>{v.title}</td>
                    <td style={{ fontSize: 11, color: 'var(--accent)' }}>{v.vendor_advisory}</td>
                    <td><span style={{ color: v.patch_available ? '#22c55e' : '#ef4444', fontSize: 12 }}>{v.patch_available ? '✓ Yes' : '✗ No'}</span></td>
                    <td><span style={{ color: v.requires_maintenance_window ? '#f97316' : '#22c55e', fontSize: 12 }}>{v.requires_maintenance_window ? '⚠ Required' : '✓ Live'}</span></td>
                    <td><Badge label={v.severity} color={SEV_COLOR[v.severity]} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {sub === 'zones' && zones && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
            {(zones.zones ?? []).map((z: any) => (
              <div key={z.id} className="g-card" style={{ padding: 16, borderLeft: `3px solid ${PURDUE_COLOR[z.purdue_level] ?? '#64748b'}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                  <span style={{ fontWeight: 700 }}>{z.name}</span>
                  <span style={{ background: (PURDUE_COLOR[z.purdue_level] ?? '#64748b') + '22', color: PURDUE_COLOR[z.purdue_level] ?? '#64748b', padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600 }}>L{z.purdue_level}</span>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 6 }}>{z.asset_count} assets · {z.firewall_policy} policy</div>
                <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 8 }}>{z.allowed_protocols}</div>
                <ScoreBar score={z.risk_score} />
                <div style={{ fontSize: 11, color: RISK_COLOR(z.risk_score), marginTop: 4, textAlign: 'right' }}>Risk: {z.risk_score}</div>
              </div>
            ))}
          </div>
          <div className="g-card" style={{ padding: 20 }}>
            <div style={{ fontWeight: 600, marginBottom: 12 }}>Purdue Model</div>
            {(zones.purdue_model ?? []).reverse().map((l: any) => (
              <div key={l.level} style={{ display: 'flex', gap: 12, padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
                <span style={{ background: (PURDUE_COLOR[l.level] ?? '#64748b') + '22', color: PURDUE_COLOR[l.level] ?? '#64748b', padding: '2px 10px', borderRadius: 4, fontSize: 12, fontWeight: 700, flexShrink: 0 }}>L{l.level}</span>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>{l.name}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-3)' }}>{l.description}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {sub === 'paths' && attackPaths && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {(attackPaths.paths ?? []).map((path: any) => (
            <div key={path.id} className="g-card" style={{ padding: 20 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
                <div style={{ fontWeight: 700, fontSize: 15 }}>{path.title}</div>
                <Badge label={path.risk} color={SEV_COLOR[path.risk]} />
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
                {(path.steps ?? []).map((s: any, i: number) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                      <div style={{ width: 28, height: 28, borderRadius: '50%', background: 'var(--accent)', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, fontWeight: 700, flexShrink: 0 }}>{s.step}</div>
                      {i < path.steps.length - 1 && <div style={{ width: 2, height: 28, background: 'var(--border)' }} />}
                    </div>
                    <div style={{ paddingTop: 4, paddingBottom: i < path.steps.length - 1 ? 0 : 0, flex: 1 }}>
                      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 2 }}>
                        <Badge label={s.layer} color="#6366f1" />
                        <code style={{ fontSize: 11, color: 'var(--accent)' }}>{s.mitre}</code>
                      </div>
                      <div style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: i < path.steps.length - 1 ? 8 : 0 }}>{s.technique}</div>
                    </div>
                  </div>
                ))}
              </div>
              {path.exploited_assets && (
                <div style={{ marginTop: 12, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <span style={{ fontSize: 12, color: 'var(--text-3)' }}>Exploited assets:</span>
                  {path.exploited_assets.map((a: string) => <Badge key={a} label={a} color="#ef4444" />)}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Intelligence Tab ─────────────────────────────────────────────────────────
function IntelligenceTab() {
  const [intel, setIntel] = useState<any>(null);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [sub, setSub] = useState<'actors' | 'malware' | 'ioc' | 'advisories' | 'timeline' | 'ai'>('actors');
  const [aiInput, setAIInput] = useState('');
  const [aiMode, setAIMode] = useState<'alert' | 'ask'>('ask');
  const [aiResult, setAIResult] = useState<any>(null);
  const [aiLoading, setAILoading] = useState(false);

  useEffect(() => {
    otICSAPI.getThreatIntel().then(r => setIntel(r.data));
    otICSAPI.getTimeline().then(r => setTimeline(r.data ?? []));
  }, []);

  const runAI = async () => {
    if (!aiInput.trim()) return;
    setAILoading(true);
    try {
      const r = await otICSAPI.analyzeAI({ mode: aiMode, content: aiInput, alert: aiInput });
      setAIResult(r.data);
    } catch { setAIResult({ error: 'AI analysis failed' }); }
    finally { setAILoading(false); }
  };

  const RISK_C: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {(['actors', 'malware', 'ioc', 'advisories', 'timeline', 'ai'] as const).map(s => (
          <button key={s} className={sub === s ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setSub(s)}>
            {s === 'actors' ? 'Threat Actors' : s === 'malware' ? 'Industrial Malware' : s === 'ioc' ? 'IOC Matches' : s === 'advisories' ? 'Advisories' : s === 'timeline' ? 'Timeline' : 'AI Analysis'}
          </button>
        ))}
      </div>

      {sub === 'actors' && intel && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {(intel.ot_threat_actors ?? []).map((a: any, i: number) => (
            <div key={i} className="g-card" style={{ padding: 16, borderLeft: `3px solid ${RISK_C[a.risk] ?? '#64748b'}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                  <span style={{ fontWeight: 700, fontSize: 15 }}>{a.name}</span>
                  <Badge label={a.nation} color="#6366f1" />
                  {a.active && <Badge label="Active" color="#ef4444" />}
                </div>
                <Badge label={a.risk} color={RISK_C[a.risk]} />
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 6 }}><strong>Targets:</strong> {a.targets}</div>
              <div style={{ fontSize: 12, color: '#f97316' }}><strong>Malware:</strong> {a.malware}</div>
            </div>
          ))}
        </div>
      )}

      {sub === 'malware' && intel && (
        <div className="g-card" style={{ overflow: 'auto' }}>
          <table className="g-table">
            <thead className="g-thead">
              <tr><th>Name</th><th>Type</th><th>Target Systems</th><th>Year</th><th>Capability</th></tr>
            </thead>
            <tbody>
              {(intel.industrial_malware ?? []).map((m: any, i: number) => (
                <tr key={i} className="g-tr">
                  <td style={{ fontWeight: 700, color: '#ef4444' }}>{m.name}</td>
                  <td><Badge label={m.type} color="#6366f1" /></td>
                  <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{m.target}</td>
                  <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{m.year}</td>
                  <td style={{ fontSize: 12 }}>{m.capability}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {sub === 'ioc' && intel && (
        <div className="g-card" style={{ overflow: 'auto' }}>
          <table className="g-table">
            <thead className="g-thead">
              <tr><th>Type</th><th>Value</th><th>Category</th><th>Hits</th><th>Threat Actor</th></tr>
            </thead>
            <tbody>
              {(intel.ioc_matches ?? []).map((m: any, i: number) => (
                <tr key={i} className="g-tr">
                  <td><Badge label={m.type} color="#f97316" /></td>
                  <td><code style={{ fontSize: 12 }}>{m.value}</code></td>
                  <td><Badge label={m.category.replace(/_/g, ' ')} color="#6366f1" /></td>
                  <td style={{ color: '#ef4444', fontWeight: 700 }}>{m.hits}</td>
                  <td style={{ fontSize: 12 }}>{m.threat_actor}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {sub === 'advisories' && intel && (
        <div className="g-card" style={{ overflow: 'auto' }}>
          <table className="g-table">
            <thead className="g-thead">
              <tr><th>Advisory ID</th><th>Title</th><th>Affected</th><th>Severity</th><th>Date</th></tr>
            </thead>
            <tbody>
              {(intel.sector_advisories ?? []).map((a: any, i: number) => (
                <tr key={i} className="g-tr">
                  <td><code style={{ fontSize: 12, color: 'var(--accent)' }}>{a.id}</code></td>
                  <td style={{ fontWeight: 600, fontSize: 13 }}>{a.title}</td>
                  <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{a.affected}</td>
                  <td><Badge label={a.severity} color={SEV_COLOR[a.severity]} /></td>
                  <td style={{ color: 'var(--text-3)', fontSize: 12 }}>{a.date}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {sub === 'timeline' && (
        <div className="g-card" style={{ overflow: 'auto' }}>
          <table className="g-table">
            <thead className="g-thead">
              <tr><th>Event</th><th>Title</th><th>Source</th><th>Severity</th><th>Status</th><th>Time</th></tr>
            </thead>
            <tbody>
              {timeline.map((e: any) => (
                <tr key={e.id} className="g-tr">
                  <td><Badge label={e.event_type.replace(/_/g, ' ')} color="#6366f1" /></td>
                  <td style={{ fontWeight: 600, fontSize: 13 }}>{e.title}</td>
                  <td><code style={{ fontSize: 11 }}>{e.source}</code></td>
                  <td><Badge label={e.severity} color={SEV_COLOR[e.severity]} /></td>
                  <td><Badge label={e.status} color={e.status === 'open' ? '#ef4444' : e.status === 'investigating' ? '#f97316' : '#22c55e'} /></td>
                  <td style={{ color: 'var(--text-3)', fontSize: 12 }}>{timeAgo(e.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {sub === 'ai' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', gap: 8 }}>
            {(['alert', 'ask'] as const).map(m => (
              <button key={m} className={aiMode === m ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'} onClick={() => setAIMode(m)}>
                {m === 'alert' ? 'Analyze OT Alert' : 'Ask AI'}
              </button>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <textarea className="g-input" rows={4} style={{ flex: 1, resize: 'vertical', fontFamily: 'monospace', fontSize: 13 }}
              placeholder={aiMode === 'alert'
                ? 'Paste alert details, e.g.: "A PLC received write commands from an engineering workstation outside the approved maintenance window."'
                : 'Ask about OT/ICS security, e.g.: "What are the risks of allowing IT/OT flat network access?"'}
              value={aiInput} onChange={e => setAIInput(e.target.value)} />
            <button className="g-btn g-btn-primary" onClick={runAI} disabled={aiLoading} style={{ alignSelf: 'flex-start' }}>
              {aiLoading ? 'Analyzing…' : 'Analyze'}
            </button>
          </div>
          {aiResult && (
            <div className="g-card" style={{ padding: 20 }}>
              {aiResult.verdict && (
                <div style={{ marginBottom: 12 }}>
                  <span style={{ fontWeight: 700, fontSize: 18, color: aiResult.verdict === 'confirmed_threat' ? '#ef4444' : '#22c55e' }}>{aiResult.verdict?.replace(/_/g, ' ').toUpperCase()}</span>
                  {aiResult.confidence && <span style={{ marginLeft: 8, color: 'var(--text-3)', fontSize: 13 }}>Confidence: {aiResult.confidence}%</span>}
                </div>
              )}
              {aiResult.threat_technique && <div style={{ marginBottom: 8 }}><Badge label={aiResult.threat_technique} color="#6366f1" /> {aiResult.mitre_ics_technique && <code style={{ fontSize: 12, color: 'var(--accent)', marginLeft: 8 }}>{aiResult.mitre_ics_technique}</code>}</div>}
              {aiResult.explanation && <p style={{ fontSize: 14, lineHeight: 1.6, marginBottom: 12 }}>{aiResult.explanation}</p>}
              {aiResult.ot_impact && <div style={{ padding: 12, background: '#ef444422', borderRadius: 6, borderLeft: '3px solid #ef4444', fontSize: 13, marginBottom: 12 }}><strong>OT Impact:</strong> {aiResult.ot_impact}</div>}
              {aiResult.safety_note && <div style={{ padding: 12, background: '#f9731622', borderRadius: 6, borderLeft: '3px solid #f97316', fontSize: 13, marginBottom: 12 }}><strong>⚠ Safety Note:</strong> {aiResult.safety_note}</div>}
              {aiResult.recommended_actions && (
                <div>
                  <div style={{ fontWeight: 600, marginBottom: 6, fontSize: 13 }}>Recommended Actions</div>
                  <ul style={{ margin: 0, paddingLeft: 20 }}>
                    {aiResult.recommended_actions.map((a: string, i: number) => <li key={i} style={{ fontSize: 13, marginBottom: 4 }}>{a}</li>)}
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

// ─── Compliance Tab ────────────────────────────────────────────────────────────
function ComplianceTab() {
  const [compliance, setCompliance] = useState<any>(null);
  useEffect(() => { otICSAPI.getCompliance().then(r => setCompliance(r.data)); }, []);
  if (!compliance) return <div style={{ color: 'var(--text-3)', padding: 32 }}>Loading…</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <StatCard label="Overall Compliance Score" value={`${compliance.overall_score}%`} color={compliance.overall_score >= 70 ? '#22c55e' : compliance.overall_score >= 50 ? '#f97316' : '#ef4444'} />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
        {(compliance.frameworks ?? []).map((f: any, i: number) => (
          <div key={i} className="g-card" style={{ padding: 16 }}>
            <div style={{ fontWeight: 600, marginBottom: 4 }}>{f.name}</div>
            {f.version && <div style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 8 }}>{f.version}</div>}
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
  );
}

// ─── Analytics Tab ─────────────────────────────────────────────────────────────
function AnalyticsTab() {
  const [analytics, setAnalytics] = useState<any>(null);
  useEffect(() => { otICSAPI.getAnalytics().then(r => setAnalytics(r.data)); }, []);
  if (!analytics) return <div style={{ color: 'var(--text-3)', padding: 32 }}>Loading analytics…</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Most Active PLCs</div>
          {(analytics.most_active_plcs ?? []).map((p: any, i: number) => (
            <div key={i} style={{ padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <span style={{ fontWeight: 600 }}>{p.name}</span>
                <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{p.commands_per_hour.toLocaleString()} cmd/h</span>
              </div>
              <div style={{ display: 'flex', gap: 16, fontSize: 12, color: 'var(--text-3)' }}>
                <span>Reads: {p.reads}</span>
                <span>Writes: {p.writes}</span>
                {p.anomalies > 0 && <span style={{ color: '#ef4444' }}>⚠ {p.anomalies} anomalies</span>}
              </div>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Protocol Distribution</div>
          {(analytics.protocol_distribution ?? []).map((p: any, i: number) => (
            <div key={i} style={{ marginBottom: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <span style={{ fontSize: 13 }}>{p.protocol}</span>
                <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{p.percent}%</span>
              </div>
              <ScoreBar score={p.percent} color="var(--accent)" />
            </div>
          ))}
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Firmware Age Distribution</div>
          {(analytics.firmware_age ?? []).map((f: any, i: number) => (
            <div key={i} style={{ marginBottom: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <span style={{ fontSize: 13 }}>{f.category}</span>
                <span style={{ color: f.color, fontWeight: 700 }}>{f.count}</span>
              </div>
              <ScoreBar score={(f.count / 47) * 100} color={f.color} />
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Config Changes (7 days)</div>
          <div style={{ display: 'flex', alignItems: 'flex-end', gap: 6, height: 80 }}>
            {(analytics.config_changes_7d ?? []).map((d: any, i: number) => {
              const max = Math.max(...(analytics.config_changes_7d ?? []).map((x: any) => x.count), 1);
              return (
                <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
                  <div style={{ width: '100%', background: d.count > 2 ? '#ef4444' : 'var(--accent)', borderRadius: 2, height: `${(d.count / max) * 60}px` }} />
                  <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{d.day}</div>
                  <div style={{ fontSize: 11, fontWeight: 700, color: d.count > 2 ? '#ef4444' : 'var(--text-2)' }}>{d.count}</div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 12 }}>Alert Trend (14 days)</div>
        <div style={{ display: 'flex', alignItems: 'flex-end', gap: 4, height: 80 }}>
          {(analytics.alert_trend ?? []).map((p: any, i: number) => {
            const max = Math.max(...(analytics.alert_trend ?? []).map((x: any) => x.count), 1);
            return (
              <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                <div style={{ width: '100%', background: p.count > 5 ? '#ef4444' : 'var(--accent)', borderRadius: 2, height: `${(p.count / max) * 60}px` }} />
                {i % 4 === 0 && <div style={{ fontSize: 9, color: 'var(--text-3)', transform: 'rotate(-30deg)' }}>{p.date?.slice(5)}</div>}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ─── Response Tab ──────────────────────────────────────────────────────────────
function ResponseTab() {
  const [action, setAction] = useState('notify_operators');
  const [target, setTarget] = useState('');
  const [reason, setReason] = useState('');
  const [responseMode, setResponseMode] = useState('alert_only');
  const [result, setResult] = useState<any>(null);
  const [executing, setExecuting] = useState(false);
  const [reportType, setReportType] = useState('executive');
  const [report, setReport] = useState<any>(null);
  const [generating, setGenerating] = useState(false);

  const ACTIONS = [
    { value: 'notify_operators', label: 'Notify Operators', desc: 'Send alarm to control room and dashboard', safe: true },
    { value: 'create_incident', label: 'Create Incident', desc: 'Open incident in OT incident management', safe: true },
    { value: 'run_soar_playbook', label: 'Run SOAR Playbook', desc: 'Execute OT-specific SOAR response', safe: true },
    { value: 'capture_traffic', label: 'Capture Traffic', desc: 'Passive PCAP capture on affected segment', safe: true },
    { value: 'block_network_path', label: 'Block Network Path', desc: 'Requires operator approval — affects network', safe: false },
    { value: 'escalate_emergency', label: 'Emergency Escalation', desc: 'Escalate to CISO and OT operations team', safe: true },
  ];

  const MODES = [
    { value: 'alert_only', label: 'Alert Only', desc: 'No automated action — monitor and notify only' },
    { value: 'operator_approval', label: 'Operator Approval', desc: 'All actions require operator confirmation' },
    { value: 'maintenance_window', label: 'Maintenance Window', desc: 'Remediation actions allowed during approved windows only' },
    { value: 'emergency', label: 'Emergency Escalation', desc: 'Immediate escalation to OT operations and CISO' },
  ];

  const execute = async () => {
    setExecuting(true);
    try { const r = await otICSAPI.respond({ action, target, reason, response_mode: responseMode }); setResult(r.data); }
    catch { setResult({ error: 'Action failed' }); }
    finally { setExecuting(false); }
  };

  const generateReport = async () => {
    setGenerating(true);
    try { const r = await otICSAPI.generateReport({ report_type: reportType }); setReport(r.data); }
    catch { setReport({ error: 'Report generation failed' }); }
    finally { setGenerating(false); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="g-card" style={{ padding: 16, borderLeft: '3px solid #f97316' }}>
        <div style={{ fontWeight: 700, color: '#f97316', marginBottom: 6 }}>⚠ Safety-Aware Response</div>
        <div style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.6 }}>
          Automated responses that could reboot PLCs, stop processes, or block critical control paths are prohibited unless explicitly operator-approved. This prevents accidental impact on physical operations and safety systems.
        </div>
      </div>

      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 12 }}>Response Mode</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10, marginBottom: 20 }}>
          {MODES.map(m => (
            <div key={m.value} onClick={() => setResponseMode(m.value)}
              style={{ padding: 12, border: `2px solid ${responseMode === m.value ? 'var(--accent)' : 'var(--border)'}`, borderRadius: 8, cursor: 'pointer', background: responseMode === m.value ? 'var(--accent)11' : undefined }}>
              <div style={{ fontWeight: 600, fontSize: 13 }}>{m.label}</div>
              <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>{m.desc}</div>
            </div>
          ))}
        </div>

        <div style={{ fontWeight: 600, marginBottom: 12 }}>Response Actions</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10, marginBottom: 16 }}>
          {ACTIONS.map(a => (
            <div key={a.value} onClick={() => setAction(a.value)}
              style={{ padding: 12, border: `2px solid ${action === a.value ? (a.safe ? 'var(--accent)' : '#ef4444') : 'var(--border)'}`, borderRadius: 8, cursor: 'pointer', background: action === a.value ? (a.safe ? 'var(--accent)11' : '#ef444411') : undefined }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 11, color: a.safe ? '#22c55e' : '#ef4444' }}>{a.safe ? '●' : '⚠'}</span>
                <span style={{ fontWeight: 600, fontSize: 13 }}>{a.label}</span>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>{a.desc}</div>
            </div>
          ))}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <input className="g-input" placeholder="Target (asset name, IP, zone…)" value={target} onChange={e => setTarget(e.target.value)} />
          <div style={{ display: 'flex', gap: 10 }}>
            <input className="g-input" style={{ flex: 1 }} placeholder="Reason / justification" value={reason} onChange={e => setReason(e.target.value)} />
            <button className="g-btn g-btn-primary" onClick={execute} disabled={executing} style={{ background: '#f97316' }}>
              {executing ? 'Executing…' : 'Execute'}
            </button>
          </div>
        </div>
        {result && (
          <div style={{ marginTop: 16 }}>
            <div style={{ padding: 12, background: result.error ? '#ef444422' : '#22c55e22', borderRadius: 6, borderLeft: `3px solid ${result.error ? '#ef4444' : '#22c55e'}`, marginBottom: result.safety_note ? 8 : 0 }}>
              {result.error ? result.error : result.message}
              {result.requires_approval && <div style={{ fontSize: 11, color: '#f97316', marginTop: 4 }}>⚠ Pending operator approval</div>}
            </div>
            {result.safety_note && <div style={{ padding: 12, background: '#f9731622', borderRadius: 6, borderLeft: '3px solid #f97316', fontSize: 12 }}>{result.safety_note}</div>}
          </div>
        )}
      </div>

      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 12 }}>Generate Report</div>
        <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
          {['executive', 'technical', 'compliance', 'incident'].map(t => (
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
            <div style={{ fontWeight: 700, fontSize: 18 }}>{report.title}</div>
            <p style={{ fontSize: 14, lineHeight: 1.6, color: 'var(--text-2)' }}>{report.executive_summary}</p>
            {report.key_findings && (
              <div>
                <div style={{ fontWeight: 600, marginBottom: 8 }}>Key Findings</div>
                <ul style={{ margin: 0, paddingLeft: 20 }}>
                  {report.key_findings.map((f: string, i: number) => <li key={i} style={{ fontSize: 13, marginBottom: 4 }}>{f}</li>)}
                </ul>
              </div>
            )}
            {report.ot_specific_risks && (
              <div>
                <div style={{ fontWeight: 600, marginBottom: 8, color: '#f97316' }}>OT-Specific Risks</div>
                <ul style={{ margin: 0, paddingLeft: 20 }}>
                  {report.ot_specific_risks.map((r: string, i: number) => <li key={i} style={{ fontSize: 13, marginBottom: 4, color: '#f97316' }}>{r}</li>)}
                </ul>
              </div>
            )}
            {report.top_recommendations && (
              <div>
                <div style={{ fontWeight: 600, marginBottom: 8 }}>Top Recommendations</div>
                {report.top_recommendations.map((r: any, i: number) => (
                  <div key={i} style={{ padding: '10px 14px', background: 'var(--border)', borderRadius: 6, marginBottom: 8, display: 'flex', gap: 12 }}>
                    <span style={{ background: 'var(--accent)', color: '#fff', borderRadius: '50%', width: 22, height: 22, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, flexShrink: 0, fontWeight: 700 }}>{r.priority}</span>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: 13 }}>{r.action}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-3)' }}>Effort: {r.estimated_effort}</div>
                      {r.safety_note && <div style={{ fontSize: 11, color: '#f97316', marginTop: 2 }}>⚠ {r.safety_note}</div>}
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

// ─── Main Page ─────────────────────────────────────────────────────────────────
export default function OTICSPage() {
  const [tab, setTab] = useState<Tab>('overview');
  const [dash, setDash] = useState<any>(null);
  const loaded = useRef<Record<string, boolean>>({});

  useEffect(() => { otICSAPI.getDashboard().then(r => setDash(r.data)); }, []);

  if (!loaded.current[tab]) loaded.current[tab] = true;

  const tabContent = useMemo(() => ({
    overview:     <OverviewTab dash={dash} />,
    inventory:    <InventoryTab />,
    topology:     <TopologyTab />,
    protocols:    <ProtocolsTab />,
    monitoring:   <MonitoringTab />,
    threats:      <ThreatsTab />,
    risk:         <RiskTab />,
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
              <h1 style={{ margin: 0, fontSize: 22, fontWeight: 700 }}>OT / ICS Security</h1>
              <p style={{ margin: '4px 0 0', fontSize: 13, color: 'var(--text-3)' }}>
                Modbus · DNP3 · OPC UA · EtherNet/IP · PROFINET · IEC 60870-5-104 · IEC 61850 · S7 · BACnet · Purdue Model monitoring
              </p>
            </div>
            {dash && (
              <div style={{ display: 'flex', gap: 16, fontSize: 13, alignItems: 'center' }}>
                <span style={{ color: '#ef4444' }}>{dash.critical_alerts} critical</span>
                <span style={{ color: '#f97316' }}>{dash.active_incidents} incidents</span>
                <span style={{ color: dash.network_health >= 85 ? '#22c55e' : '#f97316', fontWeight: 700 }}>Health: {dash.network_health}%</span>
                <span style={{ color: RISK_COLOR(dash.ot_risk_score), fontWeight: 700 }}>Risk: {dash.ot_risk_score}</span>
              </div>
            )}
          </div>
          <div style={{ display: 'flex', gap: 0, overflowX: 'auto' }}>
            {(Object.keys(TAB_LABELS) as Tab[]).map(t => (
              <button key={t} onClick={() => setTab(t)} style={{
                padding: '8px 14px', background: 'none', border: 'none', cursor: 'pointer', fontSize: 13, fontWeight: 500,
                color: tab === t ? 'var(--accent)' : 'var(--text-3)',
                borderBottom: `2px solid ${tab === t ? 'var(--accent)' : 'transparent'}`,
                whiteSpace: 'nowrap',
              }}>{TAB_LABELS[t]}</button>
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
