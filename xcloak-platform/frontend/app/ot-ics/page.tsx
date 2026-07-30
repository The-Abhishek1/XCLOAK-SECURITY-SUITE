'use client';

import { useState, useEffect, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { otICSAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import { MetricCard, SectionCard, DataTable, TabBar, ActionButton } from '@/components/design-system';
import {
  LayoutDashboard, Boxes, Network, Workflow, Activity, ShieldAlert, AlertTriangle, Radar,
  ClipboardCheck, BarChart3, Siren, Cpu, Monitor, Antenna, Server, Database, Laptop, Plug,
  Gauge, Wrench, Router, Package, Check, X, Circle,
} from 'lucide-react';

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

const TAB_ICONS: Record<Tab, any> = {
  overview: LayoutDashboard, inventory: Boxes, topology: Network, protocols: Workflow,
  monitoring: Activity, threats: ShieldAlert, risk: AlertTriangle, intelligence: Radar,
  compliance: ClipboardCheck, analytics: BarChart3, response: Siren,
};

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#3b82f6',
};

const RISK_COLOR = (s: number) => s >= 80 ? '#ef4444' : s >= 60 ? '#f97316' : s >= 40 ? '#eab308' : '#22c55e';

const ASSET_ICON: Record<string, any> = {
  plc: Cpu, hmi: Monitor, rtu: Antenna, scada_server: Server, historian: Database,
  engineering_workstation: Laptop, opc_server: Plug, sensor: Gauge, actuator: Wrench, industrial_switch: Router,
};

const PURDUE_COLOR: Record<number, string> = {
  0: '#22c55e', 1: '#3b82f6', 2: '#6366f1', 3: '#a855f7', 4: '#f97316',
};

function AssetIcon({ type, size = 16 }: { type: string; size?: number }) {
  const Icon = ASSET_ICON[type] ?? Package;
  return <Icon style={{ width: size, height: size, color: 'var(--text-2)' }} />;
}

function ScoreBar({ score, color }: { score: number; color?: string }) {
  return (
    <div style={{ background: 'var(--border)', borderRadius: 4, height: 6, width: '100%', overflow: 'hidden' }}>
      <div style={{ width: `${Math.min(score, 100)}%`, height: '100%', background: color ?? RISK_COLOR(score), borderRadius: 4 }} />
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

function Dot({ on, color }: { on: boolean; color?: string }) {
  return (
    <span style={{
      display: 'inline-block', width: 6, height: 6, borderRadius: '50%', marginRight: 6,
      background: on ? (color ?? '#22c55e') : '#ef4444',
    }} />
  );
}

// ─── Overview Tab ─────────────────────────────────────────────────────────────
function OverviewTab({ dash }: { dash: any }) {
  if (!dash) return <div style={{ color: 'var(--text-3)', padding: 32 }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
        <MetricCard label="Sites" value={dash.sites} />
        <MetricCard label="Industrial Zones" value={dash.industrial_zones} />
        <MetricCard label="PLCs" value={dash.plcs} color="#3b82f6" />
        <MetricCard label="HMIs" value={dash.hmis} color="#6366f1" />
        <MetricCard label="RTUs" value={dash.rtus} color="#a855f7" />
        <MetricCard label="Eng. Workstations" value={dash.engineering_workstations} color="#f97316" />
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
        <MetricCard label="OT Risk Score" value={`${dash.ot_risk_score}%`} color={RISK_COLOR(dash.ot_risk_score)} />
        <MetricCard label="Critical Alerts" value={dash.critical_alerts} color="#ef4444" />
        <MetricCard label="Active Incidents" value={dash.active_incidents} color="#f97316" />
        <MetricCard label="Network Health" value={`${dash.network_health}%`} color={dash.network_health >= 85 ? '#22c55e' : '#f97316'} />
      </div>
      <SectionCard title="OT Risk Score">
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{ fontSize: 48, fontWeight: 800, color: RISK_COLOR(dash.ot_risk_score) }}>{dash.ot_risk_score}</div>
          <div style={{ flex: 1 }}>
            <ScoreBar score={dash.ot_risk_score} />
            <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 8 }}>
              Score considers internet exposure, firmware age, authentication posture, segmentation, and active threats.
            </div>
          </div>
        </div>
      </SectionCard>
      <div className="g-card" style={{ padding: 16, borderLeft: '3px solid #f97316' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#f97316', marginBottom: 6, fontSize: 13, fontWeight: 600 }}>
          <AlertTriangle style={{ width: 14, height: 14 }} /> Safety-Aware Response Mode
        </div>
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
        <select className="g-select" style={{ width: 180, flexShrink: 0 }} value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
          <option value="">All Asset Types</option>
          {ASSET_TYPES.map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
        </select>
        <select className="g-select" style={{ width: 180, flexShrink: 0 }} value={zoneFilter} onChange={e => setZoneFilter(e.target.value)}>
          <option value="">All Zones</option>
          {zones.map(z => <option key={z} value={z}>{z}</option>)}
        </select>
        <div style={{ marginLeft: 'auto', fontSize: 13, color: 'var(--text-3)', alignSelf: 'center' }}>{assets.length} assets</div>
      </div>
      <DataTable<any>
        rows={assets}
        rowKey={(a: any) => a.id}
        columns={[
          { key: 'icon', header: '', render: (a: any) => <AssetIcon type={a.asset_type} /> },
          { key: 'name', header: 'Name', render: (a: any) => <span style={{ fontWeight: 600 }}>{a.name}</span> },
          { key: 'type', header: 'Type', render: (a: any) => <Badge label={a.asset_type.replace(/_/g, ' ')} color="#6366f1" /> },
          { key: 'vendor', header: 'Vendor / Model', render: (a: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{a.vendor} {a.model}</span> },
          { key: 'firmware', header: 'Firmware', render: (a: any) => <code style={{ fontSize: 11 }}>{a.firmware}</code> },
          { key: 'ip', header: 'IP', render: (a: any) => <code style={{ fontSize: 12 }}>{a.ip}</code> },
          { key: 'zone', header: 'Zone', render: (a: any) => <span style={{ fontSize: 12 }}>{a.zone}</span> },
          { key: 'purdue', header: 'Purdue', render: (a: any) => (
            <span style={{ background: (PURDUE_COLOR[a.purdue_level] ?? '#64748b') + '22', color: PURDUE_COLOR[a.purdue_level] ?? '#64748b', padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600 }}>
              L{a.purdue_level}
            </span>
          ) },
          { key: 'criticality', header: 'Criticality', render: (a: any) => <Badge label={a.criticality} color={a.criticality === 'critical' ? '#ef4444' : a.criticality === 'high' ? '#f97316' : '#64748b'} /> },
          { key: 'status', header: 'Status', render: (a: any) => (
            <span style={{ display: 'inline-flex', alignItems: 'center', color: a.is_online ? '#22c55e' : '#ef4444', fontSize: 12 }}>
              <Dot on={a.is_online} color="#22c55e" />{a.is_online ? 'Online' : 'Offline'}
            </span>
          ) },
          { key: 'risk', header: 'Risk', render: (a: any) => (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ color: RISK_COLOR(a.risk_score), fontWeight: 700, fontSize: 13, width: 28 }}>{a.risk_score}</span>
              <div style={{ width: 50 }}><ScoreBar score={a.risk_score} /></div>
            </div>
          ) },
          { key: 'last_seen', header: 'Last Seen', render: (a: any) => <span style={{ color: 'var(--text-3)', fontSize: 12 }}>{timeAgo(a.last_seen)}</span> },
        ]}
      />
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
      <SectionCard title="Purdue Model — Live Network Map">
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
                  <div style={{ marginBottom: 2 }}><AssetIcon type={n.asset_type} /></div>
                  <div style={{ fontSize: 12, fontWeight: 600 }}>{n.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{n.ip}</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
                    <Dot on={n.is_online} color="#22c55e" />
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
      </SectionCard>
      <SectionCard title="Live Communication Paths">
        <DataTable<any>
          rows={topo.links ?? []}
          rowKey={(l: any, i: number) => i}
          columns={[
            { key: 'src', header: 'Source', render: (l: any) => <code style={{ fontSize: 12 }}>{l.src}</code> },
            { key: 'dst', header: 'Destination', render: (l: any) => <code style={{ fontSize: 12 }}>{l.dst}</code> },
            { key: 'protocol', header: 'Protocol', render: (l: any) => <Badge label={l.protocol} color="#3b82f6" /> },
            { key: 'status', header: 'Status', render: (l: any) => (
              <span style={{ display: 'inline-flex', alignItems: 'center', color: l.active ? '#22c55e' : '#ef4444', fontSize: 12 }}>
                <Dot on={l.active} color="#22c55e" />{l.active ? 'Active' : 'Inactive'}
              </span>
            ) },
            { key: 'anomaly', header: 'Anomaly', render: (l: any) => l.anomaly ? <Badge label={l.anomaly.replace(/_/g, ' ')} color="#ef4444" /> : <span style={{ color: 'var(--text-3)', fontSize: 12 }}>—</span> },
          ]}
        />
      </SectionCard>
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
          <ActionButton key={s} variant={sub === s ? 'primary' : 'ghost'} onClick={() => setSub(s)}>
            {s === 'overview' ? 'Protocol Overview' : s === 'traffic' ? 'Traffic Monitor' : 'Industrial DPI'}
          </ActionButton>
        ))}
      </div>

      {sub === 'overview' && protos && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
            <SectionCard title="Protocol Distribution">
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
            </SectionCard>
            <SectionCard title="Supported Protocols">
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {(protos.supported_protocols ?? []).map((p: string) => (
                  <Badge key={p} label={p} color="#3b82f6" />
                ))}
              </div>
            </SectionCard>
          </div>
          <SectionCard title="Active Sessions">
            <DataTable<any>
              rows={protos.sessions ?? []}
              rowKey={(s: any, i: number) => i}
              columns={[
                { key: 'src', header: 'Source', render: (s: any) => <code style={{ fontSize: 12 }}>{s.src}</code> },
                { key: 'dst', header: 'Destination', render: (s: any) => <code style={{ fontSize: 12 }}>{s.dst}</code> },
                { key: 'protocol', header: 'Protocol', render: (s: any) => <Badge label={s.protocol} color="#3b82f6" /> },
                { key: 'packets', header: 'Packets', render: (s: any) => <span>{s.packets.toLocaleString()}</span> },
                { key: 'anomaly', header: 'Anomaly', render: (s: any) => s.anomaly ? <Badge label={s.anomaly.replace(/_/g, ' ')} color="#ef4444" /> : <span style={{ color: 'var(--text-3)' }}>—</span> },
                { key: 'last_seen', header: 'Last Seen', render: (s: any) => <span style={{ color: 'var(--text-3)', fontSize: 12 }}>{timeAgo(s.last_seen)}</span> },
              ]}
            />
          </SectionCard>
        </div>
      )}

      {sub === 'traffic' && (
        <>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <select className="g-select" style={{ width: 180, flexShrink: 0 }} value={protFilter} onChange={e => setProtFilter(e.target.value)}>
              <option value="">All Protocols</option>
              {['Modbus TCP', 'DNP3', 'OPC UA', 'EtherNet/IP', 'S7', 'IEC 60870-5-104', 'BACnet', 'CIP', 'MQTT'].map(p => <option key={p} value={p}>{p}</option>)}
            </select>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
              <input type="checkbox" checked={unauthorizedOnly} onChange={e => setUnauthorizedOnly(e.target.checked)} />
              Unauthorized only
            </label>
          </div>
          <DataTable<any>
            rows={traffic}
            rowKey={(t: any) => t.id}
            columns={[
              { key: 'src_ip', header: 'Source', render: (t: any) => <code style={{ fontSize: 11 }}>{t.src_ip}</code> },
              { key: 'dst_ip', header: 'Destination', render: (t: any) => <code style={{ fontSize: 11 }}>{t.dst_ip}</code> },
              { key: 'protocol', header: 'Protocol', render: (t: any) => <Badge label={t.protocol} color="#3b82f6" /> },
              { key: 'function_code', header: 'Function Code', render: (t: any) => <code style={{ fontSize: 11 }}>{t.function_code}</code> },
              { key: 'operation', header: 'Operation', render: (t: any) => <span style={{ fontSize: 12 }}>{t.operation}</span> },
              { key: 'register_addr', header: 'Register', render: (t: any) => <code style={{ fontSize: 11, color: 'var(--text-3)' }}>{t.register_addr || '—'}</code> },
              { key: 'value', header: 'Value', render: (t: any) => <code style={{ fontSize: 11 }}>{t.value || '—'}</code> },
              { key: 'auth', header: 'Auth', render: (t: any) => t.is_authorized
                ? <Check style={{ width: 13, height: 13, color: '#22c55e' }} />
                : <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#ef4444', fontSize: 12 }}><X style={{ width: 13, height: 13 }} /> Unauth</span> },
              { key: 'severity', header: 'Severity', render: (t: any) => <Badge label={t.severity} color={SEV_COLOR[t.severity]} /> },
              { key: 'time', header: 'Time', render: (t: any) => <span style={{ color: 'var(--text-3)', fontSize: 11 }}>{timeAgo(t.created_at)}</span> },
            ]}
          />
        </>
      )}

      {sub === 'dpi' && dpi && (
        <SectionCard title="Decoded Industrial Protocol Frames">
          <DataTable<any>
            rows={dpi.decoded_frames ?? []}
            rowKey={(f: any) => f.id}
            columns={[
              { key: 'src_ip', header: 'Source', render: (f: any) => <code style={{ fontSize: 11 }}>{f.src_ip}</code> },
              { key: 'dst_ip', header: 'Destination', render: (f: any) => <code style={{ fontSize: 11 }}>{f.dst_ip}</code> },
              { key: 'protocol', header: 'Protocol', render: (f: any) => <Badge label={f.protocol} color="#6366f1" /> },
              { key: 'function_code', header: 'FC / Request', render: (f: any) => <code style={{ fontSize: 11, color: 'var(--accent)' }}>{f.function_code}</code> },
              { key: 'operation', header: 'Operation', render: (f: any) => <span style={{ fontSize: 12 }}>{f.operation}</span> },
              { key: 'register_addr', header: 'Register / Tag', render: (f: any) => <code style={{ fontSize: 11, color: 'var(--text-3)' }}>{f.register_addr || '—'}</code> },
              { key: 'value', header: 'Value', render: (f: any) => <code style={{ fontSize: 11 }}>{f.value || '—'}</code> },
              { key: 'auth', header: 'Auth', render: (f: any) => f.is_authorized
                ? <Check style={{ width: 13, height: 13, color: '#22c55e' }} />
                : <X style={{ width: 13, height: 13, color: '#ef4444' }} /> },
              { key: 'time', header: 'Time', render: (f: any) => <span style={{ color: 'var(--text-3)', fontSize: 11 }}>{timeAgo(f.created_at)}</span> },
            ]}
          />
        </SectionCard>
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
          <ActionButton key={s} variant={sub === s ? 'primary' : 'ghost'} onClick={() => setSub(s)}>
            {s === 'devices' ? 'Device Health' : s === 'firmware' ? 'Firmware Changes' : 'Baseline Learning'}
          </ActionButton>
        ))}
      </div>

      {sub === 'devices' && devData && (
        <DataTable<any>
          rows={devData.devices ?? []}
          rowKey={(d: any) => d.id}
          columns={[
            { key: 'icon', header: '', render: (d: any) => <AssetIcon type={d.asset_type} /> },
            { key: 'name', header: 'Name', render: (d: any) => <span style={{ fontWeight: 600 }}>{d.name}</span> },
            { key: 'type', header: 'Type', render: (d: any) => <Badge label={d.asset_type.replace(/_/g, ' ')} color="#6366f1" /> },
            { key: 'firmware', header: 'Firmware', render: (d: any) => <code style={{ fontSize: 11 }}>{d.firmware}</code> },
            { key: 'ip', header: 'IP', render: (d: any) => <code style={{ fontSize: 12 }}>{d.ip}</code> },
            { key: 'zone', header: 'Zone', render: (d: any) => <span style={{ fontSize: 12 }}>{d.zone}</span> },
            { key: 'status', header: 'Status', render: (d: any) => (
              <span style={{ display: 'inline-flex', alignItems: 'center', color: d.is_online ? '#22c55e' : '#ef4444', fontSize: 12 }}>
                <Dot on={d.is_online} color="#22c55e" />{d.is_online ? 'Online' : 'Offline'}
              </span>
            ) },
            { key: 'uptime', header: 'Uptime', render: (d: any) => <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{d.uptime_hours.toLocaleString()}h</span> },
            { key: 'last_seen', header: 'Last Seen', render: (d: any) => <span style={{ color: 'var(--text-3)', fontSize: 12 }}>{timeAgo(d.last_seen)}</span> },
          ]}
        />
      )}

      {sub === 'firmware' && devData && (
        <DataTable<any>
          rows={devData.firmware_changes ?? []}
          rowKey={(f: any) => f.id}
          columns={[
            { key: 'asset_id', header: 'Asset ID', render: (f: any) => <span style={{ fontWeight: 600 }}>Asset #{f.asset_id}</span> },
            { key: 'firmware_version', header: 'New Firmware', render: (f: any) => <code style={{ fontSize: 12, color: '#22c55e' }}>{f.firmware_version}</code> },
            { key: 'previous_version', header: 'Previous', render: (f: any) => <code style={{ fontSize: 12, color: 'var(--text-3)' }}>{f.previous_version}</code> },
            { key: 'changed_by', header: 'Changed By', render: (f: any) => <code style={{ fontSize: 12 }}>{f.changed_by}</code> },
            { key: 'authorized', header: 'Authorized', render: (f: any) => f.is_authorized
              ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#22c55e', fontWeight: 700 }}><Check style={{ width: 13, height: 13 }} /> Authorized</span>
              : <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#ef4444', fontWeight: 700 }}><X style={{ width: 13, height: 13 }} /> Unauthorized</span> },
            { key: 'changed_at', header: 'Changed', render: (f: any) => <span style={{ color: 'var(--text-3)', fontSize: 12 }}>{timeAgo(f.changed_at)}</span> },
          ]}
        />
      )}

      {sub === 'baseline' && baseline && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
            {(baseline.categories ?? []).map((c: any, i: number) => (
              <div key={i} className="g-card" style={{ padding: 16 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                  <span style={{ fontWeight: 600, fontSize: 13 }}>{c.type.replace(/_/g, ' ')}</span>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: c.learned ? '#22c55e' : '#eab308', fontSize: 12 }}>
                    {c.learned ? <Check style={{ width: 12, height: 12 }} /> : <Circle style={{ width: 10, height: 10 }} />}
                    {c.learned ? 'Learned' : 'Learning'}
                  </span>
                </div>
                <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--accent)' }}>{c.items}</div>
              </div>
            ))}
          </div>
          <SectionCard title={<span style={{ color: '#f97316' }}>Baseline Deviations Detected</span>}>
            {(baseline.deviations ?? []).length === 0 && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No open deviations.</div>}
            {(baseline.deviations ?? []).map((d: any, i: number) => (
              <div key={i} style={{ padding: 12, background: 'var(--border)', borderRadius: 6, marginBottom: 8, borderLeft: `3px solid ${SEV_COLOR[d.severity] ?? '#64748b'}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Badge label={d.type.replace(/_/g, ' ')} color={SEV_COLOR[d.severity]} />
                  <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{timeAgo(d.time)}</span>
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-2)', marginTop: 4 }}>{d.detail}</div>
              </div>
            ))}
          </SectionCard>
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
          <ActionButton key={s} variant={sub === s ? 'primary' : 'ghost'} onClick={() => setSub(s)}>
            {s === 'threats' ? 'Threat Detections' : 'Alert Management'}
          </ActionButton>
        ))}
      </div>

      {sub === 'threats' && threatData && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <SectionCard title="OT Threat Detection Categories">
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {(threatData.detection_categories ?? []).map((c: string) => (
                <Badge key={c} label={c.replace(/_/g, ' ')} color="#6366f1" />
              ))}
            </div>
          </SectionCard>
          <DataTable<any>
            rows={threatData.threats ?? []}
            rowKey={(t: any) => t.id}
            columns={[
              { key: 'alert_type', header: 'Type', render: (t: any) => <Badge label={t.alert_type.replace(/_/g, ' ')} color="#6366f1" /> },
              { key: 'title', header: 'Title', render: (t: any) => <span style={{ fontWeight: 600, fontSize: 13 }}>{t.title}</span> },
              { key: 'description', header: 'Description', render: (t: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{t.description}</span> },
              { key: 'protocol', header: 'Protocol', render: (t: any) => <Badge label={t.protocol} color="#3b82f6" /> },
              { key: 'src_ip', header: 'Source IP', render: (t: any) => <code style={{ fontSize: 11 }}>{t.src_ip}</code> },
              { key: 'severity', header: 'Severity', render: (t: any) => <Badge label={t.severity} color={SEV_COLOR[t.severity]} /> },
              { key: 'status', header: 'Status', render: (t: any) => <Badge label={t.status} color={t.status === 'open' ? '#ef4444' : t.status === 'investigating' ? '#f97316' : '#22c55e'} /> },
              { key: 'time', header: 'Time', render: (t: any) => <span style={{ color: 'var(--text-3)', fontSize: 12 }}>{timeAgo(t.created_at)}</span> },
            ]}
          />
        </div>
      )}

      {sub === 'alerts' && alertData && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
            <MetricCard label="Total Alerts" value={alertData.total ?? 0} />
            <MetricCard label="Open" value={alertData.open ?? 0} color="#f97316" />
            <MetricCard label="Critical" value={alertData.critical ?? 0} color="#ef4444" />
          </div>
          <DataTable<any>
            rows={alertData.alerts ?? []}
            rowKey={(a: any) => a.id}
            columns={[
              { key: 'alert_type', header: 'Type', render: (a: any) => <Badge label={a.alert_type.replace(/_/g, ' ')} color="#6366f1" /> },
              { key: 'title', header: 'Title', render: (a: any) => <span style={{ fontWeight: 600, fontSize: 13 }}>{a.title}</span> },
              { key: 'protocol', header: 'Protocol', render: (a: any) => <Badge label={a.protocol} color="#3b82f6" /> },
              { key: 'src_ip', header: 'Source', render: (a: any) => <code style={{ fontSize: 11 }}>{a.src_ip}</code> },
              { key: 'severity', header: 'Severity', render: (a: any) => <Badge label={a.severity} color={SEV_COLOR[a.severity]} /> },
              { key: 'status', header: 'Status', render: (a: any) => <Badge label={a.status} color={a.status === 'open' ? '#ef4444' : a.status === 'investigating' ? '#f97316' : '#22c55e'} /> },
              { key: 'time', header: 'Time', render: (a: any) => <span style={{ color: 'var(--text-3)', fontSize: 12 }}>{timeAgo(a.created_at)}</span> },
            ]}
          />
        </div>
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
          <ActionButton key={s} variant={sub === s ? 'primary' : 'ghost'} onClick={() => setSub(s)}>
            {s === 'risk' ? 'Risk Overview' : s === 'vulns' ? 'Vulnerabilities' : s === 'zones' ? 'Zone Segmentation' : 'Attack Paths'}
          </ActionButton>
        ))}
      </div>

      {sub === 'risk' && risk && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
            <MetricCard label="Internet Exposed" value={risk.internet_exposed} color="#ef4444" sub="Critical — direct internet path" />
            <MetricCard label="Unsupported Firmware" value={risk.unsupported_firmware} color="#f97316" sub="EOL / no security patches" />
            <MetricCard label="Missing Segmentation" value={risk.missing_segmentation} color="#f97316" sub="Zones without firewall" />
            <MetricCard label="Total OT Assets" value={risk.total_assets} />
          </div>
          <SectionCard title="Critical Assets">
            {(risk.critical_assets ?? []).map((a: any, i: number) => (
              <div key={i} style={{ padding: 12, background: 'var(--border)', borderRadius: 6, marginBottom: 8, borderLeft: `3px solid ${RISK_COLOR(a.risk)}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <AssetIcon type={a.type} />
                    <span style={{ fontWeight: 700 }}>{a.name}</span>
                    <code style={{ fontSize: 11, color: 'var(--text-3)' }}>{a.ip}</code>
                  </div>
                  <span style={{ color: RISK_COLOR(a.risk), fontWeight: 700 }}>{a.risk}</span>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-2)' }}>{a.reason}</div>
              </div>
            ))}
          </SectionCard>
          <SectionCard title="Risk Findings">
            <DataTable<any>
              rows={risk.findings ?? []}
              rowKey={(f: any, i: number) => i}
              columns={[
                { key: 'category', header: 'Category', render: (f: any) => <span style={{ fontWeight: 600 }}>{f.category}</span> },
                { key: 'count', header: 'Count', render: (f: any) => <span style={{ color: SEV_COLOR[f.severity], fontWeight: 700 }}>{f.count}</span> },
                { key: 'severity', header: 'Severity', render: (f: any) => <Badge label={f.severity} color={SEV_COLOR[f.severity]} /> },
                { key: 'detail', header: 'Detail', render: (f: any) => <span style={{ fontSize: 12 }}>{f.detail}</span> },
              ]}
            />
          </SectionCard>
        </div>
      )}

      {sub === 'vulns' && vulns && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
            <MetricCard label="Critical CVEs" value={vulns.critical} color="#ef4444" />
            <MetricCard label="High CVEs" value={vulns.high} color="#f97316" />
            <MetricCard label="Patch Available" value={vulns.patchable} color="#22c55e" sub="Requires maintenance window" />
          </div>
          <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #f97316' }}>
            <div style={{ fontSize: 12, color: '#f97316', fontWeight: 600, marginBottom: 4 }}>OT Patch Consideration</div>
            <div style={{ fontSize: 12, color: 'var(--text-2)' }}>Patching ICS/OT devices typically requires a planned maintenance window and process shutdown. Coordinate with operations and safety teams before applying any firmware updates.</div>
          </div>
          <DataTable<any>
            rows={vulns.vulns ?? []}
            rowKey={(v: any) => v.id}
            columns={[
              { key: 'cve_id', header: 'CVE', render: (v: any) => <code style={{ fontSize: 12, color: 'var(--accent)' }}>{v.cve_id}</code> },
              { key: 'cvss', header: 'CVSS', render: (v: any) => <span style={{ color: v.cvss >= 9 ? '#ef4444' : v.cvss >= 7 ? '#f97316' : '#eab308', fontWeight: 700 }}>{v.cvss.toFixed(1)}</span> },
              { key: 'title', header: 'Title', render: (v: any) => <span style={{ fontSize: 12 }}>{v.title}</span> },
              { key: 'vendor_advisory', header: 'Advisory', render: (v: any) => <span style={{ fontSize: 11, color: 'var(--accent)' }}>{v.vendor_advisory}</span> },
              { key: 'patch_available', header: 'Patch', render: (v: any) => v.patch_available
                ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#22c55e', fontSize: 12 }}><Check style={{ width: 13, height: 13 }} /> Yes</span>
                : <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#ef4444', fontSize: 12 }}><X style={{ width: 13, height: 13 }} /> No</span> },
              { key: 'maint_window', header: 'Maint. Window', render: (v: any) => v.requires_maintenance_window
                ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#f97316', fontSize: 12 }}><AlertTriangle style={{ width: 12, height: 12 }} /> Required</span>
                : <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#22c55e', fontSize: 12 }}><Check style={{ width: 13, height: 13 }} /> Live</span> },
              { key: 'severity', header: 'Severity', render: (v: any) => <Badge label={v.severity} color={SEV_COLOR[v.severity]} /> },
            ]}
          />
        </div>
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
          <SectionCard title="Purdue Model">
            {(zones.purdue_model ?? []).slice().reverse().map((l: any) => (
              <div key={l.level} style={{ display: 'flex', gap: 12, padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
                <span style={{ background: (PURDUE_COLOR[l.level] ?? '#64748b') + '22', color: PURDUE_COLOR[l.level] ?? '#64748b', padding: '2px 10px', borderRadius: 4, fontSize: 12, fontWeight: 700, flexShrink: 0 }}>L{l.level}</span>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>{l.name}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-3)' }}>{l.description}</div>
                </div>
              </div>
            ))}
          </SectionCard>
        </div>
      )}

      {sub === 'paths' && attackPaths && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <SectionCard title="Highest-Risk OT Assets">
            {(attackPaths.risk_assets ?? []).length === 0 && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No high-risk assets found.</div>}
            {(attackPaths.risk_assets ?? []).map((a: any, i: number) => (
              <div key={i} style={{ padding: 12, background: 'var(--border)', borderRadius: 6, marginBottom: 8, borderLeft: `3px solid ${RISK_COLOR(a.risk_score)}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <AssetIcon type={a.asset_type} />
                    <span style={{ fontWeight: 700 }}>{a.name}</span>
                    <code style={{ fontSize: 11, color: 'var(--text-3)' }}>{a.ip}</code>
                  </div>
                  <span style={{ color: RISK_COLOR(a.risk_score), fontWeight: 700 }}>{a.risk_score}</span>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-2)' }}>Zone: {a.zone} · Purdue L{a.purdue_level} · {a.criticality} criticality</div>
              </div>
            ))}
          </SectionCard>
          <SectionCard title="Exposed Control-Layer Vulnerabilities" subtitle="CVEs affecting assets at Purdue level 0–1">
            {(attackPaths.exposed_control_vulns ?? []).length === 0 && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>None found.</div>}
            {(attackPaths.exposed_control_vulns ?? []).map((v: any, i: number) => (
              <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
                <div>
                  <code style={{ fontSize: 12, color: 'var(--accent)', fontWeight: 600 }}>{v.cve_id}</code>
                  <span style={{ fontSize: 12, color: 'var(--text-3)', marginLeft: 8 }}>{v.asset}</span>
                </div>
                <Badge label={v.severity} color={SEV_COLOR[v.severity]} />
              </div>
            ))}
          </SectionCard>
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
          <ActionButton key={s} variant={sub === s ? 'primary' : 'ghost'} onClick={() => setSub(s)}>
            {s === 'actors' ? 'Threat Actors' : s === 'malware' ? 'Industrial Malware' : s === 'ioc' ? 'IOC Matches' : s === 'advisories' ? 'Advisories' : s === 'timeline' ? 'Timeline' : 'AI Analysis'}
          </ActionButton>
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
        <DataTable<any>
          rows={intel.industrial_malware ?? []}
          rowKey={(m: any, i: number) => i}
          columns={[
            { key: 'name', header: 'Name', render: (m: any) => <span style={{ fontWeight: 700, color: '#ef4444' }}>{m.name}</span> },
            { key: 'type', header: 'Type', render: (m: any) => <Badge label={m.type} color="#6366f1" /> },
            { key: 'target', header: 'Target Systems', render: (m: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{m.target}</span> },
            { key: 'year', header: 'Year', render: (m: any) => <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{m.year}</span> },
            { key: 'capability', header: 'Capability', render: (m: any) => <span style={{ fontSize: 12 }}>{m.capability}</span> },
          ]}
        />
      )}

      {sub === 'ioc' && intel && (
        <DataTable<any>
          rows={intel.ioc_matches ?? []}
          rowKey={(m: any, i: number) => i}
          columns={[
            { key: 'type', header: 'Type', render: (m: any) => <Badge label={m.type} color="#f97316" /> },
            { key: 'value', header: 'Value', render: (m: any) => <code style={{ fontSize: 12 }}>{m.value}</code> },
            { key: 'hits', header: 'Hits', render: (m: any) => <span style={{ color: '#ef4444', fontWeight: 700 }}>{m.hits}</span> },
          ]}
        />
      )}

      {sub === 'advisories' && intel && (
        <DataTable<any>
          rows={intel.sector_advisories ?? []}
          rowKey={(a: any, i: number) => i}
          columns={[
            { key: 'id', header: 'Advisory ID', render: (a: any) => <code style={{ fontSize: 12, color: 'var(--accent)' }}>{a.id}</code> },
            { key: 'title', header: 'Title', render: (a: any) => <span style={{ fontWeight: 600, fontSize: 13 }}>{a.title}</span> },
            { key: 'affected', header: 'Affected', render: (a: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{a.affected}</span> },
            { key: 'severity', header: 'Severity', render: (a: any) => <Badge label={a.severity} color={SEV_COLOR[a.severity]} /> },
            { key: 'date', header: 'Date', render: (a: any) => <span style={{ color: 'var(--text-3)', fontSize: 12 }}>{a.date}</span> },
          ]}
        />
      )}

      {sub === 'timeline' && (
        <DataTable<any>
          rows={timeline}
          rowKey={(e: any) => e.id}
          columns={[
            { key: 'event_type', header: 'Event', render: (e: any) => <Badge label={e.event_type.replace(/_/g, ' ')} color="#6366f1" /> },
            { key: 'title', header: 'Title', render: (e: any) => <span style={{ fontWeight: 600, fontSize: 13 }}>{e.title}</span> },
            { key: 'source', header: 'Source', render: (e: any) => <code style={{ fontSize: 11 }}>{e.source}</code> },
            { key: 'severity', header: 'Severity', render: (e: any) => <Badge label={e.severity} color={SEV_COLOR[e.severity]} /> },
            { key: 'status', header: 'Status', render: (e: any) => <Badge label={e.status} color={e.status === 'open' ? '#ef4444' : e.status === 'investigating' ? '#f97316' : '#22c55e'} /> },
            { key: 'time', header: 'Time', render: (e: any) => <span style={{ color: 'var(--text-3)', fontSize: 12 }}>{timeAgo(e.created_at)}</span> },
          ]}
        />
      )}

      {sub === 'ai' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', gap: 8 }}>
            {(['alert', 'ask'] as const).map(m => (
              <ActionButton key={m} variant={aiMode === m ? 'primary' : 'ghost'} onClick={() => setAIMode(m)}>
                {m === 'alert' ? 'Analyze OT Alert' : 'Ask AI'}
              </ActionButton>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <textarea className="g-input" rows={4} style={{ flex: 1, resize: 'vertical', fontFamily: 'monospace', fontSize: 13 }}
              placeholder={aiMode === 'alert'
                ? 'Paste alert details, e.g.: "A PLC received write commands from an engineering workstation outside the approved maintenance window."'
                : 'Ask about OT/ICS security, e.g.: "What are the risks of allowing IT/OT flat network access?"'}
              value={aiInput} onChange={e => setAIInput(e.target.value)} />
            <ActionButton variant="primary" onClick={runAI} loading={aiLoading} style={{ alignSelf: 'flex-start' }}>
              {aiLoading ? 'Analyzing…' : 'Analyze'}
            </ActionButton>
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
              {aiResult.safety_note && (
                <div style={{ display: 'flex', gap: 8, padding: 12, background: '#f9731622', borderRadius: 6, borderLeft: '3px solid #f97316', fontSize: 13, marginBottom: 12 }}>
                  <AlertTriangle style={{ width: 14, height: 14, color: '#f97316', flexShrink: 0, marginTop: 2 }} />
                  <span><strong>Safety Note:</strong> {aiResult.safety_note}</span>
                </div>
              )}
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
      <MetricCard label="Overall Compliance Score" value={`${compliance.overall_score}%`} color={compliance.overall_score >= 70 ? '#22c55e' : compliance.overall_score >= 50 ? '#f97316' : '#ef4444'} />
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
        <SectionCard title="Most Active PLCs">
          {(analytics.most_active_plcs ?? []).map((p: any, i: number) => (
            <div key={i} style={{ padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <span style={{ fontWeight: 600 }}>{p.name}</span>
                <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{p.commands.toLocaleString()} commands</span>
              </div>
              <div style={{ display: 'flex', gap: 16, fontSize: 12, color: 'var(--text-3)', alignItems: 'center' }}>
                <span>Reads: {p.reads}</span>
                <span>Writes: {p.writes}</span>
                {p.anomalies > 0 && (
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#ef4444' }}>
                    <AlertTriangle style={{ width: 12, height: 12 }} /> {p.anomalies} anomalies
                  </span>
                )}
              </div>
            </div>
          ))}
        </SectionCard>
        <SectionCard title="Protocol Distribution">
          {(analytics.protocol_distribution ?? []).map((p: any, i: number) => (
            <div key={i} style={{ marginBottom: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <span style={{ fontSize: 13 }}>{p.protocol}</span>
                <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{p.percent}%</span>
              </div>
              <ScoreBar score={p.percent} color="var(--accent)" />
            </div>
          ))}
        </SectionCard>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 16 }}>
        <SectionCard title="Config Changes (7 days)">
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
        </SectionCard>
      </div>
      <SectionCard title="Alert Trend (14 days)">
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
      </SectionCard>
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
    catch (err: any) { setResult({ error: err?.response?.data?.error || 'Action failed' }); }
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
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontWeight: 700, color: '#f97316', marginBottom: 6 }}>
          <AlertTriangle style={{ width: 14, height: 14 }} /> Safety-Aware Response
        </div>
        <div style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.6 }}>
          Automated responses that could reboot PLCs, stop processes, or block critical control paths are prohibited unless explicitly operator-approved. This prevents accidental impact on physical operations and safety systems.
        </div>
      </div>

      <SectionCard title="Response Mode">
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
                {a.safe ? <Dot on={true} color="#22c55e" /> : <AlertTriangle style={{ width: 11, height: 11, color: '#ef4444' }} />}
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
            <ActionButton variant="primary" onClick={execute} loading={executing} style={{ background: '#f97316' }}>
              {executing ? 'Executing…' : 'Execute'}
            </ActionButton>
          </div>
          <a href="/playbooks" className="g-btn g-btn-ghost" style={{ textAlign: 'center' as const }}>Run SOAR Playbook</a>
        </div>
        {result && (
          <div style={{ marginTop: 16 }}>
            <div style={{ padding: 12, background: result.error ? '#ef444422' : '#22c55e22', borderRadius: 6, borderLeft: `3px solid ${result.error ? '#ef4444' : '#22c55e'}`, marginBottom: result.safety_note ? 8 : 0 }}>
              {result.error ? result.error : result.message}
              {result.requires_approval && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: '#f97316', marginTop: 4 }}>
                  <AlertTriangle style={{ width: 11, height: 11 }} /> Pending operator approval
                </div>
              )}
            </div>
            {result.safety_note && <div style={{ padding: 12, background: '#f9731622', borderRadius: 6, borderLeft: '3px solid #f97316', fontSize: 12 }}>{result.safety_note}</div>}
          </div>
        )}
      </SectionCard>

      <SectionCard
        title="Generate Report"
        actions={<ActionButton variant="primary" onClick={generateReport} loading={generating}>{generating ? 'Generating…' : 'Generate with AI'}</ActionButton>}
      >
        <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
          {['executive', 'technical', 'compliance', 'incident'].map(t => (
            <ActionButton key={t} variant={reportType === t ? 'primary' : 'ghost'} onClick={() => setReportType(t)}>
              {t.charAt(0).toUpperCase() + t.slice(1)}
            </ActionButton>
          ))}
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
                      {r.safety_note && (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: 11, color: '#f97316', marginTop: 2 }}>
                          <AlertTriangle style={{ width: 11, height: 11 }} /> {r.safety_note}
                        </div>
                      )}
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
    <RootLayout title="OT / ICS Security"
      subtitle="Modbus · DNP3 · OPC UA · EtherNet/IP · PROFINET · IEC 60870-5-104 · IEC 61850 · S7 · BACnet · Purdue Model monitoring"
      actions={dash ? (
        <div style={{ display: 'flex', gap: 16, fontSize: 13, alignItems: 'center' }}>
          <span style={{ color: '#ef4444' }}>{dash.critical_alerts} critical</span>
          <span style={{ color: '#f97316' }}>{dash.active_incidents} incidents</span>
          <span style={{ color: dash.network_health >= 85 ? '#22c55e' : '#f97316', fontWeight: 700 }}>Health: {dash.network_health}%</span>
          <span style={{ color: RISK_COLOR(dash.ot_risk_score), fontWeight: 700 }}>Risk: {dash.ot_risk_score}</span>
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
