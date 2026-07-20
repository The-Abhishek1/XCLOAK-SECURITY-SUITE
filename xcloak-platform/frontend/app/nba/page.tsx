'use client';

import { useEffect, useState, useCallback, useMemo, useRef } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { nbaAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import Link from 'next/link';
import { Activity, AlertTriangle, ArrowRight, ArrowUpRight, Ban, BarChart2, Bot, Cable, CheckCircle2, ChevronRight, Clock, Cpu, Crosshair, Download, Eye, FileText, FlaskConical, GitBranch, Globe, HardDrive, Info, Layers, Loader2, Lock, Map, Monitor, Network, Package, Play, Radio, RefreshCw, ScanLine, Search, Server, Shield, ShieldAlert, Terminal, TrendingUp, Wifi, X, XCircle, Zap } from '@/lib/icon-stubs';

// ── Types ──────────────────────────────────────────────────────────────────

interface Overview {
  total_flows: number; active_connections: number; suspicious_connections: number;
  beaconing_detections: number; lateral_movement: number; data_exfiltration: number;
  c2_communications: number; high_risk_hosts: number; network_risk_score: number;
  top_talkers: TopTalker[]; window_minutes: number;
}
interface TopTalker {
  host: string; agent_id: number; conn_count: number; unique_ips: number; anomaly_count: number;
}
interface Flow {
  agent_id: number; hostname: string; src_address: string; dst_address: string;
  protocol: string; process: string; state: string; country: string; country_code: string;
  is_external: boolean; is_suspicious: boolean; detected_at: string;
}
interface TrafficAnalysis {
  protocols: Array<{ protocol: string; count: number }>;
  top_talkers: Array<{ host: string; conn_count: number; unique_external_ips: number }>;
  top_destinations: Array<{ remote_address: string; count: number }>;
  east_west_count: number; north_south_count: number;
  hourly_trend: Array<{ hour: string; count: number }>;
}
interface DNSAnalytics {
  total_dns_queries: number; dns_anomalies: number;
  dns_events: Array<{ agent_id: number; hostname: string; type: string; score: number; description: string; detected_at: string }>;
  top_dns_servers: Array<{ dest: string; count: number }>;
}
interface TLSAnalytics {
  total_tls_connections: number; unknown_destinations: number;
  ja3_fingerprints: Array<{ id: number; fingerprint: string; label: string; severity: string; description: string; tenant_wide: boolean }>;
  suspicious_tls: Array<{ address: string; count: number; hostname: string }>;
}
interface Beacon {
  id: number; agent_id: number; hostname: string; dst_ip: string; dst_port: number;
  proto: string; score: number; description: string; process: string; detected_at: string;
}
interface BeaconData { beacons: Beacon[]; total: number; high_confidence: number; unique_c2_ips: number; }
interface LateralEvent {
  agent_id: number; src_host: string; dst_address: string; protocol: string;
  port: string; method: string; process: string; count: number; first_seen: string; last_seen: string;
}
interface LateralAnomaly {
  id: number; agent_id: number; hostname: string; dst_ip: string; score: number; description: string; detected_at: string;
}
interface LateralData { lateral_events: LateralEvent[]; lateral_anomalies: LateralAnomaly[]; total: number; }
interface TIHit {
  agent_id: number; hostname: string; remote_address: string; process: string;
  ioc_type: string; ioc_value: string; threat_type: string; confidence: number; first_seen: string;
}
interface IOCBlock { ip: string; hit_count: number; blocked_at: string; }
interface ThreatIntelData { threat_intel_hits: TIHit[]; ioc_blocks: IOCBlock[]; total_hits: number; }
interface MITRETechnique {
  technique_id: string; technique_name: string; anomaly_types: string[]; hit_count: number; max_score: number;
}
interface ProtoEntry { name: string; port: string; count: number; is_risky: boolean; }
interface TimelineEvent {
  event_type: string; hostname: string; agent_id: number; remote_address: string;
  protocol: string; process: string; score: number; detail: string; timestamp: string;
}
interface AnalyticsData {
  total_connections: number; unique_hosts: number; blocked_ips: number;
  geo_distribution: Array<{ country: string; country_code: string; count: number }>;
  anomaly_trend: Array<{ hour: string; count: number; avg_score: number }>;
  most_suspicious_hosts: Array<{ hostname: string; agent_id: number; anomaly_count: number; max_score: number }>;
  beacon_frequency: Array<{ hostname: string; count: number; max_score: number }>;
}
interface AIInsight {
  threat_summary: string; risk_level: string; key_findings: string[];
  suspicious_behaviors: string[]; mitre_techniques: string[];
  recommendations: string[]; confidence: number;
}

// ── Helpers / constants ───────────────────────────────────────────────────

const RISK_COLOR = (s: number) => s >= 80 ? 'var(--red)' : s >= 60 ? 'var(--orange)' : s >= 30 ? 'var(--yellow)' : 'var(--green)';
const RL: Record<string, string> = { critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--green)' };
const SEV: Record<string, string> = { critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--green)', info: 'var(--text-3)' };
const PROTO_COLOR: Record<string, string> = {
  HTTP: 'var(--blue)', HTTPS: 'var(--green)', DNS: 'var(--yellow)', SMB: 'var(--red)', LDAP: 'var(--orange)',
  Kerberos: 'var(--orange)', SSH: 'var(--accent)', FTP: 'var(--yellow)', SMTP: 'var(--blue)',
  RDP: 'var(--red)', WinRM: 'var(--orange)', SNMP: 'var(--text-3)', MQTT: 'var(--accent)',
};

const LATERAL_METHOD_ICON: Record<string, any> = {
  SMB: HardDrive, RDP: Monitor, SSH: Terminal, 'WinRM': Server, 'WinRM(S)': Server,
  'RPC/DCOM': Cpu, Telnet: Terminal, VNC: Eye, NetBIOS: Network, Meterpreter: Zap,
};

function SectionHeader({ icon: Icon, title, action }: { icon: any; title: string; action?: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 px-4 py-2.5 shrink-0"
      style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
      <Icon className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--accent)' }} />
      <span className="text-[10px] font-bold uppercase tracking-wider flex-1" style={{ color: 'var(--text-3)' }}>{title}</span>
      {action}
    </div>
  );
}

function Spinner() {
  return <div className="flex justify-center py-6"><Loader2 className="h-5 w-5 animate-spin" style={{ color: 'var(--text-3)' }} /></div>;
}

function Empty({ icon: Icon, text }: { icon: any; text: string }) {
  return (
    <div className="py-8 text-center space-y-2">
      <Icon className="h-8 w-8 mx-auto opacity-15" style={{ color: 'var(--text-3)' }} />
      <p className="text-xs" style={{ color: 'var(--text-3)' }}>{text}</p>
    </div>
  );
}

function ScoreBadge({ score }: { score: number }) {
  const c = RISK_COLOR(score);
  return (
    <span className="text-[10px] px-2 py-0.5 rounded font-bold tabular-nums"
      style={{ background: `${c}18`, color: c, border: `1px solid ${c}44` }}>{score}</span>
  );
}

function Tag({ text, color = 'var(--accent)' }: { text: string; color?: string }) {
  return (
    <span className="text-[9px] px-1.5 py-0.5 rounded font-semibold"
      style={{ background: `${color}18`, color, border: `1px solid ${color}33` }}>{text}</span>
  );
}

// ── Network Graph (SVG) ────────────────────────────────────────────────────

function NetworkGraph({ overview, onClick }: { overview: Overview | null; onClick: (node: string) => void }) {
  const nodes = useMemo(() => [
    { id: 'internet',   label: 'Internet',      x: 300, y: 40,  icon: '🌐️', color: 'var(--text-3)' },
    { id: 'firewall',   label: 'Firewall',       x: 300, y: 130, icon: '🛡️', color: 'var(--green)' },
    { id: 'dmz',        label: 'DMZ',            x: 160, y: 220, icon: '⚡️', color: 'var(--yellow)' },
    { id: 'corp',       label: 'Corp Network',   x: 300, y: 220, icon: '🏢️', color: 'var(--accent)' },
    { id: 'ot',         label: 'OT/ICS',         x: 440, y: 220, icon: '⚙️', color: 'var(--orange)' },
    { id: 'workstation',label: 'Workstations',   x: 180, y: 320, icon: '💻️', color: 'var(--accent)' },
    { id: 'server',     label: 'File Server',    x: 300, y: 320, icon: '🖥️', color: 'var(--blue)' },
    { id: 'dc',         label: 'Domain Ctrl',    x: 420, y: 320, icon: '🔑️', color: 'var(--orange)' },
    { id: 'db',         label: 'Database',       x: 300, y: 410, icon: '🗄️', color: 'var(--red)' },
  ], []);

  const edges = [
    { from: 'internet', to: 'firewall' },
    { from: 'firewall', to: 'dmz' },
    { from: 'firewall', to: 'corp' },
    { from: 'firewall', to: 'ot' },
    { from: 'corp', to: 'workstation' },
    { from: 'corp', to: 'server' },
    { from: 'corp', to: 'dc' },
    { from: 'server', to: 'db' },
  ];

  const lateral = (overview?.lateral_movement ?? 0) > 0;
  const beaconing = (overview?.beaconing_detections ?? 0) > 0;

  const nodeMap = useMemo(() => Object.fromEntries(nodes.map(n => [n.id, n])), [nodes]);

  return (
    <div className="relative">
      <svg viewBox="0 0 600 460" className="w-full" style={{ maxHeight: 460 }}>
        {/* Edges */}
        {edges.map(e => {
          const s = nodeMap[e.from]; const t = nodeMap[e.to];
          const isLateral = lateral && ['workstation', 'server', 'dc', 'db'].includes(e.from);
          const isBeacon = beaconing && ['internet'].includes(e.from);
          return (
            <line key={`${e.from}-${e.to}`} x1={s.x} y1={s.y} x2={t.x} y2={t.y} strokeWidth="1.5"
              stroke={isLateral ? 'var(--red)' : isBeacon ? 'var(--orange)' : 'var(--border)'}
              strokeDasharray={isLateral || isBeacon ? '4,3' : undefined} opacity={0.7} />
          );
        })}
        {/* Nodes */}
        {nodes.map(n => (
          <g key={n.id} style={{ cursor: 'pointer' }} onClick={() => onClick(n.label)}>
            <circle cx={n.x} cy={n.y} r="24" fill={`${n.color}18`} stroke={n.color} strokeWidth="1.5" />
            <text x={n.x} y={n.y + 1} textAnchor="middle" dominantBaseline="middle" fontSize="16">{n.icon}</text>
            <text x={n.x} y={n.y + 34} textAnchor="middle" fontSize="9" fill="var(--text-2)" fontFamily="sans-serif">{n.label}</text>
            {n.id === 'internet' && beaconing && (
              <circle cx={n.x + 18} cy={n.y - 18} r="6" fill="var(--orange)" className="animate-pulse" />
            )}
            {['workstation', 'dc'].includes(n.id) && lateral && (
              <circle cx={n.x + 18} cy={n.y - 18} r="6" fill="var(--red)" className="animate-pulse" />
            )}
          </g>
        ))}
      </svg>
      {/* Legend */}
      <div className="absolute bottom-2 right-3 flex flex-col gap-1">
        <div className="flex items-center gap-1.5 text-[9px]" style={{ color: 'var(--text-3)' }}>
          <div className="h-0.5 w-4 rounded" style={{ background: 'var(--border)' }} /> Normal traffic
        </div>
        <div className="flex items-center gap-1.5 text-[9px]" style={{ color: 'var(--red)' }}>
          <div className="h-0.5 w-4 rounded border-t border-dashed" style={{ borderColor: 'var(--red)' }} /> Lateral movement
        </div>
        <div className="flex items-center gap-1.5 text-[9px]" style={{ color: 'var(--orange)' }}>
          <div className="h-0.5 w-4 rounded border-t border-dashed" style={{ borderColor: 'var(--orange)' }} /> C2 beaconing
        </div>
      </div>
    </div>
  );
}

// ── Flow Table ────────────────────────────────────────────────────────────

function FlowTable({ flows, loading, searchQ }: { flows: Flow[]; loading: boolean; searchQ: string }) {
  const filtered = useMemo(() => {
    if (!searchQ) return flows;
    const q = searchQ.toLowerCase();
    return flows.filter(f =>
      f.hostname?.toLowerCase().includes(q) ||
      f.src_address?.includes(q) ||
      f.dst_address?.includes(q) ||
      f.protocol?.toLowerCase().includes(q) ||
      f.process?.toLowerCase().includes(q)
    );
  }, [flows, searchQ]);

  if (loading) return <Spinner />;
  if (filtered.length === 0) return <Empty icon={Network} text="No flows in the selected time window." />;

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border)' }}>
            {['Source', 'Destination', 'Protocol', 'Process', 'State', 'Ext', ''].map(h => (
              <th key={h} className="px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {filtered.slice(0, 200).map((f, i) => (
            <tr key={i} className="hover:bg-[var(--glass-hover)] transition-colors" style={{ borderBottom: '1px solid var(--border)' }}>
              <td className="px-3 py-2 font-mono text-[11px]" style={{ color: 'var(--text-2)' }}>{f.src_address || f.hostname || '—'}</td>
              <td className="px-3 py-2 font-mono text-[11px]" style={{ color: f.is_suspicious ? 'var(--red)' : 'var(--accent)' }}>
                {f.dst_address || '—'}
              </td>
              <td className="px-3 py-2">
                <Tag text={f.protocol?.toUpperCase() || 'TCP'} color={PROTO_COLOR[f.protocol?.toUpperCase()] ?? 'var(--text-3)'} />
              </td>
              <td className="px-3 py-2 font-mono text-[10px] max-w-[120px] truncate" style={{ color: 'var(--text-3)' }}>{f.process || '—'}</td>
              <td className="px-3 py-2">
                <span className="text-[10px]" style={{ color: f.state === 'closed' ? 'var(--text-3)' : 'var(--green)' }}>
                  {f.state || 'connected'}
                </span>
              </td>
              <td className="px-3 py-2">
                {f.is_external && (
                  <div className="flex items-center gap-1">
                    <ArrowUpRight className="h-3 w-3" style={{ color: 'var(--orange)' }} />
                    {f.country_code && <span className="text-[9px]" style={{ color: 'var(--text-3)' }}>{f.country_code}</span>}
                  </div>
                )}
              </td>
              <td className="px-3 py-2">
                {f.is_suspicious && <AlertTriangle className="h-3.5 w-3.5" style={{ color: 'var(--red)' }} />}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Protocol Radar ─────────────────────────────────────────────────────────

function ProtocolBreakdown({ protocols, loading }: { protocols: ProtoEntry[]; loading: boolean }) {
  if (loading) return <Spinner />;
  const maxCount = Math.max(...protocols.map(p => p.count), 1);
  return (
    <div className="p-3 space-y-2">
      {protocols.map(p => (
        <div key={p.port} className="flex items-center gap-2">
          <div className="w-24 text-right shrink-0">
            <span className="text-[10px] font-mono" style={{ color: p.is_risky ? 'var(--red)' : 'var(--text-2)' }}>
              {p.name}
            </span>
          </div>
          <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: 'var(--border)' }}>
            <div className="h-full rounded-full"
              style={{ width: `${(p.count / maxCount) * 100}%`, background: p.is_risky ? 'var(--red)' : PROTO_COLOR[p.name] ?? 'var(--accent)' }} />
          </div>
          <span className="text-[10px] font-bold tabular-nums w-10 text-right" style={{ color: p.is_risky ? 'var(--red)' : 'var(--text-3)' }}>
            {p.count.toLocaleString()}
          </span>
          {p.is_risky && <AlertTriangle className="h-3 w-3 shrink-0" style={{ color: 'var(--red)' }} />}
        </div>
      ))}
      {protocols.length === 0 && <Empty icon={Layers} text="No protocol data." />}
    </div>
  );
}

// ── Behavioral Detection Panel ─────────────────────────────────────────────

const BEHAVIORAL_CHECKS = [
  { label: 'Port Scanning',      key: 'port_scan',       icon: ScanLine,    desc: 'Rapid connection attempts across multiple ports' },
  { label: 'Host Discovery',     key: 'host_discovery',  icon: Network,     desc: 'Systematic sweep of IP ranges' },
  { label: 'ARP Spoofing',       key: 'arp_spoof',       icon: Cable,       desc: 'ARP cache poisoning detected' },
  { label: 'DNS Tunneling',      key: 'dns_tunnel',      icon: Globe,       desc: 'Data exfiltrated via DNS queries' },
  { label: 'ICMP Tunneling',     key: 'icmp_tunnel',     icon: Radio,       desc: 'Covert channel via ICMP echo' },
  { label: 'Beaconing',          key: 'beacon',          icon: Radio,       desc: 'Regular C2 callback pattern detected' },
  { label: 'C2 Communication',   key: 'c2',              icon: Crosshair,   desc: 'Command & control channel active' },
  { label: 'Lateral Movement',   key: 'lateral_movement',icon: GitBranch,   desc: 'Internal host-to-host attacks' },
  { label: 'Data Exfiltration',  key: 'exfiltration',    icon: Download,    desc: 'Large volume leaving network' },
  { label: 'Volume Spike',       key: 'volume_spike',    icon: TrendingUp,  desc: 'Traffic 3× above baseline' },
  { label: 'Brute Force',        key: 'brute_force',     icon: Zap,         desc: 'Repeated auth failures' },
  { label: 'Password Spraying',  key: 'password_spray',  icon: Zap,         desc: 'Low-and-slow multi-account spray' },
];

function BehavioralDetection({ anomalyTypes }: { anomalyTypes: Set<string> }) {
  const detected = BEHAVIORAL_CHECKS.filter(c => anomalyTypes.has(c.key));
  const clean = BEHAVIORAL_CHECKS.filter(c => !anomalyTypes.has(c.key));
  return (
    <div className="p-3 space-y-1.5">
      {detected.map(c => (
        <div key={c.key} className="flex items-center gap-2.5 rounded-lg px-3 py-2"
          style={{ background: 'var(--red)10', border: '1px solid var(--red)33' }}>
          <c.icon className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--red)' }} />
          <div className="flex-1 min-w-0">
            <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{c.label}</p>
            <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{c.desc}</p>
          </div>
          <span className="text-[10px] font-bold" style={{ color: 'var(--red)' }}>DETECTED</span>
        </div>
      ))}
      {clean.slice(0, 5).map(c => (
        <div key={c.key} className="flex items-center gap-2.5 rounded-lg px-3 py-2"
          style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
          <c.icon className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />
          <span className="text-xs flex-1" style={{ color: 'var(--text-3)' }}>{c.label}</span>
          <CheckCircle2 className="h-3.5 w-3.5" style={{ color: 'var(--green)' }} />
        </div>
      ))}
    </div>
  );
}

// ── Beacon Detection ───────────────────────────────────────────────────────

function BeaconPanel({ data, loading }: { data: BeaconData | null; loading: boolean }) {
  if (loading) return <Spinner />;
  if (!data) return <Empty icon={Radio} text="No beacon data." />;

  return (
    <div className="p-3 space-y-3">
      <div className="grid grid-cols-3 gap-2">
        {[
          { l: 'Total Beacons', v: data.total,          c: 'var(--red)' },
          { l: 'High Confidence', v: data.high_confidence, c: 'var(--red)' },
          { l: 'Unique C2 IPs',  v: data.unique_c2_ips, c: 'var(--orange)' },
        ].map(s => (
          <div key={s.l} className="rounded-xl px-3 py-2 text-center"
            style={{ background: `${s.c}10`, border: `1px solid ${s.c}33` }}>
            <p className="text-base font-bold tabular-nums" style={{ color: s.c }}>{s.v}</p>
            <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>{s.l}</p>
          </div>
        ))}
      </div>
      {data.beacons.length === 0
        ? <Empty icon={Radio} text="No beacons detected in the last 48h." />
        : (
          <div className="space-y-1.5">
            {data.beacons.slice(0, 15).map((b, i) => (
              <div key={i} className="rounded-lg px-3 py-2.5"
                style={{ background: 'var(--glass-bg)', border: `1px solid ${RISK_COLOR(b.score)}33` }}>
                <div className="flex items-center justify-between gap-2 mb-1">
                  <div className="flex items-center gap-2">
                    <Radio className="h-3.5 w-3.5 shrink-0" style={{ color: RISK_COLOR(b.score) }} />
                    <span className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{b.hostname}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {b.dst_ip && <span className="text-[10px] font-mono" style={{ color: 'var(--red)' }}>{b.dst_ip}:{b.dst_port}</span>}
                    <ScoreBadge score={b.score} />
                  </div>
                </div>
                <p className="text-[10px] pl-5" style={{ color: 'var(--text-3)' }}>{b.description}</p>
                <p className="text-[9px] pl-5 mt-0.5" style={{ color: 'var(--text-3)' }}>{timeAgo(b.detected_at)}</p>
              </div>
            ))}
          </div>
        )
      }
    </div>
  );
}

// ── Lateral Movement ───────────────────────────────────────────────────────

function LateralMovementPanel({ data, loading }: { data: LateralData | null; loading: boolean }) {
  if (loading) return <Spinner />;
  if (!data || (data.lateral_events.length === 0 && data.lateral_anomalies.length === 0)) {
    return <Empty icon={GitBranch} text="No lateral movement detected." />;
  }

  return (
    <div className="p-3 space-y-3">
      {data.lateral_events.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Connection Events</p>
          {data.lateral_events.slice(0, 10).map((e, i) => {
            const Icon = LATERAL_METHOD_ICON[e.method] ?? GitBranch;
            return (
              <div key={i} className="flex items-center gap-2.5 rounded-lg px-3 py-2.5 mb-1.5"
                style={{ background: 'var(--red)08', border: '1px solid var(--red)33' }}>
                <Icon className="h-4 w-4 shrink-0" style={{ color: 'var(--red)' }} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="text-xs font-bold" style={{ color: 'var(--text-1)' }}>{e.src_host}</span>
                    <ArrowRight className="h-3 w-3" style={{ color: 'var(--text-3)' }} />
                    <span className="text-xs font-mono" style={{ color: 'var(--red)' }}>{e.dst_address}</span>
                    <Tag text={e.method} color="var(--red)" />
                  </div>
                  <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>
                    {e.process && `Process: ${e.process} · `}Count: {e.count} · {timeAgo(e.last_seen)}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {data.lateral_anomalies.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Anomaly Detections</p>
          {data.lateral_anomalies.slice(0, 10).map((a, i) => (
            <div key={i} className="rounded-lg px-3 py-2 mb-1.5"
              style={{ background: 'var(--glass-bg)', border: `1px solid ${RISK_COLOR(a.score)}33` }}>
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{a.hostname}</span>
                <ScoreBadge score={a.score} />
              </div>
              <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{a.description}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── DNS Panel ──────────────────────────────────────────────────────────────

function DNSPanel({ data, loading }: { data: DNSAnalytics | null; loading: boolean }) {
  if (loading) return <Spinner />;
  if (!data) return <Empty icon={Globe} text="No DNS data." />;
  return (
    <div className="p-3 space-y-3">
      <div className="grid grid-cols-2 gap-2">
        <div className="rounded-xl px-3 py-2 text-center" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
          <p className="text-base font-bold tabular-nums" style={{ color: 'var(--accent)' }}>{data.total_dns_queries.toLocaleString()}</p>
          <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>DNS Queries (24h)</p>
        </div>
        <div className="rounded-xl px-3 py-2 text-center" style={{ background: 'var(--red)10', border: '1px solid var(--red)33' }}>
          <p className="text-base font-bold tabular-nums" style={{ color: 'var(--red)' }}>{data.dns_anomalies}</p>
          <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>DNS Anomalies</p>
        </div>
      </div>
      {data.dns_events.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Suspicious DNS Events</p>
          {data.dns_events.slice(0, 8).map((e, i) => (
            <div key={i} className="flex items-start gap-2 py-1.5" style={{ borderBottom: '1px solid var(--border)' }}>
              <Globe className="h-3.5 w-3.5 shrink-0 mt-0.5" style={{ color: RISK_COLOR(e.score) }} />
              <div className="flex-1 min-w-0">
                <p className="text-[11px] font-medium" style={{ color: 'var(--text-1)' }}>{e.description}</p>
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{e.hostname} · {timeAgo(e.detected_at)}</p>
              </div>
              <ScoreBadge score={e.score} />
            </div>
          ))}
        </div>
      )}
      {data.top_dns_servers.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Top DNS Resolvers</p>
          {data.top_dns_servers.map((d, i) => (
            <div key={i} className="flex items-center justify-between text-xs py-1" style={{ borderBottom: '1px solid var(--border)' }}>
              <span className="font-mono" style={{ color: 'var(--text-2)' }}>{d.dest}</span>
              <span className="font-bold tabular-nums" style={{ color: 'var(--accent)' }}>{d.count}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── TLS Panel ──────────────────────────────────────────────────────────────

function TLSPanel({ data, loading }: { data: TLSAnalytics | null; loading: boolean }) {
  if (loading) return <Spinner />;
  if (!data) return <Empty icon={Lock} text="No TLS data." />;
  return (
    <div className="p-3 space-y-3">
      <div className="grid grid-cols-2 gap-2">
        <div className="rounded-xl px-3 py-2 text-center" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
          <p className="text-base font-bold tabular-nums" style={{ color: 'var(--green)' }}>{data.total_tls_connections.toLocaleString()}</p>
          <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>TLS Connections</p>
        </div>
        <div className="rounded-xl px-3 py-2 text-center" style={{ background: 'var(--orange)10', border: '1px solid var(--orange)33' }}>
          <p className="text-base font-bold tabular-nums" style={{ color: 'var(--orange)' }}>{data.unknown_destinations}</p>
          <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>Unknown Destinations</p>
        </div>
      </div>
      {data.ja3_fingerprints.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>JA3 Fingerprints</p>
          {data.ja3_fingerprints.slice(0, 8).map((j, i) => (
            <div key={i} className="rounded-lg px-3 py-2 mb-1.5"
              style={{ background: 'var(--glass-bg)', border: `1px solid ${SEV[j.severity] ?? 'var(--border)'}33` }}>
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{j.label}</span>
                <Tag text={j.severity} color={SEV[j.severity] ?? 'var(--text-3)'} />
              </div>
              <p className="text-[10px] font-mono mt-0.5" style={{ color: 'var(--text-3)' }}>{j.fingerprint}</p>
              {j.description && <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{j.description}</p>}
            </div>
          ))}
        </div>
      )}
      {data.suspicious_tls.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Suspicious TLS</p>
          {data.suspicious_tls.slice(0, 6).map((t, i) => (
            <div key={i} className="flex items-center justify-between text-xs py-1.5" style={{ borderBottom: '1px solid var(--border)' }}>
              <span className="font-mono" style={{ color: 'var(--red)' }}>{t.address}</span>
              <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{t.hostname}</span>
              <span className="font-bold" style={{ color: 'var(--orange)' }}>{t.count}×</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Threat Intel Panel ─────────────────────────────────────────────────────

function ThreatIntelPanel({ data, loading }: { data: ThreatIntelData | null; loading: boolean }) {
  if (loading) return <Spinner />;
  if (!data) return <Empty icon={Shield} text="No threat intel data." />;
  return (
    <div className="p-3 space-y-3">
      <div className="flex items-center gap-2 rounded-lg px-3 py-2"
        style={{ background: data.total_hits > 0 ? 'var(--red)10' : 'var(--glass-bg)', border: `1px solid ${data.total_hits > 0 ? 'var(--red)' : 'var(--border)'}33` }}>
        <ShieldAlert className="h-4 w-4" style={{ color: data.total_hits > 0 ? 'var(--red)' : 'var(--green)' }} />
        <span className="text-sm font-bold" style={{ color: data.total_hits > 0 ? 'var(--red)' : 'var(--green)' }}>
          {data.total_hits} IOC hit{data.total_hits !== 1 ? 's' : ''}
        </span>
        {data.total_hits === 0 && <span className="text-xs" style={{ color: 'var(--text-3)' }}>— no malicious destinations detected</span>}
      </div>
      {data.threat_intel_hits.slice(0, 10).map((h, i) => (
        <div key={i} className="rounded-lg px-3 py-2.5" style={{ background: 'var(--red)08', border: '1px solid var(--red)22' }}>
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{h.hostname}</span>
            <div className="flex items-center gap-1.5">
              <Tag text={h.ioc_type.toUpperCase()} color="var(--red)" />
              <Tag text={`${h.confidence}%`} color="var(--orange)" />
            </div>
          </div>
          <p className="text-[10px] mt-0.5 font-mono" style={{ color: 'var(--red)' }}>{h.remote_address}</p>
          {h.threat_type && <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{h.threat_type} · {h.process}</p>}
        </div>
      ))}
      {data.ioc_blocks.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Blocked IPs ({data.ioc_blocks.length})</p>
          {data.ioc_blocks.slice(0, 8).map((b, i) => (
            <div key={i} className="flex items-center justify-between text-xs py-1.5" style={{ borderBottom: '1px solid var(--border)' }}>
              <span className="font-mono" style={{ color: 'var(--red)' }}>{b.ip}</span>
              <span className="text-[10px]" style={{ color: 'var(--orange)' }}>{b.hit_count} hits</span>
              <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(b.blocked_at)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── MITRE Panel ────────────────────────────────────────────────────────────

function MITREPanel({ techniques, loading }: { techniques: MITRETechnique[]; loading: boolean }) {
  if (loading) return <Spinner />;
  if (techniques.length === 0) return <Empty icon={Layers} text="No MITRE mappings." />;
  const sorted = [...techniques].sort((a, b) => b.hit_count - a.hit_count);
  return (
    <div className="p-3 space-y-2">
      {sorted.map(t => (
        <div key={t.technique_id} className="rounded-lg px-3 py-2.5"
          style={{
            background: t.hit_count > 0 ? `${RISK_COLOR(t.max_score)}10` : 'var(--glass-bg)',
            border: `1px solid ${t.hit_count > 0 ? RISK_COLOR(t.max_score) : 'var(--border)'}33`,
          }}>
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded"
                style={{ background: t.hit_count > 0 ? `${RISK_COLOR(t.max_score)}18` : 'var(--glass-bg)', color: t.hit_count > 0 ? RISK_COLOR(t.max_score) : 'var(--text-3)' }}>
                {t.technique_id}
              </span>
              <span className="text-xs" style={{ color: t.hit_count > 0 ? 'var(--text-1)' : 'var(--text-3)' }}>{t.technique_name}</span>
            </div>
            {t.hit_count > 0 && (
              <div className="flex items-center gap-2">
                <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{t.hit_count} hit{t.hit_count !== 1 ? 's' : ''}</span>
                <ScoreBadge score={t.max_score} />
              </div>
            )}
            {t.hit_count === 0 && <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>Not detected</span>}
          </div>
          {(t.anomaly_types ?? []).length > 0 && (
            <div className="flex flex-wrap gap-1 mt-1.5">
              {t.anomaly_types.map(a => <Tag key={a} text={a.replace(/_/g, ' ')} color="var(--text-3)" />)}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Timeline Panel ─────────────────────────────────────────────────────────

function TimelinePanel({ events, loading, searchHost, onSearchHost }: {
  events: TimelineEvent[]; loading: boolean; searchHost: string; onSearchHost: (h: string) => void;
}) {
  if (loading) return <Spinner />;
  return (
    <div className="p-3 space-y-2">
      <div className="relative">
        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
        <input value={searchHost} onChange={e => onSearchHost(e.target.value)}
          placeholder="Filter by host…" className="g-input w-full text-xs pl-8" />
      </div>
      {events.length === 0
        ? <Empty icon={Clock} text="No timeline events for this host." />
        : (
          <div className="relative pl-4">
            <div className="absolute left-5 top-0 bottom-0 w-px" style={{ background: 'var(--border)' }} />
            {events.slice(0, 60).map((e, i) => {
              const isAnomaly = e.event_type === 'anomaly';
              const color = isAnomaly ? RISK_COLOR(e.score) : 'var(--accent)';
              return (
                <div key={i} className="relative pl-5 mb-3">
                  <div className="absolute left-0 top-0.5 h-4 w-4 rounded-full flex items-center justify-center"
                    style={{ background: `${color}18`, border: `1px solid ${color}44` }}>
                    {isAnomaly
                      ? <AlertTriangle className="h-2.5 w-2.5" style={{ color }} />
                      : <Network className="h-2.5 w-2.5" style={{ color }} />
                    }
                  </div>
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <p className="text-[10px] font-bold uppercase" style={{ color: 'var(--text-3)' }}>
                        {e.event_type === 'anomaly' ? 'Network Anomaly' : 'Connection'} · {e.hostname}
                      </p>
                      <p className="text-xs" style={{ color: 'var(--text-1)' }}>
                        {e.remote_address} {e.protocol && <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>/{e.protocol}</span>}
                      </p>
                      {e.detail && <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{e.detail}</p>}
                    </div>
                    <span className="text-[9px] shrink-0" style={{ color: 'var(--text-3)' }}>{timeAgo(e.timestamp)}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )
      }
    </div>
  );
}

// ── Analytics Panel ────────────────────────────────────────────────────────

function AnalyticsPanel({ data, loading }: { data: AnalyticsData | null; loading: boolean }) {
  if (loading) return <Spinner />;
  if (!data) return <Empty icon={BarChart2} text="No analytics data." />;

  const maxTrend = Math.max(...(data.anomaly_trend ?? []).map(t => t.count), 1);

  return (
    <div className="p-4 space-y-5">
      <div className="grid grid-cols-3 gap-3">
        {[
          { l: 'Total Connections', v: data.total_connections.toLocaleString(), c: 'var(--accent)' },
          { l: 'Unique Hosts',      v: data.unique_hosts,                        c: 'var(--text-2)' },
          { l: 'Blocked IPs',       v: data.blocked_ips,                          c: 'var(--red)' },
        ].map(s => (
          <div key={s.l} className="g-card px-3 py-2 text-center">
            <p className="text-base font-bold" style={{ color: s.c }}>{s.v}</p>
            <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>{s.l}</p>
          </div>
        ))}
      </div>

      {(data.anomaly_trend ?? []).length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Anomaly Trend (24h)</p>
          <div className="flex items-end gap-0.5 h-14">
            {data.anomaly_trend.map(t => (
              <div key={t.hour} title={`${t.hour}: ${t.count} anomalies, avg score ${t.avg_score}`}
                className="flex-1 rounded-t" style={{ height: `${(t.count / maxTrend) * 100}%`, background: RISK_COLOR(t.avg_score), opacity: 0.85, minHeight: '2px' }} />
            ))}
          </div>
        </div>
      )}

      {(data.geo_distribution ?? []).length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Geographic Distribution</p>
          {data.geo_distribution.slice(0, 8).map(g => (
            <div key={g.country} className="flex items-center gap-2 py-1.5" style={{ borderBottom: '1px solid var(--border)' }}>
              <span className="text-[10px] font-mono w-6" style={{ color: 'var(--text-3)' }}>{g.country_code}</span>
              <span className="text-xs flex-1" style={{ color: 'var(--text-2)' }}>{g.country}</span>
              <span className="text-[10px] font-bold tabular-nums" style={{ color: 'var(--accent)' }}>{g.count.toLocaleString()}</span>
            </div>
          ))}
        </div>
      )}

      {(data.most_suspicious_hosts ?? []).length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Most Suspicious Hosts</p>
          {data.most_suspicious_hosts.slice(0, 6).map(h => (
            <div key={h.hostname} className="flex items-center gap-2 py-1.5" style={{ borderBottom: '1px solid var(--border)' }}>
              <Server className="h-3.5 w-3.5 shrink-0" style={{ color: RISK_COLOR(h.max_score) }} />
              <span className="text-xs flex-1 font-medium" style={{ color: 'var(--text-1)' }}>{h.hostname}</span>
              <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{h.anomaly_count} anomalies</span>
              <ScoreBadge score={h.max_score} />
            </div>
          ))}
        </div>
      )}

      {(data.beacon_frequency ?? []).length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Beacon Frequency by Host</p>
          {data.beacon_frequency.map(b => (
            <div key={b.hostname} className="flex items-center gap-2 py-1.5" style={{ borderBottom: '1px solid var(--border)' }}>
              <Radio className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--red)' }} />
              <span className="text-xs flex-1" style={{ color: 'var(--text-1)' }}>{b.hostname}</span>
              <span className="text-[10px]" style={{ color: 'var(--red)' }}>{b.count} beacons</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Response Actions ───────────────────────────────────────────────────────

const RESPONSE_ACTIONS = [
  { key: 'block_ip',          label: 'Block IP',           icon: Ban,       color: 'var(--red)',    needs: 'ip',      placeholder: 'IP address' },
  { key: 'block_domain',      label: 'Block Domain',       icon: Globe,     color: 'var(--red)',    needs: 'domain',  placeholder: 'domain.com' },
  { key: 'block_asn',         label: 'Block ASN',          icon: Layers,    color: 'var(--orange)', needs: 'asn',     placeholder: 'AS12345' },
  { key: 'push_firewall_rule',label: 'Push Firewall Rule', icon: Shield,    color: 'var(--orange)', needs: 'ip',      placeholder: 'Target IP' },
  { key: 'isolate_endpoint',  label: 'Isolate Endpoint',   icon: Server,    color: 'var(--red)',    needs: 'agent_id',placeholder: 'Agent ID' },
  { key: 'kill_process',      label: 'Kill Process',       icon: XCircle,   color: 'var(--orange)', needs: 'pid',     placeholder: 'PID' },
  { key: 'create_incident',   label: 'Create Incident',    icon: ShieldAlert,color: 'var(--accent)',needs: 'reason',  placeholder: 'Description' },
  { key: 'start_pcap',        label: 'Start PCAP',         icon: FlaskConical,color:'var(--accent)',needs: 'agent_id',placeholder: 'Agent ID' },
  { key: 'run_playbook',      label: 'Run SOAR Playbook',  icon: Play,      color: 'var(--accent)', needs: null,      placeholder: '' },
];

function ResponseActionsPanel({ onToast }: { onToast: (m: string) => void }) {
  const [active, setActive] = useState<string | null>(null);
  const [param, setParam] = useState('');
  const [reason, setReason] = useState('');
  const [running, setRunning] = useState<string | null>(null);

  const dispatch = async (key: string, a: typeof RESPONSE_ACTIONS[0]) => {
    setRunning(key);
    try {
      const body: Record<string, unknown> = { reason };
      if (a.needs === 'ip') body.ip = param;
      else if (a.needs === 'domain') body.domain = param;
      else if (a.needs === 'asn') body.asn = param;
      else if (a.needs === 'agent_id') body.agent_id = parseInt(param) || 0;
      else if (a.needs === 'pid') body.pid = parseInt(param) || 0;
      else if (a.needs === 'reason') body.reason = param;
      const r = await nbaAPI.responseAction(key, body);
      onToast((r.data as any)?.result ?? `${key} executed`);
      setActive(null); setParam('');
    } catch { onToast('Action failed'); }
    finally { setRunning(null); }
  };

  return (
    <div className="p-3 space-y-3">
      {active && (() => {
        const a = RESPONSE_ACTIONS.find(x => x.key === active)!;
        return a.needs && (
          <div className="flex items-center gap-2 rounded-lg px-3 py-2.5"
            style={{ background: 'var(--glass-bg)', border: '1px solid var(--accent-border)' }}>
            <input value={param} onChange={e => setParam(e.target.value)}
              placeholder={a.placeholder} className="g-input flex-1 text-xs"
              onKeyDown={e => e.key === 'Enter' && param && dispatch(active, a)} />
            <input value={reason} onChange={e => setReason(e.target.value)}
              placeholder="Reason…" className="g-input flex-1 text-xs" />
            <button onClick={() => dispatch(active, a)} disabled={!param || running !== null} className="g-btn g-btn-primary text-xs px-3">
              {running === active ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : 'Execute'}
            </button>
            <button onClick={() => { setActive(null); setParam(''); }} className="g-btn g-btn-ghost text-xs px-2">
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        );
      })()}
      <div className="grid grid-cols-3 gap-1.5">
        {RESPONSE_ACTIONS.map(a => (
          <button key={a.key}
            onClick={() => a.needs ? (setActive(a.key), setParam('')) : dispatch(a.key, a)}
            disabled={running !== null}
            className="flex items-center gap-2 rounded-lg px-3 py-2 text-left hover:bg-[var(--glass-hover)] transition-colors"
            style={{ background: 'var(--glass-bg)', border: `1px solid ${a.color}33` }}>
            {running === a.key
              ? <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" style={{ color: a.color }} />
              : <a.icon className="h-3.5 w-3.5 shrink-0" style={{ color: a.color }} />}
            <span className="text-[10px] font-medium" style={{ color: 'var(--text-1)' }}>{a.label}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

// ── AI Insights Panel ──────────────────────────────────────────────────────

function AIInsightsPanel({ onResult }: { onResult?: (ai: AIInsight) => void }) {
  const [ai,      setAi]      = useState<AIInsight | null>(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState('');
  const [ctx,     setCtx]     = useState('');

  const run = async () => {
    setLoading(true); setError(''); setAi(null);
    try {
      const r = await nbaAPI.aiInsights({ context: ctx });
      const data = r.data as AIInsight;
      setAi(data); onResult?.(data);
    } catch { setError('AI analysis unavailable'); }
    finally { setLoading(false); }
  };

  return (
    <div className="p-4 space-y-3">
      {!ai && !loading && (
        <div className="space-y-2">
          <textarea value={ctx} onChange={e => setCtx(e.target.value)}
            placeholder="Optional context: which hosts to focus on, recent events to consider…"
            rows={2} className="g-input w-full text-xs resize-none" />
          <button onClick={run} className="g-btn g-btn-primary text-xs w-full justify-center">
            <Bot className="h-3.5 w-3.5" /> Run AI Network Analysis
          </button>
        </div>
      )}
      {loading && <div className="text-center py-6 space-y-2">
        <Loader2 className="h-6 w-6 animate-spin mx-auto" style={{ color: 'var(--accent)' }} />
        <p className="text-xs" style={{ color: 'var(--text-3)' }}>Analyzing network behavior patterns…</p>
      </div>}
      {error && <p className="text-xs" style={{ color: 'var(--red)' }}>{error}</p>}
      {ai && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Risk Level</span>
            <Tag text={ai.risk_level.toUpperCase()} color={RL[ai.risk_level.toLowerCase()] ?? 'var(--text-3)'} />
            <Tag text={`Confidence: ${ai.confidence}%`} color="var(--accent)" />
          </div>
          <div className="rounded-xl p-3" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
            <p className="text-xs leading-relaxed italic" style={{ color: 'var(--text-1)' }}>"{ai.threat_summary}"</p>
          </div>
          {ai.key_findings?.length > 0 && (
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>Key Findings</p>
              {ai.key_findings.map((f, i) => (
                <div key={i} className="flex gap-2 text-xs py-1">
                  <Info className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--accent)' }} />
                  <span style={{ color: 'var(--text-2)' }}>{f}</span>
                </div>
              ))}
            </div>
          )}
          {ai.suspicious_behaviors?.length > 0 && (
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>Suspicious Behaviors</p>
              {ai.suspicious_behaviors.map((b, i) => (
                <div key={i} className="flex gap-2 text-xs py-1">
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--orange)' }} />
                  <span style={{ color: 'var(--text-2)' }}>{b}</span>
                </div>
              ))}
            </div>
          )}
          {ai.mitre_techniques?.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {ai.mitre_techniques.map((t, i) => (
                <span key={i} className="text-[10px] px-2 py-0.5 rounded font-mono"
                  style={{ background: 'var(--orange)18', color: 'var(--orange)', border: '1px solid var(--orange)44' }}>{t}</span>
              ))}
            </div>
          )}
          {ai.recommendations?.length > 0 && (
            <div className="rounded-xl p-3" style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
              <p className="text-[10px] font-semibold mb-1.5" style={{ color: 'var(--text-3)' }}>Recommendations</p>
              {ai.recommendations.map((r, i) => (
                <div key={i} className="flex gap-2 text-xs py-0.5">
                  <ChevronRight className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--accent)' }} />
                  <span style={{ color: 'var(--accent)' }}>{r}</span>
                </div>
              ))}
            </div>
          )}
          <button onClick={() => { setAi(null); setCtx(''); }} className="g-btn g-btn-ghost text-[10px] w-full justify-center">
            <RefreshCw className="h-3 w-3" /> Re-analyze
          </button>
        </div>
      )}
    </div>
  );
}

// ── Traffic Analysis Panel ─────────────────────────────────────────────────

function TrafficPanel({ data, loading }: { data: TrafficAnalysis | null; loading: boolean }) {
  if (loading) return <Spinner />;
  if (!data) return <Empty icon={Activity} text="No traffic data." />;

  const total = data.east_west_count + data.north_south_count;
  const ewPct = total > 0 ? Math.round((data.east_west_count / total) * 100) : 0;
  const nsPct = 100 - ewPct;

  const maxTalker = Math.max(...(data.top_talkers ?? []).map(t => t.conn_count), 1);
  const maxTrend = Math.max(...(data.hourly_trend ?? []).map(t => t.count), 1);

  return (
    <div className="p-3 space-y-4">
      {/* E-W vs N-S */}
      <div>
        <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Traffic Direction</p>
        <div className="flex items-center gap-3">
          <div className="flex-1">
            <div className="h-3 rounded-full overflow-hidden flex" style={{ background: 'var(--border)' }}>
              <div style={{ width: `${ewPct}%`, background: 'var(--accent)' }} />
              <div style={{ width: `${nsPct}%`, background: 'var(--orange)' }} />
            </div>
            <div className="flex justify-between mt-1">
              <span className="text-[9px]" style={{ color: 'var(--accent)' }}>East-West {ewPct}%</span>
              <span className="text-[9px]" style={{ color: 'var(--orange)' }}>North-South {nsPct}%</span>
            </div>
          </div>
        </div>
      </div>

      {/* Hourly trend */}
      {(data.hourly_trend ?? []).length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Hourly Connection Trend (12h)</p>
          <div className="flex items-end gap-0.5 h-10">
            {data.hourly_trend.map(t => (
              <div key={t.hour} title={`${t.hour}: ${t.count}`}
                className="flex-1 rounded-t" style={{ height: `${(t.count / maxTrend) * 100}%`, background: 'var(--accent)', opacity: 0.7, minHeight: 2 }} />
            ))}
          </div>
        </div>
      )}

      {/* Top talkers */}
      {(data.top_talkers ?? []).length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Top Talkers</p>
          {data.top_talkers.slice(0, 8).map(t => (
            <div key={t.host} className="flex items-center gap-2 py-1.5" style={{ borderBottom: '1px solid var(--border)' }}>
              <Server className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--accent)' }} />
              <span className="text-xs flex-1 font-medium truncate" style={{ color: 'var(--text-1)' }}>{t.host}</span>
              <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--border)' }}>
                <div style={{ width: `${(t.conn_count / maxTalker) * 100}%`, background: 'var(--accent)', height: '100%' }} />
              </div>
              <span className="text-[10px] tabular-nums w-12 text-right" style={{ color: 'var(--text-3)' }}>
                {t.conn_count} conns
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Top destinations */}
      {(data.top_destinations ?? []).length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Top Destinations</p>
          {data.top_destinations.slice(0, 8).map((d, i) => (
            <div key={i} className="flex items-center justify-between text-xs py-1.5" style={{ borderBottom: '1px solid var(--border)' }}>
              <span className="font-mono text-[10px]" style={{ color: 'var(--accent)' }}>{d.remote_address}</span>
              <span className="font-bold tabular-nums" style={{ color: 'var(--text-3)' }}>{d.count}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── PCAP Panel ─────────────────────────────────────────────────────────────

function PCAPPanel({ onToast }: { onToast: (m: string) => void }) {
  const [agentId, setAgentId] = useState('');
  const [duration, setDuration] = useState('60');
  const [running, setRunning] = useState(false);

  const startCapture = async () => {
    if (!agentId) return;
    setRunning(true);
    try {
      const r = await nbaAPI.responseAction('start_pcap', { agent_id: parseInt(agentId), reason: `PCAP capture for ${duration}s` });
      onToast((r.data as any)?.result ?? 'PCAP capture started');
    } catch { onToast('PCAP capture failed'); }
    finally { setRunning(false); }
  };

  return (
    <div className="p-4 space-y-3">
      <p className="text-xs" style={{ color: 'var(--text-3)' }}>
        Initiate packet capture on any agent. Requires NGFW/DPI integration for session reconstruction, HTTP object extraction, and file carving.
      </p>
      <div className="flex items-center gap-2">
        <input value={agentId} onChange={e => setAgentId(e.target.value)}
          placeholder="Agent ID" type="number" className="g-input w-28 text-xs" />
        <select value={duration} onChange={e => setDuration(e.target.value)} className="g-select text-xs">
          {['30', '60', '120', '300', '600'].map(d => <option key={d} value={d}>{d}s</option>)}
        </select>
        <button onClick={startCapture} disabled={!agentId || running} className="g-btn g-btn-primary text-xs px-3">
          {running ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FlaskConical className="h-3.5 w-3.5" />} Start PCAP
        </button>
      </div>
      <div className="grid grid-cols-2 gap-2">
        {[
          { l: 'Open PCAP',              icon: Eye,      desc: 'View in Wireshark-style viewer' },
          { l: 'Download PCAP',          icon: Download, desc: 'Download .pcap file' },
          { l: 'Session Reconstruction', icon: Activity, desc: 'Rebuild TCP streams' },
          { l: 'HTTP Objects',           icon: Package,  desc: 'Extract HTTP files' },
          { l: 'File Extraction',        icon: FileText, desc: 'Carve files from pcap' },
        ].map(a => (
          <div key={a.l} className="flex items-center gap-2 rounded-lg px-3 py-2"
            style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', opacity: 0.6 }}>
            <a.icon className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />
            <div>
              <p className="text-[10px] font-medium" style={{ color: 'var(--text-2)' }}>{a.l}</p>
              <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>{a.desc}</p>
            </div>
          </div>
        ))}
      </div>
      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
        Full PCAP integration requires agent-side tcpdump/libpcap support or NGFW integration via SPAN/TAP.
      </p>
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────

type ViewTab = 'overview' | 'flows' | 'traffic' | 'dns' | 'tls' | 'protocols' |
               'behavioral' | 'beacons' | 'lateral' | 'threat-intel' |
               'timeline' | 'mitre' | 'pcap' | 'analytics' | 'response';

export default function NBAPage() {
  const [overview,   setOverview]   = useState<Overview | null>(null);
  const [flows,      setFlows]      = useState<Flow[]>([]);
  const [traffic,    setTraffic]    = useState<TrafficAnalysis | null>(null);
  const [dns,        setDns]        = useState<DNSAnalytics | null>(null);
  const [tls,        setTls]        = useState<TLSAnalytics | null>(null);
  const [beacons,    setBeacons]    = useState<BeaconData | null>(null);
  const [lateral,    setLateral]    = useState<LateralData | null>(null);
  const [threatIntel,setThreatIntel]= useState<ThreatIntelData | null>(null);
  const [mitre,      setMitre]      = useState<MITRETechnique[]>([]);
  const [protocols,  setProtocols]  = useState<ProtoEntry[]>([]);
  const [timeline,   setTimeline]   = useState<TimelineEvent[]>([]);
  const [analytics,  setAnalytics]  = useState<AnalyticsData | null>(null);

  const [loadingO,   setLoadingO]   = useState(true);
  const [loadingF,   setLoadingF]   = useState(true);
  const [loadingT,   setLoadingT]   = useState(true);
  const [loadingD,   setLoadingD]   = useState(false);
  const [loadingTLS, setLoadingTLS] = useState(false);
  const [loadingB,   setLoadingB]   = useState(false);
  const [loadingL,   setLoadingL]   = useState(false);
  const [loadingTI,  setLoadingTI]  = useState(false);
  const [loadingM,   setLoadingM]   = useState(false);
  const [loadingP,   setLoadingP]   = useState(false);
  const [loadingTL,  setLoadingTL]  = useState(false);
  const [loadingA,   setLoadingA]   = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const [view,       setView]       = useState<ViewTab>('overview');
  const [searchQ,    setSearchQ]    = useState('');
  const [timeHost,   setTimeHost]   = useState('');
  const [minutes,    setMinutes]    = useState(60);
  const [toast,      setToast]      = useState<string | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 4000); };

  const anomalyTypes = useMemo(() => {
    const s = new Set<string>();
    if (overview) {
      if (overview.beaconing_detections > 0) s.add('beacon');
      if (overview.lateral_movement > 0) s.add('lateral_movement');
      if (overview.c2_communications > 0) s.add('c2');
      if (overview.data_exfiltration > 0) s.add('exfiltration');
    }
    return s;
  }, [overview]);

  const loadOverview = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    setLoadingO(true);
    const r = await nbaAPI.getOverview(minutes);
    if (r.data) setOverview(r.data as Overview);
    setLoadingO(false); setRefreshing(false);
  }, [minutes]);

  const loadFlows = useCallback(async () => {
    setLoadingF(true);
    const r = await nbaAPI.getFlows({ minutes });
    setFlows((r.data as any)?.flows ?? []);
    setLoadingF(false);
  }, [minutes]);

  const loadTraffic = useCallback(async () => {
    setLoadingT(true);
    const r = await nbaAPI.getTrafficAnalysis(Math.ceil(minutes / 60));
    if (r.data) setTraffic(r.data as TrafficAnalysis);
    setLoadingT(false);
  }, [minutes]);

  useEffect(() => {
    loadOverview(); loadFlows(); loadTraffic();
  }, [loadOverview, loadFlows, loadTraffic]);

  // Lazy-load panels when the tab is first opened
  useEffect(() => {
    if (view === 'dns'       && !dns)        { setLoadingD(true);  nbaAPI.getDnsAnalytics().then(r => { setDns(r.data as DNSAnalytics); setLoadingD(false); }); }
    if (view === 'tls'       && !tls)        { setLoadingTLS(true); nbaAPI.getTlsAnalytics().then(r => { setTls(r.data as TLSAnalytics); setLoadingTLS(false); }); }
    if (view === 'beacons'   && !beacons)    { setLoadingB(true);  nbaAPI.getBeacons().then(r => { setBeacons(r.data as BeaconData); setLoadingB(false); }); }
    if (view === 'lateral'   && !lateral)    { setLoadingL(true);  nbaAPI.getLateralMovement().then(r => { setLateral(r.data as LateralData); setLoadingL(false); }); }
    if (view === 'threat-intel' && !threatIntel) { setLoadingTI(true); nbaAPI.getThreatIntel().then(r => { setThreatIntel(r.data as ThreatIntelData); setLoadingTI(false); }); }
    if (view === 'mitre'     && !mitre.length) { setLoadingM(true); nbaAPI.getMitreMapping().then(r => { setMitre((r.data as any)?.techniques ?? []); setLoadingM(false); }); }
    if (view === 'protocols' && !protocols.length) { setLoadingP(true); nbaAPI.getProtocolBreakdown().then(r => { setProtocols((r.data as any)?.protocols ?? []); setLoadingP(false); }); }
    if (view === 'timeline')  { setLoadingTL(true); nbaAPI.getHostTimeline(timeHost).then(r => { setTimeline((r.data as any)?.events ?? []); setLoadingTL(false); }); }
    if (view === 'analytics' && !analytics)  { setLoadingA(true);  nbaAPI.getAnalytics().then(r => { setAnalytics(r.data as AnalyticsData); setLoadingA(false); }); }
  }, [view]); // eslint-disable-line react-hooks/exhaustive-deps

  // Reload timeline when host filter changes
  useEffect(() => {
    if (view !== 'timeline') return;
    setLoadingTL(true);
    nbaAPI.getHostTimeline(timeHost).then(r => { setTimeline((r.data as any)?.events ?? []); setLoadingTL(false); });
  }, [timeHost]); // eslint-disable-line react-hooks/exhaustive-deps

  const TABS: { id: ViewTab; label: string; icon: any }[] = [
    { id: 'overview',    label: 'Overview',       icon: BarChart2 },
    { id: 'flows',       label: 'Live Flows',      icon: Network },
    { id: 'traffic',     label: 'Traffic',         icon: Activity },
    { id: 'dns',         label: 'DNS',             icon: Globe },
    { id: 'tls',         label: 'TLS',             icon: Lock },
    { id: 'protocols',   label: 'Protocols',       icon: Layers },
    { id: 'behavioral',  label: 'Behavioral',      icon: ScanLine },
    { id: 'beacons',     label: 'Beacons',         icon: Radio },
    { id: 'lateral',     label: 'Lateral',         icon: GitBranch },
    { id: 'threat-intel',label: 'Threat Intel',    icon: Shield },
    { id: 'timeline',    label: 'Timeline',        icon: Clock },
    { id: 'mitre',       label: 'MITRE',           icon: Crosshair },
    { id: 'pcap',        label: 'PCAP',            icon: FlaskConical },
    { id: 'analytics',   label: 'Analytics',       icon: TrendingUp },
    { id: 'response',    label: 'Response',        icon: Zap },
  ];

  const CARD = 'g-card flex flex-col overflow-hidden';

  return (
    <RootLayout title="Network Behavior Analytics"
      subtitle="Live flows · Behavioral detection · Beacon analysis · Lateral movement · Threat intel"
      onRefresh={() => loadOverview(true)} refreshing={refreshing}>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 px-4 py-2.5 rounded-lg text-sm font-medium shadow-xl"
          style={{ background: 'var(--accent)', color: '#000' }}>{toast}</div>
      )}

      <div className="space-y-4">

        {/* KPI Strip */}
        {overview && (
          <div className="grid grid-cols-2 sm:grid-cols-5 lg:grid-cols-10 gap-2">
            {[
              { l: 'Total Flows',     v: overview.total_flows.toLocaleString(),         c: 'var(--text-2)',    i: Activity },
              { l: 'Active Conns',    v: overview.active_connections.toLocaleString(),   c: 'var(--green)',     i: Wifi },
              { l: 'Suspicious',      v: overview.suspicious_connections,                c: overview.suspicious_connections > 0 ? 'var(--orange)' : 'var(--text-3)', i: AlertTriangle },
              { l: 'Beaconing',       v: overview.beaconing_detections,                  c: overview.beaconing_detections > 0 ? 'var(--red)' : 'var(--text-3)',    i: Radio },
              { l: 'Lateral Move',    v: overview.lateral_movement,                      c: overview.lateral_movement > 0 ? 'var(--red)' : 'var(--text-3)',        i: GitBranch },
              { l: 'Exfiltration',    v: overview.data_exfiltration,                     c: overview.data_exfiltration > 0 ? 'var(--red)' : 'var(--text-3)',       i: Download },
              { l: 'C2 Comms',        v: overview.c2_communications,                     c: overview.c2_communications > 0 ? 'var(--red)' : 'var(--text-3)',       i: Crosshair },
              { l: 'High Risk Hosts', v: overview.high_risk_hosts,                       c: overview.high_risk_hosts > 0 ? 'var(--orange)' : 'var(--text-3)',      i: Server },
              { l: 'Net Risk Score',  v: `${overview.network_risk_score}/100`,           c: RISK_COLOR(overview.network_risk_score),                                i: Shield },
              { l: 'Window',          v: `${overview.window_minutes}m`,                  c: 'var(--text-3)',    i: Clock },
            ].map(({ l, v, c, i: Icon }) => (
              <div key={l} className="g-card p-2.5 flex items-center gap-2">
                <Icon className="h-3.5 w-3.5 shrink-0" style={{ color: c }} />
                <div className="min-w-0">
                  <p className="text-sm font-bold tabular-nums truncate" style={{ color: c }}>{v}</p>
                  <p className="text-[9px] leading-tight truncate" style={{ color: 'var(--text-3)' }}>{l}</p>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Controls */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
            <input value={searchQ} onChange={e => setSearchQ(e.target.value)}
              placeholder="Search IPs, hosts, protocols…" className="g-input w-full text-xs pl-8" />
            {searchQ && <button onClick={() => setSearchQ('')} className="absolute right-2.5 top-1/2 -translate-y-1/2"><X className="h-3 w-3" style={{ color: 'var(--text-3)' }} /></button>}
          </div>
          <select value={minutes} onChange={e => setMinutes(+e.target.value)} className="g-select text-xs">
            {[[15,'15m'],[30,'30m'],[60,'1h'],[360,'6h'],[1440,'24h'],[10080,'7d']].map(([v, l]) => (
              <option key={v} value={v}>{l}</option>
            ))}
          </select>
          <button onClick={() => { loadOverview(true); loadFlows(); loadTraffic(); }}
            className="g-btn g-btn-ghost text-xs">
            {refreshing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />} Refresh
          </button>
        </div>

        {/* Tab bar */}
        <div className="flex items-center gap-1 flex-wrap">
          {TABS.map(t => (
            <button key={t.id} onClick={() => setView(t.id)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[10px] font-medium transition-all"
              style={{
                background: view === t.id ? 'var(--accent-glow)' : 'var(--glass-bg)',
                border: `1px solid ${view === t.id ? 'var(--accent-border)' : 'var(--border)'}`,
                color: view === t.id ? 'var(--accent)' : 'var(--text-2)',
              }}>
              <t.icon className="h-3 w-3" />
              {t.label}
            </button>
          ))}
        </div>

        {/* ── Overview ── */}
        {view === 'overview' && (
          <div className="space-y-3">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
              {/* Network Graph */}
              <div className={CARD}>
                <SectionHeader icon={Map} title="Network Topology" />
                <div className="p-2">
                  <NetworkGraph overview={overview}
                    onClick={node => { setSearchQ(node); setView('flows'); }} />
                </div>
              </div>

              {/* Top Talkers */}
              <div className={CARD}>
                <SectionHeader icon={TrendingUp} title="Top Talkers" />
                {loadingO
                  ? <Spinner />
                  : !overview || overview.top_talkers.length === 0
                    ? <Empty icon={Server} text="No traffic data yet." />
                    : (
                      <div className="p-3 space-y-2">
                        {overview.top_talkers.map((t, i) => (
                          <div key={i} className="flex items-center gap-2.5 rounded-lg px-3 py-2.5"
                            style={{ background: 'var(--glass-bg)', border: `1px solid ${t.anomaly_count > 0 ? 'var(--orange)33' : 'var(--border)'}` }}>
                            <span className="text-[10px] font-bold w-4 text-center" style={{ color: 'var(--text-3)' }}>{i + 1}</span>
                            <div className="flex-1 min-w-0">
                              <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{t.host}</p>
                              <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                                {t.conn_count} conns · {t.unique_ips} unique IPs
                                {t.anomaly_count > 0 && <span className="ml-1" style={{ color: 'var(--orange)' }}>· {t.anomaly_count} anomalies</span>}
                              </p>
                            </div>
                            <button onClick={() => { setTimeHost(t.host); setView('timeline'); }}
                              className="g-btn g-btn-ghost text-[10px] px-2">
                              <Eye className="h-3 w-3" />
                            </button>
                          </div>
                        ))}
                      </div>
                    )
                }
              </div>
            </div>

            {/* Active alerts */}
            {overview && (overview.beaconing_detections > 0 || overview.lateral_movement > 0 || overview.c2_communications > 0) && (
              <div className="g-card p-3 space-y-2" style={{ border: '1px solid var(--red)33' }}>
                <p className="text-[10px] font-bold uppercase tracking-wider" style={{ color: 'var(--red)' }}>Active Threats</p>
                <div className="grid grid-cols-3 gap-2">
                  {overview.beaconing_detections > 0 && (
                    <div className="flex items-center gap-2 rounded-lg px-3 py-2.5 cursor-pointer"
                      style={{ background: 'var(--red)08', border: '1px solid var(--red)33' }}
                      onClick={() => setView('beacons')}>
                      <Radio className="h-4 w-4 animate-pulse shrink-0" style={{ color: 'var(--red)' }} />
                      <div>
                        <p className="text-sm font-bold" style={{ color: 'var(--red)' }}>{overview.beaconing_detections}</p>
                        <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>Beaconing</p>
                      </div>
                    </div>
                  )}
                  {overview.lateral_movement > 0 && (
                    <div className="flex items-center gap-2 rounded-lg px-3 py-2.5 cursor-pointer"
                      style={{ background: 'var(--red)08', border: '1px solid var(--red)33' }}
                      onClick={() => setView('lateral')}>
                      <GitBranch className="h-4 w-4 animate-pulse shrink-0" style={{ color: 'var(--red)' }} />
                      <div>
                        <p className="text-sm font-bold" style={{ color: 'var(--red)' }}>{overview.lateral_movement}</p>
                        <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>Lateral Movement</p>
                      </div>
                    </div>
                  )}
                  {overview.c2_communications > 0 && (
                    <div className="flex items-center gap-2 rounded-lg px-3 py-2.5 cursor-pointer"
                      style={{ background: 'var(--red)08', border: '1px solid var(--red)33' }}
                      onClick={() => setView('beacons')}>
                      <Crosshair className="h-4 w-4 animate-pulse shrink-0" style={{ color: 'var(--red)' }} />
                      <div>
                        <p className="text-sm font-bold" style={{ color: 'var(--red)' }}>{overview.c2_communications}</p>
                        <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>C2 Comms</p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Live Flows ── */}
        {view === 'flows' && (
          <div className={CARD}>
            <SectionHeader icon={Network} title={`Live Network Flows (${flows.length})`}
              action={
                <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                  Last {minutes}m · click column to sort
                </span>
              } />
            <div className="flex-1 overflow-y-auto" style={{ maxHeight: 600 }}>
              <FlowTable flows={flows} loading={loadingF} searchQ={searchQ} />
            </div>
          </div>
        )}

        {/* ── Traffic Analysis ── */}
        {view === 'traffic' && (
          <div className={CARD}>
            <SectionHeader icon={Activity} title="Traffic Analysis" />
            <TrafficPanel data={traffic} loading={loadingT} />
          </div>
        )}

        {/* ── DNS ── */}
        {view === 'dns' && (
          <div className={CARD}>
            <SectionHeader icon={Globe} title="DNS Analytics" />
            <DNSPanel data={dns} loading={loadingD} />
          </div>
        )}

        {/* ── TLS ── */}
        {view === 'tls' && (
          <div className={CARD}>
            <SectionHeader icon={Lock} title="TLS Analytics" />
            <TLSPanel data={tls} loading={loadingTLS} />
          </div>
        )}

        {/* ── Protocols ── */}
        {view === 'protocols' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            <div className={CARD}>
              <SectionHeader icon={Layers} title="Protocol Distribution" />
              <ProtocolBreakdown protocols={protocols} loading={loadingP} />
            </div>
            <div className={CARD}>
              <SectionHeader icon={Info} title="Protocol Risk Guide" />
              <div className="p-3 space-y-2">
                {[
                  { proto: 'SMB (445)',    risk: 'HIGH',   desc: 'File shares, lateral movement (PsExec/WannaCry)' },
                  { proto: 'RDP (3389)',   risk: 'HIGH',   desc: 'Remote desktop — common brute-force target' },
                  { proto: 'WinRM (5985)', risk: 'HIGH',   desc: 'Remote PowerShell execution' },
                  { proto: 'DNS (53/UDP)', risk: 'MEDIUM', desc: 'Monitor for tunneling, DGA, long queries' },
                  { proto: 'LDAP (389)',   risk: 'MEDIUM', desc: 'AD enumeration if queried from endpoints' },
                  { proto: 'Kerberos (88)',risk: 'MEDIUM', desc: 'AS-REP roasting, kerberoasting, TGT abuse' },
                  { proto: 'FTP (21)',     risk: 'HIGH',   desc: 'Cleartext credentials, exfiltration' },
                  { proto: 'Telnet (23)',  risk: 'CRITICAL',desc: 'Plaintext — should never be active' },
                ].map(p => (
                  <div key={p.proto} className="flex items-start gap-2.5 text-xs py-1.5" style={{ borderBottom: '1px solid var(--border)' }}>
                    <Tag text={p.risk} color={p.risk === 'CRITICAL' ? 'var(--red)' : p.risk === 'HIGH' ? 'var(--orange)' : 'var(--yellow)'} />
                    <div>
                      <span className="font-mono font-medium" style={{ color: 'var(--text-1)' }}>{p.proto}</span>
                      <span className="ml-2" style={{ color: 'var(--text-3)' }}>{p.desc}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── Behavioral Detection ── */}
        {view === 'behavioral' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            <div className={CARD}>
              <SectionHeader icon={ScanLine} title="Behavioral Detection" />
              <BehavioralDetection anomalyTypes={anomalyTypes} />
            </div>
            <div className={CARD}>
              <SectionHeader icon={AlertTriangle} title="Recent Anomalies" />
              <div className="p-3 space-y-1.5" style={{ maxHeight: 500, overflowY: 'auto' }}>
                {flows.filter(f => f.is_suspicious).slice(0, 20).map((f, i) => (
                  <div key={i} className="rounded-lg px-3 py-2" style={{ background: 'var(--red)08', border: '1px solid var(--red)22' }}>
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--red)' }} />
                      <span className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{f.hostname}</span>
                      <span className="font-mono text-[10px]" style={{ color: 'var(--red)' }}>{f.dst_address}</span>
                    </div>
                    <p className="text-[10px] pl-5 mt-0.5" style={{ color: 'var(--text-3)' }}>{f.process} · {f.protocol}</p>
                  </div>
                ))}
                {flows.filter(f => f.is_suspicious).length === 0 &&
                  <Empty icon={CheckCircle2} text="No suspicious flows detected." />}
              </div>
            </div>
          </div>
        )}

        {/* ── Beacons ── */}
        {view === 'beacons' && (
          <div className={CARD}>
            <SectionHeader icon={Radio} title="Beacon Detection" />
            <BeaconPanel data={beacons} loading={loadingB} />
          </div>
        )}

        {/* ── Lateral Movement ── */}
        {view === 'lateral' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
            <div className={CARD} style={{ gridColumn: 'span 2' }}>
              <SectionHeader icon={GitBranch} title="Lateral Movement Events" />
              <div style={{ maxHeight: 500, overflowY: 'auto' }}>
                <LateralMovementPanel data={lateral} loading={loadingL} />
              </div>
            </div>
            <div className={CARD}>
              <SectionHeader icon={Info} title="Attack Path Visualization" />
              <div className="p-4 space-y-3">
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Typical lateral movement chain:</p>
                {[
                  { host: 'Workstation (WS-014)', color: 'var(--accent)' },
                  { host: 'SMB → File Server', color: 'var(--orange)', arrow: true },
                  { host: 'RDP → Server-02', color: 'var(--orange)', arrow: true },
                  { host: 'PsExec → Domain Controller', color: 'var(--red)', arrow: true },
                ].map((s, i) => (
                  <div key={i} className="flex items-center gap-2">
                    {s.arrow && <ArrowRight className="h-3.5 w-3.5 shrink-0" style={{ color: s.color }} />}
                    <div className={`${s.arrow ? '' : 'ml-5'} flex-1 rounded-lg px-3 py-2`}
                      style={{ background: `${s.color}10`, border: `1px solid ${s.color}33` }}>
                      <p className="text-xs" style={{ color: s.color }}>{s.host}</p>
                    </div>
                  </div>
                ))}
                <p className="text-[10px] mt-2" style={{ color: 'var(--text-3)' }}>
                  See full attack path in <Link href="/attack-path" className="underline" style={{ color: 'var(--accent)' }}>Attack Path</Link>
                </p>
              </div>
            </div>
          </div>
        )}

        {/* ── Threat Intel ── */}
        {view === 'threat-intel' && (
          <div className={CARD}>
            <SectionHeader icon={Shield} title="Threat Intelligence Correlation" />
            <ThreatIntelPanel data={threatIntel} loading={loadingTI} />
          </div>
        )}

        {/* ── Timeline ── */}
        {view === 'timeline' && (
          <div className={CARD}>
            <SectionHeader icon={Clock} title="Network Event Timeline" />
            <TimelinePanel events={timeline} loading={loadingTL} searchHost={timeHost} onSearchHost={setTimeHost} />
          </div>
        )}

        {/* ── MITRE ── */}
        {view === 'mitre' && (
          <div className={CARD}>
            <SectionHeader icon={Crosshair} title="MITRE ATT&CK Mapping" />
            <MITREPanel techniques={mitre} loading={loadingM} />
          </div>
        )}

        {/* ── PCAP ── */}
        {view === 'pcap' && (
          <div className={CARD}>
            <SectionHeader icon={FlaskConical} title="PCAP Integration" />
            <PCAPPanel onToast={notify} />
          </div>
        )}

        {/* ── Analytics ── */}
        {view === 'analytics' && (
          <div className={CARD}>
            <SectionHeader icon={TrendingUp} title="Network Analytics" />
            <AnalyticsPanel data={analytics} loading={loadingA} />
          </div>
        )}

        {/* ── Response Actions ── */}
        {view === 'response' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            <div className={CARD}>
              <SectionHeader icon={Zap} title="Response Actions" />
              <ResponseActionsPanel onToast={notify} />
            </div>
            <div className={CARD}>
              <SectionHeader icon={Bot} title="AI Network Insights" />
              <AIInsightsPanel />
            </div>
          </div>
        )}

      </div>
    </RootLayout>
  );
}
