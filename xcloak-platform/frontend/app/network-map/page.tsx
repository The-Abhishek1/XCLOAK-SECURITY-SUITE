'use client';

import { createPortal } from 'react-dom';
import { useEffect, useMemo, useRef, useState, useCallback } from 'react';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { RootLayout } from '@/components/layout/RootLayout';
import { networkMapAPI, iocsAPI, agentsAPI, alertsAPI } from '@/lib/api';
import { NetworkMapGraph, NetworkMapNode, NetworkMapEdge, IPEnrichment } from '@/types';
import { sevClass, timeAgo } from '@/lib/utils';
import {
  Network, Search, X, Globe, Cpu, ShieldAlert,
  ZoomIn, AlertTriangle, Wifi, WifiOff, Info, Shield,
  MapPin, Building, ExternalLink, Clock, Copy, Plus,
  CheckCircle, Loader2, ChevronDown, ChevronUp,
  Lock, Cloud, GitMerge, Layers, Radio, Server,
  Terminal, Bug, Users, BarChart2, AlertCircle,
  Flame, HardDrive, Activity, Filter, Download,
  Eye, Zap, Database, Monitor, Sliders, Play,
  ArrowRight, TrendingUp, Fingerprint, ShieldCheck,
  ScanLine, Wrench, Power, Send, Gauge, Share2,
  FileJson, FileText, Image, Crosshair, Hash,
  MemoryStick, Container, Boxes, GitFork, SkipBack,
  Target, Workflow, UserCheck,
} from 'lucide-react';

const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), { ssr: false });

// ── Constants ─────────────────────────────────────────────────────────────────

const RISK_FILL: Record<string, string> = {
  critical: '#f85149',
  high:     '#fb923c',
  medium:   '#fbbf24',
  low:      '#38bdf8',
  unknown:  '#64748b',
};

const THREAT_FILL: Record<string, string> = {
  critical: '#f85149',
  high:     '#fb923c',
  medium:   '#fbbf24',
  low:      '#38bdf8',
  none:     '#64748b',
};

const SENSITIVITY_COLOR: Record<string, string> = {
  critical:  '#f85149',
  sensitive: '#fb923c',
  neutral:   '#94a3b8',
  safe:      '#4ade80',
};

const SEV_COLORS: Record<string, string> = {
  critical: '#f85149', high: '#fb923c', medium: '#fbbf24', low: '#38bdf8',
};

const INFRA_FILL: Record<string, string> = {
  firewall:         '#f97316',
  router:           '#06b6d4',
  switch:           '#3b82f6',
  vpn:              '#8b5cf6',
  wireless:         '#10b981',
  cloud:            '#38bdf8',
  wan:              '#94a3b8',
  internet_gateway: '#f43f5e',
  dmz:              '#f97316',
  load_balancer:    '#0ea5e9',
  reverse_proxy:    '#6366f1',
  dns_server:       '#a855f7',
  dhcp_server:      '#d946ef',
  hypervisor:       '#0891b2',
  storage:          '#64748b',
  iot:              '#22d3ee',
  ot_ics:           '#ef4444',
  kubernetes:       '#326ce5',
  container:        '#00b4d8',
  vm:               '#7c3aed',
  sdwan:            '#059669',
  vpn_site:         '#7c3aed',
};

const INFRA_LABELS: Record<string, string> = {
  firewall:         'Firewall',
  router:           'Router',
  switch:           'Switch',
  vpn:              'VPN Gateway',
  wireless:         'Wireless AP',
  cloud:            'Cloud Resource',
  wan:              'WAN Link',
  internet_gateway: 'Internet Gateway',
  dmz:              'DMZ',
  load_balancer:    'Load Balancer',
  reverse_proxy:    'Reverse Proxy',
  dns_server:       'DNS Server',
  dhcp_server:      'DHCP Server',
  hypervisor:       'Hypervisor',
  storage:          'Storage (NAS/SAN)',
  iot:              'IoT Device',
  ot_ics:           'OT/ICS Device',
  kubernetes:       'Kubernetes Cluster',
  container:        'Container',
  vm:               'Virtual Machine',
  sdwan:            'SD-WAN',
  vpn_site:         'Site-to-Site VPN',
};

const VIEW_MODES = ['Physical', 'Logical', 'Security', 'Cloud', 'Identity', 'Application'] as const;
type ViewMode = typeof VIEW_MODES[number];

const THREAT_OVERLAYS: { id: string; label: string; color: string; pattern: RegExp }[] = [
  { id: 'malware',          label: 'Malware',           color: '#f85149', pattern: /malware|ransomware|trojan|rootkit/i },
  { id: 'beaconing',        label: 'Beaconing',         color: '#fb923c', pattern: /beacon|c2|command.control|cobalt/i },
  { id: 'lateral_movement', label: 'Lateral Movement',  color: '#fbbf24', pattern: /lateral|psexec|pass.the|wmiexec/i },
  { id: 'c2',               label: 'C2 Traffic',        color: '#f43f5e', pattern: /cobalt|empire|metasploit|\bc2\b|rat\b/i },
  { id: 'dns_tunnel',       label: 'DNS Tunneling',     color: '#a855f7', pattern: /dns.*tunnel|iodine|dnscat/i },
  { id: 'port_scan',        label: 'Port Scanning',     color: '#38bdf8', pattern: /port.?scan|nmap|masscan/i },
  { id: 'smb_abuse',        label: 'SMB Abuse',         color: '#fb923c', pattern: /smb|eternalblue|wannacry/i },
  { id: 'rdp_abuse',        label: 'RDP Abuse',         color: '#f97316', pattern: /rdp|bluekeep|3389/i },
  { id: 'brute_force',      label: 'SSH Brute Force',   color: '#fbbf24', pattern: /brute|ssh.*fail|pass.*fail/i },
  { id: 'exfiltration',     label: 'Data Exfiltration', color: '#f43f5e', pattern: /exfil|data.?loss|upload.*large/i },
  { id: 'susp_vpn',         label: 'Suspicious VPN',    color: '#d946ef', pattern: /vpn.*anomaly|split.*tunnel/i },
  { id: 'east_west',        label: 'East-West',         color: '#0ea5e9', pattern: /east.*west|internal.*spread/i },
];

const TIME_WINDOWS = [
  { label: '15m', minutes: 15 },
  { label: '1h',  minutes: 60 },
  { label: '6h',  minutes: 360 },
  { label: '24h', minutes: 1440 },
];

const AGENT_TABS = [
  { id: 'overview',  label: 'Overview',  icon: Activity    },
  { id: 'identity',  label: 'Identity',  icon: Fingerprint },
  { id: 'security',  label: 'Security',  icon: ShieldCheck },
  { id: 'hardware',  label: 'Hardware',  icon: HardDrive   },
  { id: 'traffic',   label: 'Traffic',   icon: TrendingUp  },
  { id: 'ports',     label: 'Ports',     icon: Server      },
  { id: 'cves',      label: 'CVEs',      icon: Bug         },
  { id: 'processes', label: 'Processes', icon: Terminal    },
  { id: 'alerts',    label: 'Alerts',    icon: AlertCircle },
  { id: 'timeline',  label: 'Timeline',  icon: Clock       },
  { id: 'actions',   label: 'Actions',   icon: Zap         },
  { id: 'ai',        label: 'AI',        icon: Flame       },
];

interface GNode extends NetworkMapNode { val: number; }

function resolveVar(name: string): string {
  if (typeof window === 'undefined') return '#64748b';
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || '#64748b';
}

// ── Legend ─────────────────────────────────────────────────────────────────────

function Legend() {
  const [open, setOpen] = useState(false);
  const btnRef = useRef<HTMLButtonElement>(null);
  const [pos, setPos] = useState({ top: 0, right: 0 });

  const openLegend = () => {
    if (btnRef.current) {
      const r = btnRef.current.getBoundingClientRect();
      setPos({ top: r.bottom + 6, right: window.innerWidth - r.right });
    }
    setOpen(o => !o);
  };

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (btnRef.current && !btnRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  const panel = open && typeof document !== 'undefined'
    ? createPortal(
        <div onMouseDown={e => e.stopPropagation()}
          style={{
            position: 'fixed', top: pos.top, right: pos.right, zIndex: 99999, width: 288,
            background: 'var(--bg-1)', border: '1px solid var(--border)',
            borderRadius: 14, padding: 16, boxShadow: '0 20px 40px rgba(0,0,0,0.4)',
          }}>

          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Agent risk (fill)</p>
          <div className="grid grid-cols-2 gap-1 mb-3">
            {Object.entries(RISK_FILL).map(([k, v]) => (
              <div key={k} className="flex items-center gap-2 text-[11px]" style={{ color: 'var(--text-2)' }}>
                <span className="h-3 w-3 rounded-full shrink-0" style={{ background: v }} />{k}
              </div>
            ))}
          </div>

          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Infrastructure (fill)</p>
          <div className="grid grid-cols-2 gap-1 mb-3">
            {Object.entries(INFRA_FILL).map(([k, v]) => (
              <div key={k} className="flex items-center gap-2 text-[11px]" style={{ color: 'var(--text-2)' }}>
                <span className="h-3 w-3 rounded shrink-0" style={{ background: v }} />{INFRA_LABELS[k]}
              </div>
            ))}
          </div>

          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>External IP threat (fill)</p>
          <div className="grid grid-cols-2 gap-1 mb-3">
            {Object.entries(THREAT_FILL).filter(([k]) => k !== 'none').map(([k, v]) => (
              <div key={k} className="flex items-center gap-2 text-[11px]" style={{ color: 'var(--text-2)' }}>
                <span className="h-3 w-3 rounded-full shrink-0" style={{ background: v }} />{k}
              </div>
            ))}
            <div className="flex items-center gap-2 text-[11px]" style={{ color: 'var(--text-2)' }}>
              <span className="h-3 w-3 rounded-full shrink-0" style={{ background: '#64748b' }} />unknown
            </div>
          </div>

          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Zone (ring)</p>
          <div className="space-y-1 mb-3 text-[11px]" style={{ color: 'var(--text-2)' }}>
            <div className="flex items-center gap-2"><span className="h-3 w-3 rounded-full border shrink-0" style={{ borderColor: '#94a3b8' }} /> Internal</div>
            <div className="flex items-center gap-2"><span className="h-3 w-3 rounded-full border-2 shrink-0" style={{ borderColor: '#fb923c' }} /> DMZ (internet-exposed)</div>
            <div className="flex items-center gap-2"><span className="h-3 w-3 rounded-full shrink-0" style={{ background: '#94a3b8' }} /> External IP</div>
          </div>

          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Overlays</p>
          <div className="space-y-1 mb-3 text-[11px]" style={{ color: 'var(--text-2)' }}>
            <div className="flex items-center gap-2"><span className="h-3 w-3 rounded-full shrink-0" style={{ background: '#e879f9' }} /> IOC match</div>
            <div className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-full shrink-0" style={{ background: '#f85149' }} /> Active alerts (top-right dot)</div>
          </div>

          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Edge (port risk)</p>
          <div className="space-y-1 text-[11px]" style={{ color: 'var(--text-2)' }}>
            {Object.entries(SENSITIVITY_COLOR).map(([k, v]) => (
              <div key={k} className="flex items-center gap-2">
                <span className="h-0.5 w-6 shrink-0 rounded" style={{ background: v }} />{k}
              </div>
            ))}
            <div className="flex items-center gap-2">
              <span className="h-0.5 w-6 shrink-0 rounded" style={{ background: 'rgba(99,179,237,0.6)' }} /> internal (no port risk)
            </div>
          </div>
        </div>,
        document.body
      )
    : null;

  return (
    <>
      <button ref={btnRef} type="button" onClick={openLegend}
        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs transition-colors"
        style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
        <Info className="h-3.5 w-3.5" /> Legend
      </button>
      {panel}
    </>
  );
}

// ── EnrichPanel ───────────────────────────────────────────────────────────────

function EnrichPanel({ ip, tenantFetched }: { ip: string; tenantFetched: boolean }) {
  const [data, setData] = useState<IPEnrichment | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [addingIOC, setAddingIOC] = useState(false);
  const [iocAdded, setIocAdded] = useState(false);
  const [open, setOpen] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setData(null);
    setLoading(true);
    networkMapAPI.getIPInfo(ip)
      .then(r => { if (!cancelled) setData(r.data); })
      .catch(() => {})
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [ip]);

  const copyIP = () => {
    navigator.clipboard.writeText(ip);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const addToIOC = async () => {
    if (!data) return;
    setAddingIOC(true);
    try {
      await iocsAPI.create({
        indicator: ip, type: 'ip',
        severity: data.threat_level === 'none' ? 'low' : data.threat_level,
        description: data.threat_tags.join(', ') || 'Added from network map',
        enabled: true,
      });
      setIocAdded(true);
    } catch {}
    finally { setAddingIOC(false); }
  };

  const tlColor = data ? (THREAT_FILL[data.threat_level] || '#64748b') : '#64748b';

  return (
    <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
      <button type="button" onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-3 py-2.5 text-xs font-bold uppercase tracking-wider"
        style={{ background: 'var(--glass-bg)', color: 'var(--text-3)' }}>
        <span className="flex items-center gap-2">
          <Globe className="h-3.5 w-3.5" /> Threat Intelligence
          {data && (
            <span className="rounded-full px-2 py-0.5 text-[10px] font-semibold capitalize"
              style={{ background: tlColor + '22', color: tlColor, border: `1px solid ${tlColor}55` }}>
              {data.threat_level}
            </span>
          )}
        </span>
        {open ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
      </button>

      {open && (
        <div className="p-3 space-y-3">
          <div className="flex items-center gap-2">
            <span className="mono text-xs flex-1 truncate" style={{ color: 'var(--text-1)' }}>{ip}</span>
            <button type="button" onClick={copyIP} title="Copy IP"
              className="p-1 rounded" style={{ color: copied ? 'var(--green)' : 'var(--text-3)' }}>
              {copied ? <CheckCircle className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
            </button>
            {data && !data.is_ioc && !iocAdded && (
              <button type="button" onClick={addToIOC} disabled={addingIOC} title="Add to IOC list"
                className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] transition-colors"
                style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)', color: 'var(--accent)' }}>
                {addingIOC ? <Loader2 className="h-3 w-3 animate-spin" /> : <Plus className="h-3 w-3" />}
                Add IOC
              </button>
            )}
            {iocAdded && (
              <span className="flex items-center gap-1 text-[10px]" style={{ color: 'var(--green)' }}>
                <CheckCircle className="h-3.5 w-3.5" /> Added
              </span>
            )}
          </div>

          {loading && (
            <div className="flex items-center gap-2 py-2 text-xs" style={{ color: 'var(--text-3)' }}>
              <Loader2 className="h-3.5 w-3.5 animate-spin" /> Fetching threat intel…
            </div>
          )}

          {data && (
            <>
              {data.threat_tags.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {data.threat_tags.map(t => (
                    <span key={t} className="rounded-full px-2 py-0.5 text-[10px] font-medium"
                      style={{ background: tlColor + '22', color: tlColor, border: `1px solid ${tlColor}44` }}>
                      {t}
                    </span>
                  ))}
                </div>
              )}
              {!data.is_private && data.country && (
                <div className="grid grid-cols-2 gap-2">
                  <InfoCell icon={<MapPin className="h-3 w-3" />} label="Location"
                    val={[data.city, data.region, data.country].filter(Boolean).join(', ')} />
                  <InfoCell icon={<Building className="h-3 w-3" />} label="Org / ASN"
                    val={data.org || data.asn || '—'} />
                </div>
              )}
              {data.is_private && (
                <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>Private / RFC-1918 address — no external enrichment.</p>
              )}
              {(data.is_proxy || data.is_hosting) && (
                <div className="flex flex-wrap gap-1.5">
                  {data.is_proxy && <Flag label="VPN / Proxy" color="#fb923c" />}
                  {data.is_hosting && <Flag label="Hosting / DC" color="#94a3b8" />}
                </div>
              )}
              {data.abuse_score != null && (
                <div className="rounded-lg p-2.5" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                  <div className="flex items-center justify-between mb-1.5">
                    <p className="text-[10px] font-bold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>AbuseIPDB</p>
                    <a href={`https://www.abuseipdb.com/check/${ip}`} target="_blank" rel="noopener noreferrer"
                      className="text-[10px] flex items-center gap-0.5" style={{ color: 'var(--accent)' }}>
                      check <ExternalLink className="h-2.5 w-2.5" />
                    </a>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--border)' }}>
                      <div className="h-full rounded-full transition-all" style={{
                        width: `${data.abuse_score}%`,
                        background: data.abuse_score >= 75 ? '#f85149' : data.abuse_score >= 25 ? '#fb923c' : '#fbbf24',
                      }} />
                    </div>
                    <span className="text-xs font-semibold tabular-nums" style={{
                      color: data.abuse_score >= 75 ? '#f85149' : data.abuse_score >= 25 ? '#fb923c' : 'var(--text-2)',
                    }}>{data.abuse_score}%</span>
                    <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{data.abuse_reports} reports</span>
                  </div>
                  {data.abuse_categories && data.abuse_categories.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {data.abuse_categories.slice(0, 5).map(c => (
                        <span key={c} className="text-[10px] rounded px-1.5 py-0.5"
                          style={{ background: 'var(--glass-bg)', color: 'var(--text-3)', border: '1px solid var(--border)' }}>{c}</span>
                      ))}
                    </div>
                  )}
                </div>
              )}
              {data.vt_malicious != null && data.vt_total != null && (
                <div className="rounded-lg p-2.5" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                  <div className="flex items-center justify-between mb-1.5">
                    <p className="text-[10px] font-bold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>VirusTotal</p>
                    <a href={`https://www.virustotal.com/gui/ip-address/${ip}`} target="_blank" rel="noopener noreferrer"
                      className="text-[10px] flex items-center gap-0.5" style={{ color: 'var(--accent)' }}>
                      report <ExternalLink className="h-2.5 w-2.5" />
                    </a>
                  </div>
                  <div className="flex items-center gap-2 text-xs">
                    <span style={{ color: data.vt_malicious > 0 ? '#f85149' : 'var(--green)' }}>
                      {data.vt_malicious} malicious
                    </span>
                    {data.vt_suspicious != null && data.vt_suspicious > 0 && (
                      <span style={{ color: '#fb923c' }}>{data.vt_suspicious} suspicious</span>
                    )}
                    <span style={{ color: 'var(--text-3)' }}>/ {data.vt_total} engines</span>
                  </div>
                </div>
              )}
              {data.is_ioc && (
                <div className="rounded-lg p-2.5" style={{ background: 'rgba(232,121,249,0.08)', border: '1px solid rgba(232,121,249,0.3)' }}>
                  <p className="text-[10px] font-bold uppercase tracking-wider mb-0.5" style={{ color: '#e879f9' }}>Local IOC Match</p>
                  <p className="text-[11px]" style={{ color: 'var(--text-2)' }}>
                    Severity: <strong>{data.ioc_severity}</strong>
                    {data.ioc_description && ` · ${data.ioc_description}`}
                  </p>
                  <Link href="/threat-intel" className="text-[10px] mt-1 inline-flex items-center gap-0.5"
                    style={{ color: '#e879f9' }}>
                    View in Threat Intel <ExternalLink className="h-2.5 w-2.5" />
                  </Link>
                </div>
              )}
              {data.sources.length > 0 && (
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                  Sources: {data.sources.join(' · ')}
                </p>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ── Helper components ─────────────────────────────────────────────────────────

function InfoCell({ icon, label, val }: { icon: React.ReactNode; label: string; val: string }) {
  return (
    <div className="rounded-lg p-2" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
      <div className="flex items-center gap-1 mb-0.5" style={{ color: 'var(--text-3)' }}>
        {icon}
        <p className="text-[10px] uppercase tracking-wider">{label}</p>
      </div>
      <p className="text-[11px] leading-tight" style={{ color: 'var(--text-1)' }}>{val}</p>
    </div>
  );
}

function Flag({ label, color }: { label: string; color: string }) {
  return (
    <span className="rounded-full px-2 py-0.5 text-[10px] font-medium"
      style={{ background: color + '22', color, border: `1px solid ${color}55` }}>
      {label}
    </span>
  );
}

function PortBadge({ e }: { e: NetworkMapEdge }) {
  const sens  = e.port_sensitivity || 'neutral';
  const color = SENSITIVITY_COLOR[sens] || '#94a3b8';
  const label = e.service ? `${e.port}/${e.service}` : e.port;
  return (
    <span title={e.port_note || ''} className="rounded px-1.5 py-0.5 mono text-[10px] cursor-default"
      style={{ background: color + '20', color, border: `1px solid ${color}55` }}>
      {label}/{e.protocol.toUpperCase()}
    </span>
  );
}

// ── Agent drawer tabs ─────────────────────────────────────────────────────────

function PortsTab({ edges }: { edges: NetworkMapEdge[] }) {
  const ports = useMemo(() => {
    const seen = new Map<string, NetworkMapEdge>();
    for (const e of edges) {
      const key = `${e.port}/${e.protocol}`;
      if (!seen.has(key)) seen.set(key, e);
    }
    return Array.from(seen.values()).sort((a, b) => {
      const ord: Record<string, number> = { critical: 0, sensitive: 1, neutral: 2, safe: 3 };
      return (ord[a.port_sensitivity || 'neutral'] ?? 2) - (ord[b.port_sensitivity || 'neutral'] ?? 2);
    });
  }, [edges]);

  if (ports.length === 0) {
    return (
      <div className="py-10 text-center">
        <Server className="mx-auto h-7 w-7 mb-2" style={{ color: 'var(--text-3)' }} />
        <p className="text-xs" style={{ color: 'var(--text-3)' }}>No port data in selected time window.</p>
      </div>
    );
  }

  return (
    <div className="space-y-1.5">
      {ports.map((e, i) => {
        const sens  = e.port_sensitivity || 'neutral';
        const color = SENSITIVITY_COLOR[sens] || '#94a3b8';
        return (
          <div key={i} className="flex items-center gap-3 rounded-lg px-3 py-2.5"
            style={{ background: 'var(--bg-0)', border: `1px solid ${color}44` }}>
            <div className="h-1.5 w-1.5 rounded-full shrink-0" style={{ background: color }} />
            <div className="flex-1 min-w-0">
              <p className="mono text-xs font-medium" style={{ color: 'var(--text-1)' }}>
                {e.port}/{e.protocol.toUpperCase()}
                {e.service && <span className="text-[10px] ml-1.5" style={{ color: 'var(--text-3)' }}>{e.service}</span>}
              </p>
              {e.process && <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>process: {e.process}</p>}
            </div>
            <span className="text-[10px] font-medium capitalize shrink-0" style={{ color }}>{sens}</span>
          </div>
        );
      })}
    </div>
  );
}

function CVEsTab({ vulns }: { vulns: any[] }) {
  if (vulns.length === 0) {
    return (
      <div className="py-10 text-center">
        <Bug className="mx-auto h-7 w-7 mb-2" style={{ color: 'var(--text-3)' }} />
        <p className="text-xs" style={{ color: 'var(--text-3)' }}>No vulnerabilities detected on this host.</p>
      </div>
    );
  }

  const sorted = [...vulns].sort((a, b) => (b.cvss_score ?? 0) - (a.cvss_score ?? 0));

  return (
    <div className="space-y-2">
      {sorted.map((v, i) => {
        const color = SEV_COLORS[v.severity] || 'var(--text-3)';
        return (
          <div key={i} className="rounded-lg p-3" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
            <div className="flex items-start justify-between gap-2 mb-1">
              <p className="mono text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{v.cve_id}</p>
              <div className="flex items-center gap-1.5 shrink-0">
                {v.cvss_score != null && (
                  <span className="text-[10px] font-bold tabular-nums" style={{ color }}>{v.cvss_score}</span>
                )}
                <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase`}
                  style={{ background: color + '22', color, border: `1px solid ${color}55` }}>
                  {v.severity}
                </span>
              </div>
            </div>
            {v.description && (
              <p className="text-[11px] leading-relaxed" style={{ color: 'var(--text-2)' }}>{v.description}</p>
            )}
            {v.package_name && (
              <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>Package: {v.package_name} {v.installed_version}</p>
            )}
          </div>
        );
      })}
    </div>
  );
}

function ProcessesTab({ processes }: { processes: any[] }) {
  if (processes.length === 0) {
    return (
      <div className="py-10 text-center">
        <Terminal className="mx-auto h-7 w-7 mb-2" style={{ color: 'var(--text-3)' }} />
        <p className="text-xs" style={{ color: 'var(--text-3)' }}>No process data available.</p>
      </div>
    );
  }

  return (
    <div className="space-y-1">
      {processes.slice(0, 30).map((p, i) => (
        <div key={i} className="flex items-center gap-2 rounded-lg px-3 py-2"
          style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
          <span className="mono text-[10px] w-10 tabular-nums shrink-0" style={{ color: 'var(--text-3)' }}>{p.pid}</span>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{p.name || p.process_name}</p>
            {(p.cmd || p.cmdline) && (
              <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }} title={p.cmd || p.cmdline}>
                {(p.cmd || p.cmdline).slice(0, 60)}
              </p>
            )}
          </div>
          {p.cpu_percent != null && (
            <span className="text-[10px] tabular-nums shrink-0" style={{ color: 'var(--text-3)' }}>
              {Number(p.cpu_percent).toFixed(1)}%
            </span>
          )}
        </div>
      ))}
    </div>
  );
}

function AlertsTab({ alerts, agentId }: { alerts: any[]; agentId: number }) {
  const nodeAlerts = alerts.filter(a => a.agent_id === agentId).slice(0, 15);

  if (nodeAlerts.length === 0) {
    return (
      <div className="py-10 text-center">
        <AlertCircle className="mx-auto h-7 w-7 mb-2" style={{ color: 'var(--text-3)' }} />
        <p className="text-xs" style={{ color: 'var(--text-3)' }}>No recent alerts for this host.</p>
      </div>
    );
  }

  return (
    <div className="space-y-1.5">
      {nodeAlerts.map((a, i) => {
        const color = SEV_COLORS[a.severity] || 'var(--text-3)';
        return (
          <Link key={i} href="/alerts"
            className="block rounded-lg p-3 transition-colors"
            style={{ background: 'var(--bg-0)', border: `1px solid ${color}33` }}
            onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--glass-hover)'}
            onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'var(--bg-0)'}>
            <div className="flex items-start justify-between gap-2 mb-0.5">
              <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{a.rule_name}</p>
              <span className="text-[9px] px-1.5 py-0.5 rounded font-bold uppercase shrink-0"
                style={{ background: color + '22', color, border: `1px solid ${color}55` }}>
                {a.severity}
              </span>
            </div>
            {a.log_message && (
              <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>{a.log_message}</p>
            )}
            <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>{timeAgo(a.created_at)}</p>
          </Link>
        );
      })}
    </div>
  );
}

function TimelineTab({ timeline }: { timeline: any[] }) {
  if (timeline.length === 0) {
    return (
      <div className="py-10 text-center">
        <Clock className="mx-auto h-7 w-7 mb-2" style={{ color: 'var(--text-3)' }} />
        <p className="text-xs" style={{ color: 'var(--text-3)' }}>No timeline events available.</p>
      </div>
    );
  }

  return (
    <div className="relative">
      <div className="absolute left-3.5 top-0 bottom-0 w-px" style={{ background: 'var(--border)' }} />
      <div className="space-y-3 pl-8">
        {timeline.map((ev, i) => {
          const color = SEV_COLORS[ev.severity] || 'var(--text-3)';
          return (
            <div key={i} className="relative">
              <div className="absolute -left-5 top-1.5 h-2.5 w-2.5 rounded-full border-2"
                style={{ background: color + '44', borderColor: color }} />
              <div className="rounded-lg p-3" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                <div className="flex items-center justify-between gap-2 mb-0.5">
                  <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color }}>{ev.event_type}</p>
                  <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(ev.timestamp || ev.created_at)}</span>
                </div>
                <p className="text-xs" style={{ color: 'var(--text-1)' }}>{ev.message}</p>
                {ev.mitre_tactic && (
                  <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>MITRE: {ev.mitre_tactic}</p>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── New drawer tabs ───────────────────────────────────────────────────────────

function IdentityTab({ node }: { node: NetworkMapNode }) {
  const rows = [
    { label: 'Hostname',      val: node.hostname || '—' },
    { label: 'IPv4',          val: node.ip || '—' },
    { label: 'IPv6',          val: '—' },
    { label: 'MAC Address',   val: '—' },
    { label: 'DNS Name',      val: node.hostname ? `${node.hostname}.local` : '—' },
    { label: 'OS',            val: '—' },
    { label: 'Domain',        val: '—' },
    { label: 'Zone',          val: node.zone },
    { label: 'VLAN',          val: node.vlan || '—' },
    { label: 'Role',          val: node.role || '—' },
    { label: 'Asset Owner',   val: '—' },
    { label: 'Business Unit', val: '—' },
    { label: 'Criticality',   val: node.risk_level },
  ];
  return (
    <div className="space-y-1.5">
      {rows.map(({ label, val }) => (
        <div key={label} className="flex items-center justify-between px-3 py-2 rounded-lg"
          style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
          <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{label}</span>
          <span className="mono text-[11px] font-medium" style={{ color: 'var(--text-1)' }}>{val}</span>
        </div>
      ))}
    </div>
  );
}

function SecurityTab({ node, vulns }: { node: NetworkMapNode; vulns: any[] }) {
  const criticalCVEs = vulns.filter(v => v.severity === 'critical').length;
  const patchScore   = vulns.length === 0 ? 100 : Math.max(0, 100 - vulns.length * 5);
  const exposureScore = node.risk_score;

  const items = [
    { label: 'EDR Status',        val: node.agent_id ? 'Installed' : 'Not Installed', ok: !!node.agent_id },
    { label: 'Firewall Status',   val: 'Unknown', ok: null },
    { label: 'Antivirus',         val: 'Unknown', ok: null },
    { label: 'Disk Encryption',   val: 'Unknown', ok: null },
    { label: 'Patch Level',       val: `${patchScore}%`, ok: patchScore > 80 },
    { label: 'Last Vuln Scan',    val: '—', ok: null },
    { label: 'Critical CVEs',     val: String(criticalCVEs), ok: criticalCVEs === 0 },
    { label: 'Total CVEs',        val: String(vulns.length), ok: vulns.length === 0 },
  ];
  return (
    <div className="space-y-3">
      <div className="rounded-xl p-3" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
        <div className="flex items-center justify-between mb-1.5">
          <span className="text-[10px] font-bold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Exposure Score</span>
          <span className="text-sm font-bold tabular-nums" style={{ color: RISK_FILL[node.risk_level] || 'var(--text-1)' }}>{exposureScore}/100</span>
        </div>
        <div className="h-2 rounded-full overflow-hidden" style={{ background: 'var(--bg-0)' }}>
          <div className="h-full rounded-full" style={{ width: `${exposureScore}%`, background: RISK_FILL[node.risk_level] || 'var(--accent)' }} />
        </div>
      </div>
      <div className="space-y-1.5">
        {items.map(({ label, val, ok }) => (
          <div key={label} className="flex items-center justify-between px-3 py-2 rounded-lg"
            style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
            <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{label}</span>
            <span className="text-[11px] font-medium"
              style={{ color: ok === null ? 'var(--text-2)' : ok ? 'var(--green)' : 'var(--red)' }}>
              {val}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function HardwareTab({ processes }: { processes: any[] }) {
  const cpuTop = processes.reduce((sum, p) => sum + (p.cpu_percent || 0), 0);
  const memTop = processes.reduce((sum, p) => sum + (p.memory_mb || p.mem_rss || 0), 0);

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-2">
        {[
          { label: 'CPU Usage',   val: `${Math.min(100, cpuTop).toFixed(1)}%`, icon: Gauge },
          { label: 'Memory',      val: memTop > 0 ? `${(memTop / 1024).toFixed(1)} GB` : '—', icon: MemoryStick },
          { label: 'Disk',        val: '—',  icon: HardDrive },
          { label: 'Uptime',      val: '—',  icon: Clock     },
          { label: 'Manufacturer',val: '—',  icon: Monitor   },
          { label: 'Serial',      val: '—',  icon: Hash      },
        ].map(({ label, val, icon: Icon }) => (
          <div key={label} className="rounded-xl p-3" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
            <div className="flex items-center gap-1.5 mb-1" style={{ color: 'var(--text-3)' }}>
              <Icon className="h-3 w-3" />
              <span className="text-[10px] uppercase tracking-wider">{label}</span>
            </div>
            <p className="mono text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{val}</p>
          </div>
        ))}
      </div>
      {processes.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>Top CPU Processes</p>
          <div className="space-y-1">
            {[...processes].sort((a, b) => (b.cpu_percent || 0) - (a.cpu_percent || 0)).slice(0, 5).map((p, i) => (
              <div key={i} className="flex items-center justify-between px-3 py-1.5 rounded-lg"
                style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                <span className="text-xs truncate" style={{ color: 'var(--text-1)' }}>{p.name || p.process_name}</span>
                <span className="mono text-[11px]" style={{ color: 'var(--text-3)' }}>{Number(p.cpu_percent || 0).toFixed(1)}%</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function TrafficTab({ edges, nodeId }: { edges: NetworkMapEdge[]; nodeId: string }) {
  const totalConns = edges.length;
  const outbound   = edges.filter(e => e.source === nodeId).length;
  const inbound    = edges.filter(e => e.target === nodeId).length;
  const protocols  = edges.reduce<Record<string, number>>((acc, e) => {
    acc[e.protocol] = (acc[e.protocol] || 0) + (e.count || 1); return acc;
  }, {});
  const topProtos  = Object.entries(protocols).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const totalFlow  = edges.reduce((s, e) => s + (e.count || 1), 0);

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-3 gap-2">
        {[
          { label: 'Active Sessions', val: totalConns },
          { label: 'Outbound',        val: outbound   },
          { label: 'Inbound',         val: inbound    },
        ].map(({ label, val }) => (
          <div key={label} className="rounded-xl p-3 text-center" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
            <p className="text-lg font-bold tabular-nums" style={{ color: 'var(--text-1)' }}>{val}</p>
            <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{label}</p>
          </div>
        ))}
      </div>
      <div>
        <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Protocol Distribution</p>
        <div className="space-y-1.5">
          {topProtos.map(([proto, count]) => (
            <div key={proto} className="flex items-center gap-2">
              <span className="mono text-[11px] w-14 shrink-0" style={{ color: 'var(--text-2)' }}>{proto.toUpperCase()}</span>
              <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--bg-0)' }}>
                <div className="h-full rounded-full" style={{ width: `${(count / totalFlow) * 100}%`, background: 'var(--accent)' }} />
              </div>
              <span className="text-[10px] w-8 text-right tabular-nums" style={{ color: 'var(--text-3)' }}>{count}</span>
            </div>
          ))}
        </div>
      </div>
      <div>
        <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Top Connections</p>
        <div className="space-y-1.5">
          {edges.slice(0, 8).map((e, i) => (
            <div key={i} className="flex items-center justify-between px-3 py-2 rounded-lg text-[11px]"
              style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
              <span className="mono truncate" style={{ color: 'var(--text-1)' }}>
                {e.source === nodeId ? '→' : '←'} {e.process || 'unknown'}
              </span>
              <span style={{ color: 'var(--text-3)' }}>×{e.count}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ActionsTab({ node, onToast }: { node: NetworkMapNode; onToast: (m: string) => void }) {
  const agentActions = [
    { label: 'Isolate Endpoint',  icon: Shield,     color: 'var(--red)',    action: () => onToast('Isolation request sent') },
    { label: 'Scan Host',         icon: ScanLine,   color: 'var(--accent)', action: () => onToast('Scan initiated') },
    { label: 'Ping',              icon: Crosshair,  color: 'var(--accent)', action: () => onToast('Ping sent') },
    { label: 'Port Scan',         icon: Target,     color: 'var(--orange)', action: () => onToast('Port scan queued') },
    { label: 'Vulnerability Scan',icon: Bug,        color: 'var(--orange)', action: () => onToast('Vuln scan queued') },
    { label: 'Collect Logs',      icon: FileText,   color: 'var(--accent)', action: () => onToast('Log collection started') },
    { label: 'Restart Agent',     icon: Power,      color: 'var(--orange)', action: () => onToast('Restart command sent') },
    { label: 'Create Incident',   icon: AlertCircle,color: 'var(--red)',    action: () => onToast('Incident created') },
  ];
  const ipActions = [
    { label: 'Block IP',     icon: Shield,      color: 'var(--red)',    action: () => onToast('Block rule pushed') },
    { label: 'Add to IOC',   icon: AlertTriangle,color:'var(--orange)', action: () => onToast('Added to IOC list') },
    { label: 'Whois Lookup', icon: Globe,       color: 'var(--accent)', action: () => onToast('Whois lookup sent') },
  ];
  const actions = node.type === 'agent' ? agentActions : node.type === 'external_ip' ? ipActions : agentActions.slice(0, 4);
  return (
    <div className="grid grid-cols-2 gap-2">
      {actions.map(({ label, icon: Icon, color, action }) => (
        <button key={label} onClick={action}
          className="flex flex-col items-center gap-2 p-3 rounded-xl text-xs font-medium transition-all hover:opacity-80"
          style={{ background: 'var(--bg-0)', border: `1px solid ${color}44`, color }}>
          <Icon className="h-4 w-4" />
          {label}
        </button>
      ))}
      {node.agent_id && (
        <Link href={`/agents/${node.agent_id}`}
          className="flex flex-col items-center gap-2 p-3 rounded-xl text-xs font-medium transition-all hover:opacity-80 col-span-2"
          style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)', color: 'var(--accent)' }}>
          <ArrowRight className="h-4 w-4" />
          Open Full Agent Detail
        </Link>
      )}
    </div>
  );
}

function AITab({ node, alerts, vulns, edges }: { node: NetworkMapNode; alerts: any[]; vulns: any[]; edges: NetworkMapEdge[] }) {
  const nodeAlerts   = alerts.filter(a => a.agent_id === node.agent_id);
  const criticalCVEs = vulns.filter(v => v.severity === 'critical').length;
  const extEdges     = edges.filter(e => e.edge_type === 'external');
  const highPort     = edges.filter(e => e.port_sensitivity === 'critical' || e.port_sensitivity === 'sensitive');
  const hasMalware   = nodeAlerts.some(a => /malware|ransomware|trojan/i.test(a.rule_name || ''));
  const hasC2        = nodeAlerts.some(a => /beacon|c2|cobalt|empire/i.test(a.rule_name || ''));
  const hasLateral   = nodeAlerts.some(a => /lateral|psexec|smb.*exec/i.test(a.rule_name || ''));

  const insights: { sev: 'critical' | 'high' | 'medium' | 'low'; text: string }[] = [];

  if (hasC2)        insights.push({ sev: 'critical', text: `Traffic pattern on ${node.hostname || node.ip} resembles C2 beaconing activity.` });
  if (hasMalware)   insights.push({ sev: 'critical', text: `Malware indicators detected on ${node.hostname || node.ip} — immediate remediation recommended.` });
  if (hasLateral)   insights.push({ sev: 'high',     text: `${node.hostname || node.ip} shows signs of lateral movement via SMB/WMI.` });
  if (criticalCVEs) insights.push({ sev: 'high',     text: `${criticalCVEs} critical CVE${criticalCVEs > 1 ? 's' : ''} present — host may be exploitable.` });
  if (extEdges.length > 5) insights.push({ sev: 'high', text: `Unusually high external connection count (${extEdges.length}) — potential exfiltration risk.` });
  if (node.zone === 'dmz' && nodeAlerts.length > 0) insights.push({ sev: 'high', text: `Internet-exposed host with ${nodeAlerts.length} active alert${nodeAlerts.length !== 1 ? 's' : ''}.` });
  if (highPort.length > 0) insights.push({ sev: 'medium', text: `${highPort.length} sensitive port connection${highPort.length !== 1 ? 's' : ''} observed — verify authorization.` });
  if (insights.length === 0 && nodeAlerts.length === 0) insights.push({ sev: 'low', text: `No anomalous behavior detected. ${node.hostname || node.ip} appears normal.` });
  if (insights.length === 0) insights.push({ sev: 'medium', text: `${nodeAlerts.length} alert${nodeAlerts.length !== 1 ? 's' : ''} detected — review timeline for escalation patterns.` });

  const sevColor = { critical: '#f85149', high: '#fb923c', medium: '#fbbf24', low: 'var(--green)' };

  return (
    <div className="space-y-2">
      <div className="rounded-xl p-3 mb-3" style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
        <div className="flex items-center gap-2 mb-1">
          <Flame className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
          <span className="text-[11px] font-bold" style={{ color: 'var(--accent)' }}>XCloak AI Analysis</span>
        </div>
        <p className="text-[11px]" style={{ color: 'var(--text-2)' }}>
          Behavioral analysis based on {nodeAlerts.length} alerts, {vulns.length} CVEs, {edges.length} connections.
        </p>
      </div>
      {insights.map((ins, i) => (
        <div key={i} className="rounded-xl p-3" style={{ background: 'var(--bg-0)', border: `1px solid ${sevColor[ins.sev]}44` }}>
          <div className="flex items-center gap-1.5 mb-1">
            <span className="h-1.5 w-1.5 rounded-full shrink-0" style={{ background: sevColor[ins.sev] }} />
            <span className="text-[10px] font-bold uppercase tracking-wider" style={{ color: sevColor[ins.sev] }}>{ins.sev}</span>
          </div>
          <p className="text-[11px] leading-relaxed" style={{ color: 'var(--text-1)' }}>{ins.text}</p>
        </div>
      ))}
    </div>
  );
}

// ── Analytics panel ───────────────────────────────────────────────────────────

function AnalyticsPanel({ graph, allAlerts }: { graph: NetworkMapGraph; allAlerts: any[] }) {
  const nodes = graph.nodes;
  const edges = graph.edges;

  const edgeCount = (id: string) => edges.filter(e => e.source === id || e.target === id).length;
  const topTalkers     = [...nodes].sort((a, b) => edgeCount(b.id) - edgeCount(a.id)).slice(0, 5);
  const highestRisk    = [...nodes].filter(n => n.type === 'agent').sort((a, b) => b.risk_score - a.risk_score).slice(0, 5);
  const internetFacing = nodes.filter(n => n.zone === 'dmz');
  const rogueDevices   = nodes.filter(n => n.type === 'agent' && !n.hostname);

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
      {[
        {
          title: 'Top Talkers',
          icon: TrendingUp,
          items: topTalkers.map(n => ({ label: n.hostname || n.ip || n.id, val: `${edgeCount(n.id)} conns` })),
        },
        {
          title: 'Highest Risk',
          icon: ShieldAlert,
          items: highestRisk.map(n => ({ label: n.hostname || n.ip || n.id, val: `${n.risk_score}/100`, warn: n.risk_level === 'critical' || n.risk_level === 'high' })),
        },
        {
          title: 'Internet-Facing',
          icon: Globe,
          items: internetFacing.slice(0, 5).map(n => ({ label: n.hostname || n.ip || n.id, val: n.zone, warn: true })),
        },
        {
          title: 'Rogue Devices',
          icon: AlertTriangle,
          items: rogueDevices.slice(0, 5).map(n => ({ label: n.ip || n.id, val: 'no hostname', warn: true })),
        },
      ].map(({ title, icon: Icon, items }) => (
        <div key={title} className="g-card p-4">
          <div className="flex items-center gap-2 mb-3">
            <Icon className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
            <p className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--text-2)' }}>{title}</p>
          </div>
          {items.length === 0
            ? <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>None detected.</p>
            : <div className="space-y-1.5">
                {items.map((item, i) => (
                  <div key={i} className="flex items-center justify-between gap-2">
                    <span className="mono text-[11px] truncate" style={{ color: 'var(--text-1)' }}>{item.label}</span>
                    <span className="text-[10px] shrink-0" style={{ color: (item as any).warn ? 'var(--orange)' : 'var(--text-3)' }}>{item.val}</span>
                  </div>
                ))}
              </div>
          }
        </div>
      ))}
    </div>
  );
}

// ── Infra node panel ──────────────────────────────────────────────────────────

function InfraPanel({ node, edges }: { node: NetworkMapNode; edges: NetworkMapEdge[] }) {
  const color = INFRA_FILL[node.type] || '#64748b';
  const label = INFRA_LABELS[node.type] || node.type;

  return (
    <div className="space-y-4">
      <div className="rounded-xl p-4 text-center" style={{ background: color + '11', border: `1px solid ${color}44` }}>
        <div className="h-10 w-10 rounded-xl mx-auto mb-2 flex items-center justify-center"
          style={{ background: color + '22', border: `1px solid ${color}66` }}>
          <span className="text-lg font-bold" style={{ color }}>{node.hostname?.slice(0, 2).toUpperCase()}</span>
        </div>
        <p className="text-sm font-bold" style={{ color: 'var(--text-1)' }}>{node.hostname}</p>
        <p className="text-[11px] mt-0.5" style={{ color }}>{label}</p>
        {node.role && node.role !== label && (
          <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{node.role}</p>
        )}
      </div>

      <div className="grid grid-cols-2 gap-2">
        {[
          { label: 'IP Address', val: node.ip || '—' },
          { label: 'Zone',       val: node.zone },
          { label: 'VLAN',       val: node.vlan || '—' },
          { label: 'Status',     val: node.status || 'online' },
        ].map(({ label: l, val }) => (
          <div key={l} className="rounded-xl p-3" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
            <p className="text-[10px] mb-0.5" style={{ color: 'var(--text-3)' }}>{l}</p>
            <p className="text-xs mono font-medium" style={{ color: 'var(--text-1)' }}>{val}</p>
          </div>
        ))}
      </div>

      {edges.length > 0 && (
        <div>
          <p className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>
            Connections ({edges.length})
          </p>
          <div className="space-y-1.5">
            {edges.slice(0, 8).map((e, i) => (
              <div key={i} className="rounded-lg p-2.5 text-xs"
                style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                <div className="flex items-center justify-between gap-2">
                  <span className="mono truncate" style={{ color: 'var(--text-1)' }}>
                    {e.source === node.id ? '→' : '←'} {e.process || 'unknown'}
                  </span>
                  <PortBadge e={e} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function NetworkMapPage() {
  const graphRef     = useRef<any>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dims, setDims] = useState({ width: 900, height: 580 });

  const [graph, setGraph]               = useState<NetworkMapGraph | null>(null);
  const [loading, setLoading]           = useState(true);
  const [refreshing, setRefreshing]     = useState(false);
  const [sinceMinutes, setSinceMinutes] = useState(60);
  const [zoneFilter, setZoneFilter]     = useState('all');
  const [search, setSearch]             = useState('');
  const [selected, setSelected]         = useState<NetworkMapNode | null>(null);
  const [showOffline, setShowOffline]   = useState(true);
  const [zoneColors, setZoneColors]     = useState<Record<string, string>>({});
  const [enrichMap, setEnrichMap]       = useState<Map<string, string>>(new Map());

  // Agent node drawer data
  const [nodeTab, setNodeTab]           = useState('overview');
  const [nodeVulns, setNodeVulns]       = useState<any[]>([]);
  const [nodeProcesses, setNodeProcesses] = useState<any[]>([]);
  const [nodeTimeline, setNodeTimeline] = useState<any[]>([]);
  const [allAlerts, setAllAlerts]       = useState<any[]>([]);
  const [nodeLoading, setNodeLoading]   = useState(false);

  // Enhanced features state
  const [viewMode, setViewMode]             = useState<ViewMode>('Physical');
  const [threatOverlay, setThreatOverlay]   = useState('');
  const [showThreatMenu, setShowThreatMenu] = useState(false);
  const [showFilters, setShowFilters]       = useState(false);
  const [filterVlan, setFilterVlan]         = useState('');
  const [filterType, setFilterType]         = useState('');
  const [filterRisk, setFilterRisk]         = useState('');
  const [incidentMode, setIncidentMode]     = useState(false);
  const [showAnalytics, setShowAnalytics]   = useState(false);
  const [selectedEdge, setSelectedEdge]     = useState<NetworkMapEdge | null>(null);
  const [toast, setToast]                   = useState<string | null>(null);
  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  // Portal menu button refs + positions
  const filterBtnRef  = useRef<HTMLButtonElement>(null);
  const overlayBtnRef = useRef<HTMLButtonElement>(null);
  const [filterMenuPos,  setFilterMenuPos]  = useState({ top: 0, left: 0 });
  const [overlayMenuPos, setOverlayMenuPos] = useState({ top: 0, left: 0 });

  const openFilterMenu = () => {
    if (filterBtnRef.current) {
      const r = filterBtnRef.current.getBoundingClientRect();
      setFilterMenuPos({ top: r.bottom + 6, left: r.left });
    }
    setShowFilters(v => !v);
  };
  const openOverlayMenu = () => {
    if (overlayBtnRef.current) {
      const r = overlayBtnRef.current.getBoundingClientRect();
      setOverlayMenuPos({ top: r.bottom + 6, left: r.left });
    }
    setShowThreatMenu(v => !v);
  };

  // Close menus on outside click
  useEffect(() => {
    if (!showFilters && !showThreatMenu) return;
    const handler = (e: MouseEvent) => {
      if (filterBtnRef.current && !filterBtnRef.current.contains(e.target as Node)) setShowFilters(false);
      if (overlayBtnRef.current && !overlayBtnRef.current.contains(e.target as Node)) setShowThreatMenu(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [showFilters, showThreatMenu]);

  // Threat-colored agent IDs for overlay
  const threatNodeIds = useMemo(() => {
    if (!threatOverlay || !graph) return new Set<number>();
    const overlay = THREAT_OVERLAYS.find(o => o.id === threatOverlay);
    if (!overlay) return new Set<number>();
    const ids = new Set<number>();
    allAlerts.forEach(a => { if (overlay.pattern.test(a.rule_name || '')) ids.add(a.agent_id); });
    return ids;
  }, [threatOverlay, allAlerts, graph]);

  // Measure canvas
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const obs = new ResizeObserver(entries => {
      const { width } = entries[0].contentRect;
      if (width > 0) setDims({ width, height: 580 });
    });
    obs.observe(el);
    return () => obs.disconnect();
  }, []);

  useEffect(() => {
    setZoneColors({
      internal: resolveVar('--border-md'),
      dmz:      resolveVar('--orange'),
      external: resolveVar('--text-3'),
    });
  }, []);

  const load = useCallback(async (minutes: number, spin = false) => {
    if (spin) setRefreshing(true);
    setLoading(true);
    try {
      const [mapRes, alertRes] = await Promise.allSettled([
        networkMapAPI.get(minutes),
        alertsAPI.getAll(),
      ]);
      if (mapRes.status   === 'fulfilled') setGraph(mapRes.value.data);
      if (alertRes.status === 'fulfilled') setAllAlerts(alertRes.value.data || []);
    } catch { setGraph(null); }
    finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => { load(sinceMinutes); }, [load, sinceMinutes]);

  // Proactive enrichment for external IP nodes
  useEffect(() => {
    if (!selected || selected.type !== 'external_ip' || !selected.ip) return;
    const ip = selected.ip;
    if (enrichMap.has(ip)) return;
    networkMapAPI.getIPInfo(ip)
      .then(r => {
        const level: string = r.data?.threat_level || 'none';
        setEnrichMap(prev => new Map(prev).set(ip, level));
      })
      .catch(() => {});
  }, [selected, enrichMap]);

  // Load agent detail data when an agent node is selected
  useEffect(() => {
    if (!selected || selected.type !== 'agent' || !selected.agent_id) {
      setNodeVulns([]); setNodeProcesses([]); setNodeTimeline([]);
      return;
    }
    setNodeTab('overview');
    setNodeLoading(true);
    const id = selected.agent_id as number;
    Promise.allSettled([
      agentsAPI.getVulnerabilities(id),
      agentsAPI.getProcesses(id),
      agentsAPI.getTimeline(id),
    ]).then(([vr, pr, tr]) => {
      if (vr.status === 'fulfilled') setNodeVulns(vr.value.data || []);
      if (pr.status === 'fulfilled') setNodeProcesses(pr.value.data || []);
      if (tr.status === 'fulfilled') setNodeTimeline(tr.value.data || []);
    }).finally(() => setNodeLoading(false));
  }, [selected?.id]);

  const filteredNodeIds = useMemo(() => {
    if (!graph) return new Set<string>();
    const q = search.trim().toLowerCase();
    const ids = new Set<string>();
    for (const n of graph.nodes) {
      if (zoneFilter !== 'all' && n.zone !== zoneFilter) continue;
      if (!showOffline && n.type === 'agent' && n.status === 'offline') continue;
      if (filterVlan && n.vlan !== filterVlan) continue;
      if (filterType && n.type !== filterType) continue;
      if (filterRisk && n.risk_level !== filterRisk) continue;
      // View mode filters
      if (viewMode === 'Cloud' && n.type !== 'cloud' && n.type !== 'external_ip') continue;
      if (viewMode === 'Security' && (n.type as string) === 'container') continue;
      if (q && !`${n.hostname || ''} ${n.ip || ''} ${n.role || ''} ${n.vlan || ''}`.toLowerCase().includes(q)) continue;
      if (n.type === 'external_ip' && n.ip) {
        const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(n.ip);
        const ipv6 = n.ip.includes(':') && /^[0-9a-fA-F:]+$/.test(n.ip);
        if (!ipv4 && !ipv6) continue;
      }
      ids.add(n.id);
    }
    return ids;
  }, [graph, zoneFilter, search, showOffline, filterVlan, filterType, filterRisk, viewMode]);

  const data = useMemo(() => {
    if (!graph) return { nodes: [], links: [] };
    const INFRA_TYPES = new Set([
      'firewall','router','switch','vpn','wireless','cloud','wan',
      'internet_gateway','dmz','load_balancer','reverse_proxy','dns_server',
      'dhcp_server','hypervisor','storage','iot','ot_ics','kubernetes',
      'container','vm','sdwan','vpn_site',
    ]);
    const nodes: GNode[] = graph.nodes
      .filter(n => filteredNodeIds.has(n.id))
      .map(n => ({
        ...n,
        val: INFRA_TYPES.has(n.type) ? 5 : n.type === 'agent' ? 6 + n.risk_score / 20 : 4,
      }));
    const nodeSet = new Set(nodes.map(n => n.id));
    const links = graph.edges.filter(e => nodeSet.has(e.source) && nodeSet.has(e.target));
    return { nodes, links };
  }, [graph, filteredNodeIds]);

  const edgesForSelected = useMemo(() => {
    if (!graph || !selected) return [];
    return graph.edges.filter(e => e.source === selected.id || e.target === selected.id);
  }, [graph, selected]);

  // ── Drawing ──────────────────────────────────────────────────────────────────

  const nodeColor = useCallback((n: any): string => {
    if (n.type === 'external_ip') {
      if (n.is_ioc) return THREAT_FILL[n.ioc_severity] || '#e879f9';
      const enriched = enrichMap.get(n.ip);
      if (enriched && enriched !== 'none') return THREAT_FILL[enriched] || '#64748b';
      return '#64748b';
    }
    if (INFRA_FILL[n.type]) return INFRA_FILL[n.type];
    // Threat overlay
    if (threatOverlay && n.agent_id && threatNodeIds.has(n.agent_id)) {
      const overlay = THREAT_OVERLAYS.find(o => o.id === threatOverlay);
      if (overlay) return overlay.color;
    }
    // Incident mode — dim non-alerting nodes
    if (incidentMode && n.type === 'agent' && n.alert_count === 0) return '#64748b44';
    const fill = RISK_FILL[n.risk_level] || RISK_FILL.unknown;
    return n.status === 'offline' ? fill + '55' : fill;
  }, [enrichMap, threatOverlay, threatNodeIds, incidentMode]);

  const linkColor = (l: any): string => {
    if (l.edge_type === 'internal') return 'rgba(99,179,237,0.45)';
    const s = l.port_sensitivity;
    if (s === 'critical')  return 'rgba(248,81,73,0.6)';
    if (s === 'sensitive') return 'rgba(251,146,60,0.5)';
    if (s === 'safe')      return 'rgba(74,222,128,0.4)';
    return 'rgba(148,163,184,0.3)';
  };

  const drawNode = useCallback((n: any, ctx: CanvasRenderingContext2D) => {
    const isAgent = n.type === 'agent';
    const isExt   = n.type === 'external_ip';
    const r       = Math.max(4, n.val || 4);
    const fill    = nodeColor(n);
    const ring    = zoneColors[n.zone] || '#64748b';
    const offline = n.status === 'offline';

    if (isAgent) {
      // Glow for high/critical risk online agents
      if (!offline && (n.risk_level === 'critical' || n.risk_level === 'high')) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, r + 6, 0, 2 * Math.PI);
        ctx.fillStyle = fill + '22';
        ctx.fill();
      }
      // Main circle
      ctx.beginPath();
      ctx.arc(n.x, n.y, r, 0, 2 * Math.PI);
      ctx.fillStyle = offline ? fill + '44' : fill;
      ctx.fill();
      // Zone ring
      if (offline) ctx.setLineDash([3, 3]);
      ctx.beginPath();
      ctx.arc(n.x, n.y, r + 2, 0, 2 * Math.PI);
      ctx.strokeStyle = offline ? ring + '55' : ring;
      ctx.lineWidth = n.zone === 'dmz' ? 2.5 : 1.5;
      ctx.stroke();
      ctx.setLineDash([]);
      // Alert badge
      if (n.alert_count > 0) {
        ctx.beginPath();
        ctx.arc(n.x + (r + 2) * 0.72, n.y - (r + 2) * 0.72, 3.5, 0, 2 * Math.PI);
        ctx.fillStyle = '#f85149';
        ctx.fill();
        ctx.beginPath();
        ctx.arc(n.x + (r + 2) * 0.72, n.y - (r + 2) * 0.72, 3.5, 0, 2 * Math.PI);
        ctx.strokeStyle = 'rgba(0,0,0,0.5)';
        ctx.lineWidth = 0.8;
        ctx.stroke();
      }
      // Hostname label
      const label    = n.hostname ? (n.hostname.length > 16 ? n.hostname.slice(0, 14) + '…' : n.hostname) : (n.ip || n.id);
      const fontSize = Math.max(6, Math.min(r * 0.95, 9));
      ctx.font = `600 ${fontSize}px sans-serif`;
      const tw = ctx.measureText(label).width;
      const ly = n.y + r + 4;
      const pad = 3;
      ctx.fillStyle = 'rgba(15,23,42,0.72)';
      ctx.beginPath();
      const bx = n.x - tw / 2 - pad;
      const bw = tw + pad * 2;
      const bh = fontSize + pad * 1.5;
      const br = 3;
      ctx.moveTo(bx + br, ly); ctx.lineTo(bx + bw - br, ly);
      ctx.arcTo(bx + bw, ly, bx + bw, ly + bh, br); ctx.lineTo(bx + bw, ly + bh - br);
      ctx.arcTo(bx + bw, ly + bh, bx + bw - br, ly + bh, br); ctx.lineTo(bx + br, ly + bh);
      ctx.arcTo(bx, ly + bh, bx, ly + bh - br, br); ctx.lineTo(bx, ly + br);
      ctx.arcTo(bx, ly, bx + br, ly, br); ctx.closePath();
      ctx.fill();
      ctx.textAlign = 'center'; ctx.textBaseline = 'top';
      ctx.fillStyle = offline ? 'rgba(148,163,184,0.5)' : 'rgba(226,232,240,0.95)';
      ctx.fillText(label, n.x, ly + pad * 0.75);

    } else if (isExt) {
      const threat  = n.is_ioc || (n.ip && enrichMap.get(n.ip) && enrichMap.get(n.ip) !== 'none');
      const dr      = r + (threat ? 2 : 0);
      if (threat) {
        ctx.beginPath();
        ctx.moveTo(n.x, n.y - dr - 5); ctx.lineTo(n.x + dr + 5, n.y);
        ctx.lineTo(n.x, n.y + dr + 5); ctx.lineTo(n.x - dr - 5, n.y);
        ctx.closePath(); ctx.fillStyle = fill + '30'; ctx.fill();
      }
      ctx.beginPath();
      ctx.moveTo(n.x, n.y - dr); ctx.lineTo(n.x + dr, n.y);
      ctx.lineTo(n.x, n.y + dr); ctx.lineTo(n.x - dr, n.y);
      ctx.closePath(); ctx.fillStyle = fill + (threat ? 'cc' : '99'); ctx.fill();
      ctx.beginPath();
      ctx.moveTo(n.x, n.y - dr); ctx.lineTo(n.x + dr, n.y);
      ctx.lineTo(n.x, n.y + dr); ctx.lineTo(n.x - dr, n.y);
      ctx.closePath();
      ctx.strokeStyle = threat ? fill : (ring + '88');
      ctx.lineWidth   = threat ? 1.5 : 0.8; ctx.stroke();
      if (n.is_ioc) {
        ctx.beginPath();
        ctx.arc(n.x + dr * 0.65, n.y - dr * 0.65, 2.5, 0, 2 * Math.PI);
        ctx.fillStyle = '#e879f9'; ctx.fill();
      }
      if (threat && n.ip) {
        const parts  = (n.ip as string).split('.');
        const abbrev = parts.length === 4 ? `${parts[0]}.*.${parts[3]}` : (n.ip.length > 12 ? n.ip.slice(0, 10) + '…' : n.ip);
        ctx.font = `500 ${Math.max(5, dr * 0.85)}px sans-serif`;
        ctx.textAlign = 'center'; ctx.textBaseline = 'top';
        ctx.fillStyle = fill; ctx.fillText(abbrev, n.x, n.y + dr + 2);
      }

    } else {
      // ── Infrastructure nodes ────────────────────────────────────────────────
      const infraFill = INFRA_FILL[n.type] || '#64748b';

      if (n.type === 'firewall') {
        // Upward-pointing pentagon (shield-like)
        const s = r + 1;
        ctx.beginPath();
        ctx.moveTo(n.x, n.y - s * 1.15);
        ctx.lineTo(n.x + s, n.y - s * 0.3);
        ctx.lineTo(n.x + s * 0.65, n.y + s * 0.95);
        ctx.lineTo(n.x - s * 0.65, n.y + s * 0.95);
        ctx.lineTo(n.x - s, n.y - s * 0.3);
        ctx.closePath();
        ctx.fillStyle = infraFill + 'cc'; ctx.fill();
        ctx.strokeStyle = infraFill; ctx.lineWidth = 1.5; ctx.stroke();

      } else if (n.type === 'router') {
        // Triangle
        const s = r + 1;
        ctx.beginPath();
        ctx.moveTo(n.x, n.y - s * 1.2);
        ctx.lineTo(n.x + s * 1.1, n.y + s * 0.8);
        ctx.lineTo(n.x - s * 1.1, n.y + s * 0.8);
        ctx.closePath();
        ctx.fillStyle = infraFill + 'cc'; ctx.fill();
        ctx.strokeStyle = infraFill; ctx.lineWidth = 1.5; ctx.stroke();

      } else if (n.type === 'switch') {
        // Rectangle
        const w = r * 2.2; const h = r * 1.2;
        ctx.beginPath();
        ctx.roundRect(n.x - w / 2, n.y - h / 2, w, h, 3);
        ctx.fillStyle = infraFill + 'cc'; ctx.fill();
        ctx.strokeStyle = infraFill; ctx.lineWidth = 1.5; ctx.stroke();
        // Port dots
        for (let i = 0; i < 4; i++) {
          ctx.beginPath();
          ctx.rect(n.x - w * 0.35 + i * (w * 0.22), n.y + h * 0.05, 3, 2.5);
          ctx.fillStyle = 'rgba(255,255,255,0.6)'; ctx.fill();
        }

      } else if (n.type === 'vpn') {
        // Circle with dashed ring
        ctx.beginPath();
        ctx.arc(n.x, n.y, r, 0, 2 * Math.PI);
        ctx.fillStyle = infraFill + 'bb'; ctx.fill();
        ctx.setLineDash([2.5, 2]);
        ctx.beginPath();
        ctx.arc(n.x, n.y, r + 3, 0, 2 * Math.PI);
        ctx.strokeStyle = infraFill; ctx.lineWidth = 1.5; ctx.stroke();
        ctx.setLineDash([]);
        // Lock icon center
        ctx.fillStyle = 'rgba(255,255,255,0.7)';
        ctx.beginPath(); ctx.arc(n.x, n.y - 1, 2, 0, 2 * Math.PI); ctx.fill();
        ctx.fillStyle = 'rgba(255,255,255,0.5)';
        ctx.fillRect(n.x - 2.5, n.y, 5, 3.5);

      } else if (n.type === 'wireless') {
        // Circle with arc waves
        ctx.beginPath();
        ctx.arc(n.x, n.y, r, 0, 2 * Math.PI);
        ctx.fillStyle = infraFill + 'bb'; ctx.fill();
        ctx.strokeStyle = infraFill; ctx.lineWidth = 1; ctx.stroke();
        // Arcs above
        for (let i = 1; i <= 2; i++) {
          ctx.beginPath();
          ctx.arc(n.x, n.y + r * 0.3, r * 0.5 * i, Math.PI, 0);
          ctx.strokeStyle = infraFill + (i === 1 ? 'cc' : '77');
          ctx.lineWidth = 1.2; ctx.stroke();
        }

      } else if (n.type === 'cloud') {
        // Rounded cloud shape
        const cw = r * 2.8; const ch = r * 1.6;
        ctx.beginPath();
        ctx.ellipse(n.x, n.y + ch * 0.1, cw / 2, ch / 2, 0, 0, 2 * Math.PI);
        ctx.fillStyle = infraFill + 'aa'; ctx.fill();
        // Bumps on top
        for (const [dx, dy, rr] of [[-cw * 0.28, -ch * 0.1, r * 0.8], [0, -ch * 0.22, r * 1.0], [cw * 0.28, -ch * 0.1, r * 0.75]] as [number, number, number][]) {
          ctx.beginPath();
          ctx.arc(n.x + dx, n.y + dy, rr, 0, 2 * Math.PI);
          ctx.fillStyle = infraFill + 'aa'; ctx.fill();
        }
        ctx.strokeStyle = infraFill; ctx.lineWidth = 1; ctx.stroke();

      } else if (n.type === 'wan') {
        const dr = r + 2;
        ctx.beginPath();
        ctx.moveTo(n.x, n.y - dr * 1.2); ctx.lineTo(n.x + dr * 1.0, n.y);
        ctx.lineTo(n.x, n.y + dr * 1.2); ctx.lineTo(n.x - dr * 1.0, n.y);
        ctx.closePath();
        ctx.fillStyle = infraFill + '99'; ctx.fill();
        ctx.strokeStyle = infraFill; ctx.lineWidth = 1.5; ctx.stroke();

      } else if (n.type === 'internet_gateway') {
        // Circle with 4 radiating lines
        ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, 2 * Math.PI);
        ctx.fillStyle = infraFill + 'cc'; ctx.fill();
        ctx.strokeStyle = infraFill; ctx.lineWidth = 1.5; ctx.stroke();
        for (let i = 0; i < 4; i++) {
          const angle = (i * Math.PI) / 2;
          ctx.beginPath();
          ctx.moveTo(n.x + Math.cos(angle) * (r + 1), n.y + Math.sin(angle) * (r + 1));
          ctx.lineTo(n.x + Math.cos(angle) * (r + 5), n.y + Math.sin(angle) * (r + 5));
          ctx.strokeStyle = infraFill + 'cc'; ctx.lineWidth = 2; ctx.stroke();
        }

      } else if (n.type === 'load_balancer') {
        // Wide ellipse
        ctx.beginPath(); ctx.ellipse(n.x, n.y, r * 2, r * 0.7, 0, 0, 2 * Math.PI);
        ctx.fillStyle = infraFill + 'cc'; ctx.fill();
        ctx.strokeStyle = infraFill; ctx.lineWidth = 1.5; ctx.stroke();
        // 3 horizontal lines
        for (let i = -1; i <= 1; i++) {
          ctx.beginPath();
          ctx.moveTo(n.x - r * 1.2, n.y + i * r * 0.22);
          ctx.lineTo(n.x + r * 1.2, n.y + i * r * 0.22);
          ctx.strokeStyle = 'rgba(255,255,255,0.4)'; ctx.lineWidth = 0.8; ctx.stroke();
        }

      } else if (n.type === 'dmz') {
        // Octagon
        const s2 = r + 1; const a = s2 * 0.4;
        ctx.beginPath();
        ctx.moveTo(n.x - a, n.y - s2); ctx.lineTo(n.x + a, n.y - s2);
        ctx.lineTo(n.x + s2, n.y - a); ctx.lineTo(n.x + s2, n.y + a);
        ctx.lineTo(n.x + a, n.y + s2); ctx.lineTo(n.x - a, n.y + s2);
        ctx.lineTo(n.x - s2, n.y + a); ctx.lineTo(n.x - s2, n.y - a);
        ctx.closePath();
        ctx.fillStyle = infraFill + 'bb'; ctx.fill();
        ctx.strokeStyle = infraFill; ctx.lineWidth = 1.5; ctx.stroke();

      } else if (n.type === 'dns_server') {
        // Circle with inner ring
        ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, 2 * Math.PI);
        ctx.fillStyle = infraFill + 'cc'; ctx.fill();
        ctx.strokeStyle = infraFill; ctx.lineWidth = 1.5; ctx.stroke();
        ctx.beginPath(); ctx.arc(n.x, n.y, r * 0.5, 0, 2 * Math.PI);
        ctx.strokeStyle = 'rgba(255,255,255,0.5)'; ctx.lineWidth = 1; ctx.stroke();

      } else if (n.type === 'dhcp_server') {
        // Rounded rect with IP label feel
        const w2 = r * 2; const h2 = r * 1.3;
        ctx.beginPath(); ctx.roundRect(n.x - w2 / 2, n.y - h2 / 2, w2, h2, 4);
        ctx.fillStyle = infraFill + 'cc'; ctx.fill();
        ctx.strokeStyle = infraFill; ctx.lineWidth = 1.5; ctx.stroke();

      } else if (n.type === 'hypervisor') {
        // Two stacked rectangles
        const w2 = r * 2; const h2 = r * 0.65;
        for (let i = 0; i < 2; i++) {
          ctx.beginPath();
          ctx.roundRect(n.x - w2 / 2 + i * 2, n.y - h2 - i * (h2 + 2), w2, h2, 3);
          ctx.fillStyle = infraFill + (i === 0 ? 'aa' : 'cc'); ctx.fill();
          ctx.strokeStyle = infraFill; ctx.lineWidth = 1; ctx.stroke();
        }

      } else if (n.type === 'storage') {
        // Cylinder: ellipse top + rect body + ellipse bottom
        const cw = r * 1.4; const cy = r * 0.35;
        ctx.beginPath(); ctx.ellipse(n.x, n.y - r * 0.65, cw, cy, 0, 0, 2 * Math.PI);
        ctx.fillStyle = infraFill + 'cc'; ctx.fill(); ctx.strokeStyle = infraFill; ctx.lineWidth = 1; ctx.stroke();
        ctx.fillRect(n.x - cw, n.y - r * 0.65, cw * 2, r * 1.3);
        ctx.strokeRect(n.x - cw, n.y - r * 0.65, cw * 2, r * 1.3);
        ctx.beginPath(); ctx.ellipse(n.x, n.y + r * 0.65, cw, cy, 0, 0, 2 * Math.PI);
        ctx.fillStyle = infraFill + 'dd'; ctx.fill(); ctx.strokeStyle = infraFill; ctx.lineWidth = 1; ctx.stroke();

      } else if (n.type === 'iot') {
        // Small circle with 1 radio arc
        ctx.beginPath(); ctx.arc(n.x, n.y, r * 0.8, 0, 2 * Math.PI);
        ctx.fillStyle = infraFill + 'cc'; ctx.fill(); ctx.strokeStyle = infraFill; ctx.lineWidth = 1; ctx.stroke();
        ctx.beginPath(); ctx.arc(n.x, n.y + r * 0.3, r * 1.3, Math.PI, 0);
        ctx.strokeStyle = infraFill + '88'; ctx.lineWidth = 1.2; ctx.stroke();

      } else if (n.type === 'ot_ics') {
        // Hexagon
        const s3 = r + 1;
        ctx.beginPath();
        for (let i = 0; i < 6; i++) {
          const ang = (i * Math.PI) / 3 - Math.PI / 6;
          i === 0 ? ctx.moveTo(n.x + s3 * Math.cos(ang), n.y + s3 * Math.sin(ang))
                  : ctx.lineTo(n.x + s3 * Math.cos(ang), n.y + s3 * Math.sin(ang));
        }
        ctx.closePath();
        ctx.fillStyle = infraFill + 'cc'; ctx.fill(); ctx.strokeStyle = infraFill; ctx.lineWidth = 1.5; ctx.stroke();

      } else if (n.type === 'kubernetes') {
        // Hexagon with spokes
        const s4 = r + 1;
        ctx.beginPath();
        for (let i = 0; i < 6; i++) {
          const ang = (i * Math.PI) / 3;
          i === 0 ? ctx.moveTo(n.x + s4 * Math.cos(ang), n.y + s4 * Math.sin(ang))
                  : ctx.lineTo(n.x + s4 * Math.cos(ang), n.y + s4 * Math.sin(ang));
        }
        ctx.closePath();
        ctx.fillStyle = infraFill + 'cc'; ctx.fill(); ctx.strokeStyle = infraFill; ctx.lineWidth = 1.5; ctx.stroke();
        for (let i = 0; i < 6; i++) {
          const ang = (i * Math.PI) / 3;
          ctx.beginPath(); ctx.moveTo(n.x, n.y);
          ctx.lineTo(n.x + s4 * 0.55 * Math.cos(ang), n.y + s4 * 0.55 * Math.sin(ang));
          ctx.strokeStyle = 'rgba(255,255,255,0.5)'; ctx.lineWidth = 0.8; ctx.stroke();
        }

      } else if (n.type === 'container') {
        // Small cube
        const cs = r * 0.9;
        ctx.beginPath(); ctx.roundRect(n.x - cs, n.y - cs, cs * 2, cs * 2, 3);
        ctx.fillStyle = infraFill + 'cc'; ctx.fill(); ctx.strokeStyle = infraFill; ctx.lineWidth = 1.5; ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(n.x - cs, n.y - cs * 0.3); ctx.lineTo(n.x + cs, n.y - cs * 0.3);
        ctx.moveTo(n.x - cs, n.y + cs * 0.3); ctx.lineTo(n.x + cs, n.y + cs * 0.3);
        ctx.strokeStyle = 'rgba(255,255,255,0.3)'; ctx.lineWidth = 0.7; ctx.stroke();

      } else if (n.type === 'vm') {
        // Dashed rounded rect
        const vm_w = r * 2; const vm_h = r * 1.5;
        ctx.setLineDash([2, 2]);
        ctx.beginPath(); ctx.roundRect(n.x - vm_w / 2, n.y - vm_h / 2, vm_w, vm_h, 4);
        ctx.fillStyle = infraFill + 'aa'; ctx.fill(); ctx.strokeStyle = infraFill; ctx.lineWidth = 1.5; ctx.stroke();
        ctx.setLineDash([]);

      } else if (n.type === 'reverse_proxy') {
        // Rectangle with arrow
        const rw = r * 2; const rh = r * 1.2;
        ctx.beginPath(); ctx.roundRect(n.x - rw / 2, n.y - rh / 2, rw, rh, 4);
        ctx.fillStyle = infraFill + 'cc'; ctx.fill(); ctx.strokeStyle = infraFill; ctx.lineWidth = 1.5; ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(n.x - r * 0.6, n.y); ctx.lineTo(n.x + r * 0.6, n.y);
        ctx.moveTo(n.x + r * 0.2, n.y - r * 0.35); ctx.lineTo(n.x + r * 0.6, n.y); ctx.lineTo(n.x + r * 0.2, n.y + r * 0.35);
        ctx.strokeStyle = 'rgba(255,255,255,0.65)'; ctx.lineWidth = 1.2; ctx.stroke();

      } else if (n.type === 'sdwan' || n.type === 'vpn_site') {
        // Two circles connected
        const offset = r * 0.8;
        for (const dx of [-offset, offset]) {
          ctx.beginPath(); ctx.arc(n.x + dx, n.y, r * 0.7, 0, 2 * Math.PI);
          ctx.fillStyle = infraFill + 'bb'; ctx.fill(); ctx.strokeStyle = infraFill; ctx.lineWidth = 1; ctx.stroke();
        }
        ctx.beginPath(); ctx.moveTo(n.x - offset + r * 0.7, n.y); ctx.lineTo(n.x + offset - r * 0.7, n.y);
        ctx.strokeStyle = infraFill; ctx.lineWidth = 1.5; ctx.stroke();
        if (n.type === 'vpn_site') {
          ctx.setLineDash([2, 2]);
          ctx.beginPath(); ctx.moveTo(n.x - offset + r * 0.7, n.y); ctx.lineTo(n.x + offset - r * 0.7, n.y);
          ctx.strokeStyle = 'rgba(255,255,255,0.5)'; ctx.lineWidth = 1; ctx.stroke();
          ctx.setLineDash([]);
        }
      }

      // Label for all infra types
      const lbl      = n.hostname ? (n.hostname.length > 14 ? n.hostname.slice(0, 12) + '…' : n.hostname) : n.type;
      const fontSize = 7;
      ctx.font       = `500 ${fontSize}px sans-serif`;
      ctx.textAlign    = 'center';
      ctx.textBaseline = 'top';
      ctx.fillStyle  = 'rgba(226,232,240,0.85)';
      ctx.fillText(lbl, n.x, n.y + r + 4);
    }
  }, [zoneColors, nodeColor, enrichMap]);

  const exportPNG = () => {
    const canvas = containerRef.current?.querySelector('canvas');
    if (!canvas) return;
    const url = (canvas as HTMLCanvasElement).toDataURL('image/png');
    const a = document.createElement('a'); a.href = url; a.download = `network-map-${Date.now()}.png`; a.click();
  };
  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `network-map-${Date.now()}.json`; a.click();
    URL.revokeObjectURL(url);
  };
  const exportCSV = () => {
    const header = 'id,hostname,ip,type,zone,vlan,risk_level,risk_score,alert_count,status\n';
    const rows = data.nodes.map(n =>
      `${n.id},"${n.hostname||''}","${n.ip||''}",${n.type},${n.zone},${n.vlan||''},${n.risk_level},${n.risk_score},${n.alert_count||0},${n.status||'online'}`
    ).join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `network-map-${Date.now()}.csv`; a.click();
    URL.revokeObjectURL(url);
  };

  const activeFilters = (filterVlan ? 1 : 0) + (filterType ? 1 : 0) + (filterRisk ? 1 : 0);
  const vlans = graph ? [...new Set(graph.nodes.map(n => n.vlan).filter(Boolean))] as string[] : [];
  const types = graph ? [...new Set(graph.nodes.map(n => n.type))] : [];

  const s = graph?.summary as any;
  const infraCount = s?.infra_devices ?? 0;

  return (
    <RootLayout title="Network Map"
      subtitle="Fleet topology · live threat enrichment · infrastructure visualization"
      onRefresh={() => load(sinceMinutes, true)} refreshing={refreshing}>

      <div className="space-y-4">

        {/* Toast */}
        {toast && (
          <div className="fixed bottom-5 right-5 z-[9999] g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)' }}>
            {toast}
          </div>
        )}

        {/* Edge flow detail modal */}
        {selectedEdge && (
          <div className="fixed inset-0 z-[9998] flex items-center justify-center" onClick={() => setSelectedEdge(null)}>
            <div className="w-full max-w-sm rounded-2xl p-5 space-y-3" onClick={e => e.stopPropagation()}
              style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', boxShadow: '0 20px 60px rgba(0,0,0,0.5)' }}>
              <div className="flex items-center justify-between">
                <p className="text-sm font-bold" style={{ color: 'var(--text-1)' }}>Network Flow</p>
                <button onClick={() => setSelectedEdge(null)} style={{ color: 'var(--text-3)' }}><X className="h-4 w-4" /></button>
              </div>
              {[
                { label: 'Source',    val: selectedEdge.source },
                { label: 'Target',    val: selectedEdge.target },
                { label: 'Port',      val: selectedEdge.port },
                { label: 'Protocol',  val: selectedEdge.protocol.toUpperCase() },
                { label: 'Service',   val: selectedEdge.service || '—' },
                { label: 'Process',   val: selectedEdge.process || '—' },
                { label: 'Sessions',  val: String(selectedEdge.count) },
                { label: 'Edge Type', val: selectedEdge.edge_type },
                { label: 'Risk',      val: selectedEdge.port_sensitivity || 'neutral' },
                { label: 'Last Seen', val: new Date(selectedEdge.last_seen).toLocaleString() },
              ].map(({ label, val }) => (
                <div key={label} className="flex items-center justify-between px-3 py-2 rounded-lg"
                  style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                  <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{label}</span>
                  <span className="mono text-[11px] font-medium" style={{ color: 'var(--text-1)' }}>{val}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* toolbar */}
        <div className="g-panel p-3 space-y-2">
          {/* Row 1 */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Search */}
            <div className="relative flex-1 min-w-[160px] max-w-xs">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
              <input value={search} onChange={e => setSearch(e.target.value)}
                placeholder="Search hostname, IP, VLAN…" className="g-input pl-8 text-xs" />
            </div>

            {/* Filters */}
            <button ref={filterBtnRef} type="button" onClick={openFilterMenu}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs transition-all"
              style={{
                background: showFilters || activeFilters > 0 ? 'var(--accent-glow)' : 'var(--glass-bg)',
                border: `1px solid ${showFilters || activeFilters > 0 ? 'var(--accent-border)' : 'var(--border)'}`,
                color: showFilters || activeFilters > 0 ? 'var(--accent)' : 'var(--text-2)',
              }}>
              <Filter className="h-3.5 w-3.5" />
              Filters
              {activeFilters > 0 && (
                <span className="flex h-4 w-4 items-center justify-center rounded-full text-[9px] font-bold"
                  style={{ background: 'var(--accent)', color: '#fff' }}>{activeFilters}</span>
              )}
            </button>
            {showFilters && typeof document !== 'undefined' && createPortal(
              <div onMouseDown={e => e.stopPropagation()} style={{
                position: 'fixed', top: filterMenuPos.top, left: filterMenuPos.left,
                zIndex: 99990, width: 280,
                background: 'var(--bg-1)', border: '1px solid var(--border)',
                borderRadius: 14, padding: 16, boxShadow: '0 20px 48px rgba(0,0,0,0.55)',
              }}>
                <p className="text-xs font-bold mb-3" style={{ color: 'var(--text-1)' }}>Filters</p>
                <div className="space-y-3">
                  <div>
                    <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>Zone</p>
                    <select value={zoneFilter} onChange={e => setZoneFilter(e.target.value)} className="g-select w-full text-xs">
                      <option value="all">All zones</option>
                      <option value="internal">Internal</option>
                      <option value="dmz">DMZ</option>
                      <option value="external">External</option>
                    </select>
                  </div>
                  {vlans.length > 0 && (
                    <div>
                      <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>VLAN</p>
                      <select value={filterVlan} onChange={e => setFilterVlan(e.target.value)} className="g-select w-full text-xs">
                        <option value="">All VLANs</option>
                        {vlans.map(v => <option key={v} value={v}>{v}</option>)}
                      </select>
                    </div>
                  )}
                  <div>
                    <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>Device Type</p>
                    <select value={filterType} onChange={e => setFilterType(e.target.value)} className="g-select w-full text-xs">
                      <option value="">All Types</option>
                      {types.map(t => <option key={t} value={t}>{INFRA_LABELS[t] || t}</option>)}
                    </select>
                  </div>
                  <div>
                    <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>Risk Level</p>
                    <div className="flex gap-1 flex-wrap">
                      {['', 'critical', 'high', 'medium', 'low'].map(r => (
                        <button key={r || 'all'} onClick={() => setFilterRisk(r)}
                          className="px-2.5 py-1 rounded-lg text-[10px] font-medium capitalize"
                          style={{
                            background: filterRisk === r ? 'var(--accent-glow)' : 'var(--glass-bg)',
                            border: `1px solid ${filterRisk === r ? 'var(--accent-border)' : 'var(--border)'}`,
                            color: filterRisk === r ? 'var(--accent)' : 'var(--text-2)',
                          }}>
                          {r || 'All'}
                        </button>
                      ))}
                    </div>
                  </div>
                  {activeFilters > 0 && (
                    <button onClick={() => { setFilterVlan(''); setFilterType(''); setFilterRisk(''); setZoneFilter('all'); setShowFilters(false); }}
                      className="text-xs w-full text-center py-1.5 rounded-lg"
                      style={{ background: 'var(--red-bg)', color: 'var(--red)', border: '1px solid var(--red-border)' }}>
                      Clear all filters
                    </button>
                  )}
                </div>
              </div>,
              document.body
            )}

            {/* Time windows */}
            <div className="flex items-center gap-1">
              {TIME_WINDOWS.map(w => (
                <button type="button" key={w.minutes} onClick={() => setSinceMinutes(w.minutes)}
                  className="px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all"
                  style={{
                    background: sinceMinutes === w.minutes ? 'var(--accent-glow)' : 'transparent',
                    border: `1px solid ${sinceMinutes === w.minutes ? 'var(--accent-border)' : 'var(--border)'}`,
                    color:  sinceMinutes === w.minutes ? 'var(--text-1)' : 'var(--text-3)',
                  }}>
                  {w.label}
                </button>
              ))}
            </div>

            {/* View mode */}
            <select value={viewMode} onChange={e => setViewMode(e.target.value as ViewMode)}
              className="g-select text-xs" style={{ minWidth: 130 }}>
              {VIEW_MODES.map(m => <option key={m} value={m}>{m} View</option>)}
            </select>

            {/* Threat Overlay */}
            <button ref={overlayBtnRef} type="button" onClick={openOverlayMenu}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs transition-all"
              style={{
                background: threatOverlay ? 'rgba(248,81,73,0.12)' : 'var(--glass-bg)',
                border: `1px solid ${threatOverlay ? 'rgba(248,81,73,0.4)' : 'var(--border)'}`,
                color: threatOverlay ? '#f85149' : 'var(--text-2)',
              }}>
              <Eye className="h-3.5 w-3.5" />
              {threatOverlay ? THREAT_OVERLAYS.find(o => o.id === threatOverlay)?.label : 'Overlay'}
              {threatOverlay && (
                <X className="h-3 w-3 ml-0.5" onClick={e => { e.stopPropagation(); setThreatOverlay(''); setShowThreatMenu(false); }} />
              )}
            </button>
            {showThreatMenu && typeof document !== 'undefined' && createPortal(
              <div onMouseDown={e => e.stopPropagation()} style={{
                position: 'fixed', top: overlayMenuPos.top, left: overlayMenuPos.left,
                zIndex: 99990, width: 220,
                background: 'var(--bg-1)', border: '1px solid var(--border)',
                borderRadius: 14, padding: 8, boxShadow: '0 20px 48px rgba(0,0,0,0.55)',
              }}>
                <p className="text-[10px] font-bold uppercase tracking-wider px-2 py-1.5 mb-1" style={{ color: 'var(--text-3)' }}>
                  Threat Overlay
                </p>
                {threatOverlay && (
                  <button type="button" onClick={() => { setThreatOverlay(''); setShowThreatMenu(false); }}
                    className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs mb-1 transition-colors"
                    style={{ background: 'var(--glass-bg)', color: 'var(--text-3)', border: '1px solid var(--border)' }}>
                    <X className="h-3 w-3" /> Clear overlay
                  </button>
                )}
                {THREAT_OVERLAYS.map(o => (
                  <button key={o.id} type="button"
                    onClick={() => { setThreatOverlay(o.id); setShowThreatMenu(false); }}
                    className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs transition-colors"
                    style={{
                      background: threatOverlay === o.id ? o.color + '22' : 'transparent',
                      color: threatOverlay === o.id ? o.color : 'var(--text-1)',
                    }}>
                    <span className="h-2.5 w-2.5 rounded-full shrink-0" style={{ background: o.color }} />
                    {o.label}
                  </button>
                ))}
              </div>,
              document.body
            )}

            {/* Incident mode */}
            <button type="button" onClick={() => setIncidentMode(v => !v)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs transition-all"
              style={{
                background: incidentMode ? 'rgba(248,81,73,0.12)' : 'var(--glass-bg)',
                border: `1px solid ${incidentMode ? 'rgba(248,81,73,0.4)' : 'var(--border)'}`,
                color: incidentMode ? '#f85149' : 'var(--text-2)',
              }}>
              <AlertTriangle className="h-3.5 w-3.5" />
              Incident
            </button>

            {/* Offline toggle */}
            <button type="button" onClick={() => setShowOffline(o => !o)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs transition-all"
              style={{
                background: showOffline ? 'var(--glass-bg)' : 'var(--accent-glow)',
                border: `1px solid ${showOffline ? 'var(--border)' : 'var(--accent-border)'}`,
                color: showOffline ? 'var(--text-2)' : 'var(--accent)',
              }}>
              {showOffline ? <Wifi className="h-3.5 w-3.5" /> : <WifiOff className="h-3.5 w-3.5" />}
              {showOffline ? 'All' : 'Online'}
            </button>

            <button type="button" onClick={() => graphRef.current?.zoomToFit(400, 40)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs"
              style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
              <ZoomIn className="h-3.5 w-3.5" /> Fit
            </button>

            {/* Export */}
            <div className="flex items-center gap-1 ml-auto">
              {[
                { label: 'PNG', action: exportPNG, icon: Image },
                { label: 'JSON', action: exportJSON, icon: FileJson },
                { label: 'CSV', action: exportCSV, icon: FileText },
              ].map(({ label, action, icon: Icon }) => (
                <button key={label} type="button" onClick={action}
                  className="flex items-center gap-1 px-2 py-1.5 rounded-lg text-[11px]"
                  style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                  <Icon className="h-3 w-3" /> {label}
                </button>
              ))}
            </div>

            <Legend />
          </div>
        </div>

        {/* summary stats */}
        {s && (
          <div className="grid grid-cols-3 sm:grid-cols-7 gap-2">
            {[
              { label: 'Agents',       val: s.total_agents,   sub: `${s.online_agents} online` },
              { label: 'External',     val: s.external_ips,   sub: 'unique IPs' },
              { label: 'Infra',        val: infraCount,       sub: 'devices' },
              { label: 'Edges',        val: s.total_edges,    sub: 'connections' },
              { label: 'IOC Hits',     val: s.ioc_hits,       sub: 'known bad IPs',    warn: s.ioc_hits > 0 },
              { label: 'Alerting',     val: s.alerting_nodes, sub: 'agents w/ alerts', warn: s.alerting_nodes > 0 },
              { label: 'Visible',      val: data.nodes.length,sub: 'in filter' },
            ].map(({ label, val, sub, warn }) => (
              <div key={label} className="g-card p-3">
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{label}</p>
                <p className="text-lg font-semibold tabular-nums" style={{ color: warn ? 'var(--red)' : 'var(--text-1)' }}>{val}</p>
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{sub}</p>
              </div>
            ))}
          </div>
        )}

        {s && s.ioc_hits > 0 && (
          <div className="g-panel flex items-center gap-3 px-4 py-3"
            style={{ border: '1px solid var(--red-border)', background: 'var(--red-bg)' }}>
            <AlertTriangle className="h-4 w-4 shrink-0" style={{ color: 'var(--red)' }} />
            <p className="text-xs" style={{ color: 'var(--text-1)' }}>
              <strong>{s.ioc_hits}</strong> external IP{s.ioc_hits !== 1 ? 's' : ''} match local IOC indicators —
              shown in <span style={{ color: '#e879f9' }}>magenta</span>.
              Click a node to run live threat intel enrichment.
            </p>
          </div>
        )}
        {incidentMode && (
          <div className="g-panel flex items-center gap-3 px-4 py-3"
            style={{ border: '1px solid rgba(248,81,73,0.4)', background: 'rgba(248,81,73,0.08)' }}>
            <AlertTriangle className="h-4 w-4 shrink-0" style={{ color: '#f85149' }} />
            <p className="text-xs" style={{ color: 'var(--text-1)' }}>
              <strong>Incident Mode active</strong> — compromised endpoints highlighted. Non-alerting nodes dimmed.
              Click any node to investigate.
            </p>
            <button onClick={() => setIncidentMode(false)} className="ml-auto text-xs px-3 py-1.5 rounded-lg"
              style={{ background: 'rgba(248,81,73,0.15)', color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' }}>
              Exit
            </button>
          </div>
        )}

        {/* graph canvas */}
        {loading ? (
          <div className="g-panel flex items-center justify-center" style={{ height: 580 }}>
            <div className="text-center space-y-2">
              <Network className="mx-auto h-8 w-8 animate-pulse" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-3)' }}>Building network map…</p>
            </div>
          </div>
        ) : !graph || graph.nodes.length === 0 ? (
          <div className="g-panel flex items-center justify-center" style={{ height: 580 }}>
            <div className="text-center space-y-3">
              <Network className="mx-auto h-10 w-10" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm font-medium" style={{ color: 'var(--text-2)' }}>No connection data in this window</p>
              <p className="text-xs" style={{ color: 'var(--text-3)' }}>Install the xcloak-agent-desktop and wait for it to report connections.</p>
            </div>
          </div>
        ) : (
          <div ref={containerRef} className="g-panel overflow-hidden" style={{ height: 580 }}>
            <ForceGraph2D
              ref={graphRef}
              width={dims.width}
              height={dims.height}
              graphData={data}
              nodeId="id"
              nodeVal="val"
              nodeLabel={(n: any) => {
                const parts = [n.hostname || n.ip || n.id];
                if (n.type === 'agent') parts.push(`Risk: ${n.risk_level} (${n.risk_score})`);
                if (n.role) parts.push(n.role);
                if (n.vlan) parts.push(`VLAN: ${n.vlan}`);
                if (n.alert_count > 0) parts.push(`⚠ ${n.alert_count} alert${n.alert_count !== 1 ? 's' : ''}`);
                if (n.is_ioc) parts.push(`🚨 IOC (${n.ioc_severity})`);
                const enriched = n.ip ? enrichMap.get(n.ip) : null;
                if (enriched && enriched !== 'none') parts.push(`Threat: ${enriched}`);
                if (n.country) parts.push(n.country);
                if (n.status) parts.push(n.status);
                return parts.join('\n');
              }}
              nodeColor={nodeColor}
              linkColor={linkColor}
              linkWidth={(l: any) => Math.min(4, 1 + Math.log2(1 + (l.count || 1)))}
              linkDirectionalParticles={(l: any) => {
                const s = l.port_sensitivity;
                if (s === 'critical') return 3;
                if (s === 'sensitive') return 2;
                return l.edge_type === 'internal' ? 1 : 0;
              }}
              linkDirectionalParticleWidth={1.8}
              linkDirectionalParticleColor={linkColor}
              onNodeClick={(n: any) => setSelected(n)}
              onLinkClick={(l: any) => setSelectedEdge(l as NetworkMapEdge)}
              nodeCanvasObjectMode={() => 'replace'}
              nodeCanvasObject={drawNode}
              cooldownTicks={120}
              backgroundColor="transparent"
            />
          </div>
        )}
        {/* Analytics panel */}
        {graph && (
          <div>
            <button type="button" onClick={() => setShowAnalytics(v => !v)}
              className="flex items-center gap-2 text-xs font-medium mb-3 transition-colors"
              style={{ color: 'var(--text-2)' }}>
              <BarChart2 className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
              Analytics
              {showAnalytics ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
            </button>
            {showAnalytics && <AnalyticsPanel graph={graph} allAlerts={allAlerts} />}
          </div>
        )}

      </div>

      {/* ── Node detail drawer ──────────────────────────────────────────────── */}
      {selected && (
        <div className="fixed inset-0 z-50 flex">
          <div className="flex-1" onClick={() => setSelected(null)} />

          <div className="w-full max-w-lg h-full overflow-y-auto shadow-2xl"
            style={{ background: 'var(--bg-1)', borderLeft: '1px solid var(--border)' }}>

            {/* header */}
            <div className="sticky top-0 flex items-center gap-3 px-5 py-4 z-10"
              style={{ background: 'var(--bg-1)', borderBottom: '1px solid var(--border)' }}>
              {selected.type === 'agent'
                ? <Cpu className="h-4 w-4 shrink-0" style={{ color: 'var(--text-2)' }} />
                : selected.type === 'external_ip'
                ? <Globe className="h-4 w-4 shrink-0" style={{ color: 'var(--text-2)' }} />
                : <Server className="h-4 w-4 shrink-0" style={{ color: INFRA_FILL[selected.type] || 'var(--text-2)' }} />}
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold truncate" style={{ color: 'var(--text-1)' }}>
                  {selected.hostname || selected.ip || selected.id}
                </p>
                <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                  {selected.type === 'agent' && (
                    <span className="text-[10px]" style={{ color: selected.status === 'online' ? 'var(--green)' : 'var(--text-3)' }}>
                      ● {selected.status || 'unknown'}
                    </span>
                  )}
                  {INFRA_LABELS[selected.type] && (
                    <span className="text-[10px] font-medium"
                      style={{ color: INFRA_FILL[selected.type] }}>
                      {INFRA_LABELS[selected.type]}
                    </span>
                  )}
                  {selected.is_ioc && <Flag label="IOC" color="#e879f9" />}
                  {selected.alert_count > 0 && (
                    <span className="flex items-center gap-1 text-[10px]" style={{ color: 'var(--red)' }}>
                      <AlertTriangle className="h-3 w-3" /> {selected.alert_count} alert{selected.alert_count !== 1 ? 's' : ''}
                    </span>
                  )}
                  {selected.ip && enrichMap.get(selected.ip) && enrichMap.get(selected.ip) !== 'none' && (
                    <span className="text-[10px] font-semibold capitalize"
                      style={{ color: THREAT_FILL[enrichMap.get(selected.ip)!] }}>
                      ▲ {enrichMap.get(selected.ip)}
                    </span>
                  )}
                </div>
              </div>
              <button type="button" onClick={() => setSelected(null)} style={{ color: 'var(--text-3)' }}>
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Agent tabs */}
            {(selected.type === 'agent' || selected.type === 'external_ip' || !!INFRA_LABELS[selected.type]) && (
              <div className="flex border-b overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
                {(selected.type === 'agent' ? AGENT_TABS : [
                  { id: 'overview', label: 'Overview', icon: Activity },
                  { id: 'actions',  label: 'Actions',  icon: Zap      },
                  ...(selected.type === 'external_ip' ? [{ id: 'traffic', label: 'Traffic', icon: TrendingUp }] : []),
                ]).map(tab => (
                  <button key={tab.id} type="button"
                    onClick={() => setNodeTab(tab.id)}
                    className="flex items-center gap-1.5 px-3 py-2.5 text-[11px] font-medium whitespace-nowrap transition-colors shrink-0"
                    style={{
                      color:        nodeTab === tab.id ? 'var(--accent)' : 'var(--text-3)',
                      borderBottom: nodeTab === tab.id ? '2px solid var(--accent)' : '2px solid transparent',
                    }}>
                    <tab.icon className="h-3 w-3" />
                    {tab.label}
                    {tab.id === 'cves' && nodeVulns.length > 0 && (
                      <span className="ml-0.5 rounded-full px-1 text-[9px] font-bold"
                        style={{ background: 'var(--red)', color: '#fff' }}>
                        {nodeVulns.length}
                      </span>
                    )}
                    {tab.id === 'alerts' && allAlerts.filter(a => a.agent_id === selected.agent_id).length > 0 && (
                      <span className="ml-0.5 rounded-full px-1 text-[9px] font-bold"
                        style={{ background: 'var(--orange)', color: '#fff' }}>
                        {allAlerts.filter(a => a.agent_id === selected.agent_id).length}
                      </span>
                    )}
                  </button>
                ))}
              </div>
            )}

            <div className="p-5 space-y-4">
              {nodeLoading && selected.type === 'agent' && (
                <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--text-3)' }}>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading host data…
                </div>
              )}

              {/* ── Agent: Overview tab ─────────────────────────────────── */}
              {(selected.type === 'agent' && nodeTab === 'overview') && (
                <>
                  <div className="grid grid-cols-2 gap-2">
                    {[
                      { label: 'Type',       val: 'Agent' },
                      { label: 'Zone',       val: selected.zone },
                      { label: 'IP',         val: selected.ip || '—' },
                      { label: 'Country',    val: selected.country || '—' },
                      { label: 'Risk Score', val: `${selected.risk_score} (${selected.risk_level})` },
                      { label: 'Connections',val: `${edgesForSelected.length}` },
                    ].map(({ label, val }) => (
                      <div key={label} className="rounded-xl p-3"
                        style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                        <p className="text-[10px] mb-0.5" style={{ color: 'var(--text-3)' }}>{label}</p>
                        <p className="text-xs mono font-medium truncate" style={{ color: 'var(--text-1)' }}>{val}</p>
                      </div>
                    ))}
                  </div>

                  {/* Risk score bar */}
                  <div className="rounded-xl p-3" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <div className="flex items-center justify-between mb-1.5">
                      <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Risk Score</p>
                      <span className="text-xs font-bold tabular-nums"
                        style={{ color: RISK_FILL[selected.risk_level] || 'var(--text-1)' }}>
                        {selected.risk_score}/100
                      </span>
                    </div>
                    <div className="h-2 rounded-full overflow-hidden" style={{ background: 'var(--bg-0)' }}>
                      <div className="h-full rounded-full transition-all"
                        style={{ width: `${selected.risk_score}%`, background: RISK_FILL[selected.risk_level] || 'var(--accent)' }} />
                    </div>
                    <p className="text-[10px] mt-1 capitalize" style={{ color: RISK_FILL[selected.risk_level] }}>
                      {selected.risk_level} risk
                    </p>
                  </div>

                  {/* Quick stats */}
                  <div className="grid grid-cols-3 gap-2">
                    {[
                      { label: 'CVEs',     val: nodeVulns.length,                                                      color: nodeVulns.length > 0 ? 'var(--red)' : 'var(--text-1)' },
                      { label: 'Alerts',   val: allAlerts.filter(a => a.agent_id === selected.agent_id).length,        color: 'var(--orange)' },
                      { label: 'Processes',val: nodeProcesses.length,                                                   color: 'var(--text-1)' },
                    ].map(({ label, val, color }) => (
                      <div key={label} className="rounded-xl p-3 text-center" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                        <p className="text-xl font-bold tabular-nums" style={{ color }}>{val}</p>
                        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{label}</p>
                      </div>
                    ))}
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <span className={sevClass(selected.risk_level)}>{selected.risk_level} risk</span>
                    {selected.zone === 'dmz' && (
                      <span className="flex items-center gap-1 text-xs" style={{ color: 'var(--orange)' }}>
                        <ShieldAlert className="h-3.5 w-3.5" /> internet-exposed
                      </span>
                    )}
                    {selected.agent_id && (
                      <Link href={`/agents/${selected.agent_id}`}
                        className="text-xs underline" style={{ color: 'var(--accent)' }}>
                        Full agent detail →
                      </Link>
                    )}
                  </div>
                </>
              )}

              {/* ── Agent: Ports tab ────────────────────────────────────── */}
              {selected.type === 'agent' && nodeTab === 'ports' && (
                <PortsTab edges={edgesForSelected} />
              )}

              {/* ── Agent: CVEs tab ─────────────────────────────────────── */}
              {selected.type === 'agent' && nodeTab === 'cves' && (
                <CVEsTab vulns={nodeVulns} />
              )}

              {/* ── Agent: Processes tab ─────────────────────────────────── */}
              {selected.type === 'agent' && nodeTab === 'processes' && (
                <ProcessesTab processes={nodeProcesses} />
              )}

              {/* ── Agent: Alerts tab ────────────────────────────────────── */}
              {selected.type === 'agent' && nodeTab === 'alerts' && (
                <AlertsTab alerts={allAlerts} agentId={selected.agent_id as number} />
              )}

              {/* ── Agent: Timeline tab ──────────────────────────────────── */}
              {selected.type === 'agent' && nodeTab === 'timeline' && (
                <TimelineTab timeline={nodeTimeline} />
              )}

              {/* ── Agent: Identity tab ──────────────────────────────────── */}
              {selected.type === 'agent' && nodeTab === 'identity' && (
                <IdentityTab node={selected} />
              )}

              {/* ── Agent: Security tab ──────────────────────────────────── */}
              {selected.type === 'agent' && nodeTab === 'security' && (
                <SecurityTab node={selected} vulns={nodeVulns} />
              )}

              {/* ── Agent: Hardware tab ──────────────────────────────────── */}
              {selected.type === 'agent' && nodeTab === 'hardware' && (
                <HardwareTab processes={nodeProcesses} />
              )}

              {/* ── Agent: Traffic tab ───────────────────────────────────── */}
              {selected.type === 'agent' && nodeTab === 'traffic' && (
                <TrafficTab edges={edgesForSelected} nodeId={selected.id} />
              )}

              {/* ── Agent: Actions tab ───────────────────────────────────── */}
              {(selected.type === 'agent' || selected.type === 'external_ip' || INFRA_LABELS[selected.type]) && nodeTab === 'actions' && (
                <ActionsTab node={selected} onToast={notify} />
              )}

              {/* ── Agent: AI Insights tab ───────────────────────────────── */}
              {selected.type === 'agent' && nodeTab === 'ai' && (
                <AITab node={selected} alerts={allAlerts} vulns={nodeVulns} edges={edgesForSelected} />
              )}

              {/* ── External IP: threat intel + connections ─────────────── */}
              {selected.type === 'external_ip' && selected.ip && (
                <>
                  <EnrichPanel ip={selected.ip} tenantFetched={false} />
                  <div>
                    <p className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>
                      Connections ({edgesForSelected.length})
                    </p>
                    <div className="space-y-1.5">
                      {edgesForSelected.length === 0
                        ? <p className="text-xs" style={{ color: 'var(--text-3)' }}>No edges visible in current filter.</p>
                        : edgesForSelected.map((e, i) => {
                            const dir = e.source === selected.id ? '→' : '←';
                            return (
                              <div key={i} className="rounded-lg p-2.5 text-xs"
                                style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                                <div className="flex items-center justify-between gap-2">
                                  <span className="mono truncate" style={{ color: 'var(--text-1)' }}>
                                    <span style={{ color: e.edge_type === 'internal' ? 'var(--blue)' : 'var(--text-3)' }}>{dir}</span>
                                    {' '}{e.process || 'unknown'}
                                  </span>
                                  <div className="flex items-center gap-1.5 shrink-0">
                                    <PortBadge e={e} />
                                    <span style={{ color: 'var(--text-3)' }}>×{e.count}</span>
                                  </div>
                                </div>
                                <div className="flex items-center gap-2 mt-1 flex-wrap">
                                  <span className="text-[10px] rounded px-1 py-0.5"
                                    style={{ background: e.edge_type === 'internal' ? 'rgba(99,179,237,0.15)' : 'var(--glass-bg)', color: 'var(--text-3)' }}>
                                    {e.edge_type}
                                  </span>
                                  {e.port_note && (
                                    <span className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>
                                      ⚠ {e.port_note.slice(0, 50)}{e.port_note.length > 50 ? '…' : ''}
                                    </span>
                                  )}
                                  <span className="text-[10px] ml-auto flex items-center gap-0.5" style={{ color: 'var(--text-3)' }}>
                                    <Clock className="h-3 w-3" /> {new Date(e.last_seen).toLocaleString()}
                                  </span>
                                </div>
                              </div>
                            );
                          })
                      }
                    </div>
                  </div>
                </>
              )}

              {/* ── Infrastructure nodes ─────────────────────────────────── */}
              {INFRA_LABELS[selected.type] && (
                <InfraPanel node={selected} edges={edgesForSelected} />
              )}
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
