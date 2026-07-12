'use client';

import { createPortal } from 'react-dom';
import { useEffect, useMemo, useRef, useState, useCallback } from 'react';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { RootLayout } from '@/components/layout/RootLayout';
import { networkMapAPI, iocsAPI } from '@/lib/api';
import { NetworkMapGraph, NetworkMapNode, NetworkMapEdge, IPEnrichment } from '@/types';
import { sevClass } from '@/lib/utils';
import {
  Network, Search, X, Globe, Cpu, ShieldAlert,
  ZoomIn, AlertTriangle, Wifi, WifiOff, Info, Shield,
  MapPin, Building, ExternalLink, Clock, Copy, Plus,
  CheckCircle, Loader2, ChevronDown, ChevronUp,
} from 'lucide-react';

const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), { ssr: false });

// ── color constants ───────────────────────────────────────────────────────────

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

const TIME_WINDOWS = [
  { label: '15m', minutes: 15 },
  { label: '1h',  minutes: 60 },
  { label: '6h',  minutes: 360 },
  { label: '24h', minutes: 1440 },
];

interface GNode extends NetworkMapNode { val: number; }

function resolveVar(name: string): string {
  if (typeof window === 'undefined') return '#64748b';
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || '#64748b';
}

// ── Legend (createPortal to escape stacking contexts) ─────────────────────────

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
      if (btnRef.current && !btnRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  const panel = open && typeof document !== 'undefined'
    ? createPortal(
        <div onMouseDown={e => e.stopPropagation()}
          style={{
            position: 'fixed', top: pos.top, right: pos.right,
            zIndex: 99999, width: 272,
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

// ── IP Enrichment panel (shown inside node drawer) ────────────────────────────

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
        indicator: ip,
        type: 'ip',
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
          {/* IP + quick actions */}
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
              {/* Threat tags */}
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

              {/* Geo info */}
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

              {/* Flags */}
              {(data.is_proxy || data.is_hosting) && (
                <div className="flex flex-wrap gap-1.5">
                  {data.is_proxy && <Flag label="VPN / Proxy" color="#fb923c" />}
                  {data.is_hosting && <Flag label="Hosting / DC" color="#94a3b8" />}
                </div>
              )}

              {/* AbuseIPDB */}
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

              {/* VirusTotal */}
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

              {/* IOC match from local DB */}
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

              {/* Sources */}
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

// ── Port badge ────────────────────────────────────────────────────────────────

function PortBadge({ e }: { e: NetworkMapEdge }) {
  const sens = e.port_sensitivity || 'neutral';
  const color = SENSITIVITY_COLOR[sens] || '#94a3b8';
  const label = e.service ? `${e.port}/${e.service}` : e.port;
  return (
    <span title={e.port_note || ''} className="rounded px-1.5 py-0.5 mono text-[10px] cursor-default"
      style={{ background: color + '20', color, border: `1px solid ${color}55` }}>
      {label}/{e.protocol.toUpperCase()}
    </span>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function NetworkMapPage() {
  const graphRef     = useRef<any>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dims, setDims] = useState({ width: 900, height: 580 });

  const [graph, setGraph]             = useState<NetworkMapGraph | null>(null);
  const [loading, setLoading]         = useState(true);
  const [refreshing, setRefreshing]   = useState(false);
  const [sinceMinutes, setSinceMinutes] = useState(60);
  const [zoneFilter, setZoneFilter]   = useState('all');
  const [search, setSearch]           = useState('');
  const [selected, setSelected]       = useState<NetworkMapNode | null>(null);
  const [showOffline, setShowOffline] = useState(true);
  const [zoneColors, setZoneColors]   = useState<Record<string, string>>({});

  // Progressive enrichment cache: ip → threat_level — drives node color updates
  const [enrichMap, setEnrichMap] = useState<Map<string, string>>(new Map());

  // measure canvas
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
      const r = await networkMapAPI.get(minutes);
      setGraph(r.data);
    } catch { setGraph(null); }
    finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => { load(sinceMinutes); }, [load, sinceMinutes]);

  // When an external IP node is selected, proactively enrich it and update map
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

  const filteredNodeIds = useMemo(() => {
    if (!graph) return new Set<string>();
    const q = search.trim().toLowerCase();
    const ids = new Set<string>();
    for (const n of graph.nodes) {
      if (zoneFilter !== 'all' && n.zone !== zoneFilter) continue;
      if (!showOffline && n.type === 'agent' && n.status === 'offline') continue;
      if (q && !`${n.hostname || ''} ${n.ip || ''}`.toLowerCase().includes(q)) continue;
      // Drop external_ip nodes with garbage IPs (hex strings, brackets, etc.)
      if (n.type === 'external_ip' && n.ip) {
        const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(n.ip);
        const ipv6 = n.ip.includes(':') && /^[0-9a-fA-F:]+$/.test(n.ip);
        if (!ipv4 && !ipv6) continue;
      }
      ids.add(n.id);
    }
    return ids;
  }, [graph, zoneFilter, search, showOffline]);

  const data = useMemo(() => {
    if (!graph) return { nodes: [], links: [] };
    const nodes: GNode[] = graph.nodes
      .filter(n => filteredNodeIds.has(n.id))
      .map(n => ({ ...n, val: n.type === 'agent' ? 6 + n.risk_score / 20 : 4 }));
    const nodeSet = new Set(nodes.map(n => n.id));
    const links = graph.edges.filter(e => nodeSet.has(e.source) && nodeSet.has(e.target));
    return { nodes, links };
  }, [graph, filteredNodeIds]);

  const edgesForSelected = useMemo(() => {
    if (!graph || !selected) return [];
    return graph.edges.filter(e => e.source === selected.id || e.target === selected.id);
  }, [graph, selected]);

  // ── drawing ─────────────────────────────────────────────────────────────────

  const nodeColor = useCallback((n: any): string => {
    if (n.type === 'external_ip') {
      if (n.is_ioc) return THREAT_FILL[n.ioc_severity] || '#e879f9';
      const enriched = enrichMap.get(n.ip);
      if (enriched && enriched !== 'none') return THREAT_FILL[enriched] || '#64748b';
      return '#64748b';
    }
    const fill = RISK_FILL[n.risk_level] || RISK_FILL.unknown;
    return n.status === 'offline' ? fill + '55' : fill;
  }, [enrichMap]);

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

      // Ring — dashed for offline
      if (offline) {
        ctx.setLineDash([3, 3]);
      }
      ctx.beginPath();
      ctx.arc(n.x, n.y, r + 2, 0, 2 * Math.PI);
      ctx.strokeStyle = offline ? ring + '55' : ring;
      ctx.lineWidth = n.zone === 'dmz' ? 2.5 : 1.5;
      ctx.stroke();
      ctx.setLineDash([]);

      // Alert badge (top-right red dot)
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

      // Hostname label with background pill
      const label    = n.hostname
        ? (n.hostname.length > 16 ? n.hostname.slice(0, 14) + '…' : n.hostname)
        : (n.ip || n.id);
      const fontSize = Math.max(6, Math.min(r * 0.95, 9));
      ctx.font = `600 ${fontSize}px sans-serif`;
      const tw   = ctx.measureText(label).width;
      const ly   = n.y + r + 4;
      const pad  = 3;
      ctx.fillStyle = 'rgba(15,23,42,0.72)';
      ctx.beginPath();
      const bx = n.x - tw / 2 - pad;
      const bw = tw + pad * 2;
      const bh = fontSize + pad * 1.5;
      const br = 3;
      ctx.moveTo(bx + br, ly); ctx.lineTo(bx + bw - br, ly);
      ctx.arcTo(bx + bw, ly, bx + bw, ly + bh, br);
      ctx.lineTo(bx + bw, ly + bh - br);
      ctx.arcTo(bx + bw, ly + bh, bx + bw - br, ly + bh, br);
      ctx.lineTo(bx + br, ly + bh);
      ctx.arcTo(bx, ly + bh, bx, ly + bh - br, br);
      ctx.lineTo(bx, ly + br);
      ctx.arcTo(bx, ly, bx + br, ly, br);
      ctx.closePath();
      ctx.fill();

      ctx.textAlign    = 'center';
      ctx.textBaseline = 'top';
      ctx.fillStyle    = offline ? 'rgba(148,163,184,0.5)' : 'rgba(226,232,240,0.95)';
      ctx.fillText(label, n.x, ly + pad * 0.75);

    } else if (isExt) {
      // Diamond shape for external IPs
      const threat  = n.is_ioc || (n.ip && enrichMap.get(n.ip) && enrichMap.get(n.ip) !== 'none');
      const extFill = fill;
      const dr      = r + (threat ? 2 : 0);

      if (threat) {
        // Glow for IOC/enriched nodes
        ctx.beginPath();
        ctx.moveTo(n.x, n.y - dr - 5);
        ctx.lineTo(n.x + dr + 5, n.y);
        ctx.lineTo(n.x, n.y + dr + 5);
        ctx.lineTo(n.x - dr - 5, n.y);
        ctx.closePath();
        ctx.fillStyle = extFill + '30';
        ctx.fill();
      }

      // Diamond fill
      ctx.beginPath();
      ctx.moveTo(n.x, n.y - dr);
      ctx.lineTo(n.x + dr, n.y);
      ctx.lineTo(n.x, n.y + dr);
      ctx.lineTo(n.x - dr, n.y);
      ctx.closePath();
      ctx.fillStyle = extFill + (threat ? 'cc' : '99');
      ctx.fill();

      // Diamond stroke
      ctx.beginPath();
      ctx.moveTo(n.x, n.y - dr);
      ctx.lineTo(n.x + dr, n.y);
      ctx.lineTo(n.x, n.y + dr);
      ctx.lineTo(n.x - dr, n.y);
      ctx.closePath();
      ctx.strokeStyle = threat ? extFill : (ring + '88');
      ctx.lineWidth   = threat ? 1.5 : 0.8;
      ctx.stroke();

      // IOC badge (top-right purple dot)
      if (n.is_ioc) {
        ctx.beginPath();
        ctx.arc(n.x + dr * 0.65, n.y - dr * 0.65, 2.5, 0, 2 * Math.PI);
        ctx.fillStyle = '#e879f9';
        ctx.fill();
      }

      // Label for IOC nodes or enriched threats — abbreviated IP
      if (threat && n.ip) {
        const parts  = (n.ip as string).split('.');
        const abbrev = parts.length === 4
          ? `${parts[0]}.*.${parts[3]}`
          : (n.ip.length > 12 ? n.ip.slice(0, 10) + '…' : n.ip);
        const fontSize = Math.max(5, dr * 0.85);
        ctx.font       = `500 ${fontSize}px sans-serif`;
        ctx.textAlign    = 'center';
        ctx.textBaseline = 'top';
        ctx.fillStyle  = extFill;
        ctx.fillText(abbrev, n.x, n.y + dr + 2);
      }
    }
  }, [zoneColors, nodeColor, enrichMap]);

  const s = graph?.summary;

  return (
    <RootLayout title="Network Map"
      subtitle="Fleet-wide connections · live threat enrichment"
      onRefresh={() => load(sinceMinutes, true)} refreshing={refreshing}>

      <div className="space-y-4">

        {/* toolbar */}
        <div className="g-panel p-3 flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1">
            {TIME_WINDOWS.map(w => (
              <button type="button" key={w.minutes} onClick={() => setSinceMinutes(w.minutes)}
                className="px-2.5 py-1 rounded-lg text-xs font-medium transition-all"
                style={{
                  background: sinceMinutes === w.minutes ? 'var(--accent-glow)' : 'transparent',
                  border: `1px solid ${sinceMinutes === w.minutes ? 'var(--accent-border)' : 'var(--border)'}`,
                  color:  sinceMinutes === w.minutes ? 'var(--text-1)' : 'var(--text-3)',
                }}>
                {w.label}
              </button>
            ))}
          </div>

          <select value={zoneFilter} onChange={e => setZoneFilter(e.target.value)} className="g-select" style={{ minWidth: 130 }}>
            <option value="all">All zones</option>
            <option value="internal">Internal</option>
            <option value="dmz">DMZ (exposed)</option>
            <option value="external">External</option>
          </select>

          <div className="relative flex-1 min-w-[180px] max-w-xs">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search hostname or IP…" className="g-input pl-8 text-xs" />
          </div>

          <button type="button" onClick={() => setShowOffline(o => !o)}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs transition-all"
            style={{
              background: showOffline ? 'var(--glass-bg)' : 'var(--accent-glow)',
              border: `1px solid ${showOffline ? 'var(--border)' : 'var(--accent-border)'}`,
              color: showOffline ? 'var(--text-2)' : 'var(--accent)',
            }}>
            {showOffline ? <Wifi className="h-3.5 w-3.5" /> : <WifiOff className="h-3.5 w-3.5" />}
            {showOffline ? 'All' : 'Online only'}
          </button>

          <button type="button" onClick={() => graphRef.current?.zoomToFit(400, 40)}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs"
            style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
            <ZoomIn className="h-3.5 w-3.5" /> Fit
          </button>

          <Legend />
        </div>

        {/* summary stats */}
        {s && (
          <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
            {[
              { label: 'Agents',   val: s.total_agents,    sub: `${s.online_agents} online` },
              { label: 'External', val: s.external_ips,    sub: 'unique IPs' },
              { label: 'Edges',    val: s.total_edges,     sub: 'connections' },
              { label: 'IOC Hits', val: s.ioc_hits,        sub: 'known bad IPs',    warn: s.ioc_hits > 0 },
              { label: 'Alerting', val: s.alerting_nodes,  sub: 'agents w/ alerts', warn: s.alerting_nodes > 0 },
              { label: 'Visible',  val: data.nodes.length, sub: 'in filter' },
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

        {/* graph */}
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
              nodeCanvasObjectMode={() => 'replace'}
              nodeCanvasObject={drawNode}
              cooldownTicks={120}
              backgroundColor="transparent"
            />
          </div>
        )}
      </div>

      {/* ── node detail drawer ── */}
      {selected && (
        <div className="fixed inset-0 z-50 flex">
          <div className="flex-1" onClick={() => setSelected(null)} />

          <div className="w-full max-w-md h-full overflow-y-auto shadow-2xl"
            style={{ background: 'var(--bg-1)', borderLeft: '1px solid var(--border)' }}>

            {/* header */}
            <div className="sticky top-0 flex items-center gap-3 px-5 py-4 z-10"
              style={{ background: 'var(--bg-1)', borderBottom: '1px solid var(--border)' }}>
              {selected.type === 'agent'
                ? <Cpu className="h-4 w-4 shrink-0" style={{ color: 'var(--text-2)' }} />
                : <Globe className="h-4 w-4 shrink-0" style={{ color: 'var(--text-2)' }} />}
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

            <div className="p-5 space-y-4">

              {/* meta grid */}
              <div className="grid grid-cols-2 gap-2">
                {[
                  { label: 'Type',    val: selected.type === 'agent' ? 'Agent' : 'External IP' },
                  { label: 'Zone',    val: selected.zone },
                  { label: 'IP',      val: selected.ip || '—' },
                  { label: 'Country', val: selected.country || '—' },
                  ...(selected.type === 'agent' ? [{ label: 'Risk score', val: `${selected.risk_score} (${selected.risk_level})` }] : []),
                  ...(selected.is_ioc ? [{ label: 'IOC severity', val: selected.ioc_severity || 'unknown' }] : []),
                ].map(({ label, val }) => (
                  <div key={label} className="rounded-xl p-3"
                    style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <p className="text-[10px] mb-0.5" style={{ color: 'var(--text-3)' }}>{label}</p>
                    <p className="text-xs mono font-medium truncate" style={{ color: 'var(--text-1)' }}>{val}</p>
                  </div>
                ))}
              </div>

              {selected.type === 'agent' && (
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
                      View agent →
                    </Link>
                  )}
                </div>
              )}

              {/* Threat intel enrichment for external IPs */}
              {selected.type === 'external_ip' && selected.ip && (
                <EnrichPanel ip={selected.ip} tenantFetched={false} />
              )}

              {/* connections */}
              <div>
                <p className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>
                  Connections ({edgesForSelected.length})
                </p>
                <div className="space-y-1.5">
                  {edgesForSelected.length === 0
                    ? <p className="text-xs" style={{ color: 'var(--text-3)' }}>No edges visible in current filter.</p>
                    : edgesForSelected.map((e: NetworkMapEdge, i: number) => {
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
                                <span className="text-[10px] truncate" style={{ color: 'var(--text-3)' }} title={e.port_note}>
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
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
