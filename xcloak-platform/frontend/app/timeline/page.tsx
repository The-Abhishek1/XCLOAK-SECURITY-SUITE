'use client';

import { useEffect, useState, useCallback, useMemo, useRef } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { agentsAPI, timelineAPI } from '@/lib/api';
import { TimelineEvent, Agent } from '@/types';
import { formatDate, timeAgo } from '@/lib/utils';
import {
  Clock, Search, AlertTriangle, Terminal, Shield, Globe, Server,
  Monitor, FileText, Database, LogIn, Activity, Network, Flame,
  Play, Cpu, HardDrive, Wifi, Lock, X, ChevronDown, ChevronRight,
  Download, Bookmark, BookmarkCheck, RefreshCw, Filter, Zap,
  Eye, Copy, Check, MoreHorizontal, SlidersHorizontal,
} from 'lucide-react';

// ── Category metadata ─────────────────────────────────────────────────────────

const CATEGORY: Record<string, { label: string; color: string; Icon: any }> = {
  alert:           { label: 'Alert',          color: 'var(--red)',    Icon: AlertTriangle },
  incident:        { label: 'Incident',       color: 'var(--orange)', Icon: Flame },
  process:         { label: 'Process',        color: 'var(--blue)',   Icon: Cpu },
  file:            { label: 'File',           color: 'var(--yellow)', Icon: FileText },
  network:         { label: 'Network',        color: 'var(--accent)', Icon: Globe },
  playbook_action: { label: 'Playbook',       color: 'var(--green)',  Icon: Play },
  fim:             { label: 'FIM',            color: 'var(--yellow)', Icon: HardDrive },
  login:           { label: 'Login',          color: 'var(--blue)',   Icon: LogIn },
  dns:             { label: 'DNS',            color: 'var(--accent)', Icon: Server },
  registry:        { label: 'Registry',       color: 'var(--orange)', Icon: Database },
  browser:         { label: 'Browser',        color: 'var(--green)',  Icon: Monitor },
  firewall:        { label: 'Firewall',       color: 'var(--blue)',   Icon: Shield },
};

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)',
  high:     'var(--orange)',
  medium:   'var(--yellow)',
  low:      'var(--green)',
  info:     'var(--text-3)',
};

const SEV_BG: Record<string, string> = {
  critical: 'rgba(239,68,68,0.12)',
  high:     'rgba(249,115,22,0.12)',
  medium:   'rgba(234,179,8,0.12)',
  low:      'rgba(34,197,94,0.12)',
  info:     'var(--glass-bg)',
};

const DATE_RANGES = [
  { label: '1h',  hours: 1 },
  { label: '6h',  hours: 6 },
  { label: '24h', hours: 24 },
  { label: '7d',  hours: 24 * 7 },
  { label: '30d', hours: 24 * 30 },
  { label: 'All', hours: Infinity },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function dayKey(iso: string) {
  const d = new Date(iso);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function dayLabel(key: string) {
  const d = new Date(key + 'T00:00:00');
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const yest  = new Date(today); yest.setDate(yest.getDate() - 1);
  if (d.toDateString() === today.toDateString()) return 'Today';
  if (d.toDateString() === yest.toDateString())  return 'Yesterday';
  return d.toLocaleDateString('en-US', { weekday: 'long', month: 'short', day: 'numeric' });
}

function exportJSON(events: TimelineEvent[]) {
  const blob = new Blob([JSON.stringify(events, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `xcloak-timeline-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function exportCSV(events: TimelineEvent[]) {
  const header = 'timestamp,event_type,severity,message,hostname,username,process,mitre,source';
  const rows   = events.map(e => [
    e.created_at, e.event_type, e.severity ?? '', e.message.replace(/,/g, ';'),
    e.hostname ?? '', e.username ?? '', e.process_name ?? '',
    e.mitre_technique ?? '', e.source ?? '',
  ].map(v => `"${v}"`).join(','));
  const blob = new Blob([[header, ...rows].join('\n')], { type: 'text/csv' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `xcloak-timeline-${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Evidence Panel ────────────────────────────────────────────────────────────

function EvidencePanel({ ev, onClose, bookmarked, onBookmark }: {
  ev: TimelineEvent;
  onClose: () => void;
  bookmarked: boolean;
  onBookmark: () => void;
}) {
  const [showRaw, setShowRaw] = useState(false);
  const [copied, setCopied]   = useState(false);
  const cat = CATEGORY[ev.event_type] ?? { label: ev.event_type, color: 'var(--accent)', Icon: Activity };
  const sev = ev.severity ?? 'info';

  const copyJSON = () => {
    navigator.clipboard.writeText(JSON.stringify(ev, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const details = ev.details ? Object.entries(ev.details).filter(([, v]) => v !== null && v !== '' && v !== 0) : [];

  return (
    <div
      style={{
        width: 380, minHeight: '100%', background: 'var(--glass-bg)',
        borderLeft: '1px solid var(--border)', display: 'flex', flexDirection: 'column',
        flexShrink: 0,
      }}
    >
      {/* Header */}
      <div className="flex items-center gap-2 px-4 py-3"
        style={{ borderBottom: '1px solid var(--border)', background: `${cat.color}11` }}>
        <cat.Icon className="h-4 w-4 shrink-0" style={{ color: cat.color }} />
        <span className="text-xs font-bold uppercase flex-1" style={{ color: cat.color }}>
          {cat.label} — Evidence
        </span>
        <button onClick={onBookmark} title={bookmarked ? 'Remove bookmark' : 'Bookmark'}>
          {bookmarked
            ? <BookmarkCheck className="h-4 w-4" style={{ color: 'var(--accent)' }} />
            : <Bookmark className="h-4 w-4" style={{ color: 'var(--text-3)' }} />}
        </button>
        <button onClick={copyJSON} title="Copy JSON">
          {copied
            ? <Check className="h-4 w-4" style={{ color: 'var(--green)' }} />
            : <Copy className="h-4 w-4" style={{ color: 'var(--text-3)' }} />}
        </button>
        <button onClick={onClose}>
          <X className="h-4 w-4" style={{ color: 'var(--text-3)' }} />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4" style={{ fontSize: 12 }}>
        {/* Severity + time */}
        <div className="flex items-center gap-2 flex-wrap">
          {sev !== 'info' && (
            <span className="rounded px-2 py-0.5 text-[10px] font-bold uppercase"
              style={{ background: SEV_BG[sev], color: SEV_COLOR[sev], border: `1px solid ${SEV_COLOR[sev]}44` }}>
              {sev}
            </span>
          )}
          <span style={{ color: 'var(--text-3)' }}>{formatDate(ev.created_at)}</span>
          <span style={{ color: 'var(--text-3)' }}>({timeAgo(ev.created_at)})</span>
        </div>

        {/* Message */}
        <div>
          <p className="text-[10px] font-semibold uppercase mb-1" style={{ color: 'var(--text-3)' }}>Message</p>
          <p className="leading-relaxed font-mono break-all" style={{ color: 'var(--text-1)', fontSize: 11 }}>
            {ev.message}
          </p>
        </div>

        {/* Context chips */}
        <div className="grid gap-2" style={{ gridTemplateColumns: '1fr 1fr' }}>
          {ev.hostname && <KV label="Host" value={ev.hostname} mono />}
          {ev.username && <KV label="User" value={ev.username} mono />}
          {ev.process_name && <KV label="Process" value={ev.process_name} mono />}
          {ev.source && <KV label="Source" value={ev.source} />}
          {ev.agent_id && <KV label="Agent ID" value={String(ev.agent_id)} mono />}
        </div>

        {/* MITRE */}
        {ev.mitre_technique && (
          <div className="rounded-lg px-3 py-2"
            style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
            <p className="text-[10px] font-semibold uppercase mb-1" style={{ color: 'var(--text-3)' }}>MITRE ATT&CK</p>
            <p className="font-mono font-bold" style={{ color: 'var(--accent)', fontSize: 11 }}>{ev.mitre_technique}</p>
            {ev.mitre_name && <p style={{ color: 'var(--text-2)', fontSize: 11 }}>{ev.mitre_name}</p>}
          </div>
        )}

        {/* Event-specific details */}
        {details.length > 0 && (
          <div>
            <div className="flex items-center justify-between mb-2">
              <p className="text-[10px] font-semibold uppercase" style={{ color: 'var(--text-3)' }}>Details</p>
              <button
                onClick={() => setShowRaw(x => !x)}
                className="text-[10px] flex items-center gap-1"
                style={{ color: 'var(--accent)' }}>
                <Eye className="h-3 w-3" />
                {showRaw ? 'Parsed' : 'Raw JSON'}
              </button>
            </div>

            {showRaw ? (
              <pre className="rounded-lg p-3 overflow-x-auto text-[10px] font-mono"
                style={{ background: 'rgba(0,0,0,0.3)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>
                {JSON.stringify(ev.details, null, 2)}
              </pre>
            ) : (
              <div className="space-y-1.5">
                {details.map(([k, v]) => (
                  <div key={k} className="flex gap-2 min-w-0">
                    <span className="shrink-0 text-[10px] font-semibold" style={{ color: 'var(--text-3)', width: 100 }}>
                      {k.replace(/_/g, ' ')}
                    </span>
                    <span className="text-[10px] font-mono break-all" style={{ color: 'var(--text-1)' }}>
                      {Array.isArray(v) ? v.join(', ') : String(v)}
                    </span>
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

function KV({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-lg px-2 py-1.5" style={{ background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border)' }}>
      <p className="text-[9px] uppercase font-semibold mb-0.5" style={{ color: 'var(--text-3)' }}>{label}</p>
      <p className={`text-[11px] truncate ${mono ? 'font-mono' : ''}`} style={{ color: 'var(--text-1)' }}>{value}</p>
    </div>
  );
}

// ── Context menu ──────────────────────────────────────────────────────────────

function ContextMenu({ x, y, ev, onClose, onBookmark, bookmarked }: {
  x: number; y: number; ev: TimelineEvent; onClose: () => void;
  onBookmark: () => void; bookmarked: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const handler = () => onClose();
    document.addEventListener('click', handler);
    return () => document.removeEventListener('click', handler);
  }, [onClose]);

  const items = [
    {
      label: bookmarked ? 'Remove Bookmark' : 'Bookmark Event',
      Icon: bookmarked ? BookmarkCheck : Bookmark,
      action: onBookmark,
    },
    {
      label: 'Copy Message',
      Icon: Copy,
      action: () => navigator.clipboard.writeText(ev.message),
    },
    {
      label: 'Copy as JSON',
      Icon: Copy,
      action: () => navigator.clipboard.writeText(JSON.stringify(ev, null, 2)),
    },
    ...(ev.hostname ? [{
      label: `Filter by Host: ${ev.hostname}`,
      Icon: Filter,
      action: () => { /* parent handles via onClose + state */ },
    }] : []),
  ];

  return (
    <div ref={ref}
      style={{
        position: 'fixed', top: y, left: x, zIndex: 9999,
        background: 'var(--glass-bg)', border: '1px solid var(--border)',
        borderRadius: 8, minWidth: 200, padding: '4px 0',
        boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
      }}>
      {items.map(({ label, Icon, action }) => (
        <button key={label} onClick={(e) => { e.stopPropagation(); action(); onClose(); }}
          className="w-full flex items-center gap-2 px-3 py-2 text-xs text-left transition-colors"
          style={{ color: 'var(--text-1)' }}
          onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--accent-glow)'}
          onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}>
          <Icon className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />
          {label}
        </button>
      ))}
    </div>
  );
}

// ── Event card ────────────────────────────────────────────────────────────────

function EventCard({ ev, selected, bookmarked, onSelect, onBookmark, onContextMenu }: {
  ev: TimelineEvent;
  selected: boolean;
  bookmarked: boolean;
  onSelect: () => void;
  onBookmark: () => void;
  onContextMenu: (e: React.MouseEvent) => void;
}) {
  const cat = CATEGORY[ev.event_type] ?? { label: ev.event_type, color: 'var(--accent)', Icon: Activity };
  const sev = ev.severity ?? 'info';
  const color = cat.color;
  const Icon  = cat.Icon;

  return (
    <div
      className="relative flex gap-3 group cursor-pointer"
      onClick={onSelect}
      onContextMenu={onContextMenu}
    >
      {/* Timeline node */}
      <div className="shrink-0 flex flex-col items-center" style={{ width: 28 }}>
        <div className="flex h-7 w-7 items-center justify-center rounded-full z-10 transition-transform group-hover:scale-110"
          style={{
            background: selected ? color : `${color}22`,
            border: `2px solid ${color}`,
          }}>
          <Icon className="h-3 w-3" style={{ color: selected ? '#fff' : color }} />
        </div>
      </div>

      {/* Card */}
      <div className="flex-1 mb-3 rounded-xl px-4 py-3 transition-all"
        style={{
          background: selected ? `${color}11` : 'var(--glass-bg)',
          border:     `1px solid ${selected ? color : 'var(--border)'}`,
          borderLeft: `3px solid ${SEV_COLOR[sev] ?? color}`,
        }}
        onMouseEnter={e => { if (!selected) (e.currentTarget as HTMLElement).style.borderColor = `${color}66`; }}
        onMouseLeave={e => { if (!selected) (e.currentTarget as HTMLElement).style.borderColor = 'var(--border)'; }}
      >
        {/* Header row */}
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-1.5 min-w-0 flex-wrap">
            <span className="text-[10px] font-bold uppercase rounded px-1.5 py-0.5 shrink-0"
              style={{ background: `${color}22`, color, border: `1px solid ${color}44` }}>
              {cat.label}
            </span>

            {sev !== 'info' && (
              <span className="text-[10px] font-semibold capitalize shrink-0 rounded px-1.5 py-0.5"
                style={{ background: SEV_BG[sev], color: SEV_COLOR[sev] }}>
                {sev}
              </span>
            )}

            {ev.hostname && (
              <span className="mono text-[10px] shrink-0 rounded px-1.5 py-0.5"
                style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                {ev.hostname}
              </span>
            )}

            {ev.username && (
              <span className="text-[10px] shrink-0 rounded px-1.5 py-0.5"
                style={{ background: 'rgba(0,0,0,0.2)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>
                {ev.username}
              </span>
            )}

            {ev.mitre_technique && (
              <span className="text-[10px] rounded px-1.5 py-0.5 font-mono shrink-0"
                style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}
                title={ev.mitre_name}>
                {ev.mitre_technique}
              </span>
            )}
          </div>

          <div className="flex items-center gap-1.5 shrink-0">
            {bookmarked && (
              <BookmarkCheck className="h-3 w-3" style={{ color: 'var(--accent)' }} />
            )}
            <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
              {timeAgo(ev.created_at)}
            </span>
          </div>
        </div>

        {/* Message */}
        <p className="text-xs mt-1.5 leading-relaxed font-mono break-all" style={{ color: 'var(--text-1)' }}>
          {ev.message}
        </p>

        {/* Process + source row */}
        {(ev.process_name || ev.source) && (
          <div className="flex items-center gap-2 mt-1.5">
            {ev.process_name && (
              <span className="text-[10px] font-mono" style={{ color: 'var(--text-3)' }}>
                proc: {ev.process_name}
              </span>
            )}
            {ev.source && (
              <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                · {ev.source}
              </span>
            )}
          </div>
        )}

        {ev.mitre_name && (
          <p className="text-[10px] mt-1 italic" style={{ color: 'var(--text-3)' }}>
            MITRE: {ev.mitre_name}
          </p>
        )}
      </div>
    </div>
  );
}

// ── Stats bar ─────────────────────────────────────────────────────────────────

function StatsBar({ stats, activeTypes, onToggle }: {
  stats: Record<string, number>;
  activeTypes: string[];
  onToggle: (t: string) => void;
}) {
  const total = Object.values(stats).reduce((a, b) => a + b, 0);
  if (total === 0) return null;

  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      <span className="text-[10px] font-semibold uppercase mr-1" style={{ color: 'var(--text-3)' }}>
        7d stats:
      </span>
      {Object.entries(stats)
        .sort((a, b) => b[1] - a[1])
        .map(([type, count]) => {
          const meta   = CATEGORY[type] ?? { label: type, color: 'var(--text-3)', Icon: Activity };
          const active = activeTypes.length === 0 || activeTypes.includes(type);
          return (
            <button key={type} onClick={() => onToggle(type)}
              className="flex items-center gap-1 text-[10px] px-2 py-1 rounded-lg transition-all"
              style={{
                background: active ? `${meta.color}18` : 'var(--glass-bg)',
                border: `1px solid ${active ? meta.color + '55' : 'var(--border)'}`,
                color: active ? meta.color : 'var(--text-3)',
              }}>
              <meta.Icon className="h-2.5 w-2.5" />
              {meta.label}
              <span className="font-bold ml-0.5">{count.toLocaleString()}</span>
            </button>
          );
        })}
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function TimelinePage() {
  const [agents, setAgents]               = useState<Agent[]>([]);
  const [events, setEvents]               = useState<TimelineEvent[]>([]);
  const [stats, setStats]                 = useState<Record<string, number>>({});
  const [loading, setLoading]             = useState(true);
  const [refreshing, setRefreshing]       = useState(false);
  const [search, setSearch]               = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [catFilter, setCatFilter]         = useState<string[]>([]);
  const [severityFilter, setSeverityFilter] = useState('');
  const [agentId, setAgentId]             = useState<number | 'all'>('all');
  const [rangeHours, setRangeHours]       = useState(24);
  const [liveMode, setLiveMode]           = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | null>(null);
  const [bookmarks, setBookmarks]         = useState<Set<number>>(new Set());
  const [showBookmarksOnly, setShowBookmarksOnly] = useState(false);
  const [contextMenu, setContextMenu]     = useState<{ x: number; y: number; ev: TimelineEvent } | null>(null);
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [showFilters, setShowFilters]     = useState(false);
  const liveTimer                         = useRef<ReturnType<typeof setInterval> | null>(null);

  // Debounce search
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search), 400);
    return () => clearTimeout(t);
  }, [search]);

  const buildTimeParams = useCallback(() => {
    if (rangeHours === Infinity) return {};
    const to   = new Date();
    const from = new Date(Date.now() - rangeHours * 3600000);
    return { from: from.toISOString(), to: to.toISOString() };
  }, [rangeHours]);

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    else setLoading(true);
    try {
      const [agRes, statsRes] = await Promise.all([
        agentsAPI.getAll(),
        timelineAPI.stats(),
      ]);
      setAgents(agRes.data || []);
      setStats(statsRes.data || {});

      const params: Parameters<typeof timelineAPI.get>[0] = {
        limit: 500,
        event_types: catFilter.length > 0 ? catFilter.join(',') : undefined,
        severity: severityFilter || undefined,
        agent_id: agentId === 'all' ? undefined : agentId,
        search: debouncedSearch || undefined,
        ...buildTimeParams(),
      };

      let res: { data: TimelineEvent[] | null };
      if (agentId !== 'all') {
        const r = await agentsAPI.getTimeline(agentId as number);
        res = r as { data: TimelineEvent[] | null };
      } else {
        res = (await timelineAPI.get(params)) as { data: TimelineEvent[] | null };
      }

      const all: TimelineEvent[] = (res?.data || []);
      all.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
      setEvents(all);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [catFilter, severityFilter, agentId, debouncedSearch, buildTimeParams]);

  // Initial + filter change load
  useEffect(() => { load(); }, [load]);

  // Live mode timer
  useEffect(() => {
    if (liveTimer.current) clearInterval(liveTimer.current);
    if (liveMode) {
      liveTimer.current = setInterval(() => load(true), 30000);
    }
    return () => { if (liveTimer.current) clearInterval(liveTimer.current); };
  }, [liveMode, load]);

  // Client-side filtering for bookmark-only view
  const filtered = useMemo(() => {
    let list = events;
    if (showBookmarksOnly) {
      list = list.filter(e => e.id != null && bookmarks.has(e.id));
    }
    return list;
  }, [events, showBookmarksOnly, bookmarks]);

  // Group by day
  const grouped = useMemo(() => {
    const map = new Map<string, TimelineEvent[]>();
    filtered.forEach(e => {
      const k = dayKey(e.created_at);
      if (!map.has(k)) map.set(k, []);
      map.get(k)!.push(e);
    });
    return Array.from(map.entries()).sort((a, b) => b[0].localeCompare(a[0]));
  }, [filtered]);

  const toggleCat = (c: string) => {
    setCatFilter(f => f.includes(c) ? f.filter(x => x !== c) : [...f, c]);
    setSelectedEvent(null);
  };

  const toggleBookmark = (ev: TimelineEvent) => {
    if (ev.id == null) return;
    setBookmarks(b => {
      const next = new Set(b);
      next.has(ev.id!) ? next.delete(ev.id!) : next.add(ev.id!);
      return next;
    });
  };

  const handleContextMenu = (e: React.MouseEvent, ev: TimelineEvent) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, ev });
  };

  const allEventTypes = useMemo(() => {
    const types = new Set(events.map(e => e.event_type));
    return Array.from(types).sort();
  }, [events]);

  const activeFilterCount = [
    catFilter.length > 0,
    !!severityFilter,
    agentId !== 'all',
    showBookmarksOnly,
  ].filter(Boolean).length;

  return (
    <RootLayout title="Timeline" subtitle="Forensic investigation backbone"
      onRefresh={() => load(true)} refreshing={refreshing}>

      <div className="flex gap-0" style={{ height: 'calc(100vh - 140px)', overflow: 'hidden' }}>

        {/* ── Main timeline column ── */}
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">

          {/* Toolbar */}
          <div className="flex items-center gap-2 flex-wrap mb-3">
            {/* Search */}
            <div className="relative min-w-[200px] flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5"
                style={{ color: 'var(--text-3)' }} />
              <input value={search} onChange={e => setSearch(e.target.value)}
                placeholder="Search message, host, user, process…"
                className="g-input pl-9" style={{ width: '100%' }} />
              {search && (
                <button onClick={() => setSearch('')}
                  className="absolute right-3 top-1/2 -translate-y-1/2">
                  <X className="h-3 w-3" style={{ color: 'var(--text-3)' }} />
                </button>
              )}
            </div>

            {/* Time range */}
            <div className="flex items-center gap-1">
              {DATE_RANGES.map(r => (
                <button key={r.label} onClick={() => setRangeHours(r.hours)}
                  className="text-xs px-2.5 py-1.5 rounded-lg transition-all"
                  style={{
                    background: rangeHours === r.hours ? 'var(--accent-glow)' : 'var(--glass-bg)',
                    border:     `1px solid ${rangeHours === r.hours ? 'var(--accent-border)' : 'var(--border)'}`,
                    color:      rangeHours === r.hours ? 'var(--accent)' : 'var(--text-2)',
                  }}>
                  {r.label}
                </button>
              ))}
            </div>

            {/* Agent selector */}
            <select value={agentId}
              onChange={e => setAgentId(e.target.value === 'all' ? 'all' : Number(e.target.value))}
              className="g-select" style={{ minWidth: 160 }}>
              <option value="all">All Agents</option>
              {agents.map(a => <option key={a.id} value={a.id}>{a.hostname}</option>)}
            </select>

            {/* Filters toggle */}
            <button onClick={() => setShowFilters(x => !x)}
              className="g-btn g-btn-ghost flex items-center gap-1.5 relative"
              style={{ color: activeFilterCount > 0 ? 'var(--accent)' : undefined }}>
              <SlidersHorizontal className="h-3.5 w-3.5" />
              Filters
              {activeFilterCount > 0 && (
                <span className="absolute -top-1 -right-1 h-4 w-4 rounded-full text-[9px] font-bold flex items-center justify-center"
                  style={{ background: 'var(--accent)', color: '#000' }}>
                  {activeFilterCount}
                </span>
              )}
            </button>

            {/* Live mode */}
            <button
              onClick={() => setLiveMode(x => !x)}
              className="g-btn g-btn-ghost flex items-center gap-1.5"
              style={{ color: liveMode ? 'var(--green)' : undefined }}>
              <Zap className={`h-3.5 w-3.5 ${liveMode ? 'animate-pulse' : ''}`} />
              Live
            </button>

            {/* Bookmarks toggle */}
            <button onClick={() => setShowBookmarksOnly(x => !x)}
              className="g-btn g-btn-ghost flex items-center gap-1.5"
              style={{ color: showBookmarksOnly ? 'var(--accent)' : undefined }}>
              <Bookmark className="h-3.5 w-3.5" />
              {bookmarks.size > 0 ? bookmarks.size : ''}
            </button>

            {/* Export */}
            <div className="relative">
              <button onClick={() => setShowExportMenu(x => !x)}
                className="g-btn g-btn-ghost flex items-center gap-1.5">
                <Download className="h-3.5 w-3.5" />
                Export
              </button>
              {showExportMenu && (
                <div className="absolute right-0 top-full mt-1 rounded-lg overflow-hidden z-50"
                  style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', minWidth: 140 }}>
                  <button onClick={() => { exportJSON(filtered); setShowExportMenu(false); }}
                    className="w-full text-left px-3 py-2 text-xs hover:bg-accent-glow transition-colors"
                    style={{ color: 'var(--text-1)' }}>
                    Export JSON
                  </button>
                  <button onClick={() => { exportCSV(filtered); setShowExportMenu(false); }}
                    className="w-full text-left px-3 py-2 text-xs hover:bg-accent-glow transition-colors"
                    style={{ color: 'var(--text-1)' }}>
                    Export CSV
                  </button>
                </div>
              )}
            </div>

            <span className="text-xs ml-auto shrink-0" style={{ color: 'var(--text-3)' }}>
              {filtered.length.toLocaleString()} events
            </span>
          </div>

          {/* Expanded filters panel */}
          {showFilters && (
            <div className="mb-3 rounded-xl p-3 space-y-2"
              style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
              {/* Event type chips */}
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[10px] font-semibold uppercase shrink-0 mr-1" style={{ color: 'var(--text-3)' }}>
                  Type
                </span>
                <button onClick={() => setCatFilter([])}
                  className="text-[10px] px-2 py-1 rounded-lg transition-all"
                  style={{
                    background: catFilter.length === 0 ? 'var(--accent-glow)' : 'var(--glass-bg)',
                    border:     `1px solid ${catFilter.length === 0 ? 'var(--accent-border)' : 'var(--border)'}`,
                    color:      catFilter.length === 0 ? 'var(--accent)' : 'var(--text-2)',
                  }}>
                  All
                </button>
                {allEventTypes.map(c => {
                  const meta   = CATEGORY[c] ?? { label: c, color: 'var(--accent)', Icon: Activity };
                  const active = catFilter.includes(c);
                  return (
                    <button key={c} onClick={() => toggleCat(c)}
                      className="flex items-center gap-1 text-[10px] px-2 py-1 rounded-lg transition-all"
                      style={{
                        background: active ? `${meta.color}22` : 'var(--glass-bg)',
                        border:     `1px solid ${active ? meta.color : 'var(--border)'}`,
                        color:      active ? meta.color : 'var(--text-2)',
                      }}>
                      <meta.Icon className="h-2.5 w-2.5" />
                      {meta.label}
                    </button>
                  );
                })}
              </div>

              {/* Severity filter */}
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[10px] font-semibold uppercase shrink-0 mr-1" style={{ color: 'var(--text-3)' }}>
                  Severity
                </span>
                {['', 'critical', 'high', 'medium', 'low', 'info'].map(s => (
                  <button key={s} onClick={() => setSeverityFilter(s)}
                    className="text-[10px] px-2 py-1 rounded-lg capitalize transition-all"
                    style={{
                      background: severityFilter === s ? (s ? SEV_BG[s] : 'var(--accent-glow)') : 'var(--glass-bg)',
                      border:     `1px solid ${severityFilter === s ? (s ? SEV_COLOR[s] : 'var(--accent-border)') : 'var(--border)'}`,
                      color:      severityFilter === s ? (s ? SEV_COLOR[s] : 'var(--accent)') : 'var(--text-2)',
                    }}>
                    {s || 'All'}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* 7-day stats bar */}
          {Object.keys(stats).length > 0 && (
            <div className="mb-3">
              <StatsBar stats={stats} activeTypes={catFilter} onToggle={toggleCat} />
            </div>
          )}

          {/* Timeline body */}
          <div className="flex-1 overflow-y-auto pr-1" style={{ scrollbarWidth: 'thin' }}>
            {loading ? (
              <div className="py-16 text-center animate-pulse text-sm" style={{ color: 'var(--text-3)' }}>
                Loading timeline…
              </div>
            ) : filtered.length === 0 ? (
              <div className="g-card py-16 text-center">
                <Clock className="mx-auto h-10 w-10 mb-3" style={{ color: 'var(--text-3)' }} />
                <p className="text-sm" style={{ color: 'var(--text-2)' }}>No events match your filters.</p>
                {activeFilterCount > 0 && (
                  <button className="mt-3 text-xs" style={{ color: 'var(--accent)' }}
                    onClick={() => { setCatFilter([]); setSeverityFilter(''); setSearch(''); setShowBookmarksOnly(false); }}>
                    Clear all filters
                  </button>
                )}
              </div>
            ) : (
              <div className="space-y-6">
                {grouped.map(([dk, evs]) => (
                  <div key={dk}>
                    {/* Day header */}
                    <div className="flex items-center gap-2 mb-3 sticky top-0 z-10 py-1"
                      style={{ background: 'transparent', backdropFilter: 'blur(8px)' }}>
                      <span className="text-xs font-bold" style={{ color: 'var(--text-1)' }}>
                        {dayLabel(dk)}
                      </span>
                      <span className="text-xs" style={{ color: 'var(--text-3)' }}>{dk}</span>
                      <span className="text-[10px] rounded-full px-2 py-0.5"
                        style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-3)' }}>
                        {evs.length}
                      </span>
                      <div className="flex-1 h-px" style={{ background: 'var(--border)' }} />
                    </div>

                    {/* Events */}
                    <div className="relative">
                      <div className="absolute left-[13px] top-0 bottom-0 w-px"
                        style={{ background: 'var(--border)' }} />
                      {evs.map((ev, i) => (
                        <EventCard
                          key={ev.id ?? i}
                          ev={ev}
                          selected={selectedEvent?.id === ev.id && selectedEvent?.created_at === ev.created_at}
                          bookmarked={ev.id != null && bookmarks.has(ev.id)}
                          onSelect={() => setSelectedEvent(s =>
                            s?.id === ev.id && s?.created_at === ev.created_at ? null : ev
                          )}
                          onBookmark={() => toggleBookmark(ev)}
                          onContextMenu={(e) => handleContextMenu(e, ev)}
                        />
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* ── Evidence panel ── */}
        {selectedEvent && (
          <EvidencePanel
            ev={selectedEvent}
            onClose={() => setSelectedEvent(null)}
            bookmarked={selectedEvent.id != null && bookmarks.has(selectedEvent.id)}
            onBookmark={() => toggleBookmark(selectedEvent)}
          />
        )}
      </div>

      {/* Context menu */}
      {contextMenu && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          ev={contextMenu.ev}
          bookmarked={contextMenu.ev.id != null && bookmarks.has(contextMenu.ev.id)}
          onBookmark={() => toggleBookmark(contextMenu.ev)}
          onClose={() => setContextMenu(null)}
        />
      )}

      {/* Close export menu on outside click */}
      {showExportMenu && (
        <div className="fixed inset-0 z-40" onClick={() => setShowExportMenu(false)} />
      )}
    </RootLayout>
  );
}
