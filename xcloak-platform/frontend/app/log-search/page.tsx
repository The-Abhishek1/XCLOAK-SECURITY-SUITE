'use client';

import {
  useState, useEffect, useCallback, useRef, useMemo, ReactNode,
} from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { logSearchAPI, agentsAPI, iocsAPI } from '@/lib/api';
import { Agent } from '@/types';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import { AlertCircle, AlertTriangle, AlignLeft, ArrowRight, BarChart2, BookOpen, Bookmark as BookmarkIcon, BookmarkCheck, Calendar, Check, ChevronDown, ChevronRight, ChevronUp, Clock, Code, Copy, Download, ExternalLink, Eye, EyeOff, FileJson, FileText, Filter, GitMerge, Globe, Hash, Layers, Link2, Monitor, Play, Plus, RefreshCw, Search, ShieldAlert, SlidersHorizontal, Sparkles, Star, StarOff, Table2, Terminal, Trash2, TrendingUp, User, X } from '@/lib/icon-stubs';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface LogEntry {
  id: number; agent_id: number; log_source: string;
  log_message: string; parsed_fields: string; collected_at: string;
}
interface LogStats {
  total: number; search_time_ms?: number; docs_scanned?: number;
  hourly_volume: { hour: string; count: number }[];
  top_sources?: { name: string; count: number }[];
}
interface SavedLogSearch {
  id: number; name: string; query: string; time_range: string;
  run_count: number; last_run_at?: string; created_by?: string;
}
interface FieldMeta {
  name: string; type: string; count: number;
  null_count: number; unique_count: number;
  top_values: { value: string; count: number }[];
}
interface SearchTemplate {
  id: string; name: string; category: string;
  description: string; query: string; time_range: string; tags: string[];
}
interface ScheduledSearch {
  id: number; name: string; query: string; time_range: string;
  schedule: string; action: string; enabled: boolean; created_at: string;
}
interface QueryTerm { type: 'text'|'field'|'regex'; field?: string; value: string; negate: boolean; }
interface PipeCmd   { type: 'stats'|'top'|'timechart'|'correlate'; field?: string; n?: number; span?: string; within?: number; }
interface AggRow    { label: string; count: number; }
interface CorrGroup { value: string; count: number; span_min: number; events: LogEntry[]; }
interface Pivot     { field: string; value: string; }
interface Bookmark  { id: string; type: 'event'|'query'; label: string; query?: string; logId?: number; ts: number; }

type ViewMode   = 'table' | 'json' | 'raw' | 'parsed' | 'viz';
type RightTab   = 'context' | 'intelligence' | 'related';
type QLang      = 'kql' | 'lucene' | 'sql' | 'nl';
type VizType    = 'bar' | 'pie' | 'area';
type LeftTab    = 'fields' | 'saved' | 'templates' | 'bookmarks' | 'scheduled';

const LS_HIST = 'xcloak_search_history';
const LS_BM   = 'xcloak_log_bookmarks';
const LIMIT   = 100;

const TIME_RANGES = [
  { label: '5m', value: '5m' }, { label: '15m', value: '15m' },
  { label: '1h', value: '1h' }, { label: '6h', value: '6h' },
  { label: '24h', value: '24h' }, { label: 'Today', value: 'today' },
  { label: 'Yesterday', value: 'yesterday' }, { label: '7d', value: '7d' },
  { label: '30d', value: '30d' },
];

const CHART_COLORS = ['var(--accent)', 'var(--green)', 'var(--orange)', 'var(--yellow)', 'var(--red)', '#a78bfa', '#34d399'];

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)', error: 'var(--red)', warn: 'var(--yellow)',
  warning: 'var(--yellow)', info: 'var(--text-3)',
};

// ─────────────────────────────────────────────────────────────────────────────
// Query parser
// ─────────────────────────────────────────────────────────────────────────────

function parseQStr(input: string): { terms: QueryTerm[]; pipes: PipeCmd[] } {
  const [rawQ, ...rawPipes] = input.split('|');
  const pipes: PipeCmd[] = rawPipes.map(p => {
    const t = p.trim();
    const sm = t.match(/^stats\s+count\s+by\s+(\w+)/i);  if (sm) return { type: 'stats', field: sm[1] };
    const tm = t.match(/^top\s+(\d+)\s+(\w+)/i);         if (tm) return { type: 'top', n: +tm[1], field: tm[2] };
    const ts = t.match(/^top\s+(\w+)/i);                  if (ts) return { type: 'top', n: 10, field: ts[1] };
    const tc = t.match(/^timechart(?:\s+span=(\w+))?/i); if (tc) return { type: 'timechart', span: tc[1] || '1h' };
    const cr = t.match(/^correlate\s+(\w+)\s+within\s+(\d+)m?/i); if (cr) return { type: 'correlate', field: cr[1], within: +cr[2] };
    return { type: 'stats', field: 'log_source' };
  }) as PipeCmd[];

  const terms: QueryTerm[] = [];
  const RE = /(-?)(?:(\w[\w.]*):("(?:[^"\\]|\\.)*"|\S+)|"((?:[^"\\]|\\.)*)"|(\/[^\/]+\/)|(\S+))/g;
  let m: RegExpExecArray | null;
  while ((m = RE.exec(rawQ)) !== null) {
    const neg = m[1] === '-';
    if (m[2] && m[3]) {
      terms.push({ type: 'field', field: m[2], value: m[3].startsWith('"') ? m[3].slice(1,-1) : m[3], negate: neg });
    } else if (m[4] !== undefined) {
      terms.push({ type: 'text', value: m[4], negate: neg });
    } else if (m[5]) {
      terms.push({ type: 'regex', value: m[5].slice(1,-1), negate: neg });
    } else if (m[6] && !['AND','OR','NOT'].includes(m[6].toUpperCase())) {
      // fuzzy: ends with ~
      const fuzzy = m[6].endsWith('~');
      terms.push({ type: 'text', value: fuzzy ? m[6].slice(0,-1) : m[6], negate: neg });
    }
  }
  return { terms, pipes };
}

function matchLog(log: LogEntry, terms: QueryTerm[]): boolean {
  if (terms.length === 0) return true;
  let fields: Record<string, string> = {};
  try { fields = JSON.parse(log.parsed_fields || '{}'); } catch {}
  const msg = log.log_message.toLowerCase();
  for (const term of terms) {
    let hit = false;
    if (term.type === 'regex') {
      try { hit = new RegExp(term.value, 'i').test(log.log_message); } catch {}
    } else if (term.type === 'field' && term.field) {
      const fv = (fields[term.field] ?? '').toLowerCase();
      hit = term.value.includes('*')
        ? new RegExp('^' + term.value.replace(/\*/g, '.*') + '$', 'i').test(fv)
        : fv === term.value.toLowerCase();
    } else {
      const v = term.value.toLowerCase();
      hit = msg.includes(v) || Object.values(fields).some(fv => String(fv).toLowerCase().includes(v));
    }
    if (term.negate ? hit : !hit) return false;
  }
  return true;
}

function computeAgg(logs: LogEntry[], cmd: PipeCmd): AggRow[] {
  const counts = new Map<string, number>();
  for (const log of logs) {
    let v = '';
    try { v = (JSON.parse(log.parsed_fields || '{}') as any)[cmd.field!] ?? ''; } catch {}
    if (!v) v = cmd.field === 'log_source' ? log.log_source : '(empty)';
    counts.set(v, (counts.get(v) ?? 0) + 1);
  }
  return Array.from(counts.entries()).map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count).slice(0, cmd.n ?? 20);
}

function computeCorr(logs: LogEntry[], field: string, withinMin: number): CorrGroup[] {
  const groups = new Map<string, LogEntry[]>();
  for (const log of logs) {
    let v = ''; try { v = (JSON.parse(log.parsed_fields || '{}') as any)[field] ?? ''; } catch {}
    if (!v) continue;
    if (!groups.has(v)) groups.set(v, []);
    groups.get(v)!.push(log);
  }
  const result: CorrGroup[] = [];
  for (const [value, evts] of groups) {
    if (evts.length < 2) continue;
    const times = evts.map(e => new Date(e.collected_at).getTime()).sort((a, b) => a - b);
    const span = (times[times.length - 1] - times[0]) / 60000;
    if (span <= withinMin) result.push({ value, count: evts.length, span_min: Math.round(span), events: evts });
  }
  return result.sort((a, b) => b.count - a.count);
}

function severityOf(log: LogEntry): string {
  const m = log.log_message.toLowerCase();
  if (m.includes('critical') || m.includes('fatal')) return 'critical';
  if (m.includes('error') || m.includes('failed') || m.includes('failure')) return 'error';
  if (m.includes('warn')) return 'warn';
  return '';
}

function hlText(text: string, term: string): ReactNode {
  if (!term) return text;
  try {
    const esc = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const parts = text.split(new RegExp(`(${esc})`, 'gi'));
    return parts.map((p, i) =>
      p.toLowerCase() === term.toLowerCase()
        ? <mark key={i} style={{ background: 'var(--yellow)', color: 'var(--bg-0)', borderRadius: 2 }}>{p}</mark>
        : p
    );
  } catch { return text; }
}

function loadHistory(): string[] { try { return JSON.parse(localStorage.getItem(LS_HIST) ?? '[]'); } catch { return []; } }
function pushHistory(q: string)  {
  if (!q.trim()) return;
  const h = [q, ...loadHistory().filter(x => x !== q)].slice(0, 30);
  localStorage.setItem(LS_HIST, JSON.stringify(h));
}
function loadBookmarks(): Bookmark[] { try { return JSON.parse(localStorage.getItem(LS_BM) ?? '[]'); } catch { return []; } }
function saveBookmarks(bm: Bookmark[]) { localStorage.setItem(LS_BM, JSON.stringify(bm)); }

// ─────────────────────────────────────────────────────────────────────────────
// Field type icon
// ─────────────────────────────────────────────────────────────────────────────

function FieldTypeIcon({ type }: { type: string }) {
  const icons: Record<string, ReactNode> = {
    ip: <Globe className="h-2.5 w-2.5" />, number: <Hash className="h-2.5 w-2.5" />,
    date: <Calendar className="h-2.5 w-2.5" />, keyword: <AlignLeft className="h-2.5 w-2.5" />,
    text: <FileText className="h-2.5 w-2.5" />,
  };
  return <span style={{ color: 'var(--text-3)' }}>{icons[type] ?? <Hash className="h-2.5 w-2.5" />}</span>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Field Explorer
// ─────────────────────────────────────────────────────────────────────────────

function FieldExplorer({ fields, onAddFilter }: {
  fields: FieldMeta[]; onAddFilter: (field: string, value: string) => void;
}) {
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);
  const filtered = fields.filter(f => f.name.toLowerCase().includes(search.toLowerCase()));
  return (
    <div className="space-y-2">
      <input value={search} onChange={e => setSearch(e.target.value)}
        placeholder="Filter fields…" className="g-input text-xs h-7 w-full" />
      <div className="space-y-0.5 max-h-[400px] overflow-y-auto">
        {filtered.map(f => (
          <div key={f.name}>
            <button className="w-full flex items-center gap-1.5 px-1.5 py-1 rounded text-left hover:bg-[var(--glass-hover)] transition-colors"
              onClick={() => setExpanded(e => e === f.name ? null : f.name)}>
              <FieldTypeIcon type={f.type} />
              <span className="text-[10px] font-mono flex-1 truncate" style={{ color: 'var(--text-1)' }}>{f.name}</span>
              <span className="text-[9px] shrink-0" style={{ color: 'var(--text-3)' }}>{f.count.toLocaleString()}</span>
              {expanded === f.name
                ? <ChevronUp className="h-2.5 w-2.5 shrink-0" style={{ color: 'var(--text-3)' }} />
                : <ChevronDown className="h-2.5 w-2.5 shrink-0" style={{ color: 'var(--text-3)' }} />}
            </button>
            {expanded === f.name && (
              <div className="ml-4 mb-1 rounded-lg overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                <div className="flex justify-between px-2 py-1.5 text-[9px]" style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-0)' }}>
                  <span style={{ color: 'var(--text-3)' }}>Unique: <strong style={{ color: 'var(--text-2)' }}>{f.unique_count}</strong></span>
                  <span style={{ color: 'var(--text-3)' }}>Null: <strong style={{ color: 'var(--text-2)' }}>{f.null_count}</strong></span>
                </div>
                {f.top_values.map(tv => {
                  const pct = f.count > 0 ? (tv.count / f.count) * 100 : 0;
                  return (
                    <button key={tv.value} onClick={() => onAddFilter(f.name, tv.value)}
                      className="w-full flex items-center gap-2 px-2 py-1 text-left hover:bg-[var(--glass-hover)] transition-colors group">
                      <div className="flex-1 min-w-0">
                        <span className="text-[10px] font-mono truncate block" style={{ color: 'var(--accent)' }}>{tv.value}</span>
                        <div className="h-1 mt-0.5 rounded-full" style={{ background: 'var(--border)' }}>
                          <div className="h-full rounded-full" style={{ width: `${pct}%`, background: 'var(--accent)' }} />
                        </div>
                      </div>
                      <span className="text-[9px] shrink-0" style={{ color: 'var(--text-3)' }}>{tv.count}</span>
                      <Plus className="h-3 w-3 opacity-0 group-hover:opacity-100 shrink-0" style={{ color: 'var(--accent)' }} />
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        ))}
        {filtered.length === 0 && <p className="text-[10px] text-center py-4" style={{ color: 'var(--text-3)' }}>No fields found</p>}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Context / right panel
// ─────────────────────────────────────────────────────────────────────────────

function ContextPanel({ log, allLogs, tab, onTabChange, onPivot, bookmarks, onBookmark }: {
  log: LogEntry | null; allLogs: LogEntry[]; tab: RightTab;
  onTabChange: (t: RightTab) => void; onPivot: (f: string, v: string) => void;
  bookmarks: Bookmark[]; onBookmark: (bm: Bookmark) => void;
}) {
  const [copied, setCopied] = useState(false);
  let fields: Record<string, string> = {};
  if (log) { try { fields = JSON.parse(log.parsed_fields || '{}'); } catch {} }

  const isBookmarked = log ? bookmarks.some(b => b.logId === log.id) : false;
  const addBookmark = () => {
    if (!log) return;
    const bm: Bookmark = { id: String(Date.now()), type: 'event', label: log.log_message.slice(0, 60), logId: log.id, ts: Date.now() };
    onBookmark(bm);
  };

  const related = log ? allLogs.filter(l => l.id !== log.id && l.log_source === log.log_source).slice(-5) : [];

  const TABS: { id: RightTab; label: string }[] = [
    { id: 'context', label: 'Detail' }, { id: 'related', label: 'Related' }, { id: 'intelligence', label: 'Intel' },
  ];

  return (
    <div className="flex flex-col h-full">
      <div className="flex shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => onTabChange(t.id)}
            className="flex-1 py-2.5 text-[10px] font-semibold transition-colors"
            style={{ color: tab === t.id ? 'var(--accent)' : 'var(--text-3)', borderBottom: `2px solid ${tab === t.id ? 'var(--accent)' : 'transparent'}`, background: tab === t.id ? 'var(--accent-glow)' : 'transparent' }}>
            {t.label}
          </button>
        ))}
      </div>
      <div className="flex-1 overflow-y-auto p-3 space-y-3">
        {!log ? (
          <p className="text-[11px] text-center py-8" style={{ color: 'var(--text-3)' }}>Select a log to inspect</p>
        ) : tab === 'context' ? (
          <>
            <div className="flex gap-1.5 flex-wrap">
              <button onClick={addBookmark} className="g-btn g-btn-ghost text-[10px] h-7 flex items-center gap-1">
                {isBookmarked ? <BookmarkCheck className="h-3 w-3" style={{ color: 'var(--yellow)' }} /> : <BookmarkIcon className="h-3 w-3" />}
                {isBookmarked ? 'Saved' : 'Bookmark'}
              </button>
              <button onClick={() => { navigator.clipboard.writeText(JSON.stringify(log, null, 2)); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
                className="g-btn g-btn-ghost text-[10px] h-7 flex items-center gap-1">
                {copied ? <Check className="h-3 w-3" style={{ color: 'var(--green)' }} /> : <Copy className="h-3 w-3" />} Copy
              </button>
            </div>
            <div>
              <p className="text-[9px] uppercase font-semibold mb-1" style={{ color: 'var(--text-3)' }}>Raw Message</p>
              <pre className="text-[10px] font-mono leading-relaxed whitespace-pre-wrap break-all p-2 rounded-lg"
                style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border)', color: 'var(--text-1)' }}>
                {log.log_message}
              </pre>
            </div>
            <div>
              <p className="text-[9px] uppercase font-semibold mb-1" style={{ color: 'var(--text-3)' }}>Metadata</p>
              {[['Source', log.log_source], ['Agent', String(log.agent_id)], ['Time', new Date(log.collected_at).toLocaleString()]].map(([k,v]) => (
                <div key={k} className="flex gap-2 text-[10px] py-0.5">
                  <span className="w-14 shrink-0" style={{ color: 'var(--text-3)' }}>{k}</span>
                  <span className="font-mono" style={{ color: 'var(--text-1)' }}>{v}</span>
                </div>
              ))}
            </div>
            {Object.keys(fields).length > 0 && (
              <div>
                <p className="text-[9px] uppercase font-semibold mb-1.5" style={{ color: 'var(--text-3)' }}>Parsed Fields</p>
                <div className="space-y-0.5">
                  {Object.entries(fields).map(([k, v]) => (
                    <button key={k} onClick={() => onPivot(k, String(v))}
                      className="w-full flex items-center gap-2 text-[10px] text-left px-1.5 py-1 rounded hover:bg-[var(--glass-hover)] transition-colors group">
                      <span className="w-24 shrink-0 font-semibold" style={{ color: 'var(--text-3)' }}>{k}</span>
                      <span className="font-mono flex-1 truncate" style={{ color: 'var(--accent)' }}>{String(v)}</span>
                      <Plus className="h-3 w-3 opacity-0 group-hover:opacity-100 shrink-0" style={{ color: 'var(--text-3)' }} />
                    </button>
                  ))}
                </div>
              </div>
            )}
            <div>
              <p className="text-[9px] uppercase font-semibold mb-1" style={{ color: 'var(--text-3)' }}>Quick Actions</p>
              <div className="grid grid-cols-2 gap-1">
                {[
                  { label: 'Timeline', icon: TrendingUp, href: '/timeline' },
                  { label: 'Investigate Host', icon: Monitor, href: '/network-map' },
                  { label: 'Investigate User', icon: User, href: '/risk-posture' },
                  { label: 'Create Alert', icon: AlertTriangle, href: '/alerts' },
                  { label: 'Create Sigma', icon: Code, href: undefined },
                  { label: 'Hunt Similar', icon: Search, href: undefined },
                ].map(({ label, icon: Icon, href }) => (
                  <button key={label}
                    onClick={() => href && window.open(href, '_blank')}
                    className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg text-[10px] text-left transition-colors"
                    style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}
                    onMouseEnter={e => (e.currentTarget as HTMLElement).style.borderColor = 'var(--accent)'}
                    onMouseLeave={e => (e.currentTarget as HTMLElement).style.borderColor = 'var(--border)'}>
                    <Icon className="h-3 w-3 shrink-0" style={{ color: 'var(--text-3)' }} /> {label}
                  </button>
                ))}
              </div>
            </div>
          </>
        ) : tab === 'related' ? (
          <>
            <p className="text-[9px] uppercase font-semibold" style={{ color: 'var(--text-3)' }}>Same Source ({log.log_source})</p>
            {related.length === 0
              ? <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>No related logs in result set</p>
              : related.map(l => (
                <div key={l.id} className="text-[10px] font-mono p-1.5 rounded" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                  <span style={{ color: 'var(--text-3)' }}>{new Date(l.collected_at).toLocaleTimeString()} </span>
                  <span style={{ color: 'var(--text-2)' }}>{l.log_message.slice(0, 80)}</span>
                </div>
              ))}
          </>
        ) : (
          <>
            <p className="text-[9px] uppercase font-semibold" style={{ color: 'var(--text-3)' }}>Threat Intelligence</p>
            {Object.entries(fields).filter(([k]) => ['src_ip','dst_ip','domain','url','hash'].includes(k)).map(([k, v]) => (
              <div key={k} className="rounded-lg p-2.5" style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>
                <p className="text-[9px] uppercase mb-1" style={{ color: 'var(--text-3)' }}>{k}</p>
                <p className="text-[10px] font-mono" style={{ color: 'var(--accent)' }}>{String(v)}</p>
                <div className="flex gap-1 mt-1.5">
                  <span className="text-[9px] px-1.5 py-0.5 rounded" style={{ background: 'rgba(239,68,68,0.1)', color: 'var(--red)', border: '1px solid rgba(239,68,68,0.3)' }}>Checking VT…</span>
                </div>
              </div>
            ))}
            {Object.keys(fields).filter(k => ['src_ip','dst_ip','domain','url','hash'].includes(k)).length === 0 && (
              <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>No enrichable indicators in this log</p>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Log row variants
// ─────────────────────────────────────────────────────────────────────────────

function LogRow({ log, search, onPivot, selected, onSelect, onCtxMenu }: {
  log: LogEntry; search: string; onPivot: (f: string, v: string) => void;
  selected: boolean; onSelect: () => void; onCtxMenu: (e: React.MouseEvent) => void;
}) {
  const [open, setOpen] = useState(false);
  const sev = severityOf(log);
  const sevCol = SEV_COLOR[sev];
  let fields: Record<string, string> = {};
  try { fields = JSON.parse(log.parsed_fields || '{}'); } catch {}
  const fieldEntries = Object.entries(fields).filter(([k]) => k !== 'extra');
  return (
    <div style={{ borderBottom: '1px solid var(--border)', background: selected ? 'var(--accent-glow)' : undefined, borderLeft: `2px solid ${selected ? 'var(--accent)' : 'transparent'}` }}
      onContextMenu={onCtxMenu}>
      <button className="w-full text-left px-3 py-1.5 flex items-start gap-2 transition-colors hover:bg-[var(--glass-hover)]"
        onClick={() => { setOpen(o => !o); onSelect(); }}>
        <span className="mt-1.5 shrink-0">
          {open ? <ChevronDown className="h-3 w-3" style={{ color: 'var(--text-3)' }} />
                : <ChevronRight className="h-3 w-3" style={{ color: 'var(--text-3)' }} />}
        </span>
        {sevCol && <span className="mt-2.5 h-1.5 w-1.5 rounded-full shrink-0" style={{ background: sevCol }} />}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-1.5 mb-0.5">
            <span className="text-[10px] font-mono shrink-0" style={{ color: 'var(--text-3)' }}>
              {new Date(log.collected_at).toLocaleString()}
            </span>
            <span className="text-[10px] px-1.5 py-0.5 rounded shrink-0"
              style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
              {log.log_source}
            </span>
            {sevCol && <span className="text-[9px] px-1 py-0.5 rounded font-semibold shrink-0"
              style={{ background: `${sevCol}22`, color: sevCol }}>{sev}</span>}
            {Object.entries(fields).slice(0, 3).map(([k, v]) => (
              <span key={k} className="text-[9px] px-1.5 rounded shrink-0" style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', color: 'var(--text-3)' }}>
                {k}:<span style={{ color: 'var(--accent)' }}>{String(v).slice(0,20)}</span>
              </span>
            ))}
          </div>
          <p className="text-[11px] font-mono leading-snug" style={{ color: 'var(--text-1)' }}>
            {open ? log.log_message : (log.log_message.length > 180 ? log.log_message.slice(0, 180) + '…' : log.log_message)}
          </p>
        </div>
      </button>
      {open && (
        <div className="px-8 pb-2 space-y-2">
          {search && (
            <pre className="text-[10px] font-mono leading-relaxed p-2 rounded overflow-x-auto whitespace-pre-wrap break-all"
              style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
              {hlText(log.log_message, search)}
            </pre>
          )}
          {fieldEntries.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {fieldEntries.map(([k, v]) => (
                <button key={k} onClick={() => onPivot(k, String(v))}
                  className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono hover:opacity-80 transition-opacity"
                  style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', color: 'var(--accent)' }}
                  title={`Add ${k}:${v} to query`}>
                  <span style={{ color: 'var(--text-3)', fontSize: 8 }}>{k}</span> {String(v)} <Link2 className="h-2.5 w-2.5 ml-0.5" />
                </button>
              ))}
            </div>
          )}
          <div className="flex items-center gap-4 text-[10px]" style={{ color: 'var(--text-3)' }}>
            <span>ID:{log.id}</span><span>Agent:{log.agent_id}</span>
            <button onClick={() => window.open('/timeline', '_blank')} className="flex items-center gap-1 hover:opacity-70" style={{ color: 'var(--accent)' }}>
              <ExternalLink className="h-3 w-3" /> Timeline
            </button>
            <button onClick={() => window.open('/alerts', '_blank')} className="flex items-center gap-1 hover:opacity-70" style={{ color: 'var(--accent)' }}>
              <Plus className="h-3 w-3" /> Create Alert
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function TableView({ logs, search, onPivot, selected, onSelect, onCtxMenu }: {
  logs: LogEntry[]; search: string; onPivot: (f: string, v: string) => void;
  selected: LogEntry | null; onSelect: (l: LogEntry) => void; onCtxMenu: (e: React.MouseEvent, l: LogEntry) => void;
}) {
  const COLS = ['Time', 'Source', 'Sev', 'Host', 'User', 'Message'];
  return (
    <div style={{ fontSize: 11, fontFamily: 'monospace' }}>
      <div className="flex sticky top-0 z-10" style={{ background: 'var(--bg-1)', borderBottom: '1px solid var(--border)' }}>
        {COLS.map((c, i) => (
          <div key={c} className="px-2 py-1.5 text-[9px] font-semibold uppercase shrink-0"
            style={{ color: 'var(--text-3)', width: [80, 100, 48, 100, 80][i], flex: i === 5 ? 1 : undefined }}>
            {c}
          </div>
        ))}
      </div>
      {logs.map((l, i) => {
        let fields: Record<string, string> = {};
        try { fields = JSON.parse(l.parsed_fields || '{}'); } catch {}
        const sev = severityOf(l);
        const sevCol = SEV_COLOR[sev];
        const isSel = selected?.id === l.id;
        return (
          <div key={l.id} className="flex items-center cursor-pointer transition-colors"
            style={{ background: isSel ? 'var(--accent-glow)' : i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)', borderLeft: `2px solid ${isSel ? 'var(--accent)' : 'transparent'}`, borderBottom: '1px solid rgba(255,255,255,0.03)' }}
            onClick={() => onSelect(l)} onContextMenu={e => onCtxMenu(e, l)}>
            <div className="px-2 py-1 shrink-0 truncate" style={{ width: 80, color: 'var(--text-3)' }}>{new Date(l.collected_at).toLocaleTimeString('en', { hour12: false })}</div>
            <div className="px-2 py-1 shrink-0 truncate" style={{ width: 100, color: 'var(--accent)' }}>{l.log_source}</div>
            <div className="px-2 py-1 shrink-0" style={{ width: 48, color: sevCol || 'var(--text-3)', fontSize: 9, fontWeight: 700 }}>{sev || '—'}</div>
            <div className="px-2 py-1 shrink-0 truncate" style={{ width: 100, color: 'var(--text-2)' }}>{fields.hostname || '—'}</div>
            <div className="px-2 py-1 shrink-0 truncate" style={{ width: 80, color: fields.user ? 'var(--accent)' : 'var(--text-3)' }}>{fields.user || fields.target_user || '—'}</div>
            <div className="px-2 py-1 flex-1 truncate" style={{ color: 'var(--text-1)' }}>{hlText(l.log_message.slice(0, 120), search)}</div>
          </div>
        );
      })}
    </div>
  );
}

function JsonView({ logs, selected, onSelect }: { logs: LogEntry[]; selected: LogEntry | null; onSelect: (l: LogEntry) => void }) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  return (
    <div className="p-2 space-y-1">
      {logs.map(l => {
        const isExp = expanded.has(l.id);
        const isSel = selected?.id === l.id;
        let parsed: Record<string, string> = {};
        try { parsed = JSON.parse(l.parsed_fields || '{}'); } catch {}
        return (
          <div key={l.id} className="rounded overflow-hidden cursor-pointer"
            style={{ border: `1px solid ${isSel ? 'var(--accent)' : 'var(--border)'}`, background: isSel ? 'var(--accent-glow)' : 'transparent' }}>
            <div className="flex items-center gap-2 px-2 py-1.5" onClick={() => { setExpanded(s => { const n = new Set(s); n.has(l.id) ? n.delete(l.id) : n.add(l.id); return n; }); onSelect(l); }}>
              {isExp ? <ChevronDown className="h-3 w-3 shrink-0" style={{ color: 'var(--text-3)' }} /> : <ChevronRight className="h-3 w-3 shrink-0" style={{ color: 'var(--text-3)' }} />}
              <span className="text-[10px] font-mono" style={{ color: 'var(--text-3)' }}>{new Date(l.collected_at).toLocaleTimeString('en', { hour12: false })}</span>
              <span className="text-[10px] font-mono flex-1 truncate" style={{ color: 'var(--text-1)' }}>{l.log_message.slice(0, 100)}</span>
            </div>
            {isExp && (
              <pre className="text-[10px] font-mono p-3 overflow-x-auto"
                style={{ background: 'rgba(0,0,0,0.3)', color: 'var(--text-2)', borderTop: '1px solid var(--border)' }}>
                {JSON.stringify({ id: l.id, ts: l.collected_at, source: l.log_source, parsed, message: l.log_message }, null, 2)}
              </pre>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Histogram
// ─────────────────────────────────────────────────────────────────────────────

function Histogram({ volume, drillIdx, onDrill }: {
  volume: { hour: string; count: number }[] | null | undefined; drillIdx: number | null; onDrill: (i: number | null) => void;
}) {
  const safeVolume = volume ?? [];
  const max = Math.max(...safeVolume.map(h => h.count), 1);
  return (
    <div className="flex items-end gap-0.5 h-12 px-1">
      {safeVolume.map((h, i) => (
        <button key={i} title={`${new Date(h.hour).toLocaleTimeString()} — ${h.count} events`}
          onClick={() => onDrill(drillIdx === i ? null : i)}
          className="flex-1 rounded-t-sm transition-all hover:opacity-100"
          style={{ height: `${Math.max(4, (h.count / max) * 100)}%`, background: 'var(--accent)', opacity: drillIdx === null ? (0.3 + (h.count / max) * 0.7) : (drillIdx === i ? 1 : 0.2) }} />
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Visualization panel
// ─────────────────────────────────────────────────────────────────────────────

function VizPanel({ aggRows, field, vizType, setVizType }: {
  aggRows: AggRow[]; field: string; vizType: VizType; setVizType: (v: VizType) => void;
}) {
  const chartData = aggRows.slice(0, 12).map(r => ({ name: r.label || '(empty)', value: r.count }));
  return (
    <div className="p-4 space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold" style={{ color: 'var(--text-2)' }}>
          Distribution by <code className="font-mono">{field}</code>
        </span>
        <div className="flex rounded-lg overflow-hidden" style={{ border: '1px solid var(--border)' }}>
          {(['bar', 'pie', 'area'] as VizType[]).map(v => (
            <button key={v} onClick={() => setVizType(v)}
              className="px-2.5 py-1 text-[10px] transition-colors"
              style={{ background: vizType === v ? 'var(--accent-glow)' : 'transparent', color: vizType === v ? 'var(--accent)' : 'var(--text-3)' }}>
              {v}
            </button>
          ))}
        </div>
      </div>
      <ResponsiveContainer width="100%" height={200}>
        {vizType === 'bar' ? (
          <BarChart data={chartData} margin={{ top: 4, right: 4, bottom: 30, left: 4 }}>
            <XAxis dataKey="name" tick={{ fontSize: 9, fill: 'var(--text-3)' }} angle={-35} textAnchor="end" interval={0} />
            <YAxis tick={{ fontSize: 9, fill: 'var(--text-3)' }} />
            <Tooltip contentStyle={{ background: 'var(--bg-1)', border: '1px solid var(--border)', fontSize: 10 }} />
            <Bar dataKey="value" fill="var(--accent)" radius={[3,3,0,0]} />
          </BarChart>
        ) : vizType === 'pie' ? (
          <PieChart>
            <Pie data={chartData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={({ name, percent }) => `${name} ${(percent*100).toFixed(0)}%`} labelLine={false}>
              {chartData.map((_, i) => <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />)}
            </Pie>
            <Tooltip contentStyle={{ background: 'var(--bg-1)', border: '1px solid var(--border)', fontSize: 10 }} />
          </PieChart>
        ) : (
          <AreaChart data={chartData} margin={{ top: 4, right: 4, bottom: 4, left: 4 }}>
            <XAxis dataKey="name" tick={{ fontSize: 9, fill: 'var(--text-3)' }} />
            <YAxis tick={{ fontSize: 9, fill: 'var(--text-3)' }} />
            <Tooltip contentStyle={{ background: 'var(--bg-1)', border: '1px solid var(--border)', fontSize: 10 }} />
            <defs><linearGradient id="vizGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="var(--accent)" stopOpacity={0.4} /><stop offset="95%" stopColor="var(--accent)" stopOpacity={0} /></linearGradient></defs>
            <Area type="monotone" dataKey="value" stroke="var(--accent)" fill="url(#vizGrad)" strokeWidth={2} dot={false} />
          </AreaChart>
        )}
      </ResponsiveContainer>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Context menu
// ─────────────────────────────────────────────────────────────────────────────

function CtxMenu({ x, y, log, onClose, onPivot, onBookmark, bookmarked }: {
  x: number; y: number; log: LogEntry; onClose: () => void;
  onPivot: (f: string, v: string) => void; onBookmark: () => void; bookmarked: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const h = () => onClose();
    setTimeout(() => document.addEventListener('click', h), 0);
    return () => document.removeEventListener('click', h);
  }, [onClose]);
  let fields: Record<string, string> = {};
  try { fields = JSON.parse(log.parsed_fields || '{}'); } catch {}
  const items = [
    { label: bookmarked ? 'Remove Bookmark' : 'Bookmark Event', icon: BookmarkIcon, action: onBookmark },
    { label: 'Copy Raw', icon: Copy, action: () => navigator.clipboard.writeText(log.log_message) },
    { label: 'Copy JSON', icon: FileJson, action: () => navigator.clipboard.writeText(JSON.stringify(log, null, 2)) },
    { label: '─', icon: null, action: () => {} },
    ...(fields.src_ip ? [{ label: `Filter src_ip:${fields.src_ip}`, icon: Filter, action: () => onPivot('src_ip', fields.src_ip) }] : []),
    ...(fields.hostname ? [{ label: `Filter host:${fields.hostname}`, icon: Monitor, action: () => onPivot('hostname', fields.hostname) }] : []),
    ...(fields.user || fields.target_user ? [{ label: `Filter user:${fields.user || fields.target_user}`, icon: User, action: () => onPivot('user', fields.user || fields.target_user) }] : []),
    { label: '─', icon: null, action: () => {} },
    { label: 'Open Timeline', icon: TrendingUp, action: () => window.open('/timeline', '_blank') },
    { label: 'Create Alert Rule', icon: AlertTriangle, action: () => {} },
    { label: 'Create Sigma Rule', icon: Code, action: () => {} },
    { label: 'Add to Case', icon: Plus, action: () => {} },
    { label: 'Hunt Similar', icon: Search, action: () => {} },
  ];
  return (
    <div ref={ref} style={{ position: 'fixed', top: y, left: x, zIndex: 9999, background: 'var(--glass-bg)', border: '1px solid var(--border)', borderRadius: 8, minWidth: 210, padding: '4px 0', boxShadow: '0 8px 32px rgba(0,0,0,0.6)', backdropFilter: 'blur(12px)' }}>
      {items.map(({ label, icon: Icon, action }, i) =>
        label === '─' ? <div key={i} style={{ borderTop: '1px solid var(--border)', margin: '3px 0' }} /> : (
          <button key={i} onClick={e => { e.stopPropagation(); action(); onClose(); }}
            className="w-full flex items-center gap-2 px-3 py-1.5 text-[11px] text-left transition-colors"
            style={{ color: 'var(--text-1)' }}
            onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--accent-glow)'}
            onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}>
            {Icon && <Icon className="h-3 w-3 shrink-0" style={{ color: 'var(--text-3)' }} />} {label}
          </button>
        )
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Detection builder modal
// ─────────────────────────────────────────────────────────────────────────────

function DetectionModal({ query, samples, onClose }: { query: string; samples: string[]; onClose: () => void }) {
  const [type, setType] = useState<'sigma'|'alert'>('sigma');
  const [name, setName] = useState('');
  const [result, setResult] = useState('');
  const [loading, setLoading] = useState(false);

  const build = async () => {
    if (!name.trim()) return;
    setLoading(true);
    try {
      const r = await logSearchAPI.buildDetection(type, query, name, samples.slice(0, 5));
      setResult((r as any).data?.rule ?? '');
    } catch { setResult('AI service unavailable'); }
    finally { setLoading(false); }
  };

  return (
    <div className="g-modal-backdrop" onClick={onClose}>
      <div className="g-modal" style={{ maxWidth: 600 }} onClick={e => e.stopPropagation()}>
        <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <span className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Detection Builder</span>
          <button onClick={onClose} style={{ color: 'var(--text-3)', fontSize: 18, lineHeight: 1 }} title="Close">×</button>
        </div>
        <div className="p-4 space-y-3">
          <div className="flex gap-2">
            {(['sigma', 'alert'] as const).map(t => (
              <button key={t} onClick={() => setType(t)}
                className={`flex-1 py-2 rounded-lg text-xs font-semibold transition-colors`}
                style={{ background: type === t ? 'var(--accent-glow)' : 'var(--bg-1)', color: type === t ? 'var(--accent)' : 'var(--text-3)', border: `1px solid ${type === t ? 'var(--accent-border)' : 'var(--border)'}` }}>
                {t === 'sigma' ? 'Sigma Rule' : 'Alert Rule'}
              </button>
            ))}
          </div>
          <input value={name} onChange={e => setName(e.target.value)} placeholder="Rule name…" className="g-input w-full" />
          <div className="rounded-lg p-2.5" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
            <p className="text-[9px] uppercase mb-1" style={{ color: 'var(--text-3)' }}>Search Query</p>
            <code className="text-[10px] font-mono" style={{ color: 'var(--accent)' }}>{query || '(all)'}</code>
          </div>
          <button onClick={build} disabled={loading || !name.trim()} className="w-full g-btn g-btn-primary flex items-center justify-center gap-2 disabled:opacity-40">
            {loading ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5" />}
            {loading ? 'Generating…' : 'Generate with AI'}
          </button>
          {result && (
            <div>
              <div className="flex items-center justify-between mb-1">
                <p className="text-[9px] uppercase" style={{ color: 'var(--text-3)' }}>Generated Rule</p>
                <button onClick={() => navigator.clipboard.writeText(result)} className="text-[10px] flex items-center gap-1" style={{ color: 'var(--accent)' }}>
                  <Copy className="h-3 w-3" /> Copy
                </button>
              </div>
              <pre className="text-[10px] font-mono p-3 rounded-lg overflow-x-auto"
                style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                {result}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main page
// ─────────────────────────────────────────────────────────────────────────────

export default function LogSearchPage() {
  const queryRef = useRef<HTMLInputElement>(null);

  // Core search state
  const [query,      setQuery]      = useState('');
  const [agentID,    setAgentID]    = useState(0);
  const [timeRange,  setTimeRange]  = useState('24h');
  const [source,     setSource]     = useState('');
  const [qLang,      setQLang]      = useState<QLang>('kql');
  const [pivots,     setPivots]     = useState<Pivot[]>([]);
  const [drillIdx,   setDrillIdx]   = useState<number | null>(null);

  // AI
  const [nlQuestion, setNlQuestion] = useState('');
  const [showAI,     setShowAI]     = useState(false);
  const [aiLoading,  setAiLoading]  = useState(false);
  const [aiExplain,  setAiExplain]  = useState('');

  // Results
  const [allLogs,    setAllLogs]    = useState<LogEntry[]>([]);
  const [loading,    setLoading]    = useState(false);
  const [error,      setError]      = useState('');
  const [page,       setPage]       = useState(0);
  const [searchTime, setSearchTime] = useState<number | null>(null);

  // Meta
  const [agents,     setAgents]     = useState<Agent[]>([]);
  const [stats,      setStats]      = useState<LogStats | null>(null);
  const [saved,      setSaved]      = useState<SavedLogSearch[]>([]);
  const [fields,     setFields]     = useState<FieldMeta[]>([]);
  const [templates,  setTemplates]  = useState<SearchTemplate[]>([]);
  const [scheduled,  setScheduled]  = useState<ScheduledSearch[]>([]);
  const [history,    setHistory]    = useState<string[]>([]);
  const [bookmarks,  setBookmarks]  = useState<Bookmark[]>([]);

  // View
  const [viewMode,     setViewMode]    = useState<ViewMode>('raw');
  const [activeTab,    setActiveTab]   = useState<'events'|'statistics'|'viz'|'ioc'>('events');
  const [leftTab,      setLeftTab]     = useState<LeftTab>('saved');
  const [showLeftPanel,setShowLeftPanel] = useState(false);
  const [rightPanel,   setRightPanel]  = useState(false);
  const [rightTab,    setRightTab]    = useState<RightTab>('context');
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
  const [showSave,    setShowSave]    = useState(false);
  const [saveName,    setSaveName]    = useState('');
  const [showDetect,  setShowDetect]  = useState(false);
  const [showSchedule,setShowSchedule]= useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [ctxMenu,     setCtxMenu]     = useState<{ x: number; y: number; log: LogEntry } | null>(null);
  const [pinnedIds,   setPinnedIds]   = useState<Set<number>>(new Set());
  const [vizType,     setVizType]     = useState<VizType>('bar');
  const [schedForm,   setSchedForm]   = useState({ name: '', schedule: 'daily', action: 'alert' });

  // Parsed query
  const [parsedQ, setParsedQ] = useState<{ terms: QueryTerm[]; pipes: PipeCmd[] }>({ terms: [], pipes: [] });

  // Autocomplete
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [showSuggest, setShowSuggest] = useState(false);

  // Load initial data
  useEffect(() => {
    setHistory(loadHistory());
    setBookmarks(loadBookmarks());
    agentsAPI.getAll().then(r => setAgents(r.data || [])).catch(() => {});
    logSearchAPI.stats().then(r => setStats(r.data)).catch(() => {});
    logSearchAPI.getSavedSearches().then(r => setSaved(r.data || [])).catch(() => {});
    logSearchAPI.getTemplates().then(r => setTemplates((r as any).data?.templates || [])).catch(() => {});
    logSearchAPI.getFields().then(r => setFields((r as any).data?.fields || [])).catch(() => {});
    logSearchAPI.getScheduled().then(r => setScheduled((r as any).data?.searches || [])).catch(() => {});
  }, []);

  // Autocomplete suggestions from fields + history
  useEffect(() => {
    if (!query || query.length < 2) { setSuggestions([]); return; }
    const q = query.toLowerCase();
    const fieldSuggs = fields.filter(f => f.name.startsWith(q)).map(f => `${f.name}:`);
    const histSuggs  = history.filter(h => h.toLowerCase().includes(q) && h !== query);
    setSuggestions([...fieldSuggs, ...histSuggs].slice(0, 8));
  }, [query, fields, history]);

  const runSearch = useCallback(async (pg = 0, qOverride?: string) => {
    const q = qOverride ?? query;
    const pq = parseQStr(q);
    setParsedQ(pq);
    setLoading(true); setError(''); setPage(pg); setSearchTime(null); setAiExplain('');
    const t0 = Date.now();
    try {
      const r = await logSearchAPI.search({ range: timeRange, limit: 500, agent_id: agentID || undefined, source: source || undefined });
      const logs: LogEntry[] = r.data?.logs || [];
      setAllLogs(logs);
      setSearchTime(Date.now() - t0);
      if (q.trim()) pushHistory(q);
      setHistory(loadHistory());
      setActiveTab(pq.pipes.some(p => p.type === 'stats' || p.type === 'top') ? 'statistics' :
        pq.pipes.some(p => p.type === 'timechart') ? 'viz' : 'events');
    } catch (e: any) { setError(e?.response?.data?.error || 'Search failed'); }
    finally { setLoading(false); }
  }, [query, agentID, timeRange, source]);

  const filteredLogs = useMemo(() => {
    const drillHour = drillIdx !== null && stats?.hourly_volume[drillIdx];
    return allLogs.filter(log => {
      if (!matchLog(log, parsedQ.terms)) return false;
      if (pivots.length > 0) {
        let pf: Record<string, string> = {};
        try { pf = JSON.parse(log.parsed_fields || '{}'); } catch {}
        for (const p of pivots) {
          if (!(pf[p.field] ?? '').toLowerCase().includes(p.value.toLowerCase())) return false;
        }
      }
      if (drillHour) {
        const lt = new Date(log.collected_at).getTime();
        const ht = new Date(drillHour.hour).getTime();
        if (lt < ht || lt > ht + 3600000) return false;
      }
      return true;
    });
  }, [allLogs, parsedQ.terms, pivots, drillIdx, stats]);

  const aggPipe    = parsedQ.pipes.find(p => p.type === 'stats' || p.type === 'top');
  const corrPipe   = parsedQ.pipes.find(p => p.type === 'correlate');
  const aggRows    = useMemo(() => aggPipe ? computeAgg(filteredLogs, aggPipe) : [], [filteredLogs, aggPipe]);
  const corrGroups = useMemo(() => corrPipe ? computeCorr(filteredLogs, corrPipe.field!, corrPipe.within ?? 5) : [], [filteredLogs, corrPipe]);
  const textSearch = parsedQ.terms.filter(t => t.type === 'text' && !t.negate).map(t => t.value).join(' ');

  const statTopSources = useMemo(() => computeAgg(allLogs, { type: 'stats', field: 'log_source' }).slice(0, 8), [allLogs]);
  const statTopIPs     = useMemo(() => computeAgg(allLogs, { type: 'top', n: 8, field: 'src_ip' }).slice(0, 8), [allLogs]);
  const statAuthResult = useMemo(() => computeAgg(allLogs, { type: 'stats', field: 'auth_result' }).slice(0, 6), [allLogs]);
  const statEventIDs   = useMemo(() => computeAgg(allLogs, { type: 'top', n: 8, field: 'event_id' }).slice(0, 8), [allLogs]);

  const addPivot = (field: string, value: string) => {
    setPivots(prev => prev.some(p => p.field === field && p.value === value) ? prev : [...prev, { field, value }]);
    if (allLogs.length === 0) runSearch();
  };

  const handleSave = async () => {
    if (!saveName.trim()) return;
    await logSearchAPI.saveSearch({ name: saveName, query, time_range: timeRange });
    setSaveName(''); setShowSave(false);
    logSearchAPI.getSavedSearches().then(r => setSaved(r.data || []));
  };

  const handleRunSaved = async (s: SavedLogSearch) => {
    setQuery(s.query); setTimeRange(s.time_range || '24h');
    await runSearch(0, s.query);
    logSearchAPI.getSavedSearches().then(r => setSaved(r.data || []));
  };

  const handleAIQuery = async () => {
    if (!nlQuestion.trim()) return;
    setAiLoading(true);
    try {
      const r = await logSearchAPI.aiQuery(nlQuestion, qLang);
      const q = (r as any).data?.query ?? '';
      setQuery(q); setShowAI(false); setNlQuestion('');
      await runSearch(0, q);
    } catch { setError('AI query failed'); }
    finally { setAiLoading(false); }
  };

  const handleAIExplain = async () => {
    setAiLoading(true);
    try {
      const r = await logSearchAPI.aiExplain(query, filteredLogs.length, filteredLogs.slice(0, 10).map(l => l.log_message));
      setAiExplain((r as any).data?.explanation ?? '');
    } catch { setAiExplain('AI service unavailable'); }
    finally { setAiLoading(false); }
  };

  const handleCreateScheduled = async () => {
    if (!schedForm.name.trim()) return;
    await logSearchAPI.createScheduled({ ...schedForm, query, time_range: timeRange });
    setShowSchedule(false);
    logSearchAPI.getScheduled().then(r => setScheduled((r as any).data?.searches || []));
  };

  const toggleBookmark = (bm: Bookmark) => {
    const next = bookmarks.some(b => b.id === bm.id)
      ? bookmarks.filter(b => b.id !== bm.id)
      : [...bookmarks, bm];
    setBookmarks(next); saveBookmarks(next);
  };

  const bookmarkQuery = () => {
    const bm: Bookmark = { id: String(Date.now()), type: 'query', label: query.slice(0, 60) || '(all)', query, ts: Date.now() };
    toggleBookmark(bm);
  };

  const exportLogs = (fmt: 'csv' | 'json' | 'ndjson' | 'evidence') => {
    let content = '';
    let filename = `logs-${Date.now()}`;
    if (fmt === 'ndjson') { content = filteredLogs.map(l => JSON.stringify(l)).join('\n'); filename += '.ndjson'; }
    else if (fmt === 'json') { content = JSON.stringify(filteredLogs, null, 2); filename += '.json'; }
    else if (fmt === 'evidence') { content = JSON.stringify({ query, time_range: timeRange, exported_at: new Date().toISOString(), total: filteredLogs.length, logs: filteredLogs }, null, 2); filename += '-evidence.json'; }
    else { content = ['id,agent_id,log_source,collected_at,log_message', ...filteredLogs.map(l => `${l.id},${l.agent_id},${l.log_source},${l.collected_at},"${l.log_message.replace(/"/g, '""')}"`).join('\n')].join('\n'); filename += '.csv'; }
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  };

  const pagedLogs  = filteredLogs.slice(page * LIMIT, page * LIMIT + LIMIT);
  const totalPages = Math.ceil(filteredLogs.length / LIMIT);

  const LANG_OPTS: { id: QLang; label: string }[] = [
    { id: 'kql', label: 'KQL' }, { id: 'lucene', label: 'Lucene' },
    { id: 'sql', label: 'SQL' }, { id: 'nl', label: 'Natural Language' },
  ];

  const LEFT_TABS: { id: LeftTab; label: string; icon: any }[] = [
    { id: 'fields',    label: 'Fields',    icon: Hash },
    { id: 'saved',     label: 'Saved',     icon: Star },
    { id: 'templates', label: 'Templates', icon: BookOpen },
    { id: 'bookmarks', label: 'Bookmarks', icon: BookmarkIcon },
    { id: 'scheduled', label: 'Scheduled', icon: Clock },
  ];

  // Keyboard shortcuts
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      if (e.key === 'Enter') runSearch(0);
      if (e.key === 'Escape') { setCtxMenu(null); setShowAI(false); }
      if (e.ctrlKey && e.key === 's') { e.preventDefault(); setShowSave(true); }
      if (e.ctrlKey && e.key === 'e') { e.preventDefault(); exportLogs('csv'); }
    };
    document.addEventListener('keydown', h);
    return () => document.removeEventListener('keydown', h);
  }, [runSearch]);

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <RootLayout title="Log Search" subtitle="KQL · Lucene · SQL · Natural Language · AI-powered">

      {/* ── Mobile toggle bar ── */}
      <div className="flex items-center gap-2 mb-2 lg:hidden flex-wrap">
        <button onClick={() => setShowLeftPanel(p => !p)}
          className={`g-btn text-xs ${showLeftPanel ? 'g-btn-primary' : 'g-btn-ghost'} flex items-center gap-1.5`}>
          <SlidersHorizontal className="h-3.5 w-3.5" />
          {showLeftPanel ? 'Hide Sidebar' : 'Sidebar'}
        </button>
        <button onClick={() => setRightPanel(p => !p)}
          className={`g-btn text-xs ${rightPanel ? 'g-btn-primary' : 'g-btn-ghost'} flex items-center gap-1.5`}>
          {rightPanel ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
          {rightPanel ? 'Hide Detail' : 'Show Detail'}
        </button>
        {selectedLog && !rightPanel && (
          <button onClick={() => setRightPanel(true)}
            className="g-btn g-btn-primary text-xs flex items-center gap-1.5 ml-auto">
            <Eye className="h-3.5 w-3.5" /> View Selected
          </button>
        )}
      </div>

      {/* ── Mobile sidebar drawer ── */}
      {showLeftPanel && (
        <div className="lg:hidden mb-3 rounded-2xl overflow-hidden" style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>
          <div className="flex overflow-x-auto" style={{ borderBottom: '1px solid var(--border)' }}>
            {LEFT_TABS.map(t => (
              <button key={t.id} onClick={() => setLeftTab(t.id)}
                className="flex items-center gap-1.5 px-3 py-2.5 shrink-0 text-xs transition-colors"
                style={{ color: leftTab === t.id ? 'var(--accent)' : 'var(--text-3)', borderBottom: `2px solid ${leftTab === t.id ? 'var(--accent)' : 'transparent'}`, background: leftTab === t.id ? 'var(--accent-glow)' : 'transparent' }}>
                <t.icon className="h-3.5 w-3.5" /> {t.label}
              </button>
            ))}
          </div>
          <div className="p-3 max-h-64 overflow-y-auto">
            {leftTab === 'fields' && <FieldExplorer fields={fields} onAddFilter={addPivot} />}
            {leftTab === 'saved' && (
              <div className="space-y-1">
                {saved.length === 0 && <p className="text-xs text-center py-3" style={{ color: 'var(--text-3)' }}>No saved searches</p>}
                {saved.map(s => (
                  <button key={s.id} onClick={() => { handleRunSaved(s); setShowLeftPanel(false); }}
                    className="w-full text-left rounded-lg px-3 py-2 hover:bg-[var(--glass-hover)] transition-colors">
                    <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{s.name}</p>
                    <p className="text-[10px] font-mono truncate" style={{ color: 'var(--text-3)' }}>{s.query || '(all)'} · {s.time_range}</p>
                  </button>
                ))}
              </div>
            )}
            {leftTab === 'templates' && (
              <div className="grid grid-cols-2 gap-2">
                {templates.map(t => (
                  <button key={t.id} onClick={() => { setQuery(t.query); setTimeRange(t.time_range); runSearch(0, t.query); setShowLeftPanel(false); }}
                    className="text-left rounded-lg p-2.5 hover:bg-[var(--glass-hover)] transition-colors"
                    style={{ border: '1px solid var(--border)' }}>
                    <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{t.name}</p>
                    <p className="text-[9px] mt-0.5" style={{ color: 'var(--text-3)' }}>{t.category}</p>
                  </button>
                ))}
              </div>
            )}
            {leftTab === 'bookmarks' && (
              <div className="space-y-1">
                {bookmarks.length === 0 && <p className="text-xs text-center py-3" style={{ color: 'var(--text-3)' }}>No bookmarks yet</p>}
                {bookmarks.map(bm => (
                  <div key={bm.id} className="flex items-center gap-2 rounded-lg px-2 py-1.5" style={{ border: '1px solid var(--border)' }}>
                    <span className="text-[9px] px-1 rounded" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>{bm.type}</span>
                    <span className="flex-1 text-[10px] font-mono truncate" style={{ color: 'var(--text-2)' }}>{bm.label}</span>
                    {bm.query && <button onClick={() => { setQuery(bm.query!); runSearch(0, bm.query!); }} className="text-[10px]" style={{ color: 'var(--accent)' }}>Run</button>}
                    <button onClick={() => toggleBookmark(bm)}><X className="h-3 w-3" style={{ color: 'var(--text-3)' }} /></button>
                  </div>
                ))}
              </div>
            )}
            {leftTab === 'scheduled' && (
              <div className="space-y-1.5">
                {scheduled.length === 0 && <p className="text-xs text-center py-3" style={{ color: 'var(--text-3)' }}>No scheduled searches</p>}
                {scheduled.map(s => (
                  <div key={s.id} className="rounded-lg px-3 py-2" style={{ border: '1px solid var(--border)' }}>
                    <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>{s.name}</p>
                    <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>{s.schedule} → {s.action}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Main three-column layout ── */}
      <div className="flex gap-3 min-h-0 lg:h-[calc(100vh-130px)]">

        {/* ── Left sidebar (desktop only) ── */}
        <div className="hidden lg:flex flex-col shrink-0" style={{ width: 240, background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: '1rem', overflow: 'hidden' }}>
          {/* Tab strip */}
          <div className="flex shrink-0 overflow-x-auto" style={{ borderBottom: '1px solid var(--border)' }}>
            {LEFT_TABS.map(t => (
              <button key={t.id} onClick={() => setLeftTab(t.id)}
                className="flex flex-col items-center gap-0.5 px-2 py-2 shrink-0 transition-colors"
                style={{ color: leftTab === t.id ? 'var(--accent)' : 'var(--text-3)', borderBottom: `2px solid ${leftTab === t.id ? 'var(--accent)' : 'transparent'}`, background: leftTab === t.id ? 'var(--accent-glow)' : 'transparent' }}>
                <t.icon className="h-3.5 w-3.5" />
                <span style={{ fontSize: 8 }}>{t.label}</span>
              </button>
            ))}
          </div>

          <div className="flex-1 overflow-y-auto p-3">

            {/* Fields */}
            {leftTab === 'fields' && (
              <FieldExplorer fields={fields} onAddFilter={(f, v) => { addPivot(f, v); }} />
            )}

            {/* Saved searches */}
            {leftTab === 'saved' && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-semibold uppercase" style={{ color: 'var(--text-3)' }}>Saved Searches</span>
                  <button onClick={() => setShowSave(true)} className="text-[10px] px-2 py-1 rounded" style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>+ Save</button>
                </div>
                {saved.length === 0 && <p className="text-[10px] text-center py-4" style={{ color: 'var(--text-3)' }}>No saved searches</p>}
                {saved.map(s => (
                  <div key={s.id} className="group flex items-start gap-1 rounded-lg p-2 transition-colors hover:bg-[var(--glass-hover)]">
                    <button onClick={() => handleRunSaved(s)} className="flex-1 text-left min-w-0">
                      <p className="text-[11px] font-medium truncate" style={{ color: 'var(--text-1)' }}>{s.name}</p>
                      <p className="text-[9px] font-mono truncate" style={{ color: 'var(--text-3)' }}>{s.query || '(all)'} · {s.time_range}</p>
                      <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>{s.run_count} runs</p>
                    </button>
                    <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button onClick={() => setPinnedIds(p => { const n = new Set(p); n.has(s.id) ? n.delete(s.id) : n.add(s.id); return n; })}>
                        {pinnedIds.has(s.id) ? <Star className="h-3 w-3" style={{ color: 'var(--yellow)' }} /> : <StarOff className="h-3 w-3" style={{ color: 'var(--text-3)' }} />}
                      </button>
                      <button onClick={() => logSearchAPI.deleteSearch(s.id).then(() => setSaved(ss => ss.filter(x => x.id !== s.id)))}>
                        <Trash2 className="h-3 w-3" style={{ color: 'var(--red)' }} />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Templates */}
            {leftTab === 'templates' && (
              <div className="space-y-1.5">
                <p className="text-[10px] font-semibold uppercase mb-2" style={{ color: 'var(--text-3)' }}>Hunt Templates</p>
                {templates.map(t => (
                  <button key={t.id} onClick={() => { setQuery(t.query); setTimeRange(t.time_range); runSearch(0, t.query); }}
                    className="w-full text-left rounded-lg p-2.5 transition-colors hover:bg-[var(--glass-hover)]"
                    style={{ border: '1px solid var(--border)' }}>
                    <p className="text-[11px] font-semibold" style={{ color: 'var(--text-1)' }}>{t.name}</p>
                    <p className="text-[9px] mt-0.5" style={{ color: 'var(--text-3)' }}>{t.description}</p>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {t.tags.map(tag => (
                        <span key={tag} className="text-[8px] px-1 rounded" style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>{tag}</span>
                      ))}
                    </div>
                  </button>
                ))}
              </div>
            )}

            {/* Bookmarks */}
            {leftTab === 'bookmarks' && (
              <div className="space-y-1.5">
                <p className="text-[10px] font-semibold uppercase mb-2" style={{ color: 'var(--text-3)' }}>Bookmarks</p>
                {bookmarks.length === 0 && <p className="text-[10px] text-center py-4" style={{ color: 'var(--text-3)' }}>No bookmarks yet</p>}
                {bookmarks.map(bm => (
                  <div key={bm.id} className="group flex items-start gap-2 rounded-lg p-2 hover:bg-[var(--glass-hover)] transition-colors">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1 mb-0.5">
                        <span className="text-[8px] px-1 rounded" style={{ background: bm.type === 'query' ? 'var(--accent-glow)' : 'rgba(234,179,8,0.15)', color: bm.type === 'query' ? 'var(--accent)' : 'var(--yellow)', border: `1px solid ${bm.type === 'query' ? 'var(--accent-border)' : 'rgba(234,179,8,0.3)'}` }}>{bm.type}</span>
                      </div>
                      <p className="text-[10px] font-mono truncate" style={{ color: 'var(--text-2)' }}>{bm.label}</p>
                      {bm.query && (
                        <button onClick={() => { setQuery(bm.query!); runSearch(0, bm.query!); }} className="text-[9px] mt-0.5" style={{ color: 'var(--accent)' }}>Run query</button>
                      )}
                    </div>
                    <button onClick={() => toggleBookmark(bm)} className="opacity-0 group-hover:opacity-100 shrink-0">
                      <X className="h-3 w-3" style={{ color: 'var(--text-3)' }} />
                    </button>
                  </div>
                ))}
              </div>
            )}

            {/* Scheduled searches */}
            {leftTab === 'scheduled' && (
              <div className="space-y-2">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-[10px] font-semibold uppercase" style={{ color: 'var(--text-3)' }}>Scheduled</p>
                  <button onClick={() => setShowSchedule(true)} className="text-[10px] px-2 py-1 rounded" style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>+ New</button>
                </div>
                {scheduled.length === 0 && <p className="text-[10px] text-center py-4" style={{ color: 'var(--text-3)' }}>No scheduled searches</p>}
                {scheduled.map(s => (
                  <div key={s.id} className="rounded-lg p-2.5" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                    <p className="text-[11px] font-semibold" style={{ color: 'var(--text-1)' }}>{s.name}</p>
                    <p className="text-[9px] font-mono truncate" style={{ color: 'var(--text-3)' }}>{s.query || '(all)'}</p>
                    <div className="flex items-center gap-2 mt-1 text-[9px]" style={{ color: 'var(--text-3)' }}>
                      <span>{s.schedule}</span><span>→</span><span>{s.action}</span>
                      <span className="ml-auto px-1 rounded" style={{ background: s.enabled ? 'rgba(34,197,94,0.15)' : 'var(--bg-1)', color: s.enabled ? 'var(--green)' : 'var(--text-3)', border: `1px solid ${s.enabled ? 'rgba(34,197,94,0.3)' : 'var(--border)'}` }}>
                        {s.enabled ? 'ON' : 'OFF'}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Search History */}
          <div className="shrink-0 p-2" style={{ borderTop: '1px solid var(--border)' }}>
            <button onClick={() => setShowHistory(h => !h)} className="w-full flex items-center justify-between text-[10px] px-1 py-1"
              style={{ color: 'var(--text-3)' }}>
              <span className="flex items-center gap-1"><Clock className="h-3 w-3" /> History ({history.length})</span>
              {showHistory ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
            </button>
            {showHistory && (
              <div className="space-y-0.5 mt-1 max-h-32 overflow-y-auto">
                {history.slice(0, 10).map((h, i) => (
                  <button key={i} onClick={() => { setQuery(h); runSearch(0, h); setShowHistory(false); }}
                    className="w-full text-left text-[10px] font-mono px-1.5 py-1 rounded truncate hover:bg-[var(--glass-hover)] transition-colors"
                    style={{ color: 'var(--text-2)' }}>{h}</button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* ── Center: search + results ── */}
        <div className="flex-1 flex flex-col gap-2 min-w-0 min-h-0">

          {/* Query bar */}
          <div className="rounded-2xl p-3 space-y-2 shrink-0" style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>
            {/* Query language + action toolbar */}
            <div className="flex flex-wrap items-center gap-2">
              <div className="flex rounded-lg overflow-hidden shrink-0" style={{ border: '1px solid var(--border)' }}>
                {LANG_OPTS.map(l => (
                  <button key={l.id} onClick={() => setQLang(l.id)}
                    className="px-2 sm:px-2.5 py-1 text-[10px] font-semibold transition-colors"
                    style={{ background: qLang === l.id ? 'var(--accent-glow)' : 'transparent', color: qLang === l.id ? 'var(--accent)' : 'var(--text-3)', borderRight: l.id !== 'nl' ? '1px solid var(--border)' : undefined }}>
                    <span className="hidden sm:inline">{l.label}</span>
                    <span className="sm:hidden">{l.id.toUpperCase()}</span>
                  </button>
                ))}
              </div>
              <button onClick={() => setShowAI(s => !s)}
                className={`g-btn text-xs ${showAI ? 'g-btn-primary' : 'g-btn-ghost'} flex items-center gap-1.5`}>
                <Sparkles className="h-3.5 w-3.5" /> <span className="hidden sm:inline">AI Search</span><span className="sm:hidden">AI</span>
              </button>
              <button onClick={bookmarkQuery} className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
                {bookmarks.some(b => b.query === query) ? <BookmarkCheck className="h-3.5 w-3.5" style={{ color: 'var(--yellow)' }} /> : <BookmarkIcon className="h-3.5 w-3.5" />}
              </button>
              <button onClick={() => setShowDetect(true)} disabled={allLogs.length === 0}
                className="g-btn g-btn-ghost text-xs flex items-center gap-1.5 disabled:opacity-40">
                <Code className="h-3.5 w-3.5" /> <span className="hidden md:inline">Build Detection</span>
              </button>
              <button onClick={() => setShowSchedule(true)} className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
                <Calendar className="h-3.5 w-3.5" /> <span className="hidden md:inline">Schedule</span>
              </button>
            </div>

            {/* AI prompt panel */}
            {showAI && (
              <div className="flex gap-2 p-2 rounded-xl" style={{ background: 'rgba(99,102,241,0.08)', border: '1px solid rgba(99,102,241,0.3)' }}>
                <Sparkles className="h-4 w-4 shrink-0 mt-2" style={{ color: 'var(--accent)' }} />
                <input value={nlQuestion} onChange={e => setNlQuestion(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleAIQuery()}
                  placeholder='e.g. "Show all suspicious PowerShell executions in the last 24h"'
                  className="flex-1 bg-transparent text-sm outline-none font-mono" style={{ color: 'var(--text-1)' }} />
                <button onClick={handleAIQuery} disabled={aiLoading || !nlQuestion.trim()}
                  className="g-btn g-btn-primary text-xs disabled:opacity-40 flex items-center gap-1.5">
                  {aiLoading ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <ArrowRight className="h-3.5 w-3.5" />}
                  Convert
                </button>
              </div>
            )}

            {/* Main query input */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
              <input ref={queryRef} value={query}
                onChange={e => { setQuery(e.target.value); setShowSuggest(true); }}
                onFocus={() => setShowSuggest(true)}
                onBlur={() => setTimeout(() => setShowSuggest(false), 150)}
                onKeyDown={e => { if (e.key === 'Enter') { runSearch(0); setShowSuggest(false); } }}
                className="g-input pl-9 pr-24 font-mono text-sm w-full"
                placeholder={qLang === 'nl' ? 'Ask in natural language…' : qLang === 'sql' ? 'SELECT * FROM logs WHERE …' : 'src_ip:185.220.101.35 AND "failed" | stats count by user'} />
              <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-1">
                {query && <button onClick={() => setQuery('')}><X className="h-3 w-3" style={{ color: 'var(--text-3)' }} /></button>}
              </div>
              {/* Autocomplete */}
              {showSuggest && suggestions.length > 0 && (
                <div className="absolute top-full left-0 right-0 mt-1 z-50 rounded-xl overflow-hidden"
                  style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', backdropFilter: 'blur(12px)' }}>
                  {suggestions.map((s, i) => (
                    <button key={i} onMouseDown={() => { setQuery(s); setShowSuggest(false); }}
                      className="w-full text-left px-3 py-1.5 text-xs font-mono transition-colors"
                      style={{ color: 'var(--text-1)' }}
                      onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--accent-glow)'}
                      onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}>
                      {s}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Filters row */}
            <div className="space-y-2">
              {/* Time range — scrollable on small screens */}
              <div className="flex items-center gap-2">
                <SlidersHorizontal className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />
                <div className="flex-1 overflow-x-auto" style={{ scrollbarWidth: 'none' }}>
                  <div className="flex rounded-lg overflow-hidden w-max" style={{ border: '1px solid var(--border)' }}>
                    {TIME_RANGES.map(r => (
                      <button key={r.value} onClick={() => setTimeRange(r.value)}
                        className="px-2 py-1 text-[10px] font-medium transition-colors whitespace-nowrap"
                        style={{ background: timeRange === r.value ? 'var(--accent)' : 'transparent', color: timeRange === r.value ? '#000' : 'var(--text-3)', borderRight: '1px solid var(--border)' }}>
                        {r.label}
                      </button>
                    ))}
                  </div>
                </div>
                <button onClick={() => runSearch(0)} disabled={loading}
                  className="g-btn g-btn-primary text-xs px-4 flex items-center gap-1.5 shrink-0">
                  {loading ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
                  <span className="hidden sm:inline">Run</span>
                </button>
              </div>
              {/* Agent + source filters */}
              <div className="flex flex-wrap items-center gap-2">
                <select className="g-select text-xs py-1 flex-1 min-w-[120px]" value={agentID} onChange={e => setAgentID(+e.target.value)}>
                  <option value={0}>All agents</option>
                  {agents.map(a => <option key={a.id} value={a.id}>{a.hostname}</option>)}
                </select>
                <input className="g-input text-xs py-1 flex-1 min-w-[100px] max-w-[200px]" placeholder="Log source…" value={source}
                  onChange={e => setSource(e.target.value)} onKeyDown={e => e.key === 'Enter' && runSearch(0)} />
                {(query || agentID > 0 || source || pivots.length > 0) && (
                  <button onClick={() => { setQuery(''); setAgentID(0); setSource(''); setPivots([]); setDrillIdx(null); setAllLogs([]); }}
                    className="text-xs flex items-center gap-1" style={{ color: 'var(--text-3)' }}>
                    <X className="h-3 w-3" /> Clear all
                  </button>
                )}
              </div>
            </div>

            {/* Pivot chips */}
            {pivots.length > 0 && (
              <div className="flex items-center gap-2 flex-wrap pt-1" style={{ borderTop: '1px solid var(--border)' }}>
                <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>Filters:</span>
                {pivots.map((p, i) => (
                  <span key={i} className="flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-lg"
                    style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)', color: 'var(--accent)' }}>
                    {p.field}:{p.value}
                    <button onClick={() => setPivots(pp => pp.filter((_, j) => j !== i))} className="ml-0.5">
                      <X className="h-2.5 w-2.5" />
                    </button>
                  </span>
                ))}
                <button onClick={() => setPivots([])} className="text-[10px]" style={{ color: 'var(--text-3)' }}>Clear</button>
              </div>
            )}
          </div>

          {/* Error */}
          {error && (
            <div className="flex items-center gap-2 px-3 py-2 rounded-xl text-xs shrink-0"
              style={{ background: 'rgba(248,81,73,0.1)', color: 'var(--red)', border: '1px solid rgba(248,81,73,0.3)' }}>
              <AlertCircle className="h-4 w-4 shrink-0" /> {error}
            </div>
          )}

          {/* Stats bar */}
          {allLogs.length > 0 && (
            <div className="flex items-center gap-4 px-3 py-2 rounded-xl shrink-0 flex-wrap"
              style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>
              {[
                { label: 'Matched', value: filteredLogs.length.toLocaleString(), color: 'var(--accent)' },
                { label: 'Total in range', value: allLogs.length.toLocaleString(), color: 'var(--text-2)' },
                ...(searchTime !== null ? [{ label: 'Search time', value: `${searchTime}ms`, color: 'var(--green)' }] : []),
              ].map(({ label, value, color }) => (
                <span key={label} className="text-[11px]">
                  <span style={{ color: 'var(--text-3)' }}>{label}: </span>
                  <strong style={{ color }}>{value}</strong>
                </span>
              ))}
              {drillIdx !== null && (
                <button onClick={() => setDrillIdx(null)} className="text-[10px] underline ml-auto" style={{ color: 'var(--accent)' }}>Clear drill-down</button>
              )}
            </div>
          )}

          {/* Histogram */}
          {stats && allLogs.length > 0 && (
            <div className="px-3 py-2 rounded-xl shrink-0" style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>
              <Histogram volume={stats.hourly_volume} drillIdx={drillIdx} onDrill={setDrillIdx} />
            </div>
          )}

          {/* AI explanation */}
          {aiExplain && (
            <div className="rounded-xl px-4 py-3 shrink-0"
              style={{ background: 'rgba(99,102,241,0.08)', border: '1px solid rgba(99,102,241,0.3)' }}>
              <div className="flex items-center gap-2 mb-2">
                <Sparkles className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
                <span className="text-[10px] font-semibold uppercase" style={{ color: 'var(--accent)' }}>AI Analysis</span>
                <button onClick={() => setAiExplain('')} className="ml-auto"><X className="h-3 w-3" style={{ color: 'var(--text-3)' }} /></button>
              </div>
              <p className="text-[11px] leading-relaxed whitespace-pre-wrap" style={{ color: 'var(--text-1)' }}>{aiExplain}</p>
            </div>
          )}

          {/* Results area */}
          {allLogs.length > 0 ? (
            <div className="flex-1 rounded-2xl overflow-hidden flex flex-col min-h-0" style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>
              {/* Tab + controls strip */}
              <div className="shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
                {/* Tabs — scrollable on mobile */}
                <div className="flex items-center justify-between">
                  <div className="flex overflow-x-auto" style={{ scrollbarWidth: 'none' }}>
                    {([
                      { id: 'events',     label: 'Events',  Icon: Search },
                      { id: 'statistics', label: 'Stats',   Icon: BarChart2 },
                      { id: 'viz',        label: 'Viz',     Icon: TrendingUp },
                      { id: 'ioc',        label: 'IOC',     Icon: ShieldAlert },
                    ] as const).map(tab => (
                      <button key={tab.id} onClick={() => setActiveTab(tab.id)}
                        className="flex items-center gap-1.5 px-3 sm:px-4 py-2.5 text-xs font-medium transition-colors border-b-2 whitespace-nowrap shrink-0"
                        style={{ borderColor: activeTab === tab.id ? 'var(--accent)' : 'transparent', color: activeTab === tab.id ? 'var(--accent)' : 'var(--text-3)' }}>
                        <tab.Icon className="h-3.5 w-3.5" />
                        <span className="hidden sm:inline">{tab.label}</span>
                        {tab.id === 'events' && <span className="text-[9px] px-1 rounded-full" style={{ background: 'var(--bg-0)', color: 'var(--text-3)' }}>{filteredLogs.length}</span>}
                      </button>
                    ))}
                  </div>
                  {/* Right controls */}
                  <div className="flex items-center gap-1 pr-2 shrink-0">
                    {activeTab === 'events' && (
                      <div className="flex rounded-lg overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                        {([['raw', Terminal], ['table', Table2], ['json', FileJson]] as [ViewMode, any][]).map(([m, Icon]) => (
                          <button key={m} onClick={() => setViewMode(m)}
                            className="flex items-center gap-1 px-2 py-1 text-[10px] transition-colors"
                            style={{ background: viewMode === m ? 'var(--accent-glow)' : 'transparent', color: viewMode === m ? 'var(--accent)' : 'var(--text-3)', borderRight: m !== 'json' ? '1px solid var(--border)' : undefined }}>
                            <Icon className="h-3 w-3" />
                          </button>
                        ))}
                      </div>
                    )}
                    {filteredLogs.length > 0 && (
                      <button onClick={handleAIExplain} disabled={aiLoading}
                        className="g-btn g-btn-ghost text-[11px] flex items-center gap-1 disabled:opacity-40" title="AI explain">
                        ✨️ {aiLoading ? 'Explaining…' : 'Explain'}
                      </button>
                    )}
                    <div className="relative">
                      <button className="g-btn g-btn-ghost text-[11px] flex items-center gap-1"
                        onMouseEnter={e => { const m = (e.currentTarget.nextElementSibling as HTMLElement); if (m) m.style.display = 'block'; }}
                        onMouseLeave={e => { setTimeout(() => { const m = (e.currentTarget.nextElementSibling as HTMLElement); if (m) m.style.display = 'none'; }, 200); }}>
                        <Download className="h-3 w-3" />
                      </button>
                      <div className="absolute right-0 top-full mt-1 hidden z-50 rounded-lg overflow-hidden"
                        style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', minWidth: 130, backdropFilter: 'blur(12px)' }}
                        onMouseEnter={e => (e.currentTarget as HTMLElement).style.display = 'block'}
                        onMouseLeave={e => (e.currentTarget as HTMLElement).style.display = 'none'}>
                        {[['csv','CSV'],['json','JSON'],['ndjson','NDJSON'],['evidence','Evidence Package']].map(([f, l]) => (
                          <button key={f} onClick={() => exportLogs(f as any)}
                            className="w-full text-left px-3 py-1.5 text-xs transition-colors"
                            style={{ color: 'var(--text-1)' }}
                            onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--accent-glow)'}
                            onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}>
                            {l}
                          </button>
                        ))}
                      </div>
                    </div>
                    <button onClick={() => setRightPanel(p => !p)} className="g-btn g-btn-ghost text-[11px] hidden lg:flex items-center gap-1">
                      {rightPanel ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                    </button>
                  </div>
                </div>
              </div>

              {/* Events tab */}
              {activeTab === 'events' && (
                <>
                  <div className="flex-1 overflow-y-auto">
                    {pagedLogs.length === 0 ? (
                      <div className="py-16 text-center">
                        <Search className="mx-auto h-8 w-8 mb-2 opacity-20" style={{ color: 'var(--text-3)' }} />
                        <p className="text-sm" style={{ color: 'var(--text-3)' }}>No logs matched</p>
                      </div>
                    ) : viewMode === 'table' ? (
                      <TableView logs={pagedLogs} search={textSearch} onPivot={addPivot}
                        selected={selectedLog} onSelect={l => setSelectedLog(s => s?.id === l.id ? null : l)}
                        onCtxMenu={(e, l) => { e.preventDefault(); setCtxMenu({ x: e.clientX, y: e.clientY, log: l }); }} />
                    ) : viewMode === 'json' ? (
                      <JsonView logs={pagedLogs} selected={selectedLog} onSelect={l => setSelectedLog(s => s?.id === l.id ? null : l)} />
                    ) : (
                      pagedLogs.map(l => (
                        <LogRow key={l.id} log={l} search={textSearch} onPivot={addPivot}
                          selected={selectedLog?.id === l.id}
                          onSelect={() => setSelectedLog(s => s?.id === l.id ? null : l)}
                          onCtxMenu={e => { e.preventDefault(); setCtxMenu({ x: e.clientX, y: e.clientY, log: l }); }} />
                      ))
                    )}
                  </div>
                  {totalPages > 1 && (
                    <div className="flex items-center justify-between px-4 py-2 shrink-0" style={{ borderTop: '1px solid var(--border)' }}>
                      <button disabled={page === 0} onClick={() => setPage(p => p - 1)} className="g-btn g-btn-ghost text-xs disabled:opacity-40">← Prev</button>
                      <span className="text-xs" style={{ color: 'var(--text-3)' }}>Page {page + 1}/{totalPages} · {filteredLogs.length.toLocaleString()} results</span>
                      <button disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)} className="g-btn g-btn-ghost text-xs disabled:opacity-40">Next →</button>
                    </div>
                  )}
                </>
              )}

              {/* Statistics tab */}
              {activeTab === 'statistics' && (
                <div className="flex-1 overflow-y-auto p-4 space-y-6">
                  {corrPipe && corrGroups.length > 0 && (
                    <div>
                      <p className="text-xs font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--text-2)' }}>
                        <GitMerge className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
                        Correlation by <code className="font-mono">{corrPipe.field}</code> within {corrPipe.within}m
                      </p>
                      <div className="space-y-2">
                        {corrGroups.map(g => (
                          <div key={g.value} className="rounded-xl p-3" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                            <div className="flex justify-between mb-1.5">
                              <span className="font-mono text-xs font-semibold" style={{ color: 'var(--accent)' }}>{g.value}</span>
                              <span className="text-xs" style={{ color: 'var(--text-3)' }}>{g.count} events · span {g.span_min}m</span>
                            </div>
                            {g.events.slice(0, 2).map(e => (
                              <p key={e.id} className="text-[10px] font-mono truncate" style={{ color: 'var(--text-3)' }}>
                                {new Date(e.collected_at).toLocaleTimeString()} · {e.log_message.slice(0, 100)}
                              </p>
                            ))}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {aggPipe && aggRows.length > 0 && (
                    <div>
                      <p className="text-xs font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--text-2)' }}>
                        <Layers className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
                        Count by <code className="font-mono">{aggPipe.field}</code>
                      </p>
                      <div className="space-y-1.5">
                        {aggRows.map(r => {
                          const max = aggRows[0].count;
                          return (
                            <div key={r.label} className="flex items-center gap-3">
                              <span className="text-[11px] font-mono truncate" style={{ color: 'var(--text-2)', width: 140, flexShrink: 0 }}>{r.label || '(empty)'}</span>
                              <div className="flex-1 h-4 rounded overflow-hidden" style={{ background: 'var(--bg-0)' }}>
                                <div className="h-full rounded" style={{ width: `${(r.count/max)*100}%`, background: 'var(--accent)' }} />
                              </div>
                              <span className="text-[11px] font-mono w-10 text-right shrink-0" style={{ color: 'var(--text-1)' }}>{r.count.toLocaleString()}</span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                  {!aggPipe && !corrPipe && (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      {[
                        { label: 'Top Sources',    rows: statTopSources },
                        { label: 'Top Source IPs', rows: statTopIPs },
                        { label: 'Auth Results',   rows: statAuthResult },
                        { label: 'Event IDs',      rows: statEventIDs },
                      ].map(panel => panel.rows.length > 0 && (
                        <div key={panel.label} className="rounded-xl p-3" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                          <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-2)' }}>{panel.label}</p>
                          {panel.rows.map(r => {
                            const max = panel.rows[0]?.count ?? 1;
                            return (
                              <div key={r.label} className="flex items-center gap-2 mb-1">
                                <span className="text-[10px] font-mono truncate" style={{ color: 'var(--text-2)', width: 100, flexShrink: 0 }}>{r.label || '(empty)'}</span>
                                <div className="flex-1 h-3 rounded overflow-hidden" style={{ background: 'var(--border)' }}>
                                  <div className="h-full rounded" style={{ width: `${(r.count/max)*100}%`, background: 'var(--accent)' }} />
                                </div>
                                <span className="text-[10px] font-mono w-8 text-right shrink-0" style={{ color: 'var(--text-3)' }}>{r.count}</span>
                              </div>
                            );
                          })}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Visualization tab */}
              {activeTab === 'viz' && aggPipe && (
                <div className="flex-1 overflow-y-auto">
                  <VizPanel aggRows={aggRows} field={aggPipe.field ?? 'log_source'} vizType={vizType} setVizType={setVizType} />
                </div>
              )}
              {activeTab === 'viz' && !aggPipe && (
                <div className="flex-1 flex items-center justify-center">
                  <div className="text-center">
                    <TrendingUp className="h-10 w-10 mx-auto mb-2 opacity-20" style={{ color: 'var(--text-3)' }} />
                    <p className="text-sm" style={{ color: 'var(--text-3)' }}>Add a pipe to visualize</p>
                    <code className="text-xs font-mono" style={{ color: 'var(--accent)' }}>| stats count by log_source</code>
                  </div>
                </div>
              )}

              {/* IOC tab */}
              {activeTab === 'ioc' && (
                <div className="flex-1 overflow-y-auto p-4">
                  <p className="text-xs mb-4" style={{ color: 'var(--text-3)' }}>Checking {filteredLogs.length} results against threat intel…</p>
                  <div className="space-y-2">
                    {filteredLogs.filter(l => {
                      let f: any = {}; try { f = JSON.parse(l.parsed_fields || '{}'); } catch {}
                      return f.src_ip || f.domain || f.url;
                    }).slice(0, 20).map(l => {
                      let f: any = {}; try { f = JSON.parse(l.parsed_fields || '{}'); } catch {}
                      return (
                        <div key={l.id} className="rounded-xl p-3 flex items-center gap-3"
                          style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                          <ShieldAlert className="h-4 w-4 shrink-0" style={{ color: 'var(--yellow)' }} />
                          <div className="flex-1 min-w-0">
                            <div className="flex flex-wrap gap-1.5 mb-0.5">
                              {f.src_ip && <span className="text-[10px] font-mono px-1.5 rounded" style={{ background: 'rgba(239,68,68,0.1)', color: 'var(--red)', border: '1px solid rgba(239,68,68,0.3)' }}>ip:{f.src_ip}</span>}
                              {f.domain && <span className="text-[10px] font-mono px-1.5 rounded" style={{ background: 'rgba(239,68,68,0.1)', color: 'var(--orange)', border: '1px solid rgba(251,146,60,0.3)' }}>domain:{f.domain}</span>}
                            </div>
                            <p className="text-[10px] font-mono truncate" style={{ color: 'var(--text-3)' }}>{l.log_message.slice(0, 80)}</p>
                          </div>
                          <button onClick={() => f.src_ip && addPivot('src_ip', f.src_ip)}
                            className="text-[10px] flex items-center gap-1 shrink-0" style={{ color: 'var(--accent)' }}>
                            <Link2 className="h-3 w-3" /> Filter
                          </button>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          ) : (
            !loading && (
              <div className="flex-1 rounded-2xl flex flex-col items-center justify-center"
                style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>
                <Search className="h-10 w-10 mb-3 opacity-20" style={{ color: 'var(--text-3)' }} />
                <p className="text-sm font-medium" style={{ color: 'var(--text-2)' }}>Run a search to see results</p>
                <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>
                  Try <code className="font-mono" style={{ color: 'var(--accent)' }}>auth_result:failure | stats count by src_ip</code>
                </p>
                <p className="text-[10px] mt-3" style={{ color: 'var(--text-3)' }}>
                  Or use the AI Search button to query in natural language
                </p>
              </div>
            )
          )}
        </div>

        {/* ── Right context panel (desktop: beside; mobile: hidden via toggle) ── */}
        {rightPanel && (
          <div className="shrink-0 flex flex-col min-h-0" style={{ width: '100%', maxWidth: 280, background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: '1rem', overflow: 'hidden' }}>
            <ContextPanel
              log={selectedLog} allLogs={allLogs} tab={rightTab} onTabChange={setRightTab}
              onPivot={addPivot} bookmarks={bookmarks} onBookmark={toggleBookmark}
            />
          </div>
        )}
      </div>

      {/* ── Right panel as bottom sheet on mobile when open ── */}
      {rightPanel && selectedLog && (
        <div className="lg:hidden mt-3 rounded-2xl overflow-hidden" style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', maxHeight: 400, display: 'flex', flexDirection: 'column' }}>
          <ContextPanel
            log={selectedLog} allLogs={allLogs} tab={rightTab} onTabChange={setRightTab}
            onPivot={addPivot} bookmarks={bookmarks} onBookmark={toggleBookmark}
          />
        </div>
      )}

      {/* ── Save modal ── */}
      {showSave && (
        <div className="g-modal-backdrop" onClick={() => setShowSave(false)}>
          <div className="g-modal" style={{ maxWidth: 420 }} onClick={e => e.stopPropagation()}>
            <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
              <span className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Save Search</span>
              <button onClick={() => setShowSave(false)}><X className="h-4 w-4" style={{ color: 'var(--text-3)' }} /></button>
            </div>
            <div className="p-4 space-y-3">
              <input autoFocus className="g-input w-full" placeholder="Search name…" value={saveName}
                onChange={e => setSaveName(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleSave()} />
              {query && <p className="text-[11px] font-mono" style={{ color: 'var(--text-3)' }}>{query} · {timeRange}</p>}
            </div>
            <div className="flex gap-2 px-4 pb-4">
              <button onClick={() => setShowSave(false)} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={handleSave} className="g-btn g-btn-primary flex-1 justify-center">Save</button>
            </div>
          </div>
        </div>
      )}

      {/* ── Schedule modal ── */}
      {showSchedule && (
        <div className="g-modal-backdrop" onClick={() => setShowSchedule(false)}>
          <div className="g-modal" style={{ maxWidth: 440 }} onClick={e => e.stopPropagation()}>
            <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
              <span className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Schedule Search</span>
              <button onClick={() => setShowSchedule(false)}><X className="h-4 w-4" style={{ color: 'var(--text-3)' }} /></button>
            </div>
            <div className="p-4 space-y-3">
              <input className="g-input w-full" placeholder="Search name…"
                value={schedForm.name} onChange={e => setSchedForm(f => ({ ...f, name: e.target.value }))} />
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Schedule</label>
                  <select className="g-select w-full" value={schedForm.schedule}
                    onChange={e => setSchedForm(f => ({ ...f, schedule: e.target.value }))}>
                    {['hourly','daily','weekly'].map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
                <div>
                  <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Action</label>
                  <select className="g-select w-full" value={schedForm.action}
                    onChange={e => setSchedForm(f => ({ ...f, action: e.target.value }))}>
                    {['alert','email','dashboard','playbook'].map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
              </div>
              {query && <div className="rounded-lg p-2" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                <p className="text-[9px] uppercase mb-1" style={{ color: 'var(--text-3)' }}>Query</p>
                <code className="text-[10px] font-mono" style={{ color: 'var(--accent)' }}>{query || '(all)'}</code>
              </div>}
            </div>
            <div className="flex gap-2 px-4 pb-4">
              <button onClick={() => setShowSchedule(false)} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={handleCreateScheduled} className="g-btn g-btn-primary flex-1 justify-center">Schedule</button>
            </div>
          </div>
        </div>
      )}

      {/* ── Detection builder modal ── */}
      {showDetect && (
        <DetectionModal
          query={query}
          samples={filteredLogs.slice(0, 10).map(l => l.log_message)}
          onClose={() => setShowDetect(false)}
        />
      )}

      {/* ── Context menu ── */}
      {ctxMenu && (
        <CtxMenu x={ctxMenu.x} y={ctxMenu.y} log={ctxMenu.log}
          bookmarked={bookmarks.some(b => b.logId === ctxMenu.log.id)}
          onClose={() => setCtxMenu(null)}
          onPivot={addPivot}
          onBookmark={() => toggleBookmark({ id: String(Date.now()), type: 'event', label: ctxMenu.log.log_message.slice(0, 60), logId: ctxMenu.log.id, ts: Date.now() })}
        />
      )}
    </RootLayout>
  );
}
