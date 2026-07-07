'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import api from '@/lib/api';
import {
  Play, Save, Download, Trash2, Clock, Database, ChevronDown, ChevronRight,
  X, Copy, CheckCheck, AlertCircle, Layers, RefreshCw, BookOpen, Plus,
  Search, Code2, Table2, Braces, Activity, Server,
} from 'lucide-react';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface ESHit {
  _index: string;
  _id: string;
  _score: number;
  _source: Record<string, unknown>;
}

interface ESResult {
  took: number;
  timed_out: boolean;
  total: number;
  hits: { total: { value: number }; hits: ESHit[] };
  aggregations?: Record<string, unknown>;
  error?: string;
}

interface ESIndex {
  index: string;
  docs_count: string;
  store_size: string;
  health: string;
}

interface SavedQuery {
  id: string;
  name: string;
  index: string;
  dsl: string;
  created_at: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Security-relevant query templates
// ─────────────────────────────────────────────────────────────────────────────

const TEMPLATES = [
  {
    name: 'All Logs (latest 50)',
    description: 'Fetch the 50 most recent log entries',
    dsl: JSON.stringify({
      query: { match_all: {} },
      sort: [{ collected_at: { order: 'desc' } }],
      size: 50,
    }, null, 2),
  },
  {
    name: 'Failed SSH Auth',
    description: 'Brute-force and failed authentication events',
    dsl: JSON.stringify({
      query: {
        bool: {
          should: [
            { match_phrase: { log_message: 'Failed password' } },
            { match_phrase: { log_message: 'Invalid user' } },
            { match_phrase: { log_message: 'authentication failure' } },
          ],
          minimum_should_match: 1,
        },
      },
      sort: [{ collected_at: { order: 'desc' } }],
      size: 100,
    }, null, 2),
  },
  {
    name: 'Privilege Escalation',
    description: 'sudo, su, and setuid events',
    dsl: JSON.stringify({
      query: {
        bool: {
          should: [
            { match_phrase: { log_message: 'sudo' } },
            { match_phrase: { log_message: 'su root' } },
            { match_phrase: { log_message: 'NOPASSWD' } },
            { match_phrase: { log_message: 'setuid' } },
          ],
          minimum_should_match: 1,
        },
      },
      sort: [{ collected_at: { order: 'desc' } }],
      size: 100,
    }, null, 2),
  },
  {
    name: 'Lateral Movement (SSH)',
    description: 'Accepted SSH keys and remote login events',
    dsl: JSON.stringify({
      query: {
        bool: {
          must: [
            { match_phrase: { log_message: 'Accepted' } },
          ],
          should: [
            { match_phrase: { log_message: 'publickey' } },
            { match_phrase: { log_message: 'password' } },
          ],
          minimum_should_match: 1,
        },
      },
      sort: [{ collected_at: { order: 'desc' } }],
      size: 100,
    }, null, 2),
  },
  {
    name: 'Outbound C2 Beacons',
    description: 'Repeated network connections to same destination',
    dsl: JSON.stringify({
      query: {
        bool: {
          should: [
            { match_phrase: { log_message: 'CONNECT' } },
            { match_phrase: { log_message: 'outbound' } },
            { match_phrase: { log_message: 'tcp_out' } },
          ],
          minimum_should_match: 1,
        },
      },
      aggs: {
        by_dest: {
          terms: { field: 'parsed_fields.dst_ip', size: 20 },
        },
      },
      size: 50,
      sort: [{ collected_at: { order: 'desc' } }],
    }, null, 2),
  },
  {
    name: 'Malware / AV Detections',
    description: 'Antivirus and EDR detection events',
    dsl: JSON.stringify({
      query: {
        bool: {
          should: [
            { match_phrase: { log_message: 'MALWARE' } },
            { match_phrase: { log_message: 'THREAT' } },
            { match_phrase: { log_message: 'detected' } },
            { match_phrase: { log_message: 'quarantine' } },
            { match_phrase: { log_message: 'infected' } },
          ],
          minimum_should_match: 1,
        },
      },
      sort: [{ collected_at: { order: 'desc' } }],
      size: 100,
    }, null, 2),
  },
  {
    name: 'Events by Source (agg)',
    description: 'Count events grouped by log_source (aggregation)',
    dsl: JSON.stringify({
      query: { match_all: {} },
      aggs: {
        by_source: {
          terms: { field: 'log_source', size: 30 },
        },
        over_time: {
          date_histogram: {
            field: 'collected_at',
            calendar_interval: '1h',
          },
        },
      },
      size: 0,
    }, null, 2),
  },
  {
    name: 'Time Range — Last 1 Hour',
    description: 'All logs from the past hour',
    dsl: JSON.stringify({
      query: {
        bool: {
          filter: [
            {
              range: {
                collected_at: {
                  gte: 'now-1h/h',
                  lte: 'now',
                },
              },
            },
          ],
        },
      },
      sort: [{ collected_at: { order: 'desc' } }],
      size: 200,
    }, null, 2),
  },
  {
    name: 'Full-text Search (KQL style)',
    description: 'Query string across all text fields',
    dsl: JSON.stringify({
      query: {
        query_string: {
          query: 'error OR failed OR denied',
          default_field: 'log_message',
          analyze_wildcard: true,
        },
      },
      sort: [{ collected_at: { order: 'desc' } }],
      size: 100,
    }, null, 2),
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────────────────────

function healthColor(h: string) {
  if (h === 'green')  return '#22c55e';
  if (h === 'yellow') return '#fbbf24';
  return '#f85149';
}

function formatJson(v: unknown): string {
  try { return JSON.stringify(v, null, 2); } catch { return String(v); }
}

function flattenSource(source: Record<string, unknown>, prefix = ''): [string, string][] {
  const pairs: [string, string][] = [];
  for (const [k, v] of Object.entries(source)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      pairs.push(...flattenSource(v as Record<string, unknown>, key));
    } else {
      pairs.push([key, String(v)]);
    }
  }
  return pairs;
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-components
// ─────────────────────────────────────────────────────────────────────────────

function HitRow({ hit, idx }: { hit: ESHit; idx: number }) {
  const [open, setOpen] = useState(false);
  const [jsonMode, setJsonMode] = useState(false);
  const fields = flattenSource(hit._source);

  return (
    <div style={{ borderBottom: '1px solid var(--border)' }}>
      <button
        className="w-full text-left px-4 py-2.5 flex items-start gap-3 transition-colors hover:bg-[var(--glass-hover)]"
        onClick={() => setOpen(o => !o)}>
        <span className="text-[10px] font-mono mt-0.5 shrink-0 w-6 text-right" style={{ color: 'var(--text-3)' }}>
          {idx + 1}
        </span>
        <div className="mt-1 shrink-0">
          {open
            ? <ChevronDown className="h-3 w-3" style={{ color: 'var(--text-3)' }} />
            : <ChevronRight className="h-3 w-3" style={{ color: 'var(--text-3)' }} />}
        </div>
        <div className="min-w-0 flex-1 text-[12px] font-mono" style={{ color: 'var(--text-2)' }}>
          <span className="mr-3" style={{ color: 'var(--text-3)' }}>[{hit._index}]</span>
          {fields.find(([k]) => k === 'collected_at' || k === '@timestamp')?.[1] && (
            <span className="mr-3" style={{ color: 'var(--accent)' }}>
              {fields.find(([k]) => k === 'collected_at' || k === '@timestamp')![1]}
            </span>
          )}
          <span style={{ color: 'var(--text-1)' }}>
            {String(hit._source.log_message ?? hit._source.message ?? '').slice(0, 160)}
          </span>
        </div>
      </button>
      {open && (
        <div className="px-10 pb-3">
          <div className="rounded-lg p-3" style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}>
            <div className="flex items-center gap-2 mb-2">
              <button
                onClick={() => setJsonMode(false)}
                className="text-[10px] px-2 py-0.5 rounded"
                style={{
                  background: !jsonMode ? 'var(--accent-glow)' : 'transparent',
                  color: !jsonMode ? 'var(--accent)' : 'var(--text-3)',
                  border: `1px solid ${!jsonMode ? 'var(--accent-border)' : 'transparent'}`,
                }}>
                Table
              </button>
              <button
                onClick={() => setJsonMode(true)}
                className="text-[10px] px-2 py-0.5 rounded"
                style={{
                  background: jsonMode ? 'var(--accent-glow)' : 'transparent',
                  color: jsonMode ? 'var(--accent)' : 'var(--text-3)',
                  border: `1px solid ${jsonMode ? 'var(--accent-border)' : 'transparent'}`,
                }}>
                JSON
              </button>
              <span className="text-[10px] ml-auto" style={{ color: 'var(--text-3)' }}>id: {hit._id}</span>
            </div>
            {jsonMode ? (
              <pre className="text-[11px] overflow-x-auto" style={{ color: 'var(--text-1)' }}>
                {formatJson(hit._source)}
              </pre>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1">
                {fields.map(([k, v]) => (
                  <div key={k} className="flex gap-2 text-[11px] overflow-hidden">
                    <span className="shrink-0 font-semibold" style={{ color: 'var(--accent)' }}>{k}</span>
                    <span className="truncate" style={{ color: 'var(--text-2)' }} title={v}>{v}</span>
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

function AggsView({ aggs }: { aggs: Record<string, unknown> }) {
  return (
    <div className="p-4 space-y-4">
      <p className="text-[10px] font-bold tracking-widest uppercase" style={{ color: 'var(--text-3)' }}>
        Aggregations
      </p>
      {Object.entries(aggs).map(([name, value]) => {
        const agg = value as Record<string, unknown>;
        const buckets = (agg.buckets ?? []) as Array<{ key: unknown; doc_count: number }>;
        if (!buckets.length) return (
          <div key={name} className="g-card p-3">
            <p className="text-[11px] font-semibold mb-1" style={{ color: 'var(--text-2)' }}>{name}</p>
            <pre className="text-[10px]" style={{ color: 'var(--text-3)' }}>{formatJson(value)}</pre>
          </div>
        );
        const max = Math.max(...buckets.map(b => b.doc_count), 1);
        return (
          <div key={name} className="g-card p-3">
            <p className="text-[11px] font-semibold mb-3" style={{ color: 'var(--text-2)' }}>{name}</p>
            <div className="space-y-1.5">
              {buckets.slice(0, 20).map((b, i) => (
                <div key={i} className="flex items-center gap-2">
                  <span className="text-[11px] shrink-0 w-32 truncate font-mono" style={{ color: 'var(--text-2)' }}>
                    {String(b.key)}
                  </span>
                  <div className="flex-1 h-4 rounded overflow-hidden" style={{ background: 'var(--glass-bg-2)' }}>
                    <div
                      className="h-full rounded"
                      style={{
                        width: `${(b.doc_count / max) * 100}%`,
                        background: 'var(--accent)',
                        opacity: 0.7,
                      }}
                    />
                  </div>
                  <span className="text-[10px] shrink-0 tabular-nums" style={{ color: 'var(--text-3)' }}>
                    {b.doc_count.toLocaleString()}
                  </span>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main page
// ─────────────────────────────────────────────────────────────────────────────

export default function ElasticQueryPage() {
  // ── State ──────────────────────────────────────────────────────────────────
  const [indices, setIndices]       = useState<ESIndex[]>([]);
  const [clusterOk, setClusterOk]   = useState<boolean | null>(null);
  const [clusterStatus, setClusterStatus] = useState('');
  const [selectedIndex, setSelectedIndex] = useState('');
  const [dsl, setDsl]               = useState(TEMPLATES[0].dsl);
  const [result, setResult]         = useState<ESResult | null>(null);
  const [running, setRunning]       = useState(false);
  const [error, setError]           = useState<string | null>(null);
  const [activeTab, setActiveTab]   = useState<'hits' | 'aggs' | 'raw'>('hits');

  // Saved queries
  const [savedQueries, setSavedQueries] = useState<SavedQuery[]>([]);
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [saveName, setSaveName]     = useState('');

  // Query history (session only)
  const [history, setHistory]       = useState<{ dsl: string; index: string; ts: string; total: number }[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [showTemplates, setShowTemplates] = useState(false);
  const [showSaved, setShowSaved]   = useState(false);

  // Copy state
  const [copied, setCopied]         = useState(false);

  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // ── Load cluster health + indices ──────────────────────────────────────────
  const loadMeta = useCallback(async () => {
    try {
      const [healthRes, indicesRes] = await Promise.allSettled([
        api.get('/elastic/health'),
        api.get('/elastic/indices'),
      ]);
      if (healthRes.status === 'fulfilled') {
        const h = healthRes.value.data;
        setClusterOk(h.status !== 'not_configured');
        setClusterStatus(h.status ?? 'unknown');
      }
      if (indicesRes.status === 'fulfilled') {
        const idxList: ESIndex[] = indicesRes.value.data.indices ?? [];
        setIndices(idxList);
        if (!selectedIndex && idxList.length > 0) {
          const firstLog = idxList.find(i => i.index.startsWith('xcloak-logs-'));
          setSelectedIndex((firstLog ?? idxList[0]).index);
        }
      }
    } catch { /* ignore */ }
  }, [selectedIndex]);

  useEffect(() => { loadMeta(); }, []);

  // Load saved queries from localStorage
  useEffect(() => {
    try {
      const raw = localStorage.getItem('xcloak_es_saved');
      if (raw) setSavedQueries(JSON.parse(raw));
    } catch { /* ignore */ }
  }, []);

  // ── Run query ──────────────────────────────────────────────────────────────
  const runQuery = useCallback(async () => {
    let parsedDSL: unknown;
    try { parsedDSL = JSON.parse(dsl); } catch {
      setError('Invalid JSON — check your DSL syntax'); return;
    }

    setRunning(true);
    setError(null);
    setResult(null);

    try {
      const res = await api.post('/elastic/query', {
        index: selectedIndex || undefined,
        dsl: parsedDSL,
      });
      const data: ESResult = res.data;
      if (data.error) {
        setError(data.error);
      } else {
        setResult(data);
        setActiveTab(data.aggregations && Object.keys(data.aggregations).length > 0 ? 'aggs' : 'hits');
        setHistory(prev => [{
          dsl,
          index: selectedIndex,
          ts: new Date().toLocaleTimeString(),
          total: data.total,
        }, ...prev.slice(0, 49)]);
      }
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { error?: string } }; message?: string }).response?.data?.error
        ?? (e as { message?: string }).message ?? 'Query failed';
      setError(msg);
    } finally {
      setRunning(false);
    }
  }, [dsl, selectedIndex]);

  // Ctrl/Cmd+Enter to run
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runQuery(); }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [runQuery]);

  // ── Save query ─────────────────────────────────────────────────────────────
  const saveQuery = () => {
    if (!saveName.trim()) return;
    const q: SavedQuery = {
      id: Date.now().toString(),
      name: saveName.trim(),
      index: selectedIndex,
      dsl,
      created_at: new Date().toISOString(),
    };
    const next = [q, ...savedQueries];
    setSavedQueries(next);
    localStorage.setItem('xcloak_es_saved', JSON.stringify(next));
    setShowSaveDialog(false);
    setSaveName('');
  };

  const deleteSaved = (id: string) => {
    const next = savedQueries.filter(q => q.id !== id);
    setSavedQueries(next);
    localStorage.setItem('xcloak_es_saved', JSON.stringify(next));
  };

  // ── Export ─────────────────────────────────────────────────────────────────
  const exportJSON = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result.hits?.hits ?? [], null, 2)], { type: 'application/json' });
    const a = Object.assign(document.createElement('a'), {
      href: URL.createObjectURL(blob),
      download: `es-results-${Date.now()}.json`,
    });
    a.click(); URL.revokeObjectURL(a.href);
  };

  const exportCSV = () => {
    if (!result?.hits?.hits?.length) return;
    const hits = result.hits.hits;
    const allKeys = [...new Set(hits.flatMap(h => flattenSource(h._source).map(([k]) => k)))];
    const header = ['_id', '_index', ...allKeys];
    const rows = hits.map(h => {
      const flat = Object.fromEntries(flattenSource(h._source));
      return [h._id, h._index, ...allKeys.map(k => flat[k] ?? '')];
    });
    const csv = [header, ...rows]
      .map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(','))
      .join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = Object.assign(document.createElement('a'), {
      href: URL.createObjectURL(blob),
      download: `es-results-${Date.now()}.csv`,
    });
    a.click(); URL.revokeObjectURL(a.href);
  };

  const copyDSL = () => {
    navigator.clipboard.writeText(dsl);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  // Format the DSL JSON
  const formatDSL = () => {
    try { setDsl(JSON.stringify(JSON.parse(dsl), null, 2)); } catch { /* ignore */ }
  };

  const hits = result?.hits?.hits ?? [];
  const aggs = result?.aggregations ?? null;

  return (
    <RootLayout
      title="Elasticsearch Query"
      subtitle="Raw DSL query interface — advanced log analytics"
      actions={
        <div className="flex items-center gap-2">
          {/* Cluster health badge */}
          {clusterStatus && (
            <div className="flex items-center gap-1.5 px-2 py-1 rounded-lg text-[11px]"
              style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}>
              <span className="h-2 w-2 rounded-full"
                style={{ background: clusterOk ? healthColor(clusterStatus) : '#6b7280' }} />
              <span style={{ color: 'var(--text-2)' }}>
                {clusterOk ? `ES: ${clusterStatus}` : 'ES: not configured'}
              </span>
            </div>
          )}
          <button onClick={runQuery} disabled={running}
            className="g-btn g-btn-primary flex items-center gap-1.5 text-xs"
            title="Run query (Ctrl+Enter)">
            <Play className={`h-3.5 w-3.5 ${running ? 'animate-pulse' : ''}`} />
            {running ? 'Running…' : 'Run'}
            <span className="text-[9px] opacity-60 ml-0.5">⌘↵</span>
          </button>
        </div>
      }
    >
      <div className="flex flex-col gap-4" style={{ minHeight: 'calc(100vh - 8rem)' }}>

        {/* ── Row 1: Stats strip ─────────────────────────────────────────────── */}
        {result && !result.error && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: 'Total Hits',   value: result.total.toLocaleString(), icon: Database,  color: 'var(--accent)' },
              { label: 'Query Time',   value: `${result.took} ms`,           icon: Clock,     color: '#22c55e' },
              { label: 'Returned',     value: hits.length.toString(),         icon: Layers,    color: '#fbbf24' },
              { label: 'Timed Out',    value: result.timed_out ? 'Yes' : 'No', icon: Activity, color: result.timed_out ? '#f85149' : '#22c55e' },
            ].map(({ label, value, icon: Icon, color }) => (
              <div key={label} className="g-card p-3 flex items-center gap-2.5">
                <div className="p-1.5 rounded-lg" style={{ background: `${color}18`, border: `1px solid ${color}30` }}>
                  <Icon className="h-4 w-4" style={{ color }} />
                </div>
                <div>
                  <p className="text-lg font-bold" style={{ color }}>{value}</p>
                  <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{label}</p>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── Row 2: Main split pane ─────────────────────────────────────────── */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 flex-1">

          {/* ── LEFT: Editor panel ────────────────────────────────────────────── */}
          <div className="g-card flex flex-col" style={{ minHeight: 520 }}>

            {/* Editor toolbar */}
            <div className="flex items-center gap-2 px-4 py-2.5" style={{ borderBottom: '1px solid var(--border)' }}>
              {/* Index selector */}
              <div className="flex items-center gap-1.5">
                <Server className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
                <select
                  value={selectedIndex}
                  onChange={e => setSelectedIndex(e.target.value)}
                  className="g-select text-xs py-1"
                  style={{ minWidth: 160 }}>
                  <option value="">Auto (tenant index)</option>
                  {indices.map(idx => (
                    <option key={idx.index} value={idx.index}>
                      {idx.index}
                      {idx.docs_count ? ` (${Number(idx.docs_count).toLocaleString()} docs)` : ''}
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex-1" />

              <button onClick={formatDSL} className="g-btn g-btn-ghost text-[11px] py-1 px-2">
                <Code2 className="h-3 w-3 mr-1" /> Format
              </button>
              <button onClick={copyDSL} className="g-btn g-btn-ghost text-[11px] py-1 px-2">
                {copied ? <CheckCheck className="h-3 w-3" style={{ color: '#22c55e' }} /> : <Copy className="h-3 w-3" />}
              </button>
            </div>

            {/* DSL textarea with line numbers */}
            <div className="flex flex-1 overflow-hidden relative">
              <div className="text-[11px] font-mono select-none px-2 pt-3 text-right"
                style={{
                  color: 'var(--text-3)',
                  background: 'var(--glass-bg-2)',
                  borderRight: '1px solid var(--border)',
                  minWidth: 36,
                  lineHeight: '1.6',
                  userSelect: 'none',
                }}>
                {dsl.split('\n').map((_, i) => (
                  <div key={i}>{i + 1}</div>
                ))}
              </div>
              <textarea
                ref={textareaRef}
                value={dsl}
                onChange={e => setDsl(e.target.value)}
                spellCheck={false}
                className="flex-1 resize-none outline-none text-[12px] font-mono px-4 py-3"
                style={{
                  background: 'transparent',
                  color: 'var(--text-1)',
                  lineHeight: '1.6',
                  tabSize: 2,
                }}
                placeholder="Enter Elasticsearch Query DSL…"
              />
            </div>

            {/* Template / Saved / History tabs */}
            <div style={{ borderTop: '1px solid var(--border)' }}>
              <div className="flex items-center gap-0" style={{ borderBottom: '1px solid var(--border)' }}>
                {[
                  { key: 'templates', label: 'Templates', icon: BookOpen, count: TEMPLATES.length, open: showTemplates, set: setShowTemplates, others: [setShowSaved, setShowHistory] },
                  { key: 'saved',     label: 'Saved',     icon: Save,     count: savedQueries.length, open: showSaved,  set: setShowSaved,  others: [setShowTemplates, setShowHistory] },
                  { key: 'history',   label: 'History',   icon: Clock,    count: history.length, open: showHistory, set: setShowHistory, others: [setShowTemplates, setShowSaved] },
                ].map(({ key, label, icon: Icon, count, open, set, others }) => (
                  <button key={key}
                    onClick={() => { others.forEach(f => f(false)); set(o => !o); }}
                    className="flex items-center gap-1.5 px-4 py-2 text-[11px] transition-colors"
                    style={{
                      color: open ? 'var(--accent)' : 'var(--text-3)',
                      borderBottom: open ? '2px solid var(--accent)' : '2px solid transparent',
                    }}>
                    <Icon className="h-3 w-3" />
                    {label}
                    {count > 0 && (
                      <span className="text-[9px] px-1 rounded-full" style={{ background: 'var(--glass-bg-2)' }}>
                        {count}
                      </span>
                    )}
                  </button>
                ))}
              </div>

              {/* Templates panel */}
              {showTemplates && (
                <div className="max-h-52 overflow-y-auto">
                  {TEMPLATES.map(t => (
                    <button key={t.name}
                      onClick={() => { setDsl(t.dsl); setShowTemplates(false); }}
                      className="w-full text-left px-4 py-2.5 transition-colors border-b"
                      style={{ borderColor: 'var(--border)' }}
                      onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--glass-hover)'}
                      onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}>
                      <p className="text-[12px] font-semibold" style={{ color: 'var(--text-1)' }}>{t.name}</p>
                      <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{t.description}</p>
                    </button>
                  ))}
                </div>
              )}

              {/* Saved queries panel */}
              {showSaved && (
                <div className="max-h-52 overflow-y-auto">
                  {savedQueries.length === 0 ? (
                    <p className="px-4 py-6 text-center text-[11px]" style={{ color: 'var(--text-3)' }}>
                      No saved queries yet. Run a query and click Save.
                    </p>
                  ) : savedQueries.map(q => (
                    <div key={q.id} className="flex items-center px-4 py-2 border-b gap-3"
                      style={{ borderColor: 'var(--border)' }}>
                      <button className="flex-1 text-left"
                        onClick={() => { setDsl(q.dsl); if (q.index) setSelectedIndex(q.index); setShowSaved(false); }}>
                        <p className="text-[12px] font-semibold" style={{ color: 'var(--text-1)' }}>{q.name}</p>
                        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                          {q.index || 'auto'} · {new Date(q.created_at).toLocaleDateString()}
                        </p>
                      </button>
                      <button onClick={() => deleteSaved(q.id)} style={{ color: 'var(--text-3)' }}
                        onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--red)'}
                        onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {/* History panel */}
              {showHistory && (
                <div className="max-h-52 overflow-y-auto">
                  {history.length === 0 ? (
                    <p className="px-4 py-6 text-center text-[11px]" style={{ color: 'var(--text-3)' }}>
                      No history yet. Run a query first.
                    </p>
                  ) : history.map((h, i) => (
                    <button key={i}
                      onClick={() => { setDsl(h.dsl); if (h.index) setSelectedIndex(h.index); setShowHistory(false); }}
                      className="w-full text-left px-4 py-2 border-b flex items-center gap-3 transition-colors"
                      style={{ borderColor: 'var(--border)' }}
                      onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--glass-hover)'}
                      onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}>
                      <Clock className="h-3 w-3 shrink-0" style={{ color: 'var(--text-3)' }} />
                      <div className="flex-1 min-w-0">
                        <p className="text-[11px] truncate font-mono" style={{ color: 'var(--text-2)' }}>
                          {h.dsl.replace(/\s+/g, ' ').slice(0, 80)}
                        </p>
                        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                          {h.ts} · {h.index || 'auto'} · {h.total.toLocaleString()} hits
                        </p>
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* ── RIGHT: Results panel ──────────────────────────────────────────── */}
          <div className="g-card flex flex-col" style={{ minHeight: 520 }}>

            {/* Results toolbar */}
            <div className="flex items-center gap-2 px-4 py-2.5" style={{ borderBottom: '1px solid var(--border)' }}>
              {result && !result.error ? (
                <>
                  <div className="flex items-center gap-1">
                    {[
                      { id: 'hits' as const, label: 'Hits', icon: Table2, count: hits.length },
                      { id: 'aggs' as const, label: 'Aggregations', icon: Activity, count: aggs ? Object.keys(aggs).length : 0 },
                      { id: 'raw'  as const, label: 'Raw JSON', icon: Braces, count: 0 },
                    ].map(({ id, label, icon: Icon, count }) => (
                      <button key={id}
                        onClick={() => setActiveTab(id)}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] transition-colors"
                        style={{
                          background: activeTab === id ? 'var(--accent-glow)' : 'transparent',
                          color: activeTab === id ? 'var(--accent)' : 'var(--text-3)',
                          border: `1px solid ${activeTab === id ? 'var(--accent-border)' : 'transparent'}`,
                        }}>
                        <Icon className="h-3 w-3" />
                        {label}
                        {count > 0 && <span className="text-[9px] opacity-70">{count}</span>}
                      </button>
                    ))}
                  </div>
                  <div className="flex-1" />
                  <button onClick={exportCSV} className="g-btn g-btn-ghost text-[11px] py-1 px-2">
                    <Download className="h-3 w-3 mr-1" /> CSV
                  </button>
                  <button onClick={exportJSON} className="g-btn g-btn-ghost text-[11px] py-1 px-2">
                    <Download className="h-3 w-3 mr-1" /> JSON
                  </button>
                  <button
                    onClick={() => setShowSaveDialog(true)}
                    className="g-btn g-btn-ghost text-[11px] py-1 px-2">
                    <Save className="h-3 w-3 mr-1" /> Save
                  </button>
                </>
              ) : (
                <p className="text-[12px]" style={{ color: 'var(--text-3)' }}>
                  {running ? 'Executing query…' : 'Run a query to see results'}
                </p>
              )}
            </div>

            {/* Results body */}
            <div className="flex-1 overflow-y-auto">
              {error && (
                <div className="m-4 rounded-xl p-4 flex items-start gap-3"
                  style={{ background: 'rgba(248,81,73,0.08)', border: '1px solid rgba(248,81,73,0.25)' }}>
                  <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" style={{ color: '#f85149' }} />
                  <div>
                    <p className="text-[12px] font-semibold mb-1" style={{ color: '#f85149' }}>Query Error</p>
                    <p className="text-[11px] font-mono" style={{ color: 'var(--text-2)' }}>{error}</p>
                  </div>
                </div>
              )}

              {!error && !result && !running && (
                <div className="flex flex-col items-center justify-center h-64 gap-3">
                  <Search className="h-12 w-12 opacity-15" style={{ color: 'var(--text-3)' }} />
                  <p className="text-[13px]" style={{ color: 'var(--text-3)' }}>
                    Write a DSL query and press <kbd className="mono text-[11px] px-1.5 py-0.5 rounded" style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}>⌘↵</kbd> to run
                  </p>
                  <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
                    Select a template from the panel below to get started
                  </p>
                </div>
              )}

              {running && (
                <div className="flex flex-col items-center justify-center h-64 gap-3">
                  <div className="h-10 w-10 rounded-full border-2 animate-spin"
                    style={{ borderColor: 'var(--accent)', borderTopColor: 'transparent' }} />
                  <p className="text-[12px]" style={{ color: 'var(--text-3)' }}>Executing against Elasticsearch…</p>
                </div>
              )}

              {result && !result.error && activeTab === 'hits' && (
                <>
                  {hits.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-48 gap-2">
                      <Database className="h-10 w-10 opacity-15" style={{ color: 'var(--text-3)' }} />
                      <p className="text-[13px]" style={{ color: 'var(--text-3)' }}>No documents matched your query</p>
                    </div>
                  ) : (
                    <>
                      <div className="px-4 py-2 text-[11px]" style={{ color: 'var(--text-3)', borderBottom: '1px solid var(--border)' }}>
                        Showing {hits.length} of {result.total.toLocaleString()} total hits
                      </div>
                      {hits.map((hit, i) => (
                        <HitRow key={`${hit._id}-${i}`} hit={hit} idx={i} />
                      ))}
                    </>
                  )}
                </>
              )}

              {result && !result.error && activeTab === 'aggs' && aggs && (
                <AggsView aggs={aggs} />
              )}

              {result && !result.error && activeTab === 'aggs' && !aggs && (
                <div className="flex flex-col items-center justify-center h-48 gap-2">
                  <Activity className="h-10 w-10 opacity-15" style={{ color: 'var(--text-3)' }} />
                  <p className="text-[13px]" style={{ color: 'var(--text-3)' }}>
                    No aggregations in response. Add an <code className="font-mono">aggs</code> block to your DSL.
                  </p>
                </div>
              )}

              {result && activeTab === 'raw' && (
                <pre className="p-4 text-[11px] font-mono overflow-x-auto" style={{ color: 'var(--text-1)' }}>
                  {formatJson(result)}
                </pre>
              )}
            </div>
          </div>
        </div>

        {/* ── Indices table ──────────────────────────────────────────────────── */}
        {indices.length > 0 && (
          <div className="g-card overflow-hidden">
            <div className="px-4 py-2.5" style={{ borderBottom: '1px solid var(--border)' }}>
              <p className="text-[11px] font-semibold" style={{ color: 'var(--text-2)' }}>
                Available Indices ({indices.length})
              </p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-[11px]">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    {['Health', 'Index', 'Docs', 'Size', ''].map(h => (
                      <th key={h} className="px-3 py-2 text-left font-semibold uppercase tracking-wide"
                        style={{ color: 'var(--text-3)' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {indices.map(idx => (
                    <tr key={idx.index} style={{ borderBottom: '1px solid var(--border)' }}
                      className="transition-colors hover:bg-[var(--glass-hover)]">
                      <td className="px-3 py-2">
                        <span className="h-2 w-2 rounded-full inline-block"
                          style={{ background: healthColor(idx.health) }} />
                      </td>
                      <td className="px-3 py-2 font-mono" style={{ color: 'var(--accent)' }}>
                        {idx.index}
                      </td>
                      <td className="px-3 py-2 tabular-nums" style={{ color: 'var(--text-2)' }}>
                        {Number(idx.docs_count || 0).toLocaleString()}
                      </td>
                      <td className="px-3 py-2" style={{ color: 'var(--text-2)' }}>{idx.store_size}</td>
                      <td className="px-3 py-2">
                        <button
                          onClick={() => setSelectedIndex(idx.index)}
                          className="text-[10px] px-2 py-0.5 rounded"
                          style={{
                            background: selectedIndex === idx.index ? 'var(--accent-glow)' : 'var(--glass-bg-2)',
                            color: selectedIndex === idx.index ? 'var(--accent)' : 'var(--text-3)',
                            border: `1px solid ${selectedIndex === idx.index ? 'var(--accent-border)' : 'var(--border)'}`,
                          }}>
                          {selectedIndex === idx.index ? 'selected' : 'use'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* ── Save dialog ──────────────────────────────────────────────────────── */}
      {showSaveDialog && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setShowSaveDialog(false)}>
          <div className="g-modal" style={{ maxWidth: 400 }}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Save Query</h2>
              <button onClick={() => setShowSaveDialog(false)} style={{ color: 'var(--text-2)' }}>
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="p-5 space-y-3">
              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Query name</label>
                <input
                  value={saveName}
                  onChange={e => setSaveName(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') saveQuery(); }}
                  placeholder="e.g. SSH Brute Force Hunt"
                  className="g-input w-full"
                  autoFocus
                />
              </div>
              <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
                Saved queries are stored locally in your browser.
              </p>
            </div>
            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => setShowSaveDialog(false)} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={saveQuery} disabled={!saveName.trim()} className="g-btn g-btn-primary flex-1 justify-center">
                <Save className="h-3.5 w-3.5" /> Save
              </button>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
