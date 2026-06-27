'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { logSearchAPI, agentsAPI } from '@/lib/api';
import { LogEntry, LogSearchResult, SavedLogSearch, LogStats, Agent } from '@/types';
import {
  Search, Download, Save, Trash2, Clock, Database,
  ChevronDown, ChevronRight, Filter, RefreshCw, X,
  BarChart2, BookOpen, Play, AlertCircle,
} from 'lucide-react';

// ─────────────────────────────────────────────────────────────────────────────
// Parsed fields panel
// ─────────────────────────────────────────────────────────────────────────────
function ParsedFieldsGrid({ raw }: { raw: string }) {
  let pf: Record<string, string> = {};
  try { pf = JSON.parse(raw); } catch { /* empty */ }
  const entries = Object.entries(pf).filter(([, v]) => v && v !== '');
  if (entries.length === 0) return null;
  return (
    <div className="mt-2 grid grid-cols-2 sm:grid-cols-3 gap-x-4 gap-y-1 text-[11px]">
      {entries.map(([k, v]) => (
        <div key={k} className="flex gap-1.5 overflow-hidden">
          <span className="shrink-0 font-semibold" style={{ color: 'var(--accent)' }}>{k}</span>
          <span className="truncate" style={{ color: 'var(--text-2)' }}>{String(v)}</span>
        </div>
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Severity pill derived from log_message / parsed_fields heuristic
// ─────────────────────────────────────────────────────────────────────────────
function severityFromLog(log: LogEntry): string {
  const msg = (log.log_message || '').toLowerCase();
  if (msg.includes('critical') || msg.includes('emerg') || msg.includes('fatal')) return 'critical';
  if (msg.includes('error') || msg.includes('err ') || msg.includes('failed') || msg.includes('failure')) return 'error';
  if (msg.includes('warn')) return 'warn';
  return '';
}

const SEV_STYLE: Record<string, { bg: string; color: string; dot: string }> = {
  critical: { bg: 'rgba(248,81,73,0.12)', color: '#f85149', dot: '#f85149' },
  error:    { bg: 'rgba(251,146,60,0.12)', color: '#fb923c', dot: '#fb923c' },
  warn:     { bg: 'rgba(251,191,36,0.10)', color: '#fbbf24', dot: '#fbbf24' },
};

// ─────────────────────────────────────────────────────────────────────────────
// Log row
// ─────────────────────────────────────────────────────────────────────────────
function LogRow({ log, agentName }: { log: LogEntry; agentName?: string }) {
  const [open, setOpen] = useState(false);
  const sev = severityFromLog(log);
  const sevStyle = SEV_STYLE[sev];
  let ts = '';
  try { ts = new Date(log.collected_at).toLocaleString(); } catch { ts = log.collected_at; }

  return (
    <div className="border-b transition-colors"
      style={{ borderColor: 'var(--border)', background: open ? 'var(--glass-bg)' : undefined }}>
      <button
        className="w-full text-left px-4 py-2.5 flex items-start gap-3 hover:bg-[var(--glass-hover)] transition-colors"
        onClick={() => setOpen(o => !o)}>
        <div className="mt-1 shrink-0">
          {open
            ? <ChevronDown className="h-3 w-3" style={{ color: 'var(--text-3)' }} />
            : <ChevronRight className="h-3 w-3" style={{ color: 'var(--text-3)' }} />
          }
        </div>
        {sevStyle && (
          <span className="mt-1.5 h-1.5 w-1.5 rounded-full shrink-0" style={{ background: sevStyle.dot }} />
        )}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 mb-0.5">
            <span className="text-[10px] font-mono shrink-0" style={{ color: 'var(--text-3)' }}>{ts}</span>
            {log.log_source && (
              <span className="text-[10px] px-1.5 py-0.5 rounded shrink-0"
                style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                {log.log_source}
              </span>
            )}
            {agentName && (
              <span className="text-[10px] shrink-0" style={{ color: 'var(--accent)' }}>{agentName}</span>
            )}
            {sevStyle && (
              <span className="text-[10px] px-1.5 py-0.5 rounded shrink-0 font-medium"
                style={{ background: sevStyle.bg, color: sevStyle.color }}>
                {sev}
              </span>
            )}
          </div>
          <p className="text-[12px] font-mono leading-snug" style={{ color: 'var(--text-1)' }}>
            {open ? log.log_message : (
              log.log_message.length > 200 ? log.log_message.slice(0, 200) + '…' : log.log_message
            )}
          </p>
        </div>
      </button>
      {open && (
        <div className="px-10 pb-3">
          <ParsedFieldsGrid raw={log.parsed_fields} />
          <div className="mt-2 flex items-center gap-3 text-[10px]" style={{ color: 'var(--text-3)' }}>
            <span>ID: {log.id}</span>
            <span>Agent ID: {log.agent_id}</span>
            {log.log_source && <span>Source: {log.log_source}</span>}
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Stats panel (sparkline + top sources/agents)
// ─────────────────────────────────────────────────────────────────────────────
function StatsPanel({ stats }: { stats: LogStats }) {
  const volume = stats.hourly_volume ?? [];
  const max = Math.max(...volume.map(h => h.count), 1);

  return (
    <div className="g-card p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <BarChart2 className="h-4 w-4" style={{ color: 'var(--accent)' }} />
          <span className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
            {stats.total_logs.toLocaleString()} logs stored
          </span>
        </div>
        <span className="text-xs" style={{ color: 'var(--text-3)' }}>
          {stats.retention_days}d retention · 24h volume below
        </span>
      </div>

      {volume.length > 0 ? (
        <div className="flex items-end gap-0.5 h-10">
          {volume.map((h, i) => (
            <div key={i} title={`${h.count} logs`}
              className="flex-1 rounded-t-sm transition-all cursor-default"
              style={{
                height: `${Math.max(4, (h.count / max) * 100)}%`,
                background: 'var(--accent)',
                opacity: 0.4 + (h.count / max) * 0.6,
              }}
            />
          ))}
        </div>
      ) : (
        <div className="h-10 flex items-center justify-center text-xs" style={{ color: 'var(--text-3)' }}>
          No data in the last 24h
        </div>
      )}

      <div className="grid grid-cols-2 gap-4 pt-1" style={{ borderTop: '1px solid var(--border)' }}>
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>
            Top Sources
          </p>
          <div className="space-y-1">
            {(stats.by_source ?? []).slice(0, 5).map(s => (
              <div key={s.source} className="flex items-center justify-between gap-2 text-[11px]">
                <span className="truncate" style={{ color: 'var(--text-2)' }}>{s.source || 'unknown'}</span>
                <span className="shrink-0 tabular-nums font-medium" style={{ color: 'var(--text-1)' }}>
                  {s.count.toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        </div>
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>
            Top Agents
          </p>
          <div className="space-y-1">
            {(stats.by_agent ?? []).slice(0, 5).map(a => (
              <div key={a.agent_id} className="flex items-center justify-between gap-2 text-[11px]">
                <span className="truncate" style={{ color: 'var(--text-2)' }}>{a.hostname}</span>
                <span className="shrink-0 tabular-nums font-medium" style={{ color: 'var(--text-1)' }}>
                  {a.count.toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────
const TIME_RANGES = ['1h', '6h', '24h', '7d', '30d'];

// ─────────────────────────────────────────────────────────────────────────────
// Main page
// ─────────────────────────────────────────────────────────────────────────────
export default function LogSearchPage() {
  const queryRef = useRef<HTMLInputElement>(null);

  const [query, setQuery]         = useState('');
  const [agentID, setAgentID]     = useState<number>(0);
  const [timeRange, setTimeRange] = useState('24h');
  const [source, setSource]       = useState('');
  const [page, setPage]           = useState(0);
  const limit = 100;

  const [result, setResult]     = useState<LogSearchResult | null>(null);
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState('');

  const [agents, setAgents]           = useState<Agent[]>([]);
  const [stats, setStats]             = useState<LogStats | null>(null);
  const [savedSearches, setSaved]     = useState<SavedLogSearch[]>([]);
  const [retentionDays, setRetDays]   = useState(90);
  const [showSave, setShowSave]       = useState(false);
  const [saveName, setSaveName]       = useState('');
  const [showRetention, setShowRet]   = useState(false);
  const [newRetDays, setNewRetDays]   = useState(90);

  useEffect(() => {
    agentsAPI.getAll().then(r => setAgents(r.data || [])).catch(() => {});
    logSearchAPI.stats().then(r => { setStats(r.data); setRetDays(r.data.retention_days); }).catch(() => {});
    logSearchAPI.getSavedSearches().then(r => setSaved(r.data || [])).catch(() => {});
  }, []);

  const buildParams = useCallback((overridePage = page) => {
    const p: Record<string, string | number | undefined> = { range: timeRange, limit, page: overridePage };
    if (query) p.q = query;
    if (agentID) p.agent_id = agentID;
    if (source) p.source = source;
    return p;
  }, [query, agentID, timeRange, source, limit, page]);

  const runSearch = useCallback(async (pg = 0) => {
    setLoading(true);
    setError('');
    try {
      const r = await logSearchAPI.search(buildParams(pg));
      setResult(r.data);
      setPage(pg);
    } catch (e: any) {
      setError(e?.response?.data?.error || 'Search failed');
    } finally { setLoading(false); }
  }, [buildParams]);

  const clearFilters = () => { setQuery(''); setAgentID(0); setSource(''); setTimeRange('24h'); setResult(null); };

  const handleSave = async () => {
    if (!saveName.trim()) return;
    await logSearchAPI.saveSearch({ name: saveName, query, time_range: timeRange });
    setSaveName(''); setShowSave(false);
    logSearchAPI.getSavedSearches().then(r => setSaved(r.data || []));
  };

  const handleDeleteSaved = async (id: number) => {
    await logSearchAPI.deleteSearch(id);
    setSaved(s => s.filter(x => x.id !== id));
  };

  const handleRunSaved = async (s: SavedLogSearch) => {
    setQuery(s.query);
    setTimeRange(s.time_range || '24h');
    setAgentID(0); setSource('');
    setLoading(true); setError('');
    try {
      const params: Record<string, string | number | undefined> = {
        range: s.time_range || '24h', limit, page: 0,
      };
      if (s.query) params.q = s.query;
      const r = await logSearchAPI.search(params);
      setResult(r.data); setPage(0);
    } catch (e: any) { setError(e?.response?.data?.error || 'Failed'); }
    finally { setLoading(false); }
  };

  const handleSetRetention = async () => {
    await logSearchAPI.setRetention(newRetDays);
    setRetDays(newRetDays); setShowRet(false);
  };

  const handleExport = async (fmt: 'csv' | 'json') => {
    const r = await logSearchAPI.export(buildParams(), fmt);
    const url = URL.createObjectURL(new Blob([r.data]));
    const a = document.createElement('a');
    a.href = url;
    a.download = `logs-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.${fmt}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const hasActiveFilters = query || agentID || source || timeRange !== '24h';

  return (
    <RootLayout
      title="Log Search"
      subtitle='KQL-lite: user:admin src_ip:10.0 "failed" -process:nmap'
      actions={
        <button onClick={() => { setShowRet(true); setNewRetDays(retentionDays); }}
          className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
          <Database className="h-3.5 w-3.5" />
          Retention: {retentionDays}d
        </button>
      }>

      <div className="grid grid-cols-12 gap-4">

        {/* ── Left: saved searches ─────────────────────── */}
        <aside className="col-span-12 lg:col-span-3">
          <div className="g-card p-4 sticky top-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <BookOpen className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
                <span className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
                  Saved
                </span>
              </div>
              <button onClick={() => setShowSave(true)}
                className="flex items-center gap-1 text-[11px] px-2 py-1 rounded-lg"
                style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                <Save className="h-3 w-3" /> Save
              </button>
            </div>

            {savedSearches.length === 0 ? (
              <p className="text-xs py-4 text-center" style={{ color: 'var(--text-3)' }}>
                No saved searches
              </p>
            ) : (
              <div className="space-y-1">
                {savedSearches.map(s => (
                  <div key={s.id} className="group flex items-start gap-1 rounded-lg p-2 transition-colors hover:bg-[var(--glass-hover)]">
                    <button onClick={() => handleRunSaved(s)} className="flex-1 text-left min-w-0">
                      <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{s.name}</p>
                      <p className="text-[10px] mono truncate mt-0.5" style={{ color: 'var(--text-3)' }}>
                        {s.query || '(all)'} · {s.time_range}
                      </p>
                      <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>
                        {s.run_count} run{s.run_count !== 1 ? 's' : ''}
                        {s.last_run_at && ` · ${new Date(s.last_run_at).toLocaleDateString()}`}
                      </p>
                    </button>
                    <button onClick={() => handleDeleteSaved(s.id)}
                      className="opacity-0 group-hover:opacity-100 shrink-0 p-1 rounded transition-opacity"
                      style={{ color: 'var(--red)' }}>
                      <Trash2 className="h-3 w-3" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </aside>

        {/* ── Right: search + results ──────────────────── */}
        <main className="col-span-12 lg:col-span-9 space-y-4">

          {/* Stats */}
          {stats && <StatsPanel stats={stats} />}

          {/* Search bar */}
          <div className="g-card p-4 space-y-3">
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                <input
                  ref={queryRef}
                  className="g-input pl-9 font-mono text-sm"
                  placeholder='Search logs… e.g. user:admin "failed login"'
                  value={query}
                  onChange={e => setQuery(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && runSearch(0)}
                />
              </div>
              <button onClick={() => runSearch(0)} disabled={loading}
                className="g-btn g-btn-primary flex items-center gap-1.5 px-5">
                {loading
                  ? <RefreshCw className="h-4 w-4 animate-spin" />
                  : <Play className="h-4 w-4" />}
                Run
              </button>
            </div>

            {/* Filter row */}
            <div className="flex flex-wrap items-center gap-2">
              <Filter className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />

              {/* Time range pills */}
              <div className="flex rounded-lg overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                {TIME_RANGES.map(r => (
                  <button key={r}
                    className="px-2.5 py-1 text-[11px] font-medium transition-colors"
                    style={{
                      background: timeRange === r ? 'var(--accent)' : 'transparent',
                      color: timeRange === r ? '#000' : 'var(--text-3)',
                    }}
                    onClick={() => setTimeRange(r)}>
                    {r}
                  </button>
                ))}
              </div>

              <select className="g-select text-xs py-1" value={agentID}
                onChange={e => setAgentID(Number(e.target.value))}>
                <option value={0}>All agents</option>
                {agents.map(a => <option key={a.id} value={a.id}>{a.hostname}</option>)}
              </select>

              <input
                className="g-input text-xs py-1 max-w-[140px]"
                placeholder="Log source…"
                value={source}
                onChange={e => setSource(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && runSearch(0)}
              />

              {hasActiveFilters && (
                <button onClick={clearFilters}
                  className="flex items-center gap-1 text-xs ml-auto"
                  style={{ color: 'var(--text-3)' }}>
                  <X className="h-3 w-3" /> Clear
                </button>
              )}
            </div>
          </div>

          {/* Error */}
          {error && (
            <div className="flex items-center gap-2 px-4 py-3 rounded-xl text-sm"
              style={{ background: 'var(--red-bg)', color: 'var(--red)', border: '1px solid var(--red-border)' }}>
              <AlertCircle className="h-4 w-4 shrink-0" /> {error}
            </div>
          )}

          {/* Results */}
          {result && (
            <div className="g-card overflow-hidden">
              <div className="flex items-center justify-between px-4 py-2.5"
                style={{ borderBottom: '1px solid var(--border)' }}>
                <span className="text-xs font-medium" style={{ color: 'var(--text-2)' }}>
                  {result.total.toLocaleString()} result{result.total !== 1 ? 's' : ''}
                  {result.total > limit && ` · page ${page + 1}`}
                </span>
                <div className="flex items-center gap-2">
                  <button onClick={() => handleExport('csv')}
                    className="g-btn g-btn-ghost text-[11px] flex items-center gap-1 py-1">
                    <Download className="h-3 w-3" /> CSV
                  </button>
                  <button onClick={() => handleExport('json')}
                    className="g-btn g-btn-ghost text-[11px] flex items-center gap-1 py-1">
                    <Download className="h-3 w-3" /> JSON
                  </button>
                </div>
              </div>

              <div className="max-h-[640px] overflow-y-auto">
                {result.logs.length === 0 ? (
                  <div className="py-16 text-center">
                    <Search className="mx-auto h-8 w-8 mb-2 opacity-30" style={{ color: 'var(--text-3)' }} />
                    <p className="text-sm" style={{ color: 'var(--text-3)' }}>No logs matched your query</p>
                  </div>
                ) : result.logs.map(l => (
                  <LogRow key={l.id} log={l} agentName={agents.find(a => a.id === l.agent_id)?.hostname} />
                ))}
              </div>

              {(page > 0 || result.has_more) && (
                <div className="flex items-center justify-between px-4 py-2"
                  style={{ borderTop: '1px solid var(--border)' }}>
                  <button disabled={page === 0} onClick={() => runSearch(page - 1)}
                    className="g-btn g-btn-ghost text-xs disabled:opacity-40">
                    ← Prev
                  </button>
                  <span className="text-xs" style={{ color: 'var(--text-3)' }}>Page {page + 1}</span>
                  <button disabled={!result.has_more} onClick={() => runSearch(page + 1)}
                    className="g-btn g-btn-ghost text-xs disabled:opacity-40">
                    Next →
                  </button>
                </div>
              )}
            </div>
          )}

          {!result && !loading && (
            <div className="g-card py-20 text-center">
              <Clock className="h-10 w-10 mx-auto mb-3 opacity-20" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm font-medium" style={{ color: 'var(--text-2)' }}>
                Run a search or pick a saved query
              </p>
              <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>
                Press Enter in the search bar or click Run
              </p>
            </div>
          )}
        </main>
      </div>

      {/* ── Save search modal ──────────────────────────── */}
      {showSave && (
        <div className="g-modal-backdrop" onClick={() => setShowSave(false)}>
          <div className="g-modal" style={{ maxWidth: 400 }} onClick={e => e.stopPropagation()}>
            <div className="p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Save Search</h2>
            </div>
            <div className="p-5">
              <label className="block text-xs mb-1.5" style={{ color: 'var(--text-3)' }}>Name</label>
              <input autoFocus className="g-input w-full" placeholder="My search…"
                value={saveName} onChange={e => setSaveName(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleSave()} />
              {query && (
                <p className="text-[11px] mt-2 mono" style={{ color: 'var(--text-3)' }}>
                  Query: {query} · {timeRange}
                </p>
              )}
            </div>
            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => setShowSave(false)} className="g-btn g-btn-ghost flex-1 justify-center">
                Cancel
              </button>
              <button onClick={handleSave} className="g-btn g-btn-primary flex-1 justify-center">
                Save
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Retention modal ────────────────────────────── */}
      {showRetention && (
        <div className="g-modal-backdrop" onClick={() => setShowRet(false)}>
          <div className="g-modal" style={{ maxWidth: 380 }} onClick={e => e.stopPropagation()}>
            <div className="p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Log Retention</h2>
            </div>
            <div className="p-5 space-y-4">
              <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                Logs older than this are automatically deleted by the nightly cleanup job.
              </p>
              <div className="flex items-center gap-3">
                <input type="number" min={1} max={730} className="g-input w-24"
                  value={newRetDays} onChange={e => setNewRetDays(Number(e.target.value))} />
                <span className="text-sm" style={{ color: 'var(--text-2)' }}>days</span>
              </div>
              <div className="flex gap-2 flex-wrap">
                {[30, 60, 90, 180, 365].map(d => (
                  <button key={d} onClick={() => setNewRetDays(d)}
                    className="text-xs px-3 py-1 rounded-lg"
                    style={{
                      background: newRetDays === d ? 'var(--accent)' : 'var(--glass-bg)',
                      color: newRetDays === d ? '#000' : 'var(--text-2)',
                      border: '1px solid var(--border)',
                    }}>
                    {d}d
                  </button>
                ))}
              </div>
            </div>
            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => setShowRet(false)} className="g-btn g-btn-ghost flex-1 justify-center">
                Cancel
              </button>
              <button onClick={handleSetRetention} className="g-btn g-btn-primary flex-1 justify-center">
                Apply
              </button>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
