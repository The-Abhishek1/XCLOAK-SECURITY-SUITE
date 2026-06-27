'use client';

import { useState, useEffect, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { logSearchAPI, agentsAPI } from '@/lib/api';
import { LogEntry, LogSearchResult, SavedLogSearch, LogStats, Agent } from '@/types';
import {
  Search, Download, Save, Trash2, Clock, Database,
  ChevronDown, ChevronRight, Filter, RefreshCw, X, BarChart2,
} from 'lucide-react';

// ─────────────────────────────────────────────────────────────────────────────
// Parsed-fields panel inside a log row
// ─────────────────────────────────────────────────────────────────────────────
function ParsedFieldsGrid({ raw }: { raw: string }) {
  let pf: Record<string, string> = {};
  try { pf = JSON.parse(raw); } catch { /* empty */ }
  const entries = Object.entries(pf).filter(([, v]) => v && v !== '');
  if (entries.length === 0) return null;
  return (
    <div className="mt-2 grid grid-cols-2 sm:grid-cols-3 gap-1 text-[11px]">
      {entries.map(([k, v]) => (
        <div key={k} className="flex gap-1 overflow-hidden">
          <span className="shrink-0 font-semibold" style={{ color: 'var(--accent)' }}>{k}:</span>
          <span className="truncate" style={{ color: 'var(--text-2)' }}>{String(v)}</span>
        </div>
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Log row
// ─────────────────────────────────────────────────────────────────────────────
function LogRow({ log }: { log: LogEntry }) {
  const [open, setOpen] = useState(false);
  let ts = '';
  try { ts = new Date(log.collected_at).toLocaleString(); } catch { ts = log.collected_at; }

  return (
    <div className="border-b" style={{ borderColor: 'var(--border)' }}>
      <button
        className="w-full text-left px-4 py-2 flex items-start gap-3 hover:bg-[var(--glass-hover)] transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        {open
          ? <ChevronDown className="h-3.5 w-3.5 mt-0.5 shrink-0" style={{ color: 'var(--text-3)' }} />
          : <ChevronRight className="h-3.5 w-3.5 mt-0.5 shrink-0" style={{ color: 'var(--text-3)' }} />
        }
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-3 mb-0.5">
            <span className="text-[10px] font-mono shrink-0" style={{ color: 'var(--text-3)' }}>{ts}</span>
            <span className="text-[10px] px-1.5 py-0.5 rounded-md shrink-0"
              style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
              {log.log_source || 'unknown'}
            </span>
            <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>agent:{log.agent_id}</span>
          </div>
          <p className="text-[12px] font-mono truncate" style={{ color: 'var(--text-1)' }}>
            {log.log_message}
          </p>
        </div>
      </button>
      {open && (
        <div className="px-4 pb-3 ml-6">
          <p className="text-[12px] font-mono whitespace-pre-wrap break-all mb-2" style={{ color: 'var(--text-1)' }}>
            {log.log_message}
          </p>
          <ParsedFieldsGrid raw={log.parsed_fields} />
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Stats mini-bar
// ─────────────────────────────────────────────────────────────────────────────
function StatsPanel({ stats }: { stats: LogStats }) {
  const max = Math.max(...stats.hourly_volume.map(h => h.count), 1);
  return (
    <div className="rounded-xl p-4 mb-4" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
      <div className="flex items-center gap-2 mb-3">
        <BarChart2 className="h-4 w-4" style={{ color: 'var(--accent)' }} />
        <span className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
          Log Volume (24h) — {stats.total_logs.toLocaleString()} total stored
        </span>
        <span className="ml-auto text-xs" style={{ color: 'var(--text-3)' }}>
          Retention: {stats.retention_days} days
        </span>
      </div>

      {/* Hourly sparkline */}
      {stats.hourly_volume.length > 0 && (
        <div className="flex items-end gap-0.5 h-10 mb-3">
          {stats.hourly_volume.map((h, i) => (
            <div key={i} title={`${h.count} logs`}
              className="flex-1 rounded-t-sm transition-all"
              style={{
                height: `${Math.max(2, (h.count / max) * 100)}%`,
                background: 'var(--accent)',
                opacity: 0.6 + (h.count / max) * 0.4,
              }}
            />
          ))}
        </div>
      )}

      <div className="grid grid-cols-2 gap-3">
        <div>
          <p className="text-[10px] uppercase font-bold mb-1" style={{ color: 'var(--text-3)' }}>Top Sources</p>
          {stats.by_source.slice(0, 4).map(s => (
            <div key={s.source} className="flex justify-between text-[11px]">
              <span style={{ color: 'var(--text-2)' }} className="truncate max-w-[120px]">{s.source || 'unknown'}</span>
              <span style={{ color: 'var(--text-1)' }}>{s.count.toLocaleString()}</span>
            </div>
          ))}
        </div>
        <div>
          <p className="text-[10px] uppercase font-bold mb-1" style={{ color: 'var(--text-3)' }}>Top Agents</p>
          {stats.by_agent.slice(0, 4).map(a => (
            <div key={a.agent_id} className="flex justify-between text-[11px]">
              <span style={{ color: 'var(--text-2)' }} className="truncate max-w-[120px]">{a.hostname}</span>
              <span style={{ color: 'var(--text-1)' }}>{a.count.toLocaleString()}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main page
// ─────────────────────────────────────────────────────────────────────────────
const TIME_RANGES = ['1h', '6h', '24h', '7d', '30d'];

export default function LogSearchPage() {
  const [query, setQuery]         = useState('');
  const [agentID, setAgentID]     = useState<number>(0);
  const [timeRange, setTimeRange] = useState('24h');
  const [severity, setSeverity]   = useState('');
  const [source, setSource]       = useState('');
  const [page, setPage]           = useState(0);
  const [limit]                   = useState(100);

  const [result, setResult]   = useState<LogSearchResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');

  const [agents, setAgents]       = useState<Agent[]>([]);
  const [stats, setStats]         = useState<LogStats | null>(null);
  const [savedSearches, setSaved] = useState<SavedLogSearch[]>([]);
  const [retentionDays, setRetDays] = useState(90);
  const [showSave, setShowSave] = useState(false);
  const [saveName, setSaveName]      = useState('');
  const [showSettings, setShowSettings] = useState(false);
  const [newRetDays, setNewRetDays]    = useState(90);

  useEffect(() => {
    agentsAPI.getAll().then(r => setAgents(r.data || [])).catch(() => {});
    logSearchAPI.stats().then(r => { setStats(r.data); setRetDays(r.data.retention_days); }).catch(() => {});
    logSearchAPI.getSavedSearches().then(r => setSaved(r.data || [])).catch(() => {});
  }, []);

  const buildParams = useCallback(() => {
    const p: Record<string, string | number | undefined> = { range: timeRange, limit, page };
    if (query) p.q = query;
    if (agentID) p.agent_id = agentID;
    if (severity) p.severity = severity;
    if (source) p.source = source;
    return p;
  }, [query, agentID, timeRange, severity, source, limit, page]);

  const runSearch = useCallback(async (overridePage = page) => {
    setLoading(true);
    setError('');
    try {
      const params = buildParams();
      params.page = overridePage;
      const r = await logSearchAPI.search(params);
      setResult(r.data);
      setPage(overridePage);
    } catch (e: any) {
      setError(e?.response?.data?.error || 'Search failed');
    } finally {
      setLoading(false);
    }
  }, [buildParams, page]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') runSearch(0);
  };

  const handleSave = async () => {
    if (!saveName.trim()) return;
    await logSearchAPI.saveSearch({ name: saveName, query, time_range: timeRange });
    setSaveName('');
    setShowSave(false);
    const r = await logSearchAPI.getSavedSearches();
    setSaved(r.data || []);
  };

  const handleDeleteSaved = async (id: number) => {
    await logSearchAPI.deleteSearch(id);
    setSaved(s => s.filter(x => x.id !== id));
  };

  const handleRunSaved = async (s: SavedLogSearch) => {
    setQuery(s.query);
    setTimeRange(s.time_range || '24h');
    await logSearchAPI.runSaved(s.id);
    const params: Record<string, string | number | undefined> = { range: s.time_range || '24h', limit, page: 0 };
    if (s.query) params.q = s.query;
    const r = await logSearchAPI.search(params);
    setResult(r.data);
    setPage(0);
  };

  const handleSetRetention = async () => {
    await logSearchAPI.setRetention(newRetDays);
    setRetDays(newRetDays);
    setShowSettings(false);
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

  return (
    <RootLayout>
      <div className="p-6 max-w-7xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-xl font-bold" style={{ color: 'var(--text-1)' }}>Log Search</h1>
            <p className="text-sm" style={{ color: 'var(--text-3)' }}>
              KQL-lite: <code className="text-[11px]">user:admin src_ip:10.0 &quot;failed&quot; -process:nmap</code>
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => { setShowSettings(true); setNewRetDays(retentionDays); }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs"
              style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
              <Database className="h-3.5 w-3.5" /> Retention ({retentionDays}d)
            </button>
          </div>
        </div>

        <div className="grid grid-cols-12 gap-4">
          {/* ── Left panel: saved searches ────────────── */}
          <div className="col-span-12 lg:col-span-3">
            <div className="rounded-xl p-4" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-bold uppercase" style={{ color: 'var(--text-3)' }}>Saved Searches</span>
                <button onClick={() => setShowSave(true)}
                  className="flex items-center gap-1 text-[11px] px-2 py-0.5 rounded"
                  style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                  <Save className="h-3 w-3" /> Save current
                </button>
              </div>
              {savedSearches.length === 0 && (
                <p className="text-xs" style={{ color: 'var(--text-3)' }}>No saved searches yet</p>
              )}
              <div className="space-y-1">
                {savedSearches.map(s => (
                  <div key={s.id} className="flex items-center justify-between gap-1 rounded-lg p-2 hover:bg-[var(--glass-hover)] group"
                    style={{ border: '1px solid transparent' }}>
                    <button onClick={() => handleRunSaved(s)} className="flex-1 text-left min-w-0">
                      <p className="text-[12px] font-medium truncate" style={{ color: 'var(--text-1)' }}>{s.name}</p>
                      <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>
                        {s.query || '(all logs)'} · {s.time_range}
                      </p>
                      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                        runs: {s.run_count}
                        {s.last_run_at && ` · ${new Date(s.last_run_at).toLocaleDateString()}`}
                      </p>
                    </button>
                    <button onClick={() => handleDeleteSaved(s.id)}
                      className="opacity-0 group-hover:opacity-100 p-1 rounded transition-opacity"
                      style={{ color: 'var(--red)' }}>
                      <Trash2 className="h-3 w-3" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* ── Right panel: search + results ─────────── */}
          <div className="col-span-12 lg:col-span-9 space-y-4">
            {/* Stats */}
            {stats && <StatsPanel stats={stats} />}

            {/* Search bar */}
            <div className="rounded-xl p-4" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
              <div className="flex gap-2 mb-3">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                  <input
                    className="w-full pl-9 pr-4 py-2 rounded-lg text-sm font-mono"
                    style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', color: 'var(--text-1)', outline: 'none' }}
                    placeholder='user:admin src_ip:10.0 "failed login"'
                    value={query}
                    onChange={e => setQuery(e.target.value)}
                    onKeyDown={handleKeyDown}
                  />
                </div>
                <button onClick={() => runSearch(0)}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-semibold"
                  style={{ background: 'var(--accent)', color: '#000' }}>
                  {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                  Search
                </button>
              </div>

              {/* Filters row */}
              <div className="flex flex-wrap gap-2">
                <div className="flex items-center gap-1">
                  <Filter className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
                  <span className="text-xs" style={{ color: 'var(--text-3)' }}>Filters:</span>
                </div>

                {/* Time range */}
                <div className="flex rounded-lg overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                  {TIME_RANGES.map(r => (
                    <button key={r}
                      className="px-2 py-0.5 text-[11px] transition-colors"
                      style={{
                        background: timeRange === r ? 'var(--accent)' : 'var(--glass-bg)',
                        color: timeRange === r ? '#000' : 'var(--text-2)',
                      }}
                      onClick={() => setTimeRange(r)}>
                      {r}
                    </button>
                  ))}
                </div>

                {/* Agent */}
                <select
                  className="text-xs px-2 py-0.5 rounded-lg"
                  style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-1)' }}
                  value={agentID}
                  onChange={e => setAgentID(Number(e.target.value))}>
                  <option value={0}>All agents</option>
                  {agents.map(a => <option key={a.id} value={a.id}>{a.hostname}</option>)}
                </select>

                {/* Severity */}
                <select
                  className="text-xs px-2 py-0.5 rounded-lg"
                  style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-1)' }}
                  value={severity}
                  onChange={e => setSeverity(e.target.value)}>
                  <option value="">All severities</option>
                  {['critical','high','medium','low','info'].map(s => <option key={s} value={s}>{s}</option>)}
                </select>

                {/* Source filter */}
                <input
                  className="text-xs px-2 py-0.5 rounded-lg"
                  style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-1)' }}
                  placeholder="Log source…"
                  value={source}
                  onChange={e => setSource(e.target.value)}
                />

                {/* Clear */}
                {(query || agentID || severity || source) && (
                  <button onClick={() => { setQuery(''); setAgentID(0); setSeverity(''); setSource(''); }}
                    className="flex items-center gap-1 text-xs"
                    style={{ color: 'var(--text-3)' }}>
                    <X className="h-3 w-3" /> Clear
                  </button>
                )}
              </div>
            </div>

            {error && (
              <div className="text-sm px-4 py-2 rounded-lg" style={{ background: 'var(--red-bg)', color: 'var(--red)', border: '1px solid var(--red)' }}>
                {error}
              </div>
            )}

            {/* Results */}
            {result && (
              <div className="rounded-xl overflow-hidden" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                <div className="flex items-center justify-between px-4 py-2" style={{ borderBottom: '1px solid var(--border)' }}>
                  <span className="text-xs" style={{ color: 'var(--text-2)' }}>
                    {result.total.toLocaleString()} result{result.total !== 1 ? 's' : ''}
                    {result.total > limit && ` (page ${page + 1})`}
                  </span>
                  <div className="flex items-center gap-2">
                    <button onClick={() => handleExport('csv')}
                      className="flex items-center gap-1 text-[11px] px-2 py-0.5 rounded"
                      style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                      <Download className="h-3 w-3" /> CSV
                    </button>
                    <button onClick={() => handleExport('json')}
                      className="flex items-center gap-1 text-[11px] px-2 py-0.5 rounded"
                      style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                      <Download className="h-3 w-3" /> JSON
                    </button>
                  </div>
                </div>

                <div className="max-h-[600px] overflow-y-auto">
                  {result.logs.length === 0 ? (
                    <p className="text-sm text-center py-8" style={{ color: 'var(--text-3)' }}>No logs found</p>
                  ) : (
                    result.logs.map(l => <LogRow key={l.id} log={l} />)
                  )}
                </div>

                {/* Pagination */}
                {(page > 0 || result.has_more) && (
                  <div className="flex justify-between px-4 py-2" style={{ borderTop: '1px solid var(--border)' }}>
                    <button disabled={page === 0}
                      onClick={() => runSearch(page - 1)}
                      className="text-xs px-3 py-1 rounded disabled:opacity-40"
                      style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                      ← Prev
                    </button>
                    <span className="text-xs self-center" style={{ color: 'var(--text-3)' }}>
                      Page {page + 1}
                    </span>
                    <button disabled={!result.has_more}
                      onClick={() => runSearch(page + 1)}
                      className="text-xs px-3 py-1 rounded disabled:opacity-40"
                      style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                      Next →
                    </button>
                  </div>
                )}
              </div>
            )}

            {!result && !loading && (
              <div className="text-center py-16" style={{ color: 'var(--text-3)' }}>
                <Clock className="h-10 w-10 mx-auto mb-3 opacity-30" />
                <p className="text-sm">Enter a query and click Search, or select a saved search.</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Save Search Modal ──────────────────────── */}
      {showSave && (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.6)' }}>
          <div className="rounded-xl p-6 w-80" style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>
            <h3 className="font-semibold mb-4" style={{ color: 'var(--text-1)' }}>Save Search</h3>
            <input
              className="w-full px-3 py-2 rounded-lg mb-4 text-sm"
              style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', color: 'var(--text-1)', outline: 'none' }}
              placeholder="Search name…"
              value={saveName}
              onChange={e => setSaveName(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') handleSave(); }}
              autoFocus
            />
            <div className="flex gap-2 justify-end">
              <button onClick={() => setShowSave(false)}
                className="px-3 py-1.5 rounded-lg text-sm"
                style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                Cancel
              </button>
              <button onClick={handleSave}
                className="px-3 py-1.5 rounded-lg text-sm font-semibold"
                style={{ background: 'var(--accent)', color: '#000' }}>
                Save
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Retention Settings Modal ───────────────── */}
      {showSettings && (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.6)' }}>
          <div className="rounded-xl p-6 w-80" style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>
            <h3 className="font-semibold mb-2" style={{ color: 'var(--text-1)' }}>Log Retention</h3>
            <p className="text-xs mb-4" style={{ color: 'var(--text-3)' }}>
              Logs older than this will be automatically deleted.
            </p>
            <div className="flex items-center gap-2 mb-4">
              <input type="number" min={1} max={730}
                className="w-20 px-3 py-2 rounded-lg text-sm"
                style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', color: 'var(--text-1)', outline: 'none' }}
                value={newRetDays}
                onChange={e => setNewRetDays(Number(e.target.value))}
              />
              <span className="text-sm" style={{ color: 'var(--text-2)' }}>days</span>
            </div>
            <div className="flex gap-2 mb-2">
              {[30, 60, 90, 180, 365].map(d => (
                <button key={d} onClick={() => setNewRetDays(d)}
                  className="text-[11px] px-2 py-0.5 rounded"
                  style={{
                    background: newRetDays === d ? 'var(--accent)' : 'var(--glass-bg)',
                    color: newRetDays === d ? '#000' : 'var(--text-2)',
                    border: '1px solid var(--border)',
                  }}>
                  {d}d
                </button>
              ))}
            </div>
            <div className="flex gap-2 justify-end mt-4">
              <button onClick={() => setShowSettings(false)}
                className="px-3 py-1.5 rounded-lg text-sm"
                style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                Cancel
              </button>
              <button onClick={handleSetRetention}
                className="px-3 py-1.5 rounded-lg text-sm font-semibold"
                style={{ background: 'var(--accent)', color: '#000' }}>
                Apply
              </button>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
