'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import api from '@/lib/api';
import { Search, Play, Save, Trash2, Clock, ChevronDown, ChevronRight, Shield, Download, Cpu, Calendar, Zap } from 'lucide-react';
import { agentsAPI } from '@/lib/api';
import { Agent } from '@/types';
import { timeAgo } from '@/lib/utils';

const QUERY_TYPES = [
  { id: 'process',    label: 'Processes',    hint: 'e.g. nmap, bash, python3' },
  { id: 'connection', label: 'Connections',  hint: 'e.g. 192.168., :4444, ESTABLISHED' },
  { id: 'user',       label: 'Users',        hint: 'e.g. root, /bin/bash, /tmp' },
  { id: 'package',    label: 'Packages',     hint: 'e.g. openssh, curl, python3' },
  { id: 'log',        label: 'Logs',         hint: 'e.g. failed password, sudo, accepted' },
  { id: 'alert',      label: 'Alerts',       hint: 'e.g. T1078, brute force, IOC' },
  { id: 'file_hash',  label: 'File Hashes',  hint: 'e.g. /etc/passwd, sha256 hash prefix' },
];

const PRESET_HUNTS = [
  { name: 'Reverse Shell Indicators', type: 'process',    text: '/dev/tcp' },
  { name: 'Suspicious Bash',          type: 'process',    text: 'bash -i' },
  { name: 'Crypto Miners',            type: 'process',    text: 'xmrig' },
  { name: 'High Outbound Port',       type: 'connection', text: ':4444' },
  { name: 'Root Shell Users',         type: 'user',       text: '/bin/bash' },
  { name: 'Vulnerable SSH',           type: 'package',    text: 'openssh' },
  { name: 'Auth Failures',            type: 'log',        text: 'failed password' },
  { name: 'MITRE T1078',             type: 'alert',      text: 'T1078' },
];

interface SavedQuery {
  id: number;
  name: string;
  query_type: string;
  query_text: string;
  hit_count: number;
  last_run_at: string | null;
  created_at: string;
}

interface HuntResult {
  query_id: number;
  hits: number;
  duration_ms: string;
  results: Array<{ id: number; agent_id: number; result: any }>;
}

export default function HuntPage() {
  const [queryType, setQueryType] = useState('process');
  const [queryText, setQueryText] = useState('');
  const [saveName, setSaveName]   = useState('');
  const [running, setRunning]     = useState(false);
  const [result, setResult]       = useState<HuntResult | null>(null);
  const [saved, setSaved]         = useState<SavedQuery[]>([]);
  const [expanded, setExpanded]   = useState<number | null>(null);
  const [toast, setToast]         = useState<string | null>(null);
  const [agents, setAgents]       = useState<Agent[]>([]);
  const [agentFilter, setAgentFilter] = useState('');
  const [timeRange, setTimeRange]  = useState('24h');
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const [promoteModal, setPromoteModal] = useState(false);
  const [promoteName, setPromoteName]  = useState('');

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const loadSaved = useCallback(async () => {
    try { const r = await api.get('/hunt/queries'); setSaved(r.data || []); } catch {}
  }, []);

  useEffect(() => { loadSaved(); }, [loadSaved]);
  useEffect(() => {
    agentsAPI.getAll().then(r => setAgents(r.data || [])).catch(() => {});
  }, []);

  const run = async (type = queryType, text = queryText, saveIt = false) => {
    if (!text.trim()) return;
    setRunning(true);
    setResult(null);
    setExpandedRow(null);
    try {
      const r = await api.post('/hunt/run', {
        query_type: type,
        query_text: text,
        save:       saveIt && saveName.trim() !== '',
        name:       saveName || `${type}: ${text}`,
        agent_id:   agentFilter ? parseInt(agentFilter) : undefined,
        time_range: timeRange,
      });
      setResult(r.data);
      if (saveIt) { setSaveName(''); loadSaved(); notify('Query saved'); }
    } catch {
      notify('Hunt query failed');
    } finally {
      setRunning(false);
    }
  };

  const exportResults = () => {
    if (!result) return;
    const rows = result.results.map(r => {
      const data = typeof r.result === 'string' ? JSON.parse(r.result) : r.result;
      return JSON.stringify({ agent_id: r.agent_id, ...data });
    });
    const blob = new Blob([rows.join('\n')], { type: 'application/x-ndjson' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = `hunt-${queryType}-${Date.now()}.ndjson`;
    a.click(); URL.revokeObjectURL(url);
  };

  const promoteToRule = async () => {
    if (!promoteName.trim()) return;
    try {
      await api.post('/sigma-rules/from-hunt', {
        name: promoteName,
        query_type: queryType,
        query_text: queryText,
      });
      notify('Detection rule created — see Sigma Rules');
      setPromoteModal(false);
      setPromoteName('');
    } catch { notify('Promotion failed'); }
  };

  const rerun = async (q: SavedQuery) => {
    setQueryType(q.query_type);
    setQueryText(q.query_text);
    setRunning(true);
    setResult(null);
    try {
      const r = await api.post(`/hunt/queries/${q.id}/run`, {});
      setResult(r.data);
      loadSaved();
    } finally { setRunning(false); }
  };

  const del = async (id: number) => {
    await api.delete(`/hunt/queries/${id}`);
    setSaved(s => s.filter(q => q.id !== id));
    notify('Deleted');
  };

  const selectedType = QUERY_TYPES.find(t => t.id === queryType);
  const resultKeys   = result?.results?.[0]
    ? Object.keys(JSON.parse(typeof result.results[0].result === 'string'
        ? result.results[0].result
        : JSON.stringify(result.results[0].result))).filter(k => k !== 'agent_id')
    : [];

  return (
    <RootLayout title="Threat Hunt" subtitle="Search across all collected endpoint data">
      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)' }}>{toast}</div>}

      <div className="space-y-5">
        {/* Query builder */}
        <div className="g-card p-5 space-y-4">
          <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Query Builder</p>

          {/* Type selector */}
          <div className="flex gap-2 flex-wrap">
            {QUERY_TYPES.map(t => (
              <button key={t.id} onClick={() => setQueryType(t.id)}
                className="text-xs px-3 py-1.5 rounded-xl transition-all"
                style={{
                  background: queryType === t.id ? 'var(--accent-glow)' : 'var(--glass-bg)',
                  border:     `1px solid ${queryType === t.id ? 'var(--accent-border)' : 'var(--border)'}`,
                  color:      queryType === t.id ? 'var(--accent)' : 'var(--text-2)',
                }}>
                {t.label}
              </button>
            ))}
          </div>

          {/* Search input */}
          <div className="flex gap-2 flex-wrap">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
              <input value={queryText}
                onChange={e => setQueryText(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && run()}
                placeholder={selectedType?.hint || 'Search term…'}
                className="g-input pl-9 w-full font-mono" />
            </div>
            {/* Agent filter */}
            <div className="relative">
              <Cpu className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 pointer-events-none" style={{ color: 'var(--text-3)' }} />
              <select value={agentFilter} onChange={e => setAgentFilter(e.target.value)}
                className="g-select pl-8 text-xs" style={{ minWidth: 140 }}>
                <option value="">All Agents</option>
                {agents.map(a => <option key={a.id} value={String(a.id)}>{a.hostname}</option>)}
              </select>
            </div>
            {/* Time range */}
            <div className="relative">
              <Calendar className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 pointer-events-none" style={{ color: 'var(--text-3)' }} />
              <select value={timeRange} onChange={e => setTimeRange(e.target.value)}
                className="g-select pl-8 text-xs" style={{ minWidth: 110 }}>
                <option value="1h">Last 1h</option>
                <option value="24h">Last 24h</option>
                <option value="7d">Last 7d</option>
                <option value="30d">Last 30d</option>
              </select>
            </div>
            <input value={saveName} onChange={e => setSaveName(e.target.value)}
              placeholder="Save as… (optional)"
              className="g-input" style={{ width: 160 }} />
            <button onClick={() => run(queryType, queryText, saveName.trim() !== '')}
              disabled={running || !queryText.trim()}
              className="g-btn g-btn-primary text-xs gap-2">
              {running
                ? <span className="animate-spin">⟳</span>
                : <><Play className="h-3.5 w-3.5" /> Hunt</>}
            </button>
          </div>

          {/* Presets */}
          <div>
            <p className="text-[10px] uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Quick Hunts</p>
            <div className="flex gap-2 flex-wrap">
              {PRESET_HUNTS.map(p => (
                <button key={p.name} onClick={() => { setQueryType(p.type); setQueryText(p.text); run(p.type, p.text); }}
                  className="text-[11px] px-2.5 py-1 rounded-lg transition-all"
                  style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}
                  onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = 'var(--accent-border)'; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = 'var(--border)'; }}>
                  {p.name}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Results */}
        {result && (
          <div className="g-card overflow-hidden">
            <div className="flex items-center justify-between px-5 py-3 flex-wrap gap-2"
              style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="flex items-center gap-3">
                <span className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
                  {result.hits} hit{result.hits !== 1 ? 's' : ''}
                </span>
                <span className="text-xs" style={{ color: 'var(--text-3)' }}>
                  in {result.duration_ms}ms
                </span>
                {result.hits === 0 && (
                  <span className="text-xs" style={{ color: 'var(--green)' }}>✓ No matches — clean</span>
                )}
              </div>
              <div className="flex items-center gap-2">
                <span className="mono text-[10px]" style={{ color: 'var(--text-3)' }}>
                  {queryType}: {queryText}
                </span>
                {result.hits > 0 && (
                  <>
                    <button onClick={exportResults}
                      className="g-btn g-btn-ghost text-[11px] flex items-center gap-1">
                      <Download className="h-3 w-3" /> Export
                    </button>
                    <button onClick={() => { setPromoteName(`Detect: ${queryText}`); setPromoteModal(true); }}
                      className="g-btn text-[11px] flex items-center gap-1"
                      style={{ background: 'rgba(168,85,247,0.1)', color: '#a855f7', border: '1px solid rgba(168,85,247,0.3)' }}>
                      <Zap className="h-3 w-3" /> Promote to Rule
                    </button>
                  </>
                )}
              </div>
            </div>

            {result.hits > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-[11px]">
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
                      <th className="text-left px-4 py-2.5" style={{ color: 'var(--text-3)', fontWeight: 600 }}>Agent</th>
                      {resultKeys.slice(0, 5).map(k => (
                        <th key={k} className="text-left px-4 py-2.5 capitalize"
                          style={{ color: 'var(--text-3)', fontWeight: 600 }}>
                          {k.replace(/_/g, ' ')}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {result.results.slice(0, 100).map((r, i) => {
                      const data = typeof r.result === 'string' ? JSON.parse(r.result) : r.result;
                      const isExp = expandedRow === i;
                      return (
                        <>
                          <tr key={i} className="border-b transition-colors cursor-pointer"
                            style={{ borderColor: 'var(--border)' }}
                            onClick={() => setExpandedRow(isExp ? null : i)}
                            onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--glass-bg)'}
                            onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = ''}>
                            <td className="px-4 py-2 font-mono" style={{ color: 'var(--accent)' }}>
                              {data.hostname || `#${r.agent_id}`}
                            </td>
                            {resultKeys.slice(0, 5).map(k => (
                              <td key={k} className="px-4 py-2 max-w-[200px] truncate"
                                style={{ color: 'var(--text-1)' }}>
                                {String(data[k] ?? '—')}
                              </td>
                            ))}
                          </tr>
                          {isExp && (
                            <tr key={`${i}-exp`} style={{ borderColor: 'var(--border)' }}>
                              <td colSpan={resultKeys.slice(0, 5).length + 1}
                                className="px-4 py-3"
                                style={{ background: 'var(--bg-0)' }}>
                                <pre className="text-[10px] font-mono overflow-x-auto"
                                  style={{ color: 'var(--text-2)' }}>
                                  {JSON.stringify(data, null, 2)}
                                </pre>
                              </td>
                            </tr>
                          )}
                        </>
                      );
                    })}
                  </tbody>
                </table>
                {result.hits > 100 && (
                  <p className="px-4 py-2 text-[10px]" style={{ color: 'var(--text-3)' }}>
                    Showing 100 of {result.hits} results
                  </p>
                )}
              </div>
            )}
          </div>
        )}

        {/* Saved queries */}
        {saved.length > 0 && (
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>
              Saved Hunts ({saved.length})
            </p>
            <div className="space-y-2">
              {saved.map(q => (
                <div key={q.id} className="g-card flex items-center gap-4 px-4 py-3">
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{q.name}</p>
                    <p className="mono text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>
                      {q.query_type}: {q.query_text}
                    </p>
                  </div>
                  <div className="flex items-center gap-3 text-[10px] shrink-0" style={{ color: 'var(--text-3)' }}>
                    <span>{q.hit_count} hits</span>
                    {q.last_run_at && <span>{timeAgo(q.last_run_at)}</span>}
                    <button onClick={() => rerun(q)} disabled={running}
                      className="g-btn g-btn-ghost text-[11px]" style={{ padding: '4px 10px' }}>
                      <Play className="h-3 w-3" /> Run
                    </button>
                    <button onClick={() => del(q.id)} style={{ color: 'var(--text-3)' }}
                      onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--red)'}
                      onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
      {/* Promote to rule modal */}
      {promoteModal && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setPromoteModal(false)}>
          <div className="g-modal" style={{ maxWidth: 440 }}>
            <div className="flex items-center justify-between p-5"
              style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="flex items-center gap-2">
                <Zap className="h-4 w-4" style={{ color: '#a855f7' }} />
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
                  Promote to Detection Rule
                </p>
              </div>
              <button onClick={() => setPromoteModal(false)} style={{ color: 'var(--text-3)' }}>
                <Search className="h-4 w-4 rotate-45" />
              </button>
            </div>
            <div className="p-5 space-y-4">
              <div className="rounded-xl p-3 mono text-[11px]"
                style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                {queryType}: {queryText}
              </div>
              <div>
                <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Rule Name</label>
                <input value={promoteName} onChange={e => setPromoteName(e.target.value)}
                  className="g-input w-full" placeholder="e.g. Detect Reverse Shell" />
              </div>
              <div className="flex gap-3">
                <button onClick={() => setPromoteModal(false)} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
                <button onClick={promoteToRule}
                  className="g-btn flex-1 justify-center"
                  style={{ background: 'rgba(168,85,247,0.12)', color: '#a855f7', border: '1px solid rgba(168,85,247,0.3)' }}>
                  <Zap className="h-3.5 w-3.5" /> Create Rule
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
