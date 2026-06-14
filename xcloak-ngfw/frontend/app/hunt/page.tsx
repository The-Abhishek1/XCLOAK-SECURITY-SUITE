'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import api from '@/lib/api';
import { Search, Play, Save, Trash2, Clock, ChevronDown, ChevronRight, Shield } from 'lucide-react';
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

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const loadSaved = useCallback(async () => {
    try { const r = await api.get('/hunt/queries'); setSaved(r.data || []); } catch {}
  }, []);

  useEffect(() => { loadSaved(); }, [loadSaved]);

  const run = async (type = queryType, text = queryText, saveIt = false) => {
    if (!text.trim()) return;
    setRunning(true);
    setResult(null);
    try {
      const r = await api.post('/hunt/run', {
        query_type: type,
        query_text: text,
        save:       saveIt && saveName.trim() !== '',
        name:       saveName || `${type}: ${text}`,
      });
      setResult(r.data);
      if (saveIt) { setSaveName(''); loadSaved(); notify('Query saved'); }
    } catch {
      notify('Hunt query failed');
    } finally {
      setRunning(false);
    }
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
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
              <input value={queryText}
                onChange={e => setQueryText(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && run()}
                placeholder={selectedType?.hint || 'Search term…'}
                className="g-input pl-9 w-full font-mono" />
            </div>
            <input value={saveName} onChange={e => setSaveName(e.target.value)}
              placeholder="Save as… (optional)"
              className="g-input" style={{ width: 180 }} />
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
            <div className="flex items-center justify-between px-5 py-3"
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
              <span className="mono text-[10px]" style={{ color: 'var(--text-3)' }}>
                {queryType}: {queryText}
              </span>
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
                      return (
                        <tr key={i} className="border-b transition-colors"
                          style={{ borderColor: 'var(--border)' }}
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
    </RootLayout>
  );
}
