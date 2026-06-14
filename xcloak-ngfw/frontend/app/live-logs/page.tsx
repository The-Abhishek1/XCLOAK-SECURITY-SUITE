'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { agentsAPI } from '@/lib/api';
import { Agent } from '@/types';
import { Activity, Pause, Play, Trash2, Search, Filter } from 'lucide-react';

interface LogEntry {
  id: number;
  source: string;
  message: string;
  ts: string;
}

const MAX_LOGS = 500;

const SEV_COLORS: Record<string, string> = {
  error:    'var(--red)',
  fail:     'var(--red)',
  warn:     'var(--orange)',
  critical: 'var(--red)',
  denied:   'var(--orange)',
  invalid:  'var(--yellow)',
  accepted: 'var(--green)',
  success:  'var(--green)',
  session:  'var(--blue)',
};

function getLineColor(msg: string): string {
  const lower = msg.toLowerCase();
  for (const [kw, color] of Object.entries(SEV_COLORS)) {
    if (lower.includes(kw)) return color;
  }
  return 'var(--text-2)';
}

export default function LiveLogsPage() {
  const [agents, setAgents]       = useState<Agent[]>([]);
  const [agentId, setAgentId]     = useState<number | null>(null);
  const [logs, setLogs]           = useState<LogEntry[]>([]);
  const [paused, setPaused]       = useState(false);
  const [search, setSearch]       = useState('');
  const [connected, setConnected] = useState(false);
  const esRef                     = useRef<EventSource | null>(null);
  const bottomRef                 = useRef<HTMLDivElement>(null);
  const pausedRef                 = useRef(false);

  useEffect(() => {
    agentsAPI.getAll().then(r => {
      const list = r.data || [];
      setAgents(list);
      if (list.length > 0) setAgentId(list[0].id);
    });
  }, []);

  const connect = useCallback((id: number) => {
    if (esRef.current) { esRef.current.close(); }

    const token = localStorage.getItem('token') || '';
    const url   = `/api/agents/${id}/logs/stream?token=${encodeURIComponent(token)}`;

    const es = new EventSource(url);
    esRef.current = es;

    es.onopen = () => setConnected(true);

    es.onmessage = (evt) => {
      if (pausedRef.current) return;
      try {
        const entry = JSON.parse(evt.data) as { id: number; source: string; message: string };
        setLogs(prev => {
          const next = [...prev, { ...entry, ts: new Date().toISOString() }];
          return next.length > MAX_LOGS ? next.slice(next.length - MAX_LOGS) : next;
        });
      } catch { /* ignore malformed SSE data */ }
    };

    es.onerror = () => { setConnected(false); };

    return () => { es.close(); setConnected(false); };
  }, []);

  useEffect(() => {
    if (agentId) return connect(agentId);
  }, [agentId, connect]);

  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  useEffect(() => {
    if (!paused) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, paused]);

  const filtered = search
    ? logs.filter(l => l.message.toLowerCase().includes(search.toLowerCase()) || l.source.toLowerCase().includes(search.toLowerCase()))
    : logs;

  return (
    <RootLayout title="Live Logs" subtitle="Real-time agent log stream">
      <div className="flex flex-col gap-3" style={{ height: 'calc(100vh - 130px)' }}>

        {/* Controls */}
        <div className="flex items-center gap-3 flex-wrap">
          <select value={agentId || ''} onChange={e => setAgentId(Number(e.target.value))}
            className="g-select" style={{ minWidth: 180 }}>
            {agents.map(a => (
              <option key={a.id} value={a.id}>{a.hostname} (#{a.id})</option>
            ))}
          </select>

          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full"
              style={{ background: connected ? 'var(--green)' : 'var(--red)' }} />
            <span className="text-xs" style={{ color: 'var(--text-3)' }}>
              {connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>

          <button onClick={() => setPaused(p => !p)}
            className={`g-btn text-xs ${paused ? 'g-btn-primary' : 'g-btn-ghost'}`}>
            {paused ? <><Play className="h-3.5 w-3.5" /> Resume</> : <><Pause className="h-3.5 w-3.5" /> Pause</>}
          </button>

          <button onClick={() => setLogs([])} className="g-btn g-btn-ghost text-xs">
            <Trash2 className="h-3.5 w-3.5" /> Clear
          </button>

          <div className="relative flex-1 min-w-[160px] max-w-xs">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Filter logs…" className="g-input pl-8" style={{ fontSize: 12 }} />
          </div>

          <span className="text-xs" style={{ color: 'var(--text-3)' }}>
            {filtered.length}/{logs.length} lines
          </span>
        </div>

        {/* Log terminal */}
        <div className="flex-1 overflow-y-auto rounded-2xl p-4 font-mono text-[11px] leading-5"
          style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>

          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-40 gap-2">
              <Activity className="h-7 w-7" style={{ color: 'var(--text-3)' }} />
              <p style={{ color: 'var(--text-3)' }}>
                {connected ? 'Waiting for logs…' : 'Select an agent to start streaming'}
              </p>
            </div>
          ) : filtered.map((log, i) => (
            <div key={log.id || i} className="flex gap-2 py-0.5 hover:bg-white/5 rounded px-1 transition-colors">
              <span className="shrink-0 w-16" style={{ color: 'var(--text-3)' }}>
                {new Date(log.ts).toLocaleTimeString('en', { hour12: false })}
              </span>
              <span className="shrink-0 w-16 truncate" style={{ color: 'var(--accent)' }}>
                {log.source}
              </span>
              <span style={{ color: getLineColor(log.message) }}>
                {log.message}
              </span>
            </div>
          ))}

          <div ref={bottomRef} />
        </div>
      </div>
    </RootLayout>
  );
}
