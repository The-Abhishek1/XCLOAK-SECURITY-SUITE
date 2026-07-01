'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { RootLayout }  from '@/components/layout/RootLayout';
import { agentsAPI }   from '@/lib/api';
import { Agent }       from '@/types';
import { Activity, Pause, Play, Trash2, Search, Filter, X } from 'lucide-react';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface ParsedFields {
  timestamp?:   string;
  user?:        string;
  src_ip?:      string;
  dst_ip?:      string;
  src_port?:    string;
  dst_port?:    string;
  hostname?:    string;
  process?:     string;
  pid?:         string;
  event_id?:    string;
  channel?:     string;
  auth_result?: string;
  auth_method?: string;
  severity?:    string;
  format?:      string;
  logon_type?:  string;
  subject_user?: string;
  target_user?:  string;
  workstation_name?: string;
  device_vendor?:  string;
  device_product?: string;
  cef_name?:    string;
  extra?:       Record<string, string>;
}

interface LogEntry {
  id:      number;
  source:  string;
  message: string;
  ts:      string;
  fields:  ParsedFields;
  type?:   string;
}

const MAX_LOGS = 500;

// ─────────────────────────────────────────────────────────────────────────────
// Colour coding
// ─────────────────────────────────────────────────────────────────────────────

const AUTH_COLORS: Record<string, string> = {
  failure: 'var(--red)',
  failed:  'var(--red)',
  error:   'var(--red)',
  critical:'var(--red)',
  denied:  'var(--red)',
  invalid: 'var(--yellow)',
  success: 'var(--green)',
  accepted:'var(--green)',
  explicit:'var(--blue)',
  logoff:  'var(--text-3)',
};

function lineColor(msg: string, fields: ParsedFields): string {
  if (fields.auth_result) {
    const c = AUTH_COLORS[fields.auth_result];
    if (c) return c;
  }
  if (fields.severity) {
    const c = AUTH_COLORS[fields.severity];
    if (c) return c;
  }
  // Fallback to message scan.
  const lower = msg.toLowerCase();
  for (const [kw, color] of Object.entries(AUTH_COLORS)) {
    if (lower.includes(kw)) return color;
  }
  return 'var(--text-2)';
}

// Lookup tables for human-readable labels.
const LOGON_TYPES: Record<string, string> = {
  '2':  'Interactive', '3': 'Network', '4': 'Batch',
  '5':  'Service',     '7': 'Unlock',  '8': 'NetworkCleartext',
  '9':  'NewCred',     '10':'RemoteInteractive', '11':'CachedInteractive',
};

const WIN_EVENT_NAMES: Record<string, string> = {
  '4624': 'Logon',      '4625': 'Logon Fail',  '4634': 'Logoff',
  '4648': 'RunAs',      '4688': 'New Process',  '4720': 'User Created',
  '4726': 'User Deleted','4732':'Group Add',    '4733': 'Group Remove',
  '4740': 'Account Locked', '4767': 'Account Unlocked',
};

// ─────────────────────────────────────────────────────────────────────────────
// Field chip component
// ─────────────────────────────────────────────────────────────────────────────

function FieldChip({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono shrink-0"
      style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', color: color || 'var(--text-2)' }}>
      <span style={{ color: 'var(--text-3)', fontSize: 8 }}>{label}</span>
      <span style={{ color: color || 'var(--text-1)' }}>{value}</span>
    </span>
  );
}

// Render the most informative chips for a given log line, capped at ~5 so
// the line doesn't wrap excessively.
function FieldChips({ fields, source }: { fields: ParsedFields; source: string }) {
  const chips: React.ReactNode[] = [];

  // Windows Event ID — show first with human label.
  if (fields.event_id) {
    const name = WIN_EVENT_NAMES[fields.event_id];
    chips.push(
      <FieldChip key="eid" label="EventID" value={`${fields.event_id}${name ? ` (${name})` : ''}`}
        color={fields.event_id === '4625' ? 'var(--red)' : fields.event_id === '4624' ? 'var(--green)' : undefined} />
    );
  }

  // Auth result.
  if (fields.auth_result) {
    const c = AUTH_COLORS[fields.auth_result] || 'var(--text-2)';
    chips.push(<FieldChip key="ar" label="result" value={fields.auth_result} color={c} />);
  }

  // Username (prefer target_user for Windows logon events).
  const user = fields.target_user || fields.user || fields.subject_user;
  if (user) {
    chips.push(<FieldChip key="user" label="user" value={user} color="var(--accent)" />);
  }

  // Source IP.
  if (fields.src_ip && fields.src_ip !== '::' && fields.src_ip !== '::1' && fields.src_ip !== '-') {
    chips.push(<FieldChip key="sip" label="src" value={`${fields.src_ip}${fields.src_port ? ':'+fields.src_port : ''}`} />);
  }

  // Logon type (Windows).
  if (fields.logon_type) {
    const lt = LOGON_TYPES[fields.logon_type] || fields.logon_type;
    chips.push(<FieldChip key="lt" label="logon" value={lt} />);
  }

  // Process name.
  if (fields.process && chips.length < 5) {
    chips.push(<FieldChip key="proc" label="proc" value={fields.process} />);
  }

  // Auth method (password / publickey).
  if (fields.auth_method && chips.length < 5) {
    chips.push(<FieldChip key="am" label="via" value={fields.auth_method} />);
  }

  // Format badge only if non-trivial.
  if (fields.format && fields.format !== 'raw' && chips.length < 6) {
    chips.push(
      <span key="fmt" className="px-1 py-0.5 rounded text-[8px] font-mono"
        style={{ background: 'var(--bg-2)', color: 'var(--text-3)', border: '1px solid var(--border)' }}>
        {fields.format}
      </span>
    );
  }

  return chips.length === 0 ? null : (
    <span className="flex items-center gap-1 flex-wrap">{chips}</span>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Field filter panel — allows filtering live stream by field value
// ─────────────────────────────────────────────────────────────────────────────

const FILTERABLE_FIELDS = [
  { key: 'src_ip',      label: 'Source IP'     },
  { key: 'user',        label: 'Username'      },
  { key: 'event_id',    label: 'Event ID'      },
  { key: 'auth_result', label: 'Auth Result'   },
  { key: 'process',     label: 'Process'       },
  { key: 'hostname',    label: 'Hostname'      },
];

interface FieldFilter { field: string; value: string; }

// ─────────────────────────────────────────────────────────────────────────────
// Main page
// ─────────────────────────────────────────────────────────────────────────────

export default function LiveLogsPage() {
  const [agents, setAgents]           = useState<Agent[]>([]);
  const [agentId, setAgentId]         = useState<number | null>(null);
  const [logs, setLogs]               = useState<LogEntry[]>([]);
  const [paused, setPaused]           = useState(false);
  const [search, setSearch]           = useState('');
  const [connected, setConnected]     = useState(false);
  const [statusMsg, setStatusMsg]     = useState('');
  const [showFilters, setShowFilters] = useState(false);
  const [fieldFilters, setFieldFilters] = useState<FieldFilter[]>([]);
  const [addField, setAddField]       = useState(FILTERABLE_FIELDS[0].key);
  const [addValue, setAddValue]       = useState('');

  const wsRef     = useRef<WebSocket | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const pausedRef = useRef(false);

  useEffect(() => {
    agentsAPI.getAll().then(r => {
      const list = r.data || [];
      setAgents(list);
      if (list.length > 0) setAgentId(list[0].id);
    });
  }, []);

  const connect = useCallback(async (id: number) => {
    if (wsRef.current) wsRef.current.close();

    // Obtain a short-lived single-use ticket via the proxy (carries the
    // httpOnly session cookie). WS goes direct to the backend port.
    let ticket = '';
    try {
      const r = await fetch('/api/ws/ticket', { method: 'POST', credentials: 'include' });
      if (!r.ok) { setConnected(false); return; }
      const data = await r.json();
      ticket = data.ticket;
    } catch {
      setConnected(false);
      return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const host     = window.location.hostname;
    const url      = `${protocol}://${host}:8080/api/agents/${id}/logs/stream?ticket=${encodeURIComponent(ticket)}`;

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen  = () => { setConnected(true);  setStatusMsg(''); };
    ws.onclose = () => { setConnected(false); };
    ws.onerror = () => { setConnected(false); };

    ws.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);

        if (data.type === 'connected') { setConnected(true); return; }
        if (data.type === 'info')      { setStatusMsg(data.message); return; }

        if (pausedRef.current) return;

        // Deserialise parsed_fields if present.
        let fields: ParsedFields = {};
        const rawFields = data.parsed_fields || data.fields;
        if (rawFields) {
          fields = typeof rawFields === 'string'
            ? JSON.parse(rawFields)
            : rawFields;
        }

        const entry: LogEntry = {
          id:      data.id || Date.now(),
          source:  data.source || data.log_source || 'agent',
          message: data.message || data.log_message || '',
          ts:      data.ts || new Date().toISOString(),
          fields,
        };

        setLogs(prev => {
          const next = [...prev, entry];
          return next.length > MAX_LOGS ? next.slice(next.length - MAX_LOGS) : next;
        });
      } catch { /* ignore malformed */ }
    };
  }, []);

  useEffect(() => {
    if (agentId) connect(agentId);
    return () => wsRef.current?.close();
  }, [agentId, connect]);

  useEffect(() => { pausedRef.current = paused; }, [paused]);

  useEffect(() => {
    if (!paused) bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs, paused]);

  // ── Filtering ─────────────────────────────────────────────────
  const filtered = logs.filter(l => {
    // Text search across message + source.
    if (search) {
      const s = search.toLowerCase();
      if (!l.message.toLowerCase().includes(s) && !l.source.toLowerCase().includes(s)) {
        return false;
      }
    }
    // Field filters.
    for (const ff of fieldFilters) {
      const fieldKey = ff.field as keyof ParsedFields;
      const val = l.fields[fieldKey];
      if (!val || typeof val !== 'string') return false;
      if (!val.toLowerCase().includes(ff.value.toLowerCase())) return false;
    }
    return true;
  });

  const addFilter = () => {
    if (!addValue.trim()) return;
    setFieldFilters(f => [...f, { field: addField, value: addValue.trim() }]);
    setAddValue('');
  };

  return (
    <RootLayout title="Live Logs" subtitle="Real-time agent log stream with field extraction">
      <div className="flex flex-col gap-3" style={{ height: 'calc(100vh - 130px)' }}>

        {/* ── Controls ──────────────────────────────────────────── */}
        <div className="flex items-center gap-3 flex-wrap">
          <select value={agentId || ''} onChange={e => setAgentId(Number(e.target.value))}
            className="g-select" style={{ minWidth: 180 }}>
            {agents.map(a => <option key={a.id} value={a.id}>{a.hostname} (#{a.id})</option>)}
          </select>

          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full animate-pulse"
              style={{ background: connected ? 'var(--green)' : 'var(--red)' }} />
            <span className="text-xs" style={{ color: 'var(--text-3)' }}>
              {connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>

          <button onClick={() => setPaused(p => !p)}
            className={`g-btn text-xs ${paused ? 'g-btn-primary' : 'g-btn-ghost'}`}>
            {paused
              ? <><Play  className="h-3.5 w-3.5" /> Resume</>
              : <><Pause className="h-3.5 w-3.5" /> Pause</>}
          </button>

          <button onClick={() => setLogs([])} className="g-btn g-btn-ghost text-xs">
            <Trash2 className="h-3.5 w-3.5" /> Clear
          </button>

          <button onClick={() => setShowFilters(f => !f)}
            className={`g-btn text-xs ${showFilters || fieldFilters.length > 0 ? 'g-btn-primary' : 'g-btn-ghost'}`}>
            <Filter className="h-3.5 w-3.5" />
            Field Filters
            {fieldFilters.length > 0 && (
              <span className="ml-1 px-1 rounded text-[9px]"
                style={{ background: 'var(--accent)', color: '#fff' }}>
                {fieldFilters.length}
              </span>
            )}
          </button>

          <div className="relative flex-1 min-w-[160px] max-w-xs">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5"
              style={{ color: 'var(--text-3)' }} />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Filter message text…" className="g-input pl-8" style={{ fontSize: 12 }} />
          </div>

          <span className="text-xs" style={{ color: 'var(--text-3)' }}>
            {filtered.length}/{logs.length}
          </span>
        </div>

        {/* ── Field filter panel ────────────────────────────────── */}
        {showFilters && (
          <div className="rounded-xl p-3 flex flex-wrap items-center gap-2"
            style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>
            {fieldFilters.map((ff, i) => (
              <div key={i} className="flex items-center gap-1 px-2 py-1 rounded-lg text-[11px]"
                style={{ background: 'var(--bg-2)', border: '1px solid var(--accent-border)' }}>
                <span style={{ color: 'var(--text-3)' }}>{ff.field}</span>
                <span style={{ color: 'var(--text-3)' }}>:</span>
                <span style={{ color: 'var(--accent)' }}>{ff.value}</span>
                <button onClick={() => setFieldFilters(f => f.filter((_, j) => j !== i))}
                  className="ml-1 hover:opacity-70">
                  <X className="h-3 w-3" style={{ color: 'var(--text-3)' }} />
                </button>
              </div>
            ))}
            <select value={addField} onChange={e => setAddField(e.target.value)}
              className="g-select text-xs h-7" style={{ minWidth: 110 }}>
              {FILTERABLE_FIELDS.map(f => (
                <option key={f.key} value={f.key}>{f.label}</option>
              ))}
            </select>
            <input value={addValue} onChange={e => setAddValue(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && addFilter()}
              placeholder="value…" className="g-input text-xs h-7 w-28" />
            <button onClick={addFilter} className="g-btn g-btn-primary text-xs h-7">
              Add
            </button>
            {fieldFilters.length > 0 && (
              <button onClick={() => setFieldFilters([])}
                className="g-btn g-btn-ghost text-xs h-7">
                Clear all
              </button>
            )}
          </div>
        )}

        {statusMsg && (
          <div className="rounded-xl px-4 py-2.5 text-xs"
            style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)', color: 'var(--accent)' }}>
            {statusMsg}
          </div>
        )}

        {/* ── Log terminal ──────────────────────────────────────── */}
        <div className="flex-1 overflow-y-auto rounded-2xl p-4 font-mono text-[11px] leading-5"
          style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>

          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-40 gap-2">
              <Activity className="h-7 w-7 animate-pulse" style={{ color: 'var(--text-3)' }} />
              <p style={{ color: 'var(--text-3)' }}>
                {connected ? 'Waiting for logs…' : 'Select an agent to connect'}
              </p>
            </div>
          ) : filtered.map((log, i) => (
            <div key={log.id || i}
              className="flex flex-col gap-0.5 py-0.5 hover:bg-white/5 rounded px-1 transition-colors">
              {/* Main log line */}
              <div className="flex gap-2 items-baseline flex-wrap">
                <span className="shrink-0 w-[68px]" style={{ color: 'var(--text-3)' }}>
                  {new Date(log.ts).toLocaleTimeString('en', { hour12: false })}
                </span>
                <span className="shrink-0 w-[72px] truncate" style={{ color: 'var(--accent)' }}>
                  {log.source}
                </span>
                <span style={{ color: lineColor(log.message, log.fields), wordBreak: 'break-all' }}>
                  {log.message}
                </span>
              </div>
              {/* Extracted fields chips — only shown when fields exist */}
              {log.fields && Object.keys(log.fields).filter(k => k !== 'format' && k !== 'extra').length > 0 && (
                <div className="ml-[148px] flex flex-wrap gap-1">
                  <FieldChips fields={log.fields} source={log.source} />
                </div>
              )}
            </div>
          ))}

          <div ref={bottomRef} />
        </div>
      </div>
    </RootLayout>
  );
}
