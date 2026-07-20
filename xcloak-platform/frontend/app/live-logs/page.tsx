'use client';

import {
  useEffect, useRef, useState, useCallback, useMemo, ReactNode,
} from 'react';
import { RootLayout }    from '@/components/layout/RootLayout';
import { agentsAPI, liveLogAPI } from '@/lib/api';
import { Agent }         from '@/types';
import { formatDate }    from '@/lib/utils';
import { Activity, AlertTriangle, ArrowRight, BarChart2, Bookmark, BookmarkCheck, Check, ChevronDown, ChevronRight, Clock, Code, Columns, Copy, Cpu, Database, Download, Eye, EyeOff, FileJson, Filter, Globe, Hash, Key, Monitor, Network, Pause, Play, Plus, RotateCcw, Save, Search, Server, Shield, SlidersHorizontal, Sparkles, Table2, Terminal, Trash2, X, Zap } from '@/lib/icon-stubs';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface ParsedFields {
  timestamp?: string; user?: string; src_ip?: string; dst_ip?: string;
  src_port?: string; dst_port?: string; hostname?: string; process?: string;
  pid?: string; event_id?: string; channel?: string; auth_result?: string;
  auth_method?: string; severity?: string; format?: string; logon_type?: string;
  subject_user?: string; target_user?: string; workstation_name?: string;
  device_vendor?: string; device_product?: string; cef_name?: string;
  domain?: string; url?: string; hash?: string; signature?: string;
  extra?: Record<string, string>;
}

interface LogEntry {
  id: number; source: string; message: string; ts: string;
  fields: ParsedFields; note?: string; tags?: string[];
}

interface FieldFilter { field: string; value: string; negate?: boolean; }
interface SavedView {
  id: string; name: string; search: string; fieldFilters: FieldFilter[];
  viewMode: ViewMode; hiddenCols: string[];
}
interface Correlation {
  type: string; label: string; color: string; count: number; detail: string;
}

type ViewMode  = 'raw' | 'table' | 'json' | 'parsed';
type RightTab  = 'context' | 'stats' | 'ai';
type SearchMode = 'text' | 'regex' | 'field';

const MAX_LOGS  = 2000;
const LS_VIEWS  = 'xcloak_live_views';

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const SOURCE_ICON: Record<string, ReactNode> = {
  sshd:       <Key     className="h-2.5 w-2.5" />,
  ssh:        <Key     className="h-2.5 w-2.5" />,
  nginx:      <Globe   className="h-2.5 w-2.5" />,
  apache:     <Globe   className="h-2.5 w-2.5" />,
  postgres:   <Database className="h-2.5 w-2.5" />,
  mysql:      <Database className="h-2.5 w-2.5" />,
  named:      <Server  className="h-2.5 w-2.5" />,
  dns:        <Server  className="h-2.5 w-2.5" />,
  auditd:     <Cpu     className="h-2.5 w-2.5" />,
  systemd:    <Cpu     className="h-2.5 w-2.5" />,
  kernel:     <Cpu     className="h-2.5 w-2.5" />,
  cron:       <Clock   className="h-2.5 w-2.5" />,
  snort:      <AlertTriangle className="h-2.5 w-2.5" />,
  suricata:   <AlertTriangle className="h-2.5 w-2.5" />,
};
function sourceIcon(src: string): ReactNode {
  const key = Object.keys(SOURCE_ICON).find(k => src.toLowerCase().startsWith(k));
  if (key) return SOURCE_ICON[key];
  if (/winevent|powershell/i.test(src)) return <Monitor className="h-2.5 w-2.5" />;
  if (/fw|firewall|pf-|palo|fortinet/i.test(src)) return <Shield className="h-2.5 w-2.5" />;
  if (/xcloak|agent/i.test(src)) return <Zap className="h-2.5 w-2.5" />;
  return <Terminal className="h-2.5 w-2.5" />;
}

const AUTH_COLORS: Record<string, string> = {
  failure: 'var(--red)', failed: 'var(--red)', error: 'var(--red)',
  critical: 'var(--red)', denied: 'var(--red)', invalid: 'var(--yellow)',
  success: 'var(--green)', accepted: 'var(--green)',
};

function lineColor(msg: string, fields: ParsedFields): string {
  if (fields.auth_result) { const c = AUTH_COLORS[fields.auth_result]; if (c) return c; }
  if (fields.severity)    { const c = AUTH_COLORS[fields.severity];    if (c) return c; }
  const lower = msg.toLowerCase();
  for (const [kw, color] of Object.entries(AUTH_COLORS)) {
    if (lower.includes(kw)) return color;
  }
  return 'var(--text-2)';
}

const WIN_EVENT_NAMES: Record<string, string> = {
  '4624': 'Logon',      '4625': 'Logon Fail', '4634': 'Logoff',
  '4648': 'RunAs',      '4688': 'New Process', '4103': 'PS Module',
  '4104': 'PS Script',  '4720': 'User Created','4726': 'User Deleted',
  '4732': 'Group Add',  '4740': 'Acct Locked', '4767': 'Acct Unlocked',
};
const LOGON_TYPES: Record<string, string> = {
  '2': 'Interactive', '3': 'Network', '4': 'Batch', '5': 'Service',
  '7': 'Unlock', '8': 'NetCleartext', '9': 'NewCred',
  '10': 'RemoteInteractive', '11': 'CachedInteractive',
};

type LogFormat = 'json' | 'cef' | 'winevent' | 'syslog' | 'nginx' | 'raw';
const FORMAT_COLOR: Record<LogFormat, string> = {
  json: 'var(--green)', cef: 'var(--orange)', winevent: 'var(--blue)',
  syslog: 'var(--yellow)', nginx: 'var(--accent)', raw: 'var(--text-3)',
};
function detectFormat(msg: string): LogFormat {
  if (msg.trimStart().startsWith('{')) { try { JSON.parse(msg); return 'json'; } catch {} }
  if (msg.startsWith('CEF:')) return 'cef';
  if (/EventCode=\d+|EventID[:\s]+\d+/i.test(msg)) return 'winevent';
  if (/^\w{3}\s+\d+\s+[\d:]+\s+\S+\s+\S+/.test(msg)) return 'syslog';
  if (/^\S+ - \S+ \[.+\] "\w+ \S+ HTTP/.test(msg)) return 'nginx';
  return 'raw';
}

// Demo templates
const DEMO_TEMPLATES: Omit<LogEntry, 'id' | 'ts'>[] = [
  { source: 'sshd', message: 'Accepted publickey for ubuntu from 10.10.1.100 port 52341 ssh2: RSA SHA256:abc123', fields: { hostname: 'win-workstation-05', process: 'sshd', pid: '2211', auth_result: 'success', auth_method: 'publickey', user: 'ubuntu', src_ip: '10.10.1.100', src_port: '52341', format: 'syslog' } },
  { source: 'sshd', message: 'Failed password for root from 185.220.101.35 port 41392 ssh2', fields: { hostname: 'db-server-02', process: 'sshd', pid: '3301', auth_result: 'failure', auth_method: 'password', user: 'root', src_ip: '185.220.101.35', src_port: '41392', format: 'syslog' } },
  { source: 'sshd', message: 'Invalid user admin from 185.220.101.35 port 43211', fields: { hostname: 'db-server-02', process: 'sshd', pid: '3305', auth_result: 'invalid', user: 'admin', src_ip: '185.220.101.35', src_port: '43211', format: 'syslog' } },
  { source: 'sshd', message: 'Accepted password for svc_deploy from 10.10.5.100 port 55210 ssh2', fields: { hostname: 'dc-01', process: 'sshd', pid: '4412', auth_result: 'success', auth_method: 'password', user: 'svc_deploy', src_ip: '10.10.5.100', src_port: '55210', format: 'syslog' } },
  { source: 'WinEvent/Security', message: 'EventCode=4624 An account was successfully logged on. Account Name: jdoe Logon Type: 3 Source Network Address: 10.10.1.50', fields: { event_id: '4624', target_user: 'jdoe', logon_type: '3', src_ip: '10.10.1.50', process: 'lsass.exe', auth_result: 'success', format: 'winevent' } },
  { source: 'WinEvent/Security', message: 'EventCode=4625 An account failed to log on. Account Name: Administrator Source Network Address: 185.220.101.35', fields: { event_id: '4625', target_user: 'Administrator', src_ip: '185.220.101.35', auth_result: 'failure', format: 'winevent' } },
  { source: 'WinEvent/Security', message: 'EventCode=4688 New Process: C:\\Windows\\System32\\cmd.exe Command Line: cmd.exe /c whoami /all', fields: { event_id: '4688', subject_user: 'jdoe', process: 'cmd.exe', format: 'winevent' } },
  { source: 'WinEvent/Security', message: 'EventCode=4740 A user account was locked out. Account Name: jdoe Caller: win-workstation-05', fields: { event_id: '4740', target_user: 'jdoe', hostname: 'win-workstation-05', auth_result: 'failure', format: 'winevent' } },
  { source: 'nginx', message: '185.220.101.35 - - "GET /admin/config HTTP/1.1" 403 287 "python-requests/2.28.0"', fields: { src_ip: '185.220.101.35', auth_result: 'denied', format: 'nginx' } },
  { source: 'pf-fw-01', message: 'CEF:0|PFSense|pfSense|2.6.0|block|Blocked outbound to known C2|9|src=10.10.1.50 dst=185.220.101.35 spt=54321 dpt=443 proto=TCP', fields: { device_vendor: 'PFSense', cef_name: 'Blocked outbound to known C2', severity: 'critical', src_ip: '10.10.1.50', dst_ip: '185.220.101.35', src_port: '54321', dst_port: '443', format: 'cef' } },
  { source: 'snort', message: 'CEF:0|Snort|IDS|3.1.6|1001|ET SCAN Nmap SYN Scan|7|src=185.220.101.35 dst=10.10.1.0/24 dpt=22', fields: { device_vendor: 'Snort', cef_name: 'ET SCAN Nmap SYN Scan', severity: 'high', src_ip: '185.220.101.35', dst_ip: '10.10.1.0/24', dst_port: '22', format: 'cef' } },
  { source: 'xcloak-agent', message: '{"level":"warn","msg":"Unsigned driver loaded","driver":"C:\\\\Windows\\\\System32\\\\drivers\\\\evil.sys","pid":8812,"hostname":"win-workstation-05"}', fields: { severity: 'warn', hostname: 'win-workstation-05', process: 'evil.sys', pid: '8812', format: 'json' } },
  { source: 'xcloak-agent', message: '{"level":"error","msg":"FIM alert: file modified","path":"/etc/passwd","user":"root","hostname":"db-server-02"}', fields: { severity: 'error', hostname: 'db-server-02', user: 'root', format: 'json' } },
  { source: 'xcloak-agent', message: '{"level":"info","msg":"Process terminated","name":"cobalt-strike-beacon","user":"SYSTEM","hostname":"win-workstation-05"}', fields: { severity: 'info', hostname: 'win-workstation-05', user: 'SYSTEM', pid: '9999', process: 'cobalt-strike-beacon', format: 'json' } },
  { source: 'auditd', message: 'type=EXECVE msg=audit(7741): argc=4 a0="vssadmin" a1="delete" a2="shadows" a3="/all" uid=0 pid=11234', fields: { user: 'root', pid: '11234', hostname: 'db-server-02', process: 'vssadmin', format: 'syslog' } },
  { source: 'PowerShell/Operational', message: 'EventCode=4104 ScriptBlock: powershell.exe -nop -w hidden -EncodedCommand JABjA...', fields: { event_id: '4104', process: 'powershell.exe', format: 'winevent' } },
  { source: 'named', message: 'query: a1b2c3d4e5.cobalt-beacon.io IN A from 10.10.1.50', fields: { hostname: 'win-workstation-05', process: 'named', src_ip: '10.10.1.50', domain: 'cobalt-beacon.io', format: 'syslog' } },
  { source: 'snort', message: 'CEF:0|Snort|IDS|3.1.6|2001|ET MALWARE Cobalt Strike Beacon|10|src=10.10.1.50 dst=185.220.101.35 dpt=443', fields: { device_vendor: 'Snort', cef_name: 'ET MALWARE Cobalt Strike Beacon', severity: 'critical', src_ip: '10.10.1.50', dst_ip: '185.220.101.35', dst_port: '443', format: 'cef' } },
  { source: 'sshd', message: 'Failed password for invalid user guest from 185.220.101.35 port 47210', fields: { hostname: 'dc-01', auth_result: 'failure', user: 'guest', src_ip: '185.220.101.35', format: 'syslog' } },
  { source: 'sshd', message: 'Failed password for root from 185.220.101.35 port 47218', fields: { hostname: 'api-server-01', auth_result: 'failure', user: 'root', src_ip: '185.220.101.35', format: 'syslog' } },
  { source: 'sshd', message: 'Failed password for ubuntu from 185.220.101.35 port 47226', fields: { hostname: 'web-01', auth_result: 'failure', user: 'ubuntu', src_ip: '185.220.101.35', format: 'syslog' } },
  { source: 'postgres', message: 'connection received: host=185.220.101.35 port=52199 user=postgres database=production', fields: { hostname: 'db-server-02', process: 'postgres', src_ip: '185.220.101.35', user: 'postgres', format: 'syslog' } },
  { source: 'cron', message: '(jdoe) CMD (C:\\Windows\\System32\\wscript.exe C:\\ProgramData\\beacon.vbs)', fields: { hostname: 'win-workstation-05', process: 'CRON', pid: '8812', user: 'jdoe', format: 'syslog' } },
];

// ─────────────────────────────────────────────────────────────────────────────
// Search parsing
// ─────────────────────────────────────────────────────────────────────────────

function matchesSearch(log: LogEntry, query: string, mode: SearchMode): boolean {
  if (!query) return true;
  const msg = log.message.toLowerCase();
  const src = log.source.toLowerCase();

  if (mode === 'regex') {
    try {
      const re = new RegExp(query, 'i');
      return re.test(log.message) || re.test(log.source);
    } catch { return false; }
  }

  if (mode === 'field') {
    // Support: field:value AND field2:value2
    const terms = query.toLowerCase().split(/\s+and\s+|\s+&&\s+/i);
    return terms.every(term => {
      const colon = term.indexOf(':');
      if (colon < 0) return msg.includes(term) || src.includes(term);
      const field = term.slice(0, colon).trim();
      const val   = term.slice(colon + 1).trim();
      // Map common field aliases
      const fieldMap: Record<string, (keyof ParsedFields)[]> = {
        host:     ['hostname'], user: ['user', 'target_user', 'subject_user'],
        process:  ['process'],  pid: ['pid'],
        src:      ['src_ip'],   dst: ['dst_ip'],
        ip:       ['src_ip', 'dst_ip'],
        domain:   ['domain'],   event: ['event_id'],
        severity: ['severity'], auth: ['auth_result'],
      };
      const keys = fieldMap[field] ?? [field as keyof ParsedFields];
      return keys.some(k => {
        const v = log.fields[k];
        return v ? String(v).toLowerCase().includes(val) : false;
      });
    });
  }

  // Text mode: support -exclude, "phrase", wildcards
  const tokens = query.toLowerCase().match(/-?"[^"]*"|-?\S+/g) ?? [];
  return tokens.every(token => {
    const exclude = token.startsWith('-');
    const clean   = token.replace(/^-/, '').replace(/^"|"$/g, '').replace(/\*/g, '');
    const found   = msg.includes(clean) || src.includes(clean);
    return exclude ? !found : found;
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Live correlation detection
// ─────────────────────────────────────────────────────────────────────────────

function detectCorrelations(logs: LogEntry[]): Correlation[] {
  const recent = logs.slice(-200);
  const result: Correlation[] = [];

  // Failed logins from same IP
  const failsByIP: Record<string, number> = {};
  for (const l of recent) {
    if (l.fields.auth_result === 'failure' && l.fields.src_ip) {
      failsByIP[l.fields.src_ip] = (failsByIP[l.fields.src_ip] ?? 0) + 1;
    }
  }
  for (const [ip, cnt] of Object.entries(failsByIP)) {
    if (cnt >= 3) {
      result.push({ type: 'brute_force', label: 'Brute Force', color: 'var(--red)', count: cnt, detail: `${cnt} failed logins from ${ip}` });
      break;
    }
  }

  // Credential dumping
  const credDump = recent.some(l =>
    /lsass|vssadmin delete|ntds\.dit|mimikatz|sekurlsa/i.test(l.message)
  );
  if (credDump) result.push({ type: 'cred_dump', label: 'Cred Dump', color: 'var(--red)', count: 1, detail: 'Credential dumping indicators detected' });

  // Suspicious PowerShell
  const psSusp = recent.some(l =>
    /-EncodedCommand|-enc |-nop -w hidden|IEX\(|Invoke-Expression/i.test(l.message)
  );
  if (psSusp) result.push({ type: 'powershell', label: 'Suspicious PS', color: 'var(--orange)', count: 1, detail: 'Encoded/obfuscated PowerShell detected' });

  // C2 / beacon indicators
  const c2 = recent.some(l => /cobalt.strike|beacon|\.io IN A|known C2/i.test(l.message));
  if (c2) result.push({ type: 'c2', label: 'C2 Activity', color: 'var(--red)', count: 1, detail: 'C2 beaconing indicators detected' });

  // Lateral movement: same user, multiple hosts
  const userHosts: Record<string, Set<string>> = {};
  for (const l of recent) {
    const u = l.fields.user ?? l.fields.target_user;
    const h = l.fields.hostname;
    if (u && h) {
      if (!userHosts[u]) userHosts[u] = new Set();
      userHosts[u].add(h);
    }
  }
  for (const [user, hosts] of Object.entries(userHosts)) {
    if (hosts.size >= 3) {
      result.push({ type: 'lateral', label: 'Lateral Movement', color: 'var(--orange)', count: hosts.size, detail: `${user} seen on ${hosts.size} hosts` });
      break;
    }
  }

  // Port scan
  const portsByIP: Record<string, Set<string>> = {};
  for (const l of recent) {
    if (l.fields.src_ip && l.fields.dst_port) {
      if (!portsByIP[l.fields.src_ip]) portsByIP[l.fields.src_ip] = new Set();
      portsByIP[l.fields.src_ip].add(l.fields.dst_port);
    }
  }
  for (const [ip, ports] of Object.entries(portsByIP)) {
    if (ports.size >= 8) {
      result.push({ type: 'port_scan', label: 'Port Scan', color: 'var(--yellow)', count: ports.size, detail: `${ports.size} ports scanned from ${ip}` });
      break;
    }
  }

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Highlight helper
// ─────────────────────────────────────────────────────────────────────────────

function HL({ text, term }: { text: string; term: string }): ReactNode {
  if (!term) return text;
  try {
    const re    = new RegExp(`(${term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
    const parts = text.split(re);
    return parts.map((p, i) =>
      re.test(p)
        ? <mark key={i} style={{ background: 'var(--yellow)', color: 'var(--bg-0)', borderRadius: 2 }}>{p}</mark>
        : p
    );
  } catch { return text; }
}

// ─────────────────────────────────────────────────────────────────────────────
// Field chips
// ─────────────────────────────────────────────────────────────────────────────

function FieldChip({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-mono"
      style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', color: color ?? 'var(--text-2)' }}>
      <span style={{ color: 'var(--text-3)', fontSize: 8 }}>{label}</span>
      <span style={{ color: color ?? 'var(--text-1)' }}>{value}</span>
    </span>
  );
}

function FieldChips({ fields }: { fields: ParsedFields }) {
  const chips: ReactNode[] = [];
  if (fields.event_id) {
    const name = WIN_EVENT_NAMES[fields.event_id];
    chips.push(<FieldChip key="eid" label="EventID"
      value={`${fields.event_id}${name ? ` (${name})` : ''}`}
      color={fields.event_id === '4625' ? 'var(--red)' : fields.event_id === '4624' ? 'var(--green)' : undefined} />);
  }
  if (fields.auth_result) chips.push(<FieldChip key="ar" label="result" value={fields.auth_result} color={AUTH_COLORS[fields.auth_result]} />);
  const user = fields.target_user ?? fields.user ?? fields.subject_user;
  if (user) chips.push(<FieldChip key="user" label="user" value={user} color="var(--accent)" />);
  if (fields.src_ip) chips.push(<FieldChip key="sip" label="src" value={`${fields.src_ip}${fields.src_port ? ':'+fields.src_port : ''}`} />);
  if (fields.hostname && chips.length < 5) chips.push(<FieldChip key="host" label="host" value={fields.hostname} />);
  if (fields.process  && chips.length < 5) chips.push(<FieldChip key="proc" label="proc" value={fields.process} />);
  if (fields.logon_type && chips.length < 5) chips.push(<FieldChip key="lt" label="logon" value={LOGON_TYPES[fields.logon_type] ?? fields.logon_type} />);
  if (fields.domain && chips.length < 5) chips.push(<FieldChip key="dom" label="domain" value={fields.domain} color="var(--red)" />);
  return chips.length === 0 ? null : <span className="flex items-center gap-1 flex-wrap">{chips}</span>;
}

// ─────────────────────────────────────────────────────────────────────────────
// View modes
// ─────────────────────────────────────────────────────────────────────────────

const TABLE_COLS = [
  { key: 'ts',      label: 'Time',     width: 70 },
  { key: 'source',  label: 'Source',   width: 110 },
  { key: 'severity',label: 'Sev',      width: 50 },
  { key: 'host',    label: 'Host',     width: 100 },
  { key: 'user',    label: 'User',     width: 80 },
  { key: 'process', label: 'Process',  width: 80 },
  { key: 'message', label: 'Message',  width: -1 },  // flex-1
];

function TableView({ logs, search, hiddenCols, selected, bookmarked, onSelect, onContextMenu }:
  { logs: LogEntry[]; search: string; hiddenCols: string[]; selected: LogEntry | null;
    bookmarked: Set<number>; onSelect: (l: LogEntry) => void; onContextMenu: (e: React.MouseEvent, l: LogEntry) => void }
) {
  const cols = TABLE_COLS.filter(c => !hiddenCols.includes(c.key));
  return (
    <div style={{ fontFamily: 'monospace', fontSize: 11 }}>
      {/* Header */}
      <div className="flex items-center gap-0 sticky top-0 z-10 select-none"
        style={{ background: 'var(--bg-1)', borderBottom: '1px solid var(--border)' }}>
        {cols.map(c => (
          <div key={c.key} className="px-2 py-1.5 text-[9px] font-semibold uppercase shrink-0 truncate"
            style={{ width: c.width === -1 ? undefined : c.width, flex: c.width === -1 ? 1 : undefined, color: 'var(--text-3)' }}>
            {c.label}
          </div>
        ))}
      </div>
      {logs.map((l, i) => {
        const color = lineColor(l.message, l.fields);
        const isSelected = selected?.id === l.id;
        const user = l.fields.target_user ?? l.fields.user ?? l.fields.subject_user ?? '';
        const sev  = l.fields.severity ?? l.fields.auth_result ?? '';
        const sevColor = AUTH_COLORS[sev] ?? 'var(--text-3)';
        return (
          <div key={l.id || i}
            className="flex items-center gap-0 cursor-pointer hover:bg-opacity-50 transition-colors"
            style={{
              background: isSelected ? 'var(--accent-glow)' : i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)',
              borderLeft: `2px solid ${isSelected ? 'var(--accent)' : 'transparent'}`,
              borderBottom: '1px solid rgba(255,255,255,0.03)',
            }}
            onClick={() => onSelect(l)}
            onContextMenu={e => onContextMenu(e, l)}
          >
            {cols.map(c => {
              let content: ReactNode = '';
              if (c.key === 'ts')      content = <span style={{ color: 'var(--text-3)' }}>{new Date(l.ts).toLocaleTimeString('en', { hour12: false })}</span>;
              if (c.key === 'source')  content = <span className="flex items-center gap-1"><span style={{ color: 'var(--text-3)' }}>{sourceIcon(l.source)}</span><span className="truncate" style={{ color: 'var(--accent)' }}>{l.source}</span></span>;
              if (c.key === 'severity') content = <span style={{ color: sevColor, fontWeight: 600, fontSize: 9, textTransform: 'uppercase' }}>{sev || '—'}</span>;
              if (c.key === 'host')    content = <span className="truncate" style={{ color: 'var(--text-2)' }}>{l.fields.hostname ?? '—'}</span>;
              if (c.key === 'user')    content = <span className="truncate" style={{ color: user ? 'var(--accent)' : 'var(--text-3)' }}>{user || '—'}</span>;
              if (c.key === 'process') content = <span className="truncate" style={{ color: 'var(--text-2)' }}>{l.fields.process ?? '—'}</span>;
              if (c.key === 'message') content = <span className="truncate" style={{ color }}><HL text={l.message} term={search} /></span>;
              return (
                <div key={c.key} className="px-2 py-1 shrink-0 overflow-hidden"
                  style={{ width: c.width === -1 ? undefined : c.width, flex: c.width === -1 ? 1 : undefined }}>
                  {content}
                </div>
              );
            })}
          </div>
        );
      })}
    </div>
  );
}

function JsonView({ logs, search, selected, onSelect, onContextMenu }: {
  logs: LogEntry[]; search: string; selected: LogEntry | null;
  onSelect: (l: LogEntry) => void; onContextMenu: (e: React.MouseEvent, l: LogEntry) => void;
}) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  return (
    <div className="space-y-0.5 p-1">
      {logs.map((l, i) => {
        const isExp = expanded.has(l.id);
        const isSel = selected?.id === l.id;
        return (
          <div key={l.id || i} className="rounded overflow-hidden"
            style={{ border: `1px solid ${isSel ? 'var(--accent)' : 'var(--border)'}`, background: isSel ? 'var(--accent-glow)' : 'transparent' }}>
            <div className="flex items-center gap-2 px-2 py-1.5 cursor-pointer"
              onClick={() => { setExpanded(s => { const n = new Set(s); n.has(l.id) ? n.delete(l.id) : n.add(l.id); return n; }); onSelect(l); }}
              onContextMenu={e => onContextMenu(e, l)}>
              {isExp ? <ChevronDown className="h-3 w-3 shrink-0" style={{ color: 'var(--text-3)' }} />
                     : <ChevronRight className="h-3 w-3 shrink-0" style={{ color: 'var(--text-3)' }} />}
              <span className="text-[10px] font-mono shrink-0" style={{ color: 'var(--text-3)' }}>{new Date(l.ts).toLocaleTimeString('en', { hour12: false })}</span>
              <span className="text-[10px] font-mono truncate flex-1" style={{ color: 'var(--text-1)' }}>
                <HL text={l.message.slice(0, 120)} term={search} />
              </span>
            </div>
            {isExp && (
              <pre className="text-[10px] font-mono p-3 overflow-x-auto"
                style={{ background: 'rgba(0,0,0,0.3)', color: 'var(--text-2)', borderTop: '1px solid var(--border)' }}>
                {JSON.stringify({ id: l.id, ts: l.ts, source: l.source, fields: l.fields, message: l.message }, null, 2)}
              </pre>
            )}
          </div>
        );
      })}
    </div>
  );
}

function ParsedView({ logs, selected, onSelect, onContextMenu }: {
  logs: LogEntry[]; selected: LogEntry | null;
  onSelect: (l: LogEntry) => void; onContextMenu: (e: React.MouseEvent, l: LogEntry) => void;
}) {
  return (
    <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
      {logs.map((l, i) => {
        const fmt    = detectFormat(l.message);
        const fc     = FORMAT_COLOR[fmt];
        const isSel  = selected?.id === l.id;
        const entries = Object.entries(l.fields).filter(([k]) => k !== 'extra' && k !== 'format');
        return (
          <div key={l.id || i} className="px-3 py-2 cursor-pointer transition-colors"
            style={{ background: isSel ? 'var(--accent-glow)' : undefined }}
            onClick={() => onSelect(l)} onContextMenu={e => onContextMenu(e, l)}>
            <div className="flex items-center gap-2 mb-1.5">
              <span style={{ color: 'var(--text-3)', fontSize: 9 }}>{new Date(l.ts).toLocaleTimeString('en', { hour12: false })}</span>
              <span className="text-[10px] font-bold flex items-center gap-1" style={{ color: 'var(--accent)' }}>
                {sourceIcon(l.source)} {l.source}
              </span>
              <span className="text-[9px] px-1 rounded font-mono" style={{ background: `${fc}22`, color: fc, border: `1px solid ${fc}44` }}>{fmt.toUpperCase()}</span>
              <span className="text-[10px] truncate flex-1" style={{ color: 'var(--text-2)' }}>{l.message.slice(0, 80)}</span>
            </div>
            {entries.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {entries.map(([k, v]) => (
                  <span key={k} className="text-[9px] font-mono px-1.5 py-0.5 rounded"
                    style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', color: 'var(--text-1)' }}>
                    <span style={{ color: 'var(--text-3)' }}>{k}:</span>
                    <span style={{ color: 'var(--accent)' }}> {String(v)}</span>
                  </span>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Context / right panel
// ─────────────────────────────────────────────────────────────────────────────

function ContextPanel({ log, logs, tab, onTabChange, bookmarked, onBookmark, aiResult, aiLoading, onExplain, onSummarize, dbStats }: {
  log: LogEntry | null; logs: LogEntry[]; tab: RightTab; onTabChange: (t: RightTab) => void;
  bookmarked: Set<number>; onBookmark: (id: number) => void;
  aiResult: string; aiLoading: boolean; onExplain: () => void; onSummarize: () => void;
  dbStats: any;
}) {
  const [copied, setCopied] = useState(false);
  const [note, setNote]     = useState(log?.note ?? '');
  const [tagInput, setTagInput] = useState('');
  const [sigmaModal, setSigmaModal] = useState(false);

  useEffect(() => { setNote(log?.note ?? ''); }, [log?.id]);

  const copyLog = () => {
    if (!log) return;
    navigator.clipboard.writeText(JSON.stringify(log, null, 2));
    setCopied(true); setTimeout(() => setCopied(false), 1500);
  };

  // Stats from local buffer
  const topSources = useMemo(() => {
    const m: Record<string, number> = {};
    logs.forEach(l => { m[l.source] = (m[l.source] ?? 0) + 1; });
    return Object.entries(m).sort((a,b) => b[1]-a[1]).slice(0, 8);
  }, [logs]);
  const topHosts = useMemo(() => {
    const m: Record<string, number> = {};
    logs.forEach(l => { if (l.fields.hostname) m[l.fields.hostname] = (m[l.fields.hostname] ?? 0) + 1; });
    return Object.entries(m).sort((a,b) => b[1]-a[1]).slice(0, 8);
  }, [logs]);
  const topUsers = useMemo(() => {
    const m: Record<string, number> = {};
    logs.forEach(l => {
      const u = l.fields.user ?? l.fields.target_user;
      if (u) m[u] = (m[u] ?? 0) + 1;
    });
    return Object.entries(m).sort((a,b) => b[1]-a[1]).slice(0, 8);
  }, [logs]);

  const TABS: { id: RightTab; label: string; Icon: any }[] = [
    { id: 'context', label: 'Context', Icon: Eye },
    { id: 'stats',   label: 'Stats',   Icon: BarChart2 },
    { id: 'ai',      label: 'AI',      Icon: Sparkles },
  ];

  return (
    <div className="flex flex-col h-full" style={{ fontSize: 12 }}>
      {/* Tabs */}
      <div className="flex items-center shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => onTabChange(t.id)}
            className="flex-1 flex items-center justify-center gap-1.5 py-2.5 text-[11px] font-semibold transition-colors"
            style={{
              color:         tab === t.id ? 'var(--accent)'  : 'var(--text-3)',
              borderBottom:  `2px solid ${tab === t.id ? 'var(--accent)' : 'transparent'}`,
              background:    tab === t.id ? 'var(--accent-glow)' : 'transparent',
            }}>
            <t.Icon className="h-3 w-3" /> {t.label}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto p-3 space-y-3">
        {/* ── Context tab ── */}
        {tab === 'context' && !log && (
          <p className="text-center py-8 text-[11px]" style={{ color: 'var(--text-3)' }}>
            Click any log entry to inspect it.
          </p>
        )}
        {tab === 'context' && log && (
          <>
            {/* Actions strip */}
            <div className="flex items-center gap-1.5 flex-wrap">
              <button onClick={() => onBookmark(log.id)}
                className="g-btn g-btn-ghost text-[10px] h-7 flex items-center gap-1">
                {bookmarked.has(log.id) ? <BookmarkCheck className="h-3 w-3" style={{ color: 'var(--yellow)' }} /> : <Bookmark className="h-3 w-3" />}
                {bookmarked.has(log.id) ? 'Saved' : 'Bookmark'}
              </button>
              <button onClick={copyLog} className="g-btn g-btn-ghost text-[10px] h-7 flex items-center gap-1">
                {copied ? <Check className="h-3 w-3" style={{ color: 'var(--green)' }} /> : <Copy className="h-3 w-3" />}
                Copy JSON
              </button>
              <button onClick={onExplain} className="g-btn g-btn-ghost text-[10px] h-7 flex items-center gap-1" style={{ color: 'var(--accent)' }}>
                <Sparkles className="h-3 w-3" /> Explain
              </button>
            </div>

            {/* Raw message */}
            <div>
              <p className="text-[9px] uppercase font-semibold mb-1" style={{ color: 'var(--text-3)' }}>Raw Message</p>
              <pre className="text-[10px] leading-relaxed whitespace-pre-wrap break-all font-mono p-2 rounded-lg"
                style={{ background: 'rgba(0,0,0,0.3)', color: 'var(--text-1)', border: '1px solid var(--border)' }}>
                {log.message}
              </pre>
            </div>

            {/* Parsed fields */}
            {Object.keys(log.fields).length > 0 && (
              <div>
                <p className="text-[9px] uppercase font-semibold mb-1.5" style={{ color: 'var(--text-3)' }}>Parsed Fields</p>
                <div className="space-y-0.5">
                  {Object.entries(log.fields).filter(([k]) => k !== 'extra').map(([k, v]) => (
                    <div key={k} className="flex gap-2 text-[10px]">
                      <span className="shrink-0 font-semibold" style={{ color: 'var(--text-3)', width: 90 }}>{k}</span>
                      <span className="font-mono break-all" style={{ color: 'var(--text-1)' }}>{String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Note */}
            <div>
              <p className="text-[9px] uppercase font-semibold mb-1" style={{ color: 'var(--text-3)' }}>Analyst Note</p>
              <textarea value={note} onChange={e => setNote(e.target.value)} rows={2}
                placeholder="Add a note to this log…"
                className="w-full rounded-lg p-2 text-[11px] font-mono resize-none g-input" />
            </div>

            {/* Tags */}
            <div>
              <p className="text-[9px] uppercase font-semibold mb-1" style={{ color: 'var(--text-3)' }}>Tags</p>
              <div className="flex items-center gap-1.5">
                <input value={tagInput} onChange={e => setTagInput(e.target.value)}
                  placeholder="Add tag…" className="g-input text-[10px] h-6 flex-1" />
                <button className="g-btn g-btn-ghost text-[10px] h-6" title="Add tag">+</button>
              </div>
              {log.tags && log.tags.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-1">
                  {log.tags.map(t => (
                    <span key={t} className="text-[9px] px-1.5 py-0.5 rounded"
                      style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </div>

            {/* Quick analyst actions */}
            <div>
              <p className="text-[9px] uppercase font-semibold mb-1" style={{ color: 'var(--text-3)' }}>Analyst Actions</p>
              <div className="grid grid-cols-2 gap-1">
                {[
                  { label: 'Create Sigma Rule', icon: Code },
                  { label: 'Hunt Similar',      icon: Search },
                  { label: 'Add to Case',        icon: Plus },
                  { label: 'Open Investigation', icon: Eye },
                ].map(({ label, icon: Icon }) => (
                  <button key={label}
                    className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg text-[10px] text-left transition-colors"
                    style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}
                    onMouseEnter={e => (e.currentTarget as HTMLElement).style.borderColor = 'var(--accent)'}
                    onMouseLeave={e => (e.currentTarget as HTMLElement).style.borderColor = 'var(--border)'}>
                    <Icon className="h-3 w-3 shrink-0" style={{ color: 'var(--text-3)' }} /> {label}
                  </button>
                ))}
              </div>
            </div>

            {/* Related logs (same source) */}
            <div>
              <p className="text-[9px] uppercase font-semibold mb-1" style={{ color: 'var(--text-3)' }}>Related Logs</p>
              {logs.filter(l => l.id !== log.id && l.source === log.source).slice(-3).map(l => (
                <div key={l.id} className="text-[10px] font-mono truncate py-0.5" style={{ color: 'var(--text-3)' }}>
                  {new Date(l.ts).toLocaleTimeString()} — {l.message.slice(0, 60)}
                </div>
              ))}
            </div>
          </>
        )}

        {/* ── Stats tab ── */}
        {tab === 'stats' && (
          <>
            <div className="grid grid-cols-2 gap-2">
              {[
                { label: 'Total in Buffer', value: logs.length.toLocaleString() },
                { label: 'Unique Sources',  value: new Set(logs.map(l => l.source)).size },
                { label: 'Unique Hosts',    value: new Set(logs.map(l => l.fields.hostname).filter(Boolean)).size },
                { label: 'Auth Failures',   value: logs.filter(l => l.fields.auth_result === 'failure').length },
              ].map(({ label, value }) => (
                <div key={label} className="rounded-lg p-2.5" style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>
                  <p className="text-[9px] uppercase" style={{ color: 'var(--text-3)' }}>{label}</p>
                  <p className="text-lg font-bold font-mono mt-0.5" style={{ color: 'var(--accent)' }}>{value}</p>
                </div>
              ))}
            </div>

            <StatList title="Top Sources" items={topSources} max={topSources[0]?.[1] ?? 1} />
            <StatList title="Top Hosts"   items={topHosts}   max={topHosts[0]?.[1]   ?? 1} />
            <StatList title="Top Users"   items={topUsers}   max={topUsers[0]?.[1]   ?? 1} />

            {dbStats && (
              <div className="rounded-lg p-2.5" style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>
                <p className="text-[9px] uppercase font-semibold mb-2" style={{ color: 'var(--text-3)' }}>Database (all time)</p>
                <div className="flex justify-between text-[10px]">
                  <span style={{ color: 'var(--text-2)' }}>Total logs</span>
                  <span className="font-mono font-bold" style={{ color: 'var(--text-1)' }}>{(dbStats.total_logs ?? 0).toLocaleString()}</span>
                </div>
                <div className="flex justify-between text-[10px] mt-1">
                  <span style={{ color: 'var(--text-2)' }}>Last hour</span>
                  <span className="font-mono font-bold" style={{ color: 'var(--green)' }}>{(dbStats.last_hour_logs ?? 0).toLocaleString()}</span>
                </div>
              </div>
            )}
          </>
        )}

        {/* ── AI tab ── */}
        {tab === 'ai' && (
          <>
            <div className="space-y-2">
              <button onClick={onExplain} disabled={!log || aiLoading}
                className="w-full g-btn g-btn-primary text-xs flex items-center justify-center gap-2 disabled:opacity-40">
                <Sparkles className="h-3.5 w-3.5" />
                {aiLoading ? 'Thinking…' : 'Explain Selected Log'}
              </button>
              <button onClick={onSummarize} disabled={logs.length === 0 || aiLoading}
                className="w-full g-btn g-btn-ghost text-xs flex items-center justify-center gap-2 disabled:opacity-40">
                <BarChart2 className="h-3.5 w-3.5" />
                {aiLoading ? 'Thinking…' : `Summarize ${Math.min(logs.length, 100)} Logs`}
              </button>
            </div>

            {aiResult && (
              <div className="rounded-xl p-3"
                style={{ background: 'rgba(99,102,241,0.08)', border: '1px solid rgba(99,102,241,0.3)' }}>
                <p className="text-[9px] uppercase font-semibold mb-2" style={{ color: 'var(--accent)' }}>AI Analysis</p>
                <p className="text-[11px] leading-relaxed whitespace-pre-wrap" style={{ color: 'var(--text-1)' }}>
                  {aiResult}
                </p>
              </div>
            )}

            <div className="space-y-1">
              {[
                'Why is this log suspicious?',
                'Convert to Sigma rule',
                'Identify anomalies in stream',
              ].map(q => (
                <button key={q} className="w-full text-left px-3 py-2 rounded-lg text-[10px] transition-colors flex items-center gap-2"
                  style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.borderColor = 'var(--accent)'}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.borderColor = 'var(--border)'}>
                  <ArrowRight className="h-3 w-3 shrink-0" style={{ color: 'var(--text-3)' }} /> {q}
                </button>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function StatList({ title, items, max }: { title: string; items: [string, number][]; max: number }) {
  if (items.length === 0) return null;
  return (
    <div>
      <p className="text-[9px] uppercase font-semibold mb-2" style={{ color: 'var(--text-3)' }}>{title}</p>
      <div className="space-y-1">
        {items.map(([name, cnt]) => (
          <div key={name} className="flex items-center gap-2">
            <span className="text-[10px] font-mono truncate" style={{ color: 'var(--text-2)', width: 80, flexShrink: 0 }}>{name}</span>
            <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--border)' }}>
              <div className="h-full rounded-full" style={{ width: `${(cnt/max)*100}%`, background: 'var(--accent)' }} />
            </div>
            <span className="text-[10px] font-mono shrink-0" style={{ color: 'var(--text-3)' }}>{cnt}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Context menu
// ─────────────────────────────────────────────────────────────────────────────

function CtxMenu({ x, y, log, onClose, onBookmark, bookmarked, onAddFilter }: {
  x: number; y: number; log: LogEntry; onClose: () => void;
  onBookmark: () => void; bookmarked: boolean;
  onAddFilter: (field: string, value: string) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const h = () => onClose();
    setTimeout(() => document.addEventListener('click', h), 0);
    return () => document.removeEventListener('click', h);
  }, [onClose]);

  const src_ip  = log.fields.src_ip;
  const host    = log.fields.hostname;
  const user    = log.fields.user ?? log.fields.target_user;
  const process = log.fields.process;

  const items = [
    { label: bookmarked ? 'Remove Bookmark' : 'Bookmark', icon: Bookmark, action: onBookmark },
    { label: 'Copy Raw Message', icon: Copy, action: () => navigator.clipboard.writeText(log.message) },
    { label: 'Copy as JSON',     icon: FileJson, action: () => navigator.clipboard.writeText(JSON.stringify(log, null, 2)) },
    { label: '─', icon: null, action: () => {} },
    ...(src_ip ? [{ label: `Filter: src=${src_ip}`, icon: Filter, action: () => onAddFilter('src_ip', src_ip) }] : []),
    ...(host   ? [{ label: `Filter: host=${host}`,  icon: Filter, action: () => onAddFilter('hostname', host) }] : []),
    ...(user   ? [{ label: `Filter: user=${user}`,  icon: Filter, action: () => onAddFilter('user', user) }] : []),
    { label: '─', icon: null, action: () => {} },
    ...(src_ip ? [{ label: `Investigate IP: ${src_ip}`, icon: Network, action: () => window.open(`/network-map?highlight=${src_ip}`, '_blank') }] : []),
    ...(host   ? [{ label: `Investigate Host: ${host}`, icon: Monitor, action: () => window.open(`/network-map?host=${host}`, '_blank') }] : []),
    ...(user   ? [{ label: `Investigate User: ${user}`, icon: Eye, action: () => window.open(`/risk-posture?user=${user}`, '_blank') }] : []),
    { label: 'Open Timeline', icon: Clock, action: () => window.open('/timeline', '_blank') },
    { label: '─', icon: null, action: () => {} },
    { label: 'Create IOC',        icon: Plus, action: () => {} },
    { label: 'Create Alert Rule', icon: AlertTriangle, action: () => {} },
  ];

  return (
    <div ref={ref}
      style={{
        position: 'fixed', top: y, left: x, zIndex: 9999,
        background: 'var(--glass-bg)', border: '1px solid var(--border)',
        borderRadius: 8, minWidth: 210, padding: '4px 0',
        boxShadow: '0 8px 32px rgba(0,0,0,0.6)',
        backdropFilter: 'blur(12px)',
      }}>
      {items.map(({ label, icon: Icon, action }, i) => (
        label === '─' ? (
          <div key={i} style={{ borderTop: '1px solid var(--border)', margin: '3px 0' }} />
        ) : (
          <button key={i} onClick={(e) => { e.stopPropagation(); action(); onClose(); }}
            className="w-full flex items-center gap-2 px-3 py-1.5 text-[11px] text-left transition-colors"
            style={{ color: 'var(--text-1)' }}
            onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--accent-glow)'}
            onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}>
            {Icon && <Icon className="h-3 w-3 shrink-0" style={{ color: 'var(--text-3)' }} />}
            {label}
          </button>
        )
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Saved views helpers
// ─────────────────────────────────────────────────────────────────────────────

function loadSavedViews(): SavedView[]  { try { return JSON.parse(localStorage.getItem(LS_VIEWS) ?? '[]'); } catch { return []; } }
function storeSavedViews(vs: SavedView[]) { localStorage.setItem(LS_VIEWS, JSON.stringify(vs)); }

// ─────────────────────────────────────────────────────────────────────────────
// Main page
// ─────────────────────────────────────────────────────────────────────────────

export default function LiveLogsPage() {
  const [agents, setAgents]             = useState<Agent[]>([]);
  const [agentId, setAgentId]           = useState<number | null>(null);
  const [logs, setLogs]                 = useState<LogEntry[]>([]);
  const [paused, setPaused]             = useState(false);
  const [autoScroll, setAutoScroll]     = useState(true);
  const [connected, setConnected]       = useState(false);
  const [statusMsg, setStatusMsg]       = useState('');
  const [isDemo, setIsDemo]             = useState(false);
  const [replaying, setReplaying]       = useState(false);
  const [replaySpeed, setReplaySpeed]   = useState(5);
  const [replayIdx, setReplayIdx]       = useState(0);

  // View / layout
  const [viewMode, setViewMode]         = useState<ViewMode>('raw');
  const [rightPanel, setRightPanel]     = useState<RightTab | null>('context');
  const [rightTab, setRightTab]         = useState<RightTab>('context');
  const [hiddenCols, setHiddenCols]     = useState<string[]>([]);

  // Search
  const [search, setSearch]             = useState('');
  const [searchMode, setSearchMode]     = useState<SearchMode>('text');
  const [fieldFilters, setFieldFilters] = useState<FieldFilter[]>([]);
  const [showFilters, setShowFilters]   = useState(false);
  const [addField, setAddField]         = useState('src_ip');
  const [addValue, setAddValue]         = useState('');

  // Analyst
  const [bookmarked, setBookmarked]     = useState<Set<number>>(new Set());
  const [showBookmarks, setShowBookmarks] = useState(false);
  const [selectedLog, setSelectedLog]   = useState<LogEntry | null>(null);
  const [contextMenu, setContextMenu]   = useState<{ x: number; y: number; log: LogEntry } | null>(null);

  // Stats
  const [epsRate, setEpsRate]           = useState(0);
  const [dbStats, setDbStats]           = useState<any>(null);
  const [correlations, setCorrelations] = useState<Correlation[]>([]);

  // AI
  const [aiResult, setAiResult]         = useState('');
  const [aiLoading, setAiLoading]       = useState(false);

  // Saved views
  const [savedViews, setSavedViews]     = useState<SavedView[]>([]);
  const [showViewsPanel, setShowViewsPanel] = useState(false);
  const [saveName, setSaveName]         = useState('');

  // Export
  const [showExport, setShowExport]     = useState(false);

  const wsRef          = useRef<WebSocket | null>(null);
  const epsCountRef    = useRef(0);
  const bottomRef      = useRef<HTMLDivElement>(null);
  const pausedRef      = useRef(false);
  const demoTimerRef   = useRef<ReturnType<typeof setInterval> | null>(null);
  const replayTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const searchRef      = useRef<HTMLInputElement>(null);

  // EPS ticker
  useEffect(() => {
    const iv = setInterval(() => { setEpsRate(epsCountRef.current); epsCountRef.current = 0; }, 1000);
    return () => clearInterval(iv);
  }, []);

  // Correlation detection
  useEffect(() => {
    if (logs.length % 20 === 0) setCorrelations(detectCorrelations(logs));
  }, [logs.length]);

  // DB stats on load
  useEffect(() => {
    setSavedViews(loadSavedViews());
    liveLogAPI.stats().then(r => setDbStats(r.data));
    agentsAPI.getAll().then(r => {
      const list: Agent[] = r.data ?? [];
      setAgents(list);
      if (list.length > 0) setAgentId(list[0].id);
    });
  }, []);

  // Keyboard shortcuts
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      if (e.key === ' ') { e.preventDefault(); setPaused(p => !p); }
      if (e.key === '/') { e.preventDefault(); searchRef.current?.focus(); }
      if (e.key === 'Escape') { setSelectedLog(null); setContextMenu(null); }
      if (e.key === 'b' && selectedLog) toggleBookmark(selectedLog.id);
      if (e.ctrlKey && e.key === 'e') { e.preventDefault(); setShowExport(s => !s); }
      if (e.ctrlKey && e.key === 's') { e.preventDefault(); setShowViewsPanel(s => !s); }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [selectedLog]);

  // Demo stream
  const startDemoStream = useCallback(() => {
    if (demoTimerRef.current) clearInterval(demoTimerRef.current);
    let idx = 0;
    demoTimerRef.current = setInterval(() => {
      if (pausedRef.current) return;
      const t = DEMO_TEMPLATES[idx % DEMO_TEMPLATES.length]; idx++;
      const e: LogEntry = { ...t, id: Date.now() + Math.random(), ts: new Date().toISOString() };
      epsCountRef.current += 1;
      setLogs(prev => { const n = [...prev, e]; return n.length > MAX_LOGS ? n.slice(-MAX_LOGS) : n; });
    }, 320 + Math.floor(Math.random() * 100));
  }, []);

  const stopDemoStream = useCallback(() => {
    if (demoTimerRef.current) { clearInterval(demoTimerRef.current); demoTimerRef.current = null; }
  }, []);

  const connect = useCallback(async (id: number) => {
    if (wsRef.current) wsRef.current.close();
    stopDemoStream();
    let ticket = '';
    try {
      const r = await fetch('/api/ws/ticket', { method: 'POST', credentials: 'include' });
      if (!r.ok) { setConnected(false); return; }
      ticket = (await r.json()).ticket;
    } catch { setConnected(false); return; }

    if (ticket === 'demo-ws-ticket-noop') {
      setIsDemo(true); setConnected(true);
      setStatusMsg('Demo mode — simulated live stream (~3 EPS)');
      startDemoStream(); return;
    }

    setIsDemo(false);
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${window.location.hostname}:8080/api/agents/${id}/logs/stream?ticket=${encodeURIComponent(ticket)}`);
    wsRef.current = ws;
    ws.onopen  = () => { setConnected(true);  setStatusMsg(''); };
    ws.onclose = () => setConnected(false);
    ws.onerror = () => setConnected(false);
    ws.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        if (data.type === 'connected') { setConnected(true); return; }
        if (data.type === 'info') { setStatusMsg(data.message); return; }
        if (pausedRef.current) return;
        const rawFields = data.parsed_fields ?? data.fields;
        const fields: ParsedFields = rawFields
          ? (typeof rawFields === 'string' ? JSON.parse(rawFields) : rawFields) : {};
        epsCountRef.current += 1;
        const e: LogEntry = { id: data.id ?? Date.now(), source: data.source ?? 'agent', message: data.message ?? '', ts: data.ts ?? new Date().toISOString(), fields };
        setLogs(prev => { const n = [...prev, e]; return n.length > MAX_LOGS ? n.slice(-MAX_LOGS) : n; });
      } catch {}
    };
  }, [startDemoStream, stopDemoStream]);

  useEffect(() => {
    if (agentId) connect(agentId);
    return () => { wsRef.current?.close(); stopDemoStream(); };
  }, [agentId, connect, stopDemoStream]);

  useEffect(() => { pausedRef.current = paused; }, [paused]);

  useEffect(() => {
    if (!paused && autoScroll) bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs, paused, autoScroll]);

  // Replay
  const startReplay = () => {
    if (replayTimerRef.current) clearInterval(replayTimerRef.current);
    stopDemoStream(); setReplaying(true); setLogs([]); setReplayIdx(0);
    let i = 0;
    const delay = Math.max(40, Math.floor(1000 / replaySpeed));
    replayTimerRef.current = setInterval(() => {
      if (i >= DEMO_TEMPLATES.length) {
        clearInterval(replayTimerRef.current!); setReplaying(false);
        if (isDemo) startDemoStream(); return;
      }
      const t = DEMO_TEMPLATES[i];
      const e: LogEntry = { ...t, id: Date.now() + i, ts: new Date(Date.now() - (DEMO_TEMPLATES.length - i) * delay).toISOString() };
      setReplayIdx(i + 1);
      setLogs(prev => [...prev, e]);
      i++;
    }, delay);
  };

  const stopReplay = () => {
    if (replayTimerRef.current) { clearInterval(replayTimerRef.current); replayTimerRef.current = null; }
    setReplaying(false); if (isDemo) startDemoStream();
  };

  // Filtering
  const filtered = useMemo(() => logs.filter(l => {
    if (showBookmarks && !bookmarked.has(l.id)) return false;
    if (!matchesSearch(l, search, searchMode)) return false;
    for (const ff of fieldFilters) {
      const val = (l.fields as Record<string, unknown>)[ff.field];
      const match = val ? String(val).toLowerCase().includes(ff.value.toLowerCase()) : false;
      if (ff.negate ? match : !match) return false;
    }
    return true;
  }), [logs, search, searchMode, fieldFilters, showBookmarks, bookmarked]);

  const toggleBookmark = (id: number) =>
    setBookmarked(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });

  const addFilter = (field?: string, value?: string) => {
    const f = field ?? addField;
    const v = value ?? addValue.trim();
    if (!v) return;
    setFieldFilters(prev => [...prev, { field: f, value: v }]);
    setAddValue('');
  };

  // AI handlers
  const handleExplain = async () => {
    if (!selectedLog) return;
    setAiLoading(true); setRightPanel('ai'); setRightTab('ai');
    try {
      const r = await liveLogAPI.explainLog(selectedLog.message, selectedLog.source, selectedLog.fields);
      setAiResult((r as any).data?.explanation ?? 'No explanation available.');
    } catch { setAiResult(isDemo ? '• This log shows a brute-force SSH attempt from an external IP.\n• It is suspicious because root login attempts from unknown IPs are a high-risk indicator.\n• Recommendation: Block the source IP and review all auth logs for this host.' : 'AI service unavailable.'); }
    finally { setAiLoading(false); }
  };

  const handleSummarize = async () => {
    setAiLoading(true); setRightPanel('ai'); setRightTab('ai');
    const messages = filtered.slice(-100).map(l => l.message);
    try {
      const r = await liveLogAPI.summarizeLogs(messages);
      setAiResult((r as any).data?.summary ?? 'No summary available.');
    } catch { setAiResult(isDemo ? '• High volume of failed SSH logins from 185.220.101.35 targeting multiple hosts.\n• Cobalt Strike beaconing detected from 10.10.1.50 to external C2.\n• vssadmin used to delete volume shadow copies — likely ransomware precursor.\n• Recommended: Isolate db-server-02 and win-workstation-05 immediately.' : 'AI service unavailable.'); }
    finally { setAiLoading(false); }
  };

  // Export
  const doExport = (format: string) => {
    let content = '';
    let filename = `live-logs-${Date.now()}`;
    if (format === 'ndjson') {
      content = filtered.map(l => JSON.stringify(l)).join('\n');
      filename += '.ndjson';
    } else if (format === 'json') {
      content = JSON.stringify(filtered, null, 2);
      filename += '.json';
    } else if (format === 'csv') {
      const hdr = 'timestamp,source,severity,hostname,user,process,src_ip,message';
      const rows = filtered.map(l => [
        l.ts, l.source, l.fields.severity ?? l.fields.auth_result ?? '',
        l.fields.hostname ?? '', l.fields.user ?? l.fields.target_user ?? '',
        l.fields.process ?? '', l.fields.src_ip ?? '',
        l.message.replace(/,/g, ';').replace(/\n/g, ' '),
      ].map(v => `"${v}"`).join(','));
      content = [hdr, ...rows].join('\n');
      filename += '.csv';
    } else if (format === 'evidence') {
      const pkg = { exported_at: new Date().toISOString(), total: filtered.length, logs: filtered };
      content = JSON.stringify(pkg, null, 2);
      filename += '-evidence.json';
    }
    const blob = new Blob([content], { type: 'text/plain' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
    setShowExport(false);
  };

  // Save view
  const saveView = () => {
    if (!saveName.trim()) return;
    const v: SavedView = { id: String(Date.now()), name: saveName.trim(), search, fieldFilters, viewMode, hiddenCols };
    const next = [...savedViews, v];
    setSavedViews(next); storeSavedViews(next); setSaveName('');
  };
  const loadView = (v: SavedView) => {
    setSearch(v.search); setFieldFilters(v.fieldFilters); setViewMode(v.viewMode); setHiddenCols(v.hiddenCols);
    setShowViewsPanel(false);
  };
  const deleteView = (id: string) => {
    const next = savedViews.filter(v => v.id !== id);
    setSavedViews(next); storeSavedViews(next);
  };

  const FILTERABLE_FIELDS = ['src_ip', 'hostname', 'user', 'process', 'event_id', 'auth_result', 'severity', 'domain', 'dst_ip', 'pid'];

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <RootLayout title="Live Logs" subtitle="Real-time multi-source log stream with correlation engine">
      <div className="flex flex-col gap-2" style={{ height: 'calc(100vh - 130px)' }}>

        {/* ── Metrics bar ── */}
        <div className="flex items-center gap-3 shrink-0 flex-wrap">
          {[
            { label: 'EPS', value: epsRate, color: epsRate > 0 ? 'var(--green)' : 'var(--text-3)', icon: <Zap className="h-3 w-3" /> },
            { label: 'Buffer', value: `${logs.length}/${MAX_LOGS}`, color: 'var(--text-2)', icon: <Activity className="h-3 w-3" /> },
            { label: 'Matching', value: filtered.length, color: 'var(--accent)', icon: <Filter className="h-3 w-3" /> },
            { label: 'Bookmarked', value: bookmarked.size, color: 'var(--yellow)', icon: <Bookmark className="h-3 w-3" /> },
          ].map(({ label, value, color, icon }) => (
            <div key={label} className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg"
              style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
              <span style={{ color: 'var(--text-3)' }}>{icon}</span>
              <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{label}</span>
              <span className="text-xs font-bold font-mono" style={{ color }}>{value}</span>
            </div>
          ))}

          {/* Connection pill */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg ml-auto"
            style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
            <span className="h-2 w-2 rounded-full shrink-0 transition-all"
              style={{ background: connected ? 'var(--green)' : 'var(--red)', boxShadow: connected && !paused ? '0 0 5px var(--green)' : 'none' }} />
            <span className="text-[10px]" style={{ color: 'var(--text-2)' }}>
              {connected ? (paused ? 'Paused' : (replaying ? 'Replay' : 'Live')) : 'Offline'}
            </span>
            {isDemo && <span className="text-[9px] px-1 rounded" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>DEMO</span>}
          </div>
        </div>

        {/* ── Correlation alerts ── */}
        {correlations.length > 0 && (
          <div className="flex items-center gap-2 flex-wrap shrink-0">
            {correlations.map(c => (
              <div key={c.type} className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[10px] font-semibold"
                style={{ background: `${c.color}18`, border: `1px solid ${c.color}44`, color: c.color }}>
                <AlertTriangle className="h-3 w-3 shrink-0" />
                {c.label} · {c.detail}
              </div>
            ))}
          </div>
        )}

        {/* ── Stream controls ── */}
        <div className="flex items-center gap-2 flex-wrap shrink-0">
          <select value={agentId ?? ''} onChange={e => setAgentId(Number(e.target.value))}
            className="g-select" style={{ minWidth: 160 }}>
            {agents.map(a => <option key={a.id} value={a.id}>{a.hostname} (#{a.id})</option>)}
          </select>

          <button onClick={() => setPaused(p => !p)} className={`g-btn text-xs ${paused ? 'g-btn-primary' : 'g-btn-ghost'} flex items-center gap-1.5`}>
            {paused ? <><Play className="h-3.5 w-3.5" />Resume</> : <><Pause className="h-3.5 w-3.5" />Pause</>}
          </button>

          <button onClick={() => setAutoScroll(s => !s)}
            className={`g-btn text-xs ${autoScroll ? 'g-btn-primary' : 'g-btn-ghost'} flex items-center gap-1.5`}>
            <ArrowRight className="h-3.5 w-3.5" /> AutoScroll
          </button>

          <button onClick={() => { setLogs([]); setBookmarked(new Set()); setSelectedLog(null); setAiResult(''); }}
            className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
            <Trash2 className="h-3.5 w-3.5" /> Clear
          </button>

          {isDemo && !replaying && (
            <>
              <select value={replaySpeed} onChange={e => setReplaySpeed(Number(e.target.value))}
                className="g-select text-xs" style={{ width: 64 }}>
                {[1, 5, 10, 20].map(s => <option key={s} value={s}>{s}×</option>)}
              </select>
              <button onClick={startReplay} className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
                <RotateCcw className="h-3.5 w-3.5" /> Replay
              </button>
            </>
          )}

          {replaying && (
            <div className="flex items-center gap-2 ml-auto">
              <span className="text-xs mono" style={{ color: 'var(--text-3)' }}>Replaying {replayIdx}/{DEMO_TEMPLATES.length}</span>
              <div className="w-20 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--border)' }}>
                <div className="h-full rounded-full" style={{ width: `${(replayIdx/DEMO_TEMPLATES.length)*100}%`, background: 'var(--accent)' }} />
              </div>
              <button onClick={stopReplay} className="g-btn g-btn-ghost text-xs" title="Stop replay">×</button>
            </div>
          )}
        </div>

        {/* ── Search + view controls ── */}
        <div className="flex items-center gap-2 flex-wrap shrink-0">
          {/* Search mode selector */}
          <div className="flex rounded-lg overflow-hidden shrink-0" style={{ border: '1px solid var(--border)' }}>
            {(['text', 'regex', 'field'] as SearchMode[]).map(m => (
              <button key={m} onClick={() => setSearchMode(m)}
                className="px-2.5 py-1.5 text-[10px] font-semibold uppercase transition-colors"
                style={{
                  background: searchMode === m ? 'var(--accent-glow)' : 'transparent',
                  color:      searchMode === m ? 'var(--accent)' : 'var(--text-3)',
                  borderRight: m !== 'field' ? '1px solid var(--border)' : undefined,
                }}>
                {m === 'regex' ? '/re/' : m}
              </button>
            ))}
          </div>

          {/* Search input */}
          <div className="relative flex-1 min-w-[200px] max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
            <input ref={searchRef} value={search} onChange={e => setSearch(e.target.value)}
              placeholder={searchMode === 'regex' ? 'Regex pattern…' : searchMode === 'field' ? 'host:server01 AND user:admin…' : 'Search logs… (-exclude, "phrase")'}
              className="g-input pl-9 pr-8" />
            {search && (
              <button onClick={() => setSearch('')} className="absolute right-3 top-1/2 -translate-y-1/2">
                <X className="h-3 w-3" style={{ color: 'var(--text-3)' }} />
              </button>
            )}
          </div>

          {/* View mode */}
          <div className="flex rounded-lg overflow-hidden shrink-0" style={{ border: '1px solid var(--border)' }}>
            {([['raw', 'Raw', Terminal], ['table', 'Table', Table2], ['json', 'JSON', FileJson], ['parsed', 'Parsed', Hash]] as [ViewMode, string, any][]).map(([m, label, Icon]) => (
              <button key={m} onClick={() => setViewMode(m)}
                className="flex items-center gap-1 px-2.5 py-1.5 text-[10px] transition-colors"
                style={{
                  background: viewMode === m ? 'var(--accent-glow)' : 'transparent',
                  color:      viewMode === m ? 'var(--accent)' : 'var(--text-3)',
                  borderRight: m !== 'parsed' ? '1px solid var(--border)' : undefined,
                }}>
                <Icon className="h-3 w-3" /> {label}
              </button>
            ))}
          </div>

          {/* Tools */}
          <button onClick={() => setShowFilters(f => !f)}
            className={`g-btn text-xs ${showFilters || fieldFilters.length > 0 ? 'g-btn-primary' : 'g-btn-ghost'} flex items-center gap-1.5`}>
            <SlidersHorizontal className="h-3.5 w-3.5" /> Filters
            {fieldFilters.length > 0 && <span className="text-[9px] px-1 rounded" style={{ background: 'var(--accent)', color: '#fff' }}>{fieldFilters.length}</span>}
          </button>

          <button onClick={() => setShowBookmarks(b => !b)}
            className={`g-btn text-xs ${showBookmarks ? 'g-btn-primary' : 'g-btn-ghost'} flex items-center gap-1.5`}>
            <Bookmark className="h-3.5 w-3.5" />
            {bookmarked.size > 0 && <span className="text-[9px] px-1 rounded" style={{ background: 'var(--yellow)', color: 'var(--bg-0)' }}>{bookmarked.size}</span>}
          </button>

          <button onClick={() => setShowViewsPanel(v => !v)}
            className={`g-btn text-xs ${showViewsPanel ? 'g-btn-primary' : 'g-btn-ghost'} flex items-center gap-1.5`}>
            <Save className="h-3.5 w-3.5" /> Views
          </button>

          {viewMode === 'table' && (
            <button onClick={() => {}} className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
              <Columns className="h-3.5 w-3.5" /> Columns
            </button>
          )}

          {/* Right panel toggle */}
          <button onClick={() => setRightPanel(p => p ? null : 'context')}
            className={`g-btn text-xs ${rightPanel ? 'g-btn-primary' : 'g-btn-ghost'} flex items-center gap-1.5 ml-auto`}>
            {rightPanel ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
            Panel
          </button>

          <div className="relative">
            <button onClick={() => setShowExport(e => !e)} className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
              <Download className="h-3.5 w-3.5" /> Export
            </button>
            {showExport && (
              <div className="absolute right-0 top-full mt-1 rounded-lg overflow-hidden z-50"
                style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', minWidth: 150, backdropFilter: 'blur(12px)' }}>
                {[['ndjson','NDJSON'],['json','JSON'],['csv','CSV'],['evidence','Evidence Package']].map(([fmt, label]) => (
                  <button key={fmt} onClick={() => doExport(fmt)}
                    className="w-full text-left px-3 py-2 text-xs transition-colors"
                    style={{ color: 'var(--text-1)' }}
                    onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--accent-glow)'}
                    onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}>
                    {label}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* ── Field filter panel ── */}
        {showFilters && (
          <div className="rounded-xl p-3 flex flex-wrap items-center gap-2 shrink-0"
            style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>
            {fieldFilters.map((ff, i) => (
              <div key={i} className="flex items-center gap-1 px-2 py-1 rounded-lg text-[11px]"
                style={{ background: 'var(--bg-2)', border: '1px solid var(--accent-border)' }}>
                <span style={{ color: 'var(--text-3)' }}>{ff.field}:</span>
                <span style={{ color: 'var(--accent)' }}>{ff.value}</span>
                <button onClick={() => setFieldFilters(f => f.filter((_,j) => j !== i))} className="ml-1">
                  <X className="h-3 w-3" style={{ color: 'var(--text-3)' }} />
                </button>
              </div>
            ))}
            <select value={addField} onChange={e => setAddField(e.target.value)} className="g-select text-xs h-7" style={{ minWidth: 100 }}>
              {FILTERABLE_FIELDS.map(f => <option key={f} value={f}>{f}</option>)}
            </select>
            <input value={addValue} onChange={e => setAddValue(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && addFilter()}
              placeholder="value…" className="g-input text-xs h-7 w-28" />
            <button onClick={() => addFilter()} className="g-btn g-btn-primary text-xs h-7">Add</button>
            {fieldFilters.length > 0 && (
              <button onClick={() => setFieldFilters([])} className="g-btn g-btn-ghost text-xs h-7">Clear all</button>
            )}
          </div>
        )}

        {/* ── Saved views panel ── */}
        {showViewsPanel && (
          <div className="rounded-xl p-3 shrink-0" style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <input value={saveName} onChange={e => setSaveName(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && saveView()}
                placeholder="Name this view…" className="g-input text-xs h-7 w-40" />
              <button onClick={saveView} className="g-btn g-btn-primary text-xs h-7">Save Current</button>
            </div>
            {savedViews.length === 0 ? (
              <p className="text-xs" style={{ color: 'var(--text-3)' }}>No saved views yet.</p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {savedViews.map(v => (
                  <div key={v.id} className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg"
                    style={{ background: 'var(--bg-2)', border: '1px solid var(--border)' }}>
                    <button onClick={() => loadView(v)} className="text-xs font-medium" style={{ color: 'var(--accent)' }}>{v.name}</button>
                    <span className="text-[9px]" style={{ color: 'var(--text-3)' }}>{v.viewMode} · {v.fieldFilters.length} filters</span>
                    <button onClick={() => deleteView(v.id)}><X className="h-3 w-3" style={{ color: 'var(--text-3)' }} /></button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {statusMsg && (
          <div className="rounded-xl px-4 py-2 text-xs shrink-0"
            style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)', color: 'var(--accent)' }}>
            {statusMsg}
          </div>
        )}

        {/* ── Main area ── */}
        <div className="flex-1 flex gap-3 min-h-0 overflow-hidden">

          {/* Log stream */}
          <div className="flex-1 overflow-y-auto rounded-2xl min-h-0"
            style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
            {filtered.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-40 gap-2">
                <Activity className="h-7 w-7 animate-pulse" style={{ color: 'var(--text-3)' }} />
                <p style={{ color: 'var(--text-3)', fontSize: 12 }}>
                  {connected ? (logs.length === 0 ? 'Waiting for logs…' : 'No matching events') : 'Select an agent to connect'}
                </p>
              </div>
            ) : viewMode === 'table' ? (
              <TableView logs={filtered} search={search} hiddenCols={hiddenCols}
                selected={selectedLog} bookmarked={bookmarked}
                onSelect={l => setSelectedLog(s => s?.id === l.id ? null : l)}
                onContextMenu={(e, l) => { e.preventDefault(); setContextMenu({ x: e.clientX, y: e.clientY, log: l }); }} />
            ) : viewMode === 'json' ? (
              <JsonView logs={filtered} search={search}
                selected={selectedLog}
                onSelect={l => setSelectedLog(s => s?.id === l.id ? null : l)}
                onContextMenu={(e, l) => { e.preventDefault(); setContextMenu({ x: e.clientX, y: e.clientY, log: l }); }} />
            ) : viewMode === 'parsed' ? (
              <ParsedView logs={filtered} selected={selectedLog}
                onSelect={l => setSelectedLog(s => s?.id === l.id ? null : l)}
                onContextMenu={(e, l) => { e.preventDefault(); setContextMenu({ x: e.clientX, y: e.clientY, log: l }); }} />
            ) : (
              /* Raw view */
              <div className="font-mono text-[11px] leading-5 p-3">
                {filtered.map((log, i) => {
                  const isSelected   = selectedLog?.id === log.id;
                  const isBookmarked = bookmarked.has(log.id);
                  const color        = lineColor(log.message, log.fields);
                  const isSusp       = correlations.some(c => {
                    if (c.type === 'brute_force' && log.fields.auth_result === 'failure') return true;
                    if (c.type === 'c2' && /cobalt|beacon|C2/i.test(log.message)) return true;
                    if (c.type === 'powershell' && /-enc|-nop -w hidden|EncodedCommand/i.test(log.message)) return true;
                    return false;
                  });
                  return (
                    <div key={log.id || i}
                      className="group relative flex flex-col gap-0.5 py-0.5 px-1 rounded cursor-pointer transition-all"
                      style={{
                        background:   isSelected ? 'var(--accent-glow)' : undefined,
                        borderLeft:  `2px solid ${isSelected ? 'var(--accent)' : isSusp ? 'var(--red)' : 'transparent'}`,
                        outline:      isSusp && !isSelected ? '1px solid rgba(239,68,68,0.2)' : undefined,
                      }}
                      onClick={() => setSelectedLog(s => s?.id === log.id ? null : log)}
                      onContextMenu={e => { e.preventDefault(); setContextMenu({ x: e.clientX, y: e.clientY, log }); }}>
                      <div className="flex gap-2 items-baseline flex-wrap">
                        <button onClick={e => { e.stopPropagation(); toggleBookmark(log.id); }}
                          className={`transition-opacity shrink-0 ${isBookmarked ? '' : 'opacity-0 group-hover:opacity-100'}`}>
                          {isBookmarked
                            ? <BookmarkCheck className="h-3 w-3" style={{ color: 'var(--yellow)' }} />
                            : <Bookmark className="h-3 w-3" style={{ color: 'var(--text-3)' }} />}
                        </button>
                        <span className="shrink-0 select-none" style={{ color: 'var(--text-3)', width: 64 }}>
                          {new Date(log.ts).toLocaleTimeString('en', { hour12: false })}
                        </span>
                        <span className="shrink-0 flex items-center gap-1" style={{ color: 'var(--accent)', width: 96 }}>
                          {sourceIcon(log.source)}
                          <span className="truncate text-[10px]">{log.source}</span>
                        </span>
                        <span style={{ color, wordBreak: 'break-all', flex: 1 }}>
                          <HL text={log.message} term={searchMode !== 'regex' ? search : ''} />
                        </span>
                        <span className="opacity-0 group-hover:opacity-60 shrink-0 transition-opacity">
                          {isSelected ? <ChevronDown className="h-3 w-3" style={{ color: 'var(--text-3)' }} /> : <ChevronRight className="h-3 w-3" style={{ color: 'var(--text-3)' }} />}
                        </span>
                      </div>
                      <div style={{ paddingLeft: 170 }}>
                        <FieldChips fields={log.fields} />
                      </div>
                    </div>
                  );
                })}
                <div ref={bottomRef} />
              </div>
            )}
            {viewMode !== 'raw' && <div ref={bottomRef} />}
          </div>

          {/* Right panel */}
          {rightPanel && (
            <div style={{ width: 320, flexShrink: 0, minHeight: 0, overflow: 'hidden', display: 'flex', flexDirection: 'column', background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: '1rem' }}>
              <ContextPanel
                log={selectedLog} logs={logs} tab={rightTab} onTabChange={t => { setRightTab(t); setRightPanel(t); }}
                bookmarked={bookmarked} onBookmark={toggleBookmark}
                aiResult={aiResult} aiLoading={aiLoading}
                onExplain={handleExplain} onSummarize={handleSummarize}
                dbStats={dbStats}
              />
            </div>
          )}
        </div>

        {/* Keyboard shortcut hint */}
        <div className="flex items-center gap-3 shrink-0 flex-wrap" style={{ fontSize: 9, color: 'var(--text-3)' }}>
          {[['Space','Pause'],['/', 'Search'],['Esc','Deselect'],['b','Bookmark'],['Ctrl+E','Export'],['Ctrl+S','Save View']].map(([key, label]) => (
            <span key={key}><span className="px-1 rounded" style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', fontFamily: 'monospace' }}>{key}</span> {label}</span>
          ))}
        </div>
      </div>

      {/* Context menu */}
      {contextMenu && (
        <CtxMenu x={contextMenu.x} y={contextMenu.y} log={contextMenu.log}
          bookmarked={bookmarked.has(contextMenu.log.id)}
          onBookmark={() => toggleBookmark(contextMenu.log.id)}
          onClose={() => setContextMenu(null)}
          onAddFilter={(f, v) => { addFilter(f, v); setShowFilters(true); }} />
      )}

      {/* Close overlays on backdrop click */}
      {(showExport) && <div className="fixed inset-0 z-40" onClick={() => setShowExport(false)} />}
    </RootLayout>
  );
}
