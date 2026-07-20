'use client';

import { useState, useEffect, useCallback, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { elasticAPI } from '@/lib/api';
import {
  BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer,
} from 'recharts';
import { Activity, AlertCircle, ArrowUpDown, BookOpen, Bot, Braces, Check, ChevronDown, ChevronRight, ChevronUp, Clock, Code2, Copy, Database, DatabaseZap, Download, FileJson, Filter, Hash, Layers, Lightbulb, Play, RefreshCw, RotateCcw, Save, Server, Star, StarOff, Table2, Terminal, Trash2, Wand2, X } from '@/lib/icon-stubs';

// ── Types ─────────────────────────────────────────────────────────────────────

interface ESHit {
  _index: string; _id: string; _score: number; _source: Record<string, unknown>;
}
interface ESResult {
  took: number; timed_out: boolean; total: number;
  hits: { total: { value: number; relation?: string }; hits: ESHit[] };
  aggregations?: Record<string, unknown>;
  _shards?: { total: number; successful: number; skipped: number; failed: number };
  error?: string;
}
interface ESIndex {
  index: string; docs_count: string; store_size: string; health: string;
  status?: string; pri?: number; rep?: number; creation_date?: string;
}
interface SavedQuery {
  id: string; name: string; index: string; dsl: string;
  created_at: string; starred: boolean; folder: string;
}
interface EditorTab { id: string; name: string; index: string; dsl: string; }
interface HistoryEntry { dsl: string; index: string; ts: string; total: number; took: number; }

// ── Query library ─────────────────────────────────────────────────────────────

interface LibEntry { id: string; name: string; folder: string; desc: string; dsl: string; }

const LIB: LibEntry[] = [
  // Threat Hunting
  { id:'th1', folder:'Threat Hunting', name:'Failed Logins (SSH + Windows)',
    desc:'Auth failures from SSH, PAM, and Windows 4625',
    dsl: JSON.stringify({ query:{ bool:{ should:[{ match_phrase:{ log_message:'Failed password' } },{ match_phrase:{ log_message:'authentication failure' } },{ term:{ 'parsed_fields.event_id':'4625' } }], minimum_should_match:1, filter:[{ range:{ collected_at:{ gte:'now-24h' } } }] } }, aggs:{ by_ip:{ terms:{ field:'parsed_fields.src_ip', size:20 } }, by_user:{ terms:{ field:'parsed_fields.user', size:10 } } }, sort:[{ collected_at:{ order:'desc' } }], size:100 }, null, 2) },
  { id:'th2', folder:'Threat Hunting', name:'PowerShell Execution (4103/4104)',
    desc:'PowerShell script block and module logging events',
    dsl: JSON.stringify({ query:{ bool:{ should:[{ match_phrase:{ log_message:'powershell.exe' } },{ match_phrase:{ log_message:'Invoke-Expression' } },{ term:{ 'parsed_fields.event_id':'4104' } }], minimum_should_match:1 } }, sort:[{ collected_at:{ order:'desc' } }], size:50 }, null, 2) },
  { id:'th3', folder:'Threat Hunting', name:'Encoded / Obfuscated Commands',
    desc:'-EncodedCommand, FromBase64String, bypass flags',
    dsl: JSON.stringify({ query:{ bool:{ should:[{ match_phrase:{ log_message:'-EncodedCommand' } },{ match_phrase:{ log_message:'FromBase64String' } },{ match_phrase:{ log_message:'-ExecutionPolicy Bypass' } }], minimum_should_match:1 } }, sort:[{ collected_at:{ order:'desc' } }], size:50 }, null, 2) },
  { id:'th4', folder:'Threat Hunting', name:'LSASS Memory Access',
    desc:'Credential dumping via LSASS — mimikatz, procdump patterns',
    dsl: JSON.stringify({ query:{ bool:{ should:[{ match_phrase:{ log_message:'lsass' } },{ match_phrase:{ log_message:'mimikatz' } },{ match_phrase:{ log_message:'sekurlsa' } },{ term:{ 'parsed_fields.event_id':'4656' } }], minimum_should_match:1 } }, sort:[{ collected_at:{ order:'desc' } }], size:50 }, null, 2) },
  { id:'th5', folder:'Threat Hunting', name:'Suspicious DNS (DGA / exfil)',
    desc:'NXDOMAIN storms, long subdomains, unusual TLDs',
    dsl: JSON.stringify({ query:{ bool:{ filter:[{ term:{ log_source:'named' } }] } }, aggs:{ top_queries:{ terms:{ field:'parsed_fields.query_name', size:30 } }, nxdomain:{ filter:{ match_phrase:{ log_message:'NXDOMAIN' } } } }, sort:[{ collected_at:{ order:'desc' } }], size:50 }, null, 2) },
  { id:'th6', folder:'Threat Hunting', name:'C2 Beaconing (periodic outbound)',
    desc:'Regular-interval outbound connections to same dest IP',
    dsl: JSON.stringify({ query:{ bool:{ filter:[{ range:{ collected_at:{ gte:'now-6h' } } }], should:[{ match_phrase:{ log_message:'CONNECT' } },{ match_phrase:{ log_message:'outbound' } }], minimum_should_match:1 } }, aggs:{ by_dest:{ terms:{ field:'parsed_fields.dst_ip', size:20 }, aggs:{ over_time:{ date_histogram:{ field:'collected_at', fixed_interval:'5m' } } } } }, size:0 }, null, 2) },
  { id:'th7', folder:'Threat Hunting', name:'Kerberoasting (Event 4769 RC4)',
    desc:'TGS requests with RC4-HMAC encryption (0x17)',
    dsl: JSON.stringify({ query:{ bool:{ must:[{ term:{ 'parsed_fields.event_id':'4769' } }], should:[{ match_phrase:{ log_message:'0x17' } },{ match_phrase:{ log_message:'RC4-HMAC' } }], minimum_should_match:1 } }, aggs:{ by_user:{ terms:{ field:'parsed_fields.user', size:10 } } }, sort:[{ collected_at:{ order:'desc' } }], size:100 }, null, 2) },
  { id:'th8', folder:'Threat Hunting', name:'DCSync (4662 — DS-Replication)',
    desc:'Domain controller replication right abuse',
    dsl: JSON.stringify({ query:{ bool:{ must:[{ term:{ 'parsed_fields.event_id':'4662' } }], should:[{ match_phrase:{ log_message:'1131f6aa' } },{ match_phrase:{ log_message:'DS-Replication' } }], minimum_should_match:1 } }, sort:[{ collected_at:{ order:'desc' } }], size:50 }, null, 2) },
  // Incident Response
  { id:'ir1', folder:'Incident Response', name:'New Service Installed (7045)',
    desc:'New Windows service creation — persistence detection',
    dsl: JSON.stringify({ query:{ bool:{ should:[{ term:{ 'parsed_fields.event_id':'7045' } },{ match_phrase:{ log_message:'New service was installed' } }], minimum_should_match:1 } }, sort:[{ collected_at:{ order:'desc' } }], size:50 }, null, 2) },
  { id:'ir2', folder:'Incident Response', name:'Lateral Movement via RDP (4624 T3)',
    desc:'Remote interactive logons — lateral movement indicator',
    dsl: JSON.stringify({ query:{ bool:{ must:[{ term:{ 'parsed_fields.event_id':'4624' } }], filter:[{ match_phrase:{ log_message:'RemoteInteractive' } }] } }, aggs:{ by_src:{ terms:{ field:'parsed_fields.src_ip', size:20 } } }, sort:[{ collected_at:{ order:'desc' } }], size:100 }, null, 2) },
  { id:'ir3', folder:'Incident Response', name:'Account Created / Added to Admins',
    desc:'4720 (created), 4732 (added to local admins)',
    dsl: JSON.stringify({ query:{ bool:{ should:[{ term:{ 'parsed_fields.event_id':'4720' } },{ term:{ 'parsed_fields.event_id':'4732' } },{ term:{ 'parsed_fields.event_id':'4728' } }], minimum_should_match:1 } }, sort:[{ collected_at:{ order:'desc' } }], size:50 }, null, 2) },
  { id:'ir4', folder:'Incident Response', name:'Data Exfiltration (large outbound)',
    desc:'High-volume outbound transfers — zip, tar, large bytes',
    dsl: JSON.stringify({ query:{ bool:{ should:[{ match_phrase:{ log_message:'zip' } },{ match_phrase:{ log_message:'tar.gz' } },{ range:{ 'parsed_fields.bytes':{ gte:10485760 } } }], minimum_should_match:1 } }, sort:[{ collected_at:{ order:'desc' } }], size:50 }, null, 2) },
  // Detection Engineering
  { id:'de1', folder:'Detection Engineering', name:'High-Volume Auth Failures (threshold)',
    desc:'Aggregation: IPs with >20 failures in 1h',
    dsl: JSON.stringify({ query:{ bool:{ should:[{ match_phrase:{ log_message:'Failed password' } },{ term:{ 'parsed_fields.event_id':'4625' } }], minimum_should_match:1, filter:[{ range:{ collected_at:{ gte:'now-1h' } } }] } }, aggs:{ by_ip:{ terms:{ field:'parsed_fields.src_ip', size:50 }, aggs:{ per_minute:{ date_histogram:{ field:'collected_at', fixed_interval:'1m' } } } } }, size:0 }, null, 2) },
  { id:'de2', folder:'Detection Engineering', name:'Web Shell Detection',
    desc:'Suspicious web server processes — cmd.exe, powershell as children',
    dsl: JSON.stringify({ query:{ bool:{ should:[{ match_phrase:{ log_message:'cmd.exe' } },{ match_phrase:{ log_message:'/bin/bash' } },{ match_phrase:{ log_message:'whoami' } }], minimum_should_match:1, filter:[{ term:{ log_source:'nginx' } }] } }, sort:[{ collected_at:{ order:'desc' } }], size:50 }, null, 2) },
  // Compliance
  { id:'co1', folder:'Compliance', name:'Admin Login Audit (4672)',
    desc:'Special privileges assigned — admin logons',
    dsl: JSON.stringify({ query:{ bool:{ should:[{ term:{ 'parsed_fields.event_id':'4672' } },{ match_phrase:{ log_message:'SeDebugPrivilege' } }], minimum_should_match:1, filter:[{ range:{ collected_at:{ gte:'now-7d' } } }] } }, aggs:{ by_user:{ terms:{ field:'parsed_fields.user', size:20 } }, by_day:{ date_histogram:{ field:'collected_at', calendar_interval:'1d' } } }, sort:[{ collected_at:{ order:'desc' } }], size:100 }, null, 2) },
  { id:'co2', folder:'Compliance', name:'Account Lockouts (4740)',
    desc:'Account lockout events for compliance report',
    dsl: JSON.stringify({ query:{ bool:{ should:[{ term:{ 'parsed_fields.event_id':'4740' } },{ match_phrase:{ log_message:'account is locked out' } }], minimum_should_match:1 } }, aggs:{ by_user:{ terms:{ field:'parsed_fields.user', size:20 } } }, sort:[{ collected_at:{ order:'desc' } }], size:100 }, null, 2) },
  // Daily
  { id:'da1', folder:'Daily', name:'Last 1 Hour — All Events',
    desc:'Recent log activity across all sources',
    dsl: JSON.stringify({ query:{ range:{ collected_at:{ gte:'now-1h' } } }, aggs:{ by_source:{ terms:{ field:'log_source', size:20 } }, over_time:{ date_histogram:{ field:'collected_at', fixed_interval:'5m' } } }, sort:[{ collected_at:{ order:'desc' } }], size:50 }, null, 2) },
  { id:'da2', folder:'Daily', name:'Top Log Sources (24h)',
    desc:'Event distribution across all log sources',
    dsl: JSON.stringify({ query:{ range:{ collected_at:{ gte:'now-24h' } } }, aggs:{ by_source:{ terms:{ field:'log_source', size:30 } } }, size:0 }, null, 2) },
];

const LIB_FOLDERS = [...new Set(LIB.map(q => q.folder))];

// ── ECS field explorer ────────────────────────────────────────────────────────

interface FieldDef { path: string; type: string; example: string; desc: string; }

const ECS_FIELDS: FieldDef[] = [
  { path:'host.name',                type:'keyword', example:'web-prod-01',     desc:'Hostname of the source system' },
  { path:'process.name',             type:'keyword', example:'powershell.exe',  desc:'Process executable name' },
  { path:'process.command_line',     type:'text',    example:'powershell -enc…', desc:'Full command line string' },
  { path:'process.pid',              type:'long',    example:'4512',            desc:'Process ID' },
  { path:'process.parent.name',      type:'keyword', example:'winword.exe',     desc:'Parent process name' },
  { path:'user.name',                type:'keyword', example:'jdoe',            desc:'Username performing action' },
  { path:'user.domain',              type:'keyword', example:'CORP',            desc:'User domain / realm' },
  { path:'file.path',                type:'keyword', example:'/tmp/malware.sh', desc:'Full file path' },
  { path:'file.hash.sha256',         type:'keyword', example:'abc123…',         desc:'SHA-256 hash of file' },
  { path:'registry.path',            type:'keyword', example:'HKLM\\\\Run\\\\evil', desc:'Registry key path' },
  { path:'dns.question.name',        type:'keyword', example:'evil.c2.io',      desc:'DNS query hostname' },
  { path:'network.direction',        type:'keyword', example:'outbound',        desc:'Network traffic direction' },
  { path:'source.ip',                type:'ip',      example:'10.0.0.5',        desc:'Source IP address' },
  { path:'destination.ip',           type:'ip',      example:'185.220.101.35',  desc:'Destination IP address' },
  { path:'destination.port',         type:'long',    example:'443',             desc:'Destination port' },
  { path:'event.category',           type:'keyword', example:'authentication',  desc:'High-level event category (ECS)' },
  { path:'event.action',             type:'keyword', example:'user-logon',      desc:'Specific event action' },
  { path:'event.outcome',            type:'keyword', example:'failure',         desc:'Event outcome: success/failure' },
  { path:'winlog.event_id',          type:'keyword', example:'4625',            desc:'Windows event ID' },
  { path:'winlog.channel',           type:'keyword', example:'Security',        desc:'Windows event channel' },
  // XCloak native
  { path:'log_source',               type:'keyword', example:'ssh',             desc:'XCloak log source type' },
  { path:'log_message',              type:'text',    example:'Failed password…', desc:'Raw log line' },
  { path:'collected_at',             type:'date',    example:'2026-07-14T…',    desc:'Ingest timestamp' },
  { path:'agent_id',                 type:'long',    example:'3',               desc:'XCloak agent ID' },
  { path:'parsed_fields.src_ip',     type:'ip',      example:'185.220.101.35',  desc:'Source IP (parsed)' },
  { path:'parsed_fields.dst_ip',     type:'ip',      example:'1.2.3.4',         desc:'Destination IP (parsed)' },
  { path:'parsed_fields.user',       type:'keyword', example:'root',            desc:'Username (parsed)' },
  { path:'parsed_fields.process',    type:'keyword', example:'sshd',            desc:'Process name (parsed)' },
  { path:'parsed_fields.event_id',   type:'keyword', example:'4625',            desc:'Windows Event ID (parsed)' },
  { path:'parsed_fields.auth_result',type:'keyword', example:'failure',         desc:'Auth outcome (parsed)' },
  { path:'parsed_fields.bytes',      type:'long',    example:'1048576',         desc:'Bytes transferred (parsed)' },
  { path:'parsed_fields.method',     type:'keyword', example:'GET',             desc:'HTTP method (parsed)' },
];

const TYPE_COLOR: Record<string, string> = {
  keyword: 'var(--blue)', text: 'var(--green)', date: 'var(--yellow)',
  long: 'var(--orange)', integer: 'var(--orange)', ip: 'var(--accent)',
};

// ── Aggregation builder templates ─────────────────────────────────────────────

const AGG_TEMPLATES = [
  { name:'Terms (top N)',        key:'top_terms',   agg:{ terms:{ field:'log_source', size:10 } } },
  { name:'Date Histogram',       key:'over_time',   agg:{ date_histogram:{ field:'collected_at', fixed_interval:'1h' } } },
  { name:'Avg',                  key:'avg_field',   agg:{ avg:{ field:'parsed_fields.bytes' } } },
  { name:'Cardinality (unique)', key:'unique_vals', agg:{ cardinality:{ field:'parsed_fields.src_ip' } } },
  { name:'Top Hits',             key:'top_events',  agg:{ top_hits:{ size:3, _source:['log_message','collected_at'] } } },
  { name:'Filter bucket',        key:'failures',    agg:{ filter:{ term:{ 'parsed_fields.auth_result':'failure' } } } },
];

// ── Utilities ─────────────────────────────────────────────────────────────────

function flatSrc(src: Record<string, unknown>, prefix = ''): [string, string][] {
  const out: [string, string][] = [];
  for (const [k, v] of Object.entries(src)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) out.push(...flatSrc(v as Record<string, unknown>, key));
    else out.push([key, v === null ? 'null' : Array.isArray(v) ? JSON.stringify(v) : String(v)]);
  }
  return out;
}

function tryGenCode(index: string, dsl: string, lang: 'curl' | 'python' | 'js', host: string): string {
  let parsed: unknown;
  try { parsed = JSON.parse(dsl); } catch { return '// invalid DSL — fix JSON first'; }
  const payload = JSON.stringify({ index: index || undefined, dsl: parsed }, null, 2);
  if (lang === 'curl') return `curl -X POST "${host}/api/elastic/query" \\\n  -H "Content-Type: application/json" \\\n  -H "Cookie: session=<token>" \\\n  --data-raw '${payload}'`;
  if (lang === 'python') return `import requests, json\n\nresp = requests.post(\n    "${host}/api/elastic/query",\n    json=${payload},\n    cookies={"session": "<token>"},\n)\nprint(json.dumps(resp.json(), indent=2))`;
  return `const resp = await fetch("${host}/api/elastic/query", {\n  method: "POST",\n  headers: { "Content-Type": "application/json" },\n  credentials: "include",\n  body: JSON.stringify(${payload}),\n});\nconsole.log(await resp.json());`;
}

const CHART_COLORS = ['var(--accent)','var(--blue)','var(--green)','var(--orange)','var(--red)','var(--yellow)','#a855f7','#ec4899'];

function hColor(h: string) {
  return h === 'green' ? 'var(--green)' : h === 'yellow' ? 'var(--yellow)' : 'var(--red)';
}

// ── Sub-components ────────────────────────────────────────────────────────────

function HitRow({ hit, idx, hiddenCols, allCols }: {
  hit: ESHit; idx: number; hiddenCols: Set<string>; allCols: string[];
}) {
  const [open, setOpen]   = useState(false);
  const [json, setJson]   = useState(false);
  const [copied, setCopied] = useState(false);
  const flat = flatSrc(hit._source);
  const visibleCols = allCols.filter(c => !hiddenCols.has(c));
  const val = (col: string) => flat.find(([k]) => k === col)?.[1] ?? '';

  return (
    <div style={{ borderBottom:'1px solid var(--border)' }}>
      <button className="w-full text-left flex items-start gap-2 hover:bg-[var(--glass-hover)] transition-colors"
        style={{ minHeight:32 }} onClick={() => setOpen(o => !o)}>
        <span className="text-[10px] font-mono px-2 py-2 shrink-0 w-8 text-right" style={{ color:'var(--text-3)' }}>{idx+1}</span>
        <span className="mt-2 shrink-0">
          {open ? <ChevronDown className="h-3 w-3" style={{ color:'var(--text-3)' }} />
                : <ChevronRight className="h-3 w-3" style={{ color:'var(--text-3)' }} />}
        </span>
        <div className="flex items-center gap-3 flex-1 min-w-0 py-1.5 overflow-hidden">
          {visibleCols.slice(0,6).map(col => {
            const v = val(col);
            if (!v || v === 'undefined') return null;
            return (
              <span key={col} className="shrink-0 text-[11px] font-mono" style={{ color:'var(--text-2)' }}>
                {col === 'collected_at' ? new Date(v).toLocaleTimeString() : v.length > 40 ? v.slice(0,40)+'…' : v}
              </span>
            );
          })}
          {!visibleCols.length && (
            <span className="text-[11px] font-mono truncate" style={{ color:'var(--text-2)' }}>
              {String(hit._source.log_message ?? JSON.stringify(hit._source)).slice(0,120)}
            </span>
          )}
        </div>
        <span className="text-[10px] font-mono shrink-0 px-2 py-2" style={{ color:'var(--text-3)' }}>
          {hit._score.toFixed(2)}
        </span>
      </button>

      {open && (
        <div className="px-8 pb-3">
          <div className="rounded-xl overflow-hidden" style={{ border:'1px solid var(--border)' }}>
            <div className="flex items-center gap-2 px-3 py-2" style={{ background:'var(--glass-bg)', borderBottom:'1px solid var(--border)' }}>
              <span className="text-[10px] font-mono" style={{ color:'var(--text-3)' }}>{hit._index} · {hit._id}</span>
              <div className="flex gap-1 ml-auto">
                {(['Table','JSON'] as const).map(m => (
                  <button key={m} onClick={() => setJson(m==='JSON')}
                    className="text-[10px] px-2 py-0.5 rounded"
                    style={{ background:((m==='JSON')===json)?'var(--accent-glow)':'transparent', color:((m==='JSON')===json)?'var(--accent)':'var(--text-3)', border:`1px solid ${((m==='JSON')===json)?'var(--accent-border)':'transparent'}` }}>
                    {m}
                  </button>
                ))}
                <button onClick={() => { navigator.clipboard.writeText(JSON.stringify(hit._source, null, 2)); setCopied(true); setTimeout(()=>setCopied(false),1500); }}
                  className="text-[10px] px-2 py-0.5 rounded flex items-center gap-1"
                  style={{ background:'transparent', color:'var(--text-3)', border:'1px solid var(--border)' }}>
                  {copied ? <Check className="h-2.5 w-2.5" /> : <Copy className="h-2.5 w-2.5" />}
                </button>
              </div>
            </div>
            {json ? (
              <pre className="p-3 text-[10px] font-mono overflow-x-auto max-h-80 whitespace-pre-wrap break-all"
                style={{ color:'var(--text-1)' }}>
                {JSON.stringify(hit._source, null, 2)}
              </pre>
            ) : (
              <div className="grid grid-cols-2 gap-0 max-h-80 overflow-y-auto">
                {flat.map(([k,v],i) => (
                  <div key={k} className="flex items-start gap-2 px-3 py-1.5 text-[11px]"
                    style={{ background:i%2===0?'transparent':'rgba(255,255,255,0.01)', borderBottom:'1px solid var(--border)' }}>
                    <span className="font-mono shrink-0 w-40 truncate" style={{ color:'var(--text-3)' }} title={k}>{k}</span>
                    <span className="font-mono break-all" style={{ color:TYPE_COLOR[ECS_FIELDS.find(f=>f.path===k)?.type??''] ?? 'var(--text-1)' }}>{v}</span>
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
    <div className="p-4 space-y-5">
      {Object.entries(aggs).map(([name, agg]) => {
        const a = agg as Record<string, unknown>;
        if (Array.isArray(a?.buckets)) {
          const buckets = a.buckets as Array<{ key: unknown; key_as_string?: string; doc_count: number }>;
          const max = Math.max(...buckets.map(b => b.doc_count), 1);
          return (
            <div key={name}>
              <p className="text-xs font-semibold mb-2" style={{ color:'var(--text-2)' }}>{name}</p>
              <div className="space-y-1.5">
                {buckets.slice(0,20).map(b => (
                  <div key={String(b.key)} className="flex items-center gap-3">
                    <span className="text-[11px] font-mono w-36 shrink-0 truncate" style={{ color:'var(--text-2)' }}>
                      {String(b.key_as_string ?? b.key)}
                    </span>
                    <div className="flex-1 h-4 rounded overflow-hidden" style={{ background:'var(--bg-1)' }}>
                      <div className="h-full rounded" style={{ width:`${(b.doc_count/max)*100}%`, background:'var(--accent)' }} />
                    </div>
                    <span className="text-[11px] font-mono tabular-nums w-10 text-right shrink-0" style={{ color:'var(--text-1)' }}>
                      {b.doc_count.toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          );
        }
        if (typeof (a as Record<string,unknown>)?.value === 'number') {
          return (
            <div key={name} className="rounded-xl px-4 py-3 flex items-center justify-between"
              style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
              <span className="text-xs font-medium" style={{ color:'var(--text-2)' }}>{name}</span>
              <span className="text-lg font-bold tabular-nums" style={{ color:'var(--accent)' }}>
                {Number((a as Record<string,unknown>).value).toLocaleString()}
              </span>
            </div>
          );
        }
        return null;
      })}
    </div>
  );
}

function ChartView({ aggs }: { aggs: Record<string, unknown> }) {
  const [chartType, setChartType] = useState<'bar'|'pie'>('bar');
  const firstBucket = Object.values(aggs).find((a): a is Record<string,unknown> =>
    !!a && typeof a === 'object' && Array.isArray((a as Record<string,unknown>).buckets)
  );
  if (!firstBucket) {
    return <p className="text-sm text-center py-8" style={{ color:'var(--text-3)' }}>No bucket aggregations to chart</p>;
  }
  const buckets = firstBucket.buckets as Array<{ key: unknown; key_as_string?: string; doc_count: number }>;
  const data = buckets.slice(0,15).map(b => ({
    name: String(b.key_as_string ?? b.key).slice(0,20),
    value: b.doc_count,
  }));
  return (
    <div className="p-4">
      <div className="flex gap-2 mb-4">
        {(['bar','pie'] as const).map(t => (
          <button key={t} onClick={() => setChartType(t)}
            className="text-[11px] px-3 py-1 rounded-lg transition-colors"
            style={{ background:chartType===t?'var(--accent-glow)':'transparent', color:chartType===t?'var(--accent)':'var(--text-3)', border:`1px solid ${chartType===t?'var(--accent-border)':'var(--border)'}` }}>
            {t === 'bar' ? 'Bar Chart' : 'Pie Chart'}
          </button>
        ))}
      </div>
      <ResponsiveContainer width="100%" height={280}>
        {chartType === 'bar' ? (
          <BarChart data={data} margin={{ top:4, right:8, bottom:40, left:8 }}>
            <XAxis dataKey="name" tick={{ fontSize:9, fill:'var(--text-3)' }} angle={-35} textAnchor="end" interval={0} />
            <YAxis tick={{ fontSize:9, fill:'var(--text-3)' }} />
            <Tooltip contentStyle={{ background:'var(--bg-1)', border:'1px solid var(--border)', fontSize:11 }} />
            <Bar dataKey="value" radius={[3,3,0,0]}>
              {data.map((_, i) => <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />)}
            </Bar>
          </BarChart>
        ) : (
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={100}>
              {data.map((_, i) => <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />)}
            </Pie>
            <Tooltip contentStyle={{ background:'var(--bg-1)', border:'1px solid var(--border)', fontSize:11 }} />
          </PieChart>
        )}
      </ResponsiveContainer>
    </div>
  );
}

// ── Defaults ──────────────────────────────────────────────────────────────────

const DEFAULT_DSL = JSON.stringify(
  { query:{ match_all:{} }, sort:[{ collected_at:{ order:'desc' } }], size:20 },
  null, 2
);
const LS_SAVED = 'xcloak_es_saved_v2';

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ElasticQueryPage() {
  // Tabs
  const [tabs, setTabs] = useState<EditorTab[]>([{ id:'t1', name:'Query 1', index:'', dsl:DEFAULT_DSL }]);
  const [activeTabId, setActiveTabId] = useState('t1');
  const activeTab = tabs.find(t => t.id === activeTabId) ?? tabs[0];
  const updateTab = (id: string, patch: Partial<EditorTab>) =>
    setTabs(ts => ts.map(t => t.id === id ? { ...t, ...patch } : t));

  // Cluster
  const [indices,       setIndices]       = useState<ESIndex[]>([]);
  const [clusterStatus, setClusterStatus] = useState<Record<string,unknown>|null>(null);
  const [mapping,       setMapping]       = useState<Record<string,{type:string}>|null>(null);
  const [loadingMapping, setLoadingMapping] = useState(false);

  // Execution
  const [result,  setResult]  = useState<ESResult|null>(null);
  const [running, setRunning] = useState(false);
  const [error,   setError]   = useState('');
  const [history, setHistory] = useState<HistoryEntry[]>([]);

  // Results view
  const [resultTab,  setResultTab]  = useState<'hits'|'json'|'aggs'|'chart'>('hits');
  const [sortField,  setSortField]  = useState<string|null>(null);
  const [sortDir,    setSortDir]    = useState<'asc'|'desc'>('asc');
  const [hiddenCols, setHiddenCols] = useState<Set<string>>(new Set());
  const [showColMenu, setShowColMenu] = useState(false);

  // Sidebar
  const [sidebarTab,  setSidebarTab]  = useState<'library'|'fields'|'history'>('library');
  const [libFolder,   setLibFolder]   = useState('Threat Hunting');
  const [libSearch,   setLibSearch]   = useState('');
  const [fieldSearch, setFieldSearch] = useState('');

  // Save / saved queries
  const [savedQueries, setSavedQueries] = useState<SavedQuery[]>([]);
  const [showSave, setShowSave] = useState(false);
  const [saveName, setSaveName] = useState('');
  const [saveFolder, setSaveFolder] = useState('Personal');

  // Panels
  const [showAI,           setShowAI]           = useState(false);
  const [showRestAPI,      setShowRestAPI]      = useState(false);
  const [showExplain,      setShowExplain]      = useState(false);
  const [explainResult,    setExplainResult]    = useState<Record<string,unknown>|null>(null);
  const [showIndexExp,     setShowIndexExp]     = useState(false);
  const [showAggBuilder,   setShowAggBuilder]   = useState(false);

  // AI
  const [aiPrompt,  setAiPrompt]  = useState('');
  const [aiLoading, setAiLoading] = useState(false);
  const [aiDsl,     setAiDsl]     = useState('');
  const [aiExpl,    setAiExpl]    = useState('');

  // REST API
  const [restLang, setRestLang] = useState<'curl'|'python'|'js'>('curl');
  const [copied,   setCopied]   = useState(false);

  const host = typeof window !== 'undefined' ? window.location.origin : '';

  // ── Load metadata ──────────────────────────────────────────────────────────
  const loadMeta = useCallback(async () => {
    const [h, i] = await Promise.allSettled([elasticAPI.health(), elasticAPI.indices()]);
    if (h.status === 'fulfilled') setClusterStatus(h.value.data as Record<string,unknown>);
    if (i.status === 'fulfilled') {
      const idx: ESIndex[] = (i.value.data as { indices: ESIndex[] }).indices ?? [];
      setIndices(idx);
      if (!activeTab.index && idx.length) {
        const preferred = idx.find(x => x.index.startsWith('xcloak-logs-')) ?? idx[0];
        updateTab(activeTabId, { index: preferred.index });
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { loadMeta(); }, [loadMeta]);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(LS_SAVED);
      if (raw) setSavedQueries(JSON.parse(raw) as SavedQuery[]);
    } catch {}
  }, []);

  // Ctrl+Enter to run
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runQuery(); }
    };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab]);

  const loadMapping = async (index: string) => {
    if (!index) return;
    setLoadingMapping(true);
    try {
      const r = await elasticAPI.mapping(index);
      const d = r.data as { mapping?: { properties?: Record<string,{type:string}> } };
      setMapping(d.mapping?.properties ?? null);
    } catch {} finally { setLoadingMapping(false); }
  };

  // ── Run ────────────────────────────────────────────────────────────────────
  const runQuery = useCallback(async () => {
    let parsedDSL: unknown;
    try { parsedDSL = JSON.parse(activeTab.dsl); } catch { setError('Invalid JSON — fix DSL syntax'); return; }
    setRunning(true); setError(''); setResult(null);
    try {
      const res = await elasticAPI.query({ index: activeTab.index || undefined, dsl: parsedDSL });
      const data = res.data as ESResult;
      if (data.error) { setError(data.error); }
      else {
        setResult(data);
        const hasAggs = data.aggregations && Object.keys(data.aggregations).length > 0;
        setResultTab(hasAggs ? 'aggs' : 'hits');
        setHistory(prev => [{
          dsl: activeTab.dsl, index: activeTab.index,
          ts: new Date().toLocaleTimeString(),
          total: data.total, took: data.took,
        }, ...prev.slice(0,49)]);
      }
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { error?: string } }; message?: string })?.response?.data?.error
        ?? (e as { message?: string })?.message ?? 'Query failed';
      setError(msg);
    } finally { setRunning(false); }
  }, [activeTab]);

  // ── Format ─────────────────────────────────────────────────────────────────
  const formatDSL = () => {
    try { updateTab(activeTabId, { dsl: JSON.stringify(JSON.parse(activeTab.dsl), null, 2) }); } catch {}
  };

  const isValidDSL = useMemo(() => {
    try { JSON.parse(activeTab.dsl); return true; } catch { return false; }
  }, [activeTab.dsl]);

  // ── Explain ────────────────────────────────────────────────────────────────
  const runExplain = async () => {
    let dsl: unknown;
    try { dsl = JSON.parse(activeTab.dsl); } catch { return; }
    setShowExplain(true); setExplainResult(null);
    try {
      const r = await elasticAPI.explain({ index: activeTab.index, dsl });
      setExplainResult(r.data as Record<string,unknown>);
    } catch {}
  };

  // ── AI ─────────────────────────────────────────────────────────────────────
  const runAI = async () => {
    if (!aiPrompt.trim()) return;
    setAiLoading(true); setAiDsl(''); setAiExpl('');
    try {
      const r = await elasticAPI.aiQuery(aiPrompt);
      const d = r.data as { dsl: unknown; explanation?: string };
      setAiDsl(JSON.stringify(d.dsl, null, 2));
      setAiExpl(d.explanation ?? '');
    } catch { setAiDsl('// AI query failed'); } finally { setAiLoading(false); }
  };

  const acceptAiDsl = () => {
    updateTab(activeTabId, { dsl: aiDsl });
    setShowAI(false); setAiDsl(''); setAiPrompt('');
  };

  // ── Save ───────────────────────────────────────────────────────────────────
  const doSave = () => {
    if (!saveName.trim()) return;
    const q: SavedQuery = {
      id: Date.now().toString(), name: saveName.trim(),
      index: activeTab.index, dsl: activeTab.dsl,
      created_at: new Date().toISOString(), starred: false, folder: saveFolder,
    };
    const next = [q, ...savedQueries];
    setSavedQueries(next); localStorage.setItem(LS_SAVED, JSON.stringify(next));
    setShowSave(false); setSaveName('');
  };

  const toggleStar = (id: string) => {
    const next = savedQueries.map(q => q.id === id ? { ...q, starred: !q.starred } : q);
    setSavedQueries(next); localStorage.setItem(LS_SAVED, JSON.stringify(next));
  };

  const deleteSaved = (id: string) => {
    const next = savedQueries.filter(q => q.id !== id);
    setSavedQueries(next); localStorage.setItem(LS_SAVED, JSON.stringify(next));
  };

  // ── Tabs ───────────────────────────────────────────────────────────────────
  const addTab = () => {
    const id = `t${Date.now()}`;
    setTabs(ts => [...ts, { id, name:`Query ${ts.length+1}`, index:activeTab.index, dsl:DEFAULT_DSL }]);
    setActiveTabId(id);
  };
  const closeTab = (id: string) => {
    if (tabs.length === 1) return;
    const next = tabs.filter(t => t.id !== id);
    setTabs(next);
    if (activeTabId === id) setActiveTabId(next[next.length-1].id);
  };

  // ── Results derived ────────────────────────────────────────────────────────
  const hits = useMemo(() => {
    const h = result?.hits?.hits ?? [];
    if (!sortField) return h;
    return [...h].sort((a, b) => {
      const av = String(flatSrc(a._source).find(([k]) => k === sortField)?.[1] ?? '');
      const bv = String(flatSrc(b._source).find(([k]) => k === sortField)?.[1] ?? '');
      return sortDir === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av);
    });
  }, [result, sortField, sortDir]);

  const allCols = useMemo(() => {
    if (!hits.length) return [];
    const keys = new Set<string>();
    for (const h of hits.slice(0,20)) flatSrc(h._source).forEach(([k]) => keys.add(k));
    return [...keys].slice(0,16);
  }, [hits]);

  const aggs = result?.aggregations ?? null;

  // ── Export ─────────────────────────────────────────────────────────────────
  const exportData = (fmt: 'csv' | 'json') => {
    if (!result) return;
    const content = fmt === 'json'
      ? JSON.stringify(result.hits.hits, null, 2)
      : [
          ['_id','_index','_score',...allCols],
          ...hits.map(h => {
            const f = Object.fromEntries(flatSrc(h._source));
            return [h._id, h._index, String(h._score), ...allCols.map(c => f[c] ?? '')];
          }),
        ].map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(',')).join('\n');
    const blob = new Blob([content], { type: fmt === 'csv' ? 'text/csv' : 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = `es-results.${fmt}`; a.click();
    URL.revokeObjectURL(a.href);
  };

  // ── Filtered sidebar items ─────────────────────────────────────────────────
  const filteredLib = useMemo(() => {
    const byFolder = LIB.filter(q => q.folder === libFolder);
    return libSearch
      ? byFolder.filter(q => q.name.toLowerCase().includes(libSearch.toLowerCase()) || q.desc.toLowerCase().includes(libSearch.toLowerCase()))
      : byFolder;
  }, [libFolder, libSearch]);

  const filteredFields = useMemo(() =>
    fieldSearch
      ? ECS_FIELDS.filter(f => f.path.includes(fieldSearch.toLowerCase()) || f.desc.toLowerCase().includes(fieldSearch.toLowerCase()))
      : ECS_FIELDS,
  [fieldSearch]);

  const esNotConfigured = clusterStatus?.enabled === false || clusterStatus?.status === 'not_configured';
  const statusColor = esNotConfigured ? 'var(--text-3)'
    : (clusterStatus?.status === 'green') ? 'var(--green)'
    : (clusterStatus?.status === 'yellow') ? 'var(--yellow)'
    : clusterStatus ? 'var(--red)' : 'var(--text-3)';

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <RootLayout title="ES Query" subtitle="Elasticsearch · raw DSL · index explorer · AI assistant · aggregations">
      <div className="flex flex-col gap-4">

        {/* Top action bar */}
        <div className="g-card px-4 py-3 flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1.5 text-[11px] shrink-0">
            <span className="h-2 w-2 rounded-full" style={{ background: statusColor }} />
            <span style={{ color: statusColor }}>
              {esNotConfigured
                ? 'Elasticsearch not configured'
                : clusterStatus
                ? `${String(clusterStatus.cluster_name)} · ${String(clusterStatus.status)} · ${String(clusterStatus.number_of_nodes)}N`
                : 'Connecting…'}
            </span>
          </div>

          <select
            value={activeTab.index}
            onChange={e => { updateTab(activeTabId, { index: e.target.value }); loadMapping(e.target.value); }}
            className="g-select text-xs py-1 max-w-[220px]">
            <option value="">Auto (all indices)</option>
            {indices.map(i => <option key={i.index} value={i.index}>{i.index}</option>)}
          </select>

          <div className="flex-1" />

          <div className="flex items-center gap-2 flex-wrap">
            <button onClick={formatDSL} className="g-btn g-btn-ghost text-xs py-1">
              <Code2 className="h-3.5 w-3.5" /> Format
            </button>
            <button onClick={runExplain} disabled={!isValidDSL} className="g-btn g-btn-ghost text-xs py-1">
              <Lightbulb className="h-3.5 w-3.5" /> Explain
            </button>
            <button onClick={() => setShowAggBuilder(v => !v)} className="g-btn g-btn-ghost text-xs py-1">
              <Layers className="h-3.5 w-3.5" /> Agg Builder
            </button>
            <button onClick={() => { setShowSave(true); setSaveName(activeTab.name); }} className="g-btn g-btn-ghost text-xs py-1">
              <Save className="h-3.5 w-3.5" /> Save
            </button>
            <button onClick={() => setShowAI(v => !v)}
              className="g-btn text-xs py-1 px-3"
              style={{ background:showAI?'var(--accent-glow)':'var(--glass-bg)', color:showAI?'var(--accent)':'var(--text-2)', border:`1px solid ${showAI?'var(--accent-border)':'var(--border)'}` }}>
              <Bot className="h-3.5 w-3.5" /> AI Assist
            </button>
            <button onClick={runQuery} disabled={running || !isValidDSL} className="g-btn g-btn-primary text-xs px-4">
              {running
                ? <><RefreshCw className="h-3.5 w-3.5 animate-spin" /> Running…</>
                : <><Play className="h-3.5 w-3.5" /> Run <span className="opacity-60 text-[10px] ml-1">⌘↵</span></>}
            </button>
          </div>
        </div>

        {/* Editor tab strip */}
        <div className="flex items-center" style={{ borderBottom:'1px solid var(--border)' }}>
          {tabs.map(t => (
            <div key={t.id} className="flex items-center shrink-0"
              style={{ borderRight:'1px solid var(--border)', background:activeTabId===t.id?'var(--bg-1)':'transparent' }}>
              <button onClick={() => setActiveTabId(t.id)}
                className="text-[11px] px-4 py-2 flex items-center gap-1.5"
                style={{ color: activeTabId===t.id ? 'var(--accent)' : 'var(--text-3)' }}>
                {t.name}
                {!isValidDSL && activeTabId===t.id && <AlertCircle className="h-3 w-3" style={{ color: 'var(--red)' }} />}
              </button>
              {tabs.length > 1 && (
                <button onClick={e => { e.stopPropagation(); closeTab(t.id); }}
                  className="pr-2 hover:opacity-70" style={{ color:'var(--text-3)' }}>
                  <X className="h-3 w-3" />
                </button>
              )}
            </div>
          ))}
          <button onClick={addTab} className="px-3 py-2 hover:opacity-70" style={{ color:'var(--text-3)', fontSize: 16 }} title="New query tab">
            +
          </button>
        </div>

        {/* Main body: sidebar + editor area */}
        <div className="flex gap-4">

          {/* Sidebar */}
          <aside className="w-56 shrink-0 space-y-2">
            <div className="g-card flex overflow-hidden" style={{ padding:0 }}>
              {([
                ['library', 'Library',  BookOpen],
                ['fields',  'Fields',   Hash],
                ['history', 'History',  Clock],
              ] as const).map(([id, label, Icon]) => (
                <button key={id} onClick={() => setSidebarTab(id)}
                  className="flex-1 flex flex-col items-center py-2 text-[10px] font-medium transition-colors"
                  style={{
                    background: sidebarTab===id ? 'var(--accent-glow)' : 'transparent',
                    color:      sidebarTab===id ? 'var(--accent)' : 'var(--text-3)',
                    borderRight:'1px solid var(--border)',
                  }}>
                  <Icon className="h-3.5 w-3.5 mb-0.5" />
                  {label}
                </button>
              ))}
            </div>

            {/* Library tab */}
            {sidebarTab === 'library' && (
              <div className="g-card p-3 space-y-3" style={{ maxHeight:'65vh', overflow:'hidden', display:'flex', flexDirection:'column' }}>
                <input className="g-input text-xs py-1" placeholder="Search queries…"
                  value={libSearch} onChange={e => setLibSearch(e.target.value)} />
                <div className="flex flex-wrap gap-1">
                  {LIB_FOLDERS.map(f => (
                    <button key={f} onClick={() => setLibFolder(f)}
                      className="text-[9px] px-2 py-0.5 rounded-full transition-colors"
                      style={{ background:libFolder===f?'var(--accent)':'var(--glass-bg)', color:libFolder===f?'#000':'var(--text-3)', border:'1px solid var(--border)' }}>
                      {f}
                    </button>
                  ))}
                </div>
                <div className="space-y-1 overflow-y-auto flex-1">
                  {filteredLib.map(q => (
                    <button key={q.id}
                      onClick={() => updateTab(activeTabId, { dsl: q.dsl, name: q.name })}
                      className="w-full text-left px-2.5 py-2 rounded-lg hover:bg-[var(--glass-hover)] transition-colors">
                      <p className="text-[11px] font-medium leading-tight" style={{ color:'var(--text-1)' }}>{q.name}</p>
                      <p className="text-[10px] mt-0.5 leading-tight" style={{ color:'var(--text-3)' }}>{q.desc}</p>
                    </button>
                  ))}
                  {!filteredLib.length && (
                    <p className="text-[10px] text-center py-3" style={{ color:'var(--text-3)' }}>No queries found</p>
                  )}
                </div>
                {savedQueries.length > 0 && (
                  <div style={{ borderTop:'1px solid var(--border)', paddingTop:8 }}>
                    <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color:'var(--text-3)' }}>Saved</p>
                    {savedQueries.slice(0,8).map(q => (
                      <div key={q.id} className="group flex items-center gap-1 py-1">
                        <button onClick={() => toggleStar(q.id)} className="shrink-0">
                          {q.starred
                            ? <Star    className="h-3 w-3" style={{ color:'var(--yellow)' }} />
                            : <StarOff className="h-3 w-3" style={{ color:'var(--text-3)' }} />}
                        </button>
                        <button onClick={() => updateTab(activeTabId, { dsl:q.dsl, index:q.index, name:q.name })}
                          className="flex-1 text-left text-[10px] truncate hover:opacity-80" style={{ color:'var(--text-2)' }}>
                          {q.name}
                        </button>
                        <button onClick={() => deleteSaved(q.id)} className="opacity-0 group-hover:opacity-100 shrink-0">
                          <Trash2 className="h-3 w-3" style={{ color:'var(--red)' }} />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Fields tab */}
            {sidebarTab === 'fields' && (
              <div className="g-card p-3 space-y-2" style={{ maxHeight:'65vh', display:'flex', flexDirection:'column' }}>
                <input className="g-input text-xs py-1" placeholder="Search fields…"
                  value={fieldSearch} onChange={e => setFieldSearch(e.target.value)} />
                <div className="overflow-y-auto flex-1 space-y-0.5">
                  {filteredFields.map(f => (
                    <button key={f.path}
                      onClick={() => navigator.clipboard.writeText(f.path)}
                      title={`${f.desc} · Example: ${f.example}`}
                      className="w-full text-left px-2 py-1.5 rounded hover:bg-[var(--glass-hover)] transition-colors group">
                      <div className="flex items-center gap-1.5">
                        <span className="text-[9px] px-1 rounded shrink-0 font-mono"
                          style={{ background:`${TYPE_COLOR[f.type] ?? 'var(--text-3)'}22`, color:TYPE_COLOR[f.type]??'var(--text-3)', border:`1px solid ${TYPE_COLOR[f.type]??'var(--border)'}44` }}>
                          {f.type}
                        </span>
                        <span className="text-[10px] font-mono truncate" style={{ color:'var(--text-1)' }}>{f.path}</span>
                        <Copy className="h-2.5 w-2.5 opacity-0 group-hover:opacity-60 shrink-0 ml-auto" style={{ color:'var(--text-3)' }} />
                      </div>
                      <p className="text-[9px] pl-1 mt-0.5 truncate" style={{ color:'var(--text-3)' }}>{f.desc}</p>
                    </button>
                  ))}
                </div>
                {mapping && (
                  <div style={{ borderTop:'1px solid var(--border)', paddingTop:8 }}>
                    <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color:'var(--text-3)' }}>
                      {loadingMapping ? 'Loading mapping…' : 'Index Mapping'}
                    </p>
                    {Object.entries(mapping).slice(0,15).map(([k,v]) => (
                      <div key={k} className="flex items-center gap-2 text-[10px] py-0.5">
                        <span className="text-[8px] px-1 rounded shrink-0"
                          style={{ background:`${TYPE_COLOR[v.type]??'var(--text-3)'}22`, color:TYPE_COLOR[v.type]??'var(--text-3)' }}>
                          {v.type}
                        </span>
                        <span className="font-mono truncate" style={{ color:'var(--text-2)' }}>{k}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* History tab */}
            {sidebarTab === 'history' && (
              <div className="g-card p-2 space-y-1" style={{ maxHeight:'65vh', overflowY:'auto' }}>
                {!history.length && (
                  <p className="text-[10px] text-center py-4" style={{ color:'var(--text-3)' }}>Run a query to see history</p>
                )}
                {history.map((h, i) => (
                  <button key={i} onClick={() => updateTab(activeTabId, { dsl:h.dsl, index:h.index })}
                    className="w-full text-left px-2.5 py-2 rounded-lg hover:bg-[var(--glass-hover)] transition-colors">
                    <div className="flex items-center gap-2 mb-0.5">
                      <Clock className="h-3 w-3 shrink-0" style={{ color:'var(--text-3)' }} />
                      <span className="text-[10px]" style={{ color:'var(--text-3)' }}>{h.ts}</span>
                      <span className="text-[10px] ml-auto font-mono" style={{ color:'var(--accent)' }}>{h.took}ms</span>
                    </div>
                    <p className="text-[10px] font-mono truncate" style={{ color:'var(--text-2)' }}>
                      {h.dsl.replace(/\s+/g,' ').slice(0,60)}
                    </p>
                    <p className="text-[9px] mt-0.5" style={{ color:'var(--text-3)' }}>
                      {h.total.toLocaleString()} hits · {h.index || 'auto'}
                    </p>
                  </button>
                ))}
              </div>
            )}
          </aside>

          {/* Editor + results */}
          <div className="flex-1 min-w-0 space-y-4">

            {/* AI Assistant panel */}
            {showAI && (
              <div className="g-card p-4 space-y-3">
                <div className="flex items-center gap-2 mb-1">
                  <Bot className="h-4 w-4" style={{ color:'var(--accent)' }} />
                  <p className="text-xs font-semibold" style={{ color:'var(--text-1)' }}>AI Query Assistant</p>
                  <p className="text-[10px]" style={{ color:'var(--text-3)' }}>Describe what to find — AI generates ES DSL</p>
                  <button onClick={() => setShowAI(false)} className="ml-auto" style={{ color:'var(--text-3)' }}>
                    <X className="h-4 w-4" />
                  </button>
                </div>
                <div className="flex gap-2">
                  <input value={aiPrompt} onChange={e => setAiPrompt(e.target.value)}
                    onKeyDown={e => e.key==='Enter' && runAI()}
                    placeholder='e.g. "Find PowerShell attacks yesterday" or "LSASS access last 6h"'
                    className="g-input flex-1 text-sm" />
                  <button onClick={runAI} disabled={aiLoading || !aiPrompt.trim()} className="g-btn g-btn-primary px-4">
                    {aiLoading
                      ? <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                      : <><Wand2 className="h-3.5 w-3.5" /> Generate</>}
                  </button>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {[
                    'Find PowerShell attacks yesterday',
                    'Show users logging in from two countries',
                    'LSASS access attempts last 6h',
                    'C2 beaconing in last hour',
                    'Kerberoasting events',
                  ].map(ex => (
                    <button key={ex} onClick={() => setAiPrompt(ex)}
                      className="text-[10px] px-2.5 py-1 rounded-full"
                      style={{ background:'var(--glass-bg)', color:'var(--text-3)', border:'1px solid var(--border)' }}>
                      {ex}
                    </button>
                  ))}
                </div>
                {aiDsl && (
                  <div className="space-y-2">
                    {aiExpl && <p className="text-[11px] italic" style={{ color:'var(--text-3)' }}>{aiExpl}</p>}
                    <pre className="rounded-xl p-3 text-[11px] font-mono overflow-x-auto max-h-52 whitespace-pre-wrap"
                      style={{ background:'var(--bg-0)', border:'1px solid var(--border)', color:'var(--text-1)' }}>
                      {aiDsl}
                    </pre>
                    <div className="flex gap-2">
                      <button onClick={acceptAiDsl} className="g-btn g-btn-primary text-xs">
                        <Check className="h-3.5 w-3.5" /> Use this DSL
                      </button>
                      <button onClick={() => { acceptAiDsl(); setTimeout(runQuery, 50); }} className="g-btn g-btn-ghost text-xs">
                        <Play className="h-3.5 w-3.5" /> Use &amp; Run
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Agg Builder */}
            {showAggBuilder && (
              <div className="g-card p-4">
                <div className="flex items-center gap-2 mb-3">
                  <Layers className="h-3.5 w-3.5" style={{ color:'var(--accent)' }} />
                  <p className="text-xs font-semibold" style={{ color:'var(--text-1)' }}>Aggregation Builder</p>
                  <button onClick={() => setShowAggBuilder(false)} className="ml-auto" style={{ color:'var(--text-3)' }}>
                    <X className="h-4 w-4" />
                  </button>
                </div>
                <div className="grid grid-cols-3 gap-2">
                  {AGG_TEMPLATES.map(a => (
                    <button key={a.key}
                      onClick={() => {
                        try {
                          const parsed = JSON.parse(activeTab.dsl);
                          parsed.aggs = { ...(parsed.aggs ?? {}), [a.key]: a.agg };
                          updateTab(activeTabId, { dsl: JSON.stringify(parsed, null, 2) });
                        } catch {}
                        setShowAggBuilder(false);
                      }}
                      className="text-left px-3 py-2.5 rounded-xl hover:opacity-80 transition-opacity"
                      style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                      <p className="text-[11px] font-medium" style={{ color:'var(--text-1)' }}>{a.name}</p>
                      <p className="text-[9px] font-mono mt-0.5 truncate" style={{ color:'var(--text-3)' }}>{a.key}</p>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* DSL Editor */}
            <div className="g-card overflow-hidden">
              <div className="flex items-center gap-2 px-4 py-2" style={{ borderBottom:'1px solid var(--border)' }}>
                <Code2 className="h-3.5 w-3.5" style={{ color:'var(--text-3)' }} />
                <span className="text-[11px] font-medium" style={{ color:'var(--text-2)' }}>Elasticsearch DSL</span>
                {!isValidDSL && (
                  <span className="text-[10px] px-2 py-0.5 rounded"
                    style={{ background:'rgba(248,81,73,0.1)', color:'var(--red)', border:'1px solid rgba(248,81,73,0.3)' }}>
                    Invalid JSON
                  </span>
                )}
                <div className="flex-1" />
                <button onClick={() => { navigator.clipboard.writeText(activeTab.dsl); setCopied(true); setTimeout(()=>setCopied(false),1500); }}
                  className="g-btn g-btn-ghost text-[10px] py-0.5 px-2">
                  {copied ? <><Check className="h-3 w-3" /> Copied</> : <><Copy className="h-3 w-3" /> Copy</>}
                </button>
                <button onClick={() => updateTab(activeTabId, { dsl: DEFAULT_DSL })}
                  className="g-btn g-btn-ghost text-[10px] py-0.5 px-2" title="Reset to default">
                  <RotateCcw className="h-3 w-3" />
                </button>
              </div>
              <textarea
                value={activeTab.dsl}
                onChange={e => updateTab(activeTabId, { dsl: e.target.value })}
                spellCheck={false}
                className="w-full font-mono text-xs resize-none"
                style={{ minHeight:280, background:'var(--bg-0)', color:'var(--text-1)', padding:'12px 16px', outline:'none', border:'none', lineHeight:1.6 }}
              />
            </div>

            {/* Error */}
            {error && (
              <div className="flex items-start gap-2 px-4 py-3 rounded-xl text-xs"
                style={{ background:'rgba(248,81,73,0.08)', color:'var(--red)', border:'1px solid rgba(248,81,73,0.25)' }}>
                <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                <p className="font-mono">{error}</p>
              </div>
            )}

            {/* Results */}
            {result && !result.error && (
              <div className="g-card overflow-hidden">
                {/* Stats bar */}
                <div className="flex flex-wrap items-center gap-4 px-4 py-2.5"
                  style={{ borderBottom:'1px solid var(--border)', background:'var(--glass-bg)' }}>
                  {[
                    { label:'Hits',    val:`${result.total.toLocaleString()} (${result.hits.hits.length} shown)` },
                    { label:'Time',    val:`${result.took}ms`, color:'var(--accent)' },
                    { label:'Shards',  val:`${result._shards?.successful ?? '?'}/${result._shards?.total ?? '?'}` },
                    { label:'Timeout', val:result.timed_out ? 'YES' : 'No', color:result.timed_out?'var(--red)':undefined },
                  ].map(s => (
                    <div key={s.label} className="flex items-center gap-1.5 text-[11px]">
                      <span style={{ color:'var(--text-3)' }}>{s.label}:</span>
                      <span className="font-mono font-semibold" style={{ color:s.color??'var(--text-1)' }}>{s.val}</span>
                    </div>
                  ))}
                  <div className="flex-1" />
                  <button onClick={() => setShowRestAPI(true)} className="g-btn g-btn-ghost text-[10px] py-1">
                    <Terminal className="h-3 w-3" /> API Code
                  </button>
                  <button onClick={() => exportData('csv')} className="g-btn g-btn-ghost text-[10px] py-1">
                    <Download className="h-3 w-3" /> CSV
                  </button>
                  <button onClick={() => exportData('json')} className="g-btn g-btn-ghost text-[10px] py-1">
                    <FileJson className="h-3 w-3" /> JSON
                  </button>
                </div>

                {/* Result tabs */}
                <div className="flex items-center justify-between px-4" style={{ borderBottom:'1px solid var(--border)' }}>
                  <div className="flex">
                    {([
                      { id:'hits',  label:'Hits',        Icon:Table2,     count:hits.length },
                      { id:'json',  label:'Raw JSON',     Icon:Braces,     count:0 },
                      { id:'aggs',  label:'Aggregations', Icon:Activity,   count:aggs?Object.keys(aggs).length:0 },
                      { id:'chart', label:'Chart',        Icon:DatabaseZap, count:0 },
                    ] as const).map(t => (
                      <button key={t.id} onClick={() => setResultTab(t.id)}
                        className="flex items-center gap-1.5 px-4 py-2.5 text-[11px] font-medium border-b-2 transition-colors"
                        style={{ borderColor:resultTab===t.id?'var(--accent)':'transparent', color:resultTab===t.id?'var(--accent)':'var(--text-3)' }}>
                        <t.Icon className="h-3.5 w-3.5" />
                        {t.label}
                        {t.count > 0 && <span className="text-[9px] opacity-60">{t.count}</span>}
                      </button>
                    ))}
                  </div>
                  {resultTab === 'hits' && (
                    <button onClick={() => setShowColMenu(v => !v)} className="g-btn g-btn-ghost text-[10px] py-1 mr-2">
                      <Filter className="h-3 w-3" /> Columns
                    </button>
                  )}
                </div>

                {/* Column chooser */}
                {showColMenu && resultTab === 'hits' && (
                  <div className="flex flex-wrap gap-2 px-4 py-3" style={{ borderBottom:'1px solid var(--border)', background:'var(--glass-bg)' }}>
                    {allCols.map(col => (
                      <button key={col}
                        onClick={() => setHiddenCols(s => { const n=new Set(s); n.has(col)?n.delete(col):n.add(col); return n; })}
                        className="text-[10px] px-2 py-0.5 rounded-full font-mono transition-colors"
                        style={{ background:hiddenCols.has(col)?'var(--glass-bg)':'var(--accent-glow)', color:hiddenCols.has(col)?'var(--text-3)':'var(--accent)', border:`1px solid ${hiddenCols.has(col)?'var(--border)':'var(--accent-border)'}`, opacity:hiddenCols.has(col)?0.5:1 }}>
                        {col}
                      </button>
                    ))}
                    <button onClick={() => setHiddenCols(new Set())} className="text-[10px] px-2 py-0.5 underline" style={{ color:'var(--text-3)' }}>
                      Show all
                    </button>
                  </div>
                )}

                {/* Results body */}
                <div className="max-h-[520px] overflow-y-auto">
                  {resultTab === 'hits' && !hits.length && (
                    <div className="py-16 text-center">
                      <Database className="h-8 w-8 mx-auto mb-2 opacity-20" style={{ color:'var(--text-3)' }} />
                      <p className="text-sm" style={{ color:'var(--text-3)' }}>No documents matched</p>
                    </div>
                  )}
                  {resultTab === 'hits' && hits.length > 0 && (
                    <>
                      <div className="flex items-center gap-2 px-4 py-1.5 sticky top-0"
                        style={{ background:'var(--bg-1)', borderBottom:'1px solid var(--border)', zIndex:5 }}>
                        <span className="w-8 shrink-0" />
                        <span className="w-3 shrink-0" />
                        {allCols.filter(c => !hiddenCols.has(c)).slice(0,6).map(col => (
                          <button key={col}
                            onClick={() => { if (sortField===col) setSortDir(d => d==='asc'?'desc':'asc'); else { setSortField(col); setSortDir('asc'); } }}
                            className="flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider shrink-0"
                            style={{ color:sortField===col?'var(--accent)':'var(--text-3)' }}>
                            {col.split('.').pop()}
                            <ArrowUpDown className="h-2.5 w-2.5 opacity-60" />
                          </button>
                        ))}
                        <span className="ml-auto text-[10px] shrink-0" style={{ color:'var(--text-3)' }}>_score</span>
                      </div>
                      {hits.map((h, i) => (
                        <HitRow key={`${h._id}-${i}`} hit={h} idx={i}
                          hiddenCols={hiddenCols} allCols={allCols} />
                      ))}
                    </>
                  )}
                  {resultTab === 'json' && (
                    <pre className="p-4 text-[11px] font-mono overflow-x-auto" style={{ color:'var(--text-1)' }}>
                      {JSON.stringify(result, null, 2)}
                    </pre>
                  )}
                  {resultTab === 'aggs' && aggs && <AggsView aggs={aggs} />}
                  {resultTab === 'aggs' && !aggs && (
                    <div className="py-12 text-center">
                      <Activity className="h-8 w-8 mx-auto mb-2 opacity-20" style={{ color:'var(--text-3)' }} />
                      <p className="text-sm" style={{ color:'var(--text-3)' }}>Add an <code className="font-mono">aggs</code> block to your DSL</p>
                    </div>
                  )}
                  {resultTab === 'chart' && aggs && <ChartView aggs={aggs} />}
                  {resultTab === 'chart' && !aggs && (
                    <div className="py-12 text-center">
                      <DatabaseZap className="h-8 w-8 mx-auto mb-2 opacity-20" style={{ color:'var(--text-3)' }} />
                      <p className="text-sm" style={{ color:'var(--text-3)' }}>No aggregations available to chart</p>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Index Explorer */}
        <div className="g-card overflow-hidden">
          <button className="w-full flex items-center gap-2 px-4 py-3 hover:bg-[var(--glass-hover)] transition-colors"
            onClick={() => setShowIndexExp(v => !v)}>
            <Server className="h-3.5 w-3.5" style={{ color:'var(--text-3)' }} />
            <span className="text-xs font-semibold" style={{ color:'var(--text-2)' }}>
              Index Explorer ({indices.length} indices)
            </span>
            <div className="flex-1" />
            {showIndexExp
              ? <ChevronUp   className="h-3.5 w-3.5" style={{ color:'var(--text-3)' }} />
              : <ChevronDown className="h-3.5 w-3.5" style={{ color:'var(--text-3)' }} />}
          </button>
          {showIndexExp && (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr style={{ borderTop:'1px solid var(--border)', borderBottom:'1px solid var(--border)' }}>
                    {['Health','Index','Status','Docs','Size','Pri','Rep',''].map(h => (
                      <th key={h} className="text-left px-4 py-2 text-[10px] font-semibold uppercase tracking-wider"
                        style={{ color:'var(--text-3)' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {indices.map(idx => (
                    <tr key={idx.index} className="hover:bg-[rgba(255,255,255,0.02)] transition-colors"
                      style={{ borderBottom:'1px solid var(--border)' }}>
                      <td className="px-4 py-2.5">
                        <span className="h-2 w-2 rounded-full inline-block" style={{ background:hColor(idx.health) }} />
                      </td>
                      <td className="px-4 py-2.5 font-mono" style={{ color:'var(--accent)' }}>{idx.index}</td>
                      <td className="px-4 py-2.5">
                        <span className="text-[10px] px-1.5 py-0.5 rounded"
                          style={{ background:'var(--glass-bg)', color:'var(--text-3)', border:'1px solid var(--border)' }}>
                          {idx.status || 'open'}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 tabular-nums" style={{ color:'var(--text-2)' }}>
                        {Number(idx.docs_count || 0).toLocaleString()}
                      </td>
                      <td className="px-4 py-2.5" style={{ color:'var(--text-2)' }}>{idx.store_size}</td>
                      <td className="px-4 py-2.5" style={{ color:'var(--text-3)' }}>{idx.pri ?? '—'}</td>
                      <td className="px-4 py-2.5" style={{ color:'var(--text-3)' }}>{idx.rep ?? '—'}</td>
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => { updateTab(activeTabId, { index:idx.index }); loadMapping(idx.index); setSidebarTab('fields'); }}
                            className="text-[10px] px-2 py-0.5 rounded transition-colors"
                            style={{ background:activeTab.index===idx.index?'var(--accent-glow)':'var(--glass-bg)', color:activeTab.index===idx.index?'var(--accent)':'var(--text-3)', border:`1px solid ${activeTab.index===idx.index?'var(--accent-border)':'var(--border)'}` }}>
                            {activeTab.index===idx.index ? 'selected' : 'use'}
                          </button>
                          <button onClick={() => loadMapping(idx.index)}
                            className="text-[10px] px-2 py-0.5 rounded"
                            style={{ background:'var(--glass-bg)', color:'var(--text-3)', border:'1px solid var(--border)' }}>
                            mapping
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Save modal */}
      {showSave && (
        <div className="g-modal-backdrop" onClick={() => setShowSave(false)}>
          <div className="g-modal" style={{ maxWidth:400 }} onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom:'1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color:'var(--text-1)' }}>Save Query</h2>
              <button onClick={() => setShowSave(false)}><X className="h-4 w-4" style={{ color:'var(--text-3)' }} /></button>
            </div>
            <div className="p-5 space-y-3">
              <div>
                <label className="text-xs mb-1 block" style={{ color:'var(--text-3)' }}>Name</label>
                <input autoFocus value={saveName} onChange={e => setSaveName(e.target.value)}
                  onKeyDown={e => e.key==='Enter' && doSave()}
                  placeholder="e.g. SSH Brute Force Hunt" className="g-input w-full" />
              </div>
              <div>
                <label className="text-xs mb-1 block" style={{ color:'var(--text-3)' }}>Folder</label>
                <select value={saveFolder} onChange={e => setSaveFolder(e.target.value)} className="g-select w-full text-xs">
                  {['Personal','Threat Hunting','Incident Response','Detection Engineering','Compliance','Daily','Shared'].map(f => (
                    <option key={f}>{f}</option>
                  ))}
                </select>
              </div>
              <p className="text-[11px]" style={{ color:'var(--text-3)' }}>Saved to browser localStorage.</p>
            </div>
            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => setShowSave(false)} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={doSave} disabled={!saveName.trim()} className="g-btn g-btn-primary flex-1 justify-center">
                <Save className="h-3.5 w-3.5" /> Save
              </button>
            </div>
          </div>
        </div>
      )}

      {/* REST API Generator modal */}
      {showRestAPI && (
        <div className="g-modal-backdrop" onClick={() => setShowRestAPI(false)}>
          <div className="g-modal" style={{ maxWidth:620 }} onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-5 py-4" style={{ borderBottom:'1px solid var(--border)' }}>
              <div className="flex items-center gap-2">
                <Terminal className="h-4 w-4" style={{ color:'var(--accent)' }} />
                <h2 className="text-sm font-semibold" style={{ color:'var(--text-1)' }}>REST API Code Generator</h2>
              </div>
              <button onClick={() => setShowRestAPI(false)}><X className="h-4 w-4" style={{ color:'var(--text-3)' }} /></button>
            </div>
            <div className="p-5 space-y-4">
              <div className="flex gap-2">
                {(['curl','python','js'] as const).map(l => (
                  <button key={l} onClick={() => setRestLang(l)}
                    className="text-xs px-3 py-1 rounded-lg transition-colors"
                    style={{ background:restLang===l?'var(--accent)':'var(--glass-bg)', color:restLang===l?'#000':'var(--text-2)', border:'1px solid var(--border)' }}>
                    {l === 'js' ? 'JavaScript' : l === 'python' ? 'Python' : 'cURL'}
                  </button>
                ))}
              </div>
              <div className="relative group">
                <pre className="rounded-xl p-4 text-[11px] font-mono overflow-x-auto max-h-80 whitespace-pre-wrap break-all"
                  style={{ background:'var(--bg-0)', border:'1px solid var(--border)', color:'var(--text-1)' }}>
                  {tryGenCode(activeTab.index, activeTab.dsl, restLang, host)}
                </pre>
                <button
                  onClick={() => { navigator.clipboard.writeText(tryGenCode(activeTab.index,activeTab.dsl,restLang,host)); setCopied(true); setTimeout(()=>setCopied(false),1500); }}
                  className="absolute top-2 right-2 p-1.5 rounded opacity-0 group-hover:opacity-100 transition-opacity"
                  style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                  {copied
                    ? <Check className="h-3.5 w-3.5" style={{ color:'var(--green)' }} />
                    : <Copy  className="h-3.5 w-3.5" style={{ color:'var(--text-3)' }} />}
                </button>
              </div>
              <p className="text-[11px]" style={{ color:'var(--text-3)' }}>Replace the session token with your actual auth cookie or API key.</p>
            </div>
          </div>
        </div>
      )}

      {/* Explain modal */}
      {showExplain && (
        <div className="g-modal-backdrop" onClick={() => setShowExplain(false)}>
          <div className="g-modal" style={{ maxWidth:560 }} onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-5 py-4" style={{ borderBottom:'1px solid var(--border)' }}>
              <div className="flex items-center gap-2">
                <Lightbulb className="h-4 w-4" style={{ color:'var(--yellow)' }} />
                <h2 className="text-sm font-semibold" style={{ color:'var(--text-1)' }}>Query Explain</h2>
              </div>
              <button onClick={() => setShowExplain(false)}><X className="h-4 w-4" style={{ color:'var(--text-3)' }} /></button>
            </div>
            {!explainResult ? (
              <div className="py-10 text-center">
                <RefreshCw className="h-5 w-5 animate-spin mx-auto" style={{ color:'var(--text-3)' }} />
              </div>
            ) : (
              <div className="p-5 space-y-4 overflow-y-auto max-h-[70vh]">
                {([
                  ['Parsed Query',   JSON.stringify(explainResult.parsed_query, null, 2)],
                  ['Execution Plan', String(explainResult.execution_plan ?? '')],
                  ['Scoring',        String(explainResult.scoring ?? '')],
                  ['Analyzer',       String(explainResult.analyzer ?? '')],
                  ['Optimizations',  (Array.isArray(explainResult.optimizations) ? explainResult.optimizations : []).join('\n')],
                ] as [string,string][]).map(([label, val]) => (
                  <div key={label}>
                    <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color:'var(--text-3)' }}>{label}</p>
                    <pre className="rounded-xl p-3 text-[11px] font-mono whitespace-pre-wrap break-all overflow-x-auto"
                      style={{ background:'var(--bg-0)', border:'1px solid var(--border)', color:'var(--text-1)' }}>
                      {val}
                    </pre>
                  </div>
                ))}
                {typeof explainResult.cost_estimate === 'object' && explainResult.cost_estimate !== null && (
                  <div className="grid grid-cols-3 gap-3">
                    {[
                      { label:'Docs Scanned',   val:String((explainResult.cost_estimate as Record<string,unknown>).docs_scanned ?? '?') },
                      { label:'Shards Queried', val:String((explainResult.cost_estimate as Record<string,unknown>).shards_queried ?? '?') },
                      { label:'Est. Time',      val:`${String((explainResult.cost_estimate as Record<string,unknown>).estimated_ms ?? '?')}ms` },
                    ].map(s => (
                      <div key={s.label} className="rounded-xl px-3 py-2.5 text-center"
                        style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                        <p className="text-[10px]" style={{ color:'var(--text-3)' }}>{s.label}</p>
                        <p className="text-base font-bold tabular-nums" style={{ color:'var(--accent)' }}>{s.val}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </RootLayout>
  );
}
