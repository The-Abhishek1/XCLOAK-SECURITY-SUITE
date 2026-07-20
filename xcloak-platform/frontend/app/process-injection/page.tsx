'use client';
import { useState, useEffect, useRef } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { processInjectionAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';

type Tab = 'overview' | 'processes' | 'memory' | 'api' | 'intelligence' | 'analytics' | 'response';

const TAB_LABELS: Record<Tab, string> = {
  overview:     'Overview',
  processes:    'Processes',
  memory:       'Memory & Modules',
  api:          'API Monitor',
  intelligence: 'Intelligence',
  analytics:    'Analytics',
  response:     'Response',
};

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  info:     '#3b82f6',
};

const RISK_COLOR = (score: number) =>
  score >= 80 ? '#ef4444' : score >= 60 ? '#f97316' : score >= 40 ? '#eab308' : '#22c55e';

// ── Overview ─────────────────────────────────────────────────────────────────
function OverviewTab({ dash }: { dash: any }) {
  if (!dash) return <div style={{ color: 'var(--text-3)', padding: '2rem' }}>Loading…</div>;
  const cards = [
    { label: 'Injection Alerts',       value: dash.injection_alerts,     color: '#ef4444' },
    { label: 'Active Injections',      value: dash.active_injections,    color: '#f97316' },
    { label: 'Suspicious Processes',   value: dash.suspicious_processes, color: '#eab308' },
    { label: 'Protected Processes',    value: dash.protected_processes,  color: '#22c55e' },
    { label: 'Memory Modifications',   value: dash.memory_modifications, color: '#f97316' },
    { label: 'High-Risk Hosts',        value: dash.high_risk_hosts,      color: '#ef4444' },
    { label: 'Detection Coverage',     value: `${dash.detection_coverage}%`, color: '#3b82f6' },
  ];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(180px,1fr))', gap: '1rem' }}>
        {cards.map(c => (
          <div key={c.label} className="g-card" style={{ padding: '1.25rem', borderTop: `3px solid ${c.color}` }}>
            <div style={{ fontSize: '2rem', fontWeight: 700, color: c.color }}>{c.value}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-3)', marginTop: '0.25rem' }}>{c.label}</div>
          </div>
        ))}
      </div>
      <div className="g-card" style={{ padding: '1.25rem' }}>
        <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Injection Technique Coverage</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
          {(dash.injection_types || []).map((t: string) => (
            <span key={t} style={{
              background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
              color: '#ef4444', borderRadius: '4px', padding: '0.25rem 0.6rem', fontSize: '0.75rem',
            }}>{t}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Processes ─────────────────────────────────────────────────────────────────
function ProcessesTab() {
  const [processes, setProcesses] = useState<any[]>([]);
  const [tree, setTree] = useState<any[]>([]);
  const [view, setView] = useState<'list' | 'tree'>('list');
  const [selected, setSelected] = useState<any>(null);
  const [suspicious, setSuspicious] = useState(false);

  useEffect(() => {
    processInjectionAPI.getProcesses(suspicious ? { suspicious: 'true' } : undefined).then(r => setProcesses(r.data || []));
    processInjectionAPI.getProcessTree().then(r => setTree(r.data || []));
  }, [suspicious]);

  const buildTree = (nodes: any[]) => {
    const map: Record<number, any> = {};
    nodes.forEach(n => { map[n.pid] = { ...n, childNodes: [] }; });
    const roots: any[] = [];
    nodes.forEach(n => {
      if (map[n.ppid] && n.ppid !== n.pid) map[n.ppid].childNodes.push(map[n.pid]);
      else roots.push(map[n.pid]);
    });
    return roots;
  };

  const renderNode = (node: any, depth = 0): React.ReactNode => (
    <div key={node.pid} style={{ marginLeft: `${depth * 1.5}rem` }}>
      <div
        onClick={() => setSelected(node)}
        style={{
          padding: '0.4rem 0.75rem', marginBottom: '2px', borderRadius: '4px', cursor: 'pointer',
          background: selected?.pid === node.pid ? 'rgba(99,102,241,0.15)' : 'transparent',
          border: `1px solid ${node.risk_score > 60 ? 'rgba(239,68,68,0.4)' : 'transparent'}`,
          display: 'flex', alignItems: 'center', gap: '0.5rem',
        }}
      >
        <span style={{ color: RISK_COLOR(node.risk_score), fontFamily: 'monospace', fontSize: '0.8rem' }}>
          [{node.pid.toString().padStart(5)}]
        </span>
        <span style={{ fontWeight: node.risk_score > 60 ? 600 : 400 }}>{node.name}</span>
        {node.risk_score > 60 && (
          <span style={{ fontSize: '0.7rem', background: '#ef4444', color: '#fff', borderRadius: '3px', padding: '1px 5px', marginLeft: 'auto' }}>
            RISK {node.risk_score}
          </span>
        )}
      </div>
      {(node.childNodes || []).map((c: any) => renderNode(c, depth + 1))}
    </div>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
        {(['list', 'tree'] as const).map(v => (
          <button key={v} className={`g-btn ${view === v ? 'g-btn-primary' : 'g-btn-ghost'}`}
            onClick={() => setView(v)}>
            {v === 'list' ? 'Process List' : 'Process Tree'}
          </button>
        ))}
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginLeft: 'auto', cursor: 'pointer', fontSize: '0.85rem' }}>
          <input type="checkbox" checked={suspicious} onChange={e => setSuspicious(e.target.checked)} />
          Suspicious only
        </label>
      </div>

      <div style={{ display: 'flex', gap: '1rem' }}>
        <div className="g-card" style={{ flex: 1, overflowX: 'auto', padding: 0 }}>
          {view === 'list' ? (
            <table className="g-table" style={{ width: '100%' }}>
              <thead className="g-thead">
                <tr>
                  <th className="g-tr">PID</th><th className="g-tr">Name</th>
                  <th className="g-tr">PPID</th><th className="g-tr">User</th>
                  <th className="g-tr">Integrity</th><th className="g-tr">Risk</th>
                  <th className="g-tr">Command</th>
                </tr>
              </thead>
              <tbody>
                {processes.map(p => (
                  <tr key={p.id} onClick={() => setSelected(p)} style={{ cursor: 'pointer', background: selected?.id === p.id ? 'rgba(99,102,241,0.1)' : undefined }}>
                    <td className="g-tr" style={{ fontFamily: 'monospace', color: 'var(--text-3)' }}>{p.pid}</td>
                    <td className="g-tr" style={{ fontWeight: p.risk_score > 60 ? 600 : 400, color: p.risk_score > 80 ? '#ef4444' : undefined }}>{p.name}</td>
                    <td className="g-tr" style={{ fontFamily: 'monospace', color: 'var(--text-3)' }}>{p.ppid}</td>
                    <td className="g-tr" style={{ fontSize: '0.8rem' }}>{p.username}</td>
                    <td className="g-tr">
                      <span style={{ fontSize: '0.75rem', padding: '2px 6px', borderRadius: '3px',
                        background: p.integrity_level === 'System' ? 'rgba(239,68,68,0.1)' : 'rgba(99,102,241,0.1)',
                        color: p.integrity_level === 'System' ? '#ef4444' : '#818cf8' }}>
                        {p.integrity_level}
                      </span>
                    </td>
                    <td className="g-tr">
                      <span style={{ display: 'inline-block', width: '4rem', height: '6px', borderRadius: '3px',
                        background: `linear-gradient(to right, ${RISK_COLOR(p.risk_score)} ${p.risk_score}%, rgba(255,255,255,0.1) 0%)` }} />
                      <span style={{ marginLeft: '0.4rem', fontSize: '0.8rem', color: RISK_COLOR(p.risk_score) }}>{p.risk_score}</span>
                    </td>
                    <td className="g-tr" style={{ fontFamily: 'monospace', fontSize: '0.72rem', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.cmdline}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div style={{ padding: '1rem', fontFamily: 'monospace', fontSize: '0.82rem' }}>
              {buildTree(tree).map(n => renderNode(n))}
            </div>
          )}
        </div>

        {selected && (
          <div className="g-card" style={{ width: '320px', padding: '1rem', fontSize: '0.82rem', flexShrink: 0 }}>
            <div style={{ fontWeight: 600, marginBottom: '0.75rem', color: 'var(--accent)' }}>
              {selected.name} ({selected.pid})
            </div>
            {([
              ['PID', selected.pid], ['PPID', selected.ppid],
              ['Username', selected.username], ['Integrity', selected.integrity_level],
              ['Risk Score', selected.risk_score], ['SHA256', selected.sha256],
              ['Signature', selected.signature || 'Unsigned'],
              ['Started', selected.start_time ? timeAgo(selected.start_time) : '—'],
              ['Path', selected.path],
            ] as [string, any][]).map(([k, v]) => (
              <div key={k} style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.35rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.35rem' }}>
                <span style={{ color: 'var(--text-3)', minWidth: '80px' }}>{k}</span>
                <span style={{ wordBreak: 'break-all', color: k === 'Risk Score' ? RISK_COLOR(Number(v)) : undefined, fontWeight: k === 'Risk Score' ? 600 : undefined }}>{v}</span>
              </div>
            ))}
            {selected.cmdline && (
              <div style={{ marginTop: '0.5rem', background: 'rgba(0,0,0,0.3)', padding: '0.5rem', borderRadius: '4px', fontSize: '0.72rem', wordBreak: 'break-all' }}>
                {selected.cmdline}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Memory & Modules ──────────────────────────────────────────────────────────
function MemoryTab() {
  const [memData, setMemData] = useState<any>(null);
  const [modules, setModules] = useState<any>(null);
  const [view, setView] = useState<'memory' | 'modules'>('memory');

  useEffect(() => {
    processInjectionAPI.getMemory().then(r => setMemData(r.data));
    processInjectionAPI.getModules().then(r => setModules(r.data));
  }, []);

  const regions = memData?.regions || [];
  const mods = modules?.modules || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      {memData && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: '0.75rem' }}>
          {[
            { label: 'RWX Pages',        value: memData.rwx_pages, color: '#ef4444' },
            { label: 'Shellcode Regions', value: memData.shellcode,  color: '#f97316' },
            { label: 'Unbacked Regions',  value: memData.unbacked,  color: '#eab308' },
          ].map(c => (
            <div key={c.label} className="g-card" style={{ padding: '1rem', textAlign: 'center', borderTop: `2px solid ${c.color}` }}>
              <div style={{ fontSize: '1.8rem', fontWeight: 700, color: c.color }}>{c.value}</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-3)' }}>{c.label}</div>
            </div>
          ))}
        </div>
      )}

      <div style={{ display: 'flex', gap: '0.75rem' }}>
        {(['memory', 'modules'] as const).map(v => (
          <button key={v} className={`g-btn ${view === v ? 'g-btn-primary' : 'g-btn-ghost'}`}
            onClick={() => setView(v)}>
            {v === 'memory' ? 'Memory Regions' : 'Module Analysis'}
          </button>
        ))}
      </div>

      <div className="g-card" style={{ overflowX: 'auto', padding: 0 }}>
        {view === 'memory' ? (
          <table className="g-table" style={{ width: '100%' }}>
            <thead className="g-thead">
              <tr>
                <th className="g-tr">Process</th><th className="g-tr">Base Address</th>
                <th className="g-tr">Size</th><th className="g-tr">Protection</th>
                <th className="g-tr">Entropy</th><th className="g-tr">Shellcode</th>
                <th className="g-tr">Backed</th><th className="g-tr">Type</th>
              </tr>
            </thead>
            <tbody>
              {regions.map((r: any, i: number) => (
                <tr key={i} style={{ background: r.is_suspicious ? 'rgba(239,68,68,0.05)' : undefined }}>
                  <td className="g-tr">{r.process_name} <span style={{ color: 'var(--text-3)', fontSize: '0.75rem' }}>({r.pid})</span></td>
                  <td className="g-tr" style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{r.base_addr}</td>
                  <td className="g-tr" style={{ fontSize: '0.8rem' }}>{(r.size_bytes / 1024).toFixed(0)} KB</td>
                  <td className="g-tr">
                    <span style={{ background: r.protection === 'RWX' ? 'rgba(239,68,68,0.15)' : 'rgba(99,102,241,0.1)',
                      color: r.protection === 'RWX' ? '#ef4444' : '#818cf8', padding: '2px 6px', borderRadius: '3px', fontSize: '0.75rem', fontFamily: 'monospace' }}>
                      {r.protection}
                    </span>
                  </td>
                  <td className="g-tr">
                    <span style={{ color: r.entropy > 7 ? '#ef4444' : r.entropy > 6 ? '#f97316' : 'var(--text-2)' }}>{r.entropy?.toFixed(2)}</span>
                  </td>
                  <td className="g-tr">{r.contains_shellcode ? <span style={{ color: '#ef4444' }}>YES</span> : <span style={{ color: 'var(--text-3)' }}>No</span>}</td>
                  <td className="g-tr">{r.is_backed ? <span style={{ color: '#22c55e' }}>Backed</span> : <span style={{ color: '#ef4444' }}>Unbacked</span>}</td>
                  <td className="g-tr" style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>{r.region_type}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <table className="g-table" style={{ width: '100%' }}>
            <thead className="g-thead">
              <tr>
                <th className="g-tr">Module</th><th className="g-tr">Process</th>
                <th className="g-tr">Vendor</th><th className="g-tr">Signed</th>
                <th className="g-tr">Base Address</th><th className="g-tr">Size</th>
                <th className="g-tr">Flags</th>
              </tr>
            </thead>
            <tbody>
              {mods.map((m: any, i: number) => (
                <tr key={i} style={{ background: m.suspicious ? 'rgba(239,68,68,0.05)' : undefined }}>
                  <td className="g-tr" style={{ fontWeight: m.suspicious ? 600 : 400, color: m.suspicious ? '#ef4444' : undefined }}>{m.name || '[hidden]'}</td>
                  <td className="g-tr">{m.process} <span style={{ color: 'var(--text-3)', fontSize: '0.75rem' }}>({m.pid})</span></td>
                  <td className="g-tr" style={{ fontSize: '0.82rem', color: 'var(--text-3)' }}>{m.vendor}</td>
                  <td className="g-tr">{m.signed ? <span style={{ color: '#22c55e' }}>✓ Signed</span> : <span style={{ color: '#ef4444' }}>✗ Unsigned</span>}</td>
                  <td className="g-tr" style={{ fontFamily: 'monospace', fontSize: '0.78rem' }}>{m.base_addr}</td>
                  <td className="g-tr" style={{ fontSize: '0.8rem' }}>{m.size ? `${(m.size / 1024).toFixed(0)} KB` : '—'}</td>
                  <td className="g-tr">
                    {m.hidden && <span style={{ background: 'rgba(239,68,68,0.15)', color: '#ef4444', padding: '1px 5px', borderRadius: '3px', fontSize: '0.72rem', marginRight: '4px' }}>HIDDEN</span>}
                    {m.suspicious && !m.hidden && <span style={{ background: 'rgba(249,115,22,0.15)', color: '#f97316', padding: '1px 5px', borderRadius: '3px', fontSize: '0.72rem' }}>SUSPICIOUS</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ── API Monitor ───────────────────────────────────────────────────────────────
function APITab() {
  const [apiData, setApiData] = useState<any>(null);
  const [behavioral, setBehavioral] = useState<any>(null);
  const [handles, setHandles] = useState<any>(null);
  const [view, setView] = useState<'calls' | 'behavioral' | 'handles'>('calls');

  useEffect(() => {
    processInjectionAPI.getAPICalls().then(r => setApiData(r.data));
    processInjectionAPI.getBehavioral().then(r => setBehavioral(r.data));
    processInjectionAPI.getHandles().then(r => setHandles(r.data));
  }, []);

  const calls = apiData?.api_calls || [];
  const detections = behavioral?.detections || [];
  const handleList = handles?.handles || [];
  const monitored = apiData?.monitored_apis || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div className="g-card" style={{ padding: '1rem' }}>
        <div style={{ fontSize: '0.78rem', color: 'var(--text-3)', marginBottom: '0.5rem' }}>Monitored Win32 APIs</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
          {monitored.map((api: string) => (
            <code key={api} style={{ background: 'rgba(99,102,241,0.1)', color: '#818cf8', padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem' }}>{api}</code>
          ))}
        </div>
      </div>

      <div style={{ display: 'flex', gap: '0.75rem' }}>
        {(['calls', 'behavioral', 'handles'] as const).map(v => (
          <button key={v} className={`g-btn ${view === v ? 'g-btn-primary' : 'g-btn-ghost'}`}
            onClick={() => setView(v)}>
            {v === 'calls' ? 'API Calls' : v === 'behavioral' ? 'Behavioral Detections' : 'Handle Analysis'}
          </button>
        ))}
      </div>

      <div className="g-card" style={{ overflowX: 'auto', padding: 0 }}>
        {view === 'calls' && (
          <table className="g-table" style={{ width: '100%' }}>
            <thead className="g-thead">
              <tr>
                <th className="g-tr">Time</th><th className="g-tr">Process</th>
                <th className="g-tr">API</th><th className="g-tr">Target</th>
                <th className="g-tr">Parameters</th><th className="g-tr">Risk</th>
              </tr>
            </thead>
            <tbody>
              {calls.map((c: any, i: number) => (
                <tr key={i} style={{ background: c.is_suspicious ? 'rgba(239,68,68,0.05)' : undefined }}>
                  <td className="g-tr" style={{ fontSize: '0.78rem', color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(c.created_at)}</td>
                  <td className="g-tr">{c.process_name} <span style={{ color: 'var(--text-3)', fontSize: '0.75rem' }}>({c.pid})</span></td>
                  <td className="g-tr">
                    <code style={{ background: c.is_suspicious ? 'rgba(239,68,68,0.1)' : 'rgba(99,102,241,0.1)',
                      color: c.is_suspicious ? '#ef4444' : '#818cf8', padding: '2px 6px', borderRadius: '3px', fontSize: '0.78rem' }}>
                      {c.api_name}
                    </code>
                  </td>
                  <td className="g-tr" style={{ fontSize: '0.8rem' }}>{c.target_pid ? `PID ${c.target_pid}` : '—'}</td>
                  <td className="g-tr" style={{ fontFamily: 'monospace', fontSize: '0.7rem', maxWidth: '350px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-3)' }}>{c.parameters}</td>
                  <td className="g-tr">{c.is_suspicious ? <span style={{ color: '#ef4444', fontSize: '0.78rem' }}>⚠ Suspicious</span> : <span style={{ color: 'var(--text-3)', fontSize: '0.78rem' }}>—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {view === 'behavioral' && (
          <div style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {detections.map((d: any) => (
              <div key={d.id} className="g-card" style={{ padding: '1rem', borderLeft: `3px solid ${SEV_COLOR[d.severity] || '#666'}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                  <span style={{ fontWeight: 600 }}>{d.rule}</span>
                  <div style={{ display: 'flex', gap: '0.5rem', fontSize: '0.78rem' }}>
                    <span style={{ background: `${SEV_COLOR[d.severity]}20`, color: SEV_COLOR[d.severity], padding: '2px 8px', borderRadius: '3px' }}>{d.severity.toUpperCase()}</span>
                    <code style={{ background: 'rgba(99,102,241,0.1)', color: '#818cf8', padding: '2px 6px', borderRadius: '3px' }}>{d.mitre}</code>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem', fontSize: '0.82rem' }}>
                  <span style={{ color: '#f97316', fontFamily: 'monospace' }}>{d.parent}</span>
                  <span style={{ color: 'var(--text-3)' }}>→</span>
                  <span style={{ color: '#ef4444', fontFamily: 'monospace' }}>{d.child}</span>
                  <span style={{ marginLeft: 'auto', color: 'var(--text-3)' }}>{d.hostname}</span>
                </div>
                <code style={{ display: 'block', background: 'rgba(0,0,0,0.3)', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.72rem', wordBreak: 'break-all' }}>{d.cmdline}</code>
              </div>
            ))}
          </div>
        )}

        {view === 'handles' && (
          <table className="g-table" style={{ width: '100%' }}>
            <thead className="g-thead">
              <tr>
                <th className="g-tr">Process</th><th className="g-tr">Handle Type</th>
                <th className="g-tr">Target</th><th className="g-tr">Access</th>
                <th className="g-tr">Risk</th><th className="g-tr">Reason</th>
              </tr>
            </thead>
            <tbody>
              {handleList.map((h: any, i: number) => (
                <tr key={i} style={{ background: h.suspicious ? 'rgba(239,68,68,0.05)' : undefined }}>
                  <td className="g-tr">{h.process} <span style={{ color: 'var(--text-3)', fontSize: '0.75rem' }}>({h.pid})</span></td>
                  <td className="g-tr" style={{ fontSize: '0.8rem' }}>{h.handle_type}</td>
                  <td className="g-tr" style={{ fontWeight: h.suspicious ? 600 : 400 }}>{h.target} <span style={{ color: 'var(--text-3)', fontSize: '0.75rem' }}>({h.target_pid})</span></td>
                  <td className="g-tr"><code style={{ fontSize: '0.72rem', color: '#818cf8' }}>{h.access}</code></td>
                  <td className="g-tr">{h.suspicious ? <span style={{ color: '#ef4444' }}>⚠ Suspicious</span> : <span style={{ color: '#22c55e' }}>OK</span>}</td>
                  <td className="g-tr" style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>{h.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ── Intelligence ──────────────────────────────────────────────────────────────
function IntelligenceTab() {
  const [intel, setIntel] = useState<any>(null);
  const [mitre, setMitre] = useState<any>(null);
  const [view, setView] = useState<'intel' | 'mitre'>('intel');

  useEffect(() => {
    processInjectionAPI.getThreatIntel().then(r => setIntel(r.data));
    processInjectionAPI.getMITREMap().then(r => setMitre(r.data));
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', gap: '0.75rem' }}>
        {(['intel', 'mitre'] as const).map(v => (
          <button key={v} className={`g-btn ${view === v ? 'g-btn-primary' : 'g-btn-ghost'}`}
            onClick={() => setView(v)}>
            {v === 'intel' ? 'Threat Intelligence' : 'MITRE T1055 Map'}
          </button>
        ))}
      </div>

      {view === 'intel' && intel && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div className="g-card" style={{ padding: '1.25rem' }}>
            <div style={{ fontWeight: 600, marginBottom: '0.75rem', color: '#ef4444' }}>Malware Matches</div>
            {intel.malware_matches?.map((m: any, i: number) => (
              <div key={i} style={{ padding: '0.75rem', background: 'rgba(239,68,68,0.07)', borderRadius: '6px', marginBottom: '0.5rem', border: '1px solid rgba(239,68,68,0.2)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
                  <span style={{ fontWeight: 600, color: '#ef4444' }}>{m.name}</span>
                  <span style={{ fontSize: '0.78rem', color: '#22c55e' }}>Confidence: {m.confidence}%</span>
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-3)', marginBottom: '0.25rem' }}>
                  Technique: <span style={{ color: 'var(--text-2)' }}>{m.injection_type}</span> → Target: <span style={{ color: '#f97316' }}>{m.target}</span>
                </div>
                <code style={{ fontSize: '0.7rem', color: 'var(--text-3)' }}>{m.sha256}</code>
              </div>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <div className="g-card" style={{ padding: '1.25rem' }}>
              <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Threat Actors</div>
              {intel.threat_actors?.map((a: any, i: number) => (
                <div key={i} style={{ marginBottom: '0.75rem', paddingBottom: '0.75rem', borderBottom: '1px solid var(--border)' }}>
                  <div style={{ fontWeight: 600, color: '#f97316', marginBottom: '0.25rem' }}>{a.name}</div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-3)', marginBottom: '0.35rem' }}>Targets: {a.targets}</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
                    {a.ttps?.map((t: string) => (
                      <span key={t} style={{ background: 'rgba(99,102,241,0.1)', color: '#818cf8', padding: '1px 6px', borderRadius: '3px', fontSize: '0.72rem' }}>{t}</span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
            <div className="g-card" style={{ padding: '1.25rem' }}>
              <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Active Campaigns</div>
              {intel.campaigns?.map((c: any, i: number) => (
                <div key={i} style={{ marginBottom: '0.75rem', paddingBottom: '0.75rem', borderBottom: '1px solid var(--border)' }}>
                  <div style={{ fontWeight: 600, marginBottom: '0.25rem' }}>{c.name}</div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>Actor: <span style={{ color: '#f97316' }}>{c.actor}</span></div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-3)', marginTop: '0.2rem' }}>{c.technique}</div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-3)', marginTop: '0.25rem' }}>Detected: {timeAgo(c.detected)}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {view === 'mitre' && mitre && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div className="g-card" style={{ padding: '1.25rem', borderLeft: '4px solid var(--accent)' }}>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>{mitre.parent?.tactic}</div>
            <div style={{ fontWeight: 700, fontSize: '1.1rem', marginTop: '0.25rem' }}>
              {mitre.parent?.technique_id} — {mitre.parent?.name}
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(280px,1fr))', gap: '0.75rem' }}>
            {mitre.sub_techniques?.map((t: any) => (
              <div key={t.id} className="g-card" style={{
                padding: '0.85rem', borderLeft: `3px solid ${t.detected ? '#ef4444' : 'var(--border)'}`,
                opacity: t.detected ? 1 : 0.5,
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                  <code style={{ fontSize: '0.78rem', color: t.detected ? '#ef4444' : 'var(--text-3)' }}>{t.id}</code>
                  {t.detected && <span style={{ background: 'rgba(239,68,68,0.15)', color: '#ef4444', padding: '1px 6px', borderRadius: '3px', fontSize: '0.7rem' }}>DETECTED ×{t.count}</span>}
                </div>
                <div style={{ fontSize: '0.82rem', fontWeight: t.detected ? 600 : 400 }}>{t.name}</div>
              </div>
            ))}
          </div>
          <div className="g-card" style={{ padding: '1.25rem' }}>
            <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Related Techniques</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
              {mitre.related?.map((r: any) => (
                <div key={r.id} style={{
                  padding: '0.5rem 0.75rem', borderRadius: '6px', fontSize: '0.8rem',
                  background: r.detected ? 'rgba(239,68,68,0.1)' : 'rgba(255,255,255,0.05)',
                  border: `1px solid ${r.detected ? 'rgba(239,68,68,0.3)' : 'var(--border)'}`,
                }}>
                  <code style={{ color: r.detected ? '#ef4444' : 'var(--text-3)' }}>{r.id}</code>
                  <span style={{ marginLeft: '0.4rem' }}>{r.name}</span>
                  <span style={{ marginLeft: '0.4rem', color: 'var(--text-3)', fontSize: '0.72rem' }}>({r.tactic})</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Analytics ─────────────────────────────────────────────────────────────────
function AnalyticsTab() {
  const [data, setData] = useState<any>(null);
  useEffect(() => { processInjectionAPI.getAnalytics().then(r => setData(r.data)); }, []);
  if (!data) return <div style={{ color: 'var(--text-3)', padding: '2rem' }}>Loading…</div>;

  const maxTrend = Math.max(...(data.injection_trend?.map((p: any) => p.count) || [1]), 1);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div className="g-card" style={{ padding: '1.25rem' }}>
        <div style={{ fontWeight: 600, marginBottom: '1rem' }}>Injection Trend (14d)</div>
        <div style={{ display: 'flex', alignItems: 'flex-end', gap: '4px', height: '120px' }}>
          {data.injection_trend?.map((p: any, i: number) => (
            <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '4px' }}>
              <div style={{
                width: '100%', background: p.count > 3 ? '#ef4444' : p.count > 1 ? '#f97316' : '#3b82f6',
                height: `${Math.max((p.count / maxTrend) * 80, p.count > 0 ? 6 : 2)}px`,
                borderRadius: '3px 3px 0 0',
              }} title={`${p.date}: ${p.count}`} />
              <div style={{ fontSize: '0.6rem', color: 'var(--text-3)', transform: 'rotate(-30deg)', whiteSpace: 'nowrap' }}>
                {p.date.slice(5)}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div className="g-card" style={{ padding: '1.25rem' }}>
          <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Top Injection Techniques</div>
          {data.top_techniques?.map((t: any) => (
            <div key={t.technique} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.6rem' }}>
              <span style={{ minWidth: '170px', fontSize: '0.82rem' }}>{t.technique}</span>
              <div style={{ flex: 1, height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
                <div style={{ width: `${(t.count / 6) * 100}%`, height: '100%', borderRadius: '4px', background: SEV_COLOR[t.severity] || '#666' }} />
              </div>
              <span style={{ fontSize: '0.8rem', minWidth: '20px', textAlign: 'right' }}>{t.count}</span>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: '1.25rem' }}>
          <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Most Targeted Processes</div>
          {data.most_targeted_processes?.map((p: any) => (
            <div key={p.process} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.6rem' }}>
              <code style={{ minWidth: '120px', fontSize: '0.8rem' }}>{p.process}</code>
              <div style={{ flex: 1, height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
                <div style={{ width: `${(p.count / 6) * 100}%`, height: '100%', borderRadius: '4px', background: SEV_COLOR[p.risk] || '#666' }} />
              </div>
              <span style={{ fontSize: '0.8rem', minWidth: '20px', textAlign: 'right' }}>{p.count}</span>
            </div>
          ))}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div className="g-card" style={{ padding: '1.25rem' }}>
          <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Most Used APIs</div>
          {data.most_used_apis?.map((a: any) => (
            <div key={a.api} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.6rem' }}>
              <code style={{ minWidth: '180px', fontSize: '0.78rem', color: '#818cf8' }}>{a.api}</code>
              <div style={{ flex: 1, height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
                <div style={{ width: `${(a.count / 14) * 100}%`, height: '100%', borderRadius: '4px', background: '#6366f1' }} />
              </div>
              <span style={{ fontSize: '0.8rem', minWidth: '20px', textAlign: 'right' }}>{a.count}</span>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: '1.25rem' }}>
          <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>High-Risk Hosts</div>
          {data.high_risk_hosts?.map((h: any) => (
            <div key={h.hostname} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.6rem' }}>
              <span style={{ minWidth: '140px', fontSize: '0.82rem', fontFamily: 'monospace' }}>{h.hostname}</span>
              <div style={{ flex: 1, height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
                <div style={{ width: `${h.risk}%`, height: '100%', borderRadius: '4px', background: RISK_COLOR(h.risk) }} />
              </div>
              <span style={{ fontSize: '0.8rem', color: RISK_COLOR(h.risk), minWidth: '30px', textAlign: 'right' }}>{h.risk}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Response ──────────────────────────────────────────────────────────────────
function ResponseTab() {
  const [injData, setInjData] = useState<any>(null);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState<Record<string, boolean>>({});
  const [reportLoading, setReportLoading] = useState(false);
  const [report, setReport] = useState<any>(null);
  const [aiQuery, setAiQuery] = useState('');
  const [aiResult, setAiResult] = useState<any>(null);
  const [aiLoading, setAiLoading] = useState(false);

  useEffect(() => {
    processInjectionAPI.getInjections({ limit: 5 }).then(r => setInjData(r.data));
    processInjectionAPI.getTimeline().then(r => setTimeline(r.data || []));
  }, []);

  const respond = async (action: string, target: string, pid: number, hostname: string) => {
    setLoading(l => ({ ...l, [action]: true }));
    const r = await processInjectionAPI.respond({ action, target, pid, hostname, reason: 'Manual response' });
    setResult(r.data);
    setLoading(l => ({ ...l, [action]: false }));
  };

  const generateReport = async () => {
    setReportLoading(true);
    const r = await processInjectionAPI.generateReport({ report_type: 'executive' });
    setReport(r.data);
    setReportLoading(false);
  };

  const runAI = async () => {
    if (!aiQuery.trim()) return;
    setAiLoading(true);
    const r = await processInjectionAPI.analyzeAI({ content: aiQuery });
    setAiResult(r.data);
    setAiLoading(false);
  };

  const ACTIONS = [
    { id: 'kill_process',     label: 'Kill Process',      desc: 'Terminate via TerminateProcess',   color: '#ef4444' },
    { id: 'suspend_process',  label: 'Suspend Process',   desc: 'Halt execution for investigation', color: '#f97316' },
    { id: 'dump_memory',      label: 'Dump Memory',       desc: 'Full memory dump for forensics',   color: '#3b82f6' },
    { id: 'collect_process',  label: 'Collect Process',   desc: 'Capture handles/modules/network',  color: '#6366f1' },
    { id: 'isolate_endpoint', label: 'Isolate Endpoint',  desc: 'Revoke all network access',        color: '#a855f7' },
    { id: 'run_soar',         label: 'Run SOAR Playbook', desc: 'Execute PI-RESPONSE-01',           color: '#22c55e' },
  ];

  const inj = injData?.injections?.[0];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {result && (
        <div style={{ background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.3)', borderRadius: '8px', padding: '1rem' }}>
          <div style={{ fontWeight: 600, color: '#22c55e', marginBottom: '0.25rem' }}>Action Executed: {result.action}</div>
          <div style={{ fontSize: '0.85rem' }}>{result.message}</div>
          {result.hostname && <div style={{ fontSize: '0.78rem', color: 'var(--text-3)', marginTop: '0.25rem' }}>Host: {result.hostname}</div>}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(280px,1fr))', gap: '0.75rem' }}>
        {ACTIONS.map(a => (
          <div key={a.id} className="g-card" style={{ padding: '1rem', borderLeft: `3px solid ${a.color}` }}>
            <div style={{ fontWeight: 600, marginBottom: '0.25rem' }}>{a.label}</div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-3)', marginBottom: '0.75rem' }}>{a.desc}</div>
            <button
              className="g-btn g-btn-primary"
              style={{ background: a.color, border: 'none', width: '100%', opacity: loading[a.id] ? 0.7 : 1 }}
              disabled={loading[a.id]}
              onClick={() => respond(a.id, inj?.dst_name || 'explorer.exe', inj?.dst_pid || 4512, inj?.hostname || 'WS-ANALYST-01')}
            >
              {loading[a.id] ? 'Executing…' : a.label}
            </button>
          </div>
        ))}
      </div>

      <div className="g-card" style={{ padding: '1.25rem' }}>
        <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>AI-Assisted Investigation</div>
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
          <input className="g-input" style={{ flex: 1 }} placeholder="Ask about an injection event, technique, or IOC…"
            value={aiQuery} onChange={e => setAiQuery(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') runAI(); }} />
          <button className="g-btn g-btn-primary" onClick={runAI} disabled={aiLoading}>
            {aiLoading ? 'Analyzing…' : 'Analyze'}
          </button>
        </div>
        {aiResult && (
          <div style={{ background: 'rgba(99,102,241,0.07)', padding: '1rem', borderRadius: '6px', border: '1px solid rgba(99,102,241,0.2)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
              <span style={{ fontWeight: 600, color: aiResult.verdict === 'malicious' ? '#ef4444' : '#f97316' }}>
                {aiResult.verdict?.toUpperCase()}
              </span>
              {aiResult.confidence && <span style={{ fontSize: '0.78rem', color: '#22c55e' }}>Confidence: {aiResult.confidence}%</span>}
            </div>
            {aiResult.technique && (
              <div style={{ fontSize: '0.82rem', marginBottom: '0.4rem' }}>
                <strong>Technique:</strong> <code style={{ color: '#818cf8' }}>{aiResult.mitre_technique}</code> {aiResult.technique}
              </div>
            )}
            {aiResult.explanation && <div style={{ fontSize: '0.82rem', color: 'var(--text-2)', marginBottom: '0.5rem' }}>{aiResult.explanation}</div>}
            {aiResult.answer && <div style={{ fontSize: '0.82rem', color: 'var(--text-2)', marginBottom: '0.5rem' }}>{aiResult.answer}</div>}
            {aiResult.indicators && (
              <div style={{ marginBottom: '0.5rem' }}>
                <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-3)', marginBottom: '0.3rem' }}>Indicators</div>
                {aiResult.indicators.map((ind: string, i: number) => (
                  <div key={i} style={{ fontSize: '0.78rem', color: '#ef4444', paddingLeft: '0.5rem', borderLeft: '2px solid #ef4444', marginBottom: '0.2rem' }}>{ind}</div>
                ))}
              </div>
            )}
            {aiResult.recommended_actions && (
              <div>
                <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-3)', marginBottom: '0.3rem' }}>Recommended Actions</div>
                {aiResult.recommended_actions.map((ra: string, i: number) => (
                  <div key={i} style={{ fontSize: '0.78rem', color: '#22c55e', paddingLeft: '0.5rem', borderLeft: '2px solid #22c55e', marginBottom: '0.2rem' }}>→ {ra}</div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="g-card" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
          <span style={{ fontWeight: 600 }}>Injection Timeline</span>
          <span style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>Recent events</span>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {timeline.map((e: any) => (
            <div key={e.id} style={{ padding: '0.75rem', borderRadius: '6px', background: 'rgba(255,255,255,0.03)', borderLeft: `3px solid ${SEV_COLOR[e.severity] || '#666'}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>{e.title}</span>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-3)' }}>{timeAgo(e.created_at)}</span>
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>{e.description}</div>
              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.3rem' }}>
                <code style={{ fontSize: '0.7rem', color: '#818cf8' }}>{e.mitre_technique}</code>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-3)' }}>{e.hostname}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="g-card" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
          <span style={{ fontWeight: 600 }}>Executive Report</span>
          <button className="g-btn g-btn-primary" onClick={generateReport} disabled={reportLoading}>
            {reportLoading ? 'Generating…' : 'Generate Report'}
          </button>
        </div>
        {report && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ fontWeight: 600, fontSize: '1rem' }}>{report.title}</div>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-2)', lineHeight: 1.6 }}>{report.executive_summary}</div>
            {report.key_findings && (
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.35rem' }}>Key Findings</div>
                {report.key_findings.map((f: string, i: number) => (
                  <div key={i} style={{ fontSize: '0.82rem', color: '#ef4444', paddingLeft: '0.5rem', borderLeft: '2px solid #ef4444', marginBottom: '0.25rem' }}>• {f}</div>
                ))}
              </div>
            )}
            {report.top_recommendations && (
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.35rem' }}>Top Recommendations</div>
                {report.top_recommendations.map((r: any, i: number) => (
                  <div key={i} style={{ padding: '0.5rem 0.75rem', marginBottom: '0.35rem', borderRadius: '4px', background: 'rgba(34,197,94,0.07)', borderLeft: '2px solid #22c55e' }}>
                    <span style={{ fontSize: '0.72rem', color: '#22c55e', marginRight: '0.4rem' }}>P{r.priority}</span>
                    <span style={{ fontSize: '0.82rem' }}>{r.action}</span>
                    <span style={{ fontSize: '0.72rem', color: 'var(--text-3)', marginLeft: '0.4rem' }}>({r.estimated_effort})</span>
                  </div>
                ))}
              </div>
            )}
            {report.metrics && (
              <div style={{ display: 'flex', gap: '1.5rem', paddingTop: '0.5rem', borderTop: '1px solid var(--border)', fontSize: '0.82rem', color: 'var(--text-3)' }}>
                <span>Injections: <strong style={{ color: 'var(--text-1)' }}>{report.metrics.total_injections}</strong></span>
                <span>Critical Alerts: <strong style={{ color: '#ef4444' }}>{report.metrics.critical_alerts}</strong></span>
                <span>Affected Hosts: <strong style={{ color: 'var(--text-1)' }}>{report.metrics.affected_hosts}</strong></span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────
export default function ProcessInjectionPage() {
  const [tab, setTab] = useState<Tab>('overview');
  const [dash, setDash] = useState<any>(null);
  const loaded = useRef<Record<string, boolean>>({});

  useEffect(() => {
    processInjectionAPI.getDashboard().then(r => setDash(r.data));
  }, []);

  if (!loaded.current[tab]) loaded.current[tab] = true;

  const tabs = Object.keys(TAB_LABELS) as Tab[];

  return (
    <RootLayout title="Process Injection Detection" subtitle="Memory forensics, API monitoring, and injection technique detection — MITRE T1055">
      <div style={{ padding: '1.5rem', maxWidth: '1400px', margin: '0 auto' }}>
        <div style={{ display: 'flex', gap: '0.25rem', marginBottom: '1.5rem', borderBottom: '1px solid var(--border)', overflowX: 'auto' }}>
          {tabs.map(t => (
            <button key={t}
              onClick={() => setTab(t)}
              style={{
                background: 'none', border: 'none', cursor: 'pointer',
                padding: '0.6rem 1rem', fontSize: '0.85rem', whiteSpace: 'nowrap',
                color: tab === t ? 'var(--accent)' : 'var(--text-3)',
                borderBottom: `2px solid ${tab === t ? 'var(--accent)' : 'transparent'}`,
                marginBottom: '-1px', transition: 'all 0.15s',
              }}>
              {TAB_LABELS[t]}
            </button>
          ))}
        </div>

        <div style={{ display: loaded.current['overview'] ? 'block' : 'none' }}>
          <OverviewTab dash={dash} />
        </div>
        <div style={{ display: loaded.current['processes'] && tab === 'processes' ? 'block' : 'none' }}>
          {loaded.current['processes'] && <ProcessesTab />}
        </div>
        <div style={{ display: loaded.current['memory'] && tab === 'memory' ? 'block' : 'none' }}>
          {loaded.current['memory'] && <MemoryTab />}
        </div>
        <div style={{ display: loaded.current['api'] && tab === 'api' ? 'block' : 'none' }}>
          {loaded.current['api'] && <APITab />}
        </div>
        <div style={{ display: loaded.current['intelligence'] && tab === 'intelligence' ? 'block' : 'none' }}>
          {loaded.current['intelligence'] && <IntelligenceTab />}
        </div>
        <div style={{ display: loaded.current['analytics'] && tab === 'analytics' ? 'block' : 'none' }}>
          {loaded.current['analytics'] && <AnalyticsTab />}
        </div>
        <div style={{ display: loaded.current['response'] && tab === 'response' ? 'block' : 'none' }}>
          {loaded.current['response'] && <ResponseTab />}
        </div>
      </div>
    </RootLayout>
  );
}
