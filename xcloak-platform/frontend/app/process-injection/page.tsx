'use client';
import { useState, useEffect, useRef } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { processInjectionAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import { MetricCard, DataTable, SectionCard, TabBar, ActionButton } from '@/components/design-system';
import { LayoutDashboard, Cpu, MemoryStick, Code2, Radar, BarChart3, Siren, Check, X, AlertTriangle } from 'lucide-react';

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
const TAB_ICONS: Record<Tab, any> = {
  overview: LayoutDashboard, processes: Cpu, memory: MemoryStick, api: Code2,
  intelligence: Radar, analytics: BarChart3, response: Siren,
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
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        {cards.map(c => <MetricCard key={c.label} label={c.label} value={c.value} color={c.color} />)}
      </div>
      <SectionCard title="Injection Technique Coverage">
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
          {(dash.injection_types || []).map((t: string) => (
            <span key={t} style={{
              background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
              color: '#ef4444', borderRadius: '4px', padding: '0.25rem 0.6rem', fontSize: '0.75rem',
            }}>{t}</span>
          ))}
        </div>
      </SectionCard>
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
          <ActionButton key={v} variant={view === v ? 'primary' : 'ghost'} onClick={() => setView(v)}>
            {v === 'list' ? 'Process List' : 'Process Tree'}
          </ActionButton>
        ))}
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginLeft: 'auto', cursor: 'pointer', fontSize: '0.85rem' }}>
          <input type="checkbox" checked={suspicious} onChange={e => setSuspicious(e.target.checked)} />
          Suspicious only
        </label>
      </div>

      <div style={{ display: 'flex', gap: '1rem' }}>
        <div style={{ flex: 1 }}>
          {view === 'list' ? (
            <DataTable<any>
              rows={processes}
              rowKey={(p: any) => p.id}
              onRowClick={p => setSelected(p)}
              rowStyle={(p: any) => selected?.id === p.id ? { background: 'rgba(99,102,241,0.1)' } : undefined}
              columns={[
                { key: 'pid', header: 'PID', render: (p: any) => <span style={{ fontFamily: 'monospace', color: 'var(--text-3)' }}>{p.pid}</span> },
                { key: 'name', header: 'Name', render: (p: any) => <span style={{ fontWeight: p.risk_score > 60 ? 600 : 400, color: p.risk_score > 80 ? '#ef4444' : undefined }}>{p.name}</span> },
                { key: 'ppid', header: 'PPID', render: (p: any) => <span style={{ fontFamily: 'monospace', color: 'var(--text-3)' }}>{p.ppid}</span> },
                { key: 'username', header: 'User', render: (p: any) => <span style={{ fontSize: '0.8rem' }}>{p.username}</span> },
                { key: 'integrity_level', header: 'Integrity', render: (p: any) => (
                  <span style={{ fontSize: '0.75rem', padding: '2px 6px', borderRadius: '3px',
                    background: p.integrity_level === 'System' ? 'rgba(239,68,68,0.1)' : 'rgba(99,102,241,0.1)',
                    color: p.integrity_level === 'System' ? '#ef4444' : '#818cf8' }}>
                    {p.integrity_level}
                  </span>
                ) },
                { key: 'risk_score', header: 'Risk', render: (p: any) => (
                  <span>
                    <span style={{ display: 'inline-block', width: '4rem', height: '6px', borderRadius: '3px',
                      background: `linear-gradient(to right, ${RISK_COLOR(p.risk_score)} ${p.risk_score}%, rgba(255,255,255,0.1) 0%)` }} />
                    <span style={{ marginLeft: '0.4rem', fontSize: '0.8rem', color: RISK_COLOR(p.risk_score) }}>{p.risk_score}</span>
                  </span>
                ) },
                { key: 'cmdline', header: 'Command', render: (p: any) => <span style={{ fontFamily: 'monospace', fontSize: '0.72rem', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>{p.cmdline}</span> },
              ]}
            />
          ) : (
            <div className="g-card" style={{ padding: '1rem', fontFamily: 'monospace', fontSize: '0.82rem' }}>
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
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          <MetricCard label="RWX Pages" value={memData.rwx_pages} color="#ef4444" />
          <MetricCard label="Shellcode Regions" value={memData.shellcode} color="#f97316" />
          <MetricCard label="Unbacked Regions" value={memData.unbacked} color="#eab308" />
        </div>
      )}

      <div style={{ display: 'flex', gap: '0.75rem' }}>
        {(['memory', 'modules'] as const).map(v => (
          <ActionButton key={v} variant={view === v ? 'primary' : 'ghost'} onClick={() => setView(v)}>
            {v === 'memory' ? 'Memory Regions' : 'Module Analysis'}
          </ActionButton>
        ))}
      </div>

      {view === 'memory' ? (
        <DataTable<any>
          rows={regions}
          rowKey={(r: any, i: number) => i}
          rowStyle={(r: any) => r.is_suspicious ? { background: 'rgba(239,68,68,0.05)' } : undefined}
          columns={[
            { key: 'process_name', header: 'Process', render: (r: any) => <span>{r.process_name} <span style={{ color: 'var(--text-3)', fontSize: '0.75rem' }}>({r.pid})</span></span> },
            { key: 'base_addr', header: 'Base Address', render: (r: any) => <span style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{r.base_addr}</span> },
            { key: 'size_bytes', header: 'Size', render: (r: any) => <span style={{ fontSize: '0.8rem' }}>{(r.size_bytes / 1024).toFixed(0)} KB</span> },
            { key: 'protection', header: 'Protection', render: (r: any) => (
              <span style={{ background: r.protection === 'RWX' ? 'rgba(239,68,68,0.15)' : 'rgba(99,102,241,0.1)',
                color: r.protection === 'RWX' ? '#ef4444' : '#818cf8', padding: '2px 6px', borderRadius: '3px', fontSize: '0.75rem', fontFamily: 'monospace' }}>
                {r.protection}
              </span>
            ) },
            { key: 'entropy', header: 'Entropy', render: (r: any) => <span style={{ color: r.entropy > 7 ? '#ef4444' : r.entropy > 6 ? '#f97316' : 'var(--text-2)' }}>{r.entropy?.toFixed(2)}</span> },
            { key: 'contains_shellcode', header: 'Shellcode', render: (r: any) => r.contains_shellcode ? <span style={{ color: '#ef4444' }}>YES</span> : <span style={{ color: 'var(--text-3)' }}>No</span> },
            { key: 'is_backed', header: 'Backed', render: (r: any) => r.is_backed ? <span style={{ color: '#22c55e' }}>Backed</span> : <span style={{ color: '#ef4444' }}>Unbacked</span> },
            { key: 'region_type', header: 'Type', render: (r: any) => <span style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>{r.region_type}</span> },
          ]}
        />
      ) : (
        <DataTable<any>
          rows={mods}
          rowKey={(m: any, i: number) => i}
          rowStyle={(m: any) => m.suspicious ? { background: 'rgba(239,68,68,0.05)' } : undefined}
          columns={[
            { key: 'name', header: 'Module', render: (m: any) => <span style={{ fontWeight: m.suspicious ? 600 : 400, color: m.suspicious ? '#ef4444' : undefined }}>{m.name || '[hidden]'}</span> },
            { key: 'process', header: 'Process', render: (m: any) => <span>{m.process} <span style={{ color: 'var(--text-3)', fontSize: '0.75rem' }}>({m.pid})</span></span> },
            { key: 'vendor', header: 'Vendor', render: (m: any) => <span style={{ fontSize: '0.82rem', color: 'var(--text-3)' }}>{m.vendor}</span> },
            { key: 'signed', header: 'Signed', render: (m: any) => m.signed
              ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#22c55e' }}><Check style={{ width: 11, height: 11 }} /> Signed</span>
              : <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#ef4444' }}><X style={{ width: 11, height: 11 }} /> Unsigned</span> },
            { key: 'base_addr', header: 'Base Address', render: (m: any) => <span style={{ fontFamily: 'monospace', fontSize: '0.78rem' }}>{m.base_addr}</span> },
            { key: 'size', header: 'Size', render: (m: any) => <span style={{ fontSize: '0.8rem' }}>{m.size ? `${(m.size / 1024).toFixed(0)} KB` : '—'}</span> },
            { key: 'flags', header: 'Flags', render: (m: any) => (
              <span>
                {m.hidden && <span style={{ background: 'rgba(239,68,68,0.15)', color: '#ef4444', padding: '1px 5px', borderRadius: '3px', fontSize: '0.72rem', marginRight: '4px' }}>HIDDEN</span>}
                {m.suspicious && !m.hidden && <span style={{ background: 'rgba(249,115,22,0.15)', color: '#f97316', padding: '1px 5px', borderRadius: '3px', fontSize: '0.72rem' }}>SUSPICIOUS</span>}
              </span>
            ) },
          ]}
        />
      )}
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
      <SectionCard title="Monitored Win32 APIs">
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
          {monitored.map((api: string) => (
            <code key={api} style={{ background: 'rgba(99,102,241,0.1)', color: '#818cf8', padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem' }}>{api}</code>
          ))}
        </div>
      </SectionCard>

      <div style={{ display: 'flex', gap: '0.75rem' }}>
        {(['calls', 'behavioral', 'handles'] as const).map(v => (
          <ActionButton key={v} variant={view === v ? 'primary' : 'ghost'} onClick={() => setView(v)}>
            {v === 'calls' ? 'API Calls' : v === 'behavioral' ? 'Behavioral Detections' : 'Handle Analysis'}
          </ActionButton>
        ))}
      </div>

      {view === 'calls' && (
        <DataTable<any>
          rows={calls}
          rowKey={(c: any, i: number) => i}
          rowStyle={(c: any) => c.is_suspicious ? { background: 'rgba(239,68,68,0.05)' } : undefined}
          columns={[
            { key: 'created_at', header: 'Time', render: (c: any) => <span style={{ fontSize: '0.78rem', color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(c.created_at)}</span> },
            { key: 'process_name', header: 'Process', render: (c: any) => <span>{c.process_name} <span style={{ color: 'var(--text-3)', fontSize: '0.75rem' }}>({c.pid})</span></span> },
            { key: 'api_name', header: 'API', render: (c: any) => (
              <code style={{ background: c.is_suspicious ? 'rgba(239,68,68,0.1)' : 'rgba(99,102,241,0.1)',
                color: c.is_suspicious ? '#ef4444' : '#818cf8', padding: '2px 6px', borderRadius: '3px', fontSize: '0.78rem' }}>
                {c.api_name}
              </code>
            ) },
            { key: 'target_pid', header: 'Target', render: (c: any) => <span style={{ fontSize: '0.8rem' }}>{c.target_pid ? `PID ${c.target_pid}` : '—'}</span> },
            { key: 'parameters', header: 'Parameters', render: (c: any) => <span style={{ fontFamily: 'monospace', fontSize: '0.7rem', maxWidth: '350px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-3)', display: 'block' }}>{c.parameters}</span> },
            { key: 'is_suspicious', header: 'Risk', render: (c: any) => c.is_suspicious
              ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#ef4444', fontSize: '0.78rem' }}><AlertTriangle style={{ width: 11, height: 11 }} /> Suspicious</span>
              : <span style={{ color: 'var(--text-3)', fontSize: '0.78rem' }}>—</span> },
          ]}
        />
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
        <DataTable<any>
          rows={handleList}
          rowKey={(h: any, i: number) => i}
          rowStyle={(h: any) => h.suspicious ? { background: 'rgba(239,68,68,0.05)' } : undefined}
          columns={[
            { key: 'process', header: 'Process', render: (h: any) => <span>{h.process} <span style={{ color: 'var(--text-3)', fontSize: '0.75rem' }}>({h.pid})</span></span> },
            { key: 'handle_type', header: 'Handle Type', render: (h: any) => <span style={{ fontSize: '0.8rem' }}>{h.handle_type}</span> },
            { key: 'target', header: 'Target', render: (h: any) => <span style={{ fontWeight: h.suspicious ? 600 : 400 }}>{h.target} <span style={{ color: 'var(--text-3)', fontSize: '0.75rem' }}>({h.target_pid})</span></span> },
            { key: 'access', header: 'Access', render: (h: any) => <code style={{ fontSize: '0.72rem', color: '#818cf8' }}>{h.access}</code> },
            { key: 'suspicious', header: 'Risk', render: (h: any) => h.suspicious
              ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: '#ef4444' }}><AlertTriangle style={{ width: 11, height: 11 }} /> Suspicious</span>
              : <span style={{ color: '#22c55e' }}>OK</span> },
            { key: 'reason', header: 'Reason', render: (h: any) => <span style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>{h.reason}</span> },
          ]}
        />
      )}
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
          <ActionButton key={v} variant={view === v ? 'primary' : 'ghost'} onClick={() => setView(v)}>
            {v === 'intel' ? 'Threat Intelligence' : 'MITRE T1055 Map'}
          </ActionButton>
        ))}
      </div>

      {view === 'intel' && intel && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <SectionCard title={<span style={{ color: '#ef4444' }}>Malware Matches</span>}>
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
          </SectionCard>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <SectionCard title="Threat Actors">
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
            </SectionCard>
            <SectionCard title="Active Campaigns">
              {intel.campaigns?.map((c: any, i: number) => (
                <div key={i} style={{ marginBottom: '0.75rem', paddingBottom: '0.75rem', borderBottom: '1px solid var(--border)' }}>
                  <div style={{ fontWeight: 600, marginBottom: '0.25rem' }}>{c.name}</div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>Actor: <span style={{ color: '#f97316' }}>{c.actor}</span></div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-3)', marginTop: '0.2rem' }}>{c.technique}</div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-3)', marginTop: '0.25rem' }}>Detected: {timeAgo(c.detected)}</div>
                </div>
              ))}
            </SectionCard>
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
          <SectionCard title="Related Techniques">
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
          </SectionCard>
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
      <SectionCard title="Injection Trend (14d)">
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
      </SectionCard>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <SectionCard title="Top Injection Techniques">
          {data.top_techniques?.map((t: any) => (
            <div key={t.technique} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.6rem' }}>
              <span style={{ minWidth: '170px', fontSize: '0.82rem' }}>{t.technique}</span>
              <div style={{ flex: 1, height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
                <div style={{ width: `${(t.count / 6) * 100}%`, height: '100%', borderRadius: '4px', background: SEV_COLOR[t.severity] || '#666' }} />
              </div>
              <span style={{ fontSize: '0.8rem', minWidth: '20px', textAlign: 'right' }}>{t.count}</span>
            </div>
          ))}
        </SectionCard>
        <SectionCard title="Most Targeted Processes">
          {data.most_targeted_processes?.map((p: any) => (
            <div key={p.process} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.6rem' }}>
              <code style={{ minWidth: '120px', fontSize: '0.8rem' }}>{p.process}</code>
              <div style={{ flex: 1, height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
                <div style={{ width: `${(p.count / 6) * 100}%`, height: '100%', borderRadius: '4px', background: SEV_COLOR[p.risk] || '#666' }} />
              </div>
              <span style={{ fontSize: '0.8rem', minWidth: '20px', textAlign: 'right' }}>{p.count}</span>
            </div>
          ))}
        </SectionCard>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <SectionCard title="Most Used APIs">
          {data.most_used_apis?.map((a: any) => (
            <div key={a.api} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.6rem' }}>
              <code style={{ minWidth: '180px', fontSize: '0.78rem', color: '#818cf8' }}>{a.api}</code>
              <div style={{ flex: 1, height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
                <div style={{ width: `${(a.count / 14) * 100}%`, height: '100%', borderRadius: '4px', background: '#6366f1' }} />
              </div>
              <span style={{ fontSize: '0.8rem', minWidth: '20px', textAlign: 'right' }}>{a.count}</span>
            </div>
          ))}
        </SectionCard>
        <SectionCard title="High-Risk Hosts">
          {data.high_risk_hosts?.map((h: any) => (
            <div key={h.hostname} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.6rem' }}>
              <span style={{ minWidth: '140px', fontSize: '0.82rem', fontFamily: 'monospace' }}>{h.hostname}</span>
              <div style={{ flex: 1, height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
                <div style={{ width: `${h.risk}%`, height: '100%', borderRadius: '4px', background: RISK_COLOR(h.risk) }} />
              </div>
              <span style={{ fontSize: '0.8rem', color: RISK_COLOR(h.risk), minWidth: '30px', textAlign: 'right' }}>{h.risk}</span>
            </div>
          ))}
        </SectionCard>
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
            <ActionButton
              variant="primary"
              loading={loading[a.id]}
              onClick={() => respond(a.id, inj?.dst_name || 'explorer.exe', inj?.dst_pid || 4512, inj?.hostname || 'WS-ANALYST-01')}
              style={{ background: a.color, border: 'none', width: '100%', justifyContent: 'center' }}
            >
              {loading[a.id] ? 'Executing…' : a.label}
            </ActionButton>
          </div>
        ))}
      </div>

      <SectionCard title="AI-Assisted Investigation">
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
          <input className="g-input" style={{ flex: 1 }} placeholder="Ask about an injection event, technique, or IOC…"
            value={aiQuery} onChange={e => setAiQuery(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') runAI(); }} />
          <ActionButton variant="primary" onClick={runAI} disabled={aiLoading}>
            {aiLoading ? 'Analyzing…' : 'Analyze'}
          </ActionButton>
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
      </SectionCard>

      <SectionCard title="Injection Timeline" actions={<span style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>Recent events</span>}>
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
      </SectionCard>

      <SectionCard
        title="Executive Report"
        actions={<ActionButton variant="primary" onClick={generateReport} disabled={reportLoading}>{reportLoading ? 'Generating…' : 'Generate Report'}</ActionButton>}
      >
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
      </SectionCard>
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
        <div style={{ marginBottom: '1.5rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.75rem' }}>
          <TabBar
            tabs={tabs.map(t => ({ key: t, label: TAB_LABELS[t], icon: TAB_ICONS[t] }))}
            active={tab}
            onChange={t => setTab(t as Tab)}
          />
        </div>

        <div style={{ display: loaded.current['overview'] && tab === 'overview' ? 'block' : 'none' }}>
          {loaded.current['overview'] && <OverviewTab dash={dash} />}
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
