'use client';
import { useState, useEffect, useRef } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { defenseEvasionAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';

type Tab = 'overview' | 'controls' | 'tamper' | 'evasion' | 'behavioral' | 'mitre' | 'intelligence' | 'analytics' | 'response';

const TAB_LABELS: Record<Tab, string> = {
  overview:     'Dashboard',
  controls:     'Security Controls',
  tamper:       'Tamper & Logs',
  evasion:      'Evasion Events',
  behavioral:   'Behavioral',
  mitre:        'MITRE Coverage',
  intelligence: 'Threat Intel',
  analytics:    'Analytics',
  response:     'Response',
};

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#3b82f6',
};
const STATUS_COLOR: Record<string, string> = {
  active: '#22c55e', degraded: '#eab308', disabled: '#ef4444', tampered: '#ef4444',
};

// ── Overview ──────────────────────────────────────────────────────────────────
function OverviewTab({ dash }: { dash: any }) {
  if (!dash) return <div style={{ color: 'var(--text-3)', padding: '2rem' }}>Loading…</div>;
  const cards = [
    { label: 'Evasion Alerts',           value: dash.defense_evasion_alerts,     color: '#ef4444' },
    { label: 'Active Attempts',           value: dash.active_evasion_attempts,    color: '#f97316' },
    { label: 'Disabled Controls',         value: dash.disabled_security_controls, color: '#ef4444' },
    { label: 'Tamper Events',             value: dash.tamper_events,              color: '#eab308' },
    { label: 'AMSI Bypass Attempts',      value: dash.amsi_bypass_attempts,       color: '#f97316' },
    { label: 'High-Risk Hosts',           value: dash.high_risk_hosts,            color: '#ef4444' },
    { label: 'MITRE TA0005 Coverage',     value: `${dash.mitre_coverage}%`,       color: '#3b82f6' },
  ];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(175px,1fr))', gap: '1rem' }}>
        {cards.map(c => (
          <div key={c.label} className="g-card" style={{ padding: '1.25rem', borderTop: `3px solid ${c.color}` }}>
            <div style={{ fontSize: '2rem', fontWeight: 700, color: c.color }}>{c.value}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-3)', marginTop: '0.25rem' }}>{c.label}</div>
          </div>
        ))}
      </div>
      <div className="g-card" style={{ padding: '1.25rem' }}>
        <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Detected Evasion Categories</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
          {(dash.top_categories || []).map((t: string) => (
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

// ── Security Controls ─────────────────────────────────────────────────────────
function ControlsTab() {
  const [data, setData] = useState<any>(null);
  useEffect(() => { defenseEvasionAPI.getControls().then(r => setData(r.data)); }, []);
  const controls = data?.controls || [];

  const ICONS: Record<string, string> = {
    antivirus: '🛡', edr: '🔍', firewall: '🔥', audit_logging: '📋', mac: '🔒',
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      {data && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: '0.75rem' }}>
          {[
            { label: 'Active',   value: data.active,   color: '#22c55e' },
            { label: 'Degraded', value: data.degraded, color: '#eab308' },
            { label: 'Disabled', value: data.disabled, color: '#ef4444' },
          ].map(c => (
            <div key={c.label} className="g-card" style={{ padding: '1rem', textAlign: 'center', borderTop: `2px solid ${c.color}` }}>
              <div style={{ fontSize: '1.8rem', fontWeight: 700, color: c.color }}>{c.value}</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-3)' }}>{c.label}</div>
            </div>
          ))}
        </div>
      )}
      <div className="g-card" style={{ overflowX: 'auto', padding: 0 }}>
        <table className="g-table" style={{ width: '100%' }}>
          <thead className="g-thead">
            <tr>
              <th className="g-tr">Control</th><th className="g-tr">Type</th>
              <th className="g-tr">Host</th><th className="g-tr">Status</th>
              <th className="g-tr">Version</th><th className="g-tr">Last Check</th>
              <th className="g-tr">Tampered</th>
            </tr>
          </thead>
          <tbody>
            {controls.map((c: any) => (
              <tr key={c.id} style={{ background: c.tampered ? 'rgba(239,68,68,0.04)' : undefined }}>
                <td className="g-tr" style={{ fontWeight: 600 }}>
                  <span style={{ marginRight: '0.4rem' }}>{ICONS[c.control_type] || '⚙'}</span>{c.control_name}
                </td>
                <td className="g-tr" style={{ fontSize: '0.8rem', color: 'var(--text-3)' }}>{c.control_type}</td>
                <td className="g-tr" style={{ fontFamily: 'monospace', fontSize: '0.82rem' }}>{c.hostname}</td>
                <td className="g-tr">
                  <span style={{
                    background: `${STATUS_COLOR[c.status] || '#666'}18`,
                    color: STATUS_COLOR[c.status] || '#666',
                    padding: '2px 8px', borderRadius: '3px', fontSize: '0.78rem', fontWeight: 600,
                  }}>{c.status.toUpperCase()}</span>
                </td>
                <td className="g-tr" style={{ fontSize: '0.8rem', color: 'var(--text-3)' }}>{c.version}</td>
                <td className="g-tr" style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>{timeAgo(c.last_check)}</td>
                <td className="g-tr">{c.tampered ? <span style={{ color: '#ef4444', fontWeight: 600 }}>⚠ YES</span> : <span style={{ color: '#22c55e' }}>OK</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Tamper & Log Evasion ──────────────────────────────────────────────────────
function TamperTab() {
  const [tamper, setTamper] = useState<any>(null);
  const [logEvasion, setLogEvasion] = useState<any[]>([]);
  const [view, setView] = useState<'tamper' | 'log'>('tamper');

  useEffect(() => {
    defenseEvasionAPI.getTamper().then(r => setTamper(r.data));
    defenseEvasionAPI.getLogEvasion().then(r => setLogEvasion(r.data || []));
  }, []);

  const events = tamper?.events || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', gap: '0.75rem' }}>
        {(['tamper', 'log'] as const).map(v => (
          <button key={v} className={`g-btn ${view === v ? 'g-btn-primary' : 'g-btn-ghost'}`}
            onClick={() => setView(v)}>
            {v === 'tamper' ? `Tamper Events${tamper ? ` (${tamper.total})` : ''}` : 'Log Evasion'}
          </button>
        ))}
      </div>

      <div className="g-card" style={{ padding: 0, overflowX: 'auto' }}>
        {view === 'tamper' ? (
          <table className="g-table" style={{ width: '100%' }}>
            <thead className="g-thead">
              <tr>
                <th className="g-tr">Time</th><th className="g-tr">Host</th>
                <th className="g-tr">Target</th><th className="g-tr">Action</th>
                <th className="g-tr">Actor</th><th className="g-tr">MITRE</th>
                <th className="g-tr">Severity</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e: any) => (
                <tr key={e.id} style={{ background: 'rgba(239,68,68,0.04)' }}>
                  <td className="g-tr" style={{ fontSize: '0.78rem', color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(e.created_at)}</td>
                  <td className="g-tr" style={{ fontFamily: 'monospace', fontSize: '0.82rem' }}>{e.hostname}</td>
                  <td className="g-tr" style={{ fontWeight: 600, fontSize: '0.85rem', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.target}</td>
                  <td className="g-tr" style={{ fontFamily: 'monospace', fontSize: '0.72rem', maxWidth: '260px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-3)' }}>{e.action}</td>
                  <td className="g-tr">{e.actor_name} <span style={{ color: 'var(--text-3)', fontSize: '0.72rem' }}>({e.actor_pid})</span></td>
                  <td className="g-tr"><code style={{ color: '#818cf8', fontSize: '0.78rem' }}>{e.mitre_id}</code></td>
                  <td className="g-tr">
                    <span style={{ background: `${SEV_COLOR[e.severity]}18`, color: SEV_COLOR[e.severity], padding: '2px 6px', borderRadius: '3px', fontSize: '0.75rem', fontWeight: 600 }}>
                      {e.severity.toUpperCase()}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {logEvasion.map((e: any) => (
              <div key={e.id} className="g-card" style={{ padding: '1rem', borderLeft: `3px solid ${SEV_COLOR[e.severity] || '#666'}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
                  <span style={{ fontWeight: 600 }}>{e.technique}</span>
                  <div style={{ display: 'flex', gap: '0.5rem', fontSize: '0.78rem' }}>
                    <span style={{ background: `${SEV_COLOR[e.severity]}18`, color: SEV_COLOR[e.severity], padding: '2px 6px', borderRadius: '3px' }}>{e.severity.toUpperCase()}</span>
                    <code style={{ background: 'rgba(99,102,241,0.1)', color: '#818cf8', padding: '2px 6px', borderRadius: '3px' }}>{e.mitre_id}</code>
                  </div>
                </div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-2)', marginBottom: '0.35rem' }}>{e.description}</div>
                <div style={{ display: 'flex', gap: '1rem', fontSize: '0.78rem', color: 'var(--text-3)' }}>
                  <span>{e.hostname}</span><span>{e.user_name}</span><span>{timeAgo(e.created_at)}</span>
                </div>
                <code style={{ display: 'block', marginTop: '0.4rem', background: 'rgba(0,0,0,0.3)', padding: '0.35rem 0.6rem', borderRadius: '4px', fontSize: '0.72rem', wordBreak: 'break-all' }}>{e.cmdline}</code>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Evasion Events ────────────────────────────────────────────────────────────
const EVASION_CATEGORIES = [
  { key: '',                    label: 'All' },
  { key: 'process_evasion',     label: 'Process' },
  { key: 'script_evasion',      label: 'Script' },
  { key: 'credential_evasion',  label: 'Credential' },
  { key: 'persistence_evasion', label: 'Persistence' },
  { key: 'file_evasion',        label: 'File & Binary' },
  { key: 'network_evasion',     label: 'Network' },
  { key: 'container_evasion',   label: 'Container/Cloud' },
];

function EvasionTab() {
  const [events, setEvents] = useState<any[]>([]);
  const [cat, setCat] = useState('');
  const [selected, setSelected] = useState<any>(null);

  useEffect(() => {
    defenseEvasionAPI.getEvasionEvents(cat ? { category: cat } : undefined).then(r => setEvents(r.data || []));
  }, [cat]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
        {EVASION_CATEGORIES.map(c => (
          <button key={c.key} className={`g-btn ${cat === c.key ? 'g-btn-primary' : 'g-btn-ghost'}`}
            onClick={() => setCat(c.key)} style={{ fontSize: '0.8rem', padding: '0.35rem 0.75rem' }}>
            {c.label}
          </button>
        ))}
      </div>

      <div style={{ display: 'flex', gap: '1rem' }}>
        <div className="g-card" style={{ flex: 1, padding: 0, overflowX: 'auto' }}>
          <table className="g-table" style={{ width: '100%' }}>
            <thead className="g-thead">
              <tr>
                <th className="g-tr">Time</th><th className="g-tr">Host</th>
                <th className="g-tr">Technique</th><th className="g-tr">Category</th>
                <th className="g-tr">MITRE</th><th className="g-tr">Severity</th>
                <th className="g-tr">Process</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e: any) => (
                <tr key={e.id} onClick={() => setSelected(e)} style={{ cursor: 'pointer', background: selected?.id === e.id ? 'rgba(99,102,241,0.08)' : undefined }}>
                  <td className="g-tr" style={{ fontSize: '0.78rem', color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(e.created_at)}</td>
                  <td className="g-tr" style={{ fontFamily: 'monospace', fontSize: '0.82rem' }}>{e.hostname}</td>
                  <td className="g-tr" style={{ fontWeight: 600 }}>{e.technique}</td>
                  <td className="g-tr" style={{ fontSize: '0.78rem' }}>
                    <span style={{ background: 'rgba(99,102,241,0.1)', color: '#818cf8', padding: '1px 6px', borderRadius: '3px' }}>
                      {e.category?.replace(/_/g, ' ')}
                    </span>
                  </td>
                  <td className="g-tr"><code style={{ color: '#818cf8', fontSize: '0.78rem' }}>{e.mitre_id}</code></td>
                  <td className="g-tr">
                    <span style={{ background: `${SEV_COLOR[e.severity]}18`, color: SEV_COLOR[e.severity], padding: '2px 6px', borderRadius: '3px', fontSize: '0.75rem', fontWeight: 600 }}>
                      {e.severity.toUpperCase()}
                    </span>
                  </td>
                  <td className="g-tr" style={{ fontFamily: 'monospace', fontSize: '0.78rem', color: 'var(--text-3)' }}>{e.process_name}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {selected && (
          <div className="g-card" style={{ width: '320px', padding: '1rem', flexShrink: 0, fontSize: '0.82rem' }}>
            <div style={{ fontWeight: 600, color: '#ef4444', marginBottom: '0.75rem' }}>{selected.technique}</div>
            {([
              ['Host', selected.hostname], ['Category', selected.category?.replace(/_/g, ' ')],
              ['MITRE', selected.mitre_id], ['Severity', selected.severity],
              ['User', selected.user_name], ['Process', selected.process_name],
              ['Time', timeAgo(selected.created_at)],
            ] as [string, any][]).map(([k, v]) => (
              <div key={k} style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.35rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.35rem' }}>
                <span style={{ color: 'var(--text-3)', minWidth: '75px' }}>{k}</span>
                <span style={{ wordBreak: 'break-all', color: k === 'Severity' ? SEV_COLOR[v] : undefined, fontWeight: k === 'Severity' ? 600 : undefined }}>{v}</span>
              </div>
            ))}
            <div style={{ marginTop: '0.4rem', fontSize: '0.8rem', color: 'var(--text-2)' }}>{selected.description}</div>
            {selected.cmdline && (
              <code style={{ display: 'block', marginTop: '0.5rem', background: 'rgba(0,0,0,0.3)', padding: '0.4rem', borderRadius: '4px', fontSize: '0.7rem', wordBreak: 'break-all' }}>{selected.cmdline}</code>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Behavioral Analysis ───────────────────────────────────────────────────────
function BehavioralTab() {
  const [behavioral, setBehavioral] = useState<any>(null);
  const [correlation, setCorrelation] = useState<any[]>([]);

  useEffect(() => {
    defenseEvasionAPI.getBehavioral().then(r => setBehavioral(r.data));
    defenseEvasionAPI.getCorrelation().then(r => setCorrelation(r.data || []));
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div className="g-card" style={{ padding: '1.25rem' }}>
        <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Behavioral Detections</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {(behavioral?.detections || []).map((d: any) => (
            <div key={d.id} style={{ padding: '1rem', background: 'rgba(255,255,255,0.03)', borderRadius: '6px', borderLeft: `3px solid ${SEV_COLOR[d.severity] || '#666'}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
                <span style={{ fontWeight: 600 }}>{d.rule}</span>
                <div style={{ display: 'flex', gap: '0.5rem', fontSize: '0.78rem' }}>
                  <span style={{ background: `${SEV_COLOR[d.severity]}18`, color: SEV_COLOR[d.severity], padding: '2px 6px', borderRadius: '3px' }}>{d.severity.toUpperCase()}</span>
                  <code style={{ background: 'rgba(99,102,241,0.1)', color: '#818cf8', padding: '2px 6px', borderRadius: '3px' }}>{d.mitre}</code>
                  <span style={{ color: 'var(--text-3)' }}>{d.hostname}</span>
                </div>
              </div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-2)', marginBottom: '0.4rem' }}>{d.description}</div>
              <code style={{ display: 'block', background: 'rgba(0,0,0,0.3)', padding: '0.35rem 0.6rem', borderRadius: '4px', fontSize: '0.72rem', wordBreak: 'break-all' }}>{d.cmdline}</code>
            </div>
          ))}
        </div>
      </div>

      <div className="g-card" style={{ padding: '1.25rem' }}>
        <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Correlated Incidents</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {correlation.map((inc: any) => (
            <div key={inc.id} style={{ padding: '1rem', background: 'rgba(239,68,68,0.05)', borderRadius: '6px', border: '1px solid rgba(239,68,68,0.2)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
                <div>
                  <code style={{ fontSize: '0.75rem', color: 'var(--text-3)', marginRight: '0.5rem' }}>{inc.incident_id}</code>
                  <span style={{ fontWeight: 600 }}>{inc.title}</span>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem', fontSize: '0.78rem', alignItems: 'center' }}>
                  <span style={{ background: `${SEV_COLOR[inc.severity]}18`, color: SEV_COLOR[inc.severity], padding: '2px 6px', borderRadius: '3px' }}>{inc.severity.toUpperCase()}</span>
                  <span style={{ color: 'var(--text-3)' }}>{inc.hostname}</span>
                </div>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', marginTop: '0.35rem' }}>
                {inc.techniques.split(', ').map((t: string) => (
                  <span key={t} style={{ background: 'rgba(239,68,68,0.1)', color: '#ef4444', padding: '1px 7px', borderRadius: '3px', fontSize: '0.72rem' }}>{t}</span>
                ))}
              </div>
              <div style={{ marginTop: '0.35rem', fontSize: '0.75rem', color: 'var(--text-3)' }}>Detected {timeAgo(inc.created_at)}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── MITRE Coverage ────────────────────────────────────────────────────────────
function MITRETab() {
  const [mitre, setMitre] = useState<any>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => { defenseEvasionAPI.getMITRE().then(r => setMitre(r.data)); }, []);
  if (!mitre) return <div style={{ color: 'var(--text-3)', padding: '2rem' }}>Loading…</div>;

  const detected = mitre.techniques?.filter((t: any) => t.detected).length || 0;
  const total = mitre.techniques?.length || 1;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div className="g-card" style={{ padding: '1.25rem', borderLeft: '4px solid var(--accent)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>MITRE ATT&CK Tactic</div>
            <div style={{ fontWeight: 700, fontSize: '1.1rem', marginTop: '0.2rem' }}>
              {mitre.tactic?.id} — {mitre.tactic?.name}
            </div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '2rem', fontWeight: 700, color: '#3b82f6' }}>{Math.round((detected / total) * 100)}%</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-3)' }}>{detected}/{total} techniques detected</div>
          </div>
        </div>
        <div style={{ marginTop: '0.75rem', height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
          <div style={{ width: `${(detected / total) * 100}%`, height: '100%', borderRadius: '4px', background: '#3b82f6' }} />
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        {mitre.techniques?.map((t: any) => (
          <div key={t.id} className="g-card" style={{ padding: 0, overflow: 'hidden', opacity: t.detected ? 1 : 0.55 }}>
            <div
              style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.85rem 1rem', cursor: t.sub_techniques?.length ? 'pointer' : 'default', borderLeft: `4px solid ${t.detected ? SEV_COLOR[t.severity] || '#666' : 'var(--border)'}` }}
              onClick={() => setExpanded(expanded === t.id ? null : t.id)}
            >
              <code style={{ fontSize: '0.8rem', color: t.detected ? '#ef4444' : 'var(--text-3)', minWidth: '60px' }}>{t.id}</code>
              <span style={{ fontWeight: 600, flex: 1 }}>{t.name}</span>
              {t.detected && (
                <span style={{ background: `${SEV_COLOR[t.severity]}18`, color: SEV_COLOR[t.severity], padding: '2px 8px', borderRadius: '3px', fontSize: '0.75rem' }}>
                  ×{t.count} {t.severity}
                </span>
              )}
              {t.sub_techniques?.length > 0 && (
                <span style={{ color: 'var(--text-3)', fontSize: '0.8rem' }}>{expanded === t.id ? '▲' : '▼'} {t.sub_techniques.length}</span>
              )}
            </div>
            {expanded === t.id && t.sub_techniques?.length > 0 && (
              <div style={{ borderTop: '1px solid var(--border)', background: 'rgba(0,0,0,0.15)' }}>
                {t.sub_techniques.map((st: any) => (
                  <div key={st.id} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.6rem 1rem 0.6rem 2rem', borderBottom: '1px solid rgba(255,255,255,0.04)', opacity: st.detected ? 1 : 0.5 }}>
                    <code style={{ fontSize: '0.75rem', color: st.detected ? '#ef4444' : 'var(--text-3)', minWidth: '80px' }}>{st.id}</code>
                    <span style={{ fontSize: '0.82rem', flex: 1 }}>{st.name}</span>
                    {st.detected
                      ? <span style={{ background: 'rgba(239,68,68,0.15)', color: '#ef4444', padding: '1px 6px', borderRadius: '3px', fontSize: '0.7rem' }}>DETECTED ×{st.count}</span>
                      : <span style={{ color: 'var(--text-3)', fontSize: '0.72rem' }}>Not detected</span>
                    }
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Threat Intelligence ───────────────────────────────────────────────────────
function IntelligenceTab() {
  const [intel, setIntel] = useState<any>(null);
  useEffect(() => { defenseEvasionAPI.getThreatIntel().then(r => setIntel(r.data)); }, []);
  if (!intel) return <div style={{ color: 'var(--text-3)', padding: '2rem' }}>Loading…</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div className="g-card" style={{ padding: '1.25rem' }}>
        <div style={{ fontWeight: 600, marginBottom: '0.75rem', color: '#ef4444' }}>Malware Families — Evasion Matches</div>
        {intel.malware_families?.map((m: any, i: number) => (
          <div key={i} style={{ padding: '0.85rem', background: 'rgba(239,68,68,0.06)', borderRadius: '6px', marginBottom: '0.5rem', border: '1px solid rgba(239,68,68,0.18)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
              <span style={{ fontWeight: 600, color: '#ef4444' }}>{m.name}</span>
              <div style={{ display: 'flex', gap: '0.75rem', fontSize: '0.78rem' }}>
                <span style={{ color: '#22c55e' }}>Confidence: {m.confidence}%</span>
                <span style={{ color: 'var(--text-3)' }}>IOC matches: {m.ioc_matches}</span>
              </div>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
              {m.evasion_techniques?.map((t: string) => (
                <span key={t} style={{ background: 'rgba(239,68,68,0.1)', color: '#ef4444', padding: '1px 6px', borderRadius: '3px', fontSize: '0.72rem' }}>{t}</span>
              ))}
            </div>
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
                {a.known_techniques?.map((t: string) => (
                  <code key={t} style={{ background: 'rgba(99,102,241,0.1)', color: '#818cf8', padding: '1px 5px', borderRadius: '3px', fontSize: '0.72rem' }}>{t}</code>
                ))}
              </div>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: '1.25rem' }}>
          <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Active Campaigns</div>
          {intel.campaigns?.map((c: any, i: number) => (
            <div key={i} style={{ marginBottom: '0.75rem', paddingBottom: '0.75rem', borderBottom: '1px solid var(--border)' }}>
              <div style={{ fontWeight: 600, marginBottom: '0.2rem' }}>{c.name}</div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>Actor: <span style={{ color: '#f97316' }}>{c.actor}</span></div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-3)', marginTop: '0.15rem' }}>{c.technique}</div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-3)', marginTop: '0.25rem' }}>Detected {timeAgo(c.detected)}</div>
            </div>
          ))}
          <div style={{ fontWeight: 600, marginTop: '0.75rem', marginBottom: '0.5rem' }}>IOC Matches</div>
          {intel.ioc_matches?.map((ioc: any, i: number) => (
            <div key={i} style={{ padding: '0.5rem', background: 'rgba(239,68,68,0.07)', borderRadius: '4px', marginBottom: '0.4rem' }}>
              <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.2rem' }}>
                <span style={{ fontSize: '0.72rem', background: 'rgba(239,68,68,0.15)', color: '#ef4444', padding: '1px 5px', borderRadius: '3px' }}>{ioc.type}</span>
                <span style={{ fontSize: '0.72rem', color: '#22c55e' }}>{ioc.family}</span>
              </div>
              <code style={{ fontSize: '0.68rem', color: 'var(--text-3)', wordBreak: 'break-all', display: 'block' }}>{ioc.value}</code>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-3)', marginTop: '0.15rem' }}>{ioc.context}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Analytics ─────────────────────────────────────────────────────────────────
function AnalyticsTab() {
  const [analytics, setAnalytics] = useState<any>(null);
  const [validation, setValidation] = useState<any>(null);
  const [view, setView] = useState<'analytics' | 'validation'>('analytics');

  useEffect(() => {
    defenseEvasionAPI.getAnalytics().then(r => setAnalytics(r.data));
    defenseEvasionAPI.getValidation().then(r => setValidation(r.data));
  }, []);

  if (!analytics) return <div style={{ color: 'var(--text-3)', padding: '2rem' }}>Loading…</div>;

  const maxTrend = Math.max(...(analytics.evasion_trend?.map((p: any) => p.count) || [1]), 1);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div style={{ display: 'flex', gap: '0.75rem' }}>
        {(['analytics', 'validation'] as const).map(v => (
          <button key={v} className={`g-btn ${view === v ? 'g-btn-primary' : 'g-btn-ghost'}`} onClick={() => setView(v)}>
            {v === 'analytics' ? 'Analytics' : 'Detection Validation'}
          </button>
        ))}
      </div>

      {view === 'analytics' && (
        <>
          <div className="g-card" style={{ padding: '1.25rem' }}>
            <div style={{ fontWeight: 600, marginBottom: '1rem' }}>Evasion Trend (8d)</div>
            <div style={{ display: 'flex', alignItems: 'flex-end', gap: '4px', height: '100px' }}>
              {analytics.evasion_trend?.map((p: any, i: number) => (
                <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '4px' }}>
                  <div style={{
                    width: '100%', background: p.count > 5 ? '#ef4444' : p.count > 2 ? '#f97316' : '#3b82f6',
                    height: `${Math.max((p.count / maxTrend) * 80, p.count > 0 ? 6 : 2)}px`,
                    borderRadius: '3px 3px 0 0',
                  }} title={`${p.date}: ${p.count}`} />
                  <div style={{ fontSize: '0.6rem', color: 'var(--text-3)', transform: 'rotate(-25deg)', whiteSpace: 'nowrap' }}>{p.date.slice(5)}</div>
                </div>
              ))}
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <div className="g-card" style={{ padding: '1.25rem' }}>
              <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Top Evasion Techniques</div>
              {analytics.top_techniques?.map((t: any) => (
                <div key={t.technique} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.6rem' }}>
                  <span style={{ minWidth: '160px', fontSize: '0.82rem' }}>{t.technique}</span>
                  <div style={{ flex: 1, height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
                    <div style={{ width: `${(t.count / 9) * 100}%`, height: '100%', borderRadius: '4px', background: SEV_COLOR[t.severity] || '#666' }} />
                  </div>
                  <span style={{ fontSize: '0.8rem', minWidth: '20px', textAlign: 'right' }}>{t.count}</span>
                </div>
              ))}
            </div>
            <div className="g-card" style={{ padding: '1.25rem' }}>
              <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Most Targeted Endpoints</div>
              {analytics.most_targeted_endpoints?.map((e: any) => (
                <div key={e.hostname} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.6rem' }}>
                  <span style={{ minWidth: '130px', fontSize: '0.82rem', fontFamily: 'monospace' }}>{e.hostname}</span>
                  <div style={{ flex: 1, height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
                    <div style={{ width: `${e.risk}%`, height: '100%', borderRadius: '4px', background: e.risk >= 90 ? '#ef4444' : e.risk >= 70 ? '#f97316' : '#eab308' }} />
                  </div>
                  <span style={{ fontSize: '0.8rem', color: e.risk >= 90 ? '#ef4444' : 'var(--text-2)', minWidth: '25px', textAlign: 'right' }}>{e.risk}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="g-card" style={{ padding: '1.25rem' }}>
            <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Security Control Coverage</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
              {analytics.control_status?.map((c: any) => (
                <div key={c.control} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <span style={{ minWidth: '160px', fontSize: '0.82rem' }}>{c.control}</span>
                  <span style={{ width: '80px', fontSize: '0.75rem', background: `${STATUS_COLOR[c.status] || '#666'}18`, color: STATUS_COLOR[c.status] || '#666', padding: '1px 6px', borderRadius: '3px', textAlign: 'center' }}>{c.status}</span>
                  <div style={{ flex: 1, height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
                    <div style={{ width: `${c.coverage}%`, height: '100%', borderRadius: '4px', background: c.coverage >= 80 ? '#22c55e' : c.coverage >= 50 ? '#eab308' : '#ef4444' }} />
                  </div>
                  <span style={{ fontSize: '0.8rem', minWidth: '35px', textAlign: 'right' }}>{c.coverage}%</span>
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      {view === 'validation' && validation && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(160px,1fr))', gap: '0.75rem' }}>
            {[
              { label: 'Detection Success Rate', value: `${validation.detection_success_rate}%`, color: '#22c55e' },
              { label: 'Missed Attempts',         value: validation.missed_attempts,              color: '#ef4444' },
              { label: 'False Positives',         value: validation.false_positives,              color: '#eab308' },
              { label: 'Avg Time to Detect',      value: `${validation.avg_time_to_detect_seconds}s`, color: '#3b82f6' },
            ].map(c => (
              <div key={c.label} className="g-card" style={{ padding: '1rem', textAlign: 'center', borderTop: `2px solid ${c.color}` }}>
                <div style={{ fontSize: '1.6rem', fontWeight: 700, color: c.color }}>{c.value}</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-3)', marginTop: '0.25rem' }}>{c.label}</div>
              </div>
            ))}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <div className="g-card" style={{ padding: '1.25rem' }}>
              <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Coverage by Platform</div>
              {validation.coverage_by_platform?.map((p: any) => (
                <div key={p.platform} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.6rem' }}>
                  <span style={{ minWidth: '80px', fontSize: '0.82rem' }}>{p.platform}</span>
                  <div style={{ flex: 1, height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
                    <div style={{ width: `${p.coverage}%`, height: '100%', borderRadius: '4px', background: p.coverage >= 80 ? '#22c55e' : p.coverage >= 60 ? '#eab308' : '#ef4444' }} />
                  </div>
                  <span style={{ fontSize: '0.8rem', minWidth: '35px', textAlign: 'right' }}>{p.coverage}%</span>
                </div>
              ))}
            </div>
            <div className="g-card" style={{ padding: '1.25rem' }}>
              <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>Coverage by Evasion Category</div>
              {validation.technique_coverage?.map((t: any) => (
                <div key={t.category} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.6rem' }}>
                  <span style={{ minWidth: '120px', fontSize: '0.82rem' }}>{t.category}</span>
                  <div style={{ flex: 1, height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
                    <div style={{ width: `${(t.covered / t.total) * 100}%`, height: '100%', borderRadius: '4px', background: '#3b82f6' }} />
                  </div>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-3)', minWidth: '40px', textAlign: 'right' }}>{t.covered}/{t.total}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Response ──────────────────────────────────────────────────────────────────
function ResponseTab() {
  const [timeline, setTimeline] = useState<any[]>([]);
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState<Record<string, boolean>>({});
  const [reportLoading, setReportLoading] = useState(false);
  const [report, setReport] = useState<any>(null);
  const [aiQuery, setAiQuery] = useState('');
  const [aiResult, setAiResult] = useState<any>(null);
  const [aiLoading, setAiLoading] = useState(false);

  useEffect(() => { defenseEvasionAPI.getTimeline().then(r => setTimeline(r.data || [])); }, []);

  const respond = async (action: string) => {
    setLoading(l => ({ ...l, [action]: true }));
    const r = await defenseEvasionAPI.respond({ action, hostname: 'WS-ANALYST-01', target: 'Windows Defender', reason: 'Manual response' });
    setResult(r.data);
    setLoading(l => ({ ...l, [action]: false }));
  };

  const generateReport = async () => {
    setReportLoading(true);
    const r = await defenseEvasionAPI.generateReport({ report_type: 'executive' });
    setReport(r.data);
    setReportLoading(false);
  };

  const runAI = async () => {
    if (!aiQuery.trim()) return;
    setAiLoading(true);
    const r = await defenseEvasionAPI.analyzeAI({ content: aiQuery });
    setAiResult(r.data);
    setAiLoading(false);
  };

  const ACTIONS = [
    { id: 'restart_security_services', label: 'Restart Security Services', desc: 'Restart Defender, EDR, Sysmon, Audit logging', color: '#22c55e' },
    { id: 'reenable_defender',         label: 'Re-enable Defender',         desc: 'Force enable and update definitions',          color: '#3b82f6' },
    { id: 'restore_firewall',          label: 'Restore Firewall Policy',    desc: 'Restore from last known good configuration',   color: '#6366f1' },
    { id: 'isolate_endpoint',          label: 'Isolate Endpoint',           desc: 'Revoke all network access',                   color: '#a855f7' },
    { id: 'kill_process',              label: 'Kill Process',               desc: 'Terminate evasion process',                   color: '#ef4444' },
    { id: 'collect_memory',            label: 'Collect Memory',             desc: 'Full memory dump for forensics',              color: '#f97316' },
    { id: 'create_incident',           label: 'Create Incident',            desc: 'Assign to SOC Tier 2',                        color: '#eab308' },
    { id: 'run_soar',                  label: 'Run SOAR Playbook',          desc: 'Execute DE-RESPONSE-01',                      color: '#22c55e' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {result && (
        <div style={{ background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.3)', borderRadius: '8px', padding: '1rem' }}>
          <div style={{ fontWeight: 600, color: '#22c55e', marginBottom: '0.25rem' }}>Action Executed: {result.action}</div>
          <div style={{ fontSize: '0.85rem' }}>{result.message}</div>
          {result.hostname && <div style={{ fontSize: '0.78rem', color: 'var(--text-3)', marginTop: '0.25rem' }}>Host: {result.hostname}</div>}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(270px,1fr))', gap: '0.75rem' }}>
        {ACTIONS.map(a => (
          <div key={a.id} className="g-card" style={{ padding: '1rem', borderLeft: `3px solid ${a.color}` }}>
            <div style={{ fontWeight: 600, marginBottom: '0.2rem' }}>{a.label}</div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-3)', marginBottom: '0.75rem' }}>{a.desc}</div>
            <button className="g-btn g-btn-primary" style={{ background: a.color, border: 'none', width: '100%', opacity: loading[a.id] ? 0.7 : 1 }}
              disabled={loading[a.id]} onClick={() => respond(a.id)}>
              {loading[a.id] ? 'Executing…' : a.label}
            </button>
          </div>
        ))}
      </div>

      <div className="g-card" style={{ padding: '1.25rem' }}>
        <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}>AI-Assisted Analysis</div>
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
          <input className="g-input" style={{ flex: 1 }} placeholder="Describe an evasion event or ask about a technique…"
            value={aiQuery} onChange={e => setAiQuery(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') runAI(); }} />
          <button className="g-btn g-btn-primary" onClick={runAI} disabled={aiLoading}>
            {aiLoading ? 'Analyzing…' : 'Analyze'}
          </button>
        </div>
        {aiResult && (
          <div style={{ background: 'rgba(99,102,241,0.07)', padding: '1rem', borderRadius: '6px', border: '1px solid rgba(99,102,241,0.2)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
              <span style={{ fontWeight: 600, color: '#ef4444' }}>{aiResult.verdict?.replace(/_/g, ' ').toUpperCase()}</span>
              {aiResult.confidence && <span style={{ fontSize: '0.78rem', color: '#22c55e' }}>Confidence: {aiResult.confidence}%</span>}
            </div>
            {aiResult.technique && <div style={{ fontSize: '0.82rem', marginBottom: '0.4rem' }}><strong>Technique:</strong> <code style={{ color: '#818cf8' }}>{aiResult.mitre_id}</code> {aiResult.technique}</div>}
            {aiResult.explanation && <div style={{ fontSize: '0.82rem', color: 'var(--text-2)', marginBottom: '0.5rem' }}>{aiResult.explanation}</div>}
            {aiResult.answer && <div style={{ fontSize: '0.82rem', color: 'var(--text-2)', marginBottom: '0.5rem' }}>{aiResult.answer}</div>}
            {aiResult.attack_chain && (
              <div style={{ marginBottom: '0.5rem' }}>
                <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-3)', marginBottom: '0.3rem' }}>Attack Chain</div>
                {aiResult.attack_chain.map((step: string, i: number) => (
                  <div key={i} style={{ fontSize: '0.78rem', color: '#f97316', paddingLeft: '0.5rem', borderLeft: '2px solid #f97316', marginBottom: '0.2rem' }}>{step}</div>
                ))}
              </div>
            )}
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
          <span style={{ fontWeight: 600 }}>Evasion Timeline</span>
          <span style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>
            PowerShell → AMSI Bypass → Defender Disabled → Logs Cleared → Payload
          </span>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0' }}>
          {timeline.map((e: any, i: number) => (
            <div key={e.id} style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
                <div style={{ width: '12px', height: '12px', borderRadius: '50%', background: SEV_COLOR[e.severity] || '#666', marginTop: '4px', flexShrink: 0 }} />
                {i < timeline.length - 1 && <div style={{ width: '2px', flex: 1, minHeight: '32px', background: 'var(--border)' }} />}
              </div>
              <div style={{ paddingBottom: '1rem', flex: 1 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.2rem' }}>
                  <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>{e.technique}</span>
                  <div style={{ display: 'flex', gap: '0.5rem', fontSize: '0.72rem', color: 'var(--text-3)' }}>
                    <code style={{ color: '#818cf8' }}>{e.mitre_id}</code>
                    <span>{timeAgo(e.created_at)}</span>
                  </div>
                </div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>{e.description}</div>
                {e.cmdline && <code style={{ display: 'block', marginTop: '0.25rem', background: 'rgba(0,0,0,0.25)', padding: '0.25rem 0.5rem', borderRadius: '3px', fontSize: '0.7rem', wordBreak: 'break-all', color: 'var(--text-3)' }}>{e.cmdline}</code>}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="g-card" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
          <span style={{ fontWeight: 600 }}>Defense Evasion Report</span>
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
            {report.mitre_techniques && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                {report.mitre_techniques.map((t: string) => (
                  <code key={t} style={{ background: 'rgba(99,102,241,0.1)', color: '#818cf8', padding: '2px 7px', borderRadius: '3px', fontSize: '0.75rem' }}>{t}</code>
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
                <span>Events: <strong style={{ color: 'var(--text-1)' }}>{report.metrics.total_events}</strong></span>
                <span>Tamper: <strong style={{ color: '#ef4444' }}>{report.metrics.tamper_events}</strong></span>
                <span>Disabled Controls: <strong style={{ color: '#ef4444' }}>{report.metrics.disabled_controls}</strong></span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────
export default function DefenseEvasionPage() {
  const [tab, setTab] = useState<Tab>('overview');
  const [dash, setDash] = useState<any>(null);
  const loaded = useRef<Record<string, boolean>>({});

  useEffect(() => { defenseEvasionAPI.getDashboard().then(r => setDash(r.data)); }, []);

  if (!loaded.current[tab]) loaded.current[tab] = true;

  const tabs = Object.keys(TAB_LABELS) as Tab[];

  return (
    <RootLayout>
      <div style={{ padding: '1.5rem', maxWidth: '1400px', margin: '0 auto' }}>
        <div style={{ marginBottom: '1.5rem' }}>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Defense Evasion Detection</h1>
          <p style={{ color: 'var(--text-3)', margin: '0.25rem 0 0', fontSize: '0.85rem' }}>
            Security control monitoring, tamper detection, AMSI/log/process evasion — MITRE TA0005
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.25rem', marginBottom: '1.5rem', borderBottom: '1px solid var(--border)', overflowX: 'auto' }}>
          {tabs.map(t => (
            <button key={t} onClick={() => setTab(t)} style={{
              background: 'none', border: 'none', cursor: 'pointer',
              padding: '0.6rem 1rem', fontSize: '0.85rem', whiteSpace: 'nowrap',
              color: tab === t ? 'var(--accent)' : 'var(--text-3)',
              borderBottom: `2px solid ${tab === t ? 'var(--accent)' : 'transparent'}`,
              marginBottom: '-1px', transition: 'all 0.15s',
            }}>{TAB_LABELS[t]}</button>
          ))}
        </div>

        <div style={{ display: loaded.current['overview'] ? 'block' : 'none' }}>
          <OverviewTab dash={dash} />
        </div>
        <div style={{ display: loaded.current['controls'] && tab === 'controls' ? 'block' : 'none' }}>
          {loaded.current['controls'] && <ControlsTab />}
        </div>
        <div style={{ display: loaded.current['tamper'] && tab === 'tamper' ? 'block' : 'none' }}>
          {loaded.current['tamper'] && <TamperTab />}
        </div>
        <div style={{ display: loaded.current['evasion'] && tab === 'evasion' ? 'block' : 'none' }}>
          {loaded.current['evasion'] && <EvasionTab />}
        </div>
        <div style={{ display: loaded.current['behavioral'] && tab === 'behavioral' ? 'block' : 'none' }}>
          {loaded.current['behavioral'] && <BehavioralTab />}
        </div>
        <div style={{ display: loaded.current['mitre'] && tab === 'mitre' ? 'block' : 'none' }}>
          {loaded.current['mitre'] && <MITRETab />}
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
