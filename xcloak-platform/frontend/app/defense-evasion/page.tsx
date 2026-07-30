'use client';
import { useState, useEffect, useRef } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { defenseEvasionAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import { MetricCard, DataTable, SectionCard, TabBar, ActionButton } from '@/components/design-system';
import {
  LayoutDashboard, ShieldCheck, ShieldAlert, Ghost, Activity, Target, Radar, BarChart3, Siren,
  Shield, Search, Flame, ScrollText, Lock, AlertTriangle, ChevronUp, ChevronDown, Cog,
} from 'lucide-react';

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
const TAB_ICONS: Record<Tab, any> = {
  overview: LayoutDashboard, controls: ShieldCheck, tamper: ShieldAlert, evasion: Ghost,
  behavioral: Activity, mitre: Target, intelligence: Radar, analytics: BarChart3, response: Siren,
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
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        {cards.map(c => <MetricCard key={c.label} label={c.label} value={c.value} color={c.color} />)}
      </div>
      <SectionCard title="Detected Evasion Categories">
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
          {(dash.top_categories || []).map((t: string) => (
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

// ── Security Controls ─────────────────────────────────────────────────────────
const CONTROL_ICONS: Record<string, any> = {
  antivirus: Shield, edr: Search, firewall: Flame, audit_logging: ScrollText, mac: Lock,
};

function ControlsTab() {
  const [data, setData] = useState<any>(null);
  useEffect(() => { defenseEvasionAPI.getControls().then(r => setData(r.data)); }, []);
  const controls = data?.controls || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      {data && (
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          <MetricCard label="Active" value={data.active} color="#22c55e" />
          <MetricCard label="Degraded" value={data.degraded} color="#eab308" />
          <MetricCard label="Disabled" value={data.disabled} color="#ef4444" />
        </div>
      )}
      <DataTable<any>
        rows={controls}
        rowKey={(c: any) => c.id}
        rowStyle={(c: any) => c.tampered ? { background: 'rgba(239,68,68,0.04)' } : undefined}
        columns={[
          { key: 'control_name', header: 'Control', render: (c: any) => {
            const Icon = CONTROL_ICONS[c.control_type] || Cog;
            return (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontWeight: 600 }}>
                <Icon style={{ width: 13, height: 13, flexShrink: 0 }} />{c.control_name}
              </span>
            );
          } },
          { key: 'control_type', header: 'Type', render: (c: any) => <span style={{ fontSize: '0.8rem', color: 'var(--text-3)' }}>{c.control_type}</span> },
          { key: 'hostname', header: 'Host', render: (c: any) => <span style={{ fontFamily: 'monospace', fontSize: '0.82rem' }}>{c.hostname}</span> },
          { key: 'status', header: 'Status', render: (c: any) => (
            <span style={{ background: `${STATUS_COLOR[c.status] || '#666'}18`, color: STATUS_COLOR[c.status] || '#666', padding: '2px 8px', borderRadius: '3px', fontSize: '0.78rem', fontWeight: 600 }}>{c.status.toUpperCase()}</span>
          ) },
          { key: 'version', header: 'Version', render: (c: any) => <span style={{ fontSize: '0.8rem', color: 'var(--text-3)' }}>{c.version}</span> },
          { key: 'last_check', header: 'Last Check', render: (c: any) => <span style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>{timeAgo(c.last_check)}</span> },
          { key: 'tampered', header: 'Tampered', render: (c: any) => c.tampered
            ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: '#ef4444', fontWeight: 600 }}><AlertTriangle style={{ width: 12, height: 12 }} /> YES</span>
            : <span style={{ color: '#22c55e' }}>OK</span> },
        ]}
      />
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
          <ActionButton key={v} variant={view === v ? 'primary' : 'ghost'} onClick={() => setView(v)}>
            {v === 'tamper' ? `Tamper Events${tamper ? ` (${tamper.total})` : ''}` : 'Log Evasion'}
          </ActionButton>
        ))}
      </div>

      {view === 'tamper' ? (
        <DataTable<any>
          rows={events}
          rowKey={(e: any) => e.id}
          rowStyle={() => ({ background: 'rgba(239,68,68,0.04)' })}
          columns={[
            { key: 'created_at', header: 'Time', render: (e: any) => <span style={{ fontSize: '0.78rem', color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(e.created_at)}</span> },
            { key: 'hostname', header: 'Host', render: (e: any) => <span style={{ fontFamily: 'monospace', fontSize: '0.82rem' }}>{e.hostname}</span> },
            { key: 'target', header: 'Target', render: (e: any) => <span style={{ fontWeight: 600, fontSize: '0.85rem', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>{e.target}</span> },
            { key: 'action', header: 'Action', render: (e: any) => <span style={{ fontFamily: 'monospace', fontSize: '0.72rem', maxWidth: '260px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-3)', display: 'block' }}>{e.action}</span> },
            { key: 'actor', header: 'Actor', render: (e: any) => <span>{e.actor_name} <span style={{ color: 'var(--text-3)', fontSize: '0.72rem' }}>({e.actor_pid})</span></span> },
            { key: 'mitre_id', header: 'MITRE', render: (e: any) => <code style={{ color: '#818cf8', fontSize: '0.78rem' }}>{e.mitre_id}</code> },
            { key: 'severity', header: 'Severity', render: (e: any) => (
              <span style={{ background: `${SEV_COLOR[e.severity]}18`, color: SEV_COLOR[e.severity], padding: '2px 6px', borderRadius: '3px', fontSize: '0.75rem', fontWeight: 600 }}>
                {e.severity.toUpperCase()}
              </span>
            ) },
          ]}
        />
      ) : (
        <div className="g-card" style={{ padding: 0, overflowX: 'auto' }}>
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
        </div>
      )}
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
          <ActionButton key={c.key} variant={cat === c.key ? 'primary' : 'ghost'} onClick={() => setCat(c.key)} style={{ fontSize: '0.8rem', padding: '0.35rem 0.75rem' }}>
            {c.label}
          </ActionButton>
        ))}
      </div>

      <div style={{ display: 'flex', gap: '1rem' }}>
        <div style={{ flex: 1 }}>
          <DataTable<any>
            rows={events}
            rowKey={(e: any) => e.id}
            onRowClick={e => setSelected(e)}
            rowStyle={(e: any) => selected?.id === e.id ? { background: 'rgba(99,102,241,0.08)' } : undefined}
            columns={[
              { key: 'created_at', header: 'Time', render: (e: any) => <span style={{ fontSize: '0.78rem', color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(e.created_at)}</span> },
              { key: 'hostname', header: 'Host', render: (e: any) => <span style={{ fontFamily: 'monospace', fontSize: '0.82rem' }}>{e.hostname}</span> },
              { key: 'technique', header: 'Technique', render: (e: any) => <span style={{ fontWeight: 600 }}>{e.technique}</span> },
              { key: 'category', header: 'Category', render: (e: any) => (
                <span style={{ background: 'rgba(99,102,241,0.1)', color: '#818cf8', padding: '1px 6px', borderRadius: '3px', fontSize: '0.78rem' }}>
                  {e.category?.replace(/_/g, ' ')}
                </span>
              ) },
              { key: 'mitre_id', header: 'MITRE', render: (e: any) => <code style={{ color: '#818cf8', fontSize: '0.78rem' }}>{e.mitre_id}</code> },
              { key: 'severity', header: 'Severity', render: (e: any) => (
                <span style={{ background: `${SEV_COLOR[e.severity]}18`, color: SEV_COLOR[e.severity], padding: '2px 6px', borderRadius: '3px', fontSize: '0.75rem', fontWeight: 600 }}>
                  {e.severity.toUpperCase()}
                </span>
              ) },
              { key: 'process_name', header: 'Process', render: (e: any) => <span style={{ fontFamily: 'monospace', fontSize: '0.78rem', color: 'var(--text-3)' }}>{e.process_name}</span> },
            ]}
          />
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
      <SectionCard title="Behavioral Detections">
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
      </SectionCard>

      <SectionCard title="Correlated Incidents">
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
      </SectionCard>
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
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: 'var(--text-3)', fontSize: '0.8rem' }}>
                  {expanded === t.id ? <ChevronUp style={{ width: 12, height: 12 }} /> : <ChevronDown style={{ width: 12, height: 12 }} />} {t.sub_techniques.length}
                </span>
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
      <SectionCard title="Observed Evasion Techniques">
        <div style={{ fontSize: '0.75rem', color: 'var(--text-3)', marginBottom: '0.75rem' }}>
          No malware-family/threat-actor attribution or campaign-tracking data exists in this schema — this reflects real technique frequency observed in this tenant's own events instead.
        </div>
        {(intel.observed_techniques ?? []).length === 0 && <div style={{ fontSize: '0.85rem', color: 'var(--text-3)' }}>No evasion events observed yet.</div>}
        {intel.observed_techniques?.map((t: any, i: number) => (
          <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.6rem 0', borderBottom: '1px solid var(--border)' }}>
            <span style={{ fontSize: '0.85rem' }}>{t.technique}</span>
            <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center' }}>
              <span style={{ fontSize: '0.72rem', background: `${SEV_COLOR[t.severity] || '#666'}18`, color: SEV_COLOR[t.severity] || '#666', padding: '1px 6px', borderRadius: '3px' }}>{t.severity}</span>
              <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>{t.count}</span>
            </div>
          </div>
        ))}
      </SectionCard>
    </div>
  );
}

// ── Analytics ─────────────────────────────────────────────────────────────────
function AnalyticsTab() {
  const [analytics, setAnalytics] = useState<any>(null);

  useEffect(() => {
    defenseEvasionAPI.getAnalytics().then(r => setAnalytics(r.data));
  }, []);

  if (!analytics) return <div style={{ color: 'var(--text-3)', padding: '2rem' }}>Loading…</div>;

  const maxTrend = Math.max(...(analytics.evasion_trend?.map((p: any) => p.count) || [1]), 1);
  const maxTech = Math.max(...(analytics.top_techniques?.map((t: any) => t.count) || [1]), 1);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <SectionCard title="Evasion Trend (8d)">
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
      </SectionCard>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <SectionCard title="Top Evasion Techniques">
          {analytics.top_techniques?.map((t: any) => (
            <div key={t.technique} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.6rem' }}>
              <span style={{ minWidth: '160px', fontSize: '0.82rem' }}>{t.technique}</span>
              <div style={{ flex: 1, height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
                <div style={{ width: `${(t.count / maxTech) * 100}%`, height: '100%', borderRadius: '4px', background: SEV_COLOR[t.severity] || '#666' }} />
              </div>
              <span style={{ fontSize: '0.8rem', minWidth: '20px', textAlign: 'right' }}>{t.count}</span>
            </div>
          ))}
        </SectionCard>
        <SectionCard title="Most Targeted Endpoints">
          {analytics.most_targeted_endpoints?.map((e: any) => (
            <div key={e.hostname} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.6rem' }}>
              <span style={{ minWidth: '130px', fontSize: '0.82rem', fontFamily: 'monospace' }}>{e.hostname}</span>
              <div style={{ flex: 1, height: '8px', borderRadius: '4px', background: 'rgba(255,255,255,0.08)' }}>
                <div style={{ width: `${e.risk}%`, height: '100%', borderRadius: '4px', background: e.risk >= 90 ? '#ef4444' : e.risk >= 70 ? '#f97316' : '#eab308' }} />
              </div>
              <span style={{ fontSize: '0.8rem', color: e.risk >= 90 ? '#ef4444' : 'var(--text-2)', minWidth: '25px', textAlign: 'right' }}>{e.risk}</span>
            </div>
          ))}
        </SectionCard>
      </div>

      <SectionCard title="Security Control Coverage">
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
      </SectionCard>
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
  const [hostname, setHostname] = useState('');
  const [target, setTarget] = useState('');

  useEffect(() => { defenseEvasionAPI.getTimeline().then(r => setTimeline(r.data || [])); }, []);

  const respond = async (action: string) => {
    setLoading(l => ({ ...l, [action]: true }));
    try {
      const r = await defenseEvasionAPI.respond({ action, hostname, target, reason: 'Manual response' });
      setResult(r.data);
    } catch (err: any) {
      setResult({ action, error: err?.response?.data?.error || 'Action failed' });
    }
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
    try {
      const r = await defenseEvasionAPI.analyzeAI({ content: aiQuery });
      setAiResult(r.data);
    } catch { setAiResult({ error: 'Analysis failed' }); }
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
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {result && (
        <div style={{ background: result.error ? 'rgba(239,68,68,0.1)' : 'rgba(34,197,94,0.1)', border: `1px solid ${result.error ? 'rgba(239,68,68,0.3)' : 'rgba(34,197,94,0.3)'}`, borderRadius: '8px', padding: '1rem' }}>
          <div style={{ fontWeight: 600, color: result.error ? '#ef4444' : '#22c55e', marginBottom: '0.25rem' }}>
            {result.error ? `Action Failed: ${result.action}` : `Action Executed: ${result.action}`}
          </div>
          <div style={{ fontSize: '0.85rem' }}>{result.error || result.message}</div>
          {result.hostname && <div style={{ fontSize: '0.78rem', color: 'var(--text-3)', marginTop: '0.25rem' }}>Host: {result.hostname}</div>}
        </div>
      )}

      <SectionCard title="Target">
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <input className="g-input" style={{ flex: 1 }} placeholder="Hostname" value={hostname} onChange={e => setHostname(e.target.value)} />
          <input className="g-input" style={{ flex: 1 }} placeholder="Target (pid for Kill Process, otherwise ignored)" value={target} onChange={e => setTarget(e.target.value)} />
        </div>
      </SectionCard>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(270px,1fr))', gap: '0.75rem' }}>
        {ACTIONS.map(a => (
          <div key={a.id} className="g-card" style={{ padding: '1rem', borderLeft: `3px solid ${a.color}` }}>
            <div style={{ fontWeight: 600, marginBottom: '0.2rem' }}>{a.label}</div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-3)', marginBottom: '0.75rem' }}>{a.desc}</div>
            <ActionButton variant="primary" loading={loading[a.id]} onClick={() => respond(a.id)} style={{ background: a.color, border: 'none', width: '100%', justifyContent: 'center' }}>
              {loading[a.id] ? 'Executing…' : a.label}
            </ActionButton>
          </div>
        ))}
        <a href="/playbooks" className="g-btn g-btn-ghost" style={{ padding: '1rem', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>Run SOAR Playbook</a>
      </div>

      <SectionCard title="AI-Assisted Analysis">
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
          <input className="g-input" style={{ flex: 1 }} placeholder="Describe an evasion event or ask about a technique…"
            value={aiQuery} onChange={e => setAiQuery(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') runAI(); }} />
          <ActionButton variant="primary" onClick={runAI} disabled={aiLoading}>
            {aiLoading ? 'Analyzing…' : 'Analyze'}
          </ActionButton>
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
      </SectionCard>

      <SectionCard
        title="Evasion Timeline"
        actions={<span style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>PowerShell → AMSI Bypass → Defender Disabled → Logs Cleared → Payload</span>}
      >
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
      </SectionCard>

      <SectionCard
        title="Defense Evasion Report"
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
      </SectionCard>
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
    <RootLayout title="Defense Evasion Detection"
      subtitle="Security control monitoring, tamper detection, AMSI/log/process evasion — MITRE TA0005">
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
