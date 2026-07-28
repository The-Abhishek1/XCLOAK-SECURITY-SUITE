'use client';
import React, { useState, useEffect, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { mdmeAPI } from '@/lib/api';
import { MetricCard, DataTable, EmptyState, SectionCard, TabBar, ActionButton } from '@/components/design-system';
import {
  LayoutDashboard, Smartphone, AppWindow, FileText, ShieldCheck, Radio, ShieldAlert,
  BarChart3, Sparkles, FileBarChart2, ScrollText, X, Lock, Unlock, MapPin, Volume2,
  RotateCw, RefreshCw, CheckCircle2, KeyRound, Trash2, Eraser, ShieldOff, Bell, Search, FilePlus2,
} from 'lucide-react';

type Tab = 'dashboard' | 'inventory' | 'apps' | 'policies' | 'compliance' | 'remote' | 'threats' | 'analytics' | 'ai' | 'reports' | 'audit';

// ── helpers ───────────────────────────────────────────────────────────────────

function pill(label: string, color?: string) {
  const map: Record<string, string> = {
    compliant: '#22c55e', non_compliant: '#ef4444', enrolled: '#22c55e',
    unenrolled: '#6b7280', blocked: '#ef4444', pending: '#eab308',
    critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
    info: '#3b82f6', open: '#ef4444', investigating: '#f97316', resolved: '#22c55e',
    android: '#3ddc84', ios: '#555', windows: '#0078d4', macos: '#555',
    approved: '#22c55e', risky: '#f97316', blocked_app: '#ef4444',
    completed: '#22c55e', failed: '#ef4444', active: '#22c55e', inactive: '#6b7280',
    lost: '#ef4444', quarantined: '#8b5cf6', rooted: '#ef4444', jailbroken: '#ef4444',
    security: '#ef4444', productivity: '#3b82f6', communication: '#8b5cf6',
    browser: '#14b8a6', other: '#6b7280',
  };
  const key = label?.toLowerCase().replace(/ /g, '_') ?? '';
  const bg = color ?? map[key] ?? '#6b7280';
  return (
    <span style={{
      background: bg + '22', color: bg, border: `1px solid ${bg}44`,
      borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600,
      display: 'inline-block', whiteSpace: 'nowrap',
    }}>{label}</span>
  );
}

function ScoreRing({ score, size = 80, label }: { score: number; size?: number; label?: string }) {
  const r = size * 0.38;
  const circ = 2 * Math.PI * r;
  const color = score >= 80 ? '#22c55e' : score >= 60 ? '#eab308' : score >= 40 ? '#f97316' : '#ef4444';
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
      <svg width={size} height={size}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--border)" strokeWidth={size * 0.1} />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={size * 0.1}
          strokeDasharray={circ} strokeDashoffset={circ * (1 - score / 100)} strokeLinecap="round"
          style={{ transformOrigin: `${size / 2}px ${size / 2}px`, transform: 'rotate(-90deg)' }} />
        <text x={size / 2} y={size / 2 + 5} textAnchor="middle" fill="var(--text-1)"
          fontSize={size * 0.22} fontWeight={700}>{score}</text>
      </svg>
      {label && <div style={{ fontSize: 11, color: 'var(--text-2)' }}>{label}</div>}
    </div>
  );
}

function HorizBar({ label, value, max, color = '#6366f1', sub }: { label: string; value: number; max: number; color?: string; sub?: string }) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0;
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: 'var(--text-2)', marginBottom: 4 }}>
        <span>{label}{sub && <span style={{ color: 'var(--text-3)', marginLeft: 6 }}>{sub}</span>}</span>
        <span style={{ fontWeight: 600, color: 'var(--text-1)' }}>{value.toLocaleString()}</span>
      </div>
      <div style={{ background: 'var(--border)', borderRadius: 4, height: 6 }}>
        <div style={{ width: `${pct}%`, height: 6, background: color, borderRadius: 4, transition: 'width .4s' }} />
      </div>
    </div>
  );
}

function ProgressBar({ pct, color }: { pct: number; color?: string }) {
  const c = color ?? (pct >= 80 ? '#22c55e' : pct >= 60 ? '#eab308' : '#ef4444');
  return (
    <div style={{ background: 'var(--border)', borderRadius: 4, height: 6 }}>
      <div style={{ width: `${pct}%`, height: 6, background: c, borderRadius: 4 }} />
    </div>
  );
}

const PLATFORM_COLOR: Record<string, string> = { ios: '#555', android: '#3ddc84', windows: '#0078d4' };

const AI_ACTIONS = [
  { id: 'device_health_summary',       label: 'Fleet Health' },
  { id: 'risk_assessment',             label: 'Risk Assessment' },
  { id: 'compliance_recommendations',  label: 'Compliance Recs' },
  { id: 'security_policy_suggestions', label: 'Policy Suggestions' },
  { id: 'application_risk_analysis',   label: 'App Risk Analysis' },
  { id: 'lost_device_guidance',        label: 'Lost Device Guide' },
];

const REMOTE_ACTIONS = [
  { type: 'lock',            label: 'Lock Device',        icon: Lock,        color: '#f97316' },
  { type: 'unlock',          label: 'Unlock Device',      icon: Unlock,      color: '#22c55e' },
  { type: 'locate',          label: 'Locate Device',      icon: MapPin,      color: '#3b82f6' },
  { type: 'play_sound',      label: 'Play Sound',         icon: Volume2,     color: '#8b5cf6' },
  { type: 'restart',         label: 'Restart Device',     icon: RotateCw,    color: '#6366f1' },
  { type: 'sync_policies',   label: 'Sync Policies',      icon: RefreshCw,   color: '#14b8a6' },
  { type: 'compliance_check', label: 'Run Compliance',    icon: CheckCircle2, color: '#22c55e' },
  { type: 'collect_logs',    label: 'Collect Logs',       icon: FileText,    color: '#6b7280' },
  { type: 'reset_passcode',  label: 'Reset Passcode',     icon: KeyRound,    color: '#eab308' },
  { type: 'wipe_corporate',  label: 'Wipe Corporate Data', icon: Trash2,     color: '#ef4444' },
  { type: 'factory_reset',   label: 'Factory Reset',      icon: Eraser,      color: '#ef4444' },
  { type: 'quarantine',      label: 'Quarantine Device',  icon: ShieldOff,   color: '#8b5cf6' },
];

// ── AI Panel ──────────────────────────────────────────────────────────────────

function AIPanel({ onClose, device }: { onClose: () => void; device: any }) {
  const [action, setAction] = useState('device_health_summary');
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState('');

  const run = useCallback(async (a: string) => {
    setAction(a);
    setLoading(true);
    setResponse('');
    try {
      const r = await mdmeAPI.ai({ action: a, device_id: device?.device_id ?? '' });
      setResponse(r.data?.response ?? '');
    } catch { setResponse('AI analysis unavailable.'); }
    finally { setLoading(false); }
  }, [device]);

  return (
    <div style={{ position: 'fixed', inset: '0 0 0 auto', width: 420, background: 'var(--bg-1)', borderLeft: '1px solid var(--border)', zIndex: 200, display: 'flex', flexDirection: 'column' }}>
      <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div className="flex items-center gap-2">
          <Sparkles className="h-4 w-4" style={{ color: 'var(--accent)' }} />
          <div>
            <div style={{ fontWeight: 700, fontSize: 16 }}>AI MDM Advisor</div>
            {device && <div style={{ fontSize: 12, color: 'var(--text-2)', marginTop: 2 }}>{device.device_name}</div>}
          </div>
        </div>
        <ActionButton variant="ghost" icon={X} onClick={onClose} style={{ padding: '4px 8px' }} />
      </div>
      <div style={{ padding: '14px 24px', borderBottom: '1px solid var(--border)', display: 'flex', flexWrap: 'wrap', gap: 8 }}>
        {AI_ACTIONS.map(a => (
          <ActionButton key={a.id} variant={action === a.id ? 'primary' : 'ghost'}
            onClick={() => run(a.id)} style={{ fontSize: 12, padding: '5px 10px' }}>{a.label}</ActionButton>
        ))}
      </div>
      <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>
        {loading && <div style={{ color: 'var(--text-2)', fontStyle: 'italic' }}>Analyzing…</div>}
        {!loading && response && <pre style={{ fontFamily: 'inherit', whiteSpace: 'pre-wrap', fontSize: 13, lineHeight: 1.7, margin: 0 }}>{response}</pre>}
        {!loading && !response && <div style={{ color: 'var(--text-3)', fontSize: 13 }}>Select an analysis type above.</div>}
      </div>
    </div>
  );
}

// ── Device Detail Panel ───────────────────────────────────────────────────────

function DevicePanel({ deviceId, onClose, onRemoteAction }: { deviceId: string; onClose: () => void; onRemoteAction: (d: any) => void }) {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [tlTab, setTlTab] = useState<'overview' | 'timeline' | 'apps'>('overview');
  const [actionDone, setActionDone] = useState('');

  useEffect(() => {
    setLoading(true);
    mdmeAPI.getDeviceDetail(deviceId).then(r => { setData(r.data); setLoading(false); });
  }, [deviceId]);

  const sendAction = async (type: string, label: string) => {
    if (!data) return;
    if (['factory_reset', 'wipe_corporate'].includes(type)) {
      if (!window.confirm(`Send "${label}" to ${data.device_name}? This cannot be undone.`)) return;
    }
    await mdmeAPI.sendRemoteAction({ device_id: deviceId, device_name: data.device_name, action_type: type });
    setActionDone(`"${label}" queued successfully`);
    setTimeout(() => setActionDone(''), 3000);
  };

  return (
    <div style={{ position: 'fixed', inset: '0 0 0 auto', width: 520, background: 'var(--bg-1)', borderLeft: '1px solid var(--border)', zIndex: 150, display: 'flex', flexDirection: 'column', overflowY: 'auto' }}>
      <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', position: 'sticky', top: 0, background: 'var(--bg-1)', zIndex: 10 }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 15 }}>{loading ? '…' : data?.device_name}</div>
          {data && <div style={{ fontSize: 12, color: 'var(--text-2)', marginTop: 2 }}>{data.manufacturer} {data.model} · {data.platform}</div>}
        </div>
        <ActionButton variant="ghost" icon={X} onClick={onClose} style={{ padding: '4px 8px' }} />
      </div>

      {loading && <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-2)' }}>Loading…</div>}
      {!loading && data && (
        <div style={{ padding: 24 }}>
          {/* status pills */}
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 16 }}>
            {pill(data.enrollment_status)}
            {pill(data.compliance_status)}
            {pill(data.platform)}
            {data.rooted && pill('Rooted', '#ef4444')}
            {data.jailbroken && pill('Jailbroken', '#ef4444')}
            {data.is_lost && pill('Lost', '#ef4444')}
            {data.is_quarantined && pill('Quarantined', '#8b5cf6')}
          </div>

          {/* resource bars */}
          <div style={{ display: 'grid', gridTemplateColumns: '80px 1fr', gap: 10, alignItems: 'center', marginBottom: 20 }}>
            <ScoreRing score={100 - (data.risk_score ?? 0)} size={70} label="Safety" />
            <div>
              <div style={{ marginBottom: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: 'var(--text-2)', marginBottom: 3 }}>
                  <span>🔋 Battery</span><span>{data.battery_level}%</span>
                </div>
                <ProgressBar pct={data.battery_level} color={data.battery_level < 20 ? '#ef4444' : '#22c55e'} />
              </div>
              <div style={{ marginBottom: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: 'var(--text-2)', marginBottom: 3 }}>
                  <span>💾 Storage</span><span>{data.storage_used_gb?.toFixed(1)} / {data.storage_total_gb?.toFixed(0)} GB ({data.storage_pct}%)</span>
                </div>
                <ProgressBar pct={data.storage_pct} color={data.storage_pct > 85 ? '#ef4444' : '#6366f1'} />
              </div>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: 'var(--text-2)', marginBottom: 3 }}>
                  <span>🧠 Memory</span><span>{data.memory_used_gb?.toFixed(1)} / {data.memory_total_gb?.toFixed(0)} GB ({data.memory_pct}%)</span>
                </div>
                <ProgressBar pct={data.memory_pct} color="#8b5cf6" />
              </div>
            </div>
          </div>

          {/* sub-tabs */}
          <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', marginBottom: 16, gap: 0 }}>
            {(['overview', 'timeline', 'apps'] as const).map(t => (
              <button key={t} onClick={() => setTlTab(t)} style={{
                padding: '7px 16px', fontSize: 12, fontWeight: tlTab === t ? 700 : 400,
                color: tlTab === t ? 'var(--accent)' : 'var(--text-2)',
                background: 'none', border: 'none', cursor: 'pointer',
                borderBottom: tlTab === t ? '2px solid var(--accent)' : '2px solid transparent',
              }}>{t.charAt(0).toUpperCase() + t.slice(1)}</button>
            ))}
          </div>

          {/* overview */}
          {tlTab === 'overview' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <SectionCard title="Device Info">
                {[
                  ['Device ID', data.device_id],
                  ['Serial', data.serial_number],
                  ['IMEI', data.imei],
                  ['OS Version', data.os_version],
                  ['Security Patch', data.security_patch],
                  ['Owner', data.owner],
                  ['Email', data.owner_email],
                  ['Department', data.department],
                  ['Business Unit', data.business_unit],
                  ['Last Check-in', data.last_checkin_at ? new Date(data.last_checkin_at).toLocaleString() : '—'],
                  ['Enrolled', data.enrolled_at ? new Date(data.enrolled_at).toLocaleDateString() : '—'],
                ].map(([k, v]) => v ? (
                  <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
                    <span style={{ color: 'var(--text-2)' }}>{k}</span>
                    <span style={{ color: 'var(--text-1)', maxWidth: 220, textAlign: 'right' }}>{v}</span>
                  </div>
                ) : null)}
              </SectionCard>

              <SectionCard title="Connectivity & Security">
                {[
                  ['Wi-Fi', data.wifi_ssid ? `${data.wifi_ssid} (${data.wifi_signal_pct}%)` : '—'],
                  ['Cellular', data.cellular_carrier ? `${data.cellular_carrier} (${data.cellular_signal_pct}%)` : '—'],
                  ['Bluetooth', data.bluetooth_enabled ? 'Enabled' : 'Disabled'],
                  ['GPS', data.gps_location || 'Not available'],
                  ['Encryption', data.encryption_enabled ? 'Enabled ✅' : 'DISABLED ❌'],
                  ['Screen Lock', data.screen_lock_enabled ? `Enabled (${data.screen_lock_timeout_min}min)` : 'DISABLED ❌'],
                  ['Biometric', data.biometric_enabled ? 'Enabled' : 'Not enrolled'],
                ].map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
                    <span style={{ color: 'var(--text-2)' }}>{k}</span>
                    <span style={{ color: 'var(--text-1)' }}>{v}</span>
                  </div>
                ))}
              </SectionCard>

              {/* Remote Actions */}
              <SectionCard title="Remote Actions">
                {actionDone && <div style={{ color: '#22c55e', fontSize: 12, marginBottom: 8 }}>{actionDone}</div>}
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {REMOTE_ACTIONS.map(a => (
                    <ActionButton key={a.type} variant="ghost" icon={a.icon} onClick={() => sendAction(a.type, a.label)}
                      style={{ fontSize: 11, padding: '5px 10px', borderColor: a.color + '44', color: a.color }}>
                      {a.label}
                    </ActionButton>
                  ))}
                </div>
              </SectionCard>
            </div>
          )}

          {/* timeline */}
          {tlTab === 'timeline' && (
            <div>
              {(data.timeline ?? []).length === 0 && <div style={{ color: 'var(--text-3)', fontSize: 13 }}>No timeline events</div>}
              {(data.timeline ?? []).map((t: any, i: number) => (
                <div key={i} style={{ display: 'flex', gap: 10, padding: '7px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
                  <div style={{ width: 6, height: 6, borderRadius: '50%', background: t.severity === 'critical' ? '#ef4444' : t.severity === 'high' ? '#f97316' : t.severity === 'medium' ? '#eab308' : '#22c55e', marginTop: 4, flexShrink: 0 }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontWeight: 500, color: 'var(--text-1)' }}>{t.summary}</div>
                    <div style={{ color: 'var(--text-3)', marginTop: 2 }}>{t.actor} · {t.created_at ? new Date(t.created_at).toLocaleString() : ''}</div>
                    {t.details && <div style={{ color: 'var(--text-2)', marginTop: 2, fontStyle: 'italic' }}>{t.details}</div>}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* apps */}
          {tlTab === 'apps' && (
            <div>
              {(data.installed_apps ?? []).length === 0 && <div style={{ color: 'var(--text-3)', fontSize: 13 }}>No app data</div>}
              {(data.installed_apps ?? []).map((a: any, i: number) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
                  <div>
                    <div style={{ fontWeight: 500 }}>{a.app_name} <span style={{ color: 'var(--text-3)' }}>v{a.version}</span></div>
                    <div style={{ color: 'var(--text-3)', marginTop: 2 }}>{a.vendor} · {a.size_mb?.toFixed(0)} MB</div>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 3 }}>
                    {pill(a.status, a.status)}
                    {a.managed && <span style={{ fontSize: 10, color: 'var(--text-3)' }}>managed</span>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Tab: Dashboard ────────────────────────────────────────────────────────────

function DashboardTab({ d }: { d: any }) {
  if (!d) return <div style={{ color: 'var(--text-3)' }}>Loading dashboard…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
        <MetricCard label="Total Devices" value={d.total ?? 0} />
        <MetricCard label="Enrolled" value={d.enrolled ?? 0} color="#22c55e" />
        <MetricCard label="Unmanaged" value={d.unmanaged ?? 0} color="#6b7280" />
        <MetricCard label="Compliant" value={d.compliant ?? 0} color="#22c55e" />
        <MetricCard label="Non-Compliant" value={d.non_compliant ?? 0} color="#ef4444" />
        <MetricCard label="Rooted/Jailbroken" value={d.rooted_jailbroken ?? 0} color="#ef4444" />
        <MetricCard label="Lost" value={d.lost ?? 0} color="#ef4444" />
        <MetricCard label="Quarantined" value={d.quarantined ?? 0} color="#8b5cf6" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 14 }}>
        <SectionCard>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>Enrollment Rate</div>
          <div style={{ fontSize: 32, fontWeight: 700, color: '#22c55e' }}>{d.enrollment_rate ?? 0}%</div>
          <ProgressBar pct={d.enrollment_rate ?? 0} color="#22c55e" />
        </SectionCard>
        <SectionCard>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>Compliance Rate</div>
          <div style={{ fontSize: 32, fontWeight: 700, color: '#6366f1' }}>
            {d.total > 0 ? Math.round(d.compliant / d.total * 100) : 0}%
          </div>
          <ProgressBar pct={d.total > 0 ? Math.round(d.compliant / d.total * 100) : 0} color="#6366f1" />
        </SectionCard>
        <SectionCard>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>Health Score</div>
          <div style={{ fontSize: 32, fontWeight: 700, color: '#14b8a6' }}>{d.health_score ?? 0}</div>
          <ProgressBar pct={d.health_score ?? 0} color="#14b8a6" />
        </SectionCard>
        <SectionCard>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>Open Threats</div>
          <div style={{ fontSize: 32, fontWeight: 700, color: d.open_threats > 0 ? '#ef4444' : '#22c55e' }}>{d.open_threats ?? 0}</div>
          <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 4 }}>require attention</div>
        </SectionCard>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <SectionCard title="By Platform">
          {(d.by_platform ?? []).map((p: any) => (
            <HorizBar key={p.platform} label={p.platform} value={p.count} max={d.total}
              color={PLATFORM_COLOR[p.platform] ?? '#6b7280'} />
          ))}
        </SectionCard>
        <SectionCard title="Recent Check-ins">
          {(d.recent_checkins ?? []).map((r: any) => (
            <div key={r.device_id} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
              <div>
                <div style={{ fontWeight: 500 }}>{r.device_name}</div>
                <div style={{ color: 'var(--text-3)', fontSize: 11 }}>{r.platform}</div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 3 }}>
                {pill(r.compliance_status)}
                <span style={{ fontSize: 11, color: 'var(--text-3)' }}>
                  {r.last_checkin_at ? new Date(r.last_checkin_at).toLocaleTimeString() : '—'}
                </span>
              </div>
            </div>
          ))}
        </SectionCard>
      </div>
    </div>
  );
}

// ── Tab: Inventory ────────────────────────────────────────────────────────────

function InventoryTab({ devices, onSelect }: { devices: any[]; onSelect: (d: any) => void }) {
  const [search, setSearch] = useState('');
  const [platformF, setPlatformF] = useState('');
  const [complianceF, setComplianceF] = useState('');
  const [enrollF, setEnrollF] = useState('');

  const filtered = (devices ?? []).filter(d => {
    if (search && !`${d.device_name}${d.owner}${d.imei}${d.serial_number}`.toLowerCase().includes(search.toLowerCase())) return false;
    if (platformF && d.platform !== platformF) return false;
    if (complianceF && d.compliance_status !== complianceF) return false;
    if (enrollF && d.enrollment_status !== enrollF) return false;
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
        <input className="g-input" value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search name, user, IMEI, serial…" style={{ minWidth: 240 }} />
        <select className="g-input" value={platformF} onChange={e => setPlatformF(e.target.value)}>
          <option value="">All Platforms</option>
          {['android', 'ios', 'windows'].map(p => <option key={p} value={p}>{p}</option>)}
        </select>
        <select className="g-input" value={complianceF} onChange={e => setComplianceF(e.target.value)}>
          <option value="">All Compliance</option>
          <option value="compliant">Compliant</option>
          <option value="non_compliant">Non-Compliant</option>
        </select>
        <select className="g-input" value={enrollF} onChange={e => setEnrollF(e.target.value)}>
          <option value="">All Enrollment</option>
          <option value="enrolled">Enrolled</option>
          <option value="unenrolled">Unenrolled</option>
          <option value="blocked">Blocked</option>
        </select>
        <span style={{ fontSize: 12, color: 'var(--text-3)', marginLeft: 'auto' }}>{filtered.length} devices</span>
      </div>

      <DataTable<any>
        rows={filtered}
        rowKey={(d: any) => d.device_id}
        onRowClick={d => onSelect(d)}
        emptyState={<EmptyState title="No devices match filters" />}
        columns={[
          { key: 'device_name', header: 'Device', render: (d: any) => (
            <div>
              <div style={{ fontWeight: 600, fontSize: 13 }}>{d.device_name}</div>
              <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{d.manufacturer} {d.model}</div>
              <div style={{ display: 'flex', gap: 4, marginTop: 2 }}>
                {d.rooted && pill('Rooted', '#ef4444')}
                {d.jailbroken && pill('Jailbroken', '#ef4444')}
                {d.is_lost && pill('Lost', '#ef4444')}
                {d.is_quarantined && pill('Quarantined', '#8b5cf6')}
              </div>
            </div>
          ) },
          { key: 'platform', header: 'Platform', render: (d: any) => pill(d.platform) },
          { key: 'os_version', header: 'OS', render: (d: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{d.os_version}</span> },
          { key: 'owner', header: 'Owner', render: (d: any) => (
            <div>
              <div style={{ fontSize: 13 }}>{d.owner}</div>
              <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{d.owner_email}</div>
            </div>
          ) },
          { key: 'department', header: 'Dept', render: (d: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{d.department}</span> },
          { key: 'enrollment_status', header: 'Enrollment', render: (d: any) => pill(d.enrollment_status) },
          { key: 'compliance_status', header: 'Compliance', render: (d: any) => pill(d.compliance_status) },
          { key: 'risk_score', header: 'Risk', render: (d: any) => (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <div style={{ width: 36, height: 6, background: 'var(--border)', borderRadius: 3 }}>
                <div style={{ width: `${d.risk_score}%`, height: '100%', borderRadius: 3, background: d.risk_score >= 70 ? '#ef4444' : d.risk_score >= 40 ? '#f97316' : '#22c55e' }} />
              </div>
              <span style={{ fontSize: 12 }}>{d.risk_score}</span>
            </div>
          ) },
          { key: 'battery_level', header: 'Battery', render: (d: any) => (
            <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}>
              <span>{d.battery_level}%</span>
              <div style={{ width: 20, height: 8, border: '1px solid var(--border)', borderRadius: 2, position: 'relative' }}>
                <div style={{ position: 'absolute', inset: 1, right: 'auto', width: `${d.battery_level * 18 / 100}px`, background: d.battery_level < 20 ? '#ef4444' : '#22c55e', borderRadius: 1 }} />
              </div>
            </div>
          ) },
          { key: 'last_checkin_at', header: 'Last Check-in', render: (d: any) => (
            <span style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
              {d.last_checkin_at ? new Date(d.last_checkin_at).toLocaleString() : '—'}
            </span>
          ) },
        ]}
      />
    </div>
  );
}

// ── Tab: Apps ─────────────────────────────────────────────────────────────────

function AppsTab({ d }: { d: any }) {
  const [filter, setFilter] = useState('');
  const apps: any[] = d?.apps ?? [];
  const summary = d?.summary ?? {};
  const shown = filter ? apps.filter((a: any) => a.status === filter) : apps;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <MetricCard label="Approved" value={summary.approved ?? 0} color="#22c55e" />
        <MetricCard label="Risky" value={summary.risky ?? 0} color="#f97316" />
        <MetricCard label="Blocked" value={summary.blocked ?? 0} color="#ef4444" />
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        {['', 'approved', 'risky', 'blocked'].map(f => (
          <ActionButton key={f} variant={filter === f ? 'primary' : 'ghost'} onClick={() => setFilter(f)} style={{ fontSize: 12 }}>
            {f === '' ? 'All' : f.charAt(0).toUpperCase() + f.slice(1)}
          </ActionButton>
        ))}
      </div>
      <DataTable<any>
        rows={shown}
        rowKey={(a: any, i: number) => i}
        emptyState={<EmptyState title="No apps" />}
        columns={[
          { key: 'app_name', header: 'App Name', render: (a: any) => <span style={{ fontWeight: 500 }}>{a.app_name}</span> },
          { key: 'version', header: 'Version', render: (a: any) => <span style={{ fontSize: 12, color: 'var(--text-2)', fontFamily: 'monospace' }}>{a.version}</span> },
          { key: 'vendor', header: 'Vendor', render: (a: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{a.vendor}</span> },
          { key: 'category', header: 'Category', render: (a: any) => pill(a.category) },
          { key: 'status', header: 'Status', render: (a: any) => pill(a.status) },
          { key: 'device_count', header: 'Devices', render: (a: any) => <span style={{ fontWeight: 600 }}>{a.device_count}</span> },
          { key: 'last_seen', header: 'Last Seen', render: (a: any) => <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{a.last_seen ? new Date(a.last_seen).toLocaleDateString() : '—'}</span> },
        ]}
      />
    </div>
  );
}

// ── Tab: Policies ─────────────────────────────────────────────────────────────

function PoliciesTab({ policies }: { policies: any[] }) {
  const rows = policies ?? [];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 10 }}>
        <MetricCard label="Total Policies" value={rows.length} />
        <MetricCard label="Enabled" value={rows.filter(p => p.enabled).length} color="#22c55e" />
        <MetricCard label="Disabled" value={rows.filter(p => !p.enabled).length} color="#6b7280" />
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {rows.map(p => (
          <SectionCard key={p.policy_id}
            title={p.name}
            subtitle={`${p.policy_type} · ${p.platform} · Priority ${p.priority} · ${p.devices_applied} devices`}
            actions={<>{pill(p.enabled ? 'active' : 'inactive')}{pill(p.platform)}</>}>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {p.require_encryption && <span style={{ fontSize: 11, background: '#22c55e22', color: '#22c55e', border: '1px solid #22c55e44', borderRadius: 4, padding: '2px 8px' }}>Encryption Required</span>}
              {p.require_screen_lock && <span style={{ fontSize: 11, background: '#22c55e22', color: '#22c55e', border: '1px solid #22c55e44', borderRadius: 4, padding: '2px 8px' }}>Screen Lock ({p.screen_lock_timeout}min)</span>}
              {p.require_biometric && <span style={{ fontSize: 11, background: '#6366f122', color: '#6366f1', border: '1px solid #6366f144', borderRadius: 4, padding: '2px 8px' }}>Biometric Required</span>}
              {p.block_camera && <span style={{ fontSize: 11, background: '#ef444422', color: '#ef4444', border: '1px solid #ef444444', borderRadius: 4, padding: '2px 8px' }}>Camera Blocked</span>}
              {p.block_usb && <span style={{ fontSize: 11, background: '#ef444422', color: '#ef4444', border: '1px solid #ef444444', borderRadius: 4, padding: '2px 8px' }}>USB Blocked</span>}
              {p.block_bluetooth && <span style={{ fontSize: 11, background: '#ef444422', color: '#ef4444', border: '1px solid #ef444444', borderRadius: 4, padding: '2px 8px' }}>Bluetooth Blocked</span>}
              {p.require_vpn && <span style={{ fontSize: 11, background: '#8b5cf622', color: '#8b5cf6', border: '1px solid #8b5cf644', borderRadius: 4, padding: '2px 8px' }}>VPN Required</span>}
              {p.require_complex_password && <span style={{ fontSize: 11, background: '#6366f122', color: '#6366f1', border: '1px solid #6366f144', borderRadius: 4, padding: '2px 8px' }}>Complex Password ({p.min_password_length}+ chars)</span>}
              {p.min_os_version && <span style={{ fontSize: 11, background: '#14b8a622', color: '#14b8a6', border: '1px solid #14b8a644', borderRadius: 4, padding: '2px 8px' }}>Min OS: {p.min_os_version}</span>}
            </div>
          </SectionCard>
        ))}
        {rows.length === 0 && <EmptyState title="No policies configured" />}
      </div>
    </div>
  );
}

// ── Tab: Compliance ────────────────────────────────────────────────────────────

function ComplianceTab({ d }: { d: any }) {
  if (!d) return <div style={{ color: 'var(--text-3)' }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', alignItems: 'center' }}>
        <div className="g-card" style={{ padding: 20, display: 'flex', gap: 20, alignItems: 'center' }}>
          <ScoreRing score={d.compliance_rate ?? 0} size={80} label="Compliant" />
          <div>
            <div style={{ fontSize: 22, fontWeight: 700 }}>{d.compliant ?? 0} / {d.total ?? 0}</div>
            <div style={{ fontSize: 13, color: 'var(--text-2)' }}>Compliant Devices</div>
          </div>
        </div>
        <MetricCard label="Non-Compliant" value={d.non_compliant ?? 0} color="#ef4444" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <SectionCard title="Control Coverage">
          {(d.controls ?? []).map((c: any) => (
            <div key={c.control} style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 4 }}>
                <span>{c.control}</span>
                <span style={{ fontWeight: 700, color: c.pct >= 80 ? '#22c55e' : c.pct >= 60 ? '#eab308' : '#ef4444' }}>{c.pct}%</span>
              </div>
              <ProgressBar pct={c.pct} color={c.pct >= 80 ? '#22c55e' : c.pct >= 60 ? '#eab308' : '#ef4444'} />
              <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 3 }}>{c.passed} passed · {c.failed} failed</div>
            </div>
          ))}
        </SectionCard>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <SectionCard title="Policy Violations">
            {(d.violations ?? []).map((v: any, i: number) => (
              <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
                <span>{v.violation}</span>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                  <span style={{ fontWeight: 600 }}>{v.count}</span>
                  {pill(v.severity)}
                </div>
              </div>
            ))}
          </SectionCard>

          <SectionCard title="Non-Compliant Devices">
            {(d.non_compliant_devices ?? []).slice(0, 6).map((dev: any) => (
              <div key={dev.device_id} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
                <div>
                  <div style={{ fontWeight: 500 }}>{dev.device_name}</div>
                  <div style={{ color: 'var(--text-3)', fontSize: 11 }}>{dev.owner} · {dev.department}</div>
                </div>
                <span style={{ fontWeight: 600, color: '#ef4444' }}>{dev.risk_score}</span>
              </div>
            ))}
          </SectionCard>
        </div>
      </div>
    </div>
  );
}

// ── Tab: Remote Actions ────────────────────────────────────────────────────────

function RemoteActionsTab({ actions, devices, onRefresh }: { actions: any[]; devices: any[]; onRefresh: () => void }) {
  const [selDevice, setSelDevice] = useState('');
  const [actionDone, setActionDone] = useState('');
  const [sending, setSending] = useState('');

  const device = devices.find(d => d.device_id === selDevice);

  const send = async (type: string, label: string) => {
    if (!selDevice || !device) return;
    if (['factory_reset', 'wipe_corporate'].includes(type)) {
      if (!window.confirm(`Send "${label}" to ${device.device_name}? This cannot be undone.`)) return;
    }
    setSending(type);
    await mdmeAPI.sendRemoteAction({ device_id: selDevice, device_name: device.device_name, action_type: type });
    setSending('');
    setActionDone(`"${label}" queued for ${device.device_name}`);
    setTimeout(() => setActionDone(''), 4000);
    onRefresh();
  };

  const statusColor: Record<string, string> = { pending: '#eab308', completed: '#22c55e', failed: '#ef4444' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <SectionCard title="Send Remote Action">
        <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
          <select className="g-input" value={selDevice} onChange={e => setSelDevice(e.target.value)} style={{ minWidth: 280 }}>
            <option value="">Select a device…</option>
            {devices.map(d => (
              <option key={d.device_id} value={d.device_id}>{d.device_name} — {d.owner}</option>
            ))}
          </select>
          {device && (
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              {pill(device.platform)}{pill(device.compliance_status)}
              <span style={{ fontSize: 12, color: 'var(--text-2)' }}>Risk: {device.risk_score}</span>
            </div>
          )}
        </div>
        {actionDone && <div style={{ color: '#22c55e', fontSize: 13, marginBottom: 12 }}>{actionDone}</div>}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {REMOTE_ACTIONS.map(a => (
            <ActionButton key={a.type} variant="ghost" icon={a.icon}
              disabled={!selDevice || sending === a.type}
              loading={sending === a.type}
              onClick={() => send(a.type, a.label)}
              style={{ fontSize: 12, padding: '7px 12px', borderColor: a.color + '55', color: a.color, opacity: !selDevice ? 0.4 : 1 }}>
              {a.label}
            </ActionButton>
          ))}
        </div>
      </SectionCard>

      <DataTable<any>
        rows={actions ?? []}
        rowKey={(a: any, i: number) => i}
        emptyState={<EmptyState title="No remote actions yet" />}
        columns={[
          { key: 'created_at', header: 'Time', render: (a: any) => <span style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{a.created_at ? new Date(a.created_at).toLocaleString() : '—'}</span> },
          { key: 'device_name', header: 'Device', render: (a: any) => <span style={{ fontSize: 13, fontWeight: 500 }}>{a.device_name ?? a.device_id}</span> },
          { key: 'action_type', header: 'Action', render: (a: any) => <span style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--text-1)' }}>{a.action_type}</span> },
          { key: 'status', header: 'Status', render: (a: any) => <span style={{ fontSize: 12, fontWeight: 600, color: statusColor[a.status] ?? 'var(--text-2)' }}>{a.status}</span> },
          { key: 'initiated_by', header: 'By', render: (a: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{a.initiated_by}</span> },
          { key: 'result', header: 'Result', render: (a: any) => <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{a.result ?? '—'}</span> },
        ]}
      />
    </div>
  );
}

// ── Tab: Threats ──────────────────────────────────────────────────────────────

function ThreatsTab({ d, onRefresh }: { d: any; onRefresh: () => void }) {
  const threats: any[] = d?.threats ?? [];
  const summary = d?.summary ?? {};

  const resolve = async (threatId: string) => {
    await mdmeAPI.updateThreat(threatId, { status: 'resolved' });
    onRefresh();
  };
  const investigate = async (threatId: string) => {
    await mdmeAPI.updateThreat(threatId, { status: 'investigating' });
    onRefresh();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', gap: 10 }}>
        <MetricCard label="Open" value={summary.open ?? 0} color="#ef4444" />
        <MetricCard label="Investigating" value={summary.investigating ?? 0} color="#f97316" />
        <MetricCard label="Resolved" value={summary.resolved ?? 0} color="#22c55e" />
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {threats.map(t => (
          <div key={t.threat_id} className="g-card" style={{ padding: 16, borderLeft: `3px solid ${t.severity === 'critical' ? '#ef4444' : t.severity === 'high' ? '#f97316' : t.severity === 'medium' ? '#eab308' : '#22c55e'}` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                {pill(t.severity)}
                {pill(t.status)}
                <span style={{ fontSize: 12, color: 'var(--text-3)', fontFamily: 'monospace' }}>{t.threat_type}</span>
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                {t.status === 'open' && (
                  <ActionButton variant="ghost" icon={Search} onClick={() => investigate(t.threat_id)} style={{ fontSize: 11 }}>Investigate</ActionButton>
                )}
                {t.status !== 'resolved' && (
                  <ActionButton variant="primary" icon={CheckCircle2} onClick={() => resolve(t.threat_id)} style={{ fontSize: 11 }}>Resolve</ActionButton>
                )}
              </div>
            </div>
            <div style={{ fontWeight: 600, fontSize: 14 }}>{t.title}</div>
            <div style={{ fontSize: 13, color: 'var(--text-2)', marginTop: 4 }}>{t.description}</div>
            <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 6 }}>
              Device: <strong>{t.device_name}</strong> · Detected: {t.detected_at ? new Date(t.detected_at).toLocaleString() : '—'}
              {t.resolved_by && ` · Resolved by: ${t.resolved_by}`}
            </div>
          </div>
        ))}
        {threats.length === 0 && (
          <div className="g-card flex items-center justify-center gap-2" style={{ padding: 32, color: '#22c55e' }}>
            <CheckCircle2 className="h-4 w-4" />
            No active threats detected
          </div>
        )}
      </div>
    </div>
  );
}

// ── Tab: Analytics ────────────────────────────────────────────────────────────

function AnalyticsTab({ d }: { d: any }) {
  if (!d) return <div style={{ color: 'var(--text-3)' }}>Loading…</div>;
  const maxEnroll = Math.max(...(d.enrollment_trend ?? [{ enrolled: 1 }]).map((x: any) => x.enrolled));
  const maxComp = Math.max(...(d.compliance_trend ?? [{ compliant: 1 }]).map((x: any) => x.compliant + x.non_compliant));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <SectionCard title="Platform Distribution">
          {(d.os_distribution ?? []).map((o: any, i: number) => (
            <div key={i} style={{ marginBottom: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 3 }}>
                <span>{o.platform} {o.os_version}</span>
                <span style={{ fontWeight: 600 }}>{o.count}</span>
              </div>
              <ProgressBar pct={o.count * 100 / (d.os_distribution.reduce((s: number, x: any) => s + x.count, 0) || 1)}
                color={PLATFORM_COLOR[o.platform] ?? '#6b7280'} />
            </div>
          ))}
        </SectionCard>

        <SectionCard title="Department Distribution">
          {(d.dept_distribution ?? []).map((dept: any) => (
            <HorizBar key={dept.department} label={dept.department} value={dept.count}
              max={Math.max(...(d.dept_distribution ?? [{ count: 1 }]).map((x: any) => x.count))} color="#6366f1" />
          ))}
        </SectionCard>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <SectionCard title="Enrollment Trend (6 months)">
          <div style={{ display: 'flex', gap: 2, alignItems: 'flex-end', height: 80 }}>
            {(d.enrollment_trend ?? []).map((g: any) => (
              <div key={g.month} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
                <div style={{ width: '100%', height: Math.round(g.enrolled / maxEnroll * 72), background: '#22c55e', borderRadius: '3px 3px 0 0', minHeight: 4 }} />
                <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{g.month}</div>
              </div>
            ))}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 8 }}>
            Current: {(d.enrollment_trend ?? []).slice(-1)[0]?.enrolled ?? 0} enrolled
          </div>
        </SectionCard>

        <SectionCard title="Compliance Trend (6 months)">
          <div style={{ display: 'flex', gap: 2, alignItems: 'flex-end', height: 80 }}>
            {(d.compliance_trend ?? []).map((g: any) => {
              const total = g.compliant + g.non_compliant;
              const h = Math.round(total / maxComp * 72);
              const compH = Math.round(g.compliant / total * h);
              return (
                <div key={g.month} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
                  <div style={{ width: '100%', display: 'flex', flexDirection: 'column', height: h }}>
                    <div style={{ flex: 1, background: '#22c55e', borderRadius: '3px 3px 0 0' }} />
                    <div style={{ height: h - compH, background: '#ef4444' }} />
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{g.month}</div>
                </div>
              );
            })}
          </div>
          <div style={{ display: 'flex', gap: 12, marginTop: 8, fontSize: 12 }}>
            <span style={{ color: '#22c55e' }}>■ Compliant</span>
            <span style={{ color: '#ef4444' }}>■ Non-Compliant</span>
          </div>
        </SectionCard>
      </div>

      <SectionCard title="Top Apps Across Fleet" padded={false}>
        <DataTable<any>
          rows={d.top_apps ?? []}
          rowKey={(a: any, i: number) => i}
          columns={[
            { key: 'app_name', header: 'App', render: (a: any) => <span style={{ fontWeight: 500 }}>{a.app_name}</span> },
            { key: 'category', header: 'Category', render: (a: any) => pill(a.category) },
            { key: 'device_count', header: 'Devices', render: (a: any) => (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ flex: 1, height: 6, background: 'var(--border)', borderRadius: 3 }}>
                  <div style={{ width: `${a.device_count / 427 * 100}%`, height: '100%', background: '#6366f1', borderRadius: 3 }} />
                </div>
                <span style={{ fontWeight: 600, minWidth: 30 }}>{a.device_count}</span>
              </div>
            ) },
          ]}
        />
      </SectionCard>
    </div>
  );
}

// ── Tab: AI Insights ──────────────────────────────────────────────────────────

function AIInsightsTab({ device }: { device: any }) {
  const [action, setAction] = useState('device_health_summary');
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState('');

  const run = useCallback(async (a: string) => {
    setAction(a);
    setLoading(true);
    setResponse('');
    try {
      const r = await mdmeAPI.ai({ action: a, device_id: device?.device_id ?? '' });
      setResponse(r.data?.response ?? '');
    } catch { setResponse('AI analysis unavailable.'); }
    finally { setLoading(false); }
  }, [device]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {device && (
        <div className="g-card" style={{ padding: '12px 16px', display: 'flex', gap: 10, alignItems: 'center' }}>
          <span style={{ fontSize: 13, color: 'var(--text-2)' }}>Context device:</span>
          <strong>{device.device_name}</strong>
          {pill(device.platform)}{pill(device.compliance_status)}
        </div>
      )}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {AI_ACTIONS.map(a => (
          <ActionButton key={a.id} variant={action === a.id ? 'primary' : 'ghost'}
            onClick={() => run(a.id)} style={{ fontSize: 13 }}>{a.label}</ActionButton>
        ))}
      </div>
      {loading && <div className="g-card" style={{ padding: 32, textAlign: 'center', color: 'var(--text-2)', fontStyle: 'italic' }}>Analyzing…</div>}
      {!loading && response && (
        <div className="g-card" style={{ padding: 24 }}>
          <pre style={{ fontFamily: 'inherit', whiteSpace: 'pre-wrap', fontSize: 13, lineHeight: 1.7, margin: 0 }}>{response}</pre>
        </div>
      )}
      {!loading && !response && (
        <div className="g-card" style={{ padding: 24, color: 'var(--text-3)', fontSize: 13 }}>
          Select an analysis type above to get AI-powered MDM insights.
        </div>
      )}
    </div>
  );
}

// ── Tab: Reports ──────────────────────────────────────────────────────────────

function ReportsTab({ reports, onRefresh }: { reports: any[]; onRefresh: () => void }) {
  const [title, setTitle] = useState('');
  const [rtype, setRtype] = useState('device_inventory');
  const [format, setFormat] = useState('pdf');
  const [gen, setGen] = useState(false);

  const generate = async () => {
    if (!title) return;
    setGen(true);
    await mdmeAPI.generateReport({ title, report_type: rtype, format });
    setTitle('');
    onRefresh();
    setGen(false);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <SectionCard title="Generate Report">
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <input className="g-input" value={title} onChange={e => setTitle(e.target.value)}
            placeholder="Report title…" style={{ minWidth: 240 }} />
          <select className="g-input" value={rtype} onChange={e => setRtype(e.target.value)}>
            <option value="device_inventory">Device Inventory</option>
            <option value="compliance_report">Compliance Report</option>
            <option value="security_policy_report">Security Policy Report</option>
            <option value="application_inventory">Application Inventory</option>
            <option value="lost_device_report">Lost Device Report</option>
            <option value="executive_mdm_summary">Executive MDM Summary</option>
            <option value="audit_report">Audit Report</option>
          </select>
          <select className="g-input" value={format} onChange={e => setFormat(e.target.value)}>
            <option value="pdf">PDF</option>
            <option value="csv">CSV</option>
            <option value="xlsx">XLSX</option>
          </select>
          <ActionButton variant="primary" icon={FilePlus2} onClick={generate} disabled={!title || gen}>
            {gen ? 'Generating…' : 'Generate'}
          </ActionButton>
        </div>
      </SectionCard>
      <DataTable<any>
        rows={reports ?? []}
        rowKey={(r: any) => r.report_id}
        emptyState={<EmptyState title="No reports yet" />}
        columns={[
          { key: 'title', header: 'Title', render: (r: any) => <span style={{ fontWeight: 500 }}>{r.title}</span> },
          { key: 'report_type', header: 'Type', render: (r: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{r.report_type}</span> },
          { key: 'generated_by', header: 'By', render: (r: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{r.generated_by}</span> },
          { key: 'device_count', header: 'Devices', render: (r: any) => <span style={{ fontWeight: 600 }}>{r.device_count}</span> },
          { key: 'format', header: 'Format', render: (r: any) => pill(r.format, '#3b82f6') },
          { key: 'size_bytes', header: 'Size', render: (r: any) => <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{r.size_bytes ? `${(r.size_bytes / 1024).toFixed(0)} KB` : '—'}</span> },
          { key: 'created_at', header: 'Date', render: (r: any) => <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{r.created_at ? new Date(r.created_at).toLocaleDateString() : '—'}</span> },
        ]}
      />
    </div>
  );
}

// ── Tab: Audit ────────────────────────────────────────────────────────────────

function AuditTab({ entries }: { entries: any[] }) {
  return (
    <SectionCard padded={false}>
      <DataTable<any>
        rows={entries ?? []}
        rowKey={(e: any, i: number) => i}
        emptyState={<EmptyState title="No audit entries" />}
        columns={[
          { key: 'created_at', header: 'Time', render: (e: any) => <span style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{e.created_at ? new Date(e.created_at).toLocaleString() : '—'}</span> },
          { key: 'action', header: 'Action', render: (e: any) => pill(e.action?.replace(/_/g, ' '), '#3b82f6') },
          { key: 'object_type', header: 'Object', render: (e: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{e.object_type}</span> },
          { key: 'object_name', header: 'Name', render: (e: any) => <span style={{ fontSize: 12 }}>{e.object_name ?? e.object_id ?? '—'}</span> },
          { key: 'actor', header: 'Actor', render: (e: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{e.actor}</span> },
          { key: 'details', header: 'Details', render: (e: any) => <span style={{ fontSize: 11, color: 'var(--text-3)', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>{e.details ?? '—'}</span> },
        ]}
      />
    </SectionCard>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

const TABS: { key: Tab; label: string; icon: any }[] = [
  { key: 'dashboard',  label: 'Dashboard',       icon: LayoutDashboard },
  { key: 'inventory',  label: 'Devices',         icon: Smartphone },
  { key: 'apps',       label: 'Applications',    icon: AppWindow },
  { key: 'policies',   label: 'Policies',        icon: FileText },
  { key: 'compliance', label: 'Compliance',      icon: ShieldCheck },
  { key: 'remote',     label: 'Remote Actions',  icon: Radio },
  { key: 'threats',    label: 'Threats',         icon: ShieldAlert },
  { key: 'analytics',  label: 'Analytics',       icon: BarChart3 },
  { key: 'ai',         label: 'AI Assistant',    icon: Sparkles },
  { key: 'reports',    label: 'Reports',         icon: FileBarChart2 },
  { key: 'audit',      label: 'Audit Trail',     icon: ScrollText },
];

export default function MDMPage() {
  const [tab, setTab]               = useState<Tab>('dashboard');
  const [showAI, setShowAI]         = useState(false);
  const [selectedDevice, setSelectedDevice] = useState<any>(null);
  const [showDevicePanel, setShowDevicePanel] = useState(false);
  const [unread, setUnread]         = useState(0);

  const [dashboard, setDashboard]   = useState<any>(null);
  const [devices, setDevices]       = useState<any[]>([]);
  const [apps, setApps]             = useState<any>(null);
  const [policies, setPolicies]     = useState<any[]>([]);
  const [compliance, setCompliance] = useState<any>(null);
  const [remoteActions, setRemoteActions] = useState<any[]>([]);
  const [threats, setThreats]       = useState<any>(null);
  const [analytics, setAnalytics]   = useState<any>(null);
  const [reports, setReports]       = useState<any[]>([]);
  const [notifications, setNotifications] = useState<any[]>([]);
  const [audit, setAudit]           = useState<any[]>([]);

  const loadAll = useCallback(async () => {
    const [dash, devs, appData, pols, comp, ra, thr, anal, rpts, notifs, aud] = await Promise.all([
      mdmeAPI.getDashboard(),
      mdmeAPI.getDevices(),
      mdmeAPI.getApps(),
      mdmeAPI.getPolicies(),
      mdmeAPI.getCompliance(),
      mdmeAPI.getRemoteActions(),
      mdmeAPI.getThreats(),
      mdmeAPI.getAnalytics(),
      mdmeAPI.getReports(),
      mdmeAPI.getNotifications(),
      mdmeAPI.getAudit(),
    ]);
    setDashboard(dash.data);
    setDevices(Array.isArray(devs.data) ? devs.data : []);
    setApps(appData.data);
    setPolicies(Array.isArray(pols.data) ? pols.data : []);
    setCompliance(comp.data);
    setRemoteActions(Array.isArray(ra.data) ? ra.data : []);
    setThreats(thr.data);
    setAnalytics(anal.data);
    setReports(Array.isArray(rpts.data) ? rpts.data : []);
    const notifArr = Array.isArray(notifs.data) ? notifs.data : [];
    setNotifications(notifArr);
    setUnread(notifArr.filter((n: any) => !n.read).length);
    setAudit(Array.isArray(aud.data) ? aud.data : []);
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  const handleDeviceSelect = (d: any) => {
    setSelectedDevice(d);
    setShowDevicePanel(true);
  };

  const markRead = async () => {
    await mdmeAPI.markNotificationsRead();
    setUnread(0);
  };

  const refreshRemoteActions = useCallback(async () => {
    const r = await mdmeAPI.getRemoteActions();
    setRemoteActions(Array.isArray(r.data) ? r.data : []);
  }, []);

  return (
    <RootLayout
      title="Mobile Device Management"
      onRefresh={loadAll}
      actions={
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <div style={{ position: 'relative' }}>
            <ActionButton variant="ghost" icon={Bell} onClick={() => { setTab('audit'); markRead(); }} />
            {unread > 0 && (
              <span style={{ position: 'absolute', top: -4, right: -4, background: '#ef4444', color: '#fff', borderRadius: '50%', width: 16, height: 16, fontSize: 10, display: 'flex', alignItems: 'center', justifyContent: 'center', pointerEvents: 'none' }}>
                {unread}
              </span>
            )}
          </div>
          <ActionButton variant="ghost" icon={Sparkles} onClick={() => setShowAI(v => !v)}>AI Assistant</ActionButton>
        </div>
      }
    >
      {/* tab bar */}
      <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: 2, marginBottom: 24, overflowX: 'auto' }}>
        <TabBar tabs={TABS} active={tab} onChange={k => setTab(k as Tab)} />
      </div>

      {tab === 'dashboard'  && <DashboardTab d={dashboard} />}
      {tab === 'inventory'  && <InventoryTab devices={devices} onSelect={handleDeviceSelect} />}
      {tab === 'apps'       && <AppsTab d={apps} />}
      {tab === 'policies'   && <PoliciesTab policies={policies} />}
      {tab === 'compliance' && <ComplianceTab d={compliance} />}
      {tab === 'remote'     && <RemoteActionsTab actions={remoteActions} devices={devices} onRefresh={refreshRemoteActions} />}
      {tab === 'threats'    && <ThreatsTab d={threats} onRefresh={loadAll} />}
      {tab === 'analytics'  && <AnalyticsTab d={analytics} />}
      {tab === 'ai'         && <AIInsightsTab device={selectedDevice} />}
      {tab === 'reports'    && <ReportsTab reports={reports} onRefresh={() => mdmeAPI.getReports().then(r => setReports(r.data ?? []))} />}
      {tab === 'audit'      && <AuditTab entries={audit} />}

      {showDevicePanel && selectedDevice && (
        <DevicePanel deviceId={selectedDevice.device_id} onClose={() => setShowDevicePanel(false)} onRemoteAction={() => {}} />
      )}
      {showAI && <AIPanel onClose={() => setShowAI(false)} device={selectedDevice} />}
    </RootLayout>
  );
}
