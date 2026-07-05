'use client';

import { useState, useEffect, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { mdmAPI } from '@/lib/api';
import {
  Smartphone, ShieldCheck, ShieldOff, AlertTriangle, Ban,
  Copy, Check, Trash2, Plus, RefreshCw, ChevronDown, ChevronRight,
  Lock, Unlock, Key, Clock, CheckCircle2, XCircle, Circle,
  Search, X, Wifi, WifiOff, Terminal, Shield,
} from 'lucide-react';

// ── Types ─────────────────────────────────────────────────────────────────────

interface MDMDevice {
  id: number;
  udid: string;
  device_name: string;
  model: string;
  platform: string;
  os_version: string;
  owner_email: string;
  enrollment_type: string;
  enrolled_at: string;
  last_check_in: string | null;
  status: string; // enrolled | blocked | unenrolled
  is_encrypted: boolean | null;
  has_passcode: boolean | null;
  is_jailbroken: boolean;
  developer_mode_on: boolean;
  compliance_status: string; // compliant | non_compliant | unknown
}

interface EnrollmentToken {
  id: number;
  token: string;
  label: string;
  platform: string;
  used_count: number;
  max_uses: number | null;
  expires_at: string | null;
  created_at: string;
}

interface MDMCommand {
  id: number;
  device_id: number;
  command_type: string;
  status: string; // pending | sent | done | failed
  queued_at: string;
  sent_at: string | null;
  acknowledged_at: string | null;
  error_msg: string;
}

interface ComplianceResult {
  rule_type: string;
  status: string;
  actual_value: string;
  severity: string;
}

type Tab = 'devices' | 'tokens' | 'commands';

// ── Helpers ───────────────────────────────────────────────────────────────────

function ago(ts: string | null) {
  if (!ts) return '—';
  const s = (Date.now() - new Date(ts).getTime()) / 1000;
  if (s < 60)    return 'just now';
  if (s < 3600)  return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function isOnline(ts: string | null) {
  if (!ts) return false;
  return (Date.now() - new Date(ts).getTime()) < 15 * 60 * 1000;
}

function fmtDate(ts: string | null) {
  if (!ts) return '—';
  return new Date(ts).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

function useCopy() {
  const [copied, setCopied] = useState<string | null>(null);
  const copy = (text: string, key: string) => {
    navigator.clipboard.writeText(text).catch(() => {});
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };
  return { copied, copy };
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function StatusDot({ online }: { online: boolean }) {
  return (
    <span className="inline-block h-2 w-2 rounded-full shrink-0"
      style={{ background: online ? 'var(--green)' : 'var(--text-3)' }} />
  );
}

function PostureBadge({ ok, label }: { ok: boolean | null; label: string }) {
  if (ok === null) return null;
  return (
    <span className="inline-flex items-center gap-0.5 rounded px-1.5 py-0.5 text-[10px] font-semibold"
      style={{
        background: ok ? 'rgba(34,197,94,0.12)' : 'rgba(239,68,68,0.12)',
        color: ok ? 'var(--green)' : 'var(--red)',
      }}>
      {ok ? <Check className="h-2.5 w-2.5" /> : <X className="h-2.5 w-2.5" />}
      {label}
    </span>
  );
}

function ComplianceBadge({ status }: { status: string }) {
  const map: Record<string, { bg: string; color: string; label: string }> = {
    compliant:     { bg: 'rgba(34,197,94,0.12)',  color: 'var(--green)',  label: 'Compliant' },
    non_compliant: { bg: 'rgba(239,68,68,0.12)',  color: 'var(--red)',    label: 'Non-Compliant' },
    unknown:       { bg: 'rgba(156,163,175,0.12)', color: 'var(--text-3)', label: 'Unknown' },
  };
  const s = map[status] ?? map.unknown;
  return (
    <span className="inline-block rounded px-2 py-0.5 text-[11px] font-semibold"
      style={{ background: s.bg, color: s.color }}>
      {s.label}
    </span>
  );
}

function DeviceStatusBadge({ status }: { status: string }) {
  const map: Record<string, { bg: string; color: string }> = {
    enrolled:   { bg: 'rgba(34,211,238,0.12)',  color: 'var(--accent)' },
    blocked:    { bg: 'rgba(239,68,68,0.12)',   color: 'var(--red)' },
    unenrolled: { bg: 'rgba(156,163,175,0.12)', color: 'var(--text-3)' },
  };
  const s = map[status] ?? map.unenrolled;
  return (
    <span className="inline-block rounded px-2 py-0.5 text-[11px] font-semibold capitalize"
      style={{ background: s.bg, color: s.color }}>
      {status}
    </span>
  );
}

function CmdStatusBadge({ status }: { status: string }) {
  const map: Record<string, { color: string; icon: React.ReactNode }> = {
    pending:      { color: 'var(--orange)', icon: <Clock className="h-3 w-3" /> },
    sent:         { color: 'var(--accent)',  icon: <RefreshCw className="h-3 w-3" /> },
    acknowledged: { color: 'var(--green)',   icon: <CheckCircle2 className="h-3 w-3" /> },
    failed:       { color: 'var(--red)',     icon: <XCircle className="h-3 w-3" /> },
    timed_out:    { color: 'var(--red)',     icon: <XCircle className="h-3 w-3" /> },
  };
  const s = map[status] ?? { color: 'var(--text-3)', icon: <Circle className="h-3 w-3" /> };
  return (
    <span className="inline-flex items-center gap-1 text-[11px] font-semibold capitalize"
      style={{ color: s.color }}>
      {s.icon} {status}
    </span>
  );
}

function Toast({ msg, onDone }: { msg: string; onDone: () => void }) {
  useEffect(() => { const t = setTimeout(onDone, 3000); return () => clearTimeout(t); }, [onDone]);
  return (
    <div className="fixed bottom-6 right-6 z-50 rounded-xl px-5 py-3 text-sm font-medium shadow-xl"
      style={{ background: 'var(--bg-1)', border: '1px solid var(--accent-border)', color: 'var(--accent)' }}>
      {msg}
    </div>
  );
}

// ── Stat Card ─────────────────────────────────────────────────────────────────

function StatCard({ label, value, sub, accent }: { label: string; value: number | string; sub?: string; accent?: string }) {
  return (
    <div className="g-card flex flex-col gap-1 p-4">
      <p className="text-[11px] font-medium uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>{label}</p>
      <p className="text-2xl font-bold" style={{ color: accent ?? 'var(--text-1)' }}>{value}</p>
      {sub && <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{sub}</p>}
    </div>
  );
}

// ── Compliance Detail Modal ───────────────────────────────────────────────────

function ComplianceModal({ device, onClose }: { device: MDMDevice; onClose: () => void }) {
  const [results, setResults] = useState<ComplianceResult[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    mdmAPI.getCompliance(device.id)
      .then(r => setResults(r.data?.results ?? []))
      .finally(() => setLoading(false));
  }, [device.id]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(6px)' }}
      onClick={onClose}>
      <div className="g-card w-full max-w-lg p-6 space-y-4" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <div>
            <p className="font-bold" style={{ color: 'var(--text-1)' }}>{device.device_name}</p>
            <p className="text-xs" style={{ color: 'var(--text-3)' }}>{device.model} · Android {device.os_version}</p>
          </div>
          <button onClick={onClose} style={{ color: 'var(--text-3)' }}><X className="h-4 w-4" /></button>
        </div>

        <div className="flex flex-wrap gap-2">
          <PostureBadge ok={device.is_encrypted} label="Encrypted" />
          <PostureBadge ok={device.has_passcode} label="Passcode" />
          <PostureBadge ok={device.is_jailbroken ? false : true} label="Not Rooted" />
          <PostureBadge ok={device.developer_mode_on ? false : true} label="Dev Mode Off" />
        </div>

        {loading ? (
          <p className="text-sm" style={{ color: 'var(--text-3)' }}>Loading compliance results…</p>
        ) : results.length === 0 ? (
          <p className="text-sm" style={{ color: 'var(--text-3)' }}>No compliance rules evaluated yet.</p>
        ) : (
          <div className="space-y-2">
            {results.map((r, i) => (
              <div key={i} className="flex items-center justify-between rounded-lg px-3 py-2"
                style={{ background: 'var(--bg-1)' }}>
                <div>
                  <p className="text-[12px] font-medium" style={{ color: 'var(--text-1)' }}>
                    {r.rule_type.replace(/_/g, ' ')}
                  </p>
                  {r.actual_value && (
                    <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>value: {r.actual_value}</p>
                  )}
                </div>
                <span className="text-[11px] font-semibold capitalize"
                  style={{ color: r.status === 'pass' ? 'var(--green)' : 'var(--red)' }}>
                  {r.status}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Command Queue Modal ───────────────────────────────────────────────────────

const CMD_TYPES = [
  { value: 'collect_apps',  label: 'Collect App Inventory' },
  { value: 'sync',          label: 'Force Sync' },
  { value: 'lock',          label: 'Lock Device' },
  { value: 'wipe',          label: 'Remote Wipe' },
  { value: 'push_profile',  label: 'Push Profile' },
  { value: 'collect_logs',  label: 'Collect Logs' },
];

function QueueCommandModal({
  devices,
  preselect,
  onClose,
  onQueued,
}: {
  devices: MDMDevice[];
  preselect?: number;
  onClose: () => void;
  onQueued: (msg: string) => void;
}) {
  const [deviceId, setDeviceId] = useState<number>(preselect ?? (devices[0]?.id ?? 0));
  const [cmdType, setCmdType]   = useState('collect_apps');
  const [busy, setBusy]         = useState(false);

  async function submit() {
    if (!deviceId) return;
    setBusy(true);
    try {
      await mdmAPI.queueCommand(deviceId, cmdType);
      onQueued(`Command "${cmdType}" queued`);
      onClose();
    } catch {
      onQueued('Failed to queue command');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(6px)' }}
      onClick={onClose}>
      <div className="g-card w-full max-w-md p-6 space-y-4" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <p className="font-bold" style={{ color: 'var(--text-1)' }}>Queue Command</p>
          <button onClick={onClose} style={{ color: 'var(--text-3)' }}><X className="h-4 w-4" /></button>
        </div>

        <div className="space-y-3">
          <div>
            <label className="block text-[11px] font-medium mb-1" style={{ color: 'var(--text-3)' }}>Device</label>
            <select className="g-input w-full" value={deviceId} onChange={e => setDeviceId(Number(e.target.value))}>
              {devices.map(d => (
                <option key={d.id} value={d.id}>{d.device_name || d.udid} — {d.owner_email || 'no email'}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-[11px] font-medium mb-1" style={{ color: 'var(--text-3)' }}>Command</label>
            <select className="g-input w-full" value={cmdType} onChange={e => setCmdType(e.target.value)}>
              {CMD_TYPES.map(c => <option key={c.value} value={c.value}>{c.label}</option>)}
            </select>
          </div>

          {cmdType === 'wipe' && (
            <div className="rounded-lg px-3 py-2 text-[12px]"
              style={{ background: 'rgba(239,68,68,0.1)', color: 'var(--red)', border: '1px solid rgba(239,68,68,0.3)' }}>
              Warning: Remote Wipe will erase all device data and cannot be undone.
            </div>
          )}
        </div>

        <div className="flex gap-2 justify-end">
          <button className="g-btn px-4 py-2" onClick={onClose}>Cancel</button>
          <button
            className="g-btn-primary px-4 py-2 flex items-center gap-2"
            onClick={submit}
            disabled={busy || !deviceId}
            style={{ opacity: busy || !deviceId ? 0.6 : 1 }}>
            {busy ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Terminal className="h-3.5 w-3.5" />}
            Queue
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Create Token Modal ────────────────────────────────────────────────────────

function CreateTokenModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (token: EnrollmentToken) => void;
}) {
  const [label, setLabel]       = useState('');
  const [platform, setPlatform] = useState('any');
  const [maxUses, setMaxUses]   = useState('');
  const [expiresIn, setExpiresIn] = useState('');
  const [busy, setBusy]         = useState(false);
  const [err, setErr]           = useState('');

  async function submit() {
    if (!label.trim()) { setErr('Label is required'); return; }
    setBusy(true); setErr('');
    try {
      const mu = maxUses ? parseInt(maxUses) : undefined;
      const ei = expiresIn ? parseInt(expiresIn) * 86400 : undefined; // days → seconds
      const res = await mdmAPI.createToken(label.trim(), platform, mu, ei);
      onCreated(res.data as EnrollmentToken);
    } catch {
      setErr('Failed to create token');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(6px)' }}
      onClick={onClose}>
      <div className="g-card w-full max-w-md p-6 space-y-4" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <p className="font-bold" style={{ color: 'var(--text-1)' }}>Generate Enrollment Token</p>
          <button onClick={onClose} style={{ color: 'var(--text-3)' }}><X className="h-4 w-4" /></button>
        </div>

        <div className="space-y-3">
          <div>
            <label className="block text-[11px] font-medium mb-1" style={{ color: 'var(--text-3)' }}>Label *</label>
            <input className="g-input w-full" placeholder="e.g. Sales Team Q3" value={label}
              onChange={e => setLabel(e.target.value)} />
          </div>
          <div>
            <label className="block text-[11px] font-medium mb-1" style={{ color: 'var(--text-3)' }}>Platform</label>
            <select className="g-input w-full" value={platform} onChange={e => setPlatform(e.target.value)}>
              <option value="any">Any</option>
              <option value="android">Android</option>
              <option value="ios">iOS</option>
            </select>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[11px] font-medium mb-1" style={{ color: 'var(--text-3)' }}>Max Uses (blank = unlimited)</label>
              <input className="g-input w-full" type="number" min="1" placeholder="unlimited" value={maxUses}
                onChange={e => setMaxUses(e.target.value)} />
            </div>
            <div>
              <label className="block text-[11px] font-medium mb-1" style={{ color: 'var(--text-3)' }}>Expires In (days, blank = never)</label>
              <input className="g-input w-full" type="number" min="1" placeholder="never" value={expiresIn}
                onChange={e => setExpiresIn(e.target.value)} />
            </div>
          </div>
          {err && <p className="text-[12px]" style={{ color: 'var(--red)' }}>{err}</p>}
        </div>

        <div className="flex gap-2 justify-end">
          <button className="g-btn px-4 py-2" onClick={onClose}>Cancel</button>
          <button className="g-btn-primary px-4 py-2 flex items-center gap-2"
            onClick={submit} disabled={busy} style={{ opacity: busy ? 0.6 : 1 }}>
            {busy ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Key className="h-3.5 w-3.5" />}
            Generate
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Token Display Modal (shown after creation) ────────────────────────────────

function TokenDisplayModal({ token, onClose }: { token: EnrollmentToken; onClose: () => void }) {
  const { copied, copy } = useCopy();

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(6px)' }}>
      <div className="g-card w-full max-w-lg p-6 space-y-4">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl"
            style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
            <Key className="h-4 w-4" style={{ color: 'var(--accent)' }} />
          </div>
          <div>
            <p className="font-bold" style={{ color: 'var(--text-1)' }}>Enrollment Token Created</p>
            <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>Copy this token — share it with the device owner to enroll</p>
          </div>
        </div>

        <div className="rounded-xl p-4" style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
          <p className="break-all font-mono text-sm" style={{ color: 'var(--accent)' }}>{token.token}</p>
        </div>

        <div className="grid grid-cols-2 gap-3 text-[12px]" style={{ color: 'var(--text-3)' }}>
          <div><span className="font-medium">Label:</span> {token.label}</div>
          <div><span className="font-medium">Platform:</span> {token.platform}</div>
          <div><span className="font-medium">Max Uses:</span> {token.max_uses ?? 'unlimited'}</div>
          <div><span className="font-medium">Expires:</span> {token.expires_at ? fmtDate(token.expires_at) : 'never'}</div>
        </div>

        <div className="flex gap-2 justify-end">
          <button
            className="g-btn-primary px-4 py-2 flex items-center gap-2"
            onClick={() => copy(token.token, 'new')}>
            {copied === 'new' ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
            {copied === 'new' ? 'Copied!' : 'Copy Token'}
          </button>
          <button className="g-btn px-4 py-2" onClick={onClose}>Done</button>
        </div>
      </div>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function MDMPage() {
  const [tab, setTab]                   = useState<Tab>('devices');
  const [loading, setLoading]           = useState(true);
  const [refreshing, setRefreshing]     = useState(false);
  const [devices, setDevices]           = useState<MDMDevice[]>([]);
  const [tokens, setTokens]             = useState<EnrollmentToken[]>([]);
  const [commands, setCommands]         = useState<MDMCommand[]>([]);
  const [search, setSearch]             = useState('');
  const [toast, setToast]               = useState<string | null>(null);
  const [actionId, setActionId]         = useState<number | null>(null);

  // Modals
  const [complianceDevice, setComplianceDevice] = useState<MDMDevice | null>(null);
  const [showCreateToken, setShowCreateToken]   = useState(false);
  const [newToken, setNewToken]                 = useState<EnrollmentToken | null>(null);
  const [showCmdModal, setShowCmdModal]         = useState(false);
  const [cmdPreselect, setCmdPreselect]         = useState<number | undefined>();

  const { copied, copy } = useCopy();

  const showToast = (msg: string) => { setToast(msg); };

  // ── Load ──────────────────────────────────────────────────────────────────

  const loadDevices = useCallback(async () => {
    const res = await mdmAPI.getDevices();
    setDevices(res.data?.devices ?? []);
  }, []);

  const loadTokens = useCallback(async () => {
    const res = await mdmAPI.getTokens();
    setTokens(Array.isArray(res.data) ? res.data : []);
  }, []);

  const loadAllCommands = useCallback(async (devs: MDMDevice[]) => {
    if (devs.length === 0) return;
    const results = await Promise.allSettled(
      devs.map(d => mdmAPI.getCommands(d.id, 20))
    );
    const all: MDMCommand[] = [];
    results.forEach(r => {
      if (r.status === 'fulfilled') all.push(...(r.value.data?.commands ?? []));
    });
    all.sort((a, b) => new Date(b.queued_at).getTime() - new Date(a.queued_at).getTime());
    setCommands(all.slice(0, 100));
  }, []);

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const [devRes, tokRes] = await Promise.allSettled([loadDevices(), loadTokens()]);
      if (devRes.status === 'fulfilled') {
        const devs = await mdmAPI.getDevices().then(r => r.data?.devices ?? []);
        await loadAllCommands(devs);
      }
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [loadDevices, loadTokens, loadAllCommands]);

  useEffect(() => { load(); }, [load]);

  // ── Actions ───────────────────────────────────────────────────────────────

  async function toggleBlock(device: MDMDevice) {
    setActionId(device.id);
    try {
      if (device.status === 'blocked') {
        await mdmAPI.unblockDevice(device.id);
        showToast(`${device.device_name || device.udid} unblocked`);
      } else {
        await mdmAPI.blockDevice(device.id);
        showToast(`${device.device_name || device.udid} blocked`);
      }
      await loadDevices();
    } catch { showToast('Action failed'); }
    finally { setActionId(null); }
  }

  async function unenroll(device: MDMDevice) {
    if (!confirm(`Unenroll ${device.device_name || device.udid}? This cannot be undone.`)) return;
    setActionId(device.id);
    try {
      await mdmAPI.unenrollDevice(device.id);
      showToast('Device unenrolled');
      await loadDevices();
    } catch { showToast('Unenroll failed'); }
    finally { setActionId(null); }
  }

  async function revokeToken(id: number) {
    if (!confirm('Revoke this enrollment token?')) return;
    try {
      await mdmAPI.revokeToken(id);
      showToast('Token revoked');
      await loadTokens();
    } catch { showToast('Revoke failed'); }
  }

  function openCmdModal(deviceId?: number) {
    setCmdPreselect(deviceId);
    setShowCmdModal(true);
  }

  // ── Derived ───────────────────────────────────────────────────────────────

  const online    = devices.filter(d => isOnline(d.last_check_in)).length;
  const compliant = devices.filter(d => d.compliance_status === 'compliant').length;
  const blocked   = devices.filter(d => d.status === 'blocked').length;

  const filtered = devices.filter(d => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      d.device_name?.toLowerCase().includes(q) ||
      d.model?.toLowerCase().includes(q) ||
      d.owner_email?.toLowerCase().includes(q) ||
      d.udid?.toLowerCase().includes(q)
    );
  });

  const tabs: { id: Tab; label: string }[] = [
    { id: 'devices',  label: `Devices (${devices.length})` },
    { id: 'tokens',   label: `Enrollment Tokens (${tokens.length})` },
    { id: 'commands', label: `Commands (${commands.length})` },
  ];

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <RootLayout
      title="Mobile Devices"
      subtitle={`MDM · ${devices.length} enrolled`}
      onRefresh={() => load(true)}
      refreshing={refreshing}>

      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
        <StatCard label="Enrolled"  value={devices.length} />
        <StatCard label="Online"    value={online}    accent="var(--green)"  sub="last 15 min" />
        <StatCard label="Compliant" value={compliant} accent="var(--accent)" />
        <StatCard label="Blocked"   value={blocked}   accent={blocked > 0 ? 'var(--red)' : undefined} />
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-4 p-1 rounded-xl w-fit"
        style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
        {tabs.map(t => (
          <button key={t.id}
            onClick={() => setTab(t.id)}
            className="px-4 py-1.5 rounded-lg text-[13px] font-medium transition-all"
            style={{
              background: tab === t.id ? 'var(--accent-glow)' : 'transparent',
              color:      tab === t.id ? 'var(--accent)'      : 'var(--text-3)',
              border:     tab === t.id ? '1px solid var(--accent-border)' : '1px solid transparent',
            }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Devices tab ──────────────────────────────────────────────────── */}
      {tab === 'devices' && (
        <div className="g-card">
          {/* Toolbar */}
          <div className="flex flex-wrap items-center gap-3 p-4" style={{ borderBottom: '1px solid var(--border)' }}>
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
              <input className="g-input w-full pl-8 text-sm" placeholder="Search devices…"
                value={search} onChange={e => setSearch(e.target.value)} />
            </div>
            <button
              className="g-btn-primary flex items-center gap-2 px-3 py-2 text-sm"
              onClick={() => openCmdModal()}>
              <Terminal className="h-3.5 w-3.5" /> Queue Command
            </button>
          </div>

          {loading ? (
            <div className="flex items-center justify-center py-20" style={{ color: 'var(--text-3)' }}>
              <RefreshCw className="h-5 w-5 animate-spin mr-2" /> Loading devices…
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 gap-3">
              <Smartphone className="h-10 w-10" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-3)' }}>
                {search ? 'No devices match your search.' : 'No devices enrolled yet.'}
              </p>
              {!search && (
                <p className="text-[12px]" style={{ color: 'var(--text-3)' }}>
                  Generate an enrollment token, then enter it in the XCloak mobile app.
                </p>
              )}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    {['Device', 'Owner', 'OS', 'Last Check-in', 'Posture', 'Compliance', 'Status', ''].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider"
                        style={{ color: 'var(--text-3)' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(d => (
                    <tr key={d.id}
                      style={{ borderBottom: '1px solid var(--border)' }}
                      className="hover:bg-[var(--glass-hover)] transition-colors">
                      {/* Device */}
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <StatusDot online={isOnline(d.last_check_in)} />
                          <div>
                            <p className="font-medium" style={{ color: 'var(--text-1)' }}>
                              {d.device_name || d.udid.slice(0, 12) + '…'}
                            </p>
                            <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{d.model}</p>
                          </div>
                        </div>
                      </td>
                      {/* Owner */}
                      <td className="px-4 py-3" style={{ color: 'var(--text-2)' }}>
                        {d.owner_email || '—'}
                      </td>
                      {/* OS */}
                      <td className="px-4 py-3" style={{ color: 'var(--text-2)' }}>
                        {d.platform} {d.os_version}
                      </td>
                      {/* Last check-in */}
                      <td className="px-4 py-3 whitespace-nowrap" style={{ color: 'var(--text-2)' }}>
                        {ago(d.last_check_in)}
                      </td>
                      {/* Posture */}
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          <PostureBadge ok={d.is_encrypted} label="Enc" />
                          <PostureBadge ok={d.has_passcode} label="Pin" />
                          {d.is_jailbroken && (
                            <span className="inline-flex items-center gap-0.5 rounded px-1.5 py-0.5 text-[10px] font-semibold"
                              style={{ background: 'rgba(239,68,68,0.12)', color: 'var(--red)' }}>
                              <AlertTriangle className="h-2.5 w-2.5" /> Rooted
                            </span>
                          )}
                          {d.developer_mode_on && (
                            <span className="inline-flex items-center gap-0.5 rounded px-1.5 py-0.5 text-[10px] font-semibold"
                              style={{ background: 'rgba(251,146,60,0.12)', color: 'var(--orange)' }}>
                              Dev
                            </span>
                          )}
                        </div>
                      </td>
                      {/* Compliance */}
                      <td className="px-4 py-3">
                        <button onClick={() => setComplianceDevice(d)}>
                          <ComplianceBadge status={d.compliance_status || 'unknown'} />
                        </button>
                      </td>
                      {/* Status */}
                      <td className="px-4 py-3">
                        <DeviceStatusBadge status={d.status} />
                      </td>
                      {/* Actions */}
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1">
                          <button
                            title={d.status === 'blocked' ? 'Unblock' : 'Block'}
                            onClick={() => toggleBlock(d)}
                            disabled={actionId === d.id}
                            className="flex h-7 w-7 items-center justify-center rounded-lg transition-colors"
                            style={{ color: d.status === 'blocked' ? 'var(--green)' : 'var(--orange)' }}
                            onMouseEnter={e => (e.currentTarget.style.background = 'var(--glass-hover)')}
                            onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                            {actionId === d.id
                              ? <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                              : d.status === 'blocked'
                                ? <Unlock className="h-3.5 w-3.5" />
                                : <Lock className="h-3.5 w-3.5" />}
                          </button>
                          <button
                            title="Queue Command"
                            onClick={() => openCmdModal(d.id)}
                            className="flex h-7 w-7 items-center justify-center rounded-lg transition-colors"
                            style={{ color: 'var(--accent)' }}
                            onMouseEnter={e => (e.currentTarget.style.background = 'var(--glass-hover)')}
                            onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                            <Terminal className="h-3.5 w-3.5" />
                          </button>
                          <button
                            title="Unenroll"
                            onClick={() => unenroll(d)}
                            className="flex h-7 w-7 items-center justify-center rounded-lg transition-colors"
                            style={{ color: 'var(--text-3)' }}
                            onMouseEnter={e => { (e.currentTarget.style.background = 'rgba(239,68,68,0.1)'); (e.currentTarget.style.color = 'var(--red)'); }}
                            onMouseLeave={e => { (e.currentTarget.style.background = 'transparent'); (e.currentTarget.style.color = 'var(--text-3)'); }}>
                            <Trash2 className="h-3.5 w-3.5" />
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
      )}

      {/* ── Tokens tab ───────────────────────────────────────────────────── */}
      {tab === 'tokens' && (
        <div className="g-card">
          <div className="flex items-center justify-between p-4" style={{ borderBottom: '1px solid var(--border)' }}>
            <p className="text-sm font-medium" style={{ color: 'var(--text-2)' }}>
              Enrollment tokens let mobile devices self-enroll via the XCloak app.
            </p>
            <button className="g-btn-primary flex items-center gap-2 px-3 py-2 text-sm"
              onClick={() => setShowCreateToken(true)}>
              <Plus className="h-3.5 w-3.5" /> Generate Token
            </button>
          </div>

          {tokens.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 gap-3">
              <Key className="h-10 w-10" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-3)' }}>No enrollment tokens yet.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    {['Label', 'Platform', 'Token', 'Used', 'Expires', 'Created', ''].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider"
                        style={{ color: 'var(--text-3)' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {tokens.map(t => {
                    const expired = t.expires_at ? new Date(t.expires_at) < new Date() : false;
                    const exhausted = t.max_uses != null && t.used_count >= t.max_uses;
                    return (
                      <tr key={t.id} style={{ borderBottom: '1px solid var(--border)' }}
                        className="hover:bg-[var(--glass-hover)] transition-colors">
                        <td className="px-4 py-3 font-medium" style={{ color: 'var(--text-1)' }}>{t.label}</td>
                        <td className="px-4 py-3 capitalize" style={{ color: 'var(--text-2)' }}>{t.platform}</td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <code className="text-[11px] font-mono" style={{ color: 'var(--accent)' }}>
                              {t.token.slice(0, 20)}…
                            </code>
                            <button
                              onClick={() => copy(t.token, String(t.id))}
                              className="flex h-6 w-6 items-center justify-center rounded transition-colors"
                              style={{ color: 'var(--text-3)' }}
                              title="Copy full token">
                              {copied === String(t.id)
                                ? <Check className="h-3 w-3" style={{ color: 'var(--green)' }} />
                                : <Copy className="h-3 w-3" />}
                            </button>
                          </div>
                        </td>
                        <td className="px-4 py-3" style={{ color: exhausted ? 'var(--red)' : 'var(--text-2)' }}>
                          {t.used_count}{t.max_uses != null ? ` / ${t.max_uses}` : ''}
                        </td>
                        <td className="px-4 py-3"
                          style={{ color: expired ? 'var(--red)' : 'var(--text-2)' }}>
                          {t.expires_at ? fmtDate(t.expires_at) : 'Never'}
                          {expired && ' (expired)'}
                        </td>
                        <td className="px-4 py-3" style={{ color: 'var(--text-3)' }}>{fmtDate(t.created_at)}</td>
                        <td className="px-4 py-3">
                          <button
                            onClick={() => revokeToken(t.id)}
                            className="flex h-7 w-7 items-center justify-center rounded-lg transition-colors"
                            style={{ color: 'var(--text-3)' }}
                            title="Revoke"
                            onMouseEnter={e => { (e.currentTarget.style.background = 'rgba(239,68,68,0.1)'); (e.currentTarget.style.color = 'var(--red)'); }}
                            onMouseLeave={e => { (e.currentTarget.style.background = 'transparent'); (e.currentTarget.style.color = 'var(--text-3)'); }}>
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── Commands tab ─────────────────────────────────────────────────── */}
      {tab === 'commands' && (
        <div className="g-card">
          <div className="flex items-center justify-between p-4" style={{ borderBottom: '1px solid var(--border)' }}>
            <p className="text-sm font-medium" style={{ color: 'var(--text-2)' }}>
              Recent commands queued across all enrolled devices.
            </p>
            <button className="g-btn-primary flex items-center gap-2 px-3 py-2 text-sm"
              onClick={() => openCmdModal()}>
              <Terminal className="h-3.5 w-3.5" /> Queue Command
            </button>
          </div>

          {commands.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 gap-3">
              <Terminal className="h-10 w-10" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-3)' }}>No commands queued yet.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    {['Device', 'Command', 'Status', 'Queued', 'Completed', 'Error'].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider"
                        style={{ color: 'var(--text-3)' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {commands.map(cmd => {
                    const dev = devices.find(d => d.id === cmd.device_id);
                    return (
                      <tr key={cmd.id} style={{ borderBottom: '1px solid var(--border)' }}
                        className="hover:bg-[var(--glass-hover)] transition-colors">
                        <td className="px-4 py-3 font-medium" style={{ color: 'var(--text-1)' }}>
                          {dev?.device_name || `Device #${cmd.device_id}`}
                        </td>
                        <td className="px-4 py-3">
                          <span className="font-mono text-[12px]" style={{ color: 'var(--accent)' }}>
                            {cmd.command_type}
                          </span>
                        </td>
                        <td className="px-4 py-3"><CmdStatusBadge status={cmd.status} /></td>
                        <td className="px-4 py-3 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>
                          {ago(cmd.queued_at)}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>
                          {cmd.acknowledged_at ? ago(cmd.acknowledged_at) : '—'}
                        </td>
                        <td className="px-4 py-3 text-[11px]"
                          style={{ color: cmd.error_msg ? 'var(--red)' : 'var(--text-3)', maxWidth: 200 }}>
                          {cmd.error_msg || '—'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── Modals ────────────────────────────────────────────────────────── */}

      {complianceDevice && (
        <ComplianceModal device={complianceDevice} onClose={() => setComplianceDevice(null)} />
      )}

      {showCreateToken && (
        <CreateTokenModal
          onClose={() => setShowCreateToken(false)}
          onCreated={t => {
            setShowCreateToken(false);
            setNewToken(t);
            loadTokens();
          }}
        />
      )}

      {newToken && (
        <TokenDisplayModal token={newToken} onClose={() => setNewToken(null)} />
      )}

      {showCmdModal && (
        <QueueCommandModal
          devices={devices.filter(d => d.status !== 'unenrolled')}
          preselect={cmdPreselect}
          onClose={() => setShowCmdModal(false)}
          onQueued={msg => { showToast(msg); load(false); }}
        />
      )}

      {toast && <Toast msg={toast} onDone={() => setToast(null)} />}
    </RootLayout>
  );
}
