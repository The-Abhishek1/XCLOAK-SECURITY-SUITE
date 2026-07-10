'use client';

import { useState, useEffect, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { vulnQueueAPI } from '@/lib/api';
import { VulnQueueItem } from '@/types';
import { RefreshCw, ChevronDown, ChevronRight, ExternalLink, Shield, Zap, Download } from 'lucide-react';

const SEV_COLOR: Record<string, string> = { critical: '#f85149', high: '#fb923c', medium: '#fbbf24', low: '#22c55e' };

const PATCH_STATUSES = [
  { value: 'open',          label: 'Open',          color: '#f85149' },
  { value: 'in_progress',   label: 'In Progress',   color: '#fb923c' },
  { value: 'patched',       label: 'Patched',       color: '#22c55e' },
  { value: 'accepted_risk', label: 'Accepted Risk',  color: '#6b7280' },
];

function PriorityBar({ score }: { score: number }) {
  const color = score >= 700 ? '#f85149' : score >= 400 ? '#fb923c' : score >= 200 ? '#fbbf24' : '#22c55e';
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--glass-bg-2)' }}>
        <div className="h-full rounded-full" style={{ width: `${Math.min(100, score / 10)}%`, background: color }} />
      </div>
      <span className="text-xs tabular-nums font-semibold" style={{ color }}>{score}</span>
    </div>
  );
}

function PatchStatusBadge({ status }: { status: string }) {
  const s = PATCH_STATUSES.find(x => x.value === status) || PATCH_STATUSES[0];
  return (
    <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded" style={{
      background: `${s.color}18`, color: s.color, border: `1px solid ${s.color}40`,
    }}>{s.label}</span>
  );
}

function VulnRow({ v, expanded, onToggle, onStatusChange }: {
  v: VulnQueueItem;
  expanded: boolean;
  onToggle: () => void;
  onStatusChange: (status: string, notes: string) => void;
}) {
  const [saving, setSaving] = useState(false);
  const [draftStatus, setDraftStatus] = useState(v.patch_status);
  const [draftNotes, setDraftNotes] = useState(v.patch_notes);

  const save = async () => {
    setSaving(true);
    await onStatusChange(draftStatus, draftNotes);
    setSaving(false);
  };

  return (
    <>
      <tr className="cursor-pointer transition-colors hover:bg-[var(--glass-bg-2)]" onClick={onToggle}>
        <td className="px-3 py-2.5">
          <div className="flex items-center gap-2">
            {expanded ? <ChevronDown className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />
                      : <ChevronRight className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />}
            <PriorityBar score={v.priority_score} />
          </div>
        </td>
        <td className="px-3 py-2.5">
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] font-bold px-1 rounded" style={{
              color: SEV_COLOR[v.severity], background: `${SEV_COLOR[v.severity]}18`,
              border: `1px solid ${SEV_COLOR[v.severity]}40`,
            }}>{v.severity.toUpperCase()}</span>
            {v.is_kev && <span className="text-[10px] px-1 rounded font-bold" style={{
              background: 'rgba(248,81,73,0.15)', color: '#f85149', border: '1px solid rgba(248,81,73,0.4)',
            }}>KEV</span>}
            {v.kev_ransomware && <span className="text-[10px] px-1 rounded font-bold" style={{
              background: 'rgba(168,85,247,0.15)', color: '#a855f7', border: '1px solid rgba(168,85,247,0.4)',
            }}>RANSOM</span>}
          </div>
        </td>
        <td className="px-3 py-2.5 font-mono text-xs" style={{ color: 'var(--accent)' }}>
          <a href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`} target="_blank" rel="noopener noreferrer"
            className="flex items-center gap-1 hover:underline" onClick={e => e.stopPropagation()}>
            {v.cve_id} <ExternalLink className="h-2.5 w-2.5" />
          </a>
        </td>
        <td className="px-3 py-2.5">
          <p className="text-xs truncate max-w-[180px]" style={{ color: 'var(--text-1)' }}>{v.package_name}</p>
          <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{v.package_version}</p>
        </td>
        <td className="px-3 py-2.5 text-xs" style={{ color: 'var(--text-2)' }}>{v.hostname || '—'}</td>
        <td className="px-3 py-2.5">
          <div className="flex items-center gap-2 text-[11px]" style={{ color: 'var(--text-3)' }}>
            <span title="CVSS">C:{v.cvss_score.toFixed(1)}</span>
            <span title="EPSS" style={{ color: v.epss_score > 0.5 ? '#f85149' : 'var(--text-3)' }}>
              E:{(v.epss_score * 100).toFixed(1)}%
            </span>
          </div>
        </td>
        <td className="px-3 py-2.5"><PatchStatusBadge status={v.patch_status} /></td>
        <td className="px-3 py-2.5 text-[11px]" style={{ color: 'var(--text-3)' }}>
          {v.patch_sla_days ? `${v.patch_sla_days}d` : '—'}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={8} className="px-4 pb-4 pt-1">
            <div className="rounded-xl p-4 space-y-3" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>Description</p>
                  <p className="text-xs" style={{ color: 'var(--text-2)' }}>{v.name || '—'}</p>
                </div>
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>Remediation</p>
                  <p className="text-xs" style={{ color: 'var(--text-2)' }}>{v.remediation || 'Update to latest patched version.'}</p>
                </div>
              </div>
              <div className="flex gap-3 items-end flex-wrap">
                <div>
                  <label className="block text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>Patch Status</label>
                  <select value={draftStatus} onChange={e => setDraftStatus(e.target.value as any)}
                    className="g-select text-xs" onClick={e => e.stopPropagation()}>
                    {PATCH_STATUSES.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
                  </select>
                </div>
                <div className="flex-1 min-w-[160px]">
                  <label className="block text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>Notes</label>
                  <input value={draftNotes} onChange={e => setDraftNotes(e.target.value)}
                    placeholder="Ticket #, assignee, etc."
                    className="g-input text-xs w-full" onClick={e => e.stopPropagation()} />
                </div>
                <button onClick={e => { e.stopPropagation(); save(); }} disabled={saving}
                  className="g-btn g-btn-primary text-xs flex items-center gap-1.5">
                  {saving ? 'Saving…' : 'Save'}
                </button>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export default function VulnQueuePage() {
  const [items, setItems] = useState<VulnQueueItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [expandedID, setExpandedID] = useState<number | null>(null);
  const [statusFilter, setStatusFilter] = useState('open,in_progress');

  const load = useCallback(async () => {
    setLoading(true);
    const r = await vulnQueueAPI.getQueue({ status: statusFilter });
    setItems(r.data.items || []);
    setTotal(r.data.total || 0);
    setLoading(false);
  }, [statusFilter]);

  useEffect(() => { load(); }, [load]);

  const refresh = async () => {
    setRefreshing(true);
    await vulnQueueAPI.refresh();
    setTimeout(() => { load(); setRefreshing(false); }, 2000);
  };

  const updateStatus = async (id: number, status: string, notes: string) => {
    await vulnQueueAPI.updateStatus(id, status, notes);
    setItems(prev => prev.map(v => v.id === id ? { ...v, patch_status: status as any, patch_notes: notes } : v));
  };

  const criticalCount = items.filter(i => i.severity === 'critical').length;
  const kevCount = items.filter(i => i.is_kev).length;
  const highScore = items.filter(i => i.priority_score >= 700).length;

  const exportCSV = () => {
    const headers = ['CVE', 'Severity', 'Package', 'Version', 'Host', 'CVSS', 'EPSS%', 'KEV', 'Priority', 'Status', 'Notes'];
    const rows = items.map(v => [
      v.cve_id, v.severity, v.package_name, v.package_version, v.hostname || '',
      v.cvss_score.toFixed(1), (v.epss_score * 100).toFixed(2),
      v.is_kev ? 'Yes' : 'No', v.priority_score, v.patch_status, v.patch_notes || '',
    ]);
    const csv = [headers, ...rows].map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
    const a = Object.assign(document.createElement('a'), {
      href: URL.createObjectURL(new Blob([csv], { type: 'text/csv' })),
      download: `vuln-queue-${new Date().toISOString().slice(0, 10)}.csv`,
    });
    a.click(); URL.revokeObjectURL(a.href);
  };

  return (
    <RootLayout title="Vulnerability Priority Queue" subtitle="Risk-ranked patch tracking · CVSS + EPSS + KEV + Asset criticality"
      actions={
        <div className="flex gap-2">
          {items.length > 0 && (
            <button onClick={exportCSV} className="g-btn g-btn-ghost flex items-center gap-1.5 text-xs">
              <Download className="h-3.5 w-3.5" /> Export CSV
            </button>
          )}
          <button onClick={refresh} disabled={refreshing}
            className="g-btn g-btn-ghost flex items-center gap-1.5 text-xs">
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            {refreshing ? 'Rescoring…' : 'Rescore'}
          </button>
        </div>
      }>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
        {[
          { label: 'In Queue', value: total, color: 'var(--text-1)' },
          { label: 'Critical', value: criticalCount, color: '#f85149' },
          { label: 'KEV', value: kevCount, color: '#a855f7' },
          { label: 'Score ≥700', value: highScore, color: '#fb923c' },
        ].map(({ label, value, color }) => (
          <div key={label} className="g-card p-4">
            <p className="text-2xl font-bold" style={{ color }}>{value}</p>
            <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{label}</p>
          </div>
        ))}
      </div>

      {/* Filter */}
      <div className="flex gap-2 mb-4 flex-wrap">
        {[
          { label: 'Open + In Progress', value: 'open,in_progress' },
          { label: 'All', value: 'open,in_progress,patched,accepted_risk' },
          { label: 'Patched', value: 'patched' },
          { label: 'Accepted Risk', value: 'accepted_risk' },
        ].map(f => (
          <button key={f.value} onClick={() => setStatusFilter(f.value)}
            className="text-xs px-3 py-1.5 rounded-lg transition-colors"
            style={{
              background: statusFilter === f.value ? 'var(--accent)' : 'var(--glass-bg-2)',
              color: statusFilter === f.value ? '#000' : 'var(--text-2)',
              border: '1px solid var(--border)',
            }}>{f.label}</button>
        ))}
        <span className="ml-auto text-[11px] self-center" style={{ color: 'var(--text-3)' }}>
          {total} vulnerabilities · Score = CVSS×10 + EPSS×200 + KEV+300 + Criticality + Risk bonus
        </span>
      </div>

      {/* Table */}
      <div className="g-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full" style={{ borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Priority', 'Severity', 'CVE', 'Package', 'Host', 'Scores', 'Status', 'SLA'].map(h => (
                  <th key={h} className="px-3 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wider"
                    style={{ color: 'var(--text-3)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody style={{ borderColor: 'var(--border)' }}>
              {loading ? (
                <tr><td colSpan={8} className="px-4 py-12 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</td></tr>
              ) : items.length === 0 ? (
                <tr><td colSpan={8} className="px-4 py-12 text-center">
                  <Shield className="mx-auto h-10 w-10 mb-2 opacity-20" style={{ color: 'var(--text-3)' }} />
                  <p className="text-sm" style={{ color: 'var(--text-3)' }}>
                    No vulnerabilities in this view. Run a vulnerability scan from the Agents page.
                  </p>
                </td></tr>
              ) : items.map(v => (
                <VulnRow key={v.id} v={v}
                  expanded={expandedID === v.id}
                  onToggle={() => setExpandedID(prev => prev === v.id ? null : v.id)}
                  onStatusChange={(s, n) => updateStatus(v.id, s, n)} />
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </RootLayout>
  );
}
