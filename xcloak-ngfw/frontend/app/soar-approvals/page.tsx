'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { tasksAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import { ShieldCheck, CheckCircle2, XCircle, X, AlertTriangle, ChevronDown, ChevronRight, Clock } from 'lucide-react';
import { useUser } from '@/context/UserContext';

// Risk level per action — mirrors CrowdStrike's containment decision hierarchy
const RISK: Record<string, { label: string; color: string; bg: string }> = {
  isolate_host:    { label: 'High Risk', color: '#f85149', bg: 'rgba(248,81,73,0.12)' },
  quarantine_file: { label: 'High Risk', color: '#f85149', bg: 'rgba(248,81,73,0.12)' },
  kill_process:    { label: 'Med Risk',  color: '#fb923c', bg: 'rgba(251,146,60,0.12)' },
  execute_script:  { label: 'Med Risk',  color: '#fb923c', bg: 'rgba(251,146,60,0.12)' },
};
const riskOf = (t: string) => RISK[t] ?? { label: 'Low Risk', color: '#fbbf24', bg: 'rgba(251,191,36,0.10)' };

interface PendingTask {
  id: number;
  agent_id: number;
  hostname: string;
  task_type: string;
  payload: string;
  created_at: string;
}

export default function SoarApprovalsPage() {
  const { profile } = useUser();
  const [tasks, setTasks]       = useState<PendingTask[]>([]);
  const [loading, setLoading]   = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [acting, setActing]     = useState<number | null>(null);
  const [rejectId, setRejectId] = useState<number | null>(null);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [reason, setReason]     = useState('');
  const [toast, setToast]       = useState<string | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const r = await tasksAPI.getPendingApproval();
      setTasks(r.data || []);
    } finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(() => load(), 30000);
    return () => clearInterval(t);
  }, [load]);

  const approve = async (id: number) => {
    setActing(id);
    try {
      await tasksAPI.approve(id);
      setTasks(t => t.filter(x => x.id !== id));
      notify('Action approved — agent will run it on next poll');
    } catch (e: any) {
      notify(e?.response?.data?.error || 'Approve failed');
    } finally { setActing(null); }
  };

  const reject = async () => {
    if (rejectId == null) return;
    setActing(rejectId);
    try {
      await tasksAPI.reject(rejectId, reason || 'rejected by analyst');
      setTasks(t => t.filter(x => x.id !== rejectId));
      notify('Action rejected');
    } catch (e: any) {
      notify(e?.response?.data?.error || 'Reject failed');
    } finally { setActing(null); setRejectId(null); setReason(''); }
  };

  const isAdmin = profile?.role === 'admin';

  const describePayload = (raw: string) => {
    try {
      const p = JSON.parse(raw);
      const parts = Object.entries(p)
        .filter(([k]) => k !== 'log_sample')
        .map(([k, v]) => `${k}=${v}`);
      return parts.join('  ');
    } catch { return raw; }
  };

  return (
    <RootLayout title="SOAR Approval Queue" subtitle={`${tasks.length} destructive action(s) awaiting review`}
      onRefresh={() => load(true)} refreshing={refreshing}>

      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)', minWidth: 200 }}>{toast}</div>}

      {!isAdmin && (
        <div className="g-panel mb-4 flex items-center gap-2 px-4 py-3 text-xs" style={{ color: 'var(--text-2)' }}>
          <AlertTriangle className="h-4 w-4" style={{ color: 'var(--amber)' }} />
          Only admins can approve or reject these actions. You can view the queue.
        </div>
      )}

      <div className="g-table">
        <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '90px 120px 1fr 80px 20px 200px' }}>
          <span>Agent</span><span>Action</span><span>Context</span><span>Queued</span><span />
          <span>Decision</span>
        </div>

        {loading ? (
          <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
        ) : tasks.length === 0 ? (
          <div className="py-16 text-center">
            <ShieldCheck className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>Nothing awaiting approval.</p>
          </div>
        ) : tasks.map(t => {
          const risk = riskOf(t.task_type);
          const expanded = expandedId === t.id;
          let prettyPayload = '';
          try { prettyPayload = JSON.stringify(JSON.parse(t.payload), null, 2); } catch { prettyPayload = t.payload; }
          return (
            <div key={t.id} className="border-b" style={{ borderColor: 'var(--border)' }}>
              <div className="grid gap-3 items-center px-4 py-3"
                style={{ gridTemplateColumns: '90px 120px 1fr 80px 20px 200px' }}>
                <span className="text-xs truncate" style={{ color: 'var(--text-2)' }}>{t.hostname || `#${t.agent_id}`}</span>
                <div>
                  <span className="mono text-xs font-semibold block" style={{ color: 'var(--red)' }}>{t.task_type}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded mt-0.5 inline-block" style={{ background: risk.bg, color: risk.color }}>{risk.label}</span>
                </div>
                <span className="mono text-[11px] truncate" style={{ color: 'var(--text-3)' }}>{describePayload(t.payload)}</span>
                <span className="text-[11px] flex items-center gap-1" style={{ color: 'var(--text-3)' }}>
                  <Clock className="h-3 w-3" />{timeAgo(t.created_at)}
                </span>
                <button onClick={() => setExpandedId(expanded ? null : t.id)} style={{ color: 'var(--text-3)' }}>
                  {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                </button>
                <div className="flex items-center gap-2">
                  <button title="Approve — dispatch to agent" onClick={() => approve(t.id)}
                    disabled={!isAdmin || acting === t.id} className="g-btn text-xs"
                    style={{ background: 'rgba(52,211,153,0.15)', color: 'var(--green)', border: '1px solid rgba(52,211,153,0.3)', opacity: isAdmin ? 1 : 0.5 }}>
                    <CheckCircle2 className="h-3.5 w-3.5" /> Approve
                  </button>
                  <button title="Reject" onClick={() => setRejectId(t.id)}
                    disabled={!isAdmin || acting === t.id} className="g-btn text-xs"
                    style={{ background: 'var(--red-bg)', color: 'var(--red)', border: '1px solid var(--red-border)', opacity: isAdmin ? 1 : 0.5 }}>
                    <XCircle className="h-3.5 w-3.5" /> Reject
                  </button>
                </div>
              </div>
              {expanded && (
                <div className="px-4 pb-3">
                  <pre className="rounded-lg p-3 mono text-[11px] overflow-x-auto"
                    style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-2)', maxHeight: 200 }}>
                    {prettyPayload}
                  </pre>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {rejectId !== null && (
        <div className="g-modal-backdrop" onClick={() => setRejectId(null)}>
          <div className="g-modal" style={{ maxWidth: 420 }} onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Reject Action</h2>
              <button onClick={() => setRejectId(null)} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>
            <div className="p-5 space-y-3">
              <label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Reason (optional)</label>
              <input value={reason} onChange={e => setReason(e.target.value)}
                placeholder="false positive, alert was benign…" className="g-input" />
            </div>
            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => setRejectId(null)} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={reject} disabled={acting === rejectId}
                className="g-btn flex-1 justify-center"
                style={{ background: 'var(--red-bg)', color: 'var(--red)', border: '1px solid var(--red-border)' }}>
                {acting === rejectId ? 'Rejecting…' : 'Reject'}
              </button>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
