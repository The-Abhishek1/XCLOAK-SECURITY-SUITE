'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { Pagination } from '@/components/ui/Pagination';
import { alertsAPI, aiAPI } from '@/lib/api';
import { Alert } from '@/types';
import { sevClass, timeAgo, formatDate } from '@/lib/utils';
import { Bell, Search, Filter, X, Bot, Loader2, ChevronRight, Shield, Tag } from 'lucide-react';

const SEVERITIES = ['all', 'critical', 'high', 'medium', 'low'];
const PER_PAGE = 50;

interface PagedResult {
  data: Alert[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

interface AITriage {
  summary: string;
  severity: string;
  recommended_action: string;
  false_positive: boolean;
  mitre_technique: string;
  tags: string[];
}

export default function AlertsPage() {
  const [result, setResult]       = useState<PagedResult | null>(null);
  const [page, setPage]           = useState(1);
  const [severity, setSeverity]   = useState('');
  const [search, setSearch]       = useState('');
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Detail drawer
  const [selected, setSelected]   = useState<Alert | null>(null);
  const [triage, setTriage]       = useState<AITriage | null>(null);
  const [triaging, setTriaging]   = useState(false);
  const [toast, setToast]         = useState<string | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const load = useCallback(async (p = page, sev = severity, spin = false) => {
    if (spin) setRefreshing(true);
    setLoading(true);
    try {
      const res = await alertsAPI.getPaginated(p, PER_PAGE, sev === 'all' ? '' : sev);
      setResult(res.data);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [page, severity]);

  useEffect(() => { load(); }, [page, severity]);

  const changeSev  = (s: string) => { setSeverity(s); setPage(1); };
  const changePage = (p: number) => { setPage(p); window.scrollTo(0, 0); };

  const openAlert = (a: Alert) => {
    setSelected(a);
    setTriage(null);
    // Auto-triage if no AI data yet
    if (!a.ai_summary) runTriage(a.id);
  };

  const runTriage = async (id: number) => {
    setTriaging(true);
    try {
      await aiAPI.triageAlert(id);
      // Reload to get updated ai_summary
      const res = await alertsAPI.getPaginated(page, PER_PAGE, severity);
      setResult(res.data);
      const updated = res.data?.data?.find((a: Alert) => a.id === id);
      if (updated) setSelected(updated);
    } catch {
      notify('AI triage failed — check LLM config');
    } finally {
      setTriaging(false);
    }
  };

  const alerts   = result?.data || [];
  const filtered = search
    ? alerts.filter(a =>
        a.rule_name?.toLowerCase().includes(search.toLowerCase()) ||
        a.log_message?.toLowerCase().includes(search.toLowerCase()) ||
        a.mitre_technique?.toLowerCase().includes(search.toLowerCase())
      )
    : alerts;

  return (
    <RootLayout title="Alerts" subtitle={result ? `${result.total} total alerts` : ''}
      onRefresh={() => load(page, severity, true)} refreshing={refreshing}>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)' }}>
          {toast}
        </div>
      )}

      <div className="space-y-4">
        {/* Filters */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative flex-1 min-w-[180px] max-w-xs">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search rule, message, MITRE…" className="g-input pl-9" />
          </div>
          <div className="flex items-center gap-1">
            <Filter className="h-3.5 w-3.5 mr-1" style={{ color: 'var(--text-3)' }} />
            {SEVERITIES.map(s => (
              <button key={s} onClick={() => changeSev(s === 'all' ? '' : s)}
                className="px-3 py-1.5 rounded-lg text-xs font-medium capitalize transition-all"
                style={{
                  background: (severity === s || (s === 'all' && !severity))
                    ? 'var(--accent-glow)' : 'var(--glass-bg)',
                  border: `1px solid ${(severity === s || (s === 'all' && !severity))
                    ? 'var(--accent-border)' : 'var(--border)'}`,
                  color: (severity === s || (s === 'all' && !severity))
                    ? 'var(--accent)' : 'var(--text-2)',
                }}>
                {s}
              </button>
            ))}
          </div>
        </div>

        {/* Table */}
        <div className="g-table">
          <div className="g-thead grid gap-3 px-4"
            style={{ gridTemplateColumns: '70px 1fr 100px 90px 100px 80px 24px' }}>
            <span>Agent</span><span>Rule / Message</span>
            <span>MITRE</span><span>Tactic</span>
            <span>Severity</span><span>Time</span><span></span>
          </div>

          {loading ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          ) : filtered.length === 0 ? (
            <div className="py-16 text-center">
              <Bell className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>
                {search ? 'No alerts match your search.' : 'No alerts yet.'}
              </p>
            </div>
          ) : filtered.map(a => (
            <div key={a.id}
              className="g-tr grid gap-3 items-center px-4 cursor-pointer"
              style={{ gridTemplateColumns: '70px 1fr 100px 90px 90px 100px 24px' }}
              onClick={() => openAlert(a)}>
              <span className="mono text-xs" style={{ color: 'var(--text-2)' }}>#{a.agent_id}</span>
              <div className="min-w-0">
                <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{a.rule_name}</p>
                <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>{a.log_message}</p>
              </div>
              <span className="mono text-[10px] rounded px-1.5 py-0.5 w-fit"
                style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                {a.mitre_technique || '—'}
              </span>
              <span className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>
                {a.mitre_tactic || '—'}
              </span>
              <span className={sevClass(a.severity)}>{a.severity}</span>
              <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{timeAgo(a.created_at)}</span>
              <ChevronRight className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
            </div>
          ))}
        </div>

        {result && !search && (
          <Pagination
            page={result.page} totalPages={result.total_pages}
            total={result.total} perPage={result.per_page}
            onPage={changePage}
          />
        )}
      </div>

      {/* ── Alert detail drawer ──────────────────────────────── */}
      {selected && (
        <div className="fixed inset-0 z-50 flex">
          {/* Backdrop */}
          <div className="flex-1" onClick={() => setSelected(null)} />

          {/* Drawer */}
          <div className="w-full max-w-md h-full overflow-y-auto shadow-2xl"
            style={{ background: 'var(--bg-1)', borderLeft: '1px solid var(--border)' }}>

            {/* Header */}
            <div className="sticky top-0 flex items-center gap-3 px-5 py-4"
              style={{ background: 'var(--bg-1)', borderBottom: '1px solid var(--border)', zIndex: 10 }}>
              <span className={sevClass(selected.severity)}>{selected.severity}</span>
              <p className="flex-1 text-sm font-semibold truncate" style={{ color: 'var(--text-1)' }}>
                {selected.rule_name}
              </p>
              <button onClick={() => setSelected(null)} style={{ color: 'var(--text-3)' }}>
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="p-5 space-y-4">
              {/* Meta */}
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: 'Alert ID',   val: `#${selected.id}` },
                  { label: 'Agent',      val: `#${selected.agent_id}` },
                  { label: 'Time',       val: formatDate(selected.created_at) },
                  { label: 'Fingerprint', val: selected.fingerprint?.slice(0, 16) + '…' || '—' },
                ].map(({ label, val }) => (
                  <div key={label} className="rounded-xl p-3"
                    style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <p className="text-[10px] mb-0.5" style={{ color: 'var(--text-3)' }}>{label}</p>
                    <p className="text-xs mono font-medium truncate" style={{ color: 'var(--text-1)' }}>{val}</p>
                  </div>
                ))}
              </div>

              {/* Log message */}
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>
                  Log Message
                </p>
                <div className="rounded-xl p-3 mono text-[11px] break-all"
                  style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                  {selected.log_message}
                </div>
              </div>

              {/* MITRE */}
              {(selected.mitre_technique || selected.mitre_tactic) && (
                <div className="rounded-xl p-3"
                  style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
                  <div className="flex items-center gap-2 mb-2">
                    <Shield className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
                    <p className="text-xs font-semibold" style={{ color: 'var(--accent)' }}>MITRE ATT&CK</p>
                  </div>
                  <div className="grid grid-cols-3 gap-2 text-[11px]">
                    <div>
                      <p style={{ color: 'var(--text-3)' }}>Technique</p>
                      <p className="mono font-bold" style={{ color: 'var(--text-1)' }}>
                        {selected.mitre_technique || '—'}
                      </p>
                    </div>
                    <div>
                      <p style={{ color: 'var(--text-3)' }}>Tactic</p>
                      <p className="font-medium" style={{ color: 'var(--text-1)' }}>
                        {selected.mitre_tactic || '—'}
                      </p>
                    </div>
                    <div>
                      <p style={{ color: 'var(--text-3)' }}>Name</p>
                      <p style={{ color: 'var(--text-1)' }}>{selected.mitre_name || '—'}</p>
                    </div>
                  </div>
                </div>
              )}

              {/* AI Triage section */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Bot className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
                    <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
                      AI Triage
                    </p>
                  </div>
                  <button
                    onClick={() => runTriage(selected.id)}
                    disabled={triaging}
                    className="g-btn g-btn-ghost text-[11px]" style={{ padding: '3px 10px' }}>
                    {triaging
                      ? <><Loader2 className="h-3 w-3 animate-spin" /> Analyzing…</>
                      : 'Re-triage'}
                  </button>
                </div>

                {triaging && (
                  <div className="rounded-xl p-4 text-center"
                    style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <Loader2 className="h-5 w-5 animate-spin mx-auto mb-2" style={{ color: 'var(--accent)' }} />
                    <p className="text-xs" style={{ color: 'var(--text-3)' }}>AI analyzing alert…</p>
                  </div>
                )}

                {!triaging && selected.ai_summary && (
                  <div className="rounded-xl p-3 space-y-2"
                    style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <p className="text-xs leading-relaxed" style={{ color: 'var(--text-1)' }}>
                      {selected.ai_summary}
                    </p>
                    {selected.ai_action && (
                      <div className="rounded-lg px-3 py-2"
                        style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
                        <p className="text-[10px] mb-0.5" style={{ color: 'var(--text-3)' }}>Recommended Action</p>
                        <p className="text-xs font-medium" style={{ color: 'var(--accent)' }}>{selected.ai_action}</p>
                      </div>
                    )}
                  </div>
                )}

                {!triaging && !selected.ai_summary && (
                  <div className="rounded-xl p-4 text-center"
                    style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <Bot className="h-6 w-6 mx-auto mb-2" style={{ color: 'var(--text-3)' }} />
                    <p className="text-xs" style={{ color: 'var(--text-3)' }}>No AI analysis yet.</p>
                    <button onClick={() => runTriage(selected.id)}
                      className="g-btn g-btn-primary text-xs mt-3">
                      <Bot className="h-3.5 w-3.5" /> Run AI Triage
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
