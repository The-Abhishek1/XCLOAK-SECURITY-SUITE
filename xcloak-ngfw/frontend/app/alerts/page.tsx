'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { Pagination } from '@/components/ui/Pagination';
import { alertsAPI, aiAPI, agentsAPI, investigateAPI } from '@/lib/api';
import { Alert, Agent, InvestigationContext, PlaybookRecommendation } from '@/types';
import { sevClass, timeAgo, formatDate } from '@/lib/utils';
import Link from 'next/link';
import { Bell, Search, Filter, X, Bot, Loader2, ChevronRight, Shield, Tag, Zap, Skull, Lock, Package, Activity, Cpu, Check } from 'lucide-react';
import api from '@/lib/api';

const SEVERITIES = ['all', 'critical', 'high', 'medium', 'low'];
const PER_PAGE = 50;

interface PagedResult {
  alerts: Alert[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
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
  const [statusFilter, setStatusFilter] = useState('open');
  const [agentId, setAgentId]     = useState('');
  const [agents, setAgents]       = useState<Agent[]>([]);
  const [search, setSearch]       = useState('');
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [acking, setAcking]       = useState<number | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [bulking, setBulking]     = useState(false);

  // Detail drawer
  const [selected, setSelected]   = useState<Alert | null>(null);
  const [triage, setTriage]       = useState<AITriage | null>(null);
  const [triaging, setTriaging]   = useState(false);
  const [investigation, setInvestigation] = useState<InvestigationContext | null>(null);
  const [investigating, setInvestigating] = useState(false);
  const [pbRecs, setPbRecs] = useState<PlaybookRecommendation[]>([]);
  const [loadingRecs, setLoadingRecs] = useState(false);
  const [executingRec, setExecutingRec] = useState<number | null>(null);
  const [responding, setResponding] = useState(false);
  const [responseAction, setResponseAction] = useState('kill_process');
  const [responsePID, setResponsePID] = useState('');
  const [responseFile, setResponseFile] = useState('');
  const [toast, setToast]         = useState<string | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const load = useCallback(async (p = page, sev = severity, aid = agentId, st = statusFilter, spin = false) => {
    if (spin) setRefreshing(true);
    setLoading(true);
    try {
      const res = await alertsAPI.getPaginated(p, PER_PAGE, sev === 'all' ? '' : sev, aid, st === 'all' ? '' : st);
      setResult(res.data);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [page, severity, agentId, statusFilter]);

  useEffect(() => { load(page, severity, agentId, statusFilter); }, [page, severity, agentId, statusFilter]);

  useEffect(() => {
    agentsAPI.getAll().then(r => setAgents(r.data || [])).catch(() => {});
  }, []);

  const changeSev    = (s: string) => { setSeverity(s); setPage(1); };
  const changeAgent  = (id: string) => { setAgentId(id); setPage(1); };
  const changeStatus = (s: string) => { setStatusFilter(s); setPage(1); };
  const changePage   = (p: number) => { setPage(p); window.scrollTo(0, 0); };

  const ackAlert = async (id: number, action: 'acknowledge' | 'resolve') => {
    setAcking(id);
    try {
      if (action === 'acknowledge') await alertsAPI.acknowledge(id);
      else await alertsAPI.resolve(id);
      notify(action === 'acknowledge' ? 'Alert acknowledged' : 'Alert resolved');
      load(page, severity, agentId, statusFilter);
      setSelected(null);
    } catch { notify('Action failed'); }
    finally { setAcking(null); }
  };

  const runInvestigation = async (id: number) => {
    setInvestigating(true);
    try {
      const r = await investigateAPI.getContext(id);
      setInvestigation(r.data);
    } catch { /* best-effort */ }
    finally { setInvestigating(false); }
  };

  const loadPlaybookRecs = async (id: number) => {
    setLoadingRecs(true);
    setPbRecs([]);
    try {
      const r = await api.get(`/alerts/${id}/playbook-recommendations`);
      setPbRecs(r.data ?? []);
    } catch { /* best-effort */ }
    finally { setLoadingRecs(false); }
  };

  const executeRec = async (recID: number) => {
    if (!selected) return;
    setExecutingRec(recID);
    try {
      await api.post(`/alerts/${selected.id}/execute-recommendation`, { recommendation_id: recID });
      notify('Playbook dispatched');
      setPbRecs(prev => prev.map(r => r.id === recID ? { ...r, executed: true } : r));
    } catch { notify('Failed to execute playbook'); }
    finally { setExecutingRec(null); }
  };

  const openAlert = (a: Alert) => {
    setSelected(a);
    setTriage(null);
    setInvestigation(null);
    setPbRecs([]);
    // Auto-triage if no AI data yet
    if (!a.ai_summary) runTriage(a.id);
    runInvestigation(a.id);
    loadPlaybookRecs(a.id);
  };

  const runTriage = async (id: number) => {
    setTriaging(true);
    try {
      await aiAPI.triageAlert(id);
      // Reload to get updated ai_summary
      const res = await alertsAPI.getPaginated(page, PER_PAGE, severity, agentId, statusFilter === 'all' ? '' : statusFilter);
      setResult(res.data);
      const updated = res.data?.alerts?.find((a: Alert) => a.id === id);
      if (updated) setSelected(updated);
    } catch {
      notify('AI triage failed — check LLM config');
    } finally {
      setTriaging(false);
    }
  };

  const toggleSelect = (id: number, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedIds(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const toggleAll = () => {
    if (selectedIds.size === filtered.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filtered.map(a => a.id)));
    }
  };

  const bulkAck = async (action: 'acknowledge' | 'resolve') => {
    const ids = [...selectedIds];
    if (ids.length === 0) return;
    setBulking(true);
    try {
      if (action === 'acknowledge') await alertsAPI.bulkAcknowledge(ids);
      else await Promise.all(ids.map(id => alertsAPI.resolve(id)));
      setSelectedIds(new Set());
      load(page, severity, agentId, statusFilter);
      notify(`${ids.length} alert${ids.length !== 1 ? 's' : ''} ${action === 'acknowledge' ? 'acknowledged' : 'resolved'}`);
    } catch { notify('Bulk action failed'); }
    finally { setBulking(false); }
  };

  const alerts   = result?.alerts || [];
  const filtered = search
    ? alerts.filter(a =>
        a.rule_name?.toLowerCase().includes(search.toLowerCase()) ||
        a.log_message?.toLowerCase().includes(search.toLowerCase()) ||
        a.mitre_technique?.toLowerCase().includes(search.toLowerCase())
      )
    : alerts;

  return (
    <RootLayout title="Alerts" subtitle={result ? `${result.total} total alerts` : ''}
      onRefresh={() => load(page, severity, agentId, statusFilter, true)} refreshing={refreshing}>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)' }}>
          {toast}
        </div>
      )}

      <div className="space-y-4">
        {/* Status tabs */}
        <div className="flex items-center gap-1.5 flex-wrap">
          {['open', 'acknowledged', 'resolved', 'all'].map(s => (
            <button key={s} onClick={() => changeStatus(s)}
              className="px-3 py-1.5 rounded-lg text-xs font-medium capitalize transition-all"
              style={{
                background: statusFilter === s ? 'var(--accent-glow)' : 'var(--glass-bg)',
                border: `1px solid ${statusFilter === s ? 'var(--accent-border)' : 'var(--border)'}`,
                color: statusFilter === s ? 'var(--accent)' : 'var(--text-2)',
              }}>
              {s}
            </button>
          ))}
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative flex-1 min-w-[180px] max-w-xs">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search rule, message, MITRE…" className="g-input pl-9" />
          </div>

          {/* Agent picker */}
          {agents.length > 0 && (
            <div className="relative">
              <Cpu className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 pointer-events-none" style={{ color: 'var(--text-3)' }} />
              <select value={agentId} onChange={e => changeAgent(e.target.value)}
                className="g-select pl-8 text-xs" style={{ minWidth: 160 }}>
                <option value="">All Agents</option>
                {agents.map(a => (
                  <option key={a.id} value={String(a.id)}>{a.hostname}</option>
                ))}
              </select>
            </div>
          )}

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

          {/* Active filter chips */}
          {(agentId || severity) && (
            <button onClick={() => { setAgentId(''); setSeverity(''); setPage(1); }}
              className="flex items-center gap-1 text-xs px-2.5 py-1.5 rounded-lg"
              style={{ background: 'var(--red-bg)', color: 'var(--red)', border: '1px solid var(--red-border)' }}>
              <X className="h-3 w-3" /> Clear filters
            </button>
          )}
        </div>

        {/* Bulk action bar */}
        {selectedIds.size > 0 && (
          <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl"
            style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
            <span className="text-xs font-medium" style={{ color: 'var(--accent)' }}>
              {selectedIds.size} selected
            </span>
            <button onClick={() => bulkAck('acknowledge')} disabled={bulking}
              className="g-btn g-btn-ghost text-xs">
              {bulking ? <Loader2 className="h-3 w-3 animate-spin" /> : 'Acknowledge All'}
            </button>
            <button onClick={() => bulkAck('resolve')} disabled={bulking}
              className="g-btn text-xs"
              style={{ background: 'rgba(52,211,153,0.1)', color: 'var(--green)', border: '1px solid rgba(52,211,153,0.3)' }}>
              Resolve All
            </button>
            <button onClick={() => setSelectedIds(new Set())}
              className="ml-auto" style={{ color: 'var(--text-3)' }}>
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        )}

        {/* Table */}
        <div className="g-table">
          <div className="g-thead grid gap-3 px-4 items-center"
            style={{ gridTemplateColumns: '20px 70px 1fr 100px 90px 100px 80px 24px' }}>
            <button onClick={toggleAll}
              className="flex h-4 w-4 items-center justify-center rounded"
              style={{
                background: selectedIds.size > 0 && selectedIds.size === filtered.length ? 'var(--accent-glow)' : 'transparent',
                border: `1px solid ${selectedIds.size > 0 ? 'var(--accent)' : 'var(--border-md)'}`,
              }}>
              {selectedIds.size > 0 && selectedIds.size === filtered.length && (
                <Check className="h-2.5 w-2.5" style={{ color: 'var(--accent)' }} />
              )}
            </button>
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
              style={{
                gridTemplateColumns: '20px 70px 1fr 100px 90px 90px 100px 24px',
                opacity: a.status === 'acknowledged' ? 0.6 : 1,
              }}
              onClick={() => openAlert(a)}>
              <button onClick={e => toggleSelect(a.id, e)}
                className="flex h-4 w-4 items-center justify-center rounded shrink-0"
                style={{
                  background: selectedIds.has(a.id) ? 'var(--accent-glow)' : 'transparent',
                  border: `1px solid ${selectedIds.has(a.id) ? 'var(--accent)' : 'var(--border-md)'}`,
                }}>
                {selectedIds.has(a.id) && <Check className="h-2.5 w-2.5" style={{ color: 'var(--accent)' }} />}
              </button>
              <Link href={`/agents/${a.agent_id}`}
                onClick={e => e.stopPropagation()}
                className="mono text-xs truncate hover:underline"
                style={{ color: 'var(--accent)' }}>
                {a.hostname || `#${a.agent_id}`}
              </Link>
              <div className="min-w-0">
                <p className="text-xs font-medium truncate" style={{
                  color: 'var(--text-1)',
                  textDecoration: a.status === 'resolved' ? 'line-through' : undefined,
                }}>{a.rule_name}</p>
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
            page={result.page} totalPages={result.pages}
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
            <div className="sticky top-0 px-5 py-4"
              style={{ background: 'var(--bg-1)', borderBottom: '1px solid var(--border)', zIndex: 10 }}>
              <div className="flex items-center gap-3 mb-3">
                <span className={sevClass(selected.severity)}>{selected.severity}</span>
                {selected.status && selected.status !== 'open' && (
                  <span className="text-[10px] px-2 py-0.5 rounded font-semibold capitalize"
                    style={{
                      background: selected.status === 'resolved' ? 'rgba(52,211,153,0.1)' : 'var(--glass-bg)',
                      color: selected.status === 'resolved' ? 'var(--green)' : 'var(--text-3)',
                      border: `1px solid ${selected.status === 'resolved' ? 'rgba(52,211,153,0.3)' : 'var(--border)'}`,
                    }}>
                    {selected.status}
                  </span>
                )}
                <p className="flex-1 text-sm font-semibold truncate" style={{ color: 'var(--text-1)' }}>
                  {selected.rule_name}
                </p>
                <button onClick={() => setSelected(null)} style={{ color: 'var(--text-3)' }}>
                  <X className="h-4 w-4" />
                </button>
              </div>
              {/* Quick actions */}
              {selected.status !== 'resolved' && (
                <div className="flex gap-2">
                  {selected.status !== 'acknowledged' && (
                    <button onClick={() => ackAlert(selected.id, 'acknowledge')}
                      disabled={acking === selected.id}
                      className="g-btn text-xs flex-1 justify-center"
                      style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                      {acking === selected.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : 'Acknowledge'}
                    </button>
                  )}
                  <button onClick={() => ackAlert(selected.id, 'resolve')}
                    disabled={acking === selected.id}
                    className="g-btn text-xs flex-1 justify-center"
                    style={{ background: 'rgba(52,211,153,0.1)', color: 'var(--green)', border: '1px solid rgba(52,211,153,0.3)' }}>
                    {acking === selected.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : 'Mark Resolved'}
                  </button>
                </div>
              )}
            </div>

            <div className="p-5 space-y-4">
              {/* Meta */}
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: 'Alert ID',   val: `#${selected.id}` },
                  { label: 'Agent',      val: selected.hostname || `#${selected.agent_id}` },
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

                {/* ── Investigation Context ───────────────── */}
                <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                  <div className="px-4 py-3 flex items-center justify-between"
                    style={{ background: 'var(--glass-bg)', borderBottom: '1px solid var(--border)' }}>
                    <div className="flex items-center gap-2">
                      <Search className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
                      <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Investigation Context</p>
                    </div>
                    {investigation && (
                      <span className="text-[11px] px-2 py-0.5 rounded-full font-bold"
                        style={{
                          background: investigation.threat_score >= 70 ? 'rgba(248,81,73,0.15)' : investigation.threat_score >= 40 ? 'rgba(251,146,60,0.15)' : 'rgba(34,197,94,0.15)',
                          color: investigation.threat_score >= 70 ? '#f85149' : investigation.threat_score >= 40 ? '#fb923c' : '#22c55e',
                        }}>
                        Threat Score: {investigation.threat_score}
                      </span>
                    )}
                  </div>
                  <div className="p-4">
                    {investigating ? (
                      <div className="text-center py-4">
                        <Loader2 className="h-4 w-4 animate-spin mx-auto mb-1" style={{ color: 'var(--accent)' }} />
                        <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>Enriching indicators…</p>
                      </div>
                    ) : !investigation ? (
                      <button onClick={() => runInvestigation(selected.id)} className="g-btn g-btn-ghost text-xs w-full justify-center">
                        <Search className="h-3.5 w-3.5" /> Investigate
                      </button>
                    ) : (
                      <div className="space-y-3">
                        {/* IOC Hits */}
                        {investigation.ioc_hits.length > 0 && (
                          <div>
                            <p className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: '#f85149' }}>
                              IOC Matches ({investigation.ioc_hits.length})
                            </p>
                            <div className="space-y-1">
                              {investigation.ioc_hits.map((hit, i) => (
                                <div key={i} className="flex items-center justify-between rounded-lg px-3 py-2 text-[11px]"
                                  style={{ background: 'rgba(248,81,73,0.08)', border: '1px solid rgba(248,81,73,0.2)' }}>
                                  <span className="mono" style={{ color: 'var(--text-1)' }}>{hit.indicator}</span>
                                  <span className="ml-2 px-1.5 py-0.5 rounded text-[10px] font-bold"
                                    style={{ background: 'rgba(248,81,73,0.2)', color: '#f85149' }}>
                                    {hit.type} · {hit.severity}
                                  </span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Similar Alerts */}
                        {investigation.similar_alerts.length > 0 && (
                          <div>
                            <p className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>
                              Similar Alerts (7d)
                            </p>
                            <div className="space-y-1">
                              {investigation.similar_alerts.slice(0, 4).map(a => (
                                <div key={a.id} className="flex items-center justify-between rounded-lg px-3 py-1.5 text-[11px]"
                                  style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                                  <span style={{ color: 'var(--text-2)' }}>{a.hostname || `#${a.id}`}</span>
                                  <span style={{ color: 'var(--text-3)' }}>{a.status}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Suggested Cases */}
                        {investigation.suggested_cases.length > 0 && (
                          <div>
                            <p className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>
                              Suggested Cases
                            </p>
                            <div className="space-y-1">
                              {investigation.suggested_cases.slice(0, 3).map(c => (
                                <div key={c.id} className="flex items-center gap-2 rounded-lg px-3 py-1.5 text-[11px]"
                                  style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                                  <span className="font-mono" style={{ color: 'var(--accent)' }}>#{c.id}</span>
                                  <span className="truncate" style={{ color: 'var(--text-2)' }}>{c.title}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Correlated Rules */}
                        {investigation.correlated_rules.length > 0 && (
                          <div>
                            <p className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>
                              Correlated Rules (24h)
                            </p>
                            <div className="flex flex-wrap gap-1">
                              {investigation.correlated_rules.map((r, i) => (
                                <span key={i} className="text-[10px] px-2 py-0.5 rounded-full"
                                  style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                                  {r}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                        {investigation.ioc_hits.length === 0 && investigation.similar_alerts.length === 0 && investigation.correlated_rules.length === 0 && (
                          <p className="text-[11px] text-center py-2" style={{ color: 'var(--text-3)' }}>
                            No IOC hits, similar alerts, or correlated rules found.
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                </div>

                {/* ── Playbook Recommendations ────────────── */}
                <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                  <div className="px-4 py-3 flex items-center gap-2"
                    style={{ background: 'var(--glass-bg)', borderBottom: '1px solid var(--border)' }}>
                    <Zap className="h-3.5 w-3.5" style={{ color: '#a855f7' }} />
                    <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>AI Playbook Recommendations</p>
                    {pbRecs.length > 0 && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded-full font-bold ml-auto"
                        style={{ background: 'rgba(168,85,247,0.12)', color: '#a855f7' }}>
                        {pbRecs.length}
                      </span>
                    )}
                  </div>
                  <div className="p-3 space-y-1.5">
                    {loadingRecs ? (
                      <div className="flex items-center justify-center gap-2 py-3">
                        <Loader2 className="h-3.5 w-3.5 animate-spin" style={{ color: 'var(--text-3)' }} />
                        <span className="text-xs" style={{ color: 'var(--text-3)' }}>Scoring playbooks…</span>
                      </div>
                    ) : pbRecs.length === 0 ? (
                      <p className="text-[11px] text-center py-2" style={{ color: 'var(--text-3)' }}>
                        No playbooks match this alert's profile.
                      </p>
                    ) : pbRecs.map(rec => (
                      <div key={rec.id} className="flex items-center gap-2 rounded-lg px-3 py-2"
                        style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', opacity: rec.executed ? 0.6 : 1 }}>
                        <div className="flex-1 min-w-0">
                          <p className="text-[11px] font-medium truncate" style={{ color: 'var(--text-1)' }}>{rec.playbook_name}</p>
                          <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>{rec.reason}</p>
                        </div>
                        <span className="text-[11px] font-bold shrink-0" style={{ color: rec.score >= 70 ? '#22c55e' : '#fbbf24' }}>
                          {rec.score}%
                        </span>
                        {rec.executed ? (
                          <span className="text-[10px] flex items-center gap-0.5 shrink-0" style={{ color: 'var(--text-3)' }}>
                            <Check className="h-3 w-3" /> done
                          </span>
                        ) : (
                          <button onClick={() => executeRec(rec.id)} disabled={executingRec === rec.id}
                            className="g-btn g-btn-ghost text-[10px] shrink-0 flex items-center gap-1">
                            {executingRec === rec.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Zap className="h-3 w-3" />}
                            Run
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* ── Manual Response Panel ───────────────── */}
                <div className="rounded-xl overflow-hidden"
                  style={{ border: '1px solid var(--border)' }}>
                  <div className="px-4 py-3 flex items-center gap-2"
                    style={{ background: 'var(--glass-bg)', borderBottom: '1px solid var(--border)' }}>
                    <Zap className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
                    <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>
                      Manual Response
                    </p>
                  </div>
                  <div className="p-4 space-y-3">
                    <div>
                      <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>Action</label>
                      <select value={responseAction} onChange={e => setResponseAction(e.target.value)}
                        className="g-select w-full text-xs">
                        <option value="kill_process">Kill Process</option>
                        <option value="isolate_host">Isolate Host</option>
                        <option value="quarantine_file">Quarantine File</option>
                        <option value="collect_processes">Collect Processes</option>
                        <option value="collect_connections">Collect Connections</option>
                        <option value="collect_file_hashes">Collect File Hashes</option>
                        <option value="fim_scan">FIM Scan</option>
                        <option value="vulnerability_scan">Vulnerability Scan</option>
                      </select>
                    </div>

                    {responseAction === 'kill_process' && (
                      <div>
                        <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>PID</label>
                        <input value={responsePID} onChange={e => setResponsePID(e.target.value)}
                          placeholder="e.g. 1234" className="g-input w-full mono text-xs" />
                      </div>
                    )}

                    {responseAction === 'quarantine_file' && (
                      <div>
                        <label className="text-[10px] mb-1 block" style={{ color: 'var(--text-3)' }}>File Path</label>
                        <input value={responseFile} onChange={e => setResponseFile(e.target.value)}
                          placeholder="/tmp/malware.bin" className="g-input w-full mono text-xs" />
                      </div>
                    )}

                    <button
                      disabled={responding}
                      onClick={async () => {
                        setResponding(true);
                        const payload: Record<string, any> = {};
                        if (responseAction === 'kill_process' && responsePID)
                          payload.pid = parseInt(responsePID);
                        if (responseAction === 'quarantine_file' && responseFile)
                          payload.file_path = responseFile;
                        try {
                          const { data } = await api.post(`/alerts/${selected.id}/respond`, {
                            action_type: responseAction,
                            payload,
                          });
                          notify(data.message === 'task pending approval'
                            ? `${responseAction} queued for admin approval — see SOAR Approvals`
                            : `Dispatched: ${responseAction}`);
                        } catch {
                          notify('Dispatch failed');
                        } finally {
                          setResponding(false);
                        }
                      }}
                      className="g-btn g-btn-primary w-full justify-center text-xs">
                      {responding
                        ? <><Loader2 className="h-3.5 w-3.5 animate-spin" /> Dispatching…</>
                        : <><Zap className="h-3.5 w-3.5" /> Dispatch to {selected.hostname || `Agent #${selected.agent_id}`}</>}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
