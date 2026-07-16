'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { Pagination } from '@/components/ui/Pagination';
import { alertsAPI, agentsAPI } from '@/lib/api';
import { Alert, Agent } from '@/types';
import { sevClass, timeAgo } from '@/lib/utils';
import Link from 'next/link';
import { Bell, Search, Filter, X, Loader2, ChevronRight, Cpu, Check, Clock, Download } from 'lucide-react';
import { AlertDetailDrawer } from '@/components/alerts/AlertDetailDrawer';

const SEVERITIES = ['all', 'critical', 'high', 'medium', 'low'];
const PER_PAGE = 50;

// SLA thresholds (hours until critical/high should be acknowledged)
const SLA_HOURS: Record<string, number> = { critical: 1, high: 4, medium: 24, low: 72 };


function isSlaBreach(a: Alert): boolean {
  if (a.status !== 'open') return false;
  const slaH = SLA_HOURS[a.severity];
  if (!slaH) return false;
  const ageH = (Date.now() - new Date(a.created_at).getTime()) / 3_600_000;
  return ageH > slaH;
}

function exportCSV(alerts: Alert[]) {
  const header = ['id','agent','rule','severity','tactic','technique','status','created_at'].join(',');
  const rows = alerts.map(a => [
    a.id,
    `"${(a.hostname || String(a.agent_id)).replace(/"/g, '""')}"`,
    `"${a.rule_name.replace(/"/g, '""')}"`,
    a.severity,
    a.mitre_tactic || '',
    a.mitre_technique || '',
    a.status || 'open',
    a.created_at,
  ].join(','));
  const blob = new Blob([header + '\n' + rows.join('\n')], { type: 'text/csv' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = `xcloak-alerts-${Date.now()}.csv`;
  a.click(); URL.revokeObjectURL(url);
}

interface PagedResult {
  alerts: Alert[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
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

  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [bulking, setBulking]     = useState(false);

  // Detail drawer
  const [selected, setSelected] = useState<Alert | null>(null);
  const [toast, setToast]       = useState<string | null>(null);

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

  const openAlert = (a: Alert) => setSelected(a);

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

          {/* Export */}
          <button onClick={() => exportCSV(filtered)}
            className="ml-auto flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg transition-all"
            style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
            <Download className="h-3.5 w-3.5" /> Export CSV
          </button>
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
              <span className="flex items-center gap-1 text-[11px]" style={{ color: isSlaBreach(a) ? 'var(--red)' : 'var(--text-3)' }}>
                {isSlaBreach(a) && <span title={`SLA breach — ${SLA_HOURS[a.severity]}h unacknowledged`}><Clock className="h-3 w-3" /></span>}
                {timeAgo(a.created_at)}
              </span>
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
        <AlertDetailDrawer
          alert={selected}
          onClose={() => setSelected(null)}
          onToast={notify}
          onReload={() => load(page, severity, agentId, statusFilter)}
        />
      )}
    </RootLayout>
  );
}

