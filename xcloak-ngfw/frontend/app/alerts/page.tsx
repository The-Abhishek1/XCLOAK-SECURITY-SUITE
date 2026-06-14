'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { Pagination } from '@/components/ui/Pagination';
import { alertsAPI } from '@/lib/api';
import { Alert } from '@/types';
import { sevClass, timeAgo } from '@/lib/utils';
import { Bell, Search, Filter } from 'lucide-react';

const SEVERITIES = ['all', 'critical', 'high', 'medium', 'low'];
const PER_PAGE = 50;

interface PagedResult {
  data: Alert[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

export default function AlertsPage() {
  const [result, setResult]       = useState<PagedResult | null>(null);
  const [page, setPage]           = useState(1);
  const [severity, setSeverity]   = useState('');
  const [search, setSearch]       = useState('');
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefreshing] = useState(false);

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

  const changeSev = (s: string) => { setSeverity(s); setPage(1); };
  const changePage = (p: number) => { setPage(p); window.scrollTo(0, 0); };

  const alerts = result?.data || [];
  const filtered = search
    ? alerts.filter(a =>
        a.rule_name?.toLowerCase().includes(search.toLowerCase()) ||
        a.log_message?.toLowerCase().includes(search.toLowerCase())
      )
    : alerts;

  return (
    <RootLayout title="Alerts" subtitle={result ? `${result.total} total alerts` : ''}
      onRefresh={() => load(page, severity, true)} refreshing={refreshing}>

      <div className="space-y-4">
        {/* Filters */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative flex-1 min-w-[180px] max-w-xs">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search rule or message…" className="g-input pl-9" />
          </div>
          <div className="flex items-center gap-1">
            <Filter className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
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
            style={{ gridTemplateColumns: '80px 1fr 120px 100px 120px 120px' }}>
            <span>Agent</span><span>Rule</span><span>MITRE</span>
            <span>Severity</span><span>Time</span><span>Tactic</span>
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
            <div key={a.id} className="g-tr grid gap-3 items-center px-4"
              style={{ gridTemplateColumns: '80px 1fr 120px 100px 120px 120px' }}>
              <span className="mono text-xs" style={{ color: 'var(--text-2)' }}>#{a.agent_id}</span>
              <div className="min-w-0">
                <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{a.rule_name}</p>
                <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>{a.log_message}</p>
              </div>
              <span className="mono text-[10px] rounded px-1.5 py-0.5 w-fit"
                style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                {a.mitre_technique || '—'}
              </span>
              <span className={sevClass(a.severity)}>{a.severity}</span>
              <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{timeAgo(a.created_at)}</span>
              <span className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>{a.mitre_tactic || '—'}</span>
            </div>
          ))}
        </div>

        {result && !search && (
          <Pagination
            page={result.page}
            totalPages={result.total_pages}
            total={result.total}
            perPage={result.per_page}
            onPage={changePage}
          />
        )}
      </div>
    </RootLayout>
  );
}
