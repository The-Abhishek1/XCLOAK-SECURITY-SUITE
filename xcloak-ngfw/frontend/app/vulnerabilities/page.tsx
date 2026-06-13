'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { agentsAPI } from '@/lib/api';
import { Agent, Vulnerability } from '@/types';
import { sevClass, formatDate } from '@/lib/utils';
import { Bug, Play, Search, CheckCircle2 } from 'lucide-react';

export default function VulnerabilitiesPage() {
  const [agents, setAgents]   = useState<Agent[]>([]);
  const [vulns, setVulns]     = useState<{ agent: Agent; vuln: Vulnerability }[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState<number | null>(null);
  const [filter, setFilter]   = useState('all');
  const [search, setSearch]   = useState('');
  const [toast, setToast]     = useState<string | null>(null);

  const loadVulns = useCallback(async (agentList: Agent[]) => {
    const all: { agent: Agent; vuln: Vulnerability }[] = [];
    await Promise.allSettled(agentList.map(async ag => {
      const vr = await agentsAPI.getVulnerabilities(ag.id);
      (vr.data || []).forEach((v: Vulnerability) => all.push({ agent: ag, vuln: v }));
    }));
    setVulns(all);
  }, []);

  const loadAll = useCallback(async () => {
    const r = await agentsAPI.getAll();
    const agList: Agent[] = r.data || [];
    setAgents(agList);
    await loadVulns(agList);
    setLoading(false);
  }, [loadVulns]);

  useEffect(() => { loadAll(); }, [loadAll]);

  const runScan = async (agentId: number) => {
    setScanning(agentId);
    try {
      await agentsAPI.vulnerabilityScan(agentId);
      setToast('✓ Scan complete — refreshing results…');

      // Backend scan is synchronous (returns "Vulnerability scan completed"),
      // so re-fetch immediately. Poll a couple more times in case results
      // take a moment to commit.
      await loadVulns(agents);
      setTimeout(() => loadVulns(agents), 2000);
      setTimeout(() => loadVulns(agents), 5000);

      setTimeout(() => setToast(null), 4000);
    } catch (err) {
      setToast('Scan failed — check agent connectivity');
      setTimeout(() => setToast(null), 4000);
    } finally {
      setScanning(null);
    }
  };

  const counts = ['critical','high','medium','low'].reduce((a,s) => { a[s] = vulns.filter(v => v.vuln.severity === s).length; return a; }, {} as Record<string,number>);

  const filtered = vulns.filter(({ agent, vuln }) => {
    const mf = filter === 'all' || vuln.severity === filter;
    const ms = !search || vuln.name?.toLowerCase().includes(search.toLowerCase()) || agent.hostname?.toLowerCase().includes(search.toLowerCase());
    return mf && ms;
  });

  return (
    <RootLayout title="Vulnerabilities" subtitle={`${vulns.length} findings · ${agents.length} agents`}
      onRefresh={loadAll}>
      {toast && (
        <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm flex items-center gap-2" style={{ color: 'var(--text-1)' }}>
          <CheckCircle2 className="h-4 w-4" style={{ color: 'var(--green)' }} /> {toast}
        </div>
      )}

      <div className="space-y-4">
        {/* Scan agents row */}
        <div className="g-card p-4">
          <p className="text-xs font-semibold mb-3 uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Scan Agents</p>
          <div className="flex flex-wrap gap-2">
            {agents.length === 0 && <p className="text-xs" style={{ color: 'var(--text-3)' }}>No agents registered.</p>}
            {agents.map(a => (
              <button key={a.id} onClick={() => runScan(a.id)} disabled={scanning === a.id}
                className="g-btn g-btn-ghost text-xs"
                style={scanning === a.id ? { background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' } : undefined}>
                <Play className={`h-3 w-3 ${scanning === a.id ? 'animate-pulse' : ''}`} />
                {scanning === a.id ? 'Scanning…' : a.hostname}
              </button>
            ))}
          </div>
        </div>

        {/* Summary cards */}
        <div className="grid grid-cols-4 gap-3">
          {['critical','high','medium','low'].map(s => (
            <button key={s} onClick={() => setFilter(filter === s ? 'all' : s)}
              className="stat-glow text-left"
              style={filter === s ? { borderColor: 'var(--accent-border)', boxShadow: '0 0 12px var(--accent-glow)' } : undefined}>
              <p className="text-2xl font-bold tabular-nums" style={{ color: 'var(--text-1)' }}>{counts[s] || 0}</p>
              <span className={`inline-block mt-1 ${sevClass(s)}`}>{s}</span>
            </button>
          ))}
        </div>

        <div className="relative max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search vulnerability, agent…" className="g-input pl-9" />
        </div>

        <div className="g-table">
          <div className="g-thead grid gap-4 px-4" style={{ gridTemplateColumns: '24px 1fr 80px 100px 1fr 100px' }}>
            <span /><span>Vulnerability</span><span>Severity</span><span>Agent</span><span>Remediation</span><span>Found</span>
          </div>

          {loading ? (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
          ) : filtered.length === 0 ? (
            <div className="py-16 text-center">
              <Bug className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>
                {vulns.length === 0 ? 'No vulnerabilities found. Run a scan above.' : 'No matches for this filter.'}
              </p>
            </div>
          ) : filtered.map(({ agent, vuln }) => (
            <div key={`${agent.id}-${vuln.id}`} className="g-tr grid gap-4 items-start px-4"
              style={{ gridTemplateColumns: '24px 1fr 80px 100px 1fr 100px' }}>
              <span className="h-2 w-2 rounded-full mt-1.5"
                style={{ background: vuln.severity === 'critical' ? 'var(--red)' : vuln.severity === 'high' ? 'var(--orange)' : vuln.severity === 'medium' ? 'var(--yellow)' : 'var(--blue)' }} />
              <div>
                <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{vuln.name}</p>
                <p className="text-[11px] mt-0.5" style={{ color: 'var(--text-3)' }}>{vuln.description}</p>
              </div>
              <span className={`inline-block w-fit mt-0.5 ${sevClass(vuln.severity)}`}>{vuln.severity}</span>
              <span className="text-xs" style={{ color: 'var(--text-2)' }}>{agent.hostname}</span>
              <span className="text-xs" style={{ color: 'var(--text-3)' }}>{vuln.remediation}</span>
              <span className="text-xs" style={{ color: 'var(--text-3)' }}>{formatDate(vuln.discovered_at)}</span>
            </div>
          ))}
        </div>
      </div>
    </RootLayout>
  );
}
