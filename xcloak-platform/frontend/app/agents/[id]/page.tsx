'use client';

import { useEffect, useState, useCallback } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { RootLayout } from '@/components/layout/RootLayout';
import { agentsAPI, alertsAPI, tasksAPI, fimAPI, aiAPI } from '@/lib/api';
import { Agent, AgentSummary, Vulnerability, TimelineEvent, Alert, FIMAlert, FIMBaseline, Connection } from '@/types';
import { sevClass, formatDate, timeAgo, formatUptime } from '@/lib/utils';
import {
  ArrowLeft, Activity, Network, Database, Package,
  Users, Clock, Bug, FileSearch, Bell, Play, ShieldAlert, Search,
  ShieldCheck, Radio, Brain, ListChecks,
} from 'lucide-react';

const TABS = [
  { id: 'alerts',         label: 'Alerts',         icon: Bell },
  { id: 'processes',      label: 'Processes',       icon: Activity },
  { id: 'auditd',          label: 'Cmd History',      icon: Activity },
  { id: 'connections',    label: 'Connections',     icon: Network },
  { id: 'services',       label: 'Services',        icon: Database },
  { id: 'packages',       label: 'Packages',        icon: Package },
  { id: 'users',          label: 'Users',           icon: Users },
  { id: 'timeline',       label: 'Timeline',        icon: Clock },
  { id: 'vulnerabilities',label: 'Vulnerabilities', icon: Bug },
  { id: 'filehashes',     label: 'File Hashes',     icon: FileSearch },
  { id: 'fim',            label: 'FIM',             icon: ShieldCheck },
  { id: 'logs',           label: 'Auth Logs',       icon: Radio },
  { id: 'anomaly',        label: 'Anomaly',         icon: Brain },
  { id: 'tasks',          label: 'Task History',    icon: ListChecks },
];

export default function AgentDetailPage() {
  const params  = useParams();
  const agentId = parseInt(params.id as string);

  const [agent, setAgent]       = useState<Agent | null>(null);
  const [summary, setSummary]   = useState<AgentSummary | null>(null);
  const [vulns, setVulns]       = useState<Vulnerability[]>([]);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [agentAlerts, setAgentAlerts] = useState<Alert[]>([]);
  const [riskScore, setRiskScore] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState('alerts');
  const [loading, setLoading]   = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [dispatching, setDispatching] = useState(false);
  const [toast, setToast]       = useState<string | null>(null);

  // Tab data — loaded lazily on tab click
  const [processes, setProcesses]     = useState<any[] | null>(null);
  const [auditEvents, setAuditEvents]  = useState<any[] | null>(null);
  const [connections, setConnections] = useState<Connection[] | null>(null);
  const [services, setServices]       = useState<any[] | null>(null);
  const [users, setUsers]             = useState<any[] | null>(null);
  const [packages, setPackages]       = useState<any[] | null>(null);
  const [fimAlerts, setFimAlerts]     = useState<FIMAlert[] | null>(null);
  const [fimBaseline, setFimBaseline] = useState<FIMBaseline[] | null>(null);
  const [authLogs, setAuthLogs]       = useState<any[] | null>(null);
  const [anomalies, setAnomalies]       = useState<any[] | null>(null);
  const [runningAnomaly, setRunningAnomaly] = useState(false);
  const [taskHistory, setTaskHistory]   = useState<any[] | null>(null);
  const [fileHashes, setFileHashes]      = useState<any[] | null>(null);
  const [tabLoading, setTabLoading]   = useState(false);
  const [search, setSearch]           = useState('');

  const load = useCallback(async () => {
    try {
      const agentRes = await agentsAPI.getById(agentId);
      setAgent(agentRes.data);
    } catch {
      setNotFound(true);
      setLoading(false);
      return;
    }

    const results = await Promise.allSettled([
      agentsAPI.getSummary(agentId),
      agentsAPI.getVulnerabilities(agentId),
      agentsAPI.getTimeline(agentId),
      alertsAPI.getByAgent(agentId),
      agentsAPI.getRisk(agentId),
    ]);

    if (results[0].status === 'fulfilled') setSummary(results[0].value.data);
    if (results[1].status === 'fulfilled') setVulns(results[1].value.data || []);
    if (results[2].status === 'fulfilled') setTimeline(results[2].value.data || []);
    if (results[3].status === 'fulfilled') setAgentAlerts(results[3].value.data || []);
    if (results[4].status === 'fulfilled' && results[4].value.data) {
      setRiskScore(results[4].value.data.risk_score ?? null);
    }

    setLoading(false);
  }, [agentId]);

  useEffect(() => { if (!isNaN(agentId)) load(); }, [agentId, load]);

  // Lazy-load tab data on switch
  const loadTabData = useCallback(async (tab: string) => {
    setSearch('');
    setTabLoading(true);
    try {
      switch (tab) {
        case 'processes':
          if (processes === null) { const r = await agentsAPI.getProcesses(agentId); setProcesses(r.data || []); }
          break;
        case 'auditd':
          if (auditEvents === null) { const r = await fetch(`/api/agents/${agentId}/audit-events?limit=500`); setAuditEvents(await r.json() || []); }
          break;
        case 'connections':
          if (connections === null) { const r = await agentsAPI.getConnections(agentId); setConnections(r.data || []); }
          break;
        case 'services':
          if (services === null) { const r = await agentsAPI.getServices(agentId); setServices(r.data || []); }
          break;
        case 'users':
          if (users === null) { const r = await agentsAPI.getUsers(agentId); setUsers(r.data || []); }
          break;
        case 'packages':
          if (packages === null) { const r = await agentsAPI.getPackages(agentId); setPackages(r.data || []); }
          break;
        case 'fim':
          if (fimAlerts === null) {
            const [fa, fb] = await Promise.allSettled([fimAPI.getAlerts(agentId), fimAPI.getBaseline(agentId)]);
            if (fa.status === 'fulfilled') setFimAlerts(fa.value.data || []);
            if (fb.status === 'fulfilled') setFimBaseline(fb.value.data || []);
          }
          break;
        case 'logs':
          if (authLogs === null) {
            const r = await agentsAPI.getAuthLogs(agentId).catch(() => ({ data: [] }));
            setAuthLogs(r.data || []);
          }
          break;
        case 'filehashes':
          if (fileHashes === null) {
            agentsAPI.getFileHashes(agentId).then(r => {
              setFileHashes(Array.isArray(r.data) ? r.data : []);
            }).catch(() => setFileHashes([]));
          }
          break;
        case 'tasks':
          if (taskHistory === null) {
            const r = await agentsAPI.getTasks(agentId);
            setTaskHistory(r.data || []);
          }
          break;
        case 'anomaly':
          if (anomalies === null) {
            const r = await aiAPI.getAnomalies(agentId).catch(() => ({ data: [] }));
            setAnomalies(r.data || []);
          }
          break;
      }
    } finally {
      setTabLoading(false);
    }
  }, [agentId, processes, connections, services, users, packages, fimAlerts, authLogs, anomalies]);

  const selectTab = (tab: string) => {
    setActiveTab(tab);
    loadTabData(tab);
  };

  const dispatch = async (taskType: string, refreshTab?: string) => {
    setDispatching(true);
    // Reset tab data so it reloads after task completes
    if (taskType === 'fim_scan') { setFimAlerts(null); setFimBaseline(null); }
    if (taskType === 'collect_auth_logs') setAuthLogs(null);
    if (taskType === 'collect_file_hashes') setFileHashes(null);
    if (taskType === 'collect_processes') setProcesses(null);
    if (taskType === 'collect_connections') setConnections(null);
    try {
      await tasksAPI.create({ agent_id: agentId, task_type: taskType, payload: {} });
      setToast('✓ Task dispatched — refresh in ~15s');
      setTimeout(() => setToast(null), 4000);

      // Force-refresh the relevant tab's cache after a delay
      if (refreshTab) {
        setTimeout(async () => {
          switch (refreshTab) {
            case 'processes':   setProcesses(null);   if (activeTab === 'processes')   loadTabData('processes'); break;
            case 'auditd':      setAuditEvents(null);  if (activeTab === 'auditd')      loadTabData('auditd'); break;
            case 'connections': setConnections(null); if (activeTab === 'connections') loadTabData('connections'); break;
            case 'services':    setServices(null);    if (activeTab === 'services')    loadTabData('services'); break;
            case 'users':       setUsers(null);       if (activeTab === 'users')       loadTabData('users'); break;
            case 'packages':    setPackages(null);    if (activeTab === 'packages')    loadTabData('packages'); break;
            case 'fim':         setFimAlerts(null); setFimBaseline(null); if (activeTab === 'fim') loadTabData('fim'); break;
            case 'logs':        setAuthLogs(null);  if (activeTab === 'logs')  loadTabData('logs');  break;
            case 'filehashes':  setFileHashes(null); if (activeTab === 'filehashes') loadTabData('filehashes'); break;
          }
          load(); // refresh summary counts too
        }, 8000);
      }
    } catch {
      setToast('Failed to dispatch task');
      setTimeout(() => setToast(null), 4000);
    } finally {
      setDispatching(false);
    }
  };

  const acceptFIMBaseline = async (filePath: string) => {
    try {
      await fimAPI.acceptBaseline(agentId, filePath);
      setToast('✓ Baseline accepted for ' + filePath);
      setFimAlerts(null); setFimBaseline(null);
      loadTabData('fim');
    } catch {
      setToast('Failed to accept baseline');
    } finally {
      setTimeout(() => setToast(null), 4000);
    }
  };

  const statsCards = [
    { label: 'Processes',   val: summary?.processes   ?? 0, icon: Activity  },
    { label: 'Connections', val: summary?.connections ?? 0, icon: Network   },
    { label: 'Services',    val: summary?.services    ?? 0, icon: Database  },
    { label: 'Packages',    val: summary?.packages    ?? 0, icon: Package   },
    { label: 'Users',       val: summary?.users       ?? 0, icon: Users     },
    { label: 'Risk Score',  val: riskScore !== null ? riskScore : '—', icon: ShieldAlert },
  ];

  if (loading) return (
    <RootLayout title="Loading agent…">
      <div className="flex h-64 items-center justify-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading agent…</div>
    </RootLayout>
  );

  if (notFound || !agent) return (
    <RootLayout title="Agent Not Found">
      <div className="flex flex-col items-center justify-center h-64 gap-3">
        <ShieldAlert className="h-10 w-10" style={{ color: 'var(--text-3)' }} />
        <p className="text-sm" style={{ color: 'var(--text-2)' }}>Agent not found or unreachable.</p>
        <Link href="/agents" className="text-xs" style={{ color: 'var(--accent)' }}>← Back to agents</Link>
      </div>
    </RootLayout>
  );

  return (
    <RootLayout title={agent.hostname} subtitle={`${agent.os} · ${agent.ip_address}`} onRefresh={load}
      actions={
        <Link href="/agents"
          className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
          <ArrowLeft className="h-3.5 w-3.5" /> All Agents
        </Link>
      }>

      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)' }}>{toast}</div>}

      <div className="space-y-5">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <Link href="/agents" className="flex items-center gap-1 text-xs" style={{ color: 'var(--text-2)' }}>
            <ArrowLeft className="h-3.5 w-3.5" /> All agents
          </Link>
          <span className={agent.status === 'online' ? 's-online' : 's-offline'}>{agent.status}</span>
        </div>

        <div className="g-card p-4">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 text-xs">
            <div><p style={{ color: 'var(--text-3)' }}>Agent ID</p><p className="mt-0.5 font-medium" style={{ color: 'var(--text-1)' }}>{agent.id}</p></div>
            <div><p style={{ color: 'var(--text-3)' }}>Machine ID</p><p className="mt-0.5 mono truncate" style={{ color: 'var(--text-1)' }}>{agent.machine_id ? agent.machine_id.slice(0, 16) + '…' : '—'}</p></div>
            <div><p style={{ color: 'var(--text-3)' }}>IP Address</p><p className="mt-0.5 font-medium" style={{ color: 'var(--text-1)' }}>{agent.ip_address}</p></div>
            <div><p style={{ color: 'var(--text-3)' }}>Last Seen</p><p className="mt-0.5 font-medium" style={{ color: 'var(--text-1)' }}>{timeAgo(agent.last_seen)}</p></div>
            <div><p style={{ color: 'var(--text-3)' }}>Agent Version</p><p className="mt-0.5 mono font-medium" style={{ color: 'var(--text-1)' }}>{agent.version || '—'}</p></div>
            <div><p style={{ color: 'var(--text-3)' }}>Uptime</p><p className="mt-0.5 font-medium" style={{ color: 'var(--text-1)' }}>{formatUptime(agent.uptime_seconds)}</p></div>
            <div><p style={{ color: 'var(--text-3)' }}>Memory</p><p className="mt-0.5 font-medium" style={{ color: 'var(--text-1)' }}>{agent.mem_alloc_mb != null ? `${agent.mem_alloc_mb} MB` : '—'}</p></div>
            <div><p style={{ color: 'var(--text-3)' }}>Goroutines</p><p className="mt-0.5 font-medium" style={{ color: 'var(--text-1)' }}>{agent.goroutines ?? '—'}</p></div>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-3 sm:grid-cols-6">
          {statsCards.map(({ label, val, icon: Icon }) => (
            <div key={label} className="g-card p-3 flex flex-col gap-1">
              <div className="flex items-center gap-1.5">
                <Icon className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--accent)' }} />
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{label}</p>
              </div>
              <p className="text-xl font-semibold tabular-nums" style={{ color: 'var(--text-1)' }}>{val}</p>
            </div>
          ))}
        </div>

        <div className="g-card overflow-hidden">
          <div className="flex overflow-x-auto" style={{ borderBottom: '1px solid var(--border)' }}>
            {TABS.map(tab => {
              const Icon = tab.icon;
              return (
                <button key={tab.id} onClick={() => selectTab(tab.id)}
                  className="flex items-center gap-1.5 whitespace-nowrap px-4 py-3 text-[11px] font-medium transition-colors"
                  style={{
                    color: activeTab === tab.id ? 'var(--accent)' : 'var(--text-2)',
                    borderBottom: activeTab === tab.id ? '2px solid var(--accent)' : '2px solid transparent',
                  }}>
                  <Icon className="h-3.5 w-3.5" />
                  <span className="hidden sm:inline">{tab.label}</span>
                </button>
              );
            })}
          </div>

          <div className="p-5 overflow-y-auto" style={{ maxHeight: "calc(100vh - 320px)" }}>
            {/* Alerts */}
            {activeTab === 'alerts' && (
              <div className="space-y-2">
                {agentAlerts.length === 0 ? <EmptyState msg="No alerts for this agent." /> :
                  agentAlerts.map(a => (
                    <div key={a.id} className="flex items-start gap-3 rounded-lg p-3" style={{ background: 'var(--glass-bg-2)' }}>
                      <span className="mt-1 h-2 w-2 rounded-full shrink-0"
                        style={{ background: a.severity === 'critical' ? 'var(--red)' : a.severity === 'high' ? 'var(--orange)' : a.severity === 'medium' ? 'var(--yellow)' : 'var(--blue)' }} />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium" style={{ color: 'var(--text-1)' }}>{a.rule_name}</p>
                        <p className="text-xs mt-0.5 truncate" style={{ color: 'var(--text-2)' }}>{a.log_message}</p>
                      </div>
                      <div className="shrink-0 text-right">
                        <span className={sevClass(a.severity)}>{a.severity}</span>
                        <p className="mt-1 text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(a.created_at)}</p>
                      </div>
                    </div>
                  ))}
              </div>
            )}

            {/* Timeline */}
            {activeTab === 'timeline' && (
              timeline.length === 0 ? <EmptyState msg="No timeline events." /> : (
                <div className="relative pl-5 space-y-4">
                  <div className="absolute left-2 top-0 bottom-0 w-px" style={{ background: 'var(--border-md)' }} />
                  {timeline.map((ev, i) => (
                    <div key={i} className="relative">
                      <div className="absolute -left-3 top-1.5 h-2 w-2 rounded-full" style={{ background: 'var(--accent)' }} />
                      <p className="text-sm" style={{ color: 'var(--text-1)' }}>{ev.message}</p>
                      <p className="text-xs mt-0.5" style={{ color: 'var(--text-3)' }}>{formatDate(ev.created_at)} · {ev.event_type}</p>
                    </div>
                  ))}
                </div>
              )
            )}

            {/* Vulnerabilities */}
            {activeTab === 'vulnerabilities' && (
              <div className="space-y-3">
                <div className="flex justify-end">
                  <button onClick={() => dispatch('vulnerability_scan')} disabled={dispatching} className="g-btn g-btn-primary text-xs">
                    <Play className="h-3 w-3" /> {dispatching ? 'Scanning…' : 'Run Scan'}
                  </button>
                </div>
                {(() => {
                  const seen = new Set<string>();
                  const unique = vulns.filter(v => {
                    const key = v.cve_id || `${v.package_name}-${v.package_version}`;
                    if (seen.has(key)) return false;
                    seen.add(key);
                    return true;
                  });
                  return unique.length === 0
                    ? <EmptyState msg="No vulnerabilities found. Run a scan." />
                    : unique.map(v => (
                    <div key={v.id} className="rounded-lg p-4 space-y-1.5" style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}>
                      <div className="flex items-center justify-between">
                        <p className="text-sm font-medium" style={{ color: 'var(--text-1)' }}>{v.name}</p>
                        <span className={sevClass(v.severity)}>{v.severity}</span>
                      </div>
                      <p className="text-xs" style={{ color: 'var(--text-2)' }}>{v.description}</p>
                      <p className="text-xs" style={{ color: 'var(--accent)' }}>Fix: {v.remediation}</p>
                    </div>
                  ));
                })()
                }
              </div>
            )}

            {/* Processes table */}
            {activeTab === 'processes' && (
              <DataTable
                data={processes} loading={tabLoading} search={search} setSearch={setSearch}
                onCollect={() => dispatch('collect_processes', 'processes')} dispatching={dispatching}
                collectLabel="Collect Processes" searchKeys={['process_name', 'cmdline', 'username', 'exe_path']}
                columns={[
                  { key: 'pid',          label: 'PID',      width: '60px',  mono: true },
                  { key: 'ppid',         label: 'PPID',     width: '60px',  mono: true },
                  { key: 'username',     label: 'User',     width: '90px'  },
                  { key: 'process_name', label: 'Name',     width: '140px' },
                  { key: 'cmdline',      label: 'Cmdline',  mono: true     },
                  { key: 'cpu_percent',  label: 'CPU%',     width: '60px', mono: true },
                  { key: 'mem_percent',  label: 'MEM%',     width: '60px', mono: true },
                  { key: 'exe_path',     label: 'Path',     width: '200px', mono: true },
                ]}
              />
            )}

            {/* Auditd / command history tab */}
            {activeTab === 'auditd' && (
              <div className="space-y-2">
                {(auditEvents ?? []).length === 0 && !tabLoading && (
                  <div className="text-center py-12 text-sm" style={{ color: 'var(--text-3)' }}>
                    No command history yet. Requires auditd installed on the endpoint.<br/>
                    <code className="text-xs mt-2 block" style={{ color: 'var(--text-2)' }}>
                      sudo apt install auditd &amp;&amp; sudo systemctl enable --now auditd
                    </code>
                  </div>
                )}
                {(auditEvents ?? []).map((ev: any, i: number) => (
                  <div key={i} className="rounded-lg px-4 py-2.5 font-mono text-xs"
                    style={{
                      background: ev.threat_tag ? '#f8514910' : 'var(--bg-1)',
                      border: `1px solid ${ev.threat_tag ? '#f8514940' : 'var(--border)'}`,
                    }}>
                    <div className="flex items-center gap-3 flex-wrap">
                      <span style={{ color: 'var(--text-3)', minWidth: 140 }}>
                        {new Date(ev.created_at).toLocaleTimeString()}
                      </span>
                      <span className="px-1.5 py-0.5 rounded text-[10px]"
                        style={{ background: 'var(--bg-2)', color: 'var(--text-2)' }}>
                        uid={ev.uid}{ev.euid !== ev.uid ? `→${ev.euid}` : ''}
                      </span>
                      {ev.username && (
                        <span style={{ color: 'var(--accent)' }}>{ev.username}</span>
                      )}
                      <span style={{ color: 'var(--text-3)' }}>pid={ev.pid}</span>
                      {ev.threat_tag && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold"
                          style={{ background: '#f8514920', color: '#f85149' }}>
                          ⚠ {ev.threat_tag}
                        </span>
                      )}
                    </div>
                    <div className="mt-1 truncate" style={{ color: ev.threat_tag ? '#f87171' : 'var(--text-1)', maxWidth: '100%' }}>
                      {ev.cmdline || ev.exe || ev.comm}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Connections table */}
            {activeTab === 'connections' && (
              <DataTable
                data={connections} loading={tabLoading} search={search} setSearch={setSearch}
                onCollect={() => dispatch('collect_connections', 'connections')} dispatching={dispatching}
                collectLabel="Collect Connections" searchKeys={['local_address', 'remote_address', 'protocol', 'state', 'process_name']}
                columns={[
                  { key: 'protocol',      label: 'Proto',   width: '70px',  mono: true, upper: true },
                  { key: 'state',         label: 'State',   width: '90px' },
                  { key: 'local_address', label: 'Local',   mono: true },
                  { key: 'remote_address',label: 'Remote',  mono: true },
                  { key: 'process_name',  label: 'Process', width: '130px', mono: true },
                ]}
              />
            )}

            {/* Services table */}
            {activeTab === 'services' && (
              <DataTable
                data={services} loading={tabLoading} search={search} setSearch={setSearch}
                onCollect={() => dispatch('collect_services', 'services')} dispatching={dispatching}
                collectLabel="Collect Services" searchKeys={['service_name', 'service_state']}
                columns={[
                  { key: 'service_name', label: 'Service Name', mono: true },
                  { key: 'service_state', label: 'State', width: '100px', badge: true },
                ]}
              />
            )}

            {/* Packages table */}
            {activeTab === 'packages' && (
              <DataTable
                data={packages} loading={tabLoading} search={search} setSearch={setSearch}
                onCollect={() => dispatch('collect_file_hashes', 'packages')} dispatching={dispatching}
                collectLabel="Refresh (via hash scan)" searchKeys={['package_name', 'version']}
                columns={[
                  { key: 'package_name', label: 'Package', mono: true },
                  { key: 'version', label: 'Version', width: '160px', mono: true },
                ]}
              />
            )}

            {/* Users table */}
            {activeTab === 'users' && (
              <DataTable
                data={users} loading={tabLoading} search={search} setSearch={setSearch}
                onCollect={() => dispatch('collect_users', 'users')} dispatching={dispatching}
                collectLabel="Collect Users" searchKeys={['username', 'shell']}
                columns={[
                  { key: 'username', label: 'Username', mono: true },
                  { key: 'uid', label: 'UID', width: '80px', mono: true },
                  { key: 'shell', label: 'Shell', mono: true },
                ]}
              />
            )}

            {/* File hashes */}
            {activeTab === 'filehashes' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                    {fileHashes?.length || 0} files indexed
                  </p>
                  <button onClick={() => dispatch('collect_file_hashes', 'filehashes')}
                    disabled={dispatching} className="g-btn g-btn-primary text-xs">
                    <Play className="h-3 w-3" /> {dispatching ? 'Collecting…' : 'Collect Hashes'}
                  </button>
                </div>
                {tabLoading ? (
                  <div className="py-8 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
                ) : (fileHashes?.length || 0) === 0 ? (
                  <EmptyState msg="No file hashes collected. Click 'Collect Hashes' to index files." />
                ) : (
                  <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                    <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '1fr 1fr 140px 80px' }}>
                      <span>File Path</span><span>SHA256</span><span>MD5</span><span>Size</span>
                    </div>
                    {fileHashes!.map((h: any, i: number) => (
                      <div key={i} className="g-tr grid gap-3 items-center px-4"
                        style={{ gridTemplateColumns: '1fr 1fr 140px 80px' }}>
                        <div className="min-w-0">
                          <p className="mono text-[11px] truncate" style={{ color: 'var(--text-1)' }}
                            title={h.file_path}>{h.file_path}</p>
                          <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{h.file_name}</p>
                        </div>
                        <span className="mono text-[10px] truncate" style={{ color: 'var(--text-3)' }}
                          title={h.sha256_hash}>{h.sha256_hash?.slice(0, 20) || '—'}…</span>
                        <span className="mono text-[10px] truncate" style={{ color: 'var(--text-3)' }}>
                          {h.md5_hash?.slice(0, 16) || '—'}…
                        </span>
                        <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                          {h.file_size ? (h.file_size / 1024).toFixed(1) + ' KB' : '—'}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* ── FIM Tab ─────────────────────────────────────── */}
            {activeTab === 'fim' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                    Baseline: {fimBaseline?.length || 0} files · Violations: {fimAlerts?.length || 0}
                  </p>
                  <button onClick={() => dispatch('fim_scan', 'fim')} disabled={dispatching} className="g-btn g-btn-primary text-xs">
                    <Play className="h-3 w-3" /> {dispatching ? 'Scanning…' : 'Run FIM Scan'}
                  </button>
                </div>

                {tabLoading ? (
                  <div className="py-8 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
                ) : (fimAlerts?.length || 0) === 0 ? (
                  <div className="py-10 text-center space-y-3">
                    <p className="text-sm" style={{ color: 'var(--text-2)' }}>No FIM violations detected.</p>
                    <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                      Click &quot;Run FIM Scan&quot; — the agent will hash watched paths and report any changes (~15s).
                      Baseline: {fimBaseline?.length || 0} files tracked.
                    </p>
                  </div>
                ) : (
                  <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                    <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '110px 1fr 1fr 100px 80px' }}>
                      <span>Change</span><span>File Path</span><span>Details</span><span>Time</span><span></span>
                    </div>
                    {fimAlerts!.map((a: FIMAlert, i: number) => {
                      const isPermChange = a.change_type === 'permission_change';
                      const badgeStyle = {
                        modified:          { bg: 'var(--orange-bg)',  fg: 'var(--orange)',  border: 'var(--orange-border)' },
                        permission_change: { bg: 'rgba(168,85,247,.12)', fg: 'rgb(192,132,252)', border: 'rgba(168,85,247,.4)' },
                        deleted:           { bg: 'var(--red-bg)',     fg: 'var(--red)',     border: 'var(--red-border)' },
                        created:           { bg: 'var(--accent-glow)',fg: 'var(--accent)',  border: 'var(--accent-border)' },
                      }[a.change_type] ?? { bg: 'var(--accent-glow)', fg: 'var(--accent)', border: 'var(--accent-border)' };
                      return (
                        <div key={i} className="g-tr grid gap-3 items-center px-4"
                          style={{ gridTemplateColumns: '110px 1fr 1fr 100px 80px' }}>
                          <span className="text-[11px] font-medium capitalize rounded px-2 py-0.5 w-fit"
                            style={{ background: badgeStyle.bg, color: badgeStyle.fg, border: `1px solid ${badgeStyle.border}` }}>
                            {a.change_type.replace('_', ' ')}
                          </span>
                          <span className="text-[11px] mono truncate" style={{ color: 'var(--text-1)' }}>{a.file_path}</span>
                          <span className="text-[10px] mono truncate" style={{ color: 'var(--text-3)' }}>
                            {isPermChange && a.old_mode && a.new_mode
                              ? <>{a.old_mode} <span style={{ color: 'var(--orange)' }}>→</span> {a.new_mode}</>
                              : (a.new_hash?.slice(0, 16) || '—')}
                          </span>
                          <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{timeAgo(a.created_at)}</span>
                          {a.change_type !== 'created' ? (
                            <button onClick={() => acceptFIMBaseline(a.file_path)}
                              title="Accept this change as the new baseline — stops it from re-alerting"
                              className="g-btn g-btn-ghost text-[10px] justify-self-start">
                              Accept
                            </button>
                          ) : <span />}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* ── Auth Logs Tab ────────────────────────────────── */}
            {activeTab === 'logs' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                    {authLogs?.length || 0} log entries
                  </p>
                  <button onClick={() => dispatch('collect_auth_logs', 'logs')}
                    disabled={dispatching} className="g-btn g-btn-primary text-xs">
                    <Play className="h-3 w-3" /> {dispatching ? 'Collecting…' : 'Collect Auth Logs'}
                  </button>
                </div>

                {tabLoading ? (
                  <div className="py-8 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
                ) : (authLogs?.length || 0) === 0 ? (
                  <div className="py-10 text-center space-y-3">
                    <p className="text-sm" style={{ color: 'var(--text-2)' }}>No auth logs collected yet.</p>
                    <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                      Click &quot;Collect Auth Logs&quot; — the agent will read /var/log/auth.log and send entries here (~15s).
                    </p>
                  </div>
                ) : (
                  <div className="rounded-xl overflow-hidden font-mono text-[11px]"
                    style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', maxHeight: 480, overflowY: 'auto' }}>
                    {authLogs!.map((l: any, i: number) => {
                      const msg = l.log_message || '';
                      const color = msg.toLowerCase().includes('fail') || msg.toLowerCase().includes('invalid')
                        ? 'var(--red)' : msg.toLowerCase().includes('accepted') || msg.toLowerCase().includes('opened')
                        ? 'var(--green)' : 'var(--text-2)';
                      return (
                        <div key={i} className="flex gap-3 px-3 py-1 hover:bg-white/5 transition-colors">
                          <span className="shrink-0 w-14 text-[10px]" style={{ color: 'var(--text-3)' }}>{i + 1}</span>
                          <span style={{ color }}>{msg}</span>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* ── Anomaly Tab ──────────────────────────────────── */}
            {activeTab === 'anomaly' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                    {anomalies?.length || 0} anomalies detected
                  </p>
                  <button
                    onClick={async () => {
                      setRunningAnomaly(true);
                      // Check if we have data to analyze
                      if ((processes?.length || 0) === 0 && (connections?.length || 0) === 0) {
                        setToast('Collect processes and connections first for better analysis');
                      }
                      try {
                        const r = await aiAPI.runAnomaly(agentId);
                        setAnomalies(r.data?.findings || []);
                      } catch (e: any) {
                        const msg = e?.response?.data?.error || 'AI anomaly detection failed';
                        setToast(msg.includes('LLM') || msg.includes('unavailable')
                          ? 'Ollama not responding — ensure it is running: ollama serve'
                          : msg);
                      }
                      finally { setRunningAnomaly(false); }
                    }}
                    disabled={runningAnomaly}
                    className="g-btn g-btn-primary text-xs">
                    <Brain className="h-3 w-3" /> {runningAnomaly ? 'Analyzing…' : 'Run AI Detection'}
                  </button>
                </div>

                {tabLoading || runningAnomaly ? (
                  <div className="py-8 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>
                    {runningAnomaly ? 'AI analyzing endpoint data…' : 'Loading…'}
                  </div>
                ) : (anomalies?.length || 0) === 0 ? (
                  <EmptyState msg="No anomalies detected. Run AI Detection to analyze processes, connections, and users." />
                ) : (
                  <div className="space-y-2">
                    {anomalies!.map((a: any, i: number) => (
                      <div key={i} className="g-card p-4">
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1.5">
                              <span className="text-[10px] font-medium capitalize px-2 py-0.5 rounded"
                                style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                                {a.finding_type}
                              </span>
                              <span className={sevClass(a.severity)}>{a.severity}</span>
                            </div>
                            <p className="text-xs leading-relaxed" style={{ color: 'var(--text-1)' }}>{a.description}</p>
                            {a.raw_context?.indicator && (
                              <p className="mono text-[10px] mt-1.5 px-2 py-1 rounded"
                                style={{ background: 'var(--bg-0)', color: 'var(--accent)' }}>
                                {a.raw_context.indicator}
                              </p>
                            )}
                          </div>
                          <span className="text-[10px] shrink-0" style={{ color: 'var(--text-3)' }}>
                            {timeAgo(a.created_at)}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* ── Task History Tab ─────────────────────────── */}
            {activeTab === 'tasks' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                    {taskHistory?.length || 0} tasks dispatched
                  </p>
                  <button onClick={() => { setTaskHistory(null); loadTabData('tasks'); }}
                    className="g-btn g-btn-ghost text-xs">
                    Refresh
                  </button>
                </div>
                {tabLoading ? (
                  <div className="py-8 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
                ) : (taskHistory?.length || 0) === 0 ? (
                  <EmptyState msg="No tasks dispatched to this agent yet." />
                ) : (
                  <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                    <div className="g-thead grid gap-3 px-4"
                      style={{ gridTemplateColumns: '140px 80px 1fr 90px 60px' }}>
                      <span>Task Type</span><span>Status</span><span>Result</span>
                      <span>Completed</span><span>ID</span>
                    </div>
                    {taskHistory!.map((t: any) => {
                      const ok = t.status === 'completed'
                        && !t.result?.toLowerCase().includes('fail')
                        && !t.result?.toLowerCase().includes('error');
                      const color = t.status === 'completed' ? (ok ? 'var(--green)' : 'var(--orange)')
                        : t.status === 'running' ? 'var(--accent)' : 'var(--text-3)';
                      return (
                        <div key={t.id} className="g-tr grid gap-3 items-start px-4 py-2.5"
                          style={{ gridTemplateColumns: '140px 80px 1fr 90px 60px' }}>
                          <span className="mono text-[11px]" style={{ color: 'var(--accent)' }}>
                            {t.task_type}
                          </span>
                          <span className="text-[11px] font-medium capitalize" style={{ color }}>
                            {t.status}
                          </span>
                          <span className="text-[11px] truncate" style={{ color: 'var(--text-2)' }}
                            title={t.result || '—'}>
                            {t.result || '—'}
                          </span>
                          <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                            {t.completed_at ? timeAgo(t.completed_at) : '—'}
                          </span>
                          <span className="mono text-[10px]" style={{ color: 'var(--text-3)' }}>
                            #{t.id}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

          </div>
        </div>
      </div>
    </RootLayout>
  );
}

function EmptyState({ msg }: { msg: string }) {
  return <p className="py-10 text-center text-sm" style={{ color: 'var(--text-2)' }}>{msg}</p>;
}

interface Column {
  key: string;
  label: string;
  width?: string;
  mono?: boolean;
  upper?: boolean;
  badge?: boolean;
  fmt?: (v: any) => string;
}

function DataTable({
  data, loading, search, setSearch, onCollect, dispatching, collectLabel, searchKeys, columns,
}: {
  data: any[] | null; loading: boolean; search: string; setSearch: (s: string) => void;
  onCollect: () => void; dispatching: boolean; collectLabel: string;
  searchKeys: string[]; columns: Column[];
}) {
  const rows = data || [];
  const filtered = search
    ? rows.filter(r => searchKeys.some(k => String(r[k] ?? '').toLowerCase().includes(search.toLowerCase())))
    : rows;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[180px] max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Filter…"
            className="g-input pl-8" style={{ height: 32, fontSize: 12 }} />
        </div>
        <button onClick={onCollect} disabled={dispatching} className="g-btn g-btn-primary text-xs">
          <Play className="h-3 w-3" /> {dispatching ? 'Dispatching…' : collectLabel}
        </button>
      </div>

      {loading ? (
        <div className="py-12 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
      ) : rows.length === 0 ? (
        <EmptyState msg="No data yet. Dispatch the collect task above." />
      ) : (
        <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
          <div className="g-thead grid gap-3 px-3"
            style={{ gridTemplateColumns: columns.map(c => c.width || '1fr').join(' ') }}>
            {columns.map(c => <span key={c.key}>{c.label}</span>)}
          </div>
          <div className="max-h-96 overflow-y-auto">
            {filtered.length === 0 ? (
              <div className="py-8 text-center text-xs" style={{ color: 'var(--text-3)' }}>No matches for &quot;{search}&quot;</div>
            ) : filtered.map((row, i) => (
              <div key={i} className="g-tr grid gap-3 items-center px-3 py-2"
                style={{ gridTemplateColumns: columns.map(c => c.width || '1fr').join(' ') }}>
                {columns.map(c => {
                  const val = c.fmt ? c.fmt(row[c.key]) : row[c.key];
                  if (c.badge) {
                    return (
                      <span key={c.key} className={String(row[c.key]).toLowerCase().includes('running') || String(row[c.key]).toLowerCase().includes('active') ? 's-online' : 's-offline'}>
                        {val}
                      </span>
                    );
                  }
                  return (
                    <span key={c.key}
                      className={`text-xs truncate ${c.mono ? 'mono' : ''} ${c.upper ? 'uppercase' : ''}`}
                      style={{ color: c.mono ? 'var(--text-2)' : 'var(--text-1)' }}>
                      {val ?? '—'}
                    </span>
                  );
                })}
              </div>
            ))}
          </div>
        </div>
      )}
      {rows.length > 0 && (
        <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
          Showing {filtered.length} of {rows.length}
        </p>
      )}
    </div>
  );
}
