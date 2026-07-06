'use client';

import { useState, useEffect } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import api from '@/lib/api';
import { HardDrive, Play, ChevronDown, ChevronRight, Clock, CheckCircle, Loader2, Plus, AlertTriangle, List, Layers, Download, Filter } from 'lucide-react';

interface ForensicCollection {
  id: number; tenant_id: number; incident_id: number | null; agent_id: number | null;
  agent_hostname: string; label: string; status: string;
  artifact_types: string[]; triggered_by: string;
  started_at: string | null; completed_at: string | null;
  created_at: string; artifact_count: number;
}

interface ForensicArtifact {
  id: number; collection_id: number; artifact_type: string;
  data: unknown[]; item_count: number; collected_at: string;
}

interface TimelineEvent {
  time: string; source: string; event_type: string;
  summary: string; severity: string; hostname: string; raw_id: number;
}

interface Agent { id: number; hostname: string; status: string; }

const STATUS_COLOR: Record<string, string> = {
  completed: '#22c55e', running: '#38bdf8', partial: '#fbbf24', pending: 'var(--text-3)', failed: '#f85149',
};
const SOURCE_COLOR: Record<string, string> = {
  alert: '#f85149', log: '#38bdf8', connection: '#a855f7', artifact: '#22c55e',
};
const ARTIFACT_ICONS: Record<string, string> = {
  collect_processes: '⚙️', collect_connections: '🔗', collect_services: '🛠',
  collect_packages: '📦', collect_users: '👤', collect_auth_logs: '🔑', collect_file_hashes: '#️⃣',
};

function CollectionCard({ col, onExpand, expanded }: {
  col: ForensicCollection; expanded: boolean; onExpand: () => void;
}) {
  const [artifacts, setArtifacts] = useState<ForensicArtifact[]>([]);
  const [loading, setLoading] = useState(false);

  const load = async () => {
    if (artifacts.length > 0) return;
    setLoading(true);
    const r = await api.get(`/dfir/collections/${col.id}/artifacts`).catch(() => ({ data: [] }));
    setArtifacts(r.data || []);
    setLoading(false);
  };

  const handleExpand = () => { onExpand(); if (!expanded) load(); };
  const statusColor = STATUS_COLOR[col.status] || 'var(--text-3)';

  return (
    <div className="g-card overflow-hidden">
      <div className="px-4 py-3 flex items-center gap-3 cursor-pointer hover:bg-[var(--glass-bg-2)] transition-colors" onClick={handleExpand}>
        {expanded ? <ChevronDown className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />
                  : <ChevronRight className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />}
        <div className="p-2 rounded-lg shrink-0" style={{ background: `${statusColor}15`, border: `1px solid ${statusColor}30` }}>
          <HardDrive className="h-3.5 w-3.5" style={{ color: statusColor }} />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{col.label}</p>
          <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
            {col.agent_hostname || `Agent #${col.agent_id}`} · by {col.triggered_by} · {new Date(col.created_at).toLocaleString()}
          </p>
        </div>
        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full shrink-0"
          style={{ background: `${statusColor}18`, color: statusColor }}>
          {col.status}
        </span>
        <span className="text-[10px] shrink-0" style={{ color: 'var(--text-3)' }}>
          {col.artifact_count} artifacts
        </span>
      </div>

      {expanded && (
        <div className="px-4 pb-4 border-t space-y-3" style={{ borderColor: 'var(--border)' }}>
          <div className="flex flex-wrap gap-1.5 mt-3">
            {(col.artifact_types || []).map(t => (
              <span key={t} className="text-[10px] px-2 py-0.5 rounded-full"
                style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                {ARTIFACT_ICONS[t] || '📄'} {t.replace('collect_', '')}
              </span>
            ))}
          </div>

          {loading ? (
            <div className="flex items-center gap-2 py-2">
              <Loader2 className="h-3.5 w-3.5 animate-spin" style={{ color: 'var(--text-3)' }} />
              <span className="text-xs" style={{ color: 'var(--text-3)' }}>Loading artifacts…</span>
            </div>
          ) : artifacts.length === 0 ? (
            <p className="text-xs" style={{ color: 'var(--text-3)' }}>No artifacts collected yet — collection may still be running.</p>
          ) : (
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
              {artifacts.map(a => (
                <div key={a.id} className="rounded-xl p-3" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                  <p className="text-xs font-semibold mb-0.5" style={{ color: 'var(--text-1)' }}>
                    {ARTIFACT_ICONS[a.artifact_type] || '📄'} {a.artifact_type.replace('collect_', '')}
                  </p>
                  <p className="text-xl font-bold" style={{ color: 'var(--accent)' }}>{a.item_count}</p>
                  <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>items</p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function TimelineView({ events }: { events: TimelineEvent[] }) {
  if (events.length === 0) return (
    <div className="py-12 text-center">
      <Clock className="mx-auto h-10 w-10 mb-2 opacity-20" style={{ color: 'var(--text-3)' }} />
      <p className="text-sm" style={{ color: 'var(--text-3)' }}>No events in timeline window.</p>
    </div>
  );

  return (
    <div className="relative">
      <div className="absolute left-5 top-0 bottom-0 w-px" style={{ background: 'var(--border)' }} />
      <div className="space-y-2 ml-12">
        {events.map((e, i) => {
          const color = SOURCE_COLOR[e.source] || 'var(--text-3)';
          return (
            <div key={i} className="relative">
              <div className="absolute -left-[42px] top-2 w-3 h-3 rounded-full border-2 border-[var(--bg-primary)]"
                style={{ background: color }} />
              <div className="rounded-xl px-3 py-2" style={{ background: 'var(--glass-bg)', border: `1px solid ${color}25` }}>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[10px] font-bold uppercase" style={{ color }}>{e.source}</span>
                  <span className="text-[10px] tabular-nums" style={{ color: 'var(--text-3)' }}>
                    {new Date(e.time).toLocaleTimeString()}
                  </span>
                </div>
                <p className="text-xs truncate mt-0.5" style={{ color: 'var(--text-1)' }}>{e.summary}</p>
                {e.hostname && <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{e.hostname}</p>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function DFIRPage() {
  const [collections, setCollections] = useState<ForensicCollection[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedID, setExpandedID] = useState<number | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [tab, setTab] = useState<'collections' | 'timeline'>('collections');
  const [statusFilter, setStatusFilter] = useState('');
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [timelineIncident, setTimelineIncident] = useState('');
  const [loadingTimeline, setLoadingTimeline] = useState(false);

  // Create form state
  const [form, setForm] = useState({ agentID: '', label: 'IR Evidence Collection', incidentID: '' });
  const [triggering, setTriggering] = useState(false);

  useEffect(() => {
    load();
    api.get('/agents').then(r => setAgents((r.data?.agents ?? r.data) || [])).catch(() => {});
  }, []);

  const load = async () => {
    setLoading(true);
    const r = await api.get('/dfir/collections?limit=50').catch(() => ({ data: [] }));
    setCollections(r.data || []);
    setLoading(false);
  };

  const triggerCollection = async () => {
    if (!form.agentID) return;
    setTriggering(true);
    await api.post('/dfir/collections', {
      agent_id: parseInt(form.agentID),
      label: form.label || 'IR Evidence Collection',
      incident_id: form.incidentID ? parseInt(form.incidentID) : null,
    });
    setTriggering(false);
    setShowCreate(false);
    load();
  };

  const loadTimeline = async () => {
    if (!timelineIncident) return;
    setLoadingTimeline(true);
    const r = await api.get(`/dfir/incidents/${timelineIncident}/timeline`).catch(() => ({ data: [] }));
    setTimeline(r.data || []);
    setLoadingTimeline(false);
  };

  const running = collections.filter(c => c.status === 'running').length;

  const exportCollection = (col: ForensicCollection) => {
    const blob = new Blob([JSON.stringify(col, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = `dfir-${col.id}-${col.agent_hostname}.json`;
    a.click(); URL.revokeObjectURL(url);
  };

  const displayedCollections = statusFilter
    ? collections.filter(c => c.status === statusFilter)
    : collections;

  return (
    <RootLayout title="Digital Forensics & IR"
      subtitle="Forensic artifact collection · Evidence preservation · Incident timeline"
      actions={
        <button onClick={() => setShowCreate(s => !s)} className="g-btn g-btn-primary text-xs flex items-center gap-1.5">
          <Plus className="h-3.5 w-3.5" /> New Collection
        </button>
      }>

      {/* Create panel */}
      {showCreate && (
        <div className="g-card p-4 mb-4">
          <p className="text-sm font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Trigger Forensic Collection</p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-3">
            <div>
              <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Agent *</label>
              <select value={form.agentID} onChange={e => setForm(f => ({ ...f, agentID: e.target.value }))} className="g-select w-full text-xs">
                <option value="">Select agent…</option>
                {agents.map((a: Agent) => <option key={a.id} value={a.id}>{a.hostname} ({a.status})</option>)}
              </select>
            </div>
            <div>
              <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Label</label>
              <input value={form.label} onChange={e => setForm(f => ({ ...f, label: e.target.value }))} className="g-input w-full text-xs" />
            </div>
            <div>
              <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Link to Incident (optional)</label>
              <input value={form.incidentID} onChange={e => setForm(f => ({ ...f, incidentID: e.target.value }))} className="g-input w-full text-xs" placeholder="Incident ID" type="number" />
            </div>
          </div>
          <div className="text-[10px] mb-3 px-3 py-2 rounded-lg" style={{ background: 'var(--glass-bg)', color: 'var(--text-3)' }}>
            <strong>Volatile-first order:</strong> processes → connections → services → users → auth logs → packages → file hashes.
            Results available after agent checks in (up to 10 min). Chain-of-custody log created automatically.
          </div>
          <div className="flex justify-end gap-2">
            <button onClick={() => setShowCreate(false)} className="g-btn g-btn-ghost text-xs">Cancel</button>
            <button onClick={triggerCollection} disabled={triggering || !form.agentID} className="g-btn g-btn-primary text-xs flex items-center gap-1.5">
              {triggering ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
              {triggering ? 'Queuing…' : 'Trigger Collection'}
            </button>
          </div>
        </div>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
        {[
          { label: 'Collections', value: collections.length, color: 'var(--accent)', icon: HardDrive },
          { label: 'Running', value: running, color: running > 0 ? '#38bdf8' : 'var(--text-3)', icon: Loader2 },
          { label: 'Completed', value: collections.filter(c => c.status === 'completed').length, color: '#22c55e', icon: CheckCircle },
          { label: 'Partial/Failed', value: collections.filter(c => ['partial','failed'].includes(c.status)).length, color: '#fbbf24', icon: AlertTriangle },
        ].map(({ label, value, color, icon: Icon }) => (
          <div key={label} className="g-card p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg" style={{ background: `${color}18` }}>
              <Icon className="h-4 w-4" style={{ color }} />
            </div>
            <div>
              <p className="text-xl font-bold" style={{ color }}>{value}</p>
              <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1.5 mb-4">
        {([['collections', 'Collections', List], ['timeline', 'Forensic Timeline', Layers]] as const).map(([v, l, Icon]) => (
          <button key={v} onClick={() => setTab(v)}
            className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5"
            style={{
              background: tab === v ? 'var(--accent-glow)' : 'var(--glass-bg)',
              border: `1px solid ${tab === v ? 'var(--accent-border)' : 'var(--border)'}`,
              color: tab === v ? 'var(--accent)' : 'var(--text-2)',
            }}>
            <Icon className="h-3 w-3" />{l}
          </button>
        ))}
      </div>

      {tab === 'collections' ? (
        loading ? <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div> :
        collections.length === 0 ? (
          <div className="py-16 text-center">
            <HardDrive className="mx-auto h-12 w-12 mb-3 opacity-20" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm font-medium" style={{ color: 'var(--text-2)' }}>No forensic collections yet.</p>
            <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>Trigger a collection on an agent to capture evidence snapshots.</p>
          </div>
        ) : (
          <>
            {/* Status filter */}
            <div className="flex items-center gap-1.5 mb-3">
              <Filter className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
              {['', 'running', 'completed', 'partial', 'failed'].map(s => (
                <button key={s || 'all'} onClick={() => setStatusFilter(s)}
                  className="px-2.5 py-1 text-[11px] rounded-lg capitalize transition-all"
                  style={{
                    background: statusFilter === s ? 'var(--accent-glow)' : 'var(--glass-bg)',
                    border: `1px solid ${statusFilter === s ? 'var(--accent-border)' : 'var(--border)'}`,
                    color: statusFilter === s ? 'var(--accent)' : 'var(--text-2)',
                  }}>
                  {s || 'all'}{s && ` (${collections.filter(c => c.status === s).length})`}
                </button>
              ))}
            </div>
            <div className="space-y-2">
              {displayedCollections.map(c => (
                <div key={c.id} className="relative">
                  <CollectionCard col={c}
                    expanded={expandedID === c.id}
                    onExpand={() => setExpandedID(p => p === c.id ? null : c.id)} />
                  {c.status === 'completed' && (
                    <button onClick={() => exportCollection(c)}
                      title="Export collection metadata as JSON"
                      className="absolute top-3 right-3 p-1.5 rounded-lg transition-all"
                      style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-3)' }}
                      onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--accent)'}
                      onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                      <Download className="h-3 w-3" />
                    </button>
                  )}
                </div>
              ))}
            </div>
          </>
        )
      ) : (
        <div className="g-card p-4">
          <div className="flex items-end gap-3 mb-5">
            <div className="flex-1">
              <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Incident ID</label>
              <input value={timelineIncident} onChange={e => setTimelineIncident(e.target.value)}
                placeholder="Enter incident ID to build timeline…"
                className="g-input w-full text-sm" type="number" />
            </div>
            <button onClick={loadTimeline} disabled={!timelineIncident || loadingTimeline}
              className="g-btn g-btn-primary text-xs flex items-center gap-1.5 shrink-0">
              {loadingTimeline ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Clock className="h-3.5 w-3.5" />}
              Build Timeline
            </button>
          </div>
          {loadingTimeline ? (
            <div className="py-8 text-center animate-pulse text-sm" style={{ color: 'var(--text-3)' }}>Building timeline…</div>
          ) : (
            <TimelineView events={timeline} />
          )}
        </div>
      )}
    </RootLayout>
  );
}
