'use client';

import { useState, useEffect, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import api from '@/lib/api';
import { Search, Plus, Play, Trash2, Clock, CheckCircle, AlertCircle, ChevronDown, ChevronRight, BookOpen, Target } from 'lucide-react';

interface HuntTemplate {
  id: number; name: string; description: string; mitre_tactic: string;
  mitre_technique: string; kql_query: string; schedule: string;
  is_active: boolean; created_by: string; created_at: string;
}
interface HuntFinding { log_id: number; agent_id: number; hostname: string; source: string; message: string; timestamp: string; }
interface HuntRun {
  id: number; template_id: number | null; name: string; kql_query: string;
  status: string; hit_count: number; findings: HuntFinding[];
  analyst: string; severity: string; notes: string;
  started_at: string; completed_at: string | null;
}

const BUILTIN_TEMPLATES: Omit<HuntTemplate, 'id' | 'is_active' | 'created_by' | 'created_at'>[] = [
  { name: 'Suspicious Auth Failures', description: 'High rate of failed logins — potential brute force', mitre_tactic: 'credential_access', mitre_technique: 'T1110', kql_query: 'Failed password', schedule: '' },
  { name: 'Privilege Escalation via Sudo', description: 'Sudo usage outside expected patterns', mitre_tactic: 'privilege_escalation', mitre_technique: 'T1548', kql_query: 'sudo', schedule: '' },
  { name: 'Outbound to Rare Countries', description: 'Connections to unusual geo — possible C2', mitre_tactic: 'command_and_control', mitre_technique: 'T1071', kql_query: 'connection_established', schedule: '' },
  { name: 'Lateral Movement (SMB)', description: 'SMB auth on internal hosts', mitre_tactic: 'lateral_movement', mitre_technique: 'T1021', kql_query: 'smb', schedule: '' },
  { name: 'Process Execution from /tmp', description: 'Unusual process launch from temp dir', mitre_tactic: 'execution', mitre_technique: 'T1059', kql_query: '/tmp/', schedule: '' },
  { name: 'New Cron Jobs Added', description: 'Persistence via cron', mitre_tactic: 'persistence', mitre_technique: 'T1053', kql_query: 'crontab', schedule: '' },
];

const SEV_COLOR: Record<string, string> = { critical: '#f85149', high: '#fb923c', medium: '#fbbf24', low: '#22c55e' };

function RunCard({ run, onExpand, expanded, onUpdateNotes }: {
  run: HuntRun; expanded: boolean; onExpand: () => void;
  onUpdateNotes: (id: number, notes: string, severity: string) => void;
}) {
  const [notes, setNotes] = useState(run.notes);
  const [severity, setSeverity] = useState(run.severity || 'medium');
  const [saving, setSaving] = useState(false);
  const save = async () => {
    setSaving(true);
    await onUpdateNotes(run.id, notes, severity);
    setSaving(false);
  };

  const statusIcon = run.status === 'running' ? <Clock className="h-3.5 w-3.5 animate-spin" style={{ color: '#fbbf24' }} />
    : run.status === 'completed' ? <CheckCircle className="h-3.5 w-3.5" style={{ color: '#22c55e' }} />
    : <AlertCircle className="h-3.5 w-3.5" style={{ color: '#f85149' }} />;

  return (
    <div className="g-card overflow-hidden">
      <div className="px-4 py-3 flex items-center gap-3 cursor-pointer hover:bg-[var(--glass-bg-2)] transition-colors" onClick={onExpand}>
        {expanded ? <ChevronDown className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} /> : <ChevronRight className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />}
        {statusIcon}
        <span className="text-sm font-medium flex-1 truncate" style={{ color: 'var(--text-1)' }}>{run.name}</span>
        {run.hit_count > 0 && (
          <span className="text-[11px] font-bold px-2 py-0.5 rounded-full" style={{ background: 'rgba(248,81,73,0.15)', color: '#f85149' }}>
            {run.hit_count} hit{run.hit_count > 1 ? 's' : ''}
          </span>
        )}
        <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{new Date(run.started_at).toLocaleString()}</span>
        {run.analyst && <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)' }}>{run.analyst}</span>}
      </div>

      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t" style={{ borderColor: 'var(--border)' }}>
          {/* KQL query */}
          <div className="mt-3">
            <p className="text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>Query</p>
            <div className="font-mono text-[11px] px-3 py-2 rounded-lg" style={{ background: 'var(--bg-0)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>
              {run.kql_query}
            </div>
          </div>

          {/* Findings */}
          {run.hit_count > 0 && (
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: '#f85149' }}>Findings ({run.findings.length})</p>
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {run.findings.slice(0, 20).map((f, i) => (
                  <div key={i} className="rounded-lg px-3 py-2" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-[10px] font-mono" style={{ color: 'var(--accent)' }}>{f.source}</span>
                      <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{f.timestamp}</span>
                    </div>
                    <p className="text-[11px] truncate" style={{ color: 'var(--text-2)' }}>{f.message}</p>
                  </div>
                ))}
                {run.findings.length > 20 && (
                  <p className="text-[11px] text-center pt-1" style={{ color: 'var(--text-3)' }}>+{run.findings.length - 20} more</p>
                )}
              </div>
            </div>
          )}

          {/* Analyst notes */}
          <div className="flex gap-2 items-end">
            <div>
              <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Severity</label>
              <select value={severity} onChange={e => setSeverity(e.target.value)} className="g-select text-xs">
                {['critical','high','medium','low'].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div className="flex-1">
              <label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Analyst Notes</label>
              <input value={notes} onChange={e => setNotes(e.target.value)} className="g-input text-xs w-full" placeholder="False positive / confirmed / escalated to case…" />
            </div>
            <button onClick={save} disabled={saving} className="g-btn g-btn-primary text-xs">{saving ? 'Saving…' : 'Save'}</button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function HuntWorkbenchPage() {
  const [templates, setTemplates] = useState<HuntTemplate[]>([]);
  const [runs, setRuns] = useState<HuntRun[]>([]);
  const [tab, setTab] = useState<'hunt' | 'templates' | 'runs'>('hunt');
  const [query, setQuery] = useState('');
  const [huntName, setHuntName] = useState('');
  const [running, setRunning] = useState(false);
  const [expandedRun, setExpandedRun] = useState<number | null>(null);
  const [showCreateTemplate, setShowCreateTemplate] = useState(false);
  const [newTpl, setNewTpl] = useState({ name: '', description: '', mitre_tactic: '', mitre_technique: '', kql_query: '', schedule: '' });
  const [toast, setToast] = useState<string | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const load = useCallback(async () => {
    const [t, r] = await Promise.all([
      api.get('/hunt/templates').catch(() => ({ data: [] })),
      api.get('/hunt/runs').catch(() => ({ data: [] })),
    ]);
    setTemplates(t.data || []);
    setRuns(r.data || []);
  }, []);

  useEffect(() => { load(); }, [load]);

  // Poll running hunts
  useEffect(() => {
    const running = runs.some(r => r.status === 'running');
    if (!running) return;
    const t = setInterval(() => load(), 4000);
    return () => clearInterval(t);
  }, [runs, load]);

  const executeHunt = async (kql = query, name = huntName, templateID?: number) => {
    if (!kql) return;
    setRunning(true);
    const body: any = { kql_query: kql, name: name || 'Ad-hoc Hunt' };
    if (templateID) body.template_id = templateID;
    const r = await api.post('/hunt/execute', body).catch(() => ({ data: null }));
    setRunning(false);
    if (r.data) {
      setRuns(prev => [r.data, ...prev]);
      setTab('runs');
      setExpandedRun(r.data.id);
      notify('Hunt started — results will appear when complete');
    }
  };

  const createTemplate = async () => {
    if (!newTpl.name || !newTpl.kql_query) return;
    await api.post('/hunt/templates', newTpl);
    setShowCreateTemplate(false);
    setNewTpl({ name: '', description: '', mitre_tactic: '', mitre_technique: '', kql_query: '', schedule: '' });
    load();
    notify('Template saved');
  };

  const deleteTemplate = async (id: number) => {
    await api.delete(`/hunt/templates/${id}`);
    setTemplates(prev => prev.filter(t => t.id !== id));
    notify('Template deleted');
  };

  const updateNotes = async (id: number, notes: string, severity: string) => {
    await api.patch(`/hunt/runs/${id}/notes`, { notes, severity });
    setRuns(prev => prev.map(r => r.id === id ? { ...r, notes, severity } : r));
  };

  return (
    <RootLayout title="Hunt Workbench" subtitle="KQL-powered threat hunting · Templates · Findings tracker">
      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)' }}>{toast}</div>}

      {/* Tabs */}
      <div className="flex gap-1.5 mb-4">
        {[
          { key: 'hunt', label: 'New Hunt' },
          { key: 'templates', label: `Templates (${templates.length})` },
          { key: 'runs', label: `Runs (${runs.length})` },
        ].map(t => (
          <button key={t.key} onClick={() => setTab(t.key as any)}
            className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
            style={{
              background: tab === t.key ? 'var(--accent-glow)' : 'var(--glass-bg)',
              border: `1px solid ${tab === t.key ? 'var(--accent-border)' : 'var(--border)'}`,
              color: tab === t.key ? 'var(--accent)' : 'var(--text-2)',
            }}>{t.label}</button>
        ))}
      </div>

      {/* New Hunt tab */}
      {tab === 'hunt' && (
        <div className="space-y-4">
          <div className="g-card p-5 space-y-3">
            <div>
              <label className="block text-[11px] mb-1 font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Hunt Name</label>
              <input value={huntName} onChange={e => setHuntName(e.target.value)} className="g-input w-full text-sm"
                placeholder="e.g. Brute Force Investigation 2026-06-28" />
            </div>
            <div>
              <label className="block text-[11px] mb-1 font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>KQL Query</label>
              <textarea value={query} onChange={e => setQuery(e.target.value)}
                className="g-input w-full font-mono text-sm resize-none" rows={4}
                placeholder={'Failed password\n\nOR use field filters: severity:high source:auth.log\n\nOr combine: sudo AND NOT tty'} />
            </div>
            <button onClick={() => executeHunt()} disabled={running || !query}
              className="g-btn g-btn-primary flex items-center gap-2">
              <Play className="h-4 w-4" />
              {running ? 'Hunting…' : 'Execute Hunt'}
            </button>
          </div>

          {/* Built-in templates quick launch */}
          <div>
            <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-3)' }}>Quick Launch — MITRE-mapped templates</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
              {BUILTIN_TEMPLATES.map(t => (
                <div key={t.name} className="g-card p-3 flex items-start gap-2">
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-semibold truncate" style={{ color: 'var(--text-1)' }}>{t.name}</p>
                    <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{t.mitre_technique} · {t.mitre_tactic}</p>
                    <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{t.description}</p>
                  </div>
                  <button onClick={() => { setQuery(t.kql_query); setHuntName(t.name); }}
                    className="g-btn g-btn-ghost text-[11px] shrink-0 flex items-center gap-1">
                    <Target className="h-3 w-3" /> Use
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Templates tab */}
      {tab === 'templates' && (
        <div className="space-y-3">
          <div className="flex justify-end">
            <button onClick={() => setShowCreateTemplate(!showCreateTemplate)} className="g-btn g-btn-primary text-xs flex items-center gap-1.5">
              <Plus className="h-3.5 w-3.5" /> Save Template
            </button>
          </div>
          {showCreateTemplate && (
            <div className="g-card p-4 space-y-3">
              <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>New Hunt Template</p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Name</label>
                  <input value={newTpl.name} onChange={e => setNewTpl(p => ({ ...p, name: e.target.value }))} className="g-input w-full text-xs" /></div>
                <div><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>MITRE Technique</label>
                  <input value={newTpl.mitre_technique} onChange={e => setNewTpl(p => ({ ...p, mitre_technique: e.target.value }))} className="g-input w-full text-xs mono" placeholder="T1059" /></div>
                <div className="sm:col-span-2"><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>KQL Query</label>
                  <textarea value={newTpl.kql_query} onChange={e => setNewTpl(p => ({ ...p, kql_query: e.target.value }))} className="g-input w-full text-xs font-mono resize-none" rows={3} /></div>
                <div><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Schedule (cron, optional)</label>
                  <input value={newTpl.schedule} onChange={e => setNewTpl(p => ({ ...p, schedule: e.target.value }))} className="g-input w-full text-xs mono" placeholder="0 6 * * 1" /></div>
                <div><label className="block text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>Description</label>
                  <input value={newTpl.description} onChange={e => setNewTpl(p => ({ ...p, description: e.target.value }))} className="g-input w-full text-xs" /></div>
              </div>
              <div className="flex justify-end gap-2">
                <button onClick={() => setShowCreateTemplate(false)} className="g-btn g-btn-ghost text-xs">Cancel</button>
                <button onClick={createTemplate} className="g-btn g-btn-primary text-xs">Save</button>
              </div>
            </div>
          )}
          {templates.length === 0 ? (
            <div className="g-card p-10 text-center">
              <BookOpen className="mx-auto h-10 w-10 mb-2 opacity-20" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-3)' }}>No saved templates. Save a hunt above to reuse it later.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {templates.map(t => (
                <div key={t.id} className="g-card p-4 flex items-center gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <p className="text-sm font-medium" style={{ color: 'var(--text-1)' }}>{t.name}</p>
                      {t.mitre_technique && <span className="text-[10px] mono px-1.5 py-0.5 rounded" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>{t.mitre_technique}</span>}
                      {t.schedule && <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)' }}>⏰ {t.schedule}</span>}
                    </div>
                    <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{t.description}</p>
                    <p className="font-mono text-[10px] mt-1 truncate" style={{ color: 'var(--text-3)' }}>{t.kql_query}</p>
                  </div>
                  <button onClick={() => executeHunt(t.kql_query, t.name, t.id)} disabled={running}
                    className="g-btn g-btn-ghost text-xs flex items-center gap-1.5 shrink-0">
                    <Play className="h-3 w-3" /> Run
                  </button>
                  <button onClick={() => deleteTemplate(t.id)} className="p-1.5 rounded hover:bg-[var(--glass-bg-2)]">
                    <Trash2 className="h-3.5 w-3.5" style={{ color: '#f85149' }} />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Runs tab */}
      {tab === 'runs' && (
        <div className="space-y-2">
          {runs.length === 0 ? (
            <div className="g-card p-10 text-center">
              <Search className="mx-auto h-10 w-10 mb-2 opacity-20" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-3)' }}>No hunts run yet. Start one from the Hunt tab.</p>
            </div>
          ) : (
            runs.map(r => (
              <RunCard key={r.id} run={r}
                expanded={expandedRun === r.id}
                onExpand={() => setExpandedRun(prev => prev === r.id ? null : r.id)}
                onUpdateNotes={updateNotes} />
            ))
          )}
        </div>
      )}
    </RootLayout>
  );
}
