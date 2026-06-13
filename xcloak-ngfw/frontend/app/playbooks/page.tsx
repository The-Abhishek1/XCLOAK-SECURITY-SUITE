'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { playbooksAPI } from '@/lib/api';
import { Playbook, PlaybookAction, PlaybookExecution } from '@/types';
import { timeAgo } from '@/lib/utils';
import { Play, Plus, Trash2, Edit2, ChevronDown, ChevronRight, X, Zap, ToggleLeft, ToggleRight } from 'lucide-react';

const TRIGGERS = ['IOC Match','YARA Match','alert_critical','alert_high','alert_medium','incident_created'];
const ACTIONS_LIST = ['kill_process','isolate_host','quarantine_file','collect_processes','collect_connections','collect_file_hashes','vulnerability_scan','execute_script'];

const emptyPB  = { name: '', trigger_type: 'alert_critical', action_type: 'isolate_host', enabled: true };
const emptyAct = { step_order: 1, action_type: 'collect_processes', payload: '{}' };

export default function PlaybooksPage() {
  const [playbooks, setPlaybooks]   = useState<Playbook[]>([]);
  const [executions, setExecutions] = useState<PlaybookExecution[]>([]);
  const [loading, setLoading]       = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [expanded, setExpanded]     = useState<number | null>(null);
  const [pbActions, setPbActions]   = useState<Record<number, PlaybookAction[]>>({});
  const [toast, setToast]           = useState<string | null>(null);
  const [saving, setSaving]         = useState(false);

  const [showAddPB, setShowAddPB]   = useState(false);
  const [showEditPB, setShowEditPB] = useState<Playbook | null>(null);
  const [pbForm, setPbForm]         = useState({ ...emptyPB });

  const [showAddAct, setShowAddAct]   = useState<number | null>(null);
  const [actForm, setActForm]         = useState({ ...emptyAct });

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    const [pb, ex] = await Promise.allSettled([playbooksAPI.getAll(), playbooksAPI.getExecutions()]);
    if (pb.status === 'fulfilled') setPlaybooks(pb.value.data || []);
    if (ex.status === 'fulfilled') setExecutions(ex.value.data || []);
    setLoading(false);
    setRefreshing(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const loadActions = async (pbId: number) => {
    const r = await playbooksAPI.getActions(pbId);
    setPbActions(p => ({ ...p, [pbId]: r.data || [] }));
  };

  const toggleExpand = async (pb: Playbook) => {
    if (expanded === pb.id) { setExpanded(null); return; }
    setExpanded(pb.id);
    await loadActions(pb.id);
  };

  // ── Playbook CRUD ──
  const addPB = async () => {
    setSaving(true);
    try { await playbooksAPI.create(pbForm); load(); setShowAddPB(false); setPbForm({ ...emptyPB }); notify('Playbook created'); }
    catch { notify('Failed to create playbook'); }
    finally { setSaving(false); }
  };

  const updatePB = async () => {
    if (!showEditPB) return;
    setSaving(true);
    try {
      await playbooksAPI.update(showEditPB.id, pbForm);
      setPlaybooks(p => p.map(x => x.id === showEditPB.id ? { ...x, ...pbForm } : x));
      setShowEditPB(null);
      notify('Playbook updated');
    } catch { notify('Failed to update playbook'); }
    finally { setSaving(false); }
  };

  const deletePB = async (id: number) => {
    try {
      await playbooksAPI.delete(id);
      setPlaybooks(p => p.filter(pb => pb.id !== id));
      notify('Playbook deleted');
    } catch {
      notify('Failed to delete playbook');
    }
  };

  const togglePB = async (pb: Playbook) => {
    try {
      pb.enabled ? await playbooksAPI.disable(pb.id) : await playbooksAPI.enable(pb.id);
      setPlaybooks(p => p.map(x => x.id === pb.id ? { ...x, enabled: !x.enabled } : x));
    } catch {
      notify('Failed to toggle playbook');
    }
  };

  const openEditPB = (pb: Playbook) => {
    setPbForm({ name: pb.name, trigger_type: pb.trigger_type, action_type: pb.action_type, enabled: pb.enabled });
    setShowEditPB(pb);
  };

  // ── Action CRUD ──
  const addAction = async () => {
    if (!showAddAct) return;
    setSaving(true);
    try {
      await playbooksAPI.createAction({ ...actForm, playbook_id: showAddAct });
      await loadActions(showAddAct);
      setShowAddAct(null); setActForm({ ...emptyAct }); notify('Action added');
    } finally { setSaving(false); }
  };

  const deleteAction = async (actionId: number, pbId: number) => {
    await playbooksAPI.deleteAction(actionId);
    setPbActions(p => ({ ...p, [pbId]: (p[pbId] || []).filter(a => a.id !== actionId) }));
    notify('Action deleted');
  };

  return (
    <RootLayout title="Playbooks" subtitle="SOAR automation"
      onRefresh={() => load(true)} refreshing={refreshing}
      actions={
        <button onClick={() => { setPbForm({ ...emptyPB }); setShowAddPB(true); }} className="g-btn g-btn-primary text-xs">
          <Plus className="h-3.5 w-3.5" /> New Playbook
        </button>
      }>

      {toast && <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm" style={{ color: 'var(--text-1)', minWidth: 220 }}>{toast}</div>}

      <div className="space-y-4">
        {loading ? (
          <div className="py-20 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
        ) : playbooks.length === 0 ? (
          <div className="py-20 text-center">
            <Zap className="mx-auto h-10 w-10 mb-3" style={{ color: 'var(--text-3)' }} />
            <p className="text-sm" style={{ color: 'var(--text-2)' }}>No playbooks. Create one to automate responses.</p>
          </div>
        ) : (
          <div className="space-y-2">
            {playbooks.map(pb => (
              <div key={pb.id} className="g-card overflow-hidden">
                <div className="flex items-center gap-3 px-5 py-4">
                  <button onClick={() => togglePB(pb)} title={pb.enabled ? 'Disable' : 'Enable'}
                    className="flex h-8 w-8 items-center justify-center rounded-lg shrink-0 transition-colors"
                    style={{ background: pb.enabled ? 'var(--green-bg)' : 'var(--glass-bg)', border: `1px solid ${pb.enabled ? 'var(--green-border)' : 'var(--border)'}` }}>
                    {pb.enabled
                      ? <ToggleRight className="h-4 w-4" style={{ color: 'var(--green)' }} />
                      : <ToggleLeft className="h-4 w-4" style={{ color: 'var(--text-3)' }} />}
                  </button>

                  <div className="flex-1 min-w-0 cursor-pointer" onClick={() => toggleExpand(pb)}>
                    <p className="text-sm font-medium" style={{ color: 'var(--text-1)' }}>{pb.name}</p>
                    <p className="text-xs mt-0.5" style={{ color: 'var(--text-3)' }}>
                      Trigger: <span className="mono" style={{ color: 'var(--accent)' }}>{pb.trigger_type}</span>
                      <span style={{ color: 'var(--text-3)' }}> → </span>
                      <span className="mono">{pb.action_type}</span>
                    </p>
                  </div>

                  <span className="text-[11px] shrink-0" style={{ color: 'var(--text-3)' }}>{timeAgo(pb.created_at)}</span>

                  <button onClick={() => openEditPB(pb)}
                    className="shrink-0 p-1.5 rounded transition-colors" style={{ color: 'var(--text-3)' }}
                    onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--accent)'}
                    onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                    <Edit2 className="h-3.5 w-3.5" />
                  </button>

                  <button onClick={() => deletePB(pb.id)}
                    className="shrink-0 p-1.5 rounded transition-colors" style={{ color: 'var(--text-3)' }}
                    onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--red)'}
                    onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>

                  <button onClick={() => toggleExpand(pb)} className="shrink-0" style={{ color: 'var(--text-3)' }}>
                    {expanded === pb.id ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                  </button>
                </div>

                {expanded === pb.id && (
                  <div className="px-5 pb-4" style={{ borderTop: '1px solid var(--border)' }}>
                    <div className="flex items-center justify-between mt-3 mb-2">
                      <p className="text-[10px] font-bold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Actions</p>
                      <button onClick={() => { setActForm({ ...emptyAct, step_order: (pbActions[pb.id] || []).length + 1 }); setShowAddAct(pb.id); }}
                        className="g-btn g-btn-ghost text-[10px]" style={{ padding: '3px 8px' }}>
                        <Plus className="h-3 w-3" /> Add Action
                      </button>
                    </div>

                    {(pbActions[pb.id] || []).length === 0 ? (
                      <p className="text-xs" style={{ color: 'var(--text-3)' }}>No actions. Add one above.</p>
                    ) : (pbActions[pb.id] || []).map(a => (
                      <div key={a.id} className="flex items-center gap-3 py-2" style={{ borderBottom: '1px solid var(--border)' }}>
                        <span className="text-[10px] w-5 text-right shrink-0 font-bold" style={{ color: 'var(--text-3)' }}>{a.step_order}.</span>
                        <span className="mono text-xs flex-1" style={{ color: 'var(--accent)' }}>{a.action_type}</span>
                        {a.payload && a.payload !== '{}' && (
                          <span className="text-[10px] truncate" style={{ color: 'var(--text-3)', maxWidth: 120 }}>{a.payload}</span>
                        )}
                        <button onClick={() => deleteAction(a.id, pb.id)}
                          className="p-1 rounded shrink-0" style={{ color: 'var(--text-3)' }}
                          onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--red)'}
                          onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
                          <Trash2 className="h-3 w-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {executions.length > 0 && (
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>Execution Log</p>
            <div className="g-table">
              <div className="g-thead grid gap-3 px-4" style={{ gridTemplateColumns: '60px 1fr 80px 120px 80px 80px' }}>
                <span>ID</span><span>Trigger</span><span>Agent</span><span>Action</span><span>Status</span><span>Time</span>
              </div>
              {executions.slice(0, 10).map(ex => (
                <div key={ex.id} className="g-tr grid gap-3 items-center px-4"
                  style={{ gridTemplateColumns: '60px 1fr 80px 120px 80px 80px' }}>
                  <span className="mono text-[11px]" style={{ color: 'var(--text-3)' }}>#{ex.id}</span>
                  <span className="text-xs truncate" style={{ color: 'var(--text-1)' }}>{ex.alert_rule}</span>
                  <span className="text-xs" style={{ color: 'var(--text-2)' }}>#{ex.agent_id}</span>
                  <span className="mono text-[10px] truncate" style={{ color: 'var(--text-2)' }}>{ex.action_type}</span>
                  <span className={ex.status === 'success' ? 's-online' : 's-critical'}>{ex.status}</span>
                  <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{timeAgo(ex.created_at)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Add/Edit Playbook modal */}
      {(showAddPB || showEditPB) && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && (setShowAddPB(false), setShowEditPB(null))}>
          <div className="g-modal">
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{showEditPB ? 'Edit Playbook' : 'New Playbook'}</h2>
              <button onClick={() => { setShowAddPB(false); setShowEditPB(null); }} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>
            <div className="p-5 space-y-3">
              <div><label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Name *</label>
                <input value={pbForm.name} onChange={e => setPbForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g. Auto-isolate on IOC match" className="g-input" /></div>
              <div><label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Trigger</label>
                <select value={pbForm.trigger_type} onChange={e => setPbForm(f => ({ ...f, trigger_type: e.target.value }))} className="g-select">
                  {TRIGGERS.map(t => <option key={t} value={t}>{t}</option>)}</select></div>
              <div><label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Primary Action</label>
                <select value={pbForm.action_type} onChange={e => setPbForm(f => ({ ...f, action_type: e.target.value }))} className="g-select">
                  {ACTIONS_LIST.map(a => <option key={a} value={a}>{a}</option>)}</select></div>
              <div className="flex items-center gap-2">
                <button onClick={() => setPbForm(f => ({ ...f, enabled: !f.enabled }))}>
                  {pbForm.enabled ? <ToggleRight className="h-5 w-5" style={{ color: 'var(--green)' }} /> : <ToggleLeft className="h-5 w-5" style={{ color: 'var(--text-3)' }} />}
                </button>
                <span className="text-xs" style={{ color: 'var(--text-2)' }}>{pbForm.enabled ? 'Enabled' : 'Disabled'}</span>
              </div>
            </div>
            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => { setShowAddPB(false); setShowEditPB(null); }} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={showEditPB ? updatePB : addPB} disabled={saving || !pbForm.name.trim()} className="g-btn g-btn-primary flex-1 justify-center">
                {saving ? 'Saving…' : (showEditPB ? 'Update' : 'Create')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add Action modal */}
      {showAddAct && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setShowAddAct(null)}>
          <div className="g-modal">
            <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Add Action</h2>
              <button onClick={() => setShowAddAct(null)} style={{ color: 'var(--text-2)' }}><X className="h-4 w-4" /></button>
            </div>
            <div className="p-5 space-y-3">
              <div><label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Step Order</label>
                <input type="number" value={actForm.step_order} onChange={e => setActForm(f => ({ ...f, step_order: parseInt(e.target.value) || 1 }))} className="g-input" /></div>
              <div><label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Action Type</label>
                <select value={actForm.action_type} onChange={e => setActForm(f => ({ ...f, action_type: e.target.value }))} className="g-select">
                  {ACTIONS_LIST.map(a => <option key={a} value={a}>{a}</option>)}</select></div>
              <div><label className="block text-xs mb-1" style={{ color: 'var(--text-3)' }}>Payload (JSON)</label>
                <input value={actForm.payload} onChange={e => setActForm(f => ({ ...f, payload: e.target.value }))} placeholder='{}' className="g-input mono" /></div>
            </div>
            <div className="flex gap-3 px-5 pb-5">
              <button onClick={() => setShowAddAct(null)} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
              <button onClick={addAction} disabled={saving} className="g-btn g-btn-primary flex-1 justify-center">
                {saving ? 'Adding…' : 'Add Action'}
              </button>
            </div>
          </div>
        </div>
      )}
    </RootLayout>
  );
}
