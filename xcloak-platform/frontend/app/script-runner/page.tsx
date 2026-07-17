'use client';

import React, { useState, useEffect, useRef, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { srAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';

type Tab = 'dashboard' | 'scripts' | 'editor' | 'executions' | 'ai' | 'schedule' | 'approvals' | 'analytics' | 'audit' | 'reports';
const TAB_LABELS: Record<Tab, string> = {
  dashboard: 'Dashboard', scripts: 'Script Library', editor: 'Code Editor',
  executions: 'Execution History', ai: 'AI Assistant', schedule: 'Schedule',
  approvals: 'Approvals', analytics: 'Analytics', audit: 'Audit Trail', reports: 'Reports',
};

const LANG_COLOR: Record<string, string> = {
  powershell: '#2563eb', bash: '#16a34a', python: '#d97706', batch: '#6b7280',
  shell: '#16a34a', go: '#06b6d4', custom: '#a855f7',
};
const STATUS_COLOR: Record<string, string> = {
  success: '#22c55e', running: '#3b82f6', failed: '#ef4444', pending: '#f97316',
  queued: '#eab308', cancelled: '#6b7280',
};
const ACTION_COLOR: Record<string, string> = {
  created: '#3b82f6', modified: '#eab308', executed: '#22c55e', approved: '#22c55e',
  rejected: '#ef4444', scheduled: '#a855f7', deleted: '#ef4444',
  approval_required: '#f97316', status_changed: '#6b7280', report_generated: '#06b6d4',
};
const TRIGGER_ICON: Record<string, string> = {
  manual: '👆', scheduled: '⏰', alert: '🚨', incident: '🔥', playbook: '📋', case: '📁',
};

function StatCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="g-card" style={{ padding: '14px 18px', minWidth: 120 }}>
      <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 700, color: color || 'var(--text-1)', lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 3 }}>{sub}</div>}
    </div>
  );
}

function LangPill({ lang }: { lang: string }) {
  const c = LANG_COLOR[lang] || '#6b7280';
  return <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 3, background: c + '22', color: c, border: `1px solid ${c}44`, textTransform: 'uppercase' }}>{lang}</span>;
}

function StatusPill({ s }: { s: string }) {
  const c = STATUS_COLOR[s] || '#6b7280';
  return <span style={{ fontSize: 10, fontWeight: 600, padding: '2px 8px', borderRadius: 10, background: c + '22', color: c, border: `1px solid ${c}44`, textTransform: 'capitalize' }}>{s}</span>;
}

// ─── Dashboard ────────────────────────────────────────────────────────────
function DashboardTab({ dash }: { dash: any }) {
  if (!dash) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total Scripts" value={dash.total_scripts} color="var(--accent)" />
        <StatCard label="Active Scripts" value={dash.active_scripts} color="#22c55e" />
        <StatCard label="Running Jobs" value={dash.running_jobs} color="#3b82f6" sub="currently executing" />
        <StatCard label="Scheduled Jobs" value={dash.scheduled_jobs} color="#a855f7" sub="enabled" />
        <StatCard label="Successful" value={dash.successful_executions} color="#22c55e" sub="total executions" />
        <StatCard label="Failed" value={dash.failed_executions} color="#ef4444" sub="total executions" />
        <StatCard label="Avg Runtime" value={`${(dash.avg_execution_time / 1000).toFixed(1)}s`} color="#f97316" />
        <StatCard label="Managed Endpoints" value={dash.managed_endpoints} color="#06b6d4" />
      </div>

      {dash.pending_approvals > 0 && (
        <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #f97316', background: '#f9731608' }}>
          <span style={{ fontWeight: 700, color: '#f97316' }}>⚠ {dash.pending_approvals} execution{dash.pending_approvals !== 1 ? 's' : ''} pending approval.</span>
          <span style={{ fontSize: 13, color: 'var(--text-2)', marginLeft: 8 }}>Review in the Approvals tab.</span>
        </div>
      )}
      {dash.running_jobs > 0 && (
        <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #3b82f6', background: '#3b82f608' }}>
          <span style={{ fontWeight: 700, color: '#3b82f6' }}>▶ {dash.running_jobs} script{dash.running_jobs !== 1 ? 's' : ''} currently executing.</span>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Execution Health</div>
          {[
            ['Successful Executions', dash.successful_executions, '#22c55e'],
            ['Failed Executions', dash.failed_executions, '#ef4444'],
            ['Running Now', dash.running_jobs, '#3b82f6'],
            ['Pending Approval', dash.pending_approvals, '#f97316'],
          ].map(([label, val, color]) => (
            <div key={label as string} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', borderRadius: 8, background: 'var(--bg)', border: '1px solid var(--border)', marginBottom: 6 }}>
              <span style={{ fontSize: 13, color: 'var(--text-2)' }}>{label}</span>
              <span style={{ fontSize: 20, fontWeight: 700, color: color as string }}>{String(val)}</span>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Automation Coverage</div>
          {[
            ['Scripts Managed', dash.total_scripts, dash.total_scripts, '#3b82f6'],
            ['Active Scripts', dash.active_scripts, dash.total_scripts, '#22c55e'],
            ['Scheduled Jobs', dash.scheduled_jobs, 20, '#a855f7'],
            ['Endpoints Covered', dash.managed_endpoints, 150, '#06b6d4'],
          ].map(([label, val, max, color]) => (
            <div key={label as string} style={{ marginBottom: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 3 }}>
                <span style={{ color: 'var(--text-2)' }}>{label}</span>
                <span style={{ fontWeight: 700, color: color as string }}>{String(val)}</span>
              </div>
              <div style={{ background: 'var(--border)', borderRadius: 2, height: 5 }}>
                <div style={{ background: color as string, borderRadius: 2, height: 5, width: `${Math.min(100, Math.round((Number(val) / Number(max)) * 100))}%` }} />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Script Library ───────────────────────────────────────────────────────
function ScriptsTab({ scripts, onOpenEditor, onRefresh }: { scripts: any[]; onOpenEditor: (s: any) => void; onRefresh: () => void }) {
  const [search, setSearch] = useState('');
  const [filterLang, setFilterLang] = useState('');
  const [filterCat, setFilterCat] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [deleting, setDeleting] = useState<number | null>(null);

  const filtered = useMemo(() => scripts.filter(s => {
    if (filterLang && s.language !== filterLang) return false;
    if (filterCat && s.category !== filterCat) return false;
    if (filterStatus && s.status !== filterStatus) return false;
    if (search) {
      const q = search.toLowerCase();
      return s.name.toLowerCase().includes(q) || s.script_id.toLowerCase().includes(q) || (s.description || '').toLowerCase().includes(q);
    }
    return true;
  }), [scripts, filterLang, filterCat, filterStatus, search]);

  const del = async (id: number) => {
    setDeleting(id);
    await srAPI.deleteScript(id);
    onRefresh();
    setDeleting(null);
  };

  const langs = [...new Set(scripts.map(s => s.language))];
  const cats = [...new Set(scripts.map(s => s.category))];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <input className="g-input" placeholder="Search scripts…" value={search} onChange={e => setSearch(e.target.value)} style={{ fontSize: 12, width: 220 }} />
        <select className="g-select" value={filterLang} onChange={e => setFilterLang(e.target.value)} style={{ fontSize: 11 }}>
          <option value="">All Languages</option>
          {langs.map(l => <option key={l} value={l}>{l}</option>)}
        </select>
        <select className="g-select" value={filterCat} onChange={e => setFilterCat(e.target.value)} style={{ fontSize: 11 }}>
          <option value="">All Categories</option>
          {cats.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <select className="g-select" value={filterStatus} onChange={e => setFilterStatus(e.target.value)} style={{ fontSize: 11 }}>
          <option value="">All Status</option>
          {['active','deprecated','disabled'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={onRefresh}>↻</button>
        <button className="g-btn g-btn-primary" style={{ fontSize: 11, marginLeft: 'auto' }} onClick={() => onOpenEditor(null)}>+ New Script</button>
      </div>
      <div className="g-card" style={{ overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table className="g-table" style={{ width: '100%' }}>
            <thead className="g-thead">
              <tr>{['Script ID', 'Name', 'Language', 'Category', 'Version', 'Author', 'Status', 'Approval', 'Modified', ''].map(h => (
                <th key={h} className="g-tr" style={{ padding: '8px 14px', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
              ))}</tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr><td colSpan={10} style={{ padding: 24, textAlign: 'center', color: 'var(--text-3)' }}>No scripts found</td></tr>
              )}
              {filtered.map(s => {
                let tags: string[] = [];
                try { tags = JSON.parse(s.tags || '[]'); } catch { tags = []; }
                return (
                  <tr key={s.id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '10px 14px', fontSize: 10, fontFamily: 'monospace', color: 'var(--accent)' }}>{s.script_id}</td>
                    <td style={{ padding: '10px 14px' }}>
                      <div style={{ fontWeight: 600, fontSize: 13 }}>{s.name}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2, maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.description}</div>
                      {tags.length > 0 && (
                        <div style={{ display: 'flex', gap: 3, marginTop: 4, flexWrap: 'wrap' }}>
                          {tags.slice(0, 3).map(t => <span key={t} style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3, background: 'var(--border)', color: 'var(--text-3)' }}>{t}</span>)}
                        </div>
                      )}
                    </td>
                    <td style={{ padding: '10px 14px' }}><LangPill lang={s.language} /></td>
                    <td style={{ padding: '10px 14px', fontSize: 12, color: 'var(--text-2)', textTransform: 'capitalize' }}>{s.category}</td>
                    <td style={{ padding: '10px 14px', fontSize: 11, fontFamily: 'monospace', color: 'var(--text-3)' }}>v{s.version}</td>
                    <td style={{ padding: '10px 14px', fontSize: 12, color: 'var(--text-2)' }}>{s.author}</td>
                    <td style={{ padding: '10px 14px' }}>
                      <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 10, background: s.status === 'active' ? '#22c55e22' : '#6b728022', color: s.status === 'active' ? '#22c55e' : '#6b7280', border: `1px solid ${s.status === 'active' ? '#22c55e44' : '#6b728044'}`, textTransform: 'capitalize' }}>{s.status}</span>
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      {s.requires_approval
                        ? <span style={{ fontSize: 10, color: '#f97316', background: '#f9731622', padding: '2px 7px', borderRadius: 4, border: '1px solid #f9731644', fontWeight: 700 }}>REQUIRED</span>
                        : <span style={{ fontSize: 10, color: '#22c55e', background: '#22c55e22', padding: '2px 7px', borderRadius: 4, border: '1px solid #22c55e44', fontWeight: 700 }}>NOT REQ.</span>}
                    </td>
                    <td style={{ padding: '10px 14px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(s.last_modified)}</td>
                    <td style={{ padding: '10px 14px' }}>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <button className="g-btn g-btn-ghost" style={{ fontSize: 11, padding: '3px 8px' }} onClick={() => onOpenEditor(s)}>Edit</button>
                        <button className="g-btn g-btn-ghost" style={{ fontSize: 11, padding: '3px 8px', color: '#ef4444' }} onClick={() => del(s.id)} disabled={deleting === s.id}>Del</button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ─── Code Editor ─────────────────────────────────────────────────────────
function EditorTab({ editScript, onSaved }: { editScript: any; onSaved: () => void }) {
  const [name, setName] = useState(editScript?.name || '');
  const [desc, setDesc] = useState(editScript?.description || '');
  const [lang, setLang] = useState(editScript?.language || 'bash');
  const [cat, setCat] = useState(editScript?.category || 'general');
  const [ver, setVer] = useState(editScript?.version || '1.0.0');
  const [content, setContent] = useState(editScript?.content || '');
  const [tags, setTags] = useState('');
  const [reqApproval, setReqApproval] = useState(editScript?.requires_approval || false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [execTarget, setExecTarget] = useState('');
  const [execRunAs, setExecRunAs] = useState('system');
  const [executing, setExecuting] = useState(false);
  const [execResult, setExecResult] = useState<any>(null);
  const [lineCount, setLineCount] = useState(1);

  const LANGS = ['powershell', 'bash', 'python', 'batch', 'shell', 'go', 'custom'];
  const CATS = ['general', 'monitoring', 'remediation', 'forensics', 'patch', 'discovery', 'logging', 'security', 'identity'];
  const RUN_AS_OPTIONS = ['system', 'administrator', 'root', 'current_user', 'custom_service_account', 'temporary_elevated'];

  const save = async () => {
    setSaving(true);
    const data = { name, description: desc, language: lang, category: cat, version: ver, content, tags: `[${tags.split(',').filter(Boolean).map(t => `"${t.trim()}"`).join(',')}]`, requires_approval: reqApproval };
    if (editScript?.id) {
      await srAPI.updateScript(editScript.id, data);
    } else {
      await srAPI.createScript(data);
    }
    setSaved(true);
    setSaving(false);
    setTimeout(() => setSaved(false), 2000);
    onSaved();
  };

  const execute = async () => {
    if (!execTarget) return;
    setExecuting(true);
    const r = await srAPI.execute({
      script_id: editScript?.script_id || 'new',
      script_name: name,
      target: execTarget,
      run_as: execRunAs,
      require_approval: reqApproval,
      trigger_source: 'manual',
    });
    setExecResult(r.data);
    setExecuting(false);
  };

  const updateContent = (val: string) => {
    setContent(val);
    setLineCount(val.split('\n').length);
  };

  const lines = Array.from({ length: Math.max(lineCount, content.split('\n').length) }, (_, i) => i + 1);

  return (
    <div style={{ display: 'flex', gap: 14 }}>
      {/* Editor area */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div className="g-card" style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <input className="g-input" placeholder="Script name" value={name} onChange={e => setName(e.target.value)} style={{ flex: 2, minWidth: 180 }} />
            <select className="g-select" value={lang} onChange={e => setLang(e.target.value)} style={{ flex: 1 }}>
              {LANGS.map(l => <option key={l} value={l}>{l}</option>)}
            </select>
            <select className="g-select" value={cat} onChange={e => setCat(e.target.value)} style={{ flex: 1 }}>
              {CATS.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
            <input className="g-input" placeholder="Version" value={ver} onChange={e => setVer(e.target.value)} style={{ width: 80 }} />
          </div>
          <input className="g-input" placeholder="Description" value={desc} onChange={e => setDesc(e.target.value)} />
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <input className="g-input" placeholder="Tags (comma-separated)" value={tags} onChange={e => setTags(e.target.value)} style={{ flex: 1 }} />
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-2)', cursor: 'pointer', whiteSpace: 'nowrap' }}>
              <input type="checkbox" checked={reqApproval} onChange={e => setReqApproval(e.target.checked)} />
              Require Approval
            </label>
          </div>
        </div>

        <div className="g-card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '8px 12px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: '#0d1117' }}>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <LangPill lang={lang} />
              <span style={{ fontSize: 11, color: '#6b7280', fontFamily: 'monospace' }}>{name || 'untitled'}</span>
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={save} disabled={saving}>
                {saved ? '✓ Saved' : saving ? 'Saving…' : '💾 Save'}
              </button>
            </div>
          </div>
          <div style={{ display: 'flex', background: '#0d1117', minHeight: 320, maxHeight: 500, overflow: 'auto' }}>
            <div style={{ padding: '10px 8px', background: '#161b22', borderRight: '1px solid #30363d', minWidth: 40, textAlign: 'right', userSelect: 'none' }}>
              {lines.map(n => <div key={n} style={{ fontSize: 11, fontFamily: 'monospace', lineHeight: '21px', color: '#6e7681' }}>{n}</div>)}
            </div>
            <textarea
              value={content}
              onChange={e => updateContent(e.target.value)}
              spellCheck={false}
              style={{ flex: 1, background: 'transparent', border: 'none', outline: 'none', padding: '10px 12px', fontFamily: 'monospace', fontSize: 12, lineHeight: '21px', color: '#e6edf3', resize: 'none', minHeight: 320 }}
              placeholder={lang === 'powershell' ? '# PowerShell script\nParam([string]$Target)\n\nWrite-Host "XCloak Script Runner"\n' : lang === 'python' ? '#!/usr/bin/env python3\nimport sys\n\ndef main():\n    print("XCloak Script Runner")\n    return 0\n\nif __name__ == "__main__":\n    sys.exit(main())\n' : '#!/bin/bash\nset -euo pipefail\n\necho "XCloak Script Runner"\nexit 0\n'}
            />
          </div>
        </div>

        {/* Execute */}
        <div className="g-card" style={{ padding: 14 }}>
          <div style={{ fontWeight: 600, marginBottom: 10, fontSize: 13 }}>Execute Script</div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
            <div style={{ flex: 2 }}>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 3 }}>Target</label>
              <input className="g-input" placeholder="Hostname, IP, Asset Group, Department…" value={execTarget} onChange={e => setExecTarget(e.target.value)} />
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 3 }}>Run As</label>
              <select className="g-select" value={execRunAs} onChange={e => setExecRunAs(e.target.value)}>
                {RUN_AS_OPTIONS.map(r => <option key={r} value={r}>{r.replace(/_/g, ' ')}</option>)}
              </select>
            </div>
            <button className="g-btn g-btn-primary" style={{ fontSize: 12 }} onClick={execute} disabled={executing || !execTarget || !name}>
              {executing ? '▶ Running…' : '▶ Execute'}
            </button>
          </div>
          {execResult && (
            <div style={{ marginTop: 12, padding: 10, background: 'var(--bg)', borderRadius: 6, border: '1px solid var(--border)' }}>
              {execResult.approval_required ? (
                <div style={{ color: '#f97316', fontWeight: 600, fontSize: 12 }}>⚠ Approval required. Execution queued — ID: <span style={{ fontFamily: 'monospace' }}>{execResult.execution_id}</span></div>
              ) : (
                <div style={{ fontSize: 12 }}>
                  <span style={{ color: '#22c55e', fontWeight: 700 }}>▶ Execution started</span>
                  <span style={{ color: 'var(--text-3)', marginLeft: 8, fontFamily: 'monospace' }}>{execResult.execution_id}</span>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Right panel */}
      <div style={{ width: 260, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div className="g-card" style={{ padding: 14 }}>
          <div style={{ fontWeight: 600, marginBottom: 10, fontSize: 13 }}>Supported Languages</div>
          {LANGS.map(l => (
            <div key={l} onClick={() => setLang(l)} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 8px', borderRadius: 5, cursor: 'pointer', background: lang === l ? 'var(--border)' : 'transparent', marginBottom: 2 }}>
              <LangPill lang={l} />
              <span style={{ fontSize: 12, color: 'var(--text-2)', textTransform: 'capitalize' }}>{l}</span>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: 14 }}>
          <div style={{ fontWeight: 600, marginBottom: 10, fontSize: 13 }}>Execution Context</div>
          {RUN_AS_OPTIONS.map(r => (
            <div key={r} onClick={() => setExecRunAs(r)} style={{ padding: '6px 8px', borderRadius: 5, cursor: 'pointer', background: execRunAs === r ? 'var(--border)' : 'transparent', fontSize: 12, color: 'var(--text-2)', textTransform: 'capitalize', marginBottom: 2 }}>
              {r.replace(/_/g, ' ')}
              {(r === 'root' || r === 'administrator' || r === 'temporary_elevated') && <span style={{ marginLeft: 4, fontSize: 9, color: '#f97316', fontWeight: 700 }}>↑ PRIV</span>}
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: 14 }}>
          <div style={{ fontWeight: 600, marginBottom: 8, fontSize: 13 }}>Response Actions</div>
          {['Kill Process', 'Collect Logs', 'Gather Memory', 'Restart Service', 'Stop Service', 'Delete File', 'Update Config', 'Run Remediation', 'Trigger Script'].map(a => (
            <div key={a} style={{ padding: '5px 0', fontSize: 12, color: 'var(--text-3)', borderBottom: '1px solid var(--border)' }}>{a}</div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Execution History ─────────────────────────────────────────────────────
function ExecutionsTab({ executions, onRefresh }: { executions: any[]; onRefresh: () => void }) {
  const [selected, setSelected] = useState<any>(null);
  const [detail, setDetail] = useState<any>(null);
  const [filterStatus, setFilterStatus] = useState('');
  const [search, setSearch] = useState('');

  const filtered = useMemo(() => executions.filter(e => {
    if (filterStatus && e.status !== filterStatus) return false;
    if (search) {
      const q = search.toLowerCase();
      return e.script_name.toLowerCase().includes(q) || e.execution_id.toLowerCase().includes(q) || e.target.toLowerCase().includes(q);
    }
    return true;
  }), [executions, filterStatus, search]);

  const selectExec = async (e: any) => {
    setSelected(e);
    const r = await srAPI.getExecution(e.id);
    setDetail(r.data);
  };

  const durationMs = (e: any) => {
    if (e.execution_time) return `${(e.execution_time / 1000).toFixed(1)}s`;
    if (e.status === 'running') return 'running…';
    return '—';
  };

  return (
    <div style={{ display: 'flex', gap: 14, minHeight: 500 }}>
      <div className="g-card" style={{ width: 380, flexShrink: 0, display: 'flex', flexDirection: 'column', padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 6 }}>
          <input className="g-input" placeholder="Search…" value={search} onChange={e => setSearch(e.target.value)} style={{ fontSize: 12, flex: 1 }} />
          <select className="g-select" value={filterStatus} onChange={e => setFilterStatus(e.target.value)} style={{ fontSize: 11 }}>
            <option value="">All Status</option>
            {['success','running','failed','pending','cancelled'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={onRefresh}>↻</button>
        </div>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {filtered.length === 0 && <div style={{ padding: 20, color: 'var(--text-3)', fontSize: 13, textAlign: 'center' }}>No executions</div>}
          {filtered.map(e => (
            <div key={e.id} onClick={() => selectExec(e)}
              style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)', cursor: 'pointer', background: selected?.id === e.id ? 'var(--accent)10' : 'transparent', borderLeft: selected?.id === e.id ? '3px solid var(--accent)' : '3px solid transparent' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <span style={{ fontSize: 13 }}>{TRIGGER_ICON[e.trigger_source] || '▶'}</span>
                <span style={{ fontWeight: 600, fontSize: 12, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.script_name}</span>
                <StatusPill s={e.status} />
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-3)' }}>
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '55%' }}>{e.target}{e.target_count > 1 ? ` (×${e.target_count})` : ''}</span>
                <span>{durationMs(e)} · {timeAgo(e.started_at)}</span>
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>{e.execution_id} · {e.executed_by}</div>
            </div>
          ))}
        </div>
      </div>

      {!selected ? (
        <div className="g-card" style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 10 }}>
          <div style={{ fontSize: 40 }}>📋</div>
          <div style={{ color: 'var(--text-3)' }}>Select an execution to view details</div>
        </div>
      ) : (
        <div className="g-card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: 0 }}>
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span style={{ fontWeight: 700, fontSize: 15 }}>{selected.script_name}</span>
              <StatusPill s={selected.status} />
              {selected.exit_code !== null && selected.exit_code !== undefined && (
                <span style={{ fontSize: 11, fontFamily: 'monospace', color: selected.exit_code === 0 ? '#22c55e' : '#ef4444' }}>exit {selected.exit_code}</span>
              )}
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-3)' }}>
              {selected.execution_id} · {selected.target} · {TRIGGER_ICON[selected.trigger_source]} {selected.trigger_source} · RunAs: {selected.run_as} · {selected.executed_by}
            </div>
          </div>
          <div style={{ flex: 1, overflowY: 'auto', padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
              <StatCard label="Duration" value={durationMs(selected)} />
              <StatCard label="Target Count" value={selected.target_count} />
              <StatCard label="Exit Code" value={selected.exit_code ?? '—'} color={selected.exit_code === 0 ? '#22c55e' : selected.exit_code ? '#ef4444' : 'var(--text-1)'} />
            </div>
            {detail?.stdout && (
              <div className="g-card" style={{ padding: 12 }}>
                <div style={{ fontSize: 10, color: '#22c55e', textTransform: 'uppercase', marginBottom: 6, fontWeight: 700 }}>stdout</div>
                <pre style={{ fontSize: 11, color: '#e6edf3', background: '#0d1117', padding: 10, borderRadius: 5, overflowX: 'auto', overflowY: 'auto', maxHeight: 220, margin: 0, fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{detail.stdout}</pre>
              </div>
            )}
            {detail?.stderr && (
              <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #ef4444' }}>
                <div style={{ fontSize: 10, color: '#ef4444', textTransform: 'uppercase', marginBottom: 6, fontWeight: 700 }}>stderr</div>
                <pre style={{ fontSize: 11, color: '#fca5a5', background: '#0d1117', padding: 10, borderRadius: 5, overflowX: 'auto', maxHeight: 120, margin: 0, fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{detail.stderr}</pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── AI Assistant ─────────────────────────────────────────────────────────
function AITab({ scripts }: { scripts: any[] }) {
  const [action, setAction] = useState<'generate' | 'explain' | 'optimize' | 'detect_unsafe' | 'convert' | 'suggest'>('generate');
  const [lang, setLang] = useState('bash');
  const [targetOS, setTargetOS] = useState('linux');
  const [prompt, setPrompt] = useState('');
  const [content, setContent] = useState('');
  const [selectedScript, setSelectedScript] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  const ACTIONS: [typeof action, string, string][] = [
    ['generate', '✨ Generate', 'Describe what the script should do'],
    ['explain', '📖 Explain', 'Paste a script to get a full explanation'],
    ['optimize', '⚡ Optimize', 'Paste a script to get an optimized version'],
    ['detect_unsafe', '🛡 Safety Scan', 'Detect dangerous commands and security issues'],
    ['convert', '🔄 Convert', 'Convert between languages'],
    ['suggest', '💡 Improve', 'Suggest improvements for existing code'],
  ];
  const LANGS = ['powershell', 'bash', 'python', 'batch', 'shell', 'go', 'custom'];

  const loadScript = (id: string) => {
    const s = scripts.find(s => String(s.id) === id);
    if (s) setContent(s.content || '');
    setSelectedScript(id);
  };

  const run = async () => {
    setLoading(true);
    const r = await srAPI.askAI({ action, language: lang, content, prompt, target_os: targetOS });
    if (r.data?.result) {
      try { setResult(JSON.parse(r.data.result)); } catch { setResult({ raw: r.data.result }); }
    }
    setLoading(false);
  };

  return (
    <div style={{ display: 'flex', gap: 16 }}>
      <div style={{ width: 280, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div className="g-card" style={{ padding: 14 }}>
          <div style={{ fontWeight: 600, marginBottom: 10, fontSize: 13 }}>AI Action</div>
          {ACTIONS.map(([a, label, hint]) => (
            <div key={a} onClick={() => setAction(a)}
              style={{ padding: '8px 10px', borderRadius: 6, cursor: 'pointer', background: action === a ? 'var(--accent)20' : 'transparent', border: action === a ? '1px solid var(--accent)' : '1px solid transparent', marginBottom: 4 }}>
              <div style={{ fontWeight: action === a ? 600 : 400, fontSize: 13, color: action === a ? 'var(--accent)' : 'var(--text-2)' }}>{label}</div>
              <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 1 }}>{hint}</div>
            </div>
          ))}
        </div>
        <div className="g-card" style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div>
            <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 3 }}>Language</label>
            <select className="g-select" value={lang} onChange={e => setLang(e.target.value)} style={{ width: '100%' }}>
              {LANGS.map(l => <option key={l} value={l}>{l}</option>)}
            </select>
          </div>
          <div>
            <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 3 }}>Target OS</label>
            <select className="g-select" value={targetOS} onChange={e => setTargetOS(e.target.value)} style={{ width: '100%' }}>
              {['linux', 'windows', 'macos', 'any'].map(o => <option key={o} value={o}>{o}</option>)}
            </select>
          </div>
          {scripts.length > 0 && (
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 3 }}>Load from Library</label>
              <select className="g-select" value={selectedScript} onChange={e => loadScript(e.target.value)} style={{ width: '100%' }}>
                <option value="">Choose script…</option>
                {scripts.map(s => <option key={s.id} value={String(s.id)}>{s.name}</option>)}
              </select>
            </div>
          )}
        </div>
      </div>

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 12 }}>
        {action === 'generate' ? (
          <div className="g-card" style={{ padding: 14 }}>
            <div style={{ fontWeight: 600, marginBottom: 8, fontSize: 13 }}>Describe the script</div>
            <textarea className="g-input" rows={4} value={prompt} onChange={e => setPrompt(e.target.value)} placeholder="e.g., Collect running processes, open network connections, and recent event logs from a Windows endpoint. Output should be structured and easy to parse." style={{ width: '100%', resize: 'none', fontSize: 13, lineHeight: 1.5 }} />
          </div>
        ) : (
          <div className="g-card" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ padding: '8px 12px', borderBottom: '1px solid var(--border)', background: '#0d1117', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <LangPill lang={lang} />
              <span style={{ fontSize: 11, color: '#6b7280' }}>Paste script content here</span>
            </div>
            <textarea value={content} onChange={e => setContent(e.target.value)} style={{ width: '100%', minHeight: 180, background: '#0d1117', border: 'none', outline: 'none', padding: 12, fontFamily: 'monospace', fontSize: 12, color: '#e6edf3', resize: 'vertical', display: 'block' }} placeholder={`# Paste your ${lang} script here…`} />
          </div>
        )}
        <button className="g-btn g-btn-primary" style={{ fontSize: 13, alignSelf: 'flex-start' }} onClick={run} disabled={loading || (action === 'generate' ? !prompt : !content)}>
          {loading ? '🧠 Analyzing…' : '🧠 Run AI Analysis'}
        </button>

        {result && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {result.script && (
              <div className="g-card" style={{ padding: 0, overflow: 'hidden' }}>
                <div style={{ padding: '8px 12px', borderBottom: '1px solid var(--border)', background: '#0d1117', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: '#22c55e' }}>Generated Script</span>
                  <LangPill lang={lang} />
                </div>
                <pre style={{ background: '#0d1117', padding: 12, margin: 0, fontSize: 12, color: '#e6edf3', overflowX: 'auto', maxHeight: 300, fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>{result.script}</pre>
              </div>
            )}
            {result.optimized_script && (
              <div className="g-card" style={{ padding: 0, overflow: 'hidden' }}>
                <div style={{ padding: '8px 12px', borderBottom: '1px solid var(--border)', background: '#0d1117' }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: '#22c55e' }}>Optimized Script</span>
                </div>
                <pre style={{ background: '#0d1117', padding: 12, margin: 0, fontSize: 12, color: '#e6edf3', overflowX: 'auto', maxHeight: 300, fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>{result.optimized_script}</pre>
              </div>
            )}
            {result.converted_script && (
              <div className="g-card" style={{ padding: 0, overflow: 'hidden' }}>
                <div style={{ padding: '8px 12px', borderBottom: '1px solid var(--border)', background: '#0d1117' }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: '#22c55e' }}>Converted to {lang}</span>
                </div>
                <pre style={{ background: '#0d1117', padding: 12, margin: 0, fontSize: 12, color: '#e6edf3', overflowX: 'auto', maxHeight: 300, fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>{result.converted_script}</pre>
              </div>
            )}
            {result.description && (
              <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #3b82f6' }}>
                <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 6 }}>Description</div>
                <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.5 }}>{result.description}</div>
              </div>
            )}
            {result.summary && (
              <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #3b82f6' }}>
                <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 6 }}>Summary</div>
                <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.5 }}>{result.summary}</div>
              </div>
            )}
            {result.risk_level && (
              <div className="g-card" style={{ padding: 12, borderLeft: `3px solid ${result.risk_level === 'critical' ? '#ef4444' : result.risk_level === 'high' ? '#f97316' : '#eab308'}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                  <div style={{ fontWeight: 700, color: result.risk_level === 'critical' ? '#ef4444' : '#f97316', textTransform: 'uppercase', fontSize: 12 }}>Risk Level: {result.risk_level}</div>
                  {result.allow_execution !== undefined && (
                    <span style={{ fontSize: 12, padding: '3px 10px', borderRadius: 10, background: result.allow_execution ? '#22c55e22' : '#ef444422', color: result.allow_execution ? '#22c55e' : '#ef4444', fontWeight: 700 }}>{result.allow_execution ? '✓ Safe to Execute' : '✗ Execution Blocked'}</span>
                  )}
                </div>
                {result.overall_assessment && <div style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 8 }}>{result.overall_assessment}</div>}
                {result.unsafe_commands?.map((c: any, i: number) => (
                  <div key={i} style={{ padding: '8px 10px', background: '#ef444408', borderRadius: 5, marginBottom: 5, border: '1px solid #ef444422' }}>
                    <div style={{ fontFamily: 'monospace', fontSize: 12, color: '#ef4444', fontWeight: 700 }}>{c.command}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>Line {c.line} — {c.reason}</div>
                  </div>
                ))}
              </div>
            )}
            {result.recommendations?.length > 0 && (
              <div className="g-card" style={{ padding: 12 }}>
                <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 8 }}>Recommendations</div>
                {result.recommendations?.map((r: any, i: number) => (
                  <div key={i} style={{ padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 12, color: 'var(--text-2)' }}>
                    <strong>{i + 1}.</strong> {typeof r === 'string' ? r : `${r.title}: ${r.description}`}
                  </div>
                ))}
              </div>
            )}
            {result.warnings?.length > 0 && (
              <div className="g-card" style={{ padding: 12, borderLeft: '3px solid #eab308' }}>
                <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 8 }}>Warnings</div>
                {result.warnings.map((w: string, i: number) => (
                  <div key={i} style={{ fontSize: 12, color: '#eab308', padding: '3px 0' }}>⚠ {w}</div>
                ))}
              </div>
            )}
            {result.parameters?.length > 0 && (
              <div className="g-card" style={{ padding: 12 }}>
                <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: 8 }}>Parameters</div>
                {result.parameters.map((param: any) => (
                  <div key={param.name} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
                    <span style={{ fontFamily: 'monospace', color: 'var(--accent)' }}>{param.name}</span>
                    <span style={{ color: 'var(--text-3)' }}>{param.type} {param.required ? '(required)' : `(default: ${param.default})`}</span>
                    <span style={{ color: 'var(--text-2)' }}>{param.description}</span>
                  </div>
                ))}
              </div>
            )}
            {result.raw && (
              <div className="g-card" style={{ padding: 12 }}>
                <pre style={{ fontSize: 12, color: 'var(--text-2)', margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{result.raw}</pre>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Schedule Tab ─────────────────────────────────────────────────────────
function ScheduleTab({ schedules, scripts, onRefresh }: { schedules: any[]; scripts: any[]; onRefresh: () => void }) {
  const [showForm, setShowForm] = useState(false);
  const [formName, setFormName] = useState('');
  const [formScript, setFormScript] = useState('');
  const [formType, setFormType] = useState('daily');
  const [formCron, setFormCron] = useState('');
  const [formTarget, setFormTarget] = useState('');
  const [formRunAs, setFormRunAs] = useState('system');
  const [saving, setSaving] = useState(false);
  const [toggling, setToggling] = useState<number | null>(null);

  const create = async () => {
    setSaving(true);
    const s = scripts.find(s => String(s.id) === formScript);
    await srAPI.createSchedule({ name: formName, script_id: s?.script_id || '', script_name: s?.name || '', schedule_type: formType, cron_expr: formCron, target: formTarget, run_as: formRunAs });
    setShowForm(false);
    setFormName(''); setFormScript(''); setFormTarget('');
    onRefresh();
    setSaving(false);
  };

  const toggle = async (id: number, enabled: boolean) => {
    setToggling(id);
    await srAPI.toggleSchedule(id, !enabled);
    onRefresh();
    setToggling(null);
  };

  const del = async (id: number) => {
    await srAPI.deleteSchedule(id);
    onRefresh();
  };

  const SCHED_TYPES = ['once', 'hourly', 'daily', 'weekly', 'monthly', 'cron', 'event'];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 1000 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontSize: 13, color: 'var(--text-3)' }}>{schedules.length} schedule{schedules.length !== 1 ? 's' : ''} configured</div>
        <button className="g-btn g-btn-primary" style={{ fontSize: 12 }} onClick={() => setShowForm(v => !v)}>+ New Schedule</button>
      </div>

      {showForm && (
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>New Scheduled Job</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <input className="g-input" placeholder="Schedule name" value={formName} onChange={e => setFormName(e.target.value)} />
            <div style={{ display: 'flex', gap: 8 }}>
              <select className="g-select" value={formScript} onChange={e => setFormScript(e.target.value)} style={{ flex: 1 }}>
                <option value="">Select script…</option>
                {scripts.filter(s => s.status === 'active').map(s => <option key={s.id} value={String(s.id)}>{s.name}</option>)}
              </select>
              <select className="g-select" value={formType} onChange={e => setFormType(e.target.value)}>
                {SCHED_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            {formType === 'cron' && (
              <input className="g-input" placeholder="Cron expression (e.g. 0 6 * * *)" value={formCron} onChange={e => setFormCron(e.target.value)} style={{ fontFamily: 'monospace' }} />
            )}
            <div style={{ display: 'flex', gap: 8 }}>
              <input className="g-input" placeholder="Target (hostname / asset group / department)" value={formTarget} onChange={e => setFormTarget(e.target.value)} style={{ flex: 1 }} />
              <select className="g-select" value={formRunAs} onChange={e => setFormRunAs(e.target.value)}>
                {['system', 'administrator', 'root', 'current_user'].map(r => <option key={r} value={r}>{r}</option>)}
              </select>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="g-btn g-btn-primary" style={{ fontSize: 12 }} onClick={create} disabled={saving || !formName || !formScript || !formTarget}>{saving ? 'Saving…' : 'Create Schedule'}</button>
              <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={() => setShowForm(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {schedules.length === 0 && (
        <div className="g-card" style={{ padding: 40, textAlign: 'center' }}>
          <div style={{ fontSize: 32, marginBottom: 8 }}>⏰</div>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>No scheduled jobs</div>
          <div style={{ color: 'var(--text-3)', fontSize: 13 }}>Create a schedule to automate script execution</div>
        </div>
      )}

      {schedules.map(s => (
        <div key={s.id} className="g-card" style={{ padding: 14, opacity: s.enabled ? 1 : 0.6 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 10 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span style={{ fontWeight: 700, fontSize: 14 }}>{s.name}</span>
                <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 10, background: s.enabled ? '#22c55e22' : '#6b728022', color: s.enabled ? '#22c55e' : '#6b7280', border: `1px solid ${s.enabled ? '#22c55e44' : '#6b728044'}`, fontWeight: 700 }}>
                  {s.enabled ? 'ENABLED' : 'DISABLED'}
                </span>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-3)' }}>
                <span style={{ fontFamily: 'monospace', color: 'var(--accent)' }}>{s.script_name}</span> · {s.schedule_type} · {s.target} · RunAs: {s.run_as}
                {s.cron_expr && <span style={{ marginLeft: 6, fontFamily: 'monospace', color: '#a855f7' }}>{s.cron_expr}</span>}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
              <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={() => toggle(s.id, s.enabled)} disabled={toggling === s.id}>
                {toggling === s.id ? '…' : s.enabled ? 'Disable' : 'Enable'}
              </button>
              <button className="g-btn g-btn-ghost" style={{ fontSize: 11, color: '#ef4444' }} onClick={() => del(s.id)}>Delete</button>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 16, fontSize: 11, color: 'var(--text-3)' }}>
            <span>Last run: {s.last_run ? timeAgo(s.last_run) : '—'}</span>
            <span>Next run: {s.next_run ? new Date(s.next_run).toLocaleString() : '—'}</span>
            <span>Created by: {s.created_by}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Approvals Tab ─────────────────────────────────────────────────────────
function ApprovalsTab({ approvals, onRefresh }: { approvals: any[]; onRefresh: () => void }) {
  const [notes, setNotes] = useState<Record<number, string>>({});
  const [loading, setLoading] = useState<number | null>(null);

  const decide = async (id: number, decision: string) => {
    setLoading(id);
    await srAPI.decide(id, { decision, notes: notes[id] || '' });
    onRefresh();
    setLoading(null);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 900 }}>
      {approvals.length === 0 && (
        <div className="g-card" style={{ padding: 40, textAlign: 'center' }}>
          <div style={{ fontSize: 32, marginBottom: 8 }}>✅</div>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>No pending approvals</div>
          <div style={{ fontSize: 13, color: 'var(--text-3)' }}>All script executions have been reviewed</div>
        </div>
      )}
      {approvals.map(a => (
        <div key={a.id} className="g-card" style={{ padding: 16, borderLeft: '3px solid #f97316' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 12 }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 4 }}>{a.script_name}</div>
              <div style={{ fontSize: 12, color: 'var(--text-3)' }}>{a.execution_id} · {timeAgo(a.created_at)}</div>
            </div>
            <span style={{ fontSize: 12, fontWeight: 700, color: '#f97316', background: '#f9731622', padding: '4px 10px', borderRadius: 6, border: '1px solid #f9731644', flexShrink: 0 }}>PENDING APPROVAL</span>
          </div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
            {[['Target', a.target], ['Run As', a.run_as], ['Requested By', a.requested_by]].map(([k, v]) => (
              <span key={k} style={{ fontSize: 11, padding: '3px 8px', borderRadius: 4, background: 'var(--border)', color: 'var(--text-2)' }}><strong>{k}:</strong> {v}</span>
            ))}
            {(a.run_as === 'root' || a.run_as === 'administrator') && (
              <span style={{ fontSize: 11, color: '#ef4444', background: '#ef444422', padding: '3px 8px', borderRadius: 4, border: '1px solid #ef444444', fontWeight: 700 }}>↑ PRIVILEGED EXECUTION</span>
            )}
          </div>
          {a.reason && (
            <div style={{ fontSize: 13, color: 'var(--text-2)', padding: '8px 12px', background: 'var(--bg)', borderRadius: 6, border: '1px solid var(--border)', marginBottom: 10, lineHeight: 1.5 }}>
              {a.reason}
            </div>
          )}
          <textarea className="g-input" rows={2} placeholder="Approval notes (optional)…" value={notes[a.id] || ''} onChange={e => setNotes(n => ({ ...n, [a.id]: e.target.value }))} style={{ width: '100%', resize: 'none', marginBottom: 10, fontSize: 12 }} />
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="g-btn g-btn-primary" style={{ fontSize: 12, background: '#22c55e' }} onClick={() => decide(a.id, 'approve')} disabled={loading === a.id}>✓ Approve &amp; Execute</button>
            <button className="g-btn g-btn-ghost" style={{ fontSize: 12, color: '#ef4444' }} onClick={() => decide(a.id, 'reject')} disabled={loading === a.id}>✗ Reject</button>
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Analytics ─────────────────────────────────────────────────────────────
function AnalyticsTab({ analytics }: { analytics: any }) {
  if (!analytics) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  const maxTrend = Math.max(...(analytics.execution_trend || []).map((d: any) => d.count), 1);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total Executions" value={analytics.total_executions} color="var(--accent)" />
        <StatCard label="Successful" value={analytics.successful} color="#22c55e" />
        <StatCard label="Failed" value={analytics.failed} color="#ef4444" />
        <StatCard label="Success Rate" value={`${analytics.success_rate}%`} color="#22c55e" />
        <StatCard label="Avg Runtime" value={`${(analytics.avg_execution_time / 1000).toFixed(1)}s`} color="#f97316" />
        <StatCard label="Time Saved" value={`${analytics.automation_time_saved_hours}h`} color="#a855f7" sub="analyst hours" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Execution Trend (7d)</div>
          <div style={{ display: 'flex', gap: 3, alignItems: 'flex-end', height: 80 }}>
            {analytics.execution_trend?.map((d: any) => (
              <div key={d.date} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                <div style={{ width: '100%', background: 'var(--accent)', borderRadius: '2px 2px 0 0', height: `${Math.max(3, (d.count / maxTrend) * 64)}px` }} title={String(d.count)} />
                <div style={{ fontSize: 8, color: 'var(--text-3)' }}>{d.date.slice(5)}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12 }}>Scripts by Category</div>
          {analytics.by_category?.map((c: any) => (
            <div key={c.category} style={{ marginBottom: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 2 }}>
                <span style={{ color: 'var(--text-2)', textTransform: 'capitalize' }}>{c.category}</span>
                <span style={{ fontWeight: 700, color: 'var(--accent)' }}>{c.count}</span>
              </div>
              <div style={{ background: 'var(--border)', borderRadius: 2, height: 5 }}>
                <div style={{ background: 'var(--accent)', borderRadius: 2, height: 5, width: `${Math.round((c.count / (analytics.by_category[0]?.count || 1)) * 100)}%` }} />
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="g-card" style={{ padding: 16 }}>
        <div style={{ fontWeight: 600, marginBottom: 12 }}>Most Executed Scripts</div>
        <div className="g-table" style={{ overflow: 'hidden' }}>
          <table style={{ width: '100%' }}>
            <thead className="g-thead">
              <tr>{['Rank', 'Script Name', 'Executions', 'Bar'].map(h => (
                <th key={h} className="g-tr" style={{ padding: '7px 14px', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left' }}>{h}</th>
              ))}</tr>
            </thead>
            <tbody>
              {analytics.most_executed?.map((s: any, i: number) => (
                <tr key={s.name} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '8px 14px', fontSize: 12, fontWeight: 700, color: i === 0 ? '#f97316' : 'var(--text-3)' }}>#{i + 1}</td>
                  <td style={{ padding: '8px 14px', fontSize: 13, fontWeight: 600 }}>{s.name}</td>
                  <td style={{ padding: '8px 14px', fontSize: 14, fontWeight: 700, color: 'var(--accent)' }}>{s.count}</td>
                  <td style={{ padding: '8px 14px', width: 200 }}>
                    <div style={{ background: 'var(--border)', borderRadius: 3, height: 6 }}>
                      <div style={{ background: 'var(--accent)', borderRadius: 3, height: 6, width: `${Math.round((s.count / (analytics.most_executed[0]?.count || 1)) * 100)}%` }} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ─── Audit Trail ─────────────────────────────────────────────────────────
function AuditTab({ entries }: { entries: any[] }) {
  return (
    <div className="g-card" style={{ overflow: 'hidden' }}>
      <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontWeight: 600 }}>Script Runner Audit Trail</span>
        <span style={{ fontSize: 12, color: 'var(--text-3)' }}>Immutable — all actions recorded</span>
      </div>
      {entries.length === 0 && <div style={{ padding: 24, color: 'var(--text-3)', textAlign: 'center' }}>No audit entries</div>}
      <div style={{ overflowX: 'auto' }}>
        <table className="g-table" style={{ width: '100%' }}>
          <thead className="g-thead">
            <tr>{['Time', 'Script', 'Action', 'Actor', 'Details'].map(h => (
              <th key={h} className="g-tr" style={{ padding: '8px 14px', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
            ))}</tr>
          </thead>
          <tbody>
            {entries.map(e => (
              <tr key={e.id} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '9px 14px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(e.created_at)}</td>
                <td style={{ padding: '9px 14px', fontSize: 12, fontWeight: 600, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.script_name}</td>
                <td style={{ padding: '9px 14px' }}>
                  <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 10, background: (ACTION_COLOR[e.action] || '#6b7280') + '22', color: ACTION_COLOR[e.action] || '#6b7280', textTransform: 'capitalize' }}>{e.action?.replace(/_/g, ' ')}</span>
                </td>
                <td style={{ padding: '9px 14px', fontSize: 12, color: 'var(--text-2)' }}>{e.actor}</td>
                <td style={{ padding: '9px 14px', fontSize: 12, color: 'var(--text-2)', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Reports ─────────────────────────────────────────────────────────────
function ReportsTab() {
  const [reportType, setReportType] = useState('execution');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const REPORT_TYPES: [string, string][] = [
    ['execution', 'Script Execution Report'],
    ['automation', 'Automation Report'],
    ['failure', 'Failure Analysis Report'],
    ['audit', 'Audit Report'],
    ['compliance', 'Compliance Report'],
  ];
  const generate = async () => {
    setLoading(true);
    const r = await srAPI.generateReport({ report_type: reportType });
    setResult(r.data);
    setLoading(false);
  };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 800 }}>
      <div className="g-card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 14 }}>Generate Report</div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'flex-end' }}>
          <div style={{ flex: 1 }}>
            <label style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase', display: 'block', marginBottom: 4 }}>Report Type</label>
            <select className="g-select" value={reportType} onChange={e => setReportType(e.target.value)} style={{ width: '100%' }}>
              {REPORT_TYPES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </div>
          <button className="g-btn g-btn-primary" onClick={generate} disabled={loading}>{loading ? 'Generating…' : 'Generate'}</button>
        </div>
      </div>
      {result && (
        <div className="g-card" style={{ padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: 15 }}>{result.title}</div>
              <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 2 }}>Generated {new Date(result.generated_at).toLocaleString()} · {result.classification}</div>
            </div>
            <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }}>⬇ Export PDF</button>
          </div>
          <div className="g-card" style={{ padding: 12, marginBottom: 16, borderLeft: '3px solid var(--accent)' }}>
            <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 6 }}>Executive Summary</div>
            <div style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.5 }}>{result.executive_summary}</div>
          </div>
          {result.key_metrics && (
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 16 }}>
              {Object.entries(result.key_metrics).map(([k, v]) => <StatCard key={k} label={k.replace(/_/g, ' ')} value={String(v)} />)}
            </div>
          )}
          {result.recommendations?.length > 0 && (
            <div>
              <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8 }}>Recommendations</div>
              {result.recommendations.map((r: string, i: number) => (
                <div key={i} style={{ display: 'flex', gap: 8, fontSize: 12, color: 'var(--text-2)', marginBottom: 5 }}>
                  <span style={{ color: 'var(--accent)', fontWeight: 700 }}>{i + 1}.</span><span>{r}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────
export default function ScriptRunnerPage() {
  const [tab, setTab] = useState<Tab>('dashboard');
  const loaded = useRef<Record<string, boolean>>({});
  const [editScript, setEditScript] = useState<any>(null);

  const [dash, setDash] = useState<any>(null);
  const [scripts, setScripts] = useState<any[]>([]);
  const [executions, setExecutions] = useState<any[]>([]);
  const [schedules, setSchedules] = useState<any[]>([]);
  const [approvals, setApprovals] = useState<any[]>([]);
  const [analytics, setAnalytics] = useState<any>(null);
  const [audit, setAudit] = useState<any[]>([]);

  useEffect(() => {
    loaded.current['dashboard'] = true;
    loaded.current['scripts'] = true;
    loaded.current['editor'] = true;
    loaded.current['executions'] = true;
    loaded.current['approvals'] = true;
    srAPI.getDashboard().then(r => setDash(r.data));
    srAPI.getScripts().then(r => setScripts(r.data || []));
    srAPI.getExecutions().then(r => setExecutions(r.data || []));
    srAPI.getApprovals().then(r => setApprovals(r.data || []));
  }, []);

  const refreshAll = () => {
    srAPI.getDashboard().then(r => setDash(r.data));
    srAPI.getScripts().then(r => setScripts(r.data || []));
    srAPI.getExecutions().then(r => setExecutions(r.data || []));
    srAPI.getApprovals().then(r => setApprovals(r.data || []));
    if (loaded.current['schedule']) srAPI.getSchedules().then(r => setSchedules(r.data || []));
    if (loaded.current['analytics']) srAPI.getAnalytics().then(r => setAnalytics(r.data));
    if (loaded.current['audit']) srAPI.getAudit().then(r => setAudit(r.data || []));
  };

  const switchTab = (t: Tab) => {
    setTab(t);
    if (!loaded.current[t]) {
      loaded.current[t] = true;
      if (t === 'schedule') srAPI.getSchedules().then(r => setSchedules(r.data || []));
      if (t === 'analytics') srAPI.getAnalytics().then(r => setAnalytics(r.data));
      if (t === 'audit') srAPI.getAudit().then(r => setAudit(r.data || []));
    }
  };

  const openEditor = (s: any) => {
    setEditScript(s);
    switchTab('editor');
  };

  const pendingApprovals = approvals.length;

  return (
    <RootLayout>
      <div style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 20, height: '100%' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>Script Runner</h1>
            <div style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 4 }}>
              Script library · Code editor · Multi-target execution · Scheduling · Approval workflow · AI generation
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {pendingApprovals > 0 && (
              <div style={{ padding: '6px 12px', borderRadius: 6, background: '#f9731622', color: '#f97316', fontSize: 12, fontWeight: 700, border: '1px solid #f9731644' }}>
                {pendingApprovals} pending approval{pendingApprovals !== 1 ? 's' : ''}
              </div>
            )}
            <button className="g-btn g-btn-ghost" style={{ fontSize: 12 }} onClick={refreshAll}>↻ Refresh</button>
            <button className="g-btn g-btn-primary" style={{ fontSize: 12 }} onClick={() => openEditor(null)}>+ New Script</button>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', overflowX: 'auto' }}>
          {(Object.keys(TAB_LABELS) as Tab[]).map(t => (
            <button key={t} onClick={() => switchTab(t)}
              style={{ padding: '8px 14px', fontSize: 12, fontWeight: tab === t ? 600 : 400, color: tab === t ? 'var(--accent)' : 'var(--text-3)', background: 'transparent', border: 'none', borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent', cursor: 'pointer', whiteSpace: 'nowrap', position: 'relative' }}>
              {TAB_LABELS[t]}
              {t === 'executions' && executions.filter(e => e.status === 'running').length > 0 && (
                <span style={{ marginLeft: 4, fontSize: 9, background: '#3b82f622', color: '#3b82f6', padding: '1px 5px', borderRadius: 8, fontWeight: 700 }}>{executions.filter(e => e.status === 'running').length}</span>
              )}
              {t === 'approvals' && pendingApprovals > 0 && (
                <span style={{ marginLeft: 4, fontSize: 9, background: '#f9731622', color: '#f97316', padding: '1px 5px', borderRadius: 8, fontWeight: 700 }}>{pendingApprovals}</span>
              )}
            </button>
          ))}
        </div>

        <div style={{ display: tab === 'dashboard' ? 'block' : 'none' }}><DashboardTab dash={dash} /></div>
        <div style={{ display: tab === 'scripts' ? 'block' : 'none' }}>
          {loaded.current['scripts'] && <ScriptsTab scripts={scripts} onOpenEditor={openEditor} onRefresh={refreshAll} />}
        </div>
        <div style={{ display: tab === 'editor' ? 'block' : 'none' }}>
          {loaded.current['editor'] && <EditorTab editScript={editScript} onSaved={refreshAll} />}
        </div>
        <div style={{ display: tab === 'executions' ? 'block' : 'none' }}>
          {loaded.current['executions'] && <ExecutionsTab executions={executions} onRefresh={refreshAll} />}
        </div>
        <div style={{ display: tab === 'ai' ? 'block' : 'none' }}>
          {loaded.current['ai'] && <AITab scripts={scripts} />}
        </div>
        <div style={{ display: tab === 'schedule' ? 'block' : 'none' }}>
          {loaded.current['schedule'] && <ScheduleTab schedules={schedules} scripts={scripts} onRefresh={refreshAll} />}
        </div>
        <div style={{ display: tab === 'approvals' ? 'block' : 'none' }}>
          {loaded.current['approvals'] && <ApprovalsTab approvals={approvals} onRefresh={refreshAll} />}
        </div>
        <div style={{ display: tab === 'analytics' ? 'block' : 'none' }}>
          {loaded.current['analytics'] && <AnalyticsTab analytics={analytics} />}
        </div>
        <div style={{ display: tab === 'audit' ? 'block' : 'none' }}>
          {loaded.current['audit'] && <AuditTab entries={audit} />}
        </div>
        <div style={{ display: tab === 'reports' ? 'block' : 'none' }}>
          {loaded.current['reports'] && <ReportsTab />}
        </div>
      </div>
    </RootLayout>
  );
}
