'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { rpeAPI, complianceAPI, exportAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';

type Tab = 'dashboard' | 'library' | 'builder' | 'scheduled' | 'history' | 'analytics' | 'audit' | 'notifications';
const TABS: { id: Tab; label: string }[] = [
  { id: 'dashboard',     label: 'Dashboard' },
  { id: 'library',       label: 'Report Library' },
  { id: 'builder',       label: 'Report Builder' },
  { id: 'scheduled',     label: 'Scheduled' },
  { id: 'history',       label: 'History' },
  { id: 'analytics',     label: 'Analytics' },
  { id: 'audit',         label: 'Audit Trail' },
  { id: 'notifications', label: 'Notifications' },
];

// ── constants ──────────────────────────────────────────────────────────────
const CATEGORIES: Record<string, { label: string; color: string; reports: string[] }> = {
  security: { label: 'Security Reports', color: '#ef4444', reports: ['Executive Security Summary','Daily SOC Report','Weekly SOC Report','Monthly Security Report','Threat Intelligence Report','Incident Summary','Alert Summary'] },
  incident_response: { label: 'Incident Response', color: '#f97316', reports: ['Incident Report','Case Report','DFIR Report','Root Cause Analysis','Lessons Learned'] },
  detection: { label: 'Detection & Monitoring', color: '#eab308', reports: ['Alert Analytics','Detection Coverage','MITRE ATT&CK Coverage','Sigma Rule Effectiveness','YARA Rule Effectiveness','False Positive Report','Suppression Report'] },
  vulnerability: { label: 'Vulnerability Management', color: '#a855f7', reports: ['Vulnerability Assessment','Risk Prioritization','Patch Status','Remediation Progress','Vulnerability SLA','Asset Exposure'] },
  endpoint_network: { label: 'Endpoint & Network', color: '#3b82f6', reports: ['Endpoint Health','Agent Status','Firewall Activity','Network Traffic Summary','Quarantine Activity'] },
  compliance: { label: 'Compliance', color: '#22c55e', reports: ['ISO 27001','NIST CSF','NIST 800-53','CIS Controls','PCI DSS','HIPAA','SOC 2','GDPR','Custom Frameworks'] },
  asset: { label: 'Asset Management', color: '#06b6d4', reports: ['Asset Inventory','Software Inventory','Hardware Inventory','CMDB Report','Mobile Device Report'] },
  executive: { label: 'Executive', color: '#8b5cf6', reports: ['Security Posture','Risk Score','Business Impact','KPI Dashboard','SLA Summary','Executive Briefing'] },
};
const DATA_SOURCES = ['SIEM','EDR','SOAR','Threat Intelligence','Vulnerability Management','CMDB','Firewall','Email Security','Cloud Security','Active Directory','Kubernetes','Audit Logs','External APIs'];
const FREQUENCIES = ['one_time','hourly','daily','weekly','monthly','quarterly','yearly','cron'];
const DELIVERY_METHODS = ['email','download_portal','api','webhook','cloud_storage'];
const EXPORT_FORMATS = ['pdf','csv','xlsx','json','html','docx'];
const BUILDER_SECTIONS = ['Executive Summary','Key Metrics KPIs','Charts & Visualizations','Threat Analysis','Alert Summary','Incident Timeline','Vulnerability Table','Compliance Scores','MITRE Heatmap','Asset Inventory','Recommendations','Appendix','Company Branding','Custom Markdown'];
const STATUS_COLOR: Record<string, string> = { active: '#22c55e', inactive: '#6b7280', completed: '#22c55e', failed: '#ef4444', running: '#3b82f6', scheduled: '#f97316', pending: '#eab308' };
const AUDIT_COLOR: Record<string, string> = { report_created: '#22c55e', report_modified: '#eab308', report_deleted: '#ef4444', report_generated: '#3b82f6', report_scheduled: '#f97316', report_exported: '#06b6d4', report_shared: '#a855f7', template_created: '#22c55e', schedule_modified: '#eab308', schedule_deleted: '#ef4444' };
const NOTIF_ICON: Record<string, string> = { report_generated: '✅', report_failed: '❌', scheduled_completed: '⏰', report_shared: '🔗', export_completed: '⬇', report_scheduled: '📅' };

function pill(label: string, color: string) {
  return <span style={{ fontSize: 10, fontWeight: 600, padding: '2px 8px', borderRadius: 10, background: color + '22', color, border: `1px solid ${color}44`, textTransform: 'capitalize', whiteSpace: 'nowrap' }}>{label}</span>;
}
function bytes(n: number) {
  if (n > 1e9) return `${(n / 1e9).toFixed(1)} GB`;
  if (n > 1e6) return `${(n / 1e6).toFixed(1)} MB`;
  if (n > 1e3) return `${(n / 1e3).toFixed(1)} KB`;
  return `${n} B`;
}
function StatCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="g-card" style={{ padding: '14px 18px', minWidth: 120 }}>
      <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 700, color: color || 'var(--text-1)', lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 3 }}>{sub}</div>}
    </div>
  );
}

// ── Dashboard ──────────────────────────────────────────────────────────────
function DashboardTab({ dash, onTabChange }: { dash: any; onTabChange: (t: Tab) => void }) {
  if (!dash) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total Reports"      value={dash.total_reports || 0}       color="var(--accent)" />
        <StatCard label="Scheduled"          value={dash.scheduled_reports || 0}    color="#f97316" />
        <StatCard label="Generated Today"    value={dash.generated_today || 0}      color="#22c55e" />
        <StatCard label="Failed"             value={dash.failed_reports || 0}        color="#ef4444" />
        <StatCard label="Templates"          value={dash.report_templates || 0}     color="#3b82f6" />
        <StatCard label="Shared"             value={dash.shared_reports || 0}       color="#a855f7" />
        <StatCard label="Exports"            value={dash.export_history || 0}       color="#06b6d4" />
        <StatCard label="Storage Used"       value={bytes(dash.storage_bytes || 0)} color="#eab308" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 13 }}>Reports by Category</div>
          {(!dash.by_category || dash.by_category.length === 0) && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No data</div>}
          {(dash.by_category || []).map((c: any) => {
            const cat = CATEGORIES[c.category];
            const color = cat?.color || '#6b7280';
            return (
              <div key={c.category} style={{ marginBottom: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 3 }}>
                  <span style={{ color: 'var(--text-2)' }}>{cat?.label || c.category}</span>
                  <span style={{ fontWeight: 700, color }}>{c.count}</span>
                </div>
                <div style={{ background: 'var(--border)', borderRadius: 3, height: 4 }}>
                  <div style={{ background: color, borderRadius: 3, height: 4, width: `${Math.min(100, (c.count / Math.max(...(dash.by_category || []).map((x: any) => x.count), 1)) * 100)}%` }} />
                </div>
              </div>
            );
          })}
        </div>

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 13 }}>Recent Executions</div>
          {(!dash.recent_executions || dash.recent_executions.length === 0) && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No recent activity</div>}
          {(dash.recent_executions || []).slice(0, 6).map((e: any, i: number) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
              <div>
                <div style={{ fontSize: 12, fontWeight: 500, maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.report_name}</div>
                <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{timeAgo(e.started_at)}</div>
              </div>
              {pill(e.status, STATUS_COLOR[e.status] || '#6b7280')}
            </div>
          ))}
        </div>

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 13 }}>Upcoming Schedules</div>
          {(!dash.upcoming_schedules || dash.upcoming_schedules.length === 0) && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No upcoming schedules</div>}
          {(dash.upcoming_schedules || []).map((s: any, i: number) => (
            <div key={i} style={{ padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <div style={{ fontSize: 12, fontWeight: 500 }}>{s.report_name}</div>
              <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>
                <span style={{ color: '#f97316', marginRight: 6 }}>{s.frequency}</span>
                {s.next_run_at ? `Next: ${timeAgo(s.next_run_at)}` : 'Not scheduled'}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Quick actions */}
      <div className="g-card" style={{ padding: 16 }}>
        <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 13 }}>Quick Exports</div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          {[
            { label: '⬇ Alerts CSV', url: exportAPI.alertsCSV() },
            { label: '⬇ Incidents CSV', url: exportAPI.incidentsCSV() },
            { label: '⬇ Vulns CSV', url: exportAPI.vulnsCSV() },
            { label: '⬇ Audit JSON', url: exportAPI.auditJSON() },
          ].map(e => (
            <a key={e.label} href={e.url} download className="g-btn g-btn-ghost" style={{ fontSize: 11 }}>{e.label}</a>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Report Library ─────────────────────────────────────────────────────────
function LibraryTab({ reports, onRefresh }: { reports: any[]; onRefresh: () => void }) {
  const [search, setSearch] = useState('');
  const [filterCat, setFilterCat] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [showNew, setShowNew] = useState(false);
  const [generating, setGenerating] = useState<string | null>(null);
  const [toast, setToast] = useState('');
  const [form, setForm] = useState({ name: '', description: '', category: 'security', report_type: '', owner: '', tags: '', data_sources: '[]', template_id: '' });
  const [saving, setSaving] = useState(false);
  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(''), 3000); };

  const filtered = useMemo(() => reports.filter(r => {
    if (filterCat && r.category !== filterCat) return false;
    if (filterStatus && r.status !== filterStatus) return false;
    if (search) {
      const q = search.toLowerCase();
      return r.name.toLowerCase().includes(q) || r.report_id.toLowerCase().includes(q) || (r.description || '').toLowerCase().includes(q) || (r.owner || '').toLowerCase().includes(q);
    }
    return true;
  }), [reports, filterCat, filterStatus, search]);

  const create = async () => {
    if (!form.name) return;
    setSaving(true);
    try { await rpeAPI.createReport(form); onRefresh(); setShowNew(false); notify('Report created'); }
    catch { notify('Failed'); } finally { setSaving(false); }
  };

  const gen = async (reportId: string, name: string) => {
    setGenerating(reportId);
    try { await rpeAPI.generate(reportId, { format: 'pdf' }); onRefresh(); notify(`'${name}' generated`); }
    catch { notify('Generation failed'); } finally { setGenerating(null); }
  };

  const del = async (id: number, name: string) => {
    await rpeAPI.deleteReport(id); onRefresh(); notify(`'${name}' deleted`);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {toast && <div className="g-card" style={{ padding: '8px 14px', borderLeft: '3px solid var(--accent)', fontSize: 13 }}>{toast}</div>}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <input className="g-input" placeholder="Search reports…" value={search} onChange={e => setSearch(e.target.value)} style={{ fontSize: 12, width: 220 }} />
        <select className="g-select" value={filterCat} onChange={e => setFilterCat(e.target.value)} style={{ fontSize: 11 }}>
          <option value="">All Categories</option>
          {Object.entries(CATEGORIES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
        </select>
        <select className="g-select" value={filterStatus} onChange={e => setFilterStatus(e.target.value)} style={{ fontSize: 11 }}>
          <option value="">All Status</option>
          {['active','inactive'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{filtered.length} of {reports.length}</span>
        <button className="g-btn g-btn-primary" style={{ fontSize: 11, marginLeft: 'auto' }} onClick={() => setShowNew(true)}>+ New Report</button>
      </div>

      <div className="g-card" style={{ overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table className="g-table" style={{ width: '100%' }}>
            <thead className="g-thead">
              <tr>{['Report ID','Name','Category','Type','Owner','Last Generated','Generations','Status','Tags',''].map(h => (
                <th key={h} className="g-tr" style={{ padding: '8px 12px', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
              ))}</tr>
            </thead>
            <tbody>
              {filtered.length === 0 && <tr><td colSpan={10} style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)' }}>No reports. Create one to get started.</td></tr>}
              {filtered.map(r => {
                const cat = CATEGORIES[r.category];
                let tags: string[] = [];
                try { tags = JSON.parse(r.tags || '[]'); } catch {}
                return (
                  <tr key={r.id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '10px 12px', fontSize: 10, fontFamily: 'monospace', color: 'var(--accent)' }}>{r.report_id}</td>
                    <td style={{ padding: '10px 12px', maxWidth: 200 }}>
                      <div style={{ fontWeight: 600, fontSize: 13 }}>{r.name}</div>
                      {r.description && <div style={{ fontSize: 11, color: 'var(--text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 180 }}>{r.description}</div>}
                    </td>
                    <td style={{ padding: '10px 12px' }}>{cat ? pill(cat.label, cat.color) : pill(r.category, '#6b7280')}</td>
                    <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-2)' }}>{r.report_type || '—'}</td>
                    <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-2)' }}>{r.owner || '—'}</td>
                    <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{r.last_generated_at ? timeAgo(r.last_generated_at) : 'Never'}</td>
                    <td style={{ padding: '10px 12px', fontSize: 12, fontWeight: 700, color: 'var(--accent)' }}>{r.generation_count}</td>
                    <td style={{ padding: '10px 12px' }}>{pill(r.status, STATUS_COLOR[r.status] || '#6b7280')}</td>
                    <td style={{ padding: '10px 12px' }}>
                      <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                        {tags.slice(0, 2).map((t: string) => <span key={t} style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3, background: 'var(--border)', color: 'var(--text-3)' }}>{t}</span>)}
                      </div>
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        <button className="g-btn g-btn-ghost" style={{ fontSize: 10, padding: '2px 8px' }} onClick={() => gen(r.report_id, r.name)} disabled={generating === r.report_id}>
                          {generating === r.report_id ? '…' : '▶ Run'}
                        </button>
                        <button style={{ fontSize: 13, color: 'var(--text-3)' }} onClick={() => del(r.id, r.name)}>🗑</button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {showNew && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setShowNew(false)}>
          <div className="g-modal" style={{ maxWidth: 560 }}>
            <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between' }}>
              <div style={{ fontWeight: 700 }}>New Report</div>
              <button onClick={() => setShowNew(false)} style={{ fontSize: 18, color: 'var(--text-3)' }}>×</button>
            </div>
            <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 12, maxHeight: '70vh', overflow: 'auto' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Report Name *</label>
                  <input className="g-input w-full" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g. Weekly SOC Report" />
                </div>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Category</label>
                  <select className="g-select w-full" value={form.category} onChange={e => setForm(f => ({ ...f, category: e.target.value }))}>
                    {Object.entries(CATEGORIES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Report Type</label>
                  <select className="g-select w-full" value={form.report_type} onChange={e => setForm(f => ({ ...f, report_type: e.target.value }))}>
                    <option value="">Select type…</option>
                    {CATEGORIES[form.category]?.reports.map(r => <option key={r} value={r}>{r}</option>)}
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Owner</label>
                  <input className="g-input w-full" value={form.owner} onChange={e => setForm(f => ({ ...f, owner: e.target.value }))} placeholder="alice@corp.com" />
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Description</label>
                  <input className="g-input w-full" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Tags (comma-separated)</label>
                  <input className="g-input w-full" value={form.tags} onChange={e => setForm(f => ({ ...f, tags: e.target.value }))} placeholder="soc, weekly, security" />
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Data Sources</label>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {DATA_SOURCES.map(ds => {
                      let selected: string[] = [];
                      try { selected = JSON.parse(form.data_sources || '[]'); } catch {}
                      const active = selected.includes(ds);
                      return (
                        <button key={ds} type="button" onClick={() => {
                          const cur = selected.includes(ds) ? selected.filter(s => s !== ds) : [...selected, ds];
                          setForm(f => ({ ...f, data_sources: JSON.stringify(cur) }));
                        }} style={{ fontSize: 10, padding: '3px 8px', borderRadius: 8, background: active ? 'var(--accent)22' : 'var(--border)', color: active ? 'var(--accent)' : 'var(--text-3)', border: `1px solid ${active ? 'var(--accent)' : 'transparent'}` }}>
                          {ds}
                        </button>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>
            <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)', display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="g-btn g-btn-ghost" onClick={() => setShowNew(false)}>Cancel</button>
              <button className="g-btn g-btn-primary" onClick={create} disabled={saving || !form.name}>{saving ? 'Creating…' : 'Create Report'}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Builder ────────────────────────────────────────────────────────────────
function BuilderTab({ templates, onRefresh }: { templates: any[]; onRefresh: () => void }) {
  const [sections, setSections] = useState<string[]>(['Executive Summary', 'Key Metrics KPIs', 'Threat Analysis', 'Recommendations']);
  const [branding, setBranding] = useState({ company: 'Acme Corp', logo: '', primary_color: '#6366f1' });
  const [selectedSources, setSelectedSources] = useState<string[]>(['SIEM', 'EDR']);
  const [showSaveTemplate, setShowSaveTemplate] = useState(false);
  const [tplForm, setTplForm] = useState({ name: '', description: '', category: 'security' });
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState('');
  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(''), 3000); };

  const toggleSection = (s: string) => setSections(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s]);
  const moveUp = (i: number) => { if (i === 0) return; const a = [...sections]; [a[i-1], a[i]] = [a[i], a[i-1]]; setSections(a); };
  const moveDown = (i: number) => { if (i >= sections.length - 1) return; const a = [...sections]; [a[i], a[i+1]] = [a[i+1], a[i]]; setSections(a); };

  const saveTemplate = async () => {
    if (!tplForm.name) return;
    setSaving(true);
    try {
      await rpeAPI.createTemplate({ ...tplForm, sections: JSON.stringify(sections), default_data_sources: JSON.stringify(selectedSources) });
      onRefresh(); setShowSaveTemplate(false); notify('Template saved');
    } catch { notify('Failed'); } finally { setSaving(false); }
  };

  const delTemplate = async (id: number, name: string) => {
    await rpeAPI.deleteTemplate(id); onRefresh(); notify(`Template '${name}' deleted`);
  };

  return (
    <div style={{ display: 'flex', gap: 20 }}>
      {/* Builder panel */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 14 }}>
        {toast && <div className="g-card" style={{ padding: '8px 14px', borderLeft: '3px solid var(--accent)', fontSize: 13 }}>{toast}</div>}

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 13 }}>Report Sections</div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 12 }}>
            {BUILDER_SECTIONS.map(s => (
              <button key={s} type="button" onClick={() => toggleSection(s)} style={{ fontSize: 10, padding: '3px 8px', borderRadius: 8, background: sections.includes(s) ? 'var(--accent)22' : 'var(--border)', color: sections.includes(s) ? 'var(--accent)' : 'var(--text-3)', border: `1px solid ${sections.includes(s) ? 'var(--accent)44' : 'transparent'}` }}>
                {sections.includes(s) ? '✓ ' : '+ '}{s}
              </button>
            ))}
          </div>
          <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8, color: 'var(--text-2)' }}>Section Order (drag to rearrange)</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {sections.map((s, i) => (
              <div key={s} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', background: 'var(--border)', borderRadius: 8 }}>
                <span style={{ fontSize: 11, color: 'var(--text-3)', width: 20 }}>{i + 1}.</span>
                <span style={{ flex: 1, fontSize: 12, fontWeight: 500 }}>{s}</span>
                <div style={{ display: 'flex', gap: 4 }}>
                  <button style={{ fontSize: 11, color: 'var(--text-3)', padding: '0 4px' }} onClick={() => moveUp(i)}>↑</button>
                  <button style={{ fontSize: 11, color: 'var(--text-3)', padding: '0 4px' }} onClick={() => moveDown(i)}>↓</button>
                  <button style={{ fontSize: 11, color: '#ef4444', padding: '0 4px' }} onClick={() => toggleSection(s)}>×</button>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 13 }}>Data Sources</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {DATA_SOURCES.map(ds => (
              <button key={ds} type="button" onClick={() => setSelectedSources(prev => prev.includes(ds) ? prev.filter(x => x !== ds) : [...prev, ds])} style={{ fontSize: 10, padding: '4px 10px', borderRadius: 8, background: selectedSources.includes(ds) ? '#22c55e22' : 'var(--border)', color: selectedSources.includes(ds) ? '#22c55e' : 'var(--text-3)', border: `1px solid ${selectedSources.includes(ds) ? '#22c55e44' : 'transparent'}` }}>
                {selectedSources.includes(ds) ? '✓ ' : ''}{ds}
              </button>
            ))}
          </div>
        </div>

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 13 }}>Company Branding</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Company Name</label>
              <input className="g-input w-full" value={branding.company} onChange={e => setBranding(b => ({ ...b, company: e.target.value }))} />
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Primary Color</label>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <input type="color" value={branding.primary_color} onChange={e => setBranding(b => ({ ...b, primary_color: e.target.value }))} style={{ width: 36, height: 32, borderRadius: 6, border: '1px solid var(--border)', cursor: 'pointer' }} />
                <input className="g-input" value={branding.primary_color} onChange={e => setBranding(b => ({ ...b, primary_color: e.target.value }))} style={{ flex: 1, fontSize: 11, fontFamily: 'monospace' }} />
              </div>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <button className="g-btn g-btn-primary" style={{ fontSize: 11 }} onClick={() => setShowSaveTemplate(true)}>💾 Save as Template</button>
        </div>
      </div>

      {/* Preview panel */}
      <div style={{ width: 320, flexShrink: 0 }}>
        <div className="g-card" style={{ padding: 16, position: 'sticky', top: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 13 }}>Preview</div>
          <div style={{ background: '#fff', borderRadius: 8, padding: 16, minHeight: 400, border: '1px solid var(--border)' }}>
            <div style={{ borderBottom: `3px solid ${branding.primary_color}`, marginBottom: 12, paddingBottom: 8 }}>
              <div style={{ fontWeight: 700, fontSize: 13, color: '#111' }}>{branding.company}</div>
              <div style={{ fontSize: 10, color: '#666' }}>Security Report — {new Date().toLocaleDateString()}</div>
            </div>
            {sections.map((s, i) => (
              <div key={s} style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: branding.primary_color, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>{i + 1}. {s}</div>
                <div style={{ height: s === 'Key Metrics KPIs' ? 36 : s === 'Charts & Visualizations' ? 48 : 18, background: '#f3f4f6', borderRadius: 4 }} />
              </div>
            ))}
            <div style={{ borderTop: '1px solid #e5e7eb', marginTop: 12, paddingTop: 8, fontSize: 9, color: '#9ca3af', textAlign: 'center' }}>
              {selectedSources.slice(0, 3).join(' · ')}{selectedSources.length > 3 ? ` +${selectedSources.length - 3}` : ''}
            </div>
          </div>
        </div>

        {/* Templates */}
        <div className="g-card" style={{ padding: 16, marginTop: 14 }}>
          <div style={{ fontWeight: 600, marginBottom: 10, fontSize: 13 }}>Saved Templates ({templates.length})</div>
          {templates.length === 0 && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No templates yet</div>}
          {templates.map(t => (
            <div key={t.id} style={{ padding: '8px 0', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600 }}>{t.name}</div>
                <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{t.is_builtin ? '🔒 Built-in' : `Used ${t.use_count}×`}</div>
              </div>
              {!t.is_builtin && <button style={{ fontSize: 13, color: 'var(--text-3)' }} onClick={() => delTemplate(t.id, t.name)}>🗑</button>}
            </div>
          ))}
        </div>
      </div>

      {showSaveTemplate && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setShowSaveTemplate(false)}>
          <div className="g-modal" style={{ maxWidth: 420 }}>
            <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between' }}>
              <div style={{ fontWeight: 700 }}>Save Template</div>
              <button onClick={() => setShowSaveTemplate(false)} style={{ fontSize: 18, color: 'var(--text-3)' }}>×</button>
            </div>
            <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Template Name *</label>
                <input className="g-input w-full" value={tplForm.name} onChange={e => setTplForm(f => ({ ...f, name: e.target.value }))} placeholder="My Security Template" />
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Description</label>
                <input className="g-input w-full" value={tplForm.description} onChange={e => setTplForm(f => ({ ...f, description: e.target.value }))} />
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Category</label>
                <select className="g-select w-full" value={tplForm.category} onChange={e => setTplForm(f => ({ ...f, category: e.target.value }))}>
                  {Object.entries(CATEGORIES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
                </select>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-3)', padding: '8px 12px', background: 'var(--border)', borderRadius: 8 }}>
                Saving {sections.length} sections · {selectedSources.length} data sources
              </div>
            </div>
            <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)', display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="g-btn g-btn-ghost" onClick={() => setShowSaveTemplate(false)}>Cancel</button>
              <button className="g-btn g-btn-primary" onClick={saveTemplate} disabled={saving || !tplForm.name}>{saving ? 'Saving…' : 'Save Template'}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Scheduled ──────────────────────────────────────────────────────────────
function ScheduledTab({ schedules, reports, onRefresh }: { schedules: any[]; reports: any[]; onRefresh: () => void }) {
  const [showNew, setShowNew] = useState(false);
  const [form, setForm] = useState({ report_id: '', report_name: '', frequency: 'weekly', cron_expr: '', delivery_method: 'email', recipients: '', export_format: 'pdf', webhook_url: '' });
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState('');
  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(''), 3000); };

  const save = async () => {
    if (!form.report_id) return;
    setSaving(true);
    const rpt = reports.find(r => r.report_id === form.report_id);
    try {
      await rpeAPI.createSchedule({ ...form, report_name: rpt?.name || form.report_name, recipients: form.recipients ? JSON.stringify(form.recipients.split(',').map(s => s.trim())) : '[]' });
      onRefresh(); setShowNew(false); notify('Schedule created');
    } catch { notify('Failed'); } finally { setSaving(false); }
  };

  const toggle = async (id: number, current: string) => {
    await rpeAPI.updateSchedule(id, { status: current === 'active' ? 'paused' : 'active' }); onRefresh();
  };
  const del = async (id: number) => { await rpeAPI.deleteSchedule(id); onRefresh(); notify('Schedule deleted'); };

  const FREQ_COLOR: Record<string, string> = { one_time: '#6b7280', hourly: '#3b82f6', daily: '#22c55e', weekly: '#a855f7', monthly: '#f97316', quarterly: '#eab308', yearly: '#06b6d4', cron: '#ef4444' };
  const DELIVERY_ICON: Record<string, string> = { email: '📧', download_portal: '⬇', api: '🔌', webhook: '🔗', cloud_storage: '☁' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {toast && <div className="g-card" style={{ padding: '8px 14px', borderLeft: '3px solid var(--accent)', fontSize: 13 }}>{toast}</div>}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontSize: 13, color: 'var(--text-3)' }}>{schedules.length} scheduled reports</div>
        <button className="g-btn g-btn-primary" style={{ fontSize: 11 }} onClick={() => setShowNew(true)}>+ New Schedule</button>
      </div>
      <div className="g-card" style={{ overflow: 'hidden' }}>
        <table className="g-table" style={{ width: '100%' }}>
          <thead className="g-thead">
            <tr>{['Schedule ID','Report','Frequency','Delivery','Format','Last Run','Next Run','Runs','Status',''].map(h => (
              <th key={h} className="g-tr" style={{ padding: '8px 12px', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
            ))}</tr>
          </thead>
          <tbody>
            {schedules.length === 0 && <tr><td colSpan={10} style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)' }}>No schedules configured</td></tr>}
            {schedules.map(s => (
              <tr key={s.id} style={{ borderBottom: '1px solid var(--border)', opacity: s.status === 'paused' ? 0.6 : 1 }}>
                <td style={{ padding: '10px 12px', fontSize: 10, fontFamily: 'monospace', color: 'var(--accent)' }}>{s.schedule_id}</td>
                <td style={{ padding: '10px 12px', fontWeight: 600, fontSize: 12, maxWidth: 180 }}>{s.report_name}</td>
                <td style={{ padding: '10px 12px' }}>{pill(s.frequency, FREQ_COLOR[s.frequency] || '#6b7280')}</td>
                <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-2)' }}>{DELIVERY_ICON[s.delivery_method] || ''} {s.delivery_method}</td>
                <td style={{ padding: '10px 12px', fontSize: 11, textTransform: 'uppercase', color: 'var(--text-3)' }}>{s.export_format}</td>
                <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{s.last_run_at ? timeAgo(s.last_run_at) : '—'}</td>
                <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{s.next_run_at ? timeAgo(s.next_run_at) : '—'}</td>
                <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-2)' }}>
                  <span style={{ color: '#22c55e' }}>✓{s.success_count}</span> / <span style={{ color: '#ef4444' }}>✗{s.failure_count}</span>
                </td>
                <td style={{ padding: '10px 12px' }}>{pill(s.status, STATUS_COLOR[s.status] || '#6b7280')}</td>
                <td style={{ padding: '10px 12px' }}>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button className="g-btn g-btn-ghost" style={{ fontSize: 10, padding: '2px 8px' }} onClick={() => toggle(s.id, s.status)}>{s.status === 'active' ? 'Pause' : 'Resume'}</button>
                    <button style={{ fontSize: 13, color: 'var(--text-3)' }} onClick={() => del(s.id)}>🗑</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showNew && (
        <div className="g-modal-backdrop" onClick={e => e.target === e.currentTarget && setShowNew(false)}>
          <div className="g-modal" style={{ maxWidth: 520 }}>
            <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between' }}>
              <div style={{ fontWeight: 700 }}>New Schedule</div>
              <button onClick={() => setShowNew(false)} style={{ fontSize: 18, color: 'var(--text-3)' }}>×</button>
            </div>
            <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Report *</label>
                <select className="g-select w-full" value={form.report_id} onChange={e => setForm(f => ({ ...f, report_id: e.target.value }))}>
                  <option value="">Select report…</option>
                  {reports.map(r => <option key={r.report_id} value={r.report_id}>{r.name}</option>)}
                </select>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Frequency</label>
                  <select className="g-select w-full" value={form.frequency} onChange={e => setForm(f => ({ ...f, frequency: e.target.value }))}>
                    {FREQUENCIES.map(f => <option key={f} value={f}>{f}</option>)}
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Export Format</label>
                  <select className="g-select w-full" value={form.export_format} onChange={e => setForm(f => ({ ...f, export_format: e.target.value }))}>
                    {EXPORT_FORMATS.map(f => <option key={f} value={f}>{f.toUpperCase()}</option>)}
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Delivery Method</label>
                  <select className="g-select w-full" value={form.delivery_method} onChange={e => setForm(f => ({ ...f, delivery_method: e.target.value }))}>
                    {DELIVERY_METHODS.map(m => <option key={m} value={m}>{m.replace(/_/g, ' ')}</option>)}
                  </select>
                </div>
                {form.frequency === 'cron' && (
                  <div>
                    <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Cron Expression</label>
                    <input className="g-input w-full" value={form.cron_expr} onChange={e => setForm(f => ({ ...f, cron_expr: e.target.value }))} placeholder="0 8 * * 1" />
                  </div>
                )}
              </div>
              {form.delivery_method === 'email' && (
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Recipients (comma-separated)</label>
                  <input className="g-input w-full" value={form.recipients} onChange={e => setForm(f => ({ ...f, recipients: e.target.value }))} placeholder="ciso@corp.com, team@corp.com" />
                </div>
              )}
              {form.delivery_method === 'webhook' && (
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Webhook URL</label>
                  <input className="g-input w-full" value={form.webhook_url} onChange={e => setForm(f => ({ ...f, webhook_url: e.target.value }))} placeholder="https://hooks.example.com/…" />
                </div>
              )}
            </div>
            <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)', display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="g-btn g-btn-ghost" onClick={() => setShowNew(false)}>Cancel</button>
              <button className="g-btn g-btn-primary" onClick={save} disabled={saving || !form.report_id}>{saving ? 'Saving…' : 'Create Schedule'}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── History ────────────────────────────────────────────────────────────────
function HistoryTab({ executions }: { executions: any[] }) {
  const FORMAT_ICON: Record<string, string> = { pdf: '📄', csv: '📊', xlsx: '📊', json: '{}', html: '🌐', docx: '📝' };
  return (
    <div className="g-card" style={{ overflow: 'hidden' }}>
      <table className="g-table" style={{ width: '100%' }}>
        <thead className="g-thead">
          <tr>{['Execution ID','Report','Status','Format','Triggered By','Executed By','Duration','Size','Started',''].map(h => (
            <th key={h} className="g-tr" style={{ padding: '8px 12px', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
          ))}</tr>
        </thead>
        <tbody>
          {executions.length === 0 && <tr><td colSpan={10} style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)' }}>No execution history</td></tr>}
          {executions.map(e => (
            <tr key={e.id} style={{ borderBottom: '1px solid var(--border)' }}>
              <td style={{ padding: '10px 12px', fontSize: 10, fontFamily: 'monospace', color: 'var(--accent)' }}>{e.execution_id}</td>
              <td style={{ padding: '10px 12px', fontWeight: 600, fontSize: 12, maxWidth: 180 }}>{e.report_name}</td>
              <td style={{ padding: '10px 12px' }}>{pill(e.status, STATUS_COLOR[e.status] || '#6b7280')}</td>
              <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-2)' }}>{FORMAT_ICON[e.export_format] || ''} {e.export_format?.toUpperCase()}</td>
              <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)' }}>{e.triggered_by}</td>
              <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-2)' }}>{e.executed_by}</td>
              <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)' }}>{e.duration_ms ? `${(e.duration_ms / 1000).toFixed(1)}s` : '—'}</td>
              <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-2)' }}>{bytes(e.file_size_bytes || 0)}</td>
              <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(e.started_at)}</td>
              <td style={{ padding: '10px 12px' }}>
                {e.download_url && <a href={e.download_url} className="g-btn g-btn-ghost" style={{ fontSize: 10, padding: '2px 8px' }}>⬇ Download</a>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Analytics ──────────────────────────────────────────────────────────────
function AnalyticsTab({ data }: { data: any }) {
  if (!data) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>No analytics data</div>;
  const FORMAT_COLOR: Record<string, string> = { pdf: '#ef4444', csv: '#22c55e', xlsx: '#3b82f6', json: '#eab308', html: '#f97316', docx: '#a855f7' };
  const successRate = parseFloat(data.success_rate || '0');
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <StatCard label="Total Executions"  value={data.total_executions || 0}  color="var(--accent)" />
        <StatCard label="Successful"        value={data.success_executions || 0} color="#22c55e" />
        <StatCard label="Failed"            value={data.failed_executions || 0}  color="#ef4444" />
        <StatCard label="Success Rate"      value={`${data.success_rate || 0}%`} color={successRate >= 90 ? '#22c55e' : successRate >= 70 ? '#eab308' : '#ef4444'} />
        <StatCard label="Avg Duration"      value={data.avg_duration_ms ? `${(data.avg_duration_ms / 1000).toFixed(1)}s` : '—'} color="#3b82f6" />
        <StatCard label="Storage Used"      value={bytes(data.storage_bytes || 0)} color="#a855f7" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 13 }}>Most Generated Reports</div>
          {(!data.most_generated || data.most_generated.length === 0) && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No data</div>}
          {(data.most_generated || []).map((r: any, i: number) => (
            <div key={r.report_name} style={{ marginBottom: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 3 }}>
                <span style={{ color: 'var(--text-2)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  <span style={{ color: 'var(--text-3)', marginRight: 6 }}>#{i + 1}</span>{r.report_name}
                </span>
                <span style={{ fontWeight: 700, color: 'var(--accent)' }}>{r.count}</span>
              </div>
              <div style={{ background: 'var(--border)', borderRadius: 3, height: 4 }}>
                <div style={{ background: 'var(--accent)', borderRadius: 3, height: 4, width: `${Math.min(100, (r.count / Math.max(...(data.most_generated || []).map((x: any) => x.count), 1)) * 100)}%` }} />
              </div>
            </div>
          ))}
        </div>

        <div className="g-card" style={{ padding: 16 }}>
          <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 13 }}>Exports by Format</div>
          {(!data.by_export_format || data.by_export_format.length === 0) && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No data</div>}
          {(data.by_export_format || []).map((f: any) => {
            const color = FORMAT_COLOR[f.format] || '#6b7280';
            const max = Math.max(...(data.by_export_format || []).map((x: any) => x.count), 1);
            return (
              <div key={f.format} style={{ marginBottom: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 3 }}>
                  <span style={{ fontWeight: 600, textTransform: 'uppercase', color }}>{f.format}</span>
                  <span style={{ fontWeight: 700, color }}>{f.count}</span>
                </div>
                <div style={{ background: 'var(--border)', borderRadius: 3, height: 4 }}>
                  <div style={{ background: color, borderRadius: 3, height: 4, width: `${(f.count / max) * 100}%` }} />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ── Audit Trail ────────────────────────────────────────────────────────────
function AuditTab({ items }: { items: any[] }) {
  return (
    <div className="g-card" style={{ overflow: 'hidden' }}>
      <table className="g-table" style={{ width: '100%' }}>
        <thead className="g-thead">
          <tr>{['Time','Action','Object Type','Object Name','Actor','Details'].map(h => (
            <th key={h} className="g-tr" style={{ padding: '8px 12px', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-3)', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
          ))}</tr>
        </thead>
        <tbody>
          {items.length === 0 && <tr><td colSpan={6} style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)' }}>No audit events</td></tr>}
          {items.map(a => (
            <tr key={a.id} style={{ borderBottom: '1px solid var(--border)' }}>
              <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(a.created_at)}</td>
              <td style={{ padding: '10px 12px' }}>{pill(a.action, AUDIT_COLOR[a.action] || '#6b7280')}</td>
              <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', textTransform: 'capitalize' }}>{(a.object_type || '').replace(/_/g, ' ')}</td>
              <td style={{ padding: '10px 12px', fontSize: 12, fontWeight: 500 }}>{a.object_name || a.object_id || '—'}</td>
              <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-2)' }}>{a.actor}</td>
              <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-3)', fontStyle: 'italic', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.details || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Notifications ──────────────────────────────────────────────────────────
function NotificationsTab({ items, onMarkRead }: { items: any[]; onMarkRead: () => void }) {
  const SEVERITY_COLOR: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#3b82f6' };
  const unread = items.filter(n => !n.read).length;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontWeight: 600 }}>Notifications {unread > 0 && <span style={{ fontSize: 11, background: '#3b82f622', color: '#3b82f6', borderRadius: 10, padding: '1px 8px', marginLeft: 6 }}>{unread} unread</span>}</div>
        {unread > 0 && <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={onMarkRead}>Mark all read</button>}
      </div>
      {items.length === 0 && <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>No notifications</div>}
      {items.map(n => (
        <div key={n.id} className="g-card" style={{ padding: '12px 16px', display: 'flex', gap: 12, alignItems: 'flex-start', opacity: n.read ? 0.65 : 1, borderLeft: `3px solid ${SEVERITY_COLOR[n.severity] || '#6b7280'}` }}>
          <div style={{ fontSize: 20, width: 28, textAlign: 'center', flexShrink: 0 }}>{NOTIF_ICON[n.event_type] || '📋'}</div>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 13, fontWeight: n.read ? 400 : 600 }}>{n.title}</div>
            <div style={{ fontSize: 12, color: 'var(--text-2)', marginTop: 2 }}>{n.message}</div>
            {n.report_name && <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>Report: {n.report_name}</div>}
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 3 }}>{timeAgo(n.created_at)}</div>
          </div>
          {pill(n.severity, SEVERITY_COLOR[n.severity] || '#6b7280')}
        </div>
      ))}
    </div>
  );
}

// ── AI Panel ───────────────────────────────────────────────────────────────
function AIPanel({ onClose }: { onClose: () => void }) {
  const [input, setInput] = useState('');
  const [response, setResponse] = useState('');
  const [loading, setLoading] = useState(false);
  const actions = [
    { id: 'generate_report',      label: '📋 Generate Report' },
    { id: 'summarize_findings',   label: '📊 Summarize Findings' },
    { id: 'highlight_risks',      label: '🚨 Highlight Critical Risks' },
    { id: 'explain_trends',       label: '📈 Explain Security Trends' },
    { id: 'recommend_actions',    label: '✅ Recommend Actions' },
    { id: 'executive_summary',    label: '👔 Executive Summary' },
  ];
  const ask = async (action: string) => {
    setLoading(true);
    try { const r = await rpeAPI.ai({ action, context: input }); setResponse((r.data as any)?.response || ''); }
    catch { setResponse('AI unavailable.'); } finally { setLoading(false); }
  };
  return (
    <div style={{ position: 'fixed', top: 0, right: 0, bottom: 0, width: 460, background: 'var(--glass-bg)', borderLeft: '1px solid var(--border)', zIndex: 100, display: 'flex', flexDirection: 'column', boxShadow: '-4px 0 24px rgba(0,0,0,0.3)' }}>
      <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontWeight: 700, fontSize: 14 }}>📋 Reports AI Assistant</div>
        <button onClick={onClose} style={{ fontSize: 18, color: 'var(--text-3)' }}>×</button>
      </div>
      <div style={{ padding: 16, flex: 1, display: 'flex', flexDirection: 'column', gap: 12, overflow: 'auto' }}>
        <textarea className="g-input" placeholder="Describe what you want to report on, paste alert data, or specify the audience…" value={input} onChange={e => setInput(e.target.value)} style={{ fontSize: 12, minHeight: 80, resize: 'vertical' }} />
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {actions.map(a => (
            <button key={a.id} className="g-btn g-btn-ghost" style={{ fontSize: 11, justifyContent: 'flex-start' }} onClick={() => ask(a.id)} disabled={loading}>{a.label}</button>
          ))}
        </div>
        {loading && <div style={{ fontSize: 12, color: 'var(--text-3)', textAlign: 'center', padding: 12 }}>Analyzing…</div>}
        {response && <div className="g-card" style={{ padding: 14, fontSize: 13, color: 'var(--text-1)', lineHeight: 1.7, whiteSpace: 'pre-wrap' }}>{response}</div>}
      </div>
    </div>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────
export default function CompliancePage() {
  const [tab, setTab] = useState<Tab>('dashboard');
  const [dash, setDash] = useState<any>(null);
  const [reports, setReports] = useState<any[]>([]);
  const [templates, setTemplates] = useState<any[]>([]);
  const [schedules, setSchedules] = useState<any[]>([]);
  const [executions, setExecutions] = useState<any[]>([]);
  const [analytics, setAnalytics] = useState<any>(null);
  const [audit, setAudit] = useState<any[]>([]);
  const [notifications, setNotifications] = useState<any[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [showAI, setShowAI] = useState(false);

  const loadAll = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const [d, r, t, s, e, an, au, n] = await Promise.all([
        rpeAPI.getDashboard(),
        rpeAPI.getReports(),
        rpeAPI.getTemplates(),
        rpeAPI.getSchedules(),
        rpeAPI.getExecutions(),
        rpeAPI.getAnalytics(),
        rpeAPI.getAudit(),
        rpeAPI.getNotifications(),
      ]);
      setDash(d.data);
      setReports((r.data as any) || []);
      setTemplates((t.data as any) || []);
      setSchedules((s.data as any) || []);
      setExecutions((e.data as any) || []);
      setAnalytics(an.data);
      setAudit((au.data as any) || []);
      setNotifications((n.data as any) || []);
    } finally { setRefreshing(false); }
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  const markRead = async () => {
    await rpeAPI.markNotificationsRead();
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
  };

  const unreadCount = notifications.filter(n => !n.read).length;

  return (
    <RootLayout
      title="Compliance & Reports"
      subtitle="Enterprise reporting platform — schedule, build, share and analyze security reports"
      onRefresh={() => loadAll(true)}
      refreshing={refreshing}
      actions={
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="g-btn g-btn-ghost" style={{ fontSize: 11 }} onClick={() => setShowAI(v => !v)}>📋 AI</button>
        </div>
      }
    >
      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', marginBottom: 20, overflowX: 'auto' }}>
        {TABS.map(t => {
          const badge = t.id === 'notifications' ? unreadCount : 0;
          return (
            <button key={t.id} onClick={() => setTab(t.id)} style={{
              padding: '10px 14px', fontSize: 12, fontWeight: tab === t.id ? 700 : 400,
              color: tab === t.id ? 'var(--accent)' : 'var(--text-2)',
              borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
              background: 'none', whiteSpace: 'nowrap', position: 'relative',
            }}>
              {t.label}
              {badge > 0 && (
                <span style={{ position: 'absolute', top: 6, right: 2, fontSize: 8, fontWeight: 700, background: '#ef4444', color: '#fff', borderRadius: 8, padding: '1px 4px', minWidth: 14, textAlign: 'center' }}>{badge}</span>
              )}
            </button>
          );
        })}
      </div>

      {tab === 'dashboard'     && <DashboardTab dash={dash} onTabChange={setTab} />}
      {tab === 'library'       && <LibraryTab reports={reports} onRefresh={() => loadAll()} />}
      {tab === 'builder'       && <BuilderTab templates={templates} onRefresh={() => loadAll()} />}
      {tab === 'scheduled'     && <ScheduledTab schedules={schedules} reports={reports} onRefresh={() => loadAll()} />}
      {tab === 'history'       && <HistoryTab executions={executions} />}
      {tab === 'analytics'     && <AnalyticsTab data={analytics} />}
      {tab === 'audit'         && <AuditTab items={audit} />}
      {tab === 'notifications' && <NotificationsTab items={notifications} onMarkRead={markRead} />}

      {showAI && <AIPanel onClose={() => setShowAI(false)} />}
    </RootLayout>
  );
}
