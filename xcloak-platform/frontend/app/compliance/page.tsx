'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { rpeAPI, exportAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import { MetricCard, DataTable, EmptyState, SectionCard, TabBar, ActionButton, Modal } from '@/components/design-system';
import {
  LayoutDashboard, Library, Wand2, CalendarClock, History, BarChart3, ScrollText, Bell,
  Sparkles, X, Plus, Play, Trash2, Save, Download, Pause, ChevronUp, ChevronDown,
  FileText, AlertTriangle, TrendingUp, CheckCircle2, Briefcase, ListChecks,
} from 'lucide-react';

type Tab = 'dashboard' | 'library' | 'builder' | 'scheduled' | 'history' | 'analytics' | 'audit' | 'notifications';
const TABS: { key: Tab; label: string; icon: any; count?: number }[] = [
  { key: 'dashboard',     label: 'Dashboard',       icon: LayoutDashboard },
  { key: 'library',       label: 'Report Library',  icon: Library },
  { key: 'builder',       label: 'Report Builder',  icon: Wand2 },
  { key: 'scheduled',     label: 'Scheduled',       icon: CalendarClock },
  { key: 'history',       label: 'History',         icon: History },
  { key: 'analytics',     label: 'Analytics',       icon: BarChart3 },
  { key: 'audit',         label: 'Audit Trail',     icon: ScrollText },
  { key: 'notifications', label: 'Notifications',   icon: Bell },
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

// ── Dashboard ──────────────────────────────────────────────────────────────
function DashboardTab({ dash }: { dash: any }) {
  if (!dash) return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>Loading…</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <MetricCard label="Total Reports"      value={dash.total_reports || 0}       color="var(--accent)" />
        <MetricCard label="Scheduled"          value={dash.scheduled_reports || 0}    color="#f97316" />
        <MetricCard label="Generated Today"    value={dash.generated_today || 0}      color="#22c55e" />
        <MetricCard label="Failed"             value={dash.failed_reports || 0}        color="#ef4444" />
        <MetricCard label="Templates"          value={dash.report_templates || 0}     color="#3b82f6" />
        <MetricCard label="Shared"             value={dash.shared_reports || 0}       color="#a855f7" />
        <MetricCard label="Exports"            value={dash.export_history || 0}       color="#06b6d4" />
        <MetricCard label="Storage Used"       value={bytes(dash.storage_bytes || 0)} color="#eab308" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
        <SectionCard title="Reports by Category">
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
        </SectionCard>

        <SectionCard title="Recent Executions">
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
        </SectionCard>

        <SectionCard title="Upcoming Schedules">
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
        </SectionCard>
      </div>

      {/* Quick actions */}
      <SectionCard title="Quick Exports">
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          {[
            { label: 'Alerts CSV', url: exportAPI.alertsCSV() },
            { label: 'Incidents CSV', url: exportAPI.incidentsCSV() },
            { label: 'Vulns CSV', url: exportAPI.vulnsCSV() },
            { label: 'Audit JSON', url: exportAPI.auditJSON() },
          ].map(e => (
            <a key={e.label} href={e.url} download className="g-btn g-btn-ghost" style={{ fontSize: 11 }}>
              <Download className="h-3.5 w-3.5" /> {e.label}
            </a>
          ))}
        </div>
      </SectionCard>
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
    try { await rpeAPI.deleteReport(id); onRefresh(); notify(`'${name}' deleted`); }
    catch { notify('Failed to delete report'); }
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
        <ActionButton variant="primary" icon={Plus} style={{ fontSize: 11, marginLeft: 'auto' }} onClick={() => setShowNew(true)}>New Report</ActionButton>
      </div>

      <DataTable<any>
        rows={filtered}
        rowKey={(r: any) => r.id}
        emptyState={<EmptyState title="No reports" message="Create one to get started." />}
        columns={[
          { key: 'report_id', header: 'Report ID', render: (r: any) => <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--accent)' }}>{r.report_id}</span> },
          { key: 'name', header: 'Name', render: (r: any) => (
            <div style={{ maxWidth: 200 }}>
              <div style={{ fontWeight: 600, fontSize: 13 }}>{r.name}</div>
              {r.description && <div style={{ fontSize: 11, color: 'var(--text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 180 }}>{r.description}</div>}
            </div>
          ) },
          { key: 'category', header: 'Category', render: (r: any) => { const cat = CATEGORIES[r.category]; return cat ? pill(cat.label, cat.color) : pill(r.category, '#6b7280'); } },
          { key: 'report_type', header: 'Type', render: (r: any) => <span style={{ fontSize: 11, color: 'var(--text-2)' }}>{r.report_type || '—'}</span> },
          { key: 'owner', header: 'Owner', render: (r: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{r.owner || '—'}</span> },
          { key: 'last_generated_at', header: 'Last Generated', render: (r: any) => <span style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{r.last_generated_at ? timeAgo(r.last_generated_at) : 'Never'}</span> },
          { key: 'generation_count', header: 'Generations', render: (r: any) => <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--accent)' }}>{r.generation_count}</span> },
          { key: 'status', header: 'Status', render: (r: any) => pill(r.status, STATUS_COLOR[r.status] || '#6b7280') },
          { key: 'tags', header: 'Tags', render: (r: any) => {
            let tags: string[] = [];
            try { tags = JSON.parse(r.tags || '[]'); } catch {}
            return (
              <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                {tags.slice(0, 2).map((t: string) => <span key={t} style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3, background: 'var(--border)', color: 'var(--text-3)' }}>{t}</span>)}
              </div>
            );
          } },
          { key: 'actions', header: '', render: (r: any) => (
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <ActionButton variant="ghost" icon={Play} style={{ fontSize: 10 }} onClick={() => gen(r.report_id, r.name)} disabled={generating === r.report_id}>
                {generating === r.report_id ? '…' : 'Run'}
              </ActionButton>
              <ActionButton variant="danger" icon={Trash2} onClick={() => del(r.id, r.name)} />
            </div>
          ) },
        ]}
      />

      <Modal open={showNew} onClose={() => setShowNew(false)} title="New Report" maxWidth={560}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, maxHeight: '60vh', overflow: 'auto' }}>
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
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', marginTop: 16 }}>
          <ActionButton variant="ghost" icon={X} onClick={() => setShowNew(false)}>Cancel</ActionButton>
          <ActionButton variant="primary" icon={Save} onClick={create} disabled={saving || !form.name}>{saving ? 'Creating…' : 'Create Report'}</ActionButton>
        </div>
      </Modal>
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
    try { await rpeAPI.deleteTemplate(id); onRefresh(); notify(`Template '${name}' deleted`); }
    catch { notify('Failed to delete template'); }
  };

  return (
    <div style={{ display: 'flex', gap: 20 }}>
      {/* Builder panel */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 14 }}>
        {toast && <div className="g-card" style={{ padding: '8px 14px', borderLeft: '3px solid var(--accent)', fontSize: 13 }}>{toast}</div>}

        <SectionCard title="Report Sections">
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
                <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                  <button style={{ color: 'var(--text-3)', padding: '0 2px', display: 'flex' }} onClick={() => moveUp(i)}><ChevronUp className="h-3.5 w-3.5" /></button>
                  <button style={{ color: 'var(--text-3)', padding: '0 2px', display: 'flex' }} onClick={() => moveDown(i)}><ChevronDown className="h-3.5 w-3.5" /></button>
                  <button style={{ color: '#ef4444', padding: '0 2px', display: 'flex' }} onClick={() => toggleSection(s)}><X className="h-3.5 w-3.5" /></button>
                </div>
              </div>
            ))}
          </div>
        </SectionCard>

        <SectionCard title="Data Sources">
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {DATA_SOURCES.map(ds => (
              <button key={ds} type="button" onClick={() => setSelectedSources(prev => prev.includes(ds) ? prev.filter(x => x !== ds) : [...prev, ds])} style={{ fontSize: 10, padding: '4px 10px', borderRadius: 8, background: selectedSources.includes(ds) ? '#22c55e22' : 'var(--border)', color: selectedSources.includes(ds) ? '#22c55e' : 'var(--text-3)', border: `1px solid ${selectedSources.includes(ds) ? '#22c55e44' : 'transparent'}` }}>
                {selectedSources.includes(ds) ? '✓ ' : ''}{ds}
              </button>
            ))}
          </div>
        </SectionCard>

        <SectionCard title="Company Branding">
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
        </SectionCard>

        <div style={{ display: 'flex', gap: 10 }}>
          <ActionButton variant="primary" icon={Save} style={{ fontSize: 11 }} onClick={() => setShowSaveTemplate(true)}>Save as Template</ActionButton>
        </div>
      </div>

      {/* Preview panel */}
      <div style={{ width: 320, flexShrink: 0 }}>
        <div style={{ position: 'sticky', top: 20 }}>
          <SectionCard title="Preview">
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
          </SectionCard>

          {/* Templates */}
          <SectionCard title={`Saved Templates (${templates.length})`} className="mt-4">
            {templates.length === 0 && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No templates yet</div>}
            {templates.map(t => (
              <div key={t.id} style={{ padding: '8px 0', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600 }}>{t.name}</div>
                  <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{t.is_builtin ? 'Built-in' : `Used ${t.use_count}×`}</div>
                </div>
                {!t.is_builtin && <ActionButton variant="danger" icon={Trash2} onClick={() => delTemplate(t.id, t.name)} />}
              </div>
            ))}
          </SectionCard>
        </div>
      </div>

      <Modal open={showSaveTemplate} onClose={() => setShowSaveTemplate(false)} title="Save Template" maxWidth={420}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
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
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', marginTop: 16 }}>
          <ActionButton variant="ghost" icon={X} onClick={() => setShowSaveTemplate(false)}>Cancel</ActionButton>
          <ActionButton variant="primary" icon={Save} onClick={saveTemplate} disabled={saving || !tplForm.name}>{saving ? 'Saving…' : 'Save Template'}</ActionButton>
        </div>
      </Modal>
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
    try { await rpeAPI.updateSchedule(id, { status: current === 'active' ? 'paused' : 'active' }); onRefresh(); }
    catch { notify('Failed to update schedule'); }
  };
  const del = async (id: number) => {
    try { await rpeAPI.deleteSchedule(id); onRefresh(); notify('Schedule deleted'); }
    catch { notify('Failed to delete schedule'); }
  };

  const FREQ_COLOR: Record<string, string> = { one_time: '#6b7280', hourly: '#3b82f6', daily: '#22c55e', weekly: '#a855f7', monthly: '#f97316', quarterly: '#eab308', yearly: '#06b6d4', cron: '#ef4444' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {toast && <div className="g-card" style={{ padding: '8px 14px', borderLeft: '3px solid var(--accent)', fontSize: 13 }}>{toast}</div>}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontSize: 13, color: 'var(--text-3)' }}>{schedules.length} scheduled reports</div>
        <ActionButton variant="primary" icon={Plus} style={{ fontSize: 11 }} onClick={() => setShowNew(true)}>New Schedule</ActionButton>
      </div>
      <DataTable<any>
        rows={schedules}
        rowKey={(s: any) => s.id}
        rowStyle={(s: any) => s.status === 'paused' ? { opacity: 0.6 } : undefined}
        emptyState={<EmptyState title="No schedules configured" />}
        columns={[
          { key: 'schedule_id', header: 'Schedule ID', render: (s: any) => <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--accent)' }}>{s.schedule_id}</span> },
          { key: 'report_name', header: 'Report', render: (s: any) => <span style={{ fontWeight: 600, fontSize: 12, maxWidth: 180, display: 'block' }}>{s.report_name}</span> },
          { key: 'frequency', header: 'Frequency', render: (s: any) => pill(s.frequency, FREQ_COLOR[s.frequency] || '#6b7280') },
          { key: 'delivery_method', header: 'Delivery', render: (s: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{s.delivery_method}</span> },
          { key: 'export_format', header: 'Format', render: (s: any) => <span style={{ fontSize: 11, textTransform: 'uppercase', color: 'var(--text-3)' }}>{s.export_format}</span> },
          { key: 'last_run_at', header: 'Last Run', render: (s: any) => <span style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{s.last_run_at ? timeAgo(s.last_run_at) : '—'}</span> },
          { key: 'next_run_at', header: 'Next Run', render: (s: any) => <span style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{s.next_run_at ? timeAgo(s.next_run_at) : '—'}</span> },
          { key: 'runs', header: 'Runs', render: (s: any) => (
            <span style={{ fontSize: 11, color: 'var(--text-2)' }}>
              <span style={{ color: '#22c55e' }}>✓{s.success_count}</span> / <span style={{ color: '#ef4444' }}>✗{s.failure_count}</span>
            </span>
          ) },
          { key: 'status', header: 'Status', render: (s: any) => pill(s.status, STATUS_COLOR[s.status] || '#6b7280') },
          { key: 'actions', header: '', render: (s: any) => (
            <div style={{ display: 'flex', gap: 6 }}>
              <ActionButton variant="ghost" icon={s.status === 'active' ? Pause : Play} style={{ fontSize: 10 }} onClick={() => toggle(s.id, s.status)}>{s.status === 'active' ? 'Pause' : 'Resume'}</ActionButton>
              <ActionButton variant="danger" icon={Trash2} onClick={() => del(s.id)} />
            </div>
          ) },
        ]}
      />

      <Modal open={showNew} onClose={() => setShowNew(false)} title="New Schedule" maxWidth={520}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
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
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', marginTop: 16 }}>
          <ActionButton variant="ghost" icon={X} onClick={() => setShowNew(false)}>Cancel</ActionButton>
          <ActionButton variant="primary" icon={Save} onClick={save} disabled={saving || !form.report_id}>{saving ? 'Saving…' : 'Create Schedule'}</ActionButton>
        </div>
      </Modal>
    </div>
  );
}

// ── History ────────────────────────────────────────────────────────────────
function HistoryTab({ executions }: { executions: any[] }) {
  return (
    <DataTable<any>
      rows={executions}
      rowKey={(e: any) => e.id}
      emptyState={<EmptyState title="No execution history" />}
      columns={[
        { key: 'execution_id', header: 'Execution ID', render: (e: any) => <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--accent)' }}>{e.execution_id}</span> },
        { key: 'report_name', header: 'Report', render: (e: any) => <span style={{ fontWeight: 600, fontSize: 12, maxWidth: 180, display: 'block' }}>{e.report_name}</span> },
        { key: 'status', header: 'Status', render: (e: any) => pill(e.status, STATUS_COLOR[e.status] || '#6b7280') },
        { key: 'export_format', header: 'Format', render: (e: any) => <span style={{ fontSize: 11, color: 'var(--text-2)', textTransform: 'uppercase' }}>{e.export_format}</span> },
        { key: 'triggered_by', header: 'Triggered By', render: (e: any) => <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{e.triggered_by}</span> },
        { key: 'executed_by', header: 'Executed By', render: (e: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{e.executed_by}</span> },
        { key: 'duration_ms', header: 'Duration', render: (e: any) => <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{e.duration_ms ? `${(e.duration_ms / 1000).toFixed(1)}s` : '—'}</span> },
        { key: 'file_size_bytes', header: 'Size', render: (e: any) => <span style={{ fontSize: 11, color: 'var(--text-2)' }}>{bytes(e.file_size_bytes || 0)}</span> },
        { key: 'started_at', header: 'Started', render: (e: any) => <span style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(e.started_at)}</span> },
        { key: 'download_url', header: '', render: (e: any) => (
          e.download_url ? (
            <a href={e.download_url} className="g-btn g-btn-ghost" style={{ fontSize: 10, padding: '2px 8px' }}>
              <Download className="h-3 w-3" /> Download
            </a>
          ) : null
        ) },
      ]}
    />
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
        <MetricCard label="Total Executions"  value={data.total_executions || 0}  color="var(--accent)" />
        <MetricCard label="Successful"        value={data.success_executions || 0} color="#22c55e" />
        <MetricCard label="Failed"            value={data.failed_executions || 0}  color="#ef4444" />
        <MetricCard label="Success Rate"      value={`${data.success_rate || 0}%`} color={successRate >= 90 ? '#22c55e' : successRate >= 70 ? '#eab308' : '#ef4444'} />
        <MetricCard label="Avg Duration"      value={data.avg_duration_ms ? `${(data.avg_duration_ms / 1000).toFixed(1)}s` : '—'} color="#3b82f6" />
        <MetricCard label="Storage Used"      value={bytes(data.storage_bytes || 0)} color="#a855f7" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <SectionCard title="Most Generated Reports">
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
        </SectionCard>

        <SectionCard title="Exports by Format">
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
        </SectionCard>
      </div>
    </div>
  );
}

// ── Audit Trail ────────────────────────────────────────────────────────────
function AuditTab({ items }: { items: any[] }) {
  return (
    <SectionCard padded={false}>
      <DataTable<any>
        rows={items}
        rowKey={(a: any) => a.id}
        emptyState={<EmptyState title="No audit events" />}
        columns={[
          { key: 'created_at', header: 'Time', render: (a: any) => <span style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{timeAgo(a.created_at)}</span> },
          { key: 'action', header: 'Action', render: (a: any) => pill(a.action, AUDIT_COLOR[a.action] || '#6b7280') },
          { key: 'object_type', header: 'Object Type', render: (a: any) => <span style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'capitalize' }}>{(a.object_type || '').replace(/_/g, ' ')}</span> },
          { key: 'object_name', header: 'Object Name', render: (a: any) => <span style={{ fontSize: 12, fontWeight: 500 }}>{a.object_name || a.object_id || '—'}</span> },
          { key: 'actor', header: 'Actor', render: (a: any) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{a.actor}</span> },
          { key: 'details', header: 'Details', render: (a: any) => <span style={{ fontSize: 11, color: 'var(--text-3)', fontStyle: 'italic', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>{a.details || '—'}</span> },
        ]}
      />
    </SectionCard>
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
        {unread > 0 && <ActionButton variant="ghost" style={{ fontSize: 11 }} onClick={onMarkRead}>Mark all read</ActionButton>}
      </div>
      {items.length === 0 && <EmptyState title="No notifications" />}
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
    { id: 'generate_report',      label: 'Generate Report',          icon: FileText },
    { id: 'summarize_findings',   label: 'Summarize Findings',       icon: ListChecks },
    { id: 'highlight_risks',      label: 'Highlight Critical Risks', icon: AlertTriangle },
    { id: 'explain_trends',       label: 'Explain Security Trends',  icon: TrendingUp },
    { id: 'recommend_actions',    label: 'Recommend Actions',        icon: CheckCircle2 },
    { id: 'executive_summary',    label: 'Executive Summary',        icon: Briefcase },
  ];
  const ask = async (action: string) => {
    setLoading(true);
    try { const r = await rpeAPI.ai({ action, context: input }); setResponse((r.data as any)?.response || ''); }
    catch { setResponse('AI unavailable.'); } finally { setLoading(false); }
  };
  return (
    <div style={{ position: 'fixed', top: 0, right: 0, bottom: 0, width: 460, background: 'var(--glass-bg)', borderLeft: '1px solid var(--border)', zIndex: 100, display: 'flex', flexDirection: 'column', boxShadow: '-4px 0 24px rgba(0,0,0,0.3)' }}>
      <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span className="flex items-center gap-2" style={{ fontWeight: 700, fontSize: 14 }}>
          <Sparkles className="h-4 w-4" style={{ color: 'var(--accent)' }} /> Reports AI Assistant
        </span>
        <ActionButton variant="ghost" icon={X} onClick={onClose} />
      </div>
      <div style={{ padding: 16, flex: 1, display: 'flex', flexDirection: 'column', gap: 12, overflow: 'auto' }}>
        <textarea className="g-input" placeholder="Describe what you want to report on, paste alert data, or specify the audience…" value={input} onChange={e => setInput(e.target.value)} style={{ fontSize: 12, minHeight: 80, resize: 'vertical' }} />
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {actions.map(a => (
            <ActionButton key={a.id} variant="ghost" icon={a.icon} style={{ fontSize: 11, justifyContent: 'flex-start' }} onClick={() => ask(a.id)} disabled={loading}>{a.label}</ActionButton>
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
    try {
      await rpeAPI.markNotificationsRead();
      setNotifications(prev => prev.map(n => ({ ...n, read: true })));
    } catch { /* non-critical, next load will reflect real state */ }
  };

  const unreadCount = notifications.filter(n => !n.read).length;
  const tabsWithCount = TABS.map(t => t.key === 'notifications' ? { ...t, count: unreadCount || undefined } : t);

  return (
    <RootLayout
      title="Compliance & Reports"
      subtitle="Enterprise reporting platform — schedule, build, share and analyze security reports"
      onRefresh={() => loadAll(true)}
      refreshing={refreshing}
      actions={
        <ActionButton variant="ghost" icon={Sparkles} style={{ fontSize: 11 }} onClick={() => setShowAI(v => !v)}>AI Assistant</ActionButton>
      }
    >
      {/* Tab bar */}
      <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: 2, marginBottom: 20, overflowX: 'auto' }}>
        <TabBar tabs={tabsWithCount} active={tab} onChange={k => setTab(k as Tab)} />
      </div>

      {tab === 'dashboard'     && <DashboardTab dash={dash} />}
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
