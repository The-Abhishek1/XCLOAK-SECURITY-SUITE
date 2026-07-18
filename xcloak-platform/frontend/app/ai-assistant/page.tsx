'use client';
import { useState, useEffect, useRef } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { aiaAPI } from '@/lib/api';

/* ── colour helpers ───────────────────────────────────────────────────────── */
const PILL_COLORS: Record<string, string> = {
  critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#65a30d',
  info: '#2563eb', open: '#dc2626', accepted: '#16a34a', dismissed: '#6b7280',
  pending_approval: '#d97706', approved: '#16a34a', rejected: '#dc2626',
  executed: '#16a34a', active: '#16a34a', completed: '#6b7280',
  chat: '#2563eb', investigate: '#7c3aed', copilot: '#0891b2',
  automation: '#ea580c', executive: '#be185d', general: '#6b7280',
  detection: '#dc2626', threat_intel: '#7c3aed', compliance: '#0891b2',
  connected: '#16a34a', partial: '#d97706', pending: '#6b7280',
};
function pill(label: string, color?: string) {
  const bg = color ?? PILL_COLORS[label?.toLowerCase()] ?? '#6b7280';
  return (
    <span style={{
      background: bg + '22', color: bg, border: `1px solid ${bg}55`,
      borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600,
      textTransform: 'uppercase', letterSpacing: 0.5, whiteSpace: 'nowrap',
    }}>{label}</span>
  );
}

function StatCard({ label, value, sub, color }: { label: string; value: any; sub?: string; color?: string }) {
  return (
    <div className="g-card" style={{ padding: '18px 22px', minWidth: 140 }}>
      <div style={{ fontSize: 28, fontWeight: 700, color: color ?? 'var(--accent)' }}>{value}</div>
      <div style={{ fontSize: 13, color: 'var(--text-2)', marginTop: 2 }}>{label}</div>
      {sub && <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

/* ── simple markdown renderer ─────────────────────────────────────────────── */
function MarkdownBlock({ content }: { content: string }) {
  const lines = content.split('\n');
  return (
    <div style={{ fontSize: 13 }}>
      {lines.map((line, i) => {
        if (line.startsWith('### ')) return <h3 key={i} style={{ color: 'var(--accent)', margin: '12px 0 6px', fontSize: 14 }}>{line.slice(4)}</h3>;
        if (line.startsWith('## ')) return <h2 key={i} style={{ color: 'var(--text-1)', margin: '14px 0 8px', fontSize: 16, fontWeight: 700 }}>{line.slice(3)}</h2>;
        if (line.startsWith('# ')) return <h1 key={i} style={{ color: 'var(--text-1)', margin: '14px 0 8px', fontSize: 18, fontWeight: 700 }}>{line.slice(2)}</h1>;
        if (line.startsWith('---')) return <hr key={i} style={{ border: 'none', borderTop: '1px solid var(--border)', margin: '8px 0' }} />;
        if (line.startsWith('- ') || line.startsWith('→ ') || line.match(/^\d+\. /)) {
          return <p key={i} style={{ margin: '3px 0', paddingLeft: 16, color: 'var(--text-2)' }}>{line}</p>;
        }
        if (line.startsWith('| ')) {
          return <p key={i} style={{ margin: '2px 0', fontFamily: 'monospace', fontSize: 12, color: 'var(--text-2)' }}>{line}</p>;
        }
        if (line.startsWith('```') || line.startsWith('`')) {
          return <code key={i} style={{ display: 'block', background: 'var(--bg-1)', borderRadius: 4, padding: '2px 8px', fontSize: 12, color: 'var(--accent)', margin: '4px 0' }}>{line.replace(/`/g, '')}</code>;
        }
        if (line === '') return <div key={i} style={{ margin: '6px 0' }} />;
        return <p key={i} style={{ margin: '4px 0', color: 'var(--text-2)', lineHeight: 1.6 }}>{line}</p>;
      })}
    </div>
  );
}

/* ── constants ────────────────────────────────────────────────────────────── */
const TABS = [
  { id: 'dashboard',       label: 'Dashboard' },
  { id: 'chat',            label: 'AI Chat' },
  { id: 'investigate',     label: 'Investigate' },
  { id: 'copilot',         label: 'Copilot' },
  { id: 'recommendations', label: 'Recommendations' },
  { id: 'automation',      label: 'Automation' },
  { id: 'insights',        label: 'Insights' },
  { id: 'actions',         label: 'Actions' },
  { id: 'prompts',         label: 'Prompt Library' },
  { id: 'analytics',       label: 'Analytics' },
  { id: 'reports',         label: 'Reports' },
  { id: 'audit',           label: 'Audit Trail' },
];

const MODE_OPTIONS = [
  { id: 'chat',         label: 'General Chat',          desc: 'Ask anything about your security environment' },
  { id: 'investigate',  label: 'Investigation',         desc: 'Deep-dive incident and threat analysis' },
  { id: 'copilot',      label: 'Security Copilot',      desc: 'Explain alerts, rules, logs, playbooks' },
  { id: 'automation',   label: 'Automation Assistant',  desc: 'Generate Sigma, YARA, SOAR, scripts' },
  { id: 'executive',    label: 'Executive Assistant',   desc: 'Board-ready reports and risk summaries' },
  { id: 'threat_intel', label: 'Threat Intelligence',   desc: 'IOC lookups, actor profiles, MITRE mapping' },
];

const TEMPLATE_PROMPTS: Record<string, string[]> = {
  chat:        ['Show current threat summary', 'What happened in the last 24 hours?', 'Compare this week vs last week'],
  investigate: ['Why did WKSTN-FIN-047 trigger a ransomware alert?', 'Trace the attack chain for INC-2025-0892', 'What is the root cause of the Finance breach attempt?'],
  copilot:     ['Explain this Sigma rule', 'What does this log entry mean?', 'Describe the MITRE T1566.001 technique', 'Summarize this playbook'],
  automation:  ['Generate a Sigma rule for PowerShell-spawned malware', 'Write a YARA rule for Cobalt Strike beacons', 'Create a SOAR playbook for ransomware response'],
  executive:   ['Write a board-ready executive summary for this month', 'What is our current risk exposure?', 'Quantify the ROI of our security investments'],
  threat_intel:['What is the LockBit 3.0 threat profile?', 'Show all IOCs from last 30 days', 'Map our recent incidents to MITRE ATT&CK'],
};

const COPILOT_TEMPLATES = [
  { label: 'Explain Alert',    prompt: 'Explain this security alert: ' },
  { label: 'Decode Log',       prompt: 'Decode and explain this log entry: ' },
  { label: 'MITRE Technique',  prompt: 'Explain MITRE ATT&CK technique T1' },
  { label: 'Rule Explanation', prompt: 'Explain this detection rule: ' },
  { label: 'Script Analysis',  prompt: 'Analyze this script for malicious behavior: ' },
  { label: 'Playbook Summary', prompt: 'Summarize this playbook: ' },
];

const AUTOMATION_TEMPLATES = [
  { label: 'Sigma Rule',    prompt: 'Generate a Sigma rule for: ' },
  { label: 'YARA Rule',     prompt: 'Generate a YARA rule to detect: ' },
  { label: 'SOAR Playbook', prompt: 'Generate a SOAR playbook for: ' },
  { label: 'Firewall Rule', prompt: 'Generate firewall rules to block: ' },
  { label: 'KQL Query',     prompt: 'Generate a KQL query to find: ' },
  { label: 'Python Script', prompt: 'Write a Python security script to: ' },
];

const CONNECTED_SOURCES = [
  { name: 'Elastic SIEM',       type: 'siem',         status: 'connected', data: '1.2M events/day' },
  { name: 'CrowdStrike EDR',    type: 'edr',          status: 'connected', data: '419 endpoints' },
  { name: 'Palo Alto Firewall', type: 'firewall',     status: 'connected', data: '847K flows/hr' },
  { name: 'Qualys VMDR',        type: 'vuln',         status: 'connected', data: '2,847 vulns' },
  { name: 'VirusTotal',         type: 'threat_intel', status: 'connected', data: 'IOC lookups' },
  { name: 'MITRE ATT&CK',       type: 'threat_intel', status: 'connected', data: 'v14 framework' },
  { name: 'CMDB / Assets',      type: 'cmdb',         status: 'connected', data: '2,847 assets' },
  { name: 'MDM (Mobile)',       type: 'mdm',          status: 'connected', data: '427 devices' },
  { name: 'Azure AD',           type: 'identity',     status: 'connected', data: '1,248 users' },
  { name: 'ServiceNow',         type: 'ticketing',    status: 'connected', data: 'Ticket sync' },
  { name: 'Anthropic Claude',   type: 'llm',          status: 'connected', data: 'claude-sonnet-4-6' },
  { name: 'OpenAI GPT-4o',      type: 'llm',          status: 'connected', data: 'GPT-4o-mini' },
  { name: 'Google Gemini',      type: 'llm',          status: 'partial',   data: 'gemini-1.5-pro' },
  { name: 'Ollama (Local)',      type: 'llm',          status: 'pending',   data: 'llama3.1:70b' },
];

const INSIGHTS_DATA = [
  { title: 'Detection Gap: Lateral Movement via RDP',       severity: 'critical', description: 'No detection rules covering RDP lateral movement from non-admin workstations. 3 incidents last month were discovered only through EDR telemetry.', recommendation: 'Deploy Sigma rule: Lateral_Movement_RDP_Unusual_Source' },
  { title: 'Anomaly: Finance Team Working Outside Hours',    severity: 'high',     description: '8 Finance users accessed sensitive systems between 02:00-05:00 UTC over the last 2 weeks. This is 340% above baseline.', recommendation: 'Review authentication logs, check for credential sharing or compromise' },
  { title: 'Attack Pattern: Living-off-the-Land Increasing', severity: 'high',     description: 'LOLBin usage (certutil, mshta, wscript, regsvr32) has increased 67% month-over-month. Possible pre-attack reconnaissance.', recommendation: 'Enable LOLBin execution logging, create detection rules for abuse patterns' },
  { title: 'Coverage Gap: macOS Endpoints Missing EDR',      severity: 'medium',   description: '34 macOS endpoints (Engineering team) have no EDR coverage. These represent 8% of the estate but 0% visibility.', recommendation: 'Deploy CrowdStrike Falcon for Mac to all 34 devices within 14 days' },
  { title: 'Compliance Risk: MFA Not Enforced — 23 Accounts',severity: 'high',     description: 'Active Directory shows 23 privileged accounts without MFA enforcement, including 3 Domain Admin accounts.', recommendation: 'Enforce MFA for all privileged accounts immediately via Azure AD Conditional Access' },
];

/* ── component ────────────────────────────────────────────────────────────── */
export default function AIAssistantEnterprise() {
  const [tab, setTab]         = useState('dashboard');
  const [data, setData]       = useState<any>({});
  const [loading, setLoading] = useState(true);

  const [chatMode, setChatMode]         = useState('chat');
  const [chatInput, setChatInput]       = useState('');
  const [chatSession, setChatSession]   = useState('');
  const [messages, setMessages]         = useState<any[]>([]);
  const [sending, setSending]           = useState(false);
  const [sessions, setSessions]         = useState<any[]>([]);
  const chatEndRef = useRef<HTMLDivElement>(null);

  const [promptTitle, setPromptTitle]     = useState('');
  const [promptContent, setPromptContent] = useState('');
  const [promptCat, setPromptCat]         = useState('general');
  const [savingPrompt, setSavingPrompt]   = useState(false);

  const [reportTitle, setReportTitle] = useState('');
  const [reportType, setReportType]   = useState('executive_summary');
  const [genReport, setGenReport]     = useState(false);

  async function loadAll() {
    setLoading(true);
    const [dash, recs, actions, prompts, analytics, reports, audit, sess] = await Promise.all([
      aiaAPI.getDashboard(),
      aiaAPI.getRecommendations(),
      aiaAPI.getActions(),
      aiaAPI.getPrompts(),
      aiaAPI.getAnalytics(),
      aiaAPI.getReports(),
      aiaAPI.getAudit(),
      aiaAPI.getSessions(),
    ]);
    setData({
      dashboard:       dash?.data ?? null,
      recommendations: Array.isArray(recs?.data)     ? recs.data     : [],
      actions:         Array.isArray(actions?.data)   ? actions.data  : [],
      prompts:         Array.isArray(prompts?.data)   ? prompts.data  : [],
      analytics:       analytics?.data ?? null,
      reports:         Array.isArray(reports?.data)   ? reports.data  : [],
      audit:           Array.isArray(audit?.data)     ? audit.data    : [],
    });
    setSessions(Array.isArray(sess?.data) ? sess.data : []);
    setLoading(false);
  }

  useEffect(() => { loadAll(); }, []);
  useEffect(() => { chatEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  async function sendMessage(text?: string) {
    const msg = (text ?? chatInput).trim();
    if (!msg || sending) return;
    setChatInput('');
    setSending(true);
    setMessages(prev => [...prev, { role: 'user', content: msg, created_at: new Date().toISOString() }]);
    try {
      const res = await aiaAPI.chat({ session_id: chatSession, message: msg, mode: chatMode });
      if (res?.data?.session_id) setChatSession(res.data.session_id);
      setMessages(prev => [...prev, { role: 'assistant', content: res?.data?.response ?? 'No response.', created_at: new Date().toISOString() }]);
    } catch {
      setMessages(prev => [...prev, { role: 'assistant', content: 'Error getting response.', created_at: new Date().toISOString() }]);
    }
    setSending(false);
  }

  async function loadSession(s: any) {
    setChatSession(s.session_id);
    setChatMode(s.mode ?? 'chat');
    try {
      const res = await aiaAPI.getMessages(s.session_id);
      setMessages(Array.isArray(res?.data) ? res.data : []);
    } catch { setMessages([]); }
    setTab('chat');
  }

  function startNewChat(mode?: string) {
    setChatSession('');
    setMessages([]);
    if (mode) setChatMode(mode);
    setTab('chat');
  }

  async function savePrompt() {
    if (!promptTitle || !promptContent) return;
    setSavingPrompt(true);
    try {
      await aiaAPI.createPrompt({ title: promptTitle, content: promptContent, category: promptCat, is_template: true });
      setPromptTitle(''); setPromptContent(''); setPromptCat('general');
      loadAll();
    } finally { setSavingPrompt(false); }
  }

  async function genReportFn() {
    if (!reportTitle) return;
    setGenReport(true);
    try {
      await aiaAPI.generateReport({ title: reportTitle, report_type: reportType });
      setReportTitle('');
      loadAll();
    } finally { setGenReport(false); }
  }

  const d = data.dashboard;

  return (
    <RootLayout>
      <div style={{ padding: '24px 32px', minHeight: '100vh', background: 'var(--bg-1)' }}>
        {/* header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-1)', margin: 0 }}>AI Security Assistant</h1>
            <p style={{ color: 'var(--text-3)', fontSize: 13, margin: '4px 0 0' }}>
              Agentic AI copilot — investigation · detection · automation · executive intelligence
            </p>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="g-btn-ghost" onClick={() => startNewChat('chat')}>+ New Chat</button>
            <button className="g-btn-ghost" onClick={() => startNewChat('investigate')}>+ Investigate</button>
            <button className="g-btn" onClick={loadAll}>Refresh</button>
          </div>
        </div>

        {/* tab bar */}
        <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', marginBottom: 24, overflowX: 'auto' }}>
          {TABS.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)} style={{
              background: 'none', border: 'none', padding: '10px 16px', cursor: 'pointer',
              fontSize: 13, fontWeight: tab === t.id ? 600 : 400,
              color: tab === t.id ? 'var(--accent)' : 'var(--text-2)',
              borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
              marginBottom: -1, whiteSpace: 'nowrap',
            }}>{t.label}</button>
          ))}
        </div>

        {loading ? (
          <div style={{ color: 'var(--text-3)', padding: 40, textAlign: 'center' }}>Loading…</div>
        ) : (
          <>
            {/* ── DASHBOARD ───────────────────────────────────────────────── */}
            {tab === 'dashboard' && (
              <div>
                <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 24 }}>
                  <StatCard label="Total Sessions"       value={d?.total_sessions ?? 0} />
                  <StatCard label="Messages Sent"        value={d?.total_messages ?? 0} />
                  <StatCard label="Saved Prompts"        value={d?.saved_prompts ?? 0} />
                  <StatCard label="Open Recommendations" value={d?.open_recommendations ?? 0} color="#ea580c" />
                  <StatCard label="Pending Actions"      value={d?.pending_actions ?? 0}       color="#d97706" />
                  <StatCard label="Connected Sources"    value={d?.connected_sources ?? 0}     color="#16a34a" />
                  <StatCard label="Health Score"         value={`${d?.health_score ?? 0}%`}    color="#16a34a" />
                  <StatCard label="Hours Saved"          value={d?.stats?.analyst_hours_saved ?? 0} sub="this month" color="#7c3aed" />
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>
                  <div className="g-card">
                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Recent Sessions</div>
                    <table className="g-table" style={{ width: '100%' }}>
                      <thead><tr><th>Title</th><th>Mode</th><th>Msgs</th><th>Status</th></tr></thead>
                      <tbody>
                        {(d?.recent_sessions ?? []).map((s: any, i: number) => (
                          <tr key={i} style={{ cursor: 'pointer' }} onClick={() => loadSession(s)}>
                            <td style={{ color: 'var(--accent)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.title}</td>
                            <td>{pill(s.mode)}</td>
                            <td>{s.message_count}</td>
                            <td>{pill(s.status)}</td>
                          </tr>
                        ))}
                        {!d?.recent_sessions?.length && <tr><td colSpan={4} style={{ color: 'var(--text-3)', textAlign: 'center', padding: 20 }}>No sessions yet — start a new chat</td></tr>}
                      </tbody>
                    </table>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                    <div className="g-card">
                      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 12, color: 'var(--text-1)' }}>Quick Start</div>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                        {MODE_OPTIONS.map(m => (
                          <button key={m.id} className="g-btn-ghost" onClick={() => startNewChat(m.id)}
                            style={{ textAlign: 'left', padding: '10px 12px', height: 'auto' }}>
                            <div style={{ fontWeight: 600, fontSize: 12 }}>{m.label}</div>
                            <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>{m.desc}</div>
                          </button>
                        ))}
                      </div>
                    </div>

                    <div className="g-card">
                      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 12, color: 'var(--text-1)' }}>Automation Stats</div>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                        {[
                          ['Automation Rate', `${d?.stats?.automation_rate ?? 34}%`],
                          ['Queries/Today', d?.stats?.queries_today ?? 48],
                          ['Actions Run', d?.stats?.actions_executed ?? 89],
                          ['Success Rate', `${d?.stats?.success_rate ?? 97}%`],
                        ].map(([l, v]) => (
                          <div key={String(l)} style={{ background: 'var(--bg-2)', borderRadius: 6, padding: '10px 14px' }}>
                            <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--accent)' }}>{v}</div>
                            <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{l}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>

                <div className="g-card">
                  <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Top Prompts</div>
                  <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                    {(d?.top_prompts ?? []).map((p: any, i: number) => (
                      <button key={i} className="g-btn-ghost" onClick={() => { setChatInput(p.title); setTab('chat'); }}
                        style={{ fontSize: 12, padding: '6px 12px' }}>
                        {p.title} <span style={{ color: 'var(--text-3)', marginLeft: 6 }}>{p.usage_count}×</span>
                      </button>
                    ))}
                    {!d?.top_prompts?.length && <span style={{ color: 'var(--text-3)', fontSize: 13 }}>No prompts saved yet — visit Prompt Library to add some</span>}
                  </div>
                </div>
              </div>
            )}

            {/* ── CHAT ──────────────────────────────────────────────────────── */}
            {tab === 'chat' && (
              <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: 20, height: 'calc(100vh - 210px)' }}>
                {/* sidebar */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12, minHeight: 0 }}>
                  <div className="g-card" style={{ padding: 12 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-3)', marginBottom: 8 }}>MODE</div>
                    {MODE_OPTIONS.map(m => (
                      <button key={m.id} onClick={() => setChatMode(m.id)} style={{
                        display: 'block', width: '100%', textAlign: 'left', padding: '8px 10px',
                        background: chatMode === m.id ? 'var(--accent)22' : 'none',
                        border: chatMode === m.id ? '1px solid var(--accent)55' : '1px solid transparent',
                        borderRadius: 6, cursor: 'pointer', marginBottom: 4,
                        color: 'var(--text-1)', fontSize: 12, fontWeight: 600,
                      }}>{m.label}</button>
                    ))}
                  </div>

                  <div className="g-card" style={{ padding: 12, overflow: 'auto', flex: 1, minHeight: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-3)' }}>HISTORY</div>
                      <button className="g-btn-ghost" onClick={() => { setChatSession(''); setMessages([]); }}
                        style={{ fontSize: 11, padding: '2px 8px' }}>New</button>
                    </div>
                    {sessions.slice(0, 20).map((s: any, i: number) => (
                      <div key={i} onClick={() => loadSession(s)} style={{
                        padding: '8px 10px', borderRadius: 6, cursor: 'pointer', marginBottom: 4,
                        background: chatSession === s.session_id ? 'var(--accent)22' : 'transparent',
                        border: `1px solid ${chatSession === s.session_id ? 'var(--accent)55' : 'transparent'}`,
                      }}>
                        <div style={{ fontSize: 12, color: 'var(--text-1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.title}</div>
                        <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{s.mode} · {s.message_count} msgs</div>
                      </div>
                    ))}
                    {!sessions.length && <div style={{ color: 'var(--text-3)', fontSize: 12, textAlign: 'center', padding: 16 }}>No history</div>}
                  </div>
                </div>

                {/* main chat */}
                <div className="g-card" style={{ display: 'flex', flexDirection: 'column', padding: 0, overflow: 'hidden', minHeight: 0 }}>
                  <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 12 }}>
                    <div style={{ flex: 1 }}>
                      <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-1)' }}>
                        {MODE_OPTIONS.find(m => m.id === chatMode)?.label ?? 'AI Chat'}
                      </span>
                      <span style={{ fontSize: 12, color: 'var(--text-3)', marginLeft: 12 }}>
                        claude-sonnet-4-6 · {messages.length} messages
                      </span>
                    </div>
                    {chatSession && (
                      <button className="g-btn-ghost" style={{ fontSize: 11 }}
                        onClick={() => { setChatSession(''); setMessages([]); }}>Clear</button>
                    )}
                  </div>

                  {/* messages */}
                  <div style={{ flex: 1, overflow: 'auto', padding: 18 }}>
                    {!messages.length && (
                      <div style={{ color: 'var(--text-3)', textAlign: 'center', marginTop: 60 }}>
                        <div style={{ fontSize: 36, marginBottom: 12 }}>◉</div>
                        <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-2)', marginBottom: 8 }}>
                          {MODE_OPTIONS.find(m => m.id === chatMode)?.label}
                        </div>
                        <div style={{ fontSize: 13, marginBottom: 24 }}>
                          {MODE_OPTIONS.find(m => m.id === chatMode)?.desc}
                        </div>
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'center' }}>
                          {(TEMPLATE_PROMPTS[chatMode] ?? []).map((p, i) => (
                            <button key={i} className="g-btn-ghost" onClick={() => sendMessage(p)}
                              style={{ fontSize: 12 }}>{p}</button>
                          ))}
                        </div>
                      </div>
                    )}
                    {messages.map((m: any, i: number) => (
                      <div key={i} style={{ marginBottom: 18, display: 'flex', flexDirection: m.role === 'user' ? 'row-reverse' : 'row', gap: 12 }}>
                        <div style={{
                          width: 32, height: 32, borderRadius: '50%', flexShrink: 0,
                          background: m.role === 'user' ? 'var(--accent)' : '#7c3aed',
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          fontSize: 13, fontWeight: 700, color: '#fff',
                        }}>{m.role === 'user' ? 'U' : 'AI'}</div>
                        <div style={{ maxWidth: '75%' }}>
                          <div style={{
                            background: m.role === 'user' ? 'var(--accent)' : 'var(--bg-2)',
                            color: m.role === 'user' ? '#fff' : 'var(--text-1)',
                            borderRadius: m.role === 'user' ? '16px 16px 4px 16px' : '16px 16px 16px 4px',
                            padding: '12px 16px',
                          }}>
                            {m.role === 'user'
                              ? <p style={{ margin: 0, fontSize: 13 }}>{m.content}</p>
                              : <MarkdownBlock content={m.content} />
                            }
                          </div>
                          <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4, textAlign: m.role === 'user' ? 'right' : 'left' }}>
                            {m.created_at ? new Date(m.created_at).toLocaleTimeString() : ''}
                          </div>
                        </div>
                      </div>
                    ))}
                    {sending && (
                      <div style={{ display: 'flex', gap: 12, marginBottom: 12 }}>
                        <div style={{ width: 32, height: 32, borderRadius: '50%', background: '#7c3aed', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 13, fontWeight: 700, color: '#fff' }}>AI</div>
                        <div style={{ background: 'var(--bg-2)', borderRadius: '16px 16px 16px 4px', padding: '14px 18px', color: 'var(--text-3)', fontSize: 13 }}>
                          Analyzing… ◌
                        </div>
                      </div>
                    )}
                    <div ref={chatEndRef} />
                  </div>

                  {/* template shortcuts */}
                  <div style={{ padding: '8px 18px', borderTop: '1px solid var(--border)', display: 'flex', gap: 6, overflowX: 'auto' }}>
                    {(TEMPLATE_PROMPTS[chatMode] ?? []).map((p, i) => (
                      <button key={i} className="g-btn-ghost" onClick={() => sendMessage(p)}
                        style={{ fontSize: 11, padding: '4px 10px', whiteSpace: 'nowrap', flexShrink: 0 }}>{p}</button>
                    ))}
                  </div>

                  {/* input */}
                  <div style={{ padding: '12px 18px', borderTop: '1px solid var(--border)', display: 'flex', gap: 10 }}>
                    <input className="g-input" value={chatInput} onChange={e => setChatInput(e.target.value)}
                      onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } }}
                      placeholder={`Ask the ${MODE_OPTIONS.find(m => m.id === chatMode)?.label ?? 'AI'}…`}
                      style={{ flex: 1, padding: '10px 14px' }} disabled={sending} />
                    <button className="g-btn" onClick={() => sendMessage()} disabled={sending || !chatInput.trim()}
                      style={{ padding: '10px 20px', flexShrink: 0 }}>Send</button>
                  </div>
                </div>
              </div>
            )}

            {/* ── INVESTIGATE ─────────────────────────────────────────────── */}
            {tab === 'investigate' && (
              <div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>
                  <div className="g-card">
                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Investigation Assistant</div>
                    <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 14 }}>
                      Deep-dive analysis of incidents, alerts, and threat activity. The AI correlates data across SIEM, EDR, Firewall, and Threat Intel.
                    </p>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      {[
                        'Why did WKSTN-FIN-047 trigger a ransomware alert?',
                        'Trace the full attack chain for the June 28 incident',
                        'Show all failed logins from Finance laptops, last 24h',
                        'What endpoints communicated with 185.220.101.44?',
                        'Investigate INC-2025-0892 root cause',
                      ].map((q, i) => (
                        <button key={i} className="g-btn-ghost"
                          onClick={() => { setChatMode('investigate'); setChatInput(q); setTab('chat'); }}
                          style={{ textAlign: 'left', fontSize: 12 }}>{q}</button>
                      ))}
                    </div>
                  </div>

                  <div className="g-card">
                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Active Investigations</div>
                    {[
                      { id: 'INC-2025-0892', title: 'Ransomware Attempt — Finance Workstation', status: 'active', severity: 'critical', progress: 78 },
                      { id: 'INC-2025-0891', title: 'Lateral Movement Detected — VLAN-CORP',    status: 'active', severity: 'high',     progress: 45 },
                      { id: 'INC-2025-0884', title: 'Data Exfiltration Attempt — Salesforce',   status: 'completed', severity: 'medium', progress: 100 },
                    ].map((inv, i) => (
                      <div key={i} className="g-card" style={{ marginBottom: 10, background: 'var(--bg-2)' }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                          <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-1)' }}>{inv.id}</span>
                          <div style={{ display: 'flex', gap: 6 }}>{pill(inv.severity)} {pill(inv.status)}</div>
                        </div>
                        <div style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 8 }}>{inv.title}</div>
                        <div style={{ height: 4, background: 'var(--border)', borderRadius: 2 }}>
                          <div style={{ height: '100%', width: `${inv.progress}%`, background: 'var(--accent)', borderRadius: 2 }} />
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6, fontSize: 11, color: 'var(--text-3)' }}>
                          <span>{inv.progress}% complete</span>
                          <button className="g-btn-ghost" style={{ fontSize: 11, padding: '2px 8px' }}
                            onClick={() => { setChatMode('investigate'); setChatInput(`Investigate ${inv.id}: ${inv.title}`); setTab('chat'); }}>Continue</button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="g-card">
                  <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Investigation Templates</div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
                    {[
                      { title: 'Malware Analysis',       prompt: 'Perform full malware analysis for alert ID: ' },
                      { title: 'Phishing Investigation', prompt: 'Investigate phishing email received by user: ' },
                      { title: 'Insider Threat Review',  prompt: 'Analyze potential insider threat activity for user: ' },
                      { title: 'Data Exfil Hunt',        prompt: 'Hunt for data exfiltration indicators in: ' },
                      { title: 'C2 Beacon Analysis',     prompt: 'Analyze potential C2 beaconing to IP: ' },
                      { title: 'Vulnerability Exploit',  prompt: 'Investigate exploitation of CVE-' },
                    ].map((t, i) => (
                      <button key={i} className="g-btn-ghost"
                        onClick={() => { setChatMode('investigate'); setChatInput(t.prompt); setTab('chat'); }}
                        style={{ textAlign: 'left', padding: '12px 14px', height: 'auto' }}>
                        <div style={{ fontWeight: 600, fontSize: 13 }}>{t.title}</div>
                        <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>{t.prompt}</div>
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* ── COPILOT ──────────────────────────────────────────────────── */}
            {tab === 'copilot' && (
              <div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>
                  <div className="g-card">
                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Security Copilot</div>
                    <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 14 }}>
                      Explain security concepts, alerts, logs, detection rules, MITRE techniques, and playbooks in plain English.
                    </p>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                      {COPILOT_TEMPLATES.map((t, i) => (
                        <button key={i} className="g-btn-ghost"
                          onClick={() => { setChatMode('copilot'); setChatInput(t.prompt); setTab('chat'); }}
                          style={{ textAlign: 'left', padding: '10px 12px', height: 'auto' }}>
                          <div style={{ fontWeight: 600, fontSize: 12 }}>{t.label}</div>
                          <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>{t.prompt}</div>
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="g-card">
                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Knowledge Base Topics</div>
                    {[
                      { topic: 'MITRE ATT&CK Framework', desc: '14 tactics, 200+ techniques explained' },
                      { topic: 'Detection Engineering',   desc: 'Sigma, YARA, Snort, KQL, SPL syntax' },
                      { topic: 'Incident Response',       desc: 'PICERL process and playbook library' },
                      { topic: 'Malware Analysis',        desc: 'Static/dynamic analysis techniques' },
                      { topic: 'Network Security',        desc: 'Firewall rules, NSM, protocol analysis' },
                      { topic: 'Cloud Security',          desc: 'AWS, Azure, GCP security best practices' },
                      { topic: 'Identity & Access',       desc: 'Zero Trust, PAM, MFA, RBAC' },
                      { topic: 'Vulnerability Mgmt',      desc: 'CVSS, EPSS, KEV prioritization' },
                    ].map((k, i) => (
                      <div key={i} onClick={() => { setChatMode('copilot'); setChatInput(`Explain ${k.topic}`); setTab('chat'); }}
                        style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid var(--border)', cursor: 'pointer' }}>
                        <div>
                          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--accent)' }}>{k.topic}</div>
                          <div style={{ fontSize: 12, color: 'var(--text-3)' }}>{k.desc}</div>
                        </div>
                        <span style={{ color: 'var(--text-3)', fontSize: 14, alignSelf: 'center' }}>›</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="g-card">
                  <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 12, color: 'var(--text-1)' }}>Quick Explain</div>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    {['T1566 Phishing', 'T1059 PowerShell', 'T1486 Ransomware', 'T1021 Lateral Movement',
                      'Cobalt Strike', 'LSASS Dumping', 'Kerberoasting', 'DCSync', 'Pass-the-Hash',
                      'AMSI Bypass', 'LOLBins', 'Sigma Rules', 'YARA Hunting', 'EPSS Score'].map((t, i) => (
                      <button key={i} className="g-btn-ghost"
                        onClick={() => { setChatMode('copilot'); sendMessage(`Explain ${t}`); setTab('chat'); }}
                        style={{ fontSize: 12, padding: '6px 12px' }}>{t}</button>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* ── RECOMMENDATIONS ─────────────────────────────────────────── */}
            {tab === 'recommendations' && (
              <div>
                <div style={{ display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap' }}>
                  {(['critical', 'high', 'medium', 'low'] as const).map(p => {
                    const cnt = (data.recommendations ?? []).filter((r: any) => r.priority === p).length;
                    return <StatCard key={p} label={p.charAt(0).toUpperCase() + p.slice(1)} value={cnt} color={PILL_COLORS[p]} />;
                  })}
                  <StatCard label="Total" value={(data.recommendations ?? []).length} />
                </div>

                <div className="g-card">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                    <div style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-1)' }}>
                      AI Recommendations ({(data.recommendations ?? []).length})
                    </div>
                    <button className="g-btn-ghost"
                      onClick={() => { setChatMode('chat'); setChatInput('Generate new security recommendations based on current threat landscape'); setTab('chat'); }}>
                      Generate More
                    </button>
                  </div>
                  {!(data.recommendations ?? []).length ? (
                    <div style={{ color: 'var(--text-3)', textAlign: 'center', padding: 40 }}>
                      No recommendations yet — start a chat session to generate AI-powered recommendations
                    </div>
                  ) : (
                    <table className="g-table" style={{ width: '100%' }}>
                      <thead><tr><th>Title</th><th>Category</th><th>Priority</th><th>Impact</th><th>Effort</th><th>Status</th><th>Actions</th></tr></thead>
                      <tbody>
                        {(data.recommendations ?? []).map((r: any, i: number) => (
                          <tr key={i}>
                            <td>
                              <div style={{ fontWeight: 600, color: 'var(--text-1)', marginBottom: 2 }}>{r.title}</div>
                              <div style={{ fontSize: 12, color: 'var(--text-3)' }}>{(r.description ?? '').slice(0, 80)}{r.description?.length > 80 ? '…' : ''}</div>
                            </td>
                            <td>{pill(r.category)}</td>
                            <td>{pill(r.priority)}</td>
                            <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{r.impact}</td>
                            <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{r.effort}</td>
                            <td>{pill(r.status)}</td>
                            <td>
                              {r.status === 'open' && (
                                <div style={{ display: 'flex', gap: 6 }}>
                                  <button className="g-btn" style={{ fontSize: 11, padding: '4px 10px' }}
                                    onClick={() => aiaAPI.updateRecommendation(r.rec_id, { status: 'accepted' }).then(loadAll)}>Accept</button>
                                  <button className="g-btn-ghost" style={{ fontSize: 11, padding: '4px 10px' }}
                                    onClick={() => aiaAPI.updateRecommendation(r.rec_id, { status: 'dismissed' }).then(loadAll)}>Dismiss</button>
                                </div>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>
            )}

            {/* ── AUTOMATION ──────────────────────────────────────────────── */}
            {tab === 'automation' && (
              <div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>
                  <div className="g-card">
                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Detection Engineering</div>
                    <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 14 }}>
                      Generate Sigma rules, YARA signatures, KQL/SPL queries, and Python scripts from natural language.
                    </p>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      {AUTOMATION_TEMPLATES.map((t, i) => (
                        <button key={i} className="g-btn-ghost"
                          onClick={() => { setChatMode('automation'); setChatInput(t.prompt); setTab('chat'); }}
                          style={{ textAlign: 'left', padding: '10px 14px', height: 'auto' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontWeight: 600, fontSize: 13 }}>{t.label}</span>
                            {pill('automation')}
                          </div>
                          <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>{t.prompt}</div>
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="g-card">
                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>SOAR & Playbook Builder</div>
                    {[
                      { title: 'Ransomware Response',  prompt: 'Generate complete SOAR playbook for ransomware containment and recovery' },
                      { title: 'Phishing Triage',      prompt: 'Generate automated phishing investigation and response playbook' },
                      { title: 'Privilege Escalation', prompt: 'Generate playbook for privilege escalation detection and response' },
                      { title: 'Insider Threat',       prompt: 'Generate insider threat investigation workflow' },
                      { title: 'DDoS Response',        prompt: 'Generate DDoS mitigation and response playbook' },
                      { title: 'Supply Chain Attack',  prompt: 'Generate supply chain compromise investigation playbook' },
                    ].map((t, i) => (
                      <div key={i} onClick={() => { setChatMode('automation'); setChatInput(t.prompt); setTab('chat'); }}
                        style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid var(--border)', cursor: 'pointer' }}>
                        <div>
                          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--accent)' }}>{t.title}</div>
                          <div style={{ fontSize: 12, color: 'var(--text-3)' }}>{t.prompt.slice(0, 60)}…</div>
                        </div>
                        <span style={{ color: 'var(--text-3)', fontSize: 14, alignSelf: 'center' }}>›</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="g-card">
                  <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Generated Assets (Demo)</div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
                    {[
                      { label: 'Sigma Rules',    value: 14,  color: '#dc2626' },
                      { label: 'YARA Rules',     value: 7,   color: '#7c3aed' },
                      { label: 'SOAR Playbooks', value: 5,   color: '#0891b2' },
                      { label: 'KQL/SPL Queries',value: 31,  color: '#16a34a' },
                      { label: 'Python Scripts', value: 9,   color: '#ea580c' },
                      { label: 'Firewall Rules', value: 22,  color: '#be185d' },
                      { label: 'Reports',        value: 23,  color: '#6b7280' },
                      { label: 'Hours Saved',    value: 127, color: '#d97706' },
                    ].map((item, i) => (
                      <div key={i} style={{ background: 'var(--bg-2)', borderRadius: 8, padding: '14px 16px', textAlign: 'center' }}>
                        <div style={{ fontSize: 28, fontWeight: 700, color: item.color }}>{item.value}</div>
                        <div style={{ fontSize: 12, color: 'var(--text-3)' }}>{item.label}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* ── INSIGHTS ─────────────────────────────────────────────────── */}
            {tab === 'insights' && (
              <div>
                <div style={{ display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap' }}>
                  <StatCard label="Detection Gaps"      value={2}    color="#dc2626" />
                  <StatCard label="Anomalies Detected"  value={5}    color="#ea580c" />
                  <StatCard label="Attack Patterns"     value={3}    color="#7c3aed" />
                  <StatCard label="Coverage Score"      value="87%"  color="#16a34a" />
                  <StatCard label="MITRE Coverage"      value="74%"  color="#0891b2" />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginBottom: 20 }}>
                  {INSIGHTS_DATA.map((insight, i) => (
                    <div key={i} className="g-card">
                      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                        <div style={{ width: 6, height: 6, borderRadius: '50%', background: PILL_COLORS[insight.severity], marginTop: 6, flexShrink: 0 }} />
                        <div style={{ flex: 1 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                            <span style={{ fontWeight: 700, fontSize: 14, color: 'var(--text-1)' }}>{insight.title}</span>
                            {pill(insight.severity)}
                          </div>
                          <p style={{ fontSize: 13, color: 'var(--text-2)', margin: '0 0 10px' }}>{insight.description}</p>
                          <div style={{ background: 'var(--bg-2)', borderRadius: 6, padding: '8px 12px', fontSize: 12, color: 'var(--text-2)' }}>
                            <strong>Recommendation:</strong> {insight.recommendation}
                          </div>
                        </div>
                        <button className="g-btn-ghost" style={{ fontSize: 11, flexShrink: 0 }}
                          onClick={() => { setChatMode('investigate'); setChatInput(`Investigate: ${insight.title}`); setTab('chat'); }}>
                          Investigate
                        </button>
                      </div>
                    </div>
                  ))}
                </div>

                <div className="g-card">
                  <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Connected Data Sources</div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
                    {CONNECTED_SOURCES.map((src, i) => (
                      <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, background: 'var(--bg-2)', borderRadius: 6, padding: '10px 12px' }}>
                        <div style={{ width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                          background: src.status === 'connected' ? '#16a34a' : src.status === 'partial' ? '#d97706' : '#6b7280' }} />
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)' }}>{src.name}</div>
                          <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{src.data}</div>
                        </div>
                        {pill(src.status)}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* ── ACTIONS ──────────────────────────────────────────────────── */}
            {tab === 'actions' && (
              <div>
                <div style={{ display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap' }}>
                  <StatCard label="Pending Approval" value={(data.actions ?? []).filter((a: any) => a.status === 'pending_approval').length} color="#d97706" />
                  <StatCard label="Approved"         value={(data.actions ?? []).filter((a: any) => a.status === 'approved').length}          color="#16a34a" />
                  <StatCard label="Rejected"         value={(data.actions ?? []).filter((a: any) => a.status === 'rejected').length}           color="#dc2626" />
                  <StatCard label="Total Actions"    value={(data.actions ?? []).length} />
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: 20 }}>
                  <div className="g-card">
                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Request AI Action</div>
                    <p style={{ color: 'var(--text-3)', fontSize: 13, marginBottom: 14 }}>
                      AI-driven actions require human approval before execution — full audit trail maintained.
                    </p>
                    {[
                      { type: 'create_case',          label: 'Create Case' },
                      { type: 'create_incident',       label: 'Create Incident' },
                      { type: 'create_playbook',       label: 'Generate Playbook' },
                      { type: 'create_detection_rule', label: 'Create Detection Rule' },
                      { type: 'block_ip',              label: 'Block IP Address' },
                      { type: 'isolate_endpoint',      label: 'Isolate Endpoint' },
                      { type: 'generate_report',       label: 'Generate Report' },
                      { type: 'notify_team',           label: 'Notify SOC Team' },
                    ].map((act, i) => (
                      <button key={i} className="g-btn-ghost" style={{ width: '100%', textAlign: 'left', marginBottom: 6, fontSize: 12 }}
                        onClick={() => {
                          const desc = window.prompt(`Describe the ${act.label} action:`);
                          if (desc) aiaAPI.createAction({ action_type: act.type, description: desc }).then(loadAll);
                        }}>
                        + {act.label}
                      </button>
                    ))}
                  </div>

                  <div className="g-card">
                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Action Queue</div>
                    {!(data.actions ?? []).length ? (
                      <div style={{ color: 'var(--text-3)', textAlign: 'center', padding: 40 }}>No actions yet</div>
                    ) : (
                      <table className="g-table" style={{ width: '100%' }}>
                        <thead><tr><th>Action</th><th>Description</th><th>Requested By</th><th>Status</th><th>Approve</th></tr></thead>
                        <tbody>
                          {(data.actions ?? []).map((a: any, i: number) => (
                            <tr key={i}>
                              <td>{pill((a.action_type ?? '').replace(/_/g, ' '))}</td>
                              <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{a.description}</td>
                              <td style={{ fontSize: 12 }}>{a.requested_by}</td>
                              <td>{pill(a.status)}</td>
                              <td>
                                {a.status === 'pending_approval' && (
                                  <div style={{ display: 'flex', gap: 6 }}>
                                    <button className="g-btn" style={{ fontSize: 11, padding: '4px 10px' }}
                                      onClick={() => aiaAPI.approveAction(a.action_id, { approve: true }).then(loadAll)}>Approve</button>
                                    <button className="g-btn-ghost" style={{ fontSize: 11, padding: '4px 10px' }}
                                      onClick={() => aiaAPI.approveAction(a.action_id, { approve: false }).then(loadAll)}>Reject</button>
                                  </div>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* ── PROMPTS ──────────────────────────────────────────────────── */}
            {tab === 'prompts' && (
              <div>
                <div style={{ display: 'grid', gridTemplateColumns: '340px 1fr', gap: 20 }}>
                  <div className="g-card">
                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Save Prompt</div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                      <input className="g-input" placeholder="Prompt title" value={promptTitle} onChange={e => setPromptTitle(e.target.value)} />
                      <select className="g-input" value={promptCat} onChange={e => setPromptCat(e.target.value)}>
                        <option value="general">General</option>
                        <option value="detection">Detection</option>
                        <option value="threat_intel">Threat Intel</option>
                        <option value="investigation">Investigation</option>
                        <option value="automation">Automation</option>
                        <option value="compliance">Compliance</option>
                        <option value="executive">Executive</option>
                      </select>
                      <textarea className="g-input" rows={6} placeholder="Prompt content…" value={promptContent} onChange={e => setPromptContent(e.target.value)} style={{ resize: 'vertical' }} />
                      <button className="g-btn" disabled={savingPrompt || !promptTitle || !promptContent} onClick={savePrompt}>
                        {savingPrompt ? 'Saving…' : 'Save Prompt'}
                      </button>
                    </div>

                    <div style={{ marginTop: 20, borderTop: '1px solid var(--border)', paddingTop: 16 }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-3)', marginBottom: 8 }}>Quick Templates</div>
                      {Object.entries(TEMPLATE_PROMPTS).flatMap(([mode, ps]) => ps.slice(0, 1).map((p, i) => (
                        <button key={`${mode}-${i}`} className="g-btn-ghost"
                          onClick={() => { setChatInput(p); setTab('chat'); }}
                          style={{ display: 'block', width: '100%', textAlign: 'left', fontSize: 12, marginBottom: 4, padding: '6px 10px' }}>
                          {p}
                        </button>
                      )))}
                    </div>
                  </div>

                  <div className="g-card">
                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>
                      Prompt Library ({(data.prompts ?? []).length})
                    </div>
                    {!(data.prompts ?? []).length ? (
                      <div style={{ color: 'var(--text-3)', textAlign: 'center', padding: 40 }}>
                        No saved prompts — save your frequently used prompts here for quick access
                      </div>
                    ) : (
                      <table className="g-table" style={{ width: '100%' }}>
                        <thead><tr><th>Title</th><th>Category</th><th>Used</th><th>Actions</th></tr></thead>
                        <tbody>
                          {(data.prompts ?? []).map((p: any, i: number) => (
                            <tr key={i}>
                              <td>
                                <div style={{ fontWeight: 600, color: 'var(--text-1)' }}>{p.title}</div>
                                <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{(p.content ?? '').slice(0, 80)}{p.content?.length > 80 ? '…' : ''}</div>
                              </td>
                              <td>{pill(p.category)}</td>
                              <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{p.usage_count}×</td>
                              <td>
                                <button className="g-btn-ghost" style={{ fontSize: 11 }}
                                  onClick={() => { setChatInput(p.content); setTab('chat'); }}>Use</button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* ── ANALYTICS ───────────────────────────────────────────────── */}
            {tab === 'analytics' && (
              <div>
                <div style={{ display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap' }}>
                  <StatCard label="Total Sessions"  value={data.analytics?.total_sessions ?? 0} />
                  <StatCard label="Total Messages"  value={data.analytics?.total_messages ?? 0} />
                  <StatCard label="Avg Response"    value={`${data.analytics?.response_quality?.avg_latency_ms ?? 0}ms`} />
                  <StatCard label="User Rating"     value={`${data.analytics?.response_quality?.user_rating_avg ?? 0}/5`}   color="#16a34a" />
                  <StatCard label="Accuracy Rate"   value={`${data.analytics?.response_quality?.accuracy_rate ?? 0}%`}       color="#16a34a" />
                  <StatCard label="Hours Saved"     value={data.analytics?.automation_stats?.analyst_hours_saved ?? 0}        color="#7c3aed" />
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>
                  <div className="g-card">
                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Usage Trend (7 Days)</div>
                    <div style={{ display: 'flex', alignItems: 'flex-end', gap: 8, height: 120 }}>
                      {(data.analytics?.usage_trend ?? []).map((d2: any, i: number) => {
                        const barH = Math.max(4, Math.round((d2.sessions / 35) * 100));
                        return (
                          <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
                            <div title={`Sessions: ${d2.sessions}`}
                              style={{ width: '100%', height: barH, background: 'var(--accent)', borderRadius: '3px 3px 0 0' }} />
                            <div style={{ fontSize: 10, color: 'var(--text-3)' }}>{d2.date}</div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  <div className="g-card">
                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Top Analysts</div>
                    <table className="g-table" style={{ width: '100%' }}>
                      <thead><tr><th>Analyst</th><th>Sessions</th><th>Messages</th><th>Actions</th></tr></thead>
                      <tbody>
                        {(data.analytics?.top_analysts ?? []).map((a: any, i: number) => (
                          <tr key={i}>
                            <td style={{ fontWeight: 600 }}>{a.analyst}</td>
                            <td>{a.sessions}</td>
                            <td>{a.messages}</td>
                            <td>{a.actions_executed}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
                  {[
                    { label: 'Sigma Rules Generated', value: data.analytics?.automation_stats?.sigma_rules_generated ?? 0 },
                    { label: 'YARA Rules Generated',  value: data.analytics?.automation_stats?.yara_rules_generated ?? 0 },
                    { label: 'Playbooks Generated',   value: data.analytics?.automation_stats?.playbooks_generated ?? 0 },
                    { label: 'Reports Generated',     value: data.analytics?.automation_stats?.reports_generated ?? 0 },
                    { label: 'Scripts Generated',     value: data.analytics?.automation_stats?.scripts_generated ?? 0 },
                    { label: 'Queries Generated',     value: data.analytics?.automation_stats?.queries_generated ?? 0 },
                    { label: 'Hours Saved',           value: data.analytics?.automation_stats?.analyst_hours_saved ?? 0 },
                    { label: 'Hallucination Rate',    value: `${data.analytics?.response_quality?.hallucination_rate ?? 0}%` },
                  ].map((item, i) => (
                    <div key={i} className="g-card" style={{ textAlign: 'center' }}>
                      <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--accent)' }}>{item.value}</div>
                      <div style={{ fontSize: 12, color: 'var(--text-3)' }}>{item.label}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* ── REPORTS ──────────────────────────────────────────────────── */}
            {tab === 'reports' && (
              <div>
                <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 20 }}>
                  <div className="g-card">
                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>Generate AI Report</div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                      <input className="g-input" placeholder="Report title" value={reportTitle} onChange={e => setReportTitle(e.target.value)} />
                      <select className="g-input" value={reportType} onChange={e => setReportType(e.target.value)}>
                        <option value="executive_summary">Executive Summary</option>
                        <option value="incident_report">Incident Report</option>
                        <option value="threat_brief">Threat Intelligence Brief</option>
                        <option value="compliance_report">Compliance Report</option>
                        <option value="vulnerability_report">Vulnerability Report</option>
                        <option value="risk_assessment">Risk Assessment</option>
                        <option value="investigation_report">Investigation Report</option>
                        <option value="weekly_digest">Weekly Digest</option>
                      </select>
                      <button className="g-btn" disabled={genReport || !reportTitle} onClick={genReportFn}>
                        {genReport ? 'Generating…' : 'Generate Report'}
                      </button>
                    </div>

                    <div style={{ marginTop: 20, borderTop: '1px solid var(--border)', paddingTop: 16 }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-3)', marginBottom: 8 }}>Quick Reports</div>
                      {[
                        { title: 'Monthly Executive Summary', type: 'executive_summary' },
                        { title: 'Weekly Threat Brief',       type: 'threat_brief' },
                        { title: 'Q2 Risk Assessment',        type: 'risk_assessment' },
                        { title: 'SOC2 Compliance Status',    type: 'compliance_report' },
                      ].map((r, i) => (
                        <button key={i} className="g-btn-ghost"
                          style={{ display: 'block', width: '100%', textAlign: 'left', fontSize: 12, marginBottom: 4 }}
                          onClick={() => { setReportTitle(r.title); setReportType(r.type); }}>
                          {r.title}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="g-card">
                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>
                      Generated Reports ({(data.reports ?? []).length})
                    </div>
                    {!(data.reports ?? []).length ? (
                      <div style={{ color: 'var(--text-3)', textAlign: 'center', padding: 40 }}>No reports generated yet</div>
                    ) : (
                      <table className="g-table" style={{ width: '100%' }}>
                        <thead><tr><th>Title</th><th>Type</th><th>Format</th><th>Generated By</th><th>Date</th><th></th></tr></thead>
                        <tbody>
                          {(data.reports ?? []).map((r: any, i: number) => (
                            <tr key={i}>
                              <td style={{ fontWeight: 600, color: 'var(--text-1)' }}>{r.title}</td>
                              <td>{pill((r.report_type ?? '').replace(/_/g, ' '))}</td>
                              <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{(r.format ?? '').toUpperCase()}</td>
                              <td style={{ fontSize: 12 }}>{r.generated_by}</td>
                              <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{r.created_at ? new Date(r.created_at).toLocaleDateString() : ''}</td>
                              <td>
                                <button className="g-btn-ghost" style={{ fontSize: 11 }}
                                  onClick={() => { setChatMode('executive'); setChatInput(`Generate ${r.report_type} report: ${r.title}`); setTab('chat'); }}>
                                  Regenerate
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* ── AUDIT ────────────────────────────────────────────────────── */}
            {tab === 'audit' && (
              <div className="g-card">
                <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, color: 'var(--text-1)' }}>
                  Audit Trail ({(data.audit ?? []).length} entries)
                </div>
                <table className="g-table" style={{ width: '100%' }}>
                  <thead>
                    <tr><th>Time</th><th>Action</th><th>Object Type</th><th>Object ID</th><th>Actor</th><th>Details</th></tr>
                  </thead>
                  <tbody>
                    {(data.audit ?? []).map((e: any, i: number) => (
                      <tr key={i}>
                        <td style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
                          {e.created_at ? new Date(e.created_at).toLocaleString() : ''}
                        </td>
                        <td>{pill((e.action ?? '').replace(/_/g, ' '))}</td>
                        <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{e.object_type}</td>
                        <td style={{ fontSize: 12, color: 'var(--text-3)', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {e.object_id ?? '—'}
                        </td>
                        <td style={{ fontSize: 12, fontWeight: 600 }}>{e.actor}</td>
                        <td style={{ fontSize: 12, color: 'var(--text-3)' }}>{e.details ?? '—'}</td>
                      </tr>
                    ))}
                    {!(data.audit ?? []).length && (
                      <tr><td colSpan={6} style={{ color: 'var(--text-3)', textAlign: 'center', padding: 32 }}>No audit entries yet</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
    </RootLayout>
  );
}
