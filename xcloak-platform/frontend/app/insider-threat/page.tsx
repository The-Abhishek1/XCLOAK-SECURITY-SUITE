'use client';

import { useEffect, useState, useCallback, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { insiderThreatAPI, casesAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import Link from 'next/link';
import {
  UserX, RefreshCw, Loader2, AlertTriangle, Shield, Clock,
  Database, ShieldAlert, TrendingUp, Search, X, Filter,
  FileText, Usb, Cloud, Printer, Bot, Play, Lock, LogOut,
  Ban, Server, XCircle, KeyRound, Users, Star, Plus, Trash2,
  ChevronRight, BarChart2, Activity, Download, Eye, Check,
  Layers, GitBranch, ArrowUpRight, Crosshair, Zap, Package,
  Globe2, Terminal, CheckCircle2, Info, MessageSquare, Scale,
} from 'lucide-react';

// ── Types ─────────────────────────────────────────────────────────────────────

interface InsiderScore {
  username: string; score: number; risk_level: string;
  contributors: Record<string, number>;
  alert_fired: boolean; score_date: string;
}

interface UserDetail {
  score_detail: InsiderScore;
  ueba_score: number;
  flags: string[];
  event_counts: Array<{ category: string; count: number }>;
  case_titles: string[];
  alert_count: number;
}

interface AIAnalysis {
  narrative: string;
  data_theft_risk: number;
  credential_abuse_risk: number;
  privilege_abuse_risk: number;
  compliance_risk: number;
  overall_insider_risk: number;
  key_indicators: string[];
  mitre_techniques: string[];
  recommendation: string;
  similar_cases: string;
}

interface PolicyViolation {
  id: number; username: string; event_type: string; severity: string;
  description: string; source_ip: string; detected_at: string; policy: string;
}

interface Policy {
  id: number; name: string; event_type: string;
  threshold: number; severity: string; enabled: boolean; created_at: string;
}

interface WatchEntry {
  username: string; category: string; added_at: string; added_by: string; score: number;
}

interface Analytics {
  active_cases: number; high_risk_count: number; insider_score: number;
  policy_violations: number; exfil_events: number; usb_events: number; cloud_uploads: number;
  top_users: InsiderScore[]; trend: Array<{ day: string; avg_score: number; count: number }>;
  top_violations: Array<{ event_type: string; count: number }>;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const RISK_COLOR = (score: number) =>
  score >= 80 ? 'var(--red)' : score >= 60 ? 'var(--orange)' : score >= 30 ? 'var(--yellow)' : 'var(--green)';

const RISK_LABEL = (score: number) =>
  score >= 80 ? 'Critical' : score >= 60 ? 'High' : score >= 30 ? 'Medium' : 'Low';

const RL_COLOR: Record<string, string> = {
  critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--green)',
};

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--green)', info: 'var(--text-3)',
};

const MITRE_COLORS = ['var(--red)', 'var(--orange)', 'var(--yellow)', 'var(--accent)', 'var(--green)'];

const WATCH_CATEGORIES = ['Executive', 'Finance', 'HR', 'Developer', 'Contractor', 'Departing Employee', 'Privileged User', 'Third-Party', 'General'];

const CONTRIB_META: Record<string, { label: string; max: number; color: string }> = {
  off_hours_auth:     { label: 'Off-Hours Auth',       max: 20, color: 'var(--orange)' },
  failed_auth:        { label: 'Failed Auth',           max: 15, color: 'var(--red)' },
  data_exfil:         { label: 'Data Exfiltration',    max: 25, color: 'var(--red)' },
  sensitive_access:   { label: 'Sensitive Access',     max: 15, color: 'var(--yellow)' },
  privesc_attempt:    { label: 'Priv Escalation',      max: 15, color: 'var(--orange)' },
  anomalous_location: { label: 'Anomalous Location',   max: 10, color: 'var(--yellow)' },
};

// ── Small helpers ─────────────────────────────────────────────────────────────

function RiskGauge({ score }: { score: number }) {
  const color = RISK_COLOR(score);
  const circ = 2 * Math.PI * 36;
  const offset = circ * (1 - score / 100);
  return (
    <div className="relative h-24 w-24 shrink-0">
      <svg className="h-24 w-24 -rotate-90" viewBox="0 0 80 80">
        <circle cx="40" cy="40" r="36" fill="none" strokeWidth="8" stroke="var(--border)" />
        <circle cx="40" cy="40" r="36" fill="none" strokeWidth="8"
          stroke={color} strokeLinecap="round" strokeDasharray={circ} strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 0.8s ease' }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-bold tabular-nums" style={{ color }}>{score}</span>
        <span className="text-[9px] font-semibold" style={{ color: 'var(--text-3)' }}>/100</span>
      </div>
    </div>
  );
}

function RiskBadge({ score, level }: { score?: number; level?: string }) {
  const s = score ?? 0;
  const l = level ?? RISK_LABEL(s);
  const color = RL_COLOR[l.toLowerCase()] ?? RISK_COLOR(s);
  return (
    <span className="text-[10px] px-2 py-0.5 rounded font-bold"
      style={{ background: `${color}18`, color, border: `1px solid ${color}44` }}>
      {l}
    </span>
  );
}

function FlagChip({ flag }: { flag: string }) {
  return (
    <span className="text-[9px] px-1.5 py-0.5 rounded font-medium capitalize"
      style={{ background: 'var(--orange)18', color: 'var(--orange)', border: '1px solid var(--orange)33' }}>
      {flag.replace(/_/g, ' ')}
    </span>
  );
}

function SectionHeader({ icon: Icon, title, action }: { icon: any; title: string; action?: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 px-4 py-2.5 shrink-0"
      style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
      <Icon className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--accent)' }} />
      <span className="text-[10px] font-bold uppercase tracking-wider flex-1" style={{ color: 'var(--text-3)' }}>{title}</span>
      {action}
    </div>
  );
}

function Spinner() {
  return <Loader2 className="h-4 w-4 animate-spin mx-auto" style={{ color: 'var(--text-3)' }} />;
}

function Empty({ icon: Icon, text }: { icon: any; text: string }) {
  return (
    <div className="py-8 text-center space-y-2">
      <Icon className="h-7 w-7 mx-auto opacity-15" style={{ color: 'var(--text-3)' }} />
      <p className="text-xs" style={{ color: 'var(--text-3)' }}>{text}</p>
    </div>
  );
}

// ── Risk Score Breakdown ──────────────────────────────────────────────────────

function RiskBreakdown({ detail, ai }: { detail: UserDetail | null; ai: AIAnalysis | null }) {
  if (!detail) return <div className="p-4"><Spinner /></div>;
  const sd = detail.score_detail;
  const aiMetrics = ai ? [
    { label: 'Data Theft Risk',      val: ai.data_theft_risk,        color: 'var(--red)' },
    { label: 'Credential Abuse',     val: ai.credential_abuse_risk,  color: 'var(--orange)' },
    { label: 'Privilege Abuse',      val: ai.privilege_abuse_risk,   color: 'var(--yellow)' },
    { label: 'Compliance Risk',      val: ai.compliance_risk,        color: 'var(--accent)' },
    { label: 'Overall Insider Risk', val: ai.overall_insider_risk,   color: RL_COLOR[sd.risk_level] ?? 'var(--text-2)' },
  ] : [];

  return (
    <div className="p-4 space-y-4">
      <div className="flex items-center gap-4">
        <RiskGauge score={sd.score} />
        <div className="flex-1 space-y-1.5">
          <div>
            <p className="text-lg font-bold" style={{ color: RL_COLOR[sd.risk_level] ?? 'var(--text-1)' }}>
              {sd.risk_level?.toUpperCase()} RISK
            </p>
            <p className="text-xs" style={{ color: 'var(--text-3)' }}>
              Score date: {sd.score_date}
              {sd.alert_fired && <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'var(--red)18', color: 'var(--red)' }}>Alert Fired</span>}
            </p>
          </div>
          <div className="flex flex-wrap gap-1">
            {(detail.flags ?? []).map(f => <FlagChip key={f} flag={f} />)}
          </div>
        </div>
      </div>

      <div className="space-y-2">
        <p className="text-[10px] font-bold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Signal Breakdown</p>
        {Object.entries(CONTRIB_META).map(([key, meta]) => {
          const val = (sd.contributors?.[key] ?? 0) as number;
          const pct = (val / meta.max) * 100;
          return (
            <div key={key}>
              <div className="flex items-center justify-between mb-0.5">
                <span className="text-[11px]" style={{ color: 'var(--text-2)' }}>{meta.label}</span>
                <span className="text-[10px] font-mono" style={{ color: val > 0 ? meta.color : 'var(--text-3)' }}>{val}/{meta.max}</span>
              </div>
              <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--border)' }}>
                <div className="h-full rounded-full" style={{ width: `${pct}%`, background: meta.color }} />
              </div>
            </div>
          );
        })}
      </div>

      {aiMetrics.length > 0 && (
        <div className="space-y-2 pt-2" style={{ borderTop: '1px solid var(--border)' }}>
          <p className="text-[10px] font-bold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>AI Risk Breakdown</p>
          {aiMetrics.map(m => (
            <div key={m.label}>
              <div className="flex items-center justify-between mb-0.5">
                <span className="text-[11px]" style={{ color: 'var(--text-2)' }}>{m.label}</span>
                <span className="text-[10px] font-bold font-mono" style={{ color: m.color }}>{m.val}</span>
              </div>
              <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--border)' }}>
                <div className="h-full rounded-full" style={{ width: `${m.val}%`, background: m.color }} />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Timeline feed ─────────────────────────────────────────────────────────────

const ET_ICONS: Record<string, any> = {
  failed_login: XCircle, login: CheckCircle2, off_hours_login: Clock,
  priv_escalation: TrendingUp, usb_copy: Usb, cloud_upload: Cloud,
  exfiltration: Download, sensitive_file: FileText, source_code: GitBranch,
  mass_file_access: Layers, mass_file_deletion: Trash2, print: Printer,
  analyst_action: Shield, legal_hold: Scale, rare_network: Globe2,
  brute_force: Zap, encryption: Lock,
};

function TimelineFeed({ events, loading }: { events: any[]; loading: boolean }) {
  if (loading) return <div className="p-6"><Spinner /></div>;
  if (events.length === 0) return <Empty icon={Clock} text="No events." />;
  return (
    <div className="relative px-4 py-3 space-y-3">
      <div className="absolute left-6 top-0 bottom-0 w-px" style={{ background: 'var(--border)' }} />
      {events.map((ev, i) => {
        const Icon = ET_ICONS[ev.event_type] ?? Activity;
        const color = SEV_COLOR[ev.severity] ?? 'var(--text-3)';
        return (
          <div key={i} className="relative pl-5">
            <div className="absolute left-0 top-0.5 h-4 w-4 rounded-full flex items-center justify-center"
              style={{ background: `${color}18`, border: `1px solid ${color}44` }}>
              <Icon className="h-2.5 w-2.5" style={{ color }} />
            </div>
            <div className="flex items-start justify-between gap-2">
              <div>
                <span className="text-[10px] font-bold uppercase" style={{ color: 'var(--text-3)' }}>
                  {ev.event_type?.replace(/_/g, ' ')}
                </span>
                {ev.source_ip && <span className="text-[10px] ml-2 font-mono" style={{ color: 'var(--text-3)' }}>from {ev.source_ip}</span>}
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-1)' }}>{ev.description}</p>
              </div>
              <span className="text-[10px] shrink-0" style={{ color: 'var(--text-3)' }}>{timeAgo(ev.detected_at)}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Data / Exfil Activity ─────────────────────────────────────────────────────

function DataExfilCard({ events, detail }: { events: any[]; detail: UserDetail | null }) {
  const exfilTypes = [
    { label: 'USB Copy',              icon: Usb,      key: 'usb_copy',           color: 'var(--red)' },
    { label: 'Cloud Upload',          icon: Cloud,    key: 'cloud_upload',        color: 'var(--orange)' },
    { label: 'Mass File Copy',        icon: Layers,   key: 'mass_file_access',    color: 'var(--orange)' },
    { label: 'Mass File Deletion',    icon: Trash2,   key: 'mass_file_deletion',  color: 'var(--red)' },
    { label: 'Source Code Access',    icon: GitBranch,key: 'source_code',         color: 'var(--red)' },
    { label: 'Exfiltration Detected', icon: Download, key: 'exfiltration',        color: 'var(--red)' },
    { label: 'Sensitive File Access', icon: FileText, key: 'sensitive_file',      color: 'var(--yellow)' },
    { label: 'Encryption Tool Used',  icon: Lock,     key: 'encryption',          color: 'var(--orange)' },
  ];
  const evSet = new Set(events.map(e => e.event_type));
  const countMap = (detail?.event_counts ?? []).reduce((m, c) => ({ ...m, [c.category]: c.count }), {} as Record<string, number>);

  return (
    <div className="p-3 space-y-2">
      {exfilTypes.map(t => {
        const detected = evSet.has(t.key);
        const cnt = countMap[t.key] ?? 0;
        return (
          <div key={t.label} className="flex items-center gap-2.5 rounded-lg px-3 py-2"
            style={{ background: detected ? `${t.color}10` : 'var(--glass-bg)', border: `1px solid ${detected ? t.color + '33' : 'var(--border)'}` }}>
            <t.icon className="h-3.5 w-3.5 shrink-0" style={{ color: detected ? t.color : 'var(--text-3)' }} />
            <span className="text-xs flex-1" style={{ color: detected ? 'var(--text-1)' : 'var(--text-3)' }}>{t.label}</span>
            {detected
              ? <span className="text-[10px] font-bold" style={{ color: t.color }}>{cnt > 0 ? `${cnt}×` : 'Detected'}</span>
              : <Check className="h-3 w-3" style={{ color: 'var(--text-3)' }} />}
          </div>
        );
      })}
    </div>
  );
}

// ── USB & Cloud Activity ──────────────────────────────────────────────────────

function USBCloudCard({ events }: { events: any[] }) {
  const usb    = events.filter(e => e.event_type === 'usb_copy');
  const cloud  = events.filter(e => e.event_type === 'cloud_upload');
  const print  = events.filter(e => e.event_type === 'print');
  const source = events.filter(e => e.event_type === 'source_code');

  const sections = [
    { label: 'USB Events',         icon: Usb,      items: usb,    color: 'var(--red)' },
    { label: 'Cloud Uploads',      icon: Cloud,    items: cloud,  color: 'var(--orange)' },
    { label: 'Print Jobs',         icon: Printer,  items: print,  color: 'var(--yellow)' },
    { label: 'Source Code Access', icon: GitBranch,items: source, color: 'var(--red)' },
  ];

  return (
    <div className="p-3 space-y-3">
      {sections.map(s => (
        <div key={s.label}>
          <div className="flex items-center gap-2 mb-1.5">
            <s.icon className="h-3.5 w-3.5 shrink-0" style={{ color: s.color }} />
            <span className="text-[11px] font-semibold" style={{ color: s.items.length > 0 ? s.color : 'var(--text-3)' }}>
              {s.label} ({s.items.length})
            </span>
          </div>
          {s.items.slice(0, 3).map((ev, i) => (
            <div key={i} className="pl-5 text-[11px] pb-1" style={{ borderBottom: '1px solid var(--border)' }}>
              <p className="truncate" style={{ color: 'var(--text-2)' }}>{ev.description}</p>
              <p style={{ color: 'var(--text-3)' }}>{timeAgo(ev.detected_at)}</p>
            </div>
          ))}
          {s.items.length === 0 && <p className="pl-5 text-[10px]" style={{ color: 'var(--text-3)' }}>No activity</p>}
        </div>
      ))}
    </div>
  );
}

// ── Sensitive Data Access ─────────────────────────────────────────────────────

function SensitiveAccessCard({ events, detail }: { events: any[]; detail: UserDetail | null }) {
  const categories = [
    { label: 'HR Files',             flag: 'hr_access',       icon: Users },
    { label: 'Finance Data',         flag: 'finance_access',  icon: BarChart2 },
    { label: 'Payroll',              flag: 'payroll_access',  icon: Database },
    { label: 'Customer Database',    flag: 'customer_db',     icon: Database },
    { label: 'Source Code',          flag: 'source_code',     icon: GitBranch },
    { label: 'API Keys / Certs',     flag: 'credential_access',icon: Lock },
    { label: 'Password Vaults',      flag: 'password_vault',  icon: Lock },
    { label: 'Intellectual Property',flag: 'ip_access',       icon: FileText },
    { label: 'Confidential Docs',    flag: 'sensitive_file',  icon: FileText },
  ];
  const flags = new Set([...(detail?.flags ?? []), ...events.map(e => e.event_type)]);
  return (
    <div className="p-3 grid grid-cols-2 gap-1.5">
      {categories.map(cat => {
        const detected = flags.has(cat.flag);
        return (
          <div key={cat.label} className="flex items-center gap-1.5 text-[11px] py-0.5">
            {detected
              ? <AlertTriangle className="h-3 w-3 shrink-0" style={{ color: 'var(--red)' }} />
              : <Check className="h-3 w-3 shrink-0" style={{ color: 'var(--text-3)' }} />}
            <span style={{ color: detected ? 'var(--red)' : 'var(--text-3)' }}>{cat.label}</span>
          </div>
        );
      })}
    </div>
  );
}

// ── Behavioral Indicators ─────────────────────────────────────────────────────

function BehavioralIndicatorsCard({ events, detail }: { events: any[]; detail: UserDetail | null }) {
  const evTypes = new Set(events.map(e => e.event_type));
  const flags = new Set(detail?.flags ?? []);
  const indicators = [
    { label: 'Working Outside Normal Hours', detected: evTypes.has('off_hours_login'),      color: 'var(--orange)' },
    { label: 'Weekend Activity',             detected: flags.has('weekend_activity'),         color: 'var(--yellow)' },
    { label: 'Large File Transfers',         detected: evTypes.has('usb_copy') || evTypes.has('cloud_upload'), color: 'var(--red)' },
    { label: 'Excessive Downloads',          detected: evTypes.has('mass_file_access'),      color: 'var(--orange)' },
    { label: 'Mass File Deletion',           detected: evTypes.has('mass_file_deletion'),    color: 'var(--red)' },
    { label: 'Accessing Unusual Systems',    detected: evTypes.has('rare_network'),          color: 'var(--yellow)' },
    { label: 'Repeated Policy Violations',   detected: (detail?.event_counts?.length ?? 0) > 3, color: 'var(--orange)' },
    { label: 'New Device Usage',             detected: flags.has('new_device'),              color: 'var(--yellow)' },
    { label: 'Privileged User Activity',     detected: evTypes.has('priv_escalation') || evTypes.has('sudo'), color: 'var(--red)' },
    { label: 'Printing Sensitive Files',     detected: evTypes.has('print'),                 color: 'var(--orange)' },
    { label: 'Encryption Tool Usage',        detected: evTypes.has('encryption'),            color: 'var(--red)' },
    { label: 'Brute Force Attempt',          detected: evTypes.has('brute_force'),           color: 'var(--red)' },
  ];
  const triggered = indicators.filter(i => i.detected);
  return (
    <div className="p-3">
      {triggered.length === 0
        ? <p className="text-xs py-4 text-center" style={{ color: 'var(--text-3)' }}>No behavioral indicators — within normal baseline.</p>
        : (
          <div className="grid grid-cols-2 gap-1.5">
            {triggered.map(ind => (
              <div key={ind.label} className="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5"
                style={{ background: `${ind.color}10`, border: `1px solid ${ind.color}33` }}>
                <AlertTriangle className="h-3 w-3 shrink-0" style={{ color: ind.color }} />
                <span className="text-[10px]" style={{ color: 'var(--text-1)' }}>{ind.label}</span>
              </div>
            ))}
          </div>
        )
      }
    </div>
  );
}

// ── Evidence Panel ────────────────────────────────────────────────────────────

function EvidencePanel({ detail, events }: { detail: UserDetail | null; events: any[] }) {
  const evidenceItems = [
    ...events.slice(0, 5).map(e => ({
      type: 'UEBA Event', title: e.event_type?.replace(/_/g, ' '), desc: e.description,
      time: e.detected_at, icon: Activity, color: SEV_COLOR[e.severity] ?? 'var(--text-3)',
    })),
    ...(detail?.case_titles ?? []).map(t => ({
      type: 'Case', title: t, desc: 'Linked investigation case',
      time: new Date().toISOString(), icon: Scale, color: 'var(--accent)',
    })),
  ];
  if (evidenceItems.length === 0) return <Empty icon={FileText} text="No evidence collected yet." />;
  return (
    <div className="p-3 space-y-2">
      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>Evidence items automatically collected from UEBA + cases. Legal hold preserves integrity.</p>
      {evidenceItems.map((item, i) => (
        <div key={i} className="flex items-start gap-2.5 rounded-lg px-3 py-2"
          style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
          <div className="h-6 w-6 rounded-lg flex items-center justify-center shrink-0"
            style={{ background: `${item.color}18`, border: `1px solid ${item.color}44` }}>
            <item.icon className="h-3.5 w-3.5" style={{ color: item.color }} />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-[10px] font-bold uppercase" style={{ color: 'var(--text-3)' }}>{item.type}</p>
            <p className="text-xs font-medium truncate capitalize" style={{ color: 'var(--text-1)' }}>{item.title}</p>
            <p className="text-[10px] truncate" style={{ color: 'var(--text-3)' }}>{item.desc}</p>
          </div>
          <span className="text-[9px] shrink-0" style={{ color: 'var(--text-3)' }}>{timeAgo(item.time)}</span>
        </div>
      ))}
    </div>
  );
}

// ── AI Analysis Panel ─────────────────────────────────────────────────────────

function AIAnalysisPanel({ username, onResult }: { username: string; onResult: (ai: AIAnalysis) => void }) {
  const [ai,       setAi]       = useState<AIAnalysis | null>(null);
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState('');

  const run = async () => {
    setLoading(true); setError(''); setAi(null);
    try {
      const r = await insiderThreatAPI.aiAnalysis(username);
      const data = r.data as AIAnalysis;
      setAi(data);
      onResult(data);
    } catch { setError('AI analysis unavailable'); }
    finally { setLoading(false); }
  };

  return (
    <div className="p-4 space-y-3">
      {loading && <div className="flex justify-center py-4"><Spinner /></div>}
      {error && <p className="text-xs" style={{ color: 'var(--red)' }}>{error}</p>}
      {!loading && !ai && (
        <div className="text-center py-6 space-y-2">
          <Bot className="h-8 w-8 mx-auto opacity-15" style={{ color: 'var(--accent)' }} />
          <p className="text-xs" style={{ color: 'var(--text-3)' }}>AI will analyze patterns, compare with peers, and flag insider threat indicators.</p>
          <button onClick={run} className="g-btn g-btn-primary text-xs mx-auto">
            <Bot className="h-3.5 w-3.5" /> Run AI Risk Analysis
          </button>
        </div>
      )}
      {ai && (
        <div className="space-y-3">
          <div className="rounded-xl p-3" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
            <p className="text-xs leading-relaxed italic" style={{ color: 'var(--text-1)' }}>"{ai.narrative}"</p>
          </div>
          {ai.key_indicators?.length > 0 && (
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>Key Indicators</p>
              {ai.key_indicators.map((ind, i) => (
                <div key={i} className="flex gap-2 text-xs py-1">
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--orange)' }} />
                  <span style={{ color: 'var(--text-2)' }}>{ind}</span>
                </div>
              ))}
            </div>
          )}
          {ai.mitre_techniques?.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {ai.mitre_techniques.map((t, i) => (
                <span key={t} className="text-[10px] px-2.5 py-1 rounded-lg font-mono font-medium"
                  style={{ background: `${MITRE_COLORS[i % MITRE_COLORS.length]}18`, color: MITRE_COLORS[i % MITRE_COLORS.length], border: `1px solid ${MITRE_COLORS[i % MITRE_COLORS.length]}44` }}>
                  {t}
                </span>
              ))}
            </div>
          )}
          {ai.recommendation && (
            <div className="rounded-xl p-3" style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
              <p className="text-[10px] font-semibold mb-1" style={{ color: 'var(--text-3)' }}>Recommendation</p>
              <p className="text-xs" style={{ color: 'var(--accent)' }}>{ai.recommendation}</p>
            </div>
          )}
          {ai.similar_cases && (
            <div className="rounded-xl p-3" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
              <p className="text-[10px] font-semibold mb-1" style={{ color: 'var(--text-3)' }}>Similar Historical Pattern</p>
              <p className="text-xs" style={{ color: 'var(--text-2)' }}>{ai.similar_cases}</p>
            </div>
          )}
          <button onClick={run} className="g-btn g-btn-ghost text-[10px] w-full justify-center">
            <RefreshCw className="h-3 w-3" /> Re-analyze
          </button>
        </div>
      )}
    </div>
  );
}

// ── Policy Violations Table ───────────────────────────────────────────────────

function PolicyViolationsPanel({ violations }: { violations: PolicyViolation[] }) {
  if (violations.length === 0) return <Empty icon={Shield} text="No policy violations in last 30 days." />;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border)' }}>
            {['Policy', 'Event', 'User', 'Time'].map(h => (
              <th key={h} className="text-left px-3 py-2 text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {violations.slice(0, 20).map((v, i) => (
            <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
              <td className="px-3 py-2">
                <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: `${SEV_COLOR[v.severity] ?? 'var(--text-3)'}18`, color: SEV_COLOR[v.severity] ?? 'var(--text-3)' }}>
                  {v.policy}
                </span>
              </td>
              <td className="px-3 py-2 font-mono text-[10px] capitalize" style={{ color: 'var(--text-2)' }}>
                {v.event_type.replace(/_/g, ' ')}
              </td>
              <td className="px-3 py-2 font-mono font-medium" style={{ color: 'var(--accent)' }}>{v.username}</td>
              <td className="px-3 py-2" style={{ color: 'var(--text-3)' }}>{timeAgo(v.detected_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Response Actions ──────────────────────────────────────────────────────────

const RESPONSE_ACTIONS = [
  { key: 'disable_user',     label: 'Disable User',        icon: Ban,        color: 'var(--red)',    desc: 'Revoke all access' },
  { key: 'lock_account',     label: 'Lock Account',         icon: Lock,       color: 'var(--red)',    desc: 'Block login pending review' },
  { key: 'force_logout',     label: 'Force Logout',         icon: LogOut,     color: 'var(--red)',    desc: 'Revoke all sessions' },
  { key: 'require_mfa',      label: 'Require MFA',          icon: KeyRound,   color: 'var(--yellow)', desc: 'Enforce on next login' },
  { key: 'block_usb',        label: 'Block USB',            icon: Usb,        color: 'var(--orange)', desc: 'Policy: no removable storage' },
  { key: 'block_cloud',      label: 'Block Cloud Upload',   icon: Cloud,      color: 'var(--orange)', desc: 'Proxy-level block' },
  { key: 'isolate_endpoint', label: 'Isolate Endpoint',     icon: Server,     color: 'var(--red)',    desc: 'Network isolation' },
  { key: 'kill_process',     label: 'Kill Process',         icon: XCircle,    color: 'var(--orange)', desc: 'Kill by PID' },
  { key: 'remove_privileges',label: 'Remove Privileges',    icon: ShieldAlert,color: 'var(--yellow)', desc: 'Revoke admin rights' },
  { key: 'legal_hold',       label: 'Legal Hold',           icon: Scale,      color: 'var(--accent)', desc: 'Preserve evidence + audit trail' },
  { key: 'run_playbook',     label: 'Run SOAR Playbook',    icon: Play,       color: 'var(--accent)', desc: 'Automated response' },
];

function ResponseActionsPanel({ username, onAction }: { username: string; onAction: (msg: string) => void }) {
  const [running, setRunning] = useState<string | null>(null);
  const [activeKey, setActiveKey] = useState<string | null>(null);
  const [param, setParam] = useState('');

  const PARAM_LABELS: Record<string, string> = { kill_process: 'PID', run_playbook: 'Playbook ID' };
  const needsParam = activeKey ? PARAM_LABELS[activeKey] : null;

  const dispatch = async (key: string, p = '') => {
    setRunning(key);
    try {
      const params: Record<string, string> = {};
      if (key === 'kill_process') params.pid = p;
      if (key === 'run_playbook') params.playbook_id = p;
      const r = await insiderThreatAPI.responseAction(username, key, params);
      onAction((r.data as any)?.result ?? `${key} dispatched`);
      setActiveKey(null); setParam('');
    } catch { onAction('Action failed'); }
    finally { setRunning(null); }
  };

  return (
    <div className="p-3 space-y-2">
      {activeKey && needsParam && (
        <div className="flex items-center gap-2 rounded-lg px-3 py-2.5"
          style={{ background: 'var(--glass-bg)', border: '1px solid var(--accent-border)' }}>
          <input value={param} onChange={e => setParam(e.target.value)}
            placeholder={needsParam + '…'} className="g-input flex-1 text-xs"
            onKeyDown={e => e.key === 'Enter' && param && dispatch(activeKey, param)} />
          <button onClick={() => param && dispatch(activeKey, param)} disabled={!param || running === activeKey}
            className="g-btn g-btn-primary text-xs px-3">
            {running === activeKey ? <Loader2 className="h-3 w-3 animate-spin" /> : 'Run'}
          </button>
          <button onClick={() => { setActiveKey(null); setParam(''); }} className="g-btn g-btn-ghost text-xs px-2">
            <X className="h-3 w-3" />
          </button>
        </div>
      )}
      <div className="grid grid-cols-3 gap-1.5">
        {RESPONSE_ACTIONS.map(a => (
          <button key={a.key}
            onClick={() => PARAM_LABELS[a.key] ? (setActiveKey(a.key), setParam('')) : dispatch(a.key)}
            disabled={running !== null}
            className="flex items-center gap-2 rounded-lg px-3 py-2 text-left hover:bg-[var(--glass-hover)] transition-colors"
            style={{ background: 'var(--glass-bg)', border: `1px solid ${a.color}33` }}>
            {running === a.key
              ? <Loader2 className="h-3.5 w-3.5 animate-spin shrink-0" style={{ color: a.color }} />
              : <a.icon className="h-3.5 w-3.5 shrink-0" style={{ color: a.color }} />}
            <div className="min-w-0">
              <p className="text-[10px] font-medium truncate" style={{ color: 'var(--text-1)' }}>{a.label}</p>
              <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>{a.desc}</p>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

// ── Open Cases Panel ──────────────────────────────────────────────────────────

function OpenCasesPanel({ username, caseTitles }: { username: string; caseTitles: string[] }) {
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState(false);

  const openCase = async () => {
    setCreating(true);
    try {
      await casesAPI.create({
        title: `Insider Threat Investigation — ${username}`,
        description: `Automated case opened from insider threat monitoring for user ${username}.`,
        severity: 'high',
        status: 'open',
        phase: 'detection',
      });
      setCreated(true);
    } catch {}
    finally { setCreating(false); }
  };

  return (
    <div className="p-4 space-y-3">
      {caseTitles.length === 0
        ? (
          <div className="text-center py-4 space-y-2">
            <Scale className="h-7 w-7 mx-auto opacity-15" style={{ color: 'var(--text-3)' }} />
            <p className="text-xs" style={{ color: 'var(--text-3)' }}>No open cases for this user.</p>
          </div>
        )
        : caseTitles.map((t, i) => (
          <div key={i} className="flex items-center gap-2.5 rounded-lg px-3 py-2.5"
            style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
            <Scale className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--accent)' }} />
            <span className="text-xs flex-1 truncate" style={{ color: 'var(--text-1)' }}>{t}</span>
          </div>
        ))
      }
      {created
        ? <p className="text-xs" style={{ color: 'var(--green)' }}>Case opened successfully.</p>
        : (
          <button onClick={openCase} disabled={creating} className="g-btn g-btn-primary text-xs w-full justify-center">
            {creating ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
            Open Insider Threat Case
          </button>
        )
      }
      <Link href="/cases" className="g-btn g-btn-ghost text-xs w-full justify-center">
        <Eye className="h-3.5 w-3.5" /> View All Cases
      </Link>
    </div>
  );
}

// ── User Detail Panel ─────────────────────────────────────────────────────────

function UserDetailPanel({ score, onClose }: { score: InsiderScore; onClose: () => void }) {
  const [detail,     setDetail]     = useState<UserDetail | null>(null);
  const [timeline,   setTimeline]   = useState<any[]>([]);
  const [violations, setViolations] = useState<PolicyViolation[]>([]);
  const [aiResult,   setAiResult]   = useState<AIAnalysis | null>(null);
  const [loadingD,   setLoadingD]   = useState(true);
  const [loadingT,   setLoadingT]   = useState(true);
  const [loadingV,   setLoadingV]   = useState(true);
  const [toast,      setToast]      = useState<string | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  useEffect(() => {
    setDetail(null); setTimeline([]); setViolations([]); setAiResult(null);
    setLoadingD(true); setLoadingT(true); setLoadingV(true);

    insiderThreatAPI.getUserDetail(score.username).then(r => { setDetail(r.data); setLoadingD(false); });
    insiderThreatAPI.getUserTimeline(score.username).then(r => { setTimeline(r.data?.events ?? []); setLoadingT(false); });
    insiderThreatAPI.getPolicyViolations(score.username).then(r => { setViolations(r.data?.violations ?? []); setLoadingV(false); });
  }, [score.username]);

  const CARD = 'g-card flex flex-col overflow-hidden';

  return (
    <div className="flex flex-col h-full overflow-y-auto" style={{ background: 'var(--bg-0)' }}>
      {toast && (
        <div className="fixed bottom-4 right-4 z-50 px-4 py-2 rounded-lg text-sm font-medium shadow-xl"
          style={{ background: 'var(--accent)', color: '#000' }}>{toast}</div>
      )}

      {/* Header */}
      <div className="sticky top-0 z-30 flex items-center gap-3 px-4 py-3"
        style={{ background: 'var(--bg-1)', borderBottom: '1px solid var(--border)' }}>
        <div className="h-9 w-9 rounded-full flex items-center justify-center text-sm font-bold shrink-0"
          style={{ background: `${RL_COLOR[score.risk_level] ?? 'var(--text-3)'}22`, color: RL_COLOR[score.risk_level] ?? 'var(--text-3)', border: `1px solid ${RL_COLOR[score.risk_level] ?? 'var(--border)'}44` }}>
          {score.username.charAt(0).toUpperCase()}
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-bold" style={{ color: 'var(--text-1)' }}>{score.username}</p>
          <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>Score: {score.score}/100 · {score.score_date}</p>
        </div>
        <RiskBadge level={score.risk_level} />
        {score.alert_fired && (
          <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded"
            style={{ background: 'var(--red)18', color: 'var(--red)', border: '1px solid var(--red)33' }}>
            <ShieldAlert className="h-3 w-3" /> Alert Fired
          </span>
        )}
        <button onClick={onClose} className="g-btn g-btn-ghost text-xs"><X className="h-4 w-4" /></button>
      </div>

      <div className="p-4 space-y-3 max-w-[1400px] mx-auto w-full">

        {/* Row 1: Risk Score + Dashboard KPIs */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={CARD}>
            <SectionHeader icon={BarChart2} title="Insider Risk Score Breakdown" />
            <div className="flex-1 overflow-y-auto" style={{ maxHeight: 440 }}>
              {loadingD ? <div className="p-4"><Spinner /></div> : <RiskBreakdown detail={detail} ai={aiResult} />}
            </div>
          </div>
          <div className={CARD}>
            <SectionHeader icon={Activity} title="Activity Summary" />
            <div className="p-4 space-y-3">
              {loadingD ? <Spinner /> : (
                <>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                    {[
                      { l: 'UEBA Score',    v: detail?.ueba_score ?? 0,  c: RISK_COLOR(detail?.ueba_score ?? 0) },
                      { l: 'Alerts (30d)',  v: detail?.alert_count ?? 0, c: 'var(--orange)' },
                      { l: 'Violations',   v: violations.length,          c: 'var(--red)' },
                      { l: 'Open Cases',   v: detail?.case_titles?.length ?? 0, c: 'var(--accent)' },
                      { l: 'Event Types',  v: detail?.event_counts?.length ?? 0, c: 'var(--text-2)' },
                      { l: 'Timeline',     v: timeline.length,             c: 'var(--text-2)' },
                    ].map(s => (
                      <div key={s.l} className="rounded-xl px-3 py-2.5 text-center"
                        style={{ background: 'var(--glass-bg)', border: `1px solid ${s.c}33` }}>
                        <p className="text-lg font-bold tabular-nums" style={{ color: s.c }}>{s.v}</p>
                        <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>{s.l}</p>
                      </div>
                    ))}
                  </div>
                  <div>
                    <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Quick Investigations</p>
                    <div className="grid grid-cols-2 gap-1.5">
                      {[
                        { label: 'View Alerts',    href: `/alerts?username=${score.username}`,    icon: ShieldAlert },
                        { label: 'Search Logs',    href: `/log-search?q=${score.username}`,       icon: Search },
                        { label: 'Threat Hunt',    href: `/hunt?query=${score.username}`,          icon: Crosshair },
                        { label: 'Attack Path',    href: `/attack-path`,                           icon: GitBranch },
                        { label: 'View Cases',     href: `/cases`,                                 icon: Scale },
                        { label: 'Full Timeline',  href: `/timeline?username=${score.username}`,   icon: Clock },
                      ].map(a => (
                        <Link key={a.label} href={a.href}
                          className="flex items-center gap-1.5 rounded-lg px-2.5 py-2 text-xs hover:bg-[var(--glass-hover)] transition-colors"
                          style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
                          <a.icon className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--accent)' }} />
                          {a.label}
                        </Link>
                      ))}
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>

        {/* Row 2: Timeline + Behavioral Indicators */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={CARD} style={{ maxHeight: 420 }}>
            <SectionHeader icon={Clock} title={`User Activity Timeline (${timeline.length})`} />
            <div className="flex-1 overflow-y-auto">
              <TimelineFeed events={timeline} loading={loadingT} />
            </div>
          </div>
          <div className={CARD}>
            <SectionHeader icon={AlertTriangle} title="Behavioral Indicators" />
            {loadingD ? <div className="p-4"><Spinner /></div>
              : <BehavioralIndicatorsCard events={timeline} detail={detail} />}
          </div>
        </div>

        {/* Row 3: Data Exfil + USB / Cloud */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={CARD}>
            <SectionHeader icon={Download} title="Data Exfiltration Detection" />
            {loadingT ? <div className="p-4"><Spinner /></div>
              : <DataExfilCard events={timeline} detail={detail} />}
          </div>
          <div className={CARD}>
            <SectionHeader icon={Usb} title="USB / Cloud / Print Activity" />
            {loadingT ? <div className="p-4"><Spinner /></div>
              : <USBCloudCard events={timeline} />}
          </div>
        </div>

        {/* Row 4: Sensitive Data Access + Privileged User Monitoring */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={CARD}>
            <SectionHeader icon={Database} title="Sensitive Data Access" />
            {loadingD ? <div className="p-4"><Spinner /></div>
              : <SensitiveAccessCard events={timeline} detail={detail} />}
          </div>
          <div className={CARD}>
            <SectionHeader icon={TrendingUp} title="Privileged User Monitoring" />
            <div className="p-3 space-y-2">
              {[
                { label: 'Domain Admin Activity', et: 'priv_escalation',  color: 'var(--red)' },
                { label: 'Sudo / RunAs',           et: 'sudo',             color: 'var(--orange)' },
                { label: 'Service Account Login',  et: 'service_account',  color: 'var(--yellow)' },
                { label: 'Cloud Admin Access',     et: 'cloud_admin',      color: 'var(--orange)' },
                { label: 'Unusual Admin Activity', et: 'rare_admin',       color: 'var(--red)' },
                { label: 'Policy Change',          et: 'policy_change',    color: 'var(--yellow)' },
                { label: 'Account Creation',       et: 'account_creation', color: 'var(--orange)' },
              ].map(p => {
                const detected = timeline.some(e => e.event_type === p.et);
                return (
                  <div key={p.label} className="flex items-center gap-2.5 text-[11px]">
                    {detected
                      ? <AlertTriangle className="h-3 w-3 shrink-0" style={{ color: p.color }} />
                      : <Check className="h-3 w-3 shrink-0" style={{ color: 'var(--text-3)' }} />}
                    <span style={{ color: detected ? p.color : 'var(--text-3)' }}>{p.label}</span>
                    {detected && <span className="ml-auto font-bold" style={{ color: p.color }}>Detected</span>}
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Row 5: Evidence + Related Alerts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={CARD} style={{ maxHeight: 380 }}>
            <SectionHeader icon={FileText} title="Evidence & Legal Hold" />
            <div className="flex-1 overflow-y-auto">
              {loadingD ? <div className="p-4"><Spinner /></div>
                : <EvidencePanel detail={detail} events={timeline.slice(0, 8)} />}
            </div>
          </div>
          <div className={CARD} style={{ maxHeight: 380 }}>
            <SectionHeader icon={ShieldAlert} title="Related Alerts" />
            <div className="p-4 space-y-2">
              {!loadingD && detail && (
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-2xl font-bold" style={{ color: detail.alert_count > 0 ? 'var(--red)' : 'var(--green)' }}>
                    {detail.alert_count}
                  </span>
                  <span className="text-sm" style={{ color: 'var(--text-3)' }}>alerts in last 30 days</span>
                </div>
              )}
              <Link href={`/alerts?username=${score.username}`}
                className="g-btn g-btn-ghost text-xs w-full justify-center">
                <Eye className="h-3.5 w-3.5" /> View Alerts
              </Link>
              <Link href={`/incidents?username=${score.username}`}
                className="g-btn g-btn-ghost text-xs w-full justify-center">
                <Shield className="h-3.5 w-3.5" /> View Incidents
              </Link>
              {(detail?.event_counts ?? []).slice(0, 5).map(ec => (
                <div key={ec.category} className="flex items-center justify-between py-1.5" style={{ borderBottom: '1px solid var(--border)' }}>
                  <span className="text-xs capitalize" style={{ color: 'var(--text-2)' }}>{ec.category.replace(/_/g, ' ')}</span>
                  <span className="text-xs font-bold tabular-nums" style={{ color: 'var(--orange)' }}>{ec.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Row 6: Policy Violations + Open Cases */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={CARD} style={{ maxHeight: 360 }}>
            <SectionHeader icon={Shield} title={`Policy Violations (${violations.length})`} />
            <div className="flex-1 overflow-y-auto">
              {loadingV ? <div className="p-4"><Spinner /></div>
                : <PolicyViolationsPanel violations={violations} />}
            </div>
          </div>
          <div className={CARD} style={{ maxHeight: 360 }}>
            <SectionHeader icon={Scale} title="Case Management" />
            {loadingD ? <div className="p-4"><Spinner /></div>
              : <OpenCasesPanel username={score.username} caseTitles={detail?.case_titles ?? []} />}
          </div>
        </div>

        {/* Row 7: AI Analysis (full width) */}
        <div className={CARD}>
          <SectionHeader icon={Bot} title="AI Risk Analysis" />
          <AIAnalysisPanel username={score.username} onResult={setAiResult} />
        </div>

        {/* Row 8: Response Actions (full width) */}
        <div className={CARD}>
          <SectionHeader icon={Zap} title="Response Actions" />
          <ResponseActionsPanel username={score.username} onAction={notify} />
        </div>

      </div>
    </div>
  );
}

// ── Analytics Dashboard ───────────────────────────────────────────────────────

function AnalyticsDashboard({ analytics }: { analytics: Analytics | null }) {
  if (!analytics) return <div className="p-8"><Spinner /></div>;
  const maxTrend = Math.max(...(analytics.trend ?? []).map(t => t.avg_score), 1);
  return (
    <div className="p-4 space-y-5">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { l: 'Active Cases',       v: analytics.active_cases,      c: 'var(--accent)' },
          { l: 'Policy Violations',  v: analytics.policy_violations,  c: 'var(--red)' },
          { l: 'Exfil Events (7d)', v: analytics.exfil_events,      c: 'var(--red)' },
          { l: 'USB Events (7d)',   v: analytics.usb_events,         c: 'var(--orange)' },
          { l: 'Cloud Uploads',     v: analytics.cloud_uploads,      c: 'var(--yellow)' },
          { l: 'High Risk Users',   v: analytics.high_risk_count,    c: 'var(--orange)' },
          { l: 'Avg Insider Score', v: `${analytics.insider_score}%`, c: RISK_COLOR(analytics.insider_score) },
        ].map(s => (
          <div key={s.l} className="g-card px-3 py-2.5 text-center">
            <p className="text-lg font-bold tabular-nums" style={{ color: s.c }}>{s.v}</p>
            <p className="text-[9px]" style={{ color: 'var(--text-3)' }}>{s.l}</p>
          </div>
        ))}
      </div>

      {analytics.trend.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Insider Risk Score Trend (14 days)</p>
          <div className="flex items-end gap-0.5 h-16">
            {analytics.trend.map(t => (
              <div key={t.day} title={`${t.day}: avg ${t.avg_score}`}
                className="flex-1 rounded-t" style={{ height: `${(t.avg_score / maxTrend) * 100}%`, background: RISK_COLOR(t.avg_score), opacity: 0.8, minHeight: '2px' }} />
            ))}
          </div>
        </div>
      )}

      {analytics.top_violations.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Top Violation Types (7d)</p>
          <div className="space-y-1.5">
            {analytics.top_violations.slice(0, 6).map((v, i) => (
              <div key={v.event_type} className="flex items-center gap-2">
                <span className="text-[10px] w-4 font-mono" style={{ color: 'var(--text-3)' }}>{i + 1}.</span>
                <span className="text-[11px] flex-1 capitalize" style={{ color: 'var(--text-2)' }}>{v.event_type.replace(/_/g, ' ')}</span>
                <span className="text-[10px] font-bold" style={{ color: 'var(--orange)' }}>{v.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Policy Engine Panel ───────────────────────────────────────────────────────

function PolicyEnginePanel({ policies, onAdd }: { policies: Policy[]; onAdd: () => void }) {
  const [newName, setNewName] = useState('');
  const [newType, setNewType] = useState('usb_copy');
  const [newSev, setNewSev] = useState('high');
  const [adding, setAdding] = useState(false);

  const EVENT_TYPES = ['usb_copy', 'cloud_upload', 'mass_file_access', 'mass_file_deletion',
    'source_code', 'priv_escalation', 'off_hours_login', 'sensitive_file', 'brute_force', 'encryption', 'print'];

  const submit = async () => {
    if (!newName.trim()) return;
    setAdding(true);
    try {
      await insiderThreatAPI.createPolicy({ name: newName, event_type: newType, severity: newSev, threshold: 1 });
      setNewName(''); onAdd();
    } catch {} finally { setAdding(false); }
  };

  return (
    <div className="p-4 space-y-4">
      <div className="flex flex-wrap gap-2">
        <input value={newName} onChange={e => setNewName(e.target.value)} placeholder="Policy name…"
          className="g-input flex-1 min-w-[200px] text-xs" onKeyDown={e => e.key === 'Enter' && submit()} />
        <select value={newType} onChange={e => setNewType(e.target.value)} className="g-select text-xs">
          {EVENT_TYPES.map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
        </select>
        <select value={newSev} onChange={e => setNewSev(e.target.value)} className="g-select text-xs">
          {['low', 'medium', 'high', 'critical'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <button onClick={submit} disabled={!newName.trim() || adding} className="g-btn g-btn-primary text-xs px-3">
          {adding ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />} Add Policy
        </button>
      </div>
      <div className="space-y-2">
        {policies.map(p => (
          <div key={p.id} className="flex items-center gap-3 rounded-lg px-3 py-2.5"
            style={{ background: 'var(--glass-bg)', border: `1px solid ${SEV_COLOR[p.severity] ?? 'var(--border)'}33` }}>
            <div className={`h-2 w-2 rounded-full shrink-0 ${p.enabled ? 'animate-pulse' : 'opacity-30'}`}
              style={{ background: SEV_COLOR[p.severity] ?? 'var(--text-3)' }} />
            <span className="text-xs font-medium flex-1" style={{ color: 'var(--text-1)' }}>{p.name}</span>
            <span className="text-[10px] font-mono" style={{ color: 'var(--text-3)' }}>{p.event_type.replace(/_/g, ' ')}</span>
            <span className="text-[10px] px-1.5 py-0.5 rounded capitalize"
              style={{ background: `${SEV_COLOR[p.severity] ?? 'var(--text-3)'}18`, color: SEV_COLOR[p.severity] ?? 'var(--text-3)' }}>
              {p.severity}
            </span>
          </div>
        ))}
        {policies.length === 0 && <p className="text-xs text-center py-4" style={{ color: 'var(--text-3)' }}>No policies configured. Add one above.</p>}
      </div>
    </div>
  );
}

// ── Watchlist Panel ───────────────────────────────────────────────────────────

function WatchlistPanel({ watchlist, onAdd, onRemove, loadingUser }: {
  watchlist: WatchEntry[]; onAdd: (u: string, c: string) => void;
  onRemove: (u: string) => void; loadingUser: string | null;
}) {
  const [newUser, setNewUser] = useState('');
  const [newCat, setNewCat] = useState('General');
  return (
    <div className="p-4 space-y-3">
      <div className="flex items-center gap-2">
        <input value={newUser} onChange={e => setNewUser(e.target.value)}
          placeholder="Username to monitor…" className="g-input flex-1 text-xs"
          onKeyDown={e => e.key === 'Enter' && newUser.trim() && onAdd(newUser.trim(), newCat)} />
        <select value={newCat} onChange={e => setNewCat(e.target.value)} className="g-select text-xs" style={{ width: 130 }}>
          {WATCH_CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <button onClick={() => newUser.trim() && onAdd(newUser.trim(), newCat)} className="g-btn g-btn-primary text-xs px-3">
          <Plus className="h-3.5 w-3.5" />
        </button>
      </div>
      {watchlist.length === 0
        ? <p className="text-xs text-center py-4" style={{ color: 'var(--text-3)' }}>Add users to apply stricter detection thresholds (executives, contractors, finance, HR…).</p>
        : watchlist.map(w => (
          <div key={w.username} className="flex items-center gap-2.5 rounded-lg px-3 py-2.5"
            style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
            <div className="h-7 w-7 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
              style={{ background: `${RISK_COLOR(w.score)}18`, color: RISK_COLOR(w.score) }}>
              {w.username.charAt(0).toUpperCase()}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{w.username}</p>
              <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{w.category} · Added {timeAgo(w.added_at)}</p>
            </div>
            <RiskBadge score={w.score} />
            <button onClick={() => onRemove(w.username)} className="g-btn g-btn-ghost text-xs px-2">
              {loadingUser === w.username ? <Loader2 className="h-3 w-3 animate-spin" /> : <Trash2 className="h-3 w-3" />}
            </button>
          </div>
        ))
      }
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function InsiderThreatPage() {
  const [scores,     setScores]     = useState<InsiderScore[]>([]);
  const [analytics,  setAnalytics]  = useState<Analytics | null>(null);
  const [watchlist,  setWatchlist]  = useState<WatchEntry[]>([]);
  const [policies,   setPolicies]   = useState<Policy[]>([]);
  const [violations, setViolations] = useState<PolicyViolation[]>([]);
  const [loading,    setLoading]    = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selected,   setSelected]   = useState<InsiderScore | null>(null);
  const [view,       setView]       = useState<'users' | 'analytics' | 'policy' | 'watchlist'>('users');
  const [searchQ,    setSearchQ]    = useState('');
  const [riskFilter, setRiskFilter] = useState('all');
  const [days,       setDays]       = useState(7);
  const [watchLoading, setWatchLoading] = useState<string | null>(null);
  const [toast,      setToast]      = useState<string | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    const [sRes, aRes, wRes, pRes, vRes] = await Promise.allSettled([
      insiderThreatAPI.getScores(days, 0),
      insiderThreatAPI.getAnalytics(),
      insiderThreatAPI.getWatchlist(),
      insiderThreatAPI.getPolicies(),
      insiderThreatAPI.getPolicyViolations(),
    ]);
    if (sRes.status === 'fulfilled') setScores(Array.isArray(sRes.value.data) ? sRes.value.data : []);
    if (aRes.status === 'fulfilled' && aRes.value.data) setAnalytics(aRes.value.data as Analytics);
    if (wRes.status === 'fulfilled') setWatchlist(wRes.value.data?.watchlist ?? []);
    if (pRes.status === 'fulfilled') setPolicies(pRes.value.data?.policies ?? []);
    if (vRes.status === 'fulfilled') setViolations(vRes.value.data?.violations ?? []);
    setLoading(false); setRefreshing(false);
  }, [days]);

  useEffect(() => { load(); }, [load]);

  const addToWatchlist = async (username: string, category: string) => {
    try { await insiderThreatAPI.addToWatchlist(username, category); load(); notify(`${username} added`); }
    catch { notify('Failed to add'); }
  };

  const removeFromWatchlist = async (username: string) => {
    setWatchLoading(username);
    try { await insiderThreatAPI.removeFromWatchlist(username); setWatchlist(w => w.filter(e => e.username !== username)); notify(`${username} removed`); }
    catch { notify('Failed to remove'); }
    finally { setWatchLoading(null); }
  };

  const filtered = useMemo(() => {
    let s = [...scores];
    if (riskFilter === 'critical') s = s.filter(u => u.score >= 80);
    else if (riskFilter === 'high')    s = s.filter(u => u.score >= 60 && u.score < 80);
    else if (riskFilter === 'medium')  s = s.filter(u => u.score >= 30 && u.score < 60);
    else if (riskFilter === 'low')     s = s.filter(u => u.score < 30);
    if (searchQ) s = s.filter(u => u.username.toLowerCase().includes(searchQ.toLowerCase()));
    return s;
  }, [scores, riskFilter, searchQ]);

  const critCount = useMemo(() => scores.filter(s => s.score >= 80).length, [scores]);
  const highCount = useMemo(() => scores.filter(s => s.score >= 60).length, [scores]);
  const alertCount = useMemo(() => scores.filter(s => s.alert_fired).length, [scores]);

  if (selected) {
    return (
      <div className="h-screen flex overflow-hidden" style={{ background: 'var(--bg-0)' }}>
        {/* Compact list sidebar */}
        <div className="w-72 shrink-0 flex flex-col border-r" style={{ borderColor: 'var(--border)' }}>
          <div className="px-3 py-3 shrink-0" style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-1)' }}>
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
              <input value={searchQ} onChange={e => setSearchQ(e.target.value)}
                placeholder="Search…" className="g-input w-full text-xs pl-8" />
            </div>
          </div>
          <div className="flex-1 overflow-y-auto">
            {filtered.map(s => (
              <div key={`${s.username}-${s.score_date}`}
                onClick={() => setSelected(s)}
                className="flex items-center gap-2.5 px-3 py-3 cursor-pointer transition-colors border-b"
                style={{
                  borderColor: 'var(--border)',
                  background: selected?.username === s.username ? 'var(--accent-glow)' : undefined,
                  borderLeft: selected?.username === s.username ? '2px solid var(--accent)' : '2px solid transparent',
                }}>
                <div className="h-7 w-7 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
                  style={{ background: `${RL_COLOR[s.risk_level] ?? 'var(--text-3)'}18`, color: RL_COLOR[s.risk_level] ?? 'var(--text-3)' }}>
                  {s.username.charAt(0).toUpperCase()}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>{s.username}</p>
                  <div className="h-1.5 rounded-full overflow-hidden mt-1" style={{ background: 'var(--border)' }}>
                    <div className="h-full rounded-full" style={{ width: `${s.score}%`, background: RL_COLOR[s.risk_level] ?? 'var(--text-3)' }} />
                  </div>
                </div>
                <span className="text-[10px] font-bold shrink-0" style={{ color: RL_COLOR[s.risk_level] ?? 'var(--text-3)' }}>{s.score}</span>
                {s.alert_fired && <ShieldAlert className="h-3 w-3 shrink-0" style={{ color: 'var(--red)' }} />}
              </div>
            ))}
          </div>
        </div>
        <div className="flex-1 overflow-hidden">
          <UserDetailPanel score={selected} onClose={() => setSelected(null)} />
        </div>
      </div>
    );
  }

  return (
    <RootLayout title="Insider Threat" subtitle="User & data risk monitoring"
      onRefresh={() => load(true)} refreshing={refreshing}>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 px-4 py-2.5 rounded-lg text-sm font-medium shadow-xl"
          style={{ background: 'var(--accent)', color: '#000' }}>{toast}</div>
      )}

      <div className="space-y-4">

        {/* KPI strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
          {[
            { l: 'Total Users',     v: scores.length,                  icon: Users,      c: 'var(--accent)' },
            { l: 'Critical',        v: critCount,                       icon: UserX,      c: 'var(--red)' },
            { l: 'High Risk',       v: highCount,                       icon: AlertTriangle, c: 'var(--orange)' },
            { l: 'Alerts Fired',    v: alertCount,                      icon: ShieldAlert, c: 'var(--red)' },
            { l: 'Policy Violations',v: violations.length,             icon: Shield,     c: 'var(--yellow)' },
            { l: 'Watchlisted',     v: watchlist.length,               icon: Star,       c: 'var(--accent)' },
          ].map(({ l, v, icon: Icon, c }) => (
            <div key={l} className="g-card p-3 flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg shrink-0" style={{ background: `${c}18` }}>
                <Icon className="h-4 w-4" style={{ color: c }} />
              </div>
              <div>
                <p className="text-base font-bold tabular-nums" style={{ color: c }}>{v}</p>
                <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{l}</p>
              </div>
            </div>
          ))}
        </div>

        {/* View tabs */}
        <div className="flex items-center gap-2 flex-wrap">
          {([['users', 'High-Risk Users'], ['analytics', 'Analytics'], ['policy', 'Policy Engine'], ['watchlist', 'Watchlists']] as const).map(([v, l]) => (
            <button key={v} onClick={() => setView(v)}
              className="g-btn text-xs"
              style={{
                background: view === v ? 'var(--accent-glow)' : 'var(--glass-bg)',
                color: view === v ? 'var(--accent)' : 'var(--text-2)',
                border: `1px solid ${view === v ? 'var(--accent-border)' : 'var(--border)'}`,
              }}>{l}
            </button>
          ))}
          <select value={days} onChange={e => setDays(+e.target.value)} className="g-select text-xs ml-auto">
            {[1, 7, 14, 30, 90].map(d => <option key={d} value={d}>Last {d}d</option>)}
          </select>
        </div>

        {view === 'analytics' && (
          <div className="g-card overflow-hidden">
            <SectionHeader icon={BarChart2} title="Insider Threat Analytics" />
            <AnalyticsDashboard analytics={analytics} />
          </div>
        )}

        {view === 'policy' && (
          <div className="g-card overflow-hidden">
            <SectionHeader icon={Shield} title="Policy Engine" />
            <PolicyEnginePanel policies={policies} onAdd={load} />
          </div>
        )}

        {view === 'watchlist' && (
          <div className="g-card overflow-hidden">
            <SectionHeader icon={Star} title="Insider Threat Watchlists" />
            <WatchlistPanel watchlist={watchlist} onAdd={addToWatchlist} onRemove={removeFromWatchlist} loadingUser={watchLoading} />
          </div>
        )}

        {view === 'users' && (
          <>
            {/* Filters */}
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
                <input value={searchQ} onChange={e => setSearchQ(e.target.value)}
                  placeholder="Search users…" className="g-input w-full text-xs pl-8" />
                {searchQ && <button onClick={() => setSearchQ('')} className="absolute right-2.5 top-1/2 -translate-y-1/2"><X className="h-3 w-3" style={{ color: 'var(--text-3)' }} /></button>}
              </div>
              <div className="flex items-center gap-1">
                <Filter className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
                {[
                  { val: 'all', label: 'All' },
                  { val: 'critical', label: 'Critical (80+)' },
                  { val: 'high',     label: 'High (60+)' },
                  { val: 'medium',   label: 'Medium (30+)' },
                  { val: 'low',      label: 'Low' },
                ].map(f => (
                  <button key={f.val} onClick={() => setRiskFilter(f.val)}
                    className="px-2.5 py-1 text-[11px] rounded-lg transition-all"
                    style={{
                      background: riskFilter === f.val ? 'var(--accent-glow)' : 'var(--glass-bg)',
                      border: `1px solid ${riskFilter === f.val ? 'var(--accent-border)' : 'var(--border)'}`,
                      color: riskFilter === f.val ? 'var(--accent)' : 'var(--text-2)',
                    }}>
                    {f.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Table */}
            <div className="g-table">
              <div className="g-thead grid gap-3 px-4"
                style={{ gridTemplateColumns: '28px 1fr 100px 120px 80px 80px 80px 28px' }}>
                <span /><span>User</span><span>Risk Level</span><span>Score</span>
                <span>Off-Hrs</span><span>Failed</span><span>Exfil</span><span />
              </div>
              {loading
                ? <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading insider threat data…</div>
                : filtered.length === 0
                  ? (
                    <div className="py-16 text-center">
                      <UserX className="mx-auto h-8 w-8 mb-2 opacity-20" style={{ color: 'var(--text-3)' }} />
                      <p className="text-sm" style={{ color: 'var(--text-2)' }}>
                        {scores.length === 0 ? 'No scores yet — scores compute every 6 hours from auth, exfil, and privilege signals.' : 'No users match filter.'}
                      </p>
                    </div>
                  )
                  : filtered.map(s => {
                    const color = RL_COLOR[s.risk_level] ?? 'var(--text-3)';
                    return (
                      <div key={`${s.username}-${s.score_date}`}
                        onClick={() => setSelected(s)}
                        className="g-tr grid gap-3 items-center px-4 cursor-pointer"
                        style={{ gridTemplateColumns: '28px 1fr 100px 120px 80px 80px 80px 28px' }}>
                        <div className="h-7 w-7 rounded-full flex items-center justify-center text-xs font-bold"
                          style={{ background: `${color}18`, color }}>
                          {s.username.charAt(0).toUpperCase()}
                        </div>
                        <div className="min-w-0">
                          <p className="text-xs font-semibold truncate" style={{ color: 'var(--text-1)' }}>{s.username}</p>
                          <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{s.score_date}</p>
                        </div>
                        <RiskBadge level={s.risk_level} />
                        <div className="flex items-center gap-2">
                          <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--border)' }}>
                            <div className="h-full rounded-full" style={{ width: `${s.score}%`, background: color }} />
                          </div>
                          <span className="text-xs font-bold tabular-nums w-6 text-right" style={{ color }}>{s.score}</span>
                        </div>
                        <span className="text-xs tabular-nums font-mono" style={{ color: (s.contributors?.off_hours_auth ?? 0) > 0 ? 'var(--orange)' : 'var(--text-3)' }}>
                          {s.contributors?.off_hours_auth ?? 0}
                        </span>
                        <span className="text-xs tabular-nums font-mono" style={{ color: (s.contributors?.failed_auth ?? 0) > 0 ? 'var(--red)' : 'var(--text-3)' }}>
                          {s.contributors?.failed_auth ?? 0}
                        </span>
                        <span className="text-xs tabular-nums font-mono" style={{ color: (s.contributors?.data_exfil ?? 0) > 0 ? 'var(--red)' : 'var(--text-3)' }}>
                          {s.contributors?.data_exfil ?? 0}
                        </span>
                        <ChevronRight className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
                      </div>
                    );
                  })
              }
            </div>

            {!loading && (
              <div className="g-card px-4 py-3">
                <p className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>Score Components</p>
                <div className="flex gap-6 flex-wrap text-[11px]" style={{ color: 'var(--text-3)' }}>
                  <span><span style={{ color: 'var(--orange)' }} className="font-bold">off_hours_auth</span> max 20</span>
                  <span><span style={{ color: 'var(--red)' }} className="font-bold">failed_auth</span> max 15</span>
                  <span><span style={{ color: 'var(--red)' }} className="font-bold">data_exfil</span> max 25</span>
                  <span><span style={{ color: 'var(--yellow)' }} className="font-bold">sensitive_access</span> max 15</span>
                  <span><span style={{ color: 'var(--orange)' }} className="font-bold">privesc_attempt</span> max 15</span>
                  <span><span style={{ color: 'var(--yellow)' }} className="font-bold">anomalous_location</span> max 10</span>
                  <span className="ml-auto">Scores recomputed every 6h · 7-day rolling window · Alerts fire at 60+</span>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </RootLayout>
  );
}
