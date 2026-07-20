'use client';

import { useEffect, useState, useCallback, useMemo } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { uebaAPI } from '@/lib/api';
import { UserRiskProfile, UEBAEvent } from '@/types';
import { timeAgo, formatDate } from '@/lib/utils';
import Link from 'next/link';
import { Activity, AlertTriangle, ArrowUpRight, Ban, BarChart2, Bot, Check, CheckCircle2, ChevronRight, Clock, Cpu, Crosshair, Database, FileText, Filter, GitBranch, Globe2, KeyRound, Loader2, LogOut, Network, Package, Play, Plus, RefreshCw, Search, Server, Shield, Star, Target, Terminal, Trash2, TrendingUp, User, Users, Wifi, X, XCircle, Zap, Lock } from '@/lib/icon-stubs';

// ── Types ─────────────────────────────────────────────────────────────────────

interface UserDetail {
  profile: UserRiskProfile;
  recent_events: UEBAEvent[];
  total_events: number;
  alert_count: number;
  incident_count: number;
  known_ips: Array<{ ip: string; count: number; last_seen: string }>;
}

interface PeerComparison {
  user: {
    risk_score: number; total_events: number; failed_logins: number;
    off_hours_events: number; unique_ips: number; privilege_escalations: number;
  };
  peers: {
    avg_risk_score: number; avg_total_events: number; avg_failed_logins: number;
    avg_off_hours: number; avg_unique_ips: number; avg_priv_escalations: number;
    total_peers: number;
  };
  outliers: Array<{ username: string; risk_score: number; metric: string; value: number }>;
}

interface AIInsights {
  narrative: string;
  risk_reason: string;
  anomalies: string[];
  mitre_techniques: string[];
  recommendation: string;
}

interface Analytics {
  high_risk_users: Array<{ username: string; source: string; risk_score: number; flags: string[] }>;
  top_anomalies: Array<{ event_type: string; count: number }>;
  risk_distribution: Array<{ label: string; count: number }>;
  trend: Array<{ day: string; count: number }>;
  total_users: number;
  total_events_7d: number;
  insider_threat_score: number;
}

interface WatchEntry {
  username: string; category: string; added_at: string; added_by: string; risk_score: number;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const RISK_COLOR = (score: number) =>
  score >= 80 ? 'var(--red)' : score >= 60 ? 'var(--orange)' : score >= 30 ? 'var(--yellow)' : 'var(--green)';

const RISK_LABEL = (score: number) =>
  score >= 80 ? 'Critical' : score >= 60 ? 'High' : score >= 30 ? 'Medium' : 'Low';

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)',
  low: 'var(--green)', info: 'var(--text-3)',
};

const MITRE_COLORS = ['var(--red)', 'var(--orange)', 'var(--yellow)', 'var(--accent)', 'var(--green)'];

const WATCH_CATEGORIES = ['VIP', 'Admin', 'Finance', 'HR', 'Contractor', 'Executive', 'Service Account', 'General'];

// ── Small helpers ─────────────────────────────────────────────────────────────

function RiskBar({ score, showLabel = true }: { score: number; showLabel?: boolean }) {
  const color = RISK_COLOR(score);
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background:'var(--border)' }}>
        <div className="h-full rounded-full transition-all" style={{ width:`${score}%`, background:color }} />
      </div>
      {showLabel && <span className="text-xs tabular-nums font-bold w-6 text-right" style={{ color }}>{score}</span>}
    </div>
  );
}

function RiskBadge({ score }: { score: number }) {
  const color = RISK_COLOR(score);
  return (
    <span className="text-[10px] px-2 py-0.5 rounded font-bold"
      style={{ background:`${color}18`, color, border:`1px solid ${color}44` }}>
      {RISK_LABEL(score)}
    </span>
  );
}

function FlagChip({ flag }: { flag: string }) {
  return (
    <span className="text-[9px] px-1.5 py-0.5 rounded font-medium capitalize"
      style={{ background:'var(--orange)18', color:'var(--orange)', border:'1px solid var(--orange)33' }}>
      {flag.replace(/_/g,' ')}
    </span>
  );
}

function SectionHeader({ icon: Icon, title, action }: { icon: any; title: string; action?: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 px-4 py-2.5 shrink-0"
      style={{ borderBottom:'1px solid var(--border)', background:'var(--glass-bg)' }}>
      <Icon className="h-3.5 w-3.5 shrink-0" style={{ color:'var(--accent)' }} />
      <span className="text-[10px] font-bold uppercase tracking-wider flex-1" style={{ color:'var(--text-3)' }}>{title}</span>
      {action}
    </div>
  );
}

function Spinner() {
  return <Loader2 className="h-4 w-4 animate-spin mx-auto" style={{ color:'var(--text-3)' }} />;
}

function Empty({ icon: Icon, text }: { icon: any; text: string }) {
  return (
    <div className="py-8 text-center space-y-2">
      <Icon className="h-7 w-7 mx-auto opacity-15" style={{ color:'var(--text-3)' }} />
      <p className="text-xs" style={{ color:'var(--text-3)' }}>{text}</p>
    </div>
  );
}

// ── Behavioral Baseline card ──────────────────────────────────────────────────

function BaselineCard({ profile }: { profile: UserRiskProfile }) {
  const items = [
    { label:'Working Hours',   val:'9AM – 6PM',        icon:Clock },
    { label:'Login Frequency', val:`${profile.total_events} / 7d`, icon:Activity },
    { label:'Known IPs',       val:`${profile.unique_ips}`,        icon:Globe2 },
    { label:'Source',          val:profile.source,                  icon:Database },
    { label:'Last Seen IP',    val:profile.last_seen_ip || '—',     icon:Wifi },
    { label:'Off-Hours',       val:`${profile.off_hours_events}`,   icon:Clock },
  ];
  return (
    <div className="p-3 space-y-1.5">
      {items.map(i => (
        <div key={i.label} className="flex items-center gap-2.5">
          <i.icon className="h-3.5 w-3.5 shrink-0" style={{ color:'var(--accent)' }} />
          <span className="text-[11px] w-28 shrink-0" style={{ color:'var(--text-3)' }}>{i.label}</span>
          <span className="text-[11px] font-mono font-medium" style={{ color:'var(--text-1)' }}>{i.val}</span>
        </div>
      ))}
    </div>
  );
}

// ── Login Analytics card ──────────────────────────────────────────────────────

function LoginAnalyticsCard({ profile, events }: { profile: UserRiskProfile; events: UEBAEvent[] }) {
  const loginEvents = events.filter(e =>
    ['failed_login', 'login', 'off_hours_login', 'brute_force'].includes(e.event_type));
  const anomalies = [
    profile.flags.includes('impossible_travel')    && { label:'Impossible Travel',    color:'var(--red)' },
    profile.off_hours_events > 0                   && { label:`Off-Hours Logins (${profile.off_hours_events})`, color:'var(--orange)' },
    profile.failed_logins > 0                      && { label:`Failed Logins (${profile.failed_logins})`, color:'var(--red)' },
    profile.flags.includes('brute_force')          && { label:'Brute Force Detected', color:'var(--red)' },
    profile.flags.includes('password_spray')       && { label:'Password Spraying',   color:'var(--red)' },
    profile.flags.includes('credential_stuffing')  && { label:'Credential Stuffing', color:'var(--red)' },
    profile.unique_ips > 3                         && { label:`Multiple IPs (${profile.unique_ips})`, color:'var(--yellow)' },
  ].filter(Boolean) as Array<{ label: string; color: string }>;

  return (
    <div className="p-3 space-y-2">
      <div className="grid grid-cols-3 gap-2">
        {[
          { label:'Failed', val:profile.failed_logins, color:'var(--red)' },
          { label:'Off-Hrs', val:profile.off_hours_events, color:'var(--orange)' },
          { label:'IPs', val:profile.unique_ips, color:'var(--yellow)' },
        ].map(s => (
          <div key={s.label} className="rounded-xl px-3 py-2 text-center"
            style={{ background:'var(--glass-bg)', border:`1px solid ${s.color}33` }}>
            <p className="text-lg font-bold tabular-nums" style={{ color:s.color }}>{s.val}</p>
            <p className="text-[9px]" style={{ color:'var(--text-3)' }}>{s.label}</p>
          </div>
        ))}
      </div>
      {anomalies.length > 0 && (
        <div className="space-y-1">
          {anomalies.map(a => (
            <div key={a.label} className="flex items-center gap-2 text-[11px]">
              <AlertTriangle className="h-3 w-3 shrink-0" style={{ color:a.color }} />
              <span style={{ color:a.color }}>{a.label}</span>
            </div>
          ))}
        </div>
      )}
      {anomalies.length === 0 && <p className="text-xs" style={{ color:'var(--text-3)' }}>No login anomalies detected.</p>}
    </div>
  );
}

// ── Timeline feed ─────────────────────────────────────────────────────────────

const EVENT_ICONS: Record<string, any> = {
  failed_login: XCircle, login: CheckCircle2, off_hours_login: Clock,
  priv_escalation: TrendingUp, priv_change: Shield, brute_force: Zap,
  sudo: Terminal, analyst_action: User, file_access: FileText,
  network: Wifi, process: Cpu, dns: Globe2, usb: Package,
};

function TimelineFeed({ events, loading }: { events: UEBAEvent[]; loading: boolean }) {
  if (loading) return <div className="p-6"><Spinner /></div>;
  if (events.length === 0) return <Empty icon={Clock} text="No events found." />;
  return (
    <div className="relative px-4 py-3 space-y-3">
      <div className="absolute left-6 top-0 bottom-0 w-px" style={{ background:'var(--border)' }} />
      {events.map((ev, i) => {
        const Icon = EVENT_ICONS[ev.event_type] ?? Activity;
        const color = SEV_COLOR[ev.severity] ?? 'var(--text-3)';
        return (
          <div key={i} className="relative pl-5">
            <div className="absolute left-0 top-0.5 h-4 w-4 rounded-full flex items-center justify-center"
              style={{ background:`${color}18`, border:`1px solid ${color}44` }}>
              <Icon className="h-2.5 w-2.5" style={{ color }} />
            </div>
            <div className="flex items-start justify-between gap-2">
              <div>
                <span className="text-[10px] font-bold uppercase" style={{ color:'var(--text-3)' }}>
                  {ev.event_type.replace(/_/g,' ')}
                </span>
                {ev.source_ip && (
                  <span className="text-[10px] ml-2 font-mono" style={{ color:'var(--text-3)' }}>from {ev.source_ip}</span>
                )}
                <p className="text-xs mt-0.5 leading-relaxed" style={{ color:'var(--text-1)' }}>{ev.description}</p>
              </div>
              <span className="text-[10px] shrink-0" style={{ color:'var(--text-3)' }}>
                {timeAgo(ev.detected_at)}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Peer Comparison ───────────────────────────────────────────────────────────

function PeerCard({ data, loading }: { data: PeerComparison | null; loading: boolean }) {
  if (loading) return <div className="p-6"><Spinner /></div>;
  if (!data) return <Empty icon={Users} text="Peer data unavailable." />;
  const metrics = [
    { label:'Risk Score',    user: data.user.risk_score,          peer: data.peers.avg_risk_score,        fmt: (v: number) => v.toFixed(0) },
    { label:'Total Events',  user: data.user.total_events,        peer: data.peers.avg_total_events,      fmt: (v: number) => v.toFixed(1) },
    { label:'Failed Logins', user: data.user.failed_logins,       peer: data.peers.avg_failed_logins,     fmt: (v: number) => v.toFixed(1) },
    { label:'Off-Hours',     user: data.user.off_hours_events,    peer: data.peers.avg_off_hours,         fmt: (v: number) => v.toFixed(1) },
    { label:'Unique IPs',    user: data.user.unique_ips,          peer: data.peers.avg_unique_ips,        fmt: (v: number) => v.toFixed(1) },
    { label:'Priv Escalations', user: data.user.privilege_escalations, peer: data.peers.avg_priv_escalations, fmt: (v: number) => v.toFixed(1) },
  ];
  return (
    <div className="p-3 space-y-2.5">
      <p className="text-[10px]" style={{ color:'var(--text-3)' }}>Compared to {data.peers.total_peers} peers</p>
      {metrics.map(m => {
        const ratio = m.peer > 0 ? m.user / m.peer : 1;
        const high = ratio > 2;
        const color = high ? 'var(--red)' : ratio > 1.3 ? 'var(--orange)' : 'var(--green)';
        return (
          <div key={m.label}>
            <div className="flex items-center justify-between mb-1">
              <span className="text-[11px]" style={{ color:'var(--text-2)' }}>{m.label}</span>
              <div className="flex items-center gap-3 text-[11px]">
                <span className="font-mono font-bold" style={{ color }}>{m.fmt(m.user)}</span>
                <span style={{ color:'var(--text-3)' }}>vs {m.fmt(m.peer)} avg</span>
                {high && <ArrowUpRight className="h-3 w-3" style={{ color:'var(--red)' }} />}
              </div>
            </div>
            <div className="h-1.5 rounded-full overflow-hidden relative" style={{ background:'var(--border)' }}>
              <div className="absolute left-0 top-0 h-full rounded-full" style={{ width:`${Math.min(100,(m.peer/Math.max(m.user,m.peer))*100)}%`, background:'var(--text-3)', opacity:0.4 }} />
              <div className="absolute left-0 top-0 h-full rounded-full" style={{ width:`${Math.min(100,(m.user/Math.max(m.user,m.peer,1))*100)}%`, background:color }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Anomaly Detection ─────────────────────────────────────────────────────────

function AnomalyCard({ profile, events }: { profile: UserRiskProfile; events: UEBAEvent[] }) {
  const flaggedTypes = new Set(events.map(e => e.event_type));
  const anomalies = [
    { label:'First Time Seen',       detected: profile.total_events <= 1 },
    { label:'Rare Process',          detected: flaggedTypes.has('rare_process') },
    { label:'Rare Application',      detected: flaggedTypes.has('rare_app') },
    { label:'Rare Country',          detected: profile.flags.includes('impossible_travel') },
    { label:'Rare Device',           detected: profile.flags.includes('new_device') },
    { label:'Rare Network',          detected: profile.flags.includes('rare_network') },
    { label:'Rare Parent Process',   detected: flaggedTypes.has('rare_parent_process') },
    { label:'Rare Command Line',     detected: flaggedTypes.has('powershell') || flaggedTypes.has('bash') },
    { label:'Privilege Escalation',  detected: profile.privilege_escalations > 0 },
    { label:'Off-Hours Activity',    detected: profile.off_hours_events > 0 },
    { label:'Brute Force',           detected: profile.flags.includes('brute_force') },
    { label:'Mass File Access',      detected: flaggedTypes.has('mass_file_access') },
  ];
  const detected = anomalies.filter(a => a.detected);
  return (
    <div className="p-3">
      {detected.length === 0
        ? <p className="text-xs" style={{ color:'var(--text-3)' }}>No anomalies detected — user behavior is within baseline.</p>
        : (
          <div className="grid grid-cols-2 gap-1.5">
            {detected.map(a => (
              <div key={a.label} className="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5"
                style={{ background:'var(--red)10', border:'1px solid var(--red)33' }}>
                <AlertTriangle className="h-3 w-3 shrink-0" style={{ color:'var(--red)' }} />
                <span className="text-[11px]" style={{ color:'var(--text-1)' }}>{a.label}</span>
              </div>
            ))}
          </div>
        )
      }
    </div>
  );
}

// ── Entity Relationships ──────────────────────────────────────────────────────

function EntityGraph({ profile, detail }: { profile: UserRiskProfile; detail: UserDetail | null }) {
  const nodes = [
    { label: profile.username,          sub:'User',          icon:User,     color:'var(--accent)' },
    { label: profile.last_seen_ip || '—', sub:'Last IP',    icon:Globe2,   color:'var(--blue)' },
    { label: 'VPN Gateway',             sub:'Network',        icon:Wifi,     color:'var(--yellow)' },
    { label: detail?.alert_count ? `${detail.alert_count} Alerts` : 'No Alerts', sub:'Alerts', icon:AlertTriangle, color: detail?.alert_count ? 'var(--orange)' : 'var(--text-3)' },
    { label: detail?.incident_count ? `${detail.incident_count} Incidents` : 'No Incidents', sub:'Incidents', icon:Shield, color: detail?.incident_count ? 'var(--red)' : 'var(--text-3)' },
    { label: 'Cloud Account',           sub:'Cloud',          icon:Database, color:'var(--accent)' },
  ];
  return (
    <div className="p-3 space-y-1.5">
      {nodes.map((n, i) => (
        <div key={n.label}>
          <div className="flex items-center gap-2 rounded-lg px-3 py-2"
            style={{ background:'var(--glass-bg)', border:`1px solid ${n.color}44`, marginLeft:`${i * 8}px` }}>
            <n.icon className="h-3.5 w-3.5 shrink-0" style={{ color:n.color }} />
            <span className="text-xs font-medium flex-1" style={{ color:'var(--text-1)' }}>{n.label}</span>
            <span className="text-[10px]" style={{ color:'var(--text-3)' }}>{n.sub}</span>
          </div>
          {i < nodes.length - 1 && (
            <div className="h-1.5 w-px ml-4" style={{ background:'var(--border)' }} />
          )}
        </div>
      ))}
    </div>
  );
}

// ── Endpoint Behavior ─────────────────────────────────────────────────────────

function EndpointBehaviorCard({ events }: { events: UEBAEvent[] }) {
  const eTypes = new Set(events.map(e => e.event_type));
  const tracked = [
    { label:'PowerShell Usage',    detected: eTypes.has('powershell'),        color:'var(--orange)' },
    { label:'Bash Activity',       detected: eTypes.has('bash'),               color:'var(--yellow)' },
    { label:'Privilege Escalation',detected: eTypes.has('priv_escalation'),   color:'var(--red)' },
    { label:'Sudo Usage',          detected: eTypes.has('sudo'),               color:'var(--orange)' },
    { label:'New Service',         detected: eTypes.has('new_service'),        color:'var(--yellow)' },
    { label:'Registry Change',     detected: eTypes.has('registry'),           color:'var(--yellow)' },
    { label:'Process Injection',   detected: eTypes.has('process_injection'),  color:'var(--red)' },
    { label:'Persistence',         detected: eTypes.has('persistence'),        color:'var(--red)' },
  ];
  return (
    <div className="p-3 grid grid-cols-2 gap-1.5">
      {tracked.map(t => (
        <div key={t.label} className="flex items-center gap-1.5 text-[11px] py-0.5">
          {t.detected
            ? <AlertTriangle className="h-3 w-3 shrink-0" style={{ color:t.color }} />
            : <Check className="h-3 w-3 shrink-0" style={{ color:'var(--text-3)' }} />}
          <span style={{ color: t.detected ? t.color : 'var(--text-3)' }}>{t.label}</span>
        </div>
      ))}
    </div>
  );
}

// ── Network Behavior ──────────────────────────────────────────────────────────

function NetworkBehaviorCard({ events, detail }: { events: UEBAEvent[]; detail: UserDetail | null }) {
  const behaviors = [
    { label:'Beaconing Detected',    icon:Wifi,    val: 'No', color:'var(--text-3)' },
    { label:'DNS Tunneling',         icon:Globe2,  val: 'No', color:'var(--text-3)' },
    { label:'Lateral Movement',      icon:Network, val: events.some(e=>e.event_type==='lateral_movement')?'Yes':'No', color: events.some(e=>e.event_type==='lateral_movement')?'var(--red)':'var(--text-3)' },
    { label:'Data Exfiltration',     icon:ArrowUpRight, val: events.some(e=>e.event_type==='exfiltration')?'Yes':'No', color: events.some(e=>e.event_type==='exfiltration')?'var(--red)':'var(--text-3)' },
    { label:'Unique IPs',            icon:Globe2,  val:`${detail?.profile.unique_ips ?? 0}`, color:'var(--text-1)' },
    { label:'VPN Sessions',          icon:Lock,    val: events.filter(e=>e.event_type==='vpn').length.toString(), color:'var(--text-1)' },
    { label:'RDP Sessions',          icon:Monitor,  val: events.filter(e=>e.event_type==='rdp').length.toString(), color:'var(--text-1)' },
    { label:'SSH Sessions',          icon:Terminal, val: events.filter(e=>e.event_type==='ssh').length.toString(), color:'var(--text-1)' },
  ];
  return (
    <div className="p-3 space-y-2">
      {behaviors.map(b => (
        <div key={b.label} className="flex items-center gap-2.5">
          <b.icon className="h-3.5 w-3.5 shrink-0" style={{ color:'var(--accent)' }} />
          <span className="text-[11px] flex-1" style={{ color:'var(--text-3)' }}>{b.label}</span>
          <span className="text-[11px] font-semibold" style={{ color:b.color }}>{b.val}</span>
        </div>
      ))}
    </div>
  );
}

// Need a Monitor icon substitute
function Monitor(props: any) { return <Cpu {...props} />; }

// ── File Behavior ─────────────────────────────────────────────────────────────

function FileBehaviorCard({ profile, events }: { profile: UserRiskProfile; events: UEBAEvent[] }) {
  const fileFlags = [
    { label:'Mass File Access',      detected: profile.flags.includes('mass_file_access'),    color:'var(--red)' },
    { label:'Mass File Deletion',    detected: profile.flags.includes('mass_file_deletion'),  color:'var(--red)' },
    { label:'Sensitive File Access', detected: profile.flags.includes('sensitive_file'),      color:'var(--orange)' },
    { label:'Encryption Activity',   detected: profile.flags.includes('encryption'),          color:'var(--orange)' },
    { label:'USB Copy Detected',     detected: profile.flags.includes('usb_copy'),            color:'var(--red)' },
    { label:'Cloud Upload',          detected: profile.flags.includes('cloud_upload'),        color:'var(--yellow)' },
    { label:'Source Code Access',    detected: profile.flags.includes('source_code'),         color:'var(--red)' },
    { label:'File Uploads',          detected: events.some(e=>e.event_type==='file_upload'), color:'var(--yellow)' },
  ];
  return (
    <div className="p-3 grid grid-cols-2 gap-1.5">
      {fileFlags.map(f => (
        <div key={f.label} className="flex items-center gap-1.5 text-[11px] py-0.5">
          {f.detected
            ? <AlertTriangle className="h-3 w-3 shrink-0" style={{ color:f.color }} />
            : <Check className="h-3 w-3 shrink-0" style={{ color:'var(--text-3)' }} />}
          <span style={{ color: f.detected ? f.color : 'var(--text-3)' }}>{f.label}</span>
        </div>
      ))}
    </div>
  );
}

// ── Risk Score Card ───────────────────────────────────────────────────────────

function RiskScoreCard({ profile }: { profile: UserRiskProfile }) {
  const color = RISK_COLOR(profile.risk_score);
  const circ = 2 * Math.PI * 36;
  const offset = circ * (1 - profile.risk_score / 100);
  return (
    <div className="p-4 flex items-center gap-4">
      <div className="relative h-24 w-24 shrink-0">
        <svg className="h-24 w-24 -rotate-90" viewBox="0 0 80 80">
          <circle cx="40" cy="40" r="36" fill="none" strokeWidth="8" stroke="var(--border)" />
          <circle cx="40" cy="40" r="36" fill="none" strokeWidth="8"
            stroke={color} strokeLinecap="round" strokeDasharray={circ} strokeDashoffset={offset}
            style={{ transition:'stroke-dashoffset 0.8s ease' }} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold tabular-nums" style={{ color }}>{profile.risk_score}</span>
          <span className="text-[9px] font-semibold" style={{ color:'var(--text-3)' }}>/100</span>
        </div>
      </div>
      <div className="flex-1 space-y-2">
        <div>
          <p className="text-lg font-bold" style={{ color }}>{RISK_LABEL(profile.risk_score)}</p>
          <p className="text-xs" style={{ color:'var(--text-3)' }}>Risk Classification</p>
        </div>
        {profile.flags.length > 0 && (
          <div>
            <p className="text-[10px] font-bold uppercase tracking-wider mb-1" style={{ color:'var(--text-3)' }}>Risk Drivers</p>
            <div className="flex flex-wrap gap-1">
              {profile.flags.map(f => <FlagChip key={f} flag={f} />)}
            </div>
          </div>
        )}
        <div className="flex gap-3 text-[11px]">
          {[
            { l:'Failed', v:profile.failed_logins, c:'var(--red)' },
            { l:'Off-Hrs', v:profile.off_hours_events, c:'var(--orange)' },
            { l:'Priv Esc', v:profile.privilege_escalations, c:'var(--yellow)' },
          ].map(s => (
            <div key={s.l}>
              <span style={{ color:s.c }} className="font-bold">{s.v}</span>
              <span style={{ color:'var(--text-3)' }}> {s.l}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── AI Insights Panel ─────────────────────────────────────────────────────────

function AIInsightsPanel({ username }: { username: string }) {
  const [insights, setInsights] = useState<AIInsights | null>(null);
  const [loading,  setLoading]  = useState(false);

  const run = async () => {
    setLoading(true); setInsights(null);
    try {
      const r = await uebaAPI.getAIInsights(username);
      setInsights(r.data as AIInsights);
    } catch {}
    finally { setLoading(false); }
  };

  return (
    <div className="p-4 space-y-3">
      {loading && <div className="flex justify-center py-4"><Spinner /></div>}
      {!loading && !insights && (
        <div className="text-center py-6 space-y-2">
          <Bot className="h-8 w-8 mx-auto opacity-15" style={{ color:'var(--accent)' }} />
          <p className="text-xs" style={{ color:'var(--text-3)' }}>AI will analyze login patterns, device usage, and behavioral anomalies.</p>
          <button onClick={run} className="g-btn g-btn-primary text-xs mx-auto"><Bot className="h-3.5 w-3.5" /> Run AI Analysis</button>
        </div>
      )}
      {insights && (
        <div className="space-y-3">
          <div className="rounded-xl p-3" style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
            <p className="text-xs leading-relaxed" style={{ color:'var(--text-1)' }}>"{insights.narrative}"</p>
          </div>
          <div className="rounded-xl p-3" style={{ background:'var(--accent-glow)', border:'1px solid var(--accent-border)' }}>
            <p className="text-[10px] font-semibold mb-1" style={{ color:'var(--text-3)' }}>Primary Risk Factor</p>
            <p className="text-xs" style={{ color:'var(--accent)' }}>{insights.risk_reason}</p>
          </div>
          {insights.anomalies?.length > 0 && (
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color:'var(--text-3)' }}>Anomalies Detected</p>
              {insights.anomalies.map((a, i) => (
                <div key={i} className="flex gap-2 text-xs py-1">
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0" style={{ color:'var(--orange)' }} />
                  <span style={{ color:'var(--text-2)' }}>{a}</span>
                </div>
              ))}
            </div>
          )}
          {insights.mitre_techniques?.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {insights.mitre_techniques.map((t, i) => (
                <span key={t} className="text-[10px] px-2.5 py-1 rounded-lg font-mono font-medium"
                  style={{ background:`${MITRE_COLORS[i%MITRE_COLORS.length]}18`, color:MITRE_COLORS[i%MITRE_COLORS.length], border:`1px solid ${MITRE_COLORS[i%MITRE_COLORS.length]}44` }}>
                  {t}
                </span>
              ))}
            </div>
          )}
          {insights.recommendation && (
            <div className="rounded-xl p-3" style={{ background:'var(--green)10', border:'1px solid var(--green)33' }}>
              <p className="text-[10px] font-semibold mb-1" style={{ color:'var(--text-3)' }}>Recommendation</p>
              <p className="text-xs" style={{ color:'var(--green)' }}>{insights.recommendation}</p>
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

// ── Response Actions ──────────────────────────────────────────────────────────

const RESPONSE_ACTIONS = [
  { key:'disable_user',     label:'Disable User',      icon:Ban,      color:'var(--red)',    desc:'Suspend AD / local account' },
  { key:'force_logout',     label:'Force Logout',      icon:LogOut,   color:'var(--red)',    desc:'Revoke all sessions' },
  { key:'reset_password',   label:'Reset Password',    icon:KeyRound, color:'var(--yellow)', desc:'Force password change' },
  { key:'require_mfa',      label:'Require MFA',       icon:Shield,   color:'var(--yellow)', desc:'Enforce MFA on next login' },
  { key:'block_vpn',        label:'Block VPN',         icon:Lock,     color:'var(--orange)', desc:'Revoke VPN certificates' },
  { key:'isolate_endpoint', label:'Isolate Endpoint',  icon:Server,   color:'var(--red)',    desc:'Network-isolate device' },
  { key:'kill_process',     label:'Kill Process',      icon:XCircle,  color:'var(--orange)', desc:'Kill by PID' },
  { key:'run_playbook',     label:'Run SOAR Playbook', icon:Play,     color:'var(--accent)', desc:'Trigger automated response' },
];

function ResponseActionsPanel({ username, onAction }: { username: string; onAction: (msg: string) => void }) {
  const [running, setRunning] = useState<string | null>(null);
  const [activeKey, setActiveKey] = useState<string | null>(null);
  const [param, setParam] = useState('');

  const PARAM_LABELS: Record<string, string> = {
    kill_process: 'PID', run_playbook: 'Playbook ID',
  };
  const needsParam = activeKey ? PARAM_LABELS[activeKey] : null;

  const dispatch = async (key: string, p = '') => {
    setRunning(key);
    try {
      const params: Record<string, string> = {};
      if (key === 'kill_process') params.pid = p;
      if (key === 'run_playbook') params.playbook_id = p;
      const r = await uebaAPI.responseAction(username, key, params);
      onAction((r.data as any)?.result ?? `${key} dispatched`);
      setActiveKey(null); setParam('');
    } catch { onAction('Action failed'); }
    finally { setRunning(null); }
  };

  return (
    <div className="p-3 space-y-2">
      {activeKey && needsParam && (
        <div className="flex items-center gap-2 rounded-lg px-3 py-2.5"
          style={{ background:'var(--glass-bg)', border:'1px solid var(--accent-border)' }}>
          <input value={param} onChange={e=>setParam(e.target.value)}
            placeholder={needsParam + '…'} className="g-input flex-1 text-xs"
            onKeyDown={e=>e.key==='Enter'&&param&&dispatch(activeKey,param)} />
          <button onClick={()=>param&&dispatch(activeKey,param)} disabled={!param||running===activeKey}
            className="g-btn g-btn-primary text-xs px-3">
            {running===activeKey?<Loader2 className="h-3 w-3 animate-spin"/>:'Run'}
          </button>
          <button onClick={()=>{setActiveKey(null);setParam('');}} className="g-btn g-btn-ghost text-xs px-2">
            <X className="h-3 w-3"/>
          </button>
        </div>
      )}
      <div className="grid grid-cols-2 gap-1.5">
        {RESPONSE_ACTIONS.map(a => (
          <button key={a.key}
            onClick={() => PARAM_LABELS[a.key] ? (setActiveKey(a.key), setParam('')) : dispatch(a.key)}
            disabled={running !== null}
            className="flex items-center gap-2 rounded-lg px-3 py-2 text-left hover:bg-[var(--glass-hover)] transition-colors"
            style={{ background:'var(--glass-bg)', border:`1px solid ${a.color}33` }}>
            {running===a.key
              ? <Loader2 className="h-3.5 w-3.5 animate-spin shrink-0" style={{ color:a.color }}/>
              : <a.icon className="h-3.5 w-3.5 shrink-0" style={{ color:a.color }}/>}
            <div className="min-w-0">
              <p className="text-[11px] font-medium truncate" style={{ color:'var(--text-1)' }}>{a.label}</p>
              <p className="text-[9px]" style={{ color:'var(--text-3)' }}>{a.desc}</p>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

// ── Analytics Dashboard (condensed) ──────────────────────────────────────────

function AnalyticsDashboard({ analytics }: { analytics: Analytics | null }) {
  if (!analytics) return <div className="p-4"><Spinner /></div>;
  const maxCount = Math.max(...(analytics.trend ?? []).map(t => t.count), 1);
  return (
    <div className="p-4 space-y-4">
      <div className="grid grid-cols-3 gap-2">
        {[
          { l:'Total Users',       v:analytics.total_users,           c:'var(--accent)' },
          { l:'Events (7d)',       v:analytics.total_events_7d,       c:'var(--orange)' },
          { l:'Insider Score',     v:`${analytics.insider_threat_score}%`, c: analytics.insider_threat_score > 60 ? 'var(--red)' : 'var(--text-2)' },
        ].map(s => (
          <div key={s.l} className="rounded-xl px-3 py-2.5 text-center"
            style={{ background:'var(--glass-bg)', border:`1px solid ${s.c}33` }}>
            <p className="text-lg font-bold tabular-nums" style={{ color:s.c }}>{s.v}</p>
            <p className="text-[9px]" style={{ color:'var(--text-3)' }}>{s.l}</p>
          </div>
        ))}
      </div>

      <div>
        <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color:'var(--text-3)' }}>Risk Distribution</p>
        {analytics.risk_distribution.map(b => (
          <div key={b.label} className="flex items-center gap-2 mb-1.5">
            <span className="text-[10px] capitalize w-14 shrink-0" style={{ color:'var(--text-3)' }}>{b.label}</span>
            <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background:'var(--border)' }}>
              <div className="h-full rounded-full" style={{
                width:`${(b.count/(analytics.total_users||1))*100}%`,
                background: b.label==='critical'?'var(--red)':b.label==='high'?'var(--orange)':b.label==='medium'?'var(--yellow)':'var(--green)'
              }} />
            </div>
            <span className="text-[10px] tabular-nums font-mono w-6 text-right" style={{ color:'var(--text-3)' }}>{b.count}</span>
          </div>
        ))}
      </div>

      {analytics.trend.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color:'var(--text-3)' }}>14-Day Event Trend</p>
          <div className="flex items-end gap-0.5 h-12">
            {analytics.trend.map(t => (
              <div key={t.day} className="flex-1 rounded-t" title={`${t.day}: ${t.count}`}
                style={{ height:`${(t.count/maxCount)*100}%`, background:'var(--accent)', opacity:0.7, minHeight:'2px' }} />
            ))}
          </div>
        </div>
      )}

      {analytics.top_anomalies.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color:'var(--text-3)' }}>Top Anomaly Types</p>
          <div className="space-y-1.5">
            {analytics.top_anomalies.slice(0, 5).map((a, i) => (
              <div key={a.event_type} className="flex items-center gap-2">
                <span className="text-[10px] w-4 font-mono" style={{ color:'var(--text-3)' }}>{i+1}.</span>
                <span className="text-[11px] flex-1 capitalize" style={{ color:'var(--text-2)' }}>{a.event_type.replace(/_/g,' ')}</span>
                <span className="text-[10px] font-mono font-bold" style={{ color:'var(--orange)' }}>{a.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Watchlist Manager ─────────────────────────────────────────────────────────

function WatchlistPanel({
  watchlist, onAdd, onRemove, loadingUsername,
}: {
  watchlist: WatchEntry[];
  onAdd: (u: string, cat: string) => void;
  onRemove: (u: string) => void;
  loadingUsername: string | null;
}) {
  const [newUser, setNewUser] = useState('');
  const [newCat, setNewCat] = useState('General');
  return (
    <div className="p-3 space-y-3">
      <div className="flex items-center gap-2">
        <input value={newUser} onChange={e=>setNewUser(e.target.value)}
          placeholder="Username to watch…" className="g-input flex-1 text-xs"
          onKeyDown={e=>e.key==='Enter'&&newUser.trim()&&onAdd(newUser.trim(),newCat)} />
        <select value={newCat} onChange={e=>setNewCat(e.target.value)} className="g-select text-xs" style={{ width:110 }}>
          {WATCH_CATEGORIES.map(c=><option key={c} value={c}>{c}</option>)}
        </select>
        <button onClick={()=>newUser.trim()&&onAdd(newUser.trim(),newCat)} className="g-btn g-btn-primary text-xs px-3">
          <Plus className="h-3.5 w-3.5"/>
        </button>
      </div>
      {watchlist.length === 0
        ? <p className="text-xs text-center py-4" style={{ color:'var(--text-3)' }}>No users on watchlist. Add executives, admins, or contractors to apply stricter detection thresholds.</p>
        : watchlist.map(w => (
          <div key={w.username} className="flex items-center gap-2.5 rounded-lg px-3 py-2.5"
            style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
            <div className="h-7 w-7 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
              style={{ background:'var(--glass-hover)', color:'var(--text-2)' }}>
              {w.username.charAt(0).toUpperCase()}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium" style={{ color:'var(--text-1)' }}>{w.username}</p>
              <p className="text-[10px]" style={{ color:'var(--text-3)' }}>{w.category} · Added {timeAgo(w.added_at)}</p>
            </div>
            <RiskBadge score={w.risk_score} />
            <button onClick={()=>onRemove(w.username)} className="g-btn g-btn-ghost text-xs px-2">
              {loadingUsername===w.username ? <Loader2 className="h-3 w-3 animate-spin"/> : <Trash2 className="h-3 w-3"/>}
            </button>
          </div>
        ))
      }
    </div>
  );
}

// ── User Detail Panel ─────────────────────────────────────────────────────────

function UserDetailPanel({
  profile, onClose,
}: {
  profile: UserRiskProfile;
  onClose: () => void;
}) {
  const [detail,   setDetail]   = useState<UserDetail | null>(null);
  const [timeline, setTimeline] = useState<UEBAEvent[]>([]);
  const [peerData, setPeerData] = useState<PeerComparison | null>(null);
  const [loadingDetail,   setLoadingDetail]   = useState(true);
  const [loadingTimeline, setLoadingTimeline] = useState(true);
  const [loadingPeer,     setLoadingPeer]     = useState(true);
  const [toast, setToast] = useState<string | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(()=>setToast(null),3000); };

  useEffect(() => {
    setDetail(null); setTimeline([]); setPeerData(null);
    setLoadingDetail(true); setLoadingTimeline(true); setLoadingPeer(true);

    uebaAPI.getUserDetail(profile.username).then(r => {
      setDetail(r.data as UserDetail);
      setLoadingDetail(false);
    });
    uebaAPI.getUserTimeline(profile.username).then(r => {
      setTimeline(r.data?.events ?? []);
      setLoadingTimeline(false);
    });
    uebaAPI.getPeerComparison(profile.username).then(r => {
      setPeerData(r.data as PeerComparison);
      setLoadingPeer(false);
    });
  }, [profile.username]);

  const CARD = "g-card flex flex-col overflow-hidden";

  return (
    <div className="flex flex-col h-full overflow-y-auto" style={{ background:'var(--bg-0)' }}>
      {toast && (
        <div className="fixed bottom-4 right-4 z-50 px-4 py-2 rounded-lg text-sm font-medium shadow-xl"
          style={{ background:'var(--accent)', color:'#000' }}>{toast}</div>
      )}

      {/* Header */}
      <div className="sticky top-0 z-30 flex items-center gap-3 px-4 py-3"
        style={{ background:'var(--bg-1)', borderBottom:'1px solid var(--border)' }}>
        <div className="h-9 w-9 rounded-full flex items-center justify-center text-sm font-bold shrink-0"
          style={{ background:`${RISK_COLOR(profile.risk_score)}22`, color:RISK_COLOR(profile.risk_score), border:`1px solid ${RISK_COLOR(profile.risk_score)}44` }}>
          {profile.username.charAt(0).toUpperCase()}
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-bold" style={{ color:'var(--text-1)' }}>{profile.username}</p>
          <p className="text-[11px]" style={{ color:'var(--text-3)' }}>{profile.source} · Last seen {profile.last_event_at ? timeAgo(profile.last_event_at) : 'never'}</p>
        </div>
        <RiskBadge score={profile.risk_score} />
        <button onClick={onClose} className="g-btn g-btn-ghost text-xs" title="Close">×</button>
      </div>

      <div className="p-4 space-y-3 max-w-[1400px] mx-auto w-full">

        {/* Row 1: Risk Score + Baseline */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={CARD}>
            <SectionHeader icon={BarChart2} title="Risk Score" />
            <RiskScoreCard profile={profile} />
          </div>
          <div className={CARD}>
            <SectionHeader icon={Activity} title="Behavioral Baseline" />
            <BaselineCard profile={profile} />
          </div>
        </div>

        {/* Row 2: Timeline + Attack-chain equivalent (Entity Graph) */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={CARD} style={{ maxHeight:400 }}>
            <SectionHeader icon={Clock} title={`Timeline (${timeline.length})`} />
            <div className="flex-1 overflow-y-auto">
              <TimelineFeed events={timeline} loading={loadingTimeline} />
            </div>
          </div>
          <div className={CARD} style={{ maxHeight:400 }}>
            <SectionHeader icon={GitBranch} title="Entity Relationships" />
            <div className="flex-1 overflow-y-auto">
              <EntityGraph profile={profile} detail={detail} />
            </div>
          </div>
        </div>

        {/* Row 3: Login Analytics + File Behavior */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={CARD}>
            <SectionHeader icon={Lock} title="Login Analytics" />
            <LoginAnalyticsCard profile={profile} events={timeline} />
          </div>
          <div className={CARD}>
            <SectionHeader icon={FileText} title="File Behavior" />
            <FileBehaviorCard profile={profile} events={timeline} />
          </div>
        </div>

        {/* Row 4: Endpoint Behavior + Network Behavior */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={CARD}>
            <SectionHeader icon={Terminal} title="Endpoint Behavior" />
            <EndpointBehaviorCard events={timeline} />
          </div>
          <div className={CARD}>
            <SectionHeader icon={Network} title="Network Behavior" />
            <NetworkBehaviorCard events={timeline} detail={detail} />
          </div>
        </div>

        {/* Row 5: Anomalies + Peer Comparison */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={CARD}>
            <SectionHeader icon={AlertTriangle} title="Anomaly Detection" />
            <AnomalyCard profile={profile} events={timeline} />
          </div>
          <div className={CARD} style={{ maxHeight:380 }}>
            <SectionHeader icon={Users} title="Peer Group Analysis" />
            <div className="flex-1 overflow-y-auto">
              <PeerCard data={peerData} loading={loadingPeer} />
            </div>
          </div>
        </div>

        {/* Row 6: AI Insights + MITRE */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={CARD} style={{ maxHeight:420 }}>
            <SectionHeader icon={Bot} title="AI Behavioral Insights" />
            <div className="flex-1 overflow-y-auto">
              <AIInsightsPanel username={profile.username} />
            </div>
          </div>
          <div className={CARD}>
            <SectionHeader icon={Target} title="Threat Intel & MITRE" />
            <div className="p-4 space-y-3">
              <div className="space-y-2">
                <p className="text-[10px] font-bold uppercase tracking-wider" style={{ color:'var(--text-3)' }}>Mapped Techniques</p>
                <div className="flex flex-wrap gap-2">
                  {[
                    { id:'T1078', label:'Valid Accounts',         relevant: profile.flags.includes('impossible_travel') || profile.privilege_escalations > 0 },
                    { id:'T1059', label:'Command Interpreter',    relevant: timeline.some(e=>e.event_type==='powershell'||e.event_type==='bash') },
                    { id:'T1003', label:'Credential Dumping',     relevant: profile.privilege_escalations > 0 },
                    { id:'T1021', label:'Remote Services',        relevant: timeline.some(e=>e.event_type==='rdp'||e.event_type==='ssh') },
                    { id:'T1041', label:'Exfiltration over C2',   relevant: timeline.some(e=>e.event_type==='exfiltration') },
                    { id:'T1486', label:'Data Encrypted',         relevant: profile.flags.includes('encryption') },
                    { id:'T1566', label:'Phishing',               relevant: false },
                    { id:'T1098', label:'Account Manipulation',   relevant: profile.flags.includes('priv_change') },
                  ].filter(t => t.relevant).map((t, i) => (
                    <span key={t.id} className="text-[10px] px-2.5 py-1 rounded-lg font-mono font-medium"
                      style={{ background:`${MITRE_COLORS[i%MITRE_COLORS.length]}18`, color:MITRE_COLORS[i%MITRE_COLORS.length], border:`1px solid ${MITRE_COLORS[i%MITRE_COLORS.length]}44` }}>
                      {t.id} · {t.label}
                    </span>
                  ))}
                  {profile.flags.length === 0 && <p className="text-xs" style={{ color:'var(--text-3)' }}>No MITRE techniques mapped — no active flags.</p>}
                </div>
              </div>
              <div className="space-y-1.5">
                <p className="text-[10px] font-bold uppercase tracking-wider" style={{ color:'var(--text-3)' }}>Linked Alerts & Incidents</p>
                {loadingDetail ? <Spinner /> : (
                  <div className="flex gap-3">
                    <Link href={`/alerts?username=${encodeURIComponent(profile.username)}`}
                      className="flex items-center gap-2 rounded-lg px-3 py-2 flex-1 hover:bg-[var(--glass-hover)] transition-colors"
                      style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                      <AlertTriangle className="h-3.5 w-3.5" style={{ color:'var(--orange)' }} />
                      <span className="text-xs" style={{ color:'var(--text-1)' }}>{detail?.alert_count ?? 0} Alerts</span>
                    </Link>
                    <Link href={`/incidents?username=${encodeURIComponent(profile.username)}`}
                      className="flex items-center gap-2 rounded-lg px-3 py-2 flex-1 hover:bg-[var(--glass-hover)] transition-colors"
                      style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                      <Shield className="h-3.5 w-3.5" style={{ color:'var(--red)' }} />
                      <span className="text-xs" style={{ color:'var(--text-1)' }}>{detail?.incident_count ?? 0} Incidents</span>
                    </Link>
                  </div>
                )}
              </div>
              <div className="space-y-1.5">
                <p className="text-[10px] font-bold uppercase tracking-wider" style={{ color:'var(--text-3)' }}>Quick Investigations</p>
                <div className="grid grid-cols-2 gap-1.5">
                  {[
                    { label:'View Alerts',      href:`/alerts?username=${profile.username}`,    icon:AlertTriangle },
                    { label:'View Incidents',   href:`/incidents?username=${profile.username}`, icon:Shield },
                    { label:'Search Logs',      href:`/log-search?q=${profile.username}`,       icon:Search },
                    { label:'Timeline',         href:`/timeline?username=${profile.username}`,  icon:Clock },
                    { label:'Attack Path',      href:`/attack-path`,                            icon:GitBranch },
                    { label:'Threat Hunt',      href:`/hunt?query=${profile.username}`,         icon:Crosshair },
                  ].map(a => (
                    <Link key={a.label} href={a.href}
                      className="flex items-center gap-1.5 rounded-lg px-2.5 py-2 text-xs hover:bg-[var(--glass-hover)] transition-colors"
                      style={{ background:'var(--glass-bg)', border:'1px solid var(--border)', color:'var(--text-2)' }}>
                      <a.icon className="h-3.5 w-3.5 shrink-0" style={{ color:'var(--accent)' }} />
                      {a.label}
                    </Link>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Row 7: Response Actions (full width) */}
        <div className={CARD}>
          <SectionHeader icon={Zap} title="Response Actions" />
          <ResponseActionsPanel username={profile.username} onAction={notify} />
        </div>

      </div>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function UEBAPage() {
  const [profiles,     setProfiles]     = useState<UserRiskProfile[]>([]);
  const [analytics,    setAnalytics]    = useState<Analytics | null>(null);
  const [watchlist,    setWatchlist]    = useState<WatchEntry[]>([]);
  const [loading,      setLoading]      = useState(true);
  const [refreshing,   setRefreshing]   = useState(false);
  const [analyzing,    setAnalyzing]    = useState(false);
  const [selected,     setSelected]     = useState<UserRiskProfile | null>(null);
  const [searchQuery,  setSearchQuery]  = useState('');
  const [riskFilter,   setRiskFilter]   = useState('all');
  const [view,         setView]         = useState<'list' | 'analytics' | 'watchlist'>('list');
  const [watchLoading, setWatchLoading] = useState<string | null>(null);
  const [toast,        setToast]        = useState<string | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(()=>setToast(null),3000); };

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    const [pRes, aRes, wRes] = await Promise.allSettled([
      uebaAPI.getUsers({ limit:200 }),
      uebaAPI.getAnalytics(),
      uebaAPI.getWatchlist(),
    ]);
    if (pRes.status==='fulfilled') setProfiles(pRes.value.data.profiles ?? []);
    if (aRes.status==='fulfilled') aRes.value.data && setAnalytics(aRes.value.data as Analytics);
    if (wRes.status==='fulfilled') setWatchlist(wRes.value.data?.watchlist ?? []);
    setLoading(false); setRefreshing(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const analyze = async () => {
    setAnalyzing(true);
    await uebaAPI.analyze();
    setTimeout(() => { load(true); setAnalyzing(false); }, 3000);
  };

  const addToWatchlist = async (username: string, category: string) => {
    try {
      await uebaAPI.addToWatchlist(username, category);
      load();
      notify(`${username} added to watchlist`);
    } catch { notify('Failed to add'); }
  };

  const removeFromWatchlist = async (username: string) => {
    setWatchLoading(username);
    try {
      await uebaAPI.removeFromWatchlist(username);
      setWatchlist(w => w.filter(e => e.username !== username));
      notify(`${username} removed`);
    } catch { notify('Failed to remove'); }
    finally { setWatchLoading(null); }
  };

  const filtered = useMemo(() => {
    let p = [...profiles];
    if (riskFilter === 'critical') p = p.filter(u => u.risk_score >= 80);
    else if (riskFilter === 'high')   p = p.filter(u => u.risk_score >= 60 && u.risk_score < 80);
    else if (riskFilter === 'medium') p = p.filter(u => u.risk_score >= 30 && u.risk_score < 60);
    else if (riskFilter === 'low')    p = p.filter(u => u.risk_score < 30);
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      p = p.filter(u => u.username.toLowerCase().includes(q) || u.flags.some(f=>f.includes(q)));
    }
    return p;
  }, [profiles, riskFilter, searchQuery]);

  const highRiskCount   = useMemo(() => profiles.filter(u => u.risk_score >= 60).length, [profiles]);
  const criticalCount   = useMemo(() => profiles.filter(u => u.risk_score >= 80).length, [profiles]);
  const flaggedCount    = useMemo(() => profiles.filter(u => u.flags.length > 0).length, [profiles]);

  // Split panel if user selected
  if (selected) {
    return (
      <div className="h-screen flex overflow-hidden" style={{ background:'var(--bg-0)' }}>
        {/* Left: compact list */}
        <div className="w-72 shrink-0 flex flex-col border-r" style={{ borderColor:'var(--border)' }}>
          <div className="px-3 py-3 space-y-2 shrink-0" style={{ borderBottom:'1px solid var(--border)', background:'var(--bg-1)' }}>
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color:'var(--text-3)' }} />
              <input value={searchQuery} onChange={e=>setSearchQuery(e.target.value)}
                placeholder="Search users…" className="g-input w-full text-xs pl-8" />
            </div>
          </div>
          <div className="flex-1 overflow-y-auto">
            {filtered.map(p => (
              <div key={`${p.username}-${p.source}`}
                onClick={() => setSelected(p)}
                className="flex items-center gap-2.5 px-3 py-3 cursor-pointer transition-colors border-b"
                style={{
                  borderColor:'var(--border)',
                  background: selected?.username===p.username ? 'var(--accent-glow)' : undefined,
                  borderLeft: selected?.username===p.username ? '2px solid var(--accent)' : '2px solid transparent',
                }}>
                <div className="h-7 w-7 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
                  style={{ background:`${RISK_COLOR(p.risk_score)}18`, color:RISK_COLOR(p.risk_score) }}>
                  {p.username.charAt(0).toUpperCase()}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium truncate" style={{ color:'var(--text-1)' }}>{p.username}</p>
                  <RiskBar score={p.risk_score} showLabel={false} />
                </div>
                <span className="text-[10px] font-bold shrink-0" style={{ color:RISK_COLOR(p.risk_score) }}>{p.risk_score}</span>
              </div>
            ))}
          </div>
        </div>
        {/* Right: detail */}
        <div className="flex-1 overflow-hidden">
          <UserDetailPanel profile={selected} onClose={() => setSelected(null)} />
        </div>
      </div>
    );
  }

  return (
    <RootLayout title="UEBA" subtitle="User & Entity Behavior Analytics"
      onRefresh={() => load(true)} refreshing={refreshing}
      actions={
        <button onClick={analyze} disabled={analyzing} className="g-btn g-btn-ghost text-xs">
          <RefreshCw className={`h-3.5 w-3.5 ${analyzing?'animate-spin':''}`} />
          {analyzing ? 'Analyzing…' : 'Re-analyze'}
        </button>
      }>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 px-4 py-2.5 rounded-lg text-sm font-medium shadow-xl"
          style={{ background:'var(--accent)', color:'#000' }}>{toast}</div>
      )}

      <div className="space-y-4">

        {/* KPI strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label:'Total Users',    val:profiles.length,  icon:Users,         color:'var(--accent)' },
            { label:'Critical Risk',  val:criticalCount,    icon:AlertTriangle, color:'var(--red)' },
            { label:'High Risk',      val:highRiskCount,    icon:TrendingUp,    color:'var(--orange)' },
            { label:'Watchlisted',    val:watchlist.length, icon:Star,          color:'var(--yellow)' },
          ].map(({ label, val, icon:Icon, color }) => (
            <div key={label} className="g-card p-3 flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg shrink-0" style={{ background:`${color}18` }}>
                <Icon className="h-4 w-4" style={{ color }} />
              </div>
              <div>
                <p className="text-base font-bold tabular-nums" style={{ color }}>{val}</p>
                <p className="text-[10px]" style={{ color:'var(--text-3)' }}>{label}</p>
              </div>
            </div>
          ))}
        </div>

        {/* View tabs */}
        <div className="flex items-center gap-2">
          {([['list','User Profiles'], ['analytics','Analytics'], ['watchlist','Watchlist']] as const).map(([v, l]) => (
            <button key={v} onClick={() => setView(v)}
              className="g-btn text-xs"
              style={{
                background: view===v ? 'var(--accent-glow)' : 'var(--glass-bg)',
                color:      view===v ? 'var(--accent)' : 'var(--text-2)',
                border:     `1px solid ${view===v ? 'var(--accent-border)' : 'var(--border)'}`,
              }}>
              {l}
            </button>
          ))}
        </div>

        {view === 'analytics' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="g-card overflow-hidden">
              <SectionHeader icon={BarChart2} title="UEBA Analytics Dashboard" />
              <AnalyticsDashboard analytics={analytics} />
            </div>
            <div className="g-card overflow-hidden">
              <SectionHeader icon={AlertTriangle} title="High-Risk Users" />
              <div className="p-3 space-y-2">
                {(analytics?.high_risk_users ?? []).length === 0
                  ? <Empty icon={User} text="No high-risk users detected." />
                  : (analytics?.high_risk_users ?? []).map(u => (
                    <div key={u.username} className="flex items-center gap-2.5 rounded-lg px-3 py-2.5"
                      style={{ background:'var(--glass-bg)', border:'1px solid var(--border)', cursor:'pointer' }}
                      onClick={() => {
                        const p = profiles.find(x=>x.username===u.username);
                        if (p) setSelected(p);
                      }}>
                      <div className="h-7 w-7 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
                        style={{ background:`${RISK_COLOR(u.risk_score)}18`, color:RISK_COLOR(u.risk_score) }}>
                        {u.username.charAt(0).toUpperCase()}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium" style={{ color:'var(--text-1)' }}>{u.username}</p>
                        <div className="flex flex-wrap gap-1 mt-0.5">
                          {u.flags.slice(0,3).map(f=><FlagChip key={f} flag={f}/>)}
                        </div>
                      </div>
                      <RiskBadge score={u.risk_score} />
                      <ChevronRight className="h-3.5 w-3.5 shrink-0" style={{ color:'var(--text-3)' }} />
                    </div>
                  ))
                }
              </div>
            </div>
          </div>
        )}

        {view === 'watchlist' && (
          <div className="g-card overflow-hidden">
            <SectionHeader icon={Star} title="User Watchlists" />
            <WatchlistPanel
              watchlist={watchlist}
              onAdd={addToWatchlist}
              onRemove={removeFromWatchlist}
              loadingUsername={watchLoading}
            />
          </div>
        )}

        {view === 'list' && (
          <>
            {/* Search + filter */}
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color:'var(--text-3)' }} />
                <input value={searchQuery} onChange={e=>setSearchQuery(e.target.value)}
                  placeholder="Search users or flags…" className="g-input w-full text-xs pl-8" />
                {searchQuery && (
                  <button onClick={()=>setSearchQuery('')} className="absolute right-2.5 top-1/2 -translate-y-1/2">
                    <X className="h-3 w-3" style={{ color:'var(--text-3)' }} />
                  </button>
                )}
              </div>
              <div className="flex items-center gap-1">
                <Filter className="h-3.5 w-3.5" style={{ color:'var(--text-3)' }} />
                {[
                  { val:'all',      label:'All' },
                  { val:'critical', label:'Critical (80+)' },
                  { val:'high',     label:'High (60+)' },
                  { val:'medium',   label:'Medium (30+)' },
                  { val:'low',      label:'Low (<30)' },
                ].map(f => (
                  <button key={f.val} onClick={() => setRiskFilter(f.val)}
                    className="px-2.5 py-1 text-[11px] rounded-lg transition-all"
                    style={{
                      background: riskFilter===f.val ? 'var(--accent-glow)' : 'var(--glass-bg)',
                      border:`1px solid ${riskFilter===f.val ? 'var(--accent-border)' : 'var(--border)'}`,
                      color: riskFilter===f.val ? 'var(--accent)' : 'var(--text-2)',
                    }}>
                    {f.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Table */}
            <div className="g-table">
              <div className="g-thead grid gap-3 px-4"
                style={{ gridTemplateColumns:'28px 1fr 80px 80px 70px 70px 70px 70px 120px 28px' }}>
                <span/>
                <span>User</span>
                <span>Source</span>
                <span>Risk</span>
                <span>Failed</span>
                <span>Off-Hrs</span>
                <span>IPs</span>
                <span>Priv Esc</span>
                <span>Last Seen</span>
                <span/>
              </div>

              {loading ? (
                <div className="py-16 text-center text-sm animate-pulse" style={{ color:'var(--text-3)' }}>Analyzing user behavior…</div>
              ) : filtered.length === 0 ? (
                <div className="py-16 text-center">
                  <User className="mx-auto h-8 w-8 mb-2 opacity-20" style={{ color:'var(--text-3)' }} />
                  <p className="text-sm" style={{ color:'var(--text-2)' }}>
                    {profiles.length === 0 ? 'No user data yet — click Re-analyze to scan logs.' : 'No users match filter.'}
                  </p>
                </div>
              ) : filtered.map(p => {
                const color = RISK_COLOR(p.risk_score);
                return (
                  <div key={`${p.username}-${p.source}`}
                    onClick={() => setSelected(p)}
                    className="g-tr grid gap-3 items-center px-4 cursor-pointer"
                    style={{ gridTemplateColumns:'28px 1fr 80px 80px 70px 70px 70px 70px 120px 28px' }}>
                    <div className="h-7 w-7 rounded-full flex items-center justify-center text-xs font-bold"
                      style={{ background:`${color}18`, color }}>
                      {p.username.charAt(0).toUpperCase()}
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-semibold truncate" style={{ color:'var(--text-1)' }}>{p.username}</p>
                      <div className="flex flex-wrap gap-1 mt-0.5">
                        {p.flags.slice(0,2).map(f=><FlagChip key={f} flag={f}/>)}
                      </div>
                    </div>
                    <span className="text-[11px] capitalize" style={{ color:'var(--text-3)' }}>{p.source}</span>
                    <div>
                      <RiskBar score={p.risk_score} />
                      <RiskBadge score={p.risk_score} />
                    </div>
                    <span className="text-xs font-mono tabular-nums" style={{ color: p.failed_logins > 0 ? 'var(--red)' : 'var(--text-3)' }}>{p.failed_logins}</span>
                    <span className="text-xs font-mono tabular-nums" style={{ color: p.off_hours_events > 0 ? 'var(--orange)' : 'var(--text-3)' }}>{p.off_hours_events}</span>
                    <span className="text-xs font-mono tabular-nums" style={{ color: p.unique_ips > 3 ? 'var(--yellow)' : 'var(--text-3)' }}>{p.unique_ips}</span>
                    <span className="text-xs font-mono tabular-nums" style={{ color: p.privilege_escalations > 0 ? 'var(--red)' : 'var(--text-3)' }}>{p.privilege_escalations}</span>
                    <span className="text-[11px]" style={{ color:'var(--text-3)' }}>
                      {p.last_event_at ? timeAgo(p.last_event_at) : '—'}
                    </span>
                    <ChevronRight className="h-3.5 w-3.5" style={{ color:'var(--text-3)' }} />
                  </div>
                );
              })}
            </div>

            {/* Risk score legend */}
            {!loading && filtered.length > 0 && (
              <div className="g-card px-4 py-3">
                <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color:'var(--text-3)' }}>Risk Score Components</p>
                <div className="flex gap-6 flex-wrap text-[11px]" style={{ color:'var(--text-3)' }}>
                  <span><span className="font-semibold" style={{ color:'var(--red)' }}>×10</span> Failed login</span>
                  <span><span className="font-semibold" style={{ color:'var(--orange)' }}>×5</span> Off-hours event</span>
                  <span><span className="font-semibold" style={{ color:'var(--red)' }}>×20</span> Privilege escalation</span>
                  <span><span className="font-semibold" style={{ color:'var(--yellow)' }}>×15</span> Additional source IP</span>
                  <span className="ml-auto">Score capped at 100 · Re-analyzed every 30 min · 7-day window</span>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </RootLayout>
  );
}
