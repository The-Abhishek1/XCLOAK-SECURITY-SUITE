'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useRouter } from 'next/navigation';
import { useUser } from '@/context/UserContext';
import {
  LayoutDashboard, Cpu, Bell, AlertTriangle, Play,
  Shield, Bug, Settings, ShieldCheck, LogOut,
  Archive, ChevronRight, Network, FileCode, Code2,
  ClipboardCheck, Bot, Radio, Search, CalendarClock,
  GitMerge, Map, Clock, VolumeX, TerminalSquare, Menu, X,
  Building2, Crosshair, Activity, SearchCode, FolderOpen,
  Server, BarChart2, ListChecks, Users, Aperture, Gauge, Microscope,
  Target, Wifi, Layers, HardDrive, ScrollText, PlugZap, Fingerprint, UserX,
} from 'lucide-react';
import api from '@/lib/api';
import type { UserProfile } from '@/types';

const NAV = [
  { group: 'OVERVIEW', items: [
    { href: '/dashboard',   label: 'Dashboard',   icon: LayoutDashboard },
    { href: '/agents',      label: 'Agents',      icon: Cpu },
    { href: '/network-map', label: 'Network Map', icon: Map },
    { href: '/attack-path', label: 'Attack Paths', icon: Crosshair },
    { href: '/timeline',    label: 'Timeline',    icon: Clock },
  ]},
  { group: 'DETECTION', items: [
    { href: '/alerts',         label: 'Alerts',         icon: Bell },
    { href: '/incidents',      label: 'Incidents',      icon: AlertTriangle },
    { href: '/ueba',           label: 'UEBA',           icon: Activity },
    { href: '/insider-threat', label: 'Insider Threat', icon: UserX },
    { href: '/deception',      label: 'Deception',      icon: Aperture },
    { href: '/hunt-workbench', label: 'Hunt Workbench', icon: Microscope },
    { href: '/threat-actors',  label: 'Threat Actors',  icon: Target },
    { href: '/nba',            label: 'Net Behavior',   icon: Wifi },
    { href: '/threat-intel',   label: 'Threat Intel',   icon: Shield },
    { href: '/sigma-rules',        label: 'Sigma Rules',     icon: FileCode },
    { href: '/yara-rules',        label: 'YARA Rules',      icon: Code2 },
    { href: '/ja3-fingerprints',  label: 'JA3 Fingerprints', icon: Fingerprint },
    { href: '/threat-detection',  label: 'Behavioral',      icon: Activity },
    { href: '/live-logs',    label: 'Live Logs',    icon: Radio },
    { href: '/log-search',   label: 'Log Search',   icon: SearchCode },
    { href: '/log-sources',  label: 'Log Sources',  icon: PlugZap },
    { href: '/hunt',         label: 'Threat Hunt',  icon: Search },
    { href: '/clusters',     label: 'Alert Clusters', icon: Layers },
    { href: '/correlation',  label: 'Correlation',  icon: GitMerge },
    { href: '/suppression',  label: 'Suppression',  icon: VolumeX },
  ]},
  { group: 'RESPONSE', items: [
    { href: '/cases',           label: 'Cases',           icon: FolderOpen },
    { href: '/playbooks',       label: 'Playbooks',       icon: Play },
    { href: '/soar-approvals',  label: 'Approval Queue',  icon: ShieldCheck },
    { href: '/vulnerabilities', label: 'Vulnerabilities', icon: Bug },
    { href: '/vuln-queue',     label: 'Vuln Queue',       icon: ListChecks },
    { href: '/quarantine',      label: 'Quarantine',      icon: Archive },
    { href: '/firewall',        label: 'Firewall',        icon: Network },
    { href: '/scheduled-tasks',  label: 'Scheduled Tasks', icon: CalendarClock },
    { href: '/dfir',             label: 'DFIR',             icon: HardDrive },
    { href: '/script-runner',    label: 'Script Runner',    icon: TerminalSquare },
  ]},
  { group: 'INVENTORY', items: [
    { href: '/assets', label: 'Assets (CMDB)', icon: Server },
  ]},
  { group: 'COMPLIANCE', items: [
    { href: '/compliance',          label: 'Reports',           icon: ClipboardCheck },
    { href: '/framework-compliance', label: 'Frameworks',         icon: ScrollText },
    { href: '/executive',     label: 'Executive',     icon: BarChart2 },
    { href: '/soc-metrics',   label: 'SOC Metrics',   icon: Users },
    { href: '/risk-posture',  label: 'Risk Posture',  icon: Gauge },
  ]},
  { group: 'AI', items: [
    { href: '/ai-assistant', label: 'AI Assistant', icon: Bot },
  ]},
  { group: 'SYSTEM', items: [
    { href: '/settings', label: 'Settings', icon: Settings },
  ]},
  { group: 'PLATFORM', platformOnly: true, items: [
    { href: '/platform', label: 'Tenants', icon: Building2 },
  ]},
];


function NavBadge({ count }: { count: number }) {
  if (count <= 0) return null;
  return (
    <span className="flex h-4 min-w-4 items-center justify-center rounded-full px-1 text-[9px] font-bold"
      style={{ background: 'var(--red)', color: '#fff', lineHeight: 1 }}>
      {count > 99 ? '99+' : count}
    </span>
  );
}

function NavContent({
  pathname,
  onNavigate,
  logout,
  profile,
  badges,
}: {
  pathname: string | null;
  onNavigate?: () => void;
  logout: () => void;
  profile: UserProfile | null;
  badges: Record<string, number>;
}) {
  const visibleNav = NAV.filter(s => !s.platformOnly || profile?.is_platform_admin);

  return (
<>
      <nav className="flex-1 overflow-y-auto px-2.5 py-4 space-y-5">
        {visibleNav.map(section => (
          <div key={section.group}>
            <p className="px-3 mb-1.5 text-[9px] font-bold tracking-widest uppercase"
              style={{ color: 'var(--text-3)' }}>
              {section.group}
            </p>
            <div className="space-y-0.5">
              {section.items.map(item => {
                const Icon   = item.icon;
                const active = pathname === item.href || pathname?.startsWith(item.href + '/');
                const badge  = badges[item.href] ?? 0;
                return (
                  <Link key={item.href} href={item.href}
                    onClick={onNavigate}
                    className="flex items-center justify-between rounded-xl px-3 py-2.5 text-[13px] font-medium transition-all duration-150"
                    style={{
                      background: active ? 'var(--accent-glow)' : 'transparent',
                      color:      active ? 'var(--accent)' : 'var(--text-2)',
                      border:     active ? '1px solid var(--accent-border)' : '1px solid transparent',
                      boxShadow:  active ? '0 0 12px var(--accent-glow)' : undefined,
                    }}
                    onMouseEnter={e => { if (!active) (e.currentTarget as HTMLElement).style.background = 'var(--glass-hover)'; }}
                    onMouseLeave={e => { if (!active) (e.currentTarget as HTMLElement).style.background = 'transparent'; }}>
                    <div className="flex items-center gap-2.5">
                      <Icon className="h-4 w-4 shrink-0" />
                      {item.label}
                    </div>
                    <div className="flex items-center gap-1.5">
                      <NavBadge count={badge} />
                      {active && <ChevronRight className="h-3 w-3 opacity-50" />}
                    </div>
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      <div className="px-2.5 pb-4 space-y-0.5 shrink-0"
        style={{ borderTop: '1px solid var(--border)', paddingTop: 10 }}>
        <button onClick={logout}
          className="flex w-full items-center gap-2.5 rounded-xl px-3 py-2.5 text-[13px] font-medium transition-all"
          style={{ color: 'var(--text-2)' }}
          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--red-bg)'; (e.currentTarget as HTMLElement).style.color = 'var(--red)'; }}
          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; (e.currentTarget as HTMLElement).style.color = 'var(--text-2)'; }}>
          <LogOut className="h-4 w-4" /> Sign out
        </button>
      </div>
    </>
  );
}

function Logo() {
  return (
    <div className="flex items-center gap-3">
      <div className="flex h-8 w-8 items-center justify-center rounded-xl shrink-0"
        style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)', boxShadow: '0 0 16px var(--accent-glow)' }}>
        <ShieldCheck className="h-4 w-4" style={{ color: 'var(--accent)' }} />
      </div>
      <div>
        <p className="text-sm font-bold tracking-wide" style={{ color: 'var(--text-1)' }}>XCloak</p>
        <p className="text-[9px] tracking-widest uppercase font-medium" style={{ color: 'var(--text-3)' }}>Security Suite</p>
      </div>
    </div>
  );
}

export function Sidebar() {
  const pathname = usePathname();
  const router   = useRouter();
  const { profile } = useUser();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [badges, setBadges]         = useState<Record<string, number>>({});

  useEffect(() => {
    const loadBadges = async () => {
      const [alertRes, approvalRes] = await Promise.allSettled([
        api.get('/alerts/paginated', { params: { page: 1, per_page: 1, severity: 'critical' } }),
        api.get('/tasks/pending-approval').catch(() => ({ data: [] })),
      ]);
      const next: Record<string, number> = {};
      if (alertRes.status === 'fulfilled') {
        const n = alertRes.value.data?.total ?? 0;
        if (n > 0) next['/alerts'] = n;
      }
      if (approvalRes.status === 'fulfilled') {
        const n = (approvalRes.value.data || []).length;
        if (n > 0) next['/soar-approvals'] = n;
      }
      setBadges(next);
    };

    loadBadges();
    const t = setInterval(loadBadges, 60000);
    return () => clearInterval(t);
  }, []);

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    document.cookie = 'token=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
    router.push('/login');
  };

  return (
    <>
      {/* ── DESKTOP SIDEBAR (240px, hidden on mobile) ─────── */}
      <aside className="hidden lg:flex flex-col fixed left-0 top-0 h-screen z-40"
        style={{
          width: 240,
          background: 'var(--glass-bg)',
          backdropFilter: 'var(--blur)',
          WebkitBackdropFilter: 'var(--blur)',
          borderRight: '1px solid var(--border)',
        }}>

        <div className="flex items-center gap-3 px-5 h-14 shrink-0"
          style={{ borderBottom: '1px solid var(--border)' }}>
          <Logo />
        </div>

        <NavContent
          pathname={pathname}
          logout={logout}
          profile={profile}
          badges={badges}
        />
      </aside>

      {/* ── MOBILE: top navbar + slide-out drawer ─────────── */}
      <div className="lg:hidden">

        {/* Top navbar */}
        <div className="fixed top-0 left-0 right-0 h-14 z-50 flex items-center justify-between px-4"
          style={{
            background: 'var(--glass-bg)',
            backdropFilter: 'var(--blur)',
            WebkitBackdropFilter: 'var(--blur)',
            borderBottom: '1px solid var(--border)',
          }}>
          <Logo />
          <button
            onClick={() => setMobileOpen(o => !o)}
            className="flex h-9 w-9 items-center justify-center rounded-xl transition-all"
            style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-1)' }}>
            {mobileOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </button>
        </div>

        {/* Backdrop */}
        {mobileOpen && (
          <div
            className="fixed inset-0 z-40"
            style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}
            onClick={() => setMobileOpen(false)}
          />
        )}

        {/* Slide-out drawer */}
        <aside
          className="fixed top-0 left-0 h-screen z-50 flex flex-col transition-transform duration-300 ease-in-out"
          style={{
            width: 260,
            background: 'var(--bg-1)',
            borderRight: '1px solid var(--border)',
            transform: mobileOpen ? 'translateX(0)' : 'translateX(-100%)',
          }}>

          {/* Drawer header */}
          <div className="flex items-center justify-between px-4 h-14 shrink-0"
            style={{ borderBottom: '1px solid var(--border)' }}>
            <Logo />
            <button onClick={() => setMobileOpen(false)} style={{ color: 'var(--text-2)' }}>
              <X className="h-4 w-4" />
            </button>
          </div>

          <NavContent
            pathname={pathname}
            onNavigate={() => setMobileOpen(false)}
            logout={logout}
            profile={profile}
            badges={badges}
          />
        </aside>
      </div>
    </>
  );
}
