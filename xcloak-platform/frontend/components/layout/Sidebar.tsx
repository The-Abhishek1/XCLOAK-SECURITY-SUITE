'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useRouter } from 'next/navigation';
import { useUser } from '@/context/UserContext';
import {
  LayoutDashboard, Cpu, Bell, AlertTriangle, Play,
  Shield, Bug, Settings, ShieldCheck, LogOut,
  Archive, ChevronRight, ChevronDown, Network, FileCode, Code2,
  ClipboardCheck, Bot, Radio, Search, CalendarClock,
  GitMerge, Map, Clock, VolumeX, TerminalSquare, X,
  Building2, Crosshair, Activity, SearchCode, FolderOpen,
  Server, BarChart2, ListChecks, Users, Aperture, Gauge, Microscope,
  Target, Wifi, Layers, HardDrive, ScrollText, PlugZap, Fingerprint, UserX,
  Cloud, Mail, Container, ShieldOff, Package,
  EyeOff, Wrench, Smartphone, DatabaseZap,
  PanelLeft,
} from 'lucide-react';
import api from '@/lib/api';
import type { UserProfile } from '@/types';

const NAV = [
  { group: 'OVERVIEW', icon: LayoutDashboard, items: [
    { href: '/dashboard',    label: 'Dashboard',    icon: LayoutDashboard },
    { href: '/network-map',  label: 'Network Map',  icon: Map },
    { href: '/attack-path',  label: 'Attack Paths', icon: Crosshair },
    { href: '/risk-posture', label: 'Risk Posture', icon: Gauge },
  ]},
  { group: 'MONITORING', icon: Activity, items: [
    { href: '/agents',      label: 'Agents',      icon: Cpu },
    { href: '/timeline',    label: 'Timeline',    icon: Clock },
    { href: '/live-logs',   label: 'Live Logs',   icon: Radio },
    { href: '/log-search',     label: 'Log Search',   icon: SearchCode },
    { href: '/elastic-query',  label: 'ES Query',     icon: DatabaseZap },
    { href: '/log-sources',    label: 'Log Sources',  icon: PlugZap },
  ]},
  { group: 'DETECTION', icon: AlertTriangle, items: [
    { href: '/alerts',           label: 'Alerts',          icon: Bell },
    { href: '/incidents',        label: 'Incidents',        icon: AlertTriangle },
    { href: '/ueba',             label: 'UEBA',             icon: Activity },
    { href: '/insider-threat',   label: 'Insider Threat',   icon: UserX },
    { href: '/nba',              label: 'Net Behavior',     icon: Wifi },
    { href: '/dpi',              label: 'Deep Inspection',  icon: SearchCode },
    { href: '/threat-detection', label: 'Behavioral',       icon: Layers },
    { href: '/correlation',      label: 'Correlation',      icon: GitMerge },
    { href: '/clusters',         label: 'Alert Clusters',   icon: Aperture },
  ]},
  { group: 'INTEL & HUNT', icon: Target, items: [
    { href: '/threat-intel',     label: 'Threat Intel',     icon: Shield },
    { href: '/threat-actors',    label: 'Threat Actors',    icon: Target },
    { href: '/sigma-rules',      label: 'Sigma Rules',      icon: FileCode },
    { href: '/yara-rules',       label: 'YARA Rules',       icon: Code2 },
    { href: '/ja3-fingerprints', label: 'JA3 Fingerprints', icon: Fingerprint },
    { href: '/hunt-workbench',   label: 'Hunt Workbench',   icon: Microscope },
    { href: '/hunt',             label: 'Threat Hunt',      icon: Search },
    { href: '/dfir',             label: 'DFIR',             icon: HardDrive },
    { href: '/deception',        label: 'Deception',        icon: EyeOff },
  ]},
  { group: 'CLOUD & INFRA', icon: Cloud, items: [
    { href: '/cloud-security',     label: 'Cloud Security',    icon: Cloud },
    { href: '/email-security',     label: 'Email Security',    icon: Mail },
    { href: '/container-security', label: 'Containers / K8s',  icon: Container },
    { href: '/ad-attacks',         label: 'AD Attacks',        icon: ShieldOff },
    { href: '/supply-chain',       label: 'Supply Chain',      icon: Package },
    { href: '/ot-ics',             label: 'OT / ICS',          icon: Wrench },
    { href: '/process-injection',  label: 'Process Injection', icon: Cpu },
    { href: '/defense-evasion',    label: 'Defense Evasion',   icon: Bug },
  ]},
  { group: 'RESPONSE', icon: ShieldCheck, items: [
    { href: '/cases',           label: 'Cases',           icon: FolderOpen },
    { href: '/playbooks',       label: 'Playbooks',       icon: Play },
    { href: '/soar-approvals',  label: 'Approval Queue',  icon: ShieldCheck },
    { href: '/vulnerabilities', label: 'Vulnerabilities', icon: Bug },
    { href: '/vuln-queue',      label: 'Vuln Queue',      icon: ListChecks },
    { href: '/suppression',     label: 'Suppression',     icon: VolumeX },
    { href: '/quarantine',      label: 'Quarantine',      icon: Archive },
    { href: '/script-runner',   label: 'Script Runner',   icon: TerminalSquare },
    { href: '/scheduled-tasks', label: 'Scheduled Tasks', icon: CalendarClock },
    { href: '/firewall',        label: 'Firewall',        icon: Network },
  ]},
  { group: 'COMPLIANCE', icon: ClipboardCheck, items: [
    { href: '/compliance',           label: 'Reports',     icon: ClipboardCheck },
    { href: '/framework-compliance', label: 'Frameworks',  icon: ScrollText },
    { href: '/executive',            label: 'Executive',   icon: BarChart2 },
    { href: '/soc-metrics',          label: 'SOC Metrics', icon: Users },
  ]},
  { group: 'ASSETS', icon: Server, items: [
    { href: '/assets', label: 'Assets (CMDB)', icon: Server },
    { href: '/mdm',    label: 'Mobile (MDM)',  icon: Smartphone },
  ]},
  { group: 'AI & SYSTEM', icon: Bot, items: [
    { href: '/ai-assistant', label: 'AI Assistant', icon: Bot },
    { href: '/settings',     label: 'Settings',     icon: Settings },
  ]},
  { group: 'PLATFORM', icon: Building2, platformOnly: true, items: [
    { href: '/platform', label: 'Tenants', icon: Building2 },
  ]},
] as const;

function NavBadge({ count }: { count: number }) {
  if (count <= 0) return null;
  return (
    <span
      className="flex h-4 min-w-4 items-center justify-center rounded-full px-1 text-[9px] font-bold"
      style={{ background: 'var(--red)', color: '#fff', lineHeight: 1 }}
    >
      {count > 99 ? '99+' : count}
    </span>
  );
}

function Logo({ iconOnly = false }: { iconOnly?: boolean }) {
  return (
    <div className="flex items-center gap-3">
      <div
        className="flex h-8 w-8 items-center justify-center rounded-xl shrink-0"
        style={{
          background: 'var(--accent-glow)',
          border: '1px solid var(--accent-border)',
          boxShadow: '0 0 16px var(--accent-glow)',
        }}
      >
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
          <path d="M12 2.5 3 7v5c0 5.5 3.8 9.5 9 10.5 5.2-1 9-5 9-10.5V7Z"
            fill="currentColor" fillOpacity="0.15" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round"/>
          <path d="M9 9l6 6M15 9l-6 6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/>
        </svg>
      </div>
      {!iconOnly && (
        <div>
          <p className="text-sm font-bold tracking-wide" style={{ color: 'var(--text-1)' }}>XCloak</p>
          <p className="text-[9px] tracking-widest uppercase font-medium" style={{ color: 'var(--text-3)' }}>Security Suite</p>
        </div>
      )}
    </div>
  );
}

// ── Collapsed icon rail ──────────────────────────────────────────────────────

function CollapsedNav({
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
  const visibleNav = (NAV as unknown as any[]).filter((s: any) => !s.platformOnly || profile?.is_platform_admin);

  return (
    <>
      <nav className="flex-1 overflow-y-auto py-3 flex flex-col items-center gap-1 px-2">
        {visibleNav.map((section: any, si: number) => (
          <div key={section.group} className="flex flex-col items-center gap-1 w-full">
            {/* Divider between groups (not before first) */}
            {si > 0 && (
              <div className="w-8 my-1" style={{ height: 1, background: 'var(--border)' }} />
            )}
            {section.items.map((item: any) => {
              const Icon   = item.icon;
              const active = pathname === item.href || pathname?.startsWith(item.href + '/');
              const badge  = badges[item.href] ?? 0;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  title={item.label}
                  onClick={onNavigate}
                  className="relative flex h-10 w-10 items-center justify-center rounded-xl transition-all"
                  style={{
                    background: active ? 'var(--accent-glow)' : 'transparent',
                    color:      active ? 'var(--accent)' : 'var(--text-2)',
                    border:     active ? '1px solid var(--accent-border)' : '1px solid transparent',
                  }}
                  onMouseEnter={e => { if (!active) { (e.currentTarget as HTMLElement).style.background = 'var(--glass-hover)'; (e.currentTarget as HTMLElement).style.color = 'var(--text-1)'; } }}
                  onMouseLeave={e => { if (!active) { (e.currentTarget as HTMLElement).style.background = 'transparent'; (e.currentTarget as HTMLElement).style.color = 'var(--text-2)'; } }}
                >
                  <Icon className="shrink-0" style={{ width: 18, height: 18 }} />
                  {badge > 0 && (
                    <span
                      className="absolute -top-0.5 -right-0.5 flex h-4 min-w-4 items-center justify-center rounded-full px-0.5 text-[9px] font-bold"
                      style={{ background: 'var(--red)', color: '#fff' }}
                    >
                      {badge > 9 ? '9+' : badge}
                    </span>
                  )}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      <div
        className="flex justify-center pb-4 shrink-0 px-2"
        style={{ borderTop: '1px solid var(--border)', paddingTop: 10 }}
      >
        <button
          onClick={logout}
          title="Sign out"
          className="flex h-10 w-10 items-center justify-center rounded-xl transition-all"
          style={{ color: 'var(--text-2)' }}
          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--red-bg)'; (e.currentTarget as HTMLElement).style.color = 'var(--red)'; }}
          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; (e.currentTarget as HTMLElement).style.color = 'var(--text-2)'; }}
        >
          <LogOut style={{ width: 18, height: 18 }} />
        </button>
      </div>
    </>
  );
}

// ── Full expanded nav content ────────────────────────────────────────────────

function NavContent({
  pathname, onNavigate, logout, profile, badges,
}: {
  pathname: string | null;
  onNavigate?: () => void;
  logout: () => void;
  profile: UserProfile | null;
  badges: Record<string, number>;
}) {
  const [query, setQuery] = useState('');
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());

  const visibleNav = (NAV as unknown as any[]).filter((s: any) => !s.platformOnly || profile?.is_platform_admin);

  const lq = query.toLowerCase().trim();
  const displayed = lq
    ? visibleNav
        .map((s: any) => ({ ...s, items: s.items.filter((i: any) => i.label.toLowerCase().includes(lq)) }))
        .filter((s: any) => s.items.length > 0)
    : visibleNav;

  const toggleGroup = (group: string) =>
    setCollapsedGroups(prev => {
      const next = new Set(prev);
      next.has(group) ? next.delete(group) : next.add(group);
      return next;
    });

  const isGroupCollapsed = (group: string) => !lq && collapsedGroups.has(group);

  return (
    <>
      {/* Sidebar search */}
      <div className="px-3 pt-3 pb-2">
        <div
          className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 transition-colors"
          style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}
        >
          <Search className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Filter…"
            className="flex-1 bg-transparent outline-none text-[12px]"
            style={{ color: 'var(--text-1)' }}
          />
          {query && (
            <button onClick={() => setQuery('')} style={{ color: 'var(--text-3)' }}>
              <X className="h-3 w-3" />
            </button>
          )}
        </div>
      </div>

      {/* Nav groups */}
      <nav className="flex-1 overflow-y-auto px-2 pb-2 space-y-0.5">
        {displayed.length === 0 && (
          <p className="py-8 text-center text-xs" style={{ color: 'var(--text-3)' }}>
            No results for &quot;{query}&quot;
          </p>
        )}

        {displayed.map((section: any) => {
          const sectionCollapsed = isGroupCollapsed(section.group);
          const GroupIcon = section.icon;
          const hasActiveItem = section.items.some(
            (i: any) => pathname === i.href || pathname?.startsWith(i.href + '/'));
          const hasBadge = section.items.some((i: any) => (badges[i.href] ?? 0) > 0);

          return (
            <div key={section.group} className="mb-1">
              <button
                onClick={() => toggleGroup(section.group)}
                className="flex items-center justify-between w-full px-2.5 py-1.5 rounded-lg transition-colors"
                style={{ color: 'var(--text-3)' }}
                onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--glass-hover)'}
                onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}
              >
                <div className="flex items-center gap-2">
                  <GroupIcon className="h-3 w-3 shrink-0" />
                  <span className="text-[9.5px] font-bold tracking-widest uppercase">{section.group}</span>
                  {hasBadge && (
                    <span className="h-1.5 w-1.5 rounded-full shrink-0" style={{ background: 'var(--red)' }} />
                  )}
                </div>
                <div className="flex items-center gap-1.5">
                  {hasActiveItem && !sectionCollapsed && (
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: 'var(--accent)' }} />
                  )}
                  <ChevronDown
                    className="h-3 w-3 transition-transform duration-200"
                    style={{ transform: sectionCollapsed ? 'rotate(-90deg)' : 'rotate(0deg)' }}
                  />
                </div>
              </button>

              <div
                className="overflow-hidden transition-all duration-200"
                style={{ maxHeight: sectionCollapsed ? 0 : 9999, opacity: sectionCollapsed ? 0 : 1 }}
              >
                <div className="space-y-0.5 pl-1 pr-0.5 pb-1">
                  {section.items.map((item: any) => {
                    const Icon = item.icon;
                    const active = pathname === item.href || pathname?.startsWith(item.href + '/');
                    const badge  = badges[item.href] ?? 0;
                    return (
                      <Link
                        key={item.href}
                        href={item.href}
                        data-tour={item.href.slice(1)}
                        onClick={onNavigate}
                        className="flex items-center justify-between rounded-lg px-2.5 py-2 text-[12.5px] font-medium transition-all duration-100"
                        style={{
                          background: active ? 'var(--accent-glow)' : 'transparent',
                          color:      active ? 'var(--accent)' : 'var(--text-2)',
                          border:     active ? '1px solid var(--accent-border)' : '1px solid transparent',
                        }}
                        onMouseEnter={e => { if (!active) (e.currentTarget as HTMLElement).style.background = 'var(--glass-hover)'; }}
                        onMouseLeave={e => { if (!active) (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
                      >
                        <div className="flex items-center gap-2.5 min-w-0">
                          <Icon className="h-3.5 w-3.5 shrink-0" />
                          <span className="truncate">{item.label}</span>
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0">
                          <NavBadge count={badge} />
                          {active && <ChevronRight className="h-3 w-3 opacity-50" />}
                        </div>
                      </Link>
                    );
                  })}
                </div>
              </div>
            </div>
          );
        })}
      </nav>

      {/* Sign out */}
      <div
        className="px-2.5 pb-4 shrink-0"
        style={{ borderTop: '1px solid var(--border)', paddingTop: 10 }}
      >
        <button
          onClick={logout}
          className="flex w-full items-center gap-2.5 rounded-xl px-3 py-2.5 text-[13px] font-medium transition-all"
          style={{ color: 'var(--text-2)' }}
          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--red-bg)'; (e.currentTarget as HTMLElement).style.color = 'var(--red)'; }}
          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; (e.currentTarget as HTMLElement).style.color = 'var(--text-2)'; }}
        >
          <LogOut className="h-4 w-4" /> Sign out
        </button>
      </div>
    </>
  );
}

// ── Main export ──────────────────────────────────────────────────────────────

export function Sidebar({
  mobileOpen,
  onToggle,
  desktopCollapsed,
  onToggleCollapse,
  collapsedWidth = 68,
  expandedWidth  = 240,
}: {
  mobileOpen: boolean;
  onToggle: () => void;
  desktopCollapsed: boolean;
  onToggleCollapse: () => void;
  collapsedWidth?: number;
  expandedWidth?: number;
}) {
  const pathname = usePathname();
  const router   = useRouter();
  const { profile } = useUser();
  const [badges, setBadges] = useState<Record<string, number>>({});

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
    fetch('/api/auth/logout', { method: 'POST', credentials: 'include' }).catch(() => {});
    document.cookie = 'logged_in=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
    router.push('/login');
  };

  const sidebarStyle = {
    background: 'var(--glass-bg)',
    backdropFilter: 'var(--blur)',
    WebkitBackdropFilter: 'var(--blur)',
    borderRight: '1px solid var(--border)',
  } as const;

  return (
    <>
      {/* ── DESKTOP SIDEBAR (≥ lg) ──────────────────────────── */}
      <aside
        className="hidden lg:flex flex-col fixed left-0 top-0 h-screen z-40 transition-[width] duration-200"
        style={{ width: desktopCollapsed ? collapsedWidth : expandedWidth, ...sidebarStyle }}
      >
        {/* Logo row + collapse toggle */}
        <div
          className="flex items-center h-14 shrink-0 px-3"
          style={{
            borderBottom: '1px solid var(--border)',
            justifyContent: desktopCollapsed ? 'center' : 'space-between',
          }}
        >
          {desktopCollapsed ? (
            <button
              onClick={onToggleCollapse}
              title="Expand sidebar"
              className="flex h-9 w-9 items-center justify-center rounded-lg transition-colors"
              style={{ color: 'var(--accent)' }}
            >
              <Logo iconOnly />
            </button>
          ) : (
            <>
              <Logo />
              <button
                onClick={onToggleCollapse}
                title="Collapse sidebar"
                className="flex h-7 w-7 items-center justify-center rounded-lg transition-colors shrink-0"
                style={{ color: 'var(--text-3)', border: '1px solid var(--border)' }}
                onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = 'var(--accent)'; (e.currentTarget as HTMLElement).style.borderColor = 'var(--accent-border)'; }}
                onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'; (e.currentTarget as HTMLElement).style.borderColor = 'var(--border)'; }}
              >
                <PanelLeft className="h-3.5 w-3.5" />
              </button>
            </>
          )}
        </div>

        {desktopCollapsed ? (
          <CollapsedNav pathname={pathname} logout={logout} profile={profile} badges={badges} />
        ) : (
          <NavContent pathname={pathname} logout={logout} profile={profile} badges={badges} />
        )}
      </aside>

      {/* ── MOBILE ICON RAIL (< lg) — always visible ─────────── */}
      <aside
        className="lg:hidden flex flex-col fixed left-0 top-0 h-screen z-40"
        style={{ width: collapsedWidth, ...sidebarStyle }}
      >
        {/* Header: logo icon + expand button */}
        <div
          className="flex flex-col items-center h-14 shrink-0 justify-center gap-1 pt-1"
          style={{ borderBottom: '1px solid var(--border)' }}
        >
          <button
            onClick={onToggle}
            title="Open menu"
            className="flex h-9 w-9 items-center justify-center rounded-xl transition-colors"
            style={{ color: 'var(--accent)' }}
            onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--accent-glow)'; }}
            onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
          >
            <Logo iconOnly />
          </button>
        </div>
        <CollapsedNav pathname={pathname} onNavigate={undefined} logout={logout} profile={profile} badges={badges} />
      </aside>

      {/* ── MOBILE: full-screen overlay drawer (Discord-style) ── */}
      <div className="lg:hidden">
        {mobileOpen && (
          <div
            className="fixed inset-0 z-50"
            style={{ background: 'rgba(0,0,0,0.65)', backdropFilter: 'blur(4px)' }}
            onClick={onToggle}
          />
        )}

        <aside
          className="fixed top-0 left-0 h-screen z-[60] flex flex-col transition-transform duration-300 ease-in-out"
          style={{
            width: expandedWidth,
            background: 'var(--bg-1)',
            borderRight: '1px solid var(--border)',
            transform: mobileOpen ? 'translateX(0)' : 'translateX(-100%)',
          }}
        >
          <div
            className="flex items-center justify-between px-4 h-14 shrink-0"
            style={{ borderBottom: '1px solid var(--border)' }}
          >
            <Logo />
            <button onClick={onToggle} style={{ color: 'var(--text-2)' }}>
              <X className="h-4 w-4" />
            </button>
          </div>

          <NavContent
            pathname={pathname}
            onNavigate={onToggle}
            logout={logout}
            profile={profile}
            badges={badges}
          />
        </aside>
      </div>
    </>
  );
}
