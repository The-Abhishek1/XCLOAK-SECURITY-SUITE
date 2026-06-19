'use client';

import { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useRouter } from 'next/navigation';
import { useTheme } from '@/context/ThemeContext';
import {
  LayoutDashboard, Cpu, Bell, AlertTriangle, Play,
  Shield, Bug, Settings, ShieldCheck, LogOut,
  Sun, Moon, Archive, ChevronRight, Network, FileCode, Code2,
  ClipboardCheck, Bot, Radio, Search, CalendarClock,
  GitMerge, Map, Clock, VolumeX, TerminalSquare, Menu, X,
} from 'lucide-react';

const NAV = [
  { group: 'OVERVIEW', items: [
    { href: '/dashboard',   label: 'Dashboard',   icon: LayoutDashboard },
    { href: '/agents',      label: 'Agents',      icon: Cpu },
    { href: '/network-map', label: 'Network Map', icon: Map },
    { href: '/timeline',    label: 'Timeline',    icon: Clock },
  ]},
  { group: 'DETECTION', items: [
    { href: '/alerts',       label: 'Alerts',       icon: Bell },
    { href: '/incidents',    label: 'Incidents',    icon: AlertTriangle },
    { href: '/threat-intel', label: 'Threat Intel', icon: Shield },
    { href: '/sigma-rules',  label: 'Sigma Rules',  icon: FileCode },
    { href: '/yara-rules',   label: 'YARA Rules',   icon: Code2 },
    { href: '/live-logs',    label: 'Live Logs',    icon: Radio },
    { href: '/hunt',         label: 'Threat Hunt',  icon: Search },
    { href: '/correlation',  label: 'Correlation',  icon: GitMerge },
    { href: '/suppression',  label: 'Suppression',  icon: VolumeX },
  ]},
  { group: 'RESPONSE', items: [
    { href: '/playbooks',       label: 'Playbooks',       icon: Play },
    { href: '/soar-approvals',  label: 'Approval Queue',  icon: ShieldCheck },
    { href: '/vulnerabilities', label: 'Vulnerabilities', icon: Bug },
    { href: '/quarantine',      label: 'Quarantine',      icon: Archive },
    { href: '/firewall',        label: 'Firewall',        icon: Network },
    { href: '/scheduled-tasks',  label: 'Scheduled Tasks', icon: CalendarClock },
    { href: '/script-runner',    label: 'Script Runner',    icon: TerminalSquare },
  ]},
  { group: 'COMPLIANCE', items: [
    { href: '/compliance', label: 'Reports', icon: ClipboardCheck },
  ]},
  { group: 'AI', items: [
    { href: '/ai-assistant', label: 'AI Assistant', icon: Bot },
  ]},
  { group: 'SYSTEM', items: [
    { href: '/settings', label: 'Settings', icon: Settings },
  ]},
];

function NavContent({
  pathname,
  onNavigate,
  toggle,
  logout,
  theme,
}: {
  pathname: string | null;
  onNavigate?: () => void;
  toggle: () => void;
  logout: () => void;
  theme: string;
}) {
  return (
    <>
      <nav className="flex-1 overflow-y-auto px-2.5 py-4 space-y-5">
        {NAV.map(section => (
          <div key={section.group}>
            <p className="px-3 mb-1.5 text-[9px] font-bold tracking-widest uppercase"
              style={{ color: 'var(--text-3)' }}>
              {section.group}
            </p>
            <div className="space-y-0.5">
              {section.items.map(item => {
                const Icon   = item.icon;
                const active = pathname === item.href || pathname?.startsWith(item.href + '/');
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
                    {active && <ChevronRight className="h-3 w-3 opacity-50" />}
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      <div className="px-2.5 pb-4 space-y-0.5 shrink-0"
        style={{ borderTop: '1px solid var(--border)', paddingTop: 10 }}>
        <button onClick={toggle}
          className="flex w-full items-center gap-2.5 rounded-xl px-3 py-2.5 text-[13px] font-medium transition-all"
          style={{ color: 'var(--text-2)' }}
          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--glass-hover)'; }}
          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}>
          {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          {theme === 'dark' ? 'Light mode' : 'Dark mode'}
        </button>
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
  const { theme, toggle } = useTheme();
  const [mobileOpen, setMobileOpen] = useState(false);

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
          toggle={toggle}
          logout={logout}
          theme={theme}
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
            toggle={toggle}
            logout={logout}
            theme={theme}
          />
        </aside>
      </div>
    </>
  );
}
