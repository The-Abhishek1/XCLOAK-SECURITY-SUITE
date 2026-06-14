'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useRouter } from 'next/navigation';
import { useTheme } from '@/context/ThemeContext';
import {
  LayoutDashboard, Cpu, Bell, AlertTriangle, Play,
  Shield, Bug, Settings, ShieldCheck, LogOut,
  Sun, Moon, Archive, ChevronRight, Network, FileCode, Code2,
  ClipboardCheck, Bot, Radio, ShieldAlert, Search, CalendarClock,
} from 'lucide-react';

const NAV = [
  { group: 'OVERVIEW',  items: [
    { href: '/dashboard',   label: 'Dashboard',       icon: LayoutDashboard },
    { href: '/agents',      label: 'Agents',          icon: Cpu },
  ]},
  { group: 'DETECTION', items: [
    { href: '/alerts',       label: 'Alerts',          icon: Bell },
    { href: '/incidents',    label: 'Incidents',       icon: AlertTriangle },
    { href: '/threat-intel', label: 'Threat Intel',    icon: Shield },
    { href: '/sigma-rules',  label: 'Sigma Rules',     icon: FileCode },
    { href: '/yara-rules',   label: 'YARA Rules',      icon: Code2 },
    { href: '/live-logs',    label: 'Live Logs',       icon: Radio },
    { href: '/hunt',         label: 'Threat Hunt',     icon: Search },
  ]},
  { group: 'RESPONSE',  items: [
    { href: '/playbooks',        label: 'Playbooks',       icon: Play },
    { href: '/vulnerabilities',  label: 'Vulnerabilities', icon: Bug },
    { href: '/quarantine',       label: 'Quarantine',      icon: Archive },
    { href: '/firewall',         label: 'Firewall',        icon: Network },
    { href: '/scheduled-tasks',  label: 'Scheduled Tasks', icon: CalendarClock },
  ]},
  { group: 'COMPLIANCE', items: [
    { href: '/compliance', label: 'Reports',  icon: ClipboardCheck },
  ]},
  { group: 'AI',  items: [
    { href: '/ai-assistant', label: 'AI Assistant', icon: Bot },
  ]},
  { group: 'SYSTEM',    items: [
    { href: '/settings', label: 'Settings', icon: Settings },
  ]},
];

export function Sidebar() {
  const pathname = usePathname();
  const router   = useRouter();
  const { theme, toggle } = useTheme();

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    document.cookie = 'token=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
    router.push('/login');
  };

  return (
    <>
      {/* ── DESKTOP SIDEBAR (240px) ─────────────────────── */}
      <aside className="hidden lg:flex flex-col fixed left-0 top-0 h-screen z-40"
        style={{
          width: 240,
          background: 'var(--glass-bg)',
          backdropFilter: 'var(--blur)',
          WebkitBackdropFilter: 'var(--blur)',
          borderRight: '1px solid var(--border)',
        }}>

        {/* Logo */}
        <div className="flex items-center gap-3 px-5 h-14 shrink-0"
          style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="flex h-8 w-8 items-center justify-center rounded-xl shrink-0"
            style={{
              background: 'var(--accent-glow)',
              border: '1px solid var(--accent-border)',
              boxShadow: '0 0 16px var(--accent-glow)',
            }}>
            <ShieldCheck className="h-4 w-4" style={{ color: 'var(--accent)' }} />
          </div>
          <div>
            <p className="text-sm font-bold tracking-wide" style={{ color: 'var(--text-1)' }}>
              XCloak
            </p>
            <p className="text-[9px] tracking-widest uppercase font-medium" style={{ color: 'var(--text-3)' }}>
              Security Suite
            </p>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto px-2.5 py-4 space-y-5">
          {NAV.map(section => (
            <div key={section.group}>
              <p className="px-3 mb-1.5 text-[9px] font-bold tracking-widest uppercase"
                style={{ color: 'var(--text-3)' }}>
                {section.group}
              </p>
              <div className="space-y-0.5">
                {section.items.map(item => {
                  const Icon    = item.icon;
                  const active  = pathname === item.href || pathname?.startsWith(item.href + '/');
                  return (
                    <Link key={item.href} href={item.href}
                      className="flex items-center justify-between rounded-xl px-3 py-2.5 text-[13px] font-medium transition-all duration-150"
                      style={{
                        background:   active ? 'var(--accent-glow)' : 'transparent',
                        color:        active ? 'var(--accent)' : 'var(--text-2)',
                        border:       active ? '1px solid var(--accent-border)' : '1px solid transparent',
                        backdropFilter: active ? 'var(--blur-sm)' : undefined,
                        boxShadow:    active ? '0 0 12px var(--accent-glow)' : undefined,
                      }}
                      onMouseEnter={e => { if (!active) (e.currentTarget as HTMLElement).style.background = 'var(--glass-hover)'; }}
                      onMouseLeave={e => { if (!active) (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
                    >
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

        {/* Footer */}
        <div className="px-2.5 pb-4 space-y-0.5 shrink-0"
          style={{ borderTop: '1px solid var(--border)', paddingTop: 10 }}>
          <button onClick={toggle}
            className="flex w-full items-center gap-2.5 rounded-xl px-3 py-2.5 text-[13px] font-medium transition-all"
            style={{ color: 'var(--text-2)' }}
            onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--glass-hover)'; (e.currentTarget as HTMLElement).style.color = 'var(--text-1)'; }}
            onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; (e.currentTarget as HTMLElement).style.color = 'var(--text-2)'; }}>
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
      </aside>

      {/* ── MOBILE ICON RAIL (56px) ──────────────────────── */}
      <aside className="lg:hidden fixed left-0 top-0 h-screen z-40 flex flex-col items-center py-3 gap-1"
        style={{
          width: 56,
          background: 'var(--glass-bg)',
          backdropFilter: 'var(--blur)',
          WebkitBackdropFilter: 'var(--blur)',
          borderRight: '1px solid var(--border)',
        }}>

        <div className="flex h-10 w-10 items-center justify-center rounded-xl mb-3"
          style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
          <ShieldCheck className="h-5 w-5" style={{ color: 'var(--accent)' }} />
        </div>

        <div className="flex-1 flex flex-col gap-1 w-full px-1.5 overflow-y-auto">
          {NAV.flatMap(s => s.items).map(item => {
            const Icon   = item.icon;
            const active = pathname === item.href || pathname?.startsWith(item.href + '/');
            return (
              <Link key={item.href} href={item.href}
                title={item.label}
                className="flex items-center justify-center rounded-xl h-10 w-10 mx-auto transition-all"
                style={{
                  background: active ? 'var(--accent-glow)' : 'transparent',
                  border:     active ? '1px solid var(--accent-border)' : '1px solid transparent',
                  color:      active ? 'var(--accent)' : 'var(--text-2)',
                }}>
                <Icon className="h-4 w-4" />
              </Link>
            );
          })}
        </div>

        <div className="flex flex-col gap-1 w-full px-1.5">
          <button onClick={toggle} title="Toggle theme"
            className="flex items-center justify-center rounded-xl h-10 w-10 mx-auto transition-all"
            style={{ color: 'var(--text-2)' }}>
            {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>
          <button onClick={logout} title="Sign out"
            className="flex items-center justify-center rounded-xl h-10 w-10 mx-auto transition-all"
            style={{ color: 'var(--text-2)' }}>
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </aside>
    </>
  );
}
