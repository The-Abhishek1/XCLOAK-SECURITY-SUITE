'use client';

import React, { useState, useRef, useEffect } from 'react';
import { Sidebar } from './Sidebar';
import { useNotifications } from '@/context/NotificationContext';
import { useTheme } from '@/context/ThemeContext';
import { useUser } from '@/context/UserContext';
import { RefreshCw, Bell, X, Sun, Moon, Check, AlertTriangle, Zap, Settings, Clock, FlaskConical } from 'lucide-react';
import Link from 'next/link';
import { GlobalSearch } from '@/components/GlobalSearch';
import { timeAgo } from '@/lib/utils';

interface RootLayoutProps {
  children: React.ReactNode;
  title?: string;
  subtitle?: string;
  onRefresh?: () => void;
  refreshing?: boolean;
  actions?: React.ReactNode;
}

export function RootLayout({ children, title, subtitle, onRefresh, refreshing, actions }: RootLayoutProps) {
  const [mobileOpen, setMobileOpen]             = useState(false);
  const [desktopCollapsed, setDesktopCollapsed] = useState(false);
  const [isDesktop, setIsDesktop]               = useState(false);

  useEffect(() => {
    // Restore collapse preference
    setDesktopCollapsed(localStorage.getItem('sidebar-collapsed') === 'true');

    // Track lg breakpoint (1024px) so we only apply left margin on desktop.
    // Below lg the sidebar is hidden and the margin must be 0.
    const mq = window.matchMedia('(min-width: 1024px)');
    setIsDesktop(mq.matches);
    const handler = (e: MediaQueryListEvent) => setIsDesktop(e.matches);
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, []);

  const toggleMenu = () => setMobileOpen(o => !o);

  const toggleCollapse = () => {
    setDesktopCollapsed(c => {
      const next = !c;
      localStorage.setItem('sidebar-collapsed', String(next));
      return next;
    });
  };

  const COLLAPSED_W = 68;
  const EXPANDED_W  = 240;
  const sidebarW    = desktopCollapsed ? COLLAPSED_W : EXPANDED_W;

  return (
    <div className="flex min-h-screen" style={{ background: 'var(--bg-0)' }}>
      <div className="bg-mesh" />
      <Sidebar
        mobileOpen={mobileOpen}
        onToggle={toggleMenu}
        desktopCollapsed={desktopCollapsed}
        onToggleCollapse={toggleCollapse}
        collapsedWidth={COLLAPSED_W}
        expandedWidth={EXPANDED_W}
      />
      {/* Margin only on desktop — sidebar is hidden (display:none) below lg */}
      <div
        className="flex flex-1 flex-col min-w-0 transition-[margin-left] duration-200"
        style={{ marginLeft: isDesktop ? `${sidebarW}px` : `${COLLAPSED_W}px` }}
      >
        <AppHeader
          title={title}
          subtitle={subtitle}
          onRefresh={onRefresh}
          refreshing={refreshing}
          actions={actions}
        />
        {/* No z-10 here — fixed drawers inside children need to compete in the root
            stacking context at their own z-index (z-50), above the header (z-30). */}
        <main className="flex-1 p-4 sm:p-6">{children}</main>
      </div>
    </div>
  );
}

const ROLE_COLORS: Record<string, string> = {
  admin:   'var(--red)',
  analyst: 'var(--orange)',
  viewer:  'var(--text-3)',
};

function AppHeader({
  title, subtitle, onRefresh, refreshing, actions,
}: Omit<RootLayoutProps, 'children'> & { onToggleMenu?: () => void }) {
  const { notifications, unread, markRead, markAllRead, dismiss } = useNotifications();
  const { theme, toggle } = useTheme();
  const { profile } = useUser();
  const [bellOpen, setBellOpen]   = useState(false);
  const [useUTC, setUseUTC]       = useState(false);
  const [time, setTime]           = useState('');
  const [tzLabel, setTzLabel]     = useState('');
  const bellRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const update = () => {
      const now = new Date();
      if (useUTC) {
        setTime(now.toLocaleTimeString('en-US', { timeZone: 'UTC', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }));
        setTzLabel('UTC');
      } else {
        setTime(now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }));
        // Short timezone abbreviation from Intl if available
        try {
          const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
          const abbr = now.toLocaleTimeString('en-US', { timeZoneName: 'short' }).split(' ').pop() || tz;
          setTzLabel(abbr);
        } catch { setTzLabel('Local'); }
      }
    };
    update();
    const t = setInterval(update, 1000);
    return () => clearInterval(t);
  }, [useUTC]);

  // Close bell on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (bellRef.current && !bellRef.current.contains(e.target as Node)) setBellOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const notifIcon = (type: string) => {
    switch (type) {
      case 'alert':    return <AlertTriangle className="h-3.5 w-3.5" style={{ color: 'var(--red)' }} />;
      case 'incident': return <Zap          className="h-3.5 w-3.5" style={{ color: 'var(--orange)' }} />;
      case 'task':     return <Settings     className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />;
      default:         return <Bell         className="h-3.5 w-3.5" style={{ color: 'var(--text-2)' }} />;
    }
  };

  return (
    <header
      className="sticky top-0 z-30 flex h-14 items-center justify-between px-4 gap-2"
      style={{
        background: 'var(--glass-bg)',
        backdropFilter: 'var(--blur)',
        WebkitBackdropFilter: 'var(--blur)',
        borderBottom: '1px solid var(--border)',
      }}
    >
      {/* Page title */}
      <div className="min-w-0 flex-1">
        {title && (
          <div className="flex items-center gap-2 min-w-0">
            <h1 className="text-[15px] font-semibold truncate" style={{ color: 'var(--text-1)' }}>{title}</h1>
            {subtitle && (
              <>
                <span className="hidden sm:inline" style={{ color: 'var(--text-3)' }}>·</span>
                <p className="text-xs truncate hidden sm:block" style={{ color: 'var(--text-2)' }}>{subtitle}</p>
              </>
            )}
          </div>
        )}
      </div>

      {/* Right-side actions */}
      <div className="flex items-center gap-1.5 shrink-0">
        {actions}
        <DemoBadge />

        {/* Global search */}
        <div className="hidden md:block"><GlobalSearch /></div>
        <div className="flex md:hidden"><GlobalSearch compact /></div>

        {/* Clock — click to toggle local ↔ UTC */}
        <button
          onClick={() => setUseUTC(u => !u)}
          title={useUTC ? 'Switch to local time' : 'Switch to UTC'}
          className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-lg transition-colors"
          style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}
          onMouseEnter={e => (e.currentTarget as HTMLElement).style.borderColor = 'var(--accent-border)'}
          onMouseLeave={e => (e.currentTarget as HTMLElement).style.borderColor = 'var(--border)'}
        >
          <Clock className="h-3 w-3" style={{ color: 'var(--text-3)' }} />
          <span className="mono text-[11px]" style={{ color: 'var(--text-2)' }}>{time || '--:--:--'}</span>
          <span className="text-[9px] font-semibold uppercase" style={{ color: useUTC ? 'var(--accent)' : 'var(--text-3)' }}>{tzLabel}</span>
        </button>

        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={refreshing}
            className="flex h-8 w-8 items-center justify-center rounded-lg transition-colors"
            style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)', color: 'var(--text-2)' }}
            onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--accent)'}
            onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-2)'}
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} />
          </button>
        )}

        <button
          onClick={toggle}
          className="flex h-8 w-8 items-center justify-center rounded-lg transition-colors"
          style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)', color: 'var(--text-2)' }}
          onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--accent)'}
          onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-2)'}
        >
          {theme === 'dark' ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
        </button>

        {/* Notification bell — dropdown rendered with fixed positioning on narrow viewports */}
        <div className="relative" ref={bellRef}>
          <button
            onClick={() => setBellOpen(p => !p)}
            className="flex h-8 w-8 items-center justify-center rounded-lg transition-colors relative"
            style={{
              background: bellOpen ? 'var(--accent-glow)' : 'var(--glass-bg-2)',
              border: `1px solid ${bellOpen ? 'var(--accent-border)' : 'var(--border)'}`,
              color: bellOpen ? 'var(--accent)' : 'var(--text-2)',
            }}
          >
            <Bell className="h-3.5 w-3.5" />
            {unread > 0 && (
              <span
                className="absolute -top-1 -right-1 flex h-4 min-w-4 items-center justify-center rounded-full px-1 text-[9px] font-bold"
                style={{ background: 'var(--red)', color: '#fff' }}
              >
                {unread > 9 ? '9+' : unread}
              </span>
            )}
          </button>

          {bellOpen && (
            <div
              className="absolute right-0 top-10 w-80 rounded-xl overflow-hidden"
              style={{
                background: 'var(--glass-modal)',
                backdropFilter: 'var(--blur)',
                WebkitBackdropFilter: 'var(--blur)',
                border: '1px solid var(--border-md)',
                boxShadow: '0 20px 60px rgba(0,0,0,0.4)',
                zIndex: 200,
                // Clamp to viewport on narrow screens
                maxWidth: 'calc(100vw - 16px)',
              }}
            >
              <div
                className="flex items-center justify-between px-4 py-3"
                style={{ borderBottom: '1px solid var(--border)' }}
              >
                <div className="flex items-center gap-2">
                  <Bell className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
                  <span className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Notifications</span>
                  {unread > 0 && (
                    <span
                      className="rounded-full px-1.5 py-0.5 text-[9px] font-bold"
                      style={{ background: 'var(--red)', color: '#fff' }}
                    >{unread}</span>
                  )}
                </div>
                {unread > 0 && (
                  <button onClick={markAllRead} className="flex items-center gap-1 text-[10px]" style={{ color: 'var(--accent)' }}>
                    <Check className="h-3 w-3" /> Mark all read
                  </button>
                )}
              </div>

              <div className="max-h-80 overflow-y-auto">
                {notifications.length === 0 ? (
                  <div className="py-10 text-center">
                    <Bell className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
                    <p className="text-xs" style={{ color: 'var(--text-3)' }}>No notifications</p>
                  </div>
                ) : notifications.map(n => (
                  <div
                    key={n.id}
                    className="flex items-start gap-3 px-4 py-3 cursor-pointer transition-colors"
                    style={{
                      background: n.read ? 'transparent' : 'var(--accent-glow)',
                      borderBottom: '1px solid var(--border)',
                    }}
                    onClick={() => markRead(n.id)}
                    onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--glass-hover)'}
                    onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = n.read ? 'transparent' : 'var(--accent-glow)'}
                  >
                    <div className="mt-0.5 shrink-0">{notifIcon(n.type)}</div>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{n.title}</p>
                      <p className="text-[11px] truncate mt-0.5" style={{ color: 'var(--text-2)' }}>{n.message}</p>
                      <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{timeAgo(n.created_at)}</p>
                    </div>
                    <button
                      onClick={e => { e.stopPropagation(); dismiss(n.id); }}
                      className="shrink-0 mt-0.5"
                      style={{ color: 'var(--text-3)' }}
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* User badge — links to profile settings */}
        {profile && (
          <Link
            href="/settings?tab=profile"
            className="flex items-center gap-2 px-2 py-1.5 rounded-lg transition-colors"
            style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}
            onMouseEnter={e => (e.currentTarget as HTMLElement).style.borderColor = 'var(--accent-border)'}
            onMouseLeave={e => (e.currentTarget as HTMLElement).style.borderColor = 'var(--border)'}
          >
            <div
              className="h-6 w-6 rounded-full flex items-center justify-center text-[10px] font-bold shrink-0"
              style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)', color: 'var(--accent)' }}
            >
              {profile.username.charAt(0).toUpperCase()}
            </div>
            <div className="min-w-0 hidden md:block">
              <p className="text-[11px] font-semibold leading-none" style={{ color: 'var(--text-1)' }}>
                {profile.username}
              </p>
              <p className="text-[9px] leading-none mt-0.5" style={{ color: 'var(--text-3)' }}>
                {/* Only show role if it differs from username */}
                {profile.role !== profile.username && (
                  <>
                    <span style={{ color: ROLE_COLORS[profile.role] ?? 'var(--text-3)', fontWeight: 600 }}>
                      {profile.role}
                    </span>
                    {' · '}
                  </>
                )}
                {profile.tenant_name}
              </p>
            </div>
          </Link>
        )}
      </div>
    </header>
  );
}

function DemoBadge() {
  const [show, setShow] = useState(false);
  useEffect(() => {
    setShow(document.cookie.split(';').some(c => c.trim().startsWith('demo_mode=')));
  }, []);
  if (!show) return null;
  return (
    <a
      href="https://xcloak.tech"
      target="_blank"
      rel="noopener noreferrer"
      title="Demo mode — visit xcloak.tech for full access"
      className="flex items-center gap-1 rounded-full px-2 py-1 shrink-0 transition-opacity hover:opacity-80"
      style={{ background: 'rgba(250,204,21,0.15)', border: '1px solid rgba(250,204,21,0.4)', color: '#ca8a04' }}
    >
      <FlaskConical className="h-3 w-3" />
      <span className="hidden md:inline text-[10px] font-bold uppercase tracking-wide whitespace-nowrap">Demo</span>
    </a>
  );
}
