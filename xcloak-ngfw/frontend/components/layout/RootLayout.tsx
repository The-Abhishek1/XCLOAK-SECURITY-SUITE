'use client';

import React, { useState, useRef, useEffect } from 'react';
import { Sidebar } from './Sidebar';
import { useNotifications } from '@/context/NotificationContext';
import { useTheme } from '@/context/ThemeContext';
import { useUser } from '@/context/UserContext';
import { RefreshCw, Bell, X, Sun, Moon, Check, AlertTriangle, Zap, Settings, Clock } from 'lucide-react';
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
  return (
    <div className="flex min-h-screen" style={{ background: 'var(--bg-0)' }}>
      <div className="bg-mesh" />
      <Sidebar />
 <div className="flex flex-1 flex-col min-w-0 ml-0 lg:ml-[240px] pt-14 lg:pt-0">
        <AppHeader title={title} subtitle={subtitle} onRefresh={onRefresh} refreshing={refreshing} actions={actions} />
        <main className="flex-1 p-4 sm:p-6 relative z-10">{children}</main>
      </div>
    </div>
  );
}

const ROLE_COLORS: Record<string, string> = {
  admin:   'var(--red)',
  analyst: 'var(--orange)',
  viewer:  'var(--text-3)',
};

function AppHeader({ title, subtitle, onRefresh, refreshing, actions }: Omit<RootLayoutProps, 'children'>) {
  const { notifications, unread, markRead, markAllRead, dismiss } = useNotifications();
  const { theme, toggle } = useTheme();
  const { profile } = useUser();
  const [bellOpen, setBellOpen] = useState(false);
  const [time, setTime] = useState('');
  const bellRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const update = () => setTime(new Date().toLocaleTimeString('en-US', {
      timeZone: 'UTC',
      hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
    }));
    update();
    const t = setInterval(update, 1000);
    return () => clearInterval(t);
  }, []);

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
      case 'incident': return <Zap className="h-3.5 w-3.5" style={{ color: 'var(--orange)' }} />;
      case 'task':     return <Settings className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />;
      default:         return <Bell className="h-3.5 w-3.5" style={{ color: 'var(--text-2)' }} />;
    }
  };

  return (
    <header className="sticky top-14 lg:top-0 z-30 flex h-14 items-center justify-between px-5 gap-4"
      style={{
        background: 'var(--glass-bg)',
        backdropFilter: 'var(--blur)',
        WebkitBackdropFilter: 'var(--blur)',
        borderBottom: '1px solid var(--border)',
      }}>

      <div className="min-w-0 flex-1">
        {title && (
          <div className="flex items-center gap-2">
            <h1 className="text-[15px] font-semibold truncate" style={{ color: 'var(--text-1)' }}>{title}</h1>
            {subtitle && (
              <>
                <span style={{ color: 'var(--text-3)' }}>·</span>
                <p className="text-xs truncate hidden sm:block" style={{ color: 'var(--text-2)' }}>{subtitle}</p>
              </>
            )}
          </div>
        )}
      </div>

      <div className="flex items-center gap-2 shrink-0">
        {actions}

        <div className="hidden md:block">
          <GlobalSearch />
        </div>

        <div className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-lg"
          style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}>
          <Clock className="h-3 w-3" style={{ color: 'var(--text-3)' }} />
          <span className="mono text-[11px]" style={{ color: 'var(--text-2)' }}>{time || '--:--:--'} UTC</span>
        </div>

        {onRefresh && (
          <button onClick={onRefresh} disabled={refreshing}
            className="flex h-8 w-8 items-center justify-center rounded-lg transition-colors"
            style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)', color: 'var(--text-2)' }}
            onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--accent)'}
            onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-2)'}>
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} />
          </button>
        )}

        <button onClick={toggle}
          className="flex h-8 w-8 items-center justify-center rounded-lg transition-colors"
          style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)', color: 'var(--text-2)' }}
          onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--accent)'}
          onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-2)'}>
          {theme === 'dark' ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
        </button>

        {/* Notification bell */}
        <div className="relative" ref={bellRef}>
          <button onClick={() => setBellOpen(p => !p)}
            className="flex h-8 w-8 items-center justify-center rounded-lg transition-colors relative"
            style={{
              background: bellOpen ? 'var(--accent-glow)' : 'var(--glass-bg-2)',
              border: `1px solid ${bellOpen ? 'var(--accent-border)' : 'var(--border)'}`,
              color: bellOpen ? 'var(--accent)' : 'var(--text-2)',
            }}>
            <Bell className="h-3.5 w-3.5" />
            {unread > 0 && (
              <span className="absolute -top-1 -right-1 flex h-4 min-w-4 items-center justify-center rounded-full px-1 text-[9px] font-bold"
                style={{ background: 'var(--red)', color: '#fff' }}>
                {unread > 9 ? '9+' : unread}
              </span>
            )}
          </button>

          {bellOpen && (
            <div className="absolute right-0 top-10 w-80 rounded-xl overflow-hidden"
              style={{
                background: 'var(--glass-modal)',
                backdropFilter: 'var(--blur)',
                WebkitBackdropFilter: 'var(--blur)',
                border: '1px solid var(--border-md)',
                boxShadow: '0 20px 60px rgba(0,0,0,0.4)',
                zIndex: 100,
              }}>
              <div className="flex items-center justify-between px-4 py-3"
                style={{ borderBottom: '1px solid var(--border)' }}>
                <div className="flex items-center gap-2">
                  <Bell className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
                  <span className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Notifications</span>
                  {unread > 0 && (
                    <span className="rounded-full px-1.5 py-0.5 text-[9px] font-bold"
                      style={{ background: 'var(--red)', color: '#fff' }}>{unread}</span>
                  )}
                </div>
                {unread > 0 && (
                  <button onClick={markAllRead} className="flex items-center gap-1 text-[10px]"
                    style={{ color: 'var(--accent)' }}>
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
                  <div key={n.id}
                    className="flex items-start gap-3 px-4 py-3 cursor-pointer transition-colors"
                    style={{
                      background: n.read ? 'transparent' : 'var(--accent-glow)',
                      borderBottom: '1px solid var(--border)',
                    }}
                    onClick={() => markRead(n.id)}
                    onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--glass-hover)'}
                    onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = n.read ? 'transparent' : 'var(--accent-glow)'}>
                    <div className="mt-0.5 shrink-0">{notifIcon(n.type)}</div>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{n.title}</p>
                      <p className="text-[11px] truncate mt-0.5" style={{ color: 'var(--text-2)' }}>{n.message}</p>
                      <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>{timeAgo(n.created_at)}</p>
                    </div>
                    <button onClick={e => { e.stopPropagation(); dismiss(n.id); }}
                      className="shrink-0 mt-0.5" style={{ color: 'var(--text-3)' }}>
                      <X className="h-3 w-3" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* User badge — hydrated from shared UserContext */}
        {profile && (
          <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg"
            style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}>
            <div className="h-5 w-5 rounded-full flex items-center justify-center text-[10px] font-bold shrink-0"
              style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)', color: 'var(--accent)' }}>
              {profile.username.charAt(0).toUpperCase()}
            </div>
            <div className="min-w-0">
              <p className="text-[11px] font-semibold leading-none" style={{ color: 'var(--text-1)' }}>
                {profile.username}
              </p>
              <p className="text-[9px] leading-none mt-0.5" style={{ color: 'var(--text-3)' }}>
                <span style={{ color: ROLE_COLORS[profile.role] ?? 'var(--text-3)', fontWeight: 600 }}>
                  {profile.role}
                </span>
                {' · '}{profile.tenant_name}
              </p>
            </div>
          </div>
        )}
      </div>
    </header>
  );
}
