'use client';

import { createContext, useContext, useEffect, useState, useCallback, useRef } from 'react';
import { Notification } from '@/types';

interface NotifCtx {
  notifications: Notification[];
  liveAlerts: LiveAlert[];          // real-time WS feed for dashboard
  unread: number;
  markRead:    (id: string) => void;
  markAllRead: () => void;
  dismiss:     (id: string) => void;
}

export interface LiveAlert {
  id: number;
  severity: string;
  rule_name: string;
  agent_id: number;
  message: string;
  timestamp: string;
}

const Ctx = createContext<NotifCtx>({
  notifications: [], liveAlerts: [], unread: 0,
  markRead: () => {}, markAllRead: () => {}, dismiss: () => {},
});

let notifIdCounter = 0;
const makeId = () => `notif-${++notifIdCounter}-${Date.now()}`;

const SEV_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export function NotificationProvider({ children }: { children: React.ReactNode }) {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [liveAlerts,    setLiveAlerts]    = useState<LiveAlert[]>([]);
  const wsRef       = useRef<WebSocket | null>(null);
  const reconnectRef = useRef<NodeJS.Timeout>();
  const mountedRef  = useRef(true);

  const addNotif = useCallback((n: Notification) => {
    setNotifications(prev => {
      // Deduplicate by type + content
      const dup = prev.find(x => x.type === n.type && x.message === n.message && !x.read);
      if (dup) return prev;
      return [n, ...prev].slice(0, 50);
    });
  }, []);

  const connectWS = useCallback(async () => {
    if (!mountedRef.current) return;

    // Fetch a short-lived single-use ticket via the proxy (carries the
    // httpOnly session cookie). The WS connection goes direct to the backend
    // port and can't carry the cookie, so we use the ticket instead.
    let ticket = '';
    try {
      const r = await fetch('/api/ws/ticket', { method: 'POST', credentials: 'include' });
      if (!r.ok) return; // not authenticated
      const data = await r.json();
      ticket = data.ticket;
    } catch {
      return;
    }
    if (!mountedRef.current) return;

    // In demo mode the WS backend isn't running — pre-populate with recent alerts instead
    if (ticket === 'demo-ws-ticket-noop') {
      try {
        const ar = await fetch('/api/alerts', { credentials: 'include' });
        if (ar.ok) {
          const alerts = await ar.json();
          const live = (Array.isArray(alerts) ? alerts : []).slice(0, 50).map((a: any) => ({
            id:        a.id,
            severity:  a.severity,
            rule_name: a.rule_name ?? 'Unknown Rule',
            agent_id:  a.agent_id,
            message:   a.log_message ?? a.rule_name ?? '',
            timestamp: a.created_at ?? new Date().toISOString(),
          }));
          if (mountedRef.current) setLiveAlerts(live);
        }
      } catch { /* ignore */ }
      return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const host     = window.location.hostname;
    const ws = new WebSocket(
      `${protocol}://${host}:8080/api/notifications/stream?ticket=${encodeURIComponent(ticket)}`
    );
    wsRef.current = ws;

    ws.onopen = () => {
      console.log('[NotifWS] connected');
    };

    ws.onmessage = (ev) => {
      try {
        const payload = JSON.parse(ev.data);
        if (payload.type === 'ping') return;

        if (payload.type === 'alert') {
          // Add to live alert ticker (capped at 50)
          setLiveAlerts(prev => [{
            id:        payload.id,
            severity:  payload.severity,
            rule_name: payload.rule_name,
            agent_id:  payload.agent_id,
            message:   payload.message,
            timestamp: payload.timestamp,
          }, ...prev].slice(0, 50));

          // Only bell-notify for critical/high
          if (SEV_ORDER[payload.severity] >= 3) {
            addNotif({
              id:         makeId(),
              type:       'alert',
              title:      `${payload.severity.toUpperCase()} Alert`,
              message:    payload.rule_name,
              severity:   payload.severity,
              read:       false,
              created_at: payload.timestamp,
            });
          }
        }

        if (payload.type === 'incident') {
          addNotif({
            id:         makeId(),
            type:       'incident',
            title:      'New Critical Incident',
            message:    payload.rule_name || payload.message,
            severity:   'critical',
            read:       false,
            created_at: payload.timestamp,
          });
        }
      } catch { /* ignore malformed */ }
    };

    ws.onclose = () => {
      if (!mountedRef.current) return;
      // Reconnect with 5s backoff
      reconnectRef.current = setTimeout(connectWS, 5000);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [addNotif]);

  useEffect(() => {
    mountedRef.current = true;
    connectWS();
    return () => {
      mountedRef.current = false;
      clearTimeout(reconnectRef.current);
      wsRef.current?.close();
    };
  }, [connectWS]);

  const unread = notifications.filter(n => !n.read).length;

  const markRead = useCallback((id: string) =>
    setNotifications(prev => prev.map(n => n.id === id ? { ...n, read: true } : n)), []);

  const markAllRead = useCallback(() =>
    setNotifications(prev => prev.map(n => ({ ...n, read: true }))), []);

  const dismiss = useCallback((id: string) =>
    setNotifications(prev => prev.filter(n => n.id !== id)), []);

  return (
    <Ctx.Provider value={{ notifications, liveAlerts, unread, markRead, markAllRead, dismiss }}>
      {children}
    </Ctx.Provider>
  );
}

export const useNotifications = () => useContext(Ctx);
