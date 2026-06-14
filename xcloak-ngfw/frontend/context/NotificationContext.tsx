'use client';

import { createContext, useContext, useEffect, useState, useCallback, useRef } from 'react';
import { alertsAPI, incidentsAPI } from '@/lib/api';
import { Notification } from '@/types';

interface NotifCtx {
  notifications: Notification[];
  unread: number;
  markRead: (id: string) => void;
  markAllRead: () => void;
  dismiss: (id: string) => void;
}

const Ctx = createContext<NotifCtx>({
  notifications: [], unread: 0,
  markRead: () => {}, markAllRead: () => {}, dismiss: () => {},
});

let notifIdCounter = 0;
const makeId = () => `notif-${++notifIdCounter}-${Date.now()}`;

export function NotificationProvider({ children }: { children: React.ReactNode }) {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const seenAlerts    = useRef<Set<number>>(new Set());
  const seenIncidents = useRef<Set<number>>(new Set());
  const initialized   = useRef(false);

  const poll = useCallback(async () => {
    try {
      const [ar, ir] = await Promise.allSettled([alertsAPI.getAll(), incidentsAPI.getAll()]);
      const newNotifs: Notification[] = [];

      if (ar.status === 'fulfilled') {
        const alerts = ar.value.data || [];
        for (const a of alerts) {
          if (seenAlerts.current.has(a.id)) continue;
          seenAlerts.current.add(a.id);
          if (!initialized.current) continue; // first load: just seed, don't notify
          if (a.severity === 'critical' || a.severity === 'high') {
            newNotifs.push({
              id: makeId(), type: 'alert',
              title: `${a.severity.toUpperCase()} Alert`,
              message: a.rule_name,
              severity: a.severity, read: false, created_at: a.created_at,
            });
          }
        }
      }

      if (ir.status === 'fulfilled') {
        const incidents = ir.value.data || [];
        for (const i of incidents) {
          if (seenIncidents.current.has(i.id)) continue;
          seenIncidents.current.add(i.id);
          if (!initialized.current) continue;
          if (i.severity === 'critical') {
            newNotifs.push({
              id: makeId(), type: 'incident',
              title: 'New Critical Incident',
              message: i.title,
              severity: i.severity, read: false, created_at: i.created_at,
            });
          }
        }
      }

      initialized.current = true;
      if (newNotifs.length > 0) {
        setNotifications(p => [...newNotifs, ...p].slice(0, 50));
      }
    } catch {}
  }, []);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) return;

    poll();
    const t = setInterval(poll, 30000);

    // Real-time WebSocket notifications from backend.
    const wsUrl = `ws://localhost:8080/api/notifications/stream?token=${encodeURIComponent(token)}`;
    const ws = new WebSocket(wsUrl);

    ws.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        if (data.type === 'ping' || !data.severity) return;

        // Only surface critical/high alerts as notifications.
        if (data.severity !== 'critical' && data.severity !== 'high') return;
        if (seenAlerts.current.has(data.id)) return;
        seenAlerts.current.add(data.id);

        if (!initialized.current) return;

        setNotifications(prev => [{
          id: makeId(),
          type: 'alert' as const,
          title: `${data.severity.toUpperCase()} Alert`,
          message: data.rule_name,
          severity: data.severity,
          read: false,
          created_at: data.timestamp,
        }, ...prev].slice(0, 50));
      } catch {}
    };

    return () => {
      clearInterval(t);
      ws.close();
    };
  }, [poll]);

  const markRead    = (id: string) => setNotifications(p => p.map(n => n.id === id ? { ...n, read: true } : n));
  const markAllRead = ()           => setNotifications(p => p.map(n => ({ ...n, read: true })));
  const dismiss     = (id: string) => setNotifications(p => p.filter(n => n.id !== id));
  const unread      = notifications.filter(n => !n.read).length;

  return <Ctx.Provider value={{ notifications, unread, markRead, markAllRead, dismiss }}>{children}</Ctx.Provider>;
}

export const useNotifications = () => useContext(Ctx);
