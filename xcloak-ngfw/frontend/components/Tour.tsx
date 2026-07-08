'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { X, ChevronRight, ChevronLeft, ShieldCheck } from 'lucide-react';

interface Step {
  title: string;
  body: string;
  path?: string;
  selector?: string;       // CSS selector of element to spotlight
  tooltipSide?: 'right' | 'bottom' | 'left' | 'center';
}

const STEPS: Step[] = [
  {
    title: 'Welcome to XCloak Security Suite',
    body: 'This 2-minute guided tour walks you through a live demo loaded with realistic threat data. Everything is read-only — no real systems are affected. Click Next to begin.',
    tooltipSide: 'center',
  },
  {
    title: 'Security Command Center',
    body: 'Your mission control. Real-time overview of active threats, alert severity distribution, agent health scores, and compliance posture — all live via WebSocket.',
    path: '/dashboard',
    selector: 'a[href="/dashboard"]',
    tooltipSide: 'right',
  },
  {
    title: 'SIEM Alerts — 25 Active',
    body: 'Every security event is processed through a Sigma-compatible rule engine, MITRE ATT&CK mapped, and AI-triaged. Critical alerts like C2 beaconing and credential dumps are at the top.',
    path: '/alerts',
    selector: 'a[href="/alerts"]',
    tooltipSide: 'right',
  },
  {
    title: 'Active Incidents',
    body: 'Three incidents are in progress — a Cobalt Strike C2 implant, an active credential dump + lateral movement chain, and a contained ransomware attack. Click any to see the full timeline.',
    path: '/incidents',
    selector: 'a[href="/incidents"]',
    tooltipSide: 'right',
  },
  {
    title: 'Enrolled Endpoints',
    body: 'Four demo endpoints are live: two Linux servers, one Windows workstation, and an Android device. Each reports real-time processes, network connections, packages, and user activity.',
    path: '/agents',
    selector: 'a[href="/agents"]',
    tooltipSide: 'right',
  },
  {
    title: 'SOAR — Automated Response',
    body: 'Two actions are waiting for human approval right now: isolating web-prod-01 and blocking an attacker IP. Playbooks automate response — destructive actions always need a human green-light.',
    path: '/soar-approvals',
    selector: 'a[href="/soar-approvals"]',
    tooltipSide: 'right',
  },
  {
    title: 'NGFW — Firewall Rules',
    body: 'Dynamic rules enforce policy across all agents via iptables (Linux) and netsh (Windows). Rules propagate in under 500ms. GeoIP blocking and threat-feed-based denylisting are built in.',
    path: '/firewall',
    selector: 'a[href="/firewall"]',
    tooltipSide: 'right',
  },
  {
    title: 'Mobile MDM',
    body: 'The Android agent reports 24 posture metrics per check-in — battery, storage, VPN, USB debugging, Magisk detection, app inventory. Remote commands dispatch in real time.',
    path: '/mdm',
    selector: 'a[href="/mdm"]',
    tooltipSide: 'right',
  },
  {
    title: 'Compliance Scoring',
    body: 'Live scores against CIS Benchmarks (72%), NIST CSF (68%), and PCI-DSS (81%). Drill into any failing control to see affected endpoints and step-by-step remediation.',
    path: '/compliance',
    selector: 'a[href="/compliance"]',
    tooltipSide: 'right',
  },
  {
    title: 'Ready to deploy?',
    body: 'XCloak is open-core and self-hostable. One curl command drops the agent on any Linux or Windows host. Use Docker Compose for a quick start, or Helm for Kubernetes in production.',
    tooltipSide: 'center',
  },
];

interface Rect { top: number; left: number; width: number; height: number }

export default function Tour() {
  const router = useRouter();
  const [active, setActive] = useState(false);
  const [step, setStep]     = useState(0);
  const [rect, setRect]     = useState<Rect | null>(null);
  const navigating          = useRef(false);

  // Start tour when demo session flag is set
  useEffect(() => {
    const isDemo = document.cookie.split(';').some(c => c.trim().startsWith('demo_mode='));
    if (isDemo && sessionStorage.getItem('xcloak-tour-pending') === '1') {
      sessionStorage.removeItem('xcloak-tour-pending');
      setTimeout(() => setActive(true), 900);
    }
  }, []);

  // Spotlight the target element whenever step changes
  useEffect(() => {
    if (!active) return;
    const sel = STEPS[step].selector;
    if (!sel) { setRect(null); return; }

    const measure = () => {
      const el = document.querySelector(sel);
      if (el) {
        const r = el.getBoundingClientRect();
        setRect({ top: r.top - 6, left: r.left - 8, width: r.width + 16, height: r.height + 12 });
      } else {
        setRect(null);
      }
    };

    const t = setTimeout(measure, 350); // wait for navigation + render
    return () => clearTimeout(t);
  }, [active, step]);

  const close = useCallback(() => {
    setActive(false);
    setRect(null);
  }, []);

  const goTo = useCallback(async (idx: number) => {
    if (idx >= STEPS.length) { close(); return; }
    if (navigating.current) return;
    const target = STEPS[idx];
    if (target.path) {
      navigating.current = true;
      router.push(target.path);
      await new Promise(r => setTimeout(r, 300));
      navigating.current = false;
    }
    setStep(idx);
  }, [router, close]);

  if (!active) return null;

  const current = STEPS[step];
  const isLast  = step === STEPS.length - 1;
  const side    = current.tooltipSide ?? 'right';
  const isCenter = side === 'center' || !rect;

  // Tooltip position relative to spotlight rect
  const tooltipStyle: React.CSSProperties = isCenter
    ? { position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: '360px' }
    : side === 'right'
    ? { position: 'fixed', top: rect!.top + rect!.height / 2, left: rect!.left + rect!.width + 16, transform: 'translateY(-50%)', width: '320px' }
    : side === 'bottom'
    ? { position: 'fixed', top: rect!.top + rect!.height + 12, left: rect!.left, width: '320px' }
    : { position: 'fixed', top: rect!.top + rect!.height / 2, right: window.innerWidth - rect!.left + 16, transform: 'translateY(-50%)', width: '320px' };

  return (
    <>
      {/* Full-page nav lock overlay — sits above page content but below spotlight/tooltip */}
      <div className="fixed inset-0 z-[9998]" style={{ cursor: 'not-allowed' }} onClick={e => e.stopPropagation()} />

      {/* Spotlight: box-shadow creates the dim surround with a bright cutout */}
      {rect && (
        <div
          className="fixed z-[9999] rounded-lg pointer-events-none"
          style={{
            top:    rect.top,
            left:   rect.left,
            width:  rect.width,
            height: rect.height,
            boxShadow: '0 0 0 9999px rgba(0,0,0,0.72)',
            border: '2px solid var(--accent)',
            transition: 'all 0.25s ease',
          }}
        />
      )}

      {/* Dark overlay when no specific element (center mode) */}
      {!rect && (
        <div className="fixed inset-0 z-[9999]" style={{ background: 'rgba(0,0,0,0.72)', backdropFilter: 'blur(2px)' }} />
      )}

      {/* Tour card */}
      <div
        className="z-[10000] rounded-xl shadow-2xl p-5"
        style={{
          ...tooltipStyle,
          background: 'var(--bg-2)',
          border: '1px solid var(--accent)',
          boxShadow: '0 0 0 1px var(--accent-border), 0 20px 60px rgba(0,0,0,0.5)',
          maxWidth: '90vw',
        }}
      >
        {/* Step indicator + close */}
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4" style={{ color: 'var(--accent)' }} />
            <span className="text-[11px] font-semibold uppercase tracking-wider" style={{ color: 'var(--accent)' }}>
              {step + 1} / {STEPS.length}
            </span>
          </div>
          <button onClick={close} className="opacity-40 hover:opacity-80 transition-opacity">
            <X className="h-4 w-4" style={{ color: 'var(--text-1)' }} />
          </button>
        </div>

        <h3 className="text-sm font-bold mb-1.5 leading-snug" style={{ color: 'var(--text-1)' }}>
          {current.title}
        </h3>
        <p className="text-xs leading-relaxed mb-4" style={{ color: 'var(--text-2)' }}>
          {current.body}
        </p>

        {/* Progress dots */}
        <div className="flex items-center gap-1 mb-4">
          {STEPS.map((_, i) => (
            <div
              key={i}
              className="rounded-full transition-all duration-300"
              style={{
                width: i === step ? '18px' : '5px',
                height: '5px',
                background: i === step ? 'var(--accent)' : i < step ? 'var(--accent)' : 'var(--border)',
                opacity: i < step ? 0.5 : 1,
              }}
            />
          ))}
        </div>

        {/* Navigation */}
        <div className="flex items-center justify-between gap-2">
          <button
            onClick={() => goTo(step - 1)}
            disabled={step === 0}
            className="flex items-center gap-1 text-xs px-2.5 py-1.5 rounded-lg transition-opacity disabled:opacity-20"
            style={{ color: 'var(--text-2)', background: 'var(--bg-3)' }}
          >
            <ChevronLeft className="h-3.5 w-3.5" /> Back
          </button>

          <div className="flex items-center gap-1.5">
            <button
              onClick={close}
              className="text-xs px-2.5 py-1.5 rounded-lg opacity-50 hover:opacity-80 transition-opacity"
              style={{ color: 'var(--text-3)' }}
            >
              Skip
            </button>
            <button
              onClick={() => isLast ? router.push('/signup') : goTo(step + 1)}
              className="flex items-center gap-1 text-xs px-3.5 py-1.5 rounded-lg font-semibold hover:opacity-90 transition-opacity"
              style={{ background: 'var(--accent)', color: '#fff' }}
            >
              {isLast ? 'Sign up free' : 'Next'} <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
