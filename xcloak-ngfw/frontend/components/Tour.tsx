'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { X, ChevronRight, ChevronLeft, ShieldCheck } from 'lucide-react';

interface TourStep {
  title: string;
  body: string;
  path?: string;         // navigate before showing step
  selector?: string;     // highlight this element
  position?: 'center' | 'bottom-right';
}

const STEPS: TourStep[] = [
  {
    title: 'Welcome to XCloak Security Suite',
    body: 'You\'re viewing a live demo with pre-seeded realistic threat data. This 2-minute tour walks you through the key capabilities. Everything you see is read-only — no real endpoints are affected.',
    position: 'center',
  },
  {
    title: 'Security Command Center',
    body: 'The dashboard gives you a real-time overview of your threat posture — active incidents, alert severity breakdown, agent health, and compliance scores. All data updates live via WebSocket.',
    path: '/dashboard',
    position: 'center',
  },
  {
    title: 'SIEM — 25 Active Alerts',
    body: 'The SIEM processes 5,000+ events/minute through a Sigma-compatible rule engine. Each alert is MITRE ATT&CK mapped, AI-triaged, and correlated against live threat feeds. Click any alert to see the full event timeline.',
    path: '/alerts',
    position: 'center',
  },
  {
    title: 'Endpoint Telemetry',
    body: 'Four demo endpoints are enrolled: two Linux servers, one Windows workstation, and an Android mobile device. Click any endpoint to see real-time processes, network connections, installed packages, and user activity.',
    path: '/agents',
    position: 'center',
  },
  {
    title: 'Active Incidents',
    body: 'Three incidents are in progress — including an active C2 beacon on web-prod-01 and a credential dump chain on the Windows host. Each incident has an AI-generated summary, MITRE mapping, and full event timeline.',
    path: '/incidents',
    position: 'center',
  },
  {
    title: 'SOAR — Automated Response',
    body: 'Playbooks automate response actions like host isolation, IP blocking, and Slack notifications. Destructive actions (like wiping a host) require human approval — you can see a pending approval in the queue right now.',
    path: '/soar-approvals',
    position: 'center',
  },
  {
    title: 'File Integrity Monitoring',
    body: 'FIM is tracking 7 suspicious file changes — including /etc/passwd modification, a replaced sshd binary, and a Windows startup script created by malware. Every change is timestamped, hashed, and linked to its alert.',
    path: '/agents',
    position: 'center',
  },
  {
    title: 'NGFW — Firewall Rules',
    body: 'The dynamic rule engine enforces policies across all registered agents via iptables (Linux) and netsh (Windows). Rules propagate in under 500ms. GeoIP and threat-feed-based blocking are built in.',
    path: '/firewall',
    position: 'center',
  },
  {
    title: 'MDM — Mobile Security',
    body: 'The Android agent reports 24 posture metrics per check-in: battery, storage, VPN status, USB debugging, unknown sources, Magisk detection, app inventory, and more. Commands like token rotation are dispatched remotely.',
    path: '/mdm',
    position: 'center',
  },
  {
    title: 'Compliance Scoring',
    body: 'Live compliance scores against CIS Benchmarks, NIST CSF, and PCI-DSS. The demo org currently scores 72% CIS / 68% NIST — drill into any failing control to see the affected endpoints and remediation steps.',
    path: '/compliance',
    position: 'center',
  },
  {
    title: 'Ready to deploy?',
    body: 'XCloak is open-core and self-hostable. Deploy in 5 minutes with Docker Compose, or use the Helm chart for Kubernetes. The agent binary drops on any Linux or Windows host with a single curl command.',
    position: 'center',
  },
];

export default function Tour() {
  const router = useRouter();
  const [active, setActive] = useState(false);
  const [step, setStep] = useState(0);
  const [exiting, setExiting] = useState(false);
  const navigating = useRef(false);

  useEffect(() => {
    const pending = sessionStorage.getItem('xcloak-tour-pending');
    const isDemo = document.cookie.split(';').some(c => c.trim().startsWith('demo_mode='));
    if (pending === '1' && isDemo) {
      sessionStorage.removeItem('xcloak-tour-pending');
      setTimeout(() => setActive(true), 800);
    }
  }, []);

  const close = useCallback(() => {
    setExiting(true);
    setTimeout(() => { setActive(false); setExiting(false); }, 200);
  }, []);

  const goTo = useCallback(async (idx: number) => {
    if (idx >= STEPS.length) { close(); return; }
    if (navigating.current) return;
    const target = STEPS[idx];
    if (target.path) {
      navigating.current = true;
      router.push(target.path);
      await new Promise(r => setTimeout(r, 400));
      navigating.current = false;
    }
    setStep(idx);
  }, [router, close]);

  if (!active) return null;

  const current = STEPS[step];
  const isLast = step === STEPS.length - 1;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-[10000]"
        style={{ background: 'rgba(0,0,0,0.55)', backdropFilter: 'blur(2px)' }}
        onClick={close}
      />

      {/* Tour card */}
      <div
        className="fixed z-[10001] w-full max-w-md rounded-xl shadow-2xl p-6 transition-all duration-200"
        style={{
          top: '50%',
          left: '50%',
          transform: `translate(-50%, -50%) scale(${exiting ? 0.95 : 1})`,
          opacity: exiting ? 0 : 1,
          background: 'var(--bg-2)',
          border: '1px solid var(--border)',
        }}
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-3 mb-4">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 shrink-0" style={{ color: 'var(--accent)' }} />
            <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--accent)' }}>
              Step {step + 1} of {STEPS.length}
            </span>
          </div>
          <button onClick={close} className="opacity-40 hover:opacity-70 transition-opacity mt-0.5">
            <X className="h-4 w-4" style={{ color: 'var(--text-1)' }} />
          </button>
        </div>

        <h2 className="text-lg font-bold mb-2" style={{ color: 'var(--text-1)' }}>
          {current.title}
        </h2>
        <p className="text-sm leading-relaxed mb-6" style={{ color: 'var(--text-2)' }}>
          {current.body}
        </p>

        {/* Progress dots */}
        <div className="flex items-center gap-1.5 mb-5">
          {STEPS.map((_, i) => (
            <button
              key={i}
              onClick={() => goTo(i)}
              className="rounded-full transition-all"
              style={{
                width: i === step ? '20px' : '6px',
                height: '6px',
                background: i === step ? 'var(--accent)' : 'var(--border)',
              }}
            />
          ))}
        </div>

        {/* Navigation */}
        <div className="flex items-center justify-between gap-3">
          <button
            onClick={() => goTo(step - 1)}
            disabled={step === 0}
            className="flex items-center gap-1 text-sm px-3 py-1.5 rounded-lg transition-opacity disabled:opacity-30"
            style={{ color: 'var(--text-2)', background: 'var(--bg-3)' }}
          >
            <ChevronLeft className="h-4 w-4" /> Back
          </button>

          <div className="flex gap-2">
            <button
              onClick={close}
              className="text-sm px-3 py-1.5 rounded-lg transition-opacity hover:opacity-70"
              style={{ color: 'var(--text-3)' }}
            >
              Skip tour
            </button>
            <button
              onClick={() => isLast ? router.push('/signup') : goTo(step + 1)}
              className="flex items-center gap-1 text-sm px-4 py-1.5 rounded-lg font-semibold transition-opacity hover:opacity-90"
              style={{ background: 'var(--accent)', color: '#fff' }}
            >
              {isLast ? 'Sign up free' : 'Next'} <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
