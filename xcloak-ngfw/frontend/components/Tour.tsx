'use client';

import { useEffect, useState, useCallback, useRef, CSSProperties } from 'react';
import { useRouter } from 'next/navigation';
import { X, ChevronRight, ChevronLeft, ShieldCheck } from 'lucide-react';

interface Step {
  title: string;
  body: string;
  path?: string;
  selector?: string;
  side?: 'right' | 'bottom' | 'left';
}

const STEPS: Step[] = [
  {
    title: 'Welcome to XCloak Security Suite',
    body: 'This 2-minute guided tour walks you through a live demo loaded with realistic threat data. Everything is read-only — no real systems are affected. Click Next to begin.',
  },
  {
    title: 'Security Command Center',
    body: 'Your mission control. Real-time overview of active threats, alert severity distribution, agent health scores, and compliance posture — all live via WebSocket.',
    path: '/dashboard', selector: '[data-tour="dashboard"]', side: 'right',
  },
  {
    title: 'SIEM Alerts — 25 Active',
    body: 'Every security event is processed through a Sigma-compatible rule engine, MITRE ATT&CK mapped, and AI-triaged. Critical alerts like C2 beaconing and credential dumps are at the top.',
    path: '/alerts', selector: '[data-tour="alerts"]', side: 'right',
  },
  {
    title: 'Active Incidents',
    body: 'Three incidents are in progress — a Cobalt Strike C2 implant, an active credential dump + lateral movement chain, and a contained ransomware attack. Click any to see the full timeline.',
    path: '/incidents', selector: '[data-tour="incidents"]', side: 'right',
  },
  {
    title: 'Enrolled Endpoints',
    body: 'Four demo endpoints are live: two Linux servers, one Windows workstation, and an Android device. Each reports real-time processes, network connections, packages, and user activity.',
    path: '/agents', selector: '[data-tour="agents"]', side: 'right',
  },
  {
    title: 'SOAR — Automated Response',
    body: 'Two actions are waiting for human approval right now: isolating web-prod-01 and blocking an attacker IP. Playbooks automate response — destructive actions always need a human green-light.',
    path: '/soar-approvals', selector: '[data-tour="soar-approvals"]', side: 'right',
  },
  {
    title: 'NGFW — Firewall Rules',
    body: 'Dynamic rules enforce policy across all agents via iptables (Linux) and netsh (Windows). Rules propagate in under 500ms. GeoIP blocking and threat-feed-based denylisting are built in.',
    path: '/firewall', selector: '[data-tour="firewall"]', side: 'right',
  },
  {
    title: 'Mobile MDM',
    body: 'The Android agent reports 24 posture metrics per check-in — battery, storage, VPN, USB debugging, Magisk detection, app inventory. Remote commands dispatch in real time.',
    path: '/mdm', selector: '[data-tour="mdm"]', side: 'right',
  },
  {
    title: 'Compliance Scoring',
    body: 'Live scores against CIS Benchmarks (72%), NIST CSF (68%), and PCI-DSS (81%). Drill into any failing control to see affected endpoints and step-by-step remediation.',
    path: '/compliance', selector: '[data-tour="compliance"]', side: 'right',
  },
  {
    title: 'Ready to deploy?',
    body: 'XCloak is open-core and self-hostable. One curl command drops the agent on any Linux or Windows host. Use Docker Compose for a quick start, or Helm for Kubernetes in production.',
  },
];

interface SpotRect { top: number; left: number; width: number; height: number }

// Compute tooltip position with full viewport clamping.
// Returns null when no element was found → triggers center fallback.
function calcTooltipStyle(
  spotRect: SpotRect,
  side: Step['side'],
  vw: number,
  vh: number,
): CSSProperties {
  const TW = Math.min(320, vw - 24);  // tooltip width, never wider than viewport
  const TH = 240;                      // conservative estimate
  const PAD = 12;

  let top = 0;
  let left = 0;

  if (side === 'right') {
    left = spotRect.left + spotRect.width + 16;
    top  = spotRect.top + spotRect.height / 2 - TH / 2;
    // If it overflows right, flip to left of spotlight
    if (left + TW > vw - PAD) {
      left = spotRect.left - TW - 16;
    }
    // If still overflows (e.g., ultra-narrow), center horizontally
    if (left < PAD) {
      left = Math.max(PAD, (vw - TW) / 2);
      top  = spotRect.top + spotRect.height + 12;
    }
  } else if (side === 'left') {
    left = spotRect.left - TW - 16;
    top  = spotRect.top + spotRect.height / 2 - TH / 2;
    if (left < PAD) {
      left = spotRect.left + spotRect.width + 16;
    }
  } else {
    // bottom
    top  = spotRect.top + spotRect.height + 12;
    left = spotRect.left;
  }

  // Vertical clamp
  top = Math.max(PAD, Math.min(top, vh - TH - PAD));
  // Horizontal clamp
  left = Math.max(PAD, Math.min(left, vw - TW - PAD));

  return { position: 'fixed', top, left, width: TW };
}

const CENTER_STYLE: CSSProperties = {
  position: 'fixed',
  top: '50%',
  left: '50%',
  transform: 'translate(-50%,-50%)',
  width: 'min(380px, calc(100vw - 24px))',
};

export default function Tour() {
  const router = useRouter();
  const [active, setActive]           = useState(false);
  const [step, setStep]               = useState(0);
  const [spotRect, setSpotRect]       = useState<SpotRect | null>(null);
  const [tooltipStyle, setTooltipStyle] = useState<CSSProperties>(CENTER_STYLE);
  const navigating                    = useRef(false);

  // Start tour when demo session flag is set
  useEffect(() => {
    const isDemo = document.cookie.split(';').some(c => c.trim().startsWith('demo_mode='));
    if (isDemo && sessionStorage.getItem('xcloak-tour-pending') === '1') {
      sessionStorage.removeItem('xcloak-tour-pending');
      setTimeout(() => setActive(true), 900);
    }
  }, []);

  // Measure target element + compute clamped tooltip position
  useEffect(() => {
    if (!active) return;
    const { selector, side } = STEPS[step];
    if (!selector) {
      setSpotRect(null);
      setTooltipStyle(CENTER_STYLE);
      return;
    }

    const measure = () => {
      const vw = window.innerWidth;
      const vh = window.innerHeight;

      const el = document.querySelector(selector);
      if (!el) {
        setSpotRect(null);
        setTooltipStyle(CENTER_STYLE);
        return;
      }

      const r = el.getBoundingClientRect();
      // Element is hidden (collapsed group, off-screen drawer, or zero-size)
      if (r.width < 4 || r.height < 4) {
        setSpotRect(null);
        setTooltipStyle(CENTER_STYLE);
        return;
      }

      const spot: SpotRect = {
        top:    r.top    - 6,
        left:   r.left   - 8,
        width:  r.width  + 16,
        height: r.height + 12,
      };
      setSpotRect(spot);
      setTooltipStyle(calcTooltipStyle(spot, side ?? 'right', vw, vh));
    };

    const t = setTimeout(measure, 380);
    window.addEventListener('resize', measure, { passive: true });
    return () => {
      clearTimeout(t);
      window.removeEventListener('resize', measure);
    };
  }, [active, step]);

  const close = useCallback(() => {
    setActive(false);
    setSpotRect(null);
    setTooltipStyle(CENTER_STYLE);
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

  const current  = STEPS[step];
  const isLast   = step === STEPS.length - 1;
  const hasSpot  = !!spotRect;

  return (
    <>
      {/* Nav lock — captures all pointer events so user can't click the app */}
      <div
        className="fixed inset-0 z-[9998]"
        style={{ cursor: 'not-allowed' }}
        onClick={e => e.stopPropagation()}
        onMouseDown={e => e.stopPropagation()}
      />

      {/* Dim overlay (center mode only) */}
      {!hasSpot && (
        <div
          className="fixed inset-0 z-[9999]"
          style={{ background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(2px)' }}
        />
      )}

      {/* Spotlight cutout — box-shadow trick dims everything except the target */}
      {hasSpot && (
        <div
          className="fixed z-[9999] rounded-md pointer-events-none"
          style={{
            top:       spotRect.top,
            left:      spotRect.left,
            width:     spotRect.width,
            height:    spotRect.height,
            boxShadow: '0 0 0 9999px rgba(0,0,0,0.72)',
            border:    '2px solid var(--accent)',
            transition: 'top 0.25s ease, left 0.25s ease, width 0.25s ease, height 0.25s ease',
          }}
        />
      )}

      {/* Arrow connecting spotlight to tooltip (right-side only, desktop) */}
      {hasSpot && current.side === 'right' && typeof tooltipStyle.left === 'number' && (
        <div
          className="fixed z-[10000] pointer-events-none"
          style={{
            top:   spotRect.top + spotRect.height / 2 - 6,
            left:  spotRect.left + spotRect.width,
            width: Math.max(0, (tooltipStyle.left as number) - spotRect.left - spotRect.width),
            height: 12,
            display: 'flex',
            alignItems: 'center',
          }}
        >
          <div style={{ flex: 1, height: 1, borderTop: '1px dashed var(--accent)', opacity: 0.5 }} />
          <div style={{
            width: 6, height: 6, borderRadius: '50%',
            background: 'var(--accent)', flexShrink: 0,
          }} />
        </div>
      )}

      {/* Tour card */}
      <div
        className="fixed z-[10000] rounded-xl p-5"
        style={{
          ...tooltipStyle,
          background:  'var(--bg-2, #1e293b)',
          border:      '1px solid var(--accent)',
          boxShadow:   '0 4px 6px -1px rgba(0,0,0,.3), 0 20px 60px rgba(0,0,0,.55)',
        }}
      >
        {/* Header row */}
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 shrink-0" style={{ color: 'var(--accent)' }} />
            <span className="text-[11px] font-semibold uppercase tracking-wider" style={{ color: 'var(--accent)' }}>
              {step + 1} / {STEPS.length}
            </span>
          </div>
          <button
            onClick={close}
            className="flex items-center justify-center rounded opacity-40 hover:opacity-80 transition-opacity"
            style={{ width: 24, height: 24, cursor: 'pointer', pointerEvents: 'all' }}
          >
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
                width:      i === step ? '18px' : '5px',
                height:     '5px',
                background: i <= step ? 'var(--accent)' : 'var(--border)',
                opacity:    i < step ? 0.45 : 1,
              }}
            />
          ))}
        </div>

        {/* Navigation — pointer-events: all overrides the nav-lock overlay */}
        <div className="flex items-center justify-between" style={{ pointerEvents: 'all' }}>
          <button
            onClick={() => goTo(step - 1)}
            disabled={step === 0}
            className="flex items-center gap-1 text-xs px-2.5 py-1.5 rounded-lg transition-opacity disabled:opacity-20"
            style={{ color: 'var(--text-2)', background: 'var(--bg-3)', cursor: 'pointer' }}
          >
            <ChevronLeft className="h-3.5 w-3.5" /> Back
          </button>

          <div className="flex items-center gap-1.5">
            <button
              onClick={close}
              className="text-xs px-2.5 py-1.5 rounded-lg transition-opacity opacity-50 hover:opacity-80"
              style={{ color: 'var(--text-3)', cursor: 'pointer' }}
            >
              Skip
            </button>
            <button
              onClick={() => isLast ? router.push('/signup') : goTo(step + 1)}
              className="flex items-center gap-1 text-xs px-3.5 py-1.5 rounded-lg font-semibold hover:opacity-90 transition-opacity"
              style={{ background: 'var(--accent)', color: '#fff', cursor: 'pointer' }}
            >
              {isLast ? 'Sign up free' : 'Next'} <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
