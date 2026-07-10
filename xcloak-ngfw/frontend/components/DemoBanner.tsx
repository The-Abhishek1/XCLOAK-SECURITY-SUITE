'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { FlaskConical, X, ArrowRight } from 'lucide-react';

export default function DemoBanner() {
  const router = useRouter();
  const [visible, setVisible] = useState(false);
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    const isDemo = document.cookie.split(';').some(c => c.trim().startsWith('demo_mode='));
    const wasDismissed = sessionStorage.getItem('xcloak-demo-banner-dismissed') === '1';
    if (isDemo && !wasDismissed) setVisible(true);
  }, []);

  const dismiss = () => {
    sessionStorage.setItem('xcloak-demo-banner-dismissed', '1');
    setDismissed(true);
    setVisible(false);
  };

  if (!visible || dismissed) return null;

  return (
    <div
      className="fixed top-0 left-0 right-0 z-[9999] flex items-center justify-between gap-3 px-4 py-2 text-sm font-medium"
      style={{ background: 'var(--accent)', color: '#fff' }}
    >
      <div className="flex items-center gap-2 min-w-0">
        <FlaskConical className="h-4 w-4 shrink-0" />
        <span className="truncate">
          You&apos;re in <strong>demo mode</strong> — all data is pre-seeded and read-only.
          Actions like creating rules or dispatching commands are disabled.
        </span>
      </div>

      <div className="flex items-center gap-3 shrink-0">
        <button
          onClick={() => window.open('https://xcloak.tech', '_blank')}
          className="flex items-center gap-1 rounded px-3 py-1 text-xs font-semibold transition-opacity hover:opacity-80"
          style={{ background: 'rgba(255,255,255,0.2)' }}
        >
          Get full access <ArrowRight className="h-3 w-3" />
        </button>
        <button onClick={dismiss} className="opacity-70 hover:opacity-100 transition-opacity" aria-label="Dismiss">
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}
