'use client';

import { useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { ShieldCheck, AlertCircle } from 'lucide-react';

export default function OIDCCompletePage() {
  const searchParams = useSearchParams();
  const code     = searchParams.get('code') || '';
  const ssoError = searchParams.get('error') || '';
  const [error, setError] = useState(ssoError);

  useEffect(() => {
    if (!code) return;

    // Exchange the one-time code for a session cookie. This request goes
    // through the Next.js proxy so Set-Cookie lands on the correct origin
    // (the backend OIDC callback runs on a different port in dev and can't
    // set an httpOnly cookie on the frontend's origin directly).
    fetch('/api/auth/oidc/exchange', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ code }),
    })
      .then(r => {
        if (!r.ok) throw new Error('exchange failed');
        window.location.href = '/dashboard';
      })
      .catch(() => setError('SSO sign-in succeeded but session setup failed — try logging in again.'));
  }, [code]);

  return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: 'var(--bg-0)' }}>
      <div className="w-full max-w-[400px] px-4">
        <div className="g-panel p-8">
          <div className="flex flex-col items-center mb-6">
            <div className="flex h-14 w-14 items-center justify-center rounded-2xl mb-3"
              style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
              <ShieldCheck className="h-7 w-7" style={{ color: 'var(--accent)' }} />
            </div>
            <h1 className="text-xl font-bold" style={{ color: 'var(--text-1)' }}>XCloak Security Suite</h1>
          </div>

          {error || !code ? (
            <div className="space-y-3 text-center">
              <div className="flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm text-left"
                style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)', color: 'var(--red)' }}>
                <AlertCircle className="h-4 w-4 shrink-0" /> {error || 'SSO sign-in failed.'}
              </div>
              <a href="/login" className="g-btn g-btn-primary w-full justify-center py-2.5 text-sm font-semibold">
                Back to login
              </a>
            </div>
          ) : (
            <p className="text-sm text-center animate-pulse" style={{ color: 'var(--text-2)' }}>
              Signing you in…
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
