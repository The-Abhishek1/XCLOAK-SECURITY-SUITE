'use client';

import { useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { ShieldCheck, AlertCircle } from 'lucide-react';
import api from '@/lib/api';

export default function OIDCCompletePage() {
  const searchParams = useSearchParams();
  const token = searchParams.get('token') || '';
  const ssoError = searchParams.get('error') || '';
  const [error, setError] = useState(ssoError);

  useEffect(() => {
    if (!token) return;

    localStorage.setItem('token', token);
    document.cookie = `token=${token}; path=/; max-age=86400; SameSite=Lax`;

    api.get('/auth/profile')
      .then(r => {
        localStorage.setItem('username', r.data.username);
        window.location.href = '/dashboard';
      })
      .catch(() => setError('Signed in, but failed to load your profile — try logging in again.'));
  }, [token]);

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

          {error || !token ? (
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
