'use client';

import { useState, useEffect, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { ShieldCheck, Lock, Eye, EyeOff, AlertCircle, CheckCircle } from 'lucide-react';

export default function ResetPasswordPage() {
  return (
    <Suspense>
      <ResetPasswordContent />
    </Suspense>
  );
}

function ResetPasswordContent() {
  const router       = useRouter();
  const searchParams = useSearchParams();
  const token        = searchParams.get('token') || '';

  const [password, setPassword]   = useState('');
  const [confirm, setConfirm]     = useState('');
  const [showPw, setShowPw]       = useState(false);
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState('');
  const [success, setSuccess]     = useState(false);

  useEffect(() => {
    if (!token) router.push('/login');
  }, [token, router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== confirm) { setError('Passwords do not match'); return; }
    if (password.length < 8)  { setError('Password must be at least 8 characters'); return; }

    setLoading(true); setError('');
    try {
      const res  = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, new_password: password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Reset failed');
      setSuccess(true);
      setTimeout(() => router.push('/login'), 3000);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center"
      style={{ background: 'var(--bg-0)' }}>
      <div className="w-full max-w-[400px] px-4">
        <div className="g-panel p-8">
          <div className="flex flex-col items-center mb-6">
            <div className="flex h-14 w-14 items-center justify-center rounded-2xl mb-3"
              style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
              <ShieldCheck className="h-7 w-7" style={{ color: 'var(--accent)' }} />
            </div>
            <h1 className="text-xl font-bold" style={{ color: 'var(--text-1)' }}>Set New Password</h1>
            <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>XCloak Security Suite</p>
          </div>

          {success ? (
            <div className="text-center space-y-3">
              <CheckCircle className="h-12 w-12 mx-auto" style={{ color: 'var(--green)' }} />
              <p className="text-sm font-semibold" style={{ color: 'var(--green)' }}>
                Password reset successfully!
              </p>
              <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                Redirecting to login…
              </p>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="text-xs font-medium mb-1.5 block" style={{ color: 'var(--text-2)' }}>
                  New Password
                </label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                  <input type={showPw ? 'text' : 'password'}
                    value={password} onChange={e => setPassword(e.target.value)}
                    placeholder="Min 8 characters" required minLength={8}
                    className="g-input pl-9 pr-10 w-full" />
                  <button type="button" onClick={() => setShowPw(p => !p)}
                    className="absolute right-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-3)' }}>
                    {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>
              <div>
                <label className="text-xs font-medium mb-1.5 block" style={{ color: 'var(--text-2)' }}>
                  Confirm Password
                </label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                  <input type={showPw ? 'text' : 'password'}
                    value={confirm} onChange={e => setConfirm(e.target.value)}
                    placeholder="Repeat password" required className="g-input pl-9 w-full" />
                </div>
                {confirm && password !== confirm && (
                  <p className="text-[10px] mt-1" style={{ color: 'var(--red)' }}>Passwords do not match</p>
                )}
              </div>
              {error && (
                <div className="flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm"
                  style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)', color: 'var(--red)' }}>
                  <AlertCircle className="h-4 w-4 shrink-0" /> {error}
                </div>
              )}
              <button type="submit" disabled={loading || password !== confirm}
                className="g-btn g-btn-primary w-full justify-center py-2.5 text-sm font-semibold">
                {loading ? 'Resetting…' : 'Reset Password'}
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
