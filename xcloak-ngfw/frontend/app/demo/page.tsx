'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { ShieldCheck, Loader2 } from 'lucide-react';

export default function DemoPage() {
  const router = useRouter();
  const [error, setError] = useState('');

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch('/api/demo/start', { method: 'GET', credentials: 'include' });
        if (!res.ok) throw new Error('Failed to start demo session');
        // Backend set cookies; mark tour as pending so it fires on dashboard load
        sessionStorage.setItem('xcloak-tour-pending', '1');
        router.replace('/dashboard');
      } catch (e) {
        setError('Could not start demo session. Please try again.');
        console.error(e);
      }
    })();
  }, [router]);

  return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: 'var(--bg-1)' }}>
      <div className="flex flex-col items-center gap-4 text-center">
        <ShieldCheck className="h-12 w-12" style={{ color: 'var(--accent)' }} />
        {error ? (
          <div>
            <p className="text-sm font-medium" style={{ color: 'var(--red)' }}>{error}</p>
            <button
              onClick={() => router.push('/login')}
              className="mt-4 text-sm underline"
              style={{ color: 'var(--text-2)' }}
            >
              Back to login
            </button>
          </div>
        ) : (
          <>
            <p className="text-lg font-semibold" style={{ color: 'var(--text-1)' }}>
              Starting live demo…
            </p>
            <p className="text-sm" style={{ color: 'var(--text-3)' }}>
              Setting up your read-only session
            </p>
            <Loader2 className="h-5 w-5 animate-spin" style={{ color: 'var(--accent)' }} />
          </>
        )}
      </div>
    </div>
  );
}
