'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

// The JWT lives in an httpOnly cookie, invisible to JavaScript.
// We detect login state from the companion `logged_in=1` cookie which the
// backend sets at the same time — it carries no sensitive data.
const hasLoggedInCookie = (): boolean =>
  typeof document !== 'undefined' &&
  document.cookie.split(';').some(c => c.trim().startsWith('logged_in='));

export const isAuthenticated = (): boolean => {
  if (typeof window === 'undefined') return false;
  return hasLoggedInCookie();
};

// Token is httpOnly — JavaScript cannot read it. Returns null always.
// Kept as a no-op export so callers that were updated elsewhere don't break.
export const getToken = (): string | null => null;

export const logout = (): void => {
  // Ask the backend to revoke the token and expire the httpOnly cookie.
  // Fire-and-forget so the redirect is instant.
  fetch('/api/auth/logout', { method: 'POST', credentials: 'include' }).catch(() => {});
  if (typeof window !== 'undefined') {
    window.location.href = '/login';
  }
};

export const useAuth = () => {
  const router = useRouter();
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    if (!hasLoggedInCookie()) {
      router.push('/login');
    }
    setIsLoading(false);
  }, [router]);

  return { isLoading };
};
