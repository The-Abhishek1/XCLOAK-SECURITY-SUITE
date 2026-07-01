'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function Home() {
  const router = useRouter();

  useEffect(() => {
    const loggedIn = document.cookie.split(';').some(c => c.trim().startsWith('logged_in='));
    router.push(loggedIn ? '/dashboard' : '/login');
  }, [router]);

  return null;
}