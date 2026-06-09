'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

export const isAuthenticated = (): boolean => {
  if (typeof window === 'undefined') return false;
  const token = localStorage.getItem('token');
  return !!token;
};

export const getToken = (): string | null => {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('token');
};

export const logout = (): void => {
  localStorage.removeItem('token');
  if (typeof window !== 'undefined') {
    window.location.href = '/login';
  }
};

export const useAuth = () => {
  const router = useRouter();
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      router.push('/login');
    }
    setIsLoading(false);
  }, [router]);

  return { isLoading };
};