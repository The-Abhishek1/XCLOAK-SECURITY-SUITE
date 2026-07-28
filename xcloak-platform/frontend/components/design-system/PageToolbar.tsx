'use client';

import type { ReactNode } from 'react';

interface PageToolbarProps {
  children: ReactNode;
  className?: string;
}

export function PageToolbar({ children, className = '' }: PageToolbarProps) {
  return (
    <div className={`flex items-center gap-2 flex-wrap ${className}`}>
      {children}
    </div>
  );
}
