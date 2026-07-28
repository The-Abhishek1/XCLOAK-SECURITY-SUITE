'use client';

import { sevClass, sevDot } from '@/lib/utils';

interface StatusBadgeProps {
  status: string;
  dot?: boolean;
  size?: 'sm' | 'md';
}

export function StatusBadge({ status, dot = false, size = 'md' }: StatusBadgeProps) {
  const sizeClass = size === 'sm' ? 'text-[10px]' : '';
  return (
    <span className={`${sevClass(status)} ${sizeClass} inline-flex items-center gap-1.5 capitalize`}>
      {dot && <span className={`${sevDot(status)} inline-block`} />}
      {status}
    </span>
  );
}
