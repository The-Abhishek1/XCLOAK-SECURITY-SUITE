'use client';

import type { CSSProperties } from 'react';

interface LoadingSkeletonProps {
  variant: 'card' | 'table-row' | 'text' | 'stat';
  count?: number;
}

function pulse(style: CSSProperties, key: number) {
  return <div key={key} className="animate-pulse rounded-md" style={{ background: 'var(--glass-hover)', ...style }} />;
}

export function LoadingSkeleton({ variant, count = 3 }: LoadingSkeletonProps) {
  const items = Array.from({ length: count });

  if (variant === 'card') {
    return (
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
        {items.map((_, i) => pulse({ height: 84 }, i))}
      </div>
    );
  }

  if (variant === 'stat') {
    return <div className="flex flex-col gap-2">{items.map((_, i) => pulse({ height: 14, width: `${60 + (i % 3) * 10}%` }, i))}</div>;
  }

  if (variant === 'table-row') {
    return (
      <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
        {items.map((_, i) => (
          <div key={i} className="px-4 py-3">
            {pulse({ height: 16 }, i)}
          </div>
        ))}
      </div>
    );
  }

  return <div className="flex flex-col gap-2">{items.map((_, i) => pulse({ height: 12, width: `${50 + (i % 4) * 12}%` }, i))}</div>;
}
