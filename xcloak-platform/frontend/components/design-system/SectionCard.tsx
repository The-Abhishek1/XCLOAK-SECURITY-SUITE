'use client';

import type { ReactNode } from 'react';

interface SectionCardProps {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  padded?: boolean;
  className?: string;
  children: ReactNode;
}

export function SectionCard({ title, subtitle, actions, padded = true, className = '', children }: SectionCardProps) {
  const hasHeader = title || subtitle || actions;
  return (
    <div className={`g-card ${className}`}>
      {hasHeader && (
        <div className="flex items-center justify-between gap-3 px-4 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
          <div>
            {title && <h3 className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{title}</h3>}
            {subtitle && <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{subtitle}</p>}
          </div>
          {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
        </div>
      )}
      <div className={padded ? 'p-4' : ''}>{children}</div>
    </div>
  );
}
