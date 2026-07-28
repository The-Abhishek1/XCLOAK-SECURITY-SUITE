'use client';

import type { ComponentType, CSSProperties, ReactNode } from 'react';

type IconComponent = ComponentType<{ className?: string; style?: CSSProperties }>;

interface EmptyStateProps {
  icon?: IconComponent;
  title: string;
  message?: string;
  action?: ReactNode;
}

export function EmptyState({ icon: Icon, title, message, action }: EmptyStateProps) {
  return (
    <div className="py-12 text-center space-y-3">
      {Icon && <Icon className="h-8 w-8 mx-auto" style={{ color: 'var(--text-3)' }} />}
      <p className="text-sm font-medium" style={{ color: 'var(--text-2)' }}>{title}</p>
      {message && <p className="text-xs" style={{ color: 'var(--text-3)' }}>{message}</p>}
      {action && <div>{action}</div>}
    </div>
  );
}
