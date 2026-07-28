'use client';

import type { ReactNode } from 'react';
import { SectionCard } from './SectionCard';

interface ChartCardProps {
  title?: string;
  subtitle?: string;
  actions?: ReactNode;
  legend?: ReactNode;
  height?: number;
  className?: string;
  children: ReactNode;
}

export function ChartCard({ title, subtitle, actions, legend, height = 240, className = '', children }: ChartCardProps) {
  return (
    <SectionCard title={title} subtitle={subtitle} actions={actions} className={className}>
      <div style={{ height }}>{children}</div>
      {legend && (
        <div className="flex items-center flex-wrap gap-3 pt-3 mt-3" style={{ borderTop: '1px solid var(--border)' }}>
          {legend}
        </div>
      )}
    </SectionCard>
  );
}
