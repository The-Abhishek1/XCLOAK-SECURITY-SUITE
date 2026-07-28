'use client';

import type { ReactNode } from 'react';

interface StatsGridProps {
  children: ReactNode;
  columns?: { base?: number; sm?: number; md?: number; lg?: number; xl?: number };
  className?: string;
}

const COL_CLASS: Record<number, string> = {
  1: 'grid-cols-1', 2: 'grid-cols-2', 3: 'grid-cols-3', 4: 'grid-cols-4',
  5: 'grid-cols-5', 6: 'grid-cols-6', 7: 'grid-cols-7', 8: 'grid-cols-8',
};
const SM_CLASS: Record<number, string> = {
  1: 'sm:grid-cols-1', 2: 'sm:grid-cols-2', 3: 'sm:grid-cols-3', 4: 'sm:grid-cols-4',
  5: 'sm:grid-cols-5', 6: 'sm:grid-cols-6', 7: 'sm:grid-cols-7', 8: 'sm:grid-cols-8',
};
const MD_CLASS: Record<number, string> = {
  1: 'md:grid-cols-1', 2: 'md:grid-cols-2', 3: 'md:grid-cols-3', 4: 'md:grid-cols-4',
  5: 'md:grid-cols-5', 6: 'md:grid-cols-6', 7: 'md:grid-cols-7', 8: 'md:grid-cols-8',
};
const LG_CLASS: Record<number, string> = {
  1: 'lg:grid-cols-1', 2: 'lg:grid-cols-2', 3: 'lg:grid-cols-3', 4: 'lg:grid-cols-4',
  5: 'lg:grid-cols-5', 6: 'lg:grid-cols-6', 7: 'lg:grid-cols-7', 8: 'lg:grid-cols-8',
};
const XL_CLASS: Record<number, string> = {
  1: 'xl:grid-cols-1', 2: 'xl:grid-cols-2', 3: 'xl:grid-cols-3', 4: 'xl:grid-cols-4',
  5: 'xl:grid-cols-5', 6: 'xl:grid-cols-6', 7: 'xl:grid-cols-7', 8: 'xl:grid-cols-8',
};

export function StatsGrid({ children, columns, className = '' }: StatsGridProps) {
  const c = { base: 2, sm: 3, lg: 4, ...columns };
  const classes = [
    'grid gap-3',
    COL_CLASS[c.base ?? 2],
    c.sm ? SM_CLASS[c.sm] : '',
    c.md ? MD_CLASS[c.md] : '',
    c.lg ? LG_CLASS[c.lg] : '',
    c.xl ? XL_CLASS[c.xl] : '',
    className,
  ].filter(Boolean).join(' ');

  return <div className={classes}>{children}</div>;
}
