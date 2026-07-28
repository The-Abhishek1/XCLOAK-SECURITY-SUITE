'use client';

import Link from 'next/link';
import { Minus, TrendingDown, TrendingUp } from 'lucide-react';
import type { ComponentType, CSSProperties } from 'react';

type IconComponent = ComponentType<{ className?: string; style?: CSSProperties }>;

interface MetricCardProps {
  label: string;
  value: string | number;
  sub?: string;
  color?: string;
  icon?: IconComponent;
  pulse?: boolean;
  delta?: number;
  deltaPct?: number;
  href?: string;
  variant?: 'default' | 'compact';
  layout?: 'inline' | 'icon-chip';
}

function DeltaTag({ delta, pct }: { delta: number; pct: number }) {
  if (delta === 0) {
    return (
      <span className="text-[10px] flex items-center gap-0.5" style={{ color: 'var(--text-3)' }}>
        <Minus className="h-2.5 w-2.5" /> 0%
      </span>
    );
  }
  const up = delta > 0;
  const Icon = up ? TrendingUp : TrendingDown;
  return (
    <span className="text-[10px] flex items-center gap-0.5 font-semibold" style={{ color: up ? 'var(--red)' : 'var(--green)' }}>
      <Icon className="h-2.5 w-2.5" />{Math.abs(pct)}%
    </span>
  );
}

export function MetricCard({ label, value, sub, color, icon: Icon, pulse, delta, deltaPct, href, variant = 'default', layout = 'inline' }: MetricCardProps) {
  const compact = variant === 'compact';

  if (layout === 'icon-chip') {
    const chipContent = (
      <div className="g-card p-4 flex items-start gap-3 h-full">
        {Icon && (
          <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
            style={{ background: `color-mix(in srgb, ${color || 'var(--accent)'} 15%, transparent)` }}>
            <Icon className="w-4 h-4" style={{ color: color || 'var(--accent)' }} />
          </div>
        )}
        <div className="min-w-0">
          <p className="text-[10px] uppercase tracking-wider mb-0.5 font-medium" style={{ color: 'var(--text-3)' }}>{label}</p>
          <p className="text-2xl font-bold leading-none" style={{ color: color || 'var(--text-1)' }}>{value}</p>
          {sub && <p className="text-[11px] mt-1" style={{ color: 'var(--text-3)' }}>{sub}</p>}
        </div>
      </div>
    );
    return href ? <Link href={href} className="h-full block">{chipContent}</Link> : chipContent;
  }

  const content = (
    <div
      className={`g-card relative overflow-hidden h-full transition-all hover:border-accent ${compact ? 'p-3' : 'p-4'} flex flex-col gap-2`}
    >
      {pulse && (
        <span
          className="absolute top-3 right-3 h-2 w-2 rounded-full animate-pulse"
          style={{ background: color || 'var(--accent)' }}
        />
      )}

      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--text-3)' }}>
          {Icon && <Icon className={compact ? 'h-3.5 w-3.5' : 'h-4 w-4'} />}
          <span className={compact ? '' : 'uppercase tracking-wide text-[10px] font-medium'}>{label}</span>
        </div>
        {delta !== undefined && deltaPct !== undefined && <DeltaTag delta={delta} pct={deltaPct} />}
      </div>

      <p
        className={`font-bold tabular-nums leading-none ${compact ? 'text-xl' : 'text-2xl'}`}
        style={{ color: color || 'var(--text-1)' }}
      >
        {value ?? '—'}
      </p>

      {sub && <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{sub}</p>}
    </div>
  );

  return href ? <Link href={href} className="h-full block">{content}</Link> : content;
}
