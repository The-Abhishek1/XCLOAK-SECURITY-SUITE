'use client';

import type { ButtonHTMLAttributes, ComponentType, CSSProperties } from 'react';
import { Loader2 } from 'lucide-react';

type IconComponent = ComponentType<{ className?: string; style?: CSSProperties }>;

interface ActionButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'ghost' | 'danger';
  icon?: IconComponent;
  loading?: boolean;
}

const VARIANT_CLASS: Record<string, string> = {
  primary: 'g-btn-primary',
  ghost: 'g-btn-ghost',
  danger: 'g-btn-danger',
};

export function ActionButton({ variant = 'ghost', icon: Icon, loading, disabled, children, className = '', ...rest }: ActionButtonProps) {
  return (
    <button
      className={`g-btn ${VARIANT_CLASS[variant]} ${className}`}
      disabled={disabled || loading}
      {...rest}
    >
      {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : Icon && <Icon className="h-3.5 w-3.5" />}
      {children}
    </button>
  );
}
