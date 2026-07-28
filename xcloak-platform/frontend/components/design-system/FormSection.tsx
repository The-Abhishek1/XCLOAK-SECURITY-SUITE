'use client';

import type { ReactNode } from 'react';

interface FormSectionProps {
  title?: string;
  children: ReactNode;
  className?: string;
}

export function FormSection({ title, children, className = '' }: FormSectionProps) {
  return (
    <div className={`space-y-3 ${className}`}>
      {title && <h4 className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-3)' }}>{title}</h4>}
      <div className="space-y-3">{children}</div>
    </div>
  );
}

interface FormFieldProps {
  label: string;
  error?: string;
  required?: boolean;
  children: ReactNode;
}

export function FormField({ label, error, required, children }: FormFieldProps) {
  return (
    <div className="space-y-1.5">
      <label className="text-xs font-medium" style={{ color: 'var(--text-2)' }}>
        {label}
        {required && <span style={{ color: 'var(--red)' }}> *</span>}
      </label>
      {children}
      {error && <p className="text-[11px]" style={{ color: 'var(--red)' }}>{error}</p>}
    </div>
  );
}
