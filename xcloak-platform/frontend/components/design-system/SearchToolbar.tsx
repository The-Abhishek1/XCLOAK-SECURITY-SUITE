'use client';

import { Search, X } from 'lucide-react';

interface SearchToolbarProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  onClear?: () => void;
  className?: string;
}

export function SearchToolbar({ value, onChange, placeholder = 'Search…', onClear, className = '' }: SearchToolbarProps) {
  return (
    <div className={`relative flex-1 min-w-[200px] ${className}`}>
      <Search className="h-3.5 w-3.5 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: 'var(--text-3)' }} />
      <input
        type="text"
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className="g-input"
        style={{ paddingLeft: 32, paddingRight: value ? 32 : undefined }}
      />
      {value && (
        <button
          onClick={() => { onChange(''); onClear?.(); }}
          className="absolute right-3 top-1/2 -translate-y-1/2"
        >
          <X className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
        </button>
      )}
    </div>
  );
}
