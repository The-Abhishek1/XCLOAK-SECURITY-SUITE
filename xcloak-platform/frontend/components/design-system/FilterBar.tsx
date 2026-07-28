'use client';

interface FilterOption {
  value: string;
  label: string;
}

interface Filter {
  value: string;
  onChange: (value: string) => void;
  options: FilterOption[];
  ariaLabel?: string;
}

interface FilterBarProps {
  filters: Filter[];
  className?: string;
}

export function FilterBar({ filters, className = '' }: FilterBarProps) {
  return (
    <div className={`flex items-center gap-2 flex-wrap ${className}`}>
      {filters.map((f, i) => (
        <select
          key={i}
          value={f.value}
          onChange={e => f.onChange(e.target.value)}
          aria-label={f.ariaLabel}
          className="g-select"
          style={{ width: 'auto', minWidth: 130 }}
        >
          {f.options.map(o => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
      ))}
    </div>
  );
}
