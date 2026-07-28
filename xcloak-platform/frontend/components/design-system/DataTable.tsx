'use client';

import type { CSSProperties, ReactNode } from 'react';
import { LoadingSkeleton } from './LoadingSkeleton';
import { EmptyState } from './EmptyState';

export interface DataTableColumn<T> {
  key: string;
  header: ReactNode;
  render?: (row: T) => ReactNode;
  align?: 'left' | 'right' | 'center';
  width?: string;
}

interface DataTableProps<T> {
  columns: DataTableColumn<T>[];
  rows: T[];
  rowKey: (row: T, index: number) => string | number;
  onRowClick?: (row: T) => void;
  rowStyle?: (row: T) => CSSProperties | undefined;
  loading?: boolean;
  emptyState?: ReactNode;
  footer?: ReactNode;
  className?: string;
}

export function DataTable<T>({ columns, rows, rowKey, onRowClick, rowStyle, loading, emptyState, footer, className = '' }: DataTableProps<T>) {
  if (loading) {
    return (
      <div className={`g-table ${className}`}>
        <LoadingSkeleton variant="table-row" count={6} />
      </div>
    );
  }

  if (rows.length === 0) {
    return (
      <div className={`g-table ${className}`}>
        {emptyState ?? <EmptyState title="No data" />}
      </div>
    );
  }

  return (
    <div className={`g-table overflow-x-auto ${className}`}>
      <table className="w-full border-collapse">
        <thead>
          <tr style={{ background: 'rgba(0,0,0,0.15)', borderBottom: '1px solid var(--border)' }}>
            {columns.map(col => (
              <th
                key={col.key}
                className="text-xs font-semibold uppercase tracking-wide whitespace-nowrap"
                style={{
                  padding: '10px 16px',
                  color: 'var(--text-3)',
                  fontSize: 'var(--text-xs)',
                  letterSpacing: '0.07em',
                  textAlign: col.align ?? 'left',
                  width: col.width,
                }}
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr
              key={rowKey(row, index)}
              onClick={() => onRowClick?.(row)}
              className="transition-colors border-b last:border-b-0 [border-color:var(--border)]"
              style={{ cursor: onRowClick ? 'pointer' : undefined, ...rowStyle?.(row) }}
              onMouseEnter={e => (e.currentTarget.style.background = 'var(--accent-glow)')}
              onMouseLeave={e => (e.currentTarget.style.background = rowStyle?.(row)?.background as string ?? 'transparent')}
            >
              {columns.map(col => (
                <td
                  key={col.key}
                  className="text-sm"
                  style={{ padding: 'var(--space-3) var(--space-4)', color: 'var(--text-1)', textAlign: col.align ?? 'left' }}
                >
                  {col.render ? col.render(row) : String((row as Record<string, unknown>)[col.key] ?? '—')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {footer && <div className="px-4 py-3" style={{ borderTop: '1px solid var(--border)' }}>{footer}</div>}
    </div>
  );
}
