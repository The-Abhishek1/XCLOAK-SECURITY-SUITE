'use client';

import { ChevronLeft, ChevronRight } from 'lucide-react';

interface PaginationProps {
  page: number;
  totalPages: number;
  total: number;
  perPage: number;
  onPage: (p: number) => void;
}

export function Pagination({ page, totalPages, total, perPage, onPage }: PaginationProps) {

  if (totalPages <= 1) return null;

  const from = (page - 1) * perPage + 1;
  const to   = Math.min(page * perPage, total);

  // Generate page numbers to show (current ±2, always show first/last)
  const pages: (number | '…')[] = [];
  const add = (n: number) => { if (!pages.includes(n)) pages.push(n); };

  add(1);
  for (let i = Math.max(2, page - 2); i <= Math.min(totalPages - 1, page + 2); i++) add(i);
  add(totalPages);

  const withEllipsis: (number | '…')[] = [];
  let prev = 0;
  for (const p of pages as number[]) {
    if (prev && p - prev > 1) withEllipsis.push('…');
    withEllipsis.push(p);
    prev = p;
  }

  return (
    <div className="flex items-center justify-between pt-3 flex-wrap gap-2">
      <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
        Showing {from}–{to} of {total}
      </p>
      <div className="flex items-center gap-1">
        <button onClick={() => onPage(page - 1)} disabled={page <= 1}
          className="p-1.5 rounded-lg transition-colors disabled:opacity-30"
          style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
          <ChevronLeft className="h-3.5 w-3.5" style={{ color: 'var(--text-2)' }} />
        </button>

        {withEllipsis.map((p, i) =>
          p === '…' ? (
            <span key={`e-${i}`} className="px-2 text-xs" style={{ color: 'var(--text-3)' }}>…</span>
          ) : (
            <button key={p} onClick={() => onPage(p as number)}
              className="h-7 w-7 rounded-lg text-xs font-medium transition-colors"
              style={{
                background: p === page ? 'var(--accent)' : 'var(--glass-bg)',
                border: `1px solid ${p === page ? 'var(--accent)' : 'var(--border)'}`,
                color: p === page ? '#fff' : 'var(--text-2)',
              }}>
              {p}
            </button>
          )
        )}

        <button onClick={() => onPage(page + 1)} disabled={page >= totalPages}
          className="p-1.5 rounded-lg transition-colors disabled:opacity-30"
          style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
          <ChevronRight className="h-3.5 w-3.5" style={{ color: 'var(--text-2)' }} />
        </button>
      </div>
    </div>
  );
}
