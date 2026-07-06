'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import api from '@/lib/api';
import {
  Search, X, Cpu, Bell, AlertTriangle,
  Shield, FileCode, Bug, Package, Loader2,
} from 'lucide-react';

interface SearchResult {
  type: string;
  id: number;
  title: string;
  subtitle: string;
  severity?: string;
  href: string;
}

const TYPE_ICONS: Record<string, any> = {
  agent:      Cpu,
  alert:      Bell,
  incident:   AlertTriangle,
  ioc:        Shield,
  sigma_rule: FileCode,
  yara_rule:  Bug,
  package:    Package,
};

const TYPE_LABELS: Record<string, string> = {
  agent:      'Agent',
  alert:      'Alert',
  incident:   'Incident',
  ioc:        'IOC',
  sigma_rule: 'Sigma',
  yara_rule:  'YARA',
  package:    'Package',
};

const SEV_COLORS: Record<string, string> = {
  critical: 'var(--red)',
  high:     'var(--orange)',
  medium:   'var(--yellow)',
  low:      'var(--blue)',
};

export function GlobalSearch({ compact = false }: { compact?: boolean }) {
  const [open, setOpen]         = useState(false);
  const [query, setQuery]       = useState('');
  const [results, setResults]   = useState<SearchResult[]>([]);
  const [loading, setLoading]   = useState(false);
  const [selected, setSelected] = useState(0);
  const inputRef                = useRef<HTMLInputElement>(null);
  const router                  = useRouter();
  const debounceRef             = useRef<NodeJS.Timeout>();

  // Cmd+K / Ctrl+K to open
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setOpen(o => !o);
      }
      if (e.key === 'Escape') setOpen(false);
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 50);
      setQuery('');
      setResults([]);
      setSelected(0);
    }
  }, [open]);

  const search = useCallback(async (q: string) => {
    if (q.length < 2) { setResults([]); return; }
    setLoading(true);
    try {
      const r = await api.get('/search', { params: { q } });
      setResults(r.data?.results || []);
      setSelected(0);
    } catch {
      setResults([]);
    } finally {
      setLoading(false);
    }
  }, []);

  const onChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const q = e.target.value;
    setQuery(q);
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => search(q), 250);
  };

  const navigate = (result: SearchResult) => {
    router.push(result.href);
    setOpen(false);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setSelected(s => Math.min(s + 1, results.length - 1)); }
    if (e.key === 'ArrowUp')   { e.preventDefault(); setSelected(s => Math.max(s - 1, 0)); }
    if (e.key === 'Enter' && results[selected]) navigate(results[selected]);
  };

  if (!open) {
    if (compact) {
      return (
        <button onClick={() => setOpen(true)}
          className="flex h-8 w-8 items-center justify-center rounded-lg transition-colors"
          style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)', color: 'var(--text-2)' }}
          title="Search (Ctrl+K)">
          <Search className="h-4 w-4" />
        </button>
      );
    }
    return (
      <button
        onClick={() => setOpen(true)}
        className="flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs transition-all"
        style={{
          background: 'var(--glass-bg)',
          border: '1px solid var(--border)',
          color: 'var(--text-3)',
          minWidth: 180,
        }}
        title="Search (Ctrl+K)">
        <Search className="h-3.5 w-3.5" />
        <span>Search…</span>
        <span className="ml-auto flex items-center gap-0.5 text-[9px] font-mono opacity-60">
          <kbd className="px-1 rounded" style={{ background: 'var(--border)' }}>⌘</kbd>
          <kbd className="px-1 rounded" style={{ background: 'var(--border)' }}>K</kbd>
        </span>
      </button>
    );
  }

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-[100]" style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}
        onClick={() => setOpen(false)} />

      {/* Palette */}
      <div className="fixed top-[15%] left-1/2 -translate-x-1/2 z-[101] w-full max-w-lg"
        style={{ filter: 'drop-shadow(0 24px 60px rgba(0,0,0,0.5))' }}>
        <div className="rounded-2xl overflow-hidden"
          style={{ background: 'var(--bg-1)', border: '1px solid var(--border)' }}>

          {/* Input */}
          <div className="flex items-center gap-3 px-4 py-3.5"
            style={{ borderBottom: results.length > 0 ? '1px solid var(--border)' : undefined }}>
            {loading
              ? <Loader2 className="h-4 w-4 shrink-0 animate-spin" style={{ color: 'var(--accent)' }} />
              : <Search className="h-4 w-4 shrink-0" style={{ color: 'var(--text-3)' }} />}
            <input
              ref={inputRef}
              value={query}
              onChange={onChange}
              onKeyDown={onKeyDown}
              placeholder="Search agents, alerts, incidents, IOCs, rules…"
              className="flex-1 bg-transparent outline-none text-sm"
              style={{ color: 'var(--text-1)' }} />
            <button onClick={() => setOpen(false)} style={{ color: 'var(--text-3)' }}>
              <X className="h-4 w-4" />
            </button>
          </div>

          {/* Results */}
          {results.length > 0 && (
            <div className="max-h-80 overflow-y-auto py-2">
              {results.map((r, i) => {
                const Icon = TYPE_ICONS[r.type] || Search;
                const isSelected = i === selected;
                return (
                  <button key={`${r.type}-${r.id}-${i}`}
                    className="flex items-center gap-3 w-full px-4 py-2.5 text-left transition-all"
                    style={{ background: isSelected ? 'var(--accent-glow)' : 'transparent' }}
                    onClick={() => navigate(r)}
                    onMouseEnter={() => setSelected(i)}>
                    <div className="flex h-8 w-8 items-center justify-center rounded-lg shrink-0"
                      style={{
                        background: isSelected ? 'var(--accent-glow)' : 'var(--glass-bg)',
                        border: `1px solid ${isSelected ? 'var(--accent-border)' : 'var(--border)'}`,
                      }}>
                      <Icon className="h-3.5 w-3.5"
                        style={{ color: isSelected ? 'var(--accent)' : 'var(--text-3)' }} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>
                          {r.title}
                        </p>
                        {r.severity && (
                          <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded shrink-0"
                            style={{
                              color: SEV_COLORS[r.severity] || 'var(--text-3)',
                              background: `${SEV_COLORS[r.severity] || 'var(--text-3)'}22`,
                            }}>
                            {r.severity}
                          </span>
                        )}
                      </div>
                      <p className="text-[10px] truncate mt-0.5" style={{ color: 'var(--text-3)' }}>
                        {r.subtitle}
                      </p>
                    </div>
                    <span className="text-[10px] shrink-0 px-1.5 py-0.5 rounded font-medium"
                      style={{ background: 'var(--glass-bg)', color: 'var(--text-3)', border: '1px solid var(--border)' }}>
                      {TYPE_LABELS[r.type] || r.type}
                    </span>
                  </button>
                );
              })}
            </div>
          )}

          {/* Empty state */}
          {query.length >= 2 && !loading && results.length === 0 && (
            <div className="py-10 text-center">
              <p className="text-sm" style={{ color: 'var(--text-3)' }}>No results for &quot;{query}&quot;</p>
            </div>
          )}

          {/* Footer */}
          <div className="flex items-center gap-4 px-4 py-2 text-[10px]"
            style={{ borderTop: '1px solid var(--border)', color: 'var(--text-3)' }}>
            <span><kbd className="mono">↑↓</kbd> navigate</span>
            <span><kbd className="mono">↵</kbd> open</span>
            <span><kbd className="mono">esc</kbd> close</span>
            <span className="ml-auto">{results.length} result{results.length !== 1 ? 's' : ''}</span>
          </div>
        </div>
      </div>
    </>
  );
}
