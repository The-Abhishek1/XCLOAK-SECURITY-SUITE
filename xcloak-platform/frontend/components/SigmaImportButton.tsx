'use client';

import { useRef, useState } from 'react';
import api from '@/lib/api';
import { Upload, FileCode, CheckCircle, AlertCircle, X } from 'lucide-react';

interface ImportResult {
  imported: number;
  skipped: number;
  errors: string[];
  message: string;
}

export function SigmaImportButton({ onImported }: { onImported?: () => void }) {
  const inputRef            = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading]   = useState(false);
  const [result, setResult]     = useState<ImportResult | null>(null);

  const doUpload = async (files: File[]) => {
    if (!files.length) return;
    setLoading(true);
    setResult(null);

    const form = new FormData();
    files.forEach(f => form.append('rules', f));

    try {
      const r = await api.post('/sigma/import', form, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setResult(r.data);
      if (r.data.imported > 0) onImported?.();
    } catch {
      setResult({ imported: 0, skipped: 0, errors: ['Upload failed'], message: 'Upload failed' });
    } finally {
      setLoading(false);
    }
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    doUpload([...e.dataTransfer.files].filter(f => f.name.endsWith('.yml') || f.name.endsWith('.yaml')));
  };

  return (
    <div className="space-y-2">
      <div
        onDragOver={e => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => inputRef.current?.click()}
        className="flex flex-col items-center gap-2 rounded-xl py-6 px-4 cursor-pointer transition-all"
        style={{
          border: `2px dashed ${dragging ? 'var(--accent)' : 'var(--border)'}`,
          background: dragging ? 'var(--accent-glow)' : 'var(--glass-bg)',
        }}>
        <Upload className="h-6 w-6" style={{ color: dragging ? 'var(--accent)' : 'var(--text-3)' }} />
        <p className="text-xs text-center" style={{ color: 'var(--text-2)' }}>
          Drop Sigma YAML files here, or <span style={{ color: 'var(--accent)' }}>click to browse</span>
        </p>
        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
          Accepts .yml / .yaml — standard Sigma rule format
        </p>
        {loading && (
          <p className="text-xs animate-pulse" style={{ color: 'var(--accent)' }}>Importing…</p>
        )}
        <input ref={inputRef} type="file" multiple accept=".yml,.yaml" className="hidden"
          onChange={e => doUpload([...e.target.files!])} />
      </div>

      {result && (
        <div className="rounded-xl p-3"
          style={{
            background: result.imported > 0 ? 'var(--green-bg)' : 'var(--glass-bg)',
            border: `1px solid ${result.imported > 0 ? 'var(--green-border)' : 'var(--border)'}`,
          }}>
          <div className="flex items-center gap-2 mb-1">
            {result.imported > 0
              ? <CheckCircle className="h-4 w-4 shrink-0" style={{ color: 'var(--green)' }} />
              : <AlertCircle className="h-4 w-4 shrink-0" style={{ color: 'var(--orange)' }} />}
            <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{result.message}</p>
            <button onClick={() => setResult(null)} className="ml-auto" style={{ color: 'var(--text-3)' }}>
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
          {result.errors.length > 0 && (
            <div className="mt-1 space-y-0.5">
              {result.errors.slice(0, 5).map((e, i) => (
                <p key={i} className="text-[10px] mono" style={{ color: 'var(--red)' }}>{e}</p>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
