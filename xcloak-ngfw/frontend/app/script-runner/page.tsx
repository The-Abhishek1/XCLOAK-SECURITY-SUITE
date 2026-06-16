'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { agentsAPI } from '@/lib/api';
import api from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import {
  Terminal, Play, Loader2, Copy, Check, ChevronDown,
  ChevronRight, Clock, CheckCircle, XCircle, History,
  BookOpen, X, Cpu,
} from 'lucide-react';

interface Agent { id: number; hostname: string; ip_address: string; status: string; }
interface Template { id: string; label: string; category: string; shell: string; script: string; }
interface RunResult {
  agentId: number;
  hostname: string;
  taskId: number;
  status: 'pending' | 'running' | 'completed' | 'error';
  output: string;
  startedAt: number;
  completedAt?: number;
}
interface HistoryRow {
  id: number; agent_id: number; hostname: string; label: string;
  script: string; status: string; result: string;
  created_at: string; completed_at?: string;
}

const SHELLS = ['bash', 'sh', 'python3'] as const;

export default function ScriptRunnerPage() {
  const [agents, setAgents]             = useState<Agent[]>([]);
  const [selectedAgents, setSelectedAgents] = useState<number[]>([]);
  const [script, setScript]             = useState('');
  const [label, setLabel]               = useState('');
  const [shell, setShell]               = useState<string>('bash');
  const [running, setRunning]           = useState(false);
  const [results, setResults]           = useState<RunResult[]>([]);
  const [tab, setTab]                   = useState<'run' | 'history' | 'templates'>('run');
  const [templates, setTemplates]       = useState<{ by_category: Record<string, Template[]> }>({ by_category: {} });
  const [history, setHistory]           = useState<HistoryRow[]>([]);
  const [historyAgent, setHistoryAgent] = useState('');
  const [expandedResult, setExpandedResult] = useState<number | null>(null);
  const [toast, setToast]               = useState<string | null>(null);
  const [copied, setCopied]             = useState(false);
  const pollRef                         = useRef<Record<number, NodeJS.Timeout>>({});
  const textareaRef                     = useRef<HTMLTextAreaElement>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const copy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  useEffect(() => {
    agentsAPI.getAll().then(r => setAgents(r.data || []));
    api.get('/scripts/templates').then(r => setTemplates(r.data));
  }, []);

  useEffect(() => {
    if (tab === 'history') loadHistory();
  }, [tab, historyAgent]);

  const loadHistory = async () => {
    const r = await api.get('/scripts/history', {
      params: historyAgent ? { agent_id: historyAgent } : {},
    });
    setHistory(r.data || []);
  };

  const toggleAgent = (id: number) =>
    setSelectedAgents(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    );

  const applyTemplate = (t: Template) => {
    setScript(t.script);
    setLabel(t.label);
    setShell(t.shell);
    setTab('run');
    setTimeout(() => textareaRef.current?.focus(), 50);
  };

  const pollResult = useCallback((result: RunResult) => {
    const poll = async () => {
      try {
        const r = await api.get(`/scripts/result/${result.taskId}`);
        const { status, result: rawOutput } = r.data;
        // result is *string in Go — null when empty, string otherwise
        const output = rawOutput ?? '';

        setResults(prev => prev.map(res =>
          res.taskId === result.taskId
            ? {
                ...res,
                status: status === 'completed' ? 'completed' : status === 'failed' ? 'error' : 'running',
                output: String(output),
                completedAt: status === 'completed' ? Date.now() : undefined,
              }
            : res
        ));

        if (status !== 'pending' && status !== 'running') {
          clearInterval(pollRef.current[result.taskId]);
          delete pollRef.current[result.taskId];
        }
      } catch { /* ignore poll errors */ }
    };

    pollRef.current[result.taskId] = setInterval(poll, 3000);
    poll(); // immediate first check
  }, []);

  const run = async () => {
    if (!script.trim()) return notify('Enter a script');
    if (selectedAgents.length === 0) return notify('Select at least one agent');

    setRunning(true);
    setResults([]);

    try {
      const r = await api.post('/scripts/run', {
        agent_ids: selectedAgents,
        script,
        label,
        shell,
      });

      const tasks: RunResult[] = (r.data.tasks || []).map((t: any) => ({
        agentId:  t.agent_id,
        hostname: t.hostname,
        taskId:   t.task_id,
        status:   t.error ? 'error' : 'pending',
        output:   t.error || '',
        startedAt: Date.now(),
      }));

      setResults(tasks);
      setExpandedResult(tasks[0]?.taskId ?? null);

      // Start polling each dispatched task.
      tasks.filter(t => t.status === 'pending').forEach(pollResult);
    } catch (e: any) {
      notify(e?.response?.data?.error || 'Dispatch failed');
    } finally {
      setRunning(false);
    }
  };

  useEffect(() => () => {
    Object.values(pollRef.current).forEach(clearInterval);
  }, []);

  const onlineAgents = agents.filter(a => a.status === 'online');

  return (
    <RootLayout
      title="Script Runner"
      subtitle="Execute scripts on agents and retrieve output in real-time">

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm"
          style={{ color: 'var(--text-1)', minWidth: 200 }}>
          {toast}
        </div>
      )}

      {/* Tabs */}
      <div className="flex items-center gap-1 mb-5 p-1 rounded-xl w-fit"
        style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
        {([
          { id: 'run',       label: 'Run Script', icon: Terminal },
          { id: 'templates', label: 'Templates',  icon: BookOpen },
          { id: 'history',   label: 'History',    icon: History  },
        ] as const).map(({ id, label: lbl, icon: Icon }) => (
          <button key={id} onClick={() => setTab(id)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
            style={{
              background: tab === id ? 'var(--accent-glow)' : 'transparent',
              color:      tab === id ? 'var(--accent)' : 'var(--text-2)',
              border:     tab === id ? '1px solid var(--accent-border)' : '1px solid transparent',
            }}>
            <Icon className="h-3.5 w-3.5" /> {lbl}
          </button>
        ))}
      </div>

      {/* ── Run Script tab ──────────────────────────────────── */}
      {tab === 'run' && (
        <div className="grid gap-5 lg:grid-cols-[1fr_320px]">

          {/* Left: editor + results */}
          <div className="space-y-4">

            {/* Script editor */}
            <div className="g-card overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3"
                style={{ borderBottom: '1px solid var(--border)' }}>
                <div className="flex items-center gap-3">
                  <Terminal className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                  <input value={label} onChange={e => setLabel(e.target.value)}
                    placeholder="Script label (optional)"
                    className="bg-transparent text-sm outline-none"
                    style={{ color: 'var(--text-1)' }} />
                </div>
                <div className="flex items-center gap-2">
                  <select value={shell} onChange={e => setShell(e.target.value)}
                    className="g-select text-xs" style={{ padding: '3px 8px' }}>
                    {SHELLS.map(s => <option key={s}>{s}</option>)}
                  </select>
                  <button onClick={() => copy(script)} className="text-xs flex items-center gap-1"
                    style={{ color: 'var(--text-3)' }}>
                    {copied ? <Check className="h-3.5 w-3.5" style={{ color: 'var(--green)' }} />
                            : <Copy className="h-3.5 w-3.5" />}
                  </button>
                  {script && (
                    <button onClick={() => setScript('')}
                      className="text-xs" style={{ color: 'var(--text-3)' }}>
                      <X className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>
              </div>
              <textarea
                ref={textareaRef}
                value={script}
                onChange={e => setScript(e.target.value)}
                onKeyDown={e => {
                  // Tab inserts 2 spaces instead of changing focus
                  if (e.key === 'Tab') {
                    e.preventDefault();
                    const el = e.currentTarget;
                    const start = el.selectionStart;
                    const end   = el.selectionEnd;
                    const next  = script.slice(0, start) + '  ' + script.slice(end);
                    setScript(next);
                    setTimeout(() => el.setSelectionRange(start + 2, start + 2), 0);
                  }
                }}
                placeholder={'# Enter bash script\necho "hostname: $(hostname)"\necho "whoami: $(whoami)"\nps aux | head -10'}
                rows={18}
                spellCheck={false}
                className="w-full p-4 bg-transparent outline-none resize-none font-mono text-sm leading-relaxed"
                style={{ color: 'var(--text-1)' }}
              />
            </div>

            {/* Results */}
            {results.length > 0 && (
              <div className="space-y-2">
                <p className="text-xs font-semibold" style={{ color: 'var(--text-2)' }}>
                  Output — {results.filter(r => r.status === 'completed').length}/{results.length} completed
                </p>
                {results.map(res => {
                  const isExpanded = expandedResult === res.taskId;
                  const elapsed = res.completedAt
                    ? ((res.completedAt - res.startedAt) / 1000).toFixed(1) + 's'
                    : running || res.status === 'pending' || res.status === 'running'
                      ? ((Date.now() - res.startedAt) / 1000).toFixed(0) + 's…'
                      : '';
                  return (
                    <div key={res.taskId} className="g-card overflow-hidden">
                      <div
                        className="flex items-center gap-3 px-4 py-3 cursor-pointer"
                        style={{ borderBottom: isExpanded ? '1px solid var(--border)' : undefined }}
                        onClick={() => setExpandedResult(isExpanded ? null : res.taskId)}>
                        {res.status === 'completed' ? (
                          <CheckCircle className="h-4 w-4 shrink-0" style={{ color: 'var(--green)' }} />
                        ) : res.status === 'error' ? (
                          <XCircle className="h-4 w-4 shrink-0" style={{ color: 'var(--red)' }} />
                        ) : (
                          <Loader2 className="h-4 w-4 shrink-0 animate-spin" style={{ color: 'var(--accent)' }} />
                        )}
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>
                            {res.hostname || `Agent #${res.agentId}`}
                          </p>
                          <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                            Task #{res.taskId} · {res.status}
                            {elapsed && ` · ${elapsed}`}
                          </p>
                        </div>
                        <div className="flex items-center gap-2">
                          {res.output && (
                            <button onClick={e => { e.stopPropagation(); copy(res.output); }}
                              className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                              <Copy className="h-3 w-3" />
                            </button>
                          )}
                          {isExpanded
                            ? <ChevronDown className="h-4 w-4" style={{ color: 'var(--text-3)' }} />
                            : <ChevronRight className="h-4 w-4" style={{ color: 'var(--text-3)' }} />}
                        </div>
                      </div>

                      {isExpanded && (
                        <div className="relative">
                          {(res.status === 'pending' || res.status === 'running') && !res.output ? (
                            <div className="flex items-center gap-2 px-4 py-6 text-xs"
                              style={{ color: 'var(--text-3)' }}>
                              <Loader2 className="h-4 w-4 animate-spin" />
                              Waiting for agent response…
                            </div>
                          ) : (
                            <pre className="p-4 text-xs leading-relaxed overflow-auto max-h-80 font-mono"
                              style={{ color: 'var(--text-1)', background: 'var(--bg-0)' }}>
                              {res.output || '(empty output — script ran but produced no stdout)'}
                            </pre>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Right: agent selector + run button */}
          <div className="space-y-4">

            {/* Agent selector */}
            <div className="g-card">
              <div className="flex items-center justify-between px-4 py-3"
                style={{ borderBottom: '1px solid var(--border)' }}>
                <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>
                  Target Agents
                </p>
                <button onClick={() => setSelectedAgents(
                    selectedAgents.length === onlineAgents.length ? [] : onlineAgents.map(a => a.id)
                  )}
                  className="text-[10px]" style={{ color: 'var(--accent)' }}>
                  {selectedAgents.length === onlineAgents.length ? 'Deselect all' : 'Select all online'}
                </button>
              </div>

              {onlineAgents.length === 0 ? (
                <div className="px-4 py-6 text-center">
                  <Cpu className="h-6 w-6 mx-auto mb-2" style={{ color: 'var(--text-3)' }} />
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>No online agents</p>
                </div>
              ) : (
                <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                  {agents.map(a => (
                    <div key={a.id}
                      className="flex items-center gap-3 px-4 py-2.5 cursor-pointer transition-all"
                      style={{ opacity: a.status === 'online' ? 1 : 0.4 }}
                      onClick={() => a.status === 'online' && toggleAgent(a.id)}>
                      <div className="relative flex h-4 w-4 shrink-0 items-center justify-center rounded"
                        style={{
                          background: selectedAgents.includes(a.id) ? 'var(--accent)' : 'transparent',
                          border: `1px solid ${selectedAgents.includes(a.id) ? 'var(--accent)' : 'var(--border)'}`,
                        }}>
                        {selectedAgents.includes(a.id) && (
                          <Check className="h-3 w-3 text-white" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium truncate" style={{ color: 'var(--text-1)' }}>
                          {a.hostname}
                        </p>
                        <p className="text-[10px] mono" style={{ color: 'var(--text-3)' }}>{a.ip_address}</p>
                      </div>
                      <span className={a.status === 'online' ? 's-online' : 's-offline'}
                        style={{ fontSize: 9 }}>
                        {a.status}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Run button */}
            <button
              onClick={run}
              disabled={running || !script.trim() || selectedAgents.length === 0}
              className="g-btn g-btn-primary w-full justify-center py-3 text-sm">
              {running
                ? <><Loader2 className="h-4 w-4 animate-spin" /> Running on {selectedAgents.length} agent{selectedAgents.length !== 1 ? 's' : ''}…</>
                : <><Play className="h-4 w-4" /> Run on {selectedAgents.length || 0} Agent{selectedAgents.length !== 1 ? 's' : ''}</>}
            </button>

            {/* Quick stats */}
            {results.length > 0 && (
              <div className="g-card p-4 grid grid-cols-3 gap-3 text-center">
                {[
                  ['Dispatched', results.length, 'var(--accent)'],
                  ['Completed',  results.filter(r => r.status === 'completed').length,  'var(--green)'],
                  ['Errors',     results.filter(r => r.status === 'error').length,      'var(--red)'],
                ].map(([label, count, color]) => (
                  <div key={String(label)}>
                    <p className="text-xl font-bold" style={{ color: color as string }}>{count}</p>
                    <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{label}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Templates tab ───────────────────────────────────── */}
      {tab === 'templates' && (
        <div className="space-y-5">
          {Object.entries(templates.by_category || {}).map(([category, tmps]) => (
            <div key={category}>
              <p className="text-[10px] font-bold uppercase tracking-wider mb-2"
                style={{ color: 'var(--text-3)' }}>
                {category}
              </p>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {(tmps as Template[]).map(t => (
                  <div key={t.id} className="g-card p-4 cursor-pointer transition-all group"
                    style={{ border: '1px solid var(--border)' }}
                    onClick={() => applyTemplate(t)}
                    onMouseEnter={e => (e.currentTarget as HTMLElement).style.borderColor = 'var(--accent-border)'}
                    onMouseLeave={e => (e.currentTarget as HTMLElement).style.borderColor = 'var(--border)'}>
                    <div className="flex items-center justify-between mb-2">
                      <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>
                        {t.label}
                      </p>
                      <span className="mono text-[10px] px-1.5 py-0.5 rounded"
                        style={{ background: 'var(--glass-bg)', color: 'var(--accent)' }}>
                        {t.shell}
                      </span>
                    </div>
                    <pre className="text-[10px] font-mono truncate" style={{ color: 'var(--text-3)' }}>
                      {t.script.split('\n')[0]}
                    </pre>
                    <p className="text-[10px] mt-2 opacity-0 group-hover:opacity-100 transition-opacity"
                      style={{ color: 'var(--accent)' }}>
                      Click to load →
                    </p>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── History tab ─────────────────────────────────────── */}
      {tab === 'history' && (
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <select value={historyAgent} onChange={e => setHistoryAgent(e.target.value)}
              className="g-select text-xs">
              <option value="">All agents</option>
              {agents.map(a => (
                <option key={a.id} value={String(a.id)}>{a.hostname}</option>
              ))}
            </select>
            <p className="text-xs" style={{ color: 'var(--text-3)' }}>
              {history.length} executions
            </p>
          </div>

          {history.length === 0 ? (
            <div className="py-16 text-center">
              <History className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
              <p className="text-sm" style={{ color: 'var(--text-2)' }}>No script history yet.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {history.map(row => {
                const isExpanded = expandedResult === row.id;
                return (
                  <div key={row.id} className="g-card overflow-hidden">
                    <div className="flex items-center gap-3 px-4 py-3 cursor-pointer"
                      style={{ borderBottom: isExpanded ? '1px solid var(--border)' : undefined }}
                      onClick={() => setExpandedResult(isExpanded ? null : row.id)}>
                      {row.status === 'completed'
                        ? <CheckCircle className="h-4 w-4 shrink-0" style={{ color: 'var(--green)' }} />
                        : row.status === 'failed'
                        ? <XCircle className="h-4 w-4 shrink-0" style={{ color: 'var(--red)' }} />
                        : <Clock className="h-4 w-4 shrink-0" style={{ color: 'var(--text-3)' }} />}
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>
                          {row.label || row.script?.split('\n')[0]?.slice(0, 60) || 'Script'}
                        </p>
                        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                          {row.hostname} · #{row.id} · {timeAgo(row.created_at)}
                        </p>
                      </div>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                        row.status === 'completed' ? 's-online' : row.status === 'failed' ? 's-critical' : ''
                      }`}>
                        {row.status}
                      </span>
                      {isExpanded
                        ? <ChevronDown className="h-4 w-4" style={{ color: 'var(--text-3)' }} />
                        : <ChevronRight className="h-4 w-4" style={{ color: 'var(--text-3)' }} />}
                    </div>
                    {isExpanded && (
                      <div>
                        {row.script && (
                          <pre className="px-4 py-3 text-[11px] font-mono border-b overflow-x-auto"
                            style={{ color: 'var(--text-3)', borderColor: 'var(--border)', background: 'var(--glass-bg)' }}>
                            {row.script}
                          </pre>
                        )}
                        <pre className="px-4 py-3 text-xs font-mono overflow-auto max-h-60"
                          style={{ color: 'var(--text-1)', background: 'var(--bg-0)' }}>
                          {row.result || '(no output)'}
                        </pre>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </RootLayout>
  );
}
