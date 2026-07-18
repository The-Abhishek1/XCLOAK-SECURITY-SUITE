'use client';

import {
  useState, useEffect, useCallback, useMemo, useRef,
} from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import {
  detectionAPI, sigmaAPI, yaraAPI, correlationAPI, mitreAPI, iocsAPI,
  suppressionAPI, threatAPI,
} from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import { Activity, AlertTriangle, BarChart2, BookOpen, Brain, Check, CheckCircle2, ChevronDown, ChevronUp, Code2, Copy, Cpu, Database, Eye, FileText, FlaskConical, GitBranch, Globe, Layers, Play, Plus, RefreshCw, Search, Settings, Shield, Target, ToggleLeft, ToggleRight, Trash2, Upload, Zap, Lock } from '@/lib/icon-stubs';

// ── Types ─────────────────────────────────────────────────────────────────────

type ViewTab =
  | 'overview' | 'rules' | 'coverage' | 'correlation' | 'behavioral'
  | 'ioc' | 'analytics' | 'performance' | 'testing' | 'ai' | 'pipeline' | 'library';

interface Overview {
  total_rules: number;
  active_rules: number;
  disabled_rules: number;
  triggered_last_24h: number;
  mitre_covered: number;
  fp_rate: string;
  detection_accuracy: string;
  suppression_rules: number;
  total_alerts_24h: number;
  critical_alerts_24h: number;
  engine_health: string;
  rule_breakdown: Array<{
    type: string; active: number; disabled: number; total: number; triggered: number;
  }>;
}

interface TrendBucket { hour: string; hits: number; }
interface Trends {
  sigma: TrendBucket[];
  yara: TrendBucket[];
  alerts: TrendBucket[];
}

interface TechCoverage {
  tactic: string; technique: string; rule_count: number; active_count: number;
}
interface CoverageData {
  tactics: Array<{ tactic: string; rule_count: number }>;
  techniques: TechCoverage[];
  top_hits: Array<{ technique: string; hits: number }>;
}

interface RuleAnalytic {
  id: number; title: string; severity: string;
  mitre_tactic: string; mitre_technique: string;
  enabled: boolean; hit_count: number; last_triggered: string | null;
}
interface Analytics {
  rules: RuleAnalytic[];
  severity_distribution: Array<{ severity: string; triggered_rules: number; total_hits: number }>;
}

interface Engine {
  name: string; rules: number; status: string; avg_ms: number; hits_1h?: number;
}
interface Performance {
  engines: Engine[];
  total_active: number;
  hits_last_hour: number;
  failed_rules: number;
  queue_depth: number;
  uptime_pct: number;
}

interface SigmaRule {
  id: number; title: string; description: string; status: string;
  severity: string; mitre_tactic: string; mitre_technique: string;
  enabled: boolean; hit_count?: number; last_matched_at?: string;
  logsource_cat?: string; logsource_prod?: string; tags?: string[];
}

interface CorrelationRule {
  id: number; name: string; description: string; severity: string;
  enabled: boolean; match_count?: number; window_seconds?: number; sequence?: string[];
}

interface AnomalyFinding {
  id: number; agent_id: number; finding_type: string; severity: string;
  score: number; description: string; acknowledged: boolean; created_at: string;
}

interface IOC {
  id: number; type: string; value: string; severity: string;
  description: string; enabled: boolean; created_at: string;
}

interface SimResult {
  rule_id: number; rule_type: string; window_hours: number;
  estimated_matches: number; last_match: string | null;
  hourly_trend: Array<{ hour: string; count: number }>;
  status: string;
}

interface AIResult { raw: string; parsed: Record<string, unknown> | null; }

// ── Constants ─────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)',
  high:     '#fb923c',
  medium:   '#fbbf24',
  low:      'var(--accent)',
  info:     'var(--text-3)',
};

const MITRE_TACTICS = [
  'Reconnaissance','Resource Development','Initial Access','Execution',
  'Persistence','Privilege Escalation','Defense Evasion','Credential Access',
  'Discovery','Lateral Movement','Collection','Command and Control',
  'Exfiltration','Impact',
];

const TABS: Array<{ id: ViewTab; label: string; icon: React.ElementType }> = [
  { id: 'overview',     label: 'Overview',    icon: BarChart2 },
  { id: 'rules',        label: 'Rules',       icon: Shield },
  { id: 'coverage',     label: 'Coverage',    icon: Target },
  { id: 'correlation',  label: 'Correlation', icon: GitBranch },
  { id: 'behavioral',   label: 'Behavioral',  icon: Brain },
  { id: 'ioc',          label: 'IOC Matching',icon: Globe },
  { id: 'analytics',    label: 'Analytics',   icon: Activity },
  { id: 'performance',  label: 'Performance', icon: Cpu },
  { id: 'testing',      label: 'Testing',     icon: FlaskConical },
  { id: 'ai',           label: 'AI Assistant',icon: Brain },
  { id: 'pipeline',     label: 'Pipeline',    icon: Layers },
  { id: 'library',      label: 'Library',     icon: BookOpen },
];

// ── Small helpers ─────────────────────────────────────────────────────────────

function sevBadge(sev: string) {
  const color = SEV_COLOR[sev] ?? 'var(--text-3)';
  return (
    <span className="px-2 py-0.5 rounded text-[10px] font-bold capitalize"
      style={{ background: `color-mix(in srgb, ${color} 15%, transparent)`, color }}>
      {sev}
    </span>
  );
}

function StatusDot({ ok }: { ok: boolean }) {
  return (
    <span className="inline-block w-2 h-2 rounded-full shrink-0"
      style={{ background: ok ? 'var(--green)' : 'var(--red)' }} />
  );
}

function CopyBtn({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  const copy = () => { navigator.clipboard.writeText(text).catch(() => {}); setDone(true); setTimeout(() => setDone(false), 1500); };
  return (
    <button onClick={copy} className="shrink-0" title="Copy"
      style={{ color: done ? 'var(--accent)' : 'var(--text-3)' }}>
      {done ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  );
}

function MiniBar({ value, max, color }: { value: number; max: number; color: string }) {
  const pct = max > 0 ? Math.max(2, (value / max) * 100) : 2;
  return (
    <div className="h-1.5 flex-1 rounded-full overflow-hidden" style={{ background: 'var(--glass-bg-2)' }}>
      <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
    </div>
  );
}

// ── KPI Card ──────────────────────────────────────────────────────────────────

function KPICard({ label, value, sub, color, icon: Icon }: {
  label: string; value: number | string; sub?: string;
  color: string; icon: React.ElementType;
}) {
  return (
    <div className="g-card p-4 flex items-start gap-3">
      <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
        style={{ background: `color-mix(in srgb, ${color} 15%, transparent)` }}>
        <Icon className="w-4 h-4" style={{ color }} />
      </div>
      <div className="min-w-0">
        <p className="text-[10px] uppercase tracking-wider mb-0.5 font-medium" style={{ color: 'var(--text-3)' }}>{label}</p>
        <p className="text-2xl font-bold leading-none" style={{ color }}>{value}</p>
        {sub && <p className="text-[11px] mt-1" style={{ color: 'var(--text-3)' }}>{sub}</p>}
      </div>
    </div>
  );
}

// ── Trend Sparkline ───────────────────────────────────────────────────────────

function Sparkline({ data, color }: { data: TrendBucket[]; color: string }) {
  const max = useMemo(() => Math.max(...data.map(d => d.hits), 1), [data]);
  if (!data.length) return <div className="text-xs" style={{ color: 'var(--text-3)' }}>No data</div>;
  return (
    <div className="flex items-end gap-px h-12 w-full">
      {data.slice(-48).map((d, i) => (
        <div key={i} className="flex-1 rounded-sm min-w-[2px]"
          title={`${d.hits} @ ${new Date(d.hour).toLocaleTimeString()}`}
          style={{ height: `${Math.max(4, (d.hits / max) * 100)}%`, background: color, opacity: 0.75 }} />
      ))}
    </div>
  );
}

// ── MITRE Heatmap ─────────────────────────────────────────────────────────────

function MITREHeatmap({ coverage, topHits }: {
  coverage: TechCoverage[];
  topHits: Array<{ technique: string; hits: number }>;
}) {
  const byTactic = useMemo(() => {
    const m = new Map<string, TechCoverage[]>();
    for (const t of coverage) {
      if (!m.has(t.tactic)) m.set(t.tactic, []);
      m.get(t.tactic)!.push(t);
    }
    return m;
  }, [coverage]);

  const hitMap = useMemo(() => {
    const m: Record<string, number> = {};
    for (const h of topHits) m[h.technique] = h.hits;
    return m;
  }, [topHits]);

  const maxRules = useMemo(() =>
    Math.max(...coverage.map(t => t.rule_count), 1), [coverage]);

  if (!coverage.length) return (
    <div className="py-8 text-center text-sm" style={{ color: 'var(--text-3)' }}>
      No MITRE coverage data — add Sigma rules with mitre_tactic/mitre_technique fields.
    </div>
  );

  return (
    <div className="space-y-3">
      {MITRE_TACTICS.map(tactic => {
        const techs = byTactic.get(tactic) || [];
        if (!techs.length) return (
          <div key={tactic}>
            <p className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>{tactic}</p>
            <div className="flex gap-1">
              <div className="px-2 py-1 rounded text-[10px]" style={{ background: 'var(--glass-bg)', color: 'var(--text-3)', border: '1px solid var(--border)' }}>
                No coverage
              </div>
            </div>
          </div>
        );
        return (
          <div key={tactic}>
            <p className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-3)' }}>
              {tactic} <span className="font-normal">({techs.length} techniques)</span>
            </p>
            <div className="flex flex-wrap gap-1">
              {techs.map(t => {
                const intensity = t.rule_count / maxRules;
                const hasHits = hitMap[t.technique] > 0;
                return (
                  <div key={t.technique} title={`${t.technique}: ${t.rule_count} rules, ${t.active_count} active${hasHits ? `, ${hitMap[t.technique]} hits` : ''}`}
                    className="px-2 py-1 rounded text-[10px] cursor-default transition-opacity"
                    style={{
                      background: `color-mix(in srgb, var(--accent) ${Math.max(15, intensity * 80)}%, var(--glass-bg))`,
                      border: hasHits ? '1px solid var(--accent)' : '1px solid var(--border)',
                      color: t.active_count > 0 ? 'var(--text-1)' : 'var(--text-3)',
                      opacity: t.active_count > 0 ? 1 : 0.6,
                    }}>
                    {t.technique.split('.')[0]} ({t.rule_count})
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Detection Pipeline ─────────────────────────────────────────────────────────

function PipelineView({ engines }: { engines: Engine[] }) {
  const stages = [
    { label: 'Log Ingest', icon: Database, color: '#60a5fa', desc: 'Syslog · CEF · LEEF · JSON · Beats' },
    { label: 'Parser', icon: Code2, color: '#a78bfa', desc: 'Field extraction · Normalization · Type casting' },
    { label: 'Enrichment', icon: Globe, color: '#34d399', desc: 'GeoIP · Threat intel · Asset context · UEBA' },
    { label: 'Detection Engine', icon: Shield, color: 'var(--accent)', desc: 'Sigma · YARA · IOC · Correlation · ML' },
    { label: 'Correlation', icon: GitBranch, color: '#fbbf24', desc: 'Multi-event · Multi-host · Sequence detection' },
    { label: 'Risk Scoring', icon: BarChart2, color: '#fb923c', desc: 'Severity · Confidence · Entity risk weighting' },
    { label: 'Alert', icon: AlertTriangle, color: 'var(--red)', desc: 'Dedup · Suppression · Priority queue' },
    { label: 'Incident', icon: FileText, color: '#f472b6', desc: 'Auto-correlation · Playbook trigger · SOAR' },
  ];

  return (
    <div className="space-y-4">
      <div className="g-card p-6">
        <p className="text-sm font-semibold mb-6" style={{ color: 'var(--text-1)' }}>Detection Pipeline</p>
        <div className="relative">
          <div className="absolute top-1/2 left-6 right-6 h-0.5 -translate-y-1/2 rounded"
            style={{ background: 'var(--border)' }} />
          <div className="relative flex items-center justify-between">
            {stages.map((s, i) => (
              <div key={i} className="flex flex-col items-center gap-2 z-10">
                <div className="w-10 h-10 rounded-xl flex items-center justify-center shadow-lg"
                  style={{ background: `color-mix(in srgb, ${s.color} 20%, var(--glass-bg))`, border: `1px solid ${s.color}` }}>
                  <s.icon className="w-4 h-4" style={{ color: s.color }} />
                </div>
                <span className="text-[10px] font-medium text-center max-w-[60px] leading-tight"
                  style={{ color: 'var(--text-2)' }}>{s.label}</span>
                <span className="text-[9px] text-center max-w-[70px] leading-tight"
                  style={{ color: 'var(--text-3)' }}>{s.desc}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
        {engines.map(e => (
          <div key={e.name} className="g-card p-4 flex items-start gap-3">
            <StatusDot ok={e.status === 'healthy'} />
            <div className="min-w-0 flex-1">
              <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{e.name}</p>
              <p className="text-[11px] mt-0.5" style={{ color: 'var(--text-3)' }}>
                {e.rules} rules · avg {e.avg_ms}ms
                {e.hits_1h !== undefined && ` · ${e.hits_1h} hits/h`}
              </p>
            </div>
            <span className="text-[10px] capitalize px-2 py-0.5 rounded-full"
              style={{
                background: e.status === 'healthy' ? 'rgba(52,211,153,0.15)' : 'rgba(248,81,73,0.15)',
                color: e.status === 'healthy' ? 'var(--green)' : 'var(--red)',
              }}>
              {e.status}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Correlation Sequence Visualizer ───────────────────────────────────────────

function CorrelationSequence({ rule }: { rule: CorrelationRule }) {
  const steps = rule.sequence?.length ? rule.sequence : [rule.name, '→ Alert'];
  return (
    <div className="flex flex-wrap items-center gap-1">
      {steps.map((s, i) => (
        <div key={i} className="flex items-center gap-1">
          <span className="text-[11px] px-2 py-0.5 rounded"
            style={{ background: 'var(--glass-bg-2)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>
            {s}
          </span>
          {i < steps.length - 1 && (
            <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>↓</span>
          )}
        </div>
      ))}
    </div>
  );
}

// ── AI Assistant Panel ────────────────────────────────────────────────────────

function AIAssistantPanel() {
  const [action,   setAction]   = useState('generate');
  const [content,  setContent]  = useState('');
  const [context,  setContext]  = useState('');
  const [loading,  setLoading]  = useState(false);
  const [result,   setResult]   = useState<AIResult | null>(null);
  const [error,    setError]    = useState<string | null>(null);

  const actions = [
    { id: 'generate',   label: 'Generate Sigma',        icon: Code2,       placeholder: 'Describe the threat behavior you want to detect…' },
    { id: 'explain',    label: 'Explain Rule',          icon: Eye,         placeholder: 'Paste your detection rule here…' },
    { id: 'optimize',   label: 'Optimize Rule',         icon: Settings,    placeholder: 'Paste rule to optimize for fewer false positives…' },
    { id: 'convert',    label: 'Convert Logic',         icon: GitBranch,   placeholder: 'Paste Suricata / Snort / KQL / raw logic to convert…' },
    { id: 'suggest',    label: 'Suggest New Rules',     icon: Plus,        placeholder: 'Describe environment and coverage gaps…' },
    { id: 'redundancy', label: 'Detect Redundant',      icon: Layers,      placeholder: 'Paste multiple rules to check for overlap…' },
  ];

  const currentAction = actions.find(a => a.id === action)!;

  const run = async () => {
    if (!content.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await detectionAPI.aiAssistant(action, content, context);
      const raw = typeof res.data === 'string' ? res.data : JSON.stringify(res.data, null, 2);
      let parsed: Record<string, unknown> | null = null;
      try { parsed = typeof res.data === 'object' ? res.data as Record<string, unknown> : JSON.parse(raw); } catch {}
      setResult({ raw, parsed });
    } catch {
      setError('AI assistant failed. Try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Action selector */}
      <div className="flex flex-wrap gap-2">
        {actions.map(a => (
          <button key={a.id} onClick={() => setAction(a.id)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              action === a.id ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'
            }`}>
            <a.icon className="w-3.5 h-3.5" />
            {a.label}
          </button>
        ))}
      </div>

      {/* Input */}
      <div className="g-card p-4 space-y-3">
        <div>
          <label className="text-xs font-medium mb-1.5 block" style={{ color: 'var(--text-2)' }}>
            {currentAction.label}
          </label>
          <textarea
            value={content}
            onChange={e => setContent(e.target.value)}
            placeholder={currentAction.placeholder}
            className="g-input w-full text-xs font-mono resize-none"
            rows={8}
          />
        </div>
        {['suggest', 'optimize'].includes(action) && (
          <div>
            <label className="text-xs font-medium mb-1.5 block" style={{ color: 'var(--text-2)' }}>
              Additional context (optional)
            </label>
            <textarea
              value={context}
              onChange={e => setContext(e.target.value)}
              placeholder="Environment details, platform, existing coverage…"
              className="g-input w-full text-xs resize-none"
              rows={3}
            />
          </div>
        )}
        <button onClick={run} disabled={loading || !content.trim()} className="g-btn g-btn-primary text-xs">
          <Brain className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          {loading ? 'Running AI…' : 'Run AI'}
        </button>
      </div>

      {error && (
        <div className="g-card p-3 text-xs" style={{ color: 'var(--red)', border: '1px solid rgba(248,81,73,0.3)' }}>
          {error}
        </div>
      )}

      {result && (
        <div className="g-card p-4 space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>AI Output</p>
            <CopyBtn text={result.raw} />
          </div>

          {result.parsed && typeof result.parsed === 'object' && (
            <div className="space-y-2">
              {Object.entries(result.parsed).map(([key, val]) => {
                if (key === 'optimized_rule' || key === 'rule') return (
                  <div key={key}>
                    <p className="text-[10px] uppercase tracking-wider mb-1 font-semibold" style={{ color: 'var(--text-3)' }}>{key}</p>
                    <pre className="text-[11px] p-3 rounded-lg overflow-x-auto leading-relaxed"
                      style={{ background: 'var(--bg-0)', color: 'var(--text-1)', border: '1px solid var(--border)' }}>
                      {String(val)}
                    </pre>
                  </div>
                );
                if (Array.isArray(val)) return (
                  <div key={key}>
                    <p className="text-[10px] uppercase tracking-wider mb-1 font-semibold" style={{ color: 'var(--text-3)' }}>{key}</p>
                    <ul className="space-y-1">
                      {(val as string[]).map((item, i) => (
                        <li key={i} className="text-xs flex items-start gap-1.5">
                          <span className="mt-0.5 w-1.5 h-1.5 rounded-full shrink-0" style={{ background: 'var(--accent)' }} />
                          <span style={{ color: 'var(--text-2)' }}>{typeof item === 'object' ? JSON.stringify(item) : String(item)}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                );
                return (
                  <div key={key}>
                    <p className="text-[10px] uppercase tracking-wider mb-0.5 font-semibold" style={{ color: 'var(--text-3)' }}>{key}</p>
                    <p className="text-xs" style={{ color: 'var(--text-2)' }}>{String(val)}</p>
                  </div>
                );
              })}
            </div>
          )}

          {(!result.parsed || action === 'generate' || action === 'convert') && (
            <pre className="text-[11px] p-3 rounded-lg overflow-x-auto leading-relaxed"
              style={{ background: 'var(--bg-0)', color: 'var(--text-1)', border: '1px solid var(--border)' }}>
              {result.raw}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

// ── Testing Panel ─────────────────────────────────────────────────────────────

function TestingPanel({ sigmaRules }: { sigmaRules: SigmaRule[] }) {
  const [selectedRule, setSelectedRule] = useState<number>(0);
  const [ruleType, setRuleType]         = useState('sigma');
  const [hours, setHours]               = useState(24);
  const [loading, setLoading]           = useState(false);
  const [result, setResult]             = useState<SimResult | null>(null);

  const run = async () => {
    if (!selectedRule) return;
    setLoading(true);
    try {
      const res = await detectionAPI.simulate(ruleType, selectedRule, hours);
      setResult(res.data as SimResult);
    } catch {
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  const maxCount = useMemo(() =>
    Math.max(...(result?.hourly_trend.map(h => h.count) ?? []), 1),
  [result]);

  return (
    <div className="space-y-4">
      <div className="g-card p-4 space-y-3">
        <p className="text-xs font-semibold" style={{ color: 'var(--text-1)' }}>Rule Simulation</p>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div>
            <label className="text-[10px] uppercase tracking-wider mb-1 block font-semibold" style={{ color: 'var(--text-3)' }}>Rule Type</label>
            <select value={ruleType} onChange={e => setRuleType(e.target.value)} className="g-select text-xs w-full">
              <option value="sigma">Sigma</option>
              <option value="yara">YARA</option>
              <option value="correlation">Correlation</option>
            </select>
          </div>
          <div>
            <label className="text-[10px] uppercase tracking-wider mb-1 block font-semibold" style={{ color: 'var(--text-3)' }}>
              {ruleType === 'sigma' ? 'Sigma Rule' : 'Rule ID'}
            </label>
            {ruleType === 'sigma' ? (
              <select value={selectedRule} onChange={e => setSelectedRule(Number(e.target.value))} className="g-select text-xs w-full">
                <option value={0}>Select rule…</option>
                {sigmaRules.map(r => <option key={r.id} value={r.id}>{r.title}</option>)}
              </select>
            ) : (
              <input type="number" value={selectedRule || ''} onChange={e => setSelectedRule(Number(e.target.value))}
                placeholder="Rule ID" className="g-input text-xs w-full" />
            )}
          </div>
          <div>
            <label className="text-[10px] uppercase tracking-wider mb-1 block font-semibold" style={{ color: 'var(--text-3)' }}>Time Window</label>
            <select value={hours} onChange={e => setHours(Number(e.target.value))} className="g-select text-xs w-full">
              {[1, 6, 12, 24, 48, 168].map(h => <option key={h} value={h}>{h < 24 ? `${h}h` : h === 168 ? '7d' : '24h'}</option>)}
            </select>
          </div>
        </div>
        <button onClick={run} disabled={loading || !selectedRule} className="g-btn g-btn-primary text-xs">
          <Play className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          {loading ? 'Simulating…' : 'Run Simulation'}
        </button>
      </div>

      {result && (
        <div className="g-card p-4 space-y-4">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: 'Estimated Matches', val: result.estimated_matches, color: 'var(--accent)' },
              { label: 'Window Hours', val: result.window_hours, color: 'var(--text-2)' },
              { label: 'Rule Type', val: result.rule_type, color: 'var(--text-2)' },
              { label: 'Last Match', val: result.last_match ? timeAgo(result.last_match) : 'Never', color: result.last_match ? '#fbbf24' : 'var(--text-3)' },
            ].map(s => (
              <div key={s.label} className="g-card p-3">
                <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>{s.label}</p>
                <p className="text-lg font-bold" style={{ color: s.color }}>{s.val}</p>
              </div>
            ))}
          </div>
          {result.hourly_trend.length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-wider mb-2 font-semibold" style={{ color: 'var(--text-3)' }}>Hourly Trend</p>
              <div className="flex items-end gap-px h-16">
                {result.hourly_trend.map((h, i) => (
                  <div key={i} className="flex-1 rounded-sm min-w-[2px]"
                    title={`${h.count} @ ${new Date(h.hour).toLocaleString()}`}
                    style={{
                      height: `${Math.max(4, (h.count / maxCount) * 100)}%`,
                      background: 'var(--accent)',
                      opacity: 0.8,
                    }} />
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Rules Table ───────────────────────────────────────────────────────────────

function SigmaRulesTable({ rules, onToggle, onDelete }: {
  rules: SigmaRule[];
  onToggle: (id: number, enabled: boolean) => void;
  onDelete: (id: number) => void;
}) {
  const [search, setSearch] = useState('');
  const [sevF, setSevF]     = useState('');
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  const filtered = useMemo(() => rules.filter(r => {
    if (sevF && r.severity !== sevF) return false;
    if (!search) return true;
    const q = search.toLowerCase();
    return r.title.toLowerCase().includes(q) || r.mitre_technique.toLowerCase().includes(q) || r.mitre_tactic.toLowerCase().includes(q);
  }), [rules, search, sevF]);

  const toggle = (id: number) => setExpanded(p => { const s = new Set(p); s.has(id) ? s.delete(id) : s.add(id); return s; });

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-40">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--text-3)' }} />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search rules…"
            className="g-input pl-8 py-1.5 text-xs w-full" />
        </div>
        <select value={sevF} onChange={e => setSevF(e.target.value)} className="g-select text-xs py-1">
          <option value="">All severities</option>
          {['critical','high','medium','low','informational'].map(s => (
            <option key={s} value={s} className="capitalize">{s}</option>
          ))}
        </select>
        <span className="text-xs ml-auto" style={{ color: 'var(--text-3)' }}>{filtered.length} rules</span>
      </div>

      <div className="g-card overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
              {['Rule','Severity','MITRE','Hits','Status','Actions',''].map(h => (
                <th key={h} className="px-3 py-2.5 text-left font-semibold" style={{ color: 'var(--text-3)' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map(r => {
              const exp = expanded.has(r.id);
              return (
                <>
                  <tr key={r.id}
                    className="cursor-pointer transition-colors"
                    style={{ borderBottom: '1px solid var(--border)' }}
                    onClick={() => toggle(r.id)}>
                    <td className="px-3 py-3 max-w-[200px]">
                      <p className="font-medium truncate" style={{ color: 'var(--text-1)' }} title={r.title}>{r.title}</p>
                    </td>
                    <td className="px-3 py-3">{sevBadge(r.severity)}</td>
                    <td className="px-3 py-3">
                      {r.mitre_technique ? (
                        <span className="text-[11px] font-mono" style={{ color: 'var(--accent)' }}>{r.mitre_technique}</span>
                      ) : <span style={{ color: 'var(--text-3)' }}>—</span>}
                    </td>
                    <td className="px-3 py-3">
                      <span className="font-bold" style={{ color: r.hit_count ? '#fbbf24' : 'var(--text-3)' }}>
                        {r.hit_count ?? 0}
                      </span>
                    </td>
                    <td className="px-3 py-3">
                      <div className="flex items-center gap-1.5">
                        <StatusDot ok={r.enabled} />
                        <span style={{ color: r.enabled ? 'var(--green)' : 'var(--text-3)' }}>{r.enabled ? 'Enabled' : 'Disabled'}</span>
                      </div>
                    </td>
                    <td className="px-3 py-3">
                      <div className="flex items-center gap-1" onClick={e => e.stopPropagation()}>
                        <button onClick={() => onToggle(r.id, r.enabled)}
                          className="g-btn g-btn-ghost text-[10px]" style={{ padding: '2px 6px' }}
                          title={r.enabled ? 'Disable' : 'Enable'}>
                          {r.enabled
                            ? <ToggleRight className="w-3.5 h-3.5" style={{ color: 'var(--green)' }} />
                            : <ToggleLeft className="w-3.5 h-3.5" style={{ color: 'var(--text-3)' }} />}
                        </button>
                        <button onClick={() => onDelete(r.id)}
                          className="g-btn g-btn-ghost text-[10px]" style={{ padding: '2px 6px' }}
                          title="Delete">
                          <Trash2 className="w-3.5 h-3.5" style={{ color: 'var(--red)' }} />
                        </button>
                      </div>
                    </td>
                    <td className="px-3 py-3" style={{ color: 'var(--text-3)' }}>
                      {exp ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                    </td>
                  </tr>
                  {exp && (
                    <tr key={`${r.id}-detail`}>
                      <td colSpan={7} className="p-0">
                        <div className="px-4 py-4 space-y-2"
                          style={{ background: 'var(--glass-bg)', borderBottom: '1px solid var(--border)' }}>
                          {r.description && (
                            <p className="text-xs" style={{ color: 'var(--text-2)' }}>{r.description}</p>
                          )}
                          <div className="flex flex-wrap gap-2 text-[11px]">
                            {r.mitre_tactic && (
                              <span className="px-2 py-0.5 rounded"
                                style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)', border: '1px solid var(--border)' }}>
                                Tactic: {r.mitre_tactic}
                              </span>
                            )}
                            {r.logsource_cat && (
                              <span className="px-2 py-0.5 rounded"
                                style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)', border: '1px solid var(--border)' }}>
                                Category: {r.logsource_cat}
                              </span>
                            )}
                            {r.logsource_prod && (
                              <span className="px-2 py-0.5 rounded"
                                style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)', border: '1px solid var(--border)' }}>
                                Product: {r.logsource_prod}
                              </span>
                            )}
                            {r.last_matched_at && (
                              <span className="px-2 py-0.5 rounded"
                                style={{ background: 'var(--glass-bg-2)', color: 'var(--text-3)', border: '1px solid var(--border)' }}>
                                Last hit: {timeAgo(r.last_matched_at)}
                              </span>
                            )}
                          </div>
                          {r.tags && r.tags.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-1">
                              {r.tags.map(t => (
                                <span key={t} className="text-[10px] px-1.5 py-0.5 rounded"
                                  style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid var(--accent-border)' }}>
                                  {t}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              );
            })}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="py-12 text-center text-sm" style={{ color: 'var(--text-3)' }}>No rules match filters</div>
        )}
      </div>
    </div>
  );
}

// ── Library Panel ─────────────────────────────────────────────────────────────

const LIBRARY_CATEGORIES = [
  { id: 'endpoint',   label: 'Endpoint',   items: ['Malware','Ransomware','Persistence','LOLBins','PowerShell Abuse','Credential Dumping','Process Injection'] },
  { id: 'network',    label: 'Network',    items: ['Port Scanning','Beaconing','DNS Tunneling','C2','Lateral Movement','Data Exfiltration'] },
  { id: 'identity',   label: 'Identity',   items: ['Impossible Travel','Password Spraying','Privilege Escalation','MFA Bypass','Suspicious Login'] },
  { id: 'cloud',      label: 'Cloud',      items: ['Public Storage','IAM Abuse','Security Group Changes','Secret Exposure'] },
  { id: 'email',      label: 'Email',      items: ['Phishing','BEC','Malicious Attachments','Suspicious Links'] },
];

function LibraryPanel() {
  const [expanded, setExpanded] = useState<string | null>('endpoint');
  const toggle = (id: string) => setExpanded(p => p === id ? null : id);
  return (
    <div className="space-y-2">
      {LIBRARY_CATEGORIES.map(cat => (
        <div key={cat.id} className="g-card overflow-hidden">
          <button className="w-full px-4 py-3 flex items-center justify-between text-left"
            onClick={() => toggle(cat.id)}>
            <span className="text-sm font-medium" style={{ color: 'var(--text-1)' }}>{cat.label}</span>
            <div className="flex items-center gap-2">
              <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>{cat.items.length} categories</span>
              {expanded === cat.id ? <ChevronUp className="w-4 h-4" style={{ color: 'var(--text-3)' }} />
                                   : <ChevronDown className="w-4 h-4" style={{ color: 'var(--text-3)' }} />}
            </div>
          </button>
          {expanded === cat.id && (
            <div className="px-4 pb-4 grid grid-cols-2 sm:grid-cols-3 gap-2"
              style={{ borderTop: '1px solid var(--border)' }}>
              {cat.items.map(item => (
                <div key={item} className="flex items-center gap-2 p-2.5 rounded-lg cursor-pointer transition-colors"
                  style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}>
                  <Shield className="w-3.5 h-3.5 shrink-0" style={{ color: 'var(--accent)' }} />
                  <span className="text-xs" style={{ color: 'var(--text-2)' }}>{item}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function ThreatDetectionPage() {
  const [tab, setTab] = useState<ViewTab>('overview');
  const [hours, setHours] = useState(24);

  // Loaded flags to prevent re-fetching
  const loaded = useRef<Partial<Record<ViewTab, boolean>>>({});

  const [overview,    setOverview]    = useState<Overview | null>(null);
  const [trends,      setTrends]      = useState<Trends | null>(null);
  const [coverage,    setCoverage]    = useState<CoverageData | null>(null);
  const [analytics,   setAnalytics]   = useState<Analytics | null>(null);
  const [performance, setPerformance] = useState<Performance | null>(null);
  const [sigmaRules,  setSigmaRules]  = useState<SigmaRule[]>([]);
  const [yaraRules,   setYaraRules]   = useState<{ id: number; name: string; enabled: boolean }[]>([]);
  const [corrRules,   setCorrRules]   = useState<CorrelationRule[]>([]);
  const [iocs,        setIOCs]        = useState<IOC[]>([]);
  const [anomalies,   setAnomalies]   = useState<AnomalyFinding[]>([]);
  const [loadingTab,  setLoadingTab]  = useState(false);

  const [toast, setToast] = useState<string | null>(null);
  const notify = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 3000); };

  const loadTab = useCallback(async (t: ViewTab, force = false) => {
    if (loaded.current[t] && !force) return;
    loaded.current[t] = true;
    setLoadingTab(true);
    try {
      switch (t) {
        case 'overview':
          const [ovRes, trRes] = await Promise.all([
            detectionAPI.getOverview(hours),
            detectionAPI.getTrends(hours),
          ]);
          if (ovRes.data) setOverview(ovRes.data as Overview);
          if (trRes.data) setTrends(trRes.data as Trends);
          break;
        case 'rules':
          const srRes = await sigmaAPI.getAll();
          setSigmaRules((Array.isArray(srRes.data) ? srRes.data : []) as SigmaRule[]);
          break;
        case 'coverage':
          const cvRes = await detectionAPI.getCoverage();
          if (cvRes.data) setCoverage(cvRes.data as CoverageData);
          break;
        case 'correlation':
          const crRes = await correlationAPI.getAll();
          setCorrRules((crRes.data || []) as CorrelationRule[]);
          break;
        case 'behavioral':
          const anRes = await threatAPI.findings().catch(() => ({ data: [] }));
          setAnomalies((anRes.data || []) as AnomalyFinding[]);
          break;
        case 'ioc':
          const iocRes = await iocsAPI.getAll();
          setIOCs((iocRes.data || []) as IOC[]);
          break;
        case 'analytics':
          const anlyRes = await detectionAPI.getAnalytics();
          if (anlyRes.data) setAnalytics(anlyRes.data as Analytics);
          break;
        case 'performance':
          const perfRes = await detectionAPI.getPerformance();
          if (perfRes.data) setPerformance(perfRes.data as Performance);
          break;
        case 'pipeline':
          if (!performance) {
            const pRes = await detectionAPI.getPerformance();
            if (pRes.data) setPerformance(pRes.data as Performance);
          }
          break;
        case 'testing':
          if (!sigmaRules.length) {
            const sRes = await sigmaAPI.getAll();
            setSigmaRules((Array.isArray(sRes.data) ? sRes.data : []) as SigmaRule[]);
          }
          break;
        default:
          break;
      }
    } finally {
      setLoadingTab(false);
    }
  }, [hours, performance, sigmaRules.length]);

  useEffect(() => {
    loaded.current = {};
    loadTab(tab);
  }, [tab, hours]);

  // Sigma rule actions
  const toggleSigma = async (id: number, currentEnabled: boolean) => {
    try {
      if (currentEnabled) await sigmaAPI.disable(id);
      else await sigmaAPI.enable(id);
      setSigmaRules(rs => rs.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
      notify(currentEnabled ? 'Rule disabled' : 'Rule enabled');
    } catch { notify('Failed to toggle rule'); }
  };

  const deleteSigma = async (id: number) => {
    try {
      await sigmaAPI.delete(id);
      setSigmaRules(rs => rs.filter(r => r.id !== id));
      notify('Rule deleted');
    } catch { notify('Failed to delete rule'); }
  };

  const toggleCorrelation = async (id: number, enabled: boolean) => {
    try {
      await correlationAPI.toggle(id, !enabled);
      setCorrRules(rs => rs.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
      notify(!enabled ? 'Rule enabled' : 'Rule disabled');
    } catch { notify('Failed to toggle rule'); }
  };

  // Derived
  const openAnomalies = useMemo(() => anomalies.filter(a => !a.acknowledged), [anomalies]);

  const maxRuleHit = useMemo(() =>
    Math.max(...(analytics?.rules.map(r => r.hit_count) ?? []), 1),
  [analytics]);

  return (
    <RootLayout
      title="Threat Detection"
      subtitle="Detection Engineering · Rule Management · Coverage Analytics"
      actions={
        <div className="flex items-center gap-2">
          <select value={hours} onChange={e => { setHours(Number(e.target.value)); loaded.current = {}; }}
            className="g-select text-xs py-1">
            {[6, 12, 24, 48, 168].map(h => (
              <option key={h} value={h}>{h < 24 ? `${h}h` : h === 168 ? '7d' : '24h'}</option>
            ))}
          </select>
          <button onClick={() => { loaded.current = {}; loadTab(tab, true); }}
            className="g-btn g-btn-ghost text-xs">
            <RefreshCw className={`w-3.5 h-3.5 ${loadingTab ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      }>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 g-card px-4 py-2.5 text-sm shadow-lg"
          style={{ color: 'var(--text-1)' }}>{toast}</div>
      )}

      {/* Tab bar */}
      <div className="flex gap-0.5 mb-4 overflow-x-auto pb-1">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors ${
              tab === t.id ? 'g-btn g-btn-primary' : 'g-btn g-btn-ghost'
            }`}>
            <t.icon className="w-3.5 h-3.5" />
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Overview ── */}
      {tab === 'overview' && (
        <div className="space-y-4">
          {overview ? (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <KPICard label="Total Rules"        value={overview.total_rules}         color="var(--accent)"   icon={Shield} />
                <KPICard label="Active Rules"       value={overview.active_rules}        color="var(--green)"    icon={CheckCircle2} />
                <KPICard label="Triggered (24h)"   value={overview.triggered_last_24h}  color="#fbbf24"         icon={Zap} />
                <KPICard label="Alerts Fired"       value={overview.total_alerts_24h}    color="var(--red)"      icon={AlertTriangle} />
                <KPICard label="MITRE Techniques"   value={overview.mitre_covered}       color="#a78bfa"         icon={Target} sub="techniques covered" />
                <KPICard label="FP Rate (proxy)"    value={`${overview.fp_rate}%`}       color="#fb923c"         icon={Activity} />
                <KPICard label="Suppression Rules"  value={overview.suppression_rules}   color="var(--text-3)"   icon={Lock} />
                <KPICard label="Engine Health"      value={overview.engine_health}       color="var(--green)"    icon={Cpu} />
              </div>

              {/* Rule type breakdown */}
              <div className="g-card p-4">
                <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Detection Rule Breakdown</p>
                <div className="space-y-3">
                  {overview.rule_breakdown.map(rb => {
                    const pct = rb.total > 0 ? (rb.active / rb.total) * 100 : 0;
                    return (
                      <div key={rb.type} className="flex items-center gap-3">
                        <span className="text-xs font-medium w-24 shrink-0" style={{ color: 'var(--text-2)' }}>{rb.type}</span>
                        <MiniBar value={rb.active} max={rb.total} color="var(--accent)" />
                        <span className="text-[11px] tabular-nums w-24 shrink-0" style={{ color: 'var(--text-3)' }}>
                          {rb.active}/{rb.total} active
                        </span>
                        <span className="text-[11px] tabular-nums w-16 shrink-0" style={{ color: rb.triggered > 0 ? '#fbbf24' : 'var(--text-3)' }}>
                          {rb.triggered} hits
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Trends */}
              {trends && (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                  {[
                    { label: 'Sigma Hits',   data: trends.sigma,  color: 'var(--accent)' },
                    { label: 'YARA Matches', data: trends.yara,   color: '#a78bfa' },
                    { label: 'Alerts',       data: trends.alerts, color: 'var(--red)' },
                  ].map(({ label, data, color }) => (
                    <div key={label} className="g-card p-4">
                      <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-2)' }}>{label}</p>
                      <Sparkline data={data} color={color} />
                      <div className="flex justify-between mt-1">
                        <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                          {data[0] ? new Date(data[0].hour).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit' }) : ''}
                        </span>
                        <span className="text-[10px] font-medium" style={{ color }}>
                          Total: {data.reduce((a, b) => a + b.hits, 0)}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </>
          ) : (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading overview…</div>
          )}
        </div>
      )}

      {/* ── Rules ── */}
      {tab === 'rules' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-xs" style={{ color: 'var(--text-3)' }}>
              {sigmaRules.length} Sigma rules · {sigmaRules.filter(r => r.enabled).length} active
            </p>
            <div className="flex gap-2">
              <button className="g-btn g-btn-ghost text-xs">
                <Upload className="w-3.5 h-3.5" /> Import
              </button>
              <button className="g-btn g-btn-primary text-xs">
                <Plus className="w-3.5 h-3.5" /> New Rule
              </button>
            </div>
          </div>
          <SigmaRulesTable rules={sigmaRules} onToggle={toggleSigma} onDelete={deleteSigma} />
        </div>
      )}

      {/* ── Coverage ── */}
      {tab === 'coverage' && (
        <div className="space-y-4">
          {coverage ? (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="g-card p-4">
                  <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>Tactics Covered</p>
                  <p className="text-2xl font-bold" style={{ color: 'var(--accent)' }}>{coverage.tactics.length}</p>
                </div>
                <div className="g-card p-4">
                  <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>Techniques Covered</p>
                  <p className="text-2xl font-bold" style={{ color: '#a78bfa' }}>{coverage.techniques.length}</p>
                </div>
                <div className="g-card p-4">
                  <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>Top Hit Technique</p>
                  <p className="text-sm font-bold" style={{ color: '#fbbf24' }}>{coverage.top_hits[0]?.technique ?? '—'}</p>
                </div>
                <div className="g-card p-4">
                  <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>Uncovered Tactics</p>
                  <p className="text-2xl font-bold" style={{ color: 'var(--red)' }}>
                    {MITRE_TACTICS.length - coverage.tactics.length}
                  </p>
                </div>
              </div>

              <div className="g-card p-4">
                <p className="text-xs font-semibold mb-4" style={{ color: 'var(--text-1)' }}>
                  MITRE ATT&CK Coverage Heatmap
                  <span className="ml-2 text-[10px] font-normal" style={{ color: 'var(--text-3)' }}>
                    Color intensity = rule count · Blue border = recently triggered
                  </span>
                </p>
                <MITREHeatmap coverage={coverage.techniques} topHits={coverage.top_hits} />
              </div>
            </>
          ) : (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading coverage…</div>
          )}
        </div>
      )}

      {/* ── Correlation ── */}
      {tab === 'correlation' && (
        <div className="space-y-4">
          <div className="g-card p-4 space-y-2">
            <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>
              Correlation Rules — Multi-event · Sequence Detection
            </p>
            <div className="text-xs mb-4 p-3 rounded-lg" style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}>
              <p className="font-semibold mb-2" style={{ color: 'var(--text-2)' }}>Example: VPN Lateral Movement Chain</p>
              <div className="flex flex-wrap gap-1 items-center">
                {['VPN Login','PowerShell Exec','LSASS Access','RDP Lateral','SMB Spread','→ Incident'].map((s, i, arr) => (
                  <div key={s} className="flex items-center gap-1">
                    <span className="text-[11px] px-2 py-0.5 rounded" style={{
                      background: i === arr.length - 1 ? 'rgba(248,81,73,0.15)' : 'var(--glass-bg)',
                      color: i === arr.length - 1 ? 'var(--red)' : 'var(--text-2)',
                      border: `1px solid ${i === arr.length - 1 ? 'rgba(248,81,73,0.3)' : 'var(--border)'}`,
                    }}>
                      {s}
                    </span>
                    {i < arr.length - 1 && <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>↓</span>}
                  </div>
                ))}
              </div>
            </div>

            {corrRules.length === 0 ? (
              <div className="py-8 text-center text-sm" style={{ color: 'var(--text-3)' }}>
                No correlation rules configured.
              </div>
            ) : (
              <div className="space-y-2">
                {corrRules.map(r => (
                  <div key={r.id} className="p-3 rounded-lg" style={{ background: 'var(--glass-bg-2)', border: '1px solid var(--border)' }}>
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <div>
                        <span className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{r.name}</span>
                        {r.description && (
                          <p className="text-[11px] mt-0.5" style={{ color: 'var(--text-3)' }}>{r.description}</p>
                        )}
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {sevBadge(r.severity)}
                        <button onClick={() => toggleCorrelation(r.id, r.enabled)}
                          className="g-btn g-btn-ghost text-[10px]" style={{ padding: '2px 6px' }}>
                          {r.enabled
                            ? <ToggleRight className="w-4 h-4" style={{ color: 'var(--green)' }} />
                            : <ToggleLeft className="w-4 h-4" style={{ color: 'var(--text-3)' }} />}
                        </button>
                      </div>
                    </div>
                    {r.sequence && r.sequence.length > 0 && <CorrelationSequence rule={r} />}
                    {r.window_seconds && (
                      <p className="text-[10px] mt-2" style={{ color: 'var(--text-3)' }}>
                        Window: {r.window_seconds}s · Matches: {r.match_count ?? 0}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Behavioral ── */}
      {tab === 'behavioral' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: 'Open Findings', val: openAnomalies.length, color: 'var(--red)' },
              { label: 'Total Findings', val: anomalies.length, color: 'var(--text-2)' },
              { label: 'Acknowledged', val: anomalies.length - openAnomalies.length, color: 'var(--green)' },
              { label: 'High Severity', val: openAnomalies.filter(a => a.severity === 'high' || a.severity === 'critical').length, color: '#fb923c' },
            ].map(s => (
              <div key={s.label} className="g-card p-4">
                <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>{s.label}</p>
                <p className="text-2xl font-bold" style={{ color: s.color }}>{s.val}</p>
              </div>
            ))}
          </div>

          <div className="g-card overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
                  {['Type','Score','Severity','Description','Detected','Status'].map(h => (
                    <th key={h} className="px-4 py-2.5 text-left font-semibold" style={{ color: 'var(--text-3)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {anomalies.slice(0, 50).map(a => (
                  <tr key={a.id} style={{ borderBottom: '1px solid var(--border)', opacity: a.acknowledged ? 0.5 : 1 }}>
                    <td className="px-4 py-3">
                      <span className="font-mono text-[11px]" style={{ color: 'var(--text-2)' }}>{a.finding_type}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-bold text-sm" style={{ color: a.score >= 80 ? 'var(--red)' : a.score >= 60 ? '#fb923c' : 'var(--accent)' }}>
                        {a.score}
                      </span>
                    </td>
                    <td className="px-4 py-3">{sevBadge(a.severity)}</td>
                    <td className="px-4 py-3 max-w-[260px]">
                      <p className="truncate" style={{ color: 'var(--text-1)' }}>{a.description}</p>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>
                      {timeAgo(a.created_at)}
                    </td>
                    <td className="px-4 py-3">
                      {a.acknowledged
                        ? <span style={{ color: 'var(--green)' }} className="flex items-center gap-1"><CheckCircle2 className="w-3.5 h-3.5" />Acked</span>
                        : <span style={{ color: '#fbbf24' }}>Open</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {anomalies.length === 0 && (
              <div className="py-12 text-center text-sm" style={{ color: 'var(--text-3)' }}>
                No behavioral findings
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── IOC Matching ── */}
      {tab === 'ioc' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: 'Total IOCs',  val: iocs.length,                                    color: 'var(--text-2)' },
              { label: 'Active',      val: iocs.filter(i => i.enabled).length,              color: 'var(--green)' },
              { label: 'IPs',         val: iocs.filter(i => i.type === 'ip').length,        color: 'var(--accent)' },
              { label: 'Domains',     val: iocs.filter(i => i.type === 'domain').length,    color: '#a78bfa' },
            ].map(s => (
              <div key={s.label} className="g-card p-4">
                <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>{s.label}</p>
                <p className="text-2xl font-bold" style={{ color: s.color }}>{s.val}</p>
              </div>
            ))}
          </div>

          <div className="g-card overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
                  {['Type','Value','Severity','Description','Status','Added'].map(h => (
                    <th key={h} className="px-4 py-2.5 text-left font-semibold" style={{ color: 'var(--text-3)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {iocs.slice(0, 100).map(ioc => (
                  <tr key={ioc.id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td className="px-4 py-3">
                      <span className="text-[10px] px-1.5 py-0.5 rounded uppercase font-bold"
                        style={{ background: 'var(--glass-bg-2)', color: 'var(--accent)', border: '1px solid var(--border)' }}>
                        {ioc.type}
                      </span>
                    </td>
                    <td className="px-4 py-3 max-w-[200px]">
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono text-[11px] truncate" style={{ color: 'var(--text-1)' }}>{ioc.value}</span>
                        <CopyBtn text={ioc.value} />
                      </div>
                    </td>
                    <td className="px-4 py-3">{sevBadge(ioc.severity)}</td>
                    <td className="px-4 py-3 max-w-[220px]">
                      <p className="truncate text-[11px]" style={{ color: 'var(--text-2)' }}>{ioc.description}</p>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <StatusDot ok={ioc.enabled} />
                        <span style={{ color: ioc.enabled ? 'var(--green)' : 'var(--text-3)' }}>{ioc.enabled ? 'Active' : 'Inactive'}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>
                      {timeAgo(ioc.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {iocs.length === 0 && (
              <div className="py-12 text-center text-sm" style={{ color: 'var(--text-3)' }}>No IOCs configured</div>
            )}
          </div>
        </div>
      )}

      {/* ── Analytics ── */}
      {tab === 'analytics' && (
        <div className="space-y-4">
          {analytics ? (
            <>
              {analytics.severity_distribution.length > 0 && (
                <div className="g-card p-4">
                  <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-1)' }}>Trigger Distribution by Severity</p>
                  <div className="space-y-2">
                    {analytics.severity_distribution.map(s => {
                      const maxHits = Math.max(...analytics.severity_distribution.map(x => x.total_hits), 1);
                      return (
                        <div key={s.severity} className="flex items-center gap-3">
                          <span className="w-20 shrink-0">{sevBadge(s.severity)}</span>
                          <MiniBar value={s.total_hits} max={maxHits} color={SEV_COLOR[s.severity] ?? 'var(--text-3)'} />
                          <span className="text-[11px] tabular-nums w-24 shrink-0" style={{ color: 'var(--text-3)' }}>
                            {s.total_hits} hits · {s.triggered_rules} rules
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              <div className="g-card overflow-hidden">
                <p className="px-4 pt-4 pb-2 text-xs font-semibold" style={{ color: 'var(--text-1)' }}>
                  Per-Rule Trigger Analytics
                </p>
                <table className="w-full text-xs">
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--glass-bg)' }}>
                      {['Rule','Severity','MITRE','Hits','Hit Rate','Last Triggered','Status'].map(h => (
                        <th key={h} className="px-4 py-2.5 text-left font-semibold" style={{ color: 'var(--text-3)' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {analytics.rules.map(r => (
                      <tr key={r.id} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td className="px-4 py-3 max-w-[200px]">
                          <p className="font-medium truncate" style={{ color: 'var(--text-1)' }}>{r.title}</p>
                        </td>
                        <td className="px-4 py-3">{sevBadge(r.severity)}</td>
                        <td className="px-4 py-3">
                          <span className="font-mono text-[11px]" style={{ color: 'var(--accent)' }}>{r.mitre_technique || '—'}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="font-bold" style={{ color: r.hit_count > 0 ? '#fbbf24' : 'var(--text-3)' }}>
                            {r.hit_count}
                          </span>
                        </td>
                        <td className="px-4 py-3 min-w-[80px]">
                          <div className="flex items-center gap-2">
                            <MiniBar value={r.hit_count} max={maxRuleHit} color="var(--accent)" />
                          </div>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>
                          {r.last_triggered ? timeAgo(r.last_triggered) : '—'}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1.5">
                            <StatusDot ok={r.enabled} />
                            <span style={{ color: r.enabled ? 'var(--green)' : 'var(--text-3)' }}>{r.enabled ? 'On' : 'Off'}</span>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading analytics…</div>
          )}
        </div>
      )}

      {/* ── Performance ── */}
      {tab === 'performance' && (
        <div className="space-y-4">
          {performance ? (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                {[
                  { label: 'Active Rules',    val: performance.total_active,    color: 'var(--accent)' },
                  { label: 'Hits / Hour',     val: performance.hits_last_hour,  color: '#fbbf24' },
                  { label: 'Failed Rules',    val: performance.failed_rules,    color: performance.failed_rules > 0 ? 'var(--red)' : 'var(--green)' },
                  { label: 'Queue Depth',     val: performance.queue_depth,     color: 'var(--text-2)' },
                  { label: 'Engine Count',    val: performance.engines.length,  color: 'var(--accent)' },
                  { label: 'Uptime',          val: `${performance.uptime_pct}%`, color: 'var(--green)' },
                ].map(s => (
                  <div key={s.label} className="g-card p-4">
                    <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-3)' }}>{s.label}</p>
                    <p className="text-xl font-bold" style={{ color: s.color }}>{s.val}</p>
                  </div>
                ))}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {performance.engines.map(e => (
                  <div key={e.name} className="g-card p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{e.name}</span>
                      <span className="text-[10px] px-2 py-0.5 rounded-full capitalize"
                        style={{
                          background: e.status === 'healthy' ? 'rgba(52,211,153,0.15)' : 'rgba(248,81,73,0.15)',
                          color: e.status === 'healthy' ? 'var(--green)' : 'var(--red)',
                        }}>
                        {e.status}
                      </span>
                    </div>
                    <div className="space-y-1.5 text-[11px]">
                      <div className="flex justify-between">
                        <span style={{ color: 'var(--text-3)' }}>Rules</span>
                        <span className="font-medium" style={{ color: 'var(--text-2)' }}>{e.rules}</span>
                      </div>
                      <div className="flex justify-between">
                        <span style={{ color: 'var(--text-3)' }}>Avg Latency</span>
                        <span className="font-medium" style={{ color: e.avg_ms < 10 ? 'var(--green)' : e.avg_ms < 50 ? '#fbbf24' : 'var(--red)' }}>
                          {e.avg_ms}ms
                        </span>
                      </div>
                      {e.hits_1h !== undefined && (
                        <div className="flex justify-between">
                          <span style={{ color: 'var(--text-3)' }}>Hits/Hour</span>
                          <span className="font-medium" style={{ color: 'var(--text-2)' }}>{e.hits_1h}</span>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading performance…</div>
          )}
        </div>
      )}

      {/* ── Testing ── */}
      {tab === 'testing' && (
        <div className="space-y-4">
          <p className="text-xs" style={{ color: 'var(--text-3)' }}>
            Simulate detection rules against historical logs to estimate match rate before enabling.
          </p>
          <TestingPanel sigmaRules={sigmaRules} />
        </div>
      )}

      {/* ── AI Assistant ── */}
      {tab === 'ai' && <AIAssistantPanel />}

      {/* ── Pipeline ── */}
      {tab === 'pipeline' && (
        <PipelineView engines={performance?.engines ?? [
          { name: 'Sigma Engine', rules: 0, status: 'healthy', avg_ms: 2 },
          { name: 'YARA Engine', rules: 0, status: 'healthy', avg_ms: 8 },
          { name: 'IOC Matcher', rules: 0, status: 'healthy', avg_ms: 1 },
          { name: 'Correlation Engine', rules: 0, status: 'healthy', avg_ms: 15 },
          { name: 'ML/Behavioral', rules: 0, status: 'healthy', avg_ms: 45 },
        ]} />
      )}

      {/* ── Library ── */}
      {tab === 'library' && (
        <div className="space-y-4">
          <p className="text-xs" style={{ color: 'var(--text-3)' }}>
            Detection rule library organized by category, platform, and threat type.
          </p>
          <LibraryPanel />
        </div>
      )}
    </RootLayout>
  );
}
