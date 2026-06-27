'use client';

import { useEffect, useState, useCallback } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { threatAPI } from '@/lib/api';
import { AnomalyFinding, AgentAnomalyScore, FleetAnomalySummary } from '@/types';
import { sevClass } from '@/lib/utils';
import {
  Activity, AlertTriangle, Brain, CheckCircle2, ChevronDown,
  ChevronUp, RefreshCw, Zap
} from 'lucide-react';

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score >= 85) return 'var(--red)';
  if (score >= 70) return 'var(--yellow)';
  if (score >= 40) return 'var(--accent)';
  return 'var(--green)';
}

function ScoreBadge({ score }: { score: number }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-bold"
      style={{ background: `color-mix(in srgb, ${scoreColor(score)} 15%, transparent)`, color: scoreColor(score) }}>
      {score}
    </span>
  );
}

function ScoreBar({ score }: { score: number }) {
  return (
    <div className="h-1.5 w-full rounded-full overflow-hidden" style={{ background: 'var(--bg-0)' }}>
      <div className="h-full rounded-full transition-all duration-300"
        style={{ width: `${score}%`, background: scoreColor(score) }} />
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────────────

export default function ThreatDetectionPage() {
  const [fleet,      setFleet]      = useState<FleetAnomalySummary[]>([]);
  const [findings,   setFindings]   = useState<AnomalyFinding[]>([]);
  const [scores,     setScores]     = useState<AgentAnomalyScore[]>([]);
  const [loading,    setLoading]    = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [tab,        setTab]        = useState<'fleet' | 'findings' | 'history'>('fleet');
  const [hours,      setHours]      = useState(24);
  const [runningAI,  setRunningAI]  = useState<number | null>(null);
  const [runningScore, setRunningScore] = useState<number | null>(null);
  const [toast,      setToast]      = useState<string | null>(null);
  const [expandedAgent, setExpandedAgent] = useState<number | null>(null);

  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3000); };

  const load = useCallback(async (spin = false) => {
    if (spin) setRefreshing(true);
    try {
      const [fRes, findRes, sRes] = await Promise.all([
        threatAPI.fleet().catch(() => ({ data: [] })),
        threatAPI.findings().catch(() => ({ data: [] })),
        threatAPI.scores(0, hours).catch(() => ({ data: [] })),
      ]);
      setFleet(fRes.data || []);
      setFindings(findRes.data || []);
      setScores(sRes.data || []);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [hours]);

  useEffect(() => { load(); }, [load]);

  // ── Actions ─────────────────────────────────────────────────────────────
  const runAI = async (agentId: number) => {
    setRunningAI(agentId);
    try {
      await threatAPI.runAI(agentId);
      notify('AI analysis complete');
      load();
    } catch {
      notify('AI analysis failed');
    } finally {
      setRunningAI(null);
    }
  };

  const scoreNow = async (agentId: number) => {
    setRunningScore(agentId);
    try {
      const res = await threatAPI.scoreNow(agentId);
      notify(`Score: ${res.data.score}/100`);
      load();
    } catch {
      notify('Scoring failed');
    } finally {
      setRunningScore(null);
    }
  };

  const acknowledge = async (id: number) => {
    await threatAPI.acknowledge(id);
    setFindings(f => f.map(x => x.id === id ? { ...x, acknowledged: true } : x));
    notify('Finding acknowledged');
  };

  // ── Derived stats ────────────────────────────────────────────────────────
  const highRiskAgents = fleet.filter(f => f.peak_score >= 70).length;
  const criticalAgents = fleet.filter(f => f.peak_score >= 85).length;
  const openFindings   = findings.filter(f => !f.acknowledged).length;

  // ── Score timeline (last 24 readings per agent for top-5 agents) ─────────
  const agentScoreMap = new Map<number, AgentAnomalyScore[]>();
  scores.forEach(s => {
    const list = agentScoreMap.get(s.agent_id) || [];
    list.push(s);
    agentScoreMap.set(s.agent_id, list);
  });

  const TABS = [
    { id: 'fleet',    label: 'Fleet Overview', count: fleet.length },
    { id: 'findings', label: 'Findings',        count: openFindings },
    { id: 'history',  label: 'Score History' },
  ] as const;

  return (
    <RootLayout
      title="Behavioral Threat Detection"
      subtitle="Statistical baselines · Anomaly scoring · AI analysis"
      onRefresh={() => load(true)} refreshing={refreshing}>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 g-panel px-4 py-3 text-sm"
          style={{ color: 'var(--text-1)', minWidth: 200 }}>{toast}</div>
      )}

      {/* Summary strip */}
      <div className="grid grid-cols-3 gap-4 mb-4">
        {[
          { label: 'Agents monitored', value: fleet.length,    icon: Activity,       color: 'var(--accent)' },
          { label: 'High-risk agents', value: highRiskAgents,  icon: AlertTriangle,  color: 'var(--yellow)' },
          { label: 'Critical alerts',  value: criticalAgents,  icon: Zap,            color: 'var(--red)' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="g-card p-4 flex items-center gap-3">
            <Icon className="h-5 w-5 shrink-0" style={{ color }} />
            <div>
              <p className="text-xl font-bold" style={{ color }}>{value}</p>
              <p className="text-xs" style={{ color: 'var(--text-3)' }}>{label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-4 p-1 rounded-xl" style={{ background: 'var(--bg-0)', width: 'fit-content' }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id as typeof tab)}
            className={`px-4 py-1.5 rounded-lg text-xs font-medium transition-colors ${tab === t.id ? 'g-btn g-btn-primary' : ''}`}
            style={tab !== t.id ? { color: 'var(--text-3)' } : {}}>
            {t.label}{'count' in t && t.count !== undefined ? ` (${t.count})` : ''}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="py-20 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Loading…</div>
      ) : tab === 'fleet' ? (
        <FleetTab fleet={fleet} agentScoreMap={agentScoreMap}
          expandedAgent={expandedAgent} setExpandedAgent={setExpandedAgent}
          onRunAI={runAI} onScoreNow={scoreNow}
          runningAI={runningAI} runningScore={runningScore} />
      ) : tab === 'findings' ? (
        <FindingsTab findings={findings} onAcknowledge={acknowledge} />
      ) : (
        <HistoryTab scores={scores} fleet={fleet} hours={hours} setHours={setHours} />
      )}
    </RootLayout>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Fleet tab
// ─────────────────────────────────────────────────────────────────────────────

function FleetTab({
  fleet, agentScoreMap, expandedAgent, setExpandedAgent, onRunAI, onScoreNow, runningAI, runningScore,
}: {
  fleet: FleetAnomalySummary[];
  agentScoreMap: Map<number, AgentAnomalyScore[]>;
  expandedAgent: number | null;
  setExpandedAgent: (id: number | null) => void;
  onRunAI: (id: number) => void;
  onScoreNow: (id: number) => void;
  runningAI: number | null;
  runningScore: number | null;
}) {
  if (!fleet.length) return (
    <div className="py-16 text-center">
      <Activity className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--text-3)' }} />
      <p className="text-sm" style={{ color: 'var(--text-2)' }}>
        No score data yet — baselines build automatically as agents send logs.
      </p>
    </div>
  );

  return (
    <div className="g-table">
      <div className="g-thead grid gap-3 px-4"
        style={{ gridTemplateColumns: '1fr 100px 100px 80px 160px 60px' }}>
        <span>Agent</span>
        <span>Peak Score</span>
        <span>Avg Score</span>
        <span>Readings</span>
        <span>Last scored</span>
        <span className="text-right">Actions</span>
      </div>
      {fleet.map(f => {
        const expanded = expandedAgent === f.agent_id;
        const recentScores = (agentScoreMap.get(f.agent_id) || []).slice(0, 12);
        return (
          <div key={f.agent_id}>
            <div className="g-tr grid gap-3 items-center px-4 cursor-pointer"
              style={{ gridTemplateColumns: '1fr 100px 100px 80px 160px 60px' }}
              onClick={() => setExpandedAgent(expanded ? null : f.agent_id)}>

              <div className="flex items-center gap-2">
                {expanded ? <ChevronUp className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />
                          : <ChevronDown className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-3)' }} />}
                <span className="text-xs font-medium mono" style={{ color: 'var(--text-1)' }}>{f.hostname}</span>
              </div>
              <div>
                <ScoreBadge score={f.peak_score} />
                <ScoreBar score={f.peak_score} />
              </div>
              <div>
                <span className="text-xs" style={{ color: 'var(--text-2)' }}>{f.avg_score}</span>
                <ScoreBar score={f.avg_score} />
              </div>
              <span className="text-xs" style={{ color: 'var(--text-3)' }}>{f.readings}</span>
              <span className="text-xs" style={{ color: 'var(--text-3)' }}>
                {new Date(f.last_scored).toLocaleString()}
              </span>
              <div className="flex items-center justify-end gap-1"
                onClick={e => e.stopPropagation()}>
                <button onClick={() => onScoreNow(f.agent_id)}
                  disabled={runningScore === f.agent_id}
                  className="g-btn g-btn-ghost text-[10px]" style={{ padding: '3px 6px' }}
                  title="Score now">
                  <RefreshCw className={`h-3 w-3 ${runningScore === f.agent_id ? 'animate-spin' : ''}`} />
                </button>
                <button onClick={() => onRunAI(f.agent_id)}
                  disabled={runningAI === f.agent_id}
                  className="g-btn g-btn-ghost text-[10px]" style={{ padding: '3px 6px' }}
                  title="Run AI analysis">
                  <Brain className={`h-3 w-3 ${runningAI === f.agent_id ? 'animate-spin' : ''}`} />
                </button>
              </div>
            </div>

            {/* Expanded: mini score timeline + component breakdown */}
            {expanded && recentScores.length > 0 && (
              <div className="px-6 pb-4 pt-2" style={{ borderTop: '1px solid var(--border)' }}>
                <p className="text-[10px] uppercase tracking-wider mb-2" style={{ color: 'var(--text-3)' }}>Recent Score History</p>
                <div className="flex items-end gap-1 h-10">
                  {recentScores.slice().reverse().map((s, i) => (
                    <div key={i} title={`${s.score} @ ${new Date(s.scored_at).toLocaleTimeString()}`}
                      className="flex-1 rounded-sm transition-all"
                      style={{
                        height: `${Math.max(4, s.score)}%`,
                        minHeight: 4,
                        maxHeight: '100%',
                        background: scoreColor(s.score),
                        opacity: 0.8,
                      }} />
                  ))}
                </div>
                {recentScores[0] && (
                  <div className="grid grid-cols-4 gap-2 mt-3">
                    {[
                      { label: 'Log rate', val: recentScores[0].components?.log_rate },
                      { label: 'Login anomaly', val: recentScores[0].components?.login_anomaly },
                      { label: 'Off-hours', val: recentScores[0].components?.off_hours },
                      { label: 'Conn rate', val: recentScores[0].components?.conn_rate },
                    ].map(({ label, val }) => (
                      <div key={label} className="rounded-lg p-2 text-center"
                        style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                        <p className="text-base font-bold" style={{ color: scoreColor(val ?? 0) }}>{val ?? 0}</p>
                        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{label}</p>
                      </div>
                    ))}
                  </div>
                )}
                {recentScores[0]?.components?.detail && (
                  <p className="text-[10px] mt-2" style={{ color: 'var(--text-2)' }}>
                    {recentScores[0].components.detail}
                  </p>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Findings tab
// ─────────────────────────────────────────────────────────────────────────────

function FindingsTab({
  findings, onAcknowledge,
}: {
  findings: AnomalyFinding[];
  onAcknowledge: (id: number) => void;
}) {
  const [showAll, setShowAll] = useState(false);
  const displayed = showAll ? findings : findings.filter(f => !f.acknowledged);

  if (!findings.length) return (
    <div className="py-16 text-center">
      <CheckCircle2 className="mx-auto h-8 w-8 mb-2" style={{ color: 'var(--green)' }} />
      <p className="text-sm" style={{ color: 'var(--text-2)' }}>No anomaly findings</p>
    </div>
  );

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs" style={{ color: 'var(--text-3)' }}>
          {findings.filter(f => !f.acknowledged).length} open · {findings.filter(f => f.acknowledged).length} acknowledged
        </p>
        <button onClick={() => setShowAll(p => !p)} className="g-btn g-btn-ghost text-xs">
          {showAll ? 'Hide acknowledged' : 'Show all'}
        </button>
      </div>

      <div className="g-table">
        <div className="g-thead grid gap-3 px-4"
          style={{ gridTemplateColumns: '60px 80px 60px 80px 1fr 80px' }}>
          <span>Agent</span><span>Type</span><span>Score</span><span>Severity</span>
          <span>Description</span><span className="text-right">Action</span>
        </div>
        {displayed.map(f => (
          <div key={f.id} className={`g-tr grid gap-3 items-start px-4 ${f.acknowledged ? 'opacity-40' : ''}`}
            style={{ gridTemplateColumns: '60px 80px 60px 80px 1fr 80px' }}>
            <span className="text-xs mono" style={{ color: 'var(--text-3)' }}>#{f.agent_id}</span>
            <span className="text-xs rounded px-1.5 py-0.5 w-fit"
              style={{ background: 'var(--bg-0)', color: 'var(--text-2)', border: '1px solid var(--border)' }}>
              {f.finding_type}
            </span>
            <ScoreBadge score={f.score} />
            <span className={sevClass(f.severity)}>{f.severity}</span>
            <div>
              <p className="text-xs" style={{ color: 'var(--text-1)' }}>{f.description}</p>
              <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-3)' }}>
                {f.source} · {new Date(f.created_at).toLocaleString()}
              </p>
            </div>
            {!f.acknowledged && (
              <button onClick={() => onAcknowledge(f.id)} className="g-btn g-btn-ghost text-[10px] justify-end"
                style={{ padding: '3px 8px' }}>
                <CheckCircle2 className="h-3 w-3" /> Ack
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// History tab
// ─────────────────────────────────────────────────────────────────────────────

function HistoryTab({
  scores, fleet, hours, setHours,
}: {
  scores: AgentAnomalyScore[];
  fleet: FleetAnomalySummary[];
  hours: number;
  setHours: (h: number) => void;
}) {
  // Group by hour bucket, compute average score across all agents per bucket.
  const buckets = new Map<string, number[]>();
  scores.forEach(s => {
    const bucket = new Date(s.scored_at);
    bucket.setMinutes(0, 0, 0);
    const key = bucket.toISOString();
    const arr = buckets.get(key) || [];
    arr.push(s.score);
    buckets.set(key, arr);
  });

  const timeline = Array.from(buckets.entries())
    .map(([t, vals]) => ({
      time: t,
      avg: Math.round(vals.reduce((a, b) => a + b, 0) / vals.length),
      max: Math.max(...vals),
    }))
    .sort((a, b) => a.time.localeCompare(b.time))
    .slice(-48); // max 48 buckets

  const maxScore = Math.max(...timeline.map(t => t.max), 1);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <span className="text-xs" style={{ color: 'var(--text-3)' }}>Time range:</span>
        {[6, 24, 48, 168].map(h => (
          <button key={h} onClick={() => setHours(h)}
            className={`g-btn text-xs ${hours === h ? 'g-btn-primary' : 'g-btn-ghost'}`}
            style={{ padding: '3px 10px' }}>
            {h < 24 ? `${h}h` : h === 168 ? '7d' : '24h'}
          </button>
        ))}
      </div>

      {timeline.length === 0 ? (
        <div className="py-16 text-center text-sm" style={{ color: 'var(--text-3)' }}>No score history yet</div>
      ) : (
        <div className="g-card p-4">
          <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-3)' }}>
            Fleet Average Anomaly Score
          </p>
          <div className="flex items-end gap-px h-24 w-full">
            {timeline.map((t, i) => (
              <div key={i} className="flex-1 flex flex-col items-center gap-px" style={{ minWidth: 2 }}>
                <div className="w-full rounded-sm" title={`Max: ${t.max} · Avg: ${t.avg}`}
                  style={{
                    height: `${(t.avg / maxScore) * 100}%`,
                    minHeight: 2,
                    background: scoreColor(t.avg),
                    opacity: 0.7,
                  }} />
              </div>
            ))}
          </div>
          <div className="flex justify-between mt-1">
            <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
              {timeline[0] ? new Date(timeline[0].time).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : ''}
            </span>
            <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
              {timeline[timeline.length - 1] ? new Date(timeline[timeline.length - 1].time).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : ''}
            </span>
          </div>
        </div>
      )}

      {/* Per-agent recent scores */}
      {fleet.length > 0 && (
        <div className="g-table">
          <div className="g-thead grid gap-3 px-4"
            style={{ gridTemplateColumns: '1fr 80px 80px 100px' }}>
            <span>Agent</span><span>Peak</span><span>Avg</span><span>Last scored</span>
          </div>
          {fleet.map(f => (
            <div key={f.agent_id} className="g-tr grid gap-3 items-center px-4"
              style={{ gridTemplateColumns: '1fr 80px 80px 100px' }}>
              <span className="text-xs mono" style={{ color: 'var(--text-1)' }}>{f.hostname}</span>
              <ScoreBadge score={f.peak_score} />
              <span className="text-xs" style={{ color: scoreColor(f.avg_score) }}>{f.avg_score}</span>
              <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                {new Date(f.last_scored).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
