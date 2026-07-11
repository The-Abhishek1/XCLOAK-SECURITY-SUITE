'use client';

import { useState, useEffect } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { frameworkComplianceAPI } from '@/lib/api';
import { ShieldCheck, ChevronDown, ChevronRight, RefreshCw } from 'lucide-react';

interface ControlCoverage {
  control_ref: string; framework: string; title: string;
  category: string; severity: string; status: string;
  coverage_score: number; evidence_count: number; evidence_source: string; notes: string;
}

interface FrameworkAssessment {
  framework: string; total_controls: number; covered: number; partial: number;
  gaps: number; overall_score: number; controls: ControlCoverage[];
}

const STATUS_COLOR: Record<string, string> = {
  covered: '#22c55e', partial: '#fbbf24', gap: '#f85149',
};
const SEV_COLOR: Record<string, string> = {
  critical: '#f85149', high: '#fb923c', medium: '#fbbf24', low: '#22c55e',
};
const FRAMEWORK_COLOR: Record<string, string> = {
  CIS: '#38bdf8', NIST: '#a855f7', 'PCI-DSS': '#22c55e',
};

function ScoreRing({ score, color }: { score: number; color: string }) {
  const r = 28;
  const circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;
  return (
    <svg width="72" height="72" viewBox="0 0 72 72">
      <circle cx="36" cy="36" r={r} fill="none" strokeWidth="6" stroke="var(--glass-bg-2)" />
      <circle cx="36" cy="36" r={r} fill="none" strokeWidth="6" stroke={color}
        strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
        transform="rotate(-90 36 36)" />
      <text x="36" y="40" textAnchor="middle" fill={color} fontSize="14" fontWeight="700">{score}</text>
    </svg>
  );
}

function ControlTable({ controls, expanded }: { controls: ControlCoverage[]; expanded: boolean }) {
  if (!expanded) return null;

  // Group by category
  const grouped: Record<string, ControlCoverage[]> = {};
  controls.forEach(c => {
    if (!grouped[c.category]) grouped[c.category] = [];
    grouped[c.category].push(c);
  });

  return (
    <div className="mt-4 space-y-3">
      {Object.entries(grouped).map(([cat, items]) => (
        <div key={cat}>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5 px-1" style={{ color: 'var(--text-3)' }}>{cat}</p>
          {items.map(ctrl => {
            const statusColor = STATUS_COLOR[ctrl.status] || 'var(--text-3)';
            const sevColor = SEV_COLOR[ctrl.severity] || 'var(--text-3)';
            return (
              <div key={ctrl.control_ref} className="flex items-center gap-3 px-3 py-2.5 rounded-lg mb-1.5"
                style={{ background: 'var(--glass-bg)', border: `1px solid ${statusColor}20` }}>
                <span className="text-[10px] font-mono font-bold w-20 shrink-0" style={{ color: 'var(--accent)' }}>
                  {ctrl.control_ref}
                </span>
                <span className="flex-1 text-xs truncate" style={{ color: 'var(--text-1)' }}>{ctrl.title}</span>
                <span className="text-[10px] shrink-0 capitalize" style={{ color: sevColor }}>{ctrl.severity}</span>
                <div className="w-16 h-1.5 rounded-full overflow-hidden shrink-0" style={{ background: 'var(--glass-bg-2)' }}>
                  <div className="h-full rounded-full" style={{ width: `${ctrl.coverage_score}%`, background: statusColor }} />
                </div>
                <span className="text-[10px] font-bold w-8 text-right shrink-0 tabular-nums" style={{ color: statusColor }}>
                  {ctrl.coverage_score}%
                </span>
                <span className="text-[10px] shrink-0 capitalize px-1.5 py-0.5 rounded"
                  style={{ background: `${statusColor}15`, color: statusColor }}>
                  {ctrl.status}
                </span>
                <span className="text-[10px] shrink-0" style={{ color: 'var(--text-3)' }}>
                  {ctrl.evidence_count > 0 ? `${ctrl.evidence_count} ${ctrl.evidence_source}` : 'no evidence'}
                </span>
              </div>
            );
          })}
        </div>
      ))}
    </div>
  );
}

function FrameworkCard({ assessment }: { assessment: FrameworkAssessment }) {
  const [expanded, setExpanded] = useState(false);
  const color = FRAMEWORK_COLOR[assessment.framework] || 'var(--accent)';
  const scoreColor = assessment.overall_score >= 70 ? '#22c55e' : assessment.overall_score >= 40 ? '#fbbf24' : '#f85149';

  return (
    <div className="g-card overflow-hidden">
      <div className="p-5 flex items-center gap-5 cursor-pointer hover:bg-[var(--glass-bg-2)] transition-colors"
        onClick={() => setExpanded(e => !e)}>
        <ScoreRing score={assessment.overall_score} color={scoreColor} />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-base font-bold" style={{ color }}>{assessment.framework}</span>
            {expanded ? <ChevronDown className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />
                      : <ChevronRight className="h-3.5 w-3.5" style={{ color: 'var(--text-3)' }} />}
          </div>
          <div className="flex items-center gap-4 text-[11px]">
            <span style={{ color: '#22c55e' }}>✓ {assessment.covered} covered</span>
            <span style={{ color: '#fbbf24' }}>◑ {assessment.partial} partial</span>
            <span style={{ color: '#f85149' }}>✗ {assessment.gaps} gaps</span>
            <span style={{ color: 'var(--text-3)' }}>{assessment.total_controls} controls total</span>
          </div>
        </div>

        {/* Coverage bar */}
        <div className="w-40 hidden sm:block">
          <div className="flex justify-between text-[10px] mb-1" style={{ color: 'var(--text-3)' }}>
            <span>Coverage</span><span>{assessment.overall_score}%</span>
          </div>
          <div className="h-2 rounded-full overflow-hidden" style={{ background: 'var(--glass-bg-2)' }}>
            <div className="h-full rounded-full transition-all" style={{ width: `${assessment.overall_score}%`, background: scoreColor }} />
          </div>

          {/* Stacked mini bars */}
          <div className="flex gap-0.5 mt-1">
            {(assessment.controls ?? []).map(ctrl => (
              <div key={ctrl.control_ref} className="flex-1 h-1 rounded-sm"
                style={{ background: STATUS_COLOR[ctrl.status] || 'var(--text-3)', opacity: 0.7 }} />
            ))}
          </div>
        </div>
      </div>

      {expanded && (
        <div className="px-5 pb-5 border-t" style={{ borderColor: 'var(--border)' }}>
          <ControlTable controls={assessment.controls ?? []} expanded />
        </div>
      )}
    </div>
  );
}

export default function FrameworkCompliancePage() {
  const [assessments, setAssessments] = useState<FrameworkAssessment[]>([]);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    const r = await frameworkComplianceAPI.getAll();
    setAssessments(r.data || []);
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const avgScore = assessments.length > 0
    ? Math.round(assessments.reduce((s, a) => s + a.overall_score, 0) / assessments.length)
    : 0;
  const totalGaps = assessments.reduce((s, a) => s + a.gaps, 0);
  const totalCovered = assessments.reduce((s, a) => s + a.covered, 0);

  return (
    <RootLayout title="Framework Compliance"
      subtitle="CIS Controls v8 · NIST CSF · PCI-DSS — scored from live telemetry"
      actions={
        <button onClick={load} disabled={loading}
          className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      }>

      {/* Summary KPIs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
        {[
          { label: 'Avg Score', value: `${avgScore}%`, color: avgScore >= 70 ? '#22c55e' : avgScore >= 40 ? '#fbbf24' : '#f85149' },
          { label: 'Frameworks', value: assessments.length, color: 'var(--accent)' },
          { label: 'Covered Controls', value: totalCovered, color: '#22c55e' },
          { label: 'Control Gaps', value: totalGaps, color: totalGaps > 0 ? '#f85149' : 'var(--text-3)' },
        ].map(({ label, value, color }) => (
          <div key={label} className="g-card p-4">
            <p className="text-2xl font-bold" style={{ color }}>{value}</p>
            <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>{label}</p>
          </div>
        ))}
      </div>

      <div className="rounded-xl px-4 py-3 mb-5 text-xs" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-3)' }}>
        <span className="font-semibold" style={{ color: 'var(--text-2)' }}>How scoring works: </span>
        Each control is mapped to evidence in XCloak (Sigma rules, YARA rules, firewall rules, agents, vulnerabilities, audit logs, playbooks, etc.). Coverage score = 0% if no evidence, 40–65% partial (1–4 items), 70–100% covered (5+ items). Scores update in real-time — no manual input required.
      </div>

      {loading ? (
        <div className="py-16 text-center text-sm animate-pulse" style={{ color: 'var(--text-3)' }}>Computing compliance…</div>
      ) : (
        <div className="space-y-4">
          {assessments.map(a => <FrameworkCard key={a.framework} assessment={a} />)}
        </div>
      )}

      {assessments.length === 0 && !loading && (
        <div className="py-16 text-center">
          <ShieldCheck className="mx-auto h-12 w-12 mb-3 opacity-20" style={{ color: 'var(--text-3)' }} />
          <p className="text-sm" style={{ color: 'var(--text-3)' }}>No assessments available.</p>
        </div>
      )}
    </RootLayout>
  );
}
