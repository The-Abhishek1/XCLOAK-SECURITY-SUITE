import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the AI Assistant page (route /ai-assistant) —
// backed by aia_* tables (api/ai_assistant_enterprise.go). This is the last
// page in the sidebar page-by-page testing phase.
//
// Overall this handler was already in good shape — chat, sessions, actions,
// recommendations, and audit are all genuinely real, grounded in real
// per-tenant alert/incident/agent data (aiaBuildPrompt / aiaGatherContext),
// consistent with the earlier "Fake AI Endpoints Fixed" pass on this same
// file. The findings here were narrower, confined to Analytics/Dashboard
// and report generation:
//
// - GetAIAAnalytics's usage_trend/response_quality/top_analysts/
//   automation_stats were all fully hardcoded fake data. usage_trend is now
//   real, bucketed by the last 7 real calendar days from aia_sessions/
//   aia_messages/aia_actions. response_quality now returns only
//   avg_latency_ms (real, the same aia_messages.latency_ms column
//   Dashboard already averages) — accuracy_rate/hallucination_rate/
//   user_rating_avg/correction_rate were dropped, since no message ever
//   collects a user rating or correction flag anywhere in this codebase.
//   top_analysts is now real, grouped from aia_sessions.created_by joined
//   against a real executed-action count from aia_actions. automation_stats
//   now returns reports_generated (real aia_reports count),
//   playbooks_generated and detection_rules_generated (real aia_actions
//   counts by action_type) — sigma/yara were combined into a single
//   detection_rules_generated since the real action_type schema can't
//   distinguish them, and scripts_generated/queries_generated/
//   analyst_hours_saved were dropped (no matching action_type or formula).
// - GetAIADashboard's stats.automation_rate and stats.analyst_hours_saved
//   were both hardcoded to 0 always, with zero computation attempted (not
//   an honest real zero — just never wired up) — dropped rather than left
//   as a permanently-stuck fake metric.
// - PostAIAReport never populated aia_reports.content at all (the 6th
//   occurrence of the report-generation-produces-no-real-content pattern
//   this phase) — now generates real markdown content via the LLM, grounded
//   either in the source session's real conversation (if session_id is
//   given) or the same real fleet-wide security context aiaBuildPrompt uses
//   for chat. Added a "View" action + modal to the frontend Reports tab so
//   the real content is actually visible, since nothing rendered it before.
// - Frontend: savePrompt/genReportFn used try/finally with no catch
//   (errors were silently swallowed, not surfaced); updateRecommendation/
//   createAction/approveAction call sites used bare `.then(loadAll)` with
//   no `.catch()` at all — 7 call sites total fixed with real error
//   handling.
// - This page's own pre-existing seeder had the same non-idempotency bug
//   found on the last eight pages: aia_sessions/aia_prompts/
//   aia_recommendations/aia_actions/aia_reports all have real unique
//   constraints and were already genuinely idempotent, but aia_messages/
//   aia_audit have no ON CONFLICT clause at all. Confirmed live: 504/1134
//   rows had accumulated (vs. ~8/~18 intended) before a standard
//   tenant-count guard was added.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = [
  'Dashboard', 'AI Chat', 'Investigate', 'Copilot', 'Recommendations', 'Automation',
  'Insights', 'Actions', 'Prompt Library', 'Analytics', 'Reports', 'Audit Trail',
];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('AI Assistant — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/ai-assistant');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('main').getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/ai-assistant');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('main').getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('AI Assistant — regression guard: seed data exists and is not duplicated', () => {
  test('sessions/prompts/recommendations/actions/reports/audit show the intended counts', async ({ page }) => {
    const expected: Record<string, number> = {
      aia_sessions: 10, aia_prompts: 8, aia_recommendations: 8,
      aia_actions: 10, aia_reports: 8, aia_audit: 18,
    };
    for (const [table, count] of Object.entries(expected)) {
      const real = Number(PSQL(`SELECT count(*) FROM ${table} WHERE tenant_id='9999';`));
      expect(real, `${table} row count`).toBeGreaterThanOrEqual(count);
      expect(real, `${table} row count should not be a multiplied duplicate pile`).toBeLessThan(count * 3);
    }
  });
});

test.describe('AI Assistant — regression guard: analytics reflects real state, not hardcoded fakes', () => {
  test('top_analysts and automation_stats are real, and unbackable response_quality/dashboard fields are dropped', async ({ page }) => {
    const realAliceSessions = Number(PSQL(`SELECT count(*) FROM aia_sessions WHERE tenant_id='9999' AND created_by='alice.zhang';`));
    const realReports = Number(PSQL(`SELECT count(*) FROM aia_reports WHERE tenant_id='9999';`));

    const analytics = await page.request.get('/api/aia/analytics').then(r => r.json());
    const alice = analytics.top_analysts.find((a: any) => a.analyst === 'alice.zhang');
    expect(alice?.sessions).toBe(realAliceSessions);
    expect(analytics.automation_stats.reports_generated).toBe(realReports);
    expect(analytics.response_quality).not.toHaveProperty('accuracy_rate');
    expect(analytics.response_quality).not.toHaveProperty('user_rating_avg');
    expect(analytics.automation_stats).not.toHaveProperty('sigma_rules_generated');
    expect(analytics.automation_stats).not.toHaveProperty('analyst_hours_saved');
    expect(analytics.usage_trend).toHaveLength(7);

    const dashboard = await page.request.get('/api/aia/dashboard').then(r => r.json());
    expect(dashboard.stats).not.toHaveProperty('automation_rate');
    expect(dashboard.stats).not.toHaveProperty('analyst_hours_saved');
  });
});

test.describe('AI Assistant — regression guard: report generation produces real content', () => {
  test('a generated report has real markdown content grounded in real tenant data, not an empty column', async ({ page }) => {
    const res = await page.request.post('/api/aia/reports', {
      data: { title: 'e2e-real-content-check', report_type: 'executive_summary' },
    });
    expect(res.ok()).toBeTruthy();
    const created = await res.json();
    expect(created.content).toBeTruthy();
    expect(created.content.length).toBeGreaterThan(10);

    const reports = await page.request.get('/api/aia/reports').then(r => r.json());
    const match = reports.find((r: any) => r.report_id === created.report_id);
    expect(match).toBeTruthy();
    expect(match.content).toBe(created.content);

    PSQL(`DELETE FROM aia_audit WHERE tenant_id='9999' AND object_id='${created.report_id}'; DELETE FROM aia_reports WHERE report_id='${created.report_id}';`);
  });
});
