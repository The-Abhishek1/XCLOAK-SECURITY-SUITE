import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Script Runner page (route
// /script-runner) — backed by sr_* tables (api/script_runner_enterprise.go),
// a separate system from the older api/script_runner.go (/api/scripts/*
// routes), confirmed via grep this page's frontend only ever calls srAPI.
//
// Real bugs found and fixed this pass:
// - PatchSRScript only ever persisted content/status/version, silently
//   discarding name/description/language/category/tags/requires_approval —
//   yet the Code Editor's Save button always sends the full object
//   including those fields on every edit of an existing script. Confirmed
//   live: PATCHing a script's name/language/category/tags/requires_approval
//   and re-fetching showed the change; before the fix those fields were
//   simply never written.
// - PostSRItem accepted expires_at... (n/a here, that was Quarantine).
//   PostSRExecute's execution flow was already real (dispatches a genuine
//   agent_tasks row), but syncExecutionFromAgentTask never set
//   execution_time on completion — only ever left NULL — so
//   avg_execution_time/automation_time_saved_hours stayed 0 forever
//   regardless of real completed executions. Fixed by computing it from
//   started_at/completed_at in the same UPDATE.
// - Independently, GetSRDashboard/GetSRAnalytics scanned
//   AVG(execution_time) — a Postgres `numeric`, not `integer` — into a
//   plain Go int, which fails Scan() silently (error return discarded),
//   so avg_execution_time was ALSO stuck at 0 for a second, separate
//   reason even after the above fix. Fixed by scanning into float64,
//   matching the same AVG-into-float64 idiom already used elsewhere in
//   this codebase.
// - The Schedule tab's automation was entirely inert: next_run was
//   computed once at creation and never recalculated, no ticker ever
//   checked for due schedules, last_run stayed NULL forever. Confirmed via
//   AskUserQuestion: built real dispatch into the existing 30s scheduler
//   tick (services.RunDueScriptSchedules), reusing the exact same dispatch
//   path PostSRExecute already used for a manual run (moved into
//   services.DispatchScriptExecution so the scheduler — which can't import
//   api — can call it directly instead of duplicating the logic).
// - Building that live-tested the fix and surfaced a genuinely separate,
//   pre-existing bug: next_run/last_run are plain TIMESTAMP (no time
//   zone) columns, and time.Now() on this dev box (IST, UTC+5:30) writes
//   local wall-clock digits verbatim — which then compare as if they
//   *were* UTC against Postgres's own NOW(). A schedule seeded 2 minutes
//   in the past read back ~5.5 hours in the future and never fired.
//   Fixed by using time.Now().UTC() for every next_run/last_run write
//   this page's code makes (both the new scheduler code and the
//   pre-existing PostSRSchedule).
// - PostSRAI didn't strip markdown fences before the frontend's own
//   JSON.parse(action result) — same fence-stripping fix as every other
//   page's AI endpoint this phase (frontend already had a raw-text
//   fallback here, so less severe than Quarantine's version, but still a
//   real robustness gap on a genuinely successful response).
// - PostSRReport's recommendations were 4 fixed strings returned
//   regardless of report_type or any real data — rewritten to an
//   LLM-grounded summary/recommendations based only on this tenant's real
//   execution/script/approval/schedule counts, matching every other
//   report endpoint fixed this phase.
// - Frontend: del (script library), save/execute (editor), create/toggle/
//   delete (schedules), decide (approvals) all had zero error handling
//   despite srAPI's write methods already correctly not swallowing
//   errors — added try/catch to all seven call sites.
//
// Like every other page this phase: sr_scripts/sr_executions/sr_schedules/
// sr_approvals/sr_audit had no seed data anywhere in a fresh dev
// environment — added seedScriptRunnerEnterprise to cmd/seed/demo/main.go
// (6 scripts spanning every language/category/approval/signed combination,
// 5 historical executions spanning success/failed/running, 3 schedules —
// one deliberately already-due against a real agent hostname with real
// script content so the live scheduler tick has something genuine to
// dispatch on a fresh dev boot — and 2 approvals, one pending one decided).
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = [
  'Dashboard', 'Script Library', 'Code Editor', 'Execution History', 'AI Assistant',
  'Schedule', 'Approvals', 'Analytics', 'Audit Trail', 'Reports',
];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Script Runner — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/script-runner');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/script-runner');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('Script Runner — regression guard: seed data exists', () => {
  test('script library and dashboard show real seeded data, not an empty page', async ({ page }) => {
    const scripts = await page.request.get('/api/sr/scripts').then(r => r.json());
    const realCount = Number(PSQL(`SELECT count(*) FROM sr_scripts WHERE tenant_id=9999;`));
    expect(realCount).toBeGreaterThan(0);
    expect(scripts.length).toBe(realCount);

    const dash = await page.request.get('/api/sr/dashboard').then(r => r.json());
    expect(dash.total_scripts).toBe(realCount);
  });
});

test.describe('Script Runner — regression guard: editing a script persists all fields, not just content', () => {
  test('PatchSRScript now saves name/description/language/category/tags/requires_approval', async ({ page }) => {
    const scripts = await page.request.get('/api/sr/scripts').then(r => r.json());
    const target = scripts.find((s: any) => s.name === 'Legacy Log Rotation');
    expect(target).toBeTruthy();

    const patch = await page.request.patch(`/api/sr/scripts/${target.id}`, {
      data: { name: 'e2e-renamed-script', description: 'e2e updated', language: 'python', category: 'monitoring', tags: '["e2e"]', requires_approval: true },
    });
    expect(patch.ok()).toBeTruthy();

    const updated = await page.request.get(`/api/sr/scripts/${target.id}`).then(r => r.json());
    expect(updated.name).toBe('e2e-renamed-script');
    expect(updated.description).toBe('e2e updated');
    expect(updated.language).toBe('python');
    expect(updated.category).toBe('monitoring');
    expect(updated.requires_approval).toBe(true);

    // restore
    await page.request.patch(`/api/sr/scripts/${target.id}`, {
      data: { name: 'Legacy Log Rotation', description: target.description, language: 'bash', category: 'general', tags: '[]', requires_approval: false },
    });
  });
});

test.describe('Script Runner — regression guard: execution_time is computed on completion', () => {
  test('a real completed execution gets a real, non-null execution_time', async ({ page }) => {
    const exec = await page.request.post('/api/sr/execute', {
      data: { script_id: 'SCR-9999-20000', script_name: 'Collect Forensic Triage Snapshot', target: 'db-server-02', run_as: 'system', trigger_source: 'manual' },
    });
    expect(exec.ok()).toBeTruthy();
    const body = await exec.json();
    expect(body.status).toBe('running');

    const taskId = Number(PSQL(`SELECT agent_task_id FROM sr_executions WHERE tenant_id=9999 AND execution_id='${body.execution_id}';`));
    expect(taskId).toBeGreaterThan(0);
    PSQL(`UPDATE agent_tasks SET status='completed', result='ok', completed_at=NOW() WHERE id=${taskId};`);

    const rowId = Number(PSQL(`SELECT id FROM sr_executions WHERE tenant_id=9999 AND execution_id='${body.execution_id}';`));
    const detail = await page.request.get(`/api/sr/executions/${rowId}`).then(r => r.json());
    expect(detail.status).toBe('success');
    expect(detail.execution_time).toBeGreaterThan(0);
  });
});

test.describe('Script Runner — regression guard: avg_execution_time reflects real data', () => {
  test('dashboard and analytics report a real non-zero average, not always 0', async ({ page }) => {
    const dash = await page.request.get('/api/sr/dashboard').then(r => r.json());
    expect(dash.avg_execution_time).toBeGreaterThan(0);

    const analytics = await page.request.get('/api/sr/analytics').then(r => r.json());
    expect(analytics.avg_execution_time).toBeGreaterThan(0);
    expect(analytics.automation_time_saved_hours).toBeGreaterThan(0);
  });
});

test.describe('Script Runner — regression guard: scheduled dispatch actually recurs', () => {
  test('the hourly schedule seeded already-due was dispatched by the live scheduler and last_run/next_run advanced', async ({ page }) => {
    const lastRun = PSQL(`SELECT last_run FROM sr_schedules WHERE tenant_id=9999 AND name LIKE 'Hourly Forensic Snapshot%';`);
    expect(lastRun).not.toBe('');

    const scheduledCount = Number(PSQL(`SELECT count(*) FROM sr_executions WHERE tenant_id=9999 AND trigger_source='scheduled' AND executed_by='scheduler';`));
    expect(scheduledCount).toBeGreaterThan(0);
  });

  test('a newly created schedule stores next_run without a timezone skew', async ({ page }) => {
    const scripts = await page.request.get('/api/sr/scripts').then(r => r.json());
    const s = scripts.find((s: any) => s.name === 'Legacy Log Rotation');
    const create = await page.request.post('/api/sr/schedules', {
      data: { name: 'e2e tz-check schedule', script_id: s.script_id, script_name: s.name, schedule_type: 'once', target: 'web-prod-01', run_as: 'system' },
    });
    expect(create.ok()).toBeTruthy();
    const created = await create.json();

    // Before the .UTC() fix, next_run landed ~5.5h off on an IST dev box —
    // assert it's within a couple minutes of a genuine "now + 1h" in real
    // UTC terms, not off by the server's local offset.
    const withinWindow = PSQL(`SELECT (next_run BETWEEN NOW() + INTERVAL '55 minutes' AND NOW() + INTERVAL '65 minutes') FROM sr_schedules WHERE id=${created.id};`);
    expect(withinWindow).toBe('t');

    PSQL(`DELETE FROM sr_audit WHERE tenant_id=9999 AND script_id='${s.script_id}' AND details LIKE '%tz-check%'; DELETE FROM sr_schedules WHERE id=${created.id};`);
  });
});

test.describe('Script Runner — regression guard: report is grounded in real numbers, not fixed boilerplate', () => {
  test('PostSRReport recommendations are no longer the old fixed 4-string list', async ({ page }) => {
    const res = await page.request.post('/api/sr/report', { data: { report_type: 'execution' } });
    expect(res.ok()).toBeTruthy();
    const report = await res.json();

    const realTotal = Number(PSQL(`SELECT count(*) FROM sr_executions WHERE tenant_id=9999;`));
    expect(report.key_metrics.total_executions).toBe(realTotal);
    const oldFixedRecs = ['Enable script signing for all production scripts', 'Implement approval workflow for privileged executions'];
    for (const old of oldFixedRecs) {
      expect(report.recommendations).not.toContain(old);
    }
  });
});
