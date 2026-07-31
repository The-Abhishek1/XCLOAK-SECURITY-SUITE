import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Scheduled Tasks page (route
// /scheduled-tasks) — backed by ste_* tables (api/scheduled_tasks_enterprise.go).
// A third, separate scheduling system from Script Runner's sr_schedules and
// the generic /api/scheduler/tasks (scheduled_tasks table, used elsewhere,
// not by this page) — confirmed via grep this page's frontend only ever
// calls steAPI.
//
// Real bugs found and fixed this pass:
// - The whole page's premise is scheduled automation ("Upcoming Executions"
//   tab, cron builder, next_run countdowns), but there was no ticker
//   anywhere that read ste_tasks and dispatched due ones — next_run_at was
//   set once at creation and never advanced, tasks only ever ran via the
//   manual "Run Now" button. Confirmed via AskUserQuestion (same shape of
//   decision just made for Script Runner's Schedule tab): built real
//   dispatch into the existing 30s scheduler tick (services.RunDueSTETasks),
//   reusing this file's already-real dispatch code (moved to services as
//   DispatchSTETask/ExecuteSTETaskNow so the scheduler, which can't import
//   api, shares the same path a manual run uses).
// - Building that surfaced dispatchSTETask blindly sent ANY ste_tasks
//   task_type straight through to a real agent_tasks row — but the
//   picklist includes ~26 types (report generation, webhooks, script
//   languages with no content field anywhere to send, cleanup jobs) that
//   have no case in the agent's real executor at all; only vulnerability_scan
//   (of the types actually exercised) has a genuine 1:1 match. Added an
//   allow-list of the 21 real agent executor task types — anything else
//   now fails honestly ("task_type %q has no execution backend in this
//   build") instead of silently sending the agent garbage.
// - PostSTETask only ever computed an initial next_run_at when cron_expr
//   was non-empty — every other schedule_type (one_time/hourly/daily/
//   weekly/monthly/yearly, the majority the create form offers) got
//   next_run_at=NULL at creation, so those tasks never appeared in
//   "Upcoming Executions" and would never have been dispatchable either.
//   Fixed with a shared NextSTERunTime helper covering every schedule_type
//   (event_based/maintenance_window correctly stay NULL — no time basis).
// - syncSTEExecutions existed, was well-written, and had zero callers
//   anywhere in the codebase — every dispatched execution stayed "running"
//   forever regardless of real agent completion, which also meant
//   ste_tasks.success_count/failure_count and every duration-based metric
//   never updated either. Wired into GetSTEExecutions (sync on read) and a
//   new scheduler-tick SyncAllRunningSTEExecutions (background sweep, so
//   completion is reflected even with nobody viewing the tab).
// - PostSTEApprovalDecide only ever flipped ste_approvals.status —
//   approving a task never actually dispatched it, and PostSTERunTask
//   unconditionally re-checks requires_approval on every "Run Now" click
//   regardless of any existing decision, so a requires_approval task could
//   never run at all (approve did nothing; running again just filed
//   another pending approval). Fixed to dispatch for real on approval.
// - GetSTEAnalytics's by_category query selected `category` directly from
//   ste_executions, which has no such column (only ste_tasks does) — an
//   undefined-column error silently discarded via the ignored Query
//   return, so by_category was always empty. Fixed by joining ste_tasks.
// - PostSTEReport was the most minimal fake response on this page — zero
//   real numbers, not even a fabricated snapshot ("X report generated
//   successfully. Download will begin shortly."), with no key_metrics
//   field for the frontend to render even if it wanted to. Rewritten with
//   real computed metrics plus an LLM-grounded summary/recommendations.
//   The frontend's ReportsTab discarded the response entirely (just a
//   toast) — now renders the real title/executive_summary/key_metrics/
//   recommendations, matching the pattern established on other pages.
// - Frontend: toggle/del (Task Library), markNotificationsRead had zero
//   error handling despite steAPI's write methods already correctly not
//   swallowing errors.
// - This page's own pre-existing seedScheduledTasksEnterprise (unlike every
//   other page this phase, this one already had seed data) had no
//   idempotency guard and ON CONFLICT DO NOTHING clauses with no actual
//   unique constraint to conflict on — every fresh `go run ./cmd/seed/demo`
//   silently appended another full duplicate batch. Confirmed live: this
//   dev DB had accumulated 720 ste_tasks rows (18 × 40 reseeds) before a
//   standard tenant-count guard was added and the duplicates cleaned up.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = [
  'Dashboard', 'Task Library', 'Upcoming', 'Exec History', 'Approvals',
  'Notifications', 'Analytics', 'Audit Trail', 'Reports',
];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Scheduled Tasks — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/scheduled-tasks');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/scheduled-tasks');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('Scheduled Tasks — regression guard: seed data exists and is not duplicated', () => {
  test('task library shows exactly the seeded 18 tasks, not an accumulated duplicate pile', async ({ page }) => {
    const tasks = await page.request.get('/api/ste/tasks').then(r => r.json());
    const realCount = Number(PSQL(`SELECT count(*) FROM ste_tasks WHERE tenant_id='9999';`));
    expect(realCount).toBe(18);
    expect(tasks.length).toBe(realCount);

    const dash = await page.request.get('/api/ste/dashboard').then(r => r.json());
    expect(dash.total_tasks).toBe(realCount);
  });
});

test.describe('Scheduled Tasks — regression guard: next_run_at is set for every schedule type', () => {
  test('a daily task (no cron_expr) gets a real next_run_at, not NULL', async ({ page }) => {
    const create = await page.request.post('/api/ste/tasks', {
      data: { name: 'e2e-daily-nextrun', task_type: 'vulnerability_scan', schedule_type: 'daily', enabled: true },
    });
    expect(create.ok()).toBeTruthy();
    const created = await create.json();

    const withinWindow = PSQL(`SELECT (next_run_at BETWEEN NOW() + INTERVAL '23 hours' AND NOW() + INTERVAL '25 hours') FROM ste_tasks WHERE id=${created.id};`);
    expect(withinWindow).toBe('t');

    PSQL(`DELETE FROM ste_audit WHERE tenant_id='9999' AND task_id='${created.task_id}'; DELETE FROM ste_tasks WHERE id=${created.id};`);
  });

  test('an event_based task correctly has no next_run_at at all', async ({ page }) => {
    const create = await page.request.post('/api/ste/tasks', {
      data: { name: 'e2e-event-nextrun', task_type: 'isolate_host', schedule_type: 'event_based', enabled: true },
    });
    const created = await create.json();
    const isNull = PSQL(`SELECT next_run_at IS NULL FROM ste_tasks WHERE id=${created.id};`);
    expect(isNull).toBe('t');

    PSQL(`DELETE FROM ste_audit WHERE tenant_id='9999' AND task_id='${created.task_id}'; DELETE FROM ste_tasks WHERE id=${created.id};`);
  });
});

test.describe('Scheduled Tasks — regression guard: dispatch is honest about task_type support', () => {
  test('a task_type with no real agent executor case fails honestly instead of faking a dispatch', async ({ page }) => {
    const id = Number(PSQL(`SELECT id FROM ste_tasks WHERE tenant_id='9999' AND task_id='ST-001015';`));
    const res = await page.request.post(`/api/ste/tasks/${id}/run`);
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.status).toBe('failed');

    const errMsg = PSQL(`SELECT error_message FROM ste_executions WHERE execution_id='${body.execution_id}';`);
    expect(errMsg).toContain('no execution backend');
  });
});

test.describe('Scheduled Tasks — regression guard: approving a task actually dispatches it', () => {
  test('deciding "approved" creates a real new execution, not just an approvals status flip', async ({ page }) => {
    // Self-contained rather than relying on the single seeded pending
    // approval (ST-001010), which a prior run of this same spec would
    // already have consumed by deciding it — a fresh requires_approval
    // task makes this repeatable regardless of run order/count.
    const create = await page.request.post('/api/ste/tasks', {
      data: { name: 'e2e-approval-dispatch', task_type: 'vulnerability_scan', schedule_type: 'one_time', enabled: true, requires_approval: true },
    });
    const created = await create.json();
    const runRes = await page.request.post(`/api/ste/tasks/${created.id}/run`);
    const runBody = await runRes.json();
    expect(runBody.status).toBe('pending_approval');

    const beforeCount = Number(PSQL(`SELECT count(*) FROM ste_executions WHERE tenant_id='9999' AND task_id='${created.task_id}';`));
    expect(beforeCount).toBe(0);

    const res = await page.request.post(`/api/ste/approvals/${runBody.approval_id}/decide`, { data: { decision: 'approved', note: 'e2e' } });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.execution_id).toBeTruthy();

    const afterCount = Number(PSQL(`SELECT count(*) FROM ste_executions WHERE tenant_id='9999' AND task_id='${created.task_id}';`));
    expect(afterCount).toBe(1);

    PSQL(`DELETE FROM ste_audit WHERE tenant_id='9999' AND task_id='${created.task_id}'; DELETE FROM ste_notifications WHERE tenant_id='9999' AND task_id='${created.task_id}'; DELETE FROM ste_executions WHERE tenant_id='9999' AND task_id='${created.task_id}'; DELETE FROM ste_approvals WHERE tenant_id='9999' AND task_id='${created.task_id}'; DELETE FROM ste_tasks WHERE id=${created.id};`);
  });
});

test.describe('Scheduled Tasks — regression guard: running executions actually resolve', () => {
  test('a completed agent task is reflected on GetSTEExecutions read, not stuck at running forever', async ({ page }) => {
    // Deliberately a fresh task with requires_approval left false — ST-001003
    // (the seeded vulnerability_scan task) requires approval, which would
    // make /run correctly return pending_approval instead of dispatching.
    const create = await page.request.post('/api/ste/tasks', {
      data: { name: 'e2e-sync-check', task_type: 'vulnerability_scan', schedule_type: 'one_time', enabled: true, requires_approval: false },
    });
    const created = await create.json();

    const run = await page.request.post(`/api/ste/tasks/${created.id}/run`);
    const runBody = await run.json();
    expect(runBody.status).toBe('running');

    const execRowID = Number(PSQL(`SELECT id FROM ste_executions WHERE execution_id='${runBody.execution_id}';`));
    const taskIDs = PSQL(`SELECT agent_task_ids FROM ste_executions WHERE id=${execRowID};`);
    const ids: number[] = JSON.parse(taskIDs);
    expect(ids.length).toBeGreaterThan(0);
    PSQL(`UPDATE agent_tasks SET status='completed', result='ok', completed_at=NOW() WHERE id = ANY(ARRAY[${ids.join(',')}]);`);

    const list = await page.request.get(`/api/ste/executions?task_id=${created.task_id}`).then(r => r.json());
    const synced = list.find((e: any) => e.execution_id === runBody.execution_id);
    expect(synced.status).toBe('completed');

    PSQL(`DELETE FROM ste_audit WHERE tenant_id='9999' AND task_id='${created.task_id}'; DELETE FROM ste_notifications WHERE tenant_id='9999' AND task_id='${created.task_id}'; DELETE FROM ste_executions WHERE tenant_id='9999' AND task_id='${created.task_id}'; DELETE FROM ste_tasks WHERE id=${created.id};`);
  });
});

test.describe('Scheduled Tasks — regression guard: analytics by_category is populated, not always empty', () => {
  test('GetSTEAnalytics returns real per-category stats instead of an undefined-column empty array', async ({ page }) => {
    const analytics = await page.request.get('/api/ste/analytics').then(r => r.json());
    expect(analytics.by_category.length).toBeGreaterThan(0);
    const secOps = analytics.by_category.find((c: any) => c.category === 'security_operations');
    expect(secOps).toBeTruthy();
    expect(secOps.total).toBeGreaterThan(0);
  });
});

test.describe('Scheduled Tasks — regression guard: report has real numbers, not a canned stub', () => {
  test('PostSTEReport returns real key_metrics, not the old zero-data placeholder', async ({ page }) => {
    const res = await page.request.post('/api/ste/report', { data: { report_type: 'execution' } });
    expect(res.ok()).toBeTruthy();
    const report = await res.json();

    const realTotal = Number(PSQL(`SELECT count(*) FROM ste_tasks WHERE tenant_id='9999';`));
    expect(report.key_metrics).toBeTruthy();
    expect(report.key_metrics.total_tasks).toBe(realTotal);
    expect(report.executive_summary).not.toContain('Download will begin shortly');
  });
});
