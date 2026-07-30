import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Approval Queue page (route
// /soar-approvals) — the human-approval-gate/break-glass system backing
// `aq_requests` (already used for real by OT/ICS's block_network_path/
// escalate_emergency actions, confirmed via grep as the only other real
// caller of this table this phase).
//
// Real bugs found and fixed:
// - `GetAQDashboard`/`GetAQAnalytics` had `avg_approval_time_min`/
//   `sla_compliance` hardcoded to fixed literals (12.4 / 91.2) despite the
//   real `approved_at`/`created_at`/`due_at` columns already existing to
//   compute both honestly — wired to real aggregations.
// - `GetAQEvidence` was a fully fabricated "investigation drawer" (fake
//   incident id "INC-2026-0714-001", 3 fake alerts, a fake threat-intel
//   card, a fake process tree, fake security-event logs) that completely
//   ignored the `:id` path param — the same "huge fake-data drawer"
//   pattern already fixed on the Alerts page earlier this phase. Rewired
//   to real data derived from the request's own stored `incident_id`/
//   `alert_id`/`target_asset`/`target_user` fields: a real `incidents`
//   row, real related `alerts` sharing the same agent, and a real IOC
//   match against `target_asset`/`target_user`. `process_tree`/
//   `recent_logs` were dropped entirely — no real per-request linkage to
//   either concept exists anywhere in this schema.
// - `GetAQAnalytics`'s `by_category` was hardcoded (5 fixed fake rows);
//   `by_team` had no real team concept anywhere on `aq_requests` (only a
//   free-text `current_approver` username) — replaced with a real
//   `by_approver` breakdown grouped on the actual approver; `trend`'s 8
//   hardcoded `{date:"07-10",...}` entries were already stale — wired to
//   real daily aggregation.
// - `GetAQApprovers` was a fully fabricated 6-person fake org chart
//   (fictional names/roles/teams) — replaced with the real `users` table.
// - `PostAQReport` was a fully fabricated static report (132 requests,
//   94.7% approved, fictional recommendations) — rewritten to real
//   statistics plus an LLM-generated summary grounded only in those real
//   numbers.
// - Found a real, separate infra gap while reading `GetAQDashboard`: the
//   `expired` status/count already existed everywhere (dashboard card,
//   analytics, `STATUS_COLOR` map) but nothing anywhere ever transitioned
//   a stale-past-`due_at` pending request into it — added
//   `ExpireStaleApprovals()` to the existing 30s scheduler loop in
//   `services/scheduler_service.go` (alongside the pre-existing
//   `ExpireStaleTasks()`), confirmed live: 2 real pending requests created
//   earlier this session (via OT/ICS's `escalate_emergency`) were
//   correctly picked up and marked `expired` once the fix deployed.
// - Also fixed missing error handling on `onDecide`/`onDelegate`/
//   `onEmergency`/`onAddComment` (no try/catch at all, despite the
//   `aqAPI` client already correctly not swallowing errors on these
//   write methods — this page never had the client-side swallow bug,
//   just a missing catch at the call site).
//
// Like every other page this phase: none of this page's own tables had
// meaningful seed data (2 real rows existed only from live-testing OT/ICS
// earlier this session) — added `seedApprovalQueue` to
// `cmd/seed/demo/main.go` (6 policies, 6 requests spanning pending/
// approved/rejected/expired with real decisions/audit-trail/comments),
// guarded on a seeder-specific `AQ-SEED-%` approval_id prefix rather than
// a blanket row count so it coexists correctly with the pre-existing
// organic rows. Caught and fixed a real duplicate-seed bug in the
// seeder's own first draft: the policies block shared the requests
// block's idempotency guard, so deleting only the seeded requests (as
// done once during manual verification) caused a re-run to silently
// duplicate all 6 policies — gave policies their own independent
// existence check.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = ['Dashboard', 'Approval Queue', 'Policies & Matrix', 'Analytics', 'Audit Trail', 'Reports'];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Approval Queue — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/soar-approvals');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      // Approval Queue carries a real "(N)" pending-count badge once real
      // pending aq_requests exist, so match by prefix rather than an exact
      // "Approval Queue" string.
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/soar-approvals');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      // Approval Queue carries a real "(N)" pending-count badge once real
      // pending aq_requests exist, so match by prefix rather than an exact
      // "Approval Queue" string.
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('Approval Queue — regression guard: seed data exists', () => {
  test('the queue and dashboard show real seeded requests, not an empty page', async ({ page }) => {
    const queue = await page.request.get('/api/aq/queue').then(r => r.json());
    const realCount = Number(PSQL(`SELECT count(*) FROM aq_requests WHERE tenant_id=9999;`));
    expect(realCount).toBeGreaterThan(0);
    expect(queue.length).toBe(realCount);

    const dash = await page.request.get('/api/aq/dashboard').then(r => r.json());
    expect(dash.total_requests).toBe(realCount);
  });

  test('policies are real and were not duplicated by the seeder', async ({ page }) => {
    const policies = await page.request.get('/api/aq/policies').then(r => r.json());
    const realCount = Number(PSQL(`SELECT count(*) FROM aq_policies WHERE tenant_id=9999;`));
    expect(realCount).toBe(6);
    expect(policies.length).toBe(realCount);
  });
});

test.describe('Approval Queue — regression guard: dashboard/analytics are computed, not hardcoded', () => {
  test('avg_approval_time_min and sla_compliance are not the old fixed 12.4 / 91.2', async ({ page }) => {
    const dash = await page.request.get('/api/aq/dashboard').then(r => r.json());
    const realAvg = Number(PSQL(`SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (approved_at-created_at))/60),0) FROM aq_requests WHERE tenant_id=9999 AND status='approved';`));
    expect(Math.abs(dash.avg_approval_time_min - realAvg)).toBeLessThan(0.5);
  });

  test('by_category and by_approver reflect real seeded data', async ({ page }) => {
    const res = await page.request.get('/api/aq/analytics').then(r => r.json());
    expect(res.by_category.length).toBeGreaterThan(0);
    const endpointCat = res.by_category.find((c: any) => c.category === 'endpoint');
    expect(endpointCat).toBeTruthy();
    expect(res.by_approver.length).toBeGreaterThan(0);
    expect(res.by_approver[0].approver).toBe('admin');
  });

  test('dashboard by_policy reflects real approved-request policies, not an arbitrary 25/35/28/12 split of the approved count', async ({ page }) => {
    const dash = await page.request.get('/api/aq/dashboard').then(r => r.json());
    const realTotal = dash.by_policy.reduce((sum: number, p: any) => sum + p.count, 0);
    expect(realTotal).toBe(dash.approved);
    // The old fake breakdown always had exactly these 4 labels regardless
    // of real data; the real one is grouped on whatever policies actually
    // appear on approved rows (this seed data uses 'automatic' and
    // 'dual_approval', not 'soc_lead'/'manager_approval' split evenly).
    expect(dash.by_policy.some((p: any) => p.policy === 'soc_lead')).toBeFalsy();
  });

  test('dashboard by_category totals match the real request count', async ({ page }) => {
    const dash = await page.request.get('/api/aq/dashboard').then(r => r.json());
    const realTotal = dash.by_category.reduce((sum: number, c: any) => sum + c.count, 0);
    expect(realTotal).toBe(dash.total_requests);
  });

  test('approvers are real users, not the old fake 6-person roster', async ({ page }) => {
    const res = await page.request.get('/api/aq/approvers');
    expect(res.ok()).toBeTruthy();
    const approvers = await res.json();
    expect(approvers.some((a: any) => a.id === 'admin')).toBeTruthy();
    expect(approvers.some((a: any) => a.id === 'j.smith')).toBeFalsy();
  });
});

test.describe('Approval Queue — regression guard: evidence panel is real, not fabricated', () => {
  test('a request whose target_asset matches a real IOC returns real threat intel', async ({ page }) => {
    const rid = Number(PSQL(`SELECT id FROM aq_requests WHERE tenant_id=9999 AND approval_id='AQ-SEED-000003';`));
    const res = await page.request.get(`/api/aq/queue/${rid}/evidence`).then(r => r.json());
    expect(res.threat_intel).toBeTruthy();
    expect(res.threat_intel.indicator).toBe('185.220.101.45');
    expect(res).not.toHaveProperty('process_tree');
    expect(res).not.toHaveProperty('recent_logs');
  });

  test('a request with no linked incident/alert/IOC returns an honest empty object, not fake data', async ({ page }) => {
    const rid = Number(PSQL(`SELECT id FROM aq_requests WHERE tenant_id=9999 AND approval_id='AQ-SEED-000001';`));
    const res = await page.request.get(`/api/aq/queue/${rid}/evidence`).then(r => r.json());
    expect(res).toEqual({});
  });
});

test.describe('Approval Queue — regression guard: expiry is real, not a dead status', () => {
  test('a pending request past its due_at gets marked expired by the scheduler, not stuck pending forever', async ({ page }) => {
    test.setTimeout(90_000);
    const res = await page.request.post('/api/aq/queue', {
      data: { requested_action: 'e2e expiry test action', action_category: 'endpoint', severity: 'low', risk_level: 'low' },
    });
    const body = await res.json();
    // Force this request's due_at into the past — the same shape the
    // scheduler already found "naturally" for the 2 real OT/ICS rows from
    // earlier this session.
    execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -c "UPDATE aq_requests SET due_at=NOW()-INTERVAL '1 hour' WHERE id=${body.id};"`);

    // The scheduler ticks every 30s (services/scheduler_service.go) — give
    // it two full cycles of headroom rather than racing the first one.
    await expect.poll(
      () => PSQL(`SELECT status FROM aq_requests WHERE id=${body.id};`),
      { timeout: 65_000, intervals: [3000] },
    ).toBe('expired');
  });
});

test.describe('Approval Queue — regression guard: report uses real numbers', () => {
  test('report key statistics reflect the real request count, not a fixed 132', async ({ page }) => {
    const res = await page.request.post('/api/aq/report', { data: {} }).then(r => r.json());
    const realCount = Number(PSQL(`SELECT count(*) FROM aq_requests WHERE tenant_id=9999;`));
    expect(res.statistics.total).toBe(realCount);
    expect(res.statistics.total).not.toBe(132);
  });
});
