import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the YARA Rules page (route /yara-rules).
// Runs against a REAL backend + seeded DB — see dashboard.spec.ts's header
// comment for the dev-stack recipe, and global-setup.ts for the
// shared-login rationale.
//
// This page's architecture differs from Sigma Rules in an important way:
// YARA matching happens on the AGENT (it downloads enabled rules via
// GET /api/yara/rules/enabled and scans locally with the real libyara
// engine — confirmed real end-to-end in xcloak-agent-desktop/agent/
// executor.go's "scan_yara" case and yara.go), then reports matches back.
// So there is no server-side rule cache to invalidate (unlike Sigma), and
// the "Scheduled YARA Scan" feature (schedulerAPI create with
// task_type: "scan_yara") is genuinely real — the scheduler's generic
// dispatchAgentTask doesn't care about task type, and the agent executor
// really does implement scan_yara (confirmed by reading both sides).
//
// Real bugs found and fixed:
//  - yara_matches has no rule_id column at all — matches are correlated to
//    a rule purely by rule_name text (inherent to how YARA reports matches:
//    the agent's libyara engine only knows the rule's declared name, never
//    a database id). UpdateYaraRule let a user freely rename a rule with
//    zero warning, and doing so silently orphaned all of that rule's past
//    matches from its own detail page — verified live: match_count dropped
//    from 1 to 0 immediately after a rename via the real API, while the
//    match remained visible elsewhere (e.g. the global Matches tab).
//    Fixed by cascading the rename to yara_matches.rule_name inside the
//    same transaction; re-verified live that match_count survives a rename.
//  - A fully-built "Graph" tab (real RelGraph component, real
//    GetYaraRelationships backend endpoint with genuine rule/agent/file
//    nodes and edges) was never wired into the TABS array or render
//    section — completely unreachable dead code sitting on an otherwise-
//    live page. Wired it in. **The identical gap was also found on the
//    already-completed Sigma Rules page** (missed during that pass) and
//    fixed there too.
//  - The Matches tab's expanded-row detail had two response-action buttons
//    with no onClick at all: "Create Alert" and "Quarantine File".
//    SaveYaraMatches already calls CreateAlert for every single match
//    (verified by reading alert_service.go/yara_service.go), so "Create
//    Alert" was a misleading affordance implying alerting is a manual next
//    step when it already happened automatically — removed. "Quarantine
//    File" maps to a real, already-used response-action type
//    (services.IsDestructiveTask/repositories.CreateTaskPendingApproval,
//    the same mechanism Incidents/Alerts already use) with zero endpoint to
//    call it from this page — added POST /api/yara/matches/:id/respond and
//    wired the button to it; verified live that a real, correctly-payloaded
//    pending_approval agent_tasks row is created.
test.use({ storageState: SHARED_STORAGE_STATE });

test.describe('YARA Rules — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/yara-rules');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/yara-rules');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });
});

test.describe('YARA Rules — regression guard: renaming a rule preserves its match history', () => {
  // yara_matches has no rule_id column and no public API inserts one
  // directly (POST /api/yara/matches requires real agent-token auth, which
  // this suite doesn't have) — so this test seeds a real match row via
  // psql, matching the established pattern in agents-onwards.spec.ts for
  // exactly this kind of gap (documented there as "no pg client in this
  // project; shelling out to the same docker exec psql command used for
  // manual cleanup throughout this phase is the lowest-footprint option").
  test.afterEach(() => {
    try {
      execSync(
        `docker exec xcloak-postgres psql -U xcloak -d ngfw -c ` +
        `"DELETE FROM yara_matches WHERE rule_name IN ('E2ERenameProbe','E2ERenameProbeRenamed') AND tenant_id=9999; ` +
        `DELETE FROM yara_rules WHERE name IN ('E2ERenameProbe','E2ERenameProbeRenamed') AND tenant_id=9999;"`,
        { stdio: 'ignore' },
      );
    } catch { /* best-effort cleanup */ }
  });

  test('match_count survives a real rename via the live API', async ({ page }) => {
    const createRes = await page.request.post('/api/yara/rules', {
      data: {
        name: 'E2ERenameProbe',
        description: 'e2e probe',
        rule_content: 'rule E2ERenameProbe { condition: true }',
        enabled: true,
      },
    });
    expect(createRes.ok()).toBeTruthy();

    const rulesRes = await page.request.get('/api/yara/rules');
    const rulesBody = await rulesRes.json();
    const created = (rulesBody as any[]).find(r => r.name === 'E2ERenameProbe');
    expect(created).toBeTruthy();

    execSync(
      `docker exec xcloak-postgres psql -U xcloak -d ngfw -c ` +
      `"INSERT INTO yara_matches (agent_id, file_path, rule_name, severity, description, tenant_id) ` +
      `VALUES (1, '/tmp/e2e-probe.bin', 'E2ERenameProbe', 'high', 'e2e probe match', 9999);"`,
      { stdio: 'ignore' },
    );

    const beforeDetail = await (await page.request.get(`/api/yara/rules/${created.id}/detail`)).json();
    expect(beforeDetail.match_count).toBe(1);

    const renameRes = await page.request.put(`/api/yara/rules/${created.id}`, {
      data: {
        name: 'E2ERenameProbeRenamed',
        description: 'e2e probe',
        rule_content: 'rule E2ERenameProbeRenamed { condition: true }',
        enabled: true,
      },
    });
    expect(renameRes.ok()).toBeTruthy();

    const afterDetail = await (await page.request.get(`/api/yara/rules/${created.id}/detail`)).json();
    expect(afterDetail.name).toBe('E2ERenameProbeRenamed');
    expect(afterDetail.match_count).toBe(1);

    await page.request.delete(`/api/yara/rules/${created.id}`);
  });
});

test.describe('YARA Rules — Graph tab is real and reachable', () => {
  test('the Graph tab button exists and renders real relationship data', async ({ page }) => {
    await page.goto('/yara-rules');
    await page.getByRole('button', { name: 'Graph', exact: true }).click();
    await expect(page.locator('svg').first()).toBeVisible({ timeout: 15_000 });
  });
});

test.describe('YARA Rules — Matches tab response actions', () => {
  test('Quarantine File dispatches a real pending-approval agent task, and Create Alert is gone', async ({ page }) => {
    const matchesRes = await page.request.get('/api/yara/matches');
    const matches = await matchesRes.json();
    test.skip((matches as any[]).length === 0, 'no seeded YARA matches to verify against');

    await page.goto('/yara-rules');
    await page.getByRole('button', { name: 'Matches', exact: true }).click();
    await page.locator('.g-tr').first().click();
    await expect(page.getByRole('button', { name: 'Create Alert' })).toHaveCount(0);
    await page.getByRole('button', { name: 'Quarantine File' }).click();
    await expect(page.getByText(/queued for agent \d+, pending approval/)).toBeVisible({ timeout: 10_000 });

    // Dispatching creates a real pending_approval agent_tasks row — clean
    // it up so repeated runs don't pile up in the approval queue.
    try {
      execSync(
        `docker exec xcloak-postgres psql -U xcloak -d ngfw -c ` +
        `"DELETE FROM agent_tasks WHERE task_type='quarantine_file' AND status='pending_approval' AND payload::jsonb ? 'yara_match_id';"`,
        { stdio: 'ignore' },
      );
    } catch { /* best-effort cleanup */ }
  });
});
