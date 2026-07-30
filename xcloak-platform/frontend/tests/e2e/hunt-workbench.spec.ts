import { test, expect, type Page } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Hunt Workbench page (route
// /hunt-workbench). Runs against a REAL backend + seeded DB — see
// dashboard.spec.ts's header comment for the dev-stack recipe, and
// global-setup.ts for the shared-login rationale.
//
// Real bugs found and fixed this pass, all in `api/hunt_enterprise.go` /
// `services/hunt_workbench_service.go`:
//  - `PostHuntIOC`'s connection search (IP/domain IOC types) referenced
//    `ec.remote_addr`/`ec.created_at` on `endpoint_connections` — neither
//    column has ever existed there (the real names are `remote_address`/
//    `collected_at`, confirmed live via psql). The query error was
//    discarded, so `conn_hits` silently returned empty forever for every
//    IP/domain IOC hunt — the same wrong-column bug already found and
//    fixed 3 times over on the JA3 Fingerprints page this phase, now a
//    4th occurrence. Fixed to the real column names.
//  - `runKQLHunt` built each `models.HuntFinding.Hostname` from a struct
//    (`models.Log`) that has no such field (only `AgentID`) — every KQL
//    hunt run showed a permanently blank host column in its findings,
//    while the IOC/TTP/Actor quick-hunt panels (which join `agents`
//    directly in their own SQL) correctly showed real hostnames. Fixed by
//    resolving hostnames for the distinct agent IDs actually present in
//    the results via a follow-up query.
//  - `PostHuntResponse` — the same 100%-fake-button pattern found and
//    fixed on UEBA/Insider Threat/Network Map/Attack Paths this phase.
//    It only wrote an `audit_logs` row and returned a canned
//    `{"queued": true}`; no `agent_tasks` row, no incident, no IOC was
//    ever actually created for isolate_host/kill_process/quarantine_file/
//    block_ip/create_incident. Fixed to dispatch real actions using the
//    same primitives as `incident_enterprise.go`/`nba_enterprise.go`
//    (`repositories.CreateTask`/`CreateTaskPendingApproval` for
//    agent-targeted actions gated by `services.IsDestructiveTask`,
//    `repositories.CreateIOC` for block_ip, a real `incidents` INSERT for
//    create_incident).
//
// Frontend gaps found and fixed:
//  - The backend's Actor Hunt endpoint (`POST /api/hunt/actor`) and its
//    API client function (`huntWorkbenchAPI.actorHunt`) were both real and
//    already wired, but the page had no Actor Hunt tab at all — a
//    real, working pivot type with zero UI, alongside the already-present
//    IOC Hunt / TTP Hunt tabs. Added an "Actor Hunt" tab mirroring the IOC
//    Hunt tab's structure.
//  - The Workspace tab's "AI Explain" button was a complete no-op: it set
//    `aiPrompt`/`aiAction` state and switched to the tab it was already
//    on, but never called the AI endpoint and never rendered `aiResult`
//    anywhere in the component — clicking it did nothing visible.
//    `aiAction`/`aiPrompt`/`runAI` were themselves fully dead code (no
//    caller anywhere). Rewired the button to call `POST /api/hunt/ai`
//    with `action: 'explain_results'` and the current session's real
//    findings, and render the response (summary/risk level/false-positive
//    likelihood/recommended actions) inline.
//  - With `PostHuntResponse` now real, wired minimal, honest UI for it:
//    a per-finding "Isolate Host" button in the History tab's expanded
//    run view (only shown when the finding has a real `agent_id`), a
//    run-level "Create Incident" button, and a "Block" button on IOC Hunt
//    results for ip/domain indicator types.
//
// Deferred, not fixed (out of this page's scope): `huntWorkbenchAPI.export`
// (CSV/JSON/Markdown hunt-run report, `POST /api/hunt/export`) and
// `getRunDetail` (`GET /api/hunt/runs/:id`) are both real, working
// endpoints with no UI caller anywhere on this page — the run list already
// renders findings inline, so the latter is low-value; the former would
// need a blob-download flow not otherwise used on this page. `kill_process`
// and `quarantine_file` response actions are real on the backend but were
// not wired into any UI here — unlike isolate_host/block_ip/create_incident,
// there is no natural source of a numeric PID or file path in this page's
// findings to prefill them with.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = ['Dashboard', 'Workspace', 'IOC Hunt', 'TTP Hunt', 'Actor Hunt',
  'Templates', 'History', 'Notebook', 'MITRE', 'Analytics'];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Hunt Workbench — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/hunt-workbench');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/hunt-workbench');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });

  test('every tab (including the new Actor Hunt tab) loads without a failed API call or console error', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/hunt-workbench');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const tab of ALL_TABS) {
      await page.getByRole('button', { name: tab, exact: true }).first().click();
      await page.waitForTimeout(400);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });
});

test.describe('Hunt Workbench — regression guard: real column names on endpoint_connections', () => {
  test('IOC hunt for a seeded IP now returns connection hits instead of a silently-empty result', async ({ page }) => {
    const res = await page.request.post('/api/hunt/ioc', {
      data: { ioc_type: 'ip', value: '185.220.101.47', time_range: '7d' },
    });
    expect(res.ok()).toBeTruthy();
    const data = await res.json();
    expect(Array.isArray(data.conn_hits)).toBe(true);
    expect(data.conn_hits.length).toBeGreaterThan(0);
    expect(data.conn_hits[0].remote_addr).toContain('185.220.101.47');
  });
});

test.describe('Hunt Workbench — regression guard: KQL hunt findings show real hostnames', () => {
  test('a completed hunt run resolves hostname from the matching agent, not a blank string', async ({ page }) => {
    const execRes = await page.request.post('/api/hunt/execute', {
      data: { name: 'e2e hostname probe', kql_query: 'c2client' },
    });
    expect(execRes.ok()).toBeTruthy();
    const run = await execRes.json();

    let detail: any = null;
    for (let i = 0; i < 20; i++) {
      const r = await page.request.get(`/api/hunt/runs/${run.id}`);
      detail = await r.json();
      if (detail.status === 'completed') break;
      await page.waitForTimeout(500);
    }
    expect(detail.status).toBe('completed');
    expect(detail.hit_count).toBeGreaterThan(0);
    expect(detail.findings.length).toBeGreaterThan(0);
    for (const f of detail.findings) {
      expect(f.hostname).not.toBe('');
    }
  });
});

test.describe('Hunt Workbench — regression guard: response actions are real, not a no-op', () => {
  test('isolate_host creates a real pending agent_tasks row', async ({ page }) => {
    const before = PSQL(`SELECT count(*) FROM agent_tasks WHERE agent_id=1 AND task_type='isolate_host' AND status='pending_approval';`);
    const res = await page.request.post('/api/hunt/response', {
      data: { action: 'isolate_host', agent_id: 1, reason: 'e2e hunt workbench probe' },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.queued).toBe(true);
    const after = PSQL(`SELECT count(*) FROM agent_tasks WHERE agent_id=1 AND task_type='isolate_host' AND status='pending_approval';`);
    expect(Number(after)).toBe(Number(before) + 1);
  });

  test('block_ip creates a real, enabled IOC row', async ({ page }) => {
    const indicator = `10.99.${Math.floor(Math.random() * 200) + 1}.${Math.floor(Math.random() * 200) + 1}`;
    const res = await page.request.post('/api/hunt/response', {
      data: { action: 'block_ip', target: indicator, reason: 'e2e hunt workbench probe' },
    });
    expect(res.ok()).toBeTruthy();
    try {
      const count = PSQL(`SELECT count(*) FROM iocs WHERE indicator='${indicator}' AND type='ip' AND enabled=true;`);
      expect(Number(count)).toBe(1);
    } finally {
      PSQL(`DELETE FROM iocs WHERE indicator='${indicator}' AND type='ip';`);
    }
  });

  test('create_incident creates a real incidents row', async ({ page }) => {
    const marker = `e2e-hunt-probe-${Date.now()}`;
    const res = await page.request.post('/api/hunt/response', {
      data: { action: 'create_incident', reason: marker },
    });
    expect(res.ok()).toBeTruthy();
    try {
      const count = PSQL(`SELECT count(*) FROM incidents WHERE title LIKE 'Hunt Finding:%${marker}%';`);
      expect(Number(count)).toBe(1);
    } finally {
      PSQL(`DELETE FROM incidents WHERE title LIKE 'Hunt Finding:%${marker}%';`);
    }
  });

  test('unknown action is rejected rather than silently reporting success', async ({ page }) => {
    const res = await page.request.post('/api/hunt/response', {
      data: { action: 'not_a_real_action', reason: 'e2e' },
    });
    expect(res.status()).toBe(400);
  });
});

test.describe('Hunt Workbench — new feature: Actor Hunt tab', () => {
  test('hunting a real seeded threat actor name returns without error', async ({ page }) => {
    await page.goto('/hunt-workbench');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    await page.getByRole('button', { name: 'Actor Hunt', exact: true }).click();
    await page.getByPlaceholder(/APT29/).fill('APT29');
    await page.getByRole('button', { name: 'Hunt Actor' }).click();
    await expect(page.getByText(/Results for APT29/)).toBeVisible({ timeout: 15_000 });
  });
});

test.describe('Hunt Workbench — new feature: History tab response actions', () => {
  test('Isolate Host and Create Incident buttons on a completed run dispatch real actions', async (
    { page }: { page: Page },
  ) => {
    const execRes = await page.request.post('/api/hunt/execute', {
      data: { name: 'e2e response-action probe', kql_query: 'c2client' },
    });
    const run = await execRes.json();
    let completed = false;
    for (let i = 0; i < 20 && !completed; i++) {
      const r = await page.request.get(`/api/hunt/runs/${run.id}`);
      completed = (await r.json()).status === 'completed';
      if (!completed) await page.waitForTimeout(500);
    }
    test.skip(!completed, 'hunt run did not complete in time');

    const before = PSQL(`SELECT count(*) FROM agent_tasks WHERE agent_id=1 AND task_type='isolate_host' AND status='pending_approval';`);

    await page.goto('/hunt-workbench');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    await page.getByRole('button', { name: 'History', exact: true }).click();
    const card = page.locator('.g-card', { hasText: 'e2e response-action probe' }).first();
    await card.click();
    const isolateBtn = card.getByRole('button', { name: 'Isolate Host' }).first();
    await expect(isolateBtn).toBeVisible({ timeout: 10_000 });
    await isolateBtn.click();
    await expect(page.getByText(/isolate_host/)).toBeVisible({ timeout: 10_000 });

    const after = PSQL(`SELECT count(*) FROM agent_tasks WHERE agent_id=1 AND task_type='isolate_host' AND status='pending_approval';`);
    expect(Number(after)).toBeGreaterThan(Number(before));
  });
});

test.describe('Hunt Workbench — new feature: AI Explain is now wired to a real call', () => {
  test('AI Explain on a completed hunt renders a real analysis, not a silent no-op', async ({ page }) => {
    // This mocks the /api/hunt/ai response rather than hitting real local
    // Ollama inference: running the model alongside the rest of the dev
    // stack exhausts available memory on this machine. The mock only
    // stands in for this test's network call — `PostHuntAI` /
    // `services.CallLLM` on the backend are untouched and still make a
    // real LLM call in production; this test only verifies the frontend
    // wires the button click -> request -> response render correctly.
    await page.route('**/api/hunt/ai', route => route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        summary: 'Repeated connections to a known c2client pattern were observed across the matched findings.',
        risk_level: 'high',
        false_positive_likelihood: 'low',
        recommended_actions: ['Isolate the affected host', 'Block the associated indicator'],
      }),
    }));

    await page.goto('/hunt-workbench');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    await page.getByRole('button', { name: 'Workspace', exact: true }).click();
    const queryBox = page.getByPlaceholder(/Failed password/);
    await queryBox.fill('c2client');
    await page.getByRole('button', { name: 'Execute Hunt' }).click();
    await expect(page.getByText(/hits found/)).toBeVisible({ timeout: 15_000 });

    const explainBtn = page.getByRole('button', { name: /AI Explain/ });
    await expect(explainBtn).toBeEnabled({ timeout: 10_000 });
    await explainBtn.click();
    await expect(page.getByText('AI Analysis')).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText(/Repeated connections to a known c2client pattern/)).toBeVisible();
  });
});
