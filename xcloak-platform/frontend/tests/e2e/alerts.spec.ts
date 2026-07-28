import { test, expect, Page } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Alerts page + its detail drawer. Runs
// against a REAL backend + seeded DB — see dashboard.spec.ts's header comment
// for the dev-stack recipe and global-setup.ts for the shared-login rationale.
//
// This page's drawer (components/alerts/AlertDetailDrawer.tsx) used to render
// an entire fabricated investigation (fake risk/confidence scores that
// re-rolled via Math.random() on every render, a hardcoded "CORP\jdoe"/
// "Jane Doe"/"APT28"/"Corp Production" narrative identical for every alert,
// and action buttons like "Notify Slack"/"Create Jira Ticket" that claimed
// success with zero backend call). It was stripped down to only what's real.
// The regression-guard test below locks that in.
test.use({ storageState: SHARED_STORAGE_STATE });

async function openFirstAlert(page: Page) {
  await page.goto('/alerts');
  await expect(page.locator('.g-tr').first()).toBeVisible({ timeout: 15_000 });
  await page.locator('.g-tr').first().click();
  await expect(page.locator('.g-modal-backdrop, .fixed.inset-0.z-50').first()).toBeVisible({ timeout: 5_000 });
}

test.describe('Alerts — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];

    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });

    await page.goto('/alerts');
    await page.waitForLoadState('networkidle', { timeout: 15_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/alerts');
    await expect(page.locator('.g-tr').first()).toBeVisible({ timeout: 15_000 });

    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });

  test('subtitle total matches live /api/alerts/paginated total (status=all)', async ({ page }) => {
    const paged = await (await page.request.get('/api/alerts/paginated?status=all&per_page=50&page=1')).json();

    await page.goto('/alerts');
    await page.getByRole('button', { name: 'all', exact: true }).first().click();
    await expect(page.getByText(`${paged.total} total alerts`)).toBeVisible({ timeout: 15_000 });
  });
});

test.describe('Alerts — detail drawer regression guard', () => {
  test('no fabricated investigation content survives (fake scores, fake identities, fake actions)', async ({ page }) => {
    await openFirstAlert(page);

    const drawerText = await page.locator('.fixed.inset-0.z-50').first().innerText();

    // These were the exact hardcoded strings the drawer used to render for
    // every single alert, regardless of what actually triggered it.
    for (const banned of [
      'CORP\\jdoe', 'Jane Doe', 'APT28', 'Corp Production', 'Sigma Rule Engine',
      'evil-c2.io', '10.0.1.42', 'Emotet', 'Operation DealBreaker',
    ]) {
      expect(drawerText, `found banned fabricated string: "${banned}"`).not.toContain(banned);
    }

    // Fake-success action buttons that made no backend call.
    await expect(page.getByRole('button', { name: 'Notify Slack' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Create Jira Ticket' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Open Case' })).toHaveCount(0);
  });

  test('every tab renders without console errors', async ({ page }) => {
    const consoleErrors: string[] = [];
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await openFirstAlert(page);

    for (const tabName of ['Overview', 'Detection', 'AI', 'Actions', 'History']) {
      await page.getByRole('button', { name: tabName, exact: true }).click();
      await page.waitForTimeout(200);
    }

    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });
});

test.describe('Alerts — response actions dispatch the clicked action, not a stale one', () => {
  test('Isolate Host then Kill Process each send their own action_type', async ({ page }) => {
    // Regression guard for a stale-closure bug: dispatchResponse used to read
    // `responseAction` state set by a setResponseAction() call in the same
    // click handler, which hadn't committed yet — so every button actually
    // dispatched whichever action had been clicked *previously*, not its own.
    const dispatched: string[] = [];
    await page.route('**/api/alerts/*/respond', async route => {
      const body = route.request().postDataJSON();
      dispatched.push(body.action_type);
      await route.fulfill({ status: 200, body: JSON.stringify({ message: 'task dispatched' }) });
    });

    await openFirstAlert(page);
    await page.getByRole('button', { name: 'Actions', exact: true }).click();

    await page.getByRole('button', { name: 'Isolate Host' }).click();
    await expect.poll(() => dispatched.length).toBe(1);

    // "Process Actions" is a collapsed-by-default accordion section.
    await page.getByRole('button', { name: 'Process Actions' }).click();
    await page.getByRole('button', { name: 'Kill Process' }).click();
    await expect.poll(() => dispatched.length).toBe(2);

    expect(dispatched).toEqual(['isolate_host', 'kill_process']);
  });
});

test.describe('Alerts — acknowledge/resolve against the live backend', () => {
  // Regression guard: GetAlertsPaginated used to scan `agent_id` and several
  // other columns (fingerprint, mitre_tactic/technique/name, severity,
  // rule_name, log_message) into non-nullable Go fields with no COALESCE.
  // Any alert with a NULL agent_id (e.g. one created without a specific
  // agent, like DPI/NBA's create_alert response action) or a NULL MITRE
  // field (common — most alert sources don't set MITRE mapping) failed the
  // row scan and was silently dropped from `alerts` while still being
  // counted in `total` — real alerts could vanish from the very first page
  // of the Alerts list while the count claimed they existed.
  test('a real alert with a NULL agent_id and NULL MITRE fields still appears in the paginated list', async ({ page }) => {
    const createRes = await page.request.post('/api/dpi/response-action', {
      data: { action: 'create_alert', reason: 'e2e-null-agent-regression' },
    });
    expect(createRes.status()).toBe(200);

    const listRes = await page.request.get('/api/alerts/paginated?status=open&per_page=1&page=1');
    const list = await listRes.json();
    expect(list.total).toBeGreaterThan(0);
    // This is the exact regression: previously `alerts` was `[]` here even
    // though `total` was correctly nonzero.
    expect(list.alerts.length).toBeGreaterThan(0);
    expect(list.alerts[0].agent_id).toBe(0);
  });

  test('acknowledging an open alert persists and disappears from the Open filter', async ({ page }) => {
    const open = await (await page.request.get('/api/alerts/paginated?status=open&per_page=1&page=1')).json();
    test.skip(open.total === 0, 'no open alerts in this environment');
    const target = open.alerts[0];

    await page.goto('/alerts');
    await page.locator('.g-tr', { hasText: target.rule_name }).first().click();
    await page.getByRole('button', { name: 'Acknowledge', exact: true }).click();

    await expect(page.getByText('Alert acknowledged')).toBeVisible({ timeout: 10_000 });

    const after = await (await page.request.get(`/api/alerts/paginated?status=open&per_page=50&page=1`)).json();
    expect(after.alerts.some((a: { id: number }) => a.id === target.id)).toBe(false);
  });
});
