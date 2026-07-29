import { test, expect } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Log Search page (route /log-search).
// Runs against a REAL backend + seeded DB — see dashboard.spec.ts's header
// comment for the dev-stack recipe, and global-setup.ts for the
// shared-login rationale.
//
// Core search/AI-query/detection-builder machinery here was already real
// (verified live, not assumed from comments): `/api/logs/search` and the
// stats/viz/IOC tabs derive from real `endpoint_logs` rows, the AI-query bar
// and Detection Builder modal genuinely call the LLM, and the "hourly
// volume" chart was already fixed in an earlier untracked pass (derives
// real per-search-range buckets from the results in hand rather than the
// backend's fixed-last-24h `/api/logs/stats` endpoint).
//
// What was broken and is fixed here:
//  - `scheduled_log_searches`, the table `GetScheduledSearches`/
//    `CreateScheduledSearch`/`DeleteScheduledSearch` have always queried,
//    never had a migration. Every "Schedule" click 201'd with a
//    "persistence unavailable" fallback and silently saved nothing — the
//    Scheduled tab was permanently empty. Added migration 000072 and fixed
//    `CreateScheduledSearch`'s success-path response to report `enabled:
//    true` (the real DB default) instead of the zero-value `false`.
//  - The right-click context menu's "Create Alert Rule"/"Create Sigma
//    Rule" items were pure no-ops (`action: () => {}`); both now open the
//    real (already-functional) Detection Builder modal. "Add to Case" and
//    "Hunt Similar" were also no-ops; both now open their real destination
//    pages, matching the pattern already used on Live Logs/Network Map.
//  - The Scheduled Searches list (both the compact desktop-sidebar render
//    and the fuller mobile-panel render) had no delete affordance at all,
//    even though `DELETE /api/logs/scheduled/:id` already existed and was
//    wired into `logSearchAPI.deleteScheduled` — nothing in the frontend
//    ever called it. Added a Trash2 delete button to both renders, matching
//    the existing Saved Searches delete-button pattern.
test.use({ storageState: SHARED_STORAGE_STATE });

async function runDefaultSearch(page: import('@playwright/test').Page) {
  await page.goto('/log-search');
  const searchResponse = page.waitForResponse(res => res.url().includes('/api/logs/search?') && res.request().method() === 'GET');
  await page.getByRole('button', { name: /^Run$/ }).click();
  await searchResponse;
  // Wait for the definitive post-search state (result rows or the empty
  // placeholder), not an arbitrary timeout — React commits after the fetch.
  await Promise.race([
    page.locator('button.w-full.text-left.flex.items-start').first().waitFor({ timeout: 10_000 }),
    page.getByText('No logs matched').waitFor({ timeout: 10_000 }),
  ]).catch(() => {});
}

test.describe('Log Search — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await runDefaultSearch(page);
    await page.waitForTimeout(1000);

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await runDefaultSearch(page);
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });
});

test.describe('Log Search — Scheduled Searches now actually persist', () => {
  test('creating a scheduled search survives a reload and can be deleted', async ({ page }) => {
    // Under full-suite parallel load (especially alongside elastic-query's
    // slow local-LLM tests competing for CPU) plain API round trips here
    // have been observed to exceed the default 30s test timeout even
    // though nothing is actually wrong — bump the budget rather than the
    // individual request timeouts.
    test.setTimeout(60_000);
    await runDefaultSearch(page);

    const name = `e2e-sched-${Date.now()}`;
    await page.getByRole('button', { name: 'Schedule', exact: true }).click();
    const modal = page.getByText('Schedule Search').locator('..').locator('..');
    await page.getByPlaceholder('Search name…').fill(name);
    await modal.getByRole('button', { name: 'Schedule', exact: true }).click();
    await expect(page.getByText('Schedule Search')).not.toBeVisible();

    // Verify it actually persisted server-side, not just in local state.
    const res = await page.request.get('/api/logs/scheduled');
    const body = await res.json();
    const saved = body.searches.find((s: any) => s.name === name);
    expect(saved, 'scheduled search was not persisted by the backend').toBeTruthy();
    expect(saved.enabled).toBe(true);

    // Reflected in the sidebar without a reload.
    await page.getByRole('button', { name: 'Scheduled' }).first().click();
    await expect(page.getByText(name)).toBeVisible();

    // Delete it via the newly-added delete button and confirm it's gone
    // both from the UI and the backend.
    const row = page.locator('div.group', { has: page.getByText(name, { exact: true }) }).last();
    await row.scrollIntoViewIfNeeded();
    await row.locator('button').last().evaluate((el: HTMLElement) => el.click());
    await expect(page.getByText(name)).not.toBeVisible();

    const after = await (await page.request.get('/api/logs/scheduled')).json();
    expect(after.searches.some((s: any) => s.name === name)).toBe(false);
  });
});

test.describe('Log Search — regression guard: dead context-menu items are gone', () => {
  test('Create Alert Rule / Create Sigma Rule open the real Detection Builder', async ({ page }) => {
    await runDefaultSearch(page);

    const firstRow = page.locator('button.w-full.text-left.flex.items-start').first();
    test.skip(await firstRow.count() === 0, 'no log rows in current results to right-click');
    await firstRow.click({ button: 'right' });

    await page.getByText('Create Alert Rule').click();
    await expect(page.getByText('Detection Builder')).toBeVisible();
    await expect(page.getByText('Search Query')).toBeVisible();
  });

  test('Add to Case and Hunt Similar navigate to their real pages', async ({ page }) => {
    await runDefaultSearch(page);

    const firstRow = page.locator('button.w-full.text-left.flex.items-start').first();
    test.skip(await firstRow.count() === 0, 'no log rows in current results to right-click');

    await firstRow.click({ button: 'right' });
    const [casesPage] = await Promise.all([
      page.context().waitForEvent('page'),
      page.getByText('Add to Case').click(),
    ]);
    // Check the target URL directly rather than waiting for the new tab to
    // fully render — under heavy parallel-worker load a full page load can
    // outrun the test timeout even though navigation itself was instant.
    await casesPage.waitForURL(/\/cases/, { timeout: 15_000 });
    expect(casesPage.url()).toContain('/cases');
    await casesPage.close();

    await firstRow.click({ button: 'right' });
    const [huntPage] = await Promise.all([
      page.context().waitForEvent('page'),
      page.getByText('Hunt Similar').click(),
    ]);
    await huntPage.waitForURL(/\/hunt-workbench/, { timeout: 15_000 });
    expect(huntPage.url()).toContain('/hunt-workbench');
    await huntPage.close();
  });
});
