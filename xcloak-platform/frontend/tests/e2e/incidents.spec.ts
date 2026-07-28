import { test, expect, Page } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Incidents page (list + detail view). Runs
// against a REAL backend + seeded DB — see dashboard.spec.ts's header comment
// for the dev-stack recipe and global-setup.ts for the shared-login rationale.
//
// Real bugs found and fixed on this page:
//   - "MTTC" (Mean contain time) was fabricated as MTTR*0.7, no independent
//     basis — removed.
//   - The real MTTR query itself was silently broken (referenced a column,
//     `updated_at`, that doesn't exist on `incidents` — only `resolved_at`
//     does) so it always returned 0.0. Fixed to use the real column.
//   - The detail view's "SLA Tracking" section invented 4 of 5 sub-milestones
//     (Time to Acknowledge/Assign/Investigate/Contain) with zero real
//     tracking anywhere in the schema — removed.
//   - "Exploitability" in Risk Assessment was a fake severity-bucket with no
//     real basis — removed.
//   - "Executive PDF Report"/"Technical DFIR Report"/"STIX / TAXII Export"
//     were dead `href="#"` links with no feedback — converted to honest
//     "coming soon" toasts.
//   - Response-action dispatch swallowed the backend's real 501 reason
//     ("no identity provider integration configured") behind a generic
//     "check permissions" message that reads like an RBAC problem — fixed
//     to surface the actual backend error.
test.use({ storageState: SHARED_STORAGE_STATE });

function kpiValue(page: Page, label: string) {
  return page.locator('.g-card', { hasText: label }).first().locator('p.font-bold').first();
}

async function openFirstIncident(page: Page) {
  await page.goto('/incidents');
  await expect(page.locator('.g-tr').first()).toBeVisible({ timeout: 15_000 });
  await page.locator('.g-tr').first().click();
}

test.describe('Incidents — route health', () => {
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

    await page.goto('/incidents');
    await page.waitForLoadState('networkidle', { timeout: 15_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/incidents');
    await expect(page.locator('.g-tr').first()).toBeVisible({ timeout: 15_000 });

    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });

  test('KPI strip (Total/Open/Investigating) matches live /api/incidents/counts', async ({ page }) => {
    const counts = await (await page.request.get('/api/incidents/counts')).json();
    const total = Object.values(counts as Record<string, number>).reduce((a, b) => a + b, 0);

    await page.goto('/incidents');
    await expect(kpiValue(page, 'Total')).toHaveText(String(total), { timeout: 15_000 });
    await expect(kpiValue(page, 'Open')).toHaveText(String(counts.open ?? 0), { timeout: 15_000 });
    await expect(kpiValue(page, 'Investigating')).toHaveText(String(counts.investigating ?? 0), { timeout: 15_000 });
  });
});

test.describe('Incidents — detail view regression guard', () => {
  test('no fabricated metrics survive (MTTC, fake SLA sub-milestones, fake Exploitability)', async ({ page }) => {
    await openFirstIncident(page);
    await expect(page.locator('h1, p', { hasText: /./ }).first()).toBeVisible({ timeout: 15_000 });

    const bodyText = await page.locator('body').innerText();
    for (const banned of [
      'MTTC', 'Mean contain time',
      'Time to Acknowledge', 'Time to Assign', 'Time to Investigate', 'Time to Contain',
      'Exploitability',
    ]) {
      expect(bodyText, `found banned fabricated string: "${banned}"`).not.toContain(banned);
    }
  });

  test('detail view renders without console errors', async ({ page }) => {
    const consoleErrors: string[] = [];
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await openFirstIncident(page);
    await page.waitForLoadState('networkidle', { timeout: 15_000 });

    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('an unimplemented response action surfaces the real backend reason, not a generic "permissions" message', async ({ page }) => {
    await openFirstIncident(page);

    await page.getByRole('button', { name: 'Disable User' }).click();
    await page.getByPlaceholder('Username…').fill('jdoe');
    await page.getByRole('button', { name: 'Run', exact: true }).click();

    await expect(page.getByText(/no identity provider integration configured/i)).toBeVisible({ timeout: 10_000 });
  });

  test('a real response action (Isolate Host) dispatches against the live backend', async ({ page }) => {
    await openFirstIncident(page);

    await page.getByRole('button', { name: 'Isolate Host' }).click();
    // Scoped to the toast specifically — "isolate_host" also legitimately
    // appears in the recommendations/timeline text on this page.
    await expect(page.locator('div.fixed.bottom-4.right-4')).toContainText(/isolate_host/i, { timeout: 10_000 });
  });

  test('"coming soon" export buttons give feedback instead of doing nothing', async ({ page }) => {
    await openFirstIncident(page);

    await page.getByRole('button', { name: 'Executive PDF Report' }).click();
    await expect(page.getByText(/coming soon/i)).toBeVisible({ timeout: 5_000 });
  });
});
