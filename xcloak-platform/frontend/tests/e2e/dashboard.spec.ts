import { test, expect, Page } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Dashboard page. Unlike the stubbed
// auth-guard/login specs, these run against a REAL backend + seeded DB
// (PLAYWRIGHT_BASE_URL / dev stack must be up) so we can catch:
//   - failed API calls the stubbed smoke tests can't see
//   - fields that render fabricated/hardcoded values instead of live data
//   - two independent data paths disagreeing on the same number
//
// Requires: docker-compose.dev.yml stack + `air` (backend) + `npm run dev`
// (frontend) running, and `admin` / `admin1234` seeded via `go run ./cmd/seed`.
//
// Auth: the whole suite logs in ONCE via global-setup.ts (see that file for
// why — /api/auth/login's 10/min rate limit) and every spec file reuses that
// single shared session instead of each one logging in fresh.
test.use({ storageState: SHARED_STORAGE_STATE });

function metricCard(page: Page, label: string) {
  return page.locator('.g-card', { hasText: label }).first();
}

// The dashboard's initial load fires ~10 concurrent API calls, then commits
// all of the resulting state in one batch — `networkidle` can fire a beat
// before that commit paints, so reads must use auto-retrying `expect(...)`
// matchers (not a one-shot `.innerText()`) to avoid a race, not a real bug.
function metricValueLocator(page: Page, label: string) {
  return metricCard(page, label).locator('p.font-bold').first();
}

test.describe('Dashboard — route health', () => {
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

    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle', { timeout: 15_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/dashboard');
    // Anchor on a value known to load asynchronously so we don't snapshot
    // body text mid-render (see metricValueLocator's comment above).
    await expect(metricValueLocator(page, 'Critical Alerts')).not.toHaveText('', { timeout: 15_000 });

    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });
});

test.describe('Dashboard — rendered numbers match live backend data', () => {
  test('Critical Alerts card matches /api/dashboard/overview', async ({ page }) => {
    await page.goto('/dashboard');

    const overview = await (await page.request.get('/api/dashboard/overview')).json();

    await expect(metricValueLocator(page, 'Critical Alerts')).toHaveText(String(overview.critical_alerts), { timeout: 15_000 });
  });

  test('Endpoints On/Off cards match /api/dashboard/metrics agent_coverage', async ({ page }) => {
    await page.goto('/dashboard');

    const metrics = await (await page.request.get('/api/dashboard/metrics?range=24h')).json();

    await expect(metricValueLocator(page, 'Endpoints On')).toHaveText(String(metrics.agent_coverage.online), { timeout: 15_000 });
    await expect(metricValueLocator(page, 'Endpoints Off')).toHaveText(String(metrics.agent_coverage.offline), { timeout: 15_000 });
  });

  test('Open Incidents card matches live /api/incidents (open + investigating)', async ({ page }) => {
    await page.goto('/dashboard');

    const incidents: Array<{ status: string }> = await (await page.request.get('/api/incidents')).json();
    const openCount = incidents.filter(i => i.status === 'open' || i.status === 'investigating').length;

    await expect(metricValueLocator(page, 'Open Incidents')).toHaveText(String(openCount), { timeout: 15_000 });
  });
});

test.describe('Dashboard — Compliance Posture panel', () => {
  test('per-framework breakdown matches /api/compliance/scores/latest exactly (no fabricated offsets)', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(metricValueLocator(page, 'Critical Alerts')).not.toHaveText('', { timeout: 15_000 });

    const scores: Array<{ framework: string; score: number }> =
      await (await page.request.get('/api/compliance/scores/latest')).json();

    if (scores.length === 0) {
      test.skip(true, 'no compliance report generated yet in this environment');
      return;
    }

    const panel = page.locator('.g-card', { hasText: 'Compliance Posture' }).first();
    await expect(panel).toBeVisible({ timeout: 15_000 });

    for (const { framework, score } of scores) {
      const row = panel.locator('div', { hasText: framework }).last();
      await expect(row).toContainText(`${score}%`, { timeout: 15_000 });
    }

    // Regression guard: the old implementation fabricated these exact
    // labels via hardcoded +/- offsets from the aggregate score — neither
    // is a framework this system actually computes scores for.
    await expect(panel).not.toContainText('HIPAA');
  });
});
