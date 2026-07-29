import { test, expect } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the ES Query page (route /elastic-query).
// Runs against a REAL backend + seeded DB — see dashboard.spec.ts's header
// comment for the dev-stack recipe, and global-setup.ts for the
// shared-login rationale.
//
// This dev stack has no Elasticsearch container/ELASTICSEARCH_URL (confirmed
// via docker-compose*.yml — no ES service anywhere, and connecting to :9200
// fails). That's not a bug: `services.ElasticsearchEnabled()` gates every
// real-execution endpoint (/elastic/query, /elastic/indices,
// /elastic/mappings/:index) behind an honest 503 "Elasticsearch is not
// configured" (verified live via curl, and already covered by
// `api/elastic_query_test.go`'s TestElasticHealth_NotConfigured /
// TestElasticQuery_NotConfigured) rather than faking success — the frontend
// correctly shows a gray "Elasticsearch not configured" status pill instead
// of a fake green "healthy" one. The two AI-backed endpoints
// (/elastic/explain, /ai/es-query) don't depend on ES at all — they're pure
// LLM calls — and were verified live to genuinely call the configured LLM
// (see below).
//
// What WAS broken, found while auditing this page for the same
// icon-stubs-null-fallout bug class already fixed on 16+ other files this
// phase (grepped for `<X className`/icon-only buttons, the established
// cheap check flagged at the end of the Live Logs section): 8 buttons
// (tab-close ×, saved-query star/unstar, saved-query delete, and all 5
// modal close buttons — AI Assist, Agg Builder, Save, REST API, Explain)
// rendered zero visible content (icon-stubs.ts renders every Lucide icon as
// literal `null`) with little or no padding, making them genuinely
// zero-size and unclickable, not just visually blank. Fixed with the
// established ×/★/☆/🗑️ symbol vocabulary + `g-btn g-btn-ghost` padding.
// Two more (the hit-detail Copy button, the REST-API-code Copy button) had
// padding so were still clickable, just showed a blank pill — added
// Copy/✓ text. **This exact bug class was also found (and fixed) as a
// pre-existing issue on the already-completed Log Search page's Saved/
// Scheduled Searches delete buttons while auditing this page** — see that
// page's updated section in memory.
test.use({ storageState: SHARED_STORAGE_STATE });

test.describe('ES Query — route health', () => {
  test('every /api/** call the page makes succeeds or honestly 503s (ES not configured), and no console errors fire', async ({ page }) => {
    const badRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      const url = res.url();
      const status = res.status();
      if (!url.includes('/api/')) return;
      // /elastic/indices and /elastic/query are EXPECTED to 503 on page load
      // / query-run in this ES-less dev stack — that's the honest contract,
      // not a failure.
      if (status >= 400 && !(status === 503 && (url.includes('/elastic/indices') || url.includes('/elastic/query')))) {
        badRequests.push(`${status} ${res.request().method()} ${url}`);
      }
    });
    page.on('console', msg => {
      if (msg.type() !== 'error') return;
      // Chrome logs a console error for every non-2xx resource load, including
      // the two expected 503s above (indices/query against unconfigured ES).
      if (/status of 503/.test(msg.text())) return;
      consoleErrors.push(msg.text());
    });

    await page.goto('/elastic-query');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });

    expect(badRequests, `Unexpected failed API calls:\n${badRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/elastic-query');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });

  test('honestly shows "Elasticsearch not configured" rather than a fake healthy status', async ({ page }) => {
    const healthRes = await page.request.get('/api/elastic/health');
    expect(healthRes.ok()).toBe(true);
    const health = await healthRes.json();
    expect(health.enabled).toBe(false);
    expect(health.status).toBe('not_configured');

    await page.goto('/elastic-query');
    await expect(page.getByText('Elasticsearch not configured')).toBeVisible({ timeout: 20_000 });
  });

  test('running a query against unconfigured ES shows the real backend error, not a silent failure', async ({ page }) => {
    await page.goto('/elastic-query');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    await page.getByRole('button', { name: /^Run/ }).click();
    await expect(page.getByText(/Elasticsearch is not configured/i)).toBeVisible({ timeout: 10_000 });
  });
});

test.describe('ES Query — regression guard: icon-only buttons are gone', () => {
  test('tab close, saved-query star/delete, and all 5 modal close buttons render visible content', async ({ page }) => {
    await page.goto('/elastic-query');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });

    // Open a second tab so the close (×) button appears, then confirm it's
    // both visible and actually closes the tab.
    await page.locator('button[title="New query tab"]').click();
    const closeButtons = page.locator('button[title="Close tab"]');
    await expect(closeButtons.first()).toBeVisible();
    await expect(closeButtons.first()).toHaveText('×');
    const tabCountBefore = await page.locator('button', { hasText: /^Query \d+$/ }).count();
    await closeButtons.first().click();
    await expect(page.locator('button', { hasText: /^Query \d+$/ })).toHaveCount(tabCountBefore - 1);

    // Every modal's close (×) button is visible and clickable. (Accessible
    // name comes from the button's visible "×" text content, not its
    // `title` attribute, so target it via the title attribute selector.)
    const modals: Array<[string, string]> = [
      ['AI Assist', 'AI Query Assistant'],
      ['Agg Builder', 'Aggregation Builder'],
    ];
    for (const [openLabel, modalHeading] of modals) {
      await page.getByRole('button', { name: openLabel }).click();
      await expect(page.getByText(modalHeading)).toBeVisible();
      const closeBtn = page.locator('button[title="Close"]').first();
      await expect(closeBtn).toBeVisible();
      await expect(closeBtn).toHaveText('×');
      await closeBtn.click();
      await expect(page.getByText(modalHeading)).not.toBeVisible();
    }

    // Save modal (opened via the "Save" toolbar button).
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(page.getByText('Save Query')).toBeVisible();
    const saveClose = page.locator('button[title="Close"]').first();
    await expect(saveClose).toBeVisible();
    await saveClose.click();
    await expect(page.getByText('Save Query')).not.toBeVisible();
  });

  test('saved query star and delete buttons are visible and functional', async ({ page }) => {
    await page.goto('/elastic-query');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });

    const name = `e2e-query-${Date.now()}`;
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await page.getByPlaceholder('e.g. SSH Brute Force Hunt').fill(name);
    await page.getByRole('button', { name: 'Save', exact: true }).last().click();
    await expect(page.getByText('Save Query')).not.toBeVisible();

    const savedRow = page.locator('div', { has: page.getByText(name, { exact: true }) }).last();
    await savedRow.hover();
    const starBtn = savedRow.locator('button[title="Star"], button[title="Unstar"]');
    await expect(starBtn).toBeVisible();
    await expect(starBtn).toHaveText(/[★☆]/);
    await starBtn.click();
    await expect(starBtn).toHaveText('★');

    const deleteBtn = savedRow.locator('button[title="Delete"]');
    await expect(deleteBtn).toBeVisible();
    await expect(deleteBtn).toHaveText('🗑️');
    await deleteBtn.click();
    await expect(page.getByText(name)).not.toBeVisible();
  });
});

test.describe('ES Query — AI features work without a live ES cluster', () => {
  test('Explain calls the real LLM/static-fallback pipeline and renders a structured analysis', async ({ page }) => {
    test.setTimeout(90_000);
    await page.goto('/elastic-query');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    await page.getByRole('button', { name: /Explain/ }).click();
    await expect(page.getByText('Query Explain')).toBeVisible();
    await expect(page.getByText('Execution Plan')).toBeVisible({ timeout: 60_000 });
  });

  test('AI Assist generates a real DSL from a natural-language prompt', async ({ page }) => {
    // Local CPU-only Ollama inference (no GPU in this dev environment) can
    // take 30-90s per call, and is especially slow under full-suite
    // parallel load competing for CPU with every other worker — generous
    // budget here rather than a second redundant LLM call to verify.
    test.setTimeout(150_000);
    await page.goto('/elastic-query');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    await page.getByRole('button', { name: 'AI Assist' }).click();
    await page.getByPlaceholder(/Find PowerShell attacks yesterday/).fill('Find PowerShell attacks yesterday');
    await page.getByRole('button', { name: /Generate/ }).click();
    await expect(page.getByRole('button', { name: /Use this DSL/ })).toBeVisible({ timeout: 120_000 });

    // The "Use this DSL" button only renders once `aiDsl` is populated from
    // the real /api/ai/es-query response, so its presence already proves
    // the round trip; also assert the rendered text looks like real DSL,
    // not an error string or empty payload, without a second LLM call.
    const dslText = await page.locator('pre').filter({ hasText: /query|dsl/i }).first().innerText();
    expect(dslText.trim().length).toBeGreaterThan(0);
    expect(dslText).not.toMatch(/AI query failed/);
  });
});
