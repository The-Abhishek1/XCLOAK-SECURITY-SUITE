import { test, expect } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Log Sources page (route /log-sources).
// Runs against a REAL backend + seeded DB — see dashboard.spec.ts's header
// comment for the dev-stack recipe, and global-setup.ts for the
// shared-login rationale.
//
// This page uses real `lucide-react` icons (not the null-stubbed
// `lib/icon-stubs.ts` used elsewhere in this codebase), so the
// icon-stubs-null-fallout bug class found on several other pages this
// phase does not apply here.
//
// What was found and fixed, all in `api/log_sources_enterprise.go` +
// `app/log-sources/page.tsx`:
//  - Health tab's "Parsing"/"Auth" rows were hardcoded "ok" with zero real
//    check behind them — removed.
//  - Stats tab's "Compression: 3:1" and the storage-size estimate's implicit
//    ÷3 compression divisor were fabricated: migration 000067 explicitly
//    documents `endpoint_logs` as exempt from TimescaleDB compression (it's
//    a natively-partitioned table TimescaleDB can't wrap), so no
//    compression of any ratio ever applies to this table. "Dropped Logs"/
//    "Queue Length" claimed a queue/drop mechanism that doesn't exist
//    anywhere in this fully-synchronous ingest path. All three removed.
//  - Test Connection's "Auth"/"Parser"/"Permissions" were hardcoded "ok",
//    and "Latency" a fixed literal `12`ms regardless of anything — none had
//    a real check behind them. Removed the three fake fields; latency_ms
//    now times a real DB round-trip against this source's own data.
//  - Parser tab's "ECS Field Mapping" table claimed dotted ECS paths
//    (`source.ip`, `host.name`, `winlog.event_id`, ...) that nothing in
//    this codebase ever produces — not in Postgres storage, not in the
//    optional Elasticsearch mirror (which indexes `parsed_fields` verbatim,
//    confirmed by reading `services/elasticsearch_service.go`). Removed
//    entirely; several of its per-field claims were wrong even as
//    aspirational documentation (e.g. CEF's real field is
//    `device_product`, not "product").
//  - Parser identification itself had a real, separate bug: `format`
//    matching was case-sensitive against free-text data that was never
//    case-normalized at creation time — seeded sources with format "CEF"/
//    "JSON"/"Windows Event" (as opposed to lowercase "cef"/"json"/
//    "winevent") silently fell through to "Auto-Detect Parser" instead of
//    their real declared parser. Verified live via curl against seeded
//    source ids 15/3/14 before and after the fix. Now case-folds first.
//  - The "Alerts" tab was a fully fake, non-functional settings panel: 6
//    toggle-switches styled as clickable (cursor-pointer, on/off thumb
//    position) with hardcoded `active` booleans and **no onClick handler
//    at all** — no per-source alert-rule API exists anywhere in the
//    backend or the frontend's `logSourcesAPI` client. Removed the tab
//    entirely rather than wire fake switches to nothing.
//  - The "Receiver Endpoints" card's Syslog code block literally told
//    users to point real infrastructure at "<host>:6514  TLS" — no TLS
//    syslog listener exists anywhere (`services/syslog_receiver.go` only
//    binds plain UDP/TCP on :514); this would have sent a user down a
//    connection they could never make work. Same fake claim also appeared
//    in the Config tab's "TLS" row and the Pipeline tab's Storage stage
//    description ("PostgreSQL + compression"). All three fixed.
test.use({ storageState: SHARED_STORAGE_STATE });

test.describe('Log Sources — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/log-sources');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/log-sources');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });
});

test.describe('Log Sources — regression guard: fabricated health/stats/test fields are gone', () => {
  test('a real source\'s Health/Stats/Test tabs no longer show hardcoded-ok fields', async ({ page }) => {
    await page.goto('/log-sources');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });

    const firstRow = page.locator('table tbody tr').first();
    await expect(firstRow).toBeVisible({ timeout: 10_000 });
    await firstRow.click();

    // Health tab (default).
    await expect(page.getByText('Ingestion')).toBeVisible();
    await expect(page.getByText('Parsing', { exact: true })).not.toBeVisible();
    await expect(page.getByText('Auth', { exact: true })).not.toBeVisible();

    // Stats tab.
    await page.getByRole('button', { name: 'Stats' }).click();
    await expect(page.getByText('Storage Used (est.)')).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText('Compression', { exact: true })).not.toBeVisible();
    await expect(page.getByText('Dropped Logs')).not.toBeVisible();
    await expect(page.getByText('Queue Length')).not.toBeVisible();

    // Test tab — run a real connection test and confirm no fake fields.
    // Scope checks to the tab-content pane (not the tab strip above it,
    // which legitimately still has a "Parser" tab button — only its fake
    // content was removed).
    const tabContent = page.locator('div.flex-1.overflow-y-auto.p-4.space-y-3.text-xs');
    await page.getByRole('button', { name: 'Test' }).click();
    await page.getByRole('button', { name: 'Run Test' }).click();
    await expect(tabContent.getByText('Connection', { exact: true })).toBeVisible({ timeout: 10_000 });
    await expect(tabContent.getByText('Latency')).toBeVisible();
    await expect(tabContent.getByText('Auth', { exact: true })).toHaveCount(0);
    await expect(tabContent.getByText('Parser', { exact: true })).toHaveCount(0);
    await expect(tabContent.getByText('Permissions')).toHaveCount(0);
  });

  test('Parser tab shows no fabricated "ECS Field Mapping" and no "Alerts" tab exists', async ({ page }) => {
    await page.goto('/log-sources');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });

    const firstRow = page.locator('table tbody tr').first();
    await firstRow.click();
    await page.getByRole('button', { name: 'Parser' }).click();
    await expect(page.getByText('Field Mapping')).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText('ECS Field Mapping')).not.toBeVisible();

    // The fake toggle-switch "Alerts" tab was removed entirely.
    await expect(page.getByRole('button', { name: 'Alerts', exact: true })).toHaveCount(0);
  });
});

test.describe('Log Sources — regression guard: case-insensitive parser identification', () => {
  test('a seeded source with a capitalized format ("CEF") is identified by its real parser, not Auto-Detect', async ({ page }) => {
    // Verified live via curl against the real seeded data (source ids with
    // format "CEF"/"JSON"/"Windows Event") before writing this UI check.
    const res = await page.request.get('/api/log-sources');
    const sources = await res.json();
    const capitalizedCef = sources.find((s: any) => s.format === 'CEF' || s.format === 'Cef');
    test.skip(!capitalizedCef, 'no seeded source with a non-lowercase CEF format to verify against');

    const parserRes = await page.request.get(`/api/log-sources/${capitalizedCef.id}/parser`);
    const parser = await parserRes.json();
    expect(parser.parser_used).toBe('CEF Parser (ArcSight)');
    expect(parser.parser_used).not.toBe('Auto-Detect Parser');
  });
});

test.describe('Log Sources — Receiver Endpoints card no longer advertises a nonexistent TLS listener', () => {
  test('Syslog code block only lists UDP/TCP, not the fake :6514 TLS line', async ({ page }) => {
    await page.goto('/log-sources');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/6514/);
    expect(bodyText).toContain('Syslog (UDP / TCP)');
  });
});

test.describe('Log Sources — AI Insights calls the real LLM', () => {
  test('AI Source Insights returns real, non-empty analysis', async ({ page }) => {
    // Local CPU-only Ollama inference is slow, and scales with prompt size —
    // this endpoint's prompt includes every seeded source's health line, so
    // a real curl against this exact endpoint took ~80s standalone. Budget
    // generously rather than tighten and risk a false failure under load
    // (see elastic-query.spec.ts's header for the full infra-fix context).
    test.setTimeout(180_000);
    await page.goto('/log-sources');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    await page.getByRole('button', { name: 'AI Source Insights' }).click();
    const insightParagraphs = page.locator('.g-card', { hasText: 'AI Source Insights' }).locator('p');
    await expect(insightParagraphs.first()).toBeVisible({ timeout: 150_000 });
    const text = await insightParagraphs.first().textContent();
    expect((text ?? '').length).toBeGreaterThan(20);
  });
});
