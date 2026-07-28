import { test, expect, Page } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Behavioral Detection page
// (sidebar label "Behavioral", route /threat-detection). Runs against a REAL
// backend + seeded DB — see dashboard.spec.ts's header comment for the
// dev-stack recipe and global-setup.ts for the shared-login rationale.
//
// This page (12 tabs: Overview/Rules/Coverage/Correlation/Behavioral/IOC
// Matching/Analytics/Performance/Testing/AI Assistant/Pipeline/Library) was
// already mostly well-built and reuses other real, dedicated APIs
// (sigma/yara/correlation/iocs/suppression rule management), unlike the
// UEBA/Insider Threat-style wholesale fakery seen earlier in this phase.
// Real bugs found and fixed:
//  - GetDetectionOverview queried a nonexistent `ioc_blocks` table (same
//    missing-table bug found on the NBA page) — always silently returned 0
//    for the "IOC" row's triggered count. Replaced with a real query against
//    `iocs.last_seen` (the column repositories.RecordIOCHit actually bumps).
//  - The "Correlation" row in rule_breakdown was **hardcoded to `0`** for
//    triggered count — never queried anything — and correlation hits were
//    never included in the `triggered_last_24h` total either. Added a real
//    COUNT(DISTINCT rule_id) query against `correlation_matches`.
//  - `yara_matches` has no `matched_at` column (real: `created_at`) — every
//    query referencing it (Overview's YARA triggered count, the Trends
//    endpoint's YARA sparkline, and Simulate's YARA branch) silently
//    returned 0/empty despite real yara_matches rows existing. Fixed all 3.
//  - PostDetectionSimulate's hourly-trend query always queried
//    `sigma_rule_hits` by the given rule_id regardless of `rule_type` —
//    selecting "YARA" or "Correlation" in the Testing tab silently produced
//    either nothing or (by ID-space coincidence) a sigma rule's trend data.
//    Rewrote to branch per rule type against the correct real table
//    (sigma_rule_hits / yara_matches / correlation_matches).
//  - Frontend: the IOC Matching tab's `IOC` interface read `ioc.value`, but
//    the real `/api/iocs` response field is `indicator` — every IOC's value
//    column silently rendered blank. Fixed the interface + render.
//  - Frontend: the Correlation tab read `r.window_seconds` (never returned
//    by the real API — the real field is `window_minutes`) and only
//    rendered `<CorrelationSequence>` if a `sequence` array existed (never
//    returned either) — both were permanently-dead code paths. Fixed to use
//    the real `window_minutes` field and always render the sequence visual
//    (which already has a sensible fallback for when no real chain data
//    exists).
//  - The Library tab's category items had `cursor-pointer` + hover-transition
//    styling but no `onClick` at all — a misleading "looks clickable, does
//    nothing" affordance for what's just a static reference glossary; removed
//    the fake-interactive styling.
//  - A pre-existing React key-prop warning (shorthand `<>` fragments with no
//    key inside two different `.map()` calls — SigmaRulesTable) was caught by
//    this spec's zero-console-errors check and fixed.
//  - Demo seed had zero rows in `sigma_rule_hits`/`correlation_matches` ever
//    (cmd/seed/rules only creates rule *definitions*, nothing logs a match
//    against them) — added a seedDetectionHits() seeder. This also surfaced
//    a **separate, pre-existing bug**: cmd/seed/rules' sigma_rules/
//    correlation_rules/yara_rules inserts use `ON CONFLICT DO NOTHING` with
//    no unique constraint on the table to actually match against, so re-running
//    the rules seeder (done repeatedly over this long session) silently
//    duplicated every rule. Deduplicated the live dev DB (kept lowest id per
//    title/name) — not fixed at the schema level, since adding a unique
//    constraint is a migration beyond this pass's scope.
test.use({ storageState: SHARED_STORAGE_STATE });

function kpiValue(page: Page, label: string) {
  return page.locator('.g-card', { hasText: label }).first().locator('p.font-bold, p.text-2xl').first();
}

async function gotoTab(page: Page, label: string) {
  await page.goto('/threat-detection');
  await page.waitForTimeout(600);
  await page.getByRole('button', { name: label, exact: true }).click();
}

const ALL_TABS = ['Overview','Rules','Coverage','Correlation','Behavioral','IOC Matching',
  'Analytics','Performance','Testing','AI Assistant','Pipeline','Library'];

test.describe('Behavioral Detection — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/threat-detection');
    await page.waitForLoadState('networkidle', { timeout: 15_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/threat-detection');
    await expect(page.locator('.g-card').first()).toBeVisible({ timeout: 15_000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });

  test('every tab loads without a failed API call or console error', async ({ page }) => {
    test.setTimeout(60_000);
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/threat-detection');
    await page.waitForLoadState('networkidle', { timeout: 15_000 });
    for (const tab of ALL_TABS) {
      await page.getByRole('button', { name: tab, exact: true }).click();
      await page.waitForTimeout(600);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('KPI strip matches live /api/detection/overview', async ({ page }) => {
    const overview = await (await page.request.get('/api/detection/overview?hours=24')).json();

    await page.goto('/threat-detection');
    await expect(kpiValue(page, 'Total Rules')).toHaveText(String(overview.total_rules), { timeout: 15_000 });
    await expect(kpiValue(page, 'Triggered (24h)')).toHaveText(String(overview.triggered_last_24h), { timeout: 15_000 });
  });
});

test.describe('Behavioral Detection — regression guard: triggered-rule counts are no longer wrong', () => {
  test('Correlation row in rule breakdown reflects real correlation_matches, not a hardcoded 0', async ({ page }) => {
    const overview = await (await page.request.get('/api/detection/overview?hours=168')).json();
    const correlationRow = overview.rule_breakdown.find((r: any) => r.type === 'Correlation');
    expect(correlationRow.triggered).toBeGreaterThan(0);
  });

  test('YARA row reflects real yara_matches via the correct created_at column, not always 0', async ({ page }) => {
    const overview = await (await page.request.get('/api/detection/overview?hours=168')).json();
    const yaraRow = overview.rule_breakdown.find((r: any) => r.type === 'YARA');
    expect(yaraRow.triggered).toBeGreaterThan(0);
  });

  test('Testing tab: simulating a YARA rule type queries yara_matches, not sigma_rule_hits', async ({ page }) => {
    const res = await page.request.post('/api/detection/simulate', {
      data: { rule_type: 'yara', rule_id: 0, hours: 168 },
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.estimated_matches).toBeGreaterThan(0);
  });

  test('Testing tab: simulating a correlation rule queries correlation_matches for that specific rule_id', async ({ page }) => {
    const rules: Array<{ id: number }> = await (await page.request.get('/api/correlation/rules')).json();
    expect(rules.length).toBeGreaterThan(0);
    const res = await page.request.post('/api/detection/simulate', {
      data: { rule_type: 'correlation', rule_id: rules[0].id, hours: 168 },
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.rule_type).toBe('correlation');
  });
});

test.describe('Behavioral Detection — regression guard: IOC Matching tab shows real values', () => {
  test('IOC table renders the real indicator string, not a blank "value" field', async ({ page }) => {
    const iocsRes = await (await page.request.get('/api/iocs?limit=5')).json();
    const iocs = iocsRes.data ?? iocsRes;
    expect(iocs.length).toBeGreaterThan(0);
    const firstIndicator = iocs[0].indicator;

    await gotoTab(page, 'IOC Matching');
    await expect(page.getByText(firstIndicator, { exact: false }).first()).toBeVisible({ timeout: 15_000 });
  });
});

test.describe('Behavioral Detection — Rules tab', () => {
  test('toggling a Sigma rule disables it via the real API, then re-enables it', async ({ page }) => {
    const body = await (await page.request.get('/api/sigma/rules?limit=200')).json();
    const rules: Array<{ id: number; title: string; enabled: boolean }> = body.data ?? body;
    const target = rules.find(r => r.enabled) ?? rules[0];

    await gotoTab(page, 'Rules');
    await page.getByPlaceholder('Search rules…').fill(target.title);
    const row = page.locator('tr', { hasText: target.title }).first();
    await expect(row).toBeVisible({ timeout: 15_000 });

    await row.getByTitle(target.enabled ? 'Disable' : 'Enable').click();
    await expect(row.getByText(target.enabled ? 'Disabled' : 'Enabled')).toBeVisible({ timeout: 10_000 });

    // Restore original state so the test is repeatable.
    await row.getByTitle(target.enabled ? 'Enable' : 'Disable').click();
    await expect(row.getByText(target.enabled ? 'Enabled' : 'Disabled')).toBeVisible({ timeout: 10_000 });
  });
});

test.describe('Behavioral Detection — Correlation tab', () => {
  test('toggling a correlation rule persists via the real API', async ({ page }) => {
    const rules: Array<{ id: number; name: string; enabled: boolean }> =
      await (await page.request.get('/api/correlation/rules')).json();
    const target = rules[0];

    await gotoTab(page, 'Correlation');
    const card = page.locator('div', { hasText: target.name }).last();
    await expect(card).toBeVisible({ timeout: 15_000 });

    const toggleRes = await page.request.patch(`/api/correlation/rules/${target.id}/toggle`, {
      data: { enabled: !target.enabled },
    });
    expect(toggleRes.status()).toBe(200);

    // Restore.
    const restoreRes = await page.request.patch(`/api/correlation/rules/${target.id}/toggle`, {
      data: { enabled: target.enabled },
    });
    expect(restoreRes.status()).toBe(200);
  });
});
