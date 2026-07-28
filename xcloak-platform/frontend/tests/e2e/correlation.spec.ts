import { test, expect, Page } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Correlation Engine page (route
// /correlation, sidebar label "Correlation"). Runs against a REAL backend +
// seeded DB — see dashboard.spec.ts's header comment for the dev-stack
// recipe and global-setup.ts for the shared-login rationale.
//
// This page (10 tabs: Overview/Rules/Builder/Attack Chain/Graph/Analytics/
// Grouping/AI Analysis/Simulation/Performance) and its backend
// (api/correlation_enterprise.go + api/correlation_rules.go +
// services/correlation_service.go) were the most solidly-built of any page
// tested in this phase — real queries throughout, a genuinely well-designed
// rule engine (simple/event_count/temporal/temporal_ordered), and an honest
// "no fabricated engine latency numbers" comment matching the same pattern
// already established on the Behavioral Detection page. Two real bugs found:
//
//  - PostCorrelationSimulate (the "Simulation" tab) queried
//    `correlation_rule_stages` for columns `pattern`/`position` that don't
//    exist (real: `rule_name_pattern`/`stage_order` — confirmed by
//    `repositories.GetCorrelationRuleStages`, the correct function already
//    used by rule creation/editing). Every call errored and the loop hit
//    `continue` immediately, so the simulator always reported "0 of N rules
//    would fire" no matter what attack chain was simulated — a silently
//    inert feature. Fixed to call the real repository function instead of
//    hand-rolling a broken raw query, and added a `seedDetectionHits`-
//    adjacent seeder (`correlation_rule_stages` rows for the one real
//    temporal rule) since that table had zero rows across the entire schema
//    — no seeder anywhere ever populated it.
//  - The Rules tab shows a "Built-in Rules (always active)" list, including
//    "IOC Match → Incident" and "YARA Match → Incident" with the condition
//    text `rule_name contains "IOC"/"YARA"`. The real backend heuristic
//    (`services/correlation_service.go`'s `shouldCreateIncident`) used an
//    *exact* string match against only the literal "ioc match"/"yara match"
//    — but the real IOC detection engines (`ioc_engine.go`,
//    `ioc_hash_engine.go`) produce several other genuine IOC-match rule names
//    ("IOC: Malicious Domain", "IOC: Malicious URL", "IOC: Malicious File
//    Hash (SHA256/MD5)"), none of which satisfied the exact match — so a
//    domain/URL/hash-based malicious IOC hit silently did NOT auto-escalate
//    to an incident despite the UI unconditionally promising it would.
//    Fixed `shouldCreateIncident` to use a substring match (`strings.Contains`
//    on "ioc"/"yara"), which also makes the frontend's "contains" wording
//    accurate for the first time. Covered by new Go unit test cases in
//    `services/correlation_service_test.go` (this is internal engine logic,
//    not something meaningfully testable end-to-end via Playwright without
//    invoking a real detector).
test.use({ storageState: SHARED_STORAGE_STATE });

function kpiValue(page: Page, label: string) {
  return page.locator('.g-card', { hasText: label }).first().locator('p.font-bold, p.text-2xl').first();
}

async function gotoTab(page: Page, label: string) {
  await page.goto('/correlation');
  await page.waitForTimeout(600);
  await page.getByRole('button', { name: label, exact: true }).click();
}

const ALL_TABS = ['Overview','Rules','Builder','Attack Chain','Graph','Analytics',
  'Grouping','AI Analysis','Simulation','Performance'];

test.describe('Correlation — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/correlation');
    await page.waitForLoadState('networkidle', { timeout: 15_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/correlation');
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

    await page.goto('/correlation');
    await page.waitForLoadState('networkidle', { timeout: 15_000 });
    for (const tab of ALL_TABS) {
      await page.getByRole('button', { name: tab, exact: true }).click();
      await page.waitForTimeout(600);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('KPI strip matches live /api/correlation/overview', async ({ page }) => {
    const overview = await (await page.request.get('/api/correlation/overview?hours=24')).json();

    await page.goto('/correlation');
    await expect(kpiValue(page, 'Active Rules')).toHaveText(String(overview.active_rules), { timeout: 15_000 });
    await expect(kpiValue(page, 'Total Rules')).toHaveText(String(overview.total_rules), { timeout: 15_000 });
  });
});

test.describe('Correlation — regression guard: Simulation tab is no longer permanently inert', () => {
  test('a full attack chain reports would_fire=true with real stage data, not 0-of-N always', async ({ page }) => {
    const res = await page.request.post('/api/correlation/simulate', {
      data: { chain: ['c2 beacon detected on host', 'lateral movement via SMB'], window_minutes: 60 },
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.fired).toBeGreaterThan(0);
    const rule = body.matches.find((m: any) => m.rule_name === 'C2 + Lateral Movement Chain');
    expect(rule).toBeTruthy();
    expect(rule.would_fire).toBe(true);
    expect(rule.coverage_pct).toBe(100);
  });

  test('a partial chain honestly reports partial coverage and would_fire=false', async ({ page }) => {
    const res = await page.request.post('/api/correlation/simulate', {
      data: { chain: ['c2 beacon detected on host'], window_minutes: 60 },
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    const rule = body.matches.find((m: any) => m.rule_name === 'C2 + Lateral Movement Chain');
    expect(rule.would_fire).toBe(false);
    expect(rule.coverage_pct).toBeGreaterThan(0);
    expect(rule.coverage_pct).toBeLessThan(100);
  });

  test('Simulation tab UI renders the real result after clicking Simulate', async ({ page }) => {
    await gotoTab(page, 'Simulation');
    await page.getByRole('button', { name: 'Simulate' }).click();
    await expect(page.getByText(/of \d+ temporal rules would fire/i)).toBeVisible({ timeout: 10_000 });
  });
});

test.describe('Correlation — Rules tab', () => {
  test('toggling a correlation rule persists via the real API, then restores it', async ({ page }) => {
    const rules: Array<{ id: number; name: string; enabled: boolean }> =
      await (await page.request.get('/api/correlation/rules')).json();
    const target = rules[0];

    await gotoTab(page, 'Rules');
    await expect(page.getByText(target.name).first()).toBeVisible({ timeout: 15_000 });

    const toggleRes = await page.request.patch(`/api/correlation/rules/${target.id}/toggle`, {
      data: { enabled: !target.enabled },
    });
    expect(toggleRes.status()).toBe(200);

    const restoreRes = await page.request.patch(`/api/correlation/rules/${target.id}/toggle`, {
      data: { enabled: target.enabled },
    });
    expect(restoreRes.status()).toBe(200);
  });
});
