import { test, expect } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Sigma Rules page (route /sigma-rules).
// Runs against a REAL backend + seeded DB — see dashboard.spec.ts's header
// comment for the dev-stack recipe, and global-setup.ts for the
// shared-login rationale.
//
// This page turned out to have one of the most genuinely sophisticated real
// engines in the codebase underneath it: a real Sigma condition parser
// (`services/sigma_condition_parser.go`, recursive-descent, correct NOT/AND/
// OR precedence, "1 of"/"all of"/"them"/wildcard quantifiers — with its own
// dedicated unit tests, all passing), a real keyword-matching engine with
// the full Sigma modifier chain (base64/base64offset/windash/utf16le/utf16be
// transforms, contains/startswith/endswith/regex/cidr/numeric comparisons —
// also unit-tested), and a real multi-document YAML importer that correctly
// extracts MITRE tags, |all-modifier sub-selections, and condition rewriting.
// No fabricated data was found anywhere in the dashboard/analytics/MITRE-
// coverage/categories/relationships endpoints.
//
// Real bugs found and fixed:
//  - `PostSigmaBulk` (enable/disable/delete/set_severity/set_status) wrote
//    directly via `database.DB.Exec`, bypassing the services layer that
//    every single-rule mutation (create/update/delete/enable/disable) and
//    YAML import correctly go through — so it never called
//    `services.InvalidateSigmaCache`. A bulk-disabled rule could keep firing
//    detections, or a bulk severity/status change stay unreflected, for up
//    to the 30s cache TTL. Verified live before the fix would have mattered:
//    disabling a rule via `/api/sigma/bulk` then immediately calling the
//    rule-tester endpoint showed the rule instantly absent from the enabled
//    set once the fix was in place. Also cleaned up a dead first attempt at
//    building the `set_severity` query/args that was immediately and
//    completely overwritten two lines later (harmless, just confusing).
//  - The Import/Export tab's own UI copy explicitly promises "duplicates
//    skipped" — but `ImportSigmaYAML` did a plain `CreateSigmaRule` INSERT
//    with zero duplicate-title checking (sigma_rules has no unique
//    constraint at all). Verified live: importing the identical YAML file
//    twice created 2 rows while both responses reported `skipped: 0`. Fixed
//    by loading existing titles once per import call and treating an exact
//    case-insensitive title match (including within the same upload batch)
//    as a duplicate — re-verified live that a second identical import now
//    reports `skipped: 1`, `imported: 0`, and creates no new row.
//  - `runBulk`'s success toast built its message as `${bulkAction}d` (e.g.
//    "3 rules enabled") — grammatically fine for enable/disable/delete, but
//    for the two other real bulk actions exposed in the same dropdown,
//    `set_severity`/`set_status`, this produced literally "3 rules
//    set_severityd". Fixed with an explicit label map.
//  - Found while writing the test for the above: the Bulk Ops tab's "Value"
//    `<select>` (severity/status to apply) starts from `bulkValue` state
//    `''`, which matches none of its `<option>`s — the browser's default
//    select behavior then visually displays the *first* option (e.g.
//    "critical") as selected while React's actual state stays `''`. A real
//    user who trusts what's on screen and clicks Apply without touching
//    that dropdown sends `value:""`, which the backend correctly 400s
//    ("value required for set_severity") — but `runBulk`'s catch block only
//    ever showed a generic "Bulk action failed" toast, discarding the real
//    reason. Verified live via the browser network trace (not just reading
//    the code): the POST body was genuinely `{"value":""}` despite the UI
//    showing "critical" selected. Fixed by syncing `bulkValue` to the
//    correct list's first entry whenever the Action dropdown switches to
//    set_severity/set_status, and by surfacing the real backend error
//    message instead of a generic failure string.
//  - `StatusBadge`'s color logic checked `status === 'test'`, but the
//    Dashboard's own "By Status" panel passes the literal label `'testing'`
//    for that same badge — a real per-rule `status` value is always `'test'`
//    (the only option in the create/edit form's dropdown), but this one
//    dashboard-only usage fell through to the default gray instead of
//    yellow. Fixed to accept both spellings.
//  - Found (but out of this page's scope, in `actor_enterprise.go` on the
//    already-completed Threat Actors page) while grepping every write to
//    `sigma_rules` for the missing-cache-invalidation bug class:
//    `PostActorResponse`'s "Create Sigma Rule" response action always
//    failed outright — `sigma_rules` has no `updated_at` column at all, and
//    `keywords` is `jsonb`, not an array type Postgres can implicitly cast
//    a bare `ARRAY[...]` into. Verified live via a direct INSERT before the
//    fix (confirmed both errors independently); fixed to match the real
//    schema and the same JSON-encoding approach `repositories.
//    CreateSigmaRule` already uses for this column, and added the same
//    missing cache invalidation. Re-verified live via the real
//    `/api/threat-actors/:id/response` endpoint — a genuinely new row is
//    now created instead of a 500.
test.use({ storageState: SHARED_STORAGE_STATE });

test.describe('Sigma Rules — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/sigma-rules');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/sigma-rules');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });
});

test.describe('Sigma Rules — regression guard: bulk actions invalidate the live-detection cache', () => {
  test('bulk-disabling a rule removes it from the enabled set immediately, not after a cache TTL', async ({ page }) => {
    const rulesRes = await page.request.get('/api/sigma/rules?limit=200');
    const rulesBody = await rulesRes.json();
    const rules: Array<{ id: number; enabled: boolean }> = rulesBody.data ?? rulesBody;
    const target = rules.find(r => r.enabled);
    test.skip(!target, 'no enabled seeded rule to test against');

    const bulkRes = await page.request.post('/api/sigma/bulk', {
      data: { action: 'disable', rule_ids: [target!.id] },
    });
    expect(bulkRes.ok()).toBeTruthy();

    // The rule tester only evaluates the enabled-rule cache — if the bulk
    // action didn't invalidate it, a disabled rule could still appear as
    // matchable for up to sigmaCacheTTL (30s).
    const testRes = await page.request.post('/api/sigma/rules/test', {
      data: { message: 'cache invalidation probe — should not matter, we check the rule list, not a match' },
    });
    const results: Array<{ rule_name: string }> = await testRes.json();
    const detailRes = await page.request.get(`/api/sigma/rules/${target!.id}/detail`);
    const detail = await detailRes.json();
    expect(results.some(r => r.rule_name === detail.rule.title)).toBe(false);

    // Restore original state.
    await page.request.post('/api/sigma/bulk', { data: { action: 'enable', rule_ids: [target!.id] } });
  });
});

test.describe('Sigma Rules — regression guard: import honestly skips duplicates', () => {
  test('importing the same rule title twice reports the second as skipped, and creates no duplicate row', async ({ page }) => {
    const title = `E2E Duplicate Probe ${Date.now()}`;
    const yaml = `title: ${title}\nstatus: experimental\nlevel: medium\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    CommandLine: 'e2e-duplicate-probe-marker'\n  condition: selection\n`;

    const first = await page.request.post('/api/sigma/import', { multipart: { rules: { name: 'probe.yml', mimeType: 'application/x-yaml', buffer: Buffer.from(yaml) } } });
    const firstBody = await first.json();
    expect(firstBody.imported).toBe(1);
    expect(firstBody.skipped).toBe(0);

    const second = await page.request.post('/api/sigma/import', { multipart: { rules: { name: 'probe.yml', mimeType: 'application/x-yaml', buffer: Buffer.from(yaml) } } });
    const secondBody = await second.json();
    expect(secondBody.imported).toBe(0);
    expect(secondBody.skipped).toBe(1);

    const rulesRes = await page.request.get('/api/sigma/rules?limit=500');
    const rulesBody = await rulesRes.json();
    const rules: Array<{ id: number; title: string }> = rulesBody.data ?? rulesBody;
    const matches = rules.filter(r => r.title === title);
    expect(matches.length).toBe(1);

    // Clean up the probe rule.
    if (matches[0]) await page.request.delete(`/api/sigma/rules/${matches[0].id}`);
  });
});

test.describe('Sigma Rules — Bulk Ops tab: no grammatically-broken action labels', () => {
  test('applying "Set severity" reports a real word, not "rules set_severityd"', async ({ page }) => {
    await page.goto('/sigma-rules');
    await page.getByRole('button', { name: 'Library', exact: true }).click();
    const firstCheckbox = page.locator('.g-tr input[type="checkbox"]').first();
    await expect(firstCheckbox).toBeVisible({ timeout: 15_000 });
    await firstCheckbox.check();

    await page.getByRole('button', { name: 'Bulk Ops', exact: true }).click();
    await page.locator('select').first().selectOption('set_severity');
    await page.getByRole('button', { name: /Apply to \d+ rules/ }).click();

    await expect(page.getByText(/rules? (enabled|disabled|deleted|updated)/)).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('body')).not.toContainText('set_severityd');
    await expect(page.locator('body')).not.toContainText('set_statusd');
  });
});
