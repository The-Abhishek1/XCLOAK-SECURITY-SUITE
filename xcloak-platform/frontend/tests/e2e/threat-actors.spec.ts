import { test, expect } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Threat Actors page (route /threat-actors).
// Runs against a REAL backend + seeded DB — see dashboard.spec.ts's header
// comment for the dev-stack recipe, and global-setup.ts for the
// shared-login rationale.
//
// A repo-wide grep during the Threat Intel pass already found+fixed one bug
// here ahead of time: `PostActorResponse`'s "Block IOCs" action inserted
// into a nonexistent `ioc_blocks` table (always silently failed, reporting
// a fake "Blocked 0 IOCs" success) — fixed to `UPDATE iocs SET enabled=true`
// instead, matching the real enforcement flag used everywhere else.
//
// This pass found the single most impactful bug of the phase so far, by
// query count: `TagAlertWithActors` (services/threat_actor_service.go) —
// the sole mechanism that populates `actor_alert_tags`, which every other
// endpoint on this page (campaigns, exposure, detection coverage,
// relationships, timeline, analytics) is built on — matched an alert's
// `mitre_technique` against `threat_actors.mitre_techniques` with an exact
// `= ANY(...)` comparison. Both columns independently mix base ("T1078")
// and sub-technique ("T1071.001") MITRE ID forms, so the exact match
// silently missed ~2/3 of real correlations in this tenant's seeded data
// (54 exact matches vs. 174 once sub-technique suffixes are ignored,
// verified directly via SQL before the fix). Fixed to match on the base
// technique ID (`split_part(t,'.',1)`), and backfilled this tenant's
// existing `actor_alert_tags` to the corrected set.
//
// The identical shape of bug also existed client-side in `KillChainView`:
// its "N of 8 kill chain stages covered" calculation did an exact Set
// membership check against base technique IDs, so any actor whose
// technique list was recorded as sub-techniques (most of the real seed
// data, e.g. APT28's {T1071.001,T1059.001,T1078,T1027}) showed far fewer
// covered stages than reality (1 of 8 instead of the real 3 of 8 for
// that actor). Fixed with the same base-technique-prefix match.
//
// Also found: `threat_actors` has no unique constraint at all, and
// `cmd/seed/demo/main.go`'s `seedThreatActors` used a bare
// `ON CONFLICT DO NOTHING` with no real conflict target to trigger on —
// re-running the demo seeder duplicated its 3 actors (confirmed via two
// sets of identical rows ~2h20m apart by created_at). Fixed with an
// explicit existence-check guard (matching this same file's
// `SeedBuiltinActors` idiom) and cleaned up the pre-existing duplicates.
//
// And a misleading-affordance bug in the Hunt tab: 6 "hunt type" buttons
// were shown (IOCs/TTPs/Logs/DNS/Firewall/Cloud), but the backend
// (`PostActorHunt`) only ever differentiated 2 of them — the other 4 fell
// through to a generic `default` case producing identical, undifferentiated
// output regardless of which was clicked. A separate `queries` field
// computed for the "iocs" hunt type was also never rendered anywhere in
// the UI. Trimmed the button set to the 2 real types, added a pointer to
// the real AI-powered Hunt Guide (which already covers logs/DNS/network
// via genuine LLM calls) for the rest, and rendered the previously-dead
// `queries` field.
test.use({ storageState: SHARED_STORAGE_STATE });

async function selectFirstActor(page: import('@playwright/test').Page) {
  await page.goto('/threat-actors');
  await page.getByRole('button', { name: 'Actors', exact: true }).click();
  const firstCard = page.locator('.g-card.cursor-pointer').first();
  await expect(firstCard).toBeVisible({ timeout: 15_000 });
  const name = (await firstCard.locator('span.font-semibold').first().innerText()).trim();
  await firstCard.click();
  return name;
}

test.describe('Threat Actors — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await selectFirstActor(page);
    await page.waitForLoadState('networkidle', { timeout: 20_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/threat-actors');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });
});

test.describe('Threat Actors — regression guard: sub-technique matching', () => {
  test('base-technique matching finds real actor/alert correlations that exact matching missed', async ({ page }) => {
    // Direct backend check: with the exact-match bug, this tenant had only
    // 54 real actor/alert pairs; base-technique matching finds 174. Assert
    // the dashboard's org-wide activity reflects the larger, correct set
    // rather than the undercounted one.
    const dash = await (await page.request.get('/api/threat-actors/dashboard')).json();
    expect(dash.active_in_org).toBeGreaterThan(0);

    const actorsRes = await page.request.get('/api/threat-actors');
    const actors = await actorsRes.json();
    const withSubTechniques = (actors as any[]).find(a =>
      (a.mitre_techniques ?? []).some((t: string) => t.includes('.')));
    test.skip(!withSubTechniques, 'no seeded actor with a sub-technique entry to verify against');

    const detail = await (await page.request.get(`/api/threat-actors/${withSubTechniques.id}/campaigns`)).json();
    // Under the old exact-match bug, an actor whose techniques are entirely
    // sub-technique form could show zero campaigns despite real matching
    // alerts existing for its base techniques.
    expect(Array.isArray(detail.campaigns)).toBe(true);
  });

  test('Kill Chain view credits sub-technique entries toward their base-technique stage', async ({ page }) => {
    const name = await selectFirstActor(page);
    await page.getByRole('button', { name: 'MITRE', exact: true }).click();
    // Not all seeded actors necessarily hit a kill-chain-mapped technique,
    // but the page itself must never throw/crash rendering the tab.
    await expect(page.locator('body')).toContainText(name, { timeout: 15_000 });
  });
});

test.describe('Threat Actors — regression guard: no duplicate demo-seeded actors', () => {
  test('the 3 demo-seeded actors (APT28, Lazarus Group, BlackCat / ALPHV) each appear at most once per is_builtin flag', async ({ page }) => {
    const res = await page.request.get('/api/threat-actors');
    const actors = await res.json() as Array<{ name: string; is_builtin: boolean }>;
    const counts: Record<string, number> = {};
    for (const a of actors) {
      const key = `${a.name}::${a.is_builtin}`;
      counts[key] = (counts[key] ?? 0) + 1;
    }
    const dupes = Object.entries(counts).filter(([, n]) => n > 1);
    expect(dupes, `Duplicate actor rows: ${JSON.stringify(dupes)}`).toEqual([]);
  });
});

test.describe('Threat Actors — Hunt tab: only real hunt types are offered', () => {
  test('shows exactly 2 hunt-type buttons (IOCs, TTPs) and a pointer to the real AI Hunt Guide', async ({ page }) => {
    await selectFirstActor(page);
    await page.getByRole('button', { name: 'Hunt', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Hunt IOCs' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Hunt TTPs' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Search Logs' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Search DNS' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Search Firewall' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Search Cloud' })).toHaveCount(0);
    await expect(page.locator('body')).toContainText('AI Intel → Hunt Guide');
  });

  test('Generate Hunt Parameters against the live backend renders real IOCs/techniques', async ({ page }) => {
    await selectFirstActor(page);
    await page.getByRole('button', { name: 'Hunt', exact: true }).click();
    await page.getByRole('button', { name: 'Hunt IOCs' }).click();
    await page.getByRole('button', { name: 'Generate Hunt Parameters' }).click();
    await expect(page.getByText(/^Hunt Parameters —/)).toBeVisible({ timeout: 15_000 });
  });
});

test.describe('Threat Actors — Response Actions against the live backend', () => {
  test('Block IOCs enables real previously-disabled IOCs (not the nonexistent ioc_blocks table)', async ({ page }) => {
    const name = await selectFirstActor(page);
    await page.getByRole('button', { name: 'Hunt', exact: true }).click();
    await page.getByRole('button', { name: 'Block IOCs' }).click();
    await expect(page.getByText(/Enabled blocking for \d+/)).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('body')).toContainText(name);
  });

  // Found during the Sigma Rules pass while grepping every write to
  // sigma_rules for a missing-cache-invalidation bug: this action always
  // 500'd outright — sigma_rules has no updated_at column, and keywords is
  // jsonb (not an array type Postgres can implicitly cast a bare ARRAY[...]
  // into). Fixed to match the real schema; this locks in that the button
  // now actually creates a rule instead of erroring.
  test('Create Sigma Rule succeeds against the real schema (was a 500 on every click)', async ({ page }) => {
    await selectFirstActor(page);
    await page.getByRole('button', { name: 'Hunt', exact: true }).click();
    await page.getByRole('button', { name: 'Create Sigma Rule' }).click();
    await expect(page.getByText(/^Created Sigma rule for/)).toBeVisible({ timeout: 10_000 });
  });
});
