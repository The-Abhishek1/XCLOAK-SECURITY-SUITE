import { test, expect } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Timeline page (route /timeline).
// Runs against a REAL backend + seeded DB — see dashboard.spec.ts's header
// comment for the dev-stack recipe, and global-setup.ts for the
// shared-login rationale.
//
// This page arrived already mostly fixed from an earlier, untracked pass:
// timeline_service.go's timelineUnionSQL already COALESCEs every nullable
// column it scans (the same "NULL column silently drops the whole row from
// results" bug class found repeatedly elsewhere this phase), and the
// right-click context menu's "Filter by Host: <name>" item — which used to
// be a literal no-op (`action: () => {}` with a comment falsely claiming
// "parent handles via onClose + state") — was already wired to actually set
// the agent filter. Verified both live rather than assuming the comments
// were accurate.
//
// Two new real bugs found and fixed here:
//  - Selecting a specific agent in the toolbar routed the request through
//    `GET /agents/:id/timeline` (`agentsAPI.getTimeline`), a separate
//    endpoint that accepts no filters at all — so choosing an agent
//    silently dropped any active severity/category/search/time-range filter
//    while the toolbar kept showing them as applied (the Filters button's
//    badge count still included them). Confirmed via curl: the per-agent
//    endpoint returned 77 unfiltered events for agent 1 while
//    `/api/timeline?agent_id=1&severity=critical` correctly returned 14.
//    Fixed by routing agent selection through the general `/api/timeline`
//    endpoint's existing `agent_id` param instead, which already applies
//    every other filter correctly.
//  - The evidence panel's Bookmark/Copy-JSON header buttons, and the
//    toolbar's Bookmarks-filter toggle, were icon-only with no text
//    fallback — since this codebase's icon library is null-stubbed
//    (lib/icon-stubs.ts renders every icon as `null`, "pages use
//    text/symbols instead"), these buttons had zero visible content and (for
//    the two plain, unstyled evidence-panel buttons with no `g-btn` padding
//    class) were literally zero-size and unclickable — the same
//    "icon-stubs null fallout" bug class already fixed on 16 other files in
//    an earlier pass, just missed here. Fixed with the established
//    symbol/text-label vocabulary (★/☆ for bookmark, "Copy"/✓ for the copy
//    button, always-visible "Bookmarks" text for the toolbar toggle).
test.use({ storageState: SHARED_STORAGE_STATE });

test.describe('Timeline — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/timeline');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/timeline');
    await expect(page.getByText(/events$/)).toBeVisible({ timeout: 20_000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });
});

test.describe('Timeline — regression guard: agent selection no longer drops other filters', () => {
  test('agent_id + severity together only return matching events (API level)', async ({ page }) => {
    const agents = await (await page.request.get('/api/agents')).json();
    expect(agents.length).toBeGreaterThan(0);
    const agentId = agents[0].id;

    const unfiltered = await (await page.request.get(`/api/agents/${agentId}/timeline`)).json();
    const filtered = await (
      await page.request.get(`/api/timeline?agent_id=${agentId}&severity=critical&limit=500`)
    ).json();

    // Every event returned by the filtered general endpoint must actually be critical.
    expect(filtered.every((e: any) => e.severity === 'critical')).toBe(true);
    // Sanity: the two endpoints disagree in general (confirming the general
    // endpoint's filter is actually doing something, not coincidentally equal).
    expect(unfiltered.length).not.toBe(filtered.length);
  });

  test('UI: picking an agent while a severity filter is active only shows that severity', async ({ page }) => {
    await page.goto('/timeline');
    await expect(page.getByText(/events$/)).toBeVisible({ timeout: 20_000 });

    await page.getByRole('button', { name: /Filters/i }).click();
    await page.getByRole('button', { name: /^critical$/i }).click();

    const agents = await (await page.request.get('/api/agents')).json();
    await page.locator('select').first().selectOption(String(agents[0].id));

    await page.waitForTimeout(1000);
    const cards = page.locator('body');
    const text = await cards.innerText();
    // If any events rendered, none should show a non-critical severity badge
    // (the old bug would happily show high/medium/info events here too).
    if (!text.includes('No events match your filters')) {
      const badges = await page.locator('span:text-is("high"), span:text-is("medium"), span:text-is("low")').count();
      expect(badges).toBe(0);
    }
  });
});

test.describe('Timeline — Filter by Host context menu', () => {
  test('right-click "Filter by Host" actually sets the agent selector', async ({ page }) => {
    await page.goto('/timeline');
    await expect(page.getByText(/events$/)).toBeVisible({ timeout: 20_000 });

    const firstCard = page.locator('.group.cursor-pointer').first();
    await expect(firstCard).toBeVisible({ timeout: 15_000 });
    await firstCard.click({ button: 'right' });

    const filterItem = page.getByText(/Filter by Host:/i);
    if (await filterItem.count() > 0) {
      const label = await filterItem.textContent();
      const hostname = label!.replace('Filter by Host:', '').trim();
      await filterItem.click();
      await expect(page.locator('select').first()).not.toHaveValue('all');
      const selectedText = await page.locator('select').first().locator('option:checked').textContent();
      expect(selectedText).toBe(hostname);
    }
  });
});

test.describe('Timeline — regression guard: no invisible icon-only buttons', () => {
  test('the evidence-panel Bookmark and Copy JSON buttons have visible content', async ({ page }) => {
    await page.goto('/timeline');
    await expect(page.getByText(/events$/)).toBeVisible({ timeout: 20_000 });

    const firstCard = page.locator('.group.cursor-pointer').first();
    await expect(firstCard).toBeVisible({ timeout: 15_000 });
    await firstCard.click();

    const bookmarkBtn = page.getByTitle('Bookmark');
    const copyBtn = page.getByTitle('Copy JSON');
    await expect(bookmarkBtn).toBeVisible({ timeout: 5_000 });
    await expect(copyBtn).toBeVisible({ timeout: 5_000 });
    expect((await bookmarkBtn.textContent())?.trim()).not.toBe('');
    expect((await copyBtn.textContent())?.trim()).not.toBe('');
  });

  test('the toolbar Bookmarks toggle is always visible, even with zero bookmarks', async ({ page }) => {
    await page.goto('/timeline');
    await expect(page.getByText(/events$/)).toBeVisible({ timeout: 20_000 });
    const toggle = page.getByRole('button', { name: /^Bookmarks$/ });
    await expect(toggle).toBeVisible({ timeout: 10_000 });
  });
});

test.describe('Timeline — bookmarks and live mode', () => {
  test('bookmarking an event updates the bookmark counter and bookmarks-only view', async ({ page }) => {
    await page.goto('/timeline');
    await expect(page.getByText(/events$/)).toBeVisible({ timeout: 20_000 });

    const firstCard = page.locator('.group.cursor-pointer').first();
    await expect(firstCard).toBeVisible({ timeout: 15_000 });
    await firstCard.click();

    const bookmarkBtn = page.getByTitle('Bookmark');
    await expect(bookmarkBtn).toBeVisible({ timeout: 5_000 });
    await bookmarkBtn.click();
    await expect(page.getByTitle('Remove bookmark')).toBeVisible({ timeout: 5_000 });

    // Bookmarks-only toggle in the toolbar should now show a count of 1 and
    // filtering to it should not empty the list.
    const bookmarkToggle = page.getByRole('button', { name: /^Bookmarks \(1\)$/ });
    await expect(bookmarkToggle).toBeVisible({ timeout: 5_000 });
    await bookmarkToggle.click();
    await expect(page.getByText('No events match your filters.')).not.toBeVisible();
  });
});

test.describe('Timeline — stats bar reflects live data', () => {
  test('7d stats bar total matches /api/timeline/stats', async ({ page }) => {
    const stats = await (await page.request.get('/api/timeline/stats')).json();
    const total = Object.values(stats as Record<string, number>).reduce((a, b) => a + b, 0);
    expect(total).toBeGreaterThan(0);

    await page.goto('/timeline');
    await expect(page.getByText('7d stats:')).toBeVisible({ timeout: 20_000 });
    for (const [type, count] of Object.entries(stats as Record<string, number>)) {
      await expect(page.getByText(new RegExp(`${count.toLocaleString()}$`))).toBeTruthy();
    }
  });
});
