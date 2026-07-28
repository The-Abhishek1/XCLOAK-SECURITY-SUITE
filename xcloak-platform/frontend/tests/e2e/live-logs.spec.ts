import { test, expect } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Live Logs page (route /live-logs).
// Runs against a REAL backend + seeded DB — see dashboard.spec.ts's header
// comment for the dev-stack recipe, and global-setup.ts for the
// shared-login rationale.
//
// The core streaming feature is real: `/api/ws/ticket` issues a genuine
// single-use ticket, `LiveLogsWS` streams real `endpoint_logs` rows over a
// real WebSocket (last 50 historical rows on connect, then polls every 2s
// for new ones), and the AI Explain/Summarize actions genuinely call the
// LLM via `/api/ai/explain-log` and `/api/ai/summarize-logs`. The page's
// `ticket === 'demo-ws-ticket-noop'` fallback branch is not a bug — that
// literal string is only ever produced by the frontend's separate
// "static-demo" deployment mode router (lib/demo-data/router.ts), a
// documented, intentional no-backend hosted-demo mode; the real backend
// (confirmed live here) always issues a genuine UUID ticket.
//
// What WAS broken, all in the analyst-workflow chrome around that real
// core, and all fixed here:
//  - The right-click menu's "Create IOC" and "Create Alert Rule" items, and
//    the "Analyst Actions" grid (Create Sigma Rule/Hunt Similar/Add to
//    Case/Open Investigation), were pure no-ops (`action: () => {}` or no
//    onClick at all). "Create IOC" is now wired to the real `POST /api/iocs`
//    (via `iocsAPI.create`, the same helper Network Map already uses
//    correctly); "Create Alert Rule" has no simple one-click backend path,
//    so it now shows an honest "coming soon" toast; the four Analyst
//    Actions now navigate to the real page that can act on that data.
//  - The "Analyst Note" textarea had no persistence at all — its state was
//    local to a sub-component and keyed only by the currently-open log, so
//    it silently reset every time a different log was selected, discarding
//    whatever was typed with zero warning. Lifted into session-scoped
//    parent state (keyed by log id) so a note survives switching to another
//    log and back within the same session, honestly labeled "(this
//    session)" since there is no backend column to persist it further.
//  - The Tags input + "+" button had no onClick handler at all and no path
//    back to parent state even if it had — a broken feature end-to-end with
//    no real backend column to save to either. Removed rather than faked.
//  - Three static "AI" suggestion rows ("Why is this log suspicious?" /
//    "Identify anomalies in stream" / "Convert to Sigma rule") had no
//    onClick at all. The first two are wired to the real Explain/Summarize
//    handlers just above them (they were asking for exactly that); the
//    third now links to the real Sigma Rules page.
//  - The "Columns" button in Table view was a literal `onClick={() => {}}`
//    even though the column-visibility state (`hiddenCols`) and its
//    consumer (`TableView`'s column filtering) were already fully wired —
//    only the UI trigger to toggle it was ever missing. Added a real
//    checkbox popover.
test.use({ storageState: SHARED_STORAGE_STATE });

test.describe('Live Logs — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/live-logs');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    await page.waitForTimeout(2000); // let the WS historical backlog arrive

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/live-logs');
    await expect(page.getByText('EPS')).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(2000);
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });

  test('connects over a real WebSocket ticket, not the static-demo no-op path', async ({ page }) => {
    const ticketRes = await page.request.post('/api/ws/ticket');
    expect(ticketRes.ok()).toBe(true);
    const { ticket } = await ticketRes.json();
    expect(ticket).not.toBe('demo-ws-ticket-noop');
    expect(ticket).toMatch(/^[0-9a-f-]{36}$/);
  });
});

test.describe('Live Logs — regression guard: dead analyst-workflow buttons are gone', () => {
  test('no dead Tags input, and Analyst Actions link to real pages', async ({ page }) => {
    await page.goto('/live-logs');
    await expect(page.getByText('EPS')).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(2000);

    const firstLog = page.locator('.group.relative.flex.flex-col').first();
    if (await firstLog.count() > 0) {
      await firstLog.click();
      await expect(page.getByPlaceholder('Add tag…')).not.toBeVisible();

      const sigmaLink = page.getByRole('link', { name: /Create Sigma Rule/i });
      const huntLink  = page.getByRole('link', { name: /Hunt Similar/i });
      const caseLink  = page.getByRole('link', { name: /Add to Case/i });
      const invLink   = page.getByRole('link', { name: /Open Investigation/i });
      await expect(sigmaLink).toHaveAttribute('href', '/sigma-rules');
      await expect(huntLink).toHaveAttribute('href', '/hunt-workbench');
      await expect(caseLink).toHaveAttribute('href', '/cases');
      await expect(invLink).toHaveAttribute('href', '/dfir');
    }
  });

  test('"Create Alert Rule" shows an honest coming-soon toast instead of silently doing nothing', async ({ page }) => {
    await page.goto('/live-logs');
    await expect(page.getByText('EPS')).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(2000);

    const firstLog = page.locator('.group.relative.flex.flex-col').first();
    if (await firstLog.count() > 0) {
      await firstLog.click({ button: 'right' });
      const item = page.getByText('Create Alert Rule');
      if (await item.count() > 0) {
        await item.click();
        await expect(page.getByText(/coming soon/i)).toBeVisible({ timeout: 5_000 });
      }
    }
  });
});

test.describe('Live Logs — Columns picker now actually works', () => {
  test('unchecking a column hides it from the table view', async ({ page }) => {
    await page.goto('/live-logs');
    await expect(page.getByText('EPS')).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(2000);

    await page.getByRole('button', { name: /^Table$/ }).click();
    await page.getByRole('button', { name: /^Columns$/ }).click();

    const hostCheckbox = page.locator('label:has-text("Host") input[type="checkbox"]');
    await expect(hostCheckbox).toBeChecked();
    await hostCheckbox.uncheck();

    // Column header row should no longer show "Host" once unchecked.
    await expect(page.locator('.px-2.py-1\\.5.text-\\[9px\\]:has-text("Host")')).not.toBeVisible();
  });
});

test.describe('Live Logs — Create IOC', () => {
  test('creating an IOC from a log with a src_ip actually persists it', async ({ page }) => {
    await page.goto('/live-logs');
    await expect(page.getByText('EPS')).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(2000);

    // Find a log line whose right-click menu offers "Create IOC:" (i.e. it
    // parsed a src_ip or domain field).
    const lines = page.locator('.group.relative.flex.flex-col');
    const count = await lines.count();
    let created = false;
    for (let i = 0; i < Math.min(count, 20) && !created; i++) {
      await lines.nth(i).click({ button: 'right' });
      const iocItem = page.locator('button:has-text("Create IOC:")').first();
      if (await iocItem.count() > 0) {
        const label = (await iocItem.textContent())!.trim();
        const indicator = label.replace('Create IOC:', '').trim();
        const before = await (await page.request.get('/api/iocs')).json();
        const beforeList = before?.data ?? before;
        await iocItem.click();
        await expect(page.getByText(/IOC created/i)).toBeVisible({ timeout: 5_000 });
        const after = await (await page.request.get('/api/iocs')).json();
        const afterList = after?.data ?? after;
        expect(afterList.some((x: any) => x.indicator === indicator)).toBe(true);
        created = true;
      } else {
        await page.keyboard.press('Escape');
      }
    }
    test.skip(!created, 'no log line in the current buffer had a src_ip/domain field to create an IOC from');
  });
});

test.describe('Live Logs — Analyst Note persists within the session', () => {
  test('typing a note, switching logs, and switching back keeps the note', async ({ page }) => {
    await page.goto('/live-logs');
    await expect(page.getByText('EPS')).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(2000);

    const lines = page.locator('.group.relative.flex.flex-col');
    const count = await lines.count();
    test.skip(count < 2, 'need at least 2 log lines in the buffer for this test');

    await lines.nth(0).click();
    const noteBox = page.getByPlaceholder('Add a note to this log…');
    await noteBox.fill('investigate this — looks like brute force');

    await lines.nth(1).click();
    await lines.nth(0).click();
    await expect(page.getByPlaceholder('Add a note to this log…')).toHaveValue('investigate this — looks like brute force');
  });
});
