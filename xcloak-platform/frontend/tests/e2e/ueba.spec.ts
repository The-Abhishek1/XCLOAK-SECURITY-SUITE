import { test, expect, Page } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the UEBA page (list + detail view). Runs
// against a REAL backend + seeded DB — see dashboard.spec.ts's header comment
// for the dev-stack recipe and global-setup.ts for the shared-login rationale.
//
// The most severe issue found on this page: 7 of 8 "Response Actions"
// (Disable User, Reset Password, Require MFA, Block VPN, Isolate Endpoint,
// Kill Process, Run SOAR Playbook) returned a canned success string with NO
// real backend effect at all — no IdP call, no agent task, no playbook run —
// while logging a fake "completed" entry into the user's own UEBA timeline.
// An analyst responding to a flagged insider threat would believe the
// account was disabled or the endpoint isolated when nothing happened.
// Removed everything except Force Logout (the only one with a real effect —
// revokes session rows). Also removed a large amount of dead/fake anomaly
// detection UI (Network/File/Endpoint Behavior cards, MITRE mapping) that
// checked for event types and profile flags the UEBA analyzer
// (services/ueba_service.go) never produces, including two fields
// ("Beaconing Detected"/"DNS Tunneling") that were hardcoded to always
// show "No" rather than checking anything at all.
test.use({ storageState: SHARED_STORAGE_STATE });

function kpiValue(page: Page, label: string) {
  return page.locator('.g-card', { hasText: label }).first().locator('p.font-bold').first();
}

async function openFirstUser(page: Page) {
  await page.goto('/ueba');
  await expect(page.locator('.g-tr').first()).toBeVisible({ timeout: 15_000 });
  await page.locator('.g-tr').first().click();
}

test.describe('UEBA — route health', () => {
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

    await page.goto('/ueba');
    await page.waitForLoadState('networkidle', { timeout: 15_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/ueba');
    await expect(page.locator('.g-tr').first()).toBeVisible({ timeout: 15_000 });

    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });

  test('KPI strip (Total/Critical/High Risk) matches live /api/ueba/users', async ({ page }) => {
    const data = await (await page.request.get('/api/ueba/users?limit=200')).json();
    const profiles: Array<{ risk_score: number }> = data.profiles ?? [];
    // Matches the app's own (cumulative, not banded) definitions exactly:
    // highRiskCount is ">=60" and includes critical users too.
    const critical = profiles.filter(u => u.risk_score >= 80).length;
    const high = profiles.filter(u => u.risk_score >= 60).length;

    await page.goto('/ueba');
    await expect(kpiValue(page, 'Total Users')).toHaveText(String(profiles.length), { timeout: 15_000 });
    await expect(kpiValue(page, 'Critical Risk')).toHaveText(String(critical), { timeout: 15_000 });
    await expect(kpiValue(page, 'High Risk')).toHaveText(String(high), { timeout: 15_000 });
  });
});

test.describe('UEBA — detail view regression guard', () => {
  test('no dead/fabricated detection UI survives', async ({ page }) => {
    await openFirstUser(page);
    const detail = page.getByTestId('ueba-user-detail');
    await expect(detail.getByText('Risk Classification')).toBeVisible({ timeout: 15_000 });

    // Scoped to the detail panel, not the whole page — the sidebar has its
    // own unrelated "Process Injection" nav link that would false-positive
    // a page-wide text search.
    const bodyText = await detail.innerText();
    for (const banned of [
      'Working Hours',
      'Network Behavior', 'Beaconing Detected', 'DNS Tunneling',
      'File Behavior', 'Mass File Access', 'Mass File Deletion', 'Sensitive File Access',
      'Rare Process', 'Rare Application', 'Rare Country', 'Rare Device', 'Rare Network',
      'Rare Parent Process', 'Rare Command Line',
      'PowerShell Usage', 'Bash Activity', 'New Service', 'Registry Change',
      'Process Injection', 'Persistence',
    ]) {
      expect(bodyText, `found banned dead/fabricated string: "${banned}"`).not.toContain(banned);
    }
  });

  test('only the real Force Logout response action is offered', async ({ page }) => {
    await openFirstUser(page);
    await expect(page.getByText('Response Actions')).toBeVisible({ timeout: 15_000 });

    await expect(page.getByRole('button', { name: 'Force Logout' })).toBeVisible();
    for (const removed of [
      'Disable User', 'Reset Password', 'Require MFA', 'Block VPN',
      'Isolate Endpoint', 'Kill Process', 'Run SOAR Playbook',
    ]) {
      await expect(page.getByRole('button', { name: removed })).toHaveCount(0);
    }
  });

  test('detail view renders without console errors', async ({ page }) => {
    const consoleErrors: string[] = [];
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await openFirstUser(page);
    await page.waitForLoadState('networkidle', { timeout: 15_000 });

    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('Force Logout dispatches a real request and the backend rejects any other action', async ({ page }) => {
    const data = await (await page.request.get('/api/ueba/users?limit=200')).json();
    const username = data.profiles[0].username;

    await openFirstUser(page);
    await page.getByRole('button', { name: 'Force Logout' }).click();
    // Scoped to the toast — the same text also legitimately appears in the
    // timeline once the action is logged as a real event.
    await expect(page.locator('div.fixed.bottom-4.right-4')).toContainText(/sessions for .* revoked/i, { timeout: 10_000 });

    // Regression guard at the API level — if a fake action button ever gets
    // re-added to the UI without backend support, this still catches it.
    const res = await page.request.post(`/api/ueba/users/${username}/response-action`, {
      data: { action: 'isolate_endpoint' },
    });
    expect(res.status()).toBe(400);
  });
});
