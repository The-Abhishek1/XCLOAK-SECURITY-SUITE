import { test, expect, Page } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Insider Threat page (list + detail view).
// Runs against a REAL backend + seeded DB — see dashboard.spec.ts's header
// comment for the dev-stack recipe and global-setup.ts for the shared-login
// rationale.
//
// This page shares a near-identical shape (and near-identical bugs) with the
// UEBA page — same response-action fakery, same class of dead detection UI,
// evidently from copy-pasted code. See ueba.spec.ts for the fuller writeup;
// summarized here:
//   - InsiderThreatResponseAction (api/insider_threat_enterprise.go) faked
//     10 of 11 actions (disable_user/lock_account/require_mfa/block_usb/
//     block_cloud/isolate_endpoint/kill_process/remove_privileges/legal_hold/
//     run_playbook) with a canned success string and no real backend effect,
//     fake-logged as a real timeline event. Fixed to only accept force_logout.
//   - DataExfilCard, USBCloudCard, and SensitiveAccessCard (all removed) and
//     most of BehavioralIndicatorsCard + "Privileged User Monitoring" checked
//     event types/flags services/ueba_service.go never produces (USB copy,
//     cloud upload, mass file access/deletion, source code access,
//     encryption, print jobs, HR/finance/payroll/credential access, service
//     account login, cloud admin access, account creation, etc.) — trimmed
//     to only what's backed by a real signal.
//   - The demo seeder's insider_threat_scores.contributors used the wrong
//     JSON keys entirely (off_hours/failed_logins/data_access instead of
//     the real off_hours_auth/failed_auth/data_exfil/sensitive_access/
//     privesc_attempt/anomalous_location), so the Signal Breakdown UI
//     rendered nothing for every demo-seeded user. Fixed + reseeded.
test.use({ storageState: SHARED_STORAGE_STATE });

function kpiValue(page: Page, label: string) {
  return page.locator('.g-card', { hasText: label }).first().locator('p.font-bold').first();
}

async function openFirstUser(page: Page) {
  await page.goto('/insider-threat');
  await expect(page.locator('.g-tr').first()).toBeVisible({ timeout: 15_000 });
  await page.locator('.g-tr').first().click();
}

test.describe('Insider Threat — route health', () => {
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

    await page.goto('/insider-threat');
    await page.waitForLoadState('networkidle', { timeout: 15_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/insider-threat');
    await expect(page.locator('.g-tr').first()).toBeVisible({ timeout: 15_000 });

    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });

  test('KPI strip (Total Users/Critical/High Risk) matches live /api/insider-threat', async ({ page }) => {
    const scores: Array<{ score: number }> = await (await page.request.get('/api/insider-threat?days=7&min_score=0')).json();
    const critical = scores.filter(s => s.score >= 80).length;
    const high = scores.filter(s => s.score >= 60).length; // cumulative, includes critical

    await page.goto('/insider-threat');
    await expect(kpiValue(page, 'Total Users')).toHaveText(String(scores.length), { timeout: 15_000 });
    await expect(kpiValue(page, 'Critical')).toHaveText(String(critical), { timeout: 15_000 });
    await expect(kpiValue(page, 'High Risk')).toHaveText(String(high), { timeout: 15_000 });
  });
});

test.describe('Insider Threat — detail view regression guard', () => {
  test('Signal Breakdown reflects the real per-user contributors (seed-key fix)', async ({ page }) => {
    const scores: Array<{ username: string; contributors: Record<string, number> }> =
      await (await page.request.get('/api/insider-threat?days=7&min_score=0')).json();
    const target = scores[0];

    await openFirstUser(page);
    await expect(page.getByText('Signal Breakdown')).toBeVisible({ timeout: 15_000 });

    // Real CONTRIB_META labels the page renders for each contributor key.
    const LABELS: Record<string, string> = {
      off_hours_auth: 'Off-Hours Auth', failed_auth: 'Failed Auth', data_exfil: 'Data Exfiltration',
      sensitive_access: 'Sensitive Access', privesc_attempt: 'Priv Escalation', anomalous_location: 'Anomalous Location',
    };
    for (const [key, label] of Object.entries(LABELS)) {
      const val = target.contributors[key] ?? 0;
      const row = page.locator('div', { hasText: label }).last();
      await expect(row).toContainText(`${val}/`);
    }
  });

  test('no dead/fabricated detection UI survives', async ({ page }) => {
    await openFirstUser(page);
    await expect(page.getByText('Signal Breakdown')).toBeVisible({ timeout: 15_000 });

    const bodyText = await page.locator('body').innerText();
    for (const banned of [
      'Data Exfiltration Detection', 'USB / Cloud', 'Sensitive Data Access',
      'USB Copy', 'Mass File Copy', 'Mass File Deletion', 'Encryption Tool',
      'Weekend Activity', 'New Device Usage', 'Accessing Unusual Systems',
      'Printing Sensitive Files', 'HR Files', 'Finance Data', 'Payroll',
      'Customer Database', 'Password Vaults', 'Intellectual Property',
      'Service Account Login', 'Cloud Admin Access', 'Unusual Admin Activity',
      'Account Creation',
    ]) {
      expect(bodyText, `found banned dead/fabricated string: "${banned}"`).not.toContain(banned);
    }
  });

  test('only the real Force Logout response action is offered', async ({ page }) => {
    await openFirstUser(page);
    await expect(page.getByRole('button', { name: 'Force Logout' })).toBeVisible({ timeout: 15_000 });

    for (const removed of [
      'Disable User', 'Lock Account', 'Require MFA', 'Block USB', 'Block Cloud Upload',
      'Isolate Endpoint', 'Kill Process', 'Remove Privileges', 'Legal Hold', 'Run SOAR Playbook',
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
    const scores: Array<{ username: string }> = await (await page.request.get('/api/insider-threat?days=7&min_score=0')).json();
    const username = scores[0].username;

    await openFirstUser(page);
    await page.getByRole('button', { name: 'Force Logout' }).click();
    await expect(page.locator('div.fixed.bottom-4.right-4, div.fixed.bottom-5.right-5'))
      .toContainText(/sessions revoked/i, { timeout: 10_000 });

    const res = await page.request.post(`/api/insider-threat/users/${username}/response-action`, {
      data: { action: 'isolate_endpoint' },
    });
    expect(res.status()).toBe(400);
  });
});
