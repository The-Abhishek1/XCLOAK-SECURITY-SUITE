import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Cloud Security page (route
// /cloud-security) — CSPM/CIEM/CWPP/multi-cloud asset security.
//
// This page's frontend and backend were both genuinely well-built —
// real queries against real columns throughout (double-checked, no
// fabrication found across any of the 9 tabs) — with two real exceptions:
//
// - `PostCloudResponse`'s `block_ip` action had no case in the switch at
//   all — it fell through doing nothing while the handler still returned
//   200 "queued" and logged a (now-real, after last pass's fix) alert.
//   Fixed with a real enabled IOC, matching every other page's block_ip
//   this phase (this domain has no real cloud firewall/security-group API
//   integration to enforce against).
// - `disable_iam_user` only ever checked `body.IdentityID`, but the one
//   real caller (DetectionTab, responding to a `cloud_threats` row) never
//   had a numeric `cloud_identities.id` to send — a threat only carries
//   `source_user`, a name string — so this action silently did nothing on
//   every real invocation from the UI. Fixed to also resolve by name, with
//   an honest message when there's no matching identity on file (the
//   common case — a threat's source_user is often an external/unmanaged
//   account, not one of our own tracked identities).
//
// **The bigger issue wasn't a bug in the handlers at all**: this page's
// own dedicated tables (cloud_accounts/cloud_assets/cloud_findings/
// cloud_identities/cloud_threats/cloud_drift_events) had zero seed data
// anywhere — confirmed live (`relation "cloud_accounts" does not exist`)
// — so every tab showed permanently empty regardless of how correct the
// code was. No scan/sync endpoint exists anywhere in this codebase (no
// real AWS/Azure/GCP API integration — this is a simulated CSPM/CIEM
// domain, same as the rest of the platform's approach), so unlike most
// pages this phase, the fix wasn't wiring up a broken read path but adding
// `seedCloudSecurity` to `cmd/seed/demo/main.go`, matching every other
// simulated domain in this codebase (agents, alerts, IOCs, threat actors,
// etc.) already having real seed data. Verified idempotent — a second
// seeder run doesn't duplicate any of the 6 tables' rows.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = ['Overview', 'Inventory', 'CSPM', 'CIEM', 'Detection',
  'Compliance', 'Attack Paths', 'Intelligence', 'Analytics'];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Cloud Security — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/cloud-security');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/cloud-security');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('Cloud Security — regression guard: seed data exists', () => {
  test('the dashboard shows real, non-zero counts instead of a permanently empty page', async ({ page }) => {
    const dash = await page.request.get('/api/cloud/dashboard').then(r => r.json());
    expect(dash.aws_accounts + dash.azure_subs + dash.gcp_projects).toBeGreaterThan(0);
    expect(dash.total_assets).toBeGreaterThan(0);

    const accounts = PSQL(`SELECT count(*) FROM cloud_accounts WHERE tenant_id=9999;`);
    expect(Number(accounts)).toBeGreaterThan(0);
    // Denormalized counters on cloud_accounts should reflect real child rows,
    // not sit at their zero defaults forever.
    const assetCount = PSQL(`SELECT asset_count FROM cloud_accounts WHERE tenant_id=9999 ORDER BY id LIMIT 1;`);
    expect(Number(assetCount)).toBeGreaterThan(0);
  });
});

test.describe('Cloud Security — regression guard: response actions are real, not a no-op', () => {
  test('block_ip creates a real, enabled IOC (previously had no case at all)', async ({ page }) => {
    const ip = `10.91.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    const res = await page.request.post('/api/cloud/response', {
      data: { action: 'block_ip', resource_id: 'e2e-asset', provider: 'aws', source_ip: ip },
    });
    expect(res.ok()).toBeTruthy();
    const count = PSQL(`SELECT count(*) FROM iocs WHERE indicator='${ip}' AND enabled=true;`);
    expect(Number(count)).toBe(1);
  });

  test('block_ip without source_ip fails honestly instead of silently no-oping', async ({ page }) => {
    const res = await page.request.post('/api/cloud/response', {
      data: { action: 'block_ip', resource_id: 'e2e-asset', provider: 'aws' },
    });
    expect(res.status()).toBe(400);
  });

  test('disable_iam_user resolves a real identity by name and reports success', async ({ page }) => {
    const name = `e2e-svc-account-${Date.now()}`;
    PSQL(`INSERT INTO cloud_identities (tenant_id, name, identity_type, provider, is_dormant) VALUES (9999, '${name}', 'service_account', 'aws', false);`);

    const res = await page.request.post('/api/cloud/response', {
      data: { action: 'disable_iam_user', resource_id: 'e2e-asset', provider: 'aws', source_user: name },
    });
    expect(res.ok()).toBeTruthy();

    const dormant = PSQL(`SELECT is_dormant FROM cloud_identities WHERE tenant_id=9999 AND name='${name}';`);
    expect(dormant).toBe('t');
  });

  test('disable_iam_user reports an honest message when the source_user has no matching identity', async ({ page }) => {
    const res = await page.request.post('/api/cloud/response', {
      data: { action: 'disable_iam_user', resource_id: 'e2e-asset', provider: 'aws', source_user: 'not-a-real-identity-e2e' },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.message).toContain('no cloud identity named');
  });

  test('an unrecognized action is rejected rather than silently reporting success', async ({ page }) => {
    const res = await page.request.post('/api/cloud/response', {
      data: { action: 'not_a_real_action', resource_id: 'e2e-asset', provider: 'aws' },
    });
    expect(res.status()).toBe(400);
  });
});
