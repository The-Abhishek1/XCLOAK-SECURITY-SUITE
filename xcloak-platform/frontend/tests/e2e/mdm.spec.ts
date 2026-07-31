import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Mobile / MDM page (route /mdm) —
// backed by mdme_* tables (api/mdm_enterprise.go).
//
// Real bugs found and fixed this pass:
// - GetMDMECompliance's `violations` array had 3 fully hardcoded entries
//   ("OS below minimum version": 3, "Expired certificate": 2, "Blocked app
//   installed": 5) mixed in with 3 already-real ones. "OS below minimum
//   version" is now computed for real — per-platform strictest enabled
//   policy min_os_version compared against each real device's os_version
//   via a small dotted-version-number comparator. "Blocked app installed"
//   is now a real COUNT(DISTINCT device_id) against mdme_apps. "Expired
//   certificate" was dropped — no certificate-expiry column exists
//   anywhere on mdme_devices (unlike Assets/CMDB's cert_expiry_days).
// - GetMDMEAnalytics's top_apps/enrollment_trend/compliance_trend/
//   threat_trend were all fully hardcoded fake arrays. top_apps is now a
//   real device-count grouping (the same query GetMDMEApps already does
//   correctly elsewhere on this page, just never reused here).
//   enrollment_trend is now real, computed from enrolled_at/updated_at
//   over the last 6 real calendar months — no new snapshot table needed,
//   the same pattern used on Assets/CMDB's asset_growth. compliance_trend
//   was dropped (no real historical basis — compliance_status has no
//   change-history tracking) and threat_trend was dropped as dead code,
//   confirmed via grep it was never rendered anywhere in the frontend.
// - PostMDMEReport had a fake random size_bytes and no summary column at
//   all (the 5th occurrence of this report-generation pattern this
//   phase) — now generates a real LLM-grounded summary from real fleet
//   metrics, size_bytes reflects real content length. This handler also
//   never called mdmeAudit/mdmeNotify at all (every other write action on
//   this page does) — added both for consistency. Added a "View" modal to
//   the frontend Reports tab.
// - The page fetched real notifications into state but had no
//   Notifications tab anywhere — the same gap just found on SOC Metrics
//   and Assets/CMDB, the third page in a row missing one. Added one,
//   matching the established pattern.
// - Frontend: DevicePanel's sendAction, RemoteActionsTab's send,
//   ThreatsTab's resolve/investigate, ReportsTab's generate, and the
//   notifications mark-read handler all had zero error handling — added
//   try/catch to all five.
// - This page's own pre-existing seeder had the same non-idempotency bug
//   found on the last seven pages: mdme_devices/mdme_policies/
//   mdme_threats/mdme_remote_actions/mdme_reports all have real unique
//   constraints and were already genuinely idempotent, but mdme_apps has
//   an `ON CONFLICT DO NOTHING` with no real matching unique constraint
//   (a no-op), and mdme_timeline/mdme_notifications/mdme_audit have no
//   ON CONFLICT clause at all. Confirmed live: 1380/780/600/720 rows had
//   accumulated (vs. ~23/~13/~10/~12 intended) before a standard
//   tenant-count guard was added.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = [
  'Dashboard', 'Devices', 'Applications', 'Policies', 'Compliance', 'Remote Actions',
  'Threats', 'Analytics', 'AI Assistant', 'Reports', 'Notifications', 'Audit Trail',
];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('MDM — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/mdm');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('main').getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/mdm');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('main').getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('MDM — regression guard: seed data exists and is not duplicated', () => {
  test('devices/apps/policies/threats/actions/reports/notifications/audit show the intended counts', async ({ page }) => {
    const expected: Record<string, number> = {
      mdme_devices: 11, mdme_apps: 23, mdme_policies: 6, mdme_threats: 8,
      mdme_remote_actions: 10, mdme_reports: 7, mdme_notifications: 10, mdme_audit: 12,
    };
    for (const [table, count] of Object.entries(expected)) {
      const real = Number(PSQL(`SELECT count(*) FROM ${table} WHERE tenant_id='9999';`));
      expect(real, `${table} row count`).toBeGreaterThanOrEqual(count);
      expect(real, `${table} row count should not be a multiplied duplicate pile`).toBeLessThan(count * 3);
    }
  });
});

test.describe('MDM — regression guard: bridged data reflects real state, not hardcoded fakes', () => {
  test('compliance violations are real, and the unbackable "Expired certificate" is dropped', async ({ page }) => {
    const realBlockedAppDevices = Number(PSQL(`SELECT count(DISTINCT device_id) FROM mdme_apps WHERE tenant_id='9999' AND status='blocked';`));
    expect(realBlockedAppDevices).toBeGreaterThan(0);

    const compliance = await page.request.get('/api/mdme/compliance').then(r => r.json());
    const blockedViolation = compliance.violations.find((v: any) => v.violation === 'Blocked app installed');
    expect(blockedViolation?.count).toBe(realBlockedAppDevices);
    expect(compliance.violations.map((v: any) => v.violation)).not.toContain('Expired certificate');
  });

  test('analytics top_apps/enrollment_trend are real, and dead compliance_trend/threat_trend are dropped', async ({ page }) => {
    const realOutlookDevices = Number(PSQL(`SELECT count(DISTINCT device_id) FROM mdme_apps WHERE tenant_id='9999' AND app_name='Microsoft Outlook';`));
    const analytics = await page.request.get('/api/mdme/analytics').then(r => r.json());
    const outlook = analytics.top_apps.find((a: any) => a.app_name === 'Microsoft Outlook');
    expect(outlook?.device_count).toBe(realOutlookDevices);
    expect(analytics).not.toHaveProperty('compliance_trend');
    expect(analytics).not.toHaveProperty('threat_trend');
    expect(analytics.enrollment_trend).toHaveLength(6);
    const realDeviceCount = Number(PSQL(`SELECT count(*) FROM mdme_devices WHERE tenant_id='9999';`));
    expect(analytics.enrollment_trend[5].enrolled).toBeLessThanOrEqual(realDeviceCount);
  });
});

test.describe('MDM — regression guard: report generation produces real content', () => {
  test('a generated report has a real summary and a real (small, honest) size_bytes, not a fake random number', async ({ page }) => {
    const res = await page.request.post('/api/mdme/reports', {
      data: { title: 'e2e-real-content-check', report_type: 'device_inventory', format: 'pdf' },
    });
    expect(res.ok()).toBeTruthy();
    const created = await res.json();
    expect(created.summary).toBeTruthy();
    expect(created.summary.length).toBeGreaterThan(10);

    const reports = await page.request.get('/api/mdme/reports').then(r => r.json());
    const match = reports.find((r: any) => r.report_id === created.report_id);
    expect(match).toBeTruthy();
    expect(match.summary).toBe(created.summary);
    // The old fake value was always in the 150000-650000 range regardless
    // of any real content.
    expect(match.size_bytes).toBeGreaterThan(0);
    expect(match.size_bytes).toBeLessThan(150_000);

    PSQL(`DELETE FROM mdme_audit WHERE tenant_id='9999' AND object_id='${created.report_id}'; DELETE FROM mdme_notifications WHERE tenant_id='9999' AND title LIKE '%e2e-real-content-check%'; DELETE FROM mdme_reports WHERE report_id='${created.report_id}';`);
  });
});

test.describe('MDM — regression guard: notifications can actually be marked read', () => {
  test('the Notifications tab renders real notifications and mark-all-read persists to the database', async ({ page }) => {
    PSQL(`UPDATE mdme_notifications SET read=FALSE WHERE tenant_id='9999';`);
    const unreadBefore = Number(PSQL(`SELECT count(*) FROM mdme_notifications WHERE tenant_id='9999' AND read=FALSE;`));
    expect(unreadBefore).toBeGreaterThan(0);

    await page.goto('/mdm');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    await page.getByRole('main').getByRole('button', { name: /^Notifications\b/ }).click();
    await expect(page.getByRole('button', { name: /Mark all read/ })).toBeVisible();
    const [patchResp] = await Promise.all([
      page.waitForResponse(r => r.url().includes('/api/mdme/notifications/read') && r.request().method() === 'PATCH'),
      page.getByRole('button', { name: /Mark all read/ }).click(),
    ]);
    expect(patchResp.ok()).toBeTruthy();
    await page.waitForTimeout(300);

    const unreadAfter = Number(PSQL(`SELECT count(*) FROM mdme_notifications WHERE tenant_id='9999' AND read=FALSE;`));
    expect(unreadAfter).toBe(0);
  });
});
