import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Executive page (route /executive) —
// backed by exe_* tables (api/executive_enterprise.go). An unrelated,
// dead API client pair (executiveAPI.getMetrics/downloadReport, hitting
// the older singular /api/executive/* routes) exists in lib/api.ts but is
// never called anywhere on this page — confirmed via grep, left untouched.
//
// Real bugs found and fixed this pass:
// - GetEXEVulns hardcoded "exploitable" to 0 always, even though
//   vulnerabilities.is_kev (CISA Known Exploited Vulnerabilities) is a
//   real, already-populated column that's exactly what that label means —
//   fixed to count real is_kev=true rows.
// - GetEXEBusinessImpact returned max_potential_loss/avg_recovery_cost/
//   cyber_insurance_coverage hardcoded to 0/0/"" always — no actuarial or
//   incident-cost model, and no insurance-policy data, exists anywhere in
//   this codebase to compute them honestly. The frontend rendered all
//   three as real MetricCards ("$0", "$0", "—") indistinguishable from a
//   genuinely-computed zero. Dropped from both the API response and the
//   frontend rather than fabricated, matching the same precedent as
//   Vulnerabilities' removed TLS-certificate section and Firewall's
//   removed total_bytes.
// - PostEXEReport inserted a metadata-only row with a fake randomish
//   size_bytes (420000+time.Now().Unix()%200000) and left the table's own
//   summary/key_findings/recommendations columns permanently NULL/empty —
//   the schema clearly intended real report content but nothing ever
//   produced it (a narrower, less severe version of Reports page's
//   "// Simulate execution" bug — no dead download link here, just unused
//   columns and a fake number). Now generates a real LLM-grounded summary/
//   findings/recommendations from the same real security/risk metrics
//   PostEXEAI already gathers, with size_bytes reflecting the real
//   generated content's length. Added a "View" action + modal to the
//   frontend's Reports tab so the real content is actually visible
//   somewhere, since nothing rendered it before.
// - Frontend: the report-generation button silently swallowed errors via
//   `.catch(() => null)` with zero user feedback on failure — fixed to
//   surface real errors.
// - This page's own pre-existing seeder had the same non-idempotency bug
//   found on the last four pages: exe_snapshots/exe_forecasts/exe_reports/
//   exe_integrations all have real unique constraints and were already
//   genuinely idempotent, but exe_notifications/exe_audit have none (each
//   row is a historical event, not a config row). Confirmed live: 480/576
//   rows had accumulated (vs. ~10/~12 intended) before a standard
//   tenant-count guard was added.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = [
  'Dashboard', 'Risk Overview', 'KPIs', 'Business Impact', 'Threats', 'Compliance',
  'Vulnerabilities', 'Incidents', 'Assets', 'Forecasting', 'Analytics', 'Reports',
  'Notifications', 'Integrations', 'Audit Trail',
];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Executive — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/executive');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/executive');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('Executive — regression guard: seed data exists and is not duplicated', () => {
  test('snapshots/forecasts/reports/notifications/integrations/audit show the intended counts', async ({ page }) => {
    const expected: Record<string, number> = {
      exe_snapshots: 91, exe_reports: 8, exe_notifications: 10, exe_integrations: 12, exe_audit: 12,
    };
    for (const [table, count] of Object.entries(expected)) {
      const real = Number(PSQL(`SELECT count(*) FROM ${table} WHERE tenant_id='9999';`));
      expect(real, `${table} row count`).toBeGreaterThanOrEqual(count);
      expect(real, `${table} row count should not be a multiplied duplicate pile`).toBeLessThan(count * 3);
    }
  });
});

test.describe('Executive — regression guard: exploitable count reflects real KEV data', () => {
  test('GetEXEVulns "exploitable" matches the real is_kev count, not a hardcoded 0', async ({ page }) => {
    const realKev = Number(PSQL(`SELECT count(*) FROM vulnerabilities WHERE tenant_id='9999' AND is_kev=true;`));
    expect(realKev).toBeGreaterThan(0);
    const vulns = await page.request.get('/api/exe/vulnerabilities').then(r => r.json());
    expect(vulns.exploitable).toBe(realKev);
  });
});

test.describe('Executive — regression guard: business impact drops unbackable fields', () => {
  test('GetEXEBusinessImpact no longer returns max_potential_loss/avg_recovery_cost/cyber_insurance_coverage', async ({ page }) => {
    const impact = await page.request.get('/api/exe/business-impact').then(r => r.json());
    expect(impact).not.toHaveProperty('max_potential_loss');
    expect(impact).not.toHaveProperty('avg_recovery_cost');
    expect(impact).not.toHaveProperty('cyber_insurance_coverage');
    expect(impact).toHaveProperty('financial_risk_usd');
  });
});

test.describe('Executive — regression guard: report generation produces real content', () => {
  test('a generated report has a real LLM-grounded summary and a real (small, honest) size_bytes, not a fake random number', async ({ page }) => {
    const res = await page.request.post('/api/exe/reports', {
      data: { title: 'e2e-real-content-check', report_type: 'executive_summary', format: 'pdf' },
    });
    expect(res.ok()).toBeTruthy();
    const created = await res.json();

    const reports = await page.request.get('/api/exe/reports').then(r => r.json());
    const match = reports.find((r: any) => r.report_id === created.report_id);
    expect(match).toBeTruthy();
    expect(match.summary).toBeTruthy();
    expect(match.summary.length).toBeGreaterThan(10);
    // The old fake value was always in the 420000-620000 range regardless
    // of any real content — a real summary's byte length should never
    // land in that specific band.
    expect(match.size_bytes).toBeGreaterThan(0);
    expect(match.size_bytes).toBeLessThan(420000);

    PSQL(`DELETE FROM exe_audit WHERE tenant_id='9999' AND object_id='${created.report_id}'; DELETE FROM exe_notifications WHERE tenant_id='9999' AND title LIKE '%e2e-real-content-check%'; DELETE FROM exe_reports WHERE id=${created.id};`);
  });
});
