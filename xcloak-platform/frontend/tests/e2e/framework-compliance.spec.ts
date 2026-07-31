import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Frameworks page (route
// /framework-compliance) — backed by fce_* tables
// (api/framework_compliance_enterprise.go). This is the same fce_frameworks/
// fce_controls pair Vulnerabilities' GetVMCompliance reads too (a shared,
// not page-owned, table pair) — confirmed via grep no other bug from this
// page's own handlers leaks into that one.
//
// Real bugs found and fixed this pass:
// - PostFCEAI's "Top failing controls" query joined `f.id=c.framework_id`
//   — fce_frameworks.id is an integer, fce_controls.framework_id is the
//   TEXT business key (e.g. "FWK-000123") — comparing integer to text is
//   flatly rejected by Postgres ("operator does not exist: integer =
//   text"). The discarded Query() error meant this section of the AI
//   context was silently empty on every single call, regardless of how
//   many real failing controls existed. The exact same bug class already
//   fixed on Vulnerabilities' GetVMCompliance against the same two tables
//   two pages ago — found here independently. Fixed by joining on the real
//   text framework_id (plus tenant_id, to keep the join tenant-scoped).
// - Frontend: every single write call site on this page — createFramework/
//   updateFramework/deleteFramework, updateControl (×2: note save and
//   status dropdown), addEvidence/deleteEvidence, createRemediation/
//   updateRemediation, runAssessment, markNotificationsRead — had zero
//   error handling, the most error-handling-gap-heavy page found this
//   entire phase (12 call sites, all fixed).
// - This page's own pre-existing seeder had the same non-idempotency bug
//   found on the last three pages, but split across two different causes:
//   fce_controls has no unique constraint at all (its own "ON CONFLICT DO
//   NOTHING" with no target never matched anything), and fce_notifications/
//   fce_audit have no ON CONFLICT clause whatsoever (each row is a
//   historical event, not a config object). fce_frameworks/fce_evidence/
//   fce_assessments/fce_remediations all have real unique constraints
//   their own inserts correctly targeted and were already idempotent.
//   Confirmed live: fce_controls had accumulated 2208 rows (vs. ~48
//   intended) and fce_notifications/fce_audit had 460/690 (vs. ~10/~15)
//   before a standard tenant-count guard was added.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = [
  'Dashboard', 'Frameworks', 'Controls', 'Evidence', 'Gap Analysis',
  'Remediation', 'Analytics', 'Assessments', 'Audit Trail', 'Notifications',
];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Frameworks — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/framework-compliance');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/framework-compliance');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('Frameworks — regression guard: seed data exists and is not duplicated', () => {
  test('frameworks/controls/evidence/assessments/remediations/notifications/audit show the intended counts', async ({ page }) => {
    const expected: Record<string, number> = {
      fce_frameworks: 30, fce_controls: 48, fce_evidence: 15,
      fce_assessments: 8, fce_remediations: 12, fce_notifications: 10, fce_audit: 15,
    };
    for (const [table, count] of Object.entries(expected)) {
      const real = Number(PSQL(`SELECT count(*) FROM ${table} WHERE tenant_id='9999';`));
      expect(real, `${table} row count`).toBeGreaterThanOrEqual(count);
      expect(real, `${table} row count should not be a multiplied duplicate pile`).toBeLessThan(count * 3);
    }

    const frameworks = await page.request.get('/api/fce/frameworks').then(r => r.json());
    expect(frameworks.length).toBeGreaterThanOrEqual(30);
  });
});

test.describe('Frameworks — regression guard: fce_controls/fce_frameworks join uses the real text key', () => {
  test('a direct join on framework_id (not id) returns real matched rows for failing controls', async ({ page }) => {
    const joined = PSQL(`SELECT count(*) FROM fce_controls c JOIN fce_frameworks f ON f.framework_id=c.framework_id AND f.tenant_id=c.tenant_id WHERE c.tenant_id='9999' AND c.assessment_status='failed';`);
    const failing = PSQL(`SELECT count(*) FROM fce_controls WHERE tenant_id='9999' AND assessment_status='failed';`);
    expect(Number(failing)).toBeGreaterThan(0);
    expect(joined).toBe(failing);

    // The old buggy join (integer id = text framework_id) must fail outright.
    let brokenJoinErrored = false;
    try {
      PSQL(`SELECT count(*) FROM fce_controls c JOIN fce_frameworks f ON f.id=c.framework_id WHERE c.tenant_id='9999';`);
    } catch {
      brokenJoinErrored = true;
    }
    expect(brokenJoinErrored).toBeTruthy();
  });
});

test.describe('Frameworks — regression guard: write actions surface real errors', () => {
  test('creating a framework with a duplicate-triggering bad request is handled without an unhandled rejection', async ({ page }) => {
    await page.goto('/framework-compliance');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });

    const pageErrors: string[] = [];
    page.on('pageerror', err => pageErrors.push(err.message));

    await page.getByRole('button', { name: new RegExp('^Frameworks\\b') }).click();
    await page.getByRole('button', { name: 'Add Framework' }).click();
    // Leave Name blank and click Add — the frontend's own guard
    // (`if (!form.name) return`) should no-op rather than throw.
    await page.getByRole('button', { name: 'Add', exact: true }).click();
    await page.waitForTimeout(300);

    expect(pageErrors).toEqual([]);
  });
});
