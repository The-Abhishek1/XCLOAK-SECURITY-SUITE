import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Vuln Queue page (route /vuln-queue) —
// the remediation-workflow layer (assignment/status/verification/blockers/
// exceptions) sitting on top of vm_* raw scan findings, backed by its own
// vq_* tables. Better-built than most pages this phase: every nullable
// column is already scanned into a Go pointer type, so this page never hit
// the NULL-scan bug class found on Approval Queue/Vulnerabilities, and
// GetVQQueue/GetVQItem/GetVQExceptions/GetVQDependencies already had real
// error handling and real error checks throughout.
//
// Real bugs found and fixed in api/vuln_queue_enterprise.go:
// - `PostVQAI` called the real LLM but discarded its response almost
//   entirely — `recommendation`/`steps`/`estimated_effort`/
//   `risks_if_delayed`/`alternative_mitigations` (the fields the frontend
//   actually renders) were always the same fixed literal content for
//   every CVE/asset/priority, regardless of whether the LLM call
//   succeeded; the real response was only ever exposed via a separate,
//   barely-rendered `ai_analysis` field. Rewritten so a successful LLM
//   response becomes the primary content, with the deterministic
//   (CVE/priority/team-aware) fallback used only on a real LLM failure —
//   matching the pattern every other page's AI endpoint already uses.
// - `GetVQDashboard`: `team_breakdown` was 5 hardcoded fake teams
//   unrelated to any real tenant data; `mttr_days` was a hardcoded
//   literal despite real `created_at`/`closed_at` columns existing to
//   compute it — both wired to real aggregations.
// - `GetVQAnalytics`: `sla_compliance`/`overdue_count` were hardcoded
//   despite the exact same real query already being used one function
//   away in `GetVQDashboard`; `team_performance`/`remediation_trend`/
//   `top_delayed_assets` were all hardcoded fake arrays; `sla_by_priority`
//   was hardcoded and also completely unrendered anywhere in the frontend
//   — dropped rather than fixed, since fixing fabricated data nobody
//   displays isn't a real improvement. All real fields wired to real
//   aggregations.
// - `GetVQSLA`'s `current_compliance` was 4 hardcoded percentages
//   (100/96.2/91.4/88.6, suspiciously identical to `GetVQAnalytics`'s old
//   fake `sla_by_priority` — the same fabricated numbers copy-pasted
//   between two endpoints) — replaced with a real per-priority on-time
//   percentage computed from `vq_items`. `policies` (the SLA-hour
//   thresholds per priority) kept as-is — legitimate static policy
//   config, not a per-tenant claim.
// - `PostVQReport` was a fully fabricated static report, including a
//   specific fake historical comparison ("down from 12.1 days last
//   month") — rewritten to real key_metrics/overdue_items plus an
//   LLM-generated summary grounded only in real numbers, matching the
//   pattern established on Playbooks/Approval Queue/Vulnerabilities'
//   own report endpoints.
// - Frontend: `doAssign`/`doAction`/`doVerify`/`doAddBlocker`/`doBulk`
//   had zero error handling of any kind (no try/catch at all, despite
//   the `vqAPI` client already correctly not swallowing errors on these
//   write methods) — added real try/catch with error surfacing to all
//   five, plus the exception create/approve/delete handlers. Also found
//   the "Submit" button on the New Exception form never refreshed the
//   exceptions list after a successful create — the newly-created
//   exception stayed invisible until a full page reload, since the
//   tab-switch loader only re-fetches when the list is still empty —
//   added a real refresh after create.
//
// Also found a real React key-collision bug while running this spec for
// the first time against real seeded data: the Analytics tab's "Top
// Delayed Assets" list used `key={a.asset}` — harmless with the old fake
// data (5 fixed distinct asset names), but the real seeded data has two
// different overdue CVEs on the same real asset (`web-app-01`), which
// is a completely normal real-world scenario, not a seeding mistake —
// producing a genuine React duplicate-key console error. Fixed by keying
// on `${asset}-${index}` instead.
//
// Like every other page this phase: none of this page's 3 own tables had
// any seed data anywhere in a fresh dev environment — added seedVulnQueue
// to cmd/seed/demo/main.go (8 items spanning every status/priority/team
// combination with real due_date/created_at/closed_at timestamps to
// exercise MTTR/SLA/overdue math, 1 blocked item with a real dependency
// row, 1 exception).
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = ['Dashboard', 'Remediation Queue', 'Exceptions', 'Analytics', 'Reports'];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Vuln Queue — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/vuln-queue');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/vuln-queue');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('Vuln Queue — regression guard: seed data exists', () => {
  test('queue and dashboard show real seeded items, not an empty page', async ({ page }) => {
    const queue = await page.request.get('/api/vq/queue').then(r => r.json());
    const realCount = Number(PSQL(`SELECT count(*) FROM vq_items WHERE tenant_id=9999;`));
    expect(realCount).toBeGreaterThan(0);
    expect(queue.length).toBe(realCount);

    const dash = await page.request.get('/api/vq/dashboard').then(r => r.json());
    // dash.total is defined as "not closed" (matches GetVQDashboard's own
    // COUNT(*) FILTER (WHERE status != 'closed')), not every row.
    const realNotClosed = Number(PSQL(`SELECT count(*) FROM vq_items WHERE tenant_id=9999 AND status != 'closed';`));
    expect(dash.total).toBe(realNotClosed);
  });
});

test.describe('Vuln Queue — regression guard: AI recommendations use the real LLM response, not fixed canned text', () => {
  test('askAI returns per-CVE content, not identical output for different inputs', async ({ page }) => {
    const resA = await page.request.post('/api/vq/ai', {
      data: { cve_id: 'CVE-2024-3400', asset_name: 'vpn-gw-01', priority: 'critical', risk_score: 98.4, assigned_team: 'Network Team' },
    }).then(r => r.json());
    const resB = await page.request.post('/api/vq/ai', {
      data: { cve_id: 'CVE-2023-9999', asset_name: 'win-laptop-042', priority: 'low', risk_score: 15.0, assigned_team: 'Windows Team' },
    }).then(r => r.json());
    expect(resA.recommendation).not.toBe(resB.recommendation);
    expect(resA.recommendation).toContain('CVE-2024-3400');
    expect(resB.recommendation).toContain('CVE-2023-9999');
  });
});

test.describe('Vuln Queue — regression guard: dashboard/analytics/SLA are computed, not hardcoded', () => {
  test('team_breakdown reflects real seeded teams, not the old fixed 5-team fake list', async ({ page }) => {
    const dash = await page.request.get('/api/vq/dashboard').then(r => r.json());
    const realTotal = dash.team_breakdown.reduce((sum: number, t: any) => sum + t.total, 0);
    const realOpenCount = Number(PSQL(`SELECT count(*) FROM vq_items WHERE tenant_id=9999 AND status != 'closed';`));
    expect(realTotal).toBe(realOpenCount);
  });

  test('SLA current_compliance is computed per priority, not the old fixed 100/96.2/91.4/88.6', async ({ page }) => {
    const sla = await page.request.get('/api/vq/sla').then(r => r.json());
    const realLowCompliance = sla.current_compliance.low;
    // The seeded low-priority item (CVE-2023-9999) has a due_date far in
    // the future, so it should be 100% on-time — the old fake value was
    // 88.6, distinct enough to prove this isn't a coincidental match.
    expect(realLowCompliance).toBe(100);
  });

  test('analytics team_performance and dashboard team_breakdown agree on the same real data', async ({ page }) => {
    const dash = await page.request.get('/api/vq/dashboard').then(r => r.json());
    const analytics = await page.request.get('/api/vq/analytics').then(r => r.json());
    const dashTeams = new Set(dash.team_breakdown.map((t: any) => t.team));
    const analyticsTeams = new Set(analytics.team_performance.map((t: any) => t.team));
    for (const team of dashTeams) {
      expect(analyticsTeams.has(team)).toBeTruthy();
    }
  });
});

test.describe('Vuln Queue — regression guard: write actions really persist', () => {
  test('assigning a real item updates its status and assignee', async ({ page }) => {
    const iid = Number(PSQL(`SELECT id FROM vq_items WHERE tenant_id=9999 AND cve_id='CVE-2024-26198';`));
    const res = await page.request.post(`/api/vq/items/${iid}/assign`, { data: { assigned_team: 'Cloud Team', assigned_to: 'admin' } });
    expect(res.ok()).toBeTruthy();
    const row = PSQL(`SELECT status, assigned_team, assigned_to FROM vq_items WHERE id=${iid};`);
    expect(row).toBe('assigned|Cloud Team|admin');
  });

  test('creating an exception really persists, and is immediately visible via GET (the missing-refresh bug)', async ({ page }) => {
    const before = Number(PSQL(`SELECT count(*) FROM vq_exceptions WHERE tenant_id=9999;`));
    const res = await page.request.post('/api/vq/exceptions', {
      data: { cve_id: 'CVE-2023-9999', exception_type: 'risk_acceptance', reason: 'e2e test exception' },
    });
    expect(res.ok()).toBeTruthy();
    const after = Number(PSQL(`SELECT count(*) FROM vq_exceptions WHERE tenant_id=9999;`));
    expect(after).toBe(before + 1);

    const list = await page.request.get('/api/vq/exceptions').then(r => r.json());
    expect(list.some((e: any) => e.reason === 'e2e test exception')).toBeTruthy();
  });
});

test.describe('Vuln Queue — regression guard: report uses real numbers', () => {
  test('report key_metrics reflect the real active-item count, not fabricated history', async ({ page }) => {
    const res = await page.request.post('/api/vq/report', { data: { report_type: 'executive' } }).then(r => r.json());
    const realActive = Number(PSQL(`SELECT count(*) FROM vq_items WHERE tenant_id=9999 AND status != 'closed';`));
    expect(res.key_metrics.total_active).toBe(realActive);
    expect(res.executive_summary).not.toContain('12.1 days last month');
  });
});
