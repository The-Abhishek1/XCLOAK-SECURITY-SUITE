import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Suppression page (route /suppression)
// — the alert-noise-reduction rule engine backed by `sup_*` tables,
// distinct from the older, simpler `suppression_rules` table used
// elsewhere in the app (`api/suppression_geoip_health.go`'s
// GetSuppressionRules/CreateSuppressionRule — confirmed via grep that this
// page's frontend only ever calls `supAPI`, backed exclusively by
// `/api/sup/*`; left that other file untouched).
//
// This page's backend was noticeably more careful than most this phase —
// GetSupDashboard/GetSupAnalytics already had explicit comments like "no
// per-day suppression-event table exists, so there is no honest way to
// build a real daily series — return empty rather than fabricate", and
// the real bugs found here were more subtle for exactly that reason:
//
// - `PostSupAI` called the real LLM and then discarded its response
//   almost entirely — the same "compute a real answer, throw it away for
//   canned text" bug just fixed on Vuln Queue's PostVQAI, found here
//   independently as a second occurrence. `recommendation`/
//   `confidence_pct`/`reasoning`/`conditions_if_conditional`/
//   `risk_if_suppressed`/`alternative` (everything the frontend actually
//   renders) were deterministic Go logic regardless of whether the LLM
//   call succeeded, with the real response only reachable via a
//   completely unrendered `ai_analysis` field. Rewritten so a successful
//   LLM response becomes the primary content; the deterministic fallback
//   (genuinely alert-count/incident-count/severity-aware, not generic) is
//   now used only when the LLM call itself fails.
// - `PostSupApprove` always wrote `rule_id=0, rule_name=''` to the audit
//   trail regardless of which real rule was being approved/rejected —
//   confirmed live that every approve/reject audit entry rendered with a
//   blank "Rule" cell in the Audit Trail tab. `PatchSupRule`/
//   `DeleteSupRule` had the identical `rule_id=0` gap (though
//   `rule_id` itself isn't rendered anywhere in the frontend, unlike
//   `rule_name`, which `PatchSupRule`/`DeleteSupRule` did already look up
//   correctly). Fixed all three to look up and pass the real rule id/name.
// - Frontend: `setStatus`/`deleteRule`/`approve`/`save` (rule builder)
//   had zero error handling despite `supAPI`'s write methods already
//   correctly not swallowing errors — added real try/catch to all four.
//
// Like every other page this phase: none of this page's 2 own tables had
// any seed data anywhere in a fresh dev environment — added
// seedSuppressionEnterprise to cmd/seed/demo/main.go (6 rules spanning
// active/draft, every priority, with real total_suppressed/
// last_triggered_at values on the active ones so the dashboard's "top
// suppressed"/analytics "most suppressed rules" lists have real data, 2
// pending-approval critical-priority rules to exercise the approval
// workflow, plus a matching audit trail). PostSupPreview needed no
// additional seed data — it queries the real alerts/agents tables
// directly, which already have thousands of real rows from every earlier
// page's own seeding this phase.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = ['Dashboard', 'Active Rules', 'Rule Builder', 'Analytics', 'Audit Trail', 'Reports'];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Suppression — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/suppression');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/suppression');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('Suppression — regression guard: seed data exists', () => {
  test('rules and dashboard show real seeded data, not an empty page', async ({ page }) => {
    const rules = await page.request.get('/api/sup/rules').then(r => r.json());
    const realCount = Number(PSQL(`SELECT count(*) FROM sup_rules WHERE tenant_id=9999;`));
    expect(realCount).toBeGreaterThan(0);
    expect(rules.length).toBe(realCount);

    const dash = await page.request.get('/api/sup/dashboard').then(r => r.json());
    const realActive = Number(PSQL(`SELECT count(*) FROM sup_rules WHERE tenant_id=9999 AND status='active';`));
    expect(dash.active_rules).toBe(realActive);
    expect(dash.top_suppressed.length).toBeGreaterThan(0);
  });
});

test.describe('Suppression — regression guard: AI uses the real LLM response, not fixed canned text', () => {
  test('askAI returns per-detection content, not identical output for different inputs', async ({ page }) => {
    const resA = await page.request.post('/api/sup/ai', {
      data: { detection_name: 'Weak TLS Negotiated', alert_count: 128, incident_count: 0, asset_type: 'single_asset', severity: 'low' },
    }).then(r => r.json());
    const resB = await page.request.post('/api/sup/ai', {
      data: { detection_name: 'DCSync: Credential Dump via AD Replication', alert_count: 3, incident_count: 1, asset_type: 'single_asset', severity: 'critical' },
    }).then(r => r.json());
    expect(resA.recommendation).not.toBe(resB.recommendation);
    // A detection correlated with a real confirmed incident must never be
    // recommended for suppression, regardless of which code path answers.
    expect(resB.recommendation).toBe('do_not_suppress');
    expect(resA).not.toHaveProperty('ai_analysis');
  });
});

test.describe('Suppression — regression guard: audit trail records the real rule, not a blank one', () => {
  test('approving a real rule writes its real rule_id/rule_name to the audit trail', async ({ page }) => {
    const rid = Number(PSQL(`SELECT id FROM sup_rules WHERE tenant_id=9999 AND rule_name='Critical Asset Global Suppress — db-server-02';`));
    const res = await page.request.post(`/api/sup/rules/${rid}/approve`, { data: { decision: 'approve' } });
    expect(res.ok()).toBeTruthy();

    const audit = await page.request.get('/api/sup/audit').then(r => r.json());
    const entry = audit.find((e: any) => e.rule_id === rid && e.action === 'approved');
    expect(entry).toBeTruthy();
    expect(entry.rule_name).toBe('Critical Asset Global Suppress — db-server-02');
  });

  test('deleting a real rule records the real rule name, not a blank one', async ({ page }) => {
    const create = await page.request.post('/api/sup/rules', {
      data: { rule_name: 'e2e delete-me rule', description: 'temp', priority: 'low', scope: 'single_asset', scope_value: 'win-workstation-05' },
    });
    const created = await create.json();
    const del = await page.request.delete(`/api/sup/rules/${created.id}`);
    expect(del.ok()).toBeTruthy();

    const audit = await page.request.get('/api/sup/audit').then(r => r.json());
    const entry = audit.find((e: any) => e.rule_id === created.id && e.action === 'deleted');
    expect(entry).toBeTruthy();
    expect(entry.rule_name).toBe('e2e delete-me rule');
  });
});

test.describe('Suppression — regression guard: preview queries real alerts/agents data', () => {
  test('previewing a suppression scope returns real historical matches against a real seeded agent', async ({ page }) => {
    const res = await page.request.post('/api/sup/preview', {
      data: { conditions: '[]', scope: 'single_asset', scope_value: 'win-workstation-05' },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.historical_matches).toBeGreaterThan(0);
    expect(body.impacted_assets.some((a: any) => a.hostname === 'win-workstation-05')).toBeTruthy();
  });
});
