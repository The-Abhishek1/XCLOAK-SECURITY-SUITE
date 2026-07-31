import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Quarantine / Isolation page (route
// /quarantine) — backed by qe_* tables (api/quarantine_enterprise.go),
// distinct from the older, unrelated api/quarantine.go +
// api/quarantine_actions.go (`quarantined_files` table, `/api/quarantine/*`
// routes) confirmed via grep that this page's frontend only ever calls
// qeAPI → `/api/qe/*`; left that older file untouched.
//
// Real bugs found and fixed this pass:
// - GetQEItem: owner/source_detection/incident_id/case_id/
//   quarantine_reason/detection_rule/business_impact/analyst_notes/
//   approved_by/release_type are all nullable with no DEFAULT, and
//   PostQEItem's INSERT never set analyst_notes/approved_by/release_type
//   at all — every item had NULL there until a later action set one.
//   Scanning NULL into a plain (non-pointer) Go string failed Scan()
//   unconditionally, so the item-detail view 404'd for literally every
//   quarantine item ever created (confirmed live: create then immediate
//   GET returned 404). Fixed via COALESCE(col,'') in the SELECT.
// - PostQEItem accepted `expires_at` from the request body but never
//   included it in the INSERT column list at all — silently dropped.
//   Fixed by parsing and persisting it.
// - PostQEAction's "release" case never set release_type, even though
//   the UI's "Release" button is the one real path that should set it.
// - PostQEAI didn't request strict JSON from the LLM and never stripped
//   markdown code fences before handing the raw string to the frontend's
//   own JSON.parse() — a genuinely successful LLM response wrapped in
//   ```json fences (a common LLM habit) would fail to parse and silently
//   degrade to showing only threat_summary, losing 5 other real fields
//   the UI already renders.
// - PostQEReport was missing key_metrics and by_type_summary entirely —
//   not just fabricated content, the frontend's ReportsTab already
//   renders both via Object.entries(...).map(...), so those sections
//   were always blank/undefined. Rewritten with real computed metrics
//   plus an LLM-grounded executive_summary/recommendations.
// - Frontend: doAction/doCollectEvidence/approve (main detail panel) and
//   decide (ApprovalsTab) had zero error handling despite qeAPI's write
//   methods already correctly not swallowing errors — added try/catch.
// - Architectural gap found via exhaustive grep: PostQEItem (create) had
//   zero real callers anywhere in the app — no create-form UI existed on
//   this page, and no other page's response-action dispatcher called it
//   either (unlike Approval Queue's PostAQRequest, which has a real
//   external OT/ICS trigger). Confirmed via AskUserQuestion: built a real
//   "Quarantine Asset" creation modal on the Queue tab calling the
//   already-correct PostQEItem endpoint.
//
// Like every other page this phase: qe_items/qe_evidence/qe_audit had no
// seed data anywhere in a fresh dev environment — added
// seedQuarantineEnterprise to cmd/seed/demo/main.go (8 items spanning
// every asset type/severity/status/approval state, with real audit trail
// and evidence rows on the items that have evidence_collected=true).
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = ['Dashboard', 'Queue', 'AI Analysis', 'Approvals', 'Analytics', 'Audit Trail', 'Reports'];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Quarantine — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/quarantine');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/quarantine');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('Quarantine — regression guard: seed data exists', () => {
  test('queue and dashboard show real seeded data, not an empty page', async ({ page }) => {
    const queue = await page.request.get('/api/qe/queue').then(r => r.json());
    const realCount = Number(PSQL(`SELECT count(*) FROM qe_items WHERE tenant_id='9999';`));
    expect(realCount).toBeGreaterThan(0);
    expect(queue.length).toBe(realCount);

    const dash = await page.request.get('/api/qe/dashboard').then(r => r.json());
    const realActive = Number(PSQL(`SELECT count(*) FROM qe_items WHERE tenant_id='9999' AND status='active';`));
    expect(dash.active_quarantine_sessions).toBe(realActive);
  });
});

test.describe('Quarantine — regression guard: item detail returns real data, not a 404', () => {
  test('GetQEItem succeeds for a real seeded item with NULL analyst_notes/approved_by/release_type', async ({ page }) => {
    const id = Number(PSQL(`SELECT id FROM qe_items WHERE tenant_id='9999' AND asset_name='win-workstation-05';`));
    expect(id).toBeGreaterThan(0);
    const nullChecks = PSQL(`SELECT (analyst_notes IS NULL)::text || ',' || (approved_by IS NULL)::text || ',' || (release_type IS NULL)::text FROM qe_items WHERE id=${id};`);
    expect(nullChecks).toBe('true,true,true');

    const res = await page.request.get(`/api/qe/items/${id}`);
    expect(res.ok()).toBeTruthy();
    const item = await res.json();
    expect(item.asset_name).toBe('win-workstation-05');
    expect(item.owner).toBe('soc-analyst-1');
  });

  test('a freshly created item is immediately fetchable, not a 404', async ({ page }) => {
    const create = await page.request.post('/api/qe/items', {
      data: { asset_name: 'e2e-fresh-item', asset_type: 'endpoint', severity: 'medium' },
    });
    expect(create.ok()).toBeTruthy();
    const created = await create.json();

    const res = await page.request.get(`/api/qe/items/${created.id}`);
    expect(res.status()).toBe(200);
    const item = await res.json();
    expect(item.asset_name).toBe('e2e-fresh-item');

    PSQL(`DELETE FROM qe_audit WHERE tenant_id='9999' AND item_id=${created.id}; DELETE FROM qe_items WHERE tenant_id='9999' AND id=${created.id};`);
  });
});

test.describe('Quarantine — regression guard: create form persists expires_at', () => {
  test('PostQEItem now saves expires_at instead of silently dropping it', async ({ page }) => {
    const create = await page.request.post('/api/qe/items', {
      data: { asset_name: 'e2e-expiry-item', asset_type: 'endpoint', severity: 'low', expires_at: '2026-08-15T10:00' },
    });
    expect(create.ok()).toBeTruthy();
    const created = await create.json();

    const stored = PSQL(`SELECT expires_at FROM qe_items WHERE id=${created.id};`);
    expect(stored).toContain('2026-08-15 10:00');

    PSQL(`DELETE FROM qe_audit WHERE tenant_id='9999' AND item_id=${created.id}; DELETE FROM qe_items WHERE tenant_id='9999' AND id=${created.id};`);
  });

  test('the Queue tab has a real "Quarantine Asset" form that creates a real item', async ({ page }) => {
    await page.goto('/quarantine');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    await page.getByRole('button', { name: new RegExp('^Queue\\b') }).click();
    await page.waitForTimeout(300);

    await page.getByRole('button', { name: 'Quarantine Asset' }).click();
    await page.getByPlaceholder('win-workstation-07').fill('e2e-ui-created-host');
    await page.getByRole('button', { name: 'Quarantine Asset' }).last().click();
    await page.waitForTimeout(800);

    const id = Number(PSQL(`SELECT id FROM qe_items WHERE tenant_id='9999' AND asset_name='e2e-ui-created-host';`));
    expect(id).toBeGreaterThan(0);
    await expect(page.locator('body')).toContainText('e2e-ui-created-host');

    PSQL(`DELETE FROM qe_audit WHERE tenant_id='9999' AND item_id=${id}; DELETE FROM qe_items WHERE tenant_id='9999' AND id=${id};`);
  });
});

test.describe('Quarantine — regression guard: release action sets release_type', () => {
  test('manually releasing an active item records release_type=manual, not NULL', async ({ page }) => {
    const create = await page.request.post('/api/qe/items', {
      data: { asset_name: 'e2e-release-item', asset_type: 'endpoint', severity: 'low' },
    });
    const created = await create.json();

    const res = await page.request.post(`/api/qe/items/${created.id}/action`, { data: { action: 'release', notes: 'e2e' } });
    expect(res.ok()).toBeTruthy();

    const row = PSQL(`SELECT status || ',' || release_type FROM qe_items WHERE id=${created.id};`);
    expect(row).toBe('released,manual');

    PSQL(`DELETE FROM qe_audit WHERE tenant_id='9999' AND item_id=${created.id}; DELETE FROM qe_items WHERE tenant_id='9999' AND id=${created.id};`);
  });
});

test.describe('Quarantine — regression guard: AI response is real, parseable JSON', () => {
  test('askAI returns a JSON string the frontend can JSON.parse with all fields populated', async ({ page }) => {
    const res = await page.request.post('/api/qe/ai', {
      data: {
        asset_name: 'win-workstation-05', asset_type: 'endpoint', quarantine_type: 'full_network_isolation',
        severity: 'critical', source_detection: 'EDR: Cobalt Strike beacon detected', mitre_techniques: '["T1071.001"]',
      },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.ai_analysis).not.toMatch(/```/);
    const parsed = JSON.parse(body.ai_analysis);
    expect(parsed.threat_summary).toBeTruthy();
    expect(parsed.root_cause).toBeTruthy();
    expect(Array.isArray(parsed.recommended_actions)).toBeTruthy();
    expect(parsed.release_recommendation).toBeTruthy();
  });
});

test.describe('Quarantine — regression guard: report includes key_metrics and by_type_summary', () => {
  test('PostQEReport returns real computed fields, not undefined sections', async ({ page }) => {
    const res = await page.request.post('/api/qe/report', { data: { report_type: 'quarantine_activity' } });
    expect(res.ok()).toBeTruthy();
    const report = await res.json();

    const realTotal = Number(PSQL(`SELECT count(*) FROM qe_items WHERE tenant_id='9999';`));
    expect(report.key_metrics).toBeTruthy();
    expect(report.key_metrics.total_quarantined).toBe(realTotal);
    expect(report.by_type_summary).toBeTruthy();
    expect(typeof report.by_type_summary.endpoint).toBe('number');
  });
});
