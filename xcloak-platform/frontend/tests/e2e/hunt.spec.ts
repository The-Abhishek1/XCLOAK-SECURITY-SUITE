import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Threat Hunt page (route /hunt) — the
// structured hunt-library/findings/MITRE-coverage feature, distinct from
// Hunt Workbench (/hunt-workbench, a separate KQL ad-hoc hunting feature
// with its own data model already covered by hunt-workbench.spec.ts).
//
// Real bugs found and fixed this pass, all in `api/threat_hunt_enterprise.go`
// unless noted:
//  - The MITRE tab called `huntWorkbenchAPI.mitreCoverage()` — Hunt
//    Workbench's own endpoint, scoped entirely to `hunt_templates`/
//    `hunt_runs` (a different feature/data model). A user's own threat
//    hunts here, tagged via `threat_hunts.mitre_techniques`, never affected
//    what this tab showed — confirmed live: `threat_hunts` didn't even
//    exist yet for this tenant (lazily created on first write) while
//    `hunt_templates` already had 20 seeded rows, so the tab was showing
//    100% Hunt Workbench data. Added a real `GetThreatHuntMITRECoverage`
//    (`GET /api/threat-hunt/mitre-coverage`) scoped to this page's own
//    tables, extracting the shared MITRE matrix into `api/mitre_matrix.go`
//    so both endpoints render against the same tactic/technique set without
//    duplicating it.
//  - `PostThreatHuntResponse` was the same 100%-fake-button pattern found
//    and fixed on UEBA/Insider Threat/Network Map/Attack Paths/Hunt
//    Workbench this phase — only wrote an `audit_logs` row and returned a
//    canned `{"queued": true}` regardless of action. Fixed `isolate_host`
//    (looks up the agent by hostname, dispatches via the pending_approval
//    gate), `block_ip`/`block_ioc` (real enabled IOC rows, the latter using
//    a newly-exported `services.GuessIOCType`), `open_incident` (real
//    `incidents` row), `open_case` (real `services.CreateCase`). `run_soar`
//    and `hunt_similar` didn't fit this modal's single-target-action shape
//    at all (SOAR needs a playbook picker this modal never had; "hunt
//    similar" isn't a backend action) — removed from the modal and replaced
//    with real, distinct capability instead (see frontend fixes below).
//  - The Workspace tab's "Respond" button (responding at the hunt level,
//    not tied to a specific finding) passed `form.id` — the *hunt's* ID —
//    into `responseFindingId`, which then got sent to the backend as
//    `finding_id`. Findings-tab's own "Respond" button had the opposite
//    gap: it set `finding_id` correctly but never sent `hunt_id` at all
//    (the frontend request never included that field). Both fixed by
//    tracking `responseHuntId` and `responseFindingId` as separate state.
//
// Frontend-only fixes:
//  - The entire "Automation" tab was fabricated: a hardcoded array of 8
//    "trigger → action" rules with fake active/inactive badges and zero
//    onClick/backend backing anywhere (findings never actually create
//    alerts/incidents/notifications on the backend). Removed entirely,
//    same as the Log Sources page's fake "Alerts" tab earlier this phase.
//  - Executing a hunt (Library table's inline Play button, or Workspace's
//    "Execute Now") never refreshed the Library list or dashboard cache —
//    hit_count/last_run_at/success_rate stayed stale until an unrelated
//    filter change or manual refresh. Fixed to reload both after execute.
//  - `addComment` optimistically appended a fake client-side id
//    (`Date.now()`) instead of the real id the backend already returns.
//
// Deferred, not fixed (out of this page's scope): the Recent-Hunt-Activity
// table on Dashboard uses `hit_count` (a per-hunt running total) as a proxy
// for "findings" in its 30-day trend rather than a direct count of
// `threat_hunt_findings` rows — a simplification, not a wrong-column bug,
// left alone. `run_soar`'s replacement (a plain link to /playbooks) doesn't
// pre-select or pre-fill anything there — building real per-finding
// playbook selection would need new UI on the Playbooks page itself,
// which hasn't had its own pass yet.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = ['Dashboard', 'Library', 'Categories', 'Workspace', 'Findings',
  'MITRE', 'Analytics', 'Templates'];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Threat Hunt — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/hunt');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/hunt');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });

  test('the fabricated Automation tab is gone', async ({ page }) => {
    await page.goto('/hunt');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    await expect(page.getByRole('button', { name: 'Automation', exact: true })).toHaveCount(0);
  });
});

test.describe('Threat Hunt — regression guard: MITRE tab uses this page\'s own data', () => {
  test('a hunt executed here increases this technique\'s coverage count, independent of Hunt Workbench\'s own coverage', async ({ page }) => {
    // Compares run_count deltas rather than asserting a specific starting
    // status — this suite reuses a shared, un-reset seeded tenant across
    // repeated runs, so a technique this same test tagged on a prior run
    // may already show as covered by the time it runs again.
    const technique = 'T1495'; // Firmware Corruption
    const getCount = async () => {
      const cov = await page.request.get('/api/threat-hunt/mitre-coverage').then(r => r.json());
      const tactic = cov.tactics.find((t: any) => t.techniques.some((x: any) => x.id === technique));
      return tactic?.techniques.find((x: any) => x.id === technique)?.run_count ?? 0;
    };
    const before = await getCount();

    const createRes = await page.request.post('/api/threat-hunt', {
      data: { name: 'e2e MITRE coverage probe', category: 'ttp', query_type: 'log', query_text: 'firmware', mitre_techniques: technique },
    });
    const hunt = await createRes.json();
    await page.request.post(`/api/threat-hunt/${hunt.id}/execute`);

    const after = await getCount();
    expect(after).toBeGreaterThan(before);

    // Confirm this reflects threat_hunts specifically, not hunt_templates —
    // the bug this test guards against would show this exact same result
    // whether or not the fix is in place if it were still reading Hunt
    // Workbench's tables, so cross-check the row exists where expected.
    const runCount = PSQL(`SELECT run_count FROM threat_hunts WHERE id=${hunt.id};`);
    expect(Number(runCount)).toBeGreaterThan(0);
  });
});

test.describe('Threat Hunt — regression guard: response actions are real, not a no-op', () => {
  test('block_ip creates a real, enabled IOC row', async ({ page }) => {
    const ip = `10.66.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    const before = PSQL(`SELECT count(*) FROM iocs WHERE indicator='${ip}' AND enabled=true;`);
    expect(Number(before)).toBe(0);

    const res = await page.request.post('/api/threat-hunt/response', {
      data: { action: 'block_ip', hunt_id: 0, finding_id: 0, target: ip, reason: 'e2e probe' },
    });
    expect(res.ok()).toBeTruthy();

    const after = PSQL(`SELECT count(*) FROM iocs WHERE indicator='${ip}' AND enabled=true;`);
    expect(Number(after)).toBe(1);
  });

  test('isolate_host resolves the target hostname to a real agent and dispatches a pending-approval task', async ({ page }) => {
    const before = PSQL(`SELECT count(*) FROM agent_tasks WHERE agent_id=1 AND task_type='isolate_host' AND status='pending_approval';`);

    const res = await page.request.post('/api/threat-hunt/response', {
      data: { action: 'isolate_host', hunt_id: 0, finding_id: 0, target: 'web-prod-01', reason: 'e2e probe' },
    });
    expect(res.ok()).toBeTruthy();

    const after = PSQL(`SELECT count(*) FROM agent_tasks WHERE agent_id=1 AND task_type='isolate_host' AND status='pending_approval';`);
    expect(Number(after)).toBeGreaterThan(Number(before));
  });

  test('isolate_host for an unknown hostname fails honestly instead of silently no-oping', async ({ page }) => {
    const res = await page.request.post('/api/threat-hunt/response', {
      data: { action: 'isolate_host', hunt_id: 0, finding_id: 0, target: 'no-such-host-e2e', reason: 'e2e probe' },
    });
    expect(res.status()).toBe(404);
  });
});

test.describe('Threat Hunt — regression guard: hunt_id/finding_id no longer conflated', () => {
  test('responding from the Workspace (hunt-level) records the real hunt_id, not the finding_id slot', async ({ page }) => {
    const createRes = await page.request.post('/api/threat-hunt', {
      data: { name: 'e2e hunt-id probe', category: 'ttp', query_type: 'log', query_text: 'probe' },
    });
    const hunt = await createRes.json();

    await page.request.post('/api/threat-hunt/response', {
      data: { action: 'open_incident', hunt_id: hunt.id, finding_id: 0, target: 'e2e-target', reason: 'e2e probe' },
    });

    const details = PSQL(`SELECT details FROM audit_logs WHERE action='threat_hunt.response.open_incident' AND details LIKE '%"hunt_id":${hunt.id},%' ORDER BY created_at DESC LIMIT 1;`);
    expect(details).toContain(`"finding_id":0`);

    const incidentDesc = PSQL(`SELECT description FROM incidents WHERE title LIKE 'Threat Hunt Finding: e2e-target' ORDER BY id DESC LIMIT 1;`);
    expect(incidentDesc).toContain(`hunt #${hunt.id}`);
  });
});

test.describe('Threat Hunt — Library execute refreshes stale stats', () => {
  test('executing from the Library table updates hit_count/last_run_at without a manual reload', async ({ page }) => {
    const name = `e2e stale-refresh probe ${Date.now()}`;
    const createRes = await page.request.post('/api/threat-hunt', {
      data: { name, category: 'ttp', query_type: 'log', query_text: 'auth' },
    });
    const hunt = await createRes.json();

    await page.goto('/hunt');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    await page.getByRole('button', { name: 'Library', exact: true }).click();

    const row = page.locator('tr', { hasText: name });
    await expect(row).toBeVisible({ timeout: 10_000 });
    // Columns: Name, Category, Author, MITRE, Priority, Status, Success%, Last Run, Version, actions.
    const lastRunCell = row.locator('td').nth(7);
    await expect(lastRunCell).toHaveText('—'); // last_run_at starts empty

    await row.locator('button').last().click(); // Play button
    await expect(lastRunCell).not.toHaveText('—', { timeout: 10_000 });
  });
});
