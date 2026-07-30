import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Process Injection page (route
// /process-injection) — process/memory/API-call monitoring, injection
// detection, MITRE T1055 sub-technique mapping, threat intel, analytics,
// and response actions for DLL injection / process hollowing / APC abuse.
//
// - `GetPIModules`/`GetPIHandles` were fully hardcoded (zero DB query, not
//   even `tenant_id` used) with specific fictional processes (explorer.exe
//   pid 4512, a fake "[hidden module]" entry). No agent capability collects
//   per-process loaded-module or handle-table data anywhere in this
//   codebase — both now report an honest empty list instead.
// - `GetPIBehavioral` was 6 hardcoded parent/child "detections" reusing the
//   same fictional hostnames (WS-ANALYST-01, DC-01) found elsewhere on this
//   page. Rewritten to derive real detections from `pi_injections` — an
//   injection's real src/dst process pair already *is* the behavioral
//   parent/child signal, no separate detection table needed.
// - `GetPIThreatIntel`'s `malware_matches` implied real per-tenant
//   detections (specific sha256 + "target: explorer.exe") rather than
//   generic reference content — unlike Container/Supply Chain/OT's kept
//   real-world advisory lists, this one crossed into fabricated-detection
//   territory. `threat_actors`/`campaigns` had zero real backing at all
//   (campaigns additionally recomputed a fake timestamp on every request).
//   Rewritten to a real per-tenant match: an actual `pi_processes.sha256`
//   against the real `iocs` table, the same pattern established on Supply
//   Chain/OT — `threat_actors`/`campaigns` removed since no real per-tenant
//   attribution data exists anywhere in this schema.
// - `GetPIMITREMap`'s sub-technique `detected`/`count` fields were fixed
//   booleans/numbers identical for every tenant — rewritten to a real
//   `GROUP BY mitre_technique` count over `pi_injections`.
// - `GetPIAnalytics`'s `top_techniques`/`most_targeted_processes`/
//   `most_used_apis`/`high_risk_hosts` were all hardcoded despite real
//   equivalent queries over `pi_injections`/`pi_api_calls` being one query
//   away — wired to real aggregations.
// - `PostPIResponse` was the familiar canned-message dispatcher (6 actions,
//   zero real effect). Rewritten: `kill_process`/`collect_process`/
//   `isolate_endpoint` resolve a real agent by hostname and dispatch a
//   real pending-approval agent task (kill_process/collect_processes/
//   isolate_host — all confirmed-real agent executor capabilities);
//   `suspend_process`/`dump_memory` now honestly 501 (no real agent
//   capability exists for either — confirmed against the executor's full
//   task-type list); `run_soar` removed, replaced with the real
//   `/playbooks` link.
// - Also fixed on the frontend: the Response tab's action buttons sent
//   hardcoded fallback target/pid/hostname values ('explorer.exe', 4512,
//   'WS-ANALYST-01') whenever no real injection had been fetched yet,
//   meaning a response action could silently fire against entirely
//   fictional identifiers — fixed to disable the actions with an honest
//   message instead when there's nothing real to act on. `respond()` also
//   had no error handling at all (a real gap now that real 404/501s exist)
//   — fixed to surface the real backend error.
// - Like every other page this phase: none of this page's 5 own tables had
//   any seed data anywhere in a fresh dev environment — added
//   `seedProcessInjection` to cmd/seed/demo/main.go, idempotency-guarded
//   like every other keyless table this phase, including a real IOC
//   fixture matching a seeded process hash to exercise the real
//   malware-match path end-to-end.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = ['Overview', 'Processes', 'Memory & Modules', 'API Monitor',
  'Intelligence', 'Analytics', 'Response'];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Process Injection — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/process-injection');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/process-injection');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('Process Injection — regression guard: seed data exists', () => {
  test('the dashboard shows real, non-zero counts instead of a permanently empty page', async ({ page }) => {
    const dash = await page.request.get('/api/pi/dashboard').then(r => r.json());
    expect(dash.active_injections).toBeGreaterThan(0);

    const count = PSQL(`SELECT count(*) FROM pi_processes WHERE tenant_id=9999;`);
    expect(Number(count)).toBeGreaterThan(0);
  });
});

test.describe('Process Injection — regression guard: modules/handles are honest empties, not fabricated', () => {
  test('modules and handles report empty rather than a fixed fictional explorer.exe module list', async ({ page }) => {
    const modules = await page.request.get('/api/pi/modules').then(r => r.json());
    const handles = await page.request.get('/api/pi/handles').then(r => r.json());
    expect(modules.modules).toEqual([]);
    expect(handles.handles).toEqual([]);
  });
});

test.describe('Process Injection — regression guard: behavioral/threat-intel/mitre are real, not fixed fictional data', () => {
  test('behavioral detections come from real pi_injections rows', async ({ page }) => {
    const res = await page.request.get('/api/pi/behavioral').then(r => r.json());
    const realCount = Number(PSQL(`SELECT count(*) FROM pi_injections WHERE tenant_id=9999;`));
    expect(res.detections.length).toBe(Math.min(realCount, 50));
  });

  test('malware_matches is a real IOC-hash match, and threat_actors/campaigns are gone', async ({ page }) => {
    const res = await page.request.get('/api/pi/threat-intel').then(r => r.json());
    expect(res).not.toHaveProperty('threat_actors');
    expect(res).not.toHaveProperty('campaigns');
    expect(res.malware_matches.length).toBeGreaterThan(0);
    expect(res.malware_matches[0].process).toBe('powershell.exe');
  });

  test('MITRE sub-technique counts reflect real seeded pi_injections data', async ({ page }) => {
    const res = await page.request.get('/api/pi/mitre').then(r => r.json());
    const dllInjection = res.sub_techniques.find((s: any) => s.id === 'T1055.001');
    const realCount = Number(PSQL(`SELECT count(*) FROM pi_injections WHERE tenant_id=9999 AND mitre_technique='T1055.001';`));
    expect(dllInjection.count).toBe(realCount);
    expect(dllInjection.detected).toBe(realCount > 0);
  });
});

test.describe('Process Injection — regression guard: response actions are real, not a no-op', () => {
  test('kill_process really queues a real agent task pending approval', async ({ page }) => {
    const before = Number(PSQL(`SELECT count(*) FROM agent_tasks WHERE task_type='kill_process';`));
    const res = await page.request.post('/api/pi/response', {
      data: { action: 'kill_process', pid: 7142, hostname: 'win-workstation-05', reason: 'e2e test' },
    });
    expect(res.ok()).toBeTruthy();
    const after = Number(PSQL(`SELECT count(*) FROM agent_tasks WHERE task_type='kill_process';`));
    expect(after).toBe(before + 1);
  });

  test('kill_process against an unknown hostname fails honestly instead of claiming success', async ({ page }) => {
    const res = await page.request.post('/api/pi/response', {
      data: { action: 'kill_process', pid: 123, hostname: 'not-a-real-host' },
    });
    expect(res.status()).toBe(404);
  });

  test('suspend_process and dump_memory honestly report no real capability instead of fake success', async ({ page }) => {
    const suspend = await page.request.post('/api/pi/response', { data: { action: 'suspend_process', hostname: 'win-workstation-05' } });
    expect(suspend.status()).toBe(501);
    const dump = await page.request.post('/api/pi/response', { data: { action: 'dump_memory', hostname: 'win-workstation-05' } });
    expect(dump.status()).toBe(501);
  });

  test('an unrecognized action is rejected rather than silently reporting success', async ({ page }) => {
    const res = await page.request.post('/api/pi/response', { data: { action: 'not_a_real_action' } });
    expect(res.status()).toBe(400);
  });

  test('the Response tab no longer offers a fake run_soar action button', async ({ page }) => {
    await page.goto('/process-injection');
    await page.getByRole('button', { name: 'Response', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Run SOAR Playbook' })).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Run SOAR Playbook' })).toBeVisible();
  });
});
