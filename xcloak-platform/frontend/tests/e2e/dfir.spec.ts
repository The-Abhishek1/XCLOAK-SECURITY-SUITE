import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the DFIR page (route /dfir) — Digital
// Forensics & Incident Response: investigations, evidence/custody,
// timeline, process tree, forensics (file/malware/network/artifacts),
// notebook, reports.
//
// Real bugs found and fixed this pass, all in `api/dfir_enterprise.go`
// unless noted:
//  - `GetDFIRArtifacts` queried `endpoint_logs.created_at` — that column
//    has never existed there (the real column, confirmed via `\d
//    endpoint_logs`, is `collected_at`) — the same recurring wrong-column
//    bug found many times this phase (JA3 Fingerprints, Threat Hunt,
//    Log Search). The query error was discarded, so the Artifacts sub-tab
//    silently returned zero entries for every platform/artifact-type
//    combination, forever. Fixed to the real column name.
//  - `PostDFIRResponse` was the same 100%-fake-button pattern found
//    repeatedly this phase — worse than most instances, since it didn't
//    even write an audit-log row: it validated nothing and always
//    returned a canned success with a literal comment admitting it was a
//    stub ("In production: route to agent command queue or SOAR"). Fixed
//    with real dispatch: `isolate_host`/`kill_process`/`quarantine_file`
//    resolve the target hostname to a real agent and dispatch through the
//    pending_approval gate (kill_process/quarantine_file need a separate
//    `target_host` field alongside `target`, since their target is a PID
//    or file path, not a hostname); `block_ip` creates a real enabled IOC;
//    `open_incident`/`open_case` create real rows.
//
// Frontend gaps found and fixed:
//  - The process tree's "Kill" button prefilled the response modal's
//    target with `node.process_name` (a string like "powershell.exe")
//    instead of `node.pid` — kill_process needs a numeric PID, and the
//    process name isn't even unique. It also never captured which host
//    the process was actually on. Fixed to use `node.pid` + `node.host`,
//    and added a conditional "Target Host" field to the response modal
//    for kill_process/quarantine_file (the other three response-action
//    trigger points now default it from the investigation's first target
//    host).
//  - `delete_file` was in the action list with no real backing anywhere —
//    the agent executor only supports `quarantine_file` (moves to
//    quarantine), not permanent deletion. `run_soar` needs a playbook
//    selection this modal was never built to offer. Both removed from
//    the dropdown; replaced with a real link to /playbooks instead of
//    trying to force either into a mismatched single-target-field shape.
//  - The Network Forensics table hardcoded two fake "threat" heuristics
//    with zero real backing: any remote IP starting with "185." was
//    painted red (many legitimate hosting providers use that range — this
//    actively mislabeled real, unrelated seeded traffic, e.g. a real
//    "Accepted publickey" SSH log entry's source IP), and any process
//    name containing "svchost32" (a string that appears nowhere in this
//    codebase's backend or seed data — the real Windows process is
//    svchost.exe, never "svchost32") was painted red too. Removed both;
//    neither was backed by a real IOC/reputation lookup.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = ['Dashboard', 'Investigations', 'Collect', 'Evidence', 'Timeline',
  'Process Tree', 'Forensics', 'Notebook', 'Reports'];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

async function createInvestigation(page: any, targetHosts: string) {
  const res = await page.request.post('/api/dfir/investigations', {
    data: { title: `e2e DFIR probe ${Date.now()}`, priority: 'high', target_hosts: targetHosts },
  });
  return res.json();
}

test.describe('DFIR — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/dfir');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/dfir');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });

  test('delete_file and run_soar are no longer offered as response actions', async ({ page }) => {
    await page.goto('/dfir');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    await page.getByRole('button', { name: 'Reports', exact: true }).click();
    // The One-Click Response grid renders each action as its own button.
    await expect(page.getByRole('button', { name: /delete file/i })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /run soar/i })).toHaveCount(0);
    await expect(page.getByRole('link', { name: /run playbook/i })).toBeVisible();
  });
});

test.describe('DFIR — regression guard: Artifacts tab uses the real column name', () => {
  test('a cron artifact search against a real host returns real matching log entries', async ({ page }) => {
    const inv = await createInvestigation(page, 'db-server-02');
    const res = await page.request.get(`/api/dfir/investigations/${inv.id}/artifacts`, {
      params: { platform: 'linux', artifact: 'cron' },
    });
    expect(res.ok()).toBeTruthy();
    const data = await res.json();
    expect(data.entries.length).toBeGreaterThan(0);
    expect(data.entries[0].message).toContain('cron');
  });
});

test.describe('DFIR — regression guard: response actions are real, not a no-op', () => {
  test('block_ip creates a real, enabled IOC row', async ({ page }) => {
    const inv = await createInvestigation(page, 'web-prod-01');
    const ip = `10.77.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    const res = await page.request.post(`/api/dfir/investigations/${inv.id}/response`, {
      data: { action: 'block_ip', target: ip, notes: 'e2e probe' },
    });
    expect(res.ok()).toBeTruthy();
    const count = PSQL(`SELECT count(*) FROM iocs WHERE indicator='${ip}' AND enabled=true;`);
    expect(Number(count)).toBe(1);
  });

  test('isolate_host resolves the hostname to a real agent and dispatches a pending-approval task', async ({ page }) => {
    const inv = await createInvestigation(page, 'web-prod-01');
    const before = PSQL(`SELECT count(*) FROM agent_tasks WHERE agent_id=1 AND task_type='isolate_host' AND status='pending_approval';`);
    const res = await page.request.post(`/api/dfir/investigations/${inv.id}/response`, {
      data: { action: 'isolate_host', target: 'web-prod-01', notes: 'e2e probe' },
    });
    expect(res.ok()).toBeTruthy();
    const after = PSQL(`SELECT count(*) FROM agent_tasks WHERE agent_id=1 AND task_type='isolate_host' AND status='pending_approval';`);
    expect(Number(after)).toBeGreaterThan(Number(before));
  });

  test('kill_process requires target_host to resolve which agent to dispatch to', async ({ page }) => {
    const inv = await createInvestigation(page, 'web-prod-01');
    const noHost = await page.request.post(`/api/dfir/investigations/${inv.id}/response`, {
      data: { action: 'kill_process', target: '4321' },
    });
    expect(noHost.status()).toBe(400);

    const before = Number(PSQL(`SELECT count(*) FROM agent_tasks WHERE agent_id=1 AND task_type='kill_process' AND status='pending_approval';`));
    const withHost = await page.request.post(`/api/dfir/investigations/${inv.id}/response`, {
      data: { action: 'kill_process', target: '4321', target_host: 'web-prod-01', notes: 'e2e probe' },
    });
    expect(withHost.ok()).toBeTruthy();
    const after = Number(PSQL(`SELECT count(*) FROM agent_tasks WHERE agent_id=1 AND task_type='kill_process' AND status='pending_approval';`));
    expect(after).toBeGreaterThan(before);

    const payload = PSQL(`SELECT payload::text FROM agent_tasks WHERE agent_id=1 AND task_type='kill_process' AND status='pending_approval' ORDER BY id DESC LIMIT 1;`);
    expect(payload).toContain('4321');
  });

  test('isolate_host for an unknown hostname fails honestly instead of silently no-oping', async ({ page }) => {
    const inv = await createInvestigation(page, 'web-prod-01');
    const res = await page.request.post(`/api/dfir/investigations/${inv.id}/response`, {
      data: { action: 'isolate_host', target: 'no-such-host-e2e' },
    });
    expect(res.status()).toBe(404);
  });
});
