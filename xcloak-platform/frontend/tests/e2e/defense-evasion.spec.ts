import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Defense Evasion page (route
// /defense-evasion) — security control tampering, log/process/script
// evasion event tracking, behavioral detections, MITRE TA0005 coverage,
// threat intel, analytics, and response actions.
//
// Confirmed one large judgment call with the user before touching it: a
// whole standalone "Detection Validation" tab (4 metric cards + 2 tables:
// detection success rate, missed attempts, false positives, avg
// time-to-detect, per-platform coverage, per-category technique coverage)
// was 100% hardcoded with genuinely zero possible real backing — no
// purple-team/atomic-red-team exercise tracking exists anywhere in this
// schema, and building one would be a new feature, not a bug fix. User
// chose to remove the whole tab; removed GetDEValidation's handler, its
// route registration, its API client method, and the tab/view entirely.
//
// Everything else was fixed directly as clear recurrences of patterns
// already established this phase:
// - `GetDEBehavioral` was 5 hardcoded parent/process "detections" reusing
//   fictional hostnames (WS-ANALYST-01, DC-01) found elsewhere on this
//   page — rewritten to derive real detections from `de_events` rows
//   directly (technique/process/severity/mitre/hostname/description are
//   already tracked per real event).
// - `GetDEThreatIntel`'s `malware_families`/`ioc_matches` implied real
//   per-tenant detections (specific confidence scores, a fake sha256, a
//   fake registry key) rather than generic reference content;
//   `threat_actors`/`campaigns` (the latter recomputing a fake timestamp
//   on every request — the fourth occurrence of this bug class this
//   session) had zero real per-tenant attribution data anywhere in this
//   schema (no hash column, no attribution field). All four removed;
//   replaced with a real technique-frequency breakdown from `de_events` —
//   the one thing genuinely knowable from this data.
// - `GetDEMITRE`'s sub-technique `detected`/`count` fields were fixed
//   literals identical for every tenant, laid over an otherwise-legitimate
//   static T1055-adjacent reference structure (kept as-is) — rewritten to
//   a real `GROUP BY mitre_id` count over `de_events`.
// - `GetDEAnalytics`'s `top_techniques`/`most_targeted_endpoints`/
//   `control_status`/`mitre_coverage` were all hardcoded despite real
//   equivalent queries over `de_events`/`de_controls` being one query
//   away — wired to real aggregations.
// - `PostDEResponse` was the familiar canned-message dispatcher (8
//   actions!). Rewritten: `restart_security_services`/`reenable_defender`/
//   `restore_firewall` do real UPDATEs against `de_controls`;
//   `isolate_endpoint`/`kill_process` resolve a real agent by hostname and
//   dispatch a real pending-approval task; `create_incident` does a real
//   INSERT INTO incidents; `collect_memory` now honestly 501 (no real
//   agent capability, matching Process Injection's identical finding);
//   `run_soar` removed, replaced with the real `/playbooks` link.
// - Also found and fixed a real, more severe variant of a bug pattern from
//   this session's own earlier work: the Response tab's `respond()` call
//   site sent hardcoded fake identifiers (`hostname: 'WS-ANALYST-01',
//   target: 'Windows Defender'`) for literally every action with zero
//   target-selection UI at all — worse than Process Injection's version,
//   which at least sometimes used real data. Fixed by adding real
//   hostname/target inputs. Separately discovered the API client's
//   `respond`/`analyzeAI`/`generateReport` methods on this page (and,
//   found while fixing this, Process Injection's identical methods) had a
//   `.catch(() => ({ data: null }))` wrapper that silently swallowed real
//   errors before they ever reached the component — meaning the
//   component-level error handling added to Process Injection earlier
//   this same session was dead code. Fixed both pages' API client methods
//   to stop swallowing errors, and added the matching component-level
//   try/catch to this page's `respond()`/`runAI()`.
// - Like every other page this phase: none of this page's 4 own tables
//   had any seed data anywhere in a fresh dev environment — added
//   `seedDefenseEvasion` to cmd/seed/demo/main.go, idempotency-guarded
//   like every other keyless table this phase.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = ['Dashboard', 'Security Controls', 'Tamper & Logs', 'Evasion Events',
  'Behavioral', 'MITRE Coverage', 'Threat Intel', 'Analytics', 'Response'];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Defense Evasion — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/defense-evasion');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/defense-evasion');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });

  test('the removed Detection Validation tab no longer exists', async ({ page }) => {
    await page.goto('/defense-evasion');
    await expect(page.getByRole('button', { name: 'Detection Validation' })).toHaveCount(0);
    const res = await page.request.get('/api/de/validation');
    expect(res.status()).toBe(404);
  });
});

test.describe('Defense Evasion — regression guard: seed data exists', () => {
  test('the dashboard shows real, non-zero counts instead of a permanently empty page', async ({ page }) => {
    const dash = await page.request.get('/api/de/dashboard').then(r => r.json());
    expect(dash.defense_evasion_alerts).toBeGreaterThan(0);

    const count = PSQL(`SELECT count(*) FROM de_events WHERE tenant_id=9999;`);
    expect(Number(count)).toBeGreaterThan(0);
  });
});

test.describe('Defense Evasion — regression guard: behavioral/threat-intel/mitre are real, not fixed fictional data', () => {
  test('behavioral detections come from real de_events rows', async ({ page }) => {
    const res = await page.request.get('/api/de/behavioral').then(r => r.json());
    const realCount = Number(PSQL(`SELECT count(*) FROM de_events WHERE tenant_id=9999;`));
    expect(res.detections.length).toBe(Math.min(realCount, 50));
  });

  test('threat intel is a real technique breakdown, and malware_families/threat_actors/campaigns/ioc_matches are gone', async ({ page }) => {
    const res = await page.request.get('/api/de/threat-intel').then(r => r.json());
    expect(res).not.toHaveProperty('malware_families');
    expect(res).not.toHaveProperty('threat_actors');
    expect(res).not.toHaveProperty('campaigns');
    expect(res).not.toHaveProperty('ioc_matches');
    expect(res.observed_techniques.length).toBeGreaterThan(0);
  });

  test('MITRE technique counts reflect real seeded de_events data', async ({ page }) => {
    const res = await page.request.get('/api/de/mitre').then(r => r.json());
    const t1562 = res.techniques.find((t: any) => t.id === 'T1562');
    const realCount = Number(PSQL(`SELECT count(*) FROM de_events WHERE tenant_id=9999 AND mitre_id LIKE 'T1562%';`));
    expect(t1562.count).toBe(realCount);
    expect(t1562.detected).toBe(realCount > 0);
  });
});

test.describe('Defense Evasion — regression guard: response actions are real, not a no-op', () => {
  test('reenable_defender really updates the control row', async ({ page }) => {
    const res = await page.request.post('/api/de/response', {
      data: { action: 'reenable_defender', hostname: 'win-workstation-05', reason: 'e2e test' },
    });
    expect(res.ok()).toBeTruthy();
    const status = PSQL(`SELECT status FROM de_controls WHERE tenant_id=9999 AND hostname='win-workstation-05' AND control_name ILIKE '%defender%';`);
    expect(status).toBe('active');
  });

  test('reenable_defender without a hostname fails honestly instead of claiming success', async ({ page }) => {
    const res = await page.request.post('/api/de/response', { data: { action: 'reenable_defender' } });
    expect(res.status()).toBe(400);
  });

  test('isolate_endpoint really queues a real agent task pending approval', async ({ page }) => {
    const before = Number(PSQL(`SELECT count(*) FROM agent_tasks WHERE task_type='isolate_host';`));
    const res = await page.request.post('/api/de/response', {
      data: { action: 'isolate_endpoint', hostname: 'win-workstation-05', reason: 'e2e test' },
    });
    expect(res.ok()).toBeTruthy();
    const after = Number(PSQL(`SELECT count(*) FROM agent_tasks WHERE task_type='isolate_host';`));
    expect(after).toBe(before + 1);
  });

  test('create_incident really inserts an incidents row', async ({ page }) => {
    const before = Number(PSQL(`SELECT count(*) FROM incidents WHERE tenant_id=9999;`));
    const res = await page.request.post('/api/de/response', { data: { action: 'create_incident', hostname: 'win-workstation-05' } });
    expect(res.ok()).toBeTruthy();
    const after = Number(PSQL(`SELECT count(*) FROM incidents WHERE tenant_id=9999;`));
    expect(after).toBe(before + 1);
  });

  test('collect_memory honestly reports no real capability instead of fake success', async ({ page }) => {
    const res = await page.request.post('/api/de/response', { data: { action: 'collect_memory', hostname: 'win-workstation-05' } });
    expect(res.status()).toBe(501);
  });

  test('an unrecognized action is rejected rather than silently reporting success', async ({ page }) => {
    const res = await page.request.post('/api/de/response', { data: { action: 'not_a_real_action' } });
    expect(res.status()).toBe(400);
  });

  test('the Response tab no longer offers a fake run_soar action button, and real target inputs exist', async ({ page }) => {
    await page.goto('/defense-evasion');
    await page.getByRole('button', { name: 'Response', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Run SOAR Playbook' })).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Run SOAR Playbook' })).toBeVisible();
    await expect(page.getByPlaceholder('Hostname')).toBeVisible();
  });
});
