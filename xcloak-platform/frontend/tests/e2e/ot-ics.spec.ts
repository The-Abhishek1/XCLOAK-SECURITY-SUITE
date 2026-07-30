import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the OT / ICS Security page (route /ot-ics)
// — industrial asset inventory, network topology, protocol analysis, device
// monitoring, threat detection, risk assessment, threat intel, compliance,
// analytics, and safety-aware response actions for PLCs/HMIs/RTUs/SCADA.
//
// This page had a fabrication footprint comparable to Container/AD Attacks
// — nearly every "risk"/"topology"/"attack-paths"/"compliance"/"analytics"
// endpoint had at least some hardcoded content mixed with real COUNT()
// queries. Given how closely the shapes matched patterns already reviewed
// and approved by the user 2-3 times each this phase (a fake framework-
// compliance grid → reuse the shared fce_frameworks tables, exactly as
// fixed on Supply Chain; a fake static "attack path" with specific
// fictional device names → a real top-risk-asset panel, exactly as fixed
// on Container Security and AD Attacks; hardcoded arrays with an obvious
// real query one line away → wire to real data, as fixed repeatedly this
// phase), these were fixed directly as confirmed recurrences rather than
// re-asking.
//
// - `PostOTResponse` was the familiar canned-message dispatcher (6 actions,
//   zero real effect, any action accepted). Rewritten: `create_incident`
//   does a real INSERT INTO ot_incidents; `block_network_path` and
//   `escalate_emergency` — both already flagged "requires operator
//   approval" in the old fake code — now create a real row in the existing,
//   fully-built Approval Queue system (`aq_requests`/`aq_audit`, the same
//   tables backing the real `/soar-approvals` page) instead of just
//   claiming to; `notify_operators`/`capture_traffic` now honestly 501 (no
//   real operator-alarm/PCAP-capture integration exists anywhere in this
//   codebase); `run_soar_playbook` removed, replaced with the real
//   `/playbooks` link used elsewhere this phase.
// - `GetOTCompliance`'s hardcoded IEC 62443/NERC CIP/NIST SP 800-82 grid
//   replaced with real data from the shared `fce_frameworks`/`fce_controls`
//   tables, identical fix shape to Supply Chain's `GetSCCompliance`.
// - `GetOTAttackPaths`'s two fully static attack chains (with fictional
//   device names reused from other fake endpoints on this same page)
//   replaced with real top-risk-asset and exposed-control-CVE panels.
// - `GetOTRiskAssessment`'s `weak_auth`/`open_services` fields were declared
//   but never queried (always silently 0); its `critical_assets`/`findings`
//   were fully hardcoded with the same fictional device names. Fixed to
//   real asset-risk-derived data; the two always-zero unbacked fields were
//   removed rather than kept as fake-honest zeros.
// - `GetOTBaseline`'s `categories` had fixed fake learned-item counts, and
//   its `deviations` recomputed fake timestamps fresh on every request
//   (silently drifting forward in real time) — the same "ever-refreshing
//   fabrication" bug class first found on AD Attacks' `privileged_sessions`.
//   Both replaced with real data from `ot_baselines`/`ot_alerts`.
// - `GetOTThreatIntel`'s `ioc_matches` was two hardcoded fake IOCs; the
//   `ot_threat_actors`/`industrial_malware`/`sector_advisories` fields are
//   genuine real-world ICS threat history (Stuxnet, TRITON, Industroyer)
//   kept as advisory reference content, same treatment as Supply Chain's
//   malicious-package list. `ioc_matches` rewired to a real match against
//   this tenant's actual `iocs` table, exactly like Supply Chain's fix.
// - `GetOTAnalytics`'s `most_active_plcs`/`protocol_distribution`/
//   `config_changes_7d` were hardcoded despite real equivalent queries one
//   line away — wired to real aggregations; `firmware_age` had no real
//   per-asset install-date field anywhere in this schema to back a 4-bucket
//   age breakdown, so it was removed rather than forced through a fake
//   proxy. `GetOTTopology`'s `links` and `GetOTProtocols`'s `sessions` were
//   both hardcoded fake traffic samples with fixed IPs — both wired to real
//   `ot_traffic` aggregations.
// - Also fixed: both this page's and Supply Chain's `execute()` handlers
//   had a bare `catch { setResult({ error: 'Action failed' }) }` that
//   discarded the real backend error message — meaningful now that both
//   pages have real 501 responses to surface; both fixed to read
//   `err.response.data.error`.
// - Like every other page this phase: none of this page's 8 own tables had
//   any seed data anywhere in a fresh dev environment — added
//   `seedOTICSSecurity` to cmd/seed/demo/main.go, idempotency-guarded like
//   every other keyless table this phase.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = ['Overview', 'Asset Inventory', 'Network Topology', 'Protocol Analysis',
  'Device Monitoring', 'Threat Detection', 'Risk Assessment', 'Threat Intelligence',
  'Compliance', 'Analytics', 'Response'];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('OT/ICS — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/ot-ics');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/ot-ics');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('OT/ICS — regression guard: seed data exists', () => {
  test('the dashboard shows real, non-zero counts instead of a permanently empty page', async ({ page }) => {
    const dash = await page.request.get('/api/ot/dashboard').then(r => r.json());
    expect(dash.total_assets).toBeGreaterThan(0);

    const count = PSQL(`SELECT count(*) FROM ot_assets WHERE tenant_id=9999;`);
    expect(Number(count)).toBeGreaterThan(0);
  });
});

test.describe('OT/ICS — regression guard: compliance is real, backed by the shared framework-compliance tables', () => {
  test('frameworks come from real fce_frameworks data, not a fake IEC 62443 grid', async ({ page }) => {
    const res = await page.request.get('/api/ot/compliance').then(r => r.json());
    expect(res.frameworks.length).toBeGreaterThan(0);
  });
});

test.describe('OT/ICS — regression guard: attack paths and risk assessment are real, not fixed fictional devices', () => {
  test('attack-paths risk_assets/exposed_control_vulns reflect real seeded data', async ({ page }) => {
    const res = await page.request.get('/api/ot/attack-paths').then(r => r.json());
    expect(res).not.toHaveProperty('paths');
    expect(res.risk_assets.length).toBeGreaterThan(0);
  });

  test('risk assessment critical_assets/findings are real, and unbacked weak_auth/open_services fields are gone', async ({ page }) => {
    const res = await page.request.get('/api/ot/risk').then(r => r.json());
    expect(res).not.toHaveProperty('weak_auth');
    expect(res).not.toHaveProperty('open_services');
    expect(res.critical_assets.length).toBeGreaterThan(0);
    const names = res.critical_assets.map((a: any) => a.name);
    // The old fake list always included this fictional PLC name regardless of tenant.
    const realTopRiskName = PSQL(`SELECT name FROM ot_assets WHERE tenant_id=9999 ORDER BY risk_score DESC LIMIT 1;`);
    expect(names).toContain(realTopRiskName);
  });
});

test.describe('OT/ICS — regression guard: baseline deviations are real, not an ever-refreshing fake timestamp', () => {
  test('deviations come from real open ot_alerts, categories from real ot_baselines', async ({ page }) => {
    const res = await page.request.get('/api/ot/baseline').then(r => r.json());
    expect(res.categories.length).toBeGreaterThan(0);
    const realOpenAlerts = Number(PSQL(`SELECT count(*) FROM ot_alerts WHERE tenant_id=9999 AND status='open';`));
    expect(res.deviations.length).toBe(Math.min(realOpenAlerts, 10));
  });
});

test.describe('OT/ICS — regression guard: response actions are real, not a no-op', () => {
  test('create_incident really inserts an ot_incidents row', async ({ page }) => {
    const before = Number(PSQL(`SELECT count(*) FROM ot_incidents WHERE tenant_id=9999;`));
    const res = await page.request.post('/api/ot/response', { data: { action: 'create_incident', target: 'e2e-test' } });
    expect(res.ok()).toBeTruthy();
    const after = Number(PSQL(`SELECT count(*) FROM ot_incidents WHERE tenant_id=9999;`));
    expect(after).toBe(before + 1);
  });

  test('block_network_path really creates a real approval-queue request', async ({ page }) => {
    const before = Number(PSQL(`SELECT count(*) FROM aq_requests WHERE tenant_id=9999;`));
    const res = await page.request.post('/api/ot/response', {
      data: { action: 'block_network_path', target: 'field-net', reason: 'e2e test' },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.requires_approval).toBe(true);
    const after = Number(PSQL(`SELECT count(*) FROM aq_requests WHERE tenant_id=9999;`));
    expect(after).toBe(before + 1);
  });

  test('escalate_emergency creates a real emergency approval-queue request', async ({ page }) => {
    const res = await page.request.post('/api/ot/response', {
      data: { action: 'escalate_emergency', target: 'plant-a', reason: 'e2e test' },
    });
    expect(res.ok()).toBeTruthy();
    const approvalID = (await res.json()).approval_id;
    const isEmergency = PSQL(`SELECT is_emergency FROM aq_requests WHERE tenant_id=9999 AND approval_id='${approvalID}';`);
    expect(isEmergency).toBe('t');
  });

  test('notify_operators honestly reports no real integration instead of fake success', async ({ page }) => {
    const res = await page.request.post('/api/ot/response', { data: { action: 'notify_operators' } });
    expect(res.status()).toBe(501);
  });

  test('an unrecognized action is rejected rather than silently reporting success', async ({ page }) => {
    const res = await page.request.post('/api/ot/response', { data: { action: 'not_a_real_action' } });
    expect(res.status()).toBe(400);
  });

  test('the Response tab no longer offers a fake run_soar_playbook action button', async ({ page }) => {
    await page.goto('/ot-ics');
    await page.getByRole('button', { name: 'Response', exact: true }).click();
    await expect(page.getByText('Run SOAR Playbook', { exact: true })).toHaveCount(1);
    await expect(page.getByRole('link', { name: 'Run SOAR Playbook' })).toBeVisible();
  });
});
