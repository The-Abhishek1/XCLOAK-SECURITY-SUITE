import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Container & Kubernetes Security page
// (route /container-security) — cluster/node/pod inventory, image scanning,
// runtime protection, RBAC/secrets/network policy, compliance, threat
// intel, response actions.
//
// This page's fabrication footprint rivaled Email Security's, spread across
// nearly every tab. Confirmed scope with the user via AskUserQuestion for
// the three largest/most novel judgment calls before touching them; the
// rest (response actions, a few GET endpoints with an obvious real-data
// path already sitting one query away) were fixed directly as recurrences
// of patterns already established elsewhere this phase.
//
// - `PostContainerResponse` was a pure canned-message dispatcher (7 actions,
//   zero real effect, any string accepted). Rewritten: kill_container/
//   delete_pod do real UPDATE/DELETE against k8s_pods, quarantine_node does
//   a real UPDATE against k8s_nodes, block_image creates a real enabled IOC
//   (type=image) — matching every other page's "real DB write standing in
//   for a live enforcement API that doesn't exist" pattern this phase.
//   revoke_service_account/scale_deployment now honestly 501 (no real IAM/
//   deployment abstraction exists anywhere in this schema) instead of
//   claiming fake success. run_soar_playbook was removed and replaced with
//   the same real `/playbooks` link used on Threat Hunt/DFIR/Email Security.
// - GetSupplyChain's `trusted_registries` was a hardcoded 4-row table —
//   replaced with a real per-registry aggregation from k8s_images.
// - GetK8sSecrets's `plaintext`/`expired`/`exposed` fields were permanently
//   hardcoded to 0 with zero real computation, misleadingly implying
//   "verified none exist" — removed rather than left as fake-honest zeros.
// - GetContainerCompliance's fully fabricated 5-framework grid (CIS/NSA/
//   PCI/NIST/ISO27001, identical for every tenant, no real per-framework
//   K8s control catalog exists anywhere) was replaced — per user's
//   confirmed choice — with a real summary computed from
//   k8s_admission_violations (severity breakdown, denied/allowed counts,
//   real violation rows).
// - GetContainerThreatIntel's `threat_actors`/`malware_families` (zero real
//   attribution data anywhere in this schema) were removed per user's
//   confirmed choice, matching Email Security's malicious_ips/
//   malware_families removal for the same reason. `malicious_images`/
//   `ioc_matches` DID have a real backing path — wired to the real,
//   previously-unused `k8s_images.malware_found` column and the real
//   `iocs` table respectively.
// - GetContainerAttackPaths was a fully static graph with specific
//   fictional resource names (web-app Pod, db-credentials Secret) that
//   could be mistaken for real discovered assets — replaced, per user's
//   confirmed choice, with a real "Top Risk Factors" panel built from
//   actual privileged/root/host-network pods and actual RBAC
//   excessive-permission findings.
// - GetContainerAnalytics's `top_vulnerable_images`/`alert_by_type`/
//   `namespace_risk` were hardcoded despite a real equivalent query being
//   one line away (the same "narrow, obvious real backing" shape as NBA's
//   namespace_risk duplication earlier this phase) — wired to real
//   aggregations from k8s_images/k8s_runtime_alerts/k8s_pods.
// - Like Email Security and Cloud Security before it: none of this page's
//   8 own tables had any seed data anywhere in a fresh dev environment —
//   added `seedContainerSecurity` to cmd/seed/demo/main.go,
//   idempotency-guarded like every other keyless table this phase.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = ['Overview', 'Inventory', 'Images', 'Runtime', 'RBAC + Network',
  'Intelligence', 'Compliance', 'Analytics', 'Attack Paths + Response'];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Container Security — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/container-security');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/container-security');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('Container Security — regression guard: seed data exists', () => {
  test('the dashboard shows real, non-zero counts instead of a permanently empty page', async ({ page }) => {
    const dash = await page.request.get('/api/containers/dashboard').then(r => r.json());
    expect(dash.clusters).toBeGreaterThan(0);
    expect(dash.pods).toBeGreaterThan(0);

    const count = PSQL(`SELECT count(*) FROM k8s_clusters WHERE tenant_id=9999;`);
    expect(Number(count)).toBeGreaterThan(0);
  });
});

test.describe('Container Security — regression guard: compliance is real, not a fabricated framework grid', () => {
  test('compliance data is derived from real k8s_admission_violations, no fake CIS/NSA/PCI grid remains', async ({ page }) => {
    const res = await page.request.get('/api/containers/compliance').then(r => r.json());
    expect(res).not.toHaveProperty('frameworks');
    expect(res).not.toHaveProperty('failed_controls');
    expect(res.total_violations).toBeGreaterThan(0);

    const realTotal = Number(PSQL(`SELECT count(*) FROM k8s_admission_violations WHERE tenant_id=9999;`));
    expect(res.total_violations).toBe(realTotal);
  });
});

test.describe('Container Security — regression guard: threat intel has no unbacked fabrication', () => {
  test('threat_actors and malware_families are gone, malicious_images/ioc_matches are real', async ({ page }) => {
    const res = await page.request.get('/api/containers/threat-intel').then(r => r.json());
    expect(res).not.toHaveProperty('threat_actors');
    expect(res).not.toHaveProperty('malware_families');

    const realMalwareImages = Number(PSQL(`SELECT count(*) FROM k8s_images WHERE tenant_id=9999 AND malware_found=true;`));
    expect(res.malicious_images.length).toBe(realMalwareImages);
    expect(realMalwareImages).toBeGreaterThan(0);
  });
});

test.describe('Container Security — regression guard: attack paths is real risk data, not a fake static graph', () => {
  test('risk_pods/risk_rbac reflect real seeded data, and the old fake node/edge graph is gone', async ({ page }) => {
    const res = await page.request.get('/api/containers/attack-paths').then(r => r.json());
    expect(res).not.toHaveProperty('nodes');
    expect(res).not.toHaveProperty('edges');
    expect(res.risk_pods.length).toBeGreaterThan(0);
    expect(res.risk_rbac.length).toBeGreaterThan(0);
    // The old fake graph always included this fictional pod name.
    const podNames = res.risk_pods.map((p: any) => p.name);
    expect(podNames).not.toContain('web-app Pod');
  });
});

test.describe('Container Security — regression guard: response actions are real, not a no-op', () => {
  test('kill_container really updates the pod row', async ({ page }) => {
    const target = JSON.parse(PSQL(`SELECT json_build_object('name',name,'namespace',namespace) FROM k8s_pods WHERE tenant_id=9999 AND status != 'terminated' ORDER BY id LIMIT 1;`));
    const res = await page.request.post('/api/containers/response', {
      data: { action: 'kill_container', pod_name: target.name, namespace: target.namespace },
    });
    expect(res.ok()).toBeTruthy();
    const status = PSQL(`SELECT status FROM k8s_pods WHERE tenant_id=9999 AND name='${target.name}' AND namespace='${target.namespace}';`);
    expect(status).toBe('terminated');
  });

  test('kill_container without a pod_name fails honestly instead of claiming success', async ({ page }) => {
    const res = await page.request.post('/api/containers/response', { data: { action: 'kill_container' } });
    expect(res.status()).toBe(400);
  });

  test('block_image creates a real, enabled IOC', async ({ page }) => {
    const image = `docker.io/e2e-test/malicious-${Date.now()}`;
    const res = await page.request.post('/api/containers/response', {
      data: { action: 'block_image', image },
    });
    expect(res.ok()).toBeTruthy();
    const count = PSQL(`SELECT count(*) FROM iocs WHERE indicator='${image}' AND type='image' AND enabled=true;`);
    expect(Number(count)).toBe(1);
  });

  test('quarantine_node really cordons the node row', async ({ page }) => {
    const nodeName = PSQL(`SELECT name FROM k8s_nodes WHERE tenant_id=9999 AND status != 'cordoned' ORDER BY id LIMIT 1;`);
    const res = await page.request.post('/api/containers/response', {
      data: { action: 'quarantine_node', node_name: nodeName },
    });
    expect(res.ok()).toBeTruthy();
    const status = PSQL(`SELECT status FROM k8s_nodes WHERE tenant_id=9999 AND name='${nodeName}';`);
    expect(status).toBe('cordoned');
  });

  test('revoke_service_account honestly reports no real integration instead of fake success', async ({ page }) => {
    const res = await page.request.post('/api/containers/response', {
      data: { action: 'revoke_service_account', service_account: 'e2e-test-sa' },
    });
    expect(res.status()).toBe(501);
  });

  test('an unrecognized action is rejected rather than silently reporting success', async ({ page }) => {
    const res = await page.request.post('/api/containers/response', {
      data: { action: 'not_a_real_action' },
    });
    expect(res.status()).toBe(400);
  });

  test('the Response tab no longer offers a fake run_soar_playbook action button', async ({ page }) => {
    await page.goto('/container-security');
    await page.getByRole('button', { name: 'Attack Paths + Response', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Run SOAR Playbook' })).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Run SOAR Playbook' })).toBeVisible();
  });
});
