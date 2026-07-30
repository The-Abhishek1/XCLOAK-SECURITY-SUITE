import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Supply Chain Security page (route
// /supply-chain) — repository/dependency inventory, SBOM, build pipelines,
// artifact provenance, secret scanning, threat intel, compliance, response.
//
// This was one of the cleanest backends found this phase, on par with Cloud
// Security — several endpoints already carried explicit "no real X exists
// in this schema, report an honest empty/zero result" comments from an
// earlier pass (GetSCCodeIntegrity, GetSCThirdPartyRisk's ci_plugins,
// GetSCThreatIntel's campaigns), and GetSCThreatIntel's malicious-package/
// exploited-CVE lists are genuine real-world public incident data used only
// as real per-tenant match criteria against this tenant's actual
// dependencies (not fabricated per-tenant claims) — verified live that
// ioc_matches only appears when a real matching dependency row exists.
// GetSCCompliance is also fully real, backed by the shared fce_frameworks/
// fce_controls tables the Dashboard and Risk Posture pages already use.
//
// The one real bug: `PostSCResponse` was the familiar pure canned-message
// dispatcher — 6 actions, zero real effect, any action string accepted.
// Rewritten: block_build/disable_pipeline do real UPDATEs against
// sc_build_pipelines (different status values so the two remain
// distinguishable); quarantine_artifact resolves the target's real
// artifact_hash and creates a real enabled IOC from it (the same "real DB
// write standing in for a missing live-enforcement mechanism" pattern used
// on every other page's block_* actions this phase); create_incident does
// a real INSERT INTO incidents; create_issue now honestly 501s (no real
// GitHub/GitLab API integration exists anywhere in this codebase) instead
// of claiming a fake issue was filed; trigger_soar removed, replaced with
// the same real /playbooks link used elsewhere this phase.
//
// Like every other page this phase: none of this page's 8 own tables had
// any seed data anywhere in a fresh dev environment — added
// seedSupplyChainSecurity to cmd/seed/demo/main.go, idempotency-guarded
// like every other keyless table this phase, including a real "event-stream"
// dependency deliberately seeded to exercise the real IOC-match path above.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = ['Overview', 'Repositories', 'Pipelines & Artifacts', 'SBOM & Vulnerabilities',
  'Secrets & Integrity', 'Threat Intelligence', 'Compliance & Policies', 'Analytics', 'Response & Reports'];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Supply Chain — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/supply-chain');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/supply-chain');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('Supply Chain — regression guard: seed data exists', () => {
  test('the dashboard shows real, non-zero counts instead of a permanently empty page', async ({ page }) => {
    const dash = await page.request.get('/api/supply-chain/dashboard').then(r => r.json());
    expect(dash.repositories).toBeGreaterThan(0);
    expect(dash.dependencies).toBeGreaterThan(0);

    const count = PSQL(`SELECT count(*) FROM sc_repositories WHERE tenant_id=9999;`);
    expect(Number(count)).toBeGreaterThan(0);
  });
});

test.describe('Supply Chain — regression guard: threat intel IOC matching is real, not fabricated', () => {
  test('ioc_matches only includes a known-malicious package that really exists in this tenant\'s dependencies', async ({ page }) => {
    const res = await page.request.get('/api/supply-chain/threat-intel').then(r => r.json());
    expect(res.campaigns).toEqual([]);
    const values = res.ioc_matches.map((m: any) => m.value);
    expect(values).toContain('event-stream');

    const realCount = Number(PSQL(`SELECT count(*) FROM sc_dependencies WHERE tenant_id=9999 AND package_name='event-stream';`));
    const match = res.ioc_matches.find((m: any) => m.value === 'event-stream');
    expect(match.hits).toBe(realCount);
  });
});

test.describe('Supply Chain — regression guard: compliance is real, backed by the shared framework-compliance tables', () => {
  test('frameworks come from real fce_frameworks data', async ({ page }) => {
    const res = await page.request.get('/api/supply-chain/compliance').then(r => r.json());
    expect(res.frameworks.length).toBeGreaterThan(0);
  });
});

test.describe('Supply Chain — regression guard: response actions are real, not a no-op', () => {
  test('block_build really updates the pipeline row', async ({ page }) => {
    const name = PSQL(`SELECT name FROM sc_build_pipelines WHERE tenant_id=9999 AND status NOT IN ('blocked','disabled') ORDER BY id LIMIT 1;`);
    const res = await page.request.post('/api/supply-chain/response', {
      data: { action: 'block_build', target: name },
    });
    expect(res.ok()).toBeTruthy();
    const status = PSQL(`SELECT status FROM sc_build_pipelines WHERE tenant_id=9999 AND name='${name}';`);
    expect(status).toBe('blocked');
  });

  test('block_build without a target fails honestly instead of claiming success', async ({ page }) => {
    const res = await page.request.post('/api/supply-chain/response', { data: { action: 'block_build' } });
    expect(res.status()).toBe(400);
  });

  test('quarantine_artifact creates a real, enabled IOC from the artifact\'s real hash', async ({ page }) => {
    const row = JSON.parse(PSQL(`SELECT json_build_object('name',name,'hash',artifact_hash) FROM sc_artifacts WHERE tenant_id=9999 AND artifact_hash != '' ORDER BY id LIMIT 1;`));
    const res = await page.request.post('/api/supply-chain/response', {
      data: { action: 'quarantine_artifact', target: row.name },
    });
    expect(res.ok()).toBeTruthy();
    const count = PSQL(`SELECT count(*) FROM iocs WHERE indicator='${row.hash}' AND enabled=true;`);
    expect(Number(count)).toBe(1);
  });

  test('create_incident really inserts an incidents row', async ({ page }) => {
    const before = Number(PSQL(`SELECT count(*) FROM incidents WHERE tenant_id=9999;`));
    const res = await page.request.post('/api/supply-chain/response', { data: { action: 'create_incident', target: 'e2e-test' } });
    expect(res.ok()).toBeTruthy();
    const after = Number(PSQL(`SELECT count(*) FROM incidents WHERE tenant_id=9999;`));
    expect(after).toBe(before + 1);
  });

  test('create_issue honestly reports no real integration instead of fake success', async ({ page }) => {
    const res = await page.request.post('/api/supply-chain/response', {
      data: { action: 'create_issue', target: 'e2e-test-repo' },
    });
    expect(res.status()).toBe(501);
  });

  test('an unrecognized action is rejected rather than silently reporting success', async ({ page }) => {
    const res = await page.request.post('/api/supply-chain/response', {
      data: { action: 'not_a_real_action' },
    });
    expect(res.status()).toBe(400);
  });

  test('the Response tab no longer offers a fake trigger_soar action button', async ({ page }) => {
    await page.goto('/supply-chain');
    await page.getByRole('button', { name: 'Response & Reports', exact: true }).click();
    await expect(page.getByText('Trigger SOAR', { exact: true })).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Run SOAR Playbook' })).toBeVisible();
  });
});
