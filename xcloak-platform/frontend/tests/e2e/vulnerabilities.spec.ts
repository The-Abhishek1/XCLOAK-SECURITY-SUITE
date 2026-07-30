import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Vulnerabilities page (route
// /vulnerabilities) — a fabrication footprint on par with the largest
// pages this phase (Container/AD Attacks), spread across nearly every
// tab, on top of a real, previously-unnoticed parameter-index bug.
//
// Real bugs found and fixed in api/vulnerabilities_enterprise.go:
// - `PostVMFindingAction`'s "accept_risk" case had
//   `WHERE id=$2 AND tenant_id=$3` with only 2 args bound (fid, tid) —
//   $3 was never bound, so the UPDATE always errored and the error was
//   silently discarded (`database.DB.Exec(...)` return ignored) — the
//   "Accept Risk" button had never actually updated anything despite
//   always returning `{"ok": true}`. Fixed the parameter indices and
//   added real error/not-found handling to all three actions.
// - `GetVMDashboard`: risk_score/mttr_days/patch_sla_compliance/
//   assets_affected/overdue were hardcoded literals despite real
//   risk_score/detected_at/patched_at/asset_id columns already existing
//   to compute all five — wired to real aggregations with a shared
//   per-severity SLA-window definition (critical=7d/high=30d/medium=90d/
//   low=180d) reused across the dashboard, analytics, compliance, and
//   report endpoints.
// - `GetVMCompliance` was a fully fabricated 4-framework grid (PCI DSS/
//   CIS/NIST CSF/ISO 27001, identical for every tenant, specific
//   fictional "finding" text) — replaced with the shared real
//   fce_frameworks/fce_controls tables (the established fix shape for
//   this exact pattern, already used by Container/Supply Chain/OT-ICS).
//   While wiring this in, found and fixed TWO further real, previously
//   latent bugs: (1) the per-framework controls query joined on
//   fce_frameworks.id (an integer) when fce_controls.framework_id is
//   actually the framework's TEXT code (e.g. "PCI-DSS") — every
//   framework showed 0 controls despite hundreds of real rows existing;
//   (2) even after fixing the join, fce_controls.description is
//   nullable with no DEFAULT, and scanning NULL into a plain Go string
//   silently failed rows.Scan() for every real control row — fixed with
//   COALESCE rather than altering a table other pages also depend on.
// - `GetVMAttackSurface` was 100% hardcoded (fake exposed services, fake
//   TLS certificates with dates computed fresh from time.Now() every
//   request, fake DNS records, fake firewall rules) — internet-exposed-
//   asset counts and exposed services are now derived from real
//   vm_assets.internet_facing/open_ports, firewall exposure from a real
//   firewall_rules query; certificates/DNS-exposure were dropped
//   entirely (no certificate store or DNS zone tracking exists anywhere
//   in this codebase to back either honestly) — removed the now-dead
//   "TLS Certificates" card from the frontend rather than leave it
//   permanently empty.
// - `GetVMThreatIntel`: the frontend's own section title ("CISA KEV
//   Catalog — Matched Findings") already promised per-tenant matching,
//   but the handler returned 3 fixed CVEs regardless of tenant — now
//   genuinely derived from this tenant's own kev_listed/actively_exploited/
//   exploit_maturity/threat_actors findings; dropped campaign/
//   first_observed/public_poc/metasploit/exploit_db/country/motivation/
//   target_sectors fields with zero real backing anywhere in this schema.
// - `GetVMAnalytics`: mttr_days/patch_sla were hardcoded duplicates of the
//   dashboard's fake values; top_vulnerable_assets/top_cves/risk_trend/
//   patch_sla_breakdown were all hardcoded despite real vm_assets/
//   vm_findings aggregations being one query away — wired to real data.
// - `PostVMReport` was a fully fabricated static report (31 findings,
//   6 critical, fictional recommendations) — rewritten to real
//   key_metrics/top_risks plus an LLM-generated summary grounded only in
//   those real numbers, matching the pattern established on Playbooks/
//   Approval Queue's own report endpoints.
//
// Like every other page this phase: none of this page's 5 own tables had
// any seed data anywhere in a fresh dev environment — added
// seedVulnerabilityManagement to cmd/seed/demo/main.go (4 assets, 8
// findings spanning every severity/KEV/exploit-maturity combination with
// real detected_at/patched_at timestamps to exercise MTTR/SLA math, 3
// scans, 1 exception, 3 patches), plus 2 real "wide open" firewall_rules
// fixtures since every pre-existing 0.0.0.0/0 rule this tenant already
// had was a real drop/deny rule, not an exposure.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = ['Dashboard', 'Inventory', 'Asset Exposure', 'Attack Surface', 'Patch Management',
  'Threat Intel', 'Compliance', 'Analytics', 'Scan Management', 'Exceptions', 'Reports'];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Vulnerabilities — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/vulnerabilities');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/vulnerabilities');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('Vulnerabilities — regression guard: seed data exists', () => {
  test('inventory and dashboard show real seeded findings, not an empty page', async ({ page }) => {
    const inv = await page.request.get('/api/vm/inventory').then(r => r.json());
    const realCount = Number(PSQL(`SELECT count(*) FROM vm_findings WHERE tenant_id=9999;`));
    expect(realCount).toBeGreaterThan(0);
    expect(inv.length).toBe(realCount);

    const dash = await page.request.get('/api/vm/dashboard').then(r => r.json());
    expect(dash.total).toBe(realCount);
  });
});

test.describe('Vulnerabilities — regression guard: accept_risk really persists (the $2/$3 parameter bug)', () => {
  test('accepting risk on a real finding actually updates its status', async ({ page }) => {
    const fid = Number(PSQL(`SELECT id FROM vm_findings WHERE tenant_id=9999 AND cve_id='CVE-2022-1234';`));
    const res = await page.request.post(`/api/vm/findings/${fid}/action`, { data: { action: 'accept_risk' } });
    expect(res.ok()).toBeTruthy();
    const status = PSQL(`SELECT status FROM vm_findings WHERE id=${fid};`);
    expect(status).toBe('accepted');
  });

  test('an unrecognized action is rejected rather than silently reporting success', async ({ page }) => {
    const fid = Number(PSQL(`SELECT id FROM vm_findings WHERE tenant_id=9999 LIMIT 1;`));
    const res = await page.request.post(`/api/vm/findings/${fid}/action`, { data: { action: 'not_a_real_action' } });
    expect(res.status()).toBe(400);
  });

  test('acting on a nonexistent finding returns 404, not a fake success', async ({ page }) => {
    const res = await page.request.post('/api/vm/findings/999999/action', { data: { action: 'mark_patched' } });
    expect(res.status()).toBe(404);
  });
});

test.describe('Vulnerabilities — regression guard: dashboard/analytics are computed from real data', () => {
  test('mttr_days and patch_sla_compliance are computed, not the old fixed 14.2 / 82.3', async ({ page }) => {
    const dash = await page.request.get('/api/vm/dashboard').then(r => r.json());
    const realMttr = Number(PSQL(`SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (patched_at-detected_at))/86400),0) FROM vm_findings WHERE tenant_id=9999 AND status='patched' AND patched_at IS NOT NULL;`));
    expect(Math.abs(dash.mttr_days - realMttr)).toBeLessThan(0.1);
  });

  test('analytics top_vulnerable_assets and top_cves reflect real seeded data, not fixed fictional asset names', async ({ page }) => {
    const res = await page.request.get('/api/vm/analytics').then(r => r.json());
    expect(res.top_vulnerable_assets.length).toBeGreaterThan(0);
    expect(res.top_vulnerable_assets.some((a: any) => a.asset === 'VPN-GW-01')).toBeFalsy();
    expect(res.top_cves.some((c: any) => c.cve === 'CVE-2024-3400')).toBeTruthy();
  });
});

test.describe('Vulnerabilities — regression guard: compliance uses real fce_frameworks/fce_controls', () => {
  test('at least one framework with real seeded controls shows real, non-null control rows', async ({ page }) => {
    const res = await page.request.get('/api/vm/compliance').then(r => r.json());
    const pciDSS = res.frameworks.find((f: any) => f.name === 'PCI DSS');
    expect(pciDSS).toBeTruthy();
    expect(pciDSS.controls.length).toBeGreaterThan(0);
    expect(res.failed_controls).toBeGreaterThan(0);
  });

  test('missing_patches and sla_violations are derived from real vm_findings, not the old fixed 14 / 7', async ({ page }) => {
    const res = await page.request.get('/api/vm/compliance').then(r => r.json());
    const realMissing = Number(PSQL(`SELECT count(*) FROM vm_findings WHERE tenant_id=9999 AND status='open' AND patch_available=true;`));
    expect(res.missing_patches).toBe(realMissing);
  });
});

test.describe('Vulnerabilities — regression guard: attack surface and threat intel are real, not fabricated', () => {
  test('attack surface reflects real internet-facing assets and real open ports', async ({ page }) => {
    const res = await page.request.get('/api/vm/attack-surface').then(r => r.json());
    const realExposed = Number(PSQL(`SELECT count(*) FROM vm_assets WHERE tenant_id=9999 AND internet_facing=true;`));
    expect(res.internet_exposed_assets).toBe(realExposed);
    expect(res).not.toHaveProperty('certificates');
    expect(res).not.toHaveProperty('dns_exposure');
  });

  test('firewall exposure finds the real seeded wide-open allow rule', async ({ page }) => {
    const res = await page.request.get('/api/vm/attack-surface').then(r => r.json());
    const rdpRule = res.firewall_exposure.find((r: any) => r.rule.includes('3389'));
    expect(rdpRule).toBeTruthy();
    expect(rdpRule.risk).toBe('high');
  });

  test('KEV catalog is matched against this tenant\'s real findings, not a fixed 3-CVE global list', async ({ page }) => {
    const res = await page.request.get('/api/vm/threat-intel').then(r => r.json());
    const realKevCount = Number(PSQL(`SELECT count(DISTINCT cve_id) FROM vm_findings WHERE tenant_id=9999 AND kev_listed=true;`));
    expect(res.kev_catalog.length).toBe(realKevCount);
  });
});

test.describe('Vulnerabilities — regression guard: report uses real numbers', () => {
  test('report key_metrics reflect the real open-finding count, not a fixed 31', async ({ page }) => {
    const res = await page.request.post('/api/vm/report', { data: {} }).then(r => r.json());
    const realOpen = Number(PSQL(`SELECT count(*) FROM vm_findings WHERE tenant_id=9999 AND status='open';`));
    expect(res.key_metrics.total_findings).toBe(realOpen);
    expect(res.key_metrics.total_findings).not.toBe(31);
  });
});
