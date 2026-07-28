import { test, expect, Page } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the DPI (Deep Packet Inspection) page. Runs
// against a REAL backend + seeded DB — see dashboard.spec.ts's header
// comment for the dev-stack recipe and global-setup.ts for the shared-login
// rationale.
//
// This page started as a huge frontend/backend mismatch: the backend
// (api/dpi_enterprise.go) had 14 real, DB-backed endpoints (Overview,
// Sessions, HTTP/DNS/TLS Inspection, Files, DLP, Analytics, Performance,
// Protocol Anomalies, Search, AI-Inspect, Response-Action) plus the
// pre-existing Findings/Summary pair, but the frontend only ever called
// Findings+Summary and rendered a single flat table. Per user decision, the
// full dashboard was built out (14 tabs) rather than left as-is. Building it
// surfaced several real, previously-invisible backend bugs (see comments
// inline below and the memory file for full detail):
//  - `iocs` table has real columns (indicator, type, severity, description,
//    enabled, shareable) and FORCED row-level security requiring a
//    transaction-scoped `app.tenant_id` GUC — every block_ip/block_domain/
//    block_url/block_asn response action (in this page AND the NBA page)
//    was hand-rolling a raw INSERT against a completely different, wrong
//    column set with no transaction, so it silently inserted nothing while
//    still reporting "blocked" success. Fixed via repositories.CreateIOC.
//  - `ja3_fingerprints` has real columns (hash, threat_name) — both this
//    page's and NBA's "Known Malicious JA3 Fingerprints" list referenced
//    nonexistent `fingerprint`/`label` columns and always rendered empty
//    despite 25 real threat-intel entries (Cobalt Strike, TrickBot, Emotet)
//    existing in the table the whole time.
//  - `incidents` has no `created_by` column — create_incident (in this page,
//    NBA, and two other call sites: cluster_enterprise.go's cluster-promote
//    action, alert_clustering_service.go's auto-promotion) always failed
//    the INSERT silently and returned "Incident #0 created" as if it worked.
//  - `alerts` has no `rule_id`/`message` columns (real: rule_name/
//    log_message) — create_alert always failed silently the same way.
//  - kill_session and push_firewall_rule (this page) and run_playbook (this
//    page and NBA) were previously canned-success strings with zero
//    backend effect; kill_session now honestly 501s (no agent task type
//    exists for tearing down one network session), the other two now do a
//    real dispatch/INSERT.
//  - The demo seed had zero rows in dpi_findings at all — every
//    findings-dependent tab (Findings, DNS, Files, DLP, Protocol Anomalies)
//    was always empty. Added a seedDPIFindings() seeder (cmd/seed/demo).
test.use({ storageState: SHARED_STORAGE_STATE });

function kpiValue(page: Page, label: string) {
  return page.locator('.g-card', { hasText: label }).first().locator('p.font-bold').first();
}

async function gotoTab(page: Page, label: string) {
  await page.goto('/dpi');
  await page.waitForTimeout(600);
  await page.getByRole('button', { name: label, exact: true }).first().click();
}

const ALL_TABS = ['Overview','Findings','Sessions','HTTP','DNS','TLS','Files & Malware','DLP',
  'Protocol Anomalies','Analytics','Performance','Search','AI Insights','Response'];

test.describe('DPI — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/dpi');
    await page.waitForLoadState('networkidle', { timeout: 15_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/dpi');
    await expect(page.locator('.g-card').first()).toBeVisible({ timeout: 15_000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });

  test('KPI strip matches live /api/dpi/summary', async ({ page }) => {
    const summary = await (await page.request.get('/api/dpi/summary')).json();

    await page.goto('/dpi');
    await expect(kpiValue(page, 'Findings (24h)')).toHaveText(String(summary.total_24h), { timeout: 15_000 });
    await expect(kpiValue(page, 'Alerts Fired')).toHaveText(String(summary.alerted_24h), { timeout: 15_000 });
  });

  test('every tab loads without a failed API call or console error', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/dpi');
    await page.waitForLoadState('networkidle', { timeout: 15_000 });
    for (const tab of ALL_TABS) {
      await page.getByRole('button', { name: tab, exact: true }).first().click();
      await page.waitForTimeout(500);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });
});

test.describe('DPI — regression guard: seeded findings are no longer silently empty', () => {
  test('Findings tab shows real seeded findings, not a permanently-empty table', async ({ page }) => {
    const data = await (await page.request.get('/api/dpi/findings?limit=50')).json();
    expect(data.findings.length).toBeGreaterThan(0);

    await gotoTab(page, 'Findings');
    await expect(page.getByText(/findings$/i).first()).toBeVisible({ timeout: 15_000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toContain('No DPI findings match');
  });
});

test.describe('DPI — regression guard: JA3 threat-intel is no longer hidden by a column-name bug', () => {
  test('TLS tab shows real known-malicious JA3 fingerprints (Cobalt Strike / TrickBot / etc.)', async ({ page }) => {
    const data = await (await page.request.get('/api/dpi/tls-inspection?hours=24')).json();
    expect(data.ja3_fingerprints.length).toBeGreaterThan(0);

    await gotoTab(page, 'TLS');
    await expect(page.getByText('Known Malicious JA3 Fingerprints')).toBeVisible({ timeout: 15_000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toContain('No JA3 fingerprint entries.');
  });
});

test.describe('DPI — Response Actions', () => {
  test('Block IP creates a real, persisted IOC row', async ({ page }) => {
    const testIP = '198.51.100.220';
    await gotoTab(page, 'Response');
    await page.getByRole('button', { name: 'Block IP' }).click();
    await page.getByPlaceholder('IP address').fill(testIP);
    await page.getByRole('button', { name: 'Execute' }).click();
    await expect(page.locator('div.fixed.bottom-5.right-5')).toContainText(/blocked via IOC/i, { timeout: 10_000 });

    const res = await page.request.post('/api/dpi/response-action', {
      data: { action: 'block_ip', ip: testIP, reason: 'cleanup-check' },
    });
    expect(res.status()).toBe(200); // idempotent re-block, proves the row is real and enabled
  });

  test('Block JA3 requires a 32-character hash and persists a real row', async ({ page }) => {
    await gotoTab(page, 'Response');
    await page.getByRole('button', { name: 'Block JA3' }).click();
    await page.getByPlaceholder('JA3 fingerprint').fill('tooshort');
    await page.getByRole('button', { name: 'Execute' }).click();
    await expect(page.locator('div.fixed.bottom-5.right-5')).toContainText(/32-character/i, { timeout: 10_000 });

    // API-level guard for the exact validation boundary.
    const short = await page.request.post('/api/dpi/response-action', {
      data: { action: 'block_ja3', ja3: 'abc' },
    });
    expect(short.status()).toBe(400);
  });

  test('Kill Session surfaces the honest "not supported" error instead of a fake success', async ({ page }) => {
    const res = await page.request.post('/api/dpi/response-action', {
      data: { action: 'kill_session', session_id: 'x', agent_id: 1 },
    });
    expect(res.status()).toBe(501);
    const body = await res.json();
    expect(body.error).toMatch(/not supported/i);
  });

  test('Push Firewall Rule creates a real, now-visible firewall_rules row', async ({ page }) => {
    const testIP = '198.51.100.221';
    await gotoTab(page, 'Response');
    await page.getByRole('button', { name: 'Push Firewall Rule' }).click();
    await page.getByPlaceholder('Target IP').fill(testIP);
    await page.getByRole('button', { name: 'Execute' }).click();
    await expect(page.locator('div.fixed.bottom-5.right-5')).toContainText(/firewall rule created/i, { timeout: 10_000 });

    const rules = await (await page.request.get('/api/firewall/rules')).json();
    expect(rules.some((r: any) => r.source_ip === testIP)).toBeTruthy();
  });

  test('Run SOAR Playbook requires a real playbook_id and actually executes it', async ({ page }) => {
    const playbooks: Array<{ id: number; name: string }> = await (await page.request.get('/api/playbooks')).json();
    expect(playbooks.length).toBeGreaterThan(0);

    await gotoTab(page, 'Response');
    await page.getByRole('button', { name: 'Run SOAR Playbook' }).click();
    await page.getByPlaceholder('Playbook ID').fill(String(playbooks[0].id));
    await page.getByRole('button', { name: 'Execute' }).click();
    // Under heavy parallel-suite load the toast (a fixed 4s window after the
    // real playbook-execution response lands) can finish its own timer
    // before a contention-delayed poll catches it — give this more room
    // than the single-worker default rather than treating it as flaky.
    await expect(page.locator('div.fixed.bottom-5.right-5')).toContainText(playbooks[0].name, { timeout: 20_000 });

    const res = await page.request.post('/api/dpi/response-action', {
      data: { action: 'run_playbook', playbook_id: 999999, reason: 'x' },
    });
    expect(res.status()).toBe(404);
  });

  test('Create Alert and Create Incident actually persist rows (previously silently failed)', async ({ page }) => {
    const alertRes = await page.request.post('/api/dpi/response-action', {
      data: { action: 'create_alert', reason: 'e2e-test-alert' },
    });
    expect(alertRes.status()).toBe(200);

    const incRes = await page.request.post('/api/dpi/response-action', {
      data: { action: 'create_incident', reason: 'e2e-test-incident' },
    });
    expect(incRes.status()).toBe(200);
    const incBody = await incRes.json();
    // The old bug always returned "Incident #0 created" — assert a *real*
    // (nonzero) ID came back from the RETURNING clause.
    expect(incBody.result).not.toContain('#0');
    expect(incBody.result).toMatch(/#\d+/);
  });
});

test.describe('DPI — Search', () => {
  test('cross-source search returns real results for a known seeded indicator', async ({ page }) => {
    await gotoTab(page, 'Search');
    const input = page.getByPlaceholder(/Search indicators, hosts, paths, SNIs/i);
    await input.fill('xkq7z9wq2f.biz');
    await input.press('Enter');
    await expect(page.getByText('xkq7z9wq2f.biz').first()).toBeVisible({ timeout: 10_000 });
  });
});
