import { test, expect, Page } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the NBA (Network Behavior Analytics) page.
// Runs against a REAL backend + seeded DB — see dashboard.spec.ts's header
// comment for the dev-stack recipe and global-setup.ts for the shared-login
// rationale.
//
// Unlike UEBA/Insider Threat, this page's 14 GET endpoints were all found to
// be genuinely backed by real queries against network_connect_events /
// network_anomalies / iocs / ja3_fingerprints / endpoint_connections — no
// canned data. Real bugs found and fixed instead:
//  - Response Actions: 3 of 9 actions (isolate_endpoint, kill_process,
//    run_playbook) called dead/inert code paths (an `agents.isolated` column
//    nothing reads, no dispatch at all) — rewired to the same real
//    agent_tasks/pending-approval and playbook-execution machinery
//    Incidents/Alerts already use. start_pcap now returns an honest 501
//    (no agent executor supports packet capture). push_firewall_rule now
//    writes a real firewall_rules row instead of a 200-with-caveat.
//  - GetNBAThreatIntel: the SQL join for domain-type IOCs had no match
//    condition at all (`i.ioc_type='domain'` with no comparison to
//    nce.sni/http_host), so any domain IOC cross-joined every connection
//    event, fabricating threat-intel hits. Fixed to match on sni/http_host.
//  - GetNBAFlows: `detected_at` was hardcoded to `time.Now()` at request
//    time instead of the connection's real `created_at` (not currently
//    rendered in the UI, but fixed for correctness/future use).
//  - Demo seed data used anomaly_type values ("exfil", "lateral_move") that
//    never match what the real detector (services/port_scan_detector.go)
//    and every NBA handler query for ("exfiltration", "lateral_movement") —
//    the Overview KPIs and the whole Lateral Movement tab silently showed
//    0/empty despite seeded anomalies existing. Fixed seed + live DB rows.
test.use({ storageState: SHARED_STORAGE_STATE });

function kpiValue(page: Page, label: string) {
  return page.locator('.g-card', { hasText: label }).first().locator('p.font-bold').first();
}

async function gotoTab(page: Page, label: string) {
  await page.goto('/nba');
  await page.getByRole('button', { name: label, exact: true }).click();
}

test.describe('NBA — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];

    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });

    await page.goto('/nba');
    await page.waitForLoadState('networkidle', { timeout: 15_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/nba');
    await expect(page.locator('.g-card').first()).toBeVisible({ timeout: 15_000 });

    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });

  test('KPI strip matches live /api/nba/overview (7d window, matching the widest UI selector option)', async ({ page }) => {
    const overview = await (await page.request.get('/api/nba/overview?minutes=10080')).json();

    await page.goto('/nba');
    await page.locator('select.g-select').first().selectOption('10080');
    await expect(kpiValue(page, 'Total Flows')).toHaveText(overview.total_flows.toLocaleString(), { timeout: 15_000 });
    await expect(kpiValue(page, 'Beaconing')).toHaveText(String(overview.beaconing_detections), { timeout: 15_000 });
    await expect(kpiValue(page, 'Lateral Move')).toHaveText(String(overview.lateral_movement), { timeout: 15_000 });
    await expect(kpiValue(page, 'Exfiltration')).toHaveText(String(overview.data_exfiltration), { timeout: 15_000 });
    await expect(kpiValue(page, 'C2 Comms')).toHaveText(String(overview.c2_communications), { timeout: 15_000 });
  });
});

test.describe('NBA — regression guard: seeded anomaly types are no longer silently dropped', () => {
  test('Lateral Movement tab shows the real seeded lateral_movement anomaly, not zero', async ({ page }) => {
    const data = await (await page.request.get('/api/nba/lateral-movement')).json();
    expect(data.lateral_anomalies.length).toBeGreaterThan(0);

    await gotoTab(page, 'Lateral');
    await expect(page.getByText(/pass-the-hash/i).first()).toBeVisible({ timeout: 15_000 });
  });

  test('Overview KPI "Exfiltration" reflects the real seeded exfiltration anomaly, not zero', async ({ page }) => {
    const overview = await (await page.request.get('/api/nba/overview?minutes=10080')).json();
    expect(overview.data_exfiltration).toBeGreaterThan(0);
  });
});

test.describe('NBA — Threat Intel regression guard: no fabricated hits from unmatched domain IOCs', () => {
  test('threat-intel hits (if any) are real IP/domain matches, not a cross-join of every connection', async ({ page }) => {
    const res = await page.request.get('/api/nba/threat-intel?hours=100000000');
    expect(res.status()).toBe(200);
    const data = await res.json();
    // With no domain IOC actually matching a connection's sni/http_host, this
    // must not silently balloon to "one hit per connection per domain IOC".
    const flows = await (await page.request.get('/api/nba/flows?minutes=100000000&limit=500')).json();
    expect(data.threat_intel_hits.length).toBeLessThanOrEqual(flows.flows.length + 50);
  });
});

test.describe('NBA — Response Actions', () => {
  test('Isolate Endpoint dispatches a real pending-approval agent task', async ({ page }) => {
    const agents: Array<{ id: number }> = await (await page.request.get('/api/agents')).json();
    const target = agents[agents.length - 1];

    await gotoTab(page, 'Response');
    await page.getByRole('button', { name: 'Isolate Endpoint' }).click();
    await page.getByPlaceholder('Agent ID').fill(String(target.id));
    await page.getByPlaceholder('Reason…').fill('nba e2e test');
    await page.getByRole('button', { name: 'Execute' }).click();

    await expect(page.locator('div.fixed.bottom-5.right-5')).toContainText(/queued for agent .* pending approval/i, { timeout: 10_000 });
  });

  test('Kill Process requires both PID and Agent ID, and dispatches a real task', async ({ page }) => {
    const agents: Array<{ id: number }> = await (await page.request.get('/api/agents')).json();
    const target = agents[agents.length - 1];

    await gotoTab(page, 'Response');
    await page.getByRole('button', { name: 'Kill Process' }).click();
    const execBtn = page.getByRole('button', { name: 'Execute' });
    await expect(execBtn).toBeDisabled();

    await page.getByPlaceholder('PID').fill('4321');
    await expect(execBtn).toBeDisabled(); // agent id still missing
    await page.getByPlaceholder('Agent ID').fill(String(target.id));
    await expect(execBtn).toBeEnabled();

    await execBtn.click();
    await expect(page.locator('div.fixed.bottom-5.right-5')).toContainText(/kill_process queued for agent .* pending approval/i, { timeout: 10_000 });
  });

  test('Run SOAR Playbook requires a real playbook_id and actually executes it', async ({ page }) => {
    const playbooks: Array<{ id: number; name: string }> = await (await page.request.get('/api/playbooks')).json();
    expect(playbooks.length).toBeGreaterThan(0);
    const target = playbooks[0];

    await gotoTab(page, 'Response');
    await page.getByRole('button', { name: 'Run SOAR Playbook' }).click();
    await page.getByPlaceholder('Playbook ID').fill(String(target.id));
    await page.getByRole('button', { name: 'Execute' }).click();

    await expect(page.locator('div.fixed.bottom-5.right-5')).toContainText(target.name, { timeout: 10_000 });

    // Regression guard at the API level: a nonexistent playbook must be
    // rejected, not silently accepted as if it ran.
    const res = await page.request.post('/api/nba/response-action', {
      data: { action: 'run_playbook', playbook_id: 999999, reason: 'x' },
    });
    expect(res.status()).toBe(404);
  });

  test('Start PCAP surfaces the honest "not supported" error instead of a fake success', async ({ page }) => {
    await gotoTab(page, 'Response');
    await page.getByRole('button', { name: 'Start PCAP' }).click();
    await page.getByPlaceholder('Agent ID').fill('1');
    await page.getByRole('button', { name: 'Execute' }).click();

    await expect(page.locator('div.fixed.bottom-5.right-5')).toContainText(/packet capture is not supported/i, { timeout: 10_000 });
  });

  test('Push Firewall Rule creates a real firewall_rules row', async ({ page }) => {
    const testIP = '198.51.100.77';
    await gotoTab(page, 'Response');
    await page.getByRole('button', { name: 'Push Firewall Rule' }).click();
    await page.getByPlaceholder('Target IP').fill(testIP);
    await page.getByRole('button', { name: 'Execute' }).click();

    await expect(page.locator('div.fixed.bottom-5.right-5')).toContainText(/firewall rule created/i, { timeout: 10_000 });

    const rules = await (await page.request.get('/api/firewall/rules')).json();
    const list = Array.isArray(rules) ? rules : (rules.rules ?? []);
    expect(list.some((r: any) => r.source_ip === testIP)).toBeTruthy();
  });
});
