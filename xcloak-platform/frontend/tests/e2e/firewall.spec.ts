import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Firewall page (route /firewall) —
// blends the mature base rules engine (firewallAPI -> /api/firewall/*,
// backed by firewall_rules) with a newer "enterprise" layer (fweAPI ->
// /api/fwe/*, backed by fwe_* tables) for policies/zones/NAT/threats/
// connections/blocked/approvals/notifications/analytics/audit/ai/report —
// a deliberate blend confirmed via grep, not a wrong-API-used bug.
//
// Three tabs (Threat Protection, Live Connections, Blocked List) had zero
// real writer anywhere in the codebase for their backing fwe_* tables —
// confirmed via AskUserQuestion: bridged what has a real source elsewhere,
// left what doesn't as clearly-seeded reference data.
// - Live Connections (fwe_connections, no real writer) is now backed by
//   endpoint_connections instead — the real periodic connection-snapshot
//   table agents report via POST /api/agents/connections. Real src/dst/
//   protocol/state/process data; bytes_sent/bytes_recv/duration/zone_src/
//   zone_dst/rule_id had no real source anywhere and were dropped rather
//   than fabricated (removed from both the API response and the frontend
//   table columns). GetFWEDashboard's active_connections and
//   GetFWEAnalytics's by_protocol were also silently reading the dead
//   fwe_connections table — repointed to the same real source.
// - Blocked List (fwe_blocked) already had one real write path (manual
//   blocks via PostFWEBlock) — but ioc_firewall_blocks, a second, genuinely
//   real block source (real IOC-autoblock table, populated by
//   services.autoBlockIOC), was never surfaced here at all. GetFWEBlocked
//   now merges both.
// - Threat Protection (fwe_threats) has no real detection pipeline
//   anywhere in this codebase writing anything in that shape — left as
//   clearly-seeded reference data per the user's explicit decision, no
//   code change.
//
// GetFWEDashboard's total_bytes (SUM(bytes_sent+bytes_recv) from the now
// unreferenced fwe_connections) had no real source once bridged — dropped
// from the API response and the frontend's "Total Traffic" MetricCard
// (and the then-dead `bytes()` formatter) rather than left silently
// reporting a stale/fabricated number forever.
//
// PostFWEReport was a fully fabricated one-line stub ("%s report generated
// successfully", zero real numbers, no key_metrics) — rewritten with real
// computed metrics plus an LLM-grounded summary; the frontend's ReportsTab
// discarded the response entirely (just a toast) — now renders it.
//
// Frontend: deletePolicy, firewallAPI delete/update (Rules tab),
// markNotificationsRead had zero error handling.
//
// This page's own pre-existing seeder (seedFirewallEnterprise) had the
// exact same non-idempotency bug just found on Scheduled Tasks — its own
// CREATE TABLE statements assume a different schema (policy_id UNIQUE,
// zone_id, etc.) than what the real handler's createFWETables() actually
// creates (which wins, since it runs first), so every ON CONFLICT DO
// NOTHING had no real unique constraint to conflict on. Confirmed live:
// hundreds of duplicate rows had accumulated across every fwe_* table
// before a standard tenant-count guard was added and duplicates cleaned up.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = [
  'Dashboard', 'Policies', 'Firewall Rules', 'NAT', 'Zones', 'Threat Protection',
  'Live Connections', 'Blocked List', 'Analytics', 'Approvals', 'Notifications',
  'Audit Trail', 'Reports',
];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Firewall — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/firewall');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/firewall');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('Firewall — regression guard: seed data exists and is not duplicated', () => {
  test('policies/zones/NAT/threats/approvals/notifications/blocked show exactly the seeded counts', async ({ page }) => {
    const expected: Record<string, number> = {
      fwe_policies: 6, fwe_zones: 7, fwe_nat: 8, fwe_threats: 12,
      fwe_approvals: 6, fwe_notifications: 9, fwe_blocked: 10,
    };
    for (const [table, count] of Object.entries(expected)) {
      const real = Number(PSQL(`SELECT count(*) FROM ${table} WHERE tenant_id='9999';`));
      expect(real, `${table} row count`).toBe(count);
    }

    const policies = await page.request.get('/api/fwe/policies').then(r => r.json());
    expect(policies.length).toBe(6);
  });
});

test.describe('Firewall — regression guard: Live Connections is backed by real agent data', () => {
  test('GetFWEConnections returns real endpoint_connections data with real agent hostnames', async ({ page }) => {
    const conns = await page.request.get('/api/fwe/connections').then(r => r.json());
    const realCount = Number(PSQL(`SELECT count(*) FROM endpoint_connections WHERE tenant_id='9999';`));
    expect(realCount).toBeGreaterThan(0);
    expect(conns.length).toBeGreaterThan(0);

    const realHostnames = new Set(JSON.parse(PSQL(`SELECT json_agg(DISTINCT hostname) FROM agents WHERE tenant_id=9999;`) || '[]'));
    for (const c of conns.slice(0, 20)) {
      expect(realHostnames.has(c.agent_hostname), `unexpected agent_hostname ${c.agent_hostname}`).toBeTruthy();
      expect(c).not.toHaveProperty('bytes_sent');
      expect(c).not.toHaveProperty('zone_src');
    }
  });

  test('dashboard active_connections and analytics by_protocol reflect the same real source', async ({ page }) => {
    const dash = await page.request.get('/api/fwe/dashboard').then(r => r.json());
    const realActive = Number(PSQL(`SELECT count(*) FROM endpoint_connections WHERE tenant_id='9999' AND state='ESTABLISHED';`));
    expect(dash.active_connections).toBe(realActive);
    expect(dash).not.toHaveProperty('total_bytes');

    const analytics = await page.request.get('/api/fwe/analytics').then(r => r.json());
    const realTcp = Number(PSQL(`SELECT count(*) FROM endpoint_connections WHERE tenant_id='9999' AND protocol='tcp';`));
    const tcpStat = analytics.by_protocol.find((p: any) => p.protocol === 'tcp');
    expect(tcpStat?.count).toBe(realTcp);
  });
});

test.describe('Firewall — regression guard: Blocked List merges real IOC auto-blocks', () => {
  test('a real ioc_firewall_blocks row appears alongside manual fwe_blocked entries', async ({ page }) => {
    PSQL(`DELETE FROM ioc_firewall_blocks WHERE indicator='e2e-block-test-ip'; DELETE FROM iocs WHERE indicator='e2e-block-test-ip';`);
    PSQL(`INSERT INTO iocs (indicator, type, severity, tenant_id) VALUES ('e2e-block-test-ip', 'ip', 'high', 9999);`);
    const iocID = Number(PSQL(`SELECT id FROM iocs WHERE indicator='e2e-block-test-ip' AND tenant_id=9999;`));
    PSQL(`INSERT INTO ioc_firewall_blocks (ioc_id, indicator, agent_id, tenant_id) VALUES (${iocID}, 'e2e-block-test-ip', 1, 9999);`);

    const blocked = await page.request.get('/api/fwe/blocked').then(r => r.json());
    const match = blocked.find((b: any) => b.value === 'e2e-block-test-ip');
    expect(match).toBeTruthy();
    expect(match.blocked_by).toBe('ids-auto');
    expect(match.reason).toContain('IOC match');

    PSQL(`DELETE FROM ioc_firewall_blocks WHERE ioc_id=${iocID}; DELETE FROM iocs WHERE id=${iocID};`);
  });
});

test.describe('Firewall — regression guard: report has real numbers, not a canned stub', () => {
  test('PostFWEReport returns real key_metrics, not the old one-line placeholder', async ({ page }) => {
    const res = await page.request.post('/api/fwe/report', { data: { report_type: 'threat_blocking' } });
    expect(res.ok()).toBeTruthy();
    const report = await res.json();

    const realThreats = Number(PSQL(`SELECT count(*) FROM fwe_threats WHERE tenant_id='9999';`));
    expect(report.key_metrics).toBeTruthy();
    expect(report.key_metrics.total_threats).toBe(realThreats);
    expect(report.executive_summary).not.toContain('report generated successfully');
  });
});
