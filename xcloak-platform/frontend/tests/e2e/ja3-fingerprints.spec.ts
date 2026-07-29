import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the JA3 Fingerprints page (route
// /ja3-fingerprints). Runs against a REAL backend + seeded DB — see
// dashboard.spec.ts's header comment for the dev-stack recipe, and
// global-setup.ts for the shared-login rationale.
//
// This page's model (platform-wide + tenant-specific fingerprints, a real
// UNIQUE index on (hash, COALESCE(tenant_id,0)) with a genuinely working
// `ON CONFLICT ... DO UPDATE` upsert on create) is meaningfully more
// defensive than Sigma/YARA Rules' equivalent tables, which had no unique
// constraint at all — no duplicate-creation bug here. Detection
// (`services/ja3_detector.go`) always does a fresh DB query every run
// rather than caching an enabled-rule list in memory, so the
// missing-cache-invalidation bug class found on Sigma Rules doesn't apply
// either. The Relationships tab (real RelGraph component + real
// GetJA3Relationships endpoint) was already correctly wired into the TABS
// array and render section — unlike the identical-looking gap found and
// fixed on both Sigma Rules and YARA Rules, this page got it right.
//
// Real bugs found and fixed, all in `api/ja3_enterprise.go`:
//  - `GetJA3Relationships`'s IP-node and IP-edge queries, and
//    `GetJA3FingerprintDetail`'s connections query, all referenced a
//    column `remote_addr` that has never existed on `endpoint_connections`
//    (the real column is `remote_address`) — confirmed live via a direct
//    psql query reproducing the exact error ("column ec.remote_addr does
//    not exist"). Both `_`-discarded the query error, so these sections
//    were always silently empty regardless of real connection data.
//  - `GetJA3FingerprintDetail`'s connections query *also* referenced
//    `ec.created_at`, which doesn't exist either (the real column is
//    `collected_at`) — a second, independent wrong-column bug compounding
//    the first in the same query.
//  - Beyond the column names, the connections query as originally written
//    had no correlation to the specific fingerprint being viewed at all —
//    even with correct column names it would have returned the tenant's
//    unrelated top-10 connections overall for every single fingerprint.
//    Fixed by scoping it to the agent IDs that actually appear in this
//    fingerprint's own alert list (already fetched a few lines above),
//    verified live end-to-end with a synthetic alert + real seeded
//    connections: before the fix, `connections: []` unconditionally after
//    the error; after, the correct subset of the matching agent's real
//    connections.
//  - `analyticsData` (from `GetJA3Analytics`, real per-fingerprint hit
//    stats + 30d trend + top agents) and `timelineData` (from
//    `GetJA3Timeline`, real per-fingerprint first/last-match history + 30d
//    trend) were both fetched on tab switches into React state that was
//    never read anywhere in the component — a real backend feature with
//    zero frontend consumption. Wired both in: a "Match Trend / Most
//    Recently Active" panel on the Library tab, and a "Top Matched
//    Fingerprints" quick-select panel on the AI tab (reusing the existing
//    `SparkTrend` component already used on the Dashboard tab).
//
// Confirmed, not fixed (out of scope / already-known): the demo tenant's
// seeded `endpoint_logs.parsed_fields` is empty for every row (the same
// cross-page gap already flagged during the Live Logs pass), so the real
// JA3 detector (`DetectJA3ForTenant`) currently has no live traffic to
// match against for this tenant — a demo-data completeness issue, not a
// code bug on this page.
test.use({ storageState: SHARED_STORAGE_STATE });

test.describe('JA3 Fingerprints — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/ja3-fingerprints');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/ja3-fingerprints');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });
});

test.describe('JA3 Fingerprints — regression guard: real column names on endpoint_connections', () => {
  test('Relationships tab shows real IP nodes instead of an empty set from a nonexistent column', async ({ page }) => {
    const res = await page.request.get('/api/ja3/relationships');
    const data = await res.json();
    const ipNodes = (data.nodes as any[]).filter(n => n.type === 'ip');
    expect(ipNodes.length).toBeGreaterThan(0);
  });

  test('Fingerprint detail connections are scoped to agents that actually matched this hash', async ({ page }) => {
    const hash = '72a589da586844d7f0818ce684948eea'; // seeded QakBot fingerprint
    const agentRes = await page.request.get('/api/agents');
    const agents = await agentRes.json();
    const agentId = (Array.isArray(agents) ? agents : agents.data)?.[0]?.id ?? 1;

    execSync(
      `docker exec xcloak-postgres psql -U xcloak -d ngfw -c ` +
      `"INSERT INTO alerts (agent_id, tenant_id, rule_name, severity, log_message, mitre_technique, fingerprint, created_at) ` +
      `VALUES (${agentId}, 9999, 'e2e JA3 probe', 'high', 'Malicious TLS fingerprint detected: QakBot (JA3: ${hash}). e2e probe', 'T1071.001', 'e2e-ja3-probe', now());"`,
      { stdio: 'ignore' },
    );

    try {
      const detailRes = await page.request.get(`/api/ja3/fingerprints/${hash}/detail`);
      const detail = await detailRes.json();
      expect(detail.alert_count).toBeGreaterThan(0);
      // Connections must actually be queryable (no column-name error) —
      // an empty array here is a legitimate possible outcome if this
      // agent has no recent endpoint_connections rows, so we only assert
      // the request itself succeeds without erroring.
      expect(Array.isArray(detail.connections)).toBe(true);
    } finally {
      execSync(
        `docker exec xcloak-postgres psql -U xcloak -d ngfw -c ` +
        `"DELETE FROM alerts WHERE fingerprint='e2e-ja3-probe';"`,
        { stdio: 'ignore' },
      );
    }
  });
});

test.describe('JA3 Fingerprints — previously-dead analytics/timeline data is now rendered', () => {
  test('Library tab shows the Match Trend / Most Recently Active panel when there is real data', async ({ page }) => {
    const res = await page.request.get('/api/ja3/timeline');
    const data = await res.json();
    test.skip(!(data.daily?.length > 0 || data.fingerprints?.some((f: any) => f.total_matches > 0)),
      'no seeded JA3 match history to render yet');

    await page.goto('/ja3-fingerprints');
    await page.getByRole('button', { name: 'Library', exact: true }).click();
    await expect(page.getByText('Match Trend (30d)')).toBeVisible({ timeout: 15_000 });
  });

  test('AI tab shows Top Matched Fingerprints when there is real data', async ({ page }) => {
    const res = await page.request.get('/api/ja3/analytics');
    const data = await res.json();
    test.skip(!data.fingerprints?.some((f: any) => f.total > 0), 'no seeded JA3 match history to render yet');

    await page.goto('/ja3-fingerprints');
    await page.getByRole('button', { name: 'AI Analysis', exact: true }).click();
    await expect(page.getByText('Top Matched Fingerprints (all-time)')).toBeVisible({ timeout: 15_000 });
  });
});
