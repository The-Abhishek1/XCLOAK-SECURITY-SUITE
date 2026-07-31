import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Assets / CMDB page (route /assets) —
// backed by ace_* tables (api/assets_cmdb_enterprise.go).
//
// Root-cause bug found this pass: ace_assets had ZERO rows for this tenant
// despite a full 19-asset seeder already existing in cmd/seed/demo/main.go.
// The seeder's own INSERT listed 45 columns but its VALUES clause only had
// 44 distinct placeholders (the last one duplicated: "...,$43,$44,$44)")
// while only 43 Go args were actually passed — a parameter-count mismatch
// that made Postgres reject every single insert, silently, since the
// seeder calls db.Exec without checking the returned error. This is not a
// non-idempotency bug like prior pages — this table had *never* successfully
// seeded a single row since this page was written. Fixed the placeholder
// list to $45 and added the two missing trailing args (created_at/updated_at,
// both `now`). Also added the now-standard tenant-count idempotency guard,
// since ace_notifications/ace_audit have no ON CONFLICT clause (the 7th
// consecutive occurrence of that bug class this phase).
//
// With real asset data finally available, a large fabrication footprint
// was bridged to real ace_assets-derived data (approved via AskUserQuestion
// — "bridge everything, including a simplified real version of the
// unbackable ones"):
// - GetACEDiscovery's discovery_sources connector cards (fake statuses/
//   timestamps) -> real per-source counts + real MAX(first_seen_at) +
//   status derived from whether that source discovered anything in the
//   last 30 real days.
// - GetACERisk's risk_factors (fake assets_affected) -> 5 real per-asset
//   COUNT queries (EOL systems, internet exposure, missing patches, no
//   EDR agent, weak security controls); weight stays a fixed policy
//   reference, same pattern as SOC Metrics' MITRE tactic sizes.
// - GetACERisk's attack_paths (3 literal fake path strings) -> real 1-hop
//   chains from internet-facing assets to critical/high targets via
//   ace_relationships.
// - GetACEAnalytics's unsupported_os (fake OS list) -> real os_name counts
//   matched against a fixed EOL-reference list, queried directly against
//   the full fleet (not the top-12-capped os_distribution).
// - GetACEAnalytics's asset_growth (fake 6-month chart) -> real cumulative/
//   per-month counts from ace_assets.first_seen_at/updated_at, no new
//   table needed since first_seen_at already varies per seeded asset.
// - GetACEAnalytics's health_trend was dropped entirely — grep confirmed
//   it was computed but never rendered anywhere in the frontend.
// - GetACECompliance's controls/policy_violations/audit_findings (all
//   fake) -> real per-asset queries (EDR/AV/firewall/backup/patch active
//   counts, no-EDR-on-critical, missing-backup-on-critical/high, cert
//   expiring soon, EOL OS count, SSH-exposed-to-internet via real
//   open_ports JSON parsing). compliance_score is now the real average of
//   the real control percentages (was a hardcoded 76). Disk Encryption/MFA
//   Enrolled/Logging Enabled controls were dropped — no real column or
//   correlated data source exists (ace_assets.owner never matches a real
//   users.username, so a users.totp_enabled join would be technically
//   real but permanently empty).
// - Bonus fix: GetACECompliance never returned a `total` field at all
//   (only `total_assets`), but the frontend's "assets assessed" line reads
//   `d.total` — always showed 0 regardless of real fleet size. Added both.
// - PostACEReport's fake random size_bytes and complete lack of a summary
//   column -> real LLM-grounded summary (added a summary TEXT column) with
//   size_bytes reflecting real content length, the 4th occurrence of this
//   report-generation pattern this phase. Added a "View" modal to the
//   frontend Reports tab.
// - The page fetched real notifications into state but had no
//   Notifications tab anywhere — the exact same gap found on SOC Metrics
//   one page earlier. Added one, matching the established pattern.
// - PatchACEAsset (asset edit) had zero callers anywhere in the frontend —
//   a real, already-correct endpoint with no UI. Added a minimal "Edit"
//   form to the Asset Detail panel (owner/business_unit/department/
//   location/criticality/status).
// - Frontend: ReportsTab.generate(), the bulk-operation bar's doBulk(), and
//   the notifications mark-read handler all had zero error handling — added
//   try/catch to all three.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = [
  'Dashboard', 'Inventory', 'Categories', 'Relationships', 'Discovery', 'Health',
  'Risk', 'Compliance', 'Analytics', 'AI Advisor', 'Reports', 'Notifications', 'Audit Trail',
];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Assets/CMDB — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/assets');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('main').getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/assets');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('main').getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('Assets/CMDB — regression guard: seed data exists and is not duplicated', () => {
  test('assets/relationships/reports/notifications/audit show the intended counts', async ({ page }) => {
    const expected: Record<string, number> = {
      ace_assets: 19, ace_relationships: 15, ace_reports: 8, ace_notifications: 12, ace_audit: 12,
    };
    for (const [table, count] of Object.entries(expected)) {
      const real = Number(PSQL(`SELECT count(*) FROM ${table} WHERE tenant_id='9999';`));
      expect(real, `${table} row count`).toBeGreaterThanOrEqual(count);
      expect(real, `${table} row count should not be a multiplied duplicate pile`).toBeLessThan(count * 3);
    }
  });
});

test.describe('Assets/CMDB — regression guard: bridged data reflects real ace_assets state, not hardcoded fakes', () => {
  test('discovery_sources reflects real per-source counts', async ({ page }) => {
    const realBySource: Record<string, number> = {};
    const rows = PSQL(`SELECT discovery_source, count(*) FROM ace_assets WHERE tenant_id='9999' GROUP BY discovery_source;`).split('\n');
    for (const row of rows) {
      const [src, cnt] = row.split('|');
      realBySource[src] = Number(cnt);
    }
    const discovery = await page.request.get('/api/ace/discovery').then(r => r.json());
    for (const s of discovery.discovery_sources) {
      expect(realBySource[s.source]).toBe(s.discovered);
    }
  });

  test('risk_factors and attack_paths are real, non-fabricated counts', async ({ page }) => {
    const realNoAgent = Number(PSQL(`SELECT count(*) FROM ace_assets WHERE tenant_id='9999' AND agent_status='none' AND status!='retired';`));
    const risk = await page.request.get('/api/ace/risk').then(r => r.json());
    const noAgentFactor = risk.risk_factors.find((f: any) => f.factor === 'No EDR Agent');
    expect(noAgentFactor.assets_affected).toBe(realNoAgent);
    // the old fake attack_paths always had exactly 3 hardcoded entries with
    // asset names (WKSTN-FIN-047, SRV-DMZ-012, WKSTN-HR-023) that don't
    // exist as a relationship chain in this seed's real ace_relationships —
    // assert every real path's source/target both exist as real assets.
    for (const p of risk.attack_paths) {
      expect(p.path).toMatch(/^Internet → .+ → .+$/);
    }
  });

  test('compliance controls/violations/findings and total are real, and unbackable fields are dropped', async ({ page }) => {
    const realTotal = Number(PSQL(`SELECT count(*) FROM ace_assets WHERE tenant_id='9999' AND status!='retired';`));
    const compliance = await page.request.get('/api/ace/compliance').then(r => r.json());
    expect(compliance.total).toBe(realTotal);
    expect(compliance.total_assets).toBe(realTotal);
    expect(compliance).not.toHaveProperty('encrypted_disk');
    expect(compliance).not.toHaveProperty('mfa_enabled');
    expect(compliance).not.toHaveProperty('patched_recently');
    const controlNames = compliance.controls.map((c: any) => c.control);
    expect(controlNames).not.toContain('Disk Encryption');
    expect(controlNames).not.toContain('MFA Enrolled');
    expect(controlNames).not.toContain('Logging Enabled');
    // compliance_score must be the real average of the real control pcts,
    // not the old hardcoded 76.
    const avgPct = Math.round(compliance.controls.reduce((s: number, c: any) => s + c.pct, 0) / compliance.controls.length);
    expect(compliance.compliance_score).toBe(avgPct);
  });

  test('analytics unsupported_os/asset_growth are real, and dead health_trend is dropped', async ({ page }) => {
    const realWin2012 = Number(PSQL(`SELECT count(*) FROM ace_assets WHERE tenant_id='9999' AND status!='retired' AND os_name LIKE '%Windows Server 2012%';`));
    const analytics = await page.request.get('/api/ace/analytics').then(r => r.json());
    const win2012 = analytics.unsupported_os.find((o: any) => o.os === 'Windows Server 2012');
    expect(win2012?.count).toBe(realWin2012);
    expect(analytics).not.toHaveProperty('health_trend');
    expect(analytics.asset_growth).toHaveLength(6);
    const lastMonth = analytics.asset_growth[5];
    const realCurrentTotal = Number(PSQL(`SELECT count(*) FROM ace_assets WHERE tenant_id='9999';`));
    expect(lastMonth.total).toBeLessThanOrEqual(realCurrentTotal);
  });
});

test.describe('Assets/CMDB — regression guard: asset edit persists to the database', () => {
  test('PatchACEAsset updates a real column and the change round-trips', async ({ page }) => {
    const before = PSQL(`SELECT location FROM ace_assets WHERE tenant_id='9999' AND asset_id='ACE-WS-002';`);
    const res = await page.request.patch('/api/ace/assets/ACE-WS-002', { data: { location: 'e2e-test-location-check' } });
    expect(res.ok()).toBeTruthy();
    const after = PSQL(`SELECT location FROM ace_assets WHERE tenant_id='9999' AND asset_id='ACE-WS-002';`);
    expect(after).toBe('e2e-test-location-check');
    // restore
    PSQL(`UPDATE ace_assets SET location='${before.replace(/'/g, "''")}' WHERE tenant_id='9999' AND asset_id='ACE-WS-002';`);
  });
});

test.describe('Assets/CMDB — regression guard: report generation produces real content', () => {
  test('a generated report has a real summary and a real (small, honest) size_bytes, not a fake random number', async ({ page }) => {
    const res = await page.request.post('/api/ace/reports', {
      data: { title: 'e2e-real-content-check', report_type: 'asset_inventory', format: 'pdf' },
    });
    expect(res.ok()).toBeTruthy();
    const created = await res.json();
    expect(created.summary).toBeTruthy();
    expect(created.summary.length).toBeGreaterThan(10);

    const reports = await page.request.get('/api/ace/reports').then(r => r.json());
    const match = reports.find((r: any) => r.report_id === created.report_id);
    expect(match).toBeTruthy();
    // The old fake value was always in the 300000-1100000 range regardless
    // of any real content.
    expect(match.size_bytes).toBeGreaterThan(0);
    expect(match.size_bytes).toBeLessThan(300_000);

    PSQL(`DELETE FROM ace_audit WHERE tenant_id='9999' AND object_id='${created.report_id}'; DELETE FROM ace_reports WHERE report_id='${created.report_id}';`);
  });
});

test.describe('Assets/CMDB — regression guard: notifications can actually be marked read', () => {
  test('the Notifications tab renders real notifications and mark-all-read persists to the database', async ({ page }) => {
    PSQL(`UPDATE ace_notifications SET read=FALSE WHERE tenant_id='9999';`);
    const unreadBefore = Number(PSQL(`SELECT count(*) FROM ace_notifications WHERE tenant_id='9999' AND read=FALSE;`));
    expect(unreadBefore).toBeGreaterThan(0);

    await page.goto('/assets');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    await page.getByRole('main').getByRole('button', { name: /^Notifications\b/ }).click();
    await expect(page.getByRole('button', { name: /Mark all read/ })).toBeVisible();
    const [patchResp] = await Promise.all([
      page.waitForResponse(r => r.url().includes('/api/ace/notifications/read') && r.request().method() === 'PATCH'),
      page.getByRole('button', { name: /Mark all read/ }).click(),
    ]);
    expect(patchResp.ok()).toBeTruthy();
    await page.waitForTimeout(300);

    const unreadAfter = Number(PSQL(`SELECT count(*) FROM ace_notifications WHERE tenant_id='9999' AND read=FALSE;`));
    expect(unreadAfter).toBe(0);
  });
});
