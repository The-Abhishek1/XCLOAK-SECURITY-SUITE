import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Tenants page (route /platform,
// platform-admin only). Deferred out of the 54-page sidebar count along with
// Settings. The real findings here:
//
// - CRITICAL AUTHZ GAP: every /api/tne/* route (dashboard, tenant CRUD,
//   modules, resources, health, usage, billing, AI, reports, audit — the
//   entire page) was RequireAuth()-only, no role check at all, unlike the
//   real /api/platform/* tenant-CRUD system which was correctly gated with
//   RequirePlatformAdmin(). Any authenticated user of any role at any real
//   tenant could view/edit/suspend/create platform-wide tenant records and
//   read the platform audit log. Added middleware.RequirePlatformAdmin() to
//   every /api/tne/* route — verified live with a real non-admin test user
//   (403 both before and after the fix would have differed; confirmed 403
//   post-fix on both /api/tne/dashboard and /api/platform/tenants).
// - ARCHITECTURAL GAP: the page's entire Tenant Directory/Config/Modules/
//   Resources/Billing UI runs on a `tne_tenants` shadow table with zero
//   relationship to the real `tenants` table (the one with actual
//   FK-cascade isolation used by 286 tenant_id columns across the app).
//   Nothing else in the backend reads tne_modules/tne_resources to gate any
//   real feature — it's a self-contained seeded demo console. A real,
//   secure tenant CRUD API (tenant_admin.go, RequirePlatformAdmin-gated,
//   real invite flow, real cascade delete) already existed but the frontend
//   never called it beyond the SaaS/license mode toggles. Per user decision
//   (hybrid): added a "Live Tenants" section wired to the real API
//   alongside the existing demo console, which is now clearly labeled as
//   reference/seeded data with a banner linking to the live section.
// - DATA-INTEGRITY BUG (live on this deployment, found while testing):
//   tne_tenants had 0 rows while tne_usage (650 rows) and tne_health (3900
//   rows) still held 10 tenant_refs' worth of orphaned data — the parent
//   rows were gone but nothing referenced them, since tenant_ref had no FK
//   anywhere. Root cause once restored: tne_usage/tne_health had no unique
//   constraint on the columns their seed-script ON CONFLICT DO NOTHING
//   clauses target (tenant_ref+period, tenant_ref+check_type) — the same
//   disease fixed for log_sources in migration 000071 — so every reseed
//   silently duplicated rows instead of no-opping (up to 128 dupes for a
//   single tenant+period). Fixed in InitTNETables()'s new fixTNESchema():
//   dedupe, add the missing unique indexes, and add FK CASCADE from every
//   tne_* child table back to tne_tenants(tenant_ref) so a lost parent row
//   can no longer orphan its children silently. Runs idempotently on every
//   startup (verified live: 650→70 usage rows, 3900→60 health rows).
// - Dashboard/health/analytics/billing handlers mixed real DB aggregates
//   with hardcoded fake numbers (total_assets, total_storage_used_tb,
//   platform_api_rps, monthly_revenue_usd, renewal_value_usd, a fully
//   hardcoded "platform" health block, a monthly_trend built from a fixed
//   arithmetic formula unrelated to any stored data, and per-tenant billing
//   fields — "Credit Card ****4242" / "billing@corp.example.com" —
//   identical for every tenant regardless of who they are). Rewired to
//   compute honestly from tne_usage/tne_resources/tne_billing/the real
//   `agents` table, or dropped where no real signal exists (availability,
//   log ingestion lag, API latency have no probe on this deployment).
// - The Data Isolation tab asserted a specific, unverified monitoring claim
//   ("No cross-tenant leakage detected in last 30 days") plus several
//   outright false architecture claims (RLS enabled on "every query" — only
//   6 of 286 tenant_id tables actually have RLS; per-tenant MinIO storage
//   prefix, per-tenant S3 backup buckets, HSM-backed KMS encryption, VPC
//   tagging, and region-pinned data residency — none of which exist
//   anywhere in this codebase). Rewritten to describe only what's actually
//   implemented (app-level tenant_id scoping, the real RLS table count, the
//   real shared Elasticsearch index, the real single-database pg_dump
//   backup with no per-tenant isolation).
test.use({ storageState: SHARED_STORAGE_STATE });

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

const API_BASE = 'http://localhost:8080/api';

async function extractTokenCookie(res: any): Promise<string> {
  const headers: { name: string; value: string }[] = await res.headersArray();
  const setCookies = headers.filter(h => h.name.toLowerCase() === 'set-cookie');
  const tokenHeader = setCookies.find(h => h.value.startsWith('token='));
  if (!tokenHeader) throw new Error('no token cookie in login response');
  return tokenHeader.value.split(';')[0];
}

async function createRealTestUser(page: any, username: string, password: string): Promise<void> {
  const res = await page.request.post(`${API_BASE}/users/invite`, {
    data: { username, email: `${username}@example.com`, role: 'analyst' },
  });
  expect(res.ok()).toBeTruthy();
  const token = PSQL(`SELECT password_reset_token FROM users WHERE username='${username}';`);
  const resetRes = await page.request.post(`${API_BASE}/auth/reset-password`, {
    data: { token, new_password: password },
  });
  expect(resetRes.ok()).toBeTruthy();
}

function deleteTestUser(username: string) {
  PSQL(`DELETE FROM sessions WHERE username='${username}';`);
  PSQL(`DELETE FROM users WHERE username='${username}';`);
}

test.describe('Tenants — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/platform');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });

    const TOP_TABS = ['Dashboard', 'Tenants', 'Licenses', 'Usage', 'Reports'];
    const SUB_TABS: Record<string, string[]> = {
      Tenants: ['Tenant Directory', 'Tenant Configuration', 'Live Tenants', 'Data Isolation', 'Deployment Mode'],
      Licenses: ['Users & RBAC', 'Module Management'],
      Usage: ['Resource Allocation', 'Subscription & Licensing', 'Billing'],
      Reports: ['Usage Analytics', 'Tenant Health', 'AI Assistant', 'Audit Trail'],
    };
    for (const top of TOP_TABS) {
      await page.getByRole('main').getByRole('button', { name: new RegExp(`^${top}\\b`) }).first().click();
      await page.waitForTimeout(200);
      for (const sub of SUB_TABS[top] ?? []) {
        await page.getByRole('main').getByRole('button', { name: new RegExp(`^${sub}\\b`) }).click();
        await page.waitForTimeout(200);
      }
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('Live Tenants section renders this deployment\'s real tenants', async ({ page }) => {
    await page.goto('/platform');
    await page.getByRole('main').getByRole('button', { name: /^Tenants\b/ }).first().click();
    await page.getByRole('main').getByRole('button', { name: /^Live Tenants\b/ }).click();
    await expect(page.getByRole('table').getByText('Default', { exact: true })).toBeVisible();
    await expect(page.getByRole('table').getByText('Demo Corp Security', { exact: true })).toBeVisible();
  });
});

test.describe('Tenants — regression guard: /api/tne/* and /api/platform/tenants require platform admin', () => {
  test('a regular authenticated user is rejected with 403, not served platform-wide tenant data', async ({ page, request }) => {
    const username = 'e2e-tne-authz-guard';
    await createRealTestUser(page, username, 'GuardTest1!Pw');

    const loginRes = await request.post(`${API_BASE}/auth/login`, {
      data: { username, password: 'GuardTest1!Pw' },
    });
    expect(loginRes.ok()).toBeTruthy();
    const tokenCookie = await extractTokenCookie(loginRes);

    const tneRes = await request.get(`${API_BASE}/tne/dashboard`, { headers: { Cookie: tokenCookie } });
    expect(tneRes.status()).toBe(403);

    const platformRes = await request.get(`${API_BASE}/platform/tenants`, { headers: { Cookie: tokenCookie } });
    expect(platformRes.status()).toBe(403);

    const auditRes = await request.get(`${API_BASE}/tne/audit`, { headers: { Cookie: tokenCookie } });
    expect(auditRes.status()).toBe(403);

    deleteTestUser(username);
  });
});

test.describe('Tenants — regression guard: dashboard numbers are real, not fabricated', () => {
  test('total_tenants matches a real COUNT(*), and known-fake fields are gone', async ({ request }) => {
    const res = await request.get(`${API_BASE}/tne/dashboard`);
    expect(res.ok()).toBeTruthy();
    const body = await res.json();

    const realTotal = Number(PSQL(`SELECT COUNT(*) FROM tne_tenants;`));
    expect(body.total_tenants).toBe(realTotal);

    // These were hardcoded literals identical on every request, unrelated to
    // any stored data — removed entirely rather than left as decoys.
    expect(body).not.toHaveProperty('total_assets');
    expect(body).not.toHaveProperty('total_storage_used_tb');
    expect(body).not.toHaveProperty('platform_api_rps');
    expect(body).not.toHaveProperty('renewal_value_usd');

    const healthRes = await request.get(`${API_BASE}/tne/health`);
    const healthBody = await healthRes.json();
    // availability/log_ingestion/api_health had no real probe backing them.
    expect(healthBody.platform).not.toHaveProperty('availability');
    expect(healthBody.platform).not.toHaveProperty('log_ingestion');
    expect(healthBody.platform).not.toHaveProperty('api_health');
    expect(healthBody.platform.database_health).toBe('healthy');
  });
});

test.describe('Tenants — regression guard: tne_usage/tne_health can no longer silently duplicate', () => {
  test('no duplicate (tenant_ref, period) or (tenant_ref, check_type) rows exist', async ({}) => {
    const dupUsage = Number(PSQL(
      `SELECT COUNT(*) FROM (SELECT tenant_ref, period FROM tne_usage GROUP BY tenant_ref, period HAVING COUNT(*) > 1) d;`
    ));
    expect(dupUsage).toBe(0);

    const dupHealth = Number(PSQL(
      `SELECT COUNT(*) FROM (SELECT tenant_ref, check_type FROM tne_health GROUP BY tenant_ref, check_type HAVING COUNT(*) > 1) d;`
    ));
    expect(dupHealth).toBe(0);

    // The FK cascade added alongside the unique indexes.
    const fkCount = Number(PSQL(
      `SELECT COUNT(*) FROM pg_constraint WHERE conname IN (
        'tne_modules_tenant_ref_fkey','tne_resources_tenant_ref_fkey',
        'tne_health_tenant_ref_fkey','tne_usage_tenant_ref_fkey','tne_billing_tenant_ref_fkey');`
    ));
    expect(fkCount).toBe(5);
  });
});

test.describe('Tenants — regression guard: Live Tenants CRUD hits the real tenants table', () => {
  test('create, toggle, add/remove a domain, and delete a real tenant end-to-end', async ({ request }) => {
    const slug = `e2e-live-tenant-${Date.now()}`;

    const createRes = await request.post(`${API_BASE}/platform/tenants`, {
      data: { name: 'E2E Live Tenant', slug, admin_username: `${slug}-admin`, admin_email: `${slug}@example.com` },
    });
    expect(createRes.ok()).toBeTruthy();

    const id = Number(PSQL(`SELECT id FROM tenants WHERE slug='${slug}';`));
    expect(id).toBeGreaterThan(0);

    const toggleRes = await request.patch(`${API_BASE}/platform/tenants/${id}/toggle`, { data: { is_active: false } });
    expect(toggleRes.ok()).toBeTruthy();
    expect(PSQL(`SELECT is_active FROM tenants WHERE id=${id};`)).toBe('f');

    const addDomainRes = await request.post(`${API_BASE}/platform/tenants/${id}/domains`, { data: { domain: `${slug}.example.com` } });
    expect(addDomainRes.ok()).toBeTruthy();
    const domainId = Number(PSQL(`SELECT id FROM tenant_domains WHERE tenant_id=${id};`));
    expect(domainId).toBeGreaterThan(0);

    const removeDomainRes = await request.delete(`${API_BASE}/platform/tenants/${id}/domains/${domainId}`);
    expect(removeDomainRes.ok()).toBeTruthy();
    expect(PSQL(`SELECT COUNT(*) FROM tenant_domains WHERE tenant_id=${id};`)).toBe('0');

    const deleteRes = await request.delete(`${API_BASE}/platform/tenants/${id}`);
    expect(deleteRes.ok()).toBeTruthy();
    expect(PSQL(`SELECT COUNT(*) FROM tenants WHERE id=${id};`)).toBe('0');
  });
});
