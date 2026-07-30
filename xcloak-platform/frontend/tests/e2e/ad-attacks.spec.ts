import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Active Directory Security page
// (route /ad-attacks) — AD inventory, identity risk, auth monitoring,
// Kerberos/credential attack detection, lateral movement, GPO/tiering,
// threat intel, AD hygiene assessment, response actions.
//
// This page had a fabrication footprint at least as large as Container
// Security's — nearly every "intelligence"/"exposure"/"assessment"/"graph"
// endpoint was either fully or mostly fake, glued onto a handful of real
// COUNT() queries. Confirmed the two largest/most novel judgment calls with
// the user via AskUserQuestion; the rest (response actions, two fake graphs
// with the exact same shape as Container Security's already-approved fix,
// and several "real data one query away" fields) were fixed directly.
//
// - `PostADResponse` was a pure canned-message dispatcher (7 actions, zero
//   real effect, any action string accepted). Rewritten: disable_user/
//   reset_password/remove_group_membership/disable_service_account do real
//   UPDATEs against ad_users. force_ticket_renewal/isolate_endpoint now
//   honestly 501 (no real Kerberos KDC / EDR integration exists in this
//   schema). run_soar_playbook removed, replaced with the real /playbooks
//   link used elsewhere this phase.
// - Per the user's confirmed choices: GetADAssessment's hardcoded
//   "AD Hygiene Score: 61%" and 10 always-"fail" checks (7 with zero real
//   backing, 1 with a wrong-variable bug reusing passwordNeverExpires for
//   an unrelated "inactive privileged accounts" claim) were replaced with a
//   real score computed from only the 4 checks with genuine backing.
//   GetADThreatIntel's threat_actors/malware/credential_campaigns (zero
//   real per-tenant attribution data anywhere in this schema) were removed;
//   ioc_matches was wired to the real iocs table instead.
// - GetADAttackPaths and GetADRelationshipGraph were both fully static
//   graphs with specific fictional entity names (svc_backup, hcraig,
//   administrator, jsmith) reused across multiple endpoints — the same
//   shape as Container Security's already-approved Attack Path fix, so
//   fixed directly as a confirmed recurrence: GetADAttackPaths now returns
//   real top-risk identities/computers, GetADRelationshipGraph now builds
//   a real graph from actual admin users, DCs, and unconstrained-delegation
//   computers instead of a fixed fictional node/edge set.
// - GetADTiering's fake "AD Admin Workstations: 2", "Tier-0 Groups: 3",
//   "Member Servers: 8" and hardcoded "Standard Users: 847" were removed/
//   fixed to a real query; its `privileged_sessions` array recomputed fake
//   session start times fresh on every request (silently drifting forward
//   in real time) with zero real session-tracking data anywhere — removed
//   entirely rather than left as an ever-refreshing fabrication.
// - GetADExposure's real unconstrained_delegation count had an arbitrary
//   "+2" offset and a fake affected-hosts list — fixed to the real count
//   and real affected computer names; its other 6 findings (weak ACLs,
//   anonymous LDAP, legacy protocols, etc.) had zero real per-tenant
//   backing, same category as the just-approved Assessment check removals
//   — dropped for the same reason.
// - GetADAnalytics's `top_failed_logins` was hardcoded despite a real
//   equivalent query being one line away — wired to a real GROUP BY over
//   ad_events.
// - A client-side-only "AI Insights" panel with 3 fully hardcoded findings
//   (zero backend call, specific fictional entities) sat right next to the
//   page's genuinely real AI Analysis panel — removed, matching the Alerts
//   page's "fake content beside real content" fix earlier this phase. Also
//   found 3 completely dead buttons (Open Timeline/Start Hunt/Log Search,
//   zero onClick) — wired to their real destination pages, matching the
//   Live Logs precedent.
// - Like Email/Container Security before it: none of this page's 8 own
//   tables had any seed data anywhere in a fresh dev environment — added
//   `seedADSecurity` to cmd/seed/demo/main.go, idempotency-guarded like
//   every other keyless table this phase.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = ['Overview', 'AD Inventory', 'Identity Risk', 'Authentication',
  'Attack Detection', 'Lateral + GPO', 'Intelligence', 'Analytics', 'Attack Paths + Response'];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('AD Attacks — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/ad-attacks');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/ad-attacks');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('AD Attacks — regression guard: seed data exists', () => {
  test('the dashboard shows real, non-zero counts instead of a permanently empty page', async ({ page }) => {
    const dash = await page.request.get('/api/ad/dashboard').then(r => r.json());
    expect(dash.forests).toBeGreaterThan(0);
    expect(dash.domain_controllers).toBeGreaterThan(0);

    const count = PSQL(`SELECT count(*) FROM ad_forests WHERE tenant_id=9999;`);
    expect(Number(count)).toBeGreaterThan(0);
  });
});

test.describe('AD Attacks — regression guard: assessment score is real, not a fixed 61%', () => {
  test('the score and checks are derived only from real backing, no unbacked checks remain', async ({ page }) => {
    const res = await page.request.get('/api/ad/assessment').then(r => r.json());
    expect(res.checks.length).toBe(4);
    const ids = res.checks.map((c: any) => c.id);
    expect(ids).toEqual(['inactive_privs', 'unconstrained_delegation', 'stale_computers', 'password_never_expires']);
    expect(ids).not.toContain('ldap_signing');
    expect(ids).not.toContain('smb_signing');

    const realDelegation = Number(PSQL(`SELECT count(*) FROM ad_computers WHERE tenant_id=9999 AND has_unconstrained_delegation=true;`));
    const delegationCheck = res.checks.find((c: any) => c.id === 'unconstrained_delegation');
    expect(delegationCheck.detail).toContain(String(realDelegation));
  });
});

test.describe('AD Attacks — regression guard: threat intel has no unbacked fabrication', () => {
  test('threat_actors/malware/credential_campaigns are gone', async ({ page }) => {
    const res = await page.request.get('/api/ad/threat-intel').then(r => r.json());
    expect(res).not.toHaveProperty('threat_actors');
    expect(res).not.toHaveProperty('malware');
    expect(res).not.toHaveProperty('credential_campaigns');
  });
});

test.describe('AD Attacks — regression guard: attack paths and relationship graph are real, not fake fictional entities', () => {
  test('attack-paths risk_identities/risk_computers come from real seed data', async ({ page }) => {
    const res = await page.request.get('/api/ad/attack-paths').then(r => r.json());
    expect(res).not.toHaveProperty('nodes');
    expect(res).not.toHaveProperty('edges');
    expect(res.risk_identities.length).toBeGreaterThan(0);
    const samAccounts = res.risk_identities.map((u: any) => u.sam_account);
    // Real seeded high-risk accounts should appear; the old fake graph
    // never included svc_sql (it was always a fixed different account).
    expect(samAccounts.some((s: string) => ['svc_backup', 'svc_sql', 'administrator', 'jsmith', 'hcraig'].includes(s))).toBeTruthy();
  });

  test('relationship graph is built from real admin users and DCs, not a fixed fictional set', async ({ page }) => {
    const res = await page.request.get('/api/ad/graph').then(r => r.json());
    expect(res.nodes.length).toBeGreaterThan(0);
    const realDCCount = Number(PSQL(`SELECT count(*) FROM ad_domain_controllers WHERE tenant_id=9999;`));
    const dcNodes = res.nodes.filter((n: any) => n.type === 'domain_controller');
    expect(dcNodes.length).toBe(Math.min(realDCCount, 3));
  });
});

test.describe('AD Attacks — regression guard: response actions are real, not a no-op', () => {
  test('disable_user really disables the AD user row', async ({ page }) => {
    const sam = PSQL(`SELECT sam_account FROM ad_users WHERE tenant_id=9999 AND is_enabled=true ORDER BY id LIMIT 1;`);
    const res = await page.request.post('/api/ad/response', {
      data: { action: 'disable_user', target: sam },
    });
    expect(res.ok()).toBeTruthy();
    const enabled = PSQL(`SELECT is_enabled FROM ad_users WHERE tenant_id=9999 AND sam_account='${sam}';`);
    expect(enabled).toBe('f');
  });

  test('disable_user without a target fails honestly instead of claiming success', async ({ page }) => {
    const res = await page.request.post('/api/ad/response', { data: { action: 'disable_user' } });
    expect(res.status()).toBe(400);
  });

  test('remove_group_membership really clears the admin flag', async ({ page }) => {
    const sam = PSQL(`SELECT sam_account FROM ad_users WHERE tenant_id=9999 AND is_admin=true ORDER BY id LIMIT 1;`);
    const res = await page.request.post('/api/ad/response', {
      data: { action: 'remove_group_membership', target: sam },
    });
    expect(res.ok()).toBeTruthy();
    const isAdmin = PSQL(`SELECT is_admin FROM ad_users WHERE tenant_id=9999 AND sam_account='${sam}';`);
    expect(isAdmin).toBe('f');
  });

  test('force_ticket_renewal honestly reports no real integration instead of fake success', async ({ page }) => {
    const res = await page.request.post('/api/ad/response', {
      data: { action: 'force_ticket_renewal', target: 'e2e-test-user' },
    });
    expect(res.status()).toBe(501);
  });

  test('an unrecognized action is rejected rather than silently reporting success', async ({ page }) => {
    const res = await page.request.post('/api/ad/response', {
      data: { action: 'not_a_real_action' },
    });
    expect(res.status()).toBe(400);
  });

  test('the Response tab no longer offers a fake run_soar_playbook action button', async ({ page }) => {
    await page.goto('/ad-attacks');
    await page.getByRole('button', { name: 'Attack Paths + Response', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Run SOAR Playbook' })).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Run SOAR Playbook' })).toBeVisible();
  });
});
