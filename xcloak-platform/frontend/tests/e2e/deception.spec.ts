import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Deception page (route /deception).
//
// Real bugs found and fixed this pass, all in `api/deception_enterprise.go`
// unless noted — the starkest cluster of wrong-table/wrong-column bugs
// found this phase, on code that genuinely *attempted* real work (unlike
// the usual 100%-fake-button pattern):
//  - `PostDeceptionResponse` referenced `playbook_tasks` for
//    isolate_endpoint/collect_memory — that table doesn't exist anywhere in
//    this schema (the real per-agent task table is `agent_tasks`). On top
//    of that both branches gated on `body.AgentID > 0`, but the frontend
//    never sent agent_id at all (deception_triggers has no agent_id column
//    — only source_host, since an attacker triggering a honeypot isn't
//    necessarily one of our own agents) — so even with the right table,
//    neither branch would ever have fired.
//  - `block_ip` inserted into the real `firewall_rules` table but with
//    `src_ip` — the real column is `source_ip` (confirmed via `\d
//    firewall_rules`) — so the INSERT always failed silently.
//  - `create_alert` inserted into the real `alerts` table but with
//    `title`/`description` — neither column exists (real: `rule_name`/
//    `log_message`) — the third occurrence of this exact bug found this
//    phase; also fixed the identical instance in
//    `cloud_security_enterprise.go`'s cloud response-action logging.
//  - `collect_memory` had no real backing at all — the agent executor has
//    no memory-collection task type anywhere — removed rather than wired
//    to a task the agent can't run.
//  - `disable_user` read `body.UserID`, which the frontend never sent
//    either (only `attacker_ip`) — fixed both sides to thread through the
//    trigger's real `attacker_user`, and to report an honest "no such
//    account" message instead of a false "success" when the UPDATE
//    affects 0 rows (the common case — an attacker's stolen/fake
//    credential usually isn't a real `users` row).
//
// The single biggest finding on this page: a completely separate, real,
// tested detection backend (`api/deception.go` + `services/
// deception_service.go` — canary tokens with a genuine public
// trip-recording endpoint, honeyports wired to the real agent
// connect-event pipeline) had zero frontend caller anywhere in this
// codebase before this pass, while the page's Decoys/Honeytokens/Triggers
// tabs point at a parallel data model with no real detection pipeline
// behind it at all (confirmed: nothing anywhere in the backend ever
// INSERTs into `deception_triggers` except this page's own response
// handler updating it after the fact). Built a real "Canary Tokens" tab
// wiring up token CRUD, live trip history, and honeyport management.
// While verifying that flow live, found one more real bug in the
// previously-orphaned-but-now-reachable code:
// `services.TripCanaryToken`'s alert-creation path resolved the acting
// agent via `SELECT id FROM agents WHERE status='online'`, defaulting to
// `0` when none was online — but alerts.agent_id has a foreign key to
// agents(id), and 0 isn't a valid agent, so the INSERT violated that FK on
// every trip with no online agent and silently discarded the error. Since
// canary tokens exist specifically to catch attackers who aren't running
// our agent, "no online agent" is the *common* case, not an edge case —
// verified live that a real trip was recorded but zero alerts were ever
// created for it before the fix (NULL is a valid agent_id; 0 isn't).
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = ['Dashboard', 'Decoys', 'Honeytokens', 'Honeypots', 'Triggers',
  'Canary Tokens', 'Campaigns', 'Graph', 'Intelligence', 'Analytics'];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Deception — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/deception');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/deception');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('Deception — regression guard: response actions are real, not a no-op', () => {
  test('block_ip creates a real firewall_rules row (source_ip, not src_ip)', async ({ page }) => {
    const ip = `10.88.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    const res = await page.request.post('/api/deception/response', {
      data: { action: 'block_ip', attacker_ip: ip },
    });
    expect(res.ok()).toBeTruthy();
    const count = PSQL(`SELECT count(*) FROM firewall_rules WHERE source_ip='${ip}' AND action='drop';`);
    expect(Number(count)).toBe(1);
  });

  test('create_alert creates a real alerts row (rule_name/log_message, not title/description)', async ({ page }) => {
    const ip = `10.89.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    const res = await page.request.post('/api/deception/response', {
      data: { action: 'create_alert', attacker_ip: ip },
    });
    expect(res.ok()).toBeTruthy();
    const logMsg = PSQL(`SELECT log_message FROM alerts WHERE rule_name='Deception Asset Triggered' AND log_message LIKE '%${ip}%' ORDER BY id DESC LIMIT 1;`);
    expect(logMsg).toContain(ip);
  });

  test('isolate_endpoint resolves source_host to a real agent and dispatches a pending-approval task', async ({ page }) => {
    const before = PSQL(`SELECT count(*) FROM agent_tasks WHERE agent_id=1 AND task_type='isolate_host' AND status='pending_approval';`);
    const res = await page.request.post('/api/deception/response', {
      data: { action: 'isolate_endpoint', source_host: 'web-prod-01' },
    });
    expect(res.ok()).toBeTruthy();
    const after = PSQL(`SELECT count(*) FROM agent_tasks WHERE agent_id=1 AND task_type='isolate_host' AND status='pending_approval';`);
    expect(Number(after)).toBeGreaterThan(Number(before));
  });

  test('isolate_endpoint without source_host fails honestly instead of silently no-oping', async ({ page }) => {
    const res = await page.request.post('/api/deception/response', {
      data: { action: 'isolate_endpoint' },
    });
    expect(res.status()).toBe(400);
  });

  test('disable_user reports an honest message when the username has no real account', async ({ page }) => {
    const res = await page.request.post('/api/deception/response', {
      data: { action: 'disable_user', username: 'not-a-real-account-e2e' },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.message).toContain('no real account');
  });
});

test.describe('Deception — Canary Tokens: a real, previously-orphaned detection backend', () => {
  test('creating a token and tripping its real URL records a trip and fires a real alert', async ({ page }) => {
    const name = `e2e canary probe ${Date.now()}`;
    const createRes = await page.request.post('/api/canary/tokens', {
      data: { token_type: 'file', name, description: 'e2e probe' },
    });
    expect(createRes.ok()).toBeTruthy();
    const token = await createRes.json();
    expect(token.token_value).toContain('xck-canary-');
    expect(token.alert_on_trip).toBe(true);

    // The trip endpoint is public — no auth — by design (it's meant to be
    // hit by whatever/whoever opens the bait file or URL).
    const tripRes = await page.request.get(`/api/canary/trip/${token.token_value}`, { headers: {} });
    expect(tripRes.ok()).toBeTruthy();

    const trips = await page.request.get('/api/canary/trips', { params: { token_id: token.id } }).then(r => r.json());
    expect(trips.length).toBeGreaterThan(0);
    expect(trips[0].source_ip).toBeTruthy();

    // Regression guard for the agent_id=0 FK-violation bug: this tenant's
    // seeded agents may or may not be "online" at test time, but either way
    // a real alert must exist now — previously it silently never did.
    const alertMsg = PSQL(`SELECT log_message FROM alerts WHERE rule_name='Canary Token Tripped' AND log_message LIKE '%${name}%' ORDER BY id DESC LIMIT 1;`);
    expect(alertMsg).toContain(name);
  });

  test('the Canary Tokens tab renders the real token and its trip count', async ({ page }) => {
    const name = `e2e canary ui probe ${Date.now()}`;
    const createRes = await page.request.post('/api/canary/tokens', {
      data: { token_type: 'url', name },
    });
    const token = await createRes.json();
    await page.request.get(`/api/canary/trip/${token.token_value}`);

    await page.goto('/deception');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    await page.getByRole('button', { name: 'Canary Tokens', exact: true }).click();
    const row = page.locator('tr', { hasText: name });
    await expect(row).toBeVisible({ timeout: 10_000 });
    await expect(row.getByText('1x')).toBeVisible();
  });
});
