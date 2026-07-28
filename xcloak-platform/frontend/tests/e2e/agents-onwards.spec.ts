import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Deploy Agent / onboarding wizard (route
// /agents/onwards). Runs against a REAL backend + seeded DB — see
// dashboard.spec.ts's header comment for the dev-stack recipe, and
// global-setup.ts for the shared-login rationale.
//
// This page was flagged during the Agents page work as still needing its
// own full audit (it was only spot-checked then, to decide it was the
// better of two duplicate onboarding flows). Backend (api/integrations.go's
// GenerateInstallToken + api/agents.go's RegisterAgent) is real and
// correctly built: tokens are single-use (atomic `UPDATE ... SET used=true
// WHERE used=false ... RETURNING`, so two concurrent registrations can't
// both claim one token), tenant-scoped, and expire via a real 24h DB column
// default — confirmed live via curl: generating a token, registering an
// agent with it, then reusing the same token correctly gets rejected with
// "invalid, already-used, or expired install token".
//
// One real frontend bug found: Step 4's `checkForAgent` had
// `if (recent || agents.length > 0) setFound(true)` — the `|| agents.length
// > 0` fallback made the whole "did MY new agent register" check
// meaningless for any tenant with pre-existing agents (the overwhelming
// majority, including this demo tenant's 4 seeded agents). Clicking "Check
// Now" would unconditionally show "Agent detected! Your agent is registered
// and running" on the very first click, regardless of whether the agent
// from *this* onboarding session ever actually ran — the opposite of what
// the page claims to verify. Fixed by removing the fallback so only a
// genuinely recent (< 2 min old) agent registration counts.
test.use({ storageState: SHARED_STORAGE_STATE });

// These tests register real agents against the shared `agents` table (there
// is no DELETE /api/agents/:id endpoint to clean up through the API), which
// can race other spec files' assertions about total/online agent counts if
// they happen to run in an overlapping parallel worker (observed once: a
// concurrent agents.spec.ts count assertion picked up these test agents
// mid-run). Deleting them as soon as each test finishes — rather than
// leaving them for a manual cleanup pass at the very end of the whole
// suite — shrinks that window as much as possible without adding a new
// dependency (no `pg` client in this project; shelling out to the same
// `docker exec xcloak-postgres psql` command used for manual cleanup
// throughout this phase is the lowest-footprint option available).
test.afterEach(() => {
  try {
    execSync(
      `docker exec xcloak-postgres psql -U xcloak -d ngfw -c ` +
      `"DELETE FROM agent_tasks WHERE agent_id IN (SELECT id FROM agents WHERE hostname ILIKE 'spec-test%' OR hostname ILIKE 'spec-recent%'); ` +
      `DELETE FROM agents WHERE hostname ILIKE 'spec-test%' OR hostname ILIKE 'spec-recent%';"`,
      { stdio: 'ignore' },
    );
  } catch { /* best-effort cleanup; a leftover row just gets swept by the next run */ }
});

test.describe('Deploy Agent — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/agents/onwards');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/agents/onwards');
    await expect(page.getByText('Agent Onboarding')).toBeVisible({ timeout: 20_000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });
});

test.describe('Deploy Agent — wizard walkthrough with a real backend token', () => {
  test('generating a token advances to Step 2 and shows the real token in the .env block', async ({ page }) => {
    await page.goto('/agents/onwards');
    await expect(page.getByText('Agent Onboarding')).toBeVisible({ timeout: 20_000 });

    await page.getByPlaceholder(/prod-web-01/i).fill('spec-test-agent');
    await page.getByRole('button', { name: /Generate Install Token/i }).click();

    await expect(page.getByText('Configure the agent')).toBeVisible({ timeout: 10_000 });
    const envBlock = page.locator('pre', { hasText: 'XCLOAK_INSTALL_TOKEN=' });
    await expect(envBlock).toBeVisible();
    const envText = await envBlock.innerText();
    const match = envText.match(/XCLOAK_INSTALL_TOKEN=([a-f0-9]+)/);
    expect(match).toBeTruthy();
    const token = match![1];

    // Regression guard: the token shown is real and backend-recognized —
    // reusing it via a real register call must succeed exactly once.
    const machineId = `spec-test-machine-${Date.now()}`;
    const res = await page.request.post('/api/agents/register', {
      data: { machine_id: machineId, hostname: 'spec-test-agent', os: 'linux', ip_address: '10.0.0.77', install_token: token },
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.agent_id).toBeTruthy();

    const reuse = await page.request.post('/api/agents/register', {
      data: { machine_id: machineId + '-2', hostname: 'spec-test-agent-2', os: 'linux', ip_address: '10.0.0.78', install_token: token },
    });
    expect(reuse.status()).toBe(401);
    // Test agent cleanup is handled by the afterEach hook above.

    await page.getByRole('button', { name: 'Next' }).click();
    await expect(page.getByText('Build and run the agent')).toBeVisible({ timeout: 10_000 });
    await page.getByRole('button', { name: 'Next' }).click();
    await expect(page.getByText('Verify the agent is connected')).toBeVisible({ timeout: 10_000 });
  });
});

test.describe('Deploy Agent — regression guard: Step 4 only reports success for a genuinely new agent', () => {
  test('"Check Now" does not report success just because other agents already exist in the tenant', async ({ page }) => {
    // This tenant already has several agents (seeded demo data) — the
    // fixed logic must not treat that as "my new agent registered".
    await page.goto('/agents/onwards');
    await expect(page.getByText('Agent Onboarding')).toBeVisible({ timeout: 20_000 });
    await page.getByRole('button', { name: /Generate Install Token/i }).click();
    await expect(page.getByText('Configure the agent')).toBeVisible({ timeout: 10_000 });
    await page.getByRole('button', { name: 'Next' }).click();
    await expect(page.getByText('Build and run the agent')).toBeVisible({ timeout: 10_000 });
    await page.getByRole('button', { name: 'Next' }).click();
    await expect(page.getByText('Verify the agent is connected')).toBeVisible({ timeout: 10_000 });

    await page.getByRole('button', { name: /Check Now/i }).click();
    await expect(page.getByText(/Waiting for agent…/i)).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText(/Agent detected!/i)).not.toBeVisible();
  });

  test('"Check Now" does report success once a genuinely new agent registers', async ({ page }) => {
    const tokenRes = await (await page.request.post('/api/integrations/install-tokens', {
      data: { label: 'onwards-spec-recent-check' },
    })).json();
    const machineId = `spec-recent-check-${Date.now()}`;
    const regRes = await page.request.post('/api/agents/register', {
      data: { machine_id: machineId, hostname: 'spec-recent-check-agent', os: 'linux', ip_address: '10.0.0.66', install_token: tokenRes.token },
    });
    const { agent_id } = await regRes.json();

    await page.goto('/agents/onwards');
    await expect(page.getByText('Agent Onboarding')).toBeVisible({ timeout: 20_000 });
    await page.getByRole('button', { name: /Generate Install Token/i }).click();
    await expect(page.getByText('Configure the agent')).toBeVisible({ timeout: 10_000 });
    await page.getByRole('button', { name: 'Next' }).click();
    await page.getByRole('button', { name: 'Next' }).click();
    await expect(page.getByText('Verify the agent is connected')).toBeVisible({ timeout: 10_000 });

    await page.getByRole('button', { name: /Check Now/i }).click();
    await expect(page.getByText(/Agent detected!/i)).toBeVisible({ timeout: 10_000 });
    expect(agent_id).toBeTruthy();
  });
});
