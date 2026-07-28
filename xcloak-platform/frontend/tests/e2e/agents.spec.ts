import { test, expect, Page } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Agents page. Runs against a REAL backend
// + seeded DB — see dashboard.spec.ts's header comment for the dev-stack
// recipe, and global-setup.ts for why the whole suite shares one login
// instead of each spec file logging in independently.
test.use({ storageState: SHARED_STORAGE_STATE });

function agentCard(page: Page, hostname: string) {
  return page.locator('.g-card', { hasText: hostname }).first();
}

test.describe('Agents — route health', () => {
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

    await page.goto('/agents');
    await page.waitForLoadState('networkidle', { timeout: 15_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/agents');
    await expect(page.locator('.g-card').first()).toBeVisible({ timeout: 15_000 });

    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });

  test('regression guard: no dead "Tamper protect" / "Policies" fields (no real backend source for either)', async ({ page }) => {
    await page.goto('/agents');
    await expect(page.locator('.g-card').first()).toBeVisible({ timeout: 15_000 });

    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toContain('Tamper protect');
    expect(bodyText).not.toMatch(/Policies\s/);
  });
});

test.describe('Agents — rendered data matches live backend', () => {
  test('online/total subtitle matches live /api/agents', async ({ page }) => {
    const agents: Array<{ status: string }> = await (await page.request.get('/api/agents')).json();
    const online = agents.filter(a => a.status === 'online').length;

    await page.goto('/agents');
    await expect(page.getByText(`${online}/${agents.length} online`)).toBeVisible({ timeout: 15_000 });
  });

  test('each agent card shows the same hostname/IP/status as the live API', async ({ page }) => {
    const agents: Array<{ hostname: string; ip_address: string; status: string }> =
      await (await page.request.get('/api/agents')).json();
    expect(agents.length).toBeGreaterThan(0);

    await page.goto('/agents');
    for (const a of agents) {
      const card = agentCard(page, a.hostname);
      await expect(card).toBeVisible({ timeout: 15_000 });
      await expect(card).toContainText(a.ip_address, { timeout: 15_000 });
      await expect(card.locator(a.status === 'online' ? '.s-online' : '.s-offline')).toHaveText(a.status, { timeout: 15_000 });
    }
  });
});

test.describe('Agents — isolation status reflects real task dispatch', () => {
  test('dispatching isolate_host shows the Isolated badge; de_isolate clears it', async ({ page }) => {
    // This test does 3 sequential dispatch+reload+assert cycles — under full
    // parallel-suite load that cumulative time can exceed Playwright's
    // default 30s *test* timeout even though no single assertion is close to
    // its own 20s sub-timeout. Give the whole test more room rather than
    // chasing it as "flaky" (confirmed via error-context.md: the DOM was
    // already in the correct state when the test was killed — it just ran
    // out of overall time, not a wrong-state race).
    test.setTimeout(60_000);

    const agents: Array<{ id: number; hostname: string }> = await (await page.request.get('/api/agents')).json();
    const target = agents[agents.length - 1];

    // Clean slate: de-isolate first in case a prior run left this agent isolated.
    await page.request.post('/api/tasks', { data: { agent_id: target.id, task_type: 'de_isolate', payload: {} } });
    await page.goto('/agents');
    await expect(agentCard(page, target.hostname)).toBeVisible({ timeout: 20_000 });
    await expect(agentCard(page, target.hostname)).not.toContainText('Isolated', { timeout: 20_000 });

    await page.request.post('/api/tasks', { data: { agent_id: target.id, task_type: 'isolate_host', payload: {} } });
    await page.reload();
    await expect(agentCard(page, target.hostname)).toBeVisible({ timeout: 20_000 });
    await expect(agentCard(page, target.hostname)).toContainText('Isolated', { timeout: 20_000 });

    // Clean up so this test is repeatable.
    await page.request.post('/api/tasks', { data: { agent_id: target.id, task_type: 'de_isolate', payload: {} } });
    await page.reload();
    await expect(agentCard(page, target.hostname)).toBeVisible({ timeout: 20_000 });
    await expect(agentCard(page, target.hostname)).not.toContainText('Isolated', { timeout: 20_000 });
  });
});

test.describe('Agents — enrollment', () => {
  // The Agents page used to have its own embedded 3-step "Enroll Agent"
  // onboarding modal, entirely separate from (and less complete than) the
  // dedicated /agents/onwards wizard reachable from the sidebar's "Deploy
  // Agent" link — same real backend call (integrationsAPI.createInstallToken)
  // implemented twice. The onwards page is the one that matches the agent
  // binary's actual preferred install path (.env file, checked by
  // agent/register.go before falling back to an interactive stdin prompt),
  // has server-URL configuration, and a systemd unit — so the duplicate
  // in-page modal was removed and this button now points there instead.
  test('"Enroll Agent" navigates to the real onboarding wizard at /agents/onwards', async ({ page }) => {
    await page.goto('/agents');
    await page.waitForLoadState('networkidle', { timeout: 15_000 });
    const enrollLink = page.getByRole('link', { name: /Enroll Agent/i });
    await expect(enrollLink).toBeVisible({ timeout: 15_000 });
    await enrollLink.click();
    // /agents/onwards is a separate Next.js route the dev server compiles
    // on first visit — under 4-worker parallel-suite load that on-demand
    // compile can take longer than the usual 10s assertion timeout even
    // though the click and navigation are both working correctly (confirmed
    // reliable standalone); give it more room instead of chasing it as flaky.
    await expect(page).toHaveURL(/\/agents\/onwards/, { timeout: 25_000 });
    await expect(page.getByText('Agent Onboarding')).toBeVisible({ timeout: 25_000 });
  });
});

test.describe('Agents — task dispatch', () => {
  test('dispatching a collection task from the Tasks modal succeeds against the live backend', async ({ page }) => {
    const agents: Array<{ hostname: string }> = await (await page.request.get('/api/agents')).json();
    const target = agents[0];

    await page.goto('/agents');
    const card = agentCard(page, target.hostname);
    await expect(card).toBeVisible({ timeout: 15_000 });

    await card.getByRole('button', { name: /tasks/i }).click();
    await expect(page.locator('.g-modal')).toBeVisible({ timeout: 15_000 });

    await page.locator('.g-modal button', { hasText: /dispatch 1 task/i }).click();

    await expect(page.getByText(/1 task dispatched/i)).toBeVisible({ timeout: 10_000 });
  });
});
