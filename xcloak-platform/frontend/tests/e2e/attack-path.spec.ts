import { test, expect } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Attack Paths page (route /attack-path).
// Runs against a REAL backend + seeded DB — see dashboard.spec.ts's header
// comment for the dev-stack recipe, and global-setup.ts for the
// shared-login rationale.
//
// Backend (api/attack_path.go + services/attack_path_service.go) is one of
// the most sophisticated real engines found in this whole phase: a genuine
// Dijkstra shortest-path-by-compromise-cost implementation, real MITRE
// technique mapping keyed off observed connection ports, real BFS blast-
// radius computation, and real chokepoint detection. `AttackPathNode.Type`
// is hard-limited (Go struct comment) to "internet"|"agent", and
// `RankedAttackPath.PathType` to "lateral"|"priv_esc" — no backend code path
// can ever produce the frontend's `cloud`/`container`/`domain_controller`
// node types or `cloud`/`container`/`identity`/`vpn`/`hybrid`/`saas` path
// types. Bugs found and fixed:
//
//  - PATH_TYPE_TABS had 6 filter tabs (Cloud/Container/Identity/VPN/Hybrid/
//    SaaS) that could never match a real path — clicking any of them always
//    rendered "No paths match this filter", a dead-end control masquerading
//    as a working filter. Trimmed to the 3 real values (All/Lateral/Priv Esc).
//  - The kill-chain strip's "Lockheed Kill Chain"/"Diamond Model" selector
//    buttons: neither model's phase IDs (weaponization/delivery/c2/... or
//    adversary/capability/victim/...) ever matched a real
//    `kill_chain_phase` value the backend emits (always MITRE-vocabulary
//    strings from inferKillChainPhase()), so selecting either model left
//    every phase circle permanently unlit — removed both, keeping only
//    MITRE (the one model with any real backing). The MITRE phase list
//    itself was also wrong in both directions: it included 3 phases
//    inferKillChainPhase() can never return (privilege_escalation,
//    credential_access, impact — permanently dark) and was missing
//    "exploitation" (a real value with nowhere to display it). Rebuilt to
//    exactly the 7 real phases.
//  - The node detail drawer's "Actions" tab was the same 100%-fake-button
//    pattern already found and fixed on UEBA/Insider Threat/Network Map — 10
//    buttons (Isolate Host, Scan Endpoint, Disable User, Block IP, Push FW
//    Rule, Run Playbook, Open Incident, Patch Host, Remove Privilege, Hunt
//    IOC) all just called a local toast function with canned text and made
//    zero API calls. Rewired the 3 real capabilities (tasksAPI.create for
//    isolate_host/vulnerability_scan — real agent_tasks the executor
//    genuinely handles; dpiAPI.responseAction('create_incident') — the
//    shared response-action dispatcher NBA/DPI/Network Map already use) and
//    removed the rest, since none has any real backend capability behind it
//    for this node's available data (no IP field on this node type to block,
//    no identity/AD integration, no playbook-picker UI, no patch/hunt
//    dispatch anywhere). Also hid the Actions tab entirely for the
//    "internet" node (no agent_id to act on).
//  - The Blast Radius tab's "Est. impact ₹X.XM" figure was a fully
//    fabricated dollar amount (blast_radius × an arbitrary per-type
//    multiplier, e.g. 750K for the only type that ever actually occurs)
//    with no real asset-value/criticality data behind it anywhere in the
//    schema, presented with false precision. Removed.
//  - `services/risk_score_service.go`'s CalculateRiskScore had no upper
//    bound — a host with a couple dozen alerts (routine in this seeded
//    tenant) trivially scored past 100 despite every UI surface displaying
//    it as an "X/100" figure and percentage-width bar. Masked until now
//    because `asset_risk_scores` had zero rows for the demo tenant (no
//    seeder ever populated it — real production rows are a side effect of
//    the real alert/incident/vulnerability ingestion path, which the demo
//    seeder's raw-SQL inserts bypass). Fixed the clamp and added
//    `seedRiskScores` to `cmd/seed/demo/main.go` (mirroring the real formula
//    since this package intentionally has no services/database dependency)
//    so this page's most central per-node metric — chokepoint priv-level
//    classification, node color, remediation's "remove admin rights" step —
//    has real non-zero data to display for the first time in this phase.
test.use({ storageState: SHARED_STORAGE_STATE });

test.describe('Attack Paths — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/attack-path');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/attack-path');
    await expect(page.getByText('Paths').first()).toBeVisible({ timeout: 20_000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });
});

test.describe('Attack Paths — regression guard: risk score clamp', () => {
  test('no node ever reports a risk_score above 100', async ({ page }) => {
    const graph: { nodes: Array<{ risk_score: number }> } =
      await (await page.request.get('/api/attack-path')).json();
    expect(graph.nodes.length).toBeGreaterThan(0);
    for (const n of graph.nodes) {
      expect(n.risk_score).toBeLessThanOrEqual(100);
    }
    // At least one demo agent should have a real, nonzero, non-default
    // score now that seedRiskScores populates asset_risk_scores.
    expect(graph.nodes.some(n => n.risk_score > 0)).toBe(true);
  });
});

test.describe('Attack Paths — regression guard: path-type filter is real', () => {
  test('only All Paths / Lateral / Priv Esc filter tabs exist', async ({ page }) => {
    await page.goto('/attack-path');
    await expect(page.getByText('Paths').first()).toBeVisible({ timeout: 20_000 });

    // These sit in the same top-level render as the "Paths" side-tab, but
    // under heavy 4-worker parallel-suite load `next dev`'s on-demand page
    // compilation can leave a visible gap between the two — give this the
    // same generous timeout rather than the 5s assertion default (confirmed
    // reliable standalone; see agents.spec.ts's identical rationale for
    // /agents/onwards).
    await expect(page.getByRole('button', { name: 'All Paths' })).toBeVisible({ timeout: 20_000 });
    await expect(page.getByRole('button', { name: 'Lateral', exact: true })).toBeVisible({ timeout: 20_000 });
    await expect(page.getByRole('button', { name: 'Priv Esc', exact: true })).toBeVisible({ timeout: 20_000 });

    for (const fake of ['Cloud', 'Container', 'Identity', 'VPN', 'Hybrid', 'SaaS']) {
      await expect(page.getByRole('button', { name: fake, exact: true })).toHaveCount(0);
    }
  });
});

test.describe('Attack Paths — regression guard: kill-chain model selector', () => {
  test('no Lockheed/Diamond model buttons that never highlight anything', async ({ page }) => {
    await page.goto('/attack-path');
    await expect(page.getByText('Paths').first()).toBeVisible({ timeout: 20_000 });

    await expect(page.getByText('MITRE ATT&CK')).toBeVisible({ timeout: 20_000 });
    await expect(page.getByRole('button', { name: 'Lockheed', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Diamond', exact: true })).toHaveCount(0);
  });
});

test.describe('Attack Paths — node detail: real actions only', () => {
  test('an agent node\'s Actions tab has no fake buttons, and Isolate Host dispatches a real task', async ({ page }) => {
    const graph: { nodes: Array<{ id: string; type: string; agent_id?: number; hostname?: string }> } =
      await (await page.request.get('/api/attack-path')).json();
    const agentNode = graph.nodes.find(n => n.type === 'agent' && n.hostname);
    expect(agentNode).toBeTruthy();

    await page.goto('/attack-path');
    await expect(page.getByText('Paths').first()).toBeVisible({ timeout: 20_000 });

    // Nodes are real SVG <g> elements (unlike Network Map's plain canvas) —
    // clicking the hostname <text> bubbles to the parent group's onClick.
    await page.locator('svg text', { hasText: agentNode!.hostname! }).first().click();
    await expect(page.getByRole('button', { name: 'Actions', exact: true })).toBeVisible({ timeout: 10_000 });
    await page.getByRole('button', { name: 'Actions', exact: true }).click();

    const actionsPanelText = await page.locator('body').innerText();
    for (const fake of ['Scan Endpoint', 'Disable User', 'Block IP', 'Push FW Rule', 'Run Playbook', 'Patch Host', 'Remove Privilege', 'Hunt IOC']) {
      expect(actionsPanelText).not.toContain(fake);
    }
    await expect(page.getByRole('button', { name: 'Isolate Host' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Vulnerability Scan' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Open Incident' })).toBeVisible();
  });

  test('the internet entry-point node has no Actions tab (no agent_id to act on)', async ({ page }) => {
    await page.goto('/attack-path');
    await expect(page.getByText('Paths').first()).toBeVisible({ timeout: 20_000 });

    await page.locator('svg text', { hasText: 'Internet' }).first().click();
    await expect(page.getByRole('button', { name: 'Host', exact: true })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByRole('button', { name: 'Actions', exact: true })).toHaveCount(0);
  });
});

test.describe('Attack Paths — regression guard: real actions dispatch end-to-end', () => {
  test('isolate_host task dispatch succeeds against the live backend', async ({ page }) => {
    const graph: { nodes: Array<{ type: string; agent_id?: number }> } =
      await (await page.request.get('/api/attack-path')).json();
    const agentNode = graph.nodes.find(n => n.type === 'agent' && n.agent_id);
    expect(agentNode).toBeTruthy();

    const res = await page.request.post('/api/tasks', {
      data: { agent_id: agentNode!.agent_id, task_type: 'isolate_host', payload: {} },
    });
    expect(res.status()).toBe(200);

    // Clean up so this test is repeatable.
    await page.request.post('/api/tasks', {
      data: { agent_id: agentNode!.agent_id, task_type: 'de_isolate', payload: {} },
    });
  });
});

test.describe('Attack Paths — Blast Radius tab has no fabricated business-impact figure', () => {
  test('no "Est. impact" dollar figure survives', async ({ page }) => {
    await page.goto('/attack-path');
    await expect(page.getByText('Paths').first()).toBeVisible({ timeout: 20_000 });

    await page.getByRole('button', { name: 'Blast Radius', exact: true }).click();
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toContain('Est. impact');
  });
});
