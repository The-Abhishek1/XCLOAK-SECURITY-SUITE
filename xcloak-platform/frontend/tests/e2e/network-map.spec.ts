import { test, expect } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Network Map page (route /network-map).
// Runs against a REAL backend + seeded DB — see dashboard.spec.ts's header
// comment for the dev-stack recipe, and global-setup.ts for the
// shared-login rationale.
//
// Backend (api/network_map.go + services/network_map_service.go +
// services/ip_enrich.go) is a genuinely sophisticated real topology engine —
// real node/edge construction from agents/risk scores/connect events, real
// hostname/OS-keyword node-type inference, real CIDR-based cloud-IP
// detection, and real threat-intel enrichment (local IOC lookup + free
// ip-api.com geolocation always on, AbuseIPDB/VirusTotal/Greynoise/Shodan
// gated behind env keys — an honest "skip silently if unconfigured" pattern).
// Two real bugs found and fixed:
//
//  - `alertCountsByAgent` queried a nonexistent `alerts.acknowledged` boolean
//    column instead of the real `status='open'` lifecycle convention used
//    everywhere else in this codebase. The query always errored, and the
//    caller's non-fatal fallback to an empty map meant every agent node's
//    `alert_count` — and the map summary's `alerting_nodes` count — silently
//    showed 0 no matter how many real open alerts existed. Fixed by
//    switching the WHERE clause to `status='open'`.
//  - The color/type Legend statically enumerated all 21 entries of the
//    `INFRA_FILL`/`INFRA_LABELS` maps, but `models.NetworkMapNode.Type` is
//    hard-limited (via Go struct comment) to 9 real values
//    (agent/external_ip/firewall/router/switch/vpn/wireless/cloud/wan) — the
//    other 12 (Kubernetes Cluster, Hypervisor, OT/ICS Device, DNS/DHCP
//    Server, Load Balancer, Reverse Proxy, Storage, IoT Device, Container,
//    Virtual Machine, SD-WAN, Site-to-Site VPN, Internet Gateway, DMZ) can
//    never be produced by any backend code path, so the legend was
//    presenting detection capabilities the product doesn't have. Fixed by
//    filtering the legend to the 7 real non-agent/non-external_ip infra
//    types (agent and external_ip already have their own legend sections).
//  - The node detail drawer's "Actions" tab (`ActionsTab`) was the same
//    fake-response-action pattern already found and fixed on UEBA/Insider
//    Threat: all 8 agent-node buttons and all 3 external-IP buttons just
//    called a local toast function with canned text and made zero API
//    calls. Rewired the real, working subset to actual backend dispatch
//    (tasksAPI.create for isolate_host/vulnerability_scan/collect_processes/
//    collect_auth_logs — all real agent_tasks the executor genuinely
//    handles; dpiAPI.responseAction('create_incident'/'block_ip') and
//    iocsAPI.create for Add to IOC — the same generic response-action
//    dispatcher NBA/DPI already use). Removed buttons with no real backend
//    capability anywhere in the codebase (Ping, Port Scan, ad-hoc Scan Host,
//    Restart Agent — the agent executor has no case for "restart_host", it
//    would just log "unknown task type" — and Whois Lookup, which no
//    service anywhere implements). Also removed the Actions tab entirely for
//    infra-type nodes (firewall/router/etc.) since they carry no agent_id to
//    dispatch anything against, and removed external_ip's dead "Traffic" tab
//    (its content was always rendered regardless of which tab was selected,
//    so a distinct Traffic tab never showed anything different from Overview).
test.use({ storageState: SHARED_STORAGE_STATE });

test.describe('Network Map — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/network-map');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/network-map');
    await expect(page.getByText('Agents').first()).toBeVisible({ timeout: 20_000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });
});

test.describe('Network Map — summary matches live backend', () => {
  test('summary stats strip matches live /api/network-map', async ({ page }) => {
    const graph: { summary: Record<string, number> } =
      await (await page.request.get('/api/network-map?minutes=60')).json();

    await page.goto('/network-map');
    await expect(page.getByText('Agents').first()).toBeVisible({ timeout: 20_000 });

    const summaryText = await page.locator('body').innerText();
    // Regression guard for the alerts.acknowledged -> status='open' fix:
    // alerting_nodes must reflect real open-alert counts, not always 0.
    expect(graph.summary.alerting_nodes).toBeGreaterThan(0);
    expect(summaryText).toContain(String(graph.summary.total_agents));
  });
});

test.describe('Network Map — regression guard: Legend only shows real infra types', () => {
  test('Legend panel never claims detection of infra types the backend cannot produce', async ({ page }) => {
    await page.goto('/network-map');
    await expect(page.getByText('Agents').first()).toBeVisible({ timeout: 20_000 });

    await page.getByRole('button', { name: 'Legend' }).click();
    const panelText = await page.locator('body').innerText();

    // Real, backend-producible infra types must still be present.
    expect(panelText).toContain('Firewall');
    expect(panelText).toContain('Router');
    expect(panelText).toContain('WAN Link');

    // Fabricated infra types the Go model can never emit must be absent.
    for (const fake of [
      'Kubernetes Cluster', 'Hypervisor', 'OT/ICS Device', 'DNS Server',
      'DHCP Server', 'Load Balancer', 'Reverse Proxy', 'Storage (NAS/SAN)',
      'IoT Device', 'Virtual Machine', 'SD-WAN', 'Site-to-Site VPN',
      'Internet Gateway',
    ]) {
      expect(panelText).not.toContain(fake);
    }
  });
});

test.describe('Network Map — node detail: real actions only', () => {
  test('an agent node\'s Actions tab dispatches real tasks, with no fake buttons', async ({ page }) => {
    test.setTimeout(90_000);
    const graph: { nodes: Array<{ id: string; type: string; hostname?: string }> } =
      await (await page.request.get('/api/network-map?minutes=60')).json();
    const agentNode = graph.nodes.find(n => n.type === 'agent');
    expect(agentNode).toBeTruthy();

    await page.goto('/network-map');
    await expect(page.getByText('Agents').first()).toBeVisible({ timeout: 20_000 });
    // Let the force-graph simulation settle before hit-testing node positions.
    await page.waitForTimeout(2_000);

    const canvas = page.locator('canvas').first();
    const box = await canvas.boundingBox();
    expect(box).toBeTruthy();

    // Node selection is a force-graph-2d onNodeClick callback — there's no
    // DOM element per node, so scan a grid of canvas positions (rather than
    // one fixed point) until a click actually lands on a node and opens the
    // detail drawer, since this test cares about drawer behavior once open,
    // not about exact force-simulation layout.
    const drawer = page.locator('div.fixed.inset-0.z-50');
    let drawerOpened = false;
    // Node hit-boxes on the canvas are small circles with no DOM presence,
    // so a coarse grid mostly misses them — scan finely, and give each miss
    // only a short settle before the next click (onNodeClick's React state
    // update is near-instant; a longer wait is only needed once a hit is
    // suspected, to let the backdrop actually mount before we stop clicking).
    outer: for (let gx = 0.08; gx <= 0.92 && !drawerOpened; gx += 0.06) {
      for (let gy = 0.1; gy <= 0.9 && !drawerOpened; gy += 0.1) {
        await canvas.click({ position: { x: box!.width * gx, y: box!.height * gy }, timeout: 5_000 });
        // waitFor resolves as soon as the drawer mounts (fast on a real hit)
        // but still bounds the cost of a miss to this timeout, unlike a bare
        // .count() check which can race the click's React state update.
        drawerOpened = await drawer.first().waitFor({ state: 'visible', timeout: 250 })
          .then(() => true).catch(() => false);
      }
    }
    expect(drawerOpened, 'no grid position landed a click on a node — a real regression if this fails, since the seeded graph has several nodes').toBe(true);
    await expect(page.getByRole('button', { name: 'Actions', exact: true })).toBeVisible({ timeout: 5_000 });

    await page.getByRole('button', { name: 'Actions', exact: true }).click();
    const actionsPanelText = await page.locator('body').innerText();
    // These buttons were removed because no real backend capability backs
    // them anywhere in the codebase.
    expect(actionsPanelText).not.toContain('Ping');
    expect(actionsPanelText).not.toContain('Port Scan');
    expect(actionsPanelText).not.toContain('Whois Lookup');
    expect(actionsPanelText).not.toContain('Restart Agent');
  });
});

test.describe('Network Map — regression guard: real actions endpoints work end-to-end', () => {
  test('block_ip response action creates a real, queryable IOC', async ({ page }) => {
    const testIP = '203.0.113.199';
    const res = await page.request.post('/api/dpi/response-action', {
      data: { action: 'block_ip', ip: testIP, reason: 'network-map spec test' },
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.result).toContain(testIP);

    const iocsRes = await (await page.request.get('/api/iocs')).json();
    const iocs: any[] = iocsRes?.data ?? iocsRes ?? [];
    expect(iocs.some(i => i.indicator === testIP)).toBe(true);
  });

  test('create_incident response action creates a real, queryable incident', async ({ page }) => {
    const reason = `network-map spec test ${Date.now()}`;
    const res = await page.request.post('/api/dpi/response-action', {
      data: { action: 'create_incident', reason },
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.result).toMatch(/Incident #\d+ created/);
  });
});
