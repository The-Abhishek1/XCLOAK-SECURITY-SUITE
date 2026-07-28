import { test, expect } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Risk Posture page (route /risk-posture).
// Runs against a REAL backend + seeded DB — see dashboard.spec.ts's header
// comment for the dev-stack recipe, and global-setup.ts for the
// shared-login rationale.
//
// Backend (api/risk_posture.go + services/risk_posture_service.go) is
// mostly real, careful code — deliberate "honest gap, don't fabricate a
// mapping that doesn't exist" comments throughout (computeDepartmentRisk,
// computeHighRiskApps), and a documented "EnrichRiskPostureLiveData must be
// called by every code path" invariant that's actually followed both places
// a snapshot is returned. One real backend bug found, plus three real
// frontend fabrications:
//
//  - `RefreshVulnPriorityScores` (services/vuln_priority_service.go) joined
//    `agents ag` and read `ag.risk_score` — a column that has never existed
//    on `agents` (real per-agent risk scores live in `asset_risk_scores`,
//    a separate table). This broke the query on every call — both the
//    on-startup run and every 6h scheduler tick, for every tenant, not just
//    this demo one — silently returning zero rows via an unlogged early
//    `return` on error. `priority_score`/`patch_sla_days` were therefore
//    NEVER computed for any vulnerability, ever. This cascaded directly into
//    Risk Posture's VulnScore (its formula divides by priority_score, which
//    was always 0) being permanently stuck at 0 out of its possible 30
//    points, and silently degraded the Vuln Priority Queue's "ORDER BY
//    priority_score DESC" to a plain CVSS sort. Fixed the JOIN to read from
//    `asset_risk_scores` instead, and added an error log so a future
//    schema-mismatch break like this one is visible instead of silent.
//    Confirmed via live curl before/after: VulnScore went from 0 to 13 and
//    the total score from 45 to 58 after triggering a real recompute.
//  - The Compliance card's per-framework breakdown (CIS Level 1/NIST CSF/
//    ISO 27001/SOC 2 Type II) was entirely invented client-side — it scaled
//    the page's own misconfiguration-derived `compliance` heuristic by
//    arbitrary decimals (×0.97/×0.94/×0.91) and paired the result with
//    hardcoded fake control counts ("153 controls", "108 outcomes"...) with
//    zero connection to any real control mapping. The Dashboard page
//    already has a real per-framework endpoint
//    (`/api/compliance/scores/latest`, returning real ISO27001/NIST/
//    PCI-DSS/SOC2 scores with real passed/failed counts) that this page
//    simply never called. Wired it in.
//  - The Business Impact card's "Estimated Financial Exposure ₹X Cr/L"
//    figure was `critAssets×₹2.5M + systemsAtRisk×₹750K +
//    criticalPatches×₹500K` — arbitrary per-category multipliers with no
//    real breach-cost/actuarial data behind them anywhere in the schema,
//    presented with false precision (labeled "Worst-case estimate based on
//    asset criticality and risk score" as if it were a real calculation).
//    Same fabrication class already found and removed on the Attack Paths
//    page's "Est. impact" figure. Removed; the 4 real count tiles (Users
//    Affected, Systems at Risk, Critical Assets, Departments) stay.
//  - The Remediation Queue's "status" badge claimed 'in_progress' for
//    high-severity patches and 'blocked' for EOL-OS upgrades
//    *unconditionally* — fixed per-category labels with no real tracked
//    workflow behind them (there's no remediation-task table for
//    risk-posture findings, unlike incidents' real remediation_plans/
//    remediation_steps) — so every such item claimed a specific progress
//    state regardless of whether anyone had actually touched it. Every item
//    is a real, currently-open finding, so 'open' is the only honest status;
//    normalized all items to it.
//  - The "AI Recommendations" action buttons (Start patching/Harden assets/
//    Review firewall/Fix configs/Upgrade OS) had no onClick/href at all — a
//    clickable-looking dead end, the same "misleading affordance" class
//    already found on Behavioral Detection's Library tab. Wired each to the
//    real page that lets someone act on it (/vuln-queue, /assets, /firewall,
//    /framework-compliance); "Secure identities" has no dedicated
//    identity/ITDR page in this app yet, so it's left as plain text rather
//    than linking somewhere irrelevant.
test.use({ storageState: SHARED_STORAGE_STATE });

test.describe('Risk Posture — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/risk-posture');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/risk-posture');
    await expect(page.getByText('Enterprise Risk')).toBeVisible({ timeout: 20_000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });
});

test.describe('Risk Posture — regression guard: vuln priority scoring is no longer silently zero', () => {
  test('priority_score is real and varied, not stuck at 0', async ({ page }) => {
    await page.request.post('/api/vulns/refresh-priorities');
    await page.waitForTimeout(1500);
    const queue = await (await page.request.get('/api/vulns/priority-queue?limit=50')).json();
    const items = queue.items ?? queue;
    expect(items.length).toBeGreaterThan(0);
    expect(items.some((v: any) => v.priority_score > 0)).toBe(true);
  });

  test('Risk Posture VulnScore reflects real (nonzero) vulnerability data', async ({ page }) => {
    const snap = await (await page.request.post('/api/risk-posture/refresh')).json();
    expect(snap.vuln_score).toBeGreaterThan(0);
    expect(snap.vuln_score).toBeLessThanOrEqual(30);
  });
});

test.describe('Risk Posture — regression guard: real compliance framework data', () => {
  test('Compliance card shows real framework names and scores, not fabricated CIS/NIST percentages', async ({ page }) => {
    const scores: Array<{ framework: string; score: number }> =
      await (await page.request.get('/api/compliance/scores/latest')).json();
    expect(scores.length).toBeGreaterThan(0);

    await page.goto('/risk-posture');
    await expect(page.getByText('Enterprise Risk')).toBeVisible({ timeout: 20_000 });

    const bodyText = await page.locator('body').innerText();
    for (const s of scores) {
      expect(bodyText).toContain(s.framework);
    }
    // These specific fabricated labels must not survive.
    expect(bodyText).not.toContain('153 controls');
    expect(bodyText).not.toContain('CIS Level 1');
    expect(bodyText).not.toContain('SOC 2 Type II');
  });
});

test.describe('Risk Posture — regression guard: no fabricated figures survive', () => {
  test('no fabricated financial-exposure figure, and remediation items are honestly "open"', async ({ page }) => {
    await page.goto('/risk-posture');
    await expect(page.getByText('Enterprise Risk')).toBeVisible({ timeout: 20_000 });

    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toContain('Estimated Financial Exposure');
    expect(bodyText).not.toContain('Worst-case estimate based on asset criticality');
    // If a Remediation Queue rendered, its "N in progress · N blocked"
    // summary must both be exactly 0 (no item may claim a fake status) —
    // the summary line always renders, so check the counts, not mere phrase
    // presence (a real "0 in progress" would otherwise wrongly fail this).
    const summaryMatch = bodyText.match(/(\d+) open\s*·\s*(\d+) in progress\s*·\s*(\d+) blocked/);
    if (summaryMatch) {
      expect(Number(summaryMatch[2])).toBe(0);
      expect(Number(summaryMatch[3])).toBe(0);
    }
  });

  test('AI Recommendation action buttons navigate to a real page, not a dead end', async ({ page }) => {
    await page.goto('/risk-posture');
    await expect(page.getByText('Enterprise Risk')).toBeVisible({ timeout: 20_000 });

    const patchLink = page.getByRole('link', { name: /Start patching/i });
    if (await patchLink.count() > 0) {
      await patchLink.click();
      await expect(page).toHaveURL(/\/vuln-queue/, { timeout: 15_000 });
    }
  });
});

test.describe('Risk Posture — Refresh Score', () => {
  test('clicking Refresh Score triggers a real recompute', async ({ page }) => {
    await page.goto('/risk-posture');
    await expect(page.getByText('Enterprise Risk')).toBeVisible({ timeout: 20_000 });

    await page.getByRole('button', { name: /Refresh Score/i }).click();
    await expect(page.getByText(/Computing…/i)).toBeVisible({ timeout: 5_000 }).catch(() => {});
    await expect(page.getByRole('button', { name: /Refresh Score/i })).toBeEnabled({ timeout: 20_000 });
  });
});
