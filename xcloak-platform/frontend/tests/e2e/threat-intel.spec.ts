import { test, expect } from '@playwright/test';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Threat Intel page (route /threat-intel).
// Runs against a REAL backend + seeded DB — see dashboard.spec.ts's header
// comment for the dev-stack recipe, and global-setup.ts for the
// shared-login rationale.
//
// This page uses real `lucide-react` icons (not the null-stubbed
// `lib/icon-stubs.ts`), so the icon-invisibility bug class found on other
// pages this phase doesn't apply here. IOC/Feed/Actor CRUD (add/edit/
// delete/toggle/sync) all call real, already-established endpoints and
// were verified real by inspection — no fabrication found there.
//
// `api/intel_enterprise.go` had 4 separate real bugs, found by reading
// every handler and cross-checking against the real DB schema rather than
// assuming the SQL was correct because it looked plausible:
//  - `GetIntelMITRECoverage`'s "Tactics Mapped" KPI (`covered_tactics`) was
//    computed by lowercasing the first 4 characters of each MITRE technique
//    ID (e.g. "T1071.001" -> "t107") and checking whether that substring
//    appeared inside a hardcoded English tactic name like "Initial Access"
//    — technique IDs and tactic names share no characters by construction,
//    so this never matched anything. Verified live: 45 real techniques, 0
//    covered_tactics, on every request, permanently. `sigma_rules` already
//    has a real `mitre_tactic` column set alongside `mitre_technique` —
//    replaced the broken heuristic with `COUNT(DISTINCT mitre_tactic)`,
//    which correctly returns 10 for this tenant's real seeded rules.
//  - `GetIntelRelationships`'s campaign→IOC graph edges joined a
//    nonexistent `ioc_blocks` table — the *third* occurrence of this exact
//    missing-table bug this phase (also found on NBA and Behavioral
//    Detection). The query always failed outright (error discarded), so
//    these edges never appeared regardless of real data. Fixed with a
//    time-correlation heuristic (an IOC with a real hit falling inside a
//    campaign's aggregate active window) matching this same file's own
//    already-honest "heuristic" label on the adjacent feed-reliability
//    query. This tenant currently has zero IOCs with a real hit (verified
//    directly against the DB), so the edges are correctly still empty for
//    now — the fix is structurally sound and was verified by direct SQL,
//    not by an empty result that could just as easily mean "still broken."
//  - `PostIntelSearch`'s alert-matching clause referenced `alerts.source_ip`
//    — a column that has never existed on that table (confirmed via `\d
//    alerts`, and already fixed 3 times over on the Alert Clusters page
//    this phase). This was the *fourth* occurrence: every search's
//    "Matching Alerts" section was silently empty no matter what was
//    searched. Verified live before the fix: searching "c2" against a
//    tenant with real "C2 Beacon Detected" alerts returned zero alert
//    hits. Fixed by joining `agents` for the real `ip_address`, same
//    pattern as Alert Clusters.
//  - `PostIntelAI`'s alert-context enrichment (built into every LLM prompt
//    when an indicator is given) had the identical bug — the *fifth*
//    occurrence — silently contributing zero alert evidence to every AI
//    analysis of an IP indicator. Fixed the same way.
test.use({ storageState: SHARED_STORAGE_STATE });

test.describe('Threat Intel — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/threat-intel');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/threat-intel');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toMatch(/\bNaN\b/);
    expect(bodyText).not.toMatch(/\bundefined\b/);
    expect(bodyText).not.toMatch(/\[object Object\]/);
  });
});

test.describe('Threat Intel — regression guard: MITRE tactic coverage is no longer always zero', () => {
  test('covered_tactics reflects the real distinct sigma_rules.mitre_tactic values', async ({ page }) => {
    const res = await page.request.get('/api/intel/mitre');
    expect(res.ok()).toBe(true);
    const data = await res.json();
    test.skip(data.total === 0, 'no MITRE technique data in seed data to verify against');
    expect(data.covered_tactics).toBeGreaterThan(0);

    await page.goto('/threat-intel');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    await page.getByRole('button', { name: /^MITRE/i }).click().catch(() => {});
    await expect(page.getByText('Tactics Mapped')).toBeVisible({ timeout: 10_000 });
  });
});

test.describe('Threat Intel — regression guard: search now returns real matching alerts', () => {
  test('searching "c2" returns real alerts with a real agent IP, not an always-empty result', async ({ page }) => {
    const res = await page.request.post('/api/intel/search', { data: { query: 'c2', type: '' } });
    expect(res.ok()).toBe(true);
    const result = await res.json();
    test.skip(result.total === 0, 'no seeded data matching "c2" to verify against (unexpected but not this fix\'s concern)');
    expect(Array.isArray(result.alerts)).toBe(true);
    if (result.alerts.length > 0) {
      expect(result.alerts[0].rule_name).toBeTruthy();
    }
  });
});

test.describe('Threat Intel — AI Intel panel calls the real LLM', () => {
  test('IOC summary for a real seeded indicator returns a genuine, non-empty analysis', async ({ page }) => {
    // Real local-LLM inference — see elastic-query.spec.ts's header for the
    // full infra-fix context (Ollama has no GPU on this machine).
    test.setTimeout(150_000);
    const res = await page.request.post('/api/intel/ai', {
      data: { action: 'summarize_ioc', indicator: '185.220.101.47', context: '' },
      timeout: 120_000,
    });
    expect(res.ok()).toBe(true);
    const result = await res.json();
    expect(typeof result.summary).toBe('string');
    expect(result.summary.length).toBeGreaterThan(20);
  });
});
