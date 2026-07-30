import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Playbooks & SOAR page (route
// /playbooks) — a visual drag-and-drop workflow builder (node/edge graph:
// 10 trigger types, 8 logic ops incl. IF/LOOP/PARALLEL, 12 actions, 5
// human-in-loop gates) sitting on `pb_*` tables, a separate system from the
// simpler auto-triggered `playbooks`/`playbook_actions` engine used
// elsewhere in the app (Correlation/Dashboard).
//
// The core finding: PostPBExecute created a pb_executions row with
// status='running' and NOTHING ever completed it — every real "Execute"
// click left a permanently-stuck fake-running execution forever, since no
// execution engine of any kind processed the workflow graph. Dry Run,
// Versions, and most of Analytics/Report were also 100% hardcoded
// fabrication unrelated to the real workflow being edited. Confirmed via
// AskUserQuestion: user chose "build a simplified real executor" over
// leaving execution honestly inert.
//
// Built `api/playbook_workflow_engine.go`: walks the workflow's node/edge
// graph in order (ignoring IF/LOOP/PARALLEL/WAIT/RETRY branching logic —
// treated as linear pass-through) and dispatches every reachable action
// node using a single new `target` config field (added to the action
// config panel, which previously had no way to specify a concrete
// IP/hostname/username at all). 6 of 12 action types now do real work
// reusing primitives already built this phase (Block IP/Domain → real IOC,
// Isolate Endpoint → real agent-task dispatch, Disable User → real
// ad_users UPDATE, Reset Password → real services.RequestPasswordReset,
// Update Firewall → real firewall_rules INSERT); the other 6 (Quarantine
// File, Kill Process — need 2 args the single target field can't carry;
// Send Email, Create Ticket, Run Script — no real integration exists
// anywhere in this codebase) honestly report "skipped" with a specific
// reason instead of faking success. A non-automatic human-in-loop gate now
// creates a real pb_approvals row and halts the walk there (no resume
// engine — halting honestly beats silently skipping the gate or hanging
// forever), finally giving the previously-dead, fully-built Approvals tab
// (real approve/reject/escalate UI, zero rows ever created) real data.
//
// Also fixed: GetPBVersions was 100% hardcoded (3 fake versions, ignored
// the given playbook id entirely) — added a real pb_playbook_versions
// table, populated on every real Publish. GetPBAnalytics's avg_runtime_s/
// automation_coverage/most_used/manual_vs_automated/failed_steps/trend were
// all hardcoded despite the real aggregations being one query away (the
// hardcoded trend array's dates — "07-09" etc. — were also already stale
// relative to any date after they were written) — wired to real queries.
// PostPBReport was a fully fabricated static report (247 executions, 94.7%
// success rate, fictional recommendations) — rewritten to real key_metrics
// plus an LLM-generated summary grounded only in those real numbers (with
// an honest non-LLM fallback).
//
// Found and fixed a real, separate bug while wiring up Approvals live: the
// new pb_approvals rows have a nullable `approver`/`notes` column that were
// NULL until decided, but GetPBApprovals scanned them into plain Go
// `string` fields — every approval row silently failed to scan and the
// whole list came back empty (verified live: direct SQL returned 2 real
// rows, the API returned `[]`) — fixed with COALESCE in the query.
//
// Also removed a whole fabricated "Variables" tab (confirmed via
// AskUserQuestion): claimed to be a "Global Variable Store... secrets
// encrypted at rest" but was pure client-side useState with 8 hardcoded
// fake variables (including fake masked secrets for a firewall API key,
// Slack webhook, CrowdStrike tenant ID) and zero backend call anywhere —
// anything a user "saved" vanished on refresh without ever having been
// stored, let alone encrypted.
//
// Like every other page this phase: none of this page's 5 own tables had
// any seed data anywhere in a fresh dev environment — added
// seedPBWorkflows to cmd/seed/demo/main.go (4 playbooks with real node/
// edge workflow graphs, 4 executions spanning success/failed/pending-
// approval, a real pending pb_approvals row, real pb_playbook_versions
// rows for the active playbooks, and one pb_schedule), idempotency-guarded
// like every other keyless table this phase.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = ['Dashboard', 'Library', 'Builder', 'Executions', 'Approvals',
  'Analytics', 'Templates', 'Marketplace', 'AI Assistant', 'Reports'];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Playbooks — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/playbooks');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      // Approvals carries a real "(N pending)" count badge in its label
      // once real pb_approvals rows exist, so match by prefix rather than
      // requiring an exact "Approvals" string.
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/playbooks');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });

  test('the removed Variables tab no longer exists', async ({ page }) => {
    await page.goto('/playbooks');
    await expect(page.getByRole('button', { name: 'Variables' })).toHaveCount(0);
  });
});

test.describe('Playbooks — regression guard: seed data exists', () => {
  test('the library and dashboard show real seeded playbooks, not an empty page', async ({ page }) => {
    const lib = await page.request.get('/api/pb/library').then(r => r.json());
    const realCount = Number(PSQL(`SELECT count(*) FROM pb_playbooks WHERE tenant_id=9999;`));
    expect(realCount).toBeGreaterThan(0);
    expect(lib.length).toBe(realCount);

    const dash = await page.request.get('/api/pb/dashboard').then(r => r.json());
    expect(dash.total_playbooks).toBe(realCount);
  });
});

test.describe('Playbooks — regression guard: execution really runs the real workflow instead of hanging as "running" forever', () => {
  test('executing "IOC Block" (a single Update Firewall action, no approval gate) really adds a firewall rule and resolves to success', async ({ page }) => {
    const pbID = Number(PSQL(`SELECT id FROM pb_playbooks WHERE tenant_id=9999 AND name='IOC Block';`));
    const before = Number(PSQL(`SELECT count(*) FROM firewall_rules WHERE tenant_id=9999 AND source_ip='203.0.113.9';`));

    const res = await page.request.post(`/api/pb/library/${pbID}/execute`, { data: { trigger_type: 'manual' } });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.status).toBe('success');

    const after = Number(PSQL(`SELECT count(*) FROM firewall_rules WHERE tenant_id=9999 AND source_ip='203.0.113.9';`));
    expect(after).toBe(before + 1);

    const dbStatus = PSQL(`SELECT status FROM pb_executions WHERE execution_id='${body.execution_id}';`);
    expect(dbStatus).toBe('success');
    expect(dbStatus).not.toBe('running');
  });

  test('executing "Ransomware Containment" runs its real Block IP + Isolate Endpoint actions, then halts at its real approval gate', async ({ page }) => {
    const pbID = Number(PSQL(`SELECT id FROM pb_playbooks WHERE tenant_id=9999 AND name='Ransomware Containment';`));
    const before = Number(PSQL(`SELECT count(*) FROM iocs WHERE tenant_id=9999 AND indicator='185.220.101.45';`));

    const res = await page.request.post(`/api/pb/library/${pbID}/execute`, { data: { trigger_type: 'manual' } });
    const body = await res.json();
    expect(body.status).toBe('pending');

    const after = Number(PSQL(`SELECT count(*) FROM iocs WHERE tenant_id=9999 AND indicator='185.220.101.45';`));
    expect(after).toBeGreaterThan(before - 1); // real IOC exists (created this run or a prior one — CreateIOC dedupes)
    expect(after).toBeGreaterThan(0);

    const approvalCount = Number(PSQL(`SELECT count(*) FROM pb_approvals WHERE tenant_id=9999 AND execution_id='${body.execution_id}' AND status='pending';`));
    expect(approvalCount).toBe(1);
  });

  test('an execution never gets stuck on status=running', async ({ page }) => {
    const pbID = Number(PSQL(`SELECT id FROM pb_playbooks WHERE tenant_id=9999 AND name='Phishing Response';`));
    await page.request.post(`/api/pb/library/${pbID}/execute`, { data: { trigger_type: 'manual' } });
    const stuckCount = Number(PSQL(`SELECT count(*) FROM pb_executions WHERE tenant_id=9999 AND status='running';`));
    expect(stuckCount).toBe(0);
  });
});

test.describe('Playbooks — regression guard: dry run reflects the real workflow, not 8 fixed fake steps', () => {
  test('dry-running the 2-action Phishing Response workflow reports exactly its real steps', async ({ page }) => {
    const pbID = Number(PSQL(`SELECT id FROM pb_playbooks WHERE tenant_id=9999 AND name='Phishing Response';`));
    const res = await page.request.post(`/api/pb/library/${pbID}/dry-run`, { data: {} });
    const body = await res.json();
    const stepNames = body.step_results.map((s: any) => s.step);
    expect(stepNames).toEqual(['Manual Start', 'Block Domain', 'Reset Password', 'Send Email']);
    expect(body.step_results.find((s: any) => s.step === 'Send Email').status).toBe('skipped');
  });

  test('dry run never mutates real data', async ({ page }) => {
    const pbID = Number(PSQL(`SELECT id FROM pb_playbooks WHERE tenant_id=9999 AND name='IOC Block';`));
    const before = Number(PSQL(`SELECT count(*) FROM firewall_rules WHERE tenant_id=9999;`));
    await page.request.post(`/api/pb/library/${pbID}/dry-run`, { data: {} });
    const after = Number(PSQL(`SELECT count(*) FROM firewall_rules WHERE tenant_id=9999;`));
    expect(after).toBe(before);
  });
});

test.describe('Playbooks — regression guard: versions and approvals are real, not fabricated', () => {
  test('GetPBVersions returns real per-playbook history, not a fixed 3-entry fake list', async ({ page }) => {
    const activeID = Number(PSQL(`SELECT id FROM pb_playbooks WHERE tenant_id=9999 AND name='IOC Block';`));
    const draftID = Number(PSQL(`SELECT id FROM pb_playbooks WHERE tenant_id=9999 AND name='Password Spray Response';`));

    const activeVersions = await page.request.get(`/api/pb/library/${activeID}/versions`).then(r => r.json());
    expect(activeVersions.length).toBeGreaterThan(0);

    const draftVersions = await page.request.get(`/api/pb/library/${draftID}/versions`).then(r => r.json());
    expect(draftVersions).toEqual([]); // never published — genuinely no version history yet
  });

  test('GetPBApprovals returns real pending approvals instead of an empty list (the NULL-scan regression)', async ({ page }) => {
    const res = await page.request.get('/api/pb/approvals');
    expect(res.ok()).toBeTruthy();
    const approvals = await res.json();
    const realCount = Number(PSQL(`SELECT count(*) FROM pb_approvals WHERE tenant_id=9999;`));
    expect(realCount).toBeGreaterThan(0);
    expect(approvals.length).toBe(realCount);
  });

  test('deciding a pending approval really updates the real row', async ({ page }) => {
    const approvalID = Number(PSQL(`SELECT id FROM pb_approvals WHERE tenant_id=9999 AND status='pending' ORDER BY id LIMIT 1;`));
    const res = await page.request.post(`/api/pb/approvals/${approvalID}/decision`, { data: { decision: 'approved', notes: 'e2e test' } });
    expect(res.ok()).toBeTruthy();
    const status = PSQL(`SELECT status FROM pb_approvals WHERE id=${approvalID};`);
    expect(status).toBe('approved');
  });
});

test.describe('Playbooks — regression guard: analytics and reports use real aggregations', () => {
  test('analytics avg_runtime_s and automation_coverage are computed, not the old fixed 38.4 / 78.5', async ({ page }) => {
    const res = await page.request.get('/api/pb/analytics').then(r => r.json());
    const realAvg = Number(PSQL(`SELECT COALESCE(AVG(duration_s),0) FROM pb_executions WHERE tenant_id=9999 AND status IN ('success','failed');`));
    expect(Math.abs(res.avg_runtime_s - realAvg)).toBeLessThan(0.01);
    expect(res.avg_runtime_s).not.toBe(38.4);
    expect(res.automation_coverage).not.toBe(78.5);
  });

  test('report key_metrics reflect the real execution count, not a fixed 247', async ({ page }) => {
    const res = await page.request.post('/api/pb/report', { data: {} }).then(r => r.json());
    const realCount = Number(PSQL(`SELECT count(*) FROM pb_executions WHERE tenant_id=9999;`));
    expect(res.key_metrics.total_executions).toBe(realCount);
    expect(res.key_metrics.total_executions).not.toBe(247);
  });
});
