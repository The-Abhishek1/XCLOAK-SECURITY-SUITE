import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the SOC Metrics page (route /soc-metrics) —
// backed by sme_* tables (api/soc_metrics_enterprise.go).
//
// Real bugs found and fixed this pass:
// - GetSMEVulns hardcoded "exploitable" to 0 always, even though
//   vulnerabilities.is_kev (CISA KEV) is a real, already-populated column —
//   fixed to count real is_kev=true rows (via the same agents-join style
//   already used by this handler's other vuln queries).
// - GetSMEEndpoints hardcoded blocked_connections/dpi_events/
//   network_throughput_gbps to 0 always. blocked_connections and dpi_events
//   both have genuinely real sources elsewhere in this codebase — fwe_blocked
//   + ioc_firewall_blocks (the same two tables the Firewall page's Blocked
//   List bridges) and dpi_findings (a real per-agent DPI-detection table) —
//   bridged both. network_throughput_gbps has no real source anywhere in
//   this codebase (no live byte-counting exists) — dropped from the API
//   response and the frontend rather than left as an indistinguishable fake
//   zero.
// - GetSMEAutomation's approval_queue hardcoded approved/rejected/
//   avg_wait_mins to 0 always. agent_tasks loses the approved/rejected
//   distinction once an approved task re-enters the normal 'pending' queue,
//   but task_approval.go's ApproveTask/RejectTask both write a real,
//   distinguishable event to audit_logs (SOAR_ACTION_APPROVED/_REJECTED) —
//   bridged approved/rejected to real counts from there. avg_wait_mins has
//   no reliable per-task correlation recoverable from that free-text audit
//   trail and was dropped rather than fabricated.
// - GetSMECompliance hardcoded policy_violations to 0 always — no
//   tenant-wide policy-violation tracking exists anywhere in this codebase
//   (mdm_policies/email_policies/etc are page-specific, not a generic SOC
//   metric) — dropped from the response and the frontend.
// - PostSMEReport inserted a metadata-only row with a fake randomish
//   size_bytes (200_000+rand(600_000)) and left the table's own summary
//   column permanently NULL/empty — the schema clearly intended real report
//   content but nothing ever produced it, and GetSMEReports didn't even
//   SELECT the column. Now generates a real LLM-grounded summary from the
//   same real sme_snapshots metrics PostSMEAI already gathers, with
//   size_bytes reflecting the real generated content's length. Added a
//   "View" action + modal to the frontend's Reports tab so the real content
//   is actually visible somewhere, since nothing rendered it before.
// - The page fetched real notifications (GetSMENotifications) into state but
//   had no Notifications tab anywhere to display them, and the header's
//   unread-count bell jumped to the Audit tab instead — markNotificationsRead
//   was never called from anywhere on this page. Every other page this phase
//   has a real Notifications tab; added one here too (list + mark-all-read),
//   matching the established pattern, and repointed the bell at it.
// - Frontend: the report-generation button silently swallowed errors via
//   `.catch(() => null)` with zero user feedback on failure — fixed to
//   surface real errors.
// - This page's own pre-existing seeder had the same non-idempotency bug
//   found on the last five pages: sme_snapshots/sme_analyst_perf/
//   sme_detection_rules/sme_playbook_stats/sme_reports all have real unique
//   constraints and were already genuinely idempotent, but sme_notifications/
//   sme_audit have none (each row is a historical event, not a config row).
//   Confirmed live: 500/600 rows had accumulated (vs. ~10/~12 intended)
//   before a standard tenant-count guard was added.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = [
  'Dashboard', 'Alerts', 'Incidents', 'Cases', 'Analysts', 'Detection', 'Automation',
  'Threats', 'Endpoints', 'Vulnerabilities', 'Compliance', 'Infrastructure',
  'AI Insights', 'Reports', 'Notifications', 'Audit Trail',
];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('SOC Metrics — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/soc-metrics');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('main').getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/soc-metrics');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('main').getByRole('button', { name: new RegExp(`^${label}\\b`) }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('SOC Metrics — regression guard: seed data exists and is not duplicated', () => {
  test('snapshots/analyst_perf/rules/playbooks/reports/notifications/audit show the intended counts', async ({ page }) => {
    const expected: Record<string, number> = {
      sme_snapshots: 91, sme_analyst_perf: 210, sme_detection_rules: 15,
      sme_playbook_stats: 10, sme_reports: 8, sme_notifications: 10, sme_audit: 12,
    };
    for (const [table, count] of Object.entries(expected)) {
      const real = Number(PSQL(`SELECT count(*) FROM ${table} WHERE tenant_id='9999';`));
      expect(real, `${table} row count`).toBeGreaterThanOrEqual(count);
      expect(real, `${table} row count should not be a multiplied duplicate pile`).toBeLessThan(count * 3);
    }
  });
});

test.describe('SOC Metrics — regression guard: real bridged data, not hardcoded zeros', () => {
  test('vulns.exploitable reflects the real is_kev count', async ({ page }) => {
    const realKev = Number(PSQL(`SELECT count(*) FROM vulnerabilities v JOIN agents a ON a.id=v.agent_id WHERE a.tenant_id=9999 AND v.is_kev=true;`));
    expect(realKev).toBeGreaterThan(0);
    const vulns = await page.request.get('/api/sme/vulns').then(r => r.json());
    expect(vulns.exploitable).toBe(realKev);
  });

  test('endpoints.blocked_connections/dpi_events reflect real data, and network_throughput_gbps is dropped', async ({ page }) => {
    const realBlocked = Number(PSQL(`SELECT count(*) FROM fwe_blocked WHERE tenant_id='9999' AND active=true;`))
      + Number(PSQL(`SELECT count(*) FROM ioc_firewall_blocks WHERE tenant_id=9999;`));
    const realDpi = Number(PSQL(`SELECT count(*) FROM dpi_findings WHERE tenant_id=9999;`));
    expect(realDpi).toBeGreaterThan(0);

    const endpoints = await page.request.get('/api/sme/endpoints').then(r => r.json());
    expect(endpoints.blocked_connections).toBe(realBlocked);
    expect(endpoints.dpi_events).toBe(realDpi);
    expect(endpoints).not.toHaveProperty('network_throughput_gbps');
  });

  test('automation.approval_queue reflects real audit_logs counts, and avg_wait_mins is dropped', async ({ page }) => {
    const realApproved = Number(PSQL(`SELECT count(*) FROM audit_logs WHERE tenant_id=9999 AND action='SOAR_ACTION_APPROVED';`));
    const realRejected = Number(PSQL(`SELECT count(*) FROM audit_logs WHERE tenant_id=9999 AND action='SOAR_ACTION_REJECTED';`));

    const automation = await page.request.get('/api/sme/automation').then(r => r.json());
    expect(automation.approval_queue.approved).toBe(realApproved);
    expect(automation.approval_queue.rejected).toBe(realRejected);
    expect(automation.approval_queue).not.toHaveProperty('avg_wait_mins');
  });

  test('compliance drops the unbackable policy_violations field', async ({ page }) => {
    const compliance = await page.request.get('/api/sme/compliance').then(r => r.json());
    expect(compliance).not.toHaveProperty('policy_violations');
    expect(compliance).toHaveProperty('compliance_score');
  });
});

test.describe('SOC Metrics — regression guard: report generation produces real content', () => {
  test('a generated report has a real summary and a real (small, honest) size_bytes, not a fake random number', async ({ page }) => {
    const res = await page.request.post('/api/sme/reports', {
      data: { title: 'e2e-real-content-check', report_type: 'daily_operations', period_days: 1 },
    });
    expect(res.ok()).toBeTruthy();
    const created = await res.json();
    expect(created.summary).toBeTruthy();
    expect(created.summary.length).toBeGreaterThan(10);

    const reports = await page.request.get('/api/sme/reports').then(r => r.json());
    const match = reports.find((r: any) => r.report_id === created.report_id);
    expect(match).toBeTruthy();
    expect(match.summary).toBe(created.summary);
    // The old fake value was always in the 200000-800000 range regardless of
    // any real content — a real summary's byte length should never land there.
    expect(match.size_bytes).toBeGreaterThan(0);
    expect(match.size_bytes).toBeLessThan(200_000);

    PSQL(`DELETE FROM sme_audit WHERE tenant_id='9999' AND object_id='${created.report_id}'; DELETE FROM sme_notifications WHERE tenant_id='9999' AND title LIKE '%e2e-real-content-check%'; DELETE FROM sme_reports WHERE report_id='${created.report_id}';`);
  });
});

test.describe('SOC Metrics — regression guard: notifications can actually be marked read', () => {
  test('the Notifications tab renders real notifications and mark-all-read persists to the database', async ({ page }) => {
    PSQL(`UPDATE sme_notifications SET read=FALSE WHERE tenant_id='9999';`);
    const unreadBefore = Number(PSQL(`SELECT count(*) FROM sme_notifications WHERE tenant_id='9999' AND read=FALSE;`));
    expect(unreadBefore).toBeGreaterThan(0);

    await page.goto('/soc-metrics');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    await page.getByRole('button', { name: /^Notifications\b/ }).click();
    await expect(page.getByRole('button', { name: /Mark all read/ })).toBeVisible();
    const [patchResp] = await Promise.all([
      page.waitForResponse(r => r.url().includes('/api/sme/notifications/read') && r.request().method() === 'PATCH'),
      page.getByRole('button', { name: /Mark all read/ }).click(),
    ]);
    expect(patchResp.ok()).toBeTruthy();
    await page.waitForTimeout(300);

    const unreadAfter = Number(PSQL(`SELECT count(*) FROM sme_notifications WHERE tenant_id='9999' AND read=FALSE;`));
    expect(unreadAfter).toBe(0);
  });
});
