import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Cases page (route /cases) — the highest-
// severity bug of the whole page-testing phase: `cases_enterprise.go` and
// `repositories/case_repository.go` (used by `api/cases.go`, the Executive
// dashboard, and a background SLA-breach checker) both defined a table
// literally named `cases`, but only the repository's version matches the
// real, migrated schema. `cases_enterprise.go`'s `CREATE TABLE IF NOT
// EXISTS` was a permanent no-op against the real table, so every one of its
// handlers queried columns that never existed (case_id, priority, owner,
// team, due_date, sla_status, linked_incidents, linked_alerts, content,
// author, is_internal, evidence_id, file_hash, collector, current_owner,
// verified, custody_chain, notes) — with the query errors silently
// swallowed in most places, so the entire Cases page looked merely "empty",
// not broken, in a fresh dev environment.
//
// Confirmed live via psql: `SELECT case_id FROM cases` failed with a real
// Postgres "column does not exist" error against the actual table.
//
// Fix (approved via AskUserQuestion — "fix queries to real schema + add
// tags/template columns"): every handler rewritten to the real cases /
// case_alerts / case_comments / case_evidence columns. Concepts with no real
// column and real frontend usage got a defensive `ALTER TABLE ADD COLUMN IF
// NOT EXISTS` (cases.tags/template; case_evidence.file_hash/collector/
// current_owner/verified/custody_chain). Concepts with no real column and no
// real usage were dropped outright (`team` — zero display usage anywhere,
// confirmed via grep; `linked_incidents`/`linked_alerts` as free text, since
// the real relational `case_alerts` junction table already exists for this
// and isn't currently surfaced in this page's UI). `case_id`/`evidence_id`
// are now derived from the real `id` (`CASE-%04d`/`EVD-%04d`) instead of
// stored. `sla_status` is now derived from the real `sla_breached`/
// `sla_breach_at` columns via `caseSLAStatus()`. `GetCasesEnt`/`PostCase`
// now check and surface real query errors instead of silently returning an
// empty list / claiming success on a failed INSERT. `DeleteCaseEnt` now also
// cleans up `case_tasks`/`case_notes`/`case_timeline`, which have no real FK
// cascade unlike `case_alerts`/`case_comments`/`case_evidence`.
//
// Also fixed: `applyTemplate()` only ever pre-filled the create form for
// display — selecting a template never actually created its task checklist.
// `PostCase` now auto-creates real `case_tasks` rows from the template's
// task list (`caseTemplateTasks` map, kept in sync with the existing, only
// lightly pre-existing `GetCasesTemplates` reference content) when a
// `template` is supplied.
//
// Also fixed: `casesAPI`'s write methods (createCase/updateCase/deleteCase/
// createTask/updateTask/addEvidence/addNote/addComment/linkAlert/
// unlinkAlert) had the same `.catch(() => ({ data: null }))` silent-error-
// swallowing anti-pattern found on Process Injection/Defense Evasion earlier
// this phase — fixed to let errors propagate, with real try/catch added at
// each call site.
//
// Also fixed: the seeded `cmd/seed/demo/main.go`'s `seedCases` had zero
// idempotency guard, unlike every other seeder this phase — confirmed live
// it had silently 18x-duplicated its 3 cases in this dev environment.
// Cleaned up the duplicates and added an existence-check guard, enriched
// with real `sla_breach_at`/`sla_breached`/`assigned_to_name`/`tags`/
// `template` values so the newly-real SLA/tags/template/analyst-workload
// features have real data to exercise.
//
// Also fixed: the seeded data includes real "investigating"/"resolved"
// statuses (this schema's status column is free text, not a fixed enum —
// confirmed via repositories.GetCaseMetrics's own `status NOT IN
// ('closed','recovered')` open-case definition) that neither the frontend's
// STATUS_COLOR/STATUS_LABEL maps nor the dashboard's 5-bucket status counts
// recognized — cases in either status fell through every dashboard bucket
// and rendered with an `undefined` badge color. Added both statuses to the
// frontend maps/filter, and folded them into the closest existing dashboard
// bucket (investigating→in_progress, resolved→closed) so every case is
// counted somewhere without redesigning the dashboard's fixed card layout.
//
// Also removed the redundant "Priority" field from the create-case form —
// the real schema has no independent priority column (the old fake schema's
// `priority` was a wholly separate, never-actually-different-from-severity
// concept); `caseJSON.Priority` is now just an alias for `Severity`.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = ['Dashboard', 'Cases', 'Tasks', 'Evidence', 'Notebook', 'Timeline', 'Analytics', 'Response & AI'];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Cases — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/cases');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/cases');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('Cases — regression guard: the core schema-collision bug is fixed', () => {
  test('GET /api/cases returns real, non-empty data instead of a silently-empty list', async ({ page }) => {
    const res = await page.request.get('/api/cases');
    expect(res.ok()).toBeTruthy();
    const cases = await res.json();
    const realCount = Number(PSQL(`SELECT count(*) FROM cases WHERE tenant_id=9999;`));
    expect(realCount).toBeGreaterThan(0);
    expect(cases.length).toBe(realCount);
    expect(cases[0]).toHaveProperty('case_id');
    expect(cases[0].case_id).toMatch(/^CASE-\d{4}$/);
  });

  test('GET /api/cases/dashboard shows real, non-zero counts', async ({ page }) => {
    const dash = await page.request.get('/api/cases/dashboard').then(r => r.json());
    const total = dash.open + dash.in_progress + dash.waiting_approval + dash.escalated + dash.closed;
    const realCount = Number(PSQL(`SELECT count(*) FROM cases WHERE tenant_id=9999;`));
    expect(total).toBe(realCount);
  });

  test('POST /api/cases really inserts a row into the real cases table', async ({ page }) => {
    const before = Number(PSQL(`SELECT count(*) FROM cases WHERE tenant_id=9999;`));
    const res = await page.request.post('/api/cases', {
      data: { title: 'E2E regression test case', description: 'created by cases.spec.ts', severity: 'medium', owner: 'e2e-runner', tags: 'e2e' },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.ok).toBe(true);
    expect(body.id).toBeGreaterThan(0);

    const after = Number(PSQL(`SELECT count(*) FROM cases WHERE tenant_id=9999;`));
    expect(after).toBe(before + 1);

    const title = PSQL(`SELECT title FROM cases WHERE id=${body.id};`);
    expect(title).toBe('E2E regression test case');
  });

  test('POST /api/cases without a title fails honestly instead of claiming success', async ({ page }) => {
    const res = await page.request.post('/api/cases', { data: { description: 'no title' } });
    expect(res.status()).toBe(400);
  });
});

test.describe('Cases — regression guard: template task auto-creation', () => {
  test('creating a case with a template really creates its checklist as real case_tasks rows', async ({ page }) => {
    const res = await page.request.post('/api/cases', {
      data: { title: 'E2E ransomware case', severity: 'critical', template: 'ransomware' },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();

    const taskCount = Number(PSQL(`SELECT count(*) FROM case_tasks WHERE case_id=${body.id};`));
    expect(taskCount).toBe(7); // caseTemplateTasks['ransomware'] has 7 entries

    const firstTask = PSQL(`SELECT title FROM case_tasks WHERE case_id=${body.id} ORDER BY id LIMIT 1;`);
    expect(firstTask).toBe('Isolate affected hosts');
  });
});

test.describe('Cases — regression guard: SLA status is derived from real columns', () => {
  test('a case seeded as already-breached shows BREACH in the list', async ({ page }) => {
    const cases = await page.request.get('/api/cases').then(r => r.json());
    const c2Case = cases.find((c: any) => c.title.includes('C2 Implant Investigation'));
    expect(c2Case).toBeTruthy();
    expect(c2Case.sla_status).toBe('breach');
  });

  test('a case with no sla_breach_at set reports ok, not a crash', async ({ page }) => {
    const res = await page.request.post('/api/cases', { data: { title: 'E2E no-SLA case', severity: 'low' } });
    const body = await res.json();
    const detail = await page.request.get(`/api/cases/${body.id}`).then(r => r.json());
    expect(detail.sla_status).toBe('ok');
  });
});

test.describe('Cases — regression guard: comments and evidence use the real schema', () => {
  test('adding a comment persists to the real case_comments table with the real authenticated username', async ({ page }) => {
    const cid = Number(PSQL(`SELECT id FROM cases WHERE tenant_id=9999 ORDER BY id LIMIT 1;`));
    const res = await page.request.post(`/api/cases/${cid}/comments`, { data: { content: 'e2e comment' } });
    expect(res.ok()).toBeTruthy();

    const row = PSQL(`SELECT body, username FROM case_comments WHERE case_id=${cid} ORDER BY id DESC LIMIT 1;`);
    expect(row).toBe('e2e comment|admin');
  });

  test('adding evidence persists to the real case_evidence table with a derived evidence_id', async ({ page }) => {
    const cid = Number(PSQL(`SELECT id FROM cases WHERE tenant_id=9999 ORDER BY id LIMIT 1;`));
    const res = await page.request.post(`/api/cases/${cid}/evidence`, {
      data: { title: 'e2e evidence', evidence_type: 'log', file_hash: 'deadbeef', collector: 'e2e-runner', notes: 'test note' },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.evidence_id).toMatch(/^EVD-\d{4}$/);

    const row = PSQL(`SELECT title, description, file_hash FROM case_evidence WHERE id=${body.id};`);
    expect(row).toBe('e2e evidence|test note|deadbeef');
  });

  test('a comment/evidence request for a case in another tenant is rejected', async ({ page }) => {
    const res = await page.request.post('/api/cases/999999/comments', { data: { content: 'should not land' } });
    expect(res.status()).toBe(404);
  });
});

test.describe('Cases — regression guard: seeder is idempotent and enriched with real SLA/owner/tags data', () => {
  test('seeded cases carry real assigned_to_name, tags, and template values', async ({ page }) => {
    const row = PSQL(`SELECT assigned_to_name, tags, template FROM cases WHERE tenant_id=9999 AND title LIKE 'C2 Implant%';`);
    expect(row).toBe('admin|c2,malware,lateral-movement|malware');
  });
});
