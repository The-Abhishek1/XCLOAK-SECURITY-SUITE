import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { SHARED_STORAGE_STATE } from './global-setup';

// Live-data integrity tests for the Email Security page (route
// /email-security) — mail flow, phishing/BEC/malware detection, SPF/DKIM/
// DMARC auth, sender intel, threat intel, response actions.
//
// This page had the largest fabrication footprint found so far this phase,
// spread across three GET endpoints plus the response-action dispatcher:
//
// - `PostEmailResponse` was a pure canned-message lookup table with zero
//   side effects for every action (quarantine/delete/block_*/reset_password/
//   create_incident all just returned "Action executed", and any unknown
//   action string — including typos — silently returned success too).
//   Rewritten to perform real work: quarantine/delete_email now really
//   UPDATE email_messages, block_* now create real enabled IOCs via
//   repositories.CreateIOC (with block_hash auto-detecting IOC type via
//   services.GuessIOCType), reset_password calls the real, existing,
//   anti-enumeration services.RequestPasswordReset, create_incident does a
//   real INSERT INTO incidents, and an unrecognized action now correctly
//   400s instead of lying about success.
// - `GetEmailAuthResults` computed spf/dkim/dmarc pass rates as fixed
//   percentages of the total message count (78/82/71%) regardless of any
//   message's actual auth result, and its per-domain table was a hardcoded
//   7-domain array (including literal "suspicious-bank.xyz") identical for
//   every tenant. Rewritten to aggregate real per-message spf_result/
//   dkim_result/dmarc_result columns and a real GROUP BY sender domain
//   query. ARC/BIMI were dropped entirely (no per-message signal exists for
//   either) rather than kept fabricated — the frontend had independently
//   hardcoded ARC:42/BIMI:31 rates and a literal "29% of inbound emails
//   fail DMARC" string, both removed too.
// - `GetSenderIntelligence` used a crude substring match on the domain
//   ("xyz" → malicious) and returned fully invented WHOIS/GeoIP/ASN/
//   domain-age fields. Rewritten to derive reputation from real IOC hits
//   and real email_urls malicious-verdict counts; the fabricated fields
//   were removed from the response entirely rather than kept fake.
// - `GetEmailThreatIntel` returned four fully hardcoded arrays (malicious
//   domains/IPs, malware families, threat actors) with specific fake
//   values identical regardless of tenant. Rewritten to derive
//   malicious_domains from real email_urls (verdict='malicious') and
//   threat_actors from the real (previously never-aggregated)
//   email_campaigns.threat_actor column; malicious_ips and malware_families
//   were removed — no real source-IP or structured malware-family field
//   exists anywhere in the email schema.
//
// Also found: this page's Response tab silently dropped the message_id/
// email fields when submitting quarantine_email/delete_email/reset_password
// (it only ever sent sender/domain/url/hash from the same free-text input),
// so those three of nine response actions could never have worked from the
// UI even after the backend fix — fixed to send all target fields. And a
// `run_soar_playbook` action existed in the UI with no real backend
// implementation (matching the same fake-SOAR-action pattern already fixed
// on Threat Hunt/DFIR) — replaced with the same real `<a href="/playbooks">`
// link used on those pages.
//
// Finally, like Cloud Security before it: all 7 of this page's own tables
// (email_messages/attachments/urls/campaigns/user_risk/reported/policies)
// had zero seed data anywhere in a fresh dev environment — added
// `seedEmailSecurity` to cmd/seed/demo/main.go, idempotency-guarded like
// every other keyless table this phase.
test.use({ storageState: SHARED_STORAGE_STATE });

const ALL_TABS = ['Dashboard', 'Inbox', 'Threats', 'Auth', 'Campaigns',
  'Intelligence', 'User Risk', 'Analytics', 'Response'];

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

test.describe('Email Security — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/email-security');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('page renders no NaN / undefined / [object Object] artifacts', async ({ page }) => {
    await page.goto('/email-security');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    for (const label of ALL_TABS) {
      await page.getByRole('button', { name: label, exact: true }).click();
      await page.waitForTimeout(300);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText, `tab "${label}"`).not.toMatch(/\bNaN\b|\bundefined\b|\[object Object\]/);
    }
  });
});

test.describe('Email Security — regression guard: seed data exists', () => {
  test('the dashboard shows real, non-zero counts instead of a permanently empty page', async ({ page }) => {
    const dash = await page.request.get('/api/email/dashboard').then(r => r.json());
    expect(dash.emails_processed).toBeGreaterThan(0);

    const count = PSQL(`SELECT count(*) FROM email_messages WHERE tenant_id=9999;`);
    expect(Number(count)).toBeGreaterThan(0);
  });
});

test.describe('Email Security — regression guard: auth results are real, not fixed percentages', () => {
  test('spf/dkim/dmarc rates reflect real per-message columns, and no ARC/BIMI fabrication remains', async ({ page }) => {
    const res = await page.request.get('/api/email/auth-results').then(r => r.json());
    expect(res.summary.total).toBeGreaterThan(0);

    const realSpfPass = Number(PSQL(`SELECT count(*) FROM email_messages WHERE tenant_id=9999 AND spf_result='pass';`));
    expect(res.summary.spf_pass).toBe(realSpfPass);

    expect(res.domains.length).toBeGreaterThan(0);
    for (const d of res.domains) {
      expect(d).not.toHaveProperty('arc');
      expect(d).not.toHaveProperty('bimi');
    }
    // The old hardcoded table always included this literal fake domain.
    const domainNames = res.domains.map((d: any) => d.domain);
    expect(domainNames).not.toContain('suspicious-bank.xyz');
  });
});

test.describe('Email Security — regression guard: sender intelligence is real, not invented WHOIS/geo', () => {
  test('a known-malicious domain from real seed data is correctly flagged, with no fabricated fields', async ({ page }) => {
    const res = await page.request.get('/api/email/sender-intel?domain=paypal-secure-verify.xyz').then(r => r.json());
    expect(res.reputation).toBe('malicious');
    expect(res.threat_intel_hits + res.email_volume_7d).toBeGreaterThanOrEqual(0);
    expect(res).not.toHaveProperty('domain_age_days');
    expect(res).not.toHaveProperty('whois_registrar');
    expect(res).not.toHaveProperty('geo_country');
    expect(res).not.toHaveProperty('asn');
  });

  test('a clean, unseen domain is not flagged malicious by a crude substring match', async ({ page }) => {
    const res = await page.request.get('/api/email/sender-intel?domain=example.com').then(r => r.json());
    expect(res.reputation).not.toBe('malicious');
  });
});

test.describe('Email Security — regression guard: threat intel is derived from real tables', () => {
  test('malicious_domains comes from real email_urls, and malicious_ips/malware_families are gone rather than fake', async ({ page }) => {
    const res = await page.request.get('/api/email/threat-intel').then(r => r.json());
    expect(res.malicious_domains.length).toBeGreaterThan(0);
    const domains = res.malicious_domains.map((d: any) => d.domain);
    expect(domains).toContain('paypal-secure-verify.xyz');
    expect(res).not.toHaveProperty('malicious_ips');
    expect(res).not.toHaveProperty('malware_families');
  });

  test('threat_actors comes from the real email_campaigns.threat_actor column', async ({ page }) => {
    const res = await page.request.get('/api/email/threat-intel').then(r => r.json());
    const actors = res.threat_actors.map((a: any) => a.actor);
    expect(actors).toContain('TA-Scattered-Spider');
  });
});

test.describe('Email Security — regression guard: response actions are real, not a canned message', () => {
  test('quarantine_email really updates the message row', async ({ page }) => {
    const msgId = PSQL(`SELECT message_id FROM email_messages WHERE tenant_id=9999 AND status != 'quarantined' ORDER BY id LIMIT 1;`);
    const res = await page.request.post('/api/email/response', {
      data: { action: 'quarantine_email', message_id: msgId },
    });
    expect(res.ok()).toBeTruthy();
    const status = PSQL(`SELECT status FROM email_messages WHERE tenant_id=9999 AND message_id='${msgId}';`);
    expect(status).toBe('quarantined');
  });

  test('quarantine_email without a message_id fails honestly instead of claiming success', async ({ page }) => {
    const res = await page.request.post('/api/email/response', { data: { action: 'quarantine_email' } });
    expect(res.status()).toBe(400);
  });

  test('block_domain creates a real, enabled IOC', async ({ page }) => {
    const domain = `e2e-phish-${Date.now()}.test`;
    const res = await page.request.post('/api/email/response', {
      data: { action: 'block_domain', domain },
    });
    expect(res.ok()).toBeTruthy();
    const count = PSQL(`SELECT count(*) FROM iocs WHERE indicator='${domain}' AND enabled=true;`);
    expect(Number(count)).toBe(1);
  });

  test('block_hash auto-detects the indicator type and creates a real IOC', async ({ page }) => {
    const hash = 'a'.repeat(64); // sha256-shaped
    const res = await page.request.post('/api/email/response', {
      data: { action: 'block_hash', hash },
    });
    expect(res.ok()).toBeTruthy();
    const type = PSQL(`SELECT type FROM iocs WHERE indicator='${hash}';`);
    expect(type).toBe('sha256');
  });

  test('reset_password reports success without leaking whether the email exists (anti-enumeration)', async ({ page }) => {
    const res = await page.request.post('/api/email/response', {
      data: { action: 'reset_password', email: 'definitely-not-a-real-user@xcloak-corp.com' },
    });
    expect(res.ok()).toBeTruthy();
  });

  test('create_incident really inserts an incidents row', async ({ page }) => {
    const before = Number(PSQL(`SELECT count(*) FROM incidents WHERE tenant_id=9999;`));
    const res = await page.request.post('/api/email/response', { data: { action: 'create_incident' } });
    expect(res.ok()).toBeTruthy();
    const after = Number(PSQL(`SELECT count(*) FROM incidents WHERE tenant_id=9999;`));
    expect(after).toBe(before + 1);
  });

  test('an unrecognized action is rejected rather than silently reporting success', async ({ page }) => {
    const res = await page.request.post('/api/email/response', {
      data: { action: 'not_a_real_action' },
    });
    expect(res.status()).toBe(400);
  });

  test('the Response tab no longer offers a fake run_soar_playbook action', async ({ page }) => {
    await page.goto('/email-security');
    await page.getByRole('button', { name: 'Response', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Run SOAR Playbook' })).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Run SOAR Playbook' })).toBeVisible();
  });
});
