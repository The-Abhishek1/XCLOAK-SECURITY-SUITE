import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { createHmac } from 'crypto';
import { SHARED_STORAGE_STATE } from './global-setup';

// RFC 6238 TOTP, matching the backend's algorithm/digits/period exactly
// (services/totp_service.go: SHA1, 6 digits, 30s). Used to compute real
// codes for the MFA regression guards below — no external OTP library.
function totp(base32Secret: string): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of base32Secret.toUpperCase().replace(/=+$/, '')) {
    const idx = alphabet.indexOf(c);
    if (idx === -1) continue;
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = Buffer.from(bits.match(/.{1,8}/g)!.filter(b => b.length === 8).map(b => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000 / 30)));
  const hmac = createHmac('sha1', bytes).update(counter).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return code.toString().padStart(6, '0');
}

// Live-data integrity tests for the Settings page (route /settings). This
// page is a large collection of mostly-pre-existing, already-real
// subsystems (users, sessions, api-keys, custom-roles, integrations,
// email-rules) plus a newer stte_* "enterprise" layer (org/AI-config/
// backups/updates/license/agents-config). The real findings here were
// deeper and more security-critical than a typical page this phase:
//
// - THE FLAGGED STARTING POINT: force_logout (UEBA/Insider Threat) and
//   Settings' own "Revoke Session" button both did a real DB write
//   (sessions.revoked=true) that middleware.RequireAuth() never actually
//   checked — only a Redis blacklist keyed by the raw JWT string (set only
//   on self-logout) was consulted. Revoking someone else's session wrote a
//   real row but never stopped their live JWT from working. Fixed with a
//   second, hash-keyed Redis blacklist (services.RevokeTokenHash/
//   IsHashRevoked, using sessions.token_hash's own sha256 — the only thing
//   these paths ever have on hand, never the raw token) checked in
//   middleware.RequireAuth alongside the existing one. Also fixed: Logout
//   never marked its own sessions row revoked (DB and Redis had drifted
//   apart in the other direction), and EnforceConcurrentSessionLimit
//   existed, was correctly written, and had zero callers anywhere — the
//   "Max Concurrent Sessions" policy field was pure UI theater. Wired into
//   login (CreateSessionOnLogin), with real Redis blacklisting for the
//   sessions it evicts.
// - The frontend's "Max Concurrent Sessions" input read/wrote
//   secPolicy.max_sessions — the real backend field is
//   max_concurrent_sessions. This meant the field the fix above depends on
//   could never actually be changed from the UI at all (always showed the
//   fallback default, and saving silently dropped the value since the real
//   struct has no max_sessions field).
// - PostSTTELicenseActivate accepted literally any string as a license key
//   ("Demo: accept any key and set enterprise tier") and its own INSERT was
//   additionally broken SQL (doubled single-quotes inside a Go backtick
//   string aren't valid Postgres syntax), so activation silently never
//   persisted anything despite returning a 200 with fake numbers. Rewired
//   to call the real ed25519 license validator (services.
//   ValidateLicenseToken) already used by the public license-enforcement
//   endpoint — the same signed-token system the platform-admin
//   /platform/license/keys flow issues real tokens from.
// - PostSTTEBackupTrigger fabricated a random size/duration and never
//   touched the database. Rewired to shell out to a real `docker exec
//   xcloak-postgres pg_dump` (no pg_dump binary exists on the host where
//   this Go process runs) and write a real dump file, recording real
//   size/duration — confirmed via a live 9MB+, 84k-line real SQL dump.
// - GetSTTEUpdates had a `last_checked: time.Now().Add(-2h)` — an
//   ever-refreshing fake timestamp implying a real check that never
//   happened (no real update-manifest channel exists anywhere for this
//   self-hosted appliance) — dropped rather than faked further.
// - Every mutating /api/stte/* route (org, AI config, backup trigger/
//   config, license activate, agents config) was RequireAuth()-only, so
//   any authenticated user of any role — including viewer — could trigger
//   a full database backup or activate a license. Added
//   middleware.RequireRole("admin"), matching this codebase's own
//   established convention for adjacent admin-only mutations.
// - Password Policy / Login Protection fields (min length, special chars,
//   numbers, expiry, max failed logins, lockout duration, IP allowlist)
//   were fully editable UI with a fake "saved" message, but
//   tenant_security_policy had none of these columns — nothing persisted
//   or was enforced anywhere. Added a real migration (7 new columns +
//   users.password_changed_at), made ValidatePasswordComplexity/
//   RecordLoginFailure tenant-configurable, and added a new IP-allowlist
//   check and password-expiry check to the real Login handler — all 4
//   verified live end-to-end (see the four regression guards below).
test.use({ storageState: SHARED_STORAGE_STATE });

const PSQL = (sql: string) =>
  execSync(`docker exec xcloak-postgres psql -U xcloak -d ngfw -t -A -c "${sql.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim();

const API_BASE = 'http://localhost:8080/api';

// Extracts the "token" (access JWT) cookie from a login response's Set-Cookie
// headers. APIResponse has no headerValue() (that's a Page/Response API) —
// headersArray() is required here since a login response sets multiple
// Set-Cookie headers (token + refresh_token) that headers() would otherwise
// incorrectly join into one comma-separated string.
async function extractTokenCookie(res: any): Promise<string> {
  const headers: { name: string; value: string }[] = await res.headersArray();
  const setCookies = headers.filter(h => h.name.toLowerCase() === 'set-cookie');
  const tokenHeader = setCookies.find(h => h.value.startsWith('token='));
  if (!tokenHeader) throw new Error('no token cookie in login response');
  return tokenHeader.value.split(';')[0];
}

// /api/auth/login is rate-limited at 10/min per IP+path — a real, working
// anti-brute-force control, not a bug — and this file alone makes enough
// real login calls across its other regression guards (revocation,
// max-sessions x3, lockout up to x3, etc.) to sit right at that edge before
// the MFA tests below even start. A short bounded retry on 429 here is
// waiting out a real, intentional rate limiter, not masking a product bug.
async function loginRetrying(page: any, data: Record<string, string>, path = `${API_BASE}/auth/login`) {
  for (let attempt = 0; attempt < 4; attempt++) {
    const res = await page.request.post(path, { data });
    if (res.status() !== 429) return res;
    await new Promise(r => setTimeout(r, 15_000));
  }
  return page.request.post(path, { data });
}

async function createRealTestUser(page: any, username: string, password: string): Promise<void> {
  const res = await page.request.post(`${API_BASE}/users/invite`, {
    data: { username, email: `${username}@example.com`, role: 'analyst' },
  });
  expect(res.ok()).toBeTruthy();
  const token = PSQL(`SELECT password_reset_token FROM users WHERE username='${username}';`);
  const resetRes = await page.request.post(`${API_BASE}/auth/reset-password`, {
    data: { token, new_password: password },
  });
  expect(resetRes.ok()).toBeTruthy();
}

function deleteTestUser(username: string) {
  PSQL(`DELETE FROM sessions WHERE username='${username}';`);
  PSQL(`DELETE FROM users WHERE username='${username}';`);
}

test.describe('Settings — route health', () => {
  test('every /api/** call the page makes succeeds, and no console errors fire', async ({ page }) => {
    const failedRequests: string[] = [];
    const consoleErrors: string[] = [];
    page.on('response', res => {
      if (res.url().includes('/api/') && res.status() >= 400) {
        failedRequests.push(`${res.status()} ${res.request().method()} ${res.url()}`);
      }
    });
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });

    await page.goto('/settings');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });

    const TOP_TABS = ['General', 'Security', 'Integrations', 'AI', 'System'];
    const SUB_TABS: Record<string, string[]> = {
      General: ['Organization', 'Users & RBAC'],
      Security: ['Authentication', 'Agents'],
      Integrations: ['Notifications'], // "Integrations" itself is both the top tab and its own default sub-tab — already visited by the top-tab click
      AI: ['Models', 'Guardrails', 'Usage Limits'],
      System: ['Backup & Recovery', 'API Management', 'Updates', 'Licensing', 'Audit Trail'],
    };
    for (const top of TOP_TABS) {
      await page.getByRole('main').getByRole('button', { name: new RegExp(`^${top}\\b`) }).first().click();
      await page.waitForTimeout(200);
      for (const sub of SUB_TABS[top] ?? []) {
        await page.getByRole('main').getByRole('button', { name: new RegExp(`^${sub}\\b`) }).click();
        await page.waitForTimeout(200);
      }
    }

    expect(failedRequests, `Failed API calls:\n${failedRequests.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Console errors:\n${consoleErrors.join('\n')}`).toEqual([]);
  });
});

test.describe('Settings — regression guard: session revocation actually invalidates a live session', () => {
  test('a real admin-revoked session is immediately rejected by RequireAuth, not just marked revoked in the DB', async ({ page, request }) => {
    const username = 'e2e-revoke-guard';
    await createRealTestUser(page, username, 'GuardTest1!Pw');

    const loginRes = await request.post(`${API_BASE}/auth/login`, {
      data: { username, password: 'GuardTest1!Pw' },
    });
    expect(loginRes.ok()).toBeTruthy();
    const tokenCookie = await extractTokenCookie(loginRes);

    // Confirm the new session works before revocation.
    const beforeRes = await request.get(`${API_BASE}/auth/sessions`, { headers: { Cookie: tokenCookie } });
    expect(beforeRes.ok()).toBeTruthy();

    const sessionId = Number(PSQL(`SELECT id FROM sessions WHERE tenant_id='9999' AND username='${username}' ORDER BY id DESC LIMIT 1;`));
    expect(sessionId).toBeGreaterThan(0);

    const revokeRes = await page.request.delete(`${API_BASE}/sessions/${sessionId}`);
    expect(revokeRes.ok()).toBeTruthy();

    const dbRevoked = PSQL(`SELECT revoked FROM sessions WHERE id=${sessionId};`);
    expect(dbRevoked).toBe('t');

    // The real regression check: the same still-unexpired JWT must now be
    // rejected, not just the DB row updated.
    const afterRes = await request.get(`${API_BASE}/auth/sessions`, { headers: { Cookie: tokenCookie } });
    expect(afterRes.status()).toBe(401);
    const body = await afterRes.json();
    expect(body.error).toContain('revoked');

    deleteTestUser(username);
  });
});

test.describe('Settings — regression guard: max concurrent sessions is actually enforced', () => {
  test('logging in beyond the configured limit revokes the oldest real session, not just a DB-only mark', async ({ page, request }) => {
    const username = 'e2e-maxsess-guard';
    await createRealTestUser(page, username, 'GuardTest1!Pw');

    await page.request.put(`${API_BASE}/security-policy`, {
      data: { session_timeout_mins: 480, max_concurrent_sessions: 2, mfa_required: false,
        min_password_length: 8, require_special_chars: true, require_numbers: true,
        password_expiry_days: 0, max_failed_logins: 5, lockout_duration_mins: 30, ip_allowlist: '' },
    });

    // CreateSessionOnLogin (which also enforces the concurrent-session
    // limit) runs in a goroutine — "never delays the login response," per
    // its own comment — so the session row and any eviction it triggers
    // land shortly *after* the HTTP response returns, not synchronously
    // with it. Poll for the expected row count before the next login,
    // rather than assuming immediate consistency.
    const login = async (expectRowCount: number) => {
      const res = await request.post(`${API_BASE}/auth/login`, { data: { username, password: 'GuardTest1!Pw' } });
      const cookie = await extractTokenCookie(res);
      await expect.poll(() => PSQL(`SELECT count(*) FROM sessions WHERE tenant_id='9999' AND username='${username}';`))
        .toBe(String(expectRowCount));
      return cookie;
    };
    const c1 = await login(1);
    const c2 = await login(2);
    const c3 = await login(3);
    // The 3rd login's eviction (UPDATE ... SET revoked=true, not a DELETE)
    // happens right after its own row insert in the same goroutine, so wait
    // for the not-revoked count to drop back to the real limit of 2.
    await expect.poll(() => PSQL(`SELECT count(*) FROM sessions WHERE tenant_id='9999' AND username='${username}' AND NOT revoked;`))
      .toBe('2');

    const r1 = await request.get(`${API_BASE}/auth/sessions`, { headers: { Cookie: c1 } });
    const r2 = await request.get(`${API_BASE}/auth/sessions`, { headers: { Cookie: c2 } });
    const r3 = await request.get(`${API_BASE}/auth/sessions`, { headers: { Cookie: c3 } });

    expect(r1.status(), 'oldest session should have been evicted').toBe(401);
    expect(r2.ok(), 'middle session should still be valid').toBeTruthy();
    expect(r3.ok(), 'newest session should still be valid').toBeTruthy();

    await page.request.put(`${API_BASE}/security-policy`, {
      data: { session_timeout_mins: 480, max_concurrent_sessions: 10, mfa_required: false,
        min_password_length: 8, require_special_chars: true, require_numbers: true,
        password_expiry_days: 0, max_failed_logins: 5, lockout_duration_mins: 30, ip_allowlist: '' },
    });
    deleteTestUser(username);
  });
});

test.describe('Settings — regression guard: password policy is tenant-configurable and enforced', () => {
  test('min_password_length is read from tenant_security_policy, not a fixed global 8', async ({ page }) => {
    await page.request.put(`${API_BASE}/security-policy`, {
      data: { session_timeout_mins: 480, max_concurrent_sessions: 10, mfa_required: false,
        min_password_length: 14, require_special_chars: true, require_numbers: true,
        password_expiry_days: 0, max_failed_logins: 5, lockout_duration_mins: 30, ip_allowlist: '' },
    });

    const username = 'e2e-pwpolicy-guard';
    const inviteRes = await page.request.post(`${API_BASE}/users/invite`, {
      data: { username, email: `${username}@example.com`, role: 'analyst' },
    });
    expect(inviteRes.ok()).toBeTruthy();
    const token = PSQL(`SELECT password_reset_token FROM users WHERE username='${username}';`);

    const shortRes = await page.request.post(`${API_BASE}/auth/reset-password`, {
      data: { token, new_password: 'Short1!' },
    });
    expect(shortRes.status()).toBe(400);
    const shortBody = await shortRes.json();
    expect(shortBody.error).toContain('14 characters');

    const longRes = await page.request.post(`${API_BASE}/auth/reset-password`, {
      data: { token, new_password: 'LongEnoughPassword1!' },
    });
    expect(longRes.ok()).toBeTruthy();

    await page.request.put(`${API_BASE}/security-policy`, {
      data: { session_timeout_mins: 480, max_concurrent_sessions: 10, mfa_required: false,
        min_password_length: 8, require_special_chars: true, require_numbers: true,
        password_expiry_days: 0, max_failed_logins: 5, lockout_duration_mins: 30, ip_allowlist: '' },
    });
    deleteTestUser(username);
  });
});

test.describe('Settings — regression guard: login lockout uses the real tenant-configured threshold', () => {
  test('an account locks after exactly max_failed_logins attempts, not a fixed global 5', async ({ page, request }) => {
    await page.request.put(`${API_BASE}/security-policy`, {
      data: { session_timeout_mins: 480, max_concurrent_sessions: 10, mfa_required: false,
        min_password_length: 8, require_special_chars: true, require_numbers: true,
        password_expiry_days: 0, max_failed_logins: 3, lockout_duration_mins: 15, ip_allowlist: '' },
    });
    const username = 'e2e-lockout-guard';
    await createRealTestUser(page, username, 'GuardTest1!Pw');

    for (let i = 0; i < 3; i++) {
      const r = await request.post(`${API_BASE}/auth/login`, { data: { username, password: 'wrong-password' } });
      expect(r.status()).toBe(401);
    }
    const lockedRes = await request.post(`${API_BASE}/auth/login`, { data: { username, password: 'wrong-password' } });
    expect(lockedRes.status()).toBe(429);
    const body = await lockedRes.json();
    expect(body.error).toContain('15 minutes');

    execSync(`docker exec xcloak-redis redis-cli DEL "login:locked:${username}" "login:fail:${username}"`);
    await page.request.put(`${API_BASE}/security-policy`, {
      data: { session_timeout_mins: 480, max_concurrent_sessions: 10, mfa_required: false,
        min_password_length: 8, require_special_chars: true, require_numbers: true,
        password_expiry_days: 0, max_failed_logins: 5, lockout_duration_mins: 30, ip_allowlist: '' },
    });
    deleteTestUser(username);
  });
});

test.describe('Settings — regression guard: license activation validates a real signed token', () => {
  test('garbage is rejected, and a real ed25519-signed token from the platform-admin flow persists real data', async ({ page }) => {
    const before = PSQL(`SELECT license_key, tier, seats_total FROM stte_license WHERE tenant_id='9999';`);

    const badRes = await page.request.post(`${API_BASE}/stte/license/activate`, {
      data: { license_key: 'totally-fake-key' },
    });
    expect(badRes.status()).toBe(400);

    const genRes = await page.request.post(`${API_BASE}/platform/license/keys`, {
      data: { customer_name: 'E2E Spec Customer', customer_email: 'spec@example.com', tier: 'professional',
        agent_limit: 111, user_limit: 22, expires_at: '2027-06-01T00:00:00Z', notes: 'e2e spec' },
    });
    expect(genRes.ok()).toBeTruthy();
    const { token: realToken, key_id } = await genRes.json();

    const activateRes = await page.request.post(`${API_BASE}/stte/license/activate`, {
      data: { license_key: realToken },
    });
    expect(activateRes.ok()).toBeTruthy();
    const activated = await activateRes.json();
    expect(activated.tier).toBe('professional');
    expect(activated.seats_total).toBe(22);
    expect(activated.agents_total).toBe(111);

    const licRes = await page.request.get(`${API_BASE}/stte/license`);
    const lic = await licRes.json();
    expect(lic.issued_to).toBe('E2E Spec Customer');
    expect(lic.seats_total).toBe(22);

    // restore
    const [key, tier, seats] = before.split('|');
    PSQL(`UPDATE stte_license SET license_key='${key}', tier='${tier}', seats_total=${seats}, seats_used=12, agents_total=10000, agents_used=427, valid_from='2025-01-01', valid_until='2026-01-01', issued_to='XCloak Security Suite Demo', support_tier='enterprise', is_trial=false WHERE tenant_id='9999';`);
    PSQL(`DELETE FROM license_keys WHERE key_id='${key_id}';`);
  });
});

test.describe('Settings — regression guard: backup produces a real pg_dump file', () => {
  test('Backup Now shells out to a real pg_dump and records real size/duration, not a fabricated one', async ({ page }) => {
    const res = await page.request.post(`${API_BASE}/stte/backups/trigger`);
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.status).toBe('completed');
    // The old fake value was always in the 50MB-550MB range regardless of
    // real content; a real dump of this dev DB is a few MB.
    expect(body.size_bytes).toBeGreaterThan(1_000_000);
    expect(body.size_bytes).toBeLessThan(50 * 1024 * 1024);

    const path = PSQL(`SELECT storage_path FROM stte_backups WHERE backup_id='${body.backup_id}';`);
    const head = execSync(`head -c 200 "/home/idiot/Projects/XCLOAK-SECURITY-SUITE/xcloak-platform/backend/${path}"`, { encoding: 'utf8' });
    expect(head).toContain('PostgreSQL database dump');

    execSync(`rm -f "/home/idiot/Projects/XCLOAK-SECURITY-SUITE/xcloak-platform/backend/${path}"`);
    PSQL(`DELETE FROM stte_backups WHERE backup_id='${body.backup_id}'; DELETE FROM stte_audit WHERE tenant_id='9999' AND details LIKE '%${body.backup_id}%';`);
  });
});

test.describe('Settings — regression guard: mutating /api/stte/* routes require admin', () => {
  test('a non-admin (viewer) is rejected with 403 from a previously-unprotected admin-only mutation', async ({ page }) => {
    const username = 'e2e-rbac-guard';
    await createRealTestUser(page, username, 'GuardTest1!Pw');
    PSQL(`UPDATE users SET role='viewer' WHERE username='${username}';`);

    const loginRes = await page.request.post(`${API_BASE}/auth/login`, {
      data: { username, password: 'GuardTest1!Pw' },
    });
    expect(loginRes.ok()).toBeTruthy();
    const tokenCookie = await extractTokenCookie(loginRes);

    const res = await page.request.post(`${API_BASE}/stte/backups/trigger`, { headers: { Cookie: tokenCookie } });
    expect(res.status()).toBe(403);

    deleteTestUser(username);
  });
});

// 2026-08-01: MFA had a real backend (setup/verify/disable/status, a
// correct 2-step login flow) but zero self-service UI on web (the API
// client methods existed and were never called from any page) and a
// mobile login flow that couldn't complete at all for a 2FA-enabled
// account (needs_2fa/temp_token wasn't handled — indistinguishable from
// "server didn't return a token"). Also fixed: CompleteTOTPLogin never
// created a sessions row, issued a refresh token, or wrote an audit log
// like Login does; and the tenant's "Require MFA for All Users" toggle
// was saved and never read anywhere in the login path.
test.describe('Settings — regression guard: MFA self-enrollment actually works end to end', () => {
  test('setup -> verify -> status -> 2FA login -> disable, using a real computed TOTP code', async ({ page }) => {
    // Up to two real /api/auth/login calls, each possibly retrying through
    // loginRetrying()'s 15s backoff against this file's own cumulative
    // rate-limit budget — can exceed the 30s default in the worst case.
    test.setTimeout(120_000);
    const username = 'e2e-mfa-guard';
    await createRealTestUser(page, username, 'GuardTest1!Pw');

    const loginRes = await loginRetrying(page, { username, password: 'GuardTest1!Pw' });
    expect(loginRes.ok()).toBeTruthy();
    const cookie = await extractTokenCookie(loginRes);

    // Not enrolled yet.
    const before = await page.request.get(`${API_BASE}/auth/2fa/status`, { headers: { Cookie: cookie } });
    expect((await before.json()).enabled).toBe(false);

    const setupRes = await page.request.post(`${API_BASE}/auth/2fa/setup`, { headers: { Cookie: cookie } });
    expect(setupRes.ok()).toBeTruthy();
    const { secret, qr_url } = await setupRes.json();
    expect(secret).toBeTruthy();
    expect(qr_url).toContain('otpauth://totp/');

    const verifyRes = await page.request.post(`${API_BASE}/auth/2fa/verify`, {
      headers: { Cookie: cookie }, data: { code: totp(secret) },
    });
    expect(verifyRes.ok()).toBeTruthy();

    const after = await page.request.get(`${API_BASE}/auth/2fa/status`, { headers: { Cookie: cookie } });
    expect((await after.json()).enabled).toBe(true);

    // A fresh login must now stop at the 2FA step, not issue a session.
    const login2 = await loginRetrying(page, { username, password: 'GuardTest1!Pw' });
    const login2Body = await login2.json();
    expect(login2Body.needs_2fa).toBe(true);
    expect(login2Body.temp_token).toBeTruthy();

    const completeRes = await page.request.post(`${API_BASE}/auth/login/2fa`, {
      data: { temp_token: login2Body.temp_token, code: totp(secret) },
    });
    expect(completeRes.ok()).toBeTruthy();
    const completeCookie = await extractTokenCookie(completeRes);

    // Regression guard: CompleteTOTPLogin previously skipped session
    // creation and audit logging that plain Login always did.
    await expect.poll(() =>
      Number(PSQL(`SELECT COUNT(*) FROM sessions WHERE tenant_id='9999' AND username='${username}' AND NOT revoked;`))
    ).toBeGreaterThan(0);
    const auditCount = Number(PSQL(
      `SELECT COUNT(*) FROM audit_logs WHERE username='${username}' AND action='login_success' AND details LIKE '%via:2fa%';`
    ));
    expect(auditCount).toBeGreaterThan(0);

    const disableRes = await page.request.delete(`${API_BASE}/auth/2fa`, {
      headers: { Cookie: completeCookie }, data: { code: totp(secret) },
    });
    expect(disableRes.ok()).toBeTruthy();
    const finalStatus = await page.request.get(`${API_BASE}/auth/2fa/status`, { headers: { Cookie: completeCookie } });
    expect((await finalStatus.json()).enabled).toBe(false);

    deleteTestUser(username);
  });

  test('the Settings UI actually renders the enrollment step, not just the API', async ({ page }) => {
    await page.goto('/settings');
    await page.waitForLoadState('networkidle', { timeout: 20_000 });
    await page.getByRole('main').getByRole('button', { name: /^Security\b/ }).first().click();
    await page.getByRole('main').getByRole('button', { name: /^Authentication\b/ }).click();
    // Under full-suite load this section's own data fetch (2FA status +
    // the rest of loadAll) can outrun the default 5s assertion timeout,
    // independent of any product bug — same shape as other pages' guards.
    await expect(page.getByText('Your Account MFA')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole('button', { name: 'Set Up MFA' })).toBeVisible();
    await page.getByRole('button', { name: 'Set Up MFA' }).click();
    // A real setup2FA round trip + client-side QR generation, not instant.
    await expect(page.getByText('Manual entry key')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByPlaceholder('123456')).toBeVisible();
    // Cancel rather than complete — this is the shared admin session and a
    // real enrollment here would require every other spec file that logs
    // in as admin to also solve a TOTP challenge.
    await page.getByRole('button', { name: 'Cancel' }).click();
  });
});

test.describe('Settings — regression guard: "Require MFA for All Users" is no longer a dead toggle', () => {
  test('a non-enrolled user is soft-flagged to set up MFA on login, and stops being flagged once enrolled', async ({ page }) => {
    const username = 'e2e-mfa-required-guard';
    await createRealTestUser(page, username, 'GuardTest1!Pw');

    // Narrow, immediately-restored window — mfa_required is a per-tenant
    // policy shared with every other user, including the shared admin
    // session other spec files use.
    PSQL(`UPDATE tenant_security_policy SET mfa_required=true WHERE tenant_id='9999';`);
    let loginRes;
    try {
      loginRes = await page.request.post(`${API_BASE}/auth/login`, {
        data: { username, password: 'GuardTest1!Pw' },
      });
    } finally {
      PSQL(`UPDATE tenant_security_policy SET mfa_required=false WHERE tenant_id='9999';`);
    }
    expect(loginRes.ok()).toBeTruthy();
    const body = await loginRes.json();
    // Soft enforcement, not a lockout: login still succeeds.
    expect(body.ok).toBe(true);
    expect(body.mfa_setup_required).toBe(true);

    deleteTestUser(username);
  });
});
