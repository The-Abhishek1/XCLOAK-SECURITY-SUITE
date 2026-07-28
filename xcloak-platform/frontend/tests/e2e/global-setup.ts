import { chromium, type FullConfig } from '@playwright/test';
import path from 'path';
import os from 'os';

// Every spec file used to log in independently in its own `beforeAll` — each
// file got its own cached storageState (xcloak-<page>-spec-auth.json) purely
// to dodge /api/auth/login's 10/min rate limit *within* a file. That worked
// per-file, but once the suite grew past ~10 spec files, a full clean-slate
// run (all files logging in fresh, spread across 4 parallel workers) could
// still rack up more than 10 login POSTs inside the same 60s window and get
// genuinely rate-limited — not flakiness, an actual 429 rejection surfacing
// as "login redirected to /login instead of /dashboard". globalSetup runs
// once, strictly before any worker starts, so there is exactly one login for
// the entire suite no matter how many spec files exist.
export const SHARED_STORAGE_STATE = path.join(os.tmpdir(), 'xcloak-shared-spec-auth.json');

export default async function globalSetup(config: FullConfig) {
  const baseURL = config.projects[0]?.use?.baseURL || 'http://localhost:3000';
  const browser = await chromium.launch();
  const page = await browser.newPage({ baseURL });
  await page.goto('/login');
  await page.getByPlaceholder(/username/i).fill('admin');
  await page.getByPlaceholder(/password/i).fill('admin1234');
  await page.locator('button[type="submit"]').click();
  await page.waitForURL(/\/dashboard/, { timeout: 20_000 });
  await page.context().storageState({ path: SHARED_STORAGE_STATE });
  await browser.close();
}
