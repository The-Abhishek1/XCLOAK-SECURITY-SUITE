import { test, expect } from '@playwright/test';

test.describe('Login page', () => {
  test.beforeEach(async ({ page }) => {
    // Stub auth API so tests run without a live backend.
    await page.route('/api/auth/login', route =>
      route.fulfill({ status: 401, body: JSON.stringify({ error: 'Invalid credentials' }) })
    );
    await page.route('/api/users/me', route =>
      route.fulfill({ status: 401, body: JSON.stringify({ error: 'Unauthorized' }) })
    );
  });

  test('renders login form', async ({ page }) => {
    await page.goto('/login');

    await expect(page).toHaveTitle(/XCloak/i);
    await expect(page.getByPlaceholder(/username/i)).toBeVisible();
    await expect(page.getByPlaceholder(/password/i)).toBeVisible();
    // Use [type=submit] to avoid strict-mode violation — the page has multiple
    // buttons with "Sign In" text (tab switcher + submit button + SSO button).
    await expect(page.locator('button[type="submit"]')).toBeVisible();
  });

  test('shows register tab', async ({ page }) => {
    await page.goto('/login');

    // The login page uses a tab-based UI — "Register" is a tab button, not a link.
    await expect(page.getByRole('button', { name: 'Register', exact: true })).toBeVisible();
  });

  test('displays error on failed login', async ({ page }) => {
    await page.goto('/login');

    await page.getByPlaceholder(/username/i).fill('bad-user');
    await page.getByPlaceholder(/password/i).fill('wrong-pass');
    await page.locator('button[type="submit"]').click();

    await expect(page.getByText(/invalid|incorrect|unauthorized/i)).toBeVisible({ timeout: 5_000 });
  });

  test('password field masks input by default', async ({ page }) => {
    await page.goto('/login');

    const passwordInput = page.getByPlaceholder(/password/i).first();
    await expect(passwordInput).toHaveAttribute('type', 'password');
  });

  test('toggle reveals password', async ({ page }) => {
    await page.goto('/login');

    const passwordInput = page.getByPlaceholder(/password/i).first();
    // Click the show/hide toggle (eye icon button near the password field)
    const toggleBtn = page.locator('button[type="button"]').filter({ has: page.locator('svg') }).first();
    await toggleBtn.click();
    await expect(passwordInput).toHaveAttribute('type', 'text');
  });
});
