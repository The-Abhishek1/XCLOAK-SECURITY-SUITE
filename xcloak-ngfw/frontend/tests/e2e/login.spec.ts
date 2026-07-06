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
    await expect(page.getByRole('button', { name: /sign in/i })).toBeVisible();
  });

  test('shows link to signup page', async ({ page }) => {
    await page.goto('/login');

    const signupLink = page.getByRole('link', { name: /sign up|create.*(org|account)/i });
    await expect(signupLink).toBeVisible();
  });

  test('displays error on failed login', async ({ page }) => {
    await page.goto('/login');

    await page.getByPlaceholder(/username/i).fill('bad-user');
    await page.getByPlaceholder(/password/i).fill('wrong-pass');
    await page.getByRole('button', { name: /sign in/i }).click();

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
