import { test, expect } from '@playwright/test';

// Smoke tests for route-level authentication guards.
// All API calls are stubbed — no live backend required.

test.describe('Auth guard — unauthenticated redirects', () => {
  test.beforeEach(async ({ page }) => {
    // Return 401 for the /api/users/me call that the middleware / layout uses
    // to decide whether the visitor is logged in.
    await page.route('/api/users/me', route =>
      route.fulfill({ status: 401, body: JSON.stringify({ error: 'Unauthorized' }) })
    );
    await page.route('/api/**', route =>
      route.fulfill({ status: 401, body: JSON.stringify({ error: 'Unauthorized' }) })
    );
  });

  test('/dashboard redirects to /login when unauthenticated', async ({ page }) => {
    await page.goto('/dashboard');

    await expect(page).toHaveURL(/\/login/, { timeout: 5_000 });
  });

  test('/agents redirects to /login when unauthenticated', async ({ page }) => {
    await page.goto('/agents');

    await expect(page).toHaveURL(/\/login/, { timeout: 5_000 });
  });

  test('/alerts redirects to /login when unauthenticated', async ({ page }) => {
    await page.goto('/alerts');

    await expect(page).toHaveURL(/\/login/, { timeout: 5_000 });
  });
});

test.describe('Auth guard — authenticated access', () => {
  test.beforeEach(async ({ page }) => {
    // Simulate a logged-in session by adding the cookie before navigation
    // and stubbing all API responses.
    await page.context().addCookies([
      { name: 'logged_in', value: '1', domain: 'localhost', path: '/' },
    ]);

    await page.route('/api/users/me', route =>
      route.fulfill({
        status: 200,
        body: JSON.stringify({ id: 1, username: 'testadmin', role: 'admin' }),
      })
    );
    await page.route('/api/**', route =>
      route.fulfill({ status: 200, body: '{}' })
    );
  });

  test('/login redirects to /dashboard when already logged in', async ({ page }) => {
    await page.goto('/login');

    await expect(page).toHaveURL(/\/dashboard/, { timeout: 5_000 });
  });

  test('/signup redirects to /dashboard when already logged in', async ({ page }) => {
    await page.goto('/signup');

    await expect(page).toHaveURL(/\/dashboard/, { timeout: 5_000 });
  });
});
