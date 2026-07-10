import { test, expect } from '@playwright/test';

test.describe('Signup page', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('/api/signup', route =>
      route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', 'Set-Cookie': 'logged_in=1; Path=/' },
        body: JSON.stringify({ message: 'created' }),
      })
    );
    await page.route('/api/users/me', route =>
      route.fulfill({ status: 401, body: JSON.stringify({ error: 'Unauthorized' }) })
    );
  });

  test('renders step 1 (organization)', async ({ page }) => {
    await page.goto('/signup');

    await expect(page.getByPlaceholder(/Acme Security|organization name/i)).toBeVisible();
    await expect(page.getByPlaceholder(/acme-security|slug/i)).toBeVisible();
    await expect(page.getByRole('button', { name: /continue/i })).toBeVisible();
  });

  test('slug auto-populates from org name', async ({ page }) => {
    await page.goto('/signup');

    const orgInput  = page.getByPlaceholder(/Acme Security|organization name/i);
    const slugInput = page.getByPlaceholder(/acme-security|slug/i);

    await orgInput.fill('My Test Org');
    // Slug should be derived from the name
    await expect(slugInput).toHaveValue('my-test-org');
  });

  test('step 1 validation requires org name', async ({ page }) => {
    await page.goto('/signup');

    await page.getByRole('button', { name: /continue/i }).click();
    await expect(page.getByText(/required|cannot be empty/i)).toBeVisible({ timeout: 3_000 });
  });

  test('advances to step 2 with valid org info', async ({ page }) => {
    await page.goto('/signup');

    await page.getByPlaceholder(/Acme Security|organization name/i).fill('Test Corp');
    await page.getByRole('button', { name: /continue/i }).click();

    // Step 2 fields should now be visible
    await expect(page.getByPlaceholder(/admin-handle|username/i)).toBeVisible({ timeout: 3_000 });
    await expect(page.getByPlaceholder(/admin@yourcompany|email/i)).toBeVisible();
  });

  test('step 2 password mismatch shows error', async ({ page }) => {
    await page.goto('/signup');

    await page.getByPlaceholder(/Acme Security|organization name/i).fill('Test Corp');
    await page.getByRole('button', { name: /continue/i }).click();

    await page.getByPlaceholder(/admin-handle|username/i).fill('testadmin');
    await page.getByPlaceholder(/admin@yourcompany|email/i).fill('admin@test.com');

    const passwords = page.getByPlaceholder(/password/i);
    await passwords.nth(0).fill('Password1!');
    await passwords.nth(1).fill('Different1!');

    await page.getByRole('button', { name: /create organization/i }).click();
    await expect(page.getByText(/do not match/i)).toBeVisible({ timeout: 3_000 });
  });

  test('successful signup posts to /api/signup and redirects', async ({ page }) => {
    const signupRequests: string[] = [];
    // Register wildcard FIRST so the specific /api/signup handler (registered last)
    // takes precedence — Playwright routes are evaluated in LIFO order.
    await page.route('/api/**', route => route.fulfill({ status: 200, body: '{}' }));
    await page.route('/api/signup', async route => {
      signupRequests.push(JSON.stringify(await route.request().postDataJSON()));
      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', 'Set-Cookie': 'logged_in=1; Path=/' },
        body: JSON.stringify({ message: 'created' }),
      });
    });

    await page.goto('/signup');
    await page.getByPlaceholder(/Acme Security|organization name/i).fill('Test Corp');
    await page.getByRole('button', { name: /continue/i }).click();

    await page.getByPlaceholder(/admin-handle|username/i).fill('testadmin');
    await page.getByPlaceholder(/admin@yourcompany|email/i).fill('admin@test.com');
    const passwords = page.getByPlaceholder(/password/i);
    await passwords.nth(0).fill('Password1!');
    await passwords.nth(1).fill('Password1!');
    await page.getByRole('button', { name: /create organization/i }).click();

    // Request was sent with the right shape
    await expect.poll(() => signupRequests.length).toBeGreaterThan(0);
    const body = JSON.parse(signupRequests[0]);
    expect(body).toMatchObject({ org_name: 'Test Corp', username: 'testadmin' });
  });
});
