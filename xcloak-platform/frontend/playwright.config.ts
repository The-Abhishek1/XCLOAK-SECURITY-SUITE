import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  timeout: 30_000,
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  // Logs in once for the whole suite (see global-setup.ts) instead of every
  // spec file logging in independently — avoids /api/auth/login's 10/min
  // rate limit being hit across parallel workers as the spec count grows.
  globalSetup: require.resolve('./tests/e2e/global-setup.ts'),

  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:3000',
    trace: 'on-first-retry',
    // Intercept /api/* via page.route() in tests — no backend needed for smoke.
    ignoreHTTPSErrors: true,
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  // Start the Next.js dev server automatically when not in CI.
  // In CI, start it externally before running the suite.
  webServer: process.env.CI
    ? undefined
    : {
        command: 'npm run dev',
        url: 'http://localhost:3000',
        reuseExistingServer: true,
        timeout: 120_000,
      },
});
