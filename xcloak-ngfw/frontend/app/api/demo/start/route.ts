import { NextResponse } from 'next/server';

// Sets the auth cookies that middleware checks, so the demo user is treated
// as logged in without ever hitting the Go backend.
export async function GET() {
  const res = NextResponse.json({ ok: true });

  const cookieOpts = {
    path:     '/',
    httpOnly: false,
    sameSite: 'lax' as const,
    maxAge:   60 * 60 * 8, // 8 hours
  };

  // middleware.ts reads the `token` cookie to decide if the user is authed
  res.cookies.set('token',      'demo-static-token', { ...cookieOpts, httpOnly: true });
  res.cookies.set('logged_in',  '1',                 cookieOpts);
  res.cookies.set('demo_mode',  '1',                 cookieOpts);

  return res;
}

// The demo page calls POST /api/demo/start as well on some builds
export const POST = GET;
