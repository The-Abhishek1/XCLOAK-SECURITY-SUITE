import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  // Get the token from cookies (since localStorage is not available in middleware)
  const token = request.cookies.get('token')?.value;
  const isLoginPage = request.nextUrl.pathname === '/login';
  const isApiRoute = request.nextUrl.pathname.startsWith('/api');

  // For API routes, proxy to the backend. Middleware runs per-request on
  // the Node server (unlike next.config.js's rewrites(), which Next.js
  // resolves once into a static manifest at build time) — so
  // BACKEND_INTERNAL_URL is read fresh on every request and a single built
  // image can be promoted across environments without a rebuild.
  if (isApiRoute) {
    const backendURL = process.env.BACKEND_INTERNAL_URL || 'http://localhost:8080';
    const target = new URL(request.nextUrl.pathname + request.nextUrl.search, backendURL);
    return NextResponse.rewrite(target);
  }

  // Redirect logic
  if (!token && !isLoginPage) {
    const loginUrl = new URL('/login', request.url);
    return NextResponse.redirect(loginUrl);
  }

  if (token && isLoginPage) {
    const dashboardUrl = new URL('/dashboard', request.url);
    return NextResponse.redirect(dashboardUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
  '/api/:path*',
  '/dashboard/:path*',
  '/agents/:path*',
  '/alerts/:path*',
  '/incidents/:path*',
  '/playbooks/:path*',
  '/threat-intel/:path*',
  '/vulnerabilities/:path*',
  '/timeline/:path*',
  '/settings/:path*',
  '/login',
  ],
};