import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  // Get the token from cookies (since localStorage is not available in middleware)
  const token = request.cookies.get('token')?.value;
  const isLoginPage = request.nextUrl.pathname === '/login';
  const isApiRoute = request.nextUrl.pathname.startsWith('/api');

  // API routes are handled by app/api/[...path]/route.ts which proxies to
  // the backend with full header forwarding. Middleware only handles auth
  // redirects for page routes below.
  if (isApiRoute) {
    return NextResponse.next();
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