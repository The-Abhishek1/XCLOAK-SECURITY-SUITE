import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Exact paths that do NOT require authentication.
// Everything else is protected by default — new pages need no changes here.
const PUBLIC_PATHS = new Set(['/login', '/signup', '/reset-password']);
// Path prefixes that are always public.
// /api/ routes are proxied by app/api/[...path]/route.ts and carry their own auth.
const PUBLIC_PREFIXES = ['/auth/oidc/', '/api/'];

function isPublic(pathname: string): boolean {
  if (PUBLIC_PATHS.has(pathname)) return true;
  return PUBLIC_PREFIXES.some((p) => pathname.startsWith(p));
}

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (isPublic(pathname)) {
    // Bounce already-authenticated users away from login/signup pages.
    const authPages = new Set(['/login', '/signup']);
    if (authPages.has(pathname) && request.cookies.get('token')?.value) {
      return NextResponse.redirect(new URL('/dashboard', request.url));
    }
    return NextResponse.next();
  }

  const token = request.cookies.get('token')?.value;
  if (!token) {
    const loginUrl = new URL('/login', request.url);
    // Preserve the intended destination so the login page can redirect back.
    loginUrl.searchParams.set('next', pathname);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

// Single catch-all: every page request reaches this middleware automatically.
// _next internals and static assets are skipped by the negative lookahead.
// Previously this was an explicit list of 10 routes — 48 pages were unprotected.
export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon\\.ico).*)'],
};