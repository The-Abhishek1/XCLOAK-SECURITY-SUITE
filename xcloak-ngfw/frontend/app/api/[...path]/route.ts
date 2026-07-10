import { NextRequest, NextResponse } from 'next/server';
import { demoRoute } from '@/lib/demo-data/router';

const BACKEND   = process.env.BACKEND_INTERNAL_URL || 'http://localhost:8080';
// NEXT_PUBLIC_ is baked into the bundle at build time so it's available in
// both server-side route handlers and the client — no Netlify runtime config needed.
const DEMO_ONLY = process.env.NEXT_PUBLIC_DEMO_ONLY === 'true';

async function proxy(request: NextRequest): Promise<NextResponse> {
  if (DEMO_ONLY) {
    const path = request.nextUrl.pathname;
    const sp   = request.nextUrl.searchParams;
    const { data, status } = demoRoute(path, request.method, sp);
    return NextResponse.json(data, { status });
  }

  const url     = `${BACKEND}${request.nextUrl.pathname}${request.nextUrl.search}`;
  const headers = new Headers(request.headers);
  headers.delete('host');

  const hasBody = !['GET', 'HEAD'].includes(request.method);

  let upstream: Response;
  try {
    upstream = await fetch(url, {
      method: request.method,
      headers,
      body: hasBody ? request.body : undefined,
      // @ts-ignore — required for streaming request bodies in Node.js
      duplex: 'half',
    });
  } catch {
    return NextResponse.json({ error: 'Backend unreachable' }, { status: 502 });
  }

  const responseHeaders = new Headers(upstream.headers);
  responseHeaders.delete('transfer-encoding');

  return new NextResponse(upstream.body, {
    status:     upstream.status,
    statusText: upstream.statusText,
    headers:    responseHeaders,
  });
}

export const GET     = proxy;
export const POST    = proxy;
export const PUT     = proxy;
export const DELETE  = proxy;
export const PATCH   = proxy;
export const OPTIONS = proxy;
