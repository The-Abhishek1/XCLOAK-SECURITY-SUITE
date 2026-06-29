import { NextRequest, NextResponse } from 'next/server';

const BACKEND = process.env.BACKEND_INTERNAL_URL || 'http://localhost:8080';

async function proxy(request: NextRequest): Promise<NextResponse> {
  const url = `${BACKEND}${request.nextUrl.pathname}${request.nextUrl.search}`;

  const headers = new Headers(request.headers);
  headers.delete('host');

  const hasBody = !['GET', 'HEAD'].includes(request.method);

  let upstream: Response;
  try {
    upstream = await fetch(url, {
      method: request.method,
      headers,
      body: hasBody ? request.body : undefined,
      // required for streaming request bodies in Node.js
      // @ts-ignore
      duplex: 'half',
    });
  } catch (err) {
    return NextResponse.json({ error: 'Backend unreachable' }, { status: 502 });
  }

  const responseHeaders = new Headers(upstream.headers);
  // Allow the browser to read all headers (CORS preflight already handled by backend)
  responseHeaders.delete('transfer-encoding');

  return new NextResponse(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: responseHeaders,
  });
}

export const GET     = proxy;
export const POST    = proxy;
export const PUT     = proxy;
export const DELETE  = proxy;
export const PATCH   = proxy;
export const OPTIONS = proxy;
