/** @type {import('next').NextConfig} */
const nextConfig = {
  // Netlify sets NETLIFY=true in its build env and needs the default output.
  // Docker and CI expect standalone — it collapses node_modules into a self-
  // contained server.js + .next/static that the Dockerfile copies directly.
  output: process.env.NETLIFY ? undefined : 'standalone',
  // NOTE: the /api/* proxy to the backend lives in middleware.ts, not here.
  // next.config.js's rewrites() is resolved ONCE into a static manifest at
  // build time (confirmed empirically — verified this the hard way after it
  // silently baked in a stale localhost:8080 destination from build-time env),
  // so it can't support "build once, configure BACKEND_INTERNAL_URL per
  // environment at deploy time." Middleware runs per-request on the Node
  // server and reads process.env fresh every time, which is what that needs.
  images: {
    domains: ['localhost'],
  },
}

module.exports = nextConfig