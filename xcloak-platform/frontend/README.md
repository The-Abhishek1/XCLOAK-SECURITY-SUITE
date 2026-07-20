XCloak's dashboard — a [Next.js](https://nextjs.org) app in the `xcloak-platform` backend monorepo. See the [top-level README](../../README.md) for the full picture; this file only covers the frontend package itself.

## Running

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). By default it expects a backend at `NEXT_PUBLIC_API_URL` (defaults to `http://localhost:8080`).

### Static demo mode (no backend)

```bash
NEXT_PUBLIC_DEMO_ONLY=true npm run dev
```

All data is baked into the JS bundle — no Go backend, no database. This is what runs at [suite.xcloak.tech](https://suite.xcloak.tech).

## Deploying

This app does not deploy to Vercel — it's part of a self-hosted stack. See [docs.xcloak.tech](https://docs.xcloak.tech) or the [Deployment Guide](../../docs/deployment-guide.md) for Docker Compose / Kubernetes/Helm deployment, and the [top-level README](../../README.md#running-locally) for all three run modes (full stack, seeded backend, static demo).
