# Cloudflare deployment

A React UI plus a Cloudflare Worker that fronts the **existing, unmodified**
`sbom_scorer` Python package. No scoring logic is reimplemented: the Worker is
a thin authenticating proxy, and the real `sbom-scorer` CLI runs on a
self-hosted scanner API that owns the long-running work.

```
cloudflare/
├── worker/            # Cloudflare Worker: static assets + /api proxy
│   ├── wrangler.jsonc  # assets + vars config (placeholder hostnames)
│   └── src/
│       ├── index.ts        # fetch handler: /api/health, /api/scan, static assets
│       └── types.ts        # JSON contract shared with the CLI's report.py
└── app/                # React + Vite + TypeScript + Recharts UI
    └── src/
        ├── App.tsx               # top-level state + layout
        ├── api.ts / types.ts     # /api/scan client + shared types
        ├── constants.ts          # tier colors/order, dimension labels
        └── components/
            ├── ScanForm.tsx           # file/repo input, advanced options
            ├── ScanProgressPanel.tsx  # live phase/counter/log tail while scanning
            ├── SummaryCards.tsx       # tier counts
            ├── TierBarChart.tsx       # mirrors visualize.py's tier_distribution_bar()
            ├── FindingsTable.tsx      # sortable/filterable/searchable findings list
            └── FindingDetail.tsx      # mirrors visualize.py's finding_radar()
```

## Why a proxy, not a rewrite (and not a container)

The scoring pipeline (`sbom_parser.py`, `dimensions/*.py`, `composite.py`,
`vex.py`, `cli.py`) depends on `networkx`, `cyclonedx-python-lib`,
`spdx-tools`, and outbound calls to OSV/EPSS/CISA-KEV/OSSF-Scorecard/package
registries. A straight port to Workers (V8 isolates, no arbitrary
subprocess/native deps) isn't practical.

An earlier revision ran the CLI in a [Sandbox
SDK](https://developers.cloudflare.com/sandbox/) container per request. That
was dropped: Cloudflare Containers are a Workers **Paid** feature and bill
provisioned wall-clock time rather than CPU, so a scan that spends most of its
life blocked on upstream APIs is expensive while doing nothing. Moving
execution to self-hosted infrastructure keeps this deployment inside the
Workers free plan.

## Request flow

```
browser → Worker
            ├── /api/*  → proxied to SCANNER_ORIGIN with an injected X-API-Key
            └── everything else → static React assets
```

The Worker rebuilds request headers from scratch rather than forwarding them,
so a client-supplied `Cookie`, `Authorization` or spoofed `X-API-Key` never
reaches the origin — the only credential it sees is the one injected from the
`SCANNER_API_KEY` secret. Request and response bodies are streamed, never
buffered, so a large codebase upload can't exhaust the isolate's 128 MB.

`POST /api/scan` returns `202 {id, status}` immediately; the UI then polls
`GET /api/scan/{id}` until it reports `succeeded` or `failed`. While a scan is
`running`, that response also carries a `progress` object (`phase`,
`completed`, `total`, and the tail of the scanner's log) which
`ScanProgressPanel` renders. Progress is reported per phase rather than as one
0–100% bar because the phases take wildly unequal amounts of time.

## One deploy, no CORS

The Worker's `assets` config serves the built React app directly and only
routes `/api/*` to the fetch handler (`run_worker_first: ["/api/*"]`,
`not_found_handling: "single-page-application"`). Everything ships as a single
`wrangler deploy`.

## Configuration

`wrangler.jsonc` is committed with a **placeholder** `SCANNER_ORIGIN` and no
route, so a fresh clone deploys to a `*.workers.dev` URL with no setup. To
point it at your own scanner, copy it to `wrangler.local.jsonc` (gitignored),
fill in the real origin and route, and deploy with `-c wrangler.local.jsonc`.

`SCANNER_API_KEY` is a secret and must never go in either file:

```powershell
npx wrangler secret put SCANNER_API_KEY
```

For `wrangler dev`, put a local copy in `worker/.dev.vars` (gitignored).

## Setup

Requires Node.js 18+ and a Cloudflare account. No Docker.

```powershell
# 1. Install deps
cd cloudflare/worker; npm install
cd ../app; npm install

# 2. Build the React app first — the Worker serves its dist/ output
npm run build            # from cloudflare/app

# 3. Local dev (two terminals)
cd ../worker; npm run dev      # wrangler dev, http://localhost:8787
cd ../app; npm run dev         # vite, proxies /api to :8787

# 4. Regenerate the Env type from your actual bindings (optional but recommended)
cd ../worker; npm run types

# 5. Deploy
npm run deploy                              # placeholder config
npx wrangler deploy -c wrangler.local.jsonc # your own origin/route
```

`wrangler login` first if you haven't authenticated this machine before.

## Known limitations

- **Requires a scanner origin.** The Worker does no scanning itself; without a
  reachable `SCANNER_ORIGIN` every `/api` call returns `503`. Standing up the
  scanner API is out of scope for this directory.
- **Upload limits.** SBOM files are capped at 15 MB and codebase archives at
  50 MB to bound per-scan resource use.
- **Only the two implemented charts are in the UI** (tier bar chart,
  per-finding radar) — the dependency-graph diagram, dimension scatter plot,
  and composite histogram remain `NotImplementedError` stubs in
  `output/visualize.py` itself (see `VISUALIZATION.md`), so there's nothing yet
  for the UI to call.
- **Polling, not push.** Scan status is polled every 2.5 s while running. A
  WebSocket or SSE stream would be tighter, but polling survives a Worker
  restart mid-scan and needs no connection state.
