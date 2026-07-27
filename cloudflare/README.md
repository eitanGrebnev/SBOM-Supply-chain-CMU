# Cloudflare deployment

A Cloudflare-native version of the SBOM scorer: a React UI + a Worker API
that runs the **existing, unmodified** `sbom_scorer` Python package inside a
[Sandbox SDK](https://developers.cloudflare.com/sandbox/) container. No
scoring logic is reimplemented — the Worker just uploads input, shells out
to the real `sbom-scorer` CLI, and reads back its JSON report.

```
cloudflare/
├── worker/            # Cloudflare Worker + Sandbox container
│   ├── wrangler.jsonc  # containers / durable_objects / assets config
│   ├── Dockerfile      # sandbox image; pip-installs the repo-root package
│   └── src/
│       ├── index.ts        # fetch handler: /api/health, /api/scan, static assets
│       ├── sandboxScan.ts  # sandbox lifecycle: write input, exec CLI, read report
│       └── types.ts        # JSON contract shared with the CLI's report.py
└── app/                # React + Vite + TypeScript + Recharts UI
    └── src/
        ├── App.tsx               # top-level state + layout
        ├── api.ts / types.ts     # /api/scan client + shared types
        ├── constants.ts          # tier colors/order, dimension labels
        └── components/
            ├── ScanForm.tsx      # file/repo input, advanced options
            ├── SummaryCards.tsx  # tier counts
            ├── TierBarChart.tsx  # mirrors visualize.py's tier_distribution_bar()
            ├── FindingsTable.tsx # sortable/filterable/searchable findings list
            └── FindingDetail.tsx # mirrors visualize.py's finding_radar()
```

## Why a Sandbox container, not a rewrite

The scoring pipeline (`sbom_parser.py`, `dimensions/*.py`, `composite.py`,
`vex.py`, `cli.py`) depends on `networkx`, `cyclonedx-python-lib`,
`spdx-tools`, and outbound calls to OSV/EPSS/CISA-KEV/OSSF-Scorecard/package
registries — a straight port to Workers (V8 isolates, no arbitrary
subprocess/native deps) isn't practical. The
[Sandbox SDK](https://developers.cloudflare.com/sandbox/) runs a real,
Durable-Object-backed container per request instead, so the Python code
runs completely unchanged.

## One deploy, no CORS

The Worker's `assets` config (`wrangler.jsonc`) serves the built React app
directly and only routes `/api/*` to the fetch handler
(`run_worker_first: ["/api/*"]`, `not_found_handling: "single-page-application"`).
Everything ships as a single `wrangler deploy`.

## Setup

Requires [Docker](https://www.docker.com/) locally (the Sandbox container
image is built from `worker/Dockerfile`), Node.js 18+, and a Cloudflare
account.

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
npm run deploy            # from cloudflare/worker — builds container image, deploys Worker + assets
```

`wrangler login` first if you haven't authenticated this machine before.

## Known v1 limitations

- **Public repos only.** `--repo` scans don't pass a `GITHUB_TOKEN` into the
  sandbox — avoids handling a user-supplied secret inside a shell-exec'd
  command. Private-repo scanning still works from the local CLI
  (`GITHUB_TOKEN`/`GH_TOKEN` env var — see the root `README.md`).
- **Upload limits.** SBOM files are capped at 15 MB, codebase archives at
  50 MB (`sandboxScan.ts`), to bound per-request container resource use.
- **Only the two implemented charts are in the UI** (tier bar chart,
  per-finding radar) — the dependency-graph diagram, dimension scatter
  plot, and composite histogram remain `NotImplementedError` stubs in
  `output/visualize.py` itself (see `VISUALIZATION.md`), so there's nothing
  yet for the UI to call.
- Each scan spins up and tears down its own sandbox instance
  (`crypto.randomUUID()` per request) — no session reuse or caching across
  scans yet.
