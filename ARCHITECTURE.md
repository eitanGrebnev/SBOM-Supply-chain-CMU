# Architecture

## Implementation Status

The tool now runs a **complete end-to-end scan**: SBOM in → tiered, scored
findings + charts out. What's wired:

- **All six dimensions** are implemented: Exploitability (batched EPSS
  lookups, CISA KEV override, joined source metadata, percentile scoring,
  daily local caches), Patch Latency (OSV.dev + package-registry release
  dates, fix-exists vs. no-fix-exists sub-cases), Maintainer Health (OSSF
  Scorecard per-check scores, reweighted sub-formula, GitHub repo resolution
  via `vcs_url` or registry metadata, weekly local cache), Exposure Context
  (fixed SSVC-style exposure tiers from a CycloneDX SBOM's tagged exposure
  property, worst-case default when untagged), Centrality (log2-normalized
  reachable-dependents + betweenness centrality over the parsed dependency
  graph, averaged — see below), and Reachability (import check + a
  same-codebase static call graph; needs `--codebase` to run, otherwise
  falls back to its missing-data default like Centrality does when the
  graph has no edges). Two call-graph backends: Python components use an
  in-process `ast` walker; Maven/Java components shell out to the `codeql`
  CLI (`callgraph/java_callgraph.py`) — both degrade to indeterminate
  rather than raising if the graph can't be built (no `codeql` binary
  installed, unparseable source, etc.). The vulnerable-function-to-check
  itself is identified by fetching the CVE's fix commit's diff and reading
  the changed function names off the diff's hunk-header context lines
  (`dimensions/reachability._identify_vulnerable_function`).
- **VEX gate** (`vex.py`): `apply_vex_gate` / `get_vex_status` /
  `coerce_vex_status` implemented — `not_affected` suppresses a finding to
  0/Informational before the weighted formula runs. Fed by real SBOM data:
  `sbom_parser._apply_vulnerabilities` reads CycloneDX `vulnerabilities[]`
  (CVE id from `.id` or a CVE-shaped alias in `.references[]`, matched to
  affected components via `affects[].ref`) and maps each `analysis.state`
  onto this project's VEX vocabulary (`not_affected`/`false_positive` ->
  `not_affected`, `exploitable` -> `affected`, `resolved(_with_pedigree)` ->
  `fixed`, `in_triage` -> `under_investigation`). No embedded
  `vulnerabilities[]` entry for a CVE means no VEX statement, so normal
  scoring proceeds — SPDX has no equivalent embedded-VEX field.
- **Composite scorer** (`composite.py`): `load_weights` (from `weights.yaml`,
  with fallback, and validated to sum to 1.0 within float tolerance —
  raises `ValueError` otherwise rather than silently scoring against a
  mis-summed set), `compute_composite` (VEX-gated weighted sum with
  missing-data-default substitution), `bucket_tier`, and `score_finding` are
  implemented.
- **Output layer** (`output/`): `report.py` renders console (`render_console`)
  / JSON (`write_json`) / CSV (`write_csv`) reports plus a tier summary and
  a one-line `explain_finding`; `visualize.py` renders the tier-distribution
  bar chart (`tier_distribution_bar`) and per-finding radar chart
  (`finding_radar`), matplotlib, headless Agg backend. The dependency-graph
  node-link diagram, dimension scatter plot, and composite histogram are
  intentionally still deferred/stubbed.
- **CLI orchestration** (`cli.py`): fully wired — obtain an SBOM (local file
  or fetched from a GitHub repo), parse it, discover each component's CVEs
  (embedded `vulnerabilities[]` first, OSV lookup otherwise), batch-score
  Exploitability, batch-score Centrality (one betweenness pass reused across
  all affected components), score Reachability when `--codebase` is given,
  score the remaining dimensions, apply the VEX gate, compute the composite
  + tier, and emit the report (+ optional `--charts`).
- **GitHub repo input** (`data_sources/github_sbom.py`): scan a repo by URL
  or `owner/repo` instead of a local file — fetches the repo's
  dependency-graph SBOM (SPDX JSON) via the GitHub API, no external SBOM
  generator needed. `GITHUB_TOKEN`/`GH_TOKEN` env var raises rate limits and
  reaches private repos.

`sbom_parser.py` parses **CycloneDX, JSON or XML** (`_parse_cyclonedx` +
`_build_from_cyclonedx_bom` — content, not file extension, decides which;
both encodings deserialize into the same cyclonedx-python-lib `Bom` object,
walked identically) and **SPDX, JSON or tag-value** (`_parse_spdx` +
`_build_from_spdx_document` — JSON is hand-parsed to cover the slice
GitHub's SBOM export produces: `packages[]` with a purl in `externalRefs`;
tag-value is parsed via spdx-tools' `tagvalue_parser`, since hand-rolling
that colon-delimited format safely isn't practical, then mapped through
the same purl-first field logic). Both formats populate `components[]`
(name/version/ecosystem/purl/`bom_ref`), and CycloneDX additionally
populates `vcs_url` (from `externalReferences`, type `vcs`), `exposure_tier`
(from `metadata.component.properties[]`), and `cve_ids`/`vex_statuses` (from
`vulnerabilities[]`, see above). All four format/encoding combinations
return a `DiGraph` with one node per component *and* "depends on" edges
(CycloneDX `dependencies[]` / SPDX `relationships[]` of type `DEPENDS_ON`)
— each `Component.bom_ref` matches its node id in the graph, for
Centrality (and eventually the dependency-graph visualization) to key off
of. `weights.yaml` holds the documented default weights/thresholds/
missing-data defaults. The package installs as a command-line tool
(`sbom-scorer`) via `pyproject.toml` — see `README.md` for install and
invocation instructions.

Known loose ends not covered above: `sbom_scorer/centrality.py` (repo root)
is an orphaned, unwired duplicate of `dimensions/centrality.py` using a
different (non-DIMENSIONS.md) normalization formula — dead code, not a
second code path in use. Centrality's two sub-scores are combined via a
simple average; DIMENSIONS.md flags max as a documented alternative still
worth testing empirically. Reachability's Python call graph is a
lightweight custom AST walker (by bare function name), not the JARVIS/PyCG
tooling `callgraph/python_callgraph.py` was scaffolded for — that module is
still an unimplemented stub and unused by `dimensions/reachability.py`.
Java's `callgraph/java_callgraph.py` counterpart, by contrast, is now real
(shells out to the `codeql` CLI — see Implementation Status above), but is
untested against an actual CodeQL install/database since neither is
available in the dev sandbox this was built in; treat it as implemented-but-
unvalidated until run against a real Java codebase. `patch_latency.py` is
implemented and wired but has no dedicated test module yet, unlike the
other five dimensions.
SPDX's non-standard security-vulnerability extension (SPDX's closest
equivalent to CycloneDX's `vulnerabilities[]`/VEX) is still unparsed —
GitHub's dependency-graph SBOM export doesn't emit it anyway.

## Data Flow

```
SBOM file (CycloneDX/SPDX)
        │
        ▼
  SBOM Parser ──────────────► Dependency Graph (NetworkX)
        │                              │
        │                              ▼
        │                     Centrality / Blast Radius
        │
        ▼
  Component + CVE list (from embedded vuln data or OSV lookup)
        │
        ├──► Reachability module ──────► call graph tools (JARVIS/PyCG/CodeQL)
        ├──► Exploitability module ─────► EPSS API + KEV feed
        ├──► Patch Latency module ──────► OSV.dev + package registries
        ├──► Maintainer Health module ──► OSSF Scorecard API
        └──► Exposure Context module ───► SBOM properties / deployment map
        │
        ▼
  VEX check (gate) ──────► if not_affected: suppress score
        │
        ▼
  Composite Scorer (weighted sum → 0-100 → tier)
        │
        ▼
  Output (JSON / CSV / report) — tiered, sorted findings list
        │
        ▼
  Visualization (charts/graphs) — see VISUALIZATION.md
```

## Suggested Module Layout

```
sbom_scorer/
├── PROJECT.md
├── DIMENSIONS.md
├── DATA_SOURCES.md
├── SCORING_MODEL.md
├── ARCHITECTURE.md
├── HYPOTHESIS.md
├── sbom_scorer/
│   ├── __init__.py
│   ├── sbom_parser.py          # CycloneDX/SPDX ingestion → dependency graph
│   ├── vex.py                  # VEX status parsing + override gate
│   ├── composite.py            # weighted scoring + tier bucketing
│   ├── dimensions/
│   │   ├── __init__.py
│   │   ├── reachability.py
│   │   ├── centrality.py
│   │   ├── exploitability.py
│   │   ├── patch_latency.py
│   │   ├── maintainer_health.py
│   │   └── exposure.py
│   ├── data_sources/
│   │   ├── __init__.py
│   │   ├── osv_client.py
│   │   ├── epss_client.py
│   │   ├── kev_client.py
│   │   ├── scorecard_client.py
│   │   ├── registry_client.py  # PyPI/npm/etc. release-date + repo-url lookups
│   │   ├── repo_resolver.py    # Component -> GitHub owner/repo, for Maintainer Health
│   │   └── github_sbom.py      # GitHub repo URL -> dependency-graph SBOM (SPDX)
│   ├── callgraph/
│   │   ├── __init__.py
│   │   ├── python_callgraph.py # JARVIS/PyCG wrapper
│   │   └── java_callgraph.py   # CodeQL wrapper
│   ├── output/
│   │   ├── __init__.py
│   │   ├── report.py           # JSON/CSV/console report generation
│   │   └── visualize.py        # graph/chart generation — see VISUALIZATION.md
│   └── cli.py                  # CLI logic — installed as the `sbom-scorer` command
├── tests/
│   └── ...
├── pyproject.toml               # packaging + `sbom-scorer` console-script entry point
├── weights.yaml                 # dimension weights, tier thresholds, missing-data defaults
├── main.py                      # dev-mode shim — runs the CLI without installing
└── cloudflare/                  # Cloudflare-native deployment — see cloudflare/README.md
    ├── worker/                  # Worker + Sandbox container that runs this same CLI
    └── app/                     # React + Vite + Recharts UI (SummaryCards/TierBarChart/
                                  # FindingsTable/FindingDetail) served as static assets
```

## Cloudflare Deployment

`cloudflare/` adds an alternative, browser-based deployment path alongside
the local CLI — a Worker (`cloudflare/worker/`) that runs an unmodified
`sbom_scorer` in a [Sandbox SDK](https://developers.cloudflare.com/sandbox/)
container (real Docker image, not a reimplementation of the scoring logic
in JS), fronting a React UI (`cloudflare/app/`) that consumes the exact
same JSON report contract as `output/report.py::write_json`. The Worker
serves the built React app as static assets and only proxies `/api/*` to
its fetch handler, so it's a single `wrangler deploy`, no separate hosting
or CORS setup. See `cloudflare/README.md` for the full setup, the
Dockerfile/`wrangler.jsonc` details, and documented v1 limitations (public
repos only — no `GITHUB_TOKEN` passthrough to the sandbox; SBOM/codebase
upload size caps).

## Design Principles for Implementation

1. **Each dimension module is independent and stateless.** Every module takes
   the inputs it needs (CVE ID, package name/version, SBOM component, etc.)
   and returns a 0–10 float plus a confidence/data-availability flag. No
   module should need to know about the others or about the composite
   weighting.
2. **All external API calls are wrapped in dedicated client modules** (under
   `data_sources/`) with their own caching layer, so dimension modules never
   call `requests` directly. This keeps rate-limiting, retries, and caching
   logic in one place per source.
3. **Every dimension score carries a confidence/data-availability flag**, not
   just a number — e.g. `(score=5.0, confidence="indeterminate")` vs.
   `(score=8.0, confidence="high")`. This makes it possible to distinguish
   "we scored this high because it's genuinely risky" from "we scored this
   mid because we don't have enough data," which matters both for the tool's
   usefulness and for the paper's discussion of limitations.
4. **The composite scorer is the only place weights live.** Don't hardcode
   weights inside individual dimension modules — pass them in from
   `SCORING_MODEL.md`'s documented values (ideally as a config file, e.g.
   `weights.yaml`, so they can be adjusted for the H2 sensitivity analysis
   without touching code).
5. **Output should preserve per-dimension scores, not just the final
   composite** — the report needs to show *why* something scored the way it
   did (e.g. "Critical, driven primarily by Exploitability=10 and
   Exposure=10, despite Reachability=5/indeterminate") for the tool to be
   useful for triage and for the paper's analysis.
