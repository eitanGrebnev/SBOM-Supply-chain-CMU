# External Data Sources

Reference for every external API/data source this tool depends on. All are
free/public; no API keys required for any of them as of this writing, but
verify current terms before relying on this in a shipped tool.

---

## OSV.dev

**Used for:** Patch Latency (disclosure date, fixed version), and as a
general vulnerability lookup source.

- Base API: `https://api.osv.dev/v1/query` (POST)
- Query by package + version:
  ```json
  {"package": {"name": "jinja2", "ecosystem": "PyPI"}, "version": "2.4.1"}
  ```
- Query by commit hash:
  ```json
  {"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"}
  ```
- Batch endpoint: `POST /v1/querybatch` — same `queries: [...]` list of the
  single-query payload shape above, but each result's `vulns[]` entries
  come back **abbreviated to just `id` and `modified`** (no `published`,
  `affected[].ranges[].events`, `references[]`, or `aliases`). Enough to
  know a package has *some* hit, not enough to resolve a CVE alias or get
  fix/disclosure detail — still need the single-query endpoint for that.
- Response includes `published` date, `affected[].ranges[].events` (contains
  `introduced`/`fixed` version markers), and `references[]` (look for
  `type: "FIX"` to get the fix commit URL).
- Rate limits: no published hard limit as of research; batch endpoint
  recommended for scanning many packages at once. Response size capped at
  32MiB over HTTP/1.1 — use HTTP/2 for large SBOM scans.
- No fixed-version release *timestamp* is provided directly — resolve that
  via the package registry (below).

**Implementation note:** `osv_client.py` implements both endpoints —
`query_by_package()` (single, full detail, in-process memoized) and
`query_batch()` (batch, abbreviated). `cli.py`'s CVE-discovery step
(`_batch_prefilter_candidates`) uses the batch endpoint as a cheap first
pass across the whole SBOM, then only runs the slower full-detail
`query_by_package` call on components the batch pass actually flagged —
most real dependency trees are mostly clean, so this cuts the number of
full-detail OSV round-trips substantially (e.g. 218 components down to the
~30 that actually had a hit, in one real test run). If the batch call
itself fails, the prefilter fails open (checks every component
individually, same as before this existed) rather than risking an entire
SBOM silently looking clean because of one failed request — see
`query_batch`'s docstring for why it deliberately raises on failure
instead of swallowing the error like `query_by_package` does.

## FIRST.org EPSS API

**Used for:** Exploitability.

- Base: `https://api.first.org/data/v1/epss`
- Single CVE: `?cve=CVE-2022-26332`
- Batch (comma-separated): `?cve=CVE-2022-27225,CVE-2022-27223`
- Filter by score threshold: `?epss-gt=0.5`
- Historical/time-series: `?cve=CVE-XXXX&scope=time-series`
- Specific date: `?cve=CVE-XXXX&date=2022-03-05`
- Free, no auth. Refresh daily — EPSS scores update daily.
- As of EPSS v4 (March 2025), CVEs in the NVD backlog without an official
  CVSS score can still have EPSS scores — don't assume "no CVSS" means "no
  EPSS."
- Each record returns both `epss` (raw probability, 0–1) and `percentile`
  (rank relative to all other scored CVEs, 0–1). Per `DIMENSIONS.md` #2,
  the scoring table is keyed off **`percentile`**, not the raw `epss`
  value — raw probabilities cluster near zero for most CVEs, so percentile
  rank gives a usable spread where a linear probability mapping wouldn't.

## CISA KEV Catalog

**Used for:** Exploitability (override signal).

- JSON feed: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Also available as CSV/HTML from the CISA KEV catalog page.
- Static file — no query parameters, pull the whole catalog and check CVE ID
  membership locally.
- Refresh daily (or on a schedule appropriate to scan frequency).
- Fields of interest: `cveID`, `dateAdded`, `dueDate`, `knownRansomwareCampaignUse`.

## OSSF Scorecard

**Used for:** Maintainer Health.

- Public REST API: `https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}`
  (e.g. `github.com/psf/requests` → full path
  `.../projects/github.com/psf/requests`). GitHub-only — Scorecard's public
  API and most of its individual checks don't cover other forges.
- A `Component` doesn't carry an owner/repo directly, so it's resolved first
  via `sbom_scorer.data_sources.repo_resolver.resolve_github_repo()`: prefer
  the component's `vcs_url` (from CycloneDX `externalReferences`, type
  `vcs`), else fall back to the repo URL declared in the package's registry
  entry (see Package Registries below). Non-GitHub or unresolvable repos are
  treated as "no Scorecard data."
- Returns per-check scores (0–10, or `-1` for not-applicable) plus an
  aggregate score.
- Weekly-batch API results omit `CI-Tests`, `Contributors`, and
  `Dependency-Update-Tool` checks due to compute cost at scale — be aware
  these three may simply be absent from the API response even when
  applicable. `Contributors` is one of the six checks
  `dimensions/maintainer_health.py` scores against, so it treats a missing
  key the same as an explicit `-1`: redistribute its weight.
- If a repo isn't indexed, the API returns a 404/no-data — treat as
  "no Scorecard data," not "worst score."
- Fallback for un-indexed repos: `scorecard_client.run_scorecard_cli` runs
  the Scorecard CLI (preferring a local `scorecard` binary on PATH, falling
  back to `docker run gcr.io/openssf/scorecard`) directly against the repo.
  Requires a GitHub PAT (`GITHUB_AUTH_TOKEN`/`GH_TOKEN` env var, or passed
  explicitly) and is much slower than the REST API since it clones and
  statically analyzes the repo rather than reading a precomputed weekly
  result — deliberately **not** auto-invoked by `maintainer_health.py` when
  `get_scorecard()` returns "not indexed"; it's an opt-in fallback callers
  reach for only when a specific dependency is important enough to justify
  the latency, per the tradeoff described above.

## Package Registries

Used for patch latency fix-date resolution, and — via
`registry_client.get_repo_url()` — as the Maintainer Health repo-resolution
fallback described above (same per-package JSON payloads, no extra request).

- **PyPI:** `https://pypi.org/pypi/{package}/{version}/json` →
  `urls[0].upload_time_iso_8601` for release date;
  `https://pypi.org/pypi/{package}/json` → `info.project_urls`/`info.home_page`
  for repo URL.
- **npm:** `https://registry.npmjs.org/{package}` → `time[version]` for
  release date, top-level `repository` field for repo URL.
- **Maven Central:** `search.maven.org`'s solrsearch REST API (`core=gav`,
  `q=g:"{groupId}" AND a:"{artifactId}" AND v:"{version}"`) → `timestamp`
  (epoch ms) for release date. No repo URL in the search index though — for
  that, the same API (without the `v:` filter) finds the `latestVersion`,
  then the artifact's actual POM is fetched from
  `repo1.maven.org/maven2/{group-path}/{artifactId}/{version}/...pom` and
  parsed for `<scm><url>`, falling back to `<url>`. `package` is passed as
  "groupId:artifactId" (matching `sbom_parser`'s Maven component naming —
  CycloneDX's own `name` field alone is only the artifactId).
- **RubyGems:** `https://rubygems.org/api/v1/versions/{gem}.json` → per-version
  `created_at` for release date; `https://rubygems.org/api/v1/gems/{gem}.json`
  → `source_code_uri` (preferred) or `homepage_uri` for repo URL.
- **crates.io:** `https://crates.io/api/v1/crates/{crate}` → per-version
  `created_at` for release date, `crate.repository` (preferred) or
  `crate.homepage` for repo URL. crates.io's API policy requires a
  descriptive `User-Agent` on every request (a generic one can be
  rate-limited/blocked) — both lookups send one.

**Implementation note:** all five registries' release-date and repo-URL
lookups are implemented (`registry_client.py`) — Maven/RubyGems/crates.io
were the last three filled in, since their absence meant Patch Latency
silently always used the disclosure-date "no fix resolvable" formula for
those ecosystems even when OSV reported a real fix version, and Maintainer
Health's repo-resolution fallback never worked for them either.

## GitHub Dependency-Graph SBOM

**Used for:** the `--repo` input mode — scanning a repository by URL instead
of supplying a local SBOM file (`sbom_scorer.data_sources.github_sbom`).

- Endpoint: `GET https://api.github.com/repos/{owner}/{repo}/dependency-graph/sbom`
- Returns an SPDX document (JSON) describing the repo's dependencies; the
  tool extracts the inner `sbom` object and feeds it to the SPDX parser.
- No external SBOM generator (syft/cdxgen) required — GitHub builds the SBOM
  from its own dependency graph.
- Auth: works unauthenticated for public repos but is heavily rate-limited.
  Set `GITHUB_TOKEN` (or `GH_TOKEN`) in the environment to raise the limit
  and to reach private repos; it's sent as a Bearer credential and never
  logged. Accepts a full URL, `git@` form, or a bare `owner/repo`.

## SBOM Input Formats

- **CycloneDX (JSON or XML):** parsed via `cyclonedx-python-lib` — content
  (not file extension) decides which decoder runs; both deserialize into the
  same `Bom` object, walked identically by `_build_from_cyclonedx_bom`.
  Fields consumed: `components[]` (name/version/ecosystem/purl),
  `externalReferences` (type `vcs` → `Component.vcs_url`),
  `metadata.component.properties[]` (the `exposure:tier` tag), `dependencies[]`
  graph edges, and `vulnerabilities[]`/VEX (see below).
- **SPDX (JSON or tag-value):** JSON is hand-parsed by `sbom_parser._parse_spdx`,
  covering the slice GitHub's dependency-graph export produces —
  `packages[]` with a purl in `externalRefs` (name/version/ecosystem derived
  from the purl, falling back to `name`/`versionInfo`) and `relationships[]`
  graph edges. Tag-value is parsed via spdx-tools' `tagvalue_parser` into a
  typed `Document`, then mapped through the same purl-first logic in
  `_build_from_spdx_document`.

## VEX

- Not a separate API — VEX documents are typically embedded in or
  distributed alongside the SBOM (CycloneDX has native VEX support; SPDX via
  its security-vulnerability extension; CSAF as a standalone format).
- Parse for `analysis.state` (CycloneDX) or equivalent — values include
  `affected`, `not_affected`, `fixed`, `under_investigation`. Only
  `not_affected` triggers the score-suppression override described in
  `SCORING_MODEL.md`.

**Implementation note:** `sbom_scorer.sbom_parser._apply_vulnerabilities`
parses CycloneDX `vulnerabilities[]` (JSON only) — resolving a CVE id from
`.id` or a CVE-shaped alias in `.references[]`, matching `affects[].ref`
against parsed components, and mapping each `analysis.state` onto this
vocabulary (CycloneDX's own `ImpactAnalysisState` terms differ slightly:
`not_affected`/`false_positive` -> `not_affected`, `exploitable` ->
`affected`, `resolved`/`resolved_with_pedigree` -> `fixed`, `in_triage` ->
`under_investigation`) into `Component.vex_statuses`, which
`sbom_scorer.vex.get_vex_status` reads directly. SPDX's
security-vulnerability extension and standalone CSAF are not parsed —
GitHub's dependency-graph SBOM export (this project's SPDX source) doesn't
carry either.

---

## Caching Strategy (general)

| Source | Suggested refresh interval | Notes |
|---|---|---|
| OSV.dev | Per-scan (live) | Query is cheap and specific to package+version |
| EPSS | Daily | Scores update daily; no need to re-query more often |
| CISA KEV | Daily | Static file, small |
| OSSF Scorecard | Weekly | Scorecard's own batch scan runs weekly |
| Package registry release dates | Cache indefinitely per version | Release dates never change once published |

EPSS and KEV caches default to `~/.cache/sbom-scorer/epss.json` and
`~/.cache/sbom-scorer/kev.json`. Set `SBOM_SCORER_EPSS_CACHE` or
`SBOM_SCORER_KEV_CACHE` to override either location. EPSS caches both returned
records and queried CVEs that had no record, preventing repeated same-day
lookups for known misses.

Scorecard's cache defaults to `~/.cache/sbom-scorer/scorecard.json`
(override via `SBOM_SCORER_SCORECARD_CACHE`), keyed per `owner/repo` rather
than one shared feed — each project is cached independently, refetched once
its entry is more than `CACHE_MAX_AGE_DAYS` (7) old. A 404 (unindexed repo)
is cached as `null`, not retried every run.
