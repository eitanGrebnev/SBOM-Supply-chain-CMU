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
- Batch endpoint: `POST /v1/querybatch`
- Response includes `published` date, `affected[].ranges[].events` (contains
  `introduced`/`fixed` version markers), and `references[]` (look for
  `type: "FIX"` to get the fix commit URL).
- Rate limits: no published hard limit as of research; batch endpoint
  recommended for scanning many packages at once. Response size capped at
  32MiB over HTTP/1.1 — use HTTP/2 for large SBOM scans.
- No fixed-version release *timestamp* is provided directly — resolve that
  via the package registry (below).

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

- Public REST API: `https://api.securityscorecards.dev/projects/{owner}/{repo}`
  (e.g. `github.com/psf/requests` → path `github.com/psf/requests`)
- Returns per-check scores (0–10, or `-1` for not-applicable) plus an
  aggregate score.
- Weekly-batch API results omit `CI-Tests`, `Contributors`, and
  `Dependency-Update-Tool` checks due to compute cost at scale — be aware
  these three may simply be absent from the API response even when
  applicable.
- If a repo isn't indexed, the API returns a 404/no-data — treat as
  "no Scorecard data," not "worst score."
- Fallback for un-indexed repos: run the Scorecard CLI/Docker image directly
  against the repo (requires a GitHub personal access token, slower, only
  worth doing if the dependency is important enough to justify it).

## Package Registries (for patch latency fix-date resolution)

- **PyPI:** `https://pypi.org/pypi/{package}/{version}/json` →
  `urls[0].upload_time_iso_8601`
- **npm:** `https://registry.npmjs.org/{package}` → `time[version]`
- **Maven Central:** query via `search.maven.org` REST API, timestamp field
  in the returned doc
- **RubyGems:** `https://rubygems.org/api/v1/versions/{gem}.json` → per-version
  `created_at`
- **crates.io:** `https://crates.io/api/v1/crates/{crate}` → per-version
  `created_at`

## SBOM Input Formats

- **CycloneDX:** parsed via `cyclonedx-python-lib`. Key fields:
  `dependencies[]` (graph edges), `components[]`, custom `properties[]` for
  exposure-tier tagging.
- **SPDX:** parsed via `spdx-tools`. Key fields: `relationships[]`
  (equivalent graph edges, note SPDX uses a different relationship-type
  vocabulary than CycloneDX's flat `dependsOn`).

## VEX

- Not a separate API — VEX documents are typically embedded in or
  distributed alongside the SBOM (CycloneDX has native VEX support; SPDX via
  its security-vulnerability extension; CSAF as a standalone format).
- Parse for `analysis.state` (CycloneDX) or equivalent — values include
  `affected`, `not_affected`, `fixed`, `under_investigation`. Only
  `not_affected` triggers the score-suppression override described in
  `SCORING_MODEL.md`.

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
