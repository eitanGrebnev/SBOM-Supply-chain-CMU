# Architecture

## Implementation Status

The module layout below is scaffolded in `sbom_scorer/` — every file exists
for the planned architecture. Four of six dimensions are implemented:
Exploitability (batched EPSS lookups, CISA KEV override, joined source
metadata, percentile scoring, daily local caches), Patch Latency (OSV.dev +
package-registry release dates, fix-exists vs. no-fix-exists sub-cases),
Maintainer Health (OSSF Scorecard per-check scores, reweighted sub-formula,
GitHub repo resolution via `vcs_url` or registry metadata, weekly local
cache), and Exposure Context (fixed SSVC-style exposure tiers, read from a
CycloneDX SBOM's tagged exposure property, worst-case default when
untagged/unrecognized). Reachability and Centrality still raise
`NotImplementedError`.

`sbom_parser.py` is now partially implemented: `_parse_cyclonedx` handles
JSON CycloneDX end-to-end for the slice Exposure Context and Maintainer
Health need — `components[]` (name/version/ecosystem/purl),
`externalReferences` (type `vcs`, → `Component.vcs_url`), and
`metadata.component.properties[]` (the SBOM-wide `exposure:tier` tag, →
every `Component.exposure_tier`). It returns a `DiGraph` with one node per
component (keyed by CycloneDX bom-ref) but **no edges** —
`dependencies[]` parsing, XML-encoded CycloneDX, and SPDX (any encoding)
are still out of scope and raise `NotImplementedError`/are simply
unimplemented; that's the next slice, for whoever ends up owning Centrality
or full orchestration. Exploitability, Patch Latency, and Maintainer Health
are each still tested against hand-built `Component` objects rather than a
real parsed SBOM; Exposure Context and the parser slice above are tested
against real (hand-built) CycloneDX JSON fixtures. `weights.yaml` holds the
documented default weights/thresholds; `sbom_scorer/cli.py` has argument
parsing wired but no orchestration pipeline. The package installs as a
proper command-line tool (`sbom-scorer`) via `pyproject.toml` — see
`README.md` for install and invocation instructions.

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
│   │   └── repo_resolver.py    # Component -> GitHub owner/repo, for Maintainer Health
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
└── main.py                      # dev-mode shim — runs the CLI without installing
```

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
