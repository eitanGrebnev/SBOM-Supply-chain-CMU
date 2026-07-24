# SBOM Vulnerability Scoring Tool

## Purpose

A custom supply-chain risk assessment tool that scores vulnerabilities found in a
project's Software Bill of Materials (SBOM) using a six-dimension weighted
composite model, rather than relying on CVSS severity alone. The goal is to
surface a small, high-precision set of vulnerabilities that are both
**reachable** and **exploitable in context**, instead of flooding a team with
every CVE present in the dependency tree regardless of whether it matters.

This file is the entry point for any AI assistant or contributor working on
this codebase. See the companion files for detail:

- `DIMENSIONS.md` — the six scoring dimensions, their definitions, and how each
  is computed
- `DATA_SOURCES.md` — every external API/data source used, with endpoints and
  caching notes
- `SCORING_MODEL.md` — the composite formula, weighting scheme, tier
  thresholds, and VEX override logic
- `ARCHITECTURE.md` — module layout and data flow
- `HYPOTHESIS.md` — the research hypothesis this tool is built to test, for
  anyone writing the accompanying paper/report
- `VISUALIZATION.md` — the graph/chart output the tool needs to produce, and
  what library to use for each

## Research Hypothesis (short form)

A multi-dimensional composite score will produce a more actionable
vulnerability prioritization than CVSS-only triage — surfacing a smaller, more
precise set of true-positive critical risks without missing vulnerabilities
later confirmed as actively exploited. Full hypothesis and sub-hypotheses in
`HYPOTHESIS.md`.

## The Six Dimensions (summary)

| # | Dimension | One-line definition | Weight |
|---|---|---|---|
| 1 | Reachability | Does execution ever reach the vulnerable function in this dependency? | 25% |
| 2 | Exploitability | Percent chance the vulnerability will be exploited (EPSS + KEV) | 20% |
| 3 | Exposure Context | Even if reachable, who/what can reach the system to trigger it? | 20% |
| 4 | Dependency Centrality (Blast Radius) | How many other components depend on this one? | 15% |
| 5 | Patch Latency | How long has a fix been available vs. still unpatched? | 10% |
| 6 | Maintainer Health | How maintained/healthy is the dependency's repo? | 10% |

Full definitions and implementation approach per dimension: see `DIMENSIONS.md`.

## Key Design Decisions (do not silently change these)

1. **VEX overrides everything.** If a component is marked `not_affected` in a
   VEX document, the composite score is suppressed to 0 / Informational before
   any weighting logic runs. VEX is a gate, not a dimension.
2. **Reachability and Exposure Context are conceptually multiplicative, but
   modeled additively for v1.** A vulnerability needs to be *both*
   execution-reachable *and* attacker-reachable to be truly dangerous. The
   current model treats them as independent weighted terms for simplicity.
   This is a known simplification — flag it in any writeup, and consider a
   "gated" model variant (Reachability = 0 suppresses the whole score) as a
   comparison case if there's time to build both.
3. **Missing-data defaults are deliberately inconsistent across dimensions —
   this is intentional, not a bug:**
   - Reachability: default to an **indeterminate mid-score** (~5/10) when no
     call graph can be built or the vulnerable function is unknown. Absence of
     proof is not proof of safety, but shouldn't be scored as certain danger
     either.
   - Exposure Context: default to **worst-case (internet-facing, 10/10)** when
     deployment/exposure data is missing. Unknown exposure should never be
     assumed safe.
   - Maintainer Health: default to a **neutral mid-score** when Scorecard has
     no data for a repo, rather than penalizing it as unmaintained.
   - Patch Latency: if no fix exists yet, this is scored on a **different
     clock** (time since disclosure) than "fix exists but unapplied" (time
     since fix release) — these are two different risk types, not one
     formula.
4. **Weights are a starting hypothesis, not fixed truth.** State them as a
   prior in any paper and, if empirical KEV/EPSS ground-truth validation data
   is available, show whether the data supports adjusting them (see
   `HYPOTHESIS.md`, H2).

## Tech Stack Assumptions

- Python 3.11+
- SBOM formats: CycloneDX (primary), SPDX (secondary) — both JSON and their
  alternate encodings (XML CycloneDX, SPDX tag-value) are parsed today
- SBOM input: a local SBOM file, or a GitHub repo (URL / `owner/repo`) whose
  dependency-graph SBOM is fetched automatically (see `DATA_SOURCES.md`)
- Graph library: NetworkX
- External data: OSV.dev, FIRST.org EPSS API, CISA KEV JSON feed, OSSF
  Scorecard REST API, package registry APIs (PyPI/npm/etc.) for release
  timestamps
- No paid/commercial SCA tooling — everything is free/public API or
  self-computed, since this is an academic project, not a commercial product

## Out of Scope (for now)

- Real-time/continuous scanning (this is a point-in-time scoring tool)
- Container image scanning
- Auto-remediation / PR generation
- Non-Python/Java reachability analysis (C/C++, Go, etc. — call graph tooling
  differs significantly per language and is a stretch goal at best)
