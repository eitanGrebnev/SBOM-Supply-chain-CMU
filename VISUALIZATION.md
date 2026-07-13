# Visualization Output

The tool needs to produce visual output of the scoring results, not just a
JSON/CSV table. This file specifies what to graph, why, and with what tools.

## Why Visualization Matters Here

A weighted six-dimension composite score is hard to sanity-check from a
number alone — "Critical, 84/100" doesn't tell you *why*. The graphs below
are meant to answer "why did this score the way it did" and "what does our
overall risk posture look like," which matters both for the tool's practical
usefulness and for the paper's results section (H1/H2 in `HYPOTHESIS.md`
both benefit from visual comparison, not just tables of numbers).

## Recommended Graph Types

### 1. Tier Distribution Bar Chart (overall posture)
A single bar chart showing count of findings per tier (Critical / High /
Medium / Low / Informational). This is the highest-level "how are we doing"
view, and the most directly useful chart for H1 (noise reduction): plot this
twice, once for CVSS-only classification and once for the composite model,
side by side, to visually show the reduction in Critical/High volume.

- Library: `matplotlib` (simple bar chart, no interactivity needed) or
  `plotly` if an interactive/exportable HTML chart is preferred.

### 2. Per-Finding Radar/Spider Chart (dimension breakdown)
For any individual CVE/component finding, a radar chart with one axis per
dimension (Reachability, Exploitability, Exposure, Centrality, Patch
Latency, Maintainer Health) showing that finding's 0–10 score on each axis.
This directly answers "why did this score Critical" — e.g. a chart that's
maxed out on Exploitability and Exposure but low on Reachability tells a
very different story than one maxed out on Reachability and Centrality.

- Library: `matplotlib` (polar projection) is sufficient; `plotly`'s
  `Scatterpolar` gives a nicer interactive version if the output is meant to
  be browsed rather than printed.

### 3. Dependency Graph Visualization (blast radius / centrality)
A node-link graph of the SBOM's dependency tree, with node size or color
scaled to blast-radius (ancestor count) and/or composite risk score. This
is the most visually compelling output and doubles as a sanity check on the
Centrality dimension's graph-building logic.

- Library: `networkx` for the graph structure (already a dependency per
  `ARCHITECTURE.md`) combined with either:
  - `matplotlib` + `nx.draw()` for a simple static image, or
  - `pyvis` for an interactive HTML network graph (recommended if this is
    going in a report/demo rather than a paper figure — much easier to
    explore for a large dependency tree)

### 4. Scatter Plot — Reachability vs. Exposure (or any two dimensions)
A 2D scatter plot with one dimension score per axis (e.g. Reachability on
x, Exposure on y), each point representing one finding, colored by tier.
This is useful for visually testing the "modeling simplification" limitation
noted in `SCORING_MODEL.md` and `HYPOTHESIS.md` — it should make visible
whether findings cluster in the "both high" quadrant (genuinely dangerous)
vs. spread across quadrants (where the multiplicative-vs-additive question
actually matters).

- Library: `matplotlib` or `plotly` scatter, colored by `tier`.

### 5. Composite Score Histogram
A histogram of all composite scores (0–100) across the scanned SBOM, with
vertical lines marking the tier thresholds (20/40/60/80). Useful for
sanity-checking whether the tier boundaries in `SCORING_MODEL.md` actually
split the data sensibly, or whether everything clusters in one bucket and
the thresholds need retuning.

- Library: `matplotlib`.

## Implementation Notes

- All chart-generation functions live in `output/visualize.py` per
  `ARCHITECTURE.md`, and take the same structured findings data the report
  generator uses (per-dimension scores + composite + tier + confidence
  flags) — don't build a separate data path just for charts.
- Default to saving charts as static image files (`.png`/`.svg`) for
  inclusion in a paper/report; add an interactive HTML export path (via
  `plotly` or `pyvis`) as a secondary option for exploring results
  day-to-day, not the primary deliverable.
- Keep chart generation decoupled from scoring logic — `visualize.py` should
  only ever consume already-computed scores, never recompute or call
  external APIs itself.
- For the paper specifically: the tier-distribution comparison (CVSS-only vs.
  composite, chart #1) and the scatter plot (chart #4) are the two most
  directly tied to the stated hypotheses (H1 and the reachability/exposure
  limitation) — prioritize building those two first if time is limited.
