Live site: https://sbom.grebnev.org/

# SBOM-Supply-chain-CMU

SBOM Vulnerability Scoring Tool — scores vulnerabilities in a Software Bill
of Materials using a six-dimension weighted composite model instead of
relying on CVSS alone. Academic/professional project with an accompanying
research paper.

## Status

**The tool runs a complete end-to-end scan** (SBOM in → tiered, scored
findings + charts out). All six scoring dimensions are implemented, and the
composite scorer, VEX gate, CLI orchestration, and report/chart output are
all wired:

- **Exploitability** — batched EPSS lookup, CISA KEV override metadata,
  percentile scoring, daily local JSON caches.
- **Patch Latency** — OSV.dev disclosure/fix-version lookup plus package
  registry release-date resolution, with separate fix-exists vs.
  no-fix-exists scoring.
- **Maintainer Health** — OSSF Scorecard per-check scores reweighted via a
  custom sub-formula, with GitHub repo resolution from SBOM data or package
  registry metadata, and a weekly local cache.
- **Exposure Context** — fixed exposure tiers (`dev_only`/`internal`/
  `internet_facing`) read from a CycloneDX SBOM's tagged exposure property,
  defaulting to worst-case when untagged.
- **Dependency Centrality** — reachable-dependents (log2-normalized) and
  betweenness centrality over the SBOM's parsed dependency graph, averaged
  into one 0–10 score.
- **Reachability** — import check plus a same-codebase static call graph;
  pass `--codebase` to score it, otherwise it falls back to its documented
  missing-data default like Centrality does when the graph has no edges.
  Python codebases use a built-in AST walker (no extra setup). Java/Maven
  codebases use the [CodeQL CLI](https://github.com/github/codeql-action/releases)
  — **entirely optional**: if `codeql` isn't installed, Java components just
  fall back to the same indeterminate default, no error, no other feature
  affected. Only install it if you specifically want confirmed (not
  indeterminate) reachability scores for a Java app.
- **Composite + VEX + output** — VEX gate (`not_affected` suppresses a
  finding to 0/Informational, fed by a CycloneDX SBOM's embedded
  `vulnerabilities[]`/`analysis.state`, not just usable in theory), weighted
  composite scoring with tier bucketing, and console / JSON / CSV reports
  plus tier-distribution and radar charts.

**Two input modes:** point the tool at a local SBOM file, or give it a
GitHub repo (`--repo owner/repo`) and it fetches the repo's dependency-graph
SBOM automatically.

SBOM parsing handles **CycloneDX (JSON or XML) and SPDX (JSON or
tag-value)** — components, dependency-graph edges (CycloneDX
`dependencies[]` / SPDX `relationships[]`), and for CycloneDX also
exposure-tier tagging, VCS references, and embedded vulnerabilities/VEX.

## How to Run It

You'll need [Python](https://www.python.org/downloads/) 3.11 or newer
installed. To check, open a terminal (Terminal on Mac, Command Prompt or
PowerShell on Windows) and type:

```bash
python3 --version
```

If that shows `Python 3.11` or higher, you're set. If not, install it from
the link above first.

**Step 1 — Open a terminal in this project folder.**
On Mac/Linux, `cd` into the folder. On Windows, you can usually right-click
the folder and choose "Open in Terminal."

**Step 2 — Create an isolated environment for this project (recommended).**
This keeps the tool's dependencies separate from anything else on your
computer. You only need to do this once:

```bash
python3 -m venv .venv
```

Then activate it (do this every time you open a new terminal to work on
this project):

```bash
# Mac/Linux
source .venv/bin/activate

# Windows (Command Prompt)
.venv\Scripts\activate.bat

# Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

You'll know it worked because your terminal prompt will now start with
`(.venv)`.

**Step 3 — Install the tool.**

```bash
pip install -e .
```

This reads `pyproject.toml` and installs the tool along with everything it
needs, and adds a new command called `sbom-scorer` that you can now run
from this terminal.

**Step 4 — Run it.**

```bash
sbom-scorer --help
```

That prints the list of options — a good way to confirm the install
worked. To run a real scan, point it at an SBOM file:

```bash
sbom-scorer path/to/your-sbom.json
```

CVE discovery and per-finding scoring each make one network call per
component/finding, so a large SBOM can take a few minutes — progress bars
on screen show how far along each step is rather than sitting silent.

Or scan a GitHub repository directly — the tool fetches the repo's
dependency-graph SBOM for you (no need to generate one first):

```bash
sbom-scorer --repo owner/repo
```

For private repos or to avoid GitHub rate limits, set a token first
(`$env:GITHUB_TOKEN = "..."` on PowerShell, `export GITHUB_TOKEN=...` on
Mac/Linux).

Common options:

| Option | What it does |
|---|---|
| `--repo owner/repo` | Scan a GitHub repo by URL / `owner/repo` instead of a local SBOM file |
| `--charts` | Also write tier-distribution and radar charts (PNG) to the output dir |
| `--codebase ./my-app` | Path to your application's source code, used for Reachability analysis (Python or Java/Maven) |
| `--output-dir ./results` | Where to save the report and charts |
| `--format json` | Output format — `json`, `csv`, or `console` (default) |
| `--version` | Print the installed version and exit |

**No install, just testing?** You can also run the tool directly without
installing it, straight from a fresh copy of this folder:

```bash
python3 main.py --help
```

This is handy while the tool is still being built, but installing with
`pip install -e .` (Step 3) is the normal way to use it.

## Cloudflare Deployment (Web UI)

Prefer a browser over a terminal? The [`cloudflare/`](cloudflare/) folder
has a Cloudflare-native version: a React UI plus a Worker API that runs
this same, unmodified `sbom_scorer` package inside a
[Sandbox SDK](https://developers.cloudflare.com/sandbox/) container — no
scoring logic is reimplemented. See [`cloudflare/README.md`](cloudflare/README.md)
for setup, architecture, and known v1 limitations (public repos only, no
`--codebase` codegen tooling beyond zip upload, upload size caps).

## Running the Tests

If you also want to run the test suite (useful for contributors, not
required just to use the tool):

```bash
pip install -e ".[dev]"
pytest tests/
```

## Documentation

Full design detail lives in these reference files at the repo root — read
`PROJECT.md` first:

- `PROJECT.md` — entry point, purpose, key design decisions
- `DIMENSIONS.md` — the six scoring dimensions and how each is computed
- `SCORING_MODEL.md` — composite formula, weights, tier thresholds, VEX override
- `DATA_SOURCES.md` — external APIs used, endpoints, caching notes
- `ARCHITECTURE.md` — module layout and data flow
- `HYPOTHESIS.md` — the research hypothesis this tool tests
- `VISUALIZATION.md` — required chart/graph output

## Project Structure

```
sbom_scorer/
├── sbom_parser.py          # CycloneDX/SPDX ingestion → dependency graph
├── vex.py                  # VEX status parsing + override gate
├── composite.py            # weighted scoring + tier bucketing
├── dimensions/              # one module per scoring dimension
├── data_sources/            # OSV, EPSS, KEV, Scorecard, registry clients
├── callgraph/                # Python (JARVIS/PyCG) and Java (CodeQL) wrappers
├── output/                   # report.py (JSON/CSV/console), visualize.py (charts)
└── cli.py                    # CLI logic (installed as the `sbom-scorer` command)
tests/
weights.yaml                  # dimension weights, tier thresholds, defaults
pyproject.toml                 # packaging + `sbom-scorer` console-script entry point
main.py                       # dev-mode shim, runs the CLI without installing
```

## Tech Stack

Python 3.11+, NetworkX, CycloneDX/SPDX parsing libraries, matplotlib/plotly/pyvis
for visualization. See `PROJECT.md` "Tech Stack Assumptions" for the full list.
