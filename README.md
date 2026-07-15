# SBOM-Supply-chain-CMU

SBOM Vulnerability Scoring Tool — scores vulnerabilities in a Software Bill
of Materials using a six-dimension weighted composite model instead of
relying on CVSS alone. Academic/professional project with an accompanying
research paper.

## Status

The Exploitability dimension is implemented, including batched EPSS lookup,
CISA KEV override metadata, percentile scoring, and daily local JSON caches.
The remaining dimensions and end-to-end CLI orchestration are still scaffolded
as stubs. The command-line tool below installs and runs, but does not yet run a
complete scan.

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
worked. To actually run a scan (once the scoring logic is implemented),
point it at an SBOM file:

```bash
sbom-scorer path/to/your-sbom.json
```

Common options:

| Option | What it does |
|---|---|
| `--codebase ./my-app` | Path to your application's source code, used for reachability analysis |
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
