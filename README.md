# SBOM-Supply-chain-CMU

SBOM Vulnerability Scoring Tool — scores vulnerabilities in a Software Bill
of Materials using a six-dimension weighted composite model instead of
relying on CVSS alone. Academic/professional project with an accompanying
research paper.

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

## Status

Project skeleton only. The module structure in `sbom_scorer/` matches
`ARCHITECTURE.md`'s layout, with docstring-only stub functions (all raise
`NotImplementedError`). Nothing is wired up yet — no API calls, no scoring
logic, no graphing. Fill in incrementally, module by module.

## Project Structure

```
sbom_scorer/
├── sbom_parser.py          # CycloneDX/SPDX ingestion → dependency graph
├── vex.py                  # VEX status parsing + override gate
├── composite.py            # weighted scoring + tier bucketing
├── dimensions/              # one module per scoring dimension
├── data_sources/            # OSV, EPSS, KEV, Scorecard, registry clients
├── callgraph/                # Python (JARVIS/PyCG) and Java (CodeQL) wrappers
└── output/                   # report.py (JSON/CSV/console), visualize.py (charts)
tests/
weights.yaml                 # dimension weights, tier thresholds, defaults
main.py                      # CLI entry point (stub)
```

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest tests/
```

## Tech Stack

Python 3.11+, NetworkX, CycloneDX/SPDX parsing libraries, matplotlib/plotly/pyvis
for visualization. See `PROJECT.md` "Tech Stack Assumptions" for the full list.
