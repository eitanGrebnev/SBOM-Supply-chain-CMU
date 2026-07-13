"""CLI entry point for sbom_scorer.

Per ARCHITECTURE.md data flow: parse SBOM -> build dependency graph ->
resolve component/CVE list -> run the six dimension modules -> apply the
VEX gate -> compute weighted composite + tier -> emit report + charts.

This is a stub CLI. Argument parsing and the orchestration pipeline are not
yet implemented — fill in incrementally per ARCHITECTURE.md as each module
is built out.
"""

from __future__ import annotations

import argparse
import sys


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser.

    Expected arguments (to be implemented):
        sbom_path: Path to the input CycloneDX/SPDX SBOM file.
        --weights: Path to weights.yaml (default: ./weights.yaml).
        --codebase: Path to the application source tree, for reachability
            analysis.
        --output-dir: Directory to write report + chart files to.
        --format: Report format(s) — json, csv, console.
    """
    parser = argparse.ArgumentParser(
        prog="sbom-scorer",
        description="Score SBOM vulnerabilities with a six-dimension weighted composite model.",
    )
    parser.add_argument("sbom_path", help="Path to the CycloneDX/SPDX SBOM file.")
    parser.add_argument("--weights", default="weights.yaml", help="Path to weights config.")
    parser.add_argument("--codebase", default=None, help="Path to application source for reachability analysis.")
    parser.add_argument("--output-dir", default="./output", help="Directory for report + chart output.")
    parser.add_argument(
        "--format",
        default="console",
        choices=["json", "csv", "console"],
        help="Report format.",
    )
    return parser


def run(argv: list[str] | None = None) -> int:
    """Run the full scan pipeline: parse -> score -> gate -> report -> visualize.

    Raises:
        NotImplementedError: Always, in this scaffolding stub — the
        orchestration pipeline (wiring sbom_parser, dimensions/*, vex,
        composite, and output/*) is not yet implemented.
    """
    parser = build_arg_parser()
    parser.parse_args(argv)
    raise NotImplementedError


if __name__ == "__main__":
    sys.exit(run())
