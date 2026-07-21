"""CLI entry point for sbom_scorer.

Installed as the `sbom-scorer` command (see pyproject.toml
[project.scripts]) once the package is installed via `pip install .` or
`pip install -e .`. Also runnable directly during development via
`python main.py ...` (main.py is a thin shim around main() below).

Pipeline (ARCHITECTURE.md data flow): obtain an SBOM (from a file or by
fetching a GitHub repo's dependency-graph SBOM) -> parse -> discover each
component's CVEs (OSV) -> score the implemented dimensions -> apply the VEX
gate -> weighted composite + tier -> emit report (+ charts).

Reachability and Centrality aren't wired yet; the composite substitutes
their documented missing-data defaults (see sbom_scorer.composite). They
slot in additively later without changing this pipeline.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile

from sbom_scorer.composite import (
    DimensionScore,
    Finding,
    load_weights,
    score_finding,
)


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="sbom-scorer",
        description="Score SBOM vulnerabilities with a six-dimension weighted composite model.",
    )
    parser.add_argument(
        "sbom_path",
        nargs="?",
        default=None,
        help="Path to a CycloneDX (JSON) or SPDX (JSON) SBOM file.",
    )
    parser.add_argument(
        "--repo",
        default=None,
        help="GitHub repo URL or 'owner/repo' to scan instead of a local SBOM "
        "file. Fetches the repo's dependency-graph SBOM (set GITHUB_TOKEN in "
        "the environment to raise rate limits / reach private repos).",
    )
    parser.add_argument("--weights", default="weights.yaml", help="Path to weights config.")
    parser.add_argument("--codebase", default=None, help="Path to application source for reachability analysis (not yet used).")
    parser.add_argument("--output-dir", default="./output", help="Directory for report + chart output.")
    parser.add_argument(
        "--format",
        default="console",
        choices=["json", "csv", "console"],
        help="Report format.",
    )
    parser.add_argument(
        "--charts",
        action="store_true",
        help="Also render tier-distribution and per-finding radar charts (PNG) to --output-dir.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s " + _get_version(),
    )
    return parser


def _get_version() -> str:
    """Return the installed package version (from sbom_scorer.__version__)."""
    from sbom_scorer import __version__

    return __version__


def _log(msg: str) -> None:
    """Emit progress to stderr so it doesn't pollute stdout report output."""
    print(msg, file=sys.stderr)


def _safe_dimension(fn, *, default: float, confidence: str = "default") -> DimensionScore:
    """Run a dimension scorer, returning a default DimensionScore on failure."""
    try:
        result = fn()
        if isinstance(result, DimensionScore):
            return result
        return DimensionScore(score=float(result), confidence=confidence)
    except Exception as exc:  # noqa: BLE001 — one bad lookup shouldn't abort the scan
        _log(f"  ! dimension scoring failed ({exc!r}); using default {default}")
        return DimensionScore(score=default, confidence="default")


def _resolve_sbom_path(args, tmp_dir: str) -> str:
    """Return a local SBOM path, fetching from --repo into tmp_dir if needed."""
    if args.repo:
        from sbom_scorer.data_sources import github_sbom

        out_path = os.path.join(tmp_dir, "repo.spdx.json")
        _log(f"Fetching dependency-graph SBOM for {args.repo} ...")
        github_sbom.fetch_sbom_to_file(args.repo, out_path)
        return out_path
    return args.sbom_path


def _discover_cves(component) -> list[str]:
    """Return the component's CVE IDs, discovering via OSV if not embedded."""
    if component.cve_ids:
        return list(component.cve_ids)
    if not component.ecosystem or not component.version:
        return []

    from sbom_scorer.data_sources import osv_client

    try:
        result = osv_client.query_by_package(component.name, component.ecosystem, component.version)
    except Exception as exc:  # noqa: BLE001
        _log(f"  ! OSV lookup failed for {component.name}@{component.version}: {exc!r}")
        return []

    cves: list[str] = []
    seen: set[str] = set()
    for vuln in result.get("vulns", []) or []:
        aliases = vuln.get("aliases") or []
        cve = next((a for a in aliases if str(a).upper().startswith("CVE-")), vuln.get("id"))
        # The same CVE can appear across multiple OSV records (e.g. a GHSA
        # and a PYSEC entry aliasing the same CVE) — dedupe per component.
        if cve and cve not in seen:
            seen.add(cve)
            cves.append(cve)
    return cves


def _safe_batch_exploitability(cve_ids, score_exploitabilities) -> dict:
    """Batch-score exploitability, degrading to per-CVE defaults on failure."""
    try:
        results = score_exploitabilities(cve_ids)
        return {cve: res.dimension_score for cve, res in results.items()}
    except Exception as exc:  # noqa: BLE001
        _log(f"  ! Exploitability batch failed ({exc!r}); using defaults.")
        return {cve: DimensionScore(5.0, "default") for cve in cve_ids}


def _gather_findings(components) -> list[Finding]:
    """Build (un-composited) Findings for every affected component+CVE pair."""
    from sbom_scorer.dimensions.exploitability import score_exploitabilities
    from sbom_scorer.dimensions.exposure import score_exposure
    from sbom_scorer.dimensions.maintainer_health import score_maintainer_health
    from sbom_scorer.dimensions.patch_latency import score_patch_latency
    from sbom_scorer.vex import get_vex_status

    # 1. Discover CVEs per component.
    component_cves: list[tuple] = []
    all_cves: set[str] = set()
    for component in components:
        cves = _discover_cves(component)
        if cves:
            component_cves.append((component, cves))
            all_cves.update(cves)

    _log(f"Discovered {len(all_cves)} unique CVE(s) across {len(component_cves)} affected component(s).")
    if not all_cves:
        return []

    # 2. One batched EPSS+KEV pass for all CVEs (Exploitability).
    exploit_results = _safe_batch_exploitability(sorted(all_cves), score_exploitabilities)

    # 3. Maintainer Health is per-component — compute once and reuse.
    maint_cache: dict[int, DimensionScore] = {}

    findings: list[Finding] = []
    for component, cves in component_cves:
        if id(component) not in maint_cache:
            maint_cache[id(component)] = _safe_dimension(
                lambda c=component: score_maintainer_health(c), default=5.0
            )
        exposure = _safe_dimension(
            lambda c=component: score_exposure(c.exposure_tier), default=10.0
        )
        for cve_id in cves:
            finding = Finding(
                component_name=component.name,
                component_version=component.version,
                cve_id=cve_id,
            )
            finding.exploitability = exploit_results.get(cve_id) or DimensionScore(5.0, "default")
            finding.exposure = exposure
            finding.maintainer_health = maint_cache[id(component)]
            finding.patch_latency = _safe_dimension(
                lambda c=component, v=cve_id: score_patch_latency(c, v), default=0.0
            )
            vex = get_vex_status(component, cve_id)
            finding.vex_status = vex.value if vex is not None else None
            findings.append(finding)

    return findings


def _emit_output(findings, args) -> None:
    """Write the report in the requested format, and optional charts."""
    from sbom_scorer.output import report

    os.makedirs(args.output_dir, exist_ok=True)

    if args.format == "console":
        print(report.render_console(findings))
    elif args.format == "json":
        out = os.path.join(args.output_dir, "findings.json")
        report.write_json(findings, out)
        _log(f"Wrote {out}")
    elif args.format == "csv":
        out = os.path.join(args.output_dir, "findings.csv")
        report.write_csv(findings, out)
        _log(f"Wrote {out}")

    if args.charts and findings:
        from sbom_scorer.output import visualize

        bar = os.path.join(args.output_dir, "tier_distribution.png")
        visualize.tier_distribution_bar(findings, bar)
        _log(f"Wrote {bar}")
        top = max(findings, key=lambda f: f.composite_score or 0.0)
        radar = os.path.join(args.output_dir, "top_finding_radar.png")
        visualize.finding_radar(top, radar)
        _log(f"Wrote {radar}")


def run(args) -> int:
    """Execute the scan pipeline. Returns a process exit code."""
    if not args.sbom_path and not args.repo:
        _log("error: provide an SBOM file path or --repo <github-url>.")
        return 2
    if args.sbom_path and args.repo:
        _log("error: provide either an SBOM file path or --repo, not both.")
        return 2

    from sbom_scorer.sbom_parser import parse_sbom

    with tempfile.TemporaryDirectory(prefix="sbom-scorer-") as tmp_dir:
        try:
            sbom_path = _resolve_sbom_path(args, tmp_dir)
        except Exception as exc:  # noqa: BLE001
            _log(f"error: could not obtain SBOM: {exc}")
            return 1

        try:
            components, _graph = parse_sbom(sbom_path)
        except NotImplementedError as exc:
            _log(f"error: unsupported SBOM format: {exc}")
            return 1
        except Exception as exc:  # noqa: BLE001
            _log(f"error: failed to parse SBOM: {exc}")
            return 1

    _log(f"Parsed {len(components)} component(s). Scoring ...")

    weights = load_weights(args.weights)
    findings = _gather_findings(components)
    for finding in findings:
        score_finding(finding, weights)

    _emit_output(findings, args)
    return 0


def main(argv: list[str] | None = None) -> int:
    """Console-script entry point. Parses args and runs the pipeline."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
