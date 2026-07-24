"""CLI entry point for sbom_scorer.

Installed as the `sbom-scorer` command (see pyproject.toml
[project.scripts]) once the package is installed via `pip install .` or
`pip install -e .`. Also runnable directly during development via
`python main.py ...` (main.py is a thin shim around main() below).

Pipeline (ARCHITECTURE.md data flow): obtain an SBOM (from a file or by
fetching a GitHub repo's dependency-graph SBOM) -> parse -> discover each
component's CVEs (OSV) -> score all six dimensions -> apply the VEX gate ->
weighted composite + tier -> emit report (+ charts).

Centrality is scored from the SBOM's parsed dependency graph automatically.
Reachability additionally needs a codebase to analyze — pass --codebase to
score it; without that flag it falls back to the composite's missing-data
default (see sbom_scorer.composite) rather than being skipped as an error.
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
    parser.add_argument(
        "--codebase",
        default=None,
        help="Path to application source for Reachability analysis (AST import "
        "check + static call graph, DIMENSIONS.md #1). Without this, "
        "Reachability falls back to the composite's missing-data default.",
    )
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


def _progress(iterable, *, desc: str, total: int | None = None):
    """Wrap a slow, network-bound loop with a stderr progress bar.

    Used for the two per-component/per-finding loops that make one HTTP
    call per item (OSV CVE discovery, then Maintainer Health/Patch Latency/
    Reachability scoring) — the parts of a scan where a large SBOM can
    otherwise sit silently for minutes with no feedback that anything is
    happening. Renders on stderr (tqdm's default) so it never mixes into
    stdout report output (console format prints the report to stdout;
    json/csv write to a file) — same reasoning as _log. Degrades to a
    plain, silent iterator if tqdm isn't installed, so a scan never fails
    just because of a missing optional UX dependency.
    """
    try:
        from tqdm import tqdm
    except ImportError:
        return iterable
    return tqdm(iterable, desc=desc, total=total, unit="item", file=sys.stderr, leave=False)


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


def _batch_prefilter_candidates(components) -> list:
    """Narrow `components` down to the ones worth a full OSV detail query.

    Most real dependency trees are mostly clean — components with no known
    vulnerabilities at all — and _discover_cves' full query_by_package call
    (needed for CVE-alias resolution and later per-finding detail) is the
    slowest step in a scan. This runs one cheap OSV /v1/querybatch pass
    first (abbreviated results — just enough to know "has any hit or not",
    not full detail) and returns only the components that: already have
    embedded cve_ids (skip the batch check, _discover_cves handles them for
    free), are missing ecosystem/version (same — _discover_cves would
    short-circuit anyway, no point batch-checking), or came back with at
    least one hit in the batch pass.

    If the batch call itself fails, fails open: returns every component
    that would otherwise have been batch-checked, so a network hiccup here
    just loses the speed-up, not any findings.
    """
    from sbom_scorer.data_sources import osv_client

    free_candidates = [
        c for c in components if c.cve_ids or not c.ecosystem or not c.version
    ]
    queryable = [c for c in components if not c.cve_ids and c.ecosystem and c.version]
    if not queryable:
        return free_candidates

    queries = [
        {"package": {"name": c.name, "ecosystem": c.ecosystem}, "version": c.version}
        for c in queryable
    ]
    try:
        results = osv_client.query_batch(queries)
    except Exception as exc:  # noqa: BLE001
        _log(f"  ! OSV batch prefilter failed ({exc!r}); checking every component individually.")
        return free_candidates + queryable

    hits = [c for c, result in zip(queryable, results) if (result or {}).get("vulns")]
    _log(
        f"OSV batch prefilter: {len(hits)} of {len(queryable)} component(s) have a "
        f"potential match; resolving full detail for those."
    )
    return free_candidates + hits


def _safe_batch_exploitability(cve_ids, score_exploitabilities) -> dict:
    """Batch-score exploitability, degrading to per-CVE defaults on failure."""
    try:
        results = score_exploitabilities(cve_ids)
        return {cve: res.dimension_score for cve, res in results.items()}
    except Exception as exc:  # noqa: BLE001
        _log(f"  ! Exploitability batch failed ({exc!r}); using defaults.")
        return {cve: DimensionScore(5.0, "default") for cve in cve_ids}


def _safe_centrality_batch(component_ids, dependency_graph) -> dict:
    """Batch-score centrality, degrading to the isolated-node default on failure."""
    from sbom_scorer.dimensions import centrality

    if not component_ids:
        return {}
    try:
        return centrality.score_all_components(component_ids, dependency_graph)
    except Exception as exc:  # noqa: BLE001
        _log(f"  ! Centrality batch failed ({exc!r}); using defaults.")
        return {cid: DimensionScore(0.0, "default") for cid in component_ids}


def _gather_findings(components, dependency_graph=None, codebase_path=None) -> list[Finding]:
    """Build (un-composited) Findings for every affected component+CVE pair.

    Args:
        components: Parsed SBOM components (sbom_scorer.sbom_parser.Component).
        dependency_graph: The SBOM's dependency graph (sbom_scorer.sbom_parser
            .parse_sbom's second return value) — used to score Centrality
            (DIMENSIONS.md #4) via each component's bom_ref. If None/empty,
            Centrality falls back to the composite's missing-data default.
        codebase_path: Path to application source, for Reachability
            (DIMENSIONS.md #1). If None, Reachability falls back to the
            composite's missing-data default (5.0/indeterminate) instead of
            being scored, matching --codebase's "not yet used" default.
    """
    import networkx as nx

    from sbom_scorer.dimensions.exploitability import score_exploitabilities
    from sbom_scorer.dimensions.exposure import score_exposure
    from sbom_scorer.dimensions.maintainer_health import score_maintainer_health
    from sbom_scorer.dimensions.patch_latency import score_patch_latency
    from sbom_scorer.dimensions.reachability import score_reachability
    from sbom_scorer.vex import get_vex_status

    if dependency_graph is None:
        dependency_graph = nx.DiGraph()

    # 1. Discover CVEs per component. A cheap OSV batch pass first narrows
    # down to components that actually have something (most real
    # dependency trees are mostly clean), then only those go through the
    # full per-component detail call (_discover_cves) — usually the
    # slowest step for a large SBOM otherwise, so this also cuts down what
    # the progress bar has to sit through.
    candidates = _batch_prefilter_candidates(components)
    component_cves: list[tuple] = []
    all_cves: set[str] = set()
    for component in _progress(candidates, desc="Discovering CVEs", total=len(candidates)):
        cves = _discover_cves(component)
        if cves:
            component_cves.append((component, cves))
            all_cves.update(cves)

    _log(f"Discovered {len(all_cves)} unique CVE(s) across {len(component_cves)} affected component(s).")
    if not all_cves:
        return []

    # 2. One batched EPSS+KEV pass for all CVEs (Exploitability).
    exploit_results = _safe_batch_exploitability(sorted(all_cves), score_exploitabilities)

    # 3. Centrality only depends on graph structure — score every affected
    # component once, up front, reusing one betweenness-centrality pass
    # across the whole batch (see dimensions.centrality.score_all_components).
    affected_component_ids = [
        component.bom_ref for component, _cves in component_cves if component.bom_ref
    ]
    centrality_results = _safe_centrality_batch(affected_component_ids, dependency_graph)

    # 4. Maintainer Health is per-component — compute once and reuse.
    maint_cache: dict[int, DimensionScore] = {}

    findings: list[Finding] = []
    for component, cves in _progress(component_cves, desc="Scoring findings", total=len(component_cves)):
        if id(component) not in maint_cache:
            maint_cache[id(component)] = _safe_dimension(
                lambda c=component: score_maintainer_health(c), default=5.0
            )
        exposure = _safe_dimension(
            lambda c=component: score_exposure(c.exposure_tier), default=10.0
        )
        centrality_score = centrality_results.get(component.bom_ref) if component.bom_ref else None
        for cve_id in cves:
            finding = Finding(
                component_name=component.name,
                component_version=component.version,
                cve_id=cve_id,
            )
            finding.exploitability = exploit_results.get(cve_id) or DimensionScore(5.0, "default")
            finding.exposure = exposure
            finding.maintainer_health = maint_cache[id(component)]
            finding.centrality = centrality_score
            finding.patch_latency = _safe_dimension(
                lambda c=component, v=cve_id: score_patch_latency(c, v), default=0.0
            )
            if codebase_path:
                finding.reachability = _safe_dimension(
                    lambda c=component, v=cve_id: score_reachability(c, v, codebase_path),
                    default=5.0,
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
            components, dependency_graph = parse_sbom(sbom_path)
        except NotImplementedError as exc:
            _log(f"error: unsupported SBOM format: {exc}")
            return 1
        except Exception as exc:  # noqa: BLE001
            _log(f"error: failed to parse SBOM: {exc}")
            return 1

    _log(
        f"Parsed {len(components)} component(s), "
        f"{dependency_graph.number_of_edges()} dependency edge(s). Scoring ..."
    )

    weights = load_weights(args.weights)
    findings = _gather_findings(components, dependency_graph, args.codebase)
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
