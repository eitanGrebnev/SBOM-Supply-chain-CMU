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
import json
import os
import sys
import tempfile
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor

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
    _PROGRESS.log(msg)


#: How many recent status lines the progress file keeps. Enough to show the
#: user what is happening without letting a scan that logs one warning per
#: component grow the file without bound.
_PROGRESS_LOG_LINES = 50

#: Minimum seconds between progress-file writes. Every item of a large scan
#: calling advance() would otherwise mean one small write per item onto a
#: network filesystem, which is exactly the small-random-IO pattern the
#: scans volume is worst at. Phase changes bypass this and flush immediately,
#: so the UI never sits on a stale phase name.
_PROGRESS_MIN_WRITE_INTERVAL = 0.5


class _ProgressReporter:
    """Mirror scan progress into a JSON file for an out-of-process reader.

    A scan runs inside its own Kubernetes Job pod while the API process the
    browser polls lives somewhere else entirely; the only thing the two share
    is the scans volume. Writing progress there is what makes a live progress
    bar possible at all.

    Container logs deliberately are NOT the mechanism: kubelet garbage
    collects a completed pod's logs, so anyone reloading the page after a
    scan finished would get "unable to retrieve container logs" instead of
    the run they just watched. A file on the volume outlives the pod.

    Disabled unless SBOM_SCORER_PROGRESS_FILE is set, so a normal local CLI
    run costs nothing and never leaves a stray file behind.
    """

    def __init__(self) -> None:
        self._path = os.environ.get("SBOM_SCORER_PROGRESS_FILE") or None
        # advance() is driven from the main thread, but _log() is reachable
        # from the scoring pools via _safe_dimension, so state is guarded.
        self._lock = threading.Lock()
        self._phase = "Starting"
        self._completed = 0
        self._total: int | None = None
        self._lines: deque[str] = deque(maxlen=_PROGRESS_LOG_LINES)
        self._last_write = 0.0

    @property
    def enabled(self) -> bool:
        return self._path is not None

    def log(self, msg: str) -> None:
        """Record a status line and flush, so messages appear promptly."""
        if not self._path:
            return
        with self._lock:
            self._lines.append(msg)
            self._write_locked(force=True)

    def start_phase(self, desc: str, total: int | None) -> None:
        """Begin a named phase, resetting the item counter."""
        if not self._path:
            return
        with self._lock:
            self._phase = desc
            self._completed = 0
            self._total = total
            self._write_locked(force=True)

    def advance(self) -> None:
        """Count one completed item in the current phase."""
        if not self._path:
            return
        with self._lock:
            self._completed += 1
            # The final item forces a write so the bar always lands on 100%
            # rather than freezing just short of it.
            self._write_locked(force=self._completed == self._total)

    def _write_locked(self, *, force: bool) -> None:
        """Serialize current state. Caller must hold the lock."""
        now = time.monotonic()
        if not force and now - self._last_write < _PROGRESS_MIN_WRITE_INTERVAL:
            return
        self._last_write = now
        payload = {
            "phase": self._phase,
            "completed": self._completed,
            "total": self._total,
            "lines": list(self._lines),
        }
        # Written to a temporary file and renamed so a reader polling this
        # path never observes a half-written document. os.replace is atomic
        # within a directory, which is why the temp file is a sibling rather
        # than somewhere under /tmp.
        tmp = f"{self._path}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
            os.replace(tmp, self._path)
        except OSError:
            # Progress reporting is cosmetic; a full or unwritable volume
            # must never be the reason a scan fails.
            pass


_PROGRESS = _ProgressReporter()


#: Threads used for the network-bound scoring passes. A scan spends nearly all
#: of its wall-clock time blocked on OSV/GitHub/Scorecard HTTP calls rather
#: than on CPU, so these are I/O-bound threads: the GIL is released for the
#: duration of each request and they genuinely overlap. Kept well below the
#: point where we would look like abuse to the upstream APIs.
_DEFAULT_MAX_WORKERS = 12


def _max_workers() -> int:
    """Resolve the scoring thread count, overridable per deployment."""
    raw = os.environ.get("SBOM_SCORER_MAX_WORKERS")
    if not raw:
        return _DEFAULT_MAX_WORKERS
    try:
        # Clamped rather than trusted: too many threads turns a slow scan into
        # upstream rate-limiting, which is slower still.
        return max(1, min(int(raw), 32))
    except ValueError:
        _log(f"  ! ignoring non-numeric SBOM_SCORER_MAX_WORKERS={raw!r}")
        return _DEFAULT_MAX_WORKERS


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

    The same counts also feed _ProgressReporter when a scan is running
    under the API, which is what drives the web UI's progress bar.
    """
    _PROGRESS.start_phase(desc, total)
    try:
        from tqdm import tqdm
    except ImportError:
        wrapped = iterable
    else:
        wrapped = tqdm(iterable, desc=desc, total=total, unit="item", file=sys.stderr, leave=False)
    if not _PROGRESS.enabled:
        return wrapped
    return _counted(wrapped)


def _counted(iterable):
    """Yield from iterable, reporting each item to the progress file.

    Counts on arrival rather than after the consumer handles the item: for
    the pool.map() passes the expensive network call is already done by the
    time an item is yielded, so this is the point that reflects real work.
    """
    for item in iterable:
        _PROGRESS.advance()
        yield item


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
    from sbom_scorer.sbom_parser import OSV_ECOSYSTEMS

    def _batchable(c) -> bool:
        # An ecosystem OSV doesn't recognise makes it reject the *whole*
        # batch, so those components skip the prefilter entirely and go
        # straight to per-component queries.
        return bool(
            not c.cve_ids and c.ecosystem and c.version and c.ecosystem in OSV_ECOSYSTEMS
        )

    free_candidates = [c for c in components if not _batchable(c)]
    queryable = [c for c in components if _batchable(c)]
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
    workers = _max_workers()
    component_cves: list[tuple] = []
    all_cves: set[str] = set()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        # Executor.map yields in *input* order, not completion order, so
        # findings stay deterministic regardless of which lookup returns
        # first — important for reproducible reports and stable tests.
        discovered = pool.map(_discover_cves, candidates)
        for component, cves in zip(
            candidates,
            _progress(discovered, desc="Discovering CVEs", total=len(candidates)),
        ):
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

    # 4. Maintainer Health and Exposure are per-component, so they are scored
    # once per component rather than once per finding — a component with ten
    # CVEs would otherwise repeat the same Scorecard lookup ten times.
    def _component_scores(component):
        return (
            _safe_dimension(lambda c=component: score_maintainer_health(c), default=5.0),
            _safe_dimension(lambda c=component: score_exposure(c.exposure_tier), default=10.0),
        )

    with ThreadPoolExecutor(max_workers=workers) as pool:
        per_component = list(pool.map(_component_scores, [c for c, _cves in component_cves]))

    # 5. Patch Latency and Reachability are per (component, CVE), so flatten
    # to that granularity before scoring. Doing it here rather than in a
    # nested loop means one component with many CVEs cannot become a
    # straggler holding up the whole pass.
    pairs = [
        (index, component, cve_id)
        for index, (component, cves) in enumerate(component_cves)
        for cve_id in cves
    ]

    def _build_finding(item) -> Finding:
        index, component, cve_id = item
        maintainer_health, exposure = per_component[index]

        finding = Finding(
            component_name=component.name,
            component_version=component.version,
            cve_id=cve_id,
        )
        finding.exploitability = exploit_results.get(cve_id) or DimensionScore(5.0, "default")
        finding.exposure = exposure
        finding.maintainer_health = maintainer_health
        finding.centrality = (
            centrality_results.get(component.bom_ref) if component.bom_ref else None
        )
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
        return finding

    with ThreadPoolExecutor(max_workers=workers) as pool:
        findings: list[Finding] = list(
            _progress(
                pool.map(_build_finding, pairs), desc="Scoring findings", total=len(pairs)
            )
        )

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
