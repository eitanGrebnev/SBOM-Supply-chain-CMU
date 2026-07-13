"""Reachability dimension (weight 25% — DIMENSIONS.md #1).

Does execution ever reach the vulnerable function in this dependency?
Combines a baseline import check with a call-graph-based function-level
check (via sbom_scorer.callgraph).

Score mapping (DIMENSIONS.md):
    not imported            -> 0
    imported, unreachable   -> 1-2
    indeterminate           -> 5   (default when call graph unavailable)
    confirmed reachable     -> 10

Known limitation (state explicitly per DIMENSIONS.md): static call graphs
can overestimate reachability (infeasible paths) or underestimate it
(dynamic dispatch, reflection, eval, monkey patching).
"""

from __future__ import annotations

from typing import Any

from sbom_scorer.composite import DimensionScore

DEFAULT_SCORE = 5.0  # indeterminate, per SCORING_MODEL.md missing-data defaults


def score_reachability(component: Any, cve_id: str, codebase_path: str) -> DimensionScore:
    """Score reachability for a component's CVE against a given codebase.

    Args:
        component: The sbom_scorer.sbom_parser.Component under evaluation.
        cve_id: CVE identifier (used to look up the fix commit / vulnerable
            function via _identify_vulnerable_function).
        codebase_path: Path to the application source tree to check imports
            and build/consult a call graph against.

    Returns:
        DimensionScore with score in [0, 10] and a confidence flag.

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError


def _is_package_imported(component: Any, codebase_path: str) -> bool:
    """Baseline check: AST-parse imports to confirm the package is actually used."""
    raise NotImplementedError


def _identify_vulnerable_function(cve_id: str) -> list[str]:
    """Extract vulnerable function name(s) from the CVE's fix commit diff.

    Pulls the fix commit referenced in the OSV/GHSA advisory
    (references[].type == "FIX") and diffs it to find changed function names.
    """
    raise NotImplementedError


def _is_function_reachable(codebase_path: str, function_names: list[str]) -> bool | None:
    """BFS/DFS from entry points through the call graph to check reachability.

    Returns:
        True/False if determinable, None if indeterminate (no call graph
        buildable or function unknown).
    """
    raise NotImplementedError
