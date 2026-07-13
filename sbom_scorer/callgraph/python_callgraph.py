"""Python call graph construction — JARVIS/PyCG wrapper.

Used by sbom_scorer.dimensions.reachability for function-level reachability
checks (DIMENSIONS.md #1, step 2). Builds a static call graph of the
application plus its dependencies, identifies entry points (route handlers,
main(), CLI arg parsers, webhook handlers, etc.), and supports BFS/DFS
queries from entry points to a target function.
"""

from __future__ import annotations

import networkx as nx


def build_call_graph(codebase_path: str) -> nx.DiGraph:
    """Build a static call graph for a Python codebase via JARVIS or PyCG.

    Args:
        codebase_path: Path to the Python application source tree.

    Returns:
        A NetworkX DiGraph where nodes are fully-qualified function names
        and edges represent "calls".

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError


def find_entry_points(codebase_path: str) -> list[str]:
    """Identify entry-point functions (route handlers, main(), CLI parsers, etc.)."""
    raise NotImplementedError


def is_reachable(call_graph: nx.DiGraph, entry_points: list[str], target_function: str) -> bool:
    """BFS/DFS from entry points to determine whether target_function is reachable."""
    raise NotImplementedError
