"""Dependency Centrality / Blast Radius dimension (weight 15% — DIMENSIONS.md #4).

How many other components transitively depend on this one? Computed from
the dependency graph built by sbom_scorer.sbom_parser (NetworkX DiGraph),
via ancestors() on the reverse graph.

Score mapping (DIMENSIONS.md): log-normalized against total component
count, e.g. score = min(10, log2(count+1) / log2(total+1) * 10).
"""

from __future__ import annotations

import networkx as nx

from sbom_scorer.composite import DimensionScore

DEFAULT_SCORE_ISOLATED = 0.0  # leaf/isolated node, per SCORING_MODEL.md


def score_centrality(component_id: str, dependency_graph: nx.DiGraph) -> DimensionScore:
    """Score blast radius for a component within the SBOM's dependency graph.

    Args:
        component_id: Node identifier for the component within
            dependency_graph.
        dependency_graph: The full SBOM dependency graph, as produced by
            sbom_scorer.sbom_parser.parse_sbom.

    Returns:
        DimensionScore with score in [0, 10] and a confidence flag.

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError


def _blast_radius(component_id: str, dependency_graph: nx.DiGraph) -> int:
    """Count transitive ancestors (dependents) of a component via the reversed graph."""
    raise NotImplementedError
