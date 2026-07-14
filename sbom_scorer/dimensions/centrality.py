"""Dependency Centrality / Blast Radius dimension (weight 15% — DIMENSIONS.md #4).

How many other components transitively depend on this one? Computed from
the dependency graph built by sbom_scorer.sbom_parser (NetworkX DiGraph),
combining two sub-methods:

    A. Reachable Dependents — ancestors() on the reversed graph, log-
       normalized against total component count:
       score = min(10, log2(count+1) / log2(total+1) * 10)
    B. Betweenness Centrality — networkx.betweenness_centrality on the
       original graph, scaled from its native 0-1 range to 0-10:
       score = betweenness_centrality * 10

Combining the two: not yet finalized (see DIMENSIONS.md #4) — average is
the current working default, max is a documented alternative worth testing
empirically before locking in.
"""

from __future__ import annotations

import networkx as nx

from sbom_scorer.composite import DimensionScore

DEFAULT_SCORE_ISOLATED = 0.0  # leaf/isolated node, per SCORING_MODEL.md


def score_centrality(component_id: str, dependency_graph: nx.DiGraph) -> DimensionScore:
    """Score blast radius for a component within the SBOM's dependency graph.

    Combines sub-method A (_reachable_dependents) and sub-method B
    (_betweenness_centrality) into a single 0-10 score via
    _combine_centrality_scores.

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


def _reachable_dependents(component_id: str, dependency_graph: nx.DiGraph) -> int:
    """Sub-method A: count transitive ancestors (dependents) via the reversed graph.

    Reverses dependency_graph and runs BFS/DFS (or nx.ancestors()) from
    component_id to count everything that transitively depends on it —
    everything that would be affected if this component were compromised.
    """
    raise NotImplementedError


def _reachable_dependents_score(dependent_count: int, total_components: int) -> float:
    """Log-normalize a raw dependent count into a 0-10 score.

    score = min(10, log2(count+1) / log2(total+1) * 10)
    """
    raise NotImplementedError


def _betweenness_centrality(component_id: str, dependency_graph: nx.DiGraph) -> float:
    """Sub-method B: betweenness centrality of component_id on the original graph.

    Measures how often the component lies on shortest dependency paths
    between other components — a structural-bridge signal distinct from
    raw dependent count. Uses networkx.betweenness_centrality(); returns
    the native 0-1 value (scaling to 0-10 is done by the caller).
    """
    raise NotImplementedError


def _combine_centrality_scores(reachable_dependents_score: float, betweenness_score: float) -> float:
    """Combine the two sub-method scores into one 0-10 centrality score.

    Current working default is a simple average of the two (already-scaled)
    0-10 sub-scores; taking the max is a documented alternative to evaluate
    empirically. See DIMENSIONS.md #4 "Combining the two sub-scores."
    """
    raise NotImplementedError
