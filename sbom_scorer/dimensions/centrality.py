"""Dependency Centrality / Blast Radius dimension (weight 15% — DIMENSIONS.md #4).

How many other components transitively depend on this one? Computed from
the dependency graph built by sbom_scorer.sbom_parser (NetworkX DiGraph),
combining two sub-methods:

    A. Reachable Dependents — nx.ancestors() on the dependency graph (edges
       are "A depends on B", so ancestors of B are exactly the things that
       transitively depend on B), log-normalized against total component
       count:
       score = min(10, log2(count+1) / log2(total+1) * 10)
    B. Betweenness Centrality — networkx.betweenness_centrality on the
       original graph, scaled from its native 0-1 range to 0-10:
       score = betweenness_centrality * 10

Combining the two: not yet finalized (see DIMENSIONS.md #4) — average is
the current working default, max is a documented alternative worth testing
empirically before locking in.

Note: an independent, unwired implementation of this same idea also exists
at the repo root (sbom_scorer/centrality.py) using a *linear* (not log2)
normalization for sub-method A. That module predates this one being filled
in, was never imported anywhere, and doesn't match the documented formula
above — this module (sbom_scorer.dimensions.centrality) is the one
ARCHITECTURE.md/cli.py actually wire up.
"""

from __future__ import annotations

import math

import networkx as nx

from sbom_scorer.composite import DimensionScore

DEFAULT_SCORE_ISOLATED = 0.0  # leaf/isolated node, per SCORING_MODEL.md


def score_centrality(
    component_id: str,
    dependency_graph: nx.DiGraph,
    *,
    precomputed_betweenness: dict[str, float] | None = None,
) -> DimensionScore:
    """Score blast radius for a component within the SBOM's dependency graph.

    Combines sub-method A (_reachable_dependents) and sub-method B
    (_betweenness_centrality) into a single 0-10 score via
    _combine_centrality_scores.

    Args:
        component_id: Node identifier for the component within
            dependency_graph (see sbom_scorer.sbom_parser.Component.bom_ref).
        dependency_graph: The full SBOM dependency graph, as produced by
            sbom_scorer.sbom_parser.parse_sbom.
        precomputed_betweenness: Optional pre-computed
            networkx.betweenness_centrality(dependency_graph) result, to
            avoid recomputing it (O(V*E)) for every component in a batch —
            see score_all_components.

    Returns:
        DimensionScore with score in [0, 10] and a confidence flag. Falls
        back to (DEFAULT_SCORE_ISOLATED, "default") when the graph has no
        nodes or doesn't contain component_id at all (no dependency data
        to score against — distinct from a genuinely isolated/leaf node
        that *is* present in a populated graph, which is scored normally
        and gets "high" confidence).
    """
    if dependency_graph.number_of_nodes() == 0 or component_id not in dependency_graph:
        return DimensionScore(score=DEFAULT_SCORE_ISOLATED, confidence="default")

    total_components = dependency_graph.number_of_nodes()
    dependent_count = _reachable_dependents(component_id, dependency_graph)
    dependents_score = _reachable_dependents_score(dependent_count, total_components)

    if precomputed_betweenness is not None:
        betweenness = float(precomputed_betweenness.get(component_id, 0.0))
    else:
        betweenness = _betweenness_centrality(component_id, dependency_graph)
    betweenness_score = min(10.0, max(0.0, betweenness * 10.0))

    combined = _combine_centrality_scores(dependents_score, betweenness_score)
    score = round(min(10.0, max(0.0, combined)), 2)

    # No edges anywhere in the graph means there's no real dependency
    # structure to measure from (e.g. sbom_parser couldn't build any) —
    # that's a data-availability gap, not a genuinely isolated component.
    confidence = "high" if dependency_graph.number_of_edges() > 0 else "default"
    return DimensionScore(score=score, confidence=confidence)


def _reachable_dependents(component_id: str, dependency_graph: nx.DiGraph) -> int:
    """Sub-method A: count transitive ancestors (dependents) via the reversed graph.

    Edges are stored as "depender -> dependency" (A -> B means A depends on
    B), so everything that transitively depends on component_id is exactly
    its set of ancestors in the graph as-is — nodes with a directed path
    ending at component_id. nx.ancestors() is equivalent to reversing the
    graph and taking descendants(), just without building the reversed copy.
    """
    if component_id not in dependency_graph:
        return 0
    return len(nx.ancestors(dependency_graph, component_id))


def _reachable_dependents_score(dependent_count: int, total_components: int) -> float:
    """Log-normalize a raw dependent count into a 0-10 score.

    score = min(10, log2(count+1) / log2(total+1) * 10)
    """
    if total_components <= 0:
        return 0.0
    denominator = math.log2(total_components + 1)
    if denominator <= 0:
        return 0.0
    return min(10.0, (math.log2(dependent_count + 1) / denominator) * 10.0)


def _betweenness_centrality(component_id: str, dependency_graph: nx.DiGraph) -> float:
    """Sub-method B: betweenness centrality of component_id on the original graph.

    Measures how often the component lies on shortest dependency paths
    between other components — a structural-bridge signal distinct from
    raw dependent count. Uses networkx.betweenness_centrality(); returns
    the native 0-1 value (scaling to 0-10 is done by the caller).
    """
    if component_id not in dependency_graph or dependency_graph.number_of_nodes() < 3:
        # betweenness is 0 by definition for graphs too small to have an
        # intermediate node on any shortest path.
        return 0.0
    scores = nx.betweenness_centrality(dependency_graph, normalized=True)
    return float(scores.get(component_id, 0.0))


def _combine_centrality_scores(reachable_dependents_score: float, betweenness_score: float) -> float:
    """Combine the two sub-method scores into one 0-10 centrality score.

    Current working default is a simple average of the two (already-scaled)
    0-10 sub-scores; taking the max is a documented alternative to evaluate
    empirically. See DIMENSIONS.md #4 "Combining the two sub-scores."
    """
    return (reachable_dependents_score + betweenness_score) / 2.0


def score_all_components(
    component_ids: list[str],
    dependency_graph: nx.DiGraph,
) -> dict[str, DimensionScore]:
    """Score centrality for a batch of components, computing betweenness once.

    networkx.betweenness_centrality is O(V*E) and independent of any single
    target node, so it's wasteful to let score_centrality recompute it once
    per component when scoring a whole SBOM — this precomputes it a single
    time and reuses it across the batch (see cli.py's _gather_findings).
    """
    if dependency_graph.number_of_nodes() >= 3:
        betweenness = nx.betweenness_centrality(dependency_graph, normalized=True)
    else:
        betweenness = {}
    return {
        cid: score_centrality(cid, dependency_graph, precomputed_betweenness=betweenness)
        for cid in component_ids
    }
