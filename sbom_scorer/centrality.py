"""
Dependency centrality / blast-radius scoring.

Graph convention
----------------
An edge ``A -> B`` means component A depends on component B.

Under this convention:
- The original graph represents dependency relationships.
- The reversed graph represents dependent relationships.
- Traversing from component B in the reversed graph finds every component
  that directly or transitively depends on B.

This module is independent and stateless. It accepts an already-built
NetworkX directed graph and returns scores from 0.0 to 10.0.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Hashable, Literal

import networkx as nx


Confidence = Literal["high", "medium", "low", "indeterminate"]


@dataclass(frozen=True)
class CentralityResult:
    """Centrality and blast-radius measurements for one component."""

    component: Hashable
    score: float
    confidence: Confidence

    reachable_dependents_count: int
    reachable_dependents_ratio: float
    reachable_dependents_score: float

    betweenness_centrality: float
    betweenness_score: float

    total_components: int
    reachable_weight: float
    betweenness_weight: float

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the result."""
        return asdict(self)


def _clamp_score(value: float) -> float:
    """Clamp and round a score to the documented 0-10 range."""
    return round(max(0.0, min(10.0, float(value))), 2)


def _validate_graph(graph: nx.DiGraph) -> None:
    """Validate that the input is a directed NetworkX graph."""
    if not isinstance(graph, nx.DiGraph):
        raise TypeError("graph must be a networkx.DiGraph")


def _validate_weights(
    reachable_weight: float,
    betweenness_weight: float,
) -> tuple[float, float]:
    """
    Validate and normalize the two sub-score weights.

    The caller may provide values such as 0.5/0.5 or 60/40. They are
    normalized internally so that they sum to 1.0.
    """
    if reachable_weight < 0 or betweenness_weight < 0:
        raise ValueError("centrality weights cannot be negative")

    total = reachable_weight + betweenness_weight
    if total <= 0:
        raise ValueError("at least one centrality weight must be greater than zero")

    return reachable_weight / total, betweenness_weight / total


def count_reachable_dependents(
    graph: nx.DiGraph,
    component: Hashable,
) -> set[Hashable]:
    """
    Return all unique direct and transitive dependents of a component.

    Because edges are stored as ``dependent -> dependency``, the graph is
    reversed before traversal. NetworkX descendants performs a graph search
    and returns each reachable node once.
    """
    _validate_graph(graph)

    if component not in graph:
        raise KeyError(f"component not found in dependency graph: {component!r}")

    reversed_graph = graph.reverse(copy=False)
    return set(nx.descendants(reversed_graph, component))


def score_reachable_dependents(
    graph: nx.DiGraph,
    component: Hashable,
) -> tuple[int, float, float]:
    """
    Calculate the normalized reachable-dependents blast-radius score.

    Formula:
        ratio = reachable_dependents / (N - 1)
        score = ratio * 10

    Returns:
        (dependent_count, normalized_ratio, score_0_to_10)
    """
    _validate_graph(graph)

    total_components = graph.number_of_nodes()
    dependents = count_reachable_dependents(graph, component)
    dependent_count = len(dependents)

    if total_components <= 1:
        return dependent_count, 0.0, 0.0

    ratio = dependent_count / (total_components - 1)
    score = _clamp_score(ratio * 10.0)
    return dependent_count, round(ratio, 6), score


def calculate_betweenness_scores(
    graph: nx.DiGraph,
) -> dict[Hashable, float]:
    """
    Calculate normalized betweenness centrality for every graph node.

    NetworkX returns normalized values from 0.0 to 1.0 when
    ``normalized=True``. The calculation is performed on the original
    directed dependency graph, as required by the scoring design.
    """
    _validate_graph(graph)

    if graph.number_of_nodes() == 0:
        return {}

    return nx.betweenness_centrality(
        graph,
        normalized=True,
        weight=None,
        endpoints=False,
    )


def determine_confidence(graph: nx.DiGraph) -> Confidence:
    """
    Estimate confidence from the amount of usable graph information.

    - indeterminate: no nodes
    - low: nodes exist but no dependency edges were parsed
    - medium: some nodes are isolated
    - high: graph has edges and every node participates in at least one edge
    """
    node_count = graph.number_of_nodes()
    edge_count = graph.number_of_edges()

    if node_count == 0:
        return "indeterminate"

    if edge_count == 0:
        return "low"

    isolated_nodes = list(nx.isolates(graph))
    if isolated_nodes:
        return "medium"

    return "high"


def score_centrality(
    graph: nx.DiGraph,
    component: Hashable,
    *,
    reachable_weight: float = 0.5,
    betweenness_weight: float = 0.5,
    precomputed_betweenness: dict[Hashable, float] | None = None,
) -> CentralityResult:
    """
    Score one component's dependency centrality and blast radius.

    The default combined score is an equal-weight average:

        centrality_score =
            reachable_dependents_score * 0.5
            + betweenness_score * 0.5

    Weights are configurable so sensitivity testing can be performed without
    changing the scoring implementation.

    For batch scoring, calculate betweenness once with
    ``calculate_betweenness_scores`` and pass the returned dictionary through
    ``precomputed_betweenness`` for every component.
    """
    _validate_graph(graph)

    if component not in graph:
        raise KeyError(f"component not found in dependency graph: {component!r}")

    normalized_reachable_weight, normalized_betweenness_weight = (
        _validate_weights(reachable_weight, betweenness_weight)
    )

    dependent_count, dependent_ratio, dependent_score = (
        score_reachable_dependents(graph, component)
    )

    if precomputed_betweenness is None:
        precomputed_betweenness = calculate_betweenness_scores(graph)

    betweenness_value = float(precomputed_betweenness.get(component, 0.0))
    betweenness_score = _clamp_score(betweenness_value * 10.0)

    combined_score = _clamp_score(
        dependent_score * normalized_reachable_weight
        + betweenness_score * normalized_betweenness_weight
    )

    return CentralityResult(
        component=component,
        score=combined_score,
        confidence=determine_confidence(graph),
        reachable_dependents_count=dependent_count,
        reachable_dependents_ratio=dependent_ratio,
        reachable_dependents_score=dependent_score,
        betweenness_centrality=round(betweenness_value, 6),
        betweenness_score=betweenness_score,
        total_components=graph.number_of_nodes(),
        reachable_weight=round(normalized_reachable_weight, 6),
        betweenness_weight=round(normalized_betweenness_weight, 6),
    )


def score_all_components(
    graph: nx.DiGraph,
    *,
    reachable_weight: float = 0.5,
    betweenness_weight: float = 0.5,
) -> dict[Hashable, CentralityResult]:
    """
    Score every component efficiently.

    Betweenness centrality is calculated once and reused for all components.
    """
    _validate_graph(graph)

    betweenness = calculate_betweenness_scores(graph)

    return {
        component: score_centrality(
            graph,
            component,
            reachable_weight=reachable_weight,
            betweenness_weight=betweenness_weight,
            precomputed_betweenness=betweenness,
        )
        for component in graph.nodes
    }


# Backward-friendly alias for callers that expect a generic dimension function.
score = score_centrality
