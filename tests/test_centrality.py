"""Tests for sbom_scorer.dimensions.centrality — DIMENSIONS.md #4.

Covers the documented formulas:
    Sub-method A: min(10, log2(count+1) / log2(total+1) * 10)
    Sub-method B: betweenness_centrality * 10
    Combined: simple average of the two (current working default)
"""

import math

import networkx as nx

from sbom_scorer.dimensions import centrality


def _star_graph():
    """Four leaves all depending on one hub: A, B, C, D -> HUB."""
    g = nx.DiGraph()
    for leaf in ("A", "B", "C", "D"):
        g.add_edge(leaf, "HUB")
    return g


def _chain_graph():
    """A -> B -> C -> D (A depends on B depends on C depends on D)."""
    g = nx.DiGraph()
    g.add_edge("A", "B")
    g.add_edge("B", "C")
    g.add_edge("C", "D")
    return g


def test_reachable_dependents_counts_transitive_dependents():
    g = _chain_graph()
    # Everything that transitively depends on D: A, B, C.
    assert centrality._reachable_dependents("D", g) == 3
    # Nothing depends on A (it's the root of the chain).
    assert centrality._reachable_dependents("A", g) == 0


def test_reachable_dependents_score_matches_log2_formula():
    # 3 dependents out of 4 total components (matches _chain_graph's D).
    expected = min(10.0, (math.log2(4) / math.log2(5)) * 10.0)
    assert centrality._reachable_dependents_score(3, 4) == expected


def test_reachable_dependents_score_zero_total_is_zero():
    assert centrality._reachable_dependents_score(0, 0) == 0.0


def test_betweenness_zero_for_small_graphs():
    g = nx.DiGraph()
    g.add_edge("A", "B")
    # Fewer than 3 nodes -> no node can be a "between" node.
    assert centrality._betweenness_centrality("A", g) == 0.0


def test_betweenness_identifies_bridge_node():
    g = _chain_graph()
    # C sits on the A->B->C->D... actually the shortest paths between other
    # nodes: B is the bridge between A and C/D; C is the bridge between
    # A/B and D. Both should score higher than the endpoints A and D.
    b_score = centrality._betweenness_centrality("B", g)
    a_score = centrality._betweenness_centrality("A", g)
    d_score = centrality._betweenness_centrality("D", g)
    assert b_score > a_score
    assert b_score > d_score


def test_combine_is_simple_average():
    assert centrality._combine_centrality_scores(10.0, 0.0) == 5.0
    assert centrality._combine_centrality_scores(4.0, 6.0) == 5.0


def test_hub_scores_higher_than_leaf():
    g = _star_graph()
    hub = centrality.score_centrality("HUB", g)
    leaf = centrality.score_centrality("A", g)
    assert hub.score > leaf.score
    assert hub.confidence == "high"
    assert leaf.confidence == "high"


def test_missing_component_falls_back_to_isolated_default():
    g = _star_graph()
    result = centrality.score_centrality("does-not-exist", g)
    assert result.score == centrality.DEFAULT_SCORE_ISOLATED
    assert result.confidence == "default"


def test_empty_graph_falls_back_to_isolated_default():
    result = centrality.score_centrality("anything", nx.DiGraph())
    assert result.score == centrality.DEFAULT_SCORE_ISOLATED
    assert result.confidence == "default"


def test_score_bounded_zero_to_ten():
    g = _star_graph()
    for node in g.nodes:
        result = centrality.score_centrality(node, g)
        assert 0.0 <= result.score <= 10.0


def test_score_all_components_matches_individual_scoring():
    g = _chain_graph()
    batch = centrality.score_all_components(["A", "B", "C", "D"], g)
    for node in ("A", "B", "C", "D"):
        individual = centrality.score_centrality(
            node, g, precomputed_betweenness=nx.betweenness_centrality(g, normalized=True)
        )
        assert batch[node].score == individual.score
        assert batch[node].confidence == individual.confidence


def test_score_all_components_empty_input():
    assert centrality.score_all_components([], _star_graph()) == {}
