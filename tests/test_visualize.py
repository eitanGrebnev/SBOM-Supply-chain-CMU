"""Tests for sbom_scorer.output.visualize — chart generation.

Covers the two chart functions cli.py's --charts flag actually calls
(tier_distribution_bar, finding_radar). Only checks that a non-empty image
file gets written — pixel-level content isn't asserted, matching the rest
of the project's approach to chart testing.
"""

import networkx as nx
import pytest

from sbom_scorer import composite
from sbom_scorer.composite import DimensionScore, Finding
from sbom_scorer.output import visualize

WEIGHTS = dict(composite.DEFAULT_WEIGHTS)


def _scored_finding(**scores) -> Finding:
    f = Finding(component_name="requests", component_version="2.19.0", cve_id="CVE-2023-0001")
    for dim, value in scores.items():
        setattr(f, dim, DimensionScore(score=value, confidence="high"))
    composite.score_finding(f, WEIGHTS)
    return f


@pytest.fixture
def findings():
    return [
        _scored_finding(exploitability=9, exposure=10, patch_latency=6, maintainer_health=4),
        _scored_finding(
            reachability=10, exploitability=10, exposure=10,
            centrality=10, patch_latency=10, maintainer_health=10,
        ),
    ]


def test_tier_distribution_bar_writes_file(tmp_path, findings):
    out_path = tmp_path / "tiers.png"
    visualize.tier_distribution_bar(findings, str(out_path))
    assert out_path.exists()
    assert out_path.stat().st_size > 0


def test_tier_distribution_bar_empty_findings(tmp_path):
    out_path = tmp_path / "tiers_empty.png"
    visualize.tier_distribution_bar([], str(out_path))
    assert out_path.exists()


def test_tier_distribution_bar_cvss_comparison_not_implemented(tmp_path, findings):
    with pytest.raises(NotImplementedError):
        visualize.tier_distribution_bar(findings, str(tmp_path / "x.png"), compare_cvss_only=True)


def test_finding_radar_writes_file(tmp_path, findings):
    out_path = tmp_path / "radar.png"
    visualize.finding_radar(findings[0], str(out_path))
    assert out_path.exists()
    assert out_path.stat().st_size > 0


def test_plot_dependency_graph_still_deferred():
    with pytest.raises(NotImplementedError):
        visualize.plot_dependency_graph(nx.DiGraph(), [], "x.png")


def test_plot_dimension_scatter_still_deferred():
    with pytest.raises(NotImplementedError):
        visualize.plot_dimension_scatter([], "reachability", "exposure", "x.png")


def test_plot_composite_histogram_still_deferred():
    with pytest.raises(NotImplementedError):
        visualize.plot_composite_histogram([], "x.png")
