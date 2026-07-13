"""Placeholder tests for the six dimension-scoring modules.

Each score_* function should, once implemented, be tested against the
score-mapping tables in DIMENSIONS.md. For now this just asserts the
stubs raise NotImplementedError so the test suite has a non-empty
baseline to build on.
"""

import pytest

from sbom_scorer.dimensions import (
    centrality,
    exploitability,
    exposure,
    maintainer_health,
    patch_latency,
    reachability,
)


def test_reachability_stub():
    with pytest.raises(NotImplementedError):
        reachability.score_reachability(component=None, cve_id="CVE-0000-0000", codebase_path=".")


def test_exploitability_stub():
    with pytest.raises(NotImplementedError):
        exploitability.score_exploitability(cve_id="CVE-0000-0000")


def test_exposure_stub():
    with pytest.raises(NotImplementedError):
        exposure.score_exposure(exposure_tier=None)


def test_centrality_stub():
    import networkx as nx

    with pytest.raises(NotImplementedError):
        centrality.score_centrality(component_id="pkg", dependency_graph=nx.DiGraph())


def test_patch_latency_stub():
    with pytest.raises(NotImplementedError):
        patch_latency.score_patch_latency(component=None, cve_id="CVE-0000-0000")


def test_maintainer_health_stub():
    with pytest.raises(NotImplementedError):
        maintainer_health.score_maintainer_health(owner="octocat", repo="hello-world")
