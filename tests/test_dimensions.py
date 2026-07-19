"""Placeholder tests for the still-scaffolded dimension-scoring modules.

Each score_* function should, once implemented, be tested against the
score-mapping tables in DIMENSIONS.md. For now this just asserts the
stubs raise NotImplementedError so the test suite has a non-empty
baseline to build on. Implemented dimensions get their own test module
(exploitability -> test_exploitability.py, maintainer_health ->
test_maintainer_health.py, exposure -> test_exposure.py) instead of a
stub assertion here.
"""

import pytest

from sbom_scorer.dimensions import centrality, reachability


def test_reachability_stub():
    with pytest.raises(NotImplementedError):
        reachability.score_reachability(component=None, cve_id="CVE-0000-0000", codebase_path=".")


def test_centrality_stub():
    import networkx as nx

    with pytest.raises(NotImplementedError):
        centrality.score_centrality(component_id="pkg", dependency_graph=nx.DiGraph())



# Note: patch_latency.score_patch_latency is no longer a stub (implemented
# by Tanisha — see git log) but has no dedicated test module yet, unlike
# exploitability/maintainer_health. The stub assertion that used to live
# here (`score_patch_latency(component=None, ...)` raising
# NotImplementedError) is stale and was removed: the real implementation
# raises AttributeError on `None.name` instead, so the old assertion would
# fail, not pass. Leaving this as a flagged gap rather than silently
# deleting the coverage — whoever owns patch_latency should add a real
# test_patch_latency.py.
