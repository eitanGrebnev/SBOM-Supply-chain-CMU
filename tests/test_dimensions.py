"""Historical placeholder for the dimension-scoring modules.

All six dimensions are now implemented, each with its own dedicated test
module instead of a stub assertion here: exploitability ->
test_exploitability.py, maintainer_health -> test_maintainer_health.py,
exposure -> test_exposure.py, reachability -> test_reachability.py,
centrality -> test_centrality.py, patch_latency -> test_patch_latency.py.

The two stub assertions that used to live here
(`reachability.score_reachability(component=None, ...)` and
`centrality.score_centrality(component_id="pkg", dependency_graph=nx.DiGraph())`
both raising NotImplementedError) were removed once those functions were
actually implemented — score_reachability(component=None, ...) now raises
AttributeError instead (see test_reachability.py for real coverage of the
implemented behavior), and score_centrality on an empty graph now returns
DimensionScore(0.0, "default") rather than raising (see test_centrality.py).
This file is kept as a pointer for anyone still expecting stub tests here.
"""
