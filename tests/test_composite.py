"""Tests for sbom_scorer.composite — weighted scoring + tier bucketing.

Covers SCORING_MODEL.md:
    - VEX not_affected forces composite=0, tier=Informational.
    - Weighted sum matches the documented formula for known inputs.
    - Tier boundaries (19/20, 39/40, 59/60, 79/80) bucket correctly.
    - Missing dimensions fall back to documented missing-data defaults.
"""

import pytest

from sbom_scorer import composite
from sbom_scorer.composite import DimensionScore, Finding

WEIGHTS = dict(composite.DEFAULT_WEIGHTS)


def _finding(**scores) -> Finding:
    f = Finding(component_name="pkg", component_version="1.0.0", cve_id="CVE-0000-0000")
    for dim, value in scores.items():
        setattr(f, dim, DimensionScore(score=value, confidence="high"))
    return f


@pytest.mark.parametrize(
    "score,tier",
    [
        (0.0, "Informational"),
        (19.0, "Informational"),
        (20.0, "Low"),
        (39.9, "Low"),
        (40.0, "Medium"),
        (59.9, "Medium"),
        (60.0, "High"),
        (79.9, "High"),
        (80.0, "Critical"),
        (100.0, "Critical"),
    ],
)
def test_bucket_tier_boundaries(score, tier):
    assert composite.bucket_tier(score) == tier


def test_compute_composite_all_tens_is_100():
    f = _finding(
        reachability=10,
        exploitability=10,
        exposure=10,
        centrality=10,
        patch_latency=10,
        maintainer_health=10,
    )
    assert composite.compute_composite(f, WEIGHTS) == pytest.approx(100.0)


def test_compute_composite_weighted_sum():
    # exploitability=10 (0.20), exposure=5 (0.20); the rest fall back to
    # missing-data defaults: reachability=5 (0.25), centrality=0 (0.15),
    # patch_latency=0 (0.10), maintainer_health=5 (0.10).
    # weighted 0-10 avg = 10*.2 + 5*.2 + 5*.25 + 0 + 0 + 5*.1 = 4.75 -> *10 = 47.5
    f = _finding(exploitability=10, exposure=5)
    assert composite.compute_composite(f, WEIGHTS) == pytest.approx(47.5)


def test_vex_not_affected_forces_zero():
    f = _finding(
        reachability=10, exploitability=10, exposure=10,
        centrality=10, patch_latency=10, maintainer_health=10,
    )
    f.vex_status = "not_affected"
    assert composite.compute_composite(f, WEIGHTS) == 0.0
    composite.score_finding(f, WEIGHTS)
    assert f.tier == "Informational"


def test_score_finding_populates_snapshot():
    f = _finding(exploitability=10, exposure=10)
    composite.score_finding(f, WEIGHTS)
    assert f.composite_score is not None
    assert f.tier is not None
    # Missing dimensions recorded at their defaults.
    assert f.dimension_scores["reachability"] == 5.0
    assert f.dimension_scores["centrality"] == 0.0
    assert f.dimension_scores["exploitability"] == 10.0


def test_load_weights_missing_file_falls_back():
    weights = composite.load_weights("does-not-exist.yaml")
    assert weights == composite.DEFAULT_WEIGHTS
