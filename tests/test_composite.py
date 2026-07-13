"""Tests for sbom_scorer.composite — weighted scoring + tier bucketing.

Stub scaffolding: fill in once compute_composite/bucket_tier are
implemented. Cases to cover per SCORING_MODEL.md once implemented:
    - VEX not_affected forces composite=0, tier=Informational.
    - Weighted sum matches the documented formula for known inputs.
    - Tier boundaries (19/20, 39/40, 59/60, 79/80) bucket correctly.
"""

import pytest

from sbom_scorer import composite


def test_bucket_tier_not_implemented():
    with pytest.raises(NotImplementedError):
        composite.bucket_tier(85.0)


def test_compute_composite_not_implemented():
    finding = composite.Finding(component_name="pkg", component_version="1.0.0", cve_id="CVE-0000-0000")
    with pytest.raises(NotImplementedError):
        composite.compute_composite(finding, weights={})
