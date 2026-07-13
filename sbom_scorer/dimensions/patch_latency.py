"""Patch Latency dimension (weight 10% — DIMENSIONS.md #5).

Two distinct sub-cases, not one formula (per ARCHITECTURE.md / DIMENSIONS.md):
    - Fix exists, not yet applied: latency = time since fix release.
    - No fix exists yet: latency = time since disclosure (different, and
      worsening, risk type — "unpatchable exposure").

Data: OSV.dev for disclosure date + fixed version identifier
(sbom_scorer.data_sources.osv_client), package registries for the fixed
version's actual release timestamp (sbom_scorer.data_sources.registry_client).
"""

from __future__ import annotations

from typing import Any

from sbom_scorer.composite import DimensionScore


def score_patch_latency(component: Any, cve_id: str) -> DimensionScore:
    """Score patch latency for a component's CVE.

    Args:
        component: The sbom_scorer.sbom_parser.Component under evaluation.
        cve_id: CVE identifier to look up via OSV.dev.

    Returns:
        DimensionScore with score in [0, 10] and a confidence flag.

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError


def _score_fix_exists(days_since_fix_release: int) -> float:
    """Score when a fix exists but may not yet be applied.

    0 days = 0, 60+ days unpatched = 10, linear/capped ramp in between.
    """
    raise NotImplementedError


def _score_no_fix_exists(days_since_disclosure: int) -> float:
    """Score when no fix exists yet — scales with time since disclosure."""
    raise NotImplementedError
