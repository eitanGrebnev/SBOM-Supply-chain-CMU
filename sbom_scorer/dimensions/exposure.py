"""Exposure Context dimension (weight 20% — DIMENSIONS.md #3).

Even if a vulnerable path is execution-reachable, who/what can reach the
running system to trigger it? Distinct from Reachability: this is about
external/attacker reachability, tagged at the service/deployment level via
SBOM custom properties (e.g. {"name": "exposure:tier", "value": ...}).

Score mapping (DIMENSIONS.md):
    dev_only          -> 0
    internal          -> 5
    internet_facing   -> 10
    unknown/missing   -> 10 (defaults to worst case per SSVC guidance)
"""

from __future__ import annotations

from enum import Enum

from sbom_scorer.composite import DimensionScore

DEFAULT_SCORE_UNKNOWN = 10.0  # worst-case default, per SCORING_MODEL.md


class ExposureTier(str, Enum):
    """Fixed exposure tier vocabulary, mirroring SSVC's System Exposure decision point."""

    DEV_ONLY = "dev_only"
    INTERNAL = "internal"
    INTERNET_FACING = "internet_facing"


# Score mapping per DIMENSIONS.md #3.
_SCORE_BY_TIER: dict[ExposureTier, float] = {
    ExposureTier.DEV_ONLY: 0.0,
    ExposureTier.INTERNAL: 5.0,
    ExposureTier.INTERNET_FACING: 10.0,
}


def score_exposure(exposure_tier: str | None) -> DimensionScore:
    """Score exposure context from a component/service's tagged exposure tier.

    Args:
        exposure_tier: The exposure tier string read from SBOM properties
            (see sbom_scorer.sbom_parser.Component.exposure_tier), or None
            if untagged.

    Returns:
        DimensionScore with score in [0, 10] and a confidence flag: "high"
        when the tier is a recognized value, "default" when it's missing or
        unrecognized — both fall back to DEFAULT_SCORE_UNKNOWN (worst case),
        per SSVC guidance that unknown exposure should never be assumed
        safe.
    """
    if not exposure_tier:
        return DimensionScore(score=DEFAULT_SCORE_UNKNOWN, confidence="default")

    # Defensive re-normalization: sbom_scorer.sbom_parser._extract_exposure_tier
    # already lowercases/hyphen-normalizes values it reads from a real SBOM,
    # but a Component built directly (e.g. in a test, or by a future caller
    # that doesn't go through the parser) might not have.
    normalized = exposure_tier.strip().lower().replace("-", "_")
    try:
        tier = ExposureTier(normalized)
    except ValueError:
        return DimensionScore(score=DEFAULT_SCORE_UNKNOWN, confidence="default")

    return DimensionScore(score=_SCORE_BY_TIER[tier], confidence="high")
