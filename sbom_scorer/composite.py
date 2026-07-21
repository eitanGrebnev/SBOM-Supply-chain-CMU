"""Weighted composite scoring and tier bucketing.

Per ARCHITECTURE.md design principle #4: this is the ONLY place weights
live. Individual dimension modules never hardcode weights — they're passed
in here, loaded from weights.yaml (see SCORING_MODEL.md for documented
default values), so they can be adjusted for the H2 sensitivity analysis
(HYPOTHESIS.md) without touching code.

Formula (SCORING_MODEL.md):
    if vex_status == "not_affected":
        composite = 0, tier = "Informational"
    else:
        composite = (
            reachability * w_reachability +
            exploitability * w_exploitability +
            exposure * w_exposure +
            centrality * w_centrality +
            patch_latency * w_patch_latency +
            maintainer_health * w_maintainer_health
        ) * 10
        tier = bucket(composite)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sbom_scorer.vex import apply_vex_gate

# The six dimensions, in the documented weighting order (SCORING_MODEL.md).
_DIMENSION_ORDER = (
    "reachability",
    "exploitability",
    "exposure",
    "centrality",
    "patch_latency",
    "maintainer_health",
)

# Fallback weights, used only when weights.yaml is missing/incomplete.
# Mirrors weights.yaml, which is the authoritative source (SCORING_MODEL.md).
DEFAULT_WEIGHTS: dict[str, float] = {
    "reachability": 0.25,
    "exploitability": 0.20,
    "exposure": 0.20,
    "centrality": 0.15,
    "patch_latency": 0.10,
    "maintainer_health": 0.10,
}

# Substituted for any dimension whose score is absent on a Finding (e.g.
# Reachability/Centrality before they're wired). Mirrors weights.yaml's
# missing_data_defaults (SCORING_MODEL.md). patch_latency has no documented
# default — it's always computed — so it falls back to 0.0 if ever missing.
MISSING_DATA_DEFAULTS: dict[str, float] = {
    "reachability": 5.0,
    "exploitability": 5.0,
    "exposure": 10.0,
    "centrality": 0.0,
    "patch_latency": 0.0,
    "maintainer_health": 5.0,
}

# Lower bound (inclusive) of each tier on the 0-100 composite scale
# (SCORING_MODEL.md). Ordered highest-first for bucket_tier.
TIER_THRESHOLDS: tuple[tuple[float, str], ...] = (
    (80.0, "Critical"),
    (60.0, "High"),
    (40.0, "Medium"),
    (20.0, "Low"),
    (0.0, "Informational"),
)


@dataclass
class DimensionScore:
    """A single dimension's score plus confidence/data-availability flag.

    Per ARCHITECTURE.md design principle #3: every dimension score carries
    a confidence flag, not just a number, to distinguish "scored high
    because genuinely risky" from "scored mid because data is missing."
    """

    score: float
    confidence: str  # e.g. "high", "indeterminate", "default"


@dataclass
class Finding:
    """A single component+CVE finding with per-dimension and composite scores.

    Per ARCHITECTURE.md design principle #5: output preserves per-dimension
    scores, not just the final composite, so the report can show *why* a
    finding scored the way it did.
    """

    component_name: str
    component_version: str
    cve_id: str
    reachability: DimensionScore | None = None
    exploitability: DimensionScore | None = None
    exposure: DimensionScore | None = None
    centrality: DimensionScore | None = None
    patch_latency: DimensionScore | None = None
    maintainer_health: DimensionScore | None = None
    vex_status: str | None = None
    composite_score: float | None = None
    tier: str | None = None
    dimension_scores: dict = field(default_factory=dict)


def load_weights(path: str = "weights.yaml") -> dict[str, float]:
    """Load dimension weights from config.

    Args:
        path: Path to the weights.yaml config file.

    Returns:
        A dict mapping dimension name -> weight (e.g. "reachability": 0.25),
        matching the values documented in SCORING_MODEL.md. Falls back to
        DEFAULT_WEIGHTS for any missing key, or entirely if the file is
        absent.
    """
    import yaml

    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return dict(DEFAULT_WEIGHTS)

    configured = data.get("weights") or {}
    return {
        dim: float(configured.get(dim, DEFAULT_WEIGHTS[dim]))
        for dim in _DIMENSION_ORDER
    }


def _dimension_value(finding: Finding, dim: str) -> float:
    """Return a finding's score for one dimension, or its missing-data default."""
    ds = getattr(finding, dim, None)
    if ds is not None:
        return float(ds.score)
    return MISSING_DATA_DEFAULTS.get(dim, 0.0)


def compute_composite(finding: Finding, weights: dict[str, float]) -> float:
    """Compute the weighted composite 0-100 score for a finding.

    Applies the VEX gate first (see sbom_scorer.vex.apply_vex_gate) — if the
    finding's VEX status is "not_affected", returns 0 without evaluating the
    six dimensions. Dimensions with no DimensionScore fall back to their
    documented missing-data default (MISSING_DATA_DEFAULTS).

    Args:
        finding: A Finding with its DimensionScores populated (or VEX
            status set to a suppressing value).
        weights: Dimension weights, typically from load_weights().

    Returns:
        The composite score, 0-100.
    """
    if apply_vex_gate(finding.vex_status):
        return 0.0

    weighted_sum = sum(
        _dimension_value(finding, dim) * float(weights.get(dim, 0.0))
        for dim in _DIMENSION_ORDER
    )
    return weighted_sum * 10.0


def bucket_tier(composite_score: float) -> str:
    """Map a 0-100 composite score to a tier label.

    Per SCORING_MODEL.md tier thresholds:
        80-100 Critical, 60-79 High, 40-59 Medium, 20-39 Low, 0-19 Informational.

    Args:
        composite_score: The 0-100 composite score.

    Returns:
        One of "Critical", "High", "Medium", "Low", "Informational".
    """
    for lower_bound, tier in TIER_THRESHOLDS:
        if composite_score >= lower_bound:
            return tier
    return "Informational"


def score_finding(finding: Finding, weights: dict[str, float]) -> Finding:
    """Run the full VEX-gate + composite + tier pipeline for one finding.

    Populates finding.composite_score, finding.tier, and finding.
    dimension_scores (a {dimension: score} snapshot including substituted
    missing-data defaults) in place, and returns the finding.
    """
    finding.composite_score = compute_composite(finding, weights)
    finding.tier = bucket_tier(finding.composite_score)
    finding.dimension_scores = {
        dim: _dimension_value(finding, dim) for dim in _DIMENSION_ORDER
    }
    return finding
