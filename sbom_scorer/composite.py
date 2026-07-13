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
    """Load dimension weights (and tier thresholds) from config.

    Args:
        path: Path to the weights.yaml config file.

    Returns:
        A dict mapping dimension name -> weight (e.g. "reachability": 0.25),
        matching the values documented in SCORING_MODEL.md.

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError


def compute_composite(finding: Finding, weights: dict[str, float]) -> float:
    """Compute the weighted composite 0-100 score for a finding.

    Applies the VEX gate first (see sbom_scorer.vex.apply_vex_gate) — if the
    finding's VEX status is "not_affected", returns 0 without evaluating the
    six dimensions.

    Args:
        finding: A Finding with all six DimensionScores populated (or VEX
            status set to a suppressing value).
        weights: Dimension weights, typically from load_weights().

    Returns:
        The composite score, 0-100.

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError


def bucket_tier(composite_score: float) -> str:
    """Map a 0-100 composite score to a tier label.

    Per SCORING_MODEL.md tier thresholds:
        80-100 Critical, 60-79 High, 40-59 Medium, 20-39 Low, 0-19 Informational.

    Args:
        composite_score: The 0-100 composite score.

    Returns:
        One of "Critical", "High", "Medium", "Low", "Informational".

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError


def score_finding(finding: Finding, weights: dict[str, float]) -> Finding:
    """Run the full VEX-gate + composite + tier pipeline for one finding.

    Convenience wrapper that populates finding.composite_score and
    finding.tier in place and returns the finding.

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError
