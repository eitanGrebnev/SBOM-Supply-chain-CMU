"""Maintainer Health dimension (weight 10% — DIMENSIONS.md #6).

How maintained is the dependency's repo, via OSSF Scorecard individual
check scores (not just the bundled aggregate), re-weighted per a custom
sub-formula (CHECK_WEIGHTS below):
    - Maintained, Signed-Releases, Code-Review, Contributors -> 0.20 each
      (0.80 total) — "weighted heavily" per DIMENSIONS.md
    - Branch-Protection, Vulnerabilities -> 0.10 each (0.20 total) —
      "weighted lightly" per DIMENSIONS.md

Scorecard returns -1 for not-applicable checks, and the weekly-batch API
can simply omit CI-Tests/Contributors/Dependency-Update-Tool entirely
(DATA_SOURCES.md). Both cases are treated identically: that check's weight
is redistributed proportionally across whichever of the six checks above
are actually present with a valid (>=0) score.

Two distinct "no signal" cases both fall back to DEFAULT_SCORE_NO_DATA
(5.0, confidence="default") rather than a failing score, per
SCORING_MODEL.md's stated rationale that absence of data isn't evidence of
poor maintenance:
    1. The component's GitHub repo couldn't be resolved at all (see
       sbom_scorer.data_sources.repo_resolver).
    2. Scorecard has no record for the resolved repo (not yet indexed), or
       none of the six checks this module cares about are present/valid.
"""

from __future__ import annotations

from sbom_scorer.composite import DimensionScore
from sbom_scorer.data_sources.repo_resolver import resolve_github_repo
from sbom_scorer.data_sources.scorecard_client import get_scorecard
from sbom_scorer.sbom_parser import Component

DEFAULT_SCORE_NO_DATA = 5.0  # neutral default, per SCORING_MODEL.md

# Sub-formula weights, per DIMENSIONS.md #6. Kept as a module constant
# rather than in weights.yaml: unlike the six top-level dimension weights
# composite.py consumes, this split is an internal implementation detail of
# how *this one dimension* re-derives a single score from Scorecard's
# per-check breakdown.
CHECK_WEIGHTS: dict[str, float] = {
    "Maintained": 0.20,
    "Signed-Releases": 0.20,
    "Code-Review": 0.20,
    "Contributors": 0.20,
    "Branch-Protection": 0.10,
    "Vulnerabilities": 0.10,
}

# Below this many usable checks (out of 6), too much weight has been
# redistributed to call the result "high" confidence even though it's a
# real number, not a default.
MIN_CHECKS_FOR_HIGH_CONFIDENCE = 4


def score_maintainer_health(component: Component) -> DimensionScore:
    """Score maintainer health for a component's GitHub-hosted repo.

    Resolves the component to a GitHub owner/repo (via
    sbom_scorer.data_sources.repo_resolver), fetches its OSSF Scorecard
    result, and reweights the individual check scores per CHECK_WEIGHTS.

    Args:
        component: The SBOM component being scored.

    Returns:
        DimensionScore with score in [0, 10] and a confidence flag:
        "high" when most checks are present, "medium" when significant
        redistribution occurred, "default" when there's no usable
        Scorecard signal at all (repo unresolvable, not indexed, or none
        of the six tracked checks are present/valid).
    """
    repo = resolve_github_repo(component)
    if repo is None:
        return DimensionScore(score=DEFAULT_SCORE_NO_DATA, confidence="default")

    owner, repo_name = repo
    scorecard_data = get_scorecard(owner, repo_name)
    if not scorecard_data:
        return DimensionScore(score=DEFAULT_SCORE_NO_DATA, confidence="default")

    # `or []` (not `.get("checks", [])`) so an explicit JSON null for
    # "checks" is treated the same as a missing key, not iterated as None.
    raw_checks = {
        check.get("name"): check.get("score")
        for check in scorecard_data.get("checks") or []
        if check.get("name") in CHECK_WEIGHTS
    }
    usable = _usable_checks(raw_checks)
    if not usable:
        return DimensionScore(score=DEFAULT_SCORE_NO_DATA, confidence="default")

    score = _reweight_checks(raw_checks)
    confidence = "high" if len(usable) >= MIN_CHECKS_FOR_HIGH_CONFIDENCE else "medium"
    return DimensionScore(score=score, confidence=confidence)


def _usable_checks(check_scores: dict[str, float | None]) -> dict[str, float]:
    """Filter to checks we track that have a valid (>=0) score present.

    Guards against a check score that isn't actually numeric (unexpected
    API response shape) by treating it as absent rather than raising.
    """
    return {
        name: score
        for name, score in check_scores.items()
        if name in CHECK_WEIGHTS
        and isinstance(score, (int, float))
        and not isinstance(score, bool)
        and score >= 0
    }


def _reweight_checks(check_scores: dict[str, float | None]) -> float:
    """Apply the custom sub-formula weighting to Scorecard's individual checks.

    Redistributes weight from any -1 (not-applicable) or missing checks
    across the remaining applicable checks rather than treating them as a
    zero/failing score.

    Args:
        check_scores: Scorecard per-check scores keyed by check name. Keys
            outside CHECK_WEIGHTS are ignored; -1 or missing entries are
            excluded and their weight redistributed.

    Returns:
        The reweighted 0-10 score.

    Raises:
        ValueError: If no checks in check_scores are usable — callers
            should check via _usable_checks() first and fall back to
            DEFAULT_SCORE_NO_DATA in that case, per SCORING_MODEL.md.
    """
    usable = _usable_checks(check_scores)
    total_weight = sum(CHECK_WEIGHTS[name] for name in usable)
    if total_weight <= 0:
        raise ValueError("no usable Scorecard checks to reweight")
    weighted_sum = sum(CHECK_WEIGHTS[name] * score for name, score in usable.items())
    return weighted_sum / total_weight
