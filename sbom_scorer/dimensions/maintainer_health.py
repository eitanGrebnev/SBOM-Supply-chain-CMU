"""Maintainer Health dimension (weight 10% — DIMENSIONS.md #6).

How maintained is the dependency's repo, via OSSF Scorecard individual
check scores (not just the bundled aggregate), re-weighted per a custom
sub-formula:
    - Maintained, Signed-Releases, Code-Review/Contributors -> weighted heavily
    - Branch-Protection, Vulnerabilities -> weighted lightly

Scorecard returns -1 for not-applicable checks (redistribute that check's
weight across remaining applicable checks). Default to a neutral mid-score
(5.0) when Scorecard has no data at all for a repo.
"""

from __future__ import annotations

from sbom_scorer.composite import DimensionScore

DEFAULT_SCORE_NO_DATA = 5.0  # neutral default, per SCORING_MODEL.md


def score_maintainer_health(owner: str, repo: str) -> DimensionScore:
    """Score maintainer health for a GitHub-hosted dependency repo.

    Args:
        owner: GitHub org/user owning the repo.
        repo: Repo name.

    Returns:
        DimensionScore with score in [0, 10] and a confidence flag.

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError


def _reweight_checks(check_scores: dict[str, float]) -> float:
    """Apply the custom sub-formula weighting to Scorecard's individual checks.

    Redistributes weight from any -1 (not-applicable) checks across the
    remaining applicable checks rather than treating -1 as failing.
    """
    raise NotImplementedError
