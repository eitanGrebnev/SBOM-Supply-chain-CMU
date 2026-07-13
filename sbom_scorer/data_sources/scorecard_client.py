"""OSSF Scorecard public REST API client — maintainer health data.

Endpoint (DATA_SOURCES.md):
    https://api.securityscorecards.dev/projects/{owner}/{repo}

Note: weekly-batch API results omit CI-Tests, Contributors, and
Dependency-Update-Tool checks due to compute cost — these may be absent
even when applicable. If a repo isn't indexed, treat as "no data" (404),
not "worst score".

Caching: weekly (matches Scorecard's own batch scan cadence).
"""

from __future__ import annotations

SCORECARD_API_BASE = "https://api.securityscorecards.dev/projects"


def get_scorecard(owner: str, repo: str) -> dict | None:
    """Fetch the OSSF Scorecard result for a GitHub repo.

    Args:
        owner: GitHub org/user.
        repo: Repo name.

    Returns:
        Raw Scorecard API response (aggregate score + per-check scores), or
        None if the repo isn't indexed (404/no data).

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError


def run_scorecard_cli(repo_url: str) -> dict:
    """Fallback: run the Scorecard CLI/Docker image directly against a repo.

    Only worth invoking for un-indexed repos important enough to justify
    the extra latency and GitHub PAT requirement.
    """
    raise NotImplementedError
