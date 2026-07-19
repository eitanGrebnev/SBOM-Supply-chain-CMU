"""OSSF Scorecard public REST API client — maintainer health data.

Endpoint (DATA_SOURCES.md):
    https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}

Response shape (Scorecard's documented result JSON): a top-level "score"
(aggregate, 0-10) plus a "checks" list of {"name", "score", "reason", ...}
per-check entries, where "score" is 0-10 or -1 for not-applicable.

Note: weekly-batch API results omit CI-Tests, Contributors, and
Dependency-Update-Tool checks due to compute cost — these may be absent
even when applicable. If a repo isn't indexed, treat as "no data" (404),
not "worst score".

Caching: weekly (matches Scorecard's own batch scan cadence), keyed per
owner/repo in a single local JSON file (unlike KEV/EPSS, this isn't one
shared feed — each project is fetched independently).
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import requests

SCORECARD_API_BASE = "https://api.securityscorecards.dev/projects"
CACHE_MAX_AGE_DAYS = 7  # matches Scorecard's own weekly batch-scan cadence

DEFAULT_CACHE_PATH = Path(
    os.environ.get(
        "SBOM_SCORER_SCORECARD_CACHE",
        Path.home() / ".cache" / "sbom-scorer" / "scorecard.json",
    )
)


def get_scorecard(
    owner: str, repo: str, cache_path: str | Path | None = None
) -> dict | None:
    """Fetch the OSSF Scorecard result for a GitHub repo.

    Args:
        owner: GitHub org/user.
        repo: Repo name.
        cache_path: Optional cache location, primarily for callers that need
            to keep scan artifacts together (mirrors epss_client/kev_client).

    Returns:
        Raw Scorecard API response (aggregate score + per-check scores), or
        None if the repo isn't indexed (404/no data).

    Raises:
        requests.HTTPError: If Scorecard returns a non-404 error response.
    """
    resolved_cache_path = Path(cache_path) if cache_path else DEFAULT_CACHE_PATH
    cache_key = f"{owner}/{repo}".lower()
    today = datetime.now(UTC).date()

    cache = _read_cache(resolved_cache_path)
    entry = cache.get(cache_key)
    if (
        isinstance(entry, dict)
        and _is_fresh(entry.get("fetched_on"), today)
    ):
        return entry.get("data")

    url = f"{SCORECARD_API_BASE}/github.com/{owner}/{repo}"
    response = requests.get(url, timeout=30)
    if response.status_code == 404:
        data = None
    else:
        response.raise_for_status()
        data = response.json()

    cache[cache_key] = {"fetched_on": today.isoformat(), "data": data}
    _write_cache(resolved_cache_path, cache)
    return data


def run_scorecard_cli(repo_url: str) -> dict:
    """Fallback: run the Scorecard CLI/Docker image directly against a repo.

    Only worth invoking for un-indexed repos important enough to justify
    the extra latency and GitHub PAT requirement. Out of scope for the
    initial Maintainer Health implementation — get_scorecard() returning
    None (not indexed) falls back to the neutral default score instead.

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError


def _is_fresh(fetched_on: str | None, today) -> bool:
    if not fetched_on:
        return False
    try:
        fetched_date = datetime.fromisoformat(fetched_on).date()
    except (ValueError, TypeError):
        # TypeError covers a corrupted/hand-edited cache where fetched_on
        # isn't even a string (e.g. an int) — treat like any other
        # malformed entry: not fresh, refetch rather than crash.
        return False
    return today - fetched_date < timedelta(days=CACHE_MAX_AGE_DAYS)


def _read_cache(cache_path: Path) -> dict:
    try:
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return cache if isinstance(cache, dict) else {}


def _write_cache(cache_path: Path, cache: dict) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(
        json.dumps(cache, indent=2, sort_keys=True), encoding="utf-8"
    )
