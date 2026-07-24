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
import re
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import requests

SCORECARD_API_BASE = "https://api.securityscorecards.dev/projects"
CACHE_MAX_AGE_DAYS = 7  # matches Scorecard's own weekly batch-scan cadence

# Official Scorecard Docker image (DATA_SOURCES.md), used when the `scorecard`
# binary isn't on PATH.
SCORECARD_DOCKER_IMAGE = "gcr.io/openssf/scorecard:stable"

# Scorecard clones and analyzes the repo, which is slow compared to the
# REST API's pre-computed lookup — generous but bounded so a hung clone
# doesn't hang the whole scan.
SCORECARD_CLI_TIMEOUT_SECONDS = 600

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


def run_scorecard_cli(
    repo_url: str,
    github_token: str | None = None,
    timeout: int = SCORECARD_CLI_TIMEOUT_SECONDS,
) -> dict:
    """Fallback: run the Scorecard CLI/Docker image directly against a repo.

    Only worth invoking for un-indexed repos (get_scorecard() returned None)
    important enough to justify the extra latency and GitHub PAT requirement
    — it clones and statically analyzes the repo rather than reading a
    pre-computed weekly batch result, so it's much slower than the REST API.
    Callers decide when that tradeoff is worth it; this function doesn't
    call get_scorecard() itself or apply any "is this important enough"
    policy.

    Prefers a local `scorecard` binary on PATH; falls back to
    `docker run gcr.io/openssf/scorecard` if the binary isn't found. Either
    way requires a GitHub personal access token (Scorecard hits the GitHub
    API directly and gets aggressively rate-limited without one).

    Args:
        repo_url: A GitHub repo reference in any of: `owner/repo`,
            `github.com/owner/repo`, or a full `https://github.com/owner/repo`
            URL (optionally with a trailing `.git` or `/`).
        github_token: GitHub PAT to authenticate with. Falls back to the
            `GITHUB_AUTH_TOKEN` then `GH_TOKEN` environment variables.
        timeout: Subprocess timeout in seconds.

    Returns:
        The parsed Scorecard result JSON — same shape as get_scorecard()'s
        return value (top-level "score" plus a "checks" list), so callers
        can treat the two interchangeably.

    Raises:
        RuntimeError: If no GitHub token is available, if neither the
            `scorecard` binary nor `docker` is on PATH, if the subprocess
            exits non-zero, or if its stdout isn't valid JSON.
        subprocess.TimeoutExpired: If the scan exceeds `timeout`.
    """
    token = (
        github_token
        or os.environ.get("GITHUB_AUTH_TOKEN")
        or os.environ.get("GH_TOKEN")
    )
    if not token:
        raise RuntimeError(
            "run_scorecard_cli requires a GitHub token — set GITHUB_AUTH_TOKEN "
            "or GH_TOKEN, or pass github_token=... explicitly. Scorecard's "
            "CLI hits the GitHub API directly and gets rate-limited hard "
            "without one."
        )

    repo_ref = _normalize_repo_ref(repo_url)
    binary = shutil.which("scorecard")
    env = dict(os.environ)
    env["GITHUB_AUTH_TOKEN"] = token

    if binary:
        cmd = [binary, f"--repo={repo_ref}", "--format=json"]
    else:
        docker = shutil.which("docker")
        if not docker:
            raise RuntimeError(
                "Neither the `scorecard` binary nor `docker` is available on "
                "PATH — install one of them to use the un-indexed-repo "
                "fallback (see DATA_SOURCES.md)."
            )
        cmd = [
            docker,
            "run",
            "--rm",
            "-e",
            f"GITHUB_AUTH_TOKEN={token}",
            SCORECARD_DOCKER_IMAGE,
            f"--repo={repo_ref}",
            "--format=json",
        ]

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, env=env
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"scorecard CLI failed (exit {result.returncode}) for {repo_ref}: "
            f"{(result.stderr or result.stdout).strip()}"
        )

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"scorecard CLI returned non-JSON output for {repo_ref}: {e}"
        ) from e


_REPO_URL_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$"
)


def _normalize_repo_ref(repo_url: str) -> str:
    """Normalize an owner/repo reference to Scorecard's `--repo` format.

    Accepts `owner/repo`, `github.com/owner/repo`, or a full
    `https://github.com/owner/repo` URL (with an optional trailing `.git`
    or `/`) and returns `github.com/owner/repo`.
    """
    candidate = repo_url.strip()
    match = _REPO_URL_RE.match(candidate)
    if match:
        owner, repo = match.groups()
        return f"github.com/{owner}/{repo}"

    stripped = candidate.removeprefix("github.com/")
    parts = [p for p in stripped.split("/") if p]
    if len(parts) == 2:
        owner, repo = parts
        return f"github.com/{owner}/{repo.removesuffix('.git')}"

    raise ValueError(f"Can't parse GitHub repo reference from {repo_url!r}")


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
