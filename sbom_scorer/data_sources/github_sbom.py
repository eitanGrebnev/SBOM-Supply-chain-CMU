"""GitHub repository -> SBOM fetch.

Lets a user scan a repo by URL instead of supplying an SBOM file. Uses
GitHub's dependency-graph SBOM export endpoint, which returns an SPDX
document — no external SBOM-generation binary (syft/cdxgen) required:

    GET /repos/{owner}/{repo}/dependency-graph/sbom

The returned SPDX JSON is parsed by sbom_scorer.sbom_parser._parse_spdx.

Auth: works unauthenticated for public repos but is heavily rate-limited.
Set a token via the GITHUB_TOKEN environment variable to raise the limit
and to reach private repos. The token is read from the environment and sent
as a Bearer credential; it is never logged.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any

GITHUB_API_BASE = "https://api.github.com"


class GitHubRateLimitError(RuntimeError):
    """Raised when GitHub rejects a request because of rate limiting.

    Distinct from a permission failure so callers (and the CLI's error
    output) can tell "wait or authenticate" apart from "you cannot see this".
    """

# Accepts: https://github.com/owner/repo(.git)(/...), git@github.com:owner/repo,
# github.com/owner/repo, or a bare "owner/repo".
_REPO_PATTERNS = [
    re.compile(r"github\.com[/:]([^/]+)/([^/#?]+?)(?:\.git)?(?:[/#?].*)?$", re.IGNORECASE),
    re.compile(r"^([^/\s]+)/([^/\s]+)$"),
]


def parse_repo_url(url: str) -> tuple[str, str]:
    """Extract (owner, repo) from a GitHub URL or "owner/repo" string.

    Raises:
        ValueError: If no owner/repo can be parsed from the input.
    """
    candidate = url.strip()
    for pattern in _REPO_PATTERNS:
        match = pattern.search(candidate)
        if match:
            owner, repo = match.group(1), match.group(2)
            repo = repo.removesuffix(".git")
            if owner and repo:
                return owner, repo
    raise ValueError(f"could not parse a GitHub owner/repo from {url!r}")


def _github_token() -> str | None:
    """Read a GitHub token from the environment, if set."""
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def fetch_sbom(url: str, token: str | None = None, timeout: int = 30) -> dict[str, Any]:
    """Fetch a repo's SPDX SBOM document via the GitHub dependency-graph API.

    Args:
        url: GitHub repo URL or "owner/repo".
        token: Optional GitHub token; falls back to GITHUB_TOKEN/GH_TOKEN env.
        timeout: Per-request timeout in seconds.

    Returns:
        The SPDX document dict (the inner "sbom" object from the API
        response), suitable for writing to a .spdx.json file.

    Raises:
        ValueError: On an unparseable URL or an unexpected response shape.
        requests.HTTPError: On a non-2xx GitHub response.
    """
    import requests

    owner, repo = parse_repo_url(url)
    endpoint = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/dependency-graph/sbom"

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = token or _github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    response = requests.get(endpoint, headers=headers, timeout=timeout)

    # A bare raise_for_status() here surfaces as an opaque "403 Client Error",
    # which is the single most common failure of an unauthenticated scan and
    # gives the user nothing to act on. Rate limiting, missing permissions and
    # a disabled dependency graph all need different fixes, so separate them.
    if response.status_code in (403, 429):
        remaining = response.headers.get("X-RateLimit-Remaining")
        if remaining == "0" or "Retry-After" in response.headers:
            reset = response.headers.get("X-RateLimit-Reset")
            when = ""
            if reset and reset.isdigit():
                minutes = max(0, round((int(reset) - time.time()) / 60))
                when = f" Resets in about {minutes} minute(s)."
            hint = (
                "Set GITHUB_TOKEN to raise the limit from 60 to 5,000 requests/hour."
                if not token
                else "Wait for the window to reset, or lower SBOM_SCORER_MAX_WORKERS."
            )
            raise GitHubRateLimitError(
                f"GitHub rate limit exceeded for {owner}/{repo}.{when} {hint}"
            )
        raise PermissionError(
            f"GitHub denied access to {owner}/{repo}'s dependency graph. "
            "A private repo needs a token with the 'repo' scope."
        )

    if response.status_code == 404:
        raise ValueError(
            f"No dependency-graph SBOM for {owner}/{repo}. The repo may not exist, "
            "may be private (set GITHUB_TOKEN), or may have the dependency graph "
            "disabled in Settings > Code security."
        )

    response.raise_for_status()
    data = response.json()

    sbom = data.get("sbom") if isinstance(data, dict) else None
    if not isinstance(sbom, dict):
        raise ValueError(
            f"unexpected SBOM response for {owner}/{repo}: missing 'sbom' object"
        )
    return sbom


def fetch_sbom_to_file(url: str, out_path: str, token: str | None = None) -> str:
    """Fetch a repo's SPDX SBOM and write it to out_path. Returns out_path."""
    sbom = fetch_sbom(url, token=token)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f)
    return out_path
