"""GitHub owner/repo resolution for a Component — Maintainer Health support.

DIMENSIONS.md #6 (Maintainer Health) scores against the OSSF Scorecard API,
which is keyed by GitHub owner/repo. A Component doesn't carry that
directly, so this module resolves it in two steps:

1. Component.vcs_url, if set (eventually sourced from CycloneDX
   externalReferences of type "vcs" once sbom_parser._parse_cyclonedx is
   implemented — see sbom_parser.Component's docstring).
2. Fallback: look up the package's declared repo URL from its registry
   entry (sbom_scorer.data_sources.registry_client.get_repo_url), keyed off
   Component.ecosystem/name. Covers the common case where the SBOM itself
   has no vcs_url but the package registry does (e.g. PyPI project_urls,
   npm's repository field).

Only GitHub is in scope — Scorecard's public API and most of its
individual checks are GitHub-specific (DATA_SOURCES.md, checks.md). A
non-GitHub or unresolvable repo returns None, which
sbom_scorer.dimensions.maintainer_health treats the same as "no Scorecard
data": a neutral default score, not a failing one.
"""

from __future__ import annotations

import re

from sbom_scorer.data_sources import registry_client
from sbom_scorer.sbom_parser import Component

_GITHUB_URL_RE = re.compile(
    r"(?<![\w-])github\.com[:/]+([^/\s?#]+)/([^/\s?#]+)", re.IGNORECASE
)


def resolve_github_repo(component: Component) -> tuple[str, str] | None:
    """Resolve a Component to a (owner, repo) GitHub pair, if possible.

    Args:
        component: The SBOM component to resolve.

    Returns:
        (owner, repo) if a GitHub URL could be identified, else None.
    """
    from_vcs = _parse_github_url(component.vcs_url)
    if from_vcs is not None:
        return from_vcs

    if not component.ecosystem or not component.name:
        return None
    registry_url = registry_client.get_repo_url(component.ecosystem, component.name)
    return _parse_github_url(registry_url)


def _parse_github_url(url: str | None) -> tuple[str, str] | None:
    """Extract (owner, repo) from a github.com URL in any common form.

    Handles https://github.com/owner/repo, .../owner/repo.git,
    git@github.com:owner/repo.git, URLs with trailing path segments (e.g.
    /issues, /tree/main), and trailing query strings/fragments (e.g.
    ?tab=readme, #readme) — only the first two path components after
    github.com are used, stopping at any /, ?, or #. Rejects lookalike
    hosts (e.g. notgithub.com) via a word-boundary check before
    "github.com".
    """
    if not url:
        return None
    match = _GITHUB_URL_RE.search(url)
    if not match:
        return None
    owner, repo = match.group(1), match.group(2)
    repo = re.sub(r"\.git$", "", repo, flags=re.IGNORECASE)
    if not owner or not repo:
        return None
    return owner, repo
