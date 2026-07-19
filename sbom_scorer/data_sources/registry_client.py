"""Package registry clients — fixed-version release-date resolution, plus
source-repo URL lookup.

Per DATA_SOURCES.md, get_release_date() is used by
sbom_scorer.dimensions.patch_latency to resolve the actual release
timestamp of a fixed version (OSV.dev gives a version identifier, not
always a timestamp). get_repo_url() is used by
sbom_scorer.data_sources.repo_resolver as a fallback source-repo lookup for
Maintainer Health (DIMENSIONS.md #6) when a component has no vcs_url of its
own — it reuses the same per-package JSON payload rather than issuing a
second request per ecosystem.

Registries:
    PyPI:          https://pypi.org/pypi/{package}/{version}/json
    npm:           https://registry.npmjs.org/{package}
    Maven Central: search.maven.org REST API
    RubyGems:      https://rubygems.org/api/v1/versions/{gem}.json
    crates.io:     https://crates.io/api/v1/crates/{crate}

Caching: indefinite per version (release dates never change once published).
get_repo_url() is also indefinitely cached per package — a project's
declared source repo essentially never changes release-to-release.
"""

from __future__ import annotations

import datetime
import functools
import re


@functools.lru_cache(maxsize=None)
def get_release_date(ecosystem: str, package: str, version: str) -> datetime.datetime | None:
    """Resolve the release timestamp for a specific package version.

    Dispatches to the ecosystem-specific lookup (_pypi_release_date,
    _npm_release_date, etc.) based on `ecosystem`.

    Args:
        ecosystem: One of "PyPI", "npm", "Maven", "RubyGems", "crates.io"
            (matching OSV ecosystem naming where applicable).
        package: Package name.
        version: Version string.

    Returns:
        The release datetime, or None if it could not be resolved.
    """
    ecosystem = ecosystem.lower()
    if ecosystem == "pypi":
        return _pypi_release_date(package, version)
    elif ecosystem == "npm":
        return _npm_release_date(package, version)
    # Others omitted for now
    return None


def _pypi_release_date(package: str, version: str) -> datetime.datetime | None:
    import requests
    url = f"https://pypi.org/pypi/{package}/{version}/json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        urls = data.get("urls", [])
        if urls:
            upload_time = urls[0].get("upload_time")
            if upload_time:
                return datetime.datetime.fromisoformat(upload_time).replace(tzinfo=datetime.timezone.utc)
    except requests.RequestException:
        pass
    return None


def _npm_release_date(package: str, version: str) -> datetime.datetime | None:
    import requests
    url = f"https://registry.npmjs.org/{package}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        time_dict = data.get("time", {})
        release_time = time_dict.get(version)
        if release_time:
            # Handle standard ISO8601 strings from npm
            if release_time.endswith("Z"):
                release_time = release_time[:-1] + "+00:00"
            return datetime.datetime.fromisoformat(release_time).replace(tzinfo=datetime.timezone.utc)
    except requests.RequestException:
        pass
    return None


def _maven_release_date(package: str, version: str) -> datetime.datetime | None:
    raise NotImplementedError


def _rubygems_release_date(package: str, version: str) -> datetime.datetime | None:
    raise NotImplementedError


def _crates_release_date(package: str, version: str) -> datetime.datetime | None:
    raise NotImplementedError


@functools.lru_cache(maxsize=None)
def get_repo_url(ecosystem: str, package: str) -> str | None:
    """Resolve a package's declared source-repo URL from its registry entry.

    Dispatches to the ecosystem-specific lookup based on `ecosystem`. Not
    guaranteed to be a GitHub URL — callers that specifically need a GitHub
    owner/repo (e.g. sbom_scorer.data_sources.repo_resolver) must parse and
    validate the result themselves.

    Args:
        ecosystem: One of "PyPI", "npm" (others fall through to None; see
            get_release_date's ecosystem list for what's eventually planned).
        package: Package name.

    Returns:
        A repo/homepage URL string as declared by the registry, or None if
        it could not be resolved.
    """
    ecosystem = ecosystem.lower()
    if ecosystem == "pypi":
        return _pypi_repo_url(package)
    elif ecosystem == "npm":
        return _npm_repo_url(package)
    # Others omitted for now
    return None


# Registry lookups can fail in more ways than a network error: a non-2xx
# response is covered by raise_for_status() -> requests.RequestException,
# but a malformed-but-200 body (bad JSON, or JSON whose shape isn't a dict
# where one's expected) raises ValueError/AttributeError/TypeError instead.
# Both function bodies below treat any of these as "couldn't resolve a repo
# URL" (return None) rather than crashing the caller.

_NPM_SHORTHAND_RE = re.compile(
    r"^(?:(?P<host>github|gitlab|bitbucket):)?(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)$"
)


def _normalize_npm_repository(repository: str) -> str | None:
    """Normalize npm's shorthand repository notation to a full URL.

    npm's package.json `repository` field commonly uses shorthand like
    "github:owner/repo" or bare "owner/repo" (which defaults to GitHub per
    npm's own spec) rather than a full URL. Bare "gitlab:"/"bitbucket:"
    shorthand is left as-is (not GitHub, so repo_resolver's GitHub-only
    parsing will correctly reject it rather than misidentifying it).
    """
    match = _NPM_SHORTHAND_RE.match(repository.strip())
    if not match:
        return repository
    host = match.group("host") or "github"
    if host != "github":
        return repository
    return f"https://github.com/{match.group('owner')}/{match.group('repo')}"


def _pypi_repo_url(package: str) -> str | None:
    import requests
    url = f"https://pypi.org/pypi/{package}/json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        info = response.json().get("info") or {}
        project_urls = info.get("project_urls") or {}
        for key in ("Source", "Source Code", "Repository", "Code", "Homepage"):
            candidate = project_urls.get(key)
            if candidate:
                return candidate
        for candidate in project_urls.values():
            if candidate:
                return candidate
        return info.get("home_page") or None
    except (requests.RequestException, ValueError, AttributeError, TypeError):
        # ValueError covers json.JSONDecodeError (malformed-but-200 body);
        # AttributeError/TypeError cover an unexpected (non-dict) response
        # shape, e.g. info/project_urls not being dicts as expected.
        return None


def _npm_repo_url(package: str) -> str | None:
    import requests
    url = f"https://registry.npmjs.org/{package}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        repository = response.json().get("repository")
        if isinstance(repository, dict):
            repository = repository.get("url")
        if isinstance(repository, str) and repository:
            return _normalize_npm_repository(repository)
    except (requests.RequestException, ValueError, AttributeError, TypeError):
        return None
    return None
