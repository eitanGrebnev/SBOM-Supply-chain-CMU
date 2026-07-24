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
    Maven Central: search.maven.org's solrsearch REST API for the release
                   timestamp; the artifact's own POM (fetched from
                   repo1.maven.org) for repo URL, since search.maven.org's
                   index doesn't carry SCM info. `package` is expected in
                   "groupId:artifactId" form (matching
                   sbom_scorer.sbom_parser's Maven component naming).
    RubyGems:      https://rubygems.org/api/v1/versions/{gem}.json for
                   release date; https://rubygems.org/api/v1/gems/{gem}.json
                   (source_code_uri/homepage_uri) for repo URL.
    crates.io:     https://crates.io/api/v1/crates/{crate} for both — crates.io
                   requires a descriptive User-Agent on every request (its
                   API usage policy blocks generic/default ones).

Caching: indefinite per version (release dates never change once published).
get_repo_url() is also indefinitely cached per package — a project's
declared source repo essentially never changes release-to-release.
"""

from __future__ import annotations

import datetime
import functools
import re

# crates.io's API policy requires every request to identify the calling
# application via User-Agent (https://crates.io/data-access#api) — a
# generic/default User-Agent can be rate-limited or blocked outright.
_CRATES_USER_AGENT = (
    "sbom-scorer/0.1 (https://github.com/eitanGrebnev/SBOM-Supply-chain-CMU)"
)


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
        The release datetime, or None if it could not be resolved (including
        an unrecognized ecosystem string).
    """
    ecosystem = ecosystem.lower()
    if ecosystem == "pypi":
        return _pypi_release_date(package, version)
    elif ecosystem == "npm":
        return _npm_release_date(package, version)
    elif ecosystem == "maven":
        return _maven_release_date(package, version)
    elif ecosystem == "rubygems":
        return _rubygems_release_date(package, version)
    elif ecosystem == "crates.io":
        return _crates_release_date(package, version)
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


def _split_maven_package(package: str) -> tuple[str, str] | None:
    """Split a "groupId:artifactId" package string, or None if malformed."""
    if not package or ":" not in package:
        return None
    group_id, _, artifact_id = package.partition(":")
    if not group_id or not artifact_id:
        return None
    return group_id, artifact_id


def _maven_release_date(package: str, version: str) -> datetime.datetime | None:
    import requests

    split = _split_maven_package(package)
    if split is None:
        return None
    group_id, artifact_id = split

    url = "https://search.maven.org/solrsearch/select"
    params = {
        "q": f'g:"{group_id}" AND a:"{artifact_id}" AND v:"{version}"',
        "core": "gav",
        "rows": 1,
        "wt": "json",
    }
    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        docs = response.json().get("response", {}).get("docs", [])
        if not docs:
            return None
        # "timestamp" is epoch milliseconds (when Central indexed this GAV).
        timestamp_ms = docs[0].get("timestamp")
        if timestamp_ms is None:
            return None
        return datetime.datetime.fromtimestamp(timestamp_ms / 1000, tz=datetime.timezone.utc)
    except (requests.RequestException, ValueError, AttributeError, TypeError):
        return None


def _rubygems_release_date(package: str, version: str) -> datetime.datetime | None:
    import requests

    url = f"https://rubygems.org/api/v1/versions/{package}.json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        versions = response.json()
        for entry in versions:
            if entry.get("number") == version:
                created_at = entry.get("created_at")
                if not created_at:
                    return None
                if created_at.endswith("Z"):
                    created_at = created_at[:-1] + "+00:00"
                return datetime.datetime.fromisoformat(created_at).astimezone(datetime.timezone.utc)
        return None
    except (requests.RequestException, ValueError, AttributeError, TypeError):
        return None


def _crates_release_date(package: str, version: str) -> datetime.datetime | None:
    import requests

    url = f"https://crates.io/api/v1/crates/{package}"
    headers = {"User-Agent": _CRATES_USER_AGENT}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        versions = response.json().get("versions") or []
        for entry in versions:
            if entry.get("num") == version:
                created_at = entry.get("created_at")
                if not created_at:
                    return None
                if created_at.endswith("Z"):
                    created_at = created_at[:-1] + "+00:00"
                return datetime.datetime.fromisoformat(created_at).astimezone(datetime.timezone.utc)
        return None
    except (requests.RequestException, ValueError, AttributeError, TypeError):
        return None


@functools.lru_cache(maxsize=None)
def get_repo_url(ecosystem: str, package: str) -> str | None:
    """Resolve a package's declared source-repo URL from its registry entry.

    Dispatches to the ecosystem-specific lookup based on `ecosystem`. Not
    guaranteed to be a GitHub URL — callers that specifically need a GitHub
    owner/repo (e.g. sbom_scorer.data_sources.repo_resolver) must parse and
    validate the result themselves.

    Args:
        ecosystem: One of "PyPI", "npm", "Maven", "RubyGems", "crates.io".
        package: Package name (for Maven, "groupId:artifactId" — see
            get_release_date).

    Returns:
        A repo/homepage URL string as declared by the registry, or None if
        it could not be resolved (including an unrecognized ecosystem
        string).
    """
    ecosystem = ecosystem.lower()
    if ecosystem == "pypi":
        return _pypi_repo_url(package)
    elif ecosystem == "npm":
        return _npm_repo_url(package)
    elif ecosystem == "maven":
        return _maven_repo_url(package)
    elif ecosystem == "rubygems":
        return _rubygems_repo_url(package)
    elif ecosystem == "crates.io":
        return _crates_repo_url(package)
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


# Maven POMs declare a default XML namespace (usually the 4.0.0 POM schema,
# but Maven doesn't actually validate it strictly) — try the namespaced tag
# first, then a bare (namespace-less) fallback for POMs that omit it.
_MAVEN_POM_NS = {"m": "http://maven.apache.org/POM/4.0.0"}


def _maven_repo_url(package: str) -> str | None:
    import xml.etree.ElementTree as ET

    import requests

    split = _split_maven_package(package)
    if split is None:
        return None
    group_id, artifact_id = split

    try:
        # search.maven.org's index doesn't carry SCM/repo info — only the
        # default (non-"gav") core does, and only to find the latest
        # version; the repo URL itself has to come from that version's POM.
        search_url = "https://search.maven.org/solrsearch/select"
        params = {"q": f'g:"{group_id}" AND a:"{artifact_id}"', "rows": 1, "wt": "json"}
        response = requests.get(search_url, params=params, timeout=10)
        response.raise_for_status()
        docs = response.json().get("response", {}).get("docs", [])
        if not docs:
            return None
        version = docs[0].get("latestVersion")
        if not version:
            return None

        group_path = group_id.replace(".", "/")
        pom_url = (
            f"https://repo1.maven.org/maven2/{group_path}/{artifact_id}/"
            f"{version}/{artifact_id}-{version}.pom"
        )
        pom_response = requests.get(pom_url, timeout=10)
        pom_response.raise_for_status()
        root = ET.fromstring(pom_response.content)

        for path in ("m:scm/m:url", "scm/url", "m:url", "url"):
            ns = _MAVEN_POM_NS if path.startswith("m:") else {}
            element = root.find(path, ns)
            if element is not None and element.text:
                return element.text.strip()
        return None
    except (requests.RequestException, ET.ParseError, ValueError, AttributeError, TypeError):
        return None


def _rubygems_repo_url(package: str) -> str | None:
    import requests
    url = f"https://rubygems.org/api/v1/gems/{package}.json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        for key in ("source_code_uri", "homepage_uri"):
            candidate = data.get(key)
            if candidate:
                return candidate
        return None
    except (requests.RequestException, ValueError, AttributeError, TypeError):
        return None


def _crates_repo_url(package: str) -> str | None:
    import requests
    url = f"https://crates.io/api/v1/crates/{package}"
    headers = {"User-Agent": _CRATES_USER_AGENT}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        crate = response.json().get("crate") or {}
        return crate.get("repository") or crate.get("homepage") or None
    except (requests.RequestException, ValueError, AttributeError, TypeError):
        return None
