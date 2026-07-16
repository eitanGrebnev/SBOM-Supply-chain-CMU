"""Package registry clients — fixed-version release-date resolution.

Per DATA_SOURCES.md, used by sbom_scorer.dimensions.patch_latency to
resolve the actual release timestamp of a fixed version (OSV.dev gives a
version identifier, not always a timestamp).

Registries:
    PyPI:          https://pypi.org/pypi/{package}/{version}/json
    npm:           https://registry.npmjs.org/{package}
    Maven Central: search.maven.org REST API
    RubyGems:      https://rubygems.org/api/v1/versions/{gem}.json
    crates.io:     https://crates.io/api/v1/crates/{crate}

Caching: indefinite per version (release dates never change once published).
"""

from __future__ import annotations

import datetime


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
