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

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError


def _pypi_release_date(package: str, version: str) -> datetime.datetime | None:
    raise NotImplementedError


def _npm_release_date(package: str, version: str) -> datetime.datetime | None:
    raise NotImplementedError


def _maven_release_date(package: str, version: str) -> datetime.datetime | None:
    raise NotImplementedError


def _rubygems_release_date(package: str, version: str) -> datetime.datetime | None:
    raise NotImplementedError


def _crates_release_date(package: str, version: str) -> datetime.datetime | None:
    raise NotImplementedError
