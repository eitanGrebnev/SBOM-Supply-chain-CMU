"""OSV.dev API client — patch latency data + general vulnerability lookup.

Per ARCHITECTURE.md design principle #2: all external API calls are wrapped
in dedicated client modules with their own caching layer, so dimension
modules never call `requests` directly.

Endpoints (DATA_SOURCES.md):
    POST https://api.osv.dev/v1/query       (single package+version)
    POST https://api.osv.dev/v1/querybatch  (batch)

Caching: per-scan / live (query is cheap and specific to package+version).
"""

from __future__ import annotations

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"


def query_by_package(name: str, ecosystem: str, version: str) -> dict:
    """Query OSV.dev for vulnerabilities affecting a specific package version.

    Args:
        name: Package name.
        ecosystem: OSV ecosystem string (e.g. "PyPI", "npm").
        version: Version string to check.

    Returns:
        Raw OSV response dict, including `published`, `affected[].ranges[].events`,
        and `references[]` (look for type == "FIX").

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError


def query_by_commit(commit_hash: str) -> dict:
    """Query OSV.dev for vulnerabilities associated with a specific commit."""
    raise NotImplementedError


def query_batch(queries: list[dict]) -> list[dict]:
    """Batch-query OSV.dev for many package+version pairs at once.

    Recommended over repeated query_by_package calls when scanning a full
    SBOM's worth of components.
    """
    raise NotImplementedError


def get_fix_commit_url(osv_record: dict) -> str | None:
    """Extract the fix commit URL from an OSV record's references[], if present."""
    raise NotImplementedError
