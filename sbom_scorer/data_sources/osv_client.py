"""OSV.dev API client — patch latency data + general vulnerability lookup.

Per ARCHITECTURE.md design principle #2: all external API calls are wrapped
in dedicated client modules with their own caching layer, so dimension
modules never call `requests` directly.

Endpoints (DATA_SOURCES.md):
    POST https://api.osv.dev/v1/query       (single package+version, full detail)
    POST https://api.osv.dev/v1/querybatch  (batch, abbreviated per-result detail)

Caching: per-scan / live (query is cheap and specific to package+version).
"""

from __future__ import annotations
import functools

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"

@functools.lru_cache(maxsize=None)
def query_by_package(name: str, ecosystem: str, version: str) -> dict:
    """Query OSV.dev for vulnerabilities affecting a specific package version.

    Args:
        name: Package name.
        ecosystem: OSV ecosystem string (e.g. "PyPI", "npm").
        version: Version string to check.

    Returns:
        Raw OSV response dict, including `published`, `affected[].ranges[].events`,
        and `references[]` (look for type == "FIX").
    """
    import requests
    payload = {
        "version": version,
        "package": {
            "name": name,
            "ecosystem": ecosystem
        }
    }
    try:
        response = requests.post(OSV_QUERY_URL, json=payload, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error querying OSV for {name}@{version}: {e}")
        return {}


def query_by_commit(commit_hash: str) -> dict:
    """Query OSV.dev for vulnerabilities associated with a specific commit."""
    raise NotImplementedError


def query_batch(queries: list[dict]) -> list[dict]:
    """Batch-query OSV.dev for many package+version pairs at once.

    Recommended over repeated query_by_package calls when scanning a full
    SBOM's worth of components — see sbom_scorer.cli's CVE-discovery batch
    prefilter, which uses this to cheaply skip the (usually many) clean
    components before making a full query_by_package call on each one that
    actually has a hit.

    Args:
        queries: One query dict per package, each shaped like
            query_by_package's payload: `{"package": {"name": ...,
            "ecosystem": ...}, "version": ...}`.

    Returns:
        One result dict per query, same order as `queries`. Per OSV's
        batch API, each result's `vulns[]` entries are deliberately
        abbreviated to just `id` and `modified` (no `published`,
        `affected[].ranges[].events`, `references[]`, or `aliases` — the
        detail query_by_package returns) to keep the batch response small.
        That's sufficient to know a package has *some* hit, but not enough
        to resolve a CVE alias or get fix/disclosure data — callers still
        need query_by_package for that.

    Raises:
        requests.RequestException: On any network/HTTP failure. Unlike
        query_by_package, this deliberately does NOT swallow the error
        into an empty/all-clean-looking result: a failed batch call has a
        much larger blast radius than a single failed query_by_package
        call (one component silently looking clean vs. an *entire SBOM*
        silently looking clean and never getting checked at all), so
        callers need to be able to tell "nothing found" apart from
        "couldn't check" and fail open accordingly — see
        sbom_scorer.cli._batch_prefilter_candidates.
    """
    import requests

    if not queries:
        return []

    response = requests.post(OSV_QUERYBATCH_URL, json={"queries": queries}, timeout=30)
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        # OSV's 4xx body names the offending query (e.g. "error in query at
        # index 7: ... invalid ecosystem"). raise_for_status() alone throws
        # that away, leaving a bare "400 Bad Request" that says nothing about
        # which of several hundred components broke the batch.
        detail = response.text.strip()[:300]
        raise requests.HTTPError(f"{exc} :: {detail}", response=response) from exc
    results = response.json().get("results", [])

    # Defensive: pad/truncate to match `queries` 1:1 even if OSV ever
    # returns a shorter/malformed `results[]` — callers zip() this against
    # their own query list and shouldn't have to guard against a length
    # mismatch themselves.
    if len(results) < len(queries):
        results = results + [{}] * (len(queries) - len(results))
    return results[: len(queries)]


def get_fix_commit_url(osv_record: dict) -> str | None:
    """Extract the fix commit URL from an OSV record's references[], if present."""
    raise NotImplementedError
