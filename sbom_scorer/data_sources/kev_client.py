"""CISA KEV (Known Exploited Vulnerabilities) catalog client.

Endpoint (DATA_SOURCES.md):
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Static JSON feed — pull the whole catalog and check CVE membership locally.
Refresh: daily.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import requests

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
DEFAULT_CACHE_PATH = Path(
    os.environ.get(
        "SBOM_SCORER_KEV_CACHE",
        Path.home() / ".cache" / "sbom-scorer" / "kev.json",
    )
)


def fetch_kev_catalog(cache_path: str | Path | None = None) -> list[dict]:
    """Download and parse the full CISA KEV catalog.

    Returns:
        List of KEV entries, each with fields including cveID, dateAdded,
        dueDate, knownRansomwareCampaignUse.

    Args:
        cache_path: Optional cache location, primarily for callers that need
            to keep scan artifacts together.

    Raises:
        requests.HTTPError: If CISA returns an unsuccessful response.
        ValueError: If the feed does not contain a vulnerability list.
    """
    resolved_cache_path = Path(cache_path) if cache_path else DEFAULT_CACHE_PATH
    today = datetime.now(UTC).date().isoformat()
    cached_catalog = _read_cache(resolved_cache_path, today)
    if cached_catalog is not None:
        return cached_catalog

    response = requests.get(KEV_FEED_URL, timeout=30)
    response.raise_for_status()
    catalog = response.json().get("vulnerabilities")
    if not isinstance(catalog, list):
        raise ValueError("CISA KEV feed is missing its vulnerabilities list")
    _write_cache(resolved_cache_path, today, catalog)
    return catalog


def get_kev_map(kev_catalog: list[dict] | None = None) -> dict[str, dict]:
    """Return KEV entries keyed by normalized CVE ID."""
    catalog = kev_catalog if kev_catalog is not None else fetch_kev_catalog()
    return {
        str(entry["cveID"]).strip().upper(): entry
        for entry in catalog
        if entry.get("cveID")
    }


def is_in_kev(cve_id: str, kev_catalog: list[dict] | None = None) -> bool:
    """Check whether a CVE is present in the CISA KEV catalog.

    Args:
        cve_id: CVE identifier to check.
        kev_catalog: Optionally, a pre-fetched catalog (from
            fetch_kev_catalog) to avoid refetching per call.

    Returns:
        True if the CVE is a known exploited vulnerability.
    """
    return cve_id.strip().upper() in get_kev_map(kev_catalog)


def _read_cache(cache_path: Path, today: str) -> list[dict] | None:
    try:
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    if cache.get("fetched_on") != today or not isinstance(cache.get("catalog"), list):
        return None
    return cache["catalog"]


def _write_cache(cache_path: Path, today: str, catalog: list[dict]) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(
        json.dumps(
            {"fetched_on": today, "catalog": catalog},
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
