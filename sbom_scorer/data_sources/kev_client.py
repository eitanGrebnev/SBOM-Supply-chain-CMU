"""CISA KEV (Known Exploited Vulnerabilities) catalog client.

Endpoint (DATA_SOURCES.md):
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Static JSON feed — pull the whole catalog and check CVE membership locally.
Refresh: daily.
"""

from __future__ import annotations

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def fetch_kev_catalog() -> list[dict]:
    """Download and parse the full CISA KEV catalog.

    Returns:
        List of KEV entries, each with fields including cveID, dateAdded,
        dueDate, knownRansomwareCampaignUse.

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError


def is_in_kev(cve_id: str, kev_catalog: list[dict] | None = None) -> bool:
    """Check whether a CVE is present in the CISA KEV catalog.

    Args:
        cve_id: CVE identifier to check.
        kev_catalog: Optionally, a pre-fetched catalog (from
            fetch_kev_catalog) to avoid refetching per call.

    Returns:
        True if the CVE is a known exploited vulnerability.
    """
    raise NotImplementedError
