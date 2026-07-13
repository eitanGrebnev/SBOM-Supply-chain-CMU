"""FIRST.org EPSS API client — exploitability probability scores.

Endpoint (DATA_SOURCES.md): https://api.first.org/data/v1/epss
Refresh: daily (EPSS scores update daily) — cache accordingly.
"""

from __future__ import annotations

EPSS_BASE_URL = "https://api.first.org/data/v1/epss"


def get_epss_score(cve_id: str) -> float | None:
    """Fetch the EPSS probability (0-1) for a single CVE.

    Returns:
        The EPSS probability, or None if the CVE is not present in the
        EPSS dataset.

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError


def get_epss_scores_batch(cve_ids: list[str]) -> dict[str, float]:
    """Fetch EPSS probabilities for multiple CVEs in one batched request.

    Args:
        cve_ids: List of CVE identifiers (comma-joined per EPSS API).

    Returns:
        Dict mapping cve_id -> EPSS probability. CVEs absent from the
        response are omitted (caller should treat as "not found").
    """
    raise NotImplementedError
