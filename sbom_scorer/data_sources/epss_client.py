"""FIRST.org EPSS API client — exploitability probability + percentile scores.

Endpoint (DATA_SOURCES.md): https://api.first.org/data/v1/epss
Refresh: daily (EPSS scores update daily) — cache accordingly.

Per DIMENSIONS.md #2, scoring uses the **percentile** field (rank relative
to all other scored CVEs), not the raw probability — so this client
surfaces both, matching what the API actually returns per CVE:
`epss` (probability, 0-1), `percentile` (0-1), and `date`.
"""

from __future__ import annotations

from dataclasses import dataclass

EPSS_BASE_URL = "https://api.first.org/data/v1/epss"


@dataclass
class EpssRecord:
    """A single CVE's EPSS data, as returned by FIRST.org.

    Attributes:
        cve_id: CVE identifier.
        probability: Raw EPSS probability (0-1) of exploitation in the next
            30 days.
        percentile: Percentile rank (0-1) relative to all other scored
            CVEs — this is what DIMENSIONS.md #2's scoring table uses.
        date: The EPSS scoring date (data is refreshed daily).
    """

    cve_id: str
    probability: float
    percentile: float
    date: str


def get_epss_record(cve_id: str) -> EpssRecord | None:
    """Fetch the EPSS record (probability + percentile + date) for a single CVE.

    Returns:
        An EpssRecord, or None if the CVE is not present in the EPSS
        dataset.

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError


def get_epss_records_batch(cve_ids: list[str]) -> dict[str, EpssRecord]:
    """Fetch EPSS records for multiple CVEs in one batched request.

    Corresponds to pipeline step 3 in DIMENSIONS.md #2 (normalize/dedupe
    CVE list beforehand — this function expects clean input).

    Args:
        cve_ids: List of CVE identifiers (comma-joined per EPSS API).

    Returns:
        Dict mapping cve_id -> EpssRecord. CVEs absent from the response
        are omitted (caller should treat as "not found" and apply
        DEFAULT_SCORE_NO_EPSS per sbom_scorer.dimensions.exploitability).

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError
