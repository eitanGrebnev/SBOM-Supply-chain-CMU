"""FIRST.org EPSS API client — exploitability probability + percentile scores.

Endpoint (DATA_SOURCES.md): https://api.first.org/data/v1/epss
Refresh: daily (EPSS scores update daily) — cache accordingly.

Per DIMENSIONS.md #2, scoring uses the **percentile** field (rank relative
to all other scored CVEs), not the raw probability — so this client
surfaces both, matching what the API actually returns per CVE:
`epss` (probability, 0-1), `percentile` (0-1), and `date`.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import requests

EPSS_BASE_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 100
DEFAULT_CACHE_PATH = Path(
    os.environ.get(
        "SBOM_SCORER_EPSS_CACHE",
        Path.home() / ".cache" / "sbom-scorer" / "epss.json",
    )
)


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


def get_epss_record(
    cve_id: str, cache_path: str | Path | None = None
) -> EpssRecord | None:
    """Fetch the EPSS record (probability + percentile + date) for a single CVE.

    Returns:
        An EpssRecord, or None if the CVE is not present in the EPSS
        dataset.

    The batch client backs this helper, so callers that already have a CVE
    collection should prefer get_epss_records_batch().
    """
    normalized_id = cve_id.strip().upper()
    return get_epss_records_batch([normalized_id], cache_path=cache_path).get(
        normalized_id
    )


def get_epss_records_batch(
    cve_ids: list[str], cache_path: str | Path | None = None
) -> dict[str, EpssRecord]:
    """Fetch EPSS records for multiple CVEs in one batched request.

    Corresponds to pipeline step 3 in DIMENSIONS.md #2 (normalize/dedupe
    CVE list beforehand — this function expects clean input).

    Args:
        cve_ids: CVE identifiers. Values are normalized and deduplicated.
        cache_path: Optional cache location, primarily for callers that need
            to keep scan artifacts together.

    Returns:
        Dict mapping cve_id -> EpssRecord. CVEs absent from the response
        are omitted (caller should treat as "not found" and apply
        DEFAULT_SCORE_NO_EPSS per sbom_scorer.dimensions.exploitability).

    Raises:
        requests.HTTPError: If FIRST.org returns an unsuccessful response.
        ValueError: If a returned EPSS record contains invalid values.
    """
    normalized_ids = list(
        dict.fromkeys(cve_id.strip().upper() for cve_id in cve_ids if cve_id.strip())
    )
    if not normalized_ids:
        return {}

    resolved_cache_path = Path(cache_path) if cache_path else DEFAULT_CACHE_PATH
    today = datetime.now(UTC).date().isoformat()
    cache = _read_cache(resolved_cache_path, today)
    cached_records = cache["records"]
    queried_cves = set(cache["queried_cves"])
    missing_ids = [cve_id for cve_id in normalized_ids if cve_id not in queried_cves]

    for start in range(0, len(missing_ids), EPSS_BATCH_SIZE):
        batch = missing_ids[start : start + EPSS_BATCH_SIZE]
        response = requests.get(
            EPSS_BASE_URL,
            params={"cve": ",".join(batch)},
            timeout=30,
        )
        response.raise_for_status()
        for item in response.json().get("data", []):
            record = _parse_record(item)
            cached_records[record.cve_id] = {
                "cve_id": record.cve_id,
                "probability": record.probability,
                "percentile": record.percentile,
                "date": record.date,
            }
        queried_cves.update(batch)

    if missing_ids:
        _write_cache(resolved_cache_path, today, queried_cves, cached_records)

    return {
        cve_id: EpssRecord(**cached_records[cve_id])
        for cve_id in normalized_ids
        if cve_id in cached_records
    }


def _parse_record(item: dict) -> EpssRecord:
    cve_id = str(item["cve"]).strip().upper()
    probability = float(item["epss"])
    percentile = float(item["percentile"])
    if not 0 <= probability <= 1 or not 0 <= percentile <= 1:
        raise ValueError(f"Invalid EPSS values for {cve_id}")
    return EpssRecord(cve_id, probability, percentile, str(item["date"]))


def _read_cache(cache_path: Path, today: str) -> dict:
    try:
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {"queried_cves": [], "records": {}}
    if cache.get("fetched_on") != today:
        return {"queried_cves": [], "records": {}}
    return {
        "queried_cves": cache.get("queried_cves", []),
        "records": cache.get("records", {}),
    }


def _write_cache(
    cache_path: Path, today: str, queried_cves: set[str], records: dict
) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(
        json.dumps(
            {
                "fetched_on": today,
                "queried_cves": sorted(queried_cves),
                "records": records,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
