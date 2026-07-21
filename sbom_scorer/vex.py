"""VEX status parsing and the score-suppression gate.

Per SCORING_MODEL.md: VEX status is checked *before* the weighted composite
formula runs, not as a seventh dimension. "not_affected" suppresses the
score to 0/Informational regardless of the six dimension scores.

VEX documents are typically embedded in or distributed alongside the SBOM
(CycloneDX native VEX support, SPDX security-vulnerability extension, or
CSAF standalone). See DATA_SOURCES.md VEX section.
"""

from __future__ import annotations

from enum import Enum
from typing import Any


class VexStatus(str, Enum):
    """VEX analysis.state values (CycloneDX) / equivalent.

    See SCORING_MODEL.md "VEX Override" section for how each value is
    handled downstream.
    """

    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


def coerce_vex_status(value: Any) -> VexStatus | None:
    """Normalize a raw VEX status value into a VexStatus, or None if unknown.

    Accepts an existing VexStatus, or a string in either the CycloneDX
    dashed form ("not_affected") or common variants ("not affected",
    "NotAffected"). Unrecognized values return None (treated as "no VEX
    data", i.e. normal scoring proceeds).
    """
    if value is None:
        return None
    if isinstance(value, VexStatus):
        return value
    normalized = str(value).strip().lower().replace(" ", "_").replace("-", "_")
    try:
        return VexStatus(normalized)
    except ValueError:
        return None


def get_vex_status(component: Any, cve_id: str) -> VexStatus | None:
    """Look up the VEX status for a given component + CVE pair.

    VEX statements aren't parsed out of the SBOM into the Component model
    yet (that's a later slice). Until then, this reads an optional
    ``vex_statuses`` mapping (cve_id -> status) that a caller may attach to
    a component, falling back to a single ``vex_status`` attribute, and
    otherwise returns None so normal scoring proceeds.

    Args:
        component: A sbom_scorer.sbom_parser.Component (or raw SBOM finding
            record) to check for an attached VEX analysis.
        cve_id: The CVE identifier being evaluated.

    Returns:
        The VexStatus if a VEX statement exists for this component/CVE pair,
        otherwise None (no VEX data — proceed with normal scoring).
    """
    if component is None:
        return None

    statuses = getattr(component, "vex_statuses", None)
    if isinstance(statuses, dict):
        if cve_id in statuses:
            return coerce_vex_status(statuses[cve_id])

    return coerce_vex_status(getattr(component, "vex_status", None))


def apply_vex_gate(vex_status: "VexStatus | None") -> bool:
    """Determine whether the VEX gate suppresses scoring for this finding.

    Args:
        vex_status: The VexStatus for this finding, or None if no VEX data.

    Returns:
        True if the composite score should be forced to 0/Informational
        (i.e. vex_status is NOT_AFFECTED). False otherwise — including when
        vex_status is None, AFFECTED, or UNDER_INVESTIGATION (the latter
        should instead be flagged as provisional in output, not suppressed).
    """
    return coerce_vex_status(vex_status) == VexStatus.NOT_AFFECTED
