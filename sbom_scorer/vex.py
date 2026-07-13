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


def get_vex_status(component: Any, cve_id: str) -> VexStatus | None:
    """Look up the VEX status for a given component + CVE pair.

    Args:
        component: A sbom_scorer.sbom_parser.Component (or raw SBOM finding
            record) to check for an attached VEX analysis.
        cve_id: The CVE identifier being evaluated.

    Returns:
        The VexStatus if a VEX statement exists for this component/CVE pair,
        otherwise None (no VEX data — proceed with normal scoring).

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError


def apply_vex_gate(vex_status: "VexStatus | None") -> bool:
    """Determine whether the VEX gate suppresses scoring for this finding.

    Args:
        vex_status: The VexStatus for this finding, or None if no VEX data.

    Returns:
        True if the composite score should be forced to 0/Informational
        (i.e. vex_status is NOT_AFFECTED). False otherwise — including when
        vex_status is None, AFFECTED, or UNDER_INVESTIGATION (the latter
        should instead be flagged as provisional in output, not suppressed).

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError
