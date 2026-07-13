"""SBOM ingestion — CycloneDX/SPDX parsing into components + dependency graph.

Per ARCHITECTURE.md: this module is the entry point of the data flow. It
turns a raw SBOM file into (1) a list of components with their CVE
associations and (2) a NetworkX DiGraph of "depends on" edges, which
sbom_scorer.dimensions.centrality consumes for blast-radius calculation.

Formats: CycloneDX (primary, via cyclonedx-python-lib) and SPDX
(secondary/optional, via spdx-tools). See DATA_SOURCES.md for field-level
detail (dependencies[]/components[] for CycloneDX, relationships[] for SPDX).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import networkx as nx


@dataclass
class Component:
    """A single SBOM component (package/library) and its known CVEs.

    Attributes:
        name: Package name as declared in the SBOM.
        version: Resolved version string.
        ecosystem: Package ecosystem (e.g. "PyPI", "npm", "Maven").
        purl: Package URL identifier, if present.
        cve_ids: CVE identifiers associated with this component in the SBOM
            (embedded vulnerability data) or resolved via OSV lookup.
        exposure_tier: Exposure tier tag read from SBOM properties, if any.
            See DIMENSIONS.md #3 (Exposure Context) for the tier vocabulary.
    """

    name: str
    version: str
    ecosystem: str
    purl: str | None = None
    cve_ids: list[str] | None = None
    exposure_tier: str | None = None


def parse_sbom(path: str) -> tuple[list[Component], nx.DiGraph]:
    """Parse a CycloneDX or SPDX SBOM file into components and a dependency graph.

    Args:
        path: Filesystem path to the SBOM file (JSON/XML for CycloneDX,
            JSON/tag-value for SPDX).

    Returns:
        A tuple of (components, dependency_graph) where dependency_graph is a
        NetworkX DiGraph with edges representing "depends on" relationships,
        for use by sbom_scorer.dimensions.centrality.

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError


def _detect_format(path: str) -> str:
    """Detect whether a given SBOM file is CycloneDX or SPDX.

    Returns:
        One of "cyclonedx" or "spdx".
    """
    raise NotImplementedError


def _parse_cyclonedx(path: str) -> tuple[list[Component], nx.DiGraph]:
    """Parse a CycloneDX SBOM via cyclonedx-python-lib.

    See DATA_SOURCES.md CycloneDX section for the relevant fields:
    dependencies[], components[], and custom properties[] for exposure-tier
    tagging (DIMENSIONS.md #3).
    """
    raise NotImplementedError


def _parse_spdx(path: str) -> tuple[list[Component], nx.DiGraph]:
    """Parse an SPDX SBOM via spdx-tools.

    Note SPDX's relationships[] uses a different relationship-type
    vocabulary than CycloneDX's flat dependsOn — see DATA_SOURCES.md.
    """
    raise NotImplementedError
