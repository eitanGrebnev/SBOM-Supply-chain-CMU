"""SBOM ingestion — CycloneDX/SPDX parsing into components + dependency graph.

Per ARCHITECTURE.md: this module is the entry point of the data flow. It
turns a raw SBOM file into (1) a list of components with their CVE
associations and (2) a NetworkX DiGraph of "depends on" edges, which
sbom_scorer.dimensions.centrality consumes for blast-radius calculation.

Formats: CycloneDX (primary, via cyclonedx-python-lib) and SPDX
(secondary/optional, via spdx-tools). See DATA_SOURCES.md for field-level
detail (dependencies[]/components[] for CycloneDX, relationships[] for SPDX).

Implementation status: only JSON-encoded CycloneDX is fully wired up so far
(see _parse_cyclonedx), covering the slice Exposure Context (DIMENSIONS.md
#3) and Maintainer Health (DIMENSIONS.md #6) need: components[],
properties[] (exposure tier), and externalReferences (vcs_url).
Dependency-graph *edges* (dependencies[]), XML CycloneDX, and SPDX (any
encoding) are still out of scope for this slice and remain unimplemented —
_parse_cyclonedx returns a DiGraph with one node per component (keyed by
its CycloneDX bom-ref, so wiring dependencies[] edges later is a matter of
matching that same ref) but no edges. Whoever picks up full dependency-graph
parsing and SPDX support should treat those TODOs as the next slice.
"""

from __future__ import annotations

import json
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
        vcs_url: Source-repo URL, if declared. Sourced from CycloneDX
            externalReferences (type "vcs") once _parse_cyclonedx is
            implemented; until then this is populated only by callers that
            set it directly (e.g. tests). See DIMENSIONS.md #6 (Maintainer
            Health), which resolves a GitHub owner/repo from this field
            (falling back to registry metadata) via
            sbom_scorer.data_sources.repo_resolver.
    """

    name: str
    version: str
    ecosystem: str
    purl: str | None = None
    cve_ids: list[str] | None = None
    exposure_tier: str | None = None
    vcs_url: str | None = None


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
        ValueError: If the file doesn't look like CycloneDX or SPDX.
        NotImplementedError: For SPDX and XML-encoded CycloneDX input — only
            JSON CycloneDX is implemented so far (see module docstring).
    """
    fmt = _detect_format(path)
    if fmt == "cyclonedx":
        return _parse_cyclonedx(path)
    if fmt == "spdx":
        return _parse_spdx(path)
    raise ValueError(f"unrecognized SBOM format for {path!r}: {fmt!r}")


def _detect_format(path: str) -> str:
    """Detect whether a given SBOM file is CycloneDX or SPDX.

    Sniffs the file's content rather than trusting its extension. JSON
    CycloneDX is identified by `"bomFormat": "CycloneDX"`; JSON SPDX by a
    top-level `spdxVersion` key; SPDX tag-value by an `SPDXVersion:`/
    `SPDXID:` line; XML CycloneDX by a `<bom` root element referencing the
    cyclonedx schema. Detection succeeds for all of these even though only
    JSON CycloneDX is actually parseable right now (see module docstring) —
    that way parse_sbom() fails with a clear NotImplementedError naming the
    format, not a confusing low-level parse error.

    Returns:
        One of "cyclonedx" or "spdx".

    Raises:
        ValueError: If the file doesn't look like either format.
    """
    with open(path, encoding="utf-8") as f:
        head = f.read()

    stripped = head.lstrip()
    if stripped.startswith("{"):
        try:
            data = json.loads(head)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            if data.get("bomFormat") == "CycloneDX":
                return "cyclonedx"
            if "spdxVersion" in data:
                return "spdx"

    if "SPDXVersion:" in head or "SPDXID:" in head:
        return "spdx"
    if "<bom" in head and "cyclonedx" in head.lower():
        return "cyclonedx"

    raise ValueError(f"unrecognized SBOM format: {path}")


# CycloneDX custom property (metadata.component.properties[]) that carries
# the service/deployment-level exposure tier. Per DIMENSIONS.md #3, this is
# tagged once per SBOM (on the top-level/metadata component describing the
# deployed service), not per individual dependency component — so the same
# value is applied to every parsed Component below, not read per-component.
_EXPOSURE_PROPERTY_NAME = "exposure:tier"

# purl type -> ecosystem string, matching the casing
# sbom_scorer.data_sources.registry_client expects ("PyPI", "npm", ...).
_PURL_TYPE_TO_ECOSYSTEM = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "gem": "RubyGems",
    "cargo": "crates.io",
}


def _parse_cyclonedx(path: str) -> tuple[list[Component], nx.DiGraph]:
    """Parse a JSON CycloneDX SBOM via cyclonedx-python-lib.

    Populates components[] (name/version/ecosystem/purl), each component's
    vcs_url (from externalReferences, type "vcs"), and exposure_tier (from
    metadata.component.properties[], applied SBOM-wide — see
    _EXPOSURE_PROPERTY_NAME above). Returns a DiGraph with one node per
    component, keyed by CycloneDX bom-ref, but no edges: dependencies[]
    parsing is out of scope for this slice (see module docstring).

    See DATA_SOURCES.md CycloneDX section for the relevant fields:
    dependencies[], components[], and custom properties[] for exposure-tier
    tagging (DIMENSIONS.md #3).

    Raises:
        NotImplementedError: If the file is XML-encoded CycloneDX rather
            than JSON — not yet supported by this parser slice.
    """
    from cyclonedx.model import ExternalReferenceType
    from cyclonedx.model.bom import Bom

    with open(path, encoding="utf-8") as f:
        raw_text = f.read()
    try:
        raw = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise NotImplementedError(
            "XML-encoded CycloneDX SBOMs are not supported by this parser "
            "slice yet; only JSON CycloneDX is implemented so far (see "
            "sbom_scorer.sbom_parser module docstring)."
        ) from exc

    bom = Bom.from_json(raw)
    exposure_tier = _extract_exposure_tier(bom)

    components: list[Component] = []
    graph = nx.DiGraph()
    for cdx_component in bom.components:
        vcs_url = None
        for ref in cdx_component.external_references:
            if ref.type == ExternalReferenceType.SCM:
                vcs_url = str(ref.url)
                break

        purl = cdx_component.purl
        ecosystem = (
            _PURL_TYPE_TO_ECOSYSTEM.get(str(purl.type).lower(), str(purl.type))
            if purl is not None
            else ""
        )

        component = Component(
            name=str(cdx_component.name) if cdx_component.name else "",
            version=str(cdx_component.version) if cdx_component.version else "",
            ecosystem=ecosystem,
            purl=str(purl) if purl is not None else None,
            cve_ids=None,
            exposure_tier=exposure_tier,
            vcs_url=vcs_url,
        )
        components.append(component)

        # BomRef is always a non-None wrapper object once deserialized, even
        # when the SBOM didn't declare a bom-ref — its .value is None in
        # that case, so check .value directly rather than truthiness of the
        # wrapper (which would otherwise stringify to the literal "None").
        bom_ref_value = cdx_component.bom_ref.value if cdx_component.bom_ref is not None else None
        node_id = str(bom_ref_value) if bom_ref_value else (component.purl or f"{component.name}@{component.version}")
        graph.add_node(node_id)

    return components, graph


def _extract_exposure_tier(bom: Any) -> str | None:
    """Read the SBOM-wide exposure tier from metadata.component.properties[].

    Per DIMENSIONS.md #3, only the metadata/top-level component is checked
    (not individual dependency components) — this is a service/deployment
    classification made once per SBOM, not a per-package attribute. Values
    are normalized (lowercased, hyphens -> underscores) so a producer tagging
    e.g. "internet-facing" still matches the "internet_facing" vocabulary
    sbom_scorer.dimensions.exposure.ExposureTier expects.

    Returns:
        The normalized tier string, or None if untagged (metadata.component
        missing, or no "exposure:tier" property present). exposure.py's own
        default handles a None/unrecognized value as worst-case, so this
        function doesn't validate against the tier vocabulary itself.
    """
    metadata = getattr(bom, "metadata", None)
    component = getattr(metadata, "component", None) if metadata is not None else None
    if component is None:
        return None

    for prop in component.properties:
        name = (prop.name or "").strip().lower()
        if name != _EXPOSURE_PROPERTY_NAME:
            continue
        value = (prop.value or "").strip().lower().replace("-", "_")
        return value or None
    return None


def _parse_spdx(path: str) -> tuple[list[Component], nx.DiGraph]:
    """Parse an SPDX SBOM via spdx-tools.

    Note SPDX's relationships[] uses a different relationship-type
    vocabulary than CycloneDX's flat dependsOn — see DATA_SOURCES.md.

    Raises:
        NotImplementedError: Always — SPDX parsing is out of scope for this
            slice (see module docstring).
    """
    raise NotImplementedError
