"""SBOM ingestion — CycloneDX/SPDX parsing into components + dependency graph.

Per ARCHITECTURE.md: this module is the entry point of the data flow. It
turns a raw SBOM file into (1) a list of components with their CVE
associations and (2) a NetworkX DiGraph of "depends on" edges, which
sbom_scorer.dimensions.centrality consumes for blast-radius calculation.

Formats: CycloneDX (primary, via cyclonedx-python-lib) and SPDX
(secondary/optional, via spdx-tools). See DATA_SOURCES.md for field-level
detail (dependencies[]/components[] for CycloneDX, relationships[] for SPDX).

Implementation status: CycloneDX (JSON and XML) and SPDX (JSON and
tag-value) are all wired up (see _parse_cyclonedx / _parse_spdx and their
helpers), covering the slices Exposure Context (DIMENSIONS.md #3),
Maintainer Health (DIMENSIONS.md #6), Centrality (DIMENSIONS.md #4), and
the VEX gate (SCORING_MODEL.md) need: components[], properties[] (exposure
tier), externalReferences (vcs_url), dependency-graph *edges* (CycloneDX
`dependencies[]` / SPDX `relationships[]` of type DEPENDS_ON), and
CycloneDX's embedded `vulnerabilities[]` (per-component CVE ids plus each
one's VEX `analysis.state`, per DATA_SOURCES.md's VEX section). Each
parsed Component carries a `bom_ref` matching the graph node id it
corresponds to, so callers (e.g. cli.py, dimensions/centrality.py) can
look a Component up in the graph directly. SPDX's non-standard
security-vulnerability extension remains unimplemented — SPDX has no
embedded-VEX equivalent in the base spec, and GitHub's dependency-graph
SBOM export (this project's primary SPDX source) doesn't include one
anyway.
"""

from __future__ import annotations

import io
import json
from dataclasses import dataclass
from typing import Any

import networkx as nx


@dataclass
class Component:
    """A single SBOM component (package/library) and its known CVEs.

    Attributes:
        name: Package name in the form OSV/registry lookups expect — for
            Maven and scoped npm packages this is the *combined*
            groupId:artifactId / @scope/name identity (from the purl's
            namespace + name), not just CycloneDX's bare `name` field,
            which for those two ecosystems is only the artifactId/unscoped
            name on its own (see _resolve_component_name). Every other
            ecosystem uses the SBOM's declared name as-is.
        version: Resolved version string.
        ecosystem: Package ecosystem (e.g. "PyPI", "npm", "Maven").
        purl: Package URL identifier, if present.
        cve_ids: CVE identifiers associated with this component in the SBOM
            (embedded vulnerability data, from CycloneDX `vulnerabilities[]`
            `affects[]`) or resolved via OSV lookup when empty — see
            cli._discover_cves.
        vex_statuses: cve_id -> VEX status string (e.g. "not_affected"),
            for CVEs with an embedded CycloneDX `vulnerabilities[].analysis`
            block. Read by sbom_scorer.vex.get_vex_status to drive the
            score-suppression gate (SCORING_MODEL.md). Empty/missing means
            no VEX statement for that CVE, so normal scoring proceeds.
        exposure_tier: Exposure tier tag read from SBOM properties, if any.
            See DIMENSIONS.md #3 (Exposure Context) for the tier vocabulary.
        vcs_url: Source-repo URL, if declared. Sourced from CycloneDX
            externalReferences (type "vcs") once _parse_cyclonedx is
            implemented; until then this is populated only by callers that
            set it directly (e.g. tests). See DIMENSIONS.md #6 (Maintainer
            Health), which resolves a GitHub owner/repo from this field
            (falling back to registry metadata) via
            sbom_scorer.data_sources.repo_resolver.
        bom_ref: The identifier this component was keyed under in the
            dependency_graph returned alongside it (CycloneDX bom-ref /
            SPDX SPDXID, falling back to purl or "name@version" when the
            SBOM didn't declare one) — look this up in the graph to find
            the component's node for sbom_scorer.dimensions.centrality.
    """

    name: str
    version: str
    ecosystem: str
    purl: str | None = None
    cve_ids: list[str] | None = None
    vex_statuses: dict[str, str] | None = None
    exposure_tier: str | None = None
    vcs_url: str | None = None
    bom_ref: str | None = None


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
#
# Unmapped types fall through to the raw purl type (see _parse_purl), which
# OSV rejects with a 400 rather than an empty result — and because one bad
# entry fails the whole /v1/querybatch request, a single unmapped component
# degrades the entire scan to per-component queries. GitHub's dependency
# graph emits githubactions for every workflow `uses:` line, so any repo
# with CI hit this. The names below are OSV's exact ecosystem spellings.
_PURL_TYPE_TO_ECOSYSTEM = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "gem": "RubyGems",
    "cargo": "crates.io",
    "githubactions": "GitHub Actions",
    "golang": "Go",
    "nuget": "NuGet",
    "composer": "Packagist",
}

# Ecosystems whose real package identity is split across a namespace segment
# (Maven's groupId, npm's @scope, an Action's or a Packagist package's owner,
# a Go module's host+path) plus a bare name, and the separator OSV/the
# registries expect joining them back together with. Ecosystems absent from
# this map (PyPI, RubyGems, crates.io, NuGet) address packages by a single
# flat name, so their CycloneDX `name` field is already the whole identity.
_NAMESPACED_ECOSYSTEM_JOINERS = {
    "Maven": ":",
    "npm": "/",
    "GitHub Actions": "/",
    "Go": "/",
    "Packagist": "/",
}

# The ecosystem strings OSV will actually accept, i.e. everything the map
# above can produce. An unmapped purl type falls through as its raw purl
# type ("conan", "github", ...), which OSV rejects with a 400 — and since a
# single bad entry fails an entire /v1/querybatch call, callers must be able
# to drop those *before* batching instead of losing the whole batch.
OSV_ECOSYSTEMS = frozenset(_PURL_TYPE_TO_ECOSYSTEM.values())


def _resolve_component_name(cdx_component: Any, purl: Any, ecosystem: str) -> str:
    """Build the package name OSV/registry lookups actually expect.

    CycloneDX splits a Maven/scoped-npm component's identity into `group`
    (groupId / @scope) and `name` (artifactId / unscoped name) — the
    component's own `name` field alone is NOT a valid OSV or registry
    package identifier for these ecosystems (e.g. "log4j-api" instead of
    "org.apache.logging.log4j:log4j-api"). Using it directly doesn't error;
    it just makes every lookup silently find nothing, which looks
    identical to "no known vulnerabilities" — worth getting right rather
    than discovering it from an all-zero scan of a real SBOM.

    Prefers the parsed purl's `namespace` (more consistently populated
    across producers than CycloneDX's own `group` field) when present;
    falls back to the component's plain declared name otherwise, matching
    prior behavior for everything else (PyPI/RubyGems/crates.io don't
    split identity this way, and unscoped npm/unnamespaced Maven purls
    have no namespace to prepend).
    """
    joiner = _NAMESPACED_ECOSYSTEM_JOINERS.get(ecosystem)
    if joiner and purl is not None and purl.namespace:
        return f"{purl.namespace}{joiner}{purl.name}"
    return str(cdx_component.name) if cdx_component.name else ""

# CycloneDX's ImpactAnalysisState vocabulary (its own terms) -> this
# project's VEX vocabulary (sbom_scorer.vex.VexStatus, which follows the
# CSAF/OpenVEX affected/not_affected/fixed/under_investigation terms DATA_
# SOURCES.md documents). NOT_AFFECTED already matches verbatim; the rest are
# CycloneDX-specific states mapped onto the closest equivalent:
#   exploitable            -> affected (confirmed impacted)
#   resolved(+pedigree)     -> fixed (a patched version addresses it)
#   in_triage               -> under_investigation (not yet determined)
#   false_positive          -> not_affected (determined not to actually apply)
_CDX_ANALYSIS_STATE_TO_VEX = {
    "not_affected": "not_affected",
    "false_positive": "not_affected",
    "exploitable": "affected",
    "resolved": "fixed",
    "resolved_with_pedigree": "fixed",
    "in_triage": "under_investigation",
}


def _looks_like_cve(value: Any) -> bool:
    """True if value is a non-empty string in "CVE-YYYY-NNNN" form."""
    return bool(value) and str(value).upper().startswith("CVE-")


def _extract_cve_id(vulnerability: Any) -> str | None:
    """Pick the best CVE identifier for a CycloneDX Vulnerability entry.

    Prefers vulnerability.id when it's already CVE-shaped; otherwise scans
    its references[] for a CVE-shaped alias (a vulnerability sourced from
    GHSA, for example, commonly lists the CVE as a reference rather than
    as the primary id). Falls back to the raw id (even if not CVE-shaped)
    so the finding isn't dropped outright — downstream EPSS/KEV lookups
    that expect a CVE ID simply won't match a non-CVE identifier, same as
    today's OSV-discovered CVEs that turn out to have no EPSS record.
    """
    if _looks_like_cve(vulnerability.id):
        return str(vulnerability.id)
    for ref in vulnerability.references or []:
        if _looks_like_cve(ref.id):
            return str(ref.id)
    return str(vulnerability.id) if vulnerability.id else None


def _apply_vulnerabilities(bom: Any, components_by_ref: dict[str, Component]) -> None:
    """Attach CycloneDX vulnerabilities[] data onto the Components it affects.

    For each Vulnerability, resolves a CVE id (_extract_cve_id) and matches
    affects[].ref against components_by_ref (keyed by Component.bom_ref) to
    find which parsed Component(s) it's about. Populates that Component's
    cve_ids (embedded vulnerability data, per DIMENSIONS.md's CVE-discovery
    step) and, if an analysis block is present, vex_statuses[cve_id] (the
    VEX gate's input — see _CDX_ANALYSIS_STATE_TO_VEX and
    sbom_scorer.vex.get_vex_status). A Vulnerability with no analysis block
    contributes CVE ids but no VEX status, which is correct: "no VEX
    statement" should proceed with normal scoring, not be treated as
    not_affected.
    """
    for vulnerability in bom.vulnerabilities:
        cve_id = _extract_cve_id(vulnerability)
        if not cve_id:
            continue

        vex_status = None
        analysis = vulnerability.analysis
        if analysis is not None and analysis.state is not None:
            vex_status = _CDX_ANALYSIS_STATE_TO_VEX.get(str(analysis.state.value))

        for target in vulnerability.affects or []:
            component = components_by_ref.get(str(target.ref))
            if component is None:
                continue

            if component.cve_ids is None:
                component.cve_ids = []
            if cve_id not in component.cve_ids:
                component.cve_ids.append(cve_id)

            if vex_status:
                if component.vex_statuses is None:
                    component.vex_statuses = {}
                component.vex_statuses[cve_id] = vex_status


def _parse_purl(purl: str) -> tuple[str, str, str | None] | None:
    """Split a Package URL into (ecosystem, name, version).

    Handles the common cases seen in SPDX/CycloneDX SBOMs: a leading
    ``pkg:<type>/`` prefix, an optional namespace segment, and an optional
    ``@version`` suffix (plus trailing qualifiers/subpath, which are
    stripped). Ecosystem casing is normalized to what the registry/OSV
    clients expect via _PURL_TYPE_TO_ECOSYSTEM. Returns None if the string
    isn't a purl.
    """
    from urllib.parse import unquote

    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[len("pkg:"):].split("#", 1)[0].split("?", 1)[0]
    purl_type, _, rest = body.partition("/")
    ecosystem = _PURL_TYPE_TO_ECOSYSTEM.get(purl_type.lower(), purl_type)

    version: str | None = None
    name_part = rest
    if "@" in rest:
        name_part, _, version = rest.rpartition("@")

    name_part = unquote(name_part)
    # Maven's OSV/registry name is "groupId:artifactId"; npm keeps its
    # "@scope/name" namespace form; others use the trailing segment as-is.
    if ecosystem == "Maven":
        name = name_part.replace("/", ":")
    else:
        name = name_part
    return ecosystem, name, (version or None)


def _parse_cyclonedx(path: str) -> tuple[list[Component], nx.DiGraph]:
    """Parse a JSON or XML CycloneDX SBOM via cyclonedx-python-lib.

    Content, not the file extension, decides which encoding this is: if the
    file parses as JSON it's handled as JSON CycloneDX (`Bom.from_json`);
    otherwise it's handed to `Bom.from_xml` as XML CycloneDX. Either way,
    the resulting `Bom` object is walked identically — see
    _build_from_cyclonedx_bom for what gets populated (components[],
    vcs_url, exposure_tier, cve_ids/vex_statuses, dependency-graph edges).

    Raises:
        Whatever cyclonedx-python-lib itself raises if the content is
        neither valid JSON nor valid XML CycloneDX (a genuinely malformed
        file — _detect_format already confirmed it *looks* like CycloneDX
        before this function is ever called).
    """
    from cyclonedx.model.bom import Bom

    with open(path, encoding="utf-8") as f:
        raw_text = f.read()

    try:
        raw = json.loads(raw_text)
    except json.JSONDecodeError:
        bom = Bom.from_xml(io.StringIO(raw_text))
    else:
        bom = Bom.from_json(raw)

    return _build_from_cyclonedx_bom(bom)


def _build_from_cyclonedx_bom(bom: Any) -> tuple[list[Component], nx.DiGraph]:
    """Walk an already-parsed cyclonedx-python-lib Bom into components + a graph.

    Shared by both the JSON and XML CycloneDX paths (_parse_cyclonedx) —
    once cyclonedx-python-lib has deserialized either encoding into the
    same `Bom` object model, there's nothing encoding-specific left to do.

    Populates components[] (name/version/ecosystem/purl/bom_ref), each
    component's vcs_url (from externalReferences, type "vcs"), exposure_tier
    (from metadata.component.properties[], applied SBOM-wide — see
    _EXPOSURE_PROPERTY_NAME above), and cve_ids/vex_statuses (from the
    top-level vulnerabilities[] array, matched back to components via
    affects[].ref — see _apply_vulnerabilities). Returns a DiGraph with one
    node per component (keyed by CycloneDX bom-ref, matching Component.
    bom_ref) plus "depends on" edges parsed from the top-level
    `dependencies[]` array (DIMENSIONS.md #4, Centrality) — each
    Dependency's `ref` gets an edge to every bom-ref in its
    `dependencies_as_bom_refs()`. A dependencies[] entry may reference a
    node (e.g. the root application component) that isn't itself in
    components[]; that node is added to the graph anyway so the edge isn't
    dropped.

    See DATA_SOURCES.md CycloneDX section for the relevant fields:
    dependencies[], components[], vulnerabilities[] (VEX), and custom
    properties[] for exposure-tier tagging (DIMENSIONS.md #3).
    """
    from cyclonedx.model import ExternalReferenceType

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

        # BomRef is always a non-None wrapper object once deserialized, even
        # when the SBOM didn't declare a bom-ref — its .value is None in
        # that case, so check .value directly rather than truthiness of the
        # wrapper (which would otherwise stringify to the literal "None").
        bom_ref_value = cdx_component.bom_ref.value if cdx_component.bom_ref is not None else None
        node_id = str(bom_ref_value) if bom_ref_value else (purl and str(purl)) or f"{cdx_component.name}@{cdx_component.version}"

        component = Component(
            name=_resolve_component_name(cdx_component, purl, ecosystem),
            version=str(cdx_component.version) if cdx_component.version else "",
            ecosystem=ecosystem,
            purl=str(purl) if purl is not None else None,
            cve_ids=None,
            exposure_tier=exposure_tier,
            vcs_url=vcs_url,
            bom_ref=node_id,
        )
        components.append(component)
        graph.add_node(node_id)

    # vulnerabilities[]: embedded CVE associations + VEX analysis, matched
    # back onto the components they affect via bom-ref (DATA_SOURCES.md's
    # VEX section, SCORING_MODEL.md's suppression gate).
    components_by_ref = {c.bom_ref: c for c in components if c.bom_ref}
    _apply_vulnerabilities(bom, components_by_ref)

    # dependencies[]: each entry is (ref, {direct dependency refs}) —
    # DIMENSIONS.md #4 "Sub-method A/B" both need these as real graph edges,
    # not just isolated nodes. Nodes referenced here but absent from
    # components[] (e.g. the root application component) are added so the
    # edge isn't silently dropped.
    for dependency in bom.dependencies:
        ref_value = dependency.ref.value if dependency.ref is not None else None
        if not ref_value:
            continue
        ref_id = str(ref_value)
        graph.add_node(ref_id)
        for dep_ref in dependency.dependencies_as_bom_refs():
            dep_value = dep_ref.value if dep_ref is not None else None
            if not dep_value:
                continue
            dep_id = str(dep_value)
            graph.add_node(dep_id)
            graph.add_edge(ref_id, dep_id)

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
    """Parse a JSON or tag-value SPDX SBOM into components + a dependency graph.

    JSON SPDX is parsed by hand (below) — covers the slice GitHub's
    dependency-graph SBOM export produces (see
    sbom_scorer.data_sources.github_sbom): SPDX ``packages[]`` with a purl
    in ``externalRefs`` (referenceType "purl"). Tag-value SPDX (not valid
    JSON) is parsed via spdx-tools' tagvalue_parser instead — genuinely
    impractical to hand-roll safely (colon-delimited key:value lines with
    continuation rules) — and handed to _build_from_spdx_document, which
    applies the identical field-mapping logic to spdx-tools' typed
    ``Document`` model so both encodings produce equivalent Components for
    the same logical SBOM. Component name/version/ecosystem are taken from
    the purl when present, falling back to SPDX ``name``/``versionInfo``
    either way.

    One graph node is added per package, keyed by the same id as
    Component.bom_ref (SPDXID, falling back to purl or "name@version").
    ``relationships[]`` entries of type ``DEPENDS_ON`` become edges:
    SPDX's ``spdxElementId DEPENDS_ON relatedSpdxElement`` already matches
    this module's "A -> B means A depends on B" convention directly, so
    the edge is added as-is (DIMENSIONS.md #4, Centrality). Other
    relationship types (CONTAINS, DESCRIBES, etc.) are out of scope.
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        from spdx_tools.spdx.parser.tagvalue import tagvalue_parser

        document = tagvalue_parser.parse_from_file(path)
        return _build_from_spdx_document(document)

    packages = data.get("packages") or []
    components: list[Component] = []
    graph = nx.DiGraph()
    for pkg in packages:
        purl = None
        for ref in pkg.get("externalRefs") or []:
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
                break

        name = pkg.get("name") or ""
        version = pkg.get("versionInfo")
        ecosystem = ""
        if purl:
            parsed = _parse_purl(purl)
            if parsed:
                p_ecosystem, p_name, p_version = parsed
                ecosystem = p_ecosystem or ecosystem
                name = p_name or name
                version = p_version or version

        if not name:
            continue

        node_id = str(pkg.get("SPDXID") or purl or f"{name}@{version}")
        component = Component(
            name=name,
            version=version or "",
            ecosystem=ecosystem,
            purl=purl,
            cve_ids=None,
            exposure_tier=None,
            vcs_url=None,
            bom_ref=node_id,
        )
        components.append(component)
        graph.add_node(node_id)

    for relationship in data.get("relationships") or []:
        if relationship.get("relationshipType") != "DEPENDS_ON":
            continue
        source = relationship.get("spdxElementId")
        target = relationship.get("relatedSpdxElement")
        if not source or not target:
            continue
        graph.add_node(str(source))
        graph.add_node(str(target))
        graph.add_edge(str(source), str(target))

    return components, graph


def _build_from_spdx_document(document: Any) -> tuple[list[Component], nx.DiGraph]:
    """Walk an already-parsed spdx-tools Document into components + a graph.

    Used for the tag-value SPDX path (_parse_spdx) — applies the same
    purl-first field mapping and DEPENDS_ON-edge logic as the hand-parsed
    JSON path above, just reading spdx-tools' typed model
    (document.packages / document.relationships) instead of raw dicts.
    """
    from spdx_tools.spdx.model import RelationshipType

    components: list[Component] = []
    graph = nx.DiGraph()
    for pkg in document.packages or []:
        purl = None
        for ref in pkg.external_references or []:
            if ref.reference_type == "purl":
                purl = ref.locator
                break

        name = pkg.name or ""
        version = pkg.version
        ecosystem = ""
        if purl:
            parsed = _parse_purl(purl)
            if parsed:
                p_ecosystem, p_name, p_version = parsed
                ecosystem = p_ecosystem or ecosystem
                name = p_name or name
                version = p_version or version

        if not name:
            continue

        node_id = str(pkg.spdx_id or purl or f"{name}@{version}")
        component = Component(
            name=name,
            version=version or "",
            ecosystem=ecosystem,
            purl=purl,
            cve_ids=None,
            exposure_tier=None,
            vcs_url=None,
            bom_ref=node_id,
        )
        components.append(component)
        graph.add_node(node_id)

    for relationship in document.relationships or []:
        if relationship.relationship_type != RelationshipType.DEPENDS_ON:
            continue
        source = relationship.spdx_element_id
        target = relationship.related_spdx_element_id
        if not source or not target:
            continue
        graph.add_node(str(source))
        graph.add_node(str(target))
        graph.add_edge(str(source), str(target))

    return components, graph
