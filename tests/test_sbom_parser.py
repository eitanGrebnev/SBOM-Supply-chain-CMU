import json

import pytest

from sbom_scorer.sbom_parser import _detect_format, _parse_cyclonedx, parse_sbom

# --- fixtures ----------------------------------------------------------------


def _cyclonedx_sbom(
    *,
    exposure_property=None,
    components=None,
    include_metadata=True,
    dependencies=None,
    vulnerabilities=None,
):
    """Build a minimal CycloneDX 1.6 JSON dict for tests.

    Mirrors the shape from cyclonedx-python-lib's own deserialize example
    (metadata.component + components[] + optional properties[]/
    externalReferences[]/dependencies[]/vulnerabilities[]) rather than
    inventing a fixture format.
    """
    metadata_component = {
        "type": "application",
        "name": "myApp",
        "bom-ref": "myApp",
    }
    if exposure_property is not None:
        metadata_component["properties"] = [exposure_property]

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": components if components is not None else [],
    }
    if include_metadata:
        sbom["metadata"] = {"component": metadata_component}
    if dependencies is not None:
        sbom["dependencies"] = dependencies
    if vulnerabilities is not None:
        sbom["vulnerabilities"] = vulnerabilities
    return sbom


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


_REQUESTS_COMPONENT = {
    "type": "library",
    "name": "requests",
    "version": "2.31.0",
    "bom-ref": "pkg:pypi/requests@2.31.0",
    "purl": "pkg:pypi/requests@2.31.0",
    "externalReferences": [{"type": "vcs", "url": "https://github.com/psf/requests"}],
}
_LEFTPAD_COMPONENT = {
    "type": "library",
    "name": "left-pad",
    "version": "1.0.0",
    "bom-ref": "pkg:npm/left-pad@1.0.0",
    "purl": "pkg:npm/left-pad@1.0.0",
}


# --- _detect_format ------------------------------------------------------


def test_detect_format_cyclonedx_json(tmp_path):
    path = _write(tmp_path, "sbom.json", _cyclonedx_sbom())
    assert _detect_format(path) == "cyclonedx"


def test_detect_format_spdx_json(tmp_path):
    path = tmp_path / "sbom.spdx.json"
    path.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": []}), encoding="utf-8")
    assert _detect_format(str(path)) == "spdx"


def test_detect_format_spdx_tag_value(tmp_path):
    path = tmp_path / "sbom.spdx"
    path.write_text("SPDXVersion: SPDX-2.3\nSPDXID: SPDXRef-DOCUMENT\n", encoding="utf-8")
    assert _detect_format(str(path)) == "spdx"


def test_detect_format_cyclonedx_xml(tmp_path):
    path = tmp_path / "sbom.xml"
    path.write_text(
        '<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6"></bom>',
        encoding="utf-8",
    )
    assert _detect_format(str(path)) == "cyclonedx"


def test_detect_format_unrecognized_raises(tmp_path):
    path = tmp_path / "sbom.txt"
    path.write_text("this is not an SBOM", encoding="utf-8")
    with pytest.raises(ValueError):
        _detect_format(str(path))


# --- parse_sbom / _parse_cyclonedx: components -----------------------------


def test_parses_component_fields(tmp_path):
    sbom = _cyclonedx_sbom(components=[_REQUESTS_COMPONENT])
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)

    assert len(components) == 1
    c = components[0]
    assert c.name == "requests"
    assert c.version == "2.31.0"
    assert c.ecosystem == "PyPI"
    assert c.purl == "pkg:pypi/requests@2.31.0"


@pytest.mark.parametrize(
    "purl,expected_ecosystem",
    [
        ("pkg:pypi/requests@1.0.0", "PyPI"),
        ("pkg:npm/left-pad@1.0.0", "npm"),
        ("pkg:maven/org.apache/commons@1.0.0", "Maven"),
        ("pkg:gem/rails@1.0.0", "RubyGems"),
        ("pkg:cargo/serde@1.0.0", "crates.io"),
        ("pkg:golang/example.com/foo@1.0.0", "Go"),
        ("pkg:nuget/Newtonsoft.Json@13.0.0", "NuGet"),
        ("pkg:composer/monolog/monolog@2.0.0", "Packagist"),
        # GitHub's dependency graph emits this for every workflow `uses:`
        # line, so it shows up in almost any repo-mode scan.
        ("pkg:githubactions/actions/checkout@v4", "GitHub Actions"),
        ("pkg:conan/zlib@1.0.0", "conan"),  # still unmapped -> purl type as-is
    ],
)
def test_ecosystem_derived_from_purl_type(tmp_path, purl, expected_ecosystem):
    component = {"type": "library", "name": "x", "version": "1.0.0", "purl": purl}
    sbom = _cyclonedx_sbom(components=[component])
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].ecosystem == expected_ecosystem


def test_github_actions_component_keeps_owner_repo_name(tmp_path):
    """OSV identifies an Action by its full "owner/repo", not the bare repo.

    The purl namespace ("actions") is the owner, so it must survive into
    Component.name — dropping it would turn every Action lookup into a
    silent miss that reads the same as "no known vulnerabilities".
    """
    component = {
        "type": "library",
        "name": "checkout",
        "version": "v4",
        "purl": "pkg:githubactions/actions/checkout@v4",
    }
    sbom = _cyclonedx_sbom(components=[component])
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].name == "actions/checkout"
    assert components[0].ecosystem == "GitHub Actions"


# --- Maven/npm namespaced package names -------------------------------------
#
# OSV and the package registries need the *combined* groupId:artifactId (Maven)
# or @scope/name (npm) identity, not just CycloneDX's `name` field, which for
# these two ecosystems is only the artifactId/unscoped name. Getting this
# wrong doesn't error — every OSV/registry lookup just silently finds
# nothing, indistinguishable from "no known vulnerabilities" (this is exactly
# what happened scanning the real sample_sbom.json before this was fixed:
# zero CVEs found across 218 real Maven components, including log4j-api
# 2.14.1 — Log4Shell).


def test_maven_component_name_includes_group(tmp_path):
    component = {
        "type": "library",
        "group": "org.apache.logging.log4j",
        "name": "log4j-api",
        "version": "2.14.1",
        "purl": "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1?type=jar",
    }
    sbom = _cyclonedx_sbom(components=[component])
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].name == "org.apache.logging.log4j:log4j-api"
    assert components[0].ecosystem == "Maven"


def test_npm_scoped_component_name_includes_scope(tmp_path):
    component = {
        "type": "library",
        "group": "@babel",
        "name": "core",
        "version": "7.0.0",
        "purl": "pkg:npm/%40babel/core@7.0.0",
    }
    sbom = _cyclonedx_sbom(components=[component])
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].name == "@babel/core"


def test_unscoped_npm_component_name_unaffected(tmp_path):
    # left-pad has no namespace segment in its purl -> nothing to prepend,
    # falls back to the plain declared name exactly as before this fix.
    sbom = _cyclonedx_sbom(components=[_LEFTPAD_COMPONENT])
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].name == "left-pad"


def test_maven_component_without_purl_namespace_falls_back_to_declared_name(tmp_path):
    # No purl at all -> nothing to derive a namespace from; same fallback
    # behavior as any other component with no purl.
    component = {"type": "library", "name": "log4j-api", "version": "2.14.1"}
    sbom = _cyclonedx_sbom(components=[component])
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].name == "log4j-api"


def test_pypi_component_name_unaffected_by_namespace_logic(tmp_path):
    # PyPI isn't in _NAMESPACED_ECOSYSTEM_JOINERS -> always uses the
    # declared name, regardless of what the purl says.
    sbom = _cyclonedx_sbom(components=[_REQUESTS_COMPONENT])
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].name == "requests"


def test_component_without_purl_has_empty_ecosystem_and_no_purl(tmp_path):
    component = {"type": "library", "name": "no-purl", "version": "1.0.0"}
    sbom = _cyclonedx_sbom(components=[component])
    path = _write(tmp_path, "sbom.json", sbom)
    components, graph = parse_sbom(path)

    assert components[0].purl is None
    assert components[0].ecosystem == ""
    # Falls back to name@version for the graph node id when there's no
    # bom-ref value and no purl to key off of.
    assert "no-purl@1.0.0" in graph.nodes


# --- vcs_url -----------------------------------------------------------------


def test_vcs_url_extracted_from_scm_external_reference(tmp_path):
    sbom = _cyclonedx_sbom(components=[_REQUESTS_COMPONENT])
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].vcs_url == "https://github.com/psf/requests"


def test_vcs_url_none_when_no_scm_reference(tmp_path):
    component = dict(_REQUESTS_COMPONENT)
    component.pop("externalReferences")
    sbom = _cyclonedx_sbom(components=[component])
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].vcs_url is None


def test_vcs_url_ignores_non_scm_references(tmp_path):
    component = dict(_REQUESTS_COMPONENT)
    component["externalReferences"] = [{"type": "website", "url": "https://requests.readthedocs.io"}]
    sbom = _cyclonedx_sbom(components=[component])
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].vcs_url is None


# --- exposure_tier: SBOM-wide, from metadata.component.properties[] --------


def test_exposure_tier_applied_to_all_components(tmp_path):
    sbom = _cyclonedx_sbom(
        exposure_property={"name": "exposure:tier", "value": "internet-facing"},
        components=[_REQUESTS_COMPONENT, _LEFTPAD_COMPONENT],
    )
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)

    assert len(components) == 2
    assert all(c.exposure_tier == "internet_facing" for c in components)


def test_exposure_tier_value_is_normalized(tmp_path):
    sbom = _cyclonedx_sbom(
        exposure_property={"name": "exposure:tier", "value": "  Dev-Only  "},
        components=[_REQUESTS_COMPONENT],
    )
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].exposure_tier == "dev_only"


def test_exposure_tier_none_when_no_property(tmp_path):
    sbom = _cyclonedx_sbom(components=[_REQUESTS_COMPONENT])
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].exposure_tier is None


def test_exposure_tier_none_when_no_metadata_component(tmp_path):
    sbom = _cyclonedx_sbom(components=[_REQUESTS_COMPONENT], include_metadata=False)
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].exposure_tier is None


def test_exposure_tier_passed_through_verbatim_when_unrecognized(tmp_path):
    # sbom_parser doesn't validate against the tier vocabulary — that's
    # exposure.score_exposure's job (defaults unrecognized values to
    # worst-case). The parser's contract is just "normalize case/separators
    # and hand it off."
    sbom = _cyclonedx_sbom(
        exposure_property={"name": "exposure:tier", "value": "quantum-superposition"},
        components=[_REQUESTS_COMPONENT],
    )
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].exposure_tier == "quantum_superposition"


def test_per_component_properties_are_not_used_for_exposure_tier(tmp_path):
    # DIMENSIONS.md #3 is explicit: exposure is tagged at the service level
    # (metadata.component), not per dependency component. A stray property
    # on an individual component should be ignored.
    component = dict(_REQUESTS_COMPONENT)
    component["properties"] = [{"name": "exposure:tier", "value": "dev_only"}]
    sbom = _cyclonedx_sbom(components=[component])  # no metadata-level tag
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].exposure_tier is None


# --- dependency graph -------------------------------------------------------


def test_graph_has_one_node_per_component_and_no_edges_when_undeclared(tmp_path):
    # No dependencies[] in the SBOM at all -> nodes only, matching pre-edge
    # behavior for producers that don't emit a dependency graph.
    sbom = _cyclonedx_sbom(components=[_REQUESTS_COMPONENT, _LEFTPAD_COMPONENT])
    path = _write(tmp_path, "sbom.json", sbom)
    _, graph = parse_sbom(path)

    assert set(graph.nodes) == {"pkg:pypi/requests@2.31.0", "pkg:npm/left-pad@1.0.0"}
    assert list(graph.edges) == []


def test_dependencies_become_graph_edges(tmp_path):
    sbom = _cyclonedx_sbom(
        components=[_REQUESTS_COMPONENT, _LEFTPAD_COMPONENT],
        dependencies=[
            {"ref": "myApp", "dependsOn": ["pkg:pypi/requests@2.31.0"]},
            {"ref": "pkg:pypi/requests@2.31.0", "dependsOn": ["pkg:npm/left-pad@1.0.0"]},
            {"ref": "pkg:npm/left-pad@1.0.0", "dependsOn": []},
        ],
    )
    path = _write(tmp_path, "sbom.json", sbom)
    _, graph = parse_sbom(path)

    # The root application component isn't in components[], but a
    # dependencies[] entry referencing it still gets a node so the edge
    # isn't dropped.
    assert set(graph.nodes) == {"myApp", "pkg:pypi/requests@2.31.0", "pkg:npm/left-pad@1.0.0"}
    assert set(graph.edges) == {
        ("myApp", "pkg:pypi/requests@2.31.0"),
        ("pkg:pypi/requests@2.31.0", "pkg:npm/left-pad@1.0.0"),
    }


def test_component_bom_ref_matches_graph_node_id(tmp_path):
    sbom = _cyclonedx_sbom(components=[_REQUESTS_COMPONENT])
    path = _write(tmp_path, "sbom.json", sbom)
    components, graph = parse_sbom(path)

    assert components[0].bom_ref == "pkg:pypi/requests@2.31.0"
    assert components[0].bom_ref in graph.nodes


# --- vulnerabilities[]: embedded CVEs + VEX analysis -------------------------


def test_embedded_cve_id_used_directly(tmp_path):
    sbom = _cyclonedx_sbom(
        components=[_REQUESTS_COMPONENT],
        vulnerabilities=[
            {"id": "CVE-2023-0001", "affects": [{"ref": "pkg:pypi/requests@2.31.0"}]}
        ],
    )
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].cve_ids == ["CVE-2023-0001"]
    assert components[0].vex_statuses is None  # no analysis block -> no VEX status


def test_cve_alias_resolved_from_references_when_id_is_not_cve_shaped(tmp_path):
    sbom = _cyclonedx_sbom(
        components=[_REQUESTS_COMPONENT],
        vulnerabilities=[
            {
                "id": "GHSA-aaaa-bbbb-cccc",
                "references": [{"id": "CVE-2023-0002", "source": {"name": "NVD"}}],
                "affects": [{"ref": "pkg:pypi/requests@2.31.0"}],
            }
        ],
    )
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].cve_ids == ["CVE-2023-0002"]


def test_not_affected_analysis_populates_vex_statuses(tmp_path):
    sbom = _cyclonedx_sbom(
        components=[_REQUESTS_COMPONENT],
        vulnerabilities=[
            {
                "id": "CVE-2023-0001",
                "analysis": {"state": "not_affected", "justification": "code_not_reachable"},
                "affects": [{"ref": "pkg:pypi/requests@2.31.0"}],
            }
        ],
    )
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].vex_statuses == {"CVE-2023-0001": "not_affected"}


@pytest.mark.parametrize(
    "cdx_state,expected_vex_status",
    [
        ("not_affected", "not_affected"),
        ("false_positive", "not_affected"),
        ("exploitable", "affected"),
        ("resolved", "fixed"),
        ("resolved_with_pedigree", "fixed"),
        ("in_triage", "under_investigation"),
    ],
)
def test_analysis_state_mapping(tmp_path, cdx_state, expected_vex_status):
    sbom = _cyclonedx_sbom(
        components=[_REQUESTS_COMPONENT],
        vulnerabilities=[
            {
                "id": "CVE-2023-0001",
                "analysis": {"state": cdx_state},
                "affects": [{"ref": "pkg:pypi/requests@2.31.0"}],
            }
        ],
    )
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].vex_statuses == {"CVE-2023-0001": expected_vex_status}


def test_vulnerability_can_affect_multiple_components(tmp_path):
    sbom = _cyclonedx_sbom(
        components=[_REQUESTS_COMPONENT, _LEFTPAD_COMPONENT],
        vulnerabilities=[
            {
                "id": "CVE-2023-0001",
                "affects": [
                    {"ref": "pkg:pypi/requests@2.31.0"},
                    {"ref": "pkg:npm/left-pad@1.0.0"},
                ],
            }
        ],
    )
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert all(c.cve_ids == ["CVE-2023-0001"] for c in components)


def test_vulnerability_affecting_unknown_ref_does_not_crash(tmp_path):
    sbom = _cyclonedx_sbom(
        components=[_REQUESTS_COMPONENT],
        vulnerabilities=[
            {"id": "CVE-2023-0001", "affects": [{"ref": "pkg:pypi/not-a-real-component@1.0.0"}]}
        ],
    )
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].cve_ids is None


def test_no_vulnerabilities_section_leaves_cve_ids_none(tmp_path):
    sbom = _cyclonedx_sbom(components=[_REQUESTS_COMPONENT])
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].cve_ids is None
    assert components[0].vex_statuses is None


def test_vex_gate_suppresses_finding_from_real_sbom_data(tmp_path):
    # End-to-end proof that embedded VEX data actually reaches
    # sbom_scorer.vex.get_vex_status, not just that sbom_parser stores it.
    from sbom_scorer.vex import apply_vex_gate, get_vex_status

    sbom = _cyclonedx_sbom(
        components=[_REQUESTS_COMPONENT],
        vulnerabilities=[
            {
                "id": "CVE-2023-0001",
                "analysis": {"state": "not_affected"},
                "affects": [{"ref": "pkg:pypi/requests@2.31.0"}],
            }
        ],
    )
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)

    vex_status = get_vex_status(components[0], "CVE-2023-0001")
    assert vex_status is not None
    assert apply_vex_gate(vex_status) is True


# --- format dispatch ---------------------------------------------------------


def test_parse_sbom_spdx_json_parses_packages(tmp_path):
    path = tmp_path / "sbom.spdx.json"
    path.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {
                        "SPDXID": "SPDXRef-Package-requests",
                        "name": "requests",
                        "versionInfo": "2.19.0",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:pypi/requests@2.19.0",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    components, graph = parse_sbom(str(path))
    assert len(components) == 1
    comp = components[0]
    assert comp.name == "requests"
    assert comp.version == "2.19.0"
    assert comp.ecosystem == "PyPI"
    assert list(graph.nodes) == ["SPDXRef-Package-requests"]
    assert list(graph.edges) == []


_SPDX_TAG_VALUE_WITH_REQUESTS = """SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test-doc
DocumentNamespace: https://example.com/test-doc
Creator: Tool: sbom-scorer-tests
Created: 2024-01-01T00:00:00Z

PackageName: requests
SPDXID: SPDXRef-Package-requests
PackageVersion: 2.31.0
PackageDownloadLocation: NOASSERTION
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/requests@2.31.0

PackageName: left-pad
SPDXID: SPDXRef-Package-leftpad
PackageVersion: 1.0.0
PackageDownloadLocation: NOASSERTION
ExternalRef: PACKAGE-MANAGER purl pkg:npm/left-pad@1.0.0

Relationship: SPDXRef-Package-requests DEPENDS_ON SPDXRef-Package-leftpad
"""


def test_parses_spdx_tag_value(tmp_path):
    path = tmp_path / "sbom.spdx"
    path.write_text(_SPDX_TAG_VALUE_WITH_REQUESTS, encoding="utf-8")

    components, graph = parse_sbom(str(path))

    assert len(components) == 2
    requests_component = next(c for c in components if c.name == "requests")
    assert requests_component.version == "2.31.0"
    assert requests_component.ecosystem == "PyPI"
    assert requests_component.bom_ref == "SPDXRef-Package-requests"
    assert ("SPDXRef-Package-requests", "SPDXRef-Package-leftpad") in graph.edges


def test_spdx_tag_value_and_json_produce_equivalent_components(tmp_path):
    tagvalue_path = tmp_path / "sbom.spdx"
    tagvalue_path.write_text(_SPDX_TAG_VALUE_WITH_REQUESTS, encoding="utf-8")

    json_doc = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-requests",
                "name": "requests",
                "versionInfo": "2.31.0",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:pypi/requests@2.31.0",
                    }
                ],
            }
        ],
    }
    json_path = tmp_path / "sbom.spdx.json"
    json_path.write_text(json.dumps(json_doc), encoding="utf-8")

    tagvalue_components, _ = parse_sbom(str(tagvalue_path))
    json_components, _ = parse_sbom(str(json_path))

    tv_requests = next(c for c in tagvalue_components if c.name == "requests")
    json_requests = json_components[0]
    assert tv_requests.name == json_requests.name
    assert tv_requests.version == json_requests.version
    assert tv_requests.ecosystem == json_requests.ecosystem


_CYCLONEDX_XML_WITH_REQUESTS = """<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
  <components>
    <component type="library" bom-ref="pkg:pypi/requests@2.31.0">
      <name>requests</name>
      <version>2.31.0</version>
      <purl>pkg:pypi/requests@2.31.0</purl>
      <externalReferences>
        <reference type="vcs">
          <url>https://github.com/psf/requests</url>
        </reference>
      </externalReferences>
    </component>
  </components>
</bom>
"""


def test_parses_xml_cyclonedx(tmp_path):
    path = tmp_path / "sbom.xml"
    path.write_text(_CYCLONEDX_XML_WITH_REQUESTS, encoding="utf-8")

    components, graph = parse_sbom(str(path))

    assert len(components) == 1
    c = components[0]
    assert c.name == "requests"
    assert c.version == "2.31.0"
    assert c.ecosystem == "PyPI"
    assert c.vcs_url == "https://github.com/psf/requests"
    assert c.bom_ref in graph.nodes


def test_xml_and_json_cyclonedx_produce_equivalent_components(tmp_path):
    # Same logical SBOM, two encodings -> _build_from_cyclonedx_bom should
    # produce the same result either way.
    xml_path = tmp_path / "sbom.xml"
    xml_path.write_text(_CYCLONEDX_XML_WITH_REQUESTS, encoding="utf-8")
    json_sbom = _cyclonedx_sbom(components=[_REQUESTS_COMPONENT])
    json_path = _write(tmp_path, "sbom.json", json_sbom)

    xml_components, _ = parse_sbom(str(xml_path))
    json_components, _ = parse_sbom(json_path)

    assert xml_components[0].name == json_components[0].name
    assert xml_components[0].ecosystem == json_components[0].ecosystem
    assert xml_components[0].vcs_url == json_components[0].vcs_url


def test_detect_format_still_dispatches_content_not_extension(tmp_path):
    # A ".xml"-named file that's actually JSON content still parses via the
    # JSON path — _detect_format sniffs content, not the file extension.
    path = tmp_path / "sbom.xml"
    path.write_text(json.dumps(_cyclonedx_sbom(components=[_REQUESTS_COMPONENT])), encoding="utf-8")
    components, _ = parse_sbom(str(path))
    assert components[0].name == "requests"


def test_parse_cyclonedx_directly_matches_parse_sbom(tmp_path):
    sbom = _cyclonedx_sbom(components=[_REQUESTS_COMPONENT])
    path = _write(tmp_path, "sbom.json", sbom)
    assert _parse_cyclonedx(path)[0][0].name == parse_sbom(path)[0][0].name
