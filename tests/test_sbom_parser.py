import json

import pytest

from sbom_scorer.sbom_parser import _detect_format, _parse_cyclonedx, parse_sbom

# --- fixtures ----------------------------------------------------------------


def _cyclonedx_sbom(*, exposure_property=None, components=None, include_metadata=True):
    """Build a minimal CycloneDX 1.6 JSON dict for tests.

    Mirrors the shape from cyclonedx-python-lib's own deserialize example
    (metadata.component + components[] + optional properties[]/
    externalReferences[]) rather than inventing a fixture format.
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
        ("pkg:golang/example.com/foo@1.0.0", "golang"),  # unmapped -> purl type as-is
    ],
)
def test_ecosystem_derived_from_purl_type(tmp_path, purl, expected_ecosystem):
    component = {"type": "library", "name": "x", "version": "1.0.0", "purl": purl}
    sbom = _cyclonedx_sbom(components=[component])
    path = _write(tmp_path, "sbom.json", sbom)
    components, _ = parse_sbom(path)
    assert components[0].ecosystem == expected_ecosystem


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


# --- dependency graph: nodes only, no edges ---------------------------------


def test_graph_has_one_node_per_component_and_no_edges(tmp_path):
    sbom = _cyclonedx_sbom(components=[_REQUESTS_COMPONENT, _LEFTPAD_COMPONENT])
    path = _write(tmp_path, "sbom.json", sbom)
    _, graph = parse_sbom(path)

    assert set(graph.nodes) == {"pkg:pypi/requests@2.31.0", "pkg:npm/left-pad@1.0.0"}
    assert list(graph.edges) == []


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


def test_parse_sbom_spdx_tag_value_not_implemented(tmp_path):
    path = tmp_path / "sbom.spdx"
    path.write_text("SPDXVersion: SPDX-2.3\nSPDXID: SPDXRef-DOCUMENT\n", encoding="utf-8")
    with pytest.raises(NotImplementedError):
        parse_sbom(str(path))


def test_parse_sbom_raises_not_implemented_for_cyclonedx_xml(tmp_path):
    path = tmp_path / "sbom.xml"
    path.write_text(
        '<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6"></bom>',
        encoding="utf-8",
    )
    with pytest.raises(NotImplementedError):
        parse_sbom(str(path))


def test_parse_cyclonedx_directly_matches_parse_sbom(tmp_path):
    sbom = _cyclonedx_sbom(components=[_REQUESTS_COMPONENT])
    path = _write(tmp_path, "sbom.json", sbom)
    assert _parse_cyclonedx(path)[0][0].name == parse_sbom(path)[0][0].name
