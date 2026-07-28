"""Tests for sbom_scorer.cli._batch_prefilter_candidates.

This runs before the (slower) per-component _discover_cves call in
_gather_findings — it's a pure filtering step over components, so tested
directly here rather than only indirectly through a full cli.run().
"""

from unittest.mock import Mock

from sbom_scorer import cli
from sbom_scorer.data_sources import osv_client
from sbom_scorer.sbom_parser import Component


def _component(name, *, ecosystem="PyPI", version="1.0.0", cve_ids=None):
    return Component(name=name, version=version, ecosystem=ecosystem, cve_ids=cve_ids)


def test_empty_components_returns_empty_without_network_call(monkeypatch):
    batch = Mock()
    monkeypatch.setattr(osv_client, "query_batch", batch)
    assert cli._batch_prefilter_candidates([]) == []
    batch.assert_not_called()


def test_components_with_embedded_cve_ids_skip_the_batch_call(monkeypatch):
    with_cves = _component("has-cves", cve_ids=["CVE-2023-0001"])
    batch = Mock(return_value=[])
    monkeypatch.setattr(osv_client, "query_batch", batch)

    result = cli._batch_prefilter_candidates([with_cves])

    assert result == [with_cves]
    batch.assert_not_called()


def test_components_missing_ecosystem_or_version_skip_the_batch_call(monkeypatch):
    no_ecosystem = _component("a", ecosystem="")
    no_version = _component("b", version="")
    batch = Mock(return_value=[])
    monkeypatch.setattr(osv_client, "query_batch", batch)

    result = cli._batch_prefilter_candidates([no_ecosystem, no_version])

    assert result == [no_ecosystem, no_version]
    batch.assert_not_called()


def test_component_with_unknown_ecosystem_skips_the_batch_call(monkeypatch):
    # OSV rejects the *whole* querybatch if any single entry names an
    # ecosystem it doesn't know, so unmapped purl types (conan, github, ...)
    # must never reach it — one exotic dependency would otherwise cost every
    # other component its prefilter.
    unknown = _component("zlib", ecosystem="conan")
    known = _component("requests")
    captured = {}

    def fake_batch(queries):
        captured["queries"] = queries
        return [{"vulns": []}]

    monkeypatch.setattr(osv_client, "query_batch", fake_batch)

    result = cli._batch_prefilter_candidates([unknown, known])

    assert captured["queries"] == [
        {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "1.0.0"}
    ]
    # Unbatchable, so it falls through to a per-component query rather than
    # being silently treated as clean.
    assert result == [unknown]


def test_only_queryable_components_are_sent_to_batch(monkeypatch):
    embedded = _component("has-cves", cve_ids=["CVE-2023-0001"])
    queryable = _component("check-me")
    captured = {}

    def fake_batch(queries):
        captured["queries"] = queries
        return [{"vulns": []}]

    monkeypatch.setattr(osv_client, "query_batch", fake_batch)

    cli._batch_prefilter_candidates([embedded, queryable])

    assert captured["queries"] == [
        {"package": {"name": "check-me", "ecosystem": "PyPI"}, "version": "1.0.0"}
    ]


def test_component_with_batch_hit_is_kept(monkeypatch):
    hit = _component("vulnerable-pkg")
    monkeypatch.setattr(osv_client, "query_batch", lambda queries: [{"vulns": [{"id": "GHSA-x"}]}])
    assert cli._batch_prefilter_candidates([hit]) == [hit]


def test_component_with_no_batch_hit_is_dropped(monkeypatch):
    clean = _component("clean-pkg")
    monkeypatch.setattr(osv_client, "query_batch", lambda queries: [{"vulns": []}])
    assert cli._batch_prefilter_candidates([clean]) == []


def test_mixed_hits_and_misses(monkeypatch):
    vulnerable = _component("vulnerable-pkg")
    clean = _component("clean-pkg")

    def fake_batch(queries):
        return [
            {"vulns": [{"id": "GHSA-x"}]} if q["package"]["name"] == "vulnerable-pkg" else {"vulns": []}
            for q in queries
        ]

    monkeypatch.setattr(osv_client, "query_batch", fake_batch)

    result = cli._batch_prefilter_candidates([vulnerable, clean])

    assert result == [vulnerable]


def test_batch_failure_fails_open_to_every_queryable_component(monkeypatch):
    a = _component("a")
    b = _component("b")
    monkeypatch.setattr(
        osv_client, "query_batch", Mock(side_effect=ConnectionError("boom"))
    )

    result = cli._batch_prefilter_candidates([a, b])

    # Nothing is silently dropped just because the batch call itself failed.
    assert result == [a, b]


def test_batch_failure_still_includes_free_candidates(monkeypatch):
    embedded = _component("has-cves", cve_ids=["CVE-2023-0001"])
    queryable = _component("check-me")
    monkeypatch.setattr(
        osv_client, "query_batch", Mock(side_effect=ConnectionError("boom"))
    )

    result = cli._batch_prefilter_candidates([embedded, queryable])

    assert result == [embedded, queryable]
