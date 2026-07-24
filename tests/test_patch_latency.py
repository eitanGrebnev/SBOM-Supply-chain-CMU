from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from sbom_scorer.data_sources import osv_client, registry_client
from sbom_scorer.dimensions.patch_latency import (
    _score_fix_exists,
    _score_no_fix_exists,
    score_patch_latency,
)


def _iso_z(dt: datetime) -> str:
    """Format a UTC datetime the way OSV's `published` field does (Z suffix)."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.mark.parametrize(
    ("days", "expected"),
    [(0, 0.0), (30, 5.0), (60, 10.0), (90, 10.0)],
)
def test_fix_exists_score_is_linear_and_capped(days, expected):
    assert _score_fix_exists(days) == expected


@pytest.mark.parametrize(
    ("days", "expected"),
    [(0, 0.0), (30, 5.0), (60, 10.0), (90, 10.0)],
)
def test_no_fix_score_is_linear_and_capped(days, expected):
    assert _score_no_fix_exists(days) == expected


def test_fixed_version_uses_registry_release_date(monkeypatch):
    component = SimpleNamespace(name="demo", ecosystem="PyPI", version="1.0")
    monkeypatch.setattr(
        osv_client,
        "query_by_package",
        lambda *_: {
            "vulns": [
                {
                    "id": "CVE-2026-0001",
                    "published": "2020-01-01T00:00:00Z",
                    "affected": [
                        {"ranges": [{"events": [{"fixed": "1.1"}]}]}
                    ],
                }
            ]
        },
    )
    monkeypatch.setattr(
        registry_client,
        "get_release_date",
        lambda ecosystem, name, version: datetime(2020, 2, 1, tzinfo=timezone.utc),
    )

    result = score_patch_latency(component, "CVE-2026-0001")

    assert result.score == 10.0
    assert result.confidence == "high"


def test_missing_osv_record_is_indeterminate(monkeypatch):
    component = SimpleNamespace(name="demo", ecosystem="PyPI", version="1.0")
    monkeypatch.setattr(osv_client, "query_by_package", lambda *_: {"vulns": []})

    result = score_patch_latency(component, "CVE-2026-0001")

    assert result.score == 0.0
    assert result.confidence == "indeterminate"


def test_no_published_date_is_indeterminate(monkeypatch):
    # OSV record matches the CVE but has no "published" field at all —
    # there's no disclosure-date anchor to measure latency from either way.
    component = SimpleNamespace(name="demo", ecosystem="PyPI", version="1.0")
    monkeypatch.setattr(
        osv_client,
        "query_by_package",
        lambda *_: {"vulns": [{"id": "CVE-2026-0001", "affected": []}]},
    )

    result = score_patch_latency(component, "CVE-2026-0001")

    assert result.score == 0.0
    assert result.confidence == "indeterminate"


def test_matches_vuln_via_aliases_not_just_id(monkeypatch):
    # OSV's own id is a GHSA advisory; the CVE we're scoring only shows up
    # in its aliases[] — same matching path _discover_cves relies on.
    component = SimpleNamespace(name="demo", ecosystem="PyPI", version="1.0")
    disclosed = datetime.now(timezone.utc) - timedelta(days=90)
    monkeypatch.setattr(
        osv_client,
        "query_by_package",
        lambda *_: {
            "vulns": [
                {
                    "id": "GHSA-xxxx-yyyy-zzzz",
                    "aliases": ["CVE-2026-0001"],
                    "published": _iso_z(disclosed),
                    "affected": [],
                }
            ]
        },
    )

    result = score_patch_latency(component, "CVE-2026-0001")

    # No fix event anywhere -> unpatchable-exposure branch, capped at 10
    # since 90 days since disclosure exceeds the 60-day ramp.
    assert result.score == 10.0
    assert result.confidence == "high"


def test_no_fix_exists_scores_from_disclosure_date(monkeypatch):
    # OSV has the record and a disclosure date, but no "fixed" event in any
    # range -> "unpatchable exposure" sub-case (DIMENSIONS.md #5), scored
    # off time-since-disclosure rather than time-since-fix.
    component = SimpleNamespace(name="demo", ecosystem="PyPI", version="1.0")
    disclosed = datetime.now(timezone.utc) - timedelta(days=30)
    monkeypatch.setattr(
        osv_client,
        "query_by_package",
        lambda *_: {
            "vulns": [
                {
                    "id": "CVE-2026-0001",
                    "published": _iso_z(disclosed),
                    "affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}],
                }
            ]
        },
    )

    result = score_patch_latency(component, "CVE-2026-0001")

    assert result.score == pytest.approx(5.0, abs=0.2)  # ~30/60 days -> ~5.0
    assert result.confidence == "high"


def test_fixed_version_without_registry_release_date_falls_back_to_disclosure(monkeypatch):
    # A fix version is identified, but the registry can't resolve its
    # release timestamp (e.g. yanked release, registry lookup failure) —
    # falls back to scoring off disclosure date instead of silently
    # defaulting, since a fix event existing at all is still meaningful
    # signal that the disclosure-date clock applies (DIMENSIONS.md #5).
    component = SimpleNamespace(name="demo", ecosystem="PyPI", version="1.0")
    disclosed = datetime.now(timezone.utc) - timedelta(days=90)
    monkeypatch.setattr(
        osv_client,
        "query_by_package",
        lambda *_: {
            "vulns": [
                {
                    "id": "CVE-2026-0001",
                    "published": _iso_z(disclosed),
                    "affected": [{"ranges": [{"events": [{"fixed": "1.1"}]}]}],
                }
            ]
        },
    )
    monkeypatch.setattr(registry_client, "get_release_date", lambda *a, **k: None)

    result = score_patch_latency(component, "CVE-2026-0001")

    assert result.score == 10.0
    assert result.confidence == "high"


def test_recent_disclosure_with_no_fix_scores_near_zero(monkeypatch):
    component = SimpleNamespace(name="demo", ecosystem="PyPI", version="1.0")
    monkeypatch.setattr(
        osv_client,
        "query_by_package",
        lambda *_: {
            "vulns": [
                {
                    "id": "CVE-2026-0001",
                    "published": _iso_z(datetime.now(timezone.utc)),
                    "affected": [],
                }
            ]
        },
    )

    result = score_patch_latency(component, "CVE-2026-0001")

    assert result.score == pytest.approx(0.0, abs=0.2)
    assert result.confidence == "high"