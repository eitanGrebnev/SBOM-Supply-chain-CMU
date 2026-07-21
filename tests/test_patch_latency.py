from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from sbom_scorer.data_sources import osv_client, registry_client
from sbom_scorer.dimensions.patch_latency import (
    _score_fix_exists,
    _score_no_fix_exists,
    score_patch_latency,
)


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