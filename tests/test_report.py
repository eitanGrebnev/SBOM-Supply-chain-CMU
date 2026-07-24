"""Tests for sbom_scorer.output.report — console/JSON/CSV report generation.

Covers the functions sbom_scorer.cli._emit_output actually calls
(render_console, write_json, write_csv) plus explain_finding.
"""

import csv
import json

import pytest

from sbom_scorer import composite
from sbom_scorer.composite import DimensionScore, Finding
from sbom_scorer.output import report

WEIGHTS = dict(composite.DEFAULT_WEIGHTS)


def _finding(name, version, cve_id, vex_status=None, **scores) -> Finding:
    f = Finding(component_name=name, component_version=version, cve_id=cve_id)
    for dim, value in scores.items():
        setattr(f, dim, DimensionScore(score=value, confidence="high"))
    f.vex_status = vex_status
    composite.score_finding(f, WEIGHTS)
    return f


@pytest.fixture
def findings():
    # High tier: exploit=9(.20) + exposure=10(.20) + reach default 5(.25)
    # + centrality default 0(.15) + patch 6(.10) + maint 4(.10) = 60.5 -> High
    high = _finding(
        "requests", "2.19.0", "CVE-2023-0001",
        exploitability=9, exposure=10, patch_latency=6, maintainer_health=4,
    )
    # All tens -> 100 -> Critical
    critical = _finding(
        "flask", "0.5", "CVE-2023-0002",
        reachability=10, exploitability=10, exposure=10,
        centrality=10, patch_latency=10, maintainer_health=10,
    )
    # VEX-suppressed -> Informational
    suppressed = _finding(
        "django", "4.0", "CVE-2023-0003",
        vex_status="not_affected",
        reachability=10, exploitability=10, exposure=10,
        centrality=10, patch_latency=10, maintainer_health=10,
    )
    return [high, critical, suppressed]


def test_render_console_empty():
    assert "No findings" in report.render_console([])


def test_render_console_contains_identifying_fields(findings):
    out = report.render_console(findings)
    assert "requests@2.19.0" in out
    assert "CVE-2023-0001" in out
    assert "High" in out
    assert "Critical" in out
    assert "Informational" in out


def test_render_console_sorted_highest_first(findings):
    out = report.render_console(findings)
    # Critical (100) must appear before High (60.5) must appear before
    # Informational (0, VEX-suppressed).
    assert out.index("flask@0.5") < out.index("requests@2.19.0") < out.index("django@4.0")


def test_render_console_shows_vex_suppression(findings):
    out = report.render_console(findings)
    assert "VEX: not_affected" in out


def test_explain_finding_mentions_top_dimensions(findings):
    high = findings[0]
    explanation = report.explain_finding(high)
    assert high.tier in explanation
    # exploitability=9 and exposure=10 are the two highest raw scores.
    assert "Exposure=10" in explanation
    assert "Exploitability=9" in explanation


def test_explain_finding_all_tens_has_no_despite_clause(findings):
    # When every dimension ties at 10, there's no meaningful "despite X" —
    # the lowest-scoring dimension is also one of the top dimensions.
    critical = findings[1]
    explanation = report.explain_finding(critical)
    assert "despite" not in explanation


def test_write_json_structure(tmp_path, findings):
    out_path = tmp_path / "findings.json"
    report.write_json(findings, str(out_path))

    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert data["summary"]["Critical"] == 1
    assert data["summary"]["High"] == 1
    assert data["summary"]["Informational"] == 1
    assert data["summary"]["Medium"] == 0
    assert data["summary"]["Low"] == 0

    # Sorted by composite descending: flask (100) first.
    assert data["findings"][0]["cve_id"] == "CVE-2023-0002"
    assert data["findings"][0]["component_name"] == "flask"
    assert data["findings"][1]["cve_id"] == "CVE-2023-0001"
    assert data["findings"][1]["dimension_scores"]["exposure"] == 10.0
    assert data["findings"][1]["dimension_scores"]["reachability"] == 5.0  # missing-data default


def test_write_csv_structure(tmp_path, findings):
    out_path = tmp_path / "findings.csv"
    report.write_csv(findings, str(out_path))

    with open(out_path, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 3
    assert rows[0]["cve_id"] == "CVE-2023-0002"  # highest composite first
    assert rows[1]["component_name"] == "requests"
    assert rows[1]["exposure"] == "10.0"
    assert rows[2]["tier"] == "Informational"
