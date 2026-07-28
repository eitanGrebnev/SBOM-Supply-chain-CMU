"""End-to-end CLI pipeline test with mocked network calls.

Parses a real (hand-built) CycloneDX SBOM, but stubs every network-touching
dimension so the test is deterministic and offline. Exercises the full
wiring: parse -> discover CVEs -> score dimensions -> VEX gate -> composite
-> report.
"""

import json
from types import SimpleNamespace

import pytest

from sbom_scorer import cli
from sbom_scorer.composite import DimensionScore
from sbom_scorer.dimensions import exploitability, maintainer_health, patch_latency
from sbom_scorer.data_sources import osv_client


def _cyclonedx_with_requests(tmp_path):
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "myApp",
                "bom-ref": "myApp",
                "properties": [{"name": "exposure:tier", "value": "internet_facing"}],
            }
        },
        "components": [
            {
                "type": "library",
                "name": "requests",
                "version": "2.19.0",
                "bom-ref": "pkg:pypi/requests@2.19.0",
                "purl": "pkg:pypi/requests@2.19.0",
            }
        ],
    }
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps(sbom), encoding="utf-8")
    return str(path)


@pytest.fixture
def mocked_network(monkeypatch):
    monkeypatch.setattr(
        osv_client,
        "query_by_package",
        lambda name, ecosystem, version: {
            "vulns": [{"id": "GHSA-xxxx", "aliases": ["CVE-2023-0001"]}]
        },
    )
    # The CVE-discovery batch prefilter (cli._batch_prefilter_candidates)
    # runs before query_by_package now — needs its own mock so it reports a
    # hit for every queried component, matching query_by_package's mock
    # above, or the prefilter would filter every component out before
    # query_by_package ever gets called.
    monkeypatch.setattr(
        osv_client,
        "query_batch",
        lambda queries: [{"vulns": [{"id": "GHSA-xxxx", "modified": "2024-01-01T00:00:00Z"}]}] * len(queries),
    )

    def fake_exploitabilities(cve_ids, *a, **k):
        return {
            cve: SimpleNamespace(dimension_score=DimensionScore(9.0, "high"))
            for cve in cve_ids
        }

    monkeypatch.setattr(exploitability, "score_exploitabilities", fake_exploitabilities)
    monkeypatch.setattr(
        patch_latency, "score_patch_latency", lambda component, cve_id: DimensionScore(6.0, "high")
    )
    monkeypatch.setattr(
        maintainer_health, "score_maintainer_health", lambda component: DimensionScore(4.0, "high")
    )


def test_run_pipeline_console(tmp_path, capsys, mocked_network):
    sbom_path = _cyclonedx_with_requests(tmp_path)
    parser = cli.build_arg_parser()
    args = parser.parse_args([sbom_path, "--output-dir", str(tmp_path / "out")])

    rc = cli.run(args)
    assert rc == 0

    out = capsys.readouterr().out
    assert "requests@2.19.0" in out
    assert "CVE-2023-0001" in out
    # exploit=9(.20) + exposure=10(.20) + reach default 5(.25) + centrality 0
    # + patch 6(.10) + maint 4(.10) = 1.8+2.0+1.25+0+0.6+0.4 = 6.05 -> 60.5 -> High
    assert "High" in out


def test_run_pipeline_json_output(tmp_path, mocked_network):
    sbom_path = _cyclonedx_with_requests(tmp_path)
    out_dir = tmp_path / "out"
    parser = cli.build_arg_parser()
    args = parser.parse_args([sbom_path, "--format", "json", "--output-dir", str(out_dir)])

    rc = cli.run(args)
    assert rc == 0

    data = json.loads((out_dir / "findings.json").read_text(encoding="utf-8"))
    assert data["summary"]["High"] == 1
    assert data["findings"][0]["cve_id"] == "CVE-2023-0001"
    assert data["findings"][0]["dimension_scores"]["exposure"] == 10.0


def test_run_requires_input(tmp_path):
    parser = cli.build_arg_parser()
    args = parser.parse_args([])
    assert cli.run(args) == 2


def test_run_rejects_both_inputs(tmp_path):
    parser = cli.build_arg_parser()
    args = parser.parse_args(["some.json", "--repo", "psf/requests"])
    assert cli.run(args) == 2


# --- Progress reporting ------------------------------------------------------
#
# The web UI's progress bar reads this file off the shared scans volume, because
# the scan runs in a separate pod whose container logs are garbage collected the
# moment it finishes. The file is the only durable channel between the two.


def _reporter(tmp_path, monkeypatch):
    monkeypatch.setenv("SBOM_SCORER_PROGRESS_FILE", str(tmp_path / "progress.json"))
    return cli._ProgressReporter()


def test_progress_reporter_is_disabled_without_env(monkeypatch):
    """A plain local CLI run must not create stray files."""
    monkeypatch.delenv("SBOM_SCORER_PROGRESS_FILE", raising=False)
    reporter = cli._ProgressReporter()
    assert reporter.enabled is False
    # Must be safely callable regardless, since _log() always calls it.
    reporter.log("hello")
    reporter.start_phase("Scoring", 3)
    reporter.advance()


def test_progress_reporter_writes_phase_and_counts(tmp_path, monkeypatch):
    reporter = _reporter(tmp_path, monkeypatch)
    reporter.start_phase("Discovering CVEs", 2)
    reporter.advance()
    # The last item forces a write, so the bar can always reach 100% even
    # though intermediate writes are rate limited.
    reporter.advance()

    data = json.loads((tmp_path / "progress.json").read_text(encoding="utf-8"))
    assert data["phase"] == "Discovering CVEs"
    assert data["completed"] == 2
    assert data["total"] == 2


def test_progress_reporter_keeps_only_recent_log_lines(tmp_path, monkeypatch):
    """A scan warning once per component must not grow the file unbounded."""
    reporter = _reporter(tmp_path, monkeypatch)
    for i in range(cli._PROGRESS_LOG_LINES + 25):
        reporter.log(f"line {i}")

    data = json.loads((tmp_path / "progress.json").read_text(encoding="utf-8"))
    assert len(data["lines"]) == cli._PROGRESS_LOG_LINES
    assert data["lines"][-1] == f"line {cli._PROGRESS_LOG_LINES + 24}"


def test_progress_reporter_survives_unwritable_path(tmp_path, monkeypatch):
    """Progress is cosmetic; a full volume must not fail the scan."""
    monkeypatch.setenv(
        "SBOM_SCORER_PROGRESS_FILE", str(tmp_path / "no-such-dir" / "progress.json")
    )
    reporter = cli._ProgressReporter()
    reporter.start_phase("Scoring findings", 1)
    reporter.advance()


def test_progress_wraps_iterable_and_counts(tmp_path, monkeypatch):
    """_progress must still yield every item once counting is enabled."""
    monkeypatch.setenv("SBOM_SCORER_PROGRESS_FILE", str(tmp_path / "progress.json"))
    monkeypatch.setattr(cli, "_PROGRESS", cli._ProgressReporter())

    assert list(cli._progress(iter([1, 2, 3]), desc="Scoring", total=3)) == [1, 2, 3]

    data = json.loads((tmp_path / "progress.json").read_text(encoding="utf-8"))
    assert data["completed"] == 3
