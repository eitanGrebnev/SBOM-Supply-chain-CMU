import json
import subprocess
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest
import requests

from sbom_scorer.data_sources import scorecard_client


def _mock_response(status_code=200, payload=None):
    response = Mock()
    response.status_code = status_code
    if status_code == 404:
        response.raise_for_status.side_effect = None
    else:
        response.raise_for_status.return_value = None
    response.json.return_value = payload or {}
    return response


def test_fetches_and_caches_result(tmp_path, monkeypatch):
    payload = {
        "score": 6.4,
        "checks": [{"name": "Maintained", "score": 10, "reason": "active"}],
    }
    get = Mock(return_value=_mock_response(200, payload))
    monkeypatch.setattr(scorecard_client.requests, "get", get)
    cache_path = tmp_path / "scorecard.json"

    first = scorecard_client.get_scorecard("psf", "requests", cache_path)
    second = scorecard_client.get_scorecard("psf", "requests", cache_path)

    assert first == second == payload
    get.assert_called_once_with(
        f"{scorecard_client.SCORECARD_API_BASE}/github.com/psf/requests", timeout=30
    )


def test_404_is_cached_as_no_data_not_worst_score(tmp_path, monkeypatch):
    get = Mock(return_value=_mock_response(404))
    monkeypatch.setattr(scorecard_client.requests, "get", get)
    cache_path = tmp_path / "scorecard.json"

    result = scorecard_client.get_scorecard("nobody", "unindexed-repo", cache_path)
    cached_result = scorecard_client.get_scorecard("nobody", "unindexed-repo", cache_path)

    assert result is None
    assert cached_result is None
    get.assert_called_once()


def test_stale_cache_triggers_refetch(tmp_path, monkeypatch):
    cache_path = tmp_path / "scorecard.json"
    stale_date = (datetime.now(UTC).date() - timedelta(days=scorecard_client.CACHE_MAX_AGE_DAYS)).isoformat()
    cache_path.write_text(
        json.dumps({"psf/requests": {"fetched_on": stale_date, "data": {"score": 1.0, "checks": []}}}),
        encoding="utf-8",
    )
    fresh_payload = {"score": 9.0, "checks": []}
    get = Mock(return_value=_mock_response(200, fresh_payload))
    monkeypatch.setattr(scorecard_client.requests, "get", get)

    result = scorecard_client.get_scorecard("psf", "requests", cache_path)

    assert result == fresh_payload
    get.assert_called_once()


def test_case_insensitive_cache_key(tmp_path, monkeypatch):
    payload = {"score": 5.0, "checks": []}
    get = Mock(return_value=_mock_response(200, payload))
    monkeypatch.setattr(scorecard_client.requests, "get", get)
    cache_path = tmp_path / "scorecard.json"

    scorecard_client.get_scorecard("PSF", "Requests", cache_path)
    scorecard_client.get_scorecard("psf", "requests", cache_path)

    get.assert_called_once()


def test_non_404_error_response_propagates_and_is_not_swallowed(tmp_path, monkeypatch):
    response = Mock()
    response.status_code = 500
    response.raise_for_status.side_effect = requests.HTTPError("500 server error")
    get = Mock(return_value=response)
    monkeypatch.setattr(scorecard_client.requests, "get", get)
    cache_path = tmp_path / "scorecard.json"

    with pytest.raises(requests.HTTPError):
        scorecard_client.get_scorecard("psf", "requests", cache_path)

    # Nothing should have been cached for a failed fetch.
    assert not cache_path.exists() or scorecard_client._read_cache(cache_path) == {}


def test_malformed_per_entry_cache_is_treated_as_stale_not_crashed(tmp_path, monkeypatch):
    cache_path = tmp_path / "scorecard.json"
    # Hand-corrupted/legacy cache: entry isn't the expected {fetched_on, data} dict.
    cache_path.write_text(
        json.dumps({"psf/requests": "not-a-dict"}), encoding="utf-8"
    )
    fresh_payload = {"score": 9.0, "checks": []}
    get = Mock(return_value=_mock_response(200, fresh_payload))
    monkeypatch.setattr(scorecard_client.requests, "get", get)

    result = scorecard_client.get_scorecard("psf", "requests", cache_path)

    assert result == fresh_payload
    get.assert_called_once()


def test_non_string_fetched_on_is_treated_as_stale_not_crashed(tmp_path, monkeypatch):
    cache_path = tmp_path / "scorecard.json"
    cache_path.write_text(
        json.dumps({"psf/requests": {"fetched_on": 12345, "data": {"score": 1.0}}}),
        encoding="utf-8",
    )
    fresh_payload = {"score": 9.0, "checks": []}
    get = Mock(return_value=_mock_response(200, fresh_payload))
    monkeypatch.setattr(scorecard_client.requests, "get", get)

    result = scorecard_client.get_scorecard("psf", "requests", cache_path)

    assert result == fresh_payload
    get.assert_called_once()


# --- run_scorecard_cli ---------------------------------------------------


def _mock_run(returncode=0, stdout="", stderr=""):
    completed = Mock()
    completed.returncode = returncode
    completed.stdout = stdout
    completed.stderr = stderr
    return completed


def test_run_scorecard_cli_requires_a_token(monkeypatch):
    monkeypatch.delenv("GITHUB_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    with pytest.raises(RuntimeError, match="token"):
        scorecard_client.run_scorecard_cli("psf/requests")


def test_run_scorecard_cli_uses_local_binary_when_available(monkeypatch):
    monkeypatch.setenv("GITHUB_AUTH_TOKEN", "tok")
    monkeypatch.setattr(
        scorecard_client.shutil, "which", lambda name: "/usr/bin/scorecard" if name == "scorecard" else None
    )
    payload = {"score": 7.5, "checks": [{"name": "Maintained", "score": 10}]}
    run = Mock(return_value=_mock_run(0, json.dumps(payload)))
    monkeypatch.setattr(scorecard_client.subprocess, "run", run)

    result = scorecard_client.run_scorecard_cli("psf/requests")

    assert result == payload
    cmd = run.call_args.args[0]
    assert cmd[0] == "/usr/bin/scorecard"
    assert "--repo=github.com/psf/requests" in cmd
    assert "--format=json" in cmd


def test_run_scorecard_cli_falls_back_to_docker_when_no_binary(monkeypatch):
    monkeypatch.setenv("GITHUB_AUTH_TOKEN", "tok")

    def which(name):
        return "/usr/bin/docker" if name == "docker" else None

    monkeypatch.setattr(scorecard_client.shutil, "which", which)
    payload = {"score": 3.0, "checks": []}
    run = Mock(return_value=_mock_run(0, json.dumps(payload)))
    monkeypatch.setattr(scorecard_client.subprocess, "run", run)

    result = scorecard_client.run_scorecard_cli("https://github.com/psf/requests")

    assert result == payload
    cmd = run.call_args.args[0]
    assert cmd[0] == "/usr/bin/docker"
    assert "run" in cmd
    assert scorecard_client.SCORECARD_DOCKER_IMAGE in cmd
    assert "--repo=github.com/psf/requests" in cmd


def test_run_scorecard_cli_raises_when_neither_binary_nor_docker_available(monkeypatch):
    monkeypatch.setenv("GITHUB_AUTH_TOKEN", "tok")
    monkeypatch.setattr(scorecard_client.shutil, "which", lambda name: None)

    with pytest.raises(RuntimeError, match="docker"):
        scorecard_client.run_scorecard_cli("psf/requests")


def test_run_scorecard_cli_raises_on_nonzero_exit(monkeypatch):
    monkeypatch.setenv("GITHUB_AUTH_TOKEN", "tok")
    monkeypatch.setattr(scorecard_client.shutil, "which", lambda name: "/usr/bin/scorecard")
    run = Mock(return_value=_mock_run(1, "", "repo not found"))
    monkeypatch.setattr(scorecard_client.subprocess, "run", run)

    with pytest.raises(RuntimeError, match="repo not found"):
        scorecard_client.run_scorecard_cli("psf/requests")


def test_run_scorecard_cli_raises_on_non_json_output(monkeypatch):
    monkeypatch.setenv("GITHUB_AUTH_TOKEN", "tok")
    monkeypatch.setattr(scorecard_client.shutil, "which", lambda name: "/usr/bin/scorecard")
    run = Mock(return_value=_mock_run(0, "not json"))
    monkeypatch.setattr(scorecard_client.subprocess, "run", run)

    with pytest.raises(RuntimeError, match="non-JSON"):
        scorecard_client.run_scorecard_cli("psf/requests")


def test_run_scorecard_cli_uses_explicit_token_over_env(monkeypatch):
    monkeypatch.setenv("GITHUB_AUTH_TOKEN", "env-tok")
    monkeypatch.setattr(scorecard_client.shutil, "which", lambda name: "/usr/bin/scorecard")
    run = Mock(return_value=_mock_run(0, json.dumps({"score": 1.0, "checks": []})))
    monkeypatch.setattr(scorecard_client.subprocess, "run", run)

    scorecard_client.run_scorecard_cli("psf/requests", github_token="explicit-tok")

    env = run.call_args.kwargs["env"]
    assert env["GITHUB_AUTH_TOKEN"] == "explicit-tok"


def test_run_scorecard_cli_propagates_timeout(monkeypatch):
    monkeypatch.setenv("GITHUB_AUTH_TOKEN", "tok")
    monkeypatch.setattr(scorecard_client.shutil, "which", lambda name: "/usr/bin/scorecard")
    run = Mock(side_effect=subprocess.TimeoutExpired(cmd="scorecard", timeout=1))
    monkeypatch.setattr(scorecard_client.subprocess, "run", run)

    with pytest.raises(subprocess.TimeoutExpired):
        scorecard_client.run_scorecard_cli("psf/requests", timeout=1)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("psf/requests", "github.com/psf/requests"),
        ("github.com/psf/requests", "github.com/psf/requests"),
        ("https://github.com/psf/requests", "github.com/psf/requests"),
        ("https://github.com/psf/requests.git", "github.com/psf/requests"),
        ("https://github.com/psf/requests/", "github.com/psf/requests"),
        ("http://www.github.com/psf/requests", "github.com/psf/requests"),
    ],
)
def test_normalize_repo_ref(raw, expected):
    assert scorecard_client._normalize_repo_ref(raw) == expected


def test_normalize_repo_ref_rejects_unparseable_input():
    with pytest.raises(ValueError):
        scorecard_client._normalize_repo_ref("not-a-repo-ref")
