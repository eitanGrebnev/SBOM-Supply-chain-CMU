import json
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
