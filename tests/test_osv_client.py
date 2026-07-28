"""Tests for sbom_scorer.data_sources.osv_client.

query_by_package predates this test module (used throughout the pipeline
without dedicated coverage) — covered here alongside the new query_batch,
which cli._batch_prefilter_candidates relies on to cheaply skip clean
components before the slower per-component detail call.
"""

from unittest.mock import Mock

import pytest
import requests

from sbom_scorer.data_sources import osv_client


def _mock_response(payload, status_code=200):
    response = Mock()
    response.status_code = status_code
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    return response


# --- query_by_package --------------------------------------------------------


def test_query_by_package_returns_parsed_json(monkeypatch):
    osv_client.query_by_package.cache_clear()
    payload = {"vulns": [{"id": "CVE-2021-44228"}]}
    monkeypatch.setattr(requests, "post", Mock(return_value=_mock_response(payload)))
    assert osv_client.query_by_package("log4j-core", "Maven", "2.14.1") == payload


def test_query_by_package_sends_expected_payload(monkeypatch):
    osv_client.query_by_package.cache_clear()
    post = Mock(return_value=_mock_response({"vulns": []}))
    monkeypatch.setattr(requests, "post", post)
    osv_client.query_by_package("requests", "PyPI", "2.19.0")
    _, kwargs = post.call_args
    assert kwargs["json"] == {
        "version": "2.19.0",
        "package": {"name": "requests", "ecosystem": "PyPI"},
    }


def test_query_by_package_request_exception_returns_empty_dict_not_raises(monkeypatch):
    osv_client.query_by_package.cache_clear()
    monkeypatch.setattr(requests, "post", Mock(side_effect=requests.ConnectionError("boom")))
    assert osv_client.query_by_package("requests", "PyPI", "2.19.0") == {}


# --- query_batch --------------------------------------------------------------


def test_query_batch_empty_input_returns_empty_list_without_network_call(monkeypatch):
    post = Mock()
    monkeypatch.setattr(requests, "post", post)
    assert osv_client.query_batch([]) == []
    post.assert_not_called()


def test_query_batch_returns_results_in_order(monkeypatch):
    queries = [
        {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.19.0"},
        {"package": {"name": "left-pad", "ecosystem": "npm"}, "version": "1.0.0"},
    ]
    payload = {
        "results": [
            {"vulns": [{"id": "CVE-2018-1000620", "modified": "2021-01-01T00:00:00Z"}]},
            {"vulns": []},
        ]
    }
    monkeypatch.setattr(requests, "post", Mock(return_value=_mock_response(payload)))
    results = osv_client.query_batch(queries)
    assert results == payload["results"]


def test_query_batch_sends_wrapped_queries_payload(monkeypatch):
    queries = [{"package": {"name": "x", "ecosystem": "PyPI"}, "version": "1.0"}]
    post = Mock(return_value=_mock_response({"results": [{}]}))
    monkeypatch.setattr(requests, "post", post)
    osv_client.query_batch(queries)
    _, kwargs = post.call_args
    assert kwargs["json"] == {"queries": queries}


def test_query_batch_pads_short_results_to_match_queries(monkeypatch):
    queries = [
        {"package": {"name": "a", "ecosystem": "PyPI"}, "version": "1.0"},
        {"package": {"name": "b", "ecosystem": "PyPI"}, "version": "1.0"},
    ]
    # OSV returns fewer results than queries sent (malformed/short response).
    monkeypatch.setattr(
        requests, "post", Mock(return_value=_mock_response({"results": [{"vulns": []}]}))
    )
    results = osv_client.query_batch(queries)
    assert results == [{"vulns": []}, {}]


def test_query_batch_request_exception_raises_not_swallowed(monkeypatch):
    # Deliberately different contract from query_by_package: a failed batch
    # call must be distinguishable from "checked, found nothing" so the
    # caller (cli._batch_prefilter_candidates) can fail open instead of
    # silently treating an entire SBOM as clean.
    monkeypatch.setattr(requests, "post", Mock(side_effect=requests.ConnectionError("boom")))
    with pytest.raises(requests.ConnectionError):
        osv_client.query_batch([{"package": {"name": "x", "ecosystem": "PyPI"}, "version": "1.0"}])


def test_query_batch_http_error_raises(monkeypatch):
    response = Mock()
    response.text = ""
    response.raise_for_status.side_effect = requests.HTTPError("500 server error")
    monkeypatch.setattr(requests, "post", Mock(return_value=response))
    with pytest.raises(requests.HTTPError):
        osv_client.query_batch([{"package": {"name": "x", "ecosystem": "PyPI"}, "version": "1.0"}])


def test_query_batch_http_error_includes_response_body(monkeypatch):
    # OSV's 400 body is the only thing that identifies *which* query broke a
    # several-hundred-entry batch; losing it makes the failure undiagnosable.
    response = Mock()
    response.text = '{"code":3,"message":"error in query at index 7: invalid ecosystem"}'
    response.raise_for_status.side_effect = requests.HTTPError("400 Client Error")
    monkeypatch.setattr(requests, "post", Mock(return_value=response))
    with pytest.raises(requests.HTTPError, match="index 7"):
        osv_client.query_batch([{"package": {"name": "x", "ecosystem": "PyPI"}, "version": "1.0"}])

