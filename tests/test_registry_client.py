from unittest.mock import Mock

import requests

from sbom_scorer.data_sources import registry_client


def _mock_response(payload, status_code=200):
    response = Mock()
    response.status_code = status_code
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    return response


def _clear_cache():
    registry_client.get_repo_url.cache_clear()


# --- PyPI --------------------------------------------------------------


def test_pypi_prefers_source_key_over_other_project_urls(monkeypatch):
    _clear_cache()
    payload = {
        "info": {
            "project_urls": {
                "Homepage": "https://requests.readthedocs.io",
                "Source": "https://github.com/psf/requests",
            },
            "home_page": "https://requests.readthedocs.io",
        }
    }
    monkeypatch.setattr(
        requests, "get", Mock(return_value=_mock_response(payload))
    )
    assert registry_client.get_repo_url("PyPI", "requests") == "https://github.com/psf/requests"


def test_pypi_falls_back_to_any_project_url_then_home_page(monkeypatch):
    _clear_cache()
    payload = {
        "info": {
            "project_urls": {"Changelog": "https://example.com/changelog"},
            "home_page": "https://example.com/home",
        }
    }
    monkeypatch.setattr(requests, "get", Mock(return_value=_mock_response(payload)))
    assert registry_client.get_repo_url("PyPI", "somepkg") == "https://example.com/changelog"


def test_pypi_falls_back_to_home_page_when_no_project_urls(monkeypatch):
    _clear_cache()
    payload = {"info": {"project_urls": None, "home_page": "https://example.com/home"}}
    monkeypatch.setattr(requests, "get", Mock(return_value=_mock_response(payload)))
    assert registry_client.get_repo_url("PyPI", "somepkg") == "https://example.com/home"


def test_pypi_returns_none_when_nothing_declared(monkeypatch):
    _clear_cache()
    payload = {"info": {}}
    monkeypatch.setattr(requests, "get", Mock(return_value=_mock_response(payload)))
    assert registry_client.get_repo_url("PyPI", "somepkg") is None


def test_pypi_request_exception_returns_none_not_raises(monkeypatch):
    _clear_cache()
    monkeypatch.setattr(
        requests, "get", Mock(side_effect=requests.ConnectionError("boom"))
    )
    assert registry_client.get_repo_url("PyPI", "somepkg") is None


def test_pypi_malformed_json_body_returns_none_not_raises(monkeypatch):
    _clear_cache()
    response = Mock()
    response.status_code = 200
    response.raise_for_status.return_value = None
    response.json.side_effect = ValueError("not JSON")
    monkeypatch.setattr(requests, "get", Mock(return_value=response))
    assert registry_client.get_repo_url("PyPI", "somepkg") is None


def test_pypi_unexpected_shape_returns_none_not_raises(monkeypatch):
    _clear_cache()
    # "info" is a list instead of the expected dict.
    monkeypatch.setattr(
        requests, "get", Mock(return_value=_mock_response({"info": ["unexpected"]}))
    )
    assert registry_client.get_repo_url("PyPI", "somepkg") is None


# --- npm -----------------------------------------------------------------


def test_npm_dict_repository_field(monkeypatch):
    _clear_cache()
    payload = {"repository": {"type": "git", "url": "https://github.com/expressjs/express"}}
    monkeypatch.setattr(requests, "get", Mock(return_value=_mock_response(payload)))
    assert registry_client.get_repo_url("npm", "express") == "https://github.com/expressjs/express"


def test_npm_string_repository_field(monkeypatch):
    _clear_cache()
    payload = {"repository": "https://github.com/expressjs/express"}
    monkeypatch.setattr(requests, "get", Mock(return_value=_mock_response(payload)))
    assert registry_client.get_repo_url("npm", "express") == "https://github.com/expressjs/express"


def test_npm_github_shorthand_is_normalized(monkeypatch):
    _clear_cache()
    payload = {"repository": "github:expressjs/express"}
    monkeypatch.setattr(requests, "get", Mock(return_value=_mock_response(payload)))
    assert registry_client.get_repo_url("npm", "express") == "https://github.com/expressjs/express"


def test_npm_bare_shorthand_defaults_to_github(monkeypatch):
    _clear_cache()
    payload = {"repository": "expressjs/express"}
    monkeypatch.setattr(requests, "get", Mock(return_value=_mock_response(payload)))
    assert registry_client.get_repo_url("npm", "express") == "https://github.com/expressjs/express"


def test_npm_gitlab_shorthand_is_left_unnormalized(monkeypatch):
    _clear_cache()
    payload = {"repository": "gitlab:someone/somewhere"}
    monkeypatch.setattr(requests, "get", Mock(return_value=_mock_response(payload)))
    # Not GitHub — left as-is so repo_resolver's GitHub-only parsing rejects it.
    assert registry_client.get_repo_url("npm", "pkg") == "gitlab:someone/somewhere"


def test_npm_missing_repository_returns_none(monkeypatch):
    _clear_cache()
    monkeypatch.setattr(requests, "get", Mock(return_value=_mock_response({})))
    assert registry_client.get_repo_url("npm", "pkg") is None


def test_npm_request_exception_returns_none_not_raises(monkeypatch):
    _clear_cache()
    monkeypatch.setattr(requests, "get", Mock(side_effect=requests.Timeout("boom")))
    assert registry_client.get_repo_url("npm", "pkg") is None


def test_npm_malformed_json_body_returns_none_not_raises(monkeypatch):
    _clear_cache()
    response = Mock()
    response.status_code = 200
    response.raise_for_status.return_value = None
    response.json.side_effect = ValueError("not JSON")
    monkeypatch.setattr(requests, "get", Mock(return_value=response))
    assert registry_client.get_repo_url("npm", "pkg") is None


# --- dispatch --------------------------------------------------------------


def test_unsupported_ecosystem_returns_none_without_network_call(monkeypatch):
    _clear_cache()
    get = Mock()
    monkeypatch.setattr(requests, "get", get)
    assert registry_client.get_repo_url("Maven", "some.artifact") is None
    get.assert_not_called()
