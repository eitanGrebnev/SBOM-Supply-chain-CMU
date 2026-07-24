from datetime import datetime, timezone
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
    registry_client.get_release_date.cache_clear()


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


# --- Maven ---------------------------------------------------------------


_MAVEN_SEARCH_LATEST = {"response": {"docs": [{"latestVersion": "2.14.1"}]}}
_MAVEN_SEARCH_GAV = {"response": {"docs": [{"timestamp": 1638360000000}]}}  # 2021-12-01T12:00:00Z


def _mock_pom(xml: str):
    response = Mock()
    response.status_code = 200
    response.raise_for_status.return_value = None
    response.content = xml.encode("utf-8")
    return response


def test_maven_release_date_from_search_timestamp(monkeypatch):
    _clear_cache()
    monkeypatch.setattr(requests, "get", Mock(return_value=_mock_response(_MAVEN_SEARCH_GAV)))
    result = registry_client.get_release_date(
        "Maven", "org.apache.logging.log4j:log4j-api", "2.14.1"
    )
    assert result == datetime(2021, 12, 1, 12, 0, tzinfo=timezone.utc)


def test_maven_release_date_no_matching_gav_returns_none(monkeypatch):
    _clear_cache()
    monkeypatch.setattr(
        requests, "get", Mock(return_value=_mock_response({"response": {"docs": []}}))
    )
    assert registry_client.get_release_date("Maven", "org.foo:bar", "1.0.0") is None


def test_maven_release_date_malformed_package_returns_none_without_network_call(monkeypatch):
    _clear_cache()
    get = Mock()
    monkeypatch.setattr(requests, "get", get)
    # No "groupId:artifactId" colon -> nothing to query with.
    assert registry_client.get_release_date("Maven", "log4j-api", "2.14.1") is None
    get.assert_not_called()


def test_maven_repo_url_from_pom_scm(monkeypatch):
    _clear_cache()
    pom = _mock_pom(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        "<scm><url>https://github.com/apache/logging-log4j2</url></scm>"
        "</project>"
    )
    monkeypatch.setattr(
        requests, "get", Mock(side_effect=[_mock_response(_MAVEN_SEARCH_LATEST), pom])
    )
    result = registry_client.get_repo_url("Maven", "org.apache.logging.log4j:log4j-api")
    assert result == "https://github.com/apache/logging-log4j2"


def test_maven_repo_url_falls_back_to_project_url_when_no_scm(monkeypatch):
    _clear_cache()
    pom = _mock_pom(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        "<url>https://logging.apache.org/log4j/2.x/</url>"
        "</project>"
    )
    monkeypatch.setattr(
        requests, "get", Mock(side_effect=[_mock_response(_MAVEN_SEARCH_LATEST), pom])
    )
    result = registry_client.get_repo_url("Maven", "org.apache.logging.log4j:log4j-api")
    assert result == "https://logging.apache.org/log4j/2.x/"


def test_maven_repo_url_pom_without_namespace_still_parses(monkeypatch):
    _clear_cache()
    pom = _mock_pom("<project><scm><url>https://example.com/repo</url></scm></project>")
    monkeypatch.setattr(
        requests, "get", Mock(side_effect=[_mock_response(_MAVEN_SEARCH_LATEST), pom])
    )
    assert registry_client.get_repo_url("Maven", "org.example:demo") == "https://example.com/repo"


def test_maven_repo_url_no_search_results_returns_none(monkeypatch):
    _clear_cache()
    monkeypatch.setattr(
        requests, "get", Mock(return_value=_mock_response({"response": {"docs": []}}))
    )
    assert registry_client.get_repo_url("Maven", "org.foo:bar") is None


def test_maven_repo_url_malformed_pom_returns_none_not_raises(monkeypatch):
    _clear_cache()
    bad_pom = _mock_pom("not valid xml <<<")
    monkeypatch.setattr(
        requests, "get", Mock(side_effect=[_mock_response(_MAVEN_SEARCH_LATEST), bad_pom])
    )
    assert registry_client.get_repo_url("Maven", "org.example:demo") is None


def test_maven_repo_url_malformed_package_returns_none_without_network_call(monkeypatch):
    _clear_cache()
    get = Mock()
    monkeypatch.setattr(requests, "get", get)
    assert registry_client.get_repo_url("Maven", "no-colon-here") is None
    get.assert_not_called()


# --- RubyGems --------------------------------------------------------------


def test_rubygems_release_date_matches_requested_version(monkeypatch):
    _clear_cache()
    payload = [
        {"number": "1.0.0", "created_at": "2020-01-01T00:00:00.000Z"},
        {"number": "1.1.0", "created_at": "2021-06-15T08:30:00.000Z"},
    ]
    monkeypatch.setattr(requests, "get", Mock(return_value=_mock_response(payload)))
    result = registry_client.get_release_date("RubyGems", "rails", "1.1.0")
    assert result == datetime(2021, 6, 15, 8, 30, tzinfo=timezone.utc)


def test_rubygems_release_date_no_matching_version_returns_none(monkeypatch):
    _clear_cache()
    payload = [{"number": "1.0.0", "created_at": "2020-01-01T00:00:00.000Z"}]
    monkeypatch.setattr(requests, "get", Mock(return_value=_mock_response(payload)))
    assert registry_client.get_release_date("RubyGems", "rails", "9.9.9") is None


def test_rubygems_repo_url_prefers_source_code_uri(monkeypatch):
    _clear_cache()
    payload = {
        "source_code_uri": "https://github.com/rails/rails",
        "homepage_uri": "https://rubyonrails.org",
    }
    monkeypatch.setattr(requests, "get", Mock(return_value=_mock_response(payload)))
    assert registry_client.get_repo_url("RubyGems", "rails") == "https://github.com/rails/rails"


def test_rubygems_repo_url_falls_back_to_homepage(monkeypatch):
    _clear_cache()
    payload = {"source_code_uri": None, "homepage_uri": "https://rubyonrails.org"}
    monkeypatch.setattr(requests, "get", Mock(return_value=_mock_response(payload)))
    assert registry_client.get_repo_url("RubyGems", "rails") == "https://rubyonrails.org"


def test_rubygems_request_exception_returns_none_not_raises(monkeypatch):
    _clear_cache()
    monkeypatch.setattr(requests, "get", Mock(side_effect=requests.Timeout("boom")))
    assert registry_client.get_repo_url("RubyGems", "rails") is None
    assert registry_client.get_release_date("RubyGems", "rails", "1.0.0") is None


# --- crates.io ---------------------------------------------------------------


def test_crates_release_date_matches_requested_version(monkeypatch):
    _clear_cache()
    payload = {
        "versions": [
            {"num": "1.0.0", "created_at": "2020-01-01T00:00:00.000Z"},
            {"num": "1.2.0", "created_at": "2022-03-10T00:00:00.000Z"},
        ]
    }
    monkeypatch.setattr(requests, "get", Mock(return_value=_mock_response(payload)))
    result = registry_client.get_release_date("crates.io", "serde", "1.2.0")
    assert result == datetime(2022, 3, 10, tzinfo=timezone.utc)


def test_crates_repo_url_prefers_repository_field(monkeypatch):
    _clear_cache()
    payload = {"crate": {"repository": "https://github.com/serde-rs/serde", "homepage": None}}
    monkeypatch.setattr(requests, "get", Mock(return_value=_mock_response(payload)))
    assert registry_client.get_repo_url("crates.io", "serde") == "https://github.com/serde-rs/serde"


def test_crates_repo_url_falls_back_to_homepage(monkeypatch):
    _clear_cache()
    payload = {"crate": {"repository": None, "homepage": "https://serde.rs"}}
    monkeypatch.setattr(requests, "get", Mock(return_value=_mock_response(payload)))
    assert registry_client.get_repo_url("crates.io", "serde") == "https://serde.rs"


def test_crates_requests_send_required_user_agent(monkeypatch):
    _clear_cache()
    get = Mock(return_value=_mock_response({"crate": {}}))
    monkeypatch.setattr(requests, "get", get)
    registry_client.get_repo_url("crates.io", "serde")
    _, kwargs = get.call_args
    assert "User-Agent" in kwargs.get("headers", {})


# --- dispatch --------------------------------------------------------------


def test_unrecognized_ecosystem_returns_none_without_network_call(monkeypatch):
    _clear_cache()
    get = Mock()
    monkeypatch.setattr(requests, "get", get)
    assert registry_client.get_repo_url("Cocoapods", "SomePod") is None
    assert registry_client.get_release_date("Cocoapods", "SomePod", "1.0.0") is None
    get.assert_not_called()
