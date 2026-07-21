"""Tests for sbom_scorer.data_sources.github_sbom — repo URL -> SBOM fetch."""

import json

import pytest

from sbom_scorer.data_sources import github_sbom


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://github.com/psf/requests", ("psf", "requests")),
        ("https://github.com/psf/requests.git", ("psf", "requests")),
        ("https://github.com/psf/requests/tree/main", ("psf", "requests")),
        ("git@github.com:psf/requests.git", ("psf", "requests")),
        ("github.com/psf/requests", ("psf", "requests")),
        ("psf/requests", ("psf", "requests")),
    ],
)
def test_parse_repo_url(url, expected):
    assert github_sbom.parse_repo_url(url) == expected


def test_parse_repo_url_invalid():
    with pytest.raises(ValueError):
        github_sbom.parse_repo_url("not a repo at all !!!")


def test_fetch_sbom_extracts_inner_document(monkeypatch):
    spdx_doc = {"spdxVersion": "SPDX-2.3", "packages": []}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"sbom": spdx_doc}

    captured = {}

    def fake_get(url, headers=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        return FakeResponse()

    import requests

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    result = github_sbom.fetch_sbom("psf/requests")
    assert result == spdx_doc
    assert captured["url"].endswith("/repos/psf/requests/dependency-graph/sbom")
    assert "Authorization" not in captured["headers"]


def test_fetch_sbom_adds_bearer_token(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"sbom": {"spdxVersion": "SPDX-2.3", "packages": []}}

    captured = {}

    def fake_get(url, headers=None, timeout=None):
        captured["headers"] = headers
        return FakeResponse()

    import requests

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setenv("GITHUB_TOKEN", "secret-token")

    github_sbom.fetch_sbom("psf/requests")
    assert captured["headers"]["Authorization"] == "Bearer secret-token"


def test_fetch_sbom_missing_sbom_key_raises(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"not_sbom": {}}

    import requests

    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse())
    with pytest.raises(ValueError):
        github_sbom.fetch_sbom("psf/requests")


def test_fetch_sbom_to_file_writes_json(monkeypatch, tmp_path):
    spdx_doc = {"spdxVersion": "SPDX-2.3", "packages": [{"name": "x"}]}
    monkeypatch.setattr(github_sbom, "fetch_sbom", lambda url, token=None: spdx_doc)

    out = tmp_path / "repo.spdx.json"
    github_sbom.fetch_sbom_to_file("psf/requests", str(out))
    assert json.loads(out.read_text(encoding="utf-8")) == spdx_doc
