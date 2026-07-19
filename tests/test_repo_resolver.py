from sbom_scorer.data_sources import repo_resolver
from sbom_scorer.sbom_parser import Component


def _component(**overrides):
    defaults = dict(name="requests", version="2.31.0", ecosystem="PyPI")
    defaults.update(overrides)
    return Component(**defaults)


def test_resolves_from_https_vcs_url():
    component = _component(vcs_url="https://github.com/psf/requests")
    assert repo_resolver.resolve_github_repo(component) == ("psf", "requests")


def test_resolves_from_git_suffixed_vcs_url():
    component = _component(vcs_url="https://github.com/psf/requests.git")
    assert repo_resolver.resolve_github_repo(component) == ("psf", "requests")


def test_resolves_from_ssh_style_vcs_url():
    component = _component(vcs_url="git@github.com:psf/requests.git")
    assert repo_resolver.resolve_github_repo(component) == ("psf", "requests")


def test_resolves_from_vcs_url_with_trailing_path():
    component = _component(vcs_url="https://github.com/psf/requests/issues")
    assert repo_resolver.resolve_github_repo(component) == ("psf", "requests")


def test_non_github_vcs_url_falls_back_to_registry(monkeypatch):
    component = _component(vcs_url="https://gitlab.com/someone/somewhere")
    monkeypatch.setattr(
        repo_resolver.registry_client,
        "get_repo_url",
        lambda ecosystem, package: "https://github.com/psf/requests",
    )
    assert repo_resolver.resolve_github_repo(component) == ("psf", "requests")


def test_no_vcs_url_falls_back_to_registry(monkeypatch):
    component = _component(vcs_url=None)
    calls = []

    def fake_get_repo_url(ecosystem, package):
        calls.append((ecosystem, package))
        return "https://github.com/psf/requests"

    monkeypatch.setattr(repo_resolver.registry_client, "get_repo_url", fake_get_repo_url)

    assert repo_resolver.resolve_github_repo(component) == ("psf", "requests")
    assert calls == [("PyPI", "requests")]


def test_unresolvable_returns_none(monkeypatch):
    component = _component(vcs_url=None)
    monkeypatch.setattr(
        repo_resolver.registry_client, "get_repo_url", lambda ecosystem, package: None
    )
    assert repo_resolver.resolve_github_repo(component) is None


# --- _parse_github_url edge cases -------------------------------------


def test_query_string_is_stripped_from_repo():
    assert repo_resolver._parse_github_url(
        "https://github.com/psf/requests?tab=readme"
    ) == ("psf", "requests")


def test_fragment_is_stripped_from_repo():
    assert repo_resolver._parse_github_url(
        "https://github.com/psf/requests#readme"
    ) == ("psf", "requests")


def test_git_suffix_with_trailing_query_string():
    assert repo_resolver._parse_github_url(
        "https://github.com/psf/requests.git?ref=main"
    ) == ("psf", "requests")


def test_uppercase_domain_matches():
    assert repo_resolver._parse_github_url("https://GITHUB.COM/psf/requests") == (
        "psf",
        "requests",
    )


def test_owner_only_url_returns_none():
    assert repo_resolver._parse_github_url("https://github.com/psf") is None
    assert repo_resolver._parse_github_url("https://github.com/psf/") is None
    assert repo_resolver._parse_github_url("https://github.com/") is None
    assert repo_resolver._parse_github_url("https://github.com") is None


def test_empty_and_none_return_none():
    assert repo_resolver._parse_github_url("") is None
    assert repo_resolver._parse_github_url(None) is None


def test_lookalike_domain_is_rejected():
    assert repo_resolver._parse_github_url("https://notgithub.com/psf/requests") is None
