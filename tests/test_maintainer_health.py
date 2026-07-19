import pytest

from sbom_scorer.dimensions import maintainer_health
from sbom_scorer.dimensions.maintainer_health import (
    CHECK_WEIGHTS,
    DEFAULT_SCORE_NO_DATA,
    _reweight_checks,
    _usable_checks,
    score_maintainer_health,
)
from sbom_scorer.sbom_parser import Component


def _component(**overrides):
    defaults = dict(name="requests", version="2.31.0", ecosystem="PyPI")
    defaults.update(overrides)
    return Component(**defaults)


def _scorecard(checks: dict[str, float]) -> dict:
    return {
        "score": 5.0,
        "checks": [{"name": name, "score": score} for name, score in checks.items()],
    }


# --- _reweight_checks / _usable_checks -------------------------------------


def test_reweight_full_set_is_plain_weighted_average():
    scores = {
        "Maintained": 10,
        "Signed-Releases": 10,
        "Code-Review": 10,
        "Contributors": 10,
        "Branch-Protection": 0,
        "Vulnerabilities": 0,
    }
    # 0.8 weight at score 10, 0.2 weight at score 0 -> 8.0
    assert _reweight_checks(scores) == pytest.approx(8.0)


def test_reweight_redistributes_not_applicable_checks():
    scores = {
        "Maintained": 10,
        "Signed-Releases": 10,
        "Code-Review": -1,  # not applicable -> excluded, weight redistributed
        "Contributors": 10,
        "Branch-Protection": 10,
        "Vulnerabilities": 10,
    }
    # every present, valid check scores 10 -> reweighted average is still 10
    assert _reweight_checks(scores) == pytest.approx(10.0)


def test_reweight_treats_missing_key_same_as_not_applicable():
    with_explicit_na = {"Maintained": 5, "Signed-Releases": -1}
    with_key_omitted = {"Maintained": 5}
    assert _reweight_checks(with_explicit_na) == _reweight_checks(with_key_omitted)


def test_reweight_ignores_unknown_check_names():
    scores = {"Maintained": 10, "Fuzzing": 0}
    assert _reweight_checks(scores) == pytest.approx(10.0)


def test_reweight_raises_when_nothing_usable():
    with pytest.raises(ValueError):
        _reweight_checks({"Code-Review": -1})


def test_usable_checks_filters_negative_and_unknown():
    scores = {"Maintained": 10, "Code-Review": -1, "Fuzzing": 5}
    assert _usable_checks(scores) == {"Maintained": 10}


def test_usable_checks_keeps_zero_score():
    # 0 is a genuine low score, not "missing" — must not be filtered like -1.
    assert _usable_checks({"Maintained": 0}) == {"Maintained": 0}


def test_usable_checks_filters_non_numeric_score():
    scores = {"Maintained": 10, "Signed-Releases": "not-a-number", "Code-Review": None}
    assert _usable_checks(scores) == {"Maintained": 10}


# --- score_maintainer_health -------------------------------------------


def test_unresolvable_repo_returns_neutral_default(monkeypatch):
    monkeypatch.setattr(maintainer_health, "resolve_github_repo", lambda component: None)
    result = score_maintainer_health(_component())
    assert result.score == DEFAULT_SCORE_NO_DATA
    assert result.confidence == "default"


def test_unindexed_repo_returns_neutral_default(monkeypatch):
    monkeypatch.setattr(
        maintainer_health, "resolve_github_repo", lambda component: ("psf", "requests")
    )
    monkeypatch.setattr(
        maintainer_health, "get_scorecard", lambda owner, repo: None
    )
    result = score_maintainer_health(_component())
    assert result.score == DEFAULT_SCORE_NO_DATA
    assert result.confidence == "default"


def test_indexed_repo_with_no_tracked_checks_returns_neutral_default(monkeypatch):
    monkeypatch.setattr(
        maintainer_health, "resolve_github_repo", lambda component: ("psf", "requests")
    )
    monkeypatch.setattr(
        maintainer_health,
        "get_scorecard",
        lambda owner, repo: _scorecard({"Fuzzing": 10}),
    )
    result = score_maintainer_health(_component())
    assert result.score == DEFAULT_SCORE_NO_DATA
    assert result.confidence == "default"


def test_explicit_null_checks_list_returns_neutral_default_not_crash(monkeypatch):
    # A JSON `"checks": null` (as opposed to an omitted key) must not crash
    # iteration — treat it the same as "no checks present".
    monkeypatch.setattr(
        maintainer_health, "resolve_github_repo", lambda component: ("psf", "requests")
    )
    monkeypatch.setattr(
        maintainer_health,
        "get_scorecard",
        lambda owner, repo: {"score": 5.0, "checks": None},
    )
    result = score_maintainer_health(_component())
    assert result.score == DEFAULT_SCORE_NO_DATA
    assert result.confidence == "default"


def test_full_check_set_is_high_confidence(monkeypatch):
    monkeypatch.setattr(
        maintainer_health, "resolve_github_repo", lambda component: ("psf", "requests")
    )
    monkeypatch.setattr(
        maintainer_health,
        "get_scorecard",
        lambda owner, repo: _scorecard(
            {name: 10 for name in CHECK_WEIGHTS}
        ),
    )
    result = score_maintainer_health(_component())
    assert result.score == pytest.approx(10.0)
    assert result.confidence == "high"


def test_sparse_check_set_is_medium_confidence(monkeypatch):
    monkeypatch.setattr(
        maintainer_health, "resolve_github_repo", lambda component: ("psf", "requests")
    )
    monkeypatch.setattr(
        maintainer_health,
        "get_scorecard",
        lambda owner, repo: _scorecard({"Maintained": 10, "Branch-Protection": 0}),
    )
    result = score_maintainer_health(_component())
    assert result.confidence == "medium"
    # (0.20*10 + 0.10*0) / (0.20+0.10) = 2.0 / 0.3
    assert result.score == pytest.approx(2.0 / 0.3)


def test_confidence_boundary_three_checks_is_medium(monkeypatch):
    monkeypatch.setattr(
        maintainer_health, "resolve_github_repo", lambda component: ("psf", "requests")
    )
    monkeypatch.setattr(
        maintainer_health,
        "get_scorecard",
        lambda owner, repo: _scorecard(
            {"Maintained": 10, "Signed-Releases": 10, "Code-Review": 10}
        ),
    )
    result = score_maintainer_health(_component())
    assert result.confidence == "medium"


def test_confidence_boundary_four_checks_is_high(monkeypatch):
    monkeypatch.setattr(
        maintainer_health, "resolve_github_repo", lambda component: ("psf", "requests")
    )
    monkeypatch.setattr(
        maintainer_health,
        "get_scorecard",
        lambda owner, repo: _scorecard(
            {"Maintained": 10, "Signed-Releases": 10, "Code-Review": 10, "Contributors": 10}
        ),
    )
    result = score_maintainer_health(_component())
    assert result.confidence == "high"
