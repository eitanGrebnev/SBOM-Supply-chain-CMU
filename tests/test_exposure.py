import pytest

from sbom_scorer.dimensions.exposure import DEFAULT_SCORE_UNKNOWN, score_exposure

# --- score mapping, per DIMENSIONS.md #3 ------------------------------------


@pytest.mark.parametrize(
    "tier,expected_score",
    [
        ("dev_only", 0.0),
        ("internal", 5.0),
        ("internet_facing", 10.0),
    ],
)
def test_score_mapping(tier, expected_score):
    result = score_exposure(tier)
    assert result.score == pytest.approx(expected_score)
    assert result.confidence == "high"


@pytest.mark.parametrize(
    "tier",
    [
        "Internet-Facing",  # hyphenated + mixed case, as a raw SBOM tag might read
        "  internal  ",
        "DEV_ONLY",
    ],
)
def test_score_mapping_is_case_and_separator_insensitive(tier):
    # Defensive re-normalization in score_exposure itself (sbom_parser
    # already normalizes on the way in, but this function shouldn't assume
    # every caller went through the parser).
    result = score_exposure(tier)
    assert result.confidence == "high"


# --- missing/unrecognized defaults -------------------------------------------


def test_none_defaults_to_worst_case():
    result = score_exposure(None)
    assert result.score == DEFAULT_SCORE_UNKNOWN == 10.0
    assert result.confidence == "default"


def test_empty_string_defaults_to_worst_case():
    result = score_exposure("")
    assert result.score == DEFAULT_SCORE_UNKNOWN
    assert result.confidence == "default"


def test_unrecognized_value_defaults_to_worst_case_not_a_crash():
    result = score_exposure("some-typo-tier")
    assert result.score == DEFAULT_SCORE_UNKNOWN
    assert result.confidence == "default"
