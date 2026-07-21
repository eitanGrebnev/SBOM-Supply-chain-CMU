"""Tests for sbom_scorer.vex — VEX gate logic.

Covers SCORING_MODEL.md "VEX Override":
    - not_affected -> True (suppress).
    - affected / under_investigation / fixed / None -> False (proceed).
    - string coercion of raw SBOM values.
"""

import pytest

from sbom_scorer import vex


def test_apply_vex_gate_not_affected_suppresses():
    assert vex.apply_vex_gate(vex.VexStatus.NOT_AFFECTED) is True


@pytest.mark.parametrize(
    "status",
    [
        vex.VexStatus.AFFECTED,
        vex.VexStatus.UNDER_INVESTIGATION,
        vex.VexStatus.FIXED,
        None,
    ],
)
def test_apply_vex_gate_proceeds(status):
    assert vex.apply_vex_gate(status) is False


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("not_affected", vex.VexStatus.NOT_AFFECTED),
        ("not affected", vex.VexStatus.NOT_AFFECTED),
        ("not-affected", vex.VexStatus.NOT_AFFECTED),
        ("affected", vex.VexStatus.AFFECTED),
        ("bogus", None),
        (None, None),
    ],
)
def test_coerce_vex_status(raw, expected):
    assert vex.coerce_vex_status(raw) == expected


def test_apply_vex_gate_accepts_raw_string():
    assert vex.apply_vex_gate("not_affected") is True
    assert vex.apply_vex_gate("affected") is False


def test_get_vex_status_reads_mapping():
    class FakeComponent:
        vex_statuses = {"CVE-2021-44228": "not_affected"}

    assert vex.get_vex_status(FakeComponent(), "CVE-2021-44228") == vex.VexStatus.NOT_AFFECTED
    # CVE not in the mapping, and no single vex_status attribute -> None.
    assert vex.get_vex_status(FakeComponent(), "CVE-0000-0000") is None


def test_get_vex_status_none_component():
    assert vex.get_vex_status(None, "CVE-0000-0000") is None
