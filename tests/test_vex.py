"""Tests for sbom_scorer.vex — VEX gate logic.

Stub scaffolding: fill in once apply_vex_gate is implemented. Cases to
cover per SCORING_MODEL.md "VEX Override" once implemented:
    - not_affected -> True (suppress).
    - affected / under_investigation / None -> False (proceed).
"""

import pytest

from sbom_scorer import vex


def test_apply_vex_gate_not_implemented():
    with pytest.raises(NotImplementedError):
        vex.apply_vex_gate(vex.VexStatus.NOT_AFFECTED)
