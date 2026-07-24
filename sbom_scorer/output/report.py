"""JSON/CSV/console report generation for scored findings.

Per ARCHITECTURE.md: output is a tiered, sorted findings list, preserving
per-dimension scores (not just composite) so the report can explain *why*
a finding scored the way it did — e.g. "Critical, driven primarily by
Exploitability=10 and Exposure=10, despite Reachability=5/indeterminate".

Function names here (render_console / write_json / write_csv) are the ones
sbom_scorer.cli._emit_output actually calls.
"""

from __future__ import annotations

import csv
import json

from sbom_scorer import composite
from sbom_scorer.composite import Finding

# Dimensions in the documented weighting order (SCORING_MODEL.md), with the
# human-readable label used in explanations and the CSV header.
_DIMENSION_LABELS: dict[str, str] = {
    "reachability": "Reachability",
    "exploitability": "Exploitability",
    "exposure": "Exposure",
    "centrality": "Centrality",
    "patch_latency": "Patch Latency",
    "maintainer_health": "Maintainer Health",
}
_DIMENSION_ORDER = tuple(_DIMENSION_LABELS)

# Canonical tier order, highest severity first (mirrors composite.TIER_THRESHOLDS).
_TIER_ORDER = tuple(name for _, name in composite.TIER_THRESHOLDS)


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    """Findings sorted by composite score descending (highest risk first)."""
    return sorted(findings, key=lambda f: f.composite_score or 0.0, reverse=True)


def _tier_summary(findings: list[Finding]) -> dict[str, int]:
    """Count findings per tier, including tiers with zero findings."""
    counts = {tier: 0 for tier in _TIER_ORDER}
    for finding in findings:
        if finding.tier in counts:
            counts[finding.tier] += 1
        elif finding.tier is not None:
            # Defensive: an unrecognized tier value shouldn't be silently
            # dropped from the summary.
            counts[finding.tier] = counts.get(finding.tier, 0) + 1
    return counts


def _dimension_confidence(finding: Finding, dim: str) -> str | None:
    """Return the confidence flag for one of a finding's dimension scores, if set."""
    ds = getattr(finding, dim, None)
    return ds.confidence if ds is not None else None


def explain_finding(finding: Finding) -> str:
    """Produce a one-line human-readable explanation of why a finding scored as it did.

    E.g. "Critical, driven primarily by Exploitability=10 and Exposure=10,
    despite Reachability=5/indeterminate."

    Requires finding.dimension_scores to be populated (i.e.
    composite.score_finding has already run on this finding).
    """
    scores = finding.dimension_scores or {}
    if not scores:
        return finding.tier or "Unscored"

    ranked = sorted(
        ((dim, scores[dim]) for dim in _DIMENSION_ORDER if dim in scores),
        key=lambda item: item[1],
        reverse=True,
    )
    if not ranked:
        return finding.tier or "Unscored"

    top = ranked[:2]
    top_str = " and ".join(f"{_DIMENSION_LABELS[dim]}={value:g}" for dim, value in top)

    lowest_dim, lowest_value = ranked[-1]
    if lowest_value >= top[-1][1]:
        # Everything is tied (or the "lowest" score is no lower than the
        # dimensions driving the score) — no meaningful contrast to draw.
        return f"{finding.tier}, driven primarily by {top_str}."

    confidence = _dimension_confidence(finding, lowest_dim) or "default"
    lowest_str = f"{_DIMENSION_LABELS[lowest_dim]}={lowest_value:g}/{confidence}"
    return f"{finding.tier}, driven primarily by {top_str}, despite {lowest_str}."


def render_console(findings: list[Finding]) -> str:
    """Render a human-readable console summary of findings, grouped by tier.

    Returns the full report as a single string (the caller is responsible
    for printing it) — see cli.py's _emit_output.
    """
    if not findings:
        return "No findings — SBOM scan produced zero component+CVE pairs."

    summary = _tier_summary(findings)
    lines = [
        f"SBOM Vulnerability Scan — {len(findings)} finding(s)",
        "Summary: " + "  ".join(f"{tier}={summary[tier]}" for tier in _TIER_ORDER),
        "",
    ]

    for finding in _sorted_findings(findings):
        score = finding.composite_score if finding.composite_score is not None else 0.0
        vex_suffix = f"  [VEX: {finding.vex_status}]" if finding.vex_status else ""
        lines.append(
            f"[{finding.tier}] {finding.component_name}@{finding.component_version}  "
            f"{finding.cve_id}  score={score:.1f}{vex_suffix}"
        )
        lines.append(f"    {explain_finding(finding)}")

    return "\n".join(lines)


def _finding_to_dict(finding: Finding) -> dict:
    """Serialize one Finding to a JSON/CSV-friendly dict."""
    return {
        "component_name": finding.component_name,
        "component_version": finding.component_version,
        "cve_id": finding.cve_id,
        "vex_status": finding.vex_status,
        "composite_score": finding.composite_score,
        "tier": finding.tier,
        "dimension_scores": dict(finding.dimension_scores or {}),
        "explanation": explain_finding(finding),
    }


def write_json(findings: list[Finding], output_path: str) -> None:
    """Write findings to a JSON report file, sorted by composite score descending.

    Output shape:
        {
          "summary": {"Critical": 1, "High": 2, ...},
          "findings": [{...}, ...]
        }
    """
    data = {
        "summary": _tier_summary(findings),
        "findings": [_finding_to_dict(f) for f in _sorted_findings(findings)],
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def write_csv(findings: list[Finding], output_path: str) -> None:
    """Write findings to a CSV report file, sorted by composite score descending.

    One row per finding: identifying fields, composite/tier, then each of
    the six dimension scores as its own column.
    """
    fieldnames = [
        "component_name",
        "component_version",
        "cve_id",
        "vex_status",
        "composite_score",
        "tier",
        *_DIMENSION_ORDER,
    ]
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for finding in _sorted_findings(findings):
            row = {
                "component_name": finding.component_name,
                "component_version": finding.component_version,
                "cve_id": finding.cve_id,
                "vex_status": finding.vex_status,
                "composite_score": finding.composite_score,
                "tier": finding.tier,
            }
            row.update({dim: (finding.dimension_scores or {}).get(dim) for dim in _DIMENSION_ORDER})
            writer.writerow(row)
