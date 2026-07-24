"""Chart/graph generation for scored findings — see VISUALIZATION.md.

Design rule (VISUALIZATION.md "Implementation Notes"): chart-generation
functions only ever consume already-computed scores from sbom_scorer.composite
.Finding — never recompute or call external APIs. Default output is static
image files (.png/.svg) for paper/report inclusion; interactive HTML export
(plotly/pyvis) is a secondary option.

Five chart types (VISUALIZATION.md):
    1. Tier distribution bar chart (CVSS-only vs. composite, side by side)
       -> tier_distribution_bar() (implemented; CVSS-only comparison deferred)
    2. Per-finding radar/spider chart (six-dimension breakdown)
       -> finding_radar() (implemented)
    3. Dependency graph visualization (blast radius / centrality) -> deferred,
       needs dependency-graph edges the parser doesn't build yet.
    4. Scatter plot — Reachability vs. Exposure (or any two dimensions) -> deferred.
    5. Composite score histogram, with tier-threshold lines -> deferred.
"""

from __future__ import annotations

import math

import matplotlib

matplotlib.use("Agg")  # headless — no display available in CLI/CI contexts

import matplotlib.pyplot as plt
import networkx as nx

from sbom_scorer import composite
from sbom_scorer.composite import Finding

# Canonical tier order, highest severity first (mirrors composite.TIER_THRESHOLDS).
_TIER_ORDER = tuple(name for _, name in composite.TIER_THRESHOLDS)
_TIER_COLORS: dict[str, str] = {
    "Critical": "#b30000",
    "High": "#e34a33",
    "Medium": "#fdae61",
    "Low": "#a6d96a",
    "Informational": "#1a9850",
}

# Dimensions in the documented weighting order (SCORING_MODEL.md).
_DIMENSION_LABELS: dict[str, str] = {
    "reachability": "Reachability",
    "exploitability": "Exploitability",
    "exposure": "Exposure",
    "centrality": "Centrality",
    "patch_latency": "Patch Latency",
    "maintainer_health": "Maintainer Health",
}
_DIMENSION_ORDER = tuple(_DIMENSION_LABELS)


def tier_distribution_bar(
    findings: list[Finding],
    output_path: str,
    compare_cvss_only: bool = False,
) -> None:
    """Bar chart of finding counts per tier (VISUALIZATION.md chart #1).

    Args:
        findings: Scored findings to plot.
        output_path: Where to save the chart image (.png).
        compare_cvss_only: If True, plot composite-model tiers alongside
            CVSS-only tiers for the same findings (H1 comparison per
            VISUALIZATION.md / HYPOTHESIS.md).

    Raises:
        NotImplementedError: If compare_cvss_only is True — no CVSS-only
            score is computed anywhere in the pipeline yet, so there's
            nothing to compare against (see VISUALIZATION.md chart #1).
    """
    if compare_cvss_only:
        raise NotImplementedError(
            "compare_cvss_only isn't implemented yet — the pipeline doesn't "
            "compute a CVSS-only score to compare against (VISUALIZATION.md #1)."
        )

    counts = {tier: 0 for tier in _TIER_ORDER}
    for finding in findings:
        if finding.tier in counts:
            counts[finding.tier] += 1

    fig, ax = plt.subplots(figsize=(6, 4))
    values = [counts[tier] for tier in _TIER_ORDER]
    colors = [_TIER_COLORS[tier] for tier in _TIER_ORDER]
    ax.bar(_TIER_ORDER, values, color=colors)
    ax.set_ylabel("Finding count")
    ax.set_title(f"Findings by Tier (n={len(findings)})")
    ax.set_ylim(bottom=0)
    fig.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)


def finding_radar(finding: Finding, output_path: str) -> None:
    """Radar/spider chart of one finding's six dimension scores (VISUALIZATION.md chart #2).

    Missing dimensions plot at their substituted missing-data default (they
    are already baked into finding.dimension_scores by
    composite.score_finding, which must have run on this finding first).
    """
    scores = finding.dimension_scores or {
        dim: composite.MISSING_DATA_DEFAULTS.get(dim, 0.0) for dim in _DIMENSION_ORDER
    }
    values = [float(scores.get(dim, 0.0)) for dim in _DIMENSION_ORDER]
    labels = [_DIMENSION_LABELS[dim] for dim in _DIMENSION_ORDER]

    angle_step = 2 * math.pi / len(_DIMENSION_ORDER)
    angles = [i * angle_step for i in range(len(_DIMENSION_ORDER))]
    values_closed = values + values[:1]
    angles_closed = angles + angles[:1]

    fig = plt.figure(figsize=(5, 5))
    ax = fig.add_subplot(111, polar=True)
    ax.set_theta_offset(math.pi / 2)
    ax.set_theta_direction(-1)
    ax.set_xticks(angles)
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 10)
    ax.plot(angles_closed, values_closed, linewidth=2, color="#e34a33")
    ax.fill(angles_closed, values_closed, alpha=0.25, color="#e34a33")

    title = f"{finding.component_name}@{finding.component_version} — {finding.cve_id}"
    if finding.tier:
        title += f" ({finding.tier})"
    ax.set_title(title, y=1.12)
    fig.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)


def plot_dependency_graph(
    dependency_graph: nx.DiGraph,
    findings: list[Finding],
    output_path: str,
    interactive: bool = False,
) -> None:
    """Node-link visualization of the SBOM dependency graph.

    Node size/color scaled to blast radius and/or composite risk score.

    Args:
        dependency_graph: The SBOM dependency graph (sbom_scorer.sbom_parser).
        findings: Scored findings, used to color/size nodes by risk.
        output_path: Where to save the chart (image or HTML).
        interactive: If True, produce an interactive HTML graph via pyvis
            instead of a static matplotlib image.

    Raises:
        NotImplementedError: Always. Deferred — sbom_parser doesn't build
            dependency-graph edges yet, so there's no structure to draw
            (see ARCHITECTURE.md / VISUALIZATION.md chart #3).
    """
    raise NotImplementedError(
        "Dependency graph visualization is deferred until sbom_parser builds "
        "dependency-graph edges (see VISUALIZATION.md chart #3)."
    )


def plot_dimension_scatter(
    findings: list[Finding],
    x_dimension: str,
    y_dimension: str,
    output_path: str,
) -> None:
    """2D scatter of two dimension scores across all findings, colored by tier.

    Default use case: Reachability (x) vs. Exposure (y), per VISUALIZATION.md,
    to visually test the additive-vs-multiplicative modeling simplification.

    Raises:
        NotImplementedError: Always. Not yet implemented (VISUALIZATION.md
            chart #4) — lower priority than charts #1/#2, which cli.py's
            --charts flag already wires up.
    """
    raise NotImplementedError("Dimension scatter plot is not implemented yet (VISUALIZATION.md #4).")


def plot_composite_histogram(findings: list[Finding], output_path: str) -> None:
    """Histogram of composite scores (0-100) with tier-threshold lines at 20/40/60/80.

    Raises:
        NotImplementedError: Always. Not yet implemented (VISUALIZATION.md
            chart #5).
    """
    raise NotImplementedError("Composite score histogram is not implemented yet (VISUALIZATION.md #5).")
