# Research Hypothesis

Reference for anyone (human or AI) drafting the paper/report alongside this
tool. This is the thesis the codebase is built to test — implementation
choices in the other files should stay traceable back to this.

## Primary Hypothesis

A multi-dimensional composite score that weights reachability, blast radius,
exploitability, patch latency, maintainer health, and exposure context will
produce a more actionable vulnerability prioritization ranking than
CVSS-only triage — specifically, it will surface a smaller, more precise set
of "true positive" critical risks while deprioritizing a larger share of
technically-present-but-practically-irrelevant CVEs, without missing
vulnerabilities that are later confirmed as actively exploited.

## Null Hypothesis

H0: The composite score's prioritization does not differ meaningfully from
CVSS-only prioritization in terms of which CVEs are flagged Critical/High.

## Sub-Hypotheses

**H1 — Noise Reduction**
The composite score will reduce the number of Critical/High-tier findings
compared to CVSS-only classification of the same dependency set, primarily
driven by Reachability and Exposure Context filtering out code that's
present but never executed or never network-accessible.

*How to test:* run both CVSS-only and composite classification over the same
test SBOM/dependency set; compare count and composition of Critical/High
tiers.

**H2 — Predictive Validity**
Vulnerabilities scored Critical/High by the composite model will show higher
correlation with CISA KEV membership and high EPSS scores than
vulnerabilities scored Critical/High by CVSS alone — i.e., the model
produces a *better* ranking, not just a *different* one.

*How to test:* cross-reference each model's Critical/High findings against
KEV membership and EPSS score distribution; compare precision.

*Note:* this is also the mechanism for validating or adjusting the weights
in `SCORING_MODEL.md` — if H2 doesn't hold with the initial 25/20/20/15/10/10
weighting, that's a legitimate empirical finding to report, and the weights
should be revisited rather than the hypothesis being treated as falsified
outright.

**H3 — Stability Under Missing Data**
The model's tier classification remains reasonably stable (doesn't swing
wildly) when individual dimensions fall back to their indeterminate/default
values, testing whether the "graceful degradation" defaults documented in
`SCORING_MODEL.md` actually hold up rather than being just a design
assumption.

*How to test:* run the same findings set with varying amounts of dimension
data deliberately withheld/nulled; measure tier-classification variance.

## Known Limitation to State Explicitly in the Paper

The additive weighted-sum composite formula cannot express that Reachability
and Exposure Context are conceptually multiplicative (a vulnerability needs
to be *both* execution-reachable and attacker-reachable to be truly
dangerous). This is a modeling simplification, not an oversight — worth its
own subsection in limitations/future work, and a good candidate for a
follow-up comparative experiment: additive model vs. a "gated" model variant
where Reachability = 0 suppresses the whole score (similar to how VEX
`not_affected` already works).

## Framing Note for the Paper

Present the weights in `SCORING_MODEL.md` as a hypothesis-driven starting
prior, not as an established fact. If real KEV/EPSS ground-truth data is
available for validation (per H2), report whether the data supports the
initial weighting or suggests adjustment — a sensitivity analysis here is a
significantly stronger contribution than presenting fixed weights with no
empirical check.
