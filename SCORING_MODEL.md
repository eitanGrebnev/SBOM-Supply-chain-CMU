# Composite Scoring Model

## Formula

```
if VEX status == "not_affected":
    composite_score = 0
    tier = "Informational"
else:
    composite_score = (
        reachability_score        * 0.25 +
        exploitability_score       * 0.20 +
        exposure_score              * 0.20 +
        centrality_score            * 0.15 +
        patch_latency_score         * 0.10 +
        maintainer_health_score     * 0.10
    ) * 10   # scale weighted 0-10 average up to 0-100

tier = bucket(composite_score)
```

Each individual dimension score is 0–10 before weighting. The weighted sum is
therefore also 0–10, multiplied by 10 to produce a 0–100 composite.

## Weights

| Dimension | Weight | Rationale |
|---|---|---|
| Reachability | 25% | Strongest "is this a real risk at all" signal — if the vulnerable path can't execute, nothing else matters much. |
| Exploitability | 20% | Best available empirical signal (EPSS + KEV) for real-world attack likelihood, independent of your own code. |
| Exposure Context | 20% | Determines whether an attacker can actually reach the system to trigger a reachable vulnerability — the necessary complement to Reachability. |
| Dependency Centrality (Blast Radius) | 15% | Answers "how bad if it goes wrong," useful for prioritizing within an already-risky bucket, secondary to whether it *will* go wrong. |
| Patch Latency | 10% | Operationally important for remediation SLAs, but overlaps significantly with Exploitability (an actively exploited unpatched CVE is already captured there). |
| Maintainer Health | 10% | A leading indicator for *future* vulnerabilities in this dependency, weaker direct link to the *current* CVE's risk. Included for supply-chain trust signal, not dominant. |

**These weights are a starting hypothesis, not fixed truth.** If empirical
validation data becomes available (e.g. checking whether Critical/High-tier
composite scores correlate with confirmed KEV/EPSS outcomes better than
CVSS-only tiers do), the weights should be revisited and the paper should
report on whether the data supports the original prior. See `HYPOTHESIS.md`,
sub-hypothesis H2.

## Tier Buckets

| Composite Score | Tier |
|---|---|
| 80–100 | Critical |
| 60–79 | High |
| 40–59 | Medium |
| 20–39 | Low |
| 0–19 | Informational |

Thresholds are initial defaults — adjust based on how many findings land in
each bucket during real testing; if "Critical" ends up near-empty or
near-everything, the buckets need retuning before the buckets are meaningful.

## VEX Override

VEX (Vulnerability Exploitability eXchange) status is checked **before** the
weighted formula runs, not as a seventh dimension:

- `not_affected` → composite forced to 0 / Informational, regardless of any
  dimension score. The vendor/analyst has asserted this specific deployment
  is not exploitable, which overrides all heuristic scoring.
- `affected` → proceed with normal composite scoring.
- `fixed` → treat as resolved; typically excluded from active findings
  entirely rather than scored.
- `under_investigation` → proceed with normal composite scoring, but flag the
  finding as provisional/unconfirmed in output.

## Missing-Data Defaults (per dimension — see `DIMENSIONS.md` for full detail)

| Dimension | Default when data is missing | Reasoning |
|---|---|---|
| Reachability | 5 (indeterminate) | Can't build a call graph ≠ proven safe. Split the difference rather than guessing either direction. |
| Exploitability | 0 for EPSS if CVE not found (rare) | Absence from EPSS dataset is unusual and typically means very new/obscure CVE — treat conservatively as low until data exists. |
| Exposure Context | 10 (internet-facing / worst case) | Unknown exposure should never be assumed safe. |
| Dependency Centrality | 0 if isolated/leaf node | This one is usually knowable directly from the graph — true missing data is rare here. |
| Patch Latency | Scored via disclosure-date clock if no fix exists | Not really "missing data" — it's a distinct, valid case. |
| Maintainer Health | 5 (neutral) | No Scorecard data isn't evidence of poor maintenance. |

This asymmetry (some dimensions default worst-case, others default neutral)
is deliberate and should be explicitly justified in any writeup, not
smoothed over as an oversight.

## Known Modeling Simplification

Reachability and Exposure Context are conceptually **multiplicative** in
real-world risk terms — a vulnerability needs to be both execution-reachable
and attacker-reachable to be genuinely dangerous. The additive weighted-sum
model above cannot express "Reachability = 0 should suppress the whole
score" the way the VEX override does. This is worth stating as a limitation,
and optionally worth building as a second model variant to compare against
the additive one (see `HYPOTHESIS.md` for the comparative framing — additive
vs. gated model).
