# Scoring Dimensions — Detailed Spec

Each dimension is scored 0–10 (10 = highest risk). All six feed into the
weighted composite described in `SCORING_MODEL.md`.

---

## 1. Reachability

**Definition:** If you trace through the actual code, does execution ever
reach the vulnerable function in this dependency?

**Why it matters:** A CVE in a function your code never calls is not a real
risk to you, regardless of severity rating.

**Implementation approach:**

1. **Baseline check — is the package even imported?**
   AST-parse the codebase's import statements and confirm the vulnerable
   package is actually imported somewhere (not just present in a lockfile/
   manifest). This alone eliminates a meaningful fraction of noise.
2. **Function-level check — is the specific vulnerable function reachable?**
   - Build a static call graph of the application plus its dependencies.
     - Python: JARVIS or PyCG.
     - Java: CodeQL (build a database, run a custom reachability query).
   - Identify entry points (route handlers, `main()`, CLI arg parsers,
     webhook handlers, etc.).
   - BFS/DFS from entry points through the call graph; check whether the
     vulnerable function is a reachable node.
3. **Identifying the vulnerable function itself.**
   Most CVE databases don't name the vulnerable function directly. Pull the
   fix commit referenced in the OSV/GHSA advisory (`references[].type ==
   "FIX"`), diff it, and extract the names of changed functions. This is the
   input to step 2.
4. **Fallback when function-level identification fails.**
   If no fix commit is available, or the call graph can't be built (dynamic
   language features, missing source, etc.), fall back to the baseline
   package-import check and score as **indeterminate**, not as confirmed safe
   or unsafe.

**Score mapping:**
| Condition | Score |
|---|---|
| Package not imported anywhere | 0 |
| Package imported, but vulnerable function confirmed unreachable via call graph | 1–2 |
| Indeterminate (no call graph, or vulnerable function unknown, but package is imported) | 5 |
| Vulnerable function confirmed reachable from an entry point | 10 |

**Known limitation to document:** static call graphs can overestimate
reachability (infeasible paths not actually executable at runtime) or
underestimate it (dynamic dispatch, reflection, `eval`-style calls, monkey
patching). This is a real limitation of the method, not just a corner case —
state it explicitly in any writeup.

---

## 2. Exploitability

**Definition:** Percent chance the vulnerability will be exploited.

**Implementation approach:**

1. Pull the EPSS score for the CVE from FIRST.org's API
   (`https://api.first.org/data/v1/epss?cve=...`), which returns a
   probability (0–1) of exploitation within the next 30 days. Batch queries
   are supported (comma-separated CVE list).
2. Pull the CISA KEV catalog (static JSON feed, refreshed daily) and check
   CVE membership.
3. **KEV membership overrides EPSS.** If a CVE is in KEV, it's confirmed
   actively exploited in the wild — score it at or near the maximum
   regardless of its EPSS value.
4. If not in KEV, transform the EPSS probability into a 0–10 score using a
   **log or percentile scale, not linear**. Most CVEs have very low EPSS
   scores (well under 0.01), so a linear 0–1 → 0–10 mapping compresses nearly
   every CVE into the bottom of the range and produces no useful spread.

**Score mapping:**
| Condition | Score |
|---|---|
| CVE in CISA KEV | 10 |
| EPSS ≥ ~0.5 (high confidence of exploitation) | 8–9 |
| EPSS ~0.1–0.5 | 4–7 (log-scaled) |
| EPSS < 0.1 | 0–3 (log-scaled) |

**Caching note:** cache both EPSS and KEV data locally on a daily refresh
cycle rather than querying live per scan run.

---

## 3. Exposure Context

**Definition:** Even if the vulnerable code path is reachable, who or what
has access to the system in order to trigger it?

**Why it's distinct from Reachability:** Reachability is about whether
*your own code* invokes the vulnerable path. Exposure Context is about
whether an *external actor* can reach the running system at all — dev-only,
internal-network-only, and internet-facing deployments of the exact same
reachable code carry very different real-world risk.

**Implementation approach:**

This dimension is fundamentally organizational/deployment input, not
something derivable from the package or CVE data alone. The implementation
goal is to make that input **structured**, not free text.

1. Define a small fixed set of exposure tiers, mirroring SSVC's System
   Exposure decision point:
   - `dev_only` — local/dev environment, no network exposure
   - `internal` — internal network only, behind VPN/firewall/access controls
   - `internet_facing` — reachable from the public internet
2. Tag exposure tier at the **service/deployment level**, not per-component —
   ideally at SBOM-generation time, using CycloneDX's custom `properties`
   field on the top-level component or metadata block (e.g. `{"name":
   "exposure:tier", "value": "internet-facing"}`). This makes it a one-time
   classification per service rather than a manual survey every scan.
3. If no exposure tag exists for a component/service, **default to
   `internet_facing` (worst case)** rather than assuming safety. Per SSVC
   guidance: if a deployer doesn't know their exposure, assume it's open.

**Score mapping:**
| Tier | Score |
|---|---|
| `dev_only` | 0 |
| `internal` | 5 |
| `internet_facing` | 10 |
| Unknown/missing | 10 (defaults to worst case) |

---

## 4. Dependency Centrality (Blast Radius)

**Definition:** How many other components depend on this one?

**Implementation approach:**

1. Parse the SBOM's dependency graph — CycloneDX `dependencies[]` or SPDX
   `relationships[]` — into a directed graph (NetworkX `DiGraph`), with edges
   representing "depends on."
2. To find blast radius for a given component, compute `ancestors()` on the
   reverse of that graph (i.e., everything that transitively depends on this
   component — everything that would be affected if this component were
   compromised).
3. Normalize the raw ancestor count into a 0–10 score using a **log scale**,
   since centrality distributions in real dependency graphs are heavily
   right-skewed (a small number of components have huge blast radius, most
   have very little).

**Score mapping:** log-normalized against the total component count in the
SBOM, e.g. `score = min(10, log2(count+1) / log2(total+1) * 10)`.

---

## 5. Patch Latency

**Definition:** How long has a patch been available vs. how long the
vulnerable version has been in use / unpatched.

**Implementation approach:**

1. Query OSV.dev (`POST https://api.osv.dev/v1/query`) with the package name,
   ecosystem, and version to get the matching vulnerability record, including
   its `published` (disclosure) date and `affected[].ranges[].events` (which
   contains the fixed version, when known).
2. Resolve the **fixed version's actual release date** via the relevant
   package registry API, since OSV gives a version identifier, not always a
   timestamp:
   - PyPI: `https://pypi.org/pypi/{package}/{version}/json` →
     `urls[0].upload_time_iso_8601`
   - npm: `https://registry.npmjs.org/{package}` → `time[version]`
   - Maven Central / RubyGems / crates.io: equivalent registry-specific
     lookups
3. Treat this as **two distinct sub-cases**, not one formula:
   - **Fix exists, not yet applied:** latency = time since the fix became
     available. This is the primary "why haven't we patched" signal.
   - **No fix exists yet:** this is a different risk — unpatchable exposure —
     scored instead by time since disclosure, since there's nothing to have
     applied.

**Score mapping (fix exists case):** score scales with days since fix release
(e.g. 0 days = 0, 60+ days unpatched = 10, linear or capped ramp in between).

**Score mapping (no fix exists case):** score scales with days since
disclosure, capturing the fact that an unpatchable, publicly known
vulnerability is a live and worsening risk the longer it goes unaddressed.

---

## 6. Maintainer Health

**Definition:** How maintained is the dependency's repo — activity level,
release signing, single vs. multiple maintainers.

**Implementation approach:**

1. Query the OSSF Scorecard public REST API
   (`https://api.securityscorecards.dev/projects/{owner}/{repo}`) for the
   repository backing the dependency. This covers most popular OSS packages
   already — no need to run the Scorecard CLI yourself unless a dependency
   isn't indexed.
2. Pull **individual check scores**, not just Scorecard's bundled aggregate,
   so a custom weighted sub-formula can be built that matches this project's
   specific definition of "maintainer health":
   - `Maintained` (repo activity) — weight heavily
   - `Signed-Releases` (signing) — weight heavily
   - `Code-Review` / `Contributors` (single vs. multiple maintainers) —
     weight heavily
   - `Branch-Protection`, `Vulnerabilities` — weight lightly, secondary
     signals
3. Scorecard returns `-1` for checks that are **not applicable** to a given
   project (e.g. `Code-Review` for a genuinely sole-maintainer repo) — when
   this happens, redistribute that check's weight across the remaining
   applicable checks rather than treating `-1` as a zero/failing score.
4. If Scorecard has no data at all for a repo (not yet indexed), default to a
   **neutral mid-score**, not a failing one — absence of data isn't evidence
   of poor maintenance.

**Score mapping:** weighted average of applicable Scorecard check scores
(each 0–10 natively), re-weighted per the sub-formula above; `5.0` default
when no Scorecard data exists.
