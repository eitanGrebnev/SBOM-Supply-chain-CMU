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

**Implementation approach (pipeline):**

| Step | What the code does | Input | Output |
|---|---|---|---|
| 1 | Collect CVE IDs from scanner/SBOM vulnerability results | Vulnerability records | `["CVE-2021-44228", ...]` |
| 2 | Normalize and deduplicate CVEs | Raw CVE list | Unique uppercase CVE list |
| 3 | Query EPSS batch API | CVE list | Map of CVE → EPSS probability, percentile, date |
| 4 | Download KEV JSON feed | CISA KEV JSON | Map of CVE → KEV metadata |
| 5 | Join EPSS and KEV data | CVE list + maps | Enriched vulnerability records |
| 6 | Apply scoring rule | Enriched CVE record | 0–10 exploitability score |
| 7 | Cache results locally | EPSS/KEV API responses | Reusable JSON cache |

Notes on the pipeline:

1. Pull EPSS data for the CVE from FIRST.org's API
   (`https://api.first.org/data/v1/epss?cve=...`), which returns both a raw
   probability (0–1) of exploitation within the next 30 days **and a
   percentile** (rank relative to all other scored CVEs). Batch queries are
   supported (comma-separated CVE list) — use the batch endpoint rather than
   querying per-CVE.
2. Pull the CISA KEV catalog (static JSON feed, refreshed daily) and check
   CVE membership.
3. **KEV membership overrides EPSS.** If a CVE is in KEV, it's confirmed
   actively exploited in the wild — score it at the maximum regardless of
   its EPSS value.
4. If not in KEV, score off the **EPSS percentile, not the raw probability**,
   using the table below. Most CVEs have very low raw EPSS probabilities
   (well under 0.01), so mapping the raw probability linearly onto 0–10
   compresses nearly every CVE into the bottom of the range and produces no
   useful spread — percentile rank avoids that problem directly.

**Score mapping:**
| Condition | Score | Reason |
|---|---|---|
| CVE is in CISA KEV | 10 | Confirmed exploited in the wild |
| EPSS percentile ≥ 0.99 | 9 | Top 1% of EPSS-ranked CVEs |
| EPSS percentile ≥ 0.95 | 8 | Top 5% of EPSS-ranked CVEs |
| EPSS percentile ≥ 0.90 | 7 | Top 10% of EPSS-ranked CVEs |
| EPSS percentile ≥ 0.75 | 5 | Elevated exploit likelihood |
| EPSS percentile ≥ 0.50 | 3 | Moderate relative exploit likelihood |
| EPSS exists but percentile < 0.50 | 1 | Lower relative exploit likelihood |
| No EPSS data and not in KEV | 5, low confidence | Unknown, not assumed safe |

Note this default changed from an earlier draft (which used 0/"not found is
rare, treat conservatively as low") — the current position is that an
unscored, non-KEV CVE is **genuinely unknown**, not evidence of low risk, so
it defaults to the same indeterminate mid-score philosophy used elsewhere in
this model (see Reachability's 5/indeterminate default) rather than assuming
safety.

**Caching note:** cache both EPSS and KEV data locally on a daily refresh
cycle rather than querying live per scan run (see pipeline step 7).

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

**Implementation note:** `sbom_scorer.sbom_parser._parse_cyclonedx` reads
the tag from `metadata.component.properties[]` only (matching point 2
above — service-level, not per-component), matching on property name
`exposure:tier` case-insensitively and normalizing the value (lowercased,
hyphens → underscores, e.g. `"Internet-Facing"` → `"internet_facing"`) so
common producer formatting variants still match the tier vocabulary. That
single value is applied to every `Component` parsed from the SBOM, not
looked up per component. The parser doesn't validate the value against the
tier enum — an unrecognized string is passed through as-is;
`sbom_scorer.dimensions.exposure.score_exposure` is what falls back to the
worst-case default for `None` or unrecognized values (also re-normalizing
defensively, in case a `Component` was built directly rather than via the
parser).

---

## 4. Dependency Centrality (Blast Radius)

**Definition:** How many other components depend on this one?

**Implementation approach:** two sub-methods, computed on the same
dependency graph, combined into one 0–10 score.

**Sub-method A — Reachable Dependents (blast radius proper):**

1. Parse the SBOM's dependency graph — CycloneDX `dependencies[]` or SPDX
   `relationships[]` — into a directed graph (NetworkX `DiGraph`), with edges
   representing "depends on."
2. Reverse the dependency graph.
3. To find blast radius for a given component, perform a BFS/DFS (or
   `ancestors()`) starting from that component on the reversed graph —
   i.e., everything that transitively depends on this component, everything
   that would be affected if this component were compromised.
4. Normalize the raw dependent count into a 0–10 score using a **log
   scale**, since centrality distributions in real dependency graphs are
   heavily right-skewed (a small number of components have huge blast
   radius, most have very little). Alternative linear normalization:
   divide by the total number of possible dependents (`N - 1`) and scale
   to 0–10.

Sub-method A score: `min(10, log2(count+1) / log2(total+1) * 10)`.

**Sub-method B — Betweenness Centrality:**

1. On the original (non-reversed) dependency graph, calculate the
   betweenness centrality of the component being evaluated.
2. This measures how often the component lies on the shortest dependency
   paths between *other* components — a proxy for how much it acts as a
   structural bridge in the dependency network, which is a different signal
   than raw dependent count (a component can be a critical bridge without
   having a huge number of direct/transitive dependents).
3. Scale the normalized betweenness value (0–1, as returned by
   `networkx.betweenness_centrality`) to a 0–10 score.

Sub-method B score: `betweenness_centrality * 10`.

**Combining the two sub-scores:** not yet finalized — a straight average is
the current working default (treats both signals as equally informative),
but taking the max (biasing toward whichever signal is more alarming for a
given component) is a reasonable alternative worth testing empirically
before locking this in. Document whichever choice is made, and why, in the
paper's methodology section.

**Score mapping:** each sub-method independently normalized to 0–10 as
described above; combined per the note directly above.

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

0. Resolve the component to a GitHub `owner/repo` first, since a Component
   doesn't carry that directly: prefer its declared `vcs_url` (from
   CycloneDX `externalReferences` of type `vcs`, once SBOM parsing
   populates it); otherwise fall back to the source-repo URL declared in
   the package's registry entry (PyPI `project_urls`, npm `repository`).
   If neither resolves to a `github.com` URL, treat it the same as "no
   Scorecard data" (step 4) — Scorecard's API and most of its checks are
   GitHub-specific.
1. Query the OSSF Scorecard public REST API
   (`https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}`)
   for the repository backing the dependency. This covers most popular OSS
   packages already — no need to run the Scorecard CLI yourself unless a
   dependency isn't indexed.
2. Pull **individual check scores**, not just Scorecard's bundled aggregate,
   so a custom weighted sub-formula can be built that matches this project's
   specific definition of "maintainer health". Finalized weights (sum to
   1.0):
   - `Maintained` — 0.20
   - `Signed-Releases` — 0.20
   - `Code-Review` — 0.20
   - `Contributors` — 0.20
   - `Branch-Protection` — 0.10
   - `Vulnerabilities` — 0.10
3. Scorecard returns `-1` for checks that are **not applicable** to a given
   project (e.g. `Code-Review` for a genuinely sole-maintainer repo), and the
   weekly-batch API can simply omit `Contributors` (and `CI-Tests`,
   `Dependency-Update-Tool`, which aren't in this sub-formula) entirely —
   both cases are treated identically: redistribute that check's weight
   proportionally across the remaining present, valid checks rather than
   treating it as a zero/failing score.
4. If Scorecard has no data at all for a repo (not yet indexed), or none of
   the six tracked checks are present/valid, default to a **neutral
   mid-score** (5.0), not a failing one — absence of data isn't evidence of
   poor maintenance. When fewer than 4 of the 6 checks are usable, the score
   is still reported (not defaulted) but flagged lower-confidence, since
   substantial redistribution happened.

**Score mapping:** weighted average of applicable Scorecard check scores
(each 0–10 natively), re-weighted per the sub-formula above; `5.0` default
when no Scorecard data exists (repo unresolvable or not indexed).
