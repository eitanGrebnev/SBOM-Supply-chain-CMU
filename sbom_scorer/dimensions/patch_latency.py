"""Patch Latency dimension (weight 10% — DIMENSIONS.md #5).

Two distinct sub-cases, not one formula (per ARCHITECTURE.md / DIMENSIONS.md):
    - Fix exists, not yet applied: latency = time since fix release.
    - No fix exists yet: latency = time since disclosure (different, and
      worsening, risk type — "unpatchable exposure").

Data: OSV.dev for disclosure date + fixed version identifier
(sbom_scorer.data_sources.osv_client), package registries for the fixed
version's actual release timestamp (sbom_scorer.data_sources.registry_client).
"""

from __future__ import annotations

from typing import Any

from sbom_scorer.composite import DimensionScore


from datetime import datetime, timezone

def score_patch_latency(component: Any, cve_id: str) -> DimensionScore:
    """Score patch latency for a component's CVE.

    Args:
        component: The sbom_scorer.sbom_parser.Component under evaluation.
        cve_id: CVE identifier to look up via OSV.dev.

    Returns:
        DimensionScore with score in [0, 10] and a confidence flag.
    """
    from sbom_scorer.data_sources import osv_client, registry_client
    
    # 1. Query OSV
    res = osv_client.query_by_package(component.name, component.ecosystem, component.version)
    vulns = res.get("vulns", [])
    target_vuln = None
    for v in vulns:
        if v.get("id") == cve_id or cve_id in v.get("aliases", []):
            target_vuln = v
            break
            
    if not target_vuln:
        # Not found in OSV, indeterminate latency
        return DimensionScore(score=0.0, confidence="indeterminate")
        
    disclosure_date_str = target_vuln.get("published")
    if not disclosure_date_str:
        return DimensionScore(score=0.0, confidence="indeterminate")
        
    if disclosure_date_str.endswith("Z"):
        disclosure_date_str = disclosure_date_str[:-1] + "+00:00"
    disclosure_date = datetime.fromisoformat(disclosure_date_str).replace(tzinfo=timezone.utc)
    
    # 2. Find fixed version
    fixed_version = None
    for affected in target_vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    fixed_version = event["fixed"]
                    break
            if fixed_version: break
        if fixed_version: break
        
    now = datetime.now(timezone.utc)
    
    if fixed_version:
        release_date = registry_client.get_release_date(component.ecosystem, component.name, fixed_version)
        if release_date:
            days = (now - release_date).days
            score = _score_fix_exists(max(0, days))
            return DimensionScore(score=score, confidence="high")
            
    # No fix exists (or couldn't find release date for fix)
    days = (now - disclosure_date).days
    score = _score_no_fix_exists(max(0, days))
    return DimensionScore(score=score, confidence="high")


def _score_fix_exists(days_since_fix_release: int) -> float:
    """Score when a fix exists but may not yet be applied.

    0 days = 0, 60+ days unpatched = 10, linear/capped ramp in between.
    """
    if days_since_fix_release <= 0:
        return 0.0
    if days_since_fix_release >= 60:
        return 10.0
    return (days_since_fix_release / 60.0) * 10.0


def _score_no_fix_exists(days_since_disclosure: int) -> float:
    """Score when no fix exists yet — scales with time since disclosure.
    
    0 days = 0, 60+ days unpatchable = 10, linear/capped ramp in between.
    """
    if days_since_disclosure <= 0:
        return 0.0
    if days_since_disclosure >= 60:
        return 10.0
    return (days_since_disclosure / 60.0) * 10.0
