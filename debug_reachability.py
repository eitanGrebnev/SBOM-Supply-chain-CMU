"""Diagnostic for sbom-scorer's Reachability dimension.

The normal code path (dimensions/reachability.score_reachability)
intentionally swallows every failure into an indeterminate 5.0 score rather
than raising, so a finding stuck at 5.0 doesn't tell you *which* of the
three pipeline steps (package-import check -> vulnerable-function
identification -> call-graph reachability) is failing, or why. This script
runs each step directly against a real component/CVE/codebase and prints
what actually happened at each one.

Usage (from the SBOM-Supply-chain-CMU directory, in the same venv you run
sbom-scorer from):

    python debug_reachability.py --codebase ./my-app \\
        --component org.apache.logging.log4j:log4j-core \\
        --component-version 2.14.1 \\
        --ecosystem Maven \\
        --cve CVE-2021-44228 --cve CVE-2021-45046

All arguments have defaults matching the log4j-core/Log4Shell case this
script was originally built to debug, so `python debug_reachability.py
--codebase ./path-to-reachability-test-app` alone also works.
"""

from __future__ import annotations

import argparse
import os
import shutil
import traceback

from sbom_scorer.data_sources import osv_client
from sbom_scorer.dimensions import reachability
from sbom_scorer.sbom_parser import Component

DEFAULT_COMPONENT_NAME = "org.apache.logging.log4j:log4j-core"
DEFAULT_COMPONENT_VERSION = "2.14.1"
DEFAULT_ECOSYSTEM = "Maven"
DEFAULT_CVE_IDS = ["CVE-2021-44228", "CVE-2021-45046"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--codebase", required=True,
        help="Path to the application source tree to check reachability against.",
    )
    parser.add_argument(
        "--component", default=DEFAULT_COMPONENT_NAME,
        help=f"Component name, ecosystem-formatted (e.g. 'groupId:artifactId' for Maven). "
             f"Default: {DEFAULT_COMPONENT_NAME!r}.",
    )
    parser.add_argument(
        "--component-version", default=DEFAULT_COMPONENT_VERSION,
        help=f"Component version. Default: {DEFAULT_COMPONENT_VERSION!r}.",
    )
    parser.add_argument(
        "--ecosystem", default=DEFAULT_ECOSYSTEM,
        help=f"OSV ecosystem string, e.g. 'Maven' or 'PyPI'. Default: {DEFAULT_ECOSYSTEM!r}.",
    )
    parser.add_argument(
        "--cve", dest="cve_ids", action="append",
        help="CVE id to check (repeatable). Default: the two Log4Shell CVEs.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    cve_ids = args.cve_ids or DEFAULT_CVE_IDS
    component = Component(name=args.component, version=args.component_version, ecosystem=args.ecosystem)
    is_java = args.ecosystem.lower() == "maven"

    print("=== Step 0: prerequisites ===")
    codeql = shutil.which("codeql")
    print(f"codeql on PATH: {codeql or 'NOT FOUND'}")
    print(f"codebase exists: {os.path.exists(args.codebase)}  ({args.codebase})")

    print("\n=== Step 1: package-import check ===")
    imported = (
        reachability._is_package_imported_java(component, args.codebase)
        if is_java
        else reachability._is_package_imported(component, args.codebase)
    )
    print(f"is_imported: {imported}")
    if not imported:
        print("--> score_reachability would return 0.0 here. Nothing further to check.")
        return

    for cve_id in cve_ids:
        print(f"\n=== Step 2: vulnerable-function identification for {cve_id} ===")
        try:
            data = osv_client.query_by_package(component.name, component.ecosystem, component.version)
        except Exception:
            print("query_by_package raised:")
            traceback.print_exc()
            continue

        matched = [
            v for v in data.get("vulns", [])
            if cve_id in (v.get("aliases", []) + [v.get("id")])
        ]
        print(f"OSV vulns matching {cve_id}: {len(matched)}")
        for v in matched:
            all_refs = v.get("references", [])
            print(f"  vuln id={v.get('id')}  all references ({len(all_refs)}):")
            for r in all_refs:
                print(f"    type={r.get('type')!r}  url={r.get('url')!r}")
                # _identify_vulnerable_function tries every reference's URL
                # (not just type=="FIX" — see reachability.py's docstring
                # for why), relying on _fetch_commit_diff's own URL-shape
                # check as the filter, so mirror that here per-reference.
                diff = reachability._fetch_commit_diff(r.get("url", ""))
                if diff is None:
                    print("      -> not a commit/PR-shaped GitHub URL (or the request failed), skipped")
                else:
                    funcs = reachability._function_names_from_diff(diff)
                    print(f"      -> diff fetched OK ({len(diff)} chars), extracted function names: {sorted(funcs)}")

        vulnerable_funcs = reachability._identify_vulnerable_function(cve_id, component)
        print(f"_identify_vulnerable_function({cve_id!r}) -> {vulnerable_funcs}")
        if not vulnerable_funcs:
            print("--> score_reachability would return 5.0 (indeterminate) here for this CVE.")
            continue

        if not is_java:
            print("\n=== Step 3: Python call graph ===")
            call_graph, entry_points = reachability._build_python_call_graph(args.codebase)
            print(f"entry points found: {sorted(entry_points)}")
            if not call_graph or not entry_points:
                print("--> score_reachability would return 5.0 (indeterminate): no call graph/entry points.")
                continue
            result = reachability._is_function_reachable(call_graph, entry_points, vulnerable_funcs)
            print(f"_is_function_reachable(...) -> {result}")
            continue

        print("\n=== Step 3: CodeQL reachability ===")
        if not codeql:
            print("--> No codeql binary on PATH; score_reachability would return 5.0 (indeterminate).")
            continue

        from sbom_scorer.callgraph import java_callgraph

        try:
            print("Building CodeQL database (this can take a few minutes)...")
            db_path = java_callgraph.build_codeql_database(args.codebase)
            print(f"Database built at: {db_path}")
        except Exception:
            print("build_codeql_database raised:")
            traceback.print_exc()
            continue

        for func in vulnerable_funcs:
            try:
                result = java_callgraph.run_reachability_query(db_path, func)
                print(f"run_reachability_query(db, {func!r}) -> {result}")
            except Exception:
                print(f"run_reachability_query(db, {func!r}) raised:")
                traceback.print_exc()


if __name__ == "__main__":
    main()
