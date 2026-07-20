"""Reachability dimension (weight 25% — DIMENSIONS.md #1).

Does execution ever reach the vulnerable function in this dependency?
Combines a baseline import check with a call-graph-based function-level
check.

Score mapping:
    not imported            -> 0 (high confidence)
    imported, unreachable   -> 2 (high confidence)
    indeterminate           -> 5 (default confidence)
    confirmed reachable     -> 10 (high confidence)
"""

from __future__ import annotations

import ast
from collections import deque
import os
from pathlib import Path

import networkx as nx

from sbom_scorer.composite import DimensionScore
from sbom_scorer.data_sources import osv_client


def score_reachability(component, cve_id: str, codebase_path: str) -> DimensionScore:
    """Score reachability for a component's CVE against a given codebase."""
    if not codebase_path or not os.path.exists(codebase_path):
        return DimensionScore(score=5.0, confidence="default")

    # Step 1: Package-level AST import check
    is_imported = _is_package_imported(component, codebase_path)
    if not is_imported:
        return DimensionScore(score=0.0, confidence="high")

    # Step 2: Extract target vulnerable function names from fix commit/advisory
    vulnerable_funcs = _identify_vulnerable_function(cve_id, component)
    if not vulnerable_funcs:
        # Fallback: Imported, but function-level data is unavailable -> Indeterminate
        return DimensionScore(score=5.0, confidence="default")

    # Step 3: Build static call graph and trace reachability via BFS
    call_graph, entry_points = _build_python_call_graph(codebase_path)
    if not call_graph or not entry_points:
        return DimensionScore(score=5.0, confidence="default")

    is_reachable = _is_function_reachable(call_graph, entry_points, vulnerable_funcs)
    if is_reachable is True:
        return DimensionScore(score=10.0, confidence="high")
    elif is_reachable is False:
        return DimensionScore(score=2.0, confidence="high")

    return DimensionScore(score=5.0, confidence="default")


def _is_package_imported(component, codebase_path: str) -> bool:
    """AST-parse imports across the codebase to check if package is used."""
    pkg_name = component.name.lower().replace("-", "_")

    for root, _, files in os.walk(codebase_path):
        for file in files:
            if not file.endswith(".py"):
                continue
            file_path = os.path.join(root, file)
            try:
                tree = ast.parse(Path(file_path).read_text(encoding="utf-8"), filename=file_path)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            if alias.name.split(".")[0].lower() == pkg_name:
                                return True
                    elif isinstance(node, ast.ImportFrom):
                        if node.module and node.module.split(".")[0].lower() == pkg_name:
                            return True
            except Exception:
                continue
    return False


def _identify_vulnerable_function(cve_id: str, component) -> list[str]:
    """Extract vulnerable function names from OSV references or fix metadata."""
    if not component.ecosystem or not component.version:
        return []

    try:
        data = osv_client.query_by_package(component.name, component.ecosystem, component.version)
    except Exception:
        return []

    vfuncs = []
    for vuln in data.get("vulns", []):
        aliases = vuln.get("aliases", []) + [vuln.get("id")]
        if cve_id in aliases or vuln.get("id") == cve_id:
            # Parse references for fix commit hints or affected signatures
            for ref in vuln.get("references", []):
                if ref.get("type") == "FIX":
                    # Parse trailing function names or commit diff metadata if available
                    url = ref.get("url", "")
                    if "#" in url:
                        vfuncs.append(url.split("#")[-1])
    return list(set(vfuncs))


def _build_python_call_graph(codebase_path: str) -> tuple[nx.DiGraph, set[str]]:
    """Build a static directed call graph from Python files using AST."""
    graph = nx.DiGraph()
    entry_points = set()

    for root, _, files in os.walk(codebase_path):
        for file in files:
            if not file.endswith(".py"):
                continue
            file_path = os.path.join(root, file)
            try:
                tree = ast.parse(Path(file_path).read_text(encoding="utf-8"), filename=file_path)
                current_func = None
                
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        current_func = node.name
                        graph.add_node(current_func)
                        # Assume main/cli or top-level functions act as entry points
                        if current_func in ("main", "cli", "run", "handler"):
                            entry_points.add(current_func)

                    elif isinstance(node, ast.Call) and current_func:
                        if isinstance(node.func, ast.Name):
                            called_func = node.func.id
                            graph.add_edge(current_func, called_func)
                        elif isinstance(node.func, ast.Attribute):
                            called_func = node.func.attr
                            graph.add_edge(current_func, called_func)
            except Exception:
                continue

    return graph, entry_points


def _is_function_reachable(
    call_graph: nx.DiGraph, entry_points: set[str], target_funcs: list[str]
) -> bool:
    """Run BFS traversal from entry points to trace vulnerable functions."""
    targets = set(target_funcs)
    visited = set()
    queue = deque(entry_points)

    while queue:
        node = queue.popleft()
        if node in targets:
            return True
        if node not in visited:
            visited.add(node)
            queue.extend(call_graph.successors(node))

    return False