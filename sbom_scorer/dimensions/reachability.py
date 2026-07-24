"""Reachability dimension (weight 25% — DIMENSIONS.md #1).

Does execution ever reach the vulnerable function in this dependency?
Combines a baseline import check with a call-graph-based function-level
check.

Two call-graph backends, per DIMENSIONS.md #1 step 2:
    - Python: an in-process `ast`-based walker (_build_python_call_graph).
    - Java (ecosystem == "Maven"): CodeQL, via
      sbom_scorer.callgraph.java_callgraph (_is_function_reachable_java).
Both are soft dependencies — if the relevant tooling can't build a call
graph (CodeQL not installed, dynamic Python constructs, etc.), reachability
falls back to indeterminate rather than guessing safe or unsafe.

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
import re
import shutil
from pathlib import Path

import networkx as nx

from sbom_scorer.composite import DimensionScore
from sbom_scorer.data_sources import osv_client


def score_reachability(component, cve_id: str, codebase_path: str) -> DimensionScore:
    """Score reachability for a component's CVE against a given codebase."""
    if not codebase_path or not os.path.exists(codebase_path):
        return DimensionScore(score=5.0, confidence="default")

    is_java = (component.ecosystem or "").lower() == "maven"

    # Step 1: Package-level import check
    is_imported = (
        _is_package_imported_java(component, codebase_path)
        if is_java
        else _is_package_imported(component, codebase_path)
    )
    if not is_imported:
        return DimensionScore(score=0.0, confidence="high")

    # Step 2: Extract target vulnerable function names from fix commit/advisory
    vulnerable_funcs = _identify_vulnerable_function(cve_id, component)
    if not vulnerable_funcs:
        # Fallback: Imported, but function-level data is unavailable -> Indeterminate
        return DimensionScore(score=5.0, confidence="default")

    # Step 3: Build a static call graph and trace reachability from entry points
    if is_java:
        is_reachable = _is_function_reachable_java(codebase_path, vulnerable_funcs)
    else:
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


_JAVA_IMPORT_RE_CACHE: dict[str, re.Pattern] = {}


def _is_package_imported_java(component, codebase_path: str) -> bool:
    """Text-scan .java files for an import of this component's Maven groupId.

    Component.name for Maven components is "groupId:artifactId"
    (sbom_parser._resolve_component_name). groupId is conventionally also
    the root of the Java package namespace the library ships under (e.g.
    groupId "org.apache.logging.log4j" -> classes under package
    "org.apache.logging.log4j.*"), so this checks for an
    `import <groupId>...;` statement (including wildcard imports) anywhere
    in the codebase. This mirrors _is_package_imported's role for the
    Python path: a cheap, no-false-negative-in-the-common-case baseline
    check, not the function-level check.
    """
    group_id = (component.name or "").split(":")[0]
    if not group_id:
        return False

    pattern = _JAVA_IMPORT_RE_CACHE.get(group_id)
    if pattern is None:
        pattern = re.compile(
            r"^\s*import\s+(?:static\s+)?" + re.escape(group_id) + r"(?:\.|\s*;)"
        )
        _JAVA_IMPORT_RE_CACHE[group_id] = pattern

    for root, _, files in os.walk(codebase_path):
        for file in files:
            if not file.endswith(".java"):
                continue
            file_path = os.path.join(root, file)
            try:
                text = Path(file_path).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for line in text.splitlines():
                if pattern.match(line):
                    return True
    return False


def _identify_vulnerable_function(cve_id: str, component) -> list[str]:
    """Extract vulnerable function names from the CVE's fix-commit diff.

    Per DIMENSIONS.md #1 step 3: pulls FIX references
    (`references[].type == "FIX"`) off the matching OSV vuln record, fetches
    each fix commit's unified diff, and extracts the names of functions the
    patch actually touched from the diff's hunk-header context lines — the
    `@@ -a,b +c,d @@ <context>` line git emits when it can identify the
    enclosing function/method the hunk falls inside.

    This replaces an earlier heuristic that guessed a function name from a
    URL fragment (e.g. treating "...commit/abc123#foo" as if "foo" were the
    vulnerable function). Real GitHub commit URLs in OSV/GHSA advisories
    essentially never carry a fragment like that, so that heuristic almost
    always returned nothing on real-world data.

    Deliberately does NOT filter references down to `type == "FIX"` first —
    verified against real OSV data (GHSA-jfh8-c2jp-5v3q / CVE-2021-44228,
    Log4Shell), an advisory can carry dozens of references and genuinely
    have none typed "FIX" at all, while still linking the actual fix under
    `type: "WEB"` (commonly as a pull-request URL, e.g.
    ".../pull/608", rather than a raw commit URL). `_fetch_commit_diff`
    already only accepts URLs shaped like a GitHub commit or PR permalink
    and no-ops (no network call) on anything else, so scanning every
    reference is a URL-shape check, not an unfiltered fetch storm.

    Returns an empty list (caller falls back to indeterminate) if no vuln
    record matches cve_id, or none of the references yielded a fetchable,
    parseable diff — never raises.
    """
    if not component.ecosystem or not component.version:
        return []

    try:
        data = osv_client.query_by_package(component.name, component.ecosystem, component.version)
    except Exception:
        return []

    vfuncs: set[str] = set()
    for vuln in data.get("vulns", []):
        aliases = vuln.get("aliases", []) + [vuln.get("id")]
        if cve_id not in aliases and vuln.get("id") != cve_id:
            continue
        for ref in vuln.get("references", []):
            diff_text = _fetch_commit_diff(ref.get("url", ""))
            if diff_text:
                vfuncs.update(_function_names_from_diff(diff_text))

    return list(vfuncs)


# Matches a GitHub commit permalink up through the commit SHA, or a pull
# request permalink up through the PR number — either way ignoring any
# trailing path segment, query string, or `#`-fragment (e.g. GitHub's own
# `#diff-<hash>` file anchors). We only need the base URL to append `.diff`
# to; GitHub serves a unified diff at that suffix for both commits and PRs.
# The PR case matters in practice, not just in theory: real GHSA advisories
# often link their fix as a PR URL under a generic "WEB" reference type
# rather than a "FIX"-typed raw commit URL.
_GITHUB_COMMIT_OR_PR_URL_RE = re.compile(
    r"^https?://github\.com/[^/\s]+/[^/\s]+/(?:commit/[0-9a-fA-F]{7,40}|pull/\d+)"
)


def _fetch_commit_diff(url: str) -> str | None:
    """Fetch a unified diff for a GitHub commit or pull-request URL.

    GitHub serves the raw unified diff for any commit or PR at
    `<url>.diff` with no authentication required, which is far simpler
    than going through the REST API for this. A PR's diff is the union of
    all its commits — noisier than a single commit's diff, but advisories
    frequently link the fix as a PR rather than a specific commit, so this
    is the more useful default over requiring an exact commit URL.

    Returns None (never raises) on a URL that isn't a recognizable GitHub
    commit/PR permalink, or any network/HTTP failure — callers treat that
    the same as "can't identify the function", not "confirmed safe/unsafe".
    """
    match = _GITHUB_COMMIT_OR_PR_URL_RE.match((url or "").strip())
    if not match:
        return None

    import requests

    try:
        response = requests.get(f"{match.group(0)}.diff", timeout=10)
        response.raise_for_status()
    except requests.RequestException:
        return None
    return response.text


# The hunk-header context git appends after the second "@@" when it can
# identify the enclosing function/method for that hunk (its default xfuncname
# heuristic, language-agnostic — works for Python "def"/"class" lines and
# C-family/Java-style "returnType name(args)" signatures alike).
_HUNK_HEADER_RE = re.compile(r"^@@ .*? @@\s*(.*)$")
_PY_DEF_RE = re.compile(r"\bdef\s+(\w+)\s*\(")
_IDENT_BEFORE_PAREN_RE = re.compile(r"(\w+)\s*\(")
# Control-flow keywords that can precede a "(" in a hunk-header context line
# (e.g. "if (x == null)") without being a function/method name.
_NON_FUNCTION_KEYWORDS = {
    "if", "for", "while", "switch", "catch", "return", "else", "new", "synchronized",
}


def _function_names_from_diff(diff_text: str) -> set[str]:
    """Extract candidate function names from a unified diff's hunk headers."""
    names: set[str] = set()
    for line in diff_text.splitlines():
        header_match = _HUNK_HEADER_RE.match(line)
        if not header_match:
            continue
        context = header_match.group(1).strip()
        if context:
            names.update(_function_names_from_context(context))
    return names


def _function_names_from_context(context: str) -> set[str]:
    """Pull a function/method name out of one hunk-header context line.

    Tries a Python-specific `def name(` match first (git's context line for
    a Python hunk is the literal `def`/`class` line), then falls back to a
    generic "identifier immediately before a paren, not a control-flow
    keyword" match, which covers Java/C-family method signatures like
    `public void processInput(String s)`.
    """
    py_match = _PY_DEF_RE.search(context)
    if py_match:
        return {py_match.group(1)}

    return {
        name
        for name in _IDENT_BEFORE_PAREN_RE.findall(context)
        if name not in _NON_FUNCTION_KEYWORDS
    }


def _build_python_call_graph(codebase_path: str) -> tuple[nx.DiGraph, set[str]]:
    """Build a static directed call graph from Python files using AST.

    Walks each file's AST recursively (depth-first), tracking which
    function body is currently being visited as a call stack rather than a
    single mutable variable — ast.walk() traverses breadth-first across the
    *whole* tree, so a flat "current_func" tracker gets clobbered by
    sibling function defs before their bodies are ever visited (e.g. two
    top-level functions both get visited before either function's body
    does), silently mis-attributing every call edge in a multi-function
    file. The recursive approach here correctly scopes calls to the
    function they're lexically inside.
    """
    graph = nx.DiGraph()
    entry_points = set()

    def _visit(node: ast.AST, current_func: str | None) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                graph.add_node(child.name)
                # Assume main/cli or top-level functions act as entry points
                if child.name in ("main", "cli", "run", "handler"):
                    entry_points.add(child.name)
                _visit(child, child.name)
                continue

            if isinstance(child, ast.Call) and current_func:
                if isinstance(child.func, ast.Name):
                    graph.add_edge(current_func, child.func.id)
                elif isinstance(child.func, ast.Attribute):
                    graph.add_edge(current_func, child.func.attr)

            _visit(child, current_func)

    for root, _, files in os.walk(codebase_path):
        for file in files:
            if not file.endswith(".py"):
                continue
            file_path = os.path.join(root, file)
            try:
                tree = ast.parse(Path(file_path).read_text(encoding="utf-8"), filename=file_path)
                _visit(tree, None)
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


def _is_function_reachable_java(codebase_path: str, target_funcs: list[str]) -> bool | None:
    """Build a CodeQL database and check reachability for any target function.

    Delegates to sbom_scorer.callgraph.java_callgraph — see DIMENSIONS.md
    #1 step 2 (Java: CodeQL, build a database, run a reachability query).

    Returns:
        True if any of target_funcs is confirmed reachable, False if a
        database was built and none were reachable, or None (indeterminate)
        if the `codeql` CLI isn't installed, the codebase isn't a buildable
        CodeQL-analyzable project, or any other error occurs. This is
        treated as a soft dependency: a missing CodeQL install degrades the
        score to indeterminate, the same way an unparseable Python file
        degrades _build_python_call_graph rather than raising.
    """
    if not shutil.which("codeql"):
        return None

    from sbom_scorer.callgraph import java_callgraph

    database_path = None
    try:
        database_path = java_callgraph.build_codeql_database(codebase_path)
        for func in target_funcs:
            if java_callgraph.run_reachability_query(database_path, func):
                return True
        return False
    except Exception:
        return None
    finally:
        if database_path:
            shutil.rmtree(database_path, ignore_errors=True)