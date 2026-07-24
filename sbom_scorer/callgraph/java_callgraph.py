"""Java call graph construction — CodeQL wrapper.

Used by sbom_scorer.dimensions.reachability for function-level reachability
checks (DIMENSIONS.md #1, step 2) on Java codebases. Builds a CodeQL
database and runs a bundled reachability query against it.

Unlike the Python path (dimensions/reachability._build_python_call_graph),
which builds its own lightweight in-process call graph via `ast`, Java's
build-dependent semantics (generics, overloading, annotation-driven
frameworks like Spring) make a from-scratch static call graph unreliable
without a real compiler front end. CodeQL is used instead: it builds an
actual semantic database from the project's build (Maven/Gradle) and
answers reachability as a query rather than exposing a graph object, so
this module shells out to the `codeql` CLI rather than returning a
networkx.DiGraph the way python_callgraph.build_call_graph does.

Both `codeql database create` and `codeql query run`/`bqrs decode` require
the CodeQL CLI (https://github.com/github/codeql-cli-binaries) on PATH.
Neither is available in this sandbox — this module degrades to raising
RuntimeError when the binary is missing, and callers
(dimensions.reachability) treat that as "indeterminate", the same as when
the Python path's call graph can't be built.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

# CodeQL builds a real build database, which for a nontrivial Maven/Gradle
# project can take several minutes.
CODEQL_TIMEOUT_SECONDS = 1800
CODEQL_LANGUAGE = "java"

# Bundled CodeQL query (see _REACHABILITY_QUERY below) that reports every
# method name reachable from Java entry points (main methods, and
# annotation-driven framework entry points: servlet/controller handlers,
# webhook/listener callbacks). Reachability for a specific target function
# is then just Python-side set membership against this query's results,
# which keeps the query itself target-independent (build once, reuse across
# every CVE/finding checked against the same database) rather than
# re-running CodeQL per vulnerable-function name.
_REACHABILITY_QUERY = """\
/**
 * @name Methods reachable from application entry points
 * @description Reports the (unqualified) name of every method reachable,
 *   via the static call graph, from a recognized entry point: `public
 *   static void main` methods, and methods annotated with common
 *   servlet/webhook/controller handler annotations. Consumed by
 *   sbom_scorer's Reachability dimension, which checks a specific
 *   vulnerable function name against this result set rather than
 *   re-querying per function.
 * @kind problem
 * @id java/sbom-scorer-reachable-methods
 */

import java

predicate isEntryPoint(Method m) {
  m.hasName("main") and m.isStatic() and m.isPublic()
  or
  exists(Annotation a |
    a = m.getAnAnnotation() and
    a.getType().hasQualifiedName(_, [
        "RequestMapping", "GetMapping", "PostMapping", "PutMapping",
        "DeleteMapping", "WebServlet", "EventListener"
      ])
  )
}

// polyCalls is CodeQL's virtual-dispatch-aware call edge (Member.qll):
// caller.polyCalls(callee) holds if caller may invoke callee at runtime,
// including through overriding. `*` takes the reflexive-transitive
// closure, so an entry point that IS the vulnerable method also counts as
// reaching it.
from Method entry, Method reached
where isEntryPoint(entry) and entry.polyCalls*(reached)
select reached, reached.getName()
"""


def build_codeql_database(codebase_path: str, database_path: str | None = None) -> str:
    """Build a CodeQL database for a Java codebase.

    Shells out to `codeql database create --language=java`. Requires the
    codebase to be a buildable Maven/Gradle project — CodeQL's Java
    extractor traces an actual build to resolve the semantic call graph
    (generics, overload resolution, etc.), it doesn't parse source text
    standalone the way the Python path's `ast`-based walker does.

    Args:
        codebase_path: Path to the Java application's project root.
        database_path: Where to write the CodeQL database. Defaults to
            `<codebase_path>/.codeql-db`.

    Returns:
        Path to the built CodeQL database.

    Raises:
        RuntimeError: If the `codeql` CLI isn't on PATH, `codebase_path`
            doesn't exist, or database creation exits non-zero.
        subprocess.TimeoutExpired: If the build exceeds
            CODEQL_TIMEOUT_SECONDS.
    """
    if not codebase_path or not os.path.exists(codebase_path):
        raise RuntimeError(f"codebase_path does not exist: {codebase_path!r}")

    binary = _require_codeql_binary()
    db_path = database_path or str(Path(codebase_path) / ".codeql-db")

    cmd = [
        binary,
        "database",
        "create",
        db_path,
        f"--language={CODEQL_LANGUAGE}",
        f"--source-root={codebase_path}",
        "--overwrite",
    ]
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=CODEQL_TIMEOUT_SECONDS
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"codeql database create failed (exit {result.returncode}) for "
            f"{codebase_path}: {(result.stderr or result.stdout).strip()}"
        )
    return db_path


def run_reachability_query(database_path: str, target_function: str) -> bool:
    """Run the bundled reachability query and check for `target_function`.

    Runs `codeql query run` against `database_path` with the bundled
    _REACHABILITY_QUERY, decodes the resulting BQRS to JSON via
    `codeql bqrs decode`, and checks whether `target_function` (matched as
    an unqualified method name, consistent with how
    dimensions.reachability._identify_vulnerable_function extracts bare
    names from fix-commit diffs) appears among the reachable methods.

    Args:
        database_path: Path to a CodeQL database built by
            build_codeql_database().
        target_function: The (unqualified) method name to check
            reachability for.

    Returns:
        True if `target_function` is among the methods the query reports
        reachable from an entry point, False if the query ran cleanly and
        it wasn't.

    Raises:
        RuntimeError: If the `codeql` CLI isn't on PATH, or the query
            run/decode step exits non-zero or returns unparseable output.
        subprocess.TimeoutExpired: If the query exceeds
            CODEQL_TIMEOUT_SECONDS.
    """
    binary = _require_codeql_binary()
    reachable = _run_reachability_query_all(binary, database_path)
    return target_function in reachable


def _run_reachability_query_all(binary: str, database_path: str) -> set[str]:
    """Run the bundled query once and return every reachable method name."""
    import tempfile

    with tempfile.TemporaryDirectory(prefix="sbom-scorer-codeql-query-") as tmp_dir:
        query_path = Path(tmp_dir) / "reachable_methods.ql"
        query_path.write_text(_REACHABILITY_QUERY, encoding="utf-8")
        results_path = Path(tmp_dir) / "results.bqrs"

        run_cmd = [
            binary,
            "query",
            "run",
            f"--database={database_path}",
            f"--output={results_path}",
            str(query_path),
        ]
        run_result = subprocess.run(
            run_cmd, capture_output=True, text=True, timeout=CODEQL_TIMEOUT_SECONDS
        )
        if run_result.returncode != 0:
            raise RuntimeError(
                f"codeql query run failed (exit {run_result.returncode}) "
                f"against {database_path}: "
                f"{(run_result.stderr or run_result.stdout).strip()}"
            )

        decode_cmd = [
            binary,
            "bqrs",
            "decode",
            "--format=json",
            str(results_path),
        ]
        decode_result = subprocess.run(
            decode_cmd, capture_output=True, text=True, timeout=120
        )
        if decode_result.returncode != 0:
            raise RuntimeError(
                f"codeql bqrs decode failed (exit {decode_result.returncode}): "
                f"{(decode_result.stderr or decode_result.stdout).strip()}"
            )

        try:
            payload = json.loads(decode_result.stdout)
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"codeql bqrs decode returned non-JSON output: {e}"
            ) from e

    return _method_names_from_bqrs_json(payload)


def _method_names_from_bqrs_json(payload: dict) -> set[str]:
    """Pull method-name strings out of `codeql bqrs decode --format=json` output.

    The decoded shape is `{"#select": {"columns": [...], "tuples": [[...],
    ...]}}` — each tuple is one result row (`reached`, `reached.getName()`
    per the query's `select` clause); the method name is the row's last
    (string) column.
    """
    names: set[str] = set()
    tuples = (payload.get("#select") or {}).get("tuples") or []
    for row in tuples:
        if not row:
            continue
        name = row[-1]
        if isinstance(name, str):
            names.add(name)
    return names


def _require_codeql_binary() -> str:
    binary = shutil.which("codeql")
    if not binary:
        raise RuntimeError(
            "The `codeql` CLI isn't available on PATH — install it "
            "(https://github.com/github/codeql-cli-binaries) to enable "
            "Java call-graph reachability checks. Without it, Java "
            "components fall back to indeterminate Reachability scoring."
        )
    return binary
