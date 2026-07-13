"""Java call graph construction — CodeQL wrapper.

Used by sbom_scorer.dimensions.reachability for function-level reachability
checks (DIMENSIONS.md #1, step 2) on Java codebases. Builds a CodeQL
database and runs a custom reachability query.
"""

from __future__ import annotations

import networkx as nx


def build_codeql_database(codebase_path: str) -> str:
    """Build a CodeQL database for a Java codebase.

    Returns:
        Path to the built CodeQL database.

    Raises:
        NotImplementedError: Always, in this scaffolding stub.
    """
    raise NotImplementedError


def run_reachability_query(database_path: str, target_function: str) -> bool:
    """Run a custom CodeQL reachability query against the database."""
    raise NotImplementedError
