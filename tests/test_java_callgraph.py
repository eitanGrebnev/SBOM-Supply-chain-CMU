"""Tests for sbom_scorer.callgraph.java_callgraph — DIMENSIONS.md #1 step 2
(Java call-graph reachability via CodeQL).

CodeQL itself isn't available in this sandbox (no `codeql` binary, no Java
toolchain), so every test here mocks at the shutil.which/subprocess.run
boundary — the same pattern used for scorecard_client.run_scorecard_cli.
Real end-to-end validation of the bundled query happens on a machine with
CodeQL installed.
"""

import json
import subprocess
from unittest.mock import Mock

import pytest

from sbom_scorer.callgraph import java_callgraph


def _mock_run(returncode=0, stdout="", stderr=""):
    completed = Mock()
    completed.returncode = returncode
    completed.stdout = stdout
    completed.stderr = stderr
    return completed


# --- build_codeql_database -------------------------------------------------


def test_build_codeql_database_raises_without_codebase(tmp_path):
    missing = tmp_path / "does-not-exist"
    with pytest.raises(RuntimeError, match="does not exist"):
        java_callgraph.build_codeql_database(str(missing))


def test_build_codeql_database_raises_without_codeql_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(java_callgraph.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="codeql"):
        java_callgraph.build_codeql_database(str(tmp_path))


def test_build_codeql_database_invokes_cli(tmp_path, monkeypatch):
    monkeypatch.setattr(java_callgraph.shutil, "which", lambda name: "/usr/bin/codeql")
    run = Mock(return_value=_mock_run(0))
    monkeypatch.setattr(java_callgraph.subprocess, "run", run)

    db_path = java_callgraph.build_codeql_database(str(tmp_path))

    assert db_path == str(tmp_path / ".codeql-db")
    cmd = run.call_args.args[0]
    assert cmd[0] == "/usr/bin/codeql"
    assert "database" in cmd and "create" in cmd
    assert db_path in cmd
    assert "--language=java" in cmd
    assert f"--source-root={tmp_path}" in cmd


def test_build_codeql_database_uses_explicit_database_path(tmp_path, monkeypatch):
    monkeypatch.setattr(java_callgraph.shutil, "which", lambda name: "/usr/bin/codeql")
    run = Mock(return_value=_mock_run(0))
    monkeypatch.setattr(java_callgraph.subprocess, "run", run)
    custom_db = str(tmp_path / "custom-db")

    db_path = java_callgraph.build_codeql_database(str(tmp_path), database_path=custom_db)

    assert db_path == custom_db


def test_build_codeql_database_raises_on_nonzero_exit(tmp_path, monkeypatch):
    monkeypatch.setattr(java_callgraph.shutil, "which", lambda name: "/usr/bin/codeql")
    run = Mock(return_value=_mock_run(1, "", "extraction failed"))
    monkeypatch.setattr(java_callgraph.subprocess, "run", run)

    with pytest.raises(RuntimeError, match="extraction failed"):
        java_callgraph.build_codeql_database(str(tmp_path))


# --- run_reachability_query -------------------------------------------------


def test_run_reachability_query_raises_without_codeql_binary(monkeypatch):
    monkeypatch.setattr(java_callgraph.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="codeql"):
        java_callgraph.run_reachability_query("/some/db", "vulnerableMethod")


def test_run_reachability_query_true_when_target_in_results(monkeypatch, tmp_path):
    monkeypatch.setattr(java_callgraph.shutil, "which", lambda name: "/usr/bin/codeql")
    payload = {
        "#select": {
            "columns": [{"name": "reached"}, {"name": "name"}],
            "tuples": [
                [{"label": "safeMethod"}, "safeMethod"],
                [{"label": "vulnerableMethod"}, "vulnerableMethod"],
            ],
        }
    }
    run = Mock(
        side_effect=[
            _mock_run(0),  # query run
            _mock_run(0, json.dumps(payload)),  # bqrs decode
        ]
    )
    monkeypatch.setattr(java_callgraph.subprocess, "run", run)

    result = java_callgraph.run_reachability_query(str(tmp_path), "vulnerableMethod")

    assert result is True
    query_run_cmd = run.call_args_list[0].args[0]
    assert "query" in query_run_cmd and "run" in query_run_cmd
    decode_cmd = run.call_args_list[1].args[0]
    assert "bqrs" in decode_cmd and "decode" in decode_cmd


def test_run_reachability_query_false_when_target_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(java_callgraph.shutil, "which", lambda name: "/usr/bin/codeql")
    payload = {"#select": {"columns": [], "tuples": [[{"label": "otherMethod"}, "otherMethod"]]}}
    run = Mock(side_effect=[_mock_run(0), _mock_run(0, json.dumps(payload))])
    monkeypatch.setattr(java_callgraph.subprocess, "run", run)

    result = java_callgraph.run_reachability_query(str(tmp_path), "vulnerableMethod")

    assert result is False


def test_run_reachability_query_raises_when_query_run_fails(monkeypatch, tmp_path):
    monkeypatch.setattr(java_callgraph.shutil, "which", lambda name: "/usr/bin/codeql")
    run = Mock(return_value=_mock_run(1, "", "database not found"))
    monkeypatch.setattr(java_callgraph.subprocess, "run", run)

    with pytest.raises(RuntimeError, match="database not found"):
        java_callgraph.run_reachability_query(str(tmp_path), "vulnerableMethod")


def test_run_reachability_query_raises_when_decode_fails(monkeypatch, tmp_path):
    monkeypatch.setattr(java_callgraph.shutil, "which", lambda name: "/usr/bin/codeql")
    run = Mock(side_effect=[_mock_run(0), _mock_run(1, "", "decode error")])
    monkeypatch.setattr(java_callgraph.subprocess, "run", run)

    with pytest.raises(RuntimeError, match="decode error"):
        java_callgraph.run_reachability_query(str(tmp_path), "vulnerableMethod")


def test_run_reachability_query_raises_on_non_json_decode_output(monkeypatch, tmp_path):
    monkeypatch.setattr(java_callgraph.shutil, "which", lambda name: "/usr/bin/codeql")
    run = Mock(side_effect=[_mock_run(0), _mock_run(0, "not json")])
    monkeypatch.setattr(java_callgraph.subprocess, "run", run)

    with pytest.raises(RuntimeError, match="non-JSON"):
        java_callgraph.run_reachability_query(str(tmp_path), "vulnerableMethod")


def test_run_reachability_query_propagates_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr(java_callgraph.shutil, "which", lambda name: "/usr/bin/codeql")
    run = Mock(side_effect=subprocess.TimeoutExpired(cmd="codeql", timeout=1))
    monkeypatch.setattr(java_callgraph.subprocess, "run", run)

    with pytest.raises(subprocess.TimeoutExpired):
        java_callgraph.run_reachability_query(str(tmp_path), "vulnerableMethod")


# --- _method_names_from_bqrs_json -------------------------------------------


def test_method_names_from_bqrs_json_extracts_last_column():
    payload = {
        "#select": {
            "tuples": [
                [{"label": "a"}, "methodA"],
                [{"label": "b"}, "methodB"],
            ]
        }
    }
    assert java_callgraph._method_names_from_bqrs_json(payload) == {"methodA", "methodB"}


def test_method_names_from_bqrs_json_handles_missing_select():
    assert java_callgraph._method_names_from_bqrs_json({}) == set()


def test_method_names_from_bqrs_json_ignores_non_string_columns():
    payload = {"#select": {"tuples": [[{"label": "a"}, 42]]}}
    assert java_callgraph._method_names_from_bqrs_json(payload) == set()


def test_method_names_from_bqrs_json_ignores_empty_rows():
    payload = {"#select": {"tuples": [[]]}}
    assert java_callgraph._method_names_from_bqrs_json(payload) == set()
