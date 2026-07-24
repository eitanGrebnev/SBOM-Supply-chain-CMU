"""Tests for sbom_scorer.dimensions.reachability — DIMENSIONS.md #1.

Covers the documented score mapping:
    not imported            -> 0  (high confidence)
    imported, unreachable   -> 2  (high confidence)
    indeterminate           -> 5  (default confidence)
    confirmed reachable     -> 10 (high confidence)

and the fix-commit-diff-based vulnerable-function heuristic
(_identify_vulnerable_function / _fetch_commit_diff / _function_names_from_diff).
"""

from unittest.mock import Mock

import requests

from sbom_scorer.data_sources import osv_client
from sbom_scorer.dimensions import reachability
from sbom_scorer.dimensions.reachability import score_reachability
from sbom_scorer.sbom_parser import Component

COMMIT_URL = "https://github.com/example/somepkg/commit/" + "a" * 40
PR_URL = "https://github.com/example/somepkg/pull/608"
FIX_REF = {"type": "FIX", "url": COMMIT_URL}

# A minimal-but-realistic unified diff, as GitHub's `<commit>.diff` endpoint
# would return it, whose hunk header carries the enclosing function as
# context (git's own default behavior when it can identify one).
DIFF_WITH_VULNERABLE_FUNC = (
    "diff --git a/somepkg/core.py b/somepkg/core.py\n"
    "index 1111111..2222222 100644\n"
    "--- a/somepkg/core.py\n"
    "+++ b/somepkg/core.py\n"
    "@@ -10,7 +10,7 @@ def vulnerable_func(user_input):\n"
    "-    eval(user_input)\n"
    "+    safe_eval(user_input)\n"
)

DIFF_WITH_JAVA_METHOD = (
    "diff --git a/src/main/java/com/example/Handler.java b/src/main/java/com/example/Handler.java\n"
    "index 1111111..2222222 100644\n"
    "--- a/src/main/java/com/example/Handler.java\n"
    "+++ b/src/main/java/com/example/Handler.java\n"
    "@@ -42,7 +42,7 @@ public void processInput(String input) {\n"
    "-        Runtime.getRuntime().exec(input);\n"
    "+        Runtime.getRuntime().exec(sanitize(input));\n"
)


def _component(name="somepkg"):
    return Component(name=name, version="1.0.0", ecosystem="PyPI")


def _vuln_response(references):
    return {"vulns": [{"id": "CVE-2023-0001", "aliases": [], "references": references}]}


def test_no_codebase_path_is_indeterminate():
    result = score_reachability(_component(), "CVE-2023-0001", codebase_path=None)
    assert result.score == 5.0
    assert result.confidence == "default"


def test_nonexistent_codebase_path_is_indeterminate(tmp_path):
    missing = tmp_path / "does-not-exist"
    result = score_reachability(_component(), "CVE-2023-0001", codebase_path=str(missing))
    assert result.score == 5.0
    assert result.confidence == "default"


def test_package_not_imported_scores_zero(tmp_path):
    (tmp_path / "app.py").write_text("import otherpkg\n\ndef main():\n    otherpkg.run()\n")
    result = score_reachability(_component("somepkg"), "CVE-2023-0001", codebase_path=str(tmp_path))
    assert result.score == 0.0
    assert result.confidence == "high"


def test_imported_but_no_fix_metadata_is_indeterminate(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("import somepkg\n\ndef main():\n    somepkg.run()\n")
    monkeypatch.setattr(osv_client, "query_by_package", lambda *a, **k: {"vulns": [{"id": "CVE-2023-0001", "references": []}]})

    result = score_reachability(_component("somepkg"), "CVE-2023-0001", codebase_path=str(tmp_path))
    assert result.score == 5.0
    assert result.confidence == "default"


def test_imported_but_diff_fetch_fails_is_indeterminate(tmp_path, monkeypatch):
    # No network in this sandbox -> _fetch_commit_diff naturally returns None;
    # this pins that the whole pipeline still degrades to indeterminate
    # rather than raising.
    (tmp_path / "app.py").write_text("import somepkg\n\ndef main():\n    somepkg.run()\n")
    monkeypatch.setattr(osv_client, "query_by_package", lambda *a, **k: _vuln_response([FIX_REF]))

    result = score_reachability(_component("somepkg"), "CVE-2023-0001", codebase_path=str(tmp_path))
    assert result.score == 5.0
    assert result.confidence == "default"


def test_vulnerable_function_reachable_scores_ten(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(
        "import somepkg\n\n"
        "def main():\n"
        "    helper()\n\n"
        "def helper():\n"
        "    vulnerable_func()\n"
    )
    monkeypatch.setattr(osv_client, "query_by_package", lambda *a, **k: _vuln_response([FIX_REF]))
    monkeypatch.setattr(reachability, "_fetch_commit_diff", lambda url: DIFF_WITH_VULNERABLE_FUNC)

    result = score_reachability(_component("somepkg"), "CVE-2023-0001", codebase_path=str(tmp_path))
    assert result.score == 10.0
    assert result.confidence == "high"


def test_vulnerable_function_unreachable_scores_two(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(
        "import somepkg\n\n"
        "def main():\n"
        "    helper()\n\n"
        "def helper():\n"
        "    pass\n\n"
        "def vulnerable_func():\n"
        "    pass\n"
    )
    monkeypatch.setattr(osv_client, "query_by_package", lambda *a, **k: _vuln_response([FIX_REF]))
    monkeypatch.setattr(reachability, "_fetch_commit_diff", lambda url: DIFF_WITH_VULNERABLE_FUNC)

    result = score_reachability(_component("somepkg"), "CVE-2023-0001", codebase_path=str(tmp_path))
    assert result.score == 2.0
    assert result.confidence == "high"


# --- _identify_vulnerable_function / _fetch_commit_diff ------------------


def test_identify_vulnerable_function_no_fix_ref(monkeypatch):
    monkeypatch.setattr(osv_client, "query_by_package", lambda *a, **k: _vuln_response([]))
    result = reachability._identify_vulnerable_function("CVE-2023-0001", _component())
    assert result == []


def test_identify_vulnerable_function_extracts_from_diff(monkeypatch):
    monkeypatch.setattr(osv_client, "query_by_package", lambda *a, **k: _vuln_response([FIX_REF]))
    monkeypatch.setattr(reachability, "_fetch_commit_diff", lambda url: DIFF_WITH_VULNERABLE_FUNC)

    result = reachability._identify_vulnerable_function("CVE-2023-0001", _component())
    assert result == ["vulnerable_func"]


def test_identify_vulnerable_function_ignores_non_matching_cve(monkeypatch):
    monkeypatch.setattr(
        osv_client,
        "query_by_package",
        lambda *a, **k: {"vulns": [{"id": "CVE-2023-9999", "aliases": [], "references": [FIX_REF]}]},
    )
    monkeypatch.setattr(reachability, "_fetch_commit_diff", lambda url: DIFF_WITH_VULNERABLE_FUNC)

    result = reachability._identify_vulnerable_function("CVE-2023-0001", _component())
    assert result == []


def test_identify_vulnerable_function_does_not_require_fix_type(monkeypatch):
    # Regression test for a real-world OSV/GHSA record (Log4Shell,
    # GHSA-jfh8-c2jp-5v3q / CVE-2021-44228): the advisory has 75 references
    # and NONE are typed "FIX" — the fix is only linked as a "WEB"-typed PR
    # URL. The old FIX-type gate meant this always returned []; it must not
    # anymore.
    web_ref = {"type": "WEB", "url": PR_URL}
    monkeypatch.setattr(osv_client, "query_by_package", lambda *a, **k: _vuln_response([web_ref]))
    monkeypatch.setattr(reachability, "_fetch_commit_diff", lambda url: DIFF_WITH_VULNERABLE_FUNC)

    result = reachability._identify_vulnerable_function("CVE-2023-0001", _component())
    assert result == ["vulnerable_func"]


def test_identify_vulnerable_function_skips_non_commit_shaped_references(monkeypatch):
    # Dropping the FIX-type filter means every reference gets tried, but
    # _fetch_commit_diff's own URL-shape check should still reject ordinary
    # advisory/web links (NVD pages, vendor bulletins, etc.) without a
    # network call actually happening for them.
    refs = [
        {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-0001"},
        {"type": "WEB", "url": "https://example.com/blog/some-writeup"},
    ]
    monkeypatch.setattr(osv_client, "query_by_package", lambda *a, **k: _vuln_response(refs))
    fetch = Mock(return_value=None)
    monkeypatch.setattr(reachability, "_fetch_commit_diff", fetch)

    result = reachability._identify_vulnerable_function("CVE-2023-0001", _component())

    assert result == []
    # Still called (URL-shape filtering happens inside _fetch_commit_diff
    # itself), just never yields a diff for these.
    assert fetch.call_count == 2


def test_fetch_commit_diff_rejects_non_github_url():
    assert reachability._fetch_commit_diff("https://gitlab.com/example/repo/commit/abc123") is None


def test_fetch_commit_diff_rejects_empty_url():
    assert reachability._fetch_commit_diff("") is None
    assert reachability._fetch_commit_diff(None) is None


def test_fetch_commit_diff_requests_dot_diff_suffix(monkeypatch):
    response = Mock()
    response.raise_for_status.return_value = None
    response.text = DIFF_WITH_VULNERABLE_FUNC
    get = Mock(return_value=response)
    monkeypatch.setattr(requests, "get", get)

    result = reachability._fetch_commit_diff(COMMIT_URL)

    assert result == DIFF_WITH_VULNERABLE_FUNC
    get.assert_called_once_with(f"{COMMIT_URL}.diff", timeout=10)


def test_fetch_commit_diff_ignores_trailing_fragment(monkeypatch):
    response = Mock()
    response.raise_for_status.return_value = None
    response.text = DIFF_WITH_VULNERABLE_FUNC
    get = Mock(return_value=response)
    monkeypatch.setattr(requests, "get", get)

    reachability._fetch_commit_diff(f"{COMMIT_URL}#diff-abcdef")

    get.assert_called_once_with(f"{COMMIT_URL}.diff", timeout=10)


def test_fetch_commit_diff_returns_none_on_request_failure(monkeypatch):
    get = Mock(side_effect=requests.ConnectionError("no network"))
    monkeypatch.setattr(requests, "get", get)

    assert reachability._fetch_commit_diff(COMMIT_URL) is None


def test_fetch_commit_diff_accepts_pull_request_url(monkeypatch):
    response = Mock()
    response.raise_for_status.return_value = None
    response.text = DIFF_WITH_VULNERABLE_FUNC
    get = Mock(return_value=response)
    monkeypatch.setattr(requests, "get", get)

    result = reachability._fetch_commit_diff(PR_URL)

    assert result == DIFF_WITH_VULNERABLE_FUNC
    get.assert_called_once_with(f"{PR_URL}.diff", timeout=10)


def test_fetch_commit_diff_rejects_non_numeric_pull_path():
    assert reachability._fetch_commit_diff("https://github.com/example/somepkg/pull/") is None
    assert reachability._fetch_commit_diff("https://github.com/example/somepkg/pulls") is None


def test_fetch_commit_diff_returns_none_on_http_error(monkeypatch):
    response = Mock()
    response.raise_for_status.side_effect = requests.HTTPError("404")
    monkeypatch.setattr(requests, "get", Mock(return_value=response))

    assert reachability._fetch_commit_diff(COMMIT_URL) is None


# --- _function_names_from_diff / _function_names_from_context ------------


def test_function_names_from_diff_python():
    assert reachability._function_names_from_diff(DIFF_WITH_VULNERABLE_FUNC) == {"vulnerable_func"}


def test_function_names_from_diff_java_method_signature():
    assert reachability._function_names_from_diff(DIFF_WITH_JAVA_METHOD) == {"processInput"}


def test_function_names_from_diff_no_hunk_context():
    diff = (
        "diff --git a/f.py b/f.py\n"
        "--- a/f.py\n"
        "+++ b/f.py\n"
        "@@ -1,2 +1,2 @@\n"
        "-old\n"
        "+new\n"
    )
    assert reachability._function_names_from_diff(diff) == set()


def test_function_names_from_diff_multiple_hunks():
    diff = (
        "@@ -1,3 +1,3 @@ def first_func():\n"
        "-a\n"
        "+b\n"
        "@@ -10,3 +10,3 @@ def second_func():\n"
        "-c\n"
        "+d\n"
    )
    assert reachability._function_names_from_diff(diff) == {"first_func", "second_func"}


def test_function_names_from_context_filters_control_flow_keywords():
    assert reachability._function_names_from_context("if (x == null)") == set()
    assert reachability._function_names_from_context("for (int i = 0; i < n; i++)") == set()


def test_function_names_from_context_empty_string():
    assert reachability._function_names_from_context("") == set()


# --- Java path: _is_package_imported_java / _is_function_reachable_java --


def _java_component(group_id="com.example", artifact_id="somelib"):
    return Component(name=f"{group_id}:{artifact_id}", version="1.0.0", ecosystem="Maven")


def test_java_package_not_imported_scores_zero(tmp_path):
    (tmp_path / "App.java").write_text(
        "import com.other.Thing;\n\npublic class App {\n  public static void main(String[] a) {}\n}\n"
    )
    result = score_reachability(_java_component(), "CVE-2023-0001", codebase_path=str(tmp_path))
    assert result.score == 0.0
    assert result.confidence == "high"


def test_is_package_imported_java_matches_group_id_prefix(tmp_path):
    (tmp_path / "App.java").write_text("import com.example.somelib.Thing;\n")
    assert reachability._is_package_imported_java(_java_component(), str(tmp_path)) is True


def test_is_package_imported_java_matches_wildcard_import(tmp_path):
    (tmp_path / "App.java").write_text("import com.example.*;\n")
    assert reachability._is_package_imported_java(_java_component(), str(tmp_path)) is True


def test_is_package_imported_java_no_match(tmp_path):
    (tmp_path / "App.java").write_text("import com.other.Thing;\n")
    assert reachability._is_package_imported_java(_java_component(), str(tmp_path)) is False


def test_is_package_imported_java_empty_name_returns_false(tmp_path):
    (tmp_path / "App.java").write_text("import com.example.Thing;\n")
    assert reachability._is_package_imported_java(_java_component(group_id=""), str(tmp_path)) is False


def test_java_no_codeql_binary_is_indeterminate(tmp_path, monkeypatch):
    (tmp_path / "App.java").write_text("import com.example.somelib.Thing;\n")
    monkeypatch.setattr(osv_client, "query_by_package", lambda *a, **k: _vuln_response([FIX_REF]))
    monkeypatch.setattr(reachability, "_fetch_commit_diff", lambda url: DIFF_WITH_JAVA_METHOD)
    monkeypatch.setattr(reachability.shutil, "which", lambda name: None)

    result = score_reachability(_java_component(), "CVE-2023-0001", codebase_path=str(tmp_path))
    assert result.score == 5.0
    assert result.confidence == "default"


def test_java_reachable_scores_ten(tmp_path, monkeypatch):
    (tmp_path / "App.java").write_text("import com.example.somelib.Thing;\n")
    monkeypatch.setattr(osv_client, "query_by_package", lambda *a, **k: _vuln_response([FIX_REF]))
    monkeypatch.setattr(reachability, "_fetch_commit_diff", lambda url: DIFF_WITH_JAVA_METHOD)
    monkeypatch.setattr(reachability.shutil, "which", lambda name: "/usr/bin/codeql")

    from sbom_scorer.callgraph import java_callgraph

    monkeypatch.setattr(java_callgraph, "build_codeql_database", lambda path: "/tmp/fake-db")
    monkeypatch.setattr(java_callgraph, "run_reachability_query", lambda db, func: func == "processInput")
    monkeypatch.setattr(reachability.shutil, "rmtree", lambda *a, **k: None)

    result = score_reachability(_java_component(), "CVE-2023-0001", codebase_path=str(tmp_path))
    assert result.score == 10.0
    assert result.confidence == "high"


def test_java_unreachable_scores_two(tmp_path, monkeypatch):
    (tmp_path / "App.java").write_text("import com.example.somelib.Thing;\n")
    monkeypatch.setattr(osv_client, "query_by_package", lambda *a, **k: _vuln_response([FIX_REF]))
    monkeypatch.setattr(reachability, "_fetch_commit_diff", lambda url: DIFF_WITH_JAVA_METHOD)
    monkeypatch.setattr(reachability.shutil, "which", lambda name: "/usr/bin/codeql")

    from sbom_scorer.callgraph import java_callgraph

    monkeypatch.setattr(java_callgraph, "build_codeql_database", lambda path: "/tmp/fake-db")
    monkeypatch.setattr(java_callgraph, "run_reachability_query", lambda db, func: False)
    monkeypatch.setattr(reachability.shutil, "rmtree", lambda *a, **k: None)

    result = score_reachability(_java_component(), "CVE-2023-0001", codebase_path=str(tmp_path))
    assert result.score == 2.0
    assert result.confidence == "high"


def test_java_codeql_build_failure_is_indeterminate(tmp_path, monkeypatch):
    (tmp_path / "App.java").write_text("import com.example.somelib.Thing;\n")
    monkeypatch.setattr(osv_client, "query_by_package", lambda *a, **k: _vuln_response([FIX_REF]))
    monkeypatch.setattr(reachability, "_fetch_commit_diff", lambda url: DIFF_WITH_JAVA_METHOD)
    monkeypatch.setattr(reachability.shutil, "which", lambda name: "/usr/bin/codeql")

    from sbom_scorer.callgraph import java_callgraph

    def _raise(path):
        raise RuntimeError("codeql database create failed")

    monkeypatch.setattr(java_callgraph, "build_codeql_database", _raise)

    result = score_reachability(_java_component(), "CVE-2023-0001", codebase_path=str(tmp_path))
    assert result.score == 5.0
    assert result.confidence == "default"


def test_is_function_reachable_java_cleans_up_database(tmp_path, monkeypatch):
    monkeypatch.setattr(reachability.shutil, "which", lambda name: "/usr/bin/codeql")

    from sbom_scorer.callgraph import java_callgraph

    monkeypatch.setattr(java_callgraph, "build_codeql_database", lambda path: "/tmp/fake-db")
    monkeypatch.setattr(java_callgraph, "run_reachability_query", lambda db, func: True)
    rmtree = Mock()
    monkeypatch.setattr(reachability.shutil, "rmtree", rmtree)

    result = reachability._is_function_reachable_java(str(tmp_path), ["vulnerableMethod"])

    assert result is True
    rmtree.assert_called_once_with("/tmp/fake-db", ignore_errors=True)
