"""Integration test: ingestion pipeline against VulnRez fixture."""

import shutil
import tempfile
from pathlib import Path

import pytest

VULNREZ = Path(__file__).parent / "fixtures" / "vulnrez"
CUSTOM_RULES = Path(__file__).parent.parent / ".graphsast" / "custom"


@pytest.fixture(scope="module")
def built_graph(tmp_path_factory):
    """Build graph + vuln DB once for all tests in this module."""
    db_dir = tmp_path_factory.mktemp("db")

    from graphsast.vuln_db.store import VulnStore
    from graphsast.vuln_db.loader import load_all
    from graphsast.graph_db.store import SecurityGraphStore
    from graphsast.ingestion.pipeline import IngestionPipeline

    # Load vuln DB (built-in rules + custom signatures)
    vuln_db = VulnStore(db_dir / "vulns.db")
    load_all(vuln_db, project_root=Path(__file__).parent.parent)

    # Build graph
    graph = SecurityGraphStore(db_dir / "graph.db")
    pipeline = IngestionPipeline(graph, vuln_db=vuln_db, incremental=False)
    summary = pipeline.run(VULNREZ)

    yield graph, vuln_db, summary

    graph.close()
    vuln_db.close()


def test_vuln_db_has_signatures(built_graph):
    _, vuln_db, _ = built_graph
    stats = vuln_db.stats()
    assert stats["vuln_classes"] >= 4
    assert stats["taint_signatures"] >= 20


def test_entry_points_detected(built_graph):
    graph, _, _ = built_graph
    eps = graph.get_entry_points()
    ep_names = {qn.split("::")[-1] for qn in eps}
    # All Flask route handlers should be entry points
    assert "get_user" in ep_names
    assert "search_users" in ep_names
    assert "login" in ep_names
    assert "ping" in ep_names
    assert "run_command" in ep_names
    assert "read_file" in ep_names
    # Safe route is also an entry point
    assert "get_user_safe" in ep_names


def test_sinks_annotated(built_graph):
    graph, _, _ = built_graph
    sinks = graph.get_all_sinks()
    assert "execute" in sinks
    assert "eval" in sinks
    assert "open" in sinks
    assert "popen" in sinks


def test_call_args_concatenation_detected(built_graph):
    graph, _, _ = built_graph
    # get_user calls execute with a concatenated string (via variable)
    args = graph.get_call_args("execute")
    by_func = {a.source_qn.split("::")[-1]: a for a in args}

    # login: percent format concat
    login_arg = next(
        (a for a in args if "login" in a.source_qn and a.arg_type == "percent_format"), None
    )
    assert login_arg is not None
    assert login_arg.is_concatenated

    # search_users: f-string
    search_arg = next(
        (a for a in args if "search_users" in a.source_qn and a.arg_type == "f_string"), None
    )
    assert search_arg is not None
    assert search_arg.is_concatenated


def test_parameterised_query_not_concat(built_graph):
    graph, _, _ = built_graph
    # get_user_safe uses parameterised query — should have is_parameterised=True
    args = graph.get_call_args("execute")
    safe_args = [a for a in args if "get_user_safe" in a.source_qn]
    assert any(a.is_parameterised for a in safe_args), \
        "Parameterised query in get_user_safe should be flagged as safe"
    # And NOT concatenated
    assert not any(a.is_concatenated for a in safe_args), \
        "Parameterised query should NOT be flagged as concatenated"


def test_taint_paths_found(built_graph):
    graph, _, _ = built_graph
    paths = graph.find_taint_paths()
    sink_funcs = {p["source_qn"].split("::")[-1] for p in paths}

    # These should all have taint paths to sinks
    assert "get_user" in sink_funcs       # concat via variable
    assert "search_users" in sink_funcs   # f-string
    assert "login" in sink_funcs          # percent format
    assert "ping" in sink_funcs           # command injection
    assert "read_file" in sink_funcs      # path traversal
    assert "run_command" in sink_funcs    # eval


def test_safe_route_no_taint_path(built_graph):
    graph, _, _ = built_graph
    paths = graph.find_taint_paths()
    # get_user_safe uses parameterised query — should NOT be in taint paths
    unsafe = [p for p in paths if "get_user_safe" in p["source_qn"]]
    assert len(unsafe) == 0, f"get_user_safe falsely flagged: {unsafe}"


def test_missing_checks(built_graph):
    graph, _, _ = built_graph
    mcs = graph.get_all_missing_checks()
    assert len(mcs) > 0
    types = {mc.missing_type for mc in mcs}
    assert "auth" in types
    assert "rate_limit" in types
