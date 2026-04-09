"""Integration test: full scan pipeline against VulnRez fixture."""

import json
from pathlib import Path

import pytest

VULNREZ = Path(__file__).parent / "fixtures" / "vulnrez"


@pytest.fixture(scope="module")
def scan_results(tmp_path_factory):
    """Run the full scanner once for all tests in this module."""
    db_dir = tmp_path_factory.mktemp("scan_db")

    from graphsast.vuln_db.store import VulnStore
    from graphsast.vuln_db.loader import load_all
    from graphsast.graph_db.store import SecurityGraphStore
    from graphsast.ingestion.pipeline import IngestionPipeline
    from graphsast.analysis.scanner import Scanner

    vuln_db = VulnStore(db_dir / "vulns.db")
    load_all(vuln_db, project_root=Path(__file__).parent.parent, sources=["builtin", "custom"])

    graph = SecurityGraphStore(db_dir / "graph.db")
    pipeline = IngestionPipeline(graph, vuln_db=vuln_db, incremental=False)
    pipeline.run(VULNREZ)

    scanner = Scanner(graph, vuln_db=vuln_db, run_semgrep=False)
    findings, summary = scanner.scan(VULNREZ)

    yield findings, summary

    graph.close()
    vuln_db.close()


def test_scan_produces_findings(scan_results):
    findings, summary = scan_results
    assert len(findings) > 0
    assert summary["findings_after_correlation"] == len(findings)


def test_sqli_findings_present(scan_results):
    findings, _ = scan_results
    sqli = [f for f in findings if f.cwe_id == "CWE-89"]
    assert len(sqli) >= 3, f"Expected ≥3 SQL injection findings, got {len(sqli)}"


def test_cmdi_findings_present(scan_results):
    findings, _ = scan_results
    cmdi = [f for f in findings if f.cwe_id in ("CWE-78", "CWE-95")]
    assert len(cmdi) >= 1, "Expected command injection or eval injection finding"


def test_path_traversal_present(scan_results):
    findings, _ = scan_results
    pt = [f for f in findings if f.cwe_id == "CWE-22"]
    assert len(pt) >= 1, "Expected path traversal finding"


def test_missing_auth_present(scan_results):
    findings, _ = scan_results
    auth = [f for f in findings if f.cwe_id == "CWE-306"]
    assert len(auth) >= 1, "Expected missing authentication finding"


def test_high_severity_findings_present(scan_results):
    findings, _ = scan_results
    high = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    assert len(high) >= 3, f"Expected ≥3 HIGH/CRITICAL findings, got {len(high)}"


def test_graph_taint_source_present(scan_results):
    findings, _ = scan_results
    taint = [f for f in findings if "graph_taint" in f.sources]
    assert len(taint) >= 3, "Expected taint path findings"


def test_json_output(scan_results, tmp_path):
    findings, summary = scan_results
    from graphsast.output.json_report import to_json
    doc = to_json(findings, VULNREZ, scan_run_id="test", elapsed=0.1)
    rendered = json.dumps(doc)
    data = json.loads(rendered)
    assert data["summary"]["total"] == len(findings)
    assert "findings" in data
    assert data["summary"]["by_severity"]["HIGH"] >= 1


def test_sarif_output(scan_results):
    findings, _ = scan_results
    from graphsast.output.sarif import to_sarif
    doc = to_sarif(findings, VULNREZ, scan_run_id="test")
    rendered = json.dumps(doc)
    data = json.loads(rendered)
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    run = data["runs"][0]
    assert len(run["results"]) == len(findings)
    assert len(run["tool"]["driver"]["rules"]) >= 1


def test_markdown_output(scan_results):
    findings, summary = scan_results
    from graphsast.output.markdown import to_markdown
    md = to_markdown(findings, VULNREZ, elapsed=summary["elapsed_seconds"])
    assert "# GraphSAST Security Report" in md
    assert "SQL Injection" in md
    assert "HIGH" in md
