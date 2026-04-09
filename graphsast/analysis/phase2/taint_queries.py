"""Phase 2 Pass B — Graph taint BFS queries.

Wraps SecurityGraphStore.find_taint_paths() and get_all_missing_checks()
into the standard Phase 2 finding format.
"""

from __future__ import annotations

import logging

from graphsast.graph_db.store import SecurityGraphStore

logger = logging.getLogger(__name__)


def run_taint_queries(graph: SecurityGraphStore) -> list[dict]:
    """Run taint path BFS and missing check queries.

    Returns a list of finding dicts with ``source`` field set to
    ``"graph_taint"`` or ``"missing_check"``.
    """
    findings: list[dict] = []

    # Taint paths
    taint_paths = graph.find_taint_paths()
    logger.info("Graph taint BFS: %d taint paths found", len(taint_paths))

    for p in taint_paths:
        # Map arg_type to a severity hint
        severity = _arg_type_to_severity(p.get("arg_type", ""))
        cwe = _sink_to_cwe(graph, p["sink_qn"])

        findings.append({
            "source": "graph_taint",
            "rule_id": f"taint:{p['sink_qn']}",
            "vuln_class_id": "",
            "cwe_id": cwe,
            "severity": severity,
            "message": _taint_message(p),
            "file_path": p.get("file_path", ""),
            "line_start": p.get("line", 0),
            "line_end": p.get("line", 0),
            "qualified_name": p["source_qn"],
            "confidence": "HIGH" if p.get("is_concatenated") else "MEDIUM",
            "extra": {
                "sink_qn": p["sink_qn"],
                "arg_type": p.get("arg_type"),
                "arg_position": p.get("arg_position"),
                "is_concatenated": p.get("is_concatenated"),
                "contains_var": p.get("contains_var"),
                "taint_path": p.get("path", []),
            },
        })

    # Missing checks
    missing = graph.get_all_missing_checks()
    logger.info("Missing check detector: %d entries", len(missing))

    for mc in missing:
        findings.append({
            "source": "missing_check",
            "rule_id": f"missing:{mc.missing_type}",
            "vuln_class_id": "",
            "cwe_id": _missing_type_to_cwe(mc.missing_type),
            "severity": _missing_type_to_severity(mc.missing_type),
            "message": f"Entry point has no {mc.missing_type} check in call chain",
            "file_path": _ep_to_file(graph, mc.entry_point_qn),
            "line_start": _ep_to_line(graph, mc.entry_point_qn),
            "line_end": _ep_to_line(graph, mc.entry_point_qn),
            "qualified_name": mc.entry_point_qn,
            "confidence": "MEDIUM",
            "extra": {
                "missing_type": mc.missing_type,
                "entry_point_qn": mc.entry_point_qn,
                "expected_patterns": mc.check_patterns,
            },
        })

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _arg_type_to_severity(arg_type: str) -> str:
    return {
        "binary_op": "HIGH",
        "f_string": "HIGH",
        "percent_format": "MEDIUM",
        "identifier": "MEDIUM",
    }.get(arg_type, "MEDIUM")


def _sink_to_cwe(graph: SecurityGraphStore, sink_qn: str) -> str:
    """Look up CWE for a sink from taint_annotations."""
    row = graph._conn.execute(
        "SELECT cwe_id FROM taint_annotations WHERE node_qn = ? AND annotation_type = 'SINK' LIMIT 1",
        (sink_qn,),
    ).fetchone()
    return (row["cwe_id"] or "") if row else ""


def _taint_message(p: dict) -> str:
    arg_type = p.get("arg_type", "")
    sink = p["sink_qn"].split("::")[-1] if "::" in p["sink_qn"] else p["sink_qn"]
    arg_desc = {
        "binary_op": "string concatenation (+)",
        "f_string": "f-string interpolation",
        "percent_format": "percent-format string (%)",
        "identifier": "variable (tainted)",
    }.get(arg_type, arg_type or "dynamic argument")
    return (
        f"Tainted data flows to '{sink}' via {arg_desc} "
        f"in '{p['source_qn'].split('::')[-1]}'"
    )


def _missing_type_to_cwe(missing_type: str) -> str:
    return {
        "auth": "CWE-306",
        "rate_limit": "CWE-770",
        "csrf": "CWE-352",
        "validation": "CWE-20",
    }.get(missing_type, "")


def _missing_type_to_severity(missing_type: str) -> str:
    return {
        "auth": "HIGH",
        "rate_limit": "MEDIUM",
        "csrf": "MEDIUM",
        "validation": "MEDIUM",
    }.get(missing_type, "LOW")


def _ep_to_file(graph: SecurityGraphStore, ep_qn: str) -> str:
    row = graph._conn.execute(
        "SELECT file_path FROM nodes WHERE qualified_name = ? LIMIT 1", (ep_qn,)
    ).fetchone()
    return row["file_path"] if row else ""


def _ep_to_line(graph: SecurityGraphStore, ep_qn: str) -> int:
    row = graph._conn.execute(
        "SELECT line_start FROM nodes WHERE qualified_name = ? LIMIT 1", (ep_qn,)
    ).fetchone()
    return row["line_start"] if row else 0
