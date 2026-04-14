"""Stats and scan-run API routes."""

from __future__ import annotations

import sqlite3
from typing import Any, Optional

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

router = APIRouter(tags=["stats"])


def _db(request: Request) -> sqlite3.Connection:
    return request.app.state.db


@router.get("/stats")
def get_stats(request: Request) -> JSONResponse:
    """Return summary counts for the dashboard header."""
    db = _db(request)
    target = request.app.state.target

    # Node counts by kind
    node_rows = db.execute(
        "SELECT kind, COUNT(*) as cnt FROM nodes GROUP BY kind"
    ).fetchall()
    nodes_by_kind = {r["kind"]: r["cnt"] for r in node_rows}

    # Edge counts by kind
    edge_rows = db.execute(
        "SELECT kind, COUNT(*) as cnt FROM edges GROUP BY kind"
    ).fetchall()
    edges_by_kind = {r["kind"]: r["cnt"] for r in edge_rows}

    # Findings summary
    finding_rows = db.execute(
        """SELECT
               severity,
               llm_verdict,
               COUNT(*) as cnt
           FROM findings
           GROUP BY severity, llm_verdict"""
    ).fetchall()

    findings_by_severity: dict[str, int] = {}
    findings_by_verdict: dict[str, int] = {}
    total_findings = 0
    for r in finding_rows:
        sev = r["severity"] or "UNKNOWN"
        verd = r["llm_verdict"] or "UNANALYSED"
        findings_by_severity[sev] = findings_by_severity.get(sev, 0) + r["cnt"]
        findings_by_verdict[verd] = findings_by_verdict.get(verd, 0) + r["cnt"]
        total_findings += r["cnt"]

    # Latest run
    latest_run = db.execute(
        "SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1"
    ).fetchone()

    return JSONResponse({
        "target": target,
        "graph": {
            "total_nodes": sum(nodes_by_kind.values()),
            "total_edges": sum(edges_by_kind.values()),
            "nodes_by_kind": nodes_by_kind,
            "edges_by_kind": edges_by_kind,
        },
        "findings": {
            "total": total_findings,
            "by_severity": findings_by_severity,
            "by_verdict": findings_by_verdict,
        },
        "latest_run": dict(latest_run) if latest_run else None,
    })


@router.get("/runs")
def list_runs(
    request: Request,
    limit: int = Query(20, ge=1, le=100),
) -> JSONResponse:
    """Return scan run history, newest first."""
    db = _db(request)
    rows = db.execute(
        "SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return JSONResponse({"runs": [dict(r) for r in rows]})


@router.get("/runs/{run_id}")
def get_run(request: Request, run_id: int) -> JSONResponse:
    """Return a single scan run."""
    db = _db(request)
    row = db.execute("SELECT * FROM scan_runs WHERE id = ?", (run_id,)).fetchone()
    if not row:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Run not found")
    return JSONResponse(dict(row))
