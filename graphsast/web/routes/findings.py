"""Findings API routes."""

from __future__ import annotations

import sqlite3
from typing import Any, Optional

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

router = APIRouter(tags=["findings"])


def _db(request: Request) -> sqlite3.Connection:
    return request.app.state.db


_SEVERITY_ORDER = "CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END"


def _finding_row(row: sqlite3.Row) -> dict[str, Any]:
    return dict(row)


@router.get("")
def list_findings(
    request: Request,
    severity: Optional[str] = Query(None, description="CRITICAL|HIGH|MEDIUM|LOW"),
    verdict: Optional[str] = Query(None, description="CONFIRMED|FALSE_POSITIVE|NEEDS_REVIEW"),
    source: Optional[str] = Query(None, description="semgrep|hunter"),
    status: Optional[str] = Query(None, description="open|closed"),
    file_path: Optional[str] = Query(None, description="Filter by file path (substring)"),
    run_id: Optional[int] = Query(None, description="Filter to a specific scan run"),
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
) -> JSONResponse:
    """Return findings with optional filters."""
    db = _db(request)
    params: list[Any] = []
    where_clauses: list[str] = []

    if run_id is not None:
        where_clauses.append(
            "f.id IN (SELECT finding_id FROM run_findings WHERE run_id = ?)"
        )
        params.append(run_id)
    if severity:
        where_clauses.append("f.severity = ?")
        params.append(severity.upper())
    if verdict:
        where_clauses.append("f.llm_verdict = ?")
        params.append(verdict.upper())
    if source:
        where_clauses.append("f.source = ?")
        params.append(source)
    if status:
        where_clauses.append("f.status = ?")
        params.append(status)
    if file_path:
        where_clauses.append("f.file_path LIKE ?")
        params.append(f"%{file_path}%")

    where = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    count_params = list(params)
    params.extend([limit, offset])

    try:
        rows = db.execute(
            f"""SELECT f.* FROM findings f {where}
                ORDER BY {_SEVERITY_ORDER}, f.file_path, f.line_start
                LIMIT ? OFFSET ?""",  # nosec B608
            params,
        ).fetchall()

        total = db.execute(
            f"SELECT COUNT(*) FROM findings f {where}",  # nosec B608
            count_params,
        ).fetchone()[0]
    except Exception:
        # findings table doesn't exist yet (no scan has been run)
        return JSONResponse({"total": 0, "findings": []})

    return JSONResponse({"total": total, "findings": [_finding_row(r) for r in rows]})


@router.get("/{fingerprint}")
def get_finding(request: Request, fingerprint: str) -> JSONResponse:
    """Return a single finding by fingerprint."""
    db = _db(request)
    row = db.execute(
        "SELECT * FROM findings WHERE fingerprint = ?", (fingerprint,)
    ).fetchone()
    if not row:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Finding not found")
    return JSONResponse(_finding_row(row))
