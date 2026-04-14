"""Graph API routes — nodes, edges, neighborhood queries."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

router = APIRouter(tags=["graph"])


def _db(request: Request) -> sqlite3.Connection:
    return request.app.state.db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _node_row(row: sqlite3.Row) -> dict[str, Any]:
    extra: Any = row["extra"] or "{}"
    if isinstance(extra, str):
        try:
            extra = json.loads(extra)
        except Exception:
            extra = {}
    return {
        "id": row["id"],
        "kind": row["kind"],
        "name": row["name"],
        "qualified_name": row["qualified_name"],
        "file_path": row["file_path"],
        "line_start": row["line_start"],
        "line_end": row["line_end"],
        "language": row["language"],
        "parent_name": row["parent_name"],
        "params": row["params"],
        "return_type": row["return_type"],
        "is_test": bool(row["is_test"]),
        "extra": extra,
    }


def _edge_row(row: sqlite3.Row) -> dict[str, Any]:
    extra: Any = row["extra"] or "{}"
    if isinstance(extra, str):
        try:
            extra = json.loads(extra)
        except Exception:
            extra = {}
    return {
        "id": row["id"],
        "kind": row["kind"],
        "source": row["source_qualified"],
        "target": row["target_qualified"],
        "file_path": row["file_path"],
        "line": row["line"],
        "extra": extra,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/nodes")
def list_nodes(
    request: Request,
    kind: Optional[str] = Query(None, description="Filter by kind: File|Class|Function|Type|Test"),
    file_path: Optional[str] = Query(None, description="Filter by file path (substring)"),
    limit: int = Query(2000, ge=1, le=10000),
    offset: int = Query(0, ge=0),
) -> JSONResponse:
    """Return all graph nodes, with optional filters."""
    db = _db(request)
    params: list[Any] = []
    where_clauses: list[str] = []

    if kind:
        where_clauses.append("kind = ?")
        params.append(kind)
    if file_path:
        where_clauses.append("file_path LIKE ?")
        params.append(f"%{file_path}%")

    where = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    params.extend([limit, offset])

    rows = db.execute(
        f"SELECT * FROM nodes {where} ORDER BY kind, file_path, line_start LIMIT ? OFFSET ?",  # nosec B608
        params,
    ).fetchall()

    total = db.execute(
        f"SELECT COUNT(*) FROM nodes {where}",  # nosec B608
        params[:-2],
    ).fetchone()[0]

    return JSONResponse({"total": total, "nodes": [_node_row(r) for r in rows]})


@router.get("/edges")
def list_edges(
    request: Request,
    kind: Optional[str] = Query(None, description="Filter by kind: CALLS|IMPORTS_FROM|INHERITS|CONTAINS|..."),
    limit: int = Query(5000, ge=1, le=50000),
    offset: int = Query(0, ge=0),
) -> JSONResponse:
    """Return all graph edges."""
    db = _db(request)
    params: list[Any] = []
    where_clauses: list[str] = []

    if kind:
        where_clauses.append("kind = ?")
        params.append(kind)

    where = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    params.extend([limit, offset])

    rows = db.execute(
        f"SELECT * FROM edges {where} ORDER BY kind, source_qualified LIMIT ? OFFSET ?",  # nosec B608
        params,
    ).fetchall()

    return JSONResponse({"edges": [_edge_row(r) for r in rows]})


@router.get("/neighborhood")
def neighborhood(
    request: Request,
    qualified_name: str = Query(..., description="Fully qualified node name"),
    depth: int = Query(1, ge=1, le=3, description="Hop depth (1–3)"),
) -> JSONResponse:
    """Return a subgraph centered on a node up to N hops away.

    Returns nodes + edges that form the neighborhood, suitable for focused
    visualization when the full graph is too large.
    """
    db = _db(request)

    # Check root node exists
    root = db.execute(
        "SELECT * FROM nodes WHERE qualified_name = ?", (qualified_name,)
    ).fetchone()
    if not root:
        # Try case-insensitive fallback
        root = db.execute(
            "SELECT * FROM nodes WHERE LOWER(qualified_name) = LOWER(?)", (qualified_name,)
        ).fetchone()
    if not root:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"Node not found: {qualified_name}")

    visited_nodes: dict[str, dict] = {root["qualified_name"]: _node_row(root)}
    visited_edges: list[dict] = []
    frontier = {root["qualified_name"]}

    for _ in range(depth):
        next_frontier: set[str] = set()
        for qn in frontier:
            # Outgoing edges
            out_rows = db.execute(
                "SELECT * FROM edges WHERE source_qualified = ? LIMIT 100", (qn,)
            ).fetchall()
            for e in out_rows:
                visited_edges.append(_edge_row(e))
                target = e["target_qualified"]
                if target not in visited_nodes:
                    t_row = db.execute(
                        "SELECT * FROM nodes WHERE qualified_name = ?", (target,)
                    ).fetchone()
                    if t_row:
                        visited_nodes[target] = _node_row(t_row)
                        next_frontier.add(target)

            # Incoming edges
            in_rows = db.execute(
                "SELECT * FROM edges WHERE target_qualified = ? LIMIT 100", (qn,)
            ).fetchall()
            for e in in_rows:
                visited_edges.append(_edge_row(e))
                source = e["source_qualified"]
                if source not in visited_nodes:
                    s_row = db.execute(
                        "SELECT * FROM nodes WHERE qualified_name = ?", (source,)
                    ).fetchone()
                    if s_row:
                        visited_nodes[source] = _node_row(s_row)
                        next_frontier.add(source)

        frontier = next_frontier

    # Deduplicate edges by id
    seen_edge_ids: set[int] = set()
    unique_edges: list[dict] = []
    for e in visited_edges:
        if e["id"] not in seen_edge_ids:
            seen_edge_ids.add(e["id"])
            unique_edges.append(e)

    return JSONResponse({
        "root": qualified_name,
        "nodes": list(visited_nodes.values()),
        "edges": unique_edges,
    })


@router.get("/search")
def search_nodes(
    request: Request,
    q: str = Query(..., min_length=1, description="Search query"),
    limit: int = Query(30, ge=1, le=200),
) -> JSONResponse:
    """Full-text search over node names."""
    db = _db(request)
    words = q.lower().split()
    conditions = ["(LOWER(name) LIKE ? OR LOWER(qualified_name) LIKE ?)" for _ in words]
    params: list[Any] = []
    for w in words:
        params.extend([f"%{w}%", f"%{w}%"])
    params.append(limit)
    where = " AND ".join(conditions)
    rows = db.execute(
        f"SELECT * FROM nodes WHERE {where} LIMIT ?",  # nosec B608
        params,
    ).fetchall()
    return JSONResponse({"results": [_node_row(r) for r in rows]})


@router.get("/flows")
def list_flows(
    request: Request,
    limit: int = Query(20, ge=1, le=100),
) -> JSONResponse:
    """Return pre-computed execution flows (if available)."""
    db = _db(request)
    # flows table is optional — may not exist in all DBs
    try:
        rows = db.execute(
            "SELECT * FROM flows ORDER BY criticality_score DESC LIMIT ?", (limit,)
        ).fetchall()
    except Exception:
        return JSONResponse({"flows": []})

    flows = []
    for r in rows:
        steps: Any = r["steps"] if "steps" in r.keys() else "[]"
        if isinstance(steps, str):
            try:
                steps = json.loads(steps)
            except Exception:
                steps = []
        flows.append({
            "id": r["id"],
            "entry_point": r["entry_point"],
            "sink": r["sink"],
            "criticality_score": r["criticality_score"],
            "steps": steps,
        })
    return JSONResponse({"flows": flows})


@router.get("/source")
def get_source(
    request: Request,
    file_path: str = Query(..., description="Absolute path to the source file"),
    line_start: int = Query(1, ge=1, description="First line of the node (1-based)"),
    line_end: int = Query(0, ge=0, description="Last line of the node (0 = same as line_start)"),
    context: int = Query(3, ge=0, le=20, description="Extra context lines before/after"),
) -> JSONResponse:
    """Return source lines for a graph node, with surrounding context.

    Response includes:
    - ``lines``: list of ``{number, text}`` dicts
    - ``highlight_start`` / ``highlight_end``: 1-based line numbers of the node body
    - ``language``: detected language (from file extension)
    """
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail=f"File not found: {file_path}")

    # Safety check — only serve files inside the scanned target
    target = Path(request.app.state.target)
    try:
        path.resolve().relative_to(target.resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail="File is outside the scanned target")

    if line_end == 0:
        line_end = line_start

    fetch_start = max(1, line_start - context)
    fetch_end = line_end + context

    try:
        raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    total = len(raw_lines)
    fetch_end = min(fetch_end, total)

    lines = [
        {"number": i + 1, "text": raw_lines[i]}
        for i in range(fetch_start - 1, fetch_end)
    ]

    ext_map = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".tsx": "typescript", ".jsx": "javascript",
        ".java": "java", ".go": "go", ".cs": "csharp",
        ".rb": "ruby", ".rs": "rust", ".cpp": "cpp", ".c": "c",
        ".yml": "yaml", ".yaml": "yaml", ".json": "json",
        ".sh": "bash", ".toml": "toml",
    }
    language = ext_map.get(path.suffix.lower(), "plaintext")

    return JSONResponse({
        "file_path": file_path,
        "language": language,
        "total_lines": total,
        "highlight_start": line_start,
        "highlight_end": line_end,
        "lines": lines,
    })
