"""Thin query wrapper over code_review_graph.GraphStore.

Provides the six graph navigation operations used by the MCP tools.
All queries are read-only; the graph is built by code_review_graph.
"""

from __future__ import annotations

import dataclasses
import logging
from collections import deque
from pathlib import Path
from typing import Optional

from code_review_graph.flows import get_flow_by_id as _crg_get_flow_by_id
from code_review_graph.flows import get_flows as _crg_get_flows
from code_review_graph.graph import GraphStore

logger = logging.getLogger(__name__)


class GraphClient:
    """Read-only interface to a code_review_graph SQLite database."""

    def __init__(self, db_path: Path, repo_root: Path) -> None:
        self._store = GraphStore(str(db_path))
        self._conn = self._store._conn
        self._repo_root = repo_root

    # ── Public API ─────────────────────────────────────────────────────────────

    def get_function(self, name: str) -> Optional[dict]:
        """Return metadata + source snippet for the best-matching function."""
        row = self._conn.execute(
            """SELECT kind, name, qualified_name, file_path,
                      line_start, line_end, language, params, return_type
               FROM nodes
               WHERE kind IN ('Function', 'Method')
                 AND (name = ? OR qualified_name = ? OR qualified_name LIKE ?)
               ORDER BY length(qualified_name) ASC
               LIMIT 1""",
            (name, name, f"%{name}%"),
        ).fetchone()
        if not row:
            return None

        result = dict(row)
        result["snippet"] = self._read_lines(
            result["file_path"], result["line_start"], result["line_end"]
        )
        return result

    def get_callers(self, name: str) -> list[dict]:
        """Return functions that call *name*."""
        rows = self._conn.execute(
            """SELECT DISTINCT e.source_qualified as qualified_name,
                      n.file_path, n.line_start
               FROM edges e
               LEFT JOIN nodes n ON n.qualified_name = e.source_qualified
               WHERE e.kind = 'CALLS'
                 AND (e.target_qualified = ? OR e.target_qualified LIKE ?)
               LIMIT 50""",
            (name, f"%{name}%"),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_callees(self, name: str) -> list[dict]:
        """Return functions called by *name*."""
        rows = self._conn.execute(
            """SELECT DISTINCT e.target_qualified as qualified_name,
                      n.file_path, n.line_start
               FROM edges e
               LEFT JOIN nodes n ON n.qualified_name = e.target_qualified
               WHERE e.kind = 'CALLS'
                 AND (e.source_qualified = ? OR e.source_qualified LIKE ?)
               LIMIT 50""",
            (name, f"%{name}%"),
        ).fetchall()
        return [dict(r) for r in rows]

    def read_file(
        self, path: str, start_line: Optional[int] = None, end_line: Optional[int] = None
    ) -> str:
        """Read a source file (or a line range of it).

        Resolves relative paths against repo_root.
        When start_line/end_line are given only those lines are returned,
        which keeps tool results small and context-window-friendly.
        """
        p = Path(path)
        if not p.is_absolute():
            p = self._repo_root / p
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return f"Error reading file: {exc}"

        if start_line is None and end_line is None:
            return text

        lines = text.splitlines()
        s = max(0, (start_line or 1) - 1)
        e = min(len(lines), end_line or len(lines))
        return "\n".join(lines[s:e])

    def get_file_summary(self, path: str) -> list[dict]:
        """Return all functions and classes in *path* with their line ranges.

        Gives the LLM a map of the file without reading the full source,
        so it can decide which specific function to read next.
        """
        # Normalise to absolute path for DB lookup
        p = Path(path)
        if not p.is_absolute():
            p = self._repo_root / p
        abs_path = str(p)

        rows = self._conn.execute(
            """SELECT kind, name, qualified_name, line_start, line_end
               FROM nodes
               WHERE file_path = ?
                 AND kind IN ('Function', 'Method', 'Class')
               ORDER BY line_start""",
            (abs_path,),
        ).fetchall()

        # If no exact match try a LIKE (handles path normalisation differences)
        if not rows:
            rows = self._conn.execute(
                """SELECT kind, name, qualified_name, line_start, line_end
                   FROM nodes
                   WHERE file_path LIKE ?
                     AND kind IN ('Function', 'Method', 'Class')
                   ORDER BY line_start""",
                (f"%{Path(path).name}%",),
            ).fetchall()

        return [dict(r) for r in rows]

    def list_entry_points(self) -> list[dict]:
        """Return functions that have no callers — likely public API / HTTP handlers.

        These are the starting points for attack-surface analysis.
        """
        rows = self._conn.execute(
            """SELECT n.kind, n.name, n.qualified_name, n.file_path,
                      n.line_start, n.language
               FROM nodes n
               WHERE n.kind IN ('Function', 'Method')
                 AND NOT EXISTS (
                     SELECT 1 FROM edges e
                     WHERE e.kind = 'CALLS' AND e.target_qualified = n.qualified_name
                 )
               ORDER BY n.file_path, n.line_start
               LIMIT 100""",
        ).fetchall()
        return [dict(r) for r in rows]

    def search_nodes(self, pattern: str, limit: int = 20) -> list[dict]:
        """Search nodes by name — uses FTS5 index if available, falls back to LIKE."""
        # Try FTS5 first (built by code_review_graph postprocess)
        try:
            rows = self._conn.execute(
                """SELECT n.kind, n.name, n.qualified_name, n.file_path,
                          n.line_start, n.language
                   FROM nodes_fts f
                   JOIN nodes n ON n.qualified_name = f.qualified_name
                   WHERE nodes_fts MATCH ?
                   LIMIT ?""",
                (pattern, limit),
            ).fetchall()
            if rows:
                return [dict(r) for r in rows]
        except Exception:
            pass  # FTS table not available, fall through

        # Fallback: LIKE search
        rows = self._conn.execute(
            """SELECT kind, name, qualified_name, file_path, line_start, language
               FROM nodes
               WHERE name LIKE ?
                  OR qualified_name LIKE ?
               LIMIT ?""",
            (f"%{pattern}%", f"%{pattern}%", limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def trace_path(self, from_fn: str, to_fn: str, max_depth: int = 8) -> list[str]:
        """BFS through CALLS edges from *from_fn* to *to_fn*.

        Returns the first path found as a list of qualified names, or empty
        list if no path exists within *max_depth* hops.
        """
        queue: deque[tuple[str, list[str]]] = deque([(from_fn, [from_fn])])
        visited: set[str] = {from_fn}

        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth:
                break

            rows = self._conn.execute(
                """SELECT DISTINCT target_qualified FROM edges
                   WHERE kind = 'CALLS' AND (source_qualified = ? OR source_qualified LIKE ?)""",
                (current, f"%{current}%"),
            ).fetchall()

            for row in rows:
                target = row["target_qualified"]
                if target in visited:
                    continue
                new_path = path + [target]
                if target == to_fn or to_fn in target:
                    return new_path
                visited.add(target)
                queue.append((target, new_path))

        return []

    def get_nodes_by_file(self, path: str) -> list[dict]:
        """Return all nodes (functions, classes, imports…) in a file.

        Richer than get_file_summary — includes params, return_type, is_test.
        Tries absolute path first, then a LIKE fallback on the filename.
        """
        p = Path(path)
        if not p.is_absolute():
            p = self._repo_root / p
        abs_path = str(p)

        nodes = self._store.get_nodes_by_file(abs_path)
        if not nodes:
            # Fallback: match by filename only
            rows = self._conn.execute(
                "SELECT * FROM nodes WHERE file_path LIKE ?",
                (f"%{Path(path).name}%",),
            ).fetchall()
            nodes = [self._store._row_to_node(r) for r in rows]

        return [dataclasses.asdict(n) for n in nodes]

    def get_edges_for_node(self, qualified_name: str) -> list[dict]:
        """Return all edges (any kind) where *qualified_name* is source or target.

        Exposes CALLS, IMPORTS_FROM, INHERITS, IMPLEMENTS, CONTAINS edges —
        not just CALLS like get_callers/get_callees.
        """
        outgoing = self._store.get_edges_by_source(qualified_name)
        incoming = self._store.get_edges_by_target(qualified_name)
        seen: set[int] = set()
        result: list[dict] = []
        for edge in outgoing + incoming:
            if edge.id not in seen:
                seen.add(edge.id)
                result.append(dataclasses.asdict(edge))
        return result

    def get_impact_radius(self, file_paths: list[str], max_depth: int = 4) -> dict:
        """BFS from the given files — returns all transitively impacted nodes/files.

        Useful for understanding the blast radius of a vulnerability:
        which callers, importers, and subclasses are affected downstream.
        """
        # Resolve to absolute paths
        resolved: list[str] = []
        for p in file_paths:
            path = Path(p)
            if not path.is_absolute():
                path = self._repo_root / path
            resolved.append(str(path))

        raw = self._store.get_impact_radius(resolved, max_depth=max_depth)

        # Slim down the result — strip heavy 'extra' fields to keep tokens low
        def _slim_node(n: dict) -> dict:
            return {k: n[k] for k in ("kind", "name", "qualified_name", "file_path", "line_start") if k in n}

        return {
            "changed_nodes":  [_slim_node(dataclasses.asdict(n)) for n in raw.get("changed_nodes", [])],
            "impacted_nodes": [_slim_node(dataclasses.asdict(n)) for n in raw.get("impacted_nodes", [])],
            "impacted_files": raw.get("impacted_files", []),
            "truncated":      raw.get("truncated", False),
            "total_impacted": raw.get("total_impacted", 0),
        }

    def get_stats(self) -> dict:
        """Return a summary of the graph: node/edge counts, languages, top files, hubs."""
        # Node counts by kind
        nodes_by_kind = {
            row["kind"]: row["cnt"]
            for row in self._conn.execute(
                "SELECT kind, COUNT(*) AS cnt FROM nodes GROUP BY kind ORDER BY cnt DESC"
            ).fetchall()
        }

        # Edge counts by kind
        edges_by_kind = {
            row["kind"]: row["cnt"]
            for row in self._conn.execute(
                "SELECT kind, COUNT(*) AS cnt FROM edges GROUP BY kind ORDER BY cnt DESC"
            ).fetchall()
        }

        # Language breakdown (functions + methods only)
        languages = {
            row["language"]: row["cnt"]
            for row in self._conn.execute(
                """SELECT COALESCE(language, 'unknown') AS language, COUNT(*) AS cnt
                   FROM nodes WHERE kind IN ('Function', 'Method') AND language IS NOT NULL
                   GROUP BY language ORDER BY cnt DESC"""
            ).fetchall()
        }

        # Top files by symbol count
        top_files = [
            {"file_path": row["file_path"], "symbol_count": row["cnt"]}
            for row in self._conn.execute(
                """SELECT file_path, COUNT(*) AS cnt FROM nodes
                   WHERE kind IN ('Function', 'Method', 'Class') AND file_path IS NOT NULL
                   GROUP BY file_path ORDER BY cnt DESC LIMIT 15"""
            ).fetchall()
        ]

        # Hub functions — most-called (most incoming CALLS edges)
        hub_functions = [
            {"qualified_name": row["target_qualified"], "caller_count": row["cnt"]}
            for row in self._conn.execute(
                """SELECT target_qualified, COUNT(*) AS cnt FROM edges
                   WHERE kind = 'CALLS'
                   GROUP BY target_qualified ORDER BY cnt DESC LIMIT 10"""
            ).fetchall()
        ]

        # File count
        file_count = (
            self._conn.execute(
                "SELECT COUNT(DISTINCT file_path) AS cnt FROM nodes WHERE file_path IS NOT NULL"
            ).fetchone() or {"cnt": 0}
        )["cnt"]

        # Flow count
        try:
            flow_count = self._conn.execute("SELECT COUNT(*) AS cnt FROM flows").fetchone()["cnt"]
        except Exception:
            flow_count = 0

        return {
            "files":          file_count,
            "nodes_total":    sum(nodes_by_kind.values()),
            "nodes_by_kind":  nodes_by_kind,
            "edges_total":    sum(edges_by_kind.values()),
            "edges_by_kind":  edges_by_kind,
            "languages":      languages,
            "flows":          flow_count,
            "top_files":      top_files,
            "hub_functions":  hub_functions,
        }

    def get_flows(self, limit: int = 20) -> list[dict]:
        """Return pre-computed execution flows sorted by criticality (highest first).

        Each flow starts at an entry point and traces the full call path.
        Use get_flow_by_id() to see the step-by-step path of a specific flow.
        Returns empty list if flows haven't been computed yet.
        """
        try:
            return _crg_get_flows(self._store, sort_by="criticality", limit=limit)
        except Exception:
            return []

    def get_flow_by_id(self, flow_id: int) -> Optional[dict]:
        """Return a single flow with its full step-by-step call path."""
        try:
            return _crg_get_flow_by_id(self._store, flow_id)
        except Exception:
            return None

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _read_lines(
        self, file_path: str, line_start: Optional[int], line_end: Optional[int]
    ) -> str:
        if not file_path:
            return ""
        try:
            lines = Path(file_path).read_text(encoding="utf-8", errors="replace").splitlines()
            s = max(0, (line_start or 1) - 1)
            e = min(len(lines), (line_end or line_start or 1))
            return "\n".join(lines[s:e])
        except OSError:
            return ""

    def close(self) -> None:
        try:
            self._store.close()
        except Exception:
            pass

    def __enter__(self) -> "GraphClient":
        return self

    def __exit__(self, *_) -> None:
        self.close()
