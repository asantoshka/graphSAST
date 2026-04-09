"""SecurityGraphStore — extends base GraphStore with security-specific queries."""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from code_review_graph.graph import GraphStore

from .migrations import run_graphsast_migrations

logger = logging.getLogger(__name__)


@dataclass
class CallArgRecord:
    source_qn: str
    target_qn: str
    file_path: str
    line: int
    arg_position: int
    arg_type: str           # string_literal|binary_op|f_string|tuple|identifier|other
    is_concatenated: bool
    is_parameterised: bool
    contains_var: bool
    raw_ast_type: str = ""


@dataclass
class TaintAnnotation:
    node_qn: str
    annotation_type: str    # SOURCE|SINK|SANITIZER
    vuln_class_id: str = ""
    cwe_id: str = ""
    source_ref: str = ""


@dataclass
class MissingCheck:
    entry_point_qn: str
    missing_type: str       # auth|rate_limit|csrf|validation
    check_patterns: list[str]


class SecurityGraphStore(GraphStore):
    """GraphStore with security analysis extensions."""

    def __init__(self, db_path: str | Path) -> None:
        super().__init__(db_path)
        # Apply GraphSAST security migrations
        run_graphsast_migrations(self._conn)

    # ------------------------------------------------------------------
    # call_arguments
    # ------------------------------------------------------------------

    def upsert_call_args(self, records: list[CallArgRecord]) -> None:
        """Insert/replace argument structure records for a file's call sites."""
        self._conn.executemany(
            """INSERT OR REPLACE INTO call_arguments
               (source_qn, target_qn, file_path, line, arg_position,
                arg_type, is_concatenated, is_parameterised, contains_var, raw_ast_type)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    r.source_qn, r.target_qn, r.file_path, r.line,
                    r.arg_position, r.arg_type,
                    int(r.is_concatenated), int(r.is_parameterised),
                    int(r.contains_var), r.raw_ast_type,
                )
                for r in records
            ],
        )

    def get_call_args(self, target_qn: str) -> list[CallArgRecord]:
        rows = self._conn.execute(
            "SELECT * FROM call_arguments WHERE target_qn = ?", (target_qn,)
        ).fetchall()
        return [_row_to_call_arg(r) for r in rows]

    def get_call_args_for_file(self, file_path: str) -> list[CallArgRecord]:
        rows = self._conn.execute(
            "SELECT * FROM call_arguments WHERE file_path = ?", (file_path,)
        ).fetchall()
        return [_row_to_call_arg(r) for r in rows]

    def delete_call_args_for_file(self, file_path: str) -> None:
        self._conn.execute(
            "DELETE FROM call_arguments WHERE file_path = ?", (file_path,)
        )

    # ------------------------------------------------------------------
    # taint_annotations
    # ------------------------------------------------------------------

    def upsert_taint_annotation(self, ann: TaintAnnotation) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO taint_annotations
               (node_qn, annotation_type, vuln_class_id, cwe_id, source_ref)
               VALUES (?, ?, ?, ?, ?)""",
            (ann.node_qn, ann.annotation_type, ann.vuln_class_id,
             ann.cwe_id, ann.source_ref),
        )

    def get_taint_annotations(self, node_qn: str) -> list[TaintAnnotation]:
        rows = self._conn.execute(
            "SELECT * FROM taint_annotations WHERE node_qn = ?", (node_qn,)
        ).fetchall()
        return [
            TaintAnnotation(
                node_qn=r["node_qn"],
                annotation_type=r["annotation_type"],
                vuln_class_id=r["vuln_class_id"] or "",
                cwe_id=r["cwe_id"] or "",
                source_ref=r["source_ref"] or "",
            )
            for r in rows
        ]

    def delete_taint_annotations_for_file(self, file_path: str) -> None:
        """Remove taint annotations for all nodes belonging to a file."""
        self._conn.execute(
            """DELETE FROM taint_annotations WHERE node_qn IN (
                SELECT qualified_name FROM nodes WHERE file_path = ?
            )""",
            (file_path,),
        )

    def get_all_sinks(self) -> list[str]:
        """Return qualified names of all nodes annotated SINK."""
        rows = self._conn.execute(
            "SELECT DISTINCT node_qn FROM taint_annotations WHERE annotation_type = 'SINK'"
        ).fetchall()
        return [r["node_qn"] for r in rows]

    def get_all_sources(self) -> list[str]:
        """Return qualified names of all nodes annotated SOURCE."""
        rows = self._conn.execute(
            "SELECT DISTINCT node_qn FROM taint_annotations WHERE annotation_type = 'SOURCE'"
        ).fetchall()
        return [r["node_qn"] for r in rows]

    # ------------------------------------------------------------------
    # missing_checks
    # ------------------------------------------------------------------

    def upsert_missing_check(self, mc: MissingCheck) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO missing_checks
               (entry_point_qn, missing_type, check_patterns)
               VALUES (?, ?, ?)""",
            (mc.entry_point_qn, mc.missing_type, json.dumps(mc.check_patterns)),
        )

    def get_missing_checks(self, entry_point_qn: str) -> list[MissingCheck]:
        rows = self._conn.execute(
            "SELECT * FROM missing_checks WHERE entry_point_qn = ?",
            (entry_point_qn,),
        ).fetchall()
        return [
            MissingCheck(
                entry_point_qn=r["entry_point_qn"],
                missing_type=r["missing_type"],
                check_patterns=json.loads(r["check_patterns"]),
            )
            for r in rows
        ]

    def get_all_missing_checks(self) -> list[MissingCheck]:
        rows = self._conn.execute("SELECT * FROM missing_checks").fetchall()
        return [
            MissingCheck(
                entry_point_qn=r["entry_point_qn"],
                missing_type=r["missing_type"],
                check_patterns=json.loads(r["check_patterns"]),
            )
            for r in rows
        ]

    def delete_missing_checks_for_entry(self, entry_point_qn: str) -> None:
        self._conn.execute(
            "DELETE FROM missing_checks WHERE entry_point_qn = ?", (entry_point_qn,)
        )

    # ------------------------------------------------------------------
    # entry point / taint node queries
    # ------------------------------------------------------------------

    def mark_entry_point(self, qualified_name: str) -> None:
        self._conn.execute(
            "UPDATE nodes SET is_entry_point = 1 WHERE qualified_name = ?",
            (qualified_name,),
        )

    def mark_user_controlled(self, qualified_name: str) -> None:
        self._conn.execute(
            "UPDATE nodes SET is_user_controlled = 1 WHERE qualified_name = ?",
            (qualified_name,),
        )

    def get_entry_points(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT qualified_name FROM nodes WHERE is_entry_point = 1"
        ).fetchall()
        return [r["qualified_name"] for r in rows]

    # ------------------------------------------------------------------
    # Taint path finder — call_arguments based
    # ------------------------------------------------------------------

    def find_taint_paths(self, max_depth: int = 10) -> list[dict]:
        """Find source→sink call arg records with no SANITIZER in chain.

        Strategy:
          - SOURCE: nodes where is_user_controlled=1, OR call_arguments records
            whose source function calls a known SOURCE target
          - SINK: call_arguments records whose target_qn is a known SINK
          - A finding is (function, sink_call, arg_record) where the arg
            is not parameterised and the function is reachable from a source
        """
        # Get sinks and sanitizers from taint_annotations
        sink_targets = set(self.get_all_sinks())
        sanitizer_targets = set(self._get_all_sanitizers())

        # Get source targets (SOURCE-annotated names like "request.args")
        source_targets = set(self.get_all_sources())

        results = []

        # Find call_argument records at sink call sites that are NOT parameterised
        if not sink_targets:
            return results

        # Build query: find all call_arg rows where target_qn is a known sink
        # and is_concatenated or contains_var (not safe)
        placeholders = ",".join("?" * len(sink_targets))
        rows = self._conn.execute(
            f"SELECT * FROM call_arguments WHERE target_qn IN ({placeholders})",
            list(sink_targets),
        ).fetchall()

        for row in rows:
            ca = _row_to_call_arg(row)
            if ca.is_parameterised:
                continue  # safe
            if not (ca.is_concatenated or ca.contains_var):
                continue  # literal string — safe

            # Check if this function is connected to a source
            func_qn = ca.source_qn
            is_tainted = self._function_calls_source(
                func_qn, source_targets, sanitizer_targets, max_depth
            )

            if is_tainted:
                # Check no sanitizer in path between source and this call site
                results.append({
                    "source_qn": func_qn,
                    "sink_qn": ca.target_qn,
                    "path": [func_qn, ca.target_qn],
                    "depth": 1,
                    "arg_type": ca.arg_type,
                    "arg_position": ca.arg_position,
                    "file_path": ca.file_path,
                    "line": ca.line,
                    "is_concatenated": ca.is_concatenated,
                    "contains_var": ca.contains_var,
                })

        return results

    def _get_all_sanitizers(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT DISTINCT node_qn FROM taint_annotations WHERE annotation_type = 'SANITIZER'"
        ).fetchall()
        return [r["node_qn"] for r in rows]

    def _function_calls_source(
        self,
        func_qn: str,
        source_targets: set[str],
        sanitizer_targets: set[str],
        max_depth: int,
    ) -> bool:
        """Return True if func_qn calls any source node within max_depth hops
        OR is itself an entry point (HTTP handler receives user input directly).
        """
        # Entry point? — user input arrives directly
        row = self._conn.execute(
            "SELECT is_entry_point FROM nodes WHERE qualified_name = ?", (func_qn,)
        ).fetchone()
        if row and row["is_entry_point"]:
            return True

        # Check if func_qn calls a source target
        from collections import deque
        queue: deque[tuple[str, int]] = deque([(func_qn, 0)])
        visited: set[str] = {func_qn}

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue

            rows = self._conn.execute(
                "SELECT target_qualified FROM edges WHERE source_qualified = ? AND kind = 'CALLS'",
                (current,),
            ).fetchall()

            for row in rows:
                target = row["target_qualified"]
                if target in sanitizer_targets:
                    continue
                if target in source_targets:
                    return True
                if target not in visited:
                    visited.add(target)
                    queue.append((target, depth + 1))

        return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def store_file_security_data(
        self,
        file_path: str,
        call_args: list[CallArgRecord],
        taint_annotations: list[TaintAnnotation],
    ) -> None:
        """Atomically replace security data for a file."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self.delete_call_args_for_file(file_path)
            self.delete_taint_annotations_for_file(file_path)
            if call_args:
                self.upsert_call_args(call_args)
            for ann in taint_annotations:
                self.upsert_taint_annotation(ann)
            self._conn.commit()
        except BaseException:
            self._conn.rollback()
            raise


def _row_to_call_arg(r: sqlite3.Row) -> CallArgRecord:
    return CallArgRecord(
        source_qn=r["source_qn"],
        target_qn=r["target_qn"],
        file_path=r["file_path"],
        line=r["line"],
        arg_position=r["arg_position"],
        arg_type=r["arg_type"],
        is_concatenated=bool(r["is_concatenated"]),
        is_parameterised=bool(r["is_parameterised"]),
        contains_var=bool(r["contains_var"]),
        raw_ast_type=r["raw_ast_type"] or "",
    )
