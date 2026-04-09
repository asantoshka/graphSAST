"""Taint annotation pass.

Reads taint_signatures from vulns.db and annotates graph nodes in graph.db
as SOURCE, SINK, or SANITIZER by matching qualified names.

Entry point patterns are loaded from the entry_point_patterns table in vulns.db,
so adding a new language/framework requires only data, not code.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

from graphsast.graph_db.store import SecurityGraphStore, TaintAnnotation

logger = logging.getLogger(__name__)


class TaintMarker:
    """Applies taint annotations to a SecurityGraphStore from a VulnDB."""

    def __init__(self, graph: SecurityGraphStore, vuln_db=None) -> None:
        self.graph = graph
        self._vuln_db = vuln_db
        self._parsers: dict[str, object] = {}
        # Cache: language → list of compiled pattern dicts
        self._ep_patterns_cache: dict[str, list[dict]] = {}

    def _get_parser(self, language: str):
        if language not in self._parsers:
            try:
                import tree_sitter_language_pack as tslp
                self._parsers[language] = tslp.get_parser(language)
            except Exception:
                return None
        return self._parsers[language]

    def annotate_all(self, vuln_db) -> int:
        """Annotate all nodes matching taint signatures in vuln_db.

        Returns the number of annotations applied.
        """
        from graphsast.vuln_db.store import VulnStore
        assert isinstance(vuln_db, VulnStore)

        sigs = vuln_db.get_all_taint_signatures()
        count = 0

        for sig in sigs:
            pattern = sig["qualified_pattern"]
            sig_type = sig["sig_type"]          # SOURCE|SINK|SANITIZER
            vuln_class_id = sig.get("vuln_class_id", "")
            cwe_ids = sig.get("cwe_ids", [])
            cwe_id = cwe_ids[0] if cwe_ids else ""

            matched = self._find_matching_nodes(pattern, sig["language"])
            for node_qn in matched:
                ann = TaintAnnotation(
                    node_qn=node_qn,
                    annotation_type=sig_type,
                    vuln_class_id=vuln_class_id,
                    cwe_id=cwe_id,
                    source_ref=sig["id"],
                )
                self.graph.upsert_taint_annotation(ann)
                count += 1

        self.graph.commit()
        logger.info("TaintMarker: applied %d annotations", count)
        return count

    def detect_entry_points(self) -> int:
        """Mark HTTP route handlers and CLI commands as entry points.

        Runs a tree-sitter decorator extraction pass on all Python files
        in the graph, then checks for web framework route decorators.
        """
        conn = self.graph._conn
        count = 0

        # Get all Python files in the graph
        file_rows = conn.execute(
            "SELECT DISTINCT file_path, language FROM nodes WHERE kind = 'File'"
        ).fetchall()

        for file_row in file_rows:
            file_path = file_row["file_path"]
            language = file_row["language"] or ""
            if language != "python":
                continue

            # Extract decorator info by re-parsing the file
            decorated = self._extract_python_decorators(Path(file_path))

            for func_name, decorators in decorated.items():
                if self._is_entry_point(language, decorators):
                    func_rows = conn.execute(
                        "SELECT qualified_name FROM nodes WHERE name = ? AND file_path = ? AND kind = 'Function'",
                        (func_name, file_path),
                    ).fetchall()
                    for r in func_rows:
                        self.graph.mark_entry_point(r["qualified_name"])
                        count += 1

        self.graph.commit()
        logger.info("TaintMarker: marked %d entry points", count)
        return count

    def _extract_python_decorators(self, path: Path) -> dict[str, list[str]]:
        """Return {func_name: [decorator_texts]} for all decorated functions in a Python file."""
        try:
            source = path.read_bytes()
        except (OSError, PermissionError):
            return {}

        parser = self._get_parser("python")
        if not parser:
            return {}

        tree = parser.parse(source)
        result: dict[str, list[str]] = {}
        self._walk_for_decorators(tree.root_node, source, result)
        return result

    def _walk_for_decorators(self, node, source: bytes, result: dict[str, list[str]]) -> None:
        """Walk Python AST and collect decorator texts per function."""
        if node.type == "decorated_definition":
            decorators: list[str] = []
            func_name: Optional[str] = None
            for child in node.children:
                if child.type == "decorator":
                    dec_text = source[child.start_byte:child.end_byte].decode("utf-8", errors="replace").strip()
                    decorators.append(dec_text)
                elif child.type == "function_definition":
                    for subchild in child.children:
                        if subchild.type == "identifier":
                            func_name = source[subchild.start_byte:subchild.end_byte].decode("utf-8", errors="replace")
                            break
            if func_name and decorators:
                result[func_name] = decorators

        for child in node.children:
            self._walk_for_decorators(child, source, result)

    def _find_matching_nodes(self, pattern: str, language: str) -> list[str]:
        """Find graph nodes OR CALLS edge targets matching a taint signature pattern.

        Most sink/source functions are library calls and won't have a defined
        node in the graph. We also match against CALLS edge targets so that
        `cursor.execute`, `os.system`, etc. are annotated even though they are
        external functions.
        """
        conn = self.graph._conn
        found: set[str] = set()

        # 1. Exact qualified_name match on defined nodes
        rows = conn.execute(
            "SELECT qualified_name FROM nodes WHERE qualified_name = ?", (pattern,)
        ).fetchall()
        found.update(r["qualified_name"] for r in rows)

        # 2. Suffix match on defined nodes
        rows = conn.execute(
            "SELECT qualified_name FROM nodes WHERE qualified_name LIKE ?",
            (f"%::{pattern}",),
        ).fetchall()
        found.update(r["qualified_name"] for r in rows)

        # 3. Name-only match on defined Function nodes
        name = pattern.split(".")[-1]
        lang_filter = ""
        params: list = [name]
        if language and language != "any":
            lang_filter = " AND language = ?"
            params.append(language)
        rows = conn.execute(
            f"SELECT qualified_name FROM nodes WHERE name = ? AND kind = 'Function'{lang_filter}",
            params,
        ).fetchall()
        found.update(r["qualified_name"] for r in rows)

        # 4. Match against CALLS edge targets (handles external library calls)
        # Pattern like "cursor.execute" → match target_qualified LIKE "%execute"
        # Pattern like "os.system" → match both "os.system" and "system"
        name_part = pattern.split(".")[-1]
        rows = conn.execute(
            "SELECT DISTINCT target_qualified FROM edges WHERE kind = 'CALLS' "
            "AND (target_qualified = ? OR target_qualified LIKE ?)",
            (pattern, f"%.{name_part}"),
        ).fetchall()
        found.update(r["target_qualified"] for r in rows)

        # Also exact name match on edge targets
        rows = conn.execute(
            "SELECT DISTINCT target_qualified FROM edges WHERE kind = 'CALLS' "
            "AND target_qualified = ?",
            (name_part,),
        ).fetchall()
        found.update(r["target_qualified"] for r in rows)

        return list(found)


    def _is_entry_point(self, language: str, decorators: list[str]) -> bool:
        """Check if a function with these decorators is an entry point.

        Patterns are loaded from the entry_point_patterns table in vulns.db.
        Falls back to an empty pattern list if no vuln_db is available.
        """
        if not decorators:
            return False

        if language not in self._ep_patterns_cache:
            if self._vuln_db:
                rows = self._vuln_db.get_entry_point_patterns(language)
            else:
                rows = []
            self._ep_patterns_cache[language] = rows

        patterns = self._ep_patterns_cache[language]

        for dec in decorators:
            for row in patterns:
                match_type = row.get("match_type", "substring")
                pattern = row["pattern"]
                if match_type == "substring":
                    if pattern in dec:
                        return True
                elif match_type == "regex":
                    if re.search(pattern, dec):
                        return True

        return False
