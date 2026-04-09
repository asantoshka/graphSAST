"""Graph inspection tools exposed to the LLM.

These are the five tools the LLM can call during Phase 1A / 1B analysis.
Each tool reads from the graph and returns a compact text summary so the
LLM doesn't need to reason over raw SQL rows.

Tool schemas follow the OpenAI function-calling format that Ollama accepts.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from graphsast.graph_db.store import SecurityGraphStore

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# OpenAI-format tool schema definitions
# ──────────────────────────────────────────────────────────────────────────────

TOOL_SCHEMAS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "fetch_function_source",
            "description": (
                "Retrieve the source code of a function or method by its fully-qualified name. "
                "Use this to read the actual implementation when you need to reason about "
                "what the code does."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "qualified_name": {
                        "type": "string",
                        "description": "Fully-qualified name, e.g. 'src/app.py::login'",
                    }
                },
                "required": ["qualified_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_call_context",
            "description": (
                "Return the callers (who calls this function) and callees (what this "
                "function calls) from the code graph. Useful for understanding data flow."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "qualified_name": {
                        "type": "string",
                        "description": "Fully-qualified name of the function",
                    }
                },
                "required": ["qualified_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_taint_path",
            "description": (
                "Find taint paths between a source function and a sink function. "
                "Returns the call chain and argument structure at the sink."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "source_qn": {
                        "type": "string",
                        "description": "Qualified name of the source (entry point) function",
                    },
                    "sink_qn": {
                        "type": "string",
                        "description": "Qualified name of the sink function (e.g. 'execute')",
                    },
                },
                "required": ["source_qn", "sink_qn"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_argument_structure",
            "description": (
                "Return how arguments are passed to a specific call site. "
                "Reports arg_type (string_literal/binary_op/f_string/tuple/identifier), "
                "is_concatenated, is_parameterised flags."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "caller_qn": {
                        "type": "string",
                        "description": "Qualified name of the calling function",
                    },
                    "callee_qn": {
                        "type": "string",
                        "description": "Qualified name of the called function (the sink)",
                    },
                },
                "required": ["caller_qn", "callee_qn"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_missing_checks",
            "description": (
                "Return which security checks (auth, rate_limit, csrf, validation) "
                "are absent from an entry point's call chain."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "entry_point_qn": {
                        "type": "string",
                        "description": "Qualified name of the entry point function",
                    }
                },
                "required": ["entry_point_qn"],
            },
        },
    },
]


# ──────────────────────────────────────────────────────────────────────────────
# Tool executor
# ──────────────────────────────────────────────────────────────────────────────

class GraphTools:
    """Executes LLM tool calls against the SecurityGraphStore."""

    def __init__(self, graph: SecurityGraphStore) -> None:
        self.graph = graph

    def execute(self, tool_name: str, args: dict) -> str:
        """Dispatch tool call. Returns a compact text result."""
        dispatch = {
            "fetch_function_source":   self._fetch_function_source,
            "fetch_call_context":      self._fetch_call_context,
            "fetch_taint_path":        self._fetch_taint_path,
            "fetch_argument_structure":self._fetch_argument_structure,
            "fetch_missing_checks":    self._fetch_missing_checks,
        }
        fn = dispatch.get(tool_name)
        if fn is None:
            return f"Unknown tool: {tool_name}"
        try:
            return fn(**args)
        except Exception as exc:
            return f"Tool error: {exc}"

    # ------------------------------------------------------------------

    def _fetch_function_source(self, qualified_name: str) -> str:
        conn = self.graph._conn
        row = conn.execute(
            "SELECT file_path, line_start, line_end FROM nodes "
            "WHERE qualified_name = ? LIMIT 1",
            (qualified_name,),
        ).fetchone()

        if not row:
            # Try suffix match
            name_part = qualified_name.split("::")[-1]
            row = conn.execute(
                "SELECT file_path, line_start, line_end FROM nodes "
                "WHERE name = ? AND kind IN ('Function','Method') LIMIT 1",
                (name_part,),
            ).fetchone()

        if not row:
            return f"Function '{qualified_name}' not found in graph."

        file_path   = row["file_path"]
        line_start  = row["line_start"] or 1
        line_end    = row["line_end"]

        try:
            all_lines = Path(file_path).read_text(encoding="utf-8", errors="replace").splitlines()
            start = max(0, (line_start or 1) - 1)
            end   = (line_end or start + 60) + 1
            # Cap at 60 lines to keep context small for local models
            raw_slice = all_lines[start:end]
            if len(raw_slice) > 60:
                raw_slice = raw_slice[:60]
            snippet = "\n".join(
                f"{start + i + 1}: {l}" for i, l in enumerate(raw_slice)
            )
            return f"# {qualified_name}  ({file_path}:{line_start})\n\n{snippet}"
        except OSError as exc:
            return f"Could not read {file_path}: {exc}"

    def _fetch_call_context(self, qualified_name: str) -> str:
        conn = self.graph._conn

        callers = conn.execute(
            "SELECT DISTINCT source_qualified FROM edges "
            "WHERE kind = 'CALLS' AND target_qualified = ? LIMIT 20",
            (qualified_name,),
        ).fetchall()

        callees = conn.execute(
            "SELECT DISTINCT target_qualified FROM edges "
            "WHERE kind = 'CALLS' AND source_qualified = ? LIMIT 20",
            (qualified_name,),
        ).fetchall()

        # Taint annotations
        annotations = conn.execute(
            "SELECT annotation_type, cwe_id FROM taint_annotations "
            "WHERE node_qn = ?",
            (qualified_name,),
        ).fetchall()

        lines = [f"Call context for: {qualified_name}"]
        lines.append(f"\nCallers ({len(callers)}):")
        for r in callers:
            lines.append(f"  <- {r['source_qualified']}")
        lines.append(f"\nCallees ({len(callees)}):")
        for r in callees:
            lines.append(f"  -> {r['target_qualified']}")
        if annotations:
            lines.append("\nTaint annotations:")
            for a in annotations:
                lines.append(f"  [{a['annotation_type']}] cwe={a['cwe_id']}")

        return "\n".join(lines)

    def _fetch_taint_path(self, source_qn: str, sink_qn: str) -> str:
        paths = self.graph.find_taint_paths()
        matching = [
            p for p in paths
            if p["source_qn"] == source_qn
            and (p["sink_qn"] == sink_qn or sink_qn in p["sink_qn"])
        ]

        if not matching:
            return (
                f"No taint path found from '{source_qn}' to '{sink_qn}'.\n"
                f"(This may mean the path goes through sanitised args or the sink "
                f"isn't in the signature database.)"
            )

        lines = [f"Taint paths: {source_qn} → {sink_qn}\n"]
        for p in matching:
            lines.append(f"  arg_type     : {p['arg_type']}")
            lines.append(f"  is_concat    : {p['is_concatenated']}")
            lines.append(f"  contains_var : {p['contains_var']}")
            lines.append(f"  line         : {p['line']}")
            lines.append(f"  path         : {' -> '.join(p['path'])}")
            lines.append("")
        return "\n".join(lines)

    def _fetch_argument_structure(self, caller_qn: str, callee_qn: str) -> str:
        conn = self.graph._conn
        rows = conn.execute(
            "SELECT * FROM call_arguments "
            "WHERE source_qn = ? AND target_qn = ? "
            "ORDER BY arg_position",
            (caller_qn, callee_qn),
        ).fetchall()

        if not rows:
            # Loose match on name parts
            callee_name = callee_qn.split("::")[-1]
            rows = conn.execute(
                "SELECT * FROM call_arguments "
                "WHERE source_qn LIKE ? AND target_qn LIKE ? "
                "ORDER BY arg_position",
                (f"%{caller_qn.split('::')[-1]}%", f"%{callee_name}%"),
            ).fetchall()

        if not rows:
            return f"No call_arguments record for {caller_qn} -> {callee_qn}."

        lines = [f"Argument structure: {caller_qn} → {callee_qn}\n"]
        for r in rows:
            lines.append(f"  arg[{r['arg_position']}]:")
            lines.append(f"    type           : {r['arg_type']}")
            lines.append(f"    is_concatenated: {bool(r['is_concatenated'])}")
            lines.append(f"    is_parameterised:{bool(r['is_parameterised'])}")
            lines.append(f"    contains_var   : {bool(r['contains_var'])}")
            lines.append(f"    raw_ast_type   : {r['raw_ast_type']}")
        return "\n".join(lines)

    def _fetch_missing_checks(self, entry_point_qn: str) -> str:
        mcs = self.graph.get_missing_checks(entry_point_qn)
        if not mcs:
            return f"No missing checks recorded for '{entry_point_qn}'."
        lines = [f"Missing security checks for: {entry_point_qn}\n"]
        for mc in mcs:
            lines.append(f"  [{mc.missing_type}] expected patterns: {mc.check_patterns}")
        return "\n".join(lines)
