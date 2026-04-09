"""AST argument structure pass — DB-driven, language-agnostic.

For every CALLS edge in a file, inspects the argument AST node types at the
call site. Classification rules are read from the `arg_node_types` table in
vulns.db, so adding a new language requires only data, not code.

Lookup order per argument node:
  1. (language, node_type, operator_text) — exact match
  2. (language, node_type, child_type_check) — child inspection match
  3. (language, node_type) with no operator / child constraint — fallback
  4. ARG_OTHER if nothing matches
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import tree_sitter_language_pack as tslp

from graphsast.graph_db.store import CallArgRecord

logger = logging.getLogger(__name__)

# Canonical arg type constants (stored in call_arguments.arg_type)
ARG_STRING_LITERAL  = "string_literal"
ARG_BINARY_OP       = "binary_op"
ARG_F_STRING        = "f_string"
ARG_STR_FORMAT      = "str_format"
ARG_PERCENT_FORMAT  = "percent_format"
ARG_TUPLE           = "tuple"
ARG_LIST            = "list"
ARG_IDENTIFIER      = "identifier"
ARG_NONE            = "none"
ARG_OTHER           = "other"

UNSAFE_ARG_TYPES = {ARG_BINARY_OP, ARG_F_STRING, ARG_STR_FORMAT, ARG_PERCENT_FORMAT}
SAFE_ARG_TYPES   = {ARG_STRING_LITERAL, ARG_TUPLE, ARG_LIST, ARG_NONE}

# Node types that wrap a keyword argument (unwrap to the value child)
_KEYWORD_ARG_TYPES = {"keyword_argument", "named_argument", "assignment_expression"}

# Languages that have a decorator-less annotation system needing a custom EP walker
# (Go, etc.) — used elsewhere, not in this file
_ANNOTATION_LANGUAGES = {"java"}


class ArgInspector:
    """Inspects call-site argument structures in a source file.

    Args:
        vuln_db: VulnStore instance to load node-type rules from.
                 If None, falls back to an empty rule set (all args → ARG_OTHER).
    """

    def __init__(self, vuln_db=None) -> None:
        self._vuln_db = vuln_db
        self._parsers: dict[str, object] = {}
        # Cache: language → compiled rule set
        self._rules_cache: dict[str, "_RuleSet"] = {}

    def _get_parser(self, language: str):
        if language not in self._parsers:
            try:
                self._parsers[language] = tslp.get_parser(language)
            except Exception:
                return None
        return self._parsers[language]

    def _get_rules(self, language: str) -> "_RuleSet":
        if language not in self._rules_cache:
            rows = self._vuln_db.get_arg_node_types(language) if self._vuln_db else []
            self._rules_cache[language] = _RuleSet(rows)
        return self._rules_cache[language]

    def inspect_file(
        self,
        file_path: str,
        source: bytes,
        language: str,
        calls_edges: list[tuple[str, str, int]],
    ) -> list[CallArgRecord]:
        """Return CallArgRecords for every call site in the given CALLS edges."""
        parser = self._get_parser(language)
        if not parser:
            return []

        rules = self._get_rules(language)
        tree = parser.parse(source)

        # Build line → [(caller_qn, callee_qn)] index
        line_to_calls: dict[int, list[tuple[str, str]]] = {}
        for src_qn, tgt_qn, line in calls_edges:
            line_to_calls.setdefault(line, []).append((src_qn, tgt_qn))

        records: list[CallArgRecord] = []
        _walk_calls(tree.root_node, source, language, file_path,
                    line_to_calls, rules, records)
        return records


# ──────────────────────────────────────────────────────────────────────────────
# Rule set
# ──────────────────────────────────────────────────────────────────────────────

class _RuleSet:
    """In-memory index of arg_node_types rows for one language."""

    def __init__(self, rows: list[dict]) -> None:
        # Index: node_type → list of rules (sorted: operator/child rules first)
        self._by_type: dict[str, list[dict]] = {}
        # Which node types need operator extraction
        self._needs_operator: set[str] = set()

        for row in rows:
            nt = row["node_type"]
            self._by_type.setdefault(nt, []).append(row)
            if row.get("operator_text"):
                self._needs_operator.add(nt)

        # Sort each bucket: rules with constraints first, fallbacks last
        for nt in self._by_type:
            self._by_type[nt].sort(
                key=lambda r: (
                    r.get("operator_text") is None,
                    r.get("child_type_check") is None,
                )
            )

    def classify(self, node, source: bytes) -> dict | None:
        """Return the matching rule row for this AST node, or None."""
        nt = node.type
        rules = self._by_type.get(nt)
        if not rules:
            return None

        op_text = None
        if nt in self._needs_operator:
            op_text = _extract_operator(node, source)

        for rule in rules:
            expected_op = rule.get("operator_text")
            child_type = rule.get("child_type_check")
            child_prefix = rule.get("child_text_prefix")

            # Operator constraint
            if expected_op is not None:
                if op_text != expected_op:
                    continue

            # Child type / prefix constraint
            if child_type is not None:
                if not _child_matches(node, source, child_type, child_prefix):
                    continue

            return rule  # first matching rule wins

        return None


# ──────────────────────────────────────────────────────────────────────────────
# Generic AST walker
# ──────────────────────────────────────────────────────────────────────────────

def _walk_calls(
    node,
    source: bytes,
    language: str,
    file_path: str,
    line_to_calls: dict[int, list[tuple[str, str]]],
    rules: _RuleSet,
    out: list[CallArgRecord],
) -> None:
    """Recursively walk any language's AST looking for call nodes."""
    # Tree-sitter call node types across languages
    _CALL_NODE_TYPES = {
        "call",                    # Python
        "call_expression",         # JS/TS/Go/Java/Kotlin/Swift/C/C++
        "new_expression",          # JS/TS
        "method_invocation",       # Java
        "object_creation_expression",  # Java
        "function_call",           # Lua/PHP
        "member_call_expression",  # PHP
    }

    if node.type in _CALL_NODE_TYPES:
        call_line = node.start_point[0] + 1
        if call_line in line_to_calls:
            args_node = _find_args_node(node)
            if args_node is not None:
                arg_nodes = [
                    c for c in args_node.children
                    if c.type not in (",", "(", ")", "comment", "ws")
                ]
                for src_qn, tgt_qn in line_to_calls[call_line]:
                    for pos, arg_node in enumerate(arg_nodes):
                        rec = _classify_arg(
                            arg_node, source, language, rules,
                            src_qn, tgt_qn, file_path, call_line, pos,
                        )
                        out.append(rec)

    for child in node.children:
        _walk_calls(child, source, language, file_path,
                    line_to_calls, rules, out)


def _find_args_node(call_node):
    """Find the argument list child of a call node."""
    _ARG_LIST_TYPES = {
        "argument_list",   # Python, Java, C, C++
        "arguments",       # JS/TS/Go/Kotlin/Swift/PHP
        "arg_list",        # some grammars
    }
    for child in call_node.children:
        if child.type in _ARG_LIST_TYPES:
            return child
    return None


def _classify_arg(
    node,
    source: bytes,
    language: str,
    rules: _RuleSet,
    source_qn: str,
    target_qn: str,
    file_path: str,
    line: int,
    pos: int,
) -> CallArgRecord:
    """Classify a single argument node using the DB rule set."""

    # Unwrap keyword argument wrappers (e.g. Python keyword_argument)
    if node.type in _KEYWORD_ARG_TYPES:
        value = _unwrap_keyword(node)
        if value is not None:
            return _classify_arg(value, source, language, rules,
                                 source_qn, target_qn, file_path, line, pos)

    # Special case: .format() call — structural pattern, not a node type lookup
    if node.type in ("call", "call_expression") and _is_str_format_call(node, source):
        return CallArgRecord(
            source_qn=source_qn, target_qn=target_qn,
            file_path=file_path, line=line, arg_position=pos,
            arg_type=ARG_STR_FORMAT,
            is_concatenated=True, is_parameterised=False, contains_var=True,
            raw_ast_type=node.type,
        )

    rule = rules.classify(node, source)

    if rule:
        return CallArgRecord(
            source_qn=source_qn, target_qn=target_qn,
            file_path=file_path, line=line, arg_position=pos,
            arg_type=rule["arg_type"],
            is_concatenated=bool(rule.get("is_concatenated")),
            is_parameterised=bool(rule.get("is_parameterised")),
            contains_var=bool(rule.get("contains_var")),
            raw_ast_type=node.type,
        )

    # No rule matched → conservative: flag as OTHER with contains_var=True
    return CallArgRecord(
        source_qn=source_qn, target_qn=target_qn,
        file_path=file_path, line=line, arg_position=pos,
        arg_type=ARG_OTHER,
        is_concatenated=False, is_parameterised=False, contains_var=True,
        raw_ast_type=node.type,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _extract_operator(node, source: bytes) -> Optional[str]:
    """Extract the operator text from a binary_operator / binary_expression node."""
    # In most grammars the operator is a direct child that is not an identifier,
    # string, or other value node — it's a punctuation/operator token.
    _VALUE_TYPES = {
        "identifier", "string", "formatted_string", "attribute",
        "subscript", "call", "call_expression", "tuple", "list",
        "array", "integer", "float", "true", "false", "null",
        "parenthesized_expression", "concatenated_string",
        "template_literal", "string_literal", "template_string",
        "binary_expression", "binary_operator",
        "interpreted_string_literal", "raw_string_literal",
        "(", ")", ",",
    }
    for child in node.children:
        if child.type not in _VALUE_TYPES and not child.type.endswith("_expression"):
            try:
                text = source[child.start_byte:child.end_byte].decode("utf-8", errors="replace").strip()
                if text:
                    return text
            except Exception:
                pass
    return None


def _child_matches(node, source: bytes, child_type: str, child_prefix: Optional[str]) -> bool:
    """Return True if any direct child matches child_type and text prefix."""
    for child in node.children:
        if child.type == child_type:
            if child_prefix is None:
                return True
            try:
                text = source[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
                if text.startswith(child_prefix) or text.lower().startswith(child_prefix.lower()):
                    return True
            except Exception:
                pass
        # Also check for interpolation as a child (marks any f-string)
        if child_type == "interpolation" and child.type == "interpolation":
            return True
    return False


def _unwrap_keyword(node):
    """Return the value child of a keyword argument node."""
    for child in node.children:
        if child.type not in ("identifier", "=", ":=", ":"):
            return child
    return None


def _is_str_format_call(call_node, source: bytes) -> bool:
    """Check if call_node is a .format() call on a string."""
    for child in call_node.children:
        if child.type == "attribute":
            for sub in child.children:
                if sub.type == "identifier":
                    text = source[sub.start_byte:sub.end_byte].decode("utf-8", errors="replace")
                    if text == "format":
                        return True
    return False
