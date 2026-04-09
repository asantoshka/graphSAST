"""Phase 1A — Autonomous LLM security analysis per entry point.

The LLM acts as an independent security researcher. It receives a graph
summary of an entry point and can call tools to read real code. It has
no hints about what to look for — it finds issues from its own knowledge.

DB 2 (vulns.db) is NOT consulted here. The LLM works purely from the
code graph and the source files.

Each entry point gets its own conversation (max MAX_TURNS turns).
Findings are stored in the phase1a_findings table.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from graphsast.graph_db.store import SecurityGraphStore
from graphsast.llm.base import LLMClient
from graphsast.llm.cache import make_cache_key, get_cached, set_cached
from graphsast.llm.tools import GraphTools, TOOL_SCHEMAS

logger = logging.getLogger(__name__)

MAX_TURNS = 8

SYSTEM_PROMPT = """You are an expert security researcher performing a source code security audit.

You have access to a code graph that maps how functions call each other, what data
flows where, and which security checks are present or absent.

Your job: For the entry point given to you, explore its call chain, read actual
source code as needed, and identify security vulnerabilities.

Available tools:
- fetch_function_source   — read the real source code of any function
- fetch_call_context      — see who calls a function and what it calls
- fetch_taint_path        — check if tainted data flows to a sink
- fetch_argument_structure — see how arguments are passed to a function call
- fetch_missing_checks    — see which security checks are absent

When you find a vulnerability:
  1. Describe it precisely (what the bug is, where it is, why it's exploitable)
  2. Assign a CWE if you know it
  3. Rate your confidence: HIGH / MEDIUM / LOW

When you are done investigating, output your findings as a JSON object:
{
  "suspected_vuln": "description of the vulnerability",
  "suggested_cwe": "CWE-XX or empty string",
  "confidence": "HIGH|MEDIUM|LOW",
  "affected_nodes": ["qualified::name1", "qualified::name2"],
  "reasoning": "step by step explanation of how you found this"
}

If you find no vulnerability, output:
{"suspected_vuln": "", "suggested_cwe": "", "confidence": "LOW",
 "affected_nodes": [], "reasoning": "No exploitable path found"}

Rules:
- Do NOT fabricate code you haven't read. Use the tools to fetch real code.
- Focus on real, exploitable issues. Avoid theoretical low-impact findings.
- You have at most 8 turns. Be efficient.
"""


def analyse_entry_point(
    graph: SecurityGraphStore,
    entry_point_qn: str,
    client: LLMClient,
    scan_run_id: str = "",
) -> dict:
    """Run Phase 1A analysis for one entry point.

    Returns a finding dict (saved by the caller).
    Skips the LLM call and returns a cached result if the source file
    hasn't changed since the last analysis with the same model.
    """
    # ── Cache check ──────────────────────────────────────────────────────────
    file_path = _get_file_path(graph, entry_point_qn)
    cache_key = make_cache_key("1a", entry_point_qn, file_path, client.model)
    cached = get_cached(graph._conn, cache_key)
    if cached:
        logger.info("Phase 1A cache HIT: %s", entry_point_qn)
        cached["scan_run_id"] = scan_run_id   # refresh for this run
        return cached

    graph_tools = GraphTools(graph)

    # Build the initial user message with graph context
    context = _build_entry_point_context(graph, entry_point_qn)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": context},
    ]

    logger.info("Phase 1A: analysing %s", entry_point_qn)

    messages, turns_used = client.run_loop(
        messages=messages,
        tool_schemas=TOOL_SCHEMAS,
        tool_executor=graph_tools.execute,
        max_turns=MAX_TURNS,
    )

    # Extract the last assistant message and parse the JSON finding
    assistant_msgs = [m for m in messages if m.get("role") == "assistant"]
    last_text = _extract_text(assistant_msgs[-1]) if assistant_msgs else ""

    finding_json = _extract_json(last_text)

    # Collect all source code the LLM fetched (tool results)
    source_seen = [
        m["content"] for m in messages
        if m.get("role") == "tool" and m.get("name") == "fetch_function_source"
    ]

    finding_id = str(uuid.uuid4())[:16]
    result = {
        "id": finding_id,
        "scan_run_id": scan_run_id,
        "entry_point_qn": entry_point_qn,
        "suspected_vuln": finding_json.get("suspected_vuln", ""),
        "suggested_cwe": finding_json.get("suggested_cwe", ""),
        "affected_nodes": json.dumps(finding_json.get("affected_nodes", [])),
        "reasoning": finding_json.get("reasoning", last_text[:2000]),
        "confidence": finding_json.get("confidence", "LOW"),
        "source_code_seen": json.dumps(source_seen),
        "turns_used": turns_used,
        "model": client.model,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # ── Cache write ───────────────────────────────────────────────────────────
    set_cached(graph._conn, cache_key, "1a", result)

    return result


def run_phase1a(
    graph: SecurityGraphStore,
    client: LLMClient,
    scan_run_id: str = "",
    max_entry_points: int = 0,
) -> list[dict]:
    """Run Phase 1A for all (or the first N) entry points.

    Stores results in phase1a_findings and returns them as a list.
    """
    entry_points = graph.get_entry_points()
    if max_entry_points > 0:
        entry_points = entry_points[:max_entry_points]

    logger.info("Phase 1A: %d entry points to analyse", len(entry_points))

    findings = []
    for ep in entry_points:
        try:
            f = analyse_entry_point(graph, ep, client, scan_run_id)
            _save_finding(graph, f)
            if f["suspected_vuln"]:
                logger.info(
                    "Phase 1A finding [%s] %s: %s",
                    f["confidence"], ep, f["suspected_vuln"][:80],
                )
                findings.append(f)
        except Exception as exc:
            logger.error("Phase 1A failed for %s: %s", ep, exc)

    logger.info("Phase 1A complete: %d findings from %d entry points", len(findings), len(entry_points))
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _get_file_path(graph: SecurityGraphStore, qn: str) -> str:
    """Return the file_path for a qualified name, or empty string if not found."""
    row = graph._conn.execute(
        "SELECT file_path FROM nodes WHERE qualified_name = ? LIMIT 1", (qn,)
    ).fetchone()
    return row["file_path"] if row else ""


def _build_entry_point_context(graph: SecurityGraphStore, ep_qn: str) -> str:
    """Build the initial context message for an entry point."""
    conn = graph._conn

    # Basic node info
    node = conn.execute(
        "SELECT name, file_path, line_start, line_end, language "
        "FROM nodes WHERE qualified_name = ? LIMIT 1",
        (ep_qn,),
    ).fetchone()

    lines = [f"## Entry Point Analysis: `{ep_qn}`\n"]

    if node:
        lines.append(f"- File     : {node['file_path']}")
        lines.append(f"- Language : {node['language'] or 'unknown'}")
        lines.append(f"- Lines    : {node['line_start']}–{node['line_end']}")

    # Callees (what this entry point calls)
    callees = conn.execute(
        "SELECT DISTINCT target_qualified FROM edges "
        "WHERE kind = 'CALLS' AND source_qualified = ? LIMIT 30",
        (ep_qn,),
    ).fetchall()
    if callees:
        lines.append(f"\nCalls ({len(callees)} distinct targets):")
        for c in callees:
            lines.append(f"  -> {c['target_qualified']}")

    # Call arg records (how args are passed to sinks)
    call_args = conn.execute(
        "SELECT target_qn, arg_type, is_concatenated, is_parameterised, line "
        "FROM call_arguments WHERE source_qn = ? ORDER BY line",
        (ep_qn,),
    ).fetchall()
    if call_args:
        lines.append(f"\nArgument structures at call sites:")
        for ca in call_args:
            flag = ""
            if ca["is_concatenated"]:
                flag = " ⚠ CONCATENATED"
            elif ca["is_parameterised"]:
                flag = " ✓ parameterised"
            lines.append(
                f"  {ca['target_qn']}(arg_type={ca['arg_type']}, line={ca['line']}){flag}"
            )

    # Missing checks
    missing = graph.get_missing_checks(ep_qn)
    if missing:
        types = ", ".join(m.missing_type for m in missing)
        lines.append(f"\n⚠ Missing security checks: {types}")

    lines.append(
        "\n\nPlease investigate this entry point for security vulnerabilities. "
        "Use the available tools to read source code and understand the data flow."
    )

    return "\n".join(lines)


def _extract_text(msg: dict) -> str:
    content = msg.get("content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(
            b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"
        )
    return str(content)


def _extract_json(text: str) -> dict:
    """Parse the JSON finding from the LLM's last message."""
    # Try to find a JSON block
    import re
    # Look for ```json ... ``` or bare { ... }
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
    if not m:
        m = re.search(r"(\{[^{}]*\"suspected_vuln\"[^{}]*\})", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    # Last resort: find the last { ... } block
    try:
        start = text.rfind("{")
        end   = text.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(text[start:end])
    except (json.JSONDecodeError, ValueError):
        pass
    return {}


def _save_finding(graph: SecurityGraphStore, f: dict) -> None:
    graph._conn.execute(
        """INSERT OR REPLACE INTO phase1a_findings
           (id, scan_run_id, entry_point_qn, suspected_vuln, suggested_cwe,
            affected_nodes, reasoning, confidence, source_code_seen,
            turns_used, model, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            f["id"], f["scan_run_id"], f["entry_point_qn"],
            f["suspected_vuln"], f["suggested_cwe"], f["affected_nodes"],
            f["reasoning"], f["confidence"], f["source_code_seen"],
            f["turns_used"], f["model"], f["timestamp"],
        ),
    )
    graph.commit()
