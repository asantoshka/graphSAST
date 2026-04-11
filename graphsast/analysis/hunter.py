"""Autonomous LLM-driven security hunt — independent of Semgrep.

Instead of confirming scanner-flagged findings, the hunter starts from the
codebase's natural attack surface (entry points + pre-computed flows) and
asks the LLM to find vulnerabilities on its own.

Flow:
  1. List entry points (functions with no callers).
  2. List pre-computed flows (ranked by criticality).
  3. Deduplicate: skip entry points already covered by a flow.
  4. For each candidate run hunt_one() — a ReAct tool loop.
  5. Parse zero or more FINDING blocks from the LLM response.
  6. Return list of raw finding dicts (same shape as Semgrep findings).
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Optional

from pathlib import Path

if TYPE_CHECKING:
    from graphsast.graph.client import GraphClient
    from graphsast.llm.base import LLMClient
    from graphsast.vuln_db.store import VulnStore

logger = logging.getLogger(__name__)

# ── System prompt ──────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
/no_think
You are a security researcher performing a manual code audit.
You have been given an ENTRY POINT — a function that can be reached from
outside the application (no upstream callers, or the start of a pre-computed
execution flow). Your job is to trace data through it and find exploitable
security vulnerabilities.

━━━ AUDIT PROTOCOL — follow these steps in order ━━━

STEP 1 — READ THE ENTRY POINT
  • Call get_function(name) to read the full source of the entry point.
  • Call get_file_summary(path) to understand the surrounding module.

STEP 2 — TRACE DATA FLOW FORWARD (callees / sinks)
  • Call get_callees(name) to see what this function calls.
  • Follow interesting callees deeper: read functions that touch user input,
    databases, file system, shell, network, templates, or serialization.
  • Look for dangerous sinks: SQL execution, os.system / subprocess,
    open() for write, render_template, pickle.loads, eval, exec, etc.

STEP 3 — CHECK FOR SANITISATION
  • Search for validators or escape functions on the data path:
    search_nodes("sanitize"), search_nodes("validate"), search_nodes("escape"),
    search_nodes("quote"), search_nodes("clean"), search_nodes("filter").
  • Read any sanitizer you find to verify it actually covers this data path.

STEP 4 — CONFIRM USER CONTROLLABILITY
  • Trace back to the entry point: is the dangerous input coming from a
    request parameter, URL path, header, file upload, environment variable,
    or other attacker-controlled source?
  • Use get_callers(), get_flows(), or trace_path() to confirm reachability.

STEP 5 — LOOK FOR MORE ISSUES
  • After finishing the first finding (or confirming no finding), read
    sibling functions in the same file via get_file_summary() and check
    whether any other method shares the same pattern.

━━━ RULES ━━━
• You MUST call at least 5 tools before writing any findings.
• Read the actual source — do not speculate without evidence.
• If a tool returns nothing, try a related name or search_nodes(pattern).
• Ignore test files and mock objects.
• Only report vulnerabilities you can trace from input to sink.

━━━ AVAILABLE TOOLS ━━━
- get_function(name)                       read a function's full source + metadata
- get_callers(name)                        who calls this function
- get_callees(name)                        what this function calls
- search_nodes(pattern, limit=20)          find functions/classes by name pattern
- read_file(path, start_line, end_line)    read a file or a line range
- get_file_summary(path)                   all symbols in a file with line ranges
- get_nodes_by_file(path)                  full metadata for every symbol in a file
- list_entry_points()                      all public handlers with no callers
- get_edges_for_node(qualified_name)       all edges (CALLS, IMPORTS_FROM, INHERITS…)
- get_impact_radius(file_paths)            blast radius from a file
- get_flows(limit=20)                      pre-computed flows ranked by criticality
- get_flow_by_id(flow_id)                  step-by-step path of one flow
- trace_path(from_fn, to_fn)               call chain between two functions

━━━ OUTPUT FORMAT ━━━
After your investigation write a summary section.

If you found vulnerabilities, repeat this block once per finding
(multiple findings are allowed):

FINDING_START
VULN_TYPE: <e.g. SQL Injection, Command Injection, Path Traversal, XSS, IDOR…>
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW>
LOCATION: <file_path>:<line_number>
FUNCTION: <qualified function name>
CVSS: <numeric score 0.0–10.0, e.g. 9.8>
CVSS_VECTOR: <CVSS:3.1/AV:…/AC:…/PR:…/UI:…/S:…/C:…/I:…/A:…>
DESCRIPTION: <two to four sentences — what the vulnerability is and why it is dangerous>
POC: <concrete step-by-step exploit an attacker would perform>
REASONING: <two to four sentences — what you read, how input reaches the sink,
            why it is exploitable, what sanitisation is missing>
FINDING_END

If you found NO vulnerabilities write exactly:
NO_FINDINGS
REASONING: <one sentence — why this entry point is safe>
"""


# ── Parsing ────────────────────────────────────────────────────────────────────

_FINDING_BLOCK_RE = re.compile(
    r"FINDING_START\s*\n(.*?)FINDING_END", re.S
)
_FIELD_RE = {
    "vuln_type":   re.compile(r"VULN_TYPE\s*:\s*(.+)", re.I),
    "severity":    re.compile(r"SEVERITY\s*:\s*(CRITICAL|HIGH|MEDIUM|LOW)", re.I),
    "location":    re.compile(r"LOCATION\s*:\s*(.+)", re.I),
    "function":    re.compile(r"FUNCTION\s*:\s*(.+)", re.I),
    "cvss":        re.compile(r"CVSS\s*:\s*([\d.]+)", re.I),
    "cvss_vector": re.compile(r"CVSS_VECTOR\s*:\s*(.+?)(?=\n[A-Z_]+\s*:|$)", re.I | re.S),
    "description": re.compile(r"DESCRIPTION\s*:\s*(.+?)(?=\n[A-Z_]+\s*:|$)", re.I | re.S),
    "poc":         re.compile(r"POC\s*:\s*(.+?)(?=\n[A-Z_]+\s*:|$)", re.I | re.S),
    "reasoning":   re.compile(r"REASONING\s*:\s*(.+?)(?=\n[A-Z_]+\s*:|$)", re.I | re.S),
}


def _parse_findings(text: str, entry_name: str) -> list[dict]:
    """Extract zero or more FINDING blocks from the LLM's final response."""
    results = []
    for block in _FINDING_BLOCK_RE.finditer(text):
        body = block.group(1)
        vuln_type   = _field(body, "vuln_type") or "Unknown"
        severity    = (_field(body, "severity") or "MEDIUM").upper()
        location    = _field(body, "location") or ""
        function    = _field(body, "function") or entry_name
        reasoning   = _field(body, "reasoning") or ""
        description = _field(body, "description") or ""
        poc         = _field(body, "poc") or ""
        cvss_vector = (_field(body, "cvss_vector") or "").strip()
        cvss_score  = None
        raw_cvss    = _field(body, "cvss")
        if raw_cvss:
            try:
                cvss_score = float(raw_cvss)
            except ValueError:
                pass
        if cvss_vector.upper() in ("N/A", "NA", "NONE", "-"):
            cvss_vector = ""
        if poc.upper() in ("N/A", "NA", "NONE", "-"):
            poc = ""

        file_path = location
        line_start = 0
        if ":" in location:
            parts = location.rsplit(":", 1)
            file_path = parts[0]
            try:
                line_start = int(parts[1])
            except ValueError:
                pass

        results.append({
            "rule_id":     f"hunter.{vuln_type.lower().replace(' ', '-')}",
            "title":       vuln_type,
            "severity":    severity,
            "file_path":   file_path,
            "line_start":  line_start,
            "line_end":    line_start,
            "message":     (description or reasoning).strip()[:500],
            "reasoning":   reasoning.strip(),
            "description": description.strip(),
            "poc":         poc.strip(),
            "cvss_score":  cvss_score,
            "cvss_vector": cvss_vector,
            "function":    function,
            "source":      "hunter",
        })
    return results


def _field(text: str, key: str) -> Optional[str]:
    m = _FIELD_RE[key].search(text)
    return m.group(1).strip() if m else None


# ── Core logic ─────────────────────────────────────────────────────────────────

def hunt_one(
    entry: dict,
    llm_client: "LLMClient",
    graph: "GraphClient",
    max_turns: int = 15,
    max_tokens: int = 4096,
    vuln_store: Optional["VulnStore"] = None,
) -> list[dict]:
    """Run one hunt session for a single entry point.

    Returns a (possibly empty) list of finding dicts.
    """
    from graphsast.mcp.tools import TOOLS, execute_tool

    name     = entry.get("name") or entry.get("qualified_name", "unknown")
    qname    = entry.get("qualified_name", name)
    fp       = entry.get("file_path", "")
    line     = entry.get("line_start", "?")
    flow_id  = entry.get("flow_id")

    logger.info("Hunt: %s @ %s:%s", qname, fp, line)

    # ── VulnDB pre-flight ──────────────────────────────────────────────────────
    signal_block = ""
    if vuln_store is not None:
        try:
            from graphsast.analysis.vuln_context import detect_signals, format_signals_for_prompt
            signals = detect_signals(qname, fp, graph, vuln_store)
            signal_block = format_signals_for_prompt(signals)
        except Exception as exc:
            logger.debug("vuln_context failed for %s: %s", qname, exc)

    if flow_id:
        user_msg = (
            f"Audit this pre-computed execution flow (flow_id={flow_id}).\n\n"
            f"Flow entry point: {qname}\n"
            f"File: {fp}  Line: {line}\n\n"
            "Use get_flow_by_id to see the full path, then trace data through it."
        )
    else:
        user_msg = (
            f"Audit this entry point — it has no upstream callers.\n\n"
            f"Function: {qname}\n"
            f"File: {fp}  Line: {line}\n\n"
            "Start by reading the function, then follow the data."
        )

    if signal_block:
        user_msg += f"\n\n{signal_block}"

    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user",   "content": user_msg},
    ]

    def tool_executor(name: str, args: dict) -> str:
        return execute_tool(name, args, graph)

    try:
        final_messages, turns = llm_client.run_loop(
            messages,
            tool_schemas=TOOLS,
            tool_executor=tool_executor,
            max_turns=max_turns,
            max_tokens=max_tokens,
        )
        logger.debug("hunt_one: %s used %d turns", qname, turns)
    except Exception as exc:
        logger.error("LLM error hunting %s: %s", qname, exc)
        return []

    last_text = _extract_last_text(final_messages)
    findings = _parse_findings(last_text, qname)

    if findings:
        logger.info("  → %d finding(s) at %s", len(findings), qname)
    else:
        logger.info("  → no findings at %s", qname)

    return findings


def hunt(
    graph: "GraphClient",
    llm_client: "LLMClient",
    max_entry_points: int = 10,
    max_turns: int = 15,
    vuln_db_path: Optional[Path] = None,
) -> list[dict]:
    """Run a full autonomous hunt.

    Selects up to *max_entry_points* candidates from entry points and flows,
    runs hunt_one() for each, and returns all raw finding dicts.
    """
    candidates: list[dict] = []
    seen_names: set[str] = set()

    # Prefer pre-computed flows (have more context / criticality score)
    flows = graph.get_flows(limit=max_entry_points)
    for flow in flows:
        # flows are dicts with keys: id, entry_point, criticality, ...
        qname = flow.get("entry_point") or flow.get("qualified_name", "")
        if qname and qname not in seen_names:
            seen_names.add(qname)
            # Resolve file/line from graph
            node = graph.get_function(qname) or {}
            candidates.append({
                "qualified_name": qname,
                "name":           qname.split("::")[-1] if "::" in qname else qname,
                "file_path":      node.get("file_path", ""),
                "line_start":     node.get("line_start", 0),
                "flow_id":        flow.get("id"),
            })

    # Fill remaining slots from entry points
    if len(candidates) < max_entry_points:
        entry_points = graph.list_entry_points()
        for ep in entry_points:
            if len(candidates) >= max_entry_points:
                break
            qname = ep.get("qualified_name", "")
            if qname and qname not in seen_names:
                seen_names.add(qname)
                candidates.append(ep)

    logger.info(
        "Hunt: %d candidates (%d from flows, %d from entry points)",
        len(candidates),
        sum(1 for c in candidates if c.get("flow_id")),
        sum(1 for c in candidates if not c.get("flow_id")),
    )

    # ── Open vulndb if available ───────────────────────────────────────────────
    vuln_store = None
    if vuln_db_path and vuln_db_path.exists():
        try:
            from graphsast.vuln_db.store import VulnStore
            vuln_store = VulnStore(vuln_db_path)
            stats = vuln_store.stats()
            logger.info(
                "VulnDB: %d vuln classes, %d taint signatures",
                stats["vuln_classes"], stats["taint_signatures"],
            )
        except Exception as exc:
            logger.warning("Could not open vulndb at %s: %s", vuln_db_path, exc)
            vuln_store = None
    else:
        logger.debug("No vulndb found at %s — running without signal pre-flight", vuln_db_path)

    try:
        all_findings: list[dict] = []
        for i, candidate in enumerate(candidates, 1):
            logger.info(
                "[%d/%d] %s", i, len(candidates),
                candidate.get("qualified_name", "?"),
            )
            findings = hunt_one(
                candidate, llm_client, graph,
                max_turns=max_turns,
                vuln_store=vuln_store,
            )
            all_findings.extend(findings)
    finally:
        if vuln_store is not None:
            vuln_store.close()

    return all_findings


# ── Helpers ────────────────────────────────────────────────────────────────────

def _extract_last_text(messages: list[dict]) -> str:
    for msg in reversed(messages):
        if msg.get("role") == "assistant":
            content = msg.get("content")
            if isinstance(content, str) and content.strip():
                return content
            if isinstance(content, list):
                for block in reversed(content):
                    if isinstance(block, dict) and block.get("type") == "text":
                        text = block.get("text", "")
                        if text.strip():
                            return text
    return ""
