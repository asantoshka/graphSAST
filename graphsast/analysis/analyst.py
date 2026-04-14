"""LLM analyst — investigates one Semgrep finding at a time.

For each finding the analyst:
  1. Builds a system prompt describing the task.
  2. Sends the finding details as the first user message.
  3. Runs a tool loop — the LLM can call graph navigation tools
     to read code, trace call paths, and explore context.
  4. Parses a structured verdict from the final LLM message.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from graphsast.graph.client import GraphClient
    from graphsast.llm.base import LLMClient

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
/no_think
You are a security analyst investigating a potential vulnerability flagged by Semgrep.
Your goal is to determine with confidence whether this is a real exploitable issue.

━━━ INVESTIGATION PROTOCOL — follow these steps in order ━━━

STEP 1 — READ THE FLAGGED CODE
  • Call get_function(name) for the function named in the finding.
  • If not found, call get_file_summary(path) to orient yourself, then
    read_file(path, start_line, end_line) with ~20 lines of context around the finding.

STEP 2 — TRACE DATA SOURCES (callers)
  • Call get_callers(name) to find who calls the flagged function.
  • For each relevant caller, call get_function(caller_name) to see what
    arguments they pass. Ask: is this input user-controlled or hardcoded?

STEP 3 — TRACE DATA SINKS (callees)
  • Call get_callees(name) to see what the function does with the data.
  • Look for dangerous sinks: SQL execution, shell commands, file writes,
    HTTP response bodies, template rendering, deserialization.

STEP 4 — CHECK FOR SANITISATION
  • Search for validators or escape functions near the call path:
    search_nodes("sanitize"), search_nodes("validate"), search_nodes("escape"),
    search_nodes("quote"), search_nodes("clean").
  • If found, read the sanitizer to confirm it actually covers this data path.

STEP 5 — CONFIRM REACHABILITY FROM USER INPUT
  • Use trace_path(entry_fn, flagged_fn) or get_flows() to verify the
    flagged code is reachable from an HTTP handler, CLI argument, or
    other user-controlled entry point.
  • If flows are available, use get_flow_by_id(id) on any flow that
    passes through the vulnerable file.

━━━ RULES ━━━
• You MUST call at least 5 tools before writing a verdict.
• NEVER base a verdict on the Semgrep snippet alone — always read the real source.
• If a tool returns nothing, try a related name or use search_nodes(pattern).
• If a function has no callers in the graph, check list_entry_points() —
  it may be a direct entry point itself.
• Keep investigating until you can answer:
  "Can an attacker control the dangerous input, and does it reach the sink unsanitised?"

━━━ AVAILABLE TOOLS ━━━
- get_function(name)                       read a function's full source + metadata
- get_callers(name)                        who calls this function (data sources)
- get_callees(name)                        what this function calls (data sinks)
- search_nodes(pattern, limit=20)          find functions/classes by name pattern
- read_file(path, start_line, end_line)    read a file or a line range
- get_file_summary(path)                   all symbols in a file with line ranges
- get_nodes_by_file(path)                  full metadata for every symbol in a file
- list_entry_points()                      public handlers with no callers
- get_edges_for_node(qualified_name)       all edges (CALLS, IMPORTS_FROM, INHERITS…)
- get_impact_radius(file_paths)            blast radius from a file
- get_flows(limit=20)                      pre-computed flows ranked by criticality
- get_flow_by_id(flow_id)                  step-by-step path of one flow
- trace_path(from_fn, to_fn)              call chain between two functions

━━━ VERDICT FORMAT ━━━
After your investigation, end with EXACTLY this block (all fields required):

VERDICT: <CONFIRMED|FALSE_POSITIVE|NEEDS_REVIEW>
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW>
CVSS: <numeric score 0.0–10.0, e.g. 8.1>
CVSS_VECTOR: <CVSS:3.1/AV:…/AC:…/PR:…/UI:…/S:…/C:…/I:…/A:… or N/A>
DESCRIPTION: <two to four sentences — what the vulnerability is, why it is dangerous>
POC: <Step-by-step exploit. Must include: (1) exact payload or input value, (2) how to deliver it
     (HTTP request with headers/params, CLI argument, file content, env var, etc.),
     (3) what happens on the server/system, (4) what the attacker gains.
     Example for SQLi: "Send POST /login with body username=admin'--&password=x — the query
     becomes SELECT * FROM users WHERE username='admin'--'… returning admin row without password check."
     Use "N/A" only for FALSE_POSITIVE verdicts.>
REASONING: <one to three sentences — what you read and what you found>
"""


def analyse_finding(
    raw: dict,
    llm_client: "LLMClient",
    graph: "GraphClient",
    max_turns: int = 15,
    max_tokens: int = 4096,
) -> dict:
    """Investigate one raw semgrep finding dict and return a verdict dict.

    Returns:
        {
            "verdict":   "CONFIRMED" | "FALSE_POSITIVE" | "NEEDS_REVIEW",
            "severity":  "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
            "reasoning": str,
        }
    """
    from graphsast.mcp.tools import TOOLS, execute_tool

    check_id   = raw.get("check_id", "unknown")
    file_path  = raw.get("path", "")
    start      = raw.get("start", {})
    extra      = raw.get("extra", {})
    message    = (extra.get("message") or "")[:500]
    severity   = (extra.get("severity") or "MEDIUM").upper()
    snippet    = (extra.get("lines") or "").strip()

    logger.info("Analysing: %s @ %s:%s", check_id, file_path, start.get("line", "?"))

    user_message = f"""\
Semgrep finding:

Rule:     {check_id}
File:     {file_path}
Line:     {start.get('line', '?')}
Severity: {severity}
Message:  {message}
"""
    if snippet:
        user_message += f"\nCode:\n```\n{snippet}\n```\n"

    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user",   "content": user_message},
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
        logger.debug("analyst: %s used %d turns", check_id, turns)
    except Exception as exc:
        logger.error("LLM error for %s: %s", check_id, exc)
        return _unknown_verdict()

    # Extract last assistant text message
    last_text = ""
    for msg in reversed(final_messages):
        if msg.get("role") == "assistant":
            content = msg.get("content")
            if isinstance(content, str) and content.strip():
                last_text = content
                break
            # Some backends return content as a list of blocks
            if isinstance(content, list):
                for block in reversed(content):
                    if isinstance(block, dict) and block.get("type") == "text":
                        last_text = block.get("text", "")
                        break
                if last_text:
                    break

    verdict = _parse_verdict(last_text)

    # Fallback: if the LLM didn't output a structured verdict, ask for it explicitly
    if verdict["verdict"] == "NEEDS_REVIEW" and verdict["reasoning"] == "LLM analysis could not produce a verdict.":
        try:
            final_messages.append({
                "role": "user",
                "content": (
                    "Based on your investigation above, write your verdict now.\n"
                    "Use EXACTLY this format:\n"
                    "VERDICT: <CONFIRMED|FALSE_POSITIVE|NEEDS_REVIEW>\n"
                    "SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW>\n"
                    "REASONING: <one sentence>\n"
                ),
            })
            retry_messages, _ = llm_client.run_loop(
                final_messages,
                tool_schemas=[],   # no tools — just need text
                tool_executor=lambda n, a: "",
                max_turns=1,
                max_tokens=512,
            )
            retry_text = ""
            for msg in reversed(retry_messages):
                if msg.get("role") == "assistant":
                    content = msg.get("content")
                    if isinstance(content, str) and content.strip():
                        retry_text = content
                        break
                    if isinstance(content, list):
                        for block in reversed(content):
                            if isinstance(block, dict) and block.get("type") == "text":
                                retry_text = block.get("text", "")
                                break
                        if retry_text:
                            break
            if retry_text:
                verdict = _parse_verdict(retry_text)
        except Exception as exc:
            logger.debug("Verdict fallback failed: %s", exc)

    logger.info(
        "Verdict: %s (%s) — %s",
        verdict["verdict"], verdict["severity"],
        verdict["reasoning"][:100] + ("…" if len(verdict["reasoning"]) > 100 else ""),
    )
    return verdict


# ── Verdict parsing ────────────────────────────────────────────────────────────

_VERDICT_RE     = re.compile(r"VERDICT\s*:\s*(CONFIRMED|FALSE_POSITIVE|NEEDS_REVIEW)", re.I)
_SEVERITY_RE    = re.compile(r"SEVERITY\s*:\s*(CRITICAL|HIGH|MEDIUM|LOW)", re.I)
_CVSS_RE        = re.compile(r"CVSS\s*:\s*([\d.]+)", re.I)
_CVSS_VEC_RE    = re.compile(r"CVSS_VECTOR\s*:\s*(.+?)(?:\n[A-Z_]+\s*:|$)", re.I | re.S)
_DESCRIPTION_RE = re.compile(r"DESCRIPTION\s*:\s*(.+?)(?:\n[A-Z_]+\s*:|$)", re.I | re.S)
_POC_RE         = re.compile(r"POC\s*:\s*(.+?)(?:\n[A-Z_]+\s*:|$)", re.I | re.S)
_REASON_RE      = re.compile(r"REASONING\s*:\s*(.+?)(?:\n[A-Z_]+\s*:|$)", re.I | re.S)


def _parse_verdict(text: str) -> dict:
    verdict_m     = _VERDICT_RE.search(text)
    severity_m    = _SEVERITY_RE.search(text)
    cvss_m        = _CVSS_RE.search(text)
    cvss_vec_m    = _CVSS_VEC_RE.search(text)
    description_m = _DESCRIPTION_RE.search(text)
    poc_m         = _POC_RE.search(text)
    reason_m      = _REASON_RE.search(text)

    if not verdict_m:
        return _unknown_verdict()

    cvss_score = None
    if cvss_m:
        try:
            cvss_score = float(cvss_m.group(1))
        except ValueError:
            pass

    cvss_vector = cvss_vec_m.group(1).strip() if cvss_vec_m else None
    if cvss_vector and cvss_vector.upper() in ("N/A", "NA", "NONE", "-"):
        cvss_vector = None

    description = description_m.group(1).strip() if description_m else None
    poc = poc_m.group(1).strip() if poc_m else None
    if poc and poc.upper() in ("N/A", "NA", "NONE", "-"):
        poc = None

    return {
        "verdict":     verdict_m.group(1).upper(),
        "severity":    severity_m.group(1).upper() if severity_m else "MEDIUM",
        "reasoning":   reason_m.group(1).strip() if reason_m else text.strip()[:500],
        "description": description,
        "poc":         poc,
        "cvss_score":  cvss_score,
        "cvss_vector": cvss_vector,
    }


def _unknown_verdict() -> dict:
    return {
        "verdict":     "NEEDS_REVIEW",
        "severity":    "MEDIUM",
        "reasoning":   "LLM analysis could not produce a verdict.",
        "description": None,
        "poc":         None,
        "cvss_score":  None,
        "cvss_vector": None,
    }
