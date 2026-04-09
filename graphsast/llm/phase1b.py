"""Phase 1B — ReAct validation loop for graph-identified suspect paths.

The graph already found a specific suspect path (source → sink via taint,
or entry point with missing check). Phase 1B asks the LLM:
  "Here is the specific evidence. Is this a real vulnerability or a false positive?"

Three-layer resolution:
  Layer 1: pattern + graph alone (no LLM) — handles ~65% of cases
  Layer 2: single-shot LLM validation (max 5 turns)
  Layer 3: micro-task (yes/no only) for anything Layer 2 left uncertain

Findings stored in phase1b_findings table.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

from graphsast.graph_db.store import SecurityGraphStore
from graphsast.llm.base import LLMClient
from graphsast.llm.cache import make_cache_key, get_cached, set_cached
from graphsast.llm.tools import GraphTools, TOOL_SCHEMAS
from graphsast.analysis.phase3.correlator import Finding

logger = logging.getLogger(__name__)

MAX_TURNS_L2 = 5
MAX_TURNS_L3 = 3


SYSTEM_PROMPT_L2 = """You are a security engineer validating a potential vulnerability.

The code graph has flagged a specific suspect path. Your job is to confirm whether
this is a real, exploitable vulnerability or a false positive.

Use the tools to read actual source code if you need more evidence.

When you have enough information, output your verdict as JSON:
{
  "verdict": "CONFIRMED" | "FALSE_POSITIVE" | "UNCERTAIN",
  "confidence": "HIGH" | "MEDIUM" | "LOW",
  "reasoning": "explanation",
  "cwe_id": "CWE-XX or empty",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
}

Be conservative: only output CONFIRMED if you have read the actual code and
are certain the vulnerability exists and is exploitable.
"""

SYSTEM_PROMPT_L3 = """Answer with ONLY a JSON object, nothing else:
{"verdict": "CONFIRMED" or "FALSE_POSITIVE", "reasoning": "one sentence"}
"""


def validate_finding(
    graph: SecurityGraphStore,
    finding: Finding,
    client: LLMClient,
    scan_run_id: str = "",
) -> dict:
    """Run Phase 1B validation for a single Phase 2 finding.

    Returns a phase1b result dict.
    Skips LLM layers if a valid cache entry exists for this
    (qualified_name, file_hash, vuln_class, model) combination.
    """
    # Layer 1: pattern + graph — free, always run
    layer1_result = _try_layer1(graph, finding)
    if layer1_result:
        return _make_result(
            finding, layer1_result["verdict"], layer1_result["confidence"],
            layer1_result["reasoning"], method="pattern+graph",
            scan_run_id=scan_run_id, model="none", turns_used=0,
        )

    # ── Cache check (before expensive LLM layers) ─────────────────────────────
    vuln_class = finding.vuln_class_ids[0] if finding.vuln_class_ids else ""
    cache_key = make_cache_key(
        "1b",
        finding.qualified_name or "",
        finding.file_path or "",
        client.model,
        vuln_class_id=vuln_class,
    )
    cached = get_cached(graph._conn, cache_key)
    if cached:
        logger.info("Phase 1B cache HIT: %s [%s]", finding.qualified_name, vuln_class)
        cached["scan_run_id"] = scan_run_id
        return cached

    # Layer 2: single-shot LLM with tools
    l2 = _run_layer2(graph, finding, client, scan_run_id)
    if l2["verdict"] != "UNCERTAIN":
        set_cached(graph._conn, cache_key, "1b", l2)
        return l2

    # Layer 3: micro-task (yes/no)
    result = _run_layer3(graph, finding, client, l2, scan_run_id)
    set_cached(graph._conn, cache_key, "1b", result)
    return result


def run_phase1b(
    graph: SecurityGraphStore,
    findings: list[Finding],
    client: LLMClient,
    scan_run_id: str = "",
    sources_to_validate: list[str] | None = None,
) -> list[dict]:
    """Validate all Phase 2 findings that are worth LLM review.

    Args:
        sources_to_validate: which finding sources to validate.
                             Defaults to ['graph_taint', 'semgrep'].
    """
    if sources_to_validate is None:
        sources_to_validate = ["graph_taint", "semgrep"]

    candidates = [
        f for f in findings
        if any(s in f.sources for s in sources_to_validate)
        and f.severity in ("CRITICAL", "HIGH", "MEDIUM")
    ]

    logger.info("Phase 1B: validating %d candidates", len(candidates))

    results = []
    for f in candidates:
        try:
            r = validate_finding(graph, f, client, scan_run_id)
            _save_result(graph, r)
            results.append(r)
            logger.info(
                "Phase 1B [%s] %s | %s (%s)",
                r["method"], r["qualified_name"], r["verdict"], r["confidence"],
            )
        except Exception as exc:
            logger.error("Phase 1B failed for %s: %s", f.qualified_name, exc)

    confirmed = [r for r in results if r["verdict"] == "CONFIRMED"]
    fp        = [r for r in results if r["verdict"] == "FALSE_POSITIVE"]
    logger.info(
        "Phase 1B complete: %d confirmed, %d false positives, %d uncertain",
        len(confirmed), len(fp), len(results) - len(confirmed) - len(fp),
    )
    return results


# ──────────────────────────────────────────────────────────────────────────────
# Layer implementations
# ──────────────────────────────────────────────────────────────────────────────

def _try_layer1(graph: SecurityGraphStore, finding: Finding) -> dict | None:
    """Layer 1: resolve without LLM using graph + pattern data alone.

    Returns a result dict if resolved, else None.
    """
    # Case 1: parameterised query — definitely not SQLi
    if "graph_taint" in finding.sources:
        extra = finding.extra or {}
        if extra.get("arg_type") == "tuple":
            return {
                "verdict": "FALSE_POSITIVE",
                "confidence": "HIGH",
                "reasoning": "Argument is a tuple (parameterised query) — not injectable.",
            }

    # Case 2: is_concatenated=True AND HIGH/CRITICAL severity — high confidence confirm
    if finding.cwe_id in ("CWE-89", "CWE-78", "CWE-95"):
        extra = finding.extra or {}
        if extra.get("is_concatenated") and finding.severity in ("CRITICAL", "HIGH"):
            return {
                "verdict": "CONFIRMED",
                "confidence": "HIGH",
                "reasoning": (
                    f"Direct string concatenation ({extra.get('arg_type')}) "
                    f"passed to {extra.get('sink_qn','sink')} — {finding.cwe_id} confirmed."
                ),
            }

    # Case 3: missing_check findings — already definitively flagged by graph
    if "missing_check" in finding.sources and "graph_taint" not in finding.sources:
        return {
            "verdict": "CONFIRMED",
            "confidence": "MEDIUM",
            "reasoning": "Graph BFS confirms this security check is absent from the entry point's call chain.",
        }

    return None  # needs LLM


def _run_layer2(
    graph: SecurityGraphStore,
    finding: Finding,
    client: LLMClient,
    scan_run_id: str,
) -> dict:
    graph_tools = GraphTools(graph)
    prompt = _build_validation_prompt(finding)

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT_L2},
        {"role": "user",   "content": prompt},
    ]

    messages, turns = client.run_loop(
        messages=messages,
        tool_schemas=TOOL_SCHEMAS,
        tool_executor=graph_tools.execute,
        max_turns=MAX_TURNS_L2,
    )

    assistant_msgs = [m for m in messages if m.get("role") == "assistant"]
    last_text = _extract_text(assistant_msgs[-1]) if assistant_msgs else ""
    verdict_json = _extract_json(last_text)

    verdict    = verdict_json.get("verdict", "UNCERTAIN")
    confidence = verdict_json.get("confidence", "LOW")
    reasoning  = verdict_json.get("reasoning", last_text[:1000])
    cwe_id     = verdict_json.get("cwe_id", finding.cwe_id)
    severity   = verdict_json.get("severity", finding.severity)

    return _make_result(
        finding, verdict, confidence, reasoning,
        method="llm-single", scan_run_id=scan_run_id,
        model=client.model, turns_used=turns,
        cwe_id=cwe_id, severity=severity,
    )


def _run_layer3(
    graph: SecurityGraphStore,
    finding: Finding,
    client: LLMClient,
    l2_result: dict,
    scan_run_id: str,
) -> dict:
    """Layer 3: yes/no micro-task for uncertain Layer 2 results."""
    graph_tools = GraphTools(graph)

    # Distil the specific uncertainty from L2's reasoning
    uncertainty = l2_result.get("reasoning", "")[:400]
    prompt = (
        f"Vulnerability: {finding.title} ({finding.cwe_id})\n"
        f"Location: {finding.qualified_name}\n"
        f"Uncertainty from previous analysis: {uncertainty}\n\n"
        f"Fetch the source code with fetch_function_source and decide: "
        f"is this a real exploitable vulnerability? Answer CONFIRMED or FALSE_POSITIVE."
    )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT_L3},
        {"role": "user",   "content": prompt},
    ]

    messages, turns = client.run_loop(
        messages=messages,
        tool_schemas=TOOL_SCHEMAS,
        tool_executor=graph_tools.execute,
        max_turns=MAX_TURNS_L3,
    )

    assistant_msgs = [m for m in messages if m.get("role") == "assistant"]
    last_text = _extract_text(assistant_msgs[-1]) if assistant_msgs else ""
    verdict_json = _extract_json(last_text)

    verdict   = verdict_json.get("verdict", "UNCERTAIN")
    reasoning = verdict_json.get("reasoning", last_text[:500])

    return _make_result(
        finding, verdict, "LOW", reasoning,
        method="llm-microtask", scan_run_id=scan_run_id,
        model=client.model, turns_used=turns,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _build_validation_prompt(finding: Finding) -> str:
    lines = [
        f"## Suspect path to validate\n",
        f"Title     : {finding.title}",
        f"CWE       : {finding.cwe_id}",
        f"Severity  : {finding.severity}",
        f"Location  : {finding.qualified_name}",
        f"File      : {finding.file_path}:{finding.line_start}",
        f"Sources   : {', '.join(finding.sources)}",
        f"\nMessage: {finding.message}",
    ]

    extra = finding.extra or {}
    if extra.get("taint_path"):
        lines.append(f"\nTaint path: {' -> '.join(str(n) for n in extra['taint_path'])}")
    if extra.get("arg_type"):
        lines.append(f"Arg type  : {extra['arg_type']}")
        lines.append(f"Concat    : {extra.get('is_concatenated')}")
    if extra.get("missing_type"):
        lines.append(f"Missing   : {extra['missing_type']}")

    lines.append(
        "\n\nFetch the source code of the flagged function and any relevant callees. "
        "Then determine: is this a real, exploitable vulnerability? Output your verdict as JSON."
    )
    return "\n".join(lines)


def _make_result(
    finding: Finding,
    verdict: str,
    confidence: str,
    reasoning: str,
    method: str,
    scan_run_id: str,
    model: str,
    turns_used: int,
    cwe_id: str | None = None,
    severity: str | None = None,
) -> dict:
    return {
        "id": str(uuid.uuid4())[:16],
        "scan_run_id": scan_run_id,
        "qualified_name": finding.qualified_name or "",
        "vuln_class_id": (finding.vuln_class_ids[0] if finding.vuln_class_ids else ""),
        "suspect_path": json.dumps(finding.extra or {}),
        "verdict": verdict,
        "confidence": confidence,
        "method": method,
        "cwe_id": cwe_id or finding.cwe_id,
        "severity": severity or finding.severity,
        "reasoning": reasoning,
        "source_seen": "[]",
        "turns_used": turns_used,
        "taint_path": json.dumps((finding.extra or {}).get("taint_path", [])),
        "model": model,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _extract_text(msg: dict) -> str:
    content = msg.get("content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(
            b.get("text", "") for b in content if isinstance(b, dict)
        )
    return str(content)


def _extract_json(text: str) -> dict:
    import re
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
    if not m:
        m = re.search(r'(\{[^{}]*"verdict"[^{}]*\})', text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    try:
        start = text.rfind("{")
        end   = text.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(text[start:end])
    except (json.JSONDecodeError, ValueError):
        pass
    return {}


def _save_result(graph: SecurityGraphStore, r: dict) -> None:
    graph._conn.execute(
        """INSERT OR REPLACE INTO phase1b_findings
           (id, scan_run_id, qualified_name, vuln_class_id, suspect_path,
            verdict, confidence, method, cwe_id, severity, reasoning,
            source_seen, turns_used, taint_path, model, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            r["id"], r["scan_run_id"], r["qualified_name"], r["vuln_class_id"],
            r["suspect_path"], r["verdict"], r["confidence"], r["method"],
            r["cwe_id"], r["severity"], r["reasoning"], r["source_seen"],
            r["turns_used"], r["taint_path"], r["model"], r["timestamp"],
        ),
    )
    graph.commit()
