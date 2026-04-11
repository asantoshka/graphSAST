"""LLM-powered codebase describer.

Takes graph stats + entry points + flows and asks the LLM to write a
narrative description of the application: what it does, its architecture,
key data flows, and security-relevant observations.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from graphsast.graph.client import GraphClient
    from graphsast.llm.base import LLMClient

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
/no_think
You are a senior software architect reviewing a codebase via its call graph.
You have been given structured data extracted from the graph — file counts,
node/edge statistics, entry points, execution flows, and hub functions.

Write a clear, well-structured technical description covering:

1. OVERVIEW — What does this application do? What kind of system is it?
   (web API, CLI tool, data pipeline, library, etc.)

2. ARCHITECTURE — Key modules/layers and how they relate. Name the important
   files and describe their roles. Identify patterns (MVC, service layer,
   repository, etc.) if present.

3. DATA FLOWS — Describe the most important execution flows. How does data
   enter the system, get processed, and leave? What are the critical paths?

4. EXTERNAL DEPENDENCIES — What external systems, APIs, or services does this
   code interact with? (databases, cloud services, message queues, etc.)

5. SECURITY OBSERVATIONS — Based purely on the structure (not deep code
   analysis), note anything worth a closer look: large entry surfaces, direct
   database access from handlers, external data flows, authentication patterns.

Keep the description factual and grounded in the data provided.
Be concise but thorough. Use markdown with headers and bullet points.
"""


def describe(
    graph: "GraphClient",
    llm_client: "LLMClient",
    repo_root: Path,
    max_tokens: int = 4096,
) -> str:
    """Generate an LLM narrative description of the codebase.

    Returns a markdown string.
    """
    stats = graph.get_stats()
    entry_points = graph.list_entry_points()
    flows = graph.get_flows(limit=20)

    # Build context block
    context = _build_context(stats, entry_points, flows, repo_root)

    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user",   "content": context},
    ]

    try:
        resp_messages, _ = llm_client.run_loop(
            messages,
            tool_schemas=[],
            tool_executor=lambda n, a: "",
            max_turns=1,
            max_tokens=max_tokens,
        )
    except Exception as exc:
        logger.error("LLM describe failed: %s", exc)
        return "_LLM description unavailable._"

    for msg in reversed(resp_messages):
        if msg.get("role") == "assistant":
            content = msg.get("content")
            if isinstance(content, str) and content.strip():
                return content.strip()
            if isinstance(content, list):
                for block in reversed(content):
                    if isinstance(block, dict) and block.get("type") == "text":
                        text = block.get("text", "").strip()
                        if text:
                            return text
    return "_LLM description unavailable._"


def _build_context(
    stats: dict,
    entry_points: list[dict],
    flows: list[dict],
    repo_root: Path,
) -> str:
    lines: list[str] = []

    lines.append(f"## Codebase: {repo_root.name}\n")

    # ── Stats ──────────────────────────────────────────────────────────────────
    lines.append("### Graph Statistics")
    lines.append(f"- Files: {stats['files']}")
    lines.append(f"- Total nodes: {stats['nodes_total']}")
    for kind, cnt in stats["nodes_by_kind"].items():
        lines.append(f"  - {kind}: {cnt}")
    lines.append(f"- Total edges: {stats['edges_total']}")
    for kind, cnt in stats["edges_by_kind"].items():
        lines.append(f"  - {kind}: {cnt}")
    lines.append(f"- Pre-computed flows: {stats['flows']}")
    lines.append(f"- Entry points (no callers): {len(entry_points)}\n")

    # ── Languages ──────────────────────────────────────────────────────────────
    if stats["languages"]:
        lines.append("### Language Breakdown")
        total_lang = sum(stats["languages"].values())
        for lang, cnt in stats["languages"].items():
            pct = round(100 * cnt / total_lang) if total_lang else 0
            lines.append(f"- {lang}: {cnt} symbols ({pct}%)")
        lines.append("")

    # ── Top files ──────────────────────────────────────────────────────────────
    if stats["top_files"]:
        lines.append("### Top Files by Symbol Count")
        for tf in stats["top_files"]:
            try:
                rel = Path(tf["file_path"]).relative_to(repo_root).as_posix()
            except ValueError:
                rel = tf["file_path"]
            lines.append(f"- {rel}  ({tf['symbol_count']} symbols)")
        lines.append("")

    # ── Hub functions ──────────────────────────────────────────────────────────
    if stats["hub_functions"]:
        lines.append("### Most-Called Functions (Hubs)")
        for hf in stats["hub_functions"]:
            name = hf["qualified_name"].split("::")[-1] if "::" in hf["qualified_name"] else hf["qualified_name"]
            lines.append(f"- {name}  (called by {hf['caller_count']} functions)  — {hf['qualified_name']}")
        lines.append("")

    # ── Entry points ───────────────────────────────────────────────────────────
    if entry_points:
        lines.append("### Entry Points (Public API Surface)")
        # Group by file
        by_file: dict[str, list[str]] = {}
        for ep in entry_points:
            fp = ep.get("file_path") or "unknown"
            try:
                fp = Path(fp).relative_to(repo_root).as_posix()
            except ValueError:
                pass
            by_file.setdefault(fp, []).append(
                f"{ep.get('name', '?')}  (line {ep.get('line_start', '?')})"
            )
        for fp, names in by_file.items():
            lines.append(f"\n**{fp}**")
            for n in names:
                lines.append(f"  - {n}")
        lines.append("")

    # ── Top flows ──────────────────────────────────────────────────────────────
    if flows:
        lines.append("### Pre-Computed Execution Flows (by criticality)")
        for i, flow in enumerate(flows[:15], 1):
            name       = flow.get("name") or flow.get("entry_point", "?")
            depth      = flow.get("depth", "?")
            node_count = flow.get("node_count", "?")
            file_count = flow.get("file_count", "?")
            crit       = flow.get("criticality", 0)
            lines.append(
                f"{i}. **{name}**  depth={depth}, nodes={node_count}, "
                f"files={file_count}, criticality={crit:.2f}"
            )
        lines.append("")

    return "\n".join(lines)
