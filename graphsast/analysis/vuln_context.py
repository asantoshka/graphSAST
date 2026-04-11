"""VulnDB-guided pre-flight signal detection for the hunt.

Before the LLM investigates an entry point, this module walks its callgraph
(BFS, depth ≤ 3) and matches reachable function names against known SINK
patterns in the vulnerability database.

For each matched sink we also pull the corresponding SOURCE and SANITIZER
signatures so the LLM gets a complete "here's what to trace" brief.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from graphsast.graph.client import GraphClient
    from graphsast.vuln_db.store import VulnStore

logger = logging.getLogger(__name__)

# File extension → language tag used in taint_signatures
_EXT_TO_LANG: dict[str, str] = {
    ".py":   "python",
    ".js":   "javascript",
    ".mjs":  "javascript",
    ".cjs":  "javascript",
    ".ts":   "typescript",
    ".tsx":  "typescript",
    ".cs":   "csharp",
    ".java": "java",
    ".go":   "go",
    ".rb":   "ruby",
    ".php":  "php",
}


def _lang_from_path(file_path: str) -> Optional[str]:
    return _EXT_TO_LANG.get(Path(file_path).suffix.lower())


def _callee_names(qname: str) -> list[str]:
    """Return candidate short names to match against sink patterns.

    For a qualified name like '/repo/app.js::Router::getUser' we emit:
      - 'Router::getUser'
      - 'getUser'
      - '/repo/app.js::Router::getUser'  (full, for exact matches)
    """
    parts = qname.split("::")
    candidates = [qname]
    if len(parts) >= 2:
        candidates.append("::".join(parts[-2:]))
    candidates.append(parts[-1])
    return candidates


def _matches_pattern(names: list[str], pattern: str) -> bool:
    """True if *pattern* is a substring of any candidate name (case-insensitive)."""
    p = pattern.lower()
    return any(p in n.lower() for n in names)


def detect_signals(
    entry_qname: str,
    file_path: str,
    graph: "GraphClient",
    vuln_store: "VulnStore",
    max_depth: int = 3,
) -> list[dict]:
    """Walk callgraph from *entry_qname* and match callees against vulndb SINKs.

    Returns a list of signal dicts, one per matched vuln_class:
    {
        "vuln_class_id": str,
        "cwe_id": str,
        "name": str,
        "severity": str,
        "matched_sinks": [str, ...],
        "known_sources": [str, ...],
        "known_sanitizers": [str, ...],
    }

    Returns empty list if vulns.db has no data or no matches are found.
    """
    lang = _lang_from_path(file_path)

    # ── Load taint signatures from vulndb ─────────────────────────────────────
    all_sigs = vuln_store.get_all_taint_signatures()
    if not all_sigs:
        return []

    # Index by sig_type × vuln_class_id for fast lookup
    sinks_by_class:      dict[str, list[str]] = {}
    sources_by_class:    dict[str, list[str]] = {}
    sanitizers_by_class: dict[str, list[str]] = {}

    for sig in all_sigs:
        sig_lang = sig.get("language", "any")
        # Keep sigs that match the file's language or are language-agnostic
        if lang and sig_lang not in ("any", lang):
            continue
        vc_id = sig["vuln_class_id"]
        pat   = sig["qualified_pattern"]
        st    = sig["sig_type"].upper()
        if st == "SINK":
            sinks_by_class.setdefault(vc_id, []).append(pat)
        elif st == "SOURCE":
            sources_by_class.setdefault(vc_id, []).append(pat)
        elif st == "SANITIZER":
            sanitizers_by_class.setdefault(vc_id, []).append(pat)

    if not sinks_by_class:
        return []

    # ── BFS through callgraph ─────────────────────────────────────────────────
    visited:   set[str] = {entry_qname}
    frontier:  list[str] = [entry_qname]
    all_callees: set[str] = set()

    for _ in range(max_depth):
        next_frontier: list[str] = []
        for qname in frontier:
            callees = graph.get_callees(qname)
            for c in callees:
                cq = c.get("qualified_name", "")
                if cq and cq not in visited:
                    visited.add(cq)
                    all_callees.add(cq)
                    next_frontier.append(cq)
        if not next_frontier:
            break
        frontier = next_frontier

    logger.debug(
        "vuln_context: %d reachable callees from %s (depth=%d)",
        len(all_callees), entry_qname, max_depth,
    )

    if not all_callees:
        return []

    # ── Match callees against sink patterns ───────────────────────────────────
    matched: dict[str, list[str]] = {}   # vuln_class_id → matched sink names

    for callee_qname in all_callees:
        names = _callee_names(callee_qname)
        for vc_id, sink_pats in sinks_by_class.items():
            for pat in sink_pats:
                if _matches_pattern(names, pat):
                    matched.setdefault(vc_id, [])
                    # Record the actual callee name that triggered the match
                    short = callee_qname.split("::")[-1]
                    if short not in matched[vc_id]:
                        matched[vc_id].append(short)

    if not matched:
        return []

    # ── Build signal dicts ────────────────────────────────────────────────────
    signals: list[dict] = []
    for vc_id, sink_names in matched.items():
        vc = vuln_store.get_vuln_class(vc_id)
        if not vc:
            continue
        signals.append({
            "vuln_class_id":    vc_id,
            "cwe_id":           vc.get("cwe_id", ""),
            "name":             vc.get("name", vc_id),
            "severity":         vc.get("severity", "MEDIUM"),
            "matched_sinks":    sink_names,
            "known_sources":    sources_by_class.get(vc_id, []),
            "known_sanitizers": sanitizers_by_class.get(vc_id, []),
        })

    # Sort by severity (CRITICAL first)
    _sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    signals.sort(key=lambda s: _sev_rank.get(s["severity"].upper(), 4))

    logger.info(
        "vuln_context: %d signal(s) for %s — %s",
        len(signals),
        entry_qname,
        ", ".join(f"{s['name']} ({s['severity']})" for s in signals),
    )
    return signals


def format_signals_for_prompt(signals: list[dict]) -> str:
    """Render signals as a concise prompt injection block."""
    if not signals:
        return ""

    lines = ["━━━ VulnDB signals detected in this call graph ━━━\n"]
    for sig in signals:
        sinks = ", ".join(sig["matched_sinks"][:5]) or "—"
        sources = ", ".join(sig["known_sources"][:6]) or "—"
        sanitizers = ", ".join(sig["known_sanitizers"][:4]) or "none known"
        cwe = f" ({sig['cwe_id']})" if sig["cwe_id"] else ""
        lines.append(
            f"⚠  {sig['name']}{cwe}  [{sig['severity']}]\n"
            f"   Matched sinks    : {sinks}\n"
            f"   Known sources    : {sources}\n"
            f"   Known sanitizers : {sanitizers}\n"
        )

    lines.append(
        "Focus STEP 2 and STEP 3 on the matched sinks and their sources first.\n"
        "If the actual code doesn't match a signal, investigate other patterns normally.\n"
    )
    return "\n".join(lines)
