"""JSON report formatter.

Produces a structured JSON report suitable for CI pipelines and tooling.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from graphsast.analysis.phase3.correlator import Finding


def to_json(
    findings: list[Finding],
    target: Path,
    scan_run_id: str = "",
    elapsed: float = 0.0,
) -> dict:
    """Convert findings to a structured report dict.

    Active and suppressed findings are separated in the output so consumers
    can choose what to act on.
    """
    active     = [f for f in findings if not f.is_suppressed]
    suppressed = [f for f in findings if f.is_suppressed]

    return {
        "schema_version": "1.1",
        "scan_run_id": scan_run_id,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "target": str(target),
        "elapsed_seconds": round(elapsed, 2),
        "summary": {
            "active_total": len(active),
            "suppressed_total": len(suppressed),
            "by_severity": _count_by_severity(active),
            "by_source": _count_by_source(active),
        },
        "findings": [_finding_to_dict(f, target) for f in active],
        "suppressed": [_finding_to_dict(f, target) for f in suppressed],
    }


def _finding_to_dict(f: Finding, target: Path) -> dict:
    try:
        rel = Path(f.file_path).relative_to(target).as_posix() if f.file_path else ""
    except ValueError:
        rel = f.file_path

    d = {
        "id": f.id,
        "title": f.title,
        "cwe_id": f.cwe_id,
        "severity": f.severity,
        "confidence": f.confidence,
        "message": f.message,
        "location": {
            "file": rel,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "qualified_name": f.qualified_name,
        },
        "sources": f.sources,
        "rule_ids": f.rule_ids,
        "reachability": f.extra.get("reachability"),
        "extra": f.extra,
    }
    # LLM analysis fields (only present when LLM was enabled)
    if f.llm_verdict is not None:
        d["llm"] = {
            "verdict":    f.llm_verdict,
            "confidence": f.llm_confidence,
            "method":     f.llm_method,
            "reasoning":  f.llm_reasoning,
        }
    return d


def _count_by_severity(findings: list[Finding]) -> dict:
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _count_by_source(findings: list[Finding]) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        for src in f.sources:
            counts[src] = counts.get(src, 0) + 1
    return counts
