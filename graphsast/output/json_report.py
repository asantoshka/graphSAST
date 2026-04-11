"""JSON report formatter."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from graphsast.analysis.models import Finding

try:
    from importlib.metadata import version as _pkg_version
    _GRAPHSAST_VERSION = _pkg_version("graphsast")
except Exception:
    _GRAPHSAST_VERSION = "0.0.0"


def to_json(findings: list[Finding], target: Path, elapsed: float = 0.0) -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    active = [f for f in findings if not f.is_false_positive]

    return {
        "graphsast_version": _GRAPHSAST_VERSION,
        "scanned_at": ts,
        "target": str(target),
        "elapsed_seconds": elapsed,
        "summary": {
            "total": len(findings),
            "active": len(active),
            "false_positives": len(findings) - len(active),
            "by_severity": _count_by_severity(active),
        },
        "findings": [_serialise(f, target) for f in findings],
    }


def _serialise(f: Finding, target: Path) -> dict:
    try:
        rel = Path(f.file_path).relative_to(target).as_posix()
    except ValueError:
        rel = f.file_path

    return {
        "rule_id":         f.rule_id,
        "title":           f.title,
        "message":         f.message,
        "severity":        f.effective_severity,
        "cwe_id":          f.cwe_id,
        "file":            rel,
        "line_start":      f.line_start,
        "line_end":        f.line_end,
        "snippet":         f.snippet,
        "llm_verdict":     f.llm_verdict,
        "llm_severity":    f.llm_severity,
        "llm_description": f.llm_description,
        "llm_poc":         f.llm_poc,
        "llm_cvss_score":  f.llm_cvss_score,
        "llm_cvss_vector": f.llm_cvss_vector,
        "llm_reasoning":   f.llm_reasoning,
    }


def _count_by_severity(findings: list[Finding]) -> dict:
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.effective_severity
        counts[sev] = counts.get(sev, 0) + 1
    return counts
