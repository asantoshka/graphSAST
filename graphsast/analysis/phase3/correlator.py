"""Phase 3 — Correlate, deduplicate, and score findings.

Merges findings from:
  - graph_taint  (Phase 2 Pass B)
  - semgrep      (Phase 2 Pass A)
  - missing_check (Phase 2 Pass B)
  - structure    (Phase 2 Pass C)

Grouping key: (normalised_file, line_bucket, cwe_id)
  line_bucket = (line // 5) * 5   — groups findings within 5 lines together

Confidence scoring:
  Each "signal" that agrees adds weight.  The final confidence tier
  is derived from the weighted sum.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Source → base weight
_SOURCE_WEIGHTS = {
    "graph_taint": 3,
    "semgrep": 2,
    "missing_check": 2,
    "structure": 1,
    "llm_1a": 3,    # autonomous LLM discovery (read actual code)
    "llm_1b": 2,    # LLM validation of a suspect path
}

# Severity ordering
_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class Finding:
    """A correlated, deduplicated security finding."""

    id: str                     # e.g. "CWE-89:src/app.py:25"
    cwe_id: str
    severity: str
    confidence: str             # HIGH | MEDIUM | LOW
    title: str
    message: str
    file_path: str
    line_start: int
    line_end: int
    qualified_name: str | None
    sources: list[str] = field(default_factory=list)   # which phases contributed
    rule_ids: list[str] = field(default_factory=list)
    vuln_class_ids: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)
    # LLM analysis fields (populated by llm_merge)
    llm_verdict: str | None = None      # CONFIRMED | FALSE_POSITIVE | UNCERTAIN
    llm_confidence: str | None = None
    llm_reasoning: str | None = None
    llm_method: str | None = None       # pattern+graph | llm-single | llm-microtask
    is_suppressed: bool = False         # True = LLM ruled FALSE_POSITIVE


def correlate(all_findings: list[dict]) -> list[Finding]:
    """Merge all Phase 2 findings into a deduplicated, scored list.

    Args:
        all_findings: flat list of finding dicts from all Phase 2 passes

    Returns:
        Sorted list of Finding objects (highest severity first)
    """
    # Group by key
    groups: dict[str, list[dict]] = defaultdict(list)
    for f in all_findings:
        key = _group_key(f)
        groups[key].append(f)

    results: list[Finding] = []
    for key, group in groups.items():
        finding = _merge_group(key, group)
        results.append(finding)

    # Sort: severity desc, then confidence desc
    results.sort(key=lambda f: (
        _SEV_ORDER.get(f.severity, 0),
        _SEV_ORDER.get(f.confidence, 0),
    ), reverse=True)

    logger.info(
        "Correlator: %d raw → %d unique findings",
        len(all_findings), len(results),
    )
    return results


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _group_key(f: dict) -> str:
    """Compute the dedup key for a finding."""
    file_path = (f.get("file_path") or "").replace("\\", "/")
    line = int(f.get("line_start") or 0)
    line_bucket = (line // 5) * 5
    cwe = f.get("cwe_id") or "no-cwe"
    # For missing_check and structure, also factor in the rule_id sub-type
    if f.get("source") in ("missing_check", "structure"):
        return f"{file_path}:{line_bucket}:{f.get('rule_id','')}"
    return f"{file_path}:{line_bucket}:{cwe}"


def _merge_group(key: str, group: list[dict]) -> Finding:
    """Merge a group of related findings into a single Finding."""
    # Pick the highest severity
    best = max(group, key=lambda f: _SEV_ORDER.get(f.get("severity", "LOW"), 0))

    # Aggregate sources
    sources = sorted({f["source"] for f in group})
    rule_ids = list({f.get("rule_id", "") for f in group if f.get("rule_id")})
    vc_ids = list({f.get("vuln_class_id", "") for f in group if f.get("vuln_class_id")})

    # Score confidence
    weight = sum(_SOURCE_WEIGHTS.get(s, 1) for s in sources)
    confidence = _weight_to_confidence(weight, len(sources))

    # Pick best message
    message = best.get("message") or ""
    if len(group) > 1:
        other_sources = [s for s in sources if s != best["source"]]
        if other_sources:
            message += f" (also detected by: {', '.join(other_sources)})"

    cwe = best.get("cwe_id") or ""
    title = _make_title(cwe, best.get("severity", "MEDIUM"), best.get("source", ""))

    # Merge extra dicts
    extra: dict = {}
    for f in group:
        extra.update(f.get("extra") or {})

    return Finding(
        id=key,
        cwe_id=cwe,
        severity=best.get("severity", "MEDIUM"),
        confidence=confidence,
        title=title,
        message=message,
        file_path=best.get("file_path") or "",
        line_start=int(best.get("line_start") or 0),
        line_end=int(best.get("line_end") or 0),
        qualified_name=best.get("qualified_name"),
        sources=sources,
        rule_ids=rule_ids,
        vuln_class_ids=vc_ids,
        extra=extra,
    )


def _weight_to_confidence(weight: int, source_count: int) -> str:
    """Derive confidence tier from aggregate source weight."""
    if weight >= 5 or source_count >= 3:
        return "HIGH"
    if weight >= 3 or source_count >= 2:
        return "MEDIUM"
    return "LOW"


_CWE_TITLES = {
    "CWE-89":  "SQL Injection",
    "CWE-78":  "OS Command Injection",
    "CWE-79":  "Cross-Site Scripting (XSS)",
    "CWE-94":  "Code Injection",
    "CWE-95":  "Eval Injection",
    "CWE-22":  "Path Traversal",
    "CWE-502": "Insecure Deserialization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-306": "Missing Authentication",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-770": "Missing Rate Limiting",
    "CWE-20":  "Improper Input Validation",
    "CWE-327": "Use of Weak Cryptographic Algorithm",
    "CWE-338": "Use of Weak PRNG",
    "CWE-295": "Improper Certificate Validation",
    "CWE-377": "Insecure Temporary File",
    "CWE-561": "Dead Code (Sensitive Function)",
    "CWE-1120": "God Function (High Complexity)",
}


def _make_title(cwe: str, severity: str, source: str) -> str:
    if cwe and cwe in _CWE_TITLES:
        return _CWE_TITLES[cwe]
    if source == "missing_check":
        return "Missing Security Check"
    if source == "structure":
        return "Structural Security Issue"
    return f"Security Issue ({cwe or 'unknown CWE'})"
